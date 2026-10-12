//! WinSafe 메인 창.
//!
//! 이 모듈의 코드는 모두 UI thread에서 돈다. 서버에는 [`Controller`]로 명령만 보내고,
//! 결과와 로그는 timer가 울릴 때마다 channel에서 꺼내 화면에 반영한다. worker가 UI
//! thread를 직접 부르지 않으므로 창을 닫는 동안 서로를 기다리며 멈출 일이 없다.
//!
//! 창은 설정 하나를 들고 있다. Target 이름과 listen 주소는 입력 칸에, LUN은 목록에
//! 있고, 서버를 시작하거나 저장할 때 [`Settings`]로 모아 검증한다. 서버가 도는 동안은
//! 설정을 고칠 수 없다.

use std::cell::{Cell, RefCell};
use std::path::{Path, PathBuf};
use std::rc::Rc;

use iscsi_target_server::{LunBackendConfig, LunConfig, ServerConfig};
use winsafe::{self as w, co, gui, prelude::*};

use crate::controller::{Controller, Event, LunView, ServerState, TargetView, describe_backend};
use crate::logging::{self, LogBuffer, LogReceiver, LogUpdate};
use crate::settings::{LunForm, Settings, format_capacity};
use crate::{controls, file_dialog, lun_dialog};

const APP_TITLE: &str = "iSCSI Target Server";
const POLL_TIMER_ID: usize = 1;
const POLL_INTERVAL_MS: u32 = 100;
/// 로그 영역에 남기는 최대 줄 수.
const LOG_LINE_LIMIT: usize = 2000;
const STATUS_PART_STATE: u32 = 0;
const STATUS_PART_ADDRESS: u32 = 1;
const CONFIG_FILE_TYPES: [(&str, &str); 2] =
    [("Configuration files", "*.toml"), ("All files", "*.*")];

/// 창을 만들고 닫힐 때까지 message loop를 돌린다.
pub fn run(initial_config_path: Option<PathBuf>) -> w::AnyResult<()> {
    // 파일 선택 dialog가 COM을 쓴다.
    let _com = w::CoInitializeEx(co::COINIT::APARTMENTTHREADED | co::COINIT::DISABLE_OLE1DDE)?;
    let logs = logging::install()?;
    let controller = Controller::spawn()?;

    let window = MainWindow::new(controller, logs, initial_config_path);
    let result = window.wnd.run_main(None);
    // 창은 서버가 내려간 뒤에 닫히지만, message loop가 오류로 끝난 경우에도 서버를
    // 내리고 storage backend를 닫은 뒤에 process를 끝낸다.
    window.shared.controller.shutdown();
    result.map(|_| ())
}

/// 창을 띄우지 못했을 때 오류를 알린다.
pub fn show_fatal_error(message: &str) {
    let _ = w::HWND::NULL.MessageBox(message, APP_TITLE, co::MB::OK | co::MB::ICONERROR);
}

struct Shared {
    controller: Controller,
    logs: LogReceiver,
    state: Cell<ServerState>,
    /// 사용자가 창을 닫기로 했고 서버가 내려가기를 기다리는 중이다.
    closing: Cell<bool>,
    log_buffer: RefCell<LogBuffer>,
    /// 지금 고치고 있는 설정. 입력 칸의 글자는 [`MainWindow::collect`]가 옮겨 담는다.
    settings: RefCell<Settings>,
    /// 마지막으로 읽거나 저장한 때의 설정. 지금 것과 다르면 저장할 것이 있다.
    saved: RefCell<Settings>,
    path: RefCell<Option<PathBuf>>,
    /// 실행 중인 서버가 실제로 연 LUN. 용량과 block size는 여기서만 알 수 있다.
    running_luns: RefCell<Vec<LunView>>,
    /// 창이 뜬 뒤 처음 읽을 설정 파일.
    pending_open: RefCell<Option<PathBuf>>,
    /// 읽어 온 파일을 덮어쓰면 주석이 사라진다는 경고를 이 파일에 대해 이미 했다.
    rewrite_confirmed: Cell<bool>,
    /// control이 모두 만들어졌다. 그 전의 변경 알림은 무시한다.
    ready: Cell<bool>,
}

#[derive(Clone)]
struct MainWindow {
    wnd: gui::WindowMain,
    new: gui::Button,
    open: gui::Button,
    save: gui::Button,
    save_as: gui::Button,
    target_name: gui::Edit,
    listen_address: gui::Edit,
    listen_port: gui::Edit,
    authentication: gui::Label,
    luns: gui::ListView,
    add_lun: gui::Button,
    edit_lun: gui::Button,
    remove_lun: gui::Button,
    start: gui::Button,
    stop: gui::Button,
    log: gui::Edit,
    status: gui::StatusBar,
    shared: Rc<Shared>,
}

impl MainWindow {
    fn new(
        controller: Controller,
        logs: LogReceiver,
        initial_config_path: Option<PathBuf>,
    ) -> Self {
        let wnd = gui::WindowMain::new(gui::WindowMainOpts {
            title: APP_TITLE,
            size: gui::dpi(760, 580),
            style: gui::WindowMainOpts::default().style
                | co::WS::SIZEBOX
                | co::WS::MINIMIZEBOX
                | co::WS::MAXIMIZEBOX,
            ..Default::default()
        });

        let button = |text: &str, x: i32, y: i32, width: i32, horz: gui::Horz| {
            gui::Button::new(
                &wnd,
                gui::ButtonOpts {
                    text,
                    position: gui::dpi(x, y),
                    width: gui::dpi_x(width),
                    height: gui::dpi_y(26),
                    resize_behavior: (horz, gui::Vert::None),
                    ..Default::default()
                },
            )
        };
        let label = |text: &str, x: i32, y: i32, width: i32| {
            gui::Label::new(
                &wnd,
                gui::LabelOpts {
                    text,
                    position: gui::dpi(x, y),
                    size: gui::dpi(width, 20),
                    control_style: co::SS::LEFT | co::SS::NOTIFY | co::SS::ENDELLIPSIS,
                    ..Default::default()
                },
            )
        };
        let edit = |x: i32, y: i32, width: i32, horz: gui::Horz| {
            gui::Edit::new(
                &wnd,
                gui::EditOpts {
                    position: gui::dpi(x, y),
                    width: gui::dpi_x(width),
                    resize_behavior: (horz, gui::Vert::None),
                    ..Default::default()
                },
            )
        };

        // control은 만든 순서가 tab 순서다.
        let new = button("&New", 12, 12, 84, gui::Horz::None);
        let open = button("&Open...", 102, 12, 84, gui::Horz::None);
        let save = button("&Save", 192, 12, 84, gui::Horz::None);
        let save_as = button("Save &As...", 282, 12, 96, gui::Horz::None);

        let _ = label("Target name:", 12, 54, 110);
        let target_name = edit(126, 50, 622, gui::Horz::Resize);
        let _ = label("Listen address:", 12, 86, 110);
        let listen_address = edit(126, 82, 200, gui::Horz::None);
        let _ = label("Port:", 342, 86, 40);
        let listen_port = edit(384, 82, 70, gui::Horz::None);
        let authentication = gui::Label::new(
            &wnd,
            gui::LabelOpts {
                text: "",
                position: gui::dpi(470, 86),
                size: gui::dpi(278, 20),
                control_style: co::SS::LEFT | co::SS::NOTIFY | co::SS::ENDELLIPSIS,
                resize_behavior: (gui::Horz::Resize, gui::Vert::None),
                ..Default::default()
            },
        );

        let luns = gui::ListView::new(
            &wnd,
            gui::ListViewOpts {
                position: gui::dpi(12, 116),
                size: gui::dpi(636, 150),
                columns: &[
                    ("LUN", gui::dpi_x(46)),
                    ("Backend", gui::dpi_x(290)),
                    ("Capacity", gui::dpi_x(100)),
                    ("Block size", gui::dpi_x(80)),
                    ("Access", gui::dpi_x(100)),
                ],
                resize_behavior: (gui::Horz::Resize, gui::Vert::None),
                ..Default::default()
            },
        );
        let add_lun = button("A&dd LUN...", 658, 116, 90, gui::Horz::Repos);
        let edit_lun = button("&Edit...", 658, 148, 90, gui::Horz::Repos);
        let remove_lun = button("&Remove", 658, 180, 90, gui::Horz::Repos);

        let start = button("S&tart", 12, 278, 90, gui::Horz::None);
        let stop = button("Sto&p", 110, 278, 90, gui::Horz::None);

        let log = gui::Edit::new(
            &wnd,
            gui::EditOpts {
                position: gui::dpi(12, 314),
                width: gui::dpi_x(736),
                height: gui::dpi_y(230),
                control_style: co::ES::MULTILINE
                    | co::ES::READONLY
                    | co::ES::AUTOVSCROLL
                    | co::ES::NOHIDESEL,
                window_style: gui::EditOpts::default().window_style | co::WS::VSCROLL,
                resize_behavior: (gui::Horz::Resize, gui::Vert::Resize),
                ..Default::default()
            },
        );
        let status = gui::StatusBar::new(
            &wnd,
            &[
                gui::SbPart::Fixed(gui::dpi_x(140)),
                gui::SbPart::Proportional(1),
            ],
        );

        for edit in [&target_name, &listen_address, &listen_port, &log] {
            guard_escape(edit);
        }

        let new_settings = new_settings();
        let new_self = Self {
            wnd,
            new,
            open,
            save,
            save_as,
            target_name,
            listen_address,
            listen_port,
            authentication,
            luns,
            add_lun,
            edit_lun,
            remove_lun,
            start,
            stop,
            log,
            status,
            shared: Rc::new(Shared {
                controller,
                logs,
                state: Cell::new(ServerState::default()),
                closing: Cell::new(false),
                log_buffer: RefCell::new(LogBuffer::new(LOG_LINE_LIMIT)),
                settings: RefCell::new(new_settings.clone()),
                saved: RefCell::new(new_settings),
                path: RefCell::new(None),
                running_luns: RefCell::new(Vec::new()),
                pending_open: RefCell::new(initial_config_path),
                rewrite_confirmed: Cell::new(false),
                ready: Cell::new(false),
            }),
        };
        new_self.events();
        new_self
    }

    fn events(&self) {
        self.wnd.on().wm_create({
            let this = self.clone();
            move |_| {
                // 기본 상한은 약 30000자라 로그가 금방 찬다. 줄 수는 LogBuffer가 제한한다.
                this.log.limit_text(None);
                this.shared.ready.set(true);
                this.show_settings()?;
                this.show_state()?;
                this.wnd
                    .hwnd()
                    .SetTimer(POLL_TIMER_ID, POLL_INTERVAL_MS, None)?;
                Ok(0)
            }
        });

        self.wnd.on().wm_timer(POLL_TIMER_ID, {
            let this = self.clone();
            move || this.poll()
        });

        self.new.on().bn_clicked({
            let this = self.clone();
            move || {
                if this.confirm_discard()? {
                    this.replace_settings(new_settings(), None)?;
                }
                Ok(())
            }
        });

        self.open.on().bn_clicked({
            let this = self.clone();
            move || {
                if !this.confirm_discard()? {
                    return Ok(());
                }
                if let Some(path) = file_dialog::open(this.wnd.hwnd(), &CONFIG_FILE_TYPES)? {
                    this.open_file(Path::new(&path))?;
                }
                Ok(())
            }
        });

        self.save.on().bn_clicked({
            let this = self.clone();
            move || this.save_current().map(|_| ())
        });

        self.save_as.on().bn_clicked({
            let this = self.clone();
            move || this.save_as_new().map(|_| ())
        });

        // 입력 칸이 바뀌면 제목의 "저장할 것이 있음" 표시를 고친다.
        for edit in [&self.target_name, &self.listen_address, &self.listen_port] {
            edit.on().en_change({
                let this = self.clone();
                move || this.show_title()
            });
        }

        self.add_lun.on().bn_clicked({
            let this = self.clone();
            move || {
                let form = LunForm::new(this.shared.settings.borrow().next_free_lun());
                this.edit_lun_with(None, &form)
            }
        });

        self.edit_lun.on().bn_clicked({
            let this = self.clone();
            move || this.edit_selected_lun()
        });

        self.luns.on().nm_dbl_clk({
            let this = self.clone();
            move |_| {
                if this.shared.state.get().can_start() {
                    this.edit_selected_lun()?;
                }
                Ok(())
            }
        });

        self.remove_lun.on().bn_clicked({
            let this = self.clone();
            move || {
                let Some(lun) = this.selected_lun()? else {
                    return Ok(());
                };
                this.shared.settings.borrow_mut().remove_lun(lun);
                this.show_luns()?;
                this.show_title()
            }
        });

        self.start.on().bn_clicked({
            let this = self.clone();
            move || {
                if let Some(config) = this.checked_config()? {
                    this.shared.controller.start(config);
                }
                Ok(())
            }
        });

        self.stop.on().bn_clicked({
            let this = self.clone();
            move || {
                this.shared.controller.stop();
                Ok(())
            }
        });

        // 이 event를 처리하면 기본 동작(창 파괴)이 없어지므로 직접 파괴한다.
        self.wnd.on().wm_close({
            let this = self.clone();
            move || this.close_requested()
        });

        self.wnd.on().wm_destroy({
            let this = self.clone();
            move || {
                this.wnd.hwnd().KillTimer(POLL_TIMER_ID)?;
                Ok(())
            }
        });
    }

    // ── 설정 ────────────────────────────────────────────────────────────────

    /// 입력 칸의 글자를 설정에 옮겨 담는다.
    fn collect(&self) -> w::AnyResult<()> {
        let target_name = controls::text(&self.target_name)?;
        let listen_address = controls::text(&self.listen_address)?;
        let listen_port = controls::text(&self.listen_port)?;
        let mut settings = self.shared.settings.borrow_mut();
        settings.target_name = target_name;
        settings.listen_address = listen_address;
        settings.listen_port = listen_port;
        Ok(())
    }

    /// 지금 설정에 저장하지 않은 변경이 있는지.
    fn is_modified(&self) -> w::AnyResult<bool> {
        self.collect()?;
        Ok(*self.shared.settings.borrow() != *self.shared.saved.borrow())
    }

    /// 입력을 검증해 서버 설정으로 바꾼다. 틀린 곳이 있으면 알리고 `None`을 돌려준다.
    fn checked_config(&self) -> w::AnyResult<Option<ServerConfig>> {
        self.collect()?;
        let checked = self.shared.settings.borrow().to_config();
        match checked {
            Ok(config) => Ok(Some(config)),
            Err(message) => {
                self.wnd.hwnd().MessageBox(
                    &message,
                    APP_TITLE,
                    co::MB::OK | co::MB::ICONWARNING,
                )?;
                Ok(None)
            }
        }
    }

    /// 설정을 통째로 바꾸고 화면을 맞춘다. 새 설정은 저장된 상태로 본다.
    fn replace_settings(&self, settings: Settings, path: Option<PathBuf>) -> w::AnyResult<()> {
        *self.shared.saved.borrow_mut() = settings.clone();
        *self.shared.settings.borrow_mut() = settings;
        *self.shared.path.borrow_mut() = path;
        self.shared.rewrite_confirmed.set(false);
        self.show_settings()
    }

    fn open_file(&self, path: &Path) -> w::AnyResult<()> {
        let loaded = ServerConfig::load_from_file(path)
            .map_err(|error| error.to_string())
            .and_then(|config| Settings::from_config(&config));
        match loaded {
            Ok(settings) => {
                tracing::info!(path = %path.display(), "configuration loaded");
                self.replace_settings(settings, Some(path.to_path_buf()))
            }
            Err(message) => {
                tracing::error!(path = %path.display(), error = %message, "could not load the configuration");
                self.show_error(&format!("Could not load {}.", path.display()), &message)
            }
        }
    }

    /// 읽어 온 파일에 저장한다. 파일이 없으면 이름을 묻는다. 저장했으면 `true`다.
    fn save_current(&self) -> w::AnyResult<bool> {
        let Some(path) = self.shared.path.borrow().clone() else {
            return self.save_as_new();
        };
        if !self.shared.rewrite_confirmed.get() {
            let answer = self.wnd.hwnd().MessageBox(
                "Saving rewrites the file in a standard layout. Comments and the original formatting in it will be lost.\n\nSave anyway?",
                APP_TITLE,
                co::MB::OKCANCEL | co::MB::ICONWARNING,
            )?;
            if answer != co::DLGID::OK {
                return Ok(false);
            }
        }
        self.save_to(&path)
    }

    fn save_as_new(&self) -> w::AnyResult<bool> {
        // 틀린 설정으로 파일 이름부터 묻지 않는다.
        if self.checked_config()?.is_none() {
            return Ok(false);
        }
        match file_dialog::save(self.wnd.hwnd(), &CONFIG_FILE_TYPES, "toml")? {
            Some(path) => self.save_to(Path::new(&path)),
            None => Ok(false),
        }
    }

    fn save_to(&self, path: &Path) -> w::AnyResult<bool> {
        let Some(config) = self.checked_config()? else {
            return Ok(false);
        };
        if let Err(error) = config.save_to_file(path) {
            tracing::error!(path = %path.display(), %error, "could not save the configuration");
            self.show_error(
                &format!("Could not save {}.", path.display()),
                &error.to_string(),
            )?;
            return Ok(false);
        }
        tracing::info!(path = %path.display(), "configuration saved");
        let saved = self.shared.settings.borrow().clone();
        *self.shared.saved.borrow_mut() = saved;
        *self.shared.path.borrow_mut() = Some(path.to_path_buf());
        // 이제 이 파일은 이 프로그램이 쓴 것이라 다시 물을 필요가 없다.
        self.shared.rewrite_confirmed.set(true);
        self.show_title()?;
        Ok(true)
    }

    /// 저장하지 않은 변경을 버려도 되는지 묻는다. 계속해도 되면 `true`다.
    fn confirm_discard(&self) -> w::AnyResult<bool> {
        if !self.is_modified()? {
            return Ok(true);
        }
        let answer = self.wnd.hwnd().MessageBox(
            "Save the changes to the configuration?",
            APP_TITLE,
            co::MB::YESNOCANCEL | co::MB::ICONQUESTION,
        )?;
        match answer {
            co::DLGID::YES => self.save_current(),
            co::DLGID::NO => Ok(true),
            _ => Ok(false),
        }
    }

    fn selected_lun(&self) -> w::AnyResult<Option<u64>> {
        Ok(self
            .luns
            .items()
            .iter_selected()
            .next()
            .and_then(|item| item.text(0).parse().ok()))
    }

    fn edit_selected_lun(&self) -> w::AnyResult<()> {
        let Some(lun) = self.selected_lun()? else {
            return Ok(());
        };
        let form = self
            .shared
            .settings
            .borrow()
            .luns()
            .iter()
            .find(|existing| existing.lun() == lun)
            .map(LunForm::from_config);
        match form {
            Some(form) => self.edit_lun_with(Some(lun), &form),
            None => Ok(()),
        }
    }

    /// LUN dialog를 띄우고, OK로 닫히면 설정에 넣는다. `replacing`이 있으면 그 번호의
    /// LUN을 고치는 것이다.
    fn edit_lun_with(&self, replacing: Option<u64>, form: &LunForm) -> w::AnyResult<()> {
        let title = if replacing.is_some() {
            "Edit LUN"
        } else {
            "Add LUN"
        };
        // dialog가 닫히기 전에 번호가 겹치는지 알려 주려고 사본에 넣어 본다.
        let shared = self.shared.clone();
        let accept = move |lun: &LunConfig| {
            shared
                .settings
                .borrow()
                .clone()
                .put_lun(replacing, lun.clone())
        };
        let Some(lun) = lun_dialog::show(&self.wnd, title, form, accept)? else {
            return Ok(());
        };
        let put = self.shared.settings.borrow_mut().put_lun(replacing, lun);
        if let Err(message) = put {
            self.wnd
                .hwnd()
                .MessageBox(&message, APP_TITLE, co::MB::OK | co::MB::ICONWARNING)?;
        }
        self.show_luns()?;
        self.show_title()
    }

    // ── 화면 ────────────────────────────────────────────────────────────────

    /// 설정 전체를 화면에 옮긴다.
    fn show_settings(&self) -> w::AnyResult<()> {
        // 입력 칸을 바꾸면 변경 알림이 와서 설정을 다시 읽는다. borrow를 먼저 놓는다.
        let (target_name, listen_address, listen_port, authentication) = {
            let settings = self.shared.settings.borrow();
            (
                settings.target_name.clone(),
                settings.listen_address.clone(),
                settings.listen_port.clone(),
                settings.authentication_label(),
            )
        };
        self.shared.ready.set(false);
        self.target_name.set_text(&target_name)?;
        self.listen_address.set_text(&listen_address)?;
        self.listen_port.set_text(&listen_port)?;
        self.shared.ready.set(true);
        self.authentication
            .hwnd()
            .SetWindowText(&format!("Authentication: {authentication}"))?;
        self.show_luns()?;
        self.show_title()
    }

    fn show_luns(&self) -> w::AnyResult<()> {
        let selected = self.selected_lun()?;
        self.luns.items().delete_all()?;
        let settings = self.shared.settings.borrow();
        let running = self.shared.running_luns.borrow();
        for lun in settings.luns() {
            let opened = running.iter().find(|view| view.lun == lun.lun());
            let item = self.luns.items().add(&lun_columns(lun, opened), None, ())?;
            if selected == Some(lun.lun()) {
                item.select(true)?;
            }
        }
        Ok(())
    }

    /// 제목에 파일 이름과, 저장하지 않은 변경이 있으면 `*`를 보인다.
    fn show_title(&self) -> w::AnyResult<()> {
        if !self.shared.ready.get() {
            return Ok(());
        }
        let name = match self.shared.path.borrow().as_deref() {
            Some(path) => path
                .file_name()
                .unwrap_or(path.as_os_str())
                .to_string_lossy()
                .into_owned(),
            None => "Untitled".to_owned(),
        };
        let mark = if self.is_modified()? { "*" } else { "" };
        self.wnd
            .hwnd()
            .SetWindowText(&format!("{name}{mark} - {APP_TITLE}"))?;
        Ok(())
    }

    /// 상태에 맞춰 버튼과 status bar를 고친다. 서버가 도는 동안은 설정을 고칠 수 없다.
    fn show_state(&self) -> w::AnyResult<()> {
        let state = self.shared.state.get();
        let editable = state.can_start();
        for button in [
            &self.new,
            &self.open,
            &self.add_lun,
            &self.edit_lun,
            &self.remove_lun,
            &self.start,
        ] {
            button.hwnd().EnableWindow(editable);
        }
        for edit in [&self.target_name, &self.listen_address, &self.listen_port] {
            edit.hwnd().EnableWindow(editable);
        }
        self.stop.hwnd().EnableWindow(state.can_stop());
        self.status
            .parts()
            .get(STATUS_PART_STATE)
            .set_text(state.label())?;
        Ok(())
    }

    fn show_error(&self, summary: &str, detail: &str) -> w::AnyResult<()> {
        // 창을 닫는 중이면 사용자를 dialog로 붙잡지 않는다. 내용은 로그에 남아 있다.
        if self.shared.closing.get() {
            return Ok(());
        }
        self.wnd.hwnd().MessageBox(
            &format!("{summary}\n\n{detail}"),
            APP_TITLE,
            co::MB::OK | co::MB::ICONERROR,
        )?;
        Ok(())
    }

    // ── 서버 ────────────────────────────────────────────────────────────────

    /// worker가 보낸 event와 로그를 화면에 반영한다.
    ///
    /// dialog가 떠 있는 동안에도 timer는 계속 울려 이 함수가 다시 불린다. 그래서
    /// dialog를 띄우는 동안에는 `RefCell` borrow를 들고 있지 않는다.
    fn poll(&self) -> w::AnyResult<()> {
        let pending = self.shared.pending_open.borrow_mut().take();
        if let Some(path) = pending {
            self.open_file(&path)?;
        }
        while let Some(event) = self.shared.controller.try_event() {
            self.apply(event)?;
        }
        self.drain_logs()?;
        if self.shared.closing.get() && self.shared.state.get() == ServerState::Stopped {
            self.shared.closing.set(false);
            self.wnd.hwnd().DestroyWindow()?;
        }
        Ok(())
    }

    fn apply(&self, event: Event) -> w::AnyResult<()> {
        self.shared.state.set(self.shared.state.get().after(&event));
        self.show_state()?;
        match event {
            Event::Starting | Event::Stopping => {}
            Event::Started { address, targets } => {
                self.show_running(targets)?;
                self.status
                    .parts()
                    .get(STATUS_PART_ADDRESS)
                    .set_text(&format!("Listening on {address}"))?;
            }
            Event::Stopped(summary) => {
                self.show_running(Vec::new())?;
                tracing::info!(
                    accepted = summary.accepted_connections,
                    completed = summary.completed_connections,
                    failed = summary.failed_connections,
                    aborted = summary.aborted_connections,
                    "Target service stopped"
                );
            }
            Event::StartFailed(message) => {
                self.show_running(Vec::new())?;
                tracing::error!(error = %message, "could not start the server");
                self.show_error("Could not start the server.", &message)?;
            }
            Event::Failed(message) => {
                self.show_running(Vec::new())?;
                tracing::error!(error = %message, "the server stopped on an error");
                self.show_error("The server stopped on an error.", &message)?;
            }
        }
        Ok(())
    }

    /// 실행 중인 서버가 연 LUN의 크기를 목록에 반영한다. 빈 목록이면 지운다.
    fn show_running(&self, targets: Vec<TargetView>) -> w::AnyResult<()> {
        let stopped = targets.is_empty();
        *self.shared.running_luns.borrow_mut() =
            targets.into_iter().flat_map(|target| target.luns).collect();
        if stopped {
            self.status.parts().get(STATUS_PART_ADDRESS).set_text("")?;
        }
        self.show_luns()
    }

    fn close_requested(&self) -> w::AnyResult<()> {
        // dialog가 떠 있는 동안에는 이 창이 비활성이다. 그때 온 닫기 요청은 받지 않는다.
        if self.shared.closing.get() || !self.wnd.hwnd().IsWindowEnabled() {
            return Ok(());
        }
        if !self.confirm_discard()? {
            return Ok(());
        }
        if self.shared.state.get() == ServerState::Stopped {
            self.wnd.hwnd().DestroyWindow()?;
            return Ok(());
        }
        let answer = self.wnd.hwnd().MessageBox(
            "The server is running. Initiators that are connected will lose their disks.\n\nStop the server and exit?",
            APP_TITLE,
            co::MB::YESNO | co::MB::DEFBUTTON2 | co::MB::ICONWARNING,
        )?;
        if answer != co::DLGID::YES {
            return Ok(());
        }
        // dialog가 떠 있는 동안 서버가 스스로 내려갔을 수 있다.
        if self.shared.state.get() == ServerState::Stopped {
            self.wnd.hwnd().DestroyWindow()?;
            return Ok(());
        }
        // 서버가 내려갔다는 event가 오면 poll()이 창을 닫는다. 시작하는 중이면 이
        // 요청은 시작이 끝난 뒤에 처리된다.
        self.shared.closing.set(true);
        self.shared.controller.stop();
        Ok(())
    }

    // ── 로그 ────────────────────────────────────────────────────────────────

    fn drain_logs(&self) -> w::AnyResult<()> {
        let dropped = self.shared.logs.take_dropped();
        if dropped > 0 {
            self.append_log(&format!("({dropped} log lines were dropped)"))?;
        }
        while let Some(line) = self.shared.logs.try_line() {
            self.append_log(&line)?;
        }
        Ok(())
    }

    fn append_log(&self, line: &str) -> w::AnyResult<()> {
        let update = self.shared.log_buffer.borrow_mut().push(line);
        match update {
            LogUpdate::Append(text) => {
                let end = controls::text_length(self.log.hwnd())?;
                self.log.set_selection(end, end);
                self.log.replace_selection(&text);
            }
            LogUpdate::Replace(text) => {
                self.log.set_text(&text)?;
                let end = controls::text_length(self.log.hwnd())?;
                self.log.set_selection(end, end);
                // 빈 선택을 바꿔 넣어 caret이 있는 끝까지 scroll되게 한다.
                self.log.replace_selection("");
            }
        }
        Ok(())
    }
}

/// 새로 만드는 설정. Target 이름을 이 PC의 이름과 지금 날짜로 미리 채운다.
fn new_settings() -> Settings {
    let computer_name = std::env::var("COMPUTERNAME").unwrap_or_default();
    let unix_seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or_default();
    Settings::new_for(&computer_name, unix_seconds)
}

/// Edit에서 누른 ESC가 창을 닫지 않게 막는다.
///
/// 여러 줄 Edit control은 ESC keydown을 받으면 부모 창에 `WM_CLOSE`를 보낸다. dialog의
/// 취소 동작을 위한 것인데, 이 창에서는 로그를 보다가 ESC를 누르면 프로그램이 닫혀
/// 버린다. 그래서 control을 subclass해 ESC keydown만 삼키고 나머지 key는 원래
/// 처리로 넘긴다. event는 창이 만들어지기 전에 등록해야 한다.
fn guard_escape(edit: &gui::Edit) {
    let guarded = edit.clone();
    edit.on_subclass().wm(co::WM::KEYDOWN, move |message| {
        if message.wparam == usize::from(co::VK::ESCAPE.raw()) {
            return Ok(0);
        }
        // SAFETY: `message`는 이 control의 subclass procedure가 방금 받은 message를 고치지
        // 않고 그대로 넘기는 것이고, handle도 그 control의 것이다. subclass chain의 다음
        // 처리로 넘기는 정해진 방법이다.
        Ok(unsafe { guarded.hwnd().DefSubclassProc(message) })
    });
}

/// LUN 목록의 한 줄. `opened`는 실행 중인 서버가 실제로 연 결과이고, 있으면 그 크기를
/// 쓴다. image 파일과 disk의 크기는 열어 봐야 알 수 있어 그 전에는 비워 둔다.
fn lun_columns(lun: &LunConfig, opened: Option<&LunView>) -> [String; 5] {
    let (configured_block_size, configured_capacity, read_only) = match lun.backend() {
        LunBackendConfig::Memory {
            block_size,
            block_count,
            read_only,
        } => (
            Some(*block_size),
            u64::from(*block_size).checked_mul(*block_count),
            *read_only,
        ),
        LunBackendConfig::File {
            block_size,
            read_only,
            ..
        } => (Some(*block_size), None, *read_only),
        LunBackendConfig::WindowsPhysicalDrive { read_only, .. }
        | LunBackendConfig::WindowsVolume { read_only, .. } => (None, None, *read_only),
    };
    let capacity = match opened {
        Some(view) => view.capacity_bytes(),
        None => configured_capacity,
    };
    let block_size = opened.map(|view| view.block_size).or(configured_block_size);
    [
        lun.lun().to_string(),
        describe_backend(lun.backend()),
        capacity.map(format_capacity).unwrap_or_default(),
        block_size.map(|size| size.to_string()).unwrap_or_default(),
        if read_only {
            "Read-only".to_owned()
        } else {
            "Read/write".to_owned()
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lun_row_shows_configured_values_until_the_server_opens_the_backend() {
        let memory = LunConfig::new(
            2,
            LunBackendConfig::Memory {
                block_size: 512,
                block_count: 2 * 1024 * 1024,
                read_only: true,
            },
        )
        .unwrap();
        assert_eq!(
            lun_columns(&memory, None),
            ["2", "Memory", "1 GiB", "512", "Read-only"]
        );

        // disk의 크기와 block size는 열기 전에는 모른다.
        let drive = LunConfig::new(
            0,
            LunBackendConfig::WindowsPhysicalDrive {
                device_number: 1,
                read_only: false,
                virtual_disk_identity: true,
            },
        )
        .unwrap();
        assert_eq!(
            lun_columns(&drive, None),
            ["0", "Physical drive 1", "", "", "Read/write"]
        );
        let opened = LunView {
            lun: 0,
            backend: String::new(),
            block_size: 4096,
            block_count: 1024 * 1024,
            read_only: false,
        };
        assert_eq!(
            lun_columns(&drive, Some(&opened)),
            ["0", "Physical drive 1", "4 GiB", "4096", "Read/write"]
        );
    }
}
