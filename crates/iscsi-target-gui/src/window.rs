//! WinSafe 메인 창.
//!
//! 이 모듈의 코드는 모두 UI thread에서 돈다. 서버에는 [`Controller`]로 명령만 보내고,
//! 결과와 로그는 timer가 울릴 때마다 channel에서 꺼내 화면에 반영한다. worker가 UI
//! thread를 직접 부르지 않으므로 창을 닫는 동안 서로를 기다리며 멈출 일이 없다.

use std::cell::{Cell, RefCell};
use std::path::PathBuf;
use std::rc::Rc;

use winsafe::{self as w, co, gui, prelude::*};

use crate::controller::{Controller, Event, LunView, ServerState, TargetView};
use crate::logging::{self, LogBuffer, LogReceiver, LogUpdate};

const APP_TITLE: &str = "iSCSI Target Server";
const POLL_TIMER_ID: usize = 1;
const POLL_INTERVAL_MS: u32 = 100;
/// 로그 영역에 남기는 최대 줄 수.
const LOG_LINE_LIMIT: usize = 2000;
const STATUS_PART_STATE: u32 = 0;
const STATUS_PART_ADDRESS: u32 = 1;

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
}

#[derive(Clone)]
struct MainWindow {
    wnd: gui::WindowMain,
    config_path: gui::Edit,
    browse: gui::Button,
    start: gui::Button,
    stop: gui::Button,
    target: gui::Label,
    luns: gui::ListView,
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
            size: gui::dpi(760, 520),
            style: gui::WindowMainOpts::default().style
                | co::WS::SIZEBOX
                | co::WS::MINIMIZEBOX
                | co::WS::MAXIMIZEBOX,
            ..Default::default()
        });

        // control은 만든 순서가 tab 순서다.
        let _ = gui::Label::new(
            &wnd,
            gui::LabelOpts {
                text: "Configuration file:",
                position: gui::dpi(12, 16),
                size: gui::dpi(134, 20),
                ..Default::default()
            },
        );
        let initial_text = initial_config_path
            .map(|path| path.to_string_lossy().into_owned())
            .unwrap_or_default();
        let config_path = gui::Edit::new(
            &wnd,
            gui::EditOpts {
                text: &initial_text,
                position: gui::dpi(150, 12),
                width: gui::dpi_x(500),
                resize_behavior: (gui::Horz::Resize, gui::Vert::None),
                ..Default::default()
            },
        );
        let browse = gui::Button::new(
            &wnd,
            gui::ButtonOpts {
                text: "&Browse...",
                position: gui::dpi(658, 11),
                width: gui::dpi_x(90),
                height: gui::dpi_y(25),
                resize_behavior: (gui::Horz::Repos, gui::Vert::None),
                ..Default::default()
            },
        );
        let start = gui::Button::new(
            &wnd,
            gui::ButtonOpts {
                text: "&Start",
                position: gui::dpi(12, 46),
                width: gui::dpi_x(90),
                height: gui::dpi_y(26),
                ..Default::default()
            },
        );
        let stop = gui::Button::new(
            &wnd,
            gui::ButtonOpts {
                text: "S&top",
                position: gui::dpi(110, 46),
                width: gui::dpi_x(90),
                height: gui::dpi_y(26),
                ..Default::default()
            },
        );
        let target = gui::Label::new(
            &wnd,
            gui::LabelOpts {
                text: "",
                position: gui::dpi(212, 51),
                size: gui::dpi(536, 20),
                control_style: co::SS::LEFT | co::SS::NOTIFY | co::SS::ENDELLIPSIS,
                resize_behavior: (gui::Horz::Resize, gui::Vert::None),
                ..Default::default()
            },
        );
        let luns = gui::ListView::new(
            &wnd,
            gui::ListViewOpts {
                position: gui::dpi(12, 84),
                size: gui::dpi(736, 150),
                columns: &[
                    ("LUN", gui::dpi_x(50)),
                    ("Backend", gui::dpi_x(300)),
                    ("Capacity", gui::dpi_x(100)),
                    ("Block size", gui::dpi_x(80)),
                    ("Blocks", gui::dpi_x(90)),
                    ("Access", gui::dpi_x(100)),
                ],
                resize_behavior: (gui::Horz::Resize, gui::Vert::None),
                ..Default::default()
            },
        );
        let log = gui::Edit::new(
            &wnd,
            gui::EditOpts {
                position: gui::dpi(12, 244),
                width: gui::dpi_x(736),
                height: gui::dpi_y(240),
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

        guard_escape(&config_path);
        guard_escape(&log);

        let new_self = Self {
            wnd,
            config_path,
            browse,
            start,
            stop,
            target,
            luns,
            log,
            status,
            shared: Rc::new(Shared {
                controller,
                logs,
                state: Cell::new(ServerState::default()),
                closing: Cell::new(false),
                log_buffer: RefCell::new(LogBuffer::new(LOG_LINE_LIMIT)),
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

        self.browse.on().bn_clicked({
            let this = self.clone();
            move || this.browse_for_config()
        });

        self.start.on().bn_clicked({
            let this = self.clone();
            move || {
                let path = this.config_path.text()?;
                let path = path.trim();
                if path.is_empty() {
                    this.wnd.hwnd().MessageBox(
                        "Choose a configuration file first.",
                        APP_TITLE,
                        co::MB::OK | co::MB::ICONINFORMATION,
                    )?;
                    return Ok(());
                }
                this.shared.controller.start(PathBuf::from(path));
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
            move || {
                if this.shared.state.get() == ServerState::Stopped {
                    this.wnd.hwnd().DestroyWindow()?;
                    return Ok(());
                }
                if this.shared.closing.get() {
                    return Ok(());
                }
                let answer = this.wnd.hwnd().MessageBox(
                    "The server is running. Initiators that are connected will lose their disks.\n\nStop the server and exit?",
                    APP_TITLE,
                    co::MB::YESNO | co::MB::DEFBUTTON2 | co::MB::ICONWARNING,
                )?;
                if answer != co::DLGID::YES {
                    return Ok(());
                }
                // dialog가 떠 있는 동안 서버가 스스로 내려갔을 수 있다.
                if this.shared.state.get() == ServerState::Stopped {
                    this.wnd.hwnd().DestroyWindow()?;
                    return Ok(());
                }
                // 서버가 내려갔다는 event가 오면 poll()이 창을 닫는다. 시작하는 중이면
                // 이 요청은 시작이 끝난 뒤에 처리된다.
                this.shared.closing.set(true);
                this.shared.controller.stop();
                Ok(())
            }
        });

        self.wnd.on().wm_destroy({
            let this = self.clone();
            move || {
                this.wnd.hwnd().KillTimer(POLL_TIMER_ID)?;
                Ok(())
            }
        });
    }

    /// worker가 보낸 event와 로그를 화면에 반영한다.
    ///
    /// 오류 dialog가 떠 있는 동안에도 timer는 계속 울려 이 함수가 다시 불린다. 그래서
    /// dialog를 띄우는 동안에는 `RefCell` borrow를 들고 있지 않는다.
    fn poll(&self) -> w::AnyResult<()> {
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
                self.show_targets(&targets)?;
                self.status
                    .parts()
                    .get(STATUS_PART_ADDRESS)
                    .set_text(&format!("Listening on {address}"))?;
            }
            Event::Stopped(summary) => {
                self.clear_targets()?;
                tracing::info!(
                    accepted = summary.accepted_connections,
                    completed = summary.completed_connections,
                    failed = summary.failed_connections,
                    aborted = summary.aborted_connections,
                    "Target service stopped"
                );
            }
            Event::StartFailed(message) => {
                self.clear_targets()?;
                tracing::error!(error = %message, "could not start the server");
                self.show_error("Could not start the server.", &message)?;
            }
            Event::Failed(message) => {
                self.clear_targets()?;
                tracing::error!(error = %message, "the server stopped on an error");
                self.show_error("The server stopped on an error.", &message)?;
            }
        }
        Ok(())
    }

    /// 상태에 맞춰 버튼과 status bar를 고친다.
    fn show_state(&self) -> w::AnyResult<()> {
        let state = self.shared.state.get();
        self.start.hwnd().EnableWindow(state.can_start());
        self.config_path.hwnd().EnableWindow(state.can_start());
        self.browse.hwnd().EnableWindow(state.can_start());
        self.stop.hwnd().EnableWindow(state.can_stop());
        self.status
            .parts()
            .get(STATUS_PART_STATE)
            .set_text(state.label())?;
        Ok(())
    }

    fn show_targets(&self, targets: &[TargetView]) -> w::AnyResult<()> {
        self.luns.items().delete_all()?;
        let summary = targets
            .iter()
            .map(|target| format!("Target: {} ({})", target.name, target.authentication))
            .collect::<Vec<_>>()
            .join(", ");
        self.target.hwnd().SetWindowText(&summary)?;
        for lun in targets.iter().flat_map(|target| &target.luns) {
            self.luns.items().add(&lun_columns(lun), None, ())?;
        }
        Ok(())
    }

    fn clear_targets(&self) -> w::AnyResult<()> {
        self.luns.items().delete_all()?;
        self.target.hwnd().SetWindowText("")?;
        self.status.parts().get(STATUS_PART_ADDRESS).set_text("")?;
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
                let end = self.log.hwnd().GetWindowTextLength()?;
                self.log.set_selection(end, end);
                self.log.replace_selection(&text);
            }
            LogUpdate::Replace(text) => {
                self.log.set_text(&text)?;
                let end = self.log.hwnd().GetWindowTextLength()?;
                self.log.set_selection(end, end);
                // 빈 선택을 바꿔 넣어 caret이 있는 끝까지 scroll되게 한다.
                self.log.replace_selection("");
            }
        }
        Ok(())
    }

    fn browse_for_config(&self) -> w::AnyResult<()> {
        let dialog = w::CoCreateInstance::<w::IFileOpenDialog>(
            &co::CLSID::FileOpenDialog,
            None::<&w::IUnknown>,
            co::CLSCTX::INPROC_SERVER,
        )?;
        dialog
            .SetOptions(dialog.GetOptions()? | co::FOS::FORCEFILESYSTEM | co::FOS::FILEMUSTEXIST)?;
        dialog.SetFileTypes(&[("Configuration files", "*.toml"), ("All files", "*.*")])?;
        dialog.SetFileTypeIndex(1)?;
        if dialog.Show(self.wnd.hwnd())? {
            let path = dialog.GetResult()?.GetDisplayName(co::SIGDN::FILESYSPATH)?;
            self.config_path.set_text(&path)?;
        }
        Ok(())
    }
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

fn lun_columns(lun: &LunView) -> [String; 6] {
    [
        lun.lun.to_string(),
        lun.backend.clone(),
        lun.capacity_bytes()
            .map(format_capacity)
            .unwrap_or_default(),
        lun.block_size.to_string(),
        lun.block_count.to_string(),
        if lun.read_only {
            "Read-only".to_owned()
        } else {
            "Read/write".to_owned()
        },
    ]
}

/// byte 수를 1024 단위로 읽기 쉽게 적는다. 예: `1.5 GiB`.
fn format_capacity(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["KiB", "MiB", "GiB", "TiB", "PiB"];
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let mut value = bytes as f64 / 1024.0;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    // 소수점 아래 한 자리로 반올림하되 `.0`은 떼어 낸다.
    let rounded = (value * 10.0).round() / 10.0;
    if rounded.fract() == 0.0 {
        format!("{rounded:.0} {}", UNITS[unit])
    } else {
        format!("{rounded:.1} {}", UNITS[unit])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capacity_is_formatted_in_binary_units() {
        assert_eq!(format_capacity(0), "0 B");
        assert_eq!(format_capacity(1023), "1023 B");
        assert_eq!(format_capacity(1024), "1 KiB");
        assert_eq!(format_capacity(32 * 1024), "32 KiB");
        assert_eq!(format_capacity(1536 * 1024 * 1024), "1.5 GiB");
        assert_eq!(format_capacity(640 * 1024 * 1024), "640 MiB");
        assert_eq!(format_capacity(u64::MAX), "16384 PiB");
    }

    #[test]
    fn lun_row_shows_every_column() {
        let lun = LunView {
            lun: 2,
            backend: "Physical drive 1".to_owned(),
            block_size: 512,
            block_count: 2 * 1024 * 1024,
            read_only: true,
        };
        assert_eq!(
            lun_columns(&lun),
            [
                "2",
                "Physical drive 1",
                "1 GiB",
                "512",
                "2097152",
                "Read-only"
            ]
        );
    }
}
