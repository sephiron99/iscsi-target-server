//! LUN 하나를 더하거나 고치는 modal dialog.
//!
//! 입력 칸의 값은 [`LunForm`]으로 모아 검증한다. 고른 backend가 쓰지 않는 칸은
//! 비활성으로 둔다.

use std::cell::RefCell;
use std::rc::Rc;

use iscsi_target_server::LunConfig;
use winsafe::{self as w, co, gui, prelude::*};

use crate::settings::{BackendKind, LunForm};
use crate::{controls, file_dialog};

/// dialog를 띄우고 닫힐 때까지 기다린다. OK로 닫으면 검증된 LUN을, 취소하면 `None`을
/// 돌려준다.
///
/// `accept`는 OK를 눌렀을 때 불린다. 오류를 돌려주면 그 문구를 보여 주고 dialog를
/// 닫지 않는다. LUN 번호가 겹치는지처럼 dialog 밖의 상태에 달린 검증에 쓴다.
pub fn show(
    parent: &gui::WindowMain,
    title: &str,
    form: &LunForm,
    accept: impl Fn(&LunConfig) -> Result<(), String> + 'static,
) -> w::AnyResult<Option<LunConfig>> {
    let dialog = LunDialog::new(title, form, Rc::new(accept));
    dialog.wnd.show_modal(parent)?;
    Ok(dialog.result.borrow_mut().take())
}

type Accept = Rc<dyn Fn(&LunConfig) -> Result<(), String>>;

#[derive(Clone)]
struct LunDialog {
    wnd: gui::WindowModal,
    lun: gui::Edit,
    kind: gui::ComboBox,
    path: gui::Edit,
    browse: gui::Button,
    block_size: gui::Edit,
    block_count: gui::Edit,
    device_number: gui::Edit,
    drive_letter: gui::Edit,
    read_only: gui::CheckBox,
    durable_flush: gui::CheckBox,
    virtual_disk_identity: gui::CheckBox,
    ok: gui::Button,
    cancel: gui::Button,
    accept: Accept,
    result: Rc<RefCell<Option<LunConfig>>>,
}

const LABEL_X: i32 = 14;
const FIELD_X: i32 = 136;
const ROW_HEIGHT: i32 = 30;

impl LunDialog {
    fn new(title: &str, form: &LunForm, accept: Accept) -> Self {
        let wnd = gui::WindowModal::new(gui::WindowModalOpts {
            title,
            size: gui::dpi(440, 356),
            ..Default::default()
        });

        let row = |index: i32| 12 + index * ROW_HEIGHT;
        let label = |text: &str, index: i32| {
            let _ = gui::Label::new(
                &wnd,
                gui::LabelOpts {
                    text,
                    position: gui::dpi(LABEL_X, row(index) + 4),
                    size: gui::dpi(FIELD_X - LABEL_X - 6, 20),
                    ..Default::default()
                },
            );
        };
        let edit = |text: &str, index: i32, width: i32| {
            gui::Edit::new(
                &wnd,
                gui::EditOpts {
                    text,
                    position: gui::dpi(FIELD_X, row(index)),
                    width: gui::dpi_x(width),
                    ..Default::default()
                },
            )
        };
        let check = |text: &str, index: i32, checked: bool| {
            gui::CheckBox::new(
                &wnd,
                gui::CheckBoxOpts {
                    text,
                    position: gui::dpi(FIELD_X, row(index) + 2),
                    size: gui::dpi(290, 20),
                    check_state: if checked {
                        co::BST::CHECKED
                    } else {
                        co::BST::UNCHECKED
                    },
                    ..Default::default()
                },
            )
        };

        // control은 만든 순서가 tab 순서다.
        label("LUN number:", 0);
        let lun = edit(&form.lun, 0, 70);
        label("Backend:", 1);
        let kind = gui::ComboBox::new(
            &wnd,
            gui::ComboBoxOpts {
                position: gui::dpi(FIELD_X, row(1)),
                width: gui::dpi_x(290),
                items: &BackendKind::ALL.map(BackendKind::label),
                selected_item: Some(form.kind.index()),
                ..Default::default()
            },
        );
        label("Image file:", 2);
        let path = edit(&form.path, 2, 204);
        let browse = gui::Button::new(
            &wnd,
            gui::ButtonOpts {
                text: "&Browse...",
                position: gui::dpi(FIELD_X + 210, row(2) - 1),
                width: gui::dpi_x(80),
                height: gui::dpi_y(25),
                ..Default::default()
            },
        );
        label("Block size:", 3);
        let block_size = edit(&form.block_size, 3, 90);
        label("Block count:", 4);
        let block_count = edit(&form.block_count, 4, 130);
        label("Disk number:", 5);
        let device_number = edit(&form.device_number, 5, 70);
        label("Drive letter:", 6);
        let drive_letter = edit(&form.drive_letter, 6, 50);
        let read_only = check("&Read-only", 7, form.read_only);
        let durable_flush = check("&Flush writes to the disk (durable)", 8, form.durable_flush);
        let virtual_disk_identity = check(
            "&Virtual disk identity (same-PC Initiator)",
            9,
            form.virtual_disk_identity,
        );
        // Enter는 IDOK, ESC는 IDCANCEL command로 온다. 버튼 ID를 거기에 맞춘다.
        let ok = gui::Button::new(
            &wnd,
            gui::ButtonOpts {
                text: "OK",
                position: gui::dpi(254, 318),
                width: gui::dpi_x(82),
                height: gui::dpi_y(26),
                control_style: co::BS::DEFPUSHBUTTON,
                ctrl_id: co::DLGID::OK.raw(),
                ..Default::default()
            },
        );
        let cancel = gui::Button::new(
            &wnd,
            gui::ButtonOpts {
                text: "Cancel",
                position: gui::dpi(344, 318),
                width: gui::dpi_x(82),
                height: gui::dpi_y(26),
                ctrl_id: co::DLGID::CANCEL.raw(),
                ..Default::default()
            },
        );

        let new_self = Self {
            wnd,
            lun,
            kind,
            path,
            browse,
            block_size,
            block_count,
            device_number,
            drive_letter,
            read_only,
            durable_flush,
            virtual_disk_identity,
            ok,
            cancel,
            accept,
            result: Rc::new(RefCell::new(None)),
        };
        new_self.events();
        new_self
    }

    fn events(&self) {
        self.wnd.on().wm_create({
            let this = self.clone();
            move |_| {
                this.show_kind();
                this.lun.focus()?;
                Ok(0)
            }
        });

        self.kind.on().cbn_sel_change({
            let this = self.clone();
            move || {
                this.show_kind();
                Ok(())
            }
        });

        self.browse.on().bn_clicked({
            let this = self.clone();
            move || {
                let chosen = file_dialog::open(
                    this.wnd.hwnd(),
                    &[("Disk images", "*.img;*.raw;*.bin"), ("All files", "*.*")],
                )?;
                if let Some(chosen) = chosen {
                    this.path.set_text(&chosen)?;
                }
                Ok(())
            }
        });

        self.ok.on().bn_clicked({
            let this = self.clone();
            move || {
                let checked = this
                    .form()?
                    .to_config()
                    .and_then(|lun| (this.accept)(&lun).map(|()| lun));
                match checked {
                    Ok(lun) => {
                        *this.result.borrow_mut() = Some(lun);
                        this.wnd.close();
                    }
                    Err(message) => {
                        this.wnd.hwnd().MessageBox(
                            &message,
                            "LUN",
                            co::MB::OK | co::MB::ICONWARNING,
                        )?;
                    }
                }
                Ok(())
            }
        });

        self.cancel.on().bn_clicked({
            let this = self.clone();
            move || {
                this.wnd.close();
                Ok(())
            }
        });
    }

    fn selected_kind(&self) -> BackendKind {
        self.kind
            .items()
            .selected_index()
            .and_then(BackendKind::from_index)
            .unwrap_or(BackendKind::File)
    }

    /// 고른 backend가 쓰는 칸만 활성으로 둔다.
    fn show_kind(&self) {
        let kind = self.selected_kind();
        self.path.hwnd().EnableWindow(kind.uses_path());
        self.browse.hwnd().EnableWindow(kind.uses_path());
        self.block_size.hwnd().EnableWindow(kind.uses_block_size());
        self.block_count
            .hwnd()
            .EnableWindow(kind.uses_block_count());
        self.device_number
            .hwnd()
            .EnableWindow(kind.uses_device_number());
        self.drive_letter
            .hwnd()
            .EnableWindow(kind.uses_drive_letter());
        self.durable_flush
            .hwnd()
            .EnableWindow(kind.uses_durable_flush());
        self.virtual_disk_identity
            .hwnd()
            .EnableWindow(kind.uses_virtual_disk_identity());
    }

    fn form(&self) -> w::AnyResult<LunForm> {
        Ok(LunForm {
            lun: controls::text(&self.lun)?,
            kind: self.selected_kind(),
            path: controls::text(&self.path)?,
            block_size: controls::text(&self.block_size)?,
            block_count: controls::text(&self.block_count)?,
            device_number: controls::text(&self.device_number)?,
            drive_letter: controls::text(&self.drive_letter)?,
            read_only: self.read_only.is_checked(),
            durable_flush: self.durable_flush.is_checked(),
            virtual_disk_identity: self.virtual_disk_identity.is_checked(),
        })
    }
}
