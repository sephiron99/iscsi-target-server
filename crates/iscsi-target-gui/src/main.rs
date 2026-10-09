//! `iscsi-target-gui` — iSCSI Target Server의 Windows GUI.
//!
//! 아직 구현하지 않은 자리이다. 패키지 경계만 먼저 잡아 두었고, 화면과 기능은
//! plan.md 9단계에서 채운다. 지금은 `iscsi-targetd`를 사용한다.

use std::process::ExitCode;

fn main() -> ExitCode {
    eprintln!("iscsi-target-gui is not implemented yet. Use iscsi-targetd.");
    ExitCode::FAILURE
}
