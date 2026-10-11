//! `iscsi-target-gui` — iSCSI Target Server의 Windows GUI.
//!
//! 창은 WinSafe의 UI thread에서 돌고, 서버는 [`controller`]가 만든 별도 thread의
//! Tokio runtime에서 돈다. 둘은 channel로만 이야기한다. UI thread는 network와
//! storage 작업을 직접 하지 않는다.
//!
//! - [`controller`]: 서버 시작/중지 명령을 받아 실행하고 결과를 event로 돌려준다
//! - [`logging`]: `tracing` 로그를 창의 로그 영역으로 넘긴다
//! - `window`: WinSafe 창과 control. Windows target에서만 컴파일한다

// 콘솔 창 없이 실행한다.
#![cfg_attr(windows, windows_subsystem = "windows")]

use std::process::ExitCode;

#[cfg_attr(not(windows), allow(dead_code))]
mod controller;
#[cfg_attr(not(windows), allow(dead_code))]
mod logging;
#[cfg(windows)]
mod window;

#[cfg(windows)]
fn main() -> ExitCode {
    // 첫 번째 인자가 있으면 설정 파일 경로로 미리 채운다.
    let initial_config_path = std::env::args_os().nth(1).map(std::path::PathBuf::from);
    match window::run(initial_config_path) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            window::show_fatal_error(&error.to_string());
            ExitCode::FAILURE
        }
    }
}

#[cfg(not(windows))]
fn main() -> ExitCode {
    eprintln!("iscsi-target-gui runs on Windows only.");
    ExitCode::FAILURE
}
