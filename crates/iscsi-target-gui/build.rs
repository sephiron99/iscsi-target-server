//! 실행 파일에 application manifest를 넣는다.
//!
//! manifest가 없으면 Windows는 옛 Common Controls(5)를 쓴다. 그러면 WinSafe가 만든
//! ComboBox의 목록이 펼쳐지지 않고, control도 Windows 10/11의 모습으로 그려지지 않는다.
//! 내용과 이유는 `app.manifest`에 있다.
//!
//! MSVC linker의 `/MANIFEST:EMBED /MANIFESTINPUT`으로 넣는다. 이때 linker는 Windows SDK의
//! `mt.exe`를 부르므로 그것이 PATH에 있어야 한다. WSL에서 cross-build할 때는 linker
//! wrapper(`.cargo/config.toml` 주석의 msvc-wsl-rust)가 SDK의 bin을 PATH에 두고 manifest를
//! Windows 쪽 경로로 넘긴다.

use std::path::Path;

fn main() {
    println!("cargo:rerun-if-changed=app.manifest");
    println!("cargo:rerun-if-changed=build.rs");

    // 지원하는 target은 MSVC뿐이다. 아래 인자는 MSVC linker의 것이다.
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    if target_os != "windows" || target_env != "msvc" {
        return;
    }

    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")
        .expect("cargo sets CARGO_MANIFEST_DIR for build scripts");
    let manifest = Path::new(&manifest_dir).join("app.manifest");
    println!("cargo:rustc-link-arg-bins=/MANIFEST:EMBED");
    println!(
        "cargo:rustc-link-arg-bins=/MANIFESTINPUT:{}",
        manifest.display()
    );
    // 실행 권한(asInvoker)은 `app.manifest`에 적었다. linker가 같은 항목을 또 만들면 둘이
    // 합쳐지면서 겹치므로 linker 쪽은 끈다.
    println!("cargo:rustc-link-arg-bins=/MANIFESTUAC:NO");
}
