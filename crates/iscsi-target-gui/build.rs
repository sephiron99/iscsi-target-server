//! 실행 파일에 application manifest를 넣는다.
//!
//! manifest가 없으면 Windows는 옛 Common Controls(5)를 쓴다. 그러면 WinSafe가 만든
//! ComboBox의 목록이 펼쳐지지 않고, control도 Windows 10/11의 모습으로 그려지지 않는다.
//! 내용과 이유는 `app.manifest`에 있다.
//!
//! manifest는 resource로 넣는다. linker의 `/MANIFESTINPUT`은 Windows SDK의 `mt.exe`를,
//! resource script는 `rc.exe`를 필요로 하는데, WSL에서 cross-build할 때는 둘 다 찾지
//! 못한다. 그래서 compile된 resource 파일(`.res`)을 여기서 직접 만들어 linker에 넘긴다.
//! `.res`를 object로 바꾸는 `cvtres.exe`는 linker와 같은 곳에 있어 따로 준비할 것이 없다.

use std::path::Path;

/// resource 종류 `RT_MANIFEST`.
const RT_MANIFEST: u16 = 24;
/// 실행 파일의 manifest가 쓰는 resource ID `CREATEPROCESS_MANIFEST_RESOURCE_ID`.
const MANIFEST_RESOURCE_ID: u16 = 1;

fn main() {
    println!("cargo:rerun-if-changed=app.manifest");
    println!("cargo:rerun-if-changed=build.rs");

    // 지원하는 target은 MSVC뿐이다. 아래 인자는 MSVC linker의 것이다.
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    if target_os != "windows" || target_env != "msvc" {
        return;
    }

    let manifest = std::fs::read("app.manifest").expect("app.manifest must be readable");
    let out_dir = std::env::var("OUT_DIR").expect("cargo sets OUT_DIR for build scripts");
    let resource = Path::new(&out_dir).join("manifest.res");
    std::fs::write(&resource, manifest_resource_file(&manifest))
        .expect("the resource file must be writable");

    // linker가 스스로 manifest를 만들어 넣으면 같은 resource가 둘이 된다.
    println!("cargo:rustc-link-arg-bins=/MANIFEST:NO");
    println!("cargo:rustc-link-arg-bins={}", resource.display());
}

/// manifest 하나만 담은 `.res` 파일의 내용.
///
/// `.res`는 resource entry를 이어 붙인 것이고, 32-bit 형식임을 알리는 빈 entry로
/// 시작한다. entry는 header와 data로 이루어지며 각각 4 byte 경계에 맞춘다.
fn manifest_resource_file(manifest: &[u8]) -> Vec<u8> {
    let mut file = resource_entry(0, 0, &[]);
    file.extend(resource_entry(RT_MANIFEST, MANIFEST_RESOURCE_ID, manifest));
    file
}

/// `RESOURCEHEADER`와 data. 종류와 이름은 둘 다 숫자 ID다.
fn resource_entry(kind: u16, id: u16, data: &[u8]) -> Vec<u8> {
    const HEADER_LENGTH: u32 = 32;
    /// `MOVEABLE | PURE | DISCARDABLE`. resource compiler가 쓰는 기본값이다.
    const MEMORY_FLAGS: u16 = 0x1030;
    /// 영어(미국). manifest는 언어와 무관하지만 관례를 따른다.
    const LANGUAGE: u16 = 0x0409;

    let data_length = u32::try_from(data.len()).expect("the manifest is far below 4 GiB");
    let mut entry = Vec::with_capacity(HEADER_LENGTH as usize + data.len() + 3);
    entry.extend(data_length.to_le_bytes());
    entry.extend(HEADER_LENGTH.to_le_bytes());
    // 0xFFFF로 시작하면 문자열이 아니라 숫자 ID라는 뜻이다.
    entry.extend([0xFFFF, kind, 0xFFFF, id].map(u16::to_le_bytes).concat());
    entry.extend(0u32.to_le_bytes()); // DataVersion
    entry.extend(if data.is_empty() { 0 } else { MEMORY_FLAGS }.to_le_bytes());
    entry.extend(if data.is_empty() { 0 } else { LANGUAGE }.to_le_bytes());
    entry.extend(0u32.to_le_bytes()); // Version
    entry.extend(0u32.to_le_bytes()); // Characteristics
    entry.extend(data);
    entry.resize(entry.len().next_multiple_of(4), 0);
    entry
}
