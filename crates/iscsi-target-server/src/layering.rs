//! 계층 경계를 지키는지 소스에서 확인하는 테스트.
//!
//! AGENTS.md의 "목표 아키텍처"가 정한 규칙 가운데 컴파일러가 검사하지 않는 것을 여기서
//! 검사한다. 새 모듈을 추가하면 [`LAYERS`]의 알맞은 묶음에 넣어야 한다.
//!
//! 테스트는 Windows에서 실행되어 소스를 경로로 읽을 수 없으므로 `include_str!`로 컴파일
//! 시점에 넣는다. 문자열 검사라서 `use crate::{a::X, b::Y}`처럼 중괄호 안에 적은 모듈
//! 이름은 보지 못한다.

/// 모듈 하나: `lib.rs`에 선언된 이름과 소스.
type Module = (&'static str, &'static str);

macro_rules! module {
    ($name:literal) => {
        ($name, include_str!(concat!($name, ".rs")))
    };
    ($name:literal, $path:literal) => {
        ($name, include_str!($path))
    };
}

/// byte와 PDU를 서로 바꾸는 계층. 자기 묶음의 모듈만 참조한다.
const WIRE: &[Module] = &[
    module!("bhs"),
    module!("opcode"),
    module!("error"),
    module!("digest"),
    module!("frame"),
    module!("login"),
    module!("control"),
    module!("scsi"),
];

/// SCSI 실행과 Storage backend. iSCSI를 모르고 자기 묶음의 모듈만 참조한다.
const SCSI_AND_STORAGE: &[Module] = &[
    module!("scsi_target"),
    module!("disk_identity"),
    module!("platform", "platform/windows.rs"),
];

/// 프로토콜 상태 머신과 설정. async runtime 없이 동작한다.
const PROTOCOL_AND_CONFIGURATION: &[Module] = &[
    module!("auth"),
    module!("login_policy"),
    module!("negotiation"),
    module!("target_login"),
    module!("session"),
    module!("serial"),
    module!("control_state"),
    module!("connection"),
    module!("config"),
    module!("config_file"),
    module!("management"),
];

/// Tokio로 실제 TCP 접속을 처리하는 계층. async runtime을 쓰는 것은 이 묶음뿐이다.
const TOKIO_SERVICE: &[Module] = &[
    module!("codec"),
    module!("connection_io"),
    module!("target_service"),
    module!("server"),
];

const LAYERS: &[&[Module]] = &[
    WIRE,
    SCSI_AND_STORAGE,
    PROTOCOL_AND_CONFIGURATION,
    TOKIO_SERVICE,
];

/// 크레이트 루트. 모듈 선언과 `Pdu` 정의가 함께 있다.
const CRATE_ROOT: &str = include_str!("lib.rs");

/// 이 파일 자신. 검사 대상이 아니다.
const THIS_MODULE: &str = "layering";

/// `source`에서 `crate::<이름>` 형태로 참조한 모듈 이름들. 대문자로 시작하는 것은 모듈이
/// 아니라 크레이트 루트의 타입이나 상수이므로 제외한다.
fn referenced_modules(source: &str) -> Vec<&str> {
    let mut modules = Vec::new();
    for (start, _) in source.match_indices("crate::") {
        let rest = &source[start + "crate::".len()..];
        let end = rest
            .find(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
            .unwrap_or(rest.len());
        let name = &rest[..end];
        if name.starts_with(|character: char| character.is_ascii_lowercase())
            && !modules.contains(&name)
        {
            modules.push(name);
        }
    }
    modules
}

/// `lib.rs`의 `mod <이름>;` 선언에서 모듈 이름을 뽑는다.
fn declared_modules(root: &str) -> Vec<&str> {
    root.lines()
        .filter_map(|line| {
            let line = line.trim();
            let declaration = line
                .strip_prefix("pub mod ")
                .or(line.strip_prefix("mod "))?;
            declaration.strip_suffix(';')
        })
        .collect()
}

fn names(layer: &[Module]) -> Vec<&'static str> {
    layer.iter().map(|(name, _)| *name).collect()
}

#[test]
fn only_the_service_modules_use_the_async_runtime() {
    for layer in [WIRE, SCSI_AND_STORAGE, PROTOCOL_AND_CONFIGURATION] {
        for (name, source) in layer {
            assert!(
                !source.contains("tokio"),
                "`{name}` 모듈은 async runtime을 쓰지 않는 계층이다. Tokio 연동은 {:?}에 둔다",
                names(TOKIO_SERVICE)
            );
        }
    }
    assert!(
        !CRATE_ROOT.contains("tokio"),
        "crate root는 async runtime을 쓰지 않는다"
    );
}

#[test]
fn lower_layers_do_not_reference_upper_layers() {
    for layer in [WIRE, SCSI_AND_STORAGE] {
        let allowed = names(layer);
        for (name, source) in layer {
            for referenced in referenced_modules(source) {
                assert!(
                    allowed.contains(&referenced),
                    "`{name}` 모듈이 `{referenced}`를 참조한다. 이 계층은 {allowed:?}만 참조한다"
                );
            }
        }
    }
}

#[test]
fn every_module_belongs_to_a_layer() {
    let classified: Vec<&str> = LAYERS.iter().flat_map(|layer| names(layer)).collect();
    let declared = declared_modules(CRATE_ROOT);
    assert!(
        declared.len() > 20,
        "lib.rs에서 모듈 선언을 읽지 못했다: {declared:?}"
    );

    for module in &declared {
        if *module == THIS_MODULE {
            continue;
        }
        assert!(
            classified.contains(module),
            "`{module}` 모듈이 layering.rs의 어느 묶음에도 없다. LAYERS에 추가한다"
        );
    }
    for module in &classified {
        assert!(
            declared.contains(module),
            "layering.rs의 `{module}`이 lib.rs에 선언되어 있지 않다"
        );
        assert_eq!(
            classified.iter().filter(|other| other == &module).count(),
            1,
            "`{module}`이 둘 이상의 묶음에 들어 있다"
        );
    }
}

#[test]
fn reference_scanner_reads_module_paths_and_skips_root_items() {
    let source = "use crate::login::IscsiName;\nuse crate::{BHS_LEN, Pdu};\n\
                  let x = crate::scsi_target::MAX_LUN; crate::login::AuthMethod::None";
    assert_eq!(referenced_modules(source), ["login", "scsi_target"]);
    assert_eq!(
        declared_modules("pub mod bhs;\nmod control_state;\n#[cfg(test)]\nmod layering;\nuse x;"),
        ["bhs", "control_state", "layering"]
    );
}
