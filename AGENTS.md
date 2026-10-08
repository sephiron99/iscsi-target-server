# AGENTS.md

## 적용 범위와 언어

이 문서는 저장소 전체에 적용한다.

이 프로젝트의 작업 설명, 진행 보고, 설계 문서, 사용자 대상 문구와 커밋 메시지는 기본적으로 한글로 작성한다. 다만 Rust 식별자, 공개 API 이름, RFC 필드명, 프로토콜 키, 명령어와 표준 명칭은 정확성을 위해 영문 원문을 유지한다. 코드 주석은 복잡한 프로토콜 의도와 제약을 설명할 때 한글로 작성하되, 해당 RFC 절을 함께 표시한다.

## 프로젝트 목표

이 프로젝트는 [TalAloni/iSCSIConsole](https://github.com/TalAloni/iSCSIConsole)을 목표 대상으로 삼아 Rust로 새로 작성하는 사용자 공간 iSCSI Target Server이다. iSCSIConsole은 기능과 상호운용성의 참고 자료일 뿐이며, 이 프로젝트는 그 코드를 가져오거나 번역해 쓰지 않는다. C# 클래스 구조, 스레딩 방식, 전역 상태, Windows 전용 설계도 따르지 않고, Rust의 소유권, 명시적 상태 머신, 모듈 경계와 오류 처리를 활용해 표준에서부터 설계한다.

요구사항이 충돌할 때는 다음 순서를 따른다.

1. RFC 7143 및 관련 SCSI 표준
2. 표준 준수 Initiator와의 실제 상호운용성
3. 원본 iSCSIConsole의 의도된 외부 동작
4. 현재 로컬 구현의 세부 동작

원본 동작과 표준이 충돌하면 표준을 우선하고, 호환성에 영향이 있다면 의도적인 차이를 문서화한다.

## 지원 target

이 Target Server의 지원 target은 Windows 10과 Windows 11뿐이다. 그 외 운영체제(Linux, macOS, BSD, Windows 8.1 이하 등)는 지원, 검증과 배포 대상에서 배제한다.

- Windows 10, 11은 반드시 지원되어야 한다.
- Windows에서 USB memory 저장장치도 Storage Backend로 반드시 지원되어야 한다.
- Windows 이외 target을 위한 기능, platform backend, packaging과 호환성 작업을 추가하지 않는다.
- 설계나 구현이 Windows와 다른 target 사이에서 충돌하면 Windows 동작을 기준으로 결정한다.
- WSL/Linux host에서의 build와 test는 개발 편의를 위한 것이며 해당 target을 지원한다는 의미가 아니다.
- 이 제한은 서버가 실행되는 target에 대한 것이다. Linux open-iscsi 등 다른 운영체제의 Initiator와의 상호운용성 검증은 그대로 유지한다.

## 완료와 배포 원칙

먼저 실제로 동작하고 검증된 Target Server를 완성한다. PDU 등 재사용 가능한 core는 나중에 별도 크레이트로 분리할 수 있도록 경계를 유지하지만, 프로젝트 완성 전에는 물리적으로 분리하거나 공개 API를 성급히 고정하지 않는다.

사용자가 명시적으로 요청하지 않는 한 다음 작업을 하지 않는다.

- workspace를 출판 단위의 여러 크레이트로 분리
- crates.io 이름 확보를 위한 크레이트 이름 변경
- 배포만을 위한 메타데이터 추가 및 공개 API 안정화
- `cargo publish`, release/tag 생성 또는 외부 배포

`cargo publish`는 서버의 end-to-end 동작, Initiator 상호운용성, 보안 강화, 문서화, API 검토, 라이선스 결정을 모두 마친 뒤 사용자의 명시적 승인으로 수행하는 마지막 과정이다.

## 목표 아키텍처

의존성은 아래 방향으로만 흐르게 한다.

```text
애플리케이션 / CLI / 관리 기능
    -> Target 서비스 / Connection / Session
        -> SCSI Target / Storage backend 인터페이스
        -> 재사용 가능한 iSCSI protocol core
```

protocol core가 Target 설정, 디스크 경로, 로깅 정책, UI, 플랫폼 전용 저장소 코드에 의존하게 만들지 않는다.

### iSCSI protocol core

현재 `pdu` 크레이트는 향후 core 크레이트 후보이다. 다음과 같은 프로토콜 공통 기능을 둔다.

- BHS와 opcode 정의
- 타입이 있는 PDU 파싱과 직렬화
- AHS, padding, CRC32C digest 처리
- 바이트 스트림 frame 인코딩과 디코딩
- 프로토콜 값 타입과 검증 오류

기본 빌드는 async runtime에 독립적이어야 한다. Tokio 같은 runtime 연동은 동일한 frame 구현을 감싸는 선택적 feature로 제공하며 별도의 프로토콜 구현을 만들지 않는다.

개발 중에는 Login text 파싱과 협상 메커니즘을 PDU 가까이에 둘 수 있다. 그러나 Target 정책, 응답 값 선택, 인증 정책, Connection/Session 상태, Target discovery와 저장소 설정은 최종 저수준 PDU 크레이트에 포함하지 않는다.

### Target 서비스

Target 계층은 다음 책임을 갖는다.

- Connection 수락과 수명주기 관리
- Login, Text, Logout, NOP, Reject, task management 처리
- Login 응답 정책과 Full Feature Phase 전환
- Session 식별, 복구, 명령 수명주기와 sequence number 관리
- iSCSI 명령을 SCSI 실행으로 연결
- Target discovery와 LUN 노출
- timeout, recovery와 연결 종료 정책

프로토콜 진행 상태는 명시적인 enum과 상태 머신으로 표현한다. 공유 전역 가변 상태보다 소유권이 분명한 구조와 메시지 전달을 선호한다.

### SCSI와 Storage

SCSI CDB 실행, status, sense data, residual count와 LUN 동작은 iSCSI transport 상태와 분리한다.

Storage backend는 capacity, block size, read, write, flush, read-only 여부 등 작은 기능 중심 인터페이스 뒤에 둔다. IMG/VHD/VMDK, 물리 디스크와 플랫폼 API는 backend 또는 platform 모듈에 격리한다. Win32나 UI 타입을 protocol/SCSI 계층에 노출하지 않는다.

원본 Windows Forms UI는 기능과 작업 흐름의 참고 자료이지 Rust UI 구조의 요구사항이 아니다. 정확한 라이브러리와 Target 서비스를 먼저 만들고 CLI 또는 관리 기능을 그 위에 구성한다.

## 향후 core 크레이트 분리 기준

다음 조건을 모두 만족할 때 별도 공개 크레이트 후보로 본다.

1. 특정 애플리케이션 정책이 아닌 프로토콜 공통 기능이다.
2. 둘 이상의 소비자가 재사용할 수 있고, 가능한 경우 Initiator와 Target 양쪽에서 쓸 수 있다.
3. 기본 API가 runtime과 플랫폼에 독립적이다.
4. 실제 Target, 디스크 목록, 애플리케이션 설정 없이 독립적으로 테스트할 수 있다.
5. 의존성이 작고 선택적 연동은 feature로 분리되어 있다.
6. 불변식과 실패가 타입과 오류로 표현된다.
7. semantic versioning을 감당할 만큼 공개 API가 안정되었다.
8. 외부 사용에 필요한 문서, wire fixture와 잘못된 입력 테스트가 있다.

지금은 이 경계를 지키되, Target Server 완성과 end-to-end 검증 전에는 물리적인 크레이트 분리나 publish를 수행하지 않는다.

## 현재 구현 기준선

이 문서를 작성한 시점의 protocol core에는 다음 기능이 있다.

- 고정 48-byte BHS와 opcode dispatch
- control, Login, SCSI PDU 타입
- AHS를 포함하는 frame 배치와 24-bit data length 처리
- CRC32C header/data digest, padding 검증과 크기 제한
- runtime 독립적인 `FrameCodec`과 선택적 Tokio adapter
- RFC 기본값을 포함한 송수신 방향별 `MaxRecvDataSegmentLength` 제한
- 엄격한 Login text 파싱과 조각난 text 누적, digest 협상을 포함한 Target 측 협상 상태

보통 다음 이정표는 Initiator의 Login 제안을 Target 응답 parameter로 만드는 정책/응답 생성 계층이며, 그다음은 완전한 Connection/Session 상태 구현이다. 실제 작업 전에는 반드시 현재 worktree와 테스트를 확인해 이 기준선이 여전히 맞는지 판단한다.

## Wire format 불변식

peer가 보낸 모든 바이트는 공격자 입력으로 취급한다. 파서는 타입이 있는 오류를 반환해야 하며 panic, 공격자 제어 크기만큼의 무제한 할당, 잘못된 상태의 묵시적 수용을 허용하지 않는다.

- 다중 byte 정수는 network byte order를 사용한다.
- frame 순서는 `BHS | AHS | HeaderDigest? | Data | padding | DataDigest?`이다.
- `TotalAHSLength`는 4-byte word 수이고 `DataSegmentLength`는 24-bit byte 수이다.
- Header Digest 범위는 BHS와 AHS이다.
- Data Digest 범위는 data와 실제 wire padding이다.
- data 길이가 0이면 Data Digest도 없다.
- Login Request/Response에는 협상된 digest를 적용하지 않는다.
- 불완전한 입력은 byte를 소비하지 않고 “완전한 frame 없음”으로 반환한다.
- buffer 확보와 할당 전에 길이, 산술 overflow와 설정된 제한을 검증한다.
- 알 수 없거나 아직 해석하지 않은 AHS와 정확한 Login text 원문을 보존할 수 있어야 한다.
- 불변 payload에는 zero-copy를 유지할 수 있는 `bytes::Bytes`를 우선한다.

로컬 receive 제한은 decode할 frame을 제한하고 peer가 선언한 receive 제한은 encode할 frame을 제한한다. 이 방향성을 명시적으로 유지한다. 협상이 완료되지 않았다면 RFC 기본 `MaxRecvDataSegmentLength`인 8192 byte를 사용한다.

Login text의 key와 value는 대소문자를 구분한다. 표준이 허용하는 decimal/hexadecimal 형식을 정확히 파싱한다. 유효한 stage 전환이 확정될 때 협상 값 집합을 원자적으로 적용한다. Continue/Transit 및 stage 제약을 검사하고, connection-scoped 값과 session-scoped 값을 구분하며, 이어 붙이는 text 총량에 상한을 둔다.

sequence number를 구현할 때는 serial number 산술과 wraparound를 명시한다. 일반 정수 비교만 사용해서는 안 된다.

## 기능 구현 방식

원본에 있는 기능 하나를 구현할 때 다음 순서로 진행한다.

1. 원본의 관찰 가능한 외부 동작을 확인한다. 원본 코드는 동작을 이해하는 데만 쓰고 옮겨 적지 않는다.
2. 해당 동작을 지배하는 RFC/SCSI 요구사항과 경계 조건을 확인한다.
3. 코드를 쓰기 전에 Rust 소유권, 상태와 모듈 경계를 정한다.
4. 공개 경계를 통해 테스트할 수 있는 가장 작은 vertical slice를 구현한다.
5. 정상 경로뿐 아니라 잘못된 입력과 상태 전환 테스트를 추가한다.

원본의 코드를 복사하거나 줄 단위로 번역하지 않는다. 구현은 표준 문서에서 출발한다.

## 외부 구현과 의존성

현재 결정은 `Masorubka1/iscsI-client-rs`를 가져오거나 복사하지 않고 로컬 PDU 구현을 계속 사용하는 것이다. 해당 구현은 client 중심의 범위와 API 경계 때문에 이 Target의 재사용 가능한 protocol core보다 적합하지 않다. 사용자가 명시적으로 재검토를 요청할 때만 최신 기능, 유지보수 상태와 라이선스 호환성을 다시 조사한다.

의존성을 추가하기 전에 어떤 불변식이나 상당한 구현 부담을 대신하는지 설명한다. 작고 감사 가능한 구현이면 core에 불필요한 의존성을 추가하지 않는다. runtime, tracing, 인증과 platform 연동은 보편적으로 필요하지 않으면 feature로 분리한다.

`unsafe`를 피한다. 플랫폼 I/O나 zero-copy 연동 때문에 꼭 필요하면 안전한 인터페이스 뒤에 격리하고 모든 safety invariant를 문서화하며 집중 테스트를 추가한다. 네트워크나 디스크 입력으로 도달할 수 있는 production 경로에서는 `unwrap`과 `expect`를 사용하지 않는다.

## 보안과 자원 제한

- frame 크기에 쓰이는 덧셈, 곱셈, offset과 정수 변환을 검사한다.
- 할당이나 buffering 전에 프로토콜 제한과 설정 제한을 적용한다.
- Login continuation text, outstanding command, queued data, Connection, Session과 recovery state에 상한을 둔다.
- 잘못된 padding, digest, flag, stage 전환과 지원하지 않는 필수 parameter를 결정적으로 거부한다.
- parsing 오류, 정책 거절과 transport I/O 오류를 구분한다.
- credential, CHAP secret, 인증 정보와 민감한 raw payload를 로그로 남기지 않는다.
- CHAP 구현 시 검증된 암호 primitive와 필요한 constant-time 비교를 사용하고 secret 수명을 명시한다.
- 인터페이스가 안정되면 frame/PDU/Login text/state machine에 fuzzing 또는 property test를 추가한다.

## 테스트와 검증

변경 범위에 맞는 검증을 실행한다. protocol core 변경의 전체 검증 기준은 다음과 같다.

```sh
cargo fmt --all -- --check
cargo cross test --no-default-features
cargo cross test --all-features
cargo cross clippy --all-targets --all-features -- -D warnings
git diff --check
```

`.cargo/config.toml`의 기본 build target은 `i686-pc-windows-gnu`이다. WSL host에서는 `cargo cross`가 mingw-w64 toolchain을 구성하고 WSL interop으로 Windows test binary를 실행한다. `cargo cross` 없이 `cargo test`를 직접 실행하면 linker를 찾지 못해 실패한다.

관련 변경에는 다음 테스트를 포함한다.

- RFC 예제 또는 독립적으로 확인한 고정 wire fixture
- Header/Data Digest 조합과 digest 손상
- AHS, padding, zero-length data와 최대/경계 길이
- 의미 있는 모든 byte 경계에서 잘린 입력
- 한 buffer의 여러 frame과 불완전한 마지막 frame
- 잘못된 flag, opcode, reserved field, text와 상태 전환
- 방향별 협상 제한과 continuation 누적 상한
- 임의 peer 입력에서 panic이 발생하지 않음

동일 구현의 serialize/parse round trip만으로 직렬화를 검증하지 않는다. 고정된 예상 byte 또는 독립적인 두 번째 기준을 사용한다. 서버 완료 전 Linux open-iscsi와 Windows Initiator를 포함한 실제 상호운용성 테스트를 추가한다.

## Worktree와 Git 규칙

수정 전에 `git status`를 확인한다. worktree에는 사용자 또는 다른 작업의 미완성 변경이 있을 수 있으므로 보존하고, 관련 없는 파일까지 광범위하게 고치지 않는다.

- 파괴적인 Git 명령으로 변경을 버리지 않는다.
- 사용자가 명시적으로 요청하지 않으면 commit, amend, push, tag 또는 release하지 않는다.
- 요청된 commit은 한 가지 논리 변경에 집중하고, 손대지 않은 관련 없는 변경을 보고한다.
- `Cargo.lock`을 직접 편집하거나 삭제하지 않는다. 의존성 해석이 의도적으로 바뀔 때만 Cargo가 갱신하게 하고, commit 요청 시 해당 생성 변경도 관련 commit에 포함한다.
- 정리 작업의 일부로 라이선스나 publish metadata를 변경하지 않는다.

## 라이선스와 출처

iSCSIConsole은 참고 자료일 뿐이고 이 프로젝트에는 그 코드가 들어 있지 않다. 이 상태를 유지한다: LGPL-3.0인 iSCSIConsole을 포함해 외부 프로젝트의 코드를 복사하거나 번역해 넣지 않는다. 꼭 가져와야 할 코드가 생기면 먼저 소유자에게 알리고, 승인된 경우에만 라이선스 호환성을 확인한 뒤 출처와 고지를 기록한다.

이 프로젝트의 라이선스는 소유자가 GPL 버전 3 또는 그 이후 버전(`GPL-3.0-or-later`)으로 결정했다. 전문은 저장소의 `LICENSE`에 있고 `Cargo.toml`의 `license`에 선언한다. 새 의존성이나 가져오는 코드는 GPL-3.0과 호환되는 라이선스여야 한다.

publish 조건은 최종 배포 전에 소유자가 결정한다. 명시적인 결정 없이 라이선스를 바꾸거나 package를 publish하지 않는다. 전체 의존성의 라이선스 감사는 배포 전 작업으로 남아 있다.

## 기본 이정표 순서

사용자가 우선순위를 바꾸지 않는 한 다음 순서로 완성을 진행한다.

1. wire/PDU core 완성과 강화
2. Login 정책, 응답 생성과 Connection 상태
3. Session, sequencing, command 추적, Logout, recovery와 discovery
4. SCSI command 실행, status, sense, residual과 LUN 동작
5. Storage 인터페이스와 안전한 raw file/image backend, 이후 platform backend
6. Target daemon과 설정/관리 인터페이스
7. Initiator 상호운용성, 장시간 실행, 비정상 입력과 recovery 테스트
8. 재사용 크레이트 추출, API 안정화, 문서화와 라이선스 감사
9. 명시적으로 승인된 마지막 단계로 publish
10. VHD/VMDK 가상 디스크 포맷 지원 — 위의 모든 과업이 완성된 뒤 최후 순위

VHD/VMDK는 10번에 도달하기 전에는 조사, 의존성 추가와 구현을 시작하지 않는다. 그때까지 지원하는 image backend는 raw IMG/file뿐이다.

아키텍처, 검증 명령 또는 배포 계획이 실질적으로 바뀌면 이 문서를 갱신한다.
