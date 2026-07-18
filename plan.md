# iSCSI Target Server 남은 작업 계획

최종 갱신: 2026-07-18

## 상태 표기

- `[ ]`: 시작 전
- `[-]`: 진행 중이거나 미커밋 상태
- `[x]`: 완료 및 검증됨

## 계획 원칙

- RFC 7143과 관련 SCSI 표준을 원본 iSCSIConsole 구현보다 우선한다.
- protocol core, Target/Session, SCSI, Storage, 관리 UI의 의존 방향을 분리한다.
- 먼저 end-to-end로 동작하는 Target Server를 완성한다.
- PDU 등 core의 별도 크레이트 분리와 publish는 프로젝트 완성 후 마지막 단계에서 수행한다.
- 각 단계는 정상 동작뿐 아니라 잘못된 peer 입력, 자원 제한과 상태 전환 테스트를 포함해야 완료로 본다.

## 현재 출발점

다음 기능은 구현되어 있으며 이후 작업의 기반으로 사용한다.

- 고정 48-byte BHS와 opcode별 PDU 표현
- control, Login, SCSI PDU 파싱과 직렬화
- AHS, padding, CRC32C Header/Data Digest를 포함한 frame codec
- runtime 독립적인 `FrameCodec`과 선택적 Tokio codec
- 송수신 방향별 data segment 크기 제한
- Login text parsing과 Target 측 frame parameter 협상

현재 Login 협상 관련 변경은 worktree에 미커밋 상태로 남아 있으므로 1단계에서 먼저 정리한다.

## 1. 현재 Login 협상 변경 완료

- [x] `negotiation.rs`와 연관된 Login/frame/codec 변경 전체 검토
- [x] Login text 원문 보존, 조각 누적과 stage 전환 경계 테스트 보강
- [x] Digest와 `MaxRecvDataSegmentLength` 협상 결과가 성공 시점에만 원자적으로 적용되는지 확인
- [x] 오류 타입과 공개 API 이름 검토
- [x] no-default/all-features 테스트, clippy와 format 검증
- [x] 현재 변경을 하나의 집중된 commit으로 정리

완료 조건:

- Login 협상 단위 테스트가 성공하고 codec 설정 반영 전후의 상태가 명확하다.
- 네트워크 입력으로 도달 가능한 경로에 panic과 무제한 누적이 없다.

## 2. Target Login 정책과 응답 생성

- [x] `TargetLoginPolicy`와 협상 가능한 값/기본값 정의
- [x] `AuthMethod`, `InitiatorName`, `TargetName`, `SessionType` 처리
- [x] normal/discovery session 구분과 허용 정책
- [x] 지원하는 operational key의 제안, 선택, 거부 규칙 구현
- [x] Initiator 제안에서 `LoginResponse` text와 status class/detail 생성
- [x] Continue/Transit 조합과 여러 Login PDU에 걸친 응답 분할
- [x] 잘못된 stage, 필수 key 누락과 지원 불가 값의 일관된 거부
- [x] 협상 완료 후 `FrameConfig` 전환을 Connection 계층에 전달

완료 조건:

- 입력 Login PDU 시퀀스에 대해 다음 응답 PDU와 상태 전환을 결정할 수 있다.
- 정상 로그인과 대표적인 거부 사유가 고정 wire fixture로 검증된다.

## 3. 인증, Connection과 Session 상태

- [x] 인증 없음과 단방향 CHAP 정책 지원
- [x] 검증된 암호 primitive 사용, secret 비노출과 필요한 constant-time 비교
- [x] Connection 상태 머신 구현
  - SecurityNegotiation
  - LoginOperationalNegotiation
  - FullFeaturePhase
  - Logout/Closed
- [x] ISID, TSIH, CID와 connection reinstatement 규칙
- [x] Session 생성, 조회, 종료와 자원 상한
- [x] `CmdSN`, `ExpCmdSN`, `MaxCmdSN`, `StatSN`, `ExpStatSN` 관리
- [x] serial number wraparound 비교와 command window 검증
- [x] timeout, protocol error와 transport error에 따른 종료 정책

완료 조건:

- TCP Connection 하나가 Login부터 Full Feature Phase와 정상 종료까지 진행한다.
- 잘못된 sequence number와 상태에 맞지 않는 PDU가 결정적으로 거부된다.

## 4. 제어 PDU와 Discovery

- [x] NOP-Out/NOP-In keepalive 및 ping 응답
- [x] Text Request/Response의 continuation 처리
- [x] discovery session의 `SendTargets` 구현
- [x] Logout Request/Response와 reason별 종료 처리
- [x] Reject PDU 생성과 원인별 정책
- [x] Task Management Request/Response 기본 기능
- [x] Async Message PDU 타입과 필요한 Target 알림 검토
- [x] 지원하지 않는 기능의 명시적 응답과 ERL 0 정책 정의
- [ ] Linux `open-iscsi`를 사용한 실제 discovery 상호운용성 검증

완료 조건:

- open-iscsi가 discovery를 수행하고 Target 목록을 받을 수 있다.
- keepalive, Logout과 잘못된 PDU 처리 후 Connection 상태가 일관된다.

## 5. SCSI 명령 실행 계층

- [x] CDB 공통 파싱과 LUN dispatch
- [x] `TEST UNIT READY`
- [x] `INQUIRY`와 필수 VPD page
- [x] `REQUEST SENSE`
- [x] `READ CAPACITY (10/16)`
- [x] `REPORT LUNS`
- [x] `MODE SENSE (6/10)`의 필요한 최소 page
- [x] `READ (10/12/16)`
- [x] `WRITE (10/12/16)`
- [x] `SYNCHRONIZE CACHE (10/16)`
- [x] unsupported/invalid CDB의 CHECK CONDITION과 sense data 생성
- [x] SCSI status, sense, underflow/overflow와 residual count 검증
- [ ] Data 전송 경로를 통한 Initiator block read/write/flush 통합 검증

완료 조건:

- 메모리 또는 파일 backend를 사용해 Initiator가 LUN을 조회하고 block read/write/flush를 수행한다.
- 범위를 벗어난 I/O와 지원하지 않는 명령이 올바른 SCSI 오류로 변환된다.

## 6. iSCSI Data 전송 경로

- [ ] Immediate Data 처리
- [ ] InitialR2T와 unsolicited Data-Out 정책
- [ ] R2T 발행, `TTT`, `R2TSN`과 burst 추적
- [ ] Data-Out의 `DataSN`, `BufferOffset`, final bit와 중복/누락 검증
- [ ] Data-In segment 분할, `DataSN`, status 동봉과 residual 처리
- [ ] `FirstBurstLength`, `MaxBurstLength`, `MaxOutstandingR2T` 적용
- [ ] `DataPDUInOrder`, `DataSequenceInOrder` 지원 범위 결정
- [ ] backpressure와 connection별 buffered byte 상한

완료 조건:

- 작은 I/O와 여러 segment/burst로 나뉜 대용량 I/O가 모두 동작한다.
- 순서 오류, 중복, 누락과 크기 초과가 메모리 폭증 없이 처리된다.

## 7. Storage backend

- [ ] capacity, block size, read, write, flush, read-only 상태를 제공하는 backend trait
- [ ] 정렬, 범위, short I/O와 동시 접근 규칙
- [ ] 테스트용 memory backend
- [ ] raw IMG/file backend와 파일 크기 기반 LUN 생성
- [ ] sparse file 및 durable flush 정책
- [ ] read-only LUN과 write protection sense 처리
- [ ] VHD/VMDK 지원 범위와 외부 라이브러리 도입 여부 조사
- [ ] Windows physical disk/volume backend를 별도 platform 모듈로 격리
- [ ] backend 오류를 SCSI sense로 변환하는 규칙

완료 조건:

- protocol/Session 계층이 파일 경로나 Win32 타입을 알지 않고 backend를 사용할 수 있다.
- 여러 Session의 동시 I/O, flush와 종료 시 데이터 일관성이 검증된다.

## 8. Target daemon, 설정과 CLI

- [ ] TCP listener와 connection task 수명주기
- [ ] bind 주소, port, Target IQN, LUN과 인증 설정 모델
- [ ] 설정 파일 load/validate/save와 안전한 secret 처리
- [ ] Target/LUN 추가, 제거와 상태 조회를 위한 service API
- [ ] start, stop, graceful shutdown과 active session 정리
- [ ] 구조화된 logging과 민감 정보 필터링
- [ ] headless 실행용 CLI
- [ ] daemon과 CLI 통합 테스트

완료 조건:

- GUI 없이 설정 파일과 CLI만으로 Target을 실행하고 정상 종료할 수 있다.
- 관리 기능이 protocol 내부 타입을 직접 변경하지 않고 service API를 통해 동작한다.

## 9. WinSafe 기반 Windows GUI

GUI는 [WinSafe](https://github.com/rodrigocfd/winsafe)의 native Win32 고수준 GUI API를 사용한다. 현재 공식 예시는 `winsafe`의 `gui` feature를 사용하며, 실제 구현을 시작할 때 최신 안정 버전과 필요한 최소 feature를 다시 확인한다.

### 구조

- [ ] Windows 전용 binary 또는 module로 격리하고 `#[cfg(windows)]` 적용
- [ ] `winsafe` 의존성을 Windows target 전용 dependency로 추가
- [ ] 먼저 `gui` feature만 사용하고 실제 control/API에 필요한 feature만 추가
- [ ] GUI가 daemon/CLI와 동일한 관리 service API를 사용하도록 구성
- [ ] WinSafe event loop와 Target async runtime을 분리
- [ ] network/storage 작업은 GUI thread에서 실행하지 않고 channel로 명령과 event 전달
- [ ] background event를 안전하게 UI thread로 전달하고 종료 순서를 명시
- [ ] non-Windows 기본 빌드와 protocol core에 Win32 의존성이 유입되지 않도록 검증

### 화면과 기능

- [ ] 메인 창: 서버 실행/중지, listen 주소와 전체 상태
- [ ] Target 목록: IQN, 활성 여부, 인증 정책 추가/수정/삭제
- [ ] LUN 관리: backend 선택, LUN 번호, 용량, block size, read-only 설정
- [ ] 이미지 파일 선택과 새 raw image 생성 dialog
- [ ] active Session/Connection 목록과 상세 상태
- [ ] 관리자가 선택한 Session/Connection 종료
- [ ] discovery 설정과 CHAP credential 관리
- [ ] 상태 bar, 오류 dialog와 최근 event/log 표시
- [ ] 설정 저장, 다시 읽기와 종료 전 변경 확인
- [ ] DPI scaling, keyboard navigation, tab order와 긴 한글/영문 문자열 표시

### 검증

- [ ] UI event가 장시간 I/O 중에도 block되지 않는지 확인
- [ ] backend/Target 변경 실패 시 UI model과 실제 service 상태가 어긋나지 않는지 확인
- [ ] start/stop 반복, 창 닫기와 daemon 종료 race 테스트
- [ ] Windows CI에서 GUI binary build/check
- [ ] 실제 Windows에서 high-DPI, 관리자 권한 필요 작업과 오류 표시 확인
- [ ] WinSafe MIT license와 최종 배포물의 고지 사항 기록

완료 조건:

- Windows 사용자가 GUI만으로 Target과 LUN을 구성하고 서버를 시작/중지할 수 있다.
- Session 상태를 확인하고 안전하게 종료할 수 있다.
- GUI를 제외한 빌드는 WinSafe에 의존하지 않는다.

## 10. 상호운용성, 보안과 안정성 강화

- [ ] Linux open-iscsi discovery/login/read/write/logout 시나리오
- [ ] Windows iSCSI Initiator discovery/login/read/write/logout 시나리오
- [ ] digest 조합과 협상 key 조합별 테스트
- [ ] 다중 Connection/Session과 다중 LUN 부하 테스트
- [ ] 장시간 실행, 재접속과 비정상 연결 종료 테스트
- [ ] frame/PDU/Login text/CDB/state machine fuzzing
- [ ] allocation, outstanding command와 queue 상한 검증
- [ ] 로그의 secret/raw payload 노출 감사
- [ ] I/O 오류, full disk, read-only와 backend 제거 시나리오
- [ ] 지원 범위와 알려진 제한 문서화

완료 조건:

- Linux와 Windows Initiator에서 반복 가능한 end-to-end 테스트가 성공한다.
- 임의 입력과 자원 고갈 시나리오에서 panic, deadlock과 무제한 메모리 증가가 없다.

## 11. 문서화와 최종 릴리스 준비

- [ ] 설치, 설정, CLI와 Windows GUI 사용 문서
- [ ] 지원하는 Login key, PDU, SCSI command와 backend 표
- [ ] 아키텍처와 상태 머신 문서
- [ ] 보안 모델, 제한값과 운영 권장사항
- [ ] 원본 iSCSIConsole 직접 번역 부분의 출처/revision 기록
- [ ] 전체 dependency와 라이선스 감사
- [ ] Windows 실행 파일 packaging 방식 결정
- [ ] release build와 재현 가능한 테스트 절차 정리

완료 조건:

- 새 사용자가 문서만으로 Target을 설치, 구성하고 Initiator를 연결할 수 있다.
- 지원 범위, 알려진 제한과 라이선스가 명확하다.

## 12. Core 크레이트 분리와 publish

이 단계는 1~11단계가 완료된 뒤에만 시작한다.

- [ ] protocol-general API와 Target 전용 정책의 최종 경계 검토
- [ ] PDU/frame/digest/error 기능을 runtime 독립 크레이트로 추출
- [ ] 선택적 Tokio adapter feature 분리
- [ ] public API, semantic versioning과 MSRV 결정
- [ ] 독립 fixture, malformed-input test와 crate 문서 완성
- [ ] package 이름, repository metadata와 Rust 크레이트 라이선스 결정
- [ ] 로컬 package 검증과 dry-run
- [ ] 사용자의 명시적 승인 후 마지막 작업으로 publish

완료 조건:

- 추출 후에도 Target Server의 전체 테스트와 상호운용성 테스트가 동일하게 성공한다.
- core 크레이트가 Target 설정, GUI, Storage와 async runtime에 기본 의존하지 않는다.

## 공통 검증 명령

```sh
cargo fmt --all -- --check
cargo test --no-default-features
cargo test --all-features
cargo clippy --all-targets --all-features -- -D warnings
git diff --check
```

Windows GUI가 추가된 뒤에는 Windows runner에서 GUI target의 build/check도 필수 검증에 포함한다.

## 참고 자료

- [TalAloni/iSCSIConsole](https://github.com/TalAloni/iSCSIConsole)
- [RFC 7143: Internet Small Computer System Interface](https://www.rfc-editor.org/rfc/rfc7143)
- [WinSafe 공식 저장소](https://github.com/rodrigocfd/winsafe)
- [WinSafe stable API 문서](https://docs.rs/winsafe)
