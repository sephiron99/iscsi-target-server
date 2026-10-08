# iSCSIConsole과의 기능 비교

원본: [TalAloni/iSCSIConsole](https://github.com/TalAloni/iSCSIConsole) master `8e31281` (2026-06-29 시점, 159개 C# 파일 전수 확인)
이 문서의 이 프로젝트 상태: plan.md 2026-10-08 기준 (미구현 항목 포함)

## 요약

- 이 프로젝트는 **프로토콜 정확성, 보안, 테스트**에서 원본을 앞선다: CHAP, CRC32C digest, Task Management, serial number 산술, 자원 상한, 113개 단위/통합 테스트.
- 원본이 앞선 영역은 **storage backend 다양성**(VHD dynamic, VMDK, dynamic volume, SPTI), **실전 검증 이력**, **실행 가능한 완제품**이라는 점이다.
- plan.md의 우선순위(8단계 daemon → 상호운용 검증)가 실전 검증과 완제품 격차를 겨냥한다. VHD/VMDK 격차는 모든 과업이 완성된 뒤 최후 순위(plan 13단계)로 미뤘다.

## 인증 (CHAP)

**iSCSIConsole에는 CHAP이 없다.** 소스 전체에서 `chap` 검색 결과 0건이며,
`ISCSI/ISCSI.Server/ISCSIServer.Login.cs:199`에서 항상 `AuthMethod=None`으로 응답한다.
대신 `OnAuthorizationRequest` 이벤트(`TargetEventArgs/AuthorizationRequestArgs.cs`)로
InitiatorName/ISID/endpoint 기반 허용·거부 훅만 제공한다.

이 프로젝트의 단방향 CHAP(`auth.rs`, `subtle` constant-time 비교 + `zeroize` secret 소거)은 원본에 없는 추가 기능이다.

## 프로토콜 계층 비교

| 기능                                   | iSCSIConsole                                                | 이 프로젝트                                           |
|----------------------------------------|-------------------------------------------------------------|-------------------------------------------------------|
| 기준 표준                              | RFC 3720                                                    | RFC 7143                                              |
| 인증                                   | 없음 (`AuthMethod=None` 고정)                               | None + 단방향 CHAP                                    |
| Header/Data Digest                     | 없음 (`None` 고정, CRC32C 미지원)                           | CRC32C 협상·검증                                      |
| Login 파라미터 협상                    | 있음                                                        | 있음                                                  |
| Discovery `SendTargets`                | 있음 (`ISCSIServer.TextRequest.cs`)                         | 있음                                                  |
| discovery session 명령 제한            | 있음 (Reject)                                               | 있음                                                  |
| Session/Connection reinstatement       | 있음 (`ISCSIServer.Login.cs`)                               | 있음                                                  |
| NOP keepalive (target발 probe)         | 있음 (`ConnectionManager.SendKeepAlive`)                    | 있음 (idle timeout 기반)                              |
| Task Management                        | **PDU 타입 자체가 없음** — 일반 Reject(CommandNotSupported) | Request/Response 기본 기능                            |
| Async Message                          | PDU 타입 없음                                               | 타입 있는 PDU                                         |
| Reject                                 | 있음                                                        | 있음                                                  |
| ERL                                    | 0                                                           | 0                                                     |
| MC/S (`MaxConnections`)                | 1 ("implementation limit")                                  | 1                                                     |
| `DataPDUInOrder`/`DataSequenceInOrder` | 기본값 Yes/Yes 고정                                         | Yes/Yes 고정                                          |
| sequence number wraparound 산술        | 일반 정수 비교 위주                                         | serial number 산술 (`serial.rs`)                      |
| peer 입력 자원 상한                    | 제한적                                                      | frame/text/buffered byte 상한 + bounded blocking 실행 |

원본의 기본/희망 파라미터 (`DefaultParameters.cs`, `ISCSIServer.Parameters.cs`):
`MaxRecvDataSegmentLength=262144`, `MaxBurstLength=262144`, `FirstBurstLength=65536`,
`MaxOutstandingR2T=16`, `CommandQueueSize=64`, `InitialR2T=Yes`, `ImmediateData=Yes`.

## SCSI 명령 비교

공통: `TEST UNIT READY`, `INQUIRY`(+VPD), `REQUEST SENSE`, `READ CAPACITY(10/16)`,
`REPORT LUNS`, `MODE SENSE(6)`, `READ(10/16)`, `WRITE(10/16)`, `SYNCHRONIZE CACHE(10)`.

원본에만 있는 것 (`ISCSI/SCSITarget/VirtualSCSITarget.cs`):

- `READ(6)` / `WRITE(6)`
- `RESERVE(6)` / `RELEASE(6)` — SCSI-2 reservation. 구식이지만 일부 클러스터 환경(예: ESXi VMFS)이 사용. plan 5단계에 검토 항목으로 추가할 가치가 있음
- `VERIFY(10/16)` — 실제 검증 없는 stub

이 프로젝트에만 있는 것:

- `READ(12)` / `WRITE(12)`
- `MODE SENSE(10)`
- `SYNCHRONIZE CACHE(16)`

VPD page: 원본은 Supported Pages, Unit Serial Number, Device Identification,
Block Limits, Block Device Characteristics 제공.

## Storage backend 비교 — 원본이 크게 앞선 유일한 영역

| backend                                     | iSCSIConsole (DiskAccessLibrary 1.6.3)        | 이 프로젝트                        |
|---------------------------------------------|-----------------------------------------------|------------------------------------|
| memory (RAM disk)                           | 있음 (GUI에서 생성)                           | 있음 (테스트용)                    |
| raw IMG/file                                | 있음                                          | 있음 (sparse 생성 + durable flush) |
| VHD fixed                                   | 있음 (생성 가능)                              | 없음 (plan 13단계, 최후 순위)      |
| VHD dynamic                                 | 있음                                          | 없음 (동일)                        |
| VMDK                                        | 있음                                          | 없음 (동일)                        |
| 물리 디스크 (Windows)                       | 있음                                          | 있음 (`platform/windows.rs`)       |
| basic volume                                | 있음                                          | volume lock/read 지원              |
| dynamic volume (소프트웨어 RAID)            | 있음                                          | 없음                               |
| SPTI pass-through (실 SCSI 장치에 CDB 전달) | 있음 (`ISCSI/Win32/SCSITarget/SPTITarget.cs`) | 없음, 계획에도 없음                |

원본 README가 내세우는 대표 기능이 가상 디스크 서빙이므로, 기능 격차의 본체는 **VHD(특히 dynamic) 지원**이다. 이 격차는 의도적으로 남겨 두며, plan 1~12단계가 모두 끝난 뒤 13단계에서 다룬다.

## 관리·운영 비교

| 항목                | iSCSIConsole                                                  | 이 프로젝트 (plan 포함)                            |
|---------------------|---------------------------------------------------------------|----------------------------------------------------|
| GUI                 | WinForms (target 추가, VHD/RAM disk 생성, 디스크/volume 선택) | WinSafe 계획 (9단계, 미구현)                       |
| 설정 저장/복원      | **없음 — 재시작마다 GUI로 재구성**                            | versioned TOML load/save + 외부 CHAP secret 파일   |
| CLI / headless 실행 | 없음                                                          | `iscsi-targetd` TOML 설정 daemon (단일 Target)     |
| Target 수           | 여러 Target (Login의 `TargetName`으로 선택)                   | 단일 Target만 허용 (의도적 차이, 여러 LUN은 가능)  |
| service API         | 이벤트 훅 수준                                                | Target/LUN 추가·제거·상태 조회 구현                |
| logging             | severity 로그 + 파일                                          | tracing 구조화 로깅 (secret/payload 미기록)        |
| 크로스플랫폼        | Windows + Mono(Linux/macOS/WinPE)                             | Windows 10/11 전용 (그 외 OS 배제)                 |
| initiator 구현      | basic client 포함 (`ISCSI.Client`)                            | 없음 (12단계 core 분리 시 양쪽 사용 가능성만 유지) |
| 라이브러리 배포     | NuGet package                                                 | 12단계 crates.io 계획                              |

## 구현 방식 차이

- 동시성: 원본은 target당 단일 워커 thread + 콜백 큐 (`SCSITarget.cs`,
  `VirtualSCSITarget.ExecuteCommand`는 "not thread-safe" 명시).
  이 프로젝트는 tokio task + service 전역 bounded blocking pool.
- 테스트: 원본은 자동 테스트 전무. 이 프로젝트는 113개 (wire fixture, malformed 입력, 실 TCP 왕복 포함).
- 라이선스: 원본 LGPL-3.0 — 직접 번역 부분은 출처/revision 기록 의무 (AGENTS.md 참고).

## 이 비교에서 나온 plan.md 반영 후보

- [ ] 5단계: `RESERVE(6)`/`RELEASE(6)` (필요 시 `READ(6)`/`WRITE(6)`, `VERIFY` stub) 지원 여부 결정
- 13단계(최후 순위) VHD/VMDK 조사 시 원본의 DiskAccessLibrary 지원 범위(fixed/dynamic VHD, VMDK, dynamic volume)를 기준선으로 사용
