// pdu/src/lib.rs
//
// iSCSI PDU 계층 — 와이어 포맷과 타입 안전한 표현 사이의 변환
//
// 계층 구조:
//   ┌─────────────────────────────────────────┐
//   │ Pdu enum (타입 안전)                       │  ← 애플리케이션이 다루는 표현
//   ├─────────────────────────────────────────┤
//   │ 각 PDU 구조체 (LoginRequest, ScsiCommand)  │  ← named field 파싱
//   ├─────────────────────────────────────────┤
//   │ Bhs ([u8; 48])                            │  ← 저수준 word 접근
//   └─────────────────────────────────────────┘

pub mod auth;
pub mod bhs;
pub mod connection;
pub mod control;
mod control_state;
pub mod digest;
pub mod error;
pub mod frame;
pub mod login;
pub mod login_policy;
pub mod negotiation;
pub mod opcode;
pub mod platform;
pub mod scsi;
pub mod scsi_target;
pub mod serial;
pub mod session;
pub mod target_login;

// codec은 tokio-util 의존성이 필요하므로 feature로 분리.
// 순수 PDU 파싱/직렬화만 쓰는 경우 Tokio 의존성 없이 사용 가능.
#[cfg(feature = "codec")]
pub mod codec;
pub mod config;
#[cfg(feature = "codec")]
pub mod connection_io;
#[cfg(feature = "codec")]
pub mod target_service;

pub use auth::{ChapCredentials, ChapError, ChapExchange};
pub use bhs::{Bhs, BHS_LEN};
pub use config::{
    AuthenticationConfig, ChapAuthenticationConfig, ConfigError, DaemonConfig, ListenConfig,
    LunBackendConfig, LunConfig, TargetConfig,
};
pub use connection::{
    ConnectionCloseReason, ConnectionError, ConnectionOutput, ConnectionPhase,
    ConnectionStateMachine, ConnectionTimeoutKind, ConnectionTimeouts,
};
#[cfg(feature = "codec")]
pub use connection_io::{
    run_connection, run_connection_with_executor, BlockingStorageExecutor,
    BlockingStorageExecutorError, ConnectionIoError, DEFAULT_MAX_BLOCKING_STORAGE_OPERATIONS,
};
pub use control_state::{ControlError, DiscoveryTarget, DEFAULT_MAX_TEXT_SEQUENCE_LENGTH};
pub use error::{CodecError, FrameError, PduError};
pub use frame::{
    FrameCodec, FrameConfig, PduFrame, RawFrame, DEFAULT_MAX_RECV_DATA_SEGMENT_LENGTH,
    MAX_AHS_LENGTH, MAX_DATA_SEGMENT_LENGTH,
};
pub use login::{
    AuthMethod, AuthMethodError, IscsiName, IscsiNameError, SessionType, SessionTypeError,
};
pub use login_policy::{
    AuthenticationPolicy, DigestPolicy, ErrorRecoveryLevel, TargetLoginPolicy,
    TargetLoginPolicyError, TaskReporting,
};
pub use negotiation::{
    LoginContinuationError, LoginSide, LoginTransitionError, NegotiatedFrameParameters,
    NegotiationError, TargetLoginNegotiation, DEFAULT_MAX_LOGIN_TEXT_SEQUENCE_LENGTH,
    MIN_LOGIN_TEXT_SEQUENCE_LENGTH, MIN_MAX_RECV_DATA_SEGMENT_LENGTH,
};
pub use opcode::Opcode;
pub use scsi_target::{StorageError, StorageIoError, StorageIoOperation};
pub use serial::{SequenceError, SequenceState, SerialNumber32};
pub use session::{
    Session, SessionBinding, SessionError, SessionId, SessionIdentity, SessionRegistry,
    SessionRegistryLimits,
};
pub use target_login::{
    NegotiatedDataParameters, TargetLoginError, TargetLoginOutcome, TargetLoginProcessor,
};
#[cfg(feature = "codec")]
pub use target_service::{
    TargetService, TargetServiceConfig, TargetServiceError, TargetServiceSummary,
};

use bytes::{BufMut, Bytes, BytesMut};

use control::{
    AsyncMessage, LogoutRequest, LogoutResponse, NopIn, NopOut, Reject, TaskMgmtRequest,
    TaskMgmtResponse, TextRequest, TextResponse,
};
use login::{LoginRequest, LoginResponse};
use scsi::{R2t, ScsiCommand, ScsiDataIn, ScsiDataOut, ScsiResponse};

// ─── 통합 PDU 열거형 ───────────────────────────────────────────────────────
//
// opcode별 타입 PDU를 하나의 enum으로 통합.
// 이게 디스패치의 핵심 — opcode 매칭으로 올바른 variant 생성.

#[derive(Debug, Clone)]
pub enum Pdu {
    // Initiator → Target
    LoginRequest(LoginRequest),
    LogoutRequest(LogoutRequest),
    TextRequest(TextRequest),
    ScsiCommand(ScsiCommand),
    ScsiDataOut(ScsiDataOut),
    NopOut(NopOut),
    TaskMgmtRequest(TaskMgmtRequest),

    // Target → Initiator
    LoginResponse(LoginResponse),
    LogoutResponse(LogoutResponse),
    TextResponse(TextResponse),
    ScsiResponse(ScsiResponse),
    ScsiDataIn(ScsiDataIn),
    NopIn(NopIn),
    TaskMgmtResponse(TaskMgmtResponse),
    R2t(R2t),
    AsyncMessage(AsyncMessage),
    Reject(Reject),
}

impl Pdu {
    /// 이 PDU의 opcode
    pub fn opcode(&self) -> Opcode {
        match self {
            Pdu::LoginRequest(_) => Opcode::LoginRequest,
            Pdu::LogoutRequest(_) => Opcode::LogoutRequest,
            Pdu::TextRequest(_) => Opcode::TextRequest,
            Pdu::ScsiCommand(_) => Opcode::ScsiCommand,
            Pdu::ScsiDataOut(_) => Opcode::ScsiDataOut,
            Pdu::NopOut(_) => Opcode::NopOut,
            Pdu::TaskMgmtRequest(_) => Opcode::ScsiTaskMgmtRequest,
            Pdu::LoginResponse(_) => Opcode::LoginResponse,
            Pdu::LogoutResponse(_) => Opcode::LogoutResponse,
            Pdu::TextResponse(_) => Opcode::TextResponse,
            Pdu::ScsiResponse(_) => Opcode::ScsiResponse,
            Pdu::ScsiDataIn(_) => Opcode::ScsiDataIn,
            Pdu::NopIn(_) => Opcode::NopIn,
            Pdu::TaskMgmtResponse(_) => Opcode::ScsiTaskMgmtResponse,
            Pdu::R2t(_) => Opcode::R2t,
            Pdu::AsyncMessage(_) => Opcode::AsyncMessage,
            Pdu::Reject(_) => Opcode::Reject,
        }
    }

    // ── DECODE: (BHS 바이트, data segment) → 타입 PDU ──
    //
    // codec이 분리해준 48바이트 BHS와 (de-padded) data segment를 받아
    // opcode로 디스패치하여 올바른 타입 PDU 생성.

    pub fn decode(bhs_bytes: &[u8; BHS_LEN], data: Bytes) -> Result<Self, PduError> {
        let bhs = Bhs::from_bytes(bhs_bytes);
        let opcode = Opcode::from_byte(bhs.opcode_byte())?;

        Ok(match opcode {
            Opcode::LoginRequest => Pdu::LoginRequest(LoginRequest::decode(&bhs, data)?),
            Opcode::LogoutRequest => Pdu::LogoutRequest(LogoutRequest::decode(&bhs, data)?),
            Opcode::TextRequest => Pdu::TextRequest(TextRequest::decode(&bhs, data)?),
            Opcode::ScsiCommand => Pdu::ScsiCommand(ScsiCommand::decode(&bhs, data)?),
            Opcode::ScsiDataOut => Pdu::ScsiDataOut(ScsiDataOut::decode(&bhs, data)?),
            Opcode::NopOut => Pdu::NopOut(NopOut::decode(&bhs, data)?),
            Opcode::ScsiTaskMgmtRequest => {
                Pdu::TaskMgmtRequest(TaskMgmtRequest::decode(&bhs, data)?)
            }
            Opcode::LoginResponse => Pdu::LoginResponse(LoginResponse::decode(&bhs, data)?),
            Opcode::LogoutResponse => Pdu::LogoutResponse(LogoutResponse::decode(&bhs, data)?),
            Opcode::TextResponse => Pdu::TextResponse(TextResponse::decode(&bhs, data)?),
            Opcode::ScsiResponse => Pdu::ScsiResponse(ScsiResponse::decode(&bhs, data)?),
            Opcode::ScsiDataIn => Pdu::ScsiDataIn(ScsiDataIn::decode(&bhs, data)?),
            Opcode::NopIn => Pdu::NopIn(NopIn::decode(&bhs, data)?),
            Opcode::ScsiTaskMgmtResponse => {
                Pdu::TaskMgmtResponse(TaskMgmtResponse::decode(&bhs, data)?)
            }
            Opcode::R2t => Pdu::R2t(R2t::decode(&bhs, data)?),
            Opcode::Reject => Pdu::Reject(Reject::decode(&bhs, data)?),
            Opcode::AsyncMessage => Pdu::AsyncMessage(AsyncMessage::decode(&bhs, data)?),
        })
    }

    // ── ENCODE: 타입 PDU → 완전한 와이어 바이트 ──
    //
    // BHS 작성 + data segment 추가 + 4바이트 패딩.
    // 다이제스트는 여기서 추가하지 않음 (codec 책임).

    pub(crate) fn encode_parts(&self) -> ([u8; BHS_LEN], Bytes) {
        let mut bhs = Bhs::zeroed();

        // 각 variant가 BHS를 채우고 data segment를 결정
        let data: Bytes = match self {
            Pdu::LoginRequest(p) => {
                p.encode_bhs(&mut bhs);
                p.params.encode()
            }
            Pdu::LoginResponse(p) => {
                p.encode_bhs(&mut bhs);
                p.params.encode()
            }
            Pdu::LogoutRequest(p) => {
                p.encode_bhs(&mut bhs);
                Bytes::new()
            }
            Pdu::LogoutResponse(p) => {
                p.encode_bhs(&mut bhs);
                Bytes::new()
            }
            Pdu::TextRequest(p) => {
                p.encode_bhs(&mut bhs);
                p.params.encode()
            }
            Pdu::TextResponse(p) => {
                p.encode_bhs(&mut bhs);
                p.params.encode()
            }
            Pdu::ScsiCommand(p) => {
                p.encode_bhs(&mut bhs);
                p.immediate_data.clone()
            }
            Pdu::ScsiResponse(p) => {
                p.encode_bhs(&mut bhs);
                p.encode_data()
            }
            Pdu::ScsiDataIn(p) => {
                p.encode_bhs(&mut bhs);
                p.data.clone()
            }
            Pdu::ScsiDataOut(p) => {
                p.encode_bhs(&mut bhs);
                p.data.clone()
            }
            Pdu::NopOut(p) => {
                p.encode_bhs(&mut bhs);
                p.data.clone()
            }
            Pdu::NopIn(p) => {
                p.encode_bhs(&mut bhs);
                p.data.clone()
            }
            Pdu::TaskMgmtRequest(p) => {
                p.encode_bhs(&mut bhs);
                Bytes::new()
            }
            Pdu::TaskMgmtResponse(p) => {
                p.encode_bhs(&mut bhs);
                Bytes::new()
            }
            Pdu::R2t(p) => {
                p.encode_bhs(&mut bhs);
                Bytes::new()
            }
            Pdu::AsyncMessage(p) => {
                p.encode_bhs(&mut bhs);
                p.data.clone()
            }
            Pdu::Reject(p) => {
                p.encode_bhs(&mut bhs);
                p.rejected_header.clone()
            }
        };

        // DataSegmentLength 설정
        bhs.set_data_segment_length(data.len() as u32);

        (*bhs.as_bytes(), data)
    }

    pub fn encode(&self) -> BytesMut {
        let (bhs, data) = self.encode_parts();

        // 조립: BHS + data + 4바이트 패딩
        let padded_len = (data.len() + 3) & !3;
        let mut out = BytesMut::with_capacity(BHS_LEN + padded_len);
        out.extend_from_slice(&bhs);
        out.extend_from_slice(&data);
        for _ in data.len()..padded_len {
            out.put_u8(0);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use login::TextParameters;

    /// codec 시뮬레이션: encode → BHS/data 분리 → decode 라운드트립
    fn round_trip(pdu: Pdu) -> Pdu {
        let wire = pdu.encode();

        // codec이 하는 일: BHS 48바이트 분리, DataSegmentLength로 data 추출
        let bhs_bytes: [u8; BHS_LEN] = wire[..BHS_LEN].try_into().unwrap();
        let dsl = {
            let b = &wire;
            ((b[5] as usize) << 16) | ((b[6] as usize) << 8) | (b[7] as usize)
        };
        let data = Bytes::copy_from_slice(&wire[BHS_LEN..BHS_LEN + dsl]);

        Pdu::decode(&bhs_bytes, data).unwrap()
    }

    #[test]
    fn test_scsi_command_round_trip() {
        let mut cdb = [0u8; 16];
        cdb[0] = 0x28; // READ(10)
        cdb[2..6].copy_from_slice(&100u32.to_be_bytes()); // LBA = 100

        let pdu = Pdu::ScsiCommand(ScsiCommand {
            immediate: false,
            final_: true,
            read: true,
            write: false,
            attr: opcode::TaskAttribute::Simple,
            lun: 0,
            initiator_task_tag: 0xDEADBEEF,
            expected_data_transfer_length: 8192,
            cmd_sn: 7,
            exp_stat_sn: 7,
            cdb,
            immediate_data: Bytes::new(),
        });

        match round_trip(pdu) {
            Pdu::ScsiCommand(c) => {
                assert!(c.read);
                assert_eq!(c.initiator_task_tag, 0xDEADBEEF);
                assert_eq!(c.expected_data_transfer_length, 8192);
                assert_eq!(c.scsi_opcode(), 0x28);
                assert_eq!(
                    u32::from_be_bytes([c.cdb[2], c.cdb[3], c.cdb[4], c.cdb[5]]),
                    100
                );
            }
            other => panic!("wrong variant: {:?}", other),
        }
    }

    #[test]
    fn test_login_with_params_round_trip() {
        let mut params = TextParameters::new();
        params.push("TargetName", "iqn.2024-01.com.example:disk0");
        params.push("MaxRecvDataSegmentLength", "262144");

        let pdu = Pdu::LoginResponse(LoginResponse {
            transit: true,
            continue_: false,
            current_stage: opcode::LoginStage::Operational,
            next_stage: opcode::LoginStage::FullFeature,
            version_max: 0,
            version_active: 0,
            isid: [0; 6],
            tsih: 42,
            initiator_task_tag: 1,
            stat_sn: 1,
            exp_cmd_sn: 2,
            max_cmd_sn: 34,
            status_class: 0,
            status_detail: 0,
            params,
        });

        match round_trip(pdu) {
            Pdu::LoginResponse(r) => {
                assert_eq!(r.tsih, 42);
                assert_eq!(r.status_class, 0);
                assert_eq!(r.params.get("MaxRecvDataSegmentLength"), Some("262144"));
            }
            other => panic!("wrong variant: {:?}", other),
        }
    }

    #[test]
    fn test_data_in_with_payload_round_trip() {
        let payload = Bytes::from_static(b"hello iscsi world!!!"); // 20 bytes
        let pdu = Pdu::ScsiDataIn(ScsiDataIn {
            final_: true,
            acknowledge: false,
            status_present: true,
            overflow: false,
            underflow: false,
            status: 0,
            lun: 0,
            initiator_task_tag: 0x55,
            target_transfer_tag: 0xFFFFFFFF,
            stat_sn: 2,
            exp_cmd_sn: 3,
            max_cmd_sn: 35,
            data_sn: 0,
            buffer_offset: 0,
            residual_count: 0,
            data: payload.clone(),
        });

        match round_trip(pdu) {
            Pdu::ScsiDataIn(d) => {
                assert!(d.status_present);
                assert_eq!(d.data, payload);
            }
            other => panic!("wrong variant: {:?}", other),
        }
    }

    #[test]
    fn test_padding_alignment() {
        // 20바이트 data → 패딩 없이 20바이트 (4의 배수)
        // 18바이트 data → 20바이트로 패딩
        let payload = Bytes::from_static(b"18-byte-payload!!!"); // 18 bytes
        let pdu = Pdu::NopIn(NopIn {
            lun: 0,
            initiator_task_tag: 1,
            target_transfer_tag: 0xFFFFFFFF,
            stat_sn: 1,
            exp_cmd_sn: 1,
            max_cmd_sn: 1,
            data: payload,
        });

        let wire = pdu.encode();
        // 48 BHS + 20 (18 padded to 20) = 68
        assert_eq!(wire.len(), 68);
        // DataSegmentLength는 패딩 전 실제 길이 18
        let dsl = ((wire[5] as usize) << 16) | ((wire[6] as usize) << 8) | (wire[7] as usize);
        assert_eq!(dsl, 18);
    }

    #[test]
    fn fixed_size_bhs_dispatch_never_panics_for_any_opcode_or_flags_byte() {
        for opcode in u8::MIN..=u8::MAX {
            for flags in u8::MIN..=u8::MAX {
                let mut bhs = [0u8; BHS_LEN];
                bhs[0] = opcode;
                bhs[1] = flags;
                let _ = Pdu::decode(&bhs, Bytes::new());
            }
        }
    }

    #[test]
    fn asynchronous_message_is_a_typed_pdu() {
        let mut bhs = [0u8; BHS_LEN];
        bhs[0] = Opcode::AsyncMessage as u8;
        bhs[1] = 0x80;
        bhs[16..20].copy_from_slice(&u32::MAX.to_be_bytes());
        bhs[36] = 1;
        bhs[42..44].copy_from_slice(&30u16.to_be_bytes());

        let Pdu::AsyncMessage(message) = Pdu::decode(&bhs, Bytes::new()).unwrap() else {
            panic!("expected AsyncMessage");
        };
        assert_eq!(message.async_event, 1);
        assert_eq!(message.parameter3, 30);
    }
}
