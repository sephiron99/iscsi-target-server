// pdu/src/opcode.rs
//
// iSCSI opcode 및 비트필드 정의 (RFC 3720 §10.2.1)
//
// 핵심: iSCSI의 flags 바이트는 packed bitfield임.
// 예) SCSI Command byte 1 = F(1) R(1) W(1) rsvd(2) ATTR(3)
//     Login byte 1       = T(1) C(1) rsvd(2) CSG(2) NSG(2)
// 이런 불규칙한 비트 레이아웃을 타입으로 안전하게 감싸는 게 목표.

use crate::error::PduError;

// ─── Opcode ────────────────────────────────────────────────────────────────
//
// byte 0의 하위 6비트가 opcode. bit 6은 I(Immediate) 플래그.
// 0x00-0x06 = initiator → target, 0x20-0x3f = target → initiator

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Opcode {
    // Initiator → Target
    NopOut = 0x00,
    ScsiCommand = 0x01,
    ScsiTaskMgmtRequest = 0x02,
    LoginRequest = 0x03,
    TextRequest = 0x04,
    ScsiDataOut = 0x05,
    LogoutRequest = 0x06,

    // Target → Initiator
    NopIn = 0x20,
    ScsiResponse = 0x21,
    ScsiTaskMgmtResponse = 0x22,
    LoginResponse = 0x23,
    TextResponse = 0x24,
    ScsiDataIn = 0x25,
    LogoutResponse = 0x26,
    R2t = 0x31,
    AsyncMessage = 0x32,
    Reject = 0x3f,
}

impl Opcode {
    /// byte 0에서 opcode 추출 (I 플래그 마스킹)
    pub fn from_byte(b: u8) -> Result<Self, PduError> {
        Ok(match b & 0x3f {
            0x00 => Opcode::NopOut,
            0x01 => Opcode::ScsiCommand,
            0x02 => Opcode::ScsiTaskMgmtRequest,
            0x03 => Opcode::LoginRequest,
            0x04 => Opcode::TextRequest,
            0x05 => Opcode::ScsiDataOut,
            0x06 => Opcode::LogoutRequest,
            0x20 => Opcode::NopIn,
            0x21 => Opcode::ScsiResponse,
            0x22 => Opcode::ScsiTaskMgmtResponse,
            0x23 => Opcode::LoginResponse,
            0x24 => Opcode::TextResponse,
            0x25 => Opcode::ScsiDataIn,
            0x26 => Opcode::LogoutResponse,
            0x31 => Opcode::R2t,
            0x32 => Opcode::AsyncMessage,
            0x3f => Opcode::Reject,
            other => return Err(PduError::UnknownOpcode(other)),
        })
    }

    /// initiator가 보내는 opcode인가 (서버 입장에서 수신 가능 여부 검증)
    pub fn is_from_initiator(&self) -> bool {
        (*self as u8) < 0x20
    }
}

// ─── Login Stage (CSG/NSG) ─────────────────────────────────────────────────
//
// Login byte 1의 CSG(Current Stage), NSG(Next Stage)는 각각 2비트.
// 값 2는 예약(미사용)이라 enum에서 제외.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LoginStage {
    /// SecurityNegotiation — CHAP 등 인증 협상
    Security = 0,
    /// LoginOperationalNegotiation — 파라미터 협상
    Operational = 1,
    /// FullFeaturePhase — SCSI 명령 처리 가능
    FullFeature = 3,
}

impl LoginStage {
    pub fn from_bits(b: u8) -> Result<Self, PduError> {
        Ok(match b & 0x3 {
            0 => LoginStage::Security,
            1 => LoginStage::Operational,
            3 => LoginStage::FullFeature,
            other => return Err(PduError::InvalidLoginStage(other)),
        })
    }
}

// ─── SCSI Task Attribute ───────────────────────────────────────────────────
//
// SCSI Command byte 1의 하위 3비트 (ATTR)

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TaskAttribute {
    Untagged = 0,
    Simple = 1,
    Ordered = 2,
    HeadOfQueue = 3,
    Aca = 4,
}

impl TaskAttribute {
    pub fn from_bits(b: u8) -> Self {
        match b & 0x7 {
            0 => TaskAttribute::Untagged,
            1 => TaskAttribute::Simple,
            2 => TaskAttribute::Ordered,
            3 => TaskAttribute::HeadOfQueue,
            4 => TaskAttribute::Aca,
            _ => TaskAttribute::Simple, // 알 수 없는 값은 Simple로 폴백
        }
    }
}

// ─── Task Management Function ──────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TaskMgmtFunction {
    AbortTask = 1,
    AbortTaskSet = 2,
    ClearAca = 3,
    ClearTaskSet = 4,
    LogicalUnitReset = 5,
    TargetWarmReset = 6,
    TargetColdReset = 7,
    TaskReassign = 8,
}

impl TaskMgmtFunction {
    pub fn from_byte(b: u8) -> Result<Self, PduError> {
        // bit 7은 항상 set (reserved), 하위 7비트가 function code
        Ok(match b & 0x7f {
            1 => TaskMgmtFunction::AbortTask,
            2 => TaskMgmtFunction::AbortTaskSet,
            3 => TaskMgmtFunction::ClearAca,
            4 => TaskMgmtFunction::ClearTaskSet,
            5 => TaskMgmtFunction::LogicalUnitReset,
            6 => TaskMgmtFunction::TargetWarmReset,
            7 => TaskMgmtFunction::TargetColdReset,
            8 => TaskMgmtFunction::TaskReassign,
            other => return Err(PduError::Malformed(format!("unknown TMF: {}", other))),
        })
    }
}
