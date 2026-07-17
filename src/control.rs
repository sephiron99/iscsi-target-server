// pdu/src/control.rs
//
// 제어 PDU들 — NOP(keepalive), Logout, Text, TMF, Reject

use crate::bhs::Bhs;
use crate::error::PduError;
use crate::login::TextParameters;
use crate::opcode::{Opcode, TaskMgmtFunction};

use bytes::Bytes;

// ─── NOP-Out (0x00) / NOP-In (0x20) — keepalive / ping ─────────────────────

#[derive(Debug, Clone)]
pub struct NopOut {
    pub lun: u64,
    pub initiator_task_tag: u32,
    pub target_transfer_tag: u32,
    pub cmd_sn: u32,
    pub exp_stat_sn: u32,
    pub data: Bytes,
}

impl NopOut {
    pub fn decode(bhs: &Bhs, data: Bytes) -> Result<Self, PduError> {
        Ok(Self {
            lun: bhs.lun(),
            initiator_task_tag: bhs.initiator_task_tag(),
            target_transfer_tag: bhs.get_u32(20),
            cmd_sn: bhs.get_u32(24),
            exp_stat_sn: bhs.get_u32(28),
            data,
        })
    }

    pub fn encode_bhs(&self, bhs: &mut Bhs) {
        bhs.set_opcode(Opcode::NopOut, true);
        bhs.set_flags(0x80); // F bit
        bhs.set_lun(self.lun);
        bhs.set_initiator_task_tag(self.initiator_task_tag);
        bhs.set_u32(20, self.target_transfer_tag);
        bhs.set_u32(24, self.cmd_sn);
        bhs.set_u32(28, self.exp_stat_sn);
    }
}

#[derive(Debug, Clone)]
pub struct NopIn {
    pub lun: u64,
    pub initiator_task_tag: u32,
    pub target_transfer_tag: u32,
    pub stat_sn: u32,
    pub exp_cmd_sn: u32,
    pub max_cmd_sn: u32,
    pub data: Bytes,
}

impl NopIn {
    pub fn decode(bhs: &Bhs, data: Bytes) -> Result<Self, PduError> {
        Ok(Self {
            lun: bhs.lun(),
            initiator_task_tag: bhs.initiator_task_tag(),
            target_transfer_tag: bhs.get_u32(20),
            stat_sn: bhs.get_u32(24),
            exp_cmd_sn: bhs.get_u32(28),
            max_cmd_sn: bhs.get_u32(32),
            data,
        })
    }

    pub fn encode_bhs(&self, bhs: &mut Bhs) {
        bhs.set_opcode(Opcode::NopIn, false);
        bhs.set_flags(0x80);
        bhs.set_lun(self.lun);
        bhs.set_initiator_task_tag(self.initiator_task_tag);
        bhs.set_u32(20, self.target_transfer_tag);
        bhs.set_u32(24, self.stat_sn);
        bhs.set_u32(28, self.exp_cmd_sn);
        bhs.set_u32(32, self.max_cmd_sn);
    }

    /// NOP-Out에 대한 응답 생성 (data echo)
    pub fn reply_to(req: &NopOut, stat_sn: u32, exp_cmd_sn: u32, max_cmd_sn: u32) -> Self {
        Self {
            lun: req.lun,
            initiator_task_tag: req.initiator_task_tag,
            target_transfer_tag: 0xFFFFFFFF,
            stat_sn,
            exp_cmd_sn,
            max_cmd_sn,
            data: req.data.clone(),
        }
    }
}

// ─── Logout Request (0x06) / Response (0x26) ───────────────────────────────

#[derive(Debug, Clone)]
pub struct LogoutRequest {
    /// byte 1 하위 7비트: 0=세션, 1=연결, 2=연결 복구
    pub reason_code: u8,
    pub initiator_task_tag: u32,
    pub cid: u16,
    pub cmd_sn: u32,
    pub exp_stat_sn: u32,
}

impl LogoutRequest {
    pub fn decode(bhs: &Bhs, _data: Bytes) -> Result<Self, PduError> {
        Ok(Self {
            reason_code: bhs.flags() & 0x7f,
            initiator_task_tag: bhs.initiator_task_tag(),
            cid: bhs.get_u16(20),
            cmd_sn: bhs.get_u32(24),
            exp_stat_sn: bhs.get_u32(28),
        })
    }

    pub fn encode_bhs(&self, bhs: &mut Bhs) {
        bhs.set_opcode(Opcode::LogoutRequest, true);
        bhs.set_flags(0x80 | (self.reason_code & 0x7f));
        bhs.set_initiator_task_tag(self.initiator_task_tag);
        bhs.set_u16(20, self.cid);
        bhs.set_u32(24, self.cmd_sn);
        bhs.set_u32(28, self.exp_stat_sn);
    }
}

#[derive(Debug, Clone)]
pub struct LogoutResponse {
    /// byte 2: 0=성공
    pub response: u8,
    pub initiator_task_tag: u32,
    pub stat_sn: u32,
    pub exp_cmd_sn: u32,
    pub max_cmd_sn: u32,
}

impl LogoutResponse {
    pub fn decode(bhs: &Bhs, _data: Bytes) -> Result<Self, PduError> {
        Ok(Self {
            response: bhs.get_u8(2),
            initiator_task_tag: bhs.initiator_task_tag(),
            stat_sn: bhs.get_u32(24),
            exp_cmd_sn: bhs.get_u32(28),
            max_cmd_sn: bhs.get_u32(32),
        })
    }

    pub fn encode_bhs(&self, bhs: &mut Bhs) {
        bhs.set_opcode(Opcode::LogoutResponse, false);
        bhs.set_flags(0x80);
        bhs.set_u8(2, self.response);
        bhs.set_initiator_task_tag(self.initiator_task_tag);
        bhs.set_u32(24, self.stat_sn);
        bhs.set_u32(28, self.exp_cmd_sn);
        bhs.set_u32(32, self.max_cmd_sn);
    }

    pub fn success(itt: u32, stat_sn: u32, exp_cmd_sn: u32, max_cmd_sn: u32) -> Self {
        Self {
            response: 0,
            initiator_task_tag: itt,
            stat_sn,
            exp_cmd_sn,
            max_cmd_sn,
        }
    }
}

// ─── Text Request (0x04) / Response (0x24) — discovery 등 ──────────────────

#[derive(Debug, Clone)]
pub struct TextRequest {
    pub final_: bool,
    pub continue_: bool,
    pub lun: u64,
    pub initiator_task_tag: u32,
    pub target_transfer_tag: u32,
    pub cmd_sn: u32,
    pub exp_stat_sn: u32,
    pub params: TextParameters,
}

impl TextRequest {
    pub fn decode(bhs: &Bhs, data: Bytes) -> Result<Self, PduError> {
        let flags = bhs.flags();
        Ok(Self {
            final_: flags & 0x80 != 0,
            continue_: flags & 0x40 != 0,
            lun: bhs.lun(),
            initiator_task_tag: bhs.initiator_task_tag(),
            target_transfer_tag: bhs.get_u32(20),
            cmd_sn: bhs.get_u32(24),
            exp_stat_sn: bhs.get_u32(28),
            params: TextParameters::parse(&data),
        })
    }

    pub fn encode_bhs(&self, bhs: &mut Bhs) {
        bhs.set_opcode(Opcode::TextRequest, false);
        let flags = (self.final_ as u8) << 7 | (self.continue_ as u8) << 6;
        bhs.set_flags(flags);
        bhs.set_lun(self.lun);
        bhs.set_initiator_task_tag(self.initiator_task_tag);
        bhs.set_u32(20, self.target_transfer_tag);
        bhs.set_u32(24, self.cmd_sn);
        bhs.set_u32(28, self.exp_stat_sn);
    }
}

#[derive(Debug, Clone)]
pub struct TextResponse {
    pub final_: bool,
    pub continue_: bool,
    pub lun: u64,
    pub initiator_task_tag: u32,
    pub target_transfer_tag: u32,
    pub stat_sn: u32,
    pub exp_cmd_sn: u32,
    pub max_cmd_sn: u32,
    pub params: TextParameters,
}

impl TextResponse {
    pub fn decode(bhs: &Bhs, data: Bytes) -> Result<Self, PduError> {
        let flags = bhs.flags();
        Ok(Self {
            final_: flags & 0x80 != 0,
            continue_: flags & 0x40 != 0,
            lun: bhs.lun(),
            initiator_task_tag: bhs.initiator_task_tag(),
            target_transfer_tag: bhs.get_u32(20),
            stat_sn: bhs.get_u32(24),
            exp_cmd_sn: bhs.get_u32(28),
            max_cmd_sn: bhs.get_u32(32),
            params: TextParameters::parse(&data),
        })
    }

    pub fn encode_bhs(&self, bhs: &mut Bhs) {
        bhs.set_opcode(Opcode::TextResponse, false);
        let flags = (self.final_ as u8) << 7 | (self.continue_ as u8) << 6;
        bhs.set_flags(flags);
        bhs.set_lun(self.lun);
        bhs.set_initiator_task_tag(self.initiator_task_tag);
        bhs.set_u32(20, self.target_transfer_tag);
        bhs.set_u32(24, self.stat_sn);
        bhs.set_u32(28, self.exp_cmd_sn);
        bhs.set_u32(32, self.max_cmd_sn);
    }
}

// ─── Task Management Request (0x02) / Response (0x22) ──────────────────────

#[derive(Debug, Clone)]
pub struct TaskMgmtRequest {
    pub function: TaskMgmtFunction,
    pub lun: u64,
    pub initiator_task_tag: u32,
    /// 참조 task tag (ABORT TASK 등에서 대상 명령 지정)
    pub referenced_task_tag: u32,
    pub cmd_sn: u32,
    pub exp_stat_sn: u32,
}

impl TaskMgmtRequest {
    pub fn decode(bhs: &Bhs, _data: Bytes) -> Result<Self, PduError> {
        Ok(Self {
            function: TaskMgmtFunction::from_byte(bhs.flags())?,
            lun: bhs.lun(),
            initiator_task_tag: bhs.initiator_task_tag(),
            referenced_task_tag: bhs.get_u32(20),
            cmd_sn: bhs.get_u32(24),
            exp_stat_sn: bhs.get_u32(28),
        })
    }

    pub fn encode_bhs(&self, bhs: &mut Bhs) {
        bhs.set_opcode(Opcode::ScsiTaskMgmtRequest, true);
        bhs.set_flags(0x80 | (self.function as u8));
        bhs.set_lun(self.lun);
        bhs.set_initiator_task_tag(self.initiator_task_tag);
        bhs.set_u32(20, self.referenced_task_tag);
        bhs.set_u32(24, self.cmd_sn);
        bhs.set_u32(28, self.exp_stat_sn);
    }
}

#[derive(Debug, Clone)]
pub struct TaskMgmtResponse {
    /// byte 2: 0=function complete
    pub response: u8,
    pub initiator_task_tag: u32,
    pub stat_sn: u32,
    pub exp_cmd_sn: u32,
    pub max_cmd_sn: u32,
}

impl TaskMgmtResponse {
    pub fn decode(bhs: &Bhs, _data: Bytes) -> Result<Self, PduError> {
        Ok(Self {
            response: bhs.get_u8(2),
            initiator_task_tag: bhs.initiator_task_tag(),
            stat_sn: bhs.get_u32(24),
            exp_cmd_sn: bhs.get_u32(28),
            max_cmd_sn: bhs.get_u32(32),
        })
    }

    pub fn encode_bhs(&self, bhs: &mut Bhs) {
        bhs.set_opcode(Opcode::ScsiTaskMgmtResponse, false);
        bhs.set_flags(0x80);
        bhs.set_u8(2, self.response);
        bhs.set_initiator_task_tag(self.initiator_task_tag);
        bhs.set_u32(24, self.stat_sn);
        bhs.set_u32(28, self.exp_cmd_sn);
        bhs.set_u32(32, self.max_cmd_sn);
    }
}

// ─── Reject (0x3f) — 프로토콜 에러 통지 ────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Reject {
    /// byte 2: reason (예: 0x09 = invalid PDU field)
    pub reason: u8,
    pub stat_sn: u32,
    pub exp_cmd_sn: u32,
    pub max_cmd_sn: u32,
    pub data_sn: u32,
    /// 거부된 PDU의 헤더 (48바이트)를 data segment에 echo
    pub rejected_header: Bytes,
}

impl Reject {
    pub fn decode(bhs: &Bhs, data: Bytes) -> Result<Self, PduError> {
        Ok(Self {
            reason: bhs.get_u8(2),
            stat_sn: bhs.get_u32(24),
            exp_cmd_sn: bhs.get_u32(28),
            max_cmd_sn: bhs.get_u32(32),
            data_sn: bhs.get_u32(36),
            rejected_header: data,
        })
    }

    pub fn encode_bhs(&self, bhs: &mut Bhs) {
        bhs.set_opcode(Opcode::Reject, false);
        bhs.set_flags(0x80);
        bhs.set_u8(2, self.reason);
        bhs.set_initiator_task_tag(0xFFFFFFFF); // Reject는 ITT=0xFFFFFFFF
        bhs.set_u32(24, self.stat_sn);
        bhs.set_u32(28, self.exp_cmd_sn);
        bhs.set_u32(32, self.max_cmd_sn);
        bhs.set_u32(36, self.data_sn);
    }
}
