// src/control.rs
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
    pub immediate: bool,
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
            immediate: bhs.is_immediate(),
            lun: bhs.lun(),
            initiator_task_tag: bhs.initiator_task_tag(),
            target_transfer_tag: bhs.get_u32(20),
            cmd_sn: bhs.get_u32(24),
            exp_stat_sn: bhs.get_u32(28),
            data,
        })
    }

    pub fn encode_bhs(&self, bhs: &mut Bhs) {
        bhs.set_opcode(Opcode::NopOut, self.immediate);
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

    pub fn with_data(mut self, data: Bytes) -> Self {
        self.data = data;
        self
    }
}

// ─── Logout Request (0x06) / Response (0x26) ───────────────────────────────

#[derive(Debug, Clone)]
pub struct LogoutRequest {
    pub immediate: bool,
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
            immediate: bhs.is_immediate(),
            reason_code: bhs.flags() & 0x7f,
            initiator_task_tag: bhs.initiator_task_tag(),
            cid: bhs.get_u16(20),
            cmd_sn: bhs.get_u32(24),
            exp_stat_sn: bhs.get_u32(28),
        })
    }

    pub fn encode_bhs(&self, bhs: &mut Bhs) {
        bhs.set_opcode(Opcode::LogoutRequest, self.immediate);
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
    pub time2_wait: u16,
    pub time2_retain: u16,
}

impl LogoutResponse {
    pub fn decode(bhs: &Bhs, _data: Bytes) -> Result<Self, PduError> {
        Ok(Self {
            response: bhs.get_u8(2),
            initiator_task_tag: bhs.initiator_task_tag(),
            stat_sn: bhs.get_u32(24),
            exp_cmd_sn: bhs.get_u32(28),
            max_cmd_sn: bhs.get_u32(32),
            time2_wait: bhs.get_u16(40),
            time2_retain: bhs.get_u16(42),
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
        bhs.set_u16(40, self.time2_wait);
        bhs.set_u16(42, self.time2_retain);
    }

    pub fn success(itt: u32, stat_sn: u32, exp_cmd_sn: u32, max_cmd_sn: u32) -> Self {
        Self {
            response: 0,
            initiator_task_tag: itt,
            stat_sn,
            exp_cmd_sn,
            max_cmd_sn,
            time2_wait: 0,
            time2_retain: 0,
        }
    }

    pub fn with_response(
        response: LogoutResponseCode,
        itt: u32,
        stat_sn: u32,
        exp_cmd_sn: u32,
        max_cmd_sn: u32,
    ) -> Self {
        Self {
            response: response as u8,
            initiator_task_tag: itt,
            stat_sn,
            exp_cmd_sn,
            max_cmd_sn,
            time2_wait: 0,
            time2_retain: 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LogoutResponseCode {
    ClosedSuccessfully = 0,
    CidNotFound = 1,
    RecoveryNotSupported = 2,
    CleanupFailed = 3,
}

// ─── Text Request (0x04) / Response (0x24) — discovery 등 ──────────────────

#[derive(Debug, Clone)]
pub struct TextRequest {
    pub immediate: bool,
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
            immediate: bhs.is_immediate(),
            final_: flags & 0x80 != 0,
            continue_: flags & 0x40 != 0,
            lun: bhs.lun(),
            initiator_task_tag: bhs.initiator_task_tag(),
            target_transfer_tag: bhs.get_u32(20),
            cmd_sn: bhs.get_u32(24),
            exp_stat_sn: bhs.get_u32(28),
            params: TextParameters::from_bytes(data),
        })
    }

    pub fn encode_bhs(&self, bhs: &mut Bhs) {
        bhs.set_opcode(Opcode::TextRequest, self.immediate);
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
            params: TextParameters::from_bytes(data),
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
    pub immediate: bool,
    pub function: TaskMgmtFunction,
    pub lun: u64,
    pub initiator_task_tag: u32,
    /// 참조 task tag (ABORT TASK 등에서 대상 명령 지정)
    pub referenced_task_tag: u32,
    pub cmd_sn: u32,
    pub exp_stat_sn: u32,
    pub ref_cmd_sn: u32,
    pub exp_data_sn: u32,
}

impl TaskMgmtRequest {
    pub fn decode(bhs: &Bhs, _data: Bytes) -> Result<Self, PduError> {
        Ok(Self {
            immediate: bhs.is_immediate(),
            function: TaskMgmtFunction::from_byte(bhs.flags())?,
            lun: bhs.lun(),
            initiator_task_tag: bhs.initiator_task_tag(),
            referenced_task_tag: bhs.get_u32(20),
            cmd_sn: bhs.get_u32(24),
            exp_stat_sn: bhs.get_u32(28),
            ref_cmd_sn: bhs.get_u32(32),
            exp_data_sn: bhs.get_u32(36),
        })
    }

    pub fn encode_bhs(&self, bhs: &mut Bhs) {
        bhs.set_opcode(Opcode::ScsiTaskMgmtRequest, self.immediate);
        bhs.set_flags(0x80 | (self.function as u8));
        bhs.set_lun(self.lun);
        bhs.set_initiator_task_tag(self.initiator_task_tag);
        bhs.set_u32(20, self.referenced_task_tag);
        bhs.set_u32(24, self.cmd_sn);
        bhs.set_u32(28, self.exp_stat_sn);
        bhs.set_u32(32, self.ref_cmd_sn);
        bhs.set_u32(36, self.exp_data_sn);
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RejectReason {
    DataDigestError = 0x02,
    SnackRejected = 0x03,
    ProtocolError = 0x04,
    CommandNotSupported = 0x05,
    ImmediateCommandRejected = 0x06,
    TaskInProgress = 0x07,
    InvalidDataAck = 0x08,
    InvalidPduField = 0x09,
    LongOperationRejected = 0x0a,
    WaitingForLogout = 0x0c,
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

// ─── Asynchronous Message (0x32) ──────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct AsyncMessage {
    pub lun: u64,
    pub stat_sn: u32,
    pub exp_cmd_sn: u32,
    pub max_cmd_sn: u32,
    pub async_event: u8,
    pub async_vcode: u8,
    pub parameter1: u16,
    pub parameter2: u16,
    pub parameter3: u16,
    pub data: Bytes,
}

impl AsyncMessage {
    pub fn decode(bhs: &Bhs, data: Bytes) -> Result<Self, PduError> {
        Ok(Self {
            lun: bhs.lun(),
            stat_sn: bhs.get_u32(24),
            exp_cmd_sn: bhs.get_u32(28),
            max_cmd_sn: bhs.get_u32(32),
            async_event: bhs.get_u8(36),
            async_vcode: bhs.get_u8(37),
            parameter1: bhs.get_u16(38),
            parameter2: bhs.get_u16(40),
            parameter3: bhs.get_u16(42),
            data,
        })
    }

    pub fn encode_bhs(&self, bhs: &mut Bhs) {
        bhs.set_opcode(Opcode::AsyncMessage, false);
        bhs.set_flags(0x80);
        bhs.set_lun(self.lun);
        bhs.set_initiator_task_tag(u32::MAX);
        bhs.set_u32(24, self.stat_sn);
        bhs.set_u32(28, self.exp_cmd_sn);
        bhs.set_u32(32, self.max_cmd_sn);
        bhs.set_u8(36, self.async_event);
        bhs.set_u8(37, self.async_vcode);
        bhs.set_u16(38, self.parameter1);
        bhs.set_u16(40, self.parameter2);
        bhs.set_u16(42, self.parameter3);
    }

    /// RFC 7143 11.9.1절의 target-initiated Logout 요청.
    pub fn request_logout(
        stat_sn: u32,
        exp_cmd_sn: u32,
        max_cmd_sn: u32,
        timeout_seconds: u16,
    ) -> Self {
        Self {
            lun: 0,
            stat_sn,
            exp_cmd_sn,
            max_cmd_sn,
            async_event: 1,
            async_vcode: 0,
            parameter1: 0,
            parameter2: 0,
            parameter3: timeout_seconds,
            data: Bytes::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Pdu;

    #[test]
    fn logout_response_has_a_fixed_rfc_7143_header() {
        let response = Pdu::LogoutResponse(LogoutResponse {
            response: LogoutResponseCode::RecoveryNotSupported as u8,
            initiator_task_tag: 0x0102_0304,
            stat_sn: 0x1112_1314,
            exp_cmd_sn: 0x2122_2324,
            max_cmd_sn: 0x3132_3334,
            time2_wait: 0x4142,
            time2_retain: 0x4344,
        });
        let expected = [
            0x26, 0x80, 0x02, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x02, 0x03, 0x04, 0,
            0, 0, 0, 0x11, 0x12, 0x13, 0x14, 0x21, 0x22, 0x23, 0x24, 0x31, 0x32, 0x33, 0x34, 0, 0,
            0, 0, 0x41, 0x42, 0x43, 0x44, 0, 0, 0, 0,
        ];
        assert_eq!(&response.encode()[..48], &expected);
    }

    #[test]
    fn task_reassign_request_has_ref_cmd_sn_and_exp_data_sn() {
        let request = Pdu::TaskMgmtRequest(TaskMgmtRequest {
            immediate: true,
            function: TaskMgmtFunction::TaskReassign,
            lun: 0x0102_0304_0506_0708,
            initiator_task_tag: 0x1112_1314,
            referenced_task_tag: 0x2122_2324,
            cmd_sn: 0x3132_3334,
            exp_stat_sn: 0x4142_4344,
            ref_cmd_sn: 0x5152_5354,
            exp_data_sn: 0x6162_6364,
        });
        let expected = [
            0x42, 0x88, 0, 0, 0, 0, 0, 0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x11,
            0x12, 0x13, 0x14, 0x21, 0x22, 0x23, 0x24, 0x31, 0x32, 0x33, 0x34, 0x41, 0x42, 0x43,
            0x44, 0x51, 0x52, 0x53, 0x54, 0x61, 0x62, 0x63, 0x64, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        assert_eq!(&request.encode()[..48], &expected);
    }

    #[test]
    fn asynchronous_logout_request_has_a_fixed_header() {
        let message = Pdu::AsyncMessage(AsyncMessage::request_logout(
            0x0102_0304,
            0x1112_1314,
            0x2122_2324,
            30,
        ));
        let expected = [
            0x32, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0, 0, 0,
            0, 0x01, 0x02, 0x03, 0x04, 0x11, 0x12, 0x13, 0x14, 0x21, 0x22, 0x23, 0x24, 0x01, 0, 0,
            0, 0, 0, 0, 0x1e, 0, 0, 0, 0,
        ];
        assert_eq!(&message.encode()[..48], &expected);
    }
}
