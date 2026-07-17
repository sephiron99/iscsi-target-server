// pdu/src/scsi.rs
//
// SCSI 데이터 경로 PDU들 — iSCSI의 핵심 트래픽
//
// READ 흐름:  ScsiCommand(R) → [ScsiDataIn ...] → (마지막 Data-In에 status 포함하거나 ScsiResponse)
// WRITE 흐름: ScsiCommand(W) → [R2t → ScsiDataOut ...] → ScsiResponse

use crate::bhs::Bhs;
use crate::error::PduError;
use crate::opcode::{Opcode, TaskAttribute};

use bytes::{BufMut, Bytes, BytesMut};

// ─── SCSI Command (0x01) ───────────────────────────────────────────────────
//
// byte 1: F(1) R(1) W(1) rsvd(2) ATTR(3)
// bytes 32-47: SCSI CDB (16바이트, 그 이상은 AHS로 확장)

#[derive(Debug, Clone)]
pub struct ScsiCommand {
    pub final_: bool,
    pub read: bool,
    pub write: bool,
    pub attr: TaskAttribute,
    pub lun: u64,
    pub initiator_task_tag: u32,
    pub expected_data_transfer_length: u32,
    pub cmd_sn: u32,
    pub exp_stat_sn: u32,
    pub cdb: [u8; 16],
    /// ImmediateData=Yes 협상 시, WRITE 명령에 데이터가 즉시 포함될 수 있음
    pub immediate_data: Bytes,
}

impl ScsiCommand {
    pub fn decode(bhs: &Bhs, data: Bytes) -> Result<Self, PduError> {
        let flags = bhs.flags();
        let mut cdb = [0u8; 16];
        cdb.copy_from_slice(&bhs.0[32..48]);

        Ok(Self {
            final_: flags & 0x80 != 0,
            read: flags & 0x40 != 0,
            write: flags & 0x20 != 0,
            attr: TaskAttribute::from_bits(flags),
            lun: bhs.lun(),
            initiator_task_tag: bhs.initiator_task_tag(),
            expected_data_transfer_length: bhs.get_u32(20),
            cmd_sn: bhs.get_u32(24),
            exp_stat_sn: bhs.get_u32(28),
            cdb,
            immediate_data: data,
        })
    }

    pub fn encode_bhs(&self, bhs: &mut Bhs) {
        bhs.set_opcode(Opcode::ScsiCommand, false);
        let flags = (self.final_ as u8) << 7
            | (self.read as u8) << 6
            | (self.write as u8) << 5
            | (self.attr as u8);
        bhs.set_flags(flags);
        bhs.set_lun(self.lun);
        bhs.set_initiator_task_tag(self.initiator_task_tag);
        bhs.set_u32(20, self.expected_data_transfer_length);
        bhs.set_u32(24, self.cmd_sn);
        bhs.set_u32(28, self.exp_stat_sn);
        bhs.0[32..48].copy_from_slice(&self.cdb);
    }

    /// CDB opcode (첫 바이트) — SCSI 명령 종류
    pub fn scsi_opcode(&self) -> u8 {
        self.cdb[0]
    }
}

// ─── SCSI Response (0x21) ──────────────────────────────────────────────────
//
// byte 1: 1(rsvd) .(rsvd) .(rsvd) o(1) u(1) O(1) U(1) .(rsvd)
//   o/u = bidirectional residual overflow/underflow
//   O/U = residual overflow/underflow
// byte 2: Response (0x00 = command completed at target)
// byte 3: Status (SCSI status: 0x00 GOOD, 0x02 CHECK CONDITION, ...)
// Sense data는 data segment에 2바이트 길이 접두사와 함께 들어감

#[derive(Debug, Clone)]
pub struct ScsiResponse {
    pub response: u8,
    pub status: u8,
    pub overflow: bool,
    pub underflow: bool,
    pub initiator_task_tag: u32,
    pub stat_sn: u32,
    pub exp_cmd_sn: u32,
    pub max_cmd_sn: u32,
    pub exp_data_sn: u32,
    pub residual_count: u32,
    /// CHECK CONDITION 시 sense data (길이 접두사 제외한 raw sense)
    pub sense: Bytes,
}

impl ScsiResponse {
    pub fn decode(bhs: &Bhs, data: Bytes) -> Result<Self, PduError> {
        let flags = bhs.flags();
        // sense data: 앞 2바이트가 길이, 이후 sense bytes
        let sense = if data.len() >= 2 {
            let sense_len = u16::from_be_bytes([data[0], data[1]]) as usize;
            let end = std::cmp::min(2 + sense_len, data.len());
            data.slice(2..end)
        } else {
            Bytes::new()
        };

        Ok(Self {
            response: bhs.get_u8(2),
            status: bhs.get_u8(3),
            overflow: flags & 0x04 != 0,
            underflow: flags & 0x02 != 0,
            initiator_task_tag: bhs.initiator_task_tag(),
            stat_sn: bhs.get_u32(24),
            exp_cmd_sn: bhs.get_u32(28),
            max_cmd_sn: bhs.get_u32(32),
            exp_data_sn: bhs.get_u32(36),
            residual_count: bhs.get_u32(44),
            sense,
        })
    }

    pub fn encode_bhs(&self, bhs: &mut Bhs) {
        bhs.set_opcode(Opcode::ScsiResponse, false);
        // byte 1: bit 7 항상 set, residual 플래그
        let flags = 0x80 | (self.overflow as u8) << 2 | (self.underflow as u8) << 1;
        bhs.set_flags(flags);
        bhs.set_u8(2, self.response);
        bhs.set_u8(3, self.status);
        bhs.set_initiator_task_tag(self.initiator_task_tag);
        bhs.set_u32(24, self.stat_sn);
        bhs.set_u32(28, self.exp_cmd_sn);
        bhs.set_u32(32, self.max_cmd_sn);
        bhs.set_u32(36, self.exp_data_sn);
        bhs.set_u32(44, self.residual_count);
    }

    /// data segment 생성 (sense data에 2바이트 길이 접두사 추가)
    pub fn encode_data(&self) -> Bytes {
        if self.sense.is_empty() {
            return Bytes::new();
        }
        let mut buf = BytesMut::with_capacity(2 + self.sense.len());
        buf.put_u16(self.sense.len() as u16);
        buf.extend_from_slice(&self.sense);
        buf.freeze()
    }

    /// GOOD status 응답 빌더
    pub fn good(itt: u32, stat_sn: u32, exp_cmd_sn: u32, max_cmd_sn: u32) -> Self {
        Self {
            response: 0x00,
            status: 0x00,
            overflow: false,
            underflow: false,
            initiator_task_tag: itt,
            stat_sn,
            exp_cmd_sn,
            max_cmd_sn,
            exp_data_sn: 0,
            residual_count: 0,
            sense: Bytes::new(),
        }
    }
}

// ─── SCSI Data-In (0x25) — target → initiator (READ 데이터) ────────────────
//
// byte 1: F(1) A(1) rsvd(2) O(1) U(1) S(1)
//   F = Final, A = Acknowledge 요청, S = Status 포함
//   S=1이면 byte 3에 status, 별도 ScsiResponse 생략 가능

#[derive(Debug, Clone)]
pub struct ScsiDataIn {
    pub final_: bool,
    pub acknowledge: bool,
    pub status_present: bool,
    pub overflow: bool,
    pub underflow: bool,
    pub status: u8,
    pub lun: u64,
    pub initiator_task_tag: u32,
    pub target_transfer_tag: u32,
    pub stat_sn: u32,
    pub exp_cmd_sn: u32,
    pub max_cmd_sn: u32,
    pub data_sn: u32,
    pub buffer_offset: u32,
    pub residual_count: u32,
    pub data: Bytes,
}

impl ScsiDataIn {
    pub fn decode(bhs: &Bhs, data: Bytes) -> Result<Self, PduError> {
        let flags = bhs.flags();
        Ok(Self {
            final_: flags & 0x80 != 0,
            acknowledge: flags & 0x40 != 0,
            status_present: flags & 0x01 != 0,
            overflow: flags & 0x04 != 0,
            underflow: flags & 0x02 != 0,
            status: bhs.get_u8(3),
            lun: bhs.lun(),
            initiator_task_tag: bhs.initiator_task_tag(),
            target_transfer_tag: bhs.get_u32(20),
            stat_sn: bhs.get_u32(24),
            exp_cmd_sn: bhs.get_u32(28),
            max_cmd_sn: bhs.get_u32(32),
            data_sn: bhs.get_u32(36),
            buffer_offset: bhs.get_u32(40),
            residual_count: bhs.get_u32(44),
            data,
        })
    }

    pub fn encode_bhs(&self, bhs: &mut Bhs) {
        bhs.set_opcode(Opcode::ScsiDataIn, false);
        let flags = (self.final_ as u8) << 7
            | (self.acknowledge as u8) << 6
            | (self.overflow as u8) << 2
            | (self.underflow as u8) << 1
            | (self.status_present as u8);
        bhs.set_flags(flags);
        if self.status_present {
            bhs.set_u8(3, self.status);
        }
        bhs.set_lun(self.lun);
        bhs.set_initiator_task_tag(self.initiator_task_tag);
        bhs.set_u32(20, self.target_transfer_tag);
        bhs.set_u32(24, self.stat_sn);
        bhs.set_u32(28, self.exp_cmd_sn);
        bhs.set_u32(32, self.max_cmd_sn);
        bhs.set_u32(36, self.data_sn);
        bhs.set_u32(40, self.buffer_offset);
        bhs.set_u32(44, self.residual_count);
    }
}

// ─── SCSI Data-Out (0x05) — initiator → target (WRITE 데이터) ──────────────

#[derive(Debug, Clone)]
pub struct ScsiDataOut {
    pub final_: bool,
    pub lun: u64,
    pub initiator_task_tag: u32,
    pub target_transfer_tag: u32,
    pub exp_stat_sn: u32,
    pub data_sn: u32,
    pub buffer_offset: u32,
    pub data: Bytes,
}

impl ScsiDataOut {
    pub fn decode(bhs: &Bhs, data: Bytes) -> Result<Self, PduError> {
        let flags = bhs.flags();
        Ok(Self {
            final_: flags & 0x80 != 0,
            lun: bhs.lun(),
            initiator_task_tag: bhs.initiator_task_tag(),
            target_transfer_tag: bhs.get_u32(20),
            exp_stat_sn: bhs.get_u32(28),
            data_sn: bhs.get_u32(36),
            buffer_offset: bhs.get_u32(40),
            data,
        })
    }

    pub fn encode_bhs(&self, bhs: &mut Bhs) {
        bhs.set_opcode(Opcode::ScsiDataOut, false);
        bhs.set_flags((self.final_ as u8) << 7);
        bhs.set_lun(self.lun);
        bhs.set_initiator_task_tag(self.initiator_task_tag);
        bhs.set_u32(20, self.target_transfer_tag);
        bhs.set_u32(28, self.exp_stat_sn);
        bhs.set_u32(36, self.data_sn);
        bhs.set_u32(40, self.buffer_offset);
    }
}

// ─── R2T (0x31) — Ready To Transfer (WRITE flow control) ───────────────────
//
// target이 "이제 이만큼 데이터를 보내라"고 initiator에게 알림
// data segment 없음

#[derive(Debug, Clone)]
pub struct R2t {
    pub lun: u64,
    pub initiator_task_tag: u32,
    pub target_transfer_tag: u32,
    pub stat_sn: u32,
    pub exp_cmd_sn: u32,
    pub max_cmd_sn: u32,
    pub r2t_sn: u32,
    pub buffer_offset: u32,
    pub desired_data_transfer_length: u32,
}

impl R2t {
    pub fn decode(bhs: &Bhs, _data: Bytes) -> Result<Self, PduError> {
        Ok(Self {
            lun: bhs.lun(),
            initiator_task_tag: bhs.initiator_task_tag(),
            target_transfer_tag: bhs.get_u32(20),
            stat_sn: bhs.get_u32(24),
            exp_cmd_sn: bhs.get_u32(28),
            max_cmd_sn: bhs.get_u32(32),
            r2t_sn: bhs.get_u32(36),
            buffer_offset: bhs.get_u32(40),
            desired_data_transfer_length: bhs.get_u32(44),
        })
    }

    pub fn encode_bhs(&self, bhs: &mut Bhs) {
        bhs.set_opcode(Opcode::R2t, false);
        bhs.set_flags(0x80); // F bit 항상 set
        bhs.set_lun(self.lun);
        bhs.set_initiator_task_tag(self.initiator_task_tag);
        bhs.set_u32(20, self.target_transfer_tag);
        bhs.set_u32(24, self.stat_sn);
        bhs.set_u32(28, self.exp_cmd_sn);
        bhs.set_u32(32, self.max_cmd_sn);
        bhs.set_u32(36, self.r2t_sn);
        bhs.set_u32(40, self.buffer_offset);
        bhs.set_u32(44, self.desired_data_transfer_length);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scsi_command_read_flags() {
        let mut bhs = Bhs::zeroed();
        let mut cdb = [0u8; 16];
        cdb[0] = 0x28; // READ(10)
        let cmd = ScsiCommand {
            final_: true,
            read: true,
            write: false,
            attr: TaskAttribute::Simple,
            lun: 0,
            initiator_task_tag: 0x1234,
            expected_data_transfer_length: 4096,
            cmd_sn: 5,
            exp_stat_sn: 5,
            cdb,
            immediate_data: Bytes::new(),
        };
        cmd.encode_bhs(&mut bhs);

        // flags = F(1) R(1) W(0) rsvd(00) ATTR(001) = 1100_0001 = 0xC1
        assert_eq!(bhs.flags(), 0xC1);

        let decoded = ScsiCommand::decode(&bhs, Bytes::new()).unwrap();
        assert!(decoded.read);
        assert!(!decoded.write);
        assert_eq!(decoded.scsi_opcode(), 0x28);
        assert_eq!(decoded.expected_data_transfer_length, 4096);
    }

    #[test]
    fn test_scsi_response_good_round_trip() {
        let resp = ScsiResponse::good(0x1234, 10, 11, 42);
        let mut bhs = Bhs::zeroed();
        resp.encode_bhs(&mut bhs);

        let decoded = ScsiResponse::decode(&bhs, Bytes::new()).unwrap();
        assert_eq!(decoded.status, 0x00);
        assert_eq!(decoded.initiator_task_tag, 0x1234);
        assert_eq!(decoded.max_cmd_sn, 42);
    }

    #[test]
    fn test_data_in_status_flag() {
        let mut bhs = Bhs::zeroed();
        let data_in = ScsiDataIn {
            final_: true,
            acknowledge: false,
            status_present: true,
            overflow: false,
            underflow: false,
            status: 0x00,
            lun: 0,
            initiator_task_tag: 0xAA,
            target_transfer_tag: 0xFFFFFFFF,
            stat_sn: 3,
            exp_cmd_sn: 4,
            max_cmd_sn: 36,
            data_sn: 0,
            buffer_offset: 0,
            residual_count: 0,
            data: Bytes::new(),
        };
        data_in.encode_bhs(&mut bhs);
        // flags = F(1) A(0) rsvd O(0) U(0) S(1) = 1000_0001 = 0x81
        assert_eq!(bhs.flags(), 0x81);
    }
}
