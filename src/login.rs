// pdu/src/login.rs
//
// Login Request/Response — 가장 복잡한 PDU
//
// byte 1 비트 레이아웃:
//   T(1) C(1) rsvd(2) CSG(2) NSG(2)
//   T = Transit (다음 stage로 전환)
//   C = Continue (text가 여러 PDU에 분할됨)
//   CSG = Current Stage, NSG = Next Stage
//
// Data Segment = key=value 협상 파라미터 (null로 구분)

use crate::bhs::Bhs;
use crate::error::PduError;
use crate::opcode::{LoginStage, Opcode};

use bytes::{BufMut, Bytes, BytesMut};

// ─── Text Parameters (key=value) ───────────────────────────────────────────
//
// Login/Text PDU의 data segment 형식: "key=value\0key=value\0..."
// 순서가 의미를 가질 수 있으므로 Vec로 유지 (HashMap 아님)

#[derive(Debug, Clone, Default)]
pub struct TextParameters(pub Vec<(String, String)>);

impl TextParameters {
    pub fn new() -> Self {
        Self(Vec::new())
    }

    /// data segment 바이트에서 파싱
    pub fn parse(data: &[u8]) -> Self {
        let mut pairs = Vec::new();
        for entry in data.split(|&b| b == 0) {
            if entry.is_empty() {
                continue;
            }
            if let Some(pos) = entry.iter().position(|&b| b == b'=') {
                let key = String::from_utf8_lossy(&entry[..pos]).into_owned();
                let value = String::from_utf8_lossy(&entry[pos + 1..]).into_owned();
                pairs.push((key, value));
            }
        }
        Self(pairs)
    }

    /// data segment 바이트로 직렬화
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::new();
        for (key, value) in &self.0 {
            buf.extend_from_slice(key.as_bytes());
            buf.put_u8(b'=');
            buf.extend_from_slice(value.as_bytes());
            buf.put_u8(0);
        }
        buf.freeze()
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    pub fn push(&mut self, key: &str, value: &str) {
        self.0.push((key.to_string(), value.to_string()));
    }
}

// ─── Login Request ─────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct LoginRequest {
    pub transit: bool,
    pub continue_: bool,
    pub current_stage: LoginStage,
    pub next_stage: LoginStage,
    pub version_max: u8,
    pub version_min: u8,
    pub isid: [u8; 6],
    pub tsih: u16,
    pub initiator_task_tag: u32,
    pub cid: u16,
    pub cmd_sn: u32,
    pub exp_stat_sn: u32,
    pub params: TextParameters,
}

impl LoginRequest {
    pub fn decode(bhs: &Bhs, data: Bytes) -> Result<Self, PduError> {
        let flags = bhs.flags();
        let transit = flags & 0x80 != 0;
        let continue_ = flags & 0x40 != 0;
        let current_stage = LoginStage::from_bits((flags >> 2) & 0x3)?;
        let next_stage = LoginStage::from_bits(flags & 0x3)?;

        Ok(Self {
            transit,
            continue_,
            current_stage,
            next_stage,
            version_max: bhs.get_u8(2),
            version_min: bhs.get_u8(3),
            isid: bhs.get_bytes6(8),
            tsih: bhs.get_u16(14),
            initiator_task_tag: bhs.initiator_task_tag(),
            cid: bhs.get_u16(20),
            cmd_sn: bhs.get_u32(24),
            exp_stat_sn: bhs.get_u32(28),
            params: TextParameters::parse(&data),
        })
    }

    pub fn encode_bhs(&self, bhs: &mut Bhs) {
        // Login PDU는 항상 immediate
        bhs.set_opcode(Opcode::LoginRequest, true);
        let flags = (self.transit as u8) << 7
            | (self.continue_ as u8) << 6
            | (self.current_stage as u8) << 2
            | (self.next_stage as u8);
        bhs.set_flags(flags);
        bhs.set_u8(2, self.version_max);
        bhs.set_u8(3, self.version_min);
        bhs.set_bytes6(8, &self.isid);
        bhs.set_u16(14, self.tsih);
        bhs.set_initiator_task_tag(self.initiator_task_tag);
        bhs.set_u16(20, self.cid);
        bhs.set_u32(24, self.cmd_sn);
        bhs.set_u32(28, self.exp_stat_sn);
    }
}

// ─── Login Response ────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct LoginResponse {
    pub transit: bool,
    pub continue_: bool,
    pub current_stage: LoginStage,
    pub next_stage: LoginStage,
    pub version_max: u8,
    pub version_active: u8,
    pub isid: [u8; 6],
    pub tsih: u16,
    pub initiator_task_tag: u32,
    pub stat_sn: u32,
    pub exp_cmd_sn: u32,
    pub max_cmd_sn: u32,
    /// Status-Class (byte 36): 0 = success
    pub status_class: u8,
    /// Status-Detail (byte 37)
    pub status_detail: u8,
    pub params: TextParameters,
}

impl LoginResponse {
    pub fn decode(bhs: &Bhs, data: Bytes) -> Result<Self, PduError> {
        let flags = bhs.flags();
        Ok(Self {
            transit: flags & 0x80 != 0,
            continue_: flags & 0x40 != 0,
            current_stage: LoginStage::from_bits((flags >> 2) & 0x3)?,
            next_stage: LoginStage::from_bits(flags & 0x3)?,
            version_max: bhs.get_u8(2),
            version_active: bhs.get_u8(3),
            isid: bhs.get_bytes6(8),
            tsih: bhs.get_u16(14),
            initiator_task_tag: bhs.initiator_task_tag(),
            stat_sn: bhs.get_u32(24),
            exp_cmd_sn: bhs.get_u32(28),
            max_cmd_sn: bhs.get_u32(32),
            status_class: bhs.get_u8(36),
            status_detail: bhs.get_u8(37),
            params: TextParameters::parse(&data),
        })
    }

    pub fn encode_bhs(&self, bhs: &mut Bhs) {
        bhs.set_opcode(Opcode::LoginResponse, false);
        let flags = (self.transit as u8) << 7
            | (self.continue_ as u8) << 6
            | (self.current_stage as u8) << 2
            | (self.next_stage as u8);
        bhs.set_flags(flags);
        bhs.set_u8(2, self.version_max);
        bhs.set_u8(3, self.version_active);
        bhs.set_bytes6(8, &self.isid);
        bhs.set_u16(14, self.tsih);
        bhs.set_initiator_task_tag(self.initiator_task_tag);
        bhs.set_u32(24, self.stat_sn);
        bhs.set_u32(28, self.exp_cmd_sn);
        bhs.set_u32(32, self.max_cmd_sn);
        bhs.set_u8(36, self.status_class);
        bhs.set_u8(37, self.status_detail);
    }

    /// 성공 응답 빌더
    pub fn success(
        req: &LoginRequest,
        tsih: u16,
        stat_sn: u32,
        exp_cmd_sn: u32,
        max_cmd_sn: u32,
        params: TextParameters,
    ) -> Self {
        Self {
            transit: req.transit,
            continue_: false,
            current_stage: req.current_stage,
            next_stage: req.next_stage,
            version_max: 0,
            version_active: 0,
            isid: req.isid,
            tsih,
            initiator_task_tag: req.initiator_task_tag,
            stat_sn,
            exp_cmd_sn,
            max_cmd_sn,
            status_class: 0, // success
            status_detail: 0,
            params,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_text_params_round_trip() {
        let mut p = TextParameters::new();
        p.push("InitiatorName", "iqn.2024-01.com.example:host");
        p.push("MaxRecvDataSegmentLength", "262144");

        let encoded = p.encode();
        let decoded = TextParameters::parse(&encoded);

        assert_eq!(decoded.get("MaxRecvDataSegmentLength"), Some("262144"));
        assert_eq!(
            decoded.get("InitiatorName"),
            Some("iqn.2024-01.com.example:host")
        );
    }

    #[test]
    fn test_login_request_flags() {
        let mut bhs = Bhs::zeroed();
        let req = LoginRequest {
            transit: true,
            continue_: false,
            current_stage: LoginStage::Operational,
            next_stage: LoginStage::FullFeature,
            version_max: 0,
            version_min: 0,
            isid: [0x80, 0x01, 0x02, 0x03, 0x04, 0x05],
            tsih: 0,
            initiator_task_tag: 0xABCD,
            cid: 1,
            cmd_sn: 1,
            exp_stat_sn: 1,
            params: TextParameters::new(),
        };
        req.encode_bhs(&mut bhs);

        // flags = T(1) C(0) rsvd(00) CSG(01) NSG(11) = 1000_0111 = 0x87
        assert_eq!(bhs.flags(), 0x87);

        // round-trip
        let decoded = LoginRequest::decode(&bhs, Bytes::new()).unwrap();
        assert!(decoded.transit);
        assert!(!decoded.continue_);
        assert_eq!(decoded.current_stage, LoginStage::Operational);
        assert_eq!(decoded.next_stage, LoginStage::FullFeature);
        assert_eq!(decoded.isid, [0x80, 0x01, 0x02, 0x03, 0x04, 0x05]);
        assert_eq!(decoded.initiator_task_tag, 0xABCD);
    }
}
