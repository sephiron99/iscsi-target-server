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

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TextParameters {
    entries: Vec<(String, String)>,
    encoded: Bytes,
}

#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum TextParameterError {
    #[error("text parameter sequence is not NUL-terminated")]
    MissingTerminator,

    #[error("empty text parameter at byte offset {offset}")]
    EmptyEntry { offset: usize },

    #[error("text parameter at byte offset {offset} is missing '='")]
    MissingEquals { offset: usize },

    #[error("text parameter key at byte offset {offset} is empty")]
    EmptyKey { offset: usize },

    #[error("text parameter contains invalid UTF-8 at byte offset {offset}")]
    InvalidUtf8 { offset: usize },
}

impl TextParameters {
    pub fn new() -> Self {
        Self::default()
    }

    /// Parse a data segment while preserving its exact wire bytes.
    ///
    /// The structured view is intentionally permissive because a Login/Text
    /// PDU with the Continue bit may end in the middle of a key-value pair.
    pub fn parse(data: &[u8]) -> Self {
        Self::from_bytes(Bytes::copy_from_slice(data))
    }

    pub fn from_bytes(encoded: Bytes) -> Self {
        let mut pairs = Vec::new();
        for entry in encoded.split(|&b| b == 0) {
            if entry.is_empty() {
                continue;
            }
            if let Some(pos) = entry.iter().position(|&b| b == b'=') {
                let key = String::from_utf8_lossy(&entry[..pos]).into_owned();
                let value = String::from_utf8_lossy(&entry[pos + 1..]).into_owned();
                pairs.push((key, value));
            }
        }
        Self {
            entries: pairs,
            encoded,
        }
    }

    /// Strictly parse one complete NUL-terminated negotiation sequence.
    pub fn parse_complete(data: &[u8]) -> Result<Self, TextParameterError> {
        Self::from_complete_bytes(Bytes::copy_from_slice(data))
    }

    pub(crate) fn from_complete_bytes(encoded: Bytes) -> Result<Self, TextParameterError> {
        if encoded.is_empty() {
            return Ok(Self::new());
        }
        if encoded.last() != Some(&0) {
            return Err(TextParameterError::MissingTerminator);
        }

        let mut entries = Vec::new();
        let mut offset = 0;
        for entry in encoded[..encoded.len() - 1].split(|&byte| byte == 0) {
            if entry.is_empty() {
                return Err(TextParameterError::EmptyEntry { offset });
            }
            let text =
                std::str::from_utf8(entry).map_err(|error| TextParameterError::InvalidUtf8 {
                    offset: offset + error.valid_up_to(),
                })?;
            let Some(equals) = text.find('=') else {
                return Err(TextParameterError::MissingEquals { offset });
            };
            if equals == 0 {
                return Err(TextParameterError::EmptyKey { offset });
            }
            entries.push((text[..equals].to_owned(), text[equals + 1..].to_owned()));
            offset += entry.len() + 1;
        }

        Ok(Self { entries, encoded })
    }

    /// Return the exact data-segment bytes, including any partial entry.
    pub fn encode(&self) -> Bytes {
        self.encoded.clone()
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.encoded
    }

    pub fn is_empty(&self) -> bool {
        self.encoded.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.entries
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str()))
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.entries
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    pub fn push(&mut self, key: &str, value: &str) {
        let terminate_partial = !self.encoded.is_empty() && self.encoded.last() != Some(&0);
        let mut encoded = BytesMut::with_capacity(
            self.encoded.len() + key.len() + value.len() + 2 + usize::from(terminate_partial),
        );
        encoded.extend_from_slice(&self.encoded);
        if terminate_partial {
            encoded.put_u8(0);
        }
        encoded.extend_from_slice(key.as_bytes());
        encoded.put_u8(b'=');
        encoded.extend_from_slice(value.as_bytes());
        encoded.put_u8(0);
        self.encoded = encoded.freeze();
        self.entries.push((key.to_owned(), value.to_owned()));
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
            params: TextParameters::from_bytes(data),
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
            params: TextParameters::from_bytes(data),
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
    fn text_params_preserve_a_partial_wire_entry() {
        let partial = b"HeaderDigest=CRC";
        let params = TextParameters::parse(partial);

        assert_eq!(params.as_bytes(), partial);
        assert_eq!(params.encode(), Bytes::from_static(partial));
        assert_eq!(params.get("HeaderDigest"), Some("CRC"));
        assert_eq!(
            TextParameters::parse_complete(partial),
            Err(TextParameterError::MissingTerminator)
        );
    }

    #[test]
    fn complete_text_parser_rejects_malformed_entries() {
        assert_eq!(
            TextParameters::parse_complete(b"HeaderDigest\0"),
            Err(TextParameterError::MissingEquals { offset: 0 })
        );
        assert_eq!(
            TextParameters::parse_complete(b"=CRC32C\0"),
            Err(TextParameterError::EmptyKey { offset: 0 })
        );
        assert_eq!(
            TextParameters::parse_complete(b"Key=ok\0\xff=x\0"),
            Err(TextParameterError::InvalidUtf8 { offset: 7 })
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
