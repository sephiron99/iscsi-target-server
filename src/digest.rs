// pdu/src/digest.rs
//
// CRC32C (Castagnoli) 다이제스트 — iSCSI 무결성 검증
//
// Login에서 HeaderDigest=CRC32C / DataDigest=CRC32C로 협상되면
// 각 PDU에 다이제스트가 추가됨:
//
//   [BHS 48B] [AHS] [HeaderDigest 4B] [Data Segment + pad] [DataDigest 4B]
//
// 중요: 다이제스트는 PDU 계층의 책임이 아님.
// PDU는 "논리적 내용"만 알고, 다이제스트 유무는 협상된 "연결 상태"에 의존.
// 따라서 codec(연결 상태를 아는 계층)에서 추가/검증.
//
// 이 분리가 중요한 이유:
// - 같은 Pdu 구조체가 다이제스트 on/off 양쪽에서 재사용됨
// - 테스트 시 다이제스트 없이 PDU 로직만 검증 가능

/// CRC32C 계산.
///
/// `crc32c` crate는 지원되는 플랫폼에서 하드웨어 가속을 사용한다.
#[inline]
pub fn crc32c(data: &[u8]) -> u32 {
    ::crc32c::crc32c(data)
}

/// 여러 연속 slice를 하나의 byte stream으로 간주하여 CRC32C를 계산한다.
pub(crate) fn crc32c_slices(parts: &[&[u8]]) -> u32 {
    parts
        .iter()
        .fold(0, |crc, part| ::crc32c::crc32c_append(crc, part))
}

/// 다이제스트 방식
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestType {
    None,
    Crc32c,
}

#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
#[error("unsupported digest value {0:?}")]
pub struct ParseDigestError(String);

impl DigestType {
    /// Parse the case-sensitive RFC 7143 negotiation value.
    pub fn from_text_value(s: &str) -> Result<Self, ParseDigestError> {
        match s {
            "None" => Ok(DigestType::None),
            "CRC32C" => Ok(DigestType::Crc32c),
            _ => Err(ParseDigestError(s.to_owned())),
        }
    }

    /// 다이제스트가 차지하는 바이트 수
    pub fn wire_len(&self) -> usize {
        match self {
            DigestType::None => 0,
            DigestType::Crc32c => 4,
        }
    }

    pub fn is_enabled(&self) -> bool {
        matches!(self, DigestType::Crc32c)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crc32c_known_vector() {
        // CRC32C("123456789") = 0xE3069283 (표준 테스트 벡터)
        assert_eq!(crc32c(b"123456789"), 0xE3069283);
    }

    #[test]
    fn test_crc32c_empty() {
        assert_eq!(crc32c(b""), 0x00000000);
    }

    #[test]
    fn test_rfc7143_zero_vector_wire_order() {
        // RFC 7143 Appendix A.4: 32 zero bytes -> aa 36 91 8a on the wire.
        let crc = crc32c(&[0; 32]);
        assert_eq!(crc.to_le_bytes(), [0xaa, 0x36, 0x91, 0x8a]);
    }

    #[test]
    fn test_rfc7143_scsi_read10_header_vector() {
        // RFC 7143 Appendix A.4 SCSI Read(10) Command PDU.
        let header = [
            0x01, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0..7
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 8..15
            0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, // 16..23
            0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x18, // 24..31
            0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 32..39
            0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 40..47
        ];
        assert_eq!(crc32c(&header).to_le_bytes(), [0x56, 0x3a, 0x96, 0xd9]);
    }

    #[test]
    fn test_digest_type_parse() {
        assert_eq!(
            DigestType::from_text_value("CRC32C"),
            Ok(DigestType::Crc32c)
        );
        assert_eq!(DigestType::from_text_value("None"), Ok(DigestType::None));
        assert_eq!(
            DigestType::from_text_value("crc32c"),
            Err(ParseDigestError("crc32c".to_owned()))
        );
        assert_eq!(DigestType::Crc32c.wire_len(), 4);
    }
}
