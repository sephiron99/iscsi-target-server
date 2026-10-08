//! Runtime-independent iSCSI wire framing.
//!
//! A frame is laid out as:
//! `BHS | AHS | HeaderDigest? | Data | DataPadding | DataDigest?`.
//! `TotalAHSLength` already expresses the complete, 4-byte-aligned AHS area.

use bytes::{Bytes, BytesMut};

use crate::digest::{DigestType, crc32c_slices};
use crate::error::{FrameError, PduError};
use crate::{BHS_LEN, Opcode, Pdu};

/// Largest AHS area representable by the one-byte TotalAHSLength field.
pub const MAX_AHS_LENGTH: usize = (u8::MAX as usize) * 4;
/// Largest data segment representable by the 24-bit DataSegmentLength field.
pub const MAX_DATA_SEGMENT_LENGTH: usize = 0x00ff_ffff;
/// RFC 7143 default for each endpoint's MaxRecvDataSegmentLength declaration.
pub const DEFAULT_MAX_RECV_DATA_SEGMENT_LENGTH: usize = 8192;

const DIGEST_LEN: usize = 4;

#[inline]
const fn padding_len(len: usize) -> usize {
    (4 - (len & 3)) & 3
}

#[inline]
fn data_segment_length(bhs: &[u8; BHS_LEN]) -> usize {
    ((bhs[5] as usize) << 16) | ((bhs[6] as usize) << 8) | bhs[7] as usize
}

#[inline]
fn ahs_length(bhs: &[u8; BHS_LEN]) -> usize {
    bhs[4] as usize * 4
}

#[inline]
fn is_login_pdu(bhs: &[u8; BHS_LEN]) -> bool {
    matches!(
        bhs[0] & 0x3f,
        value if value == Opcode::LoginRequest as u8 || value == Opcode::LoginResponse as u8
    )
}

/// Connection-level settings needed to frame PDUs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameConfig {
    header_digest: DigestType,
    data_digest: DigestType,
    max_ahs_length: usize,
    max_recv_data_segment_length: usize,
    max_send_data_segment_length: usize,
}

impl FrameConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn header_digest(&self) -> DigestType {
        self.header_digest
    }

    pub fn data_digest(&self) -> DigestType {
        self.data_digest
    }

    pub fn max_ahs_length(&self) -> usize {
        self.max_ahs_length
    }

    /// Largest data segment accepted by the decoder from the peer.
    pub fn max_recv_data_segment_length(&self) -> usize {
        self.max_recv_data_segment_length
    }

    /// Largest data segment emitted by the encoder for the peer.
    pub fn max_send_data_segment_length(&self) -> usize {
        self.max_send_data_segment_length
    }

    pub fn set_digests(&mut self, header: DigestType, data: DigestType) {
        self.header_digest = header;
        self.data_digest = data;
    }

    pub fn set_max_ahs_length(&mut self, len: usize) {
        self.max_ahs_length = len.min(MAX_AHS_LENGTH);
    }

    pub fn set_max_recv_data_segment_length(&mut self, len: usize) {
        self.max_recv_data_segment_length = len.min(MAX_DATA_SEGMENT_LENGTH);
    }

    pub fn set_max_send_data_segment_length(&mut self, len: usize) {
        self.max_send_data_segment_length = len.min(MAX_DATA_SEGMENT_LENGTH);
    }

    fn digest_lengths(&self, bhs: &[u8; BHS_LEN], data_len: usize) -> (usize, usize) {
        // Login Request/Response formats do not carry negotiated digests.
        if is_login_pdu(bhs) {
            return (0, 0);
        }

        let header = self.header_digest.wire_len();
        let data = if data_len == 0 {
            0
        } else {
            self.data_digest.wire_len()
        };
        (header, data)
    }
}

impl Default for FrameConfig {
    fn default() -> Self {
        Self {
            header_digest: DigestType::None,
            data_digest: DigestType::None,
            max_ahs_length: MAX_AHS_LENGTH,
            max_recv_data_segment_length: DEFAULT_MAX_RECV_DATA_SEGMENT_LENGTH,
            max_send_data_segment_length: DEFAULT_MAX_RECV_DATA_SEGMENT_LENGTH,
        }
    }
}

/// A validated logical frame with padding and digests removed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawFrame {
    pub bhs: [u8; BHS_LEN],
    pub ahs: Bytes,
    pub data: Bytes,
}

impl RawFrame {
    pub fn new(mut bhs: [u8; BHS_LEN], ahs: Bytes, data: Bytes) -> Result<Self, FrameError> {
        if ahs.len() & 3 != 0 {
            return Err(FrameError::InvalidAhsLength { len: ahs.len() });
        }
        if ahs.len() > MAX_AHS_LENGTH {
            return Err(FrameError::AhsTooLarge {
                len: ahs.len(),
                max: MAX_AHS_LENGTH,
            });
        }
        if data.len() > MAX_DATA_SEGMENT_LENGTH {
            return Err(FrameError::DataSegmentTooLarge {
                len: data.len(),
                max: MAX_DATA_SEGMENT_LENGTH,
            });
        }

        bhs[4] = (ahs.len() / 4) as u8;
        bhs[5] = (data.len() >> 16) as u8;
        bhs[6] = (data.len() >> 8) as u8;
        bhs[7] = data.len() as u8;

        Ok(Self { bhs, ahs, data })
    }

    pub fn from_pdu(pdu: &Pdu, ahs: Bytes) -> Result<Self, FrameError> {
        let (bhs, data) = pdu.encode_parts();
        Self::new(bhs, ahs, data)
    }

    pub fn into_pdu(self) -> Result<PduFrame, PduError> {
        let Self { bhs, ahs, data } = self;
        let pdu = Pdu::decode(&bhs, data)?;
        Ok(PduFrame { pdu, ahs })
    }
}

/// A typed PDU together with any AHS bytes carried by its frame.
#[derive(Debug, Clone)]
pub struct PduFrame {
    pub pdu: Pdu,
    pub ahs: Bytes,
}

impl PduFrame {
    pub fn new(pdu: Pdu, ahs: Bytes) -> Self {
        Self { pdu, ahs }
    }

    pub fn without_ahs(pdu: Pdu) -> Self {
        Self::new(pdu, Bytes::new())
    }

    pub fn into_raw(self) -> Result<RawFrame, FrameError> {
        RawFrame::from_pdu(&self.pdu, self.ahs)
    }
}

impl From<Pdu> for PduFrame {
    fn from(pdu: Pdu) -> Self {
        Self::without_ahs(pdu)
    }
}

/// Incremental frame encoder/decoder with no async-runtime dependency.
#[derive(Debug, Clone)]
pub struct FrameCodec {
    config: FrameConfig,
}

impl FrameCodec {
    pub fn new(config: FrameConfig) -> Self {
        Self { config }
    }

    pub fn config(&self) -> &FrameConfig {
        &self.config
    }

    pub fn config_mut(&mut self) -> &mut FrameConfig {
        &mut self.config
    }

    /// Decode one complete frame. `Ok(None)` means more bytes are required.
    /// Incomplete input is never consumed.
    pub fn decode(&self, src: &mut BytesMut) -> Result<Option<RawFrame>, FrameError> {
        if src.len() < BHS_LEN {
            return Ok(None);
        }

        let mut bhs = [0u8; BHS_LEN];
        bhs.copy_from_slice(&src[..BHS_LEN]);

        let ahs_len = ahs_length(&bhs);
        let data_len = data_segment_length(&bhs);
        self.validate_lengths(ahs_len, data_len, self.config.max_recv_data_segment_length)?;

        let (header_digest_len, data_digest_len) = self.config.digest_lengths(&bhs, data_len);
        let data_padding_len = padding_len(data_len);
        let total_len = BHS_LEN
            .checked_add(ahs_len)
            .and_then(|len| len.checked_add(header_digest_len))
            .and_then(|len| len.checked_add(data_len))
            .and_then(|len| len.checked_add(data_padding_len))
            .and_then(|len| len.checked_add(data_digest_len))
            .ok_or(FrameError::LengthOverflow)?;

        if src.len() < total_len {
            src.reserve(total_len - src.len());
            return Ok(None);
        }

        let mut encoded = src.split_to(total_len);
        let _bhs_bytes = encoded.split_to(BHS_LEN);
        let ahs = encoded.split_to(ahs_len).freeze();

        if header_digest_len != 0 {
            let digest_bytes = encoded.split_to(DIGEST_LEN);
            let received = u32::from_le_bytes(digest_bytes[..].try_into().expect("4 bytes"));
            let expected = crc32c_slices(&[&bhs, &ahs]);
            if received != expected {
                return Err(FrameError::HeaderDigestMismatch);
            }
        }

        let data = encoded.split_to(data_len).freeze();
        let data_padding = encoded.split_to(data_padding_len);

        if data_digest_len != 0 {
            let digest_bytes = encoded.split_to(DIGEST_LEN);
            let received = u32::from_le_bytes(digest_bytes[..].try_into().expect("4 bytes"));
            let expected = crc32c_slices(&[&data, &data_padding]);
            if received != expected {
                return Err(FrameError::DataDigestMismatch);
            }
        }

        debug_assert!(encoded.is_empty());
        Ok(Some(RawFrame { bhs, ahs, data }))
    }

    pub fn encode(&self, frame: &RawFrame, dst: &mut BytesMut) -> Result<(), FrameError> {
        self.validate_frame(frame)?;

        let data_len = frame.data.len();
        let data_padding_len = padding_len(data_len);
        let (header_digest_len, data_digest_len) = self.config.digest_lengths(&frame.bhs, data_len);
        let additional = frame
            .ahs
            .len()
            .checked_add(header_digest_len)
            .and_then(|len| len.checked_add(data_len))
            .and_then(|len| len.checked_add(data_padding_len))
            .and_then(|len| len.checked_add(data_digest_len))
            .ok_or(FrameError::LengthOverflow)?;

        let total_len = BHS_LEN
            .checked_add(additional)
            .ok_or(FrameError::LengthOverflow)?;
        dst.reserve(total_len);
        dst.extend_from_slice(&frame.bhs);
        dst.extend_from_slice(&frame.ahs);

        if header_digest_len != 0 {
            let digest = crc32c_slices(&[&frame.bhs, &frame.ahs]);
            dst.extend_from_slice(&digest.to_le_bytes());
        }

        dst.extend_from_slice(&frame.data);
        const ZERO_PADDING: [u8; 3] = [0; 3];
        let padding = &ZERO_PADDING[..data_padding_len];
        dst.extend_from_slice(padding);

        if data_digest_len != 0 {
            let digest = crc32c_slices(&[&frame.data, padding]);
            dst.extend_from_slice(&digest.to_le_bytes());
        }

        Ok(())
    }

    fn validate_lengths(
        &self,
        ahs_len: usize,
        data_len: usize,
        max_data_segment_length: usize,
    ) -> Result<(), FrameError> {
        if ahs_len > self.config.max_ahs_length {
            return Err(FrameError::AhsTooLarge {
                len: ahs_len,
                max: self.config.max_ahs_length,
            });
        }
        if data_len > max_data_segment_length {
            return Err(FrameError::DataSegmentTooLarge {
                len: data_len,
                max: max_data_segment_length,
            });
        }
        Ok(())
    }

    fn validate_frame(&self, frame: &RawFrame) -> Result<(), FrameError> {
        if frame.ahs.len() & 3 != 0 {
            return Err(FrameError::InvalidAhsLength {
                len: frame.ahs.len(),
            });
        }
        self.validate_lengths(
            frame.ahs.len(),
            frame.data.len(),
            self.config.max_send_data_segment_length,
        )?;

        let declared_ahs = ahs_length(&frame.bhs);
        if declared_ahs != frame.ahs.len() {
            return Err(FrameError::LengthMismatch {
                segment: "AHS",
                declared: declared_ahs,
                actual: frame.ahs.len(),
            });
        }

        let declared_data = data_segment_length(&frame.bhs);
        if declared_data != frame.data.len() {
            return Err(FrameError::LengthMismatch {
                segment: "data segment",
                declared: declared_data,
                actual: frame.data.len(),
            });
        }
        Ok(())
    }
}

impl Default for FrameCodec {
    fn default() -> Self {
        Self::new(FrameConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::digest::crc32c;

    fn raw_frame(opcode: Opcode, ahs: &'static [u8], data: &'static [u8]) -> RawFrame {
        let mut bhs = [0u8; BHS_LEN];
        bhs[0] = opcode as u8;
        RawFrame::new(bhs, Bytes::from_static(ahs), Bytes::from_static(data)).unwrap()
    }

    fn codec_with_digests(header: DigestType, data: DigestType) -> FrameCodec {
        let mut config = FrameConfig::default();
        config.set_digests(header, data);
        FrameCodec::new(config)
    }

    #[test]
    fn round_trips_all_digest_combinations_with_ahs() {
        for header in [DigestType::None, DigestType::Crc32c] {
            for data in [DigestType::None, DigestType::Crc32c] {
                let codec = codec_with_digests(header, data);
                let expected = raw_frame(
                    Opcode::NopOut,
                    b"\x01\x00\x00\x00\xde\xad\xbe\xef",
                    b"hello",
                );
                let mut wire = BytesMut::new();
                codec.encode(&expected, &mut wire).unwrap();

                let decoded = codec.decode(&mut wire).unwrap().unwrap();
                assert_eq!(decoded, expected);
                assert!(wire.is_empty());
            }
        }
    }

    #[test]
    fn accepts_one_byte_at_a_time_without_consuming_incomplete_input() {
        let codec = codec_with_digests(DigestType::Crc32c, DigestType::Crc32c);
        let expected = raw_frame(
            Opcode::ScsiDataOut,
            b"\x01\x00\x00\x00\xde\xad\xbe\xef",
            b"five5",
        );
        let mut encoded = BytesMut::new();
        codec.encode(&expected, &mut encoded).unwrap();

        let wire = encoded.freeze();
        let mut input = BytesMut::new();
        for (index, byte) in wire.iter().copied().enumerate() {
            input.extend_from_slice(&[byte]);
            let before = input.len();
            let decoded = codec.decode(&mut input).unwrap();
            if index + 1 == wire.len() {
                assert_eq!(decoded.unwrap(), expected);
                assert!(input.is_empty());
            } else {
                assert!(decoded.is_none());
                assert_eq!(input.len(), before);
            }
        }
    }

    #[test]
    fn leaves_following_frame_in_input() {
        let codec = FrameCodec::default();
        let first = raw_frame(Opcode::NopOut, b"", b"one");
        let second = raw_frame(Opcode::NopIn, b"", b"two");
        let mut wire = BytesMut::new();
        codec.encode(&first, &mut wire).unwrap();
        codec.encode(&second, &mut wire).unwrap();

        assert_eq!(codec.decode(&mut wire).unwrap().unwrap(), first);
        assert!(!wire.is_empty());
        assert_eq!(codec.decode(&mut wire).unwrap().unwrap(), second);
        assert!(wire.is_empty());
    }

    #[test]
    fn rejects_lengths_before_waiting_for_or_allocating_payload() {
        let mut config = FrameConfig::default();
        config.set_max_ahs_length(4);
        config.set_max_recv_data_segment_length(4);
        let codec = FrameCodec::new(config);

        let mut excessive_ahs = BytesMut::zeroed(BHS_LEN);
        excessive_ahs[4] = 2;
        assert_eq!(
            codec.decode(&mut excessive_ahs),
            Err(FrameError::AhsTooLarge { len: 8, max: 4 })
        );

        let mut excessive_data = BytesMut::zeroed(BHS_LEN);
        excessive_data[7] = 5;
        assert_eq!(
            codec.decode(&mut excessive_data),
            Err(FrameError::DataSegmentTooLarge { len: 5, max: 4 })
        );
    }

    #[test]
    fn rejects_corrupted_header_and_data_digests() {
        let codec = codec_with_digests(DigestType::Crc32c, DigestType::Crc32c);
        let frame = raw_frame(Opcode::NopOut, b"", b"payload");

        let mut header_corrupted = BytesMut::new();
        codec.encode(&frame, &mut header_corrupted).unwrap();
        header_corrupted[8] ^= 1;
        assert_eq!(
            codec.decode(&mut header_corrupted),
            Err(FrameError::HeaderDigestMismatch)
        );

        let mut data_corrupted = BytesMut::new();
        codec.encode(&frame, &mut data_corrupted).unwrap();
        let data_offset = BHS_LEN + DIGEST_LEN;
        data_corrupted[data_offset] ^= 1;
        assert_eq!(
            codec.decode(&mut data_corrupted),
            Err(FrameError::DataDigestMismatch)
        );
    }

    #[test]
    fn login_frames_do_not_carry_negotiated_digests() {
        let codec = codec_with_digests(DigestType::Crc32c, DigestType::Crc32c);
        let frame = raw_frame(Opcode::LoginRequest, b"", b"k=v\0");
        let mut wire = BytesMut::new();
        codec.encode(&frame, &mut wire).unwrap();

        assert_eq!(wire.len(), BHS_LEN + 4);
        assert_eq!(codec.decode(&mut wire).unwrap().unwrap(), frame);
    }

    #[test]
    fn zero_length_data_does_not_carry_a_data_digest() {
        let codec = codec_with_digests(DigestType::Crc32c, DigestType::Crc32c);
        let frame = raw_frame(Opcode::NopOut, b"", b"");
        let mut wire = BytesMut::new();
        codec.encode(&frame, &mut wire).unwrap();

        assert_eq!(wire.len(), BHS_LEN + DIGEST_LEN);
        assert_eq!(codec.decode(&mut wire).unwrap().unwrap(), frame);
    }

    #[test]
    fn configured_limits_are_capped_by_wire_field_widths() {
        let mut config = FrameConfig::default();
        config.set_max_ahs_length(usize::MAX);
        config.set_max_recv_data_segment_length(usize::MAX);
        config.set_max_send_data_segment_length(usize::MAX);
        assert_eq!(config.max_ahs_length(), MAX_AHS_LENGTH);
        assert_eq!(
            config.max_recv_data_segment_length(),
            MAX_DATA_SEGMENT_LENGTH
        );
        assert_eq!(
            config.max_send_data_segment_length(),
            MAX_DATA_SEGMENT_LENGTH
        );
    }

    #[test]
    fn receive_and_send_limits_are_directional() {
        let mut config = FrameConfig::default();
        config.set_max_recv_data_segment_length(4);
        config.set_max_send_data_segment_length(8);
        let codec = FrameCodec::new(config);

        let outbound = raw_frame(Opcode::NopOut, b"", b"12345");
        let mut wire = BytesMut::new();
        codec.encode(&outbound, &mut wire).unwrap();

        assert_eq!(
            codec.decode(&mut wire),
            Err(FrameError::DataSegmentTooLarge { len: 5, max: 4 })
        );
    }

    #[test]
    fn rejects_unaligned_ahs_and_mutated_length_fields() {
        let bhs = [0u8; BHS_LEN];
        assert_eq!(
            RawFrame::new(bhs, Bytes::from_static(b"abc"), Bytes::new()),
            Err(FrameError::InvalidAhsLength { len: 3 })
        );

        let codec = FrameCodec::default();
        let mut frame = raw_frame(Opcode::NopOut, b"", b"data");
        frame.bhs[7] = 3;
        assert_eq!(
            codec.encode(&frame, &mut BytesMut::new()),
            Err(FrameError::LengthMismatch {
                segment: "data segment",
                declared: 3,
                actual: 4,
            })
        );
    }

    #[test]
    fn every_short_bhs_prefix_is_incomplete_and_never_panics() {
        let codec = FrameCodec::default();
        for len in 0..BHS_LEN {
            let mut input = BytesMut::zeroed(len);
            assert!(codec.decode(&mut input).unwrap().is_none());
            assert_eq!(input.len(), len);
        }
    }

    #[test]
    fn data_padding_is_zeroed() {
        let codec = FrameCodec::default();
        let frame = raw_frame(Opcode::NopOut, b"", b"x");
        let mut wire = BytesMut::new();
        codec.encode(&frame, &mut wire).unwrap();
        assert_eq!(&wire[BHS_LEN + 1..], &[0, 0, 0]);
    }

    #[test]
    fn crc_helper_treats_slices_as_one_contiguous_stream() {
        assert_eq!(
            crc32c_slices(&[b"header", b" bytes"]),
            crc32c(b"header bytes")
        );
    }

    #[test]
    fn decoder_covers_received_padding_bytes_with_data_digest() {
        let codec = codec_with_digests(DigestType::None, DigestType::Crc32c);
        let expected = raw_frame(Opcode::NopOut, b"", b"x");
        let mut wire = BytesMut::new();
        codec.encode(&expected, &mut wire).unwrap();

        // Padding SHOULD be zero, but its actual bytes are part of the digest.
        wire[BHS_LEN + 1] = 0x5a;
        let digest = crc32c(&wire[BHS_LEN..BHS_LEN + 4]);
        wire[BHS_LEN + 4..BHS_LEN + 8].copy_from_slice(&digest.to_le_bytes());

        assert_eq!(codec.decode(&mut wire).unwrap().unwrap(), expected);
    }
}
