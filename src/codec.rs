//! Tokio adapter for the runtime-independent iSCSI frame codec.

use bytes::{Bytes, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

use crate::Pdu;
use crate::digest::DigestType;
use crate::error::CodecError;
use crate::frame::{FrameCodec, FrameConfig, PduFrame, RawFrame};
use crate::login::{LoginRequest, LoginResponse};
use crate::negotiation::{NegotiatedFrameParameters, NegotiationError, TargetLoginNegotiation};

/// Converts a Tokio byte stream into typed iSCSI PDUs while preserving AHS.
pub struct IscsiCodec {
    frames: FrameCodec,
}

impl IscsiCodec {
    pub fn new() -> Self {
        Self {
            frames: FrameCodec::default(),
        }
    }

    pub fn with_config(config: FrameConfig) -> Self {
        Self {
            frames: FrameCodec::new(config),
        }
    }

    pub fn frame_config(&self) -> &FrameConfig {
        self.frames.config()
    }

    /// Apply digest algorithms after Login negotiation completes.
    pub fn set_digests(&mut self, header: DigestType, data: DigestType) {
        self.frames.config_mut().set_digests(header, data);
    }

    pub fn set_max_ahs_length(&mut self, len: usize) {
        self.frames.config_mut().set_max_ahs_length(len);
    }

    pub fn set_max_recv_data_segment_length(&mut self, len: usize) {
        self.frames
            .config_mut()
            .set_max_recv_data_segment_length(len);
    }

    pub fn set_max_send_data_segment_length(&mut self, len: usize) {
        self.frames
            .config_mut()
            .set_max_send_data_segment_length(len);
    }

    pub fn apply_negotiated_frame_parameters(&mut self, parameters: NegotiatedFrameParameters) {
        parameters.apply_to(self.frames.config_mut());
    }

    /// Record a target-side Login exchange and atomically activate its result.
    ///
    /// Call this after the corresponding Login Response has been queued. The
    /// codec remains on its prior settings until a successful response enters
    /// Full Feature Phase.
    pub fn observe_target_login_exchange(
        &mut self,
        negotiation: &mut TargetLoginNegotiation,
        request: &LoginRequest,
        response: &LoginResponse,
    ) -> Result<Option<NegotiatedFrameParameters>, NegotiationError> {
        let completed = negotiation.observe_exchange(request, response)?;
        if let Some(parameters) = completed {
            self.apply_negotiated_frame_parameters(parameters);
        }
        Ok(completed)
    }
}

impl Default for IscsiCodec {
    fn default() -> Self {
        Self::new()
    }
}

impl Decoder for IscsiCodec {
    type Item = PduFrame;
    type Error = CodecError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let Some(frame) = self.frames.decode(src)? else {
            return Ok(None);
        };
        Ok(Some(frame.into_pdu()?))
    }
}

/// Compatibility encoder for PDUs that do not carry an AHS.
impl Encoder<Pdu> for IscsiCodec {
    type Error = CodecError;

    fn encode(&mut self, item: Pdu, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let frame = RawFrame::from_pdu(&item, Bytes::new())?;
        self.frames.encode(&frame, dst)?;
        Ok(())
    }
}

impl Encoder<PduFrame> for IscsiCodec {
    type Error = CodecError;

    fn encode(&mut self, item: PduFrame, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let frame = item.into_raw()?;
        self.frames.encode(&frame, dst)?;
        Ok(())
    }
}

impl Encoder<RawFrame> for IscsiCodec {
    type Error = CodecError;

    fn encode(&mut self, item: RawFrame, dst: &mut BytesMut) -> Result<(), Self::Error> {
        self.frames.encode(&item, dst)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::NopOut;
    use crate::login::TextParameters;
    use crate::opcode::LoginStage;

    fn nop_out(data: Bytes) -> Pdu {
        Pdu::NopOut(NopOut {
            immediate: true,
            lun: 0,
            initiator_task_tag: 7,
            target_transfer_tag: u32::MAX,
            cmd_sn: 11,
            exp_stat_sn: 13,
            data,
        })
    }

    fn login_request(transit: bool, next_stage: LoginStage, text: &[u8]) -> LoginRequest {
        LoginRequest {
            transit,
            continue_: false,
            current_stage: LoginStage::Operational,
            next_stage,
            version_max: 0,
            version_min: 0,
            isid: [0x80, 1, 2, 3, 4, 5],
            tsih: 0,
            initiator_task_tag: 1,
            cid: 0,
            cmd_sn: 1,
            exp_stat_sn: 0,
            params: TextParameters::parse(text),
        }
    }

    fn login_response(transit: bool, next_stage: LoginStage, text: &[u8]) -> LoginResponse {
        LoginResponse {
            transit,
            continue_: false,
            current_stage: LoginStage::Operational,
            next_stage,
            version_max: 0,
            version_active: 0,
            isid: [0x80, 1, 2, 3, 4, 5],
            tsih: 1,
            initiator_task_tag: 1,
            stat_sn: 1,
            exp_cmd_sn: 2,
            max_cmd_sn: 3,
            status_class: 0,
            status_detail: 0,
            params: TextParameters::parse(text),
        }
    }

    #[test]
    fn codec_error_satisfies_tokio_io_bound() {
        fn assert_from_io<T: From<std::io::Error>>() {}
        assert_from_io::<CodecError>();
    }

    #[test]
    fn tokio_adapter_round_trips_pdu_and_ahs_with_digests() {
        let ahs = Bytes::from_static(b"\x01\x00\x00\x00\xde\xad\xbe\xef");
        let pdu = PduFrame::new(nop_out(Bytes::from_static(b"ping")), ahs.clone());

        let mut encoder = IscsiCodec::new();
        encoder.set_digests(DigestType::Crc32c, DigestType::Crc32c);
        let mut wire = BytesMut::new();
        Encoder::encode(&mut encoder, pdu, &mut wire).unwrap();

        let mut decoder = IscsiCodec::new();
        decoder.set_digests(DigestType::Crc32c, DigestType::Crc32c);
        let decoded = Decoder::decode(&mut decoder, &mut wire).unwrap().unwrap();

        assert_eq!(decoded.ahs, ahs);
        match decoded.pdu {
            Pdu::NopOut(pdu) => assert_eq!(pdu.data, Bytes::from_static(b"ping")),
            other => panic!("unexpected PDU: {other:?}"),
        }
        assert!(wire.is_empty());
    }

    #[test]
    fn compatibility_pdu_encoder_uses_empty_ahs() {
        let mut codec = IscsiCodec::new();
        let mut wire = BytesMut::new();
        Encoder::encode(&mut codec, nop_out(Bytes::from_static(b"echo")), &mut wire).unwrap();

        let decoded = Decoder::decode(&mut codec, &mut wire).unwrap().unwrap();
        assert!(decoded.ahs.is_empty());
        assert!(matches!(decoded.pdu, Pdu::NopOut(_)));
    }

    #[test]
    fn decode_eof_reports_truncated_frame_as_io_error() {
        let mut codec = IscsiCodec::new();
        let mut truncated = BytesMut::from(&[0u8; 47][..]);
        let error = Decoder::decode_eof(&mut codec, &mut truncated).unwrap_err();
        assert!(matches!(error, CodecError::Io(_)));
    }

    #[test]
    fn login_result_is_applied_only_on_full_feature_transition() {
        let mut codec = IscsiCodec::new();
        let mut negotiation = TargetLoginNegotiation::new();
        let initial_config = *codec.frame_config();
        let proposal = login_request(
            false,
            LoginStage::Operational,
            b"HeaderDigest=CRC32C,None\0DataDigest=CRC32C,None\0MaxRecvDataSegmentLength=4096\0",
        );
        let invalid_selection = login_response(
            false,
            LoginStage::Operational,
            b"HeaderDigest=CRC32C\0DataDigest=Unsupported\0MaxRecvDataSegmentLength=16384\0",
        );
        let selection = login_response(
            false,
            LoginStage::Operational,
            b"HeaderDigest=CRC32C\0DataDigest=CRC32C\0MaxRecvDataSegmentLength=16384\0",
        );

        assert!(matches!(
            codec.observe_target_login_exchange(&mut negotiation, &proposal, &invalid_selection),
            Err(NegotiationError::DigestNotOffered { .. })
        ));
        assert_eq!(*codec.frame_config(), initial_config);
        assert_eq!(negotiation.parameters(), None);

        assert_eq!(
            codec
                .observe_target_login_exchange(&mut negotiation, &proposal, &selection)
                .unwrap(),
            None
        );
        assert_eq!(*codec.frame_config(), initial_config);
        assert_eq!(negotiation.parameters(), None);

        let final_request = login_request(true, LoginStage::FullFeature, b"");
        let final_response = login_response(true, LoginStage::FullFeature, b"");
        let completed = codec
            .observe_target_login_exchange(&mut negotiation, &final_request, &final_response)
            .unwrap()
            .unwrap();

        assert_eq!(completed.header_digest(), DigestType::Crc32c);
        let mut expected_config = initial_config;
        expected_config.set_digests(DigestType::Crc32c, DigestType::Crc32c);
        expected_config.set_max_recv_data_segment_length(16384);
        expected_config.set_max_send_data_segment_length(4096);
        assert_eq!(*codec.frame_config(), expected_config);

        let mut wire = BytesMut::new();
        Encoder::encode(&mut codec, nop_out(Bytes::from_static(b"x")), &mut wire).unwrap();
        assert_eq!(wire.len(), 48 + 4 + 4 + 4);
    }
}
