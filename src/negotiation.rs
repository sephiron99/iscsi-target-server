//! Connection-level parameters produced by Login negotiation.
//!
//! The wire codec deliberately does not interpret Login text. This module
//! bridges that boundary for a target: it accumulates initiator requests and
//! target responses, validates the framing-related keys, and publishes one
//! atomic result when Login enters Full Feature Phase.

use bytes::BytesMut;

use crate::digest::DigestType;
use crate::frame::{FrameConfig, DEFAULT_MAX_RECV_DATA_SEGMENT_LENGTH, MAX_DATA_SEGMENT_LENGTH};
use crate::login::{LoginRequest, LoginResponse, TextParameterError, TextParameters};
use crate::opcode::LoginStage;

pub const MIN_MAX_RECV_DATA_SEGMENT_LENGTH: usize = 512;
pub const MIN_LOGIN_TEXT_SEQUENCE_LENGTH: usize = 8192;
pub const DEFAULT_MAX_LOGIN_TEXT_SEQUENCE_LENGTH: usize = 64 * 1024;

const HEADER_DIGEST: &str = "HeaderDigest";
const DATA_DIGEST: &str = "DataDigest";
const MAX_RECV_DATA_SEGMENT_LENGTH_KEY: &str = "MaxRecvDataSegmentLength";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginSide {
    Initiator,
    Target,
}

#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum NegotiationError {
    #[error("login was rejected with status {status_class:#04x}/{status_detail:#04x}")]
    LoginRejected { status_class: u8, status_detail: u8 },

    #[error("login negotiation is already complete")]
    AlreadyComplete,

    #[error("Login Request stage {request:?} does not match response stage {response:?}")]
    StageMismatch {
        request: LoginStage,
        response: LoginStage,
    },

    #[error("expected Login stage {expected:?}, got {actual:?}")]
    UnexpectedStage {
        expected: LoginStage,
        actual: LoginStage,
    },

    #[error("invalid Login transition: {0}")]
    InvalidTransition(&'static str),

    #[error("invalid Login continuation: {0}")]
    InvalidContinuation(&'static str),

    #[error("invalid {side:?} Login text: {source}")]
    InvalidText {
        side: LoginSide,
        source: TextParameterError,
    },

    #[error("{side:?} Login text sequence length {len} exceeds maximum {max}")]
    TextSequenceTooLarge {
        side: LoginSide,
        len: usize,
        max: usize,
    },

    #[error("operational key {key} appeared during {stage:?}")]
    KeyInWrongStage {
        key: &'static str,
        stage: LoginStage,
    },

    #[error("{side:?} declared {key} more than once")]
    DuplicateDeclaration { side: LoginSide, key: &'static str },

    #[error("invalid {key} proposal {value:?} from {side:?}")]
    InvalidDigestProposal {
        side: LoginSide,
        key: &'static str,
        value: String,
    },

    #[error("invalid {key} selection {value:?} from {side:?}")]
    InvalidDigestSelection {
        side: LoginSide,
        key: &'static str,
        value: String,
    },

    #[error("{side:?} selected {selected:?} for {key}, but it was not offered")]
    DigestNotOffered {
        side: LoginSide,
        key: &'static str,
        selected: String,
    },

    #[error("unsupported negotiated digest {value:?} for {key}")]
    UnsupportedDigest { key: &'static str, value: String },

    #[error("{key} was sent again after a proposal or completed selection")]
    RepeatedDigestKey { key: &'static str },

    #[error("{key} still has an unanswered proposal at Login completion")]
    IncompleteDigestNegotiation { key: &'static str },

    #[error("invalid MaxRecvDataSegmentLength {value:?} from {side:?}")]
    InvalidMaxRecvDataSegmentLength { side: LoginSide, value: String },

    #[error("MaxRecvDataSegmentLength {value} from {side:?} is outside {min}..={max}")]
    MaxRecvDataSegmentLengthOutOfRange {
        side: LoginSide,
        value: usize,
        min: usize,
        max: usize,
    },
}

/// Framing values that become effective after a successful Login negotiation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NegotiatedFrameParameters {
    header_digest: DigestType,
    data_digest: DigestType,
    local_max_recv_data_segment_length: usize,
    peer_max_recv_data_segment_length: usize,
}

impl NegotiatedFrameParameters {
    pub fn new(
        header_digest: DigestType,
        data_digest: DigestType,
        local_max_recv_data_segment_length: usize,
        peer_max_recv_data_segment_length: usize,
    ) -> Result<Self, NegotiationError> {
        validate_max_recv(LoginSide::Target, local_max_recv_data_segment_length)?;
        validate_max_recv(LoginSide::Initiator, peer_max_recv_data_segment_length)?;
        Ok(Self {
            header_digest,
            data_digest,
            local_max_recv_data_segment_length,
            peer_max_recv_data_segment_length,
        })
    }

    pub fn header_digest(self) -> DigestType {
        self.header_digest
    }

    pub fn data_digest(self) -> DigestType {
        self.data_digest
    }

    /// Maximum data segment this target declared it can receive.
    pub fn local_max_recv_data_segment_length(self) -> usize {
        self.local_max_recv_data_segment_length
    }

    /// Maximum data segment the initiator declared it can receive.
    pub fn peer_max_recv_data_segment_length(self) -> usize {
        self.peer_max_recv_data_segment_length
    }

    pub fn apply_to(self, config: &mut FrameConfig) {
        config.set_digests(self.header_digest, self.data_digest);
        config.set_max_recv_data_segment_length(self.local_max_recv_data_segment_length);
        config.set_max_send_data_segment_length(self.peer_max_recv_data_segment_length);
    }
}

impl Default for NegotiatedFrameParameters {
    fn default() -> Self {
        Self {
            header_digest: DigestType::None,
            data_digest: DigestType::None,
            local_max_recv_data_segment_length: DEFAULT_MAX_RECV_DATA_SEGMENT_LENGTH,
            peer_max_recv_data_segment_length: DEFAULT_MAX_RECV_DATA_SEGMENT_LENGTH,
        }
    }
}

#[derive(Debug, Clone, Default)]
enum DigestNegotiation {
    #[default]
    Unset,
    Proposed {
        by: LoginSide,
        offered: Vec<String>,
    },
    Complete(DigestType),
}

impl DigestNegotiation {
    fn observe(
        &mut self,
        key: &'static str,
        side: LoginSide,
        value: &str,
    ) -> Result<(), NegotiationError> {
        match self {
            Self::Unset => {
                let offered = parse_digest_proposal(key, side, value)?;
                *self = Self::Proposed { by: side, offered };
                Ok(())
            }
            Self::Proposed { by, offered } => {
                if *by == side {
                    return Err(NegotiationError::RepeatedDigestKey { key });
                }
                if value == "Reject" {
                    *self = Self::Complete(DigestType::None);
                    return Ok(());
                }
                if value.contains(',') || value.is_empty() {
                    return Err(NegotiationError::InvalidDigestSelection {
                        side,
                        key,
                        value: value.to_owned(),
                    });
                }
                if !offered.iter().any(|candidate| candidate == value) {
                    return Err(NegotiationError::DigestNotOffered {
                        side,
                        key,
                        selected: value.to_owned(),
                    });
                }
                let selected = match value {
                    "None" => DigestType::None,
                    "CRC32C" => DigestType::Crc32c,
                    _ => {
                        return Err(NegotiationError::UnsupportedDigest {
                            key,
                            value: value.to_owned(),
                        })
                    }
                };
                *self = Self::Complete(selected);
                Ok(())
            }
            Self::Complete(_) => Err(NegotiationError::RepeatedDigestKey { key }),
        }
    }

    fn finish(&self, key: &'static str) -> Result<DigestType, NegotiationError> {
        match self {
            Self::Unset => Ok(DigestType::None),
            Self::Complete(digest) => Ok(*digest),
            Self::Proposed { .. } => Err(NegotiationError::IncompleteDigestNegotiation { key }),
        }
    }
}

fn parse_digest_proposal(
    key: &'static str,
    side: LoginSide,
    value: &str,
) -> Result<Vec<String>, NegotiationError> {
    let offered: Vec<_> = value.split(',').map(str::to_owned).collect();
    if offered.is_empty()
        || offered.iter().any(|item| {
            item.is_empty() || matches!(item.as_str(), "Reject" | "Irrelevant" | "NotUnderstood")
        })
    {
        return Err(NegotiationError::InvalidDigestProposal {
            side,
            key,
            value: value.to_owned(),
        });
    }
    Ok(offered)
}

/// Target-side accumulator for framing-related Login keys.
#[derive(Debug, Clone)]
pub struct TargetLoginNegotiation {
    header_digest: DigestNegotiation,
    data_digest: DigestNegotiation,
    initiator_max_recv: Option<usize>,
    target_max_recv: Option<usize>,
    initiator_fragment: BytesMut,
    initiator_fragment_stage: Option<LoginStage>,
    target_fragment: BytesMut,
    target_fragment_stage: Option<LoginStage>,
    target_continuation_pending: bool,
    completed: Option<NegotiatedFrameParameters>,
    max_text_sequence_length: usize,
    current_stage: Option<LoginStage>,
}

impl Default for TargetLoginNegotiation {
    fn default() -> Self {
        Self {
            header_digest: DigestNegotiation::default(),
            data_digest: DigestNegotiation::default(),
            initiator_max_recv: None,
            target_max_recv: None,
            initiator_fragment: BytesMut::new(),
            initiator_fragment_stage: None,
            target_fragment: BytesMut::new(),
            target_fragment_stage: None,
            target_continuation_pending: false,
            completed: None,
            max_text_sequence_length: DEFAULT_MAX_LOGIN_TEXT_SEQUENCE_LENGTH,
            current_stage: None,
        }
    }
}

impl TargetLoginNegotiation {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn parameters(&self) -> Option<NegotiatedFrameParameters> {
        self.completed
    }

    pub fn max_text_sequence_length(&self) -> usize {
        self.max_text_sequence_length
    }

    pub fn set_max_text_sequence_length(&mut self, len: usize) {
        self.max_text_sequence_length = len.max(MIN_LOGIN_TEXT_SEQUENCE_LENGTH);
    }

    /// Record one request/response exchange.
    ///
    /// State changes are atomic: an invalid exchange leaves this accumulator
    /// unchanged. `Some` is returned exactly once, when the successful target
    /// response transits to Full Feature Phase.
    pub fn observe_exchange(
        &mut self,
        request: &LoginRequest,
        response: &LoginResponse,
    ) -> Result<Option<NegotiatedFrameParameters>, NegotiationError> {
        if self.completed.is_some() {
            return Err(NegotiationError::AlreadyComplete);
        }

        let mut next = self.clone();
        let completed = next.observe_exchange_inner(request, response)?;
        *self = next;
        Ok(completed)
    }

    fn observe_exchange_inner(
        &mut self,
        request: &LoginRequest,
        response: &LoginResponse,
    ) -> Result<Option<NegotiatedFrameParameters>, NegotiationError> {
        if response.status_class != 0 {
            return Err(NegotiationError::LoginRejected {
                status_class: response.status_class,
                status_detail: response.status_detail,
            });
        }
        if request.current_stage != response.current_stage {
            return Err(NegotiationError::StageMismatch {
                request: request.current_stage,
                response: response.current_stage,
            });
        }
        if let Some(expected) = self.current_stage {
            if request.current_stage != expected {
                return Err(NegotiationError::UnexpectedStage {
                    expected,
                    actual: request.current_stage,
                });
            }
        } else if request.current_stage == LoginStage::FullFeature {
            return Err(NegotiationError::InvalidTransition(
                "Login cannot start in Full Feature Phase",
            ));
        }
        if request.continue_ && request.transit {
            return Err(NegotiationError::InvalidContinuation(
                "a Login Request cannot set both C and T",
            ));
        }
        if response.continue_ && response.transit {
            return Err(NegotiationError::InvalidContinuation(
                "a Login Response cannot set both C and T",
            ));
        }
        if response.transit && !request.transit {
            return Err(NegotiationError::InvalidTransition(
                "the target cannot transit unless the initiator requested transit",
            ));
        }
        if response.transit && (response.next_stage as u8) > (request.next_stage as u8) {
            return Err(NegotiationError::InvalidTransition(
                "the target selected a stage beyond the initiator's requested stage",
            ));
        }
        if response.transit
            && !matches!(
                (response.current_stage, response.next_stage),
                (LoginStage::Security, LoginStage::Operational)
                    | (LoginStage::Security, LoginStage::FullFeature)
                    | (LoginStage::Operational, LoginStage::FullFeature)
            )
        {
            return Err(NegotiationError::InvalidTransition(
                "the selected stage transition is not permitted",
            ));
        }

        let request_is_empty_continuation = self.target_continuation_pending;
        if request_is_empty_continuation {
            if !request.params.is_empty() || request.continue_ || request.transit {
                return Err(NegotiationError::InvalidContinuation(
                    "a target text continuation must be acknowledged by an empty request",
                ));
            }
            self.target_continuation_pending = false;
        } else {
            self.append_fragment(
                LoginSide::Initiator,
                request.current_stage,
                &request.params,
                request.continue_,
            )?;
        }

        if request.continue_ {
            if !response.params.is_empty() || response.continue_ || response.transit {
                return Err(NegotiationError::InvalidContinuation(
                    "an initiator text continuation requires an empty response",
                ));
            }
        } else {
            self.append_fragment(
                LoginSide::Target,
                response.current_stage,
                &response.params,
                response.continue_,
            )?;
            self.target_continuation_pending = response.continue_;
        }

        let enters_full_feature =
            response.transit && response.next_stage == LoginStage::FullFeature;
        self.current_stage = Some(if response.transit {
            response.next_stage
        } else {
            response.current_stage
        });
        if !enters_full_feature {
            return Ok(None);
        }
        if request.next_stage != LoginStage::FullFeature {
            return Err(NegotiationError::InvalidTransition(
                "final Login Request did not select Full Feature Phase",
            ));
        }
        if !self.initiator_fragment.is_empty()
            || !self.target_fragment.is_empty()
            || self.target_continuation_pending
        {
            return Err(NegotiationError::InvalidContinuation(
                "Login completed with an unfinished text sequence",
            ));
        }

        let parameters = NegotiatedFrameParameters::new(
            self.header_digest.finish(HEADER_DIGEST)?,
            self.data_digest.finish(DATA_DIGEST)?,
            self.target_max_recv
                .unwrap_or(DEFAULT_MAX_RECV_DATA_SEGMENT_LENGTH),
            self.initiator_max_recv
                .unwrap_or(DEFAULT_MAX_RECV_DATA_SEGMENT_LENGTH),
        )?;
        self.completed = Some(parameters);
        Ok(Some(parameters))
    }

    fn append_fragment(
        &mut self,
        side: LoginSide,
        stage: LoginStage,
        params: &TextParameters,
        continues: bool,
    ) -> Result<(), NegotiationError> {
        let max_text_sequence_length = self.max_text_sequence_length;
        let (fragment, fragment_stage) = match side {
            LoginSide::Initiator => (
                &mut self.initiator_fragment,
                &mut self.initiator_fragment_stage,
            ),
            LoginSide::Target => (&mut self.target_fragment, &mut self.target_fragment_stage),
        };

        let accumulated_len = fragment.len().saturating_add(params.as_bytes().len());
        if accumulated_len > max_text_sequence_length {
            return Err(NegotiationError::TextSequenceTooLarge {
                side,
                len: accumulated_len,
                max: max_text_sequence_length,
            });
        }

        if let Some(previous) = *fragment_stage {
            if previous != stage {
                return Err(NegotiationError::InvalidContinuation(
                    "a text sequence crossed Login stages",
                ));
            }
        } else {
            *fragment_stage = Some(stage);
        }
        fragment.extend_from_slice(params.as_bytes());

        if continues {
            return Ok(());
        }

        let encoded = std::mem::take(fragment).freeze();
        *fragment_stage = None;
        let complete = TextParameters::from_complete_bytes(encoded)
            .map_err(|source| NegotiationError::InvalidText { side, source })?;
        self.process_parameters(side, stage, &complete)
    }

    fn process_parameters(
        &mut self,
        side: LoginSide,
        stage: LoginStage,
        params: &TextParameters,
    ) -> Result<(), NegotiationError> {
        for (key, value) in params.iter() {
            let standard_key = match key {
                HEADER_DIGEST => Some(HEADER_DIGEST),
                DATA_DIGEST => Some(DATA_DIGEST),
                MAX_RECV_DATA_SEGMENT_LENGTH_KEY => Some(MAX_RECV_DATA_SEGMENT_LENGTH_KEY),
                _ => None,
            };
            let Some(key) = standard_key else {
                continue;
            };
            if stage != LoginStage::Operational {
                return Err(NegotiationError::KeyInWrongStage { key, stage });
            }

            match key {
                HEADER_DIGEST => self.header_digest.observe(HEADER_DIGEST, side, value)?,
                DATA_DIGEST => self.data_digest.observe(DATA_DIGEST, side, value)?,
                MAX_RECV_DATA_SEGMENT_LENGTH_KEY => {
                    let parsed = parse_max_recv(side, value)?;
                    let slot = match side {
                        LoginSide::Initiator => &mut self.initiator_max_recv,
                        LoginSide::Target => &mut self.target_max_recv,
                    };
                    if slot.replace(parsed).is_some() {
                        return Err(NegotiationError::DuplicateDeclaration { side, key });
                    }
                }
                _ => unreachable!("filtered above"),
            }
        }
        Ok(())
    }
}

fn parse_max_recv(side: LoginSide, value: &str) -> Result<usize, NegotiationError> {
    let parsed = if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        if hex.is_empty() {
            None
        } else {
            u64::from_str_radix(hex, 16).ok()
        }
    } else if (value == "0" || (!value.starts_with('0') && !value.is_empty()))
        && value.bytes().all(|byte| byte.is_ascii_digit())
    {
        value.parse::<u64>().ok()
    } else {
        None
    }
    .ok_or_else(|| NegotiationError::InvalidMaxRecvDataSegmentLength {
        side,
        value: value.to_owned(),
    })?;

    let parsed =
        usize::try_from(parsed).map_err(|_| NegotiationError::InvalidMaxRecvDataSegmentLength {
            side,
            value: value.to_owned(),
        })?;
    validate_max_recv(side, parsed)?;
    Ok(parsed)
}

fn validate_max_recv(side: LoginSide, value: usize) -> Result<(), NegotiationError> {
    if !(MIN_MAX_RECV_DATA_SEGMENT_LENGTH..=MAX_DATA_SEGMENT_LENGTH).contains(&value) {
        return Err(NegotiationError::MaxRecvDataSegmentLengthOutOfRange {
            side,
            value,
            min: MIN_MAX_RECV_DATA_SEGMENT_LENGTH,
            max: MAX_DATA_SEGMENT_LENGTH,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::*;

    fn request(
        transit: bool,
        continue_: bool,
        current_stage: LoginStage,
        next_stage: LoginStage,
        text: &[u8],
    ) -> LoginRequest {
        LoginRequest {
            transit,
            continue_,
            current_stage,
            next_stage,
            version_max: 0,
            version_min: 0,
            isid: [0x80, 1, 2, 3, 4, 5],
            tsih: 0,
            initiator_task_tag: 1,
            cid: 0,
            cmd_sn: 1,
            exp_stat_sn: 0,
            params: TextParameters::from_bytes(Bytes::copy_from_slice(text)),
        }
    }

    fn response(
        transit: bool,
        continue_: bool,
        current_stage: LoginStage,
        next_stage: LoginStage,
        text: &[u8],
    ) -> LoginResponse {
        LoginResponse {
            transit,
            continue_,
            current_stage,
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
            params: TextParameters::from_bytes(Bytes::copy_from_slice(text)),
        }
    }

    #[test]
    fn completes_initiator_driven_negotiation_with_directional_limits() {
        let request = request(
            true,
            false,
            LoginStage::Operational,
            LoginStage::FullFeature,
            b"HeaderDigest=CRC32C,None\0DataDigest=CRC32C,None\0MaxRecvDataSegmentLength=0x1000\0",
        );
        let response = response(
            true,
            false,
            LoginStage::Operational,
            LoginStage::FullFeature,
            b"HeaderDigest=CRC32C\0DataDigest=CRC32C\0MaxRecvDataSegmentLength=16384\0",
        );

        let mut negotiation = TargetLoginNegotiation::new();
        let parameters = negotiation
            .observe_exchange(&request, &response)
            .unwrap()
            .unwrap();

        assert_eq!(parameters.header_digest(), DigestType::Crc32c);
        assert_eq!(parameters.data_digest(), DigestType::Crc32c);
        assert_eq!(parameters.local_max_recv_data_segment_length(), 16384);
        assert_eq!(parameters.peer_max_recv_data_segment_length(), 4096);
        assert_eq!(negotiation.parameters(), Some(parameters));
    }

    #[test]
    fn uses_rfc_defaults_when_operational_keys_are_absent() {
        let request = request(
            true,
            false,
            LoginStage::Security,
            LoginStage::FullFeature,
            b"InitiatorName=iqn.2024-01.example:host\0",
        );
        let response = response(
            true,
            false,
            LoginStage::Security,
            LoginStage::FullFeature,
            b"TargetPortalGroupTag=1\0",
        );

        let parameters = TargetLoginNegotiation::new()
            .observe_exchange(&request, &response)
            .unwrap()
            .unwrap();
        assert_eq!(parameters, NegotiatedFrameParameters::default());
    }

    #[test]
    fn target_may_select_an_earlier_stage_than_the_initiator_requested() {
        let mut negotiation = TargetLoginNegotiation::new();
        let security_request = request(
            true,
            false,
            LoginStage::Security,
            LoginStage::FullFeature,
            b"AuthMethod=None\0",
        );
        let operational_response = response(
            true,
            false,
            LoginStage::Security,
            LoginStage::Operational,
            b"AuthMethod=None\0",
        );
        assert_eq!(
            negotiation
                .observe_exchange(&security_request, &operational_response)
                .unwrap(),
            None
        );

        let final_request = request(
            true,
            false,
            LoginStage::Operational,
            LoginStage::FullFeature,
            b"",
        );
        let final_response = response(
            true,
            false,
            LoginStage::Operational,
            LoginStage::FullFeature,
            b"",
        );
        assert_eq!(
            negotiation
                .observe_exchange(&final_request, &final_response)
                .unwrap(),
            Some(NegotiatedFrameParameters::default())
        );
    }

    #[test]
    fn supports_a_target_initiated_digest_proposal() {
        let mut negotiation = TargetLoginNegotiation::new();
        let first_request = request(
            false,
            false,
            LoginStage::Operational,
            LoginStage::Operational,
            b"",
        );
        let first_response = response(
            false,
            false,
            LoginStage::Operational,
            LoginStage::Operational,
            b"HeaderDigest=CRC32C,None\0",
        );
        assert_eq!(
            negotiation
                .observe_exchange(&first_request, &first_response)
                .unwrap(),
            None
        );

        let final_request = request(
            true,
            false,
            LoginStage::Operational,
            LoginStage::FullFeature,
            b"HeaderDigest=CRC32C\0",
        );
        let final_response = response(
            true,
            false,
            LoginStage::Operational,
            LoginStage::FullFeature,
            b"",
        );
        let parameters = negotiation
            .observe_exchange(&final_request, &final_response)
            .unwrap()
            .unwrap();
        assert_eq!(parameters.header_digest(), DigestType::Crc32c);
    }

    #[test]
    fn reassembles_an_initiator_key_split_across_login_pdus() {
        let mut negotiation = TargetLoginNegotiation::new();
        let partial_request = request(
            false,
            true,
            LoginStage::Operational,
            LoginStage::Operational,
            b"HeaderDigest=CRC",
        );
        let empty_response = response(
            false,
            false,
            LoginStage::Operational,
            LoginStage::Operational,
            b"",
        );
        assert_eq!(
            negotiation
                .observe_exchange(&partial_request, &empty_response)
                .unwrap(),
            None
        );

        let final_request = request(
            true,
            false,
            LoginStage::Operational,
            LoginStage::FullFeature,
            b"32C,None\0MaxRecvDataSegmentLength=4096\0",
        );
        let final_response = response(
            true,
            false,
            LoginStage::Operational,
            LoginStage::FullFeature,
            b"HeaderDigest=CRC32C\0",
        );
        let parameters = negotiation
            .observe_exchange(&final_request, &final_response)
            .unwrap()
            .unwrap();
        assert_eq!(parameters.header_digest(), DigestType::Crc32c);
        assert_eq!(parameters.peer_max_recv_data_segment_length(), 4096);
    }

    #[test]
    fn reassembles_target_text_after_empty_continuation_requests() {
        let mut negotiation = TargetLoginNegotiation::new();
        let initial_request = request(
            false,
            false,
            LoginStage::Operational,
            LoginStage::Operational,
            b"",
        );
        let partial_response = response(
            false,
            true,
            LoginStage::Operational,
            LoginStage::Operational,
            b"DataDigest=CRC",
        );
        assert_eq!(
            negotiation
                .observe_exchange(&initial_request, &partial_response)
                .unwrap(),
            None
        );

        let empty_request = request(
            false,
            false,
            LoginStage::Operational,
            LoginStage::Operational,
            b"",
        );
        let rest_response = response(
            false,
            false,
            LoginStage::Operational,
            LoginStage::Operational,
            b"32C,None\0",
        );
        assert_eq!(
            negotiation
                .observe_exchange(&empty_request, &rest_response)
                .unwrap(),
            None
        );

        let final_request = request(
            true,
            false,
            LoginStage::Operational,
            LoginStage::FullFeature,
            b"DataDigest=CRC32C\0",
        );
        let final_response = response(
            true,
            false,
            LoginStage::Operational,
            LoginStage::FullFeature,
            b"",
        );
        let parameters = negotiation
            .observe_exchange(&final_request, &final_response)
            .unwrap()
            .unwrap();
        assert_eq!(parameters.data_digest(), DigestType::Crc32c);
    }

    #[test]
    fn invalid_exchange_does_not_partially_mutate_negotiation() {
        let request = request(
            true,
            false,
            LoginStage::Operational,
            LoginStage::FullFeature,
            b"HeaderDigest=CRC32C\0",
        );
        let invalid_response = response(
            true,
            false,
            LoginStage::Operational,
            LoginStage::FullFeature,
            b"HeaderDigest=None\0",
        );
        let valid_response = response(
            true,
            false,
            LoginStage::Operational,
            LoginStage::FullFeature,
            b"HeaderDigest=CRC32C\0",
        );

        let mut negotiation = TargetLoginNegotiation::new();
        assert!(matches!(
            negotiation.observe_exchange(&request, &invalid_response),
            Err(NegotiationError::DigestNotOffered { .. })
        ));
        assert_eq!(negotiation.parameters(), None);

        let parameters = negotiation
            .observe_exchange(&request, &valid_response)
            .unwrap()
            .unwrap();
        assert_eq!(parameters.header_digest(), DigestType::Crc32c);
    }

    #[test]
    fn rejects_out_of_range_max_recv_and_unfinished_digest() {
        let bad_max_request = request(
            true,
            false,
            LoginStage::Operational,
            LoginStage::FullFeature,
            b"MaxRecvDataSegmentLength=511\0",
        );
        let final_response = response(
            true,
            false,
            LoginStage::Operational,
            LoginStage::FullFeature,
            b"",
        );
        assert!(matches!(
            TargetLoginNegotiation::new().observe_exchange(&bad_max_request, &final_response),
            Err(NegotiationError::MaxRecvDataSegmentLengthOutOfRange {
                side: LoginSide::Initiator,
                value: 511,
                ..
            })
        ));

        let unanswered_request = request(
            true,
            false,
            LoginStage::Operational,
            LoginStage::FullFeature,
            b"DataDigest=CRC32C,None\0",
        );
        assert_eq!(
            TargetLoginNegotiation::new().observe_exchange(&unanswered_request, &final_response),
            Err(NegotiationError::IncompleteDigestNegotiation { key: DATA_DIGEST })
        );
    }

    #[test]
    fn bounds_a_fragmented_text_sequence() {
        let mut negotiation = TargetLoginNegotiation::new();
        negotiation.set_max_text_sequence_length(1);
        assert_eq!(
            negotiation.max_text_sequence_length(),
            MIN_LOGIN_TEXT_SEQUENCE_LENGTH
        );

        let first_chunk = vec![b'x'; 4096];
        let first_request = request(
            false,
            true,
            LoginStage::Operational,
            LoginStage::Operational,
            &first_chunk,
        );
        let empty_response = response(
            false,
            false,
            LoginStage::Operational,
            LoginStage::Operational,
            b"",
        );
        negotiation
            .observe_exchange(&first_request, &empty_response)
            .unwrap();

        let second_chunk = vec![b'x'; 4097];
        let second_request = request(
            false,
            true,
            LoginStage::Operational,
            LoginStage::Operational,
            &second_chunk,
        );
        assert_eq!(
            negotiation.observe_exchange(&second_request, &empty_response),
            Err(NegotiationError::TextSequenceTooLarge {
                side: LoginSide::Initiator,
                len: 8193,
                max: MIN_LOGIN_TEXT_SEQUENCE_LENGTH,
            })
        );
    }

    #[test]
    fn applying_parameters_preserves_direction() {
        let parameters = NegotiatedFrameParameters::new(
            DigestType::Crc32c,
            DigestType::None,
            16 * 1024,
            4 * 1024,
        )
        .unwrap();
        let mut config = FrameConfig::default();
        parameters.apply_to(&mut config);

        assert_eq!(config.header_digest(), DigestType::Crc32c);
        assert_eq!(config.data_digest(), DigestType::None);
        assert_eq!(config.max_recv_data_segment_length(), 16 * 1024);
        assert_eq!(config.max_send_data_segment_length(), 4 * 1024);
    }
}
