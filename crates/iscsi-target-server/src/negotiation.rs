//! Connection-level parameters produced by Login negotiation.
//!
//! The wire codec deliberately does not interpret Login text. This module
//! bridges that boundary for a target: it accumulates initiator requests and
//! target responses, validates the framing-related keys, and publishes one
//! atomic result when Login enters Full Feature Phase.

use bytes::BytesMut;

use crate::digest::DigestType;
use crate::frame::{DEFAULT_MAX_RECV_DATA_SEGMENT_LENGTH, FrameConfig, MAX_DATA_SEGMENT_LENGTH};
use crate::login::{
    AuthMethod, AuthMethodError, IscsiName, IscsiNameError, LoginRequest, LoginResponse,
    SessionType, SessionTypeError, TextParameterError, TextParameters,
};
use crate::opcode::LoginStage;

pub const MIN_MAX_RECV_DATA_SEGMENT_LENGTH: usize = 512;
pub const MIN_LOGIN_TEXT_SEQUENCE_LENGTH: usize = 8192;
pub const DEFAULT_MAX_LOGIN_TEXT_SEQUENCE_LENGTH: usize = 64 * 1024;

const HEADER_DIGEST: &str = "HeaderDigest";
const DATA_DIGEST: &str = "DataDigest";
const MAX_RECV_DATA_SEGMENT_LENGTH_KEY: &str = "MaxRecvDataSegmentLength";
const AUTH_METHOD: &str = "AuthMethod";
const INITIATOR_NAME: &str = "InitiatorName";
const TARGET_NAME: &str = "TargetName";
const SESSION_TYPE: &str = "SessionType";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginSide {
    Initiator,
    Target,
}

/// Reason that a Login stage transition is invalid.
#[derive(Debug, Clone, Copy, thiserror::Error, PartialEq, Eq)]
pub enum LoginTransitionError {
    #[error("Login cannot start in Full Feature Phase")]
    StartsInFullFeaturePhase,

    #[error("the target cannot transit unless the initiator requested transit")]
    TransitNotRequested,

    #[error("the target selected {selected:?}, beyond the requested stage {requested:?}")]
    SelectedStageBeyondRequested {
        requested: LoginStage,
        selected: LoginStage,
    },

    #[error("the transition from {current:?} to {next:?} is not permitted")]
    StagePairNotPermitted {
        current: LoginStage,
        next: LoginStage,
    },

    #[error("the final Login Request selected {selected:?}, not Full Feature Phase")]
    FinalRequestDoesNotSelectFullFeaturePhase { selected: LoginStage },
}

/// Reason that a fragmented Login text sequence is invalid.
#[derive(Debug, Clone, Copy, thiserror::Error, PartialEq, Eq)]
pub enum LoginContinuationError {
    #[error("a Login Request cannot set both C and T")]
    RequestSetsTransit,

    #[error("a Login Response cannot set both C and T")]
    ResponseSetsTransit,

    #[error("a target text continuation must be acknowledged by an empty request")]
    TargetContinuationRequiresEmptyRequest,

    #[error("an initiator text continuation requires an empty response")]
    InitiatorContinuationRequiresEmptyResponse,

    #[error("Login completed with an unfinished text sequence")]
    UnfinishedAtLoginCompletion,

    #[error("a {side:?} text sequence crossed Login stages from {previous:?} to {current:?}")]
    CrossesLoginStages {
        side: LoginSide,
        previous: LoginStage,
        current: LoginStage,
    },
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
    InvalidTransition(#[source] LoginTransitionError),

    #[error("invalid Login continuation: {0}")]
    InvalidContinuation(#[source] LoginContinuationError),

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

    #[error("{key} cannot be sent by {side:?} during Login")]
    KeyFromWrongSide { side: LoginSide, key: &'static str },

    #[error("invalid AuthMethod {value:?} from {side:?}: {source}")]
    InvalidAuthMethod {
        side: LoginSide,
        value: String,
        source: AuthMethodError,
    },

    #[error("invalid AuthMethod selection {value:?} from {side:?}")]
    InvalidAuthMethodSelection { side: LoginSide, value: String },

    #[error("{side:?} selected AuthMethod {selected:?}, but it was not offered")]
    AuthMethodNotOffered { side: LoginSide, selected: String },

    #[error("AuthMethod was sent again after a proposal or completed selection")]
    RepeatedAuthMethod,

    #[error("invalid {key} {value:?}: {source}")]
    InvalidIscsiName {
        key: &'static str,
        value: String,
        source: IscsiNameError,
    },

    #[error("invalid SessionType {value:?}: {source}")]
    InvalidSessionType {
        value: String,
        source: SessionTypeError,
    },

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

#[derive(Debug, Clone, Default)]
enum AuthMethodNegotiation {
    #[default]
    Unset,
    Proposed {
        by: LoginSide,
        offered: Vec<AuthMethod>,
    },
    Complete(AuthMethod),
}

impl AuthMethodNegotiation {
    fn observe(&mut self, side: LoginSide, value: &str) -> Result<(), NegotiationError> {
        match self {
            Self::Unset => {
                let offered = parse_auth_method_proposal(side, value)?;
                *self = Self::Proposed { by: side, offered };
                Ok(())
            }
            Self::Proposed { by, offered } => {
                if *by == side {
                    return Err(NegotiationError::RepeatedAuthMethod);
                }
                if value.is_empty() || value.contains(',') {
                    return Err(NegotiationError::InvalidAuthMethodSelection {
                        side,
                        value: value.to_owned(),
                    });
                }
                let selected = parse_auth_method(side, value)?;
                if !offered.contains(&selected) {
                    return Err(NegotiationError::AuthMethodNotOffered {
                        side,
                        selected: value.to_owned(),
                    });
                }
                *self = Self::Complete(selected);
                Ok(())
            }
            Self::Complete(_) => Err(NegotiationError::RepeatedAuthMethod),
        }
    }

    fn selected(&self) -> Option<&AuthMethod> {
        match self {
            Self::Complete(selected) => Some(selected),
            Self::Unset | Self::Proposed { .. } => None,
        }
    }
}

fn parse_auth_method_proposal(
    side: LoginSide,
    value: &str,
) -> Result<Vec<AuthMethod>, NegotiationError> {
    if value.is_empty() {
        return Err(NegotiationError::InvalidAuthMethodSelection {
            side,
            value: value.to_owned(),
        });
    }
    let mut offered = Vec::new();
    for item in value.split(',') {
        let method = parse_auth_method(side, item)?;
        if offered.contains(&method) {
            return Err(NegotiationError::InvalidAuthMethodSelection {
                side,
                value: value.to_owned(),
            });
        }
        offered.push(method);
    }
    Ok(offered)
}

fn parse_auth_method(side: LoginSide, value: &str) -> Result<AuthMethod, NegotiationError> {
    AuthMethod::parse(value).map_err(|source| NegotiationError::InvalidAuthMethod {
        side,
        value: value.to_owned(),
        source,
    })
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
                        });
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
    auth_method: AuthMethodNegotiation,
    initiator_name: Option<IscsiName>,
    target_name: Option<IscsiName>,
    session_type: Option<SessionType>,
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
            auth_method: AuthMethodNegotiation::default(),
            initiator_name: None,
            target_name: None,
            session_type: None,
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

    pub fn selected_auth_method(&self) -> Option<&AuthMethod> {
        self.auth_method.selected()
    }

    pub fn initiator_name(&self) -> Option<&IscsiName> {
        self.initiator_name.as_ref()
    }

    pub fn target_name(&self) -> Option<&IscsiName> {
        self.target_name.as_ref()
    }

    /// SessionType이 생략되면 RFC 7143 13.21절 기본값 Normal을 반환한다.
    pub fn session_type(&self) -> SessionType {
        self.session_type.unwrap_or_default()
    }

    pub fn declared_session_type(&self) -> Option<SessionType> {
        self.session_type
    }

    pub fn max_text_sequence_length(&self) -> usize {
        self.max_text_sequence_length
    }

    pub fn set_max_text_sequence_length(&mut self, len: usize) {
        self.max_text_sequence_length = len.max(MIN_LOGIN_TEXT_SEQUENCE_LENGTH);
    }

    pub(crate) fn preview_initiator_parameters(
        &self,
        request: &LoginRequest,
    ) -> Result<Option<TextParameters>, NegotiationError> {
        if request.continue_ {
            return Ok(None);
        }
        let len = self
            .initiator_fragment
            .len()
            .saturating_add(request.params.as_bytes().len());
        if len > self.max_text_sequence_length {
            return Err(NegotiationError::TextSequenceTooLarge {
                side: LoginSide::Initiator,
                len,
                max: self.max_text_sequence_length,
            });
        }
        if let Some(previous) = self.initiator_fragment_stage
            && previous != request.current_stage
        {
            return Err(NegotiationError::InvalidContinuation(
                LoginContinuationError::CrossesLoginStages {
                    side: LoginSide::Initiator,
                    previous,
                    current: request.current_stage,
                },
            ));
        }
        let mut encoded = BytesMut::with_capacity(len);
        encoded.extend_from_slice(&self.initiator_fragment);
        encoded.extend_from_slice(request.params.as_bytes());
        TextParameters::from_complete_bytes(encoded.freeze())
            .map(Some)
            .map_err(|source| NegotiationError::InvalidText {
                side: LoginSide::Initiator,
                source,
            })
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
                LoginTransitionError::StartsInFullFeaturePhase,
            ));
        }
        if request.continue_ && request.transit {
            return Err(NegotiationError::InvalidContinuation(
                LoginContinuationError::RequestSetsTransit,
            ));
        }
        if response.continue_ && response.transit {
            return Err(NegotiationError::InvalidContinuation(
                LoginContinuationError::ResponseSetsTransit,
            ));
        }
        if response.transit && !request.transit {
            return Err(NegotiationError::InvalidTransition(
                LoginTransitionError::TransitNotRequested,
            ));
        }
        if response.transit && (response.next_stage as u8) > (request.next_stage as u8) {
            return Err(NegotiationError::InvalidTransition(
                LoginTransitionError::SelectedStageBeyondRequested {
                    requested: request.next_stage,
                    selected: response.next_stage,
                },
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
                LoginTransitionError::StagePairNotPermitted {
                    current: response.current_stage,
                    next: response.next_stage,
                },
            ));
        }

        let request_is_empty_continuation = self.target_continuation_pending;
        if request_is_empty_continuation {
            if !request.params.is_empty() || request.continue_ {
                return Err(NegotiationError::InvalidContinuation(
                    LoginContinuationError::TargetContinuationRequiresEmptyRequest,
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
                    LoginContinuationError::InitiatorContinuationRequiresEmptyResponse,
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
                LoginTransitionError::FinalRequestDoesNotSelectFullFeaturePhase {
                    selected: request.next_stage,
                },
            ));
        }
        if !self.initiator_fragment.is_empty()
            || !self.target_fragment.is_empty()
            || self.target_continuation_pending
        {
            return Err(NegotiationError::InvalidContinuation(
                LoginContinuationError::UnfinishedAtLoginCompletion,
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
                    LoginContinuationError::CrossesLoginStages {
                        side,
                        previous,
                        current: stage,
                    },
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
                AUTH_METHOD => Some(AUTH_METHOD),
                INITIATOR_NAME => Some(INITIATOR_NAME),
                TARGET_NAME => Some(TARGET_NAME),
                SESSION_TYPE => Some(SESSION_TYPE),
                HEADER_DIGEST => Some(HEADER_DIGEST),
                DATA_DIGEST => Some(DATA_DIGEST),
                MAX_RECV_DATA_SEGMENT_LENGTH_KEY => Some(MAX_RECV_DATA_SEGMENT_LENGTH_KEY),
                _ => None,
            };
            let Some(key) = standard_key else {
                continue;
            };
            if key == AUTH_METHOD && stage != LoginStage::Security {
                return Err(NegotiationError::KeyInWrongStage { key, stage });
            }
            if matches!(
                key,
                HEADER_DIGEST | DATA_DIGEST | MAX_RECV_DATA_SEGMENT_LENGTH_KEY
            ) && stage != LoginStage::Operational
            {
                return Err(NegotiationError::KeyInWrongStage { key, stage });
            }

            match key {
                AUTH_METHOD => self.auth_method.observe(side, value)?,
                INITIATOR_NAME => {
                    require_initiator(side, key)?;
                    let parsed = parse_iscsi_name(key, value)?;
                    declare_once(&mut self.initiator_name, parsed, side, key)?;
                }
                TARGET_NAME => {
                    require_initiator(side, key)?;
                    let parsed = parse_iscsi_name(key, value)?;
                    declare_once(&mut self.target_name, parsed, side, key)?;
                }
                SESSION_TYPE => {
                    require_initiator(side, key)?;
                    let parsed = value.parse::<SessionType>().map_err(|source| {
                        NegotiationError::InvalidSessionType {
                            value: value.to_owned(),
                            source,
                        }
                    })?;
                    declare_once(&mut self.session_type, parsed, side, key)?;
                }
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

fn require_initiator(side: LoginSide, key: &'static str) -> Result<(), NegotiationError> {
    if side != LoginSide::Initiator {
        return Err(NegotiationError::KeyFromWrongSide { side, key });
    }
    Ok(())
}

fn parse_iscsi_name(key: &'static str, value: &str) -> Result<IscsiName, NegotiationError> {
    IscsiName::parse(value).map_err(|source| NegotiationError::InvalidIscsiName {
        key,
        value: value.to_owned(),
        source,
    })
}

fn declare_once<T>(
    slot: &mut Option<T>,
    value: T,
    side: LoginSide,
    key: &'static str,
) -> Result<(), NegotiationError> {
    if slot.is_some() {
        return Err(NegotiationError::DuplicateDeclaration { side, key });
    }
    *slot = Some(value);
    Ok(())
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
    fn processes_authentication_identity_and_session_type() {
        let request = request(
            true,
            false,
            LoginStage::Security,
            LoginStage::FullFeature,
            b"AuthMethod=CHAP,None\0InitiatorName=iqn.2024-01.com.example:host\0TargetName=iqn.2024-01.com.example:disk0\0SessionType=Normal\0",
        );
        let response = response(
            true,
            false,
            LoginStage::Security,
            LoginStage::FullFeature,
            b"AuthMethod=None\0",
        );

        let mut negotiation = TargetLoginNegotiation::new();
        negotiation.observe_exchange(&request, &response).unwrap();

        assert_eq!(negotiation.selected_auth_method(), Some(&AuthMethod::None));
        assert_eq!(
            negotiation.initiator_name().map(IscsiName::as_str),
            Some("iqn.2024-01.com.example:host")
        );
        assert_eq!(
            negotiation.target_name().map(IscsiName::as_str),
            Some("iqn.2024-01.com.example:disk0")
        );
        assert_eq!(negotiation.session_type(), SessionType::Normal);
        assert_eq!(
            negotiation.declared_session_type(),
            Some(SessionType::Normal)
        );
    }

    #[test]
    fn session_type_defaults_to_normal_when_omitted() {
        assert_eq!(
            TargetLoginNegotiation::new().session_type(),
            SessionType::Normal
        );
        assert_eq!(TargetLoginNegotiation::new().declared_session_type(), None);
    }

    #[test]
    fn rejects_identity_keys_from_target_and_duplicate_declarations() {
        let request = request(
            false,
            false,
            LoginStage::Security,
            LoginStage::Security,
            b"InitiatorName=iqn.2024-01.com.example:host\0",
        );
        let invalid_response = response(
            false,
            false,
            LoginStage::Security,
            LoginStage::Security,
            b"SessionType=Normal\0",
        );
        assert_eq!(
            TargetLoginNegotiation::new().observe_exchange(&request, &invalid_response),
            Err(NegotiationError::KeyFromWrongSide {
                side: LoginSide::Target,
                key: SESSION_TYPE,
            })
        );

        let mut negotiation = TargetLoginNegotiation::new();
        let empty_response = response(
            false,
            false,
            LoginStage::Security,
            LoginStage::Security,
            b"",
        );
        negotiation
            .observe_exchange(&request, &empty_response)
            .unwrap();
        assert_eq!(
            negotiation.observe_exchange(&request, &empty_response),
            Err(NegotiationError::DuplicateDeclaration {
                side: LoginSide::Initiator,
                key: INITIATOR_NAME,
            })
        );
    }

    #[test]
    fn rejects_auth_method_outside_security_negotiation() {
        let request = request(
            true,
            false,
            LoginStage::Operational,
            LoginStage::FullFeature,
            b"AuthMethod=None\0",
        );
        let response = response(
            true,
            false,
            LoginStage::Operational,
            LoginStage::FullFeature,
            b"",
        );
        assert_eq!(
            TargetLoginNegotiation::new().observe_exchange(&request, &response),
            Err(NegotiationError::KeyInWrongStage {
                key: AUTH_METHOD,
                stage: LoginStage::Operational,
            })
        );
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
    fn preserves_raw_fragments_when_a_completed_sequence_is_retried() {
        let mut negotiation = TargetLoginNegotiation::new();
        let first_chunk = b"MaxRecvDataSegment";
        let partial_request = request(
            false,
            true,
            LoginStage::Operational,
            LoginStage::Operational,
            first_chunk,
        );
        let empty_response = response(
            false,
            false,
            LoginStage::Operational,
            LoginStage::Operational,
            b"",
        );
        negotiation
            .observe_exchange(&partial_request, &empty_response)
            .unwrap();

        let invalid_final_request = request(
            true,
            false,
            LoginStage::Operational,
            LoginStage::FullFeature,
            b"\xffLength=4096\0",
        );
        let final_response = response(
            true,
            false,
            LoginStage::Operational,
            LoginStage::FullFeature,
            b"",
        );
        assert_eq!(
            negotiation.observe_exchange(&invalid_final_request, &final_response),
            Err(NegotiationError::InvalidText {
                side: LoginSide::Initiator,
                source: TextParameterError::InvalidUtf8 {
                    offset: first_chunk.len(),
                },
            })
        );

        let valid_final_request = request(
            true,
            false,
            LoginStage::Operational,
            LoginStage::FullFeature,
            b"Length=4096\0",
        );
        let parameters = negotiation
            .observe_exchange(&valid_final_request, &final_response)
            .unwrap()
            .unwrap();
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
    fn reports_typed_transition_and_continuation_reasons() {
        let request_without_transit = request(
            false,
            false,
            LoginStage::Operational,
            LoginStage::Operational,
            b"",
        );
        let transiting_response = response(
            true,
            false,
            LoginStage::Operational,
            LoginStage::FullFeature,
            b"",
        );
        assert_eq!(
            TargetLoginNegotiation::new()
                .observe_exchange(&request_without_transit, &transiting_response),
            Err(NegotiationError::InvalidTransition(
                LoginTransitionError::TransitNotRequested,
            ))
        );

        let invalid_continuation = request(
            true,
            true,
            LoginStage::Operational,
            LoginStage::FullFeature,
            b"",
        );
        let response = response(
            false,
            false,
            LoginStage::Operational,
            LoginStage::Operational,
            b"",
        );
        assert_eq!(
            TargetLoginNegotiation::new().observe_exchange(&invalid_continuation, &response),
            Err(NegotiationError::InvalidContinuation(
                LoginContinuationError::RequestSetsTransit,
            ))
        );
    }

    #[test]
    fn enforces_stage_boundaries_without_consuming_valid_state() {
        let mut negotiation = TargetLoginNegotiation::new();
        let security_request = request(
            true,
            false,
            LoginStage::Security,
            LoginStage::Operational,
            b"AuthMethod=None\0",
        );
        let operational_response = response(
            true,
            false,
            LoginStage::Security,
            LoginStage::Operational,
            b"AuthMethod=None\0",
        );
        negotiation
            .observe_exchange(&security_request, &operational_response)
            .unwrap();

        let stale_request = request(
            false,
            false,
            LoginStage::Security,
            LoginStage::Security,
            b"",
        );
        let stale_response = response(
            false,
            false,
            LoginStage::Security,
            LoginStage::Security,
            b"",
        );
        assert_eq!(
            negotiation.observe_exchange(&stale_request, &stale_response),
            Err(NegotiationError::UnexpectedStage {
                expected: LoginStage::Operational,
                actual: LoginStage::Security,
            })
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
