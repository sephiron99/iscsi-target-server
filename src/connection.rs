//! Login부터 Full Feature Phase와 종료까지의 Connection 상태 머신.

use std::time::Duration;

use crate::control::LogoutResponse;
use crate::frame::FrameConfig;
use crate::negotiation::NegotiatedFrameParameters;
use crate::opcode::LoginStage;
use crate::serial::{SequenceError, SequenceState};
use crate::target_login::{TargetLoginError, TargetLoginProcessor};
use crate::Pdu;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionPhase {
    SecurityNegotiation,
    LoginOperationalNegotiation,
    FullFeaturePhase,
    Logout,
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionCloseReason {
    NormalLogout,
    LoginRejected,
    LoginTimeout,
    IdleTimeout,
    LogoutTimeout,
    ProtocolError,
    TransportError,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionTimeoutKind {
    Login,
    Idle,
    Logout,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionTimeouts {
    pub login: Duration,
    pub idle: Duration,
    pub logout: Duration,
}

impl Default for ConnectionTimeouts {
    fn default() -> Self {
        Self {
            login: Duration::from_secs(30),
            idle: Duration::from_secs(120),
            logout: Duration::from_secs(15),
        }
    }
}

#[derive(Debug)]
pub struct ConnectionOutput {
    pub response: Pdu,
    /// 응답을 완전히 전송한 뒤 [`ConnectionStateMachine::response_sent`]를
    /// 호출해야 하는지 나타낸다.
    pub transition_after_send: bool,
}

#[derive(Debug)]
pub struct ConnectionStateMachine {
    phase: ConnectionPhase,
    login: TargetLoginProcessor,
    frame_config: FrameConfig,
    sequence: Option<SequenceState>,
    command_window: u32,
    cid: u16,
    pending_phase: Option<ConnectionPhase>,
    pending_frame_parameters: Option<NegotiatedFrameParameters>,
    pending_close_reason: Option<ConnectionCloseReason>,
    close_reason: Option<ConnectionCloseReason>,
    timeouts: ConnectionTimeouts,
}

impl ConnectionStateMachine {
    pub fn new(
        login: TargetLoginProcessor,
        cid: u16,
        command_window: u32,
    ) -> Result<Self, ConnectionError> {
        // SequenceState가 사용하는 것과 같은 창 제약을 생성 시점에 검증한다.
        SequenceState::new(0, 0, command_window)?;
        Ok(Self {
            phase: ConnectionPhase::SecurityNegotiation,
            login,
            frame_config: FrameConfig::default(),
            sequence: None,
            command_window,
            cid,
            pending_phase: None,
            pending_frame_parameters: None,
            pending_close_reason: None,
            close_reason: None,
            timeouts: ConnectionTimeouts::default(),
        })
    }

    pub fn phase(&self) -> ConnectionPhase {
        self.phase
    }

    pub fn frame_config(&self) -> &FrameConfig {
        &self.frame_config
    }

    pub fn sequence(&self) -> Option<&SequenceState> {
        self.sequence.as_ref()
    }

    pub fn close_reason(&self) -> Option<ConnectionCloseReason> {
        self.close_reason
    }

    pub fn timeouts(&self) -> ConnectionTimeouts {
        self.timeouts
    }

    pub fn set_timeouts(&mut self, timeouts: ConnectionTimeouts) {
        self.timeouts = timeouts;
    }

    pub fn receive(&mut self, pdu: Pdu) -> Result<ConnectionOutput, ConnectionError> {
        if self.pending_phase.is_some() {
            return self.protocol_error(ConnectionError::ResponseNotSent);
        }
        let result = match self.phase {
            ConnectionPhase::SecurityNegotiation | ConnectionPhase::LoginOperationalNegotiation => {
                self.receive_login(pdu)
            }
            ConnectionPhase::FullFeaturePhase => self.receive_full_feature(pdu),
            ConnectionPhase::Logout | ConnectionPhase::Closed => {
                Err(ConnectionError::PduInWrongState {
                    opcode: pdu.opcode(),
                    phase: self.phase,
                })
            }
        };
        match result {
            Ok(output) => Ok(output),
            Err(error) => self.protocol_error(error),
        }
    }

    pub fn response_sent(&mut self) -> Result<(), ConnectionError> {
        let next = self
            .pending_phase
            .take()
            .ok_or(ConnectionError::NoPendingResponse)?;
        if let Some(parameters) = self.pending_frame_parameters.take() {
            parameters.apply_to(&mut self.frame_config);
        }
        self.phase = next;
        if next == ConnectionPhase::Closed {
            self.close_reason = self.pending_close_reason.take();
        }
        Ok(())
    }

    pub fn on_timeout(&mut self, kind: ConnectionTimeoutKind) {
        let reason = match kind {
            ConnectionTimeoutKind::Login => ConnectionCloseReason::LoginTimeout,
            ConnectionTimeoutKind::Idle => ConnectionCloseReason::IdleTimeout,
            ConnectionTimeoutKind::Logout => ConnectionCloseReason::LogoutTimeout,
        };
        self.close(reason);
    }

    pub fn on_transport_error(&mut self) {
        self.close(ConnectionCloseReason::TransportError);
    }

    pub fn on_protocol_error(&mut self) {
        self.close(ConnectionCloseReason::ProtocolError);
    }

    pub fn close(&mut self, reason: ConnectionCloseReason) {
        self.pending_phase = None;
        self.pending_frame_parameters = None;
        self.pending_close_reason = None;
        self.phase = ConnectionPhase::Closed;
        self.close_reason = Some(reason);
    }

    fn receive_login(&mut self, pdu: Pdu) -> Result<ConnectionOutput, ConnectionError> {
        let Pdu::LoginRequest(request) = pdu else {
            return Err(ConnectionError::PduInWrongState {
                opcode: pdu.opcode(),
                phase: self.phase,
            });
        };
        if request.cid != self.cid {
            return Err(ConnectionError::CidMismatch {
                expected: self.cid,
                actual: request.cid,
            });
        }
        let outcome = self.login.handle_request(&request)?;
        let rejected = outcome.response.status_class != 0;
        let completed = outcome.frame_parameters();
        let next_phase = if rejected {
            self.pending_close_reason = Some(ConnectionCloseReason::LoginRejected);
            ConnectionPhase::Closed
        } else if outcome.response.transit {
            match outcome.response.next_stage {
                LoginStage::Security => ConnectionPhase::SecurityNegotiation,
                LoginStage::Operational => ConnectionPhase::LoginOperationalNegotiation,
                LoginStage::FullFeature => {
                    self.sequence = Some(SequenceState::new(
                        outcome.response.exp_cmd_sn,
                        outcome.response.stat_sn.wrapping_add(1),
                        self.command_window,
                    )?);
                    self.pending_frame_parameters = completed;
                    ConnectionPhase::FullFeaturePhase
                }
            }
        } else {
            self.phase
        };
        self.pending_phase = Some(next_phase);
        Ok(ConnectionOutput {
            response: Pdu::LoginResponse(outcome.response),
            transition_after_send: true,
        })
    }

    fn receive_full_feature(&mut self, pdu: Pdu) -> Result<ConnectionOutput, ConnectionError> {
        let Pdu::LogoutRequest(request) = pdu else {
            return Err(ConnectionError::PduInWrongState {
                opcode: pdu.opcode(),
                phase: self.phase,
            });
        };
        if request.reason_code > 2 {
            return Err(ConnectionError::InvalidLogoutReason(request.reason_code));
        }
        if request.reason_code != 0 && request.cid != self.cid {
            return Err(ConnectionError::CidMismatch {
                expected: self.cid,
                actual: request.cid,
            });
        }
        let sequence = self
            .sequence
            .as_mut()
            .ok_or(ConnectionError::MissingSequenceState)?;
        sequence.validate_cmd_sn(request.cmd_sn)?;
        sequence.acknowledge_exp_stat_sn(request.exp_stat_sn)?;
        let response = LogoutResponse::success(
            request.initiator_task_tag,
            sequence.allocate_stat_sn(),
            sequence.exp_cmd_sn(),
            sequence.max_cmd_sn(),
        );
        self.phase = ConnectionPhase::Logout;
        self.pending_phase = Some(ConnectionPhase::Closed);
        self.pending_close_reason = Some(ConnectionCloseReason::NormalLogout);
        Ok(ConnectionOutput {
            response: Pdu::LogoutResponse(response),
            transition_after_send: true,
        })
    }

    fn protocol_error<T>(&mut self, error: ConnectionError) -> Result<T, ConnectionError> {
        self.close(ConnectionCloseReason::ProtocolError);
        Err(error)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConnectionError {
    #[error("received {opcode:?} during {phase:?}")]
    PduInWrongState {
        opcode: crate::Opcode,
        phase: ConnectionPhase,
    },
    #[error("response_sent must be called before receiving another PDU")]
    ResponseNotSent,
    #[error("there is no pending response transition")]
    NoPendingResponse,
    #[error("CID {actual} does not match connection CID {expected}")]
    CidMismatch { expected: u16, actual: u16 },
    #[error("Logout reason {0} is reserved")]
    InvalidLogoutReason(u8),
    #[error("Full Feature Phase has no sequence state")]
    MissingSequenceState,
    #[error(transparent)]
    Login(#[from] TargetLoginError),
    #[error(transparent)]
    Sequence(#[from] SequenceError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::LogoutRequest;
    use crate::login::{IscsiName, LoginRequest, TextParameters};
    use crate::login_policy::TargetLoginPolicy;

    const INITIATOR: &str = "iqn.2024-01.com.example:initiator";
    const TARGET: &str = "iqn.2024-01.com.example:target";

    fn login_request(stage: LoginStage, next: LoginStage, text: &[u8], cmd_sn: u32) -> Pdu {
        Pdu::LoginRequest(LoginRequest {
            transit: true,
            continue_: false,
            current_stage: stage,
            next_stage: next,
            version_max: 0,
            version_min: 0,
            isid: [1, 2, 3, 4, 5, 6],
            tsih: 0,
            initiator_task_tag: 1,
            cid: 7,
            cmd_sn,
            exp_stat_sn: 0,
            params: TextParameters::parse(text),
        })
    }

    fn new_connection() -> ConnectionStateMachine {
        let mut policy = TargetLoginPolicy::default();
        policy.set_target_name(IscsiName::parse(TARGET).unwrap());
        ConnectionStateMachine::new(TargetLoginProcessor::new(policy, 0x1234), 7, 4).unwrap()
    }

    fn established_connection() -> ConnectionStateMachine {
        let mut connection = new_connection();
        let security = format!("InitiatorName={INITIATOR}\0TargetName={TARGET}\0AuthMethod=None\0");
        connection
            .receive(login_request(
                LoginStage::Security,
                LoginStage::Operational,
                security.as_bytes(),
                10,
            ))
            .unwrap();
        connection.response_sent().unwrap();
        connection
            .receive(login_request(
                LoginStage::Operational,
                LoginStage::FullFeature,
                b"",
                11,
            ))
            .unwrap();
        connection.response_sent().unwrap();
        connection
    }

    #[test]
    fn login_to_full_feature_and_logout_transition_after_responses_are_sent() {
        let mut connection = new_connection();
        let security = format!("InitiatorName={INITIATOR}\0TargetName={TARGET}\0AuthMethod=None\0");
        let output = connection
            .receive(login_request(
                LoginStage::Security,
                LoginStage::Operational,
                security.as_bytes(),
                10,
            ))
            .unwrap();
        assert!(matches!(output.response, Pdu::LoginResponse(_)));
        assert_eq!(connection.phase(), ConnectionPhase::SecurityNegotiation);
        connection.response_sent().unwrap();
        assert_eq!(
            connection.phase(),
            ConnectionPhase::LoginOperationalNegotiation
        );

        let _output = connection
            .receive(login_request(
                LoginStage::Operational,
                LoginStage::FullFeature,
                b"HeaderDigest=CRC32C,None\0MaxRecvDataSegmentLength=65536\0",
                11,
            ))
            .unwrap();
        assert_eq!(
            connection.frame_config().header_digest(),
            crate::digest::DigestType::None
        );
        connection.response_sent().unwrap();
        assert_eq!(connection.phase(), ConnectionPhase::FullFeaturePhase);
        assert_eq!(
            connection.frame_config().max_send_data_segment_length(),
            65_536
        );

        let output = connection
            .receive(Pdu::LogoutRequest(LogoutRequest {
                reason_code: 0,
                initiator_task_tag: 9,
                cid: 7,
                cmd_sn: 11,
                exp_stat_sn: 2,
            }))
            .unwrap();
        let Pdu::LogoutResponse(response) = output.response else {
            panic!("expected LogoutResponse");
        };
        assert_eq!(response.stat_sn, 2);
        assert_eq!(connection.phase(), ConnectionPhase::Logout);
        connection.response_sent().unwrap();
        assert_eq!(connection.phase(), ConnectionPhase::Closed);
        assert_eq!(
            connection.close_reason(),
            Some(ConnectionCloseReason::NormalLogout)
        );
    }

    #[test]
    fn wrong_state_sequence_and_timeout_errors_close_deterministically() {
        let mut connection = new_connection();
        let error = connection
            .receive(Pdu::LogoutRequest(LogoutRequest {
                reason_code: 0,
                initiator_task_tag: 1,
                cid: 7,
                cmd_sn: 0,
                exp_stat_sn: 0,
            }))
            .unwrap_err();
        assert!(matches!(error, ConnectionError::PduInWrongState { .. }));
        assert_eq!(connection.phase(), ConnectionPhase::Closed);
        assert_eq!(
            connection.close_reason(),
            Some(ConnectionCloseReason::ProtocolError)
        );

        let mut connection = new_connection();
        connection.on_timeout(ConnectionTimeoutKind::Login);
        assert_eq!(connection.phase(), ConnectionPhase::Closed);
        assert_eq!(
            connection.close_reason(),
            Some(ConnectionCloseReason::LoginTimeout)
        );

        let mut connection = established_connection();
        let error = connection
            .receive(Pdu::LogoutRequest(LogoutRequest {
                reason_code: 0,
                initiator_task_tag: 1,
                cid: 7,
                cmd_sn: 100,
                exp_stat_sn: 2,
            }))
            .unwrap_err();
        assert!(matches!(
            error,
            ConnectionError::Sequence(SequenceError::CmdSnOutsideWindow { .. })
        ));
        assert_eq!(connection.phase(), ConnectionPhase::Closed);
        assert_eq!(
            connection.close_reason(),
            Some(ConnectionCloseReason::ProtocolError)
        );
    }
}
