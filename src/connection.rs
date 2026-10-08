//! Login부터 Full Feature Phase와 종료까지의 Connection 상태 머신.

use std::time::Duration;

use crate::Pdu;
use crate::control_state::{DiscoveryTarget, FullFeatureDisposition, FullFeatureState};
use crate::frame::FrameConfig;
use crate::negotiation::NegotiatedFrameParameters;
use crate::opcode::LoginStage;
use crate::scsi_target::{ScsiTarget, SharedScsiTarget};
use crate::serial::{SequenceError, SequenceState};
use crate::target_login::{TargetLoginError, TargetLoginProcessor};

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
    ServiceShutdown,
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
    /// 응답이 필요 없는 `NOP-Out` 확인이면 `None`이다.
    pub response: Option<Pdu>,
    /// 하나의 요청에서 연속 전송해야 하는 첫 응답 이후의 PDU이다.
    pub additional_responses: Vec<Pdu>,
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
    cid: Option<u16>,
    pending_phase: Option<ConnectionPhase>,
    pending_frame_parameters: Option<NegotiatedFrameParameters>,
    pending_close_reason: Option<ConnectionCloseReason>,
    close_reason: Option<ConnectionCloseReason>,
    timeouts: ConnectionTimeouts,
    discovery_targets: Vec<DiscoveryTarget>,
    max_text_sequence_length: usize,
    full_feature: Option<FullFeatureState>,
    scsi_target: Option<SharedScsiTarget>,
}

impl ConnectionStateMachine {
    pub fn new(
        login: TargetLoginProcessor,
        cid: u16,
        command_window: u32,
    ) -> Result<Self, ConnectionError> {
        Self::with_cid(login, Some(cid), command_window)
    }

    /// 첫 Login Request에서 Initiator가 선택한 CID를 바인딩한다.
    pub fn new_unbound(
        login: TargetLoginProcessor,
        command_window: u32,
    ) -> Result<Self, ConnectionError> {
        Self::with_cid(login, None, command_window)
    }

    fn with_cid(
        login: TargetLoginProcessor,
        cid: Option<u16>,
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
            discovery_targets: Vec::new(),
            max_text_sequence_length: crate::control_state::DEFAULT_MAX_TEXT_SEQUENCE_LENGTH,
            full_feature: None,
            scsi_target: None,
        })
    }

    pub fn phase(&self) -> ConnectionPhase {
        self.phase
    }

    pub fn cid(&self) -> Option<u16> {
        self.cid
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

    pub fn set_discovery_targets(&mut self, targets: Vec<DiscoveryTarget>) {
        self.discovery_targets = targets;
    }

    pub fn set_scsi_target(&mut self, target: ScsiTarget) {
        self.set_shared_scsi_target(target.into());
    }

    pub fn set_shared_scsi_target(&mut self, target: SharedScsiTarget) {
        self.scsi_target = Some(target);
    }

    pub fn set_max_text_sequence_length(&mut self, value: usize) -> Result<(), ConnectionError> {
        if value == 0 || value > crate::frame::MAX_DATA_SEGMENT_LENGTH {
            return Err(ConnectionError::InvalidTextSequenceLimit(value));
        }
        self.max_text_sequence_length = value;
        if let Some(full_feature) = self.full_feature.as_mut() {
            full_feature.set_max_text_sequence_length(value);
        }
        Ok(())
    }

    pub fn has_pending_keepalive(&self) -> bool {
        self.full_feature
            .as_ref()
            .is_some_and(FullFeatureState::has_pending_ping)
    }

    pub fn keepalive_probe(&mut self, lun: u64) -> Result<Pdu, ConnectionError> {
        if self.phase != ConnectionPhase::FullFeaturePhase {
            return Err(ConnectionError::PduInWrongState {
                opcode: crate::Opcode::NopIn,
                phase: self.phase,
            });
        }
        let sequence = self
            .sequence
            .as_ref()
            .ok_or(ConnectionError::MissingSequenceState)?;
        self.full_feature
            .as_mut()
            .ok_or(ConnectionError::MissingFullFeatureState)?
            .keepalive_probe(sequence, lun)
            .map_err(ConnectionError::Control)
    }

    pub fn request_logout(&mut self, timeout_seconds: u16) -> Result<Pdu, ConnectionError> {
        if self.phase != ConnectionPhase::FullFeaturePhase {
            return Err(ConnectionError::PduInWrongState {
                opcode: crate::Opcode::AsyncMessage,
                phase: self.phase,
            });
        }
        let sequence = self
            .sequence
            .as_mut()
            .ok_or(ConnectionError::MissingSequenceState)?;
        Ok(self
            .full_feature
            .as_ref()
            .ok_or(ConnectionError::MissingFullFeatureState)?
            .request_logout(sequence, timeout_seconds))
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
        if let Some(cid) = self.cid {
            if request.cid != cid {
                return Err(ConnectionError::CidMismatch {
                    expected: cid,
                    actual: request.cid,
                });
            }
        } else {
            self.cid = Some(request.cid);
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
                    let mut targets = self.discovery_targets.clone();
                    if targets.is_empty()
                        && let Some(name) = self.login.configured_target_name().cloned()
                    {
                        targets.push(DiscoveryTarget::new(name));
                    }
                    let mut full_feature = FullFeatureState::new(
                        self.login.session_type(),
                        self.login.target_name().cloned(),
                        targets,
                    );
                    full_feature.set_max_text_sequence_length(self.max_text_sequence_length);
                    full_feature.set_data_parameters(self.login.data_parameters());
                    self.full_feature = Some(full_feature);
                    ConnectionPhase::FullFeaturePhase
                }
            }
        } else {
            self.phase
        };
        self.pending_phase = Some(next_phase);
        Ok(ConnectionOutput {
            response: Some(Pdu::LoginResponse(outcome.response)),
            additional_responses: Vec::new(),
            transition_after_send: true,
        })
    }

    fn receive_full_feature(&mut self, pdu: Pdu) -> Result<ConnectionOutput, ConnectionError> {
        let cid = self.cid.ok_or(ConnectionError::MissingConnectionId)?;
        let sequence = self
            .sequence
            .as_mut()
            .ok_or(ConnectionError::MissingSequenceState)?;
        let disposition = self
            .full_feature
            .as_mut()
            .ok_or(ConnectionError::MissingFullFeatureState)?
            .receive_with_scsi(
                pdu,
                sequence,
                cid,
                self.frame_config.max_send_data_segment_length(),
                self.scsi_target.as_ref(),
            )
            .map_err(|error| match error {
                crate::control_state::ControlError::Sequence(source) => {
                    ConnectionError::Sequence(source)
                }
                other => ConnectionError::Control(other),
            })?;
        match disposition {
            FullFeatureDisposition::Response(response) => Ok(ConnectionOutput {
                response: Some(response),
                additional_responses: Vec::new(),
                transition_after_send: false,
            }),
            FullFeatureDisposition::ResponseSequence(mut responses) => {
                let response = if responses.is_empty() {
                    None
                } else {
                    Some(responses.remove(0))
                };
                Ok(ConnectionOutput {
                    response,
                    additional_responses: responses,
                    transition_after_send: false,
                })
            }
            FullFeatureDisposition::NoResponse => Ok(ConnectionOutput {
                response: None,
                additional_responses: Vec::new(),
                transition_after_send: false,
            }),
            FullFeatureDisposition::CloseAfterResponse(response) => {
                self.phase = ConnectionPhase::Logout;
                self.pending_phase = Some(ConnectionPhase::Closed);
                self.pending_close_reason = Some(ConnectionCloseReason::NormalLogout);
                Ok(ConnectionOutput {
                    response: Some(response),
                    additional_responses: Vec::new(),
                    transition_after_send: true,
                })
            }
            FullFeatureDisposition::CloseAfterReject(response) => {
                self.phase = ConnectionPhase::Logout;
                self.pending_phase = Some(ConnectionPhase::Closed);
                self.pending_close_reason = Some(ConnectionCloseReason::ProtocolError);
                Ok(ConnectionOutput {
                    response: Some(response),
                    additional_responses: Vec::new(),
                    transition_after_send: true,
                })
            }
        }
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
    #[error("Connection has not bound an Initiator CID")]
    MissingConnectionId,
    #[error("Full Feature Phase has no control state")]
    MissingFullFeatureState,
    #[error("Text sequence limit {0} is outside the supported range")]
    InvalidTextSequenceLimit(usize),
    #[error("Target service could not construct a Connection for this peer")]
    ServiceUnavailable,
    #[error(transparent)]
    Login(#[from] TargetLoginError),
    #[error(transparent)]
    Sequence(#[from] SequenceError),
    #[error(transparent)]
    Control(#[from] crate::control_state::ControlError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::LogoutRequest;
    use crate::login::{IscsiName, LoginRequest, TextParameters};
    use crate::login_policy::TargetLoginPolicy;
    use crate::opcode::TaskAttribute;
    use crate::scsi::{ScsiCommand, ScsiDataOut};
    use crate::scsi_target::{MemoryBackend, ScsiTarget};
    use bytes::Bytes;

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

    fn scsi_command(
        cdb: [u8; 16],
        read: bool,
        expected: u32,
        cmd_sn: u32,
        exp_stat_sn: u32,
    ) -> Pdu {
        Pdu::ScsiCommand(ScsiCommand {
            immediate: false,
            final_: true,
            read,
            write: false,
            attr: TaskAttribute::Simple,
            lun: 0,
            initiator_task_tag: cmd_sn,
            expected_data_transfer_length: expected,
            cmd_sn,
            exp_stat_sn,
            cdb,
            immediate_data: Bytes::new(),
        })
    }

    #[test]
    fn full_feature_scsi_commands_dispatch_to_the_configured_lun() {
        let mut connection = established_connection();
        let mut target = ScsiTarget::default();
        target
            .add_lun(0, MemoryBackend::new(512, 32).unwrap())
            .unwrap();
        connection.set_scsi_target(target);

        let mut inquiry = [0; 16];
        inquiry[0] = 0x12;
        inquiry[4] = 36;
        let exp_stat_sn = connection.sequence().unwrap().next_stat_sn();
        let output = connection
            .receive(scsi_command(inquiry, true, 64, 11, exp_stat_sn))
            .unwrap();
        let Some(Pdu::ScsiDataIn(response)) = output.response else {
            panic!("expected inquiry Data-In");
        };
        assert_eq!(response.status, 0);
        assert_eq!(&response.data[8..16], b"RUSTISCS");
        assert!(response.underflow);
        assert_eq!(response.residual_count, 28);

        let mut unsupported = [0; 16];
        unsupported[0] = 0xff;
        let exp_stat_sn = connection.sequence().unwrap().next_stat_sn();
        let output = connection
            .receive(scsi_command(unsupported, false, 0, 12, exp_stat_sn))
            .unwrap();
        let Some(Pdu::ScsiResponse(response)) = output.response else {
            panic!("expected CHECK CONDITION");
        };
        assert_eq!(response.status, 0x02);
        assert_eq!((response.sense[2], response.sense[12]), (0x05, 0x20));
    }

    #[test]
    fn initial_r2t_write_validates_data_out_and_commits_on_final_segment() {
        let mut connection = established_connection();
        let mut target = ScsiTarget::default();
        target
            .add_lun(0, MemoryBackend::new(512, 32).unwrap())
            .unwrap();
        connection.set_scsi_target(target);

        let mut cdb = [0; 16];
        cdb[0] = 0x2a;
        cdb[8] = 2;
        let exp_stat_sn = connection.sequence().unwrap().next_stat_sn();
        let output = connection
            .receive(Pdu::ScsiCommand(ScsiCommand {
                immediate: false,
                final_: true,
                read: false,
                write: true,
                attr: TaskAttribute::Simple,
                lun: 0,
                initiator_task_tag: 0x55,
                expected_data_transfer_length: 1024,
                cmd_sn: 11,
                exp_stat_sn,
                cdb,
                immediate_data: Bytes::new(),
            }))
            .unwrap();
        let Some(Pdu::R2t(r2t)) = output.response else {
            panic!("expected R2T");
        };
        assert_ne!(r2t.target_transfer_tag, u32::MAX);
        assert_eq!(
            (r2t.buffer_offset, r2t.desired_data_transfer_length),
            (0, 1024)
        );

        let invalid = connection
            .receive(Pdu::ScsiDataOut(ScsiDataOut {
                final_: false,
                lun: 0,
                initiator_task_tag: 0x55,
                target_transfer_tag: u32::MAX,
                exp_stat_sn,
                data_sn: 0,
                buffer_offset: 0,
                data: Bytes::from(vec![0x5a; 512]),
            }))
            .unwrap();
        assert!(matches!(invalid.response, Some(Pdu::Reject(_))));

        let exp_stat_sn = connection.sequence().unwrap().next_stat_sn();
        let first = connection
            .receive(Pdu::ScsiDataOut(ScsiDataOut {
                final_: false,
                lun: 0,
                initiator_task_tag: 0x55,
                target_transfer_tag: r2t.target_transfer_tag,
                exp_stat_sn,
                data_sn: 0,
                buffer_offset: 0,
                data: Bytes::from(vec![0x5a; 512]),
            }))
            .unwrap();
        assert!(first.response.is_none());

        let final_output = connection
            .receive(Pdu::ScsiDataOut(ScsiDataOut {
                final_: true,
                lun: 0,
                initiator_task_tag: 0x55,
                target_transfer_tag: r2t.target_transfer_tag,
                exp_stat_sn,
                data_sn: 1,
                buffer_offset: 512,
                data: Bytes::from(vec![0xa5; 512]),
            }))
            .unwrap();
        let Some(Pdu::ScsiResponse(response)) = final_output.response else {
            panic!("expected final SCSI Response");
        };
        assert_eq!(response.status, 0);
        assert_eq!(response.residual_count, 0);

        cdb[0] = 0x28;
        let exp_stat_sn = connection.sequence().unwrap().next_stat_sn();
        let read = connection
            .receive(scsi_command(cdb, true, 1024, 12, exp_stat_sn))
            .unwrap();
        let Some(Pdu::ScsiDataIn(data_in)) = read.response else {
            panic!("expected Data-In");
        };
        assert_eq!(&data_in.data[..512], &[0x5a; 512]);
        assert_eq!(&data_in.data[512..], &[0xa5; 512]);
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
        assert!(matches!(output.response, Some(Pdu::LoginResponse(_))));
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
                immediate: true,
                reason_code: 0,
                initiator_task_tag: 9,
                cid: 7,
                cmd_sn: 11,
                exp_stat_sn: 2,
            }))
            .unwrap();
        let Some(Pdu::LogoutResponse(response)) = output.response else {
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
                immediate: true,
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
                immediate: true,
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
