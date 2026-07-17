//! Target 측 Login 정책 적용과 응답 생성.
//!
//! 이 계층은 runtime이나 socket을 알지 않는다. Connection은 요청마다
//! [`TargetLoginProcessor::handle_request`]를 호출하고, 최종 성공 결과에
//! 포함된 frame parameter를 실제 codec에 적용한다.

use std::collections::{HashSet, VecDeque};
use std::sync::Arc;

use bytes::Bytes;

use crate::auth::{ChapCredentials, ChapExchange};
use crate::digest::DigestType;
use crate::frame::FrameConfig;
use crate::login::{
    AuthMethod, IscsiName, LoginRequest, LoginResponse, SessionType, TextParameters,
};
use crate::login_policy::{DigestPolicy, TargetLoginPolicy};
use crate::negotiation::{NegotiatedFrameParameters, NegotiationError, TargetLoginNegotiation};
use crate::opcode::LoginStage;

pub const LOGIN_STATUS_SUCCESS: (u8, u8) = (0x00, 0x00);
pub const LOGIN_STATUS_AUTHENTICATION_FAILURE: (u8, u8) = (0x02, 0x01);
pub const LOGIN_STATUS_TARGET_NOT_FOUND: (u8, u8) = (0x02, 0x03);
pub const LOGIN_STATUS_VERSION_UNSUPPORTED: (u8, u8) = (0x02, 0x05);
pub const LOGIN_STATUS_MISSING_PARAMETER: (u8, u8) = (0x02, 0x07);
pub const LOGIN_STATUS_SESSION_TYPE_UNSUPPORTED: (u8, u8) = (0x02, 0x09);
pub const LOGIN_STATUS_INVALID_REQUEST: (u8, u8) = (0x02, 0x0b);

#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum TargetLoginError {
    #[error("Login processor is already finished")]
    AlreadyFinished,
}

/// Connection 계층에 돌려주는 한 번의 Login 처리 결과.
#[derive(Debug, Clone)]
pub struct TargetLoginOutcome {
    pub response: LoginResponse,
    frame_parameters: Option<NegotiatedFrameParameters>,
}

impl TargetLoginOutcome {
    pub fn frame_parameters(&self) -> Option<NegotiatedFrameParameters> {
        self.frame_parameters
    }

    /// 최종 Login Response를 전송한 뒤 호출해야 한다.
    pub fn apply_frame_parameters(&self, config: &mut FrameConfig) {
        if let Some(parameters) = self.frame_parameters {
            parameters.apply_to(config);
        }
    }
}

#[derive(Debug, Clone)]
pub struct TargetLoginProcessor {
    policy: TargetLoginPolicy,
    negotiation: TargetLoginNegotiation,
    tsih: u16,
    stat_sn: u32,
    first_complete_request_seen: bool,
    pending_response: VecDeque<Bytes>,
    seen_operational_keys: HashSet<String>,
    chap: Option<ChapExchange>,
    negotiated_max_burst_length: u32,
    negotiated_first_burst_length: u32,
    finished: bool,
}

impl TargetLoginProcessor {
    pub fn new(policy: TargetLoginPolicy, tsih: u16) -> Self {
        let negotiated_max_burst_length = policy.max_burst_length();
        let negotiated_first_burst_length = policy.first_burst_length();
        Self {
            policy,
            negotiation: TargetLoginNegotiation::new(),
            tsih,
            stat_sn: 0,
            first_complete_request_seen: false,
            pending_response: VecDeque::new(),
            seen_operational_keys: HashSet::new(),
            chap: None,
            negotiated_max_burst_length,
            negotiated_first_burst_length,
            finished: false,
        }
    }

    pub fn with_chap_credentials(
        policy: TargetLoginPolicy,
        tsih: u16,
        credentials: ChapCredentials,
    ) -> Self {
        let mut processor = Self::new(policy, tsih);
        processor.chap = Some(ChapExchange::new(Arc::new(credentials)));
        processor
    }

    pub fn handle_request(
        &mut self,
        request: &LoginRequest,
    ) -> Result<TargetLoginOutcome, TargetLoginError> {
        if self.finished {
            return Err(TargetLoginError::AlreadyFinished);
        }

        let mut next = self.clone();
        match next.handle_request_inner(request) {
            Ok(outcome) => {
                *self = next;
                Ok(outcome)
            }
            Err(status) => {
                self.finished = true;
                Ok(TargetLoginOutcome {
                    response: self.rejection(request, status),
                    frame_parameters: None,
                })
            }
        }
    }

    fn handle_request_inner(
        &mut self,
        request: &LoginRequest,
    ) -> Result<TargetLoginOutcome, (u8, u8)> {
        if request.version_min > 0 {
            return Err(LOGIN_STATUS_VERSION_UNSUPPORTED);
        }
        if !self.pending_response.is_empty() {
            return self.continue_target_response(request);
        }

        let preview = self
            .negotiation
            .preview_initiator_parameters(request)
            .map_err(map_negotiation_error)?;

        if request.continue_ {
            let response = self.success_response(
                request,
                false,
                LoginStage::Security,
                false,
                TextParameters::new(),
            );
            self.observe(request, &response)?;
            return Ok(TargetLoginOutcome {
                response,
                frame_parameters: None,
            });
        }

        let params = preview.ok_or(LOGIN_STATUS_INVALID_REQUEST)?;
        let mut response_params = self.apply_parameters(request.current_stage, &params)?;
        if !self.first_complete_request_seen {
            response_params.push(
                "TargetPortalGroupTag",
                &self.policy.target_portal_group_tag().to_string(),
            );
            self.first_complete_request_seen = true;
        }

        let wants_full_feature = request.transit && request.next_stage == LoginStage::FullFeature;
        if wants_full_feature {
            self.validate_authentication(&params)?;
            self.validate_session(&params)?;
        }

        let encoded = response_params.encode();
        let limit = self.policy.max_response_segment_length();
        self.pending_response = encoded
            .chunks(limit)
            .map(Bytes::copy_from_slice)
            .collect::<VecDeque<_>>();

        if self.pending_response.len() > 1 {
            let first = self
                .pending_response
                .pop_front()
                .ok_or(LOGIN_STATUS_INVALID_REQUEST)?;
            let response = self.success_response(
                request,
                false,
                request.next_stage,
                true,
                TextParameters::parse(&first),
            );
            self.observe(request, &response)?;
            return Ok(TargetLoginOutcome {
                response,
                frame_parameters: None,
            });
        }

        let only = self.pending_response.pop_front().unwrap_or_default();
        let transit = request.transit;
        let response = self.success_response(
            request,
            transit,
            request.next_stage,
            false,
            TextParameters::parse(&only),
        );
        let completed = self.observe(request, &response)?;
        if completed.is_some() {
            self.finished = true;
        }
        Ok(TargetLoginOutcome {
            response,
            frame_parameters: completed,
        })
    }

    fn continue_target_response(
        &mut self,
        request: &LoginRequest,
    ) -> Result<TargetLoginOutcome, (u8, u8)> {
        if request.continue_ || !request.params.is_empty() {
            return Err(LOGIN_STATUS_INVALID_REQUEST);
        }
        let chunk = self
            .pending_response
            .pop_front()
            .ok_or(LOGIN_STATUS_INVALID_REQUEST)?;
        let more = !self.pending_response.is_empty();
        let transit = !more && request.transit;
        let response = self.success_response(
            request,
            transit,
            request.next_stage,
            more,
            TextParameters::parse(&chunk),
        );
        let completed = self.observe(request, &response)?;
        if completed.is_some() {
            self.finished = true;
        }
        Ok(TargetLoginOutcome {
            response,
            frame_parameters: completed,
        })
    }

    fn apply_parameters(
        &mut self,
        stage: LoginStage,
        request: &TextParameters,
    ) -> Result<TextParameters, (u8, u8)> {
        let mut response = TextParameters::new();
        let mut packet_keys = HashSet::new();
        let session_type = request
            .get("SessionType")
            .map(str::parse::<SessionType>)
            .transpose()
            .map_err(|_| LOGIN_STATUS_INVALID_REQUEST)?
            .unwrap_or_else(|| self.negotiation.session_type());
        let chap_name = request.get("CHAP_N");
        let chap_response = request.get("CHAP_R");
        if chap_name.is_some() != chap_response.is_some() {
            return Err(LOGIN_STATUS_AUTHENTICATION_FAILURE);
        }
        if let (Some(name), Some(encoded_response)) = (chap_name, chap_response) {
            self.chap
                .as_mut()
                .ok_or(LOGIN_STATUS_AUTHENTICATION_FAILURE)?
                .verify(name, encoded_response)
                .map_err(|_| LOGIN_STATUS_AUTHENTICATION_FAILURE)?;
        }
        for (key, value) in request.iter() {
            if !packet_keys.insert(key) {
                return Err(LOGIN_STATUS_INVALID_REQUEST);
            }
            match key {
                "InitiatorName" | "TargetName" | "SessionType" => {}
                "AuthMethod" if stage == LoginStage::Security => {
                    let selected = select_auth(value, self.policy.authentication().methods())
                        .ok_or(LOGIN_STATUS_AUTHENTICATION_FAILURE)?;
                    if selected == AuthMethod::Chap && self.chap.is_none() {
                        return Err(LOGIN_STATUS_AUTHENTICATION_FAILURE);
                    }
                    response.push(key, selected.as_str());
                }
                "AuthMethod" => return Err(LOGIN_STATUS_INVALID_REQUEST),
                "CHAP_A" if stage == LoginStage::Security => {
                    let challenge = self
                        .chap
                        .as_mut()
                        .ok_or(LOGIN_STATUS_AUTHENTICATION_FAILURE)?
                        .challenge(value)
                        .map_err(|_| LOGIN_STATUS_AUTHENTICATION_FAILURE)?;
                    for (challenge_key, challenge_value) in challenge.iter() {
                        response.push(challenge_key, challenge_value);
                    }
                }
                "CHAP_N" | "CHAP_R" if stage == LoginStage::Security => {}
                // 단방향 CHAP 정책이므로 target 인증 요구는 명시적으로 거부한다.
                "CHAP_I" | "CHAP_C" if stage == LoginStage::Security => {
                    return Err(LOGIN_STATUS_AUTHENTICATION_FAILURE)
                }
                key if key.starts_with("CHAP_") => return Err(LOGIN_STATUS_INVALID_REQUEST),
                _ if stage != LoginStage::Operational => {
                    response.push(key, "NotUnderstood");
                }
                "HeaderDigest" => response.push(
                    key,
                    select_digest(value, self.policy.header_digest())
                        .ok_or(LOGIN_STATUS_INVALID_REQUEST)?,
                ),
                "DataDigest" => response.push(
                    key,
                    select_digest(value, self.policy.data_digest())
                        .ok_or(LOGIN_STATUS_INVALID_REQUEST)?,
                ),
                "MaxRecvDataSegmentLength" => {
                    response.push(key, &self.policy.max_recv_data_segment_length().to_string())
                }
                "MaxConnections" => {
                    let target = if session_type == SessionType::Discovery {
                        1
                    } else {
                        self.policy.max_connections()
                    };
                    response.push(key, &minimum(value, target)?)
                }
                "InitialR2T" => {
                    response.push(key, yes_no(parse_bool(value)? || self.policy.initial_r2t()))
                }
                "ImmediateData" => response.push(
                    key,
                    yes_no(parse_bool(value)? && self.policy.immediate_data()),
                ),
                "MaxBurstLength" => {
                    let selected = minimum(value, self.policy.max_burst_length())?;
                    self.negotiated_max_burst_length =
                        selected.parse().map_err(|_| LOGIN_STATUS_INVALID_REQUEST)?;
                    response.push(key, &selected)
                }
                "FirstBurstLength" => {
                    let selected = minimum(value, self.policy.first_burst_length())?;
                    self.negotiated_first_burst_length =
                        selected.parse().map_err(|_| LOGIN_STATUS_INVALID_REQUEST)?;
                    response.push(key, &selected)
                }
                "DefaultTime2Wait" => {
                    response.push(key, &maximum(value, self.policy.default_time2_wait())?)
                }
                "DefaultTime2Retain" => {
                    response.push(key, &minimum(value, self.policy.default_time2_retain())?)
                }
                "MaxOutstandingR2T" => {
                    response.push(key, &minimum(value, self.policy.max_outstanding_r2t())?)
                }
                "DataPDUInOrder" => response.push(
                    key,
                    yes_no(parse_bool(value)? || self.policy.data_pdu_in_order()),
                ),
                "DataSequenceInOrder" => response.push(
                    key,
                    yes_no(parse_bool(value)? || self.policy.data_sequence_in_order()),
                ),
                "ErrorRecoveryLevel" => {
                    let policy = if session_type == SessionType::Discovery {
                        0
                    } else {
                        self.policy.error_recovery_level().value()
                    };
                    response.push(key, &minimum(value, policy)?);
                }
                "TaskReporting" => {
                    let selected = value
                        .split(',')
                        .find(|item| *item == self.policy.task_reporting().as_str())
                        .ok_or(LOGIN_STATUS_INVALID_REQUEST)?;
                    response.push(key, selected);
                }
                "iSCSIProtocolLevel" => {
                    let offered = parse_number(value)?;
                    if offered < u64::from(self.policy.iscsi_protocol_level()) {
                        return Err(LOGIN_STATUS_INVALID_REQUEST);
                    }
                    response.push(key, &self.policy.iscsi_protocol_level().to_string());
                }
                // RFC 7143에서 obsolete인 marker key는 이해하지만 지원하지 않는다.
                "OFMarker" | "IFMarker" | "OFMarkInt" | "IFMarkInt" => response.push(key, "Reject"),
                _ => response.push(key, "NotUnderstood"),
            }

            if is_operational_key(key) && !self.seen_operational_keys.insert(key.to_owned()) {
                return Err(LOGIN_STATUS_INVALID_REQUEST);
            }
        }
        if self.negotiated_first_burst_length > self.negotiated_max_burst_length {
            return Err(LOGIN_STATUS_INVALID_REQUEST);
        }
        Ok(response)
    }

    fn validate_authentication(&self, current: &TextParameters) -> Result<(), (u8, u8)> {
        let selected = if let Some(value) = current.get("AuthMethod") {
            select_auth(value, self.policy.authentication().methods())
                .ok_or(LOGIN_STATUS_AUTHENTICATION_FAILURE)?
        } else {
            self.negotiation
                .selected_auth_method()
                .cloned()
                .ok_or(LOGIN_STATUS_MISSING_PARAMETER)?
        };
        match selected {
            AuthMethod::None => Ok(()),
            // CHAP credential exchange는 다음 이정표에서 이 상태를 해제한다.
            AuthMethod::Chap
                if self
                    .chap
                    .as_ref()
                    .is_some_and(ChapExchange::is_authenticated) =>
            {
                Ok(())
            }
            _ => Err(LOGIN_STATUS_AUTHENTICATION_FAILURE),
        }
    }

    fn validate_session(&self, current: &TextParameters) -> Result<(), (u8, u8)> {
        let initiator_name = current
            .get("InitiatorName")
            .map(IscsiName::parse)
            .transpose()
            .map_err(|_| LOGIN_STATUS_INVALID_REQUEST)?;
        if self.negotiation.initiator_name().is_none() && initiator_name.is_none() {
            return Err(LOGIN_STATUS_MISSING_PARAMETER);
        }
        let session_type = current
            .get("SessionType")
            .map(str::parse::<SessionType>)
            .transpose()
            .map_err(|_| LOGIN_STATUS_INVALID_REQUEST)?
            .unwrap_or_else(|| self.negotiation.session_type());
        match session_type {
            SessionType::Discovery if !self.policy.allows_discovery_sessions() => {
                Err(LOGIN_STATUS_SESSION_TYPE_UNSUPPORTED)
            }
            SessionType::Discovery => Ok(()),
            SessionType::Normal if !self.policy.allows_normal_sessions() => {
                Err(LOGIN_STATUS_SESSION_TYPE_UNSUPPORTED)
            }
            SessionType::Normal => {
                let current_target = current
                    .get("TargetName")
                    .map(IscsiName::parse)
                    .transpose()
                    .map_err(|_| LOGIN_STATUS_INVALID_REQUEST)?;
                let requested = current_target
                    .as_ref()
                    .or_else(|| self.negotiation.target_name())
                    .ok_or(LOGIN_STATUS_MISSING_PARAMETER)?;
                let configured = self
                    .policy
                    .target_name()
                    .ok_or(LOGIN_STATUS_TARGET_NOT_FOUND)?;
                if requested == configured {
                    Ok(())
                } else {
                    Err(LOGIN_STATUS_TARGET_NOT_FOUND)
                }
            }
        }
    }

    fn observe(
        &mut self,
        request: &LoginRequest,
        response: &LoginResponse,
    ) -> Result<Option<NegotiatedFrameParameters>, (u8, u8)> {
        self.negotiation
            .observe_exchange(request, response)
            .map_err(map_negotiation_error)
    }

    fn success_response(
        &mut self,
        request: &LoginRequest,
        transit: bool,
        next_stage: LoginStage,
        continue_: bool,
        params: TextParameters,
    ) -> LoginResponse {
        let tsih = if transit && next_stage == LoginStage::FullFeature {
            self.tsih
        } else {
            0
        };
        let response = LoginResponse {
            transit,
            continue_,
            current_stage: request.current_stage,
            next_stage,
            version_max: 0,
            version_active: 0,
            isid: request.isid,
            tsih,
            initiator_task_tag: request.initiator_task_tag,
            stat_sn: self.stat_sn,
            exp_cmd_sn: request.cmd_sn,
            max_cmd_sn: request.cmd_sn,
            status_class: LOGIN_STATUS_SUCCESS.0,
            status_detail: LOGIN_STATUS_SUCCESS.1,
            params,
        };
        self.stat_sn = self.stat_sn.wrapping_add(1);
        response
    }

    fn rejection(&mut self, request: &LoginRequest, status: (u8, u8)) -> LoginResponse {
        let mut response = self.success_response(
            request,
            false,
            request.current_stage,
            false,
            TextParameters::new(),
        );
        response.status_class = status.0;
        response.status_detail = status.1;
        response
    }
}

fn map_negotiation_error(_error: NegotiationError) -> (u8, u8) {
    LOGIN_STATUS_INVALID_REQUEST
}

fn select_auth(value: &str, supported: &[AuthMethod]) -> Option<AuthMethod> {
    supported
        .iter()
        .find(|candidate| {
            value
                .split(',')
                .any(|offered| offered == candidate.as_str())
        })
        .cloned()
}

fn select_digest(value: &str, policy: DigestPolicy) -> Option<&'static str> {
    policy.values().iter().find_map(|candidate| {
        let text = match candidate {
            DigestType::None => "None",
            DigestType::Crc32c => "CRC32C",
        };
        value
            .split(',')
            .any(|offered| offered == text)
            .then_some(text)
    })
}

fn parse_number(value: &str) -> Result<u64, (u8, u8)> {
    let parsed = if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        (!hex.is_empty())
            .then(|| u64::from_str_radix(hex, 16).ok())
            .flatten()
    } else if (value == "0" || (!value.starts_with('0') && !value.is_empty()))
        && value.bytes().all(|byte| byte.is_ascii_digit())
    {
        value.parse().ok()
    } else {
        None
    };
    parsed.ok_or(LOGIN_STATUS_INVALID_REQUEST)
}

fn parse_bool(value: &str) -> Result<bool, (u8, u8)> {
    match value {
        "Yes" => Ok(true),
        "No" => Ok(false),
        _ => Err(LOGIN_STATUS_INVALID_REQUEST),
    }
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "Yes"
    } else {
        "No"
    }
}

fn minimum<T>(value: &str, target: T) -> Result<String, (u8, u8)>
where
    T: Into<u64>,
{
    Ok(parse_number(value)?.min(target.into()).to_string())
}

fn maximum<T>(value: &str, target: T) -> Result<String, (u8, u8)>
where
    T: Into<u64>,
{
    Ok(parse_number(value)?.max(target.into()).to_string())
}

fn is_operational_key(key: &str) -> bool {
    matches!(
        key,
        "HeaderDigest"
            | "DataDigest"
            | "MaxRecvDataSegmentLength"
            | "MaxConnections"
            | "InitialR2T"
            | "ImmediateData"
            | "MaxBurstLength"
            | "FirstBurstLength"
            | "DefaultTime2Wait"
            | "DefaultTime2Retain"
            | "MaxOutstandingR2T"
            | "DataPDUInOrder"
            | "DataSequenceInOrder"
            | "ErrorRecoveryLevel"
            | "TaskReporting"
            | "iSCSIProtocolLevel"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Pdu;
    use md5::{Digest, Md5};

    const INITIATOR: &str = "iqn.2024-01.com.example:initiator";
    const TARGET: &str = "iqn.2024-01.com.example:target";

    fn request(stage: LoginStage, next: LoginStage, text: &[u8], cmd_sn: u32) -> LoginRequest {
        LoginRequest {
            transit: true,
            continue_: false,
            current_stage: stage,
            next_stage: next,
            version_max: 0,
            version_min: 0,
            isid: [1, 2, 3, 4, 5, 6],
            tsih: 0,
            initiator_task_tag: 0x0102_0304,
            cid: 0,
            cmd_sn,
            exp_stat_sn: 0,
            params: TextParameters::parse(text),
        }
    }

    fn normal_policy() -> TargetLoginPolicy {
        let mut policy = TargetLoginPolicy::default();
        policy.set_target_name(IscsiName::parse(TARGET).unwrap());
        policy
    }

    #[test]
    fn normal_login_generates_fixed_wire_responses_and_frame_handoff() {
        let mut policy = normal_policy();
        policy.set_header_digest(DigestPolicy::PreferCrc32c);
        let mut processor = TargetLoginProcessor::new(policy, 0x1234);
        let security_text = format!(
            "InitiatorName={INITIATOR}\0TargetName={TARGET}\0SessionType=Normal\0AuthMethod=None\0"
        );
        let first = processor
            .handle_request(&request(
                LoginStage::Security,
                LoginStage::Operational,
                security_text.as_bytes(),
                7,
            ))
            .unwrap();
        let first_wire = Pdu::LoginResponse(first.response).encode();
        let first_bhs: [u8; 48] = [
            0x23, 0x81, 0, 0, 0, 0, 0, 39, 1, 2, 3, 4, 5, 6, 0, 0, 1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 7, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        assert_eq!(&first_wire[..48], &first_bhs);
        assert_eq!(
            &first_wire[48..87],
            b"AuthMethod=None\0TargetPortalGroupTag=1\0"
        );

        let final_outcome = processor
            .handle_request(&request(
                LoginStage::Operational,
                LoginStage::FullFeature,
                b"HeaderDigest=CRC32C,None\0DataDigest=None\0MaxRecvDataSegmentLength=65536\0",
                8,
            ))
            .unwrap();
        let final_wire = Pdu::LoginResponse(final_outcome.response.clone()).encode();
        let final_bhs: [u8; 48] = [
            0x23, 0x87, 0, 0, 0, 0, 0, 66, 1, 2, 3, 4, 5, 6, 0x12, 0x34, 1, 2, 3, 4, 0, 0, 0, 0, 0,
            0, 0, 1, 0, 0, 0, 8, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        assert_eq!(&final_wire[..48], &final_bhs);
        assert_eq!(
            &final_wire[48..],
            b"HeaderDigest=CRC32C\0DataDigest=None\0MaxRecvDataSegmentLength=8192\0\0\0"
        );
        let parameters = final_outcome.frame_parameters().unwrap();
        assert_eq!(parameters.header_digest(), DigestType::Crc32c);
        assert_eq!(parameters.peer_max_recv_data_segment_length(), 65_536);
        let mut config = FrameConfig::default();
        final_outcome.apply_frame_parameters(&mut config);
        assert_eq!(config.header_digest(), DigestType::Crc32c);
        assert_eq!(config.max_send_data_segment_length(), 65_536);
    }

    #[test]
    fn missing_normal_target_has_a_fixed_rejection_fixture() {
        let mut processor = TargetLoginProcessor::new(normal_policy(), 1);
        let text = format!("InitiatorName={INITIATOR}\0AuthMethod=None\0");
        let outcome = processor
            .handle_request(&request(
                LoginStage::Security,
                LoginStage::FullFeature,
                text.as_bytes(),
                9,
            ))
            .unwrap();
        let wire = Pdu::LoginResponse(outcome.response).encode();
        let expected: [u8; 48] = [
            0x23, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 0, 0, 1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 9, 0, 0, 0, 9, 2, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        assert_eq!(&wire[..], &expected);
    }

    #[test]
    fn discovery_response_is_split_and_finishes_on_empty_acknowledgements() {
        let mut policy = TargetLoginPolicy::default();
        policy.set_max_response_segment_length(12).unwrap();
        let mut processor = TargetLoginProcessor::new(policy, 0x44);
        let text = format!("InitiatorName={INITIATOR}\0SessionType=Discovery\0AuthMethod=None\0");
        let mut outcome = processor
            .handle_request(&request(
                LoginStage::Security,
                LoginStage::FullFeature,
                text.as_bytes(),
                1,
            ))
            .unwrap();
        assert!(outcome.response.continue_);
        assert!(!outcome.response.transit);

        let mut exchanges = 1;
        while outcome.response.continue_ {
            outcome = processor
                .handle_request(&request(
                    LoginStage::Security,
                    LoginStage::FullFeature,
                    b"",
                    1,
                ))
                .unwrap();
            exchanges += 1;
        }
        assert!(exchanges > 2);
        assert!(outcome.response.transit);
        assert_eq!(outcome.response.tsih, 0x44);
        assert!(outcome.frame_parameters().is_some());
    }

    #[test]
    fn unsupported_session_and_bad_continuation_are_rejected() {
        let mut policy = TargetLoginPolicy::default();
        policy.set_allow_discovery_sessions(false);
        let mut processor = TargetLoginProcessor::new(policy, 1);
        let text = format!("InitiatorName={INITIATOR}\0SessionType=Discovery\0AuthMethod=None\0");
        let outcome = processor
            .handle_request(&request(
                LoginStage::Security,
                LoginStage::FullFeature,
                text.as_bytes(),
                1,
            ))
            .unwrap();
        assert_eq!(
            (
                outcome.response.status_class,
                outcome.response.status_detail
            ),
            LOGIN_STATUS_SESSION_TYPE_UNSUPPORTED
        );

        let mut policy = TargetLoginPolicy::default();
        policy.set_max_response_segment_length(8).unwrap();
        let mut processor = TargetLoginProcessor::new(policy, 1);
        let first = processor
            .handle_request(&request(
                LoginStage::Security,
                LoginStage::Operational,
                b"AuthMethod=None\0",
                1,
            ))
            .unwrap();
        assert!(first.response.continue_);
        let rejected = processor
            .handle_request(&request(
                LoginStage::Security,
                LoginStage::Operational,
                b"Unexpected=value\0",
                1,
            ))
            .unwrap();
        assert_eq!(
            (
                rejected.response.status_class,
                rejected.response.status_detail
            ),
            LOGIN_STATUS_INVALID_REQUEST
        );
    }

    #[test]
    fn operational_keys_apply_their_rfc_result_functions() {
        let mut processor = TargetLoginProcessor::new(normal_policy(), 1);
        let security_text =
            format!("InitiatorName={INITIATOR}\0TargetName={TARGET}\0AuthMethod=None\0");
        processor
            .handle_request(&request(
                LoginStage::Security,
                LoginStage::Operational,
                security_text.as_bytes(),
                1,
            ))
            .unwrap();

        let mut operational = request(
            LoginStage::Operational,
            LoginStage::Operational,
            b"MaxConnections=4\0InitialR2T=No\0ImmediateData=No\0MaxBurstLength=524288\0FirstBurstLength=131072\0DefaultTime2Wait=1\0DefaultTime2Retain=40\0MaxOutstandingR2T=4\0DataPDUInOrder=No\0DataSequenceInOrder=No\0ErrorRecoveryLevel=2\0TaskReporting=FastAbort,RFC3720\0iSCSIProtocolLevel=2\0UnknownKey=value\0OFMarker=Yes\0",
            2,
        );
        operational.transit = false;
        let response = processor.handle_request(&operational).unwrap().response;
        let expected = [
            ("MaxConnections", "1"),
            ("InitialR2T", "Yes"),
            ("ImmediateData", "No"),
            ("MaxBurstLength", "262144"),
            ("FirstBurstLength", "65536"),
            ("DefaultTime2Wait", "2"),
            ("DefaultTime2Retain", "20"),
            ("MaxOutstandingR2T", "1"),
            ("DataPDUInOrder", "Yes"),
            ("DataSequenceInOrder", "Yes"),
            ("ErrorRecoveryLevel", "0"),
            ("TaskReporting", "RFC3720"),
            ("iSCSIProtocolLevel", "1"),
            ("UnknownKey", "NotUnderstood"),
            ("OFMarker", "Reject"),
        ];
        for (key, value) in expected {
            assert_eq!(response.params.get(key), Some(value), "{key}");
        }
    }

    #[test]
    fn incompatible_burst_results_and_unauthenticated_chap_are_rejected() {
        let mut processor = TargetLoginProcessor::new(normal_policy(), 1);
        let security_text =
            format!("InitiatorName={INITIATOR}\0TargetName={TARGET}\0AuthMethod=None\0");
        processor
            .handle_request(&request(
                LoginStage::Security,
                LoginStage::Operational,
                security_text.as_bytes(),
                1,
            ))
            .unwrap();
        let mut bad_burst = request(
            LoginStage::Operational,
            LoginStage::Operational,
            b"MaxBurstLength=32768\0",
            2,
        );
        bad_burst.transit = false;
        let rejected = processor.handle_request(&bad_burst).unwrap();
        assert_eq!(
            (
                rejected.response.status_class,
                rejected.response.status_detail
            ),
            LOGIN_STATUS_INVALID_REQUEST
        );

        let mut chap_policy = normal_policy();
        chap_policy.set_authentication(crate::login_policy::AuthenticationPolicy::ChapOnly);
        let mut processor = TargetLoginProcessor::new(chap_policy, 1);
        let chap = format!("InitiatorName={INITIATOR}\0TargetName={TARGET}\0AuthMethod=CHAP\0");
        let rejected = processor
            .handle_request(&request(
                LoginStage::Security,
                LoginStage::FullFeature,
                chap.as_bytes(),
                1,
            ))
            .unwrap();
        assert_eq!(
            (
                rejected.response.status_class,
                rejected.response.status_detail
            ),
            LOGIN_STATUS_AUTHENTICATION_FAILURE
        );
    }

    #[test]
    fn one_way_chap_authenticates_before_stage_transition() {
        let mut policy = normal_policy();
        policy.set_authentication(crate::login_policy::AuthenticationPolicy::ChapOnly);
        let credentials =
            ChapCredentials::new("chap-user".to_owned(), b"chap-secret".to_vec()).unwrap();
        let mut processor = TargetLoginProcessor::with_chap_credentials(policy, 1, credentials);

        let identity = format!("InitiatorName={INITIATOR}\0TargetName={TARGET}\0AuthMethod=CHAP\0");
        let mut select = request(
            LoginStage::Security,
            LoginStage::Security,
            identity.as_bytes(),
            1,
        );
        select.transit = false;
        assert_eq!(
            processor
                .handle_request(&select)
                .unwrap()
                .response
                .params
                .get("AuthMethod"),
            Some("CHAP")
        );

        let mut algorithm = request(LoginStage::Security, LoginStage::Security, b"CHAP_A=5\0", 1);
        algorithm.transit = false;
        let challenge = processor.handle_request(&algorithm).unwrap().response;
        let identifier: u8 = challenge.params.get("CHAP_I").unwrap().parse().unwrap();
        let encoded_challenge = challenge.params.get("CHAP_C").unwrap();
        let challenge_bytes = encoded_challenge
            .strip_prefix("0x")
            .unwrap()
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let text = std::str::from_utf8(pair).unwrap();
                u8::from_str_radix(text, 16).unwrap()
            })
            .collect::<Vec<_>>();
        let mut hasher = Md5::new();
        hasher.update([identifier]);
        hasher.update(b"chap-secret");
        hasher.update(&challenge_bytes);
        let digest = hasher.finalize();
        let response = digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let proof = format!("CHAP_N=chap-user\0CHAP_R=0x{response}\0");
        let authenticated = processor
            .handle_request(&request(
                LoginStage::Security,
                LoginStage::Operational,
                proof.as_bytes(),
                1,
            ))
            .unwrap();
        assert!(authenticated.response.transit);
        assert_eq!(authenticated.response.status_class, 0);

        let completed = processor
            .handle_request(&request(
                LoginStage::Operational,
                LoginStage::FullFeature,
                b"",
                1,
            ))
            .unwrap();
        assert!(completed.response.transit);
        assert!(completed.frame_parameters().is_some());
    }
}
