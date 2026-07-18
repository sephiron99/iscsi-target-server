//! Full Feature Phase의 제어 PDU와 discovery 상태.

use std::collections::HashMap;

use bytes::{Bytes, BytesMut};

use crate::control::{
    AsyncMessage, LogoutResponse, LogoutResponseCode, NopIn, Reject, RejectReason,
    TaskMgmtResponse, TextResponse,
};
use crate::login::{IscsiName, SessionType, TextParameterError, TextParameters};
use crate::opcode::TaskMgmtFunction;
use crate::scsi::{R2t, ScsiCommand, ScsiDataIn, ScsiDataOut, ScsiResponse};
use crate::scsi_target::{ScsiExecution, ScsiTarget, STATUS_CHECK_CONDITION, STATUS_GOOD};
use crate::serial::{SequenceError, SequenceState};
use crate::target_login::NegotiatedDataParameters;
use crate::Pdu;

pub const RESERVED_TAG: u32 = u32::MAX;
pub const DEFAULT_MAX_TEXT_SEQUENCE_LENGTH: usize = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryTarget {
    target_name: IscsiName,
    target_addresses: Vec<String>,
}

impl DiscoveryTarget {
    pub fn new(target_name: IscsiName) -> Self {
        Self {
            target_name,
            target_addresses: Vec::new(),
        }
    }

    pub fn target_name(&self) -> &IscsiName {
        &self.target_name
    }

    pub fn target_addresses(&self) -> &[String] {
        &self.target_addresses
    }

    pub fn add_target_address(&mut self, address: String) -> Result<(), ControlError> {
        if address.is_empty() || address.as_bytes().contains(&0) {
            return Err(ControlError::InvalidTargetAddress);
        }
        self.target_addresses.push(address);
        Ok(())
    }
}

#[derive(Debug)]
pub(crate) enum FullFeatureDisposition {
    Response(Pdu),
    ResponseSequence(Vec<Pdu>),
    NoResponse,
    CloseAfterResponse(Pdu),
    CloseAfterReject(Pdu),
}

#[derive(Debug, Clone)]
struct IncomingText {
    initiator_task_tag: u32,
    target_transfer_tag: u32,
    lun: u64,
    immediate: bool,
    data: BytesMut,
}

#[derive(Debug, Clone)]
struct OutgoingText {
    initiator_task_tag: u32,
    target_transfer_tag: u32,
    lun: u64,
    data: Bytes,
    offset: usize,
}

#[derive(Debug, Clone, Copy)]
struct PendingPing {
    target_transfer_tag: u32,
    lun: u64,
}

#[derive(Debug, Clone)]
struct PendingWrite {
    lun: u64,
    initiator_task_tag: u32,
    cdb: [u8; 16],
    expected_length: usize,
    data: BytesMut,
    target_transfer_tag: u32,
    burst_end: usize,
    next_data_sn: u32,
    next_r2t_sn: u32,
}

#[derive(Debug, Clone, Copy)]
struct CommandCompletion {
    lun: u64,
    initiator_task_tag: u32,
    expected_length: u32,
    actual_length: usize,
    max_response_segment_length: usize,
}

#[derive(Debug, Clone)]
pub(crate) struct FullFeatureState {
    session_type: SessionType,
    logged_in_target: Option<IscsiName>,
    discovery_targets: Vec<DiscoveryTarget>,
    incoming_text: Option<IncomingText>,
    outgoing_text: Option<OutgoingText>,
    pending_ping: Option<PendingPing>,
    next_target_transfer_tag: u32,
    max_text_sequence_length: usize,
    data_parameters: NegotiatedDataParameters,
    pending_writes: HashMap<u32, PendingWrite>,
}

impl FullFeatureState {
    pub(crate) fn new(
        session_type: SessionType,
        logged_in_target: Option<IscsiName>,
        mut discovery_targets: Vec<DiscoveryTarget>,
    ) -> Self {
        if discovery_targets.is_empty() {
            if let Some(target_name) = logged_in_target.clone() {
                discovery_targets.push(DiscoveryTarget::new(target_name));
            }
        }
        Self {
            session_type,
            logged_in_target,
            discovery_targets,
            incoming_text: None,
            outgoing_text: None,
            pending_ping: None,
            next_target_transfer_tag: 1,
            max_text_sequence_length: DEFAULT_MAX_TEXT_SEQUENCE_LENGTH,
            data_parameters: NegotiatedDataParameters {
                initial_r2t: true,
                immediate_data: true,
                first_burst_length: 64 * 1024,
                max_burst_length: 256 * 1024,
                max_outstanding_r2t: 1,
            },
            pending_writes: HashMap::new(),
        }
    }

    pub(crate) fn set_max_text_sequence_length(&mut self, value: usize) {
        self.max_text_sequence_length = value;
    }

    pub(crate) fn set_data_parameters(&mut self, parameters: NegotiatedDataParameters) {
        self.data_parameters = parameters;
    }

    pub(crate) fn has_pending_ping(&self) -> bool {
        self.pending_ping.is_some()
    }

    pub(crate) fn keepalive_probe(
        &mut self,
        sequence: &SequenceState,
        lun: u64,
    ) -> Result<Pdu, ControlError> {
        if self.pending_ping.is_some() {
            return Err(ControlError::KeepaliveAlreadyPending);
        }
        let target_transfer_tag = self.allocate_target_transfer_tag();
        self.pending_ping = Some(PendingPing {
            target_transfer_tag,
            lun,
        });
        Ok(Pdu::NopIn(NopIn {
            lun,
            initiator_task_tag: RESERVED_TAG,
            target_transfer_tag,
            stat_sn: sequence.next_stat_sn(),
            exp_cmd_sn: sequence.exp_cmd_sn(),
            max_cmd_sn: sequence.max_cmd_sn(),
            data: Bytes::new(),
        }))
    }

    pub(crate) fn request_logout(&self, sequence: &mut SequenceState, timeout_seconds: u16) -> Pdu {
        Pdu::AsyncMessage(AsyncMessage::request_logout(
            sequence.allocate_stat_sn(),
            sequence.exp_cmd_sn(),
            sequence.max_cmd_sn(),
            timeout_seconds,
        ))
    }

    #[cfg(test)]
    pub(crate) fn receive(
        &mut self,
        pdu: Pdu,
        sequence: &mut SequenceState,
        cid: u16,
        max_response_segment_length: usize,
    ) -> Result<FullFeatureDisposition, ControlError> {
        self.receive_with_scsi(pdu, sequence, cid, max_response_segment_length, None)
    }

    pub(crate) fn receive_with_scsi(
        &mut self,
        pdu: Pdu,
        sequence: &mut SequenceState,
        cid: u16,
        max_response_segment_length: usize,
        scsi_target: Option<&mut ScsiTarget>,
    ) -> Result<FullFeatureDisposition, ControlError> {
        let rejected_header = rejected_header(&pdu);
        match pdu {
            Pdu::NopOut(request) => self.receive_nop_out(
                request,
                sequence,
                max_response_segment_length,
                rejected_header,
            ),
            Pdu::TextRequest(request) => self.receive_text(
                request,
                sequence,
                max_response_segment_length,
                rejected_header,
            ),
            Pdu::LogoutRequest(request) => {
                observe_request(
                    sequence,
                    request.cmd_sn,
                    request.exp_stat_sn,
                    request.immediate,
                )?;
                let (response_code, close) = match request.reason_code {
                    0 => (LogoutResponseCode::ClosedSuccessfully, true),
                    1 if request.cid == cid => (LogoutResponseCode::ClosedSuccessfully, true),
                    1 => (LogoutResponseCode::CidNotFound, false),
                    2 => (LogoutResponseCode::RecoveryNotSupported, false),
                    _ => {
                        return Ok(FullFeatureDisposition::Response(reject(
                            RejectReason::InvalidPduField,
                            rejected_header,
                            sequence,
                        )))
                    }
                };
                let response = Pdu::LogoutResponse(LogoutResponse::with_response(
                    response_code,
                    request.initiator_task_tag,
                    sequence.allocate_stat_sn(),
                    sequence.exp_cmd_sn(),
                    sequence.max_cmd_sn(),
                ));
                if close {
                    Ok(FullFeatureDisposition::CloseAfterResponse(response))
                } else {
                    Ok(FullFeatureDisposition::Response(response))
                }
            }
            Pdu::TaskMgmtRequest(request) => {
                observe_request(
                    sequence,
                    request.cmd_sn,
                    request.exp_stat_sn,
                    request.immediate,
                )?;
                let referenced_tag_is_valid = matches!(
                    request.function,
                    TaskMgmtFunction::AbortTask | TaskMgmtFunction::TaskReassign
                ) || request.referenced_task_tag == RESERVED_TAG;
                if !referenced_tag_is_valid
                    || (request.function == TaskMgmtFunction::TaskReassign && !request.immediate)
                {
                    return Ok(FullFeatureDisposition::Response(reject(
                        RejectReason::InvalidPduField,
                        rejected_header,
                        sequence,
                    )));
                }
                let response = match request.function {
                    TaskMgmtFunction::AbortTask => 1,
                    TaskMgmtFunction::TaskReassign => 4,
                    TaskMgmtFunction::AbortTaskSet
                    | TaskMgmtFunction::ClearAca
                    | TaskMgmtFunction::ClearTaskSet
                    | TaskMgmtFunction::LogicalUnitReset
                    | TaskMgmtFunction::TargetWarmReset
                    | TaskMgmtFunction::TargetColdReset => 5,
                };
                Ok(FullFeatureDisposition::Response(Pdu::TaskMgmtResponse(
                    TaskMgmtResponse {
                        response,
                        initiator_task_tag: request.initiator_task_tag,
                        stat_sn: sequence.allocate_stat_sn(),
                        exp_cmd_sn: sequence.exp_cmd_sn(),
                        max_cmd_sn: sequence.max_cmd_sn(),
                    },
                )))
            }
            Pdu::ScsiCommand(request) => self.receive_scsi_command(
                request,
                sequence,
                max_response_segment_length,
                scsi_target,
                rejected_header,
            ),
            Pdu::ScsiDataOut(request) => {
                self.receive_data_out(request, sequence, scsi_target, rejected_header)
            }
            Pdu::LoginRequest(_) => Ok(FullFeatureDisposition::CloseAfterReject(reject(
                RejectReason::ProtocolError,
                rejected_header,
                sequence,
            ))),
            Pdu::LoginResponse(_)
            | Pdu::LogoutResponse(_)
            | Pdu::TextResponse(_)
            | Pdu::ScsiResponse(_)
            | Pdu::ScsiDataIn(_)
            | Pdu::NopIn(_)
            | Pdu::TaskMgmtResponse(_)
            | Pdu::R2t(_)
            | Pdu::AsyncMessage(_)
            | Pdu::Reject(_) => Ok(FullFeatureDisposition::CloseAfterReject(reject(
                RejectReason::ProtocolError,
                rejected_header,
                sequence,
            ))),
        }
    }

    fn receive_scsi_command(
        &mut self,
        request: ScsiCommand,
        sequence: &mut SequenceState,
        max_response_segment_length: usize,
        scsi_target: Option<&mut ScsiTarget>,
        rejected_header: Bytes,
    ) -> Result<FullFeatureDisposition, ControlError> {
        observe_request(
            sequence,
            request.cmd_sn,
            request.exp_stat_sn,
            request.immediate,
        )?;
        let Some(target) = scsi_target else {
            return Ok(FullFeatureDisposition::Response(reject(
                RejectReason::CommandNotSupported,
                rejected_header,
                sequence,
            )));
        };

        if !request.write {
            let result = target.execute(request.lun, &request.cdb, &request.immediate_data);
            let actual_length = result.data.len();
            return Ok(command_result(
                CommandCompletion {
                    lun: request.lun,
                    initiator_task_tag: request.initiator_task_tag,
                    expected_length: request.expected_data_transfer_length,
                    actual_length,
                    max_response_segment_length,
                },
                result,
                sequence,
            ));
        }
        if request.read
            || self
                .pending_writes
                .contains_key(&request.initiator_task_tag)
            || (!self.data_parameters.immediate_data && !request.immediate_data.is_empty())
            || (self.data_parameters.initial_r2t && !request.final_)
        {
            return Ok(FullFeatureDisposition::Response(reject(
                RejectReason::InvalidPduField,
                rejected_header,
                sequence,
            )));
        }

        let expected_length = request.expected_data_transfer_length as usize;
        let immediate_length = request.immediate_data.len();
        if expected_length > target.max_transfer_length()
            || immediate_length > expected_length
            || immediate_length > self.data_parameters.first_burst_length as usize
        {
            return Ok(FullFeatureDisposition::Response(reject(
                RejectReason::InvalidPduField,
                rejected_header,
                sequence,
            )));
        }
        if immediate_length == expected_length {
            if !request.final_ {
                return Ok(FullFeatureDisposition::Response(reject(
                    RejectReason::InvalidPduField,
                    rejected_header,
                    sequence,
                )));
            }
            let result = target.execute(request.lun, &request.cdb, &request.immediate_data);
            let actual_length = if result.status == STATUS_GOOD {
                expected_length
            } else {
                0
            };
            return Ok(command_result(
                CommandCompletion {
                    lun: request.lun,
                    initiator_task_tag: request.initiator_task_tag,
                    expected_length: request.expected_data_transfer_length,
                    actual_length,
                    max_response_segment_length,
                },
                result,
                sequence,
            ));
        }

        let mut data = BytesMut::with_capacity(immediate_length);
        data.extend_from_slice(&request.immediate_data);
        let unsolicited_end = expected_length.min(self.data_parameters.first_burst_length as usize);
        self.pending_writes.insert(
            request.initiator_task_tag,
            PendingWrite {
                lun: request.lun,
                initiator_task_tag: request.initiator_task_tag,
                cdb: request.cdb,
                expected_length,
                data,
                target_transfer_tag: RESERVED_TAG,
                burst_end: unsolicited_end,
                next_data_sn: 0,
                next_r2t_sn: 0,
            },
        );

        if !self.data_parameters.initial_r2t
            && !request.final_
            && immediate_length < unsolicited_end
        {
            return Ok(FullFeatureDisposition::NoResponse);
        }
        Ok(FullFeatureDisposition::Response(
            self.issue_r2t(request.initiator_task_tag, sequence)?,
        ))
    }

    fn receive_data_out(
        &mut self,
        request: ScsiDataOut,
        sequence: &mut SequenceState,
        scsi_target: Option<&mut ScsiTarget>,
        rejected_header: Bytes,
    ) -> Result<FullFeatureDisposition, ControlError> {
        let Some(pending) = self.pending_writes.get(&request.initiator_task_tag) else {
            return Ok(invalid_data_out(rejected_header, sequence));
        };
        let new_length = pending.data.len().checked_add(request.data.len());
        let valid = request.lun == pending.lun
            && request.target_transfer_tag == pending.target_transfer_tag
            && request.buffer_offset as usize == pending.data.len()
            && request.data_sn == pending.next_data_sn
            && !request.data.is_empty()
            && new_length.is_some_and(|length| {
                length <= pending.burst_end && length <= pending.expected_length
            });
        if !valid {
            return Ok(invalid_data_out(rejected_header, sequence));
        }
        let new_length = new_length.unwrap_or(usize::MAX);
        if request.final_ != (new_length == pending.burst_end) {
            return Ok(invalid_data_out(rejected_header, sequence));
        }

        let mut next_sequence = sequence.clone();
        next_sequence.acknowledge_exp_stat_sn(request.exp_stat_sn)?;
        *sequence = next_sequence;
        let pending = self
            .pending_writes
            .get_mut(&request.initiator_task_tag)
            .ok_or(ControlError::MissingWriteState)?;
        pending.data.extend_from_slice(&request.data);
        pending.next_data_sn = pending.next_data_sn.wrapping_add(1);

        if new_length < pending.burst_end {
            return Ok(FullFeatureDisposition::NoResponse);
        }
        if new_length < pending.expected_length {
            return Ok(FullFeatureDisposition::Response(
                self.issue_r2t(request.initiator_task_tag, sequence)?,
            ));
        }

        let pending = self
            .pending_writes
            .remove(&request.initiator_task_tag)
            .ok_or(ControlError::MissingWriteState)?;
        let Some(target) = scsi_target else {
            return Ok(invalid_data_out(rejected_header, sequence));
        };
        let result = target.execute(pending.lun, &pending.cdb, &pending.data);
        let actual_length = if result.status == STATUS_GOOD {
            pending.expected_length
        } else {
            0
        };
        Ok(command_result(
            CommandCompletion {
                lun: pending.lun,
                initiator_task_tag: pending.initiator_task_tag,
                expected_length: pending.expected_length as u32,
                actual_length,
                max_response_segment_length: 0,
            },
            result,
            sequence,
        ))
    }

    fn issue_r2t(
        &mut self,
        initiator_task_tag: u32,
        sequence: &SequenceState,
    ) -> Result<Pdu, ControlError> {
        let target_transfer_tag = self.allocate_target_transfer_tag();
        let pending = self
            .pending_writes
            .get_mut(&initiator_task_tag)
            .ok_or(ControlError::MissingWriteState)?;
        let buffer_offset = pending.data.len();
        let remaining = pending.expected_length - buffer_offset;
        let desired = remaining.min(self.data_parameters.max_burst_length as usize);
        pending.target_transfer_tag = target_transfer_tag;
        pending.burst_end = buffer_offset + desired;
        pending.next_data_sn = 0;
        let r2t_sn = pending.next_r2t_sn;
        pending.next_r2t_sn = pending.next_r2t_sn.wrapping_add(1);
        Ok(Pdu::R2t(R2t {
            lun: pending.lun,
            initiator_task_tag,
            target_transfer_tag,
            stat_sn: sequence.next_stat_sn(),
            exp_cmd_sn: sequence.exp_cmd_sn(),
            max_cmd_sn: sequence.max_cmd_sn(),
            r2t_sn,
            buffer_offset: buffer_offset as u32,
            desired_data_transfer_length: desired as u32,
        }))
    }

    fn receive_nop_out(
        &mut self,
        request: crate::control::NopOut,
        sequence: &mut SequenceState,
        max_response_segment_length: usize,
        rejected_header: Bytes,
    ) -> Result<FullFeatureDisposition, ControlError> {
        observe_request(
            sequence,
            request.cmd_sn,
            request.exp_stat_sn,
            request.immediate,
        )?;

        if request.initiator_task_tag == RESERVED_TAG {
            if !request.immediate {
                return Ok(FullFeatureDisposition::Response(reject(
                    RejectReason::InvalidPduField,
                    rejected_header,
                    sequence,
                )));
            }
            if request.target_transfer_tag != RESERVED_TAG {
                let Some(pending) = self.pending_ping else {
                    return Ok(FullFeatureDisposition::Response(reject(
                        RejectReason::InvalidPduField,
                        rejected_header,
                        sequence,
                    )));
                };
                if pending.target_transfer_tag != request.target_transfer_tag
                    || pending.lun != request.lun
                {
                    return Ok(FullFeatureDisposition::Response(reject(
                        RejectReason::InvalidPduField,
                        rejected_header,
                        sequence,
                    )));
                }
                self.pending_ping = None;
            }
            return Ok(FullFeatureDisposition::NoResponse);
        }

        if request.target_transfer_tag != RESERVED_TAG {
            return Ok(FullFeatureDisposition::Response(reject(
                RejectReason::InvalidPduField,
                rejected_header,
                sequence,
            )));
        }
        let data_length = request.data.len().min(max_response_segment_length);
        Ok(FullFeatureDisposition::Response(Pdu::NopIn(
            NopIn::reply_to(
                &request,
                sequence.allocate_stat_sn(),
                sequence.exp_cmd_sn(),
                sequence.max_cmd_sn(),
            )
            .with_data(request.data.slice(..data_length)),
        )))
    }

    fn receive_text(
        &mut self,
        request: crate::control::TextRequest,
        sequence: &mut SequenceState,
        max_response_segment_length: usize,
        rejected_header: Bytes,
    ) -> Result<FullFeatureDisposition, ControlError> {
        observe_request(
            sequence,
            request.cmd_sn,
            request.exp_stat_sn,
            request.immediate,
        )?;
        if request.continue_ && request.final_ {
            return Ok(FullFeatureDisposition::Response(reject(
                RejectReason::InvalidPduField,
                rejected_header,
                sequence,
            )));
        }

        if request.target_transfer_tag == RESERVED_TAG {
            // Reserved TTT는 해당 Text negotiation을 새로 시작하라는 뜻이다
            // (RFC 7143 11.10.4, 11.11.4).
            self.outgoing_text = None;
        } else if self.outgoing_text.is_some() {
            return self.continue_outgoing_text(
                request,
                sequence,
                max_response_segment_length,
                rejected_header,
            );
        }

        if request.target_transfer_tag == RESERVED_TAG {
            self.incoming_text = None;
            if request.continue_ {
                let target_transfer_tag = self.allocate_target_transfer_tag();
                let mut data = BytesMut::new();
                append_text(
                    &mut data,
                    request.params.as_bytes(),
                    self.max_text_sequence_length,
                )?;
                self.incoming_text = Some(IncomingText {
                    initiator_task_tag: request.initiator_task_tag,
                    target_transfer_tag,
                    lun: request.lun,
                    immediate: request.immediate,
                    data,
                });
                return Ok(FullFeatureDisposition::Response(
                    self.empty_text_continuation(&request, target_transfer_tag, sequence),
                ));
            }
            if !request.final_ {
                return Ok(FullFeatureDisposition::Response(reject(
                    RejectReason::InvalidPduField,
                    rejected_header,
                    sequence,
                )));
            }
            return self.finish_text_request(
                request.initiator_task_tag,
                request.lun,
                request.params.as_bytes(),
                sequence,
                max_response_segment_length,
            );
        }

        let Some(mut incoming) = self.incoming_text.take() else {
            return Ok(FullFeatureDisposition::Response(reject(
                RejectReason::InvalidPduField,
                rejected_header,
                sequence,
            )));
        };
        if incoming.target_transfer_tag != request.target_transfer_tag
            || incoming.initiator_task_tag != request.initiator_task_tag
            || incoming.lun != request.lun
            || incoming.immediate != request.immediate
        {
            return Ok(FullFeatureDisposition::Response(reject(
                RejectReason::InvalidPduField,
                rejected_header,
                sequence,
            )));
        }
        append_text(
            &mut incoming.data,
            request.params.as_bytes(),
            self.max_text_sequence_length,
        )?;
        if request.continue_ {
            let target_transfer_tag = incoming.target_transfer_tag;
            self.incoming_text = Some(incoming);
            return Ok(FullFeatureDisposition::Response(
                self.empty_text_continuation(&request, target_transfer_tag, sequence),
            ));
        }
        if !request.final_ {
            return Ok(FullFeatureDisposition::Response(reject(
                RejectReason::InvalidPduField,
                rejected_header,
                sequence,
            )));
        }
        self.finish_text_request(
            request.initiator_task_tag,
            request.lun,
            &incoming.data,
            sequence,
            max_response_segment_length,
        )
    }

    fn empty_text_continuation(
        &self,
        request: &crate::control::TextRequest,
        target_transfer_tag: u32,
        sequence: &mut SequenceState,
    ) -> Pdu {
        Pdu::TextResponse(TextResponse {
            final_: false,
            continue_: false,
            lun: request.lun,
            initiator_task_tag: request.initiator_task_tag,
            target_transfer_tag,
            stat_sn: sequence.allocate_stat_sn(),
            exp_cmd_sn: sequence.exp_cmd_sn(),
            max_cmd_sn: sequence.max_cmd_sn(),
            params: TextParameters::new(),
        })
    }

    fn finish_text_request(
        &mut self,
        initiator_task_tag: u32,
        lun: u64,
        data: &[u8],
        sequence: &mut SequenceState,
        max_response_segment_length: usize,
    ) -> Result<FullFeatureDisposition, ControlError> {
        let request = TextParameters::parse_complete(data)?;
        let response = self.answer_text(&request)?;
        self.start_outgoing_text(
            initiator_task_tag,
            lun,
            response.encode(),
            sequence,
            max_response_segment_length,
        )
    }

    fn answer_text(&self, request: &TextParameters) -> Result<TextParameters, ControlError> {
        let entries: Vec<_> = request.iter().collect();
        if entries.len() == 1 && entries[0].0 == "SendTargets" {
            return Ok(self.send_targets(entries[0].1));
        }
        if entries.iter().any(|(key, _)| *key == "SendTargets") {
            let mut response = TextParameters::new();
            response.push("SendTargets", "Reject");
            return Ok(response);
        }
        let mut response = TextParameters::new();
        for (key, _) in entries {
            response.push(key, "NotUnderstood");
        }
        Ok(response)
    }

    fn send_targets(&self, value: &str) -> TextParameters {
        if self.session_type == SessionType::Normal && value.is_empty() {
            let mut response = TextParameters::new();
            if let Some(name) = self.logged_in_target.as_ref() {
                response.push("TargetName", name.as_str());
                if let Some(target) = self
                    .discovery_targets
                    .iter()
                    .find(|target| target.target_name() == name)
                {
                    for address in target.target_addresses() {
                        response.push("TargetAddress", address);
                    }
                }
            }
            return response;
        }
        let targets: Vec<&DiscoveryTarget> = match self.session_type {
            SessionType::Discovery if value == "All" => self.discovery_targets.iter().collect(),
            SessionType::Discovery if !value.is_empty() => self
                .discovery_targets
                .iter()
                .filter(|target| target.target_name().as_str() == value)
                .collect(),
            _ => {
                let mut response = TextParameters::new();
                response.push("SendTargets", "Reject");
                return response;
            }
        };

        let mut response = TextParameters::new();
        for target in targets {
            response.push("TargetName", target.target_name().as_str());
            for address in target.target_addresses() {
                response.push("TargetAddress", address);
            }
        }
        response
    }

    fn start_outgoing_text(
        &mut self,
        initiator_task_tag: u32,
        lun: u64,
        data: Bytes,
        sequence: &mut SequenceState,
        max_response_segment_length: usize,
    ) -> Result<FullFeatureDisposition, ControlError> {
        if data.len() > self.max_text_sequence_length {
            return Err(ControlError::TextSequenceTooLarge {
                len: data.len(),
                max: self.max_text_sequence_length,
            });
        }
        let limit = max_response_segment_length.max(1);
        let end = data.len().min(limit);
        let more = end < data.len();
        let target_transfer_tag = if more {
            self.allocate_target_transfer_tag()
        } else {
            RESERVED_TAG
        };
        let chunk = data.slice(..end);
        let continue_ = more && chunk.last() != Some(&0);
        if more {
            self.outgoing_text = Some(OutgoingText {
                initiator_task_tag,
                target_transfer_tag,
                lun,
                data,
                offset: end,
            });
        }
        Ok(FullFeatureDisposition::Response(Pdu::TextResponse(
            TextResponse {
                final_: !more,
                continue_,
                lun,
                initiator_task_tag,
                target_transfer_tag,
                stat_sn: sequence.allocate_stat_sn(),
                exp_cmd_sn: sequence.exp_cmd_sn(),
                max_cmd_sn: sequence.max_cmd_sn(),
                params: TextParameters::from_bytes(chunk),
            },
        )))
    }

    fn continue_outgoing_text(
        &mut self,
        request: crate::control::TextRequest,
        sequence: &mut SequenceState,
        max_response_segment_length: usize,
        rejected_header: Bytes,
    ) -> Result<FullFeatureDisposition, ControlError> {
        let Some(mut outgoing) = self.outgoing_text.take() else {
            return Err(ControlError::MissingTextState);
        };
        if request.target_transfer_tag != outgoing.target_transfer_tag
            || request.initiator_task_tag != outgoing.initiator_task_tag
            || request.lun != outgoing.lun
            || !request.final_
            || request.continue_
            || !request.params.is_empty()
        {
            return Ok(FullFeatureDisposition::Response(reject(
                RejectReason::InvalidPduField,
                rejected_header,
                sequence,
            )));
        }
        let limit = max_response_segment_length.max(1);
        let end = outgoing
            .data
            .len()
            .min(outgoing.offset.saturating_add(limit));
        let chunk = outgoing.data.slice(outgoing.offset..end);
        let more = end < outgoing.data.len();
        let continue_ = more && chunk.last() != Some(&0);
        let target_transfer_tag = if more {
            outgoing.target_transfer_tag
        } else {
            RESERVED_TAG
        };
        outgoing.offset = end;
        if more {
            self.outgoing_text = Some(outgoing);
        }
        Ok(FullFeatureDisposition::Response(Pdu::TextResponse(
            TextResponse {
                final_: !more,
                continue_,
                lun: request.lun,
                initiator_task_tag: request.initiator_task_tag,
                target_transfer_tag,
                stat_sn: sequence.allocate_stat_sn(),
                exp_cmd_sn: sequence.exp_cmd_sn(),
                max_cmd_sn: sequence.max_cmd_sn(),
                params: TextParameters::from_bytes(chunk),
            },
        )))
    }

    fn allocate_target_transfer_tag(&mut self) -> u32 {
        loop {
            let candidate = self.next_target_transfer_tag;
            self.next_target_transfer_tag = self.next_target_transfer_tag.wrapping_add(1);
            if candidate != RESERVED_TAG {
                return candidate;
            }
        }
    }
}

fn command_result(
    completion: CommandCompletion,
    result: ScsiExecution,
    sequence: &mut SequenceState,
) -> FullFeatureDisposition {
    let actual = u32::try_from(completion.actual_length).unwrap_or(u32::MAX);
    let underflow = actual < completion.expected_length;
    let overflow = actual > completion.expected_length;
    let residual_count = actual.abs_diff(completion.expected_length);
    let transfer_length = result.data.len().min(completion.expected_length as usize);
    if transfer_length != 0 && result.status != STATUS_CHECK_CONDITION {
        let segment_length = completion.max_response_segment_length.max(1);
        let segment_count = transfer_length.div_ceil(segment_length);
        let mut responses = Vec::with_capacity(segment_count);
        for (index, offset) in (0..transfer_length).step_by(segment_length).enumerate() {
            let end = transfer_length.min(offset + segment_length);
            let final_ = end == transfer_length;
            // RFC 7143 §11.7: status가 없는 Data-In의 StatSN은 reserved이다.
            let stat_sn = if final_ {
                sequence.allocate_stat_sn()
            } else {
                0
            };
            responses.push(Pdu::ScsiDataIn(ScsiDataIn {
                final_,
                acknowledge: false,
                status_present: final_,
                overflow: final_ && overflow,
                underflow: final_ && underflow,
                status: if final_ { result.status } else { 0 },
                lun: completion.lun,
                initiator_task_tag: completion.initiator_task_tag,
                target_transfer_tag: RESERVED_TAG,
                stat_sn,
                exp_cmd_sn: sequence.exp_cmd_sn(),
                max_cmd_sn: sequence.max_cmd_sn(),
                data_sn: index as u32,
                buffer_offset: offset as u32,
                residual_count: if final_ { residual_count } else { 0 },
                data: result.data.slice(offset..end),
            }));
        }
        return match responses.as_slice() {
            [response] => FullFeatureDisposition::Response(response.clone()),
            _ => FullFeatureDisposition::ResponseSequence(responses),
        };
    }
    let mut response = ScsiResponse::good(
        completion.initiator_task_tag,
        sequence.allocate_stat_sn(),
        sequence.exp_cmd_sn(),
        sequence.max_cmd_sn(),
    );
    response.status = result.status;
    response.sense = result.sense;
    response.underflow = underflow;
    response.overflow = overflow;
    response.residual_count = residual_count;
    FullFeatureDisposition::Response(Pdu::ScsiResponse(response))
}

fn invalid_data_out(header: Bytes, sequence: &mut SequenceState) -> FullFeatureDisposition {
    FullFeatureDisposition::Response(reject(RejectReason::InvalidPduField, header, sequence))
}

fn append_text(buffer: &mut BytesMut, data: &[u8], max: usize) -> Result<(), ControlError> {
    let new_len =
        buffer
            .len()
            .checked_add(data.len())
            .ok_or(ControlError::TextSequenceTooLarge {
                len: usize::MAX,
                max,
            })?;
    if new_len > max {
        return Err(ControlError::TextSequenceTooLarge { len: new_len, max });
    }
    buffer.extend_from_slice(data);
    Ok(())
}

fn observe_request(
    sequence: &mut SequenceState,
    cmd_sn: u32,
    exp_stat_sn: u32,
    immediate: bool,
) -> Result<(), SequenceError> {
    let mut next = sequence.clone();
    next.acknowledge_exp_stat_sn(exp_stat_sn)?;
    if immediate {
        next.validate_cmd_sn(cmd_sn)?;
    } else {
        next.accept_cmd_sn(cmd_sn)?;
    }
    *sequence = next;
    Ok(())
}

fn rejected_header(pdu: &Pdu) -> Bytes {
    let (bhs, _) = pdu.encode_parts();
    Bytes::copy_from_slice(&bhs)
}

fn reject(reason: RejectReason, header: Bytes, sequence: &mut SequenceState) -> Pdu {
    Pdu::Reject(Reject {
        reason: reason as u8,
        stat_sn: sequence.allocate_stat_sn(),
        exp_cmd_sn: sequence.exp_cmd_sn(),
        max_cmd_sn: sequence.max_cmd_sn(),
        data_sn: 0,
        rejected_header: header,
    })
}

#[derive(Debug, thiserror::Error)]
pub enum ControlError {
    #[error("TargetAddress is empty or contains NUL")]
    InvalidTargetAddress,
    #[error("a keepalive probe is already outstanding")]
    KeepaliveAlreadyPending,
    #[error("Text sequence length {len} exceeds maximum {max}")]
    TextSequenceTooLarge { len: usize, max: usize },
    #[error("Text continuation state is missing")]
    MissingTextState,
    #[error("SCSI write continuation state is missing")]
    MissingWriteState,
    #[error(transparent)]
    Text(#[from] TextParameterError),
    #[error(transparent)]
    Sequence(#[from] SequenceError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::{LogoutRequest, NopOut, TaskMgmtRequest, TextRequest};
    use crate::opcode::TaskAttribute;
    use crate::scsi_target::MemoryBackend;

    const TARGET: &str = "iqn.2024-01.com.example:target";

    fn target() -> DiscoveryTarget {
        let mut target = DiscoveryTarget::new(IscsiName::parse(TARGET).unwrap());
        target
            .add_target_address("127.0.0.1:3260,1".to_owned())
            .unwrap();
        target
    }

    fn text_request(
        final_: bool,
        continue_: bool,
        itt: u32,
        ttt: u32,
        cmd_sn: u32,
        exp_stat_sn: u32,
        text: &[u8],
    ) -> Pdu {
        Pdu::TextRequest(TextRequest {
            immediate: false,
            final_,
            continue_,
            lun: 0,
            initiator_task_tag: itt,
            target_transfer_tag: ttt,
            cmd_sn,
            exp_stat_sn,
            params: TextParameters::parse(text),
        })
    }

    #[test]
    fn fragmented_send_targets_request_is_reassembled_strictly() {
        let mut state = FullFeatureState::new(SessionType::Discovery, None, vec![target()]);
        let mut sequence = SequenceState::new(10, 0, 8).unwrap();

        let first = state
            .receive(
                text_request(false, true, 7, RESERVED_TAG, 10, 0, b"SendTar"),
                &mut sequence,
                7,
                8192,
            )
            .unwrap();
        let FullFeatureDisposition::Response(Pdu::TextResponse(first)) = first else {
            panic!("expected continuation TextResponse");
        };
        assert!(!first.final_);
        assert!(!first.continue_);
        assert_ne!(first.target_transfer_tag, RESERVED_TAG);
        assert!(first.params.is_empty());

        let final_response = state
            .receive(
                text_request(
                    true,
                    false,
                    7,
                    first.target_transfer_tag,
                    11,
                    1,
                    b"gets=All\0",
                ),
                &mut sequence,
                7,
                8192,
            )
            .unwrap();
        let FullFeatureDisposition::Response(Pdu::TextResponse(response)) = final_response else {
            panic!("expected final TextResponse");
        };
        assert!(response.final_);
        assert_eq!(response.target_transfer_tag, RESERVED_TAG);
        assert_eq!(response.params.get("TargetName"), Some(TARGET));
        assert_eq!(
            response.params.get("TargetAddress"),
            Some("127.0.0.1:3260,1")
        );
        assert_eq!(sequence.exp_cmd_sn(), 12);
    }

    #[test]
    fn long_send_targets_response_uses_ttt_until_final_segment() {
        let mut catalog = Vec::new();
        for suffix in 0..4 {
            let name =
                IscsiName::parse(&format!("iqn.2024-01.com.example:target{suffix}")).unwrap();
            catalog.push(DiscoveryTarget::new(name));
        }
        let mut state = FullFeatureState::new(SessionType::Discovery, None, catalog);
        let mut sequence = SequenceState::new(20, 5, 16).unwrap();
        let mut disposition = state
            .receive(
                text_request(true, false, 9, RESERVED_TAG, 20, 5, b"SendTargets=All\0"),
                &mut sequence,
                7,
                24,
            )
            .unwrap();
        let mut wire = BytesMut::new();
        let mut cmd_sn = 21;
        let mut exp_stat_sn = 6;
        loop {
            let FullFeatureDisposition::Response(Pdu::TextResponse(response)) = disposition else {
                panic!("expected TextResponse");
            };
            wire.extend_from_slice(response.params.as_bytes());
            if response.final_ {
                assert_eq!(response.target_transfer_tag, RESERVED_TAG);
                break;
            }
            assert_ne!(response.target_transfer_tag, RESERVED_TAG);
            disposition = state
                .receive(
                    text_request(
                        true,
                        false,
                        9,
                        response.target_transfer_tag,
                        cmd_sn,
                        exp_stat_sn,
                        b"",
                    ),
                    &mut sequence,
                    7,
                    24,
                )
                .unwrap();
            cmd_sn += 1;
            exp_stat_sn += 1;
        }
        let parsed = TextParameters::parse_complete(&wire).unwrap();
        assert_eq!(
            parsed
                .iter()
                .filter(|(key, _)| *key == "TargetName")
                .count(),
            4
        );
    }

    #[test]
    fn nop_ping_echo_and_target_keepalive_follow_tag_rules() {
        let mut state = FullFeatureState::new(SessionType::Normal, None, vec![]);
        let mut sequence = SequenceState::new(30, 2, 4).unwrap();
        let ping = Pdu::NopOut(NopOut {
            immediate: false,
            lun: 0,
            initiator_task_tag: 77,
            target_transfer_tag: RESERVED_TAG,
            cmd_sn: 30,
            exp_stat_sn: 2,
            data: Bytes::from_static(b"ping"),
        });
        let response = state.receive(ping, &mut sequence, 7, 8192).unwrap();
        let FullFeatureDisposition::Response(Pdu::NopIn(response)) = response else {
            panic!("expected NopIn");
        };
        assert_eq!(response.data, Bytes::from_static(b"ping"));
        assert_eq!(response.stat_sn, 2);

        let Pdu::NopIn(probe) = state.keepalive_probe(&sequence, 3).unwrap() else {
            panic!("expected keepalive NopIn");
        };
        assert_eq!(probe.initiator_task_tag, RESERVED_TAG);
        assert_ne!(probe.target_transfer_tag, RESERVED_TAG);
        assert_eq!(probe.stat_sn, 3);
        let acknowledgement = Pdu::NopOut(NopOut {
            immediate: true,
            lun: 3,
            initiator_task_tag: RESERVED_TAG,
            target_transfer_tag: probe.target_transfer_tag,
            cmd_sn: 31,
            exp_stat_sn: 3,
            data: Bytes::new(),
        });
        assert!(matches!(
            state
                .receive(acknowledgement, &mut sequence, 7, 8192)
                .unwrap(),
            FullFeatureDisposition::NoResponse
        ));
        assert!(!state.has_pending_ping());
    }

    #[test]
    fn erl_zero_logout_and_task_management_return_explicit_codes() {
        let mut state = FullFeatureState::new(SessionType::Normal, None, vec![]);
        let mut sequence = SequenceState::new(40, 0, 4).unwrap();
        let recovery = Pdu::LogoutRequest(LogoutRequest {
            immediate: true,
            reason_code: 2,
            initiator_task_tag: 1,
            cid: 7,
            cmd_sn: 40,
            exp_stat_sn: 0,
        });
        let disposition = state.receive(recovery, &mut sequence, 7, 8192).unwrap();
        let FullFeatureDisposition::Response(Pdu::LogoutResponse(response)) = disposition else {
            panic!("expected LogoutResponse");
        };
        assert_eq!(
            response.response,
            LogoutResponseCode::RecoveryNotSupported as u8
        );

        let task = Pdu::TaskMgmtRequest(TaskMgmtRequest {
            immediate: true,
            function: TaskMgmtFunction::TaskReassign,
            lun: 0,
            initiator_task_tag: 2,
            referenced_task_tag: 99,
            cmd_sn: 40,
            exp_stat_sn: 1,
            ref_cmd_sn: 39,
            exp_data_sn: 0,
        });
        let disposition = state.receive(task, &mut sequence, 7, 8192).unwrap();
        let FullFeatureDisposition::Response(Pdu::TaskMgmtResponse(response)) = disposition else {
            panic!("expected TaskMgmtResponse");
        };
        assert_eq!(response.response, 4);
    }

    #[test]
    fn target_address_rejects_nul_before_it_reaches_text_output() {
        let mut target = DiscoveryTarget::new(IscsiName::parse(TARGET).unwrap());
        assert!(matches!(
            target.add_target_address("host\0hidden".to_owned()),
            Err(ControlError::InvalidTargetAddress)
        ));
    }

    #[test]
    fn r2t_bursts_advance_tags_offsets_and_r2t_sn() {
        let target_name = IscsiName::parse(TARGET).unwrap();
        let mut state = FullFeatureState::new(
            SessionType::Normal,
            Some(target_name.clone()),
            vec![DiscoveryTarget::new(target_name)],
        );
        state.set_data_parameters(NegotiatedDataParameters {
            initial_r2t: true,
            immediate_data: true,
            first_burst_length: 512,
            max_burst_length: 512,
            max_outstanding_r2t: 1,
        });
        let mut target = ScsiTarget::default();
        target.add_lun(0, MemoryBackend::new(512, 8).unwrap());
        let mut sequence = SequenceState::new(10, 0, 4).unwrap();
        let mut cdb = [0; 16];
        cdb[0] = 0x2a;
        cdb[8] = 2;
        let command = Pdu::ScsiCommand(ScsiCommand {
            immediate: false,
            final_: true,
            read: false,
            write: true,
            attr: TaskAttribute::Simple,
            lun: 0,
            initiator_task_tag: 7,
            expected_data_transfer_length: 1024,
            cmd_sn: 10,
            exp_stat_sn: 0,
            cdb,
            immediate_data: Bytes::new(),
        });
        let FullFeatureDisposition::Response(Pdu::R2t(first)) = state
            .receive_with_scsi(command, &mut sequence, 1, 8192, Some(&mut target))
            .unwrap()
        else {
            panic!("expected first R2T");
        };
        assert_eq!(
            (
                first.r2t_sn,
                first.buffer_offset,
                first.desired_data_transfer_length
            ),
            (0, 0, 512)
        );

        let FullFeatureDisposition::Response(Pdu::R2t(second)) = state
            .receive_with_scsi(
                Pdu::ScsiDataOut(ScsiDataOut {
                    final_: true,
                    lun: 0,
                    initiator_task_tag: 7,
                    target_transfer_tag: first.target_transfer_tag,
                    exp_stat_sn: 0,
                    data_sn: 0,
                    buffer_offset: 0,
                    data: Bytes::from(vec![1; 512]),
                }),
                &mut sequence,
                1,
                8192,
                Some(&mut target),
            )
            .unwrap()
        else {
            panic!("expected second R2T");
        };
        assert_ne!(second.target_transfer_tag, first.target_transfer_tag);
        assert_eq!(
            (
                second.r2t_sn,
                second.buffer_offset,
                second.desired_data_transfer_length
            ),
            (1, 512, 512)
        );

        let disposition = state
            .receive_with_scsi(
                Pdu::ScsiDataOut(ScsiDataOut {
                    final_: true,
                    lun: 0,
                    initiator_task_tag: 7,
                    target_transfer_tag: second.target_transfer_tag,
                    exp_stat_sn: 0,
                    data_sn: 0,
                    buffer_offset: 512,
                    data: Bytes::from(vec![2; 512]),
                }),
                &mut sequence,
                1,
                8192,
                Some(&mut target),
            )
            .unwrap();
        assert!(matches!(
            disposition,
            FullFeatureDisposition::Response(Pdu::ScsiResponse(_))
        ));
    }

    #[test]
    fn initial_r2t_no_accepts_only_the_bounded_unsolicited_sequence() {
        let target_name = IscsiName::parse(TARGET).unwrap();
        let mut state = FullFeatureState::new(
            SessionType::Normal,
            Some(target_name.clone()),
            vec![DiscoveryTarget::new(target_name)],
        );
        state.set_data_parameters(NegotiatedDataParameters {
            initial_r2t: false,
            immediate_data: true,
            first_burst_length: 512,
            max_burst_length: 1024,
            max_outstanding_r2t: 1,
        });
        let mut target = ScsiTarget::default();
        target.add_lun(0, MemoryBackend::new(512, 8).unwrap());
        let mut sequence = SequenceState::new(10, 0, 4).unwrap();
        let mut cdb = [0; 16];
        cdb[0] = 0x2a;
        cdb[8] = 1;
        let command = Pdu::ScsiCommand(ScsiCommand {
            immediate: false,
            final_: false,
            read: false,
            write: true,
            attr: TaskAttribute::Simple,
            lun: 0,
            initiator_task_tag: 8,
            expected_data_transfer_length: 512,
            cmd_sn: 10,
            exp_stat_sn: 0,
            cdb,
            immediate_data: Bytes::new(),
        });
        assert!(matches!(
            state
                .receive_with_scsi(command, &mut sequence, 1, 8192, Some(&mut target))
                .unwrap(),
            FullFeatureDisposition::NoResponse
        ));
        let result = state
            .receive_with_scsi(
                Pdu::ScsiDataOut(ScsiDataOut {
                    final_: true,
                    lun: 0,
                    initiator_task_tag: 8,
                    target_transfer_tag: RESERVED_TAG,
                    exp_stat_sn: 0,
                    data_sn: 0,
                    buffer_offset: 0,
                    data: Bytes::from(vec![3; 512]),
                }),
                &mut sequence,
                1,
                8192,
                Some(&mut target),
            )
            .unwrap();
        assert!(matches!(
            result,
            FullFeatureDisposition::Response(Pdu::ScsiResponse(_))
        ));
    }

    #[test]
    fn read_data_is_segmented_with_monotonic_data_sn_and_final_status() {
        let target_name = IscsiName::parse(TARGET).unwrap();
        let mut state = FullFeatureState::new(
            SessionType::Normal,
            Some(target_name.clone()),
            vec![DiscoveryTarget::new(target_name)],
        );
        let mut target = ScsiTarget::default();
        target.add_lun(0, MemoryBackend::new(512, 8).unwrap());
        let mut sequence = SequenceState::new(10, 7, 4).unwrap();
        let mut cdb = [0; 16];
        cdb[0] = 0x28;
        cdb[8] = 2;

        let disposition = state
            .receive_with_scsi(
                Pdu::ScsiCommand(ScsiCommand {
                    immediate: false,
                    final_: true,
                    read: true,
                    write: false,
                    attr: TaskAttribute::Simple,
                    lun: 0,
                    initiator_task_tag: 0x1122_3344,
                    expected_data_transfer_length: 1024,
                    cmd_sn: 10,
                    exp_stat_sn: 7,
                    cdb,
                    immediate_data: Bytes::new(),
                }),
                &mut sequence,
                1,
                300,
                Some(&mut target),
            )
            .unwrap();
        let FullFeatureDisposition::ResponseSequence(responses) = disposition else {
            panic!("expected segmented Data-In responses");
        };
        assert_eq!(responses.len(), 4);

        let expected = [
            (0, 0, 300, false),
            (1, 300, 300, false),
            (2, 600, 300, false),
            (3, 900, 124, true),
        ];
        for (response, (data_sn, offset, len, final_)) in responses.iter().zip(expected) {
            let Pdu::ScsiDataIn(data_in) = response else {
                panic!("expected Data-In");
            };
            assert_eq!(
                (
                    data_in.data_sn,
                    data_in.buffer_offset,
                    data_in.data.len(),
                    data_in.final_,
                    data_in.status_present,
                ),
                (data_sn, offset, len, final_, final_)
            );
            assert_eq!(data_in.stat_sn, if final_ { 7 } else { 0 });
            assert_eq!(data_in.residual_count, 0);
        }
        assert_eq!(sequence.next_stat_sn(), 8);
    }

    #[test]
    fn data_in_never_exceeds_expected_length_and_reports_overflow() {
        let target_name = IscsiName::parse(TARGET).unwrap();
        let mut state = FullFeatureState::new(
            SessionType::Normal,
            Some(target_name.clone()),
            vec![DiscoveryTarget::new(target_name)],
        );
        let mut target = ScsiTarget::default();
        target.add_lun(0, MemoryBackend::new(512, 8).unwrap());
        let mut sequence = SequenceState::new(10, 0, 4).unwrap();
        let mut cdb = [0; 16];
        cdb[0] = 0x12;
        cdb[4] = 36;

        let disposition = state
            .receive_with_scsi(
                Pdu::ScsiCommand(ScsiCommand {
                    immediate: false,
                    final_: true,
                    read: true,
                    write: false,
                    attr: TaskAttribute::Simple,
                    lun: 0,
                    initiator_task_tag: 9,
                    expected_data_transfer_length: 20,
                    cmd_sn: 10,
                    exp_stat_sn: 0,
                    cdb,
                    immediate_data: Bytes::new(),
                }),
                &mut sequence,
                1,
                512,
                Some(&mut target),
            )
            .unwrap();
        let FullFeatureDisposition::Response(Pdu::ScsiDataIn(response)) = disposition else {
            panic!("expected final Data-In");
        };
        assert_eq!(response.data.len(), 20);
        assert!(response.final_ && response.status_present && response.overflow);
        assert!(!response.underflow);
        assert_eq!(response.residual_count, 16);
    }
}
