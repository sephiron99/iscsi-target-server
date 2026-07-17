//! Target가 Login 협상에서 제안하거나 수락할 값의 정책.
//!
//! 이 모듈은 wire PDU 표현과 분리된 Target 계층의 설정이다. 실제 key
//! 처리와 응답 생성은 이 정책을 소비하되, 정책 자체는 Connection이나
//! Session 상태를 소유하지 않는다.

use crate::digest::DigestType;
use crate::frame::{DEFAULT_MAX_RECV_DATA_SEGMENT_LENGTH, MAX_DATA_SEGMENT_LENGTH};
use crate::login::{AuthMethod, IscsiName};
use crate::negotiation::{
    DEFAULT_MAX_LOGIN_TEXT_SEQUENCE_LENGTH, MIN_MAX_RECV_DATA_SEGMENT_LENGTH,
};

pub const DEFAULT_MAX_CONNECTIONS: u16 = 1;
pub const DEFAULT_INITIAL_R2T: bool = true;
pub const DEFAULT_IMMEDIATE_DATA: bool = true;
pub const DEFAULT_MAX_BURST_LENGTH: u32 = 256 * 1024;
pub const DEFAULT_FIRST_BURST_LENGTH: u32 = 64 * 1024;
pub const DEFAULT_TIME2_WAIT: u16 = 2;
pub const DEFAULT_TIME2_RETAIN: u16 = 20;
pub const DEFAULT_MAX_OUTSTANDING_R2T: u16 = 1;
pub const DEFAULT_DATA_PDU_IN_ORDER: bool = true;
pub const DEFAULT_DATA_SEQUENCE_IN_ORDER: bool = true;
pub const DEFAULT_ERROR_RECOVERY_LEVEL: u8 = 0;
pub const ISCSI_PROTOCOL_LEVEL: u8 = 1;

pub const MAX_TIME2_VALUE: u16 = 3600;

/// Target가 실제로 선택할 수 있는 인증 정책.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum AuthenticationPolicy {
    #[default]
    NoneOnly,
    ChapOnly,
    PreferChap,
}

impl AuthenticationPolicy {
    pub fn methods(self) -> &'static [AuthMethod] {
        const NONE: &[AuthMethod] = &[AuthMethod::None];
        const CHAP: &[AuthMethod] = &[AuthMethod::Chap];
        const CHAP_NONE: &[AuthMethod] = &[AuthMethod::Chap, AuthMethod::None];

        match self {
            Self::NoneOnly => NONE,
            Self::ChapOnly => CHAP,
            Self::PreferChap => CHAP_NONE,
        }
    }
}

/// Target가 허용하는 표준 digest와 선택 우선순위.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum DigestPolicy {
    /// RFC 7143 13.1절 기본값이다.
    #[default]
    NoneOnly,
    Crc32cOnly,
    PreferNone,
    PreferCrc32c,
}

impl DigestPolicy {
    pub fn values(self) -> &'static [DigestType] {
        const NONE: &[DigestType] = &[DigestType::None];
        const CRC32C: &[DigestType] = &[DigestType::Crc32c];
        const NONE_FIRST: &[DigestType] = &[DigestType::None, DigestType::Crc32c];
        const CRC32C_FIRST: &[DigestType] = &[DigestType::Crc32c, DigestType::None];

        match self {
            Self::NoneOnly => NONE,
            Self::Crc32cOnly => CRC32C,
            Self::PreferNone => NONE_FIRST,
            Self::PreferCrc32c => CRC32C_FIRST,
        }
    }
}

/// RFC 7143 13.23절의 task completion reporting 방식.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum TaskReporting {
    #[default]
    Rfc3720,
    ResponseFence,
    FastAbort,
}

impl TaskReporting {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Rfc3720 => "RFC3720",
            Self::ResponseFence => "ResponseFence",
            Self::FastAbort => "FastAbort",
        }
    }
}

/// RFC 7143 13.20절에서 정의한 recovery level.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[repr(u8)]
pub enum ErrorRecoveryLevel {
    #[default]
    Level0 = 0,
    Level1 = 1,
    Level2 = 2,
}

impl ErrorRecoveryLevel {
    pub const fn value(self) -> u8 {
        self as u8
    }
}

#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum TargetLoginPolicyError {
    #[error("{key} {value} is outside {min}..={max}")]
    OutOfRange {
        key: &'static str,
        value: usize,
        min: usize,
        max: usize,
    },

    #[error("FirstBurstLength {first_burst_length} exceeds MaxBurstLength {max_burst_length}")]
    FirstBurstExceedsMaxBurst {
        first_burst_length: u32,
        max_burst_length: u32,
    },
}

/// Target가 Login에서 사용할 협상 값과 RFC 기본값.
///
/// 수치 setter는 RFC 범위와 교차 불변식을 먼저 검사하므로 오류가
/// 반환되면 기존 정책이 바뀌지 않는다. 실제 협상 결과 함수(OR, AND,
/// Minimum, Maximum)는 응답 생성 계층에서 적용한다 (RFC 7143 13절).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetLoginPolicy {
    target_name: Option<IscsiName>,
    target_portal_group_tag: u16,
    allow_normal_sessions: bool,
    allow_discovery_sessions: bool,
    authentication: AuthenticationPolicy,
    max_response_segment_length: usize,
    header_digest: DigestPolicy,
    data_digest: DigestPolicy,
    max_connections: u16,
    initial_r2t: bool,
    immediate_data: bool,
    max_recv_data_segment_length: usize,
    max_burst_length: u32,
    first_burst_length: u32,
    default_time2_wait: u16,
    default_time2_retain: u16,
    max_outstanding_r2t: u16,
    data_pdu_in_order: bool,
    data_sequence_in_order: bool,
    error_recovery_level: ErrorRecoveryLevel,
    task_reporting: TaskReporting,
}

impl Default for TargetLoginPolicy {
    fn default() -> Self {
        Self {
            target_name: None,
            target_portal_group_tag: 1,
            allow_normal_sessions: true,
            allow_discovery_sessions: true,
            authentication: AuthenticationPolicy::default(),
            max_response_segment_length: DEFAULT_MAX_LOGIN_TEXT_SEQUENCE_LENGTH,
            header_digest: DigestPolicy::default(),
            data_digest: DigestPolicy::default(),
            max_connections: DEFAULT_MAX_CONNECTIONS,
            initial_r2t: DEFAULT_INITIAL_R2T,
            immediate_data: DEFAULT_IMMEDIATE_DATA,
            max_recv_data_segment_length: DEFAULT_MAX_RECV_DATA_SEGMENT_LENGTH,
            max_burst_length: DEFAULT_MAX_BURST_LENGTH,
            first_burst_length: DEFAULT_FIRST_BURST_LENGTH,
            default_time2_wait: DEFAULT_TIME2_WAIT,
            default_time2_retain: DEFAULT_TIME2_RETAIN,
            max_outstanding_r2t: DEFAULT_MAX_OUTSTANDING_R2T,
            data_pdu_in_order: DEFAULT_DATA_PDU_IN_ORDER,
            data_sequence_in_order: DEFAULT_DATA_SEQUENCE_IN_ORDER,
            error_recovery_level: ErrorRecoveryLevel::default(),
            task_reporting: TaskReporting::default(),
        }
    }
}

impl TargetLoginPolicy {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn target_name(&self) -> Option<&IscsiName> {
        self.target_name.as_ref()
    }

    pub fn set_target_name(&mut self, target_name: IscsiName) {
        self.target_name = Some(target_name);
    }

    pub fn target_portal_group_tag(&self) -> u16 {
        self.target_portal_group_tag
    }

    pub fn set_target_portal_group_tag(&mut self, value: u16) {
        self.target_portal_group_tag = value;
    }

    pub fn allows_normal_sessions(&self) -> bool {
        self.allow_normal_sessions
    }

    pub fn set_allow_normal_sessions(&mut self, value: bool) {
        self.allow_normal_sessions = value;
    }

    pub fn allows_discovery_sessions(&self) -> bool {
        self.allow_discovery_sessions
    }

    pub fn set_allow_discovery_sessions(&mut self, value: bool) {
        self.allow_discovery_sessions = value;
    }

    pub fn authentication(&self) -> AuthenticationPolicy {
        self.authentication
    }

    pub fn set_authentication(&mut self, value: AuthenticationPolicy) {
        self.authentication = value;
    }

    pub fn max_response_segment_length(&self) -> usize {
        self.max_response_segment_length
    }

    pub fn set_max_response_segment_length(
        &mut self,
        value: usize,
    ) -> Result<(), TargetLoginPolicyError> {
        validate_range(
            "LoginResponseSegmentLength",
            value,
            1,
            MAX_DATA_SEGMENT_LENGTH,
        )?;
        self.max_response_segment_length = value;
        Ok(())
    }

    pub fn header_digest(&self) -> DigestPolicy {
        self.header_digest
    }

    pub fn set_header_digest(&mut self, policy: DigestPolicy) {
        self.header_digest = policy;
    }

    pub fn data_digest(&self) -> DigestPolicy {
        self.data_digest
    }

    pub fn set_data_digest(&mut self, policy: DigestPolicy) {
        self.data_digest = policy;
    }

    pub fn max_connections(&self) -> u16 {
        self.max_connections
    }

    pub fn set_max_connections(&mut self, value: u16) -> Result<(), TargetLoginPolicyError> {
        validate_range("MaxConnections", usize::from(value), 1, u16::MAX.into())?;
        self.max_connections = value;
        Ok(())
    }

    pub fn initial_r2t(&self) -> bool {
        self.initial_r2t
    }

    pub fn set_initial_r2t(&mut self, value: bool) {
        self.initial_r2t = value;
    }

    pub fn immediate_data(&self) -> bool {
        self.immediate_data
    }

    pub fn set_immediate_data(&mut self, value: bool) {
        self.immediate_data = value;
    }

    pub fn max_recv_data_segment_length(&self) -> usize {
        self.max_recv_data_segment_length
    }

    pub fn set_max_recv_data_segment_length(
        &mut self,
        value: usize,
    ) -> Result<(), TargetLoginPolicyError> {
        validate_data_length("MaxRecvDataSegmentLength", value)?;
        self.max_recv_data_segment_length = value;
        Ok(())
    }

    pub fn max_burst_length(&self) -> u32 {
        self.max_burst_length
    }

    pub fn set_max_burst_length(&mut self, value: u32) -> Result<(), TargetLoginPolicyError> {
        validate_data_length("MaxBurstLength", value as usize)?;
        validate_burst_pair(self.first_burst_length, value)?;
        self.max_burst_length = value;
        Ok(())
    }

    pub fn first_burst_length(&self) -> u32 {
        self.first_burst_length
    }

    pub fn set_first_burst_length(&mut self, value: u32) -> Result<(), TargetLoginPolicyError> {
        validate_data_length("FirstBurstLength", value as usize)?;
        validate_burst_pair(value, self.max_burst_length)?;
        self.first_burst_length = value;
        Ok(())
    }

    pub fn default_time2_wait(&self) -> u16 {
        self.default_time2_wait
    }

    pub fn set_default_time2_wait(&mut self, value: u16) -> Result<(), TargetLoginPolicyError> {
        validate_time("DefaultTime2Wait", value)?;
        self.default_time2_wait = value;
        Ok(())
    }

    pub fn default_time2_retain(&self) -> u16 {
        self.default_time2_retain
    }

    pub fn set_default_time2_retain(&mut self, value: u16) -> Result<(), TargetLoginPolicyError> {
        validate_time("DefaultTime2Retain", value)?;
        self.default_time2_retain = value;
        Ok(())
    }

    pub fn max_outstanding_r2t(&self) -> u16 {
        self.max_outstanding_r2t
    }

    pub fn set_max_outstanding_r2t(&mut self, value: u16) -> Result<(), TargetLoginPolicyError> {
        validate_range("MaxOutstandingR2T", usize::from(value), 1, u16::MAX.into())?;
        self.max_outstanding_r2t = value;
        Ok(())
    }

    pub fn data_pdu_in_order(&self) -> bool {
        self.data_pdu_in_order
    }

    pub fn set_data_pdu_in_order(&mut self, value: bool) {
        self.data_pdu_in_order = value;
    }

    pub fn data_sequence_in_order(&self) -> bool {
        self.data_sequence_in_order
    }

    pub fn set_data_sequence_in_order(&mut self, value: bool) {
        self.data_sequence_in_order = value;
    }

    pub fn error_recovery_level(&self) -> ErrorRecoveryLevel {
        self.error_recovery_level
    }

    pub fn set_error_recovery_level(&mut self, value: ErrorRecoveryLevel) {
        self.error_recovery_level = value;
    }

    pub fn task_reporting(&self) -> TaskReporting {
        self.task_reporting
    }

    pub fn set_task_reporting(&mut self, value: TaskReporting) {
        self.task_reporting = value;
    }

    pub const fn iscsi_protocol_level(&self) -> u8 {
        ISCSI_PROTOCOL_LEVEL
    }
}

fn validate_data_length(key: &'static str, value: usize) -> Result<(), TargetLoginPolicyError> {
    validate_range(
        key,
        value,
        MIN_MAX_RECV_DATA_SEGMENT_LENGTH,
        MAX_DATA_SEGMENT_LENGTH,
    )
}

fn validate_time(key: &'static str, value: u16) -> Result<(), TargetLoginPolicyError> {
    validate_range(key, usize::from(value), 0, MAX_TIME2_VALUE.into())
}

fn validate_range(
    key: &'static str,
    value: usize,
    min: usize,
    max: usize,
) -> Result<(), TargetLoginPolicyError> {
    if !(min..=max).contains(&value) {
        return Err(TargetLoginPolicyError::OutOfRange {
            key,
            value,
            min,
            max,
        });
    }
    Ok(())
}

fn validate_burst_pair(
    first_burst_length: u32,
    max_burst_length: u32,
) -> Result<(), TargetLoginPolicyError> {
    // FirstBurstLength는 MaxBurstLength를 넘을 수 없다 (RFC 7143 13.14절).
    if first_burst_length > max_burst_length {
        return Err(TargetLoginPolicyError::FirstBurstExceedsMaxBurst {
            first_burst_length,
            max_burst_length,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_rfc_7143() {
        let policy = TargetLoginPolicy::default();

        assert_eq!(policy.target_name(), None);
        assert_eq!(policy.target_portal_group_tag(), 1);
        assert!(policy.allows_normal_sessions());
        assert!(policy.allows_discovery_sessions());
        assert_eq!(policy.authentication(), AuthenticationPolicy::NoneOnly);
        assert_eq!(policy.header_digest(), DigestPolicy::NoneOnly);
        assert_eq!(policy.data_digest(), DigestPolicy::NoneOnly);
        assert_eq!(policy.max_connections(), 1);
        assert!(policy.initial_r2t());
        assert!(policy.immediate_data());
        assert_eq!(policy.max_recv_data_segment_length(), 8192);
        assert_eq!(policy.max_burst_length(), 262_144);
        assert_eq!(policy.first_burst_length(), 65_536);
        assert_eq!(policy.default_time2_wait(), 2);
        assert_eq!(policy.default_time2_retain(), 20);
        assert_eq!(policy.max_outstanding_r2t(), 1);
        assert!(policy.data_pdu_in_order());
        assert!(policy.data_sequence_in_order());
        assert_eq!(policy.error_recovery_level(), ErrorRecoveryLevel::Level0);
        assert_eq!(policy.task_reporting(), TaskReporting::Rfc3720);
        assert_eq!(policy.iscsi_protocol_level(), 1);
    }

    #[test]
    fn digest_policy_preserves_selection_order() {
        assert_eq!(
            DigestPolicy::PreferCrc32c.values(),
            &[DigestType::Crc32c, DigestType::None]
        );
        assert_eq!(
            DigestPolicy::PreferNone.values(),
            &[DigestType::None, DigestType::Crc32c]
        );
    }

    #[test]
    fn invalid_values_leave_policy_unchanged() {
        let mut policy = TargetLoginPolicy::default();
        let original = policy.clone();

        assert_eq!(
            policy.set_max_recv_data_segment_length(511),
            Err(TargetLoginPolicyError::OutOfRange {
                key: "MaxRecvDataSegmentLength",
                value: 511,
                min: 512,
                max: MAX_DATA_SEGMENT_LENGTH,
            })
        );
        assert_eq!(policy, original);

        assert_eq!(
            policy.set_default_time2_retain(MAX_TIME2_VALUE + 1),
            Err(TargetLoginPolicyError::OutOfRange {
                key: "DefaultTime2Retain",
                value: usize::from(MAX_TIME2_VALUE + 1),
                min: 0,
                max: usize::from(MAX_TIME2_VALUE),
            })
        );
        assert_eq!(policy, original);
    }

    #[test]
    fn first_burst_never_exceeds_max_burst() {
        let mut policy = TargetLoginPolicy::default();
        assert_eq!(
            policy.set_max_burst_length(DEFAULT_FIRST_BURST_LENGTH - 1),
            Err(TargetLoginPolicyError::FirstBurstExceedsMaxBurst {
                first_burst_length: DEFAULT_FIRST_BURST_LENGTH,
                max_burst_length: DEFAULT_FIRST_BURST_LENGTH - 1,
            })
        );
        assert_eq!(policy.max_burst_length(), DEFAULT_MAX_BURST_LENGTH);

        policy.set_first_burst_length(512).unwrap();
        policy.set_max_burst_length(512).unwrap();
        assert_eq!(policy.first_burst_length(), 512);
        assert_eq!(policy.max_burst_length(), 512);
    }

    #[test]
    fn accepts_numeric_boundaries() {
        let mut policy = TargetLoginPolicy::default();
        policy
            .set_max_recv_data_segment_length(MAX_DATA_SEGMENT_LENGTH)
            .unwrap();
        policy.set_first_burst_length(512).unwrap();
        policy
            .set_max_burst_length(MAX_DATA_SEGMENT_LENGTH as u32)
            .unwrap();
        policy.set_default_time2_wait(MAX_TIME2_VALUE).unwrap();
        policy.set_default_time2_retain(0).unwrap();
        policy.set_max_connections(u16::MAX).unwrap();
        policy.set_max_outstanding_r2t(u16::MAX).unwrap();
    }
}
