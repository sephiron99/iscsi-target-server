//! RFC 1982 방식의 32-bit iSCSI sequence number 산술.

use std::cmp::Ordering;
use std::collections::HashSet;

const HALF_RANGE: u32 = 1 << 31;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SerialNumber32(u32);

impl SerialNumber32 {
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    pub const fn value(self) -> u32 {
        self.0
    }

    pub const fn wrapping_add(self, increment: u32) -> Self {
        Self(self.0.wrapping_add(increment))
    }

    /// 정확히 반 바퀴 떨어진 값은 RFC 1982에서 순서가 정의되지 않는다.
    pub fn serial_cmp(self, other: Self) -> Option<Ordering> {
        if self == other {
            return Some(Ordering::Equal);
        }
        let forward = other.0.wrapping_sub(self.0);
        if forward == HALF_RANGE {
            None
        } else if forward < HALF_RANGE {
            Some(Ordering::Less)
        } else {
            Some(Ordering::Greater)
        }
    }

    pub fn is_between_inclusive(self, start: Self, end: Self) -> bool {
        matches!(
            self.serial_cmp(start),
            Some(Ordering::Equal | Ordering::Greater)
        ) && matches!(self.serial_cmp(end), Some(Ordering::Equal | Ordering::Less))
    }
}

#[derive(Debug, Clone)]
pub struct SequenceState {
    exp_cmd_sn: SerialNumber32,
    max_cmd_sn: SerialNumber32,
    next_stat_sn: SerialNumber32,
    acknowledged_stat_sn: SerialNumber32,
    command_window: u32,
    received_out_of_order: HashSet<u32>,
}

impl SequenceState {
    pub fn new(
        initial_cmd_sn: u32,
        initial_stat_sn: u32,
        command_window: u32,
    ) -> Result<Self, SequenceError> {
        if command_window == 0 || command_window >= HALF_RANGE {
            return Err(SequenceError::InvalidWindow(command_window));
        }
        let exp_cmd_sn = SerialNumber32::new(initial_cmd_sn);
        Ok(Self {
            exp_cmd_sn,
            max_cmd_sn: exp_cmd_sn.wrapping_add(command_window - 1),
            next_stat_sn: SerialNumber32::new(initial_stat_sn),
            acknowledged_stat_sn: SerialNumber32::new(initial_stat_sn),
            command_window,
            received_out_of_order: HashSet::new(),
        })
    }

    pub fn exp_cmd_sn(&self) -> u32 {
        self.exp_cmd_sn.value()
    }

    pub fn max_cmd_sn(&self) -> u32 {
        self.max_cmd_sn.value()
    }

    pub fn accept_cmd_sn(&mut self, cmd_sn: u32) -> Result<(), SequenceError> {
        self.validate_cmd_sn(cmd_sn)?;
        if !self.received_out_of_order.insert(cmd_sn) {
            return Err(SequenceError::DuplicateCmdSn(cmd_sn));
        }
        while self.received_out_of_order.remove(&self.exp_cmd_sn.value()) {
            self.exp_cmd_sn = self.exp_cmd_sn.wrapping_add(1);
            self.max_cmd_sn = self.max_cmd_sn.wrapping_add(1);
        }
        Ok(())
    }

    pub fn validate_cmd_sn(&self, cmd_sn: u32) -> Result<(), SequenceError> {
        let candidate = SerialNumber32::new(cmd_sn);
        if !candidate.is_between_inclusive(self.exp_cmd_sn, self.max_cmd_sn) {
            return Err(SequenceError::CmdSnOutsideWindow {
                cmd_sn,
                exp_cmd_sn: self.exp_cmd_sn.value(),
                max_cmd_sn: self.max_cmd_sn.value(),
            });
        }
        Ok(())
    }

    pub fn acknowledge_exp_stat_sn(&mut self, exp_stat_sn: u32) -> Result<(), SequenceError> {
        let candidate = SerialNumber32::new(exp_stat_sn);
        if !candidate.is_between_inclusive(self.acknowledged_stat_sn, self.next_stat_sn) {
            return Err(SequenceError::InvalidExpStatSn {
                exp_stat_sn,
                acknowledged: self.acknowledged_stat_sn.value(),
                next_stat_sn: self.next_stat_sn.value(),
            });
        }
        self.acknowledged_stat_sn = candidate;
        Ok(())
    }

    pub fn allocate_stat_sn(&mut self) -> u32 {
        let allocated = self.next_stat_sn;
        self.next_stat_sn = self.next_stat_sn.wrapping_add(1);
        allocated.value()
    }

    pub fn command_window(&self) -> u32 {
        self.command_window
    }
}

#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum SequenceError {
    #[error("command window {0} is outside 1..2^31")]
    InvalidWindow(u32),
    #[error("CmdSN {cmd_sn} is outside [{exp_cmd_sn}, {max_cmd_sn}]")]
    CmdSnOutsideWindow {
        cmd_sn: u32,
        exp_cmd_sn: u32,
        max_cmd_sn: u32,
    },
    #[error("CmdSN {0} was received more than once")]
    DuplicateCmdSn(u32),
    #[error("ExpStatSN {exp_stat_sn} is outside [{acknowledged}, {next_stat_sn}]")]
    InvalidExpStatSn {
        exp_stat_sn: u32,
        acknowledged: u32,
        next_stat_sn: u32,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serial_comparison_wraps_and_rejects_ambiguous_half_range() {
        assert_eq!(
            SerialNumber32::new(0).serial_cmp(SerialNumber32::new(u32::MAX)),
            Some(Ordering::Greater)
        );
        assert_eq!(
            SerialNumber32::new(u32::MAX).serial_cmp(SerialNumber32::new(0)),
            Some(Ordering::Less)
        );
        assert_eq!(
            SerialNumber32::new(0).serial_cmp(SerialNumber32::new(HALF_RANGE)),
            None
        );
    }

    #[test]
    fn command_window_accepts_out_of_order_and_advances_across_wrap() {
        let mut state = SequenceState::new(u32::MAX - 1, 9, 4).unwrap();
        assert_eq!((state.exp_cmd_sn(), state.max_cmd_sn()), (u32::MAX - 1, 1));
        state.accept_cmd_sn(0).unwrap();
        assert_eq!(state.exp_cmd_sn(), u32::MAX - 1);
        state.accept_cmd_sn(u32::MAX - 1).unwrap();
        assert_eq!(state.exp_cmd_sn(), u32::MAX);
        state.accept_cmd_sn(u32::MAX).unwrap();
        assert_eq!((state.exp_cmd_sn(), state.max_cmd_sn()), (1, 4));
        assert_eq!(
            state.accept_cmd_sn(0),
            Err(SequenceError::CmdSnOutsideWindow {
                cmd_sn: 0,
                exp_cmd_sn: 1,
                max_cmd_sn: 4
            })
        );
    }

    #[test]
    fn status_acknowledgement_cannot_move_back_or_past_unsent_status() {
        let mut state = SequenceState::new(1, u32::MAX, 1).unwrap();
        assert_eq!(state.allocate_stat_sn(), u32::MAX);
        assert_eq!(state.allocate_stat_sn(), 0);
        state.acknowledge_exp_stat_sn(1).unwrap();
        assert!(matches!(
            state.acknowledge_exp_stat_sn(u32::MAX),
            Err(SequenceError::InvalidExpStatSn { .. })
        ));
        assert!(matches!(
            state.acknowledge_exp_stat_sn(2),
            Err(SequenceError::InvalidExpStatSn { .. })
        ));
    }
}
