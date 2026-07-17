// pdu/src/error.rs

#[derive(Debug, thiserror::Error)]
pub enum PduError {
    #[error("unknown opcode: 0x{0:02x}")]
    UnknownOpcode(u8),

    #[error("invalid login stage: {0}")]
    InvalidLoginStage(u8),

    #[error("data segment too short for {pdu}: need {need}, got {got}")]
    ShortData {
        pdu: &'static str,
        need: usize,
        got: usize,
    },

    #[error("malformed PDU: {0}")]
    Malformed(String),
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FrameError {
    #[error("AHS length {len} is not aligned to a 4-byte word")]
    InvalidAhsLength { len: usize },

    #[error("AHS length {len} exceeds maximum {max}")]
    AhsTooLarge { len: usize, max: usize },

    #[error("data segment length {len} exceeds maximum {max}")]
    DataSegmentTooLarge { len: usize, max: usize },

    #[error("{segment} length in BHS is {declared}, but the frame contains {actual}")]
    LengthMismatch {
        segment: &'static str,
        declared: usize,
        actual: usize,
    },

    #[error("frame length overflow")]
    LengthOverflow,

    #[error("header digest mismatch")]
    HeaderDigestMismatch,

    #[error("data digest mismatch")]
    DataDigestMismatch,
}

#[derive(Debug, thiserror::Error)]
pub enum CodecError {
    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Frame(#[from] FrameError),

    #[error(transparent)]
    Pdu(#[from] PduError),
}
