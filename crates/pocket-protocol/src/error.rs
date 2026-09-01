use std::io;

use pocket_core::{CodedError, ErrorCode};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameSection {
    Header,
    Payload,
}

impl std::fmt::Display for FrameSection {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Header => "header",
            Self::Payload => "payload",
        })
    }
}

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("protocol I/O failed: {0}")]
    Io(#[source] io::Error),
    #[error("unexpected EOF in frame {section}: received {received} of {expected} bytes")]
    UnexpectedEof {
        section: FrameSection,
        expected: usize,
        received: usize,
    },
    #[error("frame has {remaining} trailing bytes")]
    TrailingData { remaining: usize },
    #[error("invalid frame magic {actual:02x?}")]
    BadMagic { actual: [u8; 4] },
    #[error(
        "unsupported protocol version {actual_major}.{actual_minor}; expected {expected_major}.{expected_minor}"
    )]
    UnsupportedVersion {
        actual_major: u16,
        actual_minor: u16,
        expected_major: u16,
        expected_minor: u16,
    },
    #[error("unknown message kind {kind}")]
    UnknownKind { kind: u16 },
    #[error("unsupported frame flags {flags:#06x}")]
    UnsupportedFlags { flags: u16 },
    #[error("payload length {actual} exceeds hard cap {maximum}")]
    PayloadTooLarge { actual: usize, maximum: usize },
    #[error("frame sequence mismatch: expected {expected}, received {actual}")]
    SequenceMismatch { expected: u64, actual: u64 },
    #[error("frame sequence space is exhausted")]
    SequenceExhausted,
    #[error("malformed CBOR payload: {diagnostic}")]
    CborMalformed { diagnostic: String },
    #[error("CBOR payload is valid but not in Pocket's deterministic encoding")]
    CborNonCanonical,
    #[error("message field {field} has size {actual}; hard cap is {maximum}")]
    MessageLimitExceeded {
        field: &'static str,
        actual: usize,
        maximum: usize,
    },
    #[error("invalid message field {field}: {reason}")]
    InvalidMessage {
        field: &'static str,
        reason: &'static str,
    },
    #[error("message kind {kind} is invalid in state {state} for direction {direction}")]
    InvalidStateTransition {
        state: &'static str,
        direction: &'static str,
        kind: u16,
    },
    #[error("message kind mismatch: expected {expected}, received {actual}")]
    MessageKindMismatch { expected: u16, actual: u16 },
}

impl From<io::Error> for ProtocolError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl CodedError for ProtocolError {
    fn code(&self) -> ErrorCode {
        match self {
            Self::Io(_) => ErrorCode::ProtocolIo,
            Self::UnexpectedEof { .. } => ErrorCode::ProtocolUnexpectedEof,
            Self::TrailingData { .. } => ErrorCode::ProtocolTrailingData,
            Self::BadMagic { .. } => ErrorCode::ProtocolBadMagic,
            Self::UnsupportedVersion { .. } => ErrorCode::ProtocolUnsupportedVersion,
            Self::UnknownKind { .. } => ErrorCode::ProtocolUnknownKind,
            Self::UnsupportedFlags { .. } => ErrorCode::ProtocolUnsupportedFlags,
            Self::PayloadTooLarge { .. } => ErrorCode::ProtocolPayloadTooLarge,
            Self::SequenceMismatch { .. } | Self::SequenceExhausted => {
                ErrorCode::ProtocolSequenceMismatch
            }
            Self::CborMalformed { .. } => ErrorCode::ProtocolCborMalformed,
            Self::CborNonCanonical => ErrorCode::ProtocolCborNonCanonical,
            Self::MessageLimitExceeded { .. } => ErrorCode::ProtocolMessageLimitExceeded,
            Self::InvalidMessage { .. } | Self::MessageKindMismatch { .. } => {
                ErrorCode::ProtocolInvalidMessage
            }
            Self::InvalidStateTransition { .. } => ErrorCode::ProtocolInvalidStateTransition,
        }
    }
}
