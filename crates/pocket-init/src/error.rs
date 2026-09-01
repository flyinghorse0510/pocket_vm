use std::io;

use nix::errno::Errno;
use pocket_core::{CodedError, ErrorCode};
use pocket_protocol::{ErrorMessage, MAX_DIAGNOSTIC_LENGTH, ProtocolError};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum InitError {
    #[error("{stage}: {diagnostic}")]
    Contract {
        stage: &'static str,
        diagnostic: String,
    },
    #[error("{stage}: unsupported operation: {diagnostic}")]
    Unsupported {
        stage: &'static str,
        diagnostic: String,
    },
    #[error("{stage}: {diagnostic}")]
    Child {
        stage: &'static str,
        errno: Option<i32>,
        diagnostic: String,
    },
    #[error("{stage}: {source}")]
    Io {
        stage: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("{stage}: {source}")]
    Syscall {
        stage: &'static str,
        #[source]
        source: Errno,
    },
    #[error("{stage}: {source}")]
    Protocol {
        stage: &'static str,
        #[source]
        source: ProtocolError,
    },
}

impl InitError {
    #[must_use]
    pub fn contract(stage: &'static str, diagnostic: impl Into<String>) -> Self {
        Self::Contract {
            stage,
            diagnostic: diagnostic.into(),
        }
    }

    #[must_use]
    pub fn unsupported(stage: &'static str, diagnostic: impl Into<String>) -> Self {
        Self::Unsupported {
            stage,
            diagnostic: diagnostic.into(),
        }
    }

    #[must_use]
    pub fn io(stage: &'static str, source: io::Error) -> Self {
        Self::Io { stage, source }
    }

    #[must_use]
    pub fn child(stage: &'static str, errno: Option<i32>, diagnostic: impl Into<String>) -> Self {
        Self::Child {
            stage,
            errno,
            diagnostic: diagnostic.into(),
        }
    }

    #[must_use]
    pub fn syscall(stage: &'static str, source: Errno) -> Self {
        Self::Syscall { stage, source }
    }

    #[must_use]
    pub fn protocol(stage: &'static str, source: ProtocolError) -> Self {
        Self::Protocol { stage, source }
    }

    #[must_use]
    pub const fn stage(&self) -> &'static str {
        match self {
            Self::Contract { stage, .. }
            | Self::Unsupported { stage, .. }
            | Self::Child { stage, .. }
            | Self::Io { stage, .. }
            | Self::Syscall { stage, .. }
            | Self::Protocol { stage, .. } => stage,
        }
    }

    #[must_use]
    pub fn stable_code(&self) -> ErrorCode {
        match self {
            Self::Protocol { source, .. } => source.code(),
            Self::Contract { .. } | Self::Unsupported { .. } => ErrorCode::ProtocolInvalidMessage,
            Self::Child { .. } | Self::Io { .. } | Self::Syscall { .. } => ErrorCode::ProtocolIo,
        }
    }

    #[must_use]
    pub fn errno(&self) -> Option<i32> {
        match self {
            Self::Io { source, .. } => source.raw_os_error().filter(|value| *value > 0),
            Self::Syscall { source, .. } => Some(*source as i32),
            Self::Child { errno, .. } => *errno,
            Self::Contract { .. } | Self::Unsupported { .. } | Self::Protocol { .. } => None,
        }
    }

    #[must_use]
    pub fn to_protocol_message(&self) -> ErrorMessage {
        let diagnostic = truncate_utf8(&self.to_string(), MAX_DIAGNOSTIC_LENGTH);
        ErrorMessage::new(self.stage(), self.stable_code(), self.errno(), diagnostic)
    }
}

fn truncate_utf8(value: &str, maximum: usize) -> String {
    if value.len() <= maximum {
        return value.to_owned();
    }
    let mut boundary = maximum;
    while !value.is_char_boundary(boundary) {
        boundary -= 1;
    }
    value[..boundary].to_owned()
}

#[cfg(test)]
mod tests {
    use pocket_protocol::ValidateMessage;

    use super::InitError;

    #[test]
    fn protocol_error_diagnostic_is_bounded_on_utf8_boundary() {
        let error = InitError::contract("contract", "é".repeat(9000));
        let message = error.to_protocol_message();
        assert!(message.diagnostic.len() <= pocket_protocol::MAX_DIAGNOSTIC_LENGTH);
        assert!(message.validate().is_ok());
    }
}
