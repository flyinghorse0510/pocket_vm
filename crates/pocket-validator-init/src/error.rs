use std::io;

use nix::errno::Errno;
use pocket_core::{CodedError, ErrorCode};
use pocket_protocol::{ErrorMessage, MAX_DIAGNOSTIC_LENGTH, ProtocolError};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ValidatorError {
    #[error("{stage}: validation contract violation: {diagnostic}")]
    Contract {
        stage: &'static str,
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
    #[error("{stage}: {diagnostic}")]
    Failure {
        stage: &'static str,
        code: ErrorCode,
        errno: Option<i32>,
        diagnostic: String,
    },
}

impl ValidatorError {
    #[must_use]
    pub fn contract(stage: &'static str, diagnostic: impl Into<String>) -> Self {
        Self::Contract {
            stage,
            diagnostic: diagnostic.into(),
        }
    }

    #[must_use]
    pub fn io(stage: &'static str, source: io::Error) -> Self {
        Self::Io { stage, source }
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
    pub fn failure(
        stage: &'static str,
        code: ErrorCode,
        errno: Option<i32>,
        diagnostic: impl Into<String>,
    ) -> Self {
        Self::Failure {
            stage,
            code,
            errno,
            diagnostic: diagnostic.into(),
        }
    }

    #[must_use]
    pub fn reclassify(self, code: ErrorCode) -> Self {
        Self::failure(self.stage(), code, self.errno(), self.to_string())
    }

    #[must_use]
    pub const fn stage(&self) -> &'static str {
        match self {
            Self::Contract { stage, .. }
            | Self::Io { stage, .. }
            | Self::Syscall { stage, .. }
            | Self::Protocol { stage, .. }
            | Self::Failure { stage, .. } => stage,
        }
    }

    #[must_use]
    pub fn stable_code(&self) -> ErrorCode {
        match self {
            Self::Contract { .. } => ErrorCode::ValidatorBootContract,
            Self::Io { .. } | Self::Syscall { .. } => ErrorCode::ValidatorFilesystem,
            Self::Protocol { source, .. } => match source.code() {
                ErrorCode::ProtocolIo => ErrorCode::ValidatorProtocol,
                code => code,
            },
            Self::Failure { code, .. } => *code,
        }
    }

    #[must_use]
    pub fn errno(&self) -> Option<i32> {
        match self {
            Self::Io { source, .. } => source.raw_os_error().filter(|value| *value > 0),
            Self::Syscall { source, .. } => Some(*source as i32),
            Self::Failure { errno, .. } => *errno,
            Self::Contract { .. } | Self::Protocol { .. } => None,
        }
    }

    #[must_use]
    pub fn to_protocol_message(&self) -> ErrorMessage {
        let mut diagnostic = self.to_string();
        if diagnostic.len() > MAX_DIAGNOSTIC_LENGTH {
            let mut boundary = MAX_DIAGNOSTIC_LENGTH;
            while !diagnostic.is_char_boundary(boundary) {
                boundary -= 1;
            }
            diagnostic.truncate(boundary);
        }
        ErrorMessage::new(self.stage(), self.stable_code(), self.errno(), diagnostic)
    }
}

#[cfg(test)]
mod tests {
    use pocket_protocol::ValidateMessage;

    use super::ValidatorError;

    #[test]
    fn protocol_diagnostic_is_bounded_at_utf8_boundary() {
        let error = ValidatorError::failure(
            "manifest",
            pocket_core::ErrorCode::ValidatorManifest,
            None,
            "é".repeat(9000),
        );
        let message = error.to_protocol_message();
        assert!(message.diagnostic.len() <= pocket_protocol::MAX_DIAGNOSTIC_LENGTH);
        assert!(message.validate().is_ok());
    }
}
