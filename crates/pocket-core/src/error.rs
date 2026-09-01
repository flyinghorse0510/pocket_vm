use std::fmt;

use thiserror::Error;

/// A machine-readable error code whose numeric value and symbolic name are
/// part of Pocket's compatibility contract.
///
/// Values are grouped by subsystem. Existing values must never be reused for
/// a different meaning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u16)]
pub enum ErrorCode {
    PathNotAbsolute = 0x0101,
    PathNotUtf8 = 0x0102,
    PathContainsWhitespace = 0x0103,
    PathContainsReservedCharacter = 0x0104,
    PathNotNormalized = 0x0105,
    PathTooBroad = 0x0106,
    PathTooLong = 0x0107,

    InvalidCpuProfile = 0x0201,
    InvalidCpuRequest = 0x0202,
    CpuExceedsProfileMaximum = 0x0203,
    CpuUnavailable = 0x0204,
    CpuCountMismatch = 0x0205,

    InvalidMemory = 0x0301,
    MemoryOverflow = 0x0302,
    InvalidMemoryPolicy = 0x0303,
    MemoryBelowMinimum = 0x0304,
    MemoryAboveMaximum = 0x0305,
    MemoryNotAligned = 0x0306,

    ProtocolIo = 0x1001,
    ProtocolUnexpectedEof = 0x1002,
    ProtocolTrailingData = 0x1003,
    ProtocolBadMagic = 0x1004,
    ProtocolUnsupportedVersion = 0x1005,
    ProtocolUnknownKind = 0x1006,
    ProtocolUnsupportedFlags = 0x1007,
    ProtocolPayloadTooLarge = 0x1008,
    ProtocolSequenceMismatch = 0x1009,
    ProtocolCborMalformed = 0x100a,
    ProtocolCborNonCanonical = 0x100b,
    ProtocolMessageLimitExceeded = 0x100c,
    ProtocolInvalidMessage = 0x100d,
    ProtocolInvalidStateTransition = 0x100e,

    BuilderBootContract = 0x2001,
    BuilderUnsupported = 0x2002,
    BuilderMount = 0x2003,
    BuilderInputMismatch = 0x2004,
    BuilderTargetDirty = 0x2005,
    BuilderToolMismatch = 0x2006,
    BuilderToolFailed = 0x2007,
    BuilderMarker = 0x2008,
    BuilderManifest = 0x2009,
    BuilderSync = 0x200a,
    BuilderUnmount = 0x200b,
    BuilderProtocol = 0x200c,

    ValidatorBootContract = 0x2101,
    ValidatorMount = 0x2102,
    ValidatorFilesystem = 0x2103,
    ValidatorManifest = 0x2104,
    ValidatorMarker = 0x2105,
    ValidatorAccount = 0x2106,
    ValidatorProtocol = 0x2107,
    ValidatorUnmount = 0x2108,
}

impl ErrorCode {
    /// Every code known to this protocol revision, in numeric order.
    pub const ALL: [Self; 52] = [
        Self::PathNotAbsolute,
        Self::PathNotUtf8,
        Self::PathContainsWhitespace,
        Self::PathContainsReservedCharacter,
        Self::PathNotNormalized,
        Self::PathTooBroad,
        Self::PathTooLong,
        Self::InvalidCpuProfile,
        Self::InvalidCpuRequest,
        Self::CpuExceedsProfileMaximum,
        Self::CpuUnavailable,
        Self::CpuCountMismatch,
        Self::InvalidMemory,
        Self::MemoryOverflow,
        Self::InvalidMemoryPolicy,
        Self::MemoryBelowMinimum,
        Self::MemoryAboveMaximum,
        Self::MemoryNotAligned,
        Self::ProtocolIo,
        Self::ProtocolUnexpectedEof,
        Self::ProtocolTrailingData,
        Self::ProtocolBadMagic,
        Self::ProtocolUnsupportedVersion,
        Self::ProtocolUnknownKind,
        Self::ProtocolUnsupportedFlags,
        Self::ProtocolPayloadTooLarge,
        Self::ProtocolSequenceMismatch,
        Self::ProtocolCborMalformed,
        Self::ProtocolCborNonCanonical,
        Self::ProtocolMessageLimitExceeded,
        Self::ProtocolInvalidMessage,
        Self::ProtocolInvalidStateTransition,
        Self::BuilderBootContract,
        Self::BuilderUnsupported,
        Self::BuilderMount,
        Self::BuilderInputMismatch,
        Self::BuilderTargetDirty,
        Self::BuilderToolMismatch,
        Self::BuilderToolFailed,
        Self::BuilderMarker,
        Self::BuilderManifest,
        Self::BuilderSync,
        Self::BuilderUnmount,
        Self::BuilderProtocol,
        Self::ValidatorBootContract,
        Self::ValidatorMount,
        Self::ValidatorFilesystem,
        Self::ValidatorManifest,
        Self::ValidatorMarker,
        Self::ValidatorAccount,
        Self::ValidatorProtocol,
        Self::ValidatorUnmount,
    ];

    /// Return the stable external spelling of this code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PathNotAbsolute => "E_PATH_NOT_ABSOLUTE",
            Self::PathNotUtf8 => "E_PATH_NOT_UTF8",
            Self::PathContainsWhitespace => "E_PATH_CONTAINS_WHITESPACE",
            Self::PathContainsReservedCharacter => "E_PATH_CONTAINS_RESERVED_CHARACTER",
            Self::PathNotNormalized => "E_PATH_NOT_NORMALIZED",
            Self::PathTooBroad => "E_PATH_TOO_BROAD",
            Self::PathTooLong => "E_PATH_TOO_LONG",
            Self::InvalidCpuProfile => "E_CPU_PROFILE_INVALID",
            Self::InvalidCpuRequest => "E_CPU_REQUEST_INVALID",
            Self::CpuExceedsProfileMaximum => "E_CPU_PROFILE_MAXIMUM",
            Self::CpuUnavailable => "E_CPU_UNAVAILABLE",
            Self::CpuCountMismatch => "E_CPU_COUNT_MISMATCH",
            Self::InvalidMemory => "E_MEMORY_INVALID",
            Self::MemoryOverflow => "E_MEMORY_OVERFLOW",
            Self::InvalidMemoryPolicy => "E_MEMORY_POLICY_INVALID",
            Self::MemoryBelowMinimum => "E_MEMORY_BELOW_MINIMUM",
            Self::MemoryAboveMaximum => "E_MEMORY_ABOVE_MAXIMUM",
            Self::MemoryNotAligned => "E_MEMORY_NOT_ALIGNED",
            Self::ProtocolIo => "E_PROTOCOL_IO",
            Self::ProtocolUnexpectedEof => "E_PROTOCOL_UNEXPECTED_EOF",
            Self::ProtocolTrailingData => "E_PROTOCOL_TRAILING_DATA",
            Self::ProtocolBadMagic => "E_PROTOCOL_BAD_MAGIC",
            Self::ProtocolUnsupportedVersion => "E_PROTOCOL_VERSION",
            Self::ProtocolUnknownKind => "E_PROTOCOL_KIND",
            Self::ProtocolUnsupportedFlags => "E_PROTOCOL_FLAGS",
            Self::ProtocolPayloadTooLarge => "E_PROTOCOL_PAYLOAD_TOO_LARGE",
            Self::ProtocolSequenceMismatch => "E_PROTOCOL_SEQUENCE",
            Self::ProtocolCborMalformed => "E_PROTOCOL_CBOR_MALFORMED",
            Self::ProtocolCborNonCanonical => "E_PROTOCOL_CBOR_NON_CANONICAL",
            Self::ProtocolMessageLimitExceeded => "E_PROTOCOL_MESSAGE_LIMIT",
            Self::ProtocolInvalidMessage => "E_PROTOCOL_MESSAGE_INVALID",
            Self::ProtocolInvalidStateTransition => "E_PROTOCOL_STATE",
            Self::BuilderBootContract => "E_BUILDER_BOOT_CONTRACT",
            Self::BuilderUnsupported => "E_BUILDER_UNSUPPORTED",
            Self::BuilderMount => "E_BUILDER_MOUNT",
            Self::BuilderInputMismatch => "E_BUILDER_INPUT_MISMATCH",
            Self::BuilderTargetDirty => "E_BUILDER_TARGET_DIRTY",
            Self::BuilderToolMismatch => "E_BUILDER_TOOL_MISMATCH",
            Self::BuilderToolFailed => "E_BUILDER_TOOL_FAILED",
            Self::BuilderMarker => "E_BUILDER_MARKER",
            Self::BuilderManifest => "E_BUILDER_MANIFEST",
            Self::BuilderSync => "E_BUILDER_SYNC",
            Self::BuilderUnmount => "E_BUILDER_UNMOUNT",
            Self::BuilderProtocol => "E_BUILDER_PROTOCOL",
            Self::ValidatorBootContract => "E_VALIDATOR_BOOT_CONTRACT",
            Self::ValidatorMount => "E_VALIDATOR_MOUNT",
            Self::ValidatorFilesystem => "E_VALIDATOR_FILESYSTEM",
            Self::ValidatorManifest => "E_VALIDATOR_MANIFEST",
            Self::ValidatorMarker => "E_VALIDATOR_MARKER",
            Self::ValidatorAccount => "E_VALIDATOR_ACCOUNT",
            Self::ValidatorProtocol => "E_VALIDATOR_PROTOCOL",
            Self::ValidatorUnmount => "E_VALIDATOR_UNMOUNT",
        }
    }

    /// Convert the stable numeric representation back into a typed code.
    pub const fn from_u16(value: u16) -> Result<Self, UnknownErrorCode> {
        let code = match value {
            0x0101 => Self::PathNotAbsolute,
            0x0102 => Self::PathNotUtf8,
            0x0103 => Self::PathContainsWhitespace,
            0x0104 => Self::PathContainsReservedCharacter,
            0x0105 => Self::PathNotNormalized,
            0x0106 => Self::PathTooBroad,
            0x0107 => Self::PathTooLong,
            0x0201 => Self::InvalidCpuProfile,
            0x0202 => Self::InvalidCpuRequest,
            0x0203 => Self::CpuExceedsProfileMaximum,
            0x0204 => Self::CpuUnavailable,
            0x0205 => Self::CpuCountMismatch,
            0x0301 => Self::InvalidMemory,
            0x0302 => Self::MemoryOverflow,
            0x0303 => Self::InvalidMemoryPolicy,
            0x0304 => Self::MemoryBelowMinimum,
            0x0305 => Self::MemoryAboveMaximum,
            0x0306 => Self::MemoryNotAligned,
            0x1001 => Self::ProtocolIo,
            0x1002 => Self::ProtocolUnexpectedEof,
            0x1003 => Self::ProtocolTrailingData,
            0x1004 => Self::ProtocolBadMagic,
            0x1005 => Self::ProtocolUnsupportedVersion,
            0x1006 => Self::ProtocolUnknownKind,
            0x1007 => Self::ProtocolUnsupportedFlags,
            0x1008 => Self::ProtocolPayloadTooLarge,
            0x1009 => Self::ProtocolSequenceMismatch,
            0x100a => Self::ProtocolCborMalformed,
            0x100b => Self::ProtocolCborNonCanonical,
            0x100c => Self::ProtocolMessageLimitExceeded,
            0x100d => Self::ProtocolInvalidMessage,
            0x100e => Self::ProtocolInvalidStateTransition,
            0x2001 => Self::BuilderBootContract,
            0x2002 => Self::BuilderUnsupported,
            0x2003 => Self::BuilderMount,
            0x2004 => Self::BuilderInputMismatch,
            0x2005 => Self::BuilderTargetDirty,
            0x2006 => Self::BuilderToolMismatch,
            0x2007 => Self::BuilderToolFailed,
            0x2008 => Self::BuilderMarker,
            0x2009 => Self::BuilderManifest,
            0x200a => Self::BuilderSync,
            0x200b => Self::BuilderUnmount,
            0x200c => Self::BuilderProtocol,
            0x2101 => Self::ValidatorBootContract,
            0x2102 => Self::ValidatorMount,
            0x2103 => Self::ValidatorFilesystem,
            0x2104 => Self::ValidatorManifest,
            0x2105 => Self::ValidatorMarker,
            0x2106 => Self::ValidatorAccount,
            0x2107 => Self::ValidatorProtocol,
            0x2108 => Self::ValidatorUnmount,
            _ => return Err(UnknownErrorCode(value)),
        };
        Ok(code)
    }
}

impl TryFrom<u16> for ErrorCode {
    type Error = UnknownErrorCode;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        Self::from_u16(value)
    }
}

impl From<ErrorCode> for u16 {
    fn from(code: ErrorCode) -> Self {
        code as Self
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Implemented by errors that expose a stable machine-readable code.
pub trait CodedError {
    fn code(&self) -> ErrorCode;
}

/// Returned when a peer supplies a numeric error code this build does not
/// understand.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("unknown Pocket error code {0:#06x}")]
pub struct UnknownErrorCode(pub u16);

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::ErrorCode;

    #[test]
    fn stable_codes_round_trip_and_have_external_names() {
        let mut numbers = BTreeSet::new();
        let mut names = BTreeSet::new();
        for code in ErrorCode::ALL {
            assert_eq!(ErrorCode::from_u16(code as u16), Ok(code));
            assert!(code.as_str().starts_with("E_"));
            assert!(numbers.insert(u16::from(code)), "duplicate numeric code");
            assert!(names.insert(code.as_str()), "duplicate symbolic code");
        }
        assert!(ErrorCode::from_u16(0xffff).is_err());
    }
}
