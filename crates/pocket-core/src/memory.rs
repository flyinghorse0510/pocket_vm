use std::{fmt, str::FromStr};

use thiserror::Error;

use crate::{CodedError, ErrorCode};

const KIB: u64 = 1024;
const MIB: u64 = 1024 * KIB;
const GIB: u64 = 1024 * MIB;
const TIB: u64 = 1024 * GIB;

/// A nonzero memory quantity parsed with deterministic binary suffixes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ParsedMemory(u64);

impl ParsedMemory {
    pub fn from_bytes(bytes: u64) -> Result<Self, MemoryParseError> {
        if bytes == 0 {
            return Err(MemoryParseError::Zero);
        }
        Ok(Self(bytes))
    }

    #[must_use]
    pub const fn bytes(self) -> u64 {
        self.0
    }
}

impl FromStr for ParsedMemory {
    type Err = MemoryParseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        if input.is_empty() {
            return Err(MemoryParseError::Empty);
        }
        if input.chars().any(char::is_whitespace) {
            return Err(MemoryParseError::Whitespace);
        }

        let digits_len = input.bytes().take_while(u8::is_ascii_digit).count();
        if digits_len == 0 {
            return Err(MemoryParseError::InvalidNumber);
        }
        let (digits, suffix) = input.split_at(digits_len);
        let value = digits
            .parse::<u64>()
            .map_err(|_| MemoryParseError::Overflow)?;
        if value == 0 {
            return Err(MemoryParseError::Zero);
        }

        let multiplier = match suffix.to_ascii_lowercase().as_str() {
            "" | "b" => 1,
            "k" | "kb" | "kib" => KIB,
            "m" | "mb" | "mib" => MIB,
            "g" | "gb" | "gib" => GIB,
            "t" | "tb" | "tib" => TIB,
            _ => {
                return Err(MemoryParseError::InvalidSuffix {
                    suffix: suffix.to_owned(),
                });
            }
        };
        let bytes = value
            .checked_mul(multiplier)
            .ok_or(MemoryParseError::Overflow)?;
        Self::from_bytes(bytes)
    }
}

impl fmt::Display for ParsedMemory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}B", self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum MemoryParseError {
    #[error("memory value is empty")]
    Empty,
    #[error("memory value contains whitespace")]
    Whitespace,
    #[error("memory value must begin with an unsigned decimal integer")]
    InvalidNumber,
    #[error("unsupported memory suffix {suffix:?}")]
    InvalidSuffix { suffix: String },
    #[error("memory value must be greater than zero")]
    Zero,
    #[error("memory value overflows 64-bit bytes")]
    Overflow,
}

impl CodedError for MemoryParseError {
    fn code(&self) -> ErrorCode {
        match self {
            Self::Overflow => ErrorCode::MemoryOverflow,
            Self::Empty
            | Self::Whitespace
            | Self::InvalidNumber
            | Self::InvalidSuffix { .. }
            | Self::Zero => ErrorCode::InvalidMemory,
        }
    }
}

/// Profile- or operation-specific accepted memory range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryPolicy {
    minimum: u64,
    maximum: u64,
    alignment: u64,
}

impl MemoryPolicy {
    pub fn new(minimum: u64, maximum: u64, alignment: u64) -> Result<Self, MemoryValidationError> {
        if minimum == 0
            || maximum < minimum
            || alignment == 0
            || !alignment.is_power_of_two()
            || !minimum.is_multiple_of(alignment)
            || !maximum.is_multiple_of(alignment)
        {
            return Err(MemoryValidationError::InvalidPolicy {
                minimum,
                maximum,
                alignment,
            });
        }
        Ok(Self {
            minimum,
            maximum,
            alignment,
        })
    }

    #[must_use]
    pub const fn minimum(self) -> u64 {
        self.minimum
    }

    #[must_use]
    pub const fn maximum(self) -> u64 {
        self.maximum
    }

    #[must_use]
    pub const fn alignment(self) -> u64 {
        self.alignment
    }

    pub fn validate(self, memory: ParsedMemory) -> Result<ValidatedMemory, MemoryValidationError> {
        let bytes = memory.bytes();
        if bytes < self.minimum {
            return Err(MemoryValidationError::BelowMinimum {
                actual: bytes,
                minimum: self.minimum,
            });
        }
        if bytes > self.maximum {
            return Err(MemoryValidationError::AboveMaximum {
                actual: bytes,
                maximum: self.maximum,
            });
        }
        if !bytes.is_multiple_of(self.alignment) {
            return Err(MemoryValidationError::NotAligned {
                actual: bytes,
                alignment: self.alignment,
            });
        }
        Ok(ValidatedMemory(memory))
    }

    pub fn parse_and_validate(self, input: &str) -> Result<ValidatedMemory, MemoryInputError> {
        let parsed = input.parse::<ParsedMemory>()?;
        Ok(self.validate(parsed)?)
    }
}

/// A parsed memory value accepted by a specific policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidatedMemory(ParsedMemory);

impl ValidatedMemory {
    #[must_use]
    pub const fn bytes(self) -> u64 {
        self.0.bytes()
    }

    /// Render a deterministic UML `mem=` value using the largest exact binary
    /// unit supported by the kernel command-line grammar.
    #[must_use]
    pub fn uml_value(self) -> String {
        let bytes = self.bytes();
        for (unit, suffix) in [(GIB, "G"), (MIB, "M"), (KIB, "K")] {
            if bytes.is_multiple_of(unit) {
                return format!("{}{suffix}", bytes / unit);
            }
        }
        bytes.to_string()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum MemoryValidationError {
    #[error("invalid memory policy: minimum={minimum}, maximum={maximum}, alignment={alignment}")]
    InvalidPolicy {
        minimum: u64,
        maximum: u64,
        alignment: u64,
    },
    #[error("memory {actual} is below minimum {minimum}")]
    BelowMinimum { actual: u64, minimum: u64 },
    #[error("memory {actual} is above maximum {maximum}")]
    AboveMaximum { actual: u64, maximum: u64 },
    #[error("memory {actual} is not aligned to {alignment}")]
    NotAligned { actual: u64, alignment: u64 },
}

impl CodedError for MemoryValidationError {
    fn code(&self) -> ErrorCode {
        match self {
            Self::InvalidPolicy { .. } => ErrorCode::InvalidMemoryPolicy,
            Self::BelowMinimum { .. } => ErrorCode::MemoryBelowMinimum,
            Self::AboveMaximum { .. } => ErrorCode::MemoryAboveMaximum,
            Self::NotAligned { .. } => ErrorCode::MemoryNotAligned,
        }
    }
}

#[derive(Debug, Error)]
pub enum MemoryInputError {
    #[error(transparent)]
    Parse(#[from] MemoryParseError),
    #[error(transparent)]
    Validation(#[from] MemoryValidationError),
}

impl CodedError for MemoryInputError {
    fn code(&self) -> ErrorCode {
        match self {
            Self::Parse(error) => error.code(),
            Self::Validation(error) => error.code(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::{CodedError, ErrorCode};

    use super::{GIB, MIB, MemoryParseError, MemoryPolicy, MemoryValidationError, ParsedMemory};

    fn parsed(input: &str) -> ParsedMemory {
        match ParsedMemory::from_str(input) {
            Ok(value) => value,
            Err(error) => panic!("valid memory rejected: {error}"),
        }
    }

    fn policy() -> MemoryPolicy {
        match MemoryPolicy::new(64 * MIB, 16 * GIB, 4096) {
            Ok(policy) => policy,
            Err(error) => panic!("valid policy rejected: {error}"),
        }
    }

    #[test]
    fn parses_binary_units_without_whitespace() {
        assert_eq!(parsed("4096").bytes(), 4096);
        assert_eq!(parsed("64M").bytes(), 64 * MIB);
        assert_eq!(parsed("768MiB").bytes(), 768 * MIB);
        assert_eq!(parsed("4gb").bytes(), 4 * GIB);
    }

    #[test]
    fn rejects_malformed_zero_and_overflowing_values() {
        for input in ["", "0", "-1M", "+1M", "1 M", "M", "1.5G", "1P"] {
            assert!(ParsedMemory::from_str(input).is_err(), "accepted {input:?}");
        }
        let overflow = ParsedMemory::from_str("18446744073709551615T");
        assert!(matches!(overflow, Err(MemoryParseError::Overflow)));
        assert_eq!(
            overflow.err().map(|error| error.code()),
            Some(ErrorCode::MemoryOverflow)
        );
        assert!(matches!(
            ParsedMemory::from_str("18446744073709551616"),
            Err(MemoryParseError::Overflow)
        ));
    }

    #[test]
    fn rejects_invalid_policy_boundaries() {
        assert!(MemoryPolicy::new(0, 1024, 4096).is_err());
        assert!(MemoryPolicy::new(8192, 4096, 4096).is_err());
        assert!(MemoryPolicy::new(4096, 8192, 0).is_err());
        assert!(MemoryPolicy::new(4096, 8192, 3000).is_err());
        assert!(MemoryPolicy::new(4097, 8192, 4096).is_err());
    }

    #[test]
    fn validates_range_alignment_and_formats_uml_value() {
        let policy = policy();
        let minimum = match policy.validate(parsed("64M")) {
            Ok(value) => value,
            Err(error) => panic!("minimum rejected: {error}"),
        };
        assert_eq!(minimum.uml_value(), "64M");

        let maximum = match policy.validate(parsed("16G")) {
            Ok(value) => value,
            Err(error) => panic!("maximum rejected: {error}"),
        };
        assert_eq!(maximum.uml_value(), "16G");

        assert!(matches!(
            policy.validate(parsed("63M")),
            Err(MemoryValidationError::BelowMinimum { .. })
        ));
        assert!(matches!(
            policy.validate(parsed("17G")),
            Err(MemoryValidationError::AboveMaximum { .. })
        ));
        assert!(matches!(
            policy.validate(parsed("67108865")),
            Err(MemoryValidationError::NotAligned { .. })
        ));
    }

    #[test]
    fn qualified_x86_profile_rejects_maximum_plus_one_page() {
        let policy = MemoryPolicy::new(64 * MIB, 4 * GIB, 4096).expect("qualified profile policy");
        assert!(policy.validate(parsed("64M")).is_ok());
        assert!(policy.validate(parsed("256M")).is_ok());
        assert!(policy.validate(parsed("4G")).is_ok());
        assert!(matches!(
            policy.validate(ParsedMemory::from_bytes(4 * GIB + 4096).expect("aligned value")),
            Err(MemoryValidationError::AboveMaximum {
                actual,
                maximum
            }) if actual == 4 * GIB + 4096 && maximum == 4 * GIB
        ));
    }
}
