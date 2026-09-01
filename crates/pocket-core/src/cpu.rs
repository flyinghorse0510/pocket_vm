use thiserror::Error;

use crate::{CodedError, ErrorCode};

/// Current generic UML's compiled CPU ceiling.
pub const MAX_COMPILED_CPUS: u16 = 64;

/// Immutable CPU facts bound into a profile revision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpuProfile {
    smp_enabled: bool,
    product_max_cpus: u16,
    compiled_nr_cpus: Option<u16>,
    effective_max_cpus: u16,
}

impl CpuProfile {
    /// Construct and validate a profile CPU contract.
    pub fn new(
        smp_enabled: bool,
        product_max_cpus: u16,
        compiled_nr_cpus: Option<u16>,
    ) -> Result<Self, CpuValidationError> {
        if product_max_cpus == 0 || product_max_cpus > MAX_COMPILED_CPUS {
            return Err(CpuValidationError::InvalidProfile {
                reason: "product maximum must be in 1..=64",
            });
        }

        let effective_max_cpus = if smp_enabled {
            let Some(compiled) = compiled_nr_cpus else {
                return Err(CpuValidationError::InvalidProfile {
                    reason: "SMP profile requires a compiled CPU maximum",
                });
            };
            if !(2..=MAX_COMPILED_CPUS).contains(&compiled) {
                return Err(CpuValidationError::InvalidProfile {
                    reason: "SMP compiled maximum must be in 2..=64",
                });
            }
            product_max_cpus.min(compiled)
        } else {
            if compiled_nr_cpus.is_some() {
                return Err(CpuValidationError::InvalidProfile {
                    reason: "UP profile must not claim a compiled SMP maximum",
                });
            }
            if product_max_cpus != 1 {
                return Err(CpuValidationError::InvalidProfile {
                    reason: "UP product and effective maxima must be one",
                });
            }
            1
        };

        Ok(Self {
            smp_enabled,
            product_max_cpus,
            compiled_nr_cpus,
            effective_max_cpus,
        })
    }

    #[must_use]
    pub const fn smp_enabled(self) -> bool {
        self.smp_enabled
    }

    #[must_use]
    pub const fn product_max_cpus(self) -> u16 {
        self.product_max_cpus
    }

    #[must_use]
    pub const fn compiled_nr_cpus(self) -> Option<u16> {
        self.compiled_nr_cpus
    }

    #[must_use]
    pub const fn effective_max_cpus(self) -> u16 {
        self.effective_max_cpus
    }

    /// Validate a caller request against the immutable profile. Host affinity
    /// and quota are scheduling observations, not vCPU admission ceilings.
    /// This function never clamps a request.
    pub fn validate_request(
        self,
        requested: u16,
    ) -> Result<ValidatedCpuRequest, CpuValidationError> {
        if requested == 0 {
            return Err(CpuValidationError::InvalidRequest {
                value: requested.to_string(),
            });
        }
        if requested > self.effective_max_cpus {
            return Err(CpuValidationError::ExceedsProfileMaximum {
                requested,
                maximum: self.effective_max_cpus,
            });
        }
        Ok(ValidatedCpuRequest {
            requested,
            smp_enabled: self.smp_enabled,
        })
    }

    /// Parse a decimal CPU request and validate it without accepting signs,
    /// whitespace, or fallback values.
    pub fn parse_request(self, requested: &str) -> Result<ValidatedCpuRequest, CpuValidationError> {
        if requested.is_empty() || !requested.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(CpuValidationError::InvalidRequest {
                value: requested.to_owned(),
            });
        }
        let parsed = requested
            .parse::<u16>()
            .map_err(|_| CpuValidationError::InvalidRequest {
                value: requested.to_owned(),
            })?;
        self.validate_request(parsed)
    }
}

/// A CPU request proven valid for one selected profile and host observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidatedCpuRequest {
    requested: u16,
    smp_enabled: bool,
}

impl ValidatedCpuRequest {
    #[must_use]
    pub const fn requested(self) -> u16 {
        self.requested
    }

    /// Return the explicit UML `ncpus=` argument value. A deliberately UP
    /// build returns `None` because it does not link the parser.
    #[must_use]
    pub const fn kernel_ncpus(self) -> Option<u16> {
        if self.smp_enabled {
            Some(self.requested)
        } else {
            None
        }
    }

    /// Verify HELLO's online count exactly; mismatch is never downgraded.
    pub fn verify_online(self, online: u16) -> Result<(), CpuValidationError> {
        if online != self.requested {
            return Err(CpuValidationError::OnlineCountMismatch {
                requested: self.requested,
                online,
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CpuValidationError {
    #[error("invalid CPU profile: {reason}")]
    InvalidProfile { reason: &'static str },
    #[error("invalid CPU request {value:?}")]
    InvalidRequest { value: String },
    #[error("requested {requested} CPUs, profile maximum is {maximum}")]
    ExceedsProfileMaximum { requested: u16, maximum: u16 },
    #[error("requested {requested} CPUs, guest reported {online} online")]
    OnlineCountMismatch { requested: u16, online: u16 },
}

impl CodedError for CpuValidationError {
    fn code(&self) -> ErrorCode {
        match self {
            Self::InvalidProfile { .. } => ErrorCode::InvalidCpuProfile,
            Self::InvalidRequest { .. } => ErrorCode::InvalidCpuRequest,
            Self::ExceedsProfileMaximum { .. } => ErrorCode::CpuExceedsProfileMaximum,
            Self::OnlineCountMismatch { .. } => ErrorCode::CpuCountMismatch,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{CodedError, ErrorCode};

    use super::{CpuProfile, CpuValidationError};

    fn smp_profile() -> CpuProfile {
        match CpuProfile::new(true, 8, Some(16)) {
            Ok(profile) => profile,
            Err(error) => panic!("valid SMP profile rejected: {error}"),
        }
    }

    #[test]
    fn computes_checked_effective_maximum() {
        let product_limited = smp_profile();
        assert_eq!(product_limited.effective_max_cpus(), 8);
        assert_eq!(product_limited.compiled_nr_cpus(), Some(16));

        let compiled_limited = match CpuProfile::new(true, 16, Some(4)) {
            Ok(profile) => profile,
            Err(error) => panic!("valid SMP profile rejected: {error}"),
        };
        assert_eq!(compiled_limited.effective_max_cpus(), 4);
    }

    #[test]
    fn rejects_incoherent_profile_boundaries() {
        assert!(CpuProfile::new(true, 8, None).is_err());
        assert!(CpuProfile::new(true, 8, Some(1)).is_err());
        assert!(CpuProfile::new(true, 65, Some(64)).is_err());
        assert!(CpuProfile::new(false, 2, None).is_err());
        assert!(CpuProfile::new(false, 1, Some(2)).is_err());
    }

    #[test]
    fn validates_without_downgrading() {
        let profile = smp_profile();
        let valid = match profile.validate_request(4) {
            Ok(request) => request,
            Err(error) => panic!("valid request rejected: {error}"),
        };
        assert_eq!(valid.requested(), 4);
        assert_eq!(valid.kernel_ncpus(), Some(4));
        assert!(valid.verify_online(4).is_ok());

        let over_profile = profile.validate_request(9);
        assert!(matches!(
            over_profile,
            Err(CpuValidationError::ExceedsProfileMaximum {
                requested: 9,
                maximum: 8
            })
        ));
        // A six-vCPU request is valid regardless of the caller's current host
        // affinity/quota. Runtime telemetry separately labels whether it is
        // scaling-qualified or oversubscribed.
        assert_eq!(
            profile.validate_request(6).map(|value| value.requested()),
            Ok(6)
        );
    }

    #[test]
    fn rejects_zero_negative_malformed_and_overflowing_text() {
        let profile = smp_profile();
        for value in ["", "0", "-1", "+1", " 1", "1 ", "1.0", "65536"] {
            assert!(profile.parse_request(value).is_err(), "accepted {value:?}");
        }
    }

    #[test]
    fn up_profile_omits_kernel_token_and_accepts_only_one() {
        let profile = match CpuProfile::new(false, 1, None) {
            Ok(profile) => profile,
            Err(error) => panic!("valid UP profile rejected: {error}"),
        };
        let request = match profile.validate_request(1) {
            Ok(request) => request,
            Err(error) => panic!("valid UP request rejected: {error}"),
        };
        assert_eq!(request.kernel_ncpus(), None);
        assert!(profile.validate_request(2).is_err());
    }

    #[test]
    fn online_mismatch_has_stable_error_code() {
        let request = match smp_profile().validate_request(2) {
            Ok(request) => request,
            Err(error) => panic!("valid request rejected: {error}"),
        };
        let error = match request.verify_online(1) {
            Ok(()) => panic!("online mismatch accepted"),
            Err(error) => error,
        };
        assert_eq!(error.code(), ErrorCode::CpuCountMismatch);
    }
}
