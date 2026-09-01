//! Independent, single-purpose PID 1 for pre-publication ext4 validation.
//!
//! This role has no OCI unpacker and never mounts the candidate writable. It
//! re-derives the canonical manifest, marker and account evidence in a fresh
//! UML process after the builder and host e2fsck have completed.

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

mod account;
mod config;
mod error;
#[cfg(target_os = "linux")]
mod linux;
mod manifest;

pub use config::ValidatorConfig;
pub use error::ValidatorError;
#[cfg(target_os = "linux")]
pub use linux::{emergency_poweroff, run};
pub use manifest::{ManifestSummary, validate_manifest};

#[cfg(not(target_os = "linux"))]
pub fn run() -> Result<std::convert::Infallible, ValidatorError> {
    Err(ValidatorError::failure(
        "platform",
        pocket_core::ErrorCode::ValidatorBootContract,
        None,
        "pocket-validator-init requires Linux guest kernel interfaces",
    ))
}
