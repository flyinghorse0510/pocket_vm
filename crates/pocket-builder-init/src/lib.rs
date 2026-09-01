//! Trusted, single-purpose PID 1 for Pocket's OCI-to-ext4 builder UML.
//!
//! Parsing, OCI-layout reconciliation, marker creation, user resolution and
//! manifest construction are kept independent from privileged mounts so they
//! can be exhaustively exercised on an ordinary build host.

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

mod config;
mod error;
mod input;
#[cfg(target_os = "linux")]
mod linux;
mod manifest;
mod marker;
mod operation;
mod tool;
mod user;

pub use config::BuilderConfig;
pub use error::BuilderError;
pub use input::verify_input_layout;
#[cfg(target_os = "linux")]
pub use linux::{emergency_poweroff, run};
pub use manifest::{ManifestEmitter, ManifestSummary};
pub use marker::{encode_generation_marker, write_generation_marker};
pub use operation::{BuildArtifacts, LayerApplier, UmociLayerApplier, execute_conversion};
pub use tool::{UMOCI_PATH, inspect_umoci};
pub use user::{build_account_database, resolve_image_user, resolve_image_user_from_database};

#[cfg(not(target_os = "linux"))]
pub fn run() -> Result<std::convert::Infallible, BuilderError> {
    Err(BuilderError::unsupported(
        "platform",
        "pocket-builder-init requires Linux guest kernel interfaces",
    ))
}
