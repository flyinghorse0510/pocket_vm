//! Production guest PID 1 for Pocket's trusted UML workload profile.
//!
//! The crate deliberately keeps parsing, contract reconciliation, framing,
//! and buffering independent from privileged Linux operations so they can be
//! tested on the build host. The Linux runtime is single-threaded; that is a
//! required precondition for its narrowly documented `fork(2)` calls.

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

mod capability;
mod config;
mod contract;
mod control;
mod error;
mod internal;
#[cfg(target_os = "linux")]
mod linux;
mod pump;

pub use capability::{
    ALLOWED_CAPABILITIES, BLOCKED_CAPABILITIES, CapabilitySets, RootReadOnlyGuards,
    apply_fixed_capability_mask, capability_is_allowed, fixed_root_capability_sets,
    uid_zero_read_only_guards_hold,
};
pub use config::{GuestConfig, TtyPaths};
pub use contract::{
    GenerationMarker, GuestObservation, decode_generation_marker, verify_generation_marker,
    verify_start,
};
pub use control::ControlFrameDecoder;
pub use error::InitError;
pub use internal::{InternalEvent, InternalEventDecoder};
#[cfg(target_os = "linux")]
pub use linux::{emergency_poweroff, run};
pub use pump::{MAX_PUMP_BUFFER, PumpBuffer};

#[cfg(not(target_os = "linux"))]
pub fn run() -> Result<std::convert::Infallible, InitError> {
    Err(InitError::unsupported(
        "platform",
        "pocket-init requires Linux guest kernel interfaces",
    ))
}
