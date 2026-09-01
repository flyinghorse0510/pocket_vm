//! Shared, side-effect-free validation primitives for Pocket.
//!
//! This crate deliberately contains no process launching or filesystem
//! mutation.  Values accepted here are safe to pass to the layers that do
//! perform those operations.

#![forbid(unsafe_code)]

mod cpu;
mod error;
mod memory;
mod path;

pub use cpu::{CpuProfile, CpuValidationError, MAX_COMPILED_CPUS, ValidatedCpuRequest};
pub use error::{CodedError, ErrorCode, UnknownErrorCode};
pub use memory::{
    MemoryInputError, MemoryParseError, MemoryPolicy, MemoryValidationError, ParsedMemory,
    ValidatedMemory,
};
pub use path::{
    MAX_MANAGED_UML_PATH_BYTES, MIN_MANAGED_UML_PATH_COMPONENTS, ManagedUmlPath,
    ManagedUmlPathError,
};
