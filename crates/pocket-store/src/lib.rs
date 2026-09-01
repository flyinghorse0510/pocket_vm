//! Crash-conscious, unprivileged storage primitives for Pocket root filesystems.
//!
//! Input contracts produce non-circular derivation keys used for build locking
//! and lookup. Publication derives the final generation ID from the completed
//! ext4 bytes and canonical immutable sidecars. Mutable aliases, live shared
//! lease locks, and durable retained-COW records use that final ID as independent
//! garbage-collection roots. Filesystem mutations are relative to validated
//! directory descriptors and reject symbolic links.
//!
//! This crate is Linux-specific because publication relies on
//! `renameat2(RENAME_NOREPLACE)` to make generation creation non-overwriting.

#![forbid(unsafe_code)]

#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
compile_error!("pocket-store currently requires Linux with the GNU C library");

mod codec;
mod error;
mod fs;
mod identity;
mod store;

pub use error::{MetadataKind, StoreError};
pub use identity::{
    AliasId, AliasKey, DerivationKey, Digest, GenerationId, GenerationSpec, ImmutableSidecar,
    MAX_GENERATION_SIDECARS, MAX_SIDECAR_NAME_BYTES, Platform, RetainedCowId, RetainedCowState,
};
pub use store::{
    AliasRoot, BeginGeneration, GarbageCollectionReport, Generation, GenerationManifest,
    GenerationTransaction, Lease, RecoveryReport, RetainedCow, RetainedCowLease, Store,
};

/// On-disk store schema understood by this crate.
pub const STORE_SCHEMA_VERSION: u16 = 3;

/// Upper bound for every individual metadata file.
pub const MAX_METADATA_BYTES: usize = 1024 * 1024;
