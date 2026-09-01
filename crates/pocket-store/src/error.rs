use std::{io, path::PathBuf};

use thiserror::Error;

use crate::{DerivationKey, Digest, GenerationId};

/// Kind of bounded, checksummed metadata being decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetadataKind {
    Store,
    Generation,
    Staging,
    Alias,
    Lease,
    RetainedCow,
    Instance,
    Derivation,
    Lock,
}

impl std::fmt::Display for MetadataKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Store => "store",
            Self::Generation => "generation",
            Self::Staging => "staging",
            Self::Alias => "alias",
            Self::Lease => "lease",
            Self::RetainedCow => "retained COW",
            Self::Instance => "instance",
            Self::Derivation => "derivation lookup",
            Self::Lock => "lock",
        })
    }
}

/// A stable, typed storage-layer failure.
#[derive(Debug, Error)]
pub enum StoreError {
    #[error("{operation} failed for {path}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("invalid store root {path}: {reason}")]
    InvalidRoot { path: PathBuf, reason: String },

    #[error("invalid {field}: {reason}")]
    InvalidInput { field: &'static str, reason: String },

    #[error("invalid {kind} metadata at {path}: {reason}")]
    InvalidMetadata {
        kind: MetadataKind,
        path: PathBuf,
        reason: String,
    },

    #[error("{kind} metadata at {path} exceeds the {maximum}-byte limit")]
    MetadataTooLarge {
        kind: MetadataKind,
        path: PathBuf,
        maximum: usize,
    },

    #[error("symbolic links are forbidden at {path}")]
    Symlink { path: PathBuf },

    #[error("{path} is on device {actual}, expected store device {expected}")]
    CrossDevice {
        path: PathBuf,
        expected: u64,
        actual: u64,
    },

    #[error("generation {0} does not exist")]
    GenerationNotFound(GenerationId),

    #[error("derivation {0} is already being prepared")]
    DerivationBusy(DerivationKey),

    #[error("generation {0} has already been published")]
    GenerationAlreadyExists(GenerationId),

    #[error("alias does not exist")]
    AliasNotFound,

    #[error("derivation lookup does not exist")]
    DerivationNotFound,

    #[error("retained COW record does not exist")]
    RetainedCowNotFound,

    #[error("instance does not exist")]
    InstanceNotFound,

    #[error("digest mismatch for {path}: expected {expected}, observed {actual}")]
    DigestMismatch {
        path: PathBuf,
        expected: Digest,
        actual: Digest,
    },

    #[error("size mismatch for {path}: expected {expected}, observed {actual}")]
    SizeMismatch {
        path: PathBuf,
        expected: u64,
        actual: u64,
    },

    #[error("generation {generation} has no immutable sidecar named {name:?}")]
    SidecarNotFound {
        generation: GenerationId,
        name: String,
    },

    #[error("immutable sidecar {path} is {actual} bytes, exceeding the {maximum}-byte read limit")]
    SidecarTooLarge {
        path: PathBuf,
        actual: u64,
        maximum: u64,
    },

    #[error("garbage collection refused because a GC-root record is invalid: {0}")]
    UnsafeGarbageCollection(String),

    #[error("store entry {path} has an unsupported type or name")]
    UnexpectedEntry { path: PathBuf },
}

impl StoreError {
    pub(crate) fn io(operation: &'static str, path: impl Into<PathBuf>, source: io::Error) -> Self {
        Self::Io {
            operation,
            path: path.into(),
            source,
        }
    }

    pub(crate) fn metadata(
        kind: MetadataKind,
        path: impl Into<PathBuf>,
        reason: impl Into<String>,
    ) -> Self {
        Self::InvalidMetadata {
            kind,
            path: path.into(),
            reason: reason.into(),
        }
    }
}
