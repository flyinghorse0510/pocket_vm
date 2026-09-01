use std::{io, path::PathBuf, time::Duration};

use pocket_core::{CpuValidationError, ManagedUmlPathError, MemoryValidationError};
use pocket_protocol::{ErrorMessage, ProtocolError};
use pocket_store::StoreError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ManifestError {
    #[error("could not {operation} {path}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("profile manifest {path} exceeds the {maximum}-byte limit")]
    TooLarge { path: PathBuf, maximum: usize },

    #[error("profile manifest {path} is invalid JSON: {source}")]
    Json {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },

    #[error("invalid profile field {field}: {reason}")]
    InvalidField { field: &'static str, reason: String },

    #[error("unsupported profile contract in {field}: {value:?}")]
    UnsupportedContract { field: &'static str, value: String },

    #[error("profile revision mismatch: declared {declared}, computed {computed}")]
    RevisionMismatch { declared: String, computed: String },

    #[error("profile publication target already contains different or invalid content: {path}")]
    PublishConflict { path: PathBuf },

    #[error("invalid managed profile path: {0}")]
    ManagedPath(#[from] ManagedUmlPathError),

    #[error("artifact path {path} is not a normalized relative path: {reason}")]
    ArtifactPath { path: String, reason: &'static str },

    #[error("artifact {path} resolves outside its exact bundle pathname")]
    ArtifactResolution { path: PathBuf },

    #[error("artifact {path} is not a regular file")]
    ArtifactType { path: PathBuf },

    #[error("artifact {path} has unsafe or mutable mode {mode:#06o}: {reason}")]
    ArtifactMode {
        path: PathBuf,
        mode: u32,
        reason: &'static str,
    },

    #[error("artifact {path} has a Linux file capability")]
    ArtifactCapability { path: PathBuf },

    #[error("artifact {path} size mismatch: expected {expected}, observed {actual}")]
    ArtifactSize {
        path: PathBuf,
        expected: u64,
        actual: u64,
    },

    #[error("artifact {path} digest mismatch: expected {expected}, observed {actual}")]
    ArtifactDigest {
        path: PathBuf,
        expected: String,
        actual: String,
    },

    #[error("invalid x86_64 ELF artifact {path}: {reason}")]
    Elf { path: PathBuf, reason: String },

    #[error(
        "kernel configuration {path} violates {setting}: expected {expected}, observed {actual}"
    )]
    KernelConfig {
        path: PathBuf,
        setting: String,
        expected: String,
        actual: String,
    },

    #[error("CPU profile is invalid: {0}")]
    Cpu(#[from] CpuValidationError),

    #[error("memory policy is invalid: {0}")]
    Memory(#[from] MemoryValidationError),
}

impl ManifestError {
    pub(crate) fn io(operation: &'static str, path: impl Into<PathBuf>, source: io::Error) -> Self {
        Self::Io {
            operation,
            path: path.into(),
            source,
        }
    }

    pub(crate) fn invalid(field: &'static str, reason: impl Into<String>) -> Self {
        Self::InvalidField {
            field,
            reason: reason.into(),
        }
    }
}

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error(transparent)]
    Manifest(#[from] ManifestError),

    #[error(transparent)]
    Store(#[from] StoreError),

    #[error("invalid run path: {0}")]
    ManagedPath(#[from] ManagedUmlPathError),

    #[error("invalid CPU request: {0}")]
    Cpu(#[from] CpuValidationError),

    #[error("invalid memory request: {0}")]
    Memory(#[from] MemoryValidationError),

    #[error("invalid workload protocol value: {0}")]
    Protocol(#[from] ProtocolError),

    #[error("invalid authenticated image configuration: {0}")]
    ImageConfig(#[source] pocket_oci::Error),

    #[error("could not {operation} {path}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("run configuration {field} is invalid: {reason}")]
    InvalidConfiguration { field: &'static str, reason: String },

    #[error("generation contract mismatch in {field}: expected {expected:?}, observed {actual:?}")]
    GenerationMismatch {
        field: &'static str,
        expected: String,
        actual: String,
    },

    #[error("guard spawn failed for {program}: {source}")]
    GuardSpawn {
        program: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("guard exited before {stage} with status {status}")]
    GuardExitedEarly { stage: &'static str, status: String },

    #[error("timed out after {timeout:?} while waiting for {stage}")]
    Timeout {
        stage: &'static str,
        timeout: Duration,
    },

    #[error("guest rejected the run during {stage}: {message:?}")]
    Guest {
        stage: &'static str,
        message: ErrorMessage,
    },

    #[error("guest HELLO mismatch in {field}: expected {expected:?}, observed {actual:?}")]
    HelloMismatch {
        field: &'static str,
        expected: String,
        actual: String,
    },

    #[error("invalid UML COW file {path}: {reason}")]
    Cow { path: PathBuf, reason: String },

    #[error("guard returned {status} after the guest reported EXIT")]
    GuardStatus { status: String },

    #[error("guest reported that workload filesystem or namespace cleanup was not clean")]
    GuestFilesystemUnclean,

    #[error("forced cleanup failed after {primary}: {cleanup}")]
    Cleanup { primary: Box<Self>, cleanup: String },

    #[error("{primary}; bounded run diagnostics: {diagnostic}")]
    Diagnostics {
        primary: Box<Self>,
        diagnostic: String,
    },

    #[error("captured stream worker failed for {stream}: {reason}")]
    StreamWorker {
        stream: &'static str,
        reason: String,
    },
}

impl RuntimeError {
    pub(crate) fn io(operation: &'static str, path: impl Into<PathBuf>, source: io::Error) -> Self {
        Self::Io {
            operation,
            path: path.into(),
            source,
        }
    }

    pub(crate) fn invalid(field: &'static str, reason: impl Into<String>) -> Self {
        Self::InvalidConfiguration {
            field,
            reason: reason.into(),
        }
    }
}

/// Fail-closed errors from the host-side OCI-to-generation builder workflow.
#[derive(Debug, Error)]
pub enum HostBuildError {
    #[error(transparent)]
    Manifest(#[from] ManifestError),

    #[error(transparent)]
    Store(#[from] StoreError),

    #[error(transparent)]
    Oci(#[from] pocket_oci::Error),

    #[error(transparent)]
    Protocol(#[from] ProtocolError),

    #[error("invalid managed builder path: {0}")]
    ManagedPath(#[from] ManagedUmlPathError),

    #[error("could not {operation} {path}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("builder configuration {field} is invalid: {reason}")]
    InvalidConfiguration { field: &'static str, reason: String },

    #[error("unsupported host-builder contract in {field}: {value:?}")]
    Unsupported { field: &'static str, value: String },

    #[error("guard spawn failed for {program}: {source}")]
    GuardSpawn {
        program: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("guarded {stage} failed with status {status}: {diagnostic}")]
    GuardStatus {
        stage: &'static str,
        status: String,
        diagnostic: String,
    },

    /// A control-protocol failure carries the guest console with it. Without
    /// the console a silent guest is indistinguishable from a broken host.
    #[error("{stage} control protocol failed: {reason}; guest console: {diagnostic}")]
    GuestProtocol {
        stage: &'static str,
        reason: String,
        #[source]
        source: Box<HostBuildError>,
        diagnostic: String,
    },

    #[error("timed out after {timeout:?} while waiting for {stage}")]
    Timeout {
        stage: &'static str,
        timeout: Duration,
    },

    #[error("builder guest rejected {stage}: {message:?}")]
    Guest {
        stage: &'static str,
        message: ErrorMessage,
    },

    #[error("builder HELLO mismatch in {field}: expected {expected:?}, observed {actual:?}")]
    HelloMismatch {
        field: &'static str,
        expected: String,
        actual: String,
    },

    #[error("builder evidence mismatch in {field}: expected {expected:?}, observed {actual:?}")]
    EvidenceMismatch {
        field: &'static str,
        expected: String,
        actual: String,
    },

    #[error("forced builder cleanup failed after {primary}: {cleanup}")]
    Cleanup { primary: Box<Self>, cleanup: String },

    #[error("captured builder stream worker failed for {stream}: {reason}")]
    StreamWorker {
        stream: &'static str,
        reason: String,
    },
}

impl HostBuildError {
    pub(crate) fn io(operation: &'static str, path: impl Into<PathBuf>, source: io::Error) -> Self {
        Self::Io {
            operation,
            path: path.into(),
            source,
        }
    }

    pub(crate) fn invalid(field: &'static str, reason: impl Into<String>) -> Self {
        Self::InvalidConfiguration {
            field,
            reason: reason.into(),
        }
    }
}
