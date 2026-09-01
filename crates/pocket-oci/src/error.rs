use std::{path::PathBuf, time::Duration};

/// Errors produced while normalizing or authenticating an image layout.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("I/O error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("{document} is not valid JSON: {source}")]
    Json {
        document: String,
        #[source]
        source: serde_json::Error,
    },

    #[error("{what} exceeds the configured limit of {limit}")]
    Limit { what: String, limit: u64 },

    #[error("unsupported OCI image-layout version {found:?}; expected \"1.0.0\"")]
    UnsupportedLayoutVersion { found: String },

    #[error("invalid {document}: {reason}")]
    InvalidDocument { document: String, reason: String },

    #[error("unsupported media type {media_type:?} in {context}")]
    UnsupportedMediaType { context: String, media_type: String },

    #[error("invalid digest {digest:?} in {context}: {reason}")]
    InvalidDigest {
        context: String,
        digest: String,
        reason: String,
    },

    #[error(
        "blob size mismatch for {digest}: descriptor says {expected} bytes, file supplied {actual} bytes"
    )]
    SizeMismatch {
        digest: String,
        expected: u64,
        actual: u64,
    },

    #[error("blob digest mismatch for {digest}; computed sha256:{actual}")]
    DigestMismatch { digest: String, actual: String },

    #[error("invalid or unsupported platform in {context}: {reason}")]
    Platform { context: String, reason: String },

    #[error("the layout does not contain a Linux/amd64 image")]
    NoLinuxAmd64Image,

    #[error("the layout contains {count} Linux/amd64 image candidates; exactly one is required")]
    AmbiguousLinuxAmd64 { count: usize },

    #[error("manifest has {layers} layers, but its config has {diff_ids} rootfs diff_ids")]
    RootfsCountMismatch { layers: usize, diff_ids: usize },

    #[error("could not decode layer {position} ({media_type}): {source}")]
    LayerDecode {
        position: usize,
        media_type: String,
        #[source]
        source: std::io::Error,
    },

    #[error(
        "layer {position} DiffID mismatch: config expects {expected}, but uncompressed content hashes to {actual}"
    )]
    DiffIdMismatch {
        position: usize,
        expected: String,
        actual: String,
    },

    #[error("uncompressed byte count overflow while decoding layer {position}")]
    LayerUncompressedOverflow { position: usize },

    #[error("total uncompressed byte count overflow while decoding layer {position}")]
    TotalUncompressedOverflow { position: usize },

    #[error(
        "layer {position} expands beyond its {limit}-byte uncompressed limit (observed at least {actual} bytes)"
    )]
    LayerUncompressedLimit {
        position: usize,
        limit: u64,
        actual: u64,
    },

    #[error(
        "reachable layers expand beyond the {limit}-byte total uncompressed limit while decoding layer {position} (observed at least {actual} bytes)"
    )]
    TotalUncompressedLimit {
        position: usize,
        limit: u64,
        actual: u64,
    },

    #[error(
        "layer {position} exceeds maximum decompression ratio {maximum}:1 ({uncompressed} uncompressed bytes from {compressed} compressed bytes)"
    )]
    DecompressionRatio {
        position: usize,
        maximum: u64,
        compressed: u64,
        uncompressed: u64,
    },

    #[error("invalid Docker process configuration: {reason}")]
    ProcessConfig { reason: String },

    #[error("unsafe managed OCI destination {path}: {reason}")]
    UnsafeManagedPath { path: PathBuf, reason: String },

    #[error("invalid Skopeo source reference: {reason}")]
    InvalidSource { reason: String },

    #[error("invalid Skopeo platform: {reason}")]
    InvalidPlatform { reason: String },

    #[error("invalid Skopeo execution policy: {reason}")]
    InvalidExecutionPolicy { reason: String },

    #[error("unsafe acquisition directory {path}: {reason}")]
    UnsafeAcquisitionDirectory { path: PathBuf, reason: String },

    #[error("failed to execute acquisition guard {program}: {source}")]
    AcquisitionGuardSpawn {
        program: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("timed out after {timeout:?} while waiting for guarded Skopeo acquisition")]
    SkopeoTimeout { timeout: Duration },

    #[error("guarded Skopeo exited unsuccessfully ({status}): {diagnostic}")]
    SkopeoFailed { status: String, diagnostic: String },

    #[error(
        "guarded Skopeo {stream} exceeded the {maximum}-byte capture limit (observed {actual} bytes)"
    )]
    SkopeoOutputLimit {
        stream: &'static str,
        maximum: usize,
        actual: u64,
    },

    #[error("could not collect guarded Skopeo {stream}: {reason}")]
    SkopeoStream {
        stream: &'static str,
        reason: String,
    },

    #[error("resolver/NSS input {path} is unsupported: {reason}")]
    ResolverInput { path: PathBuf, reason: String },

    #[error(
        "resolver/NSS input {path} changed during registry acquisition (before {before}, after {after})"
    )]
    ResolverInputChanged {
        path: PathBuf,
        before: String,
        after: String,
    },

    #[error("local image archive {path} is unsupported or ambiguous: {reason}")]
    ArchiveInput { path: PathBuf, reason: String },
}

pub type Result<T> = std::result::Result<T, Error>;

pub(crate) fn io_error(path: impl Into<PathBuf>, source: std::io::Error) -> Error {
    Error::Io {
        path: path.into(),
        source,
    }
}
