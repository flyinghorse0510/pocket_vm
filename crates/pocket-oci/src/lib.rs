//! Strict ingestion of OCI image layouts for Pocket VM.
//!
//! This crate intentionally accepts a narrow, executable-image subset of OCI.
//! It authenticates every blob reachable from `index.json`, selects exactly one
//! Linux/amd64 image, and returns the Docker process defaults needed by the
//! guest launcher. [`SkopeoNormalizer`] provides the bounded, anonymous,
//! guard-supervised `docker://` normalization path plus fixed-name, single-image
//! `oci-archive:` and `docker-archive:` ingestion; canonical local layouts can
//! be checked directly with [`verify_canonical_layout`].

mod error;
mod layout;
mod skopeo;

pub use error::{Error, Result};
pub use layout::{
    DescriptorDigest, DockerProcessConfig, ImagePlatform, Layer, LayerCompression,
    SELECTOR_POLICY_ID, VerifiedImage, VerifyLimits, parse_image_process_config,
    parse_image_process_config_with_limits, require_canonical_media_types, verify_canonical_layout,
    verify_canonical_layout_with_limits, verify_layout, verify_layout_with_limits,
};
pub use skopeo::{
    AcquisitionDirectory, ManagedLayoutPath, ResolverInputEvidence, ResolverInputSnapshot,
    SkopeoExecutionPolicy, SkopeoLog, SkopeoNormalizer, SkopeoOutput, SkopeoPlatform, SkopeoSource,
    SkopeoSourceKind, StagedArchive,
};
