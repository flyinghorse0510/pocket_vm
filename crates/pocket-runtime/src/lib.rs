//! Verified host-side orchestration for one trusted User-Mode Linux workload.
//!
//! This crate owns profile verification, per-run files and descriptors, the
//! `pocket-guard` launch, and the bounded host side of the guest protocol. It
//! deliberately contains no CLI parsing and never assembles a shell command.

#![cfg(target_os = "linux")]

mod builder;
mod cow;
mod error;
mod filesystem;
mod image;
mod launch;
mod manifest;
mod operation;
mod profile_seal;
mod protocol;
mod runtime;
mod terminal;

pub use builder::{
    AdjustRequest, BuildOutput, BuildRequest, BuilderPolicy, CommitRequest, HostBuilder,
};
pub use error::{HostBuildError, ManifestError, RuntimeError};
pub use image::{
    ImageArgv, ImageProcessOverrides, ResolvedImageProcess, parse_image_signal,
    resolve_image_process,
};
pub use manifest::{
    ArtifactDigest, ArtifactManifest, ArtifactSpec, BuilderContract, BuilderToolContract,
    Contracts, CpuManifest, HelloContract, LaunchContract, MemoryManifest, PROFILE_MANIFEST_FILE,
    PROFILE_SCHEMA_VERSION, ProfileManifest, ProfileMaturity, ProfileRevision, ValidatorContract,
    VerifiedProfile,
};
pub use operation::{LiveOperation, live_operations};
pub use pocket_protocol::{
    MAX_ORIGINAL_USER_LENGTH, MAX_VOLUME_COUNT, RESERVED_GUEST_PATHS, VolumeSpec,
    reserved_guest_path_conflict,
};
/// The bound the runtime applies to an image `User` value, re-exported so a
/// caller can reject an oversized one before opening anything.
pub use pocket_store::validate_instance_name;
pub use profile_seal::{
    ProfileArtifactSources, ProfileSealRequest, SealedProfile, seal_profile_bundle,
};
pub use runtime::{
    CapturedStream, RetainRequest, RunOptions, RunOutput, RunningWorkload, Runtime, RuntimePolicy,
    TerminalRequest, WorkloadSpec,
};
pub use terminal::TerminalSession;
