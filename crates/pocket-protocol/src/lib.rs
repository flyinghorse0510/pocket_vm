//! Bounded, versioned host/guest protocol primitives.
//!
//! The framing layer is intentionally independent of Unix sockets and serial
//! devices. Any `Read`/`Write` transport can use it without changing the wire
//! format.

#![forbid(unsafe_code)]

mod builder;
mod builder_state;
mod error;
mod frame;
mod message;
mod state;
mod validator;
mod validator_state;

pub use builder::{
    ACCOUNT_DB_SCHEMA, AccountDatabase, AccountDb, AccountGroup, AccountUser, BuilderDone,
    BuilderHello, BuilderLayerDescriptor, BuilderMessage, BuilderStart, FilesystemStatus,
    GenerationMarker, MAX_ACCOUNT_DB_BYTES, MAX_ACCOUNT_GROUP_MEMBERS, MAX_ACCOUNT_GROUPS,
    MAX_ACCOUNT_MEMBERSHIPS, MAX_ACCOUNT_NAME_BYTES, MAX_ACCOUNT_USERS, MAX_BUILDER_LAYERS,
    MAX_BUILDER_TOOLS, MAX_LAYER_COMPRESSED_BYTES, MAX_LAYER_UNCOMPRESSED_BYTES,
    MAX_MANIFEST_BYTES, MAX_MANIFEST_CHUNK_BYTES, MAX_MANIFEST_DEPTH,
    MAX_MANIFEST_DIRECTORY_ENTRIES, MAX_MANIFEST_DIRECTORY_NAME_BYTES, MAX_MANIFEST_ENTRIES,
    MAX_MANIFEST_ENTRY_BYTES, MAX_MANIFEST_HARDLINK_GROUPS, MAX_MANIFEST_HARDLINK_PATH_BYTES,
    MAX_MANIFEST_PATH_BYTES, MAX_MANIFEST_XATTR_BYTES, MAX_MANIFEST_XATTRS, MAX_MEDIA_TYPE_LENGTH,
    MAX_ORIGINAL_USER_LENGTH, MAX_TOTAL_UNCOMPRESSED_BYTES, ManifestBegin, ManifestChunk,
    ManifestEnd, ManifestEntry, ManifestLimits, ManifestXattr, OciDescriptor,
    SOURCE_DATE_EPOCH_MAX, SOURCE_DATE_EPOCH_MIN, ToolIdentity, UserResolution,
    builder_error_message, decode_builder_message,
};
pub use builder_state::{BuilderSession, BuilderState};
pub use error::{FrameSection, ProtocolError};
pub use frame::{
    FrameHeader, FrameReader, FrameWriter, HEADER_LEN, MAGIC, MAX_CONTROL_PAYLOAD, MessageKind,
    PROTOCOL_MAJOR, PROTOCOL_MINOR, RawFrame, decode_frame_exact, encode_frame,
};
pub use message::{
    ErrorMessage, Exit, Hello, MAX_ARG_COUNT, MAX_ARG_LENGTH, MAX_DIAGNOSTIC_LENGTH, MAX_ENV_COUNT,
    MAX_ENV_LENGTH, MAX_FEATURE_COUNT, MAX_ID_LENGTH, MAX_PATH_LENGTH, MAX_RLIMIT_COUNT,
    MAX_SHUTDOWN_GRACE_MS, MAX_STDIN_BYTES, MAX_SUPPLEMENTARY_GIDS, MAX_VOLUME_COUNT, Platform,
    RESERVED_GUEST_PATHS, Ready, Resize, ResourceLimit, SLIRP_DNS_ADDRESS, SLIRP_GATEWAY_ADDRESS,
    SLIRP_GUEST_ADDRESS, SLIRP_INTERFACE, SLIRP_PREFIX_LENGTH, Shutdown, Signal, Start,
    ValidateMessage, VolumeSpec, WorkloadMessage, decode_payload, decode_workload_message,
    encode_payload, reserved_guest_path_conflict,
};
pub use state::{Direction, WorkloadSession, WorkloadState};
pub use validator::{
    ValidatorDone, ValidatorEvidence, ValidatorHello, ValidatorMessage, ValidatorStart,
    decode_validator_message, validator_error_message, validator_evidence_sha256,
};
pub use validator_state::{ValidatorSession, ValidatorState};

/// Complete feature set emitted by the current workload guest init.
///
/// Profile sealing requires this exact sorted set so a release manifest cannot
/// accidentally claim a feature that the measured guest binary does not
/// advertise.
pub const WORKLOAD_GUEST_FEATURES: &[&str] = &[
    "curated-dev-v1",
    "exact-stdin-length-v1",
    "fixed-capabilities-v1",
    "generated-etc-v1",
    "generation-marker-v3",
    "host-volumes-v1",
    "loopback-ipv4-v1",
    "namespace-mounts",
    "nested-pidns",
    "pre-hello-error-v1",
    "privileged-capabilities-v1",
    "separate-stdio",
    "signal-forwarding",
    "slirp-network-v1",
    "terminal-pty",
    "terminal-resize",
];

/// Complete feature set emitted by the current builder guest init.
pub const BUILDER_GUEST_FEATURES: &[&str] = &[
    "account-db-v1",
    "canonical-manifest-v1",
    "generation-marker-v3",
    "named-user-resolution-v1",
    "oci-input-reverify-v1",
    "source-date-epoch-v1",
];

/// Complete feature set emitted by the independent validation guest init.
pub const VALIDATOR_GUEST_FEATURES: &[&str] = &[
    "account-db-rebuild-v1",
    "challenge-bound-evidence-v1",
    "ext4-clean-state-v1",
    "generation-marker-verify-v3",
    "independent-manifest-rewalk-v1",
    "read-only-candidate-v1",
];
