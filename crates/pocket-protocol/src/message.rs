use std::{collections::BTreeSet, path::Path};

use minicbor::{Decode, Decoder, Encode};
use pocket_core::ErrorCode;

use crate::{MAX_CONTROL_PAYLOAD, MessageKind, ProtocolError, RawFrame};

pub const MAX_ID_LENGTH: usize = 128;
pub const MAX_FEATURE_COUNT: usize = 64;
pub const MAX_ARG_COUNT: usize = 256;
pub const MAX_ARG_LENGTH: usize = 4096;
pub const MAX_ENV_COUNT: usize = 256;
pub const MAX_ENV_LENGTH: usize = 8192;
pub const MAX_PATH_LENGTH: usize = 4096;
pub const MAX_SUPPLEMENTARY_GIDS: usize = 64;
pub const MAX_RLIMIT_COUNT: usize = 32;
pub const MAX_VOLUME_COUNT: usize = 32;

/// The `slirp-bess-v1` addressing contract.
///
/// One source of truth for both sides: the host passes these to the network
/// helper on its command line, and the guest configures its interface from the
/// same constants. They are not sent in `START` because they are part of the
/// profile's sealed network contract, not a per-run choice -- a profile that
/// changes them changes its revision.
pub const SLIRP_GUEST_ADDRESS: [u8; 4] = [10, 0, 2, 100];
pub const SLIRP_GATEWAY_ADDRESS: [u8; 4] = [10, 0, 2, 2];
pub const SLIRP_DNS_ADDRESS: [u8; 4] = [10, 0, 2, 3];
pub const SLIRP_PREFIX_LENGTH: u8 = 24;
/// The guest-visible name of the vector device UML creates for `vec0`.
pub const SLIRP_INTERFACE: &str = "vec0";

/// Guest paths the runtime mounts or writes itself.
///
/// A shared host directory may not collide with one of these. Placed under a
/// runtime mount it is silently shadowed by it; placed over one, the runtime's
/// own mounts and generated files are created inside the caller's directory
/// and left there after the run. Neither is something to discover afterwards,
/// so the collision is refused instead. A path that merely sits beside one --
/// `/etc/myconfig` next to `/etc/hosts` -- is unaffected.
pub const RESERVED_GUEST_PATHS: &[&str] = &[
    "/dev",
    "/etc/hostname",
    "/etc/hosts",
    "/etc/resolv.conf",
    "/proc",
    "/run",
    "/sys",
];

/// The reserved path `destination` collides with, if any.
///
/// A collision is equality, or either path being a directory prefix of the
/// other: `/dev/x` sits under a runtime mount, and `/etc` contains three
/// generated files.
pub fn reserved_guest_path_conflict(destination: &str) -> Option<&'static str> {
    RESERVED_GUEST_PATHS.iter().copied().find(|reserved| {
        destination == *reserved
            || destination
                .strip_prefix(reserved)
                .is_some_and(|rest| rest.starts_with('/'))
            || reserved
                .strip_prefix(destination)
                .is_some_and(|rest| rest.starts_with('/'))
    })
}
pub const MAX_DIAGNOSTIC_LENGTH: usize = 8192;
pub const MAX_SHUTDOWN_GRACE_MS: u32 = 600_000;
/// Exact upper bound on the synchronous standard-input payload the host may
/// announce in START and then write to the guest stdin channel.
pub const MAX_STDIN_BYTES: u64 = 16 * 1024 * 1024;

/// Validation performed after decoding and before encoding any workload
/// payload.
pub trait ValidateMessage {
    fn validate(&self) -> Result<(), ProtocolError>;
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct Platform {
    #[n(0)]
    pub os: String,
    #[n(1)]
    pub architecture: String,
    #[n(2)]
    pub variant: Option<String>,
}

impl Platform {
    pub(crate) fn validate(&self, field: &'static str) -> Result<(), ProtocolError> {
        validate_token(field, &self.os, 32)?;
        validate_token(field, &self.architecture, 32)?;
        if let Some(variant) = &self.variant {
            validate_token(field, variant, 32)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct ResourceLimit {
    #[n(0)]
    pub resource: u8,
    #[n(1)]
    pub soft: u64,
    #[n(2)]
    pub hard: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
/// One host directory shared into the guest.
///
/// `source` is a path on the **host**, mounted into the guest through hostfs,
/// so the guest sees the host's own files rather than a copy and writes are
/// visible on both sides immediately. It is validated with the same rules as a
/// guest path -- absolute and lexically normalized -- because both must be.
pub struct VolumeSpec {
    #[n(0)]
    pub source: String,
    #[n(1)]
    pub destination: String,
    #[n(2)]
    pub read_only: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct Hello {
    #[n(0)]
    pub guest_contract_id: String,
    #[n(1)]
    pub init_build_id: String,
    #[n(2)]
    pub kernel_build_id: String,
    #[n(3)]
    pub host_elf_machine: u16,
    #[n(4)]
    pub guest_uts_machine: String,
    #[n(5)]
    pub guest_page_size: u32,
    #[n(6)]
    pub cpu_state_hwcap_policy: String,
    #[n(7)]
    pub features: Vec<String>,
    #[n(8)]
    pub online_cpus: u16,
    #[n(9)]
    pub accepted_physmem_bytes: u64,
    #[n(10)]
    pub guest_capability_policy: String,
}

impl ValidateMessage for Hello {
    fn validate(&self) -> Result<(), ProtocolError> {
        validate_sha256("guest_contract_id", &self.guest_contract_id)?;
        validate_sha256("init_build_id", &self.init_build_id)?;
        validate_sha256("kernel_build_id", &self.kernel_build_id)?;
        if !matches!(self.host_elf_machine, 62 | 183) {
            return invalid("host_elf_machine", "unsupported ELF machine");
        }
        if !matches!(self.guest_uts_machine.as_str(), "x86_64" | "aarch64") {
            return invalid("guest_uts_machine", "unsupported guest machine");
        }
        if !(4096..=65536).contains(&self.guest_page_size)
            || !self.guest_page_size.is_power_of_two()
        {
            return invalid("guest_page_size", "unsupported page size");
        }
        validate_token(
            "cpu_state_hwcap_policy",
            &self.cpu_state_hwcap_policy,
            MAX_ID_LENGTH,
        )?;
        validate_token(
            "guest_capability_policy",
            &self.guest_capability_policy,
            MAX_ID_LENGTH,
        )?;
        validate_count("features", self.features.len(), MAX_FEATURE_COUNT)?;
        let mut unique = BTreeSet::new();
        for feature in &self.features {
            validate_token("features", feature, 64)?;
            if !unique.insert(feature) {
                return invalid("features", "duplicate feature");
            }
        }
        if !(1..=64).contains(&self.online_cpus) {
            return invalid("online_cpus", "must be in 1..=64");
        }
        if self.accepted_physmem_bytes == 0
            || !self
                .accepted_physmem_bytes
                .is_multiple_of(u64::from(self.guest_page_size))
        {
            return invalid(
                "accepted_physmem_bytes",
                "must be nonzero and aligned to the guest page size",
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct Start {
    #[n(0)]
    pub profile_id: String,
    #[n(1)]
    pub profile_revision: String,
    #[n(2)]
    pub generation_id: String,
    #[n(3)]
    pub descriptor_platform: Option<Platform>,
    #[n(4)]
    pub config_platform: Platform,
    #[n(5)]
    pub effective_platform: Platform,
    #[n(6)]
    pub selector_policy: String,
    #[n(7)]
    pub root_layout: String,
    #[n(8)]
    pub filesystem_contract: String,
    #[n(9)]
    pub argv: Vec<String>,
    #[n(10)]
    pub env: Vec<String>,
    #[n(11)]
    pub cwd: String,
    #[n(12)]
    pub uid: u32,
    #[n(13)]
    pub gid: u32,
    #[n(14)]
    pub supplementary_gids: Vec<u32>,
    #[n(15)]
    pub umask: u16,
    #[n(16)]
    pub rlimits: Vec<ResourceLimit>,
    #[n(17)]
    pub hostname: String,
    #[n(18)]
    pub root_read_only: bool,
    #[n(19)]
    pub volumes: Vec<VolumeSpec>,
    #[n(20)]
    pub terminal: bool,
    #[n(21)]
    pub network_mode: u8,
    #[n(22)]
    pub stop_signal: u16,
    #[n(23)]
    pub derivation_key: String,
    #[n(24)]
    pub account_db_sha256: String,
    /// Exact number of bytes the host will write to the guest stdin channel.
    ///
    /// The guest forwards exactly this many bytes and then closes the
    /// workload's standard input. Channel end-of-file is never the terminator,
    /// because a User-Mode Linux serial line discards already-buffered input
    /// when the host end disappears.
    #[n(25)]
    pub stdin_bytes: u64,
}

impl ValidateMessage for Start {
    fn validate(&self) -> Result<(), ProtocolError> {
        validate_token("profile_id", &self.profile_id, MAX_ID_LENGTH)?;
        validate_sha256("profile_revision", &self.profile_revision)?;
        validate_sha256("generation_id", &self.generation_id)?;
        validate_sha256("derivation_key", &self.derivation_key)?;
        validate_sha256("account_db_sha256", &self.account_db_sha256)?;
        if let Some(descriptor_platform) = &self.descriptor_platform {
            descriptor_platform.validate("descriptor_platform")?;
        }
        self.config_platform.validate("config_platform")?;
        self.effective_platform.validate("effective_platform")?;
        validate_platform_agreement(self)?;
        validate_token("selector_policy", &self.selector_policy, MAX_ID_LENGTH)?;
        validate_token("root_layout", &self.root_layout, MAX_ID_LENGTH)?;
        validate_token(
            "filesystem_contract",
            &self.filesystem_contract,
            MAX_ID_LENGTH,
        )?;

        validate_count("argv", self.argv.len(), MAX_ARG_COUNT)?;
        if self.argv.is_empty() {
            return invalid("argv", "final argv must not be empty");
        }
        let mut argument_bytes = 0_usize;
        for (index, argument) in self.argv.iter().enumerate() {
            validate_text("argv", argument, MAX_ARG_LENGTH, index != 0)?;
            argument_bytes = argument_bytes.checked_add(argument.len()).ok_or(
                ProtocolError::MessageLimitExceeded {
                    field: "argv_total",
                    actual: usize::MAX,
                    maximum: MAX_CONTROL_PAYLOAD,
                },
            )?;
        }
        validate_count("argv_total", argument_bytes, MAX_CONTROL_PAYLOAD / 2)?;

        validate_count("env", self.env.len(), MAX_ENV_COUNT)?;
        let mut environment_bytes = 0_usize;
        for entry in &self.env {
            validate_text("env", entry, MAX_ENV_LENGTH, false)?;
            validate_environment(entry)?;
            environment_bytes = environment_bytes.checked_add(entry.len()).ok_or(
                ProtocolError::MessageLimitExceeded {
                    field: "env_total",
                    actual: usize::MAX,
                    maximum: MAX_CONTROL_PAYLOAD,
                },
            )?;
        }
        validate_count("env_total", environment_bytes, MAX_CONTROL_PAYLOAD / 2)?;
        validate_guest_path("cwd", &self.cwd, true)?;
        validate_count(
            "supplementary_gids",
            self.supplementary_gids.len(),
            MAX_SUPPLEMENTARY_GIDS,
        )?;
        if self.umask > 0o777 {
            return invalid("umask", "must fit Unix permission bits");
        }

        validate_count("rlimits", self.rlimits.len(), MAX_RLIMIT_COUNT)?;
        let mut resources = BTreeSet::new();
        for limit in &self.rlimits {
            if limit.resource > 15 {
                return invalid("rlimits", "resource number is unsupported");
            }
            if limit.soft > limit.hard {
                return invalid("rlimits", "soft limit exceeds hard limit");
            }
            if !resources.insert(limit.resource) {
                return invalid("rlimits", "duplicate resource limit");
            }
        }

        validate_text("hostname", &self.hostname, 64, false)?;
        if !self
            .hostname
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
        {
            return invalid("hostname", "contains unsupported character");
        }

        validate_count("volumes", self.volumes.len(), MAX_VOLUME_COUNT)?;
        let mut destinations = BTreeSet::new();
        for volume in &self.volumes {
            validate_guest_path("volume.source", &volume.source, false)?;
            validate_guest_path("volume.destination", &volume.destination, false)?;
            if reserved_guest_path_conflict(&volume.destination).is_some() {
                return invalid(
                    "volume.destination",
                    "collides with a path the runtime mounts or generates",
                );
            }
            if !destinations.insert(&volume.destination) {
                return invalid("volumes", "duplicate destination");
            }
        }
        if self.network_mode > 1 {
            return invalid("network_mode", "must be none(0) or slirp(1)");
        }
        if self.stdin_bytes > MAX_STDIN_BYTES {
            return invalid("stdin_bytes", "exceeds the synchronous input cap");
        }
        validate_signal("stop_signal", self.stop_signal)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct Ready {
    #[n(0)]
    pub guest_pid: u32,
    #[n(1)]
    pub effective_uid: u32,
    #[n(2)]
    pub effective_gid: u32,
    #[n(3)]
    pub cwd: String,
}

impl ValidateMessage for Ready {
    fn validate(&self) -> Result<(), ProtocolError> {
        if self.guest_pid == 0 {
            return invalid("guest_pid", "must be nonzero");
        }
        validate_guest_path("cwd", &self.cwd, true)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct Exit {
    #[n(0)]
    pub code: Option<u8>,
    #[n(1)]
    pub signal: Option<u16>,
    #[n(2)]
    pub elapsed_ns: u64,
    #[n(3)]
    pub filesystem_clean: bool,
}

impl ValidateMessage for Exit {
    fn validate(&self) -> Result<(), ProtocolError> {
        match (self.code, self.signal) {
            (Some(_), None) => Ok(()),
            (None, Some(signal)) => validate_signal("signal", signal),
            _ => invalid("exit_status", "exactly one of code or signal is required"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct ErrorMessage {
    #[n(0)]
    pub stage: String,
    #[n(1)]
    pub stable_code: u16,
    #[n(2)]
    pub errno: Option<i32>,
    #[n(3)]
    pub diagnostic: String,
}

impl ErrorMessage {
    #[must_use]
    pub fn new(
        stage: impl Into<String>,
        stable_code: ErrorCode,
        errno: Option<i32>,
        diagnostic: impl Into<String>,
    ) -> Self {
        Self {
            stage: stage.into(),
            stable_code: stable_code as u16,
            errno,
            diagnostic: diagnostic.into(),
        }
    }

    pub fn code(&self) -> Result<ErrorCode, ProtocolError> {
        ErrorCode::from_u16(self.stable_code).map_err(|_| ProtocolError::InvalidMessage {
            field: "stable_code",
            reason: "unknown stable error code",
        })
    }
}

impl ValidateMessage for ErrorMessage {
    fn validate(&self) -> Result<(), ProtocolError> {
        validate_token("stage", &self.stage, 64)?;
        let _ = self.code()?;
        if let Some(errno) = self.errno
            && !(1..=4095).contains(&errno)
        {
            return invalid("errno", "must be a positive Linux errno");
        }
        validate_text("diagnostic", &self.diagnostic, MAX_DIAGNOSTIC_LENGTH, true)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct Signal {
    #[n(0)]
    pub signal: u16,
}

impl ValidateMessage for Signal {
    fn validate(&self) -> Result<(), ProtocolError> {
        validate_signal("signal", self.signal)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct Resize {
    #[n(0)]
    pub rows: u16,
    #[n(1)]
    pub columns: u16,
}

/// Request deterministic forced termination and bounded namespace drain.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct Shutdown {
    #[n(0)]
    pub grace_ms: u32,
}

impl ValidateMessage for Shutdown {
    fn validate(&self) -> Result<(), ProtocolError> {
        if self.grace_ms == 0 || self.grace_ms > MAX_SHUTDOWN_GRACE_MS {
            return invalid("grace_ms", "must be in 1..=600000 milliseconds");
        }
        Ok(())
    }
}

impl ValidateMessage for Resize {
    fn validate(&self) -> Result<(), ProtocolError> {
        if self.rows == 0 || self.columns == 0 {
            return invalid("terminal_size", "rows and columns must be nonzero");
        }
        if self.rows > 16384 || self.columns > 16384 {
            return invalid("terminal_size", "rows or columns exceed hard cap");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkloadMessage {
    Hello(Hello),
    Start(Box<Start>),
    Ready(Ready),
    Exit(Exit),
    Error(ErrorMessage),
    Signal(Signal),
    Resize(Resize),
    Shutdown(Shutdown),
}

impl WorkloadMessage {
    #[must_use]
    pub const fn kind(&self) -> MessageKind {
        match self {
            Self::Hello(_) => MessageKind::Hello,
            Self::Start(_) => MessageKind::Start,
            Self::Ready(_) => MessageKind::Ready,
            Self::Exit(_) => MessageKind::Exit,
            Self::Error(_) => MessageKind::Error,
            Self::Signal(_) => MessageKind::Signal,
            Self::Resize(_) => MessageKind::Resize,
            Self::Shutdown(_) => MessageKind::Shutdown,
        }
    }

    pub fn encode_payload(&self) -> Result<Vec<u8>, ProtocolError> {
        match self {
            Self::Hello(message) => encode_payload(message),
            Self::Start(message) => encode_payload(message.as_ref()),
            Self::Ready(message) => encode_payload(message),
            Self::Exit(message) => encode_payload(message),
            Self::Error(message) => encode_payload(message),
            Self::Signal(message) => encode_payload(message),
            Self::Resize(message) => encode_payload(message),
            Self::Shutdown(message) => encode_payload(message),
        }
    }
}

pub fn encode_payload<T>(message: &T) -> Result<Vec<u8>, ProtocolError>
where
    T: Encode<()> + ValidateMessage,
{
    message.validate()?;
    let payload = minicbor::to_vec(message).map_err(|error| ProtocolError::CborMalformed {
        diagnostic: error.to_string(),
    })?;
    validate_count("payload", payload.len(), MAX_CONTROL_PAYLOAD)?;
    Ok(payload)
}

/// Decode, validate, and require byte-for-byte deterministic re-encoding.
/// This rejects indefinite collections, reordered or duplicate map keys,
/// non-minimal integers, unknown fields, and trailing CBOR items.
pub fn decode_payload<T>(payload: &[u8]) -> Result<T, ProtocolError>
where
    T: for<'bytes> Decode<'bytes, ()> + Encode<()> + ValidateMessage,
{
    validate_count("payload", payload.len(), MAX_CONTROL_PAYLOAD)?;
    let mut decoder = Decoder::new(payload);
    let mut context = ();
    let message =
        T::decode(&mut decoder, &mut context).map_err(|error| ProtocolError::CborMalformed {
            diagnostic: error.to_string(),
        })?;
    if decoder.position() != payload.len() {
        return Err(ProtocolError::TrailingData {
            remaining: payload.len() - decoder.position(),
        });
    }
    message.validate()?;
    let canonical = minicbor::to_vec(&message).map_err(|error| ProtocolError::CborMalformed {
        diagnostic: error.to_string(),
    })?;
    if canonical != payload {
        return Err(ProtocolError::CborNonCanonical);
    }
    Ok(message)
}

pub fn decode_workload_message(frame: &RawFrame) -> Result<WorkloadMessage, ProtocolError> {
    match frame.header.kind {
        MessageKind::Hello => decode_payload(&frame.payload).map(WorkloadMessage::Hello),
        MessageKind::Start => decode_payload(&frame.payload)
            .map(Box::new)
            .map(WorkloadMessage::Start),
        MessageKind::Ready => decode_payload(&frame.payload).map(WorkloadMessage::Ready),
        MessageKind::Exit => decode_payload(&frame.payload).map(WorkloadMessage::Exit),
        MessageKind::Error => decode_payload(&frame.payload).map(WorkloadMessage::Error),
        MessageKind::Signal => decode_payload(&frame.payload).map(WorkloadMessage::Signal),
        MessageKind::Resize => decode_payload(&frame.payload).map(WorkloadMessage::Resize),
        MessageKind::Shutdown => decode_payload(&frame.payload).map(WorkloadMessage::Shutdown),
        MessageKind::BuildHello
        | MessageKind::BuildStart
        | MessageKind::ManifestBegin
        | MessageKind::ManifestChunk
        | MessageKind::ManifestEnd
        | MessageKind::BuildDone
        | MessageKind::BuildError
        | MessageKind::AccountDb
        | MessageKind::ValidateHello
        | MessageKind::ValidateStart
        | MessageKind::ValidateDone
        | MessageKind::ValidateError => {
            invalid("kind", "non-workload message in workload protocol")
        }
    }
}

pub(crate) fn validate_count(
    field: &'static str,
    actual: usize,
    maximum: usize,
) -> Result<(), ProtocolError> {
    if actual > maximum {
        return Err(ProtocolError::MessageLimitExceeded {
            field,
            actual,
            maximum,
        });
    }
    Ok(())
}

pub(crate) fn validate_text(
    field: &'static str,
    value: &str,
    maximum: usize,
    empty_allowed: bool,
) -> Result<(), ProtocolError> {
    validate_count(field, value.len(), maximum)?;
    if !empty_allowed && value.is_empty() {
        return invalid(field, "must not be empty");
    }
    if value.contains('\0') {
        return invalid(field, "contains NUL");
    }
    Ok(())
}

pub(crate) fn validate_token(
    field: &'static str,
    value: &str,
    maximum: usize,
) -> Result<(), ProtocolError> {
    validate_text(field, value, maximum, false)?;
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return invalid(field, "contains a non-token character");
    }
    Ok(())
}

pub(crate) fn validate_sha256(field: &'static str, value: &str) -> Result<(), ProtocolError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return invalid(field, "must be 64 lowercase hexadecimal characters");
    }
    Ok(())
}

fn validate_environment(entry: &str) -> Result<(), ProtocolError> {
    let Some((key, _value)) = entry.split_once('=') else {
        return invalid("env", "entry must contain '='");
    };
    if key.is_empty() {
        return invalid("env", "key must not be empty");
    }
    if key.bytes().any(|byte| byte == b'=' || byte == 0) {
        return invalid("env", "invalid key");
    }
    Ok(())
}

fn validate_guest_path(
    field: &'static str,
    value: &str,
    root_allowed: bool,
) -> Result<(), ProtocolError> {
    validate_text(field, value, MAX_PATH_LENGTH, false)?;
    if !Path::new(value).is_absolute() {
        return invalid(field, "must be absolute");
    }
    let Some(relative) = value.strip_prefix('/') else {
        return invalid(field, "must be absolute");
    };
    if relative.is_empty() {
        return if root_allowed {
            Ok(())
        } else {
            invalid(field, "filesystem root is not allowed here")
        };
    }
    if relative
        .split('/')
        .any(|segment| segment.is_empty() || matches!(segment, "." | ".."))
    {
        return invalid(field, "must use normalized lexical form");
    }
    Ok(())
}

fn validate_signal(field: &'static str, signal: u16) -> Result<(), ProtocolError> {
    if !(1..=64).contains(&signal) {
        return invalid(field, "must be in 1..=64");
    }
    Ok(())
}

fn validate_platform_agreement(start: &Start) -> Result<(), ProtocolError> {
    let config = &start.config_platform;
    let effective = &start.effective_platform;
    if config.os != effective.os || config.architecture != effective.architecture {
        return invalid("platform", "OS or architecture fields disagree");
    }

    if let Some(descriptor) = &start.descriptor_platform {
        if descriptor.os != config.os || descriptor.architecture != config.architecture {
            return invalid("platform", "OS or architecture fields disagree");
        }
        if let (Some(descriptor_variant), Some(config_variant)) =
            (&descriptor.variant, &config.variant)
            && descriptor_variant != config_variant
        {
            return invalid("platform", "explicit variants disagree");
        }
    }
    let selected_variant = start
        .descriptor_platform
        .as_ref()
        .and_then(|platform| platform.variant.as_ref())
        .or(config.variant.as_ref());
    if selected_variant != effective.variant.as_ref() {
        return invalid("effective_platform", "variant does not match raw fields");
    }
    Ok(())
}

pub(crate) fn invalid<T>(field: &'static str, reason: &'static str) -> Result<T, ProtocolError> {
    Err(ProtocolError::InvalidMessage { field, reason })
}

#[cfg(test)]
mod tests {
    use pocket_core::ErrorCode;

    use super::{
        ErrorMessage, Exit, Hello, MAX_SHUTDOWN_GRACE_MS, MAX_STDIN_BYTES, Platform, Ready, Resize,
        ResourceLimit, Shutdown, Signal, Start, ValidateMessage, VolumeSpec, WorkloadMessage,
        decode_payload, decode_workload_message, encode_payload, reserved_guest_path_conflict,
    };
    use crate::{FrameHeader, MessageKind, ProtocolError, RawFrame};

    fn digest(character: char) -> String {
        character.to_string().repeat(64)
    }

    fn platform(variant: Option<&str>) -> Platform {
        Platform {
            os: "linux".to_owned(),
            architecture: "amd64".to_owned(),
            variant: variant.map(str::to_owned),
        }
    }

    fn hello() -> Hello {
        Hello {
            guest_contract_id: digest('a'),
            init_build_id: digest('b'),
            kernel_build_id: digest('c'),
            host_elf_machine: 62,
            guest_uts_machine: "x86_64".to_owned(),
            guest_page_size: 4096,
            cpu_state_hwcap_policy: "x86_64-v1".to_owned(),
            features: vec!["cow-v1".to_owned(), "stdio-v1".to_owned()],
            online_cpus: 2,
            accepted_physmem_bytes: 256 * 1024 * 1024,
            guest_capability_policy: "fixed-capabilities-v1".to_owned(),
        }
    }

    fn start() -> Start {
        Start {
            profile_id: "x86_64-smp-p4k".to_owned(),
            profile_revision: digest('d'),
            generation_id: digest('e'),
            descriptor_platform: Some(platform(Some("v1"))),
            config_platform: platform(Some("v1")),
            effective_platform: platform(Some("v1")),
            selector_policy: "oci-amd64-v1".to_owned(),
            root_layout: "rootfs-v1".to_owned(),
            filesystem_contract: "ext4-v1-b4096".to_owned(),
            argv: vec!["/bin/sh".to_owned(), "-c".to_owned(), "echo ok".to_owned()],
            env: vec!["PATH=/usr/bin:/bin".to_owned(), "LANG=C".to_owned()],
            cwd: "/workspace".to_owned(),
            uid: 0,
            gid: 0,
            supplementary_gids: vec![],
            umask: 0o022,
            rlimits: vec![ResourceLimit {
                resource: 7,
                soft: 1024,
                hard: 4096,
            }],
            hostname: "pocket".to_owned(),
            root_read_only: false,
            volumes: vec![VolumeSpec {
                source: "/srv/shared".to_owned(),
                destination: "/data".to_owned(),
                read_only: false,
            }],
            terminal: false,
            network_mode: 0,
            stop_signal: 15,
            derivation_key: digest('f'),
            account_db_sha256: digest('9'),
            stdin_bytes: 13,
        }
    }

    fn require_round_trip<T>(value: &T)
    where
        T: minicbor::Encode<()>
            + for<'bytes> minicbor::Decode<'bytes, ()>
            + ValidateMessage
            + PartialEq
            + std::fmt::Debug,
    {
        let encoded = match encode_payload(value) {
            Ok(encoded) => encoded,
            Err(error) => panic!("encoding failed: {error}"),
        };
        let decoded: T = match decode_payload(&encoded) {
            Ok(decoded) => decoded,
            Err(error) => panic!("decoding failed: {error}"),
        };
        assert_eq!(&decoded, value);
        let reencoded = match encode_payload(&decoded) {
            Ok(encoded) => encoded,
            Err(error) => panic!("re-encoding failed: {error}"),
        };
        assert_eq!(reencoded, encoded);
    }

    #[test]
    fn every_workload_schema_round_trips_deterministically() {
        require_round_trip(&hello());
        require_round_trip(&start());
        require_round_trip(&Ready {
            guest_pid: 1,
            effective_uid: 0,
            effective_gid: 0,
            cwd: "/workspace".to_owned(),
        });
        require_round_trip(&Exit {
            code: Some(0),
            signal: None,
            elapsed_ns: 123,
            filesystem_clean: true,
        });
        require_round_trip(&ErrorMessage::new(
            "exec",
            ErrorCode::ProtocolInvalidMessage,
            Some(2),
            "file not found",
        ));
        require_round_trip(&Signal { signal: 15 });
        require_round_trip(&Resize {
            rows: 24,
            columns: 80,
        });
        require_round_trip(&Shutdown { grace_ms: 10_000 });
    }

    #[test]
    fn workload_start_rejects_pre_exact_stdin_length_schema() {
        let mut encoded = encode_payload(&start()).expect("encode current START");
        assert_eq!(&encoded[..2], &[0xb8, 26], "START must remain a 26-key map");
        // Key 25 needs two bytes and the 13-byte fixture length needs one.
        let appended_field_bytes = 2 + 1;
        let appended_offset = encoded.len() - appended_field_bytes;
        assert_eq!(
            &encoded[appended_offset..appended_offset + 2],
            &[24, 25],
            "stdin length must be last"
        );
        encoded.truncate(appended_offset);
        encoded[1] = 25;
        assert!(decode_payload::<Start>(&encoded).is_err());
    }

    #[test]
    fn workload_start_rejects_pre_account_database_schema() {
        let mut encoded = encode_payload(&start()).expect("encode current START");
        let appended_field_bytes = (2 + 1) + (1 + 2 + 64);
        let appended_offset = encoded.len() - appended_field_bytes;
        assert_eq!(
            encoded[appended_offset], 24,
            "account digest precedes stdin"
        );
        encoded.truncate(appended_offset);
        encoded[1] = 24;
        assert!(decode_payload::<Start>(&encoded).is_err());
    }

    #[test]
    fn workload_start_rejects_an_oversized_stdin_length() {
        let mut oversized = start();
        oversized.stdin_bytes = MAX_STDIN_BYTES + 1;
        assert!(oversized.validate().is_err());
        oversized.stdin_bytes = MAX_STDIN_BYTES;
        assert!(oversized.validate().is_ok());
    }

    #[test]
    fn dynamic_workload_decode_uses_header_kind() {
        let payload = match encode_payload(&hello()) {
            Ok(payload) => payload,
            Err(error) => panic!("encoding failed: {error}"),
        };
        let header = match FrameHeader::new(MessageKind::Hello, payload.len(), 0) {
            Ok(header) => header,
            Err(error) => panic!("header failed: {error}"),
        };
        let message = match decode_workload_message(&RawFrame { header, payload }) {
            Ok(message) => message,
            Err(error) => panic!("decode failed: {error}"),
        };
        assert!(matches!(message, WorkloadMessage::Hello(_)));
    }

    #[test]
    fn rejects_trailing_and_noncanonical_cbor() {
        let mut trailing = match encode_payload(&Signal { signal: 15 }) {
            Ok(payload) => payload,
            Err(error) => panic!("encoding failed: {error}"),
        };
        trailing.push(0);
        assert!(matches!(
            decode_payload::<Signal>(&trailing),
            Err(ProtocolError::TrailingData { remaining: 1 })
        ));

        // Indefinite map containing the otherwise valid field 0 -> 15.
        let indefinite = [0xbf, 0x00, 0x0f, 0xff];
        assert!(matches!(
            decode_payload::<Signal>(&indefinite),
            Err(ProtocolError::CborNonCanonical)
        ));
    }

    #[test]
    fn malformed_payloads_return_errors_without_panicking() {
        let malformed_cases: [&[u8]; 5] = [
            &[],
            &[0xff],
            &[0xa1],
            &[0xa1, 0x00],
            &[0x9a, 0xff, 0xff, 0xff, 0xff],
        ];
        for payload in malformed_cases {
            assert!(decode_payload::<Hello>(payload).is_err());
        }
    }

    #[test]
    fn validates_schema_boundaries() {
        let mut invalid_hello = hello();
        invalid_hello.online_cpus = 0;
        assert!(invalid_hello.validate().is_err());

        let mut invalid_start = start();
        invalid_start.argv.clear();
        assert!(invalid_start.validate().is_err());

        let mut invalid_start = start();
        invalid_start.cwd = "relative".to_owned();
        assert!(invalid_start.validate().is_err());

        let mut invalid_start = start();
        invalid_start.config_platform.variant = Some("v2".to_owned());
        assert!(invalid_start.validate().is_err());

        let mut direct_manifest = start();
        direct_manifest.descriptor_platform = None;
        assert!(direct_manifest.validate().is_ok());
        require_round_trip(&direct_manifest);

        let mut root_cwd = start();
        root_cwd.cwd = "/".to_owned();
        assert!(root_cwd.validate().is_ok());

        let invalid_exit = Exit {
            code: Some(1),
            signal: Some(9),
            elapsed_ns: 0,
            filesystem_clean: false,
        };
        assert!(invalid_exit.validate().is_err());

        assert!(
            Resize {
                rows: 0,
                columns: 80
            }
            .validate()
            .is_err()
        );
        assert!(Signal { signal: 0 }.validate().is_err());
        assert!(Shutdown { grace_ms: 0 }.validate().is_err());
        assert!(
            Shutdown {
                grace_ms: MAX_SHUTDOWN_GRACE_MS + 1,
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn oversized_fields_fail_before_encoding() {
        let mut message = hello();
        message.features = (0..65).map(|index| format!("f{index}")).collect();
        assert!(matches!(
            encode_payload(&message),
            Err(ProtocolError::MessageLimitExceeded {
                field: "features",
                actual: 65,
                maximum: 64
            })
        ));
    }

    /// The rule is symmetric: a destination under a runtime mount is shadowed
    /// by it, and one containing a generated file has that file written into
    /// the caller's own directory. Both are collisions; a sibling is not.
    #[test]
    fn reserved_guest_paths_collide_in_both_directions() {
        for (destination, expected) in [
            ("/dev", Some("/dev")),
            ("/dev/shm", Some("/dev")),
            ("/proc", Some("/proc")),
            ("/run/x/y", Some("/run")),
            ("/etc", Some("/etc/hostname")),
            ("/etc/hosts", Some("/etc/hosts")),
            ("/etc/myconfig", None),
            ("/devices", None),
            ("/etc/hostnames", None),
            ("/var/lib/data", None),
        ] {
            assert_eq!(
                reserved_guest_path_conflict(destination),
                expected,
                "{destination}"
            );
        }
    }
}
