use std::collections::BTreeSet;

use minicbor::{Decode, Encode};
use pocket_core::ErrorCode;
use sha2::{Digest as _, Sha256};

use crate::{
    ErrorMessage, MAX_CONTROL_PAYLOAD, MAX_DIAGNOSTIC_LENGTH, MAX_ID_LENGTH, MessageKind, Platform,
    ProtocolError, RawFrame, ValidateMessage, decode_payload, encode_payload,
    message::{invalid, validate_count, validate_sha256, validate_text, validate_token},
};

pub const MAX_BUILDER_TOOLS: usize = 16;
pub const MAX_BUILDER_LAYERS: usize = 512;
pub const MAX_MEDIA_TYPE_LENGTH: usize = 256;
pub const MAX_ORIGINAL_USER_LENGTH: usize = 1024;
pub const MAX_MANIFEST_CHUNK_BYTES: usize = 192 * 1024;
pub const MAX_MANIFEST_ENTRY_BYTES: usize = 128 * 1024;
pub const MAX_MANIFEST_PATH_BYTES: usize = 4096;
pub const MAX_MANIFEST_XATTRS: usize = 128;
pub const MAX_MANIFEST_XATTR_BYTES: usize = 64 * 1024;
pub const MAX_MANIFEST_ENTRIES: u64 = 1_000_000;
pub const MAX_MANIFEST_BYTES: u64 = 16 * 1024 * 1024 * 1024;
pub const MAX_MANIFEST_DIRECTORY_ENTRIES: u32 = 131_072;
pub const MAX_MANIFEST_DIRECTORY_NAME_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_MANIFEST_HARDLINK_GROUPS: u32 = 131_072;
pub const MAX_MANIFEST_HARDLINK_PATH_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_MANIFEST_DEPTH: u16 = 256;
pub const MAX_LAYER_COMPRESSED_BYTES: u64 = 128 * 1024 * 1024 * 1024;
pub const MAX_LAYER_UNCOMPRESSED_BYTES: u64 = 64 * 1024 * 1024 * 1024;
pub const MAX_TOTAL_UNCOMPRESSED_BYTES: u64 = 256 * 1024 * 1024 * 1024;
pub const MAX_ACCOUNT_DB_BYTES: usize = 192 * 1024;
pub const MAX_ACCOUNT_USERS: usize = 8_192;
pub const MAX_ACCOUNT_GROUPS: usize = 8_192;
pub const MAX_ACCOUNT_NAME_BYTES: usize = 256;
pub const MAX_ACCOUNT_GROUP_MEMBERS: usize = 4_096;
pub const MAX_ACCOUNT_MEMBERSHIPS: usize = 65_536;
pub const ACCOUNT_DB_SCHEMA: &str = "pocket-accounts-v1";
/// Earliest admitted build epoch (2000-01-01T00:00:00Z).
pub const SOURCE_DATE_EPOCH_MIN: u64 = 946_684_800;
/// Latest admitted build epoch (2100-01-01T00:00:00Z).
pub const SOURCE_DATE_EPOCH_MAX: u64 = 4_102_444_800;

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct ToolIdentity {
    #[n(0)]
    pub role: String,
    #[n(1)]
    pub sha256: String,
    #[n(2)]
    pub version: String,
}

impl ToolIdentity {
    fn validate(&self) -> Result<(), ProtocolError> {
        validate_token("tool.role", &self.role, 64)?;
        validate_sha256("tool.sha256", &self.sha256)?;
        validate_text("tool.version", &self.version, 256, false)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct BuilderHello {
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
    pub online_cpus: u16,
    #[n(8)]
    pub builder_tools: Vec<ToolIdentity>,
    #[n(9)]
    pub features: Vec<String>,
    #[n(10)]
    pub accepted_physmem_bytes: u64,
}

impl ValidateMessage for BuilderHello {
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
        if self.online_cpus != 1 {
            return invalid("online_cpus", "builder must have exactly one online CPU");
        }
        validate_builder_memory("accepted_physmem_bytes", self.accepted_physmem_bytes)?;
        if !self
            .accepted_physmem_bytes
            .is_multiple_of(u64::from(self.guest_page_size))
        {
            return invalid(
                "accepted_physmem_bytes",
                "must be aligned to the reported guest page size",
            );
        }
        validate_tools(&self.builder_tools, "builder_tools")?;
        validate_count("features", self.features.len(), 32)?;
        let mut features = BTreeSet::new();
        for feature in &self.features {
            validate_token("features", feature, 64)?;
            if !features.insert(feature) {
                return invalid("features", "duplicate feature");
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct OciDescriptor {
    #[n(0)]
    pub digest: String,
    #[n(1)]
    pub size: u64,
    #[n(2)]
    pub media_type: String,
}

impl OciDescriptor {
    fn validate(&self, field: &'static str, maximum_size: u64) -> Result<(), ProtocolError> {
        validate_oci_digest(field, &self.digest)?;
        if self.size == 0 || self.size > maximum_size {
            return invalid(field, "descriptor size is zero or exceeds its hard cap");
        }
        validate_media_type(field, &self.media_type)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct BuilderLayerDescriptor {
    #[n(0)]
    pub descriptor: OciDescriptor,
    #[n(1)]
    pub diff_id: String,
    #[n(2)]
    pub uncompressed_size: u64,
}

impl BuilderLayerDescriptor {
    fn validate(&self) -> Result<(), ProtocolError> {
        self.descriptor
            .validate("layers.descriptor", MAX_LAYER_COMPRESSED_BYTES)?;
        validate_oci_digest("layers.diff_id", &self.diff_id)?;
        if self.uncompressed_size > MAX_LAYER_UNCOMPRESSED_BYTES {
            return invalid("layers.uncompressed_size", "exceeds hard cap");
        }
        if self.uncompressed_size > self.descriptor.size.saturating_mul(1024) {
            return invalid(
                "layers.uncompressed_size",
                "exceeds the fixed decompression-ratio cap",
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct ManifestLimits {
    #[n(0)]
    pub max_path_bytes: u32,
    #[n(1)]
    pub max_xattrs_per_entry: u16,
    #[n(2)]
    pub max_xattr_bytes_per_entry: u32,
    #[n(3)]
    pub max_entry_bytes: u32,
    #[n(4)]
    pub max_chunk_bytes: u32,
    #[n(5)]
    pub max_entries: u64,
    #[n(6)]
    pub max_total_bytes: u64,
    #[n(7)]
    pub max_directory_entries: u32,
    #[n(8)]
    pub max_directory_name_bytes: u64,
    #[n(9)]
    pub max_hardlink_groups: u32,
    #[n(10)]
    pub max_hardlink_path_bytes: u64,
    #[n(11)]
    pub max_depth: u16,
}

impl Default for ManifestLimits {
    fn default() -> Self {
        Self {
            max_path_bytes: MAX_MANIFEST_PATH_BYTES as u32,
            max_xattrs_per_entry: MAX_MANIFEST_XATTRS as u16,
            max_xattr_bytes_per_entry: MAX_MANIFEST_XATTR_BYTES as u32,
            max_entry_bytes: MAX_MANIFEST_ENTRY_BYTES as u32,
            max_chunk_bytes: MAX_MANIFEST_CHUNK_BYTES as u32,
            max_entries: MAX_MANIFEST_ENTRIES,
            max_total_bytes: MAX_MANIFEST_BYTES,
            max_directory_entries: MAX_MANIFEST_DIRECTORY_ENTRIES,
            max_directory_name_bytes: MAX_MANIFEST_DIRECTORY_NAME_BYTES,
            max_hardlink_groups: MAX_MANIFEST_HARDLINK_GROUPS,
            max_hardlink_path_bytes: MAX_MANIFEST_HARDLINK_PATH_BYTES,
            max_depth: MAX_MANIFEST_DEPTH,
        }
    }
}

impl ManifestLimits {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.max_path_bytes == 0 || self.max_path_bytes as usize > MAX_MANIFEST_PATH_BYTES {
            return invalid("manifest_limits.max_path_bytes", "outside supported range");
        }
        if self.max_xattrs_per_entry as usize > MAX_MANIFEST_XATTRS {
            return invalid("manifest_limits.max_xattrs_per_entry", "exceeds hard cap");
        }
        if self.max_xattr_bytes_per_entry as usize > MAX_MANIFEST_XATTR_BYTES {
            return invalid(
                "manifest_limits.max_xattr_bytes_per_entry",
                "exceeds hard cap",
            );
        }
        let max_entry = self.max_entry_bytes as usize;
        let max_chunk = self.max_chunk_bytes as usize;
        if max_entry == 0 || max_entry > MAX_MANIFEST_ENTRY_BYTES {
            return invalid("manifest_limits.max_entry_bytes", "outside supported range");
        }
        if !(4..=MAX_MANIFEST_CHUNK_BYTES).contains(&max_chunk) {
            return invalid("manifest_limits.max_chunk_bytes", "outside supported range");
        }
        if max_entry
            .checked_add(4)
            .is_none_or(|value| value > max_chunk)
        {
            return invalid(
                "manifest_limits.max_entry_bytes",
                "one length-prefixed entry must fit in a chunk",
            );
        }
        if self.max_entries == 0 || self.max_entries > MAX_MANIFEST_ENTRIES {
            return invalid("manifest_limits.max_entries", "outside supported range");
        }
        if self.max_total_bytes == 0 || self.max_total_bytes > MAX_MANIFEST_BYTES {
            return invalid("manifest_limits.max_total_bytes", "outside supported range");
        }
        if self.max_directory_entries == 0
            || self.max_directory_entries > MAX_MANIFEST_DIRECTORY_ENTRIES
        {
            return invalid(
                "manifest_limits.max_directory_entries",
                "outside supported range",
            );
        }
        if self.max_directory_name_bytes == 0
            || self.max_directory_name_bytes > MAX_MANIFEST_DIRECTORY_NAME_BYTES
        {
            return invalid(
                "manifest_limits.max_directory_name_bytes",
                "outside supported range",
            );
        }
        if self.max_hardlink_groups == 0 || self.max_hardlink_groups > MAX_MANIFEST_HARDLINK_GROUPS
        {
            return invalid(
                "manifest_limits.max_hardlink_groups",
                "outside supported range",
            );
        }
        if self.max_hardlink_path_bytes == 0
            || self.max_hardlink_path_bytes > MAX_MANIFEST_HARDLINK_PATH_BYTES
        {
            return invalid(
                "manifest_limits.max_hardlink_path_bytes",
                "outside supported range",
            );
        }
        if self.max_depth == 0 || self.max_depth > MAX_MANIFEST_DEPTH {
            return invalid("manifest_limits.max_depth", "outside supported range");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct BuilderStart {
    #[n(0)]
    pub profile_id: String,
    #[n(1)]
    pub profile_revision: String,
    #[n(2)]
    pub derivation_key: String,
    #[n(3)]
    pub selected_manifest: OciDescriptor,
    #[n(4)]
    pub config: OciDescriptor,
    #[n(5)]
    pub layers: Vec<BuilderLayerDescriptor>,
    #[n(6)]
    pub descriptor_platform: Option<Platform>,
    #[n(7)]
    pub config_platform: Platform,
    #[n(8)]
    pub effective_platform: Platform,
    #[n(9)]
    pub selector_policy: String,
    #[n(10)]
    pub root_layout: String,
    #[n(11)]
    pub filesystem_contract: String,
    #[n(12)]
    pub manifest_schema: String,
    #[n(13)]
    pub manifest_limits: ManifestLimits,
    #[n(14)]
    pub expected_tools: Vec<ToolIdentity>,
    #[n(15)]
    pub input_reference: String,
    #[n(16)]
    pub original_user: String,
    #[n(17)]
    pub expected_physmem_bytes: u64,
    #[n(18)]
    pub source_date_epoch: u64,
}

impl ValidateMessage for BuilderStart {
    fn validate(&self) -> Result<(), ProtocolError> {
        validate_token("profile_id", &self.profile_id, MAX_ID_LENGTH)?;
        validate_sha256("profile_revision", &self.profile_revision)?;
        validate_sha256("derivation_key", &self.derivation_key)?;
        self.selected_manifest
            .validate("selected_manifest", 4 * 1024 * 1024)?;
        self.config.validate("config", 16 * 1024 * 1024)?;
        validate_count("layers", self.layers.len(), MAX_BUILDER_LAYERS)?;
        let mut total_uncompressed = 0_u64;
        for layer in &self.layers {
            layer.validate()?;
            total_uncompressed = total_uncompressed
                .checked_add(layer.uncompressed_size)
                .ok_or(ProtocolError::MessageLimitExceeded {
                    field: "layers.uncompressed_total",
                    actual: usize::MAX,
                    maximum: usize::MAX,
                })?;
        }
        if total_uncompressed > MAX_TOTAL_UNCOMPRESSED_BYTES {
            return invalid("layers.uncompressed_total", "exceeds hard cap");
        }
        if let Some(platform) = &self.descriptor_platform {
            platform.validate("descriptor_platform")?;
        }
        self.config_platform.validate("config_platform")?;
        self.effective_platform.validate("effective_platform")?;
        validate_platforms(
            self.descriptor_platform.as_ref(),
            &self.config_platform,
            &self.effective_platform,
        )?;
        validate_token("selector_policy", &self.selector_policy, MAX_ID_LENGTH)?;
        validate_token("root_layout", &self.root_layout, MAX_ID_LENGTH)?;
        validate_token(
            "filesystem_contract",
            &self.filesystem_contract,
            MAX_ID_LENGTH,
        )?;
        validate_token("manifest_schema", &self.manifest_schema, MAX_ID_LENGTH)?;
        self.manifest_limits.validate()?;
        validate_tools(&self.expected_tools, "expected_tools")?;
        validate_token("input_reference", &self.input_reference, 128)?;
        if self.input_reference != "root" {
            return invalid(
                "input_reference",
                "only the canonical root reference is supported",
            );
        }
        validate_text(
            "original_user",
            &self.original_user,
            MAX_ORIGINAL_USER_LENGTH,
            true,
        )?;
        validate_builder_memory("expected_physmem_bytes", self.expected_physmem_bytes)?;
        if !(SOURCE_DATE_EPOCH_MIN..=SOURCE_DATE_EPOCH_MAX).contains(&self.source_date_epoch) {
            return invalid(
                "source_date_epoch",
                "must be a pinned Unix timestamp from 2000-01-01 through 2100-01-01",
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct GenerationMarker {
    #[n(0)]
    pub schema: String,
    #[n(1)]
    pub derivation_key: String,
    #[n(2)]
    pub profile_id: String,
    #[n(3)]
    pub profile_revision: String,
    #[n(4)]
    pub descriptor_platform: Option<Platform>,
    #[n(5)]
    pub config_platform: Platform,
    #[n(6)]
    pub effective_platform: Platform,
    #[n(7)]
    pub selector_policy: String,
    #[n(8)]
    pub root_layout: String,
    #[n(9)]
    pub filesystem_contract: String,
    #[n(10)]
    pub account_db_sha256: String,
}

impl GenerationMarker {
    #[must_use]
    pub fn from_start(start: &BuilderStart, account_db_sha256: String) -> Self {
        Self {
            schema: "pocket-generation-v3".to_owned(),
            derivation_key: start.derivation_key.clone(),
            profile_id: start.profile_id.clone(),
            profile_revision: start.profile_revision.clone(),
            descriptor_platform: start.descriptor_platform.clone(),
            config_platform: start.config_platform.clone(),
            effective_platform: start.effective_platform.clone(),
            selector_policy: start.selector_policy.clone(),
            root_layout: start.root_layout.clone(),
            filesystem_contract: start.filesystem_contract.clone(),
            account_db_sha256,
        }
    }
}

impl ValidateMessage for GenerationMarker {
    fn validate(&self) -> Result<(), ProtocolError> {
        if self.schema != "pocket-generation-v3" {
            return invalid("schema", "unsupported generation-marker schema");
        }
        validate_sha256("derivation_key", &self.derivation_key)?;
        validate_token("profile_id", &self.profile_id, MAX_ID_LENGTH)?;
        validate_sha256("profile_revision", &self.profile_revision)?;
        if let Some(platform) = &self.descriptor_platform {
            platform.validate("descriptor_platform")?;
        }
        self.config_platform.validate("config_platform")?;
        self.effective_platform.validate("effective_platform")?;
        validate_platforms(
            self.descriptor_platform.as_ref(),
            &self.config_platform,
            &self.effective_platform,
        )?;
        validate_token("selector_policy", &self.selector_policy, MAX_ID_LENGTH)?;
        validate_token("root_layout", &self.root_layout, MAX_ID_LENGTH)?;
        validate_token(
            "filesystem_contract",
            &self.filesystem_contract,
            MAX_ID_LENGTH,
        )?;
        validate_sha256("account_db_sha256", &self.account_db_sha256)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct ManifestBegin {
    #[n(0)]
    pub schema: String,
    #[n(1)]
    pub stream_id: String,
}

impl ValidateMessage for ManifestBegin {
    fn validate(&self) -> Result<(), ProtocolError> {
        validate_token("schema", &self.schema, MAX_ID_LENGTH)?;
        validate_sha256("stream_id", &self.stream_id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct ManifestChunk {
    #[n(0)]
    pub stream_id: String,
    #[n(1)]
    pub sequence: u64,
    #[n(2)]
    pub first_entry: u64,
    #[n(3)]
    pub entry_count: u32,
    #[cbor(n(4), with = "minicbor::bytes")]
    pub bytes: Vec<u8>,
}

impl ValidateMessage for ManifestChunk {
    fn validate(&self) -> Result<(), ProtocolError> {
        validate_sha256("stream_id", &self.stream_id)?;
        if self.entry_count == 0 {
            return invalid("entry_count", "chunk must contain at least one entry");
        }
        validate_count("bytes", self.bytes.len(), MAX_MANIFEST_CHUNK_BYTES)?;
        if self.bytes.is_empty() {
            return invalid("bytes", "chunk bytes must not be empty");
        }
        let decoded = count_length_prefixed_entries(&self.bytes, MAX_MANIFEST_ENTRY_BYTES)?;
        if decoded != self.entry_count as usize {
            return invalid("entry_count", "does not match length-prefixed entry bytes");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct ManifestEnd {
    #[n(0)]
    pub stream_id: String,
    #[n(1)]
    pub entry_count: u64,
    #[n(2)]
    pub byte_count: u64,
    #[n(3)]
    pub sha256: String,
}

impl ValidateMessage for ManifestEnd {
    fn validate(&self) -> Result<(), ProtocolError> {
        validate_sha256("stream_id", &self.stream_id)?;
        validate_sha256("sha256", &self.sha256)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct UserResolution {
    /// `0` for the empty image default, `1` for a numeric user, `2` for a
    /// named user, or [`Self::KIND_UNRESOLVED`] when a syntactically valid
    /// named user or group is absent from the image account database.
    #[n(0)]
    pub kind: u8,
    #[n(1)]
    pub uid: u32,
    #[n(2)]
    pub gid: u32,
    #[n(3)]
    pub supplementary_gids: Vec<u32>,
}

impl UserResolution {
    pub const KIND_UNRESOLVED: u8 = 3;

    #[must_use]
    pub fn unresolved() -> Self {
        Self {
            kind: Self::KIND_UNRESOLVED,
            uid: 0,
            gid: 0,
            supplementary_gids: Vec::new(),
        }
    }

    fn validate(&self) -> Result<(), ProtocolError> {
        if self.kind > Self::KIND_UNRESOLVED {
            return invalid("user_resolution.kind", "unknown resolution kind");
        }
        if self.kind == Self::KIND_UNRESOLVED
            && (self.uid != 0 || self.gid != 0 || !self.supplementary_gids.is_empty())
        {
            return invalid(
                "user_resolution",
                "unresolved user must not carry numeric resolution evidence",
            );
        }
        validate_count(
            "user_resolution.supplementary_gids",
            self.supplementary_gids.len(),
            64,
        )?;
        let mut gids = BTreeSet::new();
        for gid in &self.supplementary_gids {
            if !gids.insert(gid) {
                return invalid("user_resolution.supplementary_gids", "duplicate group ID");
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct FilesystemStatus {
    #[n(0)]
    pub target_synced: bool,
    #[n(1)]
    pub target_unmounted: bool,
    #[n(2)]
    pub input_unmounted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct BuilderDone {
    #[n(0)]
    pub status: u8,
    #[n(1)]
    pub manifest_sha256: String,
    #[n(2)]
    pub entry_count: u64,
    #[n(3)]
    pub byte_count: u64,
    #[n(4)]
    pub generation_marker_sha256: String,
    #[n(5)]
    pub original_user: String,
    #[n(6)]
    pub user_resolution: UserResolution,
    #[n(7)]
    pub observed_tools: Vec<ToolIdentity>,
    #[n(8)]
    pub filesystem_status: FilesystemStatus,
    #[n(9)]
    pub account_db_sha256: String,
}

impl ValidateMessage for BuilderDone {
    fn validate(&self) -> Result<(), ProtocolError> {
        if self.status != 0 {
            return invalid("status", "BUILD_DONE status must be zero");
        }
        validate_sha256("manifest_sha256", &self.manifest_sha256)?;
        validate_sha256("generation_marker_sha256", &self.generation_marker_sha256)?;
        validate_sha256("account_db_sha256", &self.account_db_sha256)?;
        validate_text(
            "original_user",
            &self.original_user,
            MAX_ORIGINAL_USER_LENGTH,
            true,
        )?;
        self.user_resolution.validate()?;
        validate_tools(&self.observed_tools, "observed_tools")?;
        if !self.filesystem_status.target_synced
            || !self.filesystem_status.target_unmounted
            || !self.filesystem_status.input_unmounted
        {
            return invalid(
                "filesystem_status",
                "successful build must be synced and fully unmounted",
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct AccountUser {
    #[n(0)]
    pub name: String,
    #[n(1)]
    pub uid: u32,
    #[n(2)]
    pub gid: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct AccountGroup {
    #[n(0)]
    pub name: String,
    #[n(1)]
    pub gid: u32,
    #[n(2)]
    pub members: Vec<String>,
}

/// Hard cap on one line of a passwd or group file.
pub const MAX_ACCOUNT_LINE_BYTES: usize = 64 * 1024;

/// Derive the canonical account records from passwd and group file contents.
///
/// This is the single definition of what `accounts.cbor` contains. Two things
/// produce it: the builder, from a freshly unpacked rootfs, and `commit`, from
/// the filesystem a kept run left behind. They have to agree exactly -- the
/// database is what `--user NAME` is resolved against, and a second
/// implementation would be free to drift -- so the derivation lives with the
/// format it produces and takes text rather than a path, leaving each caller
/// to obtain the two files however it can reach them.
pub fn account_database_from_files(
    passwd: &str,
    group: &str,
) -> Result<AccountDatabase, ProtocolError> {
    let mut users = Vec::new();
    for line in account_lines(passwd)? {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() != 7 {
            return invalid("passwd", "entry does not have seven fields");
        }
        validate_account_name("passwd.name", fields[0])?;
        users.push(AccountUser {
            name: fields[0].to_owned(),
            uid: parse_account_id(fields[2], "passwd uid")?,
            gid: parse_account_id(fields[3], "passwd gid")?,
        });
    }
    users.sort_by(|left, right| left.name.cmp(&right.name));

    let mut groups = Vec::new();
    for line in account_lines(group)? {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() != 4 {
            return invalid("group", "entry does not have four fields");
        }
        validate_account_name("group.name", fields[0])?;
        // Real group files carry members listed twice and stray commas that
        // produce empty names -- `usermod -aG` run twice is enough. Neither
        // carries any information, and the canonical database requires
        // strictly sorted unique names, so canonicalize rather than abort.
        let mut members = fields[3]
            .split(',')
            .filter(|member| !member.is_empty())
            .map(|member| {
                validate_account_name("group.members", member)?;
                Ok(member.to_owned())
            })
            .collect::<Result<Vec<_>, ProtocolError>>()?;
        members.sort();
        members.dedup();
        groups.push(AccountGroup {
            name: fields[0].to_owned(),
            gid: parse_account_id(fields[2], "group gid")?,
            members,
        });
    }
    groups.sort_by(|left, right| left.name.cmp(&right.name));

    let database = AccountDatabase {
        schema: ACCOUNT_DB_SCHEMA.to_owned(),
        users,
        groups,
    };
    database.validate()?;
    Ok(database)
}

fn account_lines(bytes: &str) -> Result<impl Iterator<Item = &str>, ProtocolError> {
    if bytes
        .lines()
        .any(|line| line.len() > MAX_ACCOUNT_LINE_BYTES)
    {
        return invalid("account_file", "line exceeds hard cap");
    }
    Ok(bytes
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#')))
}

fn parse_account_id(value: &str, field: &'static str) -> Result<u32, ProtocolError> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return invalid(field, "is not an unsigned decimal ID");
    }
    value
        .parse::<u32>()
        .map_err(|_| ProtocolError::InvalidMessage {
            field,
            reason: "does not fit u32",
        })
}

/// Canonical account records derived inside the builder from the completed
/// rootfs. Numeric IDs may repeat so later resolution can report ambiguity;
/// names and serialized ordering are unique and deterministic.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct AccountDatabase {
    #[n(0)]
    pub schema: String,
    #[n(1)]
    pub users: Vec<AccountUser>,
    #[n(2)]
    pub groups: Vec<AccountGroup>,
}

impl ValidateMessage for AccountDatabase {
    fn validate(&self) -> Result<(), ProtocolError> {
        if self.schema != ACCOUNT_DB_SCHEMA {
            return invalid("account_db.schema", "unsupported account database schema");
        }
        validate_count("account_db.users", self.users.len(), MAX_ACCOUNT_USERS)?;
        validate_count("account_db.groups", self.groups.len(), MAX_ACCOUNT_GROUPS)?;

        let mut previous_user: Option<&str> = None;
        for user in &self.users {
            validate_account_name("account_db.users.name", &user.name)?;
            if previous_user.is_some_and(|name| name >= user.name.as_str()) {
                return invalid("account_db.users", "user names are not unique and sorted");
            }
            previous_user = Some(&user.name);
        }

        let mut previous_group: Option<&str> = None;
        let mut memberships = 0_usize;
        for group in &self.groups {
            validate_account_name("account_db.groups.name", &group.name)?;
            if previous_group.is_some_and(|name| name >= group.name.as_str()) {
                return invalid("account_db.groups", "group names are not unique and sorted");
            }
            previous_group = Some(&group.name);
            validate_count(
                "account_db.groups.members",
                group.members.len(),
                MAX_ACCOUNT_GROUP_MEMBERS,
            )?;
            memberships = memberships.checked_add(group.members.len()).ok_or(
                ProtocolError::MessageLimitExceeded {
                    field: "account_db.memberships",
                    actual: usize::MAX,
                    maximum: MAX_ACCOUNT_MEMBERSHIPS,
                },
            )?;
            if memberships > MAX_ACCOUNT_MEMBERSHIPS {
                return invalid("account_db.memberships", "exceeds hard cap");
            }
            let mut previous_member: Option<&str> = None;
            for member in &group.members {
                validate_account_name("account_db.groups.members", member)?;
                if previous_member.is_some_and(|name| name >= member.as_str()) {
                    return invalid(
                        "account_db.groups.members",
                        "member names are not unique and sorted",
                    );
                }
                previous_member = Some(member);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct AccountDb {
    #[n(0)]
    pub schema: String,
    #[n(1)]
    pub byte_count: u32,
    #[n(2)]
    pub sha256: String,
    #[cbor(n(3), with = "minicbor::bytes")]
    pub canonical_bytes: Vec<u8>,
}

impl AccountDb {
    pub fn from_database(database: &AccountDatabase) -> Result<Self, ProtocolError> {
        database.validate()?;
        let canonical_bytes = encode_payload(database)?;
        validate_count(
            "account_db.canonical_bytes",
            canonical_bytes.len(),
            MAX_ACCOUNT_DB_BYTES,
        )?;
        let byte_count = u32::try_from(canonical_bytes.len()).map_err(|_| {
            ProtocolError::MessageLimitExceeded {
                field: "account_db.canonical_bytes",
                actual: canonical_bytes.len(),
                maximum: MAX_ACCOUNT_DB_BYTES,
            }
        })?;
        Ok(Self {
            schema: ACCOUNT_DB_SCHEMA.to_owned(),
            byte_count,
            sha256: hex_lower(&Sha256::digest(&canonical_bytes)),
            canonical_bytes,
        })
    }

    /// Re-authenticate already-canonical account sidecar bytes.
    ///
    /// Decoding and re-encoding rejects non-canonical CBOR and makes this the
    /// sole constructor used when a persisted sidecar is sent to the
    /// independent validation guest.
    pub fn from_canonical_bytes(canonical_bytes: Vec<u8>) -> Result<Self, ProtocolError> {
        validate_count(
            "account_db.canonical_bytes",
            canonical_bytes.len(),
            MAX_ACCOUNT_DB_BYTES,
        )?;
        let database: AccountDatabase = decode_payload(&canonical_bytes)?;
        let account_db = Self::from_database(&database)?;
        if account_db.canonical_bytes != canonical_bytes {
            return invalid(
                "account_db.canonical_bytes",
                "bytes do not match deterministic account encoding",
            );
        }
        Ok(account_db)
    }

    pub fn decode_database(&self) -> Result<AccountDatabase, ProtocolError> {
        self.validate()?;
        decode_payload(&self.canonical_bytes)
    }
}

impl ValidateMessage for AccountDb {
    fn validate(&self) -> Result<(), ProtocolError> {
        if self.schema != ACCOUNT_DB_SCHEMA {
            return invalid("account_db.schema", "unsupported account database schema");
        }
        validate_count(
            "account_db.canonical_bytes",
            self.canonical_bytes.len(),
            MAX_ACCOUNT_DB_BYTES,
        )?;
        if usize::try_from(self.byte_count).ok() != Some(self.canonical_bytes.len()) {
            return invalid("account_db.byte_count", "does not match canonical bytes");
        }
        validate_sha256("account_db.sha256", &self.sha256)?;
        if self.sha256 != hex_lower(&Sha256::digest(&self.canonical_bytes)) {
            return invalid("account_db.sha256", "does not match canonical bytes");
        }
        let database: AccountDatabase = decode_payload(&self.canonical_bytes)?;
        database.validate()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct ManifestXattr {
    #[cbor(n(0), with = "minicbor::bytes")]
    pub name: Vec<u8>,
    #[cbor(n(1), with = "minicbor::bytes")]
    pub value: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct ManifestEntry {
    #[cbor(n(0), with = "minicbor::bytes")]
    pub path: Vec<u8>,
    #[n(1)]
    pub kind: u8,
    #[n(2)]
    pub mode: u32,
    #[n(3)]
    pub uid: u32,
    #[n(4)]
    pub gid: u32,
    #[n(5)]
    pub size: u64,
    #[n(6)]
    pub rdev: u64,
    #[n(7)]
    pub mtime_seconds: i64,
    #[n(8)]
    pub mtime_nanoseconds: u32,
    #[cbor(n(9), with = "minicbor::bytes")]
    pub symlink_target: Option<Vec<u8>>,
    #[cbor(n(10), with = "minicbor::bytes")]
    pub content_sha256: Option<Vec<u8>>,
    #[cbor(n(11), with = "minicbor::bytes")]
    pub hardlink_target: Option<Vec<u8>>,
    #[n(12)]
    pub xattrs: Vec<ManifestXattr>,
}

impl ValidateMessage for ManifestEntry {
    fn validate(&self) -> Result<(), ProtocolError> {
        if self.path.len() > MAX_MANIFEST_PATH_BYTES || self.path.contains(&0) {
            return invalid("manifest_entry.path", "invalid or oversized path");
        }
        if self.path.first() == Some(&b'/')
            || (!self.path.is_empty()
                && self
                    .path
                    .split(|byte| *byte == b'/')
                    .any(|part| part.is_empty() || matches!(part, b"." | b"..")))
        {
            return invalid("manifest_entry.path", "path is not normalized and relative");
        }
        if !(1..=7).contains(&self.kind) {
            return invalid("manifest_entry.kind", "unknown filesystem entry kind");
        }
        if self.mode > 0o7777 {
            return invalid(
                "manifest_entry.mode",
                "mode exceeds permission and set-ID bits",
            );
        }
        if self.mtime_nanoseconds >= 1_000_000_000 {
            return invalid("manifest_entry.mtime_nanoseconds", "outside valid range");
        }
        if self
            .symlink_target
            .as_ref()
            .is_some_and(|value| value.contains(&0) || value.len() > MAX_MANIFEST_PATH_BYTES)
        {
            return invalid(
                "manifest_entry.symlink_target",
                "invalid or oversized target",
            );
        }
        if self
            .content_sha256
            .as_ref()
            .is_some_and(|value| value.len() != 32)
        {
            return invalid("manifest_entry.content_sha256", "digest must be 32 bytes");
        }
        if self.hardlink_target.as_ref().is_some_and(|value| {
            value.is_empty()
                || value.len() > MAX_MANIFEST_PATH_BYTES
                || value.contains(&0)
                || value.first() == Some(&b'/')
                || value
                    .split(|byte| *byte == b'/')
                    .any(|part| part.is_empty() || matches!(part, b"." | b".."))
        }) {
            return invalid("manifest_entry.hardlink_target", "invalid hardlink path");
        }
        let regular = self.kind == 1;
        if !regular && (self.content_sha256.is_some() || self.hardlink_target.is_some()) {
            return invalid(
                "manifest_entry.content",
                "only regular files carry content or hardlink evidence",
            );
        }
        if regular && self.content_sha256.is_some() == self.hardlink_target.is_some() {
            return invalid(
                "manifest_entry.content",
                "regular file needs exactly one content digest or hardlink target",
            );
        }
        if (self.kind == 3) != self.symlink_target.is_some() {
            return invalid(
                "manifest_entry.symlink_target",
                "symlink target presence does not match entry kind",
            );
        }
        if !matches!(self.kind, 4 | 5) && self.rdev != 0 {
            return invalid(
                "manifest_entry.rdev",
                "only character and block devices carry rdev",
            );
        }
        validate_count(
            "manifest_entry.xattrs",
            self.xattrs.len(),
            MAX_MANIFEST_XATTRS,
        )?;
        let mut previous: Option<&[u8]> = None;
        let mut total = 0_usize;
        for xattr in &self.xattrs {
            if xattr.name.is_empty() || xattr.name.contains(&0) {
                return invalid("manifest_entry.xattrs", "invalid xattr name");
            }
            if previous.is_some_and(|name| name >= xattr.name.as_slice()) {
                return invalid("manifest_entry.xattrs", "xattrs are not strictly sorted");
            }
            previous = Some(&xattr.name);
            total = total
                .checked_add(xattr.name.len())
                .and_then(|value| value.checked_add(xattr.value.len()))
                .ok_or(ProtocolError::MessageLimitExceeded {
                    field: "manifest_entry.xattr_bytes",
                    actual: usize::MAX,
                    maximum: MAX_MANIFEST_XATTR_BYTES,
                })?;
        }
        validate_count(
            "manifest_entry.xattr_bytes",
            total,
            MAX_MANIFEST_XATTR_BYTES,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuilderMessage {
    Hello(BuilderHello),
    Start(Box<BuilderStart>),
    ManifestBegin(ManifestBegin),
    ManifestChunk(ManifestChunk),
    ManifestEnd(ManifestEnd),
    AccountDb(AccountDb),
    Done(BuilderDone),
    Error(ErrorMessage),
}

impl BuilderMessage {
    #[must_use]
    pub const fn kind(&self) -> MessageKind {
        match self {
            Self::Hello(_) => MessageKind::BuildHello,
            Self::Start(_) => MessageKind::BuildStart,
            Self::ManifestBegin(_) => MessageKind::ManifestBegin,
            Self::ManifestChunk(_) => MessageKind::ManifestChunk,
            Self::ManifestEnd(_) => MessageKind::ManifestEnd,
            Self::AccountDb(_) => MessageKind::AccountDb,
            Self::Done(_) => MessageKind::BuildDone,
            Self::Error(_) => MessageKind::BuildError,
        }
    }

    pub fn encode_payload(&self) -> Result<Vec<u8>, ProtocolError> {
        match self {
            Self::Hello(message) => encode_payload(message),
            Self::Start(message) => encode_payload(message.as_ref()),
            Self::ManifestBegin(message) => encode_payload(message),
            Self::ManifestChunk(message) => encode_payload(message),
            Self::ManifestEnd(message) => encode_payload(message),
            Self::AccountDb(message) => encode_payload(message),
            Self::Done(message) => encode_payload(message),
            Self::Error(message) => encode_payload(message),
        }
    }

    pub fn validate(&self) -> Result<(), ProtocolError> {
        match self {
            Self::Hello(message) => message.validate(),
            Self::Start(message) => message.validate(),
            Self::ManifestBegin(message) => message.validate(),
            Self::ManifestChunk(message) => message.validate(),
            Self::ManifestEnd(message) => message.validate(),
            Self::AccountDb(message) => message.validate(),
            Self::Done(message) => message.validate(),
            Self::Error(message) => message.validate(),
        }
    }
}

pub fn decode_builder_message(frame: &RawFrame) -> Result<BuilderMessage, ProtocolError> {
    match frame.header.kind {
        MessageKind::BuildHello => decode_payload(&frame.payload).map(BuilderMessage::Hello),
        MessageKind::BuildStart => decode_payload(&frame.payload)
            .map(Box::new)
            .map(BuilderMessage::Start),
        MessageKind::ManifestBegin => {
            decode_payload(&frame.payload).map(BuilderMessage::ManifestBegin)
        }
        MessageKind::ManifestChunk => {
            decode_payload(&frame.payload).map(BuilderMessage::ManifestChunk)
        }
        MessageKind::ManifestEnd => decode_payload(&frame.payload).map(BuilderMessage::ManifestEnd),
        MessageKind::AccountDb => decode_payload(&frame.payload).map(BuilderMessage::AccountDb),
        MessageKind::BuildDone => decode_payload(&frame.payload).map(BuilderMessage::Done),
        MessageKind::BuildError => decode_payload(&frame.payload).map(BuilderMessage::Error),
        MessageKind::Hello
        | MessageKind::Start
        | MessageKind::Ready
        | MessageKind::Exit
        | MessageKind::Error
        | MessageKind::Shutdown
        | MessageKind::Signal
        | MessageKind::Resize
        | MessageKind::ValidateHello
        | MessageKind::ValidateStart
        | MessageKind::ValidateDone
        | MessageKind::ValidateError => invalid("kind", "non-builder message in builder protocol"),
    }
}

#[must_use]
pub fn builder_error_message(
    stage: impl Into<String>,
    code: ErrorCode,
    errno: Option<i32>,
    diagnostic: impl Into<String>,
) -> ErrorMessage {
    let mut diagnostic = diagnostic.into();
    if diagnostic.len() > MAX_DIAGNOSTIC_LENGTH {
        let mut boundary = MAX_DIAGNOSTIC_LENGTH;
        while !diagnostic.is_char_boundary(boundary) {
            boundary -= 1;
        }
        diagnostic.truncate(boundary);
    }
    ErrorMessage::new(stage, code, errno, diagnostic)
}

fn validate_tools(tools: &[ToolIdentity], field: &'static str) -> Result<(), ProtocolError> {
    validate_count(field, tools.len(), MAX_BUILDER_TOOLS)?;
    if tools.is_empty() {
        return invalid(field, "at least one tool identity is required");
    }
    let mut previous: Option<&str> = None;
    for tool in tools {
        tool.validate()?;
        if previous.is_some_and(|role| role >= tool.role.as_str()) {
            return invalid(field, "tool roles are not strictly sorted");
        }
        previous = Some(&tool.role);
    }
    Ok(())
}

fn validate_account_name(field: &'static str, value: &str) -> Result<(), ProtocolError> {
    validate_text(field, value, MAX_ACCOUNT_NAME_BYTES, false)?;
    if value
        .bytes()
        .any(|byte| byte <= b' ' || matches!(byte, b':' | b',' | 0x7f))
    {
        return invalid(field, "contains a forbidden account-name byte");
    }
    Ok(())
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn validate_oci_digest(field: &'static str, value: &str) -> Result<(), ProtocolError> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return invalid(field, "digest must use sha256");
    };
    validate_sha256(field, hex)
}

fn validate_media_type(field: &'static str, value: &str) -> Result<(), ProtocolError> {
    validate_text(field, value, MAX_MEDIA_TYPE_LENGTH, false)?;
    if !value.bytes().all(|byte| (0x21..=0x7e).contains(&byte)) {
        return invalid(field, "media type contains whitespace or non-ASCII bytes");
    }
    Ok(())
}

fn validate_builder_memory(field: &'static str, bytes: u64) -> Result<(), ProtocolError> {
    const MINIMUM: u64 = 64 * 1024 * 1024;
    const MAXIMUM: u64 = 1024 * 1024 * 1024 * 1024;
    if !(MINIMUM..=MAXIMUM).contains(&bytes) || !bytes.is_multiple_of(4096) {
        return invalid(
            field,
            "builder memory must be 64 MiB..=1 TiB and 4096-byte aligned",
        );
    }
    Ok(())
}

fn validate_platforms(
    descriptor: Option<&Platform>,
    config: &Platform,
    effective: &Platform,
) -> Result<(), ProtocolError> {
    if config.os != effective.os || config.architecture != effective.architecture {
        return invalid("platform", "config and effective OS/architecture disagree");
    }
    if let Some(descriptor) = descriptor {
        if descriptor.os != config.os || descriptor.architecture != config.architecture {
            return invalid("platform", "descriptor and config OS/architecture disagree");
        }
        if let (Some(left), Some(right)) = (&descriptor.variant, &config.variant)
            && left != right
        {
            return invalid("platform", "explicit variants disagree");
        }
    }
    let variant = descriptor
        .and_then(|platform| platform.variant.as_ref())
        .or(config.variant.as_ref());
    if variant != effective.variant.as_ref() {
        return invalid(
            "effective_platform",
            "variant does not match raw platform fields",
        );
    }
    Ok(())
}

pub(crate) fn count_length_prefixed_entries(
    bytes: &[u8],
    maximum_entry: usize,
) -> Result<usize, ProtocolError> {
    let mut position = 0_usize;
    let mut count = 0_usize;
    while position < bytes.len() {
        let remaining = bytes.len() - position;
        if remaining < 4 {
            return invalid("bytes", "truncated manifest-entry length");
        }
        let length = u32::from_be_bytes([
            bytes[position],
            bytes[position + 1],
            bytes[position + 2],
            bytes[position + 3],
        ]) as usize;
        if length == 0 || length > maximum_entry {
            return invalid("bytes", "manifest entry length is zero or oversized");
        }
        position = position
            .checked_add(4)
            .and_then(|value| value.checked_add(length))
            .ok_or(ProtocolError::PayloadTooLarge {
                actual: bytes.len(),
                maximum: MAX_CONTROL_PAYLOAD,
            })?;
        if position > bytes.len() {
            return invalid("bytes", "manifest entry straddles chunks");
        }
        count = count
            .checked_add(1)
            .ok_or(ProtocolError::MessageLimitExceeded {
                field: "entry_count",
                actual: usize::MAX,
                maximum: usize::MAX,
            })?;
    }
    Ok(count)
}

#[cfg(test)]
pub(crate) mod tests {
    use pocket_core::ErrorCode;

    use super::*;

    fn digest(character: char) -> String {
        character.to_string().repeat(64)
    }

    fn oci_digest(character: char) -> String {
        format!("sha256:{}", digest(character))
    }

    fn platform() -> Platform {
        Platform {
            os: "linux".to_owned(),
            architecture: "amd64".to_owned(),
            variant: None,
        }
    }

    pub(crate) fn tool() -> ToolIdentity {
        ToolIdentity {
            role: "umoci".to_owned(),
            sha256: digest('a'),
            version: "umoci 0.4.7".to_owned(),
        }
    }

    pub(crate) fn hello() -> BuilderHello {
        BuilderHello {
            guest_contract_id: digest('b'),
            init_build_id: digest('c'),
            kernel_build_id: digest('d'),
            host_elf_machine: 62,
            guest_uts_machine: "x86_64".to_owned(),
            guest_page_size: 4096,
            cpu_state_hwcap_policy: "native-x86_64-v1".to_owned(),
            online_cpus: 1,
            builder_tools: vec![tool()],
            features: vec!["canonical-manifest-v1".to_owned()],
            accepted_physmem_bytes: 768 * 1024 * 1024,
        }
    }

    pub(crate) fn start() -> BuilderStart {
        BuilderStart {
            profile_id: "x86_64-smp-p4k".to_owned(),
            profile_revision: digest('e'),
            derivation_key: digest('f'),
            selected_manifest: OciDescriptor {
                digest: oci_digest('1'),
                size: 123,
                media_type: "application/vnd.oci.image.manifest.v1+json".to_owned(),
            },
            config: OciDescriptor {
                digest: oci_digest('2'),
                size: 456,
                media_type: "application/vnd.oci.image.config.v1+json".to_owned(),
            },
            layers: vec![BuilderLayerDescriptor {
                descriptor: OciDescriptor {
                    digest: oci_digest('3'),
                    size: 789,
                    media_type: "application/vnd.oci.image.layer.v1.tar+gzip".to_owned(),
                },
                diff_id: oci_digest('4'),
                uncompressed_size: 1024,
            }],
            descriptor_platform: None,
            config_platform: platform(),
            effective_platform: platform(),
            selector_policy: "oci-native-v1".to_owned(),
            root_layout: "pocket-root-v1".to_owned(),
            filesystem_contract: "ext4-v1-b4096".to_owned(),
            manifest_schema: "pocket-fs-manifest-v1".to_owned(),
            manifest_limits: ManifestLimits::default(),
            expected_tools: vec![tool()],
            input_reference: "root".to_owned(),
            original_user: "www-data".to_owned(),
            expected_physmem_bytes: 768 * 1024 * 1024,
            source_date_epoch: 1_786_940_622,
        }
    }

    fn round_trip<T>(value: &T)
    where
        T: Encode<()>
            + for<'bytes> Decode<'bytes, ()>
            + ValidateMessage
            + PartialEq
            + std::fmt::Debug,
    {
        let bytes = encode_payload(value).expect("test value must encode");
        let decoded: T = decode_payload(&bytes).expect("test value must decode");
        assert_eq!(&decoded, value);
        assert_eq!(encode_payload(&decoded).expect("re-encode"), bytes);
    }

    #[test]
    fn builder_control_schemas_round_trip_canonically() {
        round_trip(&hello());
        round_trip(&start());
        round_trip(&GenerationMarker::from_start(&start(), digest('6')));
        round_trip(&ManifestBegin {
            schema: "pocket-fs-manifest-v1".to_owned(),
            stream_id: digest('9'),
        });
        let entry = encode_payload(&ManifestEntry {
            path: b"rootfs/bin/app".to_vec(),
            kind: 1,
            mode: 0o755,
            uid: 0,
            gid: 0,
            size: 3,
            rdev: 0,
            mtime_seconds: 1,
            mtime_nanoseconds: 2,
            symlink_target: None,
            content_sha256: Some(vec![7; 32]),
            hardlink_target: None,
            xattrs: vec![],
        })
        .expect("entry");
        let mut framed = (entry.len() as u32).to_be_bytes().to_vec();
        framed.extend(entry);
        round_trip(&ManifestChunk {
            stream_id: digest('9'),
            sequence: 0,
            first_entry: 0,
            entry_count: 1,
            bytes: framed,
        });
        round_trip(&ManifestEnd {
            stream_id: digest('9'),
            entry_count: 1,
            byte_count: 10,
            sha256: digest('8'),
        });
        let account_db = AccountDb::from_database(&AccountDatabase {
            schema: ACCOUNT_DB_SCHEMA.to_owned(),
            users: vec![AccountUser {
                name: "www-data".to_owned(),
                uid: 33,
                gid: 33,
            }],
            groups: vec![AccountGroup {
                name: "www-data".to_owned(),
                gid: 33,
                members: vec!["www-data".to_owned()],
            }],
        })
        .expect("account database");
        round_trip(&account_db);
        round_trip(&BuilderDone {
            status: 0,
            manifest_sha256: digest('8'),
            entry_count: 1,
            byte_count: 10,
            generation_marker_sha256: digest('7'),
            original_user: "www-data".to_owned(),
            user_resolution: UserResolution {
                kind: 2,
                uid: 33,
                gid: 33,
                supplementary_gids: vec![],
            },
            observed_tools: vec![tool()],
            filesystem_status: FilesystemStatus {
                target_synced: true,
                target_unmounted: true,
                input_unmounted: true,
            },
            account_db_sha256: account_db.sha256,
        });
        round_trip(&builder_error_message(
            "apply",
            ErrorCode::BuilderToolFailed,
            Some(5),
            "umoci failed",
        ));
    }

    #[test]
    fn builder_epoch_is_explicit_and_bounded_on_the_wire() {
        let mut value = start();
        value.source_date_epoch = SOURCE_DATE_EPOCH_MIN;
        assert!(value.validate().is_ok());
        value.source_date_epoch = SOURCE_DATE_EPOCH_MAX;
        assert!(value.validate().is_ok());
        value.source_date_epoch = SOURCE_DATE_EPOCH_MIN - 1;
        assert!(value.validate().is_err());
        value.source_date_epoch = SOURCE_DATE_EPOCH_MAX + 1;
        assert!(value.validate().is_err());
    }

    #[test]
    fn unresolved_user_resolution_requires_empty_numeric_evidence() {
        UserResolution::unresolved()
            .validate()
            .expect("canonical unresolved resolution");

        for invalid_resolution in [
            UserResolution {
                uid: 1,
                ..UserResolution::unresolved()
            },
            UserResolution {
                gid: 1,
                ..UserResolution::unresolved()
            },
            UserResolution {
                supplementary_gids: vec![1],
                ..UserResolution::unresolved()
            },
            UserResolution {
                kind: UserResolution::KIND_UNRESOLVED + 1,
                ..UserResolution::unresolved()
            },
        ] {
            assert!(invalid_resolution.validate().is_err());
        }
    }

    #[test]
    fn chunks_reject_straddled_and_count_mismatched_entries() {
        let chunk = ManifestChunk {
            stream_id: digest('a'),
            sequence: 0,
            first_entry: 0,
            entry_count: 1,
            bytes: vec![0, 0, 0, 5, 1, 2],
        };
        assert!(chunk.validate().is_err());

        let chunk = ManifestChunk {
            stream_id: digest('a'),
            sequence: 0,
            first_entry: 0,
            entry_count: 2,
            bytes: vec![0, 0, 0, 1, 0],
        };
        assert!(chunk.validate().is_err());
    }

    #[test]
    fn maximum_manifest_chunk_uses_a_bounded_cbor_byte_string() {
        let first_entry_len = MAX_MANIFEST_ENTRY_BYTES;
        let second_entry_len = MAX_MANIFEST_CHUNK_BYTES - first_entry_len - 8;
        let mut bytes = (first_entry_len as u32).to_be_bytes().to_vec();
        bytes.resize(4 + first_entry_len, 0xa5);
        bytes.extend_from_slice(&(second_entry_len as u32).to_be_bytes());
        bytes.resize(MAX_MANIFEST_CHUNK_BYTES, 0x5a);
        let chunk = ManifestChunk {
            stream_id: digest('a'),
            sequence: u64::MAX,
            first_entry: u64::MAX,
            entry_count: 2,
            bytes,
        };

        chunk.validate().expect("maximum chunk is valid");
        let payload = BuilderMessage::ManifestChunk(chunk.clone())
            .encode_payload()
            .expect("maximum chunk encodes");
        assert!(
            payload.len() <= MAX_CONTROL_PAYLOAD,
            "encoded chunk payload {} exceeds framing cap {MAX_CONTROL_PAYLOAD}",
            payload.len()
        );
        assert!(
            payload.len() <= MAX_MANIFEST_CHUNK_BYTES + 128,
            "manifest bytes were not encoded as a CBOR byte string: {} bytes",
            payload.len()
        );

        let decoded: ManifestChunk = decode_payload(&payload).expect("maximum chunk decodes");
        assert_eq!(decoded, chunk);
    }

    #[test]
    fn large_account_database_stays_within_its_control_frame() {
        let groups = (0..700_u32)
            .map(|index| AccountGroup {
                name: format!("{index:04}-{}", "x".repeat(251)),
                gid: index,
                members: Vec::new(),
            })
            .collect();
        let account_db = AccountDb::from_database(&AccountDatabase {
            schema: ACCOUNT_DB_SCHEMA.to_owned(),
            users: Vec::new(),
            groups,
        })
        .expect("large valid account database");
        assert!(account_db.canonical_bytes.len() > MAX_MANIFEST_ENTRY_BYTES);
        assert!(account_db.canonical_bytes.len() <= MAX_ACCOUNT_DB_BYTES);

        let payload = BuilderMessage::AccountDb(account_db.clone())
            .encode_payload()
            .expect("large account database frame");
        assert!(payload.len() <= MAX_CONTROL_PAYLOAD);
        assert!(payload.len() <= account_db.canonical_bytes.len() + 128);
        let decoded: AccountDb = decode_payload(&payload).expect("account database decodes");
        assert_eq!(decoded, account_db);
    }

    #[test]
    fn maximum_xattr_entry_stays_within_the_negotiated_entry_cap() {
        let name = b"user.pocket".to_vec();
        let value = vec![0xa5; MAX_MANIFEST_XATTR_BYTES - name.len()];
        let entry = ManifestEntry {
            path: vec![b'a'; MAX_MANIFEST_PATH_BYTES],
            kind: 2,
            mode: 0o755,
            uid: 0,
            gid: 0,
            size: 4096,
            rdev: 0,
            mtime_seconds: 0,
            mtime_nanoseconds: 0,
            symlink_target: None,
            content_sha256: None,
            hardlink_target: None,
            xattrs: vec![ManifestXattr { name, value }],
        };
        entry.validate().expect("maximum xattr entry is valid");

        let payload = encode_payload(&entry).expect("maximum xattr entry encodes");
        assert!(payload.len() <= MAX_MANIFEST_ENTRY_BYTES);
        let decoded: ManifestEntry = decode_payload(&payload).expect("manifest entry decodes");
        assert_eq!(decoded, entry);
    }

    #[test]
    fn marker_is_wire_compatible_with_workload_marker_shape() {
        let marker = GenerationMarker::from_start(&start(), digest('6'));
        let encoded = encode_payload(&marker).expect("marker");
        assert!(!encoded.is_empty());
        assert_eq!(marker.schema, "pocket-generation-v3");
    }
}
