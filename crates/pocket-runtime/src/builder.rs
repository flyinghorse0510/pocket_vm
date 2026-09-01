//! Bounded host-side OCI-to-ext4 builder orchestration.

use std::{
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
        unix::{
            fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
            net::UnixStream,
            process::CommandExt,
        },
    },
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use nix::{fcntl::OFlag, libc, unistd::pipe2};
use pocket_core::ManagedUmlPath;
use pocket_oci::{ImagePlatform, VerifiedImage};
use pocket_protocol::{
    AccountDb, BuilderDone, BuilderHello, BuilderLayerDescriptor, BuilderMessage, BuilderSession,
    BuilderStart, Direction, FrameReader, FrameWriter, GenerationMarker, MAX_ACCOUNT_DB_BYTES,
    ManifestChunk, ManifestEntry, ManifestLimits, MessageKind, OciDescriptor,
    Platform as ProtocolPlatform, ToolIdentity, ValidateMessage, ValidatorDone, ValidatorHello,
    ValidatorMessage, ValidatorSession, ValidatorStart, decode_builder_message, decode_payload,
    decode_validator_message,
};
use pocket_store::{
    AliasId, AliasKey, BeginGeneration, DerivationKey, Digest, GenerationId, GenerationSpec,
    GenerationTransaction, ImmutableSidecar, Lease, Platform as StorePlatform, Store,
};
use serde::Serialize;
use sha2::{Digest as _, Sha256};

use crate::{HostBuildError, RuntimeError, VerifiedProfile, filesystem::validate_ext4_base};

const LEASE_FD: RawFd = 8;
const LIVENESS_FD: RawFd = 9;
const CONTROL_FD: RawFd = 10;
const CONSOLE_FD: RawFd = 14;
const RELOCATED_FD_MINIMUM: RawFd = 64;
const BUILD_ID_BYTES: usize = 16;
const VALIDATION_CHALLENGE_BYTES: usize = 32;
const MAX_TIMEOUT: Duration = Duration::from_secs(24 * 60 * 60);
const MAX_LOG_BYTES: usize = 64 * 1024 * 1024;
const MAX_LAYOUT_ENTRIES: usize = 16_384;
const PAYLOAD_MINIMUM_BYTES: u64 = 128 * 1024 * 1024;
/// Floor for a converted image's filesystem.
///
/// An image's own contents rarely need this much, but the filesystem is also
/// the workload's writable space for the life of a run: everything outside a
/// `--volume` lands in the copy-on-write overlay on top of it, `/tmp`
/// included. The floor buys that room once, at image-conversion time, rather
/// than leaving every run a few hundred megabytes from ENOSPC.
///
/// It is cheap because the file is sparse: an 8 GiB base costs about 69 MiB on
/// disk, most of it the journal that `lazy_journal_init=0` writes for
/// reproducibility. It is not free, because publication hashes the complete
/// logical file: about 20 seconds at this size. `image adjust` moves an
/// existing image to another size when the default does not fit.
const TARGET_MINIMUM_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const SIZE_CLASS_BYTES: u64 = 64 * 1024 * 1024;
const MAX_PAYLOAD_BYTES: u64 = 256 * 1024 * 1024 * 1024;
const MAX_TARGET_BYTES: u64 = 512 * 1024 * 1024 * 1024;
const EXT4_BLOCK_BYTES: u64 = 4096;
const EXT4_INODE_BYTES: u64 = 256;
const TAR_RECORD_BYTES: u64 = 512;
const PAYLOAD_INODE_CLASS: u64 = 4096;
const TARGET_INODE_CLASS: u64 = 65_536;
const PAYLOAD_INODE_HEADROOM: u64 = 1024;
const TARGET_INTERNAL_INODES: u64 = 16;
const EXT4_FEATURES: &str = "has_journal,ext_attr,resize_inode,dir_index,filetype,extent,64bit,flex_bg,metadata_csum_seed,sparse_super,large_file,huge_file,dir_nlink,extra_isize,metadata_csum";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildRequest {
    pub oci_layout: PathBuf,
    pub source_reference: String,
    pub requested_variant: Option<String>,
}

#[derive(Debug, Clone, Copy)]
pub struct BuilderPolicy {
    pub startup_timeout: Duration,
    pub build_timeout: Duration,
    pub validation_timeout: Duration,
    pub helper_timeout: Duration,
    /// Added to `helper_timeout` for each started gibibyte of the image a
    /// helper stage writes or checks. `mke2fs -d` copies the whole OCI layout
    /// and `e2fsck` reads the whole base, so a single fixed budget fails large
    /// images on slow storage for no reason other than their size.
    pub helper_timeout_per_gib: Duration,
    pub guard_term_timeout: Duration,
    pub guard_exit_timeout: Duration,
    pub maximum_log_bytes: usize,
}

impl Default for BuilderPolicy {
    fn default() -> Self {
        Self {
            startup_timeout: Duration::from_secs(30),
            build_timeout: Duration::from_secs(30 * 60),
            validation_timeout: Duration::from_secs(30 * 60),
            helper_timeout: Duration::from_secs(5 * 60),
            helper_timeout_per_gib: Duration::from_secs(5 * 60),
            guard_term_timeout: Duration::from_secs(5),
            guard_exit_timeout: Duration::from_secs(10),
            maximum_log_bytes: 8 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildOutput {
    pub generation_id: GenerationId,
    pub derivation_key: DerivationKey,
    pub alias_id: AliasId,
    pub cache_hit: bool,
}

#[derive(Debug)]
struct PreparedBuild {
    image: VerifiedImage,
    spec: GenerationSpec,
    alias: AliasKey,
    start: BuilderStart,
    payload_sizing: FilesystemSizing,
    target_sizing: FilesystemSizing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FilesystemSize {
    bytes: u64,
    inodes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FilesystemSizing {
    initial: FilesystemSize,
    retry: Option<FilesystemSize>,
}

#[derive(Debug, Serialize)]
struct BuildContractRecord<'a> {
    schema: &'static str,
    profile_id: &'a str,
    profile_revision: String,
    selector_policy: &'a str,
    uml_sha256: String,
    builder_initramfs_sha256: String,
    validator_initramfs_sha256: String,
    mke2fs_sha256: String,
    e2fsck_sha256: String,
    mke2fs_config_sha256: String,
    e2fsck_config_sha256: String,
    manifest_schema: &'a str,
    validator_manifest_schema: &'a str,
    builder_tools: &'a [crate::BuilderToolContract],
    source_date_epoch: u64,
    target_initial_size_bytes: u64,
    target_initial_inodes: u64,
    target_retry_size_bytes: Option<u64>,
    target_retry_inodes: Option<u64>,
    filesystem_sizing_contract: &'static str,
    directory_hash_seed_contract: &'static str,
    capacity_retry_contract: &'static str,
    conversion_contract: &'static str,
    validation_contract: &'static str,
    protocol_major: u16,
    protocol_minor: u16,
}

/// One request to republish an image's filesystem at a different size.
#[derive(Debug, Clone)]
pub struct AdjustRequest {
    /// The image to read. It is never modified.
    pub source: AliasKey,
    /// The reference the adjusted image is published under.
    pub reference: String,
    /// Requested filesystem size in bytes, a multiple of the 4096-byte block.
    pub target_bytes: u64,
}

const EXT4_BLOCK_BYTES_U32: u32 = 4096;

/// Bound and align one requested filesystem size.
fn validate_target_size(bytes: u64) -> Result<u64, HostBuildError> {
    if !bytes.is_multiple_of(u64::from(EXT4_BLOCK_BYTES_U32)) {
        return Err(HostBuildError::invalid(
            "target_bytes",
            format!("must be a multiple of the {EXT4_BLOCK_BYTES_U32}-byte block size"),
        ));
    }
    // The floor is the smallest filesystem the conversion contract will build,
    // so an adjusted image stays inside the range a fresh one can occupy.
    if bytes < PAYLOAD_MINIMUM_BYTES {
        return Err(HostBuildError::invalid(
            "target_bytes",
            format!("must be at least {PAYLOAD_MINIMUM_BYTES} bytes"),
        ));
    }
    if bytes > MAX_TARGET_BYTES {
        return Err(HostBuildError::invalid(
            "target_bytes",
            format!("exceeds the {MAX_TARGET_BYTES}-byte maximum"),
        ));
    }
    Ok(bytes)
}

/// Copy a file while preserving its holes.
///
/// A base image is mostly hole -- an 8 GiB filesystem holding a 10 MiB image
/// is nearly all zero -- so a byte-for-byte copy would write gigabytes that
/// were never allocated. `SEEK_DATA`/`SEEK_HOLE` walk only what exists.
fn copy_sparse(source: &Path, target: &Path) -> Result<(), HostBuildError> {
    use std::io::{Seek, SeekFrom};

    let mut input = File::open(source)
        .map_err(|error| HostBuildError::io("open source base", source, error))?;
    let length = input
        .metadata()
        .map_err(|error| HostBuildError::io("stat source base", source, error))?
        .len();
    // The staged base does not exist yet: on the conversion path mke2fs
    // creates it, and here nothing has yet. `create_new` keeps that an
    // assertion rather than an overwrite of somebody else's file.
    let mut output = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(target)
        .map_err(|error| HostBuildError::io("create staged base", target, error))?;
    output
        .set_len(length)
        .map_err(|error| HostBuildError::io("size staged base", target, error))?;

    let mut offset = 0_u64;
    let mut buffer = vec![0_u8; 1024 * 1024];
    while offset < length {
        let data = match seek_hole_aware(&input, offset, true) {
            Some(position) => position,
            None => break,
        };
        if data >= length {
            break;
        }
        let end = seek_hole_aware(&input, data, false)
            .unwrap_or(length)
            .min(length);
        input
            .seek(SeekFrom::Start(data))
            .map_err(|error| HostBuildError::io("seek source base", source, error))?;
        output
            .seek(SeekFrom::Start(data))
            .map_err(|error| HostBuildError::io("seek staged base", target, error))?;
        let mut remaining = end - data;
        while remaining > 0 {
            let want = usize::try_from(remaining.min(buffer.len() as u64)).unwrap_or(buffer.len());
            let read = input
                .read(&mut buffer[..want])
                .map_err(|error| HostBuildError::io("read source base", source, error))?;
            if read == 0 {
                break;
            }
            output
                .write_all(&buffer[..read])
                .map_err(|error| HostBuildError::io("write staged base", target, error))?;
            remaining -= read as u64;
        }
        offset = end;
    }
    output
        .sync_all()
        .map_err(|error| HostBuildError::io("flush staged base", target, error))
}

/// `lseek` to the next data or hole, returning `None` at end of file.
fn seek_hole_aware(file: &File, from: u64, want_data: bool) -> Option<u64> {
    let whence = if want_data {
        nix::libc::SEEK_DATA
    } else {
        nix::libc::SEEK_HOLE
    };
    // SAFETY: a live descriptor and a plain integer whence; lseek touches no
    // memory this owns.
    let position = unsafe {
        nix::libc::lseek(
            std::os::fd::AsRawFd::as_raw_fd(file),
            from as nix::libc::off_t,
            whence,
        )
    };
    if position < 0 {
        return None;
    }
    u64::try_from(position).ok()
}

/// Replace the generation marker inside a staged filesystem, in place.
///
/// Every base carries `/.pocket-generation.cbor`, and the guest refuses to run
/// one whose marker does not reconcile with the START it was sent. An adjusted
/// image is a new generation with a new derivation key, so it needs a new
/// marker or it cannot boot.
///
/// The replacement is exactly as long as the original -- only a fixed-width
/// hex derivation key changes -- so this overwrites the file's own data blocks
/// rather than unlinking and rewriting it. That leaves every piece of
/// filesystem metadata untouched: no allocation changes, no directory changes,
/// and nothing for a repair pass to find. `debugfs` is used only to ask where
/// the blocks are; it never writes.
fn rewrite_generation_marker(
    image: &Path,
    marker: &[u8],
    context: &E2fsHelperContext<'_>,
    image_bytes: u64,
    logs: &mut Vec<StageLog>,
) -> Result<(), HostBuildError> {
    let log = run_guarded_helper(
        "adjust-locate-marker",
        E2fsHelper::Debugfs,
        &[
            OsString::from("-R"),
            OsString::from(format!("blocks {GENERATION_MARKER_PATH}")),
            image.as_os_str().to_owned(),
        ],
        context,
        image_bytes,
    )?;
    let listing = String::from_utf8_lossy(&log.stdout.bytes).to_string();
    logs.push(log);
    let blocks: Vec<u64> = listing
        .split_whitespace()
        .filter_map(|field| field.parse::<u64>().ok())
        .collect();
    let block_bytes = u64::from(EXT4_BLOCK_BYTES_U32);
    let capacity = (blocks.len() as u64).saturating_mul(block_bytes);
    if blocks.is_empty() || capacity < marker.len() as u64 {
        return Err(HostBuildError::invalid(
            "generation_marker",
            format!(
                "marker occupies {} blocks, too few for {} bytes",
                blocks.len(),
                marker.len()
            ),
        ));
    }
    let mut file = OpenOptions::new()
        .write(true)
        .open(image)
        .map_err(|error| HostBuildError::io("open staged base", image, error))?;
    let mut written = 0_usize;
    for block in blocks {
        if written >= marker.len() {
            break;
        }
        let offset = block.checked_mul(block_bytes).ok_or_else(|| {
            HostBuildError::invalid("generation_marker", "block offset overflows")
        })?;
        let end = (written + block_bytes as usize).min(marker.len());
        file.seek(std::io::SeekFrom::Start(offset))
            .and_then(|_| file.write_all(&marker[written..end]))
            .map_err(|error| HostBuildError::io("write generation marker", image, error))?;
        written = end;
    }
    file.sync_all()
        .map_err(|error| HostBuildError::io("flush generation marker", image, error))
}

const GENERATION_MARKER_PATH: &str = "/.pocket-generation.cbor";

/// Copy the generation marker out of a staged filesystem.
fn read_generation_marker(
    image: &Path,
    context: &E2fsHelperContext<'_>,
    image_bytes: u64,
    logs: &mut Vec<StageLog>,
) -> Result<Vec<u8>, HostBuildError> {
    let target = context.tmp.join("generation-marker.cbor");
    let _ = fs::remove_file(&target);
    logs.push(run_guarded_helper(
        "adjust-read-marker",
        E2fsHelper::Debugfs,
        &[
            OsString::from("-R"),
            OsString::from(format!(
                "dump {GENERATION_MARKER_PATH} {}",
                target.display()
            )),
            image.as_os_str().to_owned(),
        ],
        context,
        image_bytes,
    )?);
    let bytes = fs::read(&target)
        .map_err(|error| HostBuildError::io("read generation marker", &target, error))?;
    let _ = fs::remove_file(&target);
    if bytes.is_empty() {
        return Err(HostBuildError::invalid(
            "generation_marker",
            "image carries no generation marker",
        ));
    }
    Ok(bytes)
}

/// Read-only structural check of a staged filesystem.
fn verify_filesystem(
    image: &Path,
    context: &E2fsHelperContext<'_>,
    image_bytes: u64,
    logs: &mut Vec<StageLog>,
) -> Result<(), HostBuildError> {
    logs.push(run_guarded_helper(
        "adjust-verify",
        E2fsHelper::E2fsck,
        &[
            OsString::from("-f"),
            OsString::from("-n"),
            image.as_os_str().to_owned(),
        ],
        context,
        image_bytes,
    )?);
    Ok(())
}

/// Check, resize and re-check one staged filesystem in place.
///
/// Growing past the file's end is not possible, so the order differs by
/// direction: a grow extends the file first and lets resize2fs fill it, a
/// shrink resizes to the target block count first and truncates the emptied
/// tail afterwards.
///
/// Both checks are read-only. A preening check would be the conventional
/// choice before a resize, but `e2fsck -p` *repairs*: on a base built by
/// `mke2fs -d` it creates the `/lost+found` the conversion never made, which
/// would silently give the adjusted image one more directory than the source
/// and leave the copied content manifest describing something that no longer
/// matches. resize2fs is content with a filesystem the superblock already
/// marks clean, which this one is, so nothing has to be repaired to proceed.
fn resize_in_place(
    image: &Path,
    source_bytes: u64,
    target_bytes: u64,
    context: &E2fsHelperContext<'_>,
    logs: &mut Vec<StageLog>,
) -> Result<(), HostBuildError> {
    let blocks = target_bytes / u64::from(EXT4_BLOCK_BYTES_U32);
    let budget_bytes = source_bytes.max(target_bytes);
    logs.push(run_guarded_helper(
        "adjust-precheck",
        E2fsHelper::E2fsck,
        &[
            OsString::from("-f"),
            OsString::from("-n"),
            image.as_os_str().to_owned(),
        ],
        context,
        budget_bytes,
    )?);
    if target_bytes > source_bytes {
        set_image_length(image, target_bytes)?;
    }
    logs.push(run_guarded_helper(
        "adjust-resize",
        E2fsHelper::Resize2fs,
        &[image.as_os_str().to_owned(), blocks.to_string().into()],
        context,
        budget_bytes,
    )?);
    if target_bytes < source_bytes {
        set_image_length(image, target_bytes)?;
    }
    Ok(())
}

fn set_image_length(image: &Path, bytes: u64) -> Result<(), HostBuildError> {
    let file = OpenOptions::new()
        .write(true)
        .open(image)
        .map_err(|error| HostBuildError::io("open staged base", image, error))?;
    file.set_len(bytes)
        .map_err(|error| HostBuildError::io("resize staged base", image, error))?;
    file.sync_all()
        .map_err(|error| HostBuildError::io("flush staged base", image, error))
}

pub struct HostBuilder<'builder> {
    profile: &'builder VerifiedProfile,
    store: &'builder Store,
    runtime_root: ManagedUmlPath,
    policy: BuilderPolicy,
}

impl std::fmt::Debug for HostBuilder<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HostBuilder")
            .field("profile", &self.profile.manifest().profile_id)
            .field("runtime_root", &self.runtime_root)
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

impl<'builder> HostBuilder<'builder> {
    pub fn new(
        profile: &'builder VerifiedProfile,
        store: &'builder Store,
        runtime_root: ManagedUmlPath,
        policy: BuilderPolicy,
    ) -> Result<Self, HostBuildError> {
        validate_policy(policy)?;
        initialize_builder_root(runtime_root.as_path())?;
        Ok(Self {
            profile,
            store,
            runtime_root,
            policy,
        })
    }

    /// Build or reuse one immutable generation and atomically update the exact
    /// profile/platform-qualified alias only after full store publication.
    /// Republish one image's filesystem at a different size.
    ///
    /// A generation is immutable, so this never edits the source: it copies the
    /// base, resizes the copy, and publishes the result as its own generation.
    /// The size is part of a generation's identity -- the build contract binds
    /// it -- so the adjusted image has a different derivation key and can sit
    /// beside the original rather than replacing it.
    ///
    /// The contents are not touched, so every sidecar the source carries still
    /// describes the result exactly and is copied across unchanged.
    pub fn adjust(&self, request: AdjustRequest) -> Result<BuildOutput, HostBuildError> {
        self.profile.reverify()?;
        let source = self.store.lease_alias(&request.source)?;
        self.adjust_leased(&source, request)
    }

    /// Adjust an image already leased by the caller.
    pub fn adjust_leased(
        &self,
        source: &Lease,
        request: AdjustRequest,
    ) -> Result<BuildOutput, HostBuildError> {
        let target_bytes = validate_target_size(request.target_bytes)?;
        let generation = source.generation();
        let source_base = generation.base_path().to_path_buf();
        let (inodes, source_blocks) = crate::filesystem::ext4_geometry(&source_base)
            .map_err(|error| HostBuildError::invalid("source", error.to_string()))?;
        let source_bytes = source_blocks
            .checked_mul(u64::from(EXT4_BLOCK_BYTES_U32))
            .ok_or_else(|| HostBuildError::invalid("source", "source size overflows"))?;

        // The identity binds what was asked for, not what the filesystem
        // happens to report afterwards, so it is known before any lock is
        // taken and two identical requests converge on one generation.
        let sizing = FilesystemSizing {
            initial: FilesystemSize {
                bytes: target_bytes,
                inodes,
            },
            retry: None,
        };
        let contract = build_contract_digest(self.profile, sizing)?;
        let previous = generation.manifest().spec();
        let spec = GenerationSpec::new(
            previous.selected_manifest_digest(),
            previous.config_digest(),
            previous.layer_digests().to_vec(),
            previous.diff_ids().to_vec(),
            previous.descriptor_platform().cloned(),
            previous.config_platform().clone(),
            previous.effective_platform().clone(),
            previous.selector_policy_id(),
            previous.profile_id(),
            previous.profile_revision(),
            previous.root_layout_contract(),
            previous.filesystem_contract(),
            contract,
        )?;

        let derivation_key = spec.derivation_key();
        let alias = AliasKey::new(
            self.profile.manifest().profile_id.as_str(),
            Digest::from_bytes(self.profile.manifest().profile_revision.as_bytes()),
            request.reference.as_str(),
            previous.effective_platform().clone(),
            previous.selector_policy_id(),
        )?;
        let transaction = match self.store.try_begin_generation(spec)? {
            BeginGeneration::Existing(lease) => {
                self.store.set_alias(&alias, lease.id())?;
                return Ok(BuildOutput {
                    generation_id: lease.id(),
                    derivation_key,
                    alias_id: alias.id(),
                    cache_hit: true,
                });
            }
            BeginGeneration::Vacant(transaction) => transaction,
        };

        let mut directory = BuildDirectory::create(&self.runtime_root)?;
        let paths = directory.paths(self.profile)?;
        create_private_blkid_file(&paths.blkid_file)?;
        let context = E2fsHelperContext {
            profile: self.profile,
            lock: transaction.lock_file(),
            tmp: &paths.tmp_dir,
            blkid_file: &paths.blkid_file,
            policy: self.policy,
        };

        let staged = transaction.base_path();
        copy_sparse(&source_base, &staged)?;
        let mut logs = Vec::new();
        resize_in_place(&staged, source_bytes, target_bytes, &context, &mut logs)?;

        // The guest reconciles the marker in the filesystem against the START
        // it is sent, and this is a different generation, so the marker has to
        // say so or the adjusted image cannot boot.
        let marker_bytes = read_generation_marker(&staged, &context, target_bytes, &mut logs)?;
        let mut marker: GenerationMarker =
            pocket_protocol::decode_payload(&marker_bytes).map_err(|error| {
                HostBuildError::invalid("generation_marker", format!("cannot decode: {error}"))
            })?;
        marker.derivation_key = hex::encode(derivation_key.as_bytes());
        let updated = pocket_protocol::encode_payload(&marker).map_err(|error| {
            HostBuildError::invalid("generation_marker", format!("cannot encode: {error}"))
        })?;
        // The in-place rewrite depends on this: a derivation key is
        // fixed-width hex, so the replacement is the same length and no
        // allocation changes.
        if updated.len() != marker_bytes.len() {
            return Err(HostBuildError::invalid(
                "generation_marker",
                format!(
                    "replacement is {} bytes against the original {}",
                    updated.len(),
                    marker_bytes.len()
                ),
            ));
        }
        rewrite_generation_marker(&staged, &updated, &context, target_bytes, &mut logs)?;
        verify_filesystem(&staged, &context, target_bytes, &mut logs)?;

        // The resized filesystem must declare exactly the size it was asked
        // for; anything else is a resize that silently did something different.
        let (_, blocks) = crate::filesystem::ext4_geometry(&staged)
            .map_err(|error| HostBuildError::invalid("target", error.to_string()))?;
        let observed = blocks
            .checked_mul(u64::from(EXT4_BLOCK_BYTES_U32))
            .ok_or_else(|| HostBuildError::invalid("target", "resized size overflows"))?;
        if observed != target_bytes {
            return Err(HostBuildError::invalid(
                "target_bytes",
                format!("resize produced {observed} bytes, not the requested {target_bytes}"),
            ));
        }

        let mut sidecars = Vec::with_capacity(generation.manifest().sidecars().len());
        for sidecar in generation.manifest().sidecars() {
            let name = sidecar.name().to_owned();
            let from = generation.directory_path().join(&name);
            let bytes = fs::read(&from)
                .map_err(|error| HostBuildError::io("read source sidecar", &from, error))?;
            let mut file = transaction.create_sidecar(name.clone())?;
            write_synced(&mut file, &bytes, "sidecar")?;
            drop(file);
            let (digest, size) = hash_path(&transaction.staging_path().join(&name))?;
            sidecars.push(ImmutableSidecar::new(name, digest, size)?);
        }

        let (base_digest, _) = hash_path(&staged)?;
        let lease = transaction.publish_leased(base_digest, &sidecars)?;
        directory.cleanup()?;
        self.store.set_alias(&alias, lease.id())?;
        Ok(BuildOutput {
            generation_id: lease.id(),
            derivation_key,
            alias_id: alias.id(),
            cache_hit: false,
        })
    }

    pub fn build(&self, request: BuildRequest) -> Result<BuildOutput, HostBuildError> {
        self.profile.reverify()?;
        let prepared = prepare_build(self.profile, &request)?;
        let alias_id = prepared.alias.id();
        let derivation_key = prepared.spec.derivation_key();
        // Both arms hand back a held lease. The alias that roots the result is
        // set below, and until it is, only the lease stops a concurrent
        // collection from deleting a generation nothing yet refers to.
        match self.store.try_begin_generation(prepared.spec.clone())? {
            BeginGeneration::Existing(lease) => {
                self.store.set_alias(&prepared.alias, lease.id())?;
                Ok(BuildOutput {
                    generation_id: lease.id(),
                    derivation_key,
                    alias_id,
                    cache_hit: true,
                })
            }
            BeginGeneration::Vacant(transaction) => {
                let lease = self.build_transaction(transaction, &request, &prepared)?;
                self.store.set_alias(&prepared.alias, lease.id())?;
                Ok(BuildOutput {
                    generation_id: lease.id(),
                    derivation_key,
                    alias_id,
                    cache_hit: false,
                })
            }
        }
    }

    fn build_transaction(
        &self,
        transaction: GenerationTransaction<'_>,
        request: &BuildRequest,
        prepared: &PreparedBuild,
    ) -> Result<Lease, HostBuildError> {
        // Re-authenticate after acquiring the derivation lock. The payload is
        // subsequently re-authenticated again inside the trusted builder.
        let observed = pocket_oci::verify_canonical_layout(&request.oci_layout)?;
        if observed != prepared.image {
            return Err(HostBuildError::EvidenceMismatch {
                field: "oci_layout",
                expected: format!("{:?}", prepared.image.manifest_digest),
                actual: format!("{:?}", observed.manifest_digest),
            });
        }

        let mut directory = BuildDirectory::create(&self.runtime_root)?;
        let paths = directory.paths(self.profile)?;
        create_private_blkid_file(&paths.blkid_file)?;
        copy_builder_initramfs(self.profile, &paths.initramfs)?;
        copy_validator_initramfs(self.profile, &paths.validator_initramfs)?;
        let helper_context = E2fsHelperContext {
            profile: self.profile,
            lock: transaction.lock_file(),
            tmp: &paths.tmp_dir,
            blkid_file: &paths.blkid_file,
            policy: self.policy,
        };

        let mut stage_logs = Vec::new();
        let derivation_key = prepared.spec.derivation_key();
        let payload_uuid =
            deterministic_uuid(b"pocket-payload-ext4\0v1\0", derivation_key.as_bytes());
        let payload_hash_seed = deterministic_uuid(
            b"pocket-payload-directory-hash-seed\0v1\0",
            derivation_key.as_bytes(),
        );
        let mut payload_size = prepared.payload_sizing.initial;
        let mut payload_attempts = 0_u8;
        let mut payload_retry_resource = None;
        loop {
            payload_attempts += 1;
            create_sparse_file(&paths.payload, payload_size.bytes, "payload")?;
            self.profile.reverify()?;
            let payload_args = mke2fs_arguments(
                &paths.payload,
                "pocket-input",
                &payload_uuid,
                &payload_hash_seed,
                payload_size.inodes,
                Some(&request.oci_layout),
            );
            match run_guarded_helper(
                "format-payload",
                E2fsHelper::Mke2fs,
                &payload_args,
                &helper_context,
                payload_size.bytes,
            ) {
                Ok(log) => {
                    stage_logs.push(log);
                    break;
                }
                Err(error) => {
                    let Some(resource) = helper_capacity_resource(&error) else {
                        return Err(error);
                    };
                    let Some(retry) = capacity_retry(payload_attempts, prepared.payload_sizing)
                    else {
                        return Err(error);
                    };
                    discard_retry_file(&paths.payload, "payload", error)?;
                    payload_retry_resource = Some(resource);
                    payload_size = retry;
                }
            }
        }

        let target_uuid =
            deterministic_uuid(b"pocket-target-ext4\0v1\0", derivation_key.as_bytes());
        let target_hash_seed = deterministic_uuid(
            b"pocket-target-directory-hash-seed\0v1\0",
            derivation_key.as_bytes(),
        );

        let mut image_config = transaction.create_sidecar("image-config.json")?;
        write_synced(
            &mut image_config,
            &prepared.image.config_bytes,
            "image-config.json",
        )?;
        let mut metadata_manifest = transaction.create_sidecar("metadata.manifest")?;
        let mut accounts = transaction.create_sidecar("accounts.cbor")?;
        let mut target_size = prepared.target_sizing.initial;
        let mut target_attempts = 0_u8;
        let mut target_retry_resource = None;
        let builder_run = loop {
            target_attempts += 1;
            create_sparse_target(&transaction, target_size.bytes)?;
            self.profile.reverify()?;
            let target_args = mke2fs_arguments(
                &transaction.base_path(),
                "pocket-root",
                &target_uuid,
                &target_hash_seed,
                target_size.inodes,
                None,
            );
            match run_guarded_helper(
                "format-target",
                E2fsHelper::Mke2fs,
                &target_args,
                &helper_context,
                target_size.bytes,
            ) {
                Ok(log) => stage_logs.push(log),
                Err(error) => {
                    let Some(resource) = helper_capacity_resource(&error) else {
                        return Err(error);
                    };
                    let Some(retry) = capacity_retry(target_attempts, prepared.target_sizing)
                    else {
                        return Err(error);
                    };
                    discard_retry_file(&transaction.base_path(), "target", error)?;
                    target_retry_resource = Some(resource);
                    target_size = retry;
                    continue;
                }
            }

            reset_sidecar(
                &mut metadata_manifest,
                &transaction.staging_path().join("metadata.manifest"),
            )?;
            reset_sidecar(
                &mut accounts,
                &transaction.staging_path().join("accounts.cbor"),
            )?;
            self.profile.reverify()?;
            let launch_plan = build_builder_launch_plan(
                self.profile,
                &paths,
                &transaction.base_path(),
                self.policy.guard_term_timeout,
            )?;
            match run_builder(
                &launch_plan,
                transaction.lock_file(),
                &prepared.start,
                &mut metadata_manifest,
                &mut accounts,
                self.profile,
                self.policy,
            ) {
                Ok(run) => break run,
                Err(error) => {
                    let Some(resource) = guest_capacity_resource(&error) else {
                        return Err(error);
                    };
                    let Some(retry) = capacity_retry(target_attempts, prepared.target_sizing)
                    else {
                        return Err(error);
                    };
                    discard_retry_file(&transaction.base_path(), "target", error)?;
                    target_retry_resource = Some(resource);
                    target_size = retry;
                }
            }
        };
        stage_logs.extend(builder_run.logs);
        metadata_manifest.sync_all().map_err(|error| {
            HostBuildError::io(
                "sync metadata manifest",
                transaction.staging_path().join("metadata.manifest"),
                error,
            )
        })?;
        accounts.sync_all().map_err(|error| {
            HostBuildError::io(
                "sync account database",
                transaction.staging_path().join("accounts.cbor"),
                error,
            )
        })?;
        drop(metadata_manifest);
        drop(accounts);
        drop(image_config);

        let account_db = load_account_evidence(
            &transaction.staging_path().join("accounts.cbor"),
            &builder_run.done,
        )?;

        self.profile.reverify()?;
        stage_logs.push(run_guarded_helper(
            "check-target",
            E2fsHelper::E2fsck,
            &[
                OsString::from("-f"),
                OsString::from("-n"),
                transaction.base_path().into_os_string(),
            ],
            &helper_context,
            target_size.bytes,
        )?);
        validate_ext4_base(&transaction.base_path()).map_err(map_ext4_error)?;
        let (pre_validation_digest, base_size) = hash_path(&transaction.base_path())?;
        if base_size != target_size.bytes {
            return Err(HostBuildError::EvidenceMismatch {
                field: "base.size",
                expected: target_size.bytes.to_string(),
                actual: base_size.to_string(),
            });
        }

        let validation_start = validator_start(
            self.profile,
            prepared,
            &builder_run.done,
            account_db,
            &target_uuid,
            base_size,
            random_challenge()?,
        )?;
        self.profile.reverify()?;
        let validation_plan = build_validator_launch_plan(
            self.profile,
            &paths,
            &transaction.base_path(),
            self.policy.guard_term_timeout,
        )?;
        let validation_run = run_validator(
            &validation_plan,
            transaction.lock_file(),
            &validation_start,
            self.profile,
            self.policy,
        )?;
        stage_logs.extend(validation_run.logs);
        validate_ext4_base(&transaction.base_path()).map_err(map_ext4_error)?;
        let (base_digest, post_validation_size) = hash_path(&transaction.base_path())?;
        if base_digest != pre_validation_digest || post_validation_size != base_size {
            return Err(HostBuildError::EvidenceMismatch {
                field: "base.after_validation",
                expected: format!("{pre_validation_digest}:{base_size}"),
                actual: format!("{base_digest}:{post_validation_size}"),
            });
        }

        let validation_evidence_bytes = pocket_protocol::encode_payload(&validation_run.done)?;
        let mut validation_evidence = transaction.create_sidecar("validation-evidence.cbor")?;
        write_synced(
            &mut validation_evidence,
            &validation_evidence_bytes,
            "validation-evidence.cbor",
        )?;
        drop(validation_evidence);

        let mut artifact_digest = transaction.create_sidecar("artifact.digest")?;
        write_synced(
            &mut artifact_digest,
            format!("{base_digest}\n").as_bytes(),
            "artifact.digest",
        )?;
        drop(artifact_digest);

        let build_record_bytes = build_record(
            self.profile,
            prepared,
            &builder_run.done,
            &validation_run.done,
            base_digest,
            base_size,
            BuildSizingEvidence {
                payload: payload_size,
                payload_attempts,
                payload_retry_resource,
                target: target_size,
                target_attempts,
                target_retry_resource,
                payload_hash_seed: &payload_hash_seed,
                target_hash_seed: &target_hash_seed,
            },
        )?;
        let mut build_record_file = transaction.create_sidecar("build-record.json")?;
        write_synced(
            &mut build_record_file,
            &build_record_bytes,
            "build-record.json",
        )?;
        drop(build_record_file);

        let log_bytes = encode_build_log(&stage_logs, self.policy.maximum_log_bytes);
        let mut build_log = transaction.create_sidecar("build.log")?;
        write_synced(&mut build_log, &log_bytes, "build.log")?;
        drop(build_log);

        let sidecar_names = [
            "accounts.cbor",
            "artifact.digest",
            "build-record.json",
            "build.log",
            "image-config.json",
            "metadata.manifest",
            "validation-evidence.cbor",
        ];
        let mut sidecars = Vec::with_capacity(sidecar_names.len());
        for name in sidecar_names {
            let (digest, size) = hash_path(&transaction.staging_path().join(name))?;
            sidecars.push(ImmutableSidecar::new(name, digest, size)?);
        }
        let lease = transaction.publish_leased(base_digest, &sidecars)?;
        directory.cleanup()?;
        Ok(lease)
    }
}

fn prepare_build(
    profile: &VerifiedProfile,
    request: &BuildRequest,
) -> Result<PreparedBuild, HostBuildError> {
    if request.source_reference.is_empty()
        || request.source_reference.len() > 1024
        || request.source_reference.contains(['\0', '\n', '\r'])
    {
        return Err(HostBuildError::invalid(
            "source_reference",
            "must contain 1..=1024 bytes without NUL or line separators",
        ));
    }
    if !request.oci_layout.is_absolute() {
        return Err(HostBuildError::invalid(
            "oci_layout",
            "must be an absolute path",
        ));
    }
    let manifest = profile.manifest();
    if manifest.oci_os != "linux" || manifest.oci_architecture != "amd64" {
        return Err(HostBuildError::Unsupported {
            field: "profile.platform",
            value: format!("{}/{}", manifest.oci_os, manifest.oci_architecture),
        });
    }
    if manifest.contracts.selector_policy != pocket_oci::SELECTOR_POLICY_ID {
        return Err(HostBuildError::EvidenceMismatch {
            field: "selector_policy",
            expected: manifest.contracts.selector_policy.clone(),
            actual: pocket_oci::SELECTOR_POLICY_ID.to_owned(),
        });
    }
    if !manifest
        .accepted_oci_variants
        .iter()
        .any(|variant| variant == &request.requested_variant)
    {
        return Err(HostBuildError::invalid(
            "requested_variant",
            format!(
                "{:?} is not admitted by {:?}",
                request.requested_variant, manifest.accepted_oci_variants
            ),
        ));
    }

    let image = pocket_oci::verify_canonical_layout(&request.oci_layout)?;
    if image.selector_policy != manifest.contracts.selector_policy {
        return Err(HostBuildError::EvidenceMismatch {
            field: "verified_image.selector_policy",
            expected: manifest.contracts.selector_policy.clone(),
            actual: image.selector_policy.clone(),
        });
    }
    require_canonical_oci_boundary(&image)?;
    validate_image_platforms(profile, &image)?;
    if request
        .requested_variant
        .as_ref()
        .is_some_and(|variant| image.effective_platform.variant.as_ref() != Some(variant))
    {
        return Err(HostBuildError::EvidenceMismatch {
            field: "requested_variant",
            expected: format!("{:?}", request.requested_variant),
            actual: format!("{:?}", image.effective_platform.variant),
        });
    }

    let payload_sizing = payload_sizing(&request.oci_layout)?;
    let target_sizing = target_sizing(&image, ManifestLimits::default().max_entries)?;
    let build_contract_digest = build_contract_digest(profile, target_sizing)?;
    let descriptor_platform = image
        .descriptor_platform
        .as_ref()
        .map(store_platform)
        .transpose()?;
    let config_platform = store_platform(&image.config_platform)?;
    let effective_platform = store_platform(&image.effective_platform)?;
    let spec = GenerationSpec::new(
        Digest::from_bytes(*image.manifest_digest.bytes()),
        Digest::from_bytes(*image.config_digest.bytes()),
        image
            .layers
            .iter()
            .map(|layer| Digest::from_bytes(*layer.digest.bytes()))
            .collect(),
        image
            .layers
            .iter()
            .map(|layer| Digest::from_bytes(*layer.diff_id.bytes()))
            .collect(),
        descriptor_platform,
        config_platform,
        effective_platform,
        image.selector_policy.clone(),
        manifest.profile_id.clone(),
        Digest::from_bytes(manifest.profile_revision.as_bytes()),
        manifest.contracts.root_layout.clone(),
        manifest.contracts.filesystem.clone(),
        build_contract_digest,
    )?;
    let requested_platform = StorePlatform::new(
        "linux",
        "amd64",
        request.requested_variant.clone(),
        None,
        Vec::new(),
    )?;
    let alias = AliasKey::new(
        manifest.profile_id.clone(),
        Digest::from_bytes(manifest.profile_revision.as_bytes()),
        request.source_reference.clone(),
        requested_platform,
        manifest.contracts.selector_policy.clone(),
    )?;
    let start = builder_start(profile, &image, spec.derivation_key())?;
    Ok(PreparedBuild {
        image,
        spec,
        alias,
        start,
        payload_sizing,
        target_sizing,
    })
}

fn require_canonical_oci_boundary(image: &VerifiedImage) -> Result<(), HostBuildError> {
    const OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
    const OCI_CONFIG: &str = "application/vnd.oci.image.config.v1+json";
    const OCI_LAYER: &str = "application/vnd.oci.image.layer.v1.tar";
    const OCI_LAYER_GZIP: &str = "application/vnd.oci.image.layer.v1.tar+gzip";
    const OCI_LAYER_ZSTD: &str = "application/vnd.oci.image.layer.v1.tar+zstd";
    if image.manifest_media_type != OCI_MANIFEST {
        return Err(HostBuildError::Unsupported {
            field: "manifest_media_type",
            value: image.manifest_media_type.clone(),
        });
    }
    if image.config_media_type != OCI_CONFIG {
        return Err(HostBuildError::Unsupported {
            field: "config_media_type",
            value: image.config_media_type.clone(),
        });
    }
    for layer in &image.layers {
        if !matches!(
            layer.media_type.as_str(),
            OCI_LAYER | OCI_LAYER_GZIP | OCI_LAYER_ZSTD
        ) {
            return Err(HostBuildError::Unsupported {
                field: "layer_media_type",
                value: layer.media_type.clone(),
            });
        }
    }
    Ok(())
}

fn validate_image_platforms(
    profile: &VerifiedProfile,
    image: &VerifiedImage,
) -> Result<(), HostBuildError> {
    for (field, platform) in [
        ("config_platform", Some(&image.config_platform)),
        ("effective_platform", Some(&image.effective_platform)),
        ("descriptor_platform", image.descriptor_platform.as_ref()),
    ] {
        let Some(platform) = platform else { continue };
        if platform.os != "linux" || platform.architecture != "amd64" {
            return Err(HostBuildError::Unsupported {
                field,
                value: format!("{}/{}", platform.os, platform.architecture),
            });
        }
        if platform.os_version.is_some()
            || !platform.os_features.is_empty()
            || !platform.features.is_empty()
        {
            return Err(HostBuildError::Unsupported {
                field,
                value: format!(
                    "os_version={:?}, os_features={:?}, features={:?}",
                    platform.os_version, platform.os_features, platform.features
                ),
            });
        }
        if !profile
            .manifest()
            .accepted_oci_variants
            .iter()
            .any(|variant| variant == &platform.variant)
        {
            return Err(HostBuildError::Unsupported {
                field,
                value: format!("variant {:?}", platform.variant),
            });
        }
    }
    Ok(())
}

fn store_platform(platform: &ImagePlatform) -> Result<StorePlatform, HostBuildError> {
    if !platform.features.is_empty() {
        return Err(HostBuildError::Unsupported {
            field: "platform.features",
            value: format!("{:?}", platform.features),
        });
    }
    Ok(StorePlatform::new(
        platform.os.clone(),
        platform.architecture.clone(),
        platform.variant.clone(),
        platform.os_version.clone(),
        platform.os_features.clone(),
    )?)
}

fn protocol_platform(platform: &ImagePlatform) -> ProtocolPlatform {
    ProtocolPlatform {
        os: platform.os.clone(),
        architecture: platform.architecture.clone(),
        variant: platform.variant.clone(),
    }
}

fn builder_start(
    profile: &VerifiedProfile,
    image: &VerifiedImage,
    derivation_key: DerivationKey,
) -> Result<BuilderStart, HostBuildError> {
    let manifest = profile.manifest();
    let start = BuilderStart {
        profile_id: manifest.profile_id.clone(),
        profile_revision: manifest.profile_revision.hexadecimal(),
        derivation_key: hex::encode(derivation_key.as_bytes()),
        selected_manifest: OciDescriptor {
            digest: image.manifest_digest.to_string(),
            size: image.manifest_size,
            media_type: image.manifest_media_type.clone(),
        },
        config: OciDescriptor {
            digest: image.config_digest.to_string(),
            size: image.config_size,
            media_type: image.config_media_type.clone(),
        },
        layers: image
            .layers
            .iter()
            .map(|layer| BuilderLayerDescriptor {
                descriptor: OciDescriptor {
                    digest: layer.digest.to_string(),
                    size: layer.size,
                    media_type: layer.media_type.clone(),
                },
                diff_id: layer.diff_id.to_string(),
                uncompressed_size: layer.uncompressed_size,
            })
            .collect(),
        descriptor_platform: image.descriptor_platform.as_ref().map(protocol_platform),
        config_platform: protocol_platform(&image.config_platform),
        effective_platform: protocol_platform(&image.effective_platform),
        selector_policy: image.selector_policy.clone(),
        root_layout: manifest.contracts.root_layout.clone(),
        filesystem_contract: manifest.contracts.filesystem.clone(),
        manifest_schema: manifest.builder.manifest_schema.clone(),
        manifest_limits: ManifestLimits::default(),
        expected_tools: manifest
            .builder
            .required_tools
            .iter()
            .map(|tool| ToolIdentity {
                role: tool.role.clone(),
                sha256: tool.sha256.clone(),
                version: tool.version.clone(),
            })
            .collect(),
        input_reference: "root".to_owned(),
        original_user: image.process.user.clone(),
        expected_physmem_bytes: manifest.memory.builder_memory_bytes,
        source_date_epoch: manifest.builder.source_date_epoch,
    };
    start.validate()?;
    Ok(start)
}

fn validator_start(
    profile: &VerifiedProfile,
    prepared: &PreparedBuild,
    done: &BuilderDone,
    account_db: AccountDb,
    target_uuid: &str,
    target_bytes: u64,
    challenge: String,
) -> Result<ValidatorStart, HostBuildError> {
    let manifest = profile.manifest();
    let start = ValidatorStart {
        profile_id: manifest.profile_id.clone(),
        profile_revision: manifest.profile_revision.hexadecimal(),
        challenge,
        derivation_key: hex::encode(prepared.spec.derivation_key().as_bytes()),
        root_layout: manifest.contracts.root_layout.clone(),
        filesystem_contract: manifest.contracts.filesystem.clone(),
        manifest_schema: manifest.validator.manifest_schema.clone(),
        manifest_limits: ManifestLimits::default(),
        expected_manifest_sha256: done.manifest_sha256.clone(),
        expected_manifest_entry_count: done.entry_count,
        expected_manifest_byte_count: done.byte_count,
        expected_generation_marker: GenerationMarker::from_start(
            &prepared.start,
            done.account_db_sha256.clone(),
        ),
        expected_generation_marker_sha256: done.generation_marker_sha256.clone(),
        expected_account_db: account_db,
        expected_filesystem_uuid: target_uuid.to_owned(),
        expected_filesystem_bytes: target_bytes,
        expected_physmem_bytes: manifest.memory.validator_memory_bytes,
    };
    start.validate()?;
    Ok(start)
}

fn load_account_evidence(path: &Path, done: &BuilderDone) -> Result<AccountDb, HostBuildError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| HostBuildError::io("inspect account evidence", path, error))?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_ACCOUNT_DB_BYTES as u64 {
        return Err(HostBuildError::invalid(
            "accounts.cbor",
            "account evidence is not a bounded regular file",
        ));
    }
    let mut bytes = Vec::new();
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .and_then(|file| {
            file.take((MAX_ACCOUNT_DB_BYTES + 1) as u64)
                .read_to_end(&mut bytes)
        })
        .map_err(|error| HostBuildError::io("read account evidence", path, error))?;
    if bytes.len() > MAX_ACCOUNT_DB_BYTES || bytes.len() as u64 != metadata.len() {
        return Err(HostBuildError::invalid(
            "accounts.cbor",
            "account evidence changed or exceeds its hard cap",
        ));
    }
    let account_db = AccountDb::from_canonical_bytes(bytes)?;
    compare_evidence(
        "validator_account_db_sha256",
        &done.account_db_sha256,
        &account_db.sha256,
    )?;
    Ok(account_db)
}

/// The identity contract for one built generation.
///
/// Target sizing is here because it shapes the output filesystem. Payload
/// sizing is deliberately not: it is the scratch image the OCI layout is copied
/// into so the guest can read it, and its geometry leaves no trace in the base.
/// Folding it in would make the same image cache separately depending on how
/// many unreferenced blobs its source layout happened to carry -- a multi-arch
/// layout and a single-arch one would never share a generation.
fn build_contract_digest(
    profile: &VerifiedProfile,
    target: FilesystemSizing,
) -> Result<Digest, HostBuildError> {
    let manifest = profile.manifest();
    let record = BuildContractRecord {
        schema: "pocket-host-build-contract-v4",
        profile_id: &manifest.profile_id,
        profile_revision: manifest.profile_revision.to_string(),
        selector_policy: &manifest.contracts.selector_policy,
        uml_sha256: manifest.artifacts.uml.sha256.to_string(),
        builder_initramfs_sha256: manifest.artifacts.builder_initramfs.sha256.to_string(),
        validator_initramfs_sha256: manifest.artifacts.validator_initramfs.sha256.to_string(),
        mke2fs_sha256: manifest.artifacts.mke2fs.sha256.to_string(),
        e2fsck_sha256: manifest.artifacts.e2fsck.sha256.to_string(),
        mke2fs_config_sha256: manifest.artifacts.mke2fs_config.sha256.to_string(),
        e2fsck_config_sha256: manifest.artifacts.e2fsck_config.sha256.to_string(),
        manifest_schema: &manifest.builder.manifest_schema,
        validator_manifest_schema: &manifest.validator.manifest_schema,
        builder_tools: &manifest.builder.required_tools,
        source_date_epoch: manifest.builder.source_date_epoch,
        target_initial_size_bytes: target.initial.bytes,
        target_initial_inodes: target.initial.inodes,
        target_retry_size_bytes: target.retry.map(|size| size.bytes),
        target_retry_inodes: target.retry.map(|size| size.inodes),
        filesystem_sizing_contract: "pocket-ext4-bytes-inodes-v2",
        directory_hash_seed_contract: "sha256-derivation-domain-uuid-v1",
        capacity_retry_contract: "fresh-next-block-and-inode-class-once-v1",
        conversion_contract: "pocket-umoci-raw-unpack-v1",
        validation_contract: "fresh-read-only-uml-challenge-evidence-v1",
        protocol_major: pocket_protocol::PROTOCOL_MAJOR,
        protocol_minor: pocket_protocol::PROTOCOL_MINOR,
    };
    let bytes = serde_json::to_vec(&record).map_err(|error| {
        HostBuildError::invalid("build_contract", format!("cannot serialize: {error}"))
    })?;
    Ok(Digest::of_bytes(&bytes))
}

fn payload_sizing(root: &Path) -> Result<FilesystemSizing, HostBuildError> {
    let mut stack = vec![root.to_path_buf()];
    let mut entries = 0_usize;
    let mut bytes = 0_u64;
    while let Some(path) = stack.pop() {
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| HostBuildError::io("inspect OCI layout", &path, error))?;
        entries = entries
            .checked_add(1)
            .ok_or_else(|| HostBuildError::invalid("oci_layout", "entry count overflow"))?;
        if entries > MAX_LAYOUT_ENTRIES {
            return Err(HostBuildError::invalid(
                "oci_layout",
                format!("contains more than {MAX_LAYOUT_ENTRIES} entries"),
            ));
        }
        if metadata.file_type().is_dir() {
            for entry in fs::read_dir(&path)
                .map_err(|error| HostBuildError::io("read OCI layout", &path, error))?
            {
                stack.push(
                    entry
                        .map_err(|error| HostBuildError::io("read OCI layout", &path, error))?
                        .path(),
                );
            }
        } else if metadata.file_type().is_file() {
            bytes = bytes.checked_add(metadata.len()).ok_or_else(|| {
                HostBuildError::invalid("oci_layout", "logical byte count overflow")
            })?;
        } else {
            return Err(HostBuildError::invalid(
                "oci_layout",
                format!("{} is not a plain file or directory", path.display()),
            ));
        }
    }
    let entry_count = u64::try_from(entries)
        .map_err(|_| HostBuildError::invalid("oci_layout", "entry count does not fit u64"))?;
    let inode_requirement = entry_count
        .checked_add(entry_count / 4)
        .and_then(|value| value.checked_add(PAYLOAD_INODE_HEADROOM))
        .ok_or_else(|| HostBuildError::invalid("oci_layout", "inode sizing overflow"))?;
    let inodes = sized_inode_class(inode_requirement, PAYLOAD_INODE_CLASS, "payload")?;
    let inode_table_bytes = inodes.checked_mul(EXT4_INODE_BYTES).ok_or_else(|| {
        HostBuildError::invalid("oci_layout", "inode-table sizing arithmetic overflow")
    })?;
    let directory_bytes = entry_count.checked_mul(EXT4_BLOCK_BYTES).ok_or_else(|| {
        HostBuildError::invalid("oci_layout", "directory sizing arithmetic overflow")
    })?;
    let desired = bytes
        .checked_add(bytes / 4)
        .and_then(|value| value.checked_add(64 * 1024 * 1024))
        .and_then(|value| value.checked_add(inode_table_bytes))
        .and_then(|value| value.checked_add(directory_bytes))
        .ok_or_else(|| {
            HostBuildError::invalid("oci_layout", "payload sizing arithmetic overflow")
        })?;
    filesystem_sizing(
        desired.max(PAYLOAD_MINIMUM_BYTES),
        inodes,
        MAX_PAYLOAD_BYTES,
        PAYLOAD_INODE_CLASS,
        "payload",
    )
}

fn target_sizing(
    image: &VerifiedImage,
    maximum_manifest_entries: u64,
) -> Result<FilesystemSizing, HostBuildError> {
    let logical = image.layers.iter().try_fold(0_u64, |sum, layer| {
        sum.checked_add(layer.uncompressed_size)
            .ok_or_else(|| HostBuildError::invalid("layers", "uncompressed byte count overflow"))
    })?;
    // Every filesystem object in a tar stream consumes at least one 512-byte
    // header record. This deliberately conservative upper bound also covers
    // objects created and later removed by a subsequent layer. The negotiated
    // final-manifest limit remains the hard supported output bound.
    let archive_entry_upper = (logical / TAR_RECORD_BYTES)
        .max(1)
        .min(maximum_manifest_entries);
    let inode_requirement = archive_entry_upper
        .checked_add(TARGET_INTERNAL_INODES)
        .ok_or_else(|| HostBuildError::invalid("layers", "inode sizing overflow"))?;
    let inodes = sized_inode_class(inode_requirement, TARGET_INODE_CLASS, "target")?;
    let inode_table_bytes = inodes.checked_mul(EXT4_INODE_BYTES).ok_or_else(|| {
        HostBuildError::invalid("layers", "inode-table sizing arithmetic overflow")
    })?;
    let entry_allocation_floor = archive_entry_upper
        .checked_mul(EXT4_BLOCK_BYTES)
        .ok_or_else(|| HostBuildError::invalid("layers", "entry sizing arithmetic overflow"))?;
    let content_bytes = logical
        .checked_mul(2)
        .ok_or_else(|| HostBuildError::invalid("layers", "content sizing arithmetic overflow"))?;
    let desired = content_bytes
        .max(entry_allocation_floor)
        .checked_add(inode_table_bytes)
        .and_then(|value| value.checked_add(512 * 1024 * 1024))
        .ok_or_else(|| HostBuildError::invalid("layers", "target sizing arithmetic overflow"))?;
    filesystem_sizing(
        desired.max(TARGET_MINIMUM_BYTES),
        inodes,
        MAX_TARGET_BYTES,
        TARGET_INODE_CLASS,
        "target",
    )
}

fn filesystem_sizing(
    desired_bytes: u64,
    inodes: u64,
    maximum_bytes: u64,
    inode_class: u64,
    field: &'static str,
) -> Result<FilesystemSizing, HostBuildError> {
    let initial = FilesystemSize {
        bytes: sized_class(desired_bytes, maximum_bytes, field)?,
        inodes,
    };
    let retry = match initial
        .bytes
        .checked_add(SIZE_CLASS_BYTES)
        .filter(|bytes| *bytes <= maximum_bytes)
    {
        Some(bytes) => {
            let inodes = initial.inodes.checked_add(inode_class).ok_or_else(|| {
                HostBuildError::invalid(field, "retry inode-count arithmetic overflow")
            })?;
            Some(FilesystemSize { bytes, inodes })
        }
        None => None,
    };
    Ok(FilesystemSizing { initial, retry })
}

fn sized_inode_class(value: u64, class: u64, field: &'static str) -> Result<u64, HostBuildError> {
    value
        .checked_add(class - 1)
        .map(|value| value / class * class)
        .ok_or_else(|| HostBuildError::invalid(field, "inode-class rounding overflow"))
}

fn sized_class(value: u64, maximum: u64, field: &'static str) -> Result<u64, HostBuildError> {
    let rounded = value
        .checked_add(SIZE_CLASS_BYTES - 1)
        .map(|value| value / SIZE_CLASS_BYTES * SIZE_CLASS_BYTES)
        .ok_or_else(|| HostBuildError::invalid(field, "size-class rounding overflow"))?;
    if rounded > maximum {
        return Err(HostBuildError::invalid(
            field,
            format!("requires {rounded} bytes, maximum is {maximum}"),
        ));
    }
    Ok(rounded)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CapacityResource {
    Blocks,
    Inodes,
    BlocksAndInodes,
    BlockOrInode,
}

impl CapacityResource {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Blocks => "blocks",
            Self::Inodes => "inodes",
            Self::BlocksAndInodes => "blocks-and-inodes",
            Self::BlockOrInode => "block-or-inode",
        }
    }
}

/// A control-protocol failure wraps the typed error it carries so the guest
/// console travels with it. Every classifier must look through that wrapper,
/// or attaching the console silently turns a retryable failure into a fatal one.
fn innermost_build_error(error: &HostBuildError) -> &HostBuildError {
    match error {
        HostBuildError::GuestProtocol { source, .. } => innermost_build_error(source),
        other => other,
    }
}

fn helper_capacity_resource(error: &HostBuildError) -> Option<CapacityResource> {
    let HostBuildError::GuardStatus {
        stage, diagnostic, ..
    } = innermost_build_error(error)
    else {
        return None;
    };
    if !matches!(*stage, "format-payload" | "format-target") {
        return None;
    }
    let blocks = diagnostic.contains("Could not allocate block in ext2 filesystem");
    let inodes = diagnostic.contains("Could not allocate inode in ext2 filesystem");
    match (blocks, inodes) {
        (true, true) => Some(CapacityResource::BlocksAndInodes),
        (true, false) => Some(CapacityResource::Blocks),
        (false, true) => Some(CapacityResource::Inodes),
        (false, false) => None,
    }
}

fn capacity_retry(attempt: u8, sizing: FilesystemSizing) -> Option<FilesystemSize> {
    (attempt == 1).then_some(sizing.retry).flatten()
}

fn guest_capacity_resource(error: &HostBuildError) -> Option<CapacityResource> {
    let HostBuildError::Guest { message, .. } = innermost_build_error(error) else {
        return None;
    };
    if message.errno != Some(libc::ENOSPC) {
        return None;
    }
    // The guest names the exhausted resource exactly, as one token between
    // "target " and " capacity exhausted". Substring tests are not good enough:
    // "block-and-inode" contains "inode", so a loose match reads a build that
    // ran out of both as inode-only and retries with the same block budget that
    // just failed.
    let resource = message
        .diagnostic
        .split_once("target ")
        .and_then(|(_, rest)| rest.split_once(" capacity exhausted"))
        .map(|(resource, _)| resource);
    Some(match resource {
        Some("block-and-inode") => CapacityResource::BlocksAndInodes,
        Some("block") => CapacityResource::Blocks,
        Some("inode") => CapacityResource::Inodes,
        _ => CapacityResource::BlockOrInode,
    })
}

fn create_sparse_file(path: &Path, size: u64, role: &'static str) -> Result<(), HostBuildError> {
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| HostBuildError::io("create sparse ext4", path, error))?;
    file.set_len(size)
        .map_err(|error| HostBuildError::io("size sparse ext4", path, error))?;
    let metadata = file
        .metadata()
        .map_err(|error| HostBuildError::io("inspect sparse ext4", path, error))?;
    if !metadata.file_type().is_file()
        || metadata.len() != size
        || metadata.mode() & 0o7777 != 0o600
    {
        return Err(HostBuildError::invalid(
            role,
            "new sparse ext4 is not an exact owner-only regular file",
        ));
    }
    Ok(())
}

fn create_sparse_target(
    transaction: &GenerationTransaction<'_>,
    size: u64,
) -> Result<(), HostBuildError> {
    let path = transaction.base_path();
    let file = transaction.create_base()?;
    file.set_len(size)
        .map_err(|error| HostBuildError::io("size target ext4", &path, error))?;
    let metadata = file
        .metadata()
        .map_err(|error| HostBuildError::io("inspect target ext4", &path, error))?;
    if !metadata.file_type().is_file()
        || metadata.len() != size
        || metadata.mode() & 0o7777 != 0o600
    {
        return Err(HostBuildError::invalid(
            "target",
            "new target ext4 is not an exact owner-only regular file",
        ));
    }
    Ok(())
}

fn discard_retry_file(
    path: &Path,
    role: &'static str,
    primary: HostBuildError,
) -> Result<(), HostBuildError> {
    let cleanup = (|| {
        let metadata = fs::symlink_metadata(path)
            .map_err(|error| HostBuildError::io("inspect failed ext4", path, error))?;
        if !metadata.file_type().is_file() || metadata.mode() & 0o7777 != 0o600 {
            return Err(HostBuildError::invalid(
                role,
                "refusing to discard a substituted failed ext4 path",
            ));
        }
        fs::remove_file(path)
            .map_err(|error| HostBuildError::io("discard failed ext4", path, error))
    })();
    cleanup.map_err(|cleanup| HostBuildError::Cleanup {
        primary: Box::new(primary),
        cleanup: cleanup.to_string(),
    })
}

fn reset_sidecar(file: &mut File, path: &Path) -> Result<(), HostBuildError> {
    file.set_len(0)
        .map_err(|error| HostBuildError::io("truncate retried sidecar", path, error))?;
    file.seek(SeekFrom::Start(0))
        .map_err(|error| HostBuildError::io("rewind retried sidecar", path, error))?;
    Ok(())
}

#[derive(Debug)]
struct BuildPaths {
    uml_dir: PathBuf,
    tmp_dir: PathBuf,
    blkid_file: PathBuf,
    payload: PathBuf,
    initramfs: PathBuf,
    validator_initramfs: PathBuf,
    umid: String,
    validator_umid: String,
}

struct BuildDirectory {
    root: PathBuf,
    path: PathBuf,
    device: u64,
    inode: u64,
    cleaned: bool,
    /// Held for this directory's whole life. Its release is what tells a later
    /// sweep that this build's owner is gone, however it died.
    _owner: File,
}

impl BuildDirectory {
    fn create(root: &ManagedUmlPath) -> Result<Self, HostBuildError> {
        let root_path = root.as_path();
        // Reclaim what earlier signal-killed invocations left behind before
        // adding to it.
        crate::operation::reclaim_orphans(root_path, "build-").map_err(|error| {
            HostBuildError::io("reclaim abandoned build directories", root_path, error)
        })?;
        let creation = crate::operation::lock_creation(root_path).map_err(|error| {
            HostBuildError::io("lock build-directory creation", root_path, error)
        })?;
        for _ in 0..128 {
            let id = random_id()?;
            let path = root.as_path().join(format!("build-{id}"));
            match fs::create_dir(&path) {
                Ok(()) => {
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).map_err(
                        |error| HostBuildError::io("set build-directory mode", &path, error),
                    )?;
                    for child in ["uml", "tmp"] {
                        let child_path = path.join(child);
                        fs::create_dir(&child_path).map_err(|error| {
                            HostBuildError::io("create build subdirectory", &child_path, error)
                        })?;
                        fs::set_permissions(&child_path, fs::Permissions::from_mode(0o700))
                            .map_err(|error| {
                                HostBuildError::io(
                                    "set build subdirectory mode",
                                    &child_path,
                                    error,
                                )
                            })?;
                    }
                    let owner = crate::operation::claim_owner(&path).map_err(|error| {
                        HostBuildError::io("claim build directory", &path, error)
                    })?;
                    let metadata = fs::symlink_metadata(&path).map_err(|error| {
                        HostBuildError::io("inspect build directory", &path, error)
                    })?;
                    drop(creation);
                    return Ok(Self {
                        root: root.as_path().to_path_buf(),
                        path,
                        device: metadata.dev(),
                        inode: metadata.ino(),
                        cleaned: false,
                        _owner: owner,
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => {
                    return Err(HostBuildError::io("create build directory", &path, error));
                }
            }
        }
        Err(HostBuildError::invalid(
            "build_id",
            "could not allocate a unique build directory",
        ))
    }

    fn paths(&self, profile: &VerifiedProfile) -> Result<BuildPaths, HostBuildError> {
        let managed = ManagedUmlPath::new(&self.path)?;
        let uml_dir = managed.join_component("uml")?.into_path_buf();
        let tmp_dir = managed.join_component("tmp")?.into_path_buf();
        let blkid_file = tmp_dir.join("blkid.tab");
        let payload = managed.join_component("oci-payload.ext4")?.into_path_buf();
        let initramfs = managed
            .join_component("builder-initramfs.cpio")?
            .into_path_buf();
        let validator_initramfs = managed
            .join_component("validator-initramfs.cpio")?
            .into_path_buf();
        let umid = self
            .path
            .file_name()
            .and_then(OsStr::to_str)
            .ok_or_else(|| HostBuildError::invalid("build_id", "generated name is not UTF-8"))?
            .to_owned();
        let validator_umid = format!("{umid}-v");
        if validator_umid.len() > usize::from(profile.manifest().launch.max_umid_bytes) {
            return Err(HostBuildError::invalid(
                "build_id",
                "generated name exceeds the profile UML identifier cap",
            ));
        }
        Ok(BuildPaths {
            uml_dir,
            tmp_dir,
            blkid_file,
            payload,
            initramfs,
            validator_initramfs,
            umid,
            validator_umid,
        })
    }

    fn cleanup(&mut self) -> Result<(), HostBuildError> {
        if self.cleaned {
            return Ok(());
        }
        if self.path.parent() != Some(self.root.as_path()) {
            return Err(HostBuildError::invalid(
                "cleanup",
                "owned build directory escaped its root",
            ));
        }
        let metadata = fs::symlink_metadata(&self.path).map_err(|error| {
            HostBuildError::io("verify build directory before cleanup", &self.path, error)
        })?;
        if !metadata.file_type().is_dir()
            || metadata.dev() != self.device
            || metadata.ino() != self.inode
        {
            return Err(HostBuildError::invalid(
                "cleanup",
                "build directory identity changed",
            ));
        }
        fs::remove_dir_all(&self.path).map_err(|error| {
            HostBuildError::io("remove owned build directory", &self.path, error)
        })?;
        self.cleaned = true;
        Ok(())
    }
}

impl Drop for BuildDirectory {
    fn drop(&mut self) {
        if !self.cleaned {
            let _ = self.cleanup();
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BuilderLaunchPlan {
    guard_program: PathBuf,
    guard_arguments: Vec<OsString>,
    uml_command: Vec<OsString>,
    environment: BTreeMap<OsString, OsString>,
}

fn build_builder_launch_plan(
    profile: &VerifiedProfile,
    paths: &BuildPaths,
    target: &Path,
    guard_term_timeout: Duration,
) -> Result<BuilderLaunchPlan, HostBuildError> {
    let manifest = profile.manifest();
    let text = |field: &'static str, path: &Path| {
        path.to_str()
            .map(str::to_owned)
            .ok_or_else(|| HostBuildError::invalid(field, "path is not UTF-8"))
    };
    let payload = text("payload", &paths.payload)?;
    let target = text("target", target)?;
    let uml_dir = text("uml_dir", &paths.uml_dir)?;
    let initramfs = text("builder_initramfs", &paths.initramfs)?;
    for (field, value) in [("payload", &payload), ("target", &target)] {
        if value.len() > usize::from(manifest.launch.max_ubd_path_bytes) {
            return Err(HostBuildError::invalid(
                field,
                "UBD path exceeds the profile limit",
            ));
        }
    }
    if uml_dir.len() > usize::from(manifest.launch.max_unix_path_bytes) {
        return Err(HostBuildError::invalid(
            "uml_dir",
            "UML directory exceeds the profile Unix-path limit",
        ));
    }

    let memory = manifest.memory.builder_memory_bytes;
    let mut uml_command = vec![profile.uml_path().as_os_str().to_owned()];
    uml_command.push(format!("mem={memory}").into());
    if manifest.cpu.smp_enabled {
        uml_command.push(OsString::from("ncpus=1"));
    }
    uml_command.extend([
        OsString::from("seccomp=on"),
        format!("umid={}", paths.umid).into(),
        format!("uml_dir={uml_dir}").into(),
        format!("initrd={initramfs}").into(),
        OsString::from("rdinit=/init"),
        OsString::from("rootfstype=ramfs"),
        format!("ubd0r={payload}").into(),
        format!("ubd1={target}").into(),
        OsString::from("con=null"),
        OsString::from("con0=fd:14,fd:14"),
        OsString::from("ssl=null"),
        OsString::from("ssl0=fd:10,fd:10"),
        format!(
            "pocket.builder.guest_contract_id={}",
            manifest.builder.hello.guest_contract_id
        )
        .into(),
        format!(
            "pocket.builder.init_build_id={}",
            manifest.builder.hello.init_build_id
        )
        .into(),
        format!(
            "pocket.builder.kernel_build_id={}",
            manifest.builder.hello.kernel_build_id
        )
        .into(),
        OsString::from("pocket.builder.expected_cpus=1"),
        format!("pocket.builder.expected_memory_bytes={memory}").into(),
        format!(
            "pocket.builder.expected_page_size={}",
            manifest.guest_page_size
        )
        .into(),
        OsString::from("pocket.builder.expected_architecture=amd64"),
        format!(
            "pocket.builder.cpu_state_hwcap_policy={}",
            manifest.contracts.cpu_state_hwcap_policy
        )
        .into(),
        format!(
            "pocket.builder.root_layout={}",
            manifest.contracts.root_layout
        )
        .into(),
        format!(
            "pocket.builder.filesystem_contract={}",
            manifest.contracts.filesystem
        )
        .into(),
        format!(
            "pocket.builder.manifest_schema={}",
            manifest.builder.manifest_schema
        )
        .into(),
        OsString::from("quiet"),
        OsString::from("noreboot"),
        OsString::from("panic=1"),
    ]);

    let timeout_ms = u64::try_from(guard_term_timeout.as_millis()).map_err(|_| {
        HostBuildError::invalid("guard_term_timeout", "milliseconds do not fit u64")
    })?;
    let mut guard_arguments = vec![
        OsString::from("--supervisor-pid"),
        std::process::id().to_string().into(),
        OsString::from("--liveness-fd"),
        LIVENESS_FD.to_string().into(),
        OsString::from("--lease-fd"),
        LEASE_FD.to_string().into(),
    ];
    for fd in [CONTROL_FD, CONSOLE_FD] {
        guard_arguments.push(OsString::from("--inherit-fd"));
        guard_arguments.push(fd.to_string().into());
    }
    guard_arguments.extend([
        OsString::from("--term-timeout-ms"),
        timeout_ms.to_string().into(),
        OsString::from("--uml-personality"),
        OsString::from("--"),
    ]);
    guard_arguments.extend(uml_command.iter().cloned());
    let environment = sanitized_environment(&paths.tmp_dir);
    Ok(BuilderLaunchPlan {
        guard_program: profile.guard_path().to_path_buf(),
        guard_arguments,
        uml_command,
        environment,
    })
}

fn build_validator_launch_plan(
    profile: &VerifiedProfile,
    paths: &BuildPaths,
    target: &Path,
    guard_term_timeout: Duration,
) -> Result<BuilderLaunchPlan, HostBuildError> {
    let manifest = profile.manifest();
    let text = |field: &'static str, path: &Path| {
        path.to_str()
            .map(str::to_owned)
            .ok_or_else(|| HostBuildError::invalid(field, "path is not UTF-8"))
    };
    let target = text("validation_target", target)?;
    let uml_dir = text("uml_dir", &paths.uml_dir)?;
    let initramfs = text("validator_initramfs", &paths.validator_initramfs)?;
    if target.len() > usize::from(manifest.launch.max_ubd_path_bytes) {
        return Err(HostBuildError::invalid(
            "validation_target",
            "UBD path exceeds the profile limit",
        ));
    }
    if uml_dir.len() > usize::from(manifest.launch.max_unix_path_bytes) {
        return Err(HostBuildError::invalid(
            "uml_dir",
            "UML directory exceeds the profile Unix-path limit",
        ));
    }

    let memory = manifest.memory.validator_memory_bytes;
    let mut uml_command = vec![profile.uml_path().as_os_str().to_owned()];
    uml_command.push(format!("mem={memory}").into());
    if manifest.cpu.smp_enabled {
        uml_command.push(OsString::from("ncpus=1"));
    }
    uml_command.extend([
        OsString::from("seccomp=on"),
        format!("umid={}", paths.validator_umid).into(),
        format!("uml_dir={uml_dir}").into(),
        format!("initrd={initramfs}").into(),
        OsString::from("rdinit=/init"),
        OsString::from("rootfstype=ramfs"),
        format!("ubd0r={target}").into(),
        OsString::from("con=null"),
        OsString::from("con0=fd:14,fd:14"),
        OsString::from("ssl=null"),
        OsString::from("ssl0=fd:10,fd:10"),
        format!(
            "pocket.validator.guest_contract_id={}",
            manifest.validator.hello.guest_contract_id
        )
        .into(),
        format!(
            "pocket.validator.init_build_id={}",
            manifest.validator.hello.init_build_id
        )
        .into(),
        format!(
            "pocket.validator.kernel_build_id={}",
            manifest.validator.hello.kernel_build_id
        )
        .into(),
        OsString::from("pocket.validator.expected_cpus=1"),
        format!("pocket.validator.expected_memory_bytes={memory}").into(),
        format!(
            "pocket.validator.expected_page_size={}",
            manifest.guest_page_size
        )
        .into(),
        OsString::from("pocket.validator.expected_architecture=amd64"),
        format!(
            "pocket.validator.cpu_state_hwcap_policy={}",
            manifest.contracts.cpu_state_hwcap_policy
        )
        .into(),
        format!(
            "pocket.validator.root_layout={}",
            manifest.contracts.root_layout
        )
        .into(),
        format!(
            "pocket.validator.filesystem_contract={}",
            manifest.contracts.filesystem
        )
        .into(),
        format!(
            "pocket.validator.manifest_schema={}",
            manifest.validator.manifest_schema
        )
        .into(),
        OsString::from("quiet"),
        OsString::from("noreboot"),
        OsString::from("panic=1"),
    ]);

    let timeout_ms = u64::try_from(guard_term_timeout.as_millis()).map_err(|_| {
        HostBuildError::invalid("guard_term_timeout", "milliseconds do not fit u64")
    })?;
    let mut guard_arguments = vec![
        OsString::from("--supervisor-pid"),
        std::process::id().to_string().into(),
        OsString::from("--liveness-fd"),
        LIVENESS_FD.to_string().into(),
        OsString::from("--lease-fd"),
        LEASE_FD.to_string().into(),
    ];
    for fd in [CONTROL_FD, CONSOLE_FD] {
        guard_arguments.push(OsString::from("--inherit-fd"));
        guard_arguments.push(fd.to_string().into());
    }
    guard_arguments.extend([
        OsString::from("--term-timeout-ms"),
        timeout_ms.to_string().into(),
        OsString::from("--uml-personality"),
        OsString::from("--"),
    ]);
    guard_arguments.extend(uml_command.iter().cloned());
    Ok(BuilderLaunchPlan {
        guard_program: profile.guard_path().to_path_buf(),
        guard_arguments,
        uml_command,
        environment: sanitized_environment(&paths.tmp_dir),
    })
}

fn mke2fs_arguments(
    image: &Path,
    label: &str,
    uuid: &str,
    hash_seed: &str,
    inodes: u64,
    populate: Option<&Path>,
) -> Vec<OsString> {
    let mut arguments = vec![
        OsString::from("-F"),
        OsString::from("-q"),
        OsString::from("-t"),
        OsString::from("ext4"),
        OsString::from("-b"),
        OsString::from("4096"),
        OsString::from("-I"),
        OsString::from("256"),
        OsString::from("-N"),
        OsString::from(inodes.to_string()),
        OsString::from("-m"),
        OsString::from("0"),
        OsString::from("-L"),
        OsString::from(label),
        OsString::from("-U"),
        OsString::from(uuid),
        OsString::from("-O"),
        OsString::from(EXT4_FEATURES),
        OsString::from("-E"),
        OsString::from(format!(
            "lazy_itable_init=0,lazy_journal_init=0,root_owner=0:0,hash_seed={hash_seed}"
        )),
    ];
    if let Some(root) = populate {
        arguments.push(OsString::from("-d"));
        arguments.push(root.as_os_str().to_owned());
    }
    arguments.push(image.as_os_str().to_owned());
    arguments
}

fn deterministic_uuid(domain: &[u8], identity: &[u8; 32]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(identity);
    let mut bytes: [u8; 16] = hasher.finalize()[..16]
        .try_into()
        .expect("SHA-256 prefix has a fixed length");
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format!(
        "{}-{}-{}-{}-{}",
        hex::encode(&bytes[0..4]),
        hex::encode(&bytes[4..6]),
        hex::encode(&bytes[6..8]),
        hex::encode(&bytes[8..10]),
        hex::encode(&bytes[10..16])
    )
}

fn create_private_blkid_file(path: &Path) -> Result<(), HostBuildError> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| HostBuildError::io("create private libblkid cache", path, error))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|error| HostBuildError::io("set private libblkid-cache mode", path, error))?;
    file.sync_all()
        .map_err(|error| HostBuildError::io("sync private libblkid cache", path, error))?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| HostBuildError::io("inspect private libblkid cache", path, error))?;
    let canonical = fs::canonicalize(path)
        .map_err(|error| HostBuildError::io("canonicalize private libblkid cache", path, error))?;
    if canonical != path
        || !metadata.file_type().is_file()
        || metadata.len() != 0
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.mode() & 0o7777 != 0o600
    {
        return Err(HostBuildError::invalid(
            "BLKID_FILE",
            "must be an exact, empty, owner-only regular file in the build operation",
        ));
    }
    Ok(())
}

fn copy_builder_initramfs(
    profile: &VerifiedProfile,
    destination: &Path,
) -> Result<(), HostBuildError> {
    copy_profile_initramfs(
        profile.builder_initramfs_path(),
        &profile.manifest().artifacts.builder_initramfs,
        destination,
        "builder",
        "builder_initramfs_alias",
    )
}

fn copy_validator_initramfs(
    profile: &VerifiedProfile,
    destination: &Path,
) -> Result<(), HostBuildError> {
    copy_profile_initramfs(
        profile.validator_initramfs_path(),
        &profile.manifest().artifacts.validator_initramfs,
        destination,
        "validator",
        "validator_initramfs_alias",
    )
}

fn copy_profile_initramfs(
    source_path: &Path,
    expected: &crate::ArtifactSpec,
    destination: &Path,
    role: &'static str,
    evidence_field: &'static str,
) -> Result<(), HostBuildError> {
    let mut source = File::open(source_path)
        .map_err(|error| HostBuildError::io("open verified initramfs", source_path, error))?;
    let mut target = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .open(destination)
        .map_err(|error| HostBuildError::io("create initramfs alias", destination, error))?;
    io::copy(&mut source, &mut target)
        .map_err(|error| HostBuildError::io("copy initramfs", destination, error))?;
    target
        .sync_all()
        .map_err(|error| HostBuildError::io("sync initramfs alias", destination, error))?;
    drop(target);
    let (digest, size) = hash_path(destination)?;
    if digest.as_bytes() != &expected.sha256.as_bytes() || size != expected.size {
        return Err(HostBuildError::EvidenceMismatch {
            field: evidence_field,
            expected: format!("{}:{}", expected.sha256, expected.size),
            actual: format!("{digest}:{size}"),
        });
    }
    let metadata = fs::symlink_metadata(destination)
        .map_err(|error| HostBuildError::io("inspect initramfs alias", destination, error))?;
    if metadata.mode() & 0o7777 != 0o400 {
        return Err(HostBuildError::invalid(
            role,
            "private initramfs alias is not mode 0400",
        ));
    }
    Ok(())
}

fn sanitized_environment(tmp: &Path) -> BTreeMap<OsString, OsString> {
    BTreeMap::from([
        (OsString::from("HOME"), OsString::from("/")),
        (OsString::from("LANG"), OsString::from("C")),
        (OsString::from("LC_ALL"), OsString::from("C")),
        (OsString::from("PATH"), OsString::from("/usr/bin:/bin")),
        (OsString::from("TEMP"), tmp.as_os_str().to_owned()),
        (OsString::from("TMP"), tmp.as_os_str().to_owned()),
        (OsString::from("TMPDIR"), tmp.as_os_str().to_owned()),
        (OsString::from("TZ"), OsString::from("UTC0")),
    ])
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum E2fsHelper {
    Mke2fs,
    E2fsck,
    Resize2fs,
    Debugfs,
}

struct E2fsHelperContext<'a> {
    profile: &'a VerifiedProfile,
    lock: &'a File,
    tmp: &'a Path,
    blkid_file: &'a Path,
    policy: BuilderPolicy,
}

impl E2fsHelper {
    fn program(self, profile: &VerifiedProfile) -> &Path {
        match self {
            Self::Mke2fs => profile.mke2fs_path(),
            Self::E2fsck => profile.e2fsck_path(),
            Self::Resize2fs => profile.resize2fs_path(),
            Self::Debugfs => profile.debugfs_path(),
        }
    }
}

fn e2fs_helper_environment(
    profile: &VerifiedProfile,
    tmp: &Path,
    blkid_file: &Path,
    helper: E2fsHelper,
) -> BTreeMap<OsString, OsString> {
    let mut environment = sanitized_environment(tmp);
    environment.insert(
        OsString::from("BLKID_FILE"),
        blkid_file.as_os_str().to_owned(),
    );
    match helper {
        E2fsHelper::Mke2fs => {
            environment.insert(
                OsString::from("MKE2FS_CONFIG"),
                profile.mke2fs_config_path().as_os_str().to_owned(),
            );
        }
        E2fsHelper::E2fsck => {
            environment.insert(
                OsString::from("E2FSCK_CONFIG"),
                profile.e2fsck_config_path().as_os_str().to_owned(),
            );
        }
        // resize2fs reads neither policy file. It is given the same sanitized
        // environment and frozen clock as the other two so an adjusted image
        // is reproducible from the same inputs.
        E2fsHelper::Resize2fs | E2fsHelper::Debugfs => {}
    }
    environment.insert(
        OsString::from("E2FSPROGS_FAKE_TIME"),
        profile
            .manifest()
            .builder
            .source_date_epoch
            .to_string()
            .into(),
    );
    environment
}

#[derive(Debug, Clone)]
struct CapturedBytes {
    bytes: Vec<u8>,
    truncated: bool,
    total_bytes: u64,
}

#[derive(Debug, Clone)]
struct StageLog {
    stage: &'static str,
    stdout: CapturedBytes,
    stderr: CapturedBytes,
}

struct ChildDescriptor {
    source: OwnedFd,
    target: RawFd,
}

struct SpawnedGuard {
    child: Child,
    liveness: Option<OwnedFd>,
}

/// The wall-clock budget for one helper stage over an image of `image_bytes`.
///
/// A helper's work is proportional to the image it writes or reads, so a fixed
/// budget silently caps the image size the builder can handle. The result is
/// still bounded by `MAX_TIMEOUT`, which both inputs are validated against.
fn helper_budget(policy: BuilderPolicy, image_bytes: u64) -> Duration {
    let gibibytes = u32::try_from(image_bytes.div_ceil(1024 * 1024 * 1024)).unwrap_or(u32::MAX);
    policy
        .helper_timeout_per_gib
        .checked_mul(gibibytes)
        .and_then(|allowance| allowance.checked_add(policy.helper_timeout))
        .unwrap_or(MAX_TIMEOUT)
        .min(MAX_TIMEOUT)
}

fn run_guarded_helper(
    stage: &'static str,
    helper: E2fsHelper,
    arguments: &[OsString],
    context: &E2fsHelperContext<'_>,
    image_bytes: u64,
) -> Result<StageLog, HostBuildError> {
    let program = helper.program(context.profile);
    let budget = helper_budget(context.policy, image_bytes);
    let timeout_ms =
        u64::try_from(context.policy.guard_term_timeout.as_millis()).map_err(|_| {
            HostBuildError::invalid("guard_term_timeout", "milliseconds do not fit u64")
        })?;
    let mut guard_arguments = vec![
        OsString::from("--supervisor-pid"),
        std::process::id().to_string().into(),
        OsString::from("--liveness-fd"),
        LIVENESS_FD.to_string().into(),
        OsString::from("--lease-fd"),
        LEASE_FD.to_string().into(),
        OsString::from("--term-timeout-ms"),
        timeout_ms.to_string().into(),
        OsString::from("--"),
        program.as_os_str().to_owned(),
    ];
    guard_arguments.extend(arguments.iter().cloned());
    let environment =
        e2fs_helper_environment(context.profile, context.tmp, context.blkid_file, helper);
    let mut launch = spawn_guard_process(
        context.profile.guard_path(),
        &guard_arguments,
        &environment,
        context.lock,
        &[],
    )?;
    let stdout = launch
        .child
        .stdout
        .take()
        .ok_or_else(|| HostBuildError::invalid("guard.stdout", "missing pipe"))?;
    let stderr = launch
        .child
        .stderr
        .take()
        .ok_or_else(|| HostBuildError::invalid("guard.stderr", "missing pipe"))?;
    let stdout_worker = capture_worker(stage, "stdout", stdout, context.policy.maximum_log_bytes);
    let stderr_worker = capture_worker(stage, "stderr", stderr, context.policy.maximum_log_bytes);
    let status = wait_guard(
        &mut launch,
        Instant::now() + budget,
        budget,
        stage,
        context.policy.guard_exit_timeout,
    )?;
    let stdout = join_capture(stdout_worker, "helper stdout")?;
    let stderr = join_capture(stderr_worker, "helper stderr")?;
    if !status.success() {
        return Err(HostBuildError::GuardStatus {
            stage,
            status: status.to_string(),
            diagnostic: lossy_tail(&stderr.bytes, 4096),
        });
    }
    Ok(StageLog {
        stage,
        stdout,
        stderr,
    })
}

fn spawn_guard_process(
    guard: &Path,
    arguments: &[OsString],
    environment: &BTreeMap<OsString, OsString>,
    lock: &File,
    inherited: &[(&'static str, RawFd, RawFd)],
) -> Result<SpawnedGuard, HostBuildError> {
    let (liveness_read, liveness_write) = pipe2(OFlag::O_CLOEXEC).map_err(|errno| {
        HostBuildError::io(
            "create guard liveness pipe",
            "<builder-liveness-pipe>",
            io::Error::from_raw_os_error(errno as i32),
        )
    })?;
    let mut descriptors = vec![
        ChildDescriptor {
            source: relocate(lock.as_raw_fd(), "lease")?,
            target: LEASE_FD,
        },
        ChildDescriptor {
            source: relocate(liveness_read.as_raw_fd(), "liveness")?,
            target: LIVENESS_FD,
        },
    ];
    for (role, source, target) in inherited {
        descriptors.push(ChildDescriptor {
            source: relocate(*source, role)?,
            target: *target,
        });
    }
    let mappings: Vec<(RawFd, RawFd)> = descriptors
        .iter()
        .map(|descriptor| (descriptor.source.as_raw_fd(), descriptor.target))
        .collect();
    // SAFETY: getpid has no pointer or lifetime preconditions.
    let expected_parent = unsafe { libc::getpid() };
    let mut command = Command::new(guard);
    command
        .args(arguments)
        .env_clear()
        .envs(environment)
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // SAFETY: only async-signal-safe scalar libc operations are used between
    // fork and exec. All source descriptors were relocated above targets.
    unsafe {
        command.pre_exec(move || {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) == -1 {
                return Err(io::Error::last_os_error());
            }
            if libc::getppid() != expected_parent {
                return Err(io::Error::from_raw_os_error(libc::ESRCH));
            }
            for (source, target) in &mappings {
                if libc::dup2(*source, *target) == -1 {
                    return Err(io::Error::last_os_error());
                }
            }
            libc::umask(0o077);
            Ok(())
        });
    }
    let child = command
        .spawn()
        .map_err(|source| HostBuildError::GuardSpawn {
            program: guard.to_path_buf(),
            source,
        })?;
    drop(descriptors);
    drop(liveness_read);
    Ok(SpawnedGuard {
        child,
        liveness: Some(liveness_write),
    })
}

fn relocate(fd: RawFd, role: &'static str) -> Result<OwnedFd, HostBuildError> {
    // SAFETY: fd is borrowed and valid; F_DUPFD_CLOEXEC returns a distinct FD.
    let relocated = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, RELOCATED_FD_MINIMUM) };
    if relocated == -1 {
        return Err(HostBuildError::io(
            "relocate inherited descriptor",
            format!("<{role}-fd>"),
            io::Error::last_os_error(),
        ));
    }
    // SAFETY: fcntl returned a newly owned file descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(relocated) })
}

fn wait_guard(
    launch: &mut SpawnedGuard,
    deadline: Instant,
    timeout: Duration,
    stage: &'static str,
    cleanup_timeout: Duration,
) -> Result<ExitStatus, HostBuildError> {
    loop {
        if let Some(status) = launch
            .child
            .try_wait()
            .map_err(|error| HostBuildError::io("poll guard", "<guard>", error))?
        {
            launch.liveness.take();
            return Ok(status);
        }
        if Instant::now() >= deadline {
            launch.liveness.take();
            let cleanup_deadline = Instant::now() + cleanup_timeout;
            loop {
                if let Some(_status) = launch.child.try_wait().map_err(|error| {
                    HostBuildError::io("poll terminating guard", "<guard>", error)
                })? {
                    return Err(HostBuildError::Timeout { stage, timeout });
                }
                if Instant::now() >= cleanup_deadline {
                    let _ = launch.child.kill();
                    let _ = launch.child.wait();
                    return Err(HostBuildError::Timeout { stage, timeout });
                }
                thread::sleep(Duration::from_millis(10));
            }
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn capture_worker<R: Read + Send + 'static>(
    _stage: &'static str,
    _stream: &'static str,
    reader: R,
    maximum: usize,
) -> JoinHandle<Result<CapturedBytes, io::Error>> {
    thread::spawn(move || capture(reader, maximum))
}

fn capture(mut reader: impl Read, maximum: usize) -> Result<CapturedBytes, io::Error> {
    let mut bytes = Vec::with_capacity(maximum.min(64 * 1024));
    let mut buffer = [0_u8; 64 * 1024];
    let mut total_bytes = 0_u64;
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        total_bytes = total_bytes.saturating_add(count as u64);
        let remaining = maximum.saturating_sub(bytes.len());
        bytes.extend_from_slice(&buffer[..count.min(remaining)]);
    }
    Ok(CapturedBytes {
        truncated: total_bytes > bytes.len() as u64,
        total_bytes,
        bytes,
    })
}

fn join_capture(
    worker: JoinHandle<Result<CapturedBytes, io::Error>>,
    stream: &'static str,
) -> Result<CapturedBytes, HostBuildError> {
    worker
        .join()
        .map_err(|_| HostBuildError::StreamWorker {
            stream,
            reason: "worker panicked".to_owned(),
        })?
        .map_err(|error| HostBuildError::StreamWorker {
            stream,
            reason: error.to_string(),
        })
}

fn lossy_tail(bytes: &[u8], maximum: usize) -> String {
    let start = bytes.len().saturating_sub(maximum);
    String::from_utf8_lossy(&bytes[start..]).into_owned()
}

struct BuilderRun {
    done: BuilderDone,
    logs: Vec<StageLog>,
}

struct ValidatorRun {
    done: ValidatorDone,
    logs: Vec<StageLog>,
}

fn run_builder(
    plan: &BuilderLaunchPlan,
    lock: &File,
    start: &BuilderStart,
    metadata_manifest: &mut File,
    accounts: &mut File,
    profile: &VerifiedProfile,
    policy: BuilderPolicy,
) -> Result<BuilderRun, HostBuildError> {
    let (control_host, control_guest) = UnixStream::pair().map_err(|error| {
        HostBuildError::io(
            "create builder control socketpair",
            "<control-socketpair>",
            error,
        )
    })?;
    let (console_host, console_guest) = UnixStream::pair().map_err(|error| {
        HostBuildError::io(
            "create builder console socketpair",
            "<console-socketpair>",
            error,
        )
    })?;
    let inherited = [
        ("control", control_guest.as_raw_fd(), CONTROL_FD),
        ("console", console_guest.as_raw_fd(), CONSOLE_FD),
    ];
    let mut launch = spawn_guard_process(
        &plan.guard_program,
        &plan.guard_arguments,
        &plan.environment,
        lock,
        &inherited,
    )?;
    drop(control_guest);
    drop(console_guest);
    let guard_stdout = launch
        .child
        .stdout
        .take()
        .ok_or_else(|| HostBuildError::invalid("guard.stdout", "missing pipe"))?;
    let guard_stderr = launch
        .child
        .stderr
        .take()
        .ok_or_else(|| HostBuildError::invalid("guard.stderr", "missing pipe"))?;
    let stdout_worker = capture_worker(
        "builder-uml",
        "guard stdout",
        guard_stdout,
        policy.maximum_log_bytes,
    );
    let stderr_worker = capture_worker(
        "builder-uml",
        "guard stderr",
        guard_stderr,
        policy.maximum_log_bytes,
    );
    let console_worker = capture_worker(
        "builder-uml",
        "console",
        console_host,
        policy.maximum_log_bytes,
    );

    let mut control = BuilderControl::new(control_host);
    let protocol_result = run_builder_protocol(
        &mut control,
        start,
        metadata_manifest,
        accounts,
        profile,
        policy,
    );
    drop(control);
    let status_result = match &protocol_result {
        Ok(_) => wait_guard(
            &mut launch,
            Instant::now() + policy.guard_exit_timeout,
            policy.guard_exit_timeout,
            "builder guard exit",
            policy.guard_exit_timeout,
        ),
        Err(_) => {
            launch.liveness.take();
            wait_guard(
                &mut launch,
                Instant::now() + policy.guard_exit_timeout,
                policy.guard_exit_timeout,
                "failed builder cleanup",
                policy.guard_exit_timeout,
            )
        }
    };
    let stdout = join_capture(stdout_worker, "builder guard stdout")?;
    let stderr = join_capture(stderr_worker, "builder guard stderr")?;
    let console = join_capture(console_worker, "builder console")?;
    let done = match protocol_result {
        Ok(done) => done,
        Err(error) => {
            return Err(HostBuildError::GuestProtocol {
                stage: "builder-uml",
                reason: error.to_string(),
                source: Box::new(error),
                diagnostic: lossy_tail(&console.bytes, 4096),
            });
        }
    };
    let status = status_result?;
    if !status.success() {
        return Err(HostBuildError::GuardStatus {
            stage: "builder-uml",
            status: status.to_string(),
            diagnostic: lossy_tail(&console.bytes, 4096),
        });
    }
    Ok(BuilderRun {
        done,
        logs: vec![
            StageLog {
                stage: "builder-guard",
                stdout,
                stderr,
            },
            StageLog {
                stage: "builder-console",
                stdout: console,
                stderr: CapturedBytes {
                    bytes: Vec::new(),
                    truncated: false,
                    total_bytes: 0,
                },
            },
        ],
    })
}

fn run_validator(
    plan: &BuilderLaunchPlan,
    lock: &File,
    start: &ValidatorStart,
    profile: &VerifiedProfile,
    policy: BuilderPolicy,
) -> Result<ValidatorRun, HostBuildError> {
    let (control_host, control_guest) = UnixStream::pair().map_err(|error| {
        HostBuildError::io(
            "create validator control socketpair",
            "<control-socketpair>",
            error,
        )
    })?;
    let (console_host, console_guest) = UnixStream::pair().map_err(|error| {
        HostBuildError::io(
            "create validator console socketpair",
            "<console-socketpair>",
            error,
        )
    })?;
    let inherited = [
        ("control", control_guest.as_raw_fd(), CONTROL_FD),
        ("console", console_guest.as_raw_fd(), CONSOLE_FD),
    ];
    let mut launch = spawn_guard_process(
        &plan.guard_program,
        &plan.guard_arguments,
        &plan.environment,
        lock,
        &inherited,
    )?;
    drop(control_guest);
    drop(console_guest);
    let guard_stdout = launch
        .child
        .stdout
        .take()
        .ok_or_else(|| HostBuildError::invalid("guard.stdout", "missing pipe"))?;
    let guard_stderr = launch
        .child
        .stderr
        .take()
        .ok_or_else(|| HostBuildError::invalid("guard.stderr", "missing pipe"))?;
    let stdout_worker = capture_worker(
        "validator-uml",
        "guard stdout",
        guard_stdout,
        policy.maximum_log_bytes,
    );
    let stderr_worker = capture_worker(
        "validator-uml",
        "guard stderr",
        guard_stderr,
        policy.maximum_log_bytes,
    );
    let console_worker = capture_worker(
        "validator-uml",
        "console",
        console_host,
        policy.maximum_log_bytes,
    );

    let mut control = ValidatorControl::new(control_host);
    let protocol_result = run_validator_protocol(&mut control, start, profile, policy);
    drop(control);
    let status_result = match &protocol_result {
        Ok(_) => wait_guard(
            &mut launch,
            Instant::now() + policy.guard_exit_timeout,
            policy.guard_exit_timeout,
            "validator guard exit",
            policy.guard_exit_timeout,
        ),
        Err(_) => {
            launch.liveness.take();
            wait_guard(
                &mut launch,
                Instant::now() + policy.guard_exit_timeout,
                policy.guard_exit_timeout,
                "failed validator cleanup",
                policy.guard_exit_timeout,
            )
        }
    };
    let stdout = join_capture(stdout_worker, "validator guard stdout")?;
    let stderr = join_capture(stderr_worker, "validator guard stderr")?;
    let console = join_capture(console_worker, "validator console")?;
    let done = match protocol_result {
        Ok(done) => done,
        Err(error) => {
            return Err(HostBuildError::GuestProtocol {
                stage: "validator-uml",
                reason: error.to_string(),
                source: Box::new(error),
                diagnostic: lossy_tail(&console.bytes, 4096),
            });
        }
    };
    let status = status_result?;
    if !status.success() {
        return Err(HostBuildError::GuardStatus {
            stage: "validator-uml",
            status: status.to_string(),
            diagnostic: lossy_tail(&console.bytes, 4096),
        });
    }
    Ok(ValidatorRun {
        done,
        logs: vec![
            StageLog {
                stage: "validator-guard",
                stdout,
                stderr,
            },
            StageLog {
                stage: "validator-console",
                stdout: console,
                stderr: CapturedBytes {
                    bytes: Vec::new(),
                    truncated: false,
                    total_bytes: 0,
                },
            },
        ],
    })
}

fn run_validator_protocol(
    control: &mut ValidatorControl,
    start: &ValidatorStart,
    profile: &VerifiedProfile,
    policy: BuilderPolicy,
) -> Result<ValidatorDone, HostBuildError> {
    let startup_deadline = Instant::now() + policy.startup_timeout;
    let hello = match control.receive(startup_deadline, policy.startup_timeout, "VALIDATE_HELLO")? {
        ValidatorMessage::Hello(hello) => hello,
        ValidatorMessage::Error(message) => {
            return Err(HostBuildError::Guest {
                stage: "VALIDATE_HELLO",
                message,
            });
        }
        message => return Err(unexpected_validator("VALIDATE_HELLO", message.kind())),
    };
    verify_validator_hello(profile, &hello)?;
    control.send(
        ValidatorMessage::Start(Box::new(start.clone())),
        startup_deadline,
        policy.startup_timeout,
        "VALIDATE_START",
    )?;

    let validation_deadline = Instant::now() + policy.validation_timeout;
    match control.receive(
        validation_deadline,
        policy.validation_timeout,
        "VALIDATE_DONE",
    )? {
        ValidatorMessage::Done(done) => Ok(done),
        ValidatorMessage::Error(message) => Err(HostBuildError::Guest {
            stage: "VALIDATE_DONE",
            message,
        }),
        message => Err(unexpected_validator("VALIDATE_DONE", message.kind())),
    }
}

struct ValidatorControl {
    stream: UnixStream,
    session: ValidatorSession,
}

impl ValidatorControl {
    fn new(stream: UnixStream) -> Self {
        Self {
            stream,
            session: ValidatorSession::new(),
        }
    }

    fn receive(
        &mut self,
        deadline: Instant,
        timeout: Duration,
        stage: &'static str,
    ) -> Result<ValidatorMessage, HostBuildError> {
        let sequence = self.session.next_sequence(Direction::GuestToHost);
        let reader = DeadlineIo::new(&mut self.stream, deadline);
        let mut frames =
            FrameReader::with_limits(reader, sequence, pocket_protocol::MAX_CONTROL_PAYLOAD)?;
        let frame = frames
            .read_frame()
            .map_err(|error| classify_protocol(error, stage, timeout))?;
        let message = decode_validator_message(&frame)?;
        let mut candidate = self.session.clone();
        candidate.accept(Direction::GuestToHost, &message, frame.header.sequence)?;
        self.session = candidate;
        Ok(message)
    }

    fn send(
        &mut self,
        message: ValidatorMessage,
        deadline: Instant,
        timeout: Duration,
        stage: &'static str,
    ) -> Result<(), HostBuildError> {
        let payload = message.encode_payload()?;
        let sequence = self.session.next_sequence(Direction::HostToGuest);
        let mut candidate = self.session.clone();
        candidate.accept(Direction::HostToGuest, &message, sequence)?;
        let writer = DeadlineIo::new(&mut self.stream, deadline);
        let mut frames =
            FrameWriter::with_limits(writer, sequence, pocket_protocol::MAX_CONTROL_PAYLOAD)?;
        frames
            .write_frame(message.kind(), &payload)
            .and_then(|_| frames.flush())
            .map_err(|error| classify_protocol(error, stage, timeout))?;
        self.session = candidate;
        Ok(())
    }
}

fn run_builder_protocol(
    control: &mut BuilderControl,
    start: &BuilderStart,
    metadata_manifest: &mut File,
    accounts: &mut File,
    profile: &VerifiedProfile,
    policy: BuilderPolicy,
) -> Result<BuilderDone, HostBuildError> {
    let startup_deadline = Instant::now() + policy.startup_timeout;
    let hello = match control.receive(startup_deadline, policy.startup_timeout, "BUILD_HELLO")? {
        BuilderMessage::Hello(hello) => hello,
        BuilderMessage::Error(message) => {
            return Err(HostBuildError::Guest {
                stage: "BUILD_HELLO",
                message,
            });
        }
        message => return Err(unexpected_builder("BUILD_HELLO", message.kind())),
    };
    verify_builder_hello(profile, &hello)?;
    control.send(
        BuilderMessage::Start(Box::new(start.clone())),
        startup_deadline,
        policy.startup_timeout,
        "BUILD_START",
    )?;

    let build_deadline = Instant::now() + policy.build_timeout;
    match control.receive(build_deadline, policy.build_timeout, "MANIFEST_BEGIN")? {
        BuilderMessage::ManifestBegin(_) => {}
        BuilderMessage::Error(message) => {
            return Err(HostBuildError::Guest {
                stage: "MANIFEST_BEGIN",
                message,
            });
        }
        message => return Err(unexpected_builder("MANIFEST_BEGIN", message.kind())),
    }
    let mut verifier = ManifestStructuralVerifier::default();
    loop {
        match control.receive(build_deadline, policy.build_timeout, "metadata manifest")? {
            BuilderMessage::ManifestChunk(chunk) => {
                verifier.accept_chunk(&chunk)?;
                metadata_manifest.write_all(&chunk.bytes).map_err(|error| {
                    HostBuildError::io("write metadata manifest", "<metadata.manifest>", error)
                })?;
            }
            BuilderMessage::ManifestEnd(_) => break,
            BuilderMessage::Error(message) => {
                return Err(HostBuildError::Guest {
                    stage: "metadata manifest",
                    message,
                });
            }
            message => return Err(unexpected_builder("MANIFEST_CHUNK/END", message.kind())),
        }
    }
    verifier.finish()?;

    let account_db = match control.receive(build_deadline, policy.build_timeout, "ACCOUNT_DB")? {
        BuilderMessage::AccountDb(account_db) => account_db,
        BuilderMessage::Error(message) => {
            return Err(HostBuildError::Guest {
                stage: "ACCOUNT_DB",
                message,
            });
        }
        message => return Err(unexpected_builder("ACCOUNT_DB", message.kind())),
    };
    account_db.validate()?;
    accounts
        .write_all(&account_db.canonical_bytes)
        .map_err(|error| HostBuildError::io("write accounts.cbor", "<accounts.cbor>", error))?;

    let done = match control.receive(build_deadline, policy.build_timeout, "BUILD_DONE")? {
        BuilderMessage::Done(done) => done,
        BuilderMessage::Error(message) => {
            return Err(HostBuildError::Guest {
                stage: "BUILD_DONE",
                message,
            });
        }
        message => return Err(unexpected_builder("BUILD_DONE", message.kind())),
    };
    compare_evidence(
        "account_db_sha256",
        &account_db.sha256,
        &done.account_db_sha256,
    )?;
    compare_evidence(
        "generation_marker_sha256",
        &verifier.marker_sha256()?,
        &done.generation_marker_sha256,
    )?;
    Ok(done)
}

struct BuilderControl {
    stream: UnixStream,
    session: BuilderSession,
}

impl BuilderControl {
    fn new(stream: UnixStream) -> Self {
        Self {
            stream,
            session: BuilderSession::new(),
        }
    }

    fn receive(
        &mut self,
        deadline: Instant,
        timeout: Duration,
        stage: &'static str,
    ) -> Result<BuilderMessage, HostBuildError> {
        let sequence = self.session.next_sequence(Direction::GuestToHost);
        let reader = DeadlineIo::new(&mut self.stream, deadline);
        let mut frames =
            FrameReader::with_limits(reader, sequence, pocket_protocol::MAX_CONTROL_PAYLOAD)?;
        let frame = frames
            .read_frame()
            .map_err(|error| classify_protocol(error, stage, timeout))?;
        let message = decode_builder_message(&frame)?;
        let mut candidate = self.session.clone();
        candidate.accept(Direction::GuestToHost, &message, frame.header.sequence)?;
        self.session = candidate;
        Ok(message)
    }

    fn send(
        &mut self,
        message: BuilderMessage,
        deadline: Instant,
        timeout: Duration,
        stage: &'static str,
    ) -> Result<(), HostBuildError> {
        let payload = message.encode_payload()?;
        let sequence = self.session.next_sequence(Direction::HostToGuest);
        let mut candidate = self.session.clone();
        candidate.accept(Direction::HostToGuest, &message, sequence)?;
        let writer = DeadlineIo::new(&mut self.stream, deadline);
        let mut frames =
            FrameWriter::with_limits(writer, sequence, pocket_protocol::MAX_CONTROL_PAYLOAD)?;
        frames
            .write_frame(message.kind(), &payload)
            .and_then(|_| frames.flush())
            .map_err(|error| classify_protocol(error, stage, timeout))?;
        self.session = candidate;
        Ok(())
    }
}

struct DeadlineIo<'stream> {
    stream: &'stream mut UnixStream,
    deadline: Instant,
}

impl<'stream> DeadlineIo<'stream> {
    const fn new(stream: &'stream mut UnixStream, deadline: Instant) -> Self {
        Self { stream, deadline }
    }

    fn remaining(&self) -> io::Result<Duration> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|duration| !duration.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "protocol deadline elapsed"))
    }
}

impl Read for DeadlineIo<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.stream.set_read_timeout(Some(self.remaining()?))?;
        self.stream.read(bytes)
    }
}

impl Write for DeadlineIo<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.stream.set_write_timeout(Some(self.remaining()?))?;
        self.stream.write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.set_write_timeout(Some(self.remaining()?))?;
        self.stream.flush()
    }
}

fn classify_protocol(
    error: pocket_protocol::ProtocolError,
    stage: &'static str,
    timeout: Duration,
) -> HostBuildError {
    if matches!(
        &error,
        pocket_protocol::ProtocolError::Io(source)
            if matches!(source.kind(), io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock)
    ) {
        HostBuildError::Timeout { stage, timeout }
    } else {
        HostBuildError::Protocol(error)
    }
}

fn unexpected_builder(expected: &'static str, actual: MessageKind) -> HostBuildError {
    HostBuildError::EvidenceMismatch {
        field: "builder_message_kind",
        expected: expected.to_owned(),
        actual: format!("{actual:?}"),
    }
}

fn unexpected_validator(expected: &'static str, actual: MessageKind) -> HostBuildError {
    HostBuildError::EvidenceMismatch {
        field: "validator_message_kind",
        expected: expected.to_owned(),
        actual: format!("{actual:?}"),
    }
}

fn verify_builder_hello(
    profile: &VerifiedProfile,
    hello: &BuilderHello,
) -> Result<(), HostBuildError> {
    let manifest = profile.manifest();
    for (field, expected, actual) in [
        (
            "guest_contract_id",
            manifest.builder.hello.guest_contract_id.as_str(),
            hello.guest_contract_id.as_str(),
        ),
        (
            "init_build_id",
            manifest.builder.hello.init_build_id.as_str(),
            hello.init_build_id.as_str(),
        ),
        (
            "kernel_build_id",
            manifest.builder.hello.kernel_build_id.as_str(),
            hello.kernel_build_id.as_str(),
        ),
        (
            "guest_uts_machine",
            "x86_64",
            hello.guest_uts_machine.as_str(),
        ),
        (
            "cpu_state_hwcap_policy",
            manifest.contracts.cpu_state_hwcap_policy.as_str(),
            hello.cpu_state_hwcap_policy.as_str(),
        ),
    ] {
        if expected != actual {
            return Err(HostBuildError::HelloMismatch {
                field,
                expected: expected.to_owned(),
                actual: actual.to_owned(),
            });
        }
    }
    for (field, expected, actual) in [
        (
            "host_elf_machine",
            u64::from(manifest.host_elf_machine),
            u64::from(hello.host_elf_machine),
        ),
        (
            "guest_page_size",
            u64::from(manifest.guest_page_size),
            u64::from(hello.guest_page_size),
        ),
        ("online_cpus", 1, u64::from(hello.online_cpus)),
        (
            "accepted_physmem_bytes",
            manifest.memory.builder_memory_bytes,
            hello.accepted_physmem_bytes,
        ),
    ] {
        if expected != actual {
            return Err(HostBuildError::HelloMismatch {
                field,
                expected: expected.to_string(),
                actual: actual.to_string(),
            });
        }
    }
    let expected_tools: Vec<ToolIdentity> = manifest
        .builder
        .required_tools
        .iter()
        .map(|tool| ToolIdentity {
            role: tool.role.clone(),
            sha256: tool.sha256.clone(),
            version: tool.version.clone(),
        })
        .collect();
    if hello.builder_tools != expected_tools {
        return Err(HostBuildError::HelloMismatch {
            field: "builder_tools",
            expected: format!("{expected_tools:?}"),
            actual: format!("{:?}", hello.builder_tools),
        });
    }
    for required in &manifest.builder.hello.required_features {
        if !hello.features.iter().any(|feature| feature == required) {
            return Err(HostBuildError::HelloMismatch {
                field: "features",
                expected: required.clone(),
                actual: format!("{:?}", hello.features),
            });
        }
    }
    Ok(())
}

fn verify_validator_hello(
    profile: &VerifiedProfile,
    hello: &ValidatorHello,
) -> Result<(), HostBuildError> {
    let manifest = profile.manifest();
    for (field, expected, actual) in [
        (
            "validator.guest_contract_id",
            manifest.validator.hello.guest_contract_id.as_str(),
            hello.guest_contract_id.as_str(),
        ),
        (
            "validator.init_build_id",
            manifest.validator.hello.init_build_id.as_str(),
            hello.init_build_id.as_str(),
        ),
        (
            "validator.kernel_build_id",
            manifest.validator.hello.kernel_build_id.as_str(),
            hello.kernel_build_id.as_str(),
        ),
        (
            "validator.guest_uts_machine",
            "x86_64",
            hello.guest_uts_machine.as_str(),
        ),
        (
            "validator.cpu_state_hwcap_policy",
            manifest.contracts.cpu_state_hwcap_policy.as_str(),
            hello.cpu_state_hwcap_policy.as_str(),
        ),
    ] {
        if expected != actual {
            return Err(HostBuildError::HelloMismatch {
                field,
                expected: expected.to_owned(),
                actual: actual.to_owned(),
            });
        }
    }
    for (field, expected, actual) in [
        (
            "validator.host_elf_machine",
            u64::from(manifest.host_elf_machine),
            u64::from(hello.host_elf_machine),
        ),
        (
            "validator.guest_page_size",
            u64::from(manifest.guest_page_size),
            u64::from(hello.guest_page_size),
        ),
        ("validator.online_cpus", 1, u64::from(hello.online_cpus)),
        (
            "validator.accepted_physmem_bytes",
            manifest.memory.validator_memory_bytes,
            hello.accepted_physmem_bytes,
        ),
    ] {
        if expected != actual {
            return Err(HostBuildError::HelloMismatch {
                field,
                expected: expected.to_string(),
                actual: actual.to_string(),
            });
        }
    }
    if hello.features != manifest.validator.hello.required_features {
        return Err(HostBuildError::HelloMismatch {
            field: "validator.features",
            expected: format!("{:?}", manifest.validator.hello.required_features),
            actual: format!("{:?}", hello.features),
        });
    }
    Ok(())
}

#[derive(Default)]
struct ManifestStructuralVerifier {
    previous_path: Option<Vec<u8>>,
    saw_root: bool,
    saw_rootfs: bool,
    marker_digest: Option<String>,
}

impl ManifestStructuralVerifier {
    fn accept_chunk(&mut self, chunk: &ManifestChunk) -> Result<(), HostBuildError> {
        let mut remaining = chunk.bytes.as_slice();
        while !remaining.is_empty() {
            let length_bytes = remaining.get(..4).ok_or_else(|| {
                HostBuildError::invalid("metadata.manifest", "truncated entry length")
            })?;
            let length = u32::from_be_bytes(length_bytes.try_into().map_err(|_| {
                HostBuildError::invalid("metadata.manifest", "malformed entry length")
            })?) as usize;
            let payload = remaining
                .get(4..4 + length)
                .ok_or_else(|| HostBuildError::invalid("metadata.manifest", "truncated entry"))?;
            let entry: ManifestEntry = decode_payload(payload)?;
            entry.validate()?;
            self.accept_entry(&entry)?;
            remaining = &remaining[4 + length..];
        }
        Ok(())
    }

    fn accept_entry(&mut self, entry: &ManifestEntry) -> Result<(), HostBuildError> {
        if self.previous_path.as_ref().is_some_and(|previous| {
            manifest_path_order(previous, &entry.path) != std::cmp::Ordering::Less
        }) {
            let previous = self.previous_path.as_deref().unwrap_or_default();
            return Err(HostBuildError::invalid(
                "metadata.manifest",
                format!(
                    "paths are not strictly increasing: {} then {}",
                    manifest_path_diagnostic(previous),
                    manifest_path_diagnostic(&entry.path)
                ),
            ));
        }
        if entry.path.is_empty() {
            if self.saw_root || entry.kind != 2 {
                return Err(HostBuildError::invalid(
                    "metadata.manifest",
                    "root entry is duplicated or not a directory",
                ));
            }
            self.saw_root = true;
        } else if entry.path == b".pocket-generation.cbor" {
            if entry.kind != 1 || self.marker_digest.is_some() {
                return Err(HostBuildError::invalid(
                    "metadata.manifest",
                    "generation marker is duplicated or not a regular file",
                ));
            }
            self.marker_digest = entry.content_sha256.as_ref().map(hex::encode);
        } else if entry.path == b"rootfs" {
            if self.saw_rootfs || entry.kind != 2 {
                return Err(HostBuildError::invalid(
                    "metadata.manifest",
                    "rootfs entry is duplicated or not a directory",
                ));
            }
            self.saw_rootfs = true;
        } else if !entry.path.starts_with(b"rootfs/") {
            return Err(HostBuildError::invalid(
                "metadata.manifest",
                "entry escapes the rootfs plus marker layout",
            ));
        }
        self.previous_path = Some(entry.path.clone());
        Ok(())
    }

    fn marker_sha256(&self) -> Result<String, HostBuildError> {
        self.marker_digest.clone().ok_or_else(|| {
            HostBuildError::invalid("metadata.manifest", "missing generation marker digest")
        })
    }

    fn finish(&self) -> Result<(), HostBuildError> {
        if !self.saw_root || !self.saw_rootfs || self.marker_digest.is_none() {
            return Err(HostBuildError::invalid(
                "metadata.manifest",
                "missing root, rootfs, or generation marker evidence",
            ));
        }
        Ok(())
    }
}

/// Compare normalized relative paths in the canonical order emitted by the
/// bounded guest walker: components are bytewise lexicographic and a parent
/// precedes all of its descendants.  Raw whole-path comparison is wrong for
/// this stream because `dir/child` may compare after a sibling such as
/// `dir.ext`, even though a depth-first walker must finish `dir/` first.
fn manifest_path_order(left: &[u8], right: &[u8]) -> std::cmp::Ordering {
    let mut left_components = left.split(|byte| *byte == b'/');
    let mut right_components = right.split(|byte| *byte == b'/');
    loop {
        match (left_components.next(), right_components.next()) {
            (Some(left), Some(right)) => match left.cmp(right) {
                std::cmp::Ordering::Equal => {}
                ordering => return ordering,
            },
            (None, Some(_)) => return std::cmp::Ordering::Less,
            (Some(_), None) => return std::cmp::Ordering::Greater,
            (None, None) => return std::cmp::Ordering::Equal,
        }
    }
}

fn manifest_path_diagnostic(path: &[u8]) -> String {
    const MAXIMUM_BYTES: usize = 128;
    let prefix = &path[..path.len().min(MAXIMUM_BYTES)];
    let suffix = if path.len() > MAXIMUM_BYTES {
        format!("...(+{} bytes)", path.len() - MAXIMUM_BYTES)
    } else {
        String::new()
    };
    format!("hex:{}{suffix}", hex::encode(prefix))
}

fn compare_evidence(
    field: &'static str,
    expected: &str,
    actual: &str,
) -> Result<(), HostBuildError> {
    if expected != actual {
        return Err(HostBuildError::EvidenceMismatch {
            field,
            expected: expected.to_owned(),
            actual: actual.to_owned(),
        });
    }
    Ok(())
}

#[derive(Serialize)]
struct BuildRecord<'a> {
    schema: &'static str,
    profile_id: &'a str,
    profile_revision: String,
    derivation_key: String,
    selected_manifest: String,
    config: String,
    descriptor_platform: Option<BuildPlatform<'a>>,
    config_platform: BuildPlatform<'a>,
    effective_platform: BuildPlatform<'a>,
    selector_policy: &'a str,
    root_layout: &'a str,
    filesystem_contract: &'a str,
    base_sha256: String,
    base_size: u64,
    manifest_sha256: &'a str,
    manifest_entry_count: u64,
    manifest_byte_count: u64,
    generation_marker_sha256: &'a str,
    account_db_sha256: &'a str,
    original_user: &'a str,
    user_resolution: BuildUserResolution,
    observed_tools: Vec<BuildTool<'a>>,
    uml_sha256: String,
    builder_initramfs_sha256: String,
    validator_initramfs_sha256: String,
    mke2fs_sha256: String,
    e2fsck_sha256: String,
    mke2fs_config_sha256: String,
    e2fsck_config_sha256: String,
    payload_size_bytes: u64,
    payload_requested_inode_count: u64,
    payload_attempts: u8,
    payload_retry_resource: Option<&'static str>,
    payload_directory_hash_seed: &'a str,
    target_size_bytes: u64,
    target_requested_inode_count: u64,
    target_attempts: u8,
    target_retry_resource: Option<&'static str>,
    target_directory_hash_seed: &'a str,
    source_date_epoch: u64,
    validation: BuildValidationEvidence<'a>,
    reproducibility: BuildReproducibility,
}

#[derive(Serialize)]
struct BuildValidationEvidence<'a> {
    protocol: &'static str,
    challenge: &'a str,
    evidence_sha256: &'a str,
    manifest_sha256: &'a str,
    manifest_entry_count: u64,
    manifest_byte_count: u64,
    generation_marker_sha256: &'a str,
    account_db_sha256: &'a str,
    filesystem_uuid: &'a str,
    filesystem_bytes: u64,
    clean_before_mount: bool,
    block_device_read_only: bool,
    mounted_read_only: bool,
    unmounted: bool,
    clean_after_unmount: bool,
}

#[derive(Serialize)]
struct BuildReproducibility {
    result: &'static str,
    normalized_inputs: [&'static str; 3],
    remaining_nondeterministic_inputs: [&'static str; 3],
}

fn build_reproducibility() -> BuildReproducibility {
    BuildReproducibility {
        result: "exact-output-digest-only-v1",
        normalized_inputs: [
            "e2fsprogs-fake-time",
            "guest-realtime-initialized-before-target-mount",
            "derivation-bound-ext4-directory-hash-seeds",
        ],
        remaining_nondeterministic_inputs: [
            "guest-realtime-advances-during-conversion-and-generated-ctime-can-vary",
            "kernel-ext4-inode-generation-and-journal-runtime-entropy-are-not-normalized",
            "fresh-validator-challenge-randomizes-validation-evidence-sidecar-and-final-generation-id",
        ],
    }
}

#[derive(Clone, Copy)]
struct BuildSizingEvidence<'a> {
    payload: FilesystemSize,
    payload_attempts: u8,
    payload_retry_resource: Option<CapacityResource>,
    target: FilesystemSize,
    target_attempts: u8,
    target_retry_resource: Option<CapacityResource>,
    payload_hash_seed: &'a str,
    target_hash_seed: &'a str,
}

#[derive(Serialize)]
struct BuildPlatform<'a> {
    os: &'a str,
    architecture: &'a str,
    variant: Option<&'a str>,
    os_version: Option<&'a str>,
    os_features: &'a [String],
    features: &'a [String],
}

impl<'a> From<&'a ImagePlatform> for BuildPlatform<'a> {
    fn from(platform: &'a ImagePlatform) -> Self {
        Self {
            os: &platform.os,
            architecture: &platform.architecture,
            variant: platform.variant.as_deref(),
            os_version: platform.os_version.as_deref(),
            os_features: &platform.os_features,
            features: &platform.features,
        }
    }
}

#[derive(Serialize)]
struct BuildUserResolution {
    kind: u8,
    uid: u32,
    gid: u32,
    supplementary_gids: Vec<u32>,
}

#[derive(Serialize)]
struct BuildTool<'a> {
    role: &'a str,
    sha256: &'a str,
    version: &'a str,
}

fn build_record(
    profile: &VerifiedProfile,
    prepared: &PreparedBuild,
    done: &BuilderDone,
    validation_done: &ValidatorDone,
    base_digest: Digest,
    base_size: u64,
    sizing: BuildSizingEvidence<'_>,
) -> Result<Vec<u8>, HostBuildError> {
    let manifest = profile.manifest();
    let record = BuildRecord {
        schema: "pocket-build-record-v4",
        profile_id: &manifest.profile_id,
        profile_revision: manifest.profile_revision.to_string(),
        derivation_key: prepared.spec.derivation_key().to_string(),
        selected_manifest: prepared.image.manifest_digest.to_string(),
        config: prepared.image.config_digest.to_string(),
        descriptor_platform: prepared
            .image
            .descriptor_platform
            .as_ref()
            .map(BuildPlatform::from),
        config_platform: BuildPlatform::from(&prepared.image.config_platform),
        effective_platform: BuildPlatform::from(&prepared.image.effective_platform),
        selector_policy: &prepared.image.selector_policy,
        root_layout: &manifest.contracts.root_layout,
        filesystem_contract: &manifest.contracts.filesystem,
        base_sha256: base_digest.to_string(),
        base_size,
        manifest_sha256: &done.manifest_sha256,
        manifest_entry_count: done.entry_count,
        manifest_byte_count: done.byte_count,
        generation_marker_sha256: &done.generation_marker_sha256,
        account_db_sha256: &done.account_db_sha256,
        original_user: &done.original_user,
        user_resolution: BuildUserResolution {
            kind: done.user_resolution.kind,
            uid: done.user_resolution.uid,
            gid: done.user_resolution.gid,
            supplementary_gids: done.user_resolution.supplementary_gids.clone(),
        },
        observed_tools: done
            .observed_tools
            .iter()
            .map(|tool| BuildTool {
                role: &tool.role,
                sha256: &tool.sha256,
                version: &tool.version,
            })
            .collect(),
        uml_sha256: manifest.artifacts.uml.sha256.to_string(),
        builder_initramfs_sha256: manifest.artifacts.builder_initramfs.sha256.to_string(),
        validator_initramfs_sha256: manifest.artifacts.validator_initramfs.sha256.to_string(),
        mke2fs_sha256: manifest.artifacts.mke2fs.sha256.to_string(),
        e2fsck_sha256: manifest.artifacts.e2fsck.sha256.to_string(),
        mke2fs_config_sha256: manifest.artifacts.mke2fs_config.sha256.to_string(),
        e2fsck_config_sha256: manifest.artifacts.e2fsck_config.sha256.to_string(),
        payload_size_bytes: sizing.payload.bytes,
        payload_requested_inode_count: sizing.payload.inodes,
        payload_attempts: sizing.payload_attempts,
        payload_retry_resource: sizing.payload_retry_resource.map(CapacityResource::as_str),
        payload_directory_hash_seed: sizing.payload_hash_seed,
        target_size_bytes: sizing.target.bytes,
        target_requested_inode_count: sizing.target.inodes,
        target_attempts: sizing.target_attempts,
        target_retry_resource: sizing.target_retry_resource.map(CapacityResource::as_str),
        target_directory_hash_seed: sizing.target_hash_seed,
        source_date_epoch: manifest.builder.source_date_epoch,
        validation: BuildValidationEvidence {
            protocol: "fresh-read-only-uml-challenge-evidence-v1",
            challenge: &validation_done.challenge,
            evidence_sha256: &validation_done.evidence_sha256,
            manifest_sha256: &validation_done.evidence.manifest_sha256,
            manifest_entry_count: validation_done.evidence.manifest_entry_count,
            manifest_byte_count: validation_done.evidence.manifest_byte_count,
            generation_marker_sha256: &validation_done.evidence.generation_marker_sha256,
            account_db_sha256: &validation_done.evidence.account_db_sha256,
            filesystem_uuid: &validation_done.evidence.filesystem_uuid,
            filesystem_bytes: validation_done.evidence.filesystem_bytes,
            clean_before_mount: validation_done.evidence.clean_before_mount,
            block_device_read_only: validation_done.evidence.block_device_read_only,
            mounted_read_only: validation_done.evidence.mounted_read_only,
            unmounted: validation_done.evidence.unmounted,
            clean_after_unmount: validation_done.evidence.clean_after_unmount,
        },
        reproducibility: build_reproducibility(),
    };
    let mut bytes = serde_json::to_vec(&record).map_err(|error| {
        HostBuildError::invalid("build_record", format!("cannot serialize: {error}"))
    })?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn encode_build_log(stages: &[StageLog], maximum: usize) -> Vec<u8> {
    let mut output = Vec::with_capacity(maximum.min(64 * 1024));
    for stage in stages {
        for (stream, capture) in [("stdout", &stage.stdout), ("stderr", &stage.stderr)] {
            append_log(
                &mut output,
                maximum,
                format!(
                    "== {} {} total={} retained={} truncated={} ==\n",
                    stage.stage,
                    stream,
                    capture.total_bytes,
                    capture.bytes.len(),
                    capture.truncated
                )
                .as_bytes(),
            );
            append_log(&mut output, maximum, &capture.bytes);
            append_log(&mut output, maximum, b"\n");
        }
    }
    output
}

fn append_log(output: &mut Vec<u8>, maximum: usize, bytes: &[u8]) {
    let remaining = maximum.saturating_sub(output.len());
    output.extend_from_slice(&bytes[..bytes.len().min(remaining)]);
}

fn write_synced(file: &mut File, bytes: &[u8], role: &'static str) -> Result<(), HostBuildError> {
    file.write_all(bytes)
        .map_err(|error| HostBuildError::io("write immutable sidecar", role, error))?;
    file.sync_all()
        .map_err(|error| HostBuildError::io("sync immutable sidecar", role, error))
}

fn hash_path(path: &Path) -> Result<(Digest, u64), HostBuildError> {
    let path_metadata = fs::symlink_metadata(path)
        .map_err(|error| HostBuildError::io("inspect immutable artifact", path, error))?;
    if !path_metadata.file_type().is_file() {
        return Err(HostBuildError::invalid(
            "artifact",
            format!("{} is not a regular file", path.display()),
        ));
    }
    let mut file = File::open(path)
        .map_err(|error| HostBuildError::io("open immutable artifact", path, error))?;
    let metadata = file
        .metadata()
        .map_err(|error| HostBuildError::io("stat immutable artifact", path, error))?;
    if metadata.dev() != path_metadata.dev() || metadata.ino() != path_metadata.ino() {
        return Err(HostBuildError::invalid(
            "artifact",
            format!("{} changed while opening", path.display()),
        ));
    }
    let mut hasher = Sha256::new();
    let mut count = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| HostBuildError::io("hash immutable artifact", path, error))?;
        if read == 0 {
            break;
        }
        count = count
            .checked_add(read as u64)
            .ok_or_else(|| HostBuildError::invalid("artifact", "size overflow"))?;
        hasher.update(&buffer[..read]);
    }
    Ok((Digest::from_bytes(hasher.finalize().into()), count))
}

fn map_ext4_error(error: RuntimeError) -> HostBuildError {
    HostBuildError::invalid("base.ext4", error.to_string())
}

fn validate_policy(policy: BuilderPolicy) -> Result<(), HostBuildError> {
    for (field, timeout, maximum) in [
        ("startup_timeout", policy.startup_timeout, MAX_TIMEOUT),
        ("build_timeout", policy.build_timeout, MAX_TIMEOUT),
        ("validation_timeout", policy.validation_timeout, MAX_TIMEOUT),
        ("helper_timeout", policy.helper_timeout, MAX_TIMEOUT),
        (
            "helper_timeout_per_gib",
            policy.helper_timeout_per_gib,
            MAX_TIMEOUT,
        ),
        (
            "guard_term_timeout",
            policy.guard_term_timeout,
            Duration::from_secs(600),
        ),
        (
            "guard_exit_timeout",
            policy.guard_exit_timeout,
            Duration::from_secs(1200),
        ),
    ] {
        if timeout.is_zero() || timeout > maximum {
            return Err(HostBuildError::invalid(
                field,
                format!("must be nonzero and no greater than {maximum:?}"),
            ));
        }
    }
    if policy.guard_exit_timeout < policy.guard_term_timeout {
        return Err(HostBuildError::invalid(
            "guard_exit_timeout",
            "must be at least guard_term_timeout",
        ));
    }
    if policy.maximum_log_bytes == 0 || policy.maximum_log_bytes > MAX_LOG_BYTES {
        return Err(HostBuildError::invalid(
            "maximum_log_bytes",
            format!("must be in 1..={MAX_LOG_BYTES}"),
        ));
    }
    Ok(())
}

fn initialize_builder_root(path: &Path) -> Result<(), HostBuildError> {
    match fs::create_dir(path) {
        Ok(()) => fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|error| HostBuildError::io("set builder-root mode", path, error))?,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(HostBuildError::io("create builder root", path, error)),
    }
    let canonical = fs::canonicalize(path)
        .map_err(|error| HostBuildError::io("canonicalize builder root", path, error))?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| HostBuildError::io("inspect builder root", path, error))?;
    if canonical != path || !metadata.file_type().is_dir() {
        return Err(HostBuildError::invalid(
            "runtime_root",
            "must be an exact non-symlink directory path",
        ));
    }
    if metadata.uid() != nix::unistd::geteuid().as_raw() || metadata.mode() & 0o777 != 0o700 {
        return Err(HostBuildError::invalid(
            "runtime_root",
            "must be owned by the effective user with mode 0700",
        ));
    }
    Ok(())
}

fn random_id() -> Result<String, HostBuildError> {
    let mut bytes = [0_u8; BUILD_ID_BYTES];
    fill_random(&mut bytes, "opaque build ID")?;
    Ok(hex::encode(bytes))
}

fn random_challenge() -> Result<String, HostBuildError> {
    let mut bytes = [0_u8; VALIDATION_CHALLENGE_BYTES];
    fill_random(&mut bytes, "validation challenge")?;
    Ok(hex::encode(bytes))
}

fn fill_random(bytes: &mut [u8], role: &'static str) -> Result<(), HostBuildError> {
    OpenOptions::new()
        .read(true)
        .open("/dev/urandom")
        .and_then(|mut file| file.read_exact(bytes))
        .map_err(|error| HostBuildError::io(role, "/dev/urandom", error))
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
        path::{Path, PathBuf},
        time::Duration,
    };

    use nix::libc;
    use pocket_core::ManagedUmlPath;
    use pocket_protocol::{ErrorMessage, ManifestChunk, ManifestEntry, encode_payload};
    use pocket_store::Store;
    use serde_json::{Value, json};
    use sha2::{Digest as _, Sha256};
    use tempfile::tempdir;

    use super::{
        BuildPaths, BuildRequest, BuilderPolicy, CapacityResource, E2fsHelper, E2fsHelperContext,
        EXT4_FEATURES, FilesystemSize, FilesystemSizing, HostBuilder, MAX_TIMEOUT,
        ManifestStructuralVerifier, SIZE_CLASS_BYTES, TARGET_INODE_CLASS,
        build_builder_launch_plan, build_contract_digest, build_reproducibility,
        build_validator_launch_plan, capacity_retry, compare_evidence, create_private_blkid_file,
        deterministic_uuid, discard_retry_file, e2fs_helper_environment, guest_capacity_resource,
        helper_budget, helper_capacity_resource, manifest_path_order, mke2fs_arguments,
        prepare_build, run_guarded_helper, validate_policy,
    };
    use crate::{HostBuildError, VerifiedProfile, manifest::synthetic_profile};

    const OCI_INDEX: &str = "application/vnd.oci.image.index.v1+json";
    const OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
    const OCI_CONFIG: &str = "application/vnd.oci.image.config.v1+json";
    const OCI_LAYER: &str = "application/vnd.oci.image.layer.v1.tar";

    #[test]
    fn builder_launch_is_exact_single_cpu_decimal_memory_and_no_shell() {
        let temporary = tempdir().expect("temporary root");
        let profile_root = temporary.path().join("profiles/release/current");
        let profile = synthetic_profile(
            ManagedUmlPath::new(&profile_root).expect("managed profile path"),
            true,
        );
        let operation = temporary.path().join("runtime/build-0123456789abcdef");
        let paths = BuildPaths {
            uml_dir: operation.join("uml"),
            tmp_dir: operation.join("tmp"),
            blkid_file: operation.join("tmp/blkid.tab"),
            payload: operation.join("oci-payload.ext4"),
            initramfs: operation.join("builder-initramfs.cpio"),
            validator_initramfs: operation.join("validator-initramfs.cpio"),
            umid: "build-0123456789abcdef".to_owned(),
            validator_umid: "build-0123456789abcdef-v".to_owned(),
        };
        let target = temporary.path().join("store/staging/stage/base.ext4");
        let plan = build_builder_launch_plan(&profile, &paths, &target, Duration::from_secs(5))
            .expect("launch plan");
        let args: Vec<&str> = plan
            .uml_command
            .iter()
            .map(|value| value.to_str().expect("UTF-8 argument"))
            .collect();
        assert_eq!(args[1], "mem=536870912");
        assert_eq!(args[2], "ncpus=1");
        for required in [
            "seccomp=on",
            "pocket.builder.expected_cpus=1",
            "pocket.builder.expected_memory_bytes=536870912",
            "pocket.builder.expected_page_size=4096",
            "pocket.builder.expected_architecture=amd64",
            "pocket.builder.cpu_state_hwcap_policy=native-x86_64-v1",
            "quiet",
            "noreboot",
            "panic=1",
        ] {
            assert!(
                args.contains(&required),
                "missing {required:?} from {args:?}"
            );
        }
        assert!(
            args.iter()
                .all(|argument| *argument != "sh" && *argument != "-c")
        );
        assert_eq!(
            plan.environment.get(std::ffi::OsStr::new("PATH")),
            Some(&std::ffi::OsString::from("/usr/bin:/bin"))
        );
        let guard: Vec<&str> = plan
            .guard_arguments
            .iter()
            .map(|value| value.to_str().expect("guard argument"))
            .collect();
        assert!(guard.contains(&"--uml-personality"));
        assert_eq!(
            guard
                .iter()
                .filter(|value| **value == "--inherit-fd")
                .count(),
            2
        );

        let validator =
            build_validator_launch_plan(&profile, &paths, &target, Duration::from_secs(5))
                .expect("validator launch plan");
        let validator_args: Vec<&str> = validator
            .uml_command
            .iter()
            .map(|value| value.to_str().expect("UTF-8 argument"))
            .collect();
        assert_eq!(validator_args[1], "mem=536870912");
        assert!(validator_args.contains(&"ncpus=1"));
        let expected_disk = format!("ubd0r={}", target.display());
        assert!(validator_args.contains(&expected_disk.as_str()));
        assert!(
            validator_args
                .iter()
                .all(|value| !value.starts_with("ubd1="))
        );
        for required in [
            "seccomp=on",
            "pocket.validator.expected_cpus=1",
            "pocket.validator.expected_memory_bytes=536870912",
            "pocket.validator.manifest_schema=pocket-fs-manifest-v1",
        ] {
            assert!(validator_args.contains(&required), "missing {required}");
        }
    }

    #[test]
    fn raw_platform_evidence_is_not_collapsed_in_store_identity() {
        let (temporary, layout) = oci_layout(Some("v1"));
        let profile_root = temporary.path().join("profiles/release/current");
        let profile = synthetic_profile(
            ManagedUmlPath::new(profile_root).expect("managed profile path"),
            true,
        );
        let prepared = prepare_build(
            &profile,
            &BuildRequest {
                oci_layout: layout,
                source_reference: "docker://example.invalid/demo:latest".to_owned(),
                requested_variant: Some("v1".to_owned()),
            },
        )
        .expect("prepared build");
        assert_eq!(
            prepared
                .spec
                .descriptor_platform()
                .and_then(pocket_store::Platform::variant),
            Some("v1")
        );
        assert_eq!(prepared.spec.config_platform().variant(), None);
        assert_eq!(prepared.spec.effective_platform().variant(), Some("v1"));
        assert_eq!(
            prepared
                .start
                .descriptor_platform
                .as_ref()
                .and_then(|value| value.variant.as_deref()),
            Some("v1")
        );
    }

    #[test]
    fn explicit_selector_mismatch_fails_during_preparation() {
        let (temporary, layout) = oci_layout(None);
        let profile_root = temporary.path().join("profiles/release/current");
        let profile = synthetic_profile(
            ManagedUmlPath::new(profile_root).expect("managed profile path"),
            true,
        );
        let result = prepare_build(
            &profile,
            &BuildRequest {
                oci_layout: layout,
                source_reference: "docker://example.invalid/demo:latest".to_owned(),
                requested_variant: Some("v1".to_owned()),
            },
        );
        assert!(result.is_err());
    }

    #[test]
    fn sizing_contract_accounts_for_inodes_and_has_one_fresh_next_class() {
        let (temporary, layout) = oci_layout(None);
        let profile_root = temporary.path().join("profiles/release/current");
        let profile = synthetic_profile(
            ManagedUmlPath::new(profile_root).expect("managed profile path"),
            true,
        );
        let prepared = prepare_build(
            &profile,
            &BuildRequest {
                oci_layout: layout,
                source_reference: "docker://example.invalid/demo:latest".to_owned(),
                requested_variant: None,
            },
        )
        .expect("prepared build");
        let payload_retry = prepared.payload_sizing.retry.expect("payload retry class");
        assert!(prepared.payload_sizing.initial.inodes >= 1024);
        assert_eq!(
            payload_retry.bytes,
            prepared.payload_sizing.initial.bytes + SIZE_CLASS_BYTES
        );
        assert!(payload_retry.inodes > prepared.payload_sizing.initial.inodes);

        let target_retry = prepared.target_sizing.retry.expect("target retry class");
        assert_eq!(
            target_retry.bytes,
            prepared.target_sizing.initial.bytes + SIZE_CLASS_BYTES
        );
        assert_eq!(
            target_retry.inodes,
            prepared.target_sizing.initial.inodes + TARGET_INODE_CLASS
        );
        assert_eq!(
            capacity_retry(1, prepared.target_sizing),
            Some(target_retry)
        );
        assert_eq!(capacity_retry(2, prepared.target_sizing), None);
    }

    #[test]
    fn mke2fs_policy_binds_inode_count_and_derivation_hash_seed() {
        let arguments = mke2fs_arguments(
            Path::new("/target.ext4"),
            "pocket-root",
            "11111111-2222-5333-8444-555555555555",
            "aaaaaaaa-bbbb-5ccc-8ddd-eeeeeeeeeeee",
            131_072,
            None,
        );
        let arguments: Vec<&str> = arguments
            .iter()
            .map(|argument| argument.to_str().expect("UTF-8 argument"))
            .collect();
        let inode_flag = arguments
            .iter()
            .position(|argument| *argument == "-N")
            .expect("inode-count option");
        assert_eq!(arguments[inode_flag + 1], "131072");
        assert!(!arguments.contains(&"-i"));
        let feature_flag = arguments
            .iter()
            .position(|argument| *argument == "-O")
            .expect("feature option");
        assert_eq!(arguments[feature_flag + 1], EXT4_FEATURES);
        let extended_flag = arguments
            .iter()
            .position(|argument| *argument == "-E")
            .expect("extended option");
        assert_eq!(
            arguments[extended_flag + 1],
            "lazy_itable_init=0,lazy_journal_init=0,root_owner=0:0,hash_seed=aaaaaaaa-bbbb-5ccc-8ddd-eeeeeeeeeeee"
        );
    }

    #[test]
    fn hash_seed_domains_are_stable_and_reproducibility_record_is_truthful() {
        let identity = [7_u8; 32];
        let first = deterministic_uuid(b"pocket-target-directory-hash-seed\0v1\0", &identity);
        let second = deterministic_uuid(b"pocket-target-directory-hash-seed\0v1\0", &identity);
        let payload = deterministic_uuid(b"pocket-payload-directory-hash-seed\0v1\0", &identity);
        assert_eq!(first, second);
        assert_ne!(first, payload);

        let record = serde_json::to_value(build_reproducibility()).expect("record JSON");
        assert_eq!(record["result"], "exact-output-digest-only-v1");
        let remaining = record["remaining_nondeterministic_inputs"]
            .as_array()
            .expect("remaining inputs");
        assert_eq!(remaining.len(), 3);
        assert!(
            remaining
                .iter()
                .any(|value| { value.as_str().is_some_and(|value| value.contains("ctime")) })
        );
        assert!(remaining.iter().any(|value| {
            value
                .as_str()
                .is_some_and(|value| value.contains("validator-challenge"))
        }));
    }

    #[test]
    fn only_typed_internal_capacity_failures_trigger_retry() {
        let block_error = HostBuildError::GuardStatus {
            stage: "format-payload",
            status: "exit status: 1".to_owned(),
            diagnostic: "Could not allocate block in ext2 filesystem".to_owned(),
        };
        assert_eq!(
            helper_capacity_resource(&block_error),
            Some(CapacityResource::Blocks)
        );
        let unrelated = HostBuildError::GuardStatus {
            stage: "format-payload",
            status: "exit status: 1".to_owned(),
            diagnostic: "host helper rejected its configuration".to_owned(),
        };
        assert_eq!(helper_capacity_resource(&unrelated), None);

        let guest = HostBuildError::Guest {
            stage: "BUILD_DONE",
            message: ErrorMessage::new(
                "apply-layers",
                pocket_core::ErrorCode::BuilderToolFailed,
                Some(libc::ENOSPC),
                "target inode capacity exhausted",
            ),
        };
        assert_eq!(
            guest_capacity_resource(&guest),
            Some(CapacityResource::Inodes)
        );

        // Every token the guest can emit must map to what it says. The
        // combined case is the one that matters: reading it as inode-only
        // retries with the same block budget that just ran out.
        for (token, expected) in [
            ("block", CapacityResource::Blocks),
            ("inode", CapacityResource::Inodes),
            ("block-and-inode", CapacityResource::BlocksAndInodes),
            ("block-or-inode", CapacityResource::BlockOrInode),
        ] {
            let reported = HostBuildError::Guest {
                stage: "BUILD_DONE",
                message: ErrorMessage::new(
                    "apply-layers",
                    pocket_core::ErrorCode::BuilderToolFailed,
                    Some(libc::ENOSPC),
                    format!("target {token} capacity exhausted while applying layers: io error"),
                ),
            };
            assert_eq!(
                guest_capacity_resource(&reported),
                Some(expected),
                "{token} was misclassified"
            );
        }

        // A guest capacity failure reaches the host through the control
        // protocol, so attaching the console must not hide it from the retry
        // classifier.
        let wrapped = HostBuildError::GuestProtocol {
            stage: "builder-uml",
            reason: "guest reported an error".to_owned(),
            source: Box::new(guest),
            diagnostic: "bounded console tail".to_owned(),
        };
        assert_eq!(
            guest_capacity_resource(&wrapped),
            Some(CapacityResource::Inodes)
        );

        let wrapped_helper = HostBuildError::GuestProtocol {
            stage: "builder-uml",
            reason: "guest reported an error".to_owned(),
            source: Box::new(HostBuildError::GuardStatus {
                stage: "format-target",
                status: "exit status: 1".to_owned(),
                diagnostic: "Could not allocate block in ext2 filesystem".to_owned(),
            }),
            diagnostic: "bounded console tail".to_owned(),
        };
        assert_eq!(
            helper_capacity_resource(&wrapped_helper),
            Some(CapacityResource::Blocks)
        );
    }

    #[test]
    fn failed_attempt_is_removed_before_a_fresh_file_can_be_created() {
        let temporary = tempdir().expect("temporary root");
        let path = temporary.path().join("base.ext4");
        let file = fs::File::create(&path).expect("failed attempt");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("private mode");
        drop(file);
        discard_retry_file(
            &path,
            "target",
            HostBuildError::invalid("target", "injected capacity failure"),
        )
        .expect("discard failed attempt");
        assert!(!path.exists());
        let replacement = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .expect("fresh replacement");
        drop(replacement);
    }

    #[test]
    fn manifest_structure_binds_marker_and_rejects_account_mismatch() {
        let mut verifier = ManifestStructuralVerifier::default();
        let entries = [
            entry(Vec::new(), 2, None),
            entry(b".pocket-generation.cbor".to_vec(), 1, Some(vec![7; 32])),
            entry(b"rootfs".to_vec(), 2, None),
            entry(b"rootfs/bin".to_vec(), 2, None),
        ];
        let mut bytes = Vec::new();
        for entry in entries {
            let encoded = encode_payload(&entry).expect("entry encoding");
            bytes.extend_from_slice(&(encoded.len() as u32).to_be_bytes());
            bytes.extend_from_slice(&encoded);
        }
        verifier
            .accept_chunk(&ManifestChunk {
                stream_id: "a".repeat(64),
                sequence: 0,
                first_entry: 0,
                entry_count: 4,
                bytes,
            })
            .expect("valid chunk");
        verifier.finish().expect("complete layout");
        assert_eq!(verifier.marker_sha256().expect("marker"), "07".repeat(32));
        assert!(compare_evidence("account_db_sha256", &"a".repeat(64), &"b".repeat(64)).is_err());
    }

    #[test]
    fn manifest_path_order_matches_the_bounded_depth_first_walker() {
        let directory_child = b"rootfs/usr/lib/perl/Carp/Heavy.pm";
        let dotted_sibling = b"rootfs/usr/lib/perl/Carp.pm";
        assert_eq!(
            directory_child.as_slice().cmp(dotted_sibling.as_slice()),
            std::cmp::Ordering::Greater
        );
        assert_eq!(
            manifest_path_order(directory_child, dotted_sibling),
            std::cmp::Ordering::Less
        );
        assert_eq!(
            manifest_path_order(b"rootfs/usr/lib/perl/Carp", directory_child),
            std::cmp::Ordering::Less
        );
        assert_eq!(
            manifest_path_order(dotted_sibling, directory_child),
            std::cmp::Ordering::Greater
        );
    }

    /// A generation's identity must name what it is, not how much host scratch
    /// space went into making it. Two layouts that select the same image differ
    /// in payload sizing whenever one carries blobs for other platforms, and
    /// they must still resolve to one generation.
    #[test]
    fn payload_scratch_sizing_is_not_part_of_a_generation_identity() {
        let temporary = tempdir().expect("temporary root");
        let profile_root = temporary.path().join("profiles/release/current");
        let profile = synthetic_profile(
            ManagedUmlPath::new(&profile_root).expect("managed profile path"),
            true,
        );
        let target = FilesystemSizing {
            initial: FilesystemSize {
                bytes: 64 * 1024 * 1024,
                inodes: 65_536,
            },
            retry: None,
        };
        let digest = build_contract_digest(&profile, target).expect("contract digest");

        // The same target sizing must give the same identity no matter what
        // the payload scratch image would have had to be.
        assert_eq!(
            digest,
            build_contract_digest(&profile, target).expect("contract digest")
        );

        // Target sizing does still shape the output, so it must still count.
        let larger = FilesystemSizing {
            initial: FilesystemSize {
                bytes: 128 * 1024 * 1024,
                inodes: 65_536,
            },
            retry: None,
        };
        assert_ne!(
            digest,
            build_contract_digest(&profile, larger).expect("contract digest")
        );
    }

    /// A helper's work scales with the image it writes, so its budget must
    /// too. A fixed budget is a silent ceiling on supported image size.
    #[test]
    fn helper_budgets_grow_with_the_image_and_stay_bounded() {
        let policy = BuilderPolicy {
            helper_timeout: Duration::from_secs(300),
            helper_timeout_per_gib: Duration::from_secs(60),
            ..BuilderPolicy::default()
        };
        assert_eq!(helper_budget(policy, 0), Duration::from_secs(300));
        // A partial gibibyte still buys a whole allowance.
        assert_eq!(helper_budget(policy, 1), Duration::from_secs(360));
        assert_eq!(
            helper_budget(policy, 64 * 1024 * 1024 * 1024),
            Duration::from_secs(300 + 64 * 60)
        );
        // Nothing may exceed the validated ceiling, however absurd the size.
        assert_eq!(helper_budget(policy, u64::MAX), MAX_TIMEOUT);
        assert!(validate_policy(policy).is_ok());
        assert!(
            validate_policy(BuilderPolicy {
                helper_timeout_per_gib: Duration::ZERO,
                ..policy
            })
            .is_err()
        );
    }

    #[test]
    fn filesystem_helpers_get_only_typed_configuration_private_blkid_and_lock_fds() {
        let temporary = tempdir().expect("temporary root");
        let profile_root = temporary.path().join("profiles/release/current");
        fs::create_dir_all(profile_root.join("host")).expect("host directory");
        let guard = profile_root.join("host/pocket-guard");
        fs::write(
            &guard,
            b"#!/bin/sh\ntest -e /proc/self/fd/8 || exit 81\ntest -e /proc/self/fd/9 || exit 82\nwhile [ \"$1\" != \"--\" ]; do shift 2; done\nshift\nexec \"$@\"\n",
        )
        .expect("fake guard");
        fs::set_permissions(&guard, fs::Permissions::from_mode(0o755)).expect("guard mode");
        let mke2fs_config = profile_root.join("host/mke2fs.conf");
        fs::write(&mke2fs_config, b"[defaults]\n").expect("mke2fs config");
        let e2fsck_config = profile_root.join("host/e2fsck.conf");
        fs::write(&e2fsck_config, b"").expect("empty e2fsck config");
        let helper = profile_root.join("host/mke2fs");
        fs::write(
            &helper,
            b"#!/bin/sh\ntest -e /proc/self/fd/8 || exit 91\ntest -e /proc/self/fd/9 || exit 92\ntest -n \"${MKE2FS_CONFIG+x}\" || exit 93\ntest -z \"${E2FSCK_CONFIG+x}\" || exit 94\ntest \"$LC_ALL\" = C || exit 95\ntest \"$(pwd)\" = / || exit 96\nprintf '%s\\n%s\\n' \"$MKE2FS_CONFIG\" \"$BLKID_FILE\"\n",
        )
        .expect("fake helper");
        fs::set_permissions(&helper, fs::Permissions::from_mode(0o755)).expect("helper mode");
        let tmp = temporary.path().join("runtime/build/tmp");
        fs::create_dir_all(&tmp).expect("tmp directory");
        let blkid_file = tmp.join("blkid.tab");
        create_private_blkid_file(&blkid_file).expect("private empty blkid file");
        let lock_path = temporary.path().join("store/lock");
        fs::create_dir_all(lock_path.parent().expect("lock parent")).expect("store directory");
        let lock = fs::File::create(lock_path).expect("lock file");
        let profile = synthetic_profile(
            ManagedUmlPath::new(profile_root).expect("managed profile path"),
            true,
        );
        let mke2fs_environment =
            e2fs_helper_environment(&profile, &tmp, &blkid_file, E2fsHelper::Mke2fs);
        assert_eq!(mke2fs_environment.len(), 11);
        assert_eq!(
            mke2fs_environment.get(std::ffi::OsStr::new("MKE2FS_CONFIG")),
            Some(&mke2fs_config.as_os_str().to_owned())
        );
        assert!(!mke2fs_environment.contains_key(std::ffi::OsStr::new("E2FSCK_CONFIG")));
        assert_eq!(
            mke2fs_environment.get(std::ffi::OsStr::new("BLKID_FILE")),
            Some(&blkid_file.as_os_str().to_owned())
        );
        let e2fsck_environment =
            e2fs_helper_environment(&profile, &tmp, &blkid_file, E2fsHelper::E2fsck);
        assert_eq!(e2fsck_environment.len(), 11);
        assert!(!e2fsck_environment.contains_key(std::ffi::OsStr::new("MKE2FS_CONFIG")));
        assert_eq!(
            e2fsck_environment.get(std::ffi::OsStr::new("E2FSCK_CONFIG")),
            Some(&e2fsck_config.as_os_str().to_owned())
        );
        assert_eq!(
            e2fsck_environment.get(std::ffi::OsStr::new("BLKID_FILE")),
            Some(&blkid_file.as_os_str().to_owned())
        );
        let helper_context = E2fsHelperContext {
            profile: &profile,
            lock: &lock,
            tmp: &tmp,
            blkid_file: &blkid_file,
            policy: BuilderPolicy {
                helper_timeout: Duration::from_secs(2),
                guard_exit_timeout: Duration::from_secs(2),
                ..BuilderPolicy::default()
            },
        };
        let log = run_guarded_helper("fake-mke2fs", E2fsHelper::Mke2fs, &[], &helper_context, 0)
            .expect("guarded helper");
        let output = String::from_utf8(log.stdout.bytes).expect("UTF-8 output");
        assert_eq!(
            output.lines().collect::<Vec<_>>(),
            [
                mke2fs_config.to_str().expect("mke2fs config path"),
                blkid_file.to_str().expect("blkid path")
            ]
        );
    }

    /// Run with:
    ///
    /// `POCKET_REAL_PROFILE_ROOT=/absolute/profile \
    ///  POCKET_REAL_OCI_LAYOUT=/absolute/oci-layout \
    ///  POCKET_REAL_STORE_ROOT=/absolute/store \
    ///  POCKET_REAL_RUNTIME_ROOT=/absolute/runtime \
    ///  POCKET_REAL_SOURCE_REFERENCE=docker://registry.example/image@sha256:... \
    ///  cargo test -p pocket-runtime qualified_release_bundle_boots_real_builder_uml \
    ///  -- --ignored --exact`
    ///
    /// This is deliberately ignored: merely compiling it is not qualification
    /// evidence for the supplied kernel, initramfs, or host tools.
    #[test]
    #[ignore = "requires an externally built and qualified release profile plus OCI image"]
    fn qualified_release_bundle_boots_real_builder_uml() {
        let required_path = |name: &str| {
            PathBuf::from(
                std::env::var_os(name)
                    .unwrap_or_else(|| panic!("{name} must name an absolute test path")),
            )
        };
        let profile_root = required_path("POCKET_REAL_PROFILE_ROOT");
        let layout = required_path("POCKET_REAL_OCI_LAYOUT");
        let store_root = required_path("POCKET_REAL_STORE_ROOT");
        let runtime_root = required_path("POCKET_REAL_RUNTIME_ROOT");
        let source_reference = std::env::var("POCKET_REAL_SOURCE_REFERENCE")
            .expect("POCKET_REAL_SOURCE_REFERENCE must identify the authenticated source");

        let profile =
            VerifiedProfile::load(ManagedUmlPath::new(profile_root).expect("managed profile path"))
                .expect("qualified release profile");
        let store = Store::initialize(ManagedUmlPath::new(store_root).expect("managed store path"))
            .expect("private store");
        let builder = HostBuilder::new(
            &profile,
            &store,
            ManagedUmlPath::new(runtime_root).expect("managed runtime path"),
            BuilderPolicy::default(),
        )
        .expect("host builder");
        let output = builder
            .build(BuildRequest {
                oci_layout: layout,
                source_reference,
                requested_variant: None,
            })
            .expect("real UML builder workflow");
        let generation = store
            .verify_generation(output.generation_id)
            .expect("published generation remains fully verifiable");
        assert_eq!(
            generation.manifest().derivation_key(),
            output.derivation_key
        );
        let sidecars: Vec<&str> = generation
            .manifest()
            .sidecars()
            .iter()
            .map(pocket_store::ImmutableSidecar::name)
            .collect();
        assert_eq!(
            sidecars,
            [
                "accounts.cbor",
                "artifact.digest",
                "build-record.json",
                "build.log",
                "image-config.json",
                "metadata.manifest",
                "validation-evidence.cbor",
            ]
        );
    }

    fn entry(path: Vec<u8>, kind: u8, content_sha256: Option<Vec<u8>>) -> ManifestEntry {
        ManifestEntry {
            path,
            kind,
            mode: if kind == 2 { 0o755 } else { 0o444 },
            uid: 0,
            gid: 0,
            size: if kind == 1 { 32 } else { 4096 },
            rdev: 0,
            mtime_seconds: 1,
            mtime_nanoseconds: 0,
            symlink_target: None,
            content_sha256,
            hardlink_target: None,
            xattrs: Vec::new(),
        }
    }

    fn oci_layout(descriptor_variant: Option<&str>) -> (tempfile::TempDir, PathBuf) {
        let temporary = tempdir().expect("OCI layout");
        let root = temporary.path().join("input/layout/root");
        fs::create_dir_all(root.join("blobs/sha256")).expect("blobs directory");
        fs::write(
            root.join("oci-layout"),
            serde_json::to_vec(&json!({"imageLayoutVersion": "1.0.0"})).expect("layout JSON"),
        )
        .expect("layout document");
        let layer = b"synthetic uncompressed tar bytes";
        let layer_descriptor = write_blob(&root, OCI_LAYER, layer, None);
        let config = serde_json::to_vec(&json!({
            "architecture": "amd64",
            "os": "linux",
            "rootfs": {"type": "layers", "diff_ids": [sha256_text(layer)]},
            "config": {"User": "0", "Entrypoint": ["/bin/true"]}
        }))
        .expect("config JSON");
        let config_descriptor = write_blob(&root, OCI_CONFIG, &config, None);
        let manifest = serde_json::to_vec(&json!({
            "schemaVersion": 2,
            "mediaType": OCI_MANIFEST,
            "config": config_descriptor,
            "layers": [layer_descriptor]
        }))
        .expect("manifest JSON");
        let mut descriptor = write_blob(
            &root,
            OCI_MANIFEST,
            &manifest,
            Some(json!({
                "os": "linux",
                "architecture": "amd64",
                "variant": descriptor_variant
            })),
        );
        descriptor["annotations"] = json!({"org.opencontainers.image.ref.name": "root"});
        fs::write(
            root.join("index.json"),
            serde_json::to_vec(&json!({
                "schemaVersion": 2,
                "mediaType": OCI_INDEX,
                "manifests": [descriptor]
            }))
            .expect("index JSON"),
        )
        .expect("index document");
        (temporary, root)
    }

    fn write_blob(root: &Path, media_type: &str, bytes: &[u8], platform: Option<Value>) -> Value {
        let digest = sha256_text(bytes);
        fs::write(
            root.join("blobs/sha256")
                .join(digest.strip_prefix("sha256:").expect("digest prefix")),
            bytes,
        )
        .expect("blob");
        let mut descriptor = json!({
            "mediaType": media_type,
            "digest": digest,
            "size": bytes.len()
        });
        if let Some(platform) = platform {
            descriptor["platform"] = platform;
        }
        descriptor
    }

    fn sha256_text(bytes: &[u8]) -> String {
        format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
    }
}
