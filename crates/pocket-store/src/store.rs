use std::{
    collections::BTreeSet,
    ffi::OsStr,
    fs::File,
    io::{self, Read},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use pocket_core::ManagedUmlPath;
use sha2::{Digest as _, Sha256};

use crate::{
    AliasId, AliasKey, DerivationKey, Digest, GenerationId, GenerationSpec, ImmutableSidecar,
    InstanceId, MAX_GENERATION_SIDECARS, MAX_METADATA_BYTES, MetadataKind, RetainedCowId,
    RetainedCowState, StoreError,
    codec::{Reader, finish_record, put_text, put_u16, put_u64, start_record, verify_record},
    fs::{
        IMMUTABLE_DIR_MODE, IMMUTABLE_FILE_MODE, PRIVATE_DIR_MODE, PRIVATE_FILE_MODE,
        create_private_dir, create_regular_at, ensure_private_dir, hash_file,
        initialize_absent_absolute_dir, initialize_absolute_dir, list_names,
        open_absolute_dir_no_symlinks, open_absolute_regular_no_symlinks, open_dir_at,
        open_regular_at, read_bounded, remove_tree_at, rename_noreplace_at, rename_replace_at,
        set_mode, unlink_file_at, validate_directory, validate_private_root, validate_regular,
        write_new_synced,
    },
    identity::{
        read_derivation_key, read_digest, validate_canonical_sidecars, validate_sidecar_name,
    },
};

const STORE_MAGIC: &[u8; 8] = b"PKVMSTR2";
const GENERATION_MAGIC: &[u8; 8] = b"PKVMGEN2";
const STAGING_MAGIC: &[u8; 8] = b"PKVMSTG2";
const DERIVATION_MAGIC: &[u8; 8] = b"PKVMDER2";
const ALIAS_MAGIC: &[u8; 8] = b"PKVMALS2";
const LEASE_MAGIC: &[u8; 8] = b"PKVMLES2";
const RETAINED_MAGIC: &[u8; 8] = b"PKVMRET2";
const INSTANCE_MAGIC: &[u8; 8] = b"PKVMINS2";
const LOCK_MAGIC: &[u8; 8] = b"PKVMLCK2";

const STORE_METADATA: &str = "store.meta";
const INIT_LOCK: &str = "init.lock";
const ROOTS_LOCK: &str = "roots.lock";
const GENERATION_METADATA: &str = "generation.meta";
const STAGING_METADATA: &str = "staging.meta";
const BASE_IMAGE: &str = "base.ext4";
/// The prefix every fixed record is published through, in whichever
/// directory holds it.
const FIXED_TEMP_PREFIX: &str = ".tmp-fixed-";
const GENERATION_TEMP_PREFIX: &str = ".tmp-generation-";

static UNIQUE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// A validated content-addressed store rooted at a private directory.
pub struct Store {
    root_path: PathBuf,
    root: File,
    generations: File,
    derivations: File,
    staging: File,
    aliases: File,
    leases: File,
    retained: File,
    instances: File,
    locks: File,
    root_device: u64,
    root_inode: u64,
}

impl std::fmt::Debug for Store {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Store")
            .field("root_path", &self.root_path)
            .field("root_device", &self.root_device)
            .field("root_inode", &self.root_inode)
            .finish_non_exhaustive()
    }
}

/// Result of trying to begin a generation transaction.
pub enum BeginGeneration<'store> {
    /// The exact generation is already committed and hash-verified. The
    /// lease is held so a concurrent collection cannot delete it before the
    /// caller roots it.
    Existing(Lease),
    /// The caller owns the per-derivation build lock and a private staging area.
    Vacant(GenerationTransaction<'store>),
}

impl std::fmt::Debug for BeginGeneration<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Existing(lease) => formatter.debug_tuple("Existing").field(lease).finish(),
            Self::Vacant(transaction) => {
                formatter.debug_tuple("Vacant").field(transaction).finish()
            }
        }
    }
}

/// Hash-verified metadata for one immutable base filesystem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenerationManifest {
    id: GenerationId,
    derivation_key: DerivationKey,
    spec: GenerationSpec,
    base_digest: Digest,
    base_size: u64,
    sidecars: Vec<ImmutableSidecar>,
}

impl GenerationManifest {
    #[must_use]
    pub const fn id(&self) -> GenerationId {
        self.id
    }

    #[must_use]
    pub const fn derivation_key(&self) -> DerivationKey {
        self.derivation_key
    }

    #[must_use]
    pub const fn spec(&self) -> &GenerationSpec {
        &self.spec
    }

    #[must_use]
    pub const fn base_digest(&self) -> Digest {
        self.base_digest
    }

    #[must_use]
    pub const fn base_size(&self) -> u64 {
        self.base_size
    }

    #[must_use]
    pub fn sidecars(&self) -> &[ImmutableSidecar] {
        &self.sidecars
    }

    pub fn recompute_id(&self) -> Result<GenerationId, StoreError> {
        GenerationId::derive(
            self.derivation_key,
            self.base_digest,
            self.base_size,
            &self.sidecars,
        )
    }

    fn encode(&self) -> Vec<u8> {
        let mut bytes = start_record(GENERATION_MAGIC);
        bytes.extend_from_slice(self.id.as_bytes());
        bytes.extend_from_slice(self.derivation_key.as_bytes());
        self.spec.encode(&mut bytes);
        bytes.extend_from_slice(self.base_digest.as_bytes());
        put_u64(&mut bytes, self.base_size);
        put_u16(
            &mut bytes,
            u16::try_from(self.sidecars.len()).expect("validated sidecar count"),
        );
        for sidecar in &self.sidecars {
            sidecar.encode(&mut bytes);
        }
        finish_record(bytes)
    }

    fn decode(bytes: &[u8], path: &Path) -> Result<Self, StoreError> {
        let result = (|| {
            let mut reader = verify_record(bytes, GENERATION_MAGIC, MetadataKind::Generation)?;
            let id = read_generation_id(&mut reader)?;
            let derivation_key = read_derivation_key(&mut reader)?;
            let spec = GenerationSpec::decode(&mut reader)?;
            let base_digest = read_digest(&mut reader)?;
            let base_size = reader.u64()?;
            let sidecar_count = usize::from(reader.u16()?);
            if sidecar_count > MAX_GENERATION_SIDECARS {
                return Err(StoreError::metadata(
                    MetadataKind::Generation,
                    path,
                    "too many immutable sidecars",
                ));
            }
            let mut sidecars = Vec::with_capacity(sidecar_count);
            for _ in 0..sidecar_count {
                sidecars.push(ImmutableSidecar::decode(&mut reader)?);
            }
            reader.finish()?;
            let manifest = Self {
                id,
                derivation_key,
                spec,
                base_digest,
                base_size,
                sidecars,
            };
            validate_canonical_sidecars(&manifest.sidecars)?;
            if manifest.spec.derivation_key() != manifest.derivation_key {
                return Err(StoreError::metadata(
                    MetadataKind::Generation,
                    path,
                    "derivation key does not match canonical immutable inputs",
                ));
            }
            if manifest.recompute_id()? != manifest.id {
                return Err(StoreError::metadata(
                    MetadataKind::Generation,
                    path,
                    "generation ID does not match completed immutable outputs",
                ));
            }
            if manifest.encode() != bytes {
                return Err(StoreError::metadata(
                    MetadataKind::Generation,
                    path,
                    "record is not in canonical encoding",
                ));
            }
            Ok(manifest)
        })();
        result.map_err(|error| contextualize(error, MetadataKind::Generation, path))
    }
}

/// An immutable, verified generation selected from the store.
#[derive(Debug)]
pub struct Generation {
    manifest: GenerationManifest,
    directory_path: PathBuf,
    directory: File,
    base_path: PathBuf,
    base: File,
    root_device: u64,
}

impl Generation {
    #[must_use]
    pub const fn manifest(&self) -> &GenerationManifest {
        &self.manifest
    }

    #[must_use]
    pub const fn id(&self) -> GenerationId {
        self.manifest.id
    }

    #[must_use]
    pub fn directory_path(&self) -> &Path {
        &self.directory_path
    }

    /// Absolute path to pass as the immutable UBD COW backing file.
    #[must_use]
    pub fn base_path(&self) -> &Path {
        &self.base_path
    }

    /// An open descriptor for the exact verified base inode.
    #[must_use]
    pub const fn base_file(&self) -> &File {
        &self.base
    }
}

/// One alias that is currently rooting a generation against collection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AliasRoot {
    pub id: AliasId,
    pub profile_id: String,
    pub reference: String,
    pub platform: String,
    pub selector_policy_id: String,
    pub generation_id: GenerationId,
}

/// A shared generation lease. Its lock remains held until this value is dropped.
#[derive(Debug)]
pub struct Lease {
    generation: Generation,
    lock: File,
}

impl Lease {
    #[must_use]
    pub const fn generation(&self) -> &Generation {
        &self.generation
    }

    #[must_use]
    pub const fn id(&self) -> GenerationId {
        self.generation.id()
    }

    /// The guard process must keep this descriptor open for the full run.
    #[must_use]
    pub const fn lock_file(&self) -> &File {
        &self.lock
    }

    /// Read and re-authenticate one immutable sidecar while this exact
    /// generation remains protected by the lease.
    ///
    /// The file is opened relative to the already verified generation
    /// directory descriptor, never by following a caller-provided path. The
    /// manifest-bound size and SHA-256 digest are checked against the exact
    /// returned bytes. Callers must provide a semantic resource ceiling in
    /// addition to the generation's authenticated size.
    pub fn read_sidecar(&self, name: &str, maximum_bytes: u64) -> Result<Vec<u8>, StoreError> {
        if maximum_bytes == 0 {
            return Err(StoreError::InvalidInput {
                field: "sidecar.maximum_bytes",
                reason: "must be greater than zero".to_owned(),
            });
        }
        let sidecar = self
            .generation
            .manifest
            .sidecars
            .iter()
            .find(|sidecar| sidecar.name() == name)
            .ok_or_else(|| StoreError::SidecarNotFound {
                generation: self.id(),
                name: name.to_owned(),
            })?;
        let path = self.generation.directory_path.join(sidecar.name());
        if sidecar.size() > maximum_bytes {
            return Err(StoreError::SidecarTooLarge {
                path,
                actual: sidecar.size(),
                maximum: maximum_bytes,
            });
        }

        let mut file = open_regular_at(&self.generation.directory, sidecar.name(), &path)?;
        let metadata = validate_regular(
            &file,
            &path,
            self.generation.root_device,
            IMMUTABLE_FILE_MODE,
        )?;
        if metadata.len() != sidecar.size() {
            return Err(StoreError::SizeMismatch {
                path,
                expected: sidecar.size(),
                actual: metadata.len(),
            });
        }
        let capacity =
            usize::try_from(sidecar.size()).map_err(|_| StoreError::SidecarTooLarge {
                path: path.clone(),
                actual: sidecar.size(),
                maximum: usize::MAX as u64,
            })?;
        let mut bytes = Vec::with_capacity(capacity);
        (&mut file)
            .take(sidecar.size().saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|error| StoreError::io("read immutable sidecar", &path, error))?;
        let observed_size = u64::try_from(bytes.len()).expect("Vec length fits u64");
        if observed_size != sidecar.size() {
            return Err(StoreError::SizeMismatch {
                path,
                expected: sidecar.size(),
                actual: observed_size,
            });
        }
        let observed_digest = Digest::of_bytes(&bytes);
        if observed_digest != sidecar.digest() {
            return Err(StoreError::DigestMismatch {
                path,
                expected: sidecar.digest(),
                actual: observed_digest,
            });
        }
        // Recheck metadata after the read so a concurrent inode replacement or
        // mode change cannot be accepted merely because the bytes matched.
        let final_metadata = validate_regular(
            &file,
            &path,
            self.generation.root_device,
            IMMUTABLE_FILE_MODE,
        )?;
        if final_metadata.dev() != metadata.dev()
            || final_metadata.ino() != metadata.ino()
            || final_metadata.len() != metadata.len()
        {
            return Err(StoreError::UnexpectedEntry { path });
        }
        Ok(bytes)
    }
}

/// Bound on an instance name, which an operator types.
pub const MAX_INSTANCE_NAME_BYTES: usize = 64;

/// Bound on the recorded command line, which is evidence rather than input.
pub const MAX_INSTANCE_COMMAND_BYTES: usize = 4096;

/// Bound on a recorded argv, matching the protocol's own argument cap.
pub const MAX_INSTANCE_ARGV: usize = 1024;

/// How an instance ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstanceOutcome {
    /// Still running, or the owner died without recording an outcome.
    Unknown,
    Exited(u8),
    Signalled(u16),
}

impl InstanceOutcome {
    pub(crate) const fn encode(self) -> (u8, u16) {
        match self {
            Self::Unknown => (0, 0),
            Self::Exited(code) => (1, code as u16),
            Self::Signalled(signal) => (2, signal),
        }
    }

    pub(crate) fn decode(tag: u8, value: u16) -> Result<Self, StoreError> {
        match tag {
            0 => Ok(Self::Unknown),
            1 => u8::try_from(value).map(Self::Exited).map_err(|_| {
                StoreError::metadata(MetadataKind::Instance, "<memory>", "exit code out of range")
            }),
            2 => Ok(Self::Signalled(value)),
            _ => Err(StoreError::metadata(
                MetadataKind::Instance,
                "<memory>",
                format!("invalid instance outcome {tag}"),
            )),
        }
    }
}

/// One finished run, kept so it can be listed, committed or removed.
///
/// This is the named, mutable half of a retained run: the COW itself and its
/// generation root are the [`RetainedCow`] record, which is content-addressed
/// and therefore cannot carry a name an operator chose. Keeping the two apart
/// means renaming or removing an instance never disturbs the root that stops
/// its backing image being collected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Instance {
    id: InstanceId,
    name: String,
    generation_id: GenerationId,
    retained_id: RetainedCowId,
    image_reference: String,
    /// The exact argv to replay on a resume. `command` is the same thing
    /// joined for display, and joining is lossy: an argument containing a
    /// space cannot be recovered from it.
    argv: Vec<String>,
    command: String,
    created_unix: u64,
    finished_unix: u64,
    outcome: InstanceOutcome,
}

impl Instance {
    #[must_use]
    pub const fn id(&self) -> InstanceId {
        self.id
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub const fn generation_id(&self) -> GenerationId {
        self.generation_id
    }

    #[must_use]
    pub const fn retained_id(&self) -> RetainedCowId {
        self.retained_id
    }

    #[must_use]
    pub fn image_reference(&self) -> &str {
        &self.image_reference
    }

    #[must_use]
    pub fn command(&self) -> &str {
        &self.command
    }

    #[must_use]
    pub fn argv(&self) -> &[String] {
        &self.argv
    }

    #[must_use]
    pub const fn created_unix(&self) -> u64 {
        self.created_unix
    }

    #[must_use]
    pub const fn finished_unix(&self) -> u64 {
        self.finished_unix
    }

    #[must_use]
    pub const fn outcome(&self) -> InstanceOutcome {
        self.outcome
    }

    /// An instance is addressed by the name an operator gave it, so identity
    /// is the name and nothing else: two runs of the same image with the same
    /// command are different instances, and re-using a name is a collision the
    /// store refuses rather than a second record that shadows the first.
    fn derive_id(name: &str) -> InstanceId {
        let mut bytes = b"pocket-instance-identity\0v1\0".to_vec();
        put_text(&mut bytes, name);
        InstanceId::from_bytes(Sha256::digest(bytes).into())
    }

    fn encode(&self) -> Vec<u8> {
        let mut bytes = start_record(INSTANCE_MAGIC);
        bytes.extend_from_slice(self.id.as_bytes());
        put_text(&mut bytes, &self.name);
        bytes.extend_from_slice(self.generation_id.as_bytes());
        bytes.extend_from_slice(self.retained_id.as_bytes());
        put_text(&mut bytes, &self.image_reference);
        put_u16(
            &mut bytes,
            u16::try_from(self.argv.len()).expect("validated argv length"),
        );
        for argument in &self.argv {
            put_text(&mut bytes, argument);
        }
        put_text(&mut bytes, &self.command);
        put_u64(&mut bytes, self.created_unix);
        put_u64(&mut bytes, self.finished_unix);
        let (tag, value) = self.outcome.encode();
        bytes.push(tag);
        put_u16(&mut bytes, value);
        finish_record(bytes)
    }

    fn decode(bytes: &[u8], path: &Path) -> Result<Self, StoreError> {
        let result = (|| {
            let mut reader = verify_record(bytes, INSTANCE_MAGIC, MetadataKind::Instance)?;
            let id_bytes: [u8; 32] = reader.take(32)?.try_into().map_err(|_| {
                StoreError::metadata(MetadataKind::Instance, path, "invalid instance ID")
            })?;
            let id = InstanceId::from_bytes(id_bytes);
            let name = reader.text(MAX_INSTANCE_NAME_BYTES)?.to_owned();
            let generation_bytes: [u8; 32] = reader.take(32)?.try_into().map_err(|_| {
                StoreError::metadata(MetadataKind::Instance, path, "invalid generation ID")
            })?;
            let retained_bytes: [u8; 32] = reader.take(32)?.try_into().map_err(|_| {
                StoreError::metadata(MetadataKind::Instance, path, "invalid retained-COW ID")
            })?;
            let image_reference = reader.text(MAX_INSTANCE_COMMAND_BYTES)?.to_owned();
            let argv_len = reader.u16()?;
            let mut argv = Vec::with_capacity(usize::from(argv_len));
            for _ in 0..argv_len {
                argv.push(reader.text(MAX_INSTANCE_COMMAND_BYTES)?.to_owned());
            }
            let command = reader.text(MAX_INSTANCE_COMMAND_BYTES)?.to_owned();
            let created_unix = reader.u64()?;
            let finished_unix = reader.u64()?;
            let tag = reader.u8()?;
            let value = reader.u16()?;
            reader.finish()?;
            let instance = Self {
                id,
                name,
                generation_id: GenerationId::from_bytes(generation_bytes),
                retained_id: RetainedCowId::from_bytes(retained_bytes),
                image_reference,
                argv,
                command,
                created_unix,
                finished_unix,
                outcome: InstanceOutcome::decode(tag, value)?,
            };
            if Self::derive_id(&instance.name) != instance.id {
                return Err(StoreError::metadata(
                    MetadataKind::Instance,
                    path,
                    "instance ID does not match its name",
                ));
            }
            if instance.encode() != bytes {
                return Err(StoreError::metadata(
                    MetadataKind::Instance,
                    path,
                    "instance record is not canonical",
                ));
            }
            Ok(instance)
        })();
        result.map_err(|error| contextualize(error, MetadataKind::Instance, path))
    }
}

/// Reject an instance name that could not be typed back, or that would not be
/// a single safe filename component.
pub fn validate_instance_name(name: &str) -> Result<(), StoreError> {
    if name.is_empty() || name.len() > MAX_INSTANCE_NAME_BYTES {
        return Err(StoreError::metadata(
            MetadataKind::Instance,
            "<name>",
            format!("name must be 1 to {MAX_INSTANCE_NAME_BYTES} bytes"),
        ));
    }
    let acceptable = name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'));
    if !acceptable || name.starts_with('.') {
        return Err(StoreError::metadata(
            MetadataKind::Instance,
            "<name>",
            "name may use only letters, digits, '-', '_' and '.', and may not start with '.'",
        ));
    }
    Ok(())
}

/// A durable retained-COW record, which is an independent generation GC root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetainedCow {
    id: RetainedCowId,
    generation_id: GenerationId,
    cow_path: ManagedUmlPath,
    cow_digest: Digest,
    cow_size: u64,
    state: RetainedCowState,
}

impl RetainedCow {
    #[must_use]
    pub const fn id(&self) -> RetainedCowId {
        self.id
    }

    #[must_use]
    pub const fn generation_id(&self) -> GenerationId {
        self.generation_id
    }

    #[must_use]
    pub const fn cow_path(&self) -> &ManagedUmlPath {
        &self.cow_path
    }

    #[must_use]
    pub const fn cow_digest(&self) -> Digest {
        self.cow_digest
    }

    #[must_use]
    pub const fn cow_size(&self) -> u64 {
        self.cow_size
    }

    #[must_use]
    pub const fn state(&self) -> RetainedCowState {
        self.state
    }

    fn derive_id(
        generation_id: GenerationId,
        cow_path: &ManagedUmlPath,
        cow_digest: Digest,
        cow_size: u64,
        state: RetainedCowState,
    ) -> RetainedCowId {
        let mut bytes = b"pocket-retained-cow-identity\0v1\0".to_vec();
        bytes.extend_from_slice(generation_id.as_bytes());
        put_text(
            &mut bytes,
            cow_path.as_path().to_str().expect("managed path is UTF-8"),
        );
        bytes.extend_from_slice(cow_digest.as_bytes());
        put_u64(&mut bytes, cow_size);
        bytes.push(state.encode());
        RetainedCowId::from_bytes(Sha256::digest(bytes).into())
    }

    fn encode(&self) -> Vec<u8> {
        let mut bytes = start_record(RETAINED_MAGIC);
        bytes.extend_from_slice(self.id.as_bytes());
        bytes.extend_from_slice(self.generation_id.as_bytes());
        put_text(
            &mut bytes,
            self.cow_path
                .as_path()
                .to_str()
                .expect("managed path is UTF-8"),
        );
        bytes.extend_from_slice(self.cow_digest.as_bytes());
        put_u64(&mut bytes, self.cow_size);
        bytes.push(self.state.encode());
        finish_record(bytes)
    }

    fn decode(bytes: &[u8], path: &Path) -> Result<Self, StoreError> {
        let result = (|| {
            let mut reader = verify_record(bytes, RETAINED_MAGIC, MetadataKind::RetainedCow)?;
            let id = read_retained_id(&mut reader)?;
            let generation_id = read_generation_id(&mut reader)?;
            let cow_text = reader.text(pocket_core::MAX_MANAGED_UML_PATH_BYTES)?;
            let cow_path = ManagedUmlPath::new(cow_text).map_err(|error| {
                StoreError::metadata(MetadataKind::RetainedCow, path, error.to_string())
            })?;
            let cow_digest = read_digest(&mut reader)?;
            let cow_size = reader.u64()?;
            let state = RetainedCowState::decode(reader.u8()?)?;
            reader.finish()?;
            let retained = Self {
                id,
                generation_id,
                cow_path,
                cow_digest,
                cow_size,
                state,
            };
            if Self::derive_id(
                generation_id,
                &retained.cow_path,
                cow_digest,
                cow_size,
                state,
            ) != id
            {
                return Err(StoreError::metadata(
                    MetadataKind::RetainedCow,
                    path,
                    "retained-COW ID does not match canonical record",
                ));
            }
            if retained.encode() != bytes {
                return Err(StoreError::metadata(
                    MetadataKind::RetainedCow,
                    path,
                    "record is not in canonical encoding",
                ));
            }
            Ok(retained)
        })();
        result.map_err(|error| contextualize(error, MetadataKind::RetainedCow, path))
    }
}

/// A verified retained COW plus a shared lease on its exact backing generation.
#[derive(Debug)]
pub struct RetainedCowLease {
    retained: RetainedCow,
    generation_lease: Lease,
    cow: File,
}

impl RetainedCowLease {
    #[must_use]
    pub const fn retained(&self) -> &RetainedCow {
        &self.retained
    }

    #[must_use]
    pub const fn generation_lease(&self) -> &Lease {
        &self.generation_lease
    }

    /// An open descriptor for the exact COW inode whose digest was verified.
    #[must_use]
    pub const fn cow_file(&self) -> &File {
        &self.cow
    }
}

/// Result of crash recovery for publication staging and atomic-record remnants.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RecoveryReport {
    pub removed_staging: Vec<PathBuf>,
    pub busy_staging: Vec<PathBuf>,
    pub completed_publications: Vec<GenerationId>,
    pub busy_publications: Vec<GenerationId>,
    pub removed_temporary_records: Vec<PathBuf>,
    pub blocked_entries: Vec<PathBuf>,
}

/// Reachability and deletion result from one conservative GC pass.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct GarbageCollectionReport {
    pub collected: Vec<GenerationId>,
    pub rooted: Vec<GenerationId>,
    pub leased_or_busy: Vec<GenerationId>,
    pub corrupt_unrooted: Vec<GenerationId>,
    /// Publications that were mid-rename while this collection enumerated.
    /// They are in-flight writes by another process, not damaged entries.
    pub publication_in_flight: Vec<String>,
    /// Derivation lookups whose bytes could not be decoded and were therefore
    /// discarded. The lookup is a rebuildable index over the generations, not
    /// a record of them, so losing one costs a cache hit and nothing else.
    pub discarded_derivation_index: Vec<DerivationKey>,
}

#[derive(Debug)]
struct AliasRecord {
    id: AliasId,
    key: AliasKey,
    generation_id: GenerationId,
}

impl AliasRecord {
    fn new(key: AliasKey, generation_id: GenerationId) -> Self {
        Self {
            id: key.id(),
            key,
            generation_id,
        }
    }

    fn encode(&self) -> Vec<u8> {
        let mut bytes = start_record(ALIAS_MAGIC);
        bytes.extend_from_slice(self.id.as_bytes());
        self.key.encode(&mut bytes);
        bytes.extend_from_slice(self.generation_id.as_bytes());
        finish_record(bytes)
    }

    fn decode(bytes: &[u8], path: &Path) -> Result<Self, StoreError> {
        let result = (|| {
            let mut reader = verify_record(bytes, ALIAS_MAGIC, MetadataKind::Alias)?;
            let id = read_alias_id(&mut reader)?;
            let key = AliasKey::decode(&mut reader)?;
            let generation_id = read_generation_id(&mut reader)?;
            reader.finish()?;
            let record = Self {
                id,
                key,
                generation_id,
            };
            if record.key.id() != record.id || record.encode() != bytes {
                return Err(StoreError::metadata(
                    MetadataKind::Alias,
                    path,
                    "alias ID or encoding is not canonical",
                ));
            }
            Ok(record)
        })();
        result.map_err(|error| contextualize(error, MetadataKind::Alias, path))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DerivationRecord {
    derivation_key: DerivationKey,
    winner: GenerationId,
    alternatives: Vec<GenerationId>,
}

impl DerivationRecord {
    fn new(derivation_key: DerivationKey, winner: GenerationId) -> Self {
        Self {
            derivation_key,
            winner,
            alternatives: Vec::new(),
        }
    }

    fn insert(&mut self, generation_id: GenerationId) {
        if generation_id == self.winner || self.alternatives.binary_search(&generation_id).is_ok() {
            return;
        }
        let position = self
            .alternatives
            .binary_search(&generation_id)
            .unwrap_or_else(std::convert::identity);
        self.alternatives.insert(position, generation_id);
    }

    fn remove(&mut self, generation_id: GenerationId) -> bool {
        if generation_id == self.winner {
            if self.alternatives.is_empty() {
                return false;
            }
            self.winner = self.alternatives.remove(0);
        } else if let Ok(position) = self.alternatives.binary_search(&generation_id) {
            self.alternatives.remove(position);
        }
        true
    }

    fn ids(&self) -> impl Iterator<Item = GenerationId> + '_ {
        std::iter::once(self.winner).chain(self.alternatives.iter().copied())
    }

    fn validate(&self) -> Result<(), StoreError> {
        if self.alternatives.len() >= u16::MAX as usize {
            return Err(StoreError::metadata(
                MetadataKind::Derivation,
                "<memory>",
                "too many alternative generation IDs",
            ));
        }
        if self.alternatives.contains(&self.winner)
            || self.alternatives.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(StoreError::metadata(
                MetadataKind::Derivation,
                "<memory>",
                "alternative generation IDs are not canonical",
            ));
        }
        Ok(())
    }

    fn encode(&self) -> Vec<u8> {
        let mut bytes = start_record(DERIVATION_MAGIC);
        bytes.extend_from_slice(self.derivation_key.as_bytes());
        bytes.extend_from_slice(self.winner.as_bytes());
        put_u16(
            &mut bytes,
            u16::try_from(self.alternatives.len()).expect("validated alternative count"),
        );
        for id in &self.alternatives {
            bytes.extend_from_slice(id.as_bytes());
        }
        finish_record(bytes)
    }

    fn decode(bytes: &[u8], path: &Path) -> Result<Self, StoreError> {
        let result = (|| {
            let mut reader = verify_record(bytes, DERIVATION_MAGIC, MetadataKind::Derivation)?;
            let record = Self {
                derivation_key: read_derivation_key(&mut reader)?,
                winner: read_generation_id(&mut reader)?,
                alternatives: {
                    let count = usize::from(reader.u16()?);
                    let mut alternatives = Vec::with_capacity(count);
                    for _ in 0..count {
                        alternatives.push(read_generation_id(&mut reader)?);
                    }
                    alternatives
                },
            };
            reader.finish()?;
            record.validate()?;
            if record.encode() != bytes {
                return Err(StoreError::metadata(
                    MetadataKind::Derivation,
                    path,
                    "record is not in canonical encoding",
                ));
            }
            Ok(record)
        })();
        result.map_err(|error| contextualize(error, MetadataKind::Derivation, path))
    }
}

#[derive(Debug)]
struct StagingRecord {
    derivation_key: DerivationKey,
}

impl StagingRecord {
    fn encode(&self) -> Vec<u8> {
        let mut bytes = start_record(STAGING_MAGIC);
        bytes.extend_from_slice(self.derivation_key.as_bytes());
        finish_record(bytes)
    }

    fn decode(bytes: &[u8], path: &Path) -> Result<Self, StoreError> {
        let result = (|| {
            let mut reader = verify_record(bytes, STAGING_MAGIC, MetadataKind::Staging)?;
            let record = Self {
                derivation_key: read_derivation_key(&mut reader)?,
            };
            reader.finish()?;
            if record.encode() != bytes {
                return Err(StoreError::metadata(
                    MetadataKind::Staging,
                    path,
                    "record is not in canonical encoding",
                ));
            }
            Ok(record)
        })();
        result.map_err(|error| contextualize(error, MetadataKind::Staging, path))
    }
}

/// In-progress same-filesystem publication transaction.
pub struct GenerationTransaction<'store> {
    store: &'store Store,
    spec: GenerationSpec,
    derivation_key: DerivationKey,
    _build_lock: File,
    stage_name: String,
    stage: File,
    generation_temp_name: Option<String>,
    clean_on_drop: bool,
}

impl std::fmt::Debug for GenerationTransaction<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GenerationTransaction")
            .field("derivation_key", &self.derivation_key)
            .field("staging_path", &self.staging_path())
            .finish_non_exhaustive()
    }
}

impl Store {
    /// Create the private root if absent, initialize its schema, and open it.
    pub fn initialize(root_path: ManagedUmlPath) -> Result<Self, StoreError> {
        let root = initialize_absolute_dir(root_path.as_path())?;
        Self::open_from_file(root_path, root, true)
    }

    /// Every name a store creates directly under its own root.
    ///
    /// This is what makes an incomplete root recognizable: a directory holding
    /// only a subset of these is an initialization that did not finish, while
    /// one holding anything else is somebody else's directory.
    pub const ROOT_LAYOUT: [&'static str; 11] = [
        "aliases",
        "derivations",
        "generations",
        "init.lock",
        "instances",
        "leases",
        "locks",
        "retained",
        "roots.lock",
        "staging",
        "store.meta",
    ];

    /// Whether `path` is an existing directory whose entries are all names a
    /// store root creates, so completing it in place cannot disturb anything
    /// that was not put there by a store initialization.
    ///
    /// An empty directory qualifies. A directory holding one unrelated entry
    /// does not, however store-like the rest looks: `--store ~/.ssh` is a
    /// typo, not a request to scatter store metadata through it.
    pub fn is_resumable_root(path: &Path) -> Result<bool, StoreError> {
        let entries = match std::fs::read_dir(path) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(StoreError::io("inspect store root", path, error)),
        };
        for entry in entries {
            let entry = entry.map_err(|error| StoreError::io("inspect store root", path, error))?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                return Ok(false);
            };
            // Initialization's very first act is to publish `init.lock`
            // through a `.tmp-fixed-` temporary in this same directory, and a
            // write that fails there leaves it behind. That residue is exactly
            // what ENOSPC, EDQUOT, EIO or a signal produce, so refusing to
            // recognize it would reject the very states this exists to
            // recover. `Store::recover` already sweeps this prefix from the
            // root, so it is unambiguously the store's own.
            if !Self::ROOT_LAYOUT.contains(&name) && !name.starts_with(FIXED_TEMP_PREFIX) {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Atomically create and initialize a private store root which must be
    /// absent. Unlike [`Store::initialize`], this never fills in or repairs an
    /// existing directory, including one containing invalid store metadata.
    pub fn initialize_absent(root_path: ManagedUmlPath) -> Result<Self, StoreError> {
        let root = initialize_absent_absolute_dir(root_path.as_path())?;
        Self::open_from_file(root_path, root, true)
    }

    /// Open an existing initialized store without modifying root permissions.
    pub fn open(root_path: ManagedUmlPath) -> Result<Self, StoreError> {
        let root = open_absolute_dir_no_symlinks(root_path.as_path())?;
        Self::open_from_file(root_path, root, false)
    }

    fn open_from_file(
        root_path: ManagedUmlPath,
        root: File,
        allow_initialize: bool,
    ) -> Result<Self, StoreError> {
        let root_path = root_path.into_path_buf();
        let (root_device, root_inode) = validate_private_root(&root, &root_path)?;

        let initialization_lock = if allow_initialize {
            let bytes = lock_record(None);
            ensure_record_at(
                &root,
                &root_path,
                root_device,
                INIT_LOCK,
                &bytes,
                MetadataKind::Lock,
                PRIVATE_FILE_MODE,
            )?;
            let path = root_path.join(INIT_LOCK);
            let lock = open_regular_at(&root, INIT_LOCK, &path)?;
            validate_regular(&lock, &path, root_device, PRIVATE_FILE_MODE)?;
            validate_lock_record(
                &read_bounded(
                    lock.try_clone().map_err(|error| {
                        StoreError::io("clone initialization lock", &path, error)
                    })?,
                    &path,
                    MetadataKind::Lock,
                )?,
                None,
                &path,
            )?;
            lock.lock()
                .map_err(|error| StoreError::io("lock store initialization", &path, error))?;
            Some(lock)
        } else {
            None
        };

        let generations = if allow_initialize {
            ensure_private_dir(
                &root,
                "generations",
                &root_path.join("generations"),
                root_device,
            )?
        } else {
            open_and_validate_layout_dir(&root, &root_path, "generations", root_device)?
        };
        let derivations = if allow_initialize {
            ensure_private_dir(
                &root,
                "derivations",
                &root_path.join("derivations"),
                root_device,
            )?
        } else {
            open_and_validate_layout_dir(&root, &root_path, "derivations", root_device)?
        };
        let staging = if allow_initialize {
            ensure_private_dir(&root, "staging", &root_path.join("staging"), root_device)?
        } else {
            open_and_validate_layout_dir(&root, &root_path, "staging", root_device)?
        };
        let aliases = if allow_initialize {
            ensure_private_dir(&root, "aliases", &root_path.join("aliases"), root_device)?
        } else {
            open_and_validate_layout_dir(&root, &root_path, "aliases", root_device)?
        };
        let leases = if allow_initialize {
            ensure_private_dir(&root, "leases", &root_path.join("leases"), root_device)?
        } else {
            open_and_validate_layout_dir(&root, &root_path, "leases", root_device)?
        };
        let retained = if allow_initialize {
            ensure_private_dir(&root, "retained", &root_path.join("retained"), root_device)?
        } else {
            open_and_validate_layout_dir(&root, &root_path, "retained", root_device)?
        };
        let instances = if allow_initialize {
            ensure_private_dir(
                &root,
                "instances",
                &root_path.join("instances"),
                root_device,
            )?
        } else {
            open_and_validate_layout_dir(&root, &root_path, "instances", root_device)?
        };
        let locks = if allow_initialize {
            ensure_private_dir(&root, "locks", &root_path.join("locks"), root_device)?
        } else {
            open_and_validate_layout_dir(&root, &root_path, "locks", root_device)?
        };

        let store = Self {
            root_path,
            root,
            generations,
            derivations,
            staging,
            aliases,
            leases,
            retained,
            instances,
            locks,
            root_device,
            root_inode,
        };

        if allow_initialize {
            store.ensure_fixed_record(
                &store.root,
                STORE_METADATA,
                &store.store_header(),
                MetadataKind::Store,
                IMMUTABLE_FILE_MODE,
            )?;
            store.ensure_fixed_record(
                &store.root,
                ROOTS_LOCK,
                &lock_record(None),
                MetadataKind::Lock,
                PRIVATE_FILE_MODE,
            )?;
            store.root.sync_all().map_err(|error| {
                StoreError::io("sync initialized store root", &store.root_path, error)
            })?;
        }

        store.validate_store_header()?;
        store.validate_init_lock()?;
        store.validate_roots_lock()?;
        store.validate_root_identity()?;
        drop(initialization_lock);
        Ok(store)
    }

    #[must_use]
    pub fn root_path(&self) -> &Path {
        &self.root_path
    }

    /// Begin a non-blocking build transaction for the exact immutable inputs.
    ///
    /// A fully verified final generation already indexed by the derivation key
    /// is returned as a cache hit. Use [`Store::try_begin_rebuild`] when the
    /// caller deliberately needs to reproduce and compare the output.
    pub fn try_begin_generation(
        &self,
        spec: GenerationSpec,
    ) -> Result<BeginGeneration<'_>, StoreError> {
        self.try_begin_generation_inner(spec, false)
    }

    /// Begin a non-blocking rebuild even when this derivation already has a
    /// committed output. Rebuilds use the same per-derivation serialization
    /// lock and may publish a distinct final ID when their bytes differ.
    pub fn try_begin_rebuild(
        &self,
        spec: GenerationSpec,
    ) -> Result<GenerationTransaction<'_>, StoreError> {
        match self.try_begin_generation_inner(spec, true)? {
            BeginGeneration::Vacant(transaction) => Ok(transaction),
            BeginGeneration::Existing(_) => unreachable!("forced rebuild cannot be a cache hit"),
        }
    }

    fn try_begin_generation_inner(
        &self,
        spec: GenerationSpec,
        rebuild: bool,
    ) -> Result<BeginGeneration<'_>, StoreError> {
        self.validate_root_identity()?;
        let derivation_key = spec.derivation_key();
        let build_lock = self.open_derivation_lock(derivation_key)?;
        match build_lock.try_lock() {
            Ok(()) => {}
            Err(error) => {
                let error: io::Error = error.into();
                if error.kind() == io::ErrorKind::WouldBlock {
                    return Err(StoreError::DerivationBusy(derivation_key));
                }
                return Err(StoreError::io(
                    "lock generation derivation",
                    self.lock_path(derivation_key),
                    error,
                ));
            }
        }

        if !rebuild
            && let Some(generation) = self
                .generations_for_derivation_locked(derivation_key)?
                .into_iter()
                .next()
        {
            // Lease the cache hit before handing it back. The caller roots it
            // with an alias only afterwards, so an unleased return leaves a
            // window in which a concurrent collection may delete it.
            let id = generation.id();
            let lock = self.open_lease_lock(id)?;
            lock.lock_shared().map_err(|error| {
                StoreError::io(
                    "acquire shared generation lease",
                    self.lease_path(id),
                    error,
                )
            })?;
            match self.verify_generation(id) {
                Ok(generation) => {
                    return Ok(BeginGeneration::Existing(Lease { generation, lock }));
                }
                // Collected between the index read and the lease. Fall through
                // and rebuild rather than return something that is now gone.
                Err(StoreError::GenerationNotFound(_)) => {}
                Err(error) => return Err(error),
            }
        }

        let (stage_name, stage) = self.create_staging_directory(derivation_key)?;
        let stage_path = self.root_path.join("staging").join(&stage_name);
        let staging_record = StagingRecord { derivation_key };
        let metadata_path = stage_path.join(STAGING_METADATA);
        if let Err(error) = write_new_synced(
            &stage,
            STAGING_METADATA,
            &metadata_path,
            &staging_record.encode(),
            IMMUTABLE_FILE_MODE,
        ) {
            let _ = remove_tree_at(
                &self.staging,
                OsStr::new(&stage_name),
                &stage_path,
                self.root_device,
            );
            return Err(error);
        }
        stage
            .sync_all()
            .map_err(|error| StoreError::io("sync staging directory", &stage_path, error))?;

        Ok(BeginGeneration::Vacant(GenerationTransaction {
            store: self,
            spec,
            derivation_key,
            _build_lock: build_lock,
            stage_name,
            stage,
            generation_temp_name: None,
            clean_on_drop: true,
        }))
    }

    /// Return all verified immutable outputs for one derivation key with the
    /// current canonical winner first, followed by alternatives in final-ID
    /// order. The per-derivation lock prevents racing publication or GC.
    pub fn generations_for_derivation(
        &self,
        derivation_key: DerivationKey,
    ) -> Result<Vec<Generation>, StoreError> {
        self.validate_root_identity()?;
        let lock = self.open_derivation_lock(derivation_key)?;
        lock.lock_shared().map_err(|error| {
            StoreError::io(
                "lock derivation lookup",
                self.lock_path(derivation_key),
                error,
            )
        })?;
        self.generations_for_derivation_locked(derivation_key)
    }

    /// Fully validate a committed generation, including hashing the base image.
    pub fn verify_generation(&self, id: GenerationId) -> Result<Generation, StoreError> {
        self.verify_generation_with_directory_mode(id, IMMUTABLE_DIR_MODE)
    }

    fn verify_generation_with_directory_mode(
        &self,
        id: GenerationId,
        expected_directory_mode: u32,
    ) -> Result<Generation, StoreError> {
        self.validate_root_identity()?;
        let directory_path = self.generation_path(id);
        let directory = match open_dir_at(&self.generations, id.to_string(), &directory_path) {
            Ok(directory) => directory,
            Err(StoreError::Io { source, .. }) if source.kind() == io::ErrorKind::NotFound => {
                return Err(StoreError::GenerationNotFound(id));
            }
            Err(error) => return Err(error),
        };
        validate_directory(
            &directory,
            &directory_path,
            self.root_device,
            expected_directory_mode,
        )?;

        let mut entries = list_names(&directory, &directory_path)?;
        entries.sort();
        let metadata_path = self.generation_path(id).join(GENERATION_METADATA);
        let metadata_file = open_regular_at(&directory, GENERATION_METADATA, &metadata_path)?;
        validate_regular(
            &metadata_file,
            &metadata_path,
            self.root_device,
            IMMUTABLE_FILE_MODE,
        )?;
        let manifest = GenerationManifest::decode(
            &read_bounded(metadata_file, &metadata_path, MetadataKind::Generation)?,
            &metadata_path,
        )?;
        if manifest.id != id {
            return Err(StoreError::metadata(
                MetadataKind::Generation,
                &metadata_path,
                "manifest ID does not match generation directory",
            ));
        }

        let mut expected = vec![
            OsStr::new(BASE_IMAGE).to_os_string(),
            OsStr::new(GENERATION_METADATA).to_os_string(),
            OsStr::new(STAGING_METADATA).to_os_string(),
        ];
        expected.extend(
            manifest
                .sidecars
                .iter()
                .map(|sidecar| OsStr::new(sidecar.name()).to_os_string()),
        );
        expected.sort();
        if entries != expected {
            return Err(StoreError::UnexpectedEntry {
                path: directory_path,
            });
        }

        let stage_metadata_path = self.generation_path(id).join(STAGING_METADATA);
        let stage_file = open_regular_at(&directory, STAGING_METADATA, &stage_metadata_path)?;
        validate_regular(
            &stage_file,
            &stage_metadata_path,
            self.root_device,
            IMMUTABLE_FILE_MODE,
        )?;
        let stage_record = StagingRecord::decode(
            &read_bounded(stage_file, &stage_metadata_path, MetadataKind::Staging)?,
            &stage_metadata_path,
        )?;
        if stage_record.derivation_key != manifest.derivation_key {
            return Err(StoreError::metadata(
                MetadataKind::Staging,
                &stage_metadata_path,
                "staging derivation key does not match generation manifest",
            ));
        }

        let base_path = self.generation_path(id).join(BASE_IMAGE);
        let base = open_regular_at(&directory, BASE_IMAGE, &base_path)?;
        let metadata = validate_regular(&base, &base_path, self.root_device, IMMUTABLE_FILE_MODE)?;
        if metadata.len() != manifest.base_size {
            return Err(StoreError::SizeMismatch {
                path: base_path,
                expected: manifest.base_size,
                actual: metadata.len(),
            });
        }
        let (observed_digest, observed_size) = hash_file(&base, &base_path)?;
        if observed_size != manifest.base_size {
            return Err(StoreError::SizeMismatch {
                path: base_path,
                expected: manifest.base_size,
                actual: observed_size,
            });
        }
        if observed_digest != manifest.base_digest {
            return Err(StoreError::DigestMismatch {
                path: base_path,
                expected: manifest.base_digest,
                actual: observed_digest,
            });
        }

        for sidecar in &manifest.sidecars {
            let path = self.generation_path(id).join(sidecar.name());
            let file = open_regular_at(&directory, sidecar.name(), &path)?;
            let metadata = validate_regular(&file, &path, self.root_device, IMMUTABLE_FILE_MODE)?;
            if metadata.len() != sidecar.size() {
                return Err(StoreError::SizeMismatch {
                    path,
                    expected: sidecar.size(),
                    actual: metadata.len(),
                });
            }
            let (digest, size) = hash_file(&file, &path)?;
            if size != sidecar.size() {
                return Err(StoreError::SizeMismatch {
                    path,
                    expected: sidecar.size(),
                    actual: size,
                });
            }
            if digest != sidecar.digest() {
                return Err(StoreError::DigestMismatch {
                    path,
                    expected: sidecar.digest(),
                    actual: digest,
                });
            }
        }

        Ok(Generation {
            manifest,
            directory_path,
            directory,
            base_path,
            base,
            root_device: self.root_device,
        })
    }

    /// Acquire a shared, crash-released lock and then verify the generation.
    pub fn acquire_lease(&self, id: GenerationId) -> Result<Lease, StoreError> {
        self.validate_root_identity()?;
        self.acquire_lease_inner(id)
    }

    fn acquire_lease_inner(&self, id: GenerationId) -> Result<Lease, StoreError> {
        let lock = self.open_lease_lock(id)?;
        lock.lock_shared().map_err(|error| {
            StoreError::io(
                "acquire shared generation lease",
                self.lease_path(id),
                error,
            )
        })?;
        let generation = self.verify_generation(id)?;
        Ok(Lease { generation, lock })
    }

    /// Atomically create or move one exact profile-qualified mutable alias.
    pub fn set_alias(&self, key: &AliasKey, generation_id: GenerationId) -> Result<(), StoreError> {
        self.validate_root_identity()?;
        let roots_lock = self.lock_roots_exclusive()?;
        let generation = self.verify_generation(generation_id)?;
        validate_alias_target(key, &generation)?;
        let id = key.id();
        match self.read_alias(id) {
            Ok(record) if record.key != *key => {
                return Err(StoreError::metadata(
                    MetadataKind::Alias,
                    self.alias_path(id),
                    "alias filename collides with a different canonical key",
                ));
            }
            Ok(_) | Err(StoreError::AliasNotFound) => {}
            Err(error) => return Err(error),
        }

        let record = AliasRecord::new(key.clone(), generation_id);
        let final_name = alias_filename(id);
        let final_path = self.alias_path(id);
        let temp_name = format!(".tmp-alias-{}", unique_suffix());
        let temp_path = self.root_path.join("aliases").join(&temp_name);
        write_new_synced(
            &self.aliases,
            &temp_name,
            &temp_path,
            &record.encode(),
            IMMUTABLE_FILE_MODE,
        )?;
        if let Err(error) = rename_replace_at(
            &self.aliases,
            &temp_name,
            &self.aliases,
            &final_name,
            &final_path,
        ) {
            let _ = unlink_file_at(&self.aliases, &temp_name, &temp_path);
            return Err(error);
        }
        self.aliases
            .sync_all()
            .map_err(|error| StoreError::io("sync alias replacement", &final_path, error))?;
        drop(roots_lock);
        Ok(())
    }

    /// Return a locked lease for an alias target without a GC race.
    pub fn lease_alias(&self, key: &AliasKey) -> Result<Lease, StoreError> {
        self.validate_root_identity()?;
        let roots_lock = self.lock_roots_shared()?;
        let record = self.read_alias(key.id())?;
        if record.key != *key {
            return Err(StoreError::metadata(
                MetadataKind::Alias,
                self.alias_path(key.id()),
                "alias key does not match requested key",
            ));
        }
        let lease = self.acquire_lease_inner(record.generation_id)?;
        validate_alias_target(key, lease.generation())?;
        drop(roots_lock);
        Ok(lease)
    }

    /// Read an alias target as a snapshot. Use [`Store::lease_alias`] for runs.
    pub fn alias_target(&self, key: &AliasKey) -> Result<GenerationId, StoreError> {
        self.validate_root_identity()?;
        let roots_lock = self.lock_roots_shared()?;
        let record = self.read_alias(key.id())?;
        if record.key != *key {
            return Err(StoreError::metadata(
                MetadataKind::Alias,
                self.alias_path(key.id()),
                "alias key does not match requested key",
            ));
        }
        let generation = self.verify_generation(record.generation_id)?;
        validate_alias_target(key, &generation)?;
        let target = record.generation_id;
        drop(roots_lock);
        Ok(target)
    }

    /// Every alias root in the store, in canonical ID order.
    ///
    /// Aliases are the only thing that keeps a generation alive across a
    /// collection, and an alias outlives the profile that created it. Without
    /// a way to see them, a resealed profile's aliases root their generations
    /// forever and `garbage_collect` can never reclaim the space.
    pub fn alias_roots(&self) -> Result<Vec<AliasRoot>, StoreError> {
        self.validate_root_identity()?;
        let roots_lock = self.lock_roots_shared()?;
        let mut roots = Vec::new();
        for name in list_names(&self.aliases, &self.root_path.join("aliases"))? {
            let path = self.root_path.join("aliases").join(&name);
            let Some(text) = name.to_str() else {
                return Err(StoreError::metadata(
                    MetadataKind::Alias,
                    path,
                    "non-UTF-8 alias entry",
                ));
            };
            if text.starts_with(".tmp-alias-") {
                continue;
            }
            let Some(id) = parse_alias_filename(text) else {
                return Err(StoreError::metadata(
                    MetadataKind::Alias,
                    path,
                    "unknown alias entry",
                ));
            };
            let record = self.read_alias(id)?;
            roots.push(AliasRoot {
                id: record.id,
                profile_id: record.key.profile_id().to_owned(),
                reference: record.key.reference().to_owned(),
                platform: record.key.requested_platform().canonical_text(),
                selector_policy_id: record.key.selector_policy_id().to_owned(),
                generation_id: record.generation_id,
            });
        }
        drop(roots_lock);
        roots.sort_by_key(|root| root.id);
        Ok(roots)
    }

    /// Remove one alias named by its own ID.
    ///
    /// Reconstructing an `AliasKey` needs the profile bundle that created it,
    /// which is exactly what is gone once a profile has been resealed. The
    /// record's ID is derived from its key and checked against the filename on
    /// read, so it names the alias just as exactly.
    pub fn remove_alias_by_id(&self, id: AliasId) -> Result<bool, StoreError> {
        self.validate_root_identity()?;
        let roots_lock = self.lock_roots_exclusive()?;
        let removed = match self.read_alias(id) {
            Ok(_) => {
                let name = alias_filename(id);
                unlink_file_at(&self.aliases, &name, &self.alias_path(id))?;
                self.aliases.sync_all().map_err(|error| {
                    StoreError::io("sync alias removal", self.alias_path(id), error)
                })?;
                true
            }
            Err(StoreError::AliasNotFound) => false,
            Err(error) => return Err(error),
        };
        drop(roots_lock);
        Ok(removed)
    }

    /// Atomically remove one alias after verifying its canonical record.
    pub fn remove_alias(&self, key: &AliasKey) -> Result<(), StoreError> {
        self.validate_root_identity()?;
        let roots_lock = self.lock_roots_exclusive()?;
        let id = key.id();
        let record = self.read_alias(id)?;
        if record.key != *key {
            return Err(StoreError::metadata(
                MetadataKind::Alias,
                self.alias_path(id),
                "alias key does not match requested key",
            ));
        }
        let name = alias_filename(id);
        unlink_file_at(&self.aliases, &name, &self.alias_path(id))?;
        self.aliases
            .sync_all()
            .map_err(|error| StoreError::io("sync alias removal", self.alias_path(id), error))?;
        drop(roots_lock);
        Ok(())
    }

    /// Persist a retained COW as a root before the run lease is released.
    ///
    /// The COW must already be quiescent. The complete logical file is hashed,
    /// so a sparse file can be expensive to register.
    pub fn register_retained_cow(
        &self,
        lease: &Lease,
        cow_path: ManagedUmlPath,
        expected_digest: Digest,
        state: RetainedCowState,
    ) -> Result<RetainedCow, StoreError> {
        self.validate_root_identity()?;
        let cow_file = open_absolute_regular_no_symlinks(cow_path.as_path())?;
        let metadata = cow_file
            .metadata()
            .map_err(|error| StoreError::io("stat retained COW", cow_path.as_path(), error))?;
        if !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.uid() != nix::unistd::geteuid().as_raw()
            || metadata.mode() & 0o7777 != PRIVATE_FILE_MODE
        {
            return Err(StoreError::UnexpectedEntry {
                path: cow_path.as_path().to_path_buf(),
            });
        }
        let (observed_digest, cow_size) = hash_file(&cow_file, cow_path.as_path())?;
        if observed_digest != expected_digest {
            return Err(StoreError::DigestMismatch {
                path: cow_path.as_path().to_path_buf(),
                expected: expected_digest,
                actual: observed_digest,
            });
        }

        let generation_id = lease.id();
        let id = RetainedCow::derive_id(generation_id, &cow_path, observed_digest, cow_size, state);
        let retained = RetainedCow {
            id,
            generation_id,
            cow_path,
            cow_digest: observed_digest,
            cow_size,
            state,
        };

        let roots_lock = self.lock_roots_exclusive()?;
        let _generation = self.verify_generation(generation_id)?;
        let final_name = retained_filename(id);
        let final_path = self.retained_path(id);
        match self.read_retained(id) {
            Ok(existing) if existing == retained => return Ok(existing),
            Ok(_) => {
                return Err(StoreError::metadata(
                    MetadataKind::RetainedCow,
                    &final_path,
                    "retained-COW ID collides with a different record",
                ));
            }
            Err(StoreError::RetainedCowNotFound) => {}
            Err(error) => return Err(error),
        }
        let temp_name = format!(".tmp-retained-{}", unique_suffix());
        let temp_path = self.root_path.join("retained").join(&temp_name);
        write_new_synced(
            &self.retained,
            &temp_name,
            &temp_path,
            &retained.encode(),
            IMMUTABLE_FILE_MODE,
        )?;
        match rename_noreplace_at(
            &self.retained,
            &temp_name,
            &self.retained,
            &final_name,
            &final_path,
        ) {
            Ok(()) => {}
            Err(error) if io_error_is(&error, io::ErrorKind::AlreadyExists) => {
                let _ = unlink_file_at(&self.retained, &temp_name, &temp_path);
                let existing = self.read_retained(id)?;
                if existing != retained {
                    return Err(StoreError::metadata(
                        MetadataKind::RetainedCow,
                        &final_path,
                        "concurrent retained-COW record differs",
                    ));
                }
                return Ok(existing);
            }
            Err(error) => {
                let _ = unlink_file_at(&self.retained, &temp_name, &temp_path);
                return Err(error);
            }
        }
        self.retained
            .sync_all()
            .map_err(|error| StoreError::io("sync retained-COW publication", &final_path, error))?;
        drop(roots_lock);
        Ok(retained)
    }

    /// The directory an instance's COW is written into, created empty.
    ///
    /// A retained run writes its COW here from the start rather than being
    /// moved on exit: the store is the durable half of the pair, and copying a
    /// multi-gigabyte sparse file between filesystems at teardown would be a
    /// cost paid on every run for the benefit of the ones that are kept.
    pub fn create_instance_directory(&self, name: &str) -> Result<PathBuf, StoreError> {
        validate_instance_name(name)?;
        self.validate_root_identity()?;
        let id = Instance::derive_id(name);
        let directory = instance_directory_name(id);
        let path = self.root_path.join("instances").join(&directory);
        // The directory is reserved before the run starts, so a name already
        // in use collides here rather than when the record is written. Say so
        // in the operator's terms: they typed a name, not a path.
        match create_private_dir(&self.instances, &directory, &path, self.root_device) {
            Ok(_) => {}
            Err(StoreError::Io { source, .. }) if source.kind() == io::ErrorKind::AlreadyExists => {
                return Err(StoreError::metadata(
                    MetadataKind::Instance,
                    &path,
                    format!("an instance named {name} already exists"),
                ));
            }
            Err(error) => return Err(error),
        }
        Ok(path)
    }

    /// The directory an existing instance's overlay lives in.
    ///
    /// Unlike `create_instance_directory` this makes nothing: a resume works
    /// on the overlay that is already there, and a name with no directory is a
    /// caller resuming something that does not exist.
    pub fn instance_directory(&self, name: &str) -> Result<PathBuf, StoreError> {
        validate_instance_name(name)?;
        self.validate_root_identity()?;
        let id = Instance::derive_id(name);
        let path = self
            .root_path
            .join("instances")
            .join(instance_directory_name(id));
        if !path.is_dir() {
            return Err(StoreError::InstanceNotFound);
        }
        Ok(path)
    }

    /// Remove an instance directory that never became an instance.
    ///
    /// Refuses once a record exists for the name. A caller cleaning up after
    /// its own failed run cannot always tell whether it created the directory
    /// or collided with somebody else's instance, and the difference is a
    /// deleted overlay, so the store decides rather than the caller: a
    /// directory with a published record belongs to that instance and is
    /// removed only by `remove_instance`.
    pub fn discard_instance_directory(&self, name: &str) -> Result<(), StoreError> {
        validate_instance_name(name)?;
        let id = Instance::derive_id(name);
        match self.read_instance(id) {
            Err(StoreError::InstanceNotFound) => {}
            Ok(_) => {
                return Err(StoreError::metadata(
                    MetadataKind::Instance,
                    self.instance_path(id),
                    format!("{name} is a published instance; remove it instead of discarding it"),
                ));
            }
            Err(error) => return Err(error),
        }
        let directory = instance_directory_name(id);
        let path = self.root_path.join("instances").join(&directory);
        remove_tree_at(
            &self.instances,
            std::ffi::OsStr::new(&directory),
            &path,
            self.root_device,
        )
    }

    /// Publish one finished run as a named instance.
    ///
    /// The caller has already registered the retained COW, so the generation
    /// is rooted before this record exists: a crash between the two leaves a
    /// root with no name, which wastes space but never loses a base an
    /// instance still needs.
    #[allow(clippy::too_many_arguments)]
    pub fn create_instance(
        &self,
        name: &str,
        generation_id: GenerationId,
        retained_id: RetainedCowId,
        image_reference: &str,
        argv: &[String],
        command: &str,
        created_unix: u64,
        finished_unix: u64,
        outcome: InstanceOutcome,
    ) -> Result<Instance, StoreError> {
        validate_instance_name(name)?;
        if argv.len() > MAX_INSTANCE_ARGV {
            return Err(StoreError::metadata(
                MetadataKind::Instance,
                "<memory>",
                format!("recorded argv exceeds {MAX_INSTANCE_ARGV} arguments"),
            ));
        }
        if image_reference.len() > MAX_INSTANCE_COMMAND_BYTES
            || command.len() > MAX_INSTANCE_COMMAND_BYTES
        {
            return Err(StoreError::metadata(
                MetadataKind::Instance,
                "<memory>",
                "recorded reference or command is too long",
            ));
        }
        self.validate_root_identity()?;
        let instance = Instance {
            id: Instance::derive_id(name),
            name: name.to_owned(),
            generation_id,
            retained_id,
            image_reference: image_reference.to_owned(),
            argv: argv.to_vec(),
            command: command.to_owned(),
            created_unix,
            finished_unix,
            outcome,
        };
        let roots_lock = self.lock_roots_exclusive()?;
        let final_name = instance_filename(instance.id);
        let final_path = self.instance_path(instance.id);
        let temp_name = format!(".tmp-instance-{}", unique_suffix());
        let temp_path = self.root_path.join("instances").join(&temp_name);
        write_new_synced(
            &self.instances,
            &temp_name,
            &temp_path,
            &instance.encode(),
            IMMUTABLE_FILE_MODE,
        )?;
        match rename_noreplace_at(
            &self.instances,
            &temp_name,
            &self.instances,
            &final_name,
            &final_path,
        ) {
            Ok(()) => {}
            Err(error) if io_error_is(&error, io::ErrorKind::AlreadyExists) => {
                let _ = unlink_file_at(&self.instances, &temp_name, &temp_path);
                return Err(StoreError::metadata(
                    MetadataKind::Instance,
                    &final_path,
                    format!("an instance named {name} already exists"),
                ));
            }
            Err(error) => {
                let _ = unlink_file_at(&self.instances, &temp_name, &temp_path);
                return Err(error);
            }
        }
        self.instances
            .sync_all()
            .map_err(|error| StoreError::io("sync instance publication", &final_path, error))?;
        drop(roots_lock);
        Ok(instance)
    }

    /// Replace an instance record in place, for a run that resumed it.
    ///
    /// A resume writes through the same overlay, so its digest changes and the
    /// retained-COW record that named the old one no longer describes it. The
    /// caller registers the new root first and passes it here; the old root is
    /// released only once this record no longer points at it, so a crash
    /// between the two leaves reclaimable space rather than an instance whose
    /// backing image can be collected.
    pub fn update_instance(
        &self,
        name: &str,
        retained_id: RetainedCowId,
        finished_unix: u64,
        outcome: InstanceOutcome,
    ) -> Result<Instance, StoreError> {
        validate_instance_name(name)?;
        self.validate_root_identity()?;
        let id = Instance::derive_id(name);
        let roots_lock = self.lock_roots_exclusive()?;
        let previous = self.read_instance(id)?;
        let updated = Instance {
            retained_id,
            finished_unix,
            outcome,
            ..previous
        };
        let final_name = instance_filename(id);
        let final_path = self.instance_path(id);
        let temp_name = format!(".tmp-instance-{}", unique_suffix());
        let temp_path = self.root_path.join("instances").join(&temp_name);
        write_new_synced(
            &self.instances,
            &temp_name,
            &temp_path,
            &updated.encode(),
            IMMUTABLE_FILE_MODE,
        )?;
        rename_replace_at(
            &self.instances,
            &temp_name,
            &self.instances,
            &final_name,
            &final_path,
        )?;
        self.instances
            .sync_all()
            .map_err(|error| StoreError::io("sync instance update", &final_path, error))?;
        drop(roots_lock);
        Ok(updated)
    }

    /// Read one instance by the name an operator typed.
    pub fn instance(&self, name: &str) -> Result<Instance, StoreError> {
        validate_instance_name(name)?;
        self.validate_root_identity()?;
        let roots_lock = self.lock_roots_shared()?;
        let instance = self.read_instance(Instance::derive_id(name))?;
        drop(roots_lock);
        Ok(instance)
    }

    /// Every instance the store holds, ordered by name.
    ///
    /// A record that cannot be read is reported rather than skipped: a listing
    /// that silently omits an instance would show an operator an incomplete
    /// picture of what is occupying their disk.
    pub fn instances(&self) -> Result<Vec<Instance>, StoreError> {
        self.validate_root_identity()?;
        let roots_lock = self.lock_roots_shared()?;
        let mut found = Vec::new();
        for entry in list_names(&self.instances, &self.root_path.join("instances"))? {
            let Some(name) = entry.to_str() else {
                continue;
            };
            let Some(id_text) = name.strip_suffix(".meta") else {
                continue;
            };
            let Some(id) = InstanceId::parse_filename(id_text) else {
                continue;
            };
            found.push(self.read_instance(id)?);
        }
        drop(roots_lock);
        found.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(found)
    }

    /// Remove one instance and the COW directory it owns.
    ///
    /// The retained-COW root goes first: dropping the name while the root
    /// survives leaves reclaimable space, whereas dropping the root while the
    /// name survives leaves an instance whose base can be collected.
    pub fn remove_instance(&self, name: &str) -> Result<Instance, StoreError> {
        validate_instance_name(name)?;
        self.validate_root_identity()?;
        let id = Instance::derive_id(name);
        let instance = {
            let roots_lock = self.lock_roots_shared()?;
            let instance = self.read_instance(id)?;
            drop(roots_lock);
            instance
        };
        match self.remove_retained_cow(instance.retained_id) {
            Ok(_) | Err(StoreError::RetainedCowNotFound) => {}
            Err(error) => return Err(error),
        }
        let roots_lock = self.lock_roots_exclusive()?;
        let file_name = instance_filename(id);
        let file_path = self.instance_path(id);
        unlink_file_at(&self.instances, &file_name, &file_path)?;
        let directory = instance_directory_name(id);
        let directory_path = self.root_path.join("instances").join(&directory);
        let _ = remove_tree_at(
            &self.instances,
            std::ffi::OsStr::new(&directory),
            &directory_path,
            self.root_device,
        );
        self.instances
            .sync_all()
            .map_err(|error| StoreError::io("sync instance removal", &file_path, error))?;
        drop(roots_lock);
        Ok(instance)
    }

    fn read_instance(&self, id: InstanceId) -> Result<Instance, StoreError> {
        let path = self.instance_path(id);
        let name = instance_filename(id);
        let file = match open_regular_at(&self.instances, &name, &path) {
            Ok(file) => file,
            Err(StoreError::Io { source, .. }) if source.kind() == io::ErrorKind::NotFound => {
                return Err(StoreError::InstanceNotFound);
            }
            Err(error) => return Err(error),
        };
        validate_regular(&file, &path, self.root_device, IMMUTABLE_FILE_MODE)?;
        let bytes = read_bounded(file, &path, MetadataKind::Instance)?;
        Instance::decode(&bytes, &path)
    }

    fn instance_path(&self, id: InstanceId) -> PathBuf {
        self.root_path.join("instances").join(instance_filename(id))
    }

    /// Read and checksum a retained-COW record. This does not hash its COW file.
    pub fn retained_cow(&self, id: RetainedCowId) -> Result<RetainedCow, StoreError> {
        self.validate_root_identity()?;
        let roots_lock = self.lock_roots_shared()?;
        let retained = self.read_retained(id)?;
        drop(roots_lock);
        Ok(retained)
    }

    /// Verify a retained COW and acquire its backing-generation lease without a
    /// GC race. Callers resuming a retained root should use this method.
    pub fn lease_retained_cow(&self, id: RetainedCowId) -> Result<RetainedCowLease, StoreError> {
        self.validate_root_identity()?;
        let roots_lock = self.lock_roots_shared()?;
        let retained = self.read_retained(id)?;
        let cow = open_absolute_regular_no_symlinks(retained.cow_path.as_path())?;
        let metadata = cow.metadata().map_err(|error| {
            StoreError::io("stat retained COW", retained.cow_path.as_path(), error)
        })?;
        if !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.uid() != nix::unistd::geteuid().as_raw()
            || metadata.mode() & 0o7777 != PRIVATE_FILE_MODE
        {
            return Err(StoreError::UnexpectedEntry {
                path: retained.cow_path.as_path().to_path_buf(),
            });
        }
        let (observed_digest, observed_size) = hash_file(&cow, retained.cow_path.as_path())?;
        if observed_size != retained.cow_size {
            return Err(StoreError::SizeMismatch {
                path: retained.cow_path.as_path().to_path_buf(),
                expected: retained.cow_size,
                actual: observed_size,
            });
        }
        if observed_digest != retained.cow_digest {
            return Err(StoreError::DigestMismatch {
                path: retained.cow_path.as_path().to_path_buf(),
                expected: retained.cow_digest,
                actual: observed_digest,
            });
        }
        let generation_lease = self.acquire_lease_inner(retained.generation_id)?;
        drop(roots_lock);
        Ok(RetainedCowLease {
            retained,
            generation_lease,
            cow,
        })
    }

    /// Remove a durable retained-COW root. This never deletes the COW itself.
    pub fn remove_retained_cow(&self, id: RetainedCowId) -> Result<RetainedCow, StoreError> {
        self.validate_root_identity()?;
        let roots_lock = self.lock_roots_exclusive()?;
        let retained = self.read_retained(id)?;
        let name = retained_filename(id);
        unlink_file_at(&self.retained, &name, &self.retained_path(id))?;
        self.retained.sync_all().map_err(|error| {
            StoreError::io("sync retained-COW removal", self.retained_path(id), error)
        })?;
        drop(roots_lock);
        Ok(retained)
    }

    /// Remove abandoned canonical staging/publication-temp directories and
    /// atomic-record remnants. Active per-derivation build locks make their
    /// transaction directories ineligible.
    pub fn recover(&self) -> Result<RecoveryReport, StoreError> {
        self.validate_root_identity()?;
        let roots_lock = self.lock_roots_exclusive()?;
        let mut report = RecoveryReport::default();

        self.recover_interrupted_publications(&mut report)?;

        for name in list_names(&self.staging, &self.root_path.join("staging"))? {
            let path = self.root_path.join("staging").join(&name);
            let Some(name_text) = name.to_str() else {
                report.blocked_entries.push(path);
                continue;
            };
            let Some(filename_key) = parse_staging_name(name_text) else {
                report.blocked_entries.push(path);
                continue;
            };
            let stage = match open_dir_at(&self.staging, &name, &path) {
                Ok(stage) => stage,
                Err(_) => {
                    report.blocked_entries.push(path);
                    continue;
                }
            };
            let metadata = stage
                .metadata()
                .map_err(|error| StoreError::io("stat recovery staging", &path, error))?;
            if metadata.dev() != self.root_device
                || metadata.uid() != nix::unistd::geteuid().as_raw()
                || !matches!(
                    metadata.mode() & 0o7777,
                    PRIVATE_DIR_MODE | IMMUTABLE_DIR_MODE
                )
            {
                report.blocked_entries.push(path);
                continue;
            }
            let metadata_path = path.join(STAGING_METADATA);
            let stage_record = match open_regular_at(&stage, STAGING_METADATA, &metadata_path)
                .and_then(|file| {
                    let file_metadata = file.metadata().map_err(|error| {
                        StoreError::io("stat staging metadata", &metadata_path, error)
                    })?;
                    if file_metadata.dev() != self.root_device
                        || file_metadata.uid() != nix::unistd::geteuid().as_raw()
                        || file_metadata.mode() & 0o7777 != IMMUTABLE_FILE_MODE
                        || !file_metadata.is_file()
                        || file_metadata.nlink() != 1
                    {
                        return Err(StoreError::UnexpectedEntry {
                            path: metadata_path.clone(),
                        });
                    }
                    StagingRecord::decode(
                        &read_bounded(file, &metadata_path, MetadataKind::Staging)?,
                        &metadata_path,
                    )
                }) {
                Ok(record) if record.derivation_key == filename_key => record,
                Ok(_) | Err(_) => {
                    report.blocked_entries.push(path);
                    continue;
                }
            };
            let lock = self.open_derivation_lock(stage_record.derivation_key)?;
            match lock.try_lock() {
                Ok(()) => {}
                Err(error) => {
                    let error: io::Error = error.into();
                    if error.kind() == io::ErrorKind::WouldBlock {
                        report.busy_staging.push(path);
                        continue;
                    }
                    return Err(StoreError::io(
                        "lock generation during recovery",
                        self.lock_path(stage_record.derivation_key),
                        error,
                    ));
                }
            }
            remove_tree_at(&self.staging, &name, &path, self.root_device)?;
            report.removed_staging.push(path);
        }

        self.recover_atomic_temps(&self.aliases, "aliases", ".tmp-alias-", &mut report)?;
        self.recover_atomic_temps(
            &self.derivations,
            "derivations",
            ".tmp-derivation-",
            &mut report,
        )?;
        self.recover_atomic_temps(&self.retained, "retained", ".tmp-retained-", &mut report)?;
        self.recover_atomic_temps(&self.root, "", FIXED_TEMP_PREFIX, &mut report)?;
        self.recover_atomic_temps(&self.locks, "locks", FIXED_TEMP_PREFIX, &mut report)?;
        self.recover_atomic_temps(&self.leases, "leases", FIXED_TEMP_PREFIX, &mut report)?;

        drop(roots_lock);
        Ok(report)
    }

    fn recover_interrupted_publications(
        &self,
        report: &mut RecoveryReport,
    ) -> Result<(), StoreError> {
        let generations_path = self.root_path.join("generations");
        for name in list_names(&self.generations, &generations_path)? {
            let path = generations_path.join(&name);
            let Some(text) = name.to_str() else {
                report.blocked_entries.push(path);
                continue;
            };
            if let Some(filename_key) = parse_generation_temp_name(text) {
                let directory = match open_dir_at(&self.generations, &name, &path) {
                    Ok(directory) => directory,
                    Err(_) => {
                        report.blocked_entries.push(path);
                        continue;
                    }
                };
                let metadata = directory.metadata().map_err(|error| {
                    StoreError::io("stat publication temporary directory", &path, error)
                })?;
                if metadata.dev() != self.root_device
                    || metadata.uid() != nix::unistd::geteuid().as_raw()
                    || !matches!(
                        metadata.mode() & 0o7777,
                        PRIVATE_DIR_MODE | IMMUTABLE_DIR_MODE
                    )
                {
                    report.blocked_entries.push(path);
                    continue;
                }

                let staging_path = path.join(STAGING_METADATA);
                let stage_record = match open_regular_at(
                    &directory,
                    STAGING_METADATA,
                    &staging_path,
                )
                .and_then(|file| {
                    validate_regular(&file, &staging_path, self.root_device, IMMUTABLE_FILE_MODE)?;
                    StagingRecord::decode(
                        &read_bounded(file, &staging_path, MetadataKind::Staging)?,
                        &staging_path,
                    )
                }) {
                    Ok(record) if record.derivation_key == filename_key => record,
                    Ok(_) | Err(_) => {
                        report.blocked_entries.push(path);
                        continue;
                    }
                };

                let derivation_lock = self.open_derivation_lock(stage_record.derivation_key)?;
                match derivation_lock.try_lock() {
                    Ok(()) => {}
                    Err(error) => {
                        let error: io::Error = error.into();
                        if error.kind() == io::ErrorKind::WouldBlock {
                            report.busy_staging.push(path);
                            continue;
                        }
                        return Err(StoreError::io(
                            "lock publication temporary directory during recovery",
                            self.lock_path(stage_record.derivation_key),
                            error,
                        ));
                    }
                }
                remove_tree_at(&self.generations, &name, &path, self.root_device)?;
                report.removed_staging.push(path);
                continue;
            }
            let Some(id) = GenerationId::parse_filename(text) else {
                report.blocked_entries.push(path);
                continue;
            };
            let directory = match open_dir_at(&self.generations, &name, &path) {
                Ok(directory) => directory,
                Err(_) => {
                    report.blocked_entries.push(path);
                    continue;
                }
            };
            let metadata = directory
                .metadata()
                .map_err(|error| StoreError::io("stat interrupted publication", &path, error))?;
            let mode = metadata.mode() & 0o7777;
            if !matches!(mode, PRIVATE_DIR_MODE | IMMUTABLE_DIR_MODE)
                || metadata.dev() != self.root_device
                || metadata.uid() != nix::unistd::geteuid().as_raw()
            {
                report.blocked_entries.push(path);
                continue;
            }

            let staging_path = path.join(STAGING_METADATA);
            let stage_record = match open_regular_at(&directory, STAGING_METADATA, &staging_path)
                .and_then(|file| {
                    validate_regular(&file, &staging_path, self.root_device, IMMUTABLE_FILE_MODE)?;
                    StagingRecord::decode(
                        &read_bounded(file, &staging_path, MetadataKind::Staging)?,
                        &staging_path,
                    )
                }) {
                Ok(record) => record,
                Err(_) => {
                    report.blocked_entries.push(path);
                    continue;
                }
            };

            let derivation_lock = self.open_derivation_lock(stage_record.derivation_key)?;
            match derivation_lock.try_lock() {
                Ok(()) => {}
                Err(error) => {
                    let error: io::Error = error.into();
                    if error.kind() == io::ErrorKind::WouldBlock {
                        report.busy_publications.push(id);
                        continue;
                    }
                    return Err(StoreError::io(
                        "lock interrupted publication",
                        self.lock_path(stage_record.derivation_key),
                        error,
                    ));
                }
            }

            let expected_mode = mode;
            let generation = match self.verify_generation_with_directory_mode(id, expected_mode) {
                Ok(generation) => generation,
                Err(_) => {
                    report.blocked_entries.push(path);
                    continue;
                }
            };
            if generation.manifest.derivation_key != stage_record.derivation_key {
                report.blocked_entries.push(path);
                continue;
            }
            if mode == PRIVATE_DIR_MODE {
                set_mode(&directory, IMMUTABLE_DIR_MODE, &path)?;
                directory.sync_all().map_err(|error| {
                    StoreError::io("sync recovered generation permissions", &path, error)
                })?;
                self.generations.sync_all().map_err(|error| {
                    StoreError::io("sync recovered generation publication", &path, error)
                })?;
                report.completed_publications.push(id);
            }
            self.verify_generation(id)?;
            self.update_derivation_index(stage_record.derivation_key, id)?;
        }
        Ok(())
    }

    /// Collect only verified generations unreachable from every root.
    ///
    /// Any corrupt alias or retained-COW metadata aborts before deletion. A
    /// corrupt but unrooted generation is reported and preserved for diagnosis.
    pub fn garbage_collect(&self) -> Result<GarbageCollectionReport, StoreError> {
        self.validate_root_identity()?;
        let roots_lock = self.lock_roots_exclusive()?;
        let roots = self.collect_gc_roots()?;
        let mut report = GarbageCollectionReport::default();
        let mut candidates = Vec::new();
        for name in list_names(&self.generations, &self.root_path.join("generations"))? {
            let Some(text) = name.to_str() else {
                return Err(StoreError::UnsafeGarbageCollection(format!(
                    "non-UTF-8 generation entry at {}",
                    self.root_path.join("generations").join(name).display()
                )));
            };
            let Some(id) = GenerationId::parse_filename(text) else {
                // `publish` briefly exposes a publication-temp name inside
                // `generations` while it renames a fully flushed staging
                // directory into place. A concurrent publication is an
                // in-flight write, not corruption, so record it and continue
                // rather than aborting the whole collection.
                if parse_generation_temp_name(text).is_some() {
                    report.publication_in_flight.push(text.to_owned());
                    continue;
                }
                return Err(StoreError::UnsafeGarbageCollection(format!(
                    "unknown generation entry {text:?}"
                )));
            };
            candidates.push(id);
        }
        candidates.sort();
        report.publication_in_flight.sort();

        for id in candidates {
            if roots.contains(&id) {
                report.rooted.push(id);
                continue;
            }

            let lease_lock = self.open_lease_lock(id)?;
            match lease_lock.try_lock() {
                Ok(()) => {}
                Err(error) => {
                    let error: io::Error = error.into();
                    if error.kind() == io::ErrorKind::WouldBlock {
                        report.leased_or_busy.push(id);
                        continue;
                    }
                    return Err(StoreError::io(
                        "test generation lease for GC",
                        self.lease_path(id),
                        error,
                    ));
                }
            }
            let generation = match self.verify_generation(id) {
                Ok(generation) => generation,
                Err(_) => {
                    report.corrupt_unrooted.push(id);
                    continue;
                }
            };
            let derivation_key = generation.manifest.derivation_key;
            let derivation_lock = self.open_derivation_lock(derivation_key)?;
            match derivation_lock.try_lock() {
                Ok(()) => {}
                Err(error) => {
                    let error: io::Error = error.into();
                    if error.kind() == io::ErrorKind::WouldBlock {
                        report.leased_or_busy.push(id);
                        continue;
                    }
                    return Err(StoreError::io(
                        "test derivation build lock for GC",
                        self.lock_path(derivation_key),
                        error,
                    ));
                }
            }

            self.verify_generation(id)?;
            if self.remove_from_derivation_index(derivation_key, id)? {
                report.discarded_derivation_index.push(derivation_key);
            }
            let name = id.to_string();
            let path = self.generation_path(id);
            remove_tree_at(
                &self.generations,
                OsStr::new(&name),
                &path,
                self.root_device,
            )?;
            // The lease record above is created on demand, including for the
            // generations this loop then deletes. Drop it with the generation
            // so `leases` cannot accumulate one file per generation ever
            // published. The lock is still held here; unlinking is safe
            // because any later acquirer recreates the record.
            drop(lease_lock);
            let lease_name = lease_filename(id);
            let lease_path = self.lease_path(id);
            match unlink_file_at(&self.leases, &lease_name, &lease_path) {
                Ok(()) => {}
                Err(StoreError::Io { source, .. }) if source.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
            report.collected.push(id);
        }
        self.generations.sync_all().map_err(|error| {
            StoreError::io(
                "sync generation directory after GC",
                self.root_path.join("generations"),
                error,
            )
        })?;
        drop(roots_lock);
        Ok(report)
    }

    fn collect_gc_roots(&self) -> Result<BTreeSet<GenerationId>, StoreError> {
        let mut roots = BTreeSet::new();
        for name in list_names(&self.aliases, &self.root_path.join("aliases"))? {
            let path = self.root_path.join("aliases").join(&name);
            let Some(text) = name.to_str() else {
                return Err(StoreError::UnsafeGarbageCollection(format!(
                    "non-UTF-8 alias entry at {}",
                    path.display()
                )));
            };
            if text.starts_with(".tmp-alias-") {
                continue;
            }
            let Some(id) = parse_alias_filename(text) else {
                return Err(StoreError::UnsafeGarbageCollection(format!(
                    "unknown alias entry {text:?}"
                )));
            };
            let record = self.read_alias(id).map_err(|error| {
                StoreError::UnsafeGarbageCollection(format!("{}: {error}", path.display()))
            })?;
            let generation = self
                .verify_generation(record.generation_id)
                .map_err(|error| {
                    StoreError::UnsafeGarbageCollection(format!(
                        "alias {} has an invalid target: {error}",
                        record.id
                    ))
                })?;
            validate_alias_target(&record.key, &generation).map_err(|error| {
                StoreError::UnsafeGarbageCollection(format!(
                    "alias {} has an incompatible target: {error}",
                    record.id
                ))
            })?;
            roots.insert(record.generation_id);
        }

        for name in list_names(&self.retained, &self.root_path.join("retained"))? {
            let path = self.root_path.join("retained").join(&name);
            let Some(text) = name.to_str() else {
                return Err(StoreError::UnsafeGarbageCollection(format!(
                    "non-UTF-8 retained-COW entry at {}",
                    path.display()
                )));
            };
            if text.starts_with(".tmp-retained-") {
                continue;
            }
            let Some(id) = parse_retained_filename(text) else {
                return Err(StoreError::UnsafeGarbageCollection(format!(
                    "unknown retained-COW entry {text:?}"
                )));
            };
            let retained = self.read_retained(id).map_err(|error| {
                StoreError::UnsafeGarbageCollection(format!("{}: {error}", path.display()))
            })?;
            self.verify_generation(retained.generation_id)
                .map_err(|error| {
                    StoreError::UnsafeGarbageCollection(format!(
                        "retained COW {} has an invalid target: {error}",
                        retained.id
                    ))
                })?;
            roots.insert(retained.generation_id);
        }
        Ok(roots)
    }

    fn validate_root_identity(&self) -> Result<(), StoreError> {
        let reopened = open_absolute_dir_no_symlinks(&self.root_path)?;
        let (device, inode) = validate_private_root(&reopened, &self.root_path)?;
        if device != self.root_device || inode != self.root_inode {
            return Err(StoreError::InvalidRoot {
                path: self.root_path.clone(),
                reason: "root path no longer names the opened store inode".into(),
            });
        }
        Ok(())
    }

    fn store_header(&self) -> Vec<u8> {
        finish_record(start_record(STORE_MAGIC))
    }

    fn validate_store_header(&self) -> Result<(), StoreError> {
        let path = self.root_path.join(STORE_METADATA);
        let file = open_regular_at(&self.root, STORE_METADATA, &path)?;
        validate_regular(&file, &path, self.root_device, IMMUTABLE_FILE_MODE)?;
        let bytes = read_bounded(file, &path, MetadataKind::Store)?;
        let reader = verify_record(&bytes, STORE_MAGIC, MetadataKind::Store)
            .map_err(|error| contextualize(error, MetadataKind::Store, &path))?;
        reader
            .finish()
            .map_err(|error| contextualize(error, MetadataKind::Store, &path))?;
        if bytes != self.store_header() {
            return Err(StoreError::metadata(
                MetadataKind::Store,
                path,
                "record is not in canonical encoding",
            ));
        }
        Ok(())
    }

    fn validate_roots_lock(&self) -> Result<(), StoreError> {
        let file = self.open_fixed_lock(&self.root, ROOTS_LOCK, None, &self.root_path)?;
        drop(file);
        Ok(())
    }

    fn validate_init_lock(&self) -> Result<(), StoreError> {
        let file = self.open_fixed_lock(&self.root, INIT_LOCK, None, &self.root_path)?;
        drop(file);
        Ok(())
    }

    fn ensure_fixed_record(
        &self,
        parent: &File,
        name: &str,
        bytes: &[u8],
        kind: MetadataKind,
        mode: u32,
    ) -> Result<(), StoreError> {
        let path = self.path_for_layout_file(parent, name);
        let parent_path = path.parent().ok_or_else(|| StoreError::InvalidRoot {
            path: path.clone(),
            reason: "layout file has no parent".into(),
        })?;
        ensure_record_at(
            parent,
            parent_path,
            self.root_device,
            name,
            bytes,
            kind,
            mode,
        )
    }

    fn path_for_layout_file(&self, parent: &File, name: &str) -> PathBuf {
        let inode = parent.metadata().ok().map(|metadata| metadata.ino());
        if inode == Some(self.root_inode) {
            return self.root_path.join(name);
        }
        for (directory, file) in [
            (&self.generations, "generations"),
            (&self.derivations, "derivations"),
            (&self.staging, "staging"),
            (&self.aliases, "aliases"),
            (&self.leases, "leases"),
            (&self.retained, "retained"),
            (&self.locks, "locks"),
        ] {
            if inode == directory.metadata().ok().map(|metadata| metadata.ino()) {
                return self.root_path.join(file).join(name);
            }
        }
        self.root_path.join("<unknown>").join(name)
    }

    fn open_fixed_lock(
        &self,
        parent: &File,
        name: &str,
        derivation_key: Option<DerivationKey>,
        parent_path: &Path,
    ) -> Result<File, StoreError> {
        let path = parent_path.join(name);
        let file = open_regular_at(parent, name, &path)?;
        validate_regular(&file, &path, self.root_device, PRIVATE_FILE_MODE)?;
        let bytes = read_bounded(
            file.try_clone()
                .map_err(|error| StoreError::io("clone lock file", &path, error))?,
            &path,
            MetadataKind::Lock,
        )?;
        validate_lock_record(&bytes, derivation_key, &path)?;
        Ok(file)
    }

    fn open_derivation_lock(&self, key: DerivationKey) -> Result<File, StoreError> {
        let name = derivation_lock_filename(key);
        let bytes = lock_record(Some(key));
        self.ensure_fixed_record(
            &self.locks,
            &name,
            &bytes,
            MetadataKind::Lock,
            PRIVATE_FILE_MODE,
        )?;
        self.open_fixed_lock(&self.locks, &name, Some(key), &self.root_path.join("locks"))
    }

    fn open_lease_lock(&self, id: GenerationId) -> Result<File, StoreError> {
        let name = lease_filename(id);
        let bytes = lease_record(id);
        self.ensure_fixed_record(
            &self.leases,
            &name,
            &bytes,
            MetadataKind::Lease,
            PRIVATE_FILE_MODE,
        )?;
        let path = self.lease_path(id);
        let file = open_regular_at(&self.leases, &name, &path)?;
        validate_regular(&file, &path, self.root_device, PRIVATE_FILE_MODE)?;
        let actual = read_bounded(
            file.try_clone()
                .map_err(|error| StoreError::io("clone lease file", &path, error))?,
            &path,
            MetadataKind::Lease,
        )?;
        validate_lease_record(&actual, id, &path)?;
        Ok(file)
    }

    fn lock_roots_exclusive(&self) -> Result<File, StoreError> {
        let lock = self.open_fixed_lock(&self.root, ROOTS_LOCK, None, &self.root_path)?;
        lock.lock().map_err(|error| {
            StoreError::io(
                "acquire exclusive GC-root lock",
                self.root_path.join(ROOTS_LOCK),
                error,
            )
        })?;
        Ok(lock)
    }

    fn lock_roots_shared(&self) -> Result<File, StoreError> {
        let lock = self.open_fixed_lock(&self.root, ROOTS_LOCK, None, &self.root_path)?;
        lock.lock_shared().map_err(|error| {
            StoreError::io(
                "acquire shared GC-root lock",
                self.root_path.join(ROOTS_LOCK),
                error,
            )
        })?;
        Ok(lock)
    }

    fn generations_for_derivation_locked(
        &self,
        derivation_key: DerivationKey,
    ) -> Result<Vec<Generation>, StoreError> {
        let record = match self.read_derivation(derivation_key) {
            Ok(record) => record,
            Err(StoreError::DerivationNotFound) => return Ok(Vec::new()),
            Err(error) => return Err(error),
        };
        let mut generations = Vec::with_capacity(1 + record.alternatives.len());
        for id in record.ids() {
            let generation = self.verify_generation(id)?;
            if generation.manifest.derivation_key != derivation_key {
                return Err(StoreError::metadata(
                    MetadataKind::Derivation,
                    self.derivation_path(derivation_key),
                    "indexed generation belongs to a different derivation",
                ));
            }
            generations.push(generation);
        }
        Ok(generations)
    }

    /// Caller must hold the exclusive per-derivation build lock.
    fn update_derivation_index(
        &self,
        derivation_key: DerivationKey,
        generation_id: GenerationId,
    ) -> Result<(), StoreError> {
        let mut record = match self.read_derivation(derivation_key) {
            Ok(record) => record,
            Err(StoreError::DerivationNotFound) => {
                DerivationRecord::new(derivation_key, generation_id)
            }
            Err(error) => return Err(error),
        };
        record.insert(generation_id);
        self.write_derivation_record(&record)
    }

    /// Caller must hold the exclusive per-derivation build lock and roots lock.
    /// Returns whether a damaged lookup had to be discarded, so the caller can
    /// report the repair rather than perform it silently.
    fn remove_from_derivation_index(
        &self,
        derivation_key: DerivationKey,
        generation_id: GenerationId,
    ) -> Result<bool, StoreError> {
        // A collection interrupted between this removal and the tree removal
        // leaves the generation absent from its lookup, or the whole lookup
        // unlinked when it held only that generation, while the tree survives.
        // Both are states a retry must be able to finish, so treat them as
        // already removed rather than as corruption: the caller has already
        // verified the generation it is collecting.
        let mut record = match self.read_derivation(derivation_key) {
            Ok(record) => record,
            Err(StoreError::DerivationNotFound) => return Ok(false),
            // Bytes that provably do not decode. The lookup is an index
            // derived from the generations, so it can be discarded and rebuilt
            // by the next publication; refusing to collect anything at all
            // because one index entry is damaged turns a recoverable
            // inconsistency into a store that can never be collected again.
            // An I/O error still aborts: that tells us nothing about the
            // state, so acting on it would be a guess.
            Err(StoreError::InvalidMetadata { .. } | StoreError::MetadataTooLarge { .. }) => {
                self.discard_derivation_index(derivation_key)?;
                return Ok(true);
            }
            Err(error) => return Err(error),
        };
        if !record.ids().any(|id| id == generation_id) {
            return Ok(false);
        }
        if !record.remove(generation_id) {
            let name = derivation_filename(derivation_key);
            let path = self.derivation_path(derivation_key);
            unlink_file_at(&self.derivations, &name, &path)?;
            self.derivations
                .sync_all()
                .map_err(|error| StoreError::io("sync derivation lookup removal", &path, error))?;
            return Ok(false);
        }
        self.write_derivation_record(&record)?;
        Ok(false)
    }

    /// Unlink a derivation lookup whose bytes cannot be decoded, tolerating a
    /// concurrent unlink so a retried collection is idempotent.
    fn discard_derivation_index(&self, key: DerivationKey) -> Result<(), StoreError> {
        let name = derivation_filename(key);
        let path = self.derivation_path(key);
        match unlink_file_at(&self.derivations, &name, &path) {
            Ok(()) => {}
            Err(StoreError::Io { source, .. }) if source.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        self.derivations
            .sync_all()
            .map_err(|error| StoreError::io("sync discarded derivation lookup", &path, error))
    }

    fn write_derivation_record(&self, record: &DerivationRecord) -> Result<(), StoreError> {
        record.validate()?;
        let final_name = derivation_filename(record.derivation_key);
        let final_path = self.derivation_path(record.derivation_key);
        let temp_name = format!(".tmp-derivation-{}", unique_suffix());
        let temp_path = self.root_path.join("derivations").join(&temp_name);
        write_new_synced(
            &self.derivations,
            &temp_name,
            &temp_path,
            &record.encode(),
            IMMUTABLE_FILE_MODE,
        )?;
        if let Err(error) = rename_replace_at(
            &self.derivations,
            &temp_name,
            &self.derivations,
            &final_name,
            &final_path,
        ) {
            let _ = unlink_file_at(&self.derivations, &temp_name, &temp_path);
            return Err(error);
        }
        self.derivations.sync_all().map_err(|error| {
            StoreError::io("sync derivation lookup replacement", &final_path, error)
        })
    }

    fn read_derivation(&self, key: DerivationKey) -> Result<DerivationRecord, StoreError> {
        let path = self.derivation_path(key);
        let name = derivation_filename(key);
        let file = match open_regular_at(&self.derivations, &name, &path) {
            Ok(file) => file,
            Err(StoreError::Io { source, .. }) if source.kind() == io::ErrorKind::NotFound => {
                return Err(StoreError::DerivationNotFound);
            }
            Err(error) => return Err(error),
        };
        validate_regular(&file, &path, self.root_device, IMMUTABLE_FILE_MODE)?;
        let record =
            DerivationRecord::decode(&read_bounded(file, &path, MetadataKind::Derivation)?, &path)?;
        if record.derivation_key != key {
            return Err(StoreError::metadata(
                MetadataKind::Derivation,
                path,
                "derivation key does not match filename",
            ));
        }
        Ok(record)
    }

    fn read_alias(&self, id: AliasId) -> Result<AliasRecord, StoreError> {
        let path = self.alias_path(id);
        let name = alias_filename(id);
        let file = match open_regular_at(&self.aliases, &name, &path) {
            Ok(file) => file,
            Err(StoreError::Io { source, .. }) if source.kind() == io::ErrorKind::NotFound => {
                return Err(StoreError::AliasNotFound);
            }
            Err(error) => return Err(error),
        };
        validate_regular(&file, &path, self.root_device, IMMUTABLE_FILE_MODE)?;
        let record = AliasRecord::decode(&read_bounded(file, &path, MetadataKind::Alias)?, &path)?;
        if record.id != id {
            return Err(StoreError::metadata(
                MetadataKind::Alias,
                path,
                "alias ID does not match filename",
            ));
        }
        Ok(record)
    }

    fn read_retained(&self, id: RetainedCowId) -> Result<RetainedCow, StoreError> {
        let path = self.retained_path(id);
        let name = retained_filename(id);
        let file = match open_regular_at(&self.retained, &name, &path) {
            Ok(file) => file,
            Err(StoreError::Io { source, .. }) if source.kind() == io::ErrorKind::NotFound => {
                return Err(StoreError::RetainedCowNotFound);
            }
            Err(error) => return Err(error),
        };
        validate_regular(&file, &path, self.root_device, IMMUTABLE_FILE_MODE)?;
        let record = RetainedCow::decode(
            &read_bounded(file, &path, MetadataKind::RetainedCow)?,
            &path,
        )?;
        if record.id != id {
            return Err(StoreError::metadata(
                MetadataKind::RetainedCow,
                path,
                "retained-COW ID does not match filename",
            ));
        }
        Ok(record)
    }

    fn recover_atomic_temps(
        &self,
        directory: &File,
        relative: &str,
        prefix: &str,
        report: &mut RecoveryReport,
    ) -> Result<(), StoreError> {
        let directory_path = if relative.is_empty() {
            self.root_path.clone()
        } else {
            self.root_path.join(relative)
        };
        for name in list_names(directory, &directory_path)? {
            let Some(text) = name.to_str() else {
                continue;
            };
            if !text.starts_with(prefix) {
                continue;
            }
            let path = directory_path.join(&name);
            let file = match open_regular_at(directory, &name, &path) {
                Ok(file) => file,
                Err(_) => {
                    report.blocked_entries.push(path);
                    continue;
                }
            };
            let metadata = file
                .metadata()
                .map_err(|error| StoreError::io("stat temporary record", &path, error))?;
            if metadata.dev() != self.root_device
                || metadata.uid() != nix::unistd::geteuid().as_raw()
                || !metadata.is_file()
                || metadata.nlink() != 1
                || !matches!(
                    metadata.mode() & 0o7777,
                    PRIVATE_FILE_MODE | IMMUTABLE_FILE_MODE
                )
                || metadata.len() > MAX_METADATA_BYTES as u64
            {
                report.blocked_entries.push(path);
                continue;
            }
            unlink_file_at(directory, &name, &path)?;
            directory.sync_all().map_err(|error| {
                StoreError::io("sync temporary-record recovery", &directory_path, error)
            })?;
            report.removed_temporary_records.push(path);
        }
        Ok(())
    }

    fn create_staging_directory(
        &self,
        derivation_key: DerivationKey,
    ) -> Result<(String, File), StoreError> {
        for _ in 0..128 {
            let name = format!(
                "stage-{}-{}",
                hex::encode(derivation_key.as_bytes()),
                unique_suffix()
            );
            let path = self.root_path.join("staging").join(&name);
            match create_private_dir(&self.staging, &name, &path, self.root_device) {
                Ok(directory) => return Ok((name, directory)),
                Err(error) if io_error_is(&error, io::ErrorKind::AlreadyExists) => {}
                Err(error) => return Err(error),
            }
        }
        Err(StoreError::InvalidInput {
            field: "staging name",
            reason: "could not allocate a unique staging name".into(),
        })
    }

    fn generation_path(&self, id: GenerationId) -> PathBuf {
        self.root_path.join("generations").join(id.to_string())
    }

    fn derivation_path(&self, key: DerivationKey) -> PathBuf {
        self.root_path
            .join("derivations")
            .join(derivation_filename(key))
    }

    fn alias_path(&self, id: AliasId) -> PathBuf {
        self.root_path.join("aliases").join(alias_filename(id))
    }

    fn retained_path(&self, id: RetainedCowId) -> PathBuf {
        self.root_path.join("retained").join(retained_filename(id))
    }

    fn lease_path(&self, id: GenerationId) -> PathBuf {
        self.root_path.join("leases").join(lease_filename(id))
    }

    fn lock_path(&self, key: DerivationKey) -> PathBuf {
        self.root_path
            .join("locks")
            .join(derivation_lock_filename(key))
    }
}

impl GenerationTransaction<'_> {
    #[must_use]
    pub const fn derivation_key(&self) -> DerivationKey {
        self.derivation_key
    }

    #[must_use]
    pub const fn spec(&self) -> &GenerationSpec {
        &self.spec
    }

    /// The guard process must keep a duplicate of this descriptor open for the
    /// complete builder lifetime so the derivation lock survives host failure.
    #[must_use]
    pub const fn lock_file(&self) -> &File {
        &self._build_lock
    }

    #[must_use]
    pub fn staging_path(&self) -> PathBuf {
        self.store.root_path.join("staging").join(&self.stage_name)
    }

    #[must_use]
    pub fn base_path(&self) -> PathBuf {
        self.staging_path().join(BASE_IMAGE)
    }

    /// Create the base file exactly once with mode 0600 and `O_NOFOLLOW`.
    /// The caller may resize it and hand its path to the builder UML.
    pub fn create_base(&self) -> Result<File, StoreError> {
        self.store.validate_root_identity()?;
        create_regular_at(&self.stage, BASE_IMAGE, &self.base_path())
    }

    /// Create one future immutable output sidecar exactly once.
    pub fn create_sidecar(&self, name: impl Into<String>) -> Result<File, StoreError> {
        self.store.validate_root_identity()?;
        let name = validate_sidecar_name(name.into())?;
        let path = self.staging_path().join(&name);
        create_regular_at(&self.stage, &name, &path)
    }

    /// Verify the expected base digest and atomically publish the generation.
    ///
    /// The lease is released before this returns, so the result is immediately
    /// collectable until something roots it. A caller that intends to set an
    /// alias must use [`Self::publish_leased`] and hold the lease until it has.
    pub fn publish(self, expected_base_digest: Digest) -> Result<Generation, StoreError> {
        Ok(self.publish_leased(expected_base_digest, &[])?.generation)
    }

    /// Verify the base and canonical ordered sidecar records, then atomically
    /// publish under the final output-derived generation ID.
    ///
    /// Like [`Self::publish`], this drops the lease before returning. Use
    /// [`Self::publish_leased`] whenever the result is going to be rooted.
    pub fn publish_with_sidecars(
        self,
        expected_base_digest: Digest,
        expected_sidecars: &[ImmutableSidecar],
    ) -> Result<Generation, StoreError> {
        Ok(self
            .publish_leased(expected_base_digest, expected_sidecars)?
            .generation)
    }

    /// Publish and return a held lease on the result.
    ///
    /// A freshly published generation is not yet rooted by any alias, so a
    /// caller that intends to root it must hold this lease until it has, or a
    /// concurrent collection is entitled to delete it.
    pub fn publish_leased(
        self,
        expected_base_digest: Digest,
        expected_sidecars: &[ImmutableSidecar],
    ) -> Result<Lease, StoreError> {
        self.publish_with_sidecars_inner(expected_base_digest, expected_sidecars, |_, _, _| {})
    }

    fn publish_with_sidecars_inner<F>(
        mut self,
        expected_base_digest: Digest,
        expected_sidecars: &[ImmutableSidecar],
        observe_after_rename: F,
    ) -> Result<Lease, StoreError>
    where
        F: FnOnce(GenerationId, &Path, &File),
    {
        self.store.validate_root_identity()?;
        validate_canonical_sidecars(expected_sidecars)?;
        let stage_path = self.staging_path();

        let mut expected_staged = vec![
            OsStr::new(BASE_IMAGE).to_os_string(),
            OsStr::new(STAGING_METADATA).to_os_string(),
        ];
        expected_staged.extend(
            expected_sidecars
                .iter()
                .map(|sidecar| OsStr::new(sidecar.name()).to_os_string()),
        );
        expected_staged.sort();
        let mut staged_entries = list_names(&self.stage, &stage_path)?;
        staged_entries.sort();
        if staged_entries != expected_staged {
            return Err(StoreError::UnexpectedEntry { path: stage_path });
        }

        let base_path = self.base_path();
        let base = open_regular_at(&self.stage, BASE_IMAGE, &base_path)?;
        validate_regular(&base, &base_path, self.store.root_device, PRIVATE_FILE_MODE)?;
        base.sync_all()
            .map_err(|error| StoreError::io("sync staged base", &base_path, error))?;
        let (base_digest, base_size) = hash_file(&base, &base_path)?;
        if base_digest != expected_base_digest {
            return Err(StoreError::DigestMismatch {
                path: base_path,
                expected: expected_base_digest,
                actual: base_digest,
            });
        }
        set_mode(&base, IMMUTABLE_FILE_MODE, &base_path)?;
        base.sync_all().map_err(|error| {
            StoreError::io("sync immutable staged base metadata", &base_path, error)
        })?;

        for expected in expected_sidecars {
            let path = stage_path.join(expected.name());
            let file = open_regular_at(&self.stage, expected.name(), &path)?;
            validate_regular(&file, &path, self.store.root_device, PRIVATE_FILE_MODE)?;
            file.sync_all()
                .map_err(|error| StoreError::io("sync staged sidecar", &path, error))?;
            let (digest, size) = hash_file(&file, &path)?;
            if size != expected.size() {
                return Err(StoreError::SizeMismatch {
                    path,
                    expected: expected.size(),
                    actual: size,
                });
            }
            if digest != expected.digest() {
                return Err(StoreError::DigestMismatch {
                    path,
                    expected: expected.digest(),
                    actual: digest,
                });
            }
            set_mode(&file, IMMUTABLE_FILE_MODE, &path)?;
            file.sync_all().map_err(|error| {
                StoreError::io("sync immutable staged sidecar metadata", &path, error)
            })?;
        }

        let id = GenerationId::derive(
            self.derivation_key,
            base_digest,
            base_size,
            expected_sidecars,
        )?;
        let manifest = GenerationManifest {
            id,
            derivation_key: self.derivation_key,
            spec: self.spec.clone(),
            base_digest,
            base_size,
            sidecars: expected_sidecars.to_vec(),
        };

        // Hold the generation's shared lease across everything that follows.
        // A generation this call returns is not yet rooted by any alias -- the
        // caller sets that afterwards -- so without a lease held from before
        // the ID becomes visible, a concurrent collection is entitled to take
        // the roots lock in that window and delete what was just built.
        let lease_lock = self.store.open_lease_lock(id)?;
        lease_lock.lock_shared().map_err(|error| {
            StoreError::io("hold publication lease", self.store.lease_path(id), error)
        })?;

        match self.store.verify_generation(id) {
            Ok(existing) if existing.manifest == manifest => {
                self.store
                    .update_derivation_index(self.derivation_key, id)?;
                return Ok(Lease {
                    generation: existing,
                    lock: lease_lock,
                });
            }
            Ok(_) => return Err(StoreError::GenerationAlreadyExists(id)),
            Err(StoreError::GenerationNotFound(_)) => {}
            Err(error) => return Err(error),
        }

        let manifest_path = stage_path.join(GENERATION_METADATA);
        write_new_synced(
            &self.stage,
            GENERATION_METADATA,
            &manifest_path,
            &manifest.encode(),
            IMMUTABLE_FILE_MODE,
        )?;

        let mut entries = list_names(&self.stage, &stage_path)?;
        entries.sort();
        let mut expected = expected_staged;
        expected.push(OsStr::new(GENERATION_METADATA).to_os_string());
        expected.sort();
        if entries != expected {
            return Err(StoreError::UnexpectedEntry { path: stage_path });
        }

        self.stage.sync_all().map_err(|error| {
            StoreError::io("sync complete staging directory", &stage_path, error)
        })?;

        // Moving a directory across parents requires write permission on the
        // moved directory because its `..` entry changes. First move the fully
        // flushed but still-private inode to a non-final name in `generations`.
        // A crash can therefore leave either a recoverable staging name or a
        // recoverable publication-temp name, never an invalid final ID name.
        let generation_temp_name = format!("{GENERATION_TEMP_PREFIX}{}", self.stage_name);
        let generation_temp_path = self
            .store
            .root_path
            .join("generations")
            .join(&generation_temp_name);
        rename_noreplace_at(
            &self.store.staging,
            &self.stage_name,
            &self.store.generations,
            &generation_temp_name,
            &generation_temp_path,
        )?;
        self.generation_temp_name = Some(generation_temp_name.clone());

        // The cross-directory rename changes both parents. Make the temp name
        // and removal of the original staging name durable before sealing.
        self.store.generations.sync_all().map_err(|error| {
            StoreError::io(
                "sync publication temporary name",
                &generation_temp_path,
                error,
            )
        })?;
        self.store.staging.sync_all().map_err(|error| {
            StoreError::io("sync staging transfer", &generation_temp_path, error)
        })?;

        // Seal and durably record the final directory mode while this inode is
        // reachable only by its non-final publication-temp name. The retained
        // descriptor remains usable after chmod and across both renames.
        set_mode(&self.stage, IMMUTABLE_DIR_MODE, &generation_temp_path)?;
        self.stage.sync_all().map_err(|error| {
            StoreError::io(
                "sync sealed publication directory",
                &generation_temp_path,
                error,
            )
        })?;
        validate_directory(
            &self.stage,
            &generation_temp_path,
            self.store.root_device,
            IMMUTABLE_DIR_MODE,
        )?;

        // This same-parent rename does not modify the sealed directory's `..`
        // entry, so it succeeds without write permission on that directory.
        // The first instant the final ID is visible, every inode already has
        // its final immutable mode and its contents and metadata are flushed.
        let final_path = self.store.generation_path(id);
        match rename_noreplace_at(
            &self.store.generations,
            &generation_temp_name,
            &self.store.generations,
            &id.to_string(),
            &final_path,
        ) {
            Ok(()) => {}
            Err(error) if io_error_is(&error, io::ErrorKind::AlreadyExists) => {
                return Err(StoreError::GenerationAlreadyExists(id));
            }
            Err(error) => return Err(error),
        }
        self.generation_temp_name = None;
        self.clean_on_drop = false;
        observe_after_rename(id, &final_path, &self.stage);

        // The commit rename changes one parent. Flush it before publication
        // reports success; the source staging parent was flushed above.
        self.store
            .generations
            .sync_all()
            .map_err(|error| StoreError::io("sync generation publication", &final_path, error))?;
        let generation = self.store.verify_generation(id)?;
        self.store
            .update_derivation_index(self.derivation_key, id)?;
        Ok(Lease {
            generation,
            lock: lease_lock,
        })
    }
}

impl Drop for GenerationTransaction<'_> {
    fn drop(&mut self) {
        if !self.clean_on_drop {
            return;
        }
        if let Some(name) = &self.generation_temp_name {
            let path = self.store.root_path.join("generations").join(name);
            let _ = remove_tree_at(
                &self.store.generations,
                OsStr::new(name),
                &path,
                self.store.root_device,
            );
        } else {
            let path = self.staging_path();
            let _ = remove_tree_at(
                &self.store.staging,
                OsStr::new(&self.stage_name),
                &path,
                self.store.root_device,
            );
        }
    }
}

fn open_and_validate_layout_dir(
    root: &File,
    root_path: &Path,
    name: &str,
    device: u64,
) -> Result<File, StoreError> {
    let path = root_path.join(name);
    let directory = open_dir_at(root, name, &path)?;
    validate_directory(&directory, &path, device, PRIVATE_DIR_MODE)?;
    Ok(directory)
}

#[allow(clippy::too_many_arguments)]
fn ensure_record_at(
    parent: &File,
    parent_path: &Path,
    device: u64,
    name: &str,
    bytes: &[u8],
    kind: MetadataKind,
    mode: u32,
) -> Result<(), StoreError> {
    let path = parent_path.join(name);
    match open_regular_at(parent, name, &path) {
        Ok(file) => {
            validate_regular(&file, &path, device, mode)?;
            let actual = read_bounded(file, &path, kind)?;
            if actual != bytes {
                return Err(StoreError::metadata(kind, path, "record contents differ"));
            }
            return Ok(());
        }
        Err(StoreError::Io { source, .. }) if source.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }

    // Lease and lock records are created without the roots lock, and `recover`
    // sweeps abandoned `.tmp-fixed-` files while holding it, so a recovery can
    // unlink this temp between the write and the rename. Losing a temp that way
    // is not a failure of the operation that created it -- make another one.
    const PUBLICATION_ATTEMPTS: u32 = 4;
    for attempt in 1..=PUBLICATION_ATTEMPTS {
        let temp_name = format!("{FIXED_TEMP_PREFIX}{}", unique_suffix());
        let temp_path = parent_path.join(&temp_name);
        write_new_synced(parent, &temp_name, &temp_path, bytes, mode)?;
        match rename_noreplace_at(parent, &temp_name, parent, name, &path) {
            Ok(()) => {
                parent.sync_all().map_err(|error| {
                    StoreError::io("sync fixed record publication", &path, error)
                })?;
                break;
            }
            Err(error) if io_error_is(&error, io::ErrorKind::AlreadyExists) => {
                let _ = unlink_file_at(parent, &temp_name, &temp_path);
                break;
            }
            Err(error)
                if io_error_is(&error, io::ErrorKind::NotFound)
                    && attempt < PUBLICATION_ATTEMPTS => {}
            Err(error) => {
                let _ = unlink_file_at(parent, &temp_name, &temp_path);
                return Err(error);
            }
        }
    }
    let file = open_regular_at(parent, name, &path)?;
    validate_regular(&file, &path, device, mode)?;
    let actual = read_bounded(file, &path, kind)?;
    if actual != bytes {
        return Err(StoreError::metadata(kind, path, "record contents differ"));
    }
    Ok(())
}

fn lock_record(derivation_key: Option<DerivationKey>) -> Vec<u8> {
    let mut bytes = start_record(LOCK_MAGIC);
    match derivation_key {
        Some(key) => {
            bytes.push(1);
            bytes.extend_from_slice(key.as_bytes());
        }
        None => bytes.push(0),
    }
    finish_record(bytes)
}

fn validate_lock_record(
    bytes: &[u8],
    expected_key: Option<DerivationKey>,
    path: &Path,
) -> Result<(), StoreError> {
    let result = (|| {
        let mut reader = verify_record(bytes, LOCK_MAGIC, MetadataKind::Lock)?;
        let actual_key = match reader.u8()? {
            0 => None,
            1 => Some(read_derivation_key(&mut reader)?),
            value => {
                return Err(StoreError::metadata(
                    MetadataKind::Lock,
                    path,
                    format!("invalid lock kind {value}"),
                ));
            }
        };
        reader.finish()?;
        if actual_key != expected_key || lock_record(actual_key) != bytes {
            return Err(StoreError::metadata(
                MetadataKind::Lock,
                path,
                "lock identity or encoding differs",
            ));
        }
        Ok(())
    })();
    result.map_err(|error| contextualize(error, MetadataKind::Lock, path))
}

fn lease_record(id: GenerationId) -> Vec<u8> {
    let mut bytes = start_record(LEASE_MAGIC);
    bytes.extend_from_slice(id.as_bytes());
    finish_record(bytes)
}

fn validate_lease_record(
    bytes: &[u8],
    expected_id: GenerationId,
    path: &Path,
) -> Result<(), StoreError> {
    let result = (|| {
        let mut reader = verify_record(bytes, LEASE_MAGIC, MetadataKind::Lease)?;
        let actual_id = read_generation_id(&mut reader)?;
        reader.finish()?;
        if actual_id != expected_id || lease_record(actual_id) != bytes {
            return Err(StoreError::metadata(
                MetadataKind::Lease,
                path,
                "lease identity or encoding differs",
            ));
        }
        Ok(())
    })();
    result.map_err(|error| contextualize(error, MetadataKind::Lease, path))
}

fn read_generation_id(reader: &mut Reader<'_>) -> Result<GenerationId, StoreError> {
    let bytes: [u8; 32] = reader.take(32)?.try_into().map_err(|_| {
        StoreError::metadata(MetadataKind::Store, "<memory>", "invalid generation ID")
    })?;
    Ok(GenerationId::from_bytes(bytes))
}

fn read_alias_id(reader: &mut Reader<'_>) -> Result<AliasId, StoreError> {
    let bytes: [u8; 32] = reader
        .take(32)?
        .try_into()
        .map_err(|_| StoreError::metadata(MetadataKind::Store, "<memory>", "invalid alias ID"))?;
    Ok(AliasId::from_bytes(bytes))
}

fn read_retained_id(reader: &mut Reader<'_>) -> Result<RetainedCowId, StoreError> {
    let bytes: [u8; 32] = reader.take(32)?.try_into().map_err(|_| {
        StoreError::metadata(MetadataKind::Store, "<memory>", "invalid retained-COW ID")
    })?;
    Ok(RetainedCowId::from_bytes(bytes))
}

fn alias_filename(id: AliasId) -> String {
    format!("{id}.meta")
}

fn derivation_filename(key: DerivationKey) -> String {
    format!("{key}.meta")
}

fn instance_filename(id: InstanceId) -> String {
    format!("{id}.meta")
}

fn instance_directory_name(id: InstanceId) -> String {
    format!("{id}.d")
}

fn retained_filename(id: RetainedCowId) -> String {
    format!("{id}.meta")
}

fn derivation_lock_filename(key: DerivationKey) -> String {
    format!("{key}.lock")
}

fn lease_filename(id: GenerationId) -> String {
    format!("{id}.lock")
}

fn parse_alias_filename(value: &str) -> Option<AliasId> {
    AliasId::parse_filename(value.strip_suffix(".meta")?)
}

fn parse_retained_filename(value: &str) -> Option<RetainedCowId> {
    RetainedCowId::parse_filename(value.strip_suffix(".meta")?)
}

fn parse_staging_name(value: &str) -> Option<DerivationKey> {
    let value = value.strip_prefix("stage-")?;
    if value.len() != 64 + 1 + 32 || value.as_bytes().get(64) != Some(&b'-') {
        return None;
    }
    let id_hex = &value[..64];
    let suffix = &value[65..];
    if id_hex
        .bytes()
        .chain(suffix.bytes())
        .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
    {
        return None;
    }
    DerivationKey::parse_filename(&format!("pkvm-der-v1-{id_hex}"))
}

fn parse_generation_temp_name(value: &str) -> Option<DerivationKey> {
    parse_staging_name(value.strip_prefix(GENERATION_TEMP_PREFIX)?)
}

fn validate_alias_target(key: &AliasKey, generation: &Generation) -> Result<(), StoreError> {
    let spec = generation.manifest().spec();
    if spec.profile_id() != key.profile_id() || spec.profile_revision() != key.profile_revision() {
        return Err(StoreError::InvalidInput {
            field: "alias target",
            reason: format!(
                "generation {} belongs to {}@{}, not {}@{}",
                generation.id(),
                spec.profile_id(),
                spec.profile_revision(),
                key.profile_id(),
                key.profile_revision()
            ),
        });
    }
    if spec.selector_policy_id() != key.selector_policy_id() {
        return Err(StoreError::InvalidInput {
            field: "alias target",
            reason: format!(
                "generation {} uses selector policy {}, not {}",
                generation.id(),
                spec.selector_policy_id(),
                key.selector_policy_id()
            ),
        });
    }
    let requested = key.requested_platform();
    let effective = spec.effective_platform();
    if requested.os() != effective.os()
        || requested.architecture() != effective.architecture()
        || requested
            .variant()
            .is_some_and(|variant| effective.variant() != Some(variant))
        || requested
            .os_version()
            .is_some_and(|version| effective.os_version() != Some(version))
        || (!requested.os_features().is_empty()
            && requested.os_features() != effective.os_features())
    {
        return Err(StoreError::InvalidInput {
            field: "alias target",
            reason: format!(
                "generation {} effective platform is incompatible with the requested alias selector",
                generation.id()
            ),
        });
    }
    Ok(())
}

fn unique_suffix() -> String {
    let counter = UNIQUE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    let mut hasher = Sha256::new();
    hasher.update(b"pocket-store-unique-suffix\0v1\0");
    hasher.update(std::process::id().to_be_bytes());
    hasher.update(counter.to_be_bytes());
    hasher.update(timestamp.to_be_bytes());
    let digest = hasher.finalize();
    hex::encode(&digest[..16])
}

fn contextualize(error: StoreError, kind: MetadataKind, path: &Path) -> StoreError {
    match error {
        StoreError::MetadataTooLarge { maximum, .. } => StoreError::MetadataTooLarge {
            kind,
            path: path.to_path_buf(),
            maximum,
        },
        StoreError::InvalidMetadata { reason, .. } => StoreError::InvalidMetadata {
            kind,
            path: path.to_path_buf(),
            reason,
        },
        StoreError::InvalidInput { field, reason } => StoreError::InvalidMetadata {
            kind,
            path: path.to_path_buf(),
            reason: format!("invalid {field}: {reason}"),
        },
        other => other,
    }
}

fn io_error_is(error: &StoreError, kind: io::ErrorKind) -> bool {
    matches!(error, StoreError::Io { source, .. } if source.kind() == kind)
}

#[cfg(test)]
mod tests {
    use std::{
        fs::{OpenOptions, Permissions},
        io::{Seek, SeekFrom, Write},
        os::unix::fs::{PermissionsExt, symlink},
        sync::{Arc, Barrier},
        thread,
    };

    use tempfile::TempDir;

    use super::*;
    use crate::Platform;

    fn digest(byte: u8) -> Digest {
        Digest::from_bytes([byte; 32])
    }

    fn spec(seed: u8) -> GenerationSpec {
        GenerationSpec::new(
            digest(seed),
            digest(seed.wrapping_add(1)),
            vec![digest(seed.wrapping_add(2))],
            vec![digest(seed.wrapping_add(3))],
            None,
            Platform::new("linux", "amd64", None, None, Vec::new()).expect("valid platform"),
            Platform::new("linux", "amd64", None, None, Vec::new()).expect("valid platform"),
            "oci-selector-v1",
            "x86_64-smp-p4k",
            digest(10),
            "rootfs-dir-v1",
            "ext4-v1-b4096",
            digest(11),
        )
        .expect("valid generation spec")
    }

    fn fixture() -> (TempDir, Store) {
        let temporary = tempfile::tempdir().expect("create temp directory");
        let root = temporary.path().join("pocket").join("cache");
        std::fs::create_dir(temporary.path().join("pocket")).expect("create parent");
        let root = ManagedUmlPath::new(root).expect("valid managed cache path");
        let store = Store::initialize(root).expect("initialize store");
        (temporary, store)
    }

    fn publish(store: &Store, spec: GenerationSpec, contents: &[u8]) -> GenerationId {
        let transaction = match store.try_begin_generation(spec).expect("begin generation") {
            BeginGeneration::Existing(_) => panic!("unexpected existing generation"),
            BeginGeneration::Vacant(transaction) => transaction,
        };
        let mut base = transaction.create_base().expect("create base");
        base.write_all(contents).expect("write base");
        base.sync_all().expect("sync base in test");
        drop(base);
        transaction
            .publish(Digest::of_bytes(contents))
            .expect("publish generation")
            .id()
    }

    fn alias(seed: u8) -> AliasKey {
        AliasKey::new(
            "x86_64-smp-p4k",
            digest(10),
            format!("docker.io/library/test:{seed}"),
            Platform::new("linux", "amd64", None, None, Vec::new())
                .expect("valid requested platform"),
            "oci-selector-v1",
        )
        .expect("valid alias")
    }

    #[test]
    fn private_root_and_schema_reopen_cleanly() {
        let (_temporary, store) = fixture();
        let reopened =
            Store::open(ManagedUmlPath::new(store.root_path()).expect("valid managed root"))
                .expect("reopen store");
        assert_eq!(reopened.root_path(), store.root_path());
    }

    #[test]
    fn absent_only_initialization_never_repairs_existing_directory() {
        let temporary = tempfile::tempdir().expect("create temp directory");
        let parent = temporary.path().join("pocket");
        std::fs::create_dir(&parent).expect("create cache parent");
        let root_path = parent.join("cache");
        std::fs::create_dir(&root_path).expect("create invalid existing root");
        std::fs::set_permissions(&root_path, Permissions::from_mode(0o700))
            .expect("set invalid root mode");
        let root = ManagedUmlPath::new(&root_path).expect("managed cache root");

        assert!(matches!(
            Store::initialize_absent(root),
            Err(StoreError::InvalidRoot { .. })
        ));
        assert_eq!(
            std::fs::read_dir(&root_path)
                .expect("read untouched root")
                .count(),
            0
        );
    }

    #[test]
    fn concurrent_initializers_publish_one_valid_schema() {
        let temporary = tempfile::tempdir().expect("create temp directory");
        let parent = temporary.path().join("pocket");
        std::fs::create_dir(&parent).expect("create cache parent");
        let root = ManagedUmlPath::new(parent.join("cache")).expect("managed cache root");
        let root = Arc::new(root);
        let barrier = Arc::new(Barrier::new(8));
        let mut threads = Vec::new();
        for _ in 0..8 {
            let root = Arc::clone(&root);
            let barrier = Arc::clone(&barrier);
            threads.push(thread::spawn(move || {
                barrier.wait();
                Store::initialize((*root).clone()).expect("concurrent initialization")
            }));
        }
        for thread in threads {
            drop(thread.join().expect("initializer thread"));
        }
        Store::open((*root).clone()).expect("open concurrently initialized store");
    }

    #[test]
    fn rejects_non_private_and_symlink_roots() {
        let (temporary, store) = fixture();
        let root = store.root_path().to_path_buf();
        drop(store);
        std::fs::set_permissions(&root, Permissions::from_mode(0o755)).expect("change mode");
        assert!(matches!(
            Store::open(ManagedUmlPath::new(&root).expect("managed root")),
            Err(StoreError::InvalidRoot { .. })
        ));

        let link = temporary.path().join("pocket").join("cache-link");
        symlink(&root, &link).expect("create root symlink");
        assert!(matches!(
            Store::open(ManagedUmlPath::new(link).expect("managed link path")),
            Err(StoreError::Symlink { .. })
        ));
    }

    #[test]
    fn publication_is_immutable_verified_and_idempotently_discovered() {
        let (_temporary, store) = fixture();
        let generation_spec = spec(1);
        let id = publish(&store, generation_spec.clone(), b"root filesystem bytes");
        let verified = store.verify_generation(id).expect("verify generation");
        assert_eq!(verified.manifest().spec(), &generation_spec);
        assert_eq!(
            verified.manifest().base_digest(),
            Digest::of_bytes(b"root filesystem bytes")
        );
        assert_eq!(
            verified
                .base_file()
                .metadata()
                .expect("base metadata")
                .permissions()
                .mode()
                & 0o7777,
            IMMUTABLE_FILE_MODE
        );
        assert!(matches!(
            store
                .try_begin_generation(generation_spec)
                .expect("lookup existing"),
            BeginGeneration::Existing(_)
        ));
    }

    #[test]
    fn generation_is_fully_valid_at_first_final_name_visibility() {
        let (_temporary, store) = fixture();
        let transaction = match store
            .try_begin_generation(spec(16))
            .expect("begin observed publication")
        {
            BeginGeneration::Vacant(transaction) => transaction,
            BeginGeneration::Existing(_) => panic!("unexpected existing generation"),
        };
        let stage_path = transaction.staging_path();
        let stage_metadata = transaction.stage.metadata().expect("stat staging inode");

        let base_bytes = b"first-visible base";
        let mut base = transaction.create_base().expect("create observed base");
        base.write_all(base_bytes).expect("write observed base");
        drop(base);

        let sidecar_bytes = b"first-visible sidecar";
        let mut sidecar = transaction
            .create_sidecar("accounts.cbor")
            .expect("create observed sidecar");
        sidecar
            .write_all(sidecar_bytes)
            .expect("write observed sidecar");
        drop(sidecar);
        let sidecars = [ImmutableSidecar::new(
            "accounts.cbor",
            Digest::of_bytes(sidecar_bytes),
            u64::try_from(sidecar_bytes.len()).expect("sidecar size fits u64"),
        )
        .expect("valid sidecar")];

        let mut observed = false;
        let generation = transaction
            .publish_with_sidecars_inner(
                Digest::of_bytes(base_bytes),
                &sidecars,
                |id, final_path, published_directory| {
                    observed = true;
                    assert!(
                        !stage_path.exists(),
                        "the staging name must disappear in the same atomic rename"
                    );

                    let open_metadata = published_directory
                        .metadata()
                        .expect("stat retained publication descriptor");
                    let visible_metadata =
                        std::fs::metadata(final_path).expect("stat first-visible final directory");
                    assert_eq!(visible_metadata.mode() & 0o7777, IMMUTABLE_DIR_MODE);
                    assert_eq!(visible_metadata.dev(), stage_metadata.dev());
                    assert_eq!(visible_metadata.ino(), stage_metadata.ino());
                    assert_eq!(open_metadata.dev(), stage_metadata.dev());
                    assert_eq!(open_metadata.ino(), stage_metadata.ino());

                    for name in [
                        BASE_IMAGE,
                        STAGING_METADATA,
                        GENERATION_METADATA,
                        "accounts.cbor",
                    ] {
                        let metadata = std::fs::metadata(final_path.join(name))
                            .expect("stat first-visible generation file");
                        assert!(metadata.is_file());
                        assert_eq!(metadata.mode() & 0o7777, IMMUTABLE_FILE_MODE);
                    }

                    let verified = store
                        .verify_generation(id)
                        .expect("verify generation at first visibility");
                    assert_eq!(verified.directory_path(), final_path);
                },
            )
            .expect("complete observed publication");
        assert!(observed, "post-rename observation point was reached");
        assert_eq!(
            generation.generation().manifest().sidecars(),
            sidecars,
            "the returned generation is the first-visible verified inode"
        );
    }

    #[test]
    fn rebuilds_keep_first_winner_and_coexist_when_output_bytes_differ() {
        let (_temporary, store) = fixture();
        let generation_spec = spec(12);
        let first = publish(&store, generation_spec.clone(), b"first output");

        let rebuild = |bytes: &[u8]| {
            let transaction = store
                .try_begin_rebuild(generation_spec.clone())
                .expect("begin rebuild");
            let mut base = transaction.create_base().expect("create rebuild base");
            base.write_all(bytes).expect("write rebuild base");
            drop(base);
            transaction
                .publish(Digest::of_bytes(bytes))
                .expect("publish rebuild")
                .id()
        };

        assert_eq!(rebuild(b"first output"), first);
        let second = rebuild(b"second output");
        let third = rebuild(b"third output");
        assert_ne!(first, second);
        assert_ne!(first, third);
        assert_ne!(second, third);

        let generations = store
            .generations_for_derivation(generation_spec.derivation_key())
            .expect("lookup derivation outputs");
        let ids: Vec<_> = generations.iter().map(Generation::id).collect();
        assert_eq!(ids[0], first, "first committed output remains the winner");
        let mut alternatives = vec![second, third];
        alternatives.sort();
        assert_eq!(&ids[1..], alternatives);
        match store
            .try_begin_generation(generation_spec)
            .expect("normal cache lookup")
        {
            BeginGeneration::Existing(generation) => assert_eq!(generation.id(), first),
            BeginGeneration::Vacant(_) => panic!("normal lookup ignored canonical winner"),
        }
    }

    /// A collected generation's lease record is metadata about a tree that no
    /// longer exists, so the collection that removes the tree must remove it.
    #[test]
    fn garbage_collection_reclaims_the_lease_record_with_the_generation() {
        let (temporary, store) = fixture();
        let doomed = publish(&store, spec(41), b"collect me");
        let leases = temporary.path().join("pocket").join("cache").join("leases");
        // Acquiring a lease creates the record on demand.
        drop(store.acquire_lease(doomed).expect("lease the generation"));
        assert_eq!(std::fs::read_dir(&leases).expect("read leases").count(), 1);

        let report = store.garbage_collect().expect("collect");
        assert_eq!(report.collected, vec![doomed]);
        assert_eq!(
            std::fs::read_dir(&leases).expect("read leases").count(),
            0,
            "the lease record must not outlive its generation"
        );
    }

    /// A freshly published generation has no alias rooting it: the caller sets
    /// that only after `publish` returns. Publication must therefore hand back
    /// a held lease, or a collection racing that window deletes exactly the
    /// bytes the caller just built.
    #[test]
    fn publication_returns_a_lease_that_survives_a_concurrent_collection() {
        let (_temporary, store) = fixture();
        let transaction = match store.try_begin_generation(spec(60)).expect("begin") {
            BeginGeneration::Existing(_) => panic!("unexpected existing generation"),
            BeginGeneration::Vacant(transaction) => transaction,
        };
        let mut base = transaction.create_base().expect("create base");
        base.write_all(b"unrooted but leased").expect("write base");
        base.sync_all().expect("sync base in test");
        drop(base);
        let lease = transaction
            .publish_leased(Digest::of_bytes(b"unrooted but leased"), &[])
            .expect("publish generation");

        // Nothing roots this generation yet, and a collection runs anyway.
        let report = store.garbage_collect().expect("collect while leased");
        assert!(
            report.collected.is_empty(),
            "the publication lease must protect the generation: {report:?}"
        );
        assert_eq!(report.leased_or_busy, vec![lease.id()]);
        store
            .verify_generation(lease.id())
            .expect("the leased generation must still exist");

        // Once the caller has finished with it and set no alias, it is garbage.
        let id = lease.id();
        drop(lease);
        let report = store.garbage_collect().expect("collect after release");
        assert_eq!(report.collected, vec![id]);
    }

    /// The deduplicating early return is the same race: it hands back a
    /// generation the caller has not rooted yet.
    #[test]
    fn a_cache_hit_returns_a_lease_that_survives_a_concurrent_collection() {
        let (_temporary, store) = fixture();
        let generation_spec = spec(61);
        let published = publish(&store, generation_spec.clone(), b"cache hit");
        // Unrooted, so a collection between the two calls would remove it.
        let lease = match store
            .try_begin_generation(generation_spec)
            .expect("cache lookup")
        {
            BeginGeneration::Existing(lease) => lease,
            BeginGeneration::Vacant(_) => panic!("cache lookup missed a committed output"),
        };
        assert_eq!(lease.id(), published);

        let report = store.garbage_collect().expect("collect while leased");
        assert!(report.collected.is_empty(), "{report:?}");
        assert_eq!(report.leased_or_busy, vec![published]);
    }

    /// An alias outlives the profile that created it, and reconstructing its
    /// key needs that profile bundle. Without a way to see and drop an alias by
    /// its own ID, a resealed profile's aliases root their generations forever
    /// and collection can never reclaim the space.
    #[test]
    fn alias_roots_are_visible_and_removable_by_id() {
        let (_temporary, store) = fixture();
        let generation_spec = spec(62);
        let published = publish(&store, generation_spec, b"rooted by a stale profile");
        let key = alias(7);
        store.set_alias(&key, published).expect("root the output");

        let roots = store.alias_roots().expect("list alias roots");
        assert_eq!(roots.len(), 1);
        assert_eq!(roots[0].id, key.id());
        assert_eq!(roots[0].generation_id, published);
        assert_eq!(roots[0].profile_id, "x86_64-smp-p4k");
        assert_eq!(roots[0].platform, "linux/amd64");
        assert_eq!(roots[0].reference, key.reference());

        // Rooted, so collection must leave it alone.
        let report = store.garbage_collect().expect("rooted collection");
        assert!(report.collected.is_empty());
        assert_eq!(report.rooted, vec![published]);

        // Dropping the alias by ID alone is what makes it collectable.
        assert!(store.remove_alias_by_id(roots[0].id).expect("forget alias"));
        assert!(
            !store
                .remove_alias_by_id(roots[0].id)
                .expect("forgetting twice is not an error")
        );
        assert!(store.alias_roots().expect("list again").is_empty());
        let report = store.garbage_collect().expect("collection after forget");
        assert_eq!(report.collected, vec![published]);
    }

    /// An initialization stopped partway leaves a root that `open` rejects.
    /// It has to be completable, or the operator's only remedy is deleting a
    /// directory by hand -- but only when everything in it was put there by a
    /// store, because `--store ~/.ssh` is a typo and not permission to scatter
    /// store metadata through someone's keys.
    #[test]
    fn an_incomplete_root_is_resumable_and_an_unrelated_one_is_not() {
        let temporary = tempfile::tempdir().expect("temporary root");

        let empty = temporary.path().join("empty");
        std::fs::create_dir(&empty).expect("create empty root");
        assert!(Store::is_resumable_root(&empty).expect("inspect empty root"));

        // An initialization interrupted after part of the layout exists.
        let partial = temporary.path().join("partial");
        std::fs::create_dir(&partial).expect("create partial root");
        for name in ["generations", "staging"] {
            std::fs::create_dir(partial.join(name)).expect("create layout directory");
        }
        std::fs::write(partial.join("init.lock"), b"").expect("create layout file");
        assert!(Store::is_resumable_root(&partial).expect("inspect partial root"));

        // The likeliest residue of all: initialization publishes `init.lock`
        // through a temporary in this very directory, and ENOSPC, EDQUOT, EIO
        // or a signal leaves that temporary behind. A predicate blind to it
        // would refuse to recover the exact states it exists for.
        let interrupted = temporary.path().join("interrupted");
        std::fs::create_dir(&interrupted).expect("create interrupted root");
        std::fs::write(
            interrupted.join(format!("{FIXED_TEMP_PREFIX}0123456789abcdef")),
            b"",
        )
        .expect("leave an abandoned publication temporary");
        assert!(
            Store::is_resumable_root(&interrupted).expect("inspect interrupted root"),
            "an abandoned publication temporary is the store's own residue"
        );

        // One unrelated entry disqualifies the whole directory, however
        // store-like everything else in it looks.
        let foreign = temporary.path().join("foreign");
        std::fs::create_dir(&foreign).expect("create foreign root");
        std::fs::create_dir(foreign.join("generations")).expect("create layout directory");
        std::fs::write(foreign.join("id_ed25519"), b"PRIVATE KEY").expect("unrelated file");
        assert!(!Store::is_resumable_root(&foreign).expect("inspect foreign root"));

        // An absent path is not a resumable root; it is a fresh one.
        assert!(
            !Store::is_resumable_root(&temporary.path().join("absent"))
                .expect("inspect absent root")
        );
    }

    /// A collection interrupted between the derivation-index update and the
    /// tree removal must be finishable, not permanently fatal.
    #[test]
    fn garbage_collection_finishes_after_an_interrupted_previous_attempt() {
        let (_temporary, store) = fixture();
        let generation_spec = spec(42);
        let doomed = publish(&store, generation_spec.clone(), b"half collected");
        store
            .remove_from_derivation_index(generation_spec.derivation_key(), doomed)
            .expect("simulate the interrupted first half");

        let report = store.garbage_collect().expect("collection must finish");
        assert_eq!(report.collected, vec![doomed]);
    }

    #[test]
    fn garbage_collection_tolerates_a_concurrent_publication_in_flight() {
        let (temporary, store) = fixture();
        let rooted = publish(&store, spec(31), b"rooted output");
        let key = alias(31);
        store.set_alias(&key, rooted).expect("root the generation");

        // Reproduce the exact intermediate name publish() renames through.
        let in_flight = temporary
            .path()
            .join("pocket")
            .join("cache")
            .join("generations")
            .join(".tmp-generation-stage-".to_owned() + &"ab".repeat(32) + "-" + &"cd".repeat(16));
        std::fs::create_dir(&in_flight).expect("create in-flight publication directory");

        let report = store.garbage_collect().expect("collection must not abort");
        assert_eq!(report.publication_in_flight.len(), 1);
        assert!(report.publication_in_flight[0].starts_with(".tmp-generation-"));
        assert_eq!(report.rooted, vec![rooted]);
        assert!(report.collected.is_empty());
        assert!(
            in_flight.exists(),
            "an in-flight publication must be left alone"
        );
    }

    #[test]
    fn garbage_collection_still_refuses_an_unrecognised_generation_entry() {
        let (temporary, store) = fixture();
        let stray = temporary
            .path()
            .join("pocket")
            .join("cache")
            .join("generations")
            .join("not-a-generation");
        std::fs::create_dir(&stray).expect("create stray entry");
        let error = store
            .garbage_collect()
            .expect_err("an unrecognised entry must still abort");
        assert!(
            matches!(error, StoreError::UnsafeGarbageCollection(_)),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn garbage_collection_promotes_the_only_surviving_alternative_deterministically() {
        let (_temporary, store) = fixture();
        let generation_spec = spec(15);
        let first = publish(&store, generation_spec.clone(), b"first output");
        let rebuild = |bytes: &[u8]| {
            let transaction = store
                .try_begin_rebuild(generation_spec.clone())
                .expect("begin rebuild");
            let mut base = transaction.create_base().expect("create rebuild base");
            base.write_all(bytes).expect("write rebuild base");
            drop(base);
            transaction
                .publish(Digest::of_bytes(bytes))
                .expect("publish rebuild")
                .id()
        };
        let surviving = rebuild(b"rooted alternative");
        let discarded = rebuild(b"unrooted alternative");
        let key = alias(15);
        store
            .set_alias(&key, surviving)
            .expect("root selected alternative");

        let mut report = store.garbage_collect().expect("collect unrooted outputs");
        report.collected.sort();
        let mut expected = vec![first, discarded];
        expected.sort();
        assert_eq!(report.collected, expected);
        assert_eq!(report.rooted, vec![surviving]);

        match store
            .try_begin_generation(generation_spec.clone())
            .expect("lookup promoted winner")
        {
            BeginGeneration::Existing(generation) => assert_eq!(generation.id(), surviving),
            BeginGeneration::Vacant(_) => panic!("surviving alternative was not promoted"),
        }

        store.remove_alias(&key).expect("remove final root");
        assert_eq!(
            store
                .garbage_collect()
                .expect("collect promoted winner")
                .collected,
            vec![surviving]
        );
        assert!(
            store
                .generations_for_derivation(generation_spec.derivation_key())
                .expect("lookup removed derivation")
                .is_empty()
        );
    }

    #[test]
    fn sidecar_records_participate_in_final_identity_and_verification() {
        let (_temporary, store) = fixture();
        let generation_spec = spec(13);
        let publish_sidecar = |bytes: &[u8]| {
            let transaction = store
                .try_begin_rebuild(generation_spec.clone())
                .expect("begin sidecar rebuild");
            let mut base = transaction.create_base().expect("create base");
            base.write_all(b"same base").expect("write base");
            drop(base);
            let mut sidecar = transaction
                .create_sidecar("accounts.cbor")
                .expect("create sidecar");
            sidecar.write_all(bytes).expect("write sidecar");
            drop(sidecar);
            let records = [ImmutableSidecar::new(
                "accounts.cbor",
                Digest::of_bytes(bytes),
                u64::try_from(bytes.len()).expect("test sidecar size"),
            )
            .expect("sidecar record")];
            transaction
                .publish_with_sidecars(Digest::of_bytes(b"same base"), &records)
                .expect("publish sidecar generation")
                .id()
        };

        let first = publish_sidecar(b"first account database");
        let second = publish_sidecar(b"changed account database");
        assert_ne!(first, second);
        let verified = store
            .verify_generation(first)
            .expect("verify sidecar generation");
        assert_eq!(verified.manifest().sidecars().len(), 1);
        assert_eq!(verified.manifest().sidecars()[0].name(), "accounts.cbor");
    }

    #[test]
    fn sidecar_bytes_are_available_only_through_a_bounded_verified_lease_read() {
        let (_temporary, store) = fixture();
        let transaction = store
            .try_begin_rebuild(spec(31))
            .expect("begin sidecar generation");
        let mut base = transaction.create_base().expect("create base");
        base.write_all(b"base").expect("write base");
        drop(base);
        let expected = b"authenticated image configuration";
        let mut sidecar = transaction
            .create_sidecar("image-config.json")
            .expect("create image config");
        sidecar.write_all(expected).expect("write image config");
        drop(sidecar);
        let records = [ImmutableSidecar::new(
            "image-config.json",
            Digest::of_bytes(expected),
            u64::try_from(expected.len()).expect("test sidecar length"),
        )
        .expect("sidecar record")];
        let generation = transaction
            .publish_with_sidecars(Digest::of_bytes(b"base"), &records)
            .expect("publish generation");

        let lease = store
            .acquire_lease(generation.id())
            .expect("lease generation");
        assert_eq!(
            lease
                .read_sidecar("image-config.json", 1024)
                .expect("read verified sidecar"),
            expected
        );
        assert!(matches!(
            lease.read_sidecar("image-config.json", 4),
            Err(StoreError::SidecarTooLarge { .. })
        ));
        assert!(matches!(
            lease.read_sidecar("accounts.cbor", 1024),
            Err(StoreError::SidecarNotFound { .. })
        ));

        let generation_path = lease.generation().directory_path();
        let sidecar_path = generation_path.join("image-config.json");
        std::fs::set_permissions(generation_path, Permissions::from_mode(PRIVATE_DIR_MODE))
            .expect("make generation mutable for tamper test");
        std::fs::set_permissions(&sidecar_path, Permissions::from_mode(PRIVATE_FILE_MODE))
            .expect("make sidecar mutable for tamper test");
        std::fs::write(&sidecar_path, vec![b'X'; expected.len()]).expect("tamper sidecar bytes");
        std::fs::set_permissions(&sidecar_path, Permissions::from_mode(IMMUTABLE_FILE_MODE))
            .expect("restore sidecar mode");
        std::fs::set_permissions(generation_path, Permissions::from_mode(IMMUTABLE_DIR_MODE))
            .expect("restore generation mode");
        assert!(matches!(
            lease.read_sidecar("image-config.json", 1024),
            Err(StoreError::DigestMismatch { .. })
        ));
    }

    #[test]
    fn manifest_decode_recomputes_final_id_with_valid_record_checksum() {
        let (_temporary, store) = fixture();
        let id = publish(&store, spec(14), b"final identity bytes");
        let generation = store.verify_generation(id).expect("verify generation");
        let mut manifest = generation.manifest().clone();
        manifest.id = GenerationId::from_bytes([0x9a; 32]);
        let generation_path = store.generation_path(id);
        let manifest_path = generation_path.join(GENERATION_METADATA);
        std::fs::set_permissions(&generation_path, Permissions::from_mode(PRIVATE_DIR_MODE))
            .expect("make generation mutable");
        std::fs::set_permissions(&manifest_path, Permissions::from_mode(PRIVATE_FILE_MODE))
            .expect("make manifest writable");
        std::fs::write(&manifest_path, manifest.encode()).expect("write checksummed corruption");
        std::fs::set_permissions(&manifest_path, Permissions::from_mode(IMMUTABLE_FILE_MODE))
            .expect("restore manifest mode");
        std::fs::set_permissions(&generation_path, Permissions::from_mode(IMMUTABLE_DIR_MODE))
            .expect("restore generation mode");
        assert!(matches!(
            store.verify_generation(id),
            Err(StoreError::InvalidMetadata {
                kind: MetadataKind::Generation,
                ..
            })
        ));
    }

    #[test]
    fn prior_collapsed_platform_store_schema_is_rejected_without_migration_guessing() {
        let (_temporary, store) = fixture();
        let root = store.root_path().to_path_buf();
        let metadata_path = root.join(STORE_METADATA);
        std::fs::set_permissions(&metadata_path, Permissions::from_mode(PRIVATE_FILE_MODE))
            .expect("make store metadata writable");
        let mut payload = std::fs::read(&metadata_path).expect("read store metadata");
        payload.truncate(payload.len() - crate::codec::CHECKSUM_BYTES);
        payload[8..10].copy_from_slice(&2_u16.to_be_bytes());
        std::fs::write(&metadata_path, finish_record(payload)).expect("write prior schema record");
        std::fs::set_permissions(&metadata_path, Permissions::from_mode(IMMUTABLE_FILE_MODE))
            .expect("restore store metadata mode");
        drop(store);

        assert!(matches!(
            Store::open(ManagedUmlPath::new(root).expect("managed store root")),
            Err(StoreError::InvalidMetadata {
                kind: MetadataKind::Store,
                ..
            })
        ));
    }

    #[test]
    fn digest_failure_and_transaction_drop_never_publish() {
        let (_temporary, store) = fixture();
        let generation_spec = spec(2);
        let derivation_key = generation_spec.derivation_key();
        let transaction = match store
            .try_begin_generation(generation_spec)
            .expect("begin generation")
        {
            BeginGeneration::Vacant(transaction) => transaction,
            BeginGeneration::Existing(_) => panic!("unexpected existing generation"),
        };
        let mut base = transaction.create_base().expect("create base");
        base.write_all(b"actual").expect("write base");
        drop(base);
        assert!(matches!(
            transaction.publish(Digest::of_bytes(b"expected")),
            Err(StoreError::DigestMismatch { .. })
        ));
        assert!(
            store
                .generations_for_derivation(derivation_key)
                .expect("lookup failed derivation")
                .is_empty()
        );
        assert!(
            list_names(&store.staging, &store.root_path.join("staging"))
                .expect("list staging")
                .is_empty()
        );
    }

    #[test]
    fn active_transaction_is_busy_and_not_recovered() {
        let (_temporary, store) = fixture();
        let generation_spec = spec(3);
        let derivation_key = generation_spec.derivation_key();
        let transaction = match store
            .try_begin_generation(generation_spec.clone())
            .expect("begin generation")
        {
            BeginGeneration::Vacant(transaction) => transaction,
            BeginGeneration::Existing(_) => panic!("unexpected existing generation"),
        };
        assert!(matches!(
            store.try_begin_generation(generation_spec),
            Err(StoreError::DerivationBusy(found)) if found == derivation_key
        ));
        let report = store.recover().expect("recover while active");
        assert_eq!(report.busy_staging, vec![transaction.staging_path()]);
        assert!(report.removed_staging.is_empty());
        drop(transaction);
    }

    #[test]
    fn active_publication_temp_is_busy_and_transaction_drop_cleans_it() {
        let (_temporary, store) = fixture();
        let mut transaction = match store.try_begin_generation(spec(19)).expect("begin") {
            BeginGeneration::Vacant(transaction) => transaction,
            BeginGeneration::Existing(_) => panic!("unexpected existing generation"),
        };
        let stage_path = transaction.staging_path();
        let temp_name = format!("{GENERATION_TEMP_PREFIX}{}", transaction.stage_name);
        let temp_path = store.root_path.join("generations").join(&temp_name);
        rename_noreplace_at(
            &store.staging,
            &transaction.stage_name,
            &store.generations,
            &temp_name,
            &temp_path,
        )
        .expect("transfer active transaction to publication temp");
        transaction.generation_temp_name = Some(temp_name);

        let report = store
            .recover()
            .expect("recover while publication temp is active");
        assert_eq!(report.busy_staging, vec![temp_path.clone()]);
        assert!(report.removed_staging.is_empty());
        assert!(temp_path.exists());
        assert!(!stage_path.exists());

        drop(transaction);
        assert!(
            !temp_path.exists(),
            "transaction drop must clean its current publication-temp location"
        );
    }

    #[test]
    fn recovery_removes_a_crash_abandoned_stage() {
        let (_temporary, store) = fixture();
        let mut transaction = match store.try_begin_generation(spec(4)).expect("begin") {
            BeginGeneration::Vacant(transaction) => transaction,
            BeginGeneration::Existing(_) => panic!("unexpected existing generation"),
        };
        let stage_path = transaction.staging_path();
        transaction.clean_on_drop = false;
        drop(transaction);
        assert!(stage_path.exists());
        let report = store.recover().expect("recover abandoned staging");
        assert_eq!(report.removed_staging, vec![stage_path.clone()]);
        assert!(!stage_path.exists());
    }

    #[test]
    fn recovery_removes_crash_abandoned_publication_temps() {
        let (_temporary, store) = fixture();
        let abandon = |generation_spec: GenerationSpec, mode: u32| {
            let mut transaction = match store
                .try_begin_generation(generation_spec)
                .expect("begin publication-temp fault injection")
            {
                BeginGeneration::Vacant(transaction) => transaction,
                BeginGeneration::Existing(_) => panic!("unexpected existing generation"),
            };
            let stage_path = transaction.staging_path();
            let temp_name = format!("{GENERATION_TEMP_PREFIX}{}", transaction.stage_name);
            let temp_path = store.root_path.join("generations").join(&temp_name);
            rename_noreplace_at(
                &store.staging,
                &transaction.stage_name,
                &store.generations,
                &temp_name,
                &temp_path,
            )
            .expect("inject crash after staging transfer");
            transaction.generation_temp_name = Some(temp_name);
            store
                .generations
                .sync_all()
                .expect("sync injected publication-temp name");
            store
                .staging
                .sync_all()
                .expect("sync injected staging-name removal");
            if mode == IMMUTABLE_DIR_MODE {
                set_mode(&transaction.stage, mode, &temp_path)
                    .expect("inject crash after publication-temp seal");
                transaction
                    .stage
                    .sync_all()
                    .expect("sync injected publication-temp seal");
            }
            transaction.clean_on_drop = false;
            drop(transaction);

            assert!(!stage_path.exists());
            assert_eq!(
                std::fs::metadata(&temp_path)
                    .expect("stat abandoned publication temp")
                    .mode()
                    & 0o7777,
                mode
            );
            temp_path
        };

        let mut abandoned = vec![
            abandon(spec(17), PRIVATE_DIR_MODE),
            abandon(spec(18), IMMUTABLE_DIR_MODE),
        ];
        abandoned.sort();
        let report = store
            .recover()
            .expect("recover abandoned publication temps");
        assert_eq!(report.removed_staging, abandoned);
        assert!(report.blocked_entries.is_empty());
        for path in report.removed_staging {
            assert!(!path.exists());
        }
    }

    #[test]
    fn recovery_finishes_a_verified_post_rename_publication() {
        let (_temporary, store) = fixture();
        let id = publish(&store, spec(5), b"complete but not mode-finalized");
        let generation_path = store.generation_path(id);
        std::fs::set_permissions(&generation_path, Permissions::from_mode(PRIVATE_DIR_MODE))
            .expect("inject post-rename crash mode");
        assert!(store.verify_generation(id).is_err());
        let report = store.recover().expect("finish interrupted publication");
        assert_eq!(report.completed_publications, vec![id]);
        assert!(report.blocked_entries.is_empty());
        assert!(store.verify_generation(id).is_ok());
    }

    #[test]
    fn recovery_does_not_remove_unverifiable_staging() {
        let (_temporary, store) = fixture();
        let mut transaction = match store.try_begin_generation(spec(6)).expect("begin") {
            BeginGeneration::Vacant(transaction) => transaction,
            BeginGeneration::Existing(_) => panic!("unexpected existing generation"),
        };
        let stage_path = transaction.staging_path();
        let metadata_path = stage_path.join(STAGING_METADATA);
        transaction.clean_on_drop = false;
        drop(transaction);
        std::fs::set_permissions(&metadata_path, Permissions::from_mode(PRIVATE_FILE_MODE))
            .expect("make staging metadata writable");
        let mut metadata = OpenOptions::new()
            .write(true)
            .open(&metadata_path)
            .expect("open staging metadata");
        metadata
            .write_all(b"corrupt")
            .expect("corrupt staging metadata");
        metadata.sync_all().expect("sync staging corruption");
        std::fs::set_permissions(&metadata_path, Permissions::from_mode(IMMUTABLE_FILE_MODE))
            .expect("restore staging metadata mode");

        let report = store.recover().expect("conservative recovery");
        assert_eq!(report.blocked_entries, vec![stage_path.clone()]);
        assert!(report.removed_staging.is_empty());
        assert!(stage_path.exists());
    }

    #[test]
    fn aliases_leases_and_retained_cows_are_independent_gc_roots() {
        let (temporary, store) = fixture();
        let aliased_id = publish(&store, spec(20), b"aliased");
        let leased_id = publish(&store, spec(30), b"leased");
        let retained_id = publish(&store, spec(40), b"retained");

        let alias_key = alias(1);
        store.set_alias(&alias_key, aliased_id).expect("set alias");
        let live_lease = store.acquire_lease(leased_id).expect("lease generation");

        let retained_lease = store
            .acquire_lease(retained_id)
            .expect("lease retained base");
        let cow_path = temporary.path().join("pocket").join("retained.cow");
        std::fs::write(&cow_path, b"cow bytes").expect("write retained COW");
        std::fs::set_permissions(&cow_path, Permissions::from_mode(PRIVATE_FILE_MODE))
            .expect("make retained COW private");
        let retained = store
            .register_retained_cow(
                &retained_lease,
                ManagedUmlPath::new(&cow_path).expect("managed COW path"),
                Digest::of_bytes(b"cow bytes"),
                RetainedCowState::Clean,
            )
            .expect("register retained COW");
        drop(retained_lease);
        let resumed = store
            .lease_retained_cow(retained.id())
            .expect("verify retained COW and backing lease");
        assert_eq!(resumed.generation_lease().id(), retained_id);
        assert_eq!(resumed.retained(), &retained);
        drop(resumed);

        let report = store.garbage_collect().expect("rooted GC pass");
        assert!(report.collected.is_empty());
        let mut expected_rooted = vec![aliased_id, retained_id];
        expected_rooted.sort();
        assert_eq!(report.rooted, expected_rooted);
        assert_eq!(report.leased_or_busy, vec![leased_id]);

        store.remove_alias(&alias_key).expect("remove alias");
        drop(live_lease);
        store
            .remove_retained_cow(retained.id())
            .expect("remove retained root");
        let mut report = store.garbage_collect().expect("unrooted GC pass");
        report.collected.sort();
        let mut expected = vec![aliased_id, leased_id, retained_id];
        expected.sort();
        assert_eq!(report.collected, expected);
    }

    #[test]
    fn mutated_retained_cow_is_rejected_but_still_roots_its_base() {
        let (temporary, store) = fixture();
        let generation_id = publish(&store, spec(45), b"retained backing");
        let lease = store.acquire_lease(generation_id).expect("lease base");
        let cow_path = temporary.path().join("pocket").join("mutated.cow");
        std::fs::write(&cow_path, b"original COW").expect("write COW");
        std::fs::set_permissions(&cow_path, Permissions::from_mode(PRIVATE_FILE_MODE))
            .expect("make COW private");
        let retained = store
            .register_retained_cow(
                &lease,
                ManagedUmlPath::new(&cow_path).expect("managed COW path"),
                Digest::of_bytes(b"original COW"),
                RetainedCowState::CrashDirty,
            )
            .expect("register COW");
        drop(lease);
        std::fs::write(&cow_path, b"mutated COW").expect("mutate COW");
        assert!(matches!(
            store.lease_retained_cow(retained.id()),
            Err(StoreError::SizeMismatch { .. } | StoreError::DigestMismatch { .. })
        ));
        let report = store.garbage_collect().expect("GC with retained root");
        assert_eq!(report.rooted, vec![generation_id]);
        assert!(report.collected.is_empty());
    }

    #[test]
    fn alias_replacement_changes_only_the_named_root() {
        let (_temporary, store) = fixture();
        let old = publish(&store, spec(50), b"old");
        let new = publish(&store, spec(60), b"new");
        let key = alias(2);
        store.set_alias(&key, old).expect("set old alias");
        assert_eq!(store.alias_target(&key).expect("read old alias"), old);
        store.set_alias(&key, new).expect("replace alias");
        assert_eq!(store.alias_target(&key).expect("read new alias"), new);
        let report = store.garbage_collect().expect("collect old generation");
        assert_eq!(report.collected, vec![old]);
        assert_eq!(report.rooted, vec![new]);
    }

    #[test]
    fn alias_cannot_cross_profile_revision_boundaries() {
        let (_temporary, store) = fixture();
        let id = publish(&store, spec(65), b"profile-qualified");
        let wrong_revision = AliasKey::new(
            "x86_64-smp-p4k",
            digest(99),
            "docker.io/library/test:wrong-revision",
            Platform::new("linux", "amd64", None, None, Vec::new())
                .expect("valid requested platform"),
            "oci-selector-v1",
        )
        .expect("valid alias key");
        assert!(matches!(
            store.set_alias(&wrong_revision, id),
            Err(StoreError::InvalidInput {
                field: "alias target",
                ..
            })
        ));
        assert!(matches!(
            store.alias_target(&wrong_revision),
            Err(StoreError::AliasNotFound)
        ));
    }

    #[test]
    fn corrupt_root_metadata_aborts_gc_before_any_deletion() {
        let (_temporary, store) = fixture();
        let rooted = publish(&store, spec(70), b"rooted");
        let unrooted = publish(&store, spec(80), b"unrooted");
        let key = alias(3);
        store.set_alias(&key, rooted).expect("set alias");
        let alias_path = store.alias_path(key.id());
        std::fs::set_permissions(&alias_path, Permissions::from_mode(0o600))
            .expect("make alias writable");
        let mut file = OpenOptions::new()
            .write(true)
            .open(&alias_path)
            .expect("open alias for corruption");
        file.seek(SeekFrom::Start(12)).expect("seek alias");
        file.write_all(&[0xff]).expect("corrupt alias");
        file.sync_all().expect("sync corruption");
        std::fs::set_permissions(&alias_path, Permissions::from_mode(IMMUTABLE_FILE_MODE))
            .expect("restore alias mode");

        assert!(matches!(
            store.garbage_collect(),
            Err(StoreError::UnsafeGarbageCollection(_))
        ));
        assert!(store.generation_path(rooted).exists());
        assert!(store.generation_path(unrooted).exists());
    }

    #[test]
    fn corrupt_unrooted_generation_is_preserved_for_diagnosis() {
        let (_temporary, store) = fixture();
        let id = publish(&store, spec(85), b"corrupt generation");
        let generation_path = store.generation_path(id);
        let manifest_path = generation_path.join(GENERATION_METADATA);
        std::fs::set_permissions(&generation_path, Permissions::from_mode(PRIVATE_DIR_MODE))
            .expect("make generation mutable for fault injection");
        std::fs::set_permissions(&manifest_path, Permissions::from_mode(PRIVATE_FILE_MODE))
            .expect("make manifest writable for fault injection");
        let mut file = OpenOptions::new()
            .write(true)
            .open(&manifest_path)
            .expect("open manifest for corruption");
        file.seek(SeekFrom::Start(16)).expect("seek manifest");
        file.write_all(&[0xff]).expect("corrupt manifest");
        file.sync_all().expect("sync manifest corruption");
        std::fs::set_permissions(&manifest_path, Permissions::from_mode(IMMUTABLE_FILE_MODE))
            .expect("restore manifest mode");
        std::fs::set_permissions(&generation_path, Permissions::from_mode(IMMUTABLE_DIR_MODE))
            .expect("restore generation mode");

        let report = store.garbage_collect().expect("conservative GC");
        assert_eq!(report.corrupt_unrooted, vec![id]);
        assert!(report.collected.is_empty());
        assert!(generation_path.exists());
    }

    #[test]
    fn generation_symlink_substitution_is_rejected() {
        let (temporary, store) = fixture();
        let id = publish(&store, spec(90), b"base");
        let generation_path = store.generation_path(id);
        let base_path = generation_path.join(BASE_IMAGE);
        std::fs::set_permissions(&generation_path, Permissions::from_mode(PRIVATE_DIR_MODE))
            .expect("make generation mutable for fault injection");
        std::fs::remove_file(&base_path).expect("remove base for fault injection");
        let foreign = temporary.path().join("foreign-base");
        std::fs::write(&foreign, b"base").expect("write foreign base");
        symlink(&foreign, &base_path).expect("substitute symlink");
        std::fs::set_permissions(&generation_path, Permissions::from_mode(IMMUTABLE_DIR_MODE))
            .expect("restore generation mode");
        assert!(matches!(
            store.verify_generation(id),
            Err(StoreError::Symlink { .. })
        ));
    }

    #[test]
    fn alias_moves_and_gc_are_serialized_under_concurrency() {
        let (_temporary, store) = fixture();
        let first = publish(&store, spec(100), b"first");
        let second = publish(&store, spec(110), b"second");
        let key = alias(4);
        store.set_alias(&key, first).expect("initial alias");
        let first_lease = store.acquire_lease(first).expect("pin first during race");
        let second_lease = store.acquire_lease(second).expect("pin second during race");
        let store = Arc::new(store);
        let barrier = Arc::new(Barrier::new(3));

        let writer_store = Arc::clone(&store);
        let writer_key = key.clone();
        let writer_barrier = Arc::clone(&barrier);
        let writer = thread::spawn(move || {
            writer_barrier.wait();
            for index in 0..64 {
                let target = if index % 2 == 0 { second } else { first };
                writer_store
                    .set_alias(&writer_key, target)
                    .expect("move alias concurrently");
            }
        });

        let reader_store = Arc::clone(&store);
        let reader_key = key.clone();
        let reader_barrier = Arc::clone(&barrier);
        let reader = thread::spawn(move || {
            reader_barrier.wait();
            for _ in 0..64 {
                let lease = reader_store
                    .lease_alias(&reader_key)
                    .expect("lease alias concurrently");
                assert!(lease.id() == first || lease.id() == second);
            }
        });

        barrier.wait();
        for _ in 0..16 {
            let report = store.garbage_collect().expect("concurrent conservative GC");
            assert!(report.corrupt_unrooted.is_empty());
        }
        writer.join().expect("writer thread");
        reader.join().expect("reader thread");
        let final_target = store.alias_target(&key).expect("final alias");
        assert!(final_target == first || final_target == second);
        assert!(store.verify_generation(final_target).is_ok());
        drop(first_lease);
        drop(second_lease);
    }
}
