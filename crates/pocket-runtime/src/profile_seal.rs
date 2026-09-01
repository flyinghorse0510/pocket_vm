use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use nix::{
    errno::Errno,
    fcntl::{RenameFlags, renameat2},
};
use pocket_core::ManagedUmlPath;
use serde::Serialize;
use sha2::{Digest as _, Sha256};

use crate::{
    ArtifactDigest, ArtifactManifest, ArtifactSpec, BuilderToolContract, ManifestError,
    PROFILE_MANIFEST_FILE, ProfileManifest, VerifiedProfile,
    manifest::{read_bounded, reject_file_capability, validate_manifest},
};

const MAX_TEMPLATE_BYTES: usize = 1024 * 1024;
const MAX_SOURCE_ARTIFACT_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const ZERO_DIGEST: [u8; 32] = [0; 32];
const CONTRACT_DOMAIN: &[u8] = b"pocket-guest-contract\0v1\0";

const GUARD_PATH: &str = "host/pocket-guard";
const UML_PATH: &str = "host/linux";
const SKOPEO_PATH: &str = "host/skopeo";
const NETWORK_HELPER_PATH: &str = "host/slirp4netns";
const REGISTRY_CA_PATH: &str = "host/registry-ca.pem";
const WORKLOAD_INITRAMFS_PATH: &str = "guest/workload.cpio";
const BUILDER_INITRAMFS_PATH: &str = "guest/builder.cpio";
const VALIDATOR_INITRAMFS_PATH: &str = "guest/validator.cpio";
const MKE2FS_PATH: &str = "host/mke2fs";
const E2FSCK_PATH: &str = "host/e2fsck";
const MKE2FS_CONFIG_PATH: &str = "host/mke2fs.conf";
const E2FSCK_CONFIG_PATH: &str = "host/e2fsck.conf";
const KERNEL_CONFIG_PATH: &str = "config/linux.config";

/// Exact build outputs copied into one immutable release-profile revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileArtifactSources {
    pub guard: PathBuf,
    pub uml: PathBuf,
    pub skopeo: PathBuf,
    /// Unprivileged userspace network stack for the guest's vector device.
    pub network_helper: PathBuf,
    pub registry_ca_bundle: PathBuf,
    pub workload_initramfs: PathBuf,
    pub builder_initramfs: PathBuf,
    pub validator_initramfs: PathBuf,
    pub mke2fs: PathBuf,
    pub e2fsck: PathBuf,
    pub mke2fs_config: PathBuf,
    pub e2fsck_config: PathBuf,
    pub normalized_kernel_config: PathBuf,
}

/// Inputs to deterministic, content-addressed profile publication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileSealRequest {
    /// Strict JSON template. Its revision, identities, sizes, and digests must
    /// be zero placeholders; all semantic policy fields are authoritative.
    pub template: PathBuf,
    /// Existing non-symlink collection root. Output is
    /// `<root>/<profile-id>/<revision-hex>`.
    pub output_parent: ManagedUmlPath,
    pub artifacts: ProfileArtifactSources,
    /// Identity measured from `/usr/bin/umoci` while constructing the exact
    /// builder initramfs.
    pub umoci: BuilderToolContract,
}

/// A bundle that was verified again at its final published pathname.
#[derive(Debug)]
pub struct SealedProfile {
    bundle_root: ManagedUmlPath,
    profile: VerifiedProfile,
    newly_published: bool,
}

impl SealedProfile {
    #[must_use]
    pub fn bundle_root(&self) -> &ManagedUmlPath {
        &self.bundle_root
    }

    #[must_use]
    pub const fn profile(&self) -> &VerifiedProfile {
        &self.profile
    }

    #[must_use]
    pub const fn newly_published(&self) -> bool {
        self.newly_published
    }
}

/// Assemble, seal, atomically publish, and reload one exact profile revision.
pub fn seal_profile_bundle(request: &ProfileSealRequest) -> Result<SealedProfile, ManifestError> {
    validate_publish_directory(request.output_parent.as_path(), "profile output parent")?;
    validate_umoci_request(&request.umoci)?;

    let template_path = exact_regular_path(&request.template, "profile template")?;
    let template_bytes = read_bounded(&template_path, MAX_TEMPLATE_BYTES)?;
    let mut manifest: ProfileManifest =
        serde_json::from_slice(&template_bytes).map_err(|source| ManifestError::Json {
            path: template_path,
            source,
        })?;
    validate_template_placeholders(&manifest)?;

    let profile_parent_path = request.output_parent.as_path().join(&manifest.profile_id);
    ensure_publish_subdirectory(&profile_parent_path)?;
    let profile_parent = ManagedUmlPath::new(&profile_parent_path)?;

    let mut stage = StageDirectory::create(profile_parent.as_path())?;
    for child in ["host", "guest", "config"] {
        create_private_directory(&stage.path().join(child))?;
    }

    manifest.artifacts = ArtifactManifest {
        guard: copy_artifact(&request.artifacts.guard, stage.path(), GUARD_PATH, 0o555)?,
        uml: copy_artifact(&request.artifacts.uml, stage.path(), UML_PATH, 0o555)?,
        skopeo: copy_artifact(&request.artifacts.skopeo, stage.path(), SKOPEO_PATH, 0o555)?,
        network_helper: copy_artifact(
            &request.artifacts.network_helper,
            stage.path(),
            NETWORK_HELPER_PATH,
            0o555,
        )?,
        registry_ca_bundle: copy_artifact(
            &request.artifacts.registry_ca_bundle,
            stage.path(),
            REGISTRY_CA_PATH,
            0o444,
        )?,
        workload_initramfs: copy_artifact(
            &request.artifacts.workload_initramfs,
            stage.path(),
            WORKLOAD_INITRAMFS_PATH,
            0o444,
        )?,
        builder_initramfs: copy_artifact(
            &request.artifacts.builder_initramfs,
            stage.path(),
            BUILDER_INITRAMFS_PATH,
            0o444,
        )?,
        validator_initramfs: copy_artifact(
            &request.artifacts.validator_initramfs,
            stage.path(),
            VALIDATOR_INITRAMFS_PATH,
            0o444,
        )?,
        mke2fs: copy_artifact(&request.artifacts.mke2fs, stage.path(), MKE2FS_PATH, 0o555)?,
        e2fsck: copy_artifact(&request.artifacts.e2fsck, stage.path(), E2FSCK_PATH, 0o555)?,
        mke2fs_config: copy_artifact(
            &request.artifacts.mke2fs_config,
            stage.path(),
            MKE2FS_CONFIG_PATH,
            0o444,
        )?,
        e2fsck_config: copy_empty_artifact(
            &request.artifacts.e2fsck_config,
            stage.path(),
            E2FSCK_CONFIG_PATH,
            0o444,
        )?,
        normalized_kernel_config: copy_artifact(
            &request.artifacts.normalized_kernel_config,
            stage.path(),
            KERNEL_CONFIG_PATH,
            0o444,
        )?,
    };

    manifest.builder.required_tools = vec![request.umoci.clone()];
    bind_build_and_contract_identities(&mut manifest)?;
    let _ = validate_manifest(&manifest)?;
    manifest.profile_revision = manifest.computed_revision()?;
    write_manifest(stage.path(), &manifest)?;

    // Verify the staged bytes through the same path used for every launch.
    let stage_managed = ManagedUmlPath::new(stage.path())?;
    let staged_profile = VerifiedProfile::load(stage_managed)?;
    if staged_profile.manifest() != &manifest {
        return Err(ManifestError::invalid(
            "profile",
            "staged profile changed during verification",
        ));
    }
    drop(staged_profile);

    stage.make_immutable()?;
    let final_path = profile_parent
        .as_path()
        .join(manifest.profile_revision.hexadecimal());
    let final_managed = ManagedUmlPath::new(&final_path)?;
    let profile_parent_fd = File::open(profile_parent.as_path()).map_err(|error| {
        ManifestError::io(
            "open profile collection for publication",
            profile_parent.as_path(),
            error,
        )
    })?;
    let stage_name = stage
        .path()
        .file_name()
        .ok_or_else(|| ManifestError::invalid("profile staging", "missing staging basename"))?;
    let final_name = final_path.file_name().ok_or_else(|| {
        ManifestError::invalid("profile publication", "missing revision basename")
    })?;
    match renameat2(
        &profile_parent_fd,
        stage_name,
        &profile_parent_fd,
        final_name,
        RenameFlags::RENAME_NOREPLACE,
    ) {
        Ok(()) => stage.disarm(),
        Err(Errno::EEXIST) => {
            return load_existing(final_managed, &manifest, false);
        }
        Err(error) => {
            return Err(ManifestError::io(
                "atomically publish profile bundle without replacement",
                &final_path,
                std::io::Error::from_raw_os_error(error as i32),
            ));
        }
    }
    sync_directory(profile_parent.as_path())?;
    load_existing(final_managed, &manifest, true)
}

fn validate_umoci_request(tool: &BuilderToolContract) -> Result<(), ManifestError> {
    if tool.role != "umoci" {
        return Err(ManifestError::invalid(
            "builder.required_tools.role",
            "release sealer accepts only the measured umoci role",
        ));
    }
    if tool.sha256.len() != 64
        || tool
            .sha256
            .bytes()
            .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
    {
        return Err(ManifestError::invalid(
            "builder.required_tools.sha256",
            "must be 64 lowercase hexadecimal characters",
        ));
    }
    if tool.version.is_empty()
        || tool.version.len() > 256
        || tool.version.chars().any(char::is_control)
    {
        return Err(ManifestError::invalid(
            "builder.required_tools.version",
            "must be a bounded, measured version line",
        ));
    }
    Ok(())
}

fn validate_template_placeholders(manifest: &ProfileManifest) -> Result<(), ManifestError> {
    if manifest.profile_revision.as_bytes() != ZERO_DIGEST {
        return Err(ManifestError::invalid(
            "profile_revision",
            "profile template must contain the all-zero placeholder",
        ));
    }
    for (field, value) in [
        ("hello.guest_contract_id", &manifest.hello.guest_contract_id),
        ("hello.init_build_id", &manifest.hello.init_build_id),
        ("hello.kernel_build_id", &manifest.hello.kernel_build_id),
        (
            "builder.hello.guest_contract_id",
            &manifest.builder.hello.guest_contract_id,
        ),
        (
            "builder.hello.init_build_id",
            &manifest.builder.hello.init_build_id,
        ),
        (
            "builder.hello.kernel_build_id",
            &manifest.builder.hello.kernel_build_id,
        ),
        (
            "validator.hello.guest_contract_id",
            &manifest.validator.hello.guest_contract_id,
        ),
        (
            "validator.hello.init_build_id",
            &manifest.validator.hello.init_build_id,
        ),
        (
            "validator.hello.kernel_build_id",
            &manifest.validator.hello.kernel_build_id,
        ),
    ] {
        if value != &"00".repeat(32) {
            return Err(ManifestError::invalid(
                field,
                "profile template identity must be the all-zero placeholder",
            ));
        }
    }
    if manifest.builder.required_tools.len() != 1
        || manifest.builder.required_tools[0].role != "umoci"
    {
        return Err(ManifestError::invalid(
            "builder.required_tools",
            "profile template must contain one umoci placeholder",
        ));
    }

    let artifacts = &manifest.artifacts;
    for (field, artifact, expected_path) in [
        ("artifacts.guard", &artifacts.guard, GUARD_PATH),
        ("artifacts.uml", &artifacts.uml, UML_PATH),
        ("artifacts.skopeo", &artifacts.skopeo, SKOPEO_PATH),
        (
            "artifacts.network_helper",
            &artifacts.network_helper,
            NETWORK_HELPER_PATH,
        ),
        (
            "artifacts.registry_ca_bundle",
            &artifacts.registry_ca_bundle,
            REGISTRY_CA_PATH,
        ),
        (
            "artifacts.workload_initramfs",
            &artifacts.workload_initramfs,
            WORKLOAD_INITRAMFS_PATH,
        ),
        (
            "artifacts.builder_initramfs",
            &artifacts.builder_initramfs,
            BUILDER_INITRAMFS_PATH,
        ),
        (
            "artifacts.validator_initramfs",
            &artifacts.validator_initramfs,
            VALIDATOR_INITRAMFS_PATH,
        ),
        ("artifacts.mke2fs", &artifacts.mke2fs, MKE2FS_PATH),
        ("artifacts.e2fsck", &artifacts.e2fsck, E2FSCK_PATH),
        (
            "artifacts.mke2fs_config",
            &artifacts.mke2fs_config,
            MKE2FS_CONFIG_PATH,
        ),
        (
            "artifacts.e2fsck_config",
            &artifacts.e2fsck_config,
            E2FSCK_CONFIG_PATH,
        ),
        (
            "artifacts.normalized_kernel_config",
            &artifacts.normalized_kernel_config,
            KERNEL_CONFIG_PATH,
        ),
    ] {
        if artifact.path != expected_path
            || artifact.size != 0
            || artifact.sha256.as_bytes() != ZERO_DIGEST
        {
            return Err(ManifestError::invalid(
                field,
                format!("template requires path {expected_path:?}, zero size, and zero digest"),
            ));
        }
    }
    Ok(())
}

fn bind_build_and_contract_identities(manifest: &mut ProfileManifest) -> Result<(), ManifestError> {
    let kernel_build_id = manifest.artifacts.uml.sha256.hexadecimal();
    manifest.hello.kernel_build_id.clone_from(&kernel_build_id);
    manifest
        .builder
        .hello
        .kernel_build_id
        .clone_from(&kernel_build_id);
    manifest
        .validator
        .hello
        .kernel_build_id
        .clone_from(&kernel_build_id);
    manifest.hello.init_build_id = manifest.artifacts.workload_initramfs.sha256.hexadecimal();
    manifest.builder.hello.init_build_id =
        manifest.artifacts.builder_initramfs.sha256.hexadecimal();
    manifest.validator.hello.init_build_id =
        manifest.artifacts.validator_initramfs.sha256.hexadecimal();
    manifest.hello.guest_contract_id = contract_identity(manifest, "workload")?;
    manifest.builder.hello.guest_contract_id = contract_identity(manifest, "builder")?;
    manifest.validator.hello.guest_contract_id = contract_identity(manifest, "validator")?;
    Ok(())
}

#[derive(Serialize)]
struct CanonicalGuestContract<'a> {
    schema: &'static str,
    role: &'a str,
    protocol_major: u16,
    protocol_minor: u16,
    host_elf_machine: u16,
    oci_architecture: &'a str,
    guest_page_size: u32,
    contracts: &'a crate::Contracts,
    required_features: &'a [String],
    manifest_schema: Option<&'a str>,
}

fn contract_identity(manifest: &ProfileManifest, role: &str) -> Result<String, ManifestError> {
    let (features, manifest_schema) = match role {
        "builder" => (
            manifest.builder.hello.required_features.as_slice(),
            Some(manifest.builder.manifest_schema.as_str()),
        ),
        "validator" => (
            manifest.validator.hello.required_features.as_slice(),
            Some(manifest.validator.manifest_schema.as_str()),
        ),
        _ => (manifest.hello.required_features.as_slice(), None),
    };
    let identity = CanonicalGuestContract {
        schema: "pocket-guest-contract-v1",
        role,
        protocol_major: pocket_protocol::PROTOCOL_MAJOR,
        protocol_minor: pocket_protocol::PROTOCOL_MINOR,
        host_elf_machine: manifest.host_elf_machine,
        oci_architecture: &manifest.oci_architecture,
        guest_page_size: manifest.guest_page_size,
        contracts: &manifest.contracts,
        required_features: features,
        manifest_schema,
    };
    let encoded = serde_json::to_vec(&identity).map_err(|error| {
        ManifestError::invalid(
            "guest_contract_id",
            format!("canonicalization failed: {error}"),
        )
    })?;
    let mut hasher = Sha256::new();
    hasher.update(CONTRACT_DOMAIN);
    hasher.update(encoded);
    Ok(hex::encode(hasher.finalize()))
}

fn copy_artifact(
    source_path: &Path,
    bundle_root: &Path,
    relative: &str,
    mode: u32,
) -> Result<ArtifactSpec, ManifestError> {
    copy_artifact_with_content_policy(source_path, bundle_root, relative, mode, false)
}

/// Seal the one deliberately zero-byte policy artifact without weakening the
/// non-empty requirement for executable, initramfs, CA, and kernel inputs.
fn copy_empty_artifact(
    source_path: &Path,
    bundle_root: &Path,
    relative: &str,
    mode: u32,
) -> Result<ArtifactSpec, ManifestError> {
    copy_artifact_with_content_policy(source_path, bundle_root, relative, mode, true)
}

fn copy_artifact_with_content_policy(
    source_path: &Path,
    bundle_root: &Path,
    relative: &str,
    mode: u32,
    require_empty: bool,
) -> Result<ArtifactSpec, ManifestError> {
    let source_path = exact_regular_path(source_path, "release artifact source")?;
    let mut source = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW)
        .open(&source_path)
        .map_err(|error| ManifestError::io("open release artifact source", &source_path, error))?;
    reject_file_capability(&source, &source_path)?;
    let before = source.metadata().map_err(|error| {
        ManifestError::io("inspect release artifact source", &source_path, error)
    })?;
    if (require_empty && before.len() != 0)
        || (!require_empty && before.len() == 0)
        || before.len() > MAX_SOURCE_ARTIFACT_BYTES
    {
        return Err(ManifestError::invalid(
            "artifact source",
            format!(
                "{} has invalid size {} (must be {} and at most {})",
                source_path.display(),
                before.len(),
                if require_empty { "empty" } else { "non-empty" },
                MAX_SOURCE_ARTIFACT_BYTES
            ),
        ));
    }

    let destination = bundle_root.join(relative);
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW)
        .open(&destination)
        .map_err(|error| ManifestError::io("create sealed artifact", &destination, error))?;
    let mut hasher = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 128 * 1024];
    loop {
        let count = source.read(&mut buffer).map_err(|error| {
            ManifestError::io("read release artifact source", &source_path, error)
        })?;
        if count == 0 {
            break;
        }
        output
            .write_all(&buffer[..count])
            .map_err(|error| ManifestError::io("write sealed artifact", &destination, error))?;
        hasher.update(&buffer[..count]);
        total = total
            .checked_add(count as u64)
            .ok_or_else(|| ManifestError::invalid("artifact source", "copied size overflow"))?;
    }
    output
        .sync_all()
        .map_err(|error| ManifestError::io("sync sealed artifact", &destination, error))?;
    fs::set_permissions(&destination, fs::Permissions::from_mode(mode))
        .map_err(|error| ManifestError::io("seal artifact mode", &destination, error))?;
    output
        .sync_all()
        .map_err(|error| ManifestError::io("sync sealed artifact mode", &destination, error))?;

    let after = source.metadata().map_err(|error| {
        ManifestError::io("reinspect release artifact source", &source_path, error)
    })?;
    if !same_source_metadata(&before, &after) || total != before.len() {
        return Err(ManifestError::invalid(
            "artifact source",
            format!("{} changed while it was copied", source_path.display()),
        ));
    }

    Ok(ArtifactSpec {
        path: relative.to_owned(),
        sha256: ArtifactDigest::from_bytes(hasher.finalize().into()),
        size: total,
    })
}

fn same_source_metadata(before: &fs::Metadata, after: &fs::Metadata) -> bool {
    before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.len() == after.len()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec()
}

fn exact_regular_path(path: &Path, operation: &'static str) -> Result<PathBuf, ManifestError> {
    if !path.is_absolute() {
        return Err(ManifestError::ArtifactResolution {
            path: path.to_path_buf(),
        });
    }
    let metadata =
        fs::symlink_metadata(path).map_err(|error| ManifestError::io(operation, path, error))?;
    if !metadata.file_type().is_file() {
        return Err(ManifestError::ArtifactType {
            path: path.to_path_buf(),
        });
    }
    let canonical =
        fs::canonicalize(path).map_err(|error| ManifestError::io(operation, path, error))?;
    if canonical != path {
        return Err(ManifestError::ArtifactResolution {
            path: path.to_path_buf(),
        });
    }
    Ok(canonical)
}

fn validate_publish_directory(path: &Path, operation: &'static str) -> Result<(), ManifestError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| ManifestError::io(operation, path, error))?;
    if !metadata.file_type().is_dir() {
        return Err(ManifestError::ArtifactType {
            path: path.to_path_buf(),
        });
    }
    let canonical =
        fs::canonicalize(path).map_err(|error| ManifestError::io(operation, path, error))?;
    if canonical != path || metadata.uid() != nix::unistd::geteuid().as_raw() {
        return Err(ManifestError::ArtifactResolution {
            path: path.to_path_buf(),
        });
    }
    let mode = metadata.mode() & 0o7777;
    if mode & 0o022 != 0 || mode & 0o200 == 0 {
        return Err(ManifestError::ArtifactMode {
            path: path.to_path_buf(),
            mode,
            reason: "profile publication directory must be owner-writable and not group/world-writable",
        });
    }
    Ok(())
}

fn ensure_publish_subdirectory(path: &Path) -> Result<(), ManifestError> {
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    match builder.create(path) {
        Ok(()) => fs::set_permissions(path, fs::Permissions::from_mode(0o755))
            .map_err(|error| ManifestError::io("set profile collection mode", path, error))?,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => {
            return Err(ManifestError::io(
                "create profile collection directory",
                path,
                error,
            ));
        }
    }
    validate_publish_directory(path, "validate profile collection directory")
}

fn create_private_directory(path: &Path) -> Result<(), ManifestError> {
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    builder
        .create(path)
        .map_err(|error| ManifestError::io("create profile staging directory", path, error))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|error| ManifestError::io("set profile staging mode", path, error))
}

fn write_manifest(root: &Path, manifest: &ProfileManifest) -> Result<(), ManifestError> {
    let path = root.join(PROFILE_MANIFEST_FILE);
    let mut encoded = serde_json::to_vec_pretty(manifest).map_err(|error| {
        ManifestError::invalid("profile", format!("JSON serialization failed: {error}"))
    })?;
    encoded.push(b'\n');
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW)
        .open(&path)
        .map_err(|error| ManifestError::io("create profile manifest", &path, error))?;
    file.write_all(&encoded)
        .map_err(|error| ManifestError::io("write profile manifest", &path, error))?;
    file.sync_all()
        .map_err(|error| ManifestError::io("sync profile manifest", &path, error))?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o444))
        .map_err(|error| ManifestError::io("seal profile manifest mode", &path, error))?;
    file.sync_all()
        .map_err(|error| ManifestError::io("sync profile manifest mode", &path, error))
}

fn load_existing(
    root: ManagedUmlPath,
    expected: &ProfileManifest,
    newly_published: bool,
) -> Result<SealedProfile, ManifestError> {
    let profile =
        VerifiedProfile::load(root.clone()).map_err(|_| ManifestError::PublishConflict {
            path: root.as_path().to_path_buf(),
        })?;
    if profile.manifest() != expected {
        return Err(ManifestError::PublishConflict {
            path: root.as_path().to_path_buf(),
        });
    }
    Ok(SealedProfile {
        bundle_root: root,
        profile,
        newly_published,
    })
}

fn sync_directory(path: &Path) -> Result<(), ManifestError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| ManifestError::io("sync profile directory", path, error))
}

struct StageDirectory {
    path: PathBuf,
    armed: bool,
}

impl StageDirectory {
    fn create(parent: &Path) -> Result<Self, ManifestError> {
        for sequence in 0_u16..1024 {
            let path = parent.join(format!(".seal-{}-{sequence}", std::process::id()));
            let mut builder = fs::DirBuilder::new();
            builder.mode(0o700);
            match builder.create(&path) {
                Ok(()) => {
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).map_err(
                        |error| ManifestError::io("set profile staging mode", &path, error),
                    )?;
                    return Ok(Self { path, armed: true });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => {
                    return Err(ManifestError::io(
                        "create profile staging directory",
                        &path,
                        error,
                    ));
                }
            }
        }
        Err(ManifestError::invalid(
            "profile staging",
            "could not allocate a bounded unique staging directory",
        ))
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn make_immutable(&self) -> Result<(), ManifestError> {
        for path in [
            self.path.join("host"),
            self.path.join("guest"),
            self.path.join("config"),
            self.path.clone(),
        ] {
            sync_directory(&path)?;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o555))
                .map_err(|error| ManifestError::io("seal profile directory mode", &path, error))?;
            sync_directory(&path)?;
        }
        Ok(())
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for StageDirectory {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        for path in [
            self.path.join("host"),
            self.path.join("guest"),
            self.path.join("config"),
            self.path.clone(),
        ] {
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o700));
        }
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::fs::{PermissionsExt, symlink},
        path::PathBuf,
    };

    use pocket_core::ManagedUmlPath;
    use tempfile::tempdir;

    use super::{
        BUILDER_INITRAMFS_PATH, E2FSCK_CONFIG_PATH, E2FSCK_PATH, GUARD_PATH, KERNEL_CONFIG_PATH,
        MKE2FS_CONFIG_PATH, MKE2FS_PATH, NETWORK_HELPER_PATH, ProfileArtifactSources,
        ProfileSealRequest, REGISTRY_CA_PATH, SKOPEO_PATH, UML_PATH, VALIDATOR_INITRAMFS_PATH,
        WORKLOAD_INITRAMFS_PATH, seal_profile_bundle,
    };
    use crate::{
        ArtifactDigest, BuilderToolContract, ProfileRevision, manifest::synthetic_profile,
    };

    #[test]
    fn publishes_once_then_verifies_the_same_content_addressed_bundle() {
        let fixture = fixture();
        let first = seal_profile_bundle(&fixture.request).expect("first profile seal");
        assert!(first.newly_published());
        let first_root = first.bundle_root().as_path().to_path_buf();
        assert_eq!(
            first_root.file_name().and_then(|name| name.to_str()),
            Some(
                first
                    .profile()
                    .manifest()
                    .profile_revision
                    .hexadecimal()
                    .as_str()
            )
        );
        assert_eq!(
            first.profile().manifest().hello.kernel_build_id,
            first
                .profile()
                .manifest()
                .artifacts
                .uml
                .sha256
                .hexadecimal()
        );
        assert_eq!(
            first.profile().manifest().builder.hello.init_build_id,
            first
                .profile()
                .manifest()
                .artifacts
                .builder_initramfs
                .sha256
                .hexadecimal()
        );
        assert_eq!(
            first.profile().manifest().validator.hello.init_build_id,
            first
                .profile()
                .manifest()
                .artifacts
                .validator_initramfs
                .sha256
                .hexadecimal()
        );
        assert_eq!(first.profile().skopeo_path(), first_root.join(SKOPEO_PATH));
        assert_eq!(
            first.profile().registry_ca_bundle_path(),
            first_root.join(REGISTRY_CA_PATH)
        );
        assert_eq!(
            first.profile().e2fsck_config_path(),
            first_root.join(E2FSCK_CONFIG_PATH)
        );
        assert_eq!(
            fs::metadata(first.profile().e2fsck_config_path())
                .expect("e2fsck config metadata")
                .len(),
            0
        );
        for path in [
            first_root.clone(),
            first_root.join("host"),
            first_root.join("guest"),
            first_root.join("config"),
        ] {
            assert_eq!(
                fs::symlink_metadata(path)
                    .expect("sealed directory metadata")
                    .permissions()
                    .mode()
                    & 0o7777,
                0o555
            );
        }
        drop(first);

        let second = seal_profile_bundle(&fixture.request).expect("idempotent profile seal");
        assert!(!second.newly_published());
        assert_eq!(second.bundle_root().as_path(), first_root);
    }

    #[test]
    fn rejects_a_symlink_source_and_removes_staging_content() {
        let mut fixture = fixture();
        let real_skopeo = fixture.request.artifacts.skopeo.clone();
        let linked = fixture.sources.join("linked-skopeo");
        symlink(&real_skopeo, &linked).expect("source symlink");
        fixture.request.artifacts.skopeo = linked;
        assert!(seal_profile_bundle(&fixture.request).is_err());

        let profile_parent = fixture.output.join("x86_64-smp-p4k");
        let leftovers = fs::read_dir(profile_parent)
            .expect("profile parent")
            .collect::<Result<Vec<_>, _>>()
            .expect("profile parent entries");
        assert!(leftovers.is_empty());
    }

    #[test]
    fn rejects_nonempty_e2fsck_policy_without_weakening_other_artifact_checks() {
        let fixture = fixture();
        fs::write(
            &fixture.request.artifacts.e2fsck_config,
            b"[options]\nallow_cancellation = true\n",
        )
        .expect("replace empty e2fsck policy");
        let error = seal_profile_bundle(&fixture.request)
            .expect_err("only the exact empty e2fsck policy is supported");
        assert!(error.to_string().contains("must be empty"));
    }

    struct Fixture {
        _temporary: tempfile::TempDir,
        sources: PathBuf,
        output: PathBuf,
        request: ProfileSealRequest,
    }

    fn fixture() -> Fixture {
        let temporary = tempdir().expect("temporary directory");
        let sources = temporary.path().join("inputs");
        let output = temporary.path().join("profiles");
        fs::create_dir(&sources).expect("source directory");
        fs::create_dir(&output).expect("output directory");
        fs::set_permissions(&output, fs::Permissions::from_mode(0o755)).expect("output mode");

        let source = |name: &str| sources.join(name);
        for name in ["guard", "uml", "skopeo", "slirp4netns", "mke2fs", "e2fsck"] {
            fs::write(source(name), minimal_static_elf()).expect("static ELF source");
        }
        fs::write(source("registry-ca.pem"), certificate_fixture()).expect("CA source");
        fs::write(source("workload.cpio"), b"070701workload").expect("workload source");
        fs::write(source("builder.cpio"), b"070701builder").expect("builder source");
        fs::write(source("validator.cpio"), b"070701validator").expect("validator source");
        fs::write(
            source("mke2fs.conf"),
            b"[defaults]\nbase_features = ext_attr,filetype\n",
        )
        .expect("mke2fs config source");
        fs::write(source("e2fsck.conf"), b"").expect("empty e2fsck config source");
        fs::write(source("linux.config"), kernel_config()).expect("kernel config source");

        let template = temporary.path().join("template.json");
        let synthetic_root =
            ManagedUmlPath::new("/tmp/pocket/tests/seal-template").expect("synthetic managed root");
        let mut manifest = synthetic_profile(synthetic_root, true).manifest().clone();
        manifest.profile_revision = ProfileRevision::from_bytes([0; 32]);
        for identity in [
            &mut manifest.hello.guest_contract_id,
            &mut manifest.hello.init_build_id,
            &mut manifest.hello.kernel_build_id,
            &mut manifest.builder.hello.guest_contract_id,
            &mut manifest.builder.hello.init_build_id,
            &mut manifest.builder.hello.kernel_build_id,
            &mut manifest.validator.hello.guest_contract_id,
            &mut manifest.validator.hello.init_build_id,
            &mut manifest.validator.hello.kernel_build_id,
        ] {
            *identity = "00".repeat(32);
        }
        manifest.builder.required_tools = vec![BuilderToolContract {
            role: "umoci".to_owned(),
            sha256: "00".repeat(32),
            version: "placeholder".to_owned(),
        }];
        for (artifact, path) in [
            (&mut manifest.artifacts.guard, GUARD_PATH),
            (&mut manifest.artifacts.uml, UML_PATH),
            (&mut manifest.artifacts.skopeo, SKOPEO_PATH),
            (&mut manifest.artifacts.network_helper, NETWORK_HELPER_PATH),
            (&mut manifest.artifacts.registry_ca_bundle, REGISTRY_CA_PATH),
            (
                &mut manifest.artifacts.workload_initramfs,
                WORKLOAD_INITRAMFS_PATH,
            ),
            (
                &mut manifest.artifacts.builder_initramfs,
                BUILDER_INITRAMFS_PATH,
            ),
            (
                &mut manifest.artifacts.validator_initramfs,
                VALIDATOR_INITRAMFS_PATH,
            ),
            (&mut manifest.artifacts.mke2fs, MKE2FS_PATH),
            (&mut manifest.artifacts.e2fsck, E2FSCK_PATH),
            (&mut manifest.artifacts.mke2fs_config, MKE2FS_CONFIG_PATH),
            (&mut manifest.artifacts.e2fsck_config, E2FSCK_CONFIG_PATH),
            (
                &mut manifest.artifacts.normalized_kernel_config,
                KERNEL_CONFIG_PATH,
            ),
        ] {
            artifact.path = path.to_owned();
            artifact.sha256 = ArtifactDigest::from_bytes([0; 32]);
            artifact.size = 0;
        }
        fs::write(
            &template,
            serde_json::to_vec_pretty(&manifest).expect("template JSON"),
        )
        .expect("template");

        let request = ProfileSealRequest {
            template,
            output_parent: ManagedUmlPath::new(&output).expect("managed output"),
            artifacts: ProfileArtifactSources {
                guard: source("guard"),
                uml: source("uml"),
                skopeo: source("skopeo"),
                network_helper: source("slirp4netns"),
                registry_ca_bundle: source("registry-ca.pem"),
                workload_initramfs: source("workload.cpio"),
                builder_initramfs: source("builder.cpio"),
                validator_initramfs: source("validator.cpio"),
                mke2fs: source("mke2fs"),
                e2fsck: source("e2fsck"),
                mke2fs_config: source("mke2fs.conf"),
                e2fsck_config: source("e2fsck.conf"),
                normalized_kernel_config: source("linux.config"),
            },
            umoci: BuilderToolContract {
                role: "umoci".to_owned(),
                sha256: "ab".repeat(32),
                version: "umoci version fixture".to_owned(),
            },
        };
        Fixture {
            _temporary: temporary,
            sources,
            output,
            request,
        }
    }

    fn certificate_fixture() -> &'static [u8] {
        b"-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----\n"
    }

    fn minimal_static_elf() -> Vec<u8> {
        let mut bytes = vec![0_u8; 64 + 56];
        bytes[..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[6] = 1;
        bytes[16..18].copy_from_slice(&2_u16.to_le_bytes());
        bytes[18..20].copy_from_slice(&62_u16.to_le_bytes());
        bytes[32..40].copy_from_slice(&64_u64.to_le_bytes());
        bytes[52..54].copy_from_slice(&64_u16.to_le_bytes());
        bytes[54..56].copy_from_slice(&56_u16.to_le_bytes());
        bytes[56..58].copy_from_slice(&1_u16.to_le_bytes());
        bytes[64..68].copy_from_slice(&1_u32.to_le_bytes());
        bytes
    }

    fn kernel_config() -> String {
        let yes = [
            "CONFIG_UML",
            "CONFIG_64BIT",
            "CONFIG_X86_64",
            "CONFIG_STATIC_LINK",
            "CONFIG_LD_SCRIPT_STATIC",
            "CONFIG_BLK_DEV_INITRD",
            "CONFIG_BLK_DEV_UBD",
            "CONFIG_EXT4_FS",
            "CONFIG_EXT4_FS_POSIX_ACL",
            "CONFIG_EXT4_FS_SECURITY",
            "CONFIG_TMPFS",
            "CONFIG_PROC_FS",
            "CONFIG_SYSFS",
            "CONFIG_DEVTMPFS",
            "CONFIG_DEVTMPFS_MOUNT",
            "CONFIG_BINFMT_ELF",
            "CONFIG_BINFMT_SCRIPT",
            "CONFIG_EPOLL",
            "CONFIG_FUTEX",
            "CONFIG_TIMERFD",
            "CONFIG_EVENTFD",
            "CONFIG_MEMFD_CREATE",
            "CONFIG_SIGNALFD",
            "CONFIG_SECCOMP",
            "CONFIG_SECCOMP_FILTER",
            "CONFIG_NAMESPACES",
            "CONFIG_UTS_NS",
            "CONFIG_IPC_NS",
            "CONFIG_PID_NS",
            "CONFIG_SSL",
            "CONFIG_NULL_CHAN",
            "CONFIG_DEBUG_INFO_NONE",
            "CONFIG_SMP",
            "CONFIG_HOSTFS",
            "CONFIG_UML_NET_VECTOR",
        ];
        let no = [
            "CONFIG_BLK_DEV_UBD_SYNC",
            "CONFIG_BLK_DEV_LOOP",
            "CONFIG_BLK_DEV_NBD",
            "CONFIG_MCONSOLE",
            "CONFIG_UML_NET_VECTOR_IP_TRANSPORTS",
            "CONFIG_MODULES",
            "CONFIG_IPV6",
            "CONFIG_USER_NS",
            "CONFIG_NETDEVICES",
        ];
        let mut config = String::new();
        for setting in yes {
            config.push_str(setting);
            config.push_str("=y\n");
        }
        for setting in no {
            config.push_str("# ");
            config.push_str(setting);
            config.push_str(" is not set\n");
        }
        config.push_str("CONFIG_NR_CPUS=16\n");
        config
    }
}
