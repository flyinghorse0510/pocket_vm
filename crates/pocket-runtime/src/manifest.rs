use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    fs::{self, File},
    io::{Read, Seek, SeekFrom},
    os::{fd::AsRawFd, unix::fs::MetadataExt},
    path::{Path, PathBuf},
    str::FromStr,
};

use nix::libc;
use pocket_core::{CpuProfile, ManagedUmlPath, MemoryPolicy};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest as _, Sha256};

use crate::ManifestError;

pub const PROFILE_SCHEMA_VERSION: u16 = 3;
pub const PROFILE_MANIFEST_FILE: &str = "profile.json";
const MAX_MANIFEST_BYTES: usize = 1024 * 1024;
const MAX_CONFIG_BYTES: usize = 4 * 1024 * 1024;
const PROFILE_REVISION_DOMAIN: &[u8] = b"pocket-profile-revision\0v1\0";
const EM_X86_64: u16 = 62;

macro_rules! digest_type {
    ($name:ident) => {
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name([u8; 32]);

        impl $name {
            #[must_use]
            pub const fn from_bytes(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }

            #[must_use]
            pub const fn as_bytes(self) -> [u8; 32] {
                self.0
            }

            #[must_use]
            pub fn hexadecimal(self) -> String {
                hex::encode(self.0)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(self, formatter)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "sha256:{}", hex::encode(self.0))
            }
        }

        impl FromStr for $name {
            type Err = ManifestError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                let encoded = value.strip_prefix("sha256:").ok_or_else(|| {
                    ManifestError::invalid(
                        stringify!($name),
                        "expected sha256:<64 lowercase hexadecimal characters>",
                    )
                })?;
                if encoded.len() != 64
                    || encoded
                        .bytes()
                        .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
                {
                    return Err(ManifestError::invalid(
                        stringify!($name),
                        "expected sha256:<64 lowercase hexadecimal characters>",
                    ));
                }
                let decoded = hex::decode(encoded).map_err(|error| {
                    ManifestError::invalid(stringify!($name), error.to_string())
                })?;
                let bytes: [u8; 32] = decoded.try_into().map_err(|_| {
                    ManifestError::invalid(stringify!($name), "digest is not 32 bytes")
                })?;
                Ok(Self(bytes))
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&self.to_string())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                value.parse().map_err(serde::de::Error::custom)
            }
        }
    };
}

digest_type!(ArtifactDigest);
digest_type!(ProfileRevision);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProfileMaturity {
    Release,
    Experimental,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactSpec {
    pub path: String,
    pub sha256: ArtifactDigest,
    pub size: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CpuManifest {
    pub smp_enabled: bool,
    pub product_max_cpus: u16,
    pub compiled_nr_cpus: Option<u16>,
    pub effective_max_cpus: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryManifest {
    pub minimum_bytes: u64,
    pub default_memory_bytes: u64,
    pub product_maximum_bytes: u64,
    pub effective_max_memory_bytes: u64,
    pub builder_memory_bytes: u64,
    pub validator_memory_bytes: u64,
    pub alignment_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Contracts {
    pub selector_policy: String,
    pub root_layout: String,
    pub filesystem: String,
    pub cpu_state_hwcap_policy: String,
    pub guest_capability_policy: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HelloContract {
    pub guest_contract_id: String,
    pub init_build_id: String,
    pub kernel_build_id: String,
    pub required_features: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuilderToolContract {
    pub role: String,
    pub sha256: String,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuilderContract {
    pub hello: HelloContract,
    pub manifest_schema: String,
    pub required_tools: Vec<BuilderToolContract>,
    pub source_date_epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidatorContract {
    pub hello: HelloContract,
    pub manifest_schema: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchContract {
    pub linkage: String,
    pub cooperative_backend: String,
    pub noreboot: bool,
    pub rdinit: String,
    pub rootfstype: String,
    pub ubd: String,
    pub serial: String,
    pub network: String,
    pub max_ubd_path_bytes: u16,
    pub max_umid_bytes: u16,
    pub max_unix_path_bytes: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactManifest {
    pub guard: ArtifactSpec,
    pub uml: ArtifactSpec,
    pub skopeo: ArtifactSpec,
    pub registry_ca_bundle: ArtifactSpec,
    pub workload_initramfs: ArtifactSpec,
    pub builder_initramfs: ArtifactSpec,
    pub validator_initramfs: ArtifactSpec,
    pub mke2fs: ArtifactSpec,
    pub e2fsck: ArtifactSpec,
    pub mke2fs_config: ArtifactSpec,
    pub e2fsck_config: ArtifactSpec,
    pub normalized_kernel_config: ArtifactSpec,
}

/// Strict external profile-manifest schema. Unknown JSON fields are rejected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileManifest {
    pub schema_version: u16,
    pub profile_id: String,
    pub profile_revision: ProfileRevision,
    pub maturity: ProfileMaturity,
    pub host_architecture: String,
    pub host_elf_machine: u16,
    pub oci_os: String,
    pub oci_architecture: String,
    pub accepted_oci_variants: Vec<Option<String>>,
    pub uml_subarchitecture: String,
    pub guest_page_size: u32,
    pub cpu: CpuManifest,
    pub memory: MemoryManifest,
    pub contracts: Contracts,
    pub hello: HelloContract,
    pub builder: BuilderContract,
    pub validator: ValidatorContract,
    pub launch: LaunchContract,
    pub artifacts: ArtifactManifest,
}

#[derive(Serialize)]
struct CanonicalManifest<'a> {
    schema_version: u16,
    profile_id: &'a str,
    maturity: ProfileMaturity,
    host_architecture: &'a str,
    host_elf_machine: u16,
    oci_os: &'a str,
    oci_architecture: &'a str,
    accepted_oci_variants: &'a [Option<String>],
    uml_subarchitecture: &'a str,
    guest_page_size: u32,
    cpu: CpuManifest,
    memory: MemoryManifest,
    contracts: &'a Contracts,
    hello: &'a HelloContract,
    builder: &'a BuilderContract,
    validator: &'a ValidatorContract,
    launch: &'a LaunchContract,
    artifacts: &'a ArtifactManifest,
}

impl ProfileManifest {
    /// Compute the non-circular revision over the manifest with its revision
    /// field omitted. Serialization is compact JSON in this declared schema
    /// order and is domain-separated from every artifact digest.
    pub fn computed_revision(&self) -> Result<ProfileRevision, ManifestError> {
        let canonical = CanonicalManifest {
            schema_version: self.schema_version,
            profile_id: &self.profile_id,
            maturity: self.maturity,
            host_architecture: &self.host_architecture,
            host_elf_machine: self.host_elf_machine,
            oci_os: &self.oci_os,
            oci_architecture: &self.oci_architecture,
            accepted_oci_variants: &self.accepted_oci_variants,
            uml_subarchitecture: &self.uml_subarchitecture,
            guest_page_size: self.guest_page_size,
            cpu: self.cpu,
            memory: self.memory,
            contracts: &self.contracts,
            hello: &self.hello,
            builder: &self.builder,
            validator: &self.validator,
            launch: &self.launch,
            artifacts: &self.artifacts,
        };
        let encoded = serde_json::to_vec(&canonical).map_err(|error| {
            ManifestError::invalid(
                "profile_revision",
                format!("canonicalization failed: {error}"),
            )
        })?;
        let mut hasher = Sha256::new();
        hasher.update(PROFILE_REVISION_DOMAIN);
        hasher.update(encoded);
        Ok(ProfileRevision::from_bytes(hasher.finalize().into()))
    }
}

#[derive(Debug, Clone)]
struct VerifiedArtifact {
    path: PathBuf,
    spec: ArtifactSpec,
    role: ArtifactRole,
}

#[derive(Debug, Clone, Copy)]
enum ArtifactRole {
    HostExecutable,
    Initramfs,
    Data,
    KernelConfig,
}

/// A fully checked, explicit x86_64 profile bundle.
#[derive(Debug)]
pub struct VerifiedProfile {
    root: ManagedUmlPath,
    manifest: ProfileManifest,
    cpu_profile: CpuProfile,
    memory_policy: MemoryPolicy,
    guard: VerifiedArtifact,
    uml: VerifiedArtifact,
    skopeo: VerifiedArtifact,
    registry_ca_bundle: VerifiedArtifact,
    initramfs: VerifiedArtifact,
    builder_initramfs: VerifiedArtifact,
    validator_initramfs: VerifiedArtifact,
    mke2fs: VerifiedArtifact,
    e2fsck: VerifiedArtifact,
    mke2fs_config: VerifiedArtifact,
    e2fsck_config: VerifiedArtifact,
    kernel_config: VerifiedArtifact,
}

impl VerifiedProfile {
    /// Load `<bundle_root>/profile.json`, reject any unsupported contract, and
    /// hash/inspect every artifact before returning.
    pub fn load(bundle_root: ManagedUmlPath) -> Result<Self, ManifestError> {
        validate_exact_directory(bundle_root.as_path())?;
        let manifest_path = bundle_root.as_path().join(PROFILE_MANIFEST_FILE);
        let bytes = read_bounded(&manifest_path, MAX_MANIFEST_BYTES)?;
        let manifest: ProfileManifest =
            serde_json::from_slice(&bytes).map_err(|source| ManifestError::Json {
                path: manifest_path,
                source,
            })?;
        let (cpu_profile, memory_policy) = validate_manifest(&manifest)?;
        let computed = manifest.computed_revision()?;
        if computed != manifest.profile_revision {
            return Err(ManifestError::RevisionMismatch {
                declared: manifest.profile_revision.to_string(),
                computed: computed.to_string(),
            });
        }

        let guard = verified_artifact(
            &bundle_root,
            &manifest.artifacts.guard,
            ArtifactRole::HostExecutable,
        )?;
        let uml = verified_artifact(
            &bundle_root,
            &manifest.artifacts.uml,
            ArtifactRole::HostExecutable,
        )?;
        let skopeo = verified_artifact(
            &bundle_root,
            &manifest.artifacts.skopeo,
            ArtifactRole::HostExecutable,
        )?;
        let registry_ca_bundle = verified_artifact(
            &bundle_root,
            &manifest.artifacts.registry_ca_bundle,
            ArtifactRole::Data,
        )?;
        let initramfs = verified_artifact(
            &bundle_root,
            &manifest.artifacts.workload_initramfs,
            ArtifactRole::Initramfs,
        )?;
        let builder_initramfs = verified_artifact(
            &bundle_root,
            &manifest.artifacts.builder_initramfs,
            ArtifactRole::Initramfs,
        )?;
        let validator_initramfs = verified_artifact(
            &bundle_root,
            &manifest.artifacts.validator_initramfs,
            ArtifactRole::Initramfs,
        )?;
        let mke2fs = verified_artifact(
            &bundle_root,
            &manifest.artifacts.mke2fs,
            ArtifactRole::HostExecutable,
        )?;
        let e2fsck = verified_artifact(
            &bundle_root,
            &manifest.artifacts.e2fsck,
            ArtifactRole::HostExecutable,
        )?;
        let mke2fs_config = verified_artifact(
            &bundle_root,
            &manifest.artifacts.mke2fs_config,
            ArtifactRole::Data,
        )?;
        let e2fsck_config = verified_artifact(
            &bundle_root,
            &manifest.artifacts.e2fsck_config,
            ArtifactRole::Data,
        )?;
        if e2fsck_config.spec.size != 0 {
            return Err(ManifestError::invalid(
                "artifacts.e2fsck_config",
                "the supported e2fsck policy is an exact empty configuration file",
            ));
        }
        let kernel_config = verified_artifact(
            &bundle_root,
            &manifest.artifacts.normalized_kernel_config,
            ArtifactRole::KernelConfig,
        )?;
        let artifact_paths = [
            guard.path.as_path(),
            uml.path.as_path(),
            skopeo.path.as_path(),
            registry_ca_bundle.path.as_path(),
            initramfs.path.as_path(),
            builder_initramfs.path.as_path(),
            validator_initramfs.path.as_path(),
            mke2fs.path.as_path(),
            e2fsck.path.as_path(),
            mke2fs_config.path.as_path(),
            e2fsck_config.path.as_path(),
            kernel_config.path.as_path(),
        ];
        let unique_paths: BTreeSet<&Path> = artifact_paths.into_iter().collect();
        if unique_paths.len() != artifact_paths.len() {
            return Err(ManifestError::invalid(
                "artifacts",
                "artifact roles must resolve to distinct files",
            ));
        }
        validate_kernel_config(&kernel_config.path, &manifest.cpu)?;
        validate_registry_ca_bundle(&registry_ca_bundle.path)?;

        Ok(Self {
            root: bundle_root,
            manifest,
            cpu_profile,
            memory_policy,
            guard,
            uml,
            skopeo,
            registry_ca_bundle,
            initramfs,
            builder_initramfs,
            validator_initramfs,
            mke2fs,
            e2fsck,
            mke2fs_config,
            e2fsck_config,
            kernel_config,
        })
    }

    /// Re-open and verify all path, byte, ELF, and kernel-config contracts.
    /// The runtime calls this immediately before every launch.
    pub fn reverify(&self) -> Result<(), ManifestError> {
        validate_exact_directory(self.root.as_path())?;
        for artifact in [
            &self.guard,
            &self.uml,
            &self.skopeo,
            &self.registry_ca_bundle,
            &self.initramfs,
            &self.builder_initramfs,
            &self.validator_initramfs,
            &self.mke2fs,
            &self.e2fsck,
            &self.mke2fs_config,
            &self.e2fsck_config,
            &self.kernel_config,
        ] {
            verify_artifact_at(&artifact.path, &artifact.spec, artifact.role)?;
        }
        validate_kernel_config(&self.kernel_config.path, &self.manifest.cpu)?;
        validate_registry_ca_bundle(&self.registry_ca_bundle.path)
    }

    #[must_use]
    pub const fn manifest(&self) -> &ProfileManifest {
        &self.manifest
    }

    #[must_use]
    pub const fn cpu_profile(&self) -> CpuProfile {
        self.cpu_profile
    }

    #[must_use]
    pub const fn memory_policy(&self) -> MemoryPolicy {
        self.memory_policy
    }

    #[must_use]
    pub fn guard_path(&self) -> &Path {
        &self.guard.path
    }

    #[must_use]
    pub fn uml_path(&self) -> &Path {
        &self.uml.path
    }

    /// Exact static acquisition helper bound into this profile revision.
    #[must_use]
    pub fn skopeo_path(&self) -> &Path {
        &self.skopeo.path
    }

    /// Exact registry trust roots used by the profile-bound acquisition helper.
    #[must_use]
    pub fn registry_ca_bundle_path(&self) -> &Path {
        &self.registry_ca_bundle.path
    }

    #[must_use]
    pub fn initramfs_path(&self) -> &Path {
        &self.initramfs.path
    }

    #[must_use]
    pub fn builder_initramfs_path(&self) -> &Path {
        &self.builder_initramfs.path
    }

    #[must_use]
    pub fn validator_initramfs_path(&self) -> &Path {
        &self.validator_initramfs.path
    }

    #[must_use]
    pub fn mke2fs_path(&self) -> &Path {
        &self.mke2fs.path
    }

    #[must_use]
    pub fn e2fsck_path(&self) -> &Path {
        &self.e2fsck.path
    }

    #[must_use]
    pub fn mke2fs_config_path(&self) -> &Path {
        &self.mke2fs_config.path
    }

    /// Exact empty policy file that prevents e2fsck from reading
    /// `/etc/e2fsck.conf` or another host default.
    #[must_use]
    pub fn e2fsck_config_path(&self) -> &Path {
        &self.e2fsck_config.path
    }
}

pub(crate) fn validate_manifest(
    manifest: &ProfileManifest,
) -> Result<(CpuProfile, MemoryPolicy), ManifestError> {
    if manifest.schema_version != PROFILE_SCHEMA_VERSION {
        return Err(ManifestError::UnsupportedContract {
            field: "schema_version",
            value: manifest.schema_version.to_string(),
        });
    }
    validate_token("profile_id", &manifest.profile_id, 128)?;
    require_value("host_architecture", &manifest.host_architecture, "x86_64")?;
    if manifest.host_elf_machine != EM_X86_64 {
        return Err(ManifestError::UnsupportedContract {
            field: "host_elf_machine",
            value: manifest.host_elf_machine.to_string(),
        });
    }
    require_value("oci_os", &manifest.oci_os, "linux")?;
    require_value("oci_architecture", &manifest.oci_architecture, "amd64")?;
    require_value(
        "uml_subarchitecture",
        &manifest.uml_subarchitecture,
        "x86_64",
    )?;
    if manifest.guest_page_size != 4096 {
        return Err(ManifestError::UnsupportedContract {
            field: "guest_page_size",
            value: manifest.guest_page_size.to_string(),
        });
    }

    if manifest.accepted_oci_variants.is_empty() {
        return Err(ManifestError::invalid(
            "accepted_oci_variants",
            "at least one variant policy entry is required",
        ));
    }
    let mut variants = BTreeSet::new();
    for variant in &manifest.accepted_oci_variants {
        if let Some(value) = variant {
            validate_token("accepted_oci_variants", value, 32)?;
            if value != "v1" {
                return Err(ManifestError::UnsupportedContract {
                    field: "accepted_oci_variants",
                    value: value.clone(),
                });
            }
        }
        if !variants.insert(variant.clone()) {
            return Err(ManifestError::invalid(
                "accepted_oci_variants",
                "duplicate variant entry",
            ));
        }
    }

    let cpu_profile = CpuProfile::new(
        manifest.cpu.smp_enabled,
        manifest.cpu.product_max_cpus,
        manifest.cpu.compiled_nr_cpus,
    )?;
    if cpu_profile.effective_max_cpus() != manifest.cpu.effective_max_cpus {
        return Err(ManifestError::invalid(
            "cpu.effective_max_cpus",
            format!(
                "declared {}, computed {}",
                manifest.cpu.effective_max_cpus,
                cpu_profile.effective_max_cpus()
            ),
        ));
    }
    let memory_policy = MemoryPolicy::new(
        manifest.memory.minimum_bytes,
        manifest.memory.effective_max_memory_bytes,
        manifest.memory.alignment_bytes,
    )?;
    if manifest.memory.effective_max_memory_bytes > manifest.memory.product_maximum_bytes {
        return Err(ManifestError::invalid(
            "memory.effective_max_memory_bytes",
            "tested effective maximum exceeds the product maximum",
        ));
    }
    if !manifest
        .memory
        .product_maximum_bytes
        .is_multiple_of(manifest.memory.alignment_bytes)
    {
        return Err(ManifestError::invalid(
            "memory.product_maximum_bytes",
            "product maximum is not aligned",
        ));
    }
    for (field, value) in [
        (
            "memory.default_memory_bytes",
            manifest.memory.default_memory_bytes,
        ),
        (
            "memory.builder_memory_bytes",
            manifest.memory.builder_memory_bytes,
        ),
        (
            "memory.validator_memory_bytes",
            manifest.memory.validator_memory_bytes,
        ),
    ] {
        if value < manifest.memory.minimum_bytes
            || value > manifest.memory.effective_max_memory_bytes
        {
            return Err(ManifestError::invalid(
                field,
                "must be within the minimum..=effective tested range",
            ));
        }
        if !value.is_multiple_of(manifest.memory.alignment_bytes) {
            return Err(ManifestError::invalid(
                field,
                "must be aligned to memory.alignment_bytes",
            ));
        }
    }

    validate_token(
        "contracts.selector_policy",
        &manifest.contracts.selector_policy,
        128,
    )?;
    require_value(
        "contracts.selector_policy",
        &manifest.contracts.selector_policy,
        "native-amd64-v1",
    )?;
    require_value(
        "contracts.root_layout",
        &manifest.contracts.root_layout,
        "pocket-root-v1",
    )?;
    require_value(
        "contracts.filesystem",
        &manifest.contracts.filesystem,
        "ext4-v1-b4096",
    )?;
    require_value(
        "contracts.cpu_state_hwcap_policy",
        &manifest.contracts.cpu_state_hwcap_policy,
        "native-x86_64-v1",
    )?;
    require_value(
        "contracts.guest_capability_policy",
        &manifest.contracts.guest_capability_policy,
        "fixed-capabilities-v1",
    )?;

    validate_hello_contract("hello", &manifest.hello)?;
    validate_workload_features(&manifest.hello.required_features)?;
    validate_hello_contract("builder.hello", &manifest.builder.hello)?;
    validate_builder_features(&manifest.builder.hello.required_features)?;
    require_value(
        "builder.manifest_schema",
        &manifest.builder.manifest_schema,
        "pocket-fs-manifest-v1",
    )?;
    if !(pocket_protocol::SOURCE_DATE_EPOCH_MIN..=pocket_protocol::SOURCE_DATE_EPOCH_MAX)
        .contains(&manifest.builder.source_date_epoch)
    {
        return Err(ManifestError::invalid(
            "builder.source_date_epoch",
            "must be a pinned Unix timestamp from 2000-01-01 through 2100-01-01",
        ));
    }
    if manifest.builder.required_tools.is_empty() || manifest.builder.required_tools.len() > 16 {
        return Err(ManifestError::invalid(
            "builder.required_tools",
            "must contain 1..=16 tool identities",
        ));
    }
    let mut previous_role: Option<&str> = None;
    for tool in &manifest.builder.required_tools {
        validate_token("builder.required_tools.role", &tool.role, 64)?;
        validate_sha256("builder.required_tools.sha256", &tool.sha256)?;
        if tool.version.is_empty()
            || tool.version.len() > 256
            || tool.version.chars().any(char::is_control)
        {
            return Err(ManifestError::invalid(
                "builder.required_tools.version",
                "must contain 1..=256 non-control UTF-8 bytes",
            ));
        }
        if previous_role.is_some_and(|role| role >= tool.role.as_str()) {
            return Err(ManifestError::invalid(
                "builder.required_tools",
                "tool roles must be unique and sorted",
            ));
        }
        previous_role = Some(&tool.role);
    }
    if manifest
        .builder
        .required_tools
        .binary_search_by(|tool| tool.role.as_str().cmp("umoci"))
        .is_err()
    {
        return Err(ManifestError::invalid(
            "builder.required_tools",
            "the current builder requires an exact umoci identity",
        ));
    }

    validate_hello_contract("validator.hello", &manifest.validator.hello)?;
    validate_validator_features(&manifest.validator.hello.required_features)?;
    require_value(
        "validator.manifest_schema",
        &manifest.validator.manifest_schema,
        "pocket-fs-manifest-v1",
    )?;

    require_value("launch.linkage", &manifest.launch.linkage, "static")?;
    require_value(
        "launch.cooperative_backend",
        &manifest.launch.cooperative_backend,
        "seccomp-on",
    )?;
    if !manifest.launch.noreboot {
        return Err(ManifestError::UnsupportedContract {
            field: "launch.noreboot",
            value: "false".to_owned(),
        });
    }
    require_value("launch.rdinit", &manifest.launch.rdinit, "/init")?;
    require_value("launch.rootfstype", &manifest.launch.rootfstype, "ramfs")?;
    require_value("launch.ubd", &manifest.launch.ubd, "cow-v3")?;
    require_value("launch.serial", &manifest.launch.serial, "ssl-fd-v1")?;
    require_value("launch.network", &manifest.launch.network, "none")?;
    if manifest.launch.max_ubd_path_bytes != 4095 {
        return Err(ManifestError::invalid(
            "launch.max_ubd_path_bytes",
            "Linux 7.2 COW v3 backing paths require the pinned value 4095",
        ));
    }
    if manifest.launch.max_umid_bytes != 63 {
        return Err(ManifestError::invalid(
            "launch.max_umid_bytes",
            "Linux 7.2 UMID_LEN requires the pinned value 63",
        ));
    }
    if manifest.launch.max_unix_path_bytes != 107 {
        return Err(ManifestError::invalid(
            "launch.max_unix_path_bytes",
            "the pinned sockaddr_un pathname limit is 107 bytes",
        ));
    }

    Ok((cpu_profile, memory_policy))
}

fn validate_hello_contract(
    prefix: &'static str,
    hello: &HelloContract,
) -> Result<(), ManifestError> {
    let fields = match prefix {
        "hello" => [
            "hello.guest_contract_id",
            "hello.init_build_id",
            "hello.kernel_build_id",
        ],
        "builder.hello" => [
            "builder.hello.guest_contract_id",
            "builder.hello.init_build_id",
            "builder.hello.kernel_build_id",
        ],
        "validator.hello" => [
            "validator.hello.guest_contract_id",
            "validator.hello.init_build_id",
            "validator.hello.kernel_build_id",
        ],
        _ => unreachable!("only fixed profile HELLO roles are validated"),
    };
    for (field, id) in fields.into_iter().zip([
        &hello.guest_contract_id,
        &hello.init_build_id,
        &hello.kernel_build_id,
    ]) {
        validate_sha256(field, id)?;
    }
    Ok(())
}

fn validate_sorted_features(field: &'static str, features: &[String]) -> Result<(), ManifestError> {
    if features.len() > 64 {
        return Err(ManifestError::invalid(field, "more than 64 features"));
    }
    let mut previous: Option<&str> = None;
    for feature in features {
        validate_token(field, feature, 64)?;
        if previous.is_some_and(|value| value >= feature.as_str()) {
            return Err(ManifestError::invalid(
                field,
                "features must be unique and sorted",
            ));
        }
        previous = Some(feature);
    }
    Ok(())
}

fn validate_workload_features(features: &[String]) -> Result<(), ManifestError> {
    let field = "hello.required_features";
    validate_sorted_features(field, features)?;
    if !same_features(features, pocket_protocol::WORKLOAD_GUEST_FEATURES) {
        return Err(ManifestError::invalid(
            field,
            "must exactly match the workload guest's compiled feature set",
        ));
    }
    Ok(())
}

fn validate_builder_features(features: &[String]) -> Result<(), ManifestError> {
    let field = "builder.hello.required_features";
    validate_sorted_features(field, features)?;
    if !same_features(features, pocket_protocol::BUILDER_GUEST_FEATURES) {
        return Err(ManifestError::invalid(
            field,
            "must exactly match the builder guest's compiled feature set",
        ));
    }
    Ok(())
}

fn validate_validator_features(features: &[String]) -> Result<(), ManifestError> {
    let field = "validator.hello.required_features";
    validate_sorted_features(field, features)?;
    if !same_features(features, pocket_protocol::VALIDATOR_GUEST_FEATURES) {
        return Err(ManifestError::invalid(
            field,
            "must exactly match the validator guest's compiled feature set",
        ));
    }
    Ok(())
}

fn same_features(actual: &[String], expected: &[&str]) -> bool {
    actual.len() == expected.len()
        && actual
            .iter()
            .map(String::as_str)
            .eq(expected.iter().copied())
}

fn require_value(
    field: &'static str,
    actual: &str,
    expected: &'static str,
) -> Result<(), ManifestError> {
    if actual != expected {
        return Err(ManifestError::UnsupportedContract {
            field,
            value: actual.to_owned(),
        });
    }
    Ok(())
}

fn validate_token(field: &'static str, value: &str, maximum: usize) -> Result<(), ManifestError> {
    if value.is_empty() || value.len() > maximum {
        return Err(ManifestError::invalid(
            field,
            format!("must contain 1..={maximum} bytes"),
        ));
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(ManifestError::invalid(
            field,
            "contains a non-token character",
        ));
    }
    Ok(())
}

fn validate_sha256(field: &'static str, value: &str) -> Result<(), ManifestError> {
    if value.len() != 64
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
    {
        return Err(ManifestError::invalid(
            field,
            "must be 64 lowercase hexadecimal characters",
        ));
    }
    Ok(())
}

fn validate_exact_directory(path: &Path) -> Result<(), ManifestError> {
    let canonical = fs::canonicalize(path)
        .map_err(|error| ManifestError::io("canonicalize profile directory", path, error))?;
    if canonical != path {
        return Err(ManifestError::ArtifactResolution {
            path: path.to_path_buf(),
        });
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| ManifestError::io("inspect profile directory", path, error))?;
    if !metadata.file_type().is_dir() {
        return Err(ManifestError::ArtifactType {
            path: path.to_path_buf(),
        });
    }
    if metadata.mode() & 0o022 != 0 {
        return Err(ManifestError::ArtifactMode {
            path: path.to_path_buf(),
            mode: metadata.mode() & 0o7777,
            reason: "bundle directory must not be group- or world-writable",
        });
    }
    Ok(())
}

fn validate_relative_artifact_path(path: &str) -> Result<(), ManifestError> {
    let candidate = Path::new(path);
    if path.is_empty() || candidate.is_absolute() {
        return Err(ManifestError::ArtifactPath {
            path: path.to_owned(),
            reason: "must be non-empty and relative",
        });
    }
    if path.len() > 160
        || path.chars().any(char::is_whitespace)
        || path.bytes().any(|byte| matches!(byte, b',' | b':' | 0))
    {
        return Err(ManifestError::ArtifactPath {
            path: path.to_owned(),
            reason: "contains a reserved character or is too long",
        });
    }
    if candidate
        .components()
        .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return Err(ManifestError::ArtifactPath {
            path: path.to_owned(),
            reason: "contains a dot, parent, root, or prefix component",
        });
    }
    Ok(())
}

fn verified_artifact(
    root: &ManagedUmlPath,
    spec: &ArtifactSpec,
    role: ArtifactRole,
) -> Result<VerifiedArtifact, ManifestError> {
    validate_relative_artifact_path(&spec.path)?;
    let path = root.as_path().join(&spec.path);
    let _ = ManagedUmlPath::new(&path)?;
    let canonical = fs::canonicalize(&path)
        .map_err(|error| ManifestError::io("canonicalize artifact", &path, error))?;
    if canonical != path || !canonical.starts_with(root.as_path()) {
        return Err(ManifestError::ArtifactResolution { path });
    }
    verify_artifact_at(&canonical, spec, role)?;
    Ok(VerifiedArtifact {
        path: canonical,
        spec: spec.clone(),
        role,
    })
}

fn verify_artifact_at(
    path: &Path,
    spec: &ArtifactSpec,
    role: ArtifactRole,
) -> Result<(), ManifestError> {
    let canonical = fs::canonicalize(path)
        .map_err(|error| ManifestError::io("canonicalize artifact", path, error))?;
    if canonical != path {
        return Err(ManifestError::ArtifactResolution {
            path: path.to_path_buf(),
        });
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| ManifestError::io("inspect artifact", path, error))?;
    if !metadata.file_type().is_file() {
        return Err(ManifestError::ArtifactType {
            path: path.to_path_buf(),
        });
    }
    let mode = metadata.mode() & 0o7777;
    if mode & 0o022 != 0 {
        return Err(ManifestError::ArtifactMode {
            path: path.to_path_buf(),
            mode,
            reason: "artifact must not be group- or world-writable",
        });
    }
    match role {
        ArtifactRole::HostExecutable => {
            if mode & 0o111 == 0 || mode & 0o6000 != 0 {
                return Err(ManifestError::ArtifactMode {
                    path: path.to_path_buf(),
                    mode,
                    reason: "host executable needs an execute bit and no set-ID bit",
                });
            }
        }
        ArtifactRole::Initramfs | ArtifactRole::Data | ArtifactRole::KernelConfig => {
            if mode & 0o111 != 0 || mode & 0o6000 != 0 {
                return Err(ManifestError::ArtifactMode {
                    path: path.to_path_buf(),
                    mode,
                    reason: "data artifact must be non-executable and have no set-ID bit",
                });
            }
        }
    }
    if metadata.len() != spec.size {
        return Err(ManifestError::ArtifactSize {
            path: path.to_path_buf(),
            expected: spec.size,
            actual: metadata.len(),
        });
    }

    let mut file =
        File::open(path).map_err(|error| ManifestError::io("open artifact", path, error))?;
    reject_file_capability(&file, path)?;
    let observed = hash_reader(&mut file, path)?;
    if observed != spec.sha256 {
        return Err(ManifestError::ArtifactDigest {
            path: path.to_path_buf(),
            expected: spec.sha256.to_string(),
            actual: observed.to_string(),
        });
    }
    if matches!(role, ArtifactRole::HostExecutable) {
        verify_static_x86_64_elf(&mut file, path, metadata.len())?;
    }
    Ok(())
}

pub(crate) fn reject_file_capability(file: &File, path: &Path) -> Result<(), ManifestError> {
    let name = b"security.capability\0";
    // SAFETY: `file` is open, the attribute name is NUL-terminated, and a
    // zero-length query provides no output buffer for the kernel to write.
    let result = unsafe {
        libc::fgetxattr(
            file.as_raw_fd(),
            name.as_ptr().cast(),
            std::ptr::null_mut(),
            0,
        )
    };
    if result >= 0 {
        return Err(ManifestError::ArtifactCapability {
            path: path.to_path_buf(),
        });
    }
    let error = std::io::Error::last_os_error();
    if matches!(error.raw_os_error(), Some(libc::ENODATA | libc::ENOTSUP)) {
        return Ok(());
    }
    Err(ManifestError::io(
        "inspect artifact file capabilities",
        path,
        error,
    ))
}

fn hash_reader(file: &mut File, path: &Path) -> Result<ArtifactDigest, ManifestError> {
    file.seek(SeekFrom::Start(0))
        .map_err(|error| ManifestError::io("seek artifact", path, error))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 128 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|error| ManifestError::io("hash artifact", path, error))?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(ArtifactDigest::from_bytes(hasher.finalize().into()))
}

fn verify_static_x86_64_elf(file: &mut File, path: &Path, size: u64) -> Result<(), ManifestError> {
    let mut header = [0_u8; 64];
    file.seek(SeekFrom::Start(0))
        .map_err(|error| ManifestError::io("seek ELF header", path, error))?;
    file.read_exact(&mut header)
        .map_err(|error| ManifestError::io("read ELF header", path, error))?;
    if &header[..4] != b"\x7fELF" {
        return Err(elf(path, "missing ELF magic"));
    }
    if header[4] != 2 || header[5] != 1 || header[6] != 1 {
        return Err(elf(path, "requires ELF64 little-endian version 1"));
    }
    let elf_type = u16::from_le_bytes([header[16], header[17]]);
    if !matches!(elf_type, 2 | 3) {
        return Err(elf(path, "requires ET_EXEC or ET_DYN"));
    }
    let machine = u16::from_le_bytes([header[18], header[19]]);
    if machine != EM_X86_64 {
        return Err(elf(
            path,
            format!("expected e_machine {EM_X86_64}, observed {machine}"),
        ));
    }
    if u16::from_le_bytes([header[52], header[53]]) != 64 {
        return Err(elf(path, "unexpected ELF header size"));
    }
    let phoff = u64::from_le_bytes(
        header[32..40]
            .try_into()
            .map_err(|_| elf(path, "invalid program-header offset"))?,
    );
    let phentsize = u64::from(u16::from_le_bytes([header[54], header[55]]));
    let phnum = u64::from(u16::from_le_bytes([header[56], header[57]]));
    if phnum == 0 || phnum > 1024 || phentsize != 56 {
        return Err(elf(path, "invalid program-header table shape"));
    }
    let table_size = phentsize
        .checked_mul(phnum)
        .and_then(|value| phoff.checked_add(value))
        .ok_or_else(|| elf(path, "program-header table overflow"))?;
    if table_size > size {
        return Err(elf(path, "program-header table is outside the file"));
    }
    let mut program_header = [0_u8; 56];
    let mut has_load = false;
    for index in 0..phnum {
        file.seek(SeekFrom::Start(phoff + index * phentsize))
            .map_err(|error| ManifestError::io("seek ELF program header", path, error))?;
        file.read_exact(&mut program_header)
            .map_err(|error| ManifestError::io("read ELF program header", path, error))?;
        let segment_type = u32::from_le_bytes(
            program_header[..4]
                .try_into()
                .map_err(|_| elf(path, "invalid program-header type"))?,
        );
        match segment_type {
            1 => has_load = true,
            2 => verify_dynamic_table_has_no_needed(file, path, size, &program_header)?,
            3 => {
                return Err(elf(
                    path,
                    "profile declares static linkage but ELF contains PT_INTERP",
                ));
            }
            _ => {}
        }
    }
    if !has_load {
        return Err(elf(path, "ELF has no PT_LOAD segment"));
    }
    Ok(())
}

fn verify_dynamic_table_has_no_needed(
    file: &mut File,
    path: &Path,
    size: u64,
    program_header: &[u8; 56],
) -> Result<(), ManifestError> {
    const ELF64_DYNAMIC_ENTRY_BYTES: u64 = 16;
    const DT_NULL: u64 = 0;
    const DT_NEEDED: u64 = 1;

    let offset = u64::from_le_bytes(
        program_header[8..16]
            .try_into()
            .map_err(|_| elf(path, "invalid PT_DYNAMIC offset"))?,
    );
    let file_size = u64::from_le_bytes(
        program_header[32..40]
            .try_into()
            .map_err(|_| elf(path, "invalid PT_DYNAMIC size"))?,
    );
    let end = offset
        .checked_add(file_size)
        .ok_or_else(|| elf(path, "PT_DYNAMIC range overflow"))?;
    if file_size == 0 || !file_size.is_multiple_of(ELF64_DYNAMIC_ENTRY_BYTES) || end > size {
        return Err(elf(
            path,
            "PT_DYNAMIC table is outside the file or malformed",
        ));
    }

    file.seek(SeekFrom::Start(offset))
        .map_err(|error| ManifestError::io("seek ELF dynamic table", path, error))?;
    let mut entry = [0_u8; ELF64_DYNAMIC_ENTRY_BYTES as usize];
    let mut terminated = false;
    for _ in 0..(file_size / ELF64_DYNAMIC_ENTRY_BYTES) {
        file.read_exact(&mut entry)
            .map_err(|error| ManifestError::io("read ELF dynamic entry", path, error))?;
        let tag = u64::from_le_bytes(
            entry[..8]
                .try_into()
                .map_err(|_| elf(path, "invalid ELF dynamic tag"))?,
        );
        if tag == DT_NEEDED {
            return Err(elf(
                path,
                "profile declares static linkage but ELF contains DT_NEEDED",
            ));
        }
        if tag == DT_NULL {
            terminated = true;
            break;
        }
    }
    if !terminated {
        return Err(elf(path, "PT_DYNAMIC table has no DT_NULL terminator"));
    }
    Ok(())
}

fn elf(path: &Path, reason: impl Into<String>) -> ManifestError {
    ManifestError::Elf {
        path: path.to_path_buf(),
        reason: reason.into(),
    }
}

pub(crate) fn read_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>, ManifestError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| ManifestError::io("inspect bounded file", path, error))?;
    if !metadata.file_type().is_file() {
        return Err(ManifestError::ArtifactType {
            path: path.to_path_buf(),
        });
    }
    if metadata.len() > maximum as u64 {
        return Err(ManifestError::TooLarge {
            path: path.to_path_buf(),
            maximum,
        });
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(path)
        .and_then(|mut file| file.read_to_end(&mut bytes))
        .map_err(|error| ManifestError::io("read bounded file", path, error))?;
    if bytes.len() > maximum {
        return Err(ManifestError::TooLarge {
            path: path.to_path_buf(),
            maximum,
        });
    }
    Ok(bytes)
}

fn validate_kernel_config(path: &Path, cpu: &CpuManifest) -> Result<(), ManifestError> {
    let bytes = read_bounded(path, MAX_CONFIG_BYTES)?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| ManifestError::invalid("normalized_kernel_config", "is not UTF-8"))?;
    let mut settings = BTreeMap::<String, String>::new();
    for line in text.lines() {
        let parsed = if let Some((key, value)) = line.split_once('=') {
            if key.starts_with("CONFIG_") {
                Some((key.to_owned(), value.to_owned()))
            } else {
                None
            }
        } else {
            line.strip_prefix("# ")
                .and_then(|line| line.strip_suffix(" is not set"))
                .filter(|key| key.starts_with("CONFIG_"))
                .map(|key| (key.to_owned(), "n".to_owned()))
        };
        if let Some((key, value)) = parsed
            && settings.insert(key.clone(), value).is_some()
        {
            return Err(ManifestError::invalid(
                "normalized_kernel_config",
                format!("duplicate setting {key}"),
            ));
        }
    }

    let mut required = vec![
        ("CONFIG_UML", "y"),
        ("CONFIG_64BIT", "y"),
        ("CONFIG_X86_64", "y"),
        ("CONFIG_STATIC_LINK", "y"),
        ("CONFIG_LD_SCRIPT_STATIC", "y"),
        ("CONFIG_BLK_DEV_INITRD", "y"),
        ("CONFIG_BLK_DEV_UBD", "y"),
        ("CONFIG_BLK_DEV_UBD_SYNC", "n"),
        ("CONFIG_BLK_DEV_LOOP", "n"),
        ("CONFIG_BLK_DEV_NBD", "n"),
        ("CONFIG_EXT4_FS", "y"),
        ("CONFIG_EXT4_FS_POSIX_ACL", "y"),
        ("CONFIG_EXT4_FS_SECURITY", "y"),
        ("CONFIG_TMPFS", "y"),
        ("CONFIG_PROC_FS", "y"),
        ("CONFIG_SYSFS", "y"),
        ("CONFIG_DEVTMPFS", "y"),
        ("CONFIG_DEVTMPFS_MOUNT", "y"),
        ("CONFIG_BINFMT_ELF", "y"),
        ("CONFIG_BINFMT_SCRIPT", "y"),
        ("CONFIG_EPOLL", "y"),
        ("CONFIG_FUTEX", "y"),
        ("CONFIG_TIMERFD", "y"),
        ("CONFIG_EVENTFD", "y"),
        ("CONFIG_MEMFD_CREATE", "y"),
        ("CONFIG_SIGNALFD", "y"),
        ("CONFIG_SECCOMP", "y"),
        ("CONFIG_SECCOMP_FILTER", "y"),
        ("CONFIG_NAMESPACES", "y"),
        ("CONFIG_UTS_NS", "y"),
        ("CONFIG_IPC_NS", "y"),
        ("CONFIG_PID_NS", "y"),
        ("CONFIG_SSL", "y"),
        ("CONFIG_NULL_CHAN", "y"),
        ("CONFIG_HOSTFS", "n"),
        ("CONFIG_MCONSOLE", "n"),
        ("CONFIG_MODULES", "n"),
        ("CONFIG_UML_NET_VECTOR", "n"),
        ("CONFIG_DEBUG_INFO_NONE", "y"),
        ("CONFIG_IPV6", "n"),
        ("CONFIG_USER_NS", "n"),
        ("CONFIG_NETDEVICES", "n"),
    ];
    required.push(("CONFIG_SMP", if cpu.smp_enabled { "y" } else { "n" }));
    for (setting, expected) in required {
        require_config(path, &settings, setting, expected)?;
    }
    if cpu.smp_enabled {
        let compiled = cpu.compiled_nr_cpus.ok_or_else(|| {
            ManifestError::invalid("cpu.compiled_nr_cpus", "missing for SMP profile")
        })?;
        require_config(path, &settings, "CONFIG_NR_CPUS", &compiled.to_string())?;
    }
    Ok(())
}

fn validate_registry_ca_bundle(path: &Path) -> Result<(), ManifestError> {
    const MAX_CA_BUNDLE_BYTES: usize = 16 * 1024 * 1024;
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";

    let bytes = read_bounded(path, MAX_CA_BUNDLE_BYTES)?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| ManifestError::invalid("registry_ca_bundle", "is not UTF-8 PEM"))?;
    if text.chars().any(|character| {
        character == '\r'
            || character == '\0'
            || (character.is_control() && !matches!(character, '\n' | '\t'))
    }) {
        return Err(ManifestError::invalid(
            "registry_ca_bundle",
            "must use UTF-8 PEM with LF line endings and no unexpected controls",
        ));
    }
    let mut certificate_count = 0_usize;
    let mut inside_certificate = false;
    let mut has_encoded_line = false;
    for line in text.lines() {
        if !inside_certificate {
            if line == BEGIN {
                inside_certificate = true;
                has_encoded_line = false;
            } else if line == END {
                return Err(ManifestError::invalid(
                    "registry_ca_bundle",
                    "contains a certificate end delimiter without a begin delimiter",
                ));
            }
            continue;
        }

        if line == BEGIN {
            return Err(ManifestError::invalid(
                "registry_ca_bundle",
                "contains a nested certificate begin delimiter",
            ));
        }
        if line == END {
            if !has_encoded_line {
                return Err(ManifestError::invalid(
                    "registry_ca_bundle",
                    "contains an empty certificate PEM block",
                ));
            }
            certificate_count += 1;
            inside_certificate = false;
            continue;
        }
        if !valid_pem_base64_line(line) {
            return Err(ManifestError::invalid(
                "registry_ca_bundle",
                "certificate PEM body contains a non-base64 or malformed line",
            ));
        }
        has_encoded_line = true;
    }
    if inside_certificate || certificate_count == 0 {
        return Err(ManifestError::invalid(
            "registry_ca_bundle",
            "must contain one or more complete CERTIFICATE PEM blocks",
        ));
    }
    Ok(())
}

fn valid_pem_base64_line(line: &str) -> bool {
    if line.is_empty() || line.len() > 128 || !line.len().is_multiple_of(4) {
        return false;
    }
    let padding = line.bytes().rev().take_while(|byte| *byte == b'=').count();
    if padding > 2 || line.as_bytes()[..line.len() - padding].contains(&b'=') {
        return false;
    }
    line.bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
}

fn require_config(
    path: &Path,
    settings: &BTreeMap<String, String>,
    setting: &str,
    expected: &str,
) -> Result<(), ManifestError> {
    let actual = settings
        .get(setting)
        .map_or_else(|| "<missing>".to_owned(), Clone::clone);
    if actual != expected {
        return Err(ManifestError::KernelConfig {
            path: path.to_path_buf(),
            setting: setting.to_owned(),
            expected: expected.to_owned(),
            actual,
        });
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn synthetic_profile(root: ManagedUmlPath, smp: bool) -> VerifiedProfile {
    let cpu = if smp {
        CpuManifest {
            smp_enabled: true,
            product_max_cpus: 8,
            compiled_nr_cpus: Some(16),
            effective_max_cpus: 8,
        }
    } else {
        CpuManifest {
            smp_enabled: false,
            product_max_cpus: 1,
            compiled_nr_cpus: None,
            effective_max_cpus: 1,
        }
    };
    let empty_artifact = |path: &str| ArtifactSpec {
        path: path.to_owned(),
        sha256: ArtifactDigest::from_bytes([0; 32]),
        size: 0,
    };
    let mut manifest = ProfileManifest {
        schema_version: PROFILE_SCHEMA_VERSION,
        profile_id: if smp {
            "x86_64-smp-p4k".to_owned()
        } else {
            "x86_64-up-p4k-test".to_owned()
        },
        profile_revision: ProfileRevision::from_bytes([0; 32]),
        maturity: ProfileMaturity::Experimental,
        host_architecture: "x86_64".to_owned(),
        host_elf_machine: EM_X86_64,
        oci_os: "linux".to_owned(),
        oci_architecture: "amd64".to_owned(),
        accepted_oci_variants: vec![None, Some("v1".to_owned())],
        uml_subarchitecture: "x86_64".to_owned(),
        guest_page_size: 4096,
        cpu,
        memory: MemoryManifest {
            minimum_bytes: 128 * 1024 * 1024,
            default_memory_bytes: 256 * 1024 * 1024,
            product_maximum_bytes: 4 * 1024 * 1024 * 1024,
            effective_max_memory_bytes: 2 * 1024 * 1024 * 1024,
            builder_memory_bytes: 512 * 1024 * 1024,
            validator_memory_bytes: 512 * 1024 * 1024,
            alignment_bytes: 4096,
        },
        contracts: Contracts {
            selector_policy: "native-amd64-v1".to_owned(),
            root_layout: "pocket-root-v1".to_owned(),
            filesystem: "ext4-v1-b4096".to_owned(),
            cpu_state_hwcap_policy: "native-x86_64-v1".to_owned(),
            guest_capability_policy: "fixed-capabilities-v1".to_owned(),
        },
        hello: HelloContract {
            guest_contract_id: "11".repeat(32),
            init_build_id: "22".repeat(32),
            kernel_build_id: "33".repeat(32),
            required_features: pocket_protocol::WORKLOAD_GUEST_FEATURES
                .iter()
                .map(|feature| (*feature).to_owned())
                .collect(),
        },
        builder: BuilderContract {
            hello: HelloContract {
                guest_contract_id: "44".repeat(32),
                init_build_id: "55".repeat(32),
                kernel_build_id: "33".repeat(32),
                required_features: pocket_protocol::BUILDER_GUEST_FEATURES
                    .iter()
                    .map(|feature| (*feature).to_owned())
                    .collect(),
            },
            manifest_schema: "pocket-fs-manifest-v1".to_owned(),
            required_tools: vec![BuilderToolContract {
                role: "umoci".to_owned(),
                sha256: "66".repeat(32),
                version: "umoci version 0.4.7".to_owned(),
            }],
            source_date_epoch: 1_786_940_622,
        },
        validator: ValidatorContract {
            hello: HelloContract {
                guest_contract_id: "77".repeat(32),
                init_build_id: "88".repeat(32),
                kernel_build_id: "33".repeat(32),
                required_features: pocket_protocol::VALIDATOR_GUEST_FEATURES
                    .iter()
                    .map(|feature| (*feature).to_owned())
                    .collect(),
            },
            manifest_schema: "pocket-fs-manifest-v1".to_owned(),
        },
        launch: LaunchContract {
            linkage: "static".to_owned(),
            cooperative_backend: "seccomp-on".to_owned(),
            noreboot: true,
            rdinit: "/init".to_owned(),
            rootfstype: "ramfs".to_owned(),
            ubd: "cow-v3".to_owned(),
            serial: "ssl-fd-v1".to_owned(),
            network: "none".to_owned(),
            max_ubd_path_bytes: 4095,
            max_umid_bytes: 63,
            max_unix_path_bytes: 107,
        },
        artifacts: ArtifactManifest {
            guard: empty_artifact("host/pocket-guard"),
            uml: empty_artifact("host/linux-uml"),
            skopeo: empty_artifact("host/skopeo"),
            registry_ca_bundle: empty_artifact("host/registry-ca.pem"),
            workload_initramfs: empty_artifact("guest/workload.cpio"),
            builder_initramfs: empty_artifact("guest/builder.cpio"),
            validator_initramfs: empty_artifact("guest/validator.cpio"),
            mke2fs: empty_artifact("host/mke2fs"),
            e2fsck: empty_artifact("host/e2fsck"),
            mke2fs_config: empty_artifact("host/mke2fs.conf"),
            e2fsck_config: empty_artifact("host/e2fsck.conf"),
            normalized_kernel_config: empty_artifact("audit/kernel.config"),
        },
    };
    manifest.profile_revision = manifest.computed_revision().expect("synthetic revision");
    let cpu_profile = CpuProfile::new(smp, cpu.product_max_cpus, cpu.compiled_nr_cpus)
        .expect("synthetic CPU profile");
    let memory_policy = MemoryPolicy::new(
        manifest.memory.minimum_bytes,
        manifest.memory.effective_max_memory_bytes,
        manifest.memory.alignment_bytes,
    )
    .expect("synthetic memory profile");
    VerifiedProfile {
        guard: VerifiedArtifact {
            path: root.as_path().join("host/pocket-guard"),
            spec: manifest.artifacts.guard.clone(),
            role: ArtifactRole::HostExecutable,
        },
        uml: VerifiedArtifact {
            path: root.as_path().join("host/linux-uml"),
            spec: manifest.artifacts.uml.clone(),
            role: ArtifactRole::HostExecutable,
        },
        skopeo: VerifiedArtifact {
            path: root.as_path().join("host/skopeo"),
            spec: manifest.artifacts.skopeo.clone(),
            role: ArtifactRole::HostExecutable,
        },
        registry_ca_bundle: VerifiedArtifact {
            path: root.as_path().join("host/registry-ca.pem"),
            spec: manifest.artifacts.registry_ca_bundle.clone(),
            role: ArtifactRole::Data,
        },
        initramfs: VerifiedArtifact {
            path: root.as_path().join("guest/workload.cpio"),
            spec: manifest.artifacts.workload_initramfs.clone(),
            role: ArtifactRole::Initramfs,
        },
        builder_initramfs: VerifiedArtifact {
            path: root.as_path().join("guest/builder.cpio"),
            spec: manifest.artifacts.builder_initramfs.clone(),
            role: ArtifactRole::Initramfs,
        },
        validator_initramfs: VerifiedArtifact {
            path: root.as_path().join("guest/validator.cpio"),
            spec: manifest.artifacts.validator_initramfs.clone(),
            role: ArtifactRole::Initramfs,
        },
        mke2fs: VerifiedArtifact {
            path: root.as_path().join("host/mke2fs"),
            spec: manifest.artifacts.mke2fs.clone(),
            role: ArtifactRole::HostExecutable,
        },
        e2fsck: VerifiedArtifact {
            path: root.as_path().join("host/e2fsck"),
            spec: manifest.artifacts.e2fsck.clone(),
            role: ArtifactRole::HostExecutable,
        },
        mke2fs_config: VerifiedArtifact {
            path: root.as_path().join("host/mke2fs.conf"),
            spec: manifest.artifacts.mke2fs_config.clone(),
            role: ArtifactRole::Data,
        },
        e2fsck_config: VerifiedArtifact {
            path: root.as_path().join("host/e2fsck.conf"),
            spec: manifest.artifacts.e2fsck_config.clone(),
            role: ArtifactRole::Data,
        },
        kernel_config: VerifiedArtifact {
            path: root.as_path().join("audit/kernel.config"),
            spec: manifest.artifacts.normalized_kernel_config.clone(),
            role: ArtifactRole::KernelConfig,
        },
        root,
        manifest,
        cpu_profile,
        memory_policy,
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt, path::Path};

    use pocket_core::ManagedUmlPath;
    use sha2::{Digest as _, Sha256};
    use tempfile::tempdir;

    use super::{
        ArtifactDigest, ArtifactSpec, ProfileRevision, VerifiedProfile, synthetic_profile,
    };

    #[test]
    fn digests_require_canonical_sha256_text() {
        let good = format!("sha256:{}", "a1".repeat(32));
        assert_eq!(
            good.parse::<ArtifactDigest>()
                .expect("canonical digest")
                .to_string(),
            good
        );
        assert!("a1".repeat(32).parse::<ArtifactDigest>().is_err());
        assert!(
            format!("sha256:{}", "A1".repeat(32))
                .parse::<ProfileRevision>()
                .is_err()
        );
    }

    #[test]
    fn loads_and_reverifies_complete_static_x86_bundle() {
        let fixture = profile_fixture();
        let profile = VerifiedProfile::load(fixture.root.clone()).expect("verified profile");
        assert_eq!(profile.manifest().profile_id, "x86_64-smp-p4k");
        assert!(profile.reverify().is_ok());

        fs::set_permissions(profile.initramfs_path(), fs::Permissions::from_mode(0o644))
            .expect("writable initramfs");
        fs::write(profile.initramfs_path(), b"corrupt").expect("corrupt initramfs");
        assert!(profile.reverify().is_err());
    }

    #[test]
    fn rejects_a_revision_bound_but_nonempty_e2fsck_configuration() {
        let fixture = profile_fixture();
        let config = fixture.root.as_path().join("host/e2fsck.conf");
        fs::set_permissions(&config, fs::Permissions::from_mode(0o644))
            .expect("writable e2fsck config");
        fs::write(&config, b"[options]\nallow_cancellation = true\n")
            .expect("nonempty e2fsck config");
        fs::set_permissions(&config, fs::Permissions::from_mode(0o444))
            .expect("sealed e2fsck config");

        let manifest_path = fixture.root.as_path().join("profile.json");
        let mut manifest: super::ProfileManifest =
            serde_json::from_slice(&fs::read(&manifest_path).expect("profile manifest bytes"))
                .expect("profile manifest");
        manifest.artifacts.e2fsck_config = artifact(fixture.root.as_path(), "host/e2fsck.conf");
        manifest.profile_revision = manifest.computed_revision().expect("updated revision");
        fs::write(
            &manifest_path,
            serde_json::to_vec_pretty(&manifest).expect("updated manifest JSON"),
        )
        .expect("updated manifest");

        let error = VerifiedProfile::load(fixture.root.clone())
            .expect_err("nonempty e2fsck policy must be unsupported");
        assert!(error.to_string().contains("exact empty configuration"));
    }

    #[test]
    fn builder_validator_memory_and_mandatory_release_features_are_revision_bound() {
        let root = ManagedUmlPath::new("/tmp/pocket/tests/profile-contract")
            .expect("managed synthetic path");
        let profile = synthetic_profile(root, true);
        let mut manifest = profile.manifest().clone();
        manifest.memory.builder_memory_bytes = manifest.memory.effective_max_memory_bytes + 4096;
        assert!(super::validate_manifest(&manifest).is_err());

        let mut manifest = profile.manifest().clone();
        manifest.memory.validator_memory_bytes = manifest.memory.effective_max_memory_bytes + 4096;
        assert!(super::validate_manifest(&manifest).is_err());

        let mut manifest = profile.manifest().clone();
        manifest.memory.default_memory_bytes += 1;
        assert!(super::validate_manifest(&manifest).is_err());

        let mut manifest = profile.manifest().clone();
        manifest
            .validator
            .hello
            .required_features
            .retain(|feature| feature != "ext4-clean-state-v1");
        assert!(super::validate_manifest(&manifest).is_err());

        let mut manifest = profile.manifest().clone();
        manifest
            .builder
            .hello
            .required_features
            .retain(|feature| feature != "account-db-v1");
        assert!(super::validate_manifest(&manifest).is_err());

        let mut manifest = profile.manifest().clone();
        manifest
            .hello
            .required_features
            .retain(|feature| feature != "generated-etc-v1");
        assert!(super::validate_manifest(&manifest).is_err());
    }

    #[test]
    fn rejects_revision_drift_unknown_fields_and_dynamic_elf() {
        let fixture = profile_fixture();
        let manifest_path = fixture.root.as_path().join("profile.json");
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&manifest_path).expect("read manifest"))
                .expect("JSON");
        value["profile_id"] = serde_json::Value::String("changed-profile".to_owned());
        fs::write(
            &manifest_path,
            serde_json::to_vec(&value).expect("serialize"),
        )
        .expect("write manifest");
        assert!(VerifiedProfile::load(fixture.root.clone()).is_err());

        let fixture = profile_fixture();
        let manifest_path = fixture.root.as_path().join("profile.json");
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&manifest_path).expect("read manifest"))
                .expect("JSON");
        value["unknown"] = serde_json::Value::Bool(true);
        fs::write(
            &manifest_path,
            serde_json::to_vec(&value).expect("serialize"),
        )
        .expect("write manifest");
        assert!(VerifiedProfile::load(fixture.root.clone()).is_err());

        let fixture = profile_fixture();
        let uml = fixture.root.as_path().join("host/linux-uml");
        let dynamic = minimal_elf(true);
        fs::set_permissions(&uml, fs::Permissions::from_mode(0o755)).expect("writable UML");
        fs::write(&uml, &dynamic).expect("dynamic UML");
        fs::set_permissions(&uml, fs::Permissions::from_mode(0o555)).expect("UML mode");
        let mut manifest = synthetic_profile(fixture.root.clone(), true)
            .manifest()
            .clone();
        manifest.artifacts = fixture_artifacts(fixture.root.as_path());
        manifest.profile_revision = manifest.computed_revision().expect("revision");
        fs::write(
            fixture.root.as_path().join("profile.json"),
            serde_json::to_vec(&manifest).expect("manifest"),
        )
        .expect("write manifest");
        assert!(VerifiedProfile::load(fixture.root.clone()).is_err());
    }

    #[test]
    fn rejects_static_pie_with_a_dynamic_needed_entry() {
        let temporary = tempdir().expect("tempdir");
        let path = temporary.path().join("needed-elf");
        let bytes = minimal_elf_with_needed();
        fs::write(&path, &bytes).expect("needed ELF");
        let mut file = fs::File::open(&path).expect("open needed ELF");
        let error = super::verify_static_x86_64_elf(&mut file, &path, bytes.len() as u64)
            .expect_err("DT_NEEDED must be rejected");
        assert!(error.to_string().contains("DT_NEEDED"));
    }

    #[test]
    fn registry_ca_allows_utf8_comments_but_rejects_non_base64_pem_bodies() {
        let temporary = tempdir().expect("tempdir");
        let path = temporary.path().join("registry-ca.pem");
        fs::write(
            &path,
            "## Főtanúsítvány\n-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----\n",
        )
        .expect("valid CA fixture");
        assert!(super::validate_registry_ca_bundle(&path).is_ok());

        fs::write(
            &path,
            "-----BEGIN CERTIFICATE-----\nnot base64!\n-----END CERTIFICATE-----\n",
        )
        .expect("invalid CA fixture");
        assert!(super::validate_registry_ca_bundle(&path).is_err());
    }

    struct ProfileFixture {
        _temporary: tempfile::TempDir,
        root: ManagedUmlPath,
    }

    fn profile_fixture() -> ProfileFixture {
        let temporary = tempdir().expect("tempdir");
        let root_path = temporary.path().join("bundle");
        for directory in ["host", "guest", "audit"] {
            fs::create_dir_all(root_path.join(directory)).expect("bundle directory");
            fs::set_permissions(root_path.join(directory), fs::Permissions::from_mode(0o755))
                .expect("bundle-directory mode");
        }
        fs::set_permissions(&root_path, fs::Permissions::from_mode(0o755))
            .expect("bundle-root mode");
        for executable in [
            "host/pocket-guard",
            "host/linux-uml",
            "host/skopeo",
            "host/mke2fs",
            "host/e2fsck",
        ] {
            let path = root_path.join(executable);
            fs::write(&path, minimal_elf(false)).expect("ELF");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o555)).expect("ELF mode");
        }
        let mke2fs_config = root_path.join("host/mke2fs.conf");
        fs::write(
            &mke2fs_config,
            "[defaults]\nbase_features = sparse_super,filetype,resize_inode,dir_index,ext_attr\n",
        )
        .expect("mke2fs config");
        fs::set_permissions(&mke2fs_config, fs::Permissions::from_mode(0o444))
            .expect("mke2fs config mode");
        let e2fsck_config = root_path.join("host/e2fsck.conf");
        fs::write(&e2fsck_config, b"").expect("empty e2fsck config");
        fs::set_permissions(&e2fsck_config, fs::Permissions::from_mode(0o444))
            .expect("e2fsck config mode");
        let registry_ca_bundle = root_path.join("host/registry-ca.pem");
        fs::write(
            &registry_ca_bundle,
            b"-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----\n",
        )
        .expect("registry CA bundle");
        fs::set_permissions(&registry_ca_bundle, fs::Permissions::from_mode(0o444))
            .expect("registry CA mode");
        let initramfs = root_path.join("guest/workload.cpio");
        fs::write(&initramfs, b"070701fixture").expect("initramfs");
        fs::set_permissions(&initramfs, fs::Permissions::from_mode(0o444)).expect("initramfs mode");
        let builder_initramfs = root_path.join("guest/builder.cpio");
        fs::write(&builder_initramfs, b"070701builder-fixture").expect("builder initramfs");
        fs::set_permissions(&builder_initramfs, fs::Permissions::from_mode(0o444))
            .expect("builder initramfs mode");
        let validator_initramfs = root_path.join("guest/validator.cpio");
        fs::write(&validator_initramfs, b"070701validator-fixture").expect("validator initramfs");
        fs::set_permissions(&validator_initramfs, fs::Permissions::from_mode(0o444))
            .expect("validator initramfs mode");
        let config = root_path.join("audit/kernel.config");
        fs::write(&config, kernel_config()).expect("config");
        fs::set_permissions(&config, fs::Permissions::from_mode(0o444)).expect("config mode");

        let root = ManagedUmlPath::new(&root_path).expect("managed root");
        let mut manifest = synthetic_profile(root.clone(), true).manifest().clone();
        manifest.artifacts = fixture_artifacts(&root_path);
        manifest.profile_revision = manifest.computed_revision().expect("revision");
        fs::write(
            root_path.join("profile.json"),
            serde_json::to_vec_pretty(&manifest).expect("manifest JSON"),
        )
        .expect("manifest");
        ProfileFixture {
            _temporary: temporary,
            root,
        }
    }

    fn fixture_artifacts(root: &Path) -> super::ArtifactManifest {
        super::ArtifactManifest {
            guard: artifact(root, "host/pocket-guard"),
            uml: artifact(root, "host/linux-uml"),
            skopeo: artifact(root, "host/skopeo"),
            registry_ca_bundle: artifact(root, "host/registry-ca.pem"),
            workload_initramfs: artifact(root, "guest/workload.cpio"),
            builder_initramfs: artifact(root, "guest/builder.cpio"),
            validator_initramfs: artifact(root, "guest/validator.cpio"),
            mke2fs: artifact(root, "host/mke2fs"),
            e2fsck: artifact(root, "host/e2fsck"),
            mke2fs_config: artifact(root, "host/mke2fs.conf"),
            e2fsck_config: artifact(root, "host/e2fsck.conf"),
            normalized_kernel_config: artifact(root, "audit/kernel.config"),
        }
    }

    fn artifact(root: &Path, relative: &str) -> ArtifactSpec {
        let bytes = fs::read(root.join(relative)).expect("artifact bytes");
        ArtifactSpec {
            path: relative.to_owned(),
            sha256: ArtifactDigest::from_bytes(Sha256::digest(&bytes).into()),
            size: bytes.len() as u64,
        }
    }

    fn minimal_elf(dynamic: bool) -> Vec<u8> {
        let mut bytes = vec![0_u8; 64 + 56 + if dynamic { 8 } else { 0 }];
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
        bytes[64..68].copy_from_slice(&(if dynamic { 3_u32 } else { 1_u32 }).to_le_bytes());
        if dynamic {
            bytes[72..80].copy_from_slice(&120_u64.to_le_bytes());
            bytes[96..104].copy_from_slice(&8_u64.to_le_bytes());
            bytes[120..128].copy_from_slice(b"/ld.so\0\0");
        }
        bytes
    }

    fn minimal_elf_with_needed() -> Vec<u8> {
        let mut bytes = vec![0_u8; 64 + 56 + 32];
        bytes[..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[6] = 1;
        bytes[16..18].copy_from_slice(&3_u16.to_le_bytes());
        bytes[18..20].copy_from_slice(&62_u16.to_le_bytes());
        bytes[32..40].copy_from_slice(&64_u64.to_le_bytes());
        bytes[52..54].copy_from_slice(&64_u16.to_le_bytes());
        bytes[54..56].copy_from_slice(&56_u16.to_le_bytes());
        bytes[56..58].copy_from_slice(&1_u16.to_le_bytes());
        bytes[64..68].copy_from_slice(&2_u32.to_le_bytes());
        bytes[72..80].copy_from_slice(&120_u64.to_le_bytes());
        bytes[96..104].copy_from_slice(&32_u64.to_le_bytes());
        bytes[120..128].copy_from_slice(&1_u64.to_le_bytes());
        bytes[136..144].copy_from_slice(&0_u64.to_le_bytes());
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
        ];
        let no = [
            "CONFIG_BLK_DEV_UBD_SYNC",
            "CONFIG_BLK_DEV_LOOP",
            "CONFIG_BLK_DEV_NBD",
            "CONFIG_HOSTFS",
            "CONFIG_MCONSOLE",
            "CONFIG_MODULES",
            "CONFIG_UML_NET_VECTOR",
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
