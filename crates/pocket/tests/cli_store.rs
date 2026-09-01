use std::{
    fmt::Display,
    fs,
    io::{Cursor, Write},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use pocket::{OPERATIONAL_ERROR_EXIT, run_from};
use pocket_core::ManagedUmlPath;
use pocket_runtime::{
    ArtifactDigest, ArtifactManifest, ArtifactSpec, BuilderContract, BuilderToolContract,
    Contracts, CpuManifest, HelloContract, LaunchContract, MemoryManifest, PROFILE_SCHEMA_VERSION,
    ProfileManifest, ProfileMaturity, ProfileRevision, ValidatorContract,
};
use pocket_store::{
    AliasKey, BeginGeneration, Digest, GenerationId, GenerationSpec, Platform, Store,
};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use tempfile::TempDir;

fn must<T, E: Display>(result: Result<T, E>, operation: &str) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("{operation}: {error}"),
    }
}

fn invoke(arguments: &[String]) -> (u8, Vec<u8>, Vec<u8>) {
    let mut input = Cursor::new(Vec::<u8>::new());
    let mut output = Vec::new();
    let mut error = Vec::new();
    let status = run_from(
        arguments.iter().map(String::as_str),
        &mut input,
        &mut output,
        &mut error,
    );
    (status, output, error)
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn json(bytes: &[u8]) -> Value {
    must(serde_json::from_slice(bytes), "parse CLI JSON")
}

struct ProfileFixture {
    _temporary: TempDir,
    root: PathBuf,
    manifest: ProfileManifest,
}

fn profile_fixture() -> ProfileFixture {
    let temporary = must(tempfile::tempdir(), "create profile tempdir");
    let root = temporary.path().join("pocket").join("bundle");
    for directory in ["host", "guest", "audit"] {
        let path = root.join(directory);
        must(fs::create_dir_all(&path), "create profile directory");
        must(
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755)),
            "set profile-directory mode",
        );
    }
    must(
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)),
        "set profile-root mode",
    );

    for relative in [
        "host/pocket-guard",
        "host/linux-uml",
        "host/skopeo",
        "host/mke2fs",
        "host/e2fsck",
    ] {
        write_artifact(&root.join(relative), &minimal_elf(), 0o555);
    }
    write_artifact(
        &root.join("host/mke2fs.conf"),
        b"[defaults]\nbase_features = sparse_super,filetype,resize_inode,dir_index,ext_attr\n",
        0o444,
    );
    write_artifact(&root.join("host/e2fsck.conf"), b"", 0o444);
    write_artifact(
        &root.join("host/registry-ca.pem"),
        b"-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----\n",
        0o444,
    );
    write_artifact(&root.join("guest/workload.cpio"), b"070701workload", 0o444);
    write_artifact(&root.join("guest/builder.cpio"), b"070701builder", 0o444);
    write_artifact(
        &root.join("guest/validator.cpio"),
        b"070701validator",
        0o444,
    );
    write_artifact(
        &root.join("audit/kernel.config"),
        kernel_config().as_bytes(),
        0o444,
    );

    let artifacts = ArtifactManifest {
        guard: artifact(&root, "host/pocket-guard"),
        uml: artifact(&root, "host/linux-uml"),
        skopeo: artifact(&root, "host/skopeo"),
        registry_ca_bundle: artifact(&root, "host/registry-ca.pem"),
        workload_initramfs: artifact(&root, "guest/workload.cpio"),
        builder_initramfs: artifact(&root, "guest/builder.cpio"),
        validator_initramfs: artifact(&root, "guest/validator.cpio"),
        mke2fs: artifact(&root, "host/mke2fs"),
        e2fsck: artifact(&root, "host/e2fsck"),
        mke2fs_config: artifact(&root, "host/mke2fs.conf"),
        e2fsck_config: artifact(&root, "host/e2fsck.conf"),
        normalized_kernel_config: artifact(&root, "audit/kernel.config"),
    };
    let mut manifest = ProfileManifest {
        schema_version: PROFILE_SCHEMA_VERSION,
        profile_id: "x86_64-smp-p4k".to_owned(),
        profile_revision: ProfileRevision::from_bytes([0; 32]),
        maturity: ProfileMaturity::Experimental,
        host_architecture: "x86_64".to_owned(),
        host_elf_machine: 62,
        oci_os: "linux".to_owned(),
        oci_architecture: "amd64".to_owned(),
        accepted_oci_variants: vec![None, Some("v1".to_owned())],
        uml_subarchitecture: "x86_64".to_owned(),
        guest_page_size: 4096,
        cpu: CpuManifest {
            smp_enabled: true,
            product_max_cpus: 8,
            compiled_nr_cpus: Some(16),
            effective_max_cpus: 8,
        },
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
        artifacts,
    };
    manifest.profile_revision = must(manifest.computed_revision(), "compute profile revision");
    let encoded = must(
        serde_json::to_vec_pretty(&manifest),
        "serialize profile manifest",
    );
    write_artifact(&root.join("profile.json"), &encoded, 0o444);
    ProfileFixture {
        _temporary: temporary,
        root,
        manifest,
    }
}

fn write_artifact(path: &Path, bytes: &[u8], mode: u32) {
    must(fs::write(path, bytes), "write fixture artifact");
    must(
        fs::set_permissions(path, fs::Permissions::from_mode(mode)),
        "set fixture-artifact mode",
    );
}

fn artifact(root: &Path, relative: &str) -> ArtifactSpec {
    let bytes = must(fs::read(root.join(relative)), "read fixture artifact");
    ArtifactSpec {
        path: relative.to_owned(),
        sha256: ArtifactDigest::from_bytes(Sha256::digest(&bytes).into()),
        size: bytes.len() as u64,
    }
}

fn minimal_elf() -> Vec<u8> {
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

struct StoreFixture {
    _temporary: TempDir,
    root: PathBuf,
    store: Store,
}

fn store_fixture() -> StoreFixture {
    let temporary = must(tempfile::tempdir(), "create store tempdir");
    let parent = temporary.path().join("pocket");
    must(fs::create_dir(&parent), "create store parent");
    let root = parent.join("cache");
    let managed = must(ManagedUmlPath::new(&root), "validate store root");
    let store = must(Store::initialize(managed), "initialize store");
    StoreFixture {
        _temporary: temporary,
        root,
        store,
    }
}

fn store_digest(seed: u8) -> Digest {
    Digest::from_bytes([seed; 32])
}

fn generation_spec(profile: &ProfileManifest, seed: u8) -> GenerationSpec {
    let descriptor = must(
        Platform::new("linux", "amd64", Some("v1".to_owned()), None, Vec::new()),
        "create descriptor platform",
    );
    let config = must(
        Platform::new("linux", "amd64", None, None, Vec::new()),
        "create config platform",
    );
    let effective = must(
        Platform::new("linux", "amd64", Some("v1".to_owned()), None, Vec::new()),
        "create effective platform",
    );
    must(
        GenerationSpec::new(
            store_digest(seed),
            store_digest(seed.wrapping_add(1)),
            vec![store_digest(seed.wrapping_add(2))],
            vec![store_digest(seed.wrapping_add(3))],
            Some(descriptor),
            config,
            effective,
            profile.contracts.selector_policy.clone(),
            profile.profile_id.clone(),
            Digest::from_bytes(profile.profile_revision.as_bytes()),
            profile.contracts.root_layout.clone(),
            profile.contracts.filesystem.clone(),
            store_digest(seed.wrapping_add(4)),
        ),
        "create generation spec",
    )
}

fn publish(store: &Store, spec: GenerationSpec, contents: &[u8]) -> GenerationId {
    let transaction = match must(store.try_begin_generation(spec), "begin generation") {
        BeginGeneration::Existing(_) => panic!("unexpected existing generation"),
        BeginGeneration::Vacant(transaction) => transaction,
    };
    let mut base = must(transaction.create_base(), "create generation base");
    must(base.write_all(contents), "write generation base");
    must(base.sync_all(), "sync generation base");
    drop(base);
    must(
        transaction.publish(Digest::of_bytes(contents)),
        "publish generation",
    )
    .id()
}

#[test]
fn profile_store_inspection_listing_alias_and_gc_are_real_operations() {
    let profile = profile_fixture();
    let store = store_fixture();
    let first_spec = generation_spec(&profile.manifest, 1);
    let first_derivation = first_spec.derivation_key();
    let first_id = publish(&store.store, first_spec, b"first immutable base");
    let second_id = publish(
        &store.store,
        generation_spec(&profile.manifest, 20),
        b"second unrooted base",
    );
    let requested = must(
        Platform::new("linux", "amd64", Some("v1".to_owned()), None, Vec::new()),
        "create alias selector",
    );
    let alias = must(
        AliasKey::new(
            profile.manifest.profile_id.clone(),
            Digest::from_bytes(profile.manifest.profile_revision.as_bytes()),
            "example:latest",
            requested,
            profile.manifest.contracts.selector_policy.clone(),
        ),
        "create alias",
    );
    must(store.store.set_alias(&alias, first_id), "set alias");

    let (status, output, error) = invoke(&[
        "pocket".to_owned(),
        "profile".to_owned(),
        "verify".to_owned(),
        profile.root.display().to_string(),
        "--json".to_owned(),
    ]);
    assert_eq!(status, 0, "{}", text(&error));
    assert!(error.is_empty());
    assert_eq!(json(&output)["profile_id"], "x86_64-smp-p4k");

    let (status, output, error) = invoke(&[
        "pocket".to_owned(),
        "generation".to_owned(),
        "inspect".to_owned(),
        "--store".to_owned(),
        store.root.display().to_string(),
        first_id.to_string(),
        "--json".to_owned(),
    ]);
    assert_eq!(status, 0, "{}", text(&error));
    let inspected = json(&output);
    assert_eq!(inspected["generation_id"], first_id.to_string());
    assert_eq!(inspected["descriptor_platform"]["variant"], "v1");
    assert!(inspected["config_platform"]["variant"].is_null());
    assert_eq!(inspected["effective_platform"]["variant"], "v1");

    let (status, output, error) = invoke(&[
        "pocket".to_owned(),
        "generation".to_owned(),
        "list".to_owned(),
        "--store".to_owned(),
        store.root.display().to_string(),
        "--derivation".to_owned(),
        first_derivation.to_string(),
        "--json".to_owned(),
    ]);
    assert_eq!(status, 0, "{}", text(&error));
    let listed = json(&output);
    assert_eq!(listed.as_array().map(Vec::len), Some(1));
    assert_eq!(listed[0]["generation_id"], first_id.to_string());

    let (status, output, error) = invoke(&[
        "pocket".to_owned(),
        "image".to_owned(),
        "inspect".to_owned(),
        "--profile-bundle".to_owned(),
        profile.root.display().to_string(),
        "--store".to_owned(),
        store.root.display().to_string(),
        "--platform".to_owned(),
        "linux/amd64/v1".to_owned(),
        "example:latest".to_owned(),
        "--json".to_owned(),
    ]);
    assert_eq!(status, 0, "{}", text(&error));
    assert_eq!(json(&output)["generation_id"], first_id.to_string());

    let (status, output, error) = invoke(&[
        "pocket".to_owned(),
        "cache".to_owned(),
        "gc".to_owned(),
        "--store".to_owned(),
        store.root.display().to_string(),
        "--apply".to_owned(),
        "--json".to_owned(),
    ]);
    assert_eq!(status, 0, "{}", text(&error));
    let report = json(&output);
    assert_eq!(report["applied"], true);
    assert!(
        report["rooted"]
            .as_array()
            .is_some_and(|ids| ids.contains(&Value::String(first_id.to_string())))
    );
    assert!(
        report["collected"]
            .as_array()
            .is_some_and(|ids| ids.contains(&Value::String(second_id.to_string())))
    );
}

#[test]
fn invalid_identifiers_precede_store_access_and_platform_cannot_switch_profile() {
    let (status, _, error) = invoke(&[
        "pocket".to_owned(),
        "generation".to_owned(),
        "inspect".to_owned(),
        "--store".to_owned(),
        "/tmp/pocket/missing-store".to_owned(),
        "pkvm-gen-v1-not-a-digest".to_owned(),
    ]);
    assert_eq!(status, OPERATIONAL_ERROR_EXIT);
    assert!(text(&error).contains("E_CLI_INVALID_INPUT"));
    assert!(!text(&error).contains("No such file"));

    let profile = profile_fixture();
    let (status, _, error) = invoke(&[
        "pocket".to_owned(),
        "image".to_owned(),
        "inspect".to_owned(),
        "--profile-bundle".to_owned(),
        profile.root.display().to_string(),
        "--store".to_owned(),
        "/tmp/pocket/missing-store".to_owned(),
        "--platform".to_owned(),
        "linux/arm64/v8".to_owned(),
        "example:latest".to_owned(),
    ]);
    assert_eq!(status, OPERATIONAL_ERROR_EXIT);
    assert!(text(&error).contains("E_CLI_INVALID_INPUT"));
    assert!(text(&error).contains("profile switching are unavailable"));
    assert!(!text(&error).contains("No such file"));
}
