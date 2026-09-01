use std::error::Error as StdError;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use pocket_oci::{
    Error, LayerCompression, SELECTOR_POLICY_ID, VerifyLimits, parse_image_process_config,
    verify_canonical_layout, verify_layout, verify_layout_with_limits,
};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use tempfile::TempDir;

const OCI_INDEX: &str = "application/vnd.oci.image.index.v1+json";
const OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
const DOCKER_MANIFEST: &str = "application/vnd.docker.distribution.manifest.v2+json";
const OCI_CONFIG: &str = "application/vnd.oci.image.config.v1+json";
const DOCKER_CONFIG: &str = "application/vnd.docker.container.image.v1+json";
const OCI_LAYER: &str = "application/vnd.oci.image.layer.v1.tar";
const OCI_LAYER_GZIP: &str = "application/vnd.oci.image.layer.v1.tar+gzip";
const OCI_LAYER_ZSTD: &str = "application/vnd.oci.image.layer.v1.tar+zstd";
const DOCKER_LAYER_GZIP: &str = "application/vnd.docker.image.rootfs.diff.tar.gzip";
const FOREIGN_LAYER: &str = "application/vnd.docker.image.rootfs.foreign.diff.tar.gzip";

type TestResult<T = ()> = std::result::Result<T, Box<dyn StdError>>;

#[derive(Clone)]
struct ImageOptions {
    manifest_media_type: &'static str,
    config_media_type: &'static str,
    layer_media_type: &'static str,
    descriptor_platform: Option<Value>,
    config_os: &'static str,
    config_architecture: &'static str,
    config_variant: Option<&'static str>,
    config_os_version: Option<&'static str>,
    config_os_features: Vec<&'static str>,
    diff_id_count: usize,
    uncompressed_layer: Vec<u8>,
    encoded_layer_override: Option<Vec<u8>>,
    diff_id_payload_override: Option<Vec<u8>>,
    runtime_config: Value,
    /// Verbatim value for the config descriptor's optional `data` field.
    config_descriptor_data: Option<String>,
}

impl Default for ImageOptions {
    fn default() -> Self {
        Self {
            manifest_media_type: OCI_MANIFEST,
            config_media_type: OCI_CONFIG,
            layer_media_type: OCI_LAYER,
            descriptor_platform: Some(target_platform(None, Vec::new())),
            config_os: "linux",
            config_architecture: "amd64",
            config_variant: None,
            config_os_version: None,
            config_os_features: Vec::new(),
            diff_id_count: 1,
            uncompressed_layer: b"synthetic uncompressed layer".to_vec(),
            encoded_layer_override: None,
            diff_id_payload_override: None,
            config_descriptor_data: None,
            runtime_config: json!({
                "Env": ["A=1"],
                "Entrypoint": ["/bin/demo"],
                "Cmd": ["--flag"],
                "WorkingDir": "/work",
                "User": "1000:1000",
                "Labels": {"org.example.test": "yes"},
                "StopSignal": "SIGTERM"
            }),
        }
    }
}

struct BuiltImage {
    descriptor: Value,
    layer_path: PathBuf,
}

fn new_layout() -> TestResult<TempDir> {
    let temporary = tempfile::tempdir()?;
    std::fs::create_dir_all(temporary.path().join("blobs/sha256"))?;
    std::fs::write(
        temporary.path().join("oci-layout"),
        serde_json::to_vec(&json!({"imageLayoutVersion": "1.0.0"}))?,
    )?;
    Ok(temporary)
}

fn target_platform(variant: Option<&str>, os_features: Vec<&str>) -> Value {
    json!({
        "os": "linux",
        "architecture": "amd64",
        "variant": variant,
        "os.features": os_features,
    })
}

fn arm_platform() -> Value {
    json!({
        "os": "linux",
        "architecture": "arm64",
        "variant": "v8"
    })
}

fn sha256_text(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn standalone_config(runtime: Value) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "architecture": "amd64",
        "os": "linux",
        "rootfs": {
            "type": "layers",
            "diff_ids": [format!("sha256:{}", "11".repeat(32))]
        },
        "config": runtime
    }))
    .expect("serialize standalone config")
}

fn encode_layer(media_type: &str, uncompressed: &[u8]) -> TestResult<Vec<u8>> {
    match media_type {
        OCI_LAYER_GZIP | DOCKER_LAYER_GZIP | FOREIGN_LAYER => {
            let mut encoder =
                flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            encoder.write_all(uncompressed)?;
            Ok(encoder.finish()?)
        }
        OCI_LAYER_ZSTD => Ok(zstd::stream::encode_all(uncompressed, 0)?),
        _ => Ok(uncompressed.to_vec()),
    }
}

fn write_blob(
    root: &Path,
    media_type: &str,
    bytes: &[u8],
    platform: Option<Value>,
) -> TestResult<Value> {
    let digest = sha256_text(bytes);
    let encoded = digest
        .strip_prefix("sha256:")
        .ok_or_else(|| std::io::Error::other("test digest lacks prefix"))?;
    let path = root.join("blobs/sha256").join(encoded);
    std::fs::write(path, bytes)?;
    let mut descriptor = json!({
        "mediaType": media_type,
        "digest": digest,
        "size": bytes.len()
    });
    if let Some(platform) = platform {
        descriptor["platform"] = platform;
    }
    Ok(descriptor)
}

fn build_image(root: &Path, options: &ImageOptions) -> TestResult<BuiltImage> {
    let layer_bytes = if let Some(override_bytes) = options.encoded_layer_override.as_ref() {
        override_bytes.clone()
    } else {
        encode_layer(options.layer_media_type, &options.uncompressed_layer)?
    };
    let layer_descriptor = write_blob(root, options.layer_media_type, &layer_bytes, None)?;
    let layer_digest = sha256_text(&layer_bytes);
    let layer_path = root.join("blobs/sha256").join(
        layer_digest
            .strip_prefix("sha256:")
            .ok_or_else(|| std::io::Error::other("test digest lacks prefix"))?,
    );

    let diff_id_payload = options
        .diff_id_payload_override
        .as_deref()
        .unwrap_or(&options.uncompressed_layer);
    let diff_ids: Vec<String> = (0..options.diff_id_count)
        .map(|_| sha256_text(diff_id_payload))
        .collect();
    let config = json!({
        "architecture": options.config_architecture,
        "os": options.config_os,
        "variant": options.config_variant,
        "os.version": options.config_os_version,
        "os.features": options.config_os_features,
        "rootfs": {"type": "layers", "diff_ids": diff_ids},
        "config": options.runtime_config
    });
    let config_bytes = serde_json::to_vec(&config)?;
    let mut config_descriptor = write_blob(root, options.config_media_type, &config_bytes, None)?;
    if let Some(data) = options.config_descriptor_data.as_ref() {
        let data = if data == "@matching" {
            encode_base64(&config_bytes)
        } else {
            data.clone()
        };
        config_descriptor
            .as_object_mut()
            .ok_or_else(|| std::io::Error::other("config descriptor is not an object"))?
            .insert("data".to_owned(), Value::String(data));
    }

    let manifest = json!({
        "schemaVersion": 2,
        "mediaType": options.manifest_media_type,
        "config": config_descriptor,
        "layers": [layer_descriptor]
    });
    let manifest_bytes = serde_json::to_vec(&manifest)?;
    let descriptor = write_blob(
        root,
        options.manifest_media_type,
        &manifest_bytes,
        options.descriptor_platform.clone(),
    )?;
    Ok(BuiltImage {
        descriptor,
        layer_path,
    })
}

/// Standard base64 with canonical padding, matching what a registry emits for
/// an inline descriptor copy.
fn encode_base64(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut encoded = String::with_capacity(input.len().div_ceil(3) * 4);
    for group in input.chunks(3) {
        let mut accumulator = 0_u32;
        for index in 0..3 {
            accumulator = (accumulator << 8) | u32::from(group.get(index).copied().unwrap_or(0));
        }
        let symbols = 1 + group.len();
        for index in 0..4 {
            if index < symbols {
                let shift = 18 - 6 * index;
                let value = usize::try_from((accumulator >> shift) & 0x3f).unwrap_or(0);
                encoded.push(char::from(ALPHABET[value]));
            } else {
                encoded.push('=');
            }
        }
    }
    encoded
}

fn write_index(root: &Path, manifests: Vec<Value>) -> TestResult {
    std::fs::write(
        root.join("index.json"),
        serde_json::to_vec(&json!({
            "schemaVersion": 2,
            "mediaType": OCI_INDEX,
            "manifests": manifests
        }))?,
    )?;
    Ok(())
}

fn nested_index_descriptor(root: &Path, manifests: Vec<Value>) -> TestResult<Value> {
    let nested = serde_json::to_vec(&json!({
        "schemaVersion": 2,
        "mediaType": OCI_INDEX,
        "manifests": manifests
    }))?;
    write_blob(root, OCI_INDEX, &nested, None)
}

fn failure<T>(result: pocket_oci::Result<T>) -> TestResult<Error> {
    match result {
        Ok(_) => Err(std::io::Error::other("verification unexpectedly succeeded").into()),
        Err(error) => Ok(error),
    }
}

fn build_with_config_data(data: &str) -> TestResult<(TempDir, PathBuf)> {
    let layout = new_layout()?;
    let root = layout.path().to_path_buf();
    let image = build_image(
        &root,
        &ImageOptions {
            config_descriptor_data: Some(data.to_owned()),
            ..ImageOptions::default()
        },
    )?;
    write_index(&root, vec![image.descriptor])?;
    Ok((layout, root))
}

/// Real registries (the official Debian images among them) inline a copy of a
/// small config blob in the descriptor's optional `data` field. The copy is
/// redundant, never used as a content source, and must be checked rather than
/// treated as grounds to refuse the image.
#[test]
fn accepts_a_config_descriptor_whose_inline_data_matches_the_blob() -> TestResult {
    let (_layout, root) = build_with_config_data("@matching")?;
    verify_layout(&root)?;
    Ok(())
}

#[test]
fn rejects_inline_descriptor_data_that_disagrees_with_the_blob() -> TestResult {
    let (_layout, root) = build_with_config_data("@matching")?;
    let manifest_digest = {
        let index: Value = serde_json::from_slice(&std::fs::read(root.join("index.json"))?)?;
        index["manifests"][0]["digest"]
            .as_str()
            .ok_or_else(|| std::io::Error::other("index descriptor lacks a digest"))?
            .to_owned()
    };
    let manifest_path = root.join("blobs/sha256").join(
        manifest_digest
            .strip_prefix("sha256:")
            .ok_or_else(|| std::io::Error::other("digest lacks its prefix"))?,
    );
    let mut manifest: Value = serde_json::from_slice(&std::fs::read(&manifest_path)?)?;
    let encoded = manifest["config"]["data"]
        .as_str()
        .ok_or_else(|| std::io::Error::other("inline data is missing"))?
        .to_owned();
    // Same length, different content: only a digest check can catch this.
    let mut corrupted: Vec<u8> = encoded.into_bytes();
    let last = corrupted
        .iter()
        .rposition(|byte| *byte != b'=')
        .ok_or_else(|| std::io::Error::other("inline data is empty"))?;
    corrupted[last] = if corrupted[last] == b'A' { b'B' } else { b'A' };
    manifest["config"]["data"] = Value::String(String::from_utf8(corrupted)?);
    std::fs::write(&manifest_path, serde_json::to_vec(&manifest)?)?;
    // The manifest blob was rewritten in place, so re-point the index at it.
    let rewritten = sha256_text(&std::fs::read(&manifest_path)?);
    let target = root.join("blobs/sha256").join(
        rewritten
            .strip_prefix("sha256:")
            .ok_or_else(|| std::io::Error::other("digest lacks its prefix"))?,
    );
    std::fs::rename(&manifest_path, &target)?;
    let mut index: Value = serde_json::from_slice(&std::fs::read(root.join("index.json"))?)?;
    index["manifests"][0]["digest"] = Value::String(rewritten);
    index["manifests"][0]["size"] = json!(std::fs::metadata(&target)?.len());
    std::fs::write(root.join("index.json"), serde_json::to_vec(&index)?)?;

    let error = failure(verify_layout(&root))?;
    assert!(
        format!("{error}").contains("embedded descriptor data"),
        "unexpected error: {error}"
    );
    Ok(())
}

#[test]
fn rejects_noncanonically_encoded_inline_descriptor_data() -> TestResult {
    for encoding in [
        "not base64!",
        "QQ",    // unpadded
        "QQ ==", // embedded space
        "QQ=A",  // padding followed by a symbol
        "QR==",  // nonzero trailing bits
        "-_==",  // URL-safe alphabet
    ] {
        let (_layout, root) = build_with_config_data(encoding)?;
        let error = failure(verify_layout(&root))?;
        assert!(
            format!("{error}").contains("embedded descriptor data"),
            "encoding {encoding:?} produced {error}"
        );
    }
    Ok(())
}

#[test]
fn canonical_builder_boundary_requires_the_root_ref_name() -> TestResult {
    let layout = new_layout()?;
    let mut image = build_image(layout.path(), &ImageOptions::default())?;
    write_index(layout.path(), vec![image.descriptor.clone()])?;
    assert!(matches!(
        failure(verify_canonical_layout(layout.path()))?,
        Error::InvalidDocument { .. }
    ));

    image.descriptor["annotations"] = json!({"org.opencontainers.image.ref.name": "root"});
    write_index(layout.path(), vec![image.descriptor])?;
    verify_canonical_layout(layout.path())?;
    Ok(())
}

#[test]
fn verifies_direct_manifest_and_exposes_effective_process() -> TestResult {
    let layout = new_layout()?;
    let image = build_image(layout.path(), &ImageOptions::default())?;
    write_index(layout.path(), vec![image.descriptor])?;

    let verified = verify_layout(layout.path())?;
    assert_eq!(verified.process.entrypoint, ["/bin/demo"]);
    assert_eq!(verified.process.cmd, ["--flag"]);
    assert_eq!(verified.process.argv, ["/bin/demo", "--flag"]);
    assert_eq!(verified.process.env, ["A=1"]);
    assert_eq!(verified.process.working_dir, "/work");
    assert_eq!(verified.process.user, "1000:1000");
    assert_eq!(verified.selector_policy, SELECTOR_POLICY_ID);
    assert_eq!(
        verified
            .descriptor_platform
            .as_ref()
            .and_then(|platform| platform.variant.as_deref()),
        None
    );
    assert_eq!(verified.config_platform.architecture, "amd64");
    assert_eq!(verified.effective_platform.variant, None);
    let raw_config: Value = serde_json::from_slice(&verified.config_bytes)?;
    assert_eq!(raw_config["config"]["User"], "1000:1000");
    assert_eq!(verified.config_size, verified.config_bytes.len() as u64);
    assert_eq!(verified.layers.len(), 1);
    assert_eq!(verified.layers[0].compression, LayerCompression::None);
    assert_eq!(
        verified.layers[0].uncompressed_size,
        u64::try_from(b"synthetic uncompressed layer".len())?
    );
    Ok(())
}

#[test]
fn reparses_authenticated_config_sidecar_with_ingestion_process_rules() -> TestResult {
    let bytes = standalone_config(json!({
        "Entrypoint": ["/bin/demo"],
        "Cmd": ["--flag"],
        "Env": ["A=1"],
        "WorkingDir": "/work",
        "User": "app:app",
        "StopSignal": "SIGTERM"
    }));
    let process = parse_image_process_config(&bytes)?;
    assert_eq!(process.argv, ["/bin/demo", "--flag"]);
    assert_eq!(process.env, ["A=1"]);
    assert_eq!(process.working_dir, "/work");
    assert_eq!(process.user, "app:app");
    assert_eq!(process.stop_signal.as_deref(), Some("SIGTERM"));

    assert!(parse_image_process_config(b"").is_err());
    assert!(parse_image_process_config(b"{}").is_err());
    let duplicate = br#"{
        "architecture":"amd64",
        "architecture":"amd64",
        "os":"linux",
        "rootfs":{"type":"layers","diff_ids":[]},
        "config":{"Cmd":["/bin/true"]}
    }"#;
    assert!(parse_image_process_config(duplicate).is_err());

    let zero_defaults = serde_json::to_vec(&json!({
        "architecture": "amd64",
        "os": "linux",
        "rootfs": {"type": "layers", "diff_ids": []}
    }))?;
    let process = parse_image_process_config(&zero_defaults)?;
    assert!(process.argv.is_empty());
    assert!(process.env.is_empty());
    assert_eq!(process.working_dir, "/");
    assert_eq!(process.user, "0");
    Ok(())
}

#[test]
fn verifies_manifest_selected_through_nested_index() -> TestResult {
    let layout = new_layout()?;
    let image = build_image(layout.path(), &ImageOptions::default())?;
    let nested = nested_index_descriptor(layout.path(), vec![image.descriptor])?;
    write_index(layout.path(), vec![nested])?;
    let verified = verify_layout(layout.path())?;
    assert_eq!(verified.process.argv, ["/bin/demo", "--flag"]);
    Ok(())
}

#[test]
fn accepts_docker_v2_manifest_config_and_nonforeign_layer() -> TestResult {
    let layout = new_layout()?;
    let options = ImageOptions {
        manifest_media_type: DOCKER_MANIFEST,
        config_media_type: DOCKER_CONFIG,
        layer_media_type: DOCKER_LAYER_GZIP,
        ..ImageOptions::default()
    };
    let image = build_image(layout.path(), &options)?;
    write_index(layout.path(), vec![image.descriptor])?;
    let verified = verify_layout(layout.path())?;
    assert_eq!(verified.manifest_media_type, DOCKER_MANIFEST);
    assert_eq!(verified.config_media_type, DOCKER_CONFIG);
    assert_eq!(verified.layers[0].compression, LayerCompression::Gzip);
    Ok(())
}

#[test]
fn accepts_all_oci_layer_compressions() -> TestResult {
    for (media_type, expected) in [
        (OCI_LAYER, LayerCompression::None),
        (OCI_LAYER_GZIP, LayerCompression::Gzip),
        (OCI_LAYER_ZSTD, LayerCompression::Zstd),
    ] {
        let layout = new_layout()?;
        let image = build_image(
            layout.path(),
            &ImageOptions {
                layer_media_type: media_type,
                ..ImageOptions::default()
            },
        )?;
        write_index(layout.path(), vec![image.descriptor])?;
        assert_eq!(
            verify_layout(layout.path())?.layers[0].compression,
            expected
        );
    }
    Ok(())
}

#[test]
fn rejects_uncompressed_diff_id_mismatch_for_every_compression() -> TestResult {
    for media_type in [OCI_LAYER, OCI_LAYER_GZIP, OCI_LAYER_ZSTD] {
        let layout = new_layout()?;
        let image = build_image(
            layout.path(),
            &ImageOptions {
                layer_media_type: media_type,
                diff_id_payload_override: Some(b"different uncompressed content".to_vec()),
                ..ImageOptions::default()
            },
        )?;
        write_index(layout.path(), vec![image.descriptor])?;
        assert!(matches!(
            failure(verify_layout(layout.path()))?,
            Error::DiffIdMismatch { position: 0, .. }
        ));
    }
    Ok(())
}

#[test]
fn rejects_truncated_gzip_and_zstd_streams() -> TestResult {
    for media_type in [OCI_LAYER_GZIP, OCI_LAYER_ZSTD] {
        let mut encoded = encode_layer(media_type, b"content that must survive decompression")?;
        let shortened = encoded
            .len()
            .checked_sub(3)
            .ok_or_else(|| std::io::Error::other("encoded test layer is too short"))?;
        encoded.truncate(shortened);

        let layout = new_layout()?;
        let image = build_image(
            layout.path(),
            &ImageOptions {
                layer_media_type: media_type,
                uncompressed_layer: b"content that must survive decompression".to_vec(),
                encoded_layer_override: Some(encoded),
                ..ImageOptions::default()
            },
        )?;
        write_index(layout.path(), vec![image.descriptor])?;
        assert!(matches!(
            failure(verify_layout(layout.path()))?,
            Error::LayerDecode { position: 0, .. }
        ));
    }
    Ok(())
}

#[test]
fn rejects_descriptor_valid_gzip_checksum_corruption() -> TestResult {
    let uncompressed = b"gzip integrity is separate from descriptor integrity";
    let mut encoded = encode_layer(OCI_LAYER_GZIP, uncompressed)?;
    let checksum_index = encoded
        .len()
        .checked_sub(8)
        .ok_or_else(|| std::io::Error::other("encoded gzip test layer has no checksum"))?;
    let checksum_byte = encoded
        .get_mut(checksum_index)
        .ok_or_else(|| std::io::Error::other("encoded gzip checksum index is invalid"))?;
    *checksum_byte ^= 0xff;

    let layout = new_layout()?;
    let image = build_image(
        layout.path(),
        &ImageOptions {
            layer_media_type: OCI_LAYER_GZIP,
            uncompressed_layer: uncompressed.to_vec(),
            encoded_layer_override: Some(encoded),
            ..ImageOptions::default()
        },
    )?;
    write_index(layout.path(), vec![image.descriptor])?;
    assert!(matches!(
        failure(verify_layout(layout.path()))?,
        Error::LayerDecode { position: 0, .. }
    ));
    Ok(())
}

#[test]
fn enforces_uncompressed_layer_total_and_ratio_limits() -> TestResult {
    let uncompressed = vec![0_u8; 8 * 1024];

    let layer_layout = new_layout()?;
    let image = build_image(
        layer_layout.path(),
        &ImageOptions {
            layer_media_type: OCI_LAYER_GZIP,
            uncompressed_layer: uncompressed.clone(),
            ..ImageOptions::default()
        },
    )?;
    write_index(layer_layout.path(), vec![image.descriptor])?;
    let limits = VerifyLimits {
        max_layer_uncompressed_bytes: 1_024,
        ..VerifyLimits::default()
    };
    assert!(matches!(
        failure(verify_layout_with_limits(layer_layout.path(), &limits))?,
        Error::LayerUncompressedLimit { position: 0, .. }
    ));

    let total_layout = new_layout()?;
    let image = build_image(
        total_layout.path(),
        &ImageOptions {
            layer_media_type: OCI_LAYER_GZIP,
            uncompressed_layer: uncompressed.clone(),
            ..ImageOptions::default()
        },
    )?;
    write_index(total_layout.path(), vec![image.descriptor])?;
    let limits = VerifyLimits {
        max_total_uncompressed_bytes: 1_024,
        ..VerifyLimits::default()
    };
    assert!(matches!(
        failure(verify_layout_with_limits(total_layout.path(), &limits))?,
        Error::TotalUncompressedLimit { position: 0, .. }
    ));

    let ratio_layout = new_layout()?;
    let image = build_image(
        ratio_layout.path(),
        &ImageOptions {
            layer_media_type: OCI_LAYER_ZSTD,
            uncompressed_layer: uncompressed,
            ..ImageOptions::default()
        },
    )?;
    write_index(ratio_layout.path(), vec![image.descriptor])?;
    let limits = VerifyLimits {
        max_decompression_ratio: 1,
        ..VerifyLimits::default()
    };
    assert!(matches!(
        failure(verify_layout_with_limits(ratio_layout.path(), &limits))?,
        Error::DecompressionRatio { position: 0, .. }
    ));
    Ok(())
}

#[test]
fn rejects_corrupted_reachable_blob() -> TestResult {
    let layout = new_layout()?;
    let image = build_image(layout.path(), &ImageOptions::default())?;
    write_index(layout.path(), vec![image.descriptor])?;
    corrupt_blob_in_place(&image.layer_path)?;
    let error = failure(verify_layout(layout.path()))?;
    assert!(matches!(error, Error::DigestMismatch { .. }));
    Ok(())
}

#[test]
fn authenticates_nonselected_platform_graph_too() -> TestResult {
    let layout = new_layout()?;
    let target = build_image(layout.path(), &ImageOptions::default())?;
    let arm = build_image(
        layout.path(),
        &ImageOptions {
            descriptor_platform: Some(arm_platform()),
            config_architecture: "arm64",
            config_variant: Some("v8"),
            ..ImageOptions::default()
        },
    )?;
    write_index(layout.path(), vec![target.descriptor, arm.descriptor])?;
    corrupt_blob_in_place(&arm.layer_path)?;
    let error = failure(verify_layout(layout.path()))?;
    assert!(matches!(error, Error::DigestMismatch { .. }));
    Ok(())
}

fn corrupt_blob_in_place(path: &Path) -> TestResult {
    let mut bytes = std::fs::read(path)?;
    let first = bytes
        .first_mut()
        .ok_or_else(|| std::io::Error::other("test layer is unexpectedly empty"))?;
    *first ^= 0xff;
    std::fs::write(path, bytes)?;
    Ok(())
}

#[test]
fn rejects_ambiguous_linux_amd64_selection() -> TestResult {
    let layout = new_layout()?;
    let first = build_image(layout.path(), &ImageOptions::default())?;
    let second = build_image(layout.path(), &ImageOptions::default())?;
    write_index(layout.path(), vec![first.descriptor, second.descriptor])?;
    let error = failure(verify_layout(layout.path()))?;
    assert!(matches!(error, Error::AmbiguousLinuxAmd64 { count: 2 }));
    Ok(())
}

#[test]
fn rejects_descriptor_and_config_platform_disagreement() -> TestResult {
    let layout = new_layout()?;
    let image = build_image(
        layout.path(),
        &ImageOptions {
            descriptor_platform: Some(arm_platform()),
            ..ImageOptions::default()
        },
    )?;
    write_index(layout.path(), vec![image.descriptor])?;
    let error = failure(verify_layout(layout.path()))?;
    assert!(matches!(error, Error::Platform { .. }));
    Ok(())
}

#[test]
fn rejects_nonbaseline_amd64_variant_and_os_features() -> TestResult {
    for options in [
        ImageOptions {
            descriptor_platform: Some(target_platform(Some("v2"), Vec::new())),
            config_variant: Some("v2"),
            ..ImageOptions::default()
        },
        ImageOptions {
            descriptor_platform: Some(target_platform(None, vec!["win32k"])),
            config_os_features: vec!["win32k"],
            ..ImageOptions::default()
        },
        ImageOptions {
            descriptor_platform: Some(json!({
                "os": "linux",
                "architecture": "amd64",
                "os.version": "10.0"
            })),
            config_os_version: Some("10.0"),
            ..ImageOptions::default()
        },
        ImageOptions {
            descriptor_platform: Some(json!({
                "os": "linux",
                "architecture": "amd64",
                "features": ["future-cpu-contract"]
            })),
            ..ImageOptions::default()
        },
    ] {
        let layout = new_layout()?;
        let image = build_image(layout.path(), &options)?;
        write_index(layout.path(), vec![image.descriptor])?;
        assert!(matches!(
            failure(verify_layout(layout.path()))?,
            Error::Platform { .. }
        ));
    }
    Ok(())
}

#[test]
fn rejects_foreign_and_unknown_media_types() -> TestResult {
    let foreign_layout = new_layout()?;
    let foreign = build_image(
        foreign_layout.path(),
        &ImageOptions {
            layer_media_type: FOREIGN_LAYER,
            ..ImageOptions::default()
        },
    )?;
    write_index(foreign_layout.path(), vec![foreign.descriptor])?;
    assert!(matches!(
        failure(verify_layout(foreign_layout.path()))?,
        Error::UnsupportedMediaType { .. }
    ));

    for media_type in [
        "application/vnd.oci.artifact.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v1+json",
        "application/x-unknown",
    ] {
        let layout = new_layout()?;
        let descriptor = write_blob(layout.path(), media_type, b"{}", None)?;
        write_index(layout.path(), vec![descriptor])?;
        assert!(matches!(
            failure(verify_layout(layout.path()))?,
            Error::UnsupportedMediaType { .. }
        ));
    }

    let config_layout = new_layout()?;
    let image = build_image(
        config_layout.path(),
        &ImageOptions {
            config_media_type: "application/x-unknown-config",
            ..ImageOptions::default()
        },
    )?;
    write_index(config_layout.path(), vec![image.descriptor])?;
    assert!(matches!(
        failure(verify_layout(config_layout.path()))?,
        Error::UnsupportedMediaType { .. }
    ));
    Ok(())
}

#[test]
fn rejects_noncanonical_digest_and_wrong_descriptor_size() -> TestResult {
    let digest_layout = new_layout()?;
    let mut digest_image = build_image(digest_layout.path(), &ImageOptions::default())?;
    digest_image.descriptor["digest"] = Value::String("sha256:ABCDEF".to_owned());
    write_index(digest_layout.path(), vec![digest_image.descriptor])?;
    assert!(matches!(
        failure(verify_layout(digest_layout.path()))?,
        Error::InvalidDigest { .. }
    ));

    let size_layout = new_layout()?;
    let mut size_image = build_image(size_layout.path(), &ImageOptions::default())?;
    let old_size = size_image.descriptor["size"]
        .as_u64()
        .ok_or_else(|| std::io::Error::other("test descriptor size is not u64"))?;
    size_image.descriptor["size"] = Value::from(old_size + 1);
    write_index(size_layout.path(), vec![size_image.descriptor])?;
    assert!(matches!(
        failure(verify_layout(size_layout.path()))?,
        Error::SizeMismatch { .. }
    ));
    Ok(())
}

#[test]
fn rejects_layer_and_diff_id_count_mismatch() -> TestResult {
    let layout = new_layout()?;
    let image = build_image(
        layout.path(),
        &ImageOptions {
            diff_id_count: 0,
            ..ImageOptions::default()
        },
    )?;
    write_index(layout.path(), vec![image.descriptor])?;
    assert!(matches!(
        failure(verify_layout(layout.path()))?,
        Error::RootfsCountMismatch {
            layers: 1,
            diff_ids: 0
        }
    ));
    Ok(())
}

#[test]
fn enforces_json_and_process_field_bounds() -> TestResult {
    let json_layout = new_layout()?;
    let image = build_image(json_layout.path(), &ImageOptions::default())?;
    write_index(json_layout.path(), vec![image.descriptor])?;
    let limits = VerifyLimits {
        max_index_bytes: 8,
        ..VerifyLimits::default()
    };
    assert!(matches!(
        failure(verify_layout_with_limits(json_layout.path(), &limits))?,
        Error::Limit { .. }
    ));

    let process_layout = new_layout()?;
    let process = build_image(
        process_layout.path(),
        &ImageOptions {
            runtime_config: json!({"Cmd": ["12345678"]}),
            ..ImageOptions::default()
        },
    )?;
    write_index(process_layout.path(), vec![process.descriptor])?;
    let limits = VerifyLimits {
        max_process_string_bytes: 7,
        ..VerifyLimits::default()
    };
    assert!(matches!(
        failure(verify_layout_with_limits(process_layout.path(), &limits))?,
        Error::Limit { .. }
    ));

    let descriptor_layout = new_layout()?;
    let image = build_image(descriptor_layout.path(), &ImageOptions::default())?;
    write_index(descriptor_layout.path(), vec![image.descriptor])?;
    let limits = VerifyLimits {
        max_total_descriptors: 2,
        ..VerifyLimits::default()
    };
    assert!(matches!(
        failure(verify_layout_with_limits(descriptor_layout.path(), &limits))?,
        Error::Limit { .. }
    ));
    Ok(())
}

#[test]
fn requires_exact_oci_layout_version() -> TestResult {
    let layout = new_layout()?;
    std::fs::write(
        layout.path().join("oci-layout"),
        serde_json::to_vec(&json!({"imageLayoutVersion": "1.1.0"}))?,
    )?;
    let image = build_image(layout.path(), &ImageOptions::default())?;
    write_index(layout.path(), vec![image.descriptor])?;
    assert!(matches!(
        failure(verify_layout(layout.path()))?,
        Error::UnsupportedLayoutVersion { .. }
    ));
    Ok(())
}

#[test]
fn accepts_absent_or_v1_amd64_variant_only() -> TestResult {
    for variant in [None, Some("v1")] {
        let layout = new_layout()?;
        let image = build_image(
            layout.path(),
            &ImageOptions {
                descriptor_platform: Some(target_platform(variant, Vec::new())),
                config_variant: variant,
                ..ImageOptions::default()
            },
        )?;
        write_index(layout.path(), vec![image.descriptor])?;
        let _ = verify_layout(layout.path())?;
    }
    Ok(())
}

#[test]
fn preserves_absent_and_explicit_variant_evidence_without_inventing_raw_fields() -> TestResult {
    let layout = new_layout()?;
    let image = build_image(
        layout.path(),
        &ImageOptions {
            descriptor_platform: Some(target_platform(Some("v1"), Vec::new())),
            config_variant: None,
            ..ImageOptions::default()
        },
    )?;
    write_index(layout.path(), vec![image.descriptor])?;
    let verified = verify_layout(layout.path())?;
    assert_eq!(
        verified
            .descriptor_platform
            .as_ref()
            .and_then(|platform| platform.variant.as_deref()),
        Some("v1")
    );
    assert_eq!(verified.config_platform.variant, None);
    assert_eq!(verified.effective_platform.variant.as_deref(), Some("v1"));
    Ok(())
}

/// `WORKDIR /app/` and `/app//bin` are ordinary image-builder output, and they
/// name exactly the directory the strict form names. Accepting them at import
/// and then rejecting them at every launch would make such an image importable
/// but unrunnable, so the verifier hands back the normalized form. `..` cannot
/// be normalized lexically without knowing the symlinks, so it stays refused.
#[test]
fn normalizes_equivalent_working_directory_spellings() -> TestResult {
    for (written, expected) in [
        ("/app/", "/app"),
        ("/app//bin", "/app/bin"),
        ("/app/./bin/", "/app/bin"),
        ("//", "/"),
        ("/.", "/"),
        ("/work", "/work"),
    ] {
        let bytes = standalone_config(json!({
            "Cmd": ["/bin/true"],
            "WorkingDir": written,
        }));
        let process = parse_image_process_config(&bytes)?;
        assert_eq!(
            process.working_dir, expected,
            "WorkingDir {written:?} must normalize to {expected:?}"
        );
    }

    for refused in ["/app/../etc", "app", ""] {
        let bytes = standalone_config(json!({
            "Cmd": ["/bin/true"],
            "WorkingDir": refused,
        }));
        let outcome = parse_image_process_config(&bytes);
        if refused.is_empty() {
            // An absent or empty WorkingDir is the documented default, not an
            // error.
            assert_eq!(outcome?.working_dir, "/");
        } else {
            assert!(outcome.is_err(), "WorkingDir {refused:?} must be refused");
        }
    }
    Ok(())
}

/// A layer that is entirely zeros is ordinary image content -- a preallocated
/// file, a padded blob -- and gzip alone reaches 1030:1 on it. The default
/// ratio limit must not reject what a normal compressor normally produces.
#[test]
fn accepts_a_wholly_compressible_layer_at_its_natural_ratio() -> TestResult {
    let uncompressed = vec![0_u8; 8 * 1024 * 1024];
    for media_type in [OCI_LAYER_GZIP, OCI_LAYER_ZSTD] {
        let layout = new_layout()?;
        let image = build_image(
            layout.path(),
            &ImageOptions {
                layer_media_type: media_type,
                uncompressed_layer: uncompressed.clone(),
                ..ImageOptions::default()
            },
        )?;
        let compressed = std::fs::metadata(&image.layer_path)?.len();
        write_index(layout.path(), vec![image.descriptor])?;
        let ratio = uncompressed.len() as u64 / compressed.max(1);
        assert!(
            ratio > 1_024,
            "{media_type} produced only {ratio}:1, so this proves nothing"
        );
        verify_layout(layout.path())?;
    }
    Ok(())
}
