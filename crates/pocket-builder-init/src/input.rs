use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
};

use flate2::read::MultiGzDecoder;
use pocket_protocol::{BuilderStart, OciDescriptor, Platform};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};

use crate::BuilderError;

const OCI_LAYOUT: &str = "application/vnd.oci.image.index.v1+json";
const OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
const OCI_CONFIG: &str = "application/vnd.oci.image.config.v1+json";
const OCI_LAYER: &str = "application/vnd.oci.image.layer.v1.tar";
const OCI_LAYER_GZIP: &str = "application/vnd.oci.image.layer.v1.tar+gzip";
const OCI_LAYER_ZSTD: &str = "application/vnd.oci.image.layer.v1.tar+zstd";
const REF_NAME: &str = "org.opencontainers.image.ref.name";
const MAX_LAYOUT_BYTES: usize = 4096;
const MAX_INDEX_BYTES: usize = 4 * 1024 * 1024;

/// Re-authenticate the exact canonical single-image OCI layout supplied on
/// the read-only payload disk and reconcile it with the host's `BUILD_START`.
/// This deliberately accepts only canonical OCI media types at the umoci
/// boundary, even when ingress originally used Docker media types.
pub fn verify_input_layout(root: &Path, start: &BuilderStart) -> Result<(), BuilderError> {
    if start.selected_manifest.media_type != OCI_MANIFEST
        || start.config.media_type != OCI_CONFIG
        || start.layers.iter().any(|layer| {
            !matches!(
                layer.descriptor.media_type.as_str(),
                OCI_LAYER | OCI_LAYER_GZIP | OCI_LAYER_ZSTD
            )
        })
    {
        return Err(BuilderError::input(
            "verify-input",
            "BUILD_START does not describe a canonical OCI image boundary",
        ));
    }
    if start.layers.iter().any(|layer| {
        layer.descriptor.media_type == OCI_LAYER && layer.descriptor.size != layer.uncompressed_size
    }) {
        return Err(BuilderError::input(
            "verify-input",
            "an uncompressed OCI layer has different compressed and uncompressed sizes",
        ));
    }
    require_directory(root, "input root")?;
    require_directory(&root.join("blobs"), "blobs directory")?;
    require_directory(&root.join("blobs/sha256"), "sha256 blobs directory")?;

    let layout: Layout = parse_json(
        &read_regular_bounded(&root.join("oci-layout"), MAX_LAYOUT_BYTES)?,
        "oci-layout",
    )?;
    if layout.image_layout_version != "1.0.0" {
        return Err(BuilderError::input(
            "verify-input",
            "oci-layout version is not 1.0.0",
        ));
    }

    let index: Index = parse_json(
        &read_regular_bounded(&root.join("index.json"), MAX_INDEX_BYTES)?,
        "index.json",
    )?;
    if index.schema_version != 2
        || index
            .media_type
            .as_deref()
            .is_some_and(|value| value != OCI_LAYOUT)
        || index.manifests.len() != 1
    {
        return Err(BuilderError::input(
            "verify-input",
            "index must be a canonical schema-2 OCI index with one manifest",
        ));
    }
    let selected = &index.manifests[0];
    compare_descriptor(selected, &start.selected_manifest, "selected manifest")?;
    if selected
        .annotations
        .as_ref()
        .and_then(|annotations| annotations.get(REF_NAME))
        .map(String::as_str)
        != Some(start.input_reference.as_str())
    {
        return Err(BuilderError::input(
            "verify-input",
            "selected descriptor does not carry the requested OCI ref-name",
        ));
    }
    compare_platform(
        selected.platform.as_ref(),
        start.descriptor_platform.as_ref(),
        "descriptor platform",
    )?;

    let manifest_bytes = authenticate_json_blob(root, &start.selected_manifest)?;
    let manifest: Manifest = parse_json(&manifest_bytes, "selected manifest")?;
    if manifest.schema_version != 2
        || manifest.media_type.as_deref() != Some(OCI_MANIFEST)
        || manifest.artifact_type.is_some()
        || manifest.subject.is_some()
    {
        return Err(BuilderError::input(
            "verify-input",
            "selected document is not a canonical OCI image manifest",
        ));
    }
    compare_descriptor(&manifest.config, &start.config, "config")?;
    if manifest.layers.len() != start.layers.len() {
        return Err(BuilderError::input(
            "verify-input",
            "manifest layer count differs from BUILD_START",
        ));
    }
    for (actual, expected) in manifest.layers.iter().zip(&start.layers) {
        compare_descriptor(actual, &expected.descriptor, "layer")?;
    }

    let config_bytes = authenticate_json_blob(root, &start.config)?;
    let config: ImageConfig = parse_json(&config_bytes, "image config")?;
    let config_platform = Platform {
        os: config.os,
        architecture: config.architecture,
        variant: config.variant,
    };
    if config_platform != start.config_platform {
        return Err(BuilderError::input(
            "verify-input",
            "config platform differs from BUILD_START",
        ));
    }
    if config.os_version.is_some() || config.os_features.is_some_and(|values| !values.is_empty()) {
        return Err(BuilderError::input(
            "verify-input",
            "MVP image config cannot carry os.version or os.features",
        ));
    }
    if config.rootfs.kind != "layers" || config.rootfs.diff_ids.len() != start.layers.len() {
        return Err(BuilderError::input(
            "verify-input",
            "config rootfs is not layers or has the wrong DiffID count",
        ));
    }
    for (actual, expected) in config.rootfs.diff_ids.iter().zip(&start.layers) {
        if actual != &expected.diff_id {
            return Err(BuilderError::input(
                "verify-input",
                "config DiffID differs from BUILD_START",
            ));
        }
    }

    for layer in &start.layers {
        authenticate_layer(root, layer)?;
    }
    Ok(())
}

fn authenticate_layer(
    root: &Path,
    layer: &pocket_protocol::BuilderLayerDescriptor,
) -> Result<(), BuilderError> {
    let path = blob_path(root, &layer.descriptor.digest)?;
    authenticate_regular_file(&path, &layer.descriptor)?;
    let file = File::open(&path).map_err(|error| BuilderError::io("verify-input", error))?;
    let reader: Box<dyn Read> = match layer.descriptor.media_type.as_str() {
        OCI_LAYER => Box::new(file),
        OCI_LAYER_GZIP => Box::new(MultiGzDecoder::new(file)),
        OCI_LAYER_ZSTD => {
            let mut decoder = zstd::stream::read::Decoder::new(file)
                .map_err(|error| BuilderError::input("verify-input", error.to_string()))?;
            decoder
                .window_log_max(27)
                .map_err(|error| BuilderError::input("verify-input", error.to_string()))?;
            Box::new(decoder)
        }
        _ => {
            return Err(BuilderError::input(
                "verify-input",
                "builder boundary contains a non-canonical or unsupported layer media type",
            ));
        }
    };
    hash_decompressed(reader, layer.uncompressed_size, &layer.diff_id)
}

fn hash_decompressed(
    mut reader: Box<dyn Read>,
    expected_size: u64,
    expected_digest: &str,
) -> Result<(), BuilderError> {
    let mut hasher = Sha256::new();
    let mut count = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|error| BuilderError::input("verify-input", error.to_string()))?;
        if read == 0 {
            break;
        }
        count = count.checked_add(read as u64).ok_or_else(|| {
            BuilderError::input("verify-input", "uncompressed layer size overflow")
        })?;
        if count > expected_size {
            return Err(BuilderError::input(
                "verify-input",
                "layer expands beyond authenticated uncompressed size",
            ));
        }
        hasher.update(&buffer[..read]);
    }
    if count != expected_size
        || format!("sha256:{}", hex_lower(&hasher.finalize())) != expected_digest
    {
        return Err(BuilderError::input(
            "verify-input",
            "uncompressed layer size or DiffID mismatch",
        ));
    }
    Ok(())
}

fn authenticate_json_blob(
    root: &Path,
    descriptor: &OciDescriptor,
) -> Result<Vec<u8>, BuilderError> {
    let maximum = usize::try_from(descriptor.size).map_err(|_| {
        BuilderError::input("verify-input", "JSON descriptor size does not fit usize")
    })?;
    let path = blob_path(root, &descriptor.digest)?;
    authenticate_regular_file(&path, descriptor)?;
    read_regular_bounded(&path, maximum)
}

fn authenticate_regular_file(path: &Path, descriptor: &OciDescriptor) -> Result<(), BuilderError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| BuilderError::io("verify-input", error))?;
    if !metadata.is_file() || metadata.len() != descriptor.size {
        return Err(BuilderError::input(
            "verify-input",
            format!(
                "blob {} is not a plain file of authenticated size",
                path.display()
            ),
        ));
    }
    let mut file = File::open(path).map_err(|error| BuilderError::io("verify-input", error))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| BuilderError::io("verify-input", error))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let actual = format!("sha256:{}", hex_lower(&hasher.finalize()));
    if actual != descriptor.digest {
        return Err(BuilderError::input(
            "verify-input",
            format!("blob {} digest mismatch", path.display()),
        ));
    }
    Ok(())
}

fn blob_path(root: &Path, digest: &str) -> Result<PathBuf, BuilderError> {
    let Some(encoded) = digest.strip_prefix("sha256:") else {
        return Err(BuilderError::input("verify-input", "non-sha256 digest"));
    };
    if encoded.len() != 64
        || !encoded
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(BuilderError::input(
            "verify-input",
            "malformed sha256 digest",
        ));
    }
    Ok(root.join("blobs/sha256").join(encoded))
}

fn compare_descriptor(
    actual: &Descriptor,
    expected: &OciDescriptor,
    what: &'static str,
) -> Result<(), BuilderError> {
    if actual.digest != expected.digest
        || actual.size != expected.size
        || actual.media_type != expected.media_type
    {
        return Err(BuilderError::input(
            "verify-input",
            format!("{what} descriptor differs from BUILD_START"),
        ));
    }
    Ok(())
}

fn compare_platform(
    actual: Option<&PlatformDocument>,
    expected: Option<&Platform>,
    what: &'static str,
) -> Result<(), BuilderError> {
    let matches = match (actual, expected) {
        (None, None) => true,
        (Some(actual), Some(expected)) => {
            actual.os == expected.os
                && actual.architecture == expected.architecture
                && actual.variant == expected.variant
                && actual.os_version.is_none()
                && actual.os_features.as_ref().is_none_or(Vec::is_empty)
        }
        _ => false,
    };
    if !matches {
        return Err(BuilderError::input(
            "verify-input",
            format!("{what} differs from BUILD_START"),
        ));
    }
    Ok(())
}

fn require_directory(path: &Path, what: &'static str) -> Result<(), BuilderError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| BuilderError::io("verify-input", error))?;
    if !metadata.is_dir() {
        return Err(BuilderError::input(
            "verify-input",
            format!("{what} is not a plain directory"),
        ));
    }
    Ok(())
}

fn read_regular_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>, BuilderError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| BuilderError::io("verify-input", error))?;
    if !metadata.is_file() || metadata.len() > maximum as u64 {
        return Err(BuilderError::input(
            "verify-input",
            format!("{} is not a bounded plain file", path.display()),
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(path)
        .and_then(|mut file| file.read_to_end(&mut bytes))
        .map_err(|error| BuilderError::io("verify-input", error))?;
    if bytes.len() > maximum {
        return Err(BuilderError::input(
            "verify-input",
            format!("{} grew beyond its bound", path.display()),
        ));
    }
    Ok(bytes)
}

fn parse_json<T: for<'de> Deserialize<'de>>(
    bytes: &[u8],
    what: &'static str,
) -> Result<T, BuilderError> {
    serde_json::from_slice(bytes)
        .map_err(|error| BuilderError::input("verify-input", format!("invalid {what}: {error}")))
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

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Layout {
    image_layout_version: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Index {
    schema_version: u32,
    media_type: Option<String>,
    manifests: Vec<Descriptor>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Manifest {
    schema_version: u32,
    media_type: Option<String>,
    config: Descriptor,
    layers: Vec<Descriptor>,
    artifact_type: Option<String>,
    subject: Option<serde_json::Value>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Descriptor {
    media_type: String,
    digest: String,
    size: u64,
    platform: Option<PlatformDocument>,
    annotations: Option<BTreeMap<String, String>>,
}

#[derive(Deserialize)]
struct PlatformDocument {
    architecture: String,
    os: String,
    variant: Option<String>,
    #[serde(rename = "os.version")]
    os_version: Option<String>,
    #[serde(rename = "os.features")]
    os_features: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct ImageConfig {
    architecture: String,
    os: String,
    variant: Option<String>,
    #[serde(rename = "os.version")]
    os_version: Option<String>,
    #[serde(rename = "os.features")]
    os_features: Option<Vec<String>>,
    rootfs: RootFs,
}

#[derive(Deserialize)]
struct RootFs {
    #[serde(rename = "type")]
    kind: String,
    diff_ids: Vec<String>,
}

#[cfg(test)]
pub(crate) mod tests {
    use std::{fs, io::Write, path::Path};

    use flate2::{Compression, write::GzEncoder};
    use pocket_protocol::{
        BuilderLayerDescriptor, BuilderStart, ManifestLimits, OciDescriptor, Platform, ToolIdentity,
    };
    use sha2::{Digest as _, Sha256};
    use tempfile::TempDir;

    use super::{
        OCI_CONFIG, OCI_LAYER, OCI_LAYER_GZIP, OCI_LAYER_ZSTD, OCI_MANIFEST, hex_lower,
        verify_input_layout,
    };

    fn digest(bytes: &[u8]) -> String {
        format!("sha256:{}", hex_lower(&Sha256::digest(bytes)))
    }

    fn add_blob(root: &Path, bytes: &[u8]) -> OciDescriptor {
        let digest = digest(bytes);
        fs::write(
            root.join("blobs/sha256")
                .join(digest.strip_prefix("sha256:").expect("prefix")),
            bytes,
        )
        .expect("write blob");
        OciDescriptor {
            digest,
            size: bytes.len() as u64,
            media_type: String::new(),
        }
    }

    pub(crate) fn fixture() -> (TempDir, BuilderStart) {
        let layer_bytes = b"plain authenticated layer";
        fixture_with_layer(layer_bytes, layer_bytes, OCI_LAYER)
    }

    fn fixture_with_layer(
        stored_layer: &[u8],
        uncompressed_layer: &[u8],
        media_type: &str,
    ) -> (TempDir, BuilderStart) {
        let root = TempDir::new().expect("tempdir");
        fs::create_dir_all(root.path().join("blobs/sha256")).expect("blob dir");
        fs::write(
            root.path().join("oci-layout"),
            br#"{"imageLayoutVersion":"1.0.0"}"#,
        )
        .expect("layout");

        let mut layer = add_blob(root.path(), stored_layer);
        layer.media_type = media_type.to_owned();
        let diff_id = digest(uncompressed_layer);
        let config_bytes = format!(
            r#"{{"architecture":"amd64","os":"linux","rootfs":{{"type":"layers","diff_ids":["{diff_id}"]}}}}"#
        )
        .into_bytes();
        let mut config = add_blob(root.path(), &config_bytes);
        config.media_type = OCI_CONFIG.to_owned();
        let manifest_bytes = format!(
            r#"{{"schemaVersion":2,"mediaType":"{OCI_MANIFEST}","config":{{"mediaType":"{}","digest":"{}","size":{}}},"layers":[{{"mediaType":"{}","digest":"{}","size":{}}}]}}"#,
            config.media_type,
            config.digest,
            config.size,
            layer.media_type,
            layer.digest,
            layer.size
        )
        .into_bytes();
        let mut manifest = add_blob(root.path(), &manifest_bytes);
        manifest.media_type = OCI_MANIFEST.to_owned();
        fs::write(
            root.path().join("index.json"),
            format!(
                r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{{"mediaType":"{}","digest":"{}","size":{},"annotations":{{"org.opencontainers.image.ref.name":"root"}}}}]}}"#,
                manifest.media_type, manifest.digest, manifest.size
            ),
        )
        .expect("index");
        let platform = Platform {
            os: "linux".to_owned(),
            architecture: "amd64".to_owned(),
            variant: None,
        };
        let start = BuilderStart {
            profile_id: "x86_64-smp-p4k".to_owned(),
            profile_revision: "a".repeat(64),
            derivation_key: "b".repeat(64),
            selected_manifest: manifest,
            config,
            layers: vec![BuilderLayerDescriptor {
                descriptor: layer,
                diff_id,
                uncompressed_size: uncompressed_layer.len() as u64,
            }],
            descriptor_platform: None,
            config_platform: platform.clone(),
            effective_platform: platform,
            selector_policy: "oci-native-v1".to_owned(),
            root_layout: "pocket-root-v1".to_owned(),
            filesystem_contract: "ext4-v1-b4096".to_owned(),
            manifest_schema: "pocket-fs-manifest-v1".to_owned(),
            manifest_limits: ManifestLimits::default(),
            expected_tools: vec![ToolIdentity {
                role: "umoci".to_owned(),
                sha256: "c".repeat(64),
                version: "umoci test".to_owned(),
            }],
            input_reference: "root".to_owned(),
            original_user: String::new(),
            expected_physmem_bytes: 768 * 1024 * 1024,
            source_date_epoch: 1_786_940_622,
        };
        (root, start)
    }

    #[test]
    fn verifies_exact_single_image_layout_and_diff_id() {
        let (root, start) = fixture();
        verify_input_layout(root.path(), &start).expect("valid layout");
    }

    #[test]
    fn verifies_real_gzip_and_zstd_layers() {
        let payload = b"repeated layer bytes repeated layer bytes repeated layer bytes";
        let mut gzip = GzEncoder::new(Vec::new(), Compression::default());
        gzip.write_all(payload).expect("gzip write");
        let gzip = gzip.finish().expect("gzip finish");
        let (root, start) = fixture_with_layer(&gzip, payload, OCI_LAYER_GZIP);
        verify_input_layout(root.path(), &start).expect("gzip layout");

        let zstd = zstd::stream::encode_all(payload.as_slice(), 3).expect("zstd encode");
        let (root, start) = fixture_with_layer(&zstd, payload, OCI_LAYER_ZSTD);
        verify_input_layout(root.path(), &start).expect("zstd layout");
    }

    #[test]
    fn rejects_compressed_or_uncompressed_tampering() {
        let (root, mut start) = fixture();
        start.layers[0].diff_id = format!("sha256:{}", "0".repeat(64));
        assert!(verify_input_layout(root.path(), &start).is_err());

        let (root, start) = fixture();
        let layer_path = root.path().join("blobs/sha256").join(
            start.layers[0]
                .descriptor
                .digest
                .strip_prefix("sha256:")
                .expect("prefix"),
        );
        fs::write(layer_path, b"tampered authenticated layer").expect("tamper");
        assert!(verify_input_layout(root.path(), &start).is_err());
    }

    #[test]
    fn rejects_platform_or_ref_name_drift() {
        let (root, mut start) = fixture();
        start.config_platform.architecture = "arm64".to_owned();
        assert!(verify_input_layout(root.path(), &start).is_err());
    }
}
