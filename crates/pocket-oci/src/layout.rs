use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::fs::{File, Metadata};
use std::io::{self, Read};
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path};

use serde::de::{MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Number, Value};
use sha2::{Digest as _, Sha256};

use crate::error::{Error, Result, io_error};

const OCI_LAYOUT_VERSION: &str = "1.0.0";
const OCI_INDEX: &str = "application/vnd.oci.image.index.v1+json";
const DOCKER_INDEX: &str = "application/vnd.docker.distribution.manifest.list.v2+json";
const OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
const DOCKER_MANIFEST: &str = "application/vnd.docker.distribution.manifest.v2+json";
const OCI_CONFIG: &str = "application/vnd.oci.image.config.v1+json";
const DOCKER_CONFIG: &str = "application/vnd.docker.container.image.v1+json";
const OCI_LAYER: &str = "application/vnd.oci.image.layer.v1.tar";
const OCI_LAYER_GZIP: &str = "application/vnd.oci.image.layer.v1.tar+gzip";
const OCI_LAYER_ZSTD: &str = "application/vnd.oci.image.layer.v1.tar+zstd";
const DOCKER_LAYER_GZIP: &str = "application/vnd.docker.image.rootfs.diff.tar.gzip";
const OCI_REF_NAME_ANNOTATION: &str = "org.opencontainers.image.ref.name";
const BUILDER_INPUT_REFERENCE: &str = "root";

/// Versioned selection policy implemented by this verifier. It is intentionally
/// architecture-specific until an independently qualified native track exists.
pub const SELECTOR_POLICY_ID: &str = "native-amd64-v1";

/// Resource ceilings used while parsing and authenticating an image layout.
///
/// Defaults are intentionally generous enough for ordinary images but bounded
/// independently from descriptor-supplied sizes.
#[derive(Clone, Debug)]
pub struct VerifyLimits {
    pub max_layout_bytes: u64,
    pub max_index_bytes: u64,
    pub max_manifest_bytes: u64,
    pub max_config_bytes: u64,
    pub max_layer_bytes: u64,
    pub max_layer_uncompressed_bytes: u64,
    pub max_total_uncompressed_bytes: u64,
    pub max_decompression_ratio: u64,
    /// Maximum Zstandard back-reference window as a base-2 logarithm.
    pub max_zstd_window_log: u32,
    pub max_total_descriptors: usize,
    pub max_descriptors_per_index: usize,
    pub max_layers: usize,
    pub max_index_depth: usize,
    pub max_json_nodes: usize,
    pub max_json_depth: usize,
    pub max_array_entries: usize,
    pub max_object_entries: usize,
    pub max_json_string_bytes: usize,
    pub max_total_json_string_bytes: usize,
    pub max_process_entries: usize,
    pub max_process_string_bytes: usize,
    pub max_labels: usize,
}

impl Default for VerifyLimits {
    fn default() -> Self {
        Self {
            max_layout_bytes: 4 * 1024,
            max_index_bytes: 4 * 1024 * 1024,
            max_manifest_bytes: 4 * 1024 * 1024,
            max_config_bytes: 16 * 1024 * 1024,
            max_layer_bytes: 128 * 1024 * 1024 * 1024,
            max_layer_uncompressed_bytes: 64 * 1024 * 1024 * 1024,
            max_total_uncompressed_bytes: 256 * 1024 * 1024 * 1024,
            // DEFLATE's own ceiling is about 1032:1, so a layer that is
            // entirely zeros -- a preallocated database file, a padded model
            // blob -- measures 1030:1 as plain gzip and 32180:1 as zstd. A
            // 1024:1 limit rejects both. The absolute per-layer and total
            // uncompressed caps above are what actually bound expansion; this
            // ratio only ends a decompression bomb before those are reached.
            max_decompression_ratio: 65_536,
            max_zstd_window_log: 27,
            max_total_descriptors: 4_096,
            max_descriptors_per_index: 1_024,
            max_layers: 2_048,
            max_index_depth: 8,
            max_json_nodes: 1_000_000,
            max_json_depth: 96,
            max_array_entries: 100_000,
            max_object_entries: 100_000,
            max_json_string_bytes: 1024 * 1024,
            max_total_json_string_bytes: 16 * 1024 * 1024,
            max_process_entries: 16_384,
            max_process_string_bytes: 64 * 1024,
            max_labels: 16_384,
        }
    }
}

/// A canonical SHA-256 descriptor digest.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DescriptorDigest([u8; 32]);

impl DescriptorDigest {
    #[must_use]
    pub fn bytes(&self) -> &[u8; 32] {
        &self.0
    }

    #[must_use]
    pub fn hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Display for DescriptorDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "sha256:{}", hex::encode(self.0))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LayerCompression {
    None,
    Gzip,
    Zstd,
}

/// One authenticated layer in application order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Layer {
    pub digest: DescriptorDigest,
    pub diff_id: DescriptorDigest,
    pub size: u64,
    pub uncompressed_size: u64,
    pub media_type: String,
    pub compression: LayerCompression,
}

/// Raw or derived OCI platform evidence retained for cache identity and guest
/// reconciliation. Absence and an explicit baseline variant remain distinct.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImagePlatform {
    pub os: String,
    pub architecture: String,
    pub variant: Option<String>,
    pub os_version: Option<String>,
    pub os_features: Vec<String>,
    pub features: Vec<String>,
}

/// Docker image defaults needed to construct the guest process.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DockerProcessConfig {
    pub entrypoint: Vec<String>,
    pub cmd: Vec<String>,
    /// `Entrypoint` followed by `Cmd`, using Docker's exec-form combination.
    pub argv: Vec<String>,
    pub env: Vec<String>,
    /// `/` when the image's `WorkingDir` is absent or empty.
    pub working_dir: String,
    /// `0` when the image's `User` is absent or empty.
    pub user: String,
    pub labels: BTreeMap<String, String>,
    pub stop_signal: Option<String>,
}

/// The one selected Linux/amd64 image after all reachable blobs are verified.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedImage {
    pub manifest_digest: DescriptorDigest,
    pub manifest_size: u64,
    pub manifest_media_type: String,
    pub config_digest: DescriptorDigest,
    pub config_size: u64,
    pub config_media_type: String,
    /// Exact authenticated configuration blob, suitable for the immutable
    /// `image-config.json` sidecar without reserialization.
    pub config_bytes: Vec<u8>,
    pub descriptor_platform: Option<ImagePlatform>,
    pub config_platform: ImagePlatform,
    pub effective_platform: ImagePlatform,
    pub selector_policy: String,
    pub layers: Vec<Layer>,
    pub process: DockerProcessConfig,
}

pub fn verify_layout(root: impl AsRef<Path>) -> Result<VerifiedImage> {
    verify_layout_with_limits(root, &VerifyLimits::default())
}

/// Parse and validate the authenticated immutable image-configuration bytes
/// retained beside a built generation.
///
/// This applies the same duplicate-key rejection, JSON/resource ceilings,
/// rootfs/config validation, and Docker process-default normalization as OCI
/// ingestion. It deliberately accepts bytes rather than a pathname so the
/// caller can keep generation selection and sidecar access under its lease.
pub fn parse_image_process_config(config_bytes: &[u8]) -> Result<DockerProcessConfig> {
    parse_image_process_config_with_limits(config_bytes, &VerifyLimits::default())
}

/// [`parse_image_process_config`] with caller-supplied resource ceilings.
pub fn parse_image_process_config_with_limits(
    config_bytes: &[u8],
    limits: &VerifyLimits,
) -> Result<DockerProcessConfig> {
    if u64::try_from(config_bytes.len()).unwrap_or(u64::MAX) > limits.max_config_bytes {
        return Err(Error::Limit {
            what: "byte length of immutable image-config.json".to_owned(),
            limit: limits.max_config_bytes,
        });
    }
    let context = "immutable image-config.json";
    let config: ConfigDocument = parse_json(config_bytes, context, limits)?;
    validate_config_core(&config, context, limits)?;
    effective_process(config.config.as_ref(), limits)
}

/// Verify an OCI layout and require the canonical OCI media-type boundary
/// consumed by Pocket's builder. Docker schema-2 input remains accepted by
/// [`verify_layout`] for source inspection, but it must pass through Skopeo
/// before reaching this boundary.
pub fn verify_canonical_layout(root: impl AsRef<Path>) -> Result<VerifiedImage> {
    verify_canonical_layout_with_limits(root, &VerifyLimits::default())
}

/// [`verify_canonical_layout`] with caller-supplied resource ceilings.
pub fn verify_canonical_layout_with_limits(
    root: impl AsRef<Path>,
    limits: &VerifyLimits,
) -> Result<VerifiedImage> {
    let root = root.as_ref();
    let image = verify_layout_with_limits(root, limits)?;
    require_canonical_media_types(&image)?;
    require_canonical_builder_index(root, limits, &image)?;
    Ok(image)
}

fn require_canonical_builder_index(
    root: &Path,
    limits: &VerifyLimits,
    image: &VerifiedImage,
) -> Result<()> {
    let index_path = root.join("index.json");
    let index_bytes = read_plain_file_bounded(&index_path, limits.max_index_bytes, "index.json")?;
    let index: IndexDocument = parse_json(&index_bytes, "index.json", limits)?;
    if index
        .media_type
        .as_deref()
        .is_some_and(|media_type| media_type != OCI_INDEX)
    {
        return Err(Error::InvalidDocument {
            document: "index.json".to_owned(),
            reason: "canonical builder index has a non-OCI mediaType".to_owned(),
        });
    }
    if index.manifests.len() != 1 {
        return Err(Error::InvalidDocument {
            document: "index.json".to_owned(),
            reason: "canonical builder index must contain exactly one direct manifest".to_owned(),
        });
    }
    let descriptor = &index.manifests[0];
    if descriptor.media_type != OCI_MANIFEST
        || descriptor.digest != image.manifest_digest.to_string()
    {
        return Err(Error::InvalidDocument {
            document: "index.json".to_owned(),
            reason: "canonical builder index does not directly name the selected OCI manifest"
                .to_owned(),
        });
    }
    if descriptor
        .annotations
        .get(OCI_REF_NAME_ANNOTATION)
        .map(String::as_str)
        != Some(BUILDER_INPUT_REFERENCE)
    {
        return Err(Error::InvalidDocument {
            document: "index.json".to_owned(),
            reason: format!(
                "canonical builder manifest must carry {OCI_REF_NAME_ANNOTATION}={BUILDER_INPUT_REFERENCE}"
            ),
        });
    }
    Ok(())
}

/// Require that an already-authenticated image uses only the OCI manifest,
/// config, and filesystem-layer media types supported by the builder.
pub fn require_canonical_media_types(image: &VerifiedImage) -> Result<()> {
    if image.manifest_media_type != OCI_MANIFEST {
        return Err(Error::UnsupportedMediaType {
            context: "canonical selected manifest".to_owned(),
            media_type: image.manifest_media_type.clone(),
        });
    }
    if image.config_media_type != OCI_CONFIG {
        return Err(Error::UnsupportedMediaType {
            context: "canonical image configuration".to_owned(),
            media_type: image.config_media_type.clone(),
        });
    }
    for (position, layer) in image.layers.iter().enumerate() {
        if !matches!(
            layer.media_type.as_str(),
            OCI_LAYER | OCI_LAYER_GZIP | OCI_LAYER_ZSTD
        ) {
            return Err(Error::UnsupportedMediaType {
                context: format!("canonical layer {position}"),
                media_type: layer.media_type.clone(),
            });
        }
    }
    Ok(())
}

pub fn verify_layout_with_limits(
    root: impl AsRef<Path>,
    limits: &VerifyLimits,
) -> Result<VerifiedImage> {
    let root = root.as_ref();
    require_plain_directory(root, "OCI layout root")?;
    require_plain_directory(&root.join("blobs"), "OCI blobs directory")?;
    require_plain_directory(
        &root.join("blobs").join("sha256"),
        "OCI sha256 blobs directory",
    )?;

    let layout_path = root.join("oci-layout");
    let layout_bytes =
        read_plain_file_bounded(&layout_path, limits.max_layout_bytes, "oci-layout")?;
    let layout: LayoutDocument = parse_json(&layout_bytes, "oci-layout", limits)?;
    if layout.image_layout_version != OCI_LAYOUT_VERSION {
        return Err(Error::UnsupportedLayoutVersion {
            found: layout.image_layout_version,
        });
    }

    let index_path = root.join("index.json");
    let index_bytes = read_plain_file_bounded(&index_path, limits.max_index_bytes, "index.json")?;
    let index: IndexDocument = parse_json(&index_bytes, "index.json", limits)?;

    let mut verifier = Verifier {
        root,
        limits,
        descriptors_seen: 0,
        total_uncompressed_bytes: 0,
        active_indexes: HashSet::new(),
        candidates: Vec::new(),
    };
    verifier.validate_index(&index, "index.json", None)?;
    for descriptor in &index.manifests {
        verifier.walk_descriptor(descriptor, None, 0)?;
    }

    match verifier.candidates.len() {
        0 => Err(Error::NoLinuxAmd64Image),
        1 => verifier.candidates.pop().ok_or(Error::NoLinuxAmd64Image),
        count => Err(Error::AmbiguousLinuxAmd64 { count }),
    }
}

struct Verifier<'a> {
    root: &'a Path,
    limits: &'a VerifyLimits,
    descriptors_seen: usize,
    total_uncompressed_bytes: u64,
    active_indexes: HashSet<DescriptorDigest>,
    candidates: Vec<VerifiedImage>,
}

impl Verifier<'_> {
    fn walk_descriptor(
        &mut self,
        descriptor: &Descriptor,
        inherited_platform: Option<&Platform>,
        index_depth: usize,
    ) -> Result<()> {
        self.consume_descriptor(descriptor, "image index")?;
        let platform = merge_platforms(
            inherited_platform,
            descriptor.platform.as_ref(),
            "nested index descriptors",
            self.limits,
        )?;

        match descriptor.media_type.as_str() {
            OCI_MANIFEST | DOCKER_MANIFEST => {
                let image = self.verify_manifest(descriptor, platform.as_ref())?;
                if let Some(image) = image {
                    self.candidates.push(image);
                }
                Ok(())
            }
            OCI_INDEX | DOCKER_INDEX => {
                if index_depth >= self.limits.max_index_depth {
                    return Err(Error::Limit {
                        what: "nested image-index depth".to_owned(),
                        limit: usize_to_u64(self.limits.max_index_depth),
                    });
                }
                let digest = parse_digest(&descriptor.digest, "nested index descriptor")?;
                if !self.active_indexes.insert(digest) {
                    return Err(Error::InvalidDocument {
                        document: descriptor.digest.clone(),
                        reason: "image-index descriptor cycle".to_owned(),
                    });
                }
                let bytes = self.authenticate_json_blob(
                    descriptor,
                    self.limits.max_index_bytes,
                    "nested image index",
                )?;
                let context = descriptor.digest.clone();
                let index: IndexDocument = parse_json(&bytes, &context, self.limits)?;
                self.validate_index(&index, &context, Some(&descriptor.media_type))?;
                for child in &index.manifests {
                    self.walk_descriptor(child, platform.as_ref(), index_depth + 1)?;
                }
                self.active_indexes.remove(&digest);
                Ok(())
            }
            media_type => Err(Error::UnsupportedMediaType {
                context: "image index descriptor".to_owned(),
                media_type: media_type.to_owned(),
            }),
        }
    }

    fn verify_manifest(
        &mut self,
        descriptor: &Descriptor,
        descriptor_platform: Option<&Platform>,
    ) -> Result<Option<VerifiedImage>> {
        let bytes = self.authenticate_json_blob(
            descriptor,
            self.limits.max_manifest_bytes,
            "image manifest",
        )?;
        let context = descriptor.digest.clone();
        let manifest: ManifestDocument = parse_json(&bytes, &context, self.limits)?;
        self.validate_manifest(&manifest, descriptor, &context)?;

        self.consume_descriptor(&manifest.config, "manifest config")?;
        if manifest.config.platform.is_some() {
            return Err(Error::InvalidDocument {
                document: context.clone(),
                reason: "config descriptor unexpectedly has a platform".to_owned(),
            });
        }
        if !matches!(
            manifest.config.media_type.as_str(),
            OCI_CONFIG | DOCKER_CONFIG
        ) {
            return Err(Error::UnsupportedMediaType {
                context: "manifest config descriptor".to_owned(),
                media_type: manifest.config.media_type.clone(),
            });
        }
        let config_bytes = self.authenticate_json_blob(
            &manifest.config,
            self.limits.max_config_bytes,
            "image config",
        )?;
        let config_context = manifest.config.digest.clone();
        let config: ConfigDocument = parse_json(&config_bytes, &config_context, self.limits)?;
        validate_config_core(&config, &config_context, self.limits)?;

        if config.rootfs.diff_ids.len() != manifest.layers.len() {
            return Err(Error::RootfsCountMismatch {
                layers: manifest.layers.len(),
                diff_ids: config.rootfs.diff_ids.len(),
            });
        }

        let mut layers = Vec::with_capacity(manifest.layers.len());
        for (position, (layer, diff_id_text)) in manifest
            .layers
            .iter()
            .zip(config.rootfs.diff_ids.iter())
            .enumerate()
        {
            self.consume_descriptor(layer, &format!("manifest layer {position}"))?;
            if layer.platform.is_some() {
                return Err(Error::InvalidDocument {
                    document: context.clone(),
                    reason: format!("layer descriptor {position} unexpectedly has a platform"),
                });
            }
            let compression = layer_compression(&layer.media_type, position)?;
            let digest = self.authenticate_layer_blob(layer, position)?;
            let diff_id = parse_digest(diff_id_text, &format!("rootfs diff_id {position}"))?;
            let uncompressed_size =
                self.verify_layer_diff_id(layer, compression, diff_id, position)?;
            layers.push(Layer {
                digest,
                diff_id,
                size: layer.size,
                uncompressed_size,
                media_type: layer.media_type.clone(),
                compression,
            });
        }

        let config_platform = Platform {
            architecture: config.architecture.clone(),
            os: config.os.clone(),
            variant: config.variant.clone(),
            os_version: config.os_version.clone(),
            os_features: config.os_features.clone(),
            features: Vec::new(),
        };
        validate_platform_shape(&config_platform, &config_context, self.limits)?;
        if let Some(platform) = descriptor_platform {
            require_platform_agreement(platform, &config_platform, &context)?;
        }

        let is_target = config_platform.os == "linux" && config_platform.architecture == "amd64";
        if !is_target {
            return Ok(None);
        }
        validate_target_platform(&config_platform, &config_context)?;
        if let Some(platform) = descriptor_platform {
            validate_target_platform(platform, &context)?;
        }

        let effective_platform = effective_platform(descriptor_platform, &config_platform);

        let process = effective_process(config.config.as_ref(), self.limits)?;
        Ok(Some(VerifiedImage {
            manifest_digest: parse_digest(&descriptor.digest, "manifest descriptor")?,
            manifest_size: descriptor.size,
            manifest_media_type: descriptor.media_type.clone(),
            config_digest: parse_digest(&manifest.config.digest, "config descriptor")?,
            config_size: manifest.config.size,
            config_media_type: manifest.config.media_type,
            config_bytes,
            descriptor_platform: descriptor_platform.map(ImagePlatform::from),
            config_platform: ImagePlatform::from(&config_platform),
            effective_platform: ImagePlatform::from(&effective_platform),
            selector_policy: SELECTOR_POLICY_ID.to_owned(),
            layers,
            process,
        }))
    }

    fn validate_index(
        &self,
        index: &IndexDocument,
        context: &str,
        descriptor_media_type: Option<&String>,
    ) -> Result<()> {
        if index.schema_version != 2 {
            return Err(Error::InvalidDocument {
                document: context.to_owned(),
                reason: format!("schemaVersion is {}, not 2", index.schema_version),
            });
        }
        if let Some(media_type) = index.media_type.as_deref() {
            if !matches!(media_type, OCI_INDEX | DOCKER_INDEX) {
                return Err(Error::UnsupportedMediaType {
                    context: context.to_owned(),
                    media_type: media_type.to_owned(),
                });
            }
            if let Some(descriptor_type) = descriptor_media_type
                && media_type != descriptor_type
            {
                return Err(Error::InvalidDocument {
                    document: context.to_owned(),
                    reason: format!(
                        "document mediaType {media_type:?} disagrees with descriptor {descriptor_type:?}"
                    ),
                });
            }
        }
        if index.manifests.is_empty() {
            return Err(Error::InvalidDocument {
                document: context.to_owned(),
                reason: "manifests array is empty".to_owned(),
            });
        }
        if index.manifests.len() > self.limits.max_descriptors_per_index {
            return Err(Error::Limit {
                what: format!("descriptor count in {context}"),
                limit: usize_to_u64(self.limits.max_descriptors_per_index),
            });
        }
        validate_annotations(&index.annotations, context, self.limits)
    }

    fn validate_manifest(
        &self,
        manifest: &ManifestDocument,
        descriptor: &Descriptor,
        context: &str,
    ) -> Result<()> {
        if manifest.schema_version != 2 {
            return Err(Error::InvalidDocument {
                document: context.to_owned(),
                reason: format!("schemaVersion is {}, not 2", manifest.schema_version),
            });
        }
        if let Some(media_type) = manifest.media_type.as_deref()
            && media_type != descriptor.media_type
        {
            return Err(Error::InvalidDocument {
                document: context.to_owned(),
                reason: format!(
                    "document mediaType {media_type:?} disagrees with descriptor {:?}",
                    descriptor.media_type
                ),
            });
        }
        if manifest.artifact_type.is_some() || manifest.subject.is_some() {
            return Err(Error::InvalidDocument {
                document: context.to_owned(),
                reason: "artifact manifests and subject-linked manifests are not executable images"
                    .to_owned(),
            });
        }
        if manifest.layers.len() > self.limits.max_layers {
            return Err(Error::Limit {
                what: format!("layer count in {context}"),
                limit: usize_to_u64(self.limits.max_layers),
            });
        }
        validate_annotations(&manifest.annotations, context, self.limits)
    }

    fn validate_descriptor(&self, descriptor: &Descriptor, context: &str) -> Result<()> {
        let digest = parse_digest(&descriptor.digest, context)?;
        if descriptor.media_type.is_empty() {
            return Err(Error::InvalidDocument {
                document: context.to_owned(),
                reason: "descriptor mediaType is empty".to_owned(),
            });
        }
        if descriptor.artifact_type.is_some() {
            return Err(Error::InvalidDocument {
                document: context.to_owned(),
                reason: "artifact descriptor is not an executable image".to_owned(),
            });
        }
        if descriptor
            .urls
            .as_ref()
            .is_some_and(|urls| !urls.is_empty())
        {
            return Err(Error::InvalidDocument {
                document: context.to_owned(),
                reason: "external descriptor URLs are forbidden".to_owned(),
            });
        }
        if let Some(data) = descriptor.data.as_deref() {
            validate_embedded_data(data, descriptor, &digest, context)?;
        }
        validate_annotations(&descriptor.annotations, context, self.limits)?;
        if let Some(platform) = descriptor.platform.as_ref() {
            validate_platform_shape(platform, context, self.limits)?;
        }
        Ok(())
    }

    fn consume_descriptor(&mut self, descriptor: &Descriptor, context: &str) -> Result<()> {
        self.descriptors_seen =
            self.descriptors_seen
                .checked_add(1)
                .ok_or_else(|| Error::Limit {
                    what: "reachable descriptor count".to_owned(),
                    limit: usize_to_u64(self.limits.max_total_descriptors),
                })?;
        if self.descriptors_seen > self.limits.max_total_descriptors {
            return Err(Error::Limit {
                what: "reachable descriptor count".to_owned(),
                limit: usize_to_u64(self.limits.max_total_descriptors),
            });
        }
        self.validate_descriptor(descriptor, context)
    }

    fn authenticate_json_blob(
        &self,
        descriptor: &Descriptor,
        maximum: u64,
        context: &str,
    ) -> Result<Vec<u8>> {
        self.authenticate_blob(descriptor, maximum, true, context)
    }

    fn authenticate_layer_blob(
        &self,
        descriptor: &Descriptor,
        position: usize,
    ) -> Result<DescriptorDigest> {
        let context = format!("manifest layer {position}");
        let _ = self.authenticate_blob(descriptor, self.limits.max_layer_bytes, false, &context)?;
        parse_digest(&descriptor.digest, &context)
    }

    fn verify_layer_diff_id(
        &mut self,
        descriptor: &Descriptor,
        compression: LayerCompression,
        expected_diff_id: DescriptorDigest,
        position: usize,
    ) -> Result<u64> {
        let context = format!("manifest layer {position} DiffID replay");
        let compressed_digest = parse_digest(&descriptor.digest, &context)?;
        let path = self
            .root
            .join("blobs")
            .join("sha256")
            .join(compressed_digest.hex());
        let (file, metadata) = open_plain_file(&path, &context)?;
        if metadata.len() != descriptor.size {
            return Err(Error::SizeMismatch {
                digest: descriptor.digest.clone(),
                expected: descriptor.size,
                actual: metadata.len(),
            });
        }

        let replay = CompressedHashingReader::new(file);
        let (replay, unread_compressed, uncompressed_size, actual_diff_id) = match compression {
            LayerCompression::None => {
                let mut replay = replay;
                let (size, digest) =
                    self.hash_uncompressed_stream(&mut replay, descriptor, compression, position)?;
                (replay, 0, size, digest)
            }
            LayerCompression::Gzip => {
                let buffered = std::io::BufReader::new(replay);
                let mut decoder = flate2::bufread::MultiGzDecoder::new(buffered);
                let decoded =
                    self.hash_uncompressed_stream(&mut decoder, descriptor, compression, position);
                let buffered = decoder.into_inner();
                let unread = u64::try_from(buffered.buffer().len())
                    .map_err(|_| Error::LayerUncompressedOverflow { position })?;
                let replay = buffered.into_inner();
                let (size, digest) = decoded?;
                (replay, unread, size, digest)
            }
            LayerCompression::Zstd => {
                let mut decoder = zstd::stream::read::Decoder::new(replay)
                    .map_err(|source| layer_decode_error(position, descriptor, source))?;
                decoder
                    .window_log_max(self.limits.max_zstd_window_log)
                    .map_err(|source| layer_decode_error(position, descriptor, source))?;
                let decoded =
                    self.hash_uncompressed_stream(&mut decoder, descriptor, compression, position);
                let buffered = decoder.finish();
                let unread = u64::try_from(buffered.buffer().len())
                    .map_err(|_| Error::LayerUncompressedOverflow { position })?;
                let replay = buffered.into_inner();
                let (size, digest) = decoded?;
                (replay, unread, size, digest)
            }
        };

        self.finish_layer_replay(
            replay,
            unread_compressed,
            descriptor,
            compressed_digest,
            position,
        )?;
        if actual_diff_id != expected_diff_id.0 {
            return Err(Error::DiffIdMismatch {
                position,
                expected: expected_diff_id.to_string(),
                actual: format!("sha256:{}", hex::encode(actual_diff_id)),
            });
        }
        self.total_uncompressed_bytes = self
            .total_uncompressed_bytes
            .checked_add(uncompressed_size)
            .ok_or(Error::TotalUncompressedOverflow { position })?;
        Ok(uncompressed_size)
    }

    fn hash_uncompressed_stream<R: Read>(
        &self,
        stream: &mut R,
        descriptor: &Descriptor,
        compression: LayerCompression,
        position: usize,
    ) -> Result<(u64, [u8; 32])> {
        let mut hasher = Sha256::new();
        let mut uncompressed_size = 0_u64;
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let read_length = stream
                .read(&mut buffer)
                .map_err(|source| layer_decode_error(position, descriptor, source))?;
            if read_length == 0 {
                break;
            }
            let read = u64::try_from(read_length)
                .map_err(|_| Error::LayerUncompressedOverflow { position })?;
            uncompressed_size = uncompressed_size
                .checked_add(read)
                .ok_or(Error::LayerUncompressedOverflow { position })?;
            if uncompressed_size > self.limits.max_layer_uncompressed_bytes {
                return Err(Error::LayerUncompressedLimit {
                    position,
                    limit: self.limits.max_layer_uncompressed_bytes,
                    actual: uncompressed_size,
                });
            }
            let total = self
                .total_uncompressed_bytes
                .checked_add(uncompressed_size)
                .ok_or(Error::TotalUncompressedOverflow { position })?;
            if total > self.limits.max_total_uncompressed_bytes {
                return Err(Error::TotalUncompressedLimit {
                    position,
                    limit: self.limits.max_total_uncompressed_bytes,
                    actual: total,
                });
            }
            if compression != LayerCompression::None
                && u128::from(uncompressed_size)
                    > u128::from(descriptor.size) * u128::from(self.limits.max_decompression_ratio)
            {
                return Err(Error::DecompressionRatio {
                    position,
                    maximum: self.limits.max_decompression_ratio,
                    compressed: descriptor.size,
                    uncompressed: uncompressed_size,
                });
            }
            hasher.update(&buffer[..read_length]);
        }
        Ok((uncompressed_size, hasher.finalize().into()))
    }

    fn finish_layer_replay(
        &self,
        mut replay: CompressedHashingReader,
        buffered_trailing: u64,
        descriptor: &Descriptor,
        expected_digest: DescriptorDigest,
        position: usize,
    ) -> Result<()> {
        let count_before_drain = replay.count;
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let read = replay
                .read(&mut buffer)
                .map_err(|source| layer_decode_error(position, descriptor, source))?;
            if read == 0 {
                break;
            }
        }
        let trailing = replay
            .count
            .checked_sub(count_before_drain)
            .and_then(|value| value.checked_add(buffered_trailing))
            .ok_or(Error::LayerUncompressedOverflow { position })?;
        let actual_size = replay.count;
        let actual_digest: [u8; 32] = replay.hasher.finalize().into();
        if actual_size != descriptor.size {
            return Err(Error::SizeMismatch {
                digest: descriptor.digest.clone(),
                expected: descriptor.size,
                actual: actual_size,
            });
        }
        if actual_digest != expected_digest.0 {
            return Err(Error::DigestMismatch {
                digest: descriptor.digest.clone(),
                actual: hex::encode(actual_digest),
            });
        }
        if trailing != 0 {
            return Err(layer_decode_error(
                position,
                descriptor,
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("{trailing} trailing compressed bytes were not decoded"),
                ),
            ));
        }
        Ok(())
    }

    fn authenticate_blob(
        &self,
        descriptor: &Descriptor,
        maximum: u64,
        retain: bool,
        context: &str,
    ) -> Result<Vec<u8>> {
        if descriptor.size > maximum {
            return Err(Error::Limit {
                what: format!("descriptor size for {context}"),
                limit: maximum,
            });
        }
        let expected_digest = parse_digest(&descriptor.digest, context)?;
        let path = self
            .root
            .join("blobs")
            .join("sha256")
            .join(expected_digest.hex());
        let (mut file, metadata) = open_plain_file(&path, context)?;
        if metadata.len() != descriptor.size {
            return Err(Error::SizeMismatch {
                digest: descriptor.digest.clone(),
                expected: descriptor.size,
                actual: metadata.len(),
            });
        }

        let initial_capacity = if retain {
            usize::try_from(descriptor.size).map_err(|_| Error::Limit {
                what: format!("in-memory JSON blob for {context}"),
                limit: maximum,
            })?
        } else {
            0
        };
        let mut retained = Vec::with_capacity(initial_capacity);
        let mut hasher = Sha256::new();
        let mut count = 0_u64;
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let read = file
                .read(&mut buffer)
                .map_err(|source| io_error(&path, source))?;
            if read == 0 {
                break;
            }
            count = count
                .checked_add(u64::try_from(read).map_err(|_| Error::Limit {
                    what: format!("blob byte count for {context}"),
                    limit: maximum,
                })?)
                .ok_or_else(|| Error::Limit {
                    what: format!("blob byte count for {context}"),
                    limit: maximum,
                })?;
            if count > maximum {
                return Err(Error::Limit {
                    what: format!("blob byte count for {context}"),
                    limit: maximum,
                });
            }
            hasher.update(&buffer[..read]);
            if retain {
                retained.extend_from_slice(&buffer[..read]);
            }
        }
        if count != descriptor.size {
            return Err(Error::SizeMismatch {
                digest: descriptor.digest.clone(),
                expected: descriptor.size,
                actual: count,
            });
        }
        let actual: [u8; 32] = hasher.finalize().into();
        if actual != expected_digest.0 {
            return Err(Error::DigestMismatch {
                digest: descriptor.digest.clone(),
                actual: hex::encode(actual),
            });
        }
        Ok(retained)
    }
}

struct CompressedHashingReader {
    inner: File,
    count: u64,
    hasher: Sha256,
}

impl CompressedHashingReader {
    fn new(inner: File) -> Self {
        Self {
            inner,
            count: 0,
            hasher: Sha256::new(),
        }
    }
}

impl Read for CompressedHashingReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let read = self.inner.read(buffer)?;
        let read_u64 = u64::try_from(read)
            .map_err(|_| io::Error::other("compressed layer byte count does not fit u64"))?;
        self.count = self
            .count
            .checked_add(read_u64)
            .ok_or_else(|| io::Error::other("compressed layer byte count overflow"))?;
        self.hasher.update(&buffer[..read]);
        Ok(read)
    }
}

fn layer_decode_error(position: usize, descriptor: &Descriptor, source: io::Error) -> Error {
    Error::LayerDecode {
        position,
        media_type: descriptor.media_type.clone(),
        source,
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LayoutDocument {
    image_layout_version: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct IndexDocument {
    schema_version: u32,
    #[serde(default)]
    media_type: Option<String>,
    manifests: Vec<Descriptor>,
    #[serde(default)]
    annotations: BTreeMap<String, String>,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Descriptor {
    media_type: String,
    digest: String,
    size: u64,
    #[serde(default)]
    platform: Option<Platform>,
    #[serde(default)]
    annotations: BTreeMap<String, String>,
    #[serde(default)]
    artifact_type: Option<String>,
    #[serde(default)]
    urls: Option<Vec<String>>,
    #[serde(default)]
    data: Option<String>,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Platform {
    architecture: String,
    os: String,
    #[serde(default)]
    variant: Option<String>,
    #[serde(default, rename = "os.version")]
    os_version: Option<String>,
    #[serde(default, rename = "os.features")]
    os_features: Vec<String>,
    #[serde(default)]
    features: Vec<String>,
}

impl From<&Platform> for ImagePlatform {
    fn from(platform: &Platform) -> Self {
        Self {
            os: platform.os.clone(),
            architecture: platform.architecture.clone(),
            variant: platform.variant.clone(),
            os_version: platform.os_version.clone(),
            os_features: platform.os_features.clone(),
            features: platform.features.clone(),
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ManifestDocument {
    schema_version: u32,
    #[serde(default)]
    media_type: Option<String>,
    config: Descriptor,
    layers: Vec<Descriptor>,
    #[serde(default)]
    annotations: BTreeMap<String, String>,
    #[serde(default)]
    artifact_type: Option<String>,
    #[serde(default)]
    subject: Option<Descriptor>,
}

#[derive(Deserialize)]
struct ConfigDocument {
    architecture: String,
    os: String,
    #[serde(default)]
    variant: Option<String>,
    #[serde(default, rename = "os.version")]
    os_version: Option<String>,
    #[serde(default, rename = "os.features")]
    os_features: Vec<String>,
    rootfs: RootFs,
    #[serde(default)]
    config: Option<RuntimeConfig>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RootFs {
    #[serde(rename = "type")]
    kind: String,
    diff_ids: Vec<String>,
}

#[derive(Deserialize)]
struct RuntimeConfig {
    #[serde(default, rename = "Env")]
    env: Option<Vec<String>>,
    #[serde(default, rename = "Entrypoint")]
    entrypoint: Option<Vec<String>>,
    #[serde(default, rename = "Cmd")]
    cmd: Option<Vec<String>>,
    #[serde(default, rename = "WorkingDir")]
    working_dir: Option<String>,
    #[serde(default, rename = "User")]
    user: Option<String>,
    #[serde(default, rename = "Labels")]
    labels: Option<BTreeMap<String, String>>,
    #[serde(default, rename = "StopSignal")]
    stop_signal: Option<String>,
}

fn validate_config_core(
    config: &ConfigDocument,
    context: &str,
    limits: &VerifyLimits,
) -> Result<()> {
    if config.rootfs.kind != "layers" {
        return Err(Error::InvalidDocument {
            document: context.to_owned(),
            reason: format!("rootfs type is {:?}, not \"layers\"", config.rootfs.kind),
        });
    }
    if config.rootfs.diff_ids.len() > limits.max_layers {
        return Err(Error::Limit {
            what: format!("rootfs diff_id count in {context}"),
            limit: usize_to_u64(limits.max_layers),
        });
    }
    for (position, digest) in config.rootfs.diff_ids.iter().enumerate() {
        let _ = parse_digest(digest, &format!("rootfs diff_id {position}"))?;
    }
    Ok(())
}

fn effective_process(
    config: Option<&RuntimeConfig>,
    limits: &VerifyLimits,
) -> Result<DockerProcessConfig> {
    let entrypoint = config
        .and_then(|value| value.entrypoint.clone())
        .unwrap_or_default();
    let cmd = config
        .and_then(|value| value.cmd.clone())
        .unwrap_or_default();
    let env = config
        .and_then(|value| value.env.clone())
        .unwrap_or_default();
    let labels = config
        .and_then(|value| value.labels.clone())
        .unwrap_or_default();
    let stop_signal = config.and_then(|value| value.stop_signal.clone());
    let working_dir = config
        .and_then(|value| value.working_dir.clone())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "/".to_owned());
    let user = config
        .and_then(|value| value.user.clone())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "0".to_owned());

    for (name, values) in [
        ("Entrypoint", entrypoint.as_slice()),
        ("Cmd", cmd.as_slice()),
        ("Env", env.as_slice()),
    ] {
        if values.len() > limits.max_process_entries {
            return Err(Error::Limit {
                what: format!("Docker config {name} entry count"),
                limit: usize_to_u64(limits.max_process_entries),
            });
        }
        for value in values {
            validate_process_string(value, name, limits)?;
        }
    }
    if labels.len() > limits.max_labels {
        return Err(Error::Limit {
            what: "Docker config label count".to_owned(),
            limit: usize_to_u64(limits.max_labels),
        });
    }
    for (key, value) in &labels {
        validate_process_string(key, "label key", limits)?;
        validate_process_string(value, "label value", limits)?;
        if key.is_empty() {
            return Err(Error::ProcessConfig {
                reason: "label key is empty".to_owned(),
            });
        }
    }
    for value in &env {
        let key =
            value
                .split_once('=')
                .map(|(key, _)| key)
                .ok_or_else(|| Error::ProcessConfig {
                    reason: format!("environment entry {value:?} has no '='"),
                })?;
        if key.is_empty() || key.contains('=') {
            return Err(Error::ProcessConfig {
                reason: format!("environment entry {value:?} has an invalid key"),
            });
        }
    }
    validate_process_string(&working_dir, "WorkingDir", limits)?;
    if !Path::new(&working_dir).is_absolute()
        || Path::new(&working_dir)
            .components()
            .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(Error::ProcessConfig {
            reason: format!("WorkingDir {working_dir:?} is not an absolute normalized path"),
        });
    }
    // `/app/`, `/app//bin` and `/app/./bin` all name the same directory, and
    // image builders emit all three. Everything downstream requires the strict
    // lexical form, so normalize here rather than let such an image import and
    // then fail at every launch. `..` is rejected above: resolving it lexically
    // would be wrong in the presence of symlinks.
    let working_dir = {
        let mut normalized = String::with_capacity(working_dir.len());
        normalized.push('/');
        for component in Path::new(&working_dir).components() {
            if let Component::Normal(segment) = component {
                if normalized.len() > 1 {
                    normalized.push('/');
                }
                normalized.push_str(&segment.to_string_lossy());
            }
        }
        normalized
    };
    validate_process_string(&user, "User", limits)?;
    if let Some(signal) = stop_signal.as_ref() {
        validate_process_string(signal, "StopSignal", limits)?;
    }

    let argv_len = entrypoint
        .len()
        .checked_add(cmd.len())
        .ok_or_else(|| Error::Limit {
            what: "effective argv entry count".to_owned(),
            limit: usize_to_u64(limits.max_process_entries),
        })?;
    if argv_len > limits.max_process_entries {
        return Err(Error::Limit {
            what: "effective argv entry count".to_owned(),
            limit: usize_to_u64(limits.max_process_entries),
        });
    }
    let mut argv = Vec::with_capacity(argv_len);
    argv.extend(entrypoint.iter().cloned());
    argv.extend(cmd.iter().cloned());
    if argv.first().is_some_and(String::is_empty) {
        return Err(Error::ProcessConfig {
            reason: "effective argv[0] is empty".to_owned(),
        });
    }

    Ok(DockerProcessConfig {
        entrypoint,
        cmd,
        argv,
        env,
        working_dir,
        user,
        labels,
        stop_signal,
    })
}

fn validate_process_string(value: &str, field: &str, limits: &VerifyLimits) -> Result<()> {
    if value.len() > limits.max_process_string_bytes {
        return Err(Error::Limit {
            what: format!("Docker config {field} string length"),
            limit: usize_to_u64(limits.max_process_string_bytes),
        });
    }
    if value.contains('\0') {
        return Err(Error::ProcessConfig {
            reason: format!("{field} contains NUL"),
        });
    }
    Ok(())
}

fn layer_compression(media_type: &str, position: usize) -> Result<LayerCompression> {
    match media_type {
        OCI_LAYER => Ok(LayerCompression::None),
        OCI_LAYER_GZIP | DOCKER_LAYER_GZIP => Ok(LayerCompression::Gzip),
        OCI_LAYER_ZSTD => Ok(LayerCompression::Zstd),
        _ => Err(Error::UnsupportedMediaType {
            context: format!("manifest layer {position}"),
            media_type: media_type.to_owned(),
        }),
    }
}

fn validate_target_platform(platform: &Platform, context: &str) -> Result<()> {
    let variant = platform
        .variant
        .as_deref()
        .filter(|value| !value.is_empty());
    if !matches!(variant, None | Some("v1")) {
        return Err(Error::Platform {
            context: context.to_owned(),
            reason: format!("amd64 variant {:?} is not absent or v1", platform.variant),
        });
    }
    if platform
        .os_version
        .as_deref()
        .is_some_and(|value| !value.is_empty())
    {
        return Err(Error::Platform {
            context: context.to_owned(),
            reason: "os.version is not empty".to_owned(),
        });
    }
    if !platform.os_features.is_empty() || !platform.features.is_empty() {
        return Err(Error::Platform {
            context: context.to_owned(),
            reason: "os.features/features is not empty".to_owned(),
        });
    }
    Ok(())
}

fn validate_platform_shape(
    platform: &Platform,
    context: &str,
    limits: &VerifyLimits,
) -> Result<()> {
    if platform.os.is_empty() || platform.architecture.is_empty() {
        return Err(Error::Platform {
            context: context.to_owned(),
            reason: "os and architecture must be non-empty".to_owned(),
        });
    }
    for (name, value) in [
        ("os", platform.os.as_str()),
        ("architecture", platform.architecture.as_str()),
    ] {
        if value.len() > limits.max_process_string_bytes || value.contains('\0') {
            return Err(Error::Platform {
                context: context.to_owned(),
                reason: format!("{name} is invalid or too long"),
            });
        }
    }
    Ok(())
}

fn merge_platforms(
    inherited: Option<&Platform>,
    local: Option<&Platform>,
    context: &str,
    limits: &VerifyLimits,
) -> Result<Option<Platform>> {
    if let Some(platform) = local {
        validate_platform_shape(platform, context, limits)?;
    }
    match (inherited, local) {
        (Some(outer), Some(inner)) => {
            require_platform_agreement(outer, inner, context)?;
            Ok(Some(inner.clone()))
        }
        (Some(platform), None) | (None, Some(platform)) => Ok(Some(platform.clone())),
        (None, None) => Ok(None),
    }
}

fn require_platform_agreement(expected: &Platform, actual: &Platform, context: &str) -> Result<()> {
    let expected_variant = explicit_value(expected.variant.as_deref());
    let actual_variant = explicit_value(actual.variant.as_deref());
    let expected_version = expected
        .os_version
        .as_deref()
        .filter(|value| !value.is_empty());
    let actual_version = actual
        .os_version
        .as_deref()
        .filter(|value| !value.is_empty());
    if expected.os != actual.os
        || expected.architecture != actual.architecture
        || (expected_variant.is_some()
            && actual_variant.is_some()
            && expected_variant != actual_variant)
        || (expected_version.is_some()
            && actual_version.is_some()
            && expected_version != actual_version)
        || expected.os_features != actual.os_features
    {
        return Err(Error::Platform {
            context: context.to_owned(),
            reason: "descriptor platform disagrees with image config".to_owned(),
        });
    }
    Ok(())
}

fn explicit_value(value: Option<&str>) -> Option<&str> {
    value.filter(|value| !value.is_empty())
}

fn effective_platform(descriptor: Option<&Platform>, config: &Platform) -> Platform {
    let descriptor_variant = descriptor.and_then(|value| explicit_value(value.variant.as_deref()));
    let config_variant = explicit_value(config.variant.as_deref());
    Platform {
        architecture: config.architecture.clone(),
        os: config.os.clone(),
        variant: descriptor_variant.or(config_variant).map(str::to_owned),
        os_version: descriptor
            .and_then(|value| explicit_value(value.os_version.as_deref()))
            .or_else(|| explicit_value(config.os_version.as_deref()))
            .map(str::to_owned),
        os_features: if descriptor.is_some_and(|value| !value.os_features.is_empty()) {
            descriptor
                .map(|value| value.os_features.clone())
                .unwrap_or_default()
        } else {
            config.os_features.clone()
        },
        features: descriptor
            .map(|value| value.features.clone())
            .unwrap_or_default(),
    }
}

fn validate_annotations(
    annotations: &BTreeMap<String, String>,
    context: &str,
    limits: &VerifyLimits,
) -> Result<()> {
    if annotations.len() > limits.max_object_entries {
        return Err(Error::Limit {
            what: format!("annotation count in {context}"),
            limit: usize_to_u64(limits.max_object_entries),
        });
    }
    if annotations.keys().any(String::is_empty) {
        return Err(Error::InvalidDocument {
            document: context.to_owned(),
            reason: "annotation key is empty".to_owned(),
        });
    }
    Ok(())
}

fn parse_digest(text: &str, context: &str) -> Result<DescriptorDigest> {
    let Some(encoded) = text.strip_prefix("sha256:") else {
        return Err(Error::InvalidDigest {
            context: context.to_owned(),
            digest: text.to_owned(),
            reason: "only canonical sha256 digests are accepted".to_owned(),
        });
    };
    if encoded.len() != 64
        || !encoded
            .bytes()
            .all(|value| value.is_ascii_digit() || (b'a'..=b'f').contains(&value))
    {
        return Err(Error::InvalidDigest {
            context: context.to_owned(),
            digest: text.to_owned(),
            reason: "payload must be exactly 64 lowercase hexadecimal digits".to_owned(),
        });
    }
    let decoded = hex::decode(encoded).map_err(|source| Error::InvalidDigest {
        context: context.to_owned(),
        digest: text.to_owned(),
        reason: source.to_string(),
    })?;
    let bytes: [u8; 32] = decoded.try_into().map_err(|_| Error::InvalidDigest {
        context: context.to_owned(),
        digest: text.to_owned(),
        reason: "decoded digest is not 32 bytes".to_owned(),
    })?;
    Ok(DescriptorDigest(bytes))
}

fn require_plain_directory(path: &Path, label: &str) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path).map_err(|source| io_error(path, source))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(Error::InvalidDocument {
            document: path.display().to_string(),
            reason: format!("{label} is not a plain directory"),
        });
    }
    Ok(())
}

fn open_plain_file(path: &Path, context: &str) -> Result<(File, Metadata)> {
    let path_metadata = std::fs::symlink_metadata(path).map_err(|source| io_error(path, source))?;
    if path_metadata.file_type().is_symlink() || !path_metadata.is_file() {
        return Err(Error::InvalidDocument {
            document: context.to_owned(),
            reason: format!("{} is not a plain regular file", path.display()),
        });
    }
    let file = File::open(path).map_err(|source| io_error(path, source))?;
    let file_metadata = file.metadata().map_err(|source| io_error(path, source))?;
    if !file_metadata.is_file()
        || file_metadata.dev() != path_metadata.dev()
        || file_metadata.ino() != path_metadata.ino()
    {
        return Err(Error::InvalidDocument {
            document: context.to_owned(),
            reason: format!("{} changed while it was being opened", path.display()),
        });
    }
    Ok((file, file_metadata))
}

fn read_plain_file_bounded(path: &Path, maximum: u64, context: &str) -> Result<Vec<u8>> {
    let (mut file, metadata) = open_plain_file(path, context)?;
    if metadata.len() > maximum {
        return Err(Error::Limit {
            what: format!("byte length of {context}"),
            limit: maximum,
        });
    }
    let capacity = usize::try_from(metadata.len()).map_err(|_| Error::Limit {
        what: format!("in-memory byte length of {context}"),
        limit: maximum,
    })?;
    let mut bytes = Vec::with_capacity(capacity);
    file.by_ref()
        .take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|source| io_error(path, source))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > maximum {
        return Err(Error::Limit {
            what: format!("byte length of {context}"),
            limit: maximum,
        });
    }
    Ok(bytes)
}

fn parse_json<T>(bytes: &[u8], document: &str, limits: &VerifyLimits) -> Result<T>
where
    T: for<'de> Deserialize<'de>,
{
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let unique = UniqueValue::deserialize(&mut deserializer).map_err(|source| Error::Json {
        document: document.to_owned(),
        source,
    })?;
    deserializer.end().map_err(|source| Error::Json {
        document: document.to_owned(),
        source,
    })?;
    validate_json_shape(&unique.0, document, limits)?;
    serde_json::from_value(unique.0).map_err(|source| Error::Json {
        document: document.to_owned(),
        source,
    })
}

fn validate_json_shape(value: &Value, document: &str, limits: &VerifyLimits) -> Result<()> {
    let mut nodes = 0_usize;
    let mut total_string_bytes = 0_usize;
    let mut stack = vec![(value, 0_usize)];
    while let Some((node, depth)) = stack.pop() {
        nodes = nodes.checked_add(1).ok_or_else(|| Error::Limit {
            what: format!("JSON node count in {document}"),
            limit: usize_to_u64(limits.max_json_nodes),
        })?;
        if nodes > limits.max_json_nodes {
            return Err(Error::Limit {
                what: format!("JSON node count in {document}"),
                limit: usize_to_u64(limits.max_json_nodes),
            });
        }
        if depth > limits.max_json_depth {
            return Err(Error::Limit {
                what: format!("JSON nesting depth in {document}"),
                limit: usize_to_u64(limits.max_json_depth),
            });
        }
        match node {
            Value::String(value) => {
                add_json_string(value, document, limits, &mut total_string_bytes)?
            }
            Value::Array(values) => {
                if values.len() > limits.max_array_entries {
                    return Err(Error::Limit {
                        what: format!("JSON array length in {document}"),
                        limit: usize_to_u64(limits.max_array_entries),
                    });
                }
                stack.extend(values.iter().map(|value| (value, depth + 1)));
            }
            Value::Object(values) => {
                if values.len() > limits.max_object_entries {
                    return Err(Error::Limit {
                        what: format!("JSON object size in {document}"),
                        limit: usize_to_u64(limits.max_object_entries),
                    });
                }
                for (key, value) in values {
                    add_json_string(key, document, limits, &mut total_string_bytes)?;
                    stack.push((value, depth + 1));
                }
            }
            Value::Null | Value::Bool(_) | Value::Number(_) => {}
        }
    }
    Ok(())
}

fn add_json_string(
    value: &str,
    document: &str,
    limits: &VerifyLimits,
    total: &mut usize,
) -> Result<()> {
    if value.len() > limits.max_json_string_bytes {
        return Err(Error::Limit {
            what: format!("JSON string length in {document}"),
            limit: usize_to_u64(limits.max_json_string_bytes),
        });
    }
    *total = total.checked_add(value.len()).ok_or_else(|| Error::Limit {
        what: format!("total JSON string bytes in {document}"),
        limit: usize_to_u64(limits.max_total_json_string_bytes),
    })?;
    if *total > limits.max_total_json_string_bytes {
        return Err(Error::Limit {
            what: format!("total JSON string bytes in {document}"),
            limit: usize_to_u64(limits.max_total_json_string_bytes),
        });
    }
    Ok(())
}

/// An OCI descriptor may carry an inline copy of its own blob in `data`. Pocket
/// never reads content from it: the digest-verified blob inside the layout stays
/// the only input. Refusing every image that carries one would exclude
/// publishers who legitimately inline a small config, so the copy is checked
/// against the descriptor it accompanies and only a disagreement fails. The
/// enclosing document is already size-capped, so the decode is bounded.
fn validate_embedded_data(
    data: &str,
    descriptor: &Descriptor,
    digest: &DescriptorDigest,
    context: &str,
) -> Result<()> {
    let decoded = decode_canonical_base64(data).ok_or_else(|| Error::InvalidDocument {
        document: context.to_owned(),
        reason: "embedded descriptor data is not canonically encoded base64".to_owned(),
    })?;
    if usize_to_u64(decoded.len()) != descriptor.size {
        return Err(Error::InvalidDocument {
            document: context.to_owned(),
            reason: format!(
                "embedded descriptor data decodes to {} bytes but the descriptor declares {}",
                decoded.len(),
                descriptor.size
            ),
        });
    }
    let observed: [u8; 32] = Sha256::digest(&decoded).into();
    if &observed != digest.bytes() {
        return Err(Error::InvalidDocument {
            document: context.to_owned(),
            reason: "embedded descriptor data does not match the descriptor digest".to_owned(),
        });
    }
    Ok(())
}

/// Decode standard base64 with mandatory canonical padding. Whitespace, the
/// URL-safe alphabet, misplaced padding, and non-zero trailing bits are all
/// rejected, so an accepted blob has exactly one accepted encoding.
fn decode_canonical_base64(text: &str) -> Option<Vec<u8>> {
    fn symbol(byte: u8) -> Option<u32> {
        match byte {
            b'A'..=b'Z' => Some(u32::from(byte - b'A')),
            b'a'..=b'z' => Some(u32::from(byte - b'a') + 26),
            b'0'..=b'9' => Some(u32::from(byte - b'0') + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }

    let bytes = text.as_bytes();
    if bytes.is_empty() {
        return Some(Vec::new());
    }
    if !bytes.len().is_multiple_of(4) {
        return None;
    }
    let groups = bytes.len() / 4;
    let mut decoded = Vec::with_capacity(groups * 3);
    for (index, group) in bytes.chunks_exact(4).enumerate() {
        let last = index + 1 == groups;
        if !last && group.contains(&b'=') {
            return None;
        }
        let padding = if last {
            match (group[2], group[3]) {
                (b'=', b'=') => 2,
                (b'=', _) => return None,
                (_, b'=') => 1,
                _ => 0,
            }
        } else {
            0
        };
        let mut accumulator = 0_u32;
        for (position, byte) in group.iter().enumerate() {
            let value = if position >= 4 - padding {
                0
            } else {
                symbol(*byte)?
            };
            accumulator = (accumulator << 6) | value;
        }
        if padding > 0 && accumulator & ((1_u32 << (padding * 8)) - 1) != 0 {
            return None;
        }
        let octets = accumulator.to_be_bytes();
        decoded.extend_from_slice(&octets[1..4 - padding]);
    }
    Some(decoded)
}

fn usize_to_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

/// A serde JSON value visitor that refuses duplicate object keys.
struct UniqueValue(Value);

impl<'de> Deserialize<'de> for UniqueValue {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(UniqueValueVisitor)
    }
}

struct UniqueValueVisitor;

impl<'de> Visitor<'de> for UniqueValueVisitor {
    type Value = UniqueValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> std::result::Result<Self::Value, E> {
        Ok(UniqueValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> std::result::Result<Self::Value, E> {
        Ok(UniqueValue(Value::Number(Number::from(value))))
    }

    fn visit_u64<E>(self, value: u64) -> std::result::Result<Self::Value, E> {
        Ok(UniqueValue(Value::Number(Number::from(value))))
    }

    fn visit_f64<E>(self, value: f64) -> std::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Number::from_f64(value)
            .map(Value::Number)
            .map(UniqueValue)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_string(value.to_owned())
    }

    fn visit_string<E>(self, value: String) -> std::result::Result<Self::Value, E> {
        Ok(UniqueValue(Value::String(value)))
    }

    fn visit_none<E>(self) -> std::result::Result<Self::Value, E> {
        Ok(UniqueValue(Value::Null))
    }

    fn visit_unit<E>(self) -> std::result::Result<Self::Value, E> {
        Ok(UniqueValue(Value::Null))
    }

    fn visit_some<D>(self, deserializer: D) -> std::result::Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        UniqueValue::deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<UniqueValue>()? {
            values.push(value.0);
        }
        Ok(UniqueValue(Value::Array(values)))
    }

    fn visit_map<A>(self, mut object: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = Map::new();
        while let Some((key, value)) = object.next_entry::<String, UniqueValue>()? {
            if values.insert(key.clone(), value.0).is_some() {
                return Err(serde::de::Error::custom(format!(
                    "duplicate JSON object key {key:?}"
                )));
            }
        }
        Ok(UniqueValue(Value::Object(values)))
    }
}
