use std::{fmt, str::FromStr};

use sha2::{Digest as _, Sha256};

use crate::{
    MetadataKind, StoreError,
    codec::{Reader, put_optional_text, put_text, put_u16},
};

const MAX_ID_TEXT: usize = 128;
const MAX_REFERENCE_TEXT: usize = 1024;
const MAX_PLATFORM_FEATURES: usize = 32;
const MAX_LAYERS: usize = 512;
pub const MAX_GENERATION_SIDECARS: usize = 64;
pub const MAX_SIDECAR_NAME_BYTES: usize = 128;

/// A SHA-256 digest used by immutable store contracts.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Digest([u8; 32]);

impl Digest {
    #[must_use]
    pub fn of_bytes(bytes: &[u8]) -> Self {
        Self(Sha256::digest(bytes).into())
    }

    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "sha256:{}", hex::encode(self.0))
    }
}

impl FromStr for Digest {
    type Err = StoreError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let encoded = value
            .strip_prefix("sha256:")
            .ok_or_else(|| StoreError::InvalidInput {
                field: "digest",
                reason: "expected sha256:<64 lowercase hexadecimal characters>".into(),
            })?;
        if encoded.len() != 64
            || encoded
                .bytes()
                .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
        {
            return Err(StoreError::InvalidInput {
                field: "digest",
                reason: "expected 64 lowercase hexadecimal characters".into(),
            });
        }
        let decoded = hex::decode(encoded).map_err(|error| StoreError::InvalidInput {
            field: "digest",
            reason: error.to_string(),
        })?;
        let bytes: [u8; 32] = decoded.try_into().map_err(|_| StoreError::InvalidInput {
            field: "digest",
            reason: "decoded digest is not 32 bytes".into(),
        })?;
        Ok(Self(bytes))
    }
}

macro_rules! hash_id {
    ($name:ident, $prefix:literal) => {
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name([u8; 32]);

        impl $name {
            pub(crate) const fn from_bytes(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }

            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }

            pub(crate) fn parse_filename(value: &str) -> Option<Self> {
                let encoded = value.strip_prefix($prefix)?;
                if encoded.len() != 64
                    || encoded
                        .bytes()
                        .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
                {
                    return None;
                }
                let decoded = hex::decode(encoded).ok()?;
                Some(Self(decoded.try_into().ok()?))
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(self, formatter)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "{}{}", $prefix, hex::encode(self.0))
            }
        }

        impl FromStr for $name {
            type Err = StoreError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::parse_filename(value).ok_or_else(|| StoreError::InvalidInput {
                    field: stringify!($name),
                    reason: concat!(
                        "expected ",
                        $prefix,
                        " followed by 64 lowercase hexadecimal characters"
                    )
                    .into(),
                })
            }
        }
    };
}

hash_id!(GenerationId, "pkvm-gen-v1-");
hash_id!(DerivationKey, "pkvm-der-v1-");
hash_id!(AliasId, "pkvm-alias-v1-");
hash_id!(RetainedCowId, "pkvm-cow-v1-");

/// One immutable output sidecar covered by the final generation identity.
///
/// The final generation manifest itself is deliberately not a sidecar: its
/// bytes contain the final ID and therefore cannot participate in deriving it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ImmutableSidecar {
    name: String,
    digest: Digest,
    size: u64,
}

impl ImmutableSidecar {
    pub fn new(name: impl Into<String>, digest: Digest, size: u64) -> Result<Self, StoreError> {
        Ok(Self {
            name: validate_sidecar_name(name.into())?,
            digest,
            size,
        })
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub const fn digest(&self) -> Digest {
        self.digest
    }

    #[must_use]
    pub const fn size(&self) -> u64 {
        self.size
    }

    pub(crate) fn encode(&self, output: &mut Vec<u8>) {
        put_text(output, &self.name);
        output.extend_from_slice(self.digest.as_bytes());
        crate::codec::put_u64(output, self.size);
    }

    pub(crate) fn decode(reader: &mut Reader<'_>) -> Result<Self, StoreError> {
        Self::new(
            reader.text(MAX_SIDECAR_NAME_BYTES)?,
            read_digest(reader)?,
            reader.u64()?,
        )
    }
}

impl GenerationId {
    /// Derive the globally addressable ID from completed immutable outputs.
    ///
    /// `sidecars` must be strictly ordered by canonical byte name. This makes
    /// the API usable for future sidecars without admitting multiple encodings
    /// of one output set.
    pub fn derive(
        derivation_key: DerivationKey,
        base_digest: Digest,
        base_size: u64,
        sidecars: &[ImmutableSidecar],
    ) -> Result<Self, StoreError> {
        validate_canonical_sidecars(sidecars)?;
        let mut bytes = b"pocket-final-generation-identity\0v1\0".to_vec();
        bytes.extend_from_slice(derivation_key.as_bytes());
        bytes.extend_from_slice(base_digest.as_bytes());
        crate::codec::put_u64(&mut bytes, base_size);
        put_u16(
            &mut bytes,
            u16::try_from(sidecars.len()).expect("validated sidecar count fits u16"),
        );
        for sidecar in sidecars {
            sidecar.encode(&mut bytes);
        }
        Ok(Self::from_bytes(Sha256::digest(bytes).into()))
    }
}

/// Canonical OCI platform fields selected for a generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Platform {
    os: String,
    architecture: String,
    variant: Option<String>,
    os_version: Option<String>,
    os_features: Vec<String>,
}

impl Platform {
    pub fn new(
        os: impl Into<String>,
        architecture: impl Into<String>,
        variant: Option<String>,
        os_version: Option<String>,
        mut os_features: Vec<String>,
    ) -> Result<Self, StoreError> {
        let os = validate_identifier("platform.os", os.into())?;
        let architecture = validate_identifier("platform.architecture", architecture.into())?;
        let variant = validate_optional_identifier("platform.variant", variant)?;
        let os_version = validate_optional_text("platform.os_version", os_version, MAX_ID_TEXT)?;
        if os_features.len() > MAX_PLATFORM_FEATURES {
            return Err(invalid(
                "platform.os_features",
                format!("at most {MAX_PLATFORM_FEATURES} entries are allowed"),
            ));
        }
        for feature in &mut os_features {
            *feature = validate_identifier("platform.os_features", std::mem::take(feature))?;
        }
        os_features.sort();
        if os_features.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(invalid("platform.os_features", "duplicate entry"));
        }
        Ok(Self {
            os,
            architecture,
            variant,
            os_version,
            os_features,
        })
    }

    #[must_use]
    pub fn os(&self) -> &str {
        &self.os
    }

    #[must_use]
    pub fn architecture(&self) -> &str {
        &self.architecture
    }

    #[must_use]
    pub fn variant(&self) -> Option<&str> {
        self.variant.as_deref()
    }

    #[must_use]
    pub fn os_version(&self) -> Option<&str> {
        self.os_version.as_deref()
    }

    #[must_use]
    pub fn os_features(&self) -> &[String] {
        &self.os_features
    }

    /// The `os/architecture[/variant]` form used on the command line, with any
    /// OS version and features appended so two platforms that differ only
    /// there do not print identically.
    #[must_use]
    pub fn canonical_text(&self) -> String {
        let mut text = format!("{}/{}", self.os, self.architecture);
        if let Some(variant) = &self.variant {
            text.push('/');
            text.push_str(variant);
        }
        if let Some(version) = &self.os_version {
            text.push_str(":osversion=");
            text.push_str(version);
        }
        for feature in &self.os_features {
            text.push_str(":osfeature=");
            text.push_str(feature);
        }
        text
    }

    fn encode(&self, output: &mut Vec<u8>) {
        put_text(output, &self.os);
        put_text(output, &self.architecture);
        put_optional_text(output, self.variant.as_deref());
        put_optional_text(output, self.os_version.as_deref());
        put_u16(
            output,
            u16::try_from(self.os_features.len()).expect("validated feature count"),
        );
        for feature in &self.os_features {
            put_text(output, feature);
        }
    }

    fn decode(reader: &mut Reader<'_>) -> Result<Self, StoreError> {
        let os = reader.text(MAX_ID_TEXT)?.to_owned();
        let architecture = reader.text(MAX_ID_TEXT)?.to_owned();
        let variant = reader.optional_text(MAX_ID_TEXT)?.map(str::to_owned);
        let os_version = reader.optional_text(MAX_ID_TEXT)?.map(str::to_owned);
        let feature_count = usize::from(reader.u16()?);
        if feature_count > MAX_PLATFORM_FEATURES {
            return Err(StoreError::metadata(
                MetadataKind::Generation,
                "<memory>",
                "too many OS features",
            ));
        }
        let mut features = Vec::with_capacity(feature_count);
        for _ in 0..feature_count {
            features.push(reader.text(MAX_ID_TEXT)?.to_owned());
        }
        Self::new(os, architecture, variant, os_version, features)
    }
}

fn validate_platform_contract(
    descriptor: Option<&Platform>,
    config: &Platform,
    effective: &Platform,
) -> Result<(), StoreError> {
    for (field, expected, actual) in [
        ("platform.os", config.os(), effective.os()),
        (
            "platform.architecture",
            config.architecture(),
            effective.architecture(),
        ),
    ] {
        if expected != actual {
            return Err(invalid(field, "config and effective values disagree"));
        }
    }
    if let Some(descriptor) = descriptor
        && (descriptor.os() != config.os() || descriptor.architecture() != config.architecture())
    {
        return Err(invalid(
            "descriptor_platform",
            "descriptor and config OS/architecture disagree",
        ));
    }

    let descriptor_variant = descriptor.and_then(Platform::variant);
    let effective_variant =
        merged_optional_platform_field("platform.variant", descriptor_variant, config.variant())?;
    if effective.variant() != effective_variant {
        return Err(invalid(
            "effective_platform.variant",
            "does not equal the reconciled descriptor/config value",
        ));
    }

    let descriptor_os_version = descriptor.and_then(Platform::os_version);
    let effective_os_version = merged_optional_platform_field(
        "platform.os_version",
        descriptor_os_version,
        config.os_version(),
    )?;
    if effective.os_version() != effective_os_version {
        return Err(invalid(
            "effective_platform.os_version",
            "does not equal the reconciled descriptor/config value",
        ));
    }

    let descriptor_features = descriptor.map_or(&[][..], Platform::os_features);
    let config_features = config.os_features();
    let effective_features = if descriptor_features.is_empty() {
        config_features
    } else if config_features.is_empty() || config_features == descriptor_features {
        descriptor_features
    } else {
        return Err(invalid(
            "platform.os_features",
            "descriptor and config values disagree",
        ));
    };
    if effective.os_features() != effective_features {
        return Err(invalid(
            "effective_platform.os_features",
            "does not equal the reconciled descriptor/config value",
        ));
    }
    Ok(())
}

fn merged_optional_platform_field<'a>(
    field: &'static str,
    descriptor: Option<&'a str>,
    config: Option<&'a str>,
) -> Result<Option<&'a str>, StoreError> {
    match (descriptor, config) {
        (Some(left), Some(right)) if left != right => {
            Err(invalid(field, "descriptor and config values disagree"))
        }
        (Some(value), _) | (_, Some(value)) => Ok(Some(value)),
        (None, None) => Ok(None),
    }
}

/// Complete immutable input contract used to derive a build-serialization key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenerationSpec {
    selected_manifest_digest: Digest,
    config_digest: Digest,
    layer_digests: Vec<Digest>,
    diff_ids: Vec<Digest>,
    descriptor_platform: Option<Platform>,
    config_platform: Platform,
    effective_platform: Platform,
    selector_policy_id: String,
    profile_id: String,
    profile_revision: Digest,
    root_layout_contract: String,
    filesystem_contract: String,
    build_contract_digest: Digest,
}

impl GenerationSpec {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        selected_manifest_digest: Digest,
        config_digest: Digest,
        layer_digests: Vec<Digest>,
        diff_ids: Vec<Digest>,
        descriptor_platform: Option<Platform>,
        config_platform: Platform,
        effective_platform: Platform,
        selector_policy_id: impl Into<String>,
        profile_id: impl Into<String>,
        profile_revision: Digest,
        root_layout_contract: impl Into<String>,
        filesystem_contract: impl Into<String>,
        build_contract_digest: Digest,
    ) -> Result<Self, StoreError> {
        if layer_digests.len() > MAX_LAYERS {
            return Err(invalid(
                "layer_digests",
                format!("at most {MAX_LAYERS} layers are allowed"),
            ));
        }
        if layer_digests.len() != diff_ids.len() {
            return Err(invalid(
                "diff_ids",
                "layer digest and DiffID counts must match",
            ));
        }
        validate_platform_contract(
            descriptor_platform.as_ref(),
            &config_platform,
            &effective_platform,
        )?;
        Ok(Self {
            selected_manifest_digest,
            config_digest,
            layer_digests,
            diff_ids,
            descriptor_platform,
            config_platform,
            effective_platform,
            selector_policy_id: validate_identifier(
                "selector_policy_id",
                selector_policy_id.into(),
            )?,
            profile_id: validate_identifier("profile_id", profile_id.into())?,
            profile_revision,
            root_layout_contract: validate_identifier(
                "root_layout_contract",
                root_layout_contract.into(),
            )?,
            filesystem_contract: validate_identifier(
                "filesystem_contract",
                filesystem_contract.into(),
            )?,
            build_contract_digest,
        })
    }

    #[must_use]
    pub fn derivation_key(&self) -> DerivationKey {
        let mut bytes = b"pocket-generation-derivation\0v1\0".to_vec();
        self.encode(&mut bytes);
        DerivationKey::from_bytes(Sha256::digest(bytes).into())
    }

    #[must_use]
    pub const fn selected_manifest_digest(&self) -> Digest {
        self.selected_manifest_digest
    }

    #[must_use]
    pub const fn config_digest(&self) -> Digest {
        self.config_digest
    }

    #[must_use]
    pub fn layer_digests(&self) -> &[Digest] {
        &self.layer_digests
    }

    #[must_use]
    pub fn diff_ids(&self) -> &[Digest] {
        &self.diff_ids
    }

    #[must_use]
    pub const fn descriptor_platform(&self) -> Option<&Platform> {
        self.descriptor_platform.as_ref()
    }

    #[must_use]
    pub const fn config_platform(&self) -> &Platform {
        &self.config_platform
    }

    #[must_use]
    pub const fn effective_platform(&self) -> &Platform {
        &self.effective_platform
    }

    #[must_use]
    pub fn selector_policy_id(&self) -> &str {
        &self.selector_policy_id
    }

    #[must_use]
    pub fn profile_id(&self) -> &str {
        &self.profile_id
    }

    #[must_use]
    pub const fn profile_revision(&self) -> Digest {
        self.profile_revision
    }

    #[must_use]
    pub fn root_layout_contract(&self) -> &str {
        &self.root_layout_contract
    }

    #[must_use]
    pub fn filesystem_contract(&self) -> &str {
        &self.filesystem_contract
    }

    #[must_use]
    pub const fn build_contract_digest(&self) -> Digest {
        self.build_contract_digest
    }

    pub(crate) fn encode(&self, output: &mut Vec<u8>) {
        output.extend_from_slice(self.selected_manifest_digest.as_bytes());
        output.extend_from_slice(self.config_digest.as_bytes());
        put_u16(
            output,
            u16::try_from(self.layer_digests.len()).expect("validated layer count"),
        );
        for digest in &self.layer_digests {
            output.extend_from_slice(digest.as_bytes());
        }
        put_u16(
            output,
            u16::try_from(self.diff_ids.len()).expect("validated DiffID count"),
        );
        for digest in &self.diff_ids {
            output.extend_from_slice(digest.as_bytes());
        }
        match &self.descriptor_platform {
            Some(platform) => {
                output.push(1);
                platform.encode(output);
            }
            None => output.push(0),
        }
        self.config_platform.encode(output);
        self.effective_platform.encode(output);
        put_text(output, &self.selector_policy_id);
        put_text(output, &self.profile_id);
        output.extend_from_slice(self.profile_revision.as_bytes());
        put_text(output, &self.root_layout_contract);
        put_text(output, &self.filesystem_contract);
        output.extend_from_slice(self.build_contract_digest.as_bytes());
    }

    pub(crate) fn decode(reader: &mut Reader<'_>) -> Result<Self, StoreError> {
        let selected_manifest_digest = read_digest(reader)?;
        let config_digest = read_digest(reader)?;
        let layer_count = usize::from(reader.u16()?);
        if layer_count > MAX_LAYERS {
            return Err(StoreError::metadata(
                MetadataKind::Generation,
                "<memory>",
                "too many layers",
            ));
        }
        let mut layers = Vec::with_capacity(layer_count);
        for _ in 0..layer_count {
            layers.push(read_digest(reader)?);
        }
        let diff_count = usize::from(reader.u16()?);
        if diff_count > MAX_LAYERS {
            return Err(StoreError::metadata(
                MetadataKind::Generation,
                "<memory>",
                "too many DiffIDs",
            ));
        }
        let mut diff_ids = Vec::with_capacity(diff_count);
        for _ in 0..diff_count {
            diff_ids.push(read_digest(reader)?);
        }
        let descriptor_platform = match reader.u8()? {
            0 => None,
            1 => Some(Platform::decode(reader)?),
            value => {
                return Err(StoreError::metadata(
                    MetadataKind::Generation,
                    "<memory>",
                    format!("invalid descriptor-platform option discriminant {value}"),
                ));
            }
        };
        let config_platform = Platform::decode(reader)?;
        let effective_platform = Platform::decode(reader)?;
        Self::new(
            selected_manifest_digest,
            config_digest,
            layers,
            diff_ids,
            descriptor_platform,
            config_platform,
            effective_platform,
            reader.text(MAX_ID_TEXT)?,
            reader.text(MAX_ID_TEXT)?,
            read_digest(reader)?,
            reader.text(MAX_ID_TEXT)?,
            reader.text(MAX_ID_TEXT)?,
            read_digest(reader)?,
        )
    }
}

/// A mutable image reference qualified by exact profile revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AliasKey {
    profile_id: String,
    profile_revision: Digest,
    reference: String,
    requested_platform: Platform,
    selector_policy_id: String,
}

impl AliasKey {
    pub fn new(
        profile_id: impl Into<String>,
        profile_revision: Digest,
        reference: impl Into<String>,
        requested_platform: Platform,
        selector_policy_id: impl Into<String>,
    ) -> Result<Self, StoreError> {
        Ok(Self {
            profile_id: validate_identifier("alias.profile_id", profile_id.into())?,
            profile_revision,
            reference: validate_text("alias.reference", reference.into(), MAX_REFERENCE_TEXT)?,
            requested_platform,
            selector_policy_id: validate_identifier(
                "alias.selector_policy_id",
                selector_policy_id.into(),
            )?,
        })
    }

    #[must_use]
    pub fn id(&self) -> AliasId {
        let mut bytes = b"pocket-alias-identity\0v1\0".to_vec();
        self.encode(&mut bytes);
        AliasId::from_bytes(Sha256::digest(bytes).into())
    }

    #[must_use]
    pub fn profile_id(&self) -> &str {
        &self.profile_id
    }

    #[must_use]
    pub const fn profile_revision(&self) -> Digest {
        self.profile_revision
    }

    #[must_use]
    pub fn reference(&self) -> &str {
        &self.reference
    }

    #[must_use]
    pub const fn requested_platform(&self) -> &Platform {
        &self.requested_platform
    }

    #[must_use]
    pub fn selector_policy_id(&self) -> &str {
        &self.selector_policy_id
    }

    pub(crate) fn encode(&self, output: &mut Vec<u8>) {
        put_text(output, &self.profile_id);
        output.extend_from_slice(self.profile_revision.as_bytes());
        put_text(output, &self.reference);
        self.requested_platform.encode(output);
        put_text(output, &self.selector_policy_id);
    }

    pub(crate) fn decode(reader: &mut Reader<'_>) -> Result<Self, StoreError> {
        Self::new(
            reader.text(MAX_ID_TEXT)?,
            read_digest(reader)?,
            reader.text(MAX_REFERENCE_TEXT)?,
            Platform::decode(reader)?,
            reader.text(MAX_ID_TEXT)?,
        )
    }
}

/// Whether a retained root was cleanly shut down or crash-dirty.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetainedCowState {
    Clean,
    CrashDirty,
}

impl RetainedCowState {
    pub(crate) const fn encode(self) -> u8 {
        match self {
            Self::Clean => 0,
            Self::CrashDirty => 1,
        }
    }

    pub(crate) fn decode(value: u8) -> Result<Self, StoreError> {
        match value {
            0 => Ok(Self::Clean),
            1 => Ok(Self::CrashDirty),
            _ => Err(StoreError::metadata(
                MetadataKind::RetainedCow,
                "<memory>",
                format!("invalid retained-COW state {value}"),
            )),
        }
    }
}

pub(crate) fn read_digest(reader: &mut Reader<'_>) -> Result<Digest, StoreError> {
    let bytes: [u8; 32] = reader
        .take(32)?
        .try_into()
        .map_err(|_| StoreError::metadata(MetadataKind::Store, "<memory>", "invalid digest"))?;
    Ok(Digest::from_bytes(bytes))
}

pub(crate) fn read_derivation_key(reader: &mut Reader<'_>) -> Result<DerivationKey, StoreError> {
    let bytes: [u8; 32] = reader.take(32)?.try_into().map_err(|_| {
        StoreError::metadata(MetadataKind::Store, "<memory>", "invalid derivation key")
    })?;
    Ok(DerivationKey::from_bytes(bytes))
}

pub(crate) fn validate_canonical_sidecars(sidecars: &[ImmutableSidecar]) -> Result<(), StoreError> {
    if sidecars.len() > MAX_GENERATION_SIDECARS {
        return Err(invalid(
            "sidecars",
            format!("at most {MAX_GENERATION_SIDECARS} entries are allowed"),
        ));
    }
    if sidecars
        .windows(2)
        .any(|pair| pair[0].name.as_bytes() >= pair[1].name.as_bytes())
    {
        return Err(invalid(
            "sidecars",
            "entries must be strictly ordered by canonical byte name",
        ));
    }
    Ok(())
}

pub(crate) fn validate_sidecar_name(value: String) -> Result<String, StoreError> {
    if value.is_empty()
        || value.len() > MAX_SIDECAR_NAME_BYTES
        || matches!(
            value.as_str(),
            "." | ".." | "base.ext4" | "generation.meta" | "staging.meta"
        )
        || value.starts_with('.')
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_alphanumeric() && !matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(invalid(
            "sidecar.name",
            "must be a non-reserved ASCII basename using letters, digits, '.', '_', or '-'",
        ));
    }
    Ok(value)
}

fn validate_optional_identifier(
    field: &'static str,
    value: Option<String>,
) -> Result<Option<String>, StoreError> {
    value
        .map(|value| validate_identifier(field, value))
        .transpose()
}

fn validate_optional_text(
    field: &'static str,
    value: Option<String>,
    maximum: usize,
) -> Result<Option<String>, StoreError> {
    value
        .map(|value| validate_text(field, value, maximum))
        .transpose()
}

fn validate_identifier(field: &'static str, value: String) -> Result<String, StoreError> {
    if value.is_empty() || value.len() > MAX_ID_TEXT {
        return Err(invalid(
            field,
            format!("must contain 1..={MAX_ID_TEXT} bytes"),
        ));
    }
    if value.bytes().any(|byte| {
        !byte.is_ascii_alphanumeric() && !matches!(byte, b'-' | b'_' | b'.' | b'+' | b'/')
    }) {
        return Err(invalid(
            field,
            "must contain only ASCII letters, digits, '.', '_', '+', '-', or '/'",
        ));
    }
    Ok(value)
}

fn validate_text(field: &'static str, value: String, maximum: usize) -> Result<String, StoreError> {
    if value.is_empty() || value.len() > maximum {
        return Err(invalid(field, format!("must contain 1..={maximum} bytes")));
    }
    if value.chars().any(char::is_control) {
        return Err(invalid(field, "must not contain control characters"));
    }
    Ok(value)
}

fn invalid(field: &'static str, reason: impl Into<String>) -> StoreError {
    StoreError::InvalidInput {
        field,
        reason: reason.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: u8) -> Digest {
        Digest::from_bytes([byte; 32])
    }

    fn spec(platform: Platform) -> GenerationSpec {
        GenerationSpec::new(
            digest(1),
            digest(2),
            vec![digest(3)],
            vec![digest(4)],
            None,
            platform.clone(),
            platform,
            "oci-selector-v1",
            "x86_64-smp-p4k",
            digest(5),
            "rootfs-dir-v1",
            "ext4-v1-b4096",
            digest(6),
        )
        .expect("valid spec")
    }

    #[test]
    fn derivation_identity_is_deterministic_and_platform_sensitive() {
        let first = spec(Platform::new("linux", "amd64", None, None, vec![]).expect("platform"));
        let same = first.clone();
        let arm = spec(Platform::new("linux", "arm64", None, None, vec![]).expect("platform"));
        assert_eq!(first.derivation_key(), same.derivation_key());
        assert_ne!(first.derivation_key(), arm.derivation_key());
    }

    #[test]
    fn derivation_identity_preserves_raw_platform_presence() {
        let platform = Platform::new("linux", "amd64", None, None, vec![]).expect("platform");
        let absent = spec(platform.clone());
        let explicit = GenerationSpec::new(
            digest(1),
            digest(2),
            vec![digest(3)],
            vec![digest(4)],
            Some(platform.clone()),
            platform.clone(),
            platform,
            "oci-selector-v1",
            "x86_64-smp-p4k",
            digest(5),
            "rootfs-dir-v1",
            "ext4-v1-b4096",
            digest(6),
        )
        .expect("explicit descriptor platform");
        assert_ne!(absent.derivation_key(), explicit.derivation_key());
        assert!(absent.descriptor_platform().is_none());
        assert!(explicit.descriptor_platform().is_some());
    }

    #[test]
    fn platform_contract_reconciles_optional_fields_without_collapsing_raw_values() {
        let descriptor = Platform::new("linux", "amd64", Some("v1".to_owned()), None, vec![])
            .expect("descriptor");
        let config = Platform::new("linux", "amd64", None, None, vec![]).expect("config");
        let effective = descriptor.clone();
        let spec = GenerationSpec::new(
            digest(1),
            digest(2),
            vec![digest(3)],
            vec![digest(4)],
            Some(descriptor.clone()),
            config.clone(),
            effective,
            "oci-selector-v1",
            "x86_64-smp-p4k",
            digest(5),
            "rootfs-dir-v1",
            "ext4-v1-b4096",
            digest(6),
        )
        .expect("reconciled platform");
        assert_eq!(spec.descriptor_platform(), Some(&descriptor));
        assert_eq!(spec.config_platform(), &config);

        let wrong = Platform::new("linux", "amd64", Some("v2".to_owned()), None, vec![])
            .expect("wrong effective");
        assert!(
            GenerationSpec::new(
                digest(1),
                digest(2),
                vec![digest(3)],
                vec![digest(4)],
                Some(descriptor),
                config,
                wrong,
                "oci-selector-v1",
                "x86_64-smp-p4k",
                digest(5),
                "rootfs-dir-v1",
                "ext4-v1-b4096",
                digest(6),
            )
            .is_err()
        );
    }

    #[test]
    fn alias_identity_binds_requested_platform_and_selector_policy() {
        let absent = Platform::new("linux", "amd64", None, None, vec![]).expect("platform");
        let explicit =
            Platform::new("linux", "amd64", Some("v1".to_owned()), None, vec![]).expect("platform");
        let alias = |platform, policy| {
            AliasKey::new(
                "x86_64-smp-p4k",
                digest(5),
                "docker.io/library/example:latest",
                platform,
                policy,
            )
            .expect("alias")
        };
        let baseline = alias(absent.clone(), "oci-selector-v1");
        assert_ne!(baseline.id(), alias(explicit, "oci-selector-v1").id());
        assert_ne!(baseline.id(), alias(absent, "oci-selector-v2").id());
    }

    #[test]
    fn platform_features_have_one_canonical_order() {
        let first = Platform::new(
            "linux",
            "amd64",
            None,
            None,
            vec!["sse4".into(), "sse2".into()],
        )
        .expect("platform");
        let second = Platform::new(
            "linux",
            "amd64",
            None,
            None,
            vec!["sse2".into(), "sse4".into()],
        )
        .expect("platform");
        assert_eq!(spec(first).derivation_key(), spec(second).derivation_key());
    }

    #[test]
    fn final_identity_binds_output_bytes_sizes_and_ordered_sidecars() {
        let key = spec(Platform::new("linux", "amd64", None, None, vec![]).expect("platform"))
            .derivation_key();
        let sidecars = vec![
            ImmutableSidecar::new("image-config.json", digest(2), 10).expect("sidecar"),
            ImmutableSidecar::new("metadata.manifest", digest(3), 20).expect("sidecar"),
        ];
        let first = GenerationId::derive(key, digest(1), 100, &sidecars).expect("identity");
        assert_eq!(
            first,
            GenerationId::derive(key, digest(1), 100, &sidecars).expect("same identity")
        );
        assert_ne!(
            first,
            GenerationId::derive(key, digest(9), 100, &sidecars).expect("changed base")
        );
        assert_ne!(
            first,
            GenerationId::derive(key, digest(1), 101, &sidecars).expect("changed size")
        );

        let mut reversed = sidecars;
        reversed.reverse();
        assert!(GenerationId::derive(key, digest(1), 100, &reversed).is_err());
    }

    #[test]
    fn digest_text_is_strictly_canonical() {
        let value = digest(0xab);
        assert_eq!(value.to_string().parse::<Digest>().expect("digest"), value);
        assert!("AB".repeat(32).parse::<Digest>().is_err());
        assert!("sha256:AB".repeat(32).parse::<Digest>().is_err());
    }
}
