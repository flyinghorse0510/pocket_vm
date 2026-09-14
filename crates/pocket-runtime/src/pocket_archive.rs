//! A generation moved between stores without being rebuilt.
//!
//! The OCI export rebuilds an image so that other tools can read it, which
//! means the far side converts it again: a builder UML unpacks the layer and a
//! validator UML re-walks the result. That is the right trade for interchange
//! and the wrong one for moving a generation between two pocket stores, where
//! the bytes are already exactly what the far side would compute.
//!
//! This archive therefore carries the generation itself -- the ext4 image, its
//! sidecars, and the input contract that names it -- and the far side verifies
//! rather than recomputes. Nothing is taken on trust: the store publishes
//! under an identity derived from the bytes received, so an archive whose
//! contents do not hash to the generation it claims to be fails to publish.
//!
//! The image is stored as its allocated extents. A base is mostly holes -- an
//! eight gibibyte filesystem holding a few megabytes of Alpine -- and writing
//! those holes out would make the archive three orders of magnitude larger
//! than the data in it.

use pocket_store::{Digest, GenerationSpec, ImmutableSidecar, Platform};
use serde::{Deserialize, Serialize};

pub const SCHEMA: &str = "pocket-archive-v1";

/// The container is deliberately not a tar. Only pocket reads this file, and a
/// framed layout -- magic, a length-prefixed document, then the bytes the
/// document describes in the order it lists them -- needs no tar reader on the
/// receiving side and can be streamed in one pass.
pub const MAGIC: &[u8; 16] = b"pocket-archive1\n";

/// One contiguous run of allocated bytes in the base image.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Extent {
    pub offset: u64,
    pub length: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlatformRecord {
    pub os: String,
    pub architecture: String,
    #[serde(default)]
    pub variant: Option<String>,
    #[serde(default)]
    pub os_version: Option<String>,
    #[serde(default)]
    pub os_features: Vec<String>,
}

impl PlatformRecord {
    pub fn of(platform: &Platform) -> Self {
        Self {
            os: platform.os().to_owned(),
            architecture: platform.architecture().to_owned(),
            variant: platform.variant().map(str::to_owned),
            os_version: platform.os_version().map(str::to_owned),
            os_features: platform.os_features().to_vec(),
        }
    }

    pub fn build(&self) -> Result<Platform, String> {
        Platform::new(
            self.os.clone(),
            self.architecture.clone(),
            self.variant.clone(),
            self.os_version.clone(),
            self.os_features.clone(),
        )
        .map_err(|error| error.to_string())
    }
}

/// The input contract a generation was published under.
///
/// Carried in full rather than recomputed, because it is what decides the
/// generation's identity: the far side must arrive at the same derivation key,
/// or it is publishing something else under a borrowed name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpecRecord {
    pub selected_manifest_digest: String,
    pub config_digest: String,
    pub layer_digests: Vec<String>,
    pub diff_ids: Vec<String>,
    pub descriptor_platform: Option<PlatformRecord>,
    pub config_platform: PlatformRecord,
    pub effective_platform: PlatformRecord,
    pub selector_policy_id: String,
    pub profile_id: String,
    pub profile_revision: String,
    pub root_layout_contract: String,
    pub filesystem_contract: String,
    pub build_contract_digest: String,
}

impl SpecRecord {
    pub fn of(spec: &GenerationSpec) -> Self {
        Self {
            selected_manifest_digest: spec.selected_manifest_digest().to_string(),
            config_digest: spec.config_digest().to_string(),
            layer_digests: spec
                .layer_digests()
                .iter()
                .map(ToString::to_string)
                .collect(),
            diff_ids: spec.diff_ids().iter().map(ToString::to_string).collect(),
            descriptor_platform: spec.descriptor_platform().map(PlatformRecord::of),
            config_platform: PlatformRecord::of(spec.config_platform()),
            effective_platform: PlatformRecord::of(spec.effective_platform()),
            selector_policy_id: spec.selector_policy_id().to_owned(),
            profile_id: spec.profile_id().to_owned(),
            profile_revision: spec.profile_revision().to_string(),
            root_layout_contract: spec.root_layout_contract().to_owned(),
            filesystem_contract: spec.filesystem_contract().to_owned(),
            build_contract_digest: spec.build_contract_digest().to_string(),
        }
    }

    pub fn build(&self) -> Result<GenerationSpec, String> {
        let digest = |text: &str| text.parse::<Digest>().map_err(|error| error.to_string());
        let digests = |values: &[String]| {
            values
                .iter()
                .map(|value| digest(value))
                .collect::<Result<Vec<_>, _>>()
        };
        GenerationSpec::new(
            digest(&self.selected_manifest_digest)?,
            digest(&self.config_digest)?,
            digests(&self.layer_digests)?,
            digests(&self.diff_ids)?,
            self.descriptor_platform
                .as_ref()
                .map(PlatformRecord::build)
                .transpose()?,
            self.config_platform.build()?,
            self.effective_platform.build()?,
            self.selector_policy_id.clone(),
            self.profile_id.clone(),
            digest(&self.profile_revision)?,
            self.root_layout_contract.clone(),
            self.filesystem_contract.clone(),
            digest(&self.build_contract_digest)?,
        )
        .map_err(|error| error.to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SidecarRecord {
    pub name: String,
    pub digest: String,
    pub size: u64,
}

impl SidecarRecord {
    pub fn of(sidecar: &ImmutableSidecar) -> Self {
        Self {
            name: sidecar.name().to_owned(),
            digest: sidecar.digest().to_string(),
            size: sidecar.size(),
        }
    }

    pub fn build(&self) -> Result<ImmutableSidecar, String> {
        ImmutableSidecar::new(
            self.name.clone(),
            self.digest.parse::<Digest>().map_err(|e| e.to_string())?,
            self.size,
        )
        .map_err(|error| error.to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaseRecord {
    pub size: u64,
    pub digest: String,
    pub extents: Vec<Extent>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Document {
    pub schema: String,
    pub generation_id: String,
    pub reference: String,
    pub spec: SpecRecord,
    pub base: BaseRecord,
    pub sidecars: Vec<SidecarRecord>,
}

impl Document {
    /// Check what can be checked before a single byte is written anywhere.
    pub fn validate(&self) -> Result<(), String> {
        if self.schema != SCHEMA {
            return Err(format!("archive schema is {:?}, not {SCHEMA}", self.schema));
        }
        let mut covered = 0_u64;
        let mut previous_end = 0_u64;
        for extent in &self.base.extents {
            if extent.length == 0 {
                return Err("archive records an empty extent".to_owned());
            }
            if extent.offset < previous_end {
                return Err("archive extents overlap or are unordered".to_owned());
            }
            let end = extent
                .offset
                .checked_add(extent.length)
                .ok_or_else(|| "archive extent overflows".to_owned())?;
            if end > self.base.size {
                return Err("archive extent runs past the end of the image".to_owned());
            }
            previous_end = end;
            covered += extent.length;
        }
        if covered > self.base.size {
            return Err("archive extents cover more than the image".to_owned());
        }
        Ok(())
    }

    /// Total bytes the extents carry, which is what `base.data` must hold.
    pub fn data_length(&self) -> u64 {
        self.base.extents.iter().map(|extent| extent.length).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn document() -> Document {
        Document {
            schema: SCHEMA.to_owned(),
            generation_id: "pkvm-gen-v1-00".to_owned(),
            reference: "alpine:3.22".to_owned(),
            spec: SpecRecord {
                selected_manifest_digest: String::new(),
                config_digest: String::new(),
                layer_digests: Vec::new(),
                diff_ids: Vec::new(),
                descriptor_platform: None,
                config_platform: PlatformRecord {
                    os: "linux".to_owned(),
                    architecture: "amd64".to_owned(),
                    variant: None,
                    os_version: None,
                    os_features: Vec::new(),
                },
                effective_platform: PlatformRecord {
                    os: "linux".to_owned(),
                    architecture: "amd64".to_owned(),
                    variant: None,
                    os_version: None,
                    os_features: Vec::new(),
                },
                selector_policy_id: String::new(),
                profile_id: String::new(),
                profile_revision: String::new(),
                root_layout_contract: String::new(),
                filesystem_contract: String::new(),
                build_contract_digest: String::new(),
            },
            base: BaseRecord {
                size: 4096,
                digest: String::new(),
                extents: vec![Extent {
                    offset: 0,
                    length: 512,
                }],
            },
            sidecars: Vec::new(),
        }
    }

    #[test]
    fn a_foreign_schema_is_refused() {
        let mut subject = document();
        subject.schema = "something-else".to_owned();
        assert!(subject.validate().is_err());
    }

    #[test]
    fn overlapping_extents_are_refused() {
        let mut subject = document();
        subject.base.extents = vec![
            Extent {
                offset: 0,
                length: 1024,
            },
            Extent {
                offset: 512,
                length: 8,
            },
        ];
        assert!(subject.validate().is_err());
    }

    #[test]
    fn an_extent_past_the_end_is_refused() {
        let mut subject = document();
        subject.base.extents = vec![Extent {
            offset: 4000,
            length: 1024,
        }];
        assert!(subject.validate().is_err());
    }

    #[test]
    fn an_empty_extent_is_refused() {
        let mut subject = document();
        subject.base.extents = vec![Extent {
            offset: 0,
            length: 0,
        }];
        assert!(subject.validate().is_err());
    }

    #[test]
    fn a_sparse_image_is_described_by_its_data_alone() {
        let mut subject = document();
        subject.base.size = 8 * 1024 * 1024 * 1024;
        subject.base.extents = vec![
            Extent {
                offset: 0,
                length: 4096,
            },
            Extent {
                offset: 1 << 30,
                length: 8192,
            },
        ];
        subject.validate().expect("valid");
        assert_eq!(subject.data_length(), 12288);
    }

    #[test]
    fn the_document_round_trips_through_json() {
        let subject = document();
        let encoded = serde_json::to_vec(&subject).expect("encode");
        let decoded: Document = serde_json::from_slice(&encoded).expect("decode");
        assert_eq!(decoded, subject);
    }
}
