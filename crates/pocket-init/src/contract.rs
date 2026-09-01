use minicbor::{Decode, Decoder, Encode};
use pocket_protocol::{Platform, Start};

use crate::{GuestConfig, InitError};

pub const MAX_GENERATION_MARKER_BYTES: usize = 64 * 1024;

/// Runtime facts measured by the guest rather than accepted from START.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestObservation {
    pub uts_machine: String,
    pub oci_architecture: String,
    pub page_size: u32,
    pub online_cpus: u16,
    pub elf_machine: u16,
    pub accepted_physmem_bytes: u64,
}

/// Canonical marker stored outside the image tree in the root ext4 volume.
/// Numeric CBOR keys and byte-for-byte re-encoding make this an immutable
/// reconciliation record rather than a permissive metadata hint.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct GenerationMarker {
    #[n(0)]
    pub schema: String,
    #[n(1)]
    pub derivation_key: String,
    #[n(2)]
    pub profile_id: String,
    #[n(3)]
    pub profile_revision: String,
    #[n(4)]
    pub descriptor_platform: Option<Platform>,
    #[n(5)]
    pub config_platform: Platform,
    #[n(6)]
    pub effective_platform: Platform,
    #[n(7)]
    pub selector_policy: String,
    #[n(8)]
    pub root_layout: String,
    #[n(9)]
    pub filesystem_contract: String,
    #[n(10)]
    pub account_db_sha256: String,
}

pub fn verify_start(
    config: &GuestConfig,
    observation: &GuestObservation,
    start: &Start,
) -> Result<(), InitError> {
    if observation.online_cpus != config.expected_cpus {
        return Err(InitError::contract(
            "start-contract",
            format!(
                "guest has {} online CPUs but boot contract requires {}",
                observation.online_cpus, config.expected_cpus
            ),
        ));
    }
    if observation.accepted_physmem_bytes != config.expected_memory_bytes {
        return Err(InitError::contract(
            "start-contract",
            format!(
                "UML accepted {} physical-memory bytes but boot contract requires {}",
                observation.accepted_physmem_bytes, config.expected_memory_bytes
            ),
        ));
    }
    if observation.oci_architecture != config.expected_oci_architecture {
        return Err(InitError::contract(
            "start-contract",
            "measured guest architecture disagrees with boot contract",
        ));
    }
    if start.effective_platform.os != "linux"
        || start.effective_platform.architecture != observation.oci_architecture
    {
        return Err(InitError::contract(
            "start-contract",
            format!(
                "START platform {}/{} does not match guest linux/{}",
                start.effective_platform.os,
                start.effective_platform.architecture,
                observation.oci_architecture
            ),
        ));
    }
    if start.root_layout != config.expected_root_layout {
        return Err(InitError::contract(
            "start-contract",
            format!(
                "root layout {:?} does not match boot contract {:?}",
                start.root_layout, config.expected_root_layout
            ),
        ));
    }
    if start.filesystem_contract != config.expected_filesystem_contract {
        return Err(InitError::contract(
            "start-contract",
            format!(
                "filesystem contract {:?} does not match boot contract {:?}",
                start.filesystem_contract, config.expected_filesystem_contract
            ),
        ));
    }
    if start.network_mode > 1 {
        return Err(InitError::unsupported(
            "start-contract",
            "unknown network mode",
        ));
    }
    Ok(())
}

pub fn decode_generation_marker(bytes: &[u8]) -> Result<GenerationMarker, InitError> {
    if bytes.len() > MAX_GENERATION_MARKER_BYTES {
        return Err(InitError::contract(
            "generation-marker",
            format!(
                "generation marker is {} bytes; maximum is {}",
                bytes.len(),
                MAX_GENERATION_MARKER_BYTES
            ),
        ));
    }
    let mut decoder = Decoder::new(bytes);
    let mut context = ();
    let marker = GenerationMarker::decode(&mut decoder, &mut context).map_err(|error| {
        InitError::contract("generation-marker", format!("invalid CBOR: {error}"))
    })?;
    if decoder.position() != bytes.len() {
        return Err(InitError::contract(
            "generation-marker",
            "trailing bytes after marker",
        ));
    }
    let canonical = minicbor::to_vec(&marker).map_err(|error| {
        InitError::contract(
            "generation-marker",
            format!("cannot re-encode marker: {error}"),
        )
    })?;
    if canonical != bytes {
        return Err(InitError::contract(
            "generation-marker",
            "marker is not in deterministic CBOR encoding",
        ));
    }
    Ok(marker)
}

pub fn verify_generation_marker(marker: &GenerationMarker, start: &Start) -> Result<(), InitError> {
    if marker.schema != "pocket-generation-v3" {
        return Err(mismatch("schema"));
    }
    let matches = marker.derivation_key == start.derivation_key
        && marker.profile_id == start.profile_id
        && marker.profile_revision == start.profile_revision
        && marker.descriptor_platform == start.descriptor_platform
        && marker.config_platform == start.config_platform
        && marker.effective_platform == start.effective_platform
        && marker.selector_policy == start.selector_policy
        && marker.root_layout == start.root_layout
        && marker.filesystem_contract == start.filesystem_contract
        && marker.account_db_sha256 == start.account_db_sha256;
    if !matches {
        return Err(mismatch("START reconciliation fields"));
    }
    Ok(())
}

fn mismatch(field: &str) -> InitError {
    InitError::contract(
        "generation-marker",
        format!("generation marker {field} does not match START"),
    )
}

#[cfg(test)]
mod tests {
    use pocket_protocol::{Platform, ResourceLimit, Start};

    use super::{
        GenerationMarker, GuestObservation, decode_generation_marker, verify_generation_marker,
        verify_start,
    };
    use crate::GuestConfig;

    const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const C: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    fn config() -> GuestConfig {
        match GuestConfig::parse_cmdline(&format!(
            "pocket.expected_cpus=2 pocket.expected_memory_bytes=268435456 pocket.cpu_state_hwcap_policy=native-x86_64-v1 pocket.guest_capability_policy=fixed-capabilities-v1 pocket.guest_contract_id={A} pocket.init_build_id={B} pocket.kernel_build_id={C}"
        )) {
            Ok(config) => config,
            Err(error) => panic!("valid config rejected: {error}"),
        }
    }

    fn start() -> Start {
        let platform = Platform {
            os: "linux".to_owned(),
            architecture: "amd64".to_owned(),
            variant: None,
        };
        Start {
            profile_id: "x86_64-smp-p4k".to_owned(),
            profile_revision: A.to_owned(),
            generation_id: B.to_owned(),
            descriptor_platform: Some(platform.clone()),
            config_platform: platform.clone(),
            effective_platform: platform,
            selector_policy: "linux-amd64-v1".to_owned(),
            root_layout: "pocket-root-v1".to_owned(),
            filesystem_contract: "ext4-v1-b4096".to_owned(),
            argv: vec!["/bin/true".to_owned()],
            env: vec!["PATH=/usr/bin:/bin".to_owned()],
            cwd: "/".to_owned(),
            uid: 0,
            gid: 0,
            supplementary_gids: Vec::new(),
            umask: 0o022,
            rlimits: vec![ResourceLimit {
                resource: 7,
                soft: 1024,
                hard: 1024,
            }],
            hostname: "pocket".to_owned(),
            root_read_only: false,
            volumes: Vec::new(),
            terminal: false,
            network_mode: 0,
            privileged: false,
            stop_signal: 15,
            derivation_key: C.to_owned(),
            account_db_sha256: A.to_owned(),
            stdin_bytes: 0,
        }
    }

    fn observation() -> GuestObservation {
        GuestObservation {
            uts_machine: "x86_64".to_owned(),
            oci_architecture: "amd64".to_owned(),
            page_size: 4096,
            online_cpus: 2,
            accepted_physmem_bytes: 256 * 1024 * 1024,
            elf_machine: 62,
        }
    }

    #[test]
    fn reconciles_start_with_measured_boot_contract() {
        assert!(verify_start(&config(), &observation(), &start()).is_ok());
        let mut wrong = start();
        wrong.effective_platform.architecture = "arm64".to_owned();
        assert!(verify_start(&config(), &observation(), &wrong).is_err());
    }

    #[test]
    fn generation_marker_is_canonical_and_exact() {
        let request = start();
        let marker = GenerationMarker {
            schema: "pocket-generation-v3".to_owned(),
            derivation_key: request.derivation_key.clone(),
            profile_id: request.profile_id.clone(),
            profile_revision: request.profile_revision.clone(),
            descriptor_platform: request.descriptor_platform.clone(),
            config_platform: request.config_platform.clone(),
            effective_platform: request.effective_platform.clone(),
            selector_policy: request.selector_policy.clone(),
            root_layout: request.root_layout.clone(),
            filesystem_contract: request.filesystem_contract.clone(),
            account_db_sha256: request.account_db_sha256.clone(),
        };
        let encoded = match minicbor::to_vec(&marker) {
            Ok(encoded) => encoded,
            Err(error) => panic!("cannot encode marker: {error}"),
        };
        let decoded = match decode_generation_marker(&encoded) {
            Ok(decoded) => decoded,
            Err(error) => panic!("valid marker rejected: {error}"),
        };
        assert_eq!(decoded, marker);
        assert!(verify_generation_marker(&decoded, &request).is_ok());

        let mut mismatched = decoded;
        mismatched.derivation_key = B.to_owned();
        assert!(verify_generation_marker(&mismatched, &request).is_err());

        let mut old_schema = marker;
        old_schema.schema = "pocket-generation-v1".to_owned();
        assert!(verify_generation_marker(&old_schema, &request).is_err());
    }

    #[test]
    fn rejects_trailing_marker_data() {
        let marker = GenerationMarker {
            schema: "pocket-generation-v3".to_owned(),
            derivation_key: B.to_owned(),
            profile_id: "profile".to_owned(),
            profile_revision: A.to_owned(),
            descriptor_platform: None,
            config_platform: start().config_platform,
            effective_platform: start().effective_platform,
            selector_policy: "policy".to_owned(),
            root_layout: "pocket-root-v1".to_owned(),
            filesystem_contract: "ext4-v1-b4096".to_owned(),
            account_db_sha256: A.to_owned(),
        };
        let mut encoded = match minicbor::to_vec(&marker) {
            Ok(encoded) => encoded,
            Err(error) => panic!("cannot encode marker: {error}"),
        };
        encoded.push(0);
        assert!(decode_generation_marker(&encoded).is_err());
    }
}
