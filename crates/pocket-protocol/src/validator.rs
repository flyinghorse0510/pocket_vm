use std::collections::BTreeSet;

use minicbor::{Decode, Encode};
use pocket_core::ErrorCode;
use sha2::{Digest as _, Sha256};

use crate::{
    AccountDb, ErrorMessage, GenerationMarker, MAX_DIAGNOSTIC_LENGTH, MAX_ID_LENGTH,
    ManifestLimits, MessageKind, ProtocolError, RawFrame, ValidateMessage, decode_payload,
    encode_payload,
    message::{invalid, validate_count, validate_sha256, validate_token},
};

const EVIDENCE_DOMAIN: &[u8] = b"pocket-validator-evidence\0v1\0";

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct ValidatorHello {
    #[n(0)]
    pub guest_contract_id: String,
    #[n(1)]
    pub init_build_id: String,
    #[n(2)]
    pub kernel_build_id: String,
    #[n(3)]
    pub host_elf_machine: u16,
    #[n(4)]
    pub guest_uts_machine: String,
    #[n(5)]
    pub guest_page_size: u32,
    #[n(6)]
    pub cpu_state_hwcap_policy: String,
    #[n(7)]
    pub online_cpus: u16,
    #[n(8)]
    pub accepted_physmem_bytes: u64,
    #[n(9)]
    pub features: Vec<String>,
}

impl ValidateMessage for ValidatorHello {
    fn validate(&self) -> Result<(), ProtocolError> {
        validate_sha256("guest_contract_id", &self.guest_contract_id)?;
        validate_sha256("init_build_id", &self.init_build_id)?;
        validate_sha256("kernel_build_id", &self.kernel_build_id)?;
        if !matches!(self.host_elf_machine, 62 | 183) {
            return invalid("host_elf_machine", "unsupported ELF machine");
        }
        if !matches!(self.guest_uts_machine.as_str(), "x86_64" | "aarch64") {
            return invalid("guest_uts_machine", "unsupported guest machine");
        }
        if !(4096..=65536).contains(&self.guest_page_size)
            || !self.guest_page_size.is_power_of_two()
        {
            return invalid("guest_page_size", "unsupported page size");
        }
        validate_token(
            "cpu_state_hwcap_policy",
            &self.cpu_state_hwcap_policy,
            MAX_ID_LENGTH,
        )?;
        if self.online_cpus != 1 {
            return invalid("online_cpus", "validator must have exactly one online CPU");
        }
        validate_validator_memory("accepted_physmem_bytes", self.accepted_physmem_bytes)?;
        if !self
            .accepted_physmem_bytes
            .is_multiple_of(u64::from(self.guest_page_size))
        {
            return invalid(
                "accepted_physmem_bytes",
                "must be aligned to the reported guest page size",
            );
        }
        validate_count("features", self.features.len(), 32)?;
        let mut features = BTreeSet::new();
        for feature in &self.features {
            validate_token("features", feature, 64)?;
            if !features.insert(feature) {
                return invalid("features", "duplicate feature");
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct ValidatorStart {
    #[n(0)]
    pub profile_id: String,
    #[n(1)]
    pub profile_revision: String,
    #[n(2)]
    pub challenge: String,
    #[n(3)]
    pub derivation_key: String,
    #[n(4)]
    pub root_layout: String,
    #[n(5)]
    pub filesystem_contract: String,
    #[n(6)]
    pub manifest_schema: String,
    #[n(7)]
    pub manifest_limits: ManifestLimits,
    #[n(8)]
    pub expected_manifest_sha256: String,
    #[n(9)]
    pub expected_manifest_entry_count: u64,
    #[n(10)]
    pub expected_manifest_byte_count: u64,
    #[n(11)]
    pub expected_generation_marker: GenerationMarker,
    #[n(12)]
    pub expected_generation_marker_sha256: String,
    #[n(13)]
    pub expected_account_db: AccountDb,
    #[n(14)]
    pub expected_filesystem_uuid: String,
    #[n(15)]
    pub expected_filesystem_bytes: u64,
    #[n(16)]
    pub expected_physmem_bytes: u64,
}

impl ValidateMessage for ValidatorStart {
    fn validate(&self) -> Result<(), ProtocolError> {
        validate_token("profile_id", &self.profile_id, MAX_ID_LENGTH)?;
        for (field, value) in [
            ("profile_revision", &self.profile_revision),
            ("challenge", &self.challenge),
            ("derivation_key", &self.derivation_key),
            ("expected_manifest_sha256", &self.expected_manifest_sha256),
            (
                "expected_generation_marker_sha256",
                &self.expected_generation_marker_sha256,
            ),
        ] {
            validate_sha256(field, value)?;
        }
        validate_token("root_layout", &self.root_layout, MAX_ID_LENGTH)?;
        validate_token(
            "filesystem_contract",
            &self.filesystem_contract,
            MAX_ID_LENGTH,
        )?;
        validate_token("manifest_schema", &self.manifest_schema, MAX_ID_LENGTH)?;
        self.manifest_limits.validate()?;
        if self.expected_manifest_entry_count == 0
            || self.expected_manifest_entry_count > self.manifest_limits.max_entries
        {
            return invalid(
                "expected_manifest_entry_count",
                "outside negotiated manifest limit",
            );
        }
        if self.expected_manifest_byte_count == 0
            || self.expected_manifest_byte_count > self.manifest_limits.max_total_bytes
        {
            return invalid(
                "expected_manifest_byte_count",
                "outside negotiated manifest limit",
            );
        }
        self.expected_generation_marker.validate()?;
        if self.expected_generation_marker.profile_id != self.profile_id
            || self.expected_generation_marker.profile_revision != self.profile_revision
            || self.expected_generation_marker.derivation_key != self.derivation_key
            || self.expected_generation_marker.root_layout != self.root_layout
            || self.expected_generation_marker.filesystem_contract != self.filesystem_contract
        {
            return invalid(
                "expected_generation_marker",
                "does not agree with validation request",
            );
        }
        self.expected_account_db.validate()?;
        if self.expected_generation_marker.account_db_sha256 != self.expected_account_db.sha256 {
            return invalid(
                "expected_account_db",
                "digest differs from generation marker",
            );
        }
        validate_uuid("expected_filesystem_uuid", &self.expected_filesystem_uuid)?;
        if self.expected_filesystem_bytes < 64 * 1024 * 1024
            || !self.expected_filesystem_bytes.is_multiple_of(4096)
        {
            return invalid(
                "expected_filesystem_bytes",
                "must be at least 64 MiB and 4096-byte aligned",
            );
        }
        validate_validator_memory("expected_physmem_bytes", self.expected_physmem_bytes)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct ValidatorEvidence {
    #[n(0)]
    pub manifest_sha256: String,
    #[n(1)]
    pub manifest_entry_count: u64,
    #[n(2)]
    pub manifest_byte_count: u64,
    #[n(3)]
    pub generation_marker_sha256: String,
    #[n(4)]
    pub account_db_sha256: String,
    #[n(5)]
    pub filesystem_uuid: String,
    #[n(6)]
    pub filesystem_bytes: u64,
    #[n(7)]
    pub clean_before_mount: bool,
    #[n(8)]
    pub block_device_read_only: bool,
    #[n(9)]
    pub mounted_read_only: bool,
    #[n(10)]
    pub unmounted: bool,
    #[n(11)]
    pub clean_after_unmount: bool,
}

impl ValidateMessage for ValidatorEvidence {
    fn validate(&self) -> Result<(), ProtocolError> {
        for (field, value) in [
            ("manifest_sha256", &self.manifest_sha256),
            ("generation_marker_sha256", &self.generation_marker_sha256),
            ("account_db_sha256", &self.account_db_sha256),
        ] {
            validate_sha256(field, value)?;
        }
        validate_uuid("filesystem_uuid", &self.filesystem_uuid)?;
        if self.manifest_entry_count == 0
            || self.manifest_byte_count == 0
            || self.filesystem_bytes == 0
        {
            return invalid("validator_evidence", "numeric evidence must be nonzero");
        }
        if !self.clean_before_mount
            || !self.block_device_read_only
            || !self.mounted_read_only
            || !self.unmounted
            || !self.clean_after_unmount
        {
            return invalid(
                "validator_evidence",
                "successful validation requires clean read-only mount and unmount evidence",
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct ValidatorDone {
    #[n(0)]
    pub status: u8,
    #[n(1)]
    pub challenge: String,
    #[n(2)]
    pub evidence: ValidatorEvidence,
    #[n(3)]
    pub evidence_sha256: String,
}

impl ValidatorDone {
    #[must_use]
    pub fn from_evidence(start: &ValidatorStart, evidence: ValidatorEvidence) -> Self {
        Self {
            status: 0,
            challenge: start.challenge.clone(),
            evidence_sha256: validator_evidence_sha256(start, &evidence),
            evidence,
        }
    }
}

impl ValidateMessage for ValidatorDone {
    fn validate(&self) -> Result<(), ProtocolError> {
        if self.status != 0 {
            return invalid("status", "VALIDATE_DONE status must be zero");
        }
        validate_sha256("challenge", &self.challenge)?;
        self.evidence.validate()?;
        validate_sha256("evidence_sha256", &self.evidence_sha256)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidatorMessage {
    Hello(ValidatorHello),
    Start(Box<ValidatorStart>),
    Done(ValidatorDone),
    Error(ErrorMessage),
}

impl ValidatorMessage {
    #[must_use]
    pub const fn kind(&self) -> MessageKind {
        match self {
            Self::Hello(_) => MessageKind::ValidateHello,
            Self::Start(_) => MessageKind::ValidateStart,
            Self::Done(_) => MessageKind::ValidateDone,
            Self::Error(_) => MessageKind::ValidateError,
        }
    }

    pub fn encode_payload(&self) -> Result<Vec<u8>, ProtocolError> {
        match self {
            Self::Hello(message) => encode_payload(message),
            Self::Start(message) => encode_payload(message.as_ref()),
            Self::Done(message) => encode_payload(message),
            Self::Error(message) => encode_payload(message),
        }
    }

    pub fn validate(&self) -> Result<(), ProtocolError> {
        match self {
            Self::Hello(message) => message.validate(),
            Self::Start(message) => message.validate(),
            Self::Done(message) => message.validate(),
            Self::Error(message) => message.validate(),
        }
    }
}

pub fn decode_validator_message(frame: &RawFrame) -> Result<ValidatorMessage, ProtocolError> {
    match frame.header.kind {
        MessageKind::ValidateHello => decode_payload(&frame.payload).map(ValidatorMessage::Hello),
        MessageKind::ValidateStart => decode_payload(&frame.payload)
            .map(Box::new)
            .map(ValidatorMessage::Start),
        MessageKind::ValidateDone => decode_payload(&frame.payload).map(ValidatorMessage::Done),
        MessageKind::ValidateError => decode_payload(&frame.payload).map(ValidatorMessage::Error),
        _ => invalid("kind", "non-validator message in validator protocol"),
    }
}

#[must_use]
pub fn validator_evidence_sha256(start: &ValidatorStart, evidence: &ValidatorEvidence) -> String {
    let mut hasher = Sha256::new();
    hasher.update(EVIDENCE_DOMAIN);
    for value in [
        start.profile_id.as_bytes(),
        start.profile_revision.as_bytes(),
        start.challenge.as_bytes(),
        start.derivation_key.as_bytes(),
        start.root_layout.as_bytes(),
        start.filesystem_contract.as_bytes(),
        start.manifest_schema.as_bytes(),
        start.expected_manifest_sha256.as_bytes(),
        start.expected_generation_marker_sha256.as_bytes(),
        start.expected_account_db.sha256.as_bytes(),
        start.expected_filesystem_uuid.as_bytes(),
        evidence.manifest_sha256.as_bytes(),
        evidence.generation_marker_sha256.as_bytes(),
        evidence.account_db_sha256.as_bytes(),
        evidence.filesystem_uuid.as_bytes(),
    ] {
        hash_field(&mut hasher, value);
    }
    for value in [
        start.expected_manifest_entry_count,
        start.expected_manifest_byte_count,
        start.expected_filesystem_bytes,
        start.expected_physmem_bytes,
        evidence.manifest_entry_count,
        evidence.manifest_byte_count,
        evidence.filesystem_bytes,
    ] {
        hasher.update(value.to_be_bytes());
    }
    hasher.update([
        u8::from(evidence.clean_before_mount),
        u8::from(evidence.block_device_read_only),
        u8::from(evidence.mounted_read_only),
        u8::from(evidence.unmounted),
        u8::from(evidence.clean_after_unmount),
    ]);
    hex_lower(&hasher.finalize())
}

#[must_use]
pub fn validator_error_message(
    stage: impl Into<String>,
    code: ErrorCode,
    errno: Option<i32>,
    diagnostic: impl Into<String>,
) -> ErrorMessage {
    let mut diagnostic = diagnostic.into();
    if diagnostic.len() > MAX_DIAGNOSTIC_LENGTH {
        let mut boundary = MAX_DIAGNOSTIC_LENGTH;
        while !diagnostic.is_char_boundary(boundary) {
            boundary -= 1;
        }
        diagnostic.truncate(boundary);
    }
    ErrorMessage::new(stage, code, errno, diagnostic)
}

fn hash_field(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn validate_validator_memory(field: &'static str, bytes: u64) -> Result<(), ProtocolError> {
    if !(64 * 1024 * 1024..=1024 * 1024 * 1024 * 1024).contains(&bytes)
        || !bytes.is_multiple_of(4096)
    {
        return invalid(
            field,
            "validator memory must be 64 MiB..=1 TiB and 4096-byte aligned",
        );
    }
    Ok(())
}

fn validate_uuid(field: &'static str, value: &str) -> Result<(), ProtocolError> {
    if value.len() != 36
        || value.bytes().enumerate().any(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte != b'-',
            _ => !(byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        })
    {
        return invalid(field, "must be a lowercase canonical UUID");
    }
    Ok(())
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

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{AccountDatabase, AccountGroup, Platform};

    fn digest(character: char) -> String {
        character.to_string().repeat(64)
    }

    pub(crate) fn start() -> ValidatorStart {
        let account = AccountDb::from_database(&AccountDatabase {
            schema: crate::ACCOUNT_DB_SCHEMA.to_owned(),
            users: Vec::new(),
            groups: Vec::new(),
        })
        .expect("account database");
        ValidatorStart {
            profile_id: "x86_64-smp-p4k".to_owned(),
            profile_revision: digest('a'),
            challenge: digest('b'),
            derivation_key: digest('c'),
            root_layout: "pocket-root-v1".to_owned(),
            filesystem_contract: "ext4-v1-b4096".to_owned(),
            manifest_schema: "pocket-fs-manifest-v1".to_owned(),
            manifest_limits: ManifestLimits::default(),
            expected_manifest_sha256: digest('d'),
            expected_manifest_entry_count: 3,
            expected_manifest_byte_count: 4096,
            expected_generation_marker: GenerationMarker {
                schema: "pocket-generation-v3".to_owned(),
                derivation_key: digest('c'),
                profile_id: "x86_64-smp-p4k".to_owned(),
                profile_revision: digest('a'),
                descriptor_platform: None,
                config_platform: Platform {
                    os: "linux".to_owned(),
                    architecture: "amd64".to_owned(),
                    variant: None,
                },
                effective_platform: Platform {
                    os: "linux".to_owned(),
                    architecture: "amd64".to_owned(),
                    variant: None,
                },
                selector_policy: "native-amd64-v1".to_owned(),
                root_layout: "pocket-root-v1".to_owned(),
                filesystem_contract: "ext4-v1-b4096".to_owned(),
                account_db_sha256: account.sha256.clone(),
            },
            expected_generation_marker_sha256: digest('e'),
            expected_account_db: account,
            expected_filesystem_uuid: "11111111-2222-5333-8444-555555555555".to_owned(),
            expected_filesystem_bytes: 1024 * 1024 * 1024,
            expected_physmem_bytes: 512 * 1024 * 1024,
        }
    }

    fn evidence() -> ValidatorEvidence {
        ValidatorEvidence {
            manifest_sha256: digest('d'),
            manifest_entry_count: 3,
            manifest_byte_count: 4096,
            generation_marker_sha256: digest('e'),
            account_db_sha256: digest('f'),
            filesystem_uuid: "11111111-2222-5333-8444-555555555555".to_owned(),
            filesystem_bytes: 1024 * 1024 * 1024,
            clean_before_mount: true,
            block_device_read_only: true,
            mounted_read_only: true,
            unmounted: true,
            clean_after_unmount: true,
        }
    }

    #[test]
    fn round_trips_and_challenge_binds_evidence() {
        let start = start();
        start.validate().expect("valid start");
        let done = ValidatorDone::from_evidence(&start, evidence());
        done.validate().expect("valid done");
        let encoded = encode_payload(&done).expect("encode");
        let decoded: ValidatorDone = decode_payload(&encoded).expect("decode");
        assert_eq!(decoded, done);

        let mut changed = start.clone();
        changed.challenge = digest('9');
        assert_ne!(
            validator_evidence_sha256(&changed, &done.evidence),
            done.evidence_sha256
        );
    }

    #[test]
    fn canonical_account_sidecar_is_reauthenticated() {
        let bytes = start().expected_account_db.canonical_bytes;
        let reconstructed = AccountDb::from_canonical_bytes(bytes.clone()).expect("canonical");
        assert_eq!(reconstructed.canonical_bytes, bytes);
        let mut malformed = bytes;
        malformed.push(0);
        assert!(AccountDb::from_canonical_bytes(malformed).is_err());
    }

    #[test]
    fn maximum_account_evidence_stays_in_one_bounded_start_frame() {
        let mut value = start();
        value.expected_account_db = AccountDb::from_database(&AccountDatabase {
            schema: crate::ACCOUNT_DB_SCHEMA.to_owned(),
            users: Vec::new(),
            groups: (0..700_u32)
                .map(|index| AccountGroup {
                    name: format!("{index:04}-{}", "x".repeat(251)),
                    gid: index,
                    members: Vec::new(),
                })
                .collect(),
        })
        .expect("large valid account database");
        value.expected_generation_marker.account_db_sha256 =
            value.expected_account_db.sha256.clone();
        let encoded = encode_payload(&value).expect("encode bounded start");
        assert!(value.expected_account_db.canonical_bytes.len() > 128 * 1024);
        assert!(encoded.len() <= crate::MAX_CONTROL_PAYLOAD);
    }
}
