use std::collections::BTreeMap;

use crate::ValidatorError;

pub const DEFAULT_CONTROL_PATH: &str = "/dev/ttyS0";
pub const CANDIDATE_DEVICE: &str = "/dev/ubda";
pub const CANDIDATE_MOUNT: &str = "/candidate";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatorConfig {
    pub control_path: String,
    pub guest_contract_id: String,
    pub init_build_id: String,
    pub kernel_build_id: String,
    pub expected_oci_architecture: String,
    pub expected_page_size: u32,
    pub expected_physmem_bytes: u64,
    pub cpu_state_hwcap_policy: String,
    pub expected_root_layout: String,
    pub expected_filesystem_contract: String,
    pub expected_manifest_schema: String,
}

impl ValidatorConfig {
    pub fn parse_cmdline(cmdline: &str) -> Result<Self, ValidatorError> {
        let mut values = BTreeMap::<&str, &str>::new();
        for token in cmdline.split_ascii_whitespace() {
            let Some((key, value)) = token.split_once('=') else {
                continue;
            };
            if key.starts_with("pocket.validator.") && values.insert(key, value).is_some() {
                return Err(ValidatorError::contract(
                    "cmdline",
                    format!("duplicate {key} parameter"),
                ));
            }
        }
        for key in values.keys() {
            if !KNOWN_KEYS.contains(key) {
                return Err(ValidatorError::contract(
                    "cmdline",
                    format!("unknown Pocket validator parameter {key}"),
                ));
            }
        }
        if required(&values, "pocket.validator.expected_cpus")? != "1" {
            return Err(ValidatorError::contract(
                "cmdline",
                "pocket.validator.expected_cpus must be exactly one",
            ));
        }

        let control_path = value_or(&values, "pocket.validator.control", DEFAULT_CONTROL_PATH);
        validate_absolute_path("pocket.validator.control", control_path)?;
        let expected_architecture = value_or(
            &values,
            "pocket.validator.expected_architecture",
            compile_oci_architecture(),
        );
        if expected_architecture != compile_oci_architecture() {
            return Err(ValidatorError::contract(
                "cmdline",
                "validator architecture differs from the compiled architecture",
            ));
        }
        let expected_page_size =
            parse_page_size(required(&values, "pocket.validator.expected_page_size")?)?;
        let expected_physmem_bytes =
            parse_memory(required(&values, "pocket.validator.expected_memory_bytes")?)?;
        let cpu_state_hwcap_policy = required_or_compile(
            &values,
            "pocket.validator.cpu_state_hwcap_policy",
            option_env!("POCKET_VALIDATOR_CPU_STATE_HWCAP_POLICY"),
        )?;
        validate_token(
            "pocket.validator.cpu_state_hwcap_policy",
            cpu_state_hwcap_policy,
        )?;
        let root_layout = value_or(&values, "pocket.validator.root_layout", "pocket-root-v1");
        let filesystem_contract = value_or(
            &values,
            "pocket.validator.filesystem_contract",
            "ext4-v1-b4096",
        );
        let manifest_schema = value_or(
            &values,
            "pocket.validator.manifest_schema",
            "pocket-fs-manifest-v1",
        );
        for (field, value) in [
            ("pocket.validator.root_layout", root_layout),
            ("pocket.validator.filesystem_contract", filesystem_contract),
            ("pocket.validator.manifest_schema", manifest_schema),
        ] {
            validate_token(field, value)?;
        }

        Ok(Self {
            control_path: control_path.to_owned(),
            guest_contract_id: required_identity(
                &values,
                "pocket.validator.guest_contract_id",
                option_env!("POCKET_VALIDATOR_GUEST_CONTRACT_ID"),
            )?,
            init_build_id: required_identity(
                &values,
                "pocket.validator.init_build_id",
                option_env!("POCKET_VALIDATOR_INIT_BUILD_ID"),
            )?,
            kernel_build_id: required_identity(
                &values,
                "pocket.validator.kernel_build_id",
                option_env!("POCKET_VALIDATOR_KERNEL_BUILD_ID"),
            )?,
            expected_oci_architecture: expected_architecture.to_owned(),
            expected_page_size,
            expected_physmem_bytes,
            cpu_state_hwcap_policy: cpu_state_hwcap_policy.to_owned(),
            expected_root_layout: root_layout.to_owned(),
            expected_filesystem_contract: filesystem_contract.to_owned(),
            expected_manifest_schema: manifest_schema.to_owned(),
        })
    }
}

const KNOWN_KEYS: &[&str] = &[
    "pocket.validator.control",
    "pocket.validator.cpu_state_hwcap_policy",
    "pocket.validator.expected_architecture",
    "pocket.validator.expected_cpus",
    "pocket.validator.expected_memory_bytes",
    "pocket.validator.expected_page_size",
    "pocket.validator.filesystem_contract",
    "pocket.validator.guest_contract_id",
    "pocket.validator.init_build_id",
    "pocket.validator.kernel_build_id",
    "pocket.validator.manifest_schema",
    "pocket.validator.root_layout",
];

fn value_or<'a>(values: &BTreeMap<&str, &'a str>, key: &str, fallback: &'a str) -> &'a str {
    values.get(key).copied().unwrap_or(fallback)
}

fn required<'a>(
    values: &BTreeMap<&str, &'a str>,
    key: &'static str,
) -> Result<&'a str, ValidatorError> {
    values
        .get(key)
        .copied()
        .ok_or_else(|| ValidatorError::contract("cmdline", format!("missing required {key}")))
}

fn required_or_compile<'a>(
    values: &BTreeMap<&str, &'a str>,
    key: &'static str,
    compiled: Option<&'static str>,
) -> Result<&'a str, ValidatorError> {
    values
        .get(key)
        .copied()
        .or(compiled)
        .ok_or_else(|| ValidatorError::contract("cmdline", format!("missing required {key}")))
}

fn required_identity(
    values: &BTreeMap<&str, &str>,
    key: &'static str,
    compiled: Option<&'static str>,
) -> Result<String, ValidatorError> {
    let value = values.get(key).copied().or(compiled).ok_or_else(|| {
        ValidatorError::contract("cmdline", format!("missing required identity {key}"))
    })?;
    validate_sha256(key, value)?;
    Ok(value.to_owned())
}

fn parse_page_size(value: &str) -> Result<u32, ValidatorError> {
    let parsed = value.parse::<u32>().map_err(|_| {
        ValidatorError::contract("cmdline", "expected page size is not an unsigned integer")
    })?;
    if !(4096..=65536).contains(&parsed) || !parsed.is_power_of_two() {
        return Err(ValidatorError::contract(
            "cmdline",
            "expected page size is unsupported",
        ));
    }
    Ok(parsed)
}

fn parse_memory(value: &str) -> Result<u64, ValidatorError> {
    let bytes = value.parse::<u64>().map_err(|_| {
        ValidatorError::contract("cmdline", "expected memory is not an unsigned integer")
    })?;
    if !(64 * 1024 * 1024..=1024 * 1024 * 1024 * 1024).contains(&bytes)
        || !bytes.is_multiple_of(4096)
    {
        return Err(ValidatorError::contract(
            "cmdline",
            "expected memory is outside the validator contract",
        ));
    }
    Ok(bytes)
}

fn validate_absolute_path(field: &'static str, value: &str) -> Result<(), ValidatorError> {
    if !value.starts_with('/')
        || value == "/"
        || value.contains('\0')
        || value
            .split('/')
            .skip(1)
            .any(|part| part.is_empty() || matches!(part, "." | ".."))
    {
        return Err(ValidatorError::contract(
            "cmdline",
            format!("{field} is not a normalized non-root absolute path"),
        ));
    }
    Ok(())
}

fn validate_sha256(field: &'static str, value: &str) -> Result<(), ValidatorError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ValidatorError::contract(
            "cmdline",
            format!("{field} is not a lowercase SHA-256"),
        ));
    }
    Ok(())
}

fn validate_token(field: &'static str, value: &str) -> Result<(), ValidatorError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(ValidatorError::contract(
            "cmdline",
            format!("{field} is not a bounded token"),
        ));
    }
    Ok(())
}

const fn compile_oci_architecture() -> &'static str {
    #[cfg(target_arch = "x86_64")]
    {
        "amd64"
    }
    #[cfg(target_arch = "aarch64")]
    {
        "arm64"
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        "unsupported"
    }
}

#[cfg(test)]
mod tests {
    use super::ValidatorConfig;

    const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const C: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    fn cmdline() -> String {
        format!(
            "pocket.validator.expected_cpus=1 \
             pocket.validator.expected_memory_bytes=536870912 \
             pocket.validator.expected_page_size=4096 \
             pocket.validator.cpu_state_hwcap_policy=native-x86_64-v1 \
             pocket.validator.guest_contract_id={A} \
             pocket.validator.init_build_id={B} \
             pocket.validator.kernel_build_id={C}"
        )
    }

    #[test]
    fn parses_exact_validator_contract_and_rejects_unknown_or_duplicate_keys() {
        let config = ValidatorConfig::parse_cmdline(&cmdline()).expect("valid config");
        assert_eq!(config.expected_physmem_bytes, 536_870_912);
        assert_eq!(config.expected_oci_architecture, "amd64");
        assert!(
            ValidatorConfig::parse_cmdline(&format!(
                "{} pocket.validator.expected_cpus=1",
                cmdline()
            ))
            .is_err()
        );
        assert!(
            ValidatorConfig::parse_cmdline(&format!(
                "{} pocket.validator.unrecognized=value",
                cmdline()
            ))
            .is_err()
        );
    }
}
