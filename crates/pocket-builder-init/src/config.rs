use std::collections::BTreeMap;

use crate::BuilderError;

pub const DEFAULT_CONTROL_PATH: &str = "/dev/ttyS0";
pub const INPUT_DEVICE: &str = "/dev/ubda";
pub const TARGET_DEVICE: &str = "/dev/ubdb";
pub const INPUT_MOUNT: &str = "/input";
pub const TARGET_MOUNT: &str = "/target";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuilderConfig {
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

impl BuilderConfig {
    /// Parse the immutable builder boot contract from `/proc/cmdline`.
    ///
    /// The UBD and mount paths are intentionally not configurable. Duplicate
    /// or unknown `pocket.builder.*` parameters are rejected. UML consumes
    /// `mem=` and `ncpus=` before `/proc/cmdline` is exposed, so the launch
    /// template must also pass guest-visible decimal expected-memory and CPU
    /// aliases. Those aliases are later reconciled with measured guest state.
    pub fn parse_cmdline(cmdline: &str) -> Result<Self, BuilderError> {
        let mut values = BTreeMap::<&str, &str>::new();
        for token in cmdline.split_ascii_whitespace() {
            let Some((key, value)) = token.split_once('=') else {
                continue;
            };
            if key.starts_with("pocket.builder.") && values.insert(key, value).is_some() {
                return Err(BuilderError::contract(
                    "cmdline",
                    format!("duplicate {key} parameter"),
                ));
            }
        }
        for key in values.keys() {
            if !KNOWN_KEYS.contains(key) {
                return Err(BuilderError::contract(
                    "cmdline",
                    format!("unknown Pocket builder parameter {key}"),
                ));
            }
        }

        if required(&values, "pocket.builder.expected_cpus")? != "1" {
            return Err(BuilderError::contract(
                "cmdline",
                "pocket.builder.expected_cpus must be exactly one",
            ));
        }

        let control_path = value_or(&values, "pocket.builder.control", DEFAULT_CONTROL_PATH);
        validate_absolute_path("pocket.builder.control", control_path)?;
        let guest_contract_id = required_identity(
            &values,
            "pocket.builder.guest_contract_id",
            option_env!("POCKET_BUILDER_GUEST_CONTRACT_ID"),
        )?;
        let init_build_id = required_identity(
            &values,
            "pocket.builder.init_build_id",
            option_env!("POCKET_BUILDER_INIT_BUILD_ID"),
        )?;
        let kernel_build_id = required_identity(
            &values,
            "pocket.builder.kernel_build_id",
            option_env!("POCKET_BUILDER_KERNEL_BUILD_ID"),
        )?;

        let expected_oci_architecture = value_or(
            &values,
            "pocket.builder.expected_architecture",
            compile_oci_architecture(),
        );
        if expected_oci_architecture != compile_oci_architecture() {
            return Err(BuilderError::contract(
                "cmdline",
                format!(
                    "configured architecture {expected_oci_architecture:?} does not match this {} build",
                    compile_oci_architecture()
                ),
            ));
        }

        let expected_page_size =
            parse_page_size(required(&values, "pocket.builder.expected_page_size")?)?;
        let requested_memory =
            parse_decimal_memory(required(&values, "pocket.builder.expected_memory_bytes")?)?;

        let cpu_state_hwcap_policy = values
            .get("pocket.builder.cpu_state_hwcap_policy")
            .copied()
            .or(option_env!("POCKET_BUILDER_CPU_STATE_HWCAP_POLICY"))
            .ok_or_else(|| {
                BuilderError::contract(
                    "cmdline",
                    "missing required pocket.builder.cpu_state_hwcap_policy",
                )
            })?;
        validate_token(
            "pocket.builder.cpu_state_hwcap_policy",
            cpu_state_hwcap_policy,
        )?;
        let root_layout = value_or(&values, "pocket.builder.root_layout", "pocket-root-v1");
        let filesystem_contract = value_or(
            &values,
            "pocket.builder.filesystem_contract",
            "ext4-v1-b4096",
        );
        validate_token("pocket.builder.root_layout", root_layout)?;
        validate_token("pocket.builder.filesystem_contract", filesystem_contract)?;
        let manifest_schema = value_or(
            &values,
            "pocket.builder.manifest_schema",
            "pocket-fs-manifest-v1",
        );
        validate_token("pocket.builder.manifest_schema", manifest_schema)?;

        Ok(Self {
            control_path: control_path.to_owned(),
            guest_contract_id,
            init_build_id,
            kernel_build_id,
            expected_oci_architecture: expected_oci_architecture.to_owned(),
            expected_page_size,
            expected_physmem_bytes: requested_memory,
            cpu_state_hwcap_policy: cpu_state_hwcap_policy.to_owned(),
            expected_root_layout: root_layout.to_owned(),
            expected_filesystem_contract: filesystem_contract.to_owned(),
            expected_manifest_schema: manifest_schema.to_owned(),
        })
    }
}

const KNOWN_KEYS: &[&str] = &[
    "pocket.builder.control",
    "pocket.builder.cpu_state_hwcap_policy",
    "pocket.builder.expected_architecture",
    "pocket.builder.expected_cpus",
    "pocket.builder.expected_page_size",
    "pocket.builder.expected_memory_bytes",
    "pocket.builder.filesystem_contract",
    "pocket.builder.guest_contract_id",
    "pocket.builder.init_build_id",
    "pocket.builder.kernel_build_id",
    "pocket.builder.manifest_schema",
    "pocket.builder.root_layout",
];

fn value_or<'a>(values: &BTreeMap<&str, &'a str>, key: &str, fallback: &'a str) -> &'a str {
    values.get(key).copied().unwrap_or(fallback)
}

fn required<'a>(
    values: &BTreeMap<&str, &'a str>,
    key: &'static str,
) -> Result<&'a str, BuilderError> {
    values
        .get(key)
        .copied()
        .ok_or_else(|| BuilderError::contract("cmdline", format!("missing required {key}")))
}

fn required_identity(
    values: &BTreeMap<&str, &str>,
    key: &'static str,
    compile_value: Option<&'static str>,
) -> Result<String, BuilderError> {
    let value = values.get(key).copied().or(compile_value).ok_or_else(|| {
        BuilderError::contract(
            "cmdline",
            format!("missing required non-circular identity {key}"),
        )
    })?;
    validate_sha256(key, value)?;
    Ok(value.to_owned())
}

fn parse_page_size(value: &str) -> Result<u32, BuilderError> {
    let parsed = value.parse::<u32>().map_err(|_| {
        BuilderError::contract("cmdline", "expected page size is not an unsigned integer")
    })?;
    if !(4096..=65536).contains(&parsed) || !parsed.is_power_of_two() {
        return Err(BuilderError::contract(
            "cmdline",
            "expected page size must be a supported power of two",
        ));
    }
    Ok(parsed)
}

fn parse_decimal_memory(value: &str) -> Result<u64, BuilderError> {
    let bytes = value.parse::<u64>().map_err(|_| {
        BuilderError::contract("cmdline", "expected physical memory must be decimal bytes")
    })?;
    validate_memory(bytes)?;
    Ok(bytes)
}

fn validate_memory(bytes: u64) -> Result<(), BuilderError> {
    const MINIMUM: u64 = 64 * 1024 * 1024;
    const MAXIMUM: u64 = 1024 * 1024 * 1024 * 1024;
    if !(MINIMUM..=MAXIMUM).contains(&bytes) || !bytes.is_multiple_of(4096) {
        return Err(BuilderError::contract(
            "cmdline",
            "builder memory must be 64 MiB..=1 TiB and 4096-byte aligned",
        ));
    }
    Ok(())
}

fn validate_absolute_path(field: &'static str, value: &str) -> Result<(), BuilderError> {
    if !value.starts_with('/')
        || value == "/"
        || value.contains('\0')
        || value
            .split('/')
            .skip(1)
            .any(|part| part.is_empty() || matches!(part, "." | ".."))
    {
        return Err(BuilderError::contract(
            "cmdline",
            format!("{field} must be a normalized non-root absolute path"),
        ));
    }
    Ok(())
}

fn validate_sha256(field: &'static str, value: &str) -> Result<(), BuilderError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(BuilderError::contract(
            "cmdline",
            format!("{field} must be 64 lowercase hexadecimal characters"),
        ));
    }
    Ok(())
}

fn validate_token(field: &'static str, value: &str) -> Result<(), BuilderError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(BuilderError::contract(
            "cmdline",
            format!("{field} is not a bounded identifier"),
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
    use super::BuilderConfig;

    const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const C: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    fn valid() -> String {
        format!(
            "pocket.builder.expected_cpus=1 pocket.builder.expected_memory_bytes={} \
             pocket.builder.expected_page_size=4096 \
             pocket.builder.cpu_state_hwcap_policy=native-x86_64-v1 \
             pocket.builder.guest_contract_id={A} pocket.builder.init_build_id={B} \
             pocket.builder.kernel_build_id={C}",
            768 * 1024 * 1024
        )
    }

    #[test]
    fn parses_bounded_single_cpu_memory_contract() {
        let config = BuilderConfig::parse_cmdline(&valid()).expect("valid config");
        assert_eq!(config.expected_physmem_bytes, 768 * 1024 * 1024);
        assert_eq!(config.expected_page_size, 4096);
        assert_eq!(config.control_path, "/dev/ttyS0");
    }

    #[test]
    fn rejects_unknown_duplicate_and_multi_cpu_contracts() {
        assert!(
            BuilderConfig::parse_cmdline(&format!("{} pocket.builder.unknown=x", valid())).is_err()
        );
        assert!(
            BuilderConfig::parse_cmdline(&valid().replace(
                "pocket.builder.expected_cpus=1",
                "pocket.builder.expected_cpus=2"
            ))
            .is_err()
        );
    }

    #[test]
    fn models_consumed_uml_tokens_and_requires_guest_visible_aliases() {
        let without_memory = valid()
            .split_ascii_whitespace()
            .filter(|token| !token.starts_with("pocket.builder.expected_memory_bytes="))
            .collect::<Vec<_>>()
            .join(" ");
        assert!(BuilderConfig::parse_cmdline(&without_memory).is_err());
        let without_cpus = valid()
            .split_ascii_whitespace()
            .filter(|token| !token.starts_with("pocket.builder.expected_cpus="))
            .collect::<Vec<_>>()
            .join(" ");
        assert!(BuilderConfig::parse_cmdline(&without_cpus).is_err());

        // Non-Pocket tokens are generic kernel arguments. The aliases, not
        // any literal UML-only token, are the measured guest contract.
        assert!(BuilderConfig::parse_cmdline(&format!("mem=1M ncpus=64 {}", valid())).is_ok());
    }
}
