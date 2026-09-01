use std::{collections::BTreeMap, path::Path};

use crate::InitError;

const DEFAULT_CONTROL: &str = "/dev/ttyS0";
const DEFAULT_STDIN: &str = "/dev/ttyS1";
const DEFAULT_STDOUT: &str = "/dev/ttyS2";
const DEFAULT_STDERR: &str = "/dev/ttyS3";
const DEFAULT_ROOT_DEVICE: &str = "/dev/ubda";
const DEFAULT_VOLUME: &str = "/volume";
const DEFAULT_NEWROOT: &str = "/newroot";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TtyPaths {
    pub control: String,
    pub stdin: String,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestConfig {
    pub ttys: TtyPaths,
    pub root_device: String,
    pub volume_mount: String,
    pub newroot_mount: String,
    pub guest_contract_id: String,
    pub init_build_id: String,
    pub kernel_build_id: String,
    pub expected_cpus: u16,
    pub expected_memory_bytes: u64,
    pub expected_oci_architecture: String,
    pub cpu_state_hwcap_policy: String,
    pub guest_capability_policy: String,
    pub expected_root_layout: String,
    pub expected_filesystem_contract: String,
}

impl GuestConfig {
    /// Parse Pocket parameters from `/proc/cmdline`.
    ///
    /// Values deliberately cannot contain whitespace. Duplicate Pocket keys
    /// are rejected rather than using last-one-wins semantics. Build IDs may
    /// alternatively be injected at compile time using the corresponding
    /// `POCKET_*_BUILD_ID` environment variable.
    pub fn parse_cmdline(cmdline: &str) -> Result<Self, InitError> {
        let mut values = BTreeMap::<&str, &str>::new();
        for token in cmdline.split_ascii_whitespace() {
            if token.starts_with("ncpus=") || token.starts_with("mem=") {
                return Err(InitError::contract(
                    "cmdline",
                    "UML-only ncpus/mem option unexpectedly leaked into guest cmdline",
                ));
            }
            let Some((key, value)) = token.split_once('=') else {
                continue;
            };
            if key.starts_with("pocket.") && values.insert(key, value).is_some() {
                return Err(InitError::contract(
                    "cmdline",
                    format!("duplicate {key} parameter"),
                ));
            }
        }
        for key in values.keys() {
            if !KNOWN_POCKET_KEYS.contains(key) {
                return Err(InitError::contract(
                    "cmdline",
                    format!("unknown Pocket kernel parameter {key}"),
                ));
            }
        }

        let ttys = TtyPaths {
            control: value_or(&values, "pocket.control", DEFAULT_CONTROL).to_owned(),
            stdin: value_or(&values, "pocket.stdin", DEFAULT_STDIN).to_owned(),
            stdout: value_or(&values, "pocket.stdout", DEFAULT_STDOUT).to_owned(),
            stderr: value_or(&values, "pocket.stderr", DEFAULT_STDERR).to_owned(),
        };
        validate_ttys(&ttys)?;

        let root_device = value_or(&values, "pocket.root_device", DEFAULT_ROOT_DEVICE).to_owned();
        let volume_mount = value_or(&values, "pocket.volume", DEFAULT_VOLUME).to_owned();
        let newroot_mount = value_or(&values, "pocket.newroot", DEFAULT_NEWROOT).to_owned();
        for (field, path) in [
            ("pocket.root_device", root_device.as_str()),
            ("pocket.volume", volume_mount.as_str()),
            ("pocket.newroot", newroot_mount.as_str()),
        ] {
            validate_absolute_path(field, path)?;
        }
        if volume_mount == newroot_mount {
            return Err(InitError::contract(
                "cmdline",
                "volume and newroot mount points must differ",
            ));
        }

        let guest_contract_id = required_identity(
            &values,
            "pocket.guest_contract_id",
            option_env!("POCKET_GUEST_CONTRACT_ID"),
        )?;
        let init_build_id = required_identity(
            &values,
            "pocket.init_build_id",
            option_env!("POCKET_INIT_BUILD_ID"),
        )?;
        let kernel_build_id = required_identity(
            &values,
            "pocket.kernel_build_id",
            option_env!("POCKET_KERNEL_BUILD_ID"),
        )?;

        let expected_cpus =
            parse_cpu_count(values.get("pocket.expected_cpus").copied().ok_or_else(|| {
                InitError::contract("cmdline", "missing required pocket.expected_cpus parameter")
            })?)?;
        let expected_memory_bytes = parse_memory_bytes(
            values
                .get("pocket.expected_memory_bytes")
                .copied()
                .ok_or_else(|| {
                    InitError::contract(
                        "cmdline",
                        "missing required pocket.expected_memory_bytes parameter",
                    )
                })?,
        )?;
        let cpu_state_hwcap_policy = required_policy_identity(
            &values,
            "pocket.cpu_state_hwcap_policy",
            option_env!("POCKET_CPU_STATE_HWCAP_POLICY"),
        )?;
        let guest_capability_policy = required_policy_identity(
            &values,
            "pocket.guest_capability_policy",
            option_env!("POCKET_GUEST_CAPABILITY_POLICY"),
        )?;

        let expected_oci_architecture = value_or(
            &values,
            "pocket.expected_architecture",
            compile_oci_architecture(),
        )
        .to_owned();
        if expected_oci_architecture != compile_oci_architecture() {
            return Err(InitError::contract(
                "cmdline",
                format!(
                    "configured architecture {expected_oci_architecture:?} does not match this {} build",
                    compile_oci_architecture()
                ),
            ));
        }

        Ok(Self {
            ttys,
            root_device,
            volume_mount,
            newroot_mount,
            guest_contract_id,
            init_build_id,
            kernel_build_id,
            expected_cpus,
            expected_memory_bytes,
            expected_oci_architecture,
            cpu_state_hwcap_policy,
            guest_capability_policy,
            expected_root_layout: value_or(&values, "pocket.root_layout", "pocket-root-v1")
                .to_owned(),
            expected_filesystem_contract: value_or(
                &values,
                "pocket.filesystem_contract",
                "ext4-v1-b4096",
            )
            .to_owned(),
        })
    }

    #[must_use]
    pub fn image_root(&self) -> String {
        format!("{}/rootfs", self.volume_mount)
    }

    #[must_use]
    pub fn generation_marker_path(&self) -> String {
        format!("{}/.pocket-generation.cbor", self.volume_mount)
    }
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

fn value_or<'a>(values: &BTreeMap<&str, &'a str>, key: &str, fallback: &'a str) -> &'a str {
    values.get(key).copied().unwrap_or(fallback)
}

fn required_identity(
    values: &BTreeMap<&str, &str>,
    key: &'static str,
    compile_value: Option<&'static str>,
) -> Result<String, InitError> {
    let value = values.get(key).copied().or(compile_value).ok_or_else(|| {
        InitError::contract(
            "cmdline",
            format!("missing required non-circular identity {key}"),
        )
    })?;
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(InitError::contract(
            "cmdline",
            format!("{key} must be 64 lowercase hexadecimal characters"),
        ));
    }
    Ok(value.to_owned())
}

fn parse_cpu_count(value: &str) -> Result<u16, InitError> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(InitError::contract(
            "cmdline",
            "expected CPU count must be an unsigned decimal integer",
        ));
    }
    let parsed = value
        .parse::<u16>()
        .map_err(|_| InitError::contract("cmdline", "expected CPU count does not fit in u16"))?;
    if !(1..=64).contains(&parsed) {
        return Err(InitError::contract(
            "cmdline",
            "expected CPU count must be in 1..=64",
        ));
    }
    Ok(parsed)
}

fn parse_memory_bytes(value: &str) -> Result<u64, InitError> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(InitError::contract(
            "cmdline",
            "expected memory must be an unsigned decimal byte count",
        ));
    }
    let parsed = value.parse::<u64>().map_err(|_| {
        InitError::contract("cmdline", "expected memory byte count does not fit in u64")
    })?;
    if parsed == 0 || !parsed.is_multiple_of(4096) {
        return Err(InitError::contract(
            "cmdline",
            "expected memory must be nonzero and 4096-byte aligned",
        ));
    }
    Ok(parsed)
}

fn required_policy_identity(
    values: &BTreeMap<&str, &str>,
    key: &'static str,
    compile_value: Option<&'static str>,
) -> Result<String, InitError> {
    let value = values.get(key).copied().or(compile_value).ok_or_else(|| {
        InitError::contract("cmdline", format!("missing required policy identity {key}"))
    })?;
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(InitError::contract(
            "cmdline",
            format!("{key} must be a 1..=128 byte ASCII policy token"),
        ));
    }
    Ok(value.to_owned())
}

fn validate_ttys(ttys: &TtyPaths) -> Result<(), InitError> {
    let fields = [
        ("pocket.control", ttys.control.as_str()),
        ("pocket.stdin", ttys.stdin.as_str()),
        ("pocket.stdout", ttys.stdout.as_str()),
        ("pocket.stderr", ttys.stderr.as_str()),
    ];
    for (field, path) in fields {
        validate_absolute_path(field, path)?;
    }
    let paths = [&ttys.control, &ttys.stdin, &ttys.stdout, &ttys.stderr];
    for (index, path) in paths.iter().enumerate() {
        if paths[..index].contains(path) {
            return Err(InitError::contract(
                "cmdline",
                "control and standard-stream TTY paths must be distinct",
            ));
        }
    }
    Ok(())
}

fn validate_absolute_path(field: &str, value: &str) -> Result<(), InitError> {
    if value.len() > 4096 || value.contains('\0') || !Path::new(value).is_absolute() {
        return Err(InitError::contract(
            "cmdline",
            format!("{field} must be an absolute path without NUL"),
        ));
    }
    let relative = value.strip_prefix('/').unwrap_or_default();
    if relative.is_empty()
        || relative
            .split('/')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
    {
        return Err(InitError::contract(
            "cmdline",
            format!("{field} must use normalized lexical form"),
        ));
    }
    Ok(())
}

const KNOWN_POCKET_KEYS: &[&str] = &[
    "pocket.control",
    "pocket.stdin",
    "pocket.stdout",
    "pocket.stderr",
    "pocket.root_device",
    "pocket.volume",
    "pocket.newroot",
    "pocket.guest_contract_id",
    "pocket.init_build_id",
    "pocket.kernel_build_id",
    "pocket.expected_cpus",
    "pocket.expected_memory_bytes",
    "pocket.expected_architecture",
    "pocket.cpu_state_hwcap_policy",
    "pocket.guest_capability_policy",
    "pocket.root_layout",
    "pocket.filesystem_contract",
];

#[cfg(test)]
mod tests {
    use super::GuestConfig;

    const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const C: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    fn valid_cmdline() -> String {
        format!(
            "quiet pocket.expected_cpus=4 pocket.expected_memory_bytes=268435456 pocket.cpu_state_hwcap_policy=native-x86_64-v1 pocket.guest_capability_policy=fixed-capabilities-v1 pocket.guest_contract_id={A} pocket.init_build_id={B} pocket.kernel_build_id={C}"
        )
    }

    #[test]
    fn parses_guest_visible_cpu_and_memory_contract() {
        let config = match GuestConfig::parse_cmdline(&valid_cmdline()) {
            Ok(config) => config,
            Err(error) => panic!("valid cmdline rejected: {error}"),
        };
        assert_eq!(config.expected_cpus, 4);
        assert_eq!(config.ttys.control, "/dev/ttyS0");
        assert_eq!(config.image_root(), "/volume/rootfs");
        assert_eq!(config.expected_oci_architecture, "amd64");
        assert_eq!(config.expected_memory_bytes, 256 * 1024 * 1024);
        assert_eq!(config.cpu_state_hwcap_policy, "native-x86_64-v1");
        assert_eq!(config.guest_capability_policy, "fixed-capabilities-v1");
    }

    #[test]
    fn requires_aliases_and_rejects_consumed_uml_tokens() {
        assert!(
            GuestConfig::parse_cmdline(&valid_cmdline().replace("pocket.expected_cpus=4 ", ""))
                .is_err()
        );
        assert!(GuestConfig::parse_cmdline(&format!("{} ncpus=4", valid_cmdline())).is_err());
        assert!(GuestConfig::parse_cmdline(&format!("{} mem=256M", valid_cmdline())).is_err());
    }

    #[test]
    fn rejects_missing_ids_duplicates_and_aliasing_ttys() {
        assert!(GuestConfig::parse_cmdline("pocket.expected_cpus=2").is_err());
        assert!(
            GuestConfig::parse_cmdline(&format!("{} pocket.expected_cpus=2", valid_cmdline()))
                .is_err()
        );
        assert!(
            GuestConfig::parse_cmdline(&format!("{} pocket.stdin=/dev/ttyS0", valid_cmdline()))
                .is_err()
        );
        assert!(
            GuestConfig::parse_cmdline(&format!("{} pocket.stidn=/dev/ttyS1", valid_cmdline()))
                .is_err()
        );
    }

    #[test]
    fn rejects_malformed_cpu_and_paths() {
        for cpu in ["0", "65", "-1", "+1", "65536"] {
            assert!(
                GuestConfig::parse_cmdline(&format!(
                    "{} pocket.expected_cpus={cpu}",
                    valid_cmdline()
                ))
                .is_err()
            );
        }
        assert!(
            GuestConfig::parse_cmdline(&format!("{} pocket.volume=/a/../b", valid_cmdline()))
                .is_err()
        );
        for memory in ["0", "4097", "-1", "64M", "18446744073709551616"] {
            let cmdline = valid_cmdline().replace(
                "pocket.expected_memory_bytes=268435456",
                &format!("pocket.expected_memory_bytes={memory}"),
            );
            assert!(GuestConfig::parse_cmdline(&cmdline).is_err());
        }
    }
}
