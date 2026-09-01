use pocket_oci::{DockerProcessConfig, VerifyLimits, parse_image_process_config_with_limits};
use pocket_protocol::{
    AccountDatabase, AccountDb, AccountUser, MAX_ACCOUNT_DB_BYTES, MAX_ORIGINAL_USER_LENGTH,
    UserResolution, ValidateMessage,
};
use pocket_store::{Digest, Lease};

use crate::RuntimeError;

const IMAGE_CONFIG_SIDECAR: &str = "image-config.json";
const ACCOUNT_DATABASE_SIDECAR: &str = "accounts.cbor";
const DEFAULT_STOP_SIGNAL: u16 = 15;
const DEFAULT_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// How positional arguments participate in Docker image-command resolution.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum ImageArgv {
    /// Use the image's Entrypoint followed by its Cmd.
    #[default]
    Default,
    /// Preserve the selected Entrypoint and replace the image Cmd.
    ReplaceCmd(Vec<String>),
    /// Bypass Entrypoint/Cmd merging and use these complete argv bytes.
    Exact(Vec<String>),
}

/// Supported per-run overrides for an authenticated image configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageProcessOverrides {
    pub argv: ImageArgv,
    /// Any `Some` value replaces Entrypoint and clears the image Cmd, matching
    /// Docker; `Some([])` explicitly clears Entrypoint too.
    pub entrypoint: Option<Vec<String>>,
    pub env: Vec<String>,
    /// Hostname already selected for the workload's UTS namespace. Docker's
    /// Linux process environment exposes the same value as `HOSTNAME`.
    pub hostname: String,
    pub user: Option<String>,
    pub working_dir: Option<String>,
    pub stop_signal: Option<String>,
}

impl Default for ImageProcessOverrides {
    fn default() -> Self {
        Self {
            argv: ImageArgv::Default,
            entrypoint: None,
            env: Vec::new(),
            hostname: "pocket".to_owned(),
            user: None,
            working_dir: None,
            stop_signal: None,
        }
    }
}

/// Fully numeric and directly executable process defaults resolved under one
/// immutable-generation lease.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedImageProcess {
    pub argv: Vec<String>,
    pub env: Vec<String>,
    pub working_dir: String,
    pub user: UserResolution,
    pub stop_signal: u16,
}

/// Read the authenticated image configuration and canonical account database
/// from one already verified lease, then apply deterministic Docker-compatible
/// process overrides.
pub fn resolve_image_process(
    lease: &Lease,
    overrides: &ImageProcessOverrides,
) -> Result<ResolvedImageProcess, RuntimeError> {
    let limits = VerifyLimits::default();
    let config_bytes = lease.read_sidecar(IMAGE_CONFIG_SIDECAR, limits.max_config_bytes)?;
    let observed_config_digest = Digest::of_bytes(&config_bytes);
    let expected_config_digest = lease.generation().manifest().spec().config_digest();
    if observed_config_digest != expected_config_digest {
        return Err(RuntimeError::GenerationMismatch {
            field: "image_config.digest",
            expected: expected_config_digest.to_string(),
            actual: observed_config_digest.to_string(),
        });
    }
    let config = parse_image_process_config_with_limits(&config_bytes, &limits)
        .map_err(RuntimeError::ImageConfig)?;

    let maximum_account_bytes =
        u64::try_from(MAX_ACCOUNT_DB_BYTES).expect("account database bound fits u64");
    let account_bytes = lease.read_sidecar(ACCOUNT_DATABASE_SIDECAR, maximum_account_bytes)?;
    let account_db = AccountDb::from_canonical_bytes(account_bytes)?;
    let accounts = account_db.decode_database()?;
    resolve_verified_process(&config, &accounts, overrides)
}

fn resolve_verified_process(
    config: &DockerProcessConfig,
    accounts: &AccountDatabase,
    overrides: &ImageProcessOverrides,
) -> Result<ResolvedImageProcess, RuntimeError> {
    accounts.validate()?;
    let argv = resolve_argv(config, overrides)?;
    let env = merge_environment(&config.env, &overrides.env, &overrides.hostname)?;
    let working_dir = overrides
        .working_dir
        .clone()
        .unwrap_or_else(|| config.working_dir.clone());
    let user = resolve_user(
        accounts,
        overrides.user.as_deref().unwrap_or(config.user.as_str()),
    )?;
    let stop_signal = match overrides
        .stop_signal
        .as_deref()
        .or(config.stop_signal.as_deref())
    {
        Some(signal) => parse_signal(signal)?,
        None => DEFAULT_STOP_SIGNAL,
    };
    Ok(ResolvedImageProcess {
        argv,
        env,
        working_dir,
        user,
        stop_signal,
    })
}

fn resolve_argv(
    config: &DockerProcessConfig,
    overrides: &ImageProcessOverrides,
) -> Result<Vec<String>, RuntimeError> {
    let mut argv = match &overrides.argv {
        ImageArgv::Exact(argv) => {
            if overrides.entrypoint.is_some() {
                return Err(RuntimeError::invalid(
                    "image.argv",
                    "an Entrypoint override cannot be combined with exact argv mode",
                ));
            }
            argv.clone()
        }
        ImageArgv::Default | ImageArgv::ReplaceCmd(_) => {
            let entrypoint = overrides.entrypoint.as_ref().unwrap_or(&config.entrypoint);
            let cmd = match &overrides.argv {
                // Docker's explicit --entrypoint resets the image Cmd. A
                // positional command remains a replacement Cmd and is
                // appended below.
                ImageArgv::Default if overrides.entrypoint.is_some() => &[],
                ImageArgv::Default => config.cmd.as_slice(),
                ImageArgv::ReplaceCmd(cmd) => cmd,
                ImageArgv::Exact(_) => unreachable!("handled above"),
            };
            let capacity = entrypoint.len().checked_add(cmd.len()).ok_or_else(|| {
                RuntimeError::invalid("image.argv", "Entrypoint and Cmd length overflows")
            })?;
            let mut argv = Vec::with_capacity(capacity);
            argv.extend(entrypoint.iter().cloned());
            argv.extend(cmd.iter().cloned());
            argv
        }
    };
    if argv.is_empty() {
        return Err(RuntimeError::invalid(
            "image.argv",
            "image Entrypoint/Cmd and run overrides produce an empty final argv",
        ));
    }
    if argv[0].is_empty() {
        return Err(RuntimeError::invalid(
            "image.argv",
            "final argv[0] must not be empty",
        ));
    }
    for value in &argv {
        if value.contains('\0') {
            return Err(RuntimeError::invalid(
                "image.argv",
                "final argv contains NUL",
            ));
        }
    }
    // Do not retain spare capacity derived from attacker-controlled counts in
    // the long-lived run options.
    argv.shrink_to_fit();
    Ok(argv)
}

fn merge_environment(
    image: &[String],
    overrides: &[String],
    hostname: &str,
) -> Result<Vec<String>, RuntimeError> {
    let mut merged = vec![
        format!("PATH={DEFAULT_PATH}"),
        format!("HOSTNAME={hostname}"),
    ];

    // Moby begins with daemon defaults and applies image Env as overrides.
    // Preserve non-default image entries (including their duplicate-key
    // ordering), while PATH/HOSTNAME replace their daemon-default slots.
    for value in image {
        let key = environment_key(value)?;
        if matches!(key, "PATH" | "HOSTNAME") {
            let index = merged
                .iter()
                .rposition(|candidate| environment_key_unchecked(candidate) == key)
                .expect("PATH and HOSTNAME defaults are present");
            merged[index] = value.clone();
        } else {
            merged.push(value.clone());
        }
    }

    // CLI entries override the final matching image/default entry in place,
    // or append a new key. Repeated CLI overrides therefore have a stable
    // last-value-wins result.
    for value in overrides {
        let key = environment_key(value)?;
        if let Some(index) = merged
            .iter()
            .rposition(|candidate| environment_key_unchecked(candidate) == key)
        {
            merged[index] = value.clone();
        } else {
            merged.push(value.clone());
        }
    }
    Ok(merged)
}

fn environment_key(value: &str) -> Result<&str, RuntimeError> {
    if value.contains('\0') {
        return Err(RuntimeError::invalid(
            "image.env",
            "environment entry contains NUL",
        ));
    }
    let (key, _) = value
        .split_once('=')
        .ok_or_else(|| RuntimeError::invalid("image.env", "environment entry must contain '='"))?;
    if key.is_empty() {
        return Err(RuntimeError::invalid(
            "image.env",
            "environment key must not be empty",
        ));
    }
    Ok(key)
}

fn environment_key_unchecked(value: &str) -> &str {
    value.split_once('=').map_or(value, |(key, _value)| key)
}

fn resolve_user(
    database: &AccountDatabase,
    original: &str,
) -> Result<UserResolution, RuntimeError> {
    if original.is_empty()
        || original.len() > MAX_ORIGINAL_USER_LENGTH
        || original.contains(['\0', '\n', '\r'])
    {
        return Err(RuntimeError::invalid(
            "image.user",
            "User is empty, oversized, or contains a forbidden byte",
        ));
    }
    let mut parts = original.split(':');
    let user_part = parts.next().unwrap_or_default();
    let group_part = parts.next();
    if parts.next().is_some() || user_part.is_empty() || group_part == Some("") {
        return Err(RuntimeError::invalid(
            "image.user",
            "User must be user-or-uid with at most one nonempty group suffix",
        ));
    }

    let numeric_user = parse_optional_id(user_part, "user")?;
    let (uid, default_gid, username, kind) = if let Some(uid) = numeric_user {
        if let Some(record) = find_unique_user(
            database.users.iter().filter(|record| record.uid == uid),
            "numeric user ID",
        )? {
            (uid, record.gid, Some(record.name.as_str()), 1)
        } else {
            (uid, 0, None, 1)
        }
    } else {
        validate_account_name(user_part, "user")?;
        let record = database
            .users
            .binary_search_by(|record| record.name.as_str().cmp(user_part))
            .ok()
            .map(|index| &database.users[index])
            .ok_or_else(|| {
                RuntimeError::invalid(
                    "image.user",
                    format!("named user {user_part:?} was not found"),
                )
            })?;
        (record.uid, record.gid, Some(record.name.as_str()), 2)
    };

    let gid = match group_part {
        None => default_gid,
        Some(group) => match parse_optional_id(group, "group")? {
            Some(gid) => gid,
            None => {
                validate_account_name(group, "group")?;
                database
                    .groups
                    .binary_search_by(|record| record.name.as_str().cmp(group))
                    .ok()
                    .map(|index| database.groups[index].gid)
                    .ok_or_else(|| {
                        RuntimeError::invalid(
                            "image.user",
                            format!("named group {group:?} was not found"),
                        )
                    })?
            }
        },
    };

    let mut supplementary_gids = if group_part.is_none()
        && let Some(username) = username
    {
        database
            .groups
            .iter()
            .filter(|group| {
                group
                    .members
                    .binary_search_by(|member| member.as_str().cmp(username))
                    .is_ok()
            })
            .map(|group| group.gid)
            .collect()
    } else {
        Vec::new()
    };
    supplementary_gids.retain(|candidate| *candidate != gid);
    supplementary_gids.sort_unstable();
    supplementary_gids.dedup();
    if supplementary_gids.len() > 64 {
        return Err(RuntimeError::invalid(
            "image.user",
            "resolved supplementary group count exceeds 64",
        ));
    }

    Ok(UserResolution {
        kind,
        uid,
        gid,
        supplementary_gids,
    })
}

fn find_unique_user<'a>(
    mut matches: impl Iterator<Item = &'a AccountUser>,
    match_kind: &'static str,
) -> Result<Option<&'a AccountUser>, RuntimeError> {
    let found = matches.next();
    if found.is_some() && matches.next().is_some() {
        return Err(RuntimeError::invalid(
            "image.user",
            format!("account database has multiple entries matching {match_kind}"),
        ));
    }
    Ok(found)
}

fn parse_optional_id(value: &str, field: &'static str) -> Result<Option<u32>, RuntimeError> {
    if !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Ok(None);
    }
    if value.is_empty() {
        return Err(RuntimeError::invalid(
            "image.user",
            format!("{field} is empty"),
        ));
    }
    value.parse::<u32>().map(Some).map_err(|_| {
        RuntimeError::invalid("image.user", format!("numeric {field} does not fit u32"))
    })
}

fn validate_account_name(value: &str, field: &'static str) -> Result<(), RuntimeError> {
    if value.is_empty()
        || value.len() > 256
        || value
            .bytes()
            .any(|byte| byte <= b' ' || matches!(byte, b':' | b',' | 0x7f))
    {
        return Err(RuntimeError::invalid(
            "image.user",
            format!("{field} name has invalid bytes"),
        ));
    }
    Ok(())
}

/// Parse Docker's numeric or conventional Linux signal spelling without
/// consulting the host libc's process-specific signal-name tables.
pub fn parse_image_signal(value: &str) -> Result<u16, RuntimeError> {
    parse_signal(value)
}

fn parse_signal(value: &str) -> Result<u16, RuntimeError> {
    if value.is_empty() || !value.is_ascii() {
        return Err(RuntimeError::invalid(
            "image.stop_signal",
            "signal must be nonempty ASCII",
        ));
    }
    if value.bytes().all(|byte| byte.is_ascii_digit()) {
        let signal = value.parse::<u16>().map_err(|_| {
            RuntimeError::invalid("image.stop_signal", "numeric signal does not fit u16")
        })?;
        return valid_signal(signal);
    }
    let uppercase = value.to_ascii_uppercase();
    let name = uppercase.strip_prefix("SIG").unwrap_or(&uppercase);
    let signal = match name {
        "HUP" => 1,
        "INT" => 2,
        "QUIT" => 3,
        "ILL" => 4,
        "TRAP" => 5,
        "ABRT" | "IOT" => 6,
        "BUS" => 7,
        "FPE" => 8,
        "KILL" => 9,
        "USR1" => 10,
        "SEGV" => 11,
        "USR2" => 12,
        "PIPE" => 13,
        "ALRM" => 14,
        "TERM" => 15,
        "STKFLT" => 16,
        "CHLD" | "CLD" => 17,
        "CONT" => 18,
        "STOP" => 19,
        "TSTP" => 20,
        "TTIN" => 21,
        "TTOU" => 22,
        "URG" => 23,
        "XCPU" => 24,
        "XFSZ" => 25,
        "VTALRM" => 26,
        "PROF" => 27,
        "WINCH" => 28,
        "IO" | "POLL" => 29,
        "PWR" => 30,
        "SYS" => 31,
        "RTMIN" => 34,
        "RTMAX" => 64,
        _ => {
            if let Some(offset) = name.strip_prefix("RTMIN+") {
                let offset = parse_realtime_offset(offset)?;
                let signal = 34_u16.checked_add(offset).ok_or_else(|| {
                    RuntimeError::invalid("image.stop_signal", "realtime signal overflows")
                })?;
                valid_realtime_signal(signal)?
            } else if let Some(offset) = name.strip_prefix("RTMAX-") {
                let offset = parse_realtime_offset(offset)?;
                let signal = 64_u16.checked_sub(offset).ok_or_else(|| {
                    RuntimeError::invalid("image.stop_signal", "realtime signal underflows")
                })?;
                valid_realtime_signal(signal)?
            } else {
                return Err(RuntimeError::invalid(
                    "image.stop_signal",
                    format!("unsupported Linux signal name {value:?}"),
                ));
            }
        }
    };
    valid_signal(signal)
}

fn valid_realtime_signal(signal: u16) -> Result<u16, RuntimeError> {
    if (34..=64).contains(&signal) {
        Ok(signal)
    } else {
        Err(RuntimeError::invalid(
            "image.stop_signal",
            "named realtime signal must resolve within RTMIN..=RTMAX (34..=64)",
        ))
    }
}

fn parse_realtime_offset(value: &str) -> Result<u16, RuntimeError> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(RuntimeError::invalid(
            "image.stop_signal",
            "realtime signal offset must be unsigned decimal",
        ));
    }
    value.parse::<u16>().map_err(|_| {
        RuntimeError::invalid(
            "image.stop_signal",
            "realtime signal offset does not fit u16",
        )
    })
}

fn valid_signal(signal: u16) -> Result<u16, RuntimeError> {
    if (1..=64).contains(&signal) {
        Ok(signal)
    } else {
        Err(RuntimeError::invalid(
            "image.stop_signal",
            "signal must resolve to a value in 1..=64",
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, io::Write as _};

    use pocket_core::ManagedUmlPath;
    use pocket_oci::DockerProcessConfig;
    use pocket_protocol::{ACCOUNT_DB_SCHEMA, AccountGroup};
    use pocket_store::{Digest, GenerationId, GenerationSpec, ImmutableSidecar, Platform, Store};
    use serde_json::json;
    use tempfile::TempDir;

    use super::*;

    fn config() -> DockerProcessConfig {
        DockerProcessConfig {
            entrypoint: vec!["/entry".to_owned()],
            cmd: vec!["default".to_owned()],
            argv: vec!["/entry".to_owned(), "default".to_owned()],
            env: vec![
                "A=old".to_owned(),
                "D=first".to_owned(),
                "D=last".to_owned(),
            ],
            working_dir: "/image".to_owned(),
            user: "app".to_owned(),
            labels: BTreeMap::new(),
            stop_signal: Some("SIGTERM".to_owned()),
        }
    }

    fn accounts() -> AccountDatabase {
        AccountDatabase {
            schema: ACCOUNT_DB_SCHEMA.to_owned(),
            users: vec![
                AccountUser {
                    name: "app".to_owned(),
                    uid: 123,
                    gid: 456,
                },
                AccountUser {
                    name: "other".to_owned(),
                    uid: 124,
                    gid: 457,
                },
                AccountUser {
                    name: "root".to_owned(),
                    uid: 0,
                    gid: 0,
                },
            ],
            groups: vec![
                AccountGroup {
                    name: "app".to_owned(),
                    gid: 456,
                    members: Vec::new(),
                },
                AccountGroup {
                    name: "extra".to_owned(),
                    gid: 789,
                    members: vec!["app".to_owned()],
                },
                AccountGroup {
                    name: "root".to_owned(),
                    gid: 0,
                    members: Vec::new(),
                },
            ],
        }
    }

    fn generation_spec(seed: u8, config_digest: Digest) -> GenerationSpec {
        let digest = |offset: u8| Digest::of_bytes(&[seed.wrapping_add(offset)]);
        let platform =
            || Platform::new("linux", "amd64", None, None, Vec::new()).expect("test platform");
        GenerationSpec::new(
            digest(0),
            config_digest,
            Vec::new(),
            Vec::new(),
            None,
            platform(),
            platform(),
            "native-amd64-v1",
            "x86_64-smp-p4k",
            digest(2),
            "rootfs-dir-v1",
            "ext4-v1-b4096",
            digest(3),
        )
        .expect("generation spec")
    }

    fn generation_with_sidecars(
        seed: u8,
        sidecars: &[(&str, &[u8])],
        config_digest_override: Option<Digest>,
    ) -> (TempDir, Store, GenerationId) {
        let temporary = tempfile::tempdir().expect("temporary store");
        let parent = temporary.path().join("pocket");
        std::fs::create_dir(&parent).expect("store parent");
        let store = Store::initialize(
            ManagedUmlPath::new(parent.join("store")).expect("managed store path"),
        )
        .expect("initialize store");
        let config_digest = config_digest_override.unwrap_or_else(|| {
            sidecars
                .iter()
                .find_map(|(name, bytes)| {
                    (*name == IMAGE_CONFIG_SIDECAR).then(|| Digest::of_bytes(bytes))
                })
                .unwrap_or_else(|| Digest::of_bytes(&[seed.wrapping_add(1)]))
        });
        let transaction = store
            .try_begin_rebuild(generation_spec(seed, config_digest))
            .expect("begin generation");
        let mut base = transaction.create_base().expect("create base");
        base.write_all(b"base").expect("write base");
        drop(base);
        let mut records = Vec::new();
        for (name, bytes) in sidecars {
            let mut file = transaction.create_sidecar(*name).expect("create sidecar");
            file.write_all(bytes).expect("write sidecar");
            drop(file);
            records.push(
                ImmutableSidecar::new(
                    *name,
                    Digest::of_bytes(bytes),
                    u64::try_from(bytes.len()).expect("sidecar size"),
                )
                .expect("sidecar record"),
            );
        }
        records.sort();
        let generation = transaction
            .publish_with_sidecars(Digest::of_bytes(b"base"), &records)
            .expect("publish generation");
        let id = generation.id();
        (temporary, store, id)
    }

    fn image_config_bytes() -> Vec<u8> {
        serde_json::to_vec(&json!({
            "architecture": "amd64",
            "os": "linux",
            "rootfs": {"type": "layers", "diff_ids": []},
            "config": {
                "Entrypoint": ["/entry"],
                "Cmd": ["default"],
                "Env": ["A=image"],
                "WorkingDir": "/image",
                "User": "app",
                "StopSignal": "SIGTERM"
            }
        }))
        .expect("image config JSON")
    }

    #[test]
    fn docker_argv_modes_are_explicit_and_empty_results_fail() {
        let image = config();
        let database = accounts();
        let defaults = resolve_verified_process(&image, &database, &Default::default())
            .expect("image defaults");
        assert_eq!(defaults.argv, ["/entry", "default"]);

        let replaced = resolve_verified_process(
            &image,
            &database,
            &ImageProcessOverrides {
                argv: ImageArgv::ReplaceCmd(vec!["cli".to_owned()]),
                ..Default::default()
            },
        )
        .expect("replace Cmd");
        assert_eq!(replaced.argv, ["/entry", "cli"]);

        let changed_entrypoint = resolve_verified_process(
            &image,
            &database,
            &ImageProcessOverrides {
                entrypoint: Some(vec!["/new-entry".to_owned()]),
                ..Default::default()
            },
        )
        .expect("replace Entrypoint");
        assert_eq!(changed_entrypoint.argv, ["/new-entry"]);

        assert!(
            resolve_verified_process(
                &image,
                &database,
                &ImageProcessOverrides {
                    entrypoint: Some(Vec::new()),
                    ..Default::default()
                },
            )
            .is_err()
        );

        let entrypoint_with_cli_cmd = resolve_verified_process(
            &image,
            &database,
            &ImageProcessOverrides {
                argv: ImageArgv::ReplaceCmd(vec!["cli".to_owned()]),
                entrypoint: Some(vec!["/new-entry".to_owned()]),
                ..Default::default()
            },
        )
        .expect("replace Entrypoint and Cmd");
        assert_eq!(entrypoint_with_cli_cmd.argv, ["/new-entry", "cli"]);

        let exact = resolve_verified_process(
            &image,
            &database,
            &ImageProcessOverrides {
                argv: ImageArgv::Exact(vec!["/exact".to_owned(), "arg".to_owned()]),
                ..Default::default()
            },
        )
        .expect("exact argv");
        assert_eq!(exact.argv, ["/exact", "arg"]);

        let empty_image = DockerProcessConfig {
            entrypoint: Vec::new(),
            cmd: Vec::new(),
            argv: Vec::new(),
            ..image.clone()
        };
        assert!(resolve_verified_process(&empty_image, &database, &Default::default()).is_err());
        let supplied = resolve_verified_process(
            &empty_image,
            &database,
            &ImageProcessOverrides {
                argv: ImageArgv::Exact(vec!["/bin/true".to_owned()]),
                ..Default::default()
            },
        )
        .expect("exact argv makes zero-default OCI config runnable");
        assert_eq!(supplied.argv, ["/bin/true"]);
        assert!(
            resolve_verified_process(
                &image,
                &database,
                &ImageProcessOverrides {
                    argv: ImageArgv::Exact(vec!["/exact".to_owned()]),
                    entrypoint: Some(vec!["/ignored".to_owned()]),
                    ..Default::default()
                }
            )
            .is_err()
        );
    }

    #[test]
    fn environment_overrides_replace_the_last_matching_image_key_in_place() {
        let resolved = resolve_verified_process(
            &config(),
            &accounts(),
            &ImageProcessOverrides {
                env: vec!["D=cli".to_owned(), "B=new".to_owned(), "D=final".to_owned()],
                hostname: "guest-one".to_owned(),
                ..Default::default()
            },
        )
        .expect("merge environment");
        assert_eq!(
            resolved.env,
            [
                format!("PATH={DEFAULT_PATH}"),
                "HOSTNAME=guest-one".to_owned(),
                "A=old".to_owned(),
                "D=first".to_owned(),
                "D=final".to_owned(),
                "B=new".to_owned(),
            ]
        );
    }

    #[test]
    fn docker_environment_defaults_are_visible_and_replaceable_in_order() {
        let mut image = config();
        image.env.clear();
        let defaults = resolve_verified_process(
            &image,
            &accounts(),
            &ImageProcessOverrides {
                hostname: "configured-host".to_owned(),
                ..Default::default()
            },
        )
        .expect("daemon environment defaults");
        assert_eq!(
            defaults.env,
            [
                format!("PATH={DEFAULT_PATH}"),
                "HOSTNAME=configured-host".to_owned(),
            ]
        );
        assert!(!defaults.env.iter().any(|value| value.starts_with("HOME=")));
        assert!(!defaults.env.iter().any(|value| value.starts_with("TERM=")));

        image.env = vec![
            "PATH=/image/bin".to_owned(),
            "HOSTNAME=image-host".to_owned(),
            "HOME=/image/home".to_owned(),
            "TERM=image-term".to_owned(),
        ];
        let image_values = resolve_verified_process(
            &image,
            &accounts(),
            &ImageProcessOverrides {
                hostname: "configured-host".to_owned(),
                ..Default::default()
            },
        )
        .expect("image overrides daemon defaults");
        assert_eq!(
            image_values.env,
            [
                "PATH=/image/bin",
                "HOSTNAME=image-host",
                "HOME=/image/home",
                "TERM=image-term",
            ]
        );

        let cli_values = resolve_verified_process(
            &image,
            &accounts(),
            &ImageProcessOverrides {
                env: vec!["PATH=/cli/bin".to_owned(), "HOSTNAME=cli-host".to_owned()],
                hostname: "configured-host".to_owned(),
                ..Default::default()
            },
        )
        .expect("CLI overrides image environment");
        assert_eq!(
            cli_values.env,
            [
                "PATH=/cli/bin",
                "HOSTNAME=cli-host",
                "HOME=/image/home",
                "TERM=image-term",
            ]
        );
    }

    #[test]
    fn all_named_and_numeric_user_group_forms_resolve_from_the_sealed_database() {
        let database = accounts();
        for (input, uid, gid, supplementary) in [
            ("app", 123, 456, vec![789]),
            ("123", 123, 456, vec![789]),
            ("app:extra", 123, 789, vec![]),
            ("123:extra", 123, 789, vec![]),
            ("app:789", 123, 789, vec![]),
            ("123:789", 123, 789, vec![]),
            ("999", 999, 0, vec![]),
        ] {
            let resolved = resolve_user(&database, input).expect("resolve User form");
            assert_eq!((resolved.uid, resolved.gid), (uid, gid), "{input}");
            assert_eq!(resolved.supplementary_gids, supplementary, "{input}");
        }
        assert!(resolve_user(&database, "missing").is_err());
        assert!(resolve_user(&database, "").is_err());
        assert!(resolve_user(&database, "app:").is_err());

        let mut duplicate = database;
        duplicate.users[1].uid = 123;
        assert!(resolve_user(&duplicate, "123").is_err());

        let mut unresolved_image = config();
        unresolved_image.user = "missing".to_owned();
        assert!(
            resolve_verified_process(&unresolved_image, &accounts(), &Default::default()).is_err()
        );
        let overridden = resolve_verified_process(
            &unresolved_image,
            &accounts(),
            &ImageProcessOverrides {
                user: Some("app".to_owned()),
                ..Default::default()
            },
        )
        .expect("valid CLI User overrides unresolved image User");
        assert_eq!((overridden.user.uid, overridden.user.gid), (123, 456));
    }

    #[test]
    fn docker_signal_names_numeric_values_and_realtime_offsets_are_bounded() {
        for (input, expected) in [
            ("SIGTERM", 15),
            ("term", 15),
            ("9", 9),
            ("SIGRTMIN", 34),
            ("RTMIN+1", 35),
            ("SIGRTMAX-1", 63),
            ("RTMAX", 64),
        ] {
            assert_eq!(parse_signal(input).expect("parse signal"), expected);
        }
        for invalid in ["", "0", "65", "SIGUNKNOWN", "RTMIN+31", "RTMAX-31"] {
            assert!(parse_signal(invalid).is_err(), "{invalid}");
        }

        let mut image = config();
        image.stop_signal = None;
        let defaults =
            resolve_verified_process(&image, &accounts(), &Default::default()).expect("defaults");
        assert_eq!(defaults.stop_signal, DEFAULT_STOP_SIGNAL);
        let overridden = resolve_verified_process(
            &image,
            &accounts(),
            &ImageProcessOverrides {
                working_dir: Some("/override".to_owned()),
                stop_signal: Some("SIGKILL".to_owned()),
                ..Default::default()
            },
        )
        .expect("CLI process overrides");
        assert_eq!(overridden.working_dir, "/override");
        assert_eq!(overridden.stop_signal, 9);
    }

    #[test]
    fn generation_process_sidecars_are_mandatory_and_parsed_only_from_the_lease() {
        let account_bytes = AccountDb::from_database(&accounts())
            .expect("canonical accounts")
            .canonical_bytes;
        let config_bytes = image_config_bytes();
        let (_temporary, store, id) = generation_with_sidecars(
            70,
            &[
                (ACCOUNT_DATABASE_SIDECAR, &account_bytes),
                (IMAGE_CONFIG_SIDECAR, &config_bytes),
            ],
            None,
        );
        let lease = store.acquire_lease(id).expect("lease generation");
        let process = resolve_image_process(&lease, &Default::default())
            .expect("resolve leased process sidecars");
        assert_eq!(process.argv, ["/entry", "default"]);
        assert_eq!((process.user.uid, process.user.gid), (123, 456));
        drop(lease);

        let (_temporary, store, id) =
            generation_with_sidecars(71, &[(ACCOUNT_DATABASE_SIDECAR, &account_bytes)], None);
        let lease = store
            .acquire_lease(id)
            .expect("lease missing-config generation");
        assert!(matches!(
            resolve_image_process(&lease, &Default::default()),
            Err(RuntimeError::Store(
                pocket_store::StoreError::SidecarNotFound { .. }
            ))
        ));

        let malformed = b"{".as_slice();
        let (_temporary, store, id) = generation_with_sidecars(
            72,
            &[
                (ACCOUNT_DATABASE_SIDECAR, &account_bytes),
                (IMAGE_CONFIG_SIDECAR, malformed),
            ],
            None,
        );
        let lease = store
            .acquire_lease(id)
            .expect("lease malformed-config generation");
        assert!(matches!(
            resolve_image_process(&lease, &Default::default()),
            Err(RuntimeError::ImageConfig(_))
        ));

        let (_temporary, store, id) =
            generation_with_sidecars(73, &[(IMAGE_CONFIG_SIDECAR, &config_bytes)], None);
        let lease = store
            .acquire_lease(id)
            .expect("lease missing-account generation");
        assert!(matches!(
            resolve_image_process(&lease, &Default::default()),
            Err(RuntimeError::Store(
                pocket_store::StoreError::SidecarNotFound { .. }
            ))
        ));

        let (_temporary, store, id) = generation_with_sidecars(
            74,
            &[
                (ACCOUNT_DATABASE_SIDECAR, &account_bytes),
                (IMAGE_CONFIG_SIDECAR, &config_bytes),
            ],
            Some(Digest::of_bytes(b"different authenticated config")),
        );
        let lease = store
            .acquire_lease(id)
            .expect("lease config-digest mismatch generation");
        assert!(matches!(
            resolve_image_process(&lease, &Default::default()),
            Err(RuntimeError::GenerationMismatch {
                field: "image_config.digest",
                ..
            })
        ));
    }
}
