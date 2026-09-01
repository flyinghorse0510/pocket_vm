use std::{fs, path::Path};

use pocket_protocol::{
    AccountDatabase, AccountGroup, AccountUser, MAX_ORIGINAL_USER_LENGTH, UserResolution,
    ValidateMessage,
};

use crate::BuilderError;

const MAX_ACCOUNT_FILE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_ACCOUNT_LINE_BYTES: usize = 64 * 1024;

/// Resolve Docker's image `User` evidence against the completed rootfs.
/// The original string remains in `BUILD_DONE`; this function records the
/// deterministic numeric result or a canonical unresolved missing-name result
/// without rewriting the image-config sidecar.
pub fn resolve_image_user(rootfs: &Path, original: &str) -> Result<UserResolution, BuilderError> {
    let database = build_account_database(rootfs)?;
    resolve_image_user_from_database(&database, original)
}

/// Build the canonical account records that the host persists as
/// `accounts.cbor`. The database is generated from the completed rootfs and is
/// also the sole input to image-User resolution.
pub fn build_account_database(rootfs: &Path) -> Result<AccountDatabase, BuilderError> {
    let passwd = read_account_file(&rootfs.join("etc/passwd"))?;
    let groups = read_account_file(&rootfs.join("etc/group"))?;
    let mut users = Vec::new();
    for line in account_lines(&passwd)? {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() != 7 {
            return Err(BuilderError::contract(
                "account-database",
                "passwd entry does not have seven fields",
            ));
        }
        validate_name(fields[0], "user")?;
        users.push(AccountUser {
            name: fields[0].to_owned(),
            uid: parse_required_id(fields[2], "passwd uid")?,
            gid: parse_required_id(fields[3], "passwd gid")?,
        });
    }
    users.sort_by(|left, right| left.name.cmp(&right.name));

    let mut account_groups = Vec::new();
    for line in account_lines(&groups)? {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() != 4 {
            return Err(BuilderError::contract(
                "account-database",
                "group entry does not have four fields",
            ));
        }
        validate_name(fields[0], "group")?;
        // Real group files carry members listed twice and stray commas that
        // produce empty names -- `usermod -aG` run twice is enough. Neither
        // carries any information, and the canonical database the protocol
        // transmits requires strictly sorted unique names, so canonicalize
        // rather than abort a whole build over a cosmetic duplicate.
        let mut members = fields[3]
            .split(',')
            .filter(|member| !member.is_empty())
            .map(|member| {
                validate_name(member, "group member")?;
                Ok(member.to_owned())
            })
            .collect::<Result<Vec<_>, BuilderError>>()?;
        members.sort();
        members.dedup();
        account_groups.push(AccountGroup {
            name: fields[0].to_owned(),
            gid: parse_required_id(fields[2], "group gid")?,
            members,
        });
    }
    account_groups.sort_by(|left, right| left.name.cmp(&right.name));
    let database = AccountDatabase {
        schema: pocket_protocol::ACCOUNT_DB_SCHEMA.to_owned(),
        users,
        groups: account_groups,
    };
    database
        .validate()
        .map_err(|error| BuilderError::protocol("account-database", error))?;
    Ok(database)
}

pub fn resolve_image_user_from_database(
    database: &AccountDatabase,
    original: &str,
) -> Result<UserResolution, BuilderError> {
    database
        .validate()
        .map_err(|error| BuilderError::protocol("resolve-user", error))?;
    if original.len() > MAX_ORIGINAL_USER_LENGTH || original.contains(['\0', '\n', '\r']) {
        return Err(BuilderError::contract(
            "resolve-user",
            "image User is oversized or contains a forbidden byte",
        ));
    }
    if original.is_empty() {
        return Ok(UserResolution {
            kind: 0,
            uid: 0,
            gid: 0,
            supplementary_gids: Vec::new(),
        });
    }
    let mut parts = original.split(':');
    let user_part = parts.next().unwrap_or_default();
    let group_part = parts.next();
    if parts.next().is_some() || user_part.is_empty() || group_part == Some("") {
        return Err(BuilderError::contract(
            "resolve-user",
            "image User must be user-or-uid with at most one nonempty group suffix",
        ));
    }

    let numeric_user = parse_optional_id(user_part, "user")?;
    let mut unresolved = false;
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
        validate_name(user_part, "user")?;
        let record = database
            .users
            .binary_search_by(|record| record.name.as_str().cmp(user_part))
            .ok()
            .map(|index| &database.users[index]);
        if let Some(record) = record {
            (record.uid, record.gid, Some(record.name.as_str()), 2)
        } else {
            unresolved = true;
            (0, 0, Some(user_part), UserResolution::KIND_UNRESOLVED)
        }
    };

    let gid = match group_part {
        None => default_gid,
        Some(group) => match parse_optional_id(group, "group")? {
            Some(gid) => gid,
            None => {
                validate_name(group, "group")?;
                database
                    .groups
                    .binary_search_by(|record| record.name.as_str().cmp(group))
                    .ok()
                    .map(|index| database.groups[index].gid)
                    .unwrap_or_else(|| {
                        unresolved = true;
                        0
                    })
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
    if !unresolved {
        supplementary_gids.retain(|candidate| *candidate != gid);
    }
    supplementary_gids.sort_unstable();
    supplementary_gids.dedup();
    if supplementary_gids.len() > 64 {
        return Err(BuilderError::contract(
            "resolve-user",
            "resolved supplementary group count exceeds hard cap",
        ));
    }
    if unresolved {
        return Ok(UserResolution::unresolved());
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
) -> Result<Option<&'a AccountUser>, BuilderError> {
    let found = matches.next();
    if found.is_some() && matches.next().is_some() {
        return Err(BuilderError::contract(
            "resolve-user",
            format!("passwd has multiple entries matching {match_kind}"),
        ));
    }
    Ok(found)
}

/// Read one account file, or nothing at all.
///
/// A scratch image has no `/etc/passwd` and no `/etc/group`, and that is not an
/// error: it is an image whose only account is root by number.
fn read_account_file(path: &Path) -> Result<String, BuilderError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(String::new());
        }
        Err(error) => return Err(BuilderError::io("resolve-user", error)),
    };
    if !metadata.is_file() || metadata.len() > MAX_ACCOUNT_FILE_BYTES {
        return Err(BuilderError::contract(
            "resolve-user",
            format!("{} is not a bounded plain file", path.display()),
        ));
    }
    fs::read_to_string(path).map_err(|error| BuilderError::io("resolve-user", error))
}

fn account_lines(bytes: &str) -> Result<impl Iterator<Item = &str>, BuilderError> {
    if bytes
        .lines()
        .any(|line| line.len() > MAX_ACCOUNT_LINE_BYTES)
    {
        return Err(BuilderError::contract(
            "resolve-user",
            "account-file line exceeds hard cap",
        ));
    }
    Ok(bytes
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#')))
}

fn parse_optional_id(value: &str, field: &'static str) -> Result<Option<u32>, BuilderError> {
    if !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Ok(None);
    }
    parse_required_id(value, field).map(Some)
}

fn parse_required_id(value: &str, field: &'static str) -> Result<u32, BuilderError> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(BuilderError::contract(
            "resolve-user",
            format!("{field} is not an unsigned decimal ID"),
        ));
    }
    value
        .parse::<u32>()
        .map_err(|_| BuilderError::contract("resolve-user", format!("{field} does not fit u32")))
}

fn validate_name(value: &str, field: &'static str) -> Result<(), BuilderError> {
    if value.is_empty()
        || value.len() > 256
        || value
            .bytes()
            .any(|byte| byte <= b' ' || matches!(byte, b':' | b',' | 0x7f))
    {
        return Err(BuilderError::contract(
            "resolve-user",
            format!("{field} name has invalid bytes"),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use pocket_protocol::UserResolution;
    use tempfile::TempDir;

    use super::{build_account_database, resolve_image_user};

    fn rootfs() -> TempDir {
        let root = TempDir::new().expect("tempdir");
        fs::create_dir(root.path().join("etc")).expect("etc");
        fs::write(
            root.path().join("etc/passwd"),
            concat!(
                "root:x:0:0:root:/root:/bin/sh\n",
                "app:x:123:456::/app:/bin/false\n",
                "mapped:x:1000:1002::/app:/bin/false\n",
            ),
        )
        .expect("passwd");
        fs::write(
            root.path().join("etc/group"),
            concat!(
                "root:x:0:\n",
                "app:x:456:\n",
                "extra:x:789:app,other\n",
                "mapped-extra:x:790:mapped\n",
            ),
        )
        .expect("group");
        root
    }

    /// Group files in real images list a member twice and leave stray commas
    /// behind. Neither says anything the canonical database does not already
    /// say, so neither may abort the build that reads them.
    #[test]
    fn duplicate_and_empty_group_members_are_canonicalized_not_refused() {
        let root = TempDir::new().expect("tempdir");
        fs::create_dir(root.path().join("etc")).expect("etc");
        fs::write(
            root.path().join("etc/passwd"),
            "root:x:0:0:root:/root:/bin/sh\n",
        )
        .expect("passwd");
        fs::write(
            root.path().join("etc/group"),
            concat!(
                "root:x:0:\n",
                // `usermod -aG` run twice, plus a trailing comma.
                "sudo:x:27:alice,alice,bob,\n",
                "docker:x:999:,\n",
            ),
        )
        .expect("group");

        let database = build_account_database(root.path()).expect("canonical database");
        let group = |name: &str| {
            database
                .groups
                .iter()
                .find(|group| group.name == name)
                .unwrap_or_else(|| panic!("{name} is missing"))
                .members
                .clone()
        };
        assert_eq!(group("sudo"), ["alice", "bob"]);
        assert!(group("docker").is_empty());
        assert!(group("root").is_empty());
    }

    #[test]
    fn resolves_default_numeric_and_named_forms_with_evidence() {
        let root = rootfs();
        let default = resolve_image_user(root.path(), "").expect("default");
        assert_eq!((default.kind, default.uid, default.gid), (0, 0, 0));

        let numeric = resolve_image_user(root.path(), "1000").expect("mapped numeric");
        assert_eq!((numeric.kind, numeric.uid, numeric.gid), (1, 1000, 1002));
        assert_eq!(numeric.supplementary_gids, vec![790]);

        let numeric_fallback = resolve_image_user(root.path(), "1001").expect("numeric fallback");
        assert_eq!(
            (
                numeric_fallback.kind,
                numeric_fallback.uid,
                numeric_fallback.gid,
            ),
            (1, 1001, 0)
        );
        assert!(numeric_fallback.supplementary_gids.is_empty());

        let named = resolve_image_user(root.path(), "app").expect("named");
        assert_eq!((named.kind, named.uid, named.gid), (2, 123, 456));
        assert_eq!(named.supplementary_gids, vec![789]);

        let overridden = resolve_image_user(root.path(), "app:1234").expect("group override");
        assert_eq!(overridden.gid, 1234);
        assert!(overridden.supplementary_gids.is_empty());
    }

    #[test]
    fn records_missing_names_as_unresolved_but_rejects_malformed_specs() {
        let root = rootfs();
        for original in [
            "missing",
            "app:missing",
            "missing:1234",
            "missing:also-missing",
        ] {
            assert_eq!(
                resolve_image_user(root.path(), original).expect("missing name is unresolved"),
                UserResolution::unresolved(),
                "{original}",
            );
        }
        assert!(resolve_image_user(root.path(), "app:").is_err());
        assert!(resolve_image_user(root.path(), "a:b:c").is_err());
        assert!(resolve_image_user(root.path(), "missing:bad group").is_err());
        assert!(resolve_image_user(root.path(), "4294967296").is_err());
        assert!(resolve_image_user(root.path(), "missing:4294967296").is_err());
    }

    #[test]
    fn rejects_ambiguous_passwd_and_group_matches() {
        let root = rootfs();
        fs::write(
            root.path().join("etc/passwd"),
            concat!(
                "first:x:1000:1001::/app:/bin/false\n",
                "second:x:1000:1002::/app:/bin/false\n",
            ),
        )
        .expect("ambiguous passwd");
        assert!(resolve_image_user(root.path(), "1000").is_err());
        assert!(resolve_image_user(root.path(), "1000:missing").is_err());

        fs::write(
            root.path().join("etc/passwd"),
            "app:x:123:456::/app:/bin/false\n",
        )
        .expect("passwd");
        fs::write(
            root.path().join("etc/group"),
            "duplicate:x:789:\nduplicate:x:790:\n",
        )
        .expect("ambiguous group");
        assert!(resolve_image_user(root.path(), "app:duplicate").is_err());
    }

    #[test]
    fn rejects_malformed_account_files_and_excess_supplementary_groups() {
        let root = rootfs();
        fs::write(root.path().join("etc/passwd"), "malformed\n").expect("malformed passwd");
        assert!(resolve_image_user(root.path(), "missing").is_err());

        fs::write(
            root.path().join("etc/passwd"),
            "app:x:123:456::/app:/bin/false\n",
        )
        .expect("passwd");
        let groups = |member: &str, count| {
            (0..count)
                .map(|index| format!("extra-{index}:x:{}:{member}\n", 1_000 + index))
                .collect::<String>()
        };
        fs::write(root.path().join("etc/group"), groups("app", 64)).expect("groups");
        let maximum = resolve_image_user(root.path(), "app").expect("64 supplementary groups");
        assert_eq!(maximum.supplementary_gids.len(), 64);

        fs::write(root.path().join("etc/group"), groups("app", 65)).expect("groups");
        assert!(resolve_image_user(root.path(), "app").is_err());

        fs::write(root.path().join("etc/passwd"), "").expect("empty passwd");
        fs::write(root.path().join("etc/group"), groups("missing", 65))
            .expect("missing-user memberships");
        assert!(resolve_image_user(root.path(), "missing").is_err());
    }
}
