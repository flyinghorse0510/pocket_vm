use std::{fs, path::Path};

use pocket_protocol::{
    ACCOUNT_DB_SCHEMA, AccountDatabase, AccountDb, AccountGroup, AccountUser, ValidateMessage,
};

use crate::ValidatorError;

const MAX_ACCOUNT_FILE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_ACCOUNT_LINE_BYTES: usize = 64 * 1024;

/// Independently derive the canonical account database from the mounted
/// rootfs. This implementation deliberately does not depend on the builder.
pub(crate) fn rebuild_account_database(rootfs: &Path) -> Result<AccountDb, ValidatorError> {
    let passwd = read_account_file(&rootfs.join("etc/passwd"))?;
    let groups = read_account_file(&rootfs.join("etc/group"))?;
    let mut users = Vec::new();
    for line in account_lines(&passwd)? {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() != 7 {
            return account_error("passwd entry does not have seven fields");
        }
        validate_name(fields[0], "user")?;
        users.push(AccountUser {
            name: fields[0].to_owned(),
            uid: parse_id(fields[2], "passwd uid")?,
            gid: parse_id(fields[3], "passwd gid")?,
        });
    }
    users.sort_by(|left, right| left.name.cmp(&right.name));

    let mut account_groups = Vec::new();
    for line in account_lines(&groups)? {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() != 4 {
            return account_error("group entry does not have four fields");
        }
        validate_name(fields[0], "group")?;
        // Canonicalized exactly as the builder canonicalizes it: real group
        // files list a member twice and leave stray commas behind, and neither
        // carries information. This parse is deliberately an independent
        // implementation, but it has to agree on what the canonical database
        // is -- otherwise an image the builder accepts fails here, and the
        // failure reads as evidence tampering rather than a stray comma.
        let mut members = fields[3]
            .split(',')
            .filter(|member| !member.is_empty())
            .map(|member| {
                validate_name(member, "group member")?;
                Ok(member.to_owned())
            })
            .collect::<Result<Vec<_>, ValidatorError>>()?;
        members.sort();
        members.dedup();
        account_groups.push(AccountGroup {
            name: fields[0].to_owned(),
            gid: parse_id(fields[2], "group gid")?,
            members,
        });
    }
    account_groups.sort_by(|left, right| left.name.cmp(&right.name));
    let database = AccountDatabase {
        schema: ACCOUNT_DB_SCHEMA.to_owned(),
        users,
        groups: account_groups,
    };
    database.validate().map_err(|error| {
        ValidatorError::protocol("account-database", error)
            .reclassify(pocket_core::ErrorCode::ValidatorAccount)
    })?;
    AccountDb::from_database(&database).map_err(|error| {
        ValidatorError::protocol("account-database", error)
            .reclassify(pocket_core::ErrorCode::ValidatorAccount)
    })
}

fn read_account_file(path: &Path) -> Result<String, ValidatorError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(String::new()),
        Err(error) => {
            return Err(ValidatorError::io("account-database", error)
                .reclassify(pocket_core::ErrorCode::ValidatorAccount));
        }
    };
    if !metadata.is_file() || metadata.len() > MAX_ACCOUNT_FILE_BYTES {
        return account_error(format!("{} is not a bounded plain file", path.display()));
    }
    fs::read_to_string(path).map_err(|error| {
        ValidatorError::io("account-database", error)
            .reclassify(pocket_core::ErrorCode::ValidatorAccount)
    })
}

fn account_lines(bytes: &str) -> Result<impl Iterator<Item = &str>, ValidatorError> {
    if bytes
        .lines()
        .any(|line| line.len() > MAX_ACCOUNT_LINE_BYTES)
    {
        return account_error("account-file line exceeds hard cap");
    }
    Ok(bytes
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#')))
}

fn parse_id(value: &str, field: &'static str) -> Result<u32, ValidatorError> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return account_error(format!("{field} is not an unsigned decimal ID"));
    }
    value
        .parse::<u32>()
        .map_err(|_| account_failure(format!("{field} does not fit u32")))
}

fn validate_name(value: &str, field: &'static str) -> Result<(), ValidatorError> {
    if value.is_empty()
        || value.len() > 256
        || value
            .bytes()
            .any(|byte| byte <= b' ' || matches!(byte, b':' | b',' | 0x7f))
    {
        return account_error(format!("{field} name has invalid bytes"));
    }
    Ok(())
}

fn account_error<T>(diagnostic: impl Into<String>) -> Result<T, ValidatorError> {
    Err(account_failure(diagnostic))
}

fn account_failure(diagnostic: impl Into<String>) -> ValidatorError {
    ValidatorError::failure(
        "account-database",
        pocket_core::ErrorCode::ValidatorAccount,
        None,
        diagnostic,
    )
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::rebuild_account_database;

    #[test]
    fn independently_rebuilds_sorted_canonical_accounts() {
        let root = TempDir::new().expect("root");
        fs::create_dir(root.path().join("etc")).expect("etc");
        fs::write(
            root.path().join("etc/passwd"),
            "z:x:2:3::/:/bin/false\na:x:1:1::/:/bin/false\n",
        )
        .expect("passwd");
        fs::write(root.path().join("etc/group"), "z:x:3:z,a\na:x:1:\n").expect("group");
        let account = rebuild_account_database(root.path()).expect("account database");
        let decoded = account.decode_database().expect("decode");
        assert_eq!(decoded.users[0].name, "a");
        assert_eq!(decoded.groups[1].members, ["a", "z"]);
    }

    /// This parse is an independent implementation of the builder's, and that
    /// is only useful if the two agree on what the canonical database is. If
    /// they disagree about duplicate members or stray commas, an image the
    /// builder accepted fails here, reported as builder evidence differing
    /// from the rebuild -- which reads as tampering rather than a group file
    /// that lists someone twice.
    #[test]
    fn canonicalizes_duplicate_and_empty_members_exactly_as_the_builder_does() {
        let root = TempDir::new().expect("root");
        fs::create_dir(root.path().join("etc")).expect("etc");
        fs::write(
            root.path().join("etc/passwd"),
            "root:x:0:0:root:/root:/bin/sh\n",
        )
        .expect("passwd");
        fs::write(
            root.path().join("etc/group"),
            "docker:x:999:,\nroot:x:0:\nsudo:x:27:alice,alice,bob,\n",
        )
        .expect("group");

        let account = rebuild_account_database(root.path()).expect("account database");
        let decoded = account.decode_database().expect("decode");
        let members = |name: &str| {
            decoded
                .groups
                .iter()
                .find(|group| group.name == name)
                .unwrap_or_else(|| panic!("{name} is missing"))
                .members
                .clone()
        };
        assert_eq!(members("sudo"), ["alice", "bob"]);
        assert!(members("docker").is_empty());
        assert!(members("root").is_empty());
    }
}
