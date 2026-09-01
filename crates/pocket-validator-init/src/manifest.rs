use std::{
    collections::HashMap,
    ffi::{CString, OsStr, OsString},
    fs::{self, OpenOptions},
    io::Read,
    os::unix::{
        ffi::{OsStrExt, OsStringExt},
        fs::{FileTypeExt, MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
};

use pocket_protocol::{
    ManifestEntry, ManifestLimits, ManifestXattr, ValidateMessage, encode_payload,
};
use sha2::{Digest as _, Sha256};

use crate::ValidatorError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestSummary {
    pub sha256: String,
    pub entry_count: u64,
    pub byte_count: u64,
}

/// Independently walk and canonicalize the mounted candidate. The builder's
/// streaming implementation is intentionally not linked into this binary.
pub fn validate_manifest(
    root: &Path,
    limits: &ManifestLimits,
) -> Result<ManifestSummary, ValidatorError> {
    limits.validate().map_err(protocol_manifest)?;
    let metadata = fs::symlink_metadata(root).map_err(io_manifest)?;
    if !metadata.is_dir() {
        return manifest_error("manifest root is not a directory");
    }
    let mut walker = Walker {
        root,
        limits,
        hardlinks: HashMap::new(),
        hardlink_path_bytes: 0,
        entry_count: 0,
        byte_count: 0,
        hasher: Sha256::new(),
    };
    walker.visit(Vec::new(), 0)?;
    Ok(ManifestSummary {
        sha256: hex_lower(&walker.hasher.finalize()),
        entry_count: walker.entry_count,
        byte_count: walker.byte_count,
    })
}

struct Walker<'a> {
    root: &'a Path,
    limits: &'a ManifestLimits,
    hardlinks: HashMap<(u64, u64), Vec<u8>>,
    hardlink_path_bytes: u64,
    entry_count: u64,
    byte_count: u64,
    hasher: Sha256,
}

impl Walker<'_> {
    fn visit(&mut self, relative: Vec<u8>, depth: u16) -> Result<(), ValidatorError> {
        if depth > self.limits.max_depth {
            return manifest_error("directory depth exceeds negotiated limit");
        }
        if relative.len() > self.limits.max_path_bytes as usize {
            return manifest_error("path exceeds negotiated limit");
        }
        let path = path_from_relative(self.root, &relative);
        let metadata = fs::symlink_metadata(&path).map_err(io_manifest)?;
        let is_directory = metadata.is_dir();
        let entry = self.make_entry(&path, relative.clone(), &metadata)?;
        self.push_entry(entry)?;
        if !is_directory {
            return Ok(());
        }

        let mut children = Vec::<OsString>::new();
        let mut child_name_bytes = 0_u64;
        for child in fs::read_dir(&path).map_err(io_manifest)? {
            let name = child.map_err(io_manifest)?.file_name();
            let bytes = name.as_bytes();
            if bytes.is_empty() || bytes.contains(&0) || matches!(bytes, b"." | b"..") {
                return manifest_error("directory contains an invalid name");
            }
            child_name_bytes = child_name_bytes
                .checked_add(bytes.len() as u64)
                .ok_or_else(|| manifest_failure("directory-name byte count overflow"))?;
            if child_name_bytes > self.limits.max_directory_name_bytes {
                return manifest_error("directory names exceed negotiated limit");
            }
            children.push(name);
            if children.len() > self.limits.max_directory_entries as usize {
                return manifest_error("one directory exceeds negotiated entry limit");
            }
            if self.entry_count.saturating_add(children.len() as u64) > self.limits.max_entries {
                return manifest_error("directory entries exceed negotiated total");
            }
        }
        children.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
        for child in children {
            let mut child_relative = relative.clone();
            if !child_relative.is_empty() {
                child_relative.push(b'/');
            }
            child_relative.extend_from_slice(child.as_bytes());
            self.visit(child_relative, depth + 1)?;
        }
        Ok(())
    }

    fn make_entry(
        &mut self,
        path: &Path,
        relative: Vec<u8>,
        metadata: &fs::Metadata,
    ) -> Result<ManifestEntry, ValidatorError> {
        let file_type = metadata.file_type();
        let kind = if file_type.is_file() {
            1
        } else if file_type.is_dir() {
            2
        } else if file_type.is_symlink() {
            3
        } else if file_type.is_char_device() {
            4
        } else if file_type.is_block_device() {
            5
        } else if file_type.is_fifo() {
            6
        } else if file_type.is_socket() {
            7
        } else {
            return manifest_error("filesystem entry has an unknown type");
        };
        let symlink_target = if file_type.is_symlink() {
            Some(
                fs::read_link(path)
                    .map_err(io_manifest)?
                    .into_os_string()
                    .into_vec(),
            )
        } else {
            None
        };
        let (content_sha256, hardlink_target) = if file_type.is_file() {
            let key = (metadata.dev(), metadata.ino());
            if metadata.nlink() > 1 {
                if let Some(first_path) = self.hardlinks.get(&key) {
                    (None, Some(first_path.clone()))
                } else {
                    if self.hardlinks.len() >= self.limits.max_hardlink_groups as usize {
                        return manifest_error("hardlink groups exceed negotiated limit");
                    }
                    self.hardlink_path_bytes = self
                        .hardlink_path_bytes
                        .checked_add(relative.len() as u64)
                        .ok_or_else(|| manifest_failure("hardlink path byte count overflow"))?;
                    if self.hardlink_path_bytes > self.limits.max_hardlink_path_bytes {
                        return manifest_error("hardlink paths exceed negotiated limit");
                    }
                    self.hardlinks.insert(key, relative.clone());
                    (Some(hash_regular_file(path)?), None)
                }
            } else {
                (Some(hash_regular_file(path)?), None)
            }
        } else {
            (None, None)
        };
        let entry = ManifestEntry {
            path: relative,
            kind,
            mode: metadata.mode() & 0o7777,
            uid: metadata.uid(),
            gid: metadata.gid(),
            size: metadata.size(),
            rdev: if file_type.is_char_device() || file_type.is_block_device() {
                metadata.rdev()
            } else {
                0
            },
            mtime_seconds: metadata.mtime(),
            mtime_nanoseconds: u32::try_from(metadata.mtime_nsec())
                .map_err(|_| manifest_failure("invalid mtime nanoseconds"))?,
            symlink_target,
            content_sha256,
            hardlink_target,
            xattrs: list_xattrs(path, self.limits)?,
        };
        entry.validate().map_err(protocol_manifest)?;
        Ok(entry)
    }

    fn push_entry(&mut self, entry: ManifestEntry) -> Result<(), ValidatorError> {
        if self.entry_count >= self.limits.max_entries {
            return manifest_error("entry count exceeds negotiated limit");
        }
        let encoded = encode_payload(&entry).map_err(protocol_manifest)?;
        if encoded.is_empty() || encoded.len() > self.limits.max_entry_bytes as usize {
            return manifest_error("canonical entry exceeds negotiated limit");
        }
        let framed_len = encoded
            .len()
            .checked_add(4)
            .ok_or_else(|| manifest_failure("length-prefixed entry size overflow"))?;
        if framed_len > self.limits.max_chunk_bytes as usize {
            return manifest_error("entry cannot fit in one negotiated chunk");
        }
        let length = u32::try_from(encoded.len())
            .map_err(|_| manifest_failure("entry length does not fit protocol field"))?;
        let new_byte_count = self
            .byte_count
            .checked_add(framed_len as u64)
            .ok_or_else(|| manifest_failure("manifest byte-count overflow"))?;
        if new_byte_count > self.limits.max_total_bytes {
            return manifest_error("manifest bytes exceed negotiated limit");
        }
        self.hasher.update(length.to_be_bytes());
        self.hasher.update(&encoded);
        self.byte_count = new_byte_count;
        self.entry_count = self
            .entry_count
            .checked_add(1)
            .ok_or_else(|| manifest_failure("manifest entry-count overflow"))?;
        Ok(())
    }
}

fn path_from_relative(root: &Path, relative: &[u8]) -> PathBuf {
    if relative.is_empty() {
        root.to_owned()
    } else {
        root.join(OsStr::from_bytes(relative))
    }
}

fn hash_regular_file(path: &Path) -> Result<Vec<u8>, ValidatorError> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(io_manifest)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(io_manifest)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize().to_vec())
}

fn list_xattrs(path: &Path, limits: &ManifestLimits) -> Result<Vec<ManifestXattr>, ValidatorError> {
    let path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| manifest_failure("filesystem path contains NUL"))?;
    // SAFETY: `path` is a valid NUL-terminated C string and null/zero is the
    // documented llistxattr(2) size-query form.
    let name_bytes = unsafe { libc::llistxattr(path.as_ptr(), std::ptr::null_mut(), 0) };
    if name_bytes < 0 {
        return Err(io_manifest(std::io::Error::last_os_error()));
    }
    let name_bytes =
        usize::try_from(name_bytes).map_err(|_| manifest_failure("xattr-name size overflow"))?;
    let maximum_names = (limits.max_xattrs_per_entry as usize)
        .saturating_mul(256)
        .min(limits.max_xattr_bytes_per_entry as usize);
    if name_bytes > maximum_names {
        return manifest_error("xattr names exceed negotiated limit");
    }
    if name_bytes == 0 {
        return Ok(Vec::new());
    }
    let mut names = vec![0_u8; name_bytes];
    // SAFETY: the mutable buffer is valid for exactly `names.len()` bytes.
    let read = unsafe { libc::llistxattr(path.as_ptr(), names.as_mut_ptr().cast(), names.len()) };
    if read < 0 {
        return Err(io_manifest(std::io::Error::last_os_error()));
    }
    if read as usize != names.len() || names.last() != Some(&0) {
        return manifest_error("xattr-name list changed or is malformed");
    }
    let mut attributes = Vec::new();
    let mut total = 0_usize;
    for name in names[..names.len() - 1].split(|byte| *byte == 0) {
        if name.is_empty() {
            return manifest_error("xattr list contains an empty name");
        }
        if attributes.len() >= limits.max_xattrs_per_entry as usize {
            return manifest_error("xattr count exceeds negotiated limit");
        }
        let c_name = CString::new(name).map_err(|_| manifest_failure("xattr name contains NUL"))?;
        // SAFETY: both C strings are valid and null/zero requests the size.
        let value_len =
            unsafe { libc::lgetxattr(path.as_ptr(), c_name.as_ptr(), std::ptr::null_mut(), 0) };
        if value_len < 0 {
            return Err(io_manifest(std::io::Error::last_os_error()));
        }
        let value_len = usize::try_from(value_len)
            .map_err(|_| manifest_failure("xattr value-size overflow"))?;
        total = total
            .checked_add(name.len())
            .and_then(|value| value.checked_add(value_len))
            .ok_or_else(|| manifest_failure("xattr byte-count overflow"))?;
        if total > limits.max_xattr_bytes_per_entry as usize {
            return manifest_error("xattr bytes exceed negotiated limit");
        }
        let mut value = vec![0_u8; value_len];
        // SAFETY: both strings and the exact writable value buffer remain live.
        let value_read = unsafe {
            libc::lgetxattr(
                path.as_ptr(),
                c_name.as_ptr(),
                value.as_mut_ptr().cast(),
                value.len(),
            )
        };
        if value_read < 0 || value_read as usize != value_len {
            return Err(io_manifest(std::io::Error::last_os_error()));
        }
        attributes.push(ManifestXattr {
            name: name.to_vec(),
            value,
        });
    }
    attributes.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(attributes)
}

fn protocol_manifest(error: pocket_protocol::ProtocolError) -> ValidatorError {
    ValidatorError::protocol("manifest", error)
        .reclassify(pocket_core::ErrorCode::ValidatorManifest)
}

fn io_manifest(error: std::io::Error) -> ValidatorError {
    ValidatorError::io("manifest", error).reclassify(pocket_core::ErrorCode::ValidatorManifest)
}

fn manifest_error<T>(diagnostic: impl Into<String>) -> Result<T, ValidatorError> {
    Err(manifest_failure(diagnostic))
}

fn manifest_failure(diagnostic: impl Into<String>) -> ValidatorError {
    ValidatorError::failure(
        "manifest",
        pocket_core::ErrorCode::ValidatorManifest,
        None,
        diagnostic,
    )
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
mod tests {
    use std::{
        ffi::CString,
        fs,
        os::unix::{ffi::OsStrExt, fs::symlink},
    };

    use pocket_protocol::ManifestLimits;
    use tempfile::TempDir;

    use super::validate_manifest;

    #[test]
    fn deterministically_rewalks_content_hardlinks_symlinks_and_xattrs() {
        let target = TempDir::new().expect("tempdir");
        fs::create_dir(target.path().join("rootfs")).expect("rootfs");
        let app = target.path().join("rootfs/app");
        fs::write(&app, b"payload").expect("file");
        fs::hard_link(&app, target.path().join("rootfs/app-link")).expect("hardlink");
        symlink("app", target.path().join("rootfs/symlink")).expect("symlink");
        let path = CString::new(app.as_os_str().as_bytes()).expect("path");
        let name = CString::new("user.pocket-validator").expect("name");
        // SAFETY: fixture strings and value buffer are live and exactly sized.
        let result = unsafe {
            libc::lsetxattr(path.as_ptr(), name.as_ptr(), b"value".as_ptr().cast(), 5, 0)
        };
        assert_eq!(result, 0);
        let first = validate_manifest(target.path(), &ManifestLimits::default()).expect("first");
        let second = validate_manifest(target.path(), &ManifestLimits::default()).expect("second");
        assert_eq!(first, second);
        assert_eq!(first.entry_count, 5);
        assert!(first.byte_count > 0);
    }

    #[test]
    fn negotiated_limits_fail_closed() {
        let target = TempDir::new().expect("tempdir");
        fs::write(target.path().join("oversized"), b"x").expect("file");
        let limits = ManifestLimits {
            max_path_bytes: 4,
            ..ManifestLimits::default()
        };
        assert!(validate_manifest(target.path(), &limits).is_err());
    }
}
