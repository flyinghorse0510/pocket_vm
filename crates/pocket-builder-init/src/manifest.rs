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
    BuilderMessage, ManifestBegin, ManifestChunk, ManifestEnd, ManifestEntry, ManifestLimits,
    ManifestXattr, ValidateMessage, encode_payload,
};
use sha2::{Digest as _, Sha256};

use crate::BuilderError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestSummary {
    pub stream_id: String,
    pub sha256: String,
    pub entry_count: u64,
    pub byte_count: u64,
}

/// Sink abstraction used by the real framed serial protocol and by
/// unprivileged tests. A sink must either accept one complete message or
/// return an error; entries are never split between chunks.
pub trait ManifestEmitter {
    fn emit(&mut self, message: BuilderMessage) -> Result<(), BuilderError>;
}

pub(crate) fn emit_manifest(
    root: &Path,
    schema: &str,
    limits: &ManifestLimits,
    derivation_key: &str,
    emitter: &mut dyn ManifestEmitter,
) -> Result<ManifestSummary, BuilderError> {
    limits
        .validate()
        .map_err(|error| BuilderError::protocol("manifest", error))?;
    let metadata =
        fs::symlink_metadata(root).map_err(|error| BuilderError::io("manifest", error))?;
    if !metadata.is_dir() {
        return Err(BuilderError::manifest(
            "manifest",
            "manifest root is not a directory",
        ));
    }
    let stream_id = stream_id(derivation_key, schema);
    emitter.emit(BuilderMessage::ManifestBegin(ManifestBegin {
        schema: schema.to_owned(),
        stream_id: stream_id.clone(),
    }))?;

    let mut walker = Walker {
        root,
        limits,
        stream_id: stream_id.clone(),
        emitter,
        hardlinks: HashMap::new(),
        hardlink_path_bytes: 0,
        chunk: Vec::new(),
        chunk_entries: 0,
        chunk_first_entry: 0,
        chunk_sequence: 0,
        entry_count: 0,
        byte_count: 0,
        hasher: Sha256::new(),
    };
    walker.visit(Vec::new(), 0)?;
    walker.flush_chunk()?;
    let digest = hex_lower(&walker.hasher.clone().finalize());
    walker
        .emitter
        .emit(BuilderMessage::ManifestEnd(ManifestEnd {
            stream_id: stream_id.clone(),
            entry_count: walker.entry_count,
            byte_count: walker.byte_count,
            sha256: digest.clone(),
        }))?;
    Ok(ManifestSummary {
        stream_id,
        sha256: digest,
        entry_count: walker.entry_count,
        byte_count: walker.byte_count,
    })
}

struct Walker<'a> {
    root: &'a Path,
    limits: &'a ManifestLimits,
    stream_id: String,
    emitter: &'a mut dyn ManifestEmitter,
    hardlinks: HashMap<(u64, u64), Vec<u8>>,
    hardlink_path_bytes: u64,
    chunk: Vec<u8>,
    chunk_entries: u32,
    chunk_first_entry: u64,
    chunk_sequence: u64,
    entry_count: u64,
    byte_count: u64,
    hasher: Sha256,
}

impl Walker<'_> {
    fn visit(&mut self, relative: Vec<u8>, depth: u16) -> Result<(), BuilderError> {
        if depth > self.limits.max_depth {
            return Err(BuilderError::manifest(
                "manifest",
                "directory depth exceeds negotiated limit",
            ));
        }
        if relative.len() > self.limits.max_path_bytes as usize {
            return Err(BuilderError::manifest(
                "manifest",
                "path exceeds negotiated limit",
            ));
        }
        let path = path_from_relative(self.root, &relative);
        let metadata =
            fs::symlink_metadata(&path).map_err(|error| BuilderError::io("manifest", error))?;
        let is_directory = metadata.is_dir();
        let entry = self.make_entry(&path, relative.clone(), &metadata)?;
        self.push_entry(entry)?;
        if !is_directory {
            return Ok(());
        }

        let mut children = Vec::<OsString>::new();
        let mut child_name_bytes = 0_u64;
        for child in fs::read_dir(&path).map_err(|error| BuilderError::io("manifest", error))? {
            let name = child
                .map_err(|error| BuilderError::io("manifest", error))?
                .file_name();
            let bytes = name.as_bytes();
            if bytes.is_empty() || bytes.contains(&0) || matches!(bytes, b"." | b"..") {
                return Err(BuilderError::manifest(
                    "manifest",
                    "directory contains an invalid name",
                ));
            }
            child_name_bytes = child_name_bytes
                .checked_add(bytes.len() as u64)
                .ok_or_else(|| {
                    BuilderError::manifest("manifest", "directory-name byte count overflow")
                })?;
            if child_name_bytes > self.limits.max_directory_name_bytes {
                return Err(BuilderError::manifest(
                    "manifest",
                    "directory names exceed negotiated memory bound",
                ));
            }
            children.push(name);
            if children.len() > self.limits.max_directory_entries as usize {
                return Err(BuilderError::manifest(
                    "manifest",
                    "one directory exceeds negotiated entry bound",
                ));
            }
            if self.entry_count.saturating_add(children.len() as u64) > self.limits.max_entries {
                return Err(BuilderError::manifest(
                    "manifest",
                    "directory entries exceed negotiated total",
                ));
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
    ) -> Result<ManifestEntry, BuilderError> {
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
            return Err(BuilderError::manifest(
                "manifest",
                "filesystem entry has an unknown type",
            ));
        };
        let symlink_target = if file_type.is_symlink() {
            Some(
                fs::read_link(path)
                    .map_err(|error| BuilderError::io("manifest", error))?
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
                        return Err(BuilderError::manifest(
                            "manifest",
                            "hardlink groups exceed negotiated limit",
                        ));
                    }
                    self.hardlink_path_bytes = self
                        .hardlink_path_bytes
                        .checked_add(relative.len() as u64)
                        .ok_or_else(|| {
                            BuilderError::manifest("manifest", "hardlink path byte count overflow")
                        })?;
                    if self.hardlink_path_bytes > self.limits.max_hardlink_path_bytes {
                        return Err(BuilderError::manifest(
                            "manifest",
                            "hardlink paths exceed negotiated memory bound",
                        ));
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
            mtime_nanoseconds: u32::try_from(metadata.mtime_nsec()).map_err(|_| {
                BuilderError::manifest("manifest", "negative or oversized mtime nanoseconds")
            })?,
            symlink_target,
            content_sha256,
            hardlink_target,
            xattrs: list_xattrs(path, self.limits)?,
        };
        entry
            .validate()
            .map_err(|error| BuilderError::protocol("manifest", error))?;
        Ok(entry)
    }

    fn push_entry(&mut self, entry: ManifestEntry) -> Result<(), BuilderError> {
        if self.entry_count >= self.limits.max_entries {
            return Err(BuilderError::manifest(
                "manifest",
                "entry count exceeds negotiated limit",
            ));
        }
        let encoded =
            encode_payload(&entry).map_err(|error| BuilderError::protocol("manifest", error))?;
        if encoded.is_empty() || encoded.len() > self.limits.max_entry_bytes as usize {
            return Err(BuilderError::manifest(
                "manifest",
                "canonical entry exceeds negotiated limit",
            ));
        }
        let framed_len = encoded.len().checked_add(4).ok_or_else(|| {
            BuilderError::manifest("manifest", "length-prefixed entry size overflow")
        })?;
        if !self.chunk.is_empty()
            && self.chunk.len().saturating_add(framed_len) > self.limits.max_chunk_bytes as usize
        {
            self.flush_chunk()?;
        }
        if framed_len > self.limits.max_chunk_bytes as usize {
            return Err(BuilderError::manifest(
                "manifest",
                "entry cannot fit in one negotiated chunk",
            ));
        }
        if self.chunk.is_empty() {
            self.chunk_first_entry = self.entry_count;
        }
        let length = u32::try_from(encoded.len()).map_err(|_| {
            BuilderError::manifest("manifest", "entry length does not fit protocol field")
        })?;
        self.chunk.extend_from_slice(&length.to_be_bytes());
        self.chunk.extend_from_slice(&encoded);
        self.chunk_entries = self
            .chunk_entries
            .checked_add(1)
            .ok_or_else(|| BuilderError::manifest("manifest", "chunk entry-count overflow"))?;
        self.entry_count = self
            .entry_count
            .checked_add(1)
            .ok_or_else(|| BuilderError::manifest("manifest", "manifest entry-count overflow"))?;
        Ok(())
    }

    fn flush_chunk(&mut self) -> Result<(), BuilderError> {
        if self.chunk.is_empty() {
            return Ok(());
        }
        let bytes = std::mem::take(&mut self.chunk);
        let byte_count = self
            .byte_count
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| BuilderError::manifest("manifest", "manifest byte-count overflow"))?;
        if byte_count > self.limits.max_total_bytes {
            return Err(BuilderError::manifest(
                "manifest",
                "manifest bytes exceed negotiated limit",
            ));
        }
        self.hasher.update(&bytes);
        self.emitter
            .emit(BuilderMessage::ManifestChunk(ManifestChunk {
                stream_id: self.stream_id.clone(),
                sequence: self.chunk_sequence,
                first_entry: self.chunk_first_entry,
                entry_count: self.chunk_entries,
                bytes,
            }))?;
        self.byte_count = byte_count;
        self.chunk_sequence = self
            .chunk_sequence
            .checked_add(1)
            .ok_or_else(|| BuilderError::manifest("manifest", "chunk sequence overflow"))?;
        self.chunk_entries = 0;
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

fn hash_regular_file(path: &Path) -> Result<Vec<u8>, BuilderError> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| BuilderError::io("manifest", error))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| BuilderError::io("manifest", error))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize().to_vec())
}

fn list_xattrs(path: &Path, limits: &ManifestLimits) -> Result<Vec<ManifestXattr>, BuilderError> {
    let path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| BuilderError::manifest("manifest", "filesystem path contains NUL"))?;
    // SAFETY: `path` is a live NUL-terminated C string and a null buffer with
    // size zero is the documented size query form of llistxattr(2).
    let name_bytes = unsafe { libc::llistxattr(path.as_ptr(), std::ptr::null_mut(), 0) };
    if name_bytes < 0 {
        return Err(BuilderError::io(
            "manifest",
            std::io::Error::last_os_error(),
        ));
    }
    let name_bytes = usize::try_from(name_bytes)
        .map_err(|_| BuilderError::manifest("manifest", "xattr-name size overflow"))?;
    let maximum_names = (limits.max_xattrs_per_entry as usize)
        .saturating_mul(256)
        .min(limits.max_xattr_bytes_per_entry as usize);
    if name_bytes > maximum_names {
        return Err(BuilderError::manifest(
            "manifest",
            "xattr names exceed negotiated limit",
        ));
    }
    if name_bytes == 0 {
        return Ok(Vec::new());
    }
    let mut names = vec![0_u8; name_bytes];
    // SAFETY: the mutable buffer is valid for exactly `names.len()` bytes and
    // `path` remains a live NUL-terminated C string for the syscall.
    let read = unsafe { libc::llistxattr(path.as_ptr(), names.as_mut_ptr().cast(), names.len()) };
    if read < 0 {
        return Err(BuilderError::io(
            "manifest",
            std::io::Error::last_os_error(),
        ));
    }
    if read as usize != names.len() || names.last() != Some(&0) {
        return Err(BuilderError::manifest(
            "manifest",
            "xattr-name list changed or is malformed",
        ));
    }
    let mut attributes = Vec::new();
    let mut total = 0_usize;
    for name in names[..names.len() - 1].split(|byte| *byte == 0) {
        if name.is_empty() {
            return Err(BuilderError::manifest(
                "manifest",
                "xattr list contains an empty name",
            ));
        }
        if attributes.len() >= limits.max_xattrs_per_entry as usize {
            return Err(BuilderError::manifest(
                "manifest",
                "xattr count exceeds negotiated limit",
            ));
        }
        let c_name = CString::new(name)
            .map_err(|_| BuilderError::manifest("manifest", "xattr name contains NUL"))?;
        // SAFETY: both C strings are valid and the null/zero pair is the
        // documented lgetxattr(2) value-size query.
        let value_len =
            unsafe { libc::lgetxattr(path.as_ptr(), c_name.as_ptr(), std::ptr::null_mut(), 0) };
        if value_len < 0 {
            return Err(BuilderError::io(
                "manifest",
                std::io::Error::last_os_error(),
            ));
        }
        let value_len = usize::try_from(value_len)
            .map_err(|_| BuilderError::manifest("manifest", "xattr value-size overflow"))?;
        total = total
            .checked_add(name.len())
            .and_then(|value| value.checked_add(value_len))
            .ok_or_else(|| BuilderError::manifest("manifest", "xattr byte-count overflow"))?;
        if total > limits.max_xattr_bytes_per_entry as usize {
            return Err(BuilderError::manifest(
                "manifest",
                "xattr bytes exceed negotiated limit",
            ));
        }
        let mut value = vec![0_u8; value_len];
        // SAFETY: both strings remain valid and `value` is writable for the
        // exact requested byte count (a dangling pointer is accepted for the
        // zero-length case because the syscall will not dereference it).
        let value_read = unsafe {
            libc::lgetxattr(
                path.as_ptr(),
                c_name.as_ptr(),
                value.as_mut_ptr().cast(),
                value.len(),
            )
        };
        if value_read < 0 || value_read as usize != value_len {
            return Err(BuilderError::io(
                "manifest",
                std::io::Error::last_os_error(),
            ));
        }
        attributes.push(ManifestXattr {
            name: name.to_vec(),
            value,
        });
    }
    attributes.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(attributes)
}

fn stream_id(derivation_key: &str, schema: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"pocket-builder-manifest-stream\0v1\0");
    hasher.update(derivation_key.as_bytes());
    hasher.update([0]);
    hasher.update(schema.as_bytes());
    hex_lower(&hasher.finalize())
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

    use pocket_protocol::{BuilderMessage, ManifestEntry, ManifestLimits, decode_payload};
    use tempfile::TempDir;

    use super::{ManifestEmitter, emit_manifest};
    use crate::BuilderError;

    #[derive(Default)]
    struct Capture(Vec<BuilderMessage>);

    impl ManifestEmitter for Capture {
        fn emit(&mut self, message: BuilderMessage) -> Result<(), BuilderError> {
            self.0.push(message);
            Ok(())
        }
    }

    fn decode_entries(messages: &[BuilderMessage]) -> Vec<ManifestEntry> {
        let mut result = Vec::new();
        for message in messages {
            let BuilderMessage::ManifestChunk(chunk) = message else {
                continue;
            };
            let mut position = 0;
            while position < chunk.bytes.len() {
                let length = u32::from_be_bytes(
                    chunk.bytes[position..position + 4]
                        .try_into()
                        .expect("length bytes"),
                ) as usize;
                position += 4;
                result.push(
                    decode_payload(&chunk.bytes[position..position + length])
                        .expect("manifest entry"),
                );
                position += length;
            }
        }
        result
    }

    #[test]
    fn emits_deterministic_complete_entries_and_hardlink_evidence() {
        let target = TempDir::new().expect("tempdir");
        fs::create_dir(target.path().join("rootfs")).expect("rootfs");
        let app_path = target.path().join("rootfs/app");
        fs::write(&app_path, b"payload").expect("file");
        let c_path = CString::new(app_path.as_os_str().as_bytes()).expect("path CString");
        let c_name = CString::new("user.pocket-test").expect("name CString");
        let xattr_value = b"xattr-value";
        // SAFETY: both C strings and the immutable value buffer remain live
        // for the complete lsetxattr(2) call and their lengths are exact.
        let xattr_status = unsafe {
            libc::lsetxattr(
                c_path.as_ptr(),
                c_name.as_ptr(),
                xattr_value.as_ptr().cast(),
                xattr_value.len(),
                0,
            )
        };
        assert_eq!(
            xattr_status, 0,
            "fixture filesystem must support user xattrs"
        );
        fs::hard_link(
            target.path().join("rootfs/app"),
            target.path().join("rootfs/app-link"),
        )
        .expect("hardlink");
        symlink("app", target.path().join("rootfs/symlink")).expect("symlink");

        let mut first = Capture::default();
        let summary = emit_manifest(
            target.path(),
            "pocket-fs-manifest-v1",
            &ManifestLimits::default(),
            &"a".repeat(64),
            &mut first,
        )
        .expect("manifest");
        let entries = decode_entries(&first.0);
        assert_eq!(summary.entry_count, entries.len() as u64);
        assert!(entries.iter().any(|entry| entry.content_sha256.is_some()));
        assert!(entries.iter().any(|entry| entry.hardlink_target.is_some()));
        assert!(entries.iter().any(|entry| entry.symlink_target.is_some()));
        assert!(entries.iter().any(|entry| {
            entry
                .xattrs
                .iter()
                .any(|xattr| xattr.name == b"user.pocket-test" && xattr.value == b"xattr-value")
        }));

        let mut second = Capture::default();
        let second_summary = emit_manifest(
            target.path(),
            "pocket-fs-manifest-v1",
            &ManifestLimits::default(),
            &"a".repeat(64),
            &mut second,
        )
        .expect("second manifest");
        assert_eq!(summary, second_summary);
    }

    #[test]
    fn negotiated_entry_limit_fails_closed() {
        let target = TempDir::new().expect("tempdir");
        fs::write(target.path().join("large-name"), b"x").expect("file");
        let limits = ManifestLimits {
            max_path_bytes: 4,
            ..ManifestLimits::default()
        };
        let mut capture = Capture::default();
        assert!(
            emit_manifest(
                target.path(),
                "pocket-fs-manifest-v1",
                &limits,
                &"a".repeat(64),
                &mut capture,
            )
            .is_err()
        );
    }
}
