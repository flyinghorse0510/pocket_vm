use std::{
    ffi::{OsStr, OsString},
    fs::{File, Metadata, Permissions},
    io::{self, Read, Write},
    os::{
        fd::OwnedFd,
        unix::{
            ffi::OsStringExt,
            fs::{FileExt, MetadataExt, PermissionsExt},
        },
    },
    path::{Component, Path, PathBuf},
};

use nix::{
    dir::Dir,
    errno::Errno,
    fcntl::{AtFlags, OFlag, RenameFlags, open, openat, renameat, renameat2},
    sys::stat::{Mode, fstatat, mkdirat},
    unistd::{UnlinkatFlags, geteuid, unlinkat},
};
use sha2::{Digest as _, Sha256};

use crate::{Digest, MAX_METADATA_BYTES, MetadataKind, StoreError};

pub(crate) const PRIVATE_DIR_MODE: u32 = 0o700;
pub(crate) const IMMUTABLE_DIR_MODE: u32 = 0o500;
pub(crate) const PRIVATE_FILE_MODE: u32 = 0o600;
pub(crate) const IMMUTABLE_FILE_MODE: u32 = 0o400;

const DIRECTORY_FLAGS: OFlag = OFlag::O_RDONLY
    .union(OFlag::O_DIRECTORY)
    .union(OFlag::O_NOFOLLOW)
    .union(OFlag::O_CLOEXEC);
const READ_FLAGS: OFlag = OFlag::O_RDONLY
    .union(OFlag::O_NOFOLLOW)
    .union(OFlag::O_CLOEXEC);

pub(crate) fn open_absolute_dir_no_symlinks(path: &Path) -> Result<File, StoreError> {
    if !path.is_absolute() {
        return Err(StoreError::InvalidRoot {
            path: path.to_path_buf(),
            reason: "path is not absolute".into(),
        });
    }
    let root_fd = open(Path::new("/"), DIRECTORY_FLAGS, Mode::empty())
        .map_err(|error| StoreError::io("open filesystem root", "/", io::Error::from(error)))?;
    let mut current = File::from(root_fd);
    let mut walked = PathBuf::from("/");
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                walked.push(name);
                let next =
                    openat(&current, name, DIRECTORY_FLAGS, Mode::empty()).map_err(|error| {
                        if matches!(error, Errno::ELOOP | Errno::ENOTDIR) {
                            StoreError::Symlink {
                                path: walked.clone(),
                            }
                        } else {
                            StoreError::io("open directory component", path, io::Error::from(error))
                        }
                    })?;
                current = File::from(next);
            }
            Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                return Err(StoreError::InvalidRoot {
                    path: path.to_path_buf(),
                    reason: "path is not normalized".into(),
                });
            }
        }
    }
    Ok(current)
}

pub(crate) fn initialize_absolute_dir(path: &Path) -> Result<File, StoreError> {
    initialize_absolute_dir_inner(path, true)
}

/// Create a new root and fail without modifying anything if its final path
/// already exists. This is used by CLI acquisition so a pre-existing corrupt
/// or unrelated directory is never repaired into a store implicitly.
pub(crate) fn initialize_absent_absolute_dir(path: &Path) -> Result<File, StoreError> {
    initialize_absolute_dir_inner(path, false)
}

fn initialize_absolute_dir_inner(path: &Path, permit_existing: bool) -> Result<File, StoreError> {
    let parent = path.parent().ok_or_else(|| StoreError::InvalidRoot {
        path: path.to_path_buf(),
        reason: "store root has no parent".into(),
    })?;
    let name = path.file_name().ok_or_else(|| StoreError::InvalidRoot {
        path: path.to_path_buf(),
        reason: "store root has no final component".into(),
    })?;
    let parent_fd = open_absolute_dir_no_symlinks(parent)?;
    let created = match mkdirat(&parent_fd, name, Mode::from_bits_truncate(PRIVATE_DIR_MODE)) {
        Ok(()) => true,
        Err(Errno::EEXIST) if permit_existing => false,
        Err(Errno::EEXIST) => {
            return Err(StoreError::InvalidRoot {
                path: path.to_path_buf(),
                reason: "store initialization requires an absent root".into(),
            });
        }
        Err(error) => {
            return Err(StoreError::io(
                "create store root",
                path,
                io::Error::from(error),
            ));
        }
    };
    let root = open_dir_at(&parent_fd, name, path)?;
    if created {
        set_mode(&root, PRIVATE_DIR_MODE, path)?;
        root.sync_all()
            .map_err(|error| StoreError::io("sync new store root", path, error))?;
        parent_fd
            .sync_all()
            .map_err(|error| StoreError::io("sync store parent", parent, error))?;
    }
    Ok(root)
}

pub(crate) fn open_absolute_regular_no_symlinks(path: &Path) -> Result<File, StoreError> {
    let parent = path.parent().ok_or_else(|| StoreError::InvalidInput {
        field: "file path",
        reason: "path has no parent".into(),
    })?;
    let name = path.file_name().ok_or_else(|| StoreError::InvalidInput {
        field: "file path",
        reason: "path has no final component".into(),
    })?;
    let parent_fd = open_absolute_dir_no_symlinks(parent)?;
    open_regular_at(&parent_fd, name, path)
}

pub(crate) fn validate_private_root(file: &File, path: &Path) -> Result<(u64, u64), StoreError> {
    let metadata = file
        .metadata()
        .map_err(|error| StoreError::io("stat store root", path, error))?;
    if !metadata.is_dir() {
        return Err(StoreError::InvalidRoot {
            path: path.to_path_buf(),
            reason: "root is not a directory".into(),
        });
    }
    let mode = metadata.mode() & 0o7777;
    if mode != PRIVATE_DIR_MODE {
        return Err(StoreError::InvalidRoot {
            path: path.to_path_buf(),
            reason: format!("mode is {mode:#o}; required mode is {PRIVATE_DIR_MODE:#o}"),
        });
    }
    let expected_uid = geteuid().as_raw();
    if metadata.uid() != expected_uid {
        return Err(StoreError::InvalidRoot {
            path: path.to_path_buf(),
            reason: format!(
                "owner UID is {}; required effective UID is {expected_uid}",
                metadata.uid()
            ),
        });
    }
    Ok((metadata.dev(), metadata.ino()))
}

pub(crate) fn ensure_private_dir(
    parent: &File,
    name: &str,
    path: &Path,
    device: u64,
) -> Result<File, StoreError> {
    let created = match mkdirat(parent, name, Mode::from_bits_truncate(PRIVATE_DIR_MODE)) {
        Ok(()) => true,
        Err(Errno::EEXIST) => false,
        Err(error) => {
            return Err(StoreError::io(
                "create store directory",
                path,
                io::Error::from(error),
            ));
        }
    };
    let directory = open_dir_at(parent, name, path)?;
    if created {
        set_mode(&directory, PRIVATE_DIR_MODE, path)?;
        directory
            .sync_all()
            .map_err(|error| StoreError::io("sync new store directory", path, error))?;
        parent
            .sync_all()
            .map_err(|error| StoreError::io("sync store layout", path, error))?;
    }
    validate_directory(&directory, path, device, PRIVATE_DIR_MODE)?;
    Ok(directory)
}

pub(crate) fn create_private_dir(
    parent: &File,
    name: &str,
    path: &Path,
    device: u64,
) -> Result<File, StoreError> {
    mkdirat(parent, name, Mode::from_bits_truncate(PRIVATE_DIR_MODE)).map_err(|error| {
        StoreError::io("create private directory", path, io::Error::from(error))
    })?;
    let directory = open_dir_at(parent, name, path)?;
    set_mode(&directory, PRIVATE_DIR_MODE, path)?;
    validate_directory(&directory, path, device, PRIVATE_DIR_MODE)?;
    parent
        .sync_all()
        .map_err(|error| StoreError::io("sync parent directory", path, error))?;
    Ok(directory)
}

pub(crate) fn open_dir_at(
    parent: &File,
    name: impl AsRef<OsStr>,
    path: &Path,
) -> Result<File, StoreError> {
    openat(parent, name.as_ref(), DIRECTORY_FLAGS, Mode::empty())
        .map(File::from)
        .map_err(|error| {
            if matches!(error, Errno::ELOOP | Errno::ENOTDIR) {
                StoreError::Symlink {
                    path: path.to_path_buf(),
                }
            } else {
                StoreError::io("open directory", path, io::Error::from(error))
            }
        })
}

pub(crate) fn open_regular_at(
    parent: &File,
    name: impl AsRef<OsStr>,
    path: &Path,
) -> Result<File, StoreError> {
    openat(parent, name.as_ref(), READ_FLAGS, Mode::empty())
        .map(File::from)
        .map_err(|error| {
            if error == Errno::ELOOP {
                StoreError::Symlink {
                    path: path.to_path_buf(),
                }
            } else {
                StoreError::io("open regular file", path, io::Error::from(error))
            }
        })
}

pub(crate) fn create_regular_at(
    parent: &File,
    name: &str,
    path: &Path,
) -> Result<File, StoreError> {
    let flags =
        OFlag::O_RDWR | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
    let file = openat(
        parent,
        name,
        flags,
        Mode::from_bits_truncate(PRIVATE_FILE_MODE),
    )
    .map(File::from)
    .map_err(|error| StoreError::io("create regular file", path, io::Error::from(error)))?;
    set_mode(&file, PRIVATE_FILE_MODE, path)?;
    Ok(file)
}

pub(crate) fn validate_directory(
    file: &File,
    path: &Path,
    device: u64,
    mode: u32,
) -> Result<Metadata, StoreError> {
    let metadata = file
        .metadata()
        .map_err(|error| StoreError::io("stat directory", path, error))?;
    if !metadata.is_dir() {
        return Err(StoreError::UnexpectedEntry {
            path: path.to_path_buf(),
        });
    }
    validate_common_metadata(&metadata, path, device, mode)?;
    Ok(metadata)
}

pub(crate) fn validate_regular(
    file: &File,
    path: &Path,
    device: u64,
    mode: u32,
) -> Result<Metadata, StoreError> {
    let metadata = file
        .metadata()
        .map_err(|error| StoreError::io("stat regular file", path, error))?;
    if !metadata.is_file() || metadata.nlink() != 1 {
        return Err(StoreError::UnexpectedEntry {
            path: path.to_path_buf(),
        });
    }
    validate_common_metadata(&metadata, path, device, mode)?;
    Ok(metadata)
}

fn validate_common_metadata(
    metadata: &Metadata,
    path: &Path,
    device: u64,
    mode: u32,
) -> Result<(), StoreError> {
    if metadata.dev() != device {
        return Err(StoreError::CrossDevice {
            path: path.to_path_buf(),
            expected: device,
            actual: metadata.dev(),
        });
    }
    if metadata.uid() != geteuid().as_raw() {
        return Err(StoreError::UnexpectedEntry {
            path: path.to_path_buf(),
        });
    }
    if metadata.mode() & 0o7777 != mode {
        return Err(StoreError::UnexpectedEntry {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

pub(crate) fn set_mode(file: &File, mode: u32, path: &Path) -> Result<(), StoreError> {
    file.set_permissions(Permissions::from_mode(mode))
        .map_err(|error| StoreError::io("set permissions", path, error))
}

pub(crate) fn read_bounded(
    mut file: File,
    path: &Path,
    kind: MetadataKind,
) -> Result<Vec<u8>, StoreError> {
    let mut bytes = Vec::new();
    let mut limited = (&mut file).take((MAX_METADATA_BYTES + 1) as u64);
    limited
        .read_to_end(&mut bytes)
        .map_err(|error| StoreError::io("read metadata", path, error))?;
    if bytes.len() > MAX_METADATA_BYTES {
        return Err(StoreError::MetadataTooLarge {
            kind,
            path: path.to_path_buf(),
            maximum: MAX_METADATA_BYTES,
        });
    }
    Ok(bytes)
}

pub(crate) fn write_new_synced(
    parent: &File,
    name: &str,
    path: &Path,
    bytes: &[u8],
    final_mode: u32,
) -> Result<File, StoreError> {
    if bytes.len() > MAX_METADATA_BYTES {
        return Err(StoreError::MetadataTooLarge {
            kind: MetadataKind::Store,
            path: path.to_path_buf(),
            maximum: MAX_METADATA_BYTES,
        });
    }
    let mut file = create_regular_at(parent, name, path)?;
    file.write_all(bytes)
        .map_err(|error| StoreError::io("write metadata", path, error))?;
    file.sync_all()
        .map_err(|error| StoreError::io("sync metadata contents", path, error))?;
    set_mode(&file, final_mode, path)?;
    file.sync_all()
        .map_err(|error| StoreError::io("sync metadata permissions", path, error))?;
    Ok(file)
}

/// Whether this errno means the filesystem has no `RENAME_NOREPLACE` at all,
/// rather than that this particular rename was refused.
///
/// NFS (`fs/nfs/dir.c`), 9p and FUSE answer `EINVAL` to any rename flag they
/// do not implement; a pre-3.15 kernel has no `renameat2` syscall and answers
/// `ENOSYS`; some stacking layers answer `EOPNOTSUPP`. `ENOTSUP` is an alias
/// of `EOPNOTSUPP`, so naming both would not compile.
const fn lacks_rename_noreplace(error: Errno) -> bool {
    matches!(error, Errno::EINVAL | Errno::ENOSYS | Errno::EOPNOTSUPP)
}

/// Publish `old_name` as `new_name` without ever replacing an existing entry.
///
/// A `$HOME` on NFS is ordinary in university and corporate fleets -- exactly
/// the rootless, no-mount-control environment this runtime targets -- and NFS,
/// 9p and FUSE reject `RENAME_NOREPLACE` outright. Without a fallback, store
/// initialization died there with an opaque `EINVAL` and no diagnosis at all.
///
/// What the fallback gives up, stated rather than hidden: the check and the
/// rename become two steps instead of one, so the kernel no longer enforces
/// non-replacement against a writer outside this process. What still holds is
/// exclusion against another Pocket process, which reaches every one of these
/// publications while holding the per-derivation build lock or the exclusive
/// roots lock.
///
/// Deliberately NOT a `link` plus `unlink` for regular files, even though each
/// of those is individually atomic: that pair leaves the published name and the
/// temporary sharing one inode, and `validate_regular` rejects `nlink != 1`, so
/// a crash or a failed unlink between the two -- an NFS server hiccup, on the
/// very filesystem this exists for -- would leave `init.lock` permanently
/// unopenable and the store unrecoverable. A rename has no such durable
/// intermediate state.
pub(crate) fn rename_noreplace_at(
    old_parent: &File,
    old_name: &str,
    new_parent: &File,
    new_name: &str,
    path: &Path,
) -> Result<(), StoreError> {
    match renameat2(
        old_parent,
        old_name,
        new_parent,
        new_name,
        RenameFlags::RENAME_NOREPLACE,
    ) {
        Ok(()) => return Ok(()),
        Err(error) if lacks_rename_noreplace(error) => {}
        Err(error) => {
            return Err(StoreError::io(
                "publish without replacement",
                path,
                io::Error::from(error),
            ));
        }
    }
    rename_checked_noreplace_at(old_parent, old_name, new_parent, new_name, path)
}

/// Refuse an existing destination, then rename onto it.
///
/// Reported exactly as the flag reports it: several callers reconcile a
/// concurrent identical publication by matching `io::ErrorKind::AlreadyExists`.
fn rename_checked_noreplace_at(
    old_parent: &File,
    old_name: &str,
    new_parent: &File,
    new_name: &str,
    path: &Path,
) -> Result<(), StoreError> {
    match fstatat(new_parent, new_name, AtFlags::AT_SYMLINK_NOFOLLOW) {
        Ok(_) => {
            return Err(StoreError::io(
                "publish without replacement",
                path,
                io::Error::from(Errno::EEXIST),
            ));
        }
        Err(Errno::ENOENT) => {}
        Err(error) => {
            return Err(StoreError::io(
                "publish without replacement",
                path,
                io::Error::from(error),
            ));
        }
    }
    renameat(old_parent, old_name, new_parent, new_name).map_err(|error| {
        StoreError::io("publish without replacement", path, io::Error::from(error))
    })
}

pub(crate) fn rename_replace_at(
    old_parent: &File,
    old_name: &str,
    new_parent: &File,
    new_name: &str,
    path: &Path,
) -> Result<(), StoreError> {
    renameat(old_parent, old_name, new_parent, new_name)
        .map_err(|error| StoreError::io("replace atomically", path, io::Error::from(error)))
}

pub(crate) fn unlink_file_at(
    parent: &File,
    name: impl AsRef<OsStr>,
    path: &Path,
) -> Result<(), StoreError> {
    unlinkat(parent, name.as_ref(), UnlinkatFlags::NoRemoveDir)
        .map_err(|error| StoreError::io("unlink file", path, io::Error::from(error)))
}

pub(crate) fn list_names(directory: &File, path: &Path) -> Result<Vec<OsString>, StoreError> {
    let cloned = directory
        .try_clone()
        .map_err(|error| StoreError::io("clone directory descriptor", path, error))?;
    let owned: OwnedFd = cloned.into();
    let mut directory = Dir::from_fd(owned)
        .map_err(|error| StoreError::io("open directory stream", path, io::Error::from(error)))?;
    let mut names = Vec::new();
    for entry in directory.iter() {
        let entry = entry
            .map_err(|error| StoreError::io("read directory", path, io::Error::from(error)))?;
        let name = entry.file_name().to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        names.push(OsString::from_vec(name.to_vec()));
    }
    names.sort();
    Ok(names)
}

pub(crate) fn remove_tree_at(
    parent: &File,
    name: &OsStr,
    path: &Path,
    device: u64,
) -> Result<(), StoreError> {
    match open_dir_at(parent, name, path) {
        Ok(directory) => {
            let metadata = directory
                .metadata()
                .map_err(|error| StoreError::io("stat removal directory", path, error))?;
            if metadata.dev() != device || metadata.uid() != geteuid().as_raw() {
                return Err(StoreError::UnexpectedEntry {
                    path: path.to_path_buf(),
                });
            }
            set_mode(&directory, PRIVATE_DIR_MODE, path)?;
            for child in list_names(&directory, path)? {
                let child_path = path.join(&child);
                remove_tree_at(&directory, &child, &child_path, device)?;
            }
            directory
                .sync_all()
                .map_err(|error| StoreError::io("sync emptied directory", path, error))?;
            unlinkat(parent, name, UnlinkatFlags::RemoveDir).map_err(|error| {
                StoreError::io("remove directory", path, io::Error::from(error))
            })?;
        }
        // `open_dir_at` already turns ENOTDIR and ELOOP into `Symlink`, so this
        // is the one arm that sees "not a directory": a regular file, or a
        // symlink, either of which is unlinked rather than descended into.
        Err(StoreError::Symlink { .. }) => unlink_file_at(parent, name, path)?,
        Err(error) => return Err(error),
    }
    parent
        .sync_all()
        .map_err(|error| StoreError::io("sync removal parent", path, error))
}

pub(crate) fn hash_file(file: &File, path: &Path) -> Result<(Digest, u64), StoreError> {
    let mut hasher = Sha256::new();
    let mut size = 0_u64;
    let mut buffer = [0_u8; 128 * 1024];
    loop {
        let read = file
            .read_at(&mut buffer, size)
            .map_err(|error| StoreError::io("hash file", path, error))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        size = size
            .checked_add(u64::try_from(read).expect("read length fits u64"))
            .ok_or_else(|| StoreError::SizeMismatch {
                path: path.to_path_buf(),
                expected: u64::MAX,
                actual: u64::MAX,
            })?;
    }
    Ok((Digest::from_bytes(hasher.finalize().into()), size))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open_dir(path: &Path) -> File {
        File::from(open(path, DIRECTORY_FLAGS, Mode::empty()).expect("open directory"))
    }

    /// NFS, 9p and FUSE reject `RENAME_NOREPLACE` outright, so the fallback is
    /// the only publication path a store on such a filesystem ever takes. It
    /// cannot be reached on this host's tmpfs, which implements the flag, so it
    /// is exercised directly.
    #[test]
    fn the_publication_fallback_publishes_once_and_refuses_to_replace() {
        let temporary = tempfile::tempdir().expect("temporary root");
        let root = temporary.path();
        let parent = open_dir(root);

        // A regular file publishes, and leaves no temporary and no second link
        // behind. `validate_regular` rejects `nlink != 1`, so a fallback that
        // left one would make the published record permanently unopenable.
        std::fs::write(root.join(".tmp-record"), b"published").expect("stage a record");
        rename_checked_noreplace_at(
            &parent,
            ".tmp-record",
            &parent,
            "record",
            &root.join("record"),
        )
        .expect("publish a regular file");
        assert_eq!(
            std::fs::read(root.join("record")).expect("read published"),
            b"published"
        );
        assert!(
            !root.join(".tmp-record").exists(),
            "the temporary must be gone"
        );
        assert_eq!(
            std::fs::metadata(root.join("record"))
                .expect("stat")
                .nlink(),
            1,
            "a published record must never be left hard-linked to a temporary"
        );

        // Publishing over an existing name is refused and reported as
        // AlreadyExists: callers reconcile a concurrent identical publication
        // by matching exactly that.
        std::fs::write(root.join(".tmp-second"), b"other").expect("stage another");
        let error = rename_checked_noreplace_at(
            &parent,
            ".tmp-second",
            &parent,
            "record",
            &root.join("record"),
        )
        .expect_err("publishing over an existing name is refused");
        assert!(
            matches!(&error, StoreError::Io { source, .. } if source.kind() == io::ErrorKind::AlreadyExists),
            "{error:?}"
        );
        assert_eq!(
            std::fs::read(root.join("record")).expect("read published"),
            b"published",
            "the existing entry must be untouched"
        );

        // A directory publishes through the same path.
        std::fs::create_dir(root.join(".tmp-tree")).expect("stage a tree");
        std::fs::write(root.join(".tmp-tree/inner"), b"x").expect("populate the tree");
        rename_checked_noreplace_at(&parent, ".tmp-tree", &parent, "tree", &root.join("tree"))
            .expect("publish a directory");
        assert!(root.join("tree/inner").exists());
        assert!(!root.join(".tmp-tree").exists());

        std::fs::create_dir(root.join(".tmp-tree2")).expect("stage another tree");
        let error =
            rename_checked_noreplace_at(&parent, ".tmp-tree2", &parent, "tree", &root.join("tree"))
                .expect_err("publishing over an existing directory is refused");
        assert!(
            matches!(&error, StoreError::Io { source, .. } if source.kind() == io::ErrorKind::AlreadyExists),
            "{error:?}"
        );
        assert!(
            root.join("tree/inner").exists(),
            "the existing tree survives"
        );
    }

    /// Only an errno that means "this filesystem has no RENAME_NOREPLACE"
    /// may fall back. Anything else is a real failure of this rename and must
    /// keep its own identity.
    #[test]
    fn only_unsupported_flag_errnos_select_the_fallback() {
        for errno in [Errno::EINVAL, Errno::ENOSYS, Errno::EOPNOTSUPP] {
            assert!(lacks_rename_noreplace(errno), "{errno:?}");
        }
        for errno in [
            Errno::EEXIST,
            Errno::ENOENT,
            Errno::EXDEV,
            Errno::EACCES,
            Errno::ENOTEMPTY,
            Errno::EIO,
        ] {
            assert!(!lacks_rename_noreplace(errno), "{errno:?}");
        }
    }
}
