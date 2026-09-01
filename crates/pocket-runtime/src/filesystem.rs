use std::{
    fs::{self, File},
    io::{Read, Seek, SeekFrom},
    path::Path,
};

use crate::RuntimeError;

const EXT_SUPERBLOCK_OFFSET: u64 = 1024;
const EXT_SUPERBLOCK_BYTES: usize = 1024;
const EXT_SUPER_MAGIC: u16 = 0xef53;
const EXT4_VALID_FS: u16 = 0x0001;
const EXT4_ERROR_FS: u16 = 0x0002;
const EXT4_FEATURE_INCOMPAT_RECOVER: u32 = 0x0004;
const EXT4_FEATURE_INCOMPAT_64BIT: u32 = 0x0080;

pub(crate) fn validate_ext4_base(path: &Path) -> Result<(), RuntimeError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| RuntimeError::io("inspect ext4 base", path, error))?;
    if !metadata.file_type().is_file() {
        return Err(invalid(path, "base is not a regular file"));
    }
    if metadata.len() < EXT_SUPERBLOCK_OFFSET + EXT_SUPERBLOCK_BYTES as u64 {
        return Err(invalid(path, "base is too small for an ext superblock"));
    }
    let mut superblock = [0_u8; EXT_SUPERBLOCK_BYTES];
    let mut file =
        File::open(path).map_err(|error| RuntimeError::io("open ext4 base", path, error))?;
    file.seek(SeekFrom::Start(EXT_SUPERBLOCK_OFFSET))
        .and_then(|_| file.read_exact(&mut superblock))
        .map_err(|error| RuntimeError::io("read ext4 superblock", path, error))?;

    let magic = le_u16(&superblock, 0x38, path)?;
    if magic != EXT_SUPER_MAGIC {
        return Err(invalid(
            path,
            format!("expected ext magic {EXT_SUPER_MAGIC:#06x}, observed {magic:#06x}"),
        ));
    }
    let log_block_size = le_u32(&superblock, 0x18, path)?;
    let block_size = 1024_u64
        .checked_shl(log_block_size)
        .ok_or_else(|| invalid(path, "block-size shift overflows"))?;
    if block_size != 4096 {
        return Err(invalid(
            path,
            format!("filesystem contract requires 4096-byte blocks, observed {block_size}"),
        ));
    }
    let state = le_u16(&superblock, 0x3a, path)?;
    if state & EXT4_VALID_FS == 0 || state & EXT4_ERROR_FS != 0 {
        return Err(invalid(
            path,
            format!("filesystem state is not clean ({state:#06x})"),
        ));
    }
    let incompat = le_u32(&superblock, 0x60, path)?;
    if incompat & EXT4_FEATURE_INCOMPAT_RECOVER != 0 {
        return Err(invalid(path, "filesystem requires journal recovery"));
    }
    let blocks_low = u64::from(le_u32(&superblock, 0x04, path)?);
    let blocks_high = if incompat & EXT4_FEATURE_INCOMPAT_64BIT != 0 {
        u64::from(le_u32(&superblock, 0x150, path)?)
    } else {
        0
    };
    let blocks = blocks_low | (blocks_high << 32);
    if blocks == 0 {
        return Err(invalid(path, "filesystem declares zero blocks"));
    }
    let logical_bytes = blocks
        .checked_mul(block_size)
        .ok_or_else(|| invalid(path, "filesystem logical size overflows"))?;
    if logical_bytes > metadata.len() {
        return Err(invalid(
            path,
            format!(
                "filesystem declares {logical_bytes} bytes but base file has {}",
                metadata.len()
            ),
        ));
    }
    if superblock[0x68..0x78].iter().all(|byte| *byte == 0) {
        return Err(invalid(path, "filesystem UUID is all zero"));
    }
    Ok(())
}

fn le_u16(bytes: &[u8], offset: usize, path: &Path) -> Result<u16, RuntimeError> {
    let field = bytes
        .get(offset..offset + 2)
        .ok_or_else(|| invalid(path, "truncated u16 superblock field"))?;
    Ok(u16::from_le_bytes(field.try_into().map_err(|_| {
        invalid(path, "malformed u16 superblock field")
    })?))
}

fn le_u32(bytes: &[u8], offset: usize, path: &Path) -> Result<u32, RuntimeError> {
    let field = bytes
        .get(offset..offset + 4)
        .ok_or_else(|| invalid(path, "truncated u32 superblock field"))?;
    Ok(u32::from_le_bytes(field.try_into().map_err(|_| {
        invalid(path, "malformed u32 superblock field")
    })?))
}

fn invalid(path: &Path, reason: impl Into<String>) -> RuntimeError {
    RuntimeError::InvalidConfiguration {
        field: "ext4_base",
        reason: format!("{}: {}", path.display(), reason.into()),
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Seek, SeekFrom, Write};

    use tempfile::tempdir;

    use super::{EXT_SUPER_MAGIC, EXT4_VALID_FS, validate_ext4_base};

    #[test]
    fn requires_clean_4096_byte_ext_filesystem_contract() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("base.ext4");
        let mut file = std::fs::File::create(&path).expect("base");
        file.set_len(4096 * 8).expect("size");
        let mut superblock = [0_u8; 1024];
        superblock[0x04..0x08].copy_from_slice(&8_u32.to_le_bytes());
        superblock[0x18..0x1c].copy_from_slice(&2_u32.to_le_bytes());
        superblock[0x38..0x3a].copy_from_slice(&EXT_SUPER_MAGIC.to_le_bytes());
        superblock[0x3a..0x3c].copy_from_slice(&EXT4_VALID_FS.to_le_bytes());
        superblock[0x68] = 1;
        file.seek(SeekFrom::Start(1024)).expect("seek");
        file.write_all(&superblock).expect("superblock");
        drop(file);
        assert!(validate_ext4_base(&path).is_ok());

        superblock[0x18..0x1c].copy_from_slice(&0_u32.to_le_bytes());
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("open");
        file.seek(SeekFrom::Start(1024)).expect("seek");
        file.write_all(&superblock).expect("superblock");
        assert!(validate_ext4_base(&path).is_err());
    }
}
