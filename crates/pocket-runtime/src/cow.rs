use std::{
    fs::{self, File},
    io::Read,
    os::unix::fs::MetadataExt,
    path::Path,
};

use crate::RuntimeError;

const COW_V3_HEADER_BYTES: usize = 32 + 4096;
const COW_MAGIC: u32 = 0x4f4f4f4d;
const COW_VERSION: u32 = 3;

pub(crate) fn validate_fresh_cow(cow: &Path, base: &Path) -> Result<(), RuntimeError> {
    let metadata = fs::symlink_metadata(cow)
        .map_err(|error| RuntimeError::io("inspect UML COW", cow, error))?;
    if !metadata.file_type().is_file() {
        return Err(cow_error(cow, "not a regular file"));
    }
    if metadata.nlink() != 1 {
        return Err(cow_error(cow, "fresh COW has more than one hard link"));
    }
    if metadata.mode() & 0o077 != 0 {
        return Err(cow_error(cow, "fresh COW is accessible outside its owner"));
    }
    if metadata.len() < COW_V3_HEADER_BYTES as u64 {
        return Err(cow_error(cow, "truncated v3 header"));
    }

    let mut bytes = [0_u8; COW_V3_HEADER_BYTES];
    File::open(cow)
        .and_then(|mut file| file.read_exact(&mut bytes))
        .map_err(|error| RuntimeError::io("read UML COW header", cow, error))?;
    let magic = u32::from_be_bytes(
        bytes[0..4]
            .try_into()
            .map_err(|_| cow_error(cow, "invalid magic field"))?,
    );
    let version = u32::from_be_bytes(
        bytes[4..8]
            .try_into()
            .map_err(|_| cow_error(cow, "invalid version field"))?,
    );
    if magic != COW_MAGIC || version != COW_VERSION {
        return Err(cow_error(
            cow,
            format!("expected COW v3 magic/version, observed {magic:#x}/{version}"),
        ));
    }

    let base_metadata = fs::metadata(base)
        .map_err(|error| RuntimeError::io("inspect COW backing image", base, error))?;
    let expected_mtime = u32::try_from(base_metadata.mtime())
        .map_err(|_| cow_error(cow, "backing mtime does not fit the COW v3 field"))?;
    let observed_mtime = u32::from_be_bytes(
        bytes[8..12]
            .try_into()
            .map_err(|_| cow_error(cow, "invalid mtime field"))?,
    );
    let observed_size = u64::from_be_bytes(
        bytes[12..20]
            .try_into()
            .map_err(|_| cow_error(cow, "invalid size field"))?,
    );
    let sector_size = u32::from_be_bytes(
        bytes[20..24]
            .try_into()
            .map_err(|_| cow_error(cow, "invalid sector-size field"))?,
    );
    let alignment = u32::from_be_bytes(
        bytes[24..28]
            .try_into()
            .map_err(|_| cow_error(cow, "invalid alignment field"))?,
    );
    let cow_format = u32::from_ne_bytes(
        bytes[28..32]
            .try_into()
            .map_err(|_| cow_error(cow, "invalid COW-format field"))?,
    );
    if observed_mtime != expected_mtime {
        return Err(cow_error(cow, "backing mtime binding mismatch"));
    }
    if observed_size != base_metadata.len() {
        return Err(cow_error(cow, "backing size binding mismatch"));
    }
    if sector_size != 512 {
        return Err(cow_error(
            cow,
            format!("unsupported sector size {sector_size}"),
        ));
    }
    if !(512..=65536).contains(&alignment) || !alignment.is_power_of_two() {
        return Err(cow_error(cow, format!("invalid COW alignment {alignment}")));
    }
    if cow_format != 0 {
        return Err(cow_error(
            cow,
            format!("unsupported COW bitmap format {cow_format}"),
        ));
    }

    let backing_bytes = &bytes[32..];
    let terminator = backing_bytes
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| cow_error(cow, "backing pathname is not NUL-terminated"))?;
    let expected = base
        .to_str()
        .ok_or_else(|| cow_error(cow, "backing pathname is not UTF-8"))?
        .as_bytes();
    if &backing_bytes[..terminator] != expected {
        return Err(cow_error(cow, "backing pathname binding mismatch"));
    }
    Ok(())
}

fn cow_error(path: &Path, reason: impl Into<String>) -> RuntimeError {
    RuntimeError::Cow {
        path: path.to_path_buf(),
        reason: reason.into(),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        io::Write,
        os::unix::fs::{MetadataExt, PermissionsExt},
    };

    use tempfile::tempdir;

    use super::{COW_MAGIC, COW_V3_HEADER_BYTES, COW_VERSION, validate_fresh_cow};

    #[test]
    fn validates_exact_v3_backing_identity() {
        let directory = tempdir().expect("tempdir");
        let base = directory.path().join("base.ext4");
        fs::write(&base, vec![0_u8; 8192]).expect("base");
        let metadata = fs::metadata(&base).expect("base metadata");
        let cow = directory.path().join("root.cow");
        let mut header = vec![0_u8; COW_V3_HEADER_BYTES];
        header[0..4].copy_from_slice(&COW_MAGIC.to_be_bytes());
        header[4..8].copy_from_slice(&COW_VERSION.to_be_bytes());
        header[8..12].copy_from_slice(&(metadata.mtime() as u32).to_be_bytes());
        header[12..20].copy_from_slice(&metadata.len().to_be_bytes());
        header[20..24].copy_from_slice(&512_u32.to_be_bytes());
        header[24..28].copy_from_slice(&4096_u32.to_be_bytes());
        let name = base.to_str().expect("UTF-8").as_bytes();
        header[32..32 + name.len()].copy_from_slice(name);
        let mut file = fs::File::create(&cow).expect("cow");
        file.write_all(&header).expect("header");
        drop(file);
        fs::set_permissions(&cow, fs::Permissions::from_mode(0o600)).expect("mode");

        assert!(validate_fresh_cow(&cow, &base).is_ok());
        header[32] ^= 1;
        fs::write(&cow, header).expect("mutate");
        assert!(validate_fresh_cow(&cow, &base).is_err());
    }
}
