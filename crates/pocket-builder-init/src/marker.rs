use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::Path,
};

use nix::sys::{
    stat::{UtimensatFlags, utimensat},
    time::TimeSpec,
};
use pocket_protocol::{BuilderStart, GenerationMarker, encode_payload};
use sha2::{Digest as _, Sha256};

use crate::BuilderError;

pub const GENERATION_MARKER_NAME: &str = ".pocket-generation.cbor";
const GENERATION_MARKER_TEMP: &str = ".pocket-generation.cbor.tmp";

pub fn encode_generation_marker(
    start: &BuilderStart,
    account_db_sha256: &str,
) -> Result<Vec<u8>, BuilderError> {
    encode_payload(&GenerationMarker::from_start(
        start,
        account_db_sha256.to_owned(),
    ))
    .map_err(|error| BuilderError::protocol("generation-marker", error))
}

/// Atomically create and fsync the generation marker outside `rootfs`.
/// Existing marker or temporary paths are treated as a dirty target rather
/// than overwritten.
pub fn write_generation_marker(
    target: &Path,
    start: &BuilderStart,
    account_db_sha256: &str,
) -> Result<String, BuilderError> {
    let bytes = encode_generation_marker(start, account_db_sha256)?;
    let final_path = target.join(GENERATION_MARKER_NAME);
    let temporary_path = target.join(GENERATION_MARKER_TEMP);
    require_absent(&final_path)?;
    require_absent(&temporary_path)?;

    let write_result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary_path)
            .map_err(|error| BuilderError::io("generation-marker", error))?;
        file.write_all(&bytes)
            .map_err(|error| BuilderError::io("generation-marker", error))?;
        file.sync_all()
            .map_err(|error| BuilderError::io("generation-marker", error))?;
        fs::rename(&temporary_path, &final_path)
            .map_err(|error| BuilderError::io("generation-marker", error))?;
        File::open(target)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| BuilderError::io("generation-marker", error))?;
        Ok::<(), BuilderError>(())
    })();
    if write_result.is_err() {
        let _ = fs::remove_file(&temporary_path);
    }
    write_result.map_err(|error| error.reclassify(pocket_core::ErrorCode::BuilderMarker))?;

    // The guest clock starts at the derivation-bound epoch but keeps running,
    // so these two inodes -- the only ones the builder creates itself -- would
    // otherwise carry whatever nanosecond the conversion happened to reach.
    // That lands in the filesystem manifest and in the image bytes, and makes
    // two builds of one image two different generations. The directory is
    // pinned last because the rename above is what dirtied it.
    pin_build_time(&final_path, start.source_date_epoch)?;
    pin_build_time(target, start.source_date_epoch)?;
    Ok(hex_lower(&Sha256::digest(bytes)))
}

/// Set one path's access and modification times to the exact build epoch.
fn pin_build_time(path: &Path, source_date_epoch: u64) -> Result<(), BuilderError> {
    let seconds = i64::try_from(source_date_epoch).map_err(|_| {
        BuilderError::contract("generation-marker", "source-date epoch does not fit time_t")
    })?;
    let stamp = TimeSpec::new(seconds, 0);
    // Both paths are absolute, so the directory descriptor is unused; CWD is
    // the conventional stand-in.
    utimensat(
        std::fs::File::open("/").map_err(|error| BuilderError::io("generation-marker", error))?,
        path,
        &stamp,
        &stamp,
        UtimensatFlags::NoFollowSymlink,
    )
    .map_err(|error| {
        BuilderError::syscall("generation-marker", error)
            .reclassify(pocket_core::ErrorCode::BuilderMarker)
    })
}

fn require_absent(path: &Path) -> Result<(), BuilderError> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(BuilderError::io("generation-marker", error)),
        Ok(_) => Err(BuilderError::failure(
            "generation-marker",
            pocket_core::ErrorCode::BuilderTargetDirty,
            None,
            format!("refusing to replace existing {}", path.display()),
        )),
    }
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
    use std::fs;

    use minicbor::Decoder;
    use pocket_protocol::{GenerationMarker, ValidateMessage};
    use tempfile::TempDir;

    use crate::input::tests::fixture;

    use super::{GENERATION_MARKER_NAME, write_generation_marker};

    #[test]
    fn writes_canonical_compatible_marker_once() {
        let target = TempDir::new().expect("tempdir");
        let (_input, start) = fixture();
        let account_digest = "ab".repeat(32);
        let digest =
            write_generation_marker(target.path(), &start, &account_digest).expect("marker");
        assert_eq!(digest.len(), 64);
        let bytes = fs::read(target.path().join(GENERATION_MARKER_NAME)).expect("read marker");
        // The two inodes the builder creates itself must not carry the clock:
        // a nanosecond of conversion timing would otherwise reach the
        // filesystem manifest and make one image two generations.
        for path in [
            target.path().join(GENERATION_MARKER_NAME),
            target.path().to_path_buf(),
        ] {
            let modified = fs::symlink_metadata(&path)
                .expect("stat pinned path")
                .modified()
                .expect("modification time");
            let since_epoch = modified
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time after the epoch");
            assert_eq!(
                (since_epoch.as_secs(), since_epoch.subsec_nanos()),
                (start.source_date_epoch, 0),
                "{} was not pinned to the build epoch",
                path.display()
            );
        }
        let mut decoder = Decoder::new(&bytes);
        let marker = decoder.decode::<GenerationMarker>().expect("decode marker");
        assert_eq!(decoder.position(), bytes.len());
        assert!(marker.validate().is_ok());
        assert_eq!(marker.derivation_key, start.derivation_key);
        assert_eq!(marker.account_db_sha256, account_digest);
        assert!(write_generation_marker(target.path(), &start, &account_digest).is_err());
    }
}
