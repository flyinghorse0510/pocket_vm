//! Rebuild a distributable OCI image from a published generation.
//!
//! A generation holds an ext4 filesystem rather than the layers it was built
//! from, so exporting one is not a copy: the layer has to be reconstructed.
//! Two stored sidecars make that possible without privilege and without a
//! guest. `metadata.manifest` records every path with its type, mode, owner,
//! timestamps, device numbers, link targets, extended attributes and content
//! digest, which is exactly what a tar header carries; `image-config.json`
//! holds the original OCI configuration. Only the file *contents* are missing,
//! and `debugfs` reads those out of the image without mounting it.
//!
//! Reconstruction is therefore metadata-faithful by construction: the tar is
//! written from the manifest the builder recorded and the validator checked,
//! not from a walk of an extracted tree, which an unprivileged process could
//! not reproduce anyway. Every regular file is verified against the digest the
//! manifest recorded for it as it is written.

use std::{
    collections::BTreeMap,
    io::{self, Write},
    path::Path,
};

use pocket_protocol::ManifestEntry;
use sha2::{Digest, Sha256};

/// A tar member's type, as the manifest records it.
pub const KIND_FILE: u8 = 1;
pub const KIND_DIRECTORY: u8 = 2;
pub const KIND_SYMLINK: u8 = 3;
pub const KIND_CHAR_DEVICE: u8 = 4;
pub const KIND_BLOCK_DEVICE: u8 = 5;
pub const KIND_FIFO: u8 = 6;
pub const KIND_SOCKET: u8 = 7;

const BLOCK: usize = 512;
const NAME_FIELD: usize = 100;
const LINK_FIELD: usize = 100;

/// Decode the stored `metadata.manifest`.
///
/// The builder streams it as a four-byte big-endian length before each
/// canonical CBOR entry, and the host appends those bytes verbatim, so the
/// file on disk is that framing end to end.
pub fn decode_manifest(bytes: &[u8]) -> Result<Vec<ManifestEntry>, String> {
    let mut entries = Vec::new();
    let mut offset = 0usize;
    while offset < bytes.len() {
        let remaining = bytes.len() - offset;
        if remaining < 4 {
            return Err(format!("manifest ends inside a length prefix at {offset}"));
        }
        let length = u32::from_be_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]) as usize;
        offset += 4;
        if length == 0 || length > bytes.len() - offset {
            return Err(format!("manifest entry at {offset} claims {length} bytes"));
        }
        let entry: ManifestEntry = pocket_protocol::decode_payload(&bytes[offset..offset + length])
            .map_err(|error| format!("manifest entry at {offset} is not canonical: {error}"))?;
        entries.push(entry);
        offset += length;
    }
    Ok(entries)
}

/// Write one tar archive, hashing it as it goes.
pub struct TarBuilder<W: Write> {
    inner: W,
    digest: Sha256,
    written: u64,
}

impl<W: Write> TarBuilder<W> {
    pub fn new(inner: W) -> Self {
        Self {
            inner,
            digest: Sha256::new(),
            written: 0,
        }
    }

    fn emit(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.inner.write_all(bytes)?;
        self.digest.update(bytes);
        self.written += bytes.len() as u64;
        Ok(())
    }

    fn pad(&mut self) -> io::Result<()> {
        let remainder = (self.written % BLOCK as u64) as usize;
        if remainder != 0 {
            let padding = vec![0_u8; BLOCK - remainder];
            self.emit(&padding)?;
        }
        Ok(())
    }

    /// Finish the archive: two zero blocks, then the digest of everything.
    pub fn finish(mut self) -> io::Result<(W, [u8; 32])> {
        self.emit(&[0_u8; BLOCK * 2])?;
        self.inner.flush()?;
        let digest = self.digest.finalize();
        Ok((self.inner, digest.into()))
    }

    /// Append one manifest entry, with `contents` for a regular file.
    ///
    /// A socket has no tar representation and is skipped, which is what every
    /// other image tool does with one.
    pub fn append(&mut self, entry: &ManifestEntry, contents: &[u8]) -> io::Result<bool> {
        if entry.kind == KIND_SOCKET {
            return Ok(false);
        }
        let mut path = entry.path.clone();
        if entry.kind == KIND_DIRECTORY && !path.ends_with(b"/") {
            path.push(b'/');
        }
        let link = entry
            .hardlink_target
            .clone()
            .or_else(|| entry.symlink_target.clone())
            .unwrap_or_default();

        // A PAX header carries whatever will not fit, or is not expressible,
        // in the historical fixed-width fields.
        let mut records: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
        if path.len() > NAME_FIELD {
            records.insert(b"path".to_vec(), path.clone());
        }
        if link.len() > LINK_FIELD {
            records.insert(b"linkpath".to_vec(), link.clone());
        }
        if entry.mtime_nanoseconds != 0 {
            records.insert(
                b"mtime".to_vec(),
                format!("{}.{:09}", entry.mtime_seconds, entry.mtime_nanoseconds).into_bytes(),
            );
        }
        for xattr in &entry.xattrs {
            let mut key = b"SCHILY.xattr.".to_vec();
            key.extend_from_slice(&xattr.name);
            records.insert(key, xattr.value.clone());
        }
        if !records.is_empty() {
            let payload = encode_pax(&records);
            let mut header = [0_u8; BLOCK];
            write_field(&mut header[0..100], b"PaxHeaders/0");
            write_octal(&mut header[100..108], 0o644);
            write_octal(&mut header[108..116], 0);
            write_octal(&mut header[116..124], 0);
            write_octal(&mut header[124..136], payload.len() as u64);
            write_octal(&mut header[136..148], entry.mtime_seconds.max(0) as u64);
            header[156] = b'x';
            finish_header(&mut header);
            self.emit(&header)?;
            self.emit(&payload)?;
            self.pad()?;
        }

        let mut header = [0_u8; BLOCK];
        write_field(&mut header[0..100], &path);
        write_octal(&mut header[100..108], u64::from(entry.mode & 0o7777));
        write_octal(&mut header[108..116], u64::from(entry.uid));
        write_octal(&mut header[116..124], u64::from(entry.gid));
        let body_len = if entry.kind == KIND_FILE && entry.hardlink_target.is_none() {
            contents.len() as u64
        } else {
            0
        };
        write_octal(&mut header[124..136], body_len);
        write_octal(&mut header[136..148], entry.mtime_seconds.max(0) as u64);
        header[156] = match entry.kind {
            KIND_FILE if entry.hardlink_target.is_some() => b'1',
            KIND_FILE => b'0',
            KIND_SYMLINK => b'2',
            KIND_CHAR_DEVICE => b'3',
            KIND_BLOCK_DEVICE => b'4',
            KIND_DIRECTORY => b'5',
            KIND_FIFO => b'6',
            other => return Err(io::Error::other(format!("unknown entry kind {other}"))),
        };
        write_field(&mut header[157..257], &link);
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        if matches!(entry.kind, KIND_CHAR_DEVICE | KIND_BLOCK_DEVICE) {
            write_octal(&mut header[329..337], (entry.rdev >> 8) & 0xfff);
            write_octal(
                &mut header[337..345],
                (entry.rdev & 0xff) | ((entry.rdev >> 12) & 0xfff00),
            );
        }
        finish_header(&mut header);
        self.emit(&header)?;
        if body_len > 0 {
            self.emit(contents)?;
            self.pad()?;
        }
        Ok(true)
    }
}

fn encode_pax(records: &BTreeMap<Vec<u8>, Vec<u8>>) -> Vec<u8> {
    let mut payload = Vec::new();
    for (key, value) in records {
        // "%d %s=%s\n", where the length counts itself -- so it is solved by
        // increasing the guess until the printed width stops growing.
        let body = key.len() + value.len() + 3;
        let mut length = body + 1;
        while length.to_string().len() + body != length {
            length += 1;
        }
        payload.extend_from_slice(length.to_string().as_bytes());
        payload.push(b' ');
        payload.extend_from_slice(key);
        payload.push(b'=');
        payload.extend_from_slice(value);
        payload.push(b'\n');
    }
    payload
}

fn write_field(field: &mut [u8], value: &[u8]) {
    let take = value.len().min(field.len() - 1);
    field[..take].copy_from_slice(&value[..take]);
}

fn write_octal(field: &mut [u8], value: u64) {
    let text = format!("{:0width$o}", value, width = field.len() - 1);
    let bytes = text.as_bytes();
    let take = bytes.len().min(field.len() - 1);
    field[..take].copy_from_slice(&bytes[bytes.len() - take..]);
}

/// The checksum is computed with its own field read as spaces.
fn finish_header(header: &mut [u8; BLOCK]) {
    header[148..156].fill(b' ');
    let sum: u32 = header.iter().map(|byte| u32::from(*byte)).sum();
    let text = format!("{sum:06o}\0 ");
    header[148..156].copy_from_slice(text.as_bytes());
}

/// The digest of one blob, formatted the way an OCI descriptor wants it.
pub fn descriptor_digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

/// Verify one extracted file against the digest the manifest recorded.
pub fn content_matches(entry: &ManifestEntry, contents: &[u8]) -> bool {
    match entry.content_sha256.as_deref() {
        Some(expected) => Sha256::digest(contents).as_slice() == expected,
        None => true,
    }
}

/// The path this entry takes inside the exported layer, if it belongs there.
///
/// A generation's filesystem is the image under `rootfs/` beside pocket's own
/// `.pocket-generation.cbor` marker, so the marker, the ext4 root and the
/// `rootfs` directory itself are pocket's bookkeeping rather than image
/// content, and only what lies under `rootfs/` is exported.
pub fn layer_path(entry: &ManifestEntry) -> Option<Vec<u8>> {
    entry
        .path
        .strip_prefix(b"rootfs/".as_slice())
        .filter(|rest| !rest.is_empty())
        .map(<[u8]>::to_vec)
}

/// Where `debugfs` should write one entry's contents, relative to a scratch
/// directory: its index, so no guest-controlled path reaches the host.
pub fn staged_name(index: usize) -> String {
    format!("f{index:08}")
}

/// The `debugfs` command file that extracts every regular file in one run.
///
/// One process rather than one per file: an image with many thousands of files
/// would otherwise spend all of its time on process creation.
pub fn dump_script(entries: &[ManifestEntry], scratch: &Path) -> Vec<u8> {
    let mut script = Vec::new();
    for (index, entry) in entries.iter().enumerate() {
        if entry.kind != KIND_FILE || entry.hardlink_target.is_some() || entry.size == 0 {
            continue;
        }
        if layer_path(entry).is_none() {
            continue;
        }
        script.extend_from_slice(b"dump /");
        script.extend_from_slice(&entry.path);
        script.push(b' ');
        script.extend_from_slice(
            scratch
                .join(staged_name(index))
                .as_os_str()
                .as_encoded_bytes(),
        );
        script.push(b'\n');
    }
    script.extend_from_slice(b"quit\n");
    script
}

impl<W: Write> TarBuilder<W> {
    /// Append a plain regular file, for the archive that carries an OCI layout.
    ///
    /// These members are transport rather than image content, so they carry
    /// the caller's own ids. Recording root would make an unprivileged reader
    /// fail on the `chown` it attempts while unpacking, which is how skopeo
    /// refuses an archive it otherwise understands.
    /// Append a directory, so a reader does not invent one and then try to
    /// give it an owner the caller cannot set.
    pub fn append_dir(&mut self, name: &str) -> io::Result<()> {
        let entry = ManifestEntry {
            path: name.as_bytes().to_vec(),
            kind: KIND_DIRECTORY,
            mode: 0o755,
            uid: nix::unistd::getuid().as_raw(),
            gid: nix::unistd::getgid().as_raw(),
            size: 0,
            rdev: 0,
            mtime_seconds: 0,
            mtime_nanoseconds: 0,
            symlink_target: None,
            content_sha256: None,
            hardlink_target: None,
            xattrs: Vec::new(),
        };
        self.append(&entry, &[]).map(|_| ())
    }

    pub fn append_raw(&mut self, name: &str, contents: &[u8], mode: u32) -> io::Result<()> {
        let entry = ManifestEntry {
            path: name.as_bytes().to_vec(),
            kind: KIND_FILE,
            mode,
            uid: nix::unistd::getuid().as_raw(),
            gid: nix::unistd::getgid().as_raw(),
            size: contents.len() as u64,
            rdev: 0,
            mtime_seconds: 0,
            mtime_nanoseconds: 0,
            symlink_target: None,
            content_sha256: None,
            hardlink_target: None,
            xattrs: Vec::new(),
        };
        self.append(&entry, contents).map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pocket_protocol::ManifestXattr;

    fn entry(path: &str, kind: u8) -> ManifestEntry {
        ManifestEntry {
            path: path.as_bytes().to_vec(),
            kind,
            mode: 0o644,
            uid: 0,
            gid: 0,
            size: 0,
            rdev: 0,
            mtime_seconds: 1_700_000_000,
            mtime_nanoseconds: 0,
            symlink_target: (kind == KIND_SYMLINK).then(|| b"target".to_vec()),
            // The protocol requires a regular file to carry exactly one of a
            // content digest or a hardlink target.
            content_sha256: (kind == KIND_FILE).then(|| Sha256::digest(b"").to_vec()),
            hardlink_target: None,
            xattrs: Vec::new(),
        }
    }

    #[test]
    fn a_header_checksum_is_the_sum_with_its_own_field_blanked() {
        let mut builder = TarBuilder::new(Vec::new());
        builder
            .append(&entry("etc", KIND_DIRECTORY), &[])
            .expect("append entry");
        let (bytes, _) = builder.finish().expect("finish tar");
        let stated = std::str::from_utf8(&bytes[148..154]).expect("checksum field is ascii");
        let mut header: [u8; BLOCK] = bytes[..BLOCK].try_into().expect("one block");
        header[148..156].fill(b' ');
        let sum: u32 = header.iter().map(|byte| u32::from(*byte)).sum();
        assert_eq!(u32::from_str_radix(stated, 8).expect("octal checksum"), sum);
    }

    #[test]
    fn a_directory_is_recorded_with_a_trailing_separator() {
        let mut builder = TarBuilder::new(Vec::new());
        builder
            .append(&entry("etc", KIND_DIRECTORY), &[])
            .expect("append entry");
        let (bytes, _) = builder.finish().expect("finish tar");
        assert!(bytes.starts_with(b"etc/\0"));
        assert_eq!(bytes[156], b'5');
    }

    #[test]
    fn a_long_path_moves_into_a_pax_header() {
        let long = "a".repeat(150);
        let mut builder = TarBuilder::new(Vec::new());
        builder
            .append(&entry(&long, KIND_FILE), &[])
            .expect("append entry");
        let (bytes, _) = builder.finish().expect("finish tar");
        assert_eq!(bytes[156], b'x', "a PAX header must come first");
        let payload = String::from_utf8_lossy(&bytes[BLOCK..BLOCK * 2]);
        assert!(payload.contains(&format!("path={long}")));
    }

    #[test]
    fn an_xattr_becomes_a_schily_record() {
        let mut subject = entry("f", KIND_FILE);
        subject.xattrs = vec![ManifestXattr {
            name: b"user.demo".to_vec(),
            value: b"value".to_vec(),
        }];
        let mut builder = TarBuilder::new(Vec::new());
        builder.append(&subject, &[]).expect("append entry");
        let (bytes, _) = builder.finish().expect("finish tar");
        let payload = String::from_utf8_lossy(&bytes[BLOCK..BLOCK * 2]);
        assert!(
            payload.contains("SCHILY.xattr.user.demo=value"),
            "{payload}"
        );
    }

    #[test]
    fn a_pax_record_length_counts_itself() {
        let mut records = BTreeMap::new();
        records.insert(b"path".to_vec(), vec![b'a'; 100]);
        let payload = encode_pax(&records);
        let text = String::from_utf8(payload.clone()).expect("pax payload is utf8");
        let stated: usize = text
            .split(' ')
            .next()
            .expect("a length")
            .parse()
            .expect("decimal length");
        assert_eq!(stated, payload.len());
    }

    #[test]
    fn a_device_records_its_major_and_minor() {
        let mut subject = entry("dev/null", KIND_CHAR_DEVICE);
        subject.rdev = (1 << 8) | 3; // major 1, minor 3
        let mut builder = TarBuilder::new(Vec::new());
        builder.append(&subject, &[]).expect("append entry");
        let (bytes, _) = builder.finish().expect("finish tar");
        assert_eq!(bytes[156], b'3');
        let major = std::str::from_utf8(&bytes[329..336]).expect("octal field is ascii");
        let minor = std::str::from_utf8(&bytes[337..344]).expect("octal field is ascii");
        assert_eq!(
            u64::from_str_radix(major.trim_end_matches('\0'), 8).expect("octal field"),
            1
        );
        assert_eq!(
            u64::from_str_radix(minor.trim_end_matches('\0'), 8).expect("octal field"),
            3
        );
    }

    #[test]
    fn a_socket_has_no_tar_representation_and_is_skipped() {
        let mut builder = TarBuilder::new(Vec::new());
        assert!(
            !builder
                .append(&entry("s", KIND_SOCKET), &[])
                .expect("append entry")
        );
        let (bytes, _) = builder.finish().expect("finish tar");
        assert!(bytes.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn a_hardlink_carries_its_target_and_no_body() {
        let mut subject = entry("b", KIND_FILE);
        subject.content_sha256 = None;
        subject.hardlink_target = Some(b"a".to_vec());
        let mut builder = TarBuilder::new(Vec::new());
        builder.append(&subject, b"ignored").expect("append entry");
        let (bytes, _) = builder.finish().expect("finish tar");
        assert_eq!(bytes[156], b'1');
        assert_eq!(&bytes[157..158], b"a");
        assert_eq!(
            u64::from_str_radix(
                std::str::from_utf8(&bytes[124..135]).expect("octal field is ascii"),
                8
            )
            .expect("octal field"),
            0
        );
    }

    #[test]
    fn the_archive_ends_with_two_zero_blocks() {
        let mut builder = TarBuilder::new(Vec::new());
        builder
            .append(&entry("f", KIND_FILE), &[])
            .expect("append entry");
        let (bytes, _) = builder.finish().expect("finish tar");
        assert!(
            bytes[bytes.len() - BLOCK * 2..]
                .iter()
                .all(|byte| *byte == 0)
        );
        assert_eq!(bytes.len() % BLOCK, 0);
    }

    #[test]
    fn a_manifest_round_trips_through_its_framing() {
        let entries = vec![entry("etc", KIND_DIRECTORY), entry("etc/passwd", KIND_FILE)];
        let mut encoded = Vec::new();
        for subject in &entries {
            let payload = pocket_protocol::encode_payload(subject).expect("encode entry");
            encoded.extend_from_slice(&(payload.len() as u32).to_be_bytes());
            encoded.extend_from_slice(&payload);
        }
        assert_eq!(decode_manifest(&encoded).expect("decode manifest"), entries);
    }

    #[test]
    fn a_truncated_manifest_is_refused_rather_than_guessed_at() {
        let payload =
            pocket_protocol::encode_payload(&entry("f", KIND_FILE)).expect("encode entry");
        let mut encoded = (payload.len() as u32).to_be_bytes().to_vec();
        encoded.extend_from_slice(&payload[..payload.len() - 1]);
        assert!(decode_manifest(&encoded).is_err());
    }

    #[test]
    fn only_what_lies_under_rootfs_reaches_the_layer() {
        assert_eq!(
            layer_path(&entry("rootfs/bin/sh", KIND_FILE)),
            Some(b"bin/sh".to_vec())
        );
        // pocket's own bookkeeping is not image content.
        assert_eq!(layer_path(&entry("", KIND_DIRECTORY)), None);
        assert_eq!(layer_path(&entry("rootfs", KIND_DIRECTORY)), None);
        assert_eq!(
            layer_path(&entry(".pocket-generation.cbor", KIND_FILE)),
            None
        );
    }

    #[test]
    fn contents_are_checked_against_the_recorded_digest() {
        let mut subject = entry("f", KIND_FILE);
        subject.content_sha256 = Some(Sha256::digest(b"hello").to_vec());
        assert!(content_matches(&subject, b"hello"));
        assert!(!content_matches(&subject, b"goodbye"));
    }

    #[test]
    fn the_dump_script_skips_what_has_no_contents_to_read() {
        let mut file = entry("rootfs/etc/passwd", KIND_FILE);
        file.size = 10;
        let mut link = entry("rootfs/etc/alias", KIND_FILE);
        link.content_sha256 = None;
        link.hardlink_target = Some(b"etc/passwd".to_vec());
        let entries = vec![
            entry("rootfs", KIND_DIRECTORY),
            file,
            link,
            entry("rootfs/e", KIND_FILE),
        ];
        let script =
            String::from_utf8(dump_script(&entries, Path::new("/tmp/x"))).expect("script is utf8");
        assert_eq!(script.matches("dump ").count(), 1);
        assert!(
            script.contains("dump /rootfs/etc/passwd /tmp/x/f00000001"),
            "{script}"
        );
        assert!(script.ends_with("quit\n"));
    }
}
