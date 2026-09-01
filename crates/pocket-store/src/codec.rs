use sha2::{Digest as _, Sha256};

use crate::{MAX_METADATA_BYTES, MetadataKind, STORE_SCHEMA_VERSION, StoreError};

pub(crate) const CHECKSUM_BYTES: usize = 32;

pub(crate) fn finish_record(mut bytes: Vec<u8>) -> Vec<u8> {
    let checksum = Sha256::digest(&bytes);
    bytes.extend_from_slice(&checksum);
    bytes
}

pub(crate) fn start_record(magic: &[u8; 8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(256);
    bytes.extend_from_slice(magic);
    put_u16(&mut bytes, STORE_SCHEMA_VERSION);
    bytes
}

pub(crate) fn verify_record<'a>(
    bytes: &'a [u8],
    magic: &[u8; 8],
    kind: MetadataKind,
) -> Result<Reader<'a>, StoreError> {
    if bytes.len() > MAX_METADATA_BYTES {
        return Err(StoreError::MetadataTooLarge {
            kind,
            path: "<memory>".into(),
            maximum: MAX_METADATA_BYTES,
        });
    }
    if bytes.len() < magic.len() + 2 + CHECKSUM_BYTES {
        return Err(StoreError::metadata(
            kind,
            "<memory>",
            "record is truncated",
        ));
    }
    let payload_len = bytes.len() - CHECKSUM_BYTES;
    let expected = Sha256::digest(&bytes[..payload_len]);
    if expected.as_slice() != &bytes[payload_len..] {
        return Err(StoreError::metadata(kind, "<memory>", "checksum mismatch"));
    }

    let mut reader = Reader::new(&bytes[..payload_len]);
    if reader.take(8)? != magic {
        return Err(StoreError::metadata(kind, "<memory>", "wrong record magic"));
    }
    let version = reader.u16()?;
    if version != STORE_SCHEMA_VERSION {
        return Err(StoreError::metadata(
            kind,
            "<memory>",
            format!("unsupported schema version {version}"),
        ));
    }
    Ok(reader)
}

pub(crate) fn put_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_be_bytes());
}

pub(crate) fn put_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_be_bytes());
}

pub(crate) fn put_u64(output: &mut Vec<u8>, value: u64) {
    output.extend_from_slice(&value.to_be_bytes());
}

pub(crate) fn put_bytes(output: &mut Vec<u8>, value: &[u8]) {
    let length = u32::try_from(value.len()).expect("validated metadata length fits in u32");
    put_u32(output, length);
    output.extend_from_slice(value);
}

pub(crate) fn put_text(output: &mut Vec<u8>, value: &str) {
    put_bytes(output, value.as_bytes());
}

pub(crate) fn put_optional_text(output: &mut Vec<u8>, value: Option<&str>) {
    match value {
        Some(value) => {
            output.push(1);
            put_text(output, value);
        }
        None => output.push(0),
    }
}

pub(crate) struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    pub(crate) const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    pub(crate) fn take(&mut self, length: usize) -> Result<&'a [u8], StoreError> {
        let end = self.offset.checked_add(length).ok_or_else(|| {
            StoreError::metadata(MetadataKind::Store, "<memory>", "length overflow")
        })?;
        let value = self.bytes.get(self.offset..end).ok_or_else(|| {
            StoreError::metadata(MetadataKind::Store, "<memory>", "record is truncated")
        })?;
        self.offset = end;
        Ok(value)
    }

    pub(crate) fn u8(&mut self) -> Result<u8, StoreError> {
        Ok(self.take(1)?[0])
    }

    pub(crate) fn u16(&mut self) -> Result<u16, StoreError> {
        let bytes: [u8; 2] = self
            .take(2)?
            .try_into()
            .map_err(|_| StoreError::metadata(MetadataKind::Store, "<memory>", "invalid u16"))?;
        Ok(u16::from_be_bytes(bytes))
    }

    pub(crate) fn u32(&mut self) -> Result<u32, StoreError> {
        let bytes: [u8; 4] = self
            .take(4)?
            .try_into()
            .map_err(|_| StoreError::metadata(MetadataKind::Store, "<memory>", "invalid u32"))?;
        Ok(u32::from_be_bytes(bytes))
    }

    pub(crate) fn u64(&mut self) -> Result<u64, StoreError> {
        let bytes: [u8; 8] = self
            .take(8)?
            .try_into()
            .map_err(|_| StoreError::metadata(MetadataKind::Store, "<memory>", "invalid u64"))?;
        Ok(u64::from_be_bytes(bytes))
    }

    pub(crate) fn bytes(&mut self, maximum: usize) -> Result<&'a [u8], StoreError> {
        let length = usize::try_from(self.u32()?).map_err(|_| {
            StoreError::metadata(MetadataKind::Store, "<memory>", "length does not fit usize")
        })?;
        if length > maximum {
            return Err(StoreError::metadata(
                MetadataKind::Store,
                "<memory>",
                format!("field is {length} bytes; maximum is {maximum}"),
            ));
        }
        self.take(length)
    }

    pub(crate) fn text(&mut self, maximum: usize) -> Result<&'a str, StoreError> {
        std::str::from_utf8(self.bytes(maximum)?)
            .map_err(|_| StoreError::metadata(MetadataKind::Store, "<memory>", "text is not UTF-8"))
    }

    pub(crate) fn optional_text(&mut self, maximum: usize) -> Result<Option<&'a str>, StoreError> {
        match self.u8()? {
            0 => Ok(None),
            1 => self.text(maximum).map(Some),
            value => Err(StoreError::metadata(
                MetadataKind::Store,
                "<memory>",
                format!("invalid option discriminant {value}"),
            )),
        }
    }

    pub(crate) fn finish(self) -> Result<(), StoreError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(StoreError::metadata(
                MetadataKind::Store,
                "<memory>",
                "trailing bytes in canonical record",
            ))
        }
    }
}
