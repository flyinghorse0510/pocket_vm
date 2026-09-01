use std::io::{Read, Write};

use crate::{FrameSection, ProtocolError};

pub const MAGIC: [u8; 4] = *b"PKVM";
pub const HEADER_LEN: usize = 24;
pub const PROTOCOL_MAJOR: u16 = 1;
/// Receivers require an exact match on both numbers, so this is a wire
/// identity rather than a compatibility hint: bump it for ANY change a peer
/// can observe on the wire, including adding a field to an existing message.
/// Minor 4 added the required `Start::stdin_bytes` field; minor 5 made a
/// guest ERROR legal before HELLO; minor 6 made `Start::volumes` host
/// directories mounted through hostfs, and refuses a destination that
/// collides with a path the runtime mounts or generates; minor 7 gave
/// `Start::network_mode` a second accepted value, so a guest now configures an
/// interface and a resolver it previously refused; minor 8 added
/// `Start::privileged`, which selects the guest's capability policy per run.
pub const PROTOCOL_MINOR: u16 = 8;
pub const MAX_CONTROL_PAYLOAD: usize = 256 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum MessageKind {
    Hello = 1,
    Start = 2,
    Ready = 3,
    Exit = 4,
    Error = 5,
    Signal = 6,
    Resize = 7,
    Shutdown = 8,
    BuildHello = 32,
    BuildStart = 33,
    ManifestBegin = 34,
    ManifestChunk = 35,
    ManifestEnd = 36,
    BuildDone = 37,
    BuildError = 38,
    AccountDb = 39,
    ValidateHello = 48,
    ValidateStart = 49,
    ValidateDone = 50,
    ValidateError = 51,
}

impl MessageKind {
    pub const fn from_u16(value: u16) -> Result<Self, ProtocolError> {
        match value {
            1 => Ok(Self::Hello),
            2 => Ok(Self::Start),
            3 => Ok(Self::Ready),
            4 => Ok(Self::Exit),
            5 => Ok(Self::Error),
            6 => Ok(Self::Signal),
            7 => Ok(Self::Resize),
            8 => Ok(Self::Shutdown),
            32 => Ok(Self::BuildHello),
            33 => Ok(Self::BuildStart),
            34 => Ok(Self::ManifestBegin),
            35 => Ok(Self::ManifestChunk),
            36 => Ok(Self::ManifestEnd),
            37 => Ok(Self::BuildDone),
            38 => Ok(Self::BuildError),
            39 => Ok(Self::AccountDb),
            48 => Ok(Self::ValidateHello),
            49 => Ok(Self::ValidateStart),
            50 => Ok(Self::ValidateDone),
            51 => Ok(Self::ValidateError),
            kind => Err(ProtocolError::UnknownKind { kind }),
        }
    }
}

/// The fixed, big-endian 24-byte PKVM frame header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    pub kind: MessageKind,
    pub flags: u16,
    pub payload_len: u32,
    pub sequence: u64,
}

impl FrameHeader {
    pub fn new(
        kind: MessageKind,
        payload_len: usize,
        sequence: u64,
    ) -> Result<Self, ProtocolError> {
        ensure_payload_cap(payload_len, MAX_CONTROL_PAYLOAD)?;
        let payload_len =
            u32::try_from(payload_len).map_err(|_| ProtocolError::PayloadTooLarge {
                actual: payload_len,
                maximum: MAX_CONTROL_PAYLOAD,
            })?;
        Ok(Self {
            kind,
            flags: 0,
            payload_len,
            sequence,
        })
    }

    #[must_use]
    pub fn to_bytes(self) -> [u8; HEADER_LEN] {
        let mut bytes = [0_u8; HEADER_LEN];
        bytes[0..4].copy_from_slice(&MAGIC);
        bytes[4..6].copy_from_slice(&PROTOCOL_MAJOR.to_be_bytes());
        bytes[6..8].copy_from_slice(&PROTOCOL_MINOR.to_be_bytes());
        bytes[8..10].copy_from_slice(&(self.kind as u16).to_be_bytes());
        bytes[10..12].copy_from_slice(&self.flags.to_be_bytes());
        bytes[12..16].copy_from_slice(&self.payload_len.to_be_bytes());
        bytes[16..24].copy_from_slice(&self.sequence.to_be_bytes());
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() < HEADER_LEN {
            return Err(ProtocolError::UnexpectedEof {
                section: FrameSection::Header,
                expected: HEADER_LEN,
                received: bytes.len(),
            });
        }
        if bytes.len() > HEADER_LEN {
            return Err(ProtocolError::TrailingData {
                remaining: bytes.len() - HEADER_LEN,
            });
        }

        let actual_magic = [bytes[0], bytes[1], bytes[2], bytes[3]];
        if actual_magic != MAGIC {
            return Err(ProtocolError::BadMagic {
                actual: actual_magic,
            });
        }
        let major = u16::from_be_bytes([bytes[4], bytes[5]]);
        let minor = u16::from_be_bytes([bytes[6], bytes[7]]);
        if major != PROTOCOL_MAJOR || minor != PROTOCOL_MINOR {
            return Err(ProtocolError::UnsupportedVersion {
                actual_major: major,
                actual_minor: minor,
                expected_major: PROTOCOL_MAJOR,
                expected_minor: PROTOCOL_MINOR,
            });
        }
        let kind = MessageKind::from_u16(u16::from_be_bytes([bytes[8], bytes[9]]))?;
        let flags = u16::from_be_bytes([bytes[10], bytes[11]]);
        if flags != 0 {
            return Err(ProtocolError::UnsupportedFlags { flags });
        }
        let payload_len = u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
        ensure_payload_cap(payload_len as usize, MAX_CONTROL_PAYLOAD)?;
        let sequence = u64::from_be_bytes([
            bytes[16], bytes[17], bytes[18], bytes[19], bytes[20], bytes[21], bytes[22], bytes[23],
        ]);
        Ok(Self {
            kind,
            flags,
            payload_len,
            sequence,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawFrame {
    pub header: FrameHeader,
    pub payload: Vec<u8>,
}

pub fn encode_frame(
    kind: MessageKind,
    sequence: u64,
    payload: &[u8],
) -> Result<Vec<u8>, ProtocolError> {
    let header = FrameHeader::new(kind, payload.len(), sequence)?;
    let total = HEADER_LEN
        .checked_add(payload.len())
        .ok_or(ProtocolError::PayloadTooLarge {
            actual: payload.len(),
            maximum: MAX_CONTROL_PAYLOAD,
        })?;
    let mut encoded = Vec::with_capacity(total);
    encoded.extend_from_slice(&header.to_bytes());
    encoded.extend_from_slice(payload);
    Ok(encoded)
}

/// Decode exactly one complete frame from a byte slice. Any additional byte
/// is a protocol error rather than an implicitly ignored second message.
pub fn decode_frame_exact(input: &[u8], expected_sequence: u64) -> Result<RawFrame, ProtocolError> {
    if input.len() < HEADER_LEN {
        return Err(ProtocolError::UnexpectedEof {
            section: FrameSection::Header,
            expected: HEADER_LEN,
            received: input.len(),
        });
    }
    let header = FrameHeader::from_bytes(&input[..HEADER_LEN])?;
    ensure_payload_cap(header.payload_len as usize, MAX_CONTROL_PAYLOAD)?;
    ensure_sequence(header.sequence, expected_sequence)?;
    let expected_total = HEADER_LEN.checked_add(header.payload_len as usize).ok_or(
        ProtocolError::PayloadTooLarge {
            actual: header.payload_len as usize,
            maximum: MAX_CONTROL_PAYLOAD,
        },
    )?;
    if input.len() < expected_total {
        return Err(ProtocolError::UnexpectedEof {
            section: FrameSection::Payload,
            expected: header.payload_len as usize,
            received: input.len() - HEADER_LEN,
        });
    }
    if input.len() > expected_total {
        return Err(ProtocolError::TrailingData {
            remaining: input.len() - expected_total,
        });
    }
    Ok(RawFrame {
        header,
        payload: input[HEADER_LEN..].to_vec(),
    })
}

/// Stateful exact frame reader. Sequences are local to one stream direction.
pub struct FrameReader<R> {
    inner: R,
    expected_sequence: u64,
    maximum_payload: usize,
}

impl<R: Read> FrameReader<R> {
    #[must_use]
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            expected_sequence: 0,
            maximum_payload: MAX_CONTROL_PAYLOAD,
        }
    }

    pub fn with_limits(
        inner: R,
        expected_sequence: u64,
        maximum_payload: usize,
    ) -> Result<Self, ProtocolError> {
        if maximum_payload > MAX_CONTROL_PAYLOAD {
            return Err(ProtocolError::PayloadTooLarge {
                actual: maximum_payload,
                maximum: MAX_CONTROL_PAYLOAD,
            });
        }
        Ok(Self {
            inner,
            expected_sequence,
            maximum_payload,
        })
    }

    pub fn read_frame(&mut self) -> Result<RawFrame, ProtocolError> {
        let mut header_bytes = [0_u8; HEADER_LEN];
        read_exact_classified(&mut self.inner, &mut header_bytes, FrameSection::Header)?;
        let header = FrameHeader::from_bytes(&header_bytes)?;
        ensure_payload_cap(header.payload_len as usize, self.maximum_payload)?;
        ensure_sequence(header.sequence, self.expected_sequence)?;
        let next_sequence = self
            .expected_sequence
            .checked_add(1)
            .ok_or(ProtocolError::SequenceExhausted)?;

        let mut payload = vec![0_u8; header.payload_len as usize];
        read_exact_classified(&mut self.inner, &mut payload, FrameSection::Payload)?;
        self.expected_sequence = next_sequence;
        Ok(RawFrame { header, payload })
    }

    #[must_use]
    pub const fn expected_sequence(&self) -> u64 {
        self.expected_sequence
    }

    #[must_use]
    pub fn into_inner(self) -> R {
        self.inner
    }
}

/// Stateful exact frame writer. Sequences are incremented only after both
/// header and payload have been written successfully.
pub struct FrameWriter<W> {
    inner: W,
    next_sequence: u64,
    maximum_payload: usize,
}

impl<W: Write> FrameWriter<W> {
    #[must_use]
    pub fn new(inner: W) -> Self {
        Self {
            inner,
            next_sequence: 0,
            maximum_payload: MAX_CONTROL_PAYLOAD,
        }
    }

    pub fn with_limits(
        inner: W,
        next_sequence: u64,
        maximum_payload: usize,
    ) -> Result<Self, ProtocolError> {
        if maximum_payload > MAX_CONTROL_PAYLOAD {
            return Err(ProtocolError::PayloadTooLarge {
                actual: maximum_payload,
                maximum: MAX_CONTROL_PAYLOAD,
            });
        }
        Ok(Self {
            inner,
            next_sequence,
            maximum_payload,
        })
    }

    pub fn write_frame(&mut self, kind: MessageKind, payload: &[u8]) -> Result<u64, ProtocolError> {
        ensure_payload_cap(payload.len(), self.maximum_payload)?;
        let sequence = self.next_sequence;
        let next_sequence = sequence
            .checked_add(1)
            .ok_or(ProtocolError::SequenceExhausted)?;
        let header = FrameHeader::new(kind, payload.len(), sequence)?;
        self.inner.write_all(&header.to_bytes())?;
        self.inner.write_all(payload)?;
        self.next_sequence = next_sequence;
        Ok(sequence)
    }

    pub fn flush(&mut self) -> Result<(), ProtocolError> {
        self.inner.flush()?;
        Ok(())
    }

    #[must_use]
    pub const fn next_sequence(&self) -> u64 {
        self.next_sequence
    }

    #[must_use]
    pub fn into_inner(self) -> W {
        self.inner
    }
}

fn ensure_payload_cap(actual: usize, maximum: usize) -> Result<(), ProtocolError> {
    if actual > maximum {
        return Err(ProtocolError::PayloadTooLarge { actual, maximum });
    }
    Ok(())
}

fn ensure_sequence(actual: u64, expected: u64) -> Result<(), ProtocolError> {
    if actual != expected {
        return Err(ProtocolError::SequenceMismatch { expected, actual });
    }
    Ok(())
}

fn read_exact_classified<R: Read>(
    reader: &mut R,
    buffer: &mut [u8],
    section: FrameSection,
) -> Result<(), ProtocolError> {
    let mut received = 0;
    while received < buffer.len() {
        match reader.read(&mut buffer[received..]) {
            Ok(0) => {
                return Err(ProtocolError::UnexpectedEof {
                    section,
                    expected: buffer.len(),
                    received,
                });
            }
            Ok(count) => received += count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(ProtocolError::Io(error)),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::{self, Cursor, Read, Write};

    use pocket_core::{CodedError, ErrorCode};

    use super::{
        FrameHeader, FrameReader, FrameWriter, HEADER_LEN, MAGIC, MAX_CONTROL_PAYLOAD, MessageKind,
        PROTOCOL_MAJOR, PROTOCOL_MINOR, decode_frame_exact, encode_frame,
    };
    use crate::ProtocolError;

    struct Chunked<T> {
        inner: T,
        chunk: usize,
    }

    impl<T: Read> Read for Chunked<T> {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            let limit = self.chunk.min(buffer.len());
            self.inner.read(&mut buffer[..limit])
        }
    }

    impl<T: Write> Write for Chunked<T> {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            let limit = self.chunk.min(buffer.len());
            self.inner.write(&buffer[..limit])
        }

        fn flush(&mut self) -> io::Result<()> {
            self.inner.flush()
        }
    }

    #[test]
    fn header_is_exactly_24_big_endian_bytes() {
        let header = match FrameHeader::new(MessageKind::Hello, 0x0102, 0x0102_0304_0506_0708) {
            Ok(header) => header,
            Err(error) => panic!("header rejected: {error}"),
        };
        let bytes = header.to_bytes();
        assert_eq!(bytes.len(), HEADER_LEN);
        assert_eq!(&bytes[0..4], &MAGIC);
        assert_eq!(&bytes[4..6], &PROTOCOL_MAJOR.to_be_bytes());
        assert_eq!(&bytes[6..8], &PROTOCOL_MINOR.to_be_bytes());
        assert_eq!(&bytes[8..10], &(MessageKind::Hello as u16).to_be_bytes());
        assert_eq!(&bytes[12..16], &0x0102_u32.to_be_bytes());
        assert_eq!(&bytes[16..24], &0x0102_0304_0506_0708_u64.to_be_bytes());
    }

    #[test]
    fn frame_round_trip_and_short_io_are_exact() {
        let payload = b"bounded payload";
        let sink = Chunked {
            inner: Vec::new(),
            chunk: 2,
        };
        let mut writer = FrameWriter::new(sink);
        let sequence = match writer.write_frame(MessageKind::Hello, payload) {
            Ok(sequence) => sequence,
            Err(error) => panic!("frame failed to encode: {error}"),
        };
        assert_eq!(sequence, 0);
        let encoded = writer.into_inner().inner;

        let source = Chunked {
            inner: Cursor::new(encoded),
            chunk: 3,
        };
        let mut reader = FrameReader::new(source);
        let decoded = match reader.read_frame() {
            Ok(frame) => frame,
            Err(error) => panic!("frame failed to decode: {error}"),
        };
        assert_eq!(decoded.header.kind, MessageKind::Hello);
        assert_eq!(decoded.header.sequence, 0);
        assert_eq!(decoded.payload, payload);
        assert_eq!(reader.expected_sequence(), 1);
    }

    #[test]
    fn every_truncation_is_an_eof_error() {
        let frame = match encode_frame(MessageKind::Ready, 0, b"123456") {
            Ok(frame) => frame,
            Err(error) => panic!("encoding failed: {error}"),
        };
        for length in 0..frame.len() {
            let result = decode_frame_exact(&frame[..length], 0);
            assert!(
                matches!(result, Err(ProtocolError::UnexpectedEof { .. })),
                "truncation at {length} returned {result:?}"
            );
        }
    }

    #[test]
    fn stream_reader_distinguishes_header_and_payload_eof() {
        let mut empty = FrameReader::new(Cursor::new(Vec::<u8>::new()));
        assert!(matches!(
            empty.read_frame(),
            Err(ProtocolError::UnexpectedEof {
                section: crate::FrameSection::Header,
                expected: HEADER_LEN,
                received: 0
            })
        ));

        let complete = match encode_frame(MessageKind::Ready, 0, b"abcdef") {
            Ok(frame) => frame,
            Err(error) => panic!("encoding failed: {error}"),
        };
        let truncated = complete[..complete.len() - 2].to_vec();
        let mut reader = FrameReader::new(Cursor::new(truncated));
        assert!(matches!(
            reader.read_frame(),
            Err(ProtocolError::UnexpectedEof {
                section: crate::FrameSection::Payload,
                expected: 6,
                received: 4
            })
        ));
    }

    #[test]
    fn rejects_trailing_bytes() {
        let mut frame = match encode_frame(MessageKind::Ready, 0, b"ok") {
            Ok(frame) => frame,
            Err(error) => panic!("encoding failed: {error}"),
        };
        frame.push(0);
        assert!(matches!(
            decode_frame_exact(&frame, 0),
            Err(ProtocolError::TrailingData { remaining: 1 })
        ));
    }

    #[test]
    fn rejects_bad_magic_version_kind_and_flags() {
        let base = match encode_frame(MessageKind::Hello, 0, &[]) {
            Ok(frame) => frame,
            Err(error) => panic!("encoding failed: {error}"),
        };

        let mut bad_magic = base.clone();
        bad_magic[0] = b'X';
        assert!(matches!(
            decode_frame_exact(&bad_magic, 0),
            Err(ProtocolError::BadMagic { .. })
        ));

        let mut bad_version = base.clone();
        bad_version[4..6].copy_from_slice(&(PROTOCOL_MAJOR + 1).to_be_bytes());
        assert!(matches!(
            decode_frame_exact(&bad_version, 0),
            Err(ProtocolError::UnsupportedVersion { .. })
        ));

        let mut bad_minor = base.clone();
        bad_minor[6..8].copy_from_slice(&(PROTOCOL_MINOR + 1).to_be_bytes());
        assert!(matches!(
            decode_frame_exact(&bad_minor, 0),
            Err(ProtocolError::UnsupportedVersion { .. })
        ));

        let mut retired_minor = base.clone();
        retired_minor[6..8].copy_from_slice(&0_u16.to_be_bytes());
        assert!(matches!(
            decode_frame_exact(&retired_minor, 0),
            Err(ProtocolError::UnsupportedVersion {
                actual_major: PROTOCOL_MAJOR,
                actual_minor: 0,
                expected_major: PROTOCOL_MAJOR,
                expected_minor: PROTOCOL_MINOR,
            })
        ));

        let mut bad_kind = base.clone();
        bad_kind[8..10].copy_from_slice(&0xffff_u16.to_be_bytes());
        assert!(matches!(
            decode_frame_exact(&bad_kind, 0),
            Err(ProtocolError::UnknownKind { kind: 0xffff })
        ));

        let mut bad_flags = base;
        bad_flags[10..12].copy_from_slice(&1_u16.to_be_bytes());
        assert!(matches!(
            decode_frame_exact(&bad_flags, 0),
            Err(ProtocolError::UnsupportedFlags { flags: 1 })
        ));
    }

    #[test]
    fn oversized_length_is_rejected_before_allocation_or_payload_read() {
        let mut header = match FrameHeader::new(MessageKind::Hello, 0, 0) {
            Ok(header) => header.to_bytes(),
            Err(error) => panic!("header rejected: {error}"),
        };
        let oversized = u32::try_from(MAX_CONTROL_PAYLOAD + 1).unwrap_or(u32::MAX);
        header[12..16].copy_from_slice(&oversized.to_be_bytes());

        let mut reader = FrameReader::new(Cursor::new(header));
        let error = match reader.read_frame() {
            Ok(_) => panic!("oversized payload accepted"),
            Err(error) => error,
        };
        assert!(matches!(error, ProtocolError::PayloadTooLarge { .. }));
        assert_eq!(error.code(), ErrorCode::ProtocolPayloadTooLarge);
    }

    #[test]
    fn rejects_duplicate_or_skipped_sequence() {
        let frame = match encode_frame(MessageKind::Hello, 4, &[]) {
            Ok(frame) => frame,
            Err(error) => panic!("encoding failed: {error}"),
        };
        assert!(matches!(
            decode_frame_exact(&frame, 3),
            Err(ProtocolError::SequenceMismatch {
                expected: 3,
                actual: 4
            })
        ));
    }
}
