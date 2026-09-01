use sha2::{Digest as _, Sha256};

use crate::{
    BuilderMessage, Direction, ManifestLimits, ProtocolError, ToolIdentity,
    builder::count_length_prefixed_entries,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuilderState {
    AwaitHello,
    AwaitStart,
    AwaitManifestBegin,
    StreamingManifest,
    AwaitAccountDb,
    AwaitDone,
    Completed,
    Failed,
}

impl BuilderState {
    const fn as_str(self) -> &'static str {
        match self {
            Self::AwaitHello => "await-build-hello",
            Self::AwaitStart => "await-build-start",
            Self::AwaitManifestBegin => "await-manifest-begin",
            Self::StreamingManifest => "streaming-manifest",
            Self::AwaitAccountDb => "await-account-db",
            Self::AwaitDone => "await-build-done",
            Self::Completed => "completed",
            Self::Failed => "failed",
        }
    }

    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed)
    }
}

/// Stateful validator for the builder handshake and metadata stream.
///
/// Besides frame ordering, it binds observed tools to the host request and
/// validates every chunk sequence, entry range, negotiated limit, total and
/// digest before accepting `BUILD_DONE`.
#[derive(Debug, Clone)]
pub struct BuilderSession {
    state: BuilderState,
    next_host_sequence: u64,
    next_guest_sequence: u64,
    observed_tools: Option<Vec<ToolIdentity>>,
    accepted_physmem_bytes: Option<u64>,
    expected_tools: Option<Vec<ToolIdentity>>,
    original_user: Option<String>,
    manifest_schema: Option<String>,
    manifest_limits: Option<ManifestLimits>,
    stream_id: Option<String>,
    next_chunk_sequence: u64,
    next_entry: u64,
    byte_count: u64,
    manifest_hasher: Sha256,
    manifest_sha256: Option<String>,
    account_db_sha256: Option<String>,
}

impl Default for BuilderSession {
    fn default() -> Self {
        Self::new()
    }
}

impl BuilderSession {
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: BuilderState::AwaitHello,
            next_host_sequence: 0,
            next_guest_sequence: 0,
            observed_tools: None,
            accepted_physmem_bytes: None,
            expected_tools: None,
            original_user: None,
            manifest_schema: None,
            manifest_limits: None,
            stream_id: None,
            next_chunk_sequence: 0,
            next_entry: 0,
            byte_count: 0,
            manifest_hasher: Sha256::new(),
            manifest_sha256: None,
            account_db_sha256: None,
        }
    }

    #[must_use]
    pub const fn state(&self) -> BuilderState {
        self.state
    }

    #[must_use]
    pub const fn next_sequence(&self, direction: Direction) -> u64 {
        match direction {
            Direction::HostToGuest => self.next_host_sequence,
            Direction::GuestToHost => self.next_guest_sequence,
        }
    }

    /// Accept one decoded message. All validation is transactional: neither
    /// lifecycle state nor counters change when this method returns an error.
    pub fn accept(
        &mut self,
        direction: Direction,
        message: &BuilderMessage,
        frame_sequence: u64,
    ) -> Result<(), ProtocolError> {
        let expected_sequence = self.next_sequence(direction);
        if frame_sequence != expected_sequence {
            return Err(ProtocolError::SequenceMismatch {
                expected: expected_sequence,
                actual: frame_sequence,
            });
        }
        message.validate()?;

        let mut next = self.clone();
        next.accept_inner(direction, message)?;
        let incremented = frame_sequence
            .checked_add(1)
            .ok_or(ProtocolError::SequenceExhausted)?;
        match direction {
            Direction::HostToGuest => next.next_host_sequence = incremented,
            Direction::GuestToHost => next.next_guest_sequence = incremented,
        }
        *self = next;
        Ok(())
    }

    fn accept_inner(
        &mut self,
        direction: Direction,
        message: &BuilderMessage,
    ) -> Result<(), ProtocolError> {
        match (self.state, direction, message) {
            (BuilderState::AwaitHello, Direction::GuestToHost, BuilderMessage::Hello(hello)) => {
                self.observed_tools = Some(hello.builder_tools.clone());
                self.accepted_physmem_bytes = Some(hello.accepted_physmem_bytes);
                self.state = BuilderState::AwaitStart;
                Ok(())
            }
            (BuilderState::AwaitStart, Direction::HostToGuest, BuilderMessage::Start(start)) => {
                let observed =
                    self.observed_tools
                        .as_ref()
                        .ok_or(ProtocolError::InvalidStateTransition {
                            state: self.state.as_str(),
                            direction: "host-to-guest",
                            kind: message.kind() as u16,
                        })?;
                if observed != &start.expected_tools {
                    return invalid("expected_tools", "does not equal BUILD_HELLO tool evidence");
                }
                if self.accepted_physmem_bytes != Some(start.expected_physmem_bytes) {
                    return invalid(
                        "expected_physmem_bytes",
                        "does not equal BUILD_HELLO accepted physical memory",
                    );
                }
                self.expected_tools = Some(start.expected_tools.clone());
                self.original_user = Some(start.original_user.clone());
                self.manifest_schema = Some(start.manifest_schema.clone());
                self.manifest_limits = Some(start.manifest_limits.clone());
                self.state = BuilderState::AwaitManifestBegin;
                Ok(())
            }
            (
                BuilderState::AwaitManifestBegin,
                Direction::GuestToHost,
                BuilderMessage::ManifestBegin(begin),
            ) => {
                if Some(begin.schema.as_str()) != self.manifest_schema.as_deref() {
                    return invalid(
                        "manifest_schema",
                        "MANIFEST_BEGIN schema differs from START",
                    );
                }
                self.stream_id = Some(begin.stream_id.clone());
                self.next_chunk_sequence = 0;
                self.next_entry = 0;
                self.byte_count = 0;
                self.manifest_hasher = Sha256::new();
                self.state = BuilderState::StreamingManifest;
                Ok(())
            }
            (
                BuilderState::StreamingManifest,
                Direction::GuestToHost,
                BuilderMessage::ManifestChunk(chunk),
            ) => self.accept_chunk(chunk),
            (
                BuilderState::StreamingManifest,
                Direction::GuestToHost,
                BuilderMessage::ManifestEnd(end),
            ) => {
                if Some(end.stream_id.as_str()) != self.stream_id.as_deref() {
                    return invalid("stream_id", "MANIFEST_END stream differs from BEGIN");
                }
                if end.entry_count != self.next_entry || end.byte_count != self.byte_count {
                    return invalid("manifest_totals", "MANIFEST_END totals do not match chunks");
                }
                let digest = hex_lower(self.manifest_hasher.clone().finalize().as_slice());
                if end.sha256 != digest {
                    return invalid(
                        "manifest_sha256",
                        "MANIFEST_END digest does not match chunks",
                    );
                }
                self.manifest_sha256 = Some(digest);
                self.state = BuilderState::AwaitAccountDb;
                Ok(())
            }
            (
                BuilderState::AwaitAccountDb,
                Direction::GuestToHost,
                BuilderMessage::AccountDb(account_db),
            ) => {
                self.account_db_sha256 = Some(account_db.sha256.clone());
                self.state = BuilderState::AwaitDone;
                Ok(())
            }
            (BuilderState::AwaitDone, Direction::GuestToHost, BuilderMessage::Done(done)) => {
                if Some(done.manifest_sha256.as_str()) != self.manifest_sha256.as_deref()
                    || done.entry_count != self.next_entry
                    || done.byte_count != self.byte_count
                {
                    return invalid("build_done", "manifest evidence differs from stream");
                }
                if Some(done.original_user.as_str()) != self.original_user.as_deref() {
                    return invalid("original_user", "BUILD_DONE differs from START");
                }
                if Some(done.account_db_sha256.as_str()) != self.account_db_sha256.as_deref() {
                    return invalid("account_db_sha256", "BUILD_DONE differs from ACCOUNT_DB");
                }
                if Some(&done.observed_tools) != self.expected_tools.as_ref() {
                    return invalid("observed_tools", "BUILD_DONE differs from START");
                }
                self.state = BuilderState::Completed;
                Ok(())
            }
            (
                BuilderState::AwaitStart
                | BuilderState::AwaitManifestBegin
                | BuilderState::StreamingManifest
                | BuilderState::AwaitAccountDb
                | BuilderState::AwaitDone,
                Direction::GuestToHost,
                BuilderMessage::Error(_),
            ) => {
                self.state = BuilderState::Failed;
                Ok(())
            }
            _ => Err(ProtocolError::InvalidStateTransition {
                state: self.state.as_str(),
                direction: match direction {
                    Direction::HostToGuest => "host-to-guest",
                    Direction::GuestToHost => "guest-to-host",
                },
                kind: message.kind() as u16,
            }),
        }
    }

    fn accept_chunk(&mut self, chunk: &crate::ManifestChunk) -> Result<(), ProtocolError> {
        if Some(chunk.stream_id.as_str()) != self.stream_id.as_deref() {
            return invalid("stream_id", "MANIFEST_CHUNK stream differs from BEGIN");
        }
        if chunk.sequence != self.next_chunk_sequence {
            return invalid("chunk.sequence", "chunk sequence is not contiguous");
        }
        if chunk.first_entry != self.next_entry {
            return invalid("chunk.first_entry", "entry range is not contiguous");
        }
        let limits =
            self.manifest_limits
                .as_ref()
                .ok_or(ProtocolError::InvalidStateTransition {
                    state: self.state.as_str(),
                    direction: "guest-to-host",
                    kind: crate::MessageKind::ManifestChunk as u16,
                })?;
        if chunk.bytes.len() > limits.max_chunk_bytes as usize {
            return invalid("chunk.bytes", "exceeds negotiated chunk limit");
        }
        let entry_count =
            count_length_prefixed_entries(&chunk.bytes, limits.max_entry_bytes as usize)?;
        if entry_count != chunk.entry_count as usize {
            return invalid("chunk.entry_count", "does not match encoded entries");
        }
        validate_canonical_entries(&chunk.bytes, limits)?;
        let next_entry = self
            .next_entry
            .checked_add(chunk.entry_count as u64)
            .ok_or(ProtocolError::MessageLimitExceeded {
                field: "manifest.entry_count",
                actual: usize::MAX,
                maximum: usize::MAX,
            })?;
        if next_entry > limits.max_entries {
            return invalid("manifest.entry_count", "exceeds negotiated limit");
        }
        let byte_count = self
            .byte_count
            .checked_add(chunk.bytes.len() as u64)
            .ok_or(ProtocolError::MessageLimitExceeded {
                field: "manifest.byte_count",
                actual: usize::MAX,
                maximum: usize::MAX,
            })?;
        if byte_count > limits.max_total_bytes {
            return invalid("manifest.byte_count", "exceeds negotiated limit");
        }
        self.manifest_hasher.update(&chunk.bytes);
        self.next_chunk_sequence = self
            .next_chunk_sequence
            .checked_add(1)
            .ok_or(ProtocolError::SequenceExhausted)?;
        self.next_entry = next_entry;
        self.byte_count = byte_count;
        Ok(())
    }
}

fn validate_canonical_entries(bytes: &[u8], limits: &ManifestLimits) -> Result<(), ProtocolError> {
    let mut position = 0_usize;
    while position < bytes.len() {
        let length = u32::from_be_bytes([
            bytes[position],
            bytes[position + 1],
            bytes[position + 2],
            bytes[position + 3],
        ]) as usize;
        position += 4;
        let end = position + length;
        let entry: crate::ManifestEntry = crate::decode_payload(&bytes[position..end])?;
        if entry.path.len() > limits.max_path_bytes as usize {
            return invalid("manifest_entry.path", "exceeds negotiated limit");
        }
        if entry.xattrs.len() > limits.max_xattrs_per_entry as usize {
            return invalid("manifest_entry.xattrs", "exceeds negotiated count");
        }
        let mut xattr_bytes = 0_usize;
        for xattr in &entry.xattrs {
            xattr_bytes = xattr_bytes
                .checked_add(xattr.name.len())
                .and_then(|value| value.checked_add(xattr.value.len()))
                .ok_or(ProtocolError::MessageLimitExceeded {
                    field: "manifest_entry.xattr_bytes",
                    actual: usize::MAX,
                    maximum: limits.max_xattr_bytes_per_entry as usize,
                })?;
        }
        if xattr_bytes > limits.max_xattr_bytes_per_entry as usize {
            return invalid("manifest_entry.xattr_bytes", "exceeds negotiated limit");
        }
        position = end;
    }
    Ok(())
}

fn invalid<T>(field: &'static str, reason: &'static str) -> Result<T, ProtocolError> {
    Err(ProtocolError::InvalidMessage { field, reason })
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
    use sha2::{Digest as _, Sha256};

    use super::*;
    use crate::{
        ACCOUNT_DB_SCHEMA, AccountDatabase, AccountDb, BuilderDone, BuilderMessage,
        FilesystemStatus, ManifestBegin, ManifestChunk, ManifestEnd, ManifestEntry, UserResolution,
        builder::tests::{hello, start},
        encode_payload,
    };

    fn digest(bytes: &[u8]) -> String {
        hex_lower(Sha256::digest(bytes).as_slice())
    }

    fn chunk() -> ManifestChunk {
        let entry = encode_payload(&ManifestEntry {
            path: b"rootfs".to_vec(),
            kind: 2,
            mode: 0o755,
            uid: 0,
            gid: 0,
            size: 4096,
            rdev: 0,
            mtime_seconds: 1,
            mtime_nanoseconds: 0,
            symlink_target: None,
            content_sha256: None,
            hardlink_target: None,
            xattrs: Vec::new(),
        })
        .expect("entry");
        let mut bytes = (entry.len() as u32).to_be_bytes().to_vec();
        bytes.extend(entry);
        ManifestChunk {
            stream_id: "9".repeat(64),
            sequence: 0,
            first_entry: 0,
            entry_count: 1,
            bytes,
        }
    }

    #[test]
    fn accepts_complete_builder_stream_and_binds_all_evidence() {
        let mut session = BuilderSession::new();
        session
            .accept(Direction::GuestToHost, &BuilderMessage::Hello(hello()), 0)
            .expect("hello");
        let start = start();
        session
            .accept(
                Direction::HostToGuest,
                &BuilderMessage::Start(Box::new(start.clone())),
                0,
            )
            .expect("start");
        session
            .accept(
                Direction::GuestToHost,
                &BuilderMessage::ManifestBegin(ManifestBegin {
                    schema: start.manifest_schema.clone(),
                    stream_id: "9".repeat(64),
                }),
                1,
            )
            .expect("begin");
        let chunk = chunk();
        session
            .accept(
                Direction::GuestToHost,
                &BuilderMessage::ManifestChunk(chunk.clone()),
                2,
            )
            .expect("chunk");
        let manifest_digest = digest(&chunk.bytes);
        session
            .accept(
                Direction::GuestToHost,
                &BuilderMessage::ManifestEnd(ManifestEnd {
                    stream_id: chunk.stream_id,
                    entry_count: 1,
                    byte_count: chunk.bytes.len() as u64,
                    sha256: manifest_digest.clone(),
                }),
                3,
            )
            .expect("end");
        let account_db = AccountDb::from_database(&AccountDatabase {
            schema: ACCOUNT_DB_SCHEMA.to_owned(),
            users: Vec::new(),
            groups: Vec::new(),
        })
        .expect("account database");
        session
            .accept(
                Direction::GuestToHost,
                &BuilderMessage::AccountDb(account_db.clone()),
                4,
            )
            .expect("account database");
        session
            .accept(
                Direction::GuestToHost,
                &BuilderMessage::Done(BuilderDone {
                    status: 0,
                    manifest_sha256: manifest_digest,
                    entry_count: 1,
                    byte_count: chunk.bytes.len() as u64,
                    generation_marker_sha256: "a".repeat(64),
                    original_user: start.original_user,
                    user_resolution: UserResolution {
                        kind: 2,
                        uid: 33,
                        gid: 33,
                        supplementary_gids: vec![],
                    },
                    observed_tools: start.expected_tools,
                    filesystem_status: FilesystemStatus {
                        target_synced: true,
                        target_unmounted: true,
                        input_unmounted: true,
                    },
                    account_db_sha256: account_db.sha256,
                }),
                5,
            )
            .expect("done");
        assert_eq!(session.state(), BuilderState::Completed);
    }

    #[test]
    fn rejects_tool_mismatch_before_manifest_and_preserves_state() {
        let mut session = BuilderSession::new();
        session
            .accept(Direction::GuestToHost, &BuilderMessage::Hello(hello()), 0)
            .expect("hello");
        let mut start = start();
        start.expected_tools[0].version = "other".to_owned();
        assert!(
            session
                .accept(
                    Direction::HostToGuest,
                    &BuilderMessage::Start(Box::new(start)),
                    0,
                )
                .is_err()
        );
        assert_eq!(session.state(), BuilderState::AwaitStart);
        assert_eq!(session.next_sequence(Direction::HostToGuest), 0);
    }

    #[test]
    fn rejects_duplicate_chunk_sequence_and_bad_end_digest_transactionally() {
        let mut session = BuilderSession::new();
        session
            .accept(Direction::GuestToHost, &BuilderMessage::Hello(hello()), 0)
            .expect("hello");
        let start = start();
        session
            .accept(
                Direction::HostToGuest,
                &BuilderMessage::Start(Box::new(start.clone())),
                0,
            )
            .expect("start");
        session
            .accept(
                Direction::GuestToHost,
                &BuilderMessage::ManifestBegin(ManifestBegin {
                    schema: start.manifest_schema,
                    stream_id: "9".repeat(64),
                }),
                1,
            )
            .expect("begin");
        let chunk = chunk();
        session
            .accept(
                Direction::GuestToHost,
                &BuilderMessage::ManifestChunk(chunk.clone()),
                2,
            )
            .expect("chunk");

        let mut duplicate = chunk.clone();
        duplicate.first_entry = 1;
        assert!(
            session
                .accept(
                    Direction::GuestToHost,
                    &BuilderMessage::ManifestChunk(duplicate),
                    3,
                )
                .is_err()
        );
        assert_eq!(session.next_sequence(Direction::GuestToHost), 3);

        assert!(
            session
                .accept(
                    Direction::GuestToHost,
                    &BuilderMessage::ManifestEnd(ManifestEnd {
                        stream_id: chunk.stream_id,
                        entry_count: 1,
                        byte_count: chunk.bytes.len() as u64,
                        sha256: "0".repeat(64),
                    }),
                    3,
                )
                .is_err()
        );
        assert_eq!(session.state(), BuilderState::StreamingManifest);
    }

    #[test]
    fn rejects_noncanonical_or_wrong_schema_entry_inside_well_framed_chunk() {
        let mut session = BuilderSession::new();
        session
            .accept(Direction::GuestToHost, &BuilderMessage::Hello(hello()), 0)
            .expect("hello");
        let start = start();
        session
            .accept(
                Direction::HostToGuest,
                &BuilderMessage::Start(Box::new(start.clone())),
                0,
            )
            .expect("start");
        session
            .accept(
                Direction::GuestToHost,
                &BuilderMessage::ManifestBegin(ManifestBegin {
                    schema: start.manifest_schema,
                    stream_id: "9".repeat(64),
                }),
                1,
            )
            .expect("begin");
        let invalid = ManifestChunk {
            stream_id: "9".repeat(64),
            sequence: 0,
            first_entry: 0,
            entry_count: 1,
            bytes: vec![0, 0, 0, 1, 0xa0],
        };
        assert!(
            session
                .accept(
                    Direction::GuestToHost,
                    &BuilderMessage::ManifestChunk(invalid),
                    2,
                )
                .is_err()
        );
        assert_eq!(session.state(), BuilderState::StreamingManifest);
        assert_eq!(session.next_sequence(Direction::GuestToHost), 2);
    }
}
