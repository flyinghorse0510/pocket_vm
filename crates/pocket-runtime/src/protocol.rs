use std::{
    io::{self, Read, Write},
    os::unix::net::UnixStream,
    time::{Duration, Instant},
};

use pocket_core::{ValidatedCpuRequest, ValidatedMemory};
use pocket_protocol::{
    Direction, FrameHeader, FrameSection, FrameWriter, HEADER_LEN, Hello, MessageKind, Ready,
    Shutdown, Start, WorkloadMessage, WorkloadSession, decode_frame_exact, decode_workload_message,
};

use crate::{RuntimeError, VerifiedProfile};

pub(crate) struct ControlChannel {
    stream: UnixStream,
    session: WorkloadSession,
    receive_pending: Vec<u8>,
}

impl ControlChannel {
    pub fn new(stream: UnixStream) -> Self {
        Self {
            stream,
            session: WorkloadSession::new(),
            receive_pending: Vec::new(),
        }
    }

    pub fn receive_hello(
        &mut self,
        deadline: Instant,
        timeout: Duration,
    ) -> Result<Hello, RuntimeError> {
        match self.receive(deadline, timeout, "guest HELLO")? {
            WorkloadMessage::Hello(hello) => Ok(hello),
            WorkloadMessage::Error(message) => Err(RuntimeError::Guest {
                stage: "HELLO",
                message,
            }),
            message => Err(unexpected("HELLO", message.kind())),
        }
    }

    pub fn send_start(
        &mut self,
        start: Start,
        deadline: Instant,
        timeout: Duration,
    ) -> Result<(), RuntimeError> {
        self.send(
            WorkloadMessage::Start(Box::new(start)),
            deadline,
            timeout,
            "guest START",
        )
    }

    pub fn receive_ready(
        &mut self,
        deadline: Instant,
        timeout: Duration,
    ) -> Result<Ready, RuntimeError> {
        match self.receive(deadline, timeout, "guest READY")? {
            WorkloadMessage::Ready(ready) => Ok(ready),
            WorkloadMessage::Error(message) => Err(RuntimeError::Guest {
                stage: "READY",
                message,
            }),
            message => Err(unexpected("READY", message.kind())),
        }
    }

    pub fn receive_terminal(
        &mut self,
        deadline: Instant,
        timeout: Duration,
    ) -> Result<pocket_protocol::Exit, RuntimeError> {
        match self.receive(deadline, timeout, "guest EXIT")? {
            WorkloadMessage::Exit(exit) => Ok(exit),
            WorkloadMessage::Error(message) => Err(RuntimeError::Guest {
                stage: "RUNNING",
                message,
            }),
            message => Err(unexpected("EXIT", message.kind())),
        }
    }

    pub fn send_resize(
        &mut self,
        resize: pocket_protocol::Resize,
        deadline: Instant,
        timeout: Duration,
    ) -> Result<(), RuntimeError> {
        self.send(
            WorkloadMessage::Resize(resize),
            deadline,
            timeout,
            "guest RESIZE",
        )
    }

    pub fn send_signal(
        &mut self,
        signal: u16,
        deadline: Instant,
        timeout: Duration,
    ) -> Result<(), RuntimeError> {
        self.send(
            WorkloadMessage::Signal(pocket_protocol::Signal { signal }),
            deadline,
            timeout,
            "guest SIGNAL",
        )
    }

    pub fn send_shutdown(
        &mut self,
        grace_ms: u32,
        deadline: Instant,
        timeout: Duration,
    ) -> Result<(), RuntimeError> {
        self.send(
            WorkloadMessage::Shutdown(Shutdown { grace_ms }),
            deadline,
            timeout,
            "guest SHUTDOWN",
        )
    }

    fn receive(
        &mut self,
        deadline: Instant,
        timeout: Duration,
        stage: &'static str,
    ) -> Result<WorkloadMessage, RuntimeError> {
        let expected = self.session.next_sequence(Direction::GuestToHost);
        let frame = self.read_frame(deadline, timeout, stage, expected)?;
        let message = decode_workload_message(&frame)?;
        let mut candidate = self.session.clone();
        candidate.accept(
            Direction::GuestToHost,
            frame.header.kind,
            frame.header.sequence,
        )?;
        self.session = candidate;
        Ok(message)
    }

    /// Read exactly one frame while retaining an incomplete header or payload
    /// across a bounded timeout. Graceful-stop escalation performs several
    /// consecutive waits on the same byte stream; discarding a partial frame
    /// at any timeout would permanently desynchronize that stream.
    fn read_frame(
        &mut self,
        deadline: Instant,
        timeout: Duration,
        stage: &'static str,
        expected_sequence: u64,
    ) -> Result<pocket_protocol::RawFrame, RuntimeError> {
        const READ_CHUNK: usize = 8 * 1024;

        loop {
            let expected_total = if self.receive_pending.len() < HEADER_LEN {
                HEADER_LEN
            } else {
                let header = FrameHeader::from_bytes(&self.receive_pending[..HEADER_LEN])?;
                if header.sequence != expected_sequence {
                    return Err(pocket_protocol::ProtocolError::SequenceMismatch {
                        expected: expected_sequence,
                        actual: header.sequence,
                    }
                    .into());
                }
                HEADER_LEN.checked_add(header.payload_len as usize).ok_or(
                    pocket_protocol::ProtocolError::PayloadTooLarge {
                        actual: header.payload_len as usize,
                        maximum: pocket_protocol::MAX_CONTROL_PAYLOAD,
                    },
                )?
            };

            if self.receive_pending.len() == expected_total {
                let encoded = std::mem::take(&mut self.receive_pending);
                return decode_frame_exact(&encoded, expected_sequence).map_err(Into::into);
            }
            if self.receive_pending.len() > expected_total {
                return Err(pocket_protocol::ProtocolError::TrailingData {
                    remaining: self.receive_pending.len() - expected_total,
                }
                .into());
            }

            let remaining = deadline
                .checked_duration_since(Instant::now())
                .filter(|remaining| !remaining.is_zero())
                .ok_or(RuntimeError::Timeout { stage, timeout })?;
            self.stream
                .set_read_timeout(Some(remaining))
                .map_err(|error| {
                    classify_protocol(pocket_protocol::ProtocolError::Io(error), stage, timeout)
                })?;

            let requested = (expected_total - self.receive_pending.len()).min(READ_CHUNK);
            let mut chunk = [0_u8; READ_CHUNK];
            match self.stream.read(&mut chunk[..requested]) {
                Ok(0) => {
                    let error = if self.receive_pending.len() < HEADER_LEN {
                        pocket_protocol::ProtocolError::UnexpectedEof {
                            section: FrameSection::Header,
                            expected: HEADER_LEN,
                            received: self.receive_pending.len(),
                        }
                    } else {
                        let header = FrameHeader::from_bytes(&self.receive_pending[..HEADER_LEN])?;
                        pocket_protocol::ProtocolError::UnexpectedEof {
                            section: FrameSection::Payload,
                            expected: header.payload_len as usize,
                            received: self.receive_pending.len() - HEADER_LEN,
                        }
                    };
                    return Err(error.into());
                }
                Ok(count) => self.receive_pending.extend_from_slice(&chunk[..count]),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => {
                    return Err(classify_protocol(
                        pocket_protocol::ProtocolError::Io(error),
                        stage,
                        timeout,
                    ));
                }
            }
        }
    }

    fn send(
        &mut self,
        message: WorkloadMessage,
        deadline: Instant,
        timeout: Duration,
        stage: &'static str,
    ) -> Result<(), RuntimeError> {
        let kind = message.kind();
        let payload = message.encode_payload()?;
        let sequence = self.session.next_sequence(Direction::HostToGuest);
        let mut candidate = self.session.clone();
        candidate.accept(Direction::HostToGuest, kind, sequence)?;
        let writer = DeadlineIo::new(&mut self.stream, deadline);
        let mut frames =
            FrameWriter::with_limits(writer, sequence, pocket_protocol::MAX_CONTROL_PAYLOAD)?;
        frames
            .write_frame(kind, &payload)
            .and_then(|_| frames.flush())
            .map_err(|error| classify_protocol(error, stage, timeout))?;
        self.session = candidate;
        Ok(())
    }
}

pub(crate) fn verify_hello(
    profile: &VerifiedProfile,
    cpus: ValidatedCpuRequest,
    memory: ValidatedMemory,
    hello: &Hello,
) -> Result<(), RuntimeError> {
    let manifest = profile.manifest();
    compare(
        "guest_contract_id",
        &manifest.hello.guest_contract_id,
        &hello.guest_contract_id,
    )?;
    compare(
        "init_build_id",
        &manifest.hello.init_build_id,
        &hello.init_build_id,
    )?;
    compare(
        "kernel_build_id",
        &manifest.hello.kernel_build_id,
        &hello.kernel_build_id,
    )?;
    compare(
        "host_elf_machine",
        &manifest.host_elf_machine.to_string(),
        &hello.host_elf_machine.to_string(),
    )?;
    compare("guest_uts_machine", "x86_64", &hello.guest_uts_machine)?;
    compare(
        "guest_page_size",
        &manifest.guest_page_size.to_string(),
        &hello.guest_page_size.to_string(),
    )?;
    compare(
        "cpu_state_hwcap_policy",
        &manifest.contracts.cpu_state_hwcap_policy,
        &hello.cpu_state_hwcap_policy,
    )?;
    compare(
        "guest_capability_policy",
        &manifest.contracts.guest_capability_policy,
        &hello.guest_capability_policy,
    )?;
    cpus.verify_online(hello.online_cpus)?;
    compare(
        "accepted_physmem_bytes",
        &memory.bytes().to_string(),
        &hello.accepted_physmem_bytes.to_string(),
    )?;
    for required in &manifest.hello.required_features {
        if !hello.features.iter().any(|feature| feature == required) {
            return Err(RuntimeError::HelloMismatch {
                field: "features",
                expected: required.clone(),
                actual: format!("{:?}", hello.features),
            });
        }
    }
    Ok(())
}

fn compare(field: &'static str, expected: &str, actual: &str) -> Result<(), RuntimeError> {
    if expected != actual {
        return Err(RuntimeError::HelloMismatch {
            field,
            expected: expected.to_owned(),
            actual: actual.to_owned(),
        });
    }
    Ok(())
}

struct DeadlineIo<'stream> {
    stream: &'stream mut UnixStream,
    deadline: Instant,
}

impl<'stream> DeadlineIo<'stream> {
    const fn new(stream: &'stream mut UnixStream, deadline: Instant) -> Self {
        Self { stream, deadline }
    }

    fn remaining(&self) -> io::Result<Duration> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "protocol deadline elapsed"))
    }
}

impl Read for DeadlineIo<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.stream.set_read_timeout(Some(self.remaining()?))?;
        self.stream.read(buffer)
    }
}

impl Write for DeadlineIo<'_> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.stream.set_write_timeout(Some(self.remaining()?))?;
        self.stream.write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.set_write_timeout(Some(self.remaining()?))?;
        self.stream.flush()
    }
}

fn classify_protocol(
    error: pocket_protocol::ProtocolError,
    stage: &'static str,
    timeout: Duration,
) -> RuntimeError {
    if matches!(
        &error,
        pocket_protocol::ProtocolError::Io(source)
            if matches!(source.kind(), io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock)
    ) {
        RuntimeError::Timeout { stage, timeout }
    } else {
        RuntimeError::Protocol(error)
    }
}

fn unexpected(expected: &'static str, actual: MessageKind) -> RuntimeError {
    RuntimeError::Protocol(pocket_protocol::ProtocolError::MessageKindMismatch {
        expected: match expected {
            "HELLO" => MessageKind::Hello as u16,
            "READY" => MessageKind::Ready as u16,
            "EXIT" => MessageKind::Exit as u16,
            _ => 0,
        },
        actual: actual as u16,
    })
}

#[cfg(test)]
mod tests {
    use std::{
        io::Write,
        os::unix::net::UnixStream,
        thread,
        time::{Duration, Instant},
    };

    use pocket_protocol::{
        Direction, Exit, FrameReader, FrameWriter, Hello, MessageKind, Ready, Start,
        WorkloadMessage, WorkloadSession, decode_workload_message, encode_frame,
    };

    use super::ControlChannel;
    use crate::RuntimeError;

    fn hello() -> Hello {
        Hello {
            guest_contract_id: "11".repeat(32),
            init_build_id: "22".repeat(32),
            kernel_build_id: "33".repeat(32),
            host_elf_machine: 62,
            guest_uts_machine: "x86_64".to_owned(),
            guest_page_size: 4096,
            cpu_state_hwcap_policy: "native-x86_64-v1".to_owned(),
            features: vec!["generation-marker-v3".to_owned()],
            online_cpus: 1,
            accepted_physmem_bytes: 256 * 1024 * 1024,
            guest_capability_policy: "fixed-capabilities-v1".to_owned(),
        }
    }

    #[test]
    fn bounded_socketpair_handshake_preserves_directional_sequences() {
        let (host, guest) = UnixStream::pair().expect("socketpair");
        let peer = thread::spawn(move || {
            let reader_socket = guest.try_clone().expect("clone");
            let mut reader = FrameReader::new(reader_socket);
            let mut writer = FrameWriter::new(guest);
            let mut session = WorkloadSession::new();

            let message = WorkloadMessage::Hello(hello());
            let payload = message.encode_payload().expect("hello payload");
            session
                .accept(Direction::GuestToHost, MessageKind::Hello, 0)
                .expect("hello state");
            writer
                .write_frame(MessageKind::Hello, &payload)
                .expect("hello frame");

            let start_frame = reader.read_frame().expect("START frame");
            session
                .accept(
                    Direction::HostToGuest,
                    start_frame.header.kind,
                    start_frame.header.sequence,
                )
                .expect("START state");
            assert!(matches!(
                decode_workload_message(&start_frame).expect("START message"),
                WorkloadMessage::Start(_)
            ));

            let message = WorkloadMessage::Ready(Ready {
                guest_pid: 2,
                effective_uid: 0,
                effective_gid: 0,
                cwd: "/".to_owned(),
            });
            let payload = message.encode_payload().expect("ready payload");
            session
                .accept(Direction::GuestToHost, MessageKind::Ready, 1)
                .expect("ready state");
            writer
                .write_frame(MessageKind::Ready, &payload)
                .expect("ready frame");
        });

        let timeout = Duration::from_secs(2);
        let deadline = std::time::Instant::now() + timeout;
        let mut channel = ControlChannel::new(host);
        assert_eq!(
            channel
                .receive_hello(deadline, timeout)
                .expect("receive HELLO"),
            hello()
        );
        channel
            .send_start(sample_start(), deadline, timeout)
            .expect("send START");
        assert_eq!(
            channel
                .receive_ready(deadline, timeout)
                .expect("receive READY")
                .guest_pid,
            2
        );
        peer.join().expect("guest thread");
    }

    #[test]
    fn fake_guest_observes_signal_then_shutdown_and_returns_forced_exit() {
        let (host, guest) = UnixStream::pair().expect("socketpair");
        let peer = thread::spawn(move || {
            let reader_socket = guest.try_clone().expect("clone");
            let mut reader = FrameReader::new(reader_socket);
            let mut writer = FrameWriter::new(guest);
            let mut session = WorkloadSession::new();

            send_guest(&mut writer, &mut session, WorkloadMessage::Hello(hello()));
            assert!(matches!(
                receive_host(&mut reader, &mut session),
                WorkloadMessage::Start(_)
            ));
            send_guest(
                &mut writer,
                &mut session,
                WorkloadMessage::Ready(Ready {
                    guest_pid: 1,
                    effective_uid: 0,
                    effective_gid: 0,
                    cwd: "/".to_owned(),
                }),
            );
            assert!(matches!(
                receive_host(&mut reader, &mut session),
                WorkloadMessage::Signal(pocket_protocol::Signal { signal: 15 })
            ));
            assert!(matches!(
                receive_host(&mut reader, &mut session),
                WorkloadMessage::Shutdown(pocket_protocol::Shutdown { grace_ms: 750 })
            ));
            send_guest(
                &mut writer,
                &mut session,
                WorkloadMessage::Exit(Exit {
                    code: None,
                    signal: Some(9),
                    elapsed_ns: 42,
                    filesystem_clean: true,
                }),
            );
        });

        let timeout = Duration::from_secs(2);
        let mut channel = ControlChannel::new(host);
        channel
            .receive_hello(Instant::now() + timeout, timeout)
            .expect("HELLO");
        channel
            .send_start(sample_start(), Instant::now() + timeout, timeout)
            .expect("START");
        channel
            .receive_ready(Instant::now() + timeout, timeout)
            .expect("READY");
        channel
            .send_signal(15, Instant::now() + timeout, timeout)
            .expect("SIGNAL");

        let grace = Duration::from_millis(20);
        assert!(matches!(
            channel.receive_terminal(Instant::now() + grace, grace),
            Err(RuntimeError::Timeout { .. })
        ));
        channel
            .send_shutdown(750, Instant::now() + timeout, timeout)
            .expect("SHUTDOWN");
        let exit = channel
            .receive_terminal(Instant::now() + timeout, timeout)
            .expect("forced EXIT");
        assert_eq!(exit.signal, Some(9));
        assert!(exit.filesystem_clean);
        peer.join().expect("guest thread");
    }

    #[test]
    fn timed_receive_retains_a_partial_frame_for_the_next_wait() {
        let (host, guest) = UnixStream::pair().expect("socketpair");
        let peer = thread::spawn(move || {
            let reader_socket = guest.try_clone().expect("clone");
            let mut reader = FrameReader::new(reader_socket);
            let mut writer = FrameWriter::new(guest.try_clone().expect("writer clone"));
            let mut session = WorkloadSession::new();

            send_guest(&mut writer, &mut session, WorkloadMessage::Hello(hello()));
            assert!(matches!(
                receive_host(&mut reader, &mut session),
                WorkloadMessage::Start(_)
            ));
            send_guest(
                &mut writer,
                &mut session,
                WorkloadMessage::Ready(Ready {
                    guest_pid: 1,
                    effective_uid: 0,
                    effective_gid: 0,
                    cwd: "/".to_owned(),
                }),
            );

            let message = WorkloadMessage::Exit(Exit {
                code: Some(0),
                signal: None,
                elapsed_ns: 7,
                filesystem_clean: true,
            });
            let payload = message.encode_payload().expect("EXIT payload");
            let encoded = encode_frame(MessageKind::Exit, 2, &payload).expect("EXIT frame");
            let mut raw_writer = guest;
            raw_writer
                .write_all(&encoded[..10])
                .expect("partial header");
            thread::sleep(Duration::from_millis(60));
            raw_writer
                .write_all(&encoded[10..])
                .expect("remaining EXIT frame");
        });

        let timeout = Duration::from_secs(2);
        let mut channel = ControlChannel::new(host);
        channel
            .receive_hello(Instant::now() + timeout, timeout)
            .expect("HELLO");
        channel
            .send_start(sample_start(), Instant::now() + timeout, timeout)
            .expect("START");
        channel
            .receive_ready(Instant::now() + timeout, timeout)
            .expect("READY");

        let first_wait = Duration::from_millis(20);
        assert!(matches!(
            channel.receive_terminal(Instant::now() + first_wait, first_wait),
            Err(RuntimeError::Timeout { .. })
        ));
        let exit = channel
            .receive_terminal(Instant::now() + timeout, timeout)
            .expect("resumed EXIT frame");
        assert_eq!(exit.code, Some(0));
        peer.join().expect("guest thread");
    }

    fn send_guest(
        writer: &mut FrameWriter<UnixStream>,
        session: &mut WorkloadSession,
        message: WorkloadMessage,
    ) {
        let kind = message.kind();
        let sequence = session.next_sequence(Direction::GuestToHost);
        session
            .accept(Direction::GuestToHost, kind, sequence)
            .expect("guest message state");
        writer
            .write_frame(kind, &message.encode_payload().expect("guest payload"))
            .expect("guest frame");
        writer.flush().expect("flush guest frame");
    }

    fn receive_host(
        reader: &mut FrameReader<UnixStream>,
        session: &mut WorkloadSession,
    ) -> WorkloadMessage {
        let frame = reader.read_frame().expect("host frame");
        session
            .accept(
                Direction::HostToGuest,
                frame.header.kind,
                frame.header.sequence,
            )
            .expect("host message state");
        decode_workload_message(&frame).expect("host message")
    }

    fn sample_start() -> Start {
        let platform = pocket_protocol::Platform {
            os: "linux".to_owned(),
            architecture: "amd64".to_owned(),
            variant: None,
        };
        Start {
            profile_id: "x86_64-smp-p4k".to_owned(),
            profile_revision: "44".repeat(32),
            generation_id: "55".repeat(32),
            descriptor_platform: None,
            config_platform: platform.clone(),
            effective_platform: platform,
            selector_policy: "native-v1".to_owned(),
            root_layout: "pocket-root-v1".to_owned(),
            filesystem_contract: "ext4-v1-b4096".to_owned(),
            argv: vec!["/bin/true".to_owned()],
            env: vec!["PATH=/usr/bin:/bin".to_owned()],
            cwd: "/".to_owned(),
            uid: 0,
            gid: 0,
            supplementary_gids: Vec::new(),
            umask: 0o022,
            rlimits: Vec::new(),
            hostname: "pocket".to_owned(),
            root_read_only: false,
            volumes: Vec::new(),
            terminal: false,
            network_mode: 0,
            privileged: false,
            stdin_streaming: false,
            terminal_rows: 0,
            terminal_columns: 0,
            stop_signal: 15,
            derivation_key: "66".repeat(32),
            account_db_sha256: "77".repeat(32),
            stdin_bytes: 0,
        }
    }
}
