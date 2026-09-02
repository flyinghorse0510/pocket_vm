use std::{
    collections::VecDeque,
    convert::Infallible,
    ffi::{CString, OsString},
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::{
        fd::{AsFd, AsRawFd, FromRawFd, OwnedFd},
        unix::fs::{FileTypeExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use nix::{
    errno::Errno,
    fcntl::{FcntlArg, OFlag, OpenHow, ResolveFlag, fcntl, open, openat2},
    mount::{MntFlags, MsFlags, mount, umount2},
    poll::{PollFd, PollFlags, poll},
    pty::{Winsize, openpty},
    sched::{CloneFlags, unshare},
    sys::{
        prctl,
        reboot::{RebootMode, reboot},
        resource::{Resource, setrlimit},
        signal::{
            SaFlags, SigAction, SigHandler, SigSet, SigmaskHow, Signal as UnixSignal, kill,
            pthread_sigmask, sigaction,
        },
        stat::{Mode, SFlag, makedev, mkdirat, mknod, umask},
        statvfs::{FsFlags, statvfs},
        termios::{SetArg, cfmakeraw, tcgetattr, tcsetattr},
        utsname::uname,
    },
    unistd::{
        ForkResult, Gid, Pid, SysconfVar, Uid, chdir, chroot, dup, dup2_stderr, dup2_stdin,
        dup2_stdout, execve, fork, getpid, pipe2, setgid, setgroups, sethostname, setpgid, setsid,
        setuid, sync, syncfs, sysconf,
    },
};
use pocket_protocol::{
    Direction, Exit, FrameReader, FrameWriter, Hello, Ready, Resize, Signal, Start,
    WORKLOAD_GUEST_FEATURES, WorkloadMessage, WorkloadSession, decode_workload_message,
};

use crate::{
    CapabilitySets, ControlFrameDecoder, GuestConfig, GuestObservation, InitError, InternalEvent,
    InternalEventDecoder, PumpBuffer, RootReadOnlyGuards, capability_is_allowed,
    decode_generation_marker, fixed_root_capability_sets, full_root_capability_sets,
    uid_zero_read_only_guards_hold, verify_generation_marker, verify_start,
};

nix::ioctl_none_bad!(set_controlling_tty, libc::TIOCSCTTY);
nix::ioctl_write_ptr_bad!(set_window_size, libc::TIOCSWINSZ, libc::winsize);

const CMDLINE_LIMIT: usize = 64 * 1024;
const MARKER_LIMIT: usize = crate::contract::MAX_GENERATION_MARKER_BYTES;
const IO_CHUNK: usize = 8192;
const OUTPUT_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

pub fn run() -> Result<Infallible, InitError> {
    if getpid().as_raw() != 1 {
        return Err(InitError::contract(
            "early-boot",
            "pocket-init must run as guest PID 1",
        ));
    }

    block_sigpipe()?;
    mount_early_filesystems()?;
    bring_loopback_up()?;
    let cmdline = read_bounded_text("/proc/cmdline", CMDLINE_LIMIT, "cmdline")?;
    let config = GuestConfig::parse_cmdline(cmdline.trim_end())?;
    let mut ttys = TtyStreams::open(&config)?;

    let mut session = WorkloadSession::new();
    let mut writer = FrameWriter::new(ttys.control_writer);
    // From here the control channel exists, so every failure travels over it --
    // including one that happens before HELLO, which would otherwise reach the
    // host as a bare startup timeout with no cause attached.
    let result = (|| {
        let observation = observe_guest(&config)?;
        send_guest_message(
            &mut writer,
            &mut session,
            WorkloadMessage::Hello(make_hello(&config, &observation)),
        )?;
        run_after_hello(
            &config,
            &observation,
            &mut ttys.control_reader,
            &mut writer,
            &mut session,
            (ttys.stdin, ttys.stdout, ttys.stderr),
        )
    })();

    match result {
        Ok(exit) => {
            send_guest_message(&mut writer, &mut session, WorkloadMessage::Exit(exit))?;
        }
        Err(error) => {
            let message = WorkloadMessage::Error(error.to_protocol_message());
            let _ = send_guest_message(&mut writer, &mut session, message);
        }
    }
    let _ = writer.flush();
    sync();
    reboot(RebootMode::RB_POWER_OFF).map_err(|error| InitError::syscall("poweroff", error))
}

/// Last-resort PID-1 failure path. This is intentionally a no-return loop: a
/// returned init process causes a kernel panic and obscures the original error.
pub fn emergency_poweroff() -> ! {
    sync();
    let _ = reboot(RebootMode::RB_POWER_OFF);
    loop {
        nix::unistd::pause();
    }
}

fn run_after_hello(
    config: &GuestConfig,
    first_observation: &GuestObservation,
    control_reader: &mut File,
    writer: &mut FrameWriter<File>,
    session: &mut WorkloadSession,
    stdio: (File, File, File),
) -> Result<Exit, InitError> {
    let (stdin, stdout, stderr) = stdio;
    let mut reader = FrameReader::new(&mut *control_reader);
    let frame = reader
        .read_frame()
        .map_err(|error| InitError::protocol("receive-start", error))?;
    session
        .accept(
            Direction::HostToGuest,
            frame.header.kind,
            frame.header.sequence,
        )
        .map_err(|error| InitError::protocol("receive-start", error))?;
    let start = match decode_workload_message(&frame)
        .map_err(|error| InitError::protocol("receive-start", error))?
    {
        WorkloadMessage::Start(start) => *start,
        other => {
            return Err(InitError::contract(
                "receive-start",
                format!("expected START, received kind {}", other.kind() as u16),
            ));
        }
    };

    let second_observation = observe_guest(config)?;
    if &second_observation != first_observation {
        return Err(InitError::contract(
            "start-contract",
            "guest architecture, page size, or online CPU count changed during handshake",
        ));
    }
    verify_start(config, &second_observation, &start)?;

    // Before the workload's namespaces are built: the workload does not get
    // its own network namespace, so this configures the one it will use.
    if start.network_mode == 1 {
        configure_slirp_network()?;
    }

    let mut volume = MountedVolume::mount(config, start.root_read_only)?;
    let workload_result = (|| {
        verify_volume(config, &start)?;
        prepare_image_directories(config, &start)?;
        let topology = IoTopology::new(
            start.terminal,
            start.stdin_streaming,
            Winsize {
                ws_row: start.terminal_rows,
                ws_col: start.terminal_columns,
                ws_xpixel: 0,
                ws_ypixel: 0,
            },
            start.stdin_bytes,
            stdin,
            stdout,
            stderr,
        )?;
        let started = Instant::now();
        let (status, namespace_clean) =
            run_namespace(config, &start, control_reader, writer, session, topology)?;
        let elapsed_ns = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
        Ok::<_, InitError>((status, namespace_clean, elapsed_ns))
    })();

    let volume_clean = volume.sync_and_unmount();
    let (status, namespace_clean, elapsed_ns) = workload_result?;
    Ok(Exit {
        code: status.code,
        signal: status.signal,
        elapsed_ns,
        filesystem_clean: volume_clean && namespace_clean,
    })
}

fn send_guest_message(
    writer: &mut FrameWriter<File>,
    session: &mut WorkloadSession,
    message: WorkloadMessage,
) -> Result<(), InitError> {
    let kind = message.kind();
    let payload = message
        .encode_payload()
        .map_err(|error| InitError::protocol("send-control", error))?;
    let sequence = writer.next_sequence();
    session
        .accept(Direction::GuestToHost, kind, sequence)
        .map_err(|error| InitError::protocol("send-control", error))?;
    let written = writer
        .write_frame(kind, &payload)
        .map_err(|error| InitError::protocol("send-control", error))?;
    if written != sequence {
        return Err(InitError::contract(
            "send-control",
            "frame writer sequence changed unexpectedly",
        ));
    }
    writer
        .flush()
        .map_err(|error| InitError::protocol("send-control", error))
}

fn make_hello(config: &GuestConfig, observation: &GuestObservation) -> Hello {
    Hello {
        guest_contract_id: config.guest_contract_id.clone(),
        init_build_id: config.init_build_id.clone(),
        kernel_build_id: config.kernel_build_id.clone(),
        host_elf_machine: observation.elf_machine,
        guest_uts_machine: observation.uts_machine.clone(),
        guest_page_size: observation.page_size,
        cpu_state_hwcap_policy: config.cpu_state_hwcap_policy.clone(),
        features: WORKLOAD_GUEST_FEATURES
            .iter()
            .map(|feature| (*feature).to_owned())
            .collect(),
        online_cpus: observation.online_cpus,
        accepted_physmem_bytes: observation.accepted_physmem_bytes,
        guest_capability_policy: config.guest_capability_policy.clone(),
    }
}

fn observe_guest(config: &GuestConfig) -> Result<GuestObservation, InitError> {
    let uts = uname().map_err(|error| InitError::syscall("observe-guest", error))?;
    let uts_machine = uts
        .machine()
        .to_str()
        .ok_or_else(|| InitError::contract("observe-guest", "UTS machine is not UTF-8"))?
        .to_owned();
    let (oci_architecture, elf_machine) = match uts_machine.as_str() {
        "x86_64" => ("amd64", 62),
        "aarch64" => ("arm64", 183),
        _ => {
            return Err(InitError::contract(
                "observe-guest",
                format!("unsupported UTS machine {uts_machine:?}"),
            ));
        }
    };
    if oci_architecture != config.expected_oci_architecture {
        return Err(InitError::contract(
            "observe-guest",
            "observed architecture differs from boot configuration",
        ));
    }
    let page_size = required_sysconf(SysconfVar::PAGE_SIZE, "page size")?;
    let page_size = u32::try_from(page_size)
        .map_err(|_| InitError::contract("observe-guest", "page size does not fit in u32"))?;
    let online_cpus = required_sysconf(SysconfVar::_NPROCESSORS_ONLN, "online CPU count")?;
    let online_cpus = u16::try_from(online_cpus).map_err(|_| {
        InitError::contract("observe-guest", "online CPU count does not fit in u16")
    })?;
    if online_cpus != config.expected_cpus {
        return Err(InitError::contract(
            "observe-guest",
            format!(
                "observed {online_cpus} online CPUs; boot contract requires {}",
                config.expected_cpus
            ),
        ));
    }
    let accepted_physmem_text = read_bounded_text("/proc/uml_physmem_bytes", 32, "observe-guest")?;
    let accepted_physmem_bytes = accepted_physmem_text.trim().parse::<u64>().map_err(|_| {
        InitError::contract(
            "observe-guest",
            "/proc/uml_physmem_bytes is not an unsigned byte count",
        )
    })?;
    if accepted_physmem_bytes == 0 || !accepted_physmem_bytes.is_multiple_of(u64::from(page_size)) {
        return Err(InitError::contract(
            "observe-guest",
            "accepted UML physical memory is zero or not guest-page aligned",
        ));
    }
    if accepted_physmem_bytes != config.expected_memory_bytes {
        return Err(InitError::contract(
            "observe-guest",
            format!(
                "UML accepted {accepted_physmem_bytes} physical-memory bytes; requested {}",
                config.expected_memory_bytes
            ),
        ));
    }
    Ok(GuestObservation {
        uts_machine,
        oci_architecture: oci_architecture.to_owned(),
        page_size,
        online_cpus,
        elf_machine,
        accepted_physmem_bytes,
    })
}

fn required_sysconf(variable: SysconfVar, name: &str) -> Result<i64, InitError> {
    sysconf(variable)
        .map_err(|error| InitError::syscall("observe-guest", error))?
        .ok_or_else(|| InitError::contract("observe-guest", format!("{name} is unavailable")))
}

fn block_sigpipe() -> Result<(), InitError> {
    let mut signals = SigSet::empty();
    signals.add(UnixSignal::SIGPIPE);
    pthread_sigmask(SigmaskHow::SIG_BLOCK, Some(&signals), None)
        .map_err(|error| InitError::syscall("early-boot", error))
}

struct TtyStreams {
    control_reader: File,
    control_writer: File,
    stdin: File,
    stdout: File,
    stderr: File,
}

impl TtyStreams {
    fn open(config: &GuestConfig) -> Result<Self, InitError> {
        let control_reader = open_raw_tty(&config.ttys.control, "open-control")?;
        // Use a separate open file description: O_NONBLOCK is enabled only on
        // the reader after START and must not affect framed writes.
        let control_writer = open_raw_tty(&config.ttys.control, "open-control")?;
        Ok(Self {
            control_reader,
            control_writer,
            stdin: open_raw_tty(&config.ttys.stdin, "open-stdin")?,
            stdout: open_raw_tty(&config.ttys.stdout, "open-stdout")?,
            stderr: open_raw_tty(&config.ttys.stderr, "open-stderr")?,
        })
    }
}

fn open_raw_tty(path: &str, stage: &'static str) -> Result<File, InitError> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOCTTY)
        .open(path)
        .map_err(|error| InitError::io(stage, error))?;
    let mut attributes = tcgetattr(&file).map_err(|error| InitError::syscall(stage, error))?;
    cfmakeraw(&mut attributes);
    tcsetattr(&file, SetArg::TCSANOW, &attributes)
        .map_err(|error| InitError::syscall(stage, error))?;
    Ok(file)
}

fn mount_early_filesystems() -> Result<(), InitError> {
    for path in ["/proc", "/sys", "/dev", "/dev/pts", "/run", "/tmp"] {
        fs::create_dir_all(path).map_err(|error| InitError::io("early-mount", error))?;
    }
    mount_allow_busy(
        None,
        "/dev",
        Some("devtmpfs"),
        MsFlags::MS_NOSUID,
        Some("mode=0755"),
    )?;
    // The devtmpfs mount hides the initramfs directory tree that was visible
    // at /dev, including the /dev/pts mount point created above. Recreate the
    // mount point in devtmpfs before attempting the devpts mount.
    recreate_devpts_mountpoint(Path::new("/dev"))?;
    mount_allow_busy(
        Some("devpts"),
        "/dev/pts",
        Some("devpts"),
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
        Some("mode=0620,ptmxmode=0666"),
    )?;
    mount_allow_busy(
        Some("proc"),
        "/proc",
        Some("proc"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
        None,
    )?;
    mount_allow_busy(
        Some("sysfs"),
        "/sys",
        Some("sysfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
        None,
    )?;
    mount_allow_busy(
        Some("tmpfs"),
        "/run",
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
        Some("mode=0755,size=16m"),
    )?;
    mount_allow_busy(
        Some("tmpfs"),
        "/tmp",
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
        Some("mode=1777,size=64m"),
    )
}

fn recreate_devpts_mountpoint(dev_root: &Path) -> Result<(), InitError> {
    fs::create_dir_all(dev_root.join("pts")).map_err(|error| InitError::io("early-mount", error))
}

fn bring_loopback_up() -> Result<(), InitError> {
    // SAFETY: socket receives scalar Linux ABI values and returns a new owned
    // descriptor on success.
    let raw_socket =
        unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if raw_socket < 0 {
        return Err(InitError::io("loopback", io::Error::last_os_error()));
    }
    // SAFETY: raw_socket was just returned as a unique successful socket.
    let socket = unsafe { OwnedFd::from_raw_fd(raw_socket) };
    // SAFETY: all-zero is a valid initial ifreq representation; the union is
    // populated by SIOCGIFFLAGS before its flags member is read.
    let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
    request.ifr_name[0] = b'l' as libc::c_char;
    request.ifr_name[1] = b'o' as libc::c_char;

    // SAFETY: SIOCGIFFLAGS writes into the valid mutable ifreq and does not
    // retain its pointer beyond the ioctl.
    let result = unsafe { libc::ioctl(socket.as_raw_fd(), libc::SIOCGIFFLAGS, &mut request) };
    if result != 0 {
        return Err(InitError::io("loopback", io::Error::last_os_error()));
    }
    // SAFETY: SIOCGIFFLAGS initialized the flags union member.
    let current_flags = unsafe { request.ifr_ifru.ifru_flags };
    request.ifr_ifru.ifru_flags = loopback_flags_with_up(current_flags);
    // SAFETY: SIOCSIFFLAGS reads the initialized name and flags fields only.
    let result = unsafe { libc::ioctl(socket.as_raw_fd(), libc::SIOCSIFFLAGS, &request) };
    if result != 0 {
        return Err(InitError::io("loopback", io::Error::last_os_error()));
    }

    // Verify the kernel-observed state rather than trusting a successful set.
    // SAFETY: same valid mutable ifreq contract as the first query.
    let result = unsafe { libc::ioctl(socket.as_raw_fd(), libc::SIOCGIFFLAGS, &mut request) };
    if result != 0 {
        return Err(InitError::io("loopback", io::Error::last_os_error()));
    }
    // SAFETY: the successful query initialized the flags union member.
    let observed_flags = unsafe { request.ifr_ifru.ifru_flags };
    if observed_flags & (libc::IFF_UP as libc::c_short) == 0 {
        return Err(InitError::contract(
            "loopback",
            "loopback interface did not remain administratively up",
        ));
    }
    Ok(())
}

const fn loopback_flags_with_up(flags: libc::c_short) -> libc::c_short {
    flags | libc::IFF_UP as libc::c_short
}

/// Give the vector device its address, netmask and default route.
///
/// The addressing is the profile's sealed `slirp-bess-v1` contract rather than
/// anything discovered at run time: the host configured the helper from the
/// same constants. Done with ioctls for the same reason the loopback setup is
/// -- the guest carries no netlink library, and every step is verified against
/// what the kernel reports rather than a successful return code.
fn configure_slirp_network() -> Result<(), InitError> {
    use pocket_protocol::{
        SLIRP_GATEWAY_ADDRESS, SLIRP_GUEST_ADDRESS, SLIRP_INTERFACE, SLIRP_PREFIX_LENGTH,
    };

    // SAFETY: socket receives scalar Linux ABI values and returns a new owned
    // descriptor on success.
    let raw_socket =
        unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if raw_socket < 0 {
        return Err(InitError::io("network", io::Error::last_os_error()));
    }
    // SAFETY: raw_socket was just returned as a unique successful socket.
    let socket = unsafe { OwnedFd::from_raw_fd(raw_socket) };

    let name_bytes = SLIRP_INTERFACE.as_bytes();
    if name_bytes.len() >= libc::IFNAMSIZ {
        return Err(InitError::contract("network", "interface name is too long"));
    }
    let set_name = |request: &mut libc::ifreq| {
        for (slot, byte) in request.ifr_name.iter_mut().zip(name_bytes) {
            *slot = *byte as libc::c_char;
        }
    };
    let sockaddr_for = |octets: [u8; 4]| -> libc::sockaddr {
        let address = libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: 0,
            sin_addr: libc::in_addr {
                s_addr: u32::from_ne_bytes(octets),
            },
            sin_zero: [0; 8],
        };
        // SAFETY: sockaddr_in and sockaddr have the same size and alignment
        // for this ABI, and every byte of the source is initialized.
        unsafe { std::mem::transmute::<libc::sockaddr_in, libc::sockaddr>(address) }
    };

    let netmask = {
        let bits = u32::MAX
            .checked_shl(u32::from(32 - SLIRP_PREFIX_LENGTH))
            .unwrap_or(0);
        bits.to_be_bytes()
    };

    for (request_code, octets, stage) in [
        (libc::SIOCSIFADDR, SLIRP_GUEST_ADDRESS, "address"),
        (libc::SIOCSIFNETMASK, netmask, "netmask"),
    ] {
        // SAFETY: all-zero is a valid initial ifreq representation.
        let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
        set_name(&mut request);
        request.ifr_ifru.ifru_addr = sockaddr_for(octets);
        // SAFETY: the ioctl reads the initialized name and address fields only.
        let result = unsafe { libc::ioctl(socket.as_raw_fd(), request_code, &request) };
        if result != 0 {
            return Err(InitError::io(
                match stage {
                    "address" => "network-address",
                    _ => "network-netmask",
                },
                io::Error::last_os_error(),
            ));
        }
    }

    // Bring it up, then confirm the kernel agrees it is up.
    // SAFETY: all-zero is a valid initial ifreq representation.
    let mut flags_request: libc::ifreq = unsafe { std::mem::zeroed() };
    set_name(&mut flags_request);
    // SAFETY: SIOCGIFFLAGS writes into the valid mutable ifreq.
    if unsafe { libc::ioctl(socket.as_raw_fd(), libc::SIOCGIFFLAGS, &mut flags_request) } != 0 {
        return Err(InitError::io("network-flags", io::Error::last_os_error()));
    }
    // SAFETY: SIOCGIFFLAGS initialized the flags union member.
    let current = unsafe { flags_request.ifr_ifru.ifru_flags };
    flags_request.ifr_ifru.ifru_flags =
        current | (libc::IFF_UP as libc::c_short) | (libc::IFF_RUNNING as libc::c_short);
    // SAFETY: SIOCSIFFLAGS reads the initialized name and flags fields only.
    if unsafe { libc::ioctl(socket.as_raw_fd(), libc::SIOCSIFFLAGS, &flags_request) } != 0 {
        return Err(InitError::io("network-up", io::Error::last_os_error()));
    }
    // SAFETY: same valid mutable ifreq contract as the first query.
    if unsafe { libc::ioctl(socket.as_raw_fd(), libc::SIOCGIFFLAGS, &mut flags_request) } != 0 {
        return Err(InitError::io("network-flags", io::Error::last_os_error()));
    }
    // SAFETY: the successful query initialized the flags union member.
    let observed = unsafe { flags_request.ifr_ifru.ifru_flags };
    if observed & (libc::IFF_UP as libc::c_short) == 0 {
        return Err(InitError::contract(
            "network-up",
            "vector interface did not remain administratively up",
        ));
    }

    // Default route through the helper's gateway address.
    // SAFETY: all-zero is a valid initial rtentry representation.
    let mut route: libc::rtentry = unsafe { std::mem::zeroed() };
    route.rt_dst = sockaddr_for([0, 0, 0, 0]);
    route.rt_genmask = sockaddr_for([0, 0, 0, 0]);
    route.rt_gateway = sockaddr_for(SLIRP_GATEWAY_ADDRESS);
    route.rt_flags = (libc::RTF_UP | libc::RTF_GATEWAY) as libc::c_ushort;
    // SAFETY: SIOCADDRT reads the initialized rtentry and retains no pointer.
    if unsafe { libc::ioctl(socket.as_raw_fd(), libc::SIOCADDRT, &route) } != 0 {
        return Err(InitError::io("network-route", io::Error::last_os_error()));
    }
    Ok(())
}

fn mount_allow_busy(
    source: Option<&str>,
    target: &str,
    filesystem: Option<&str>,
    flags: MsFlags,
    data: Option<&str>,
) -> Result<(), InitError> {
    match mount(source, target, filesystem, flags, data) {
        Ok(()) | Err(Errno::EBUSY) => Ok(()),
        Err(error) => Err(InitError::syscall("early-mount", error)),
    }
}

fn read_bounded_text(path: &str, maximum: usize, stage: &'static str) -> Result<String, InitError> {
    let file = File::open(path).map_err(|error| InitError::io(stage, error))?;
    let limit = u64::try_from(maximum).unwrap_or(u64::MAX).saturating_add(1);
    let mut bytes = Vec::new();
    file.take(limit)
        .read_to_end(&mut bytes)
        .map_err(|error| InitError::io(stage, error))?;
    if bytes.len() > maximum {
        return Err(InitError::contract(
            stage,
            format!("{path} exceeds the {maximum}-byte hard cap"),
        ));
    }
    String::from_utf8(bytes)
        .map_err(|_| InitError::contract(stage, format!("{path} is not valid UTF-8")))
}

struct MountedVolume {
    path: String,
    sync_file: Option<File>,
    mounted: bool,
}

impl MountedVolume {
    fn mount(config: &GuestConfig, _root_read_only: bool) -> Result<Self, InitError> {
        fs::create_dir_all(&config.volume_mount)
            .map_err(|error| InitError::io("mount-root-volume", error))?;
        mount(
            Some(config.root_device.as_str()),
            config.volume_mount.as_str(),
            Some("ext4"),
            MsFlags::empty(),
            None::<&str>,
        )
        .map_err(|error| InitError::syscall("mount-root-volume", error))?;
        let sync_file = match File::open(&config.volume_mount) {
            Ok(file) => file,
            Err(error) => {
                let _ = umount2(config.volume_mount.as_str(), MntFlags::empty());
                return Err(InitError::io("mount-root-volume", error));
            }
        };
        Ok(Self {
            path: config.volume_mount.clone(),
            sync_file: Some(sync_file),
            mounted: true,
        })
    }

    fn sync_and_unmount(&mut self) -> bool {
        // A live directory descriptor into the mounted ext4 keeps the mount
        // busy.  Use it for syncfs, then close it before asking the kernel to
        // unmount the filesystem.
        let synced = self.sync_file.take().is_none_or(|sync_file| {
            let result = syncfs(&sync_file).is_ok();
            drop(sync_file);
            result
        });
        let unmounted = if self.mounted {
            let result = umount2(self.path.as_str(), MntFlags::empty()).is_ok();
            if result {
                self.mounted = false;
            }
            result
        } else {
            true
        };
        synced && unmounted
    }
}

fn verify_volume(config: &GuestConfig, start: &Start) -> Result<(), InitError> {
    let image_root = PathBuf::from(config.image_root());
    let metadata = fs::symlink_metadata(&image_root)
        .map_err(|error| InitError::io("verify-root-volume", error))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(InitError::contract(
            "verify-root-volume",
            "/volume/rootfs must be a real directory",
        ));
    }
    let marker_path = config.generation_marker_path();
    let marker_text = read_bounded_bytes(&marker_path, MARKER_LIMIT, "generation-marker")?;
    let marker = decode_generation_marker(&marker_text)?;
    verify_generation_marker(&marker, start)
}

fn read_bounded_bytes(
    path: &str,
    maximum: usize,
    stage: &'static str,
) -> Result<Vec<u8>, InitError> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| InitError::io(stage, error))?;
    if !file
        .metadata()
        .map_err(|error| InitError::io(stage, error))?
        .is_file()
    {
        return Err(InitError::contract(stage, "marker must be a regular file"));
    }
    let limit = u64::try_from(maximum).unwrap_or(u64::MAX).saturating_add(1);
    let mut bytes = Vec::new();
    file.take(limit)
        .read_to_end(&mut bytes)
        .map_err(|error| InitError::io(stage, error))?;
    if bytes.len() > maximum {
        return Err(InitError::contract(stage, "marker exceeds hard cap"));
    }
    Ok(bytes)
}

fn prepare_image_directories(config: &GuestConfig, start: &Start) -> Result<(), InitError> {
    let root = config.image_root();
    for path in [
        "etc",
        "proc",
        "sys",
        "dev",
        "dev/pts",
        "dev/mqueue",
        "dev/shm",
        "run",
    ] {
        ensure_directory_beneath(&root, path, 0o755)?;
    }
    if start.cwd != "/" {
        let relative = start.cwd.strip_prefix('/').ok_or_else(|| {
            InitError::contract("prepare-root", "working directory is not absolute")
        })?;
        ensure_directory_beneath(&root, relative, 0o755)?;
    }
    // Only the mount points are made here. The hostfs mounts themselves happen
    // inside the workload's own mount namespace, so they are torn down with it
    // rather than pinning the image-root bind and failing its unmount.
    for volume in &start.volumes {
        let relative = volume.destination.strip_prefix('/').ok_or_else(|| {
            InitError::contract("prepare-root", "volume destination is not absolute")
        })?;
        if relative.is_empty() {
            return Err(InitError::contract(
                "prepare-root",
                "volume destination must not be the image root",
            ));
        }
        ensure_directory_beneath(&root, relative, 0o755)?;
    }
    fs::create_dir_all(&config.newroot_mount)
        .map_err(|error| InitError::io("prepare-root", error))?;
    let mut entries = fs::read_dir(&config.newroot_mount)
        .map_err(|error| InitError::io("prepare-root", error))?;
    if entries.next().is_some() {
        return Err(InitError::contract(
            "prepare-root",
            "newroot mount point is not empty",
        ));
    }
    Ok(())
}

/// Mount every requested host directory into the image root through hostfs.
///
/// The destination is created inside the root with the same containment as any
/// other guest path, so a volume cannot be used to write outside the image.
/// The source is a host path: hostfs hands the guest the host's own files, so
/// what the workload writes is visible on the host immediately and survives
/// the run, which a copy-on-write overlay deliberately does not.
fn mount_host_volumes(
    root: &str,
    start: &Start,
    targets: &mut Vec<String>,
) -> Result<(), InitError> {
    for volume in &start.volumes {
        let relative = volume.destination.strip_prefix('/').ok_or_else(|| {
            InitError::contract("mount-volume", "volume destination is not absolute")
        })?;
        if relative.is_empty() {
            return Err(InitError::contract(
                "mount-volume",
                "volume destination must not be the image root",
            ));
        }
        // Resolve the destination inside the image root before mounting on
        // it. `mount` follows symlinks in its target, and an absolute one in
        // the image -- `/data -> /etc` -- resolves against the initramfs root
        // we are still standing in, so the share would land on the wrong
        // filesystem entirely and the teardown would unmount that. Resolving
        // in-root first gives the path the guest itself will see.
        let target = resolve_beneath(root, relative)?;
        let mut flags = MsFlags::MS_NOSUID | MsFlags::MS_NODEV;
        if volume.read_only {
            flags |= MsFlags::MS_RDONLY;
        }
        mount(
            Some("none"),
            target.as_str(),
            Some("hostfs"),
            flags,
            Some(volume.source.as_str()),
        )
        .map_err(|error| InitError::syscall("mount-volume", error))?;

        // hostfs honours MS_RDONLY only on a remount, so ask again rather than
        // hand a workload a writable mount it was told was read-only.
        if volume.read_only {
            mount(
                Some("none"),
                target.as_str(),
                Some("hostfs"),
                flags | MsFlags::MS_REMOUNT,
                Some(volume.source.as_str()),
            )
            .map_err(|error| InitError::syscall("mount-volume", error))?;
        }
        targets.push(target);
    }
    Ok(())
}

/// Resolve `relative` beneath `root` the way the guest will, and return the
/// real path it names.
///
/// The directory itself must already exist; this only says where it is. The
/// answer is always inside `root`, because `RESOLVE_IN_ROOT` makes an absolute
/// symlink resolve against `root` rather than the filesystem root we are
/// standing in, and the containment is re-checked on the returned path.
fn resolve_beneath(root: &str, relative: &str) -> Result<String, InitError> {
    let root_fd = open(
        root,
        OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| InitError::syscall("resolve-beneath", error))?;
    let resolved = openat2(
        &root_fd,
        relative,
        OpenHow::new()
            .flags(OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC)
            .resolve(ResolveFlag::RESOLVE_IN_ROOT | ResolveFlag::RESOLVE_NO_MAGICLINKS),
    )
    .map_err(|error| InitError::syscall("resolve-beneath", error))?;
    let path = fs::read_link(format!("/proc/self/fd/{}", resolved.as_raw_fd()))
        .map_err(|error| InitError::io("resolve-beneath", error))?
        .into_os_string()
        .into_string()
        .map_err(|_| InitError::contract("resolve-beneath", "resolved path is not valid UTF-8"))?;
    // RESOLVE_IN_ROOT already guarantees this; saying it again costs nothing
    // and keeps a wrong answer from ever reaching mount().
    if path != root && !path.starts_with(&format!("{root}/")) {
        return Err(InitError::contract(
            "resolve-beneath",
            "resolved path escaped the image root",
        ));
    }
    Ok(path)
}

/// Create `relative` beneath `root`, following symlinks that stay inside the
/// root and refusing any that would escape it.
///
/// Refusing to follow symlinks at all is not an option: merged-usr images make
/// `/lib`, `/bin` and `/sbin` symlinks, and nearly every image makes
/// `/var/run` one, so an ordinary working directory such as `/var/run` would
/// be rejected with a bare ENOTDIR. `RESOLVE_IN_ROOT` gives the containment
/// the previous `O_NOFOLLOW` walk was reaching for while resolving symlinks
/// the way the guest itself will: relative to the new root.
fn ensure_directory_beneath(root: &str, relative: &str, mode: u32) -> Result<(), InitError> {
    let root_fd = open(
        root,
        OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| InitError::syscall("prepare-root", error))?;

    let scoped = |path: &str| -> Result<OwnedFd, Errno> {
        openat2(
            &root_fd,
            path,
            OpenHow::new()
                .flags(OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC)
                .resolve(ResolveFlag::RESOLVE_IN_ROOT | ResolveFlag::RESOLVE_NO_MAGICLINKS),
        )
    };

    let mut walked = String::new();
    for component in relative.split('/') {
        if component.is_empty() || matches!(component, "." | "..") {
            return Err(InitError::contract(
                "prepare-root",
                "directory path is not normalized",
            ));
        }
        // Resolve the parent inside the root, then create the child in it.
        let parent = scoped(if walked.is_empty() {
            "."
        } else {
            walked.as_str()
        })
        .map_err(|error| InitError::syscall("prepare-root", error))?;
        match mkdirat(&parent, component, Mode::from_bits_truncate(mode)) {
            Ok(()) | Err(Errno::EEXIST) => {}
            Err(error) => return Err(InitError::syscall("prepare-root", error)),
        }
        if !walked.is_empty() {
            walked.push('/');
        }
        walked.push_str(component);
        // Re-resolve the accumulated path so a symlinked component is followed
        // within the root and anything that is not a directory still fails.
        scoped(walked.as_str()).map_err(|error| InitError::syscall("prepare-root", error))?;
    }
    Ok(())
}

struct IoTopology {
    pumps: PumpSet,
    child: ChildIo,
}

impl IoTopology {
    fn new(
        terminal: bool,
        stdin_streaming: bool,
        initial_size: Winsize,
        stdin_bytes: u64,
        stdin: File,
        stdout: File,
        stderr: File,
    ) -> Result<Self, InitError> {
        if terminal {
            // A streamed session announces no length: the pump runs until the
            // host hangs the channel up. The workload still sees end of file,
            // because the line discipline delivers it from the operator's VEOF
            // key rather than from the channel.
            let announced = (!stdin_streaming).then_some(stdin_bytes);
            Self::terminal(announced, initial_size, stdin, stdout, stderr)
        } else {
            Self::nonterminal(stdin_bytes, stdin, stdout, stderr)
        }
    }

    fn nonterminal(
        stdin_bytes: u64,
        stdin: File,
        stdout: File,
        stderr: File,
    ) -> Result<Self, InitError> {
        let (child_stdin, parent_stdin) =
            pipe2(OFlag::O_CLOEXEC).map_err(|error| InitError::syscall("stdio-pipes", error))?;
        let (parent_stdout, child_stdout) =
            pipe2(OFlag::O_CLOEXEC).map_err(|error| InitError::syscall("stdio-pipes", error))?;
        let (parent_stderr, child_stderr) =
            pipe2(OFlag::O_CLOEXEC).map_err(|error| InitError::syscall("stdio-pipes", error))?;

        let pumps = PumpSet::new(
            false,
            vec![
                StreamPump::new("stdin", stdin, File::from(parent_stdin), false, false)?
                    .with_input_limit(stdin_bytes),
                StreamPump::new("stdout", File::from(parent_stdout), stdout, true, false)?,
                StreamPump::new("stderr", File::from(parent_stderr), stderr, true, false)?,
            ],
            None,
        );
        Ok(Self {
            pumps,
            child: ChildIo::Pipes {
                stdin: child_stdin,
                stdout: child_stdout,
                stderr: child_stderr,
            },
        })
    }

    fn terminal(
        stdin_bytes: Option<u64>,
        initial_size: Winsize,
        stdin: File,
        stdout: File,
        _stderr: File,
    ) -> Result<Self, InitError> {
        let pty = openpty(Some(&initial_size), None)
            .map_err(|error| InitError::syscall("terminal-pty", error))?;
        let master_for_input = dup(&pty.master)
            .map(File::from)
            .map_err(|error| InitError::syscall("terminal-pty", error))?;
        let master_for_output = dup(&pty.master)
            .map(File::from)
            .map_err(|error| InitError::syscall("terminal-pty", error))?;
        let master_for_resize = File::from(pty.master);
        let pumps = PumpSet::new(
            true,
            vec![
                match stdin_bytes {
                    Some(announced) => {
                        StreamPump::new("terminal-input", stdin, master_for_input, false, false)?
                            .with_input_limit(announced)
                    }
                    None => {
                        StreamPump::new("terminal-input", stdin, master_for_input, false, false)?
                    }
                },
                StreamPump::new("terminal-output", master_for_output, stdout, true, true)?,
            ],
            Some(master_for_resize),
        );
        Ok(Self {
            pumps,
            child: ChildIo::Terminal { slave: pty.slave },
        })
    }
}

enum ChildIo {
    Pipes {
        stdin: OwnedFd,
        stdout: OwnedFd,
        stderr: OwnedFd,
    },
    Terminal {
        slave: OwnedFd,
    },
}

impl ChildIo {
    fn install(self) -> Result<(), InitError> {
        match self {
            Self::Pipes {
                stdin,
                stdout,
                stderr,
            } => {
                setpgid(Pid::from_raw(0), Pid::from_raw(0))
                    .map_err(|error| InitError::syscall("child-stdio", error))?;
                dup2_stdin(&stdin).map_err(|error| InitError::syscall("child-stdio", error))?;
                dup2_stdout(&stdout).map_err(|error| InitError::syscall("child-stdio", error))?;
                dup2_stderr(&stderr).map_err(|error| InitError::syscall("child-stdio", error))?;
            }
            Self::Terminal { slave } => {
                setsid().map_err(|error| InitError::syscall("child-terminal", error))?;
                // SAFETY: `slave` is a live PTY slave descriptor and TIOCSCTTY
                // takes no pointer argument. The child is a fresh session leader.
                unsafe { set_controlling_tty(slave.as_raw_fd()) }
                    .map_err(|error| InitError::syscall("child-terminal", error))?;
                dup2_stdin(&slave).map_err(|error| InitError::syscall("child-terminal", error))?;
                dup2_stdout(&slave).map_err(|error| InitError::syscall("child-terminal", error))?;
                dup2_stderr(&slave).map_err(|error| InitError::syscall("child-terminal", error))?;
            }
        }
        Ok(())
    }
}

struct StreamPump {
    name: &'static str,
    source: Option<File>,
    sink: Option<File>,
    buffer: PumpBuffer,
    is_output: bool,
    eio_is_eof: bool,
    /// Exact remaining input the host announced for this stream, if any.
    remaining_input: Option<u64>,
}

impl StreamPump {
    fn new(
        name: &'static str,
        source: File,
        sink: File,
        is_output: bool,
        eio_is_eof: bool,
    ) -> Result<Self, InitError> {
        set_nonblocking(&source, "stream-pump")?;
        set_nonblocking(&sink, "stream-pump")?;
        Ok(Self {
            name,
            source: Some(source),
            sink: Some(sink),
            buffer: PumpBuffer::default(),
            is_output,
            eio_is_eof,
            remaining_input: None,
        })
    }

    /// Forward exactly `bytes` source bytes and then end the sink.
    ///
    /// The host announces its standard-input length in START and keeps the
    /// channel open for the whole run, because a User-Mode Linux serial line
    /// discards buffered input when its host descriptor disappears. Counting
    /// therefore replaces channel end-of-file as the terminator.
    fn with_input_limit(mut self, bytes: u64) -> Self {
        self.remaining_input = Some(bytes);
        if bytes == 0 {
            self.source = None;
            self.sink = None;
        }
        self
    }

    fn wants_read(&self) -> bool {
        self.source.is_some()
            && self.buffer.remaining_capacity() > 0
            && self.remaining_input != Some(0)
    }

    fn wants_write(&self) -> bool {
        self.sink.is_some() && !self.buffer.is_empty()
    }

    fn source_file(&self) -> Option<&File> {
        self.source.as_ref()
    }

    fn sink_file(&self) -> Option<&File> {
        self.sink.as_ref()
    }

    fn read_available(&mut self) -> Result<(), InitError> {
        loop {
            if self.remaining_input == Some(0) {
                self.source = None;
                break;
            }
            let remaining = self.buffer.remaining_capacity();
            if remaining == 0 {
                break;
            }
            let mut chunk = [0_u8; IO_CHUNK];
            let mut maximum = remaining.min(chunk.len());
            if let Some(budget) = self.remaining_input {
                maximum = maximum.min(usize::try_from(budget).unwrap_or(usize::MAX));
            }
            let Some(source) = self.source.as_mut() else {
                break;
            };
            match source.read(&mut chunk[..maximum]) {
                Ok(0) => {
                    if let Some(budget) = self.remaining_input
                        && budget > 0
                    {
                        // The host announces the payload length and holds the
                        // channel open for the whole run, so end-of-file here
                        // means the announced bytes will never arrive. Ending
                        // the workload's standard input would present a
                        // truncated payload as a complete one, which is the
                        // failure this contract exists to prevent.
                        return Err(InitError::contract(
                            "stream-pump",
                            format!(
                                "{} ended {budget} bytes before the announced length",
                                self.name
                            ),
                        ));
                    }
                    self.source = None;
                    break;
                }
                Ok(count) => {
                    let pushed = self.buffer.push(&chunk[..count]);
                    if pushed != count {
                        return Err(InitError::contract(
                            "stream-pump",
                            "bounded stream buffer accounting failed",
                        ));
                    }
                    if let Some(budget) = self.remaining_input.as_mut() {
                        *budget = budget.saturating_sub(count as u64);
                        if *budget == 0 {
                            // The announced payload is complete. Ending the
                            // source here closes the sink once the buffered
                            // remainder is written, which is the workload's
                            // standard-input end-of-file.
                            self.source = None;
                            break;
                        }
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) if self.eio_is_eof && error.raw_os_error() == Some(libc::EIO) => {
                    self.source = None;
                    break;
                }
                Err(error) => return Err(InitError::io("stream-pump", error)),
            }
        }
        if !self.is_output && self.sink.is_none() {
            // The workload closed its standard input. Keep draining the
            // announced payload so the host's bounded write never stalls.
            self.buffer.consume(self.buffer.len());
        }
        self.close_sink_after_eof();
        Ok(())
    }

    fn write_available(&mut self) -> Result<(), InitError> {
        while !self.buffer.is_empty() {
            let Some(sink) = self.sink.as_mut() else {
                return Err(InitError::contract(
                    "stream-pump",
                    format!("{} sink closed with buffered bytes", self.name),
                ));
            };
            match sink.write(self.buffer.readable()) {
                Ok(0) => {
                    return Err(InitError::contract(
                        "stream-pump",
                        format!("{} sink returned a zero-length write", self.name),
                    ));
                }
                Ok(count) => self.buffer.consume(count),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) if !self.is_output && error.kind() == io::ErrorKind::BrokenPipe => {
                    self.sink = None;
                    self.buffer.consume(self.buffer.len());
                    break;
                }
                Err(error) => return Err(InitError::io("stream-pump", error)),
            }
        }
        self.close_sink_after_eof();
        Ok(())
    }

    fn close_sink_after_eof(&mut self) {
        if self.source.is_none() && self.buffer.is_empty() {
            self.sink = None;
        }
    }

    fn output_drained(&self) -> bool {
        !self.is_output || (self.source.is_none() && self.buffer.is_empty())
    }

    fn close_input(&mut self) {
        if !self.is_output {
            self.source = None;
            self.buffer.consume(self.buffer.len());
            self.sink = None;
        }
    }
}

struct PumpSet {
    terminal: bool,
    streams: Vec<StreamPump>,
    resize_fd: Option<File>,
}

impl PumpSet {
    fn new(terminal: bool, streams: Vec<StreamPump>, resize_fd: Option<File>) -> Self {
        Self {
            terminal,
            streams,
            resize_fd,
        }
    }

    fn close_input(&mut self) {
        for stream in &mut self.streams {
            stream.close_input();
        }
    }

    fn outputs_drained(&self) -> bool {
        self.streams.iter().all(StreamPump::output_drained)
    }

    fn resize(&self, resize: &Resize) -> Result<(), InitError> {
        if !self.terminal {
            return Err(InitError::contract(
                "terminal-resize",
                "RESIZE is invalid for a nonterminal workload",
            ));
        }
        let file = self.resize_fd.as_ref().ok_or_else(|| {
            InitError::contract("terminal-resize", "terminal PTY descriptor is unavailable")
        })?;
        let size = Winsize {
            ws_row: resize.rows,
            ws_col: resize.columns,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        // SAFETY: `file` owns the live PTY master and `size` remains valid for
        // the duration of this write-only ioctl call.
        unsafe { set_window_size(file.as_raw_fd(), &size) }
            .map_err(|error| InitError::syscall("terminal-resize", error))?;
        Ok(())
    }
}

fn set_nonblocking(file: &File, stage: &'static str) -> Result<(), InitError> {
    let raw = fcntl(file, FcntlArg::F_GETFL).map_err(|error| InitError::syscall(stage, error))?;
    let flags = OFlag::from_bits_truncate(raw);
    fcntl(file, FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK))
        .map_err(|error| InitError::syscall(stage, error))?;
    Ok(())
}

#[derive(Debug, Clone, Copy)]
struct WorkloadStatus {
    code: Option<u8>,
    signal: Option<u16>,
}

struct SpawnedNamespace {
    staging_pid: Pid,
    teardown_pid_reader: File,
    events: File,
    pumps: PumpSet,
}

fn spawn_namespace(
    config: &GuestConfig,
    start: &Start,
    topology: IoTopology,
) -> Result<SpawnedNamespace, InitError> {
    let (event_reader, event_writer) =
        pipe2(OFlag::O_CLOEXEC).map_err(|error| InitError::syscall("namespace-spawn", error))?;
    let (teardown_pid_reader, teardown_pid_writer) =
        pipe2(OFlag::O_CLOEXEC).map_err(|error| InitError::syscall("namespace-spawn", error))?;
    let IoTopology { pumps, child } = topology;

    // SAFETY: pocket-init is deliberately single-threaded from process start;
    // no Rust or libc lock can be held by another thread across this fork. The
    // child performs bounded setup and ends only through execve or `_exit`.
    match unsafe { fork() }.map_err(|error| InitError::syscall("namespace-spawn", error))? {
        ForkResult::Parent { child: staging_pid } => {
            drop(event_writer);
            drop(teardown_pid_writer);
            drop(child);
            let events = File::from(event_reader);
            let teardown_pid_reader = File::from(teardown_pid_reader);
            set_nonblocking(&events, "namespace-events")?;
            set_nonblocking(&teardown_pid_reader, "namespace-spawn")?;
            Ok(SpawnedNamespace {
                staging_pid,
                teardown_pid_reader,
                events,
                pumps,
            })
        }
        ForkResult::Child => {
            drop(event_reader);
            drop(teardown_pid_reader);
            drop(pumps);
            let mut writer = File::from(event_writer);
            let result = namespace_supervisor(
                config,
                start,
                child,
                &mut writer,
                File::from(teardown_pid_writer),
            );
            if let Err(error) = result {
                let _ = write_internal_event(
                    &mut writer,
                    &InternalEvent::Error {
                        errno: error.errno(),
                        diagnostic: bounded_internal_diagnostic(&error.to_string()),
                    },
                );
                child_exit(125);
            }
            child_exit(0);
        }
    }
}

fn namespace_supervisor(
    config: &GuestConfig,
    start: &Start,
    child_io: ChildIo,
    event_writer: &mut File,
    teardown_pid_writer: File,
) -> Result<(), InitError> {
    unshare(
        CloneFlags::CLONE_NEWNS
            | CloneFlags::CLONE_NEWUTS
            | CloneFlags::CLONE_NEWIPC
            | CloneFlags::CLONE_NEWPID,
    )
    .map_err(|error| InitError::syscall("namespace-setup", error))?;
    mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_PRIVATE | MsFlags::MS_REC,
        None::<&str>,
    )
    .map_err(|error| InitError::syscall("namespace-setup", error))?;
    verify_private_root_mount()?;
    sethostname(&start.hostname).map_err(|error| InitError::syscall("namespace-setup", error))?;
    verify_effective_hostname(&start.hostname)?;

    let mounted = mount_workload_root(config, start)?;
    let (exec_reader, exec_writer) =
        pipe2(OFlag::O_CLOEXEC).map_err(|error| InitError::syscall("workload-fork", error))?;
    let (release_reader, release_writer) =
        pipe2(OFlag::O_CLOEXEC).map_err(|error| InitError::syscall("workload-fork", error))?;
    let (liveness_reader, liveness_writer) = pipe2(OFlag::O_CLOEXEC | OFlag::O_NONBLOCK)
        .map_err(|error| InitError::syscall("workload-fork", error))?;

    // SAFETY: this process is the single-threaded child of pocket-init and has
    // not created threads. The forked workload performs only setup then execve.
    let (workload_pid, supervisor_liveness_writer) =
        match unsafe { fork() }.map_err(|error| InitError::syscall("workload-fork", error))? {
            ForkResult::Parent { child } => {
                drop(exec_writer);
                drop(release_reader);
                drop(liveness_reader);
                drop(child_io);
                let liveness_writer = File::from(liveness_writer);
                publish_teardown_pid(teardown_pid_writer, child)?;
                release_workload(File::from(release_writer))?;
                (child, liveness_writer)
            }
            ForkResult::Child => {
                drop(exec_reader);
                drop(release_writer);
                drop(liveness_writer);
                drop(teardown_pid_writer);
                let mut exec_writer = File::from(exec_writer);
                let preserve_fd = exec_writer.as_raw_fd();
                let error = match await_workload_release(File::from(release_reader)) {
                    Ok(()) => match workload_exec(
                        config,
                        start,
                        child_io,
                        File::from(liveness_reader),
                        preserve_fd,
                        mounted.filesystem_guards,
                    ) {
                        Ok(never) => match never {},
                        Err(error) => error,
                    },
                    Err(error) => error,
                };
                let _ = write_internal_event(
                    &mut exec_writer,
                    &InternalEvent::Error {
                        errno: error.errno(),
                        diagnostic: bounded_internal_diagnostic(&error.to_string()),
                    },
                );
                child_exit(127);
            }
        };

    let exec_result = read_exec_result(File::from(exec_reader))?;
    if let Some(error) = exec_result {
        write_internal_event(event_writer, &error)?;
        let _ = wait_for_exact_child(workload_pid);
        drop(supervisor_liveness_writer);
        let _ = cleanup_workload_mounts(&mounted);
        return Ok(());
    }

    // Console shells are forked after the workload, so it stays PID 1 of the
    // nested namespace and its exit remains the run's result. They are
    // ordinary siblings: killing PID 1 tears the namespace down, which is what
    // the shutdown path already relies on.
    //
    // A console that will not start is reported and skipped. It is a
    // convenience on a line the operator asked for, not the run's purpose.
    let mut consoles = Vec::new();
    for index in 0..start.extra_consoles {
        match spawn_console_shell(config, start, index, &mounted) {
            Ok((console, None)) => consoles.push(console),
            Ok((console, Some(report))) => {
                write_internal_event(event_writer, &report)?;
                let _ = kill(console.pid, UnixSignal::SIGKILL);
                let _ = wait_for_exact_child(console.pid);
            }
            Err(error) => write_internal_event(
                event_writer,
                &InternalEvent::Error {
                    errno: error.errno(),
                    diagnostic: bounded_internal_diagnostic(&format!(
                        "console line {}: {error}",
                        u32::from(index) + RESERVED_SERIAL_LINES_U32
                    )),
                },
            )?,
        }
    }

    write_internal_event(
        event_writer,
        &InternalEvent::Ready {
            outer_pid: workload_pid.as_raw(),
        },
    )?;
    let status = wait_for_workload(workload_pid, !consoles.is_empty())?;
    // Ordinarily nothing is left: the wait above reaps each console as the
    // kernel kills it. This is the safety net for one that outlived that,
    // bounded so a console which will not die cannot hold the run open.
    reap_console_shells(consoles);
    drop(supervisor_liveness_writer);
    cleanup_workload_mounts(&mounted)?;
    write_internal_event(
        event_writer,
        &InternalEvent::Exit {
            code: status.code,
            signal: status.signal,
            namespace_clean: true,
        },
    )
}

/// Kill and reap every console shell, without being able to block forever.
///
/// The kernel has already killed them if PID 1 has exited, so this is
/// ordinarily one `waitpid` each. The signal and the deadline are for the case
/// where it has not: a console shell that refuses to die is a leaked process,
/// but a supervisor that waits for it forever is a run that never reports its
/// own result, which is worse.
fn reap_console_shells(consoles: Vec<ConsoleShell>) {
    const REAP_TIMEOUT: Duration = Duration::from_secs(5);
    for console in consoles {
        let _ = kill(console.pid, UnixSignal::SIGKILL);
        let deadline = Instant::now() + REAP_TIMEOUT;
        loop {
            let mut status = 0;
            // SAFETY: `status` is a live writable integer and the PID names an
            // exact child of this process. WNOHANG keeps this from blocking,
            // which is the whole point of reaping this way.
            let waited = unsafe { libc::waitpid(console.pid.as_raw(), &mut status, libc::WNOHANG) };
            if waited != 0 {
                // Reaped, or gone already; either way it is not ours any more.
                break;
            }
            if Instant::now() >= deadline {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

const WORKLOAD_RELEASE_BYTE: u8 = 0xa5;

fn publish_teardown_pid(mut writer: File, pid: Pid) -> Result<(), InitError> {
    let raw_pid = pid.as_raw();
    if raw_pid <= 0 {
        return Err(InitError::contract(
            "workload-fork",
            "fork returned a nonpositive workload PID",
        ));
    }
    writer
        .write_all(&raw_pid.to_ne_bytes())
        .map_err(|error| InitError::io("workload-fork", error))
}

fn release_workload(mut writer: File) -> Result<(), InitError> {
    writer
        .write_all(&[WORKLOAD_RELEASE_BYTE])
        .map_err(|error| InitError::io("workload-fork", error))
}

fn await_workload_release(mut reader: File) -> Result<(), InitError> {
    let mut bytes = Vec::new();
    Read::by_ref(&mut reader)
        .take(2)
        .read_to_end(&mut bytes)
        .map_err(|error| InitError::io("workload-fork", error))?;
    if bytes == [WORKLOAD_RELEASE_BYTE] {
        Ok(())
    } else {
        Err(InitError::contract(
            "workload-fork",
            "namespace supervisor did not publish the teardown PID before workload release",
        ))
    }
}

fn read_teardown_pid(mut reader: File) -> Result<Option<Pid>, InitError> {
    let mut bytes = [0_u8; 5];
    let count = loop {
        match reader.read(&mut bytes) {
            Ok(count) => break count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(None),
            Err(error) => return Err(InitError::io("namespace-teardown", error)),
        }
    };
    if count == 0 {
        return Ok(None);
    }
    let encoded: [u8; 4] = bytes[..count].try_into().map_err(|_| {
        InitError::contract(
            "namespace-teardown",
            "teardown PID channel did not contain exactly one PID",
        )
    })?;
    let raw_pid = libc::pid_t::from_ne_bytes(encoded);
    if raw_pid <= 0 {
        return Err(InitError::contract(
            "namespace-teardown",
            "teardown PID channel contained a nonpositive PID",
        ));
    }
    Ok(Some(Pid::from_raw(raw_pid)))
}

fn verify_effective_hostname(expected: &str) -> Result<(), InitError> {
    let text = fs::read_to_string("/proc/sys/kernel/hostname")
        .map_err(|error| InitError::io("namespace-setup", error))?;
    if !hostname_text_matches(&text, expected) {
        return Err(InitError::contract(
            "namespace-setup",
            format!(
                "effective hostname {:?} does not match START {expected:?}",
                text.trim_end()
            ),
        ));
    }
    Ok(())
}

fn hostname_text_matches(text: &str, expected: &str) -> bool {
    text.strip_suffix('\n').unwrap_or(text) == expected
}

fn child_exit(code: i32) -> ! {
    // SAFETY: `_exit` terminates only the current post-fork process without
    // running inherited Rust or libc cleanup handlers.
    unsafe { libc::_exit(code) }
}

fn verify_private_root_mount() -> Result<(), InitError> {
    let mountinfo =
        read_bounded_text("/proc/self/mountinfo", 1024 * 1024, "namespace-propagation")?;
    if root_mount_is_private(&mountinfo) {
        Ok(())
    } else {
        Err(InitError::contract(
            "namespace-propagation",
            "root mount remains shared or propagation state cannot be verified",
        ))
    }
}

fn root_mount_is_private(mountinfo: &str) -> bool {
    mountinfo.lines().any(|line| {
        let fields: Vec<&str> = line.split_ascii_whitespace().collect();
        if fields.get(4) != Some(&"/") {
            return false;
        }
        let Some(separator) = fields.iter().position(|field| *field == "-") else {
            return false;
        };
        fields.get(6..separator).is_some_and(|optional| {
            !optional.iter().any(|field| {
                field.starts_with("shared:")
                    || field.starts_with("master:")
                    || field.starts_with("propagate_from:")
            })
        })
    })
}

struct WorkloadMounts {
    targets: Vec<String>,
    filesystem_guards: WorkloadFilesystemGuards,
}

#[derive(Clone, Copy)]
struct WorkloadFilesystemGuards {
    root_mount_read_only: bool,
    root_mount_nodev: bool,
    root_mount_nosuid: bool,
    private_curated_dev: bool,
}

fn mount_workload_root(config: &GuestConfig, start: &Start) -> Result<WorkloadMounts, InitError> {
    let image_root = config.image_root();
    let newroot = config.newroot_mount.as_str();
    let mut targets = Vec::new();
    mount(
        Some(image_root.as_str()),
        newroot,
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_REC,
        None::<&str>,
    )
    .map_err(|error| InitError::syscall("namespace-mounts", error))?;
    targets.push(newroot.to_owned());

    // procfs is mounted by the post-CLONE_NEWPID child below. Unlike the
    // other namespaces, unshare(CLONE_NEWPID) affects only future children;
    // mounting procfs here would expose the supervisor's parent PID namespace.
    targets.push(format!("{newroot}/proc"));
    let specifications = [
        MountSpec::new(
            "sysfs",
            "sys",
            MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC | MsFlags::MS_RDONLY,
            None,
        ),
        // A private tmpfs plus an explicit device allow-list prevents even a
        // trusted UID-0 workload from reopening the root UBD behind a
        // read-only bind mount.
        MountSpec::new(
            "tmpfs",
            "dev",
            MsFlags::MS_NOSUID,
            Some("mode=0755,size=4m"),
        ),
        MountSpec::new(
            "devpts",
            "dev/pts",
            MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
            Some("newinstance,mode=0620,ptmxmode=0666"),
        ),
        MountSpec::new(
            "mqueue",
            "dev/mqueue",
            MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
            None,
        ),
        MountSpec::new(
            "tmpfs",
            "dev/shm",
            MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
            Some("mode=1777,size=64m"),
        ),
        // A container engine refuses to start without a cgroup hierarchy it can
        // write to. This is the guest's own kernel's cgroup tree, so it grants
        // nothing over the host's.
        MountSpec::new(
            "cgroup2",
            "sys/fs/cgroup",
            MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
            None,
        ),
        MountSpec::new(
            "tmpfs",
            "run",
            MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
            Some("mode=0755,size=16m"),
        ),
    ];
    for specification in specifications {
        let target = format!("{newroot}/{}", specification.relative_target);
        fs::create_dir_all(&target).map_err(|error| InitError::io("namespace-mounts", error))?;
        mount(
            Some(specification.filesystem),
            target.as_str(),
            Some(specification.filesystem),
            specification.flags,
            specification.data,
        )
        .map_err(|error| InitError::syscall("namespace-mounts", error))?;
        targets.push(target);
    }

    mount_host_volumes(newroot, start, &mut targets)?;

    create_curated_devices(newroot)?;
    // A run that asked for extra serial lines gets their device nodes here.
    // The lines exist because the launch configured them; this is only what
    // makes them reachable from inside the workload's own /dev, which is a
    // fresh tmpfs rather than the devtmpfs that named them at boot.
    for index in 0..u64::from(start.extra_consoles) {
        let line = RESERVED_SERIAL_LINES + index;
        let path = format!("{newroot}/dev/ttyS{line}");
        mknod(
            path.as_str(),
            SFlag::S_IFCHR,
            Mode::from_bits_truncate(0o600),
            makedev(SERIAL_MAJOR, SERIAL_MINOR_BASE + line),
        )
        .map_err(|error| InitError::syscall("namespace-devices", error))?;
        fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o600))
            .map_err(|error| InitError::io("namespace-devices", error))?;
    }

    // A terminal session's PTY was allocated before this namespace existed,
    // from the instance mounted at boot. Every devpts mount is an independent
    // instance -- `get_tree_nodev`, with `newinstance` long since a no-op --
    // so the fresh mount above renumbers the terminal: `/proc/self/fd/0` still
    // reads `/dev/pts/N`, but that path now names a different device. That is
    // what makes `ttyname` fail, and with it `tty`, `script`, `who` and some
    // `login` paths. Binding the original instance over it restores the
    // identity. The instance holds exactly this workload's own terminal, so it
    // exposes nothing the workload does not already hold on its stdin.
    if start.terminal {
        let pts = format!("{newroot}/dev/pts");
        mount(
            Some("/dev/pts"),
            pts.as_str(),
            None::<&str>,
            MsFlags::MS_BIND,
            None::<&str>,
        )
        .map_err(|error| InitError::syscall("namespace-mounts", error))?;
        targets.push(pts);
    }

    let ptmx = format!("{newroot}/dev/ptmx");
    match fs::remove_file(&ptmx) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(InitError::io("namespace-mounts", error)),
    }
    std::os::unix::fs::symlink("pts/ptmx", &ptmx)
        .map_err(|error| InitError::io("namespace-mounts", error))?;
    for (name, target) in [
        ("fd", "/proc/self/fd"),
        ("stdin", "/proc/self/fd/0"),
        ("stdout", "/proc/self/fd/1"),
        ("stderr", "/proc/self/fd/2"),
    ] {
        std::os::unix::fs::symlink(target, format!("{newroot}/dev/{name}"))
            .map_err(|error| InitError::io("namespace-mounts", error))?;
    }

    mount_generated_etc_files(newroot, start, &mut targets)?;

    let mut remount_flags = MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_NODEV;
    if start.root_read_only {
        remount_flags |= MsFlags::MS_RDONLY | MsFlags::MS_NOSUID;
    }
    mount(
        None::<&str>,
        newroot,
        None::<&str>,
        remount_flags,
        None::<&str>,
    )
    .map_err(|error| InitError::syscall("namespace-mounts", error))?;
    let flags = statvfs(newroot)
        .map_err(|error| InitError::syscall("namespace-mounts", error))?
        .flags();
    if !flags.contains(FsFlags::ST_NODEV) {
        return Err(InitError::contract(
            "namespace-mounts",
            "image-root bind mount did not become nodev",
        ));
    }
    if start.root_read_only
        && (!flags.contains(FsFlags::ST_RDONLY) || !flags.contains(FsFlags::ST_NOSUID))
    {
        return Err(InitError::contract(
            "namespace-mounts",
            "read-only image-root bind lacks readonly or nosuid",
        ));
    }
    Ok(WorkloadMounts {
        targets,
        filesystem_guards: WorkloadFilesystemGuards {
            root_mount_read_only: flags.contains(FsFlags::ST_RDONLY),
            root_mount_nodev: flags.contains(FsFlags::ST_NODEV),
            root_mount_nosuid: flags.contains(FsFlags::ST_NOSUID),
            private_curated_dev: true,
        },
    })
}

const MAX_GENERATED_TARGET_SYMLINKS: usize = 40;

fn mount_generated_etc_files(
    newroot: &str,
    start: &Start,
    targets: &mut Vec<String>,
) -> Result<(), InitError> {
    let generated_directory = format!("{newroot}/run/pocket/generated");
    fs::create_dir_all(&generated_directory)
        .map_err(|error| InitError::io("generated-files", error))?;
    fs::set_permissions(
        &generated_directory,
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .map_err(|error| InitError::io("generated-files", error))?;

    // A resolver only where there is something to resolve with. Under
    // network-none the file is deliberately empty rather than absent, so a
    // workload reading it sees "no nameservers" instead of a missing file.
    let generated = generated_etc_contents(start);
    let files = [
        ("hostname", "etc/hostname", generated[0].1.as_bytes()),
        ("hosts", "etc/hosts", generated[1].1.as_bytes()),
        ("resolv.conf", "etc/resolv.conf", generated[2].1.as_bytes()),
    ];

    for (source_name, target_name, contents) in files {
        let source = format!("{generated_directory}/{source_name}");
        let mut source_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&source)
            .map_err(|error| InitError::io("generated-files", error))?;
        source_file
            .write_all(contents)
            .map_err(|error| InitError::io("generated-files", error))?;
        source_file
            .sync_all()
            .map_err(|error| InitError::io("generated-files", error))?;

        // Resolve and materialize the target through the effective new-root
        // mount topology. In particular, /run is a private tmpfs at this
        // point; resolving against the underlying image would create a target
        // that the tmpfs immediately hides and leave the bind mount with
        // ENOENT.
        let target = prepare_generated_target_in_effective_root(Path::new(newroot), target_name)?;
        let target_text = target.to_str().ok_or_else(|| {
            InitError::contract("generated-files", "generated-file target is not UTF-8")
        })?;
        mount(
            Some(source.as_str()),
            target_text,
            None::<&str>,
            MsFlags::MS_BIND,
            None::<&str>,
        )
        .map_err(|error| InitError::syscall("generated-files", error))?;
        mount(
            None::<&str>,
            target_text,
            None::<&str>,
            MsFlags::MS_BIND
                | MsFlags::MS_REMOUNT
                | MsFlags::MS_RDONLY
                | MsFlags::MS_NOSUID
                | MsFlags::MS_NODEV
                | MsFlags::MS_NOEXEC,
            None::<&str>,
        )
        .map_err(|error| InitError::syscall("generated-files", error))?;
        let flags = statvfs(&target)
            .map_err(|error| InitError::syscall("generated-files", error))?
            .flags();
        if !flags.contains(FsFlags::ST_RDONLY)
            || !flags.contains(FsFlags::ST_NOSUID)
            || !flags.contains(FsFlags::ST_NODEV)
            || !flags.contains(FsFlags::ST_NOEXEC)
        {
            return Err(InitError::contract(
                "generated-files",
                "generated-file bind lacks readonly,nodev,nosuid,noexec flags",
            ));
        }
        targets.push(target_text.to_owned());
    }
    Ok(())
}

fn prepare_generated_target_in_effective_root(
    effective_root: &Path,
    relative: &str,
) -> Result<PathBuf, InitError> {
    let target = resolve_generated_target(effective_root, relative)?;
    prepare_generated_target(&target)?;
    Ok(target)
}

fn prepare_generated_target(path: &Path) -> Result<(), InitError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => Ok(()),
        Ok(_) => Err(InitError::contract(
            "generated-files",
            format!("generated-file target {path:?} is not a regular file"),
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o644)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
                .open(path)
                .map_err(|error| InitError::io("generated-files", error))?;
            if !file
                .metadata()
                .map_err(|error| InitError::io("generated-files", error))?
                .is_file()
            {
                return Err(InitError::contract(
                    "generated-files",
                    "new generated-file target is not regular",
                ));
            }
            Ok(())
        }
        Err(error) => Err(InitError::io("generated-files", error)),
    }
}

/// Resolve an image-controlled symlink chain with chroot semantics while
/// proving that every intermediate lookup remains beneath `image_root`.
fn resolve_generated_target(image_root: &Path, relative: &str) -> Result<PathBuf, InitError> {
    if Path::new(relative).is_absolute() {
        return Err(InitError::contract(
            "generated-files",
            "generated-file target must be image-root-relative",
        ));
    }
    let mut pending = components_without_root(Path::new(relative))?;
    let mut resolved = Vec::<OsString>::new();
    let mut followed = 0_usize;

    while let Some(component) = pending.pop_front() {
        let candidate = join_components(image_root, &resolved).join(&component);
        match fs::symlink_metadata(&candidate) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                followed += 1;
                if followed > MAX_GENERATED_TARGET_SYMLINKS {
                    return Err(InitError::contract(
                        "generated-files",
                        "generated-file target contains too many symlinks",
                    ));
                }
                let link = fs::read_link(&candidate)
                    .map_err(|error| InitError::io("generated-files", error))?;
                let mut target = if link.is_absolute() {
                    Vec::new()
                } else {
                    resolved.clone()
                };
                let mut link_components = components_with_parents(&link)?;
                while let Some(link_component) = link_components.pop_front() {
                    if link_component == ".." {
                        if target.pop().is_none() {
                            return Err(InitError::contract(
                                "generated-files",
                                "generated-file symlink escapes the image root",
                            ));
                        }
                    } else {
                        target.push(link_component);
                    }
                }
                // Restart resolution at the image root so symlinks anywhere
                // in the symlink target are inspected too. Preserve the
                // original suffix after the fully normalized target.
                target.extend(pending);
                pending = target.into();
                resolved.clear();
            }
            Ok(metadata) => {
                if !pending.is_empty() && !metadata.is_dir() {
                    return Err(InitError::contract(
                        "generated-files",
                        "non-directory occurs inside generated-file target",
                    ));
                }
                resolved.push(component);
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                if !pending.is_empty() {
                    fs::create_dir(&candidate)
                        .map_err(|error| InitError::io("generated-files", error))?;
                    fs::set_permissions(
                        &candidate,
                        std::os::unix::fs::PermissionsExt::from_mode(0o755),
                    )
                    .map_err(|error| InitError::io("generated-files", error))?;
                    let metadata = fs::symlink_metadata(&candidate)
                        .map_err(|error| InitError::io("generated-files", error))?;
                    if !metadata.is_dir() || metadata.file_type().is_symlink() {
                        return Err(InitError::contract(
                            "generated-files",
                            "created generated-file parent is not a real directory",
                        ));
                    }
                }
                resolved.push(component);
            }
            Err(error) => return Err(InitError::io("generated-files", error)),
        }
    }
    Ok(join_components(image_root, &resolved))
}

fn components_without_root(path: &Path) -> Result<VecDeque<OsString>, InitError> {
    let components = components_with_parents(path)?;
    if components.iter().any(|component| component == "..") {
        return Err(InitError::contract(
            "generated-files",
            "generated-file target is not normalized",
        ));
    }
    if components.is_empty() {
        return Err(InitError::contract(
            "generated-files",
            "generated-file target is empty",
        ));
    }
    Ok(components)
}

fn components_with_parents(path: &Path) -> Result<VecDeque<OsString>, InitError> {
    let mut components = VecDeque::new();
    for component in path.components() {
        match component {
            std::path::Component::RootDir => {}
            std::path::Component::Normal(value) => components.push_back(value.to_os_string()),
            std::path::Component::ParentDir => components.push_back(OsString::from("..")),
            std::path::Component::CurDir => {}
            std::path::Component::Prefix(_) => {
                return Err(InitError::contract(
                    "generated-files",
                    "generated-file symlink has an unsupported path prefix",
                ));
            }
        }
    }
    Ok(components)
}

fn join_components(root: &Path, components: &[OsString]) -> PathBuf {
    let mut joined = root.to_path_buf();
    for component in components {
        joined.push(component);
    }
    joined
}

/// UML serial lines are `TTY_MAJOR` with minors from 64, and the runtime uses
/// the first four for control, input, output and diagnostics.
const SERIAL_MAJOR: u64 = 4;
const SERIAL_MINOR_BASE: u64 = 64;
const RESERVED_SERIAL_LINES: u64 = 4;
const RESERVED_SERIAL_LINES_U32: u32 = 4;

fn create_curated_devices(newroot: &str) -> Result<(), InitError> {
    let devices = [
        ("null", 1, 3, 0o666),
        ("zero", 1, 5, 0o666),
        ("full", 1, 7, 0o666),
        ("random", 1, 8, 0o666),
        ("urandom", 1, 9, 0o666),
        ("tty", 5, 0, 0o666),
        ("console", 5, 1, 0o600),
    ];
    for (name, major, minor, mode) in devices {
        let path = format!("{newroot}/dev/{name}");
        mknod(
            path.as_str(),
            SFlag::S_IFCHR,
            Mode::from_bits_truncate(mode),
            makedev(major, minor),
        )
        .map_err(|error| InitError::syscall("namespace-devices", error))?;
        // mknod() subtracts the process umask, which the workload's own umask
        // supplies, so the mode above is a request rather than a result. A
        // default 022 umask would leave /dev/null at 0644 and every non-root
        // workload would fail to write to it. Set the exact mode explicitly.
        fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(mode))
            .map_err(|error| InitError::io("namespace-devices", error))?;
    }
    Ok(())
}

struct MountSpec {
    filesystem: &'static str,
    relative_target: &'static str,
    flags: MsFlags,
    data: Option<&'static str>,
}

impl MountSpec {
    const fn new(
        filesystem: &'static str,
        relative_target: &'static str,
        flags: MsFlags,
        data: Option<&'static str>,
    ) -> Self {
        Self {
            filesystem,
            relative_target,
            flags,
            data,
        }
    }
}

/// Unmount whatever the workload mounted for itself, deepest first.
///
/// The runtime unmounts what it created, in reverse order. That is not enough
/// once a workload mounts anything of its own: a container engine inside the
/// guest leaves overlay and cgroup mounts under the image root, and the root's
/// own unmount then fails with EBUSY -- which the host reports as an unclean
/// filesystem, because it cannot tell that failure apart from a real one.
///
/// The mount table is the only source that knows about mounts nobody here
/// created. Deepest-first ordering is what makes this terminate: a mount can
/// only be busy because of something below it, and there is nothing below the
/// deepest one.
fn unmount_foreign_mounts_beneath(root: &str) -> Result<(), InitError> {
    let table = read_bounded_text("/proc/self/mountinfo", 1024 * 1024, "namespace-unmount")?;
    let prefix = format!("{root}/");
    let mut found: Vec<&str> = table
        .lines()
        .filter_map(|line| line.split(' ').nth(4))
        .filter(|point| point.starts_with(&prefix))
        .collect();
    // Longest first, so a parent is never attempted before its children.
    found.sort_unstable_by_key(|point| std::cmp::Reverse(point.len()));
    for point in found {
        match umount2(point, MntFlags::MNT_DETACH) {
            Ok(()) | Err(Errno::EINVAL | Errno::ENOENT) => {}
            Err(error) => {
                return Err(InitError::child(
                    "namespace-unmount",
                    Some(error as i32),
                    format!("could not unmount {point}: {error}"),
                ));
            }
        }
    }
    Ok(())
}

fn cleanup_workload_mounts(mounts: &WorkloadMounts) -> Result<(), InitError> {
    let mut first_error = None;
    // Anything the workload mounted must go before the mounts it was given,
    // or the image root cannot be released.
    if let Some(root) = mounts.targets.first()
        && let Err(error) = unmount_foreign_mounts_beneath(root)
    {
        first_error = Some(error);
    }
    for target in mounts.targets.iter().rev() {
        match umount2(target.as_str(), MntFlags::empty()) {
            Ok(()) | Err(Errno::EINVAL | Errno::ENOENT) => {}
            Err(error) if first_error.is_none() => {
                first_error = Some(InitError::child(
                    "namespace-unmount",
                    Some(error as i32),
                    format!("could not unmount {target}: {error}"),
                ));
            }
            Err(_) => {}
        }
    }
    match first_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

/// Enter the workload's root with the workload's credentials.
///
/// Everything a process needs to become the workload, short of the exec
/// itself: its stdio, its root, its limits, its capabilities and its identity,
/// in that order. Console shells go through exactly this, because a second
/// implementation of a security transition is a second one to get wrong.
fn enter_workload_context(
    config: &GuestConfig,
    start: &Start,
    child_io: ChildIo,
    preserve_fd: Option<i32>,
    // Held by the workload so it can re-check its supervisor across the
    // credential transition. A console shell passes `None`: it is not the
    // process whose death ends the run.
    supervisor_liveness: Option<File>,
    filesystem_guards: WorkloadFilesystemGuards,
) -> Result<(), InitError> {
    child_io.install()?;
    // Move the cwd under the future root before changing root. This avoids the
    // classic chroot escape precondition where cwd remains outside the jail.
    chdir(config.newroot_mount.as_str())
        .map_err(|error| InitError::syscall("workload-chroot", error))?;
    chroot(".").map_err(|error| InitError::syscall("workload-chroot", error))?;
    chdir("/").map_err(|error| InitError::syscall("workload-chroot", error))?;
    verify_chroot_transition()?;
    verify_generated_etc_files(start)?;
    let _previous = umask(Mode::from_bits_truncate(u32::from(start.umask)));
    apply_rlimits(start)?;
    let capabilities = apply_capability_policy(start.root_read_only, start.privileged)?;
    let groups: Vec<Gid> = start
        .supplementary_gids
        .iter()
        .copied()
        .map(Gid::from_raw)
        .collect();
    setgroups(&groups).map_err(|error| InitError::syscall("workload-identity", error))?;
    setgid(Gid::from_raw(start.gid))
        .map_err(|error| InitError::syscall("workload-identity", error))?;
    setuid(Uid::from_raw(start.uid))
        .map_err(|error| InitError::syscall("workload-identity", error))?;
    if start.uid != 0 {
        clear_all_capabilities()?;
    }
    chdir(start.cwd.as_str()).map_err(|error| InitError::syscall("workload-chdir", error))?;

    // Credential and capability transitions can clear PDEATHSIG. Re-arm it
    // after every such transition and close the parent-death race again.
    prctl::set_pdeathsig(UnixSignal::SIGKILL)
        .map_err(|error| InitError::syscall("workload-setup", error))?;
    if let Some(liveness) = supervisor_liveness {
        verify_namespace_supervisor_liveness(&liveness, "after workload identity setup")?;
        drop(liveness);
    }
    let closed_fds = close_unintended_fds(preserve_fd)?;
    if start.root_read_only
        && start.uid == 0
        && !uid_zero_read_only_guards_hold(RootReadOnlyGuards {
            capability_sets: capabilities.sets,
            no_new_privs: capabilities.no_new_privs,
            root_mount_read_only: filesystem_guards.root_mount_read_only,
            root_mount_nodev: filesystem_guards.root_mount_nodev,
            root_mount_nosuid: filesystem_guards.root_mount_nosuid,
            private_curated_dev: filesystem_guards.private_curated_dev,
            bounding_set_restricted: true,
            outside_root_directory_fds: closed_fds.outside_root_directory_fds,
        })
    {
        return Err(InitError::contract(
            "workload-security",
            "UID-0 read-only root guards are incomplete",
        ));
    }
    prepare_exec_signal_state()?;
    Ok(())
}

/// Candidate shells for a console line, most preferred first. An image need
/// not have any: a `scratch` image has none, and its lines are still usable
/// serial devices for whatever the workload puts on them.
const CONSOLE_SHELLS: [&str; 3] = ["/bin/sh", "/bin/bash", "/bin/ash"];

/// One console shell the supervisor is responsible for reaping.
struct ConsoleShell {
    pid: Pid,
}

/// Put an interactive shell on one extra serial line.
///
/// Reports its own setup failures the way the workload does: the child holds
/// the write end of a close-on-exec pipe, so a successful exec closes it and
/// the parent reads end of file, while any failure arrives as a record. A
/// console that cannot start is a diagnostic, never the run's failure.
fn spawn_console_shell(
    config: &GuestConfig,
    start: &Start,
    index: u8,
    mounted: &WorkloadMounts,
) -> Result<(ConsoleShell, Option<InternalEvent>), InitError> {
    let line = u32::from(index) + RESERVED_SERIAL_LINES_U32;
    let device = format!("/dev/ttyS{line}");
    let terminal = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(OFlag::O_NOCTTY.bits())
        .open(&device)
        .map_err(|error| InitError::io("console-shell", error))?;
    let (result_reader, result_writer) =
        pipe2(OFlag::O_CLOEXEC).map_err(|error| InitError::syscall("console-shell", error))?;

    // SAFETY: this process is single-threaded, as for the workload fork. The
    // child performs bounded setup and ends only through execve or `_exit`.
    match unsafe { fork() }.map_err(|error| InitError::syscall("console-shell", error))? {
        ForkResult::Parent { child } => {
            drop(result_writer);
            drop(terminal);
            let report = read_exec_result(File::from(result_reader))?;
            let _ = line;
            Ok((ConsoleShell { pid: child }, report))
        }
        ForkResult::Child => {
            drop(result_reader);
            let mut writer = File::from(result_writer);
            let preserve = writer.as_raw_fd();
            let error = match console_shell_exec(config, start, terminal, preserve, mounted) {
                Ok(never) => match never {},
                Err(error) => error,
            };
            let _ = write_internal_event(
                &mut writer,
                &InternalEvent::Error {
                    errno: error.errno(),
                    diagnostic: bounded_internal_diagnostic(&error.to_string()),
                },
            );
            child_exit(127);
        }
    }
}

fn console_shell_exec(
    config: &GuestConfig,
    start: &Start,
    terminal: File,
    preserve_fd: i32,
    mounted: &WorkloadMounts,
) -> Result<Infallible, InitError> {
    prctl::set_pdeathsig(UnixSignal::SIGKILL)
        .map_err(|error| InitError::syscall("console-shell", error))?;
    // `ChildIo::Terminal` is exactly what an interactive session needs and
    // already does it: a new session, this line as its controlling terminal,
    // and the three standard descriptors pointing at it.
    let child_io = ChildIo::Terminal {
        slave: OwnedFd::from(terminal),
    };
    enter_workload_context(
        config,
        start,
        child_io,
        Some(preserve_fd),
        None,
        mounted.filesystem_guards,
    )?;
    let environment = console_environment(start)?;
    let mut last = None;
    for shell in CONSOLE_SHELLS {
        let program = CString::new(shell)
            .map_err(|_| InitError::contract("console-shell", "shell path holds a NUL"))?;
        // A leading `-` marks a login shell, which is what a serial console is.
        let name = shell.rsplit('/').next().unwrap_or("sh");
        let argv0 = CString::new(format!("-{name}"))
            .map_err(|_| InitError::contract("console-shell", "shell name holds a NUL"))?;
        last = Some(execve(&program, &[argv0], &environment));
    }
    Err(InitError::contract(
        "console-shell",
        match last {
            Some(Err(errno)) => format!("no shell in the image could be started: {errno}"),
            _ => "no shell in the image could be started".to_owned(),
        },
    ))
}

/// The workload's environment, plus a terminal type if it carries none.
fn console_environment(start: &Start) -> Result<Vec<CString>, InitError> {
    let mut environment = Vec::with_capacity(start.env.len() + 1);
    let mut has_term = false;
    for entry in &start.env {
        has_term |= entry.starts_with("TERM=");
        environment.push(
            CString::new(entry.as_str())
                .map_err(|_| InitError::contract("console-shell", "env entry holds a NUL"))?,
        );
    }
    if !has_term {
        // A serial line reports no terminal type of its own, and a shell with
        // none behaves as though it were on a dumb terminal.
        environment.push(
            CString::new("TERM=vt100")
                .map_err(|_| InitError::contract("console-shell", "TERM holds a NUL"))?,
        );
    }
    Ok(environment)
}

fn workload_exec(
    config: &GuestConfig,
    start: &Start,
    child_io: ChildIo,
    supervisor_liveness: File,
    preserve_fd: i32,
    filesystem_guards: WorkloadFilesystemGuards,
) -> Result<Infallible, InitError> {
    prctl::set_pdeathsig(UnixSignal::SIGKILL)
        .map_err(|error| InitError::syscall("workload-setup", error))?;
    verify_namespace_supervisor_liveness(&supervisor_liveness, "during workload fork")?;
    // Restrict what any later exec can acquire before the remaining privileged
    // setup. Bounding-set removal does not revoke the current setup process's
    // permitted/effective CAP_SYS_ADMIN or CAP_SYS_CHROOT; those are removed
    // by the final capset immediately after the root transition.
    prepare_capability_bounding_set(start.privileged)?;
    let proc_target = format!("{}/proc", config.newroot_mount);
    mount(
        Some("proc"),
        proc_target.as_str(),
        Some("proc"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
        None::<&str>,
    )
    .map_err(|error| InitError::syscall("workload-proc", error))?;
    enter_workload_context(
        config,
        start,
        child_io,
        Some(preserve_fd),
        Some(supervisor_liveness),
        filesystem_guards,
    )?;

    exec_exact(start)
}

fn verify_namespace_supervisor_liveness(
    reader: &File,
    checkpoint: &'static str,
) -> Result<(), InitError> {
    let mut byte = [0_u8; 1];
    match Read::read(&mut &*reader, &mut byte) {
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(()),
        Ok(0) => Err(InitError::contract(
            "workload-setup",
            format!("namespace supervisor liveness channel closed {checkpoint}"),
        )),
        Ok(_) => Err(InitError::contract(
            "workload-setup",
            "namespace supervisor liveness channel contained unexpected data",
        )),
        Err(error) => Err(InitError::io("workload-setup", error)),
    }
}

fn prepare_exec_signal_state() -> Result<(), InitError> {
    let action = SigAction::new(SigHandler::SigDfl, SaFlags::empty(), SigSet::empty());
    // SAFETY: the action contains no userspace handler pointer and installs
    // the kernel's default SIGPIPE disposition in this single-threaded child.
    unsafe { sigaction(UnixSignal::SIGPIPE, &action) }
        .map_err(|error| InitError::syscall("workload-signals", error))?;
    pthread_sigmask(SigmaskHow::SIG_SETMASK, Some(&SigSet::empty()), None)
        .map_err(|error| InitError::syscall("workload-signals", error))
}

fn verify_chroot_transition() -> Result<(), InitError> {
    for link in ["/proc/self/root", "/proc/self/cwd"] {
        let target =
            fs::read_link(link).map_err(|error| InitError::io("workload-chroot", error))?;
        if target != Path::new("/") {
            return Err(InitError::contract(
                "workload-chroot",
                format!("{link} resolves to {target:?} instead of the new root"),
            ));
        }
    }
    Ok(())
}

/// The exact bytes of the three files the runtime generates.
///
/// Shared by the code that writes them and the code that confirms they reached
/// the workload's root. That check is about the mounts arriving, not about
/// re-deriving the content independently, so a second copy of these rules
/// would only be somewhere for the two to drift apart -- which is what
/// happened when the resolver stopped always being empty.
fn generated_etc_contents(start: &Start) -> [(&'static str, String); 3] {
    let resolv = if start.network_mode == 1 {
        let [a, b, c, d] = pocket_protocol::SLIRP_DNS_ADDRESS;
        format!("nameserver {a}.{b}.{c}.{d}\n")
    } else {
        String::new()
    };
    [
        ("hostname", format!("{}\n", start.hostname)),
        (
            "hosts",
            format!("127.0.0.1 localhost\n127.0.1.1 {}\n", start.hostname),
        ),
        ("resolv.conf", resolv),
    ]
}

fn verify_generated_etc_files(start: &Start) -> Result<(), InitError> {
    for (name, expected) in &generated_etc_contents(start) {
        let path = format!("/etc/{name}");
        let observed = read_bounded_text(&path, 4096, "generated-files")?;
        if observed != *expected {
            return Err(InitError::contract(
                "generated-files",
                format!("generated {path} content does not match START"),
            ));
        }
    }
    Ok(())
}

#[repr(C)]
struct LinuxCapabilityHeader {
    version: u32,
    pid: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct LinuxCapabilityData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

struct AppliedCapabilityPolicy {
    sets: CapabilitySets,
    no_new_privs: bool,
}

fn apply_capability_policy(
    root_read_only: bool,
    privileged: bool,
) -> Result<AppliedCapabilityPolicy, InitError> {
    const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
    let header = LinuxCapabilityHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut data = get_capability_data()?;
    let exact = if privileged {
        full_root_capability_sets(last_kernel_capability()?)
    } else {
        fixed_root_capability_sets()
    };
    for (index, word) in data.iter_mut().enumerate() {
        *word = LinuxCapabilityData {
            effective: exact.effective[index],
            permitted: exact.permitted[index],
            inheritable: exact.inheritable[index],
        };
    }
    // The bounding set and inheritable/ambient setup state were restricted
    // before mount/chroot setup. Install exact E/P allowlist and empty I now.
    // No untrusted code runs between those two operations.
    // SAFETY: capset reads the same valid header and two initialized v3 words.
    let result = unsafe {
        libc::syscall(
            libc::SYS_capset,
            &header as *const LinuxCapabilityHeader,
            data.as_ptr(),
        )
    };
    if result != 0 {
        return Err(InitError::io(
            "workload-capabilities",
            io::Error::last_os_error(),
        ));
    }
    let applied = get_capability_data()?;
    let applied_sets = CapabilitySets {
        effective: [applied[0].effective, applied[1].effective],
        permitted: [applied[0].permitted, applied[1].permitted],
        inheritable: [applied[0].inheritable, applied[1].inheritable],
    };
    if applied_sets != exact {
        return Err(InitError::contract(
            "workload-capabilities",
            "final root capability sets do not exactly match policy",
        ));
    }
    clear_ambient_capabilities()?;
    // Writable-root mode intentionally leaves set-ID and profile-allowed file
    // capabilities functional. Non-root identities receive empty E/P/I sets
    // below, without KEEPCAPS; exec can therefore acquire only capabilities
    // still admitted by this already-reduced bounding set. Read-only mode uses
    // NNP to prevent either metadata mechanism from reopening a write path.
    let no_new_privs = root_read_only;
    if no_new_privs {
        prctl::set_no_new_privs()
            .map_err(|error| InitError::syscall("workload-capabilities", error))?;
        if !prctl::get_no_new_privs()
            .map_err(|error| InitError::syscall("workload-capabilities", error))?
        {
            return Err(InitError::contract(
                "workload-capabilities",
                "no_new_privs did not remain enabled for read-only root",
            ));
        }
    }
    Ok(AppliedCapabilityPolicy {
        sets: applied_sets,
        no_new_privs,
    })
}

fn prepare_capability_bounding_set(privileged: bool) -> Result<(), InitError> {
    if privileged {
        // Nothing is dropped: a container engine needs the bounding set intact
        // to grant capabilities to what it starts.
        return Ok(());
    }
    for capability in 0..=last_kernel_capability()? {
        if capability_is_allowed(capability) {
            continue;
        }
        // SAFETY: PR_CAPBSET_DROP consumes an integer capability number and no
        // pointer arguments. The constants are covered by unit-tested policy.
        let result =
            unsafe { libc::prctl(libc::PR_CAPBSET_DROP, capability as libc::c_ulong, 0, 0, 0) };
        if result != 0 {
            return Err(InitError::io(
                "workload-capabilities",
                io::Error::last_os_error(),
            ));
        }
        // SAFETY: PR_CAPBSET_READ has the same scalar-only argument contract.
        let present =
            unsafe { libc::prctl(libc::PR_CAPBSET_READ, capability as libc::c_ulong, 0, 0, 0) };
        if present < 0 {
            return Err(InitError::io(
                "workload-capabilities",
                io::Error::last_os_error(),
            ));
        }
        if present == 1 {
            return Err(InitError::contract(
                "workload-capabilities",
                format!("capability {capability} remains in the bounding set"),
            ));
        }
    }
    clear_ambient_capabilities()?;

    // Clear inheritable state before the root transition while retaining the
    // current setup-only permitted/effective authority. Bounding-set removal
    // ensures no excluded capability can be reacquired by exec in any case.
    const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
    let header = LinuxCapabilityHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut data = get_capability_data()?;
    for word in &mut data {
        word.inheritable = 0;
    }
    // SAFETY: capset reads the valid header and two initialized v3 words.
    let result = unsafe {
        libc::syscall(
            libc::SYS_capset,
            &header as *const LinuxCapabilityHeader,
            data.as_ptr(),
        )
    };
    if result != 0 {
        return Err(InitError::io(
            "workload-capabilities",
            io::Error::last_os_error(),
        ));
    }
    let applied = get_capability_data()?;
    if applied.iter().any(|word| word.inheritable != 0) {
        return Err(InitError::contract(
            "workload-capabilities",
            "inheritable capabilities remained during privileged setup",
        ));
    }
    Ok(())
}

fn clear_ambient_capabilities() -> Result<(), InitError> {
    // SAFETY: PR_CAP_AMBIENT/CLEAR_ALL takes no pointer and deterministically
    // clears the complete ambient set.
    let result = unsafe {
        libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL,
            0,
            0,
            0,
        )
    };
    if result != 0 {
        return Err(InitError::io(
            "workload-capabilities",
            io::Error::last_os_error(),
        ));
    }
    Ok(())
}

fn last_kernel_capability() -> Result<u32, InitError> {
    let text = read_bounded_text("/proc/sys/kernel/cap_last_cap", 32, "workload-capabilities")?;
    let capability = text.trim().parse::<u32>().map_err(|_| {
        InitError::contract(
            "workload-capabilities",
            "kernel cap_last_cap is not an unsigned integer",
        )
    })?;
    if capability >= 64 {
        return Err(InitError::unsupported(
            "workload-capabilities",
            "kernel capability ABI exceeds the two-word Linux v3 capset",
        ));
    }
    Ok(capability)
}

fn clear_all_capabilities() -> Result<(), InitError> {
    const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
    let header = LinuxCapabilityHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let data = [LinuxCapabilityData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    // SAFETY: capset reads the valid v3 header and two initialized zero words;
    // dropping one's own remaining capability sets is permitted after setuid.
    let result = unsafe {
        libc::syscall(
            libc::SYS_capset,
            &header as *const LinuxCapabilityHeader,
            data.as_ptr(),
        )
    };
    if result != 0 {
        return Err(InitError::io(
            "workload-capabilities",
            io::Error::last_os_error(),
        ));
    }
    let applied = get_capability_data()?;
    if applied
        .iter()
        .any(|word| word.effective != 0 || word.permitted != 0 || word.inheritable != 0)
    {
        return Err(InitError::contract(
            "workload-capabilities",
            "non-root identity retained a capability set",
        ));
    }
    Ok(())
}

fn get_capability_data() -> Result<[LinuxCapabilityData; 2], InitError> {
    const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
    let mut header = LinuxCapabilityHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut data = [LinuxCapabilityData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    // SAFETY: capget receives a correctly versioned header and writable array
    // of the two v3 data words required by the Linux UAPI.
    let result = unsafe {
        libc::syscall(
            libc::SYS_capget,
            &mut header as *mut LinuxCapabilityHeader,
            data.as_mut_ptr(),
        )
    };
    if result != 0 {
        return Err(InitError::io(
            "workload-capabilities",
            io::Error::last_os_error(),
        ));
    }
    Ok(data)
}

fn apply_rlimits(start: &Start) -> Result<(), InitError> {
    for limit in &start.rlimits {
        let resource = linux_resource(limit.resource).ok_or_else(|| {
            InitError::unsupported(
                "workload-rlimits",
                format!("Linux rlimit resource {} is unsupported", limit.resource),
            )
        })?;
        setrlimit(resource, limit.soft, limit.hard)
            .map_err(|error| InitError::syscall("workload-rlimits", error))?;
    }
    Ok(())
}

const fn linux_resource(number: u8) -> Option<Resource> {
    match number {
        0 => Some(Resource::RLIMIT_CPU),
        1 => Some(Resource::RLIMIT_FSIZE),
        2 => Some(Resource::RLIMIT_DATA),
        3 => Some(Resource::RLIMIT_STACK),
        4 => Some(Resource::RLIMIT_CORE),
        5 => Some(Resource::RLIMIT_RSS),
        6 => Some(Resource::RLIMIT_NPROC),
        7 => Some(Resource::RLIMIT_NOFILE),
        8 => Some(Resource::RLIMIT_MEMLOCK),
        9 => Some(Resource::RLIMIT_AS),
        10 => Some(Resource::RLIMIT_LOCKS),
        11 => Some(Resource::RLIMIT_SIGPENDING),
        12 => Some(Resource::RLIMIT_MSGQUEUE),
        13 => Some(Resource::RLIMIT_NICE),
        14 => Some(Resource::RLIMIT_RTPRIO),
        15 => Some(Resource::RLIMIT_RTTIME),
        _ => None,
    }
}

struct ClosedFdEvidence {
    outside_root_directory_fds: usize,
}

fn close_unintended_fds(preserve: Option<i32>) -> Result<ClosedFdEvidence, InitError> {
    let preserve = preserve.ok_or_else(|| {
        InitError::contract("close-fds", "exec failure pipe descriptor is missing")
    })?;
    if preserve <= 2 {
        return Err(InitError::contract(
            "close-fds",
            "exec failure pipe overlaps standard I/O",
        ));
    }
    for descriptor in [0, 1, 2, preserve] {
        let kind = fs::metadata(format!("/proc/self/fd/{descriptor}"))
            .map_err(|error| InitError::io("close-fds", error))?
            .file_type();
        if kind.is_dir() {
            return Err(InitError::contract(
                "close-fds",
                "a preserved descriptor references an outside-root directory",
            ));
        }
        if descriptor == preserve && !kind.is_fifo() {
            return Err(InitError::contract(
                "close-fds",
                "exec failure descriptor is not a pipe",
            ));
        }
    }
    if preserve > 3 {
        close_range(3, (preserve - 1) as u32)?;
    }
    if preserve < i32::MAX {
        close_range((preserve + 1) as u32, u32::MAX)?;
    }
    Ok(ClosedFdEvidence {
        outside_root_directory_fds: 0,
    })
}

fn close_range(first: u32, last: u32) -> Result<(), InitError> {
    // SAFETY: close_range consumes only scalar bounds. The caller preserves
    // stdio and the one verified FIFO by splitting the range around it.
    let result = unsafe { libc::syscall(libc::SYS_close_range, first, last, 0_u32) };
    if result != 0 {
        return Err(InitError::io("close-fds", io::Error::last_os_error()));
    }
    Ok(())
}

fn exec_exact(start: &Start) -> Result<Infallible, InitError> {
    let arguments = cstrings(&start.argv, "argv")?;
    let environment = cstrings(&start.env, "env")?;
    let argv0 = start
        .argv
        .first()
        .ok_or_else(|| InitError::contract("workload-exec", "validated START has empty argv"))?;

    if argv0.contains('/') {
        let executable = CString::new(argv0.as_bytes()).map_err(|_| {
            InitError::contract("workload-exec", "executable contains an embedded NUL")
        })?;
        return execve(&executable, &arguments, &environment)
            .map_err(|error| InitError::syscall("workload-exec", error));
    }

    let path = environment_value(&start.env, "PATH")
        .unwrap_or("/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");
    let mut permission_error = None;
    for directory in path.split(':') {
        let candidate = if directory.is_empty() {
            argv0.clone()
        } else {
            format!("{directory}/{argv0}")
        };
        let executable = CString::new(candidate.as_bytes()).map_err(|_| {
            InitError::contract("workload-exec", "PATH candidate contains an embedded NUL")
        })?;
        match execve(&executable, &arguments, &environment) {
            Err(Errno::ENOENT | Errno::ENOTDIR) => {}
            Err(Errno::EACCES) => permission_error = Some(Errno::EACCES),
            Err(error) => return Err(InitError::syscall("workload-exec", error)),
            Ok(never) => match never {},
        }
    }
    Err(InitError::syscall(
        "workload-exec",
        permission_error.unwrap_or(Errno::ENOENT),
    ))
}

fn cstrings(values: &[String], field: &'static str) -> Result<Vec<CString>, InitError> {
    values
        .iter()
        .map(|value| {
            CString::new(value.as_bytes()).map_err(|_| {
                InitError::contract("workload-exec", format!("{field} contains an embedded NUL"))
            })
        })
        .collect()
}

fn environment_value<'a>(environment: &'a [String], key: &str) -> Option<&'a str> {
    environment
        .iter()
        .rev()
        .find_map(|entry| entry.strip_prefix(key)?.strip_prefix('='))
}

fn read_exec_result(mut reader: File) -> Result<Option<InternalEvent>, InitError> {
    let mut bytes = Vec::new();
    Read::by_ref(&mut reader)
        .take(4097)
        .read_to_end(&mut bytes)
        .map_err(|error| InitError::io("workload-exec", error))?;
    if bytes.is_empty() {
        return Ok(None);
    }
    if bytes.len() > 4096 {
        return Err(InitError::contract(
            "workload-exec",
            "exec failure record exceeds hard cap",
        ));
    }
    let mut decoder = InternalEventDecoder::new();
    let events = decoder.feed(&bytes)?;
    if decoder.has_pending() || events.len() != 1 {
        return Err(InitError::contract(
            "workload-exec",
            "exec failure pipe did not contain exactly one event",
        ));
    }
    match events.into_iter().next() {
        Some(event @ InternalEvent::Error { .. }) => Ok(Some(event)),
        _ => Err(InitError::contract(
            "workload-exec",
            "exec failure pipe contained the wrong event kind",
        )),
    }
}

/// Wait for the workload, reaping console shells as they die.
///
/// PID 1 of a PID namespace cannot finish exiting until every other process in
/// that namespace has been reaped: the kernel kills them and then waits. The
/// console shells are children of this supervisor, so this supervisor is the
/// only process that can reap them -- and if it waits for the workload alone,
/// the workload waits for the shells and the supervisor waits for the
/// workload. Waiting for any child instead breaks that: each shell is reaped
/// as it dies, which is exactly what lets PID 1 complete its own exit.
///
/// With no console shells there is nothing else to reap, and waiting for the
/// exact PID keeps an unexpected child from being mistaken for the workload.
fn wait_for_workload(workload: Pid, has_consoles: bool) -> Result<WorkloadStatus, InitError> {
    if !has_consoles {
        return wait_for_exact_child(workload);
    }
    loop {
        let mut status = 0;
        // SAFETY: `status` is a live writable integer, and -1 asks for any
        // child of this process, which is what the deadlock above requires.
        let waited = unsafe { libc::waitpid(-1, &mut status, 0) };
        if waited < 0 {
            let error = Errno::last();
            if error == Errno::EINTR {
                continue;
            }
            return Err(InitError::syscall("workload-wait", error));
        }
        if waited != workload.as_raw() {
            // A console shell. Reaping it is the point; it reports nothing.
            continue;
        }
        match decode_raw_wait_status(status, "workload-wait")? {
            RawChildStatus::Exited(code) => {
                return Ok(WorkloadStatus {
                    code: Some(code),
                    signal: None,
                });
            }
            RawChildStatus::Signaled(signal) => {
                return Ok(WorkloadStatus {
                    code: None,
                    signal: Some(signal),
                });
            }
            RawChildStatus::Stopped | RawChildStatus::Continued => {}
        }
    }
}

fn wait_for_exact_child(pid: Pid) -> Result<WorkloadStatus, InitError> {
    loop {
        match wait_for_raw_child(pid, "workload-wait")? {
            RawChildStatus::Exited(code) => {
                return Ok(WorkloadStatus {
                    code: Some(code),
                    signal: None,
                });
            }
            RawChildStatus::Signaled(signal) => {
                return Ok(WorkloadStatus {
                    code: None,
                    signal: Some(signal),
                });
            }
            RawChildStatus::Stopped | RawChildStatus::Continued => {}
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RawChildStatus {
    Exited(u8),
    Signaled(u16),
    Stopped,
    Continued,
}

/// Decode Linux's integer wait status without converting the terminating
/// signal through `nix::sys::signal::Signal`. The latter intentionally omits
/// the glibc-reserved and realtime signal numbers, while Pocket admits and
/// must report the kernel's complete 1..=64 signal range.
fn decode_raw_wait_status(
    status: libc::c_int,
    stage: &'static str,
) -> Result<RawChildStatus, InitError> {
    if libc::WIFEXITED(status) {
        let code = u8::try_from(libc::WEXITSTATUS(status))
            .map_err(|_| InitError::contract(stage, "exit code does not fit in u8"))?;
        return Ok(RawChildStatus::Exited(code));
    }
    if libc::WIFSIGNALED(status) {
        let signal = libc::WTERMSIG(status);
        if !(1..=64).contains(&signal) {
            return Err(InitError::contract(
                stage,
                format!("terminating signal {signal} is outside the Linux 1..=64 range"),
            ));
        }
        return Ok(RawChildStatus::Signaled(u16::try_from(signal).map_err(
            |_| InitError::contract(stage, "terminating signal does not fit in u16"),
        )?));
    }
    if libc::WIFSTOPPED(status) {
        return Ok(RawChildStatus::Stopped);
    }
    if libc::WIFCONTINUED(status) {
        return Ok(RawChildStatus::Continued);
    }
    Err(InitError::contract(
        stage,
        format!("kernel returned unrecognized wait status {status:#x}"),
    ))
}

fn wait_for_raw_child(pid: Pid, stage: &'static str) -> Result<RawChildStatus, InitError> {
    loop {
        let mut status = 0;
        // SAFETY: `status` is a live writable integer, `pid` names the exact
        // child to reap, and option zero requests only blocking state changes.
        let waited = unsafe { libc::waitpid(pid.as_raw(), &mut status, 0) };
        if waited == pid.as_raw() {
            return decode_raw_wait_status(status, stage);
        }
        if waited < 0 {
            let error = Errno::last();
            if error == Errno::EINTR {
                continue;
            }
            return Err(InitError::syscall(stage, error));
        }
        return Err(InitError::contract(
            stage,
            format!("waitpid returned unexpected child PID {waited}"),
        ));
    }
}

fn write_internal_event(writer: &mut File, event: &InternalEvent) -> Result<(), InitError> {
    let bytes = event.encode()?;
    writer
        .write_all(&bytes)
        .map_err(|error| InitError::io("internal-event", error))?;
    writer
        .flush()
        .map_err(|error| InitError::io("internal-event", error))
}

fn bounded_internal_diagnostic(value: &str) -> String {
    const LIMIT: usize = 4000;
    if value.len() <= LIMIT {
        return value.to_owned();
    }
    let mut boundary = LIMIT;
    while !value.is_char_boundary(boundary) {
        boundary -= 1;
    }
    value[..boundary].to_owned()
}

fn run_namespace(
    config: &GuestConfig,
    start: &Start,
    control: &mut File,
    writer: &mut FrameWriter<File>,
    session: &mut WorkloadSession,
    topology: IoTopology,
) -> Result<(WorkloadStatus, bool), InitError> {
    set_nonblocking(control, "control-loop")?;
    let SpawnedNamespace {
        staging_pid,
        teardown_pid_reader,
        mut events,
        mut pumps,
    } = spawn_namespace(config, start, topology)?;

    let result = namespace_event_loop(control, &mut events, &mut pumps, writer, session, start);
    let failed = result.is_err();
    let staging_kill = if failed {
        // Stop the supervisor first. It either published the exact outer PID
        // before releasing the workload, or its death closes the release gate
        // and the not-yet-released child exits without exec. If exec already
        // cleared PDEATHSIG because of set-ID or file capabilities, the PID
        // channel still lets PID 1 kill the nested namespace init explicitly.
        forward_unix_signal(staging_pid, UnixSignal::SIGKILL)
    } else {
        Ok(())
    };
    // Reap the supervisor before reading its channel so it can no longer race
    // publication or release. The channel is nonblocking because the gated
    // workload briefly inherited its writer at fork; no PID bytes means that
    // child was never released and will exit when it observes the closed gate.
    let staging_status = wait_for_staging(staging_pid);
    let workload_kill = if failed {
        read_teardown_pid(teardown_pid_reader).and_then(|pid| match pid {
            Some(pid) => forward_unix_signal(pid, UnixSignal::SIGKILL),
            None => Ok(()),
        })
    } else {
        drop(teardown_pid_reader);
        Ok(())
    };
    let teardown_result = staging_kill.and(workload_kill);
    // As the guest's outer PID 1, pocket-init adopts any orphan left while a
    // failed staging process and its nested PID namespace are being torn down.
    // Block until ECHILD rather than taking a single WNOHANG snapshot, so the
    // clean-poweroff path never leaves an unreaped descendant behind.
    let descendants_reaped = reap_all_children();
    match (result, teardown_result, staging_status, descendants_reaped) {
        (Ok(outcome), Ok(()), Ok(true), Ok(())) => Ok(outcome),
        (Ok(_), Ok(()), Ok(false), _) => Err(InitError::contract(
            "namespace-wait",
            "namespace supervisor exited unsuccessfully",
        )),
        (Ok(_), Ok(()), _, Err(error))
        | (Ok(_), Ok(()), Err(error), _)
        | (Ok(_), Err(error), _, _)
        | (Err(_), Err(error), _, _)
        | (Err(_), Ok(()), _, Err(error))
        | (Err(_), Ok(()), Err(error), _) => Err(error),
        (Err(error), Ok(()), Ok(_), Ok(())) => Err(error),
    }
}

fn wait_for_staging(pid: Pid) -> Result<bool, InitError> {
    loop {
        match wait_for_raw_child(pid, "namespace-wait")? {
            RawChildStatus::Exited(0) => return Ok(true),
            RawChildStatus::Exited(_) | RawChildStatus::Signaled(_) => return Ok(false),
            RawChildStatus::Stopped | RawChildStatus::Continued => {}
        }
    }
}

fn reap_all_children() -> Result<(), InitError> {
    loop {
        let mut status = 0;
        // SAFETY: `status` is writable and PID -1 asks for any adopted child.
        let waited = unsafe { libc::waitpid(-1, &mut status, 0) };
        if waited > 0 {
            // Decode every status as well as reaping it, so an impossible or
            // out-of-contract kernel status cannot be silently accepted.
            let _ = decode_raw_wait_status(status, "descendant-reap")?;
            continue;
        }
        if waited == 0 {
            return Err(InitError::contract(
                "descendant-reap",
                "blocking waitpid unexpectedly reported no child state",
            ));
        }
        match Errno::last() {
            Errno::ECHILD => return Ok(()),
            Errno::EINTR => {}
            error => return Err(InitError::syscall("descendant-reap", error)),
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum PollTarget {
    Control,
    NamespaceEvents,
    PumpRead(usize),
    PumpWrite(usize),
}

fn namespace_event_loop(
    control: &mut File,
    events: &mut File,
    pumps: &mut PumpSet,
    writer: &mut FrameWriter<File>,
    session: &mut WorkloadSession,
    start: &Start,
) -> Result<(WorkloadStatus, bool), InitError> {
    let mut control_decoder = ControlFrameDecoder::new(1);
    let mut event_decoder = InternalEventDecoder::new();
    let mut workload_pid = None;
    let mut outcome = None;
    let mut drain_deadline = None;
    let mut shutdown_deadline = None;
    let mut control_eof = false;
    let mut event_eof = false;

    loop {
        if outcome.is_some() && pumps.outputs_drained() {
            break;
        }
        if let Some(deadline) = drain_deadline
            && Instant::now() >= deadline
        {
            return Err(InitError::contract(
                "stream-drain",
                "output streams did not drain within the fixed shutdown bound",
            ));
        }
        if outcome.is_none()
            && let Some(deadline) = shutdown_deadline
            && Instant::now() >= deadline
        {
            return Err(InitError::contract(
                "forced-shutdown",
                "nested PID namespace did not drain within SHUTDOWN grace_ms",
            ));
        }

        let active_deadline = if outcome.is_some() {
            drain_deadline
        } else {
            shutdown_deadline
        };
        let ready = poll_once(control, events, pumps, active_deadline)?;
        for (target, flags) in ready {
            match target {
                PollTarget::Control => {
                    let read = read_control_available(control, &mut control_decoder)?;
                    if read.eof {
                        control_eof = true;
                    }
                    for frame in read.frames {
                        let message = decode_workload_message(&frame)
                            .map_err(|error| InitError::protocol("control-loop", error))?;
                        session
                            .accept(
                                Direction::HostToGuest,
                                frame.header.kind,
                                frame.header.sequence,
                            )
                            .map_err(|error| InitError::protocol("control-loop", error))?;
                        let pid = workload_pid.ok_or_else(|| {
                            InitError::contract(
                                "control-loop",
                                "runtime control message arrived before READY",
                            )
                        })?;
                        match message {
                            WorkloadMessage::Signal(signal) => forward_signal(pid, &signal)?,
                            WorkloadMessage::Resize(resize) => {
                                pumps.resize(&resize)?;
                                forward_unix_signal(pid, UnixSignal::SIGWINCH)?;
                            }
                            WorkloadMessage::Shutdown(shutdown) => {
                                // The host already sent the configured stop
                                // signal and waited its caller-selected grace.
                                // Killing PID 1 of the nested namespace makes
                                // the guest kernel synchronously tear down its
                                // remaining process tree. The supervisor then
                                // reports the actual wait status and only then
                                // cleans its private mounts.
                                forward_unix_signal(pid, UnixSignal::SIGKILL)?;
                                pumps.close_input();
                                shutdown_deadline = Some(
                                    Instant::now()
                                        + Duration::from_millis(u64::from(shutdown.grace_ms)),
                                );
                            }
                            other => {
                                return Err(InitError::contract(
                                    "control-loop",
                                    format!(
                                        "unsupported runtime message kind {}",
                                        other.kind() as u16
                                    ),
                                ));
                            }
                        }
                    }
                }
                PollTarget::NamespaceEvents => {
                    let read = read_event_available(events, &mut event_decoder)?;
                    if read.eof {
                        event_eof = true;
                    }
                    for event in read.events {
                        match event {
                            InternalEvent::Ready { outer_pid } => {
                                if workload_pid.is_some() || outer_pid <= 0 {
                                    return Err(InitError::contract(
                                        "namespace-events",
                                        "duplicate or invalid READY event",
                                    ));
                                }
                                workload_pid = Some(Pid::from_raw(outer_pid));
                                send_guest_message(
                                    writer,
                                    session,
                                    WorkloadMessage::Ready(Ready {
                                        // The directly exec'd workload is PID 1 in
                                        // its nested namespace, independent of the
                                        // outer PID used for signal delivery.
                                        guest_pid: 1,
                                        effective_uid: start.uid,
                                        effective_gid: start.gid,
                                        cwd: start.cwd.clone(),
                                    }),
                                )?;
                            }
                            InternalEvent::Exit {
                                code,
                                signal,
                                namespace_clean,
                            } => {
                                if workload_pid.is_none() || outcome.is_some() {
                                    return Err(InitError::contract(
                                        "namespace-events",
                                        "EXIT arrived before READY or more than once",
                                    ));
                                }
                                outcome = Some((WorkloadStatus { code, signal }, namespace_clean));
                                pumps.close_input();
                                drain_deadline = Some(Instant::now() + OUTPUT_DRAIN_TIMEOUT);
                            }
                            InternalEvent::Error { errno, diagnostic } => {
                                return Err(InitError::child("namespace-child", errno, diagnostic));
                            }
                        }
                    }
                }
                PollTarget::PumpRead(index) => pumps.streams[index].read_available()?,
                PollTarget::PumpWrite(index) => pumps.streams[index].write_available()?,
            }

            if flags.contains(PollFlags::POLLNVAL) {
                return Err(InitError::contract(
                    "runtime-poll",
                    "poll reported an invalid descriptor",
                ));
            }
        }

        if control_eof && outcome.is_none() {
            return Err(InitError::contract(
                "control-loop",
                "host control stream closed before workload exit",
            ));
        }
        if event_eof && outcome.is_none() {
            return Err(InitError::contract(
                "namespace-events",
                "namespace supervisor closed its event stream without EXIT",
            ));
        }
    }

    if control_decoder.has_pending() {
        return Err(InitError::contract(
            "control-loop",
            "control stream ended with a partial frame",
        ));
    }
    outcome.ok_or_else(|| InitError::contract("namespace-events", "missing workload outcome"))
}

fn poll_once(
    control: &File,
    events: &File,
    pumps: &PumpSet,
    deadline: Option<Instant>,
) -> Result<Vec<(PollTarget, PollFlags)>, InitError> {
    let mut targets = Vec::new();
    let mut descriptors = Vec::new();

    targets.push(PollTarget::Control);
    descriptors.push(PollFd::new(
        control.as_fd(),
        PollFlags::POLLIN | PollFlags::POLLHUP | PollFlags::POLLERR,
    ));
    targets.push(PollTarget::NamespaceEvents);
    descriptors.push(PollFd::new(
        events.as_fd(),
        PollFlags::POLLIN | PollFlags::POLLHUP | PollFlags::POLLERR,
    ));
    for (index, stream) in pumps.streams.iter().enumerate() {
        if stream.wants_read()
            && let Some(source) = stream.source_file()
        {
            targets.push(PollTarget::PumpRead(index));
            descriptors.push(PollFd::new(
                source.as_fd(),
                PollFlags::POLLIN | PollFlags::POLLHUP | PollFlags::POLLERR,
            ));
        }
        if stream.wants_write()
            && let Some(sink) = stream.sink_file()
        {
            targets.push(PollTarget::PumpWrite(index));
            descriptors.push(PollFd::new(
                sink.as_fd(),
                PollFlags::POLLOUT | PollFlags::POLLHUP | PollFlags::POLLERR,
            ));
        }
    }

    let timeout_ms = deadline.map_or(100_u16, |deadline| {
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            return 0;
        };
        if remaining.is_zero() {
            return 0;
        }
        let submillisecond = u128::from(u8::from(remaining.subsec_nanos() % 1_000_000 != 0));
        let rounded_up = remaining.as_millis().saturating_add(submillisecond);
        u16::try_from(rounded_up.min(100)).unwrap_or(100)
    });
    poll(&mut descriptors, timeout_ms)
        .map_err(|error| InitError::syscall("runtime-poll", error))?;
    Ok(targets
        .into_iter()
        .zip(descriptors)
        .filter_map(|(target, descriptor)| {
            descriptor
                .revents()
                .filter(|flags| !flags.is_empty())
                .map(|flags| (target, flags))
        })
        .collect())
}

struct ControlRead {
    frames: Vec<pocket_protocol::RawFrame>,
    eof: bool,
}

fn read_control_available(
    control: &mut File,
    decoder: &mut ControlFrameDecoder,
) -> Result<ControlRead, InitError> {
    let mut frames = Vec::new();
    let mut eof = false;
    loop {
        let mut chunk = [0_u8; IO_CHUNK];
        match control.read(&mut chunk) {
            Ok(0) => {
                eof = true;
                break;
            }
            Ok(count) => frames.extend(
                decoder
                    .feed(&chunk[..count])
                    .map_err(|error| InitError::protocol("control-loop", error))?,
            ),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(InitError::io("control-loop", error)),
        }
    }
    Ok(ControlRead { frames, eof })
}

struct EventRead {
    events: Vec<InternalEvent>,
    eof: bool,
}

fn read_event_available(
    event_file: &mut File,
    decoder: &mut InternalEventDecoder,
) -> Result<EventRead, InitError> {
    let mut events = Vec::new();
    let mut eof = false;
    loop {
        let mut chunk = [0_u8; IO_CHUNK];
        match event_file.read(&mut chunk) {
            Ok(0) => {
                eof = true;
                break;
            }
            Ok(count) => events.extend(decoder.feed(&chunk[..count])?),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(InitError::io("namespace-events", error)),
        }
    }
    if eof && decoder.has_pending() {
        return Err(InitError::contract(
            "namespace-events",
            "namespace event stream ended with a partial record",
        ));
    }
    Ok(EventRead { events, eof })
}

fn forward_signal(pid: Pid, signal: &Signal) -> Result<(), InitError> {
    let raw_signal = i32::from(signal.signal);
    // SAFETY: pid is a live workload PID and the shared protocol validator
    // constrains the raw Linux signal number to 1..=64. The syscall does not
    // dereference userspace pointers.
    let result = unsafe { libc::kill(pid.as_raw(), raw_signal) };
    if result == 0 {
        return Ok(());
    }
    let error = Errno::last();
    match error {
        Errno::ESRCH => Ok(()),
        _ => Err(InitError::syscall("signal-forward", error)),
    }
}

fn forward_unix_signal(pid: Pid, signal: UnixSignal) -> Result<(), InitError> {
    match kill(pid, signal) {
        Ok(()) | Err(Errno::ESRCH) => Ok(()),
        Err(error) => Err(InitError::syscall("signal-forward", error)),
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, fs::File, io, io::Write, os::unix::fs::symlink};

    use nix::{
        fcntl::OFlag,
        unistd::{Pid, pipe2},
    };
    use tempfile::tempdir;

    use super::{
        RawChildStatus, StreamPump, await_workload_release, decode_raw_wait_status,
        hostname_text_matches, loopback_flags_with_up, prepare_generated_target,
        prepare_generated_target_in_effective_root, publish_teardown_pid, read_teardown_pid,
        recreate_devpts_mountpoint, release_workload, resolve_beneath, resolve_generated_target,
        root_mount_is_private, verify_namespace_supervisor_liveness,
    };

    /// `mount` follows symlinks in its target, so a share aimed at a path the
    /// image made an absolute symlink would land on the initramfs we are still
    /// standing in rather than on the image. Resolution happens in the image
    /// root first, which is also what the guest itself will see.
    #[test]
    fn a_destination_is_resolved_inside_the_image_root() {
        let temporary = tempdir().expect("temporary root");
        let root = temporary.path().join("image");
        fs::create_dir(&root).expect("create the image root");
        fs::create_dir(root.join("etc")).expect("create etc");
        fs::create_dir(root.join("plain")).expect("create a plain directory");
        let root_text = root.to_str().expect("utf-8 root");

        assert_eq!(
            resolve_beneath(root_text, "plain").expect("a plain directory resolves"),
            format!("{root_text}/plain")
        );

        // An absolute symlink resolves against the image root, not ours.
        symlink("/etc", root.join("absolute")).expect("create an absolute symlink");
        assert_eq!(
            resolve_beneath(root_text, "absolute").expect("an absolute symlink resolves in root"),
            format!("{root_text}/etc")
        );

        // A relative one that would climb out is clamped to the root as well.
        symlink("../../../../etc", root.join("climbing")).expect("create a climbing symlink");
        assert_eq!(
            resolve_beneath(root_text, "climbing").expect("a climbing symlink resolves in root"),
            format!("{root_text}/etc")
        );

        // A destination that is not there at all is an error, not a guess.
        resolve_beneath(root_text, "absent").expect_err("an absent destination is refused");
    }

    /// Drive an input pump to completion over real pipes and return what the
    /// workload side would have observed, plus whether its standard input was
    /// ended. The announced length, not channel end-of-file, must be what
    /// terminates the stream.
    fn pump_input(announced: u64, payload: &[u8]) -> (Vec<u8>, bool) {
        use std::io::Read as _;

        let (source_read, source_write) = pipe2(OFlag::O_CLOEXEC).expect("source pipe");
        // The workload side is read non-blocking so the harness can interleave
        // pumping and draining without deadlocking on an empty pipe.
        let (sink_read, sink_write) =
            pipe2(OFlag::O_CLOEXEC | OFlag::O_NONBLOCK).expect("sink pipe");
        // The payload is fed from another thread, exactly as the host feeds the
        // channel, and the writer end is deliberately held open: the host keeps
        // the channel open for the whole run, so channel end-of-file never
        // arrives while the workload is alive.
        let payload = payload.to_vec();
        let feeder = std::thread::spawn(move || {
            let mut writer = File::from(source_write);
            let _ = writer.write_all(&payload);
            let _ = writer.flush();
            std::thread::sleep(std::time::Duration::from_millis(50));
            writer
        });

        let mut pump = StreamPump::new(
            "stdin",
            File::from(source_read),
            File::from(sink_write),
            false,
            false,
        )
        .expect("pump")
        .with_input_limit(announced);

        let mut reader = File::from(sink_read);
        let mut observed = Vec::new();
        let mut guard = 0;
        // The sink pipe is small, so alternate reading and pumping. Reads can
        // legitimately return WouldBlock while the feeder is still writing.
        while pump.wants_read() || pump.wants_write() {
            pump.read_available().expect("read");
            pump.write_available().expect("write");
            let mut chunk = [0_u8; 4096];
            // Non-blocking: the pump set both ends non-blocking.
            match reader.read(&mut chunk) {
                Ok(0) => break,
                Ok(count) => observed.extend_from_slice(&chunk[..count]),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => panic!("sink read failed: {error}"),
            }
            guard += 1;
            assert!(guard < 100_000, "pump did not converge");
        }
        drop(pump);
        loop {
            let mut chunk = [0_u8; 4096];
            match reader.read(&mut chunk) {
                Ok(0) => break,
                Ok(count) => observed.extend_from_slice(&chunk[..count]),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => panic!("sink drain failed: {error}"),
            }
        }
        let mut probe = [0_u8; 1];
        let ended = matches!(reader.read(&mut probe), Ok(0));
        drop(feeder.join().expect("payload feeder"));
        (observed, ended)
    }

    #[test]
    fn input_pump_rejects_a_source_that_ends_before_the_announced_length() {
        let (source_read, source_write) = pipe2(OFlag::O_CLOEXEC).expect("source pipe");
        let (sink_read, sink_write) =
            pipe2(OFlag::O_CLOEXEC | OFlag::O_NONBLOCK).expect("sink pipe");
        let mut writer = File::from(source_write);
        writer.write_all(b"short").expect("write a partial payload");
        // The host died after announcing more than it delivered.
        drop(writer);

        let mut pump = StreamPump::new(
            "stdin",
            File::from(source_read),
            File::from(sink_write),
            false,
            false,
        )
        .expect("pump")
        .with_input_limit(64);

        let error = pump
            .read_available()
            .expect_err("a truncated payload must fail the run, not end standard input");
        assert!(
            format!("{error}").contains("before the announced length"),
            "unexpected error: {error}"
        );
        drop(sink_read);
    }

    #[test]
    fn input_pump_ends_standard_input_after_the_announced_length() {
        let payload = b"exactly-these-bytes";
        let (observed, ended) = pump_input(payload.len() as u64, payload);
        assert_eq!(observed, payload);
        assert!(
            ended,
            "standard input must end once the payload is complete"
        );
    }

    #[test]
    fn input_pump_forwards_nothing_and_ends_immediately_for_a_zero_length_payload() {
        let (observed, ended) = pump_input(0, b"never-announced");
        assert!(observed.is_empty());
        assert!(ended, "a zero-length payload must still end standard input");
    }

    #[test]
    fn input_pump_stops_at_the_announced_length_and_ignores_surplus() {
        let (observed, ended) = pump_input(4, b"keepdiscard");
        assert_eq!(observed, b"keep");
        assert!(ended);
    }

    #[test]
    fn input_pump_spans_many_buffer_refills() {
        let payload: Vec<u8> = (0..300_000_usize)
            .map(|index| (index % 251) as u8)
            .collect();
        let (observed, ended) = pump_input(payload.len() as u64, &payload);
        assert_eq!(observed.len(), payload.len());
        assert_eq!(observed, payload);
        assert!(ended);
    }

    #[test]
    fn propagation_check_accepts_private_root_and_rejects_shared_root() {
        let private = "25 1 0:22 / / rw,relatime - rootfs rootfs rw\n";
        let shared = "25 1 0:22 / / rw,relatime shared:7 - rootfs rootfs rw\n";
        let slave = "25 1 0:22 / / rw,relatime master:7 - rootfs rootfs rw\n";
        assert!(root_mount_is_private(private));
        assert!(!root_mount_is_private(shared));
        assert!(!root_mount_is_private(slave));
        assert!(!root_mount_is_private(""));
    }

    #[test]
    fn loopback_flag_update_preserves_existing_flags_and_sets_up() {
        let original = libc::IFF_LOOPBACK as libc::c_short;
        let updated = loopback_flags_with_up(original);
        assert_eq!(updated & original, original);
        assert_ne!(updated & libc::IFF_UP as libc::c_short, 0);
    }

    #[test]
    fn effective_hostname_requires_exact_kernel_text() {
        assert!(hostname_text_matches("pocket\n", "pocket"));
        assert!(hostname_text_matches("pocket", "pocket"));
        assert!(!hostname_text_matches("pocket-2\n", "pocket"));
        assert!(!hostname_text_matches("pocket\n\n", "pocket"));
    }

    #[test]
    fn devpts_mountpoint_is_recreated_in_the_visible_dev_tree() {
        let temporary = tempdir().expect("temporary root");
        let dev = temporary.path().join("dev");
        fs::create_dir_all(dev.join("pts")).expect("initramfs devpts mount point");

        // Replacing this directory models the visibility change caused by
        // mounting devtmpfs over the initramfs /dev.
        fs::remove_dir_all(&dev).expect("hide initramfs dev tree");
        fs::create_dir(&dev).expect("visible devtmpfs root");
        assert!(!dev.join("pts").exists());

        recreate_devpts_mountpoint(&dev).expect("recreate visible mount point");
        assert!(dev.join("pts").is_dir());
    }

    #[test]
    fn generated_target_resolver_follows_relative_and_absolute_chroot_symlinks() {
        let temporary = tempdir().expect("temporary root");
        let root = temporary.path();
        fs::create_dir(root.join("etc")).expect("etc");
        symlink("../run/resolver/current", root.join("etc/resolv.conf")).expect("relative symlink");

        let resolved =
            resolve_generated_target(root, "etc/resolv.conf").expect("resolve relative symlink");
        assert_eq!(resolved, root.join("run/resolver/current"));
        assert!(root.join("run/resolver").is_dir());
        prepare_generated_target(&resolved).expect("create target");
        assert!(resolved.is_file());

        symlink("/run/resolver/absolute", root.join("etc/hostname")).expect("absolute symlink");
        let resolved =
            resolve_generated_target(root, "etc/hostname").expect("resolve absolute symlink");
        assert_eq!(resolved, root.join("run/resolver/absolute"));
    }

    #[test]
    fn generated_target_resolver_rechecks_symlink_targets_and_rejects_escape() {
        let temporary = tempdir().expect("temporary root");
        let root = temporary.path();
        fs::create_dir_all(root.join("etc/links")).expect("directories");
        symlink("links/first", root.join("etc/hosts")).expect("first link");
        symlink("../../run/hosts", root.join("etc/links/first")).expect("second link");
        let resolved = resolve_generated_target(root, "etc/hosts").expect("resolve symlink chain");
        assert_eq!(resolved, root.join("run/hosts"));

        symlink("../../../outside", root.join("etc/hostname")).expect("escape link");
        assert!(resolve_generated_target(root, "etc/hostname").is_err());
    }

    #[test]
    fn generated_run_target_is_materialized_in_the_effective_root() {
        let image = tempdir().expect("underlying image root");
        fs::create_dir_all(image.path().join("etc")).expect("image etc");
        fs::create_dir_all(image.path().join("run")).expect("image run");
        symlink(
            "../run/pocket/resolver",
            image.path().join("etc/resolv.conf"),
        )
        .expect("image resolver symlink");

        // Model the post-bind namespace with its own blank /run mount. The
        // /etc symlink remains image-controlled, but its target must be
        // created in this effective tree rather than under `image`.
        let effective = tempdir().expect("effective root");
        fs::create_dir_all(effective.path().join("etc")).expect("effective etc");
        fs::create_dir_all(effective.path().join("run")).expect("private run");
        symlink(
            "../run/pocket/resolver",
            effective.path().join("etc/resolv.conf"),
        )
        .expect("effective resolver symlink");

        let target =
            prepare_generated_target_in_effective_root(effective.path(), "etc/resolv.conf")
                .expect("prepare effective target");
        assert_eq!(target, effective.path().join("run/pocket/resolver"));
        assert!(target.is_file());
        assert!(!image.path().join("run/pocket/resolver").exists());
    }

    #[test]
    fn raw_wait_decoder_preserves_every_linux_terminating_signal() {
        for signal in 1..=64 {
            assert_eq!(
                decode_raw_wait_status(signal, "test").expect("signal status"),
                RawChildStatus::Signaled(signal as u16),
            );
        }
        assert_eq!(
            decode_raw_wait_status(34 | 0x80, "test").expect("core signal status"),
            RawChildStatus::Signaled(34),
        );
    }

    #[test]
    fn raw_wait_decoder_preserves_exit_and_nonterminal_states() {
        assert_eq!(
            decode_raw_wait_status(255 << 8, "test").expect("exit status"),
            RawChildStatus::Exited(255),
        );
        assert_eq!(
            decode_raw_wait_status((libc::SIGSTOP << 8) | 0x7f, "test").expect("stopped status"),
            RawChildStatus::Stopped,
        );
        assert_eq!(
            decode_raw_wait_status(0xffff, "test").expect("continued status"),
            RawChildStatus::Continued,
        );
    }

    #[test]
    fn teardown_pid_is_published_before_the_workload_release_gate() {
        let (pid_reader, pid_writer) = pipe2(OFlag::O_CLOEXEC).expect("PID pipe");
        let (release_reader, release_writer) = pipe2(OFlag::O_CLOEXEC).expect("release pipe");
        let expected = Pid::from_raw(4242);

        publish_teardown_pid(File::from(pid_writer), expected).expect("publish PID");
        release_workload(File::from(release_writer)).expect("release workload");

        assert_eq!(
            read_teardown_pid(File::from(pid_reader))
                .expect("read PID")
                .expect("published PID"),
            expected,
        );
        await_workload_release(File::from(release_reader)).expect("observe release");
    }

    #[test]
    fn namespace_supervisor_liveness_pipe_distinguishes_live_closed_and_corrupt() {
        let flags = OFlag::O_CLOEXEC | OFlag::O_NONBLOCK;
        let (reader, writer) = pipe2(flags).expect("live supervisor pipe");
        let reader = File::from(reader);
        verify_namespace_supervisor_liveness(&reader, "in test")
            .expect("open writer proves supervisor liveness");
        drop(writer);
        assert!(verify_namespace_supervisor_liveness(&reader, "in test").is_err());

        let (reader, writer) = pipe2(flags).expect("corrupt supervisor pipe");
        let mut writer = File::from(writer);
        writer.write_all(&[1]).expect("inject unexpected byte");
        assert!(verify_namespace_supervisor_liveness(&File::from(reader), "in test").is_err());
    }
}
