use std::{
    convert::Infallible,
    fs::{self, File, OpenOptions},
    io::Read,
    os::unix::{fs::FileTypeExt, fs::OpenOptionsExt},
    path::Path,
};

use nix::{
    mount::{MntFlags, MsFlags, mount, umount2},
    sys::{
        reboot::{RebootMode, reboot},
        signal::{SigSet, SigmaskHow, Signal, pthread_sigmask},
        termios::{SetArg, cfmakeraw, tcgetattr, tcsetattr},
        time::TimeSpec,
        utsname::uname,
    },
    time::{ClockId, clock_settime},
    unistd::{SysconfVar, getpid, sync, syncfs, sysconf},
};
use pocket_protocol::{
    BUILDER_GUEST_FEATURES, BuilderDone, BuilderHello, BuilderMessage, BuilderSession, Direction,
    FilesystemStatus, FrameReader, FrameWriter, ToolIdentity, decode_builder_message,
};

use crate::{
    BuilderConfig, BuilderError, ManifestEmitter, UmociLayerApplier,
    config::{INPUT_DEVICE, INPUT_MOUNT, TARGET_DEVICE, TARGET_MOUNT},
    execute_conversion, inspect_umoci,
    tool::UMOCI_PATH,
};

const CMDLINE_LIMIT: usize = 64 * 1024;
const PHYSMEM_LIMIT: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
struct BuilderObservation {
    uts_machine: String,
    oci_architecture: String,
    elf_machine: u16,
    page_size: u32,
    online_cpus: u16,
    accepted_physmem_bytes: u64,
}

pub fn run() -> Result<Infallible, BuilderError> {
    if getpid().as_raw() != 1 {
        return Err(BuilderError::contract(
            "early-boot",
            "pocket-builder-init must run as guest PID 1",
        ));
    }
    block_sigpipe()?;
    mount_early_filesystems()?;
    let cmdline = read_bounded_text("/proc/cmdline", CMDLINE_LIMIT, "cmdline")?;
    let config = BuilderConfig::parse_cmdline(cmdline.trim_end())?;
    let observation = observe_guest(&config)?;
    let tools = vec![inspect_umoci(Path::new(UMOCI_PATH))?];
    let control = open_raw_control(&config.control_path)?;
    let mut control_reader = control
        .try_clone()
        .map_err(|error| BuilderError::io("control", error))?;
    let mut writer = FrameWriter::new(control);
    let mut session = BuilderSession::new();
    send_guest_message(
        &mut writer,
        &mut session,
        BuilderMessage::Hello(make_hello(&config, &observation, tools.clone())),
    )?;

    let result = run_after_hello(
        &config,
        &observation,
        &tools,
        &mut control_reader,
        &mut writer,
        &mut session,
    );
    match result {
        Ok(done) => send_guest_message(&mut writer, &mut session, BuilderMessage::Done(done))?,
        Err(error) => {
            let _ = send_guest_message(
                &mut writer,
                &mut session,
                BuilderMessage::Error(error.to_protocol_message()),
            );
        }
    }
    let _ = writer.flush();
    sync();
    reboot(RebootMode::RB_POWER_OFF).map_err(|error| BuilderError::syscall("poweroff", error))
}

pub fn emergency_poweroff() -> ! {
    sync();
    let _ = reboot(RebootMode::RB_POWER_OFF);
    loop {
        nix::unistd::pause();
    }
}

fn run_after_hello(
    config: &BuilderConfig,
    first_observation: &BuilderObservation,
    tools: &[ToolIdentity],
    control_reader: &mut File,
    writer: &mut FrameWriter<File>,
    session: &mut BuilderSession,
) -> Result<BuilderDone, BuilderError> {
    let frame = FrameReader::new(control_reader)
        .read_frame()
        .map_err(|error| BuilderError::protocol("receive-start", error))?;
    let message = decode_builder_message(&frame)
        .map_err(|error| BuilderError::protocol("receive-start", error))?;
    if let BuilderMessage::Start(start) = &message {
        if start.expected_tools != tools {
            return Err(BuilderError::failure(
                "start-contract",
                pocket_core::ErrorCode::BuilderToolMismatch,
                None,
                "expected helper identities differ from measured BUILD_HELLO evidence",
            ));
        }
        if start.expected_physmem_bytes != first_observation.accepted_physmem_bytes {
            return Err(BuilderError::contract(
                "start-contract",
                "expected physical memory differs from measured BUILD_HELLO evidence",
            ));
        }
    }
    session
        .accept(Direction::HostToGuest, &message, frame.header.sequence)
        .map_err(|error| BuilderError::protocol("receive-start", error))?;
    let BuilderMessage::Start(start) = message else {
        return Err(BuilderError::contract(
            "receive-start",
            "expected BUILD_START",
        ));
    };
    let start = *start;
    let second_observation = observe_guest(config)?;
    if &second_observation != first_observation {
        return Err(BuilderError::contract(
            "start-contract",
            "guest architecture, CPU, page-size, or memory observation changed during handshake",
        ));
    }
    verify_start(config, first_observation, tools, &start)?;
    initialize_build_clock(start.source_date_epoch)?;

    let mut filesystems = MountedFilesystems::mount()?;
    let conversion = {
        let mut emitter = ProtocolEmitter { writer, session };
        let mut applier = UmociLayerApplier::new(UMOCI_PATH);
        execute_conversion(
            Path::new(INPUT_MOUNT),
            Path::new(TARGET_MOUNT),
            &start,
            &mut applier,
            &mut emitter,
        )
    };
    let cleanup = filesystems.sync_and_unmount();
    let artifacts = conversion?;
    let filesystem_status = cleanup?;
    Ok(BuilderDone {
        status: 0,
        manifest_sha256: artifacts.manifest.sha256,
        entry_count: artifacts.manifest.entry_count,
        byte_count: artifacts.manifest.byte_count,
        generation_marker_sha256: artifacts.generation_marker_sha256,
        account_db_sha256: artifacts.account_db.sha256,
        original_user: start.original_user,
        user_resolution: artifacts.user_resolution,
        observed_tools: tools.to_vec(),
        filesystem_status,
    })
}

/// Initialize guest realtime from the derivation-bound epoch before the
/// target is mounted. This removes host boot time from ext4 mount/write times
/// and from metadata created by the conversion.
///
/// Realtime still advances while the conversion runs, and that is the last
/// remaining byte-reproducibility input. What it still reaches is narrow and
/// measured: every created inode's `ctime`/`crtime`, which no syscall can set,
/// and the journal's committed transaction records. What it no longer reaches
/// is the authenticated filesystem manifest -- every field that records is
/// pinned, so two conversions of one image produce byte-identical manifests,
/// account databases and image configs, and differ only in raw ext4 bytes the
/// manifest does not describe. Two builds are therefore still two generation
/// IDs; making them one requires normalizing inode ctime/crtime and the
/// journal, which this build does not do.
fn initialize_build_clock(source_date_epoch: u64) -> Result<(), BuilderError> {
    let seconds = i64::try_from(source_date_epoch).map_err(|_| {
        BuilderError::contract("build-clock", "source-date epoch does not fit time_t")
    })?;
    clock_settime(ClockId::CLOCK_REALTIME, TimeSpec::new(seconds, 0))
        .map_err(|error| BuilderError::syscall("build-clock", error))
}

fn verify_start(
    config: &BuilderConfig,
    observation: &BuilderObservation,
    tools: &[ToolIdentity],
    start: &pocket_protocol::BuilderStart,
) -> Result<(), BuilderError> {
    if observation.online_cpus != 1
        || observation.accepted_physmem_bytes != config.expected_physmem_bytes
        || start.expected_physmem_bytes != observation.accepted_physmem_bytes
    {
        return Err(BuilderError::contract(
            "start-contract",
            "BUILD_START CPU or physical-memory contract differs from measured guest state",
        ));
    }
    if start.effective_platform.os != "linux"
        || start.effective_platform.architecture != observation.oci_architecture
    {
        return Err(BuilderError::contract(
            "start-contract",
            "effective image platform differs from native builder architecture",
        ));
    }
    if start.root_layout != config.expected_root_layout
        || start.filesystem_contract != config.expected_filesystem_contract
        || start.manifest_schema != config.expected_manifest_schema
    {
        return Err(BuilderError::contract(
            "start-contract",
            "root-layout, filesystem, or metadata-schema contract differs from boot contract",
        ));
    }
    if start.expected_tools != tools {
        return Err(BuilderError::failure(
            "start-contract",
            pocket_core::ErrorCode::BuilderToolMismatch,
            None,
            "expected helper identities differ from measured BUILD_HELLO evidence",
        ));
    }
    Ok(())
}

fn make_hello(
    config: &BuilderConfig,
    observation: &BuilderObservation,
    tools: Vec<ToolIdentity>,
) -> BuilderHello {
    BuilderHello {
        guest_contract_id: config.guest_contract_id.clone(),
        init_build_id: config.init_build_id.clone(),
        kernel_build_id: config.kernel_build_id.clone(),
        host_elf_machine: observation.elf_machine,
        guest_uts_machine: observation.uts_machine.clone(),
        guest_page_size: observation.page_size,
        cpu_state_hwcap_policy: config.cpu_state_hwcap_policy.clone(),
        online_cpus: observation.online_cpus,
        builder_tools: tools,
        features: BUILDER_GUEST_FEATURES
            .iter()
            .map(|feature| (*feature).to_owned())
            .collect(),
        accepted_physmem_bytes: observation.accepted_physmem_bytes,
    }
}

fn send_guest_message(
    writer: &mut FrameWriter<File>,
    session: &mut BuilderSession,
    message: BuilderMessage,
) -> Result<(), BuilderError> {
    let payload = message
        .encode_payload()
        .map_err(|error| BuilderError::protocol("send-control", error))?;
    let sequence = writer.next_sequence();
    session
        .accept(Direction::GuestToHost, &message, sequence)
        .map_err(|error| BuilderError::protocol("send-control", error))?;
    let written = writer
        .write_frame(message.kind(), &payload)
        .map_err(|error| BuilderError::protocol("send-control", error))?;
    if written != sequence {
        return Err(BuilderError::contract(
            "send-control",
            "frame writer sequence changed unexpectedly",
        ));
    }
    writer
        .flush()
        .map_err(|error| BuilderError::protocol("send-control", error))
}

struct ProtocolEmitter<'a> {
    writer: &'a mut FrameWriter<File>,
    session: &'a mut BuilderSession,
}

impl ManifestEmitter for ProtocolEmitter<'_> {
    fn emit(&mut self, message: BuilderMessage) -> Result<(), BuilderError> {
        send_guest_message(self.writer, self.session, message)
    }
}

fn observe_guest(config: &BuilderConfig) -> Result<BuilderObservation, BuilderError> {
    let uts = uname().map_err(|error| BuilderError::syscall("observe-guest", error))?;
    let uts_machine = uts
        .machine()
        .to_str()
        .ok_or_else(|| BuilderError::contract("observe-guest", "UTS machine is not UTF-8"))?
        .to_owned();
    let (oci_architecture, elf_machine) = match uts_machine.as_str() {
        "x86_64" => ("amd64", 62),
        "aarch64" => ("arm64", 183),
        _ => {
            return Err(BuilderError::contract(
                "observe-guest",
                format!("unsupported UTS machine {uts_machine:?}"),
            ));
        }
    };
    if oci_architecture != config.expected_oci_architecture {
        return Err(BuilderError::contract(
            "observe-guest",
            "observed architecture differs from boot contract",
        ));
    }
    let page_size = u32::try_from(required_sysconf(SysconfVar::PAGE_SIZE, "page size")?)
        .map_err(|_| BuilderError::contract("observe-guest", "page size does not fit u32"))?;
    if page_size != config.expected_page_size {
        return Err(BuilderError::contract(
            "observe-guest",
            "observed page size differs from boot contract",
        ));
    }
    let online_cpus = u16::try_from(required_sysconf(
        SysconfVar::_NPROCESSORS_ONLN,
        "online CPU count",
    )?)
    .map_err(|_| BuilderError::contract("observe-guest", "CPU count does not fit u16"))?;
    if online_cpus != 1 {
        return Err(BuilderError::contract(
            "observe-guest",
            "builder must observe exactly one online CPU",
        ));
    }
    let accepted = read_bounded_text("/proc/uml_physmem_bytes", PHYSMEM_LIMIT, "observe-guest")?;
    let accepted_physmem_bytes = accepted.trim().parse::<u64>().map_err(|_| {
        BuilderError::contract(
            "observe-guest",
            "/proc/uml_physmem_bytes is not an unsigned byte count",
        )
    })?;
    if accepted_physmem_bytes != config.expected_physmem_bytes
        || !accepted_physmem_bytes.is_multiple_of(u64::from(page_size))
    {
        return Err(BuilderError::contract(
            "observe-guest",
            format!(
                "UML accepted {accepted_physmem_bytes} bytes; boot contract requires {}",
                config.expected_physmem_bytes
            ),
        ));
    }
    Ok(BuilderObservation {
        uts_machine,
        oci_architecture: oci_architecture.to_owned(),
        elf_machine,
        page_size,
        online_cpus,
        accepted_physmem_bytes,
    })
}

fn required_sysconf(variable: SysconfVar, name: &str) -> Result<i64, BuilderError> {
    sysconf(variable)
        .map_err(|error| BuilderError::syscall("observe-guest", error))?
        .ok_or_else(|| BuilderError::contract("observe-guest", format!("{name} unavailable")))
}

struct MountedFilesystems {
    input: bool,
    target: bool,
}

impl MountedFilesystems {
    fn mount() -> Result<Self, BuilderError> {
        require_block_device(INPUT_DEVICE)?;
        require_block_device(TARGET_DEVICE)?;
        require_empty_mountpoint(INPUT_MOUNT)?;
        require_empty_mountpoint(TARGET_MOUNT)?;
        let common = MsFlags::MS_NODEV
            | MsFlags::MS_NOSUID
            | MsFlags::MS_NOEXEC
            | MsFlags::MS_NOATIME
            | MsFlags::MS_NODIRATIME;
        mount(
            Some(INPUT_DEVICE),
            INPUT_MOUNT,
            Some("ext4"),
            common | MsFlags::MS_RDONLY,
            Some("ro,noload"),
        )
        .map_err(|error| BuilderError::syscall("mount-input", error))?;
        let mut mounted = Self {
            input: true,
            target: false,
        };
        if let Err(error) = mount(
            Some(TARGET_DEVICE),
            TARGET_MOUNT,
            Some("ext4"),
            common,
            Some("rw"),
        ) {
            let _ = umount2(INPUT_MOUNT, MntFlags::UMOUNT_NOFOLLOW);
            mounted.input = false;
            return Err(BuilderError::syscall("mount-target", error));
        }
        mounted.target = true;
        Ok(mounted)
    }

    fn sync_and_unmount(&mut self) -> Result<FilesystemStatus, BuilderError> {
        let target = File::open(TARGET_MOUNT).map_err(|error| {
            BuilderError::io("sync-target", error).reclassify(pocket_core::ErrorCode::BuilderSync)
        })?;
        syncfs(&target).map_err(|error| {
            BuilderError::syscall("sync-target", error)
                .reclassify(pocket_core::ErrorCode::BuilderSync)
        })?;
        drop(target);
        umount2(TARGET_MOUNT, MntFlags::UMOUNT_NOFOLLOW).map_err(|error| {
            BuilderError::syscall("unmount-target", error)
                .reclassify(pocket_core::ErrorCode::BuilderUnmount)
        })?;
        self.target = false;
        umount2(INPUT_MOUNT, MntFlags::UMOUNT_NOFOLLOW).map_err(|error| {
            BuilderError::syscall("unmount-input", error)
                .reclassify(pocket_core::ErrorCode::BuilderUnmount)
        })?;
        self.input = false;
        Ok(FilesystemStatus {
            target_synced: true,
            target_unmounted: true,
            input_unmounted: true,
        })
    }
}

impl Drop for MountedFilesystems {
    fn drop(&mut self) {
        if self.target {
            if let Ok(target) = File::open(TARGET_MOUNT) {
                let _ = syncfs(&target);
            }
            let _ = umount2(TARGET_MOUNT, MntFlags::UMOUNT_NOFOLLOW);
        }
        if self.input {
            let _ = umount2(INPUT_MOUNT, MntFlags::UMOUNT_NOFOLLOW);
        }
    }
}

fn mount_early_filesystems() -> Result<(), BuilderError> {
    for path in [
        "/proc",
        "/sys",
        "/dev",
        "/dev/pts",
        "/run",
        "/tmp",
        INPUT_MOUNT,
        TARGET_MOUNT,
    ] {
        fs::create_dir_all(path).map_err(|error| BuilderError::io("early-mounts", error))?;
    }
    let restrictive = MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC;
    mount(
        Some("proc"),
        "/proc",
        Some("proc"),
        restrictive,
        None::<&str>,
    )
    .map_err(|error| BuilderError::syscall("early-mounts", error))?;
    mount(
        Some("sysfs"),
        "/sys",
        Some("sysfs"),
        restrictive,
        None::<&str>,
    )
    .map_err(|error| BuilderError::syscall("early-mounts", error))?;
    mount(
        Some("devtmpfs"),
        "/dev",
        Some("devtmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
        Some("mode=0755"),
    )
    .map_err(|error| BuilderError::syscall("early-mounts", error))?;
    fs::create_dir_all("/dev/pts").map_err(|error| BuilderError::io("early-mounts", error))?;
    mount(
        Some("devpts"),
        "/dev/pts",
        Some("devpts"),
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
        Some("mode=0620,ptmxmode=0666"),
    )
    .map_err(|error| BuilderError::syscall("early-mounts", error))?;
    for (path, data) in [("/run", "mode=0755"), ("/tmp", "mode=1777")] {
        mount(Some("tmpfs"), path, Some("tmpfs"), restrictive, Some(data))
            .map_err(|error| BuilderError::syscall("early-mounts", error))?;
    }
    Ok(())
}

fn require_block_device(path: &str) -> Result<(), BuilderError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| BuilderError::io("device-contract", error))?;
    if !metadata.file_type().is_block_device() {
        return Err(BuilderError::contract(
            "device-contract",
            format!("{path} is not a block device"),
        ));
    }
    Ok(())
}

fn require_empty_mountpoint(path: &str) -> Result<(), BuilderError> {
    let mut entries =
        fs::read_dir(path).map_err(|error| BuilderError::io("mount-contract", error))?;
    if entries
        .next()
        .transpose()
        .map_err(|error| BuilderError::io("mount-contract", error))?
        .is_some()
    {
        return Err(BuilderError::contract(
            "mount-contract",
            format!("{path} is not empty before mount"),
        ));
    }
    Ok(())
}

fn open_raw_control(path: &str) -> Result<File, BuilderError> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOCTTY)
        .open(path)
        .map_err(|error| BuilderError::io("control", error))?;
    let mut attributes =
        tcgetattr(&file).map_err(|error| BuilderError::syscall("control", error))?;
    cfmakeraw(&mut attributes);
    tcsetattr(&file, SetArg::TCSANOW, &attributes)
        .map_err(|error| BuilderError::syscall("control", error))?;
    Ok(file)
}

fn read_bounded_text(
    path: &str,
    maximum: usize,
    stage: &'static str,
) -> Result<String, BuilderError> {
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|error| BuilderError::io(stage, error))?
        .take((maximum + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| BuilderError::io(stage, error))?;
    if bytes.len() > maximum {
        return Err(BuilderError::contract(stage, "text file exceeds hard cap"));
    }
    String::from_utf8(bytes).map_err(|_| BuilderError::contract(stage, "text file is not UTF-8"))
}

fn block_sigpipe() -> Result<(), BuilderError> {
    let mut signals = SigSet::empty();
    signals.add(Signal::SIGPIPE);
    pthread_sigmask(SigmaskHow::SIG_BLOCK, Some(&signals), None)
        .map_err(|error| BuilderError::syscall("early-boot", error))
}

#[cfg(test)]
mod tests {
    use pocket_protocol::BuilderStart;

    use super::{BuilderObservation, verify_start};
    use crate::{BuilderConfig, input::tests::fixture};

    const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const C: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    fn config() -> BuilderConfig {
        BuilderConfig::parse_cmdline(&format!(
            "pocket.builder.expected_cpus=1 pocket.builder.expected_memory_bytes={} \
             pocket.builder.expected_page_size=4096 \
             pocket.builder.cpu_state_hwcap_policy=native-x86_64-v1 \
             pocket.builder.guest_contract_id={A} \
             pocket.builder.init_build_id={B} pocket.builder.kernel_build_id={C}",
            768 * 1024 * 1024
        ))
        .expect("config")
    }

    fn observation() -> BuilderObservation {
        BuilderObservation {
            uts_machine: "x86_64".to_owned(),
            oci_architecture: "amd64".to_owned(),
            elf_machine: 62,
            page_size: 4096,
            online_cpus: 1,
            accepted_physmem_bytes: 768 * 1024 * 1024,
        }
    }

    #[test]
    fn start_contract_binds_measured_memory_architecture_and_tools() {
        let (_input, start) = fixture();
        assert!(verify_start(&config(), &observation(), &start.expected_tools, &start).is_ok());

        let mut wrong_memory: BuilderStart = start.clone();
        wrong_memory.expected_physmem_bytes = 512 * 1024 * 1024;
        assert!(
            verify_start(
                &config(),
                &observation(),
                &wrong_memory.expected_tools,
                &wrong_memory,
            )
            .is_err()
        );
    }
}
