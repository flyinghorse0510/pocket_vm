use std::{
    convert::Infallible,
    fs::{self, File, OpenOptions},
    io::Read,
    os::unix::{fs::FileExt, fs::FileTypeExt, fs::OpenOptionsExt},
    path::Path,
};

use nix::{
    mount::{MntFlags, MsFlags, mount, umount2},
    sys::{
        reboot::{RebootMode, reboot},
        signal::{SigSet, SigmaskHow, Signal, pthread_sigmask},
        statvfs::{FsFlags, statvfs},
        termios::{SetArg, cfmakeraw, tcgetattr, tcsetattr},
        utsname::uname,
    },
    unistd::{SysconfVar, getpid, sysconf},
};
use pocket_core::ErrorCode;
use pocket_protocol::{
    Direction, FrameReader, FrameWriter, GenerationMarker, VALIDATOR_GUEST_FEATURES,
    ValidateMessage, ValidatorDone, ValidatorEvidence, ValidatorHello, ValidatorMessage,
    ValidatorSession, ValidatorStart, decode_payload, decode_validator_message,
};
use sha2::{Digest as _, Sha256};

use crate::{
    ValidatorConfig, ValidatorError,
    account::rebuild_account_database,
    config::{CANDIDATE_DEVICE, CANDIDATE_MOUNT},
    validate_manifest,
};

const CMDLINE_LIMIT: usize = 64 * 1024;
const PHYSMEM_LIMIT: usize = 32;
const MARKER_LIMIT: usize = 64 * 1024;
const EXT4_SUPERBLOCK_BYTES: usize = 1024;
const EXT4_SUPERBLOCK_OFFSET: u64 = 1024;
const EXT4_MAGIC: u16 = 0xef53;
const EXT4_VALID_FS: u16 = 0x0001;
const EXT4_ERROR_FS: u16 = 0x0002;
const EXT4_ERRORS_CONTINUE: u16 = 0x0001;
const EXT4_FEATURE_INCOMPAT_RECOVER: u32 = 0x0004;
const EXT4_FEATURE_COMPAT_CONTRACT: u32 = 0x0000_003c;
// The frozen profile explicitly enables metadata_csum_seed in addition to
// filetype, extents, 64bit, and flex_bg.
const EXT4_FEATURE_INCOMPAT_CONTRACT: u32 = 0x0000_22c2;
const EXT4_FEATURE_RO_COMPAT_CONTRACT: u32 = 0x0000_046b;
const EXT4_DEFAULT_MOUNT_OPTS_CONTRACT: u32 = 0x0000_000c;
const EXT4_VOLUME_LABEL_CONTRACT: [u8; 16] = *b"pocket-root\0\0\0\0\0";

#[derive(Debug, Clone, PartialEq, Eq)]
struct ValidatorObservation {
    uts_machine: String,
    oci_architecture: String,
    elf_machine: u16,
    page_size: u32,
    online_cpus: u16,
    accepted_physmem_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Ext4Observation {
    uuid: String,
    clean: bool,
    logical_bytes: u64,
    feature_compat: u32,
    feature_incompat: u32,
    feature_ro_compat: u32,
    default_mount_opts: u32,
}

pub fn run() -> Result<Infallible, ValidatorError> {
    if getpid().as_raw() != 1 {
        return Err(ValidatorError::contract(
            "early-boot",
            "pocket-validator-init must run as guest PID 1",
        ));
    }
    block_sigpipe()?;
    mount_early_filesystems()?;
    let cmdline = read_bounded_text("/proc/cmdline", CMDLINE_LIMIT, "cmdline")?;
    let config = ValidatorConfig::parse_cmdline(cmdline.trim_end())?;
    let observation = observe_guest(&config)?;
    let control = open_raw_control(&config.control_path)?;
    let mut reader = control
        .try_clone()
        .map_err(|error| ValidatorError::io("control", error))?;
    let mut writer = FrameWriter::new(control);
    let mut session = ValidatorSession::new();
    send_guest_message(
        &mut writer,
        &mut session,
        ValidatorMessage::Hello(make_hello(&config, &observation)),
    )?;

    let result = run_after_hello(&config, &observation, &mut reader, &mut session);
    match result {
        Ok(done) => send_guest_message(&mut writer, &mut session, ValidatorMessage::Done(done))?,
        Err(error) => {
            let _ = send_guest_message(
                &mut writer,
                &mut session,
                ValidatorMessage::Error(error.to_protocol_message()),
            );
        }
    }
    let _ = writer.flush();
    reboot(RebootMode::RB_POWER_OFF).map_err(|error| ValidatorError::syscall("poweroff", error))
}

pub fn emergency_poweroff() -> ! {
    let _ = reboot(RebootMode::RB_POWER_OFF);
    loop {
        nix::unistd::pause();
    }
}

fn run_after_hello(
    config: &ValidatorConfig,
    first_observation: &ValidatorObservation,
    control_reader: &mut File,
    session: &mut ValidatorSession,
) -> Result<ValidatorDone, ValidatorError> {
    let frame = FrameReader::new(control_reader)
        .read_frame()
        .map_err(|error| ValidatorError::protocol("receive-start", error))?;
    let message = decode_validator_message(&frame)
        .map_err(|error| ValidatorError::protocol("receive-start", error))?;
    session
        .accept(Direction::HostToGuest, &message, frame.header.sequence)
        .map_err(|error| ValidatorError::protocol("receive-start", error))?;
    let ValidatorMessage::Start(start) = message else {
        return Err(ValidatorError::contract(
            "receive-start",
            "expected VALIDATE_START",
        ));
    };
    let start = *start;
    let second_observation = observe_guest(config)?;
    if &second_observation != first_observation {
        return Err(ValidatorError::contract(
            "start-contract",
            "guest architecture, CPU, page-size, or memory changed during handshake",
        ));
    }
    verify_start(config, first_observation, &start)?;
    let evidence = validate_candidate(&start)?;
    Ok(ValidatorDone::from_evidence(&start, evidence))
}

fn verify_start(
    config: &ValidatorConfig,
    observation: &ValidatorObservation,
    start: &ValidatorStart,
) -> Result<(), ValidatorError> {
    start
        .validate()
        .map_err(|error| ValidatorError::protocol("start-contract", error))?;
    if observation.online_cpus != 1
        || observation.accepted_physmem_bytes != config.expected_physmem_bytes
        || start.expected_physmem_bytes != observation.accepted_physmem_bytes
    {
        return Err(ValidatorError::contract(
            "start-contract",
            "validation CPU or physical memory differs from measured guest state",
        ));
    }
    if start.expected_generation_marker.effective_platform.os != "linux"
        || start
            .expected_generation_marker
            .effective_platform
            .architecture
            != observation.oci_architecture
    {
        return Err(ValidatorError::contract(
            "start-contract",
            "generation platform differs from native validator architecture",
        ));
    }
    if start.root_layout != config.expected_root_layout
        || start.filesystem_contract != config.expected_filesystem_contract
        || start.manifest_schema != config.expected_manifest_schema
    {
        return Err(ValidatorError::contract(
            "start-contract",
            "root-layout, filesystem, or manifest schema differs from boot contract",
        ));
    }
    Ok(())
}

fn validate_candidate(start: &ValidatorStart) -> Result<ValidatorEvidence, ValidatorError> {
    require_block_device(CANDIDATE_DEVICE)?;
    require_empty_mountpoint(CANDIDATE_MOUNT)?;
    let block_device_read_only = read_exact_text("/sys/class/block/ubda/ro", 8)? == "1";
    if !block_device_read_only {
        return filesystem_error("candidate block device is not read-only");
    }
    let sectors = read_exact_text("/sys/class/block/ubda/size", 32)?
        .parse::<u64>()
        .map_err(|_| filesystem_failure("candidate sector count is malformed"))?;
    let filesystem_bytes = sectors
        .checked_mul(512)
        .ok_or_else(|| filesystem_failure("candidate byte size overflow"))?;
    if filesystem_bytes != start.expected_filesystem_bytes {
        return filesystem_error("candidate byte size differs from VALIDATE_START");
    }
    let before = inspect_ext4(CANDIDATE_DEVICE)?;
    reconcile_ext4(
        &before,
        &start.expected_filesystem_uuid,
        filesystem_bytes,
        start.expected_filesystem_bytes,
    )?;

    let mut candidate = MountedCandidate::mount()?;
    let mounted_read_only = statvfs(CANDIDATE_MOUNT)
        .map_err(|error| ValidatorError::syscall("mount-status", error))?
        .flags()
        .contains(FsFlags::ST_RDONLY);
    if !mounted_read_only {
        return filesystem_error("candidate mount is not read-only");
    }

    let marker_path = Path::new(CANDIDATE_MOUNT).join(".pocket-generation.cbor");
    let marker_bytes = read_bounded_regular(&marker_path, MARKER_LIMIT, "generation-marker")?;
    let marker_sha256 = hex_lower(&Sha256::digest(&marker_bytes));
    if marker_sha256 != start.expected_generation_marker_sha256 {
        return marker_error("generation marker digest differs from VALIDATE_START");
    }
    let marker: GenerationMarker = decode_payload(&marker_bytes).map_err(|error| {
        ValidatorError::protocol("generation-marker", error).reclassify(ErrorCode::ValidatorMarker)
    })?;
    marker.validate().map_err(|error| {
        ValidatorError::protocol("generation-marker", error).reclassify(ErrorCode::ValidatorMarker)
    })?;
    if marker != start.expected_generation_marker {
        return marker_error("generation marker fields differ from VALIDATE_START");
    }

    let rootfs = Path::new(CANDIDATE_MOUNT).join("rootfs");
    let rebuilt_account = rebuild_account_database(&rootfs)?;
    if rebuilt_account != start.expected_account_db {
        return account_error("rebuilt account database differs from persisted builder evidence");
    }

    let manifest = validate_manifest(Path::new(CANDIDATE_MOUNT), &start.manifest_limits)?;
    if manifest.sha256 != start.expected_manifest_sha256
        || manifest.entry_count != start.expected_manifest_entry_count
        || manifest.byte_count != start.expected_manifest_byte_count
    {
        return manifest_error("independent filesystem manifest differs from builder evidence");
    }

    candidate.unmount()?;
    let after = inspect_ext4(CANDIDATE_DEVICE)?;
    reconcile_ext4(
        &after,
        &start.expected_filesystem_uuid,
        filesystem_bytes,
        start.expected_filesystem_bytes,
    )?;
    if after != before {
        return filesystem_error("ext4 identity or clean state changed across validation mount");
    }
    Ok(ValidatorEvidence {
        manifest_sha256: manifest.sha256,
        manifest_entry_count: manifest.entry_count,
        manifest_byte_count: manifest.byte_count,
        generation_marker_sha256: marker_sha256,
        account_db_sha256: rebuilt_account.sha256,
        filesystem_uuid: after.uuid,
        filesystem_bytes,
        clean_before_mount: before.clean,
        block_device_read_only,
        mounted_read_only,
        unmounted: true,
        clean_after_unmount: after.clean,
    })
}

struct MountedCandidate {
    mounted: bool,
}

impl MountedCandidate {
    fn mount() -> Result<Self, ValidatorError> {
        let flags = MsFlags::MS_RDONLY
            | MsFlags::MS_NODEV
            | MsFlags::MS_NOSUID
            | MsFlags::MS_NOEXEC
            | MsFlags::MS_NOATIME
            | MsFlags::MS_NODIRATIME;
        mount(
            Some(CANDIDATE_DEVICE),
            CANDIDATE_MOUNT,
            Some("ext4"),
            flags,
            Some("ro,noload"),
        )
        .map_err(|error| {
            ValidatorError::syscall("mount-candidate", error).reclassify(ErrorCode::ValidatorMount)
        })?;
        Ok(Self { mounted: true })
    }

    fn unmount(&mut self) -> Result<(), ValidatorError> {
        umount2(CANDIDATE_MOUNT, MntFlags::UMOUNT_NOFOLLOW).map_err(|error| {
            ValidatorError::syscall("unmount-candidate", error)
                .reclassify(ErrorCode::ValidatorUnmount)
        })?;
        self.mounted = false;
        require_empty_mountpoint(CANDIDATE_MOUNT)
            .map_err(|error| error.reclassify(ErrorCode::ValidatorUnmount))
    }
}

impl Drop for MountedCandidate {
    fn drop(&mut self) {
        if self.mounted {
            let _ = umount2(CANDIDATE_MOUNT, MntFlags::UMOUNT_NOFOLLOW);
        }
    }
}

fn inspect_ext4(path: &str) -> Result<Ext4Observation, ValidatorError> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| ValidatorError::io("ext4-superblock", error))?;
    let mut bytes = [0_u8; EXT4_SUPERBLOCK_BYTES];
    file.read_exact_at(&mut bytes, EXT4_SUPERBLOCK_OFFSET)
        .map_err(|error| ValidatorError::io("ext4-superblock", error))?;
    parse_ext4_superblock(&bytes)
}

fn parse_ext4_superblock(
    bytes: &[u8; EXT4_SUPERBLOCK_BYTES],
) -> Result<Ext4Observation, ValidatorError> {
    let u16_at = |offset: usize| u16::from_le_bytes([bytes[offset], bytes[offset + 1]]);
    let u32_at = |offset: usize| {
        u32::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ])
    };
    if u16_at(0x38) != EXT4_MAGIC || u32_at(0x18) != 2 || u16_at(0x58) != 256 {
        return filesystem_error("candidate is not the contracted 4K/256-byte-inode ext4");
    }
    let state = u16_at(0x3a);
    if state != EXT4_VALID_FS || state & EXT4_ERROR_FS != 0 {
        return filesystem_error("candidate ext4 state is not exactly clean");
    }
    if u16_at(0x3c) != EXT4_ERRORS_CONTINUE {
        return filesystem_error("candidate ext4 error behavior differs from contract");
    }
    let feature_compat = u32_at(0x5c);
    let feature_incompat = u32_at(0x60);
    let feature_ro_compat = u32_at(0x64);
    if feature_compat != EXT4_FEATURE_COMPAT_CONTRACT
        || feature_incompat != EXT4_FEATURE_INCOMPAT_CONTRACT
        || feature_ro_compat != EXT4_FEATURE_RO_COMPAT_CONTRACT
    {
        return filesystem_error("candidate ext4 feature masks differ from contract");
    }
    if feature_incompat & EXT4_FEATURE_INCOMPAT_RECOVER != 0 {
        return filesystem_error("candidate ext4 requires journal recovery");
    }
    let last_orphan = u32_at(0xe8);
    if last_orphan != 0 {
        return filesystem_error("candidate ext4 has a pending orphan inode");
    }
    let default_mount_opts = u32_at(0x100);
    if default_mount_opts != EXT4_DEFAULT_MOUNT_OPTS_CONTRACT {
        return filesystem_error("candidate ext4 default mount options differ from contract");
    }
    if bytes[0x78..0x88] != EXT4_VOLUME_LABEL_CONTRACT {
        return filesystem_error("candidate ext4 volume label differs from contract");
    }
    let blocks = u64::from(u32_at(0x04)) | (u64::from(u32_at(0x150)) << 32);
    if blocks == 0 {
        return filesystem_error("candidate ext4 declares zero logical blocks");
    }
    let logical_bytes = blocks
        .checked_mul(4096)
        .ok_or_else(|| filesystem_failure("candidate ext4 logical byte size overflows"))?;
    Ok(Ext4Observation {
        uuid: format_uuid(
            bytes[0x68..0x78]
                .try_into()
                .map_err(|_| filesystem_failure("ext4 UUID field is malformed"))?,
        ),
        clean: true,
        logical_bytes,
        feature_compat,
        feature_incompat,
        feature_ro_compat,
        default_mount_opts,
    })
}

fn reconcile_ext4(
    observation: &Ext4Observation,
    expected_uuid: &str,
    sysfs_device_bytes: u64,
    expected_bytes: u64,
) -> Result<(), ValidatorError> {
    if observation.uuid != expected_uuid {
        return filesystem_error("candidate ext4 UUID differs from VALIDATE_START");
    }
    if observation.logical_bytes != sysfs_device_bytes
        || observation.logical_bytes != expected_bytes
    {
        return filesystem_error(
            "candidate ext4 logical size differs from the device or VALIDATE_START",
        );
    }
    Ok(())
}

fn format_uuid(bytes: [u8; 16]) -> String {
    format!(
        "{}-{}-{}-{}-{}",
        hex_lower(&bytes[0..4]),
        hex_lower(&bytes[4..6]),
        hex_lower(&bytes[6..8]),
        hex_lower(&bytes[8..10]),
        hex_lower(&bytes[10..16])
    )
}

fn make_hello(config: &ValidatorConfig, observation: &ValidatorObservation) -> ValidatorHello {
    ValidatorHello {
        guest_contract_id: config.guest_contract_id.clone(),
        init_build_id: config.init_build_id.clone(),
        kernel_build_id: config.kernel_build_id.clone(),
        host_elf_machine: observation.elf_machine,
        guest_uts_machine: observation.uts_machine.clone(),
        guest_page_size: observation.page_size,
        cpu_state_hwcap_policy: config.cpu_state_hwcap_policy.clone(),
        online_cpus: observation.online_cpus,
        accepted_physmem_bytes: observation.accepted_physmem_bytes,
        features: VALIDATOR_GUEST_FEATURES
            .iter()
            .map(|feature| (*feature).to_owned())
            .collect(),
    }
}

fn observe_guest(config: &ValidatorConfig) -> Result<ValidatorObservation, ValidatorError> {
    let uts = uname().map_err(|error| ValidatorError::syscall("observe-guest", error))?;
    let uts_machine = uts
        .machine()
        .to_str()
        .ok_or_else(|| ValidatorError::contract("observe-guest", "UTS machine is not UTF-8"))?
        .to_owned();
    let (oci_architecture, elf_machine) = match uts_machine.as_str() {
        "x86_64" => ("amd64", 62),
        "aarch64" => ("arm64", 183),
        _ => {
            return Err(ValidatorError::contract(
                "observe-guest",
                format!("unsupported UTS machine {uts_machine:?}"),
            ));
        }
    };
    if oci_architecture != config.expected_oci_architecture {
        return Err(ValidatorError::contract(
            "observe-guest",
            "observed architecture differs from boot contract",
        ));
    }
    let page_size = u32::try_from(required_sysconf(SysconfVar::PAGE_SIZE, "page size")?)
        .map_err(|_| ValidatorError::contract("observe-guest", "page size does not fit u32"))?;
    if page_size != config.expected_page_size {
        return Err(ValidatorError::contract(
            "observe-guest",
            "observed page size differs from boot contract",
        ));
    }
    let online_cpus = u16::try_from(required_sysconf(
        SysconfVar::_NPROCESSORS_ONLN,
        "online CPU count",
    )?)
    .map_err(|_| ValidatorError::contract("observe-guest", "CPU count does not fit u16"))?;
    if online_cpus != 1 {
        return Err(ValidatorError::contract(
            "observe-guest",
            "validator must observe exactly one online CPU",
        ));
    }
    let accepted = read_bounded_text("/proc/uml_physmem_bytes", PHYSMEM_LIMIT, "observe-guest")?;
    let accepted_physmem_bytes = accepted.trim().parse::<u64>().map_err(|_| {
        ValidatorError::contract(
            "observe-guest",
            "/proc/uml_physmem_bytes is not an unsigned byte count",
        )
    })?;
    if accepted_physmem_bytes != config.expected_physmem_bytes
        || !accepted_physmem_bytes.is_multiple_of(u64::from(page_size))
    {
        return Err(ValidatorError::contract(
            "observe-guest",
            "UML accepted memory differs from validation boot contract",
        ));
    }
    Ok(ValidatorObservation {
        uts_machine,
        oci_architecture: oci_architecture.to_owned(),
        elf_machine,
        page_size,
        online_cpus,
        accepted_physmem_bytes,
    })
}

fn required_sysconf(variable: SysconfVar, name: &str) -> Result<i64, ValidatorError> {
    sysconf(variable)
        .map_err(|error| ValidatorError::syscall("observe-guest", error))?
        .ok_or_else(|| ValidatorError::contract("observe-guest", format!("{name} unavailable")))
}

fn send_guest_message(
    writer: &mut FrameWriter<File>,
    session: &mut ValidatorSession,
    message: ValidatorMessage,
) -> Result<(), ValidatorError> {
    let payload = message
        .encode_payload()
        .map_err(|error| ValidatorError::protocol("send-control", error))?;
    let sequence = writer.next_sequence();
    session
        .accept(Direction::GuestToHost, &message, sequence)
        .map_err(|error| ValidatorError::protocol("send-control", error))?;
    let written = writer
        .write_frame(message.kind(), &payload)
        .map_err(|error| ValidatorError::protocol("send-control", error))?;
    if written != sequence {
        return Err(ValidatorError::contract(
            "send-control",
            "frame writer sequence changed unexpectedly",
        ));
    }
    writer
        .flush()
        .map_err(|error| ValidatorError::protocol("send-control", error))
}

fn mount_early_filesystems() -> Result<(), ValidatorError> {
    for path in ["/proc", "/sys", "/dev", "/dev/pts", CANDIDATE_MOUNT] {
        fs::create_dir_all(path).map_err(|error| ValidatorError::io("early-mounts", error))?;
    }
    let restrictive = MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC;
    mount(
        Some("proc"),
        "/proc",
        Some("proc"),
        restrictive,
        None::<&str>,
    )
    .map_err(|error| ValidatorError::syscall("early-mounts", error))?;
    mount(
        Some("sysfs"),
        "/sys",
        Some("sysfs"),
        restrictive,
        None::<&str>,
    )
    .map_err(|error| ValidatorError::syscall("early-mounts", error))?;
    mount(
        Some("devtmpfs"),
        "/dev",
        Some("devtmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
        Some("mode=0755"),
    )
    .map_err(|error| ValidatorError::syscall("early-mounts", error))?;
    fs::create_dir_all("/dev/pts").map_err(|error| ValidatorError::io("early-mounts", error))?;
    mount(
        Some("devpts"),
        "/dev/pts",
        Some("devpts"),
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
        Some("mode=0620,ptmxmode=0666"),
    )
    .map_err(|error| ValidatorError::syscall("early-mounts", error))
}

fn require_block_device(path: &str) -> Result<(), ValidatorError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| ValidatorError::io("device-contract", error))?;
    if !metadata.file_type().is_block_device() {
        return filesystem_error(format!("{path} is not a block device"));
    }
    Ok(())
}

fn require_empty_mountpoint(path: &str) -> Result<(), ValidatorError> {
    let mut entries =
        fs::read_dir(path).map_err(|error| ValidatorError::io("mount-contract", error))?;
    if entries
        .next()
        .transpose()
        .map_err(|error| ValidatorError::io("mount-contract", error))?
        .is_some()
    {
        return Err(ValidatorError::contract(
            "mount-contract",
            format!("{path} is not empty"),
        ));
    }
    Ok(())
}

fn open_raw_control(path: &str) -> Result<File, ValidatorError> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOCTTY)
        .open(path)
        .map_err(|error| ValidatorError::io("control", error))?;
    let mut attributes =
        tcgetattr(&file).map_err(|error| ValidatorError::syscall("control", error))?;
    cfmakeraw(&mut attributes);
    tcsetattr(&file, SetArg::TCSANOW, &attributes)
        .map_err(|error| ValidatorError::syscall("control", error))?;
    Ok(file)
}

fn read_bounded_regular(
    path: &Path,
    maximum: usize,
    stage: &'static str,
) -> Result<Vec<u8>, ValidatorError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| ValidatorError::io(stage, error))?;
    if !metadata.is_file() || metadata.len() > maximum as u64 {
        return Err(ValidatorError::failure(
            stage,
            ErrorCode::ValidatorMarker,
            None,
            "file is not a bounded regular file",
        ));
    }
    let mut bytes = Vec::new();
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| ValidatorError::io(stage, error))?
        .take((maximum + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| ValidatorError::io(stage, error))?;
    if bytes.len() > maximum || bytes.len() as u64 != metadata.len() {
        return marker_error("generation marker changed while reading");
    }
    Ok(bytes)
}

fn read_bounded_text(
    path: &str,
    maximum: usize,
    stage: &'static str,
) -> Result<String, ValidatorError> {
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|error| ValidatorError::io(stage, error))?
        .take((maximum + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| ValidatorError::io(stage, error))?;
    if bytes.len() > maximum {
        return Err(ValidatorError::contract(
            stage,
            "text file exceeds hard cap",
        ));
    }
    String::from_utf8(bytes).map_err(|_| ValidatorError::contract(stage, "text is not UTF-8"))
}

fn read_exact_text(path: &str, maximum: usize) -> Result<String, ValidatorError> {
    Ok(read_bounded_text(path, maximum, "device-contract")?
        .trim()
        .to_owned())
}

fn block_sigpipe() -> Result<(), ValidatorError> {
    let mut signals = SigSet::empty();
    signals.add(Signal::SIGPIPE);
    pthread_sigmask(SigmaskHow::SIG_BLOCK, Some(&signals), None)
        .map_err(|error| ValidatorError::syscall("early-boot", error))
}

fn filesystem_error<T>(diagnostic: impl Into<String>) -> Result<T, ValidatorError> {
    Err(filesystem_failure(diagnostic))
}

fn filesystem_failure(diagnostic: impl Into<String>) -> ValidatorError {
    ValidatorError::failure(
        "filesystem",
        ErrorCode::ValidatorFilesystem,
        None,
        diagnostic,
    )
}

fn marker_error<T>(diagnostic: impl Into<String>) -> Result<T, ValidatorError> {
    Err(ValidatorError::failure(
        "generation-marker",
        ErrorCode::ValidatorMarker,
        None,
        diagnostic,
    ))
}

fn account_error<T>(diagnostic: impl Into<String>) -> Result<T, ValidatorError> {
    Err(ValidatorError::failure(
        "account-database",
        ErrorCode::ValidatorAccount,
        None,
        diagnostic,
    ))
}

fn manifest_error<T>(diagnostic: impl Into<String>) -> Result<T, ValidatorError> {
    Err(ValidatorError::failure(
        "manifest",
        ErrorCode::ValidatorManifest,
        None,
        diagnostic,
    ))
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
    use super::{
        EXT4_DEFAULT_MOUNT_OPTS_CONTRACT, EXT4_ERROR_FS, EXT4_ERRORS_CONTINUE,
        EXT4_FEATURE_COMPAT_CONTRACT, EXT4_FEATURE_INCOMPAT_CONTRACT,
        EXT4_FEATURE_INCOMPAT_RECOVER, EXT4_FEATURE_RO_COMPAT_CONTRACT, EXT4_MAGIC,
        EXT4_SUPERBLOCK_BYTES, EXT4_VALID_FS, EXT4_VOLUME_LABEL_CONTRACT, parse_ext4_superblock,
        reconcile_ext4,
    };

    const UUID: &str = "01010101-0101-0101-0101-010101010101";

    fn valid_superblock() -> [u8; EXT4_SUPERBLOCK_BYTES] {
        let mut superblock = [0_u8; 1024];
        superblock[0x04..0x08].copy_from_slice(&1_u32.to_le_bytes());
        superblock[0x18..0x1c].copy_from_slice(&2_u32.to_le_bytes());
        superblock[0x38..0x3a].copy_from_slice(&EXT4_MAGIC.to_le_bytes());
        superblock[0x3a..0x3c].copy_from_slice(&EXT4_VALID_FS.to_le_bytes());
        superblock[0x3c..0x3e].copy_from_slice(&EXT4_ERRORS_CONTINUE.to_le_bytes());
        superblock[0x58..0x5a].copy_from_slice(&256_u16.to_le_bytes());
        superblock[0x5c..0x60].copy_from_slice(&EXT4_FEATURE_COMPAT_CONTRACT.to_le_bytes());
        superblock[0x60..0x64].copy_from_slice(&EXT4_FEATURE_INCOMPAT_CONTRACT.to_le_bytes());
        superblock[0x64..0x68].copy_from_slice(&EXT4_FEATURE_RO_COMPAT_CONTRACT.to_le_bytes());
        superblock[0x68..0x78].copy_from_slice(&[1; 16]);
        superblock[0x78..0x88].copy_from_slice(&EXT4_VOLUME_LABEL_CONTRACT);
        superblock[0x100..0x104].copy_from_slice(&EXT4_DEFAULT_MOUNT_OPTS_CONTRACT.to_le_bytes());
        superblock
    }

    #[test]
    fn parses_exact_ext4_contract_and_64_bit_logical_size() {
        let mut superblock = valid_superblock();
        superblock[0x04..0x08].copy_from_slice(&3_u32.to_le_bytes());
        superblock[0x150..0x154].copy_from_slice(&1_u32.to_le_bytes());
        let observation = parse_ext4_superblock(&superblock).expect("valid superblock");
        assert!(observation.clean);
        assert_eq!(observation.uuid, UUID);
        assert_eq!(observation.logical_bytes, ((1_u64 << 32) | 3) * 4096);
    }

    #[test]
    fn rejects_error_and_recovery_states() {
        let mut superblock = valid_superblock();
        superblock[0x3a..0x3c].copy_from_slice(&(EXT4_VALID_FS | EXT4_ERROR_FS).to_le_bytes());
        assert!(parse_ext4_superblock(&superblock).is_err());

        let mut superblock = valid_superblock();
        superblock[0x60..0x64].copy_from_slice(
            &(EXT4_FEATURE_INCOMPAT_CONTRACT | EXT4_FEATURE_INCOMPAT_RECOVER).to_le_bytes(),
        );
        assert!(parse_ext4_superblock(&superblock).is_err());
    }

    #[test]
    fn rejects_zero_state_zero_blocks_and_pending_orphan() {
        let mut superblock = valid_superblock();
        superblock[0x3a..0x3c].copy_from_slice(&0_u16.to_le_bytes());
        assert!(parse_ext4_superblock(&superblock).is_err());

        let mut superblock = valid_superblock();
        superblock[0x04..0x08].copy_from_slice(&0_u32.to_le_bytes());
        assert!(parse_ext4_superblock(&superblock).is_err());

        let mut superblock = valid_superblock();
        superblock[0xe8..0xec].copy_from_slice(&42_u32.to_le_bytes());
        assert!(parse_ext4_superblock(&superblock).is_err());
    }

    #[test]
    fn rejects_wrong_feature_masks_mount_options_and_label() {
        for offset in [0x5c, 0x60, 0x64] {
            let mut superblock = valid_superblock();
            superblock[offset] ^= 0x01;
            assert!(
                parse_ext4_superblock(&superblock).is_err(),
                "accepted changed feature mask at {offset:#x}"
            );
        }

        let mut superblock = valid_superblock();
        superblock[0x100] ^= 0x01;
        assert!(parse_ext4_superblock(&superblock).is_err());

        let mut superblock = valid_superblock();
        superblock[0x78] = b'P';
        assert!(parse_ext4_superblock(&superblock).is_err());
    }

    #[test]
    fn reconciles_uuid_and_logical_size_with_both_sources() {
        let observation = parse_ext4_superblock(&valid_superblock()).expect("valid superblock");
        reconcile_ext4(&observation, UUID, 4096, 4096).expect("matching evidence");
        assert!(
            reconcile_ext4(
                &observation,
                "00000000-0000-0000-0000-000000000000",
                4096,
                4096
            )
            .is_err()
        );
        assert!(reconcile_ext4(&observation, UUID, 8192, 4096).is_err());
        assert!(reconcile_ext4(&observation, UUID, 4096, 8192).is_err());
    }
}
