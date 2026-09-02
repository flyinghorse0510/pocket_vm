use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs::File,
    io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
    os::unix::{net::UnixStream, process::CommandExt},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::Duration,
};

use nix::{fcntl::OFlag, libc, unistd::pipe2};
use pocket_core::{ValidatedCpuRequest, ValidatedMemory};

use crate::{RuntimeError, VerifiedProfile};

pub(crate) const LEASE_FD: RawFd = 8;
pub(crate) const LIVENESS_FD: RawFd = 9;
pub(crate) const CONTROL_FD: RawFd = 10;
pub(crate) const STDOUT_FD: RawFd = 11;
pub(crate) const STDERR_FD: RawFd = 12;
pub(crate) const STDIN_FD: RawFd = 13;
pub(crate) const CONSOLE_FD: RawFd = 14;
/// The first inherited descriptor an extra serial line may use. The runtime's
/// own five channels occupy 10 through 14.
pub(crate) const EXTRA_CONSOLE_FD_BASE: RawFd = 15;
const RELOCATED_FD_MINIMUM: RawFd = 64;

#[derive(Debug)]
pub(crate) struct RunPaths {
    pub uml_dir: PathBuf,
    pub tmp_dir: PathBuf,
    pub cow: PathBuf,
    /// Where the network helper listens and the guest's vector device
    /// connects. Inside the run directory, so it is removed with it.
    pub network_socket: PathBuf,
    pub umid: String,
}

#[derive(Debug)]
pub(crate) struct LaunchInputs<'a> {
    pub profile: &'a VerifiedProfile,
    /// Extra guest serial lines to allocate and publish.
    pub extra_consoles: u8,
    pub paths: &'a RunPaths,
    pub base: &'a Path,
    pub cpus: ValidatedCpuRequest,
    pub memory: ValidatedMemory,
    pub guard_term_timeout: Duration,
    /// Capture the whole guest console instead of the `quiet` subset. A caller
    /// that asked for the console transcript is diagnosing something, and a
    /// console filtered to `pr_err` and above hides exactly the lockdep and
    /// RCU reports such a caller is looking for.
    pub verbose_console: bool,
    /// Start the profile's network helper and give the guest a vector device
    /// bound to it. `false` leaves the guest with loopback only.
    pub network: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LaunchPlan {
    pub guard_program: PathBuf,
    pub guard_arguments: Vec<OsString>,
    pub uml_command: Vec<OsString>,
    pub environment: BTreeMap<OsString, OsString>,
    /// How many extra serial lines the command line declares. The plan and the
    /// descriptors handed to the guard have to agree, so the count travels
    /// with the command that names them.
    pub extra_consoles: u8,
}

pub(crate) struct HostChannels {
    pub control: UnixStream,
    pub stdin: UnixStream,
    pub stdout: UnixStream,
    pub stderr: UnixStream,
    pub console: UnixStream,
    /// Masters of the pseudo-terminals backing any extra serial lines.
    ///
    /// Never read: they exist to be held. The guard has its own duplicates at
    /// the descriptors its command line names, and closing these would take
    /// the operator's attachable device away with them.
    #[allow(dead_code)]
    pub extra_consoles: Vec<nix::pty::PtyMaster>,
}

/// One extra serial line: the host keeps the master, and the slave is the path
/// an operator attaches to, exactly as `-serial pty` does.
pub(crate) struct ExtraConsole {
    pub master: nix::pty::PtyMaster,
    pub slave_path: PathBuf,
}

/// Allocate the pseudo-terminals backing a run's extra serial lines.
fn allocate_extra_consoles(count: u8) -> Result<Vec<ExtraConsole>, RuntimeError> {
    let mut consoles = Vec::with_capacity(usize::from(count));
    for index in 0..count {
        let describe = |what: &str, error: nix::errno::Errno| {
            RuntimeError::invalid(
                "extra_console",
                format!("could not {what} for serial line {index}: {error}"),
            )
        };
        let master =
            nix::pty::posix_openpt(nix::fcntl::OFlag::O_RDWR | nix::fcntl::OFlag::O_NOCTTY)
                .map_err(|error| describe("allocate a pseudo-terminal", error))?;
        nix::pty::grantpt(&master).map_err(|error| describe("grant a pseudo-terminal", error))?;
        nix::pty::unlockpt(&master).map_err(|error| describe("unlock a pseudo-terminal", error))?;
        // The slave path is what an operator opens. Nothing here holds the
        // slave open: an unopened line should read as unattached, and the
        // master keeps the path alive regardless.
        let slave_path = nix::pty::ptsname_r(&master)
            .map(PathBuf::from)
            .map_err(|error| describe("name a pseudo-terminal", error))?;
        consoles.push(ExtraConsole { master, slave_path });
    }
    Ok(consoles)
}

struct ChildDescriptor {
    source: OwnedFd,
    target: RawFd,
}

pub(crate) struct GuardLaunch {
    pub child: Child,
    pub liveness: OwnedFd,
    pub channels: HostChannels,
    /// Where an operator attaches for each extra serial line, in line order.
    pub extra_console_paths: Vec<PathBuf>,
}

pub(crate) fn build_launch_plan(inputs: &LaunchInputs<'_>) -> Result<LaunchPlan, RuntimeError> {
    let manifest = inputs.profile.manifest();
    let launch = &manifest.launch;
    let path_text = |field: &'static str, path: &Path| -> Result<String, RuntimeError> {
        path.to_str()
            .map(str::to_owned)
            .ok_or_else(|| RuntimeError::invalid(field, "path is not UTF-8"))
    };
    let cow = path_text("cow", &inputs.paths.cow)?;
    let base = path_text("base", inputs.base)?;
    let uml_dir = path_text("uml_dir", &inputs.paths.uml_dir)?;
    let initramfs = path_text("initramfs", inputs.profile.initramfs_path())?;
    if cow.len() > usize::from(launch.max_ubd_path_bytes)
        || base.len() > usize::from(launch.max_ubd_path_bytes)
    {
        return Err(RuntimeError::invalid(
            "ubd0",
            "COW or backing path exceeds the profile limit",
        ));
    }
    if inputs.paths.umid.len() > usize::from(launch.max_umid_bytes) {
        return Err(RuntimeError::invalid(
            "umid",
            "generated UML identifier exceeds the profile limit",
        ));
    }
    if uml_dir.len() > usize::from(launch.max_unix_path_bytes) {
        return Err(RuntimeError::invalid(
            "uml_dir",
            "runtime UML directory exceeds the profile Unix-path limit",
        ));
    }
    let network_socket = path_text("network_socket", &inputs.paths.network_socket)?;
    if inputs.network && network_socket.len() > usize::from(launch.max_unix_path_bytes) {
        return Err(RuntimeError::invalid(
            "network_socket",
            "network socket path exceeds the profile Unix-path limit",
        ));
    }

    let mut uml_command = vec![inputs.profile.uml_path().as_os_str().to_owned()];
    uml_command.push(format!("mem={}", inputs.memory.uml_value()).into());
    if let Some(cpus) = inputs.cpus.kernel_ncpus() {
        uml_command.push(format!("ncpus={cpus}").into());
    }
    uml_command.extend([
        OsString::from("seccomp=on"),
        format!("umid={}", inputs.paths.umid).into(),
        format!("uml_dir={uml_dir}").into(),
        format!("initrd={initramfs}").into(),
        OsString::from("rdinit=/init"),
        OsString::from("rootfstype=ramfs"),
        format!("ubd0={cow},{base}").into(),
        OsString::from("con=null"),
        OsString::from("con0=fd:14,fd:14"),
        OsString::from("ssl=null"),
        OsString::from("ssl0=fd:10,fd:10"),
        OsString::from("ssl1=fd:13,fd:13"),
        OsString::from("ssl2=fd:11,fd:11"),
        OsString::from("ssl3=fd:12,fd:12"),
    ]);
    for index in 0..inputs.extra_consoles {
        let line = u32::from(index) + 4;
        let fd = EXTRA_CONSOLE_FD_BASE + RawFd::from(index);
        uml_command.push(format!("ssl{line}=fd:{fd},fd:{fd}").into());
    }
    uml_command.extend([
        format!(
            "pocket.guest_contract_id={}",
            manifest.hello.guest_contract_id
        )
        .into(),
        format!("pocket.init_build_id={}", manifest.hello.init_build_id).into(),
        format!("pocket.kernel_build_id={}", manifest.hello.kernel_build_id).into(),
        format!("pocket.expected_cpus={}", inputs.cpus.requested()).into(),
        format!("pocket.expected_memory_bytes={}", inputs.memory.bytes()).into(),
        OsString::from("pocket.expected_architecture=amd64"),
        format!(
            "pocket.cpu_state_hwcap_policy={}",
            manifest.contracts.cpu_state_hwcap_policy
        )
        .into(),
        format!(
            "pocket.guest_capability_policy={}",
            manifest.contracts.guest_capability_policy
        )
        .into(),
        format!("pocket.root_layout={}", manifest.contracts.root_layout).into(),
        format!(
            "pocket.filesystem_contract={}",
            manifest.contracts.filesystem
        )
        .into(),
        if inputs.verbose_console {
            OsString::from("loglevel=7")
        } else {
            OsString::from("quiet")
        },
        OsString::from("noreboot"),
        OsString::from("panic=1"),
    ]);
    if inputs.network {
        // bess is the one vector transport that needs no host privilege: it is
        // an AF_UNIX socket to the helper below, not a TUN device or a raw
        // packet socket.
        uml_command
            .push(format!("vec0:transport=bess,dst={network_socket},depth=128,gro=1").into());
    }

    let timeout_ms = u64::try_from(inputs.guard_term_timeout.as_millis())
        .map_err(|_| RuntimeError::invalid("guard_term_timeout", "milliseconds do not fit u64"))?;
    let supervisor_pid = std::process::id();
    let mut guard_arguments = vec![
        OsString::from("--supervisor-pid"),
        supervisor_pid.to_string().into(),
        OsString::from("--liveness-fd"),
        LIVENESS_FD.to_string().into(),
        OsString::from("--lease-fd"),
        LEASE_FD.to_string().into(),
    ];
    for fd in [CONTROL_FD, STDOUT_FD, STDERR_FD, STDIN_FD, CONSOLE_FD] {
        guard_arguments.push(OsString::from("--inherit-fd"));
        guard_arguments.push(fd.to_string().into());
    }
    // Every extra serial line's descriptor has to be declared too: the guard
    // closes what it was not told to keep, so a line the command line names
    // but the guard has not been given would leave the guest with a device
    // that reads end-of-file forever.
    for index in 0..inputs.extra_consoles {
        guard_arguments.push(OsString::from("--inherit-fd"));
        let fd = EXTRA_CONSOLE_FD_BASE + RawFd::from(index);
        guard_arguments.push(fd.to_string().into());
    }
    if inputs.network {
        // The guard starts and stops it, so a SIGKILLed caller cannot leave a
        // helper holding the run's socket open.
        for argument in [
            inputs.profile.network_helper_path().as_os_str().to_owned(),
            OsString::from("--target-type=bess"),
            OsString::from(&network_socket),
        ] {
            guard_arguments.push(OsString::from("--network-helper-arg"));
            guard_arguments.push(argument);
        }
    }
    guard_arguments.extend([
        OsString::from("--term-timeout-ms"),
        timeout_ms.to_string().into(),
        OsString::from("--uml-personality"),
        OsString::from("--"),
    ]);
    guard_arguments.extend(uml_command.iter().cloned());

    let mut environment = BTreeMap::new();
    environment.insert(OsString::from("HOME"), OsString::from("/"));
    environment.insert(OsString::from("LANG"), OsString::from("C"));
    environment.insert(OsString::from("LC_ALL"), OsString::from("C"));
    environment.insert(OsString::from("PATH"), OsString::from("/usr/bin:/bin"));
    environment.insert(OsString::from("TZ"), OsString::from("UTC0"));
    environment.insert(
        OsString::from("TMPDIR"),
        inputs.paths.tmp_dir.as_os_str().to_owned(),
    );
    environment.insert(
        OsString::from("TMP"),
        inputs.paths.tmp_dir.as_os_str().to_owned(),
    );
    environment.insert(
        OsString::from("TEMP"),
        inputs.paths.tmp_dir.as_os_str().to_owned(),
    );

    Ok(LaunchPlan {
        extra_consoles: inputs.extra_consoles,
        guard_program: inputs.profile.guard_path().to_path_buf(),
        guard_arguments,
        uml_command,
        environment,
    })
}

pub(crate) fn spawn_guard(plan: &LaunchPlan, lease: &File) -> Result<GuardLaunch, RuntimeError> {
    let (liveness_read, liveness_write) = pipe2(OFlag::O_CLOEXEC).map_err(|errno| {
        RuntimeError::io(
            "create liveness pipe",
            Path::new("<liveness-pipe>"),
            io::Error::from_raw_os_error(errno as i32),
        )
    })?;
    let (control_host, control_guest) = socketpair("control")?;
    let (stdin_host, stdin_guest) = socketpair("stdin")?;
    let (stdout_host, stdout_guest) = socketpair("stdout")?;
    let (stderr_host, stderr_guest) = socketpair("stderr")?;
    let (console_host, console_guest) = socketpair("console")?;
    let extra = allocate_extra_consoles(plan.extra_consoles)?;

    let mut descriptors = vec![
        ChildDescriptor {
            source: relocate(lease.as_raw_fd(), "lease")?,
            target: LEASE_FD,
        },
        ChildDescriptor {
            source: relocate(liveness_read.as_raw_fd(), "liveness")?,
            target: LIVENESS_FD,
        },
        ChildDescriptor {
            source: relocate(control_guest.as_raw_fd(), "control")?,
            target: CONTROL_FD,
        },
        ChildDescriptor {
            source: relocate(stdout_guest.as_raw_fd(), "stdout")?,
            target: STDOUT_FD,
        },
        ChildDescriptor {
            source: relocate(stderr_guest.as_raw_fd(), "stderr")?,
            target: STDERR_FD,
        },
        ChildDescriptor {
            source: relocate(stdin_guest.as_raw_fd(), "stdin")?,
            target: STDIN_FD,
        },
        ChildDescriptor {
            source: relocate(console_guest.as_raw_fd(), "console")?,
            target: CONSOLE_FD,
        },
    ];

    // Each extra line's master is handed to the guard at the descriptor its
    // command line names, and its slave path is reported so an operator can
    // attach. The masters are kept open for the run: closing one would take
    // the attachable device away with it.
    let mut extra_masters = Vec::with_capacity(extra.len());
    let mut extra_paths = Vec::with_capacity(extra.len());
    for (index, console) in extra.into_iter().enumerate() {
        let target = EXTRA_CONSOLE_FD_BASE + RawFd::try_from(index).unwrap_or(RawFd::MAX);
        descriptors.push(ChildDescriptor {
            source: relocate(console.master.as_raw_fd(), "extra-console")?,
            target,
        });
        extra_paths.push(console.slave_path);
        extra_masters.push(console.master);
    }
    let mappings: Vec<(RawFd, RawFd)> = descriptors
        .iter()
        .map(|descriptor| (descriptor.source.as_raw_fd(), descriptor.target))
        .collect();
    // SAFETY: getpid has no preconditions and does not dereference pointers.
    let expected_parent = unsafe { libc::getpid() };

    let mut command = Command::new(&plan.guard_program);
    command
        .args(&plan.guard_arguments)
        .env_clear()
        .envs(&plan.environment)
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // SAFETY: the closure performs only scalar libc syscalls and constructs no
    // state shared with another thread. Source descriptors were relocated
    // above the fixed target range and all carry CLOEXEC.
    unsafe {
        command.pre_exec(move || {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) == -1 {
                return Err(io::Error::last_os_error());
            }
            if libc::getppid() != expected_parent {
                return Err(io::Error::from_raw_os_error(libc::ESRCH));
            }
            for (source, target) in &mappings {
                if libc::dup2(*source, *target) == -1 {
                    return Err(io::Error::last_os_error());
                }
            }
            libc::umask(0o077);
            Ok(())
        });
    }
    let child = command.spawn().map_err(|source| RuntimeError::GuardSpawn {
        program: plan.guard_program.clone(),
        source,
    })?;
    drop(descriptors);
    drop(liveness_read);
    drop(control_guest);
    drop(stdin_guest);
    drop(stdout_guest);
    drop(stderr_guest);
    drop(console_guest);

    Ok(GuardLaunch {
        child,
        liveness: liveness_write,
        extra_console_paths: extra_paths,
        channels: HostChannels {
            extra_consoles: extra_masters,
            control: control_host,
            stdin: stdin_host,
            stdout: stdout_host,
            stderr: stderr_host,
            console: console_host,
        },
    })
}

fn socketpair(role: &'static str) -> Result<(UnixStream, UnixStream), RuntimeError> {
    UnixStream::pair().map_err(|error| {
        RuntimeError::io(
            "create Unix socketpair",
            PathBuf::from(format!("<{role}-socketpair>")),
            error,
        )
    })
}

fn relocate(fd: RawFd, role: &'static str) -> Result<OwnedFd, RuntimeError> {
    // SAFETY: `fd` is borrowed and valid for the duration of this call. The
    // returned descriptor is uniquely owned and wrapped exactly once.
    let relocated = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, RELOCATED_FD_MINIMUM) };
    if relocated == -1 {
        return Err(RuntimeError::io(
            "relocate inherited descriptor",
            PathBuf::from(format!("<{role}-fd>")),
            io::Error::last_os_error(),
        ));
    }
    // SAFETY: F_DUPFD_CLOEXEC returned a new descriptor owned by this process.
    Ok(unsafe { OwnedFd::from_raw_fd(relocated) })
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        ffi::{OsStr, OsString},
        fs,
        io::Read,
        os::unix::fs::PermissionsExt,
        time::Duration,
    };

    use pocket_core::{ManagedUmlPath, ParsedMemory};
    use tempfile::tempdir;

    use crate::manifest::synthetic_profile;

    use super::{
        CONSOLE_FD, CONTROL_FD, LaunchInputs, LaunchPlan, RunPaths, STDERR_FD, STDIN_FD, STDOUT_FD,
        build_launch_plan, spawn_guard,
    };

    #[test]
    fn protocol_descriptor_numbers_are_stable_and_distinct() {
        let values = [CONTROL_FD, STDOUT_FD, STDERR_FD, STDIN_FD, CONSOLE_FD];
        assert_eq!(values, [10, 11, 12, 13, 14]);
        let mut sorted = values.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), values.len());
        assert_ne!(OsStr::new("--"), OsStr::new("sh"));
    }

    #[test]
    fn exact_smp_launch_pairs_uml_and_guest_contract_arguments_without_a_shell() {
        let temporary = tempdir().expect("tempdir");
        let root_path = temporary.path().join("bundle");
        fs::create_dir(&root_path).expect("bundle");
        let root = ManagedUmlPath::new(&root_path).expect("managed root");
        let profile = synthetic_profile(root, true);
        let run = temporary
            .path()
            .join("runtime/run-00112233445566778899aabbccddeeff");
        let paths = RunPaths {
            uml_dir: run.join("uml"),
            tmp_dir: run.join("tmp"),
            cow: run.join("root.cow"),
            network_socket: run.join("net"),
            umid: "run-00112233445566778899aabbccddeeff".to_owned(),
        };
        let cpus = profile
            .cpu_profile()
            .validate_request(4)
            .expect("CPU request");
        let requested_memory = 512 * 1024 * 1024;
        let memory = profile
            .memory_policy()
            .validate(ParsedMemory::from_bytes(requested_memory).expect("memory"))
            .expect("memory request");
        let plan = build_launch_plan(&LaunchInputs {
            profile: &profile,
            extra_consoles: 0,
            paths: &paths,
            base: &temporary.path().join("store/generation/base.ext4"),
            cpus,
            memory,
            guard_term_timeout: Duration::from_secs(5),
            verbose_console: false,
            network: false,
        })
        .expect("launch plan");
        let arguments: Vec<&str> = plan
            .guard_arguments
            .iter()
            .map(|argument| argument.to_str().expect("UTF-8 argument"))
            .collect();

        assert!(arguments.contains(&"--uml-personality"));
        assert!(arguments.contains(&"--lease-fd"));
        assert!(arguments.contains(&"8"));
        assert!(arguments.contains(&"--liveness-fd"));
        assert!(arguments.contains(&"9"));
        assert!(arguments.contains(&"mem=512M"));
        assert!(arguments.contains(&"pocket.expected_memory_bytes=536870912"));
        assert!(arguments.contains(&"ncpus=4"));
        assert!(arguments.contains(&"pocket.expected_cpus=4"));
        assert!(arguments.contains(&"seccomp=on"));
        assert!(arguments.contains(&"noreboot"));
        assert!(
            arguments.contains(&"quiet"),
            "the default launch must keep the guest console quiet"
        );
        assert!(!arguments.contains(&"loglevel=7"));

        // Asking for the console transcript must lift the console filter, or
        // the transcript silently omits every lockdep and RCU report.
        let verbose = build_launch_plan(&LaunchInputs {
            profile: &profile,
            extra_consoles: 0,
            paths: &paths,
            base: &temporary.path().join("store/generation/base.ext4"),
            cpus,
            memory,
            guard_term_timeout: Duration::from_secs(5),
            verbose_console: true,
            network: false,
        })
        .expect("verbose launch plan");
        let verbose_arguments: Vec<&str> = verbose
            .guard_arguments
            .iter()
            .map(|argument| argument.to_str().expect("UTF-8 argument"))
            .collect();
        assert!(verbose_arguments.contains(&"loglevel=7"));
        assert!(!verbose_arguments.contains(&"quiet"));
        assert!(arguments.contains(&"panic=1"));
        assert!(arguments.contains(&"pocket.cpu_state_hwcap_policy=native-x86_64-v1"));
        assert!(arguments.contains(&"pocket.guest_capability_policy=fixed-capabilities-v1"));
        assert_eq!(
            arguments
                .iter()
                .filter(|value| **value == "seccomp=on")
                .count(),
            1
        );
        assert_eq!(
            arguments
                .iter()
                .filter(|value| **value == "noreboot")
                .count(),
            1
        );
        assert_eq!(
            arguments
                .iter()
                .filter(|value| **value == "panic=1")
                .count(),
            1
        );
        assert!(
            !arguments
                .iter()
                .any(|value| matches!(*value, "sh" | "-c" | "env"))
        );
        let environment: Vec<&str> = plan
            .environment
            .keys()
            .map(|key| key.to_str().expect("UTF-8 environment key"))
            .collect();
        assert_eq!(
            environment,
            [
                "HOME", "LANG", "LC_ALL", "PATH", "TEMP", "TMP", "TMPDIR", "TZ"
            ]
        );
    }

    #[test]
    fn up_launch_omits_the_unlinked_ncpus_parser_but_keeps_guest_cpu_assertion() {
        let temporary = tempdir().expect("tempdir");
        let root_path = temporary.path().join("bundle");
        fs::create_dir(&root_path).expect("bundle");
        let profile =
            synthetic_profile(ManagedUmlPath::new(root_path).expect("managed root"), false);
        let run = temporary
            .path()
            .join("runtime/run-aabbccddeeff00112233445566778899");
        let paths = RunPaths {
            uml_dir: run.join("uml"),
            tmp_dir: run.join("tmp"),
            cow: run.join("root.cow"),
            network_socket: run.join("net"),
            umid: "run-aabbccddeeff00112233445566778899".to_owned(),
        };
        let plan = build_launch_plan(&LaunchInputs {
            profile: &profile,
            extra_consoles: 0,
            paths: &paths,
            base: &temporary.path().join("store/generation/base.ext4"),
            cpus: profile
                .cpu_profile()
                .validate_request(1)
                .expect("CPU request"),
            memory: profile
                .memory_policy()
                .validate(ParsedMemory::from_bytes(256 * 1024 * 1024).expect("memory"))
                .expect("memory request"),
            guard_term_timeout: Duration::from_secs(5),
            verbose_console: false,
            network: false,
        })
        .expect("launch plan");
        let arguments: Vec<&str> = plan
            .uml_command
            .iter()
            .map(|argument| argument.to_str().expect("UTF-8 argument"))
            .collect();
        assert!(
            !arguments
                .iter()
                .any(|argument| argument.starts_with("ncpus="))
        );
        assert!(arguments.contains(&"pocket.expected_cpus=1"));
    }

    #[test]
    fn fake_guard_observes_only_the_explicit_fixed_fd_topology() {
        let temporary = tempdir().expect("tempdir");
        let executable = temporary.path().join("fake-guard");
        fs::write(
            &executable,
            b"#!/bin/bash\n[[ $PWD == / ]] || exit 90\nfor fd in 8 9 10 11 12 13 14; do [[ -e /proc/self/fd/$fd ]] || exit 91; done\nprintf fd-map-ok >&14\n",
        )
        .expect("fake guard");
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700))
            .expect("fake guard mode");
        let lease_path = temporary.path().join("lease");
        let lease = fs::File::create(lease_path).expect("lease");
        let mut environment = BTreeMap::new();
        environment.insert(OsString::from("PATH"), OsString::from("/usr/bin:/bin"));
        let plan = LaunchPlan {
            extra_consoles: 0,
            guard_program: executable,
            guard_arguments: Vec::new(),
            uml_command: Vec::new(),
            environment,
        };
        let mut launch = spawn_guard(&plan, &lease).expect("spawn fake guard");
        launch
            .channels
            .console
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("console timeout");
        let mut output = String::new();
        launch
            .channels
            .console
            .read_to_string(&mut output)
            .expect("read fake-guard console");
        let mut diagnostics = String::new();
        if let Some(mut stderr) = launch.child.stderr.take() {
            stderr
                .read_to_string(&mut diagnostics)
                .expect("read fake-guard stderr");
        }
        let status = launch.child.wait().expect("wait fake guard");
        assert!(
            status.success(),
            "status={status:?}, stderr={diagnostics:?}"
        );
        assert_eq!(output, "fd-map-ok");
    }
}
