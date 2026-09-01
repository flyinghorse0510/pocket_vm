use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    marker::PhantomData,
    os::{
        fd::OwnedFd,
        unix::{
            fs::{MetadataExt, OpenOptionsExt},
            net::UnixStream,
        },
    },
    path::{Component, Path, PathBuf},
    process::{Child, ExitStatus},
    rc::Rc,
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use nix::{
    sched::{CpuSet, sched_getaffinity},
    unistd::Pid,
};
use pocket_core::{ManagedUmlPath, ParsedMemory};
use pocket_protocol::{
    Exit, MAX_SHUTDOWN_GRACE_MS, MAX_STDIN_BYTES, Ready, ResourceLimit, Start, ValidateMessage,
    VolumeSpec,
};
use pocket_store::{AliasKey, Digest, GenerationId, GenerationSpec, Lease, Store};
use sha2::{Digest as _, Sha256};

use crate::{
    RuntimeError, VerifiedProfile,
    cow::validate_fresh_cow,
    filesystem::validate_ext4_base,
    launch::{GuardLaunch, LaunchInputs, RunPaths, build_launch_plan, spawn_guard},
    protocol::{ControlChannel, verify_hello},
};

const MAX_TIMEOUT: Duration = Duration::from_secs(24 * 60 * 60);
const MAX_CAPTURE_BYTES: usize = 64 * 1024 * 1024;
const RUN_ID_BYTES: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkloadSpec {
    pub argv: Vec<String>,
    pub env: Vec<String>,
    pub cwd: String,
    pub uid: u32,
    pub gid: u32,
    pub supplementary_gids: Vec<u32>,
    pub umask: u16,
    pub rlimits: Vec<ResourceLimit>,
    pub hostname: String,
    pub root_read_only: bool,
    /// Host directories to share into the guest, already validated and
    /// canonicalized by the caller, and held under an exclusive lock for the
    /// life of the run.
    pub volumes: Vec<VolumeSpec>,
    /// Give the guest a network interface backed by the profile's helper.
    pub network: bool,
    pub stop_signal: u16,
}

#[derive(Debug, Clone)]
pub struct RunOptions {
    pub cpus: u16,
    pub memory: ParsedMemory,
    pub workload: WorkloadSpec,
    pub stdin: Vec<u8>,
    /// Write the guest console transcript to this new path. Setting it also
    /// asks the guest kernel for its full console rather than the `quiet`
    /// subset, because a transcript filtered to `pr_err` and above hides the
    /// lockdep and RCU reports a caller keeping the transcript is looking for.
    ///
    /// The runtime owns this rather than the caller so the transcript also
    /// exists when the run FAILS, which is the case it is wanted for.
    pub console_log: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy)]
pub struct RuntimePolicy {
    pub startup_timeout: Duration,
    pub execution_timeout: Option<Duration>,
    /// Grace allowed after the image stop signal when `wait` reaches its
    /// execution deadline.
    pub execution_timeout_grace: Duration,
    /// Grace encoded in SHUTDOWN for the guest to kill and drain its nested
    /// PID namespace.
    pub shutdown_namespace_grace: Duration,
    /// Host-side bound for receiving EXIT after SHUTDOWN. This is distinct
    /// from the namespace grace because EXIT follows stream draining, volume
    /// sync, and unmount.
    pub shutdown_ack_timeout: Duration,
    pub protocol_write_timeout: Duration,
    pub guard_term_timeout: Duration,
    pub guard_exit_timeout: Duration,
    pub maximum_stdout_bytes: usize,
    pub maximum_stderr_bytes: usize,
    pub maximum_console_bytes: usize,
}

impl Default for RuntimePolicy {
    fn default() -> Self {
        Self {
            startup_timeout: Duration::from_secs(30),
            execution_timeout: None,
            execution_timeout_grace: Duration::from_secs(5),
            shutdown_namespace_grace: Duration::from_secs(5),
            shutdown_ack_timeout: Duration::from_secs(15),
            protocol_write_timeout: Duration::from_secs(5),
            guard_term_timeout: Duration::from_secs(5),
            guard_exit_timeout: Duration::from_secs(10),
            maximum_stdout_bytes: 8 * 1024 * 1024,
            maximum_stderr_bytes: 8 * 1024 * 1024,
            maximum_console_bytes: 4 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedStream {
    pub bytes: Vec<u8>,
    pub truncated: bool,
    pub total_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunOutput {
    pub run_id: String,
    pub scaling_qualified: bool,
    pub guest_exit: Exit,
    pub stdout: CapturedStream,
    pub stderr: CapturedStream,
    pub console: CapturedStream,
    pub guard_stdout: CapturedStream,
    pub guard_stderr: CapturedStream,
    /// Why the requested console transcript could not be written, if it could
    /// not. A run that produced its result must still deliver it, so this is
    /// reported alongside the outcome rather than replacing it.
    pub console_log_error: Option<String>,
}

/// A synchronous runtime bound to one already selected profile revision and
/// one profile-qualified content store.
pub struct Runtime<'runtime> {
    profile: &'runtime VerifiedProfile,
    store: &'runtime Store,
    runtime_root: ManagedUmlPath,
    policy: RuntimePolicy,
}

impl std::fmt::Debug for Runtime<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Runtime")
            .field("profile", &self.profile.manifest().profile_id)
            .field("runtime_root", &self.runtime_root)
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

impl<'runtime> Runtime<'runtime> {
    pub fn new(
        profile: &'runtime VerifiedProfile,
        store: &'runtime Store,
        runtime_root: ManagedUmlPath,
        policy: RuntimePolicy,
    ) -> Result<Self, RuntimeError> {
        validate_policy(policy)?;
        initialize_runtime_root(runtime_root.as_path())?;
        Ok(Self {
            profile,
            store,
            runtime_root,
            policy,
        })
    }

    /// Prepare, start, and complete one workload on the calling thread.
    pub fn run(
        &self,
        generation_id: GenerationId,
        options: RunOptions,
    ) -> Result<RunOutput, RuntimeError> {
        self.start(generation_id, options)?.wait()
    }

    /// Atomically resolve an alias and acquire its generation lease before any
    /// generation path is observed, then run the selected immutable target.
    pub fn run_alias(
        &self,
        alias: &AliasKey,
        options: RunOptions,
    ) -> Result<RunOutput, RuntimeError> {
        self.start_alias(alias, options)?.wait()
    }

    /// Run an exact generation using a lease whose authenticated sidecars may
    /// already have been used to construct `options`.
    ///
    /// This preserves one continuous generation lease from atomic alias
    /// resolution, through image-process merging, until the guard receives the
    /// lease descriptor. It avoids resolving an alias a second time after its
    /// configuration has been read.
    pub fn run_leased(&self, lease: Lease, options: RunOptions) -> Result<RunOutput, RuntimeError> {
        self.start_leased(lease, options)?.wait()
    }

    /// Start one workload and return a same-thread lifecycle handle after
    /// HELLO/START/READY and COW validation have completed.
    pub fn start(
        &self,
        generation_id: GenerationId,
        options: RunOptions,
    ) -> Result<RunningWorkload, RuntimeError> {
        self.profile.reverify()?;
        let lease = self.store.acquire_lease(generation_id)?;
        self.start_with_lease(lease, options)
    }

    /// Resolve and lease one profile-qualified alias in the store's shared
    /// roots critical section. This method never calls the snapshot-only
    /// `alias_target` API and therefore has no alias/GC gap.
    pub fn start_alias(
        &self,
        alias: &AliasKey,
        options: RunOptions,
    ) -> Result<RunningWorkload, RuntimeError> {
        self.profile.reverify()?;
        let lease = self.store.lease_alias(alias)?;
        self.start_with_lease(lease, options)
    }

    /// Start a workload from an already acquired exact-generation lease.
    pub fn start_leased(
        &self,
        lease: Lease,
        options: RunOptions,
    ) -> Result<RunningWorkload, RuntimeError> {
        self.profile.reverify()?;
        self.start_with_lease(lease, options)
    }

    fn start_with_lease(
        &self,
        lease: Lease,
        options: RunOptions,
    ) -> Result<RunningWorkload, RuntimeError> {
        let stdin_bytes = u64::try_from(options.stdin.len())
            .ok()
            .filter(|count| *count <= MAX_STDIN_BYTES)
            .ok_or_else(|| {
                RuntimeError::invalid(
                    "stdin",
                    format!("exceeds the {MAX_STDIN_BYTES}-byte synchronous input cap"),
                )
            })?;
        let cpus = validate_profile_cpu_request(self.profile, options.cpus)?;
        let scaling_qualified = observe_scaling_qualified(options.cpus);
        let memory = self.profile.memory_policy().validate(options.memory)?;

        let generation_id = lease.id();
        validate_generation(self.profile, lease.generation().manifest().spec())?;
        let base_path = ManagedUmlPath::new(lease.generation().base_path())?;
        let base_digest = lease.generation().manifest().base_digest();
        let base_size = lease.generation().manifest().base_size();
        let account_db_sha256 = lease
            .generation()
            .manifest()
            .sidecars()
            .iter()
            .find(|sidecar| sidecar.name() == "accounts.cbor")
            .map(|sidecar| hex::encode(sidecar.digest().as_bytes()))
            .ok_or_else(|| {
                RuntimeError::invalid(
                    "generation.accounts",
                    "verified generation lacks the mandatory accounts.cbor sidecar",
                )
            })?;
        validate_ext4_base(base_path.as_path())?;
        let start = build_start(
            self.profile,
            lease.generation().manifest().spec(),
            generation_id,
            account_db_sha256,
            &options.workload,
            stdin_bytes,
        )?;

        let run_directory = RunDirectory::create(&self.runtime_root)?;
        let paths = run_directory.paths(self.profile)?;
        if paths.cow.exists() {
            return Err(RuntimeError::invalid(
                "root.cow",
                "fresh COW leaf unexpectedly exists before UML launch",
            ));
        }
        let plan = build_launch_plan(&LaunchInputs {
            profile: self.profile,
            paths: &paths,
            base: base_path.as_path(),
            cpus,
            memory,
            guard_term_timeout: self.policy.guard_term_timeout,
            verbose_console: options.console_log.is_some(),
            network: options.workload.network,
        })?;
        let launch = spawn_guard(&plan, lease.lock_file())?;
        // The guard's dup of this open file description is now the sole lock
        // owner required by the runtime lifecycle.
        drop(lease);

        let mut active = ActiveRun::from_launch(
            launch,
            run_directory,
            paths,
            base_path.into_path_buf(),
            base_digest,
            base_size,
            self.policy,
            scaling_qualified,
            &options.stdin,
        )?;
        active.console_log = options.console_log.clone();
        let startup_deadline = Instant::now() + self.policy.startup_timeout;
        let startup_result = (|| {
            let hello = active
                .control
                .as_mut()
                .ok_or_else(|| RuntimeError::invalid("control", "missing control channel"))?
                .receive_hello(startup_deadline, self.policy.startup_timeout)?;
            verify_hello(self.profile, cpus, memory, &hello)?;
            validate_fresh_cow(&active.paths.cow, &active.base_path)?;
            active
                .control
                .as_mut()
                .ok_or_else(|| RuntimeError::invalid("control", "missing control channel"))?
                .send_start(start, startup_deadline, self.policy.protocol_write_timeout)?;
            let ready = active
                .control
                .as_mut()
                .ok_or_else(|| RuntimeError::invalid("control", "missing control channel"))?
                .receive_ready(startup_deadline, self.policy.startup_timeout)?;
            verify_ready(&ready, &options.workload)?;
            Ok::<Ready, RuntimeError>(ready)
        })();
        let ready = match startup_result {
            Ok(ready) => {
                if let Err(error) = active.start_stdin_worker() {
                    return Err(active.fail(error, "stdin delivery after READY"));
                }
                ready
            }
            Err(error) => return Err(active.fail(error, "workload readiness")),
        };

        Ok(RunningWorkload {
            active: Some(active),
            ready,
            stop_signal: options.workload.stop_signal,
            scaling_qualified,
            _same_thread: PhantomData,
        })
    }
}

/// A READY workload. The `Rc` marker intentionally makes this handle neither
/// Send nor Sync: the thread which created the guard must remain alive because
/// Linux parent-death delivery is tied to that creating parent thread.
pub struct RunningWorkload {
    active: Option<ActiveRun>,
    ready: Ready,
    stop_signal: u16,
    scaling_qualified: bool,
    _same_thread: PhantomData<Rc<()>>,
}

impl std::fmt::Debug for RunningWorkload {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RunningWorkload")
            .field("ready", &self.ready)
            .field(
                "run_id",
                &self.active.as_ref().map(|active| &active.paths.umid),
            )
            .finish_non_exhaustive()
    }
}

impl RunningWorkload {
    #[must_use]
    pub const fn ready(&self) -> &Ready {
        &self.ready
    }

    /// Whether current host affinity and an observable cgroup-v2 CPU quota
    /// have enough capacity for the requested vCPU count. This is reporting,
    /// never an admission decision.
    #[must_use]
    pub const fn scaling_qualified(&self) -> bool {
        self.scaling_qualified
    }

    pub fn send_signal(&mut self, signal: u16) -> Result<(), RuntimeError> {
        let active = self
            .active
            .as_mut()
            .ok_or_else(|| RuntimeError::invalid("lifecycle", "workload is already gone"))?;
        let timeout = active.policy.protocol_write_timeout;
        active
            .control
            .as_mut()
            .ok_or_else(|| RuntimeError::invalid("control", "missing control channel"))?
            .send_signal(signal, Instant::now() + timeout, timeout)
    }

    pub fn wait(mut self) -> Result<RunOutput, RuntimeError> {
        let mut active = self
            .active
            .take()
            .ok_or_else(|| RuntimeError::invalid("lifecycle", "workload is already gone"))?;
        let (deadline, timeout) = execution_deadline(active.policy.execution_timeout);
        let result = active
            .control
            .as_mut()
            .ok_or_else(|| RuntimeError::invalid("control", "missing control channel"))?
            .receive_terminal(deadline, timeout);
        match result {
            Ok(exit) => active.finish(exit),
            Err(error) if is_timeout(&error) => {
                let grace = active.policy.execution_timeout_grace;
                request_stop_and_wait(active, self.stop_signal, grace)
            }
            Err(error) => Err(active.fail(error, "workload EXIT")),
        }
    }

    /// Request the image's validated stop signal, wait the supplied grace
    /// period for EXIT, then request bounded guest-side forced shutdown. Guard
    /// liveness is closed only if the guest does not acknowledge SHUTDOWN.
    pub fn terminate(mut self, grace: Duration) -> Result<RunOutput, RuntimeError> {
        validate_timeout("termination_grace", grace, MAX_TIMEOUT)?;
        let active = self
            .active
            .take()
            .ok_or_else(|| RuntimeError::invalid("lifecycle", "workload is already gone"))?;
        request_stop_and_wait(active, self.stop_signal, grace)
    }
}

fn request_stop_and_wait(
    mut active: ActiveRun,
    stop_signal: u16,
    grace: Duration,
) -> Result<RunOutput, RuntimeError> {
    let write_timeout = active.policy.protocol_write_timeout;
    if let Err(error) = active
        .control
        .as_mut()
        .ok_or_else(|| RuntimeError::invalid("control", "missing control channel"))?
        .send_signal(stop_signal, Instant::now() + write_timeout, write_timeout)
    {
        return Err(active.fail(error, "workload stop signal"));
    }

    let graceful = active
        .control
        .as_mut()
        .ok_or_else(|| RuntimeError::invalid("control", "missing control channel"))?
        .receive_terminal(Instant::now() + grace, grace);
    match graceful {
        Ok(exit) => active.finish(exit),
        Err(error) if is_timeout(&error) => request_shutdown_and_wait(active),
        Err(error) => Err(active.fail(error, "graceful workload termination")),
    }
}

fn request_shutdown_and_wait(mut active: ActiveRun) -> Result<RunOutput, RuntimeError> {
    let grace_ms = match shutdown_grace_ms(active.policy.shutdown_namespace_grace) {
        Ok(grace_ms) => grace_ms,
        Err(error) => return Err(active.fail(error, "SHUTDOWN configuration")),
    };
    let write_timeout = active.policy.protocol_write_timeout;
    if let Err(error) = active
        .control
        .as_mut()
        .ok_or_else(|| RuntimeError::invalid("control", "missing control channel"))?
        .send_shutdown(grace_ms, Instant::now() + write_timeout, write_timeout)
    {
        return Err(active.fail(error, "workload SHUTDOWN"));
    }

    let timeout = active.policy.shutdown_ack_timeout;
    let terminal = active
        .control
        .as_mut()
        .ok_or_else(|| RuntimeError::invalid("control", "missing control channel"))?
        .receive_terminal(Instant::now() + timeout, timeout);
    match terminal {
        Ok(exit) => active.finish(exit),
        Err(error) => Err(active.fail(error, "workload EXIT after SHUTDOWN")),
    }
}

const fn is_timeout(error: &RuntimeError) -> bool {
    matches!(error, RuntimeError::Timeout { .. })
}

impl Drop for RunningWorkload {
    fn drop(&mut self) {
        if let Some(mut active) = self.active.take() {
            let _ = active.force_cleanup();
        }
    }
}

struct ActiveRun {
    child: Option<Child>,
    liveness: Option<OwnedFd>,
    control: Option<ControlChannel>,
    stdin_stream: Option<UnixStream>,
    stdin_bytes: Option<Vec<u8>>,
    stdin_worker: Option<JoinHandle<Result<(), String>>>,
    stdout_worker: Option<CaptureWorker>,
    stderr_worker: Option<CaptureWorker>,
    console_worker: Option<CaptureWorker>,
    guard_stdout_worker: Option<CaptureWorker>,
    guard_stderr_worker: Option<CaptureWorker>,
    run_directory: Option<RunDirectory>,
    paths: RunPaths,
    base_path: PathBuf,
    base_digest: Digest,
    base_size: u64,
    policy: RuntimePolicy,
    scaling_qualified: bool,
    failure_diagnostics: Option<String>,
    /// Where to persist the guest console transcript, if the caller asked.
    console_log: Option<PathBuf>,
    cleaned: bool,
}

impl ActiveRun {
    #[allow(clippy::too_many_arguments)]
    fn from_launch(
        mut launch: GuardLaunch,
        run_directory: RunDirectory,
        paths: RunPaths,
        base_path: PathBuf,
        base_digest: Digest,
        base_size: u64,
        policy: RuntimePolicy,
        scaling_qualified: bool,
        stdin: &[u8],
    ) -> Result<Self, RuntimeError> {
        let guard_stdout = match launch.child.stdout.take() {
            Some(stdout) => stdout,
            None => {
                return Err(abort_incomplete_launch(
                    launch,
                    "guard stdout pipe was not created",
                ));
            }
        };
        let guard_stderr = match launch.child.stderr.take() {
            Some(stderr) => stderr,
            None => {
                return Err(abort_incomplete_launch(
                    launch,
                    "guard stderr pipe was not created",
                ));
            }
        };
        Ok(Self {
            child: Some(launch.child),
            liveness: Some(launch.liveness),
            control: Some(ControlChannel::new(launch.channels.control)),
            // Keep the host write side open through HELLO/START/READY. Closing
            // or half-closing it before pocket-init opens ttyS1 can make the
            // UML serial backend report a hangup before the control protocol
            // starts. Input delivery begins only after READY.
            stdin_stream: Some(launch.channels.stdin),
            stdin_bytes: Some(stdin.to_vec()),
            stdin_worker: None,
            stdout_worker: Some(CaptureWorker::spawn(
                "stdout",
                launch.channels.stdout,
                policy.maximum_stdout_bytes,
            )),
            stderr_worker: Some(CaptureWorker::spawn(
                "stderr",
                launch.channels.stderr,
                policy.maximum_stderr_bytes,
            )),
            console_worker: Some(CaptureWorker::spawn(
                "console",
                launch.channels.console,
                policy.maximum_console_bytes,
            )),
            guard_stdout_worker: Some(CaptureWorker::spawn(
                "guard-stdout",
                guard_stdout,
                policy.maximum_console_bytes,
            )),
            guard_stderr_worker: Some(CaptureWorker::spawn(
                "guard-stderr",
                guard_stderr,
                policy.maximum_console_bytes,
            )),
            run_directory: Some(run_directory),
            paths,
            base_path,
            base_digest,
            base_size,
            policy,
            scaling_qualified,
            failure_diagnostics: None,
            console_log: None,
            cleaned: false,
        })
    }

    /// Persist the guest console transcript, if one was requested. Failing to
    /// write it must never discard the run's own result, so the error is
    /// recorded and reported by the caller after the outcome is delivered.
    fn write_console_log(path: &Path, console: &CapturedStream) -> Result<(), RuntimeError> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(|error| RuntimeError::io("create console log", path, error))?;
        file.write_all(&console.bytes)
            .map_err(|error| RuntimeError::io("write console log", path, error))?;
        if console.truncated {
            writeln!(
                file,
                "pocket: console capture truncated at {} of {} bytes",
                console.bytes.len(),
                console.total_bytes
            )
            .map_err(|error| RuntimeError::io("write console log", path, error))?;
        }
        file.sync_all()
            .map_err(|error| RuntimeError::io("flush console log", path, error))?;
        Ok(())
    }

    fn start_stdin_worker(&mut self) -> Result<(), RuntimeError> {
        // The worker gets a duplicate descriptor. `self.stdin_stream` keeps the
        // channel open until teardown so the guest can drain every announced
        // byte before the serial line is hung up.
        let stream = self
            .stdin_stream
            .as_ref()
            .ok_or_else(|| RuntimeError::invalid("stdin", "stdin stream is unavailable"))?
            .try_clone()
            .map_err(|error| {
                RuntimeError::io("duplicate stdin channel", Path::new("<stdin>"), error)
            })?;
        let bytes = self
            .stdin_bytes
            .take()
            .ok_or_else(|| RuntimeError::invalid("stdin", "stdin bytes are unavailable"))?;
        self.stdin_worker = Some(thread::spawn(move || write_stdin(stream, &bytes)));
        Ok(())
    }

    fn finish(mut self, guest_exit: Exit) -> Result<RunOutput, RuntimeError> {
        if !guest_exit.filesystem_clean {
            return Err(self.fail(
                RuntimeError::GuestFilesystemUnclean,
                "guest filesystem cleanup",
            ));
        }
        let status = self.wait_for_guard()?;
        if !status.success() {
            let error = RuntimeError::GuardStatus {
                status: status_text(status),
            };
            return Err(self.fail(error, "guard exit after guest EXIT"));
        }
        self.liveness.take();
        self.control.take();
        let captures = self.join_workers()?;
        // The run produced a result, so it is delivered whatever happens here.
        // Losing a workload's exit status and output because a side file could
        // not be created would be a worse outcome than reporting that failure.
        let console_log_error = match self.console_log.as_deref() {
            Some(path) => Self::write_console_log(path, &captures.console)
                .err()
                .map(|error| error.to_string()),
            None => None,
        };
        self.verify_base_unchanged()?;
        self.cleanup_directory()?;
        self.cleaned = true;
        Ok(RunOutput {
            run_id: self.paths.umid.clone(),
            scaling_qualified: self.scaling_qualified,
            guest_exit,
            stdout: captures.stdout,
            stderr: captures.stderr,
            console: captures.console,
            guard_stdout: captures.guard_stdout,
            guard_stderr: captures.guard_stderr,
            console_log_error,
        })
    }

    fn fail(mut self, primary: RuntimeError, stage: &'static str) -> RuntimeError {
        let primary = if let Some(child) = self.child.as_mut()
            && let Ok(Some(status)) = child.try_wait()
        {
            self.child.take();
            RuntimeError::GuardExitedEarly {
                stage,
                status: status_text(status),
            }
        } else {
            primary
        };
        let cleanup = self.force_cleanup();
        let primary = match self.failure_diagnostics.take() {
            Some(diagnostic) if !diagnostic.is_empty() => RuntimeError::Diagnostics {
                primary: Box::new(primary),
                diagnostic,
            },
            _ => primary,
        };
        match cleanup {
            Some(error) => RuntimeError::Cleanup {
                primary: Box::new(primary),
                cleanup: error,
            },
            None => primary,
        }
    }

    fn force_cleanup(&mut self) -> Option<String> {
        if self.cleaned {
            return None;
        }
        let mut failures = Vec::new();
        self.control.take();
        self.liveness.take();
        self.stdin_stream.take();
        self.stdin_bytes.take();
        if let Some(child) = self.child.as_mut() {
            let deadline = Instant::now() + self.policy.guard_exit_timeout;
            match wait_child_until(child, deadline) {
                Ok(Some(_)) => {
                    self.child.take();
                }
                Ok(None) => {
                    if let Err(error) = child.kill() {
                        failures.push(format!("could not SIGKILL guard: {error}"));
                    }
                    match child.wait() {
                        Ok(_) => {
                            self.child.take();
                        }
                        Err(error) => failures.push(format!("could not reap guard: {error}")),
                    }
                }
                Err(error) => {
                    failures.push(format!("could not observe guard: {error}"));
                    if let Err(kill_error) = child.kill() {
                        failures.push(format!("could not SIGKILL guard: {kill_error}"));
                    }
                    match child.wait() {
                        Ok(_) => {
                            self.child.take();
                        }
                        Err(wait_error) => {
                            failures.push(format!("could not reap guard: {wait_error}"));
                        }
                    }
                }
            }
        }
        match self.join_workers_for_failure() {
            Ok(diagnostic) if !diagnostic.is_empty() => {
                self.failure_diagnostics = Some(diagnostic);
            }
            Ok(_) => {}
            Err(error) => failures.push(error.to_string()),
        }
        if let Err(error) = self.verify_base_unchanged() {
            failures.push(error.to_string());
        }
        if let Err(error) = self.cleanup_directory() {
            failures.push(error.to_string());
        }
        self.cleaned = true;
        if failures.is_empty() {
            None
        } else {
            Some(failures.join("; "))
        }
    }

    fn wait_for_guard(&mut self) -> Result<ExitStatus, RuntimeError> {
        let child = self
            .child
            .as_mut()
            .ok_or_else(|| RuntimeError::invalid("guard", "guard already reaped"))?;
        let deadline = Instant::now() + self.policy.guard_exit_timeout;
        let Some(status) = wait_child_until(child, deadline)
            .map_err(|error| RuntimeError::io("wait for guard", Path::new("<guard>"), error))?
        else {
            return Err(RuntimeError::Timeout {
                stage: "guard exit after guest EXIT",
                timeout: self.policy.guard_exit_timeout,
            });
        };
        self.child.take();
        Ok(status)
    }

    fn join_workers(&mut self) -> Result<JoinedCaptures, RuntimeError> {
        let deadline = Instant::now() + self.policy.guard_exit_timeout;
        join_stdin(&mut self.stdin_worker, deadline)?;
        Ok(JoinedCaptures {
            stdout: join_capture(&mut self.stdout_worker, deadline)?,
            stderr: join_capture(&mut self.stderr_worker, deadline)?,
            console: join_capture(&mut self.console_worker, deadline)?,
            guard_stdout: join_capture(&mut self.guard_stdout_worker, deadline)?,
            guard_stderr: join_capture(&mut self.guard_stderr_worker, deadline)?,
        })
    }

    fn join_workers_for_failure(&mut self) -> Result<String, RuntimeError> {
        let deadline = Instant::now() + self.policy.guard_exit_timeout;
        join_stdin(&mut self.stdin_worker, deadline)?;
        let captures = [
            (
                "stdout",
                join_capture_if_present(&mut self.stdout_worker, deadline)?,
            ),
            (
                "stderr",
                join_capture_if_present(&mut self.stderr_worker, deadline)?,
            ),
            (
                "console",
                join_capture_if_present(&mut self.console_worker, deadline)?,
            ),
            (
                "guard-stdout",
                join_capture_if_present(&mut self.guard_stdout_worker, deadline)?,
            ),
            (
                "guard-stderr",
                join_capture_if_present(&mut self.guard_stderr_worker, deadline)?,
            ),
        ];
        // The transcript matters most when the run failed, so write it here
        // too. A write failure must not replace the real failure, so it is
        // folded into the diagnostic text rather than returned.
        let mut diagnostic = failure_diagnostics(captures.clone());
        if let Some(path) = self.console_log.as_deref() {
            let console = captures
                .iter()
                .find(|(role, _)| *role == "console")
                .and_then(|(_, capture)| capture.clone());
            match console {
                Some(console) => {
                    if let Err(error) = Self::write_console_log(path, &console) {
                        diagnostic.push_str(&format!("; console log not written: {error}"));
                    }
                }
                None => {
                    diagnostic.push_str("; console log not written: console was never captured")
                }
            }
        }
        Ok(diagnostic)
    }

    fn verify_base_unchanged(&self) -> Result<(), RuntimeError> {
        let metadata = fs::metadata(&self.base_path).map_err(|error| {
            RuntimeError::io("inspect immutable base after run", &self.base_path, error)
        })?;
        if metadata.len() != self.base_size {
            return Err(RuntimeError::GenerationMismatch {
                field: "base_size_after_run",
                expected: self.base_size.to_string(),
                actual: metadata.len().to_string(),
            });
        }
        let observed = hash_file(&self.base_path)?;
        if observed.as_slice() != self.base_digest.as_bytes() {
            return Err(RuntimeError::GenerationMismatch {
                field: "base_digest_after_run",
                expected: self.base_digest.to_string(),
                actual: format!("sha256:{}", hex::encode(observed)),
            });
        }
        Ok(())
    }

    fn cleanup_directory(&mut self) -> Result<(), RuntimeError> {
        if let Some(mut directory) = self.run_directory.take() {
            directory.cleanup()
        } else {
            Ok(())
        }
    }
}

impl Drop for ActiveRun {
    fn drop(&mut self) {
        if !self.cleaned {
            let _ = self.force_cleanup();
        }
    }
}

struct JoinedCaptures {
    stdout: CapturedStream,
    stderr: CapturedStream,
    console: CapturedStream,
    guard_stdout: CapturedStream,
    guard_stderr: CapturedStream,
}

struct CaptureWorker {
    role: &'static str,
    handle: JoinHandle<Result<CapturedStream, String>>,
}

impl CaptureWorker {
    fn spawn<R>(role: &'static str, reader: R, maximum: usize) -> Self
    where
        R: Read + Send + 'static,
    {
        let handle = thread::spawn(move || capture(reader, maximum));
        Self { role, handle }
    }
}

fn abort_incomplete_launch(mut launch: GuardLaunch, reason: &'static str) -> RuntimeError {
    drop(launch.liveness);
    let _ = launch.child.kill();
    let _ = launch.child.wait();
    RuntimeError::invalid("guard.stdio", reason)
}

struct RunDirectory {
    root: PathBuf,
    path: PathBuf,
    device: u64,
    inode: u64,
    cleaned: bool,
    /// Held for this directory's whole life. Its release is what tells a later
    /// sweep that this run's owner is gone, however it died.
    _owner: File,
}

impl RunDirectory {
    fn create(root: &ManagedUmlPath) -> Result<Self, RuntimeError> {
        let root_path = root.as_path();
        // Reclaim what earlier signal-killed invocations left behind before
        // adding to it.
        crate::operation::reclaim_orphans(root_path, "run-").map_err(|error| {
            RuntimeError::io("reclaim abandoned run directories", root_path, error)
        })?;
        let creation = crate::operation::lock_creation(root_path)
            .map_err(|error| RuntimeError::io("lock run-directory creation", root_path, error))?;
        for _ in 0..128 {
            let id = random_id()?;
            let path = root.as_path().join(format!("run-{id}"));
            match fs::create_dir(&path) {
                Ok(()) => {
                    fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o700))
                        .map_err(|error| {
                            RuntimeError::io("set run-directory mode", &path, error)
                        })?;
                    for child in ["uml", "tmp"] {
                        let child_path = path.join(child);
                        fs::create_dir(&child_path).map_err(|error| {
                            RuntimeError::io("create private run subdirectory", &child_path, error)
                        })?;
                        fs::set_permissions(
                            &child_path,
                            std::os::unix::fs::PermissionsExt::from_mode(0o700),
                        )
                        .map_err(|error| {
                            RuntimeError::io("set run subdirectory mode", &child_path, error)
                        })?;
                    }
                    let owner = crate::operation::claim_owner(&path)
                        .map_err(|error| RuntimeError::io("claim run directory", &path, error))?;
                    let metadata = fs::symlink_metadata(&path).map_err(|error| {
                        RuntimeError::io("inspect private run directory", &path, error)
                    })?;
                    drop(creation);
                    return Ok(Self {
                        root: root.as_path().to_path_buf(),
                        path,
                        device: metadata.dev(),
                        inode: metadata.ino(),
                        cleaned: false,
                        _owner: owner,
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => {
                    return Err(RuntimeError::io(
                        "create private run directory",
                        &path,
                        error,
                    ));
                }
            }
        }
        Err(RuntimeError::invalid(
            "run_id",
            "could not allocate a unique run directory",
        ))
    }

    fn paths(&self, profile: &VerifiedProfile) -> Result<RunPaths, RuntimeError> {
        let managed = ManagedUmlPath::new(&self.path)?;
        let uml = managed.join_component("uml")?.into_path_buf();
        let tmp = managed.join_component("tmp")?.into_path_buf();
        let cow = managed.join_component("root.cow")?.into_path_buf();
        // Named to match `uml` and `tmp`, and no longer than either: this
        // becomes an AF_UNIX path, and a longer leaf than the existing
        // longest one would silently shorten the runtime root every caller
        // is allowed to use.
        let network_socket = managed.join_component("net")?.into_path_buf();
        let umid = self
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| RuntimeError::invalid("run_id", "generated name is not UTF-8"))?
            .to_owned();
        if umid.len() > usize::from(profile.manifest().launch.max_umid_bytes) {
            return Err(RuntimeError::invalid(
                "run_id",
                "generated name exceeds the profile umid limit",
            ));
        }
        Ok(RunPaths {
            uml_dir: uml,
            tmp_dir: tmp,
            cow,
            network_socket,
            umid,
        })
    }

    fn cleanup(&mut self) -> Result<(), RuntimeError> {
        if self.cleaned {
            return Ok(());
        }
        if self.path.parent() != Some(self.root.as_path()) {
            return Err(RuntimeError::invalid(
                "cleanup",
                "owned run directory escaped its runtime root",
            ));
        }
        let metadata = fs::symlink_metadata(&self.path).map_err(|error| {
            RuntimeError::io("verify run directory before cleanup", &self.path, error)
        })?;
        if !metadata.file_type().is_dir()
            || metadata.dev() != self.device
            || metadata.ino() != self.inode
        {
            return Err(RuntimeError::invalid(
                "cleanup",
                "run directory identity changed",
            ));
        }
        fs::remove_dir_all(&self.path)
            .map_err(|error| RuntimeError::io("remove owned run directory", &self.path, error))?;
        self.cleaned = true;
        Ok(())
    }
}

impl Drop for RunDirectory {
    fn drop(&mut self) {
        if !self.cleaned {
            let _ = self.cleanup();
        }
    }
}

fn validate_policy(policy: RuntimePolicy) -> Result<(), RuntimeError> {
    validate_timeout("startup_timeout", policy.startup_timeout, MAX_TIMEOUT)?;
    if let Some(timeout) = policy.execution_timeout {
        validate_timeout("execution_timeout", timeout, MAX_TIMEOUT)?;
    }
    validate_timeout(
        "execution_timeout_grace",
        policy.execution_timeout_grace,
        Duration::from_secs(600),
    )?;
    let _ = shutdown_grace_ms(policy.shutdown_namespace_grace)?;
    validate_timeout(
        "shutdown_ack_timeout",
        policy.shutdown_ack_timeout,
        Duration::from_secs(1200),
    )?;
    if policy.shutdown_ack_timeout <= policy.shutdown_namespace_grace {
        return Err(RuntimeError::invalid(
            "shutdown_ack_timeout",
            "must exceed shutdown_namespace_grace so EXIT can follow namespace drain",
        ));
    }
    validate_timeout(
        "protocol_write_timeout",
        policy.protocol_write_timeout,
        Duration::from_secs(600),
    )?;
    validate_timeout(
        "guard_term_timeout",
        policy.guard_term_timeout,
        Duration::from_secs(600),
    )?;
    validate_timeout(
        "guard_exit_timeout",
        policy.guard_exit_timeout,
        Duration::from_secs(1200),
    )?;
    if policy.guard_exit_timeout < policy.guard_term_timeout {
        return Err(RuntimeError::invalid(
            "guard_exit_timeout",
            "must be at least guard_term_timeout",
        ));
    }
    for (field, value) in [
        ("maximum_stdout_bytes", policy.maximum_stdout_bytes),
        ("maximum_stderr_bytes", policy.maximum_stderr_bytes),
        ("maximum_console_bytes", policy.maximum_console_bytes),
    ] {
        if value == 0 || value > MAX_CAPTURE_BYTES {
            return Err(RuntimeError::invalid(
                field,
                format!("must be in 1..={MAX_CAPTURE_BYTES}"),
            ));
        }
    }
    Ok(())
}

fn shutdown_grace_ms(value: Duration) -> Result<u32, RuntimeError> {
    const NANOS_PER_MILLISECOND: u32 = 1_000_000;

    if !value.subsec_nanos().is_multiple_of(NANOS_PER_MILLISECOND) {
        return Err(RuntimeError::invalid(
            "shutdown_namespace_grace",
            "must be an exact whole number of milliseconds",
        ));
    }
    let milliseconds = value.as_millis();
    if !(1..=u128::from(MAX_SHUTDOWN_GRACE_MS)).contains(&milliseconds) {
        return Err(RuntimeError::invalid(
            "shutdown_namespace_grace",
            format!("must be in 1..={MAX_SHUTDOWN_GRACE_MS} milliseconds"),
        ));
    }
    u32::try_from(milliseconds).map_err(|_| {
        RuntimeError::invalid(
            "shutdown_namespace_grace",
            "millisecond value does not fit the SHUTDOWN wire field",
        )
    })
}

fn validate_timeout(
    field: &'static str,
    value: Duration,
    maximum: Duration,
) -> Result<(), RuntimeError> {
    if value.is_zero() || value > maximum {
        return Err(RuntimeError::invalid(
            field,
            format!("must be nonzero and no greater than {maximum:?}"),
        ));
    }
    Ok(())
}

fn initialize_runtime_root(path: &Path) -> Result<(), RuntimeError> {
    match fs::create_dir(path) {
        Ok(()) => fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o700))
            .map_err(|error| RuntimeError::io("set runtime-root mode", path, error))?,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(RuntimeError::io("create runtime root", path, error)),
    }
    let canonical = fs::canonicalize(path)
        .map_err(|error| RuntimeError::io("canonicalize runtime root", path, error))?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| RuntimeError::io("inspect runtime root", path, error))?;
    if canonical != path || !metadata.file_type().is_dir() {
        return Err(RuntimeError::invalid(
            "runtime_root",
            "must be an exact non-symlink directory path",
        ));
    }
    if metadata.uid() != nix::unistd::geteuid().as_raw() || metadata.mode() & 0o777 != 0o700 {
        return Err(RuntimeError::invalid(
            "runtime_root",
            "must be owned by the effective user with mode 0700",
        ));
    }
    Ok(())
}

fn validate_generation(
    profile: &VerifiedProfile,
    generation: &GenerationSpec,
) -> Result<(), RuntimeError> {
    let manifest = profile.manifest();
    compare_generation("profile_id", &manifest.profile_id, generation.profile_id())?;
    compare_generation(
        "profile_revision",
        &manifest.profile_revision.to_string(),
        &generation.profile_revision().to_string(),
    )?;
    let platform = generation.effective_platform();
    compare_generation("platform.os", "linux", platform.os())?;
    compare_generation("platform.architecture", "amd64", platform.architecture())?;
    if !manifest
        .accepted_oci_variants
        .iter()
        .any(|variant| variant.as_deref() == platform.variant())
    {
        return Err(RuntimeError::GenerationMismatch {
            field: "platform.variant",
            expected: format!("{:?}", manifest.accepted_oci_variants),
            actual: format!("{:?}", platform.variant()),
        });
    }
    if platform.os_version().is_some() || !platform.os_features().is_empty() {
        return Err(RuntimeError::GenerationMismatch {
            field: "platform.os_extensions",
            expected: "no OS version or features".to_owned(),
            actual: format!(
                "version={:?}, features={:?}",
                platform.os_version(),
                platform.os_features()
            ),
        });
    }
    compare_generation(
        "selector_policy",
        &manifest.contracts.selector_policy,
        generation.selector_policy_id(),
    )?;
    compare_generation(
        "root_layout",
        &manifest.contracts.root_layout,
        generation.root_layout_contract(),
    )?;
    compare_generation(
        "filesystem_contract",
        &manifest.contracts.filesystem,
        generation.filesystem_contract(),
    )
}

fn compare_generation(
    field: &'static str,
    expected: &str,
    actual: &str,
) -> Result<(), RuntimeError> {
    if expected != actual {
        return Err(RuntimeError::GenerationMismatch {
            field,
            expected: expected.to_owned(),
            actual: actual.to_owned(),
        });
    }
    Ok(())
}

fn build_start(
    profile: &VerifiedProfile,
    generation: &GenerationSpec,
    generation_id: GenerationId,
    account_db_sha256: String,
    workload: &WorkloadSpec,
    stdin_bytes: u64,
) -> Result<Start, RuntimeError> {
    let descriptor_platform = generation.descriptor_platform().map(protocol_platform);
    let config_platform = protocol_platform(generation.config_platform());
    let effective_platform = protocol_platform(generation.effective_platform());
    let start = Start {
        profile_id: profile.manifest().profile_id.clone(),
        profile_revision: profile.manifest().profile_revision.hexadecimal(),
        generation_id: hex::encode(generation_id.as_bytes()),
        descriptor_platform,
        config_platform,
        effective_platform,
        selector_policy: profile.manifest().contracts.selector_policy.clone(),
        root_layout: profile.manifest().contracts.root_layout.clone(),
        filesystem_contract: profile.manifest().contracts.filesystem.clone(),
        argv: workload.argv.clone(),
        env: workload.env.clone(),
        cwd: workload.cwd.clone(),
        uid: workload.uid,
        gid: workload.gid,
        supplementary_gids: workload.supplementary_gids.clone(),
        umask: workload.umask,
        rlimits: workload.rlimits.clone(),
        hostname: workload.hostname.clone(),
        root_read_only: workload.root_read_only,
        volumes: workload.volumes.clone(),
        terminal: false,
        network_mode: u8::from(workload.network),
        stop_signal: workload.stop_signal,
        derivation_key: hex::encode(generation.derivation_key().as_bytes()),
        account_db_sha256,
        stdin_bytes,
    };
    start.validate()?;
    Ok(start)
}

fn protocol_platform(platform: &pocket_store::Platform) -> pocket_protocol::Platform {
    pocket_protocol::Platform {
        os: platform.os().to_owned(),
        architecture: platform.architecture().to_owned(),
        variant: platform.variant().map(str::to_owned),
    }
}

fn verify_ready(ready: &Ready, workload: &WorkloadSpec) -> Result<(), RuntimeError> {
    for (field, expected, actual) in [
        ("ready.effective_uid", workload.uid, ready.effective_uid),
        ("ready.effective_gid", workload.gid, ready.effective_gid),
    ] {
        if expected != actual {
            return Err(RuntimeError::HelloMismatch {
                field,
                expected: expected.to_string(),
                actual: actual.to_string(),
            });
        }
    }
    if ready.cwd != workload.cwd {
        return Err(RuntimeError::HelloMismatch {
            field: "ready.cwd",
            expected: workload.cwd.clone(),
            actual: ready.cwd.clone(),
        });
    }
    Ok(())
}

fn observe_scaling_qualified(requested: u16) -> bool {
    let Ok(set): Result<CpuSet, _> = sched_getaffinity(Pid::from_raw(0)) else {
        return false;
    };
    let mut count = 0_u16;
    for cpu in 0..CpuSet::count() {
        let Ok(is_set) = set.is_set(cpu) else {
            return false;
        };
        if is_set {
            count = count.saturating_add(1);
        }
    }
    let Ok(cgroup) = fs::read_to_string("/proc/self/cgroup") else {
        return false;
    };
    let Ok(mountinfo) = fs::read_to_string("/proc/self/mountinfo") else {
        return false;
    };
    let Some((mountpoint, relative)) = resolve_cgroup_v2_path(&cgroup, &mountinfo) else {
        return false;
    };

    scaling_qualified_in_chain(requested, count, &mountpoint, &relative)
}

/// Walk one cgroup-v2 membership chain from the leaf towards the root and
/// require every quota on it to admit `requested` CPUs.
fn scaling_qualified_in_chain(
    requested: u16,
    affinity_cpus: u16,
    mountpoint: &Path,
    relative: &Path,
) -> bool {
    if affinity_cpus < requested {
        return false;
    }
    let mut relative = relative.to_path_buf();
    loop {
        // Stop at the cgroup-v2 root. It never exposes cpu.max -- there is no
        // parent left to be limited by -- so failing to read one there is the
        // end of the chain, not an observation failure. Treating it as a
        // failure made this report false on every ordinary host.
        if relative.as_os_str().is_empty() {
            return true;
        }
        let cpu_max_path = mountpoint.join(&relative).join("cpu.max");
        let Ok(cpu_max) = fs::read_to_string(cpu_max_path) else {
            return false;
        };
        if !scaling_qualified_from_observation(requested, affinity_cpus, &cpu_max) {
            return false;
        }
        relative.pop();
    }
}

fn scaling_qualified_from_observation(requested: u16, affinity_cpus: u16, cpu_max: &str) -> bool {
    if affinity_cpus < requested {
        return false;
    }
    let mut fields = cpu_max.split_ascii_whitespace();
    let Some(quota) = fields.next() else {
        return false;
    };
    let Some(period) = fields.next() else {
        return false;
    };
    if fields.next().is_some() {
        return false;
    }
    if quota == "max" {
        return period.parse::<u64>().is_ok_and(|value| value != 0);
    }
    let (Ok(quota), Ok(period)) = (quota.parse::<u64>(), period.parse::<u64>()) else {
        return false;
    };
    period != 0 && u128::from(quota) >= u128::from(requested) * u128::from(period)
}

fn resolve_cgroup_v2_path(cgroup: &str, mountinfo: &str) -> Option<(PathBuf, PathBuf)> {
    let mut membership = None;
    for line in cgroup.lines() {
        let mut fields = line.splitn(3, ':');
        let (Some(hierarchy), Some(controllers), Some(path)) =
            (fields.next(), fields.next(), fields.next())
        else {
            return None;
        };
        if hierarchy == "0"
            && controllers.is_empty()
            && membership
                .replace(normalized_absolute_path(path)?)
                .is_some()
        {
            return None;
        }
    }
    let membership = membership?;

    let mut selected: Option<(usize, PathBuf, PathBuf)> = None;
    for line in mountinfo.lines() {
        let (mount_fields, filesystem_fields) = line.split_once(" - ")?;
        let filesystem_type = filesystem_fields.split_ascii_whitespace().next()?;
        if filesystem_type != "cgroup2" {
            continue;
        }
        let fields = mount_fields.split_ascii_whitespace().collect::<Vec<_>>();
        if fields.len() < 6 {
            return None;
        }
        let root = normalized_absolute_path(&decode_mountinfo_path(fields[3])?)?;
        let mountpoint = normalized_absolute_path(&decode_mountinfo_path(fields[4])?)?;
        let Ok(relative) = membership.strip_prefix(&root) else {
            continue;
        };
        let depth = root.components().count();
        let candidate = (depth, mountpoint, relative.to_path_buf());
        match &selected {
            Some((selected_depth, _, _)) if *selected_depth > depth => {}
            Some((selected_depth, selected_mountpoint, selected_relative))
                if *selected_depth == depth
                    && (selected_mountpoint != &candidate.1
                        || selected_relative != &candidate.2) =>
            {
                // Multiple equally specific visible cgroup2 mounts make the
                // source of the effective quota ambiguous. Reporting false is
                // safer than selecting one based on mountinfo order.
                return None;
            }
            _ => selected = Some(candidate),
        }
    }
    selected.map(|(_, mountpoint, relative)| (mountpoint, relative))
}

fn normalized_absolute_path(value: &str) -> Option<PathBuf> {
    let path = Path::new(value);
    if !path.is_absolute() {
        return None;
    }
    for component in path.components() {
        match component {
            Component::RootDir | Component::Normal(_) => {}
            Component::Prefix(_) | Component::CurDir | Component::ParentDir => return None,
        }
    }
    Some(path.to_path_buf())
}

fn decode_mountinfo_path(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'\\' {
            decoded.push(bytes[index]);
            index += 1;
            continue;
        }
        if index + 3 >= bytes.len() {
            return None;
        }
        let mut octal = 0_u8;
        for digit in &bytes[index + 1..=index + 3] {
            if !(b'0'..=b'7').contains(digit) {
                return None;
            }
            octal = octal.checked_mul(8)?.checked_add(*digit - b'0')?;
        }
        decoded.push(octal);
        index += 4;
    }
    String::from_utf8(decoded).ok()
}

fn validate_profile_cpu_request(
    profile: &VerifiedProfile,
    requested: u16,
) -> Result<pocket_core::ValidatedCpuRequest, RuntimeError> {
    Ok(profile.cpu_profile().validate_request(requested)?)
}

fn execution_deadline(timeout: Option<Duration>) -> (Instant, Duration) {
    let duration = timeout.unwrap_or(MAX_TIMEOUT);
    (Instant::now() + duration, duration)
}

fn wait_child_until(child: &mut Child, deadline: Instant) -> std::io::Result<Option<ExitStatus>> {
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Some(status));
        }
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            return Ok(None);
        };
        if remaining.is_zero() {
            return Ok(None);
        }
        thread::sleep(remaining.min(Duration::from_millis(10)));
    }
}

fn status_text(status: ExitStatus) -> String {
    use std::os::unix::process::ExitStatusExt;
    match (status.code(), status.signal()) {
        (Some(code), _) => format!("exit {code}"),
        (_, Some(signal)) => format!("signal {signal}"),
        _ => "unknown status".to_owned(),
    }
}

/// Deliver the exact standard-input payload announced in START.
///
/// The channel is deliberately left open. A User-Mode Linux serial line hangs
/// its tty up as soon as the host descriptor disappears, and that hangup
/// discards input the kernel has already buffered but the guest has not read
/// yet. The guest instead ends the workload's standard input after exactly
/// `Start::stdin_bytes` bytes, so the host only has to keep the descriptor
/// alive until the run is torn down.
fn write_stdin(mut stream: UnixStream, bytes: &[u8]) -> Result<(), String> {
    match stream.write_all(bytes) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
        Err(error) => Err(error.to_string()),
    }
}

fn capture<R: Read>(mut reader: R, maximum: usize) -> Result<CapturedStream, String> {
    let mut bytes = Vec::with_capacity(maximum.min(64 * 1024));
    let mut total_bytes = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.to_string()),
        };
        total_bytes = total_bytes.saturating_add(count as u64);
        let remaining = maximum.saturating_sub(bytes.len());
        bytes.extend_from_slice(&buffer[..count.min(remaining)]);
    }
    Ok(CapturedStream {
        truncated: total_bytes > bytes.len() as u64,
        bytes,
        total_bytes,
    })
}

fn failure_diagnostics<const N: usize>(
    captures: [(&'static str, Option<CapturedStream>); N],
) -> String {
    const MAXIMUM_RETAINED_PER_STREAM: usize = 8 * 1024;
    let mut diagnostic = String::new();
    for (role, capture) in captures {
        let Some(capture) = capture else {
            continue;
        };
        if capture.total_bytes == 0 {
            continue;
        }
        let start = capture
            .bytes
            .len()
            .saturating_sub(MAXIMUM_RETAINED_PER_STREAM);
        let retained = String::from_utf8_lossy(&capture.bytes[start..]);
        if !diagnostic.is_empty() {
            diagnostic.push_str("; ");
        }
        diagnostic.push_str(role);
        diagnostic.push_str("(total=");
        diagnostic.push_str(&capture.total_bytes.to_string());
        if capture.truncated {
            diagnostic.push_str(", capture-truncated");
        }
        diagnostic.push_str(")=");
        diagnostic.extend(retained.chars().flat_map(char::escape_debug));
    }
    diagnostic
}

fn join_stdin(
    worker: &mut Option<JoinHandle<Result<(), String>>>,
    deadline: Instant,
) -> Result<(), RuntimeError> {
    let Some(worker) = worker.take() else {
        return Ok(());
    };
    wait_worker_finished(&worker, deadline, "stdin")?;
    worker
        .join()
        .map_err(|_| RuntimeError::StreamWorker {
            stream: "stdin",
            reason: "worker panicked".to_owned(),
        })?
        .map_err(|reason| RuntimeError::StreamWorker {
            stream: "stdin",
            reason,
        })
}

fn join_capture(
    worker: &mut Option<CaptureWorker>,
    deadline: Instant,
) -> Result<CapturedStream, RuntimeError> {
    let worker = worker
        .take()
        .ok_or_else(|| RuntimeError::invalid("capture", "capture worker already joined"))?;
    wait_worker_finished(&worker.handle, deadline, worker.role)?;
    worker
        .handle
        .join()
        .map_err(|_| RuntimeError::StreamWorker {
            stream: worker.role,
            reason: "worker panicked".to_owned(),
        })?
        .map_err(|reason| RuntimeError::StreamWorker {
            stream: worker.role,
            reason,
        })
}

fn join_capture_if_present(
    worker: &mut Option<CaptureWorker>,
    deadline: Instant,
) -> Result<Option<CapturedStream>, RuntimeError> {
    if worker.is_none() {
        return Ok(None);
    }
    join_capture(worker, deadline).map(Some)
}

fn wait_worker_finished<T>(
    worker: &JoinHandle<T>,
    deadline: Instant,
    role: &'static str,
) -> Result<(), RuntimeError> {
    while !worker.is_finished() {
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            return Err(RuntimeError::StreamWorker {
                stream: role,
                reason: "did not stop before the bounded cleanup deadline".to_owned(),
            });
        };
        if remaining.is_zero() {
            return Err(RuntimeError::StreamWorker {
                stream: role,
                reason: "did not stop before the bounded cleanup deadline".to_owned(),
            });
        }
        thread::sleep(remaining.min(Duration::from_millis(10)));
    }
    Ok(())
}

fn hash_file(path: &Path) -> Result<[u8; 32], RuntimeError> {
    let mut file = File::open(path)
        .map_err(|error| RuntimeError::io("open immutable base for hashing", path, error))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 128 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|error| RuntimeError::io("hash immutable base", path, error))?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(hasher.finalize().into())
}

fn random_id() -> Result<String, RuntimeError> {
    let mut bytes = [0_u8; RUN_ID_BYTES];
    OpenOptions::new()
        .read(true)
        .open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut bytes))
        .map_err(|error| RuntimeError::io("read opaque run ID", "/dev/urandom", error))?;
    Ok(hex::encode(bytes))
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::{
        CapturedStream, MAX_CAPTURE_BYTES, RuntimePolicy, capture, decode_mountinfo_path,
        failure_diagnostics, resolve_cgroup_v2_path, scaling_qualified_from_observation,
        scaling_qualified_in_chain, shutdown_grace_ms, validate_policy,
    };

    #[test]
    fn capture_drains_but_bounds_retained_bytes() {
        let input = vec![7_u8; 1024];
        let captured = capture(Cursor::new(input), 17).expect("capture");
        assert_eq!(captured.bytes, vec![7_u8; 17]);
        assert_eq!(captured.total_bytes, 1024);
        assert!(captured.truncated);
    }

    #[test]
    fn failure_diagnostics_are_bounded_and_escape_binary_streams() {
        let diagnostic = failure_diagnostics([(
            "console",
            Some(CapturedStream {
                bytes: [vec![b'x'; 9_000], b"\n\0panic".to_vec()].concat(),
                truncated: true,
                total_bytes: 20_000,
            }),
        )]);
        assert!(diagnostic.contains("console(total=20000, capture-truncated)="));
        assert!(diagnostic.contains("\\n\\0panic"));
        assert!(diagnostic.len() < 9_000);
    }

    #[test]
    fn runtime_policy_rejects_unbounded_capture_and_inverted_guard_timeouts() {
        let policy = RuntimePolicy {
            maximum_stdout_bytes: MAX_CAPTURE_BYTES + 1,
            ..RuntimePolicy::default()
        };
        assert!(validate_policy(policy).is_err());

        let policy = RuntimePolicy {
            guard_exit_timeout: std::time::Duration::from_secs(1),
            ..RuntimePolicy::default()
        };
        assert!(validate_policy(policy).is_err());
    }

    #[test]
    fn runtime_policy_strictly_bounds_shutdown_timing() {
        let policy = RuntimePolicy {
            execution_timeout_grace: std::time::Duration::ZERO,
            ..RuntimePolicy::default()
        };
        assert!(validate_policy(policy).is_err());

        let policy = RuntimePolicy {
            shutdown_namespace_grace: std::time::Duration::from_micros(1500),
            ..RuntimePolicy::default()
        };
        assert!(validate_policy(policy).is_err());

        let policy = RuntimePolicy {
            shutdown_namespace_grace: std::time::Duration::from_secs(601),
            shutdown_ack_timeout: std::time::Duration::from_secs(700),
            ..RuntimePolicy::default()
        };
        assert!(validate_policy(policy).is_err());

        let policy = RuntimePolicy {
            shutdown_namespace_grace: std::time::Duration::from_secs(5),
            shutdown_ack_timeout: std::time::Duration::from_secs(5),
            ..RuntimePolicy::default()
        };
        assert!(validate_policy(policy).is_err());

        assert_eq!(
            shutdown_grace_ms(std::time::Duration::from_millis(12_345)).expect("wire grace"),
            12_345
        );
    }

    /// The cgroup-v2 root never exposes `cpu.max`, so a walk that treats
    /// reading one there as an observation failure reports "unqualified" on
    /// every ordinary host. Every ancestor that can carry a quota must still
    /// be checked.
    #[test]
    fn the_quota_walk_ends_at_the_root_rather_than_failing_there() {
        let temporary = tempfile::tempdir().expect("temporary cgroup mount");
        let mountpoint = temporary.path();
        let leaf = std::path::Path::new("user.slice/user-1000.slice/session.scope");
        for ancestor in ["user.slice", "user.slice/user-1000.slice"]
            .into_iter()
            .chain(std::iter::once("user.slice/user-1000.slice/session.scope"))
        {
            let directory = mountpoint.join(ancestor);
            std::fs::create_dir_all(&directory).expect("create cgroup directory");
            std::fs::write(directory.join("cpu.max"), "max 100000\n").expect("write quota");
        }
        // The root deliberately has no cpu.max, exactly as a real mount.
        assert!(!mountpoint.join("cpu.max").exists());
        assert!(scaling_qualified_in_chain(4, 12, mountpoint, leaf));

        // Affinity narrower than the request still disqualifies.
        assert!(!scaling_qualified_in_chain(16, 12, mountpoint, leaf));

        // A quota anywhere on the chain that cannot deliver the request
        // disqualifies, however deep it sits.
        std::fs::write(mountpoint.join("user.slice/cpu.max"), "200000 100000\n")
            .expect("narrow an ancestor quota");
        assert!(!scaling_qualified_in_chain(4, 12, mountpoint, leaf));

        // A missing cpu.max below the root is a real observation failure.
        std::fs::remove_file(mountpoint.join("user.slice/user-1000.slice/cpu.max"))
            .expect("remove an intermediate quota");
        assert!(!scaling_qualified_in_chain(2, 12, mountpoint, leaf));
    }

    #[test]
    fn host_capacity_is_reporting_and_never_a_cpu_admission_clamp() {
        assert!(!scaling_qualified_from_observation(4, 2, "max 100000"));
        assert!(!scaling_qualified_from_observation(4, 8, "200000 100000"));
        assert!(scaling_qualified_from_observation(4, 8, "400000 100000"));
        assert!(scaling_qualified_from_observation(4, 4, "max 100000"));
    }

    #[test]
    fn nested_cgroup_v2_membership_resolves_beneath_the_matching_mount() {
        let cgroup = "0::/user.slice/user-1000.slice/session-2.scope\n";
        let mountinfo = concat!(
            "20 19 0:19 / /proc rw - proc proc rw\n",
            "21 19 0:20 / /sys/fs/cgroup rw - cgroup2 cgroup rw\n",
        );
        let (mountpoint, relative) =
            resolve_cgroup_v2_path(cgroup, mountinfo).expect("resolve cgroup2 path");
        assert_eq!(mountpoint, std::path::Path::new("/sys/fs/cgroup"));
        assert_eq!(
            relative,
            std::path::Path::new("user.slice/user-1000.slice/session-2.scope")
        );
    }

    #[test]
    fn cgroup_v2_bind_mount_root_is_removed_from_membership() {
        let cgroup = "0::/user.slice/session-2.scope\n";
        let mountinfo = concat!(
            "21 19 0:20 / /sys/fs/cgroup-all rw - cgroup2 cgroup rw\n",
            "22 19 0:20 /user.slice /sys/fs/cgroup rw - cgroup2 cgroup rw\n",
        );
        let (mountpoint, relative) =
            resolve_cgroup_v2_path(cgroup, mountinfo).expect("resolve most specific mount");
        assert_eq!(mountpoint, std::path::Path::new("/sys/fs/cgroup"));
        assert_eq!(relative, std::path::Path::new("session-2.scope"));
    }

    #[test]
    fn cgroup_v2_resolution_fails_closed_for_ambiguous_or_escaping_paths() {
        let ambiguous = concat!(
            "21 19 0:20 / /sys/fs/cgroup-a rw - cgroup2 cgroup rw\n",
            "22 19 0:20 / /sys/fs/cgroup-b rw - cgroup2 cgroup rw\n",
        );
        assert!(resolve_cgroup_v2_path("0::/nested\n", ambiguous).is_none());
        assert!(resolve_cgroup_v2_path("0::/../nested\n", ambiguous).is_none());
        assert_eq!(
            decode_mountinfo_path("/sys/fs/cgroup\\040space").as_deref(),
            Some("/sys/fs/cgroup space")
        );
        assert!(decode_mountinfo_path("/bad\\escape").is_none());
    }
}
