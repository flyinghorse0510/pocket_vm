#![cfg(target_os = "linux")]

mod linux;

use std::collections::HashSet;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::time::{Duration, Instant};

use nix::libc;
use thiserror::Error;

pub const GUARD_ERROR_EXIT_CODE: i32 = 125;
const MAX_TERM_TIMEOUT: Duration = Duration::from_secs(600);

#[derive(Debug)]
pub struct GuardOptions {
    /// Expected direct parent. The caller must arrange for the guard process
    /// to be a direct child of this PID.
    pub supervisor_pid: libc::pid_t,
    /// Ownership of each optional raw descriptor is transferred to this
    /// process-lifetime API. Descriptors 0, 1, and 2 are always retained.
    pub liveness_fd: Option<RawFd>,
    pub lease_fd: Option<RawFd>,
    pub inherited_fds: Vec<RawFd>,
    pub term_timeout: Duration,
    /// Establish Linux's no-randomize personality before executing UML. This
    /// is required when a dynamic UML is invoked through a bundled loader,
    /// because UML must not re-exec `/proc/self/exe` (the loader in that form).
    pub uml_personality: bool,
    pub command: Vec<OsString>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChildOutcome {
    Exited(u8),
    Signaled(libc::c_int),
}

impl ChildOutcome {
    #[must_use]
    pub fn conventional_exit_code(self) -> i32 {
        match self {
            Self::Exited(code) => i32::from(code),
            Self::Signaled(signal) => 128 + signal,
        }
    }

    fn from_wait_status(status: libc::c_int) -> Result<Self, GuardError> {
        if libc::WIFEXITED(status) {
            return Ok(Self::Exited(libc::WEXITSTATUS(status) as u8));
        }
        if libc::WIFSIGNALED(status) {
            return Ok(Self::Signaled(libc::WTERMSIG(status)));
        }
        Err(GuardError::Lifecycle(format!(
            "child produced non-terminal wait status {status:#x}"
        )))
    }
}

#[derive(Debug, Error)]
pub enum GuardError {
    #[error("invalid guard configuration: {0}")]
    InvalidConfiguration(String),

    #[error("{operation}: {source}")]
    System {
        operation: &'static str,
        #[source]
        source: io::Error,
    },

    #[error("could not execute child program {program:?}: {source}")]
    Spawn {
        program: OsString,
        #[source]
        source: io::Error,
    },

    #[error("guard lifecycle failure: {0}")]
    Lifecycle(String),
}

impl GuardError {
    fn system(operation: &'static str, source: io::Error) -> Self {
        Self::System { operation, source }
    }
}

struct OwnedInputs {
    liveness: Option<OwnedFd>,
    lease: Option<OwnedFd>,
    inherited: Vec<OwnedFd>,
}

/// Run the process-lifetime guard until its complete child tree has exited.
///
/// # Safety
///
/// Every raw descriptor in `options` must be open, uniquely owned by the
/// caller, and transferred to this function. The guard closes those
/// descriptors during normal operation or when this function returns. The
/// process must be single-threaded because this function changes the process
/// signal mask and installs post-fork child setup.
pub unsafe fn run_guard(options: GuardOptions) -> Result<ChildOutcome, GuardError> {
    validate_supervisor_pid(options.supervisor_pid)?;

    linux::arm_parent_death(options.supervisor_pid).map_err(|error| {
        GuardError::system(
            "could not establish supervisor parent-death contract",
            error,
        )
    })?;
    validate_options(&options)?;
    linux::become_child_subreaper()
        .map_err(|error| GuardError::system("could not become a child subreaper", error))?;

    // Requiring this procfs view makes cleanup of descendants which create a
    // new process group explicit rather than pretending killpg is exhaustive.
    read_immediate_children()
        .map_err(|error| GuardError::system("could not inspect subreaper children", error))?;

    let mut retained_fds =
        HashSet::from([libc::STDIN_FILENO, libc::STDOUT_FILENO, libc::STDERR_FILENO]);
    retained_fds.extend(options.liveness_fd);
    retained_fds.extend(options.lease_fd);
    retained_fds.extend(options.inherited_fds.iter().copied());
    close_unintended_guard_fds(&retained_fds)
        .map_err(|error| GuardError::system("could not close unintended guard FDs", error))?;

    let signal_fd = linux::SignalFd::block_and_create()
        .map_err(|error| GuardError::system("could not establish signalfd", error))?;

    let mut inputs = take_owned_inputs(&options)?;
    if let Some(liveness) = inputs.liveness.as_ref() {
        linux::set_nonblocking(liveness.as_raw_fd())
            .map_err(|error| GuardError::system("could not make liveness FD nonblocking", error))?;
    }

    let guard_pid = linux::current_pid();
    let fallback_fd_limit = linux::open_fd_limit()
        .map_err(|error| GuardError::system("could not read RLIMIT_NOFILE", error))?;
    let mut child_fds = vec![libc::STDIN_FILENO, libc::STDOUT_FILENO, libc::STDERR_FILENO];
    child_fds.extend(inputs.inherited.iter().map(AsRawFd::as_raw_fd));
    let uml_personality = options.uml_personality;

    let program = options.command[0].clone();
    let mut command = Command::new(&program);
    command.args(&options.command[1..]);

    // SAFETY: the closure calls only `prepare_command_child`, whose contract
    // documents and enforces its post-fork async-signal-safe operation set.
    unsafe {
        command.pre_exec(move || {
            linux::prepare_command_child(guard_pid, &child_fds, fallback_fd_limit, uml_personality)
        });
    }

    let child = command
        .spawn()
        .map_err(|source| GuardError::Spawn { program, source })?;
    let child_pid = child.id() as libc::pid_t;

    // The child now owns the explicitly inherited descriptors. Closing the
    // guard copies is required for correct pipe/socket EOF behavior.
    inputs.inherited.clear();

    let pidfd = match linux::open_pidfd(child_pid) {
        Ok(Some(fd)) => Some(fd),
        Ok(None) => {
            eprintln!(
                "pocket-guard: pidfd unavailable for child {child_pid}; using waitpid fallback"
            );
            None
        }
        Err(error) => {
            eprintln!(
                "pocket-guard: pidfd_open failed for child {child_pid}: {error}; using waitpid fallback"
            );
            None
        }
    };

    let mut engine = Engine {
        child_pid,
        direct_outcome: None,
        pidfd,
        signal_fd,
        liveness: inputs.liveness.take(),
        _lease: inputs.lease.take(),
        term_timeout: options.term_timeout,
        shutdown: None,
        infrastructure_failure: None,
    };

    let result = match engine.run() {
        Ok(outcome) => Ok(outcome),
        Err(error) => match engine.kill_and_reap_after_failure() {
            Ok(()) => Err(error),
            Err(cleanup_error) => Err(GuardError::Lifecycle(format!(
                "{error}; emergency child cleanup also failed: {cleanup_error}"
            ))),
        },
    };
    // `waitpid` in the engine owns all reaping. Child::try_wait/wait must not
    // race it; dropping Child performs no kill or reap on Unix.
    drop(child);
    result
}

fn validate_options(options: &GuardOptions) -> Result<(), GuardError> {
    validate_supervisor_pid(options.supervisor_pid)?;

    if options.command.is_empty() || options.command[0].is_empty() {
        return Err(GuardError::InvalidConfiguration(
            "a non-empty program must follow `--`".to_owned(),
        ));
    }
    if options.term_timeout > MAX_TERM_TIMEOUT {
        return Err(GuardError::InvalidConfiguration(format!(
            "termination timeout exceeds {} milliseconds",
            MAX_TERM_TIMEOUT.as_millis()
        )));
    }

    let mut seen = HashSet::new();
    for (role, fd) in options
        .liveness_fd
        .map(|fd| ("liveness", fd))
        .into_iter()
        .chain(options.lease_fd.map(|fd| ("lease", fd)))
        .chain(
            options
                .inherited_fds
                .iter()
                .copied()
                .map(|fd| ("inherited", fd)),
        )
    {
        if fd < 3 {
            return Err(GuardError::InvalidConfiguration(format!(
                "{role} FD {fd} must be at least 3; standard streams are inherited automatically"
            )));
        }
        if !seen.insert(fd) {
            return Err(GuardError::InvalidConfiguration(format!(
                "FD {fd} is assigned more than once"
            )));
        }
        linux::fd_is_open(fd)
            .map_err(|error| GuardError::system("an inherited guard FD is not open", error))?;
    }

    Ok(())
}

fn validate_supervisor_pid(supervisor_pid: libc::pid_t) -> Result<(), GuardError> {
    if supervisor_pid <= 0 {
        return Err(GuardError::InvalidConfiguration(
            "--supervisor-pid must be positive".to_owned(),
        ));
    }
    Ok(())
}

fn take_owned_inputs(options: &GuardOptions) -> Result<OwnedInputs, GuardError> {
    // validate_options proved that these descriptors are open, unique, and
    // non-stdio. This function consumes their ownership for the guard process.
    let liveness = options.liveness_fd.map(|fd| {
        // SAFETY: ownership of each inherited raw descriptor is transferred to
        // run_guard exactly once by GuardOptions' API contract.
        unsafe { OwnedFd::from_raw_fd(fd) }
    });
    let lease = options.lease_fd.map(|fd| {
        // SAFETY: see the ownership argument above.
        unsafe { OwnedFd::from_raw_fd(fd) }
    });
    let inherited = options
        .inherited_fds
        .iter()
        .copied()
        .map(|fd| {
            // SAFETY: see the ownership argument above.
            unsafe { OwnedFd::from_raw_fd(fd) }
        })
        .collect();
    Ok(OwnedInputs {
        liveness,
        lease,
        inherited,
    })
}

fn close_unintended_guard_fds(retained: &HashSet<RawFd>) -> io::Result<()> {
    let mut candidates = Vec::new();
    for entry in fs::read_dir("/proc/self/fd")? {
        let entry = entry?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Ok(fd) = name.parse::<RawFd>() else {
            continue;
        };
        if fd >= 0 && !retained.contains(&fd) {
            candidates.push(fd);
        }
    }

    // The read_dir iterator and its own descriptor are gone before closing.
    candidates.sort_unstable();
    candidates.dedup();
    for fd in candidates {
        // SAFETY: fd was discovered through procfs and is not retained. Linux
        // closes the descriptor even if close reports EINTR, so it is not
        // retried and cannot accidentally close a reused descriptor.
        if unsafe { libc::close(fd) } == -1 {
            let error = io::Error::last_os_error();
            if !matches!(error.raw_os_error(), Some(libc::EBADF | libc::EINTR)) {
                return Err(error);
            }
        }
    }
    Ok(())
}

struct Shutdown {
    graceful_signal: libc::c_int,
    deadline: Instant,
    escalated: bool,
    signaled_children: HashSet<libc::pid_t>,
}

struct Engine {
    child_pid: libc::pid_t,
    direct_outcome: Option<ChildOutcome>,
    pidfd: Option<OwnedFd>,
    signal_fd: linux::SignalFd,
    liveness: Option<OwnedFd>,
    _lease: Option<OwnedFd>,
    term_timeout: Duration,
    shutdown: Option<Shutdown>,
    infrastructure_failure: Option<String>,
}

impl Engine {
    fn run(&mut self) -> Result<ChildOutcome, GuardError> {
        loop {
            let no_children = self.reap_all()?;

            if self.direct_outcome.is_some() && self.shutdown.is_none() && !no_children {
                self.begin_shutdown(libc::SIGTERM);
            }

            if self.direct_outcome.is_some() && no_children {
                let outcome = self.direct_outcome.ok_or_else(|| {
                    GuardError::Lifecycle("direct child outcome disappeared".to_owned())
                })?;
                if let Some(failure) = self.infrastructure_failure.take() {
                    return Err(GuardError::Lifecycle(failure));
                }
                return Ok(outcome);
            }

            if self.direct_outcome.is_none() && no_children {
                return Err(GuardError::Lifecycle(
                    "direct child disappeared without a wait status".to_owned(),
                ));
            }

            self.signal_newly_adopted_children();
            self.maybe_escalate();

            let timeout_ms = self.poll_timeout_ms();
            let mut pollfds = Vec::with_capacity(3);
            pollfds.push(libc::pollfd {
                fd: self.signal_fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            });
            let liveness_index = self.liveness.as_ref().map(|fd| {
                let index = pollfds.len();
                pollfds.push(libc::pollfd {
                    fd: fd.as_raw_fd(),
                    events: libc::POLLIN | libc::POLLHUP | libc::POLLERR,
                    revents: 0,
                });
                index
            });
            let pidfd_index = self.pidfd.as_ref().map(|fd| {
                let index = pollfds.len();
                pollfds.push(libc::pollfd {
                    fd: fd.as_raw_fd(),
                    events: libc::POLLIN | libc::POLLHUP | libc::POLLERR,
                    revents: 0,
                });
                index
            });

            linux::poll(&mut pollfds, timeout_ms)
                .map_err(|error| GuardError::system("poll failed", error))?;

            if pollfds[0].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0 {
                self.handle_signals()?;
            }

            if let Some(index) = liveness_index {
                let events = pollfds[index].revents;
                if events & libc::POLLNVAL != 0 {
                    self.record_failure("liveness FD became invalid".to_owned());
                    self.liveness.take();
                    self.begin_shutdown(libc::SIGTERM);
                } else if events & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0 {
                    let fd = self
                        .liveness
                        .as_ref()
                        .map(AsRawFd::as_raw_fd)
                        .ok_or_else(|| {
                            GuardError::Lifecycle("liveness FD disappeared".to_owned())
                        })?;
                    match linux::read_liveness(fd) {
                        Ok(true) => {
                            self.liveness.take();
                            self.begin_shutdown(libc::SIGTERM);
                        }
                        Ok(false) => {}
                        Err(error) => {
                            self.record_failure(format!("liveness FD read failed: {error}"));
                            self.liveness.take();
                            self.begin_shutdown(libc::SIGTERM);
                        }
                    }
                }
            }

            if let Some(index) = pidfd_index
                && pollfds[index].revents
                    & (libc::POLLIN | libc::POLLHUP | libc::POLLERR | libc::POLLNVAL)
                    != 0
            {
                // Readiness is only a race-free notification. waitpid is
                // still the sole source of status and the sole reaper.
                self.pidfd.take();
            }
        }
    }

    fn reap_all(&mut self) -> Result<bool, GuardError> {
        loop {
            match linux::reap_one().map_err(|error| GuardError::system("waitpid failed", error))? {
                linux::ReapedChild::Exited { pid, status } => {
                    if pid == self.child_pid {
                        self.direct_outcome = Some(ChildOutcome::from_wait_status(status)?);
                        self.pidfd.take();
                    }
                }
                linux::ReapedChild::NoExitedChild => return Ok(false),
                linux::ReapedChild::NoChildren => return Ok(true),
            }
        }
    }

    fn handle_signals(&mut self) -> Result<(), GuardError> {
        let signals = self
            .signal_fd
            .read_pending()
            .map_err(|error| GuardError::system("signalfd read failed", error))?;
        for signal in signals {
            match signal {
                libc::SIGCHLD => {}
                libc::SIGTERM | libc::SIGINT | libc::SIGHUP | libc::SIGQUIT => {
                    if self.shutdown.is_none() {
                        self.begin_shutdown(signal);
                    } else if !self.shutdown.as_ref().is_some_and(|state| state.escalated) {
                        self.escalate();
                    }
                }
                _ => {
                    self.record_failure(format!(
                        "received unexpected signal {signal} through signalfd"
                    ));
                    self.begin_shutdown(libc::SIGTERM);
                }
            }
        }
        Ok(())
    }

    fn begin_shutdown(&mut self, graceful_signal: libc::c_int) {
        if self.shutdown.is_some() {
            return;
        }
        let mut shutdown = Shutdown {
            graceful_signal,
            deadline: Instant::now() + self.term_timeout,
            escalated: false,
            signaled_children: HashSet::new(),
        };
        if let Err(error) = linux::send_signal_to_group(self.child_pid, graceful_signal) {
            self.record_failure(format!(
                "could not forward signal {graceful_signal} to child process group {}: {error}",
                self.child_pid
            ));
        }
        self.signal_immediate_children(&mut shutdown);
        self.shutdown = Some(shutdown);
        if self.term_timeout.is_zero() {
            self.escalate();
        }
    }

    fn signal_newly_adopted_children(&mut self) {
        let Some(mut shutdown) = self.shutdown.take() else {
            return;
        };
        self.signal_immediate_children(&mut shutdown);
        self.shutdown = Some(shutdown);
    }

    fn signal_immediate_children(&mut self, shutdown: &mut Shutdown) {
        let children = match read_immediate_children() {
            Ok(children) => children,
            Err(error) => {
                self.record_failure(format!("could not enumerate adopted children: {error}"));
                return;
            }
        };
        let signal = if shutdown.escalated {
            libc::SIGKILL
        } else {
            shutdown.graceful_signal
        };
        for pid in children {
            if !shutdown.signaled_children.insert(pid) {
                continue;
            }
            if let Err(error) = linux::send_signal_to_process(pid, signal) {
                self.record_failure(format!(
                    "could not send signal {signal} to adopted child {pid}: {error}"
                ));
            }
        }
    }

    fn maybe_escalate(&mut self) {
        if self
            .shutdown
            .as_ref()
            .is_some_and(|state| !state.escalated && Instant::now() >= state.deadline)
        {
            self.escalate();
        }
    }

    fn escalate(&mut self) {
        let Some(mut shutdown) = self.shutdown.take() else {
            return;
        };
        if shutdown.escalated {
            self.shutdown = Some(shutdown);
            return;
        }
        shutdown.escalated = true;
        shutdown.signaled_children.clear();
        if let Err(error) = linux::send_signal_to_group(self.child_pid, libc::SIGKILL) {
            self.record_failure(format!(
                "could not send SIGKILL to child process group {}: {error}",
                self.child_pid
            ));
        }
        self.signal_immediate_children(&mut shutdown);
        self.shutdown = Some(shutdown);
    }

    fn poll_timeout_ms(&self) -> libc::c_int {
        let Some(shutdown) = self.shutdown.as_ref() else {
            return -1;
        };
        if shutdown.escalated {
            return -1;
        }
        let remaining = shutdown.deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return 0;
        }
        remaining.as_millis().min(libc::c_int::MAX as u128) as libc::c_int
    }

    fn record_failure(&mut self, failure: String) {
        eprintln!("pocket-guard: {failure}");
        if self.infrastructure_failure.is_none() {
            self.infrastructure_failure = Some(failure);
        }
    }

    fn kill_and_reap_after_failure(&mut self) -> Result<(), String> {
        let mut failures = Vec::new();
        if let Err(error) = linux::send_signal_to_group(self.child_pid, libc::SIGKILL) {
            failures.push(format!(
                "could not send SIGKILL to child process group {}: {error}",
                self.child_pid
            ));
        }

        loop {
            let children = match read_immediate_children() {
                Ok(children) => children,
                Err(error) => {
                    failures.push(format!(
                        "could not enumerate children during emergency cleanup: {error}"
                    ));
                    break;
                }
            };
            for pid in children {
                if let Err(error) = linux::send_signal_to_process(pid, libc::SIGKILL) {
                    failures.push(format!(
                        "could not send SIGKILL to child {pid} during emergency cleanup: {error}"
                    ));
                }
            }

            match linux::reap_one_blocking() {
                Ok(Some(_)) => {}
                Ok(None) => break,
                Err(error) => {
                    failures.push(format!("waitpid failed during emergency cleanup: {error}"));
                    break;
                }
            }
        }

        if failures.is_empty() {
            Ok(())
        } else {
            Err(failures.join("; "))
        }
    }
}

fn read_immediate_children() -> io::Result<Vec<libc::pid_t>> {
    let path = format!("/proc/self/task/{}/children", linux::current_pid());
    let contents = fs::read_to_string(path)?;
    contents
        .split_ascii_whitespace()
        .map(|value| {
            value.parse::<libc::pid_t>().map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid PID {value:?} in procfs children list: {error}"),
                )
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_convention_is_stable() {
        assert_eq!(ChildOutcome::Exited(0).conventional_exit_code(), 0);
        assert_eq!(ChildOutcome::Exited(125).conventional_exit_code(), 125);
        assert_eq!(
            ChildOutcome::Signaled(libc::SIGTERM).conventional_exit_code(),
            143
        );
    }

    #[test]
    fn rejects_empty_command() {
        let error = validate_options(&GuardOptions {
            supervisor_pid: linux::current_parent_pid(),
            liveness_fd: None,
            lease_fd: None,
            inherited_fds: Vec::new(),
            term_timeout: Duration::from_secs(1),
            uml_personality: false,
            command: Vec::new(),
        })
        .expect_err("empty command must fail");
        assert!(error.to_string().contains("non-empty program"));
    }

    #[test]
    fn rejects_duplicate_descriptor_roles() {
        let error = validate_options(&GuardOptions {
            supervisor_pid: linux::current_parent_pid(),
            liveness_fd: Some(libc::STDERR_FILENO),
            lease_fd: Some(libc::STDERR_FILENO),
            inherited_fds: Vec::new(),
            term_timeout: Duration::from_secs(1),
            uml_personality: false,
            command: vec![OsString::from("/bin/true")],
        })
        .expect_err("stdio descriptors must fail before duplicate validation");
        assert!(error.to_string().contains("at least 3"));
    }
}
