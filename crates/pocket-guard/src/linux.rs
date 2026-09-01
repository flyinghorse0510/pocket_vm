//! Small Linux-specific primitives used by the guard.
//!
//! The child setup routine is called through `CommandExt::pre_exec`, after
//! `fork(2)` and before `execve(2)`. It therefore uses only Linux syscalls and
//! libc wrappers documented as async-signal-safe: `prctl`, `getppid`,
//! `setpgid`, `sigprocmask`, `close_range`, and `fcntl`. It neither allocates
//! nor locks. All vectors and limits it reads are prepared in the parent.

use std::io;
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use nix::libc;

const CLOSE_RANGE_CLOEXEC: libc::c_uint = 1 << 2;
const PERSONALITY_QUERY: libc::c_ulong = 0xffff_ffff;
const PER_LINUX: libc::c_ulong = 0;
const ADDR_NO_RANDOMIZE: libc::c_ulong = 0x0004_0000;

pub(crate) const GUARDED_SIGNALS: [libc::c_int; 5] = [
    libc::SIGCHLD,
    libc::SIGTERM,
    libc::SIGINT,
    libc::SIGHUP,
    libc::SIGQUIT,
];

pub(crate) fn current_pid() -> libc::pid_t {
    // SAFETY: getpid has no preconditions and cannot fail.
    unsafe { libc::getpid() }
}

pub(crate) fn current_parent_pid() -> libc::pid_t {
    // SAFETY: getppid has no preconditions and cannot fail.
    unsafe { libc::getppid() }
}

pub(crate) fn arm_parent_death(expected_parent: libc::pid_t) -> io::Result<()> {
    // SAFETY: PR_SET_PDEATHSIG accepts an integer signal value. No pointer is
    // passed, and SIGKILL is valid.
    if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) } == -1 {
        return Err(io::Error::last_os_error());
    }

    let actual_parent = current_parent_pid();
    if actual_parent != expected_parent {
        return Err(io::Error::other(format!(
            "supervisor changed before parent-death protection was armed: expected {expected_parent}, got {actual_parent}"
        )));
    }

    Ok(())
}

pub(crate) fn become_child_subreaper() -> io::Result<()> {
    // SAFETY: PR_SET_CHILD_SUBREAPER takes an integer boolean and no pointer.
    if unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub(crate) fn fd_is_open(fd: RawFd) -> io::Result<()> {
    // SAFETY: F_GETFD does not dereference the third variadic argument and is
    // valid for any integer descriptor.
    let result = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if result == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub(crate) fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    // SAFETY: Both fcntl commands operate only on the supplied descriptor.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: F_SETFL accepts the existing flags combined with O_NONBLOCK.
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub(crate) fn open_fd_limit() -> io::Result<RawFd> {
    let mut limit = MaybeUninit::<libc::rlimit>::uninit();
    // SAFETY: `limit` points to writable storage for one rlimit structure.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, limit.as_mut_ptr()) } == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: getrlimit succeeded and initialized `limit`.
    let limit = unsafe { limit.assume_init() };
    let maximum = if limit.rlim_cur == libc::RLIM_INFINITY {
        1_048_576_u64
    } else {
        limit.rlim_cur
    };
    Ok(maximum.min(i32::MAX as u64) as RawFd)
}

pub(crate) struct SignalFd {
    fd: OwnedFd,
}

impl SignalFd {
    pub(crate) fn block_and_create() -> io::Result<Self> {
        let mut mask = MaybeUninit::<libc::sigset_t>::uninit();
        // SAFETY: mask points to writable sigset_t storage.
        if unsafe { libc::sigemptyset(mask.as_mut_ptr()) } == -1 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: sigemptyset initialized the set.
        let mut mask = unsafe { mask.assume_init() };
        for signal in GUARDED_SIGNALS {
            // SAFETY: mask is initialized and every signal is valid.
            if unsafe { libc::sigaddset(&mut mask, signal) } == -1 {
                return Err(io::Error::last_os_error());
            }
        }

        // SAFETY: both pointers refer to valid sigset_t values (the old-mask
        // output is intentionally unused).
        let result = unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &mask, std::ptr::null_mut()) };
        if result != 0 {
            return Err(io::Error::from_raw_os_error(result));
        }

        // SAFETY: mask remains valid for the duration of this call. Passing -1
        // requests a new descriptor.
        let fd = unsafe { libc::signalfd(-1, &mask, libc::SFD_CLOEXEC | libc::SFD_NONBLOCK) };
        if fd == -1 {
            return Err(io::Error::last_os_error());
        }

        // SAFETY: signalfd returned a new owned descriptor.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        Ok(Self { fd })
    }

    pub(crate) fn read_pending(&self) -> io::Result<Vec<libc::c_int>> {
        let mut signals = Vec::new();
        loop {
            let mut info = MaybeUninit::<libc::signalfd_siginfo>::uninit();
            // SAFETY: info points to writable storage of the requested size.
            let count = unsafe {
                libc::read(
                    self.fd.as_raw_fd(),
                    info.as_mut_ptr().cast(),
                    size_of::<libc::signalfd_siginfo>(),
                )
            };
            if count == size_of::<libc::signalfd_siginfo>() as isize {
                // SAFETY: read initialized the complete structure.
                let info = unsafe { info.assume_init() };
                signals.push(info.ssi_signo as libc::c_int);
                continue;
            }
            if count == -1 {
                let error = io::Error::last_os_error();
                match error.raw_os_error() {
                    Some(libc::EAGAIN) => return Ok(signals),
                    Some(libc::EINTR) => continue,
                    _ => return Err(error),
                }
            }
            if count == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "signalfd reached EOF",
                ));
            }
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("short signalfd read: {count}"),
            ));
        }
    }
}

impl AsRawFd for SignalFd {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

/// Prepare the one command child between fork and exec.
///
/// # Safety
///
/// This function must run only in a freshly forked, single-threaded child. It
/// invokes only async-signal-safe libc/syscall operations and reads immutable
/// parent-prepared data. It must not allocate, format, log, or acquire locks.
pub(crate) unsafe fn prepare_command_child(
    expected_parent: libc::pid_t,
    inherited_fds: &[RawFd],
    fallback_fd_limit: RawFd,
    uml_personality: bool,
) -> io::Result<()> {
    // SAFETY: PR_SET_PDEATHSIG accepts the integer SIGKILL argument.
    if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) } == -1 {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: getppid has no preconditions.
    if unsafe { libc::getppid() } != expected_parent {
        return Err(io::Error::from_raw_os_error(libc::ESRCH));
    }

    // Becoming a process-group leader before exec deliberately makes UML's
    // later setsid(2) fail with EPERM, retaining a guard-owned kill target.
    // SAFETY: setpgid(0, 0) targets this process only.
    if unsafe { libc::setpgid(0, 0) } == -1 {
        return Err(io::Error::last_os_error());
    }

    let mut empty_mask = MaybeUninit::<libc::sigset_t>::uninit();
    // SAFETY: empty_mask points to writable sigset_t storage.
    if unsafe { libc::sigemptyset(empty_mask.as_mut_ptr()) } == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: sigemptyset initialized the value and sigprocmask accepts it.
    if unsafe { libc::sigprocmask(libc::SIG_SETMASK, empty_mask.as_ptr(), std::ptr::null_mut()) }
        == -1
    {
        return Err(io::Error::last_os_error());
    }

    // Mark every non-stdio descriptor close-on-exec. This deliberately keeps
    // Rust's private exec-error pipe usable until exec while ensuring it closes
    // on successful exec. Explicit child descriptors are cleared below.
    // SAFETY: close_range receives scalar arguments and no pointers.
    let close_range_result =
        unsafe { libc::syscall(libc::SYS_close_range, 3_u32, u32::MAX, CLOSE_RANGE_CLOEXEC) };
    if close_range_result == -1 {
        let error = io::Error::last_os_error();
        match error.raw_os_error() {
            Some(libc::ENOSYS | libc::EINVAL) => {
                let mut fd = 3;
                while fd < fallback_fd_limit {
                    // SAFETY: F_GETFD/F_SETFD operate only on fd.
                    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
                    if flags >= 0 {
                        // SAFETY: flags came from F_GETFD for this descriptor.
                        if unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } == -1
                        {
                            return Err(io::Error::last_os_error());
                        }
                    } else {
                        let get_error = io::Error::last_os_error();
                        if get_error.raw_os_error() != Some(libc::EBADF) {
                            return Err(get_error);
                        }
                    }
                    fd += 1;
                }
            }
            _ => return Err(error),
        }
    }

    for &fd in inherited_fds {
        // SAFETY: F_GETFD/F_SETFD operate only on an already validated fd.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags == -1 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: flags came from F_GETFD for this descriptor.
        if unsafe { libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) } == -1 {
            return Err(io::Error::last_os_error());
        }
    }

    if uml_personality {
        // A dynamic UML invoked through ld.so observes the loader at
        // /proc/self/exe. Establishing the final personality here makes UML
        // skip its otherwise destructive readlink-and-reexec path.
        // SAFETY: personality takes and returns only scalar values.
        if unsafe { libc::syscall(libc::SYS_personality, PER_LINUX | ADDR_NO_RANDOMIZE) } == -1 {
            return Err(io::Error::last_os_error());
        }
        // Query and verify instead of assuming the host accepted every bit.
        // SAFETY: PERSONALITY_QUERY is Linux's documented query sentinel.
        let current = unsafe { libc::syscall(libc::SYS_personality, PERSONALITY_QUERY) };
        if current == -1 {
            return Err(io::Error::last_os_error());
        }
        if (current as libc::c_ulong & ADDR_NO_RANDOMIZE) == 0 {
            return Err(io::Error::from_raw_os_error(libc::EPERM));
        }
    }

    Ok(())
}

pub(crate) fn open_pidfd(pid: libc::pid_t) -> io::Result<Option<OwnedFd>> {
    // SAFETY: pidfd_open accepts scalar pid and flags arguments.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0_u32) };
    if fd >= 0 {
        // SAFETY: pidfd_open returned a new owned descriptor.
        return Ok(Some(unsafe { OwnedFd::from_raw_fd(fd as RawFd) }));
    }

    let error = io::Error::last_os_error();
    match error.raw_os_error() {
        Some(libc::ENOSYS | libc::EINVAL | libc::EPERM | libc::EACCES | libc::ESRCH) => Ok(None),
        _ => Err(error),
    }
}

pub(crate) fn send_signal_to_group(
    process_group: libc::pid_t,
    signal: libc::c_int,
) -> io::Result<()> {
    // SAFETY: a negative PID addresses the corresponding process group.
    if unsafe { libc::kill(-process_group, signal) } == -1 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ESRCH) {
            return Err(error);
        }
    }
    Ok(())
}

pub(crate) fn send_signal_to_process(pid: libc::pid_t, signal: libc::c_int) -> io::Result<()> {
    // SAFETY: kill accepts scalar pid and signal arguments.
    if unsafe { libc::kill(pid, signal) } == -1 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ESRCH) {
            return Err(error);
        }
    }
    Ok(())
}

pub(crate) fn poll(fds: &mut [libc::pollfd], timeout_ms: libc::c_int) -> io::Result<()> {
    loop {
        // SAFETY: fds references `fds.len()` initialized pollfd structures.
        let result = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout_ms) };
        if result >= 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EINTR) {
            return Err(error);
        }
    }
}

pub(crate) fn read_liveness(fd: RawFd) -> io::Result<bool> {
    let mut buffer = [0_u8; 256];
    loop {
        // SAFETY: buffer is writable for buffer.len() bytes.
        let count = unsafe { libc::read(fd, buffer.as_mut_ptr().cast(), buffer.len()) };
        if count > 0 {
            continue;
        }
        if count == 0 {
            return Ok(true);
        }
        let error = io::Error::last_os_error();
        match error.raw_os_error() {
            Some(libc::EAGAIN) => return Ok(false),
            Some(libc::EINTR) => continue,
            _ => return Err(error),
        }
    }
}

pub(crate) enum ReapedChild {
    Exited {
        pid: libc::pid_t,
        status: libc::c_int,
    },
    NoExitedChild,
    NoChildren,
}

pub(crate) fn reap_one() -> io::Result<ReapedChild> {
    loop {
        let mut status = 0;
        // SAFETY: status points to writable integer storage. -1 selects any
        // child and WNOHANG makes the operation nonblocking.
        let pid = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
        if pid > 0 {
            return Ok(ReapedChild::Exited { pid, status });
        }
        if pid == 0 {
            return Ok(ReapedChild::NoExitedChild);
        }
        let error = io::Error::last_os_error();
        match error.raw_os_error() {
            Some(libc::ECHILD) => return Ok(ReapedChild::NoChildren),
            Some(libc::EINTR) => {}
            _ => return Err(error),
        }
    }
}

/// Create a close-on-exec pipe, returned as (read, write).
pub(crate) fn create_pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: pipe2 writes exactly two descriptors into the provided array.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: both descriptors were just created and are uniquely owned here.
    unsafe { Ok((OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1]))) }
}

/// Reap `pid` if it has already exited. `Ok(false)` means still running.
pub(crate) fn reap_specific_nonblocking(pid: libc::pid_t) -> io::Result<bool> {
    let mut status: libc::c_int = 0;
    // SAFETY: waitpid writes only through the provided status pointer.
    let observed = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
    if observed == -1 {
        let error = io::Error::last_os_error();
        // Already reaped, or never ours: either way there is nothing to wait for.
        if error.raw_os_error() == Some(libc::ECHILD) {
            return Ok(true);
        }
        return Err(error);
    }
    Ok(observed == pid)
}

/// Block until `pid` is reaped. Treats an absent child as already reaped.
pub(crate) fn reap_specific_blocking(pid: libc::pid_t) -> io::Result<()> {
    let mut status: libc::c_int = 0;
    loop {
        // SAFETY: waitpid writes only through the provided status pointer.
        let observed = unsafe { libc::waitpid(pid, &mut status, 0) };
        if observed == -1 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            if error.raw_os_error() == Some(libc::ECHILD) {
                return Ok(());
            }
            return Err(error);
        }
        return Ok(());
    }
}

pub(crate) fn reap_one_blocking() -> io::Result<Option<ReapedChild>> {
    loop {
        let mut status = 0;
        // SAFETY: status points to writable integer storage. -1 selects any
        // child and zero options requests a terminal status synchronously.
        let pid = unsafe { libc::waitpid(-1, &mut status, 0) };
        if pid > 0 {
            return Ok(Some(ReapedChild::Exited { pid, status }));
        }
        let error = io::Error::last_os_error();
        match error.raw_os_error() {
            Some(libc::ECHILD) => return Ok(None),
            Some(libc::EINTR) => {}
            _ => return Err(error),
        }
    }
}
