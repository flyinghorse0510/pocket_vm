use std::fs;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::process::ExitStatusExt;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use nix::libc;
use tempfile::TempDir;

const TEST_TIMEOUT: Duration = Duration::from_secs(10);

fn guard_command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_pocket-guard"));
    command
        .arg("--supervisor-pid")
        .arg(std::process::id().to_string());
    command
}

fn wait_with_timeout(mut child: Child, timeout: Duration) -> io::Result<ExitStatus> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            // This targets only the test-owned guard. Its direct child has the
            // parent-death contract and is also in an isolated process group.
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "pocket-guard test timed out",
            ));
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn pipe_for_guard() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [-1; 2];
    // SAFETY: fds points to storage for exactly two descriptors.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: pipe2 initialized both unique descriptors.
    let read = unsafe { OwnedFd::from_raw_fd(fds[0]) };
    // SAFETY: pipe2 initialized both unique descriptors.
    let write = unsafe { OwnedFd::from_raw_fd(fds[1]) };

    // The read end must cross the test-process -> guard exec boundary.
    // SAFETY: F_GETFD/F_SETFD operate only on the valid read descriptor.
    let flags = unsafe { libc::fcntl(read.as_raw_fd(), libc::F_GETFD) };
    if flags == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: flags came from F_GETFD for this descriptor.
    let set_result =
        unsafe { libc::fcntl(read.as_raw_fd(), libc::F_SETFD, flags & !libc::FD_CLOEXEC) };
    if set_result == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok((read, write))
}

fn send_signal(pid: u32, signal: libc::c_int) -> io::Result<()> {
    // SAFETY: pid names the test-owned guard and signal is valid.
    if unsafe { libc::kill(pid as libc::pid_t, signal) } == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn immediate_children(pid: u32) -> io::Result<Vec<libc::pid_t>> {
    let path = format!("/proc/{pid}/task/{pid}/children");
    let contents = fs::read_to_string(path)?;
    contents
        .split_ascii_whitespace()
        .map(|value| {
            value
                .parse::<libc::pid_t>()
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
        })
        .collect()
}

fn wait_for_child(pid: u32) -> io::Result<()> {
    let deadline = Instant::now() + TEST_TIMEOUT;
    loop {
        if !immediate_children(pid)?.is_empty() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "guard did not spawn its child",
            ));
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn wait_for_file(path: &std::path::Path) -> io::Result<()> {
    let deadline = Instant::now() + TEST_TIMEOUT;
    loop {
        if path.exists() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("timed out waiting for {}", path.display()),
            ));
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn process_exists(pid: libc::pid_t) -> bool {
    // SAFETY: signal zero performs existence/permission checking only.
    if unsafe { libc::kill(pid, 0) } == 0 {
        return true;
    }
    io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
}

#[test]
fn returns_exact_child_exit_code() {
    let mut command = guard_command();
    command.args(["--", "/bin/sh", "-c", "exit 37"]);
    let status = wait_with_timeout(command.spawn().expect("guard should spawn"), TEST_TIMEOUT)
        .expect("guard should finish");
    assert_eq!(status.code(), Some(37));
}

#[test]
fn forwards_signal_and_returns_signal_convention() {
    let mut command = guard_command();
    command.args(["--", "/bin/sleep", "30"]);
    let guard = command.spawn().expect("guard should spawn");
    wait_for_child(guard.id()).expect("guard should start child");
    send_signal(guard.id(), libc::SIGINT).expect("SIGINT should send");
    let status = wait_with_timeout(guard, TEST_TIMEOUT).expect("guard should finish");
    assert_eq!(status.code(), Some(128 + libc::SIGINT));
}

#[test]
fn liveness_eof_terminates_child() {
    let (read, write) = pipe_for_guard().expect("liveness pipe should open");
    let mut command = guard_command();
    command
        .arg("--liveness-fd")
        .arg(read.as_raw_fd().to_string())
        .args(["--", "/bin/sleep", "30"]);
    let guard = command.spawn().expect("guard should spawn");
    drop(read);
    wait_for_child(guard.id()).expect("guard should start child");
    drop(write);
    let status = wait_with_timeout(guard, TEST_TIMEOUT).expect("guard should finish");
    assert_eq!(status.code(), Some(128 + libc::SIGTERM));
}

#[test]
fn supervisor_mismatch_fails_before_exec() {
    let temporary = TempDir::new().expect("temporary directory should open");
    let marker = temporary.path().join("executed");
    let output = Command::new(env!("CARGO_BIN_EXE_pocket-guard"))
        .args(["--supervisor-pid", "1", "--", "/bin/sh", "-c"])
        .arg(format!("touch -- '{}'", marker.display()))
        .output()
        .expect("guard should execute");
    assert_eq!(output.status.code(), Some(125));
    assert!(!marker.exists(), "mismatched supervisor must prevent exec");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("supervisor changed"),
        "guard should explain the mismatch"
    );
}

#[test]
fn reaps_descendant_after_liveness_loss() {
    let temporary = TempDir::new().expect("temporary directory should open");
    let pid_file = temporary.path().join("descendant.pid");
    let (read, write) = pipe_for_guard().expect("liveness pipe should open");
    let mut command = guard_command();
    command
        .arg("--liveness-fd")
        .arg(read.as_raw_fd().to_string())
        .args(["--term-timeout-ms", "250", "--", "/bin/sh", "-c"])
        .arg("sleep 30 & echo $! > \"$1\"; wait")
        .arg("pocket-guard-test")
        .arg(&pid_file)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let guard = command.spawn().expect("guard should spawn");
    drop(read);
    wait_for_file(&pid_file).expect("descendant PID should be recorded");
    let descendant: libc::pid_t = fs::read_to_string(&pid_file)
        .expect("PID file should be readable")
        .trim()
        .parse()
        .expect("PID should parse");
    assert!(
        process_exists(descendant),
        "descendant should initially live"
    );
    drop(write);
    let status = wait_with_timeout(guard, TEST_TIMEOUT).expect("guard should finish");
    assert!(
        matches!(status.code(), Some(143 | 137)),
        "child should die during bounded termination: {status:?}"
    );
    assert!(
        !process_exists(descendant),
        "guard must reap or wait for its descendant to disappear"
    );
}

#[test]
fn escalates_after_bounded_grace_period() {
    let temporary = TempDir::new().expect("temporary directory should open");
    let pid_file = temporary.path().join("child.pid");
    let mut command = guard_command();
    command
        .args(["--term-timeout-ms", "150", "--", "/bin/sh", "-c"])
        .arg("trap '' TERM INT HUP QUIT; echo $$ > \"$1\"; while :; do sleep 1; done")
        .arg("pocket-guard-test")
        .arg(&pid_file)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let guard = command.spawn().expect("guard should spawn");
    wait_for_file(&pid_file).expect("child PID should be recorded");
    let started = Instant::now();
    send_signal(guard.id(), libc::SIGTERM).expect("SIGTERM should send");
    let status = wait_with_timeout(guard, TEST_TIMEOUT).expect("guard should finish");
    assert_eq!(status.code(), Some(128 + libc::SIGKILL));
    assert!(
        started.elapsed() >= Duration::from_millis(100),
        "SIGKILL should not precede the grace period"
    );
}

#[test]
fn closes_unintended_fd_and_preserves_explicit_fd() {
    let temporary = tempfile::tempfile().expect("temporary file should open");
    let fd: RawFd = temporary.as_raw_fd();

    // Make the descriptor eligible to cross the test -> guard exec. The guard
    // must still remove it from a child unless it is explicitly named.
    // SAFETY: F_GETFD/F_SETFD operate on the valid temporary descriptor.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    assert!(flags >= 0);
    // SAFETY: flags came from F_GETFD for this descriptor.
    let set_result = unsafe { libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) };
    assert_eq!(set_result, 0);

    let mut closed = guard_command();
    closed
        .args([
            "--",
            "/bin/sh",
            "-c",
            "test ! -e \"/proc/self/fd/$1\"",
            "test",
        ])
        .arg(fd.to_string());
    let closed_status =
        wait_with_timeout(closed.spawn().expect("guard should spawn"), TEST_TIMEOUT)
            .expect("guard should finish");
    assert_eq!(closed_status.code(), Some(0));

    let mut inherited = guard_command();
    inherited
        .arg("--inherit-fd")
        .arg(fd.to_string())
        .args([
            "--",
            "/bin/sh",
            "-c",
            "test -e \"/proc/self/fd/$1\"",
            "test",
        ])
        .arg(fd.to_string());
    let inherited_status =
        wait_with_timeout(inherited.spawn().expect("guard should spawn"), TEST_TIMEOUT)
            .expect("guard should finish");
    assert_eq!(inherited_status.code(), Some(0));
}

#[test]
fn establishes_and_verifies_uml_personality_before_exec() {
    let mut command = guard_command();
    command.args(["--uml-personality", "--", "/usr/bin/setarch", "--show"]);
    let output = command.output().expect("guard should execute setarch");
    assert_eq!(output.status.code(), Some(0));
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("ADDR_NO_RANDOMIZE"),
        "child must observe the no-randomize personality: {:?}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[cfg(target_arch = "x86_64")]
#[test]
fn bundled_loader_cannot_break_uml_personality_reexec() {
    const LOADER: &str = "/lib64/ld-linux-x86-64.so.2";
    let temporary = TempDir::new().expect("temporary directory should open");
    let probe = temporary.path().join("uml-personality-reexec");
    let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/uml_personality_reexec.c");
    let compile = Command::new("cc")
        .args(["-O2", "-Wall", "-Wextra", "-Werror"])
        .arg(&source)
        .arg("-o")
        .arg(&probe)
        .status()
        .expect("C compiler should execute");
    assert!(compile.success(), "personality fixture should compile");

    let current = Command::new("/usr/bin/setarch")
        .arg("--show")
        .output()
        .expect("setarch should report the test personality");
    assert!(current.status.success());
    assert!(
        !String::from_utf8_lossy(&current.stdout).contains("ADDR_NO_RANDOMIZE"),
        "negative lane requires personality bits initially clear"
    );

    let unguarded = Command::new(LOADER)
        .arg(&probe)
        .output()
        .expect("unprepared loader form should execute");
    assert!(
        !unguarded.status.success(),
        "manual loader form must reproduce UML's destructive self-reexec"
    );
    assert!(!String::from_utf8_lossy(&unguarded.stdout).contains("POCKET_UML_PERSONALITY_OK"));

    let mut guarded = guard_command();
    guarded
        .args(["--uml-personality", "--", LOADER])
        .arg(&probe);
    let guarded = guarded
        .output()
        .expect("guarded bundled-loader form should execute");
    assert_eq!(guarded.status.code(), Some(0));
    assert!(
        String::from_utf8_lossy(&guarded.stdout).contains("POCKET_UML_PERSONALITY_OK"),
        "guarded loader form must reach the UML-equivalent target: stdout={:?}, stderr={:?}",
        String::from_utf8_lossy(&guarded.stdout),
        String::from_utf8_lossy(&guarded.stderr)
    );
}

#[test]
fn signal_status_helpers_match_unix() {
    let status = Command::new("/bin/sh")
        .args(["-c", "kill -TERM $$"])
        .status()
        .expect("shell should run");
    assert_eq!(status.signal(), Some(libc::SIGTERM));
}
