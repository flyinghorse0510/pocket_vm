//! Reclamation of operation directories whose owner is gone.
//!
//! A run or build directory lives under the runtime root for exactly one
//! operation and is removed when that operation ends. A process killed by a
//! signal never gets there: `Drop` does not run for SIGKILL, and a `SIGINT` at
//! the wrong moment is no better. Without a sweep the runtime root gains one
//! abandoned directory per killed invocation and never loses it, taking the
//! operation's sparse COW and payload images with it.
//!
//! Ownership is an exclusive `flock` on `<operation>/owner.lock`, held for the
//! operation's whole life. A sweeper that can take that lock knows the owner is
//! gone, because the kernel releases the lock when the owning process dies
//! however it dies -- no PID liveness guess, which PID reuse would make unsafe.
//! Creation holds a shared lock on the root's sweep file and the sweep takes it
//! exclusively, so a sweep can never observe a half-built directory.

use std::{
    fs::{self, File, OpenOptions},
    io,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};

const SWEEP_LOCK: &str = ".sweep.lock";
const OWNER_LOCK: &str = "owner.lock";
const PRIVATE_FILE_MODE: u32 = 0o600;

/// Open an existing lock without creating it.
///
/// The sweep must never create the file it is about to test: creating it would
/// hand the sweeper an uncontended lock on every directory that has not claimed
/// one, which is exactly the set it must leave alone.
fn open_existing(path: &Path) -> io::Result<File> {
    OpenOptions::new().read(true).write(true).open(path)
}

fn open_private(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(PRIVATE_FILE_MODE)
        .open(path)
}

/// Hold the root's sweep file shared for the length of a directory's creation.
///
/// The caller must keep this open until the new directory owns its lock, or a
/// concurrent sweep may see the directory before it is claimed and reclaim it.
pub(crate) fn lock_creation(root: &Path) -> io::Result<File> {
    let lock = open_private(&root.join(SWEEP_LOCK))?;
    lock.lock_shared()?;
    Ok(lock)
}

/// Claim one operation directory for this process.
pub(crate) fn claim_owner(path: &Path) -> io::Result<File> {
    let lock = open_private(&path.join(OWNER_LOCK))?;
    lock.try_lock().map_err(io::Error::from)?;
    Ok(lock)
}

/// Remove every `prefix`-named directory under `root` whose owner has died.
///
/// Returns how many were reclaimed. A directory that is still owned, that has
/// no owner lock at all, or that is not a plain directory on the root's own
/// device is left exactly as it is: this reclaims abandoned work, it does not
/// clean up anything it does not fully recognize. A directory that predates the
/// owner lock therefore survives forever, which is the right way round -- an
/// unrecognized directory is not this code's to delete.
pub(crate) fn reclaim_orphans(root: &Path, prefix: &str) -> io::Result<usize> {
    let sweep = open_private(&root.join(SWEEP_LOCK))?;
    if sweep.try_lock().is_err() {
        // Another sweeper holds it, or a creation is in flight. Either way this
        // pass has nothing safe to say, and the next one will.
        return Ok(0);
    }
    let device = fs::symlink_metadata(root)?.dev();
    let mut reclaimed = 0;
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !name.starts_with(prefix) {
            continue;
        }
        let path = entry.path();
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            // Raced with another reclaimer or with a normal cleanup.
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        if !metadata.file_type().is_dir() || metadata.dev() != device {
            continue;
        }
        let owner = match open_existing(&path.join(OWNER_LOCK)) {
            Ok(owner) => owner,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
                ) =>
            {
                continue;
            }
            Err(error) => return Err(error),
        };
        if owner.try_lock().is_err() {
            continue;
        }
        // The lock is ours, so no live process owns this directory. Anything
        // still running that names it is debris from the owner's death, not a
        // participant in a live run.
        kill_processes_naming(&path);
        match fs::remove_dir_all(&path) {
            Ok(()) => reclaimed += 1,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(reclaimed)
}

/// SIGKILL anything whose command line names `path`.
///
/// The owner's own children die with it: the guard carries a parent-death
/// signal, and so does everything it starts. A *grandchild* does not --
/// `PR_SET_PDEATHSIG` is cleared across `fork(2)` -- so a helper that forks
/// internally leaves its fork behind when the guard is killed outright. That
/// was reproducible with the network helper.
///
/// Matching on the command line is safe because the directory name carries a
/// 128-bit random operation id: no unrelated process can name it, and the id
/// is never reused, so this cannot be confused by PID recycling. Best effort
/// throughout -- a process that exits first, or that we may not signal, is not
/// a reason to refuse to reclaim the directory.
fn kill_processes_naming(path: &Path) {
    let Some(needle) = path.to_str() else { return };
    let Ok(entries) = fs::read_dir("/proc") else {
        return;
    };
    let own = std::process::id();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Ok(pid) = name.parse::<u32>() else {
            continue;
        };
        if pid == own {
            continue;
        }
        let Ok(cmdline) = fs::read(entry.path().join("cmdline")) else {
            continue;
        };
        // Arguments are NUL-separated; compare against the whole blob so a
        // path that appears in any single argument matches.
        if !cmdline.split(|byte| *byte == 0).any(|argument| {
            argument
                .windows(needle.len())
                .any(|w| w == needle.as_bytes())
        }) {
            continue;
        }
        // SAFETY: kill takes two scalars and has no memory preconditions.
        unsafe { nix::libc::kill(pid as nix::libc::pid_t, nix::libc::SIGKILL) };
    }
}

#[cfg(test)]
mod tests {
    use std::process::Command;

    use super::*;

    /// A signal-killed process never runs its cleanup, so the next operation
    /// must reclaim what it left. The owner lock is what distinguishes an
    /// abandoned directory from a running one, and only the kernel can release
    /// it on the owner's death.
    #[test]
    fn abandoned_directories_are_reclaimed_and_live_ones_are_not() {
        let temporary = tempfile::tempdir().expect("temporary root");
        let root = temporary.path();

        // A directory whose owner is gone: claim it in a child that we kill.
        let abandoned = root.join("run-abandoned");
        fs::create_dir(&abandoned).expect("create abandoned");
        let mut child = Command::new("/bin/sh")
            .arg("-c")
            // flock(1) holds an exclusive lock for as long as the shell lives.
            .arg(format!(
                "exec 9>{}/{OWNER_LOCK}; flock -x 9; echo ready; read _",
                abandoned.display()
            ))
            .stdout(std::process::Stdio::piped())
            .stdin(std::process::Stdio::piped())
            .spawn()
            .expect("spawn lock holder");
        {
            use std::io::{BufRead, BufReader};
            let stdout = child.stdout.take().expect("child stdout");
            let mut line = String::new();
            BufReader::new(stdout)
                .read_line(&mut line)
                .expect("wait for the child to hold the lock");
            assert_eq!(line.trim(), "ready");
        }

        // A live owner in this process.
        let live = root.join("run-live");
        fs::create_dir(&live).expect("create live");
        let _live_owner = claim_owner(&live).expect("claim live");

        // Never claimed, and a name we do not recognize: both untouched.
        let unclaimed = root.join("run-unclaimed");
        fs::create_dir(&unclaimed).expect("create unclaimed");
        let foreign = root.join("something-else");
        fs::create_dir(&foreign).expect("create foreign");

        assert_eq!(
            reclaim_orphans(root, "run-").expect("sweep with a live owner"),
            0,
            "nothing is reclaimable while the killed child still holds its lock"
        );
        assert!(abandoned.exists());

        child.kill().expect("kill the lock holder");
        child.wait().expect("reap the lock holder");

        // The property under test is that the directory becomes reclaimable
        // once its owner is gone, not that it does so at one exact instant, so
        // give process teardown a bounded chance rather than making a loaded
        // machine look like a defect. Everything else below stays strict.
        let mut reclaimed = 0;
        for _ in 0..100 {
            reclaimed = reclaim_orphans(root, "run-").expect("sweep after the owner died");
            if reclaimed == 1 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert_eq!(reclaimed, 1, "the abandoned directory was never reclaimed");
        assert!(!abandoned.exists(), "the abandoned directory must be gone");
        assert!(live.exists(), "a live operation must survive the sweep");
        assert!(unclaimed.exists(), "an unclaimed directory is not ours");
        assert!(foreign.exists(), "a foreign name is not ours");
    }

    /// A creation in flight must be invisible to a sweep, or a run could be
    /// reclaimed between its directory appearing and its owner claiming it.
    #[test]
    fn a_sweep_does_nothing_while_a_creation_holds_the_root() {
        let temporary = tempfile::tempdir().expect("temporary root");
        let root = temporary.path();
        let half_built = root.join("run-half-built");
        fs::create_dir(&half_built).expect("create half-built");
        let creation = lock_creation(root).expect("lock creation");
        assert_eq!(reclaim_orphans(root, "run-").expect("blocked sweep"), 0);
        assert!(half_built.exists());
        drop(creation);
        // Still unclaimed once the creation lock is gone, so still not ours.
        assert_eq!(reclaim_orphans(root, "run-").expect("free sweep"), 0);
        assert!(half_built.exists());
    }
}
