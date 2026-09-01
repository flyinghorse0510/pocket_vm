//! Host terminal control for an interactive session.
//!
//! A terminal session needs the operator's own terminal put into raw mode, so
//! that keystrokes reach the guest unedited and the guest's line discipline --
//! not the host's -- decides what a character means. That is a change to state
//! this process does not own, so it is modelled as a guard that restores the
//! previous settings when it is dropped, including on the error paths.

use std::{
    io,
    os::fd::{AsFd, AsRawFd, BorrowedFd},
    sync::atomic::{AtomicBool, Ordering},
};

use nix::{
    sys::{
        signal::{SaFlags, SigAction, SigHandler, SigSet, Signal, sigaction},
        termios::{SetArg, Termios, cfmakeraw, tcgetattr, tcsetattr},
    },
    unistd::isatty,
};

use crate::error::RuntimeError;

nix::ioctl_read_bad!(get_window_size, nix::libc::TIOCGWINSZ, nix::libc::winsize);

/// Raised by the SIGWINCH handler. Only ever set here and cleared by the
/// session, so a missed edge coalesces into the next poll rather than being
/// lost.
static WINDOW_CHANGED: AtomicBool = AtomicBool::new(false);

extern "C" fn handle_window_change(_: nix::libc::c_int) {
    // Async-signal-safe: a relaxed store and nothing else.
    WINDOW_CHANGED.store(true, Ordering::Relaxed);
}

/// The operator's terminal, held in raw mode for the life of a session.
#[derive(Debug)]
pub struct TerminalSession {
    original: Termios,
    previous_winch: Option<SigAction>,
    restored: bool,
}

impl TerminalSession {
    /// Put this process's terminal into raw mode for a session.
    ///
    /// Both directions must be a terminal: without a terminal on input there
    /// is nothing to put in raw mode, and without one on output the guest
    /// would be drawing to something that cannot show it.
    pub fn acquire() -> Result<Self, RuntimeError> {
        let input = io::stdin();
        let output = io::stdout();
        for (role, fd) in [("stdin", input.as_fd()), ("stdout", output.as_fd())] {
            match isatty(fd) {
                Ok(true) => {}
                Ok(false) => {
                    return Err(RuntimeError::invalid(
                        "terminal",
                        format!("{role} is not a terminal"),
                    ));
                }
                Err(error) => {
                    return Err(RuntimeError::invalid(
                        "terminal",
                        format!("could not inspect {role}: {error}"),
                    ));
                }
            }
        }
        let original = tcgetattr(input.as_fd())
            .map_err(|error| terminal_error("read terminal settings", error))?;
        let mut raw = original.clone();
        cfmakeraw(&mut raw);
        tcsetattr(input.as_fd(), SetArg::TCSANOW, &raw)
            .map_err(|error| terminal_error("set raw mode", error))?;

        let action = SigAction::new(
            SigHandler::Handler(handle_window_change),
            SaFlags::SA_RESTART,
            SigSet::empty(),
        );
        // SAFETY: the handler only performs a relaxed atomic store, which is
        // async-signal-safe, and it is uninstalled again when this is dropped.
        let previous_winch = unsafe { sigaction(Signal::SIGWINCH, &action) }.ok();
        // Report the starting size once so the first poll does not have to.
        WINDOW_CHANGED.store(false, Ordering::Relaxed);
        Ok(Self {
            original,
            previous_winch,
            restored: false,
        })
    }

    /// The terminal's current size, as rows and columns.
    pub fn size(&self) -> Result<(u16, u16), RuntimeError> {
        current_size(io::stdout().as_fd())
    }

    /// The new size if the operator has resized since the last call.
    ///
    /// Returns `None` when nothing changed, so a caller can poll it cheaply.
    pub fn take_resize(&self) -> Option<(u16, u16)> {
        if !WINDOW_CHANGED.swap(false, Ordering::Relaxed) {
            return None;
        }
        self.size().ok()
    }

    /// Put the terminal back the way it was found.
    ///
    /// Idempotent, because it runs both on the ordinary path and from `Drop`.
    pub fn restore(&mut self) {
        if self.restored {
            return;
        }
        self.restored = true;
        let _ = tcsetattr(io::stdin().as_fd(), SetArg::TCSANOW, &self.original);
        if let Some(previous) = self.previous_winch {
            // SAFETY: restoring the action that was installed before this
            // session began.
            let _ = unsafe { sigaction(Signal::SIGWINCH, &previous) };
        }
    }
}

impl Drop for TerminalSession {
    fn drop(&mut self) {
        self.restore();
    }
}

fn current_size(fd: BorrowedFd<'_>) -> Result<(u16, u16), RuntimeError> {
    let mut size = nix::libc::winsize {
        ws_row: 0,
        ws_col: 0,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: `fd` is a live descriptor and TIOCGWINSZ writes one `winsize`.
    unsafe { get_window_size(fd.as_raw_fd(), &mut size) }
        .map_err(|error| terminal_error("read terminal size", error))?;
    // A terminal that reports nothing still has to be given a usable size, or
    // the guest starts with a zero-sized window and draws nothing.
    let rows = if size.ws_row == 0 { 24 } else { size.ws_row };
    let columns = if size.ws_col == 0 { 80 } else { size.ws_col };
    Ok((rows, columns))
}

fn terminal_error(action: &str, error: nix::errno::Errno) -> RuntimeError {
    RuntimeError::invalid("terminal", format!("could not {action}: {error}"))
}
