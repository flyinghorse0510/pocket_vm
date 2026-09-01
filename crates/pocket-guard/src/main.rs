use std::ffi::OsString;
use std::os::fd::RawFd;
use std::process;
use std::time::Duration;

use clap::Parser;
use pocket_guard::{GUARD_ERROR_EXIT_CODE, GuardOptions, run_guard};

const DEFAULT_TERM_TIMEOUT_MS: u64 = 5_000;
const MAX_TERM_TIMEOUT_MS: u64 = 600_000;

#[derive(Debug, Parser)]
#[command(
    name = "pocket-guard",
    about = "Supervise one pocket_vm operation process tree"
)]
struct Cli {
    /// PID of the process which directly created this guard.
    #[arg(long, value_name = "PID")]
    supervisor_pid: i32,

    /// Inherited read FD whose EOF requests graceful termination.
    #[arg(long, value_name = "FD")]
    liveness_fd: Option<RawFd>,

    /// Inherited FD held open for the lifetime of the operation.
    #[arg(long, value_name = "FD")]
    lease_fd: Option<RawFd>,

    /// Additional inherited FD to preserve across the child exec.
    #[arg(long = "inherit-fd", value_name = "FD")]
    inherited_fds: Vec<RawFd>,

    /// Grace interval before SIGKILL, in milliseconds.
    #[arg(long, default_value_t = DEFAULT_TERM_TIMEOUT_MS, value_name = "MS")]
    term_timeout_ms: u64,

    /// Establish PER_LINUX|ADDR_NO_RANDOMIZE before exec for a UML child.
    #[arg(long)]
    uml_personality: bool,

    /// One argument of an optional helper started before the command child
    /// and terminated when it exits. Repeat once per argument, program first.
    /// Passed this way rather than as a single string because the guard must
    /// never split an argument vector itself.
    #[arg(
        long = "network-helper-arg",
        value_name = "ARG",
        allow_hyphen_values = true
    )]
    network_helper: Vec<OsString>,

    /// Program and arguments. A literal `--` must precede the program.
    #[arg(last = true, required = true, num_args = 1.., allow_hyphen_values = true)]
    command: Vec<OsString>,
}

fn main() {
    let cli = Cli::parse();

    if cli.term_timeout_ms > MAX_TERM_TIMEOUT_MS {
        eprintln!("pocket-guard: --term-timeout-ms must not exceed {MAX_TERM_TIMEOUT_MS}");
        process::exit(GUARD_ERROR_EXIT_CODE);
    }

    let options = GuardOptions {
        supervisor_pid: cli.supervisor_pid,
        liveness_fd: cli.liveness_fd,
        lease_fd: cli.lease_fd,
        inherited_fds: cli.inherited_fds,
        term_timeout: Duration::from_millis(cli.term_timeout_ms),
        uml_personality: cli.uml_personality,
        network_helper: cli.network_helper,
        command: cli.command,
    };

    // SAFETY: this binary is single-threaded and receives unique ownership of
    // the explicitly named inherited descriptors from its creating process.
    match unsafe { run_guard(options) } {
        Ok(outcome) => process::exit(outcome.conventional_exit_code()),
        Err(error) => {
            eprintln!("pocket-guard: {error}");
            process::exit(GUARD_ERROR_EXIT_CODE);
        }
    }
}
