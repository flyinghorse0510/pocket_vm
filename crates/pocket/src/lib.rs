//! Strict command-line frontend for the currently implemented Pocket runtime.
//!
//! This crate intentionally exposes only operations backed by verified public
//! library APIs. It never invokes a shell and reports unavailable plan surface
//! as a stable error before opening a profile or content store.

#![forbid(unsafe_code)]

use std::{
    ffi::OsString,
    fs::{self, OpenOptions},
    io::{self, IsTerminal, Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::ExitCode,
    str::FromStr,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use clap::{Args, Parser, Subcommand, ValueEnum, error::ErrorKind};
use pocket_core::{CodedError, ManagedUmlPath, ManagedUmlPathError, ParsedMemory};
use pocket_oci::{
    AcquisitionDirectory, SkopeoExecutionPolicy, SkopeoNormalizer, SkopeoOutput, SkopeoPlatform,
    SkopeoSource, SkopeoSourceKind, VerifiedImage,
};
use pocket_runtime::VolumeSpec;
use pocket_runtime::{
    BuildOutput, BuildRequest, BuilderPolicy, BuilderToolContract, CommitRequest, HostBuildError,
    HostBuilder, ImageArgv, ImageProcessOverrides, ManifestError, ProfileArtifactSources,
    ProfileMaturity, ProfileSealRequest, RetainRequest, RunOptions, RunOutput, Runtime,
    RuntimeError, RuntimePolicy, TerminalRequest, TerminalSession, VerifiedProfile, WorkloadSpec,
    resolve_image_process, seal_profile_bundle,
};
use pocket_store::{
    AliasId, AliasKey, AliasRoot, DerivationKey, Digest, GarbageCollectionReport, Generation,
    GenerationId, Instance, InstanceOutcome, Lease, Platform, Store, StoreError,
};
use serde_json::{Value, json};
use thiserror::Error;

/// Exit used for a Pocket operational error before a guest status exists.
pub const OPERATIONAL_ERROR_EXIT: u8 = 125;
/// Exit used by clap for invalid command-line syntax.
pub const USAGE_ERROR_EXIT: u8 = 2;
const MAX_CLI_STDIN_BYTES: u64 = 16 * 1024 * 1024;
const SIGNAL_EXIT_BASE: u16 = 128;

#[derive(Debug, Parser)]
#[command(
    name = "pocket",
    version,
    about = "Run trusted, networkless workloads under verified User-Mode Linux artifacts",
    long_about = "Run trusted, networkless workloads under verified User-Mode Linux artifacts.\n\n\
This build is intentionally strict: registry pulls are anonymous and explicit, and it does not support \
slirp networking, PTYs, cpusets, or installed-profile discovery. Sharing a host directory is supported \
with --volume; persistent named volumes are not. Run resolves \
Entrypoint/Cmd/Env/User/WorkingDir/StopSignal only from hash-verified generation sidecars. \
Unsupported requests fail before profile or store access. \
Run only trusted images and workloads: this UML configuration is not a hostile-code sandbox."
)]
pub struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Verify or list explicitly named profile bundles.
    Profile {
        #[command(subcommand)]
        command: ProfileCommand,
    },
    /// Inspect an existing image alias or immutable generation.
    Image {
        #[command(subcommand)]
        command: ImageCommand,
    },
    /// Inspect immutable generations by final ID or derivation.
    Generation {
        #[command(subcommand)]
        command: GenerationCommand,
    },
    /// Operate on the local immutable content store.
    Cache {
        #[command(subcommand)]
        command: CacheCommand,
    },
    /// List running operations, and with `-a` the runs kept after they exited.
    Ps {
        /// Runtime root to inspect. Defaults to `runtime_root` in the config file.
        #[arg(long, value_name = "PATH")]
        runtime_root: Option<PathBuf>,
        /// Also list kept runs that have already exited.
        #[arg(short = 'a', long)]
        all: bool,
        /// Store holding kept runs. Defaults to `store` in the config file.
        #[arg(long, value_name = "PATH")]
        store: Option<PathBuf>,
        /// Emit stable JSON rather than key=value output.
        #[arg(long)]
        json: bool,
    },
    /// Publish a kept run's filesystem as a new image.
    Commit {
        /// Store holding the kept run. Defaults to `store` in the config file.
        #[arg(long, value_name = "PATH")]
        store: Option<PathBuf>,
        #[arg(long, value_name = "PATH")]
        profile_bundle: Option<PathBuf>,
        #[arg(long, value_name = "PATH")]
        runtime_root: Option<PathBuf>,
        /// Kept run to commit, by name.
        name: String,
        /// Reference the resulting image is published under.
        reference: String,
        /// Emit stable JSON rather than key=value output.
        #[arg(long)]
        json: bool,
    },
    /// Remove kept runs and the disk they hold.
    Rm {
        /// Store holding the kept runs. Defaults to `store` in the config file.
        #[arg(long, value_name = "PATH")]
        store: Option<PathBuf>,
        /// Kept runs to remove, by name.
        #[arg(required = true)]
        names: Vec<String>,
        /// Emit stable JSON rather than key=value output.
        #[arg(long)]
        json: bool,
    },
    /// Unavailable: a run is a foreground process with no daemon behind it.
    Attach,
    /// Unavailable: a run executes exactly one process.
    Exec,
    /// Run image defaults, or Docker-compatible overrides, from a generation or alias.
    Run(Box<RunArgs>),
}

#[derive(Debug, Subcommand)]
enum ProfileCommand {
    /// Assemble and atomically publish one immutable release-profile revision.
    Seal(Box<ProfileSealArgs>),
    /// Strictly verify one bundle manifest and all bound artifacts.
    Verify {
        /// Exact profile bundle directory containing profile.json.
        bundle: PathBuf,
        /// Emit stable JSON rather than key=value lines.
        #[arg(long)]
        json: bool,
    },
    /// Verify and list the explicitly supplied bundle directories.
    List {
        /// Exact bundle directories; installed-index discovery is not implemented.
        #[arg(required = true, num_args = 1..)]
        bundles: Vec<PathBuf>,
        /// Emit stable JSON rather than one summary line per bundle.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Clone, Args)]
struct ProfileSealArgs {
    /// Absolute strict JSON template with zero identity/artifact placeholders.
    #[arg(long, value_name = "PATH")]
    template: PathBuf,
    /// Existing collection root; output is ID/revision beneath it.
    #[arg(long, value_name = "PATH")]
    output_parent: PathBuf,
    #[arg(long, value_name = "PATH")]
    guard: PathBuf,
    #[arg(long, value_name = "PATH")]
    uml: PathBuf,
    #[arg(long, value_name = "PATH")]
    skopeo: PathBuf,
    #[arg(long, value_name = "PATH")]
    slirp4netns: PathBuf,
    #[arg(long, value_name = "PATH")]
    registry_ca_bundle: PathBuf,
    #[arg(long, value_name = "PATH")]
    workload_initramfs: PathBuf,
    #[arg(long, value_name = "PATH")]
    builder_initramfs: PathBuf,
    #[arg(long, value_name = "PATH")]
    validator_initramfs: PathBuf,
    #[arg(long, value_name = "PATH")]
    mke2fs: PathBuf,
    #[arg(long, value_name = "PATH")]
    e2fsck: PathBuf,
    /// Sealed static resize2fs, used by `image adjust`.
    #[arg(long, value_name = "PATH")]
    resize2fs: PathBuf,
    /// Sealed static debugfs, used by `image adjust` to locate the marker.
    #[arg(long, value_name = "PATH")]
    debugfs: PathBuf,
    #[arg(long, value_name = "PATH")]
    mke2fs_config: PathBuf,
    #[arg(long, value_name = "PATH")]
    e2fsck_config: PathBuf,
    #[arg(long, value_name = "PATH")]
    kernel_config: PathBuf,
    /// Plain lowercase SHA-256 measured from builder-initramfs umoci bytes.
    #[arg(long)]
    umoci_sha256: String,
    /// Exact single-line output from the builder's `umoci --version`.
    #[arg(long)]
    umoci_version: String,
    /// Emit stable JSON rather than key=value lines.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Subcommand)]
enum ImageCommand {
    /// Inspect an exact final generation ID or a profile-qualified alias.
    Inspect {
        #[command(flatten)]
        context: ProfileStoreArgs,
        /// `pkvm-gen-v1-...` final ID, or exact alias reference.
        target: String,
        /// Emit stable JSON rather than key=value lines.
        #[arg(long)]
        json: bool,
    },
    /// Unavailable until the store exposes safe alias enumeration.
    List,
    /// Pull one anonymous fully-qualified docker:// image and publish a generation.
    Pull {
        #[command(flatten)]
        context: ImageBuildArgs,
        /// Image to pull. A bare name is expanded the way a registry client
        /// would: `alpine:3.22` becomes `docker://docker.io/library/alpine:3.22`.
        /// An explicit `docker://` source is still accepted; other transports
        /// are still rejected rather than guessed at.
        source: String,
        /// Bounded Skopeo wall-clock timeout (`ms`, `s`, `m`, or `h`).
        #[arg(long, default_value = "15m")]
        acquisition_timeout: String,
    },
    /// Verify a canonical OCI layout and publish or reuse one generation.
    Import {
        #[command(flatten)]
        context: ImageBuildArgs,
        #[command(flatten)]
        source: ImageImportSourceArgs,
    },
    /// Republish an image's filesystem at a different size.
    ///
    /// The source is never modified: a generation is immutable, so this
    /// publishes a new one and leaves the original in place.
    Adjust {
        #[command(flatten)]
        context: ImageBuildArgs,
        /// Image to read, as an alias reference.
        source: String,
        /// New filesystem size (`K`, `M`, `G`, or plain bytes), a multiple of
        /// the 4096-byte block.
        #[arg(long)]
        size: String,
    },
}

#[derive(Debug, Clone, Args)]
#[group(required = true, multiple = false)]
struct ImageImportSourceArgs {
    /// Exact absolute canonical OCI-layout directory.
    #[arg(long, value_name = "PATH")]
    oci: Option<PathBuf>,
    /// Exact absolute single-image OCI archive to normalize with sealed Skopeo.
    #[arg(long, value_name = "PATH")]
    oci_archive: Option<PathBuf>,
    /// Exact absolute single-image Docker save archive to normalize with sealed Skopeo.
    #[arg(long, value_name = "PATH")]
    docker_archive: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
enum GenerationCommand {
    /// Verify and inspect one immutable final generation under a lease.
    Inspect {
        #[command(flatten)]
        store: StoreArgs,
        /// Full `pkvm-gen-v1-...` generation ID.
        id: String,
        /// Emit stable JSON rather than key=value lines.
        #[arg(long)]
        json: bool,
    },
    /// List verified outputs for one exact derivation key.
    List {
        #[command(flatten)]
        store: StoreArgs,
        /// Full `pkvm-der-v1-...` derivation key.
        #[arg(long)]
        derivation: String,
        /// Emit stable JSON rather than one summary line per generation.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
enum CacheCommand {
    /// Garbage-collect unrooted generations; mutation requires --apply.
    Gc {
        #[command(flatten)]
        store: StoreArgs,
        /// Perform deletion. Without this flag, fail safely because preview is unavailable.
        #[arg(long)]
        apply: bool,
        /// Emit stable JSON rather than key=value lines.
        #[arg(long)]
        json: bool,
    },
    /// List the aliases that are currently rooting generations against collection.
    Roots {
        #[command(flatten)]
        store: StoreArgs,
        /// Emit stable JSON rather than key=value lines.
        #[arg(long)]
        json: bool,
    },
    /// Drop one alias by ID so its generation becomes collectable.
    Forget {
        #[command(flatten)]
        store: StoreArgs,
        /// Exact alias ID, as printed by `pocket cache roots`.
        #[arg(long, value_name = "ALIAS_ID")]
        alias: String,
    },
}

#[derive(Debug, Clone, Args)]
struct StoreArgs {
    /// Existing initialized Pocket store root. Defaults to `store` in the
    /// config file.
    #[arg(long, value_name = "PATH")]
    store: Option<PathBuf>,
}

#[derive(Debug, Clone, Args)]
struct ProfileStoreArgs {
    /// Exact verified profile bundle directory. Defaults to `profile_bundle`
    /// in the config file.
    #[arg(long, value_name = "PATH")]
    profile_bundle: Option<PathBuf>,
    /// Existing initialized Pocket store root. Defaults to `store` in the
    /// config file.
    #[arg(long, value_name = "PATH")]
    store: Option<PathBuf>,
    /// Optional native selector assertion: OS/ARCHITECTURE[/VARIANT].
    #[arg(long, value_name = "PLATFORM")]
    platform: Option<String>,
}

#[derive(Debug, Clone, Args)]
struct ImageBuildArgs {
    /// Exact verified profile bundle directory. Defaults to `profile_bundle`
    /// in the config file.
    #[arg(long, value_name = "PATH")]
    profile_bundle: Option<PathBuf>,
    /// Existing valid store, or an absent path to initialize atomically.
    /// Defaults to `store` in the config file.
    #[arg(long, value_name = "PATH")]
    store: Option<PathBuf>,
    /// Private mode-0700 root for acquisition and builder operation
    /// directories. Defaults to `runtime_root` in the config file.
    #[arg(long, value_name = "PATH")]
    runtime_root: Option<PathBuf>,
    /// Profile-qualified alias to update after publication. Defaults to the
    /// source's own name, so a pull names an image what you asked for.
    #[arg(long, value_name = "REFERENCE")]
    reference: Option<String>,
    /// Native selector assertion: OS/ARCHITECTURE[/VARIANT]. Defaults to the
    /// verified profile's own platform, which is the only one it can run --
    /// so the assertion still holds, it is just no longer typed out.
    #[arg(long, value_name = "PLATFORM")]
    platform: Option<String>,
    /// Emit stable JSON rather than key=value output.
    #[arg(long)]
    json: bool,
    /// Atomically create a mode-0600 JSON receipt containing source, digest,
    /// resolver, and bounded helper-log evidence.
    #[arg(long, value_name = "PATH")]
    evidence_out: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum NetworkMode {
    None,
    Slirp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum PullPolicy {
    Never,
    Missing,
    Always,
}

#[derive(Debug, Args)]
struct RunArgs {
    /// Exact verified profile bundle directory. Defaults to `profile_bundle`
    /// in the config file.
    #[arg(long, value_name = "PATH")]
    profile_bundle: Option<PathBuf>,
    /// Existing initialized Pocket store root. Defaults to `store` in the
    /// config file.
    #[arg(long, value_name = "PATH")]
    store: Option<PathBuf>,
    /// Private runtime root used for this process's run directories.
    /// Defaults to `runtime_root` in the config file.
    #[arg(long, value_name = "PATH")]
    runtime_root: Option<PathBuf>,
    /// Optional native selector assertion: OS/ARCHITECTURE[/VARIANT].
    #[arg(long, value_name = "PLATFORM")]
    platform: Option<String>,
    /// Requested online UML CPUs. Defaults to one and is never clamped.
    #[arg(long, default_value = "1")]
    cpus: String,
    /// Exact guest physical-memory request; omitted uses the profile-bound default.
    #[arg(long)]
    memory: Option<String>,
    /// Bounded wall-clock execution timeout (`ms`, `s`, `m`, or `h`).
    #[arg(long)]
    timeout: Option<String>,
    /// Read at most 16 MiB from this CLI's stdin and send it to the workload.
    /// Implied by `--tty`, which streams input instead of buffering it.
    #[arg(short = 'i', long)]
    interactive: bool,
    /// Extra guest serial lines, each published as a pseudo-terminal you can
    /// attach to with `screen`, `minicom` or any terminal program. The guest
    /// exposes them as `/dev/ttyS4` upwards; what runs on one is up to the
    /// workload.
    #[arg(long, default_value = "0")]
    consoles: u8,
    /// Mirror the guest kernel console to stderr while the run boots, instead
    /// of only writing it to a file afterwards.
    #[arg(long)]
    boot_log: bool,
    /// Name this run so it can be listed, committed and removed after it
    /// exits. Defaults to a generated name.
    #[arg(long)]
    name: Option<String>,
    /// Discard the run when it exits instead of keeping it.
    #[arg(long)]
    rm: bool,
    /// Run the workload on a terminal: allocate a PTY in the guest, put this
    /// terminal in raw mode, and stream both directions until it exits.
    /// Requires that this process's stdin and stdout are both terminals.
    #[arg(short = 't', long)]
    tty: bool,
    /// Guest networking. `slirp` gives the guest NAT'd access through an
    /// unprivileged userspace stack; `none` leaves it with loopback only.
    #[arg(long, value_enum, default_value = "slirp")]
    network: NetworkMode,
    /// Unavailable: a run is a foreground process. Accepted so the refusal
    /// names the reason instead of reading as a typo.
    #[arg(short = 'd', long)]
    detach: bool,
    /// Give the workload every capability the guest kernel implements,
    /// instead of the fixed allowlist. Needed to run a container engine
    /// inside the guest. This grants nothing over the host: the guest has its
    /// own kernel, and the host boundary is an unprivileged process.
    #[arg(long)]
    privileged: bool,
    /// Share a host directory into the guest: HOST_PATH:GUEST_PATH[:ro|:rw].
    /// Both paths must be absolute; the host path must already exist and may
    /// not contain a colon. Writes are visible on the host immediately and
    /// outlive the run. `:rw` is the default.
    #[arg(long, value_name = "HOST_PATH:GUEST_PATH[:ro]")]
    volume: Vec<String>,
    /// Unsupported port-forward request.
    #[arg(short = 'p', long = "publish", value_name = "FORWARD")]
    publish: Vec<String>,
    /// Unsupported host affinity request.
    #[arg(long, value_name = "LIST")]
    cpuset: Option<String>,
    /// `run` never acquires implicitly; use an explicit `image pull` first.
    #[arg(long, value_enum, default_value = "never")]
    pull: PullPolicy,
    /// Replace Entrypoint and clear image Cmd; an empty value clears both.
    #[arg(long, value_name = "EXECUTABLE")]
    entrypoint: Option<String>,
    /// Use command after `--` as complete argv, bypassing Entrypoint/Cmd merge.
    #[arg(long)]
    exact_argv: bool,
    /// Override image User: user, uid, user:group, uid:gid, uid:group, or user:gid.
    #[arg(long, value_name = "USER[:GROUP]")]
    user: Option<String>,
    /// Override image WorkingDir with an absolute normalized guest path.
    #[arg(long, value_name = "PATH")]
    workdir: Option<String>,
    /// Override default PATH/HOSTNAME or image Env by key; repeat as needed.
    #[arg(short = 'e', long = "env", value_name = "KEY=VALUE")]
    env: Vec<String>,
    /// Guest UTS hostname and initial HOSTNAME environment value.
    #[arg(long, default_value = "pocket")]
    hostname: String,
    /// Octal process umask in 000..777.
    #[arg(long, default_value = "022")]
    umask: String,
    /// Override image StopSignal with 1..=64 or a conventional Linux name.
    #[arg(long, value_name = "SIGNAL")]
    stop_signal: Option<String>,
    /// Enforce the runtime's read-only-root guest contract.
    #[arg(long)]
    root_readonly: bool,
    /// Write the guest kernel console to this new file, on success and on
    /// failure alike. The console carries kernel and guest-init diagnostics,
    /// never workload output, so it is the evidence to keep when a run
    /// misbehaves.
    #[arg(long, value_name = "PATH")]
    console_log: Option<PathBuf>,
    /// Exact final generation ID or profile-qualified alias reference.
    image: String,
    /// Docker Cmd replacement after `--`; omit to use image Cmd (or use --exact-argv).
    #[arg(last = true, num_args = 0.., allow_hyphen_values = true)]
    command: Vec<String>,
}

/// Stable CLI failure categories printed on stderr.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CliErrorCode {
    FeatureUnsupported,
    InvalidInput,
    ProfileInvalid,
    Store,
    GenerationProfileMismatch,
    ImageAcquisition,
    ImageBuild,
    Runtime,
    Output,
}

impl CliErrorCode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FeatureUnsupported => "E_FEATURE_UNSUPPORTED",
            Self::InvalidInput => "E_CLI_INVALID_INPUT",
            Self::ProfileInvalid => "E_PROFILE_INVALID",
            Self::Store => "E_STORE",
            Self::GenerationProfileMismatch => "E_GENERATION_PROFILE_MISMATCH",
            Self::ImageAcquisition => "E_IMAGE_ACQUISITION",
            Self::ImageBuild => "E_IMAGE_BUILD",
            Self::Runtime => "E_RUNTIME",
            Self::Output => "E_CLI_OUTPUT",
        }
    }
}

#[derive(Debug, Error)]
pub enum CliError {
    #[error("feature {feature:?} is unavailable: {reason}")]
    FeatureUnsupported {
        feature: &'static str,
        reason: &'static str,
    },
    #[error("invalid {field}: {reason}")]
    InvalidInput { field: &'static str, reason: String },
    #[error(transparent)]
    ManagedPath(#[from] ManagedUmlPathError),
    #[error(transparent)]
    Profile(#[from] ManifestError),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    ImageAcquisition(#[from] pocket_oci::Error),
    #[error(transparent)]
    ImageBuild(#[from] HostBuildError),
    #[error(
        "generation field {field} does not match the selected profile: expected {expected:?}, observed {actual:?}"
    )]
    GenerationProfileMismatch {
        field: &'static str,
        expected: String,
        actual: String,
    },
    #[error(transparent)]
    Runtime(#[from] RuntimeError),
    #[error("could not {operation}: {source}")]
    Output {
        operation: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("captured {stream} was truncated after {retained} of {total} bytes")]
    OutputTruncated {
        stream: &'static str,
        retained: usize,
        total: u64,
    },
    #[error("could not serialize JSON output: {source}")]
    JsonOutput {
        #[source]
        source: serde_json::Error,
    },
}

impl CliError {
    #[must_use]
    pub fn code(&self) -> String {
        match self {
            Self::FeatureUnsupported { .. } => CliErrorCode::FeatureUnsupported.as_str().into(),
            Self::InvalidInput { .. } => CliErrorCode::InvalidInput.as_str().into(),
            Self::ManagedPath(error) => error.code().as_str().into(),
            Self::Profile(_) => CliErrorCode::ProfileInvalid.as_str().into(),
            Self::Store(_) => CliErrorCode::Store.as_str().into(),
            Self::ImageAcquisition(_) => CliErrorCode::ImageAcquisition.as_str().into(),
            Self::ImageBuild(_) => CliErrorCode::ImageBuild.as_str().into(),
            Self::GenerationProfileMismatch { .. } => {
                CliErrorCode::GenerationProfileMismatch.as_str().into()
            }
            Self::Runtime(error) => runtime_error_code(error),
            Self::Output { .. } | Self::OutputTruncated { .. } | Self::JsonOutput { .. } => {
                CliErrorCode::Output.as_str().into()
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CommandStatus(u8);

impl CommandStatus {
    const SUCCESS: Self = Self(0);
}

/// Parse and execute a CLI invocation using process standard streams.
#[must_use]
pub fn main_entry<I, T>(arguments: I) -> ExitCode
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let mut stdin = io::stdin().lock();
    let mut stdout = io::stdout().lock();
    let mut stderr = io::stderr().lock();
    ExitCode::from(run_from(arguments, &mut stdin, &mut stdout, &mut stderr))
}

/// Testable frontend which never exits the process itself.
pub fn run_from<I, T>(
    arguments: I,
    stdin: &mut dyn Read,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> u8
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let cli = match Cli::try_parse_from(arguments) {
        Ok(cli) => cli,
        Err(error) => return render_parse_error(error, stdout, stderr),
    };
    match execute(cli, stdin, stdout, stderr) {
        Ok(status) => status.0,
        Err(error) => {
            let _ = writeln!(stderr, "pocket: [{}] {error}", error.code());
            OPERATIONAL_ERROR_EXIT
        }
    }
}

fn render_parse_error(error: clap::Error, stdout: &mut dyn Write, stderr: &mut dyn Write) -> u8 {
    let help_or_version = matches!(
        error.kind(),
        ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
    );
    if help_or_version {
        let _ = stdout.write_all(error.to_string().as_bytes());
        0
    } else {
        let _ = stderr.write_all(error.to_string().as_bytes());
        USAGE_ERROR_EXIT
    }
}

/// Fill unset path arguments from the config file. A flag that was given is
/// never overridden.
fn apply_config(command: &mut Command, config: &Config) {
    let fill = |slot: &mut Option<PathBuf>, value: &Option<PathBuf>| {
        if slot.is_none() {
            slot.clone_from(value);
        }
    };
    match command {
        Command::Run(arguments) => {
            fill(&mut arguments.profile_bundle, &config.profile_bundle);
            fill(&mut arguments.store, &config.store);
            fill(&mut arguments.runtime_root, &config.runtime_root);
        }
        Command::Image { command } => match command {
            ImageCommand::Pull { context, .. }
            | ImageCommand::Import { context, .. }
            | ImageCommand::Adjust { context, .. } => {
                fill(&mut context.profile_bundle, &config.profile_bundle);
                fill(&mut context.store, &config.store);
                fill(&mut context.runtime_root, &config.runtime_root);
            }
            ImageCommand::Inspect { context, .. } => {
                fill(&mut context.profile_bundle, &config.profile_bundle);
                fill(&mut context.store, &config.store);
            }
            ImageCommand::List => {}
        },
        Command::Ps {
            runtime_root,
            store,
            ..
        } => {
            fill(runtime_root, &config.runtime_root);
            fill(store, &config.store);
        }
        Command::Commit {
            store,
            profile_bundle,
            runtime_root,
            ..
        } => {
            fill(store, &config.store);
            fill(profile_bundle, &config.profile_bundle);
            fill(runtime_root, &config.runtime_root);
        }
        Command::Rm { store, .. } => fill(store, &config.store),
        Command::Generation { command } => match command {
            GenerationCommand::Inspect { store, .. } | GenerationCommand::List { store, .. } => {
                fill(&mut store.store, &config.store);
            }
        },
        Command::Cache { command } => match command {
            CacheCommand::Gc { store, .. }
            | CacheCommand::Roots { store, .. }
            | CacheCommand::Forget { store, .. } => fill(&mut store.store, &config.store),
        },
        Command::Attach | Command::Exec | Command::Profile { .. } => {}
    }
}

/// A path argument that must be set by now, with a message naming both ways to
/// supply it.
fn required_path<'a>(
    value: &'a Option<PathBuf>,
    flag: &'static str,
    key: &'static str,
) -> Result<&'a Path, CliError> {
    value.as_deref().ok_or_else(|| {
        let location = Config::path().map_or_else(
            || "a config file".to_owned(),
            |path| path.display().to_string(),
        );
        invalid(flag, format!("pass --{flag} or set {key} in {location}"))
    })
}

fn execute(
    cli: Cli,
    stdin: &mut dyn Read,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> Result<CommandStatus, CliError> {
    let mut cli = cli;
    // Fill any path the caller did not give from the config file, once, before
    // anything is opened. A flag always wins; nothing is ever guessed.
    apply_config(&mut cli.command, &Config::load()?);
    match cli.command {
        Command::Profile { command } => execute_profile(command, stdout),
        Command::Image { command } => execute_image(command, stdout),
        Command::Generation { command } => execute_generation(command, stdout),
        Command::Cache { command } => execute_cache(command, stdout),
        Command::Ps {
            runtime_root,
            all,
            store,
            json,
        } => execute_ps(runtime_root.as_deref(), all, store.as_deref(), json, stdout),
        Command::Commit {
            store,
            profile_bundle,
            runtime_root,
            name,
            reference,
            json,
        } => execute_commit(
            store.as_deref(),
            profile_bundle.as_deref(),
            runtime_root.as_deref(),
            &name,
            &reference,
            json,
            stdout,
        ),
        Command::Rm { store, names, json } => execute_rm(store.as_deref(), &names, json, stdout),
        Command::Attach => Err(unsupported(
            "attach",
            "a run is a foreground process with no daemon behind it, so there is \
             nothing to attach to; keep the terminal that started it",
        )),
        Command::Exec => Err(unsupported(
            "exec",
            "a run executes exactly one process, decided before the guest starts; \
             starting a second one needs a control message the protocol does not have",
        )),
        Command::Run(arguments) => execute_run(*arguments, stdin, stdout, stderr),
    }
}

fn execute_profile(
    command: ProfileCommand,
    stdout: &mut dyn Write,
) -> Result<CommandStatus, CliError> {
    match command {
        ProfileCommand::Seal(arguments) => execute_profile_seal(*arguments, stdout),
        ProfileCommand::Verify { bundle, json } => {
            let profile = load_profile(&bundle)?;
            let summary = profile_summary(&profile, &bundle);
            if json {
                write_json(stdout, &summary)?;
            } else {
                write_profile_output(stdout, &[summary], false)?;
            }
            Ok(CommandStatus::SUCCESS)
        }
        ProfileCommand::List { bundles, json } => {
            let mut profiles = Vec::with_capacity(bundles.len());
            for bundle in bundles {
                let profile = load_profile(&bundle)?;
                profiles.push(profile_summary(&profile, &bundle));
            }
            profiles.sort_by(|left, right| {
                left["profile_id"]
                    .as_str()
                    .cmp(&right["profile_id"].as_str())
                    .then_with(|| {
                        left["profile_revision"]
                            .as_str()
                            .cmp(&right["profile_revision"].as_str())
                    })
            });
            write_profile_output(stdout, &profiles, json)?;
            Ok(CommandStatus::SUCCESS)
        }
    }
}

fn execute_profile_seal(
    arguments: ProfileSealArgs,
    stdout: &mut dyn Write,
) -> Result<CommandStatus, CliError> {
    let request = ProfileSealRequest {
        template: arguments.template,
        output_parent: managed_path(&arguments.output_parent)?,
        artifacts: ProfileArtifactSources {
            guard: arguments.guard,
            uml: arguments.uml,
            skopeo: arguments.skopeo,
            network_helper: arguments.slirp4netns,
            registry_ca_bundle: arguments.registry_ca_bundle,
            workload_initramfs: arguments.workload_initramfs,
            builder_initramfs: arguments.builder_initramfs,
            validator_initramfs: arguments.validator_initramfs,
            mke2fs: arguments.mke2fs,
            e2fsck: arguments.e2fsck,
            resize2fs: arguments.resize2fs,
            debugfs: arguments.debugfs,
            mke2fs_config: arguments.mke2fs_config,
            e2fsck_config: arguments.e2fsck_config,
            normalized_kernel_config: arguments.kernel_config,
        },
        umoci: BuilderToolContract {
            role: "umoci".to_owned(),
            sha256: arguments.umoci_sha256,
            version: arguments.umoci_version,
        },
    };
    let sealed = seal_profile_bundle(&request)?;
    let mut summary = profile_summary(sealed.profile(), sealed.bundle_root().as_path());
    summary["newly_published"] = Value::Bool(sealed.newly_published());
    if arguments.json {
        write_json(stdout, &summary)?;
    } else {
        write_profile_output(stdout, &[summary], false)?;
    }
    Ok(CommandStatus::SUCCESS)
}

fn execute_image(command: ImageCommand, stdout: &mut dyn Write) -> Result<CommandStatus, CliError> {
    match command {
        ImageCommand::Inspect {
            context,
            target,
            json,
        } => {
            let target = target_kind(&target)?;
            let profile = load_profile(required_path(
                &context.profile_bundle,
                "profile-bundle",
                "profile_bundle",
            )?)?;
            let requested_platform = requested_platform(&profile, context.platform.as_deref())?;
            let store = open_store(required_path(&context.store, "store", "store")?)?;
            let lease = lease_target(&store, &profile, target, requested_platform.clone())?;
            validate_generation_profile(&profile, lease.generation())?;
            validate_requested_platform(&requested_platform, lease.generation())?;
            let summary = generation_summary(lease.generation());
            if json {
                write_json(stdout, &summary)?;
            } else {
                write_generation_output(stdout, &[summary], false)?;
            }
            Ok(CommandStatus::SUCCESS)
        }
        ImageCommand::List => Err(unsupported(
            "image-list",
            "the store does not yet expose safe profile-qualified alias enumeration",
        )),
        ImageCommand::Pull {
            context,
            source,
            acquisition_timeout,
        } => execute_image_pull(context, &source, &acquisition_timeout, stdout),
        ImageCommand::Import { context, source } => execute_image_import(context, source, stdout),
        ImageCommand::Adjust {
            context,
            source,
            size,
        } => execute_image_adjust(context, &source, &size, stdout),
    }
}

/// Republish one image's filesystem at a different size.
///
/// The reference is the source's, so an adjusted image replaces its own alias
/// and the original generation stays addressable by ID. Naming the result
/// something else is `--reference`, exactly as for a pull.
fn execute_image_adjust(
    context: ImageBuildArgs,
    source: &str,
    size: &str,
    stdout: &mut dyn Write,
) -> Result<CommandStatus, CliError> {
    let target_bytes = ParsedMemory::from_str(size)
        .map_err(|error| invalid("size", error.to_string()))?
        .bytes();
    let profile = load_profile(required_path(
        &context.profile_bundle,
        "profile-bundle",
        "profile_bundle",
    )?)?;
    let requested_platform = requested_platform(&profile, context.platform.as_deref())?;
    let store = open_store(required_path(&context.store, "store", "store")?)?;
    let runtime_root = managed_runtime_root(required_path(
        &context.runtime_root,
        "runtime-root",
        "runtime_root",
    )?)?;
    let alias = alias_key(&profile, source, requested_platform.clone())?;
    let reference = context
        .reference
        .clone()
        .unwrap_or_else(|| source.to_owned());
    let builder = HostBuilder::new(&profile, &store, runtime_root, BuilderPolicy::default())?;
    let output = builder.adjust(pocket_runtime::AdjustRequest {
        source: alias,
        reference: reference.clone(),
        target_bytes,
    })?;
    write_build_output(
        stdout,
        &context,
        &output,
        "adjust",
        json!({ "source_reference": source, "target_bytes": target_bytes }),
        &reference,
        &platform_text(&requested_platform),
    )?;
    Ok(CommandStatus::SUCCESS)
}

fn execute_image_import(
    context: ImageBuildArgs,
    source: ImageImportSourceArgs,
    stdout: &mut dyn Write,
) -> Result<CommandStatus, CliError> {
    // An import has no source name to borrow, so the alias stays required.
    let reference = context.reference.clone().ok_or_else(|| {
        invalid(
            "reference",
            "an import has no name of its own; pass --reference",
        )
    })?;
    let context = ImageBuildArgs {
        reference: Some(reference.clone()),
        ..context
    };
    validate_builder_reference(&reference)?;
    if let Some(platform) = context.platform.as_deref() {
        validate_explicit_platform_syntax(platform)?;
    }
    validate_evidence_path(context.evidence_out.as_deref())?;
    let (source_path, source_kind) = match (
        source.oci.as_deref(),
        source.oci_archive.as_deref(),
        source.docker_archive.as_deref(),
    ) {
        (Some(path), None, None) => (path, SkopeoSourceKind::DockerRegistry),
        (None, Some(path), None) => (path, SkopeoSourceKind::OciArchive),
        (None, None, Some(path)) => (path, SkopeoSourceKind::DockerArchive),
        _ => {
            return Err(invalid(
                "image-import-source",
                "exactly one of --oci, --oci-archive, or --docker-archive is required",
            ));
        }
    };
    validate_import_path_syntax(source_path)?;

    let profile = load_profile(required_path(
        &context.profile_bundle,
        "profile-bundle",
        "profile_bundle",
    )?)?;
    let requested = requested_platform(&profile, context.platform.as_deref())?;
    let store = open_or_initialize_store(required_path(&context.store, "store", "store")?)?;
    let runtime_root = managed_runtime_root(required_path(
        &context.runtime_root,
        "runtime-root",
        "runtime_root",
    )?)?;
    let builder = HostBuilder::new(
        &profile,
        &store,
        runtime_root.clone(),
        BuilderPolicy::default(),
    )?;
    if source_kind == SkopeoSourceKind::DockerRegistry {
        // Authenticate the complete canonical layout before construction.
        // HostBuilder repeats this check before and after its derivation lock.
        let image = pocket_oci::verify_canonical_layout(source_path)?;
        let output = builder.build(BuildRequest {
            oci_layout: source_path.to_path_buf(),
            source_reference: reference.clone(),
            requested_variant: requested.variant().map(str::to_owned),
        })?;
        let evidence = acquisition_evidence(
            "oci-import",
            &source_path.display().to_string(),
            &image,
            None,
            None,
        )?;
        write_build_output(
            stdout,
            &context,
            &output,
            "oci-import",
            evidence,
            &reference,
            &platform_text(&requested),
        )?;
        return Ok(CommandStatus::SUCCESS);
    }

    let mut acquisition = AcquisitionDirectory::create(runtime_root.as_path())?;
    let archive = acquisition.stage_archive(source_path, source_kind)?;
    let platform = SkopeoPlatform::new(
        requested.os(),
        requested.architecture(),
        requested.variant().map(str::to_owned),
    )?;
    let normalizer = SkopeoNormalizer::new(
        profile.skopeo_path(),
        profile.guard_path(),
        SkopeoExecutionPolicy {
            timeout: archive_normalization_timeout(archive.size()),
            ..SkopeoExecutionPolicy::default()
        },
    )?;
    profile.reverify()?;
    let normalized = normalizer.normalize_archive(&archive, &platform, &acquisition)?;
    validate_normalized_platform(&requested, &normalized.image)?;
    let output = builder.build(BuildRequest {
        oci_layout: acquisition.as_path().join("layout"),
        source_reference: reference.clone(),
        requested_variant: requested.variant().map(str::to_owned),
    })?;
    let kind_text = match source_kind {
        SkopeoSourceKind::OciArchive => "oci-archive-import",
        SkopeoSourceKind::DockerArchive => "docker-archive-import",
        SkopeoSourceKind::DockerRegistry => unreachable!(),
    };
    let evidence = acquisition_evidence(
        kind_text,
        &source_path.display().to_string(),
        &normalized.image,
        Some(&normalized),
        Some((archive.sha256(), archive.size())),
    )?;
    acquisition.cleanup()?;
    write_build_output(
        stdout,
        &context,
        &output,
        kind_text,
        evidence,
        &reference,
        &platform_text(&requested),
    )?;
    Ok(CommandStatus::SUCCESS)
}

fn execute_image_pull(
    context: ImageBuildArgs,
    source: &str,
    acquisition_timeout: &str,
    stdout: &mut dyn Write,
) -> Result<CommandStatus, CliError> {
    // These input-only checks deliberately precede profile, store, and runtime
    // path access. Authentication flags are not part of the grammar at all.
    //
    // A shorthand is expanded before anything else looks at it, so everything
    // downstream -- parsing, evidence, the recorded source -- sees the one
    // fully-qualified form that was actually fetched.
    let expanded = expand_pull_source(source)?;
    // The alias defaults to what the caller asked for rather than to the
    // expanded form: `pocket image pull alpine:3.22` should be runnable as
    // `alpine:3.22`, not as `docker.io/library/alpine:3.22`.
    let reference = context
        .reference
        .clone()
        .unwrap_or_else(|| source.to_owned());
    let context = ImageBuildArgs {
        reference: Some(reference.clone()),
        ..context
    };
    let source = SkopeoSource::parse(&expanded)?;
    validate_builder_reference(&reference)?;
    if let Some(platform) = context.platform.as_deref() {
        validate_explicit_platform_syntax(platform)?;
    }
    validate_evidence_path(context.evidence_out.as_deref())?;
    let acquisition_timeout = parse_duration(acquisition_timeout)?;

    let profile = load_profile(required_path(
        &context.profile_bundle,
        "profile-bundle",
        "profile_bundle",
    )?)?;
    let requested = requested_platform(&profile, context.platform.as_deref())?;
    let store = open_or_initialize_store(required_path(&context.store, "store", "store")?)?;
    let runtime_root = managed_runtime_root(required_path(
        &context.runtime_root,
        "runtime-root",
        "runtime_root",
    )?)?;
    let builder = HostBuilder::new(
        &profile,
        &store,
        runtime_root.clone(),
        BuilderPolicy::default(),
    )?;
    let mut acquisition = AcquisitionDirectory::create(runtime_root.as_path())?;
    let platform = SkopeoPlatform::new(
        requested.os(),
        requested.architecture(),
        requested.variant().map(str::to_owned),
    )?;
    let normalizer = SkopeoNormalizer::new(
        profile.skopeo_path(),
        profile.guard_path(),
        SkopeoExecutionPolicy {
            timeout: acquisition_timeout,
            ..SkopeoExecutionPolicy::default()
        },
    )?;
    profile.reverify()?;
    let normalized = normalizer.normalize(
        &source,
        &platform,
        &acquisition,
        profile.registry_ca_bundle_path(),
    )?;
    validate_normalized_platform(&requested, &normalized.image)?;
    let output = builder.build(BuildRequest {
        oci_layout: acquisition.as_path().join("layout"),
        source_reference: reference.clone(),
        requested_variant: requested.variant().map(str::to_owned),
    })?;
    let evidence = acquisition_evidence(
        "docker-pull",
        source.as_str(),
        &normalized.image,
        Some(&normalized),
        None,
    )?;
    acquisition.cleanup()?;
    write_build_output(
        stdout,
        &context,
        &output,
        "docker-pull",
        evidence,
        &reference,
        &platform_text(&requested),
    )?;
    Ok(CommandStatus::SUCCESS)
}

fn execute_generation(
    command: GenerationCommand,
    stdout: &mut dyn Write,
) -> Result<CommandStatus, CliError> {
    match command {
        GenerationCommand::Inspect { store, id, json } => {
            let id = parse_generation_id(&id)?;
            let store = open_store(required_path(&store.store, "store", "store")?)?;
            let lease = store.acquire_lease(id)?;
            let summary = generation_summary(lease.generation());
            if json {
                write_json(stdout, &summary)?;
            } else {
                write_generation_output(stdout, &[summary], false)?;
            }
            Ok(CommandStatus::SUCCESS)
        }
        GenerationCommand::List {
            store,
            derivation,
            json,
        } => {
            let derivation = parse_derivation_key(&derivation)?;
            let store = open_store(required_path(&store.store, "store", "store")?)?;
            let generations = store.generations_for_derivation(derivation)?;
            let summaries: Vec<Value> = generations.iter().map(generation_summary).collect();
            write_generation_output(stdout, &summaries, json)?;
            Ok(CommandStatus::SUCCESS)
        }
    }
}

fn execute_cache(command: CacheCommand, stdout: &mut dyn Write) -> Result<CommandStatus, CliError> {
    match command {
        CacheCommand::Gc { store, apply, json } => {
            if !apply {
                return Err(unsupported(
                    "cache-gc-dry-run",
                    "the store currently exposes only an atomic apply operation; no deletion occurred",
                ));
            }
            let store = open_store(required_path(&store.store, "store", "store")?)?;
            let report = store.garbage_collect()?;
            write_gc_output(stdout, &report, json)?;
            Ok(CommandStatus::SUCCESS)
        }
        CacheCommand::Roots { store, json } => {
            let store = open_store(required_path(&store.store, "store", "store")?)?;
            write_alias_roots_output(stdout, &store.alias_roots()?, json)?;
            Ok(CommandStatus::SUCCESS)
        }
        CacheCommand::Forget { store, alias } => {
            let alias: AliasId = alias.parse().map_err(|_| {
                invalid(
                    "alias",
                    "must be an alias ID as printed by `pocket cache roots`",
                )
            })?;
            let store = open_store(required_path(&store.store, "store", "store")?)?;
            let removed = store.remove_alias_by_id(alias)?;
            writeln!(stdout, "alias={alias} removed={removed}")
                .map_err(|source| output_error("write alias removal output", source))?;
            Ok(CommandStatus::SUCCESS)
        }
    }
}

/// List operations whose owner is still alive.
///
/// Reads the runtime root directly rather than consulting a daemon, because
/// there is none. A run holds an exclusive lock on its own directory for its
/// whole life, and the kernel releases that lock when the owner dies however
/// it dies -- so a directory whose lock cannot be taken has a living owner.
/// This is the reclamation sweep's test read the other way round, which means
/// the listing cannot drift out of step with reality the way a daemon's
/// bookkeeping can.
fn execute_ps(
    runtime_root: Option<&Path>,
    all: bool,
    store: Option<&Path>,
    json: bool,
    stdout: &mut dyn Write,
) -> Result<CommandStatus, CliError> {
    let config = Config::load()?;
    let root = runtime_root
        .map(Path::to_path_buf)
        .or_else(|| config.runtime_root.clone())
        .ok_or_else(|| {
            invalid(
                "runtime-root",
                "pass --runtime-root or set runtime_root in the config file",
            )
        })?;
    let managed = managed_runtime_root(&root)?;
    let live = pocket_runtime::live_operations(managed.as_path(), "run-")
        .map_err(|source| output_error("list running operations", source))?;
    // Kept runs live in the store, not the runtime root: they outlive it.
    let kept = if all {
        let path = store
            .map(Path::to_path_buf)
            .or_else(|| Config::load().ok().and_then(|config| config.store))
            .ok_or_else(|| invalid("store", "pass --store or set store in the config file"))?;
        open_or_initialize_store(&path)?.instances()?
    } else {
        Vec::new()
    };

    if json {
        let rows: Vec<Value> = live
            .iter()
            .map(|operation| {
                let mut row = serde_json::Map::<String, Value>::new();
                row.insert("id".to_owned(), json!(operation.id));
                for (key, value) in &operation.description {
                    row.insert(key.clone(), json!(value));
                }
                Value::Object(row)
            })
            .collect();
        let exited: Vec<Value> = kept.iter().map(instance_row).collect();
        let mut document = serde_json::Map::<String, Value>::new();
        document.insert("running".to_owned(), Value::Array(rows));
        if all {
            document.insert("exited".to_owned(), Value::Array(exited));
        }
        writeln!(stdout, "{}", Value::Object(document))
            .map_err(|source| output_error("write ps output", source))?;
        return Ok(CommandStatus::SUCCESS);
    }
    for operation in &live {
        let field = |name: &str| {
            operation
                .description
                .iter()
                .find(|(key, _)| key == name)
                .map_or("-", |(_, value)| value.as_str())
        };
        writeln!(
            stdout,
            "id={} generation={} pid={} started={} cpus={} memory_bytes={}",
            operation.id,
            field("generation"),
            field("pid"),
            field("started"),
            field("cpus"),
            field("memory_bytes"),
        )
        .map_err(|source| output_error("write ps output", source))?;
    }
    for instance in &kept {
        writeln!(
            stdout,
            "name={} status={} image={} generation={} created={} finished={} command={}",
            instance.name(),
            outcome_text(instance.outcome()),
            instance.image_reference(),
            instance.generation_id(),
            instance.created_unix(),
            instance.finished_unix(),
            instance.command(),
        )
        .map_err(|source| output_error("write ps output", source))?;
    }
    Ok(CommandStatus::SUCCESS)
}

/// A name for a run the operator did not name, in the shape they would have
/// chosen: short, typeable, and unlikely to collide within one store.
fn generated_instance_name() -> String {
    const ADJECTIVES: [&str; 16] = [
        "amber", "brisk", "calm", "dusky", "eager", "fleet", "gentle", "hazy", "ivory", "jolly",
        "keen", "lucid", "mellow", "nimble", "olive", "plucky",
    ];
    const NOUNS: [&str; 16] = [
        "alloy", "basin", "cedar", "delta", "ember", "fjord", "grove", "harbor", "inlet", "jetty",
        "kiln", "ledge", "mesa", "nook", "orchard", "prairie",
    ];
    // Time and pid are what distinguish two runs started side by side; the
    // words are only there to make the result something a person can say.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_nanos() as u64);
    let pid = u64::from(std::process::id());
    let mixed = now ^ pid.rotate_left(29);
    format!(
        "{}-{}-{:04x}",
        ADJECTIVES[(mixed >> 8) as usize % ADJECTIVES.len()],
        NOUNS[(mixed >> 16) as usize % NOUNS.len()],
        mixed as u16,
    )
}

fn outcome_text(outcome: InstanceOutcome) -> String {
    match outcome {
        InstanceOutcome::Exited(code) => format!("exited({code})"),
        InstanceOutcome::Signalled(signal) => format!("signalled({signal})"),
        InstanceOutcome::Unknown => "unknown".to_owned(),
    }
}

fn instance_row(instance: &Instance) -> Value {
    json!({
        "name": instance.name(),
        "id": instance.id().to_string(),
        "status": outcome_text(instance.outcome()),
        "image": instance.image_reference(),
        "generation": instance.generation_id().to_string(),
        "created": instance.created_unix(),
        "finished": instance.finished_unix(),
        "command": instance.command(),
    })
}

/// Publish a kept run's filesystem as a new image.
///
/// Not implemented, and refused by name rather than left to read as a typo.
/// The merge itself is the easy half: a UML COW is a v3 header, a sector
/// bitmap and the sectors that changed, so applying it over a copy of the base
/// is mechanical. What is missing is the evidence. A generation carries a
/// `metadata.manifest` and validation evidence describing the filesystem it
/// holds, produced by a guest that walks it; a commit is the one operation
/// that changes those contents, so copying the source's sidecars would publish
/// a generation whose recorded evidence describes a filesystem that no longer
/// exists. Committing honestly needs a guest pass over the merged filesystem,
/// which `image adjust` did not because a resize preserves contents exactly.
fn execute_commit(
    store: Option<&Path>,
    profile_bundle: Option<&Path>,
    runtime_root: Option<&Path>,
    name: &str,
    reference: &str,
    json: bool,
    stdout: &mut dyn Write,
) -> Result<CommandStatus, CliError> {
    let config = Config::load()?;
    let store_path = store
        .map(Path::to_path_buf)
        .or_else(|| config.store.clone())
        .ok_or_else(|| invalid("store", "pass --store or set store in the config file"))?;
    let bundle = profile_bundle
        .map(Path::to_path_buf)
        .or_else(|| config.profile_bundle.clone())
        .ok_or_else(|| {
            invalid(
                "profile-bundle",
                "pass --profile-bundle or set profile_bundle in the config file",
            )
        })?;
    let root = runtime_root
        .map(Path::to_path_buf)
        .or_else(|| config.runtime_root.clone())
        .ok_or_else(|| {
            invalid(
                "runtime-root",
                "pass --runtime-root or set runtime_root in the config file",
            )
        })?;

    let profile = load_profile(&bundle)?;
    let store = open_or_initialize_store(&store_path)?;
    let managed_root = managed_runtime_root(&root)?;

    let instance = store.instance(name)?;
    // Lease the retained overlay and its backing generation together, so
    // neither can be collected while the merge reads them.
    let retained = store.lease_retained_cow(instance.retained_id())?;
    let source = store.acquire_lease(instance.generation_id())?;
    let cow_path = retained.retained().cow_path().as_path().to_path_buf();

    let builder = HostBuilder::new(&profile, &store, managed_root, BuilderPolicy::default())?;
    let output = builder.commit(CommitRequest {
        source,
        cow_path,
        instance_name: instance.name().to_owned(),
        reference: reference.to_owned(),
    })?;

    if json {
        writeln!(
            stdout,
            "{}",
            json!({
                "generation_id": output.generation_id.to_string(),
                "alias_id": output.alias_id.to_string(),
                "reference": reference,
                "instance": instance.name(),
                "cache_hit": output.cache_hit,
            })
        )
        .map_err(|source| output_error("write commit output", source))?;
    } else {
        writeln!(
            stdout,
            "generation_id={} alias_id={} reference={} instance={} cache_hit={}",
            output.generation_id,
            output.alias_id,
            reference,
            instance.name(),
            output.cache_hit,
        )
        .map_err(|source| output_error("write commit output", source))?;
    }
    Ok(CommandStatus::SUCCESS)
}

/// Remove kept runs, reporting each by name.
fn execute_rm(
    store: Option<&Path>,
    names: &[String],
    json: bool,
    stdout: &mut dyn Write,
) -> Result<CommandStatus, CliError> {
    let path = store
        .map(Path::to_path_buf)
        .or_else(|| Config::load().ok().and_then(|config| config.store))
        .ok_or_else(|| invalid("store", "pass --store or set store in the config file"))?;
    let store = open_or_initialize_store(&path)?;
    let mut removed = Vec::with_capacity(names.len());
    for name in names {
        let instance = store.remove_instance(name)?;
        removed.push(json!({ "name": instance.name(), "id": instance.id().to_string() }));
        if !json {
            writeln!(stdout, "removed={}", instance.name())
                .map_err(|source| output_error("write rm output", source))?;
        }
    }
    if json {
        writeln!(stdout, "{}", json!({ "removed": removed }))
            .map_err(|source| output_error("write rm output", source))?;
    }
    Ok(CommandStatus::SUCCESS)
}

fn execute_run(
    arguments: RunArgs,
    stdin: &mut dyn Read,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> Result<CommandStatus, CliError> {
    validate_run_feature_surface(&arguments)?;
    let target = target_kind(&arguments.image)?;
    let cpus = parse_decimal_u16("cpus", &arguments.cpus, false)?;
    let requested_memory = arguments
        .memory
        .as_deref()
        .map(ParsedMemory::from_str)
        .transpose()
        .map_err(|error| CliError::InvalidInput {
            field: "memory",
            reason: error.to_string(),
        })?;
    let umask = parse_umask(&arguments.umask)?;
    if let Some(workdir) = &arguments.workdir {
        validate_guest_path("workdir", workdir)?;
    }
    // These two are caller input, so a malformed one is an input error and must
    // be reported as one, before a profile or store is opened. The runtime
    // re-checks them against the image's own account database later, where a
    // failure genuinely is about the image rather than the command line.
    if let Some(signal) = &arguments.stop_signal {
        pocket_runtime::parse_image_signal(signal)
            .map_err(|error| invalid("stop-signal", error.to_string()))?;
    }
    if let Some(user) = &arguments.user {
        validate_user_spec(user)?;
    }
    validate_hostname(&arguments.hostname)?;
    for entry in &arguments.env {
        validate_env(entry)?;
    }
    for (index, value) in arguments.command.iter().enumerate() {
        validate_no_nul(if index == 0 { "command" } else { "argument" }, value)?;
        if index == 0 && value.is_empty() {
            return Err(invalid("command", "argv[0] must not be empty"));
        }
    }
    let execution_timeout = arguments
        .timeout
        .as_deref()
        .map(parse_duration)
        .transpose()?;
    let console_log = arguments.console_log.clone();

    // A terminal session streams input for as long as it lasts, so there is
    // nothing to read up front; `-i` is implied rather than separately obeyed.
    let input = if arguments.interactive && !arguments.tty {
        read_bounded_stdin(stdin)?
    } else {
        Vec::new()
    };
    let profile = load_profile(required_path(
        &arguments.profile_bundle,
        "profile-bundle",
        "profile_bundle",
    )?)?;
    let requested_platform = requested_platform(&profile, arguments.platform.as_deref())?;
    let memory = match requested_memory {
        Some(memory) => memory,
        None => ParsedMemory::from_bytes(profile.manifest().memory.default_memory_bytes).map_err(
            |error| CliError::InvalidInput {
                field: "profile.memory.default_memory_bytes",
                reason: error.to_string(),
            },
        )?,
    };
    profile
        .cpu_profile()
        .validate_request(cpus)
        .map_err(|error| CliError::InvalidInput {
            field: "cpus",
            reason: error.to_string(),
        })?;
    profile
        .memory_policy()
        .validate(memory)
        .map_err(|error| CliError::InvalidInput {
            field: "memory",
            reason: error.to_string(),
        })?;
    let store = open_store(required_path(&arguments.store, "store", "store")?)?;
    let lease = lease_target(&store, &profile, target, requested_platform.clone())?;
    validate_generation_profile(&profile, lease.generation())?;
    validate_requested_platform(&requested_platform, lease.generation())?;
    let argv = if arguments.exact_argv {
        ImageArgv::Exact(arguments.command)
    } else if arguments.command.is_empty() {
        ImageArgv::Default
    } else {
        ImageArgv::ReplaceCmd(arguments.command)
    };
    let entrypoint = arguments.entrypoint.map(|entrypoint| {
        if entrypoint.is_empty() {
            Vec::new()
        } else {
            vec![entrypoint]
        }
    });
    let mut process = resolve_image_process(
        &lease,
        &ImageProcessOverrides {
            argv,
            entrypoint,
            env: arguments.env,
            hostname: arguments.hostname.clone(),
            user: arguments.user,
            working_dir: arguments.workdir,
            stop_signal: arguments.stop_signal,
        },
    )?;
    // A terminal session needs a terminal type or curses programs cannot draw.
    // The host's own is the accurate answer, but it is attacker-influencable
    // environment, so anything but a plain terminal name falls back rather
    // than being passed into the guest.
    if arguments.tty && !process.env.iter().any(|entry| entry.starts_with("TERM=")) {
        let host_term = std::env::var("TERM").ok().filter(|value| {
            !value.is_empty()
                && value.len() <= 64
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        });
        process
            .env
            .push(format!("TERM={}", host_term.as_deref().unwrap_or("xterm")));
    }
    validate_guest_path("workdir", &process.working_dir)?;
    // Held until the run ends: dropping these releases each shared directory
    // for the next run.
    let volumes = hold_volumes(&arguments.volume)?;
    let runtime_root = managed_runtime_root(required_path(
        &arguments.runtime_root,
        "runtime-root",
        "runtime_root",
    )?)?;
    let policy = RuntimePolicy {
        execution_timeout,
        ..RuntimePolicy::default()
    };
    let runtime = Runtime::new(&profile, &store, runtime_root, policy)?;
    // A run is kept unless it is told not to be, so an operator can come back
    // to what it produced. The name is what they will address it by.
    let retain = if arguments.rm {
        None
    } else {
        let name = match arguments.name.clone() {
            Some(name) => name,
            None => generated_instance_name(),
        };
        pocket_runtime::validate_instance_name(&name)
            .map_err(|error| invalid("name", error.to_string()))?;
        Some(RetainRequest {
            name,
            image_reference: arguments.image.clone(),
            command: process.argv.join(" "),
        })
    };
    // Taken as late as possible: everything that can be refused has been, so
    // the operator's terminal is only disturbed by a run that will start.
    let terminal = hold_terminal(arguments.tty)?;
    let options = RunOptions {
        cpus,
        memory,
        workload: WorkloadSpec {
            argv: process.argv,
            env: process.env,
            cwd: process.working_dir,
            uid: process.user.uid,
            gid: process.user.gid,
            supplementary_gids: process.user.supplementary_gids,
            umask,
            rlimits: Vec::new(),
            hostname: arguments.hostname,
            root_read_only: arguments.root_readonly,
            volumes: volumes.iter().map(|held| held.spec.clone()).collect(),
            network: arguments.network == NetworkMode::Slirp,
            privileged: arguments.privileged,
            stop_signal: process.stop_signal,
        },
        stdin: input,
        retain: retain.clone(),
        boot_log: arguments.boot_log,
        extra_consoles: arguments.consoles,
        terminal: terminal.as_ref().map(|session| session.request),
        console_log,
    };

    let started_unix = unix_now();
    // A run that never starts must not leave the directory it reserved in the
    // store behind, so every failure from here releases it.
    let discard_on_error = |error: CliError| -> CliError {
        if let Some(retain) = retain.as_ref() {
            let _ = runtime.discard_retained(&retain.name);
        }
        error
    };
    let output = match terminal {
        // The operator's terminal is held in raw mode for exactly as long as
        // the session runs, and is put back before anything is printed to it:
        // a diagnostic written while the terminal is still raw comes out
        // stepped across the screen.
        Some(mut session) => {
            let running = runtime
                .start_leased(lease, options)
                .map_err(|error| discard_on_error(error.into()))?;
            announce_consoles(running.extra_console_paths(), stderr)?;
            let result = running.wait_interactive(|| session.handle.take_resize());
            session.handle.restore();
            result.map_err(|error| discard_on_error(error.into()))?
        }
        None => {
            let running = runtime
                .start_leased(lease, options)
                .map_err(|error| discard_on_error(error.into()))?;
            announce_consoles(running.extra_console_paths(), stderr)?;
            running
                .wait()
                .map_err(|error| discard_on_error(error.into()))?
        }
    };
    // A kept run becomes an instance only once it has finished and its overlay
    // is quiescent. Failing to record it must not discard the run's own
    // result, so the failure is reported alongside the outcome.
    let mut retain_error = None;
    if let Some(retain) = retain.as_ref() {
        match runtime.retain_instance(&output, retain, started_unix, unix_now()) {
            Ok(instance) => {
                writeln!(stderr, "pocket: kept as {}", instance.name())
                    .map_err(|source| output_error("write retention notice", source))?;
            }
            Err(error) => {
                let _ = runtime.discard_retained(&retain.name);
                retain_error = Some(error.to_string());
            }
        }
    }
    if let Some(reason) = retain_error {
        writeln!(stderr, "pocket: warning: run not kept: {reason}")
            .map_err(|source| output_error("write retention diagnostic", source))?;
    }
    emit_run_output(output, cpus, stdout, stderr)
}

/// Tell the operator where to attach for each extra serial line.
///
/// Printed as soon as the run has started rather than with the result: a line
/// is only useful while the guest is still running, and a path reported
/// afterwards names a device that has already gone.
fn announce_consoles(paths: &[PathBuf], stderr: &mut dyn Write) -> Result<(), CliError> {
    for (index, path) in paths.iter().enumerate() {
        writeln!(
            stderr,
            "pocket: guest /dev/ttyS{} is attachable at {}",
            index + 4,
            path.display()
        )
        .map_err(|source| output_error("write console notice", source))?;
    }
    Ok(())
}

/// Seconds since the epoch, or zero on a clock this process cannot read.
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// The operator's terminal, together with the size the guest was started with.
struct HeldTerminal {
    handle: TerminalSession,
    request: TerminalRequest,
}

/// Take the operator's terminal for a session, if one was asked for.
fn hold_terminal(enabled: bool) -> Result<Option<HeldTerminal>, CliError> {
    if !enabled {
        return Ok(None);
    }
    let handle = TerminalSession::acquire().map_err(|error| {
        // Being told "stdin is not a terminal" is more useful than a raw-mode
        // failure, so the runtime's reason is carried through verbatim.
        invalid("tty", error.to_string())
    })?;
    let (rows, columns) = handle
        .size()
        .map_err(|error| invalid("tty", error.to_string()))?;
    Ok(Some(HeldTerminal {
        handle,
        request: TerminalRequest { rows, columns },
    }))
}

/// Wall-clock budget for normalizing one staged archive of `archive_bytes`.
///
/// Normalizing a local archive is a copy, so its cost is its size. `pull` takes
/// an explicit `--acquisition-timeout` because a registry transfer's size is
/// not knowable in advance; here it is, and a single fixed budget would be a
/// silent ceiling on the archive size that can be imported at all.
fn archive_normalization_timeout(archive_bytes: u64) -> Duration {
    const BASE: Duration = Duration::from_secs(15 * 60);
    const PER_GIB: Duration = Duration::from_secs(5 * 60);
    const CEILING: Duration = Duration::from_secs(24 * 60 * 60);
    let gibibytes = u32::try_from(archive_bytes.div_ceil(1024 * 1024 * 1024)).unwrap_or(u32::MAX);
    PER_GIB
        .checked_mul(gibibytes)
        .and_then(|allowance| allowance.checked_add(BASE))
        .unwrap_or(CEILING)
        .min(CEILING)
}

/// Defaults for the three paths every command needs, read from a config file.
///
/// Requiring `--profile-bundle`, `--store` and `--runtime-root` on every single
/// invocation is friction with no safety value: the flags still win when given,
/// and nothing is guessed -- a path only has a default because the operator
/// wrote one down.
#[derive(Debug, Default)]
struct Config {
    profile_bundle: Option<PathBuf>,
    store: Option<PathBuf>,
    runtime_root: Option<PathBuf>,
}

impl Config {
    /// `$POCKET_CONFIG`, else `$XDG_CONFIG_HOME/pocket/config.toml`, else
    /// `$HOME/.config/pocket/config.toml`.
    fn path() -> Option<PathBuf> {
        if let Some(explicit) = std::env::var_os("POCKET_CONFIG") {
            return Some(PathBuf::from(explicit));
        }
        if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME")
            && !xdg.is_empty()
        {
            return Some(PathBuf::from(xdg).join("pocket/config.toml"));
        }
        std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config/pocket/config.toml"))
    }

    fn load() -> Result<Self, CliError> {
        let Some(path) = Self::path() else {
            return Ok(Self::default());
        };
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(error) => {
                return Err(invalid(
                    "config",
                    format!("cannot read {}: {error}", path.display()),
                ));
            }
        };
        Self::parse(&text, &path)
    }

    /// A deliberately small grammar: `key = "value"`, `#` comments, blank
    /// lines. Anything else is refused and named rather than guessed at, so a
    /// typo in a config file can never silently change which store is used.
    fn parse(text: &str, path: &Path) -> Result<Self, CliError> {
        let mut config = Self::default();
        for (index, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let at = |reason: &str| {
                invalid(
                    "config",
                    format!("{}:{}: {reason}", path.display(), index + 1),
                )
            };
            let Some((key, value)) = line.split_once('=') else {
                return Err(at("expected key = \"value\""));
            };
            let value = value.trim();
            let Some(value) = value
                .strip_prefix('"')
                .and_then(|value| value.strip_suffix('"'))
            else {
                return Err(at(
                    "value must be double-quoted, with nothing after the closing quote",
                ));
            };
            if value.contains('\\') || value.contains('"') {
                return Err(at("value must not contain quotes or escapes"));
            }
            let slot = match key.trim() {
                "profile_bundle" => &mut config.profile_bundle,
                "store" => &mut config.store,
                "runtime_root" => &mut config.runtime_root,
                other => return Err(at(&format!("unknown key {other:?}"))),
            };
            if slot.is_some() {
                return Err(at(&format!("duplicate key {:?}", key.trim())));
            }
            *slot = Some(PathBuf::from(value));
        }
        Ok(config)
    }
}

/// One host directory to share, plus the lock that keeps it to a single run.
#[derive(Debug)]
struct HeldVolume {
    spec: VolumeSpec,
    _lock: std::fs::File,
}

/// Parse and validate `HOST_PATH:GUEST_PATH[:ro]`, then take an exclusive lock
/// on the host directory.
///
/// Concurrent use of one shared directory is refused rather than serialized or
/// silently allowed: two guests writing one hostfs tree with independent page
/// caches is a corruption the runtime cannot make safe, so it fails loudly and
/// names the directory.
fn hold_volumes(requests: &[String]) -> Result<Vec<HeldVolume>, CliError> {
    if requests.len() > pocket_runtime::MAX_VOLUME_COUNT {
        return Err(invalid(
            "volume",
            format!(
                "at most {} volumes may be shared",
                pocket_runtime::MAX_VOLUME_COUNT
            ),
        ));
    }
    let mut held: Vec<HeldVolume> = Vec::with_capacity(requests.len());
    for request in requests {
        validate_no_nul("volume", request)?;
        let (source, rest) = request
            .split_once(':')
            .ok_or_else(|| invalid("volume", "must be HOST_PATH:GUEST_PATH[:ro]"))?;
        let (destination, read_only) = match rest.rsplit_once(':') {
            Some((destination, "ro")) => (destination, true),
            Some((destination, "rw")) => (destination, false),
            _ => (rest, false),
        };
        if source.is_empty() || destination.is_empty() {
            return Err(invalid("volume", "must be HOST_PATH:GUEST_PATH[:ro]"));
        }
        validate_guest_path("volume.destination", destination)?;
        if destination == "/" {
            return Err(invalid(
                "volume.destination",
                "must not replace the image root",
            ));
        }
        // Refused here as well as in the guest, so the caller hears which path
        // is in the way before a kernel is started for a run that cannot work.
        if let Some(reserved) = pocket_runtime::reserved_guest_path_conflict(destination) {
            return Err(invalid(
                "volume.destination",
                format!(
                    "{destination} collides with {reserved}, which the runtime \
                     mounts or generates itself"
                ),
            ));
        }

        // Resolve the host path once, so the lock, the mount and any later
        // message all name the same directory even if the caller wrote a
        // symlinked or relative-looking spelling.
        let source_path = Path::new(source);
        if !source_path.is_absolute() {
            return Err(invalid("volume.source", "host path must be absolute"));
        }
        let resolved = std::fs::canonicalize(source_path).map_err(|error| {
            invalid(
                "volume.source",
                format!("host path {source} cannot be resolved: {error}"),
            )
        })?;
        if !resolved.is_dir() {
            return Err(invalid(
                "volume.source",
                format!("host path {source} is not a directory"),
            ));
        }
        let resolved_text = resolved
            .to_str()
            .ok_or_else(|| invalid("volume.source", "host path is not valid UTF-8"))?
            .to_owned();

        if held.iter().any(|other| other.spec.source == resolved_text) {
            return Err(invalid(
                "volume.source",
                format!("host path {resolved_text} is shared more than once"),
            ));
        }
        // Checked here too, not only in the guest's START contract. Every
        // other volume rule is refused by the CLI first so the caller hears
        // which path is wrong; without this one a repeated destination came
        // back as a protocol error, which reads as an internal fault.
        if held
            .iter()
            .any(|other| other.spec.destination == destination)
        {
            return Err(invalid(
                "volume.destination",
                format!("guest path {destination} is used by more than one volume"),
            ));
        }

        let lock = lock_volume_source(&resolved)?;
        held.push(HeldVolume {
            spec: VolumeSpec {
                source: resolved_text,
                destination: destination.to_owned(),
                read_only,
            },
            _lock: lock,
        });
    }
    Ok(held)
}

/// Take an exclusive lock on the shared host directory itself.
///
/// The lock is on the directory, not on a marker file inside it. A marker
/// would be part of the share: the workload sees it, and a job that tidies its
/// own output directory -- `find /data -delete` is enough -- removes the one
/// thing keeping a second run out, after which a third run claims a directory
/// the first is still writing to. That was reproducible. A directory cannot be
/// unlinked while it is a live mount, so locking it has no such hole, leaves
/// nothing behind in the caller's folder, and needs no write permission, which
/// is what makes an ordinary read-only share work.
///
/// On a network filesystem `flock` may be local to this machine, so two hosts
/// sharing one directory are not excluded from each other. That is stated in
/// the guide rather than papered over; it is the same limit the marker had.
fn lock_volume_source(resolved: &Path) -> Result<std::fs::File, CliError> {
    let directory = std::fs::File::open(resolved).map_err(|error| {
        invalid(
            "volume.source",
            format!("cannot claim {}: {error}", resolved.display()),
        )
    })?;
    match directory.try_lock() {
        Ok(()) => Ok(directory),
        Err(std::fs::TryLockError::WouldBlock) => Err(invalid(
            "volume.source",
            format!(
                "host path {} is already shared by another running pocket; \
                 one shared directory is used by one run at a time",
                resolved.display()
            ),
        )),
        Err(std::fs::TryLockError::Error(error)) => Err(invalid(
            "volume.source",
            format!("cannot claim {}: {error}", resolved.display()),
        )),
    }
}

fn validate_run_feature_surface(arguments: &RunArgs) -> Result<(), CliError> {
    if arguments.exact_argv && arguments.command.is_empty() {
        return Err(invalid(
            "exact-argv",
            "requires a nonempty complete argv after --",
        ));
    }
    if arguments.exact_argv && arguments.entrypoint.is_some() {
        return Err(invalid(
            "entrypoint",
            "cannot be combined with --exact-argv",
        ));
    }
    if arguments.detach {
        return Err(unsupported(
            "detach",
            "a run is a foreground process with no daemon to hand it to; its exit \
             status is the point, and nothing would be left to report it",
        ));
    }
    // `--rm` discards the run, so there is nothing left for a name to address.
    // Accepting both would silently ignore one of them.
    if arguments.rm && arguments.name.is_some() {
        return Err(invalid(
            "name",
            "--name cannot be combined with --rm: a discarded run leaves nothing to name",
        ));
    }
    // Checked here, with the other refusals, so piping into an interactive
    // run is refused before any path is opened. Raw mode itself is taken much
    // later, once the run is certain to start.
    if arguments.tty {
        for (role, is_terminal) in [
            ("stdin", io::stdin().is_terminal()),
            ("stdout", io::stdout().is_terminal()),
        ] {
            if !is_terminal {
                return Err(invalid(
                    "tty",
                    format!(
                        "--tty needs a terminal on both sides, but {role} is not a terminal;                          drop --tty to run with buffered streams"
                    ),
                ));
            }
        }
    }
    if !arguments.publish.is_empty() {
        return Err(unsupported(
            "port-forwarding",
            "the network helper accepts forwards over its API socket, which is not wired up",
        ));
    }
    if arguments.cpuset.is_some() {
        return Err(unsupported(
            "cpuset",
            "pocket-runtime does not apply host affinity yet",
        ));
    }
    if arguments.pull != PullPolicy::Never {
        return Err(unsupported(
            "pull-policy",
            "image acquisition is unavailable; only --pull never is accepted",
        ));
    }
    Ok(())
}

fn emit_run_output(
    output: RunOutput,
    cpus: u16,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> Result<CommandStatus, CliError> {
    // The run produced a result, so it is delivered either way; a transcript
    // that could not be written is reported rather than substituted for it.
    if let Some(reason) = &output.console_log_error {
        writeln!(stderr, "pocket: warning: console log not written: {reason}")
            .map_err(|source| output_error("write console diagnostic", source))?;
    }
    // A request within the profile's maximum is never rejected for the host's
    // current affinity or quota, so the only way the caller learns that the
    // vCPUs they asked for cannot actually run in parallel is if we say so.
    if cpus > 1 && !output.scaling_qualified {
        writeln!(
            stderr,
            "pocket: note: the host's CPU affinity or cgroup-v2 cpu.max cannot \
             deliver {cpus} parallel vCPUs, so the guest will run them oversubscribed"
        )
        .map_err(|source| output_error("write scaling diagnostic", source))?;
    }
    stdout
        .write_all(&output.stdout.bytes)
        .map_err(|source| output_error("write workload stdout", source))?;
    stderr
        .write_all(&output.stderr.bytes)
        .map_err(|source| output_error("write workload stderr", source))?;
    if output.stdout.truncated {
        return Err(CliError::OutputTruncated {
            stream: "stdout",
            retained: output.stdout.bytes.len(),
            total: output.stdout.total_bytes,
        });
    }
    if output.stderr.truncated {
        return Err(CliError::OutputTruncated {
            stream: "stderr",
            retained: output.stderr.bytes.len(),
            total: output.stderr.total_bytes,
        });
    }
    let status = match (output.guest_exit.code, output.guest_exit.signal) {
        (Some(code), None) => code,
        (None, Some(signal)) => {
            writeln!(
                stderr,
                "pocket: workload terminated by guest signal {signal}"
            )
            .map_err(|source| output_error("write signal diagnostic", source))?;
            u8::try_from(SIGNAL_EXIT_BASE.saturating_add(signal)).unwrap_or(u8::MAX)
        }
        _ => {
            return Err(invalid(
                "guest-exit",
                "runtime returned neither an exit code nor a signal",
            ));
        }
    };
    Ok(CommandStatus(status))
}

fn load_profile(path: &Path) -> Result<VerifiedProfile, CliError> {
    Ok(VerifiedProfile::load(managed_path(path)?)?)
}

fn open_store(path: &Path) -> Result<Store, CliError> {
    Ok(Store::open(managed_path(path)?)?)
}

fn open_or_initialize_store(path: &Path) -> Result<Store, CliError> {
    let managed = managed_path(path)?;
    match std::fs::symlink_metadata(path) {
        Ok(_) => match Store::open(managed.clone()) {
            Ok(store) => Ok(store),
            // An initialization that did not finish -- interrupted by a signal
            // during a long pull, or stopped by ENOSPC, EDQUOT or EIO -- leaves
            // a root that `open` rejects for a missing subdirectory and that no
            // command could ever repair, so the operator had to delete it by
            // hand. Completing it is only safe when every entry present is one
            // this store put there; anything else is somebody else's directory
            // and is still refused.
            Err(error) => {
                if Store::is_resumable_root(path)? {
                    Ok(Store::initialize(managed)?)
                } else {
                    Err(error.into())
                }
            }
        },
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            // This absent-only API fails if a concurrent creator wins. It does
            // not fill in or replace a pre-existing invalid directory.
            Ok(Store::initialize_absent(managed)?)
        }
        Err(_) => Ok(Store::open(managed)?),
    }
}

/// Validate the caller's spelling, resolve the ancestor chain to the real
/// directories, then revalidate the form that is actually opened.
///
/// Ordinary host layouts put user data behind a symlinked ancestor: on
/// rpm-ostree systems -- Fedora Silverblue, Kinoite, CoreOS, Bluefin, Bazzite
/// -- `/home` is a symlink to `var/home`, and a hand-made `~/data` symlink is
/// just as common. Every managed path is later opened under a strict
/// `O_NOFOLLOW` component walk, so without this the store refuses to work at
/// all on those hosts, blaming a path the operator never typed.
///
/// The final component is deliberately left as written. A store root or
/// profile bundle that is itself a symlink still fails, because that leaf's
/// device and inode are exactly what the store pins.
/// A runtime root, checked against the bound the sockets inside it impose.
///
/// Refused here rather than at launch: the launch-time message would name a
/// generated run directory the caller never typed, and by then a kernel is
/// already starting.
fn managed_runtime_root(path: &Path) -> Result<ManagedUmlPath, CliError> {
    let managed = managed_path(path)?;
    let length = managed.as_path().as_os_str().len();
    if length > pocket_core::MAX_RUNTIME_ROOT_PATH_BYTES {
        return Err(invalid(
            "runtime-root",
            format!(
                "runtime root is {length} bytes; a run directory and its socket \
                 need the rest of the {} the kernel allows for a Unix socket \
                 path, so the maximum here is {}",
                pocket_core::MAX_UNIX_SOCKET_PATH_BYTES,
                pocket_core::MAX_RUNTIME_ROOT_PATH_BYTES,
            ),
        ));
    }
    Ok(managed)
}

fn managed_path(path: &Path) -> Result<ManagedUmlPath, CliError> {
    let lexical = ManagedUmlPath::new(path)?;
    let resolved = resolve_ancestors(lexical.as_path())?;
    if resolved == lexical.as_path() {
        return Ok(lexical);
    }
    ManagedUmlPath::new(&resolved).map_err(|error| {
        invalid(
            "path",
            format!(
                "{} resolves to {}, which is not a usable managed path: {error}",
                lexical.as_path().display(),
                resolved.display()
            ),
        )
    })
}

/// Replace a path's ancestor chain with its real pathname, keeping the final
/// component exactly as the caller wrote it.
fn resolve_ancestors(path: &Path) -> Result<PathBuf, CliError> {
    // `ManagedUmlPath::new` has already guaranteed an absolute, normalized
    // path of at least three components, so both of these are present.
    let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
        return Ok(path.to_path_buf());
    };
    let resolved = std::fs::canonicalize(parent).map_err(|error| {
        invalid(
            "path",
            format!(
                "the directory holding {} could not be resolved: {} ({error})",
                path.display(),
                parent.display()
            ),
        )
    })?;
    Ok(resolved.join(name))
}

fn lease_target(
    store: &Store,
    profile: &VerifiedProfile,
    target: Target,
    requested_platform: Platform,
) -> Result<Lease, CliError> {
    match target {
        Target::Generation(id) => Ok(store.acquire_lease(id)?),
        Target::Alias(reference) => {
            Ok(store.lease_alias(&alias_key(profile, &reference, requested_platform)?)?)
        }
    }
}

enum Target {
    Generation(GenerationId),
    Alias(String),
}

fn target_kind(value: &str) -> Result<Target, CliError> {
    if value.starts_with("pkvm-gen-v1-") {
        Ok(Target::Generation(parse_generation_id(value)?))
    } else {
        if value.is_empty() {
            return Err(invalid("image", "alias reference must not be empty"));
        }
        Ok(Target::Alias(value.to_owned()))
    }
}

fn parse_generation_id(value: &str) -> Result<GenerationId, CliError> {
    GenerationId::from_str(value).map_err(|error| invalid("generation-id", error.to_string()))
}

fn parse_derivation_key(value: &str) -> Result<DerivationKey, CliError> {
    DerivationKey::from_str(value).map_err(|error| invalid("derivation-key", error.to_string()))
}

fn alias_key(
    profile: &VerifiedProfile,
    reference: &str,
    requested_platform: Platform,
) -> Result<AliasKey, CliError> {
    let manifest = profile.manifest();
    let revision = Digest::from_bytes(manifest.profile_revision.as_bytes());
    Ok(AliasKey::new(
        manifest.profile_id.clone(),
        revision,
        reference,
        requested_platform,
        manifest.contracts.selector_policy.clone(),
    )?)
}

/// Expand a registry-client shorthand into the explicit source pocket needs.
///
/// `alpine:3.22` becomes `docker://docker.io/library/alpine:3.22`, the same
/// two defaults every registry client applies: Docker Hub, and its `library`
/// namespace for a single-segment name. A bare name takes `:latest`.
///
/// An explicit `docker://` is returned untouched. Anything else that names a
/// transport is still refused rather than guessed at: a source that says
/// `oci:` or `containers-storage:` means something specific, and silently
/// treating it as a registry name would acquire the wrong thing.
fn expand_pull_source(source: &str) -> Result<String, CliError> {
    if source.starts_with("docker://") {
        return Ok(source.to_owned());
    }
    // A named transport is matched against the exact set, not guessed at by
    // shape: `containers-storage:x` carries no `//`, and `alpine:3.22` would
    // look like a scheme to any rule that only searched for a colon.
    const OTHER_TRANSPORTS: [&str; 9] = [
        "containers-storage",
        "dir",
        "docker-archive",
        "docker-daemon",
        "oci",
        "oci-archive",
        "ostree",
        "sif",
        "tarball",
    ];
    if let Some((scheme, _)) = source.split_once(':')
        && OTHER_TRANSPORTS.contains(&scheme)
    {
        return Err(invalid(
            "source",
            format!("unsupported transport {scheme:?}; use an explicit docker:// source"),
        ));
    }
    let (name, tag) = split_reference_tag(source)?;
    // A registry is anything before the first slash that looks like a host.
    let qualified = match name.split_once('/') {
        Some((head, _)) if head.contains('.') || head.contains(':') || head == "localhost" => {
            name.to_owned()
        }
        Some(_) => format!("docker.io/{name}"),
        None => format!("docker.io/library/{name}"),
    };
    Ok(format!("docker://{qualified}{tag}"))
}

/// Split a reference into its name and its `:tag`/`@digest` suffix, defaulting
/// a bare name to `:latest`. A digest is kept exactly as written.
fn split_reference_tag(source: &str) -> Result<(&str, String), CliError> {
    if let Some(index) = source.find('@') {
        return Ok((&source[..index], source[index..].to_owned()));
    }
    // A colon before the last slash is a registry port, not a tag.
    let tag_at = source
        .rfind(':')
        .filter(|index| source[*index..].find('/').is_none());
    match tag_at {
        Some(index) if index + 1 == source.len() => {
            Err(invalid("source", "image reference has an empty tag"))
        }
        Some(index) => Ok((&source[..index], source[index..].to_owned())),
        None => Ok((source, ":latest".to_owned())),
    }
}

fn requested_platform(
    profile: &VerifiedProfile,
    requested: Option<&str>,
) -> Result<Platform, CliError> {
    let manifest = profile.manifest();
    let (os, architecture, variant) = match requested {
        None => (
            manifest.oci_os.as_str(),
            manifest.oci_architecture.as_str(),
            None,
        ),
        Some(value) => {
            let fields: Vec<&str> = value.split('/').collect();
            match fields.as_slice() {
                [os, architecture] => (*os, *architecture, None),
                [os, architecture, variant] if !variant.is_empty() => {
                    (*os, *architecture, Some((*variant).to_owned()))
                }
                _ => {
                    return Err(invalid(
                        "platform",
                        "must have exact OS/ARCHITECTURE[/VARIANT] form",
                    ));
                }
            }
        }
    };
    if os != manifest.oci_os || architecture != manifest.oci_architecture {
        return Err(invalid(
            "platform",
            format!(
                "must remain within selected profile {}/{}; emulation and profile switching are unavailable",
                manifest.oci_os, manifest.oci_architecture
            ),
        ));
    }
    if variant.is_some()
        && !manifest
            .accepted_oci_variants
            .iter()
            .any(|accepted| accepted.as_deref() == variant.as_deref())
    {
        return Err(invalid(
            "platform",
            format!("variant {variant:?} is not accepted by the selected profile"),
        ));
    }
    Platform::new(os, architecture, variant, None, Vec::new())
        .map_err(|error| invalid("platform", error.to_string()))
}

fn validate_explicit_platform_syntax(value: &str) -> Result<(), CliError> {
    let fields: Vec<&str> = value.split('/').collect();
    let valid = match fields.as_slice() {
        [os, architecture] => !os.is_empty() && !architecture.is_empty(),
        [os, architecture, variant] => {
            !os.is_empty() && !architecture.is_empty() && !variant.is_empty()
        }
        _ => false,
    };
    if !valid
        || fields.iter().any(|field| {
            field
                .bytes()
                .any(|byte| !byte.is_ascii_alphanumeric() && !matches!(byte, b'_' | b'.' | b'-'))
        })
    {
        return Err(invalid(
            "platform",
            "must have exact nonempty OS/ARCHITECTURE[/VARIANT] form",
        ));
    }
    Ok(())
}

fn validate_builder_reference(value: &str) -> Result<(), CliError> {
    if value.is_empty()
        || value.len() > 1024
        || value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err(invalid(
            "reference",
            "must contain 1..=1024 bytes without whitespace or control characters",
        ));
    }
    Ok(())
}

fn validate_import_path_syntax(path: &Path) -> Result<(), CliError> {
    if !path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir
                    | std::path::Component::ParentDir
                    | std::path::Component::Prefix(_)
            )
        })
    {
        return Err(invalid(
            "oci",
            "must be an absolute lexically normalized path",
        ));
    }
    let canonical = std::fs::canonicalize(path).map_err(|error| {
        invalid(
            "oci",
            format!("could not resolve exact layout path: {error}"),
        )
    })?;
    if canonical != path {
        return Err(invalid(
            "oci",
            "must be an exact path without symbolic-link components",
        ));
    }
    Ok(())
}

fn validate_normalized_platform(
    requested: &Platform,
    image: &pocket_oci::VerifiedImage,
) -> Result<(), CliError> {
    let effective = &image.effective_platform;
    if effective.os != requested.os()
        || effective.architecture != requested.architecture()
        || requested
            .variant()
            .is_some_and(|variant| effective.variant.as_deref() != Some(variant))
    {
        return Err(CliError::GenerationProfileMismatch {
            field: "normalized_platform",
            expected: format!(
                "{}/{}{}",
                requested.os(),
                requested.architecture(),
                requested
                    .variant()
                    .map_or_else(String::new, |variant| format!("/{variant}"))
            ),
            actual: format!(
                "{}/{}{}",
                effective.os,
                effective.architecture,
                effective
                    .variant
                    .as_deref()
                    .map_or_else(String::new, |variant| format!("/{variant}"))
            ),
        });
    }
    Ok(())
}

fn validate_generation_profile(
    profile: &VerifiedProfile,
    generation: &Generation,
) -> Result<(), CliError> {
    let manifest = profile.manifest();
    let spec = generation.manifest().spec();
    require_generation_field("profile_id", &manifest.profile_id, spec.profile_id())?;
    let expected_revision = Digest::from_bytes(manifest.profile_revision.as_bytes());
    require_generation_field(
        "profile_revision",
        &expected_revision.to_string(),
        &spec.profile_revision().to_string(),
    )?;
    require_generation_field(
        "effective_platform.os",
        &manifest.oci_os,
        spec.effective_platform().os(),
    )?;
    require_generation_field(
        "effective_platform.architecture",
        &manifest.oci_architecture,
        spec.effective_platform().architecture(),
    )?;
    require_generation_field(
        "root_layout",
        &manifest.contracts.root_layout,
        spec.root_layout_contract(),
    )?;
    require_generation_field(
        "filesystem",
        &manifest.contracts.filesystem,
        spec.filesystem_contract(),
    )?;
    require_generation_field(
        "selector_policy",
        &manifest.contracts.selector_policy,
        spec.selector_policy_id(),
    )?;
    if !manifest
        .accepted_oci_variants
        .iter()
        .any(|variant| variant.as_deref() == spec.effective_platform().variant())
    {
        return Err(CliError::GenerationProfileMismatch {
            field: "platform.variant",
            expected: format!("{:?}", manifest.accepted_oci_variants),
            actual: format!("{:?}", spec.effective_platform().variant()),
        });
    }
    if spec.effective_platform().os_version().is_some()
        || !spec.effective_platform().os_features().is_empty()
    {
        return Err(CliError::GenerationProfileMismatch {
            field: "effective_platform.os_extensions",
            expected: "no OS version or features".to_owned(),
            actual: format!(
                "version={:?}, features={:?}",
                spec.effective_platform().os_version(),
                spec.effective_platform().os_features()
            ),
        });
    }
    Ok(())
}

fn validate_requested_platform(
    requested: &Platform,
    generation: &Generation,
) -> Result<(), CliError> {
    let effective = generation.manifest().spec().effective_platform();
    if requested.os() != effective.os()
        || requested.architecture() != effective.architecture()
        || requested
            .variant()
            .is_some_and(|variant| effective.variant() != Some(variant))
    {
        return Err(CliError::GenerationProfileMismatch {
            field: "requested_platform",
            expected: format!(
                "{}/{}{}",
                requested.os(),
                requested.architecture(),
                requested
                    .variant()
                    .map_or_else(String::new, |variant| format!("/{variant}"))
            ),
            actual: format!(
                "{}/{}{}",
                effective.os(),
                effective.architecture(),
                effective
                    .variant()
                    .map_or_else(String::new, |variant| format!("/{variant}"))
            ),
        });
    }
    Ok(())
}

fn require_generation_field(
    field: &'static str,
    expected: &str,
    actual: &str,
) -> Result<(), CliError> {
    if expected != actual {
        return Err(CliError::GenerationProfileMismatch {
            field,
            expected: expected.to_owned(),
            actual: actual.to_owned(),
        });
    }
    Ok(())
}

fn profile_summary(profile: &VerifiedProfile, bundle: &Path) -> Value {
    let manifest = profile.manifest();
    let maturity = match manifest.maturity {
        ProfileMaturity::Release => "release",
        ProfileMaturity::Experimental => "experimental",
    };
    json!({
        "bundle": bundle,
        "profile_id": manifest.profile_id,
        "profile_revision": manifest.profile_revision.to_string(),
        "maturity": maturity,
        "host_architecture": manifest.host_architecture,
        "oci_os": manifest.oci_os,
        "oci_architecture": manifest.oci_architecture,
        "accepted_oci_variants": manifest.accepted_oci_variants,
        "guest_page_size": manifest.guest_page_size,
        "smp_enabled": manifest.cpu.smp_enabled,
        "effective_max_cpus": manifest.cpu.effective_max_cpus,
        "minimum_memory_bytes": manifest.memory.minimum_bytes,
        "effective_max_memory_bytes": manifest.memory.effective_max_memory_bytes,
    })
}

fn generation_summary(generation: &Generation) -> Value {
    let manifest = generation.manifest();
    let spec = manifest.spec();
    let descriptor_platform = spec.descriptor_platform().map(platform_summary);
    let sidecars: Vec<Value> = manifest
        .sidecars()
        .iter()
        .map(|sidecar| {
            json!({
                "name": sidecar.name(),
                "digest": sidecar.digest().to_string(),
                "size": sidecar.size(),
            })
        })
        .collect();
    json!({
        "generation_id": manifest.id().to_string(),
        "derivation_key": manifest.derivation_key().to_string(),
        "profile_id": spec.profile_id(),
        "profile_revision": spec.profile_revision().to_string(),
        "descriptor_platform": descriptor_platform,
        "config_platform": platform_summary(spec.config_platform()),
        "effective_platform": platform_summary(spec.effective_platform()),
        "selector_policy": spec.selector_policy_id(),
        "root_layout": spec.root_layout_contract(),
        "filesystem": spec.filesystem_contract(),
        "selected_manifest_digest": spec.selected_manifest_digest().to_string(),
        "config_digest": spec.config_digest().to_string(),
        "layer_digests": spec.layer_digests().iter().map(ToString::to_string).collect::<Vec<_>>(),
        "diff_ids": spec.diff_ids().iter().map(ToString::to_string).collect::<Vec<_>>(),
        "build_contract_digest": spec.build_contract_digest().to_string(),
        "base_digest": manifest.base_digest().to_string(),
        "base_size": manifest.base_size(),
        "sidecars": sidecars,
    })
}

fn platform_summary(platform: &Platform) -> Value {
    json!({
        "os": platform.os(),
        "architecture": platform.architecture(),
        "variant": platform.variant(),
        "os_version": platform.os_version(),
        "os_features": platform.os_features(),
    })
}

fn write_profile_output(
    output: &mut dyn Write,
    profiles: &[Value],
    json_output: bool,
) -> Result<(), CliError> {
    if json_output {
        return write_json(output, profiles);
    }
    for profile in profiles {
        writeln!(
            output,
            "{} {} {} {}",
            value_text(profile, "profile_id"),
            value_text(profile, "profile_revision"),
            value_text(profile, "maturity"),
            value_text(profile, "bundle")
        )
        .map_err(|source| output_error("write profile output", source))?;
    }
    Ok(())
}

fn write_generation_output(
    output: &mut dyn Write,
    generations: &[Value],
    json_output: bool,
) -> Result<(), CliError> {
    if json_output {
        return write_json(output, generations);
    }
    for generation in generations {
        writeln!(
            output,
            "generation_id={} derivation_key={} profile_id={} platform={}/{} base_size={}",
            value_text(generation, "generation_id"),
            value_text(generation, "derivation_key"),
            value_text(generation, "profile_id"),
            generation["effective_platform"]["os"]
                .as_str()
                .unwrap_or("<invalid>"),
            generation["effective_platform"]["architecture"]
                .as_str()
                .unwrap_or("<invalid>"),
            generation["base_size"].as_u64().unwrap_or(0),
        )
        .map_err(|source| output_error("write generation output", source))?;
    }
    Ok(())
}

/// Render a platform the way `--platform` accepts it, for reporting the value
/// a run actually used when the caller did not type one.
fn platform_text(platform: &Platform) -> String {
    match platform.variant() {
        Some(variant) => format!("{}/{}/{variant}", platform.os(), platform.architecture()),
        None => format!("{}/{}", platform.os(), platform.architecture()),
    }
}

fn write_build_output(
    output: &mut dyn Write,
    context: &ImageBuildArgs,
    build: &BuildOutput,
    source_kind: &'static str,
    acquisition: Value,
    // Report what was actually used, not what was typed: either may have been
    // defaulted, and the recorded identity is built from the resolved values.
    reference_text: &str,
    platform_text: &str,
) -> Result<(), CliError> {
    let value = json!({
        "acquisition": acquisition,
        "alias_id": build.alias_id.to_string(),
        "cache_hit": build.cache_hit,
        "derivation_key": build.derivation_key.to_string(),
        "generation_id": build.generation_id.to_string(),
        "platform": platform_text,
        "profile_bundle": context.profile_bundle,
        "reference": reference_text,
        "source_kind": source_kind,
        "store": context.store,
    });
    if let Some(path) = context.evidence_out.as_deref() {
        let receipt = json!({
            "schema": "pocket-acquisition-evidence-v1",
            "result": value,
        });
        write_evidence_receipt(path, &receipt)?;
    }
    if context.json {
        return write_json(output, &value);
    }
    writeln!(
        output,
        "generation_id={} derivation_key={} alias_id={} cache_hit={} reference={} platform={} source_kind={} selected_manifest={} selected_config={} skopeo_stdout_sha256={} skopeo_stderr_sha256={} evidence_out={}",
        build.generation_id,
        build.derivation_key,
        build.alias_id,
        build.cache_hit,
        reference_text,
        platform_text,
        source_kind,
        value_text(&value["acquisition"], "selected_manifest"),
        value_text(&value["acquisition"], "selected_config"),
        value_text(&value["acquisition"]["skopeo_log"], "stdout_sha256"),
        value_text(&value["acquisition"]["skopeo_log"], "stderr_sha256"),
        context
            .evidence_out
            .as_ref()
            .map_or("-", |path| path.to_str().unwrap_or("<non-utf8>")),
    )
    .map_err(|source| output_error("write image-build output", source))?;
    Ok(())
}

fn acquisition_evidence(
    source_kind: &'static str,
    source: &str,
    image: &VerifiedImage,
    normalized: Option<&SkopeoOutput>,
    archive: Option<(&str, u64)>,
) -> Result<Value, CliError> {
    let (skopeo, resolver_inputs) = if let Some(normalized) = normalized {
        (
            json!({
                "stderr_bytes": normalized.log.stderr.len(),
                "stderr_hex": hex::encode(&normalized.log.stderr),
                "stderr_sha256": normalized.log.stderr_sha256(),
                "stdout_bytes": normalized.log.stdout.len(),
                "stdout_hex": hex::encode(&normalized.log.stdout),
                "stdout_sha256": normalized.log.stdout_sha256(),
            }),
            serde_json::to_value(&normalized.resolver_inputs)
                .map_err(|source| CliError::JsonOutput { source })?,
        )
    } else {
        (Value::Null, json!([]))
    };
    Ok(json!({
        "archive": archive.map(|(sha256, size)| json!({
            "sha256": format!("sha256:{sha256}"),
            "size": size,
        })),
        "config_size": image.config_size,
        "manifest_size": image.manifest_size,
        "resolver_inputs": resolver_inputs,
        "selected_config": image.config_digest.to_string(),
        "selected_manifest": image.manifest_digest.to_string(),
        "skopeo_log": skopeo,
        "source": source,
        "source_kind": source_kind,
    }))
}

static EVIDENCE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn validate_evidence_path(path: Option<&Path>) -> Result<(), CliError> {
    let Some(path) = path else {
        return Ok(());
    };
    if !path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir
                    | std::path::Component::ParentDir
                    | std::path::Component::Prefix(_)
            )
        })
    {
        return Err(invalid(
            "evidence-out",
            "must be an absolute lexically normalized absent file path",
        ));
    }
    match fs::symlink_metadata(path) {
        Ok(_) => {
            return Err(invalid(
                "evidence-out",
                "destination already exists; evidence is never overwritten",
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(output_error("inspect evidence destination", error)),
    }
    let parent = path
        .parent()
        .ok_or_else(|| invalid("evidence-out", "destination has no parent"))?;
    let canonical = fs::canonicalize(parent)
        .map_err(|source| output_error("canonicalize evidence parent", source))?;
    let metadata = fs::symlink_metadata(parent)
        .map_err(|source| output_error("inspect evidence parent", source))?;
    if canonical != parent || !metadata.file_type().is_dir() || metadata.mode() & 0o022 != 0 {
        return Err(invalid(
            "evidence-out",
            "parent must be an exact non-symlink directory that is not group/world writable",
        ));
    }
    Ok(())
}

fn write_evidence_receipt(path: &Path, value: &Value) -> Result<(), CliError> {
    validate_evidence_path(Some(path))?;
    let mut bytes =
        serde_json::to_vec_pretty(value).map_err(|source| CliError::JsonOutput { source })?;
    bytes.push(b'\n');
    let parent = path
        .parent()
        .ok_or_else(|| invalid("evidence-out", "destination has no parent"))?;
    let sequence = EVIDENCE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let stage = parent.join(format!(
        ".pocket-acquisition-evidence-{}-{sequence}",
        std::process::id()
    ));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&stage)
            .map_err(|source| output_error("create staged acquisition evidence", source))?;
        file.write_all(&bytes)
            .map_err(|source| output_error("write acquisition evidence", source))?;
        file.sync_all()
            .map_err(|source| output_error("sync acquisition evidence", source))?;
        fs::hard_link(&stage, path).map_err(|source| {
            output_error("publish acquisition evidence without replacement", source)
        })?;
        fs::remove_file(&stage)
            .map_err(|source| output_error("remove staged acquisition evidence link", source))?;
        fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|source| output_error("sync acquisition evidence directory", source))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&stage);
    }
    result
}

fn write_gc_output(
    output: &mut dyn Write,
    report: &GarbageCollectionReport,
    json_output: bool,
) -> Result<(), CliError> {
    let value = json!({
        "applied": true,
        "collected": ids_to_strings(&report.collected),
        "rooted": ids_to_strings(&report.rooted),
        "leased_or_busy": ids_to_strings(&report.leased_or_busy),
        "corrupt_unrooted": ids_to_strings(&report.corrupt_unrooted),
        "publication_in_flight": report.publication_in_flight.clone(),
        "discarded_derivation_index": report
            .discarded_derivation_index
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
    });
    if json_output {
        return write_json(output, &value);
    }
    writeln!(
        output,
        "applied=true collected={} rooted={} leased_or_busy={} corrupt_unrooted={} publication_in_flight={} discarded_derivation_index={}",
        report.collected.len(),
        report.rooted.len(),
        report.leased_or_busy.len(),
        report.corrupt_unrooted.len(),
        report.publication_in_flight.len(),
        report.discarded_derivation_index.len(),
    )
    .map_err(|source| output_error("write garbage-collection output", source))?;
    Ok(())
}

fn write_alias_roots_output(
    output: &mut dyn Write,
    roots: &[AliasRoot],
    json_output: bool,
) -> Result<(), CliError> {
    if json_output {
        let value = json!({
            "roots": roots
                .iter()
                .map(|root| json!({
                    "alias_id": root.id.to_string(),
                    "profile_id": root.profile_id,
                    "reference": root.reference,
                    "platform": root.platform,
                    "selector_policy_id": root.selector_policy_id,
                    "generation_id": root.generation_id.to_string(),
                }))
                .collect::<Vec<_>>(),
        });
        return write_json(output, &value);
    }
    for root in roots {
        writeln!(
            output,
            "alias={} profile={} platform={} generation={} reference={}",
            root.id, root.profile_id, root.platform, root.generation_id, root.reference,
        )
        .map_err(|source| output_error("write alias root output", source))?;
    }
    Ok(())
}

fn ids_to_strings(ids: &[GenerationId]) -> Vec<String> {
    let mut values: Vec<String> = ids.iter().map(ToString::to_string).collect();
    values.sort_unstable();
    values
}

fn write_json(
    output: &mut dyn Write,
    value: &(impl serde::Serialize + ?Sized),
) -> Result<(), CliError> {
    serde_json::to_writer_pretty(&mut *output, value)
        .map_err(|source| CliError::JsonOutput { source })?;
    writeln!(output).map_err(|source| output_error("write JSON newline", source))
}

fn value_text<'value>(value: &'value Value, field: &str) -> &'value str {
    value[field].as_str().unwrap_or("<invalid>")
}

fn parse_decimal_u16(
    field: &'static str,
    value: &str,
    zero_allowed: bool,
) -> Result<u16, CliError> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid(field, "must be an unsigned decimal integer"));
    }
    let parsed = value
        .parse::<u16>()
        .map_err(|_| invalid(field, "does not fit in 16 bits"))?;
    if !zero_allowed && parsed == 0 {
        return Err(invalid(field, "must be greater than zero"));
    }
    Ok(parsed)
}

fn parse_umask(value: &str) -> Result<u16, CliError> {
    if value.is_empty()
        || value.len() > 3
        || !value.bytes().all(|byte| (b'0'..=b'7').contains(&byte))
    {
        return Err(invalid("umask", "must be one to three octal digits"));
    }
    u16::from_str_radix(value, 8).map_err(|_| invalid("umask", "invalid octal value"))
}

fn parse_duration(value: &str) -> Result<Duration, CliError> {
    let digits = value.bytes().take_while(u8::is_ascii_digit).count();
    if digits == 0 || digits == value.len() {
        return Err(invalid(
            "timeout",
            "must be a positive integer followed by ms, s, m, or h",
        ));
    }
    let amount = value[..digits]
        .parse::<u64>()
        .map_err(|_| invalid("timeout", "duration value overflows"))?;
    if amount == 0 {
        return Err(invalid("timeout", "must be greater than zero"));
    }
    let duration = match &value[digits..] {
        "ms" => Duration::from_millis(amount),
        "s" => Duration::from_secs(amount),
        "m" => Duration::from_secs(
            amount
                .checked_mul(60)
                .ok_or_else(|| invalid("timeout", "duration value overflows"))?,
        ),
        "h" => Duration::from_secs(
            amount
                .checked_mul(60 * 60)
                .ok_or_else(|| invalid("timeout", "duration value overflows"))?,
        ),
        _ => {
            return Err(invalid(
                "timeout",
                "must use one of the exact suffixes ms, s, m, or h",
            ));
        }
    };
    Ok(duration)
}

fn validate_guest_path(field: &'static str, value: &str) -> Result<(), CliError> {
    validate_no_nul(field, value)?;
    let path = Path::new(value);
    if !path.is_absolute() {
        return Err(invalid(field, "must be absolute"));
    }
    let Some(relative) = value.strip_prefix('/') else {
        return Err(invalid(field, "must be absolute"));
    };
    if !relative.is_empty()
        && relative
            .split('/')
            .any(|segment| segment.is_empty() || matches!(segment, "." | ".."))
    {
        return Err(invalid(field, "must use normalized lexical form"));
    }
    Ok(())
}

/// The image-independent half of a `--user` value.
///
/// Whether a name exists is a question for the image's account database, but
/// whether the spelling could ever name anything is not.
fn validate_user_spec(value: &str) -> Result<(), CliError> {
    validate_no_nul("user", value)?;
    if value.is_empty() || value.len() > pocket_runtime::MAX_ORIGINAL_USER_LENGTH {
        return Err(invalid(
            "user",
            format!(
                "must contain 1..={} bytes",
                pocket_runtime::MAX_ORIGINAL_USER_LENGTH
            ),
        ));
    }
    if value.contains(['\n', '\r']) {
        return Err(invalid("user", "must not contain a line separator"));
    }
    let mut parts = value.split(':');
    let user = parts.next().unwrap_or_default();
    let group = parts.next();
    if parts.next().is_some() || user.is_empty() || group == Some("") {
        return Err(invalid(
            "user",
            "must be user-or-uid with at most one nonempty group suffix",
        ));
    }
    Ok(())
}

fn validate_hostname(value: &str) -> Result<(), CliError> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
    {
        return Err(invalid(
            "hostname",
            "must contain 1..=64 ASCII letters, digits, '.', or '-'",
        ));
    }
    Ok(())
}

fn validate_env(value: &str) -> Result<(), CliError> {
    validate_no_nul("env", value)?;
    let Some((key, _)) = value.split_once('=') else {
        return Err(invalid("env", "must have KEY=VALUE form"));
    };
    if key.is_empty() {
        return Err(invalid("env", "key must not be empty"));
    }
    Ok(())
}

fn validate_no_nul(field: &'static str, value: &str) -> Result<(), CliError> {
    if value.contains('\0') {
        return Err(invalid(field, "must not contain NUL"));
    }
    Ok(())
}

fn read_bounded_stdin(input: &mut dyn Read) -> Result<Vec<u8>, CliError> {
    let mut bytes = Vec::new();
    input
        .take(MAX_CLI_STDIN_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| output_error("read stdin", source))?;
    if bytes.len() as u64 > MAX_CLI_STDIN_BYTES {
        return Err(invalid(
            "stdin",
            format!("exceeds the {MAX_CLI_STDIN_BYTES}-byte buffered limit"),
        ));
    }
    Ok(bytes)
}

fn runtime_error_code(error: &RuntimeError) -> String {
    match error {
        RuntimeError::ManagedPath(error) => error.code().as_str().into(),
        RuntimeError::Cpu(error) => error.code().as_str().into(),
        RuntimeError::Memory(error) => error.code().as_str().into(),
        RuntimeError::Protocol(error) => error.code().as_str().into(),
        RuntimeError::ImageConfig(_) => CliErrorCode::Runtime.as_str().into(),
        RuntimeError::Guest { message, .. } => message
            .code()
            .map_or_else(|_| "E_GUEST".into(), |code| code.as_str().into()),
        RuntimeError::Manifest(_) => CliErrorCode::ProfileInvalid.as_str().into(),
        RuntimeError::Store(_) => CliErrorCode::Store.as_str().into(),
        RuntimeError::GenerationMismatch { .. } => {
            CliErrorCode::GenerationProfileMismatch.as_str().into()
        }
        RuntimeError::Io { .. }
        | RuntimeError::InvalidConfiguration { .. }
        | RuntimeError::GuardSpawn { .. }
        | RuntimeError::GuardExitedEarly { .. }
        | RuntimeError::Timeout { .. }
        | RuntimeError::HelloMismatch { .. }
        | RuntimeError::Cow { .. }
        | RuntimeError::GuardStatus { .. }
        | RuntimeError::GuestFilesystemUnclean
        | RuntimeError::Cleanup { .. }
        | RuntimeError::Diagnostics { .. }
        | RuntimeError::StreamWorker { .. } => CliErrorCode::Runtime.as_str().into(),
    }
}

fn invalid(field: &'static str, reason: impl Into<String>) -> CliError {
    CliError::InvalidInput {
        field,
        reason: reason.into(),
    }
}

fn unsupported(feature: &'static str, reason: &'static str) -> CliError {
    CliError::FeatureUnsupported { feature, reason }
}

fn output_error(operation: &'static str, source: io::Error) -> CliError {
    CliError::Output { operation, source }
}

#[cfg(test)]
mod tests {
    use std::{io::Cursor, os::unix::fs::PermissionsExt};

    use clap::CommandFactory;

    use super::*;

    fn invoke(arguments: &[&str], input: &[u8]) -> (u8, Vec<u8>, Vec<u8>) {
        let mut stdin = Cursor::new(input);
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let status = run_from(
            arguments.iter().copied(),
            &mut stdin,
            &mut stdout,
            &mut stderr,
        );
        (status, stdout, stderr)
    }

    fn text(bytes: &[u8]) -> String {
        String::from_utf8_lossy(bytes).into_owned()
    }

    fn minimum_run(extra: &[&str]) -> Vec<String> {
        let mut arguments = vec![
            "pocket".into(),
            "run".into(),
            "--profile-bundle".into(),
            "/tmp/pocket/tests/profile".into(),
            "--store".into(),
            "/tmp/pocket/tests/store".into(),
            "--runtime-root".into(),
            "/tmp/pocket/tests/runtime".into(),
            "--user".into(),
            "0:0".into(),
        ];
        arguments.extend(extra.iter().map(|value| (*value).into()));
        arguments.extend(["example:latest".into(), "--".into(), "/bin/true".into()]);
        arguments
    }

    #[test]
    fn clap_definition_is_internally_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn run_syntax_distinguishes_image_defaults_cmd_replacement_and_exact_argv() {
        let parse = |tail: &[&str]| {
            let mut arguments = vec![
                "pocket",
                "run",
                "--profile-bundle",
                "/tmp/pocket/tests/profile",
                "--store",
                "/tmp/pocket/tests/store",
                "--runtime-root",
                "/tmp/pocket/tests/runtime",
            ];
            arguments.extend_from_slice(tail);
            let parsed = Cli::try_parse_from(arguments).expect("parse run syntax");
            let Command::Run(arguments) = parsed.command else {
                panic!("run command")
            };
            *arguments
        };

        let defaults = parse(&["example:latest"]);
        assert!(defaults.command.is_empty());
        assert!(!defaults.exact_argv);
        assert!(defaults.user.is_none());

        let replacement = parse(&["example:latest", "--", "arg0", "arg1"]);
        assert_eq!(replacement.command, ["arg0", "arg1"]);
        assert!(!replacement.exact_argv);

        let exact = parse(&["--exact-argv", "example:latest", "--", "/bin/true"]);
        assert_eq!(exact.command, ["/bin/true"]);
        assert!(exact.exact_argv);
    }

    #[test]
    fn help_and_version_are_successful_and_describe_the_strict_surface() {
        let (status, stdout, stderr) = invoke(&["pocket", "--help"], &[]);
        assert_eq!(status, 0);
        assert!(stderr.is_empty());
        let help = text(&stdout);
        assert!(help.contains("registry pulls are anonymous and explicit"));
        assert!(help.contains("Usage:"));

        let (status, stdout, stderr) = invoke(&["pocket", "--version"], &[]);
        assert_eq!(status, 0);
        assert!(stderr.is_empty());
        assert!(text(&stdout).starts_with("pocket "));
    }

    #[test]
    fn unknown_options_are_usage_errors_and_exact_argv_requires_a_command() {
        let (status, _, stderr) = invoke(&["pocket", "--invented"], &[]);
        assert_eq!(status, USAGE_ERROR_EXIT);
        assert!(text(&stderr).contains("unexpected argument"));

        let arguments = minimum_run(&["--exact-argv"]);
        let arguments: Vec<&str> = arguments[..arguments.len() - 2]
            .iter()
            .map(String::as_str)
            .collect();
        let (status, _, stderr) = invoke(&arguments, &[]);
        assert_eq!(status, OPERATIONAL_ERROR_EXIT);
        assert!(text(&stderr).contains("E_CLI_INVALID_INPUT"));
        assert!(text(&stderr).contains("exact-argv"));
    }

    #[test]
    fn unsupported_run_features_fail_before_paths_are_opened() {
        for (extra, feature) in [
            // Networking exists now, but nothing forwards a host port into
            // the guest yet, so --publish is still refused.
            (vec!["--publish", "8080:80"], "port-forwarding"),
            // Named so the refusal explains itself rather than reading as an
            // unknown flag, which is what an unrecognised -d would look like.
            (vec!["--detach"], "detach"),
            (vec!["--cpuset", "0-1"], "cpuset"),
            (vec!["--pull", "missing"], "pull-policy"),
        ] {
            let arguments = minimum_run(&extra);
            let borrowed: Vec<&str> = arguments.iter().map(String::as_str).collect();
            let (status, _, stderr) = invoke(&borrowed, &[]);
            assert_eq!(status, OPERATIONAL_ERROR_EXIT);
            let diagnostic = text(&stderr);
            assert!(diagnostic.contains("E_FEATURE_UNSUPPORTED"));
            assert!(diagnostic.contains(feature));
            assert!(!diagnostic.contains("No such file"));
        }

        let arguments = minimum_run(&["--exact-argv", "--entrypoint", "/bin/sh"]);
        let borrowed: Vec<&str> = arguments.iter().map(String::as_str).collect();
        let (status, _, stderr) = invoke(&borrowed, &[]);
        assert_eq!(status, OPERATIONAL_ERROR_EXIT);
        assert!(text(&stderr).contains("E_CLI_INVALID_INPUT"));
        assert!(text(&stderr).contains("cannot be combined"));
    }

    /// `--tty` is accepted now, but it needs a terminal on both sides. The
    /// test harness has pipes, so this also pins the refusal a caller gets
    /// when they pipe into an interactive run instead of silently degrading
    /// to a buffered one.
    #[test]
    fn tty_without_a_terminal_is_named_as_an_input_error() {
        let arguments = minimum_run(&["--tty"]);
        let borrowed: Vec<&str> = arguments.iter().map(String::as_str).collect();
        let (status, _, stderr) = invoke(&borrowed, &[]);
        assert_eq!(status, OPERATIONAL_ERROR_EXIT);
        let diagnostic = text(&stderr);
        assert!(diagnostic.contains("E_CLI_INVALID_INPUT"), "{diagnostic}");
        assert!(diagnostic.contains("not a terminal"), "{diagnostic}");
        assert!(
            !diagnostic.contains("E_FEATURE_UNSUPPORTED"),
            "{diagnostic}"
        );
    }

    #[test]
    fn image_list_and_gc_preview_remain_explicitly_unavailable() {
        for arguments in [
            vec!["pocket", "image", "list"],
            vec![
                "pocket",
                "cache",
                "gc",
                "--store",
                "/tmp/pocket/missing/store",
            ],
        ] {
            let (status, _, stderr) = invoke(&arguments, &[]);
            assert_eq!(status, OPERATIONAL_ERROR_EXIT);
            assert!(text(&stderr).contains("E_FEATURE_UNSUPPORTED"));
        }
    }

    /// A typo in a config file must never silently change which store a
    /// command uses, so the grammar is tiny and everything outside it is
    /// refused and named.
    #[test]
    fn the_config_grammar_is_strict_and_reports_where_it_failed() {
        let path = Path::new("/home/user/.config/pocket/config.toml");

        let config = Config::parse(
            "# a comment\n\nprofile_bundle = \"/p\"\n  store = \"/s\"\n\nruntime_root = \"/r\"\n",
            path,
        )
        .expect("a well-formed config");
        assert_eq!(config.profile_bundle, Some(PathBuf::from("/p")));
        assert_eq!(config.store, Some(PathBuf::from("/s")));
        assert_eq!(config.runtime_root, Some(PathBuf::from("/r")));

        // An empty file is valid and simply supplies nothing.
        let empty = Config::parse("", path).expect("an empty config");
        assert!(empty.store.is_none());

        for (text, expected, line) in [
            ("store /s\n", "expected key", 1),
            ("store = /s\n", "double-quoted", 1),
            ("store = \"/s\"\nstore = \"/t\"\n", "duplicate key", 2),
            ("stores = \"/s\"\n", "unknown key", 1),
            ("store = \"/s\\\\bad\"\n", "quotes or escapes", 1),
        ] {
            let error = Config::parse(text, path).expect_err(&format!("{text:?} must be refused"));
            let message = error.to_string();
            assert!(message.contains(expected), "{text:?}: {message}");
            // Every rejection names the file and the exact line, so it can be
            // found without guessing.
            assert!(
                message.contains(&format!("config.toml:{line}:")),
                "{text:?}: {message}"
            );
        }
    }

    /// A shared host directory is claimed exclusively for the length of a run.
    /// Two guests writing one hostfs tree through independent page caches is a
    /// corruption the runtime cannot make safe, so the second attempt is
    /// refused loudly and names the directory rather than being serialized or
    /// quietly allowed.
    #[test]
    fn a_shared_host_directory_is_claimed_exclusively_and_refused_twice() {
        let temporary = tempfile::tempdir().expect("temporary root");
        let shared = temporary.path().join("shared");
        std::fs::create_dir(&shared).expect("create the shared directory");
        let request = format!("{}:/data", shared.display());

        let held = hold_volumes(std::slice::from_ref(&request)).expect("claim once");
        assert_eq!(held.len(), 1);
        assert_eq!(held[0].spec.destination, "/data");
        assert!(!held[0].spec.read_only);
        assert_eq!(
            held[0].spec.source,
            std::fs::canonicalize(&shared)
                .expect("canonical shared path")
                .to_str()
                .expect("utf-8")
        );

        // A second claim while the first is held is refused, and says which
        // directory is in use.
        let error = hold_volumes(std::slice::from_ref(&request))
            .expect_err("a second concurrent claim is refused");
        assert!(error.to_string().contains("already shared"), "{error}");
        assert!(
            error.to_string().contains(&shared.display().to_string()),
            "{error}"
        );

        // Releasing the first claim frees it for the next run.
        drop(held);
        hold_volumes(std::slice::from_ref(&request)).expect("claim again after release");
    }

    /// The spelling is checked before anything is opened, and `:ro` is honoured.
    #[test]
    fn volume_specs_are_validated_and_read_only_is_parsed() {
        let temporary = tempfile::tempdir().expect("temporary root");
        let shared = temporary.path().join("shared");
        std::fs::create_dir(&shared).expect("create the shared directory");
        let file = temporary.path().join("a-file");
        std::fs::write(&file, b"x").expect("create a file");

        let held =
            hold_volumes(&[format!("{}:/data:ro", shared.display())]).expect("read-only claim");
        assert!(held[0].spec.read_only);
        drop(held);

        for (request, expected) in [
            (shared.display().to_string(), "HOST_PATH:GUEST_PATH"),
            (format!("{}:relative", shared.display()), "must be absolute"),
            (format!("{}:/", shared.display()), "image root"),
            // A colon in the host path is unrepresentable: the first colon is
            // the separator, so the remainder is read as the source.
            ("/has:colon:/data".to_owned(), "must be absolute"),
            // A destination the runtime mounts or writes itself is refused
            // rather than silently shadowed -- or, worse, used: a share at
            // /etc had the generated hostname, hosts and resolv.conf created
            // inside the caller's own directory, and left there.
            (format!("{}:/proc", shared.display()), "collides with /proc"),
            (
                format!("{}:/dev/shm", shared.display()),
                "collides with /dev",
            ),
            (
                format!("{}:/etc", shared.display()),
                "collides with /etc/hostname",
            ),
            (
                format!("{}:/etc/hosts", shared.display()),
                "collides with /etc/hosts",
            ),
            (format!("{}:/data", file.display()), "not a directory"),
            (
                format!("{}/absent:/data", shared.display()),
                "cannot be resolved",
            ),
            ("relative/path:/data".to_owned(), "must be absolute"),
        ] {
            let error = hold_volumes(std::slice::from_ref(&request))
                .expect_err(&format!("{request} must be refused"));
            assert!(
                error.to_string().contains(expected),
                "{request}: expected {expected:?}, got {error}"
            );
        }

        // Sharing one host directory twice in a single run is also refused,
        // rather than taking the lock twice against itself.
        let doubled = hold_volumes(&[
            format!("{}:/one", shared.display()),
            format!("{}:/two", shared.display()),
        ])
        .expect_err("the same host path twice is refused");
        assert!(doubled.to_string().contains("more than once"), "{doubled}");
    }

    /// The claim is on the directory itself, so it needs no write permission
    /// and leaves nothing in the caller's folder. An earlier version wrote a
    /// `.pocket-volume.lock` marker inside the share, which the workload could
    /// see and delete -- `find /data -delete` was enough -- after which a
    /// third run claimed a directory a live run still held.
    #[test]
    fn a_shared_directory_is_claimed_without_writing_anything_into_it() {
        let temporary = tempfile::tempdir().expect("temporary root");
        let shared = temporary.path().join("read-only");
        std::fs::create_dir(&shared).expect("create the shared directory");
        std::fs::write(shared.join("data"), b"x").expect("write a file to share");
        let mut permissions = std::fs::metadata(&shared)
            .expect("read the directory mode")
            .permissions();
        permissions.set_mode(0o500);
        std::fs::set_permissions(&shared, permissions).expect("make it unwritable");

        // Unwritable is still claimable: nothing is written to take the claim.
        let held = hold_volumes(&[format!("{}:/data:ro", shared.display())])
            .expect("an unwritable directory is still claimable");
        assert_eq!(held.len(), 1);

        // The share contains exactly what it contained before.
        let mut entries: Vec<String> = std::fs::read_dir(&shared)
            .expect("list the share")
            .map(|entry| {
                entry
                    .expect("entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        entries.sort();
        assert_eq!(
            entries,
            vec!["data".to_owned()],
            "the claim left a file behind"
        );

        // And it is genuinely exclusive while held.
        let error = hold_volumes(&[format!("{}:/data", shared.display())])
            .expect_err("a second claim on the same directory is refused");
        assert!(error.to_string().contains("already shared"), "{error}");
        drop(held);
        hold_volumes(&[format!("{}:/data", shared.display())]).expect("claimable once released");

        let mut restore = std::fs::metadata(&shared)
            .expect("read the directory mode")
            .permissions();
        restore.set_mode(0o700);
        std::fs::set_permissions(&shared, restore).expect("restore the mode");
    }

    /// Ordinary host layouts put user data behind a symlinked ancestor -- on
    /// rpm-ostree systems `/home` is a symlink to `var/home`. Refusing those
    /// made every command fail on a whole class of hosts, blaming a path the
    /// operator never typed. The leaf is still left exactly as written, so a
    /// root that is itself a symlink is still rejected downstream, where the
    /// store pins its device and inode.
    #[test]
    fn a_symlinked_ancestor_resolves_while_a_symlinked_leaf_is_left_alone() {
        let temporary = tempfile::tempdir().expect("temporary root");
        let real = temporary.path().join("real/user");
        std::fs::create_dir_all(&real).expect("create the real chain");
        std::os::unix::fs::symlink("real", temporary.path().join("link"))
            .expect("symlink the ancestor");

        let through_link = temporary.path().join("link/user/store");
        let resolved = managed_path(&through_link).expect("resolve a symlinked ancestor");
        assert_eq!(
            resolved.as_path(),
            std::fs::canonicalize(&real)
                .expect("canonical real chain")
                .join("store")
        );

        // The leaf keeps the caller's spelling even when it is a symlink, so
        // the strict no-symlink check downstream still sees it.
        std::os::unix::fs::symlink("elsewhere", real.join("leaf")).expect("symlink the leaf");
        let leaf = managed_path(&real.join("leaf")).expect("accept a symlinked leaf lexically");
        assert!(leaf.as_path().ends_with("leaf"));

        // A parent that does not exist is named plainly rather than surfacing
        // as an opaque failure later.
        let error = managed_path(&temporary.path().join("absent/deeper/store"))
            .expect_err("an absent parent is rejected");
        assert!(
            error.to_string().contains("could not be resolved"),
            "{error}"
        );
    }

    /// A malformed `--stop-signal` or `--user` is the caller's mistake, so it
    /// must be reported as an input error and reported before a profile or
    /// store is opened -- not as an indistinguishable `E_RUNTIME` after the
    /// command has already begun touching the caller's filesystem.
    #[test]
    fn malformed_process_overrides_are_input_errors_reported_before_any_access() {
        let common = [
            "--profile-bundle",
            "/tmp/pocket/missing/profile",
            "--store",
            "/tmp/pocket/missing/store",
            "--runtime-root",
            "/tmp/pocket/missing/runtime",
        ];
        for (flag, value, expected) in [
            ("--stop-signal", "SIGNOTASIGNAL", "stop-signal"),
            ("--stop-signal", "", "stop-signal"),
            ("--user", "a:b:c", "user"),
            ("--user", "app:", "user"),
            ("--user", "", "user"),
        ] {
            let mut run = vec!["pocket", "run"];
            run.extend(common);
            run.extend([flag, value]);
            run.push(
                "pkvm-gen-v1-0000000000000000000000000000000000000000000000000000000000000000",
            );
            let (status, _, stderr) = invoke(&run, &[]);
            assert_eq!(status, OPERATIONAL_ERROR_EXIT, "{flag} {value:?}");
            let diagnostic = text(&stderr);
            assert!(
                diagnostic.contains("E_CLI_INVALID_INPUT"),
                "{flag} {value:?}: {diagnostic}"
            );
            assert!(
                diagnostic.contains(expected),
                "{flag} {value:?}: {diagnostic}"
            );
            assert!(
                !diagnostic.contains("No such file"),
                "{flag} {value:?} reached the filesystem: {diagnostic}"
            );
        }
    }

    #[test]
    fn acquisition_input_failures_precede_profile_and_store_access() {
        let common = [
            "--profile-bundle",
            "/tmp/pocket/missing/profile",
            "--store",
            "/tmp/pocket/missing/store",
            "--runtime-root",
            "/tmp/pocket/missing/runtime",
            "--reference",
            "example:latest",
            "--platform",
            "linux/amd64",
        ];
        // A bare name is now expanded the way a registry client would, so the
        // source that must still be refused is one naming another transport.
        let mut pull = vec!["pocket", "image", "pull"];
        pull.extend(common);
        pull.push("oci:/tmp/pocket/layout:tag");
        let (status, _, stderr) = invoke(&pull, &[]);
        assert_eq!(status, OPERATIONAL_ERROR_EXIT);
        let diagnostic = text(&stderr);
        assert!(diagnostic.contains("unsupported transport"));
        assert!(!diagnostic.contains("No such file"));

        let mut import = vec!["pocket", "image", "import"];
        import.extend(common);
        import.extend(["--oci", "relative/layout"]);
        let (status, _, stderr) = invoke(&import, &[]);
        assert_eq!(status, OPERATIONAL_ERROR_EXIT);
        let diagnostic = text(&stderr);
        assert!(diagnostic.contains("E_CLI_INVALID_INPUT"));
        assert!(diagnostic.contains("absolute lexically normalized"));
        assert!(!diagnostic.contains("No such file"));
    }

    #[test]
    fn import_transport_selection_is_parser_enforced_and_unambiguous() {
        let arguments = [
            "pocket",
            "image",
            "import",
            "--profile-bundle",
            "/tmp/pocket/missing/profile",
            "--store",
            "/tmp/pocket/missing/store",
            "--runtime-root",
            "/tmp/pocket/missing/runtime",
            "--reference",
            "example:latest",
            "--platform",
            "linux/amd64",
            "--oci",
            "/tmp/a",
            "--docker-archive",
            "/tmp/b",
        ];
        let (status, _, stderr) = invoke(&arguments, &[]);
        assert_eq!(status, USAGE_ERROR_EXIT);
        assert!(text(&stderr).contains("cannot be used with"));
    }

    #[test]
    fn evidence_receipt_is_mode_0600_atomic_and_never_overwritten() {
        let temporary = tempfile::tempdir().expect("evidence directory");
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))
            .expect("private evidence directory");
        let path = temporary.path().join("receipt.json");
        let value = json!({"schema": "fixture", "source": "docker://registry.example/a:b"});
        write_evidence_receipt(&path, &value).expect("publish evidence receipt");
        assert_eq!(
            fs::symlink_metadata(&path)
                .expect("receipt metadata")
                .permissions()
                .mode()
                & 0o7777,
            0o600
        );
        let parsed: Value =
            serde_json::from_slice(&fs::read(&path).expect("receipt bytes")).expect("receipt JSON");
        assert_eq!(parsed, value);
        assert!(write_evidence_receipt(&path, &json!({"changed": true})).is_err());
        let unchanged: Value = serde_json::from_slice(&fs::read(&path).expect("unchanged bytes"))
            .expect("unchanged JSON");
        assert_eq!(unchanged, value);
    }

    #[test]
    fn credential_flags_are_rejected_by_the_parser() {
        let (status, _, stderr) = invoke(
            &[
                "pocket",
                "image",
                "pull",
                "--profile-bundle",
                "/tmp/pocket/missing/profile",
                "--store",
                "/tmp/pocket/missing/store",
                "--runtime-root",
                "/tmp/pocket/missing/runtime",
                "--reference",
                "example:latest",
                "--platform",
                "linux/amd64",
                "--creds",
                "user:password",
                "docker://registry.example/team/image:tag",
            ],
            &[],
        );
        assert_eq!(status, USAGE_ERROR_EXIT);
        assert!(text(&stderr).contains("unexpected argument '--creds'"));
    }

    #[test]
    fn image_build_output_is_stable_in_text_and_json() -> Result<(), CliError> {
        let output = BuildOutput {
            generation_id: GenerationId::from_str(&format!("pkvm-gen-v1-{}", "11".repeat(32)))?,
            derivation_key: DerivationKey::from_str(&format!("pkvm-der-v1-{}", "22".repeat(32)))?,
            alias_id: pocket_store::AliasId::from_str(&format!(
                "pkvm-alias-v1-{}",
                "33".repeat(32)
            ))?,
            cache_hit: true,
        };
        let context = ImageBuildArgs {
            profile_bundle: Some(PathBuf::from("/tmp/pocket/test/profile")),
            store: Some(PathBuf::from("/tmp/pocket/test/store")),
            runtime_root: Some(PathBuf::from("/tmp/pocket/test/runtime")),
            reference: Some("registry.example/team/image:tag".to_owned()),
            platform: Some("linux/amd64".to_owned()),
            json: false,
            evidence_out: None,
        };
        let evidence = json!({
            "selected_config": format!("sha256:{}", "44".repeat(32)),
            "selected_manifest": format!("sha256:{}", "55".repeat(32)),
            "skopeo_log": null,
        });
        let mut text_output = Vec::new();
        write_build_output(
            &mut text_output,
            &context,
            &output,
            "oci-import",
            evidence.clone(),
            "registry.example/team/image:tag",
            "linux/amd64",
        )?;
        let rendered = text(&text_output);
        assert!(rendered.starts_with("generation_id=pkvm-gen-v1-"));
        assert!(rendered.contains(" derivation_key=pkvm-der-v1-"));
        assert!(rendered.contains(" alias_id=pkvm-alias-v1-"));
        assert!(rendered.contains(" cache_hit=true "));
        assert!(rendered.contains(" source_kind=oci-import selected_manifest=sha256:"));
        assert!(rendered.ends_with(" evidence_out=-\n"));

        let mut json_context = context;
        json_context.json = true;
        let mut json_output = Vec::new();
        write_build_output(
            &mut json_output,
            &json_context,
            &output,
            "docker-pull",
            evidence,
            "registry.example/team/image:tag",
            "linux/amd64",
        )?;
        let decoded: Value = serde_json::from_slice(&json_output)
            .map_err(|source| CliError::JsonOutput { source })?;
        assert_eq!(decoded["cache_hit"], true);
        assert_eq!(decoded["source_kind"], "docker-pull");
        assert_eq!(decoded["platform"], "linux/amd64");
        Ok(())
    }

    #[test]
    fn strict_value_parsers_reject_ambiguous_forms() {
        assert_eq!(parse_umask("022").ok(), Some(0o22));
        assert!(parse_umask("888").is_err());
        assert_eq!(
            parse_duration("250ms").ok(),
            Some(Duration::from_millis(250))
        );
        assert_eq!(parse_duration("2m").ok(), Some(Duration::from_secs(120)));
        assert!(parse_duration("2").is_err());
        assert!(validate_guest_path("cwd", "/work/app").is_ok());
        assert!(validate_guest_path("cwd", "/work/../etc").is_err());
        assert!(validate_env("A=B=C").is_ok());
        assert!(validate_env("missing-equals").is_err());
    }

    #[test]
    fn target_parser_never_turns_a_malformed_full_id_into_an_alias() {
        assert!(matches!(target_kind("ubuntu:latest"), Ok(Target::Alias(_))));
        assert!(target_kind("pkvm-gen-v1-not-a-digest").is_err());
        assert!(target_kind("").is_err());
    }

    /// Normalizing a local archive is a copy: its cost is its size. A fixed
    /// budget would silently cap the archive size that can be imported at all.
    #[test]
    fn archive_normalization_budget_grows_with_the_archive() {
        assert_eq!(
            archive_normalization_timeout(0),
            Duration::from_secs(15 * 60)
        );
        assert_eq!(
            archive_normalization_timeout(1),
            Duration::from_secs(20 * 60)
        );
        assert_eq!(
            archive_normalization_timeout(256 * 1024 * 1024 * 1024),
            Duration::from_secs(15 * 60 + 256 * 5 * 60)
        );
        assert_eq!(
            archive_normalization_timeout(u64::MAX),
            Duration::from_secs(24 * 60 * 60)
        );
    }

    /// The runtime measures whether the host can actually deliver the vCPUs
    /// the caller asked for, and never rejects the request over it. That
    /// measurement is only worth taking if the caller is told.
    #[test]
    fn an_unqualified_multi_cpu_request_is_reported_and_still_succeeds() {
        let stream = || pocket_runtime::CapturedStream {
            bytes: Vec::new(),
            truncated: false,
            total_bytes: 0,
        };
        let output = |scaling_qualified| RunOutput {
            run_id: "test".into(),
            generation_id: GenerationId::from_str(&format!("pkvm-gen-v1-{}", "00".repeat(32)))
                .expect("synthetic generation id"),
            cow_path: None,
            scaling_qualified,
            guest_exit: pocket_protocol::Exit {
                code: Some(0),
                signal: None,
                elapsed_ns: 1,
                filesystem_clean: true,
            },
            stdout: stream(),
            stderr: stream(),
            console: stream(),
            guard_stdout: stream(),
            guard_stderr: stream(),
            console_log_error: None,
        };

        let mut stderr = Vec::new();
        let status = emit_run_output(output(false), 4, &mut Vec::new(), &mut stderr)
            .expect("an unqualified host is not a failure");
        assert_eq!(status.0, 0);
        let text = String::from_utf8(stderr).expect("UTF-8 diagnostic");
        assert!(text.contains("4 parallel vCPUs"), "{text:?}");

        // A qualified host says nothing, and neither does a single vCPU, for
        // which there is nothing to scale.
        for (qualified, cpus) in [(true, 4), (false, 1)] {
            let mut stderr = Vec::new();
            emit_run_output(output(qualified), cpus, &mut Vec::new(), &mut stderr)
                .expect("emit run output");
            assert!(stderr.is_empty(), "unexpected diagnostic: {stderr:?}");
        }
    }

    #[test]
    fn run_exit_mapping_preserves_codes_and_reports_signals() {
        let stream = || pocket_runtime::CapturedStream {
            bytes: Vec::new(),
            truncated: false,
            total_bytes: 0,
        };
        let output = RunOutput {
            run_id: "test".into(),
            generation_id: GenerationId::from_str(&format!("pkvm-gen-v1-{}", "00".repeat(32)))
                .expect("synthetic generation id"),
            cow_path: None,
            scaling_qualified: true,
            guest_exit: pocket_protocol::Exit {
                code: Some(42),
                signal: None,
                elapsed_ns: 1,
                filesystem_clean: true,
            },
            stdout: stream(),
            stderr: stream(),
            console: stream(),
            guard_stdout: stream(),
            guard_stderr: stream(),
            console_log_error: None,
        };
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        assert_eq!(
            emit_run_output(output, 1, &mut stdout, &mut stderr)
                .ok()
                .map(|status| status.0),
            Some(42)
        );

        let output = RunOutput {
            run_id: "test".into(),
            generation_id: GenerationId::from_str(&format!("pkvm-gen-v1-{}", "00".repeat(32)))
                .expect("synthetic generation id"),
            cow_path: None,
            scaling_qualified: true,
            guest_exit: pocket_protocol::Exit {
                code: None,
                signal: Some(9),
                elapsed_ns: 1,
                filesystem_clean: true,
            },
            stdout: stream(),
            stderr: stream(),
            console: stream(),
            guard_stdout: stream(),
            guard_stderr: stream(),
            console_log_error: None,
        };
        assert_eq!(
            emit_run_output(output, 1, &mut stdout, &mut stderr)
                .ok()
                .map(|status| status.0),
            Some(137)
        );
        assert!(text(&stderr).contains("signal 9"));
    }

    #[test]
    fn output_truncation_is_never_silent() {
        let empty = || pocket_runtime::CapturedStream {
            bytes: Vec::new(),
            truncated: false,
            total_bytes: 0,
        };
        let output = RunOutput {
            run_id: "test".into(),
            generation_id: GenerationId::from_str(&format!("pkvm-gen-v1-{}", "00".repeat(32)))
                .expect("synthetic generation id"),
            cow_path: None,
            scaling_qualified: true,
            guest_exit: pocket_protocol::Exit {
                code: Some(0),
                signal: None,
                elapsed_ns: 1,
                filesystem_clean: true,
            },
            stdout: pocket_runtime::CapturedStream {
                bytes: b"partial".to_vec(),
                truncated: true,
                total_bytes: 100,
            },
            stderr: empty(),
            console: empty(),
            guard_stdout: empty(),
            guard_stderr: empty(),
            console_log_error: None,
        };
        let result = emit_run_output(output, 1, &mut Vec::new(), &mut Vec::new());
        assert!(matches!(result, Err(CliError::OutputTruncated { .. })));
    }

    /// A registry client's two defaults -- Docker Hub, and its `library`
    /// namespace for a single-segment name -- plus `:latest` for a bare name.
    /// Anything already qualified is left exactly as written, because a
    /// rewritten source would acquire something other than what was asked for.
    #[test]
    fn pull_sources_expand_the_way_a_registry_client_would() {
        for (input, expected) in [
            ("alpine", "docker://docker.io/library/alpine:latest"),
            ("alpine:3.22", "docker://docker.io/library/alpine:3.22"),
            ("myorg/tool:v1", "docker://docker.io/myorg/tool:v1"),
            ("ghcr.io/o/i:v2", "docker://ghcr.io/o/i:v2"),
            ("localhost:5000/i:v1", "docker://localhost:5000/i:v1"),
            (
                "registry.io:5000/a/b",
                "docker://registry.io:5000/a/b:latest",
            ),
            (
                "alpine@sha256:0000000000000000000000000000000000000000000000000000000000000000",
                "docker://docker.io/library/alpine@sha256:0000000000000000000000000000000000000000000000000000000000000000",
            ),
            // Already explicit: untouched, including a non-Hub registry.
            ("docker://ghcr.io/o/i:v1", "docker://ghcr.io/o/i:v1"),
        ] {
            assert_eq!(expand_pull_source(input).expect(input), expected, "{input}");
        }

        // Another transport means something specific; guessing would acquire
        // the wrong thing, so it is refused rather than treated as a name.
        for refused in ["oci:/tmp/layout:tag", "containers-storage:x", "dir:/tmp/x"] {
            let error = expand_pull_source(refused).expect_err(refused);
            assert!(
                error.to_string().contains("unsupported transport"),
                "{error}"
            );
        }
        assert!(
            expand_pull_source("alpine:").is_err(),
            "an empty tag is refused"
        );
    }
}
