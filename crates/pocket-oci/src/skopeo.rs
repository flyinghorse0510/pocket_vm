use std::{
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
        unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
            process::CommandExt,
        },
    },
    path::{Component, Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    str::FromStr,
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use nix::{fcntl::OFlag, libc, unistd::pipe2};
use serde::Serialize;
use sha2::{Digest as _, Sha256};

use crate::error::{Error, Result, io_error};
use crate::{VerifiedImage, VerifyLimits, verify_canonical_layout_with_limits};

const LIVENESS_FD: RawFd = 9;
const RELOCATED_FD_MINIMUM: RawFd = 64;
const ACQUISITION_ID_BYTES: usize = 16;
const MAX_SOURCE_BYTES: usize = 1024;
const MAX_TIMEOUT: Duration = Duration::from_secs(24 * 60 * 60);
const MAX_CAPTURE_BYTES: usize = 64 * 1024 * 1024;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const DEFAULT_GUARD_TERM_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_GUARD_EXIT_TIMEOUT: Duration = Duration::from_secs(10);
const PRIVATE_DIRECTORY_MODE: u32 = 0o700;
const PRIVATE_FILE_MODE: u32 = 0o600;
const MAX_RESOLVER_INPUT_BYTES: u64 = 1024 * 1024;
const MAX_STAGED_ARCHIVE_BYTES: u64 = 256 * 1024 * 1024 * 1024;
const RESOLVER_PATHS: [&str; 3] = ["/etc/resolv.conf", "/etc/hosts", "/etc/nsswitch.conf"];

/// An absolute, absent path that Skopeo may populate with one managed OCI layout.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedLayoutPath(PathBuf);

impl ManagedLayoutPath {
    pub fn new(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        validate_managed_path(path)?;
        Ok(Self(path.to_path_buf()))
    }

    #[must_use]
    pub fn as_path(&self) -> &Path {
        &self.0
    }

    fn revalidate(&self) -> Result<()> {
        validate_managed_path(&self.0)
    }
}

/// One validated Skopeo source. Public string parsing accepts only an explicit,
/// anonymous, fully-qualified `docker://` reference. Archive sources can only
/// be constructed by staging an exact local file under a fixed private name.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SkopeoSourceKind {
    DockerRegistry,
    OciArchive,
    DockerArchive,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SkopeoSource {
    transport: String,
    kind: SkopeoSourceKind,
}

impl SkopeoSource {
    pub fn parse(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        validate_source(&value)?;
        Ok(Self {
            transport: value,
            kind: SkopeoSourceKind::DockerRegistry,
        })
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.transport
    }

    #[must_use]
    pub const fn kind(&self) -> SkopeoSourceKind {
        self.kind
    }
}

impl FromStr for SkopeoSource {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        Self::parse(value)
    }
}

/// Exact OCI platform override supplied to Skopeo.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SkopeoPlatform {
    os: String,
    architecture: String,
    variant: Option<String>,
}

impl SkopeoPlatform {
    pub fn new(
        os: impl Into<String>,
        architecture: impl Into<String>,
        variant: Option<String>,
    ) -> Result<Self> {
        let os = os.into();
        let architecture = architecture.into();
        if os != "linux" || architecture != "amd64" {
            return Err(Error::InvalidPlatform {
                reason: format!(
                    "this verifier release accepts only linux/amd64, observed {os}/{architecture}"
                ),
            });
        }
        if !matches!(variant.as_deref(), None | Some("v1")) {
            return Err(Error::InvalidPlatform {
                reason: format!("unsupported amd64 variant {variant:?}"),
            });
        }
        Ok(Self {
            os,
            architecture,
            variant,
        })
    }

    #[must_use]
    pub fn os(&self) -> &str {
        &self.os
    }

    #[must_use]
    pub fn architecture(&self) -> &str {
        &self.architecture
    }

    #[must_use]
    pub fn variant(&self) -> Option<&str> {
        self.variant.as_deref()
    }
}

/// Bounded execution policy for one guarded Skopeo copy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SkopeoExecutionPolicy {
    pub timeout: Duration,
    pub guard_term_timeout: Duration,
    pub guard_exit_timeout: Duration,
    pub maximum_capture_bytes: usize,
}

impl Default for SkopeoExecutionPolicy {
    fn default() -> Self {
        Self {
            timeout: DEFAULT_TIMEOUT,
            guard_term_timeout: DEFAULT_GUARD_TERM_TIMEOUT,
            guard_exit_timeout: DEFAULT_GUARD_EXIT_TIMEOUT,
            maximum_capture_bytes: 8 * 1024 * 1024,
        }
    }
}

/// Bounded stdout/stderr evidence from one successful acquisition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SkopeoLog {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl SkopeoLog {
    #[must_use]
    pub fn stdout_sha256(&self) -> String {
        hex::encode(Sha256::digest(&self.stdout))
    }

    #[must_use]
    pub fn stderr_sha256(&self) -> String {
        hex::encode(Sha256::digest(&self.stderr))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ResolverInputSnapshot {
    pub path: String,
    pub present: bool,
    pub content_sha256: Option<String>,
    pub content_size: Option<u64>,
    pub resolved_path_hex: Option<String>,
    pub symlink_target_hex: Option<String>,
    pub path_device: Option<u64>,
    pub path_inode: Option<u64>,
    pub path_mode: Option<u32>,
    pub path_uid: Option<u32>,
    pub path_gid: Option<u32>,
    pub path_mtime_seconds: Option<i64>,
    pub path_mtime_nanoseconds: Option<i64>,
    pub path_ctime_seconds: Option<i64>,
    pub path_ctime_nanoseconds: Option<i64>,
    pub device: Option<u64>,
    pub inode: Option<u64>,
    pub mode: Option<u32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub mtime_seconds: Option<i64>,
    pub mtime_nanoseconds: Option<i64>,
    pub ctime_seconds: Option<i64>,
    pub ctime_nanoseconds: Option<i64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ResolverInputEvidence {
    pub before: ResolverInputSnapshot,
    pub after: ResolverInputSnapshot,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StagedArchive {
    source: SkopeoSource,
    original_path: PathBuf,
    sha256: String,
    size: u64,
}

impl StagedArchive {
    #[must_use]
    pub const fn source(&self) -> &SkopeoSource {
        &self.source
    }

    #[must_use]
    pub fn original_path(&self) -> &Path {
        &self.original_path
    }

    #[must_use]
    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    #[must_use]
    pub const fn size(&self) -> u64 {
        self.size
    }
}

/// Authenticated canonical image and bounded helper evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SkopeoOutput {
    pub image: VerifiedImage,
    pub log: SkopeoLog,
    pub resolver_inputs: Vec<ResolverInputEvidence>,
}

/// Private state for one acquisition operation.
///
/// Every Skopeo configuration path and the destination layout lives below this
/// mode-0700 directory. Cleanup verifies its device and inode before removal,
/// including after helper failure or timeout.
#[derive(Debug)]
pub struct AcquisitionDirectory {
    root: PathBuf,
    path: PathBuf,
    device: u64,
    inode: u64,
    cleaned: bool,
}

impl AcquisitionDirectory {
    pub fn create(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref();
        validate_acquisition_root(root)?;
        for _ in 0..128 {
            let id = random_id()?;
            let path = root.join(format!("acquire-{id}"));
            match fs::create_dir(&path) {
                Ok(()) => {
                    fs::set_permissions(&path, fs::Permissions::from_mode(PRIVATE_DIRECTORY_MODE))
                        .map_err(|source| io_error(&path, source))?;
                    let metadata =
                        fs::symlink_metadata(&path).map_err(|source| io_error(&path, source))?;
                    // Establish cleanup ownership before creating children. If
                    // setup fails below, Drop removes only this exact inode.
                    let directory = Self {
                        root: root.to_path_buf(),
                        path,
                        device: metadata.dev(),
                        inode: metadata.ino(),
                        cleaned: false,
                    };
                    for child in [
                        "home",
                        "tmp",
                        "xdg-cache",
                        "xdg-config",
                        "xdg-runtime",
                        "registries.d",
                        "certs.d",
                    ] {
                        let child_path = directory.path.join(child);
                        fs::create_dir(&child_path)
                            .map_err(|source| io_error(&child_path, source))?;
                        fs::set_permissions(
                            &child_path,
                            fs::Permissions::from_mode(PRIVATE_DIRECTORY_MODE),
                        )
                        .map_err(|source| io_error(&child_path, source))?;
                    }
                    write_private_file(&directory.path.join("auth.json"), b"{\"auths\":{}}\n")?;
                    write_private_file(
                        &directory.path.join("registries.conf"),
                        b"unqualified-search-registries = []\n",
                    )?;
                    return Ok(directory);
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(source) => return Err(io_error(&path, source)),
            }
        }
        Err(Error::UnsafeAcquisitionDirectory {
            path: root.to_path_buf(),
            reason: "could not allocate a unique operation directory".to_owned(),
        })
    }

    #[must_use]
    pub fn as_path(&self) -> &Path {
        &self.path
    }

    pub fn layout_path(&self) -> Result<ManagedLayoutPath> {
        self.revalidate()?;
        ManagedLayoutPath::new(self.path.join("layout"))
    }

    /// Copy one exact local archive into the private operation directory under
    /// a fixed basename that cannot be parsed as a Skopeo transport selector.
    pub fn stage_archive(
        &self,
        source: impl AsRef<Path>,
        kind: SkopeoSourceKind,
    ) -> Result<StagedArchive> {
        self.revalidate()?;
        let source = source.as_ref();
        if kind == SkopeoSourceKind::DockerRegistry {
            return Err(Error::InvalidSource {
                reason: "registry sources cannot be staged as local archives".to_owned(),
            });
        }
        let (basename, transport) = match kind {
            SkopeoSourceKind::OciArchive => ("source.oci-archive.tar", "oci-archive"),
            SkopeoSourceKind::DockerArchive => ("source.docker-archive.tar", "docker-archive"),
            SkopeoSourceKind::DockerRegistry => unreachable!(),
        };
        let staged = self.path.join(basename);
        let (sha256, size) = copy_stable_archive(source, &staged)?;
        validate_archive_ambiguity(&staged, kind)?;
        let staged_text = staged.to_str().ok_or_else(|| Error::UnsafeManagedPath {
            path: staged.clone(),
            reason: "staged archive path is not valid UTF-8".to_owned(),
        })?;
        if staged_text.contains(':') {
            return Err(Error::UnsafeManagedPath {
                path: staged,
                reason: "fixed staged archive path unexpectedly contains ':'".to_owned(),
            });
        }
        Ok(StagedArchive {
            source: SkopeoSource {
                transport: format!("{transport}:{staged_text}"),
                kind,
            },
            original_path: source.to_path_buf(),
            sha256,
            size,
        })
    }

    pub fn cleanup(&mut self) -> Result<()> {
        if self.cleaned {
            return Ok(());
        }
        self.revalidate()?;
        fs::remove_dir_all(&self.path).map_err(|source| io_error(&self.path, source))?;
        self.cleaned = true;
        Ok(())
    }

    fn layout_path_after_copy(&self) -> Result<PathBuf> {
        self.revalidate()?;
        let path = self.path.join("layout");
        let metadata = fs::symlink_metadata(&path).map_err(|source| io_error(&path, source))?;
        if !metadata.file_type().is_dir() || metadata.dev() != self.device {
            return Err(Error::UnsafeAcquisitionDirectory {
                path,
                reason: "Skopeo destination is not a plain directory on the operation filesystem"
                    .to_owned(),
            });
        }
        Ok(path)
    }

    fn revalidate(&self) -> Result<()> {
        if self.path.parent() != Some(self.root.as_path()) {
            return Err(self.unsafe_error("operation directory escaped its root"));
        }
        validate_acquisition_root(&self.root)?;
        let metadata =
            fs::symlink_metadata(&self.path).map_err(|source| io_error(&self.path, source))?;
        if !metadata.file_type().is_dir()
            || metadata.dev() != self.device
            || metadata.ino() != self.inode
            || metadata.uid() != current_euid()
            || metadata.mode() & 0o777 != PRIVATE_DIRECTORY_MODE
        {
            return Err(self.unsafe_error("operation directory identity or mode changed"));
        }
        Ok(())
    }

    fn unsafe_error(&self, reason: &str) -> Error {
        Error::UnsafeAcquisitionDirectory {
            path: self.path.clone(),
            reason: reason.to_owned(),
        }
    }

    fn home(&self) -> PathBuf {
        self.path.join("home")
    }

    fn tmp(&self) -> PathBuf {
        self.path.join("tmp")
    }

    fn xdg_cache(&self) -> PathBuf {
        self.path.join("xdg-cache")
    }

    fn xdg_config(&self) -> PathBuf {
        self.path.join("xdg-config")
    }

    fn xdg_runtime(&self) -> PathBuf {
        self.path.join("xdg-runtime")
    }

    fn registries_directory(&self) -> PathBuf {
        self.path.join("registries.d")
    }

    fn certificates_directory(&self) -> PathBuf {
        self.path.join("certs.d")
    }

    fn auth_file(&self) -> PathBuf {
        self.path.join("auth.json")
    }

    fn registries_configuration(&self) -> PathBuf {
        self.path.join("registries.conf")
    }
}

impl Drop for AcquisitionDirectory {
    fn drop(&mut self) {
        if !self.cleaned {
            let _ = self.cleanup();
        }
    }
}

/// Shell-free, guard-supervised wrapper around a pinned `skopeo copy`.
#[derive(Clone, Debug)]
pub struct SkopeoNormalizer {
    program: PathBuf,
    guard: PathBuf,
    policy: SkopeoExecutionPolicy,
}

impl SkopeoNormalizer {
    pub fn new(
        program: impl Into<PathBuf>,
        guard: impl Into<PathBuf>,
        policy: SkopeoExecutionPolicy,
    ) -> Result<Self> {
        let program = program.into();
        let guard = guard.into();
        validate_program_path("skopeo", &program)?;
        validate_program_path("guard", &guard)?;
        validate_execution_policy(policy)?;
        Ok(Self {
            program,
            guard,
            policy,
        })
    }

    /// Build the exact guard command. The full environment is replaced, the
    /// helper path is absolute, and no shell or `PATH` lookup is involved.
    pub fn command(
        &self,
        source: &SkopeoSource,
        platform: &SkopeoPlatform,
        directory: &AcquisitionDirectory,
        ca_bundle: impl AsRef<Path>,
    ) -> Result<Command> {
        if source.kind() != SkopeoSourceKind::DockerRegistry {
            return Err(Error::InvalidSource {
                reason: "registry command requires a docker:// source".to_owned(),
            });
        }
        self.command_for_source(source, platform, directory, Some(ca_bundle.as_ref()))
    }

    fn command_for_source(
        &self,
        source: &SkopeoSource,
        platform: &SkopeoPlatform,
        directory: &AcquisitionDirectory,
        ca_bundle: Option<&Path>,
    ) -> Result<Command> {
        directory.revalidate()?;
        let destination = directory.layout_path()?;
        destination.revalidate()?;
        if let Some(ca_bundle) = ca_bundle {
            validate_ca_bundle(ca_bundle)?;
        }

        let timeout_ms =
            u64::try_from(self.policy.guard_term_timeout.as_millis()).map_err(|_| {
                Error::InvalidExecutionPolicy {
                    reason: "guard termination timeout milliseconds do not fit u64".to_owned(),
                }
            })?;
        let destination_text =
            destination
                .as_path()
                .to_str()
                .ok_or_else(|| Error::UnsafeManagedPath {
                    path: destination.as_path().to_path_buf(),
                    reason: "path is not valid UTF-8".to_owned(),
                })?;
        // `root` is the sole canonical OCI ref-name accepted by the builder
        // guest and by umoci at the authenticated host/guest boundary.
        let transport_destination = format!("oci:{destination_text}:root");

        let mut guard_arguments = vec![
            OsString::from("--supervisor-pid"),
            std::process::id().to_string().into(),
            OsString::from("--liveness-fd"),
            LIVENESS_FD.to_string().into(),
            OsString::from("--term-timeout-ms"),
            timeout_ms.to_string().into(),
            OsString::from("--"),
            self.program.as_os_str().to_owned(),
            OsString::from("--insecure-policy"),
            OsString::from("--registries.d"),
            directory.registries_directory().into_os_string(),
            OsString::from("--tmpdir"),
            directory.tmp().into_os_string(),
            OsString::from("--override-os"),
            platform.os().into(),
            OsString::from("--override-arch"),
            platform.architecture().into(),
        ];
        if let Some(variant) = platform.variant() {
            guard_arguments.push(OsString::from("--override-variant"));
            guard_arguments.push(variant.into());
        }
        guard_arguments.extend([OsString::from("copy")]);
        if source.kind() == SkopeoSourceKind::DockerRegistry {
            guard_arguments.extend([
                OsString::from("--authfile"),
                directory.auth_file().into_os_string(),
                OsString::from("--src-no-creds"),
                OsString::from("--src-cert-dir"),
                directory.certificates_directory().into_os_string(),
                OsString::from("--src-tls-verify=true"),
            ]);
        }
        guard_arguments.extend([
            OsString::from("--format"),
            OsString::from("oci"),
            OsString::from("--multi-arch"),
            OsString::from("system"),
            OsString::from("--image-parallel-copies"),
            OsString::from("1"),
            OsString::from("--retry-times"),
            OsString::from("0"),
            OsString::from("--remove-signatures"),
            OsString::from("--"),
            source.as_str().into(),
            transport_destination.into(),
        ]);

        let mut environment = BTreeMap::from([
            (OsString::from("HOME"), directory.home().into_os_string()),
            (OsString::from("LANG"), OsString::from("C")),
            (OsString::from("LC_ALL"), OsString::from("C")),
            (OsString::from("TZ"), OsString::from("UTC0")),
            (
                OsString::from("XDG_CACHE_HOME"),
                directory.xdg_cache().into_os_string(),
            ),
            (
                OsString::from("XDG_CONFIG_HOME"),
                directory.xdg_config().into_os_string(),
            ),
            (
                OsString::from("XDG_RUNTIME_DIR"),
                directory.xdg_runtime().into_os_string(),
            ),
            (OsString::from("TMPDIR"), directory.tmp().into_os_string()),
            (OsString::from("TMP"), directory.tmp().into_os_string()),
            (OsString::from("TEMP"), directory.tmp().into_os_string()),
            (
                OsString::from("SSL_CERT_DIR"),
                directory.certificates_directory().into_os_string(),
            ),
            (
                OsString::from("REGISTRY_AUTH_FILE"),
                directory.auth_file().into_os_string(),
            ),
            (
                OsString::from("CONTAINERS_REGISTRIES_CONF"),
                directory.registries_configuration().into_os_string(),
            ),
        ]);
        if let Some(ca_bundle) = ca_bundle {
            environment.insert(
                OsString::from("SSL_CERT_FILE"),
                ca_bundle.as_os_str().to_owned(),
            );
        }
        let mut command = Command::new(&self.guard);
        command
            .args(guard_arguments)
            .env_clear()
            .envs(environment)
            .current_dir("/");
        Ok(command)
    }

    pub fn normalize(
        &self,
        source: &SkopeoSource,
        platform: &SkopeoPlatform,
        directory: &AcquisitionDirectory,
        ca_bundle: impl AsRef<Path>,
    ) -> Result<SkopeoOutput> {
        self.normalize_with_limits(
            source,
            platform,
            directory,
            ca_bundle,
            &VerifyLimits::default(),
        )
    }

    pub fn normalize_with_limits(
        &self,
        source: &SkopeoSource,
        platform: &SkopeoPlatform,
        directory: &AcquisitionDirectory,
        ca_bundle: impl AsRef<Path>,
        limits: &VerifyLimits,
    ) -> Result<SkopeoOutput> {
        if source.kind() != SkopeoSourceKind::DockerRegistry {
            return Err(Error::InvalidSource {
                reason: "registry normalization requires a docker:// source".to_owned(),
            });
        }
        self.normalize_source_with_limits(
            source,
            platform,
            directory,
            Some(ca_bundle.as_ref()),
            limits,
        )
    }

    pub fn normalize_archive(
        &self,
        archive: &StagedArchive,
        platform: &SkopeoPlatform,
        directory: &AcquisitionDirectory,
    ) -> Result<SkopeoOutput> {
        self.normalize_source_with_limits(
            archive.source(),
            platform,
            directory,
            None,
            &VerifyLimits::default(),
        )
    }

    fn normalize_source_with_limits(
        &self,
        source: &SkopeoSource,
        platform: &SkopeoPlatform,
        directory: &AcquisitionDirectory,
        ca_bundle: Option<&Path>,
        limits: &VerifyLimits,
    ) -> Result<SkopeoOutput> {
        let before = if source.kind() == SkopeoSourceKind::DockerRegistry {
            Some(snapshot_resolver_inputs(&RESOLVER_PATHS)?)
        } else {
            None
        };
        let command = self.command_for_source(source, platform, directory, ca_bundle)?;
        let mut launch = spawn_guard(command, &self.guard)?;
        let stdout = launch
            .child
            .stdout
            .take()
            .ok_or_else(|| Error::SkopeoStream {
                stream: "stdout",
                reason: "guard stdout pipe is missing".to_owned(),
            })?;
        let stderr = launch
            .child
            .stderr
            .take()
            .ok_or_else(|| Error::SkopeoStream {
                stream: "stderr",
                reason: "guard stderr pipe is missing".to_owned(),
            })?;
        let stdout_worker = capture_worker(stdout, self.policy.maximum_capture_bytes);
        let stderr_worker = capture_worker(stderr, self.policy.maximum_capture_bytes);
        let status_result = wait_guard(&mut launch, self.policy);
        let stdout = join_capture(stdout_worker, "stdout")?;
        let stderr = join_capture(stderr_worker, "stderr")?;
        // Skopeo's own outcome is decided first. Checking the resolver inputs
        // before the exit status replaced a SkopeoFailed -- and the 4096-byte
        // stderr tail that explains it -- or a SkopeoTimeout with a message
        // about /etc/resolv.conf, which is a description of the host, not of
        // why the acquisition failed.
        let status = status_result?;
        require_complete_capture("stdout", &stdout, self.policy.maximum_capture_bytes)?;
        require_complete_capture("stderr", &stderr, self.policy.maximum_capture_bytes)?;
        if !status.success() {
            return Err(Error::SkopeoFailed {
                status: status.to_string(),
                diagnostic: lossy_tail(&stderr.bytes, 4096),
            });
        }
        let resolver_inputs = if let Some(before) = before {
            let after = snapshot_resolver_inputs(&RESOLVER_PATHS)?;
            compare_resolver_inputs(before, after)?
        } else {
            Vec::new()
        };

        let destination = directory.layout_path_after_copy()?;
        let image = verify_canonical_layout_with_limits(&destination, limits)?;
        Ok(SkopeoOutput {
            image,
            log: SkopeoLog {
                stdout: stdout.bytes,
                stderr: stderr.bytes,
            },
            resolver_inputs,
        })
    }
}

#[derive(Debug)]
struct CapturedBytes {
    bytes: Vec<u8>,
    total_bytes: u64,
}

#[derive(Debug)]
struct SpawnedGuard {
    child: Child,
    liveness: Option<OwnedFd>,
}

fn spawn_guard(mut command: Command, guard: &Path) -> Result<SpawnedGuard> {
    let (liveness_read, liveness_write) = pipe2(OFlag::O_CLOEXEC).map_err(|errno| {
        io_error(
            "<acquisition-liveness-pipe>",
            io::Error::from_raw_os_error(errno as i32),
        )
    })?;
    let relocated = relocate(liveness_read.as_raw_fd())?;
    let source_fd = relocated.as_raw_fd();
    // SAFETY: getpid has no pointer or lifetime preconditions.
    let expected_parent = unsafe { libc::getpid() };
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // SAFETY: only async-signal-safe scalar libc calls execute after fork.
    unsafe {
        command.pre_exec(move || {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) == -1 {
                return Err(io::Error::last_os_error());
            }
            if libc::getppid() != expected_parent {
                return Err(io::Error::from_raw_os_error(libc::ESRCH));
            }
            if libc::dup2(source_fd, LIVENESS_FD) == -1 {
                return Err(io::Error::last_os_error());
            }
            libc::umask(0o077);
            Ok(())
        });
    }
    let child = command
        .spawn()
        .map_err(|source| Error::AcquisitionGuardSpawn {
            program: guard.to_path_buf(),
            source,
        })?;
    drop(relocated);
    drop(liveness_read);
    Ok(SpawnedGuard {
        child,
        liveness: Some(liveness_write),
    })
}

fn relocate(fd: RawFd) -> Result<OwnedFd> {
    // SAFETY: fd is borrowed and valid; F_DUPFD_CLOEXEC returns a distinct FD.
    let relocated = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, RELOCATED_FD_MINIMUM) };
    if relocated == -1 {
        return Err(io_error(
            "<acquisition-liveness-fd>",
            io::Error::last_os_error(),
        ));
    }
    // SAFETY: fcntl returned a newly owned file descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(relocated) })
}

fn wait_guard(launch: &mut SpawnedGuard, policy: SkopeoExecutionPolicy) -> Result<ExitStatus> {
    let deadline = Instant::now() + policy.timeout;
    loop {
        if let Some(status) = launch
            .child
            .try_wait()
            .map_err(|source| io_error("<acquisition-guard>", source))?
        {
            launch.liveness.take();
            return Ok(status);
        }
        if Instant::now() >= deadline {
            launch.liveness.take();
            let cleanup_deadline = Instant::now() + policy.guard_exit_timeout;
            loop {
                if launch
                    .child
                    .try_wait()
                    .map_err(|source| io_error("<terminating-acquisition-guard>", source))?
                    .is_some()
                {
                    return Err(Error::SkopeoTimeout {
                        timeout: policy.timeout,
                    });
                }
                if Instant::now() >= cleanup_deadline {
                    let _ = launch.child.kill();
                    let _ = launch.child.wait();
                    return Err(Error::SkopeoTimeout {
                        timeout: policy.timeout,
                    });
                }
                thread::sleep(Duration::from_millis(10));
            }
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn capture_worker<R: Read + Send + 'static>(
    reader: R,
    maximum: usize,
) -> JoinHandle<io::Result<CapturedBytes>> {
    thread::spawn(move || capture(reader, maximum))
}

fn capture(mut reader: impl Read, maximum: usize) -> io::Result<CapturedBytes> {
    let mut bytes = Vec::with_capacity(maximum.min(64 * 1024));
    let mut buffer = [0_u8; 64 * 1024];
    let mut total_bytes = 0_u64;
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        total_bytes = total_bytes.saturating_add(count as u64);
        let remaining = maximum.saturating_sub(bytes.len());
        bytes.extend_from_slice(&buffer[..count.min(remaining)]);
    }
    Ok(CapturedBytes { bytes, total_bytes })
}

fn join_capture(
    worker: JoinHandle<io::Result<CapturedBytes>>,
    stream: &'static str,
) -> Result<CapturedBytes> {
    worker
        .join()
        .map_err(|_| Error::SkopeoStream {
            stream,
            reason: "capture worker panicked".to_owned(),
        })?
        .map_err(|error| Error::SkopeoStream {
            stream,
            reason: error.to_string(),
        })
}

fn require_complete_capture(
    stream: &'static str,
    capture: &CapturedBytes,
    maximum: usize,
) -> Result<()> {
    if capture.total_bytes > capture.bytes.len() as u64 {
        return Err(Error::SkopeoOutputLimit {
            stream,
            maximum,
            actual: capture.total_bytes,
        });
    }
    Ok(())
}

fn lossy_tail(bytes: &[u8], maximum: usize) -> String {
    let start = bytes.len().saturating_sub(maximum);
    String::from_utf8_lossy(&bytes[start..]).into_owned()
}

fn snapshot_resolver_inputs(paths: &[&str]) -> Result<Vec<ResolverInputSnapshot>> {
    paths
        .iter()
        .map(|path| snapshot_resolver_input(Path::new(path)))
        .collect()
}

fn snapshot_resolver_input(path: &Path) -> Result<ResolverInputSnapshot> {
    let path_text = path.to_str().ok_or_else(|| Error::ResolverInput {
        path: path.to_path_buf(),
        reason: "path is not valid UTF-8".to_owned(),
    })?;
    let link_before = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            match fs::symlink_metadata(path) {
                Err(second) if second.kind() == io::ErrorKind::NotFound => {}
                Ok(_) => {
                    return Err(Error::ResolverInput {
                        path: path.to_path_buf(),
                        reason: "path appeared while its absence was sampled".to_owned(),
                    });
                }
                Err(source) => return Err(io_error(path, source)),
            }
            return Ok(ResolverInputSnapshot {
                path: path_text.to_owned(),
                present: false,
                content_sha256: None,
                content_size: None,
                resolved_path_hex: None,
                symlink_target_hex: None,
                path_device: None,
                path_inode: None,
                path_mode: None,
                path_uid: None,
                path_gid: None,
                path_mtime_seconds: None,
                path_mtime_nanoseconds: None,
                path_ctime_seconds: None,
                path_ctime_nanoseconds: None,
                device: None,
                inode: None,
                mode: None,
                uid: None,
                gid: None,
                mtime_seconds: None,
                mtime_nanoseconds: None,
                ctime_seconds: None,
                ctime_nanoseconds: None,
            });
        }
        Err(source) => return Err(io_error(path, source)),
    };
    if !link_before.file_type().is_file() && !link_before.file_type().is_symlink() {
        return Err(Error::ResolverInput {
            path: path.to_path_buf(),
            reason: "must resolve from a regular file or symbolic link".to_owned(),
        });
    }
    let symlink_target_hex = if link_before.file_type().is_symlink() {
        Some(hex::encode(
            fs::read_link(path)
                .map_err(|source| io_error(path, source))?
                .as_os_str()
                .as_bytes(),
        ))
    } else {
        None
    };
    let resolved = match fs::canonicalize(path) {
        Ok(resolved) => resolved,
        // A symbolic link whose target does not exist is the shipped state of
        // a Debian or Ubuntu rootfs with no systemd-resolved running, and of
        // any chroot where /run was never populated. It is not an I/O error at
        // a path that plainly exists: it is "there is no resolver
        // configuration here", which the absent branch above already models.
        // The link itself is still recorded, so the evidence distinguishes it
        // from a path with nothing at all, and so a target that appears later
        // is still caught as drift.
        Err(error) if error.kind() == io::ErrorKind::NotFound && symlink_target_hex.is_some() => {
            return Ok(ResolverInputSnapshot {
                path: path_text.to_owned(),
                present: false,
                content_sha256: None,
                content_size: None,
                resolved_path_hex: None,
                symlink_target_hex,
                path_device: Some(link_before.dev()),
                path_inode: Some(link_before.ino()),
                path_mode: Some(link_before.mode()),
                path_uid: Some(link_before.uid()),
                path_gid: Some(link_before.gid()),
                path_mtime_seconds: Some(link_before.mtime()),
                path_mtime_nanoseconds: Some(link_before.mtime_nsec()),
                path_ctime_seconds: Some(link_before.ctime()),
                path_ctime_nanoseconds: Some(link_before.ctime_nsec()),
                device: None,
                inode: None,
                mode: None,
                uid: None,
                gid: None,
                mtime_seconds: None,
                mtime_nanoseconds: None,
                ctime_seconds: None,
                ctime_nanoseconds: None,
            });
        }
        Err(source) => return Err(io_error(path, source)),
    };
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC)
        .open(path)
        .map_err(|source| io_error(path, source))?;
    let before = file.metadata().map_err(|source| io_error(path, source))?;
    if !before.file_type().is_file() {
        return Err(Error::ResolverInput {
            path: path.to_path_buf(),
            reason: "resolved input is not a regular file".to_owned(),
        });
    }
    if before.len() > MAX_RESOLVER_INPUT_BYTES {
        return Err(Error::ResolverInput {
            path: path.to_path_buf(),
            reason: format!(
                "size {} exceeds the {}-byte snapshot limit",
                before.len(),
                MAX_RESOLVER_INPUT_BYTES
            ),
        });
    }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    Read::by_ref(&mut file)
        .take(MAX_RESOLVER_INPUT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| io_error(path, source))?;
    if bytes.len() as u64 > MAX_RESOLVER_INPUT_BYTES {
        return Err(Error::ResolverInput {
            path: path.to_path_buf(),
            reason: format!("content exceeds the {MAX_RESOLVER_INPUT_BYTES}-byte snapshot limit"),
        });
    }
    let after = file.metadata().map_err(|source| io_error(path, source))?;
    let link_after = fs::symlink_metadata(path).map_err(|source| io_error(path, source))?;
    let resolved_after = fs::canonicalize(path).map_err(|source| io_error(path, source))?;
    if !same_file_metadata(&before, &after)
        || !same_file_metadata(&link_before, &link_after)
        || resolved != resolved_after
    {
        return Err(Error::ResolverInput {
            path: path.to_path_buf(),
            reason: "changed while it was being snapshotted".to_owned(),
        });
    }
    Ok(ResolverInputSnapshot {
        path: path_text.to_owned(),
        present: true,
        content_sha256: Some(hex::encode(Sha256::digest(&bytes))),
        content_size: Some(bytes.len() as u64),
        resolved_path_hex: Some(hex::encode(resolved.as_os_str().as_bytes())),
        symlink_target_hex,
        path_device: Some(link_before.dev()),
        path_inode: Some(link_before.ino()),
        path_mode: Some(link_before.mode()),
        path_uid: Some(link_before.uid()),
        path_gid: Some(link_before.gid()),
        path_mtime_seconds: Some(link_before.mtime()),
        path_mtime_nanoseconds: Some(link_before.mtime_nsec()),
        path_ctime_seconds: Some(link_before.ctime()),
        path_ctime_nanoseconds: Some(link_before.ctime_nsec()),
        device: Some(before.dev()),
        inode: Some(before.ino()),
        mode: Some(before.mode()),
        uid: Some(before.uid()),
        gid: Some(before.gid()),
        mtime_seconds: Some(before.mtime()),
        mtime_nanoseconds: Some(before.mtime_nsec()),
        ctime_seconds: Some(before.ctime()),
        ctime_nanoseconds: Some(before.ctime_nsec()),
    })
}

fn compare_resolver_inputs(
    before: Vec<ResolverInputSnapshot>,
    after: Vec<ResolverInputSnapshot>,
) -> Result<Vec<ResolverInputEvidence>> {
    if before.len() != after.len() {
        return Err(Error::ResolverInput {
            path: PathBuf::from("/etc"),
            reason: "resolver snapshot cardinality changed".to_owned(),
        });
    }
    before
        .into_iter()
        .zip(after)
        .map(|(before, after)| {
            if resolver_behaviour_changed(&before, &after) {
                let path = PathBuf::from(&before.path);
                return Err(Error::ResolverInputChanged {
                    path,
                    before: snapshot_identity(&before),
                    after: snapshot_identity(&after),
                });
            }
            Ok(ResolverInputEvidence { before, after })
        })
        .collect()
}

/// Whether two snapshots of one resolver input differ in a way that could
/// change how a name resolves.
///
/// Only the fields that decide that are compared: whether the file is there,
/// its exact bytes, where a symbolic link points, and where the chain lands.
/// The inode, device, mode, owner and timestamps are recorded as evidence but
/// deliberately not compared, because an ordinary DHCP or NetworkManager
/// renewal rewrites `/etc/resolv.conf` with identical content -- `touch`
/// changes the timestamps, an atomic `install` over it changes the inode -- and
/// failing on that discarded a download that had already completed
/// successfully, forcing the whole image to be fetched again. A change that
/// really could have pointed the pull at a different registry still fails here,
/// which is what this check exists for.
fn resolver_behaviour_changed(
    before: &ResolverInputSnapshot,
    after: &ResolverInputSnapshot,
) -> bool {
    before.path != after.path
        || before.present != after.present
        || before.content_sha256 != after.content_sha256
        || before.content_size != after.content_size
        || before.resolved_path_hex != after.resolved_path_hex
        || before.symlink_target_hex != after.symlink_target_hex
}

fn snapshot_identity(snapshot: &ResolverInputSnapshot) -> String {
    let encoded = serde_json::to_vec(snapshot).unwrap_or_default();
    format!("sha256:{}", hex::encode(Sha256::digest(encoded)))
}

fn same_file_metadata(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.mode() == right.mode()
        && left.uid() == right.uid()
        && left.gid() == right.gid()
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}

fn validate_local_archive_path_syntax(path: &Path) -> Result<()> {
    if !path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::CurDir | Component::ParentDir | Component::Prefix(_)
            )
        })
    {
        return Err(Error::ArchiveInput {
            path: path.to_path_buf(),
            reason: "path must be absolute and lexically normalized".to_owned(),
        });
    }
    Ok(())
}

fn copy_stable_archive(source_path: &Path, destination: &Path) -> Result<(String, u64)> {
    validate_local_archive_path_syntax(source_path)?;
    let mut source = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(source_path)
        .map_err(|source| io_error(source_path, source))?;
    let before = validate_open_archive_identity(source_path, &source)?;
    if before.len() == 0 || before.len() > MAX_STAGED_ARCHIVE_BYTES {
        return Err(Error::ArchiveInput {
            path: source_path.to_path_buf(),
            reason: format!(
                "size must be in 1..={MAX_STAGED_ARCHIVE_BYTES}, observed {}",
                before.len()
            ),
        });
    }
    let mut destination_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(PRIVATE_FILE_MODE)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(destination)
        .map_err(|source| io_error(destination, source))?;
    let mut hasher = Sha256::new();
    let mut copied = 0_u64;
    let mut buffer = [0_u8; 128 * 1024];
    loop {
        let count = source
            .read(&mut buffer)
            .map_err(|error| io_error(source_path, error))?;
        if count == 0 {
            break;
        }
        copied = copied
            .checked_add(count as u64)
            .ok_or_else(|| Error::ArchiveInput {
                path: source_path.to_path_buf(),
                reason: "copied size overflow".to_owned(),
            })?;
        if copied > MAX_STAGED_ARCHIVE_BYTES {
            return Err(Error::ArchiveInput {
                path: source_path.to_path_buf(),
                reason: format!("copy exceeds the {MAX_STAGED_ARCHIVE_BYTES}-byte limit"),
            });
        }
        destination_file
            .write_all(&buffer[..count])
            .map_err(|error| io_error(destination, error))?;
        hasher.update(&buffer[..count]);
    }
    destination_file
        .sync_all()
        .map_err(|source| io_error(destination, source))?;
    let after = validate_open_archive_identity(source_path, &source)?;
    if copied != before.len() || !same_file_metadata(&before, &after) {
        return Err(Error::ArchiveInput {
            path: source_path.to_path_buf(),
            reason: "source changed while it was staged".to_owned(),
        });
    }
    Ok((hex::encode(hasher.finalize()), copied))
}

fn validate_open_archive_identity(path: &Path, file: &File) -> Result<fs::Metadata> {
    let descriptor = file.metadata().map_err(|source| io_error(path, source))?;
    let pathname = fs::symlink_metadata(path).map_err(|source| io_error(path, source))?;
    let canonical = fs::canonicalize(path).map_err(|source| io_error(path, source))?;
    if !descriptor.file_type().is_file()
        || !pathname.file_type().is_file()
        || descriptor.dev() != pathname.dev()
        || descriptor.ino() != pathname.ino()
        || canonical != path
    {
        return Err(Error::ArchiveInput {
            path: path.to_path_buf(),
            reason:
                "open descriptor is not the exact non-symlink regular file at the requested path"
                    .to_owned(),
        });
    }
    Ok(descriptor)
}

fn validate_archive_ambiguity(path: &Path, kind: SkopeoSourceKind) -> Result<()> {
    let member = match kind {
        SkopeoSourceKind::OciArchive => "index.json",
        SkopeoSourceKind::DockerArchive => "manifest.json",
        SkopeoSourceKind::DockerRegistry => {
            return Err(Error::ArchiveInput {
                path: path.to_path_buf(),
                reason: "registry source is not an archive".to_owned(),
            });
        }
    };
    let bytes = read_unique_tar_member(path, member, 16 * 1024 * 1024)?;
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|error| Error::ArchiveInput {
            path: path.to_path_buf(),
            reason: format!("{member} is invalid JSON: {error}"),
        })?;
    let count = match kind {
        SkopeoSourceKind::OciArchive => value
            .as_object()
            .and_then(|object| object.get("manifests"))
            .and_then(serde_json::Value::as_array)
            .map(Vec::len),
        SkopeoSourceKind::DockerArchive => value.as_array().map(Vec::len),
        SkopeoSourceKind::DockerRegistry => None,
    }
    .ok_or_else(|| Error::ArchiveInput {
        path: path.to_path_buf(),
        reason: format!("{member} does not contain the required image list"),
    })?;
    if count != 1 {
        return Err(Error::ArchiveInput {
            path: path.to_path_buf(),
            reason: format!(
                "{member} contains {count} top-level images; exactly one is required to avoid an implicit selector"
            ),
        });
    }
    Ok(())
}

fn read_unique_tar_member(path: &Path, wanted: &str, maximum: u64) -> Result<Vec<u8>> {
    let mut file = File::open(path).map_err(|source| io_error(path, source))?;
    let archive_size = file
        .metadata()
        .map_err(|source| io_error(path, source))?
        .len();
    let mut found = None;
    let mut entries = 0_u64;
    loop {
        let mut header = [0_u8; 512];
        match file.read_exact(&mut header) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                return Err(Error::ArchiveInput {
                    path: path.to_path_buf(),
                    reason: "truncated tar header".to_owned(),
                });
            }
            Err(source) => return Err(io_error(path, source)),
        }
        if header.iter().all(|byte| *byte == 0) {
            break;
        }
        entries += 1;
        if entries > 1_000_000 {
            return Err(Error::ArchiveInput {
                path: path.to_path_buf(),
                reason: "tar contains more than 1000000 entries".to_owned(),
            });
        }
        validate_tar_checksum(path, &header)?;
        let name = tar_name(&header);
        let size = parse_tar_size(path, &header[124..136])?;
        let padded = size
            .checked_add(511)
            .map(|value| value / 512 * 512)
            .ok_or_else(|| Error::ArchiveInput {
                path: path.to_path_buf(),
                reason: "tar entry padding overflow".to_owned(),
            })?;
        let data_start = file
            .stream_position()
            .map_err(|source| io_error(path, source))?;
        let data_end = data_start
            .checked_add(padded)
            .ok_or_else(|| Error::ArchiveInput {
                path: path.to_path_buf(),
                reason: "tar entry offset overflow".to_owned(),
            })?;
        if data_end > archive_size {
            return Err(Error::ArchiveInput {
                path: path.to_path_buf(),
                reason: "tar entry exceeds archive size".to_owned(),
            });
        }
        if name == wanted.as_bytes() {
            if found.is_some() || !matches!(header[156], 0 | b'0') {
                return Err(Error::ArchiveInput {
                    path: path.to_path_buf(),
                    reason: format!("{wanted} is duplicate or not a regular file"),
                });
            }
            if size > maximum {
                return Err(Error::ArchiveInput {
                    path: path.to_path_buf(),
                    reason: format!("{wanted} exceeds the {maximum}-byte limit"),
                });
            }
            let mut bytes = vec![0_u8; size as usize];
            file.read_exact(&mut bytes)
                .map_err(|source| io_error(path, source))?;
            found = Some(bytes);
        }
        file.seek(SeekFrom::Start(data_end))
            .map_err(|source| io_error(path, source))?;
    }
    found.ok_or_else(|| Error::ArchiveInput {
        path: path.to_path_buf(),
        reason: format!("tar does not contain a unique root {wanted}"),
    })
}

fn tar_name(header: &[u8; 512]) -> Vec<u8> {
    let trim = |bytes: &[u8]| {
        let end = bytes
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(bytes.len());
        bytes[..end].to_vec()
    };
    let name = trim(&header[..100]);
    let prefix = trim(&header[345..500]);
    let mut full = if prefix.is_empty() {
        name
    } else {
        [prefix, vec![b'/'], name].concat()
    };
    // `tar -cf archive.tar -C layout .` -- the ordinary way to hand-build an
    // oci-archive -- names every member `./index.json`. That is the same member
    // as `index.json`, and skopeo reads both, so the preflight must not report
    // a valid archive as missing its index. An archive that spells one member
    // both ways still trips the duplicate check at the call site.
    while full.starts_with(b"./") {
        full.drain(..2);
    }
    full
}

/// Read a tar size field, which is octal until it does not fit.
///
/// Twelve octal digits stop one byte short of 8 GiB, so anything at or above
/// that is written base-256 with the high bit of the leading byte set. An
/// archive holding one very large layer is ordinary input that skopeo itself
/// reads, so refusing the wider encoding would reject valid work. The decoded
/// value stays bounded by the archive's own length at the call site.
fn parse_tar_size(path: &Path, field: &[u8]) -> Result<u64> {
    let Some(&first) = field.first() else {
        return Err(Error::ArchiveInput {
            path: path.to_path_buf(),
            reason: "empty tar entry size".to_owned(),
        });
    };
    if first & 0x80 == 0 {
        return parse_tar_octal(path, field, "entry size");
    }
    // 0x80 introduces a non-negative base-256 value; 0xff introduces a
    // negative one, which is never a size. Nothing else is defined.
    if first != 0x80 {
        return Err(Error::ArchiveInput {
            path: path.to_path_buf(),
            reason: "negative or malformed base-256 tar entry size".to_owned(),
        });
    }
    field[1..].iter().try_fold(0_u64, |value, byte| {
        value
            .checked_mul(256)
            .and_then(|value| value.checked_add(u64::from(*byte)))
            .ok_or_else(|| Error::ArchiveInput {
                path: path.to_path_buf(),
                reason: "base-256 tar entry size overflow".to_owned(),
            })
    })
}

fn parse_tar_octal(path: &Path, field: &[u8], role: &str) -> Result<u64> {
    if field.first().is_some_and(|byte| byte & 0x80 != 0) {
        return Err(Error::ArchiveInput {
            path: path.to_path_buf(),
            reason: format!("base-256 {role} is unsupported"),
        });
    }
    let text = field
        .iter()
        .copied()
        .skip_while(|byte| matches!(byte, 0 | b' '))
        .take_while(|byte| !matches!(byte, 0 | b' '))
        .collect::<Vec<_>>();
    if text.is_empty() || text.iter().any(|byte| !matches!(byte, b'0'..=b'7')) {
        return Err(Error::ArchiveInput {
            path: path.to_path_buf(),
            reason: format!("invalid tar {role}"),
        });
    }
    text.into_iter().try_fold(0_u64, |value, byte| {
        value
            .checked_mul(8)
            .and_then(|value| value.checked_add(u64::from(byte - b'0')))
            .ok_or_else(|| Error::ArchiveInput {
                path: path.to_path_buf(),
                reason: format!("tar {role} overflow"),
            })
    })
}

fn validate_tar_checksum(path: &Path, header: &[u8; 512]) -> Result<()> {
    let expected = parse_tar_octal(path, &header[148..156], "checksum")?;
    let actual = header.iter().enumerate().fold(0_u64, |sum, (index, byte)| {
        sum + if (148..156).contains(&index) {
            u64::from(b' ')
        } else {
            u64::from(*byte)
        }
    });
    if actual != expected {
        return Err(Error::ArchiveInput {
            path: path.to_path_buf(),
            reason: format!("invalid tar checksum: expected {expected}, computed {actual}"),
        });
    }
    Ok(())
}

fn validate_source(source: &str) -> Result<()> {
    if source.is_empty() || source.len() > MAX_SOURCE_BYTES {
        return Err(Error::InvalidSource {
            reason: format!("source reference must contain 1..={MAX_SOURCE_BYTES} bytes"),
        });
    }
    if source.starts_with('-') {
        return Err(Error::InvalidSource {
            reason: "source reference begins with '-'".to_owned(),
        });
    }
    if source
        .chars()
        .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err(Error::InvalidSource {
            reason: "source reference contains whitespace or a control character".to_owned(),
        });
    }
    if source.contains(['?', '#', '\\']) {
        return Err(Error::InvalidSource {
            reason: "source reference contains an unsupported URL delimiter".to_owned(),
        });
    }
    let Some(reference) = source.strip_prefix("docker://") else {
        return Err(Error::InvalidSource {
            reason: "an explicit docker:// transport is required".to_owned(),
        });
    };
    let Some((registry, repository)) = reference.split_once('/') else {
        return Err(Error::InvalidSource {
            reason: "a fully-qualified registry and repository are required".to_owned(),
        });
    };
    if registry.is_empty()
        || registry.contains('@')
        || !(registry == "localhost" || registry.contains('.') || registry.contains(':'))
    {
        return Err(Error::InvalidSource {
            reason: "the first component must be an explicit registry host".to_owned(),
        });
    }
    if repository.is_empty()
        || repository.starts_with('/')
        || repository.ends_with('/')
        || repository.split('/').any(str::is_empty)
    {
        return Err(Error::InvalidSource {
            reason: "repository path is empty or not normalized".to_owned(),
        });
    }
    if let Some((name, digest)) = repository.split_once('@') {
        let Some(encoded) = digest.strip_prefix("sha256:") else {
            return Err(Error::InvalidSource {
                reason: "'@' is accepted only for a canonical sha256 image digest".to_owned(),
            });
        };
        if name.is_empty()
            || name.contains('@')
            || encoded.len() != 64
            || encoded
                .bytes()
                .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
        {
            return Err(Error::InvalidSource {
                reason: "image digest must be sha256:<64 lowercase hexadecimal characters>"
                    .to_owned(),
            });
        }
    }
    Ok(())
}

fn validate_program_path(role: &'static str, path: &Path) -> Result<()> {
    if !path.is_absolute() {
        return Err(Error::InvalidExecutionPolicy {
            reason: format!("{role} program path must be absolute"),
        });
    }
    if path.components().any(|component| {
        matches!(
            component,
            Component::CurDir | Component::ParentDir | Component::Prefix(_)
        )
    }) {
        return Err(Error::InvalidExecutionPolicy {
            reason: format!("{role} program path must be lexically normalized"),
        });
    }
    Ok(())
}

fn validate_execution_policy(policy: SkopeoExecutionPolicy) -> Result<()> {
    for (field, value) in [
        ("timeout", policy.timeout),
        ("guard_term_timeout", policy.guard_term_timeout),
        ("guard_exit_timeout", policy.guard_exit_timeout),
    ] {
        if value.is_zero() || value > MAX_TIMEOUT {
            return Err(Error::InvalidExecutionPolicy {
                reason: format!("{field} must be in 1ns..={MAX_TIMEOUT:?}"),
            });
        }
    }
    if policy.guard_exit_timeout < policy.guard_term_timeout {
        return Err(Error::InvalidExecutionPolicy {
            reason: "guard_exit_timeout must be at least guard_term_timeout".to_owned(),
        });
    }
    if policy.maximum_capture_bytes == 0 || policy.maximum_capture_bytes > MAX_CAPTURE_BYTES {
        return Err(Error::InvalidExecutionPolicy {
            reason: format!("maximum_capture_bytes must be in 1..={MAX_CAPTURE_BYTES}"),
        });
    }
    Ok(())
}

fn validate_ca_bundle(path: &Path) -> Result<()> {
    if !path.is_absolute() {
        return Err(Error::InvalidExecutionPolicy {
            reason: "registry CA bundle path must be absolute".to_owned(),
        });
    }
    let metadata = fs::symlink_metadata(path).map_err(|source| io_error(path, source))?;
    if !metadata.file_type().is_file() {
        return Err(Error::InvalidExecutionPolicy {
            reason: "registry CA bundle must be a plain regular file".to_owned(),
        });
    }
    Ok(())
}

fn validate_acquisition_root(path: &Path) -> Result<()> {
    let unsafe_root = |reason: &str| Error::UnsafeAcquisitionDirectory {
        path: path.to_path_buf(),
        reason: reason.to_owned(),
    };
    if !path.is_absolute() {
        return Err(unsafe_root("root is not absolute"));
    }
    let text = path
        .to_str()
        .ok_or_else(|| unsafe_root("root is not valid UTF-8"))?;
    if text.contains(':') || text.chars().any(char::is_control) {
        return Err(unsafe_root("root contains a reserved character"));
    }
    if path.components().any(|component| {
        matches!(
            component,
            Component::CurDir | Component::ParentDir | Component::Prefix(_)
        )
    }) {
        return Err(unsafe_root("root is not lexically normalized"));
    }
    let canonical = fs::canonicalize(path).map_err(|source| io_error(path, source))?;
    let metadata = fs::symlink_metadata(path).map_err(|source| io_error(path, source))?;
    if canonical != path || !metadata.file_type().is_dir() {
        return Err(unsafe_root("root is not an exact non-symlink directory"));
    }
    if metadata.uid() != current_euid() || metadata.mode() & 0o777 != PRIVATE_DIRECTORY_MODE {
        return Err(unsafe_root(
            "root must be owned by the effective user with mode 0700",
        ));
    }
    Ok(())
}

fn validate_managed_path(path: &Path) -> Result<()> {
    let unsafe_path = |reason: &str| Error::UnsafeManagedPath {
        path: path.to_path_buf(),
        reason: reason.to_owned(),
    };
    if !path.is_absolute() {
        return Err(unsafe_path("path is not absolute"));
    }
    let text = path
        .to_str()
        .ok_or_else(|| unsafe_path("path is not valid UTF-8"))?;
    if text.contains(':') {
        return Err(unsafe_path(
            "path contains ':' and cannot be represented unambiguously by the OCI transport",
        ));
    }
    if text.chars().any(char::is_control) {
        return Err(unsafe_path("path contains a control character"));
    }

    let mut normal_components = 0_usize;
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(value) if value != OsStr::new("") => normal_components += 1,
            Component::Prefix(_) => {
                return Err(unsafe_path("Windows path prefixes are unsupported"));
            }
            Component::CurDir | Component::ParentDir | Component::Normal(_) => {
                return Err(unsafe_path("path is not lexically normalized"));
            }
        }
    }
    if normal_components < 2 {
        return Err(unsafe_path(
            "destination must have at least two components below the filesystem root",
        ));
    }

    match fs::symlink_metadata(path) {
        Ok(_) => return Err(unsafe_path("destination already exists")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(source) => return Err(io_error(path, source)),
    }
    let parent = path
        .parent()
        .ok_or_else(|| unsafe_path("destination has no parent directory"))?;
    let parent_metadata = fs::metadata(parent).map_err(|source| io_error(parent, source))?;
    if !parent_metadata.is_dir() {
        return Err(unsafe_path("parent is not a directory"));
    }

    let mut ancestor = PathBuf::from("/");
    for component in parent.components() {
        match component {
            Component::RootDir => continue,
            Component::Normal(value) => ancestor.push(value),
            Component::Prefix(_) | Component::CurDir | Component::ParentDir => {
                return Err(unsafe_path("path is not lexically normalized"));
            }
        }
        let metadata =
            fs::symlink_metadata(&ancestor).map_err(|source| io_error(&ancestor, source))?;
        if metadata.file_type().is_symlink() {
            return Err(unsafe_path("an ancestor is a symbolic link"));
        }
        if !metadata.is_dir() {
            return Err(unsafe_path("an ancestor is not a directory"));
        }
    }
    Ok(())
}

fn write_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(PRIVATE_FILE_MODE)
        .open(path)
        .map_err(|source| io_error(path, source))?;
    file.write_all(bytes)
        .map_err(|source| io_error(path, source))?;
    file.sync_all().map_err(|source| io_error(path, source))
}

fn random_id() -> Result<String> {
    let mut bytes = [0_u8; ACQUISITION_ID_BYTES];
    File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut bytes))
        .map_err(|source| io_error("/dev/urandom", source))?;
    Ok(hex::encode(bytes))
}

fn current_euid() -> u32 {
    nix::unistd::geteuid().as_raw()
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use serde_json::json;
    use sha2::{Digest as _, Sha256};

    use super::*;

    fn private_runtime() -> io::Result<tempfile::TempDir> {
        let temporary = tempfile::tempdir()?;
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))?;
        Ok(temporary)
    }

    fn executable(path: &Path, body: &str) -> io::Result<()> {
        fs::write(path, body)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
    }

    fn fake_guard(path: &Path) -> io::Result<()> {
        executable(
            path,
            "#!/bin/sh\nwhile [ \"$#\" -gt 0 ]; do\n  if [ \"$1\" = -- ]; then shift; exec \"$@\"; fi\n  shift\ndone\nexit 125\n",
        )
    }

    fn write_tar_member(path: &Path, name: &str, bytes: &[u8]) -> io::Result<()> {
        let mut header = [0_u8; 512];
        header[..name.len()].copy_from_slice(name.as_bytes());
        header[100..108].copy_from_slice(b"0000644\0");
        header[108..116].copy_from_slice(b"0000000\0");
        header[116..124].copy_from_slice(b"0000000\0");
        header[124..136].copy_from_slice(format!("{:011o}\0", bytes.len()).as_bytes());
        header[136..148].copy_from_slice(b"00000000000\0");
        header[148..156].fill(b' ');
        header[156] = b'0';
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        let checksum: u64 = header.iter().map(|byte| u64::from(*byte)).sum();
        header[148..156].copy_from_slice(format!("{checksum:06o}\0 ").as_bytes());
        let mut output = Vec::from(header);
        output.extend_from_slice(bytes);
        output.resize(output.len().div_ceil(512) * 512, 0);
        output.resize(output.len() + 1024, 0);
        fs::write(path, output)
    }

    /// Build a tar whose first member carries a GNU base-256 size field, the
    /// encoding every tar writer switches to once a size no longer fits the
    /// twelve octal digits, followed by the member the preflight wants.
    fn write_tar_with_base256_size(
        path: &Path,
        first: &str,
        first_bytes: &[u8],
        wanted: &str,
        wanted_bytes: &[u8],
    ) -> io::Result<()> {
        let mut output = Vec::new();
        for (name, bytes, base256) in [(first, first_bytes, true), (wanted, wanted_bytes, false)] {
            let mut header = [0_u8; 512];
            header[..name.len()].copy_from_slice(name.as_bytes());
            header[100..108].copy_from_slice(b"0000644\0");
            header[108..116].copy_from_slice(b"0000000\0");
            header[116..124].copy_from_slice(b"0000000\0");
            if base256 {
                header[124] = 0x80;
                header[128..136].copy_from_slice(&(bytes.len() as u64).to_be_bytes());
            } else {
                header[124..136].copy_from_slice(format!("{:011o}\0", bytes.len()).as_bytes());
            }
            header[136..148].copy_from_slice(b"00000000000\0");
            header[148..156].fill(b' ');
            header[156] = b'0';
            header[257..263].copy_from_slice(b"ustar\0");
            header[263..265].copy_from_slice(b"00");
            let checksum: u64 = header.iter().map(|byte| u64::from(*byte)).sum();
            header[148..156].copy_from_slice(format!("{checksum:06o}\0 ").as_bytes());
            output.extend_from_slice(&header);
            output.extend_from_slice(bytes);
            output.resize(output.len().div_ceil(512) * 512, 0);
        }
        output.resize(output.len() + 1024, 0);
        fs::write(path, output)
    }

    fn write_blob(root: &Path, bytes: &[u8]) -> io::Result<(String, u64)> {
        let digest = hex::encode(Sha256::digest(bytes));
        fs::write(root.join("blobs/sha256").join(&digest), bytes)?;
        Ok((format!("sha256:{digest}"), bytes.len() as u64))
    }

    fn canonical_layout(root: &Path) -> Result<()> {
        fs::create_dir_all(root.join("blobs/sha256")).map_err(|source| io_error(root, source))?;
        fs::write(
            root.join("oci-layout"),
            b"{\"imageLayoutVersion\":\"1.0.0\"}\n",
        )
        .map_err(|source| io_error(root, source))?;
        let layer = vec![0_u8; 1024];
        let diff_id = format!("sha256:{}", hex::encode(Sha256::digest(&layer)));
        let (layer_digest, layer_size) =
            write_blob(root, &layer).map_err(|source| io_error(root, source))?;
        let config = serde_json::to_vec(&json!({
            "architecture": "amd64",
            "os": "linux",
            "rootfs": {"type": "layers", "diff_ids": [diff_id]},
            "config": {}
        }))
        .map_err(|source| Error::InvalidDocument {
            document: "test config".to_owned(),
            reason: source.to_string(),
        })?;
        let (config_digest, config_size) =
            write_blob(root, &config).map_err(|source| io_error(root, source))?;
        let manifest = serde_json::to_vec(&json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": config_digest,
                "size": config_size
            },
            "layers": [{
                "mediaType": "application/vnd.oci.image.layer.v1.tar",
                "digest": layer_digest,
                "size": layer_size
            }]
        }))
        .map_err(|source| Error::InvalidDocument {
            document: "test manifest".to_owned(),
            reason: source.to_string(),
        })?;
        let (manifest_digest, manifest_size) =
            write_blob(root, &manifest).map_err(|source| io_error(root, source))?;
        let index = serde_json::to_vec(&json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [{
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": manifest_digest,
                "size": manifest_size,
                "platform": {"os": "linux", "architecture": "amd64"},
                "annotations": {"org.opencontainers.image.ref.name": "root"}
            }]
        }))
        .map_err(|source| Error::InvalidDocument {
            document: "test index".to_owned(),
            reason: source.to_string(),
        })?;
        fs::write(root.join("index.json"), index).map_err(|source| io_error(root, source))?;
        Ok(())
    }

    #[test]
    fn source_requires_explicit_transport_and_registry() {
        assert!(SkopeoSource::parse("ubuntu:24.04").is_err());
        assert!(SkopeoSource::parse("docker://ubuntu:24.04").is_err());
        assert!(SkopeoSource::parse("docker://user@example.com/team/image:tag").is_err());
        assert!(SkopeoSource::parse("docker://registry.example/team/user:secret@image").is_err());
        assert!(SkopeoSource::parse("docker://registry.example/team/image@sha256:ABC").is_err());
        assert!(SkopeoSource::parse("docker://registry.example/team/image:tag").is_ok());
        assert!(
            SkopeoSource::parse(
                "docker://registry.example/team/image@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            )
            .is_ok()
        );
    }

    #[test]
    fn resolver_snapshots_expose_bytes_and_reject_before_after_drift() -> Result<()> {
        let runtime = private_runtime().map_err(|source| io_error("<tempdir>", source))?;
        let path = runtime.path().join("resolv.conf");
        fs::write(&path, b"nameserver 192.0.2.1\n").map_err(|source| io_error(&path, source))?;
        let text = path.to_str().ok_or_else(|| Error::ResolverInput {
            path: path.clone(),
            reason: "test path is not UTF-8".to_owned(),
        })?;
        let before = snapshot_resolver_inputs(&[text])?;
        assert_eq!(before[0].content_size, Some(21));
        assert!(before[0].content_sha256.is_some());
        fs::write(&path, b"nameserver 192.0.2.2\n").map_err(|source| io_error(&path, source))?;
        let after = snapshot_resolver_inputs(&[text])?;
        assert!(matches!(
            compare_resolver_inputs(before, after),
            Err(Error::ResolverInputChanged { .. })
        ));
        Ok(())
    }

    /// A symlink to a target that does not exist is the shipped state of a
    /// Debian or Ubuntu rootfs without systemd-resolved running, and of any
    /// chroot where /run was never populated. Refusing every registry pull
    /// over it -- with an ENOENT naming a path that plainly exists -- made a
    /// host layout into an unexplained failure.
    #[test]
    fn a_dangling_resolver_symlink_is_absent_configuration_not_an_error() -> Result<()> {
        let runtime = private_runtime().map_err(|source| io_error("<tempdir>", source))?;
        let path = runtime.path().join("resolv.conf");
        std::os::unix::fs::symlink("../run/systemd/resolve/stub-resolv.conf", &path)
            .map_err(|source| io_error(&path, source))?;
        let text = path.to_str().ok_or_else(|| Error::ResolverInput {
            path: path.clone(),
            reason: "test path is not UTF-8".to_owned(),
        })?;

        let snapshot = snapshot_resolver_inputs(&[text])?;
        assert!(!snapshot[0].present);
        assert!(snapshot[0].content_sha256.is_none());
        // The link itself is still recorded, so this is distinguishable from a
        // path with nothing at all there.
        assert!(snapshot[0].symlink_target_hex.is_some());
        assert!(snapshot[0].path_inode.is_some());

        // Two dangling snapshots agree, so a pull is not refused for it.
        let again = snapshot_resolver_inputs(&[text])?;
        compare_resolver_inputs(snapshot, again)?;

        // A target that appears mid-acquisition is still drift.
        let before = snapshot_resolver_inputs(&[text])?;
        fs::create_dir_all(
            runtime
                .path()
                .join("../run/systemd/resolve")
                .components()
                .as_path(),
        )
        .ok();
        fs::remove_file(&path).map_err(|source| io_error(&path, source))?;
        fs::write(&path, b"nameserver 192.0.2.1\n").map_err(|source| io_error(&path, source))?;
        let after = snapshot_resolver_inputs(&[text])?;
        assert!(matches!(
            compare_resolver_inputs(before, after),
            Err(Error::ResolverInputChanged { .. })
        ));
        Ok(())
    }

    /// A DHCP or NetworkManager renewal rewrites /etc/resolv.conf with the
    /// same bytes: `touch` moves the timestamps, an atomic install over it
    /// moves the inode. Neither changes how a name resolves, and failing on
    /// either discarded a registry download that had already completed.
    #[test]
    fn a_content_identical_resolver_rewrite_is_recorded_but_does_not_fail() -> Result<()> {
        let runtime = private_runtime().map_err(|source| io_error("<tempdir>", source))?;
        let path = runtime.path().join("resolv.conf");
        let contents = b"nameserver 192.0.2.1\n";
        fs::write(&path, contents).map_err(|source| io_error(&path, source))?;
        let text = path.to_str().ok_or_else(|| Error::ResolverInput {
            path: path.clone(),
            reason: "test path is not UTF-8".to_owned(),
        })?;
        let before = snapshot_resolver_inputs(&[text])?;

        // Republish identical bytes through a fresh inode, exactly as an
        // atomic rewrite does, and move the timestamps well away from the
        // original so a metadata comparison could not miss the difference.
        let staging = runtime.path().join("resolv.conf.new");
        fs::write(&staging, contents).map_err(|source| io_error(&staging, source))?;
        fs::rename(&staging, &path).map_err(|source| io_error(&path, source))?;
        let moved = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000);
        fs::File::open(&path)
            .and_then(|file| file.set_times(fs::FileTimes::new().set_modified(moved)))
            .map_err(|source| io_error(&path, source))?;
        let after = snapshot_resolver_inputs(&[text])?;

        assert_ne!(
            before[0].inode, after[0].inode,
            "the rewrite must actually have produced a different inode"
        );
        assert_ne!(before[0].mtime_seconds, after[0].mtime_seconds);
        let evidence = compare_resolver_inputs(before, after)?;
        assert_eq!(evidence.len(), 1);
        // Both snapshots are still retained, so the churn is evidence rather
        // than something silently discarded.
        assert_ne!(evidence[0].before.inode, evidence[0].after.inode);
        assert_eq!(
            evidence[0].before.content_sha256,
            evidence[0].after.content_sha256
        );
        Ok(())
    }

    #[test]
    fn archive_staging_uses_fixed_transport_names_and_rejects_ambiguous_indexes() -> Result<()> {
        let runtime = private_runtime().map_err(|source| io_error("<tempdir>", source))?;
        let source = runtime.path().join("input:with-colon.tar");
        write_tar_member(
            &source,
            "index.json",
            br#"{"schemaVersion":2,"manifests":[{}]}"#,
        )
        .map_err(|error| io_error(&source, error))?;
        let directory = AcquisitionDirectory::create(runtime.path())?;
        let archive = directory.stage_archive(&source, SkopeoSourceKind::OciArchive)?;
        assert_eq!(archive.original_path(), source);
        assert!(archive.size() > 0);
        assert_eq!(archive.sha256().len(), 64);
        assert!(archive.source().as_str().starts_with("oci-archive:"));
        assert!(
            archive
                .source()
                .as_str()
                .ends_with("/source.oci-archive.tar")
        );
        assert_eq!(archive.source().as_str().matches(':').count(), 1);

        let second = private_runtime().map_err(|source| io_error("<tempdir>", source))?;
        let ambiguous = second.path().join("ambiguous.tar");
        write_tar_member(&ambiguous, "manifest.json", br#"[{},{}]"#)
            .map_err(|error| io_error(&ambiguous, error))?;
        let directory = AcquisitionDirectory::create(second.path())?;
        let error = directory
            .stage_archive(&ambiguous, SkopeoSourceKind::DockerArchive)
            .expect_err("multiple Docker archive images need an explicit unsupported selector");
        assert!(matches!(error, Error::ArchiveInput { .. }));
        assert!(error.to_string().contains("exactly one"));
        Ok(())
    }

    #[test]
    fn archive_open_is_nonblocking_regular_only_and_detects_path_replacement() -> Result<()> {
        use nix::{sys::stat::Mode, unistd::mkfifo};

        let runtime = private_runtime().map_err(|source| io_error("<tempdir>", source))?;
        let fifo = runtime.path().join("archive.fifo");
        mkfifo(&fifo, Mode::S_IRUSR | Mode::S_IWUSR)
            .map_err(|error| io_error(&fifo, io::Error::from_raw_os_error(error as i32)))?;
        assert!(matches!(
            copy_stable_archive(&fifo, &runtime.path().join("staged.tar")),
            Err(Error::ArchiveInput { .. })
        ));

        let path = runtime.path().join("replace.tar");
        fs::write(&path, b"original").map_err(|source| io_error(&path, source))?;
        let open = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&path)
            .map_err(|source| io_error(&path, source))?;
        fs::rename(&path, runtime.path().join("original.tar"))
            .map_err(|source| io_error(&path, source))?;
        fs::write(&path, b"replacement").map_err(|source| io_error(&path, source))?;
        assert!(matches!(
            validate_open_archive_identity(&path, &open),
            Err(Error::ArchiveInput { .. })
        ));
        Ok(())
    }

    #[test]
    fn local_archive_normalization_uses_no_registry_or_resolver_inputs() -> Result<()> {
        let runtime = private_runtime().map_err(|source| io_error("<tempdir>", source))?;
        let template = runtime.path().join("template");
        canonical_layout(&template)?;
        let archive_path = runtime.path().join("source.tar");
        write_tar_member(
            &archive_path,
            "manifest.json",
            br#"[{"Config":"config.json","RepoTags":["demo:latest"],"Layers":[]}]"#,
        )
        .map_err(|error| io_error(&archive_path, error))?;
        let guard = runtime.path().join("guard");
        fake_guard(&guard).map_err(|source| io_error(&guard, source))?;
        let helper = runtime.path().join("skopeo");
        executable(
            &helper,
            &format!(
                "#!/bin/sh\nfor last do :; done\ndest=${{last#oci:}}\ndest=${{dest%:root}}\n/bin/mkdir \"$dest\" || exit 41\n/bin/cp -R {}/. \"$dest\"/ || exit 42\nprintf 'archive-copy-ok\\n'\n",
                template.display()
            ),
        )
        .map_err(|source| io_error(&helper, source))?;
        let directory = AcquisitionDirectory::create(runtime.path())?;
        let archive = directory.stage_archive(&archive_path, SkopeoSourceKind::DockerArchive)?;
        let normalizer = SkopeoNormalizer::new(&helper, &guard, SkopeoExecutionPolicy::default())?;
        let output = normalizer.normalize_archive(
            &archive,
            &SkopeoPlatform::new("linux", "amd64", None)?,
            &directory,
        )?;
        assert!(output.resolver_inputs.is_empty());
        assert_eq!(output.log.stdout, b"archive-copy-ok\n");
        Ok(())
    }

    #[test]
    fn command_is_exact_anonymous_and_has_no_path_environment() -> Result<()> {
        let runtime = private_runtime().map_err(|source| io_error("<tempdir>", source))?;
        let directory = AcquisitionDirectory::create(runtime.path())?;
        let ca = runtime.path().join("ca.pem");
        fs::write(&ca, b"test ca").map_err(|source| io_error(&ca, source))?;
        let normalizer = SkopeoNormalizer::new(
            "/bundle/host/skopeo",
            "/bundle/host/pocket-guard",
            SkopeoExecutionPolicy::default(),
        )?;
        let source = SkopeoSource::parse("docker://registry.example/team/image:tag")?;
        let platform = SkopeoPlatform::new("linux", "amd64", Some("v1".to_owned()))?;
        let command = normalizer.command(&source, &platform, &directory, &ca)?;
        assert_eq!(
            command.get_program(),
            OsStr::new("/bundle/host/pocket-guard")
        );
        assert_eq!(command.get_current_dir(), Some(Path::new("/")));
        let arguments: Vec<OsString> = command.get_args().map(OsString::from).collect();
        let separator = arguments
            .iter()
            .position(|argument| argument == OsStr::new("--"))
            .ok_or_else(|| Error::InvalidExecutionPolicy {
                reason: "missing test separator".to_owned(),
            })?;
        let expected = vec![
            OsString::from("/bundle/host/skopeo"),
            OsString::from("--insecure-policy"),
            OsString::from("--registries.d"),
            directory.registries_directory().into_os_string(),
            OsString::from("--tmpdir"),
            directory.tmp().into_os_string(),
            OsString::from("--override-os"),
            OsString::from("linux"),
            OsString::from("--override-arch"),
            OsString::from("amd64"),
            OsString::from("--override-variant"),
            OsString::from("v1"),
            OsString::from("copy"),
            OsString::from("--authfile"),
            directory.auth_file().into_os_string(),
            OsString::from("--src-no-creds"),
            OsString::from("--src-cert-dir"),
            directory.certificates_directory().into_os_string(),
            OsString::from("--src-tls-verify=true"),
            OsString::from("--format"),
            OsString::from("oci"),
            OsString::from("--multi-arch"),
            OsString::from("system"),
            OsString::from("--image-parallel-copies"),
            OsString::from("1"),
            OsString::from("--retry-times"),
            OsString::from("0"),
            OsString::from("--remove-signatures"),
            OsString::from("--"),
            OsString::from("docker://registry.example/team/image:tag"),
            OsString::from(format!(
                "oci:{}:root",
                directory.as_path().join("layout").display()
            )),
        ];
        assert_eq!(&arguments[separator + 1..], expected);
        let environment: BTreeMap<OsString, Option<OsString>> = command
            .get_envs()
            .map(|(key, value)| (key.to_owned(), value.map(OsString::from)))
            .collect();
        assert!(!environment.contains_key(OsStr::new("PATH")));
        assert_eq!(
            environment.get(OsStr::new("SSL_CERT_FILE")),
            Some(&Some(ca.into_os_string()))
        );
        assert_eq!(
            environment.get(OsStr::new("REGISTRY_AUTH_FILE")),
            Some(&Some(directory.auth_file().into_os_string()))
        );
        assert_eq!(
            environment.get(OsStr::new("CONTAINERS_REGISTRIES_CONF")),
            Some(&Some(directory.registries_configuration().into_os_string()))
        );
        assert!(!environment.contains_key(OsStr::new("CONTAINERS_REGISTRIES_CONF_DIR")));
        Ok(())
    }

    #[test]
    fn fake_guard_and_helper_produce_verified_layout() -> Result<()> {
        let runtime = private_runtime().map_err(|source| io_error("<tempdir>", source))?;
        let template = runtime.path().join("template");
        canonical_layout(&template)?;
        let guard = runtime.path().join("guard");
        fake_guard(&guard).map_err(|source| io_error(&guard, source))?;
        let helper = runtime.path().join("skopeo");
        executable(
            &helper,
            &format!(
                "#!/bin/sh\nfor last do :; done\ndest=${{last#oci:}}\ndest=${{dest%:root}}\n/bin/mkdir \"$dest\" || exit 41\n/bin/cp -R {}/. \"$dest\"/ || exit 42\nprintf 'fake-copy-ok\\n'\n",
                template.display()
            ),
        )
        .map_err(|source| io_error(&helper, source))?;
        let ca = runtime.path().join("ca.pem");
        fs::write(&ca, b"test ca").map_err(|source| io_error(&ca, source))?;
        let directory = AcquisitionDirectory::create(runtime.path())?;
        let normalizer = SkopeoNormalizer::new(
            &helper,
            &guard,
            SkopeoExecutionPolicy {
                timeout: Duration::from_secs(5),
                ..SkopeoExecutionPolicy::default()
            },
        )?;
        let output = normalizer.normalize(
            &SkopeoSource::parse("docker://registry.example/team/image:tag")?,
            &SkopeoPlatform::new("linux", "amd64", None)?,
            &directory,
            &ca,
        )?;
        assert_eq!(output.image.effective_platform.architecture, "amd64");
        assert_eq!(output.log.stdout, b"fake-copy-ok\n");
        Ok(())
    }

    #[test]
    fn failed_partial_copy_is_removed_with_operation_directory() -> Result<()> {
        let runtime = private_runtime().map_err(|source| io_error("<tempdir>", source))?;
        let guard = runtime.path().join("guard");
        fake_guard(&guard).map_err(|source| io_error(&guard, source))?;
        let helper = runtime.path().join("skopeo");
        executable(
            &helper,
            "#!/bin/sh\nfor last do :; done\ndest=${last#oci:}\ndest=${dest%:root}\n/bin/mkdir \"$dest\"\nprintf partial > \"$dest/index.json\"\nprintf 'intentional failure\\n' >&2\nexit 17\n",
        )
        .map_err(|source| io_error(&helper, source))?;
        let ca = runtime.path().join("ca.pem");
        fs::write(&ca, b"test ca").map_err(|source| io_error(&ca, source))?;
        let operation_path;
        {
            let directory = AcquisitionDirectory::create(runtime.path())?;
            operation_path = directory.as_path().to_path_buf();
            let normalizer =
                SkopeoNormalizer::new(&helper, &guard, SkopeoExecutionPolicy::default())?;
            let error = normalizer
                .normalize(
                    &SkopeoSource::parse("docker://registry.example/team/image:tag")?,
                    &SkopeoPlatform::new("linux", "amd64", None)?,
                    &directory,
                    &ca,
                )
                .expect_err("fake copy must fail");
            assert!(matches!(error, Error::SkopeoFailed { .. }));
            assert!(operation_path.join("layout/index.json").exists());
        }
        assert!(!operation_path.exists());
        Ok(())
    }

    #[test]
    fn timeout_is_bounded_and_partial_operation_is_cleaned() -> Result<()> {
        let runtime = private_runtime().map_err(|source| io_error("<tempdir>", source))?;
        let guard = runtime.path().join("guard");
        fake_guard(&guard).map_err(|source| io_error(&guard, source))?;
        let helper = runtime.path().join("skopeo");
        executable(&helper, "#!/bin/sh\nexec /bin/sleep 5\n")
            .map_err(|source| io_error(&helper, source))?;
        let ca = runtime.path().join("ca.pem");
        fs::write(&ca, b"test ca").map_err(|source| io_error(&ca, source))?;
        let operation_path;
        {
            let directory = AcquisitionDirectory::create(runtime.path())?;
            operation_path = directory.as_path().to_path_buf();
            let normalizer = SkopeoNormalizer::new(
                &helper,
                &guard,
                SkopeoExecutionPolicy {
                    timeout: Duration::from_millis(20),
                    guard_term_timeout: Duration::from_millis(10),
                    guard_exit_timeout: Duration::from_millis(50),
                    maximum_capture_bytes: 1024,
                },
            )?;
            let started = Instant::now();
            let result = normalizer.normalize(
                &SkopeoSource::parse("docker://registry.example/team/image:tag")?,
                &SkopeoPlatform::new("linux", "amd64", None)?,
                &directory,
                &ca,
            );
            assert!(matches!(result, Err(Error::SkopeoTimeout { .. })));
            assert!(started.elapsed() < Duration::from_secs(2));
        }
        assert!(!operation_path.exists());
        Ok(())
    }

    #[test]
    fn helper_output_limit_is_reported_after_draining_the_pipe() -> Result<()> {
        let runtime = private_runtime().map_err(|source| io_error("<tempdir>", source))?;
        let guard = runtime.path().join("guard");
        fake_guard(&guard).map_err(|source| io_error(&guard, source))?;
        let helper = runtime.path().join("skopeo");
        executable(
            &helper,
            "#!/bin/sh\ni=0\nwhile [ \"$i\" -lt 100 ]; do printf x; i=$((i + 1)); done\nexit 17\n",
        )
        .map_err(|source| io_error(&helper, source))?;
        let ca = runtime.path().join("ca.pem");
        fs::write(&ca, b"test ca").map_err(|source| io_error(&ca, source))?;
        let directory = AcquisitionDirectory::create(runtime.path())?;
        let normalizer = SkopeoNormalizer::new(
            &helper,
            &guard,
            SkopeoExecutionPolicy {
                maximum_capture_bytes: 32,
                ..SkopeoExecutionPolicy::default()
            },
        )?;
        let result = normalizer.normalize(
            &SkopeoSource::parse("docker://registry.example/team/image:tag")?,
            &SkopeoPlatform::new("linux", "amd64", None)?,
            &directory,
            &ca,
        );
        assert!(matches!(
            result,
            Err(Error::SkopeoOutputLimit {
                stream: "stdout",
                maximum: 32,
                actual: 100
            })
        ));
        Ok(())
    }

    #[test]
    fn managed_destination_must_be_absent_and_absolute() -> Result<()> {
        assert!(ManagedLayoutPath::new("relative/layout").is_err());
        let temporary = private_runtime().map_err(|source| io_error("<tempdir>", source))?;
        let existing = temporary.path().join("existing");
        fs::create_dir(&existing).map_err(|source| io_error(&existing, source))?;
        assert!(ManagedLayoutPath::new(existing).is_err());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn managed_destination_rejects_symlinked_ancestor() -> Result<()> {
        use std::os::unix::fs::symlink;

        let temporary = private_runtime().map_err(|source| io_error("<tempdir>", source))?;
        let real = temporary.path().join("real");
        fs::create_dir(&real).map_err(|source| io_error(&real, source))?;
        let linked = temporary.path().join("linked");
        symlink(&real, &linked).map_err(|source| io_error(&linked, source))?;
        assert!(ManagedLayoutPath::new(linked.join("layout")).is_err());
        Ok(())
    }

    /// Twelve octal digits stop at 8 GiB - 1. A layer at or above that is
    /// written base-256, and an archive holding one must still be readable.
    #[test]
    fn tar_sizes_that_do_not_fit_octal_are_decoded_not_refused() {
        let path = Path::new("/nonexistent-archive");
        let mut field = [0_u8; 12];
        field[0] = 0x80;
        field[4..12].copy_from_slice(&(9_u64 * 1024 * 1024 * 1024).to_be_bytes());
        assert_eq!(
            parse_tar_size(path, &field).expect("decode base-256 size"),
            9 * 1024 * 1024 * 1024
        );

        // The largest octal size still parses exactly as before.
        assert_eq!(
            parse_tar_size(path, b"77777777777\0").expect("decode octal size"),
            8 * 1024 * 1024 * 1024 - 1
        );

        // A negative introducer is never a size, and neither is a value that
        // does not fit a u64 offset.
        let mut negative = [0xff_u8; 12];
        negative[0] = 0xff;
        assert!(parse_tar_size(path, &negative).is_err());
        let mut huge = [0xff_u8; 12];
        huge[0] = 0x80;
        assert!(parse_tar_size(path, &huge).is_err());
    }

    /// The decode has to be wired into the scan, not just exist: a member with
    /// a base-256 size must be skipped by exactly its length so the member the
    /// preflight is looking for is still found.
    #[test]
    fn a_base256_sized_member_is_skipped_by_its_true_length() {
        let temporary = private_runtime().expect("private runtime");
        let archive = temporary.path().join("image.tar");
        let payload = vec![7_u8; 1536];
        write_tar_with_base256_size(&archive, "layer.tar", &payload, "index.json", b"{}\n")
            .expect("write archive");
        let bytes = read_unique_tar_member(&archive, "index.json", 4096)
            .expect("find the member after a base-256 sized one");
        assert_eq!(bytes, b"{}\n");
    }

    /// `tar -cf archive.tar -C layout .` names every member `./index.json`.
    /// That archive is valid and skopeo reads it, so the preflight must find
    /// its index rather than report the archive as missing one.
    #[test]
    fn a_dot_slash_prefixed_member_is_the_same_member() {
        let temporary = private_runtime().expect("private runtime");
        let archive = temporary.path().join("image.tar");
        write_tar_member(&archive, "./index.json", b"{\"manifests\":[]}\n").expect("write archive");
        let bytes = read_unique_tar_member(&archive, "index.json", 4096)
            .expect("find a ./-prefixed member");
        assert_eq!(bytes, b"{\"manifests\":[]}\n");
    }
}
