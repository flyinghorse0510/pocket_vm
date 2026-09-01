use std::{
    ffi::OsString,
    fs::{self, File},
    os::unix::ffi::{OsStrExt, OsStringExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use pocket_protocol::{AccountDb, BuilderMessage, BuilderStart, UserResolution, ValidateMessage};

use crate::{
    BuilderError, ManifestEmitter, ManifestSummary,
    input::verify_input_layout,
    manifest::emit_manifest,
    marker::write_generation_marker,
    user::{build_account_database, resolve_image_user_from_database},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildArtifacts {
    pub generation_marker_sha256: String,
    pub user_resolution: UserResolution,
    pub account_db: AccountDb,
    pub manifest: ManifestSummary,
}

pub trait LayerApplier {
    fn apply(
        &mut self,
        input_layout: &Path,
        input_reference: &str,
        target_rootfs: &Path,
    ) -> Result<(), BuilderError>;
}

#[derive(Debug, Clone)]
pub struct UmociLayerApplier {
    executable: PathBuf,
}

impl UmociLayerApplier {
    #[must_use]
    pub fn new(executable: impl Into<PathBuf>) -> Self {
        Self {
            executable: executable.into(),
        }
    }
}

impl LayerApplier for UmociLayerApplier {
    fn apply(
        &mut self,
        input_layout: &Path,
        input_reference: &str,
        target_rootfs: &Path,
    ) -> Result<(), BuilderError> {
        let arguments = umoci_arguments(input_layout, input_reference, target_rootfs)?;
        let status = Command::new(&self.executable)
            .args(arguments)
            .env_clear()
            .current_dir("/")
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
            .map_err(|error| {
                BuilderError::tool("apply-layers", error.raw_os_error(), error.to_string())
            })?;
        if !status.success() {
            return Err(BuilderError::tool(
                "apply-layers",
                None,
                format!("umoci raw unpack exited with {status}"),
            ));
        }
        Ok(())
    }
}

/// Execute all non-mount conversion steps against already-mounted filesystems.
/// A failure leaves the target unpublishable; the caller still owns sync,
/// unmount, poweroff and the typed `BUILD_ERROR` response.
pub fn execute_conversion(
    input_layout: &Path,
    target: &Path,
    start: &BuilderStart,
    applier: &mut dyn LayerApplier,
    emitter: &mut dyn ManifestEmitter,
) -> Result<BuildArtifacts, BuilderError> {
    start
        .validate()
        .map_err(|error| BuilderError::protocol("build-start", error))?;
    verify_input_layout(input_layout, start)?;
    prepare_target_root(target)?;
    let rootfs = target.join("rootfs");
    require_absent(&rootfs, "target rootfs")?;

    if let Err(error) = applier.apply(input_layout, &start.input_reference, &rootfs) {
        return Err(classify_target_capacity(target, error));
    }
    require_plain_directory(&rootfs, "unpacked rootfs")?;
    let account_database = build_account_database(&rootfs)?;
    let user_resolution =
        resolve_image_user_from_database(&account_database, &start.original_user)?;
    let account_db = AccountDb::from_database(&account_database)
        .map_err(|error| BuilderError::protocol("account-database", error))?;
    let generation_marker_sha256 = write_generation_marker(target, start, &account_db.sha256)?;
    syncfs_target(target)?;
    let manifest = emit_manifest(
        target,
        &start.manifest_schema,
        &start.manifest_limits,
        &start.derivation_key,
        emitter,
    )?;
    emitter.emit(BuilderMessage::AccountDb(account_db.clone()))?;
    Ok(BuildArtifacts {
        generation_marker_sha256,
        user_resolution,
        account_db,
        manifest,
    })
}

fn classify_target_capacity(target: &Path, error: BuilderError) -> BuilderError {
    let observed = nix::sys::statvfs::statvfs(target).ok();
    let resource = observed
        .as_ref()
        .and_then(|status| capacity_resource(status.blocks_available(), status.files_available()));
    if error.errno() != Some(libc::ENOSPC) && resource.is_none() {
        return error;
    }
    let resource = resource.unwrap_or("block-or-inode");
    BuilderError::failure(
        "apply-layers",
        pocket_core::ErrorCode::BuilderToolFailed,
        Some(libc::ENOSPC),
        format!("target {resource} capacity exhausted while applying layers: {error}"),
    )
}

fn capacity_resource(blocks_available: u64, files_available: u64) -> Option<&'static str> {
    // ext4 can retain a small number of blocks for the journal/metadata while
    // refusing a user allocation, so treat the fixed tail as block ENOSPC.
    const BLOCK_ENOSPC_TAIL: u64 = 128;
    match (blocks_available <= BLOCK_ENOSPC_TAIL, files_available == 0) {
        (true, true) => Some("block-and-inode"),
        (true, false) => Some("block"),
        (false, true) => Some("inode"),
        (false, false) => None,
    }
}

fn syncfs_target(target: &Path) -> Result<(), BuilderError> {
    let directory = File::open(target).map_err(|error| {
        BuilderError::io("sync-before-manifest", error)
            .reclassify(pocket_core::ErrorCode::BuilderSync)
    })?;
    nix::unistd::syncfs(&directory).map_err(|error| {
        BuilderError::syscall("sync-before-manifest", error)
            .reclassify(pocket_core::ErrorCode::BuilderSync)
    })
}

fn image_argument(input_layout: &Path, reference: &str) -> Result<OsString, BuilderError> {
    if reference != "root" {
        return Err(BuilderError::unsupported(
            "apply-layers",
            "only the canonical root reference is supported",
        ));
    }
    let bytes = input_layout.as_os_str().as_bytes();
    if bytes.contains(&0) {
        return Err(BuilderError::contract(
            "apply-layers",
            "input-layout path contains NUL",
        ));
    }
    let mut argument = Vec::with_capacity(bytes.len() + 5);
    argument.extend_from_slice(bytes);
    argument.extend_from_slice(b":root");
    Ok(OsString::from_vec(argument))
}

fn umoci_arguments(
    input_layout: &Path,
    reference: &str,
    target_rootfs: &Path,
) -> Result<Vec<OsString>, BuilderError> {
    Ok(vec![
        "raw".into(),
        "unpack".into(),
        "--image".into(),
        image_argument(input_layout, reference)?,
        target_rootfs.as_os_str().to_owned(),
    ])
}

fn require_absent(path: &Path, what: &'static str) -> Result<(), BuilderError> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(BuilderError::io("target-contract", error)),
        Ok(_) => Err(BuilderError::failure(
            "target-contract",
            pocket_core::ErrorCode::BuilderTargetDirty,
            None,
            format!("{what} already exists"),
        )),
    }
}

/// Normalize the freshly formatted ext4 root to Pocket's exact on-disk
/// layout.  mke2fs creates an empty `lost+found` directory even when no
/// source directory is supplied.  Pocket's immutable generation contract has
/// only `rootfs/` plus its top-level marker, so remove that one known
/// formatter-created directory and reject every other pre-existing entry.
fn prepare_target_root(target: &Path) -> Result<(), BuilderError> {
    require_plain_directory(target, "target filesystem root")?;
    for entry in fs::read_dir(target).map_err(|error| BuilderError::io("target-contract", error))? {
        let entry = entry.map_err(|error| BuilderError::io("target-contract", error))?;
        if entry.file_name().as_bytes() != b"lost+found" {
            return Err(BuilderError::failure(
                "target-contract",
                pocket_core::ErrorCode::BuilderTargetDirty,
                None,
                "target filesystem contains an unexpected entry",
            ));
        }
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|error| BuilderError::io("target-contract", error))?;
        if !metadata.is_dir() {
            return Err(BuilderError::failure(
                "target-contract",
                pocket_core::ErrorCode::BuilderTargetDirty,
                None,
                "target lost+found entry is not a plain directory",
            ));
        }
        fs::remove_dir(entry.path()).map_err(|error| {
            if error.kind() == std::io::ErrorKind::DirectoryNotEmpty {
                BuilderError::failure(
                    "target-contract",
                    pocket_core::ErrorCode::BuilderTargetDirty,
                    error.raw_os_error(),
                    "target lost+found directory is not empty",
                )
            } else {
                BuilderError::io("target-contract", error)
            }
        })?;
    }
    Ok(())
}

fn require_plain_directory(path: &Path, what: &'static str) -> Result<(), BuilderError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| BuilderError::io("target-contract", error))?;
    if !metadata.is_dir() {
        return Err(BuilderError::contract(
            "target-contract",
            format!("{what} is not a plain directory"),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{ffi::OsString, fs, path::Path};

    use pocket_protocol::BuilderMessage;
    use tempfile::TempDir;

    use super::{
        LayerApplier, capacity_resource, execute_conversion, image_argument, umoci_arguments,
    };
    use crate::{BuilderError, ManifestEmitter, input::tests::fixture};

    #[derive(Default)]
    struct FakeApplier {
        calls: Vec<(String, String, String)>,
        passwd: Option<&'static str>,
    }

    impl LayerApplier for FakeApplier {
        fn apply(
            &mut self,
            input_layout: &Path,
            input_reference: &str,
            target_rootfs: &Path,
        ) -> Result<(), BuilderError> {
            self.calls.push((
                input_layout.display().to_string(),
                input_reference.to_owned(),
                target_rootfs.display().to_string(),
            ));
            fs::create_dir(target_rootfs).map_err(|error| BuilderError::io("fake", error))?;
            fs::create_dir(target_rootfs.join("etc"))
                .map_err(|error| BuilderError::io("fake", error))?;
            fs::write(
                target_rootfs.join("etc/passwd"),
                self.passwd.unwrap_or("app:x:7:8::/:/bin/false\n"),
            )
            .map_err(|error| BuilderError::io("fake", error))?;
            fs::write(target_rootfs.join("app"), b"payload")
                .map_err(|error| BuilderError::io("fake", error))
        }
    }

    #[derive(Default)]
    struct Capture(Vec<BuilderMessage>);

    impl ManifestEmitter for Capture {
        fn emit(&mut self, message: BuilderMessage) -> Result<(), BuilderError> {
            self.0.push(message);
            Ok(())
        }
    }

    struct FailingApplier;

    impl LayerApplier for FailingApplier {
        fn apply(
            &mut self,
            _input_layout: &Path,
            _input_reference: &str,
            _target_rootfs: &Path,
        ) -> Result<(), BuilderError> {
            Err(BuilderError::tool(
                "apply-layers",
                None,
                "injected helper failure",
            ))
        }
    }

    #[test]
    fn capacity_classifier_distinguishes_block_and_inode_exhaustion() {
        assert_eq!(capacity_resource(0, 12), Some("block"));
        assert_eq!(capacity_resource(129, 0), Some("inode"));
        assert_eq!(capacity_resource(128, 0), Some("block-and-inode"));
        assert_eq!(capacity_resource(129, 1), None);
    }

    #[test]
    fn fake_helper_conversion_writes_marker_and_complete_manifest() {
        let (input, mut start) = fixture();
        start.original_user = "app".to_owned();
        let target = TempDir::new().expect("target");
        let mut applier = FakeApplier::default();
        let mut capture = Capture::default();
        let artifacts = execute_conversion(
            input.path(),
            target.path(),
            &start,
            &mut applier,
            &mut capture,
        )
        .expect("conversion");
        assert_eq!(applier.calls.len(), 1);
        assert_eq!(applier.calls[0].1, "root");
        assert_eq!(
            (artifacts.user_resolution.uid, artifacts.user_resolution.gid),
            (7, 8)
        );
        assert!(target.path().join(".pocket-generation.cbor").is_file());
        assert!(matches!(
            capture.0.first(),
            Some(BuilderMessage::ManifestBegin(_))
        ));
        assert!(matches!(
            capture.0.get(capture.0.len().saturating_sub(2)),
            Some(BuilderMessage::ManifestEnd(_))
        ));
        let Some(BuilderMessage::AccountDb(account_db)) = capture.0.last() else {
            panic!("account database must follow the manifest stream");
        };
        assert_eq!(account_db, &artifacts.account_db);
        assert_eq!(
            account_db
                .decode_database()
                .expect("canonical database")
                .users
                .len(),
            1
        );
    }

    #[test]
    fn unresolved_image_user_does_not_abort_conversion() {
        let (input, mut start) = fixture();
        start.original_user = "missing:also-missing".to_owned();
        let target = TempDir::new().expect("target");
        let mut applier = FakeApplier::default();
        let mut capture = Capture::default();

        let artifacts = execute_conversion(
            input.path(),
            target.path(),
            &start,
            &mut applier,
            &mut capture,
        )
        .expect("a valid missing account name is preserved as unresolved");

        assert_eq!(
            artifacts.user_resolution,
            pocket_protocol::UserResolution::unresolved()
        );
        assert!(target.path().join(".pocket-generation.cbor").is_file());
        assert!(matches!(
            capture.0.last(),
            Some(BuilderMessage::AccountDb(_))
        ));
    }

    #[test]
    fn malformed_or_ambiguous_accounts_abort_conversion() {
        for (original_user, passwd) in [
            ("missing", "malformed\n"),
            (
                "7",
                concat!(
                    "first:x:7:8::/:/bin/false\n",
                    "second:x:7:9::/:/bin/false\n",
                ),
            ),
        ] {
            let (input, mut start) = fixture();
            start.original_user = original_user.to_owned();
            let target = TempDir::new().expect("target");
            let mut applier = FakeApplier {
                passwd: Some(passwd),
                ..FakeApplier::default()
            };
            let mut capture = Capture::default();

            assert!(
                execute_conversion(
                    input.path(),
                    target.path(),
                    &start,
                    &mut applier,
                    &mut capture,
                )
                .is_err(),
                "{original_user}",
            );
            assert!(!target.path().join(".pocket-generation.cbor").exists());
            assert!(capture.0.is_empty());
        }
    }

    #[test]
    fn dirty_target_fails_before_invoking_helper() {
        let (input, start) = fixture();
        let target = TempDir::new().expect("target");
        fs::create_dir(target.path().join("rootfs")).expect("dirty rootfs");
        let mut applier = FakeApplier::default();
        let mut capture = Capture::default();
        assert!(
            execute_conversion(
                input.path(),
                target.path(),
                &start,
                &mut applier,
                &mut capture,
            )
            .is_err()
        );
        assert!(applier.calls.is_empty());
    }

    #[test]
    fn formatter_lost_found_is_removed_but_dirty_contents_are_rejected() {
        let (input, start) = fixture();
        let target = TempDir::new().expect("target");
        fs::create_dir(target.path().join("lost+found")).expect("formatter directory");
        let mut applier = FakeApplier::default();
        let mut capture = Capture::default();
        execute_conversion(
            input.path(),
            target.path(),
            &start,
            &mut applier,
            &mut capture,
        )
        .expect("empty formatter directory is normalized");
        assert!(!target.path().join("lost+found").exists());

        let dirty_target = TempDir::new().expect("dirty target");
        fs::create_dir(dirty_target.path().join("lost+found")).expect("formatter directory");
        fs::write(dirty_target.path().join("lost+found/entry"), b"dirty").expect("dirty entry");
        let mut applier = FakeApplier::default();
        let mut capture = Capture::default();
        assert!(
            execute_conversion(
                input.path(),
                dirty_target.path(),
                &start,
                &mut applier,
                &mut capture,
            )
            .is_err()
        );
        assert!(applier.calls.is_empty());
    }

    #[test]
    fn fake_helper_failure_never_writes_marker_or_manifest() {
        let (input, start) = fixture();
        let target = TempDir::new().expect("target");
        let mut applier = FailingApplier;
        let mut capture = Capture::default();
        let error = execute_conversion(
            input.path(),
            target.path(),
            &start,
            &mut applier,
            &mut capture,
        );
        assert!(error.is_err());
        assert!(!target.path().join(".pocket-generation.cbor").exists());
        assert!(capture.0.is_empty());
    }

    #[test]
    fn umoci_image_argument_is_one_literal_argv_element() {
        let argument = image_argument(Path::new("/input"), "root").expect("argument");
        assert_eq!(argument, "/input:root");
        assert!(image_argument(Path::new("/input"), "other").is_err());
        let arguments = umoci_arguments(Path::new("/input"), "root", Path::new("/target/rootfs"))
            .expect("arguments");
        assert_eq!(
            arguments,
            ["raw", "unpack", "--image", "/input:root", "/target/rootfs"].map(OsString::from)
        );
    }
}
