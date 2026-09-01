use std::{
    fs::{self, File},
    io::Read,
    path::Path,
    process::{Command, Stdio},
};

use pocket_protocol::ToolIdentity;
use sha2::{Digest as _, Sha256};

use crate::BuilderError;

pub const UMOCI_PATH: &str = "/usr/bin/umoci";
const MAX_TOOL_BYTES: u64 = 256 * 1024 * 1024;
const MAX_VERSION_BYTES: usize = 4096;

/// Measure the exact helper artifact and its pinned CLI identity before the
/// host is allowed to send `BUILD_START`.
pub fn inspect_umoci(path: &Path) -> Result<ToolIdentity, BuilderError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| BuilderError::io("inspect-tool", error))?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_TOOL_BYTES {
        return Err(BuilderError::contract(
            "inspect-tool",
            "umoci is not a bounded plain executable file",
        ));
    }
    let mut file = File::open(path).map_err(|error| BuilderError::io("inspect-tool", error))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| BuilderError::io("inspect-tool", error))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }

    let mut child = Command::new(path)
        .arg("--version")
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| {
            BuilderError::tool("inspect-tool", error.raw_os_error(), error.to_string())
        })?;
    let mut output = Vec::new();
    let stdout = child.stdout.take().ok_or_else(|| {
        BuilderError::tool("inspect-tool", None, "umoci version stdout pipe is missing")
    })?;
    let mut limited = stdout.take((MAX_VERSION_BYTES + 1) as u64);
    limited.read_to_end(&mut output).map_err(|error| {
        BuilderError::tool("inspect-tool", error.raw_os_error(), error.to_string())
    })?;
    if output.len() > MAX_VERSION_BYTES {
        let _ = child.kill();
        let _ = child.wait();
        return Err(BuilderError::tool(
            "inspect-tool",
            None,
            "umoci --version output exceeds hard cap",
        ));
    }
    let status = child.wait().map_err(|error| {
        BuilderError::tool("inspect-tool", error.raw_os_error(), error.to_string())
    })?;
    if !status.success() {
        return Err(BuilderError::tool(
            "inspect-tool",
            None,
            format!("umoci --version exited with {status}"),
        ));
    }
    let version = std::str::from_utf8(&output)
        .map_err(|_| BuilderError::tool("inspect-tool", None, "version output is not UTF-8"))?
        .trim()
        .to_owned();
    if version.is_empty() || version.contains('\0') {
        return Err(BuilderError::tool(
            "inspect-tool",
            None,
            "version output is empty or contains NUL",
        ));
    }

    Ok(ToolIdentity {
        role: "umoci".to_owned(),
        sha256: hex_lower(&hasher.finalize()),
        version,
    })
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt};

    use tempfile::TempDir;

    use super::inspect_umoci;

    #[test]
    fn measures_fake_helper_without_a_shell_command_line() {
        let temp = TempDir::new().expect("tempdir");
        let helper = temp.path().join("umoci-fixture");
        fs::write(&helper, b"#!/bin/sh\nprintf 'umoci fixture 1.0\\n'\n").expect("helper");
        let mut permissions = fs::metadata(&helper).expect("metadata").permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&helper, permissions).expect("permissions");
        let identity = inspect_umoci(&helper).expect("identity");
        assert_eq!(identity.role, "umoci");
        assert_eq!(identity.version, "umoci fixture 1.0");
        assert_eq!(identity.sha256.len(), 64);
    }
}
