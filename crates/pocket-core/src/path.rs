use std::path::{Path, PathBuf};

use thiserror::Error;

use crate::{CodedError, ErrorCode};

/// Keeps managed paths comfortably below UML's tighter command-line and
/// Unix-socket path consumers. Profile-specific code may impose a lower cap.
pub const MAX_MANAGED_UML_PATH_BYTES: usize = 192;

/// A managed root must name at least three components below `/`.
///
/// This rejects filesystem roots and broad locations such as `/tmp`, `/var`,
/// `/home/user`, or `/run/user` as operation-owned cleanup targets.
pub const MIN_MANAGED_UML_PATH_COMPONENTS: usize = 3;

/// An absolute, normalized, narrowly scoped path safe for UML command-line
/// grammars.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ManagedUmlPath(PathBuf);

impl ManagedUmlPath {
    /// Validate and own a managed UML path.
    pub fn new(path: impl AsRef<Path>) -> Result<Self, ManagedUmlPathError> {
        let path = path.as_ref();
        if !path.is_absolute() {
            return Err(ManagedUmlPathError::NotAbsolute);
        }

        let Some(text) = path.to_str() else {
            return Err(ManagedUmlPathError::NotUtf8);
        };

        if text.len() > MAX_MANAGED_UML_PATH_BYTES {
            return Err(ManagedUmlPathError::TooLong {
                actual: text.len(),
                maximum: MAX_MANAGED_UML_PATH_BYTES,
            });
        }
        if text.chars().any(char::is_whitespace) {
            return Err(ManagedUmlPathError::ContainsWhitespace);
        }
        if let Some(character) = text
            .chars()
            .find(|character| matches!(character, ',' | ':' | '\0'))
        {
            return Err(ManagedUmlPathError::ContainsReservedCharacter { character });
        }

        let Some(relative) = text.strip_prefix('/') else {
            return Err(ManagedUmlPathError::NotAbsolute);
        };
        if relative.is_empty() {
            return Err(ManagedUmlPathError::TooBroad {
                components: 0,
                minimum: MIN_MANAGED_UML_PATH_COMPONENTS,
            });
        }
        let segments: Vec<&str> = relative.split('/').collect();
        if segments
            .iter()
            .any(|segment| segment.is_empty() || matches!(*segment, "." | ".."))
        {
            return Err(ManagedUmlPathError::NotNormalized);
        }
        if segments.len() < MIN_MANAGED_UML_PATH_COMPONENTS {
            return Err(ManagedUmlPathError::TooBroad {
                components: segments.len(),
                minimum: MIN_MANAGED_UML_PATH_COMPONENTS,
            });
        }

        Ok(Self(path.to_path_buf()))
    }

    #[must_use]
    pub fn as_path(&self) -> &Path {
        &self.0
    }

    #[must_use]
    pub fn into_path_buf(self) -> PathBuf {
        self.0
    }

    /// Append one safe leaf component and revalidate the complete path.
    pub fn join_component(&self, component: &str) -> Result<Self, ManagedUmlPathError> {
        if component.is_empty() || component.contains('/') || matches!(component, "." | "..") {
            return Err(ManagedUmlPathError::NotNormalized);
        }
        Self::new(self.0.join(component))
    }
}

impl AsRef<Path> for ManagedUmlPath {
    fn as_ref(&self) -> &Path {
        self.as_path()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ManagedUmlPathError {
    #[error("managed UML path must be absolute")]
    NotAbsolute,
    #[error("managed UML path must be valid UTF-8")]
    NotUtf8,
    #[error("managed UML path contains whitespace")]
    ContainsWhitespace,
    #[error("managed UML path contains reserved character {character:?}")]
    ContainsReservedCharacter { character: char },
    #[error("managed UML path is not in normalized lexical form")]
    NotNormalized,
    #[error("managed UML path has only {components} components; at least {minimum} are required")]
    TooBroad { components: usize, minimum: usize },
    #[error("managed UML path is {actual} bytes; maximum is {maximum}")]
    TooLong { actual: usize, maximum: usize },
}

impl CodedError for ManagedUmlPathError {
    fn code(&self) -> ErrorCode {
        match self {
            Self::NotAbsolute => ErrorCode::PathNotAbsolute,
            Self::NotUtf8 => ErrorCode::PathNotUtf8,
            Self::ContainsWhitespace => ErrorCode::PathContainsWhitespace,
            Self::ContainsReservedCharacter { .. } => ErrorCode::PathContainsReservedCharacter,
            Self::NotNormalized => ErrorCode::PathNotNormalized,
            Self::TooBroad { .. } => ErrorCode::PathTooBroad,
            Self::TooLong { .. } => ErrorCode::PathTooLong,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use crate::{CodedError, ErrorCode};

    use super::{MAX_MANAGED_UML_PATH_BYTES, ManagedUmlPath, ManagedUmlPathError};

    #[test]
    fn accepts_a_narrow_absolute_path_and_safe_child() {
        let path = match ManagedUmlPath::new("/run/user/1000/pocket/run-a1") {
            Ok(path) => path,
            Err(error) => panic!("valid managed path rejected: {error}"),
        };
        assert_eq!(path.as_path(), Path::new("/run/user/1000/pocket/run-a1"));

        let child = match path.join_component("uml") {
            Ok(path) => path,
            Err(error) => panic!("valid child rejected: {error}"),
        };
        assert_eq!(
            child.as_path(),
            Path::new("/run/user/1000/pocket/run-a1/uml")
        );
    }

    #[test]
    fn rejects_relative_reserved_and_non_normalized_paths() {
        let cases = [
            "relative/path/leaf",
            "/tmp/pocket/run id",
            "/tmp/pocket/run,id",
            "/tmp/pocket/run:id",
            "/tmp//pocket/run",
            "/tmp/pocket/../run",
            "/tmp/pocket/./run",
            "/tmp/pocket/run/",
        ];
        for case in cases {
            assert!(ManagedUmlPath::new(case).is_err(), "accepted {case:?}");
        }
    }

    #[test]
    fn rejects_broad_roots() {
        for case in ["/", "/tmp", "/var/lib", "/home/user"] {
            let result = ManagedUmlPath::new(case);
            assert!(
                matches!(result, Err(ManagedUmlPathError::TooBroad { .. })),
                "unexpected result for {case:?}: {result:?}"
            );
        }
    }

    #[test]
    fn rejects_paths_over_the_fixed_cap() {
        let path = format!("/tmp/pocket/{}", "x".repeat(MAX_MANAGED_UML_PATH_BYTES));
        let result = ManagedUmlPath::new(path);
        assert!(matches!(result, Err(ManagedUmlPathError::TooLong { .. })));
    }

    #[test]
    fn errors_have_stable_codes() {
        assert_eq!(
            ManagedUmlPath::new("relative")
                .err()
                .map(|error| error.code()),
            Some(ErrorCode::PathNotAbsolute)
        );
        assert_eq!(
            ManagedUmlPath::new("/tmp/pocket/run:id")
                .err()
                .map(|error| error.code()),
            Some(ErrorCode::PathContainsReservedCharacter)
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_non_utf8_paths() {
        use std::{ffi::OsString, os::unix::ffi::OsStringExt, path::PathBuf};

        let path = PathBuf::from(OsString::from_vec(vec![
            b'/', b't', b'm', b'p', b'/', b'p', b'k', b'/', 0xff,
        ]));
        assert!(matches!(
            ManagedUmlPath::new(path),
            Err(ManagedUmlPathError::NotUtf8)
        ));
    }
}
