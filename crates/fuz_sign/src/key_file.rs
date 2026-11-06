//! The signing key file: where it lives by default, and how a producer loads
//! it.
//!
//! The commands that read the signing key — `cargo xtask publish`,
//! `cargo xtask release-log`, `cargo xtask key info` / `export`, and
//! `fuzf tool publish` — resolve it here: the path the caller names, or
//! `signing.key` in the fuz config directory. The read is
//! `fuz_sys::secure_file::load_secure_file` (no symlink, a regular file, owner
//! access only, bounded) and the parse is [`parse_key_file`].

use std::fmt;
use std::path::{Path, PathBuf};

use ed25519_dalek::SigningKey;
use fuz_home::{FuzHomeError, get_config_dir};
use fuz_sys::secure_file::{SecureFileError, load_secure_file};
use thiserror::Error;

use crate::error::KeyError;
use crate::key::{KeyMetadata, parse_key_file};

/// The signing key's file name in the fuz config directory.
const DEFAULT_KEY_FILE: &str = "signing.key";

/// A signing key read from its file.
pub struct LoadedSigningKey {
    /// The private key.
    pub key: SigningKey,
    /// What the file records beside the key.
    pub metadata: KeyMetadata,
    /// The file it was read from: the caller's path as given, or the default.
    pub path: PathBuf,
}

impl fmt::Debug for LoadedSigningKey {
    /// Names the file and nothing of the key.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoadedSigningKey")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

/// Why the signing key could not be loaded.
#[derive(Debug, Error)]
pub enum KeyFileError {
    /// No path was given and the fuz config directory, which holds the default
    /// key, cannot be resolved.
    #[error("failed to resolve fuz config directory: {0}")]
    ConfigDir(#[source] FuzHomeError),

    /// The key file could not be read: absent, a symlink, not a regular file,
    /// open to another user, too large, or an I/O failure.
    #[error("failed to read signing key file {}: {source}", .path.display())]
    Read {
        /// The file that was tried.
        path: PathBuf,
        #[source]
        source: SecureFileError,
    },

    /// The file was read and is not a key file.
    #[error(transparent)]
    Parse(#[from] KeyError),
}

impl KeyFileError {
    /// User-facing hint for how to fix the error, where there is one.
    pub const fn hint(&self) -> Option<&'static str> {
        match self {
            Self::ConfigDir(e) => e.hint(),
            Self::Read { source, .. } => match source {
                SecureFileError::NotFound(_) => Some(
                    "create a signing key with `cargo xtask key generate` in the fuz workspace",
                ),
                SecureFileError::InsecurePermissions(..) => {
                    Some("a signing key file is its owner's alone: `chmod 600` it")
                }
                SecureFileError::Symlink(_)
                | SecureFileError::FileTooLarge(..)
                | SecureFileError::NotRegularFile(_)
                | SecureFileError::Io(..) => None,
            },
            Self::Parse(e) => e.hint(),
        }
    }
}

/// Where the signing key lives when no path is given: `signing.key` in the fuz
/// config directory.
///
/// # Errors
///
/// [`KeyFileError::ConfigDir`] when the fuz home cannot be resolved.
pub fn default_key_path() -> Result<PathBuf, KeyFileError> {
    Ok(get_config_dir()
        .map_err(KeyFileError::ConfigDir)?
        .join(DEFAULT_KEY_FILE))
}

/// Load the signing key from `path`, or from [`default_key_path`] when `path`
/// is `None`.
///
/// A given path is used as it is: the fuz home is not resolved, so it does not
/// have to be resolvable.
///
/// # Errors
///
/// [`KeyFileError`]: the default location cannot be resolved, the file cannot
/// be read, or it is not a key file.
pub fn load_signing_key(path: Option<&Path>) -> Result<LoadedSigningKey, KeyFileError> {
    let path = match path {
        Some(path) => path.to_path_buf(),
        None => default_key_path()?,
    };
    let bytes = match load_secure_file(&path) {
        Ok(bytes) => bytes,
        Err(source) => return Err(KeyFileError::Read { path, source }),
    };
    let (key, metadata) = parse_key_file(&bytes)?;
    Ok(LoadedSigningKey {
        key,
        metadata,
        path,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_error_keeps_its_cause_in_the_message() {
        let config = KeyFileError::ConfigDir(FuzHomeError::RelativeFuzHome {
            path: PathBuf::from("relhome"),
        });
        assert_eq!(
            config.to_string(),
            format!(
                "failed to resolve fuz config directory: {}",
                FuzHomeError::RelativeFuzHome {
                    path: PathBuf::from("relhome"),
                }
            )
        );

        let read = KeyFileError::Read {
            path: PathBuf::from("/keys/signing.key"),
            source: SecureFileError::InsecurePermissions(
                PathBuf::from("/keys/signing.key"),
                0o100_644,
            ),
        };
        assert_eq!(
            read.to_string(),
            "failed to read signing key file /keys/signing.key: \
             insecure permissions on /keys/signing.key: 100644 (expected 0600)"
        );

        let parse = KeyFileError::from(KeyError::TrailingContent);
        assert_eq!(parse.to_string(), KeyError::TrailingContent.to_string());
    }

    #[test]
    fn hints_come_from_the_layer_that_failed() {
        // The home layer's own hint, for either way the home is unusable.
        let relative = FuzHomeError::RelativeFuzHome {
            path: PathBuf::from("relhome"),
        };
        let expected = relative.hint();
        assert!(expected.is_some());
        assert_eq!(KeyFileError::ConfigDir(relative).hint(), expected);

        // The key parser's own hint.
        assert_eq!(
            KeyFileError::from(KeyError::PublicKeyMismatch).hint(),
            KeyError::PublicKeyMismatch.hint()
        );
        assert!(KeyError::PublicKeyMismatch.hint().is_some());

        // A read failure: what to do depends on what is at the path.
        let read = |source| KeyFileError::Read {
            path: PathBuf::from("/k"),
            source,
        };
        let path = || PathBuf::from("/k");
        assert_eq!(
            read(SecureFileError::NotFound(path())).hint(),
            Some("create a signing key with `cargo xtask key generate` in the fuz workspace")
        );
        assert_eq!(
            read(SecureFileError::InsecurePermissions(path(), 0o644)).hint(),
            Some("a signing key file is its owner's alone: `chmod 600` it")
        );
        for unhinted in [
            SecureFileError::Symlink(path()),
            SecureFileError::FileTooLarge(path(), 2, 1),
            SecureFileError::NotRegularFile(path()),
            SecureFileError::Io(path(), std::io::Error::other("disk")),
        ] {
            let description = unhinted.to_string();
            assert_eq!(read(unhinted).hint(), None, "{description}");
        }
    }

    #[test]
    fn debug_of_a_loaded_key_names_only_the_file() {
        let loaded = LoadedSigningKey {
            key: crate::generate_keypair(),
            metadata: KeyMetadata {
                created: "2025-01-15T10:30:00Z".to_string(),
            },
            path: PathBuf::from("/keys/signing.key"),
        };
        assert_eq!(
            format!("{loaded:?}"),
            "LoadedSigningKey { path: \"/keys/signing.key\", .. }"
        );
    }
}
