//! The signing key loader against real files: the default location under the
//! fuz home, a caller's own path, and each way a key file can be unusable.
//!
//! The fuz home is redirected in-process through `fuz_home/test_home_override`
//! (edition 2024 forbids `set_var`), so every test holds [`SERIAL`] while its
//! home is the active one, and none reads the developer's `~/.fuz`.

#![expect(
    clippy::unwrap_used,
    reason = "test helpers outside `#[test]` fns panic on a failed setup or check"
)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};

use fuz_sign::{
    KeyError, KeyFileError, SigningKey, default_key_path, generate_keypair, load_signing_key,
    serialize_key_file,
};
use fuz_sys::secure_file::SecureFileError;

/// The home override is one per process.
static SERIAL: Mutex<()> = Mutex::new(());

const CREATED: &str = "2025-01-15T10:30:00Z";

/// A scratch fuz home, active until dropped.
struct Home {
    dir: tempfile::TempDir,
    _serial: MutexGuard<'static, ()>,
}

impl Home {
    fn new() -> Self {
        let serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        fuz_home::set_fuz_home_override_for_testing(dir.path().join("home"));
        Self {
            dir,
            _serial: serial,
        }
    }

    /// Where the default key belongs under this home.
    fn default_key(&self) -> PathBuf {
        self.dir
            .path()
            .join("home")
            .join("config")
            .join("signing.key")
    }

    /// A path under the scratch directory and outside the home.
    fn outside(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        fuz_home::clear_fuz_home_override_for_testing();
    }
}

/// Write `bytes` at `path` with `mode`, creating the directories above it.
fn write_file(path: &Path, bytes: &[u8], mode: u32) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, bytes).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// Write a fresh key file at `path` (mode 0600) and return its key.
fn write_key(path: &Path) -> SigningKey {
    let key = generate_keypair();
    write_file(path, &serialize_key_file(&key, CREATED), 0o600);
    key
}

#[test]
fn no_path_loads_the_key_in_the_config_directory() {
    let home = Home::new();
    assert_eq!(default_key_path().unwrap(), home.default_key());
    let key = write_key(&home.default_key());

    let loaded = load_signing_key(None).unwrap();
    assert_eq!(loaded.key.to_bytes(), key.to_bytes());
    assert_eq!(loaded.metadata.created, CREATED);
    assert_eq!(loaded.path, home.default_key());
}

#[test]
fn a_given_path_is_the_key_that_is_loaded() {
    let home = Home::new();
    // A different key sits at the default location: it is not the one read.
    let default = write_key(&home.default_key());
    let path = home.outside("elsewhere.key");
    let key = write_key(&path);
    assert_ne!(key.to_bytes(), default.to_bytes());

    let loaded = load_signing_key(Some(&path)).unwrap();
    assert_eq!(loaded.key.to_bytes(), key.to_bytes());
    assert_eq!(loaded.path, path);
}

/// The metadata returned is the loaded file's own: with a key at the default
/// location recording another time, a given path reports the time in the file
/// that was read.
#[test]
fn a_given_path_reports_its_own_metadata() {
    const OTHER_CREATED: &str = "2031-07-04T08:09:10Z";
    let home = Home::new();
    write_key(&home.default_key());
    let path = home.outside("elsewhere.key");
    let key = generate_keypair();
    write_file(&path, &serialize_key_file(&key, OTHER_CREATED), 0o600);

    let loaded = load_signing_key(Some(&path)).unwrap();
    assert_eq!(loaded.key.to_bytes(), key.to_bytes());
    assert_eq!(loaded.metadata.created, OTHER_CREATED);
}

/// A given path with no file is the error even when a usable key sits at the
/// default location: the default is never a fallback for a mistyped
/// `--key-file`.
#[test]
fn a_missing_given_path_does_not_fall_back_to_the_default_key() {
    let home = Home::new();
    write_key(&home.default_key());
    let absent = home.outside("absent.key");

    let error = load_signing_key(Some(&absent)).unwrap_err();
    assert!(
        matches!(
            &error,
            KeyFileError::Read { path, source: SecureFileError::NotFound(_) } if *path == absent
        ),
        "{error:?}"
    );
}

#[test]
fn a_missing_key_names_the_file_and_how_to_make_one() {
    let home = Home::new();
    for (given, tried) in [
        (None, home.default_key()),
        (Some(home.outside("absent.key")), home.outside("absent.key")),
    ] {
        let error = load_signing_key(given.as_deref()).unwrap_err();
        assert!(
            matches!(
                &error,
                KeyFileError::Read { path, source: SecureFileError::NotFound(_) } if *path == tried
            ),
            "{error:?}"
        );
        assert_eq!(
            error.to_string(),
            format!(
                "failed to read signing key file {0}: file not found: {0}",
                tried.display()
            )
        );
        assert_eq!(
            error.hint(),
            Some("create a signing key with `cargo xtask key generate` in the fuz workspace")
        );
    }
    // Looking for a key creates nothing: not the home, not its config directory.
    assert!(!home.dir.path().join("home").exists());
}

#[test]
fn a_key_file_open_to_others_is_refused_with_its_mode() {
    let home = Home::new();
    let path = home.default_key();
    write_key(&path);
    for mode in [0o644, 0o640, 0o604] {
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        let error = load_signing_key(None).unwrap_err();
        assert!(
            matches!(
                &error,
                KeyFileError::Read {
                    source: SecureFileError::InsecurePermissions(..),
                    ..
                }
            ),
            "{mode:o}: {error:?}"
        );
        assert_eq!(
            error.to_string(),
            format!(
                "failed to read signing key file {0}: insecure permissions on {0}: 100{mode:o} \
                 (expected 0600)",
                path.display()
            )
        );
        assert_eq!(
            error.hint(),
            Some("a signing key file is its owner's alone: `chmod 600` it")
        );
    }
    // Owner-only, read-only is a key file like any other.
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
    load_signing_key(None).unwrap();
}

#[test]
fn a_symlink_to_a_key_is_not_followed() {
    let home = Home::new();
    let real = home.outside("real.key");
    write_key(&real);
    let link = home.default_key();
    std::fs::create_dir_all(link.parent().unwrap()).unwrap();
    std::os::unix::fs::symlink(&real, &link).unwrap();

    let error = load_signing_key(None).unwrap_err();
    assert!(
        matches!(
            &error,
            KeyFileError::Read {
                source: SecureFileError::Symlink(_),
                ..
            }
        ),
        "{error:?}"
    );
    assert_eq!(error.hint(), None);
}

#[test]
fn a_file_that_is_not_a_key_file_says_what_is_wrong_with_it() {
    let home = Home::new();
    let path = home.outside("signing.key");

    write_file(&path, b"not a key file\n", 0o600);
    let error = load_signing_key(Some(&path)).unwrap_err();
    assert!(
        matches!(error, KeyFileError::Parse(KeyError::InvalidFormat)),
        "{error:?}"
    );
    assert_eq!(error.to_string(), KeyError::InvalidFormat.to_string());
    assert_eq!(error.hint(), KeyError::InvalidFormat.hint());

    // A blank line after the key: the common editor accident.
    let mut bytes = serialize_key_file(&generate_keypair(), CREATED).to_vec();
    bytes.push(b'\n');
    write_file(&path, &bytes, 0o600);
    let error = load_signing_key(Some(&path)).unwrap_err();
    assert!(
        matches!(error, KeyFileError::Parse(KeyError::TrailingContent)),
        "{error:?}"
    );
    assert_eq!(
        error.hint(),
        Some("Remove extra blank lines at end of key file")
    );
}
