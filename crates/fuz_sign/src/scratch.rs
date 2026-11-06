//! A private scratch directory for the files a producer flow stages on disk.
//!
//! A publish packs its tarball to a file before uploading it, and a backfill
//! downloads each tarball and flat binary to a file to hash it. Each stages
//! that file inside a [`ScratchDir`]: a fresh directory of its own (mode
//! 0700), removed with everything in it when the value is dropped — so the
//! file goes whenever the flow returns, by an early `?` as much as at its end,
//! with no removal to remember at each one. A process that is killed or
//! aborts runs no destructor and leaves the directory.

use std::os::unix::fs::DirBuilderExt as _;
use std::path::{Path, PathBuf};

use fuz_sys::fs::CleanupGuard;
use fuz_sys::rand::random_hex_suffix;

/// Mode of a scratch directory: its owner's alone, whatever the umask.
const SCRATCH_DIR_MODE: u32 = 0o700;

/// A scratch directory that could not be created.
#[derive(Debug)]
pub struct ScratchError {
    /// The directory that was to be created.
    pub path: PathBuf,
    pub source: std::io::Error,
}

/// A fresh directory, removed recursively when dropped.
#[derive(Debug)]
pub struct ScratchDir {
    dir: PathBuf,
    _guard: CleanupGuard,
}

impl ScratchDir {
    /// Create `<prefix>-<random>` under the system temp directory.
    pub fn new(prefix: &str) -> Result<Self, ScratchError> {
        Self::new_in(&std::env::temp_dir(), prefix)
    }

    /// Create `<prefix>-<random>` under `root`, which must exist. The random
    /// suffix keeps concurrent flows apart; an existing entry of that name is
    /// an error, never adopted.
    pub fn new_in(root: &Path, prefix: &str) -> Result<Self, ScratchError> {
        let dir = root.join(format!("{prefix}-{}", random_hex_suffix()));
        match std::fs::DirBuilder::new()
            .mode(SCRATCH_DIR_MODE)
            .create(&dir)
        {
            Ok(()) => Ok(Self {
                _guard: CleanupGuard::new(dir.clone()),
                dir,
            }),
            Err(source) => Err(ScratchError { path: dir, source }),
        }
    }

    /// The path of `name` inside the directory. Nothing is created.
    pub fn file(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn scratch_is_private_and_removed_on_drop() {
        let root = tempfile::tempdir().unwrap();
        let scratch = ScratchDir::new_in(root.path(), "fuz-test").unwrap();
        let file = scratch.file("staged");
        let dir = file.parent().unwrap().to_path_buf();
        assert_eq!(dir.parent().unwrap(), root.path());
        assert!(
            dir.file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("fuz-test-")
        );
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode();
        // Owner-only whatever the umask grants: the mode is asked for, and a
        // umask only narrows it.
        assert_eq!(mode & 0o077, 0, "{mode:o}");
        assert!(!file.exists(), "naming a file creates nothing");
        std::fs::write(&file, b"binary").unwrap();
        drop(scratch);
        assert!(!dir.exists());
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
    }

    #[test]
    fn two_scratch_directories_under_one_root_are_distinct() {
        let root = tempfile::tempdir().unwrap();
        let a = ScratchDir::new_in(root.path(), "fuz-test").unwrap();
        let b = ScratchDir::new_in(root.path(), "fuz-test").unwrap();
        assert_ne!(a.file("x"), b.file("x"));
        drop(a);
        assert!(b.file("x").parent().unwrap().is_dir());
    }

    #[test]
    fn a_root_that_is_not_there_is_an_error_naming_the_directory() {
        let root = tempfile::tempdir().unwrap();
        let missing = root.path().join("absent");
        let error = ScratchDir::new_in(&missing, "fuz-test").unwrap_err();
        assert!(error.path.starts_with(&missing), "{:?}", error.path);
        assert_eq!(error.source.kind(), std::io::ErrorKind::NotFound);
        assert!(!missing.exists());
    }

    #[test]
    fn the_default_root_is_the_system_temp_directory() {
        let scratch = ScratchDir::new("fuz-test").unwrap();
        let file = scratch.file("x");
        let dir = file.parent().unwrap().to_path_buf();
        assert_eq!(dir.parent().unwrap(), std::env::temp_dir());
        drop(scratch);
        assert!(!dir.exists());
    }
}
