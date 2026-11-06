//! Directory creation floored below a directory the caller owns.

use std::fs::DirBuilder;
use std::io;
use std::path::{Component, Path};

/// Create `path` and every missing directory between it and `base`, never
/// creating `base` itself or anything above it.
///
/// `std::fs::create_dir_all` creates every missing ancestor, so a writer
/// racing a removal of the tree it writes into puts the tree's root back: the
/// removal deletes `base`, the writer's next `create_dir_all` re-creates it,
/// and the tree outlives whoever removed it. This stops at `base`. A missing
/// `base` is the error the operating system gives for it (`NotFound`), so a
/// writer whose tree was removed fails instead of restoring it.
///
/// `mode` is the permission bits each created directory requests, before the
/// umask (`0o777` is what `create_dir_all` requests); it applies on Unix only.
/// `base` is checked with `metadata`, which follows a symlink, as
/// `create_dir_all` does for an existing ancestor.
///
/// Racing creators are fine: a directory another writer created first counts
/// as created, as it does for `create_dir_all`.
///
/// # Errors
///
/// - `NotFound` if `base` does not exist (or vanished part-way);
/// - `NotADirectory` if `base` exists but is not a directory;
/// - `InvalidInput` if `path` is not `base` or strictly below it through
///   normal components (`..`, `.`, a root or a prefix refuse), checked without
///   touching the filesystem;
/// - any other error from creating a directory, as `create_dir_all` reports it.
pub fn create_dir_all_below(base: &Path, path: &Path, mode: u32) -> io::Result<()> {
    // `starts_with` alone compares components without resolving them, so
    // `base/../x` would pass it and create `x` beside `base`: everything past
    // `base` must be a plain name.
    let below = path
        .strip_prefix(base)
        .is_ok_and(|rest| rest.components().all(|c| matches!(c, Component::Normal(_))));
    if !below {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the directory to create is not below the base directory",
        ));
    }
    let mut builder = DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = mode;
    create_below(&builder, base, path)
}

/// The recursion behind [`create_dir_all_below`]: `create_dir_all`'s shape
/// (try the directory, create the parent on `NotFound`, try again), with the
/// parent walk stopping at `base`, which is only ever checked.
fn create_below(builder: &DirBuilder, base: &Path, path: &Path) -> io::Result<()> {
    if path == base {
        return match std::fs::metadata(base) {
            Ok(meta) if meta.is_dir() => Ok(()),
            Ok(_) => Err(io::Error::new(
                io::ErrorKind::NotADirectory,
                "the base directory is not a directory",
            )),
            Err(source) => Err(source),
        };
    }
    match builder.create(path) {
        Ok(()) => return Ok(()),
        Err(source) if source.kind() == io::ErrorKind::NotFound => {}
        Err(_) if path.is_dir() => return Ok(()),
        Err(source) => return Err(source),
    }
    // `path` is strictly below `base` here, so it has a parent at or below it.
    let parent = path.parent().unwrap_or(base);
    create_below(builder, base, parent)?;
    match builder.create(path) {
        Ok(()) => Ok(()),
        Err(_) if path.is_dir() => Ok(()),
        Err(source) => Err(source),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_the_missing_directories_below_the_base() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("base");
        std::fs::create_dir(&base).unwrap();
        let path = base.join("a/b/c");
        create_dir_all_below(&base, &path, 0o755).unwrap();
        assert!(path.is_dir());
        // Existing directories, the base itself included, are fine.
        create_dir_all_below(&base, &path, 0o755).unwrap();
        create_dir_all_below(&base, &base, 0o755).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn applies_the_mode_to_each_created_directory() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path();
        create_dir_all_below(base, &base.join("a/b"), 0o700).unwrap();
        for rel in ["a", "a/b"] {
            let mode = std::fs::metadata(base.join(rel))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o700, "{rel}");
        }
    }

    /// The point of the floor: a removed base stays removed.
    #[test]
    fn a_missing_base_is_not_found_and_nothing_is_created() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("gone");
        for path in [base.clone(), base.join("a"), base.join("a/b/c")] {
            let err = create_dir_all_below(&base, &path, 0o755).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::NotFound, "{}", path.display());
            assert!(!base.exists(), "{}", path.display());
        }
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[test]
    fn a_base_that_is_a_file_is_not_a_directory() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("file");
        std::fs::write(&base, b"x").unwrap();
        let err = create_dir_all_below(&base, &base, 0o755).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotADirectory);
    }

    #[test]
    fn a_path_outside_the_base_is_refused_without_touching_the_disk() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("base");
        std::fs::create_dir(&base).unwrap();
        for outside in [dir.path().join("elsewhere/x"), base.join("../elsewhere")] {
            let err = create_dir_all_below(&base, &outside, 0o755).unwrap_err();
            assert_eq!(
                err.kind(),
                io::ErrorKind::InvalidInput,
                "{}",
                outside.display()
            );
            assert!(
                !dir.path().join("elsewhere").exists(),
                "{}",
                outside.display()
            );
        }
    }
}
