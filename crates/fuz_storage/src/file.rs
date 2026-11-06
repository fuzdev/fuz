//! Local filesystem storage backend

use std::path::{Path, PathBuf};

use fuz_sys::rand::random_hex_suffix;

use crate::Storage;
use crate::error::{StorageBackendKind, StorageError};
use crate::key::{validate_forge_key, validate_list_prefix};

/// Expand a leading `~` in a storage root against the home directory
/// (`fuz_sys::home_dir` in production, injected in tests).
///
/// A `~` root with an unusable home (empty, relative, or not found) is
/// refused rather than left as a literal `~/…` under the process cwd, which
/// the first upload would then create. Any other root is used as given,
/// without consulting the home.
fn expand_root(
    path: &Path,
    home_dir: impl FnOnce() -> Result<PathBuf, fuz_sys::HomeDirError>,
) -> Result<PathBuf, StorageError> {
    fuz_sys::expand_tilde_checked(&path.to_string_lossy(), home_dir).map_err(|reason| {
        StorageError::InvalidConfig {
            message: format!("cannot expand `~` in the local storage path: {reason}"),
        }
    })
}

/// Local filesystem storage backend.
///
/// Uses `tokio::fs` for async I/O and atomic writes via temp file + rename.
#[derive(Debug)]
pub struct FileStorage {
    root: PathBuf,
}

impl FileStorage {
    /// A `FileStorage` rooted at `path`, which need not exist yet.
    ///
    /// Changes nothing on disk: naming a store never creates it. The root
    /// comes into being with the first upload (`upload` / `upload_file` create
    /// the key's parent directories), so only a writer ever creates a store;
    /// until then reads answer as for any missing key (`NotFound`, `exists` →
    /// `false`, an empty `list`). A caller that should refuse a missing root
    /// outright opens it with [`FileStorage::open_existing`].
    ///
    /// A root that could never become a store is refused here, as
    /// [`StorageError::LocalRootNotDir`], rather than by the first upload —
    /// which for a publish comes after the packing and the signing: something
    /// at the path that is not a directory (a file, a dangling symlink; a
    /// symlink to a directory is one), or a parent of it that is not one.
    ///
    /// Expands `~` to the home directory (see `expand_root`).
    pub fn new(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        let root = expand_root(path.as_ref(), fuz_sys::home_dir)?;
        if root_is_occupied(&root) {
            return Err(StorageError::LocalRootNotDir);
        }
        Ok(Self { root })
    }

    /// Open an existing directory as storage.
    ///
    /// A path that is not a directory — missing, or something else — is
    /// [`StorageError::LocalRootNotDir`], so a mistyped location is an error
    /// rather than a store with nothing in it. Like [`FileStorage::new`], it
    /// creates nothing. Expands `~` to the home directory (see `expand_root`).
    ///
    /// The error does not repeat the path, so it can be shown where the path
    /// itself must not be.
    pub fn open_existing(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        let root = expand_root(path.as_ref(), fuz_sys::home_dir)?;
        if !root.is_dir() {
            return Err(StorageError::LocalRootNotDir);
        }
        Ok(Self { root })
    }

    /// The path a key names: the key validated ([`validate_forge_key`], the
    /// contract every backend shares), then joined onto the root.
    ///
    /// The one place a key becomes a path, so no key names a path outside the
    /// root: an absolute key would replace the root in the join, and a `..`
    /// segment would climb out of it. Where that path leads is the tree's
    /// business — a symlink under the root is followed.
    fn resolve(&self, key: &str) -> Result<PathBuf, StorageError> {
        validate_forge_key(key)?;
        Ok(self.root.join(key))
    }
}

/// Whether `root` is taken by something a store could never be created at:
/// a non-directory at the path itself (following a symlink, so a dangling one
/// counts and one to a directory does not), or a non-directory where one of
/// its parents should be.
///
/// A root that is simply not there is free, and so is one whose state cannot
/// be read (a parent without search permission): the first upload reports
/// that with its own error.
fn root_is_occupied(root: &Path) -> bool {
    match std::fs::metadata(root) {
        Ok(meta) => !meta.is_dir(),
        // Nothing reachable through the path. A symlink at the path itself
        // means it dangles: an upload would fail on it rather than replace it.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => root.is_symlink(),
        Err(e) => e.kind() == std::io::ErrorKind::NotADirectory,
    }
}

impl Storage for FileStorage {
    fn backend_kind(&self) -> StorageBackendKind {
        StorageBackendKind::File
    }

    async fn upload(&self, path: &str, data: &[u8]) -> Result<(), StorageError> {
        let dest = self.resolve(path)?;

        // Create parent directories
        if let Some(parent) = dest.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|e| StorageError::Io(StorageBackendKind::File, e))?;
        }

        // Atomic write: temp file in same directory + rename. The random
        // suffix keeps concurrent writers of the same key from clobbering each
        // other's temp.
        let temp_path = temp_sibling(&dest);

        // Write to temp file
        tokio::fs::write(&temp_path, data)
            .await
            .map_err(|e| StorageError::UploadFailed {
                backend: StorageBackendKind::File,
                message: format!("write failed: {e}"),
            })?;

        // Atomic rename
        tokio::fs::rename(&temp_path, &dest)
            .await
            .map_err(|e| StorageError::UploadFailed {
                backend: StorageBackendKind::File,
                message: format!("rename failed: {e}"),
            })?;

        Ok(())
    }

    async fn download(&self, path: &str) -> Result<Vec<u8>, StorageError> {
        let src = self.resolve(path)?;

        match tokio::fs::read(&src).await {
            Ok(data) => Ok(data),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(StorageError::NotFound {
                backend: StorageBackendKind::File,
                path: path.to_string(),
            }),
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                Err(StorageError::PermissionDenied {
                    backend: StorageBackendKind::File,
                    path: path.to_string(),
                })
            }
            Err(e) => Err(StorageError::DownloadFailed {
                backend: StorageBackendKind::File,
                message: e.to_string(),
            }),
        }
    }

    async fn download_capped(&self, path: &str, max: u64) -> Result<Vec<u8>, StorageError> {
        use tokio::io::AsyncReadExt;

        let src = self.resolve(path)?;
        let failed = |e: std::io::Error| match e.kind() {
            std::io::ErrorKind::NotFound => StorageError::NotFound {
                backend: StorageBackendKind::File,
                path: path.to_string(),
            },
            std::io::ErrorKind::PermissionDenied => StorageError::PermissionDenied {
                backend: StorageBackendKind::File,
                path: path.to_string(),
            },
            _ => StorageError::DownloadFailed {
                backend: StorageBackendKind::File,
                message: e.to_string(),
            },
        };
        let too_large = |size| StorageError::TooLarge {
            backend: StorageBackendKind::File,
            path: path.to_string(),
            size,
            max,
        };

        // Without blocking, and a regular file only: a plain open of a FIFO
        // would wait for a writer that may never come, and a device has no
        // size to bound.
        let (file, meta) = fuz_sys::secure_file::open_regular_nonblocking(&src).map_err(failed)?;
        let file = tokio::fs::File::from_std(file);
        // Refused on the size alone, before a byte is read.
        let size = meta.len();
        if size > max {
            return Err(too_large(size));
        }
        // One byte past the limit, so a file that grew after the check is
        // refused rather than truncated.
        let mut data = Vec::new();
        file.take(max.saturating_add(1))
            .read_to_end(&mut data)
            .await
            .map_err(failed)?;
        if data.len() as u64 > max {
            return Err(too_large(data.len() as u64));
        }
        Ok(data)
    }

    async fn upload_file(&self, path: &str, src: &Path) -> Result<(), StorageError> {
        let dest = self.resolve(path)?;
        if let Some(parent) = dest.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|e| StorageError::Io(StorageBackendKind::File, e))?;
        }
        // Stream the copy to a temp file in the same dir, then atomic-rename —
        // mirrors `upload`'s atomicity without buffering the whole file. The
        // random suffix avoids concurrent same-key temp collisions.
        let temp_path = temp_sibling(&dest);
        tokio::fs::copy(src, &temp_path)
            .await
            .map_err(|e| StorageError::UploadFailed {
                backend: StorageBackendKind::File,
                message: format!("copy failed: {e}"),
            })?;
        tokio::fs::rename(&temp_path, &dest)
            .await
            .map_err(|e| StorageError::UploadFailed {
                backend: StorageBackendKind::File,
                message: format!("rename failed: {e}"),
            })?;
        Ok(())
    }

    async fn download_to_file(&self, path: &str, dest: &Path) -> Result<u64, StorageError> {
        let src = self.resolve(path)?;
        // `tokio::fs::copy` streams through an internal buffer — bounded memory,
        // never the whole file in RAM.
        match tokio::fs::copy(&src, dest).await {
            Ok(n) => Ok(n),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(StorageError::NotFound {
                backend: StorageBackendKind::File,
                path: path.to_string(),
            }),
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                Err(StorageError::PermissionDenied {
                    backend: StorageBackendKind::File,
                    path: path.to_string(),
                })
            }
            Err(e) => {
                // Past the open phase `copy` has already created+truncated
                // `dest`, so a mid-stream failure (read/write error, ENOSPC)
                // leaves a truncated file behind — unlink it (best-effort) so
                // the caller never sees a partial download. (NotFound /
                // PermissionDenied fail at open, before `dest` is touched, so
                // those arms leave a pre-existing `dest` intact.)
                let _ = tokio::fs::remove_file(dest).await;
                Err(StorageError::DownloadFailed {
                    backend: StorageBackendKind::File,
                    message: e.to_string(),
                })
            }
        }
    }

    async fn exists(&self, path: &str) -> Result<bool, StorageError> {
        let full_path = self.resolve(path)?;
        match tokio::fs::metadata(&full_path).await {
            Ok(_) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(StorageError::Io(StorageBackendKind::File, e)),
        }
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>, StorageError> {
        // Held to the key contract before it is joined onto the root: the
        // prefix names the directory read below.
        validate_list_prefix(prefix)?;
        let mut results = Vec::new();
        let search_path = if prefix.is_empty() {
            self.root.clone()
        } else {
            self.root.join(prefix)
        };

        // If prefix points to a specific directory, list its contents
        // If prefix is a file prefix, list parent and filter
        //
        // The empty prefix and one ending in `/` always name a directory,
        // there or not: read as a file prefix, a directory that does not
        // exist would list its parent for the files that share its name —
        // for the root, the files beside the store; for `tools/fuzd/`, a
        // `tools/fuzd.bak`.
        let is_directory = prefix.is_empty() || prefix.ends_with('/') || search_path.is_dir();
        let (dir_to_list, file_prefix) = if is_directory {
            (search_path, String::new())
        } else {
            let parent = search_path.parent().unwrap_or(&self.root);
            let prefix_name = search_path
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_default();
            (parent.to_path_buf(), prefix_name)
        };

        let mut read_dir = match tokio::fs::read_dir(&dir_to_list).await {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(results),
            Err(e) => return Err(StorageError::Io(StorageBackendKind::File, e)),
        };

        while let Some(entry) = read_dir
            .next_entry()
            .await
            .map_err(|e| StorageError::Io(StorageBackendKind::File, e))?
        {
            let name = entry.file_name().to_string_lossy().to_string();

            // Filter by prefix if provided
            if !file_prefix.is_empty() && !name.starts_with(&file_prefix) {
                continue;
            }

            // Only include files (not directories)
            let metadata = entry
                .metadata()
                .await
                .map_err(|e| StorageError::Io(StorageBackendKind::File, e))?;
            if metadata.is_file() {
                // Return the path relative to the root, whichever form the
                // prefix took: a key a caller can hand straight back to
                // `download`, as the other backends return.
                let parent_rel = dir_to_list
                    .strip_prefix(&self.root)
                    .ok()
                    .and_then(|p| p.to_str())
                    .unwrap_or("");
                let relative = if parent_rel.is_empty() {
                    name
                } else {
                    format!("{parent_rel}/{name}")
                };
                results.push(relative);
            }
        }

        results.sort();
        Ok(results)
    }

    async fn delete(&self, path: &str) -> Result<(), StorageError> {
        let full_path = self.resolve(path)?;
        match tokio::fs::remove_file(&full_path).await {
            Ok(()) => Ok(()),
            // No error if file doesn't exist
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(StorageError::Io(StorageBackendKind::File, e)),
        }
    }
}

//
// Helper functions
//

/// A collision-resistant temp path next to `dest` (same directory, so the
/// subsequent `rename` into `dest` is atomic). The random suffix keeps two
/// concurrent writers of the same key from sharing — and clobbering — a temp.
fn temp_sibling(dest: &Path) -> PathBuf {
    let file_name = dest
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    dest.with_file_name(format!("{file_name}.{}.tmp", random_hex_suffix()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use fuz_sys::HomeDirError;

    /// A `~` root expands against a usable home and is refused, with the
    /// reason, against an unusable one — never left as a literal `~/…` under
    /// the cwd. Other roots never consult the home.
    #[test]
    fn expand_root_refuses_a_tilde_root_without_a_usable_home() {
        assert_eq!(
            expand_root(Path::new("~/store"), || Ok(PathBuf::from("/home/u"))).unwrap(),
            PathBuf::from("/home/u/store")
        );
        for reason in [
            HomeDirError::NotFound,
            HomeDirError::Empty,
            HomeDirError::Relative {
                path: PathBuf::from("h"),
            },
        ] {
            for root in ["~/store", "~"] {
                let error = expand_root(Path::new(root), || Err(reason.clone())).unwrap_err();
                assert!(
                    matches!(&error, StorageError::InvalidConfig { message }
                        if message.ends_with(&reason.to_string())),
                    "{root}, {reason}: {error}"
                );
            }
        }
        let unreachable = || -> Result<PathBuf, HomeDirError> { panic!("home consulted") };
        assert_eq!(
            expand_root(Path::new("/var/store"), unreachable).unwrap(),
            PathBuf::from("/var/store")
        );
    }

    #[tokio::test]
    async fn file_storage_upload_download() {
        let dir = tempfile::tempdir().unwrap();
        let storage = FileStorage::new(dir.path()).unwrap();

        let data = b"test content";
        storage.upload("test.txt", data).await.unwrap();

        let downloaded = storage.download("test.txt").await.unwrap();
        assert_eq!(downloaded, data);
    }

    #[tokio::test]
    async fn file_storage_download_capped_refuses_oversize_before_reading() {
        let dir = tempfile::tempdir().unwrap();
        let storage = FileStorage::new(dir.path()).unwrap();
        storage.upload("head.json", b"0123456789").await.unwrap();

        // At the limit: the whole file.
        assert_eq!(
            storage.download_capped("head.json", 10).await.unwrap(),
            b"0123456789"
        );
        // One byte over: refused with the real size, nothing truncated.
        let err = storage.download_capped("head.json", 9).await.unwrap_err();
        assert!(
            matches!(
                err,
                StorageError::TooLarge {
                    size: 10,
                    max: 9,
                    ..
                }
            ),
            "{err:?}"
        );
        // A missing key keeps its own error.
        assert!(matches!(
            storage.download_capped("absent.json", 10).await,
            Err(StorageError::NotFound { .. })
        ));
    }

    /// A key that is not a regular file is refused, and nothing is read from it.
    #[tokio::test]
    async fn file_storage_download_capped_refuses_what_is_not_a_regular_file() {
        let dir = tempfile::tempdir().unwrap();
        let storage = FileStorage::new(dir.path()).unwrap();
        std::fs::create_dir(dir.path().join("a-directory")).unwrap();
        let devices = FileStorage::open_existing("/dev").unwrap();
        for (storage, key) in [(&storage, "a-directory"), (&devices, "zero")] {
            let result = storage.download_capped(key, 1024).await;
            assert!(
                matches!(
                    &result,
                    Err(StorageError::DownloadFailed { message, .. }) if message == "not a regular file"
                ),
                "{key}: {result:?}"
            );
        }
    }

    /// A procfs file is a regular file that reports no size, so only the bounded
    /// read can refuse it: the case of a file longer than its size check said.
    #[tokio::test]
    async fn file_storage_download_capped_refuses_a_file_longer_than_its_reported_size() {
        let meta = std::fs::metadata("/proc/self/status").unwrap();
        assert!(meta.is_file() && meta.len() == 0, "procfs reports no size");
        let storage = FileStorage::open_existing("/proc/self").unwrap();
        let err = storage.download_capped("status", 16).await.unwrap_err();
        assert!(
            matches!(
                err,
                StorageError::TooLarge {
                    size: 17,
                    max: 16,
                    ..
                }
            ),
            "{err:?}"
        );
    }

    /// A FIFO key is refused at once. Run on its own thread: the open is a
    /// blocking call, so only a deadline outside it turns a lost `O_NONBLOCK`
    /// into a failure instead of a hang.
    #[test]
    fn file_storage_download_capped_does_not_wait_on_a_fifo() {
        let dir = tempfile::tempdir().unwrap();
        let storage = FileStorage::new(dir.path()).unwrap();
        assert!(
            std::process::Command::new("mkfifo")
                .arg(dir.path().join("a-fifo"))
                .status()
                .unwrap()
                .success()
        );
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let _ = tx.send(runtime.block_on(storage.download_capped("a-fifo", 1024)));
        });
        let result = rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("the open must not wait on the entry");
        assert!(
            matches!(
                &result,
                Err(StorageError::DownloadFailed { message, .. }) if message == "not a regular file"
            ),
            "{result:?}"
        );
    }

    #[test]
    fn open_existing_creates_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("not-there");
        let err = FileStorage::open_existing(&missing).unwrap_err();
        assert!(matches!(err, StorageError::LocalRootNotDir), "{err:?}");
        assert!(!err.to_string().contains("not-there"), "{err}");
        assert!(!missing.exists());
        // A file is not a directory.
        let file = dir.path().join("a-file");
        std::fs::write(&file, b"x").unwrap();
        assert!(matches!(
            FileStorage::open_existing(&file),
            Err(StorageError::LocalRootNotDir)
        ));
        // An existing directory opens.
        assert!(FileStorage::open_existing(dir.path()).is_ok());
    }

    /// Naming a store never creates it: `new` on a missing root leaves the
    /// filesystem alone, every read answers as for a missing key, and the
    /// first upload is what brings the root — parents included — into being.
    #[tokio::test]
    async fn new_creates_nothing_until_the_first_upload() {
        let dir = tempfile::tempdir().unwrap();
        let parent = dir.path().join("not-there");
        let root = parent.join("store");

        for upload_file in [false, true] {
            let storage = FileStorage::new(&root).unwrap();
            assert!(!parent.exists(), "new created the root");

            assert!(matches!(
                storage.download("latest.json").await,
                Err(StorageError::NotFound { .. })
            ));
            assert!(matches!(
                storage.download_capped("latest.json", 10).await,
                Err(StorageError::NotFound { .. })
            ));
            assert!(matches!(
                storage
                    .download_to_file("latest.json", &dir.path().join("out"))
                    .await,
                Err(StorageError::NotFound { .. })
            ));
            assert!(!storage.exists("latest.json").await.unwrap());
            for prefix in ["", "tools/fuzd/", "manifest-"] {
                assert!(storage.list(prefix).await.unwrap().is_empty(), "{prefix:?}");
            }
            storage.delete("latest.json").await.unwrap();
            assert!(!parent.exists(), "a read or a delete created the root");

            if upload_file {
                let src = dir.path().join("src");
                std::fs::write(&src, b"{}").unwrap();
                storage.upload_file("latest.json", &src).await.unwrap();
            } else {
                storage.upload("latest.json", b"{}").await.unwrap();
            }
            assert_eq!(storage.list("").await.unwrap(), ["latest.json"]);
            assert_eq!(std::fs::read(root.join("latest.json")).unwrap(), b"{}");
            std::fs::remove_dir_all(&parent).unwrap();
        }
    }

    /// A directory that is not there lists as empty, rather than as the files
    /// beside it that share its name as a prefix: the root itself, and a
    /// directory prefix (`tools/fuzd/`) one level down — the prefix a tool
    /// stream is swept by.
    #[tokio::test]
    async fn listing_a_missing_directory_stays_inside_it() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("store.bak"), b"x").unwrap();
        std::fs::write(dir.path().join("store-notes"), b"x").unwrap();
        let storage = FileStorage::new(dir.path().join("store")).unwrap();
        assert!(storage.list("").await.unwrap().is_empty());

        // An existing root, a `tools/` holding only files named like the
        // missing `tools/fuzd/`.
        let root = dir.path().join("existing");
        std::fs::create_dir_all(root.join("tools")).unwrap();
        std::fs::write(root.join("tools/fuzd.bak"), b"x").unwrap();
        std::fs::write(root.join("tools/fuzd-manifest.json"), b"x").unwrap();
        let storage = FileStorage::new(&root).unwrap();
        assert!(storage.list("tools/fuzd/").await.unwrap().is_empty());
        // Without the `/` it is a file-name prefix, and matches them.
        assert_eq!(
            storage.list("tools/fuzd").await.unwrap(),
            ["tools/fuzd-manifest.json", "tools/fuzd.bak"]
        );
        // Once the directory exists, both forms list what it holds.
        std::fs::create_dir(root.join("tools/fuzd")).unwrap();
        std::fs::write(root.join("tools/fuzd/latest.json"), b"{}").unwrap();
        for prefix in ["tools/fuzd/", "tools/fuzd"] {
            assert_eq!(
                storage.list(prefix).await.unwrap(),
                ["tools/fuzd/latest.json"],
                "{prefix:?}"
            );
        }
    }

    /// A root that could never become a store is refused when it is named, not
    /// by the first upload: a file there, a dangling symlink there, a file
    /// where a parent should be. Nothing is created — the symlink's target
    /// included — and a symlink to a directory is a directory.
    #[test]
    fn new_refuses_a_root_that_is_not_a_directory_and_creates_nothing() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("a-file");
        std::fs::write(&file, b"keep").unwrap();
        let target = dir.path().join("target-not-there");
        let dangling = dir.path().join("dangling");
        symlink(&target, &dangling).unwrap();

        for root in [file.clone(), dangling.clone(), file.join("store")] {
            for constructed in [FileStorage::new(&root), FileStorage::open_existing(&root)] {
                assert!(
                    matches!(constructed, Err(StorageError::LocalRootNotDir)),
                    "{}: {constructed:?}",
                    root.display()
                );
            }
        }
        assert_eq!(std::fs::read(&file).unwrap(), b"keep");
        assert!(dangling.is_symlink());
        assert!(!target.exists(), "the symlink's target was created");

        let real = dir.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let link = dir.path().join("link");
        symlink(&real, &link).unwrap();
        assert!(FileStorage::new(&link).is_ok());
        assert!(FileStorage::open_existing(&link).is_ok());
    }

    /// No key names a path outside the root: a key or a list prefix that is
    /// absolute or climbs with `..` is refused as an invalid key by every
    /// method, before the filesystem is touched — where a bare join onto the
    /// root would read, write, list, and delete beside the store.
    #[tokio::test]
    async fn every_method_refuses_a_key_that_leaves_the_root() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("store");
        std::fs::create_dir_all(root.join("a")).unwrap();
        let victim = dir.path().join("x");
        std::fs::write(&victim, b"outside").unwrap();
        let src = dir.path().join("src");
        std::fs::write(&src, b"new").unwrap();
        let dest = dir.path().join("dest");
        let storage = FileStorage::new(&root).unwrap();
        let absolute = victim.to_str().unwrap();

        let refused = |result: Result<(), StorageError>, what: &str, key: &str| {
            assert!(
                matches!(&result, Err(StorageError::InvalidKey { key: named, .. }) if named == key),
                "{what}({key:?}): {result:?}"
            );
        };
        // `../x` and `a/../../x` both name the victim; so does its own
        // absolute path, which a join would take in place of the root. (That
        // path is the absolute key here: were a method to act on one, it must
        // be on a file under this tempdir.)
        for key in ["../x", "a/../../x", absolute, "x\0y"] {
            refused(storage.upload(key, b"new").await, "upload", key);
            refused(storage.upload_file(key, &src).await, "upload_file", key);
            refused(storage.download(key).await.map(drop), "download", key);
            refused(
                storage.download_capped(key, 64).await.map(drop),
                "download_capped",
                key,
            );
            refused(
                storage.download_to_file(key, &dest).await.map(drop),
                "download_to_file",
                key,
            );
            refused(storage.exists(key).await.map(drop), "exists", key);
            refused(storage.delete(key).await, "delete", key);
            assert_eq!(std::fs::read(&victim).unwrap(), b"outside", "{key:?}");
            assert!(!dest.exists(), "{key:?}: read out of the root");
        }
        // A listing prefix is the directory that gets read.
        let listed_outside = format!("{}/", dir.path().display());
        for prefix in ["../", "..", "a/../../", listed_outside.as_str()] {
            refused(storage.list(prefix).await.map(drop), "list", prefix);
        }
    }

    #[tokio::test]
    async fn file_storage_download_to_file_streams_and_maps_missing() {
        let dir = tempfile::tempdir().unwrap();
        let storage = FileStorage::new(dir.path()).unwrap();
        storage.upload("a/b.bin", b"copy me").await.unwrap();

        let dest = dir.path().join("out.bin");
        let n = storage.download_to_file("a/b.bin", &dest).await.unwrap();
        assert_eq!(n, 7);
        assert_eq!(std::fs::read(&dest).unwrap(), b"copy me");

        let miss = storage.download_to_file("nope", &dest).await;
        assert!(matches!(miss, Err(StorageError::NotFound { .. })));
    }

    #[tokio::test]
    async fn file_storage_download_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let storage = FileStorage::new(dir.path()).unwrap();

        let result = storage.download("nonexistent.txt").await;
        assert!(matches!(result, Err(StorageError::NotFound { .. })));
    }

    #[tokio::test]
    async fn file_storage_exists() {
        let dir = tempfile::tempdir().unwrap();
        let storage = FileStorage::new(dir.path()).unwrap();

        assert!(!storage.exists("test.txt").await.unwrap());

        storage.upload("test.txt", b"data").await.unwrap();
        assert!(storage.exists("test.txt").await.unwrap());
    }

    #[tokio::test]
    async fn file_storage_delete() {
        let dir = tempfile::tempdir().unwrap();
        let storage = FileStorage::new(dir.path()).unwrap();

        storage.upload("test.txt", b"data").await.unwrap();
        assert!(storage.exists("test.txt").await.unwrap());

        storage.delete("test.txt").await.unwrap();
        assert!(!storage.exists("test.txt").await.unwrap());
    }

    #[tokio::test]
    async fn file_storage_delete_nonexistent_ok() {
        let dir = tempfile::tempdir().unwrap();
        let storage = FileStorage::new(dir.path()).unwrap();

        // Should not error on nonexistent file
        storage.delete("nonexistent.txt").await.unwrap();
    }

    #[tokio::test]
    async fn file_storage_list() {
        let dir = tempfile::tempdir().unwrap();
        let storage = FileStorage::new(dir.path()).unwrap();

        storage.upload("a.txt", b"a").await.unwrap();
        storage.upload("b.txt", b"b").await.unwrap();
        storage.upload("c.json", b"c").await.unwrap();

        let all = storage.list("").await.unwrap();
        assert_eq!(all, vec!["a.txt", "b.txt", "c.json"]);
    }

    /// A directory prefix lists that directory's files as keys relative to the
    /// storage root — the form `download` takes and the other backends return —
    /// and a file-name prefix inside a directory does the same.
    #[tokio::test]
    async fn file_storage_list_returns_root_relative_keys() {
        let dir = tempfile::tempdir().unwrap();
        let storage = FileStorage::new(dir.path()).unwrap();

        storage.upload("top.txt", b"t").await.unwrap();
        storage.upload("tools/fuzd/a.json", b"a").await.unwrap();
        storage.upload("tools/fuzd/b.json", b"b").await.unwrap();
        storage.upload("tools/zap/c.json", b"c").await.unwrap();

        let expected = vec!["tools/fuzd/a.json", "tools/fuzd/b.json"];
        assert_eq!(storage.list("tools/fuzd/").await.unwrap(), expected);
        assert_eq!(storage.list("tools/fuzd").await.unwrap(), expected);
        assert_eq!(
            storage.list("tools/fuzd/a").await.unwrap(),
            vec!["tools/fuzd/a.json"]
        );
        for key in storage.list("tools/zap/").await.unwrap() {
            assert_eq!(storage.download(&key).await.unwrap(), b"c");
        }
        // The root lists its own files only.
        assert_eq!(storage.list("").await.unwrap(), vec!["top.txt"]);
        assert!(storage.list("tools/none/").await.unwrap().is_empty());
    }

    /// The key contract is about keys, not about the tree under the root.
    /// `list` returns regular files only: a symlink to a file is not listed,
    /// though `exists`, `download`, and `download_to_file` follow it. A
    /// symlinked directory is followed wherever a path goes through it — the
    /// directory a `list` prefix names included — so its files are served and
    /// listed from where the link points.
    #[tokio::test]
    async fn a_symlinked_file_is_served_but_not_listed() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("store");
        let storage = FileStorage::new(&root).unwrap();
        storage
            .upload("tools/fuzd/real.json", b"real")
            .await
            .unwrap();
        let elsewhere = dir.path().join("elsewhere");
        std::fs::create_dir(&elsewhere).unwrap();
        std::fs::write(elsewhere.join("outside.json"), b"outside").unwrap();
        std::os::unix::fs::symlink(
            elsewhere.join("outside.json"),
            root.join("tools/fuzd/linked.json"),
        )
        .unwrap();
        std::os::unix::fs::symlink(&elsewhere, root.join("tools/linked")).unwrap();

        // The linked file: there for every read, absent from the listing.
        let key = "tools/fuzd/linked.json";
        assert!(storage.exists(key).await.unwrap());
        assert_eq!(storage.download(key).await.unwrap(), b"outside");
        assert_eq!(storage.download_capped(key, 64).await.unwrap(), b"outside");
        let dest = dir.path().join("out.bin");
        assert_eq!(storage.download_to_file(key, &dest).await.unwrap(), 7);
        assert_eq!(
            storage.list("tools/fuzd/").await.unwrap(),
            ["tools/fuzd/real.json"]
        );
        assert_eq!(
            storage.list("tools/fuzd/linked").await.unwrap(),
            [""; 0],
            "a file-name prefix does not list it either"
        );

        // The linked directory: not an entry of its parent's listing, and
        // followed when the prefix names it.
        assert_eq!(storage.list("tools/").await.unwrap(), [""; 0]);
        assert_eq!(
            storage.list("tools/linked/").await.unwrap(),
            ["tools/linked/outside.json"]
        );
        assert_eq!(
            storage.download("tools/linked/outside.json").await.unwrap(),
            b"outside"
        );

        // A root that is itself a link lists like the directory it points to.
        let linked_root = dir.path().join("store-link");
        std::os::unix::fs::symlink(&root, &linked_root).unwrap();
        let through_link = FileStorage::open_existing(&linked_root).unwrap();
        assert_eq!(
            through_link.list("tools/fuzd/").await.unwrap(),
            ["tools/fuzd/real.json"]
        );

        // A write to the linked file's key acts on the link, not through it:
        // an upload replaces it with a file, a delete removes it, and the file
        // it pointed to is as it was.
        storage.upload(key, b"replaced").await.unwrap();
        assert!(root.join(key).symlink_metadata().unwrap().is_file());
        assert_eq!(
            storage.list("tools/fuzd/").await.unwrap(),
            ["tools/fuzd/linked.json", "tools/fuzd/real.json"]
        );
        std::fs::remove_file(root.join(key)).unwrap();
        std::os::unix::fs::symlink(elsewhere.join("outside.json"), root.join(key)).unwrap();
        storage.delete(key).await.unwrap();
        assert!(root.join(key).symlink_metadata().is_err());
        assert_eq!(
            std::fs::read(elsewhere.join("outside.json")).unwrap(),
            b"outside"
        );
    }

    /// A `download_to_file` refused because the key is not there leaves a
    /// file already at `dest` as it was: the copy opens its source first.
    #[tokio::test]
    async fn a_missing_key_leaves_a_file_already_at_dest() {
        let dir = tempfile::tempdir().unwrap();
        let storage = FileStorage::new(dir.path().join("store")).unwrap();
        storage.upload("there.bin", b"payload").await.unwrap();
        let dest = dir.path().join("out.bin");
        std::fs::write(&dest, b"already here").unwrap();

        let err = storage
            .download_to_file("missing.bin", &dest)
            .await
            .unwrap_err();
        assert!(matches!(err, StorageError::NotFound { .. }), "{err:?}");
        assert_eq!(std::fs::read(&dest).unwrap(), b"already here");

        assert_eq!(
            storage.download_to_file("there.bin", &dest).await.unwrap(),
            7
        );
        assert_eq!(std::fs::read(&dest).unwrap(), b"payload");
    }

    #[tokio::test]
    async fn file_storage_atomic_write() {
        let dir = tempfile::tempdir().unwrap();
        let storage = FileStorage::new(dir.path()).unwrap();

        // Write should be atomic (no partial writes visible)
        storage.upload("test.txt", b"original").await.unwrap();
        storage
            .upload("test.txt", b"updated content")
            .await
            .unwrap();

        let content = storage.download("test.txt").await.unwrap();
        assert_eq!(content, b"updated content");

        // No temp file should be left behind (random-suffixed `.tmp` siblings
        // are renamed into place on success).
        let leftover_temp = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .any(|e| e.file_name().to_string_lossy().ends_with(".tmp"));
        assert!(!leftover_temp);
    }
}
