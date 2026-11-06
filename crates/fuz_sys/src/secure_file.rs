//! Secure file operations
//!
//! File I/O with security checks for sensitive data (e.g. signing keys).
//! Uses Unix-specific APIs for TOCTOU-safe operations.
//! [`open_nofollow_regular`] is the bare no-follow open, for a reader that
//! streams a file it must not reach through a link.

use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use thiserror::Error;

/// Counter for unique temp file names within the process.
/// Prevents collisions when multiple threads write to the same file concurrently.
static TEMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Maximum size for secure files (e.g. key files).
/// Prevents `DoS` from unexpectedly large files.
///
/// 4KB is sufficient for:
/// - v1 key files (~150 bytes)
/// - v2 encrypted keys (adds ~100 bytes for IV, salt, KDF params)
/// - Future expansion headroom
const MAX_SECURE_FILE_SIZE: u64 = 4096;

/// Errors that can occur during secure file operations
#[derive(Debug, Error)]
pub enum SecureFileError {
    /// File not found
    #[error("file not found: {0}")]
    NotFound(PathBuf),

    /// File is a symlink. Rejected for security.
    ///
    /// **Note on `write_secure_file`**: The symlink check has a TOCTOU window,
    /// but this is safe because temp+rename replaces the symlink itself,
    /// not its target. The check provides a clear error message.
    #[error("file is a symlink: {0}")]
    Symlink(PathBuf),

    /// Insecure file permissions
    #[error("insecure permissions on {0}: {1:o} (expected 0600)")]
    InsecurePermissions(PathBuf, u32),

    /// File too large
    #[error("file too large: {0} ({1} bytes, max {2})")]
    FileTooLarge(PathBuf, u64, u64),

    /// The path is a directory, FIFO, socket, or device rather than a regular
    /// file.
    #[error("not a regular file: {0}")]
    NotRegularFile(PathBuf),

    /// I/O error
    #[error("I/O error on {0}: {1}")]
    Io(PathBuf, #[source] std::io::Error),
}

/// Load a sensitive file with TOCTOU-safe permission checks.
/// Rejects symlinks, non-regular files, and files with insecure permissions.
///
/// # Security
///
/// - `O_NOFOLLOW` atomically rejects symlinks during open (no TOCTOU window)
/// - `O_NONBLOCK` keeps the open from waiting on a FIFO that has no writer (it
///   has no effect on a regular file), and the regular-file check on the fd
///   refuses the FIFO, a device node, or a directory before the mode check
/// - `O_NOCTTY` keeps a terminal device at the path from becoming the
///   process's controlling terminal in the moment before that check refuses it
/// - Permission check on fd, not path (attacker can't swap after open)
/// - Size limit prevents `DoS` from large files
/// - `take()` limits actual read to handle file growth between stat and read
///
/// # Errors
///
/// Returns [`SecureFileError`] if:
/// - File not found
/// - File is a symlink
/// - File is not a regular file (FIFO, device, socket, directory)
/// - Permissions allow group/world access (not 0600 or 0400)
/// - File exceeds 4KB size limit
/// - I/O error occurs
pub fn load_secure_file(path: &Path) -> Result<Vec<u8>, SecureFileError> {
    let (file, fd_meta) = open_nofollow_regular(path)?;

    // Check permissions on the open file descriptor (not the path)
    // This prevents TOCTOU: attacker can't swap file between check and read
    let mode = fd_meta.permissions().mode();
    if mode & 0o077 != 0 {
        return Err(SecureFileError::InsecurePermissions(
            path.to_path_buf(),
            mode,
        ));
    }

    // Check file size before reading
    let reported_size = fd_meta.len();
    if reported_size > MAX_SECURE_FILE_SIZE {
        return Err(SecureFileError::FileTooLarge(
            path.to_path_buf(),
            reported_size,
            MAX_SECURE_FILE_SIZE,
        ));
    }

    // Read with limit to handle file growth between stat and read
    read_bounded(&file, path, MAX_SECURE_FILE_SIZE)
}

/// Read a file whose content authenticates itself, bounded and without
/// following a symlink.
///
/// For files that are trusted because of what they contain — a signed document
/// the caller verifies after reading — rather than because of their mode, so
/// unlike [`load_secure_file`] the permission bits are not checked and the
/// size ceiling is the caller's.
///
/// - `O_NOFOLLOW` refuses a symlink at `path` during the open, so there is no
///   window between a check and the read.
/// - The regular-file check runs on the open descriptor. `O_NONBLOCK` keeps
///   the open from waiting on a FIFO that has no writer, and `O_NOCTTY` keeps a
///   terminal from becoming the controlling terminal; neither affects a
///   regular file.
/// - A file longer than `max` is refused, never truncated: the size is checked
///   on the descriptor, and the read takes `max + 1` bytes so a file that grew
///   after the check is refused too.
///
/// # Errors
///
/// [`SecureFileError::NotFound`], [`SecureFileError::Symlink`],
/// [`SecureFileError::NotRegularFile`], [`SecureFileError::FileTooLarge`], or
/// [`SecureFileError::Io`] for any other failure.
pub fn load_bounded_file(path: &Path, max: u64) -> Result<Vec<u8>, SecureFileError> {
    let (file, meta) = open_nofollow_regular(path)?;
    if meta.len() > max {
        return Err(SecureFileError::FileTooLarge(
            path.to_path_buf(),
            meta.len(),
            max,
        ));
    }
    read_bounded(&file, path, max)
}

/// Open `path` for reading without following a symlink, requiring a regular
/// file — the shared open of [`load_secure_file`] and [`load_bounded_file`].
///
/// `O_NOFOLLOW` refuses a symlink during the open (no TOCTOU window), and the
/// regular-file check runs on the open descriptor. `O_NONBLOCK` keeps the open
/// from waiting on a FIFO that has no writer, and `O_NOCTTY` keeps a terminal
/// from becoming the controlling terminal before that check refuses it.
///
/// Public for a reader that streams the file rather than buffering it — the
/// artifact store hashes a binary through the returned descriptor. Only the
/// final component is refused as a symlink; the parents resolve as usual.
///
/// # Errors
///
/// [`SecureFileError::Symlink`] on `ELOOP`, [`SecureFileError::NotFound`],
/// [`SecureFileError::NotRegularFile`], or [`SecureFileError::Io`] for any
/// other open or stat failure.
pub fn open_nofollow_regular(
    path: &Path,
) -> Result<(std::fs::File, std::fs::Metadata), SecureFileError> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY)
        .open(path)
        .map_err(|e| {
            // ELOOP means it was a symlink
            if e.raw_os_error() == Some(libc::ELOOP) {
                SecureFileError::Symlink(path.to_path_buf())
            } else if e.kind() == std::io::ErrorKind::NotFound {
                SecureFileError::NotFound(path.to_path_buf())
            } else {
                SecureFileError::Io(path.to_path_buf(), e)
            }
        })?;
    let meta = file
        .metadata()
        .map_err(|e| SecureFileError::Io(path.to_path_buf(), e))?;
    if !meta.is_file() {
        return Err(SecureFileError::NotRegularFile(path.to_path_buf()));
    }
    Ok((file, meta))
}

/// Read `reader` to its end, refusing more than `max` bytes.
///
/// The bound that holds whatever a size check said beforehand: `max + 1` bytes
/// are taken, so a source longer than `max` — a file that grew after its size
/// was checked — is refused rather than truncated.
fn read_bounded(reader: impl Read, path: &Path, max: u64) -> Result<Vec<u8>, SecureFileError> {
    let mut contents = Vec::new();
    reader
        .take(max.saturating_add(1))
        .read_to_end(&mut contents)
        .map_err(|e| SecureFileError::Io(path.to_path_buf(), e))?;
    if contents.len() as u64 > max {
        return Err(SecureFileError::FileTooLarge(
            path.to_path_buf(),
            contents.len() as u64,
            max,
        ));
    }
    Ok(contents)
}

/// Open `path` for reading without blocking, requiring a regular file.
///
/// A plain open of a FIFO waits for a writer, forever if none comes;
/// `O_NONBLOCK` returns at once, and the regular-file check on the open
/// descriptor then refuses the FIFO — and a directory, socket, or device.
/// `O_NOCTTY` keeps a terminal from becoming the controlling terminal before
/// that check. Neither flag affects reading a regular file. A symlink is
/// followed: use
/// [`load_bounded_file`] where it must not be.
///
/// # Errors
///
/// The open or stat error, or an [`std::io::ErrorKind::InvalidInput`] error
/// saying the path is not a regular file.
pub fn open_regular_nonblocking(
    path: &Path,
) -> std::io::Result<(std::fs::File, std::fs::Metadata)> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY)
        .open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "not a regular file",
        ));
    }
    Ok((file, meta))
}

/// Open `path` for writing from empty without following a symlink.
///
/// The write side of [`open_nofollow_regular`], for a file written in place (a
/// log) rather than replaced by rename; a missing file is created at `mode`.
///
/// `O_NOFOLLOW` refuses a symlink at `path` during the open, so a link planted
/// there is neither written through nor, dangling, used to create its target.
/// The regular-file check runs on the open descriptor, and the file is
/// truncated only once it passes. `O_NONBLOCK` keeps the open from waiting on a
/// FIFO with no reader and is cleared before the descriptor is returned, so
/// writes through it (a child's stdout, say) block as usual; `O_NOCTTY` keeps a
/// terminal from becoming the controlling terminal. Only the final component
/// is checked; the parents resolve as usual. `mode` applies only to a file this
/// creates, under the umask.
///
/// # Errors
///
/// [`SecureFileError::Symlink`] on `ELOOP`, [`SecureFileError::NotRegularFile`]
/// for anything else that is not a regular file, or [`SecureFileError::Io`]
/// for any other open, stat, flag, or truncate failure.
pub fn open_truncate_nofollow_regular(
    path: &Path,
    mode: u32,
) -> Result<std::fs::File, SecureFileError> {
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .mode(mode)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY)
        .open(path)
        .map_err(|e| match e.raw_os_error() {
            Some(libc::ELOOP) => SecureFileError::Symlink(path.to_path_buf()),
            // a directory, or a FIFO with no reader
            Some(libc::EISDIR | libc::ENXIO) => SecureFileError::NotRegularFile(path.to_path_buf()),
            _ => SecureFileError::Io(path.to_path_buf(), e),
        })?;
    let meta = file
        .metadata()
        .map_err(|e| SecureFileError::Io(path.to_path_buf(), e))?;
    if !meta.is_file() {
        return Err(SecureFileError::NotRegularFile(path.to_path_buf()));
    }
    clear_nonblocking(&file).map_err(|e| SecureFileError::Io(path.to_path_buf(), e))?;
    file.set_len(0)
        .map_err(|e| SecureFileError::Io(path.to_path_buf(), e))?;
    Ok(file)
}

/// Clear `O_NONBLOCK` on `file`'s open file description.
fn clear_nonblocking(file: &std::fs::File) -> std::io::Result<()> {
    use nix::fcntl::{FcntlArg, OFlag, fcntl};
    let flags = OFlag::from_bits_retain(fcntl(file, FcntlArg::F_GETFL)?);
    fcntl(file, FcntlArg::F_SETFL(flags.difference(OFlag::O_NONBLOCK)))?;
    Ok(())
}

/// Write a sensitive file atomically with restricted permissions.
/// Uses temp file + rename pattern for crash safety.
///
/// # Security
///
/// - Symlink check provides clear error message (actual protection comes from temp+rename)
/// - Temp file + rename is atomic on POSIX - no partial writes on crash
/// - `create_new(true)` (`O_EXCL`) prevents temp file races
/// - Temp file in same directory ensures same filesystem for rename atomicity
///   (the working directory, for a bare file name — [`crate::fs::parent_dir`])
/// - POSIX `rename()` replaces symlinks, not their targets (safe even with TOCTOU window)
///
/// # Durability
///
/// Follows the same discipline as [`crate::fs::write_atomic`]: fsync the
/// file content before rename, then fsync the *parent directory* after.
/// Without the parent fsync a host crash between rename and any later op
/// can lose the rename entirely — a real concern for signing keys.
///
/// This module doesn't delegate to `fs::write_atomic` because it has
/// stricter requirements (symlink check, per-thread temp counter for
/// concurrent same-path writes that secure files specifically support).
///
/// # Errors
///
/// Returns [`SecureFileError`] if:
/// - Path is a symlink
/// - Temp file creation fails
/// - Write or sync fails
/// - Atomic rename fails
pub fn write_secure_file(path: &Path, content: &[u8], mode: u32) -> Result<(), SecureFileError> {
    // Warn if target is a symlink (see security note above and SecureFileError::Symlink doc)
    if path.is_symlink() {
        return Err(SecureFileError::Symlink(path.to_path_buf()));
    }

    // Write to temp file in same directory (ensures same filesystem for rename)
    // Include PID + atomic counter to avoid collisions across processes and threads
    let parent = crate::fs::parent_dir(path).unwrap_or_else(|| Path::new("."));
    let counter = TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let temp_name = format!(
        ".{}.tmp.{}.{}",
        path.file_name().unwrap_or_default().to_string_lossy(),
        std::process::id(),
        counter
    );
    let temp_path = parent.join(&temp_name);

    // Create temp file with restricted permissions
    // O_EXCL ensures we create a new file (no overwrite)
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true) // Fail if exists (O_EXCL)
        .mode(mode)
        .open(&temp_path)
        .map_err(|e| SecureFileError::Io(temp_path.clone(), e))?;

    // Write and sync
    if let Err(e) = file.write_all(content) {
        let _ = std::fs::remove_file(&temp_path); // Clean up on error
        return Err(SecureFileError::Io(temp_path, e));
    }
    if let Err(e) = file.sync_all() {
        let _ = std::fs::remove_file(&temp_path);
        return Err(SecureFileError::Io(temp_path, e));
    }
    drop(file); // Close before rename

    // Atomic rename (POSIX guarantees atomicity on same filesystem)
    if let Err(e) = std::fs::rename(&temp_path, path) {
        let _ = std::fs::remove_file(&temp_path);
        return Err(SecureFileError::Io(path.to_path_buf(), e));
    }

    // Fsync the parent directory so the rename is durable across a crash.
    // Without this the new file's contents are durable (we sync_all'd) but
    // the *dirent* update can be lost — leaving the path either missing
    // or pointing at the old inode on recovery. Critical for secrets:
    // losing a freshly-rotated signing.key is worse than losing a
    // freshly-written meta.json.
    crate::fs::fsync_dir(parent).map_err(|e| SecureFileError::Io(path.to_path_buf(), e))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    // Test sizes are known-bounded literals; u64→usize is safe here and the
    // cast reads cleaner than `usize::try_from(...).unwrap()`.
    #![allow(clippy::cast_possible_truncation)]
    use super::*;
    use std::os::unix::fs::symlink;
    use tempfile::TempDir;

    #[test]
    fn secure_load_returns_not_found() {
        let result = load_secure_file(Path::new("/tmp/nonexistent_secure_file_test_12345"));
        assert!(matches!(result, Err(SecureFileError::NotFound(_))));
    }

    #[test]
    fn secure_load_rejects_symlink() {
        let dir = TempDir::new().expect("create temp dir");
        let target = dir.path().join("target.txt");
        let link = dir.path().join("link.txt");

        std::fs::write(&target, b"secret").expect("write target");
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600))
            .expect("set perms");
        symlink(&target, &link).expect("create symlink");

        let result = load_secure_file(&link);
        assert!(matches!(result, Err(SecureFileError::Symlink(_))));
    }

    #[test]
    fn secure_load_rejects_world_readable() {
        let dir = TempDir::new().expect("create temp dir");
        let file = dir.path().join("world_readable.txt");

        std::fs::write(&file, b"secret").expect("write file");
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).expect("set perms");

        let result = load_secure_file(&file);
        assert!(matches!(
            result,
            Err(SecureFileError::InsecurePermissions(_, _))
        ));
    }

    #[test]
    fn secure_load_rejects_group_readable() {
        let dir = TempDir::new().expect("create temp dir");
        let file = dir.path().join("group_readable.txt");

        std::fs::write(&file, b"secret").expect("write file");
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o640)).expect("set perms");

        let result = load_secure_file(&file);
        assert!(matches!(
            result,
            Err(SecureFileError::InsecurePermissions(_, _))
        ));
    }

    #[test]
    fn secure_load_accepts_owner_only() {
        let dir = TempDir::new().expect("create temp dir");
        let file = dir.path().join("owner_only.txt");

        std::fs::write(&file, b"secret data").expect("write file");
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).expect("set perms");

        let result = load_secure_file(&file).expect("load should succeed");
        assert_eq!(result, b"secret data");
    }

    #[test]
    fn secure_load_rejects_too_large() {
        let dir = TempDir::new().expect("create temp dir");
        let file = dir.path().join("too_large.txt");

        // Create file larger than MAX_SECURE_FILE_SIZE
        let content = vec![b'x'; (MAX_SECURE_FILE_SIZE + 100) as usize];
        std::fs::write(&file, &content).expect("write file");
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).expect("set perms");

        let result = load_secure_file(&file);
        assert!(matches!(
            result,
            Err(SecureFileError::FileTooLarge(_, _, _))
        ));
    }

    #[test]
    fn secure_write_rejects_symlink() {
        let dir = TempDir::new().expect("create temp dir");
        let target = dir.path().join("target.txt");
        let link = dir.path().join("link.txt");

        std::fs::write(&target, b"original").expect("write target");
        symlink(&target, &link).expect("create symlink");

        let result = write_secure_file(&link, b"new content", 0o600);
        assert!(matches!(result, Err(SecureFileError::Symlink(_))));
    }

    #[test]
    fn secure_write_creates_with_mode() {
        let dir = TempDir::new().expect("create temp dir");
        let file = dir.path().join("new_secure.txt");

        write_secure_file(&file, b"secret", 0o600).expect("write should succeed");

        let meta = std::fs::metadata(&file).expect("read metadata");
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "file should have mode 0600");

        let content = std::fs::read(&file).expect("read file");
        assert_eq!(content, b"secret");
    }

    #[test]
    fn secure_write_overwrites_existing() {
        let dir = TempDir::new().expect("create temp dir");
        let file = dir.path().join("existing.txt");

        // Create initial file
        write_secure_file(&file, b"initial", 0o600).expect("first write");

        // Overwrite
        write_secure_file(&file, b"updated", 0o600).expect("second write");

        let content = std::fs::read(&file).expect("read file");
        assert_eq!(content, b"updated");
    }

    #[test]
    fn secure_write_round_trip() {
        let dir = TempDir::new().expect("create temp dir");
        let file = dir.path().join("round_trip.txt");

        let data = b"sensitive key data";
        write_secure_file(&file, data, 0o600).expect("write");

        let loaded = load_secure_file(&file).expect("load");
        assert_eq!(loaded, data);
    }

    /// Test that file growth between stat and read is handled correctly.
    ///
    /// This simulates the case where a file grows after we check its size
    /// but before/during the read. The `take()` limit should cap the read.
    #[test]
    fn secure_load_handles_file_at_limit() {
        let dir = TempDir::new().expect("create temp dir");
        let file = dir.path().join("at_limit.txt");

        // Create file exactly at MAX_SECURE_FILE_SIZE
        let content = vec![b'x'; MAX_SECURE_FILE_SIZE as usize];
        std::fs::write(&file, &content).expect("write file");
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).expect("set perms");

        // Should succeed - exactly at limit
        let result = load_secure_file(&file).expect("load should succeed");
        assert_eq!(result.len(), MAX_SECURE_FILE_SIZE as usize);
    }

    /// Test that file just over the limit is rejected.
    #[test]
    fn secure_load_rejects_one_over_limit() {
        let dir = TempDir::new().expect("create temp dir");
        let file = dir.path().join("one_over.txt");

        // Create file one byte over MAX_SECURE_FILE_SIZE
        let content = vec![b'x'; (MAX_SECURE_FILE_SIZE + 1) as usize];
        std::fs::write(&file, &content).expect("write file");
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).expect("set perms");

        // Should fail - one byte over limit
        let result = load_secure_file(&file);
        assert!(matches!(
            result,
            Err(SecureFileError::FileTooLarge(_, _, _))
        ));
    }

    /// The crash-leftover pin: a stale permissive temp beside the target is
    /// never reused or republished. `O_CREAT` mode applies only at creation,
    /// so a *fixed* temp name reopened `O_TRUNC` would keep the stale mode
    /// and the rename would publish that inode — the unique
    /// `.{file}.tmp.{pid}.{counter}` name plus `create_new(true)` is the
    /// whole defense, and this asserts it end-to-end.
    #[test]
    fn secure_write_never_republishes_a_stale_permissive_temp() {
        let dir = TempDir::new().expect("create temp dir");
        let file = dir.path().join("secret");

        // Simulate a crash leftover in the fixed-name shape a naive
        // implementation would collide with, world-readable.
        let stale = dir.path().join("secret.tmp");
        std::fs::write(&stale, b"stale").expect("write stale temp");
        std::fs::set_permissions(&stale, std::fs::Permissions::from_mode(0o644))
            .expect("set stale perms");

        write_secure_file(&file, b"fresh-secret", 0o600).expect("write");

        let mode = std::fs::metadata(&file)
            .expect("stat published file")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "published inode must carry the requested mode");
        assert_eq!(
            load_secure_file(&file).expect("secure load"),
            b"fresh-secret",
            "published content must be the fresh write, not the stale temp"
        );
        // The stale temp is untouched — never truncated, never renamed over
        // the target, and no other temp is stranded.
        assert_eq!(
            std::fs::read(&stale).expect("stale temp still present"),
            b"stale"
        );
        let names: Vec<String> = std::fs::read_dir(dir.path())
            .expect("read dir")
            .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            names.iter().filter(|n| n.contains(".tmp")).count(),
            1,
            "only the pre-existing stale temp remains: {names:?}"
        );
    }

    /// Test concurrent writes to the same file don't corrupt data.
    ///
    /// Uses atomic counter in temp file naming to avoid collisions between threads.
    /// All writes should succeed (no temp file collisions).
    #[test]
    fn secure_write_concurrent_same_file() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::thread;

        let dir = TempDir::new().expect("create temp dir");
        let file = Arc::new(dir.path().join("concurrent.txt"));
        let success_count = Arc::new(AtomicUsize::new(0));

        // Spawn multiple threads writing different content to the same file
        let handles: Vec<_> = (0..10)
            .map(|i| {
                let file = Arc::clone(&file);
                let success_count = Arc::clone(&success_count);
                thread::spawn(move || {
                    let content = format!("thread {i} content").into_bytes();
                    // With atomic counter, all writes should succeed (no temp file collisions)
                    if write_secure_file(&file, &content, 0o600).is_ok() {
                        success_count.fetch_add(1, Ordering::Relaxed);
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().expect("thread panicked");
        }

        // All writes should succeed - no temp file collisions with atomic counter
        assert_eq!(
            success_count.load(Ordering::Relaxed),
            10,
            "all writes should succeed with atomic counter"
        );

        // File should exist and contain valid content from one of the threads
        let content = load_secure_file(&file).expect("final load");
        let content_str = String::from_utf8(content).expect("valid utf8");
        assert!(
            content_str.starts_with("thread ") && content_str.ends_with(" content"),
            "content should be from one thread, got: {content_str}"
        );
    }

    #[test]
    fn bounded_load_reads_a_regular_file_whatever_its_mode() {
        let dir = TempDir::new().expect("create temp dir");
        let file = dir.path().join("doc.json");
        std::fs::write(&file, b"signed bytes").expect("write file");
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).expect("set perms");
        assert_eq!(load_bounded_file(&file, 64).expect("load"), b"signed bytes");
        // Exactly at the limit is accepted.
        assert_eq!(load_bounded_file(&file, 12).expect("load").len(), 12);
    }

    #[test]
    fn bounded_load_refuses_oversize_without_truncating() {
        let dir = TempDir::new().expect("create temp dir");
        let file = dir.path().join("doc.json");
        std::fs::write(&file, b"thirteen byte").expect("write file");
        let result = load_bounded_file(&file, 12);
        assert!(
            matches!(result, Err(SecureFileError::FileTooLarge(_, 13, 12))),
            "{result:?}"
        );
    }

    #[test]
    fn bounded_load_refuses_symlink_missing_and_non_regular() {
        let dir = TempDir::new().expect("create temp dir");
        let target = dir.path().join("target.json");
        let link = dir.path().join("link.json");
        std::fs::write(&target, b"content").expect("write target");
        symlink(&target, &link).expect("create symlink");
        assert!(matches!(
            load_bounded_file(&link, 64),
            Err(SecureFileError::Symlink(_))
        ));
        // A dangling link is a symlink too, not "not found".
        let dangling = dir.path().join("dangling.json");
        symlink(dir.path().join("nowhere"), &dangling).expect("create symlink");
        assert!(matches!(
            load_bounded_file(&dangling, 64),
            Err(SecureFileError::Symlink(_))
        ));
        assert!(matches!(
            load_bounded_file(&dir.path().join("absent.json"), 64),
            Err(SecureFileError::NotFound(_))
        ));
        assert!(matches!(
            load_bounded_file(dir.path(), 64),
            Err(SecureFileError::NotRegularFile(_))
        ));
    }

    #[test]
    fn bounded_read_refuses_a_source_that_outgrew_its_size_check() {
        // The size check passed on a shorter file; the read is what holds.
        let path = Path::new("grown.json");
        let grown = vec![b'x'; 13];
        let result = read_bounded(grown.as_slice(), path, 12);
        assert!(
            matches!(result, Err(SecureFileError::FileTooLarge(_, 13, 12))),
            "{result:?}"
        );
        // Far past the limit: refused at `max + 1` bytes, not read whole.
        let far = vec![b'x'; 4096];
        let result = read_bounded(far.as_slice(), path, 12);
        assert!(
            matches!(result, Err(SecureFileError::FileTooLarge(_, 13, 12))),
            "{result:?}"
        );
        assert_eq!(
            read_bounded(&grown[..12], path, 12)
                .expect("at the limit")
                .len(),
            12
        );
    }

    /// A regular file is opened from empty, and a missing one created at the
    /// mode; a symlink — to a file or dangling — and a directory are refused
    /// with nothing written, truncated, or created.
    #[test]
    fn truncating_open_refuses_a_symlink_and_a_non_regular_file_untouched() {
        use std::io::Write as _;
        let dir = TempDir::new().expect("create temp dir");

        let log = dir.path().join("a.log");
        std::fs::write(&log, b"old contents").expect("write log");
        let mut file = open_truncate_nofollow_regular(&log, 0o600).expect("open existing");
        let flags = nix::fcntl::fcntl(&file, nix::fcntl::FcntlArg::F_GETFL).expect("F_GETFL");
        assert_eq!(
            flags & libc::O_NONBLOCK,
            0,
            "the returned descriptor blocks"
        );
        file.write_all(b"new").expect("write");
        drop(file);
        assert_eq!(std::fs::read(&log).expect("read log"), b"new");

        let fresh = dir.path().join("fresh.log");
        drop(open_truncate_nofollow_regular(&fresh, 0o600).expect("create"));
        let mode = std::fs::metadata(&fresh)
            .expect("stat")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "created at the mode: {mode:o}");

        let victim = dir.path().join("victim");
        std::fs::write(&victim, b"precious").expect("write victim");
        let link = dir.path().join("link.log");
        symlink(&victim, &link).expect("create symlink");
        assert!(matches!(
            open_truncate_nofollow_regular(&link, 0o600),
            Err(SecureFileError::Symlink(_))
        ));
        assert_eq!(std::fs::read(&victim).expect("read victim"), b"precious");

        let absent = dir.path().join("absent");
        let dangling = dir.path().join("dangling.log");
        symlink(&absent, &dangling).expect("create symlink");
        assert!(matches!(
            open_truncate_nofollow_regular(&dangling, 0o600),
            Err(SecureFileError::Symlink(_))
        ));
        assert!(!absent.exists(), "the link's target was created");

        assert!(matches!(
            open_truncate_nofollow_regular(dir.path(), 0o600),
            Err(SecureFileError::NotRegularFile(_))
        ));
    }

    #[test]
    fn nonblocking_open_takes_a_regular_file_and_follows_a_symlink() {
        let dir = TempDir::new().expect("create temp dir");
        let file = dir.path().join("doc.json");
        std::fs::write(&file, b"content").expect("write file");
        let (_, meta) = open_regular_nonblocking(&file).expect("open");
        assert_eq!(meta.len(), 7);
        let link = dir.path().join("link.json");
        symlink(&file, &link).expect("create symlink");
        assert!(open_regular_nonblocking(&link).is_ok());
        assert_eq!(
            open_regular_nonblocking(&dir.path().join("absent"))
                .expect_err("missing")
                .kind(),
            std::io::ErrorKind::NotFound
        );
    }

    #[test]
    fn nonblocking_open_refuses_a_directory_and_a_device_at_once() {
        let dir = TempDir::new().expect("create temp dir");
        for path in [dir.path(), Path::new("/dev/zero")] {
            let error = open_regular_nonblocking(path).expect_err("not a regular file");
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput, "{path:?}");
            assert_eq!(error.to_string(), "not a regular file", "{path:?}");
        }
    }

    #[test]
    fn secure_load_refuses_a_directory_and_a_device() {
        let dir = TempDir::new().expect("create temp dir");
        for path in [dir.path(), Path::new("/dev/zero")] {
            assert!(
                matches!(
                    load_secure_file(path),
                    Err(SecureFileError::NotRegularFile(_))
                ),
                "{path:?}"
            );
        }
    }

    /// A blocking open of a FIFO with no writer (or, opened to write, no
    /// reader) never returns. Run on its own thread: only a deadline outside
    /// the open turns a lost `O_NONBLOCK` into a failure instead of a hang.
    #[test]
    fn no_open_waits_on_a_fifo() {
        let dir = TempDir::new().expect("create temp dir");
        let fifo = dir.path().join("fifo");
        nix::unistd::mkfifo(&fifo, nix::sys::stat::Mode::S_IRWXU).expect("mkfifo");
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send((
                open_regular_nonblocking(&fifo)
                    .map(|_| ())
                    .map_err(|e| e.to_string()),
                load_bounded_file(&fifo, 64).map_err(|e| e.to_string()),
                load_secure_file(&fifo).map_err(|e| e.to_string()),
                open_truncate_nofollow_regular(&fifo, 0o600)
                    .map(|_| ())
                    .map_err(|e| e.to_string()),
            ));
        });
        let (open, load, secure, truncate) = rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("no open waits for a writer");
        assert_eq!(open, Err("not a regular file".to_string()));
        assert!(load.is_err_and(|e| e.starts_with("not a regular file")));
        assert!(secure.is_err_and(|e| e.starts_with("not a regular file")));
        assert!(truncate.is_err_and(|e| e.starts_with("not a regular file")));
    }
}
