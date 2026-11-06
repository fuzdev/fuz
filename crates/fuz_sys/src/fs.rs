//! Filesystem helpers for crash-safe writes.
//!
//! A few operations show up over and over in the artifact / release code:
//!
//! - **Atomic file write**: write to `.tmp`, fsync the content, rename to
//!   final, fsync the parent directory. Without the *parent* fsync the
//!   rename can be lost across a host crash even though the contents are
//!   durable.
//! - **Atomic symlink replace**: the same temp-sibling + rename + parent
//!   fsync dance for a *symlink* rather than file contents (which
//!   `write_atomic` can't cover) — the `current` / `bin/<name>` swaps.
//! - **Parent-directory fsync** as a standalone op (e.g. after a `rename`
//!   the caller did itself), and `parent_dir`, the parent as a path that can
//!   be opened — a bare file name's is `.`, not the empty path.
//! - **Moded directory create**: `create_dir_all` with the mode *stated*
//!   rather than inherited from the process umask, for the directories a
//!   program owns.
//! - **No-follow classification**: what is at a path without following a
//!   symlink there (`probe_real_dir`, `is_real_dir`, `is_real_file`), and
//!   whether a name is one plain path component (`is_plain_file_name`) — what
//!   the artifact and tool stores classify and address their entries with.
//!
//! - **Stale staging sweep**: remove crash-leaked `<prefix>*` staging dirs
//!   that have gone [`STALE_STAGING_DIR_AGE`] without a write
//!   (`sweep_stale_staging_dirs`) — what an install's own `CleanupGuard`
//!   cannot do once a SIGKILL or an aborting panic skips it.
//!
//! These helpers replace several hand-rolled copies of the same dance.
//! They intentionally stay narrow: `io::Result` only, no domain errors —
//! callers translate to their own error types.

#![allow(clippy::missing_errors_doc)] // io::Result is self-explanatory

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// Bytes free on the filesystem holding `path`, for an unprivileged user.
///
/// Thin wrapper over `nix::sys::statvfs::statvfs` (`blocks_available *
/// fragment_size`). `path` must exist; mount points lacking statvfs support
/// (exotic FUSE, some procfs paths) surface their errno as `Err`.
///
/// Callers use this for a disk-budget preflight — reject a write that wouldn't
/// fit (plus headroom) before starting, turning a mid-write ENOSPC into a clean
/// early rejection. It's a hint, not a reservation: the space can change between
/// the probe and the write, so the ENOSPC path stays the real backstop.
pub fn free_space_bytes(path: &Path) -> io::Result<u64> {
    let stat = nix::sys::statvfs::statvfs(path).map_err(io::Error::from)?;
    // `blocks_available` is "blocks free for unprivileged users"; `fragment_size`
    // is the fundamental block size. Their nix return types are platform aliases
    // (u64 on Linux glibc, u32 on macOS) — `try_into → u64` is a no-op on Linux
    // (hence the clippy allow) but actually narrows on macOS. `unwrap_or(u64::MAX)`
    // keeps us correct if nix ever widens to i64; saturating multiply guards
    // exabyte-scale FSes.
    #[allow(clippy::useless_conversion)] // try_into is not useless on macOS (u32 → u64)
    let blocks: u64 = stat.blocks_available().try_into().unwrap_or(u64::MAX);
    #[allow(clippy::useless_conversion)]
    let bsize: u64 = stat.fragment_size().try_into().unwrap_or(u64::MAX);
    Ok(blocks.saturating_mul(bsize))
}

/// `create_dir_all` at an explicit `mode` — the mode is **set**, not inherited.
///
/// `std::fs::create_dir_all` opens with `mkdir(path, 0o777)`, which POSIX masks
/// by the process umask, so a plain `create_dir_all` lands whatever mode the
/// invoking shell happened to carry — `0o755` under the usual `umask 022`, but
/// `0o777` under `umask 000` (routine in containers and CI images). For a
/// directory that is part of a program's own private tree that is a silent
/// security dependency on the environment, so state the mode instead.
///
/// The mode applies to **every** level this call creates (`recursive(true)` +
/// `DirBuilderExt::mode`), and pre-existing directories are left alone — the
/// call is a no-op on an already-present path, mode included, so it never
/// re-tightens a directory the user deliberately loosened.
///
/// Use it wherever a `create_dir_all` lands a directory the program owns; the
/// asynchronous equivalent is `tokio::fs::DirBuilder` with the same two
/// settings.
pub fn create_dir_all_mode(path: &Path, mode: u32) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;

    fs::DirBuilder::new()
        .mode(mode)
        .recursive(true)
        .create(path)
}

/// Fsync the directory at `path` so a prior `rename` into or within it is
/// durable across a host crash.
///
/// POSIX rename is atomic with respect to readers, but a power loss before
/// the directory's own dirent updates hit disk can lose the rename. This is
/// the standard "fsync the parent" you need after every atomic write.
pub fn fsync_dir(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

/// The directory `path` is in, as a path that can be opened: `path.parent()`,
/// with the empty parent of a bare file name read as `.`.
///
/// `Path::new("key").parent()` is `Some("")`, which names the working
/// directory when a file name is joined to it and names nothing when it is
/// opened, created, or fsynced itself. A writer that takes a path from a
/// caller goes through this, so a bare file name works as `./name` does.
///
/// `None` for a path with no parent: `/`, or the empty path.
#[must_use]
pub fn parent_dir(path: &Path) -> Option<&Path> {
    path.parent().map(|parent| {
        if parent.as_os_str().is_empty() {
            Path::new(".")
        } else {
            parent
        }
    })
}

/// Atomically write `content` to `path` with the given Unix mode.
///
/// Discipline: write `<path>.tmp.<pid>` → fsync the file → rename to
/// `path` → fsync the parent directory. The fixed `.tmp.<pid>` suffix
/// keeps the temp name predictable within the same dir without colliding
/// across processes. (Within a process, callers shouldn't be writing to
/// the same `path` concurrently — that's their lock to take.) A bare file
/// name is written in the working directory ([`parent_dir`]).
///
/// Use this for non-secret payloads (meta.json, history.json, etc.). For
/// keys and credentials use [`crate::secure_file::write_secure_file`] —
/// that path has extra TOCTOU and symlink checks this helper deliberately
/// omits.
pub fn write_atomic(path: &Path, content: &[u8], mode: u32) -> io::Result<()> {
    let parent = parent_dir(path)
        .ok_or_else(|| io::Error::other(format!("path has no parent: {}", path.display())))?;
    let file_name = path
        .file_name()
        .ok_or_else(|| io::Error::other(format!("path has no file name: {}", path.display())))?
        .to_string_lossy()
        .into_owned();
    let tmp = parent.join(format!(".{}.tmp.{}", file_name, std::process::id()));

    // Best-effort clean of stale temp from a previous crash. Any error
    // here surfaces below when we try to create_new the same path.
    let _ = fs::remove_file(&tmp);

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true) // O_EXCL: fail loudly if a temp racer exists
        .mode(mode)
        .open(&tmp)?;
    if let Err(e) = file.write_all(content).and_then(|()| file.sync_all()) {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    drop(file);

    if let Err(e) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }

    fsync_dir(parent)
}

/// Atomically create or replace the symlink at `link_path` pointing to
/// `target`, durable across a host crash.
///
/// The symlink analogue of [`write_atomic`] (which covers file *contents*,
/// not links): create a `.<name>.tmp.<pid>` sibling symlink → `rename` it
/// over `link_path` → fsync the parent directory. The rename means a
/// concurrent reader (a shell PATH lookup, a tool resolving `current`) never
/// sees `link_path` missing; the parent fsync means the swap survives a power
/// loss — the durability the hand-rolled copies kept dropping.
///
/// `target` is stored verbatim, so the caller controls whether the link is
/// relative (relocatable) or absolute. Use this for authoritative links a
/// tool resolves on every run (the `current` switch, `bin/<name>` entries).
pub fn replace_symlink_atomic(target: &Path, link_path: &Path) -> io::Result<()> {
    let parent = parent_dir(link_path).ok_or_else(|| {
        io::Error::other(format!("link path has no parent: {}", link_path.display()))
    })?;
    let file_name = link_path
        .file_name()
        .ok_or_else(|| {
            io::Error::other(format!(
                "link path has no file name: {}",
                link_path.display()
            ))
        })?
        .to_string_lossy()
        .into_owned();
    let tmp = parent.join(format!(".{}.tmp.{}", file_name, std::process::id()));

    // Best-effort: clear any stale temp from a previous crash.
    let _ = fs::remove_file(&tmp);

    std::os::unix::fs::symlink(target, &tmp)?;
    if let Err(e) = fs::rename(&tmp, link_path) {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }

    fsync_dir(parent)
}

/// What [`probe_real_dir`] found at a path, read without following a symlink
/// there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirProbe {
    /// Nothing at the path (`ENOENT`). A dangling symlink is **not** absent —
    /// it is [`NotDir`](Self::NotDir) with [`NonDirKind::Symlink`].
    Absent,
    /// A real directory, not a symlink to one.
    RealDir,
    /// Something other than a real directory.
    NotDir(NonDirKind),
}

/// The kind of a non-directory entry [`probe_real_dir`] found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonDirKind {
    /// A symlink — live or dangling, whatever it points at.
    Symlink,
    /// A regular file.
    File,
    /// A FIFO, socket, or device node.
    Other,
}

impl NonDirKind {
    /// The kind as a noun phrase for messages: `a symlink`, `a regular file`,
    /// `a special file`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Symlink => "a symlink",
            Self::File => "a regular file",
            Self::Other => "a special file",
        }
    }
}

impl std::fmt::Display for NonDirKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Classify the entry at `path` as absent, a real directory, or something else,
/// without following a symlink at `path`.
///
/// One `symlink_metadata` call. The distinction a `Path::exists` /
/// `Path::is_dir` pair cannot make is the reason to use it: both follow a link,
/// so a dangling link reads as absent (and a later `rename` onto it fails
/// `ENOTDIR`), and a link to a directory reads as that directory (and every
/// later read through the path goes wherever the link points). Here a symlink is
/// [`NonDirKind::Symlink`] whether or not its target exists.
///
/// Only the final component is inspected; the parents are resolved as usual.
/// Pass the bare entry path: a trailing `/` or `/.` (`…/entry/`, `…/entry/.`)
/// makes the kernel resolve *through* the final component, so a symlink there
/// is followed and its target classified instead.
///
/// # Errors
///
/// Any `lstat` error other than `ENOENT` (which is [`DirProbe::Absent`]) — e.g.
/// `EACCES` on a parent, or `ENOTDIR` when a parent is a file.
pub fn probe_real_dir(path: &Path) -> io::Result<DirProbe> {
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(DirProbe::Absent),
        Err(e) => return Err(e),
    };
    let file_type = meta.file_type();
    Ok(if file_type.is_symlink() {
        DirProbe::NotDir(NonDirKind::Symlink)
    } else if file_type.is_dir() {
        DirProbe::RealDir
    } else if file_type.is_file() {
        DirProbe::NotDir(NonDirKind::File)
    } else {
        DirProbe::NotDir(NonDirKind::Other)
    })
}

/// True iff `name` is a single plain path component: non-empty, no `/`, and
/// neither `.` nor `..`.
///
/// The check for a name that becomes one entry inside a directory —
/// `dir.join(name)` must name a child of `dir`, never `dir` itself, its parent,
/// or something deeper. It inspects the bytes as given rather than
/// `Path::components`, which drops a trailing `/` or `/.` (`v1-a/` would pass
/// as `v1-a`, and the kernel resolves such a path *through* the entry).
#[must_use]
pub fn is_plain_file_name(name: &std::ffi::OsStr) -> bool {
    use std::os::unix::ffi::OsStrExt;
    let bytes = name.as_bytes();
    !bytes.is_empty() && !bytes.contains(&b'/') && bytes != b"." && bytes != b".."
}

/// True iff `path` is a *real* directory — `symlink_metadata` (no-follow), so a
/// symlink (even one pointing at a directory) is **not** accepted.
///
/// The no-follow half of the fs-safety vocabulary (alongside [`write_atomic`] /
/// [`secure_file`](crate::secure_file)): callers that must refuse to traverse or
/// write *through* a symlinked path use this rather than `Path::is_dir`, which
/// follows links. The boolean form of [`probe_real_dir`], with any `lstat`
/// error read as `false`.
#[must_use]
pub fn is_real_dir(path: &Path) -> bool {
    matches!(probe_real_dir(path), Ok(DirProbe::RealDir))
}

/// True iff `path` is a *real* regular file — `symlink_metadata` (no-follow), so
/// a symlink (even one pointing at a file) is **not** accepted.
///
/// See [`is_real_dir`]; this is the file-typed companion.
#[must_use]
pub fn is_real_file(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|m| m.is_file())
}

/// Add the execute bits (`0o111`) to `path`, refusing to follow a symlink.
///
/// Opens `path` with `O_NOFOLLOW` and `fchmod`s the resulting descriptor (via
/// `File::set_permissions`), so the stat-and-chmod operate on one inode with no
/// TOCTOU window — a raced symlink can't redirect the chmod onto a file outside
/// the intended one. The no-follow-and-mutate companion to the no-follow
/// predicate [`is_real_file`]: prefer this over a `is_real_file`-check-then-
/// `set_permissions` pair, which reopens the path and re-follows symlinks.
///
/// Returns `Ok(false)` — a benign skip — when `path` is a symlink (`ELOOP`),
/// missing (`ENOENT`), or not a regular file; `Ok(true)` when the bits were set.
///
/// # Errors
///
/// Returns any other open / stat / `fchmod` error (e.g. `EACCES`).
pub fn add_exec_bit_no_follow(path: &Path) -> io::Result<bool> {
    use std::os::unix::fs::PermissionsExt;

    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(file) => file,
        // A raced symlink (`ELOOP`) or a vanished target (`ENOENT`) is a benign
        // skip, matching the prior `is_real_file`-guard behavior; anything else
        // (e.g. `EACCES`) is a real error.
        Err(e) if matches!(e.raw_os_error(), Some(libc::ELOOP | libc::ENOENT)) => return Ok(false),
        Err(e) => return Err(e),
    };
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Ok(false); // a directory / fifo / etc. — skip, never chmod
    }
    let mut perms = meta.permissions();
    perms.set_mode(perms.mode() | 0o111);
    file.set_permissions(perms)?;
    Ok(true)
}

/// RAII guard that removes a directory tree on drop unless [`defuse`]d.
///
/// The shape behind every "build into a temp dir, then atomically swap it into
/// place" flow: hold the guard while populating the temp tree, and `defuse` it
/// only once the swap has succeeded. An early return, a `?`, or a panic before
/// `defuse` removes the half-built tree, so a failed operation never strands a
/// partial directory.
///
/// For fuzi's `node_modules` materialization the guard is **security-load-bearing,
/// not merely tidy**: extraction writes into the guarded staging tree (a fresh,
/// fuzi-owned `.…installing-<rand>` dir) and only an atomic rename publishes it,
/// so a crash or hostile tarball can never leave a partially-materialized
/// `node_modules` that a later run would trust.
///
/// [`defuse`]: CleanupGuard::defuse
#[derive(Debug)]
pub struct CleanupGuard {
    path: Option<PathBuf>,
}

impl CleanupGuard {
    /// Guard `path`: it is removed (recursively, best-effort) on drop unless
    /// [`defuse`](CleanupGuard::defuse)d first.
    #[must_use]
    pub const fn new(path: PathBuf) -> Self {
        Self { path: Some(path) }
    }

    /// Prevent cleanup on drop. Call once the guarded tree has been published
    /// (e.g. atomically renamed into place) and must survive.
    pub fn defuse(mut self) {
        self.path = None;
    }
}

impl Drop for CleanupGuard {
    fn drop(&mut self) {
        if let Some(ref path) = self.path {
            let _ = fs::remove_dir_all(path);
        }
    }
}

/// How long a staging dir must go with no write before
/// [`sweep_stale_staging_dirs`] takes it for a crashed run's.
pub const STALE_STAGING_DIR_AGE: Duration = Duration::from_secs(3600);

/// Remove the `<prefix>*` staging dirs directly under `dir` whose last write is
/// older than [`STALE_STAGING_DIR_AGE`]; returns how many were removed.
///
/// For staging dirs that no lock guards, where a concurrent run's live one
/// sits beside the ones crashed runs leaked, so age is what tells them apart.
/// The age is taken from the newest mtime of the staging dir **and its direct
/// entries**, not the dir alone: a run that streams a download into a file
/// inside its staging dir moves that file's mtime, not its directory's, so a
/// slow download would otherwise read as abandoned. A run that has written
/// nothing for the whole window is taken as dead.
///
/// No-follow throughout: entry metadata is `lstat`, and only a real directory
/// is removed — a symlink or file under the prefix is left alone, and
/// `remove_dir_all` does not traverse links inside.
///
/// Best-effort and silent: an unreadable `dir` (one that does not exist yet
/// included), entry, or mtime skips it, and a failed removal is left for the
/// next sweep.
pub fn sweep_stale_staging_dirs(dir: &Path, prefix: &str) -> usize {
    sweep_stale_staging_dirs_at(dir, prefix, SystemTime::now())
}

/// [`sweep_stale_staging_dirs`] against a given `now`.
fn sweep_stale_staging_dirs_at(dir: &Path, prefix: &str, now: SystemTime) -> usize {
    let Ok(entries) = fs::read_dir(dir) else {
        return 0;
    };
    let mut removed = 0;
    for entry in entries.flatten() {
        if !entry.file_name().to_string_lossy().starts_with(prefix) {
            continue;
        }
        // `DirEntry::metadata` does not follow a symlink
        let Ok(metadata) = entry.metadata() else {
            continue;
        };
        if !metadata.is_dir() {
            continue;
        }
        let path = entry.path();
        let Some(last_write) = last_write_time(&path, &metadata) else {
            continue;
        };
        if now
            .duration_since(last_write)
            .is_ok_and(|age| age > STALE_STAGING_DIR_AGE)
            && fs::remove_dir_all(&path).is_ok()
        {
            removed += 1;
        }
    }
    removed
}

/// The newest mtime among the staging dir `dir` and its direct entries
/// (`lstat`), or `None` when any of them is unreadable — an entry that can't
/// be dated is not proof of a dead run.
fn last_write_time(dir: &Path, metadata: &fs::Metadata) -> Option<SystemTime> {
    let mut newest = metadata.modified().ok()?;
    for entry in fs::read_dir(dir).ok()? {
        let modified = entry.ok()?.metadata().ok()?.modified().ok()?;
        newest = newest.max(modified);
    }
    Some(newest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    /// Just past the stale window, measured from now.
    fn past_the_window() -> SystemTime {
        SystemTime::now() + STALE_STAGING_DIR_AGE + Duration::from_secs(60)
    }

    /// A staging dir with no write for longer than the window is swept; a
    /// younger one, one whose download is still being written, another
    /// prefix's dir, and anything under the prefix that is not a real dir are
    /// kept.
    #[test]
    fn sweep_stale_staging_dirs_takes_only_old_real_dirs_under_the_prefix() {
        let dir = TempDir::new().expect("temp dir");
        let outside = TempDir::new().expect("temp dir");
        let d = dir.path();
        let later = past_the_window();

        fs::create_dir(d.join(".installing-dead")).unwrap();
        fs::write(d.join(".installing-dead/fuzf"), b"partial").unwrap();
        fs::create_dir(d.join("v1-abc")).unwrap();
        fs::create_dir(d.join(".other-old")).unwrap();
        fs::write(d.join(".installing-file"), b"not a dir").unwrap();
        std::os::unix::fs::symlink(outside.path(), d.join(".installing-link")).unwrap();
        fs::write(outside.path().join("keep"), b"outside").unwrap();
        // live: the dir is as old as the dead one, but the tarball streaming
        // into it was written moments before `later`
        fs::create_dir(d.join(".installing-live")).unwrap();
        File::create(d.join(".installing-live/.artifact-download.tar.gz"))
            .unwrap()
            .set_modified(later - Duration::from_secs(60))
            .unwrap();

        // nothing is old yet
        assert_eq!(
            sweep_stale_staging_dirs_at(d, ".installing-", SystemTime::now()),
            0
        );
        assert!(d.join(".installing-dead").exists());

        assert_eq!(sweep_stale_staging_dirs_at(d, ".installing-", later), 1);
        assert!(!d.join(".installing-dead").exists());
        assert!(d.join(".installing-live").is_dir());
        assert!(d.join("v1-abc").is_dir());
        assert!(d.join(".other-old").is_dir());
        assert!(d.join(".installing-file").is_file());
        assert!(d.join(".installing-link").symlink_metadata().is_ok());
        assert!(outside.path().join("keep").exists());
    }

    /// The self fetch's shape: `.downloading-*` dirs in the artifacts dir,
    /// the tarball streamed into the dir. A finished-or-crashed one is swept;
    /// one still downloading is kept though the dir's own mtime is old.
    #[test]
    fn sweep_stale_staging_dirs_keeps_a_download_still_streaming() {
        let dir = TempDir::new().expect("temp dir");
        let d = dir.path();
        let later = past_the_window();

        fs::create_dir(d.join(".downloading-crashed")).unwrap();
        fs::write(
            d.join(".downloading-crashed/.artifact-download.tar.gz"),
            b"half",
        )
        .unwrap();
        fs::create_dir(d.join(".downloading-live")).unwrap();
        File::create(d.join(".downloading-live/.artifact-download.tar.gz"))
            .unwrap()
            .set_modified(later)
            .unwrap();

        assert_eq!(sweep_stale_staging_dirs_at(d, ".downloading-", later), 1);
        assert!(!d.join(".downloading-crashed").exists());
        assert!(d.join(".downloading-live").is_dir());
    }

    #[test]
    fn sweep_stale_staging_dirs_tolerates_a_missing_dir() {
        let dir = TempDir::new().expect("temp dir");
        let missing = dir.path().join("absent");
        assert_eq!(
            sweep_stale_staging_dirs_at(&missing, ".installing-", past_the_window()),
            0
        );
        assert_eq!(sweep_stale_staging_dirs(&missing, ".installing-"), 0);
    }

    #[test]
    fn create_dir_all_mode_states_the_mode_at_every_level_it_creates() {
        let dir = TempDir::new().expect("temp dir");
        let leaf = dir.path().join("a/b/c");
        create_dir_all_mode(&leaf, 0o700).expect("create nested");

        // Every level this call created carries the stated mode, not
        // `0o777 & !umask` — which under the runner's umask would be 0775,
        // 0755, or 0777, never 0700.
        for level in [dir.path().join("a"), dir.path().join("a/b"), leaf.clone()] {
            assert_eq!(
                fs::metadata(&level).expect("stat").permissions().mode() & 0o777,
                0o700,
                "{level:?} must carry the stated mode"
            );
        }

        // A pre-existing directory is left exactly as it was: the call is a
        // no-op, so it never re-tightens a mode the user chose.
        fs::set_permissions(&leaf, fs::Permissions::from_mode(0o755)).expect("chmod 755");
        create_dir_all_mode(&leaf, 0o700).expect("second create is a no-op");
        assert_eq!(
            fs::metadata(&leaf).expect("stat").permissions().mode() & 0o777,
            0o755,
            "an existing directory keeps its mode"
        );
    }

    #[test]
    fn free_space_bytes_returns_nonzero_for_tmp() {
        // /tmp is guaranteed to exist on every supported platform and is
        // backed by a real filesystem with statvfs support.
        let bytes = free_space_bytes(Path::new("/tmp")).expect("statvfs /tmp");
        assert!(bytes > 0, "/tmp should report > 0 bytes available");
    }

    #[test]
    fn free_space_bytes_on_missing_path_errors() {
        let result = free_space_bytes(Path::new("/nonexistent/path/should/not/exist/fuz"));
        assert!(result.is_err());
    }

    #[test]
    fn parent_dir_reads_a_bare_name_as_the_working_directory() {
        for (path, expected) in [
            ("bare", Some(".")),
            ("./bare", Some(".")),
            ("dir/name", Some("dir")),
            ("/abs/name", Some("/abs")),
            ("/name", Some("/")),
            ("../name", Some("..")),
            ("/", None),
            ("", None),
        ] {
            assert_eq!(
                parent_dir(Path::new(path)),
                expected.map(Path::new),
                "{path:?}"
            );
        }
    }

    #[test]
    fn fsync_dir_on_existing_dir_succeeds() {
        let dir = TempDir::new().expect("temp dir");
        fsync_dir(dir.path()).expect("fsync dir");
    }

    #[test]
    fn real_dir_and_file_predicates_do_not_follow_symlinks() {
        let dir = TempDir::new().expect("temp dir");
        let real_file = dir.path().join("f");
        fs::write(&real_file, b"x").expect("write file");
        let real_dir = dir.path().join("d");
        fs::create_dir(&real_dir).expect("create dir");
        // Symlinks pointing at a real file / dir must NOT be accepted (no-follow).
        let link_to_file = dir.path().join("lf");
        let link_to_dir = dir.path().join("ld");
        std::os::unix::fs::symlink(&real_file, &link_to_file).expect("symlink file");
        std::os::unix::fs::symlink(&real_dir, &link_to_dir).expect("symlink dir");

        assert!(is_real_file(&real_file));
        assert!(!is_real_file(&link_to_file)); // symlink-to-file → rejected
        assert!(!is_real_file(&real_dir));
        assert!(!is_real_file(&dir.path().join("absent")));

        assert!(is_real_dir(&real_dir));
        assert!(!is_real_dir(&link_to_dir)); // symlink-to-dir → rejected
        assert!(!is_real_dir(&real_file));
    }

    #[test]
    fn is_plain_file_name_accepts_one_component_only() {
        use std::ffi::OsStr;
        for ok in ["v1-abc", "fuzd", ".hidden", "a..b", "..."] {
            assert!(is_plain_file_name(OsStr::new(ok)), "{ok:?}");
        }
        for bad in ["", ".", "..", "../x", "a/b", "a/", "a/.", "/a", "/"] {
            assert!(!is_plain_file_name(OsStr::new(bad)), "{bad:?}");
        }
    }

    #[test]
    fn probe_real_dir_classifies_without_following_a_symlink() {
        let dir = TempDir::new().expect("temp dir");
        let real_dir = dir.path().join("d");
        fs::create_dir(&real_dir).expect("create dir");
        let real_file = dir.path().join("f");
        fs::write(&real_file, b"x").expect("write file");
        let link_to_dir = dir.path().join("ld");
        std::os::unix::fs::symlink(&real_dir, &link_to_dir).expect("symlink dir");
        let dangling = dir.path().join("dangling");
        std::os::unix::fs::symlink(dir.path().join("nowhere"), &dangling).expect("symlink");
        let fifo = dir.path().join("fifo");
        nix::unistd::mkfifo(&fifo, nix::sys::stat::Mode::S_IRWXU).expect("mkfifo");

        assert_eq!(probe_real_dir(&real_dir).unwrap(), DirProbe::RealDir);
        assert_eq!(
            probe_real_dir(&dir.path().join("absent")).unwrap(),
            DirProbe::Absent
        );
        // A link to a real directory is a symlink, not the directory.
        assert_eq!(
            probe_real_dir(&link_to_dir).unwrap(),
            DirProbe::NotDir(NonDirKind::Symlink)
        );
        // A dangling link is a symlink, not absent — the case `Path::exists` gets
        // wrong.
        assert_eq!(
            probe_real_dir(&dangling).unwrap(),
            DirProbe::NotDir(NonDirKind::Symlink)
        );
        assert!(
            !dangling.exists(),
            "precondition: exists() follows the link"
        );
        assert_eq!(
            probe_real_dir(&real_file).unwrap(),
            DirProbe::NotDir(NonDirKind::File)
        );
        assert_eq!(
            probe_real_dir(&fifo).unwrap(),
            DirProbe::NotDir(NonDirKind::Other)
        );
        // A parent that is a file is an error, not absence.
        let err = probe_real_dir(&real_file.join("child")).expect_err("ENOTDIR");
        assert_eq!(err.raw_os_error(), Some(libc::ENOTDIR));

        assert_eq!(NonDirKind::Symlink.to_string(), "a symlink");
    }

    #[test]
    fn add_exec_bit_no_follow_sets_bit_and_refuses_to_chmod_through_a_symlink() {
        let dir = TempDir::new().expect("temp dir");

        // A real 0644 regular file gains the exec bits, preserving the rest.
        let bin = dir.path().join("bin");
        fs::write(&bin, b"#!/bin/sh\n").expect("write bin");
        fs::set_permissions(&bin, fs::Permissions::from_mode(0o644)).expect("chmod 644");
        assert!(add_exec_bit_no_follow(&bin).expect("chmod bin"));
        assert_eq!(
            fs::metadata(&bin).expect("stat bin").permissions().mode() & 0o777,
            0o755,
            "exec bits added, other mode bits preserved"
        );

        // A symlink is a benign skip (`Ok(false)`) and — the security property —
        // its *target* is never chmod-ed through the link.
        let target = dir.path().join("target");
        fs::write(&target, b"x").expect("write target");
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).expect("chmod 600");
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&target, &link).expect("symlink");
        assert!(
            !add_exec_bit_no_follow(&link).expect("symlink → Ok(false)"),
            "a symlink target must be skipped, not followed"
        );
        assert_eq!(
            fs::metadata(&target)
                .expect("stat target")
                .permissions()
                .mode()
                & 0o777,
            0o600,
            "the symlink's target must NOT have been chmod-ed through the link"
        );

        // A missing path is a benign skip too.
        assert!(!add_exec_bit_no_follow(&dir.path().join("absent")).expect("missing → Ok(false)"));
    }

    #[test]
    fn cleanup_guard_removes_dir_on_drop() {
        let dir = TempDir::new().expect("temp dir");
        let guarded = dir.path().join("guarded");
        fs::create_dir(&guarded).expect("create dir");
        assert!(guarded.exists());
        {
            let _guard = CleanupGuard::new(guarded.clone());
            assert!(guarded.exists());
        }
        assert!(!guarded.exists(), "drop should remove the guarded tree");
    }

    #[test]
    fn cleanup_guard_defuse_keeps_dir() {
        let dir = TempDir::new().expect("temp dir");
        let guarded = dir.path().join("guarded");
        fs::create_dir(&guarded).expect("create dir");
        {
            CleanupGuard::new(guarded.clone()).defuse();
        }
        assert!(guarded.exists(), "defuse should preserve the tree");
    }

    #[test]
    fn fsync_dir_on_missing_path_errors() {
        let result = fsync_dir(Path::new("/nonexistent/path/should/not/exist/fuz"));
        assert!(result.is_err());
    }

    /// `mode` is a create-time **ceiling**, not a guarantee: it reaches the
    /// file through `O_CREAT, mode`, which POSIX masks by the process umask.
    ///
    /// So the property that holds under every umask is that no bit *outside*
    /// `mode` survives. A mode with no group or other bits additionally lands
    /// exactly, since no realistic umask masks an owner bit — which is why
    /// [`crate::SECURE_FILE_MODE`], the mode every secure-file caller passes,
    /// is safe to assert on the nose.
    ///
    /// Asserting the requested `0o644` exactly would hold at `umask 022`,
    /// `002`, and `000` and fail at `077` (`0o600`), claiming a guarantee this
    /// helper does not make.
    #[test]
    fn write_atomic_creates_with_mode() {
        let dir = TempDir::new().expect("temp dir");

        let ceiling = dir.path().join("ceiling.json");
        write_atomic(&ceiling, b"hello", 0o644).expect("write");
        let landed = fs::metadata(&ceiling)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            landed & !0o644,
            0,
            "no bit outside the requested mode may survive, got {landed:o}"
        );
        assert_eq!(fs::read(&ceiling).expect("read"), b"hello");

        let secure = dir.path().join("secure.json");
        write_atomic(&secure, b"hello", crate::SECURE_FILE_MODE).expect("write");
        assert_eq!(
            fs::metadata(&secure)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777,
            crate::SECURE_FILE_MODE,
            "an owner-only mode reaches the file exactly under every umask"
        );
    }

    #[test]
    fn write_atomic_overwrites_existing() {
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join("payload.json");
        write_atomic(&path, b"first", 0o644).expect("first write");
        write_atomic(&path, b"second", 0o644).expect("second write");
        assert_eq!(fs::read(&path).expect("read"), b"second");
    }

    #[test]
    fn write_atomic_leaves_no_temp_on_success() {
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join("payload.json");
        write_atomic(&path, b"data", 0o644).expect("write");
        // The dir should contain exactly one entry: the final file.
        let entries: Vec<_> = fs::read_dir(dir.path())
            .expect("read dir")
            .map(|e| e.expect("dirent").file_name())
            .collect();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0], "payload.json");
    }

    #[test]
    fn replace_symlink_atomic_creates_and_replaces() {
        let dir = TempDir::new().expect("temp dir");
        let link = dir.path().join("current");
        replace_symlink_atomic(Path::new("artifacts/a"), &link).expect("create link");
        assert_eq!(
            fs::read_link(&link).expect("read link"),
            PathBuf::from("artifacts/a")
        );
        // Replacing an existing link points it at the new target, atomically.
        replace_symlink_atomic(Path::new("artifacts/b"), &link).expect("replace link");
        assert_eq!(
            fs::read_link(&link).expect("read link"),
            PathBuf::from("artifacts/b")
        );
        // No temp left behind.
        let entries: Vec<_> = fs::read_dir(dir.path())
            .expect("read dir")
            .map(|e| e.expect("dirent").file_name())
            .collect();
        assert_eq!(entries, ["current"]);
    }
}
