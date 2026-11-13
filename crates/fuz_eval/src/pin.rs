//! Pinning the `fgro` binary: open it once, verify its blake3 against an
//! expected pin, and hold the descriptor that was verified so the spawn execs
//! those bytes rather than whatever the path names by then.
//!
//! **The open.** [`fuz_sys::secure_file::open_nofollow_regular`]: read-only and
//! close-on-exec, `O_NOFOLLOW` on the final component (a symlink there is refused
//! during the open, with no window), and a regular-file check on the descriptor.
//! The final component is the binary itself, so the operator names the real file
//! rather than a link to it; directories above it resolve as usual, links
//! included. Canonicalizing first would accept a link and then open its target by
//! a second lookup, which is the window the no-follow open closes. The first four
//! bytes are then read through the descriptor and must be the ELF magic. A `#!`
//! script can't run through a close-on-exec descriptor: `execve` succeeds and
//! starts the interpreter with the `/proc/self/fd` path as its script, but the
//! exec has closed that descriptor by the time the interpreter opens it, so the
//! interpreter fails on its own terms (`/bin/sh` prints `cannot open` and exits
//! `2`) rather than the spawn failing. A wrapper script is refused here instead,
//! named as one, before anything runs. So is a file with its set-user-ID or
//! set-group-ID bit, read from the descriptor's `fstat`
//! ([`FgroProblem::SetId`]): its exec would take ids other than the ones the
//! spawn sets. File capabilities (`security.capability`) are not read: a binary
//! given them by root runs with them. [`fgro_verify`] then checks that
//! `/proc/self/fd/<n>` names the held file, since the exec goes through it.
//!
//! **The stat key.** `fstat` of the held descriptor gives `(dev, ino, size,
//! mtime_ns, ctime_ns)`. A write moves ctime, which no unprivileged process can
//! set, but only to the filesystem's timestamp granularity (a clock tick, not a
//! nanosecond): a same-size rewrite within the tick the key was read in leaves
//! the key as it was. So a key is trusted to name its bytes only once its file
//! has settled — the rule git applies to a racily-clean index entry.
//!
//! **The cache.** Optional: with no directory every pin hashes the whole binary.
//! With one, the key's hex names a file in it holding that same key hex followed
//! by the binary's blake3, both lowercase hex, so an entry answers only for the
//! key it was written for: one renamed onto another key's name is a miss. A hit
//! skips the hash. Anything else is a miss, never an error: a missing entry, a
//! link, a file that isn't the euid's, has another link (`nlink` other than 1),
//! or is group- or other-writable, or contents of the wrong length, for another
//! key, uppercase, or with a trailing newline. On a miss the binary is
//! hashed through the held descriptor and its key read again; a key that moved
//! refuses the pin ([`FgroProblem::ChangedWhileHashing`] — best effort, since a
//! write within one tick may not move it). The entry is written only when the
//! file's mtime and ctime are both at least two seconds before the current time,
//! so any later write lands in a later tick and moves the key; a binary written
//! more recently than that is hashed again on its next pin. Entries are written
//! at `0600` through a uniquely named temp file and a rename, so concurrent
//! writers each land a complete entry and a reader never sees a partial one; a
//! failed write costs only a re-hash next time and is not reported. A clock set
//! backwards across the margin defeats the rule, and so does clock skew: on a
//! network filesystem the timestamps come from the server's clock, so a server
//! more than two seconds behind this host's lets a fresh file look settled.
//!
//! **The cache directory.** The caller's, and it must belong to the effective
//! uid: [`establish_cache_dir`] creates it or holds it to that rule, and a
//! directory that breaks it refuses the pin ([`EvalError::PinCacheDir`]). The
//! entries are then reached through the descriptor it was checked on
//! (`/proc/self/fd/<dir>/<key>`), not by its name again, so a directory swapped
//! in after the check is never read or written. Without `/proc` no entry is read
//! or written, and every pin hashes.
//!
//! **What the pin leaves.** The bytes are verified at the pin, not at the exec.
//! A process that can write the binary (its owner, or root) can change it in
//! place between the two; nothing here locks it. The cache trusts what its
//! directory holds: the directory is the euid's alone, and an entry must be the
//! euid's own file with a single link that no one else can write, so an entry is
//! the euid's own statement.

use std::fs::{File, Metadata};
use std::io::Read as _;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use fuz_sys::secure_file::{SecureFileError, open_nofollow_regular, write_secure_file};

use crate::EvalError;
use crate::run_as::DroppedTo;
use crate::trust_root::effective_uid;

/// The length of a blake3 in lowercase hex.
const BLAKE3_HEX_LEN: usize = 64;

/// The length of a [`StatKey`] in hex ([`StatKey::to_hex`]).
const KEY_HEX_LEN: usize = 16 * 3 + 32 * 2;

/// The length of a cache entry: its key's hex, then the blake3's.
const ENTRY_LEN: usize = KEY_HEX_LEN + BLAKE3_HEX_LEN;

/// How long before the current time a file's mtime and ctime must both be for
/// its hash to be cached: well past a local filesystem's timestamp tick, though
/// not past a network filesystem server's clock skew (module docs § The cache).
const SETTLE_MARGIN_NS: i128 = 2_000_000_000;

/// Why the `fgro` binary can't be pinned ([`EvalError::FgroUnusable`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FgroProblem {
    /// Nothing is at the path.
    NotFound,
    /// The path's final component is a symlink; the pin opens only the real
    /// file.
    Symlink,
    /// The path names a directory, FIFO, socket, or device.
    NotRegularFile,
    /// The file starts with `#!`: a script, whose interpreter can't read it
    /// through the held descriptor.
    Script,
    /// The file is not an ELF binary.
    NotElf,
    /// The file has its set-user-ID or set-group-ID bit, read from the held
    /// descriptor's `fstat`: its exec would take the file owner's or group's
    /// ids rather than the ones it is spawned with. File capabilities
    /// (`security.capability`) are not checked.
    SetId,
    /// The file's stat key moved while it was being hashed: something wrote it
    /// meanwhile. Best effort: a write within one timestamp tick may not move
    /// the key.
    ChangedWhileHashing,
    /// `/proc/self/fd/<n>` doesn't name the held file — `/proc` isn't mounted —
    /// so the binary can't be exec'd through its descriptor.
    ProcUnavailable,
    /// The held file's stat key moved between the pin and the spawn: something
    /// wrote it in between ([`PinnedFgro::check_unchanged`]). Best effort, as
    /// [`FgroProblem::ChangedWhileHashing`] is.
    ChangedSincePin,
}

/// Why a pin cache directory was refused ([`EvalError::PinCacheDir`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinCacheDirProblem {
    /// It was missing and couldn't be created (its parent must exist).
    Uncreatable,
    /// It, or what it was replaced by before the open, is a symlink.
    Symlink,
    /// It is a file, FIFO, socket, or device.
    NotDirectory,
    /// Another user owns it.
    OtherOwner,
    /// Its metadata couldn't be read.
    Unreadable,
    /// It couldn't be opened as a directory without following a link.
    Unopenable,
    /// Others could reach it and its mode couldn't be tightened to `0700`.
    Unrestrictable,
}

/// The `fgro` binary, opened, verified against its pin, and held open.
///
/// The descriptor is close-on-exec; [`exec_path`](Self::exec_path) names it for
/// a spawn, which the kernel resolves before it closes the descriptor, so the
/// verified bytes run. Drop it only after the spawn.
#[derive(Debug)]
pub struct PinnedFgro {
    file: File,
    path: PathBuf,
    blake3: String,
    key: StatKey,
}

impl PinnedFgro {
    /// The path the binary was opened from, as the caller gave it.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The verified blake3 of the binary, 64 lowercase hex characters.
    pub fn blake3(&self) -> &str {
        &self.blake3
    }

    /// The path to exec: `/proc/self/fd/<n>` of the held descriptor. Valid in this
    /// process and in a child between fork and exec, while `self` is alive.
    pub fn exec_path(&self) -> PathBuf {
        fd_path(&self.file)
    }

    /// The error for a failed spawn of [`exec_path`](Self::exec_path), naming the
    /// binary by [`path`](Self::path). The descriptor holds an ELF file and
    /// `/proc` was checked at the pin, so `ENOENT` from `execve` means its
    /// program interpreter (the dynamic loader it names) is missing, and the
    /// message says so. `dropped_to` is the user the spawn dropped to from
    /// root, if it did, which the message names.
    pub fn spawn_error(&self, source: std::io::Error, dropped_to: Option<DroppedTo>) -> EvalError {
        EvalError::FgroSpawn {
            path: self.path.display().to_string(),
            dropped_to,
            source,
        }
    }

    /// `fstat` the held descriptor again and refuse when its stat key is no
    /// longer the one the pin was verified under: the file was written since.
    /// Called right before the spawn, so the window it leaves is the spawn's
    /// own. Best effort: a write within one timestamp tick of the pin may not
    /// move the key (module docs § The stat key).
    ///
    /// # Errors
    ///
    /// [`EvalError::FgroUnusable`] with [`FgroProblem::ChangedSincePin`] when the
    /// key moved, or [`EvalError::FgroIo`] when the `fstat` fails.
    pub fn check_unchanged(&self) -> Result<(), EvalError> {
        let now = self.file.metadata().map_err(|source| EvalError::FgroIo {
            path: self.path.display().to_string(),
            source,
        })?;
        if StatKey::of(&now) == self.key {
            Ok(())
        } else {
            Err(EvalError::FgroUnusable {
                path: self.path.display().to_string(),
                problem: FgroProblem::ChangedSincePin,
            })
        }
    }
}

/// Open `path`, verify its blake3 equals `expected_blake3`, check that
/// `/proc/self/fd` reaches the held descriptor, and return it held open for the
/// spawn.
///
/// `cache_dir` is the stat-keyed hash cache (module docs § The cache, and
/// [`establish_cache_dir`]); `None` hashes every time.
///
/// # Errors
///
/// [`EvalError::InvalidPin`] when `expected_blake3` isn't 64 lowercase hex
/// characters, checked before anything is opened; [`EvalError::FgroUnusable`]
/// for a missing path, a symlinked final component, a non-regular file, a script
/// or other non-ELF file, a set-ID file, a write seen during the hash, or no
/// `/proc`;
/// [`EvalError::FgroIo`] for another open, stat, or read failure;
/// [`EvalError::PinCacheDir`] or [`EvalError::Io`] for a cache directory that
/// breaks its rule or whose owner can't be checked; [`EvalError::PinMismatch`]
/// when the hash isn't the pin.
pub fn fgro_verify(
    path: &Path,
    expected_blake3: &str,
    cache_dir: Option<&Path>,
) -> Result<PinnedFgro, EvalError> {
    if !is_blake3_hex(expected_blake3.as_bytes()) {
        return Err(EvalError::InvalidPin {
            pin: expected_blake3.to_owned(),
        });
    }
    let (file, blake3, key) = open_and_hash(path, cache_dir, SystemTime::now)?;
    if blake3 != expected_blake3 {
        return Err(EvalError::PinMismatch {
            path: path.display().to_string(),
            expected: expected_blake3.to_owned(),
            actual: blake3,
        });
    }
    let held = file.metadata().map_err(|source| EvalError::FgroIo {
        path: path.display().to_string(),
        source,
    })?;
    if let Some(problem) = exec_path_problem(&held, std::fs::metadata(fd_path(&file)).ok()) {
        return Err(EvalError::FgroUnusable {
            path: path.display().to_string(),
            problem,
        });
    }
    Ok(PinnedFgro {
        file,
        path: path.to_path_buf(),
        blake3,
        key,
    })
}

/// The blake3 of the `fgro` binary at `path`, 64 lowercase hex characters — the
/// pin a consumer records, computed the way [`fgro_verify`] checks it, through
/// the same cache.
///
/// # Errors
///
/// As [`fgro_verify`], less [`EvalError::InvalidPin`],
/// [`EvalError::PinMismatch`], and the `/proc` check.
pub fn fgro_blake3(path: &Path, cache_dir: Option<&Path>) -> Result<String, EvalError> {
    open_and_hash(path, cache_dir, SystemTime::now).map(|(_, blake3, _)| blake3)
}

/// `/proc/self/fd/<n>` of `file`.
fn fd_path(file: &File) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()))
}

/// Whether `bytes` is a blake3 as this module writes one: 64 lowercase hex
/// characters.
fn is_blake3_hex(bytes: &[u8]) -> bool {
    bytes.len() == BLAKE3_HEX_LEN
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}

/// What is wrong with exec'ing the held file through `/proc/self/fd/<n>`, given
/// the held descriptor's metadata and what a stat through that path found
/// (`None` when it failed): it must be the same file.
fn exec_path_problem(held: &Metadata, through_proc: Option<Metadata>) -> Option<FgroProblem> {
    match through_proc {
        Some(found) if found.dev() == held.dev() && found.ino() == held.ino() => None,
        _ => Some(FgroProblem::ProcUnavailable),
    }
}

/// The shared open, key, cache lookup, and hash of [`fgro_verify`] and
/// [`fgro_blake3`], returning the held file, its blake3, and the stat key the
/// blake3 was taken under; `now` is the clock the settle rule reads.
fn open_and_hash(
    path: &Path,
    cache_dir: Option<&Path>,
    now: fn() -> SystemTime,
) -> Result<(File, String, StatKey), EvalError> {
    let shown = || path.display().to_string();
    let unusable = |problem| EvalError::FgroUnusable {
        path: shown(),
        problem,
    };
    let (file, meta) = open_nofollow_regular(path).map_err(|error| match error {
        SecureFileError::NotFound(_) => unusable(FgroProblem::NotFound),
        SecureFileError::Symlink(_) => unusable(FgroProblem::Symlink),
        SecureFileError::NotRegularFile(_) => unusable(FgroProblem::NotRegularFile),
        SecureFileError::Io(_, source) => EvalError::FgroIo {
            path: shown(),
            source,
        },
        // `open_nofollow_regular` returns none of the others.
        other => EvalError::FgroIo {
            path: shown(),
            source: std::io::Error::other(other),
        },
    })?;
    let mut magic = [0_u8; 4];
    match file.read_exact_at(&mut magic, 0) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => {}
        Err(source) => {
            return Err(EvalError::FgroIo {
                path: shown(),
                source,
            });
        }
    }
    if magic.starts_with(b"#!") {
        return Err(unusable(FgroProblem::Script));
    }
    if magic != *b"\x7fELF" {
        return Err(unusable(FgroProblem::NotElf));
    }
    if meta.mode() & 0o6000 != 0 {
        return Err(unusable(FgroProblem::SetId));
    }

    let key = StatKey::of(&meta);
    let cache = cache_dir.map(open_cache_dir).transpose()?;
    if let Some(blake3) = cache.as_ref().and_then(|cache| cache.read(key)) {
        return Ok((file, blake3, key));
    }

    let mut hasher = blake3::Hasher::new();
    hasher
        .update_reader(&file)
        .map_err(|source| EvalError::FgroIo {
            path: shown(),
            source,
        })?;
    let blake3 = hasher.finalize().to_hex().to_string();
    let after = file.metadata().map_err(|source| EvalError::FgroIo {
        path: shown(),
        source,
    })?;
    if StatKey::of(&after) != key {
        return Err(unusable(FgroProblem::ChangedWhileHashing));
    }
    if let Some(cache) = &cache
        && key.is_settled(now())
    {
        cache.write(key, &blake3);
    }
    Ok((file, blake3, key))
}

/// What identifies a file's bytes without reading them, once it has settled
/// ([`StatKey::is_settled`]): a write moves `ctime`, to the filesystem's tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct StatKey {
    dev: u64,
    ino: u64,
    size: u64,
    mtime_ns: i128,
    ctime_ns: i128,
}

impl StatKey {
    fn of(meta: &Metadata) -> Self {
        let ns = |secs: i64, nsec: i64| i128::from(secs) * 1_000_000_000 + i128::from(nsec);
        Self {
            dev: meta.dev(),
            ino: meta.ino(),
            size: meta.size(),
            mtime_ns: ns(meta.mtime(), meta.mtime_nsec()),
            ctime_ns: ns(meta.ctime(), meta.ctime_nsec()),
        }
    }

    /// The fixed-width lowercase hex of the five fields in order (a negative time
    /// as its two's complement), the cache entry's file name.
    fn to_hex(self) -> String {
        format!(
            "{:016x}{:016x}{:016x}{:032x}{:032x}",
            self.dev, self.ino, self.size, self.mtime_ns, self.ctime_ns
        )
    }

    /// Whether the file's mtime and ctime both lie at least [`SETTLE_MARGIN_NS`]
    /// before `now`, so that any later write lands in a later timestamp tick and
    /// moves the key. A `now` before the epoch settles nothing.
    fn is_settled(self, now: SystemTime) -> bool {
        let Ok(since_epoch) = now.duration_since(UNIX_EPOCH) else {
            return false;
        };
        let bound = i128::try_from(since_epoch.as_nanos()).unwrap_or(i128::MAX) - SETTLE_MARGIN_NS;
        self.mtime_ns <= bound && self.ctime_ns <= bound
    }
}

/// A pin cache directory, held through the descriptor it was checked on.
#[derive(Debug)]
struct CacheDir {
    held: File,
    euid: u32,
}

impl CacheDir {
    /// The entry for `key`, addressed through the held descriptor.
    fn entry(&self, key: StatKey) -> PathBuf {
        fd_path(&self.held).join(key.to_hex())
    }

    /// The blake3 the entry for `key` holds, or `None` for anything but a regular
    /// file reached without a link, owned by the euid, with one link, writable by
    /// no one else, holding exactly `key`'s hex followed by 64 lowercase hex
    /// characters.
    fn read(&self, key: StatKey) -> Option<String> {
        read_cache_entry(&self.entry(key), &key.to_hex(), self.euid)
    }

    /// Write the entry for `key`, best effort: a failed write costs a re-hash
    /// next time, nothing more. A link at the entry's name is left in place.
    fn write(&self, key: StatKey, blake3: &str) {
        let key_hex = key.to_hex();
        let contents = format!("{key_hex}{blake3}");
        let _ = write_secure_file(&self.entry(key), contents.as_bytes(), 0o600);
    }
}

/// [`CacheDir::read`] of the entry at `entry`, written for the key whose hex is
/// `key_hex`, for the owner `euid`.
fn read_cache_entry(entry: &Path, key_hex: &str, euid: u32) -> Option<String> {
    let (file, meta) = open_nofollow_regular(entry).ok()?;
    if meta.uid() != euid
        || meta.nlink() != 1
        || meta.mode() & 0o022 != 0
        || meta.len() != ENTRY_LEN as u64
    {
        return None;
    }
    let mut bytes = Vec::with_capacity(ENTRY_LEN + 1);
    // One byte past the length, so a file that grew since the stat is a miss.
    (&file)
        .take(ENTRY_LEN as u64 + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() != ENTRY_LEN || &bytes[..KEY_HEX_LEN] != key_hex.as_bytes() {
        return None;
    }
    let blake3 = bytes.split_off(KEY_HEX_LEN);
    if is_blake3_hex(&blake3) {
        String::from_utf8(blake3).ok()
    } else {
        None
    }
}

/// Make `dir` a directory the effective uid owns alone.
///
/// Created `0700` when it is missing (its parent must exist; only the last level
/// is created), and otherwise required to be a real directory — not a symlink —
/// owned by the euid, with its mode tightened to `0700` when anyone else can
/// reach it. Under `sudo` the euid is root's, so the caller passes a directory
/// that belongs to whichever uid it runs as.
///
/// What stands at the path is judged from the name first, so another user's
/// directory is refused whether or not this user could open it. It is then
/// opened `O_DIRECTORY | O_NOFOLLOW`, judged again through that descriptor, and
/// tightened through it, so what is checked is what is restricted. The pin then
/// reads and writes its entries through that same descriptor.
///
/// # Errors
///
/// [`EvalError::PinCacheDir`] naming the rule `dir` breaks, or [`EvalError::Io`]
/// when the effective uid can't be read.
pub fn establish_cache_dir(dir: &Path) -> Result<(), EvalError> {
    open_cache_dir(dir).map(drop)
}

/// [`establish_cache_dir`], keeping the checked descriptor.
fn open_cache_dir(dir: &Path) -> Result<CacheDir, EvalError> {
    let euid = effective_uid().map_err(EvalError::Io)?;
    let held = establish_cache_dir_as(dir, euid)?;
    Ok(CacheDir { held, euid })
}

/// [`establish_cache_dir`] for the owner `euid`, returning the checked
/// descriptor.
fn establish_cache_dir_as(dir: &Path, euid: u32) -> Result<File, EvalError> {
    use std::os::unix::fs::DirBuilderExt as _;

    use nix::fcntl::OFlag;

    let refused = |problem, source| EvalError::PinCacheDir {
        path: dir.display().to_string(),
        problem,
        source,
    };
    match std::fs::DirBuilder::new().mode(0o700).create(dir) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(refused(PinCacheDirProblem::Uncreatable, Some(error))),
    }
    let named = std::fs::symlink_metadata(dir)
        .map_err(|error| refused(PinCacheDirProblem::Unreadable, Some(error)))?;
    let kind = named.file_type();
    if kind.is_symlink() {
        return Err(refused(PinCacheDirProblem::Symlink, None));
    }
    if !kind.is_dir() {
        return Err(refused(PinCacheDirProblem::NotDirectory, None));
    }
    if named.uid() != euid {
        return Err(refused(PinCacheDirProblem::OtherOwner, None));
    }
    let held = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags((OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW).bits())
        .open(dir)
        .map_err(|error| match error.raw_os_error() {
            // What stood there was replaced since it was looked at.
            Some(code) if code == nix::libc::ELOOP => refused(PinCacheDirProblem::Symlink, None),
            Some(code) if code == nix::libc::ENOTDIR => {
                refused(PinCacheDirProblem::NotDirectory, None)
            }
            _ => refused(PinCacheDirProblem::Unopenable, Some(error)),
        })?;
    let held_meta = held
        .metadata()
        .map_err(|error| refused(PinCacheDirProblem::Unreadable, Some(error)))?;
    if held_meta.uid() != euid {
        return Err(refused(PinCacheDirProblem::OtherOwner, None));
    }
    if held_meta.mode() & 0o077 != 0 {
        held.set_permissions(std::fs::Permissions::from_mode(0o700))
            .map_err(|error| refused(PinCacheDirProblem::Unrestrictable, Some(error)))?;
    }
    Ok(held)
}

#[cfg(test)]
mod tests {

    use std::time::Duration;

    use super::*;

    /// A scratch directory for one unit test, removed on drop.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Self {
            let dir =
                std::env::temp_dir().join(format!("fuz_eval_pin_{tag}_{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir(&dir).unwrap();
            Self(dir)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A clock far enough ahead that a file written now has settled.
    fn later() -> SystemTime {
        SystemTime::now() + Duration::from_secs(10)
    }

    fn blake3_of(path: &Path) -> String {
        blake3::hash(&std::fs::read(path).unwrap())
            .to_hex()
            .to_string()
    }

    fn only_entry(dir: &Path) -> PathBuf {
        let found: Vec<PathBuf> = std::fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        assert_eq!(found.len(), 1, "{found:?}");
        found.into_iter().next().unwrap()
    }

    /// A key hex for the entry tests.
    fn some_key_hex() -> String {
        StatKey {
            dev: 1,
            ino: 2,
            size: 3,
            mtime_ns: 4,
            ctime_ns: 5,
        }
        .to_hex()
    }

    /// Write an entry at `0600`, whatever the umask.
    fn write_entry(path: &Path, contents: &str) {
        std::fs::write(path, contents).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    /// The blake3 part of the entry at `path`.
    fn entry_blake3(path: &Path) -> String {
        std::fs::read_to_string(path).unwrap()[KEY_HEX_LEN..].to_owned()
    }

    /// Plant `blake3` in the entry at `path`, for the key its name says.
    fn plant(path: &Path, blake3: &str) {
        let name = path.file_name().unwrap().to_str().unwrap();
        write_entry(path, &format!("{name}{blake3}"));
    }

    #[test]
    fn cache_dir_of_another_owner_is_refused() {
        let scratch = Scratch::new("owner");
        let dir = scratch.0.join("cache");
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let other = effective_uid().unwrap() ^ 1;
        match establish_cache_dir_as(&dir, other) {
            Err(EvalError::PinCacheDir { problem, .. }) => {
                assert_eq!(problem, PinCacheDirProblem::OtherOwner);
            }
            other => panic!("expected an owner refusal, got {other:?}"),
        }
        // Refused before the open, so its mode was not touched.
        assert_eq!(std::fs::metadata(&dir).unwrap().mode() & 0o777, 0o755);
    }

    #[test]
    fn stat_key_hex_is_fixed_width() {
        let key = StatKey {
            dev: 1,
            ino: u64::MAX,
            size: 0,
            mtime_ns: -1,
            ctime_ns: 2,
        };
        let hex = key.to_hex();
        assert_eq!(hex.len(), KEY_HEX_LEN);
        assert!(is_blake3_hex(&hex.as_bytes()[..64]));
        assert_eq!(&hex[48..80], "f".repeat(32));
    }

    #[test]
    fn settled_needs_both_times_past_the_margin() {
        let at = |secs: u64| UNIX_EPOCH + Duration::from_secs(secs);
        let key = |mtime_s: i128, ctime_s: i128| StatKey {
            dev: 0,
            ino: 0,
            size: 0,
            mtime_ns: mtime_s * 1_000_000_000,
            ctime_ns: ctime_s * 1_000_000_000,
        };
        assert!(key(100, 100).is_settled(at(102)));
        assert!(key(90, 100).is_settled(at(102)));
        assert!(!key(100, 101).is_settled(at(102)));
        assert!(!key(101, 100).is_settled(at(102)));
        assert!(!key(100, 100).is_settled(at(101)));
        // A clock behind the file settles nothing.
        assert!(!key(100, 100).is_settled(at(50)));
        assert!(!key(0, 0).is_settled(UNIX_EPOCH - Duration::from_secs(1)));
    }

    #[test]
    fn exec_path_must_be_the_held_file() {
        let scratch = Scratch::new("exec_path");
        let a = scratch.0.join("a");
        let b = scratch.0.join("b");
        std::fs::write(&a, "a").unwrap();
        std::fs::write(&b, "b").unwrap();
        let held = File::open(&a).unwrap();
        let held_meta = held.metadata().unwrap();
        let through_proc = std::fs::metadata(fd_path(&held)).ok();
        assert_eq!(exec_path_problem(&held_meta, through_proc), None);
        let other = std::fs::metadata(&b).ok();
        assert_eq!(
            exec_path_problem(&held_meta, other),
            Some(FgroProblem::ProcUnavailable)
        );
        assert_eq!(
            exec_path_problem(&held_meta, None),
            Some(FgroProblem::ProcUnavailable)
        );
    }

    #[test]
    fn cache_entry_reads_only_lowercase_hex() {
        let scratch = Scratch::new("entry_hex");
        let euid = effective_uid().unwrap();
        let entry = scratch.0.join("e");
        let key = some_key_hex();
        let good = "0123456789abcdef".repeat(4);
        let cases: [(String, bool); 8] = [
            (format!("{key}{good}"), true),
            (format!("{key}{}", good.to_uppercase()), false),
            (format!("{key}{good}\n"), false),
            (format!("{key}{}", &good[..63]), false),
            (format!("{key}{}", "g".repeat(64)), false),
            // The bare blake3, with no key.
            (good.clone(), false),
            (key.clone(), false),
            (String::new(), false),
        ];
        for (contents, hit) in cases {
            write_entry(&entry, &contents);
            assert_eq!(
                read_cache_entry(&entry, &key, euid).as_deref(),
                hit.then_some(good.as_str()),
                "{contents:?}"
            );
        }
        std::fs::remove_file(&entry).unwrap();
        assert!(read_cache_entry(&entry, &key, euid).is_none());
    }

    #[test]
    fn cache_entry_must_be_the_euids_alone() {
        let scratch = Scratch::new("entry_owner");
        let euid = effective_uid().unwrap();
        let entry = scratch.0.join("e");
        let key = some_key_hex();
        write_entry(&entry, &format!("{key}{}", "a".repeat(64)));
        assert!(read_cache_entry(&entry, &key, euid).is_some());
        // Another owner.
        assert!(read_cache_entry(&entry, &key, euid ^ 1).is_none());
        // Group- or other-writable.
        for mode in [0o620, 0o602, 0o660] {
            std::fs::set_permissions(&entry, std::fs::Permissions::from_mode(mode)).unwrap();
            assert!(read_cache_entry(&entry, &key, euid).is_none(), "{mode:o}");
        }
        std::fs::set_permissions(&entry, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_cache_entry(&entry, &key, euid).is_some());
        // A second link, which whoever holds it could still write.
        let other = scratch.0.join("other");
        std::fs::hard_link(&entry, &other).unwrap();
        assert!(read_cache_entry(&entry, &key, euid).is_none());
        std::fs::remove_file(&other).unwrap();
        assert!(read_cache_entry(&entry, &key, euid).is_some());
        // A link.
        let link = scratch.0.join("link");
        std::os::unix::fs::symlink(&entry, &link).unwrap();
        assert!(read_cache_entry(&link, &key, euid).is_none());
    }

    /// The cached path for a binary written just now, with the clock moved past
    /// the settle margin — the real clock would leave it uncached. Invalidation
    /// is tested by a size change, which moves the key whatever the tick.
    #[test]
    fn settled_binary_is_cached_and_a_new_key_misses() {
        let scratch = Scratch::new("settled");
        let fgro = scratch.0.join("fgro");
        std::fs::copy("/bin/true", &fgro).unwrap();
        let cache = scratch.0.join("cache");
        let real = blake3_of(&fgro);

        let (_, first, _) = open_and_hash(&fgro, Some(&cache), later).unwrap();
        assert_eq!(first, real);
        let entry = only_entry(&cache);
        assert_eq!(entry_blake3(&entry), real);

        // A hit: a planted entry is believed while the key holds.
        let planted = "a".repeat(64);
        plant(&entry, &planted);
        assert_eq!(
            open_and_hash(&fgro, Some(&cache), later).unwrap().1,
            planted
        );

        // A size change moves the key, so the planted entry no longer answers.
        let mut bytes = std::fs::read(&fgro).unwrap();
        bytes.push(0);
        std::fs::write(&fgro, &bytes).unwrap();
        let rehashed = open_and_hash(&fgro, Some(&cache), later).unwrap().1;
        assert_eq!(rehashed, blake3::hash(&bytes).to_hex().to_string());
        assert_eq!(entry_blake3(&entry), planted);
    }

    /// An entry answers only for its own key: a valid entry renamed onto another
    /// binary's key is a miss there, and that binary is hashed.
    #[test]
    fn renamed_entry_is_a_miss() {
        let scratch = Scratch::new("renamed");
        let first = scratch.0.join("first");
        let second = scratch.0.join("second");
        std::fs::copy("/bin/true", &first).unwrap();
        std::fs::copy("/bin/true", &second).unwrap();
        let mut bytes = std::fs::read(&second).unwrap();
        bytes.push(0);
        std::fs::write(&second, &bytes).unwrap();
        let cache = scratch.0.join("cache");

        open_and_hash(&first, Some(&cache), later).unwrap();
        let first_entry = only_entry(&cache);
        let second_key = StatKey::of(&std::fs::metadata(&second).unwrap()).to_hex();
        let second_entry = cache.join(&second_key);
        std::fs::rename(&first_entry, &second_entry).unwrap();
        assert_eq!(
            read_cache_entry(&second_entry, &second_key, effective_uid().unwrap()),
            None
        );
        let (_, blake3, _) = open_and_hash(&second, Some(&cache), later).unwrap();
        assert_eq!(blake3, blake3_of(&second));
        // The miss rewrote it for its own key.
        assert_eq!(entry_blake3(&second_entry), blake3_of(&second));
    }

    /// With the real clock, a binary written just now is hashed but not cached.
    #[test]
    fn unsettled_binary_is_not_cached() {
        let scratch = Scratch::new("unsettled");
        let fgro = scratch.0.join("fgro");
        std::fs::copy("/bin/true", &fgro).unwrap();
        let cache = scratch.0.join("cache");
        let (_, blake3, _) = open_and_hash(&fgro, Some(&cache), SystemTime::now).unwrap();
        assert_eq!(blake3, blake3_of(&fgro));
        assert_eq!(std::fs::read_dir(&cache).unwrap().count(), 0);
    }

    /// The stat key is read again right before the spawn: a write between the
    /// pin and the spawn refuses it. A size change moves the key whatever the
    /// tick, so the refusal doesn't hang on the clock.
    #[test]
    fn a_write_after_the_pin_is_refused_before_the_spawn() {
        let scratch = Scratch::new("changed_since");
        let fgro = scratch.0.join("fgro");
        std::fs::copy("/bin/true", &fgro).unwrap();
        let pinned = fgro_verify(&fgro, &blake3_of(&fgro), None).unwrap();
        pinned.check_unchanged().unwrap();
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&fgro)
            .unwrap();
        std::io::Write::write_all(&mut file, b"\0").unwrap();
        drop(file);
        assert!(matches!(
            pinned.check_unchanged(),
            Err(EvalError::FgroUnusable {
                problem: FgroProblem::ChangedSincePin,
                ..
            })
        ));
    }
}
