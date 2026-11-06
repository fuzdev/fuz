//! The local content-addressed store for npm tarballs.
//!
//! A bespoke `NpmCache` — *not* a `fuz_storage::FileStorage` (its rooted-key
//! CRUD and buffered `upload` are the wrong shape for a verified
//! commit-by-rename CAS). Each entry is an algo-prefixed directory holding the
//! tarball:
//!
//! ```text
//! ~/.fuz/cache/npm/sha512-<hex>/package.tgz
//! ```
//!
//! The `sha512-<hex>` prefix keeps the key self-describing and forward-compatible
//! with the `fuzi.lock` blake3 era (`blake3-<hex>/` coexists, no migration); the
//! dir-per-key (not a flat file) keeps a later extracted-content store an
//! *additive* `sha512-<hex>/content/`, not a rewrite.
//!
//! The load-bearing invariant — *the CAS only ever holds bytes matching their
//! key* — lives in [`NpmCache::commit`], which **is the verify**: it hashes the
//! downloaded temp and renames into place only on a match. An unverified temp
//! can never enter the cache, so the invariant is a property of the type, not of
//! caller discipline.

use std::fs::{self, DirBuilder, File};
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use fuz_crypto::{HashAlgo, hash_file};
use fuz_sys::{SECURE_DIR_MODE, fs::fsync_dir, rand::random_hex_suffix};
use thiserror::Error;

use crate::entry::Integrity;

/// Per-tarball size ceiling fuzi layers on top of `fuz_sys::limits`.
///
/// `fuz_sys::limits` single-sources the workspace artifact ceiling (10 GiB,
/// sized for GB-scale signed artifacts). For npm the opposite tuning fits: a
/// single tarball over a few hundred MB is pathological, so fuzi caps tighter
/// and leans on the size-independent compression-ratio bomb guard at extraction
/// time. Enforced by the fetch transport (`crate::fetch`); defined here as a
/// cache-domain constant since it bounds what a cache entry may hold.
pub const MAX_NPM_TARBALL_SIZE: u64 = 512 * 1024 * 1024;

/// The fixed filename for a tarball within its key directory.
const TARBALL_FILE: &str = "package.tgz";

/// Prefix marking a download-in-progress temp under the npm cache dir. Swept on
/// [`NpmCache::open`]; a crash mid-download leaves only one of these (never an
/// orphan key dir, since the key dir is created inside `commit`).
const TEMP_PREFIX: &str = ".dl-";

/// How old a `.dl-*` temp must be before the sweep reaps it.
///
/// The sweep runs on **every** `NpmCache::open` — every real install opens the
/// cache (a `--dry-run` reads through a [`CacheProbe`] instead, which sweeps
/// nothing). An *unconditional* sweep therefore deletes a
/// concurrently-downloading process's temp (two terminals, or two agents
/// installing side by side):
/// `commit` re-opens the temp by path, gets `NotFound`, and aborts the whole
/// install as a hard disk error. Never corruption — the hash gates hold, and a
/// stray temp is never a false cache hit (the CAS keys on the committed
/// `package.tgz`) — but a misclassified, spurious failure.
///
/// Age-gating on mtime keeps the reaper while making that impossible: a live
/// download bumps mtime on every chunk written, so it can never look stale.
const TEMP_STALE_GRACE: Duration = Duration::from_hours(1);

/// A failure interacting with the npm tarball cache.
#[derive(Debug, Error)]
pub enum CacheError {
    /// An OS / filesystem operation failed.
    #[error("{what}: {source}")]
    Io {
        /// The operation being attempted.
        what: &'static str,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },

    /// A *fetched* tarball's bytes did not match the lockfile hash. A
    /// supply-chain alarm — fatal, never retried into acceptance.
    #[error("integrity mismatch: expected {expected}, computed {actual}")]
    IntegrityMismatch {
        /// The lockfile's expected SRI digest.
        expected: String,
        /// The digest actually computed over the downloaded bytes.
        actual: String,
    },

    /// A *cached* tarball failed re-verification on read — local corruption or
    /// tampering. Online installs self-heal (discard + refetch); `--offline`
    /// fails loud.
    #[error("cached tarball is corrupt (hash mismatch) at {key}")]
    Corrupt {
        /// The algo-prefixed cache key directory name.
        key: String,
    },
}

impl CacheError {
    const fn io(what: &'static str, source: std::io::Error) -> Self {
        Self::Io { what, source }
    }
}

/// The on-disk path of the tarball for `integrity` under `npm_dir`
/// (`<npm>/sha512-<hex>/package.tgz`) — shared by [`NpmCache`] and
/// [`CacheProbe`], so a probe and the store agree on the layout.
fn entry_path_in(npm_dir: &Path, integrity: &Integrity) -> PathBuf {
    npm_dir
        .join(NpmCache::key_dir_name(integrity))
        .join(TARBALL_FILE)
}

/// A read-only view of the cache directory: it probes which tarballs are
/// present and creates, sweeps, or writes nothing.
///
/// What `fuzi install --dry-run` reads through. [`NpmCache::open`] creates the
/// directory and sweeps stale download temps — writes a dry run must not make —
/// so the probe is its own type with nothing but reads
/// ([`contains`](Self::contains), [`verify`](Self::verify)): a dry run cannot
/// reach a write through it. A cache directory that does not
/// exist probes as empty (everything would fetch).
///
/// [`contains`](Self::contains) checks presence only; it does not re-hash.
/// [`verify`](Self::verify) is the re-hash — the real run's own check,
/// read-only — which a dry run applies to every present tarball so its verdict
/// on the cache is the real run's.
#[derive(Debug, Clone)]
pub struct CacheProbe {
    /// The `…/cache/npm` directory, which need not exist.
    npm_dir: PathBuf,
}

impl CacheProbe {
    /// A probe of the cache rooted at `npm_dir`, which need not exist.
    pub(crate) const fn at(npm_dir: PathBuf) -> Self {
        Self { npm_dir }
    }

    /// A probe of the standard cache at `~/.fuz/cache/npm`. Resolving the path
    /// touches nothing on disk.
    ///
    /// # Errors
    ///
    /// Returns [`CacheError::Io`] if `~/.fuz` cannot be resolved — the error
    /// [`NpmCache::open_default`] gives the real run.
    pub fn open_default() -> Result<Self, CacheError> {
        fuz_home::get_npm_cache_dir()
            .map(Self::at)
            .map_err(|e| CacheError::io("resolve npm cache dir", std::io::Error::other(e)))
    }

    /// Whether a tarball is present (the file, not the key dir — an orphan key
    /// dir never reads as a hit).
    pub fn contains(&self, integrity: &Integrity) -> bool {
        self.entry_path(integrity).is_file()
    }

    /// The on-disk path of the tarball for `integrity`, as
    /// [`NpmCache::entry_path`] names it.
    pub(crate) fn entry_path(&self, integrity: &Integrity) -> PathBuf {
        entry_path_in(&self.npm_dir, integrity)
    }

    /// Re-hash a cached tarball against its key — [`NpmCache::verify_cached`]'s
    /// check, read-only: a mismatch is reported, never unlinked or healed.
    ///
    /// # Errors
    ///
    /// As [`NpmCache::verify_cached`]: [`CacheError::Corrupt`] on a hash
    /// mismatch, [`CacheError::Io`] if the entry is absent or unreadable.
    pub fn verify(&self, integrity: &Integrity) -> Result<(), CacheError> {
        verify_entry_in(&self.npm_dir, integrity)
    }
}

/// Re-hash the tarball for `integrity` under `npm_dir` against its key — the
/// one check behind [`NpmCache::verify_cached`] and [`CacheProbe::verify`], so
/// a dry run's verdict is the real run's.
fn verify_entry_in(npm_dir: &Path, integrity: &Integrity) -> Result<(), CacheError> {
    let (computed, _) = hash_file(HashAlgo::Sha512, &entry_path_in(npm_dir, integrity))
        .map_err(|e| CacheError::io("read cached tarball", e))?;
    if &computed == integrity.content_hash() {
        Ok(())
    } else {
        Err(CacheError::Corrupt {
            key: NpmCache::key_dir_name(integrity),
        })
    }
}

/// The local content-addressed store of npm tarballs, rooted at an
/// `~/.fuz/cache/npm`-shaped directory.
///
/// Pure, synchronous, no network — the engine's most unit-testable surface.
/// Concrete by design (one impl, tempdir-backed tests); the network lives behind
/// the [`crate::fetch::TarballSource`] seam, not here.
#[derive(Debug, Clone)]
pub struct NpmCache {
    /// The `…/cache/npm` directory holding `sha512-<hex>/` key dirs and `.dl-*`
    /// download temps.
    npm_dir: PathBuf,
}

impl NpmCache {
    /// Open (creating on demand) a cache rooted at `npm_dir`.
    ///
    /// Creates `npm_dir` and any missing parents at mode 0700 (per-user, never
    /// machine-shared — a machine-wide cache is a cross-user poisoning surface),
    /// then sweeps `.dl-*` download temps left by a crashed install that are
    /// older than `TEMP_STALE_GRACE` (younger ones may belong to a live
    /// concurrent download — see that constant).
    ///
    /// # Errors
    ///
    /// Returns [`CacheError::Io`] if the directory cannot be created.
    pub fn open(npm_dir: PathBuf) -> Result<Self, CacheError> {
        DirBuilder::new()
            .mode(SECURE_DIR_MODE)
            .recursive(true)
            .create(&npm_dir)
            .map_err(|e| CacheError::io("create npm cache dir", e))?;
        let cache = Self { npm_dir };
        cache.sweep_temps(TEMP_STALE_GRACE);
        Ok(cache)
    }

    /// Open the standard cache at `~/.fuz/cache/npm`.
    ///
    /// # Errors
    ///
    /// Returns [`CacheError::Io`] if `~/.fuz` cannot be resolved or the cache
    /// directory cannot be created.
    pub fn open_default() -> Result<Self, CacheError> {
        let npm_dir = fuz_home::get_npm_cache_dir()
            .map_err(|e| CacheError::io("resolve npm cache dir", std::io::Error::other(e)))?;
        Self::open(npm_dir)
    }

    /// The algo-prefixed key directory name for an integrity, e.g.
    /// `sha512-<hex>`. Self-describing and forward-compatible with future
    /// `blake3-<hex>` keys.
    fn key_dir_name(integrity: &Integrity) -> String {
        let hash = integrity.content_hash();
        format!("{}-{}", hash.algo().as_str(), hash.to_hex())
    }

    /// The key directory for an integrity (`<npm>/sha512-<hex>/`).
    fn key_dir(&self, integrity: &Integrity) -> PathBuf {
        self.npm_dir.join(Self::key_dir_name(integrity))
    }

    /// The on-disk path of a cached tarball
    /// (`<npm>/sha512-<hex>/package.tgz`), whether or not it exists yet.
    #[must_use]
    pub fn entry_path(&self, integrity: &Integrity) -> PathBuf {
        entry_path_in(&self.npm_dir, integrity)
    }

    /// A read-only [`CacheProbe`] of this cache's directory.
    pub(crate) fn probe(&self) -> CacheProbe {
        CacheProbe::at(self.npm_dir.clone())
    }

    /// A fresh, unique download-temp path directly under the npm cache dir.
    ///
    /// Same filesystem as the key dirs, so [`NpmCache::commit`]'s rename is
    /// atomic; the `.dl-` prefix marks it sweepable if a crash strands it.
    #[must_use]
    pub fn temp_path(&self) -> PathBuf {
        self.npm_dir
            .join(format!("{TEMP_PREFIX}{}", random_hex_suffix()))
    }

    /// Probe whether a verified tarball is already present (a path check on the
    /// file — keying on the file, not the dir, so an orphan key dir never reads
    /// as a hit).
    #[must_use]
    pub fn contains(&self, integrity: &Integrity) -> bool {
        self.entry_path(integrity).is_file()
    }

    /// Re-hash a cached tarball against its key before use.
    ///
    /// Closes the cache-poisoning / corruption / local-tamper TOCTOU `npm ci`
    /// ignores — cheap next to untarring. A mismatch is [`CacheError::Corrupt`]
    /// (the caller heals online or fails under `--offline`); a missing entry is
    /// [`CacheError::Io`].
    ///
    /// # Errors
    ///
    /// Returns [`CacheError::Corrupt`] on a hash mismatch, or [`CacheError::Io`]
    /// if the entry is absent or unreadable.
    pub fn verify_cached(&self, integrity: &Integrity) -> Result<(), CacheError> {
        verify_entry_in(&self.npm_dir, integrity)
    }

    /// Verify a downloaded temp against its expected integrity and, **only on a
    /// match**, commit it into the cache.
    ///
    /// This *is* the verify step: hash the temp, compare constant-time against
    /// the lockfile hash, and on a match fsync the temp → create the key dir
    /// (0700) → fsync the npm dir (recording the key dir's entry) → atomically
    /// rename into `package.tgz` → fsync the key dir (recording the rename). The
    /// key dir is created here, never before the download, so a crash leaves
    /// only a sweepable `.dl-*` temp, not an orphan key dir.
    ///
    /// On a mismatch the temp is discarded and [`CacheError::IntegrityMismatch`]
    /// returned — a supply-chain alarm, never retried into acceptance. The temp
    /// is also removed on any IO failure, so a failed commit never strands it.
    ///
    /// # Errors
    ///
    /// Returns [`CacheError::IntegrityMismatch`] if the bytes do not match, or
    /// [`CacheError::Io`] on a filesystem failure.
    pub fn commit(&self, temp: &Path, integrity: &Integrity) -> Result<(), CacheError> {
        // Hash first: an unverified temp must never enter the cache.
        let hashed = hash_file(HashAlgo::Sha512, temp);
        let (computed, _) = match hashed {
            Ok(v) => v,
            Err(e) => {
                let _ = fs::remove_file(temp);
                return Err(CacheError::io("hash downloaded tarball", e));
            }
        };
        if &computed != integrity.content_hash() {
            let _ = fs::remove_file(temp);
            return Err(CacheError::IntegrityMismatch {
                expected: integrity.to_sri(),
                actual: computed.to_sri(),
            });
        }

        // Verified — now durably land it. Any failure past here still cleans the
        // temp so a re-run starts from a clean slate.
        if let Err(e) = self.land_verified(temp, integrity) {
            let _ = fs::remove_file(temp);
            return Err(e);
        }
        Ok(())
    }

    /// fsync temp → mkdir key dir → fsync npm dir → atomic rename → fsync key
    /// dir. Assumes the temp's bytes are already verified.
    fn land_verified(&self, temp: &Path, integrity: &Integrity) -> Result<(), CacheError> {
        // fsync the temp's contents before the rename makes it reachable.
        File::open(temp)
            .and_then(|f| f.sync_all())
            .map_err(|e| CacheError::io("fsync downloaded tarball", e))?;

        let key_dir = self.key_dir(integrity);
        DirBuilder::new()
            .mode(SECURE_DIR_MODE)
            .recursive(true)
            .create(&key_dir)
            .map_err(|e| CacheError::io("create cache key dir", e))?;
        // Durably record the key dir itself: the key-dir fsync below covers the
        // rename *inside* it, but not the directory's own entry in `npm_dir`, so
        // without this a host crash can lose the whole entry. Propagated like the
        // fsync below — a cache whose writes cannot be made durable is a disk
        // failure, not something to paper over.
        fsync_dir(&self.npm_dir).map_err(|e| CacheError::io("fsync npm cache dir", e))?;

        let entry = key_dir.join(TARBALL_FILE);
        fs::rename(temp, &entry).map_err(|e| CacheError::io("commit tarball into cache", e))?;

        // Durably record the rename: without the parent fsync a host crash can
        // lose it even though the bytes are durable.
        fsync_dir(&key_dir).map_err(|e| CacheError::io("fsync cache key dir", e))?;
        Ok(())
    }

    /// Best-effort removal of `.dl-*` download temps untouched for at least
    /// `grace`. Errors are ignored: a leftover temp is harmless (it is never a
    /// cache hit — the CAS keys on the committed `package.tgz`), so failing to
    /// reap one costs only disk.
    ///
    /// The age gate is **not** cosmetic: the sweep matches by *prefix*, not by
    /// the caller's own unique temp name, so without it a second fuzi process
    /// deletes a live download's temp (see [`TEMP_STALE_GRACE`]). An entry whose
    /// age cannot be determined is left alone — the conservative arm.
    fn sweep_temps(&self, grace: Duration) {
        let Ok(entries) = fs::read_dir(&self.npm_dir) else {
            return;
        };
        for entry in entries.flatten() {
            if !entry.file_name().to_string_lossy().starts_with(TEMP_PREFIX) {
                continue;
            }
            if entry_is_stale(&entry, grace) {
                let _ = fs::remove_file(entry.path());
            }
        }
    }
}

/// Whether a directory entry has gone untouched for at least `grace`.
///
/// Unreadable metadata, an unavailable mtime, or an mtime in the future all
/// report "not stale" — the sweep only ever reaps what it can *prove* is old.
fn entry_is_stale(entry: &fs::DirEntry, grace: Duration) -> bool {
    entry
        .metadata()
        .and_then(|meta| meta.modified())
        .is_ok_and(|modified| {
            SystemTime::now()
                .duration_since(modified)
                .is_ok_and(|age| age >= grace)
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::integrity_of;
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt as _;
    use tempfile::TempDir;

    /// Write `data` to a fresh temp under the cache and return its path.
    fn write_temp(cache: &NpmCache, data: &[u8]) -> PathBuf {
        let temp = cache.temp_path();
        let mut f = File::create(&temp).unwrap();
        f.write_all(data).unwrap();
        f.sync_all().unwrap();
        temp
    }

    fn open_cache() -> (TempDir, NpmCache) {
        let dir = TempDir::new().unwrap();
        let npm_dir = dir.path().join("cache").join("npm");
        let cache = NpmCache::open(npm_dir).unwrap();
        (dir, cache)
    }

    #[test]
    fn open_creates_dirs_at_0700() {
        let (root, cache) = open_cache();
        let npm_dir = root.path().join("cache").join("npm");
        assert!(npm_dir.is_dir());
        let mode = fs::metadata(&npm_dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
        // The intermediate `cache/` dir is also locked down.
        let cache_dir = root.path().join("cache");
        assert_eq!(
            fs::metadata(&cache_dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        // `cache` is usable.
        assert!(!cache.contains(&integrity_of(b"nope")));
    }

    #[test]
    fn entry_path_is_algo_prefixed() {
        let (_root, cache) = open_cache();
        let integrity = integrity_of(b"abc");
        let path = cache.entry_path(&integrity);
        assert_eq!(path.file_name().unwrap(), "package.tgz");
        let key_dir = path
            .parent()
            .unwrap()
            .file_name()
            .unwrap()
            .to_string_lossy();
        assert!(key_dir.starts_with("sha512-"), "key dir was {key_dir}");
        // Hex digest, 128 chars for sha512.
        let hex = key_dir.strip_prefix("sha512-").unwrap();
        assert_eq!(hex.len(), 128);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn commit_then_probe_then_verify() {
        let (_root, cache) = open_cache();
        let data = b"a real tarball's bytes";
        let integrity = integrity_of(data);

        assert!(!cache.contains(&integrity));
        let temp = write_temp(&cache, data);
        cache.commit(&temp, &integrity).unwrap();

        // The temp is consumed by the rename.
        assert!(!temp.exists());
        // The entry is present and re-verifies.
        assert!(cache.contains(&integrity));
        cache.verify_cached(&integrity).unwrap();
        // The committed bytes are exactly the input.
        assert_eq!(fs::read(cache.entry_path(&integrity)).unwrap(), data);
    }

    #[test]
    fn commit_rejects_wrong_bytes_and_discards_temp() {
        let (_root, cache) = open_cache();
        // Claim the integrity of "expected" but hand commit "tampered" bytes.
        let integrity = integrity_of(b"expected");
        let temp = write_temp(&cache, b"tampered");

        let err = cache.commit(&temp, &integrity).unwrap_err();
        assert!(matches!(err, CacheError::IntegrityMismatch { .. }));
        // The bad temp is gone and nothing entered the cache.
        assert!(!temp.exists());
        assert!(!cache.contains(&integrity));
        assert!(!cache.entry_path(&integrity).parent().unwrap().exists());
    }

    #[test]
    fn key_dir_is_created_at_0700() {
        let (_root, cache) = open_cache();
        let data = b"mode check";
        let integrity = integrity_of(data);
        let temp = write_temp(&cache, data);
        cache.commit(&temp, &integrity).unwrap();
        let key_dir = cache.entry_path(&integrity).parent().unwrap().to_path_buf();
        assert_eq!(
            fs::metadata(&key_dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }

    #[test]
    fn verify_cached_detects_tampering() {
        let (_root, cache) = open_cache();
        let data = b"original contents";
        let integrity = integrity_of(data);
        let temp = write_temp(&cache, data);
        cache.commit(&temp, &integrity).unwrap();

        // Tamper with the committed bytes in place.
        let entry = cache.entry_path(&integrity);
        fs::write(&entry, b"corrupted").unwrap();

        let err = cache.verify_cached(&integrity).unwrap_err();
        assert!(matches!(err, CacheError::Corrupt { .. }));
        // `contains` is only a path probe — it still reports present.
        assert!(cache.contains(&integrity));
    }

    #[test]
    fn verify_cached_missing_entry_is_io_error() {
        let (_root, cache) = open_cache();
        let err = cache.verify_cached(&integrity_of(b"absent")).unwrap_err();
        assert!(matches!(err, CacheError::Io { .. }));
    }

    #[test]
    fn commit_is_idempotent() {
        let (_root, cache) = open_cache();
        let data = b"committed twice";
        let integrity = integrity_of(data);

        let temp1 = write_temp(&cache, data);
        cache.commit(&temp1, &integrity).unwrap();
        // A second download of identical bytes (e.g. a cross-process race) just
        // re-lands the same bytes — no error.
        let temp2 = write_temp(&cache, data);
        cache.commit(&temp2, &integrity).unwrap();
        assert!(cache.contains(&integrity));
        cache.verify_cached(&integrity).unwrap();
    }

    #[test]
    fn sweep_reaps_aged_temps_and_spares_non_temps() {
        let dir = TempDir::new().unwrap();
        let npm_dir = dir.path().join("cache").join("npm");
        let cache = NpmCache::open(npm_dir.clone()).unwrap();
        let stale1 = cache.temp_path();
        let stale2 = cache.temp_path();
        fs::write(&stale1, b"partial").unwrap();
        fs::write(&stale2, b"partial").unwrap();
        let keep = npm_dir.join("not-a-temp");
        fs::write(&keep, b"keep me").unwrap();

        // A zero grace treats every temp as stale — the crashed-install reaper.
        cache.sweep_temps(Duration::ZERO);
        assert!(!stale1.exists());
        assert!(!stale2.exists());
        assert!(keep.exists(), "only `.dl-*` entries are swept");
    }

    #[test]
    fn open_spares_a_live_concurrent_download_temp() {
        // The regression: `open` sweeps by *prefix*, not by the caller's own
        // temp name, so an unconditional sweep deletes a second process's live
        // download out from under it (`commit` then fails NotFound and aborts
        // the install as a disk error). Every real install opens the cache, so
        // this is a two-terminal, not exotic, race.
        let dir = TempDir::new().unwrap();
        let npm_dir = dir.path().join("cache").join("npm");
        let downloading = NpmCache::open(npm_dir.clone()).unwrap();
        let in_flight = downloading.temp_path();
        fs::write(&in_flight, b"partially downloaded").unwrap();

        // A second fuzi process opens the same cache mid-download.
        let _other = NpmCache::open(npm_dir).unwrap();
        assert!(
            in_flight.exists(),
            "a fresh temp belongs to a live download and must survive another open"
        );

        // And it still commits (the whole point — the first process finishes).
        let integrity = integrity_of(b"partially downloaded");
        downloading.commit(&in_flight, &integrity).unwrap();
        assert!(downloading.contains(&integrity));
    }

    #[test]
    fn probe_of_an_absent_cache_creates_nothing_and_reads_empty() {
        let dir = TempDir::new().unwrap();
        let npm_dir = dir.path().join("cache").join("npm");
        let probe = CacheProbe { npm_dir };
        assert!(!probe.contains(&integrity_of(b"x")));
        assert!(
            !dir.path().join("cache").exists(),
            "a probe creates nothing"
        );
    }

    #[test]
    fn probe_sees_committed_entries_and_sweeps_nothing() {
        let (_root, cache) = open_cache();
        let data = b"probed";
        let integrity = integrity_of(data);
        let temp = write_temp(&cache, data);
        cache.commit(&temp, &integrity).unwrap();
        // An aged download temp a sweep would reap.
        let stale = cache.temp_path();
        fs::write(&stale, b"partial").unwrap();
        let old = SystemTime::now() - TEMP_STALE_GRACE - Duration::from_secs(60);
        File::options()
            .write(true)
            .open(&stale)
            .unwrap()
            .set_modified(old)
            .unwrap();

        let probe = cache.probe();
        assert!(probe.contains(&integrity));
        assert!(!probe.contains(&integrity_of(b"other")));
        assert!(stale.exists(), "a probe never sweeps");
    }

    #[test]
    fn probe_verify_reports_corruption_and_leaves_the_entry() {
        let (_root, cache) = open_cache();
        let data = b"probed and re-hashed";
        let integrity = integrity_of(data);
        let temp = write_temp(&cache, data);
        cache.commit(&temp, &integrity).unwrap();
        let probe = cache.probe();
        probe.verify(&integrity).unwrap();

        let entry = cache.entry_path(&integrity);
        fs::write(&entry, b"tampered").unwrap();
        assert!(matches!(
            probe.verify(&integrity),
            Err(CacheError::Corrupt { .. })
        ));
        assert_eq!(
            fs::read(&entry).unwrap(),
            b"tampered",
            "a probe reports a corrupt entry and never unlinks it"
        );
        assert!(matches!(
            probe.verify(&integrity_of(b"absent")),
            Err(CacheError::Io { .. })
        ));
    }

    #[test]
    fn temp_paths_are_unique() {
        let (_root, cache) = open_cache();
        assert_ne!(cache.temp_path(), cache.temp_path());
    }
}
