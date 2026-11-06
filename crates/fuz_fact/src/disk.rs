//! Disk CAS byte path: the `<shard>/<rest>` layout, atomic + streaming writes,
//! and the orphan-temp sweep.
//!
//! One layout: a fact's `blake3:<hex64>` address splits into a 2-hex shard
//! dir + the 62-hex remainder as the file name —
//! `<facts_dir>/<2-hex>/<62-hex>`, URL `file:<shard>/<rest>`.
//! [`fact_disk_path`] is the single source of truth, so the buffered write,
//! the streaming spill, and the readers can't drift.
//!
//! Nothing here touches the DB — [`crate::fact_store::PgFactStore`] inserts the
//! `fact` row after the bytes land. The byte path is therefore testable without
//! a live Postgres.
//!
//! ## fsync posture
//!
//! Both write paths ([`write_fact_atomic`] and `SpillFile::commit`) `sync_all`
//! the file's **data** before the rename makes it the canonical CAS body, then
//! deliberately **waive the parent-dir fsync** (per the workspace CAS
//! convention). The data sync matters because the serving path
//! ([`crate::fact_store::FactStore::open`] + `fuz_fact_serving`) streams the
//! hash-named file *without re-hashing* — so write-time durability, not a
//! read-time verify, is what guards served bytes against a torn write. The
//! parent-dir fsync is skipped because the dirent is regenerable: a lost rename
//! after a crash just means the fact is absent until a re-put of the same
//! content re-creates it (content addressing makes that a no-op-or-heal, never a
//! corruption). The buffered `get` path *does* re-hash external bytes, so it
//! tolerates a torn write independently.

use std::convert::Infallible;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::time::{Duration, SystemTime};

use fuz_crypto::{ContentHash, HashAlgo, Hasher};
use fuz_sys::periodic::spawn_periodic;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::error::FactError;

/// Chunk size for the streaming put read loop. Peak memory for a disk-backed
/// upload is bounded by this (plus the embedded buffer until spill), not the
/// artifact size — the point of streaming.
const STREAM_CHUNK_BYTES: usize = 64 * 1024;

/// Age after which an orphaned `.tmp/*` file is swept by [`sweep_orphan_temps`].
///
/// Temps live only for one in-flight upload; anything older is from a crashed
/// upload (mid-stream / commit failures unlink their own temp — see
/// `SpillFile`). A `SIGKILL` mid-stream is the one path that leaks one.
pub const ORPHAN_TEMP_MAX_AGE: Duration = Duration::from_secs(3600);

/// Interval for the periodic orphan-temp sweep on a long-running server.
pub const ORPHAN_TEMP_SWEEP_INTERVAL: Duration = Duration::from_secs(3600);

/// Default embedded-vs-external cutoff (1 MiB).
///
/// Matches the canonical TS `FACT_EMBEDDED_THRESHOLD_DEFAULT`. Consumers tune
/// it per workload (e.g. 16 KiB for a server whose facts are mostly small) via
/// [`crate::fact_store::PgFactStore::with_threshold`].
pub const FACT_EMBEDDED_THRESHOLD_DEFAULT: usize = 1024 * 1024;

/// Subdirectory under the facts dir for in-flight atomic temp files.
pub const FACT_TMP_DIRNAME: &str = ".tmp";

/// The `<shard>/<rest>` split of a fact's bare-hex content address — the
/// single source of truth for the on-disk layout.
///
/// `shard` is the first 2 hex chars; `rest` is the remaining 62. The disk path
/// is `<facts_dir>/<shard>/<rest>`; the stored `external_url` is
/// `file:<shard>/<rest>`. Returns `None` for a hash that isn't BLAKE3 — one
/// should never reach the store, and a SHA-256 digest has the same hex length,
/// so the algorithm is what is checked.
#[must_use]
pub fn fact_disk_path(hash: &ContentHash) -> Option<(String, String)> {
    if hash.algo() != HashAlgo::Blake3 {
        return None;
    }
    let hex = hash.to_hex();
    Some((hex[..2].to_owned(), hex[2..].to_owned()))
}

/// A parsed `file:<shard>/<rest>` external URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedFactUrl {
    /// 2-hex shard directory.
    pub shard: String,
    /// 62-hex remainder (the file name).
    pub rest: String,
}

impl ParsedFactUrl {
    /// Whether this URL is the disk address of `hash` — `shard` + `rest` is
    /// its hex.
    ///
    /// The binding a reader checks before it serves the file as `hash`'s
    /// bytes: a row whose `external_url` names another fact's file would
    /// otherwise serve those bytes under this hash, past this hash's admission.
    #[must_use]
    pub fn addresses(&self, hash: &ContentHash) -> bool {
        fact_disk_path(hash).is_some_and(|(shard, rest)| shard == self.shard && rest == self.rest)
    }
}

/// Build the facts-dir-relative URL for a fact. Stored as-is in
/// `fact.external_url`; readers resolve it against the configured facts dir.
///
/// Returns `None` for a non-blake3 hash (see [`fact_disk_path`]).
#[must_use]
pub fn mint_fact_file_url(hash: &ContentHash) -> Option<String> {
    let (shard, rest) = fact_disk_path(hash)?;
    Some(format!("file:{shard}/{rest}"))
}

/// Parse a `file:<shard>/<rest>` URL.
///
/// Returns `None` for any non-matching shape — the strict
/// `^file:[0-9a-f]{2}/[0-9a-f]{62}$` form is the defense-in-depth control that
/// keeps a malformed/injected `external_url` from addressing an arbitrary path
/// (no `..`, no absolute paths, lowercase hex only — the form
/// [`mint_fact_file_url`] writes, and the TS twin's `file_fact_url.ts`
/// grammar). The shape says nothing about *which* fact the file holds; a
/// reader checks that with [`ParsedFactUrl::addresses`].
#[must_use]
pub fn parse_fact_file_url(url: &str) -> Option<ParsedFactUrl> {
    let is_lower_hex = |s: &str| s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    let body = url.strip_prefix("file:")?;
    let (shard, rest) = body.split_once('/')?;
    let shard_ok = shard.len() == 2 && is_lower_hex(shard);
    let rest_ok = rest.len() == 62 && is_lower_hex(rest);
    if !shard_ok || !rest_ok {
        return None;
    }
    Some(ParsedFactUrl {
        shard: shard.to_owned(),
        rest: rest.to_owned(),
    })
}

/// Resolve a parsed `file:<shard>/<rest>` URL against a facts dir.
#[must_use]
pub fn fact_disk_join(facts_dir: &Path, parsed: &ParsedFactUrl) -> PathBuf {
    facts_dir.join(&parsed.shard).join(&parsed.rest)
}

/// Map a disk I/O error to a [`FactError`], distinguishing disk-full.
///
/// `ErrorKind::StorageFull` (Rust's ENOSPC) becomes [`FactError::StorageFull`]
/// — a non-retryable "server out of space" a consumer answers `507`, not a
/// generic `500`. ENOSPC can surface at the write *or* at the
/// `sync_all`/`rename`, so every disk-write boundary maps through here.
pub(crate) fn io_to_fact_err(e: std::io::Error) -> FactError {
    if e.kind() == ErrorKind::StorageFull {
        FactError::StorageFull
    } else {
        FactError::Io(e)
    }
}

/// Atomic disk write — temp + rename.
///
/// Lands the content at `<facts_dir>/<shard>/<rest>` and returns the
/// `file:<shard>/<rest>` URL for the `fact.external_url` column. The buffered
/// counterpart to the streaming `SpillFile` path (used by
/// `PgFactStore::put` for an oversized in-memory body).
///
/// # Errors
///
/// [`FactError::Io`] (or [`FactError::StorageFull`] on ENOSPC) from any file
/// operation, or [`FactError::Internal`] for a non-blake3 hash.
pub async fn write_fact_atomic(
    facts_dir: &Path,
    hash: &ContentHash,
    bytes: &[u8],
) -> Result<String, FactError> {
    let (shard, rest) = fact_disk_path(hash).ok_or_else(|| {
        FactError::Internal(format!("non-blake3 fact hash: {}", hash.to_prefixed()))
    })?;
    let shard_dir = facts_dir.join(&shard);
    let tmp_dir = facts_dir.join(FACT_TMP_DIRNAME);
    let final_path = shard_dir.join(&rest);

    tokio::fs::create_dir_all(&shard_dir)
        .await
        .map_err(io_to_fact_err)?;
    tokio::fs::create_dir_all(&tmp_dir)
        .await
        .map_err(io_to_fact_err)?;

    let tmp_path = tmp_dir.join(format!("{}.tmp", fuz_sys::rand::random_hex(16)));

    let write_result = async {
        let mut file = tokio::fs::File::create(&tmp_path).await?;
        file.write_all(bytes).await?;
        // fsync the data before the rename publishes it — the serving path
        // streams this file without re-hashing, so the bytes must be durable
        // before they become the canonical CAS body (see the module-level
        // §fsync posture; matches the streaming `SpillFile::commit` path).
        file.sync_all().await?;
        drop(file);
        tokio::fs::rename(&tmp_path, &final_path).await
    }
    .await;

    if write_result.is_err() {
        // Best-effort cleanup of the orphaned temp; the surrounding write
        // already errored, so propagate that, not the unlink result.
        let _ = tokio::fs::remove_file(&tmp_path).await;
    }
    write_result.map_err(io_to_fact_err)?;

    Ok(format!("file:{shard}/{rest}"))
}

/// Where a streamed body landed — see [`StreamedFact`].
#[derive(Debug)]
pub(crate) enum StreamPlacement {
    /// Under the embedded threshold: the bytes are in memory, bound for the
    /// `fact.bytes` column.
    Embedded(Vec<u8>),
    /// Over the threshold: the bytes are already at `<facts_dir>/<shard>/<rest>`
    /// (committed by [`SpillFile::commit`]); the row carries the `file:` URL.
    Disk,
}

/// Byte-path result of a streaming put, minus the DB row insert.
#[derive(Debug)]
pub(crate) struct StreamedFact {
    pub hash: ContentHash,
    pub size: i64,
    pub placement: StreamPlacement,
}

/// Stream `reader` to storage with bounded memory.
///
/// Hashes incrementally (blake3, plus a byte counter), buffers in
/// memory until the bytes cross `embedded_threshold`, then spills through a
/// temp file and atomically renames it over the disk CAS path.
/// Enforces `max_bytes` mid-stream (exceed unlinks the temp and returns
/// [`FactError::PayloadTooLarge`]). Does **not** touch the DB.
///
/// A body over the threshold with `facts_dir == None` is a
/// [`FactError::PayloadTooLarge`] (matches the buffered `put`).
pub(crate) async fn stream_to_storage(
    mut reader: Pin<Box<dyn tokio::io::AsyncRead + Send + '_>>,
    max_bytes: usize,
    facts_dir: Option<&Path>,
    embedded_threshold: usize,
) -> Result<StreamedFact, FactError> {
    let mut blake = Hasher::new(HashAlgo::Blake3);
    let mut total: usize = 0;
    let mut buffer: Vec<u8> = Vec::new();
    let mut spill: Option<SpillFile> = None;
    let mut chunk = vec![0u8; STREAM_CHUNK_BYTES];

    loop {
        let n = match reader.read(&mut chunk).await {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => {
                if let Some(s) = spill {
                    s.discard().await;
                }
                return Err(FactError::Io(e));
            }
        };
        let bytes = &chunk[..n];
        total = total.saturating_add(n);
        if total > max_bytes {
            if let Some(s) = spill {
                s.discard().await;
            }
            return Err(FactError::PayloadTooLarge);
        }
        blake.update(bytes);
        if let Some(s) = spill.as_mut() {
            if let Err(e) = s.write(bytes).await {
                if let Some(s) = spill {
                    s.discard().await;
                }
                return Err(e);
            }
        } else {
            buffer.extend_from_slice(bytes);
            if buffer.len() > embedded_threshold {
                let Some(facts_dir) = facts_dir else {
                    return Err(FactError::PayloadTooLarge);
                };
                let mut s = SpillFile::create(facts_dir).await?;
                if let Err(e) = s.write(&buffer).await {
                    s.discard().await;
                    return Err(e);
                }
                buffer = Vec::new();
                spill = Some(s);
            }
        }
    }

    let hash = blake.finalize();
    let size = i64::try_from(total).map_err(|_| FactError::PayloadTooLarge)?;

    let placement = if let Some(s) = spill {
        let Some(facts_dir) = facts_dir else {
            return Err(FactError::Internal("spill file without facts_dir".into()));
        };
        s.commit(facts_dir, &hash).await?;
        StreamPlacement::Disk
    } else {
        StreamPlacement::Embedded(buffer)
    };

    Ok(StreamedFact {
        hash,
        size,
        placement,
    })
}

/// In-flight temp file for a streamed disk-backed fact.
///
/// A randomly-named file under `<facts_dir>/.tmp` that the streaming put writes
/// through, then [`SpillFile::commit`]s into `<shard>/<rest>` once the final
/// hash is known. [`SpillFile::discard`] removes the temp on abort; `commit`
/// removes it on a failed commit. A process crash mid-stream is the one path
/// that leaks a temp — reaped by [`sweep_orphan_temps`].
#[derive(Debug)]
struct SpillFile {
    tmp_path: PathBuf,
    file: tokio::fs::File,
}

impl SpillFile {
    async fn create(facts_dir: &Path) -> Result<Self, FactError> {
        let tmp_dir = facts_dir.join(FACT_TMP_DIRNAME);
        tokio::fs::create_dir_all(&tmp_dir)
            .await
            .map_err(io_to_fact_err)?;
        let tmp_path = tmp_dir.join(format!("{}.tmp", fuz_sys::rand::random_hex(16)));
        let file = tokio::fs::File::create(&tmp_path)
            .await
            .map_err(io_to_fact_err)?;
        Ok(Self { tmp_path, file })
    }

    async fn write(&mut self, bytes: &[u8]) -> Result<(), FactError> {
        // The most likely ENOSPC site — bytes filling the disk — so map it to
        // `StorageFull` rather than a generic `Io`.
        self.file.write_all(bytes).await.map_err(io_to_fact_err)?;
        Ok(())
    }

    /// fsync + atomically rename the temp into `<facts_dir>/<shard>/<rest>`.
    /// The rename replaces any file already at that path: the temp's bytes were
    /// hashed on the way in, so a repeat put heals a corrupt CAS file and is
    /// otherwise a no-op. On **any** failure the temp is unlinked before
    /// returning.
    async fn commit(self, facts_dir: &Path, hash: &ContentHash) -> Result<(), FactError> {
        let Self { tmp_path, file } = self;
        let outcome = Self::rename_into_cas(file, &tmp_path, facts_dir, hash).await;
        if outcome.is_err() {
            let _ = tokio::fs::remove_file(&tmp_path).await;
        }
        outcome
    }

    async fn rename_into_cas(
        file: tokio::fs::File,
        tmp_path: &Path,
        facts_dir: &Path,
        hash: &ContentHash,
    ) -> Result<(), FactError> {
        // ENOSPC can surface at the deferred flush (`sync_all`) even when the
        // buffered `write_all`s succeeded, so map disk-full here too.
        file.sync_all().await.map_err(io_to_fact_err)?;
        drop(file);
        let (shard, rest) = fact_disk_path(hash).ok_or_else(|| {
            FactError::Internal(format!("non-blake3 fact hash: {}", hash.to_prefixed()))
        })?;
        let shard_dir = facts_dir.join(&shard);
        let final_path = shard_dir.join(&rest);
        tokio::fs::create_dir_all(&shard_dir)
            .await
            .map_err(io_to_fact_err)?;
        tokio::fs::rename(tmp_path, &final_path)
            .await
            .map_err(io_to_fact_err)?;
        Ok(())
    }

    async fn discard(self) {
        drop(self.file);
        let _ = tokio::fs::remove_file(&self.tmp_path).await;
    }
}

/// Remove orphaned streaming-upload temp files under `<facts_dir>/.tmp` older
/// than `max_age`, returning the count removed.
///
/// Best-effort and non-fatal: a missing `.tmp` dir or unreadable entry is
/// skipped (the sweep must never take the server down). The normal upload
/// paths clean up their own temp; this reaps only the leftovers from a process
/// crash mid-stream. A consumer runs it on startup and periodically through
/// [`spawn_orphan_temp_sweeper`].
pub async fn sweep_orphan_temps(facts_dir: &Path, max_age: Duration) -> usize {
    let tmp_dir = facts_dir.join(FACT_TMP_DIRNAME);
    let Ok(mut entries) = tokio::fs::read_dir(&tmp_dir).await else {
        return 0; // no `.tmp` dir yet → nothing to sweep
    };
    let now = SystemTime::now();
    let mut removed = 0usize;
    while let Ok(Some(entry)) = entries.next_entry().await {
        let Ok(metadata) = entry.metadata().await else {
            continue;
        };
        if !metadata.is_file() {
            continue;
        }
        let Ok(modified) = metadata.modified() else {
            continue;
        };
        if let Ok(age) = now.duration_since(modified)
            && age > max_age
            && tokio::fs::remove_file(entry.path()).await.is_ok()
        {
            removed += 1;
        }
    }
    removed
}

/// Spawn the orphan-temp sweeper over the disk CAS at `facts_dir`, which runs
/// until `shutdown` is cancelled: a [`sweep_orphan_temps`] pass now, then one
/// every [`ORPHAN_TEMP_SWEEP_INTERVAL`].
///
/// The crash backstop a long-running consumer of the disk CAS runs beside its
/// server. The startup sweep covers a restart after a crash; every sweep
/// spares anything younger than [`ORPHAN_TEMP_MAX_AGE`], so it is safe beside
/// in-flight uploads. A sweep that removed something logs the count at
/// `info`.
///
/// Runs on [`spawn_periodic`]. Shutdown drops a sweep in progress, which
/// leaves the remaining orphans for the next start. The handle resolves once
/// the sweeper has stopped; a consumer cancels its shutdown token and awaits
/// it after its server drains.
///
/// # Panics
///
/// When called outside a tokio runtime.
pub fn spawn_orphan_temp_sweeper(
    facts_dir: PathBuf,
    shutdown: CancellationToken,
) -> JoinHandle<()> {
    spawn_periodic(
        "orphan temp sweep",
        ORPHAN_TEMP_SWEEP_INTERVAL,
        shutdown,
        move || {
            let facts_dir = facts_dir.clone();
            async move {
                let removed = sweep_orphan_temps(&facts_dir, ORPHAN_TEMP_MAX_AGE).await;
                if removed > 0 {
                    tracing::info!(removed, "swept orphaned fact-store temp files");
                }
                // the sweep skips what it can't read and never fails the loop
                Ok::<(), Infallible>(())
            }
        },
    )
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "tests panic on assertion failure by design"
)]
mod tests {
    use super::*;

    fn tempfile_root() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "fuz_fact_disk_test_{}",
            fuz_sys::rand::random_hex(8)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn boxed_reader(data: &[u8]) -> Pin<Box<dyn tokio::io::AsyncRead + Send + '_>> {
        Box::pin(data)
    }

    fn count_dir(p: &Path) -> usize {
        std::fs::read_dir(p).map_or(0, Iterator::count)
    }

    #[test]
    fn io_to_fact_err_distinguishes_disk_full() {
        let full = io_to_fact_err(std::io::Error::from(ErrorKind::StorageFull));
        assert!(matches!(full, FactError::StorageFull));
        let other = io_to_fact_err(std::io::Error::from(ErrorKind::PermissionDenied));
        assert!(matches!(other, FactError::Io(_)));
    }

    #[test]
    fn disk_path_splits_shard_rest() {
        let h = ContentHash::blake3(b"hello");
        let (shard, rest) = fact_disk_path(&h).unwrap();
        assert_eq!(shard.len(), 2);
        assert_eq!(rest.len(), 62);
        assert_eq!(format!("{shard}{rest}"), h.to_hex());
    }

    #[test]
    fn mint_and_parse_file_url_round_trip() {
        let h = ContentHash::blake3(b"abc");
        let url = mint_fact_file_url(&h).unwrap();
        let (shard, rest) = fact_disk_path(&h).unwrap();
        assert_eq!(url, format!("file:{shard}/{rest}"));
        let parsed = parse_fact_file_url(&url).unwrap();
        assert_eq!(parsed.shard, shard);
        assert_eq!(parsed.rest, rest);
    }

    /// A non-BLAKE3 hash has no disk address, even one whose hex is the same
    /// length.
    #[test]
    fn disk_path_refuses_another_algorithm() {
        assert!(fact_disk_path(&ContentHash::sha256(b"hello")).is_none());
        assert!(fact_disk_path(&ContentHash::sha512(b"hello")).is_none());
        assert!(mint_fact_file_url(&ContentHash::sha256(b"hello")).is_none());
    }

    /// The URL is the address of its own hash and no other.
    #[test]
    fn parsed_url_addresses_only_its_own_hash() {
        let h = ContentHash::blake3(b"abc");
        let other = ContentHash::blake3(b"abd");
        let parsed = parse_fact_file_url(&mint_fact_file_url(&h).unwrap()).unwrap();
        assert!(parsed.addresses(&h));
        assert!(!parsed.addresses(&other));
        // the same hex under another algorithm is not the same address
        let sha_bytes = ContentHash::from_bytes(HashAlgo::Sha256, h.as_bytes().to_vec()).unwrap();
        assert!(!parsed.addresses(&sha_bytes));
    }

    /// Uppercase hex names the same digest but is not the form the store
    /// writes, so it is refused like any other off-grammar URL.
    #[test]
    fn parse_refuses_uppercase_hex() {
        let url = mint_fact_file_url(&ContentHash::blake3(b"abc")).unwrap();
        let body = url.strip_prefix("file:").unwrap();
        assert!(parse_fact_file_url(&format!("file:{}", body.to_ascii_uppercase())).is_none());
        let one_upper = body.replacen(|c: char| c.is_ascii_alphabetic(), "F", 1);
        assert!(parse_fact_file_url(&format!("file:{one_upper}")).is_none());
    }

    #[test]
    fn parse_rejects_traversal_and_malformed() {
        assert!(parse_fact_file_url("file:../../etc/passwd").is_none());
        assert!(
            parse_fact_file_url(
                "file:zz/0000000000000000000000000000000000000000000000000000000000000z"
            )
            .is_none()
        );
        assert!(parse_fact_file_url("https://x/y").is_none());
        // wrong lengths (old `<hash>/content` shape and a short rest)
        assert!(parse_fact_file_url("file:blake3:dead/content").is_none());
        assert!(parse_fact_file_url("file:af/dead").is_none());
    }

    #[tokio::test]
    async fn atomic_write_lands_at_shard_rest() {
        let tmp = tempfile_root();
        let h = ContentHash::blake3(b"hello world");
        let url = write_fact_atomic(&tmp, &h, b"hello world").await.unwrap();
        assert_eq!(url, mint_fact_file_url(&h).unwrap());
        let (shard, rest) = fact_disk_path(&h).unwrap();
        let bytes = tokio::fs::read(tmp.join(&shard).join(&rest)).await.unwrap();
        assert_eq!(bytes, b"hello world");
        let _ = tokio::fs::remove_dir_all(&tmp).await;
    }

    #[tokio::test]
    async fn stream_small_stays_embedded() {
        let data = b"a small embedded body";
        let out = stream_to_storage(
            boxed_reader(data),
            usize::MAX,
            None,
            FACT_EMBEDDED_THRESHOLD_DEFAULT,
        )
        .await
        .unwrap();
        assert_eq!(out.hash, ContentHash::blake3(data));
        assert_eq!(out.size, i64::try_from(data.len()).unwrap());
        match out.placement {
            StreamPlacement::Embedded(bytes) => assert_eq!(bytes, data),
            StreamPlacement::Disk => panic!("small body should stay embedded"),
        }
    }

    #[tokio::test]
    async fn stream_large_spills_to_shard_rest_cas() {
        let tmp = tempfile_root();
        let data = vec![7u8; 64];
        let out = stream_to_storage(boxed_reader(&data), usize::MAX, Some(&tmp), 16)
            .await
            .unwrap();
        assert_eq!(out.hash, ContentHash::blake3(&data));
        assert!(matches!(out.placement, StreamPlacement::Disk));
        let (shard, rest) = fact_disk_path(&out.hash).unwrap();
        let content = tokio::fs::read(tmp.join(&shard).join(&rest)).await.unwrap();
        assert_eq!(content, data);
        assert_eq!(
            count_dir(&tmp.join(FACT_TMP_DIRNAME)),
            0,
            "temp renamed away"
        );
        let _ = tokio::fs::remove_dir_all(&tmp).await;
    }

    #[tokio::test]
    async fn stream_repeat_put_heals_corrupt_cas_file() {
        let tmp = tempfile_root();
        let data = vec![3u8; 128 * 1024];
        let first = stream_to_storage(boxed_reader(&data), usize::MAX, Some(&tmp), 16)
            .await
            .unwrap();
        let (shard, rest) = fact_disk_path(&first.hash).unwrap();
        let cas_path = tmp.join(&shard).join(&rest);
        tokio::fs::write(&cas_path, b"corrupt").await.unwrap();
        let second = stream_to_storage(boxed_reader(&data), usize::MAX, Some(&tmp), 16)
            .await
            .unwrap();
        assert_eq!(first.hash, second.hash);
        assert!(matches!(second.placement, StreamPlacement::Disk));
        assert_eq!(
            tokio::fs::read(&cas_path).await.unwrap(),
            data,
            "the verified temp replaced the corrupt file"
        );
        assert_eq!(count_dir(&tmp.join(FACT_TMP_DIRNAME)), 0, "no temp lingers");
        let _ = tokio::fs::remove_dir_all(&tmp).await;
    }

    #[tokio::test]
    async fn stream_cap_exceeded_cleans_temp() {
        let tmp = tempfile_root();
        let data = vec![1u8; 128 * 1024];
        let err = stream_to_storage(boxed_reader(&data), 100 * 1024, Some(&tmp), 16)
            .await
            .expect_err("over-cap stream must reject");
        assert!(matches!(err, FactError::PayloadTooLarge));
        assert_eq!(
            count_dir(&tmp.join(FACT_TMP_DIRNAME)),
            0,
            "aborted temp unlinked"
        );
        let _ = tokio::fs::remove_dir_all(&tmp).await;
    }

    #[tokio::test]
    async fn stream_oversize_without_facts_dir_errors() {
        let data = vec![9u8; 64];
        let err = stream_to_storage(boxed_reader(&data), usize::MAX, None, 16)
            .await
            .expect_err("oversize without facts_dir must reject");
        assert!(matches!(err, FactError::PayloadTooLarge));
    }

    #[tokio::test]
    async fn sweep_orphan_temps_respects_age_and_missing_dir() {
        let tmp = tempfile_root();
        assert_eq!(sweep_orphan_temps(&tmp, Duration::from_secs(3600)).await, 0);
        let tmp_dir = tmp.join(FACT_TMP_DIRNAME);
        tokio::fs::create_dir_all(&tmp_dir).await.unwrap();
        tokio::fs::write(tmp_dir.join("a.tmp"), b"x").await.unwrap();
        tokio::fs::write(tmp_dir.join("b.tmp"), b"y").await.unwrap();
        assert_eq!(sweep_orphan_temps(&tmp, Duration::from_secs(3600)).await, 0);
        assert_eq!(sweep_orphan_temps(&tmp, Duration::ZERO).await, 2);
        let _ = tokio::fs::remove_dir_all(&tmp).await;
    }

    /// Write a temp under `tmp_dir` whose mtime is past the orphan max age.
    fn write_orphan(tmp_dir: &Path, name: &str) -> PathBuf {
        let path = tmp_dir.join(name);
        std::fs::write(&path, b"left by a crash").unwrap();
        std::fs::File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(SystemTime::now() - ORPHAN_TEMP_MAX_AGE - Duration::from_secs(60))
            .unwrap();
        path
    }

    /// Yield until `path` is gone. The sweep's file I/O runs off the paused
    /// clock, so this waits on real progress, bounded in real time; the tokio
    /// clock moves only when the test advances it, since the yielding test
    /// task never lets the runtime idle.
    async fn until_removed(path: &Path, why: &str) {
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        while path.exists() {
            assert!(std::time::Instant::now() < deadline, "{why}");
            tokio::task::yield_now().await;
        }
    }

    /// The sweeper end to end: its startup sweep reaps an orphan and spares a
    /// fresh temp with no interval to wait out, a later orphan goes at the
    /// next interval and not before, and cancelling the token ends the task.
    #[tokio::test(start_paused = true)]
    async fn the_sweeper_reaps_at_startup_and_on_its_interval_until_cancelled() {
        let root = tempfile::tempdir().unwrap();
        let tmp_dir = root.path().join(FACT_TMP_DIRNAME);
        std::fs::create_dir_all(&tmp_dir).unwrap();
        let in_flight = tmp_dir.join("in_flight");
        std::fs::write(&in_flight, b"an upload still streaming").unwrap();
        let orphan = write_orphan(&tmp_dir, "orphan");

        let started = tokio::time::Instant::now();
        let shutdown = CancellationToken::new();
        let sweeper = spawn_orphan_temp_sweeper(root.path().to_path_buf(), shutdown.clone());

        until_removed(&orphan, "the startup sweep reaps the orphan").await;
        assert_eq!(started.elapsed(), Duration::ZERO, "with no interval waited");
        assert!(in_flight.exists(), "a fresh temp is spared");

        // a crash leaves another; nothing reaps it short of the interval
        let later = write_orphan(&tmp_dir, "later");
        tokio::time::advance(ORPHAN_TEMP_SWEEP_INTERVAL * 9 / 10).await;
        for _ in 0..100 {
            tokio::task::yield_now().await;
        }
        assert!(later.exists(), "no sweep before the interval is up");
        tokio::time::advance(ORPHAN_TEMP_SWEEP_INTERVAL / 10).await;
        assert_eq!(started.elapsed(), ORPHAN_TEMP_SWEEP_INTERVAL);
        until_removed(&later, "the interval sweep reaps the later orphan").await;
        assert!(in_flight.exists(), "a fresh temp is still spared");
        assert!(!sweeper.is_finished(), "the sweeper runs until shutdown");

        shutdown.cancel();
        // bounded on the paused clock, should the sweeper ignore its token
        tokio::time::timeout(ORPHAN_TEMP_SWEEP_INTERVAL * 3, sweeper)
            .await
            .expect("cancelling the token ends the sweeper")
            .expect("the sweeper ends cleanly");
    }
}
