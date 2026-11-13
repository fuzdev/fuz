//! `FactStore` trait + the PG-backed `PgFactStore`.
//!
//! Twin of the canonical TS `db/fact_store.ts`, bounded-memory `put_stream`
//! included, plus a streaming read (`open`) the TS store doesn't have. The
//! store routes writes by size (embedded `fact.bytes` under the threshold, disk
//! CAS at `<shard>/<rest>` above), verifies disk-backed `get` reads against the
//! stored hash, and is idempotent (`ON CONFLICT DO NOTHING` + content-addressed
//! disk filenames).
//!
//! ## Holders
//!
//! Every put names its holder ([`PutOptions::holder`]): the actor whose
//! request carried the bytes, or `None` for a system put (seeds, server-side
//! imports). A named holder gets a `fact_holder` row on every put — a
//! deduplicated put included, since bringing identical bytes is possession.
//! The `fact` row, its declared refs, and the holder row commit in one
//! transaction. Cell ref admission (`fuz_cell_actions`) reads the holder rows
//! ([`crate::fact_holder_queries`] holds the table's const and the insert).
//!
//! ## Disk-backed rows
//!
//! A row with no embedded bytes carries an `external_url`, and the form `put`
//! and `put_stream` write there is `file:<shard>/<rest>` — a facts-dir-relative
//! address into the store's own disk CAS. Readers resolve that form and no
//! other: [`parse_fact_file_url`] is the whole grammar, and the URL must name
//! the row's own hash ([`crate::disk::ParsedFactUrl::addresses`]), so a row
//! whose `external_url` has any other shape or points at another fact's file
//! (the column is free text, and `query_put_fact` inserts what it is given)
//! has no bytes this store can reach. [`FactStore::get`] and
//! [`FactStore::open`] both log the refusal and answer `Ok(None)`, the same
//! not-found as a missing row, so a reader can't tell the two apart.
//!
//! ## Construction
//!
//! Builder-style, one independent knob per capability. A bare
//! `PgFactStore::new(pool)` is embedded-only at the 1 MiB
//! [`FACT_EMBEDDED_THRESHOLD_DEFAULT`]. `with_disk_root` opens the disk CAS;
//! `with_threshold` opens no path — it only moves the embedded/disk cut:
//!
//! ```ignore
//! // Embedded-only: a body under the threshold lands in `fact.bytes`, and one
//! // over it is refused — `put` and `put_stream` both return
//! // `FactError::PayloadTooLarge` rather than spilling, since there is nowhere
//! // to spill to.
//! let store = PgFactStore::new(pool);
//!
//! // Fused disk CAS: facts over the threshold spill to `<shard>/<rest>` under
//! // `facts_dir`. `get` reads them back whole and verifies them against the
//! // stored hash; `open` streams them straight off disk.
//! let store = PgFactStore::new(pool).with_disk_root(facts_dir);
//!
//! // The same disk CAS with a tuned cut: bodies over 16 KiB go to disk.
//! let store = PgFactStore::new(pool)
//!     .with_disk_root(facts_dir)
//!     .with_threshold(16 * 1024);
//! ```

use std::path::PathBuf;
use std::pin::Pin;

use deadpool_postgres::Pool;
use futures::future::BoxFuture;
use fuz_crypto::ContentHash;
use fuz_db::commit_checked;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::disk::{
    FACT_EMBEDDED_THRESHOLD_DEFAULT, StreamPlacement, fact_disk_join, parse_fact_file_url,
    stream_to_storage, write_fact_atomic,
};
use crate::error::FactError;
use crate::fact_holder_queries::query_put_fact_holder;
use crate::fact_queries::{
    FactDeleted, PutFactInput, query_delete_fact, query_get_fact, query_get_fact_meta,
    query_get_fact_refs, query_has_fact, query_put_fact, query_put_fact_refs,
};

/// Metadata returned by [`FactStore::get_meta`] — twin of the TS `FactMeta`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FactMeta {
    pub content_type: Option<String>,
    pub size: i64,
    pub created_at: String,
    /// `true` when the bytes live externally (`external_url` is set).
    pub external: bool,
}

/// Options for the put family. `refs` declares fact→fact edges written to
/// `fact_ref` after a fresh insert — the only source of edges: the store never
/// scans content for addresses. `content_type` is advisory.
///
/// No `Default`: every call site states its holder, so a put on behalf of a
/// caller can't silently skip the possession record.
#[derive(Debug, Clone)]
pub struct PutOptions {
    pub content_type: Option<String>,
    pub refs: Option<Vec<ContentHash>>,
    /// The actor that brought these bytes, recorded in `fact_holder` whether
    /// or not the fact already existed. `None` is a system put (seeds,
    /// server-side imports) that records no holder — a cell write can newly
    /// reference such a fact only as a global admin or as an actor that puts
    /// the same bytes itself (refs a cell already carries stay admitted
    /// through update and clone).
    pub holder: Option<Uuid>,
}

/// Readable content for a fact, returned by [`FactStore::open`].
///
/// Embedded (small, DB) facts come back as bytes already in memory;
/// disk-backed facts come back as a CAS path + size so the caller streams them
/// to the network without buffering the whole artifact — bounded memory for
/// GB-scale serving.
#[derive(Debug)]
pub enum FactContent {
    /// Inline DB-stored bytes — small facts (under the embedded threshold).
    Embedded(Vec<u8>),
    /// Disk-backed CAS file. Stream from `path`; `size` fills `Content-Length`.
    Disk { path: PathBuf, size: i64 },
}

/// Result of [`FactStore::put_stream`]: what the single streaming pass
/// measured.
#[derive(Debug, Clone)]
pub struct PutStreamOutcome {
    /// blake3 content address.
    pub hash: ContentHash,
    /// Byte length of the streamed body.
    pub size: i64,
}

/// The fact store interface.
///
/// **Object-safe** — consumed as `Arc<dyn FactStore>`. Async via `BoxFuture`
/// (the dyn-trait carve-out; RPITIT doesn't support `dyn`).
pub trait FactStore: Send + Sync {
    /// Idempotent put of an in-memory body. Routes embedded vs disk by size.
    fn put<'a>(
        &'a self,
        bytes: &'a [u8],
        options: PutOptions,
    ) -> BoxFuture<'a, Result<ContentHash, FactError>>;

    /// Stream a body into the store **without buffering the whole artifact**.
    /// Hashes as it reads (blake3 + a byte counter), spilling through a
    /// temp file once the bytes cross the threshold; enforces `max_bytes`
    /// mid-stream. Peak memory is `O(chunk + threshold)`, not `O(artifact)`.
    fn put_stream<'a>(
        &'a self,
        reader: Pin<Box<dyn tokio::io::AsyncRead + Send + 'a>>,
        max_bytes: usize,
        options: PutOptions,
    ) -> BoxFuture<'a, Result<PutStreamOutcome, FactError>>;

    /// Fetch bytes by hash. Verifies disk-backed bytes against the stored
    /// hash; embedded reads skip verification (PG storage *is* the hash table).
    /// A verify mismatch logs and returns `Ok(None)` (treat as unavailable), and
    /// so does a disk-backed row whose bytes cannot be read: no facts dir
    /// configured, an `external_url` that is not the `file:<shard>/<rest>` of
    /// this hash, a missing file, or an I/O error.
    fn get<'a>(
        &'a self,
        hash: &'a ContentHash,
    ) -> BoxFuture<'a, Result<Option<Vec<u8>>, FactError>>;

    /// Open a fact for reading **without buffering** — embedded bytes, or a CAS
    /// path + size for disk-backed facts. `None` if absent. The disk path is
    /// not re-hashed (the CAS file is hash-named at write time).
    ///
    /// The disk branch resolves the canonical `file:<shard>/<rest>`
    /// `external_url` shape of `hash` itself — what `put` / `put_stream`
    /// write. A row carrying any other shape or another fact's address logs
    /// and answers `Ok(None)`, like `get`; a disk-backed row on a store with
    /// no facts dir is [`FactError::Internal`] (a misconfigured server, not a
    /// bad row). A resolved path is returned whether or not the file is there.
    fn open<'a>(
        &'a self,
        hash: &'a ContentHash,
    ) -> BoxFuture<'a, Result<Option<FactContent>, FactError>>;

    /// Existence check.
    fn has<'a>(&'a self, hash: &'a ContentHash) -> BoxFuture<'a, Result<bool, FactError>>;

    /// Advisory metadata (content type, size, `created_at`, external flag).
    fn get_meta<'a>(
        &'a self,
        hash: &'a ContentHash,
    ) -> BoxFuture<'a, Result<Option<FactMeta>, FactError>>;

    /// Declared target hashes for a source fact (raw stored strings).
    fn get_refs<'a>(
        &'a self,
        hash: &'a ContentHash,
    ) -> BoxFuture<'a, Result<Vec<String>, FactError>>;

    /// Drop a fact row, returning `(size, external_url)` for disk unlink + byte
    /// tallying, or `None` if absent. Low-level: the caller verifies the fact
    /// is orphan first, and unlinks the disk file itself.
    fn delete<'a>(
        &'a self,
        hash: &'a ContentHash,
    ) -> BoxFuture<'a, Result<Option<FactDeleted>, FactError>>;
}

/// PG-backed [`FactStore`].
#[derive(Clone)]
pub struct PgFactStore {
    pool: Pool,
    /// Facts dir for the disk CAS: the `put`/`put_stream` spill, `get`'s
    /// verified read, and `open`'s disk-path resolution. `None` → embedded-only.
    facts_dir: Option<PathBuf>,
    embedded_threshold: usize,
}

impl std::fmt::Debug for PgFactStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PgFactStore")
            .field("facts_dir", &self.facts_dir)
            .field("embedded_threshold", &self.embedded_threshold)
            .finish_non_exhaustive()
    }
}

impl PgFactStore {
    /// Embedded-only store (no disk CAS). Oversized `put` bytes →
    /// [`FactError::PayloadTooLarge`].
    #[must_use]
    pub const fn new(pool: Pool) -> Self {
        Self {
            pool,
            facts_dir: None,
            embedded_threshold: FACT_EMBEDDED_THRESHOLD_DEFAULT,
        }
    }

    /// Enable the fused disk CAS at `facts_dir` (`put`/`put_stream` spill,
    /// `open` streaming, and `get`'s verified read).
    #[must_use]
    pub fn with_disk_root(mut self, facts_dir: PathBuf) -> Self {
        self.facts_dir = Some(facts_dir);
        self
    }

    /// Override the embedded-vs-external threshold (default 1 MiB).
    #[must_use]
    pub const fn with_threshold(mut self, threshold: usize) -> Self {
        self.embedded_threshold = threshold;
        self
    }

    async fn client(&self) -> Result<deadpool_postgres::Client, FactError> {
        self.pool.get().await.map_err(FactError::Pool)
    }

    /// Resolve a disk-backed row's `external_url` to its path under the facts
    /// dir — the one resolution `get` and `open` share. The URL must be the
    /// `file:<shard>/<rest>` form of `hash` itself; `Ok(None)`, logged, when
    /// it is any other shape or names another fact's file (the row has no
    /// bytes this store can reach), and [`FactError::Internal`] when no facts
    /// dir is configured. `open` streams the file without re-hashing, so the
    /// binding is what keeps a row from serving another fact's bytes.
    fn disk_path(
        &self,
        hash: &ContentHash,
        external_url: &str,
    ) -> Result<Option<PathBuf>, FactError> {
        // the URL is not echoed — the column is free text, so its shape and
        // length are whatever the row's writer chose
        let Some(parsed) = parse_fact_file_url(external_url) else {
            tracing::warn!(
                hash = %hash.to_prefixed(),
                "external_url is not a file:<shard>/<rest> URL; treating as not-found"
            );
            return Ok(None);
        };
        if !parsed.addresses(hash) {
            // a row naming another fact's file is injection or corruption, not
            // a fetch failure — report it loudly for every reader
            tracing::error!(
                hash = %hash.to_prefixed(),
                "external_url addresses another fact's file; treating as not-found"
            );
            return Ok(None);
        }
        let Some(facts_dir) = self.facts_dir.as_ref() else {
            return Err(FactError::Internal(
                "external_url present but facts_dir not configured".into(),
            ));
        };
        Ok(Some(fact_disk_join(facts_dir, &parsed)))
    }

    /// Insert the `fact` row, then — in the same transaction — its declared
    /// refs (fresh insert only) and the holder row (every put, a dedup hit
    /// included). Shared by `put` and `put_stream`.
    async fn insert_row(
        &self,
        input: &PutFactInput<'_>,
        options: &PutOptions,
    ) -> Result<(), FactError> {
        let mut client = self.client().await?;
        let tx = client.transaction().await?;
        let inserted = query_put_fact(&tx, input).await?;
        if inserted && let Some(refs) = &options.refs {
            query_put_fact_refs(&tx, input.hash, refs).await?;
        }
        if let Some(holder) = options.holder {
            query_put_fact_holder(&tx, holder, input.hash).await?;
        }
        commit_checked(tx).await.map_err(FactError::Commit)?;
        Ok(())
    }
}

impl FactStore for PgFactStore {
    fn put<'a>(
        &'a self,
        bytes: &'a [u8],
        options: PutOptions,
    ) -> BoxFuture<'a, Result<ContentHash, FactError>> {
        Box::pin(async move {
            let hash = ContentHash::blake3(bytes);
            // NOTE: the disk body lands before the `fact` row insert (here and in
            // `put_stream`). If the insert then fails, the `<shard>/<rest>` file
            // persists with no row — `sweep_orphan_temps` only reaps `.tmp/*`, and
            // the orphan-*facts* GC finds rows-without-refs, not files-without-rows.
            // Self-healing (a later identical put renames its verified temp over the
            // file and inserts the row) and it matches the canonical TS ordering, so
            // it's tolerated for now.
            // TODO: a periodic disk↔row reconciliation sweep (walk `<shard>/<rest>`,
            // drop any body with no `fact` row older than a grace window) would
            // close the leak; deferred until a real orphan-body accumulation shows.
            let external_url: Option<String> = if bytes.len() > self.embedded_threshold {
                let Some(facts_dir) = self.facts_dir.as_ref() else {
                    return Err(FactError::PayloadTooLarge);
                };
                Some(write_fact_atomic(facts_dir, &hash, bytes).await?)
            } else {
                None
            };
            let row_bytes: Option<&[u8]> = if external_url.is_some() {
                None
            } else {
                Some(bytes)
            };
            let size = i64::try_from(bytes.len()).map_err(|_| FactError::PayloadTooLarge)?;
            // refs are only ever `options.refs` — the content is never scanned
            // for addresses
            self.insert_row(
                &PutFactInput {
                    hash: &hash,
                    bytes: row_bytes,
                    external_url: external_url.as_deref(),
                    content_type: options.content_type.as_deref(),
                    size,
                },
                &options,
            )
            .await?;
            Ok(hash)
        })
    }

    fn put_stream<'a>(
        &'a self,
        reader: Pin<Box<dyn tokio::io::AsyncRead + Send + 'a>>,
        max_bytes: usize,
        options: PutOptions,
    ) -> BoxFuture<'a, Result<PutStreamOutcome, FactError>> {
        Box::pin(async move {
            let streamed = stream_to_storage(
                reader,
                max_bytes,
                self.facts_dir.as_deref(),
                self.embedded_threshold,
            )
            .await?;
            let content_type = options.content_type.as_deref();
            match &streamed.placement {
                StreamPlacement::Embedded(bytes) => {
                    self.insert_row(
                        &PutFactInput {
                            hash: &streamed.hash,
                            bytes: Some(bytes),
                            external_url: None,
                            content_type,
                            size: streamed.size,
                        },
                        &options,
                    )
                    .await?;
                }
                StreamPlacement::Disk => {
                    // The bytes already landed at `<shard>/<rest>`; mint the URL.
                    let url = crate::disk::mint_fact_file_url(&streamed.hash).ok_or_else(|| {
                        FactError::Internal(format!(
                            "non-blake3 streamed hash: {}",
                            streamed.hash.to_prefixed()
                        ))
                    })?;
                    self.insert_row(
                        &PutFactInput {
                            hash: &streamed.hash,
                            bytes: None,
                            external_url: Some(&url),
                            content_type,
                            size: streamed.size,
                        },
                        &options,
                    )
                    .await?;
                }
            }
            Ok(PutStreamOutcome {
                hash: streamed.hash,
                size: streamed.size,
            })
        })
    }

    fn get<'a>(
        &'a self,
        hash: &'a ContentHash,
    ) -> BoxFuture<'a, Result<Option<Vec<u8>>, FactError>> {
        Box::pin(async move {
            let client = self.client().await?;
            let Some(row) = query_get_fact(&client, hash).await? else {
                return Ok(None);
            };
            if let Some(bytes) = row.bytes {
                return Ok(Some(bytes));
            }
            let Some(external_url) = row.external_url else {
                return Ok(None);
            };
            let path = match self.disk_path(hash, &external_url) {
                Ok(Some(path)) => path,
                Ok(None) => return Ok(None),
                Err(e) => {
                    tracing::warn!(
                        hash = %hash.to_prefixed(),
                        error = %fuz_sys::cli::format_error_chain(&e),
                        "PgFactStore::get disk-backed row unreadable; treating as not-found"
                    );
                    return Ok(None);
                }
            };
            let bytes = match tokio::fs::read(&path).await {
                Ok(b) => b,
                Err(e) => {
                    tracing::warn!(
                        hash = %hash.to_prefixed(),
                        url = external_url,
                        error = %fuz_sys::cli::format_error_chain(&e),
                        "PgFactStore::get fetch failed"
                    );
                    return Ok(None);
                }
            };
            // Integrity verify: re-hash the fetched bytes and compare to the
            // stored address. (Not a secrecy comparison — the bytes are the
            // input — so timing is irrelevant here; `ContentHash`'s `Eq` is
            // used for its single-hashing-home discipline, not for ct.)
            if hash != &ContentHash::blake3(&bytes) {
                tracing::warn!(hash = %hash.to_prefixed(), url = external_url, "PgFactStore::get verify mismatch; treating as not-found");
                return Ok(None);
            }
            Ok(Some(bytes))
        })
    }

    fn open<'a>(
        &'a self,
        hash: &'a ContentHash,
    ) -> BoxFuture<'a, Result<Option<FactContent>, FactError>> {
        Box::pin(async move {
            let client = self.client().await?;
            let Some(row) = query_get_fact(&client, hash).await? else {
                return Ok(None);
            };
            if let Some(bytes) = row.bytes {
                return Ok(Some(FactContent::Embedded(bytes)));
            }
            let Some(external_url) = row.external_url else {
                return Ok(None);
            };
            let Some(path) = self.disk_path(hash, &external_url)? else {
                return Ok(None);
            };
            Ok(Some(FactContent::Disk {
                path,
                size: row.size,
            }))
        })
    }

    fn has<'a>(&'a self, hash: &'a ContentHash) -> BoxFuture<'a, Result<bool, FactError>> {
        Box::pin(async move {
            let client = self.client().await?;
            query_has_fact(&client, hash).await
        })
    }

    fn get_meta<'a>(
        &'a self,
        hash: &'a ContentHash,
    ) -> BoxFuture<'a, Result<Option<FactMeta>, FactError>> {
        Box::pin(async move {
            let client = self.client().await?;
            Ok(query_get_fact_meta(&client, hash)
                .await?
                .map(|row| FactMeta {
                    content_type: row.content_type,
                    size: row.size,
                    created_at: row.created_at,
                    external: row.external_url.is_some(),
                }))
        })
    }

    fn get_refs<'a>(
        &'a self,
        hash: &'a ContentHash,
    ) -> BoxFuture<'a, Result<Vec<String>, FactError>> {
        Box::pin(async move {
            let client = self.client().await?;
            query_get_fact_refs(&client, hash).await
        })
    }

    fn delete<'a>(
        &'a self,
        hash: &'a ContentHash,
    ) -> BoxFuture<'a, Result<Option<FactDeleted>, FactError>> {
        Box::pin(async move {
            let client = self.client().await?;
            query_delete_fact(&client, hash).await
        })
    }
}
