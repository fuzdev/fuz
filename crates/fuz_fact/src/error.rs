//! Error taxonomy for the fact store.
//!
//! Its arms are the fact-store failures a consumer maps into its own error type
//! with a mechanical `From`. `StorageFull` is split from generic `Io` because
//! ENOSPC is a non-retryable "server out of space" signal a consumer surfaces
//! as `507`, not a transient `500` — see `crate::disk::io_to_fact_err`.

/// Failures from the fact store and its disk-CAS byte path.
#[derive(Debug, thiserror::Error)]
pub enum FactError {
    /// A Postgres query failed.
    #[error("database error: {0}")]
    Db(#[from] tokio_postgres::Error),
    /// The `COMMIT` failed, or [`fuz_db::commit_checked`]'s pre-commit probe
    /// found the transaction aborted and rolled it back.
    #[error("commit error: {0}")]
    Commit(#[source] fuz_db::DbError),
    /// Checking out a pooled connection failed.
    #[error("pool checkout failed")]
    Pool(#[source] deadpool_postgres::PoolError),
    /// A disk I/O operation failed (not disk-full — see `StorageFull`).
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// The volume is out of space (ENOSPC). Non-retryable.
    #[error("storage full")]
    StorageFull,
    /// Bytes exceeded the embedded threshold with no disk root configured, or a
    /// streamed body exceeded the caller's `max_bytes` cap, or a size overflowed
    /// `i64`.
    #[error("payload too large")]
    PayloadTooLarge,
    /// An internal invariant was violated (e.g. an unparseable stored
    /// `external_url`, or a disk-backed row read with no facts dir configured).
    #[error("internal error: {0}")]
    Internal(String),
}
