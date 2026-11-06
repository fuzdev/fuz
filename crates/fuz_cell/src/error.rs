//! Query-layer error.

/// Error from a `cell_*` query.
///
/// Either a driver error, or a row that didn't decode into the expected
/// shape (malformed `data` JSON / unrecognized `cell_visibility`
/// literal — a schema-drift signal that should never occur against the
/// shipped DDL).
#[derive(Debug, thiserror::Error)]
pub enum CellError {
    /// Underlying `tokio_postgres` driver error.
    #[error(transparent)]
    Db(#[from] tokio_postgres::Error),
    /// A returned row could not be decoded (bad JSON / enum drift).
    #[error("cell row decode failed: {0}")]
    Decode(String),
}
