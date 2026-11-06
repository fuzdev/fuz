//! Raw queries against `fact_holder` — the possession record.
//!
//! A `fact_holder` row says an actor has put a fact's bytes. The store writes
//! one on every put that names a holder ([`crate::PutOptions::holder`]),
//! deduplicated puts included: identical bytes put again by a second actor
//! make that actor a holder too. Cell ref admission (`fuz_cell_actions`) reads
//! it back in SQL — a write may introduce a fact ref only for a fact the
//! acting actor holds.
//!
//! Same discipline as [`crate::fact_queries`]: a `GenericClient` first (the
//! caller owns the transaction), no audit side effects, idempotent writes.

use deadpool_postgres::GenericClient;
use fuz_crypto::ContentHash;
use uuid::Uuid;

use crate::error::FactError;

/// The `fact_holder` table's columns.
///
/// Twin of `fuz_app`'s `FACT_HOLDER_COLUMNS` (same names, same order). The
/// PG-gated `columns` integration test asserts this names every live column.
/// No query reads whole rows — admission reads hashes only — so the const is
/// the drift guard's anchor rather than a projection source.
pub const FACT_HOLDER_COLUMNS: [&str; 3] = ["actor_id", "hash", "created_at"];

/// Record `actor_id` as a holder of `hash`, or refresh the row's `created_at`
/// when it already holds it. The `fact` row must already exist (FK).
///
/// `created_at` is the holder's most recent put, which the orphan sweep reads
/// as the fact's grace window: a re-put keeps an old orphan out of any
/// sweep whose window covers the put.
///
/// # Errors
///
/// [`FactError::Db`] on query failure, including an unknown actor or fact.
pub async fn query_put_fact_holder<C: GenericClient + ?Sized>(
    client: &C,
    actor_id: Uuid,
    hash: &ContentHash,
) -> Result<(), FactError> {
    let hash = hash.to_prefixed();
    client
        .execute(
            "INSERT INTO fact_holder (actor_id, hash) VALUES ($1, $2) \
             ON CONFLICT (actor_id, hash) DO UPDATE SET created_at = NOW()",
            &[&actor_id, &hash],
        )
        .await?;
    Ok(())
}
