//! Possession-gated cell ref admission — the gate `cell_create`,
//! `cell_update`, and `cell_clone` run on the fact refs their `data`
//! introduces, and the one `fact_holder` read it makes.
//!
//! `fact_holder` belongs to `fuz_fact`'s migration chain, which writes it on
//! every put that names a holder. This crate reads it in SQL only, without a
//! `fuz_fact` dependency — the way `fuz_fact`'s orphan queries read the `cell`
//! table — so a consumer that mounts the cell verbs but stores no facts links
//! no fact store.

use fuz_auth::{ROLE_ADMIN, RequestActorContext};
use fuz_cell::cell_queries::extract_refs;
use fuz_http::JsonrpcError;
use serde_json::Value;
use uuid::Uuid;

use crate::cell_action_specs::ERROR_CELL_REF_NOT_HELD;

/// Refuse a write whose `data` introduces a fact ref the caller does not hold
/// — **possession-gated ref admission**, the gate that keeps a known hash from
/// being a read capability.
///
/// Fact serving admits a read of `hash` through any cell the reader can view
/// whose `refs` carry it, and refs derive from `data` alone. Without this gate
/// anyone who can write a cell could name any hash they had seen (in a URL, a
/// header, an audit row) and serve its bytes through their own cell — to the
/// world, if the cell is public — and read a fact's existence off the serve
/// answer. So a write may introduce only refs to facts its acting actor
/// **holds**: a `fact_holder` row, recorded on every put that names the actor,
/// identical bytes put by a second actor included.
///
/// `new_refs = extract_refs(data) \ base`, where `base` is what the write
/// already carries — `None` on `cell_create`, the cell's current refs on
/// `cell_update`, the source row's refs on each row `cell_clone` writes — so
/// keeping refs someone else introduced, or cloning a viewable cell's refs, is
/// admitted (the bytes were already readable through that cell). A global
/// admin is not gated. The check runs on the write's transaction, only when
/// `new_refs` is non-empty — a table probe, then one holder lookup for every
/// new ref at once — and answers from holder rows only:
/// an unheld hash reads the same whether or not a fact is stored under it.
///
/// A database without the fact chain (a consumer that mounts the cell verbs
/// but no fact store) has no holders, so every new ref is refused there too —
/// checked first, since naming a missing table would abort the transaction.
///
/// Runs as the last gate before the row is written: after the 404 masks, the
/// per-kind validator, and the create authorizer.
pub async fn require_new_refs_held<C: deadpool_postgres::GenericClient + ?Sized>(
    client: &C,
    auth: &RequestActorContext,
    base: Option<&[String]>,
    data: &Value,
) -> Result<(), JsonrpcError> {
    if auth.has_scoped_role(ROLE_ADMIN, None) {
        return Ok(());
    }
    let Some(refs) = extract_refs(data) else {
        return Ok(());
    };
    let base = base.unwrap_or_default();
    let new_refs: Vec<String> = refs.into_iter().filter(|r| !base.contains(r)).collect();
    if new_refs.is_empty() {
        return Ok(());
    }
    let fact_chain_present: bool = client
        .query_one("SELECT to_regclass('fact_holder') IS NOT NULL", &[])
        .await
        .map_err(|e| fuz_http::internal_error_with_source("fact_holder probe failed", &e))?
        .get(0);
    let all_held = fact_chain_present
        && query_fact_holder_unheld(client, auth.actor.id, &new_refs)
            .await
            .map_err(|e| fuz_http::internal_error_with_source("fact_holder query failed", &e))?
            .is_empty();
    if !all_held {
        return Err(fuz_http::forbidden(
            "cell data references a fact the caller does not hold",
            Some(ERROR_CELL_REF_NOT_HELD),
        ));
    }
    Ok(())
}

/// The subset of `hashes` that `actor_id` does **not** hold, in input order.
///
/// Answered from `fact_holder` alone: a hash with no stored fact and a stored
/// fact the actor never put read the same. Hashes are the stored ref strings,
/// compared as text. The caller has checked the table exists and passes a
/// non-empty list.
async fn query_fact_holder_unheld<C: deadpool_postgres::GenericClient + ?Sized>(
    client: &C,
    actor_id: Uuid,
    hashes: &[String],
) -> Result<Vec<String>, deadpool_postgres::tokio_postgres::Error> {
    let rows = client
        .query(
            "SELECT h.hash FROM unnest($2::text[]) WITH ORDINALITY AS h(hash, ord) \
             WHERE NOT EXISTS ( \
               SELECT 1 FROM fact_holder fh WHERE fh.actor_id = $1 AND fh.hash = h.hash \
             ) \
             ORDER BY h.ord",
            &[&actor_id, &hashes],
        )
        .await?;
    Ok(rows.iter().map(|r| r.get::<_, String>(0)).collect())
}
