//! `fuz_fact` — the content-addressed byte store for the fuz spine.
//!
//! The storage half of the fact layer: the `fuz_facts` migration namespace
//! (`fact` / `fact_ref` / `memo` / `fact_holder`), the [`FactStore`] trait + the PG-backed
//! [`PgFactStore`], the mechanical `fact_queries`, and the `<shard>/<rest>`
//! disk CAS. Twin of the canonical TS `db/fact_store.ts` + `db/fact_queries.ts`
//! (bounded-memory [`PgFactStore::put_stream`] included), plus a streaming
//! read, [`FactStore::open`], the TS store doesn't have.
//!
//! ## Layering — a pure content-addressed primitive
//!
//! `fuz_fact` is **un-authz'd storage with zero HTTP, zero cell knowledge**
//! (a fact store is not an access-control system). It depends
//! only on `fuz_db` / `fuz_crypto` / `fuz_sys` / serde — it **must not** depend
//! on `{axum, fuz_http, fuz_cell, fuz_auth, fuz_actions}`, so it *cannot* build
//! an HTTP response: bytes reach a client only through `fuz_fact_serving`, the
//! sole authz'd reader-facade. That barrier is a gated fact — the per-crate
//! layering rule in `fuz_audit`, enforced by `cargo xtask check-release`. (The
//! orphan queries reference the `cell` *table* in SQL strings, never the
//! `fuz_cell` *crate*, and `fact_holder` FKs into the auth schema's `actor`
//! *table*, never the `fuz_auth` *crate*, so the rule holds.)
//!
//! ## Hashing
//!
//! Fact addresses are [`fuz_crypto::ContentHash`] (blake3) — the workspace's
//! single hashing home. There is no parallel `FactHash` type; the
//! `blake3:<hex64>` wire/storage form is `ContentHash::to_prefixed`, read back
//! with `ContentHash::parse_fact_hash`. A disk-backed fact's file is
//! `file:<shard>/<rest>` over the same lowercase hex, and a reader checks the
//! URL names the row's own hash ([`ParsedFactUrl::addresses`]) before it
//! touches the file.
//!
//! ## Orphan-temp sweep
//!
//! The streaming disk CAS leaves a `.tmp/*` orphan only on a `SIGKILL`
//! mid-stream (every other abort path unlinks its own temp).
//! [`sweep_orphan_temps`] is the reaper and [`spawn_orphan_temp_sweeper`] its
//! schedule — a sweep at startup, then one per
//! [`ORPHAN_TEMP_SWEEP_INTERVAL`], until the shutdown token is cancelled. A
//! library has no startup of its own, so **every long-running consumer of the
//! disk CAS** (a `PgFactStore` built `with_disk_root`) spawns the sweeper
//! over that root beside its server and joins it on shutdown.

pub mod disk;
pub mod error;
pub mod fact_holder_queries;
pub mod fact_queries;
pub mod fact_store;
pub mod migrations;

pub use disk::{
    FACT_EMBEDDED_THRESHOLD_DEFAULT, FACT_TMP_DIRNAME, ORPHAN_TEMP_MAX_AGE,
    ORPHAN_TEMP_SWEEP_INTERVAL, ParsedFactUrl, fact_disk_join, fact_disk_path, mint_fact_file_url,
    parse_fact_file_url, spawn_orphan_temp_sweeper, sweep_orphan_temps, write_fact_atomic,
};
pub use error::FactError;
pub use fact_holder_queries::{FACT_HOLDER_COLUMNS, query_put_fact_holder};
pub use fact_queries::{
    FactDeleted, FactMetaRow, FactRow, OrphanFact, OrphanFactSample, OrphanFactsListResult,
    PutFactInput, query_delete_fact, query_get_fact, query_get_fact_meta, query_get_fact_refs,
    query_has_fact, query_orphan_facts_list, query_orphan_facts_select_for_delete, query_put_fact,
    query_put_fact_refs,
};
pub use fact_store::{FactContent, FactMeta, FactStore, PgFactStore, PutOptions, PutStreamOutcome};
pub use migrations::{
    FACT_COLUMN_PROJECTIONS, FACT_DROP_TABLES, FACT_MIGRATIONS, FACT_MIGRATIONS_NAMESPACE,
};
