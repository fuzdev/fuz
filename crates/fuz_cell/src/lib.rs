//! `fuz_cell` — the cell content primitive for the fuz spine.
//!
//! A single `cell` table whose JSONB `data` is interpreted by view
//! shape, with `visibility` (a top-level access-control enum) and the
//! normalized `cell_grant` / `cell_field` / `cell_item` sibling tables.
//! `path` is the sole namespace axis — globally unique on active rows,
//! no tenant/hub scoping. Soft delete via `deleted_at`. Mirrors
//! `fuz_app`'s TS cell layer; the wire contract is
//! `fuz_app/auth/cell_action_specs.ts`.
//!
//! ## Layering
//!
//! `fuz_cell` is the **storage/authz/DDL** half of the cell layer: the
//! `CELL_MIGRATIONS` namespace, the `cell_*` query modules, the
//! `can_view_cell` / `can_edit_cell` / `can_manage_cell` predicates, the
//! relation-visibility filter, and the row/input schema types. It depends
//! on `fuz_db` / `fuz_auth` / `fuz_http` (the wire-UUID serde adapters) /
//! `fuz_sys` / serde — **no `fuz_actions`** (audited by `fuz_audit`) — so a
//! consumer that wants cell storage + authz without the RPC verbs (e.g. a
//! serving facade composing `can_view_cell`) can depend on it alone.
//!
//! The RPC verb surface — `build_cell_spec_set` and the
//! cell/grant/field/item/audit `ActionSpec` handlers — lives in the sibling
//! `fuz_cell_actions` crate. The cut mirrors the fact layer's `fuz_fact`
//! (storage) / `fuz_fact_serving` (serving) split.
//!
//! ```ignore
//! use fuz_db::run_migrations;
//!
//! // FK order: auth (creates `actor`) → cell.
//! run_migrations(&pool, &[fuz_auth::AUTH_MIGRATIONS, fuz_cell::CELL_MIGRATIONS]).await?;
//! ```
//!
//! ## Current scope
//!
//! Storage + authz for the cell primitive: a single `cell` table (+ the
//! `cell_grant` / `cell_field` / `cell_item` siblings), CRUD +
//! relation + audit queries, the `can_view` /
//! `can_edit` / `can_manage` predicates (admin ‖ owner ‖ grant-admit
//! [scope-matched] + public reads for view), the view predicate's SQL form
//! ([`cell_view_sql`], which the relation lists and `cell_list` apply before
//! their limit), and [`filter_visible_targets`] (the strict relation-read
//! filter the `cell_get` bundle and the clone walk compose). The RPC verbs
//! that build on these live in `fuz_cell_actions`.

pub mod cell_audit_queries;
pub mod cell_audit_schema;
pub mod cell_authz;
pub mod cell_field_queries;
pub mod cell_field_schema;
pub mod cell_grant_queries;
pub mod cell_grant_schema;
pub mod cell_item_queries;
pub mod cell_item_schema;
pub mod cell_moderation;
pub mod cell_queries;
pub mod cell_relation_visibility;
pub mod cell_schema;
pub mod cell_steward;
pub mod cell_view_sql;
pub mod error;
pub mod migrations;

pub use cell_audit_schema::{CELL_AUDIT_LIST_DEFAULT_LIMIT, CellAuditEventRow};
pub use cell_authz::{can_edit_cell, can_manage_cell, can_steward_cell, can_view_cell};
pub use cell_field_schema::CellFieldRow;
pub use cell_grant_schema::{CellGrantLevel, CellGrantRow};
pub use cell_item_schema::CellItemRow;
pub use cell_moderation::{
    CELL_MODERATION_APPROVED, CELL_MODERATION_PENDING, CELL_MODERATION_REJECTED,
    cell_moderation_admits_audience, cell_moderation_is_stewardable,
};
pub use cell_relation_visibility::filter_visible_targets;
pub use cell_schema::{
    CellData, CellDataError, CellPolicy, CellPolicyError, CellRow, CellVisibility,
};
pub use cell_steward::cell_steward_admits;
pub use cell_view_sql::CellViewer;
pub use error::CellError;
pub use migrations::{
    CELL_COLUMN_PROJECTIONS, CELL_DROP_TABLES, CELL_MIGRATIONS, CELL_MIGRATIONS_NAMESPACE,
};
