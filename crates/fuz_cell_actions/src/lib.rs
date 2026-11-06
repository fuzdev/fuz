//! `fuz_cell_actions` — the cell RPC action-spec set atop `fuz_cell` storage.
//!
//! The upper half of the cell layer: the self-contained
//! [`build_cell_spec_set`] of [`fuz_actions::ActionSpec`]s and their
//! handlers. `fuz_cell` owns the storage/authz/DDL half (queries, schema,
//! `can_view_cell` & friends, migrations); this crate composes those into the
//! RPC verbs consumers mount.
//!
//! The split mirrors the fact layer's `fuz_fact` (storage) / `fuz_fact_serving`
//! (serving) cut: a consumer that wants cell *storage* without the RPC verbs
//! (e.g. a serving facade composing `can_view_cell`) depends on `fuz_cell`
//! alone; a consumer mounting the verb surface adds `fuz_cell_actions`.
//!
//! Consumers mount the layer exactly as they mount `fuz_auth`:
//!
//! ```ignore
//! use std::sync::Arc;
//! use fuz_db::run_migrations;
//!
//! // FK order: auth (creates `actor`) precedes cell and fact. The fact chain
//! // carries `fact_holder`, which ref admission reads; without it every new
//! // fact ref a non-admin writes is refused.
//! run_migrations(
//!     &pool,
//!     &[fuz_auth::AUTH_MIGRATIONS, fuz_cell::CELL_MIGRATIONS, fuz_fact::FACT_MIGRATIONS],
//! )
//! .await?;
//!
//! // One role registry — the auth surface's, which role-shaped
//! // `cell_grant`s validate against too.
//! let roles = Arc::new(fuz_auth::RoleRegistry::default());
//! let mut specs = fuz_actions::PROTOCOL_ACTION_SPECS();
//! specs.extend(fuz_actions::auth_adapter::build_auth_spec_set(/* ..., */ Arc::clone(&roles)));
//! // No validator + no authorizers = open create and open grant.
//! specs.extend(fuz_cell_actions::build_cell_spec_set(
//!     fuz_cell_actions::CellSpecSetOptions {
//!         roles,
//!         ..Default::default()
//!     },
//! ));
//! let registry = fuz_actions::ActionRegistry::compile(specs)?;
//! ```
//!
//! ## Current scope
//!
//! The verbs span five families: the core verbs (`cell_create` / `cell_get` /
//! `cell_update` / `cell_delete` / `cell_list` / `cell_clone` /
//! `cell_moderate` / `cell_policy_set`), the `cell_grant_*` ACL verbs
//! (`create` / `revoke` / `list`), the `cell_field_*` named-relation verbs
//! (`set` / `delete` / `list`), the `cell_item_*` ordered-child verbs
//! (`insert` / `move` / `delete` / `list`), and `cell_audit_list` (the
//! per-cell timeline).
//!
//! Authz consults the `cell_grant` branch (actor- and role-shaped admits),
//! and `cell_list` honors it too — grant-admitted cells appear, and
//! `shared_with: 'me'` returns the caller's grant footprint via a
//! grant-driven semi-join. `cell_get` bundles the forward fields + items,
//! visibility-filtered (strict relation-read filter, see
//! [`fuz_cell::filter_visible_targets`]) and truncation-flagged. Relation
//! reads (`cell_field_list` / `cell_item_list`) are bidirectional: the
//! cell named is view-gated, and a page holds the edges whose other end the
//! caller may view, filtered in SQL before the limit.
//!
//! `cell_clone` deep-walks viewable direct children (depth 1), reparents
//! at the source positions, copies outgoing fields shallowly (viewable
//! targets only), nulls `path`, and stamps the caller as owner with zero
//! grants.
//!
//! `cell_create`, `cell_update`, and `cell_clone` gate the fact refs their
//! `data` introduces on **possession**: a non-admin write may add a ref only
//! to a fact its acting actor holds, else `403 cell_ref_not_held` — answered
//! from `fact_holder` rows alone, so it says nothing about whether a fact
//! exists. Refs a cell (or a clone's source row) already carries stay
//! admitted. The gate and its rationale:
//! [`ERROR_CELL_REF_NOT_HELD`] and the `cell_ref_admission` module.
//!
//! Every write verb emits its audit event in-tx with the mutation
//! (routing via [`fuz_auth::AUDIT_EVENT_SPECS`]); `cell_audit_list` reads
//! that per-cell timeline, manage-tier-gated.

pub mod cell_action_specs;
pub mod cell_audit_action_specs;
pub mod cell_field_action_specs;
pub mod cell_grant_action_specs;
pub mod cell_item_action_specs;
mod cell_ref_admission;

pub use cell_action_specs::{
    CELL_RELATIONS_BUNDLE_LIMIT, CellCreateAuthorize, CellCreateAuthorizeInput, CellDataValidator,
    CellSpecSetOptions, ERROR_CELL_CREATE_FORBIDDEN, ERROR_CELL_GET_REQUIRES_ID_OR_PATH,
    ERROR_CELL_KIND_EMPTY, ERROR_CELL_KIND_IN_DATA, ERROR_CELL_LIST_CREATED_BY_REQUIRES_AUTH,
    ERROR_CELL_LIST_SHARED_WITH_REQUIRES_AUTH, ERROR_CELL_MODERATE_FORBIDDEN,
    ERROR_CELL_NOT_A_CONTRIBUTION, ERROR_CELL_NOT_FOUND, ERROR_CELL_NOT_PENDING,
    ERROR_CELL_PATH_ADMIN_ONLY, ERROR_CELL_PATH_TAKEN, ERROR_CELL_POLICY_INVALID,
    ERROR_CELL_POLICY_MANAGE_ONLY, ERROR_CELL_POLICY_ROOT_ONLY, ERROR_CELL_POLICY_UNSUPPORTED,
    ERROR_CELL_REF_NOT_HELD, ERROR_CELL_VISIBILITY_MANAGE_ONLY, Verdict, build_cell_spec_set,
};
pub use cell_audit_action_specs::build_cell_audit_spec_set;
pub use cell_field_action_specs::{
    ERROR_CELL_FIELD_LIST_REQUIRES_SOURCE_OR_TARGET, build_cell_field_spec_set,
};
pub use cell_grant_action_specs::{
    CellGrantCreateAuthorize, CellGrantCreateAuthorizeInput, CellGrantRevokeAuthorize,
    CellGrantRevokeAuthorizeInput, ERROR_CELL_GRANT_NOT_AUTHORIZED, ERROR_CELL_GRANT_NOT_FOUND,
    ERROR_CELL_GRANT_PRINCIPAL_IS_OWNER, ERROR_CELL_GRANT_UNAPPROVED,
    ERROR_CELL_GRANT_UNKNOWN_ROLE, build_cell_grant_spec_set,
};
pub use cell_item_action_specs::{
    ERROR_CELL_ITEM_LIST_REQUIRES_PARENT_OR_CHILD, ERROR_CELL_ITEM_POSITION_TAKEN,
    build_cell_item_spec_set,
};
