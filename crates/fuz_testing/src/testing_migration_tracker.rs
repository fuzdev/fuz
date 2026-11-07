//! `_testing_migration_tracker` action spec.
//!
//! The migration-identity twin of `_testing_schema_snapshot`. Where the
//! snapshot captures the live *schema* (provenance-agnostic — it excludes
//! the `schema_version` tracker), this returns the **tracker rows
//! themselves** as `[{namespace, name, sequence}]`, so the cross-backend
//! harness can assert the two spines record byte-identical migration
//! identity.
//!
//! This is the gate a schema-only comparison lacks: the resulting
//! schema can match while the recorded migration *names* diverge
//! (`name-divergence-at-N` — a Rust binary then refuses to boot on a
//! TS-migrated DB), and the snapshot gate is blind to it because it
//! excludes `schema_version` by design. Diffing the tracker rows turns the
//! swap-freely invariant into a gated fact.
//!
//! Read-only + daemon-token gated — effectively keeper-only without forcing
//! the `actor: 'required'` biconditional, matching `_testing_reset`.

use std::sync::Arc;

use fuz_actions::{ActionContext, ActionHandler, ActionSpec};
use fuz_db::ActionDb;
use fuz_http::{InputShape, internal_error, internal_error_with_source};
use serde_json::{Value, json};

/// Build the `_testing_migration_tracker` action spec.
///
/// The handler reads every `schema_version` row ordered by
/// `(namespace, sequence)` and returns them under an `entries` array. The TS
/// twin's input is `s.void`, so the spec declares [`InputShape::Void`]: the
/// dispatcher reads an absent `params`, `null`, and `{}` as the call and
/// refuses anything else (`-32602`) before the handler runs.
#[must_use]
pub fn create_testing_migration_tracker_action_spec() -> ActionSpec {
    let handler: ActionHandler = Arc::new(move |_params: Value, ctx: ActionContext<'_>| {
        Box::pin(async move {
            // Read-only action → the dispatcher hands a pooled client, never
            // a transaction. The `Tx` arm guards the invariant loudly.
            let rows = match &ctx.db {
                ActionDb::Pool(_) => ctx
                    .db
                    .query(
                        "SELECT namespace, name, sequence FROM schema_version
                         ORDER BY namespace ASC, sequence ASC",
                        &[],
                    )
                    .await
                    .map_err(|e| internal_error_with_source("_testing_migration_tracker", &e))?,
                ActionDb::Tx(_) => {
                    return Err(internal_error(
                        "_testing_migration_tracker requires a read-only pooled client",
                    ));
                }
            };

            let entries: Vec<Value> = rows
                .iter()
                .map(|row| {
                    json!({
                        "namespace": row.get::<_, String>("namespace"),
                        "name": row.get::<_, String>("name"),
                        "sequence": row.get::<_, i32>("sequence"),
                    })
                })
                .collect();

            Ok(json!({ "entries": entries }))
        })
    });

    ActionSpec::read_only(
        "_testing_migration_tracker",
        crate::TESTING_ACTION_AUTH,
        InputShape::Void,
        handler,
    )
}
