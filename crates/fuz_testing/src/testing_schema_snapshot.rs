//! `_testing_schema_snapshot` action spec.
//!
//! Test binaries register this on their `ActionRegistry` alongside
//! `_testing_reset`. It introspects the live database via
//! [`fuz_db::query_schema_snapshot`] and returns the snapshot as JSON
//! shaped to match `fuz_app`'s TS `SchemaSnapshot`, so the cross-backend
//! harness can diff a Rust backend's schema against the TS reference's
//! with `assert_schema_snapshots_equal` (which keys on names + compares
//! field values, so ordering between impls is irrelevant).
//!
//! Optional `exclude_tables: string[]` param drops tables from the
//! snapshot. Mirrors the TS `query_schema_snapshot` exclude option.
//!
//! Read-only + daemon-token gated — effectively keeper-only without
//! forcing the `actor: 'required'` biconditional, matching `_testing_reset`.

use std::sync::Arc;

use fuz_actions::{ActionContext, ActionHandler, ActionSpec};
use fuz_db::ActionDb;
use fuz_db::{SchemaSnapshot, query_schema_snapshot};
use fuz_http::{InputShape, internal_error, internal_error_with_source, invalid_input_params};
use serde_json::{Map, Value, json};

/// Declared input keys — the exact key set of the TS twin's
/// `testing_schema_snapshot_action_spec.input` strict object. The one field is
/// `.optional()`, so the same list is the non-nullable set.
const TESTING_SCHEMA_SNAPSHOT_KEYS: &[&str] = &["exclude_tables"];

/// Build the `_testing_schema_snapshot` action spec.
///
/// The handler introspects `public` and returns the JSON snapshot; an
/// optional `exclude_tables` array param drops named tables.
#[must_use]
pub fn create_testing_schema_snapshot_action_spec() -> ActionSpec {
    let handler: ActionHandler = Arc::new(move |params: Value, ctx: ActionContext<'_>| {
        Box::pin(async move {
            fuz_http::reject_unknown_keys(&params, TESTING_SCHEMA_SNAPSHOT_KEYS)?;
            // `exclude_tables` is `z.array(z.string()).optional()` on the
            // twin, so `null`, a non-array, and a non-string element are each
            // `-32602` there rather than silently dropped.
            fuz_http::reject_null_keys(&params, TESTING_SCHEMA_SNAPSHOT_KEYS)?;
            let exclude: Vec<String> = match params.get("exclude_tables") {
                None => Vec::new(),
                Some(value) => {
                    let arr = value.as_array().ok_or_else(|| {
                        invalid_input_params("`exclude_tables` must be an array of strings", None)
                    })?;
                    arr.iter()
                        .map(|v: &Value| {
                            v.as_str().map(str::to_owned).ok_or_else(|| {
                                invalid_input_params(
                                    "`exclude_tables` entries must be strings",
                                    None,
                                )
                            })
                        })
                        .collect::<Result<Vec<String>, _>>()?
                }
            };
            let exclude_refs: Vec<&str> = exclude.iter().map(String::as_str).collect();

            // Read-only action → the dispatcher hands a pooled client, never
            // a transaction. The `Tx` arm guards the invariant loudly.
            let snapshot = match &ctx.db {
                ActionDb::Pool(client) => query_schema_snapshot(*client, "public", &exclude_refs)
                    .await
                    .map_err(|e| internal_error_with_source("_testing_schema_snapshot", &e))?,
                ActionDb::Tx(_) => {
                    return Err(internal_error(
                        "_testing_schema_snapshot requires a read-only pooled client",
                    ));
                }
            };
            Ok(snapshot_to_json(&snapshot))
        })
    });

    ActionSpec::read_only(
        "_testing_schema_snapshot",
        crate::TESTING_ACTION_AUTH,
        InputShape::Object,
        handler,
    )
}

/// Serialize a [`SchemaSnapshot`] to the TS `SchemaSnapshot` JSON shape.
///
/// Field-name parity with the TS interface is load-bearing — the
/// constraint kind serializes as `type` (not the Rust `kind` field name),
/// and `column_default` is `null` when absent.
fn snapshot_to_json(s: &SchemaSnapshot) -> Value {
    let tables: Map<String, Value> = s
        .tables
        .iter()
        .map(|(name, t)| {
            let columns: Map<String, Value> = t
                .columns
                .iter()
                .map(|(col, c)| {
                    (
                        col.clone(),
                        json!({
                            "data_type": c.data_type,
                            "udt_name": c.udt_name,
                            "is_nullable": c.is_nullable,
                            "column_default": c.column_default,
                            "is_identity": c.is_identity,
                        }),
                    )
                })
                .collect();
            let indexes: Vec<Value> = t
                .indexes
                .iter()
                .map(|i| json!({"name": i.name, "definition": i.definition}))
                .collect();
            let constraints: Vec<Value> = t
                .constraints
                .iter()
                .map(|c| json!({"name": c.name, "type": c.kind, "definition": c.definition}))
                .collect();
            (
                name.clone(),
                json!({
                    "columns": columns,
                    "indexes": indexes,
                    "constraints": constraints,
                }),
            )
        })
        .collect();

    let sequences: Map<String, Value> = s
        .sequences
        .iter()
        .map(|(name, sq)| (name.clone(), json!({"data_type": sq.data_type})))
        .collect();

    let enums: Map<String, Value> = s
        .enums
        .iter()
        .map(|(name, e)| (name.clone(), json!({"labels": e.labels})))
        .collect();

    json!({
        "tables": tables,
        "sequences": sequences,
        "enums": enums,
    })
}
