//! Readiness probe core: live-DB column-presence drift detection.
//!
//! Twin of `fuz_app`'s TS `db/schema_ready.ts`. `/health` is a dumb liveness
//! probe; `/ready` is the deploy gate — it introspects the live database's
//! column set and compares it against a committed expected column map (what a
//! fresh full migration-chain bootstrap produces). A live DB missing an
//! expected column is exactly the failure mode that silently broke login when
//! the auth schema gained `account.deleted_at` via an in-place base-DDL edit
//! instead of an appended migration: the deployed code required a column an
//! older bootstrapped DB never got. The `/ready` route (`fuz_http`'s `ready`
//! module) turns that drift into a loud `503` so a deploy poll rolls it back.
//! The discipline that prevents the drift is the frozen append-only migration
//! chain (`fuz_auth::migrations`); this probe is the runtime net for a lapse.
//!
//! **Column-presence only** — not type / constraint / index parity. Column
//! names are DDL-deterministic and engine-portable, so a map generated against
//! `PGlite` at gen-time compares exactly against a live Postgres at runtime; a
//! single committed `expected_schema.json` is therefore the cross-impl contract
//! (TS and Rust read the same fixture). Finer-grained parity would
//! false-positive across engines, and a false positive here means a
//! rolled-back deploy — an outage you caused. Full structural parity stays the
//! dev-time cross-backend [`query_schema_snapshot`](crate::query_schema_snapshot)
//! suite's job.

use std::collections::{BTreeMap, HashSet};

use deadpool_postgres::GenericClient;

use crate::error::DbError;

/// Expected schema: table name → sorted column names, from a fresh bootstrap.
///
/// Consumers deserialize a committed `expected_schema.json` into this shape
/// (the serde dependency stays consumer-side; `fuz_db` is serde-free).
pub type ExpectedSchema = BTreeMap<String, Vec<String>>;

/// Introspect every column in `schema`, grouped by relation.
///
/// Returns relation → sorted column names. `information_schema.columns` spans
/// tables **and views**; for the drift check that's harmless (a
/// never-bootstrapped schema has neither, and extra relations are ignored — see
/// [`check_schema_drift`]).
///
/// Unlike [`query_schema_snapshot`](crate::query_schema_snapshot) (which drops
/// the `schema_version` migration tracker as framework bookkeeping), this
/// **keeps** `schema_version`, so a never-migrated DB correctly fails readiness
/// instead of passing on an empty expectation.
///
/// `schema` is the namespace to read (typically `"public"`).
///
/// # Errors
///
/// Returns [`DbError`] on query failure.
pub async fn query_ready_columns<C>(
    client: &C,
    schema: &str,
) -> Result<BTreeMap<String, Vec<String>>, DbError>
where
    C: GenericClient + Sync + ?Sized,
{
    let rows = client
        .query(
            "SELECT table_name::text AS table_name, column_name::text AS column_name \
             FROM information_schema.columns WHERE table_schema::text = $1 \
             ORDER BY table_name::text ASC, column_name::text ASC",
            &[&schema],
        )
        .await?;
    let mut by_table: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for row in &rows {
        by_table
            .entry(row.get::<_, String>("table_name"))
            .or_default()
            .push(row.get::<_, String>("column_name"));
    }
    Ok(by_table)
}

/// Columns the live DB is missing for a table the expected schema declares.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MissingColumns {
    /// The table whose columns are incomplete.
    pub table: String,
    /// Expected columns absent from the live table.
    pub columns: Vec<String>,
}

/// Outcome of a column-presence schema-drift check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaDriftResult {
    /// `true` when the live DB covers every expected table + column.
    pub ok: bool,
    /// Expected tables absent from the live DB.
    pub missing_tables: Vec<String>,
    /// Per-table columns the expected schema declares that the live DB lacks.
    pub missing_columns: Vec<MissingColumns>,
}

/// Compare `live` columns against `expected`.
///
/// Reports tables and columns the running code expects that the live DB lacks —
/// the drift that breaks queries. Extra live tables / columns are ignored:
/// forward-compatible, and a newer-than-fixture DB shouldn't fail readiness.
#[must_use]
pub fn check_schema_drift(
    live: &BTreeMap<String, Vec<String>>,
    expected: &ExpectedSchema,
) -> SchemaDriftResult {
    let mut missing_tables = Vec::new();
    let mut missing_columns = Vec::new();
    for (table, columns) in expected {
        match live.get(table) {
            None => missing_tables.push(table.clone()),
            Some(live_columns) => {
                let live_set: HashSet<&str> = live_columns.iter().map(String::as_str).collect();
                let missing: Vec<String> = columns
                    .iter()
                    .filter(|c| !live_set.contains(c.as_str()))
                    .cloned()
                    .collect();
                if !missing.is_empty() {
                    missing_columns.push(MissingColumns {
                        table: table.clone(),
                        columns: missing,
                    });
                }
            }
        }
    }
    SchemaDriftResult {
        ok: missing_tables.is_empty() && missing_columns.is_empty(),
        missing_tables,
        missing_columns,
    }
}

/// Render a drift result as a one-issue-per-line operator string (for logs).
#[must_use]
pub fn format_schema_drift(drift: &SchemaDriftResult) -> String {
    let mut lines = Vec::new();
    for table in &drift.missing_tables {
        lines.push(format!("  missing table: {table}"));
    }
    for mc in &drift.missing_columns {
        lines.push(format!(
            "  {} missing columns: {}",
            mc.table,
            mc.columns.join(", ")
        ));
    }
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::{check_schema_drift, format_schema_drift};
    use std::collections::BTreeMap;

    fn map(entries: &[(&str, &[&str])]) -> BTreeMap<String, Vec<String>> {
        entries
            .iter()
            .map(|(t, cols)| {
                (
                    (*t).to_owned(),
                    cols.iter().map(|c| (*c).to_owned()).collect(),
                )
            })
            .collect()
    }

    #[test]
    fn passes_when_live_covers_expected() {
        let live = map(&[("account", &["id", "username", "deleted_at"])]);
        let expected = map(&[("account", &["id", "deleted_at"])]);
        let drift = check_schema_drift(&live, &expected);
        assert!(drift.ok);
        assert!(drift.missing_tables.is_empty());
        assert!(drift.missing_columns.is_empty());
    }

    #[test]
    fn flags_a_missing_column() {
        let live = map(&[("account", &["id"])]);
        let expected = map(&[("account", &["id", "deleted_at"])]);
        let drift = check_schema_drift(&live, &expected);
        assert!(!drift.ok);
        assert_eq!(drift.missing_columns.len(), 1);
        assert_eq!(drift.missing_columns[0].table, "account");
        assert_eq!(drift.missing_columns[0].columns, vec!["deleted_at"]);
        assert!(drift.missing_tables.is_empty());
    }

    #[test]
    fn flags_a_missing_table() {
        let live = map(&[("account", &["id"])]);
        let expected = map(&[("account", &["id"]), ("actor", &["id"])]);
        let drift = check_schema_drift(&live, &expected);
        assert!(!drift.ok);
        assert_eq!(drift.missing_tables, vec!["actor"]);
    }

    #[test]
    fn format_lists_one_issue_per_line() {
        let live = map(&[("account", &["id"])]);
        let expected = map(&[("account", &["id", "deleted_at"]), ("actor", &["id"])]);
        let drift = check_schema_drift(&live, &expected);
        let rendered = format_schema_drift(&drift);
        assert!(rendered.contains("missing table: actor"));
        assert!(rendered.contains("account missing columns: deleted_at"));
    }
}
