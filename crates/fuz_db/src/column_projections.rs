//! Registry check for the per-table `*_COLUMNS` projection consts.
//!
//! A named projection makes a *dropped* column fail loud at the read
//! (Postgres `column "…" does not exist`); this covers the other
//! direction — a column *added* to the DDL but not to its const would
//! otherwise silently vanish from every read — and forces every live table
//! into a const-or-exemption decision. Each spine crate's PG-gated
//! `tests/columns.rs` feeds it the live map from
//! [`query_ready_columns`](crate::query_ready_columns), its consts, and its
//! reasoned exemptions. Twin of `fuz_app`'s
//! `src/test/db/column_projections.db.test.ts`.

use std::collections::BTreeMap;

/// One migration chain's contribution to a columns registry: the tables it
/// creates that carry a `*_COLUMNS` const, and the ones exempted with a
/// reason.
///
/// Each spine crate exports one per chain next to its `*_MIGRATIONS`
/// (`AUTH_COLUMN_PROJECTIONS`, `CELL_COLUMN_PROJECTIONS`,
/// `FACT_COLUMN_PROJECTIONS`, plus
/// [`DB_COLUMN_PROJECTIONS`] for the runner's own tracker). A
/// `tests/columns.rs` composes the sets for the chains it bootstraps plus
/// its own tables via [`column_projection_mismatches_merged`], so a table
/// added to a spine chain reaches every downstream registry through the one
/// set its crate exports.
#[derive(Debug, Clone, Copy)]
pub struct ColumnProjections {
    /// Table → the const every row read of that table projects through.
    pub projections: &'static [(&'static str, &'static [&'static str])],
    /// Tables with no row-shaped read, and so no const — each exempted for
    /// the reason documented on the exporting const.
    pub exempt: &'static [&'static str],
}

/// The set the migration runner itself contributes: no projections, and the
/// `schema_version` tracker exempt (framework bookkeeping read by name /
/// sequence only). Every registry includes this set.
pub const DB_COLUMN_PROJECTIONS: ColumnProjections = ColumnProjections {
    projections: &[],
    exempt: &["schema_version"],
};

/// [`column_projection_mismatches`] over the concatenation of `sets` — the
/// composed form a `tests/columns.rs` registry uses: the
/// [`ColumnProjections`] of every chain it migrates plus its own.
#[must_use]
pub fn column_projection_mismatches_merged(
    live: &BTreeMap<String, Vec<String>>,
    sets: &[ColumnProjections],
) -> Vec<String> {
    let projections: Vec<(&str, &[&str])> = sets
        .iter()
        .flat_map(|s| s.projections.iter().copied())
        .collect();
    let exempt: Vec<&str> = sets.iter().flat_map(|s| s.exempt.iter().copied()).collect();
    column_projection_mismatches(live, &projections, &exempt)
}

/// Compare projection consts + exemptions against the live column map and
/// return every mismatch as a message; empty means the registry is exact.
///
/// Three checks:
/// - each const in `projections` (`(table, columns)`) names exactly its live
///   table's columns, order-insensitive (the const order is the decode
///   order, which the live schema has no opinion on);
/// - every table in `live` is either projected or in `exempt`;
/// - no table is both projected and exempt, and no projected or exempt table
///   is absent from `live` (a stale entry is drift too).
///
/// `live` is `query_ready_columns`' relation → column-names map.
#[must_use]
pub fn column_projection_mismatches(
    live: &BTreeMap<String, Vec<String>>,
    projections: &[(&str, &[&str])],
    exempt: &[&str],
) -> Vec<String> {
    let mut mismatches = Vec::new();
    for (table, columns) in projections {
        if exempt.contains(table) {
            mismatches.push(format!("{table}: both projected and exempt"));
        }
        let Some(live_columns) = live.get(*table) else {
            mismatches.push(format!("{table}: projected but not in the live schema"));
            continue;
        };
        let mut expected: Vec<&str> = columns.to_vec();
        expected.sort_unstable();
        let mut actual: Vec<&str> = live_columns.iter().map(String::as_str).collect();
        actual.sort_unstable();
        if expected != actual {
            mismatches.push(format!(
                "{table}: projection const {expected:?} vs live columns {actual:?}"
            ));
        }
    }
    for table in exempt {
        if !live.contains_key(*table) {
            mismatches.push(format!("{table}: exempt but not in the live schema"));
        }
    }
    for table in live.keys() {
        let projected = projections.iter().any(|(t, _)| t == table);
        if !projected && !exempt.contains(&table.as_str()) {
            mismatches.push(format!(
                "{table}: live table with neither a projection const nor an exemption"
            ));
        }
    }
    mismatches
}

/// Names in `subset` that aren't in `columns`.
///
/// The DB-free check a query module's unit test runs over each narrow
/// per-shape projection against its table's `*_COLUMNS` const, so a typo in
/// a purpose-row column list fails at `cargo test` rather than at the first
/// live read.
#[must_use]
pub fn columns_not_in<'a>(subset: &[&'a str], columns: &[&str]) -> Vec<&'a str> {
    subset
        .iter()
        .copied()
        .filter(|c| !columns.contains(c))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn live(tables: &[(&str, &[&str])]) -> BTreeMap<String, Vec<String>> {
        tables
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
    fn exact_registry_has_no_mismatches() {
        let live = live(&[
            ("account", &["id", "username"]),
            ("schema_version", &["name", "sequence"]),
        ]);
        let mismatches = column_projection_mismatches(
            &live,
            &[("account", &["username", "id"])],
            &["schema_version"],
        );
        assert!(mismatches.is_empty(), "{mismatches:?}");
    }

    #[test]
    fn reports_every_drift_direction() {
        let live = live(&[
            ("account", &["id", "username", "email"]),
            ("actor", &["id"]),
            ("orphan", &["id"]),
        ]);
        let mismatches = column_projection_mismatches(
            &live,
            &[
                ("account", &["id", "username"]),
                ("gone", &["id"]),
                ("actor", &["id"]),
            ],
            &["actor", "missing"],
        );
        assert_eq!(
            mismatches,
            vec![
                "account: projection const [\"id\", \"username\"] vs live columns [\"email\", \"id\", \"username\"]",
                "gone: projected but not in the live schema",
                "actor: both projected and exempt",
                "missing: exempt but not in the live schema",
                "orphan: live table with neither a projection const nor an exemption",
            ]
        );
    }

    #[test]
    fn merged_concatenates_sets() {
        const ACCOUNT: [&str; 1] = ["id"];
        const AUTH: ColumnProjections = ColumnProjections {
            projections: &[("account", &ACCOUNT)],
            exempt: &["bootstrap_lock"],
        };
        let live = live(&[
            ("account", &["id"]),
            ("schema_version", &["name"]),
            ("bootstrap_lock", &["id"]),
        ]);
        let mismatches = column_projection_mismatches_merged(&live, &[DB_COLUMN_PROJECTIONS, AUTH]);
        assert!(mismatches.is_empty(), "{mismatches:?}");
        let mismatches = column_projection_mismatches_merged(&live, &[DB_COLUMN_PROJECTIONS]);
        assert_eq!(mismatches.len(), 2, "{mismatches:?}");
    }

    #[test]
    fn columns_not_in_names_the_strays() {
        assert!(columns_not_in(&["id", "name"], &["id", "name", "x"]).is_empty());
        assert_eq!(columns_not_in(&["id", "nam"], &["id", "name"]), vec!["nam"]);
    }
}
