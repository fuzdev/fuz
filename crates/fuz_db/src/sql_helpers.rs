//! Tiny SQL-fragment helpers shared across spine query modules.
//!
//! Houses the ISO-8601 `to_char` formatter that the wire-shape row
//! decoders depend on for cross-impl parity with the TS reference
//! backend's timestamp columns (`created_at` / `updated_at` /
//! `expires_at` / …). Both `fuz_auth` and `fuz_cell` project timestamps
//! through this fragment so every spine crate emits the identical
//! second-precision UTC ISO-8601 string on the wire, and
//! [`iso8601_timestamp_expr`] packages the fragment as the projection
//! override a query module hands [`qualify_columns`] — one call naming the
//! table's timestamp columns instead of a hand-written `match` per module.
//!
//! Also houses the named-projection companions a query module pairs with its
//! `*_COLUMNS` const: [`qualify_columns`] and [`omit_columns`] render the
//! projection the drift guard
//! ([`column_projection_mismatches`](crate::column_projection_mismatches))
//! checks against the live schema, and [`column_index`] + the
//! [`col!`](crate::col) macro resolve each decoder index against the const
//! by name at compile time — the twins of `fuz_app`'s `qualify_columns` /
//! `omit_columns` over its `*_COLUMNS` consts, plus the decode-side check
//! TS gets from reading rows by name.

/// Build a `to_char({alias}.{col} AT TIME ZONE 'UTC',
/// 'YYYY-MM-DD"T"HH24:MI:SS"Z"')` SQL fragment for embedding in a
/// SELECT projection.
///
/// `alias` is the table alias or empty string; `col` is the column
/// name. Output is a non-empty `String` ready to splice into a SQL
/// statement (no surrounding whitespace assumed).
///
/// The format string (`'YYYY-MM-DD"T"HH24:MI:SS"Z"'`) is the spine's
/// canonical timestamp wire shape; centralizing here keeps the
/// 70-char fragment from scattering across every query module.
#[must_use]
pub fn iso8601_timestamp_column(alias: &str, col: &str) -> String {
    if alias.is_empty() {
        format!("to_char({col} AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"')")
    } else {
        format!("to_char({alias}.{col} AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"')")
    }
}

/// Build the [`qualify_columns`] `expr` override that projects
/// `timestamp_columns` through [`iso8601_timestamp_column`] and leaves every
/// other column bare.
///
/// The twin of `fuz_app`'s `iso8601_timestamp_expr`, which curries the alias
/// because TS reads rows by name and must alias each override back to its
/// column; Rust decodes positionally, so the alias is a plain third argument
/// and the returned closure drops straight into [`qualify_columns`]:
///
/// ```
/// # use fuz_db::{iso8601_timestamp_expr, qualify_columns};
/// const CELL_GRANT_COLUMNS: [&str; 3] = ["id", "level", "created_at"];
///
/// fn grant_columns(alias: &str) -> String {
///     qualify_columns(
///         &CELL_GRANT_COLUMNS,
///         alias,
///         iso8601_timestamp_expr(&CELL_GRANT_COLUMNS, &["created_at"], alias),
///     )
/// }
/// ```
///
/// A projection that also overrides a non-timestamp column (a `::text` cast)
/// keeps its `match` and falls through to this closure for the rest. Bind the
/// closure to a local **outside** the `match` and call it from the fallthrough
/// arm — building it inside the arm borrows the arguments for less than the
/// `match` expression's own scope, which doesn't compile:
///
/// ```
/// # use fuz_db::{iso8601_timestamp_expr, qualify_columns};
/// const CELL_COLUMNS: [&str; 3] = ["id", "data", "created_at"];
///
/// fn cell_columns(alias: &str) -> String {
///     let timestamps = iso8601_timestamp_expr(&CELL_COLUMNS, &["created_at"], alias);
///     qualify_columns(&CELL_COLUMNS, alias, |col| match col {
///         "data" => Some(format!("{alias}.data::text")),
///         _ => timestamps(col),
///     })
/// }
/// ```
///
/// # Panics
///
/// When a name in `timestamp_columns` isn't in `columns` — the same hazard
/// [`omit_columns`] guards, and the same hard assertion, since a timestamp
/// name the const doesn't carry silently projects nothing and puts a raw
/// timestamp on the wire. The panic lands at the first render of that
/// projection, and every projection is rendered by its query module's tests
/// or at its first use.
pub fn iso8601_timestamp_expr<'a>(
    columns: &[&str],
    timestamp_columns: &'a [&'a str],
    alias: &'a str,
) -> impl Fn(&str) -> Option<String> + 'a {
    for t in timestamp_columns {
        assert!(
            columns.contains(t),
            "iso8601_timestamp_expr: {t:?} is not in the column list {columns:?}"
        );
    }
    move |col| {
        timestamp_columns
            .contains(&col)
            .then(|| iso8601_timestamp_column(alias, col))
    }
}

/// Build a comma-separated projection list from `columns`.
///
/// Each column is qualified as `{alias}.{col}` unless `expr` returns an
/// override for it (a `::text` cast, the [`iso8601_timestamp_column`]
/// projection). The output order is `columns`' order, so a positional decoder
/// can index by the const.
///
/// `alias` must be non-empty — the projection is always qualified, which is
/// what lets one const serve both the single-table reads and the aliased
/// JOIN / list reads.
#[must_use]
pub fn qualify_columns(
    columns: &[&str],
    alias: &str,
    expr: impl Fn(&str) -> Option<String>,
) -> String {
    debug_assert!(
        !alias.is_empty(),
        "qualify_columns: alias must be non-empty"
    );
    columns
        .iter()
        .map(|col| expr(col).unwrap_or_else(|| format!("{alias}.{col}")))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Drop `omitted` names from `columns`, preserving projection order.
///
/// For a read that deliberately narrows a `*_COLUMNS` const (the client-safe
/// `api_token` listing that leaves out `token_hash`, the admin summaries that
/// skip provenance columns). With compile-time [`col!`](crate::col) decoding
/// the narrowed list is typically a *literal* const the decoder indexes into,
/// pinned to this derivation by a unit test — call this at the pin site so
/// the base const's drift guard still covers the narrowed projection. Twin
/// of `fuz_app`'s `omit_columns`.
///
/// # Panics
///
/// When a name in `omitted` isn't in `columns` — a typo here would silently
/// keep the column it meant to hide.
#[must_use]
pub fn omit_columns<'a>(columns: &[&'a str], omitted: &[&str]) -> Vec<&'a str> {
    for o in omitted {
        assert!(
            columns.contains(o),
            "omit_columns: {o:?} is not in the column list {columns:?}"
        );
    }
    columns
        .iter()
        .copied()
        .filter(|c| !omitted.contains(c))
        .collect()
}

/// Const-evaluable string equality (byte loop) — `str::eq` isn't `const fn`.
const fn str_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// Index of `name` in `columns` — the compile-time name→index resolver
/// behind [`col!`](crate::col).
///
/// A positional decoder names its column and the index follows the
/// `*_COLUMNS` const automatically: insert or reorder the const and every
/// decode index moves with it; a name not in the list fails const
/// evaluation, i.e. the build.
///
/// # Panics
///
/// When `name` isn't in `columns`. Called through `col!` this happens at
/// const-eval time — a compile error, never a runtime panic.
#[must_use]
#[allow(
    clippy::panic,
    reason = "const-eval panic = compile error at the col! site; unreachable at runtime for a name the build accepted"
)]
pub const fn column_index(columns: &[&str], name: &str) -> usize {
    let mut i = 0;
    while i < columns.len() {
        if str_eq(columns[i], name) {
            return i;
        }
        i += 1;
    }
    panic!("column_index: name is not in the column list");
}

/// Compile-time column index into a `*_COLUMNS` const:
/// `row.get(col!(ACCOUNT_COLUMNS, "email"))`.
///
/// Sugar for `const { column_index(&ACCOUNT_COLUMNS, "email") }` — resolved
/// at const-eval time, so it costs nothing at runtime, a misspelled or
/// removed column name is a compile error, and the decoder cannot
/// disagree with the const the SQL projection is rendered from. Pass the
/// const by name (the macro takes the array, not a reference). Expressions a
/// read appends after the const's columns keep indexing from
/// `X_COLUMNS.len()`.
#[macro_export]
macro_rules! col {
    ($columns:expr, $name:expr) => {
        const { $crate::column_index(&$columns, $name) }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn column_index_resolves_and_col_is_const() {
        const COLS: [&str; 3] = ["id", "data", "created_at"];
        // the macro form evaluates in a const context
        const IDX: usize = crate::col!(COLS, "data");
        assert_eq!(column_index(&COLS, "id"), 0);
        assert_eq!(column_index(&COLS, "created_at"), 2);
        assert_eq!(IDX, 1);
        assert_eq!(crate::col!(COLS, "data"), 1);
    }

    #[test]
    #[should_panic(expected = "column_index: name is not in the column list")]
    fn column_index_rejects_an_unknown_name_at_runtime() {
        let _ = column_index(&["id"], "nope");
    }

    #[test]
    fn omit_columns_preserves_order() {
        assert_eq!(
            omit_columns(&["id", "token_hash", "name", "scope"], &["token_hash"]),
            vec!["id", "name", "scope"]
        );
        assert_eq!(omit_columns(&["a", "b", "c"], &["c", "a"]), vec!["b"]);
        assert_eq!(omit_columns(&["a", "b"], &[]), vec!["a", "b"]);
    }

    #[test]
    #[should_panic(expected = "omit_columns: \"token_hsh\" is not in the column list")]
    fn omit_columns_rejects_an_unknown_name() {
        let _ = omit_columns(&["id", "token_hash"], &["token_hsh"]);
    }

    #[test]
    fn qualify_columns_qualifies_and_overrides() {
        let projection = qualify_columns(&["id", "data", "created_at"], "c", |col| match col {
            "data" => Some("c.data::text".to_owned()),
            "created_at" => Some(iso8601_timestamp_column("c", col)),
            _ => None,
        });
        assert_eq!(
            projection,
            r#"c.id, c.data::text, to_char(c.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')"#,
        );
    }

    #[test]
    fn qualify_columns_preserves_order() {
        assert_eq!(qualify_columns(&["b", "a"], "t", |_| None), "t.b, t.a");
    }

    #[test]
    fn iso8601_timestamp_expr_overrides_only_the_named_columns() {
        const COLS: [&str; 4] = ["id", "data", "created_at", "updated_at"];
        let expr = iso8601_timestamp_expr(&COLS, &["created_at", "updated_at"], "c");
        assert_eq!(expr("id"), None);
        assert_eq!(expr("data"), None);
        assert_eq!(
            expr("created_at"),
            Some(iso8601_timestamp_column("c", "created_at")),
        );
        assert_eq!(
            expr("updated_at"),
            Some(iso8601_timestamp_column("c", "updated_at")),
        );
    }

    #[test]
    fn iso8601_timestamp_expr_renders_the_hand_written_match_projection() {
        const COLS: [&str; 3] = ["id", "data", "created_at"];
        let via_expr = qualify_columns(
            &COLS,
            "c",
            iso8601_timestamp_expr(&COLS, &["created_at"], "c"),
        );
        let via_match = qualify_columns(&COLS, "c", |col| match col {
            "created_at" => Some(iso8601_timestamp_column("c", col)),
            _ => None,
        });
        assert_eq!(via_expr, via_match);
    }

    #[test]
    fn iso8601_timestamp_expr_composes_under_another_override() {
        const COLS: [&str; 3] = ["id", "metadata", "created_at"];
        let timestamps = iso8601_timestamp_expr(&COLS, &["created_at"], "al");
        let projection = qualify_columns(&COLS, "al", |col| match col {
            "metadata" => Some("al.metadata::text".to_owned()),
            _ => timestamps(col),
        });
        assert_eq!(
            projection,
            r#"al.id, al.metadata::text, to_char(al.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')"#,
        );
    }

    #[test]
    #[should_panic(expected = "iso8601_timestamp_expr: \"creatd_at\" is not in the column list")]
    fn iso8601_timestamp_expr_rejects_a_name_outside_the_const() {
        let _ = iso8601_timestamp_expr(&["id", "created_at"], &["creatd_at"], "c");
    }

    #[test]
    fn iso8601_with_alias() {
        assert_eq!(
            iso8601_timestamp_column("al", "created_at"),
            r#"to_char(al.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')"#,
        );
    }

    #[test]
    fn iso8601_no_alias() {
        assert_eq!(
            iso8601_timestamp_column("", "created_at"),
            r#"to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')"#,
        );
    }
}
