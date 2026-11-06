//! Database status: connectivity, table row counts, and per-namespace
//! migration state — without a running server.
//!
//! The Rust twin of `fuz_app`'s TS `db/status.ts`. A consumer's `db-status`
//! ops subcommand reads this to answer "is this database current?". Returns
//! structured data ([`DbStatus`]) consumers print however they like
//! ([`format_db_status`] is the stock report).
//!
//! Sibling to [`crate::schema_ready`] (column-presence drift → the deploy
//! gate's `503`) and [`crate::schema_snapshot`] (full structural parity). This
//! is the migration-**tracker** view — what `schema_version` records vs. what
//! the code declares.
//!
//! **Name-divergence aware.** Unlike a count-only check, [`query_db_status`] name-prefix
//! verifies the applied migrations against the code's list, mirroring
//! [`crate::migration::run_migrations`]. A divergent history (same count,
//! different names) is the exact state the runner refuses to boot against, so
//! reporting it as `up-to-date` on a count match would be a lie.

use std::process::ExitCode;

use deadpool_postgres::Pool;

use crate::error::DbError;
use crate::migration_schema::MigrationNamespace;
use crate::pool::{create_pool, pool_config};
use crate::sql_identifier::assert_valid_sql_identifier;

/// Row count for a single public-schema table.
#[derive(Debug, Clone)]
pub struct TableStatus {
    /// Table name.
    pub name: String,
    /// `COUNT(*)` for the table.
    pub row_count: i64,
}

/// A divergence between the recorded migration tracker and the code's list.
///
/// Either variant is a state the runner refuses to boot against — a
/// re-bootstrap (drop + migrate) is needed. Structured (not a pre-formatted
/// string) so programmatic consumers can branch on it; `Display` renders the
/// operator-facing line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Divergence {
    /// An applied name doesn't match the code's name at `position`.
    NameMismatch {
        /// Sequence position of the first mismatch.
        position: usize,
        /// The name recorded in the tracker at `position`.
        applied: String,
        /// The name the code declares at `position`.
        expected: String,
    },
    /// The tracker records more migrations than the code declares.
    BinaryOlder {
        /// Count the code declares.
        declared: usize,
        /// The tracker's names past the code's list, sequence-ascending — the
        /// migrations this binary doesn't know. Never empty; the tracker's
        /// count is `declared + unknown.len()`.
        unknown: Vec<String>,
    },
}

impl std::fmt::Display for Divergence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NameMismatch {
                position,
                applied,
                expected,
            } => write!(
                f,
                "position {position}: database has `{applied}`, code has `{expected}`"
            ),
            Self::BinaryOlder { declared, unknown } => write!(
                f,
                "database has {applied} applied but code declares {declared} (binary older than database)",
                applied = declared + unknown.len(),
            ),
        }
    }
}

/// Applied/pending migration state for one namespace.
#[derive(Debug, Clone)]
pub struct MigrationStatus {
    /// Namespace key (e.g. `fuz_auth`, `fuz_cell`).
    pub namespace: String,
    /// Migration names recorded in the tracker, sequence-ascending.
    pub applied_names: Vec<String>,
    /// Code-side migration names not yet applied (the suffix past `applied`).
    pub pending_names: Vec<String>,
    /// Whether `applied_names` is the full code list with no name divergence.
    pub up_to_date: bool,
    /// The first applied/code divergence, if any. `None` when the applied names
    /// are a clean prefix of the code's list (the only state the runner boots
    /// against). `Some` means a divergent bootstrap history — a re-bootstrap
    /// (drop + migrate) is needed.
    pub divergence: Option<Divergence>,
}

/// Full database status snapshot — the [`query_db_status`] result.
#[derive(Debug, Clone)]
pub struct DbStatus {
    /// Number of tables in the `public` schema (`== tables.len()`).
    pub table_count: usize,
    /// Per-table row counts, name-sorted.
    pub tables: Vec<TableStatus>,
    /// Per-namespace migration status, in the order passed.
    pub migrations: Vec<MigrationStatus>,
}

/// Query connectivity, per-table row counts, and per-namespace migration state.
///
/// Read-only — never mutates. Acquiring the pooled client is the connectivity
/// check; a failure surfaces as [`DbError`] (the Rust shape models "not
/// connected" as `Err`, where the TS twin returns `connected: false`). When
/// `schema_version` is absent (a never-migrated database), every namespace
/// reports zero applied with its full code list pending.
///
/// # Errors
///
/// Returns [`DbError`] when the pool can't yield a client or a query fails.
pub async fn query_db_status(
    pool: &Pool,
    namespaces: &[MigrationNamespace],
) -> Result<DbStatus, DbError> {
    let client = pool.get().await?;

    let schema_version_present: bool = client
        .query_one(
            "SELECT EXISTS ( \
               SELECT 1 FROM information_schema.tables \
               WHERE table_schema = 'public' AND table_name = 'schema_version' \
             ) AS e",
            &[],
        )
        .await?
        .get("e");

    let table_names: Vec<String> = client
        .query(
            "SELECT table_name::text AS t FROM information_schema.tables \
             WHERE table_schema = 'public' ORDER BY table_name",
            &[],
        )
        .await?
        .iter()
        .map(|row| row.get::<_, String>("t"))
        .collect();

    let mut tables = Vec::with_capacity(table_names.len());
    for name in table_names {
        // `name` comes from `information_schema`, but quote-validate before
        // interpolating into the COUNT — defense in depth, never trust a name
        // straight into DDL/DML text.
        assert_valid_sql_identifier(&name)?;
        let sql = format!("SELECT count(*)::bigint AS c FROM \"{name}\"");
        let row_count: i64 = client.query_one(&sql, &[]).await?.get("c");
        tables.push(TableStatus { name, row_count });
    }

    let mut migrations = Vec::with_capacity(namespaces.len());
    for ns in namespaces {
        // No tracker (a never-migrated database) reads as nothing applied yet.
        let applied_names: Vec<String> = if schema_version_present {
            client
                .query(
                    "SELECT name FROM schema_version WHERE namespace = $1 ORDER BY sequence",
                    &[&ns.name],
                )
                .await?
                .iter()
                .map(|row| row.get::<_, String>("name"))
                .collect()
        } else {
            Vec::new()
        };
        migrations.push(migration_status(ns, applied_names));
    }

    Ok(DbStatus {
        table_count: tables.len(),
        tables,
        migrations,
    })
}

/// The first divergence between `ns`'s code-side migration list and the
/// tracker's `applied_names` (sequence-ascending), or `None` when they are a
/// clean prefix of the code's list.
///
/// The one rule both [`crate::migration::run_migrations`] (which refuses to
/// run against a divergence) and [`query_db_status`] (which reports it) apply,
/// so the runner refuses exactly what `db status` calls diverged. The length
/// check comes first: a binary-older history that also renames a migration in
/// the overlap reports [`Divergence::BinaryOlder`], not a name mismatch, so the
/// operator isn't sent chasing a phantom source revert.
pub(crate) fn namespace_divergence<S: AsRef<str>>(
    ns: &MigrationNamespace,
    applied_names: &[S],
) -> Option<Divergence> {
    let declared = ns.migrations.len();
    if applied_names.len() > declared {
        return Some(Divergence::BinaryOlder {
            declared,
            unknown: applied_names[declared..]
                .iter()
                .map(|name| name.as_ref().to_owned())
                .collect(),
        });
    }
    ns.migrations
        .iter()
        .zip(applied_names)
        .position(|(code, db)| code.name != db.as_ref())
        .map(|i| Divergence::NameMismatch {
            position: i,
            applied: applied_names[i].as_ref().to_owned(),
            expected: ns.migrations[i].name.to_owned(),
        })
}

/// Classify one namespace's tracker rows against the code's list — the pure
/// core of [`query_db_status`].
///
/// `applied_names` are the tracker's names for `ns`, sequence-ascending (empty
/// when the tracker is absent), classified by [`namespace_divergence`] — the
/// runner's own rule. The pending list is the code suffix past the applied count,
/// clamped, so a binary-older history has no pending tail.
fn migration_status(ns: &MigrationNamespace, applied_names: Vec<String>) -> MigrationStatus {
    let declared = ns.migrations.len();
    let applied = applied_names.len();
    let divergence = namespace_divergence(ns, &applied_names);

    let pending_names: Vec<String> = ns
        .migrations
        .iter()
        .skip(applied.min(declared))
        .map(|m| m.name.to_owned())
        .collect();

    MigrationStatus {
        namespace: ns.name.to_owned(),
        up_to_date: applied == declared && divergence.is_none(),
        applied_names,
        pending_names,
        divergence,
    }
}

/// The code's declared migration count for `ns` — the report's denominator.
///
/// `applied + pending` everywhere but a binary-older history, where the tracker
/// holds more rows than the code declares and the pending tail is empty; the
/// declared count is then the one the divergence carries.
const fn declared_count(ns: &MigrationStatus) -> usize {
    match ns.divergence {
        Some(Divergence::BinaryOlder { declared, .. }) => declared,
        _ => ns.applied_names.len() + ns.pending_names.len(),
    }
}

/// Render a [`DbStatus`] as the body of the human-facing operator report.
///
/// A `tables:` count with one aligned `name  N rows` line per table, then a
/// `migrations:` header (always printed, even with no namespaces) and one
/// aligned line per namespace: its state (`up-to-date`, `PENDING <n>`, or
/// `DIVERGED`), `applied/declared`, and the latest applied name (`(none)` when
/// nothing is applied). A diverged namespace adds a `diverged:` line (the
/// [`Divergence`] `Display`), a pending one a `pending:` line naming the tail.
/// Every line ends in `\n`.
///
/// The body only — the `database status` / `url:` header belongs to the CLI
/// wrapper ([`run_db_status_cli`]), which holds the URL a [`DbStatus`] never
/// sees. Byte-identical with the TS twin's `format_db_status` for a connected
/// status; both test suites pin the same fixture report.
#[must_use]
pub fn format_db_status(status: &DbStatus) -> String {
    let mut lines = vec![format!("  tables: {}", status.table_count)];

    let table_width = status
        .tables
        .iter()
        .map(|t| t.name.len())
        .max()
        .unwrap_or(0);
    for table in &status.tables {
        lines.push(format!(
            "    {:<table_width$}  {} rows",
            table.name, table.row_count
        ));
    }

    lines.push(String::new());
    lines.push("  migrations:".to_owned());

    let ns_width = status
        .migrations
        .iter()
        .map(|ns| ns.namespace.len())
        .max()
        .unwrap_or(0);
    for ns in &status.migrations {
        let state = if ns.divergence.is_some() {
            "DIVERGED".to_owned()
        } else if ns.up_to_date {
            "up-to-date".to_owned()
        } else {
            format!("PENDING {}", ns.pending_names.len())
        };
        let latest = ns.applied_names.last().map_or("(none)", String::as_str);
        lines.push(format!(
            "    {:<ns_width$}  {state:<12} {}/{}  latest: {latest}",
            ns.namespace,
            ns.applied_names.len(),
            declared_count(ns),
        ));
        if let Some(divergence) = &ns.divergence {
            lines.push(format!("    {:<ns_width$}    diverged: {divergence}", ""));
        } else if !ns.pending_names.is_empty() {
            lines.push(format!(
                "    {:<ns_width$}    pending: {}",
                "",
                ns.pending_names.join(", ")
            ));
        }
    }

    lines.join("\n") + "\n"
}

/// Printed in place of a database URL [`display_db_url`] won't render.
const UNPARSEABLE_DB_URL: &str = "(not a URL; hidden)";

/// The port tokio-postgres dials when the URL names none.
const DEFAULT_PG_PORT: u16 = 5432;

/// Render a database URL for printing from the config the pool actually dials
/// ([`pool_config`]), so the line names the server dialed and no credential can
/// leak however the input spells it.
///
/// The shape is `postgres://[user@]host:port[/dbname]` — the first host and
/// port only, never the password, and no query parameter (`sslmode` and the
/// like are dropped by design). tokio-postgres reads no fragment, so a `#…`
/// after the database name prints as part of it, encoded (`db%23frag`), and a
/// `dbname=` query parameter replaces the path's name. The scheme always prints
/// as `postgres://`, a `postgresql://` input or a `key=value` string included.
/// The port always prints, `5432` when the input names none. The user and
/// database name print percent-encoded with `encodeURIComponent`'s unreserved
/// set, so no control character, escape sequence, or bidi override reaches the
/// terminal and an `@` can't pose as the separator; each prints only when
/// non-empty. An IP-literal host prints canonically (IPv6 bracketed); a
/// Unix-socket directory prints with each `/` as `%2F`.
///
/// The whole line is `(not a URL; hidden)` when the input doesn't parse, when a
/// URL holds a malformed percent-escape (`%ZZ`), when there is no host (the
/// pool would fall back to default socket directories), when the host is
/// neither an IP literal, a hostname of `A-Z a-z 0-9 . _ -`, nor a socket
/// directory of those characters and `/`, or when the user holds `?`, `=`, `&`,
/// `/`, or `#`. Those last two catch tokio-postgres's split at the **first**
/// `@`, which pushes the tail of an unencoded-`@` password, or a query secret
/// ahead of a later `@`, into the host or the user.
///
/// Twin of the TS `display_db_url`, byte-identical on the URLs both drivers
/// read alike. They part where the drivers do: node-postgres lets a `host=` or
/// `port=` query parameter override the URL's, where tokio-postgres appends it
/// to a list whose first entry the pool dials (a `user=` parameter wins in
/// both); a `dbname=` query parameter replaces the database name here and is
/// ignored by node-postgres, and a `#…` fragment, which `new URL` drops, stays
/// part of the database name here; `new URL` rejects `key=value` strings, host
/// lists, and an unencoded `/` or `?` in the password; an unencoded `@` in the
/// userinfo splits at the last `@` there (the TS twin renders the user and host
/// it dials, where this side prints the placeholder); node-postgres decodes the
/// database name with `decodeURI`, so a reserved-character escape such as `%2F`
/// stays literal there and prints as `%252F`; an IPv4-mapped IPv6 address
/// serializes differently; and tokio-postgres refuses an unknown query
/// parameter (`sslpassword=`) that node-postgres passes.
fn display_db_url(database_url: &str) -> String {
    render_db_url(database_url).unwrap_or_else(|| UNPARSEABLE_DB_URL.to_owned())
}

fn render_db_url(database_url: &str) -> Option<String> {
    let is_url =
        database_url.starts_with("postgres://") || database_url.starts_with("postgresql://");
    if is_url && has_malformed_escape(database_url) {
        return None;
    }
    let config = pool_config(database_url).ok()?;

    let mut shown = String::from("postgres://");
    if let Some(user) = config.user.as_deref().filter(|user| !user.is_empty()) {
        if user.contains(['?', '=', '&', '/', '#']) {
            return None;
        }
        shown.push_str(&encode_uri_component(user));
        shown.push('@');
    }
    shown.push_str(&display_host(config.host.as_deref()?)?);
    shown.push(':');
    shown.push_str(&config.port.unwrap_or(DEFAULT_PG_PORT).to_string());
    if let Some(dbname) = config.dbname.as_deref().filter(|dbname| !dbname.is_empty()) {
        shown.push('/');
        shown.push_str(&encode_uri_component(dbname));
    }
    Some(shown)
}

/// Whether `url` holds a `%` not followed by two hex digits.
fn has_malformed_escape(url: &str) -> bool {
    let bytes = url.as_bytes();
    bytes.iter().enumerate().any(|(i, &byte)| {
        byte == b'%'
            && !(bytes.get(i + 1).is_some_and(u8::is_ascii_hexdigit)
                && bytes.get(i + 2).is_some_and(u8::is_ascii_hexdigit))
    })
}

/// A host as [`display_db_url`] prints it, or `None` when it isn't an IP
/// literal, a hostname, or a socket directory.
fn display_host(host: &str) -> Option<String> {
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return Some(match ip {
            std::net::IpAddr::V4(v4) => v4.to_string(),
            std::net::IpAddr::V6(v6) => format!("[{v6}]"),
        });
    }
    let plain = |byte: u8| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-');
    if let Some(dir) = host.strip_prefix('/') {
        return dir
            .bytes()
            .all(|byte| plain(byte) || byte == b'/')
            .then(|| host.replace('/', "%2F"));
    }
    (!host.is_empty() && host.bytes().all(plain)).then(|| host.to_owned())
}

/// Percent-encode `value` as JS `encodeURIComponent` does: `A-Z a-z 0-9` and
/// `- _ . ! ~ * ' ( )` pass through, every other UTF-8 byte becomes `%XX`.
fn encode_uri_component(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&byte) {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0xF)]));
        }
    }
    encoded
}

/// The complete `db-status` ops subcommand: read `DATABASE_URL`, open a pool,
/// query migration status for `namespaces`, print the report, and return an
/// exit code.
///
/// The reusable body behind every spine consumer's `db-status` subcommand — the
/// consumer's binary matches the arg and calls this in one line. Reads **only**
/// `DATABASE_URL` (not a full server-env validation) so a status check works
/// without the rest of the app's config. Mirrors the `run_*_cli` shape (cf.
/// `fuz_audit::run_check_release_cli`). The printed URL is rendered from the
/// driver's parse, without the password or query (`display_db_url`).
pub async fn run_db_status_cli(namespaces: &[MigrationNamespace]) -> ExitCode {
    let Ok(database_url) = std::env::var("DATABASE_URL") else {
        eprintln!("error: DATABASE_URL required for db-status");
        return ExitCode::FAILURE;
    };
    let pool = match create_pool(&database_url, &crate::pool::PoolOptions::default()) {
        Ok(pool) => pool,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };
    match query_db_status(&pool, namespaces).await {
        Ok(status) => {
            print!(
                "database status\n  url: {}\n{}",
                display_db_url(&database_url),
                format_db_status(&status)
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DbStatus, Divergence, MigrationStatus, TableStatus, display_db_url, encode_uri_component,
        format_db_status, migration_status,
    };
    use crate::migration_schema::{Migration, MigrationNamespace};

    const fn named(name: &'static str) -> Migration {
        Migration { name, sql: "" }
    }

    fn names(names: &[&str]) -> Vec<String> {
        names.iter().map(|&n| n.to_owned()).collect()
    }

    fn ns_status(
        namespace: &str,
        applied: &[&str],
        pending: &[&str],
        divergence: Option<Divergence>,
    ) -> MigrationStatus {
        MigrationStatus {
            namespace: namespace.to_owned(),
            up_to_date: pending.is_empty() && divergence.is_none(),
            applied_names: names(applied),
            pending_names: names(pending),
            divergence,
        }
    }

    /// One namespace in each state the report renders. The TS twin's
    /// `format_db_status` test pins this same status to the same bytes.
    fn fixture_status() -> DbStatus {
        DbStatus {
            table_count: 2,
            tables: vec![
                TableStatus {
                    name: "account".to_owned(),
                    row_count: 3,
                },
                TableStatus {
                    name: "schema_version".to_owned(),
                    row_count: 7,
                },
            ],
            migrations: vec![
                ns_status("fuz_auth", &["full_auth_schema"], &[], None),
                ns_status(
                    "app_notes",
                    &["create_notes"],
                    &["add_note_tags", "add_note_index"],
                    None,
                ),
                ns_status(
                    "fuz_cell",
                    &["cell_v0"],
                    &[],
                    Some(Divergence::NameMismatch {
                        position: 0,
                        applied: "cell_v0".to_owned(),
                        expected: "full_cell_schema".to_owned(),
                    }),
                ),
                ns_status("app_fresh", &[], &["create_fresh"], None),
                ns_status(
                    "app_older",
                    &["m0", "m1", "m2_unknown"],
                    &[],
                    Some(Divergence::BinaryOlder {
                        declared: 2,
                        unknown: vec!["m2_unknown".to_owned()],
                    }),
                ),
            ],
        }
    }

    /// The expected report for [`fixture_status`] — shared verbatim with the TS
    /// twin's test.
    const FIXTURE_REPORT: &str = "  tables: 2
    account         3 rows
    schema_version  7 rows

  migrations:
    fuz_auth   up-to-date   1/1  latest: full_auth_schema
    app_notes  PENDING 2    1/3  latest: create_notes
                 pending: add_note_tags, add_note_index
    fuz_cell   DIVERGED     1/1  latest: cell_v0
                 diverged: position 0: database has `cell_v0`, code has `full_cell_schema`
    app_fresh  PENDING 1    0/1  latest: (none)
                 pending: create_fresh
    app_older  DIVERGED     3/2  latest: m2_unknown
                 diverged: database has 3 applied but code declares 2 (binary older than database)
";

    #[test]
    fn format_renders_every_namespace_state() {
        assert_eq!(format_db_status(&fixture_status()), FIXTURE_REPORT);
    }

    #[test]
    fn format_binary_older_denominator_is_the_declared_count() {
        // 3 applied against 2 declared reads `3/2`, not `applied + pending`
        // (`3/3`, the pending tail being empty).
        let status = DbStatus {
            table_count: 0,
            tables: vec![],
            migrations: vec![ns_status(
                "older",
                &["m0", "m1", "m2"],
                &[],
                Some(Divergence::BinaryOlder {
                    declared: 2,
                    unknown: vec!["m2".to_owned()],
                }),
            )],
        };
        let report = format_db_status(&status);
        assert!(
            report.contains("DIVERGED     3/2  latest: m2\n"),
            "{report}"
        );
    }

    #[test]
    fn format_prints_the_migrations_header_with_no_namespaces() {
        let status = DbStatus {
            table_count: 0,
            tables: vec![],
            migrations: vec![],
        };
        assert_eq!(format_db_status(&status), "  tables: 0\n\n  migrations:\n");
    }

    #[test]
    fn divergence_display_names_the_mismatch() {
        let name_mismatch = Divergence::NameMismatch {
            position: 1,
            applied: "wrong_at_end".to_owned(),
            expected: "m1".to_owned(),
        };
        assert_eq!(
            name_mismatch.to_string(),
            "position 1: database has `wrong_at_end`, code has `m1`"
        );
        let binary_older = Divergence::BinaryOlder {
            declared: 2,
            unknown: vec!["m2_unknown".to_owned()],
        };
        assert_eq!(
            binary_older.to_string(),
            "database has 3 applied but code declares 2 (binary older than database)"
        );
    }

    const NS_TWO: MigrationNamespace = MigrationNamespace::new("ns", &[named("m0"), named("m1")]);

    #[test]
    fn migration_status_no_rows_pends_the_full_list() {
        // The missing-tracker read: `query_db_status` passes no names.
        let m = migration_status(&NS_TWO, vec![]);
        assert_eq!(m.namespace, "ns");
        assert!(m.applied_names.is_empty());
        assert_eq!(m.pending_names, names(&["m0", "m1"]));
        assert!(!m.up_to_date);
        assert_eq!(m.divergence, None);
    }

    #[test]
    fn migration_status_no_rows_and_no_code_is_up_to_date() {
        let m = migration_status(&MigrationNamespace::new("empty", &[]), vec![]);
        assert!(m.up_to_date);
        assert!(m.pending_names.is_empty());
        assert_eq!(m.divergence, None);
    }

    #[test]
    fn migration_status_clean_prefix_pends_the_tail() {
        let m = migration_status(&NS_TWO, names(&["m0"]));
        assert_eq!(m.pending_names, names(&["m1"]));
        assert!(!m.up_to_date);
        assert_eq!(m.divergence, None);

        let m = migration_status(&NS_TWO, names(&["m0", "m1"]));
        assert!(m.pending_names.is_empty());
        assert!(m.up_to_date);
        assert_eq!(m.divergence, None);
    }

    #[test]
    fn migration_status_name_mismatch_at_the_overlap_end() {
        // Same count, last name differs — a count-only check would call it current.
        let m = migration_status(&NS_TWO, names(&["m0", "wrong_at_end"]));
        assert!(!m.up_to_date);
        assert!(m.pending_names.is_empty());
        assert_eq!(
            m.divergence,
            Some(Divergence::NameMismatch {
                position: 1,
                applied: "wrong_at_end".to_owned(),
                expected: "m1".to_owned(),
            })
        );
    }

    #[test]
    fn migration_status_binary_older_has_no_pending_tail() {
        let m = migration_status(&NS_TWO, names(&["m0", "m1", "m2_unknown"]));
        assert!(!m.up_to_date);
        assert!(m.pending_names.is_empty());
        assert_eq!(
            m.divergence,
            Some(Divergence::BinaryOlder {
                declared: 2,
                unknown: vec!["m2_unknown".to_owned()],
            })
        );
    }

    /// Input → exact rendering for the shapes both drivers read alike. The TS
    /// twin's `display_db_url` test carries the same table.
    const SHARED_DISPLAY_CASES: &[(&str, &str)] = &[
        (
            "postgres://user:secret@db.example.com:5432/app",
            "postgres://user@db.example.com:5432/app",
        ),
        ("postgres://localhost/app", "postgres://localhost:5432/app"),
        (
            "postgresql://user@localhost/app",
            "postgres://user@localhost:5432/app",
        ),
        (
            "postgres://u:pw@[::1]:6543/db",
            "postgres://u@[::1]:6543/db",
        ),
        ("postgres://[0:0::1]/db", "postgres://[::1]:5432/db"),
        ("postgres://127.0.0.1/db", "postgres://127.0.0.1:5432/db"),
        (
            "postgres://U%40x@HOST/D%20b",
            "postgres://U%40x@HOST:5432/D%20b",
        ),
        (
            "postgres://%2Fvar%2Frun%2Fpg/db",
            "postgres://%2Fvar%2Frun%2Fpg:5432/db",
        ),
        ("postgres://h/", "postgres://h:5432"),
        (
            "postgres://h:5432/db?sslmode=disable&application_name=x",
            "postgres://h:5432/db",
        ),
        // a query `user=` replaces the URL's in both drivers
        ("postgres://u@h/db?user=admin", "postgres://admin@h:5432/db"),
        // control characters, escape sequences, and bidi overrides stay encoded
        ("postgres://h/d%0Ab", "postgres://h:5432/d%0Ab"),
        ("postgres://h/%1B%5B31mx", "postgres://h:5432/%1B%5B31mx"),
        (
            "postgres://%E2%80%AEu@h/db",
            "postgres://%E2%80%AEu@h:5432/db",
        ),
        // the placeholder: no host, a host that isn't a hostname, a user a
        // misparse could have produced, a malformed escape, no parse at all
        ("postgres:///db", "(not a URL; hidden)"),
        ("postgres://h%20x/db", "(not a URL; hidden)"),
        ("postgres://h%3Ax/db", "(not a URL; hidden)"),
        ("postgres://a%3Db@h/db", "(not a URL; hidden)"),
        ("postgres://u%ZZ@h/db", "(not a URL; hidden)"),
        ("postgres://h/db?user=u%ZZ", "(not a URL; hidden)"),
        ("garbage", "(not a URL; hidden)"),
    ];

    /// Inputs carrying the secret `s3cr3t` where a string-level redactor, or a
    /// misparse, leaks it: an unencoded `/`, `?`, or `@` in the password
    /// (tokio-postgres ends the credentials at the first `@`), a query secret
    /// ahead of a later `@`, and password query parameters, percent-encoded keys
    /// included (both drivers decode them). The TS twin's test carries the same
    /// list.
    const LEAK_CASES: &[&str] = &[
        "postgres://u:s3cr3t/b@h/db",
        "postgres://u:s3cr3t?b@h",
        "postgres://u:a/s3cr3t?c@h",
        "postgres://u:s3cr3t@x@h/db",
        "postgres://u:p@s3cr3t@h/db",
        "postgres://h?password=s3cr3t:x@b",
        "postgres://h?sslpassword=@b&sslpassword=s3cr3t",
        "postgres://u@h/db?password=s3cr3t",
        "postgres://u@h/db?pass%77ord=s3cr3t",
        "postgres://u@h/db?sslpassword=s3cr3t",
    ];

    #[test]
    fn display_renders_the_shared_cases() {
        for &(input, expected) in SHARED_DISPLAY_CASES {
            assert_eq!(display_db_url(input), expected, "input: {input}");
        }
    }

    #[test]
    fn display_never_prints_the_password() {
        let leaks: Vec<String> = LEAK_CASES
            .iter()
            .filter_map(|&input| {
                let shown = display_db_url(input);
                shown
                    .contains("s3cr3t")
                    .then(|| format!("{input} -> {shown}"))
            })
            .collect();
        assert!(leaks.is_empty(), "{leaks:#?}");
    }

    #[test]
    fn display_names_the_server_the_pool_dials() {
        // the pool dials the first host and port; a query `host=` / `port=` is
        // appended to tokio-postgres's lists, never dialed
        assert_eq!(
            display_db_url("postgres://u@h/db?host=prod.example.com&port=6000"),
            "postgres://u@h:5432/db"
        );
        assert_eq!(
            display_db_url("postgres://h1:5432,h2:5433/db"),
            "postgres://h1:5432/db"
        );
        // `hostaddr` isn't carried, and with no host the pool falls back to
        // default socket directories — no single server to name
        assert_eq!(
            display_db_url("hostaddr=127.0.0.1 user=u"),
            "(not a URL; hidden)"
        );
    }

    #[test]
    fn display_renders_what_only_tokio_postgres_parses() {
        // a key=value conninfo string — `new URL` rejects it, so the TS twin
        // prints the placeholder
        assert_eq!(
            display_db_url("host=/var/run/pg user=u password=s3cr3t dbname=d port=5433"),
            "postgres://u@%2Fvar%2Frun%2Fpg:5433/d"
        );
        // tokio-postgres decodes every escape in the database name (node-postgres
        // keeps a reserved one literal and prints `a%252Fb`)
        assert_eq!(
            display_db_url("postgres://h/a%2Fb"),
            "postgres://h:5432/a%2Fb"
        );
        // a `%` in a conninfo value is no escape
        assert_eq!(
            display_db_url("host=h user=u password=50%off"),
            "postgres://u@h:5432"
        );
        // tokio-postgres splits at the first `@`, so a password's tail lands in
        // the host — not a hostname, so the placeholder (the TS twin splits at
        // the last `@` and renders `postgres://u@h:5432/db`)
        assert_eq!(
            display_db_url("postgres://u:p@ss@h/db"),
            "(not a URL; hidden)"
        );
    }

    #[test]
    fn encode_uri_component_keeps_only_the_unreserved_set() {
        assert_eq!(encode_uri_component("Az09-_.!~*'()"), "Az09-_.!~*'()");
        assert_eq!(
            encode_uri_component("a b/@:?#\u{202e}é"),
            "a%20b%2F%40%3A%3F%23%E2%80%AE%C3%A9"
        );
    }
}
