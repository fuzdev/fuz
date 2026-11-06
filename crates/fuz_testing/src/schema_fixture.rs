//! The drift guard over a server's committed `expected_schema.json` — the
//! column map its `/ready` deploy gate embeds.

// A test assertion helper, so a failure panics; `clippy.toml`'s
// `allow-expect-in-tests` carve-out covers `#[test]` bodies, not a library
// module, so the allow is explicit.
#![allow(clippy::expect_used)]

use std::collections::BTreeMap;
use std::path::Path;

use fuz_db::{Pool, check_schema_drift, query_ready_columns};

/// The env var that makes [`assert_expected_schema_fixture`] rewrite the
/// fixture from the live schema before asserting — set it to `1` after an
/// intentional schema change, then review the diff.
pub const UPDATE_SCHEMA_READY: &str = "UPDATE_SCHEMA_READY";

/// Assert the fixture at `path` equals the `public` column map of `pool`, a
/// fresh bootstrap of the server's migration chain
/// ([`crate::fresh_test_db_pool`]).
///
/// `/ready` checks only that the live database has every column the fixture
/// names, so a stale fixture fails one of two ways: naming a column a
/// migration removed, every deploy answers `503`; missing one a migration
/// added, the addition goes ungated. With [`UPDATE_SCHEMA_READY`] set to `1`
/// it rewrites the fixture first. Also asserts the map keeps the
/// `schema_version` tracker (so a never-migrated database fails readiness)
/// and that the drift check flags a missing column.
///
/// # Panics
///
/// On a database failure, an unreadable or unparseable fixture, or drift.
pub async fn assert_expected_schema_fixture(pool: &Pool, path: &Path) {
    let client = pool.get().await.expect("pool.get");
    let live: BTreeMap<String, Vec<String>> = query_ready_columns(&client, "public")
        .await
        .expect("query ready columns");
    assert!(
        live.contains_key("schema_version"),
        "query_ready_columns keeps the schema_version tracker"
    );

    if std::env::var(UPDATE_SCHEMA_READY).as_deref() == Ok("1") {
        let json = serde_json::to_string_pretty(&live).expect("serialize fixture") + "\n";
        std::fs::write(path, json).expect("write fixture");
    }

    let raw = std::fs::read_to_string(path).expect("read the committed expected_schema.json");
    let committed: BTreeMap<String, Vec<String>> =
        serde_json::from_str(&raw).expect("parse the committed expected_schema.json");
    assert_eq!(
        live, committed,
        "expected_schema.json drifted from a fresh bootstrap — regenerate with {UPDATE_SCHEMA_READY}=1"
    );

    assert!(check_schema_drift(&live, &committed).ok);
    let mut absent = committed;
    absent
        .entry("schema_version".to_owned())
        .or_default()
        .push("nonexistent_col".to_owned());
    assert!(
        !check_schema_drift(&live, &absent).ok,
        "the drift check flags a missing column"
    );
}
