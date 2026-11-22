//! The request-reads census over this workspace: a spine handler reads its
//! query and its path params only through `fuz_http`'s strict readers. The
//! checks are [`fuz_testing::request_reads_census`]'s, shared with the other
//! workspaces on the spine that run it; this file holds this workspace's inputs — its
//! [`SUPPRESSIONS`] and its positive controls.
//!
//! `RouteParams` carries the one `#[expect]` in production code, over the axum
//! `Path` it wraps. The positive controls below use each disallowed axum type
//! under an `#[expect]`, so a path that stops resolving under this workspace's
//! `clippy.toml` (an axum upgrade moving it) leaves the expectation unfulfilled
//! — an error under `-D warnings`. The two disallowed methods live in `url` and
//! its `form_urlencoded`, which this crate can't name (no direct dependency);
//! their controls are `fuz_storage`'s `tests/request_reads_controls.rs`.

use std::path::PathBuf;

use fuz_testing::request_reads_census::{
    Suppression, assert_clippy_configs_disallow_lenient_readers,
    assert_no_lints_table_allows_disallows, assert_suppressions_listed,
};

// Positive controls: each uses one disallowed type, so the `#[expect]` is
// fulfilled only while clippy resolves that entry. One item per type — a
// shared expectation is fulfilled by any one of them.

#[expect(
    dead_code,
    clippy::disallowed_types,
    reason = "positive control: unfulfilled once `axum::extract::Path` stops resolving"
)]
const fn path_control(_: &axum::extract::Path<String>) {}

#[expect(
    dead_code,
    clippy::disallowed_types,
    reason = "positive control: unfulfilled once `axum::extract::RawPathParams` stops resolving"
)]
const fn raw_path_params_control(_: &axum::extract::RawPathParams) {}

#[expect(
    dead_code,
    clippy::disallowed_types,
    reason = "positive control: unfulfilled once `axum::extract::Query` stops resolving"
)]
const fn query_control(_: &axum::extract::Query<Vec<(String, String)>>) {}

#[expect(
    dead_code,
    clippy::disallowed_types,
    reason = "positive control: unfulfilled once `axum::extract::Form` stops resolving"
)]
const fn form_control(_: &axum::extract::Form<Vec<(String, String)>>) {}

/// Every source file that suppresses the disallow lints, each with its reason.
/// Every other file names none. The exec-free disallows (`fuzi`'s
/// `clippy.toml`) share the lints, so their suppressions are listed here too.
const SUPPRESSIONS: &[Suppression] = &[
    Suppression {
        file: "fuz_http/src/request_target.rs",
        sites: 1,
        reason: "`RouteParams` wraps axum's `Path` after checking every escape",
    },
    Suppression {
        file: "fuz_storage/tests/request_reads_controls.rs",
        sites: 2,
        reason: "the positive controls of the `url` method disallows",
    },
    Suppression {
        file: "fuz_sys/src/path.rs",
        sites: 1,
        reason: "`home_dir`'s one `std::env::home_dir` read, its password-database fallback",
    },
    Suppression {
        file: "fuz_testing/tests/request_reads_census.rs",
        sites: 4,
        reason: "the positive controls of the axum type disallows",
    },
    Suppression {
        file: "fuzi/tests/clean.rs",
        sites: 4,
        reason: "the harness spawns the built `fuzi` binary from outside its exec-free source",
    },
    Suppression {
        file: "fuzi/tests/json_contract.rs",
        sites: 2,
        reason: "the harness spawns the built `fuzi` binary from outside its exec-free source",
    },
    Suppression {
        file: "fuzi/tests/usage.rs",
        sites: 2,
        reason: "the harness spawns the built `fuzi` binary from outside its exec-free source",
    },
];

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

#[test]
fn every_clippy_config_disallows_the_lenient_readers() {
    assert_clippy_configs_disallow_lenient_readers(&workspace_root());
}

#[test]
fn every_suppression_of_the_disallows_is_listed() {
    assert_suppressions_listed(&workspace_root(), SUPPRESSIONS);
}

#[test]
fn no_lints_table_allows_the_disallows() {
    assert_no_lints_table_allows_disallows(&workspace_root());
}
