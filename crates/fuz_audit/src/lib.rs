//! Release-time dep-graph audit for the fuz ecosystem.
//!
//! Each consumer workspace's xtask asserts that no production build can pull in
//! a [`FORBIDDEN_CRATES`] entry. Consumers enter through one of the CLI
//! wrappers — [`run_check_release_cli`] from a subcommand-router arm,
//! [`xtask_main`] as the whole `main`, or [`run_check_release_cli_with_rules`]
//! where the workspace layers on its own forbids. The wrappers are the crate's
//! entry surface: the audit prints its findings and returns a process exit
//! code, and the report it builds (`AuditReport`) stays internal. The built-in
//! forbidden list is `["fuz_testing", "fuz_audit"]`:
//!
//! - `fuz_testing` ships `fuz_auth::PasswordHasher` impls with
//!   weakened argon2 params; linking it from a production binary
//!   would silently weaken password hashing.
//! - `fuz_audit` (this crate) is build-tooling only; including its
//!   dead code in production binaries would be a layering smell.
//!
//! The audit reads `cargo metadata --all-features` and runs these passes:
//!
//! - **Declared edges.** Every local (path, `source: null`) package — other
//!   than a `testing_*`-named one, a `dev_only` one (below), or a forbidden crate
//!   itself — must not *declare* a normal or build dependency on a globally
//!   forbidden crate, optional or not, for any target platform. A library no
//!   production binary reaches is checked all the same, so the forbid
//!   holds before some binary starts linking it.
//! - **Production binaries.** Each workspace binary that is not `testing_*`
//!   and not `dev_only` is walked over its resolved normal edges, with every
//!   feature on so optional edges are walked too, against the global forbids
//!   and its own [`PerBinaryForbid`] rules.
//! - **Crate layering** ([`BUILTIN_CRATE_LAYERING`]).
//! - **Test-only features.** A feature whose name starts with `test_`,
//!   declared by a local package, is test-only — a seam a test enables from
//!   `[dev-dependencies]`. Enabling one on a normal or build edge of any
//!   package a release build compiles is refused (see
//!   [`TEST_ONLY_FEATURE_PREFIX`]). Only local packages are read: the
//!   `test_*` features of registry and git packages are not derived or checked.
//! - **Lint tables** (the `lint_tables` module). A workspace member that
//!   re-declares its own `[lints.<tool>]` tables instead of
//!   `[lints] workspace = true` (a crate that needs `unsafe`, since Cargo
//!   replaces a crate's `[lints]` whole) must keep the workspace's: the same set
//!   of tool tables as `[workspace.lints.*]`, and every workspace lint at the
//!   same level and priority, except `rust.unsafe_code` ([`UNSAFE_CODE`]), which
//!   it declares at `deny` or `forbid` at the workspace's priority. When its
//!   `unsafe_code` isn't `forbid`, no lib or bin crate root may lift it with a
//!   top-of-file `#![allow(unsafe_code)]` / `#![expect(unsafe_code, …)]` (or a
//!   `cfg_attr` of one). Lints it adds pass and are listed. `cargo metadata`
//!   carries no lint tables, so this pass reads the manifests with a line-based
//!   reader that refuses, as a tooling failure, any lint-table shape it doesn't
//!   understand; the root manifest is read only once a member re-declares. A
//!   workspace without `[workspace.lints]` doesn't check its re-declaring
//!   members (the output names them), and a member with no `[lints]` at all is
//!   named in a note.
//!
//! What it cannot see: a local package outside this workspace that no edge in
//! the resolved graph reaches (one behind a path dependency's optional edge
//! this workspace leaves off) is absent from the metadata. Every spine crate is
//! a member of the `fuz` workspace, whose own `check-release` checks it there.
//!
//! ## Usage from an xtask
//!
//! Pick the entry point by xtask shape:
//!
//! - [`xtask_main`] — single-subcommand consumer xtask whose only job is
//!   `cargo xtask check-release`. Reads `std::env::args`, dispatches the
//!   `check-release` subcommand, prints usage to stdout for `help` / `-h`
//!   / `--help` and the no-arg case (exit 0), and errors to stderr on an
//!   unknown subcommand (exit 1). The whole xtask `main.rs` is three lines:
//!
//!   ```no_run
//!   use std::process::ExitCode;
//!
//!   fn main() -> ExitCode { fuz_audit::xtask_main() }
//!   ```
//!
//! - [`run_check_release_cli`] — the audit dispatch itself, for xtasks
//!   that have their own subcommand router (e.g. `argh`-derived). Call
//!   from inside the dispatch arm that matches `check-release`:
//!
//!   ```no_run
//!   use std::process::ExitCode;
//!
//!   fn main() -> ExitCode {
//!       fuz_audit::run_check_release_cli()
//!   }
//!   ```
//!
//! For workspace-specific forbids — extra global crates, or per-binary rules
//! — pass an [`AuditRules`] POD to [`run_check_release_cli_with_rules`] from the
//! router arm instead of the bare [`run_check_release_cli`].
//!
//! ## Dev-only opt-out
//!
//! Dev-only binaries (xtask, scratch tooling) opt out by declaring
//! themselves in their `Cargo.toml`:
//!
//! ```toml
//! [package.metadata.fuz_audit]
//! dev_only = true
//! ```
//!
//! The audit then excludes those packages' `[[bin]]` targets from the
//! production scan. Without this opt-out, an xtask consuming
//! `fuz_audit` would self-fail the audit (xtask depends on `fuz_audit`,
//! and `fuz_audit` is forbidden in production binary dep trees).

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::process::{Command, ExitCode};

use serde_json::Value;
use thiserror::Error;

mod lint_tables;

use lint_tables::LintTablesReport;
pub use lint_tables::UNSAFE_CODE;

/// Crate names whose presence in a production binary's transitive dep
/// tree is a release-safety violation.
///
/// Stored as a slice so callers can iterate without allocating; not
/// parameterized because the list is load-bearing policy, not
/// configuration.
pub const FORBIDDEN_CRATES: &[&str] = &["fuz_testing", "fuz_audit"];

/// Errors from running the audit. Distinguishes setup failures
/// (couldn't run `cargo metadata`, malformed output) from policy
/// findings — violations are part of [`AuditReport`], not errors.
#[derive(Debug, Error)]
enum AuditError {
    /// Failed to spawn `cargo metadata`.
    #[error("failed to run `cargo metadata`")]
    CargoRun(#[source] std::io::Error),

    /// `cargo metadata` exited non-zero.
    #[error("`cargo metadata` failed: {stderr}")]
    CargoFailed { stderr: String },

    /// `cargo metadata` output failed to parse.
    #[error("failed to parse `cargo metadata` output")]
    Parse(#[source] serde_json::Error),

    /// `cargo metadata` output is missing a field the audit expects.
    #[error("unexpected `cargo metadata` shape: {0}")]
    MetadataShape(&'static str),

    /// A manifest or crate root the lint-table pass reads couldn't be read.
    #[error("failed to read {}", path.display())]
    ReadFile {
        /// The file.
        path: PathBuf,
        /// The read's error.
        #[source]
        source: std::io::Error,
    },

    /// A manifest's lint tables are in a shape the lint-table reader doesn't
    /// understand, so it can't vouch for them.
    #[error("the lint-table reader can't read {}", path.display())]
    LintTableShape {
        /// The manifest.
        path: PathBuf,
        /// The line and shape refused.
        #[source]
        source: lint_tables::LintShapeError,
    },
}

impl AuditError {
    /// Process exit code for a *tooling* failure (sysexits-style) — distinct
    /// from the clean (`0`) and policy-violation
    /// (`POLICY_VIOLATION_EXIT_CODE`) outcomes a successful run reports via
    /// [`AuditReport::exit_code`].
    ///
    /// Exhaustive on purpose: a new variant must be classified rather than
    /// silently sharing a code (the `fuz_archive::is_security_violation` bar).
    #[must_use]
    const fn exit_code(&self) -> u8 {
        match self {
            // `cargo metadata` couldn't be produced — the support tool failed
            // to run, or ran but exited non-zero. The metadata is unavailable.
            Self::CargoRun(_) | Self::CargoFailed { .. } => 69, // EX_UNAVAILABLE
            // `cargo metadata` ran but its output didn't parse / lacked an
            // expected field, a manifest or crate root it names couldn't be
            // read, or a manifest's lint tables are in a shape the reader
            // doesn't understand — an unexpected internal/tooling state.
            Self::Parse(_)
            | Self::MetadataShape(_)
            | Self::ReadFile { .. }
            | Self::LintTableShape { .. } => 70, // EX_SOFTWARE
        }
    }
}

/// Exit code for the policy-violation outcome — a production binary links a
/// forbidden crate. `EX_DATAERR`: the audited dep graph is well-formed but
/// violates release policy, the supply-chain analogue of `fuz_archive`'s
/// hostile-data → 65. Clean runs exit `0`; tooling failures use
/// [`AuditError::exit_code`].
const POLICY_VIOLATION_EXIT_CODE: u8 = 65;

/// A single production-binary → forbidden-crate dep chain.
#[derive(Debug, Clone, PartialEq, Eq)]
struct AuditViolation {
    /// Name of the production binary target (e.g. `fuz`, `fuzd`).
    binary: String,
    /// Name of the Cargo package owning the binary target.
    package: String,
    /// Name of the forbidden crate reached.
    forbidden: String,
    /// Package names along the dep chain, starting with `package` and
    /// ending with `forbidden`.
    chain: Vec<String>,
}

impl AuditViolation {
    /// Render the chain as `a -> b -> c -> forbidden`.
    #[must_use]
    fn chain_display(&self) -> String {
        self.chain.join(" -> ")
    }
}

impl std::fmt::Display for AuditViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "production binary `{}` (package `{}`) transitively depends on `{}` via: {}",
            self.binary,
            self.package,
            self.forbidden,
            self.chain_display(),
        )
    }
}

/// A local package declaring a normal or build dependency on a globally
/// forbidden crate — whether or not any production binary links it yet.
#[derive(Debug, Clone, PartialEq, Eq)]
struct DeclaredForbiddenViolation {
    /// The declaring package.
    package: String,
    /// The forbidden crate it declares.
    forbidden: String,
    /// The edge as declared: kind, optional, target platform.
    edge: String,
}

impl std::fmt::Display for DeclaredForbiddenViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "package `{}` declares a dependency on the forbidden crate `{}` ({}) — a \
             forbidden crate belongs in `[dev-dependencies]`, or in a `testing_*` or \
             `dev_only` package",
            self.package, self.forbidden, self.edge,
        )
    }
}

/// A per-crate layering violation: library `crate_name` transitively reaches a
/// crate it is forbidden to depend on (see [`CrateLayering`]).
#[derive(Debug, Clone, PartialEq, Eq)]
struct LayeringViolation {
    /// The subject crate the layering rule constrains (e.g. `fuz_fact`).
    crate_name: String,
    /// The forbidden crate it reached.
    forbidden: String,
    /// Package names along the dep chain, `crate_name` → `forbidden`.
    chain: Vec<String>,
}

impl LayeringViolation {
    /// Render the chain as `a -> b -> forbidden`.
    #[must_use]
    fn chain_display(&self) -> String {
        self.chain.join(" -> ")
    }
}

impl std::fmt::Display for LayeringViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "crate `{}` must not depend on `{}` (layering), but reaches it via: {}",
            self.crate_name,
            self.forbidden,
            self.chain_display(),
        )
    }
}

/// A test-only feature ([`TestOnlyFeature`]) enabled where a release build
/// compiles it in.
#[derive(Debug, Clone, PartialEq, Eq)]
struct TestOnlyFeatureViolation {
    /// The package whose normal or build dependency edge enables the feature.
    package: String,
    /// The crate the feature belongs to (e.g. `fuz_http`).
    crate_name: String,
    /// The test-only feature (e.g. `test_router_access`).
    feature: String,
    /// How the edge enables it — the edge's own feature list, the crate's
    /// default features, or a feature of `package`.
    via: String,
}

impl std::fmt::Display for TestOnlyFeatureViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "package `{}` enables the test-only feature `{}/{}` on a normal or build \
             dependency edge ({}) — a release build that includes `{}` compiles it in, and \
             resolver 2 unifies a normal edge's features into every binary of the build; \
             enable it from `[dev-dependencies]` only",
            self.package, self.crate_name, self.feature, self.via, self.package,
        )
    }
}

/// Outcome of a successful audit run. `is_clean()` distinguishes
/// passing from failing — the audit *running* doesn't error on policy
/// findings; policy findings go in [`Self::violations`].
#[derive(Debug, Clone)]
struct AuditReport {
    /// Production binaries that were scanned (binary target name +
    /// owning package name).
    scanned: Vec<(String, String)>,
    /// Forbidden crate names not present in this workspace at all.
    /// Surfaced informationally; passes the audit trivially.
    absent_forbidden: Vec<String>,
    /// All dep-chain violations found, in scan order.
    violations: Vec<AuditViolation>,
    /// Declared edges from local packages to globally forbidden crates (see
    /// [`DeclaredForbiddenViolation`]).
    declared_violations: Vec<DeclaredForbiddenViolation>,
    /// Local packages whose declared edges were checked against the global
    /// forbids.
    declared_checked: usize,
    /// Per-crate layering violations (see [`LayeringViolation`]).
    layering_violations: Vec<LayeringViolation>,
    /// Layering subjects (`CrateLayering::crate_name`) that were present in this
    /// workspace and actually checked. Surfaced informationally so a subject
    /// that silently dropped out of the graph (e.g. a crate rename that didn't
    /// update the rule) is visible rather than skipped green.
    layering_checked: Vec<String>,
    /// Test-only features enabled where a release build reaches them (see
    /// [`TestOnlyFeature`]).
    test_feature_violations: Vec<TestOnlyFeatureViolation>,
    /// Test-only features (`crate/feature`) whose crate is in this workspace
    /// and that were actually checked — surfaced like `layering_checked`.
    test_features_checked: Vec<String>,
    /// The lint-table pass (see the `lint_tables` module): the re-declaring
    /// members checked, their permitted differences, and any rule broken.
    lint_tables: LintTablesReport,
}

impl AuditReport {
    /// `true` when no production binary reaches a forbidden crate, no local
    /// package declares a release edge to one, no per-crate layering rule is
    /// violated, no test-only feature is enabled on a release edge, and every
    /// re-declared lint table keeps the workspace's.
    #[must_use]
    const fn is_clean(&self) -> bool {
        self.violations.is_empty()
            && self.declared_violations.is_empty()
            && self.layering_violations.is_empty()
            && self.test_feature_violations.is_empty()
            && self.lint_tables.is_clean()
    }

    /// Process exit code for the audit outcome (sysexits-style): clean → `0`;
    /// any policy violation → `POLICY_VIOLATION_EXIT_CODE` (`65`, `EX_DATAERR`).
    /// A tooling failure never reaches a report — it surfaces as an
    /// [`AuditError`] with its own [`exit_code`](AuditError::exit_code).
    #[must_use]
    const fn exit_code(&self) -> u8 {
        if self.is_clean() {
            0
        } else {
            POLICY_VIOLATION_EXIT_CODE
        }
    }
}

/// A per-binary forbidden-crate rule.
///
/// Production binary [`Self::binary`] must not transitively link any crate in
/// [`Self::crates`], on top of the global [`FORBIDDEN_CRATES`] +
/// [`AuditRules::extra_forbidden`] set.
///
/// Expresses "binary X must not depend on crate Y, while sibling binary Z in the
/// same workspace may" — which a global forbid can't. The motivating case:
/// `fuz`/`fuzd` must not depend on any `fuzi_*` crate, yet the `fuzi` binary
/// legitimately depends on `fuzi_core`.
#[derive(Debug, Clone, Copy)]
pub struct PerBinaryForbid<'a> {
    /// Production binary target name (e.g. `fuz`, `fuzd`).
    pub binary: &'a str,
    /// Crates forbidden for this binary specifically.
    pub crates: &'a [&'a str],
}

/// A per-crate layering rule: library [`Self::crate_name`] must not
/// transitively depend on any crate in [`Self::forbidden_deps`].
///
/// Generalizes the binary-only forbids to the library graph — one rule per real
/// invariant, grown only on need (no speculative rule table). The rules: the
/// storage↔serving splits of the substrate (`fuz_fact`, `fuz_cell`) and the
/// foundation leaves staying HTTP/DB-free (`fuz_sys`, `fuz_home`):
///
/// - `fuz_fact` is a pure content-addressed byte store and must never reach the
///   HTTP / cell / authz / action layers, so fact bytes can only ever reach a
///   client through the authz'd `fuz_fact_serving` facade.
/// - `fuz_cell` is the cell **storage/authz** half and must not reach
///   `fuz_actions` (the verb/dispatch layer that `fuz_cell_actions` owns). This
///   is the structural half of the `fuz_cell` / `fuz_cell_actions` split, and
///   it's load-bearing: `fuz_fact_serving` composes `fuz_cell::can_view_cell`
///   *without* the RPC verbs, which only holds because `fuz_cell` itself stays
///   off `fuz_actions`. Note this rule is narrower than `fuz_fact`'s — it cannot
///   forbid `axum`/`fuz_http`, since `fuz_cell` legitimately reaches both
///   *transitively through `fuz_auth`* (its authz predicates need the auth
///   types), which the runtime-graph BFS would flag.
/// - `fuz_sys` (the generic OS/system leaf) must not reach `axum` / `fuz_http`,
///   and `fuz_home` (the `~/.fuz` layer) must not reach `axum` / `fuz_db` /
///   `fuz_http` — neither may grow a back-edge into the HTTP stack, and
///   `fuz_home` stays DB-free too.
///
/// A refactor that reintroduced a forbidden edge — an un-authz'd byte-store
/// bypass, or a re-merge of the cell split — fails `cargo xtask check-release`.
#[derive(Debug, Clone, Copy)]
pub struct CrateLayering<'a> {
    /// The subject crate the rule constrains.
    pub crate_name: &'a str,
    /// Crates the subject must not transitively (runtime-)depend on.
    pub forbidden_deps: &'a [&'a str],
}

/// Built-in per-crate layering rules.
///
/// Applied unconditionally by *every* workspace's `check-release` — the single
/// source of truth, picked up by the `fuz` xtask and every consumer's. A
/// subject crate absent from a workspace is skipped (the rule simply doesn't
/// apply there); the subjects that *were* checked are surfaced in the OK output
/// so a silently-vanished subject (e.g. a renamed crate) is visible rather than
/// skipped green.
pub const BUILTIN_CRATE_LAYERING: &[CrateLayering] = &[
    CrateLayering {
        crate_name: "fuz_fact",
        forbidden_deps: &["axum", "fuz_http", "fuz_cell", "fuz_auth", "fuz_actions"],
    },
    CrateLayering {
        crate_name: "fuz_cell",
        forbidden_deps: &["fuz_actions"],
    },
    // The foundation leaves stay off the HTTP stack: `fuz_sys` is the generic
    // OS/system leaf and `fuz_home` the `~/.fuz` layer, and neither may grow a
    // back-edge into it; `fuz_home` stays DB-free too.
    CrateLayering {
        crate_name: "fuz_sys",
        forbidden_deps: &["axum", "fuz_http"],
    },
    CrateLayering {
        crate_name: "fuz_home",
        forbidden_deps: &["axum", "fuz_db", "fuz_http"],
    },
];

/// The name prefix that marks a feature of a local package as test-only.
///
/// A crate gates a test-only escape hatch behind such a feature — `fuz_http`'s
/// `test_router_access` exposes `GatedRouter::into_router_for_testing`, the
/// composed router a shipping binary must not reach; `fuz_crypto`'s
/// `test_trust_anchor`, `fuz_home`'s `test_home_override`, and `fuz_artifact`'s
/// `test_binary_stubs` are the others.
/// The audit derives the set from the metadata — every feature of a local
/// (`source: null`) package whose name starts with this prefix — so a new seam
/// is covered the moment it is declared, with no list to keep. Registry and
/// git packages are not read: a crates.io package names its own features, and
/// the `test_*` features of a spine crate a consumer takes from git rather than
/// by path are not derived, so enabling one on a release edge goes unflagged.
pub const TEST_ONLY_FEATURE_PREFIX: &str = "test_";

/// A test-only feature: `crate_name`'s `feature`, which only tests may enable.
///
/// Enabled from a `[dev-dependencies]` entry, the feature is built only for
/// tests: resolver 2 leaves dev-dependency features out of a normal build.
/// Enabled on a **normal** edge, it is compiled in, and not just for the
/// package that enables it — resolver 2 unifies a crate's features across every
/// package one build compiles, so a `testing_*` server or an xtask that enables
/// it puts it into the production binaries of `cargo build --workspace
/// --release` too. A **build** edge compiles it into what the build script
/// runs; refused as well, since a seam that weakens a check has no place in a
/// build either.
///
/// The audit flags every package a workspace member reaches over normal or
/// build edges (the packages a `--workspace` release build compiles) whose
/// normal or build dependency on `crate_name` enables `feature` — in the
/// edge's `features` list, through the crate's default features, or through a
/// feature of the package naming `crate/feature` — counting every feature of
/// the crate that implies it. A feature of the package that is itself
/// test-only may name another; it is checked where it is enabled.
///
/// The rule reads declared edges, not `cargo metadata`'s resolved feature
/// sets: those unify over dev-dependencies as well, so they would report the
/// feature as on whenever a test enables it — the one legitimate use.
#[derive(Debug, Clone, Copy)]
struct TestOnlyFeature<'a> {
    /// The crate that declares the feature.
    crate_name: &'a str,
    /// The test-only feature.
    feature: &'a str,
}

/// Per-workspace forbidden-crate rules layered on top of the built-in
/// [`FORBIDDEN_CRATES`] — the single config POD the rules-taking entry point
/// [`run_check_release_cli_with_rules`] carries.
///
/// `Default` (both fields empty) reproduces the bare [`run_check_release_cli`]
/// behavior.
#[derive(Debug, Clone, Default)]
pub struct AuditRules<'a> {
    /// Extra crates forbidden for *every* production binary, on top of the
    /// built-in [`FORBIDDEN_CRATES`]. The `fuz` workspace adds `fuz_sign` (the
    /// signing crate) so its `fuz` binary's graph excludes signing — `fuz` must
    /// only ever verify — while `fuzf`/`xtask` use `fuz_sign` freely.
    pub extra_forbidden: &'a [&'a str],
    /// Per-binary forbidden-crate rules (see [`PerBinaryForbid`]).
    pub per_binary: &'a [PerBinaryForbid<'a>],
}

/// Core audit: spawn `cargo metadata` for the workspace at the cwd and scan it
/// with `rules` layered on the built-in [`FORBIDDEN_CRATES`].
///
/// Returns `Ok(report)` whether or not violations were found — the caller
/// checks [`AuditReport::is_clean`]. `Err` is a tooling failure (see
/// [`AuditError`]), not a policy finding.
fn audit_release(rules: &AuditRules) -> Result<AuditReport, AuditError> {
    let metadata = run_cargo_metadata()?;
    let mut global: Vec<&str> = FORBIDDEN_CRATES.to_vec();
    global.extend_from_slice(rules.extra_forbidden);
    let lint_tables =
        lint_tables::audit_lint_tables(&metadata, &|path| std::fs::read_to_string(path))?;
    let mut report =
        audit_metadata_with_rules(&metadata, &global, rules.per_binary, BUILTIN_CRATE_LAYERING)?;
    report.lint_tables = lint_tables;
    Ok(report)
}

/// Convenience CLI entry point: runs the audit against the cwd, prints
/// results to stdout/stderr, and returns a process exit code.
///
/// Call it from the `check-release` arm of an xtask's subcommand router.
/// Applies the built-in [`FORBIDDEN_CRATES`] and [`BUILTIN_CRATE_LAYERING`]
/// with no workspace-specific forbids; for those, the rules-taking entry
/// point is [`run_check_release_cli_with_rules`].
#[must_use]
pub fn run_check_release_cli() -> ExitCode {
    run_check_release_cli_with_rules(&AuditRules::default())
}

/// Like [`run_check_release_cli`] but applies per-workspace [`AuditRules`]
/// (extra global forbids + per-binary forbids) on top of [`FORBIDDEN_CRATES`].
///
/// The single rules-taking entry point: pass one [`AuditRules`] POD instead of
/// threading positional forbid lists. The no-arg [`run_check_release_cli`] is
/// `run_check_release_cli_with_rules(&AuditRules::default())`.
///
/// The exit code (sysexits): clean → `0`, a policy violation → `65`
/// (`EX_DATAERR`), a tooling failure → `69` (`EX_UNAVAILABLE`: `cargo
/// metadata` could not be produced) or `70` (`EX_SOFTWARE`: its output did
/// not parse or lacked an expected field, a manifest or crate root it names
/// could not be read, or a manifest's lint tables are in a shape the
/// lint-table reader doesn't understand).
#[must_use]
pub fn run_check_release_cli_with_rules(rules: &AuditRules) -> ExitCode {
    let report = match audit_release(rules) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: {e}");
            if let Some(source) = std::error::Error::source(&e) {
                eprintln!("  caused by: {source}");
            }
            return ExitCode::from(e.exit_code());
        }
    };

    // Surface absent forbids loudly on *every* run (not buried in the clean
    // path): a forbid that resolves to no package catches nothing, so a
    // typo'd or renamed entry would disable the guard with no signal.
    if !report.absent_forbidden.is_empty() {
        eprintln!(
            "note: {} forbidden crate(s) resolve to no package in this workspace, so no binary \
             walk can reach them (declared edges are still matched by name): {}. Verify this is \
             intended — a typo or renamed crate silently disables the guard.",
            report.absent_forbidden.len(),
            report.absent_forbidden.join(", "),
        );
    }

    // a member with no `[lints]` takes no lint table at all, which the
    // lint-table pass can't hold to the workspace's
    if !report.lint_tables.without_lints.is_empty() {
        eprintln!(
            "note: {} workspace member(s) declare no [lints], so no lint table applies to them \
             and the lint-table check skips them: {}. Add `[lints] workspace = true` unless \
             this is intended.",
            report.lint_tables.without_lints.len(),
            report.lint_tables.without_lints.join(", "),
        );
    }

    if report.is_clean() {
        println!(
            "OK: no production binary depends on forbidden crates, no local package declares a \
             release edge to one, no crate-layering rule is violated, no test-only feature is \
             enabled on a release edge, and every re-declared lint table keeps the workspace's"
        );
        for (bin, pkg) in &report.scanned {
            println!("  {bin} (package {pkg})");
        }
        println!(
            "  declared edges checked: {} local package(s)",
            report.declared_checked
        );
        if !report.layering_checked.is_empty() {
            println!("  layering checked: {}", report.layering_checked.join(", "));
        }
        if !report.test_features_checked.is_empty() {
            println!(
                "  test-only features checked: {}",
                report.test_features_checked.join(", ")
            );
        }
        print_lint_tables_checked(&report.lint_tables);
    } else {
        for v in &report.violations {
            eprintln!("error: {v}");
        }
        for v in &report.declared_violations {
            eprintln!("error: {v}");
        }
        for v in &report.layering_violations {
            eprintln!("error: {v}");
        }
        for v in &report.test_feature_violations {
            eprintln!("error: {v}");
        }
        for v in &report.lint_tables.violations {
            eprintln!("error: {v}");
        }
        let total = report.violations.len()
            + report.declared_violations.len()
            + report.layering_violations.len()
            + report.test_feature_violations.len()
            + report.lint_tables.violations.len();
        eprintln!(
            "audit failed: {total} violation{}",
            if total == 1 { "" } else { "s" },
        );
    }
    ExitCode::from(report.exit_code())
}

/// The clean run's lint-table lines: each re-declaring member checked, with its
/// permitted differences from the workspace's tables, so a crate that stops
/// being checked shows up.
fn print_lint_tables_checked(report: &LintTablesReport) {
    if !report.unchecked.is_empty() {
        println!(
            "  lint tables: not checked, the workspace manifest has no [workspace.lints] \
             (re-declaring: {})",
            report.unchecked.join(", ")
        );
    }
    if report.checked.is_empty() {
        if !report.unchecked.is_empty() {
            return;
        }
        println!(
            "  lint tables checked: none re-declared ({} member(s) inherit the workspace's)",
            report.inheriting.len()
        );
        return;
    }
    let names: Vec<&str> = report.checked.iter().map(|c| c.package.as_str()).collect();
    println!(
        "  lint tables checked: {} ({} other member(s) inherit the workspace's)",
        names.join(", "),
        report.inheriting.len()
    );
    for checked in &report.checked {
        if checked.differences.is_empty() {
            println!("    {}: same as the workspace's", checked.package);
        } else {
            println!(
                "    {}: {}",
                checked.package,
                checked.differences.join("; ")
            );
        }
    }
}

/// Single-subcommand xtask entry point: dispatches `cargo xtask
/// check-release` and emits a usage message for missing / unknown args.
///
/// Reads `std::env::args` and delegates to `xtask_main_inner`. Use
/// this as the entire body of a consumer-workspace xtask `main.rs`:
///
/// ```no_run
/// use std::process::ExitCode;
/// fn main() -> ExitCode { fuz_audit::xtask_main() }
/// ```
///
/// For multi-subcommand xtasks (e.g. `argh`-derived), call
/// [`run_check_release_cli`] from inside the dispatch arm instead.
#[must_use]
pub fn xtask_main() -> ExitCode {
    xtask_main_inner(std::env::args().skip(1))
}

/// Args-injected core of [`xtask_main`] — separated so unit tests can
/// drive the dispatch without spawning a subprocess.
///
/// Takes an iterator over the post-program-name args. Matches the first
/// arg: `check-release` → delegates to [`run_check_release_cli`]; `help` /
/// `-h` / `--help` and the no-arg case → usage to stdout, `ExitCode::SUCCESS`;
/// an unknown subcommand → error + usage to stderr, `ExitCode::FAILURE`.
#[must_use]
fn xtask_main_inner(mut args: impl Iterator<Item = String>) -> ExitCode {
    match args.next().as_deref() {
        Some("check-release") => run_check_release_cli(),
        None | Some("help" | "-h" | "--help") => {
            println!("usage: cargo xtask check-release");
            ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!("error: unknown xtask subcommand `{other}`");
            eprintln!("usage: cargo xtask check-release");
            ExitCode::FAILURE
        }
    }
}

// ─── implementation ─────────────────────────────────────────────────

/// The `cargo` arguments the audit reads the workspace with — every feature
/// on, so the binary walk sees optional edges too.
const CARGO_METADATA_ARGS: [&str; 5] = [
    "metadata",
    "--format-version",
    "1",
    "--locked",
    "--all-features",
];

/// Run `cargo metadata --all-features` in the cwd — the workspace the xtask
/// was invoked in.
fn run_cargo_metadata() -> Result<Value, AuditError> {
    let output = Command::new("cargo")
        .args(CARGO_METADATA_ARGS)
        .output()
        .map_err(AuditError::CargoRun)?;
    if !output.status.success() {
        return Err(AuditError::CargoFailed {
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        });
    }
    serde_json::from_slice(&output.stdout).map_err(AuditError::Parse)
}

/// Two-arg convenience over [`audit_metadata_with_rules`] (global forbids
/// only). Used by the unit tests to keep call sites terse.
#[cfg(test)]
fn audit_metadata(metadata: &Value, forbidden: &[&str]) -> Result<AuditReport, AuditError> {
    audit_metadata_with_rules(metadata, forbidden, &[], &[])
}

/// Core audit. `global_forbidden` applies to every production binary; each
/// [`PerBinaryForbid`] in `per_binary` additionally forbids its `crates` for the
/// named binary only. A binary's effective forbidden set is the union of the two.
/// `global_forbidden` is also checked against every local package's declared
/// edges ([`DeclaredForbiddenViolation`]). `layering` is the per-crate rule set
/// ([`CrateLayering`]); the test-only features ([`TestOnlyFeature`]) are derived
/// from the metadata.
fn audit_metadata_with_rules(
    metadata: &Value,
    global_forbidden: &[&str],
    per_binary: &[PerBinaryForbid],
    layering: &[CrateLayering],
) -> Result<AuditReport, AuditError> {
    let packages = metadata
        .get("packages")
        .and_then(Value::as_array)
        .ok_or(AuditError::MetadataShape("packages array missing"))?;

    // Every forbidden name mentioned, globally or per-binary.
    let mut all_names: Vec<&str> = global_forbidden.to_vec();
    for rule in per_binary {
        all_names.extend_from_slice(rule.crates);
    }
    all_names.sort_unstable();
    all_names.dedup();

    // Resolve names → package ids; names absent from the workspace are
    // surfaced informationally (they pass trivially). A name can resolve to more
    // than one id (duplicate package names), so register *every* matching id —
    // missing one would let a binary reaching that id slip past unflagged.
    let mut name_to_ids: HashMap<&str, Vec<String>> = HashMap::new();
    let mut forbidden_id_to_name: HashMap<String, String> = HashMap::new();
    let mut absent_forbidden: Vec<String> = Vec::new();
    for name in all_names {
        let ids = find_package_ids(packages, name);
        if ids.is_empty() {
            absent_forbidden.push(name.to_string());
            continue;
        }
        for id in &ids {
            forbidden_id_to_name.insert((*id).to_string(), name.to_string());
        }
        name_to_ids.insert(name, ids.iter().map(|id| (*id).to_string()).collect());
    }

    let members = workspace_member_ids(metadata)?;
    let production_bins = collect_production_binaries(packages, &members);
    let nodes = build_node_map(metadata, EdgeKinds::Normal)?;
    let id_to_name = build_id_to_name(packages);

    // Global forbidden ids apply to every production binary. A name may resolve
    // to multiple ids, so flatten every id (not just the first) into the set.
    let global_ids: HashSet<&str> = global_forbidden
        .iter()
        .filter_map(|n| name_to_ids.get(n))
        .flat_map(|ids| ids.iter().map(String::as_str))
        .collect();

    let mut violations: Vec<AuditViolation> = Vec::new();
    for (binary, package_id) in &production_bins {
        // Effective forbidden ids = global ∪ this binary's per-binary rule.
        let mut applicable: HashSet<&str> = global_ids.clone();
        for rule in per_binary {
            if rule.binary == binary.as_str() {
                for &n in rule.crates {
                    if let Some(ids) = name_to_ids.get(n) {
                        for id in ids {
                            applicable.insert(id.as_str());
                        }
                    }
                }
            }
        }
        if applicable.is_empty() {
            continue;
        }
        let reached = bfs_find_paths(&nodes, package_id, &applicable);
        for (target_id, chain_ids) in reached {
            let chain_names: Vec<String> = chain_ids
                .iter()
                .map(|id| {
                    id_to_name
                        .get(id.as_str())
                        .cloned()
                        .unwrap_or_else(|| id.clone())
                })
                .collect();
            let forbidden_name = forbidden_id_to_name
                .get(&target_id)
                .cloned()
                .unwrap_or_else(|| target_id.clone());
            let package_name = id_to_name
                .get(package_id.as_str())
                .cloned()
                .unwrap_or_else(|| package_id.clone());
            violations.push(AuditViolation {
                binary: binary.clone(),
                package: package_name,
                forbidden: forbidden_name,
                chain: chain_names,
            });
        }
    }

    // Per-crate layering pass: BFS from each subject library crate to its
    // forbidden deps over the same runtime graph. A subject absent from the
    // workspace is skipped (the rule doesn't apply there).
    let mut layering_violations: Vec<LayeringViolation> = Vec::new();
    let mut layering_checked: Vec<String> = Vec::new();
    for rule in layering {
        // A subject name may resolve to multiple ids; check each so a duplicate
        // subject crate can't hide a forbidden edge behind a non-first id.
        let subject_ids = find_package_ids(packages, rule.crate_name);
        if subject_ids.is_empty() {
            continue;
        }
        layering_checked.push(rule.crate_name.to_string());
        let targets: HashSet<&str> = rule
            .forbidden_deps
            .iter()
            .flat_map(|n| find_package_ids(packages, n))
            .collect();
        if targets.is_empty() {
            continue;
        }
        for subject_id in subject_ids {
            for (target_id, chain_ids) in bfs_find_paths(&nodes, subject_id, &targets) {
                let chain: Vec<String> = chain_ids
                    .iter()
                    .map(|id| {
                        id_to_name
                            .get(id.as_str())
                            .cloned()
                            .unwrap_or_else(|| id.clone())
                    })
                    .collect();
                let forbidden = id_to_name
                    .get(target_id.as_str())
                    .cloned()
                    .unwrap_or(target_id);
                layering_violations.push(LayeringViolation {
                    crate_name: rule.crate_name.to_string(),
                    forbidden,
                    chain,
                });
            }
        }
    }

    let (declared_violations, declared_checked) =
        find_declared_forbidden_edges(packages, global_forbidden);

    let test_only_features = derive_test_only_features(packages);
    let release_nodes = build_node_map(metadata, EdgeKinds::NormalAndBuild)?;
    let (test_feature_violations, test_features_checked) =
        find_test_only_feature_violations(packages, &release_nodes, &members, &test_only_features);

    Ok(AuditReport {
        scanned: production_bins
            .into_iter()
            .map(|(bin, pkg_id)| {
                let pkg_name = id_to_name
                    .get(pkg_id.as_str())
                    .cloned()
                    .unwrap_or_else(|| pkg_id.clone());
                (bin, pkg_name)
            })
            .collect(),
        absent_forbidden,
        violations,
        declared_violations,
        declared_checked,
        layering_violations,
        layering_checked,
        test_feature_violations,
        test_features_checked,
        lint_tables: LintTablesReport::default(),
    })
}

/// The [`TestOnlyFeature`] pass: every package a release build compiles whose
/// normal or build dependency edge enables a test-only feature, plus the
/// `crate/feature` names checked. `nodes` carries normal and build edges.
///
/// A declaring crate that is itself a workspace member and whose own
/// `default` implies the feature is refused whatever its dependers do:
/// `cargo build --workspace` selects the member from the command line, with
/// its default features, so every binary of that build gets the feature even
/// when each depender turns the defaults off.
fn find_test_only_feature_violations(
    packages: &[Value],
    nodes: &HashMap<String, Vec<String>>,
    members: &HashSet<&str>,
    rules: &[TestOnlyFeature],
) -> (Vec<TestOnlyFeatureViolation>, Vec<String>) {
    let mut violations = Vec::new();
    let mut checked = Vec::new();
    if rules.is_empty() {
        return (violations, checked);
    }
    let built = release_build_closure(members, nodes);
    for rule in rules {
        let declaring: Vec<&Value> = packages
            .iter()
            .filter(|p| p.get("name").and_then(Value::as_str) == Some(rule.crate_name))
            .collect();
        if declaring.is_empty() {
            continue;
        }
        checked.push(format!("{}/{}", rule.crate_name, rule.feature));
        let implying = features_implying(&declaring, rule.feature);
        if implying.contains("default") {
            for p in &declaring {
                let is_member = p
                    .get("id")
                    .and_then(Value::as_str)
                    .is_some_and(|id| members.contains(id));
                if is_member && features_implying(&[*p], rule.feature).contains("default") {
                    violations.push(TestOnlyFeatureViolation {
                        package: rule.crate_name.to_string(),
                        crate_name: rule.crate_name.to_string(),
                        feature: rule.feature.to_string(),
                        via: "its own default features, as a workspace member — \
                              `cargo build --workspace` builds it with them"
                            .to_string(),
                    });
                }
            }
        }
        for p in packages {
            let Some(id) = p.get("id").and_then(Value::as_str) else {
                continue;
            };
            if !built.contains(id) {
                continue;
            }
            let package = p.get("name").and_then(Value::as_str).unwrap_or(id);
            let local = is_local_package(p);
            let deps = p.get("dependencies").and_then(Value::as_array);
            for dep in deps.into_iter().flatten() {
                let Some(kind) = release_edge_kind(dep) else {
                    continue;
                };
                let mut via: Vec<String> = Vec::new();
                if dep.get("name").and_then(Value::as_str) == Some(rule.crate_name) {
                    for f in str_array(dep.get("features")) {
                        if implying.contains(f) {
                            via.push(format!("its {kind} dependency enables `{f}`"));
                        }
                    }
                    let uses_default = dep
                        .get("uses_default_features")
                        .and_then(Value::as_bool)
                        .unwrap_or(true);
                    if uses_default && implying.contains("default") {
                        via.push(format!("the crate's default features, on a {kind} edge"));
                    }
                    // a feature of the package naming the dependency by its
                    // key — unless that feature is test-only itself, checked
                    // where it is enabled
                    let key = dep
                        .get("rename")
                        .and_then(Value::as_str)
                        .unwrap_or(rule.crate_name);
                    if let Some(own) = p.get("features").and_then(Value::as_object) {
                        for (own_feature, entries) in own {
                            if local && own_feature.starts_with(TEST_ONLY_FEATURE_PREFIX) {
                                continue;
                            }
                            for entry in str_array(Some(entries)) {
                                let Some((dep_key, f)) = entry.split_once('/') else {
                                    continue;
                                };
                                if dep_key.trim_end_matches('?') == key && implying.contains(f) {
                                    via.push(format!(
                                        "its feature `{own_feature}` enables `{entry}` on a \
                                         {kind} edge"
                                    ));
                                }
                            }
                        }
                    }
                }
                for via in via {
                    violations.push(TestOnlyFeatureViolation {
                        package: package.to_string(),
                        crate_name: rule.crate_name.to_string(),
                        feature: rule.feature.to_string(),
                        via,
                    });
                }
            }
        }
    }
    (violations, checked)
}

/// The declared-edge pass: every local package — not `testing_*`-named, not
/// `dev_only`, not itself a forbidden crate — whose normal or build dependency
/// names a crate in `forbidden`, optional or not, for any target platform.
/// Returns the violations and the number of packages checked.
///
/// Reads `packages[].dependencies`, the edges as declared, not the resolved
/// graph: an optional edge no feature turns on, a target-specific edge, and a
/// library no production binary reaches yet are refused all the same.
fn find_declared_forbidden_edges(
    packages: &[Value],
    forbidden: &[&str],
) -> (Vec<DeclaredForbiddenViolation>, usize) {
    let mut violations = Vec::new();
    let mut checked = 0;
    for p in packages {
        let Some(name) = p.get("name").and_then(Value::as_str) else {
            continue;
        };
        if !is_local_package(p)
            || name.starts_with("testing_")
            || forbidden.contains(&name)
            || is_dev_only_package(p)
        {
            continue;
        }
        checked += 1;
        let deps = p.get("dependencies").and_then(Value::as_array);
        for dep in deps.into_iter().flatten() {
            let Some(dep_name) = dep.get("name").and_then(Value::as_str) else {
                continue;
            };
            if !forbidden.contains(&dep_name) {
                continue;
            }
            let Some(kind) = release_edge_kind(dep) else {
                continue;
            };
            let mut edge = vec![format!("{kind} edge")];
            if dep.get("optional").and_then(Value::as_bool) == Some(true) {
                edge.push("optional".to_string());
            }
            if let Some(target) = dep.get("target").and_then(Value::as_str) {
                edge.push(format!("target `{target}`"));
            }
            violations.push(DeclaredForbiddenViolation {
                package: name.to_string(),
                forbidden: dep_name.to_string(),
                edge: edge.join(", "),
            });
        }
    }
    (violations, checked)
}

/// Every test-only feature: each feature of a local package whose name starts
/// with [`TEST_ONLY_FEATURE_PREFIX`], sorted and deduplicated by
/// `crate/feature`.
fn derive_test_only_features(packages: &[Value]) -> Vec<TestOnlyFeature<'_>> {
    let mut out: Vec<TestOnlyFeature> = Vec::new();
    for p in packages {
        if !is_local_package(p) {
            continue;
        }
        let Some(crate_name) = p.get("name").and_then(Value::as_str) else {
            continue;
        };
        let Some(features) = p.get("features").and_then(Value::as_object) else {
            continue;
        };
        for feature in features.keys() {
            if feature.starts_with(TEST_ONLY_FEATURE_PREFIX) {
                out.push(TestOnlyFeature {
                    crate_name,
                    feature: feature.as_str(),
                });
            }
        }
    }
    out.sort_unstable_by_key(|f| (f.crate_name, f.feature));
    out.dedup_by_key(|f| (f.crate_name, f.feature));
    out
}

/// `true` for a local package — a workspace member or a path dependency,
/// which `cargo metadata` reports with `source: null`.
fn is_local_package(package: &Value) -> bool {
    package.get("source").is_none_or(Value::is_null)
}

/// The kind of a declared dependency edge a release build compiles —
/// `"normal"` or `"build"` — or `None` for a dev edge.
fn release_edge_kind(dep: &Value) -> Option<&'static str> {
    match dep.get("kind").and_then(Value::as_str) {
        None => Some("normal"),
        Some("build") => Some("build"),
        Some(_) => None,
    }
}

/// The package ids `cargo metadata` lists as `workspace_members` — what
/// `cargo build --workspace` selects. Not `source: null`, which every path
/// dependency carries too, member or not.
fn workspace_member_ids(metadata: &Value) -> Result<HashSet<&str>, AuditError> {
    Ok(metadata
        .get("workspace_members")
        .and_then(Value::as_array)
        .ok_or(AuditError::MetadataShape("workspace_members array missing"))?
        .iter()
        .filter_map(Value::as_str)
        .collect())
}

/// Every package id a `cargo build --workspace --release` compiles: the
/// workspace members and all they reach over the edges `nodes` carries (normal
/// and build, for the test-only feature pass).
fn release_build_closure<'a>(
    members: &HashSet<&'a str>,
    nodes: &'a HashMap<String, Vec<String>>,
) -> HashSet<&'a str> {
    let mut built: HashSet<&str> = HashSet::new();
    let mut queue: VecDeque<&str> = members.iter().copied().collect();
    while let Some(id) = queue.pop_front() {
        if !built.insert(id) {
            continue;
        }
        if let Some(deps) = nodes.get(id) {
            queue.extend(deps.iter().map(String::as_str));
        }
    }
    built
}

/// `feature` and every feature of the declaring crate that enables it,
/// directly or through another — `default` included when it does.
fn features_implying<'a>(declaring: &[&'a Value], feature: &'a str) -> HashSet<&'a str> {
    let mut implying: HashSet<&str> = std::iter::once(feature).collect();
    let tables: Vec<&serde_json::Map<String, Value>> = declaring
        .iter()
        .filter_map(|p| p.get("features").and_then(Value::as_object))
        .collect();
    loop {
        let before = implying.len();
        for table in &tables {
            for (name, entries) in *table {
                if str_array(Some(entries)).any(|e| implying.contains(e)) {
                    implying.insert(name.as_str());
                }
            }
        }
        if implying.len() == before {
            return implying;
        }
    }
}

/// The string elements of a JSON array (none when absent or not an array).
fn str_array(value: Option<&Value>) -> impl Iterator<Item = &str> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
}

/// Resolve a package `name` to **every** matching package id, not just the
/// first. Names are usually unique, but two packages can legitimately share one
/// (two semver-majors, or a workspace crate colliding with a crates.io crate) —
/// and the audit must register *all* of them as forbidden/subject/target ids, or
/// a production binary reaching a non-first id would slip past unflagged. Returns
/// an empty `Vec` for a name absent from the workspace (the caller treats that as
/// "absent").
fn find_package_ids<'a>(packages: &'a [Value], name: &str) -> Vec<&'a str> {
    packages
        .iter()
        .filter(|p| p.get("name").and_then(Value::as_str) == Some(name))
        .filter_map(|p| p.get("id").and_then(Value::as_str))
        .collect()
}

fn build_id_to_name(packages: &[Value]) -> HashMap<&str, String> {
    let mut map = HashMap::new();
    for p in packages {
        if let (Some(id), Some(name)) = (
            p.get("id").and_then(Value::as_str),
            p.get("name").and_then(Value::as_str),
        ) {
            map.insert(id, name.to_string());
        }
    }
    map
}

/// Collect (`binary_target_name`, `owning_package_id`) for every
/// workspace binary whose target name does NOT start with `testing_`
/// AND whose owning package is not marked `dev_only` via
/// `[package.metadata.fuz_audit] dev_only = true`.
///
/// "Workspace" is `members`, the `workspace_members` ids — what
/// `cargo build --workspace` builds binaries for. A path dependency outside
/// the workspace also carries `source: null`, but its binaries are never
/// built here, so it is not scanned as a root (its library is still in the
/// closure of every member that reaches it).
fn collect_production_binaries(
    packages: &[Value],
    members: &HashSet<&str>,
) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for p in packages {
        let Some(pkg_id) = p.get("id").and_then(Value::as_str) else {
            continue;
        };
        if !members.contains(pkg_id) {
            continue;
        }
        if is_dev_only_package(p) {
            continue;
        }
        let pkg_id = pkg_id.to_string();
        let Some(targets) = p.get("targets").and_then(Value::as_array) else {
            continue;
        };
        for t in targets {
            if !target_is_bin(t) {
                continue;
            }
            let Some(name) = t.get("name").and_then(Value::as_str) else {
                continue;
            };
            if name.starts_with("testing_") {
                continue;
            }
            out.push((name.to_string(), pkg_id.clone()));
        }
    }
    out
}

fn target_is_bin(target: &Value) -> bool {
    target
        .get("kind")
        .and_then(Value::as_array)
        .is_some_and(|kinds| kinds.iter().any(|k| k.as_str() == Some("bin")))
}

/// Reads `[package.metadata.fuz_audit] dev_only = true`.
///
/// A present-but-malformed table (unknown key, or `dev_only` of the wrong
/// type) is **not** silently treated as "not dev-only" — it warns loudly on
/// stderr. The opt-out is security-tooling config: a typo'd `dev_only` (e.g.
/// `dev-only`) that silently stayed unset would put the package back in the
/// production scan with no signal. The package stays out of the dev-only set
/// (fail-safe) regardless.
///
/// Validated by hand over `serde_json::Value` rather than a `derive`d struct
/// so this crate keeps its minimal `serde_json` + `thiserror` dep footprint
/// (it's a shared leaf — zap/forge/`fuz` all link it).
fn is_dev_only_package(package: &Value) -> bool {
    let Some(table) = package.get("metadata").and_then(|m| m.get("fuz_audit")) else {
        return false;
    };
    let name = package
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("<unknown>");
    let warn = |why: &str| {
        eprintln!(
            "warning: package `{name}` has a malformed [package.metadata.fuz_audit] table \
             ({why}); treating it as not dev-only, so it will be scanned. Fix the table — a \
             typo'd `dev_only` silently disables the opt-out."
        );
    };
    let Some(obj) = table.as_object() else {
        warn("expected a table");
        return false;
    };
    // The only recognized key is a boolean `dev_only`. An unknown key (a typo
    // like `dev-only`) or a wrong-typed value is malformed → fail-safe + loud.
    if let Some(bad) = obj.keys().find(|k| k.as_str() != "dev_only") {
        warn(&format!("unknown key `{bad}`"));
        return false;
    }
    match obj.get("dev_only") {
        None => false, // empty `{}` table — not dev-only, not malformed
        Some(Value::Bool(b)) => *b,
        Some(_) => {
            warn("`dev_only` must be a boolean");
            false
        }
    }
}

/// Which resolved edges a node map carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EdgeKinds {
    /// Normal (`[dependencies]`) edges only — what a binary links.
    Normal,
    /// Normal and build edges — everything a release build compiles.
    NormalAndBuild,
}

/// Build adjacency map: `package_id` → the dep `package_ids` over `kinds`.
fn build_node_map(
    metadata: &Value,
    kinds: EdgeKinds,
) -> Result<HashMap<String, Vec<String>>, AuditError> {
    let nodes = metadata
        .get("resolve")
        .and_then(|r| r.get("nodes"))
        .and_then(Value::as_array)
        .ok_or(AuditError::MetadataShape("resolve.nodes missing"))?;

    let mut map: HashMap<String, Vec<String>> = HashMap::new();
    for n in nodes {
        let Some(id) = n.get("id").and_then(Value::as_str) else {
            continue;
        };
        let mut deps = Vec::new();
        if let Some(deps_arr) = n.get("deps").and_then(Value::as_array) {
            for dep in deps_arr {
                let included = match kinds {
                    EdgeKinds::Normal => dep_includes_runtime(dep),
                    EdgeKinds::NormalAndBuild => dep_includes_release(dep),
                };
                if !included {
                    continue;
                }
                if let Some(pkg) = dep.get("pkg").and_then(Value::as_str) {
                    deps.push(pkg.to_string());
                }
            }
        }
        map.insert(id.to_string(), deps);
    }
    Ok(map)
}

/// `true` if a binary links the edge's target — i.e. it carries at least one
/// `dep_kind` whose `kind` field is null (the normal `[dependencies]` table).
/// `dev` / `build` edges don't contribute to the runtime closure and are
/// skipped.
fn dep_includes_runtime(dep: &Value) -> bool {
    dep_has_kind(dep, |kind| kind.is_none())
}

/// `true` if a release build compiles the edge's target: a normal or a build
/// `dep_kind`.
fn dep_includes_release(dep: &Value) -> bool {
    dep_has_kind(dep, |kind| matches!(kind, None | Some("build")))
}

/// `true` if any of the edge's `dep_kinds` passes `accept` (given the `kind`
/// string, `None` for null). An edge without `dep_kinds` counts as normal.
fn dep_has_kind(dep: &Value, accept: impl Fn(Option<&str>) -> bool) -> bool {
    let Some(kinds) = dep.get("dep_kinds").and_then(Value::as_array) else {
        return true;
    };
    if kinds.is_empty() {
        return true;
    }
    kinds
        .iter()
        .any(|k| accept(k.get("kind").and_then(Value::as_str)))
}

/// BFS from `start`, returning the shortest path to each `target` it
/// reaches. Path is a list of package ids ending in the target.
fn bfs_find_paths(
    nodes: &HashMap<String, Vec<String>>,
    start: &str,
    targets: &HashSet<&str>,
) -> HashMap<String, Vec<String>> {
    let mut found: HashMap<String, Vec<String>> = HashMap::new();

    // Edge case: start is itself a target.
    if targets.contains(start) {
        found.insert(start.to_string(), vec![start.to_string()]);
    }

    let mut parent: HashMap<String, String> = HashMap::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut queue: VecDeque<String> = VecDeque::new();
    queue.push_back(start.to_string());
    seen.insert(start.to_string());

    while let Some(cur) = queue.pop_front() {
        let Some(neighbors) = nodes.get(&cur) else {
            continue;
        };
        for n in neighbors {
            if !seen.insert(n.clone()) {
                continue;
            }
            parent.insert(n.clone(), cur.clone());
            if targets.contains(n.as_str()) && !found.contains_key(n) {
                let mut chain = vec![n.clone()];
                let mut p = n.clone();
                while let Some(parent_id) = parent.get(&p) {
                    chain.push(parent_id.clone());
                    p = parent_id.clone();
                }
                chain.reverse();
                found.insert(n.clone(), chain);
            }
            queue.push_back(n.clone());
        }
    }

    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bfs_finds_direct_edge() {
        let mut g: HashMap<String, Vec<String>> = HashMap::new();
        g.insert("a".into(), vec!["b".into()]);
        g.insert("b".into(), vec![]);
        let targets: HashSet<&str> = std::iter::once("b").collect();
        let paths = bfs_find_paths(&g, "a", &targets);
        assert_eq!(paths.get("b").unwrap(), &vec!["a".to_string(), "b".into()]);
    }

    #[test]
    fn bfs_finds_transitive_edge() {
        let mut g: HashMap<String, Vec<String>> = HashMap::new();
        g.insert("a".into(), vec!["b".into()]);
        g.insert("b".into(), vec!["c".into()]);
        g.insert("c".into(), vec![]);
        let targets: HashSet<&str> = std::iter::once("c").collect();
        let paths = bfs_find_paths(&g, "a", &targets);
        assert_eq!(
            paths.get("c").unwrap(),
            &vec!["a".to_string(), "b".into(), "c".into()],
        );
    }

    #[test]
    fn bfs_handles_cycles() {
        let mut g: HashMap<String, Vec<String>> = HashMap::new();
        g.insert("a".into(), vec!["b".into()]);
        g.insert("b".into(), vec!["a".into(), "c".into()]);
        g.insert("c".into(), vec![]);
        let targets: HashSet<&str> = std::iter::once("c").collect();
        let paths = bfs_find_paths(&g, "a", &targets);
        assert_eq!(
            paths.get("c").unwrap(),
            &vec!["a".to_string(), "b".into(), "c".into()],
        );
    }

    #[test]
    fn bfs_returns_empty_when_unreachable() {
        let mut g: HashMap<String, Vec<String>> = HashMap::new();
        g.insert("a".into(), vec!["b".into()]);
        g.insert("b".into(), vec![]);
        g.insert("c".into(), vec![]);
        let targets: HashSet<&str> = std::iter::once("c").collect();
        let paths = bfs_find_paths(&g, "a", &targets);
        assert!(paths.is_empty());
    }

    #[test]
    fn bfs_finds_multiple_targets_in_one_walk() {
        let mut g: HashMap<String, Vec<String>> = HashMap::new();
        g.insert("a".into(), vec!["b".into(), "d".into()]);
        g.insert("b".into(), vec!["c".into()]);
        g.insert("c".into(), vec![]);
        g.insert("d".into(), vec![]);
        let targets: HashSet<&str> = ["c", "d"].into_iter().collect();
        let paths = bfs_find_paths(&g, "a", &targets);
        assert!(paths.contains_key("c"));
        assert!(paths.contains_key("d"));
    }

    #[test]
    fn dep_includes_runtime_treats_missing_dep_kinds_as_runtime() {
        let dep = serde_json::json!({"pkg": "x"});
        assert!(dep_includes_runtime(&dep));
    }

    #[test]
    fn dep_includes_runtime_accepts_normal_kind() {
        let dep = serde_json::json!({"pkg": "x", "dep_kinds": [{"kind": null}]});
        assert!(dep_includes_runtime(&dep));
    }

    #[test]
    fn dep_includes_runtime_rejects_dev_only() {
        let dep = serde_json::json!({"pkg": "x", "dep_kinds": [{"kind": "dev"}]});
        assert!(!dep_includes_runtime(&dep));
    }

    #[test]
    fn dep_includes_runtime_accepts_mixed_kinds() {
        let dep = serde_json::json!({
            "pkg": "x",
            "dep_kinds": [{"kind": "dev"}, {"kind": null}]
        });
        assert!(dep_includes_runtime(&dep));
    }

    #[test]
    fn is_dev_only_reads_metadata_flag() {
        let pkg = serde_json::json!({
            "name": "xtask",
            "metadata": {"fuz_audit": {"dev_only": true}}
        });
        assert!(is_dev_only_package(&pkg));
    }

    #[test]
    fn is_dev_only_defaults_false_when_metadata_absent() {
        let pkg = serde_json::json!({"name": "fuz"});
        assert!(!is_dev_only_package(&pkg));
    }

    #[test]
    fn is_dev_only_empty_table_is_false() {
        let pkg = serde_json::json!({
            "name": "fuz",
            "metadata": {"fuz_audit": {}}
        });
        assert!(!is_dev_only_package(&pkg));
    }

    #[test]
    fn is_dev_only_unknown_key_warns_and_stays_false() {
        // deny_unknown_fields: a typo'd key (`dev-only`) is malformed → fail-safe
        // (the package stays in the production scan) and warns on stderr.
        let pkg = serde_json::json!({
            "name": "fuz",
            "metadata": {"fuz_audit": {"dev-only": true}}
        });
        assert!(!is_dev_only_package(&pkg));
    }

    #[test]
    fn is_dev_only_wrong_type_warns_and_stays_false() {
        // `dev_only` as a string is malformed → fail-safe + warn, not a silent true.
        let pkg = serde_json::json!({
            "name": "fuz",
            "metadata": {"fuz_audit": {"dev_only": "true"}}
        });
        assert!(!is_dev_only_package(&pkg));
    }

    #[test]
    fn audit_passes_when_no_forbidden_in_workspace() {
        let metadata = serde_json::json!({
            "workspace_members": ["fuz#0.1.0"],
            "packages": [
                {
                    "name": "fuz",
                    "id": "fuz#0.1.0",
                    "source": null,
                    "targets": [{"name": "fuz", "kind": ["bin"]}],
                },
            ],
            "resolve": {
                "nodes": [
                    {"id": "fuz#0.1.0", "deps": []},
                ],
            },
        });
        let report = audit_metadata(&metadata, &["fuz_testing"]).unwrap();
        assert!(report.is_clean());
        assert_eq!(report.absent_forbidden, vec!["fuz_testing".to_string()]);
        assert_eq!(report.scanned, vec![("fuz".into(), "fuz".into())]);
    }

    #[test]
    fn audit_flags_production_binary_with_forbidden_transitive_dep() {
        let metadata = serde_json::json!({
            "workspace_members": ["fuz#0.1.0", "leaky_lib#0.1.0", "fuz_testing#0.1.0"],
            "packages": [
                {
                    "name": "fuz",
                    "id": "fuz#0.1.0",
                    "source": null,
                    "targets": [{"name": "fuz", "kind": ["bin"]}],
                },
                {
                    "name": "leaky_lib",
                    "id": "leaky_lib#0.1.0",
                    "source": null,
                    "targets": [{"name": "leaky_lib", "kind": ["lib"]}],
                },
                {
                    "name": "fuz_testing",
                    "id": "fuz_testing#0.1.0",
                    "source": null,
                    "targets": [{"name": "fuz_testing", "kind": ["lib"]}],
                },
            ],
            "resolve": {
                "nodes": [
                    {"id": "fuz#0.1.0", "deps": [{"pkg": "leaky_lib#0.1.0", "dep_kinds": [{"kind": null}]}]},
                    {"id": "leaky_lib#0.1.0", "deps": [{"pkg": "fuz_testing#0.1.0", "dep_kinds": [{"kind": null}]}]},
                    {"id": "fuz_testing#0.1.0", "deps": []},
                ],
            },
        });
        let report = audit_metadata(&metadata, &["fuz_testing"]).unwrap();
        assert!(!report.is_clean());
        assert_eq!(report.violations.len(), 1);
        let v = &report.violations[0];
        assert_eq!(v.binary, "fuz");
        assert_eq!(v.forbidden, "fuz_testing");
        assert_eq!(v.chain, vec!["fuz", "leaky_lib", "fuz_testing"]);
    }

    #[test]
    fn audit_skips_dev_only_packages() {
        let metadata = serde_json::json!({
            "workspace_members": ["xtask#0.1.0", "fuz_audit#0.1.0"],
            "packages": [
                {
                    "name": "xtask",
                    "id": "xtask#0.1.0",
                    "source": null,
                    "targets": [{"name": "xtask", "kind": ["bin"]}],
                    "metadata": {"fuz_audit": {"dev_only": true}},
                },
                {
                    "name": "fuz_audit",
                    "id": "fuz_audit#0.1.0",
                    "source": null,
                    "targets": [{"name": "fuz_audit", "kind": ["lib"]}],
                },
            ],
            "resolve": {
                "nodes": [
                    {"id": "xtask#0.1.0", "deps": [{"pkg": "fuz_audit#0.1.0", "dep_kinds": [{"kind": null}]}]},
                    {"id": "fuz_audit#0.1.0", "deps": []},
                ],
            },
        });
        let report = audit_metadata(&metadata, &["fuz_audit"]).unwrap();
        assert!(report.is_clean());
        // xtask was dev-only → skipped entirely from production scan.
        assert!(report.scanned.is_empty());
    }

    #[test]
    fn audit_skips_testing_prefixed_binaries() {
        let metadata = serde_json::json!({
            "workspace_members": ["testing_fuz_forge_server#0.1.0", "fuz_testing#0.1.0"],
            "packages": [
                {
                    "name": "testing_fuz_forge_server",
                    "id": "testing_fuz_forge_server#0.1.0",
                    "source": null,
                    "targets": [{"name": "testing_fuz_forge_server", "kind": ["bin"]}],
                },
                {
                    "name": "fuz_testing",
                    "id": "fuz_testing#0.1.0",
                    "source": null,
                    "targets": [{"name": "fuz_testing", "kind": ["lib"]}],
                },
            ],
            "resolve": {
                "nodes": [
                    {"id": "testing_fuz_forge_server#0.1.0", "deps": [{"pkg": "fuz_testing#0.1.0", "dep_kinds": [{"kind": null}]}]},
                    {"id": "fuz_testing#0.1.0", "deps": []},
                ],
            },
        });
        let report = audit_metadata(&metadata, &["fuz_testing"]).unwrap();
        assert!(report.is_clean());
        assert!(report.scanned.is_empty());
    }

    #[test]
    fn audit_scans_workspace_member_binaries_not_every_path_crate() {
        // `vendored_tool` is a path crate (`source: null`) outside the
        // workspace: `cargo build --workspace` never builds its binary, so it is
        // no production root, although it reaches the forbidden crate. A
        // member binary with the same edge is flagged.
        let metadata = serde_json::json!({
            "workspace_members": ["fuz#0.1.0", "fuz_testing#0.1.0"],
            "packages": [
                {"name": "fuz", "id": "fuz#0.1.0", "source": null,
                 "targets": [{"name": "fuz", "kind": ["bin"]}]},
                {"name": "vendored_tool", "id": "vendored_tool#0.1.0", "source": null,
                 "targets": [{"name": "vendored_tool", "kind": ["bin"]}]},
                {"name": "fuz_testing", "id": "fuz_testing#0.1.0", "source": null,
                 "targets": [{"name": "fuz_testing", "kind": ["lib"]}]},
            ],
            "resolve": {"nodes": [
                {"id": "fuz#0.1.0", "deps": [{"pkg": "fuz_testing#0.1.0", "dep_kinds": [{"kind": null}]}]},
                {"id": "vendored_tool#0.1.0", "deps": [{"pkg": "fuz_testing#0.1.0", "dep_kinds": [{"kind": null}]}]},
                {"id": "fuz_testing#0.1.0", "deps": []},
            ]},
        });
        let report = audit_metadata(&metadata, &["fuz_testing"]).unwrap();
        assert_eq!(report.scanned, vec![("fuz".into(), "fuz".into())]);
        assert_eq!(report.violations.len(), 1);
        assert_eq!(report.violations[0].binary, "fuz");
    }

    #[test]
    fn audit_refuses_metadata_without_workspace_members() {
        // the production roots are the members, so metadata without the list
        // cannot be audited — refused rather than read as an empty workspace
        let mut metadata = fuz_and_fuzi_sharing_core();
        metadata
            .as_object_mut()
            .unwrap()
            .remove("workspace_members");
        assert!(matches!(
            audit_metadata(&metadata, &["fuzi_core"]),
            Err(AuditError::MetadataShape(_))
        ));
    }

    #[test]
    fn audit_reports_multiple_forbidden_for_same_binary() {
        let metadata = serde_json::json!({
            "workspace_members": ["fuz#0.1.0", "fuz_testing#0.1.0", "fuz_audit#0.1.0"],
            "packages": [
                {
                    "name": "fuz",
                    "id": "fuz#0.1.0",
                    "source": null,
                    "targets": [{"name": "fuz", "kind": ["bin"]}],
                },
                {
                    "name": "fuz_testing",
                    "id": "fuz_testing#0.1.0",
                    "source": null,
                    "targets": [{"name": "fuz_testing", "kind": ["lib"]}],
                },
                {
                    "name": "fuz_audit",
                    "id": "fuz_audit#0.1.0",
                    "source": null,
                    "targets": [{"name": "fuz_audit", "kind": ["lib"]}],
                },
            ],
            "resolve": {
                "nodes": [
                    {"id": "fuz#0.1.0", "deps": [
                        {"pkg": "fuz_testing#0.1.0", "dep_kinds": [{"kind": null}]},
                        {"pkg": "fuz_audit#0.1.0", "dep_kinds": [{"kind": null}]},
                    ]},
                    {"id": "fuz_testing#0.1.0", "deps": []},
                    {"id": "fuz_audit#0.1.0", "deps": []},
                ],
            },
        });
        let report = audit_metadata(&metadata, &["fuz_testing", "fuz_audit"]).unwrap();
        assert!(!report.is_clean());
        assert_eq!(report.violations.len(), 2);
        let forbidden_set: HashSet<&str> = report
            .violations
            .iter()
            .map(|v| v.forbidden.as_str())
            .collect();
        assert!(forbidden_set.contains("fuz_testing"));
        assert!(forbidden_set.contains("fuz_audit"));
    }

    #[test]
    fn audit_excludes_dev_kind_edges() {
        let metadata = serde_json::json!({
            "workspace_members": ["fuz#0.1.0", "fuz_testing#0.1.0"],
            "packages": [
                {
                    "name": "fuz",
                    "id": "fuz#0.1.0",
                    "source": null,
                    "targets": [{"name": "fuz", "kind": ["bin"]}],
                },
                {
                    "name": "fuz_testing",
                    "id": "fuz_testing#0.1.0",
                    "source": null,
                    "targets": [{"name": "fuz_testing", "kind": ["lib"]}],
                },
            ],
            "resolve": {
                "nodes": [
                    {"id": "fuz#0.1.0", "deps": [
                        {"pkg": "fuz_testing#0.1.0", "dep_kinds": [{"kind": "dev"}]},
                    ]},
                    {"id": "fuz_testing#0.1.0", "deps": []},
                ],
            },
        });
        // Dev-only dep edges don't contribute to runtime closure, so
        // the audit passes even though fuz lists fuz_testing as a
        // [dev-dependencies] entry.
        let report = audit_metadata(&metadata, &["fuz_testing"]).unwrap();
        assert!(report.is_clean());
    }

    /// Graph where `fuz` and `fuzi` both depend on `fuzi_core`. A per-binary
    /// rule forbidding `fuzi_core` for `fuz` must flag `fuz` but NOT `fuzi`,
    /// which legitimately depends on it (the core ⊥ fuzi_* invariant).
    fn fuz_and_fuzi_sharing_core() -> Value {
        serde_json::json!({
            "workspace_members": ["fuz#0.1.0", "fuzi#0.1.0", "fuzi_core#0.1.0"],
            "packages": [
                {"name": "fuz", "id": "fuz#0.1.0", "source": null,
                 "targets": [{"name": "fuz", "kind": ["bin"]}]},
                {"name": "fuzi", "id": "fuzi#0.1.0", "source": null,
                 "targets": [{"name": "fuzi", "kind": ["bin"]}]},
                {"name": "fuzi_core", "id": "fuzi_core#0.1.0", "source": null,
                 "targets": [{"name": "fuzi_core", "kind": ["lib"]}]},
            ],
            "resolve": {"nodes": [
                {"id": "fuz#0.1.0", "deps": [{"pkg": "fuzi_core#0.1.0", "dep_kinds": [{"kind": null}]}]},
                {"id": "fuzi#0.1.0", "deps": [{"pkg": "fuzi_core#0.1.0", "dep_kinds": [{"kind": null}]}]},
                {"id": "fuzi_core#0.1.0", "deps": []},
            ]},
        })
    }

    #[test]
    fn per_binary_forbid_flags_only_the_named_binary() {
        let metadata = fuz_and_fuzi_sharing_core();
        let rules = &[PerBinaryForbid {
            binary: "fuz",
            crates: &["fuzi_core"],
        }];
        let report = audit_metadata_with_rules(&metadata, &[], rules, &[]).unwrap();
        assert!(!report.is_clean());
        assert_eq!(report.violations.len(), 1);
        assert_eq!(report.violations[0].binary, "fuz");
        assert_eq!(report.violations[0].forbidden, "fuzi_core");
    }

    #[test]
    fn per_binary_forbid_does_not_leak_to_sibling_binaries() {
        // The rule targets `fuz`; `fuzi` depends on `fuzi_core` but is not named,
        // so it stays clean even though it reaches the same crate.
        let metadata = fuz_and_fuzi_sharing_core();
        let rules = &[PerBinaryForbid {
            binary: "fuz",
            crates: &["fuzi_core"],
        }];
        let report = audit_metadata_with_rules(&metadata, &[], rules, &[]).unwrap();
        let fuzi_flagged = report.violations.iter().any(|v| v.binary == "fuzi");
        assert!(!fuzi_flagged);
    }

    /// Graph where the library `fuz_fact` depends on `fuz_http` (forbidden by
    /// the layering rule) and on `fuz_db` (allowed); a sibling lib `other` also
    /// reaches `fuz_http` but is not a layering subject.
    fn fact_reaching_http() -> Value {
        serde_json::json!({
            "workspace_members": ["fuz_fact#0.1.0", "fuz_http#0.1.0", "fuz_db#0.1.0",
                "other#0.1.0"],
            "packages": [
                {"name": "fuz_fact", "id": "fuz_fact#0.1.0", "source": null,
                 "targets": [{"name": "fuz_fact", "kind": ["lib"]}]},
                {"name": "fuz_http", "id": "fuz_http#0.1.0", "source": null,
                 "targets": [{"name": "fuz_http", "kind": ["lib"]}]},
                {"name": "fuz_db", "id": "fuz_db#0.1.0", "source": null,
                 "targets": [{"name": "fuz_db", "kind": ["lib"]}]},
                {"name": "other", "id": "other#0.1.0", "source": null,
                 "targets": [{"name": "other", "kind": ["lib"]}]},
            ],
            "resolve": {"nodes": [
                {"id": "fuz_fact#0.1.0", "deps": [
                    {"pkg": "fuz_http#0.1.0", "dep_kinds": [{"kind": null}]},
                    {"pkg": "fuz_db#0.1.0", "dep_kinds": [{"kind": null}]}
                ]},
                {"id": "fuz_http#0.1.0", "deps": []},
                {"id": "fuz_db#0.1.0", "deps": []},
                {"id": "other#0.1.0", "deps": [
                    {"pkg": "fuz_http#0.1.0", "dep_kinds": [{"kind": null}]}
                ]},
            ]},
        })
    }

    #[test]
    fn layering_flags_subject_reaching_forbidden_dep() {
        let metadata = fact_reaching_http();
        let layering = &[CrateLayering {
            crate_name: "fuz_fact",
            forbidden_deps: &["fuz_http", "fuz_cell"],
        }];
        let report = audit_metadata_with_rules(&metadata, &[], &[], layering).unwrap();
        assert!(!report.is_clean());
        assert_eq!(report.layering_violations.len(), 1);
        assert_eq!(report.layering_violations[0].crate_name, "fuz_fact");
        assert_eq!(report.layering_violations[0].forbidden, "fuz_http");
        // The sibling `other` reaches fuz_http too, but isn't a layering subject.
        assert!(
            report
                .layering_violations
                .iter()
                .all(|v| v.crate_name == "fuz_fact")
        );
    }

    #[test]
    fn layering_clean_when_subject_avoids_forbidden_deps() {
        let metadata = fact_reaching_http();
        // Forbid only fuz_cell, which is not in fuz_fact's graph → clean.
        let layering = &[CrateLayering {
            crate_name: "fuz_fact",
            forbidden_deps: &["fuz_cell"],
        }];
        let report = audit_metadata_with_rules(&metadata, &[], &[], layering).unwrap();
        assert!(report.is_clean());
    }

    #[test]
    fn layering_skips_absent_subject() {
        // No `fuz_fact` in this workspace → the rule simply doesn't apply.
        let metadata = fuz_and_fuzi_sharing_core();
        let layering = &[CrateLayering {
            crate_name: "fuz_fact",
            forbidden_deps: &["fuz_http"],
        }];
        let report = audit_metadata_with_rules(&metadata, &[], &[], layering).unwrap();
        assert!(report.is_clean());
    }

    #[test]
    fn builtin_layering_constrains_fuz_fact() {
        // The shipped rule names fuz_fact and forbids the HTTP/cell/authz layers.
        let rule = BUILTIN_CRATE_LAYERING
            .iter()
            .find(|r| r.crate_name == "fuz_fact")
            .expect("fuz_fact layering rule is built in");
        for forbidden in ["axum", "fuz_http", "fuz_cell", "fuz_auth", "fuz_actions"] {
            assert!(rule.forbidden_deps.contains(&forbidden));
        }
    }

    #[test]
    fn builtin_layering_constrains_fuz_cell_to_no_actions() {
        // The cell storage/serving split: fuz_cell (storage/authz) must not
        // reach fuz_actions (the verb layer fuz_cell_actions owns).
        let rule = BUILTIN_CRATE_LAYERING
            .iter()
            .find(|r| r.crate_name == "fuz_cell")
            .expect("fuz_cell layering rule is built in");
        assert!(rule.forbidden_deps.contains(&"fuz_actions"));
        // Deliberately narrower than fuz_fact's rule: fuz_cell legitimately
        // reaches axum/fuz_http transitively via fuz_auth (its authz predicates
        // need the auth types), so those are NOT forbidden here.
        assert!(!rule.forbidden_deps.contains(&"axum"));
        assert!(!rule.forbidden_deps.contains(&"fuz_http"));
        assert!(!rule.forbidden_deps.contains(&"fuz_auth"));
    }

    #[test]
    fn layering_checked_lists_present_subjects() {
        // The subject (`fuz_fact`) is present and reaches none of the forbidden
        // deps → no violation, but it IS recorded as checked.
        let metadata = fact_reaching_http();
        let layering = &[CrateLayering {
            crate_name: "fuz_fact",
            forbidden_deps: &["fuz_cell"], // absent from fuz_fact's graph → clean
        }];
        let report = audit_metadata_with_rules(&metadata, &[], &[], layering).unwrap();
        assert!(report.is_clean());
        assert_eq!(report.layering_checked, vec!["fuz_fact".to_string()]);
    }

    #[test]
    fn find_package_ids_resolves_all_matches_for_duplicate_name() {
        // Two packages share the name `dup` (e.g. two semver-majors, or a
        // workspace crate colliding with a crates.io crate). Both ids must
        // resolve — registering only the first would let a binary reaching the
        // second slip past the audit unflagged.
        let packages = vec![
            serde_json::json!({"name": "dup", "id": "dup#1.0.0"}),
            serde_json::json!({"name": "other", "id": "other#0.1.0"}),
            serde_json::json!({"name": "dup", "id": "dup#2.0.0"}),
        ];
        let ids = find_package_ids(&packages, "dup");
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&"dup#1.0.0"));
        assert!(ids.contains(&"dup#2.0.0"));

        // A unique name still resolves to exactly its one id (the live case).
        assert_eq!(find_package_ids(&packages, "other"), vec!["other#0.1.0"]);
        // An absent name resolves to nothing → caller treats it as "absent".
        assert!(find_package_ids(&packages, "missing").is_empty());
    }

    #[test]
    fn audit_flags_forbidden_via_second_id_of_duplicate_name() {
        // `fuz_testing` resolves to two ids; a production binary reaches the
        // SECOND one. The first-match resolver would miss it — the all-matches
        // resolver flags it.
        let metadata = serde_json::json!({
            "workspace_members": ["fuz#0.1.0", "fuz_testing#1.0.0", "fuz_testing#2.0.0"],
            "packages": [
                {"name": "fuz", "id": "fuz#0.1.0", "source": null,
                 "targets": [{"name": "fuz", "kind": ["bin"]}]},
                {"name": "fuz_testing", "id": "fuz_testing#1.0.0", "source": null,
                 "targets": [{"name": "fuz_testing", "kind": ["lib"]}]},
                {"name": "fuz_testing", "id": "fuz_testing#2.0.0", "source": null,
                 "targets": [{"name": "fuz_testing", "kind": ["lib"]}]},
            ],
            "resolve": {"nodes": [
                // fuz reaches only the SECOND id (`#2.0.0`).
                {"id": "fuz#0.1.0", "deps": [{"pkg": "fuz_testing#2.0.0", "dep_kinds": [{"kind": null}]}]},
                {"id": "fuz_testing#1.0.0", "deps": []},
                {"id": "fuz_testing#2.0.0", "deps": []},
            ]},
        });
        let report = audit_metadata(&metadata, &["fuz_testing"]).unwrap();
        assert!(!report.is_clean());
        assert_eq!(report.violations.len(), 1);
        assert_eq!(report.violations[0].binary, "fuz");
        assert_eq!(report.violations[0].forbidden, "fuz_testing");
        assert_eq!(report.violations[0].chain, vec!["fuz", "fuz_testing"]);
    }

    #[test]
    fn layering_flags_forbidden_via_second_id_of_duplicate_name() {
        // The forbidden dep `fuz_http` resolves to two ids; the subject reaches
        // only the second. All-matches target resolution catches it.
        let metadata = serde_json::json!({
            "workspace_members": ["fuz_fact#0.1.0", "fuz_http#1.0.0", "fuz_http#2.0.0"],
            "packages": [
                {"name": "fuz_fact", "id": "fuz_fact#0.1.0", "source": null,
                 "targets": [{"name": "fuz_fact", "kind": ["lib"]}]},
                {"name": "fuz_http", "id": "fuz_http#1.0.0", "source": null,
                 "targets": [{"name": "fuz_http", "kind": ["lib"]}]},
                {"name": "fuz_http", "id": "fuz_http#2.0.0", "source": null,
                 "targets": [{"name": "fuz_http", "kind": ["lib"]}]},
            ],
            "resolve": {"nodes": [
                {"id": "fuz_fact#0.1.0", "deps": [{"pkg": "fuz_http#2.0.0", "dep_kinds": [{"kind": null}]}]},
                {"id": "fuz_http#1.0.0", "deps": []},
                {"id": "fuz_http#2.0.0", "deps": []},
            ]},
        });
        let layering = &[CrateLayering {
            crate_name: "fuz_fact",
            forbidden_deps: &["fuz_http"],
        }];
        let report = audit_metadata_with_rules(&metadata, &[], &[], layering).unwrap();
        assert!(!report.is_clean());
        assert_eq!(report.layering_violations.len(), 1);
        assert_eq!(report.layering_violations[0].crate_name, "fuz_fact");
        assert_eq!(report.layering_violations[0].forbidden, "fuz_http");
    }

    #[test]
    fn layering_checked_omits_absent_subjects() {
        // No `fuz_fact` package here → the rule is skipped and not recorded.
        let metadata = fuz_and_fuzi_sharing_core();
        let layering = &[CrateLayering {
            crate_name: "fuz_fact",
            forbidden_deps: &["fuz_http"],
        }];
        let report = audit_metadata_with_rules(&metadata, &[], &[], layering).unwrap();
        assert!(report.layering_checked.is_empty());
    }

    /// A workspace: production binary `fuz` reaches `fuz_http` through
    /// `server_lib`; `testing_stub` (a `testing_` binary no production binary
    /// reaches) and `xtask` depend on it too; `vendored`, outside the
    /// workspace, is reached only by a dev edge. `fuz_http`'s `everything`
    /// feature implies `test_router_access`. Each package's `fuz_http` edge is
    /// passed in, so a test sets the one it is about.
    fn workspace_with_router_edges(edges: &[(&str, Value)], own_features: &Value) -> Value {
        let dep = |pkg: &str| -> Value {
            edges.iter().find(|(p, _)| *p == pkg).map_or_else(
                || {
                    serde_json::json!([{"name": "fuz_http", "kind": null, "features": [],
                        "uses_default_features": true}])
                },
                |(_, e)| e.clone(),
            )
        };
        serde_json::json!({
            "workspace_members": ["fuz#0.1.0", "server_lib#0.1.0", "testing_stub#0.1.0",
                "xtask#0.1.0", "fuz_http#0.1.0"],
            "packages": [
                {"name": "fuz", "id": "fuz#0.1.0", "source": null,
                 "targets": [{"name": "fuz", "kind": ["bin"]}],
                 "dependencies": [{"name": "server_lib", "kind": null, "features": []}]},
                {"name": "server_lib", "id": "server_lib#0.1.0", "source": null,
                 "targets": [{"name": "server_lib", "kind": ["lib"]}],
                 "dependencies": dep("server_lib"), "features": own_features.clone()},
                {"name": "testing_stub", "id": "testing_stub#0.1.0", "source": null,
                 "targets": [{"name": "testing_stub", "kind": ["bin"]}],
                 "dependencies": dep("testing_stub")},
                {"name": "xtask", "id": "xtask#0.1.0", "source": null,
                 "metadata": {"fuz_audit": {"dev_only": true}},
                 "targets": [{"name": "xtask", "kind": ["bin"]}],
                 "dependencies": dep("xtask")},
                {"name": "vendored", "id": "vendored#0.1.0", "source": "registry+x",
                 "targets": [{"name": "vendored", "kind": ["lib"]}],
                 "dependencies": dep("vendored")},
                {"name": "fuz_http", "id": "fuz_http#0.1.0", "source": null,
                 "targets": [{"name": "fuz_http", "kind": ["lib"]}],
                 "features": {"test_router_access": [], "everything": ["test_router_access"]}},
            ],
            "resolve": {"nodes": [
                {"id": "fuz#0.1.0", "deps": [
                    {"pkg": "server_lib#0.1.0", "dep_kinds": [{"kind": null}]},
                    {"pkg": "vendored#0.1.0", "dep_kinds": [{"kind": "dev"}]}
                ]},
                {"id": "server_lib#0.1.0", "deps": [
                    {"pkg": "fuz_http#0.1.0", "dep_kinds": [{"kind": null}]}
                ]},
                {"id": "testing_stub#0.1.0", "deps": [
                    {"pkg": "fuz_http#0.1.0", "dep_kinds": [{"kind": null}]}
                ]},
                {"id": "xtask#0.1.0", "deps": [
                    {"pkg": "fuz_http#0.1.0", "dep_kinds": [{"kind": null}]}
                ]},
                {"id": "vendored#0.1.0", "deps": [
                    {"pkg": "fuz_http#0.1.0", "dep_kinds": [{"kind": null}]}
                ]},
                {"id": "fuz_http#0.1.0", "deps": []},
            ]},
        })
    }

    fn router_edge(kind: Option<&str>, features: &[&str], uses_default: bool) -> Value {
        serde_json::json!([{"name": "fuz_http", "kind": kind, "features": features,
            "uses_default_features": uses_default}])
    }

    fn audit_test_features(metadata: &Value) -> AuditReport {
        audit_metadata_with_rules(metadata, &[], &[], &[]).unwrap()
    }

    fn flagged_packages(report: &AuditReport) -> Vec<&str> {
        report
            .test_feature_violations
            .iter()
            .map(|v| v.package.as_str())
            .collect()
    }

    #[test]
    fn test_only_feature_clean_on_dev_edges_and_plain_normal_edges() {
        // every package depends on fuz_http normally without the feature, and
        // a dev edge enables it on each — the legitimate use
        let mut deps = Vec::new();
        for pkg in ["server_lib", "testing_stub", "xtask", "vendored"] {
            deps.push((
                pkg,
                serde_json::json!([
                    {"name": "fuz_http", "kind": null, "features": [], "uses_default_features": true},
                    {"name": "fuz_http", "kind": "dev", "features": ["test_router_access"],
                     "uses_default_features": true}
                ]),
            ));
        }
        let report =
            audit_test_features(&workspace_with_router_edges(&deps, &serde_json::json!({})));
        assert!(report.is_clean(), "{:?}", report.test_feature_violations);
        assert_eq!(
            report.test_features_checked,
            vec!["fuz_http/test_router_access".to_string()]
        );
    }

    #[test]
    fn test_only_feature_on_a_normal_edge_from_a_production_dep_is_flagged() {
        let metadata = workspace_with_router_edges(
            &[(
                "server_lib",
                router_edge(None, &["test_router_access"], true),
            )],
            &serde_json::json!({}),
        );
        let report = audit_test_features(&metadata);
        assert!(!report.is_clean());
        assert_eq!(flagged_packages(&report), vec!["server_lib"]);
        let v = &report.test_feature_violations[0];
        assert_eq!(v.crate_name, "fuz_http");
        assert_eq!(v.feature, "test_router_access");
        assert_eq!(report.exit_code(), 65);
    }

    #[test]
    fn test_only_feature_on_a_testing_or_dev_only_member_is_flagged() {
        // no production binary reaches either, but `cargo build --workspace
        // --release` builds both, and resolver 2 unifies the feature into the
        // production binaries of that build
        for pkg in ["testing_stub", "xtask"] {
            let metadata = workspace_with_router_edges(
                &[(pkg, router_edge(None, &["test_router_access"], true))],
                &serde_json::json!({}),
            );
            assert_eq!(flagged_packages(&audit_test_features(&metadata)), vec![pkg]);
        }
    }

    #[test]
    fn test_only_feature_outside_the_release_build_is_not_flagged() {
        // `vendored` is reached only by a dev edge, so no release build
        // compiles it
        let metadata = workspace_with_router_edges(
            &[("vendored", router_edge(None, &["test_router_access"], true))],
            &serde_json::json!({}),
        );
        assert!(audit_test_features(&metadata).is_clean());
    }

    #[test]
    fn test_only_feature_on_a_non_member_the_release_build_reaches_is_flagged() {
        // `vendored`, outside the workspace, flagged once a member reaches it
        // over a normal edge
        let mut metadata = workspace_with_router_edges(
            &[("vendored", router_edge(None, &["test_router_access"], true))],
            &serde_json::json!({}),
        );
        metadata["resolve"]["nodes"][0]["deps"][1]["dep_kinds"] =
            serde_json::json!([{"kind": null}]);
        assert_eq!(
            flagged_packages(&audit_test_features(&metadata)),
            vec!["vendored"]
        );
    }

    #[test]
    fn test_only_feature_build_edge_is_flagged() {
        let metadata = workspace_with_router_edges(
            &[(
                "server_lib",
                router_edge(Some("build"), &["test_router_access"], true),
            )],
            &serde_json::json!({}),
        );
        let report = audit_test_features(&metadata);
        assert_eq!(flagged_packages(&report), vec!["server_lib"]);
        assert!(
            report.test_feature_violations[0].via.contains("build"),
            "{:?}",
            report.test_feature_violations
        );
    }

    #[test]
    fn test_only_feature_on_a_package_reached_over_a_build_edge_is_flagged() {
        // `vendored`, outside the workspace, compiled for a member's build
        // script: in the release build
        let mut metadata = workspace_with_router_edges(
            &[("vendored", router_edge(None, &["test_router_access"], true))],
            &serde_json::json!({}),
        );
        metadata["resolve"]["nodes"][0]["deps"][1]["dep_kinds"] =
            serde_json::json!([{"kind": "build"}]);
        assert_eq!(
            flagged_packages(&audit_test_features(&metadata)),
            vec!["vendored"]
        );
    }

    #[test]
    fn test_only_feature_through_an_implying_feature_is_flagged() {
        let metadata = workspace_with_router_edges(
            &[("server_lib", router_edge(None, &["everything"], true))],
            &serde_json::json!({}),
        );
        let report = audit_test_features(&metadata);
        assert_eq!(flagged_packages(&report), vec!["server_lib"]);
        assert!(
            report.test_feature_violations[0]
                .via
                .contains("`everything`")
        );
    }

    /// Make `fuz_http` a path dependency outside the workspace (`source: null`
    /// still, as cargo reports a path crate), the way a consumer workspace
    /// reaches the spine.
    fn router_crate_outside_the_workspace(metadata: &mut Value) {
        metadata["workspace_members"]
            .as_array_mut()
            .unwrap()
            .retain(|id| id != "fuz_http#0.1.0");
    }

    #[test]
    fn test_only_feature_through_the_default_features_is_flagged() {
        let mut metadata = workspace_with_router_edges(&[], &serde_json::json!({}));
        router_crate_outside_the_workspace(&mut metadata);
        metadata["packages"][5]["features"]["default"] = serde_json::json!(["everything"]);
        let report = audit_test_features(&metadata);
        // every normal edge using default features, in the release build
        assert_eq!(
            flagged_packages(&report),
            vec!["server_lib", "testing_stub", "xtask"]
        );
        assert!(
            report.test_feature_violations[0]
                .via
                .contains("default features")
        );
        // an edge that turns the defaults off is clean
        let mut metadata = workspace_with_router_edges(
            &[
                ("server_lib", router_edge(None, &[], false)),
                ("testing_stub", router_edge(None, &[], false)),
                ("xtask", router_edge(None, &[], false)),
            ],
            &serde_json::json!({}),
        );
        router_crate_outside_the_workspace(&mut metadata);
        metadata["packages"][5]["features"]["default"] = serde_json::json!(["everything"]);
        assert!(audit_test_features(&metadata).is_clean());
    }

    #[test]
    fn test_only_feature_in_a_member_s_own_default_is_flagged_whatever_its_dependers_do() {
        // every depender turns the defaults off, but `cargo build --workspace`
        // selects the member itself, with its defaults
        let mut metadata = workspace_with_router_edges(
            &[
                ("server_lib", router_edge(None, &[], false)),
                ("testing_stub", router_edge(None, &[], false)),
                ("xtask", router_edge(None, &[], false)),
            ],
            &serde_json::json!({}),
        );
        metadata["packages"][5]["features"]["default"] = serde_json::json!(["everything"]);
        let report = audit_test_features(&metadata);
        assert_eq!(flagged_packages(&report), vec!["fuz_http"]);
        assert!(
            report.test_feature_violations[0]
                .via
                .contains("workspace member"),
            "{:?}",
            report.test_feature_violations
        );
        assert_eq!(report.exit_code(), 65);
        // no dependers at all — still flagged
        let mut metadata = workspace_with_router_edges(&[], &serde_json::json!({}));
        for p in metadata["packages"].as_array_mut().unwrap() {
            if p["name"] != "fuz_http" {
                p["dependencies"] = serde_json::json!([]);
            }
        }
        metadata["packages"][5]["features"]["default"] = serde_json::json!(["test_router_access"]);
        assert_eq!(
            flagged_packages(&audit_test_features(&metadata)),
            vec!["fuz_http"]
        );
    }

    #[test]
    fn test_only_feature_closure_roots_are_the_workspace_members_not_every_path_crate() {
        // `vendored` is a path crate (`source: null`) outside the workspace,
        // reached only over a dev edge: no release build compiles it, so its
        // normal edge enabling the feature is clean — `source: null` alone
        // would have rooted the closure at it
        let mut metadata = workspace_with_router_edges(
            &[("vendored", router_edge(None, &["test_router_access"], true))],
            &serde_json::json!({}),
        );
        metadata["packages"][4]["source"] = Value::Null;
        assert!(audit_test_features(&metadata).is_clean());
        // once a member reaches it over a normal edge, it is in the build
        metadata["resolve"]["nodes"][0]["deps"][1]["dep_kinds"] =
            serde_json::json!([{"kind": null}]);
        assert_eq!(
            flagged_packages(&audit_test_features(&metadata)),
            vec!["vendored"]
        );
    }

    #[test]
    fn test_only_feature_pass_refuses_metadata_without_workspace_members() {
        let mut metadata = workspace_with_router_edges(&[], &serde_json::json!({}));
        metadata
            .as_object_mut()
            .unwrap()
            .remove("workspace_members");
        let err = audit_metadata_with_rules(&metadata, &[], &[], &[]).unwrap_err();
        assert!(matches!(err, AuditError::MetadataShape(_)), "{err}");
    }

    #[test]
    fn test_only_feature_through_a_feature_of_the_package_is_flagged() {
        // `server_lib`'s own feature turns it on, under a renamed key, with
        // the weak-dependency `?` form
        let renamed = serde_json::json!([{"name": "fuz_http", "rename": "http", "kind": null,
            "features": [], "uses_default_features": true}]);
        for entry in [
            "http/test_router_access",
            "http?/test_router_access",
            "http/everything",
        ] {
            let metadata = workspace_with_router_edges(
                &[("server_lib", renamed.clone())],
                &serde_json::json!({"testing": [entry]}),
            );
            let report = audit_test_features(&metadata);
            assert_eq!(flagged_packages(&report), vec!["server_lib"], "{entry}");
            assert!(report.test_feature_violations[0].via.contains("`testing`"));
        }
        // the dependency's name is not its key once renamed
        let metadata = workspace_with_router_edges(
            &[("server_lib", renamed)],
            &serde_json::json!({"testing": ["fuz_http/test_router_access"]}),
        );
        assert!(audit_test_features(&metadata).is_clean());
    }

    #[test]
    fn test_only_features_absent_from_the_metadata_check_nothing() {
        let report = audit_metadata_with_rules(&fact_reaching_http(), &[], &[], &[]).unwrap();
        assert!(report.is_clean());
        assert!(report.test_features_checked.is_empty());
    }

    #[test]
    fn test_only_feature_violation_display_names_the_fix() {
        let v = TestOnlyFeatureViolation {
            package: "server_lib".into(),
            crate_name: "fuz_http".into(),
            feature: "test_router_access".into(),
            via: "its dependency enables `test_router_access`".into(),
        };
        let s = format!("{v}");
        assert!(s.contains("`server_lib`"), "{s}");
        assert!(s.contains("`fuz_http/test_router_access`"), "{s}");
        assert!(s.contains("[dev-dependencies]"), "{s}");
    }

    /// A spine-shaped workspace: production binary `fuz` reaches `fuz_auth`;
    /// `fuz_cell` is a library no binary reaches; `fuz_crypto` and `fuz_home`
    /// declare their test-only seams; `fuz_testing`, `fuz_sign` and the
    /// `testing_stub` / `xtask` packages sit beside them; `rand` is a crates.io
    /// package with a `test_*` feature of its own. `deps` sets the declared
    /// edges of the named packages (`[]` otherwise); the resolved graph links
    /// `fuz -> fuz_auth` and every member to `rand` only, so a declared edge is
    /// all that differs between cases.
    fn spine_workspace(deps: &[(&str, Value)]) -> Value {
        let deps_of = |pkg: &str| -> Value {
            deps.iter()
                .find(|(p, _)| *p == pkg)
                .map_or_else(|| serde_json::json!([]), |(_, d)| d.clone())
        };
        let lib = |name: &str| -> Value {
            serde_json::json!({"name": name, "id": format!("{name}#0.1.0"), "source": null,
                "targets": [{"name": name, "kind": ["lib"]}], "features": {},
                "dependencies": deps_of(name)})
        };
        let mut crypto = lib("fuz_crypto");
        crypto["features"] = serde_json::json!({"test_trust_anchor": []});
        let mut home = lib("fuz_home");
        home["features"] = serde_json::json!({"test_home_override": []});
        let mut fuz = lib("fuz");
        fuz["targets"] = serde_json::json!([{"name": "fuz", "kind": ["bin"]}]);
        let mut stub = lib("testing_stub");
        stub["targets"] = serde_json::json!([{"name": "testing_stub", "kind": ["bin"]}]);
        let mut xtask = lib("xtask");
        xtask["targets"] = serde_json::json!([{"name": "xtask", "kind": ["bin"]}]);
        xtask["metadata"] = serde_json::json!({"fuz_audit": {"dev_only": true}});
        let names = [
            "fuz",
            "fuz_auth",
            "fuz_cell",
            "fuz_crypto",
            "fuz_home",
            "fuz_testing",
            "fuz_sign",
            "testing_stub",
            "xtask",
        ];
        let mut packages: Vec<Value> = vec![
            fuz,
            lib("fuz_auth"),
            lib("fuz_cell"),
            crypto,
            home,
            lib("fuz_testing"),
            lib("fuz_sign"),
            stub,
            xtask,
        ];
        let mut rand = lib("rand");
        rand["source"] = serde_json::json!("registry+https://github.com/rust-lang/crates.io-index");
        rand["features"] = serde_json::json!({"test_rng": []});
        packages.push(rand);
        let mut nodes: Vec<Value> = names
            .iter()
            .map(|n| {
                let mut deps = vec![serde_json::json!({"pkg": "rand#0.1.0",
                    "dep_kinds": [{"kind": null}]})];
                if *n == "fuz" {
                    deps.push(serde_json::json!({"pkg": "fuz_auth#0.1.0",
                        "dep_kinds": [{"kind": null}]}));
                }
                serde_json::json!({"id": format!("{n}#0.1.0"), "deps": deps})
            })
            .collect();
        nodes.push(serde_json::json!({"id": "rand#0.1.0", "deps": []}));
        serde_json::json!({
            "workspace_members": names.iter().map(|n| format!("{n}#0.1.0")).collect::<Vec<_>>(),
            "packages": packages,
            "resolve": {"nodes": nodes},
        })
    }

    fn dep(name: &str, kind: Option<&str>, extra: &Value) -> Value {
        let mut d = serde_json::json!({"name": name, "kind": kind, "optional": false,
            "target": null, "features": [], "uses_default_features": true,
            "source": null});
        for (k, v) in extra.as_object().unwrap() {
            d[k] = v.clone();
        }
        d
    }

    fn audit_spine(metadata: &Value) -> AuditReport {
        audit_metadata_with_rules(
            metadata,
            &["fuz_testing", "fuz_audit", "fuz_sign"],
            &[],
            &[],
        )
        .unwrap()
    }

    fn declared(report: &AuditReport) -> Vec<(&str, &str)> {
        report
            .declared_violations
            .iter()
            .map(|v| (v.package.as_str(), v.forbidden.as_str()))
            .collect()
    }

    #[test]
    fn spine_workspace_is_clean() {
        let report = audit_spine(&spine_workspace(&[]));
        assert!(report.is_clean(), "{report:?}");
        // every local package but the testing_*, dev_only and forbidden ones
        assert_eq!(report.declared_checked, 5);
        assert_eq!(
            report.test_features_checked,
            vec![
                "fuz_crypto/test_trust_anchor".to_string(),
                "fuz_home/test_home_override".to_string(),
            ]
        );
    }

    #[test]
    fn declared_forbidden_dep_of_a_library_no_binary_reaches_is_flagged() {
        // no production binary reaches fuz_cell, so the binary walk is blind
        // to its edge
        let metadata = spine_workspace(&[(
            "fuz_cell",
            serde_json::json!([dep("fuz_testing", None, &serde_json::json!({}))]),
        )]);
        let report = audit_spine(&metadata);
        assert!(report.violations.is_empty());
        assert_eq!(declared(&report), vec![("fuz_cell", "fuz_testing")]);
        assert_eq!(report.exit_code(), 65);
        let message = report.declared_violations[0].to_string();
        assert!(message.contains("`fuz_cell`"), "{message}");
        assert!(message.contains("[dev-dependencies]"), "{message}");
    }

    #[test]
    fn declared_forbidden_dep_flagged_whether_optional_target_specific_or_build() {
        for (extra, kind, needle) in [
            (serde_json::json!({"optional": true}), None, "optional"),
            (
                serde_json::json!({"target": "cfg(target_os = \"linux\")"}),
                None,
                "target_os",
            ),
            (serde_json::json!({}), Some("build"), "build edge"),
        ] {
            let metadata = spine_workspace(&[(
                "fuz_auth",
                serde_json::json!([dep("fuz_testing", kind, &extra)]),
            )]);
            let report = audit_spine(&metadata);
            assert_eq!(
                declared(&report),
                vec![("fuz_auth", "fuz_testing")],
                "{extra}"
            );
            assert!(
                report.declared_violations[0].edge.contains(needle),
                "{:?}",
                report.declared_violations
            );
        }
    }

    #[test]
    fn declared_forbidden_dep_covers_every_global_forbid() {
        // `fuz_audit` built in, `fuz_sign` an extra forbid of the workspace
        for forbidden in ["fuz_audit", "fuz_sign"] {
            let metadata = spine_workspace(&[(
                "fuz_auth",
                serde_json::json!([dep(forbidden, None, &serde_json::json!({}))]),
            )]);
            assert_eq!(
                declared(&audit_spine(&metadata)),
                vec![("fuz_auth", forbidden)]
            );
        }
    }

    #[test]
    fn declared_forbidden_dep_exemptions() {
        let testing = serde_json::json!([dep("fuz_testing", None, &serde_json::json!({}))]);
        let metadata = spine_workspace(&[
            // a dev edge is the legitimate use
            (
                "fuz_auth",
                serde_json::json!([dep("fuz_testing", Some("dev"), &serde_json::json!({}))]),
            ),
            // testing_*-named, dev_only and forbidden packages are exempt
            ("testing_stub", testing.clone()),
            ("xtask", testing.clone()),
            (
                "fuz_testing",
                serde_json::json!([dep("fuz_audit", None, &serde_json::json!({}))]),
            ),
            // a crates.io package is not local
            ("rand", testing),
        ]);
        let report = audit_spine(&metadata);
        assert!(report.is_clean(), "{report:?}");
    }

    fn flagged_features(report: &AuditReport) -> Vec<(&str, &str, &str)> {
        report
            .test_feature_violations
            .iter()
            .map(|v| {
                (
                    v.package.as_str(),
                    v.crate_name.as_str(),
                    v.feature.as_str(),
                )
            })
            .collect()
    }

    #[test]
    fn derived_test_only_features_on_normal_or_build_edges_are_flagged() {
        for (crate_name, feature) in [
            ("fuz_crypto", "test_trust_anchor"),
            ("fuz_home", "test_home_override"),
        ] {
            for kind in [None, Some("build")] {
                let metadata = spine_workspace(&[(
                    "fuz_auth",
                    serde_json::json!([dep(
                        crate_name,
                        kind,
                        &serde_json::json!({"features": [feature]})
                    )]),
                )]);
                let report = audit_spine(&metadata);
                assert_eq!(
                    flagged_features(&report),
                    vec![("fuz_auth", crate_name, feature)],
                    "{crate_name}/{feature} {kind:?}"
                );
            }
        }
    }

    #[test]
    fn a_novel_test_feature_on_a_path_package_is_derived_and_flagged() {
        let mut metadata = spine_workspace(&[(
            "fuz_auth",
            serde_json::json!([dep(
                "fuz_cell",
                None,
                &serde_json::json!({"features": ["test_whatever"]})
            )]),
        )]);
        metadata["packages"][2]["features"] = serde_json::json!({"test_whatever": []});
        let report = audit_spine(&metadata);
        assert_eq!(
            flagged_features(&report),
            vec![("fuz_auth", "fuz_cell", "test_whatever")]
        );
        assert!(
            report
                .test_features_checked
                .contains(&"fuz_cell/test_whatever".to_string())
        );
    }

    #[test]
    fn test_only_features_enabled_from_dev_edges_pass() {
        let metadata = spine_workspace(&[(
            "fuz_auth",
            serde_json::json!([
                dep("fuz_crypto", None, &serde_json::json!({})),
                dep(
                    "fuz_crypto",
                    Some("dev"),
                    &serde_json::json!({"features": ["test_trust_anchor"]})
                ),
                dep(
                    "fuz_home",
                    Some("dev"),
                    &serde_json::json!({"features": ["test_home_override"]})
                ),
            ]),
        )]);
        assert!(audit_spine(&metadata).is_clean());
    }

    #[test]
    fn a_crates_io_package_s_test_feature_is_not_test_only() {
        let metadata = spine_workspace(&[(
            "fuz_auth",
            serde_json::json!([dep(
                "rand",
                None,
                &serde_json::json!({"features": ["test_rng"],
                    "source": "registry+https://github.com/rust-lang/crates.io-index"})
            )]),
        )]);
        let report = audit_spine(&metadata);
        assert!(report.is_clean(), "{report:?}");
        assert!(
            !report
                .test_features_checked
                .iter()
                .any(|f| f.starts_with("rand/"))
        );
    }

    #[test]
    fn a_test_only_feature_may_forward_to_another() {
        // `fuz_auth`'s own `test_auth` names `fuz_crypto/test_trust_anchor`:
        // test-only itself, so it is checked where it is enabled, not here
        let mut metadata = spine_workspace(&[(
            "fuz_auth",
            serde_json::json!([dep("fuz_crypto", None, &serde_json::json!({}))]),
        )]);
        metadata["packages"][1]["features"] =
            serde_json::json!({"test_auth": ["fuz_crypto/test_trust_anchor"]});
        assert!(audit_spine(&metadata).is_clean());
        // once a normal edge enables `test_auth`, that edge is refused
        metadata["packages"][2]["dependencies"] = serde_json::json!([dep(
            "fuz_auth",
            None,
            &serde_json::json!({"features": ["test_auth"]})
        )]);
        assert_eq!(
            flagged_features(&audit_spine(&metadata)),
            vec![("fuz_cell", "fuz_auth", "test_auth")]
        );
        // a feature that is not test-only naming it is refused as before
        metadata["packages"][2]["dependencies"] = serde_json::json!([]);
        metadata["packages"][1]["features"] =
            serde_json::json!({"extras": ["fuz_crypto/test_trust_anchor"]});
        assert_eq!(
            flagged_features(&audit_spine(&metadata)),
            vec![("fuz_auth", "fuz_crypto", "test_trust_anchor")]
        );
    }

    #[test]
    fn cargo_metadata_reads_every_feature_from_the_lockfile() {
        assert_eq!(
            CARGO_METADATA_ARGS,
            [
                "metadata",
                "--format-version",
                "1",
                "--locked",
                "--all-features"
            ]
        );
    }

    /// `ExitCode` lacks `PartialEq`; compare via `Debug` output instead.
    fn exit_code_eq(actual: ExitCode, expected: ExitCode) -> bool {
        format!("{actual:?}") == format!("{expected:?}")
    }

    #[test]
    fn xtask_main_no_args_prints_usage_and_succeeds() {
        let code = xtask_main_inner(std::iter::empty::<String>());
        assert!(exit_code_eq(code, ExitCode::SUCCESS));
    }

    #[test]
    fn xtask_main_help_flag_succeeds() {
        for flag in ["help", "-h", "--help"] {
            let code = xtask_main_inner([flag.to_string()].into_iter());
            assert!(
                exit_code_eq(code, ExitCode::SUCCESS),
                "flag `{flag}` should succeed"
            );
        }
    }

    #[test]
    fn xtask_main_unknown_subcommand_fails() {
        let code = xtask_main_inner(["frobnicate".to_string()].into_iter());
        assert!(exit_code_eq(code, ExitCode::FAILURE));
    }

    #[test]
    fn violation_display_renders_chain() {
        let v = AuditViolation {
            binary: "fuz".into(),
            package: "fuz".into(),
            forbidden: "fuz_testing".into(),
            chain: vec!["fuz".into(), "leaky_lib".into(), "fuz_testing".into()],
        };
        let s = format!("{v}");
        assert!(s.contains("fuz -> leaky_lib -> fuz_testing"));
    }

    #[test]
    fn report_exit_code_is_zero_when_clean_and_dataerr_when_violated() {
        let clean = AuditReport {
            scanned: vec![("fuz".into(), "fuz".into())],
            absent_forbidden: vec![],
            violations: vec![],
            declared_violations: vec![],
            declared_checked: 1,
            layering_violations: vec![],
            layering_checked: vec![],
            test_feature_violations: vec![],
            test_features_checked: vec![],
            lint_tables: LintTablesReport::default(),
        };
        assert_eq!(clean.exit_code(), 0);

        let violated = AuditReport {
            scanned: vec![("fuz".into(), "fuz".into())],
            absent_forbidden: vec![],
            violations: vec![AuditViolation {
                binary: "fuz".into(),
                package: "fuz".into(),
                forbidden: "fuz_testing".into(),
                chain: vec!["fuz".into(), "fuz_testing".into()],
            }],
            declared_violations: vec![],
            declared_checked: 1,
            layering_violations: vec![],
            layering_checked: vec![],
            test_feature_violations: vec![],
            test_features_checked: vec![],
            lint_tables: LintTablesReport::default(),
        };
        // EX_DATAERR — a forbidden dep is well-formed-but-wrong data.
        assert_eq!(violated.exit_code(), 65);

        // A layering violation alone also fails the audit (EX_DATAERR).
        let layered = AuditReport {
            scanned: vec![],
            absent_forbidden: vec![],
            violations: vec![],
            declared_violations: vec![],
            declared_checked: 0,
            layering_violations: vec![LayeringViolation {
                crate_name: "fuz_fact".into(),
                forbidden: "fuz_http".into(),
                chain: vec!["fuz_fact".into(), "fuz_http".into()],
            }],
            layering_checked: vec!["fuz_fact".into()],
            test_feature_violations: vec![],
            test_features_checked: vec![],
            lint_tables: LintTablesReport::default(),
        };
        assert!(!layered.is_clean());
        assert_eq!(layered.exit_code(), 65);

        // so does a declared edge alone
        let declared = AuditReport {
            scanned: vec![],
            absent_forbidden: vec![],
            violations: vec![],
            declared_violations: vec![DeclaredForbiddenViolation {
                package: "fuz_auth".into(),
                forbidden: "fuz_testing".into(),
                edge: "normal edge".into(),
            }],
            declared_checked: 1,
            layering_violations: vec![],
            layering_checked: vec![],
            test_feature_violations: vec![],
            test_features_checked: vec![],
            lint_tables: LintTablesReport::default(),
        };
        assert!(!declared.is_clean());
        assert_eq!(declared.exit_code(), 65);

        // and so does a lint-table violation alone
        let lint_drift = AuditReport {
            lint_tables: LintTablesReport {
                violations: vec![lint_tables::LintTableViolation::Tools {
                    package: "fuz_pty".into(),
                    missing: vec!["rustdoc".into()],
                    extra: vec![],
                }],
                ..LintTablesReport::default()
            },
            ..clean
        };
        assert!(!lint_drift.is_clean());
        assert_eq!(lint_drift.exit_code(), 65);
    }

    #[test]
    fn audit_error_exit_codes_split_unavailable_from_software() {
        // cargo couldn't run / failed → EX_UNAVAILABLE.
        assert_eq!(
            AuditError::CargoRun(std::io::Error::other("nope")).exit_code(),
            69,
        );
        assert_eq!(
            AuditError::CargoFailed {
                stderr: "boom".into()
            }
            .exit_code(),
            69,
        );
        // cargo ran but its output was unusable → EX_SOFTWARE.
        let parse_err = serde_json::from_str::<Value>("{").unwrap_err();
        assert_eq!(AuditError::Parse(parse_err).exit_code(), 70);
        assert_eq!(
            AuditError::MetadataShape("packages array missing").exit_code(),
            70,
        );
    }
}
