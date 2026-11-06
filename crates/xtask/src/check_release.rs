//! `cargo xtask check-release` — production builds must not pull in
//! `fuz_testing`, `fuz_audit`, or `fuz_sign`, nor a `test_*` feature seam.
//!
//! Thin wrapper around [`fuz_audit::run_check_release_cli_with_rules`]. The
//! audit logic itself lives in the `fuz_audit` crate so consumer-workspace
//! xtasks (`zap`, `zzz`, and any future Rust workspace consuming the
//! spine) can adopt the same check via a single function call.
//!
//! This workspace additionally forbids `fuz_sign` (the producer-side signing
//! crate) globally: the `fuz` consumer binary must only verify, never sign, so
//! its dependency graph must exclude signing, and no other local package may
//! declare it outside `[dev-dependencies]`. `xtask` itself signs and depends
//! on `fuz_sign`, but is `dev_only`-exempt from the scan.
//!
//! It also applies a *per-binary* rule: the sealed `fuz`/`fuzd` binaries must
//! not depend on any `fuzi_*` crate (the npm-bridge installer is out of core),
//! while the `fuzi` binary itself legitimately depends on `fuzi_core`. A global
//! forbid can't express that — it would flag `fuzi` — so the rule is scoped to
//! `fuz` and `fuzd` only.

use std::process::ExitCode;

/// Run the workspace dep-graph audit. Wraps
/// [`fuz_audit::run_check_release_cli_with_rules`], forbidding `fuz_sign`
/// globally and `fuzi`/`fuzi_core` for the `fuz`/`fuzd` binaries specifically.
#[must_use]
pub fn check_release() -> ExitCode {
    use fuz_audit::{AuditRules, PerBinaryForbid};
    fuz_audit::run_check_release_cli_with_rules(&AuditRules {
        extra_forbidden: &["fuz_sign"],
        per_binary: &[
            PerBinaryForbid {
                binary: "fuz",
                crates: &["fuzi", "fuzi_core"],
            },
            PerBinaryForbid {
                binary: "fuzd",
                crates: &["fuzi", "fuzi_core"],
            },
        ],
    })
}
