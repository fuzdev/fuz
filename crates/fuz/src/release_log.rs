//! The release log check, as the `fuz` binary configures and reports it.
//!
//! `fuz_release::log_check` does the checking and prints nothing. This module
//! is the two edges around it: reading the two environment variables into a
//! policy, and rendering what a check found.
//!
//! Everything that consults the log goes through here:
//!
//! - an install — `fuz self upgrade`, `fuz tool install` / `upgrade` — holds
//!   the release to the log before using its bytes;
//! - an update check — either `--check` — holds the latest release to the log
//!   before reporting on it, and writes nothing;
//! - `fuz self bootstrap` holds the binary it is about to install to the log;
//! - every `fuz self` command reads the cached head, with no request to a
//!   witness, and warns when the version it reports — the installed
//!   artifact's, or this binary's own when nothing is installed — is revoked.
//!
//! - `FUZ_RELEASE_LOG_URL` names the witnesses — one or more origins separated
//!   by commas, each an `https://` URL (`http://` for a loopback host) or an
//!   existing local directory. Unset or empty, no check runs: there is no
//!   built-in origin.
//! - `FUZ_RELEASE_LOG=off` opts out. With a URL set it disables the check and
//!   says so on stderr, once per process; with none set it changes nothing.
//!
//! The witness keys the origins are matched against are the ones built into
//! the binary, `fuz_crypto::WITNESS_KEYS`: a witness with one has its
//! co-signature checked. None is built in today, so none is requested.
//!
//! Everything rendered here goes to stderr, so a command's stdout stays what
//! it was. `--quiet` drops the one-line summary of a confirmed release and the
//! line for each co-signature seen; the warnings stay — each says the check ran with less than a fresh answer from
//! every witness, did not run at all, or found this `fuz` revoked.
//!
//! A configuration the check cannot run under — a `FUZ_RELEASE_LOG` value
//! other than `off`, an entry of `FUZ_RELEASE_LOG_URL` that is not an origin,
//! a value that is not UTF-8 — exits 2: the caller has to change it before
//! running again. `fuz self version` and `fuz self status` are the exception:
//! they are diagnostics, so there the same configuration, or a cached head
//! that cannot be used, is a one-line warning and the command goes on. They
//! treat a fuz home that cannot be resolved the same way, with the home
//! layer's hint under the warning (`crate::self_cmd`); the cached head lives
//! under the home, so that run reads the configuration alone.

use std::sync::Once;

use fuz_artifact::ArtifactMeta;
use fuz_release::{
    CoSignCoverage, CoSignReport, HeadSource, InstalledStanding, LogCheck, RELEASE_LOG_ENV,
    RELEASE_LOG_URL_ENV, ReleaseError, ReleaseLogPolicy, ReleaseLogReport,
    cached_installed_standing,
};
use serde::Serialize;

use crate::CliError;
use crate::release::ReleaseCommandError;

/// Build the release log policy from the environment, for a command that
/// holds a release to the log. An opt-out is announced on stderr, once per
/// process.
pub fn policy_from_env() -> Result<ReleaseLogPolicy, CliError> {
    let policy = read_policy()?;
    if matches!(policy, ReleaseLogPolicy::Off) && first_off_notice() {
        eprintln!("{OFF_WARNING}");
    }
    Ok(policy)
}

/// Read the two variables into a policy and print nothing.
///
/// The one place they are read. A value that is not valid UTF-8 is refused
/// rather than read as unset, since unset means "no check". The origins are
/// matched against the witness keys built into this binary.
fn read_policy() -> Result<ReleaseLogPolicy, CliError> {
    let url = read_var(
        RELEASE_LOG_URL_ENV,
        "FUZ_RELEASE_LOG_URL is not valid UTF-8",
    )?;
    let switch = read_var(RELEASE_LOG_ENV, "FUZ_RELEASE_LOG is not valid UTF-8")?;
    Ok(ReleaseLogPolicy::from_env_values(
        url.as_deref(),
        switch.as_deref(),
        fuz_crypto::WITNESS_KEYS,
    )
    .map_err(|e| ReleaseCommandError::Release(ReleaseError::ReleaseLog(e)))?)
}

fn read_var(name: &str, not_unicode: &'static str) -> Result<Option<String>, CliError> {
    match std::env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => Err(CliError::InvalidUsage(not_unicode)),
    }
}

/// What the opt-out prints.
const OFF_WARNING: &str = "warning: the release log check is disabled by FUZ_RELEASE_LOG=off";

/// Whether this is the first opt-out notice of the process — `true` exactly
/// once, so a command that builds the policy more than once warns once.
fn first_off_notice() -> bool {
    static ONCE: Once = Once::new();
    let mut first = false;
    ONCE.call_once(|| first = true);
    first
}

/// Print what a release log check found, to stderr.
pub fn render(check: &LogCheck, quiet: bool) {
    for line in lines(check, quiet) {
        eprintln!("{line}");
    }
}

/// The `release_log` object of a `--check --json` report: the head that
/// confirmed the latest release.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct CheckLogJson {
    /// The head's `seq`.
    seq: u64,
    /// Where the head came from: `witness`, `cache_ahead_of_witness`, or
    /// `cache_witness_unreachable`.
    source: &'static str,
    /// The verified co-signatures the check saw. Absent when there is none —
    /// always, unless a witness has a witness key built into this binary.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    co_signs: Vec<CoSignJson>,
}

/// One verified co-signature in a `--check --json` report.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct CoSignJson {
    /// The witness that served it.
    origin: String,
    /// The `seq` it names.
    seq: u64,
    /// What it covers: `effective_head` (the head its witness serves, which
    /// is the one that confirmed the release), `older_head` (the head its
    /// witness serves, which is older than that), or `none` (it names another
    /// `seq` than its witness's head, so nothing was compared).
    covers: &'static str,
}

/// The `release_log` object for a check's outcome. `None` unless the release
/// was confirmed, so a report made with no witness configured — or under the
/// opt-out — has no such key.
pub fn check_json(check: &LogCheck) -> Option<CheckLogJson> {
    let LogCheck::Confirmed(report) = check else {
        return None;
    };
    Some(CheckLogJson {
        seq: report.seq,
        source: match report.source {
            HeadSource::Witness => "witness",
            HeadSource::CacheAheadOfWitness => "cache_ahead_of_witness",
            HeadSource::CacheWitnessUnreachable => "cache_witness_unreachable",
        },
        co_signs: report
            .co_signs
            .iter()
            .map(|co_sign| CoSignJson {
                origin: co_sign.origin.clone(),
                seq: co_sign.seq,
                covers: match co_sign.coverage {
                    CoSignCoverage::EffectiveHead => "effective_head",
                    CoSignCoverage::OlderHead => "older_head",
                    CoSignCoverage::Uncompared => "none",
                },
            })
            .collect(),
    })
}

//
// The standing of the fuz a command reports, from the cached head
//

/// The version a `fuz self` command reports, and so the one whose standing it
/// looks up: the installed artifact's, or this binary's own when no artifact is
/// installed or `current` cannot be read.
pub fn reported_version(artifact: Option<&ArtifactMeta>) -> &str {
    artifact.map_or(env!("CARGO_PKG_VERSION"), |meta| meta.version.as_str())
}

/// Warn on stderr when the cached head records fuz `version` as revoked — for
/// `fuz self upgrade` and `fuz self bootstrap`, which then run a real check.
///
/// No witness is asked and nothing is written. The warning states the fact and
/// gives no advice: the command printing it is the remedy, already running. A
/// cached head that cannot be used says nothing here: the check that follows
/// refuses on it, with the error and its hint.
pub fn warn_if_revoked(policy: &ReleaseLogPolicy, version: &str) {
    if let Ok(Some(standing)) = cached_installed_standing(policy, Some(version))
        && let Some(line) = remedy_warning(standing, version)
    {
        eprintln!("{line}");
    }
}

/// The line [`warn_if_revoked`] prints: the fact, with no advice.
fn remedy_warning(standing: InstalledStanding, version: &str) -> Option<String> {
    revoked_line(standing, version, Advice::Omit)
}

/// The standing of fuz `version` for `fuz self version` and `fuz self status`,
/// which must report whatever state the release log is in.
///
/// Prints the revoked warning, with what to do about it, when it applies. A
/// configuration the check cannot run under, or a cached head that cannot be
/// used, is one warning line and `None` — never a failure of the command. The
/// opt-out is not announced: these commands hold no release to the log.
pub fn diagnose(version: &str) -> Option<InstalledStanding> {
    let standing = diagnostic_policy().and_then(|policy| {
        cached_installed_standing(&policy, Some(version)).map_err(|e| problem_text(&e))
    });
    for line in diagnostic_lines(&standing, version) {
        eprintln!("{line}");
    }
    standing.ok().flatten()
}

/// [`diagnose`] for a run whose fuz home cannot be resolved, which the caller
/// has reported: the cached head lives under the home, so it is not looked
/// for. A configuration the check cannot run under is still one warning line.
pub fn diagnose_configuration() {
    let configuration = diagnostic_policy().map(|_| None);
    for line in diagnostic_lines(&configuration, "") {
        eprintln!("{line}");
    }
}

/// The policy for a diagnostic, or the text of the warning that says why
/// there is none.
fn diagnostic_policy() -> Result<ReleaseLogPolicy, String> {
    read_policy().map_err(|e| match e {
        CliError::ReleaseCommand(ReleaseCommandError::Release(e)) => problem_text(&e),
        other => other.to_string(),
    })
}

/// A release log problem as a warning's text: the release log error itself,
/// without the wrapper's prefix.
fn problem_text(error: &ReleaseError) -> String {
    match error {
        ReleaseError::ReleaseLog(e) => e.to_string(),
        other => other.to_string(),
    }
}

/// The lines [`diagnose`] prints: the failure, or the revoked warning with its
/// advice, or nothing.
fn diagnostic_lines(
    standing: &Result<Option<InstalledStanding>, String>,
    version: &str,
) -> Vec<String> {
    match standing {
        Err(problem) => vec![format!("warning: {problem}")],
        Ok(None) => Vec::new(),
        Ok(Some(standing)) => revoked_line(*standing, version, Advice::Give)
            .into_iter()
            .collect(),
    }
}

/// Whether the revoked warning says what to do about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Advice {
    /// On a diagnostic: name the command that replaces the release.
    Give,
    /// On `upgrade` and `bootstrap`: the command is already doing it.
    Omit,
}

/// What the revoked warning advises, where it advises.
const REVOKED_ADVICE: &str = "run 'fuz self upgrade' to replace it";

/// The warning for a fuz `version` the cached head records as revoked: the
/// fact, then the advice when asked for. Printed under `--quiet` too: it
/// reports a failed security state, not progress.
fn revoked_line(standing: InstalledStanding, version: &str, advice: Advice) -> Option<String> {
    if !standing.revoked {
        return None;
    }
    let fact = format!(
        "warning: this fuz {version} is revoked in the release log (cached head, seq {})",
        standing.seq
    );
    Some(match advice {
        Advice::Give => format!("{fact} - {REVOKED_ADVICE}"),
        Advice::Omit => fact,
    })
}

/// The lines [`render`] prints, in order: each warning, then the summary, then
/// one line for each co-signature seen.
///
/// `quiet` drops the summary and the co-signature lines and keeps the
/// warnings. A check that did not run
/// has no lines — an inactive policy says nothing, and the opt-out warned when
/// the policy was built.
fn lines(check: &LogCheck, quiet: bool) -> Vec<String> {
    let LogCheck::Confirmed(report) = check else {
        return Vec::new();
    };
    let mut lines: Vec<String> = warnings(report)
        .into_iter()
        .map(|warning| format!("warning: {warning}"))
        .collect();
    if !quiet {
        lines.push(summary(report));
        lines.extend(report.co_signs.iter().map(co_sign_line));
    }
    lines
}

/// The line for one verified co-signature: who made it, the `seq` it names,
/// and what it covers. A co-signature that did not cover the head served
/// beside it is never here — it refused the check.
fn co_sign_line(co_sign: &CoSignReport) -> String {
    let CoSignReport {
        origin,
        seq,
        coverage,
    } = co_sign;
    match coverage {
        CoSignCoverage::EffectiveHead => {
            format!("release log: co-signed at seq {seq} by {origin}")
        }
        CoSignCoverage::OlderHead => format!(
            "release log: co-signed at seq {seq} by {origin} (an older head than the one \
             confirmed)"
        ),
        CoSignCoverage::Uncompared => format!(
            "release log: co-signature by {origin} names seq {seq}, not the seq of the head \
             it serves (not compared)"
        ),
    }
}

/// The one-line summary of a confirmed release: the head's `seq` — what two
/// users compare to tell whether they saw the same log — its `signed_at`,
/// labelled for what it is, and where the head came from.
fn summary(report: &ReleaseLogReport) -> String {
    let from = match report.source {
        HeadSource::Witness => report.answered.join(", "),
        HeadSource::CacheAheadOfWitness | HeadSource::CacheWitnessUnreachable => {
            "the cached head".to_string()
        }
    };
    format!(
        "release log: confirmed at seq {} from {from} (signed_at {}, publisher-asserted, not covered by the signature)",
        report.seq, report.signed_at
    )
}

/// The ways a confirmed check fell short of a fresh answer from every witness.
fn warnings(report: &ReleaseLogReport) -> Vec<String> {
    let mut warnings = Vec::new();
    if !report.unreachable.is_empty() {
        let list = report
            .unreachable
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        warnings.push(match report.source {
            HeadSource::CacheWitnessUnreachable => {
                format!("no release log witness reachable ({list}); confirmed from the cached head")
            }
            HeadSource::Witness | HeadSource::CacheAheadOfWitness => {
                format!("release log witness unreachable: {list}")
            }
        });
    }
    if report.source == HeadSource::CacheAheadOfWitness {
        warnings.push(format!(
            "release log witnesses behind the cached head: {}; confirmed from the cached head",
            report.answered.join(", ")
        ));
    }
    warnings
}

#[cfg(test)]
mod tests {
    use super::*;
    use fuz_release::UnreachableOrigin;

    fn report(source: HeadSource, answered: &[&str], unreachable: &[&str]) -> ReleaseLogReport {
        ReleaseLogReport {
            seq: 12,
            signed_at: "2025-01-15T10:30:00Z".to_string(),
            source,
            answered: answered.iter().map(ToString::to_string).collect(),
            unreachable: unreachable
                .iter()
                .map(|origin| UnreachableOrigin {
                    origin: (*origin).to_string(),
                    reason: "HTTPS: path not found: head.json".to_string(),
                })
                .collect(),
            cache_written: false,
            co_signs: Vec::new(),
        }
    }

    fn co_signed(coverage: CoSignCoverage, seq: u64) -> CoSignReport {
        CoSignReport {
            origin: "https://cosigner.example".to_string(),
            seq,
            coverage,
        }
    }

    #[test]
    fn a_co_signature_is_one_line_after_the_summary_and_quiet_drops_it() {
        let mut seen = report(HeadSource::Witness, &["https://cosigner.example"], &[]);
        seen.co_signs = vec![
            co_signed(CoSignCoverage::EffectiveHead, 12),
            co_signed(CoSignCoverage::OlderHead, 11),
            co_signed(CoSignCoverage::Uncompared, 13),
        ];
        let check = LogCheck::Confirmed(seen);
        let loud = lines(&check, false);
        assert_eq!(loud.len(), 4, "{loud:?}");
        assert!(loud[0].starts_with("release log: confirmed at seq 12"));
        assert_eq!(
            loud[1..],
            [
                "release log: co-signed at seq 12 by https://cosigner.example",
                "release log: co-signed at seq 11 by https://cosigner.example (an older head \
                 than the one confirmed)",
                "release log: co-signature by https://cosigner.example names seq 13, not the \
                 seq of the head it serves (not compared)",
            ]
        );
        assert!(lines(&check, true).is_empty());

        // In the report, and absent from it when there is none.
        assert_eq!(
            serde_json::to_value(check_json(&check).unwrap()).unwrap(),
            serde_json::json!({
                "seq": 12,
                "source": "witness",
                "co_signs": [
                    { "origin": "https://cosigner.example", "seq": 12, "covers": "effective_head" },
                    { "origin": "https://cosigner.example", "seq": 11, "covers": "older_head" },
                    { "origin": "https://cosigner.example", "seq": 13, "covers": "none" },
                ],
            })
        );
    }

    /// No witness key is built into this binary, so the policy it builds asks
    /// no witness for a co-signature. Embedding the first key makes this
    /// test's claim false: remove it then.
    #[test]
    fn no_witness_key_is_built_in() {
        assert!(fuz_crypto::WITNESS_KEYS.is_empty());
    }

    #[test]
    fn off_notice_fires_exactly_once_per_process() {
        // The only caller in this test binary, so the first call here is the
        // process's first.
        assert!(first_off_notice());
        assert!(!first_off_notice());
        assert!(!first_off_notice());
    }

    #[test]
    fn summary_carries_seq_and_labels_signed_at() {
        let line = summary(&report(HeadSource::Witness, &["https://log.example"], &[]));
        assert_eq!(
            line,
            "release log: confirmed at seq 12 from https://log.example (signed_at \
             2025-01-15T10:30:00Z, publisher-asserted, not covered by the signature)"
        );
        // One line, whatever the source.
        for source in [
            HeadSource::CacheAheadOfWitness,
            HeadSource::CacheWitnessUnreachable,
        ] {
            let line = summary(&report(source, &["a"], &[]));
            assert!(line.contains("seq 12 from the cached head"), "{line}");
            assert!(!line.contains('\n'), "{line}");
        }
    }

    #[test]
    fn quiet_drops_the_summary_and_keeps_the_warnings() {
        let clean = LogCheck::Confirmed(report(HeadSource::Witness, &["a"], &[]));
        let loud = lines(&clean, false);
        assert_eq!(loud.len(), 1);
        assert!(loud[0].starts_with("release log: confirmed at seq 12"));
        assert!(loud[0].contains("publisher-asserted, not covered by the signature"));
        assert!(lines(&clean, true).is_empty());

        // An unreachable witness and a lagging one each warn, quiet or not.
        let unreachable = LogCheck::Confirmed(report(HeadSource::Witness, &["a"], &["b"]));
        let lagging = LogCheck::Confirmed(report(HeadSource::CacheAheadOfWitness, &["a"], &[]));
        for (check, needle) in [
            (
                &unreachable,
                "warning: release log witness unreachable: b (",
            ),
            (
                &lagging,
                "warning: release log witnesses behind the cached head: a;",
            ),
        ] {
            let loud = lines(check, false);
            assert_eq!(loud.len(), 2, "{loud:?}");
            assert!(loud[0].starts_with(needle), "{loud:?}");
            assert!(loud[1].starts_with("release log: confirmed"), "{loud:?}");
            // Quiet: the warning alone.
            assert_eq!(lines(check, true), loud[..1], "{loud:?}");
        }
    }

    #[test]
    fn a_check_that_did_not_run_has_no_lines() {
        for check in [LogCheck::Inactive, LogCheck::Off] {
            assert!(lines(&check, false).is_empty());
            assert!(lines(&check, true).is_empty());
        }
    }

    #[test]
    fn a_fresh_answer_from_every_witness_warns_about_nothing() {
        assert!(warnings(&report(HeadSource::Witness, &["a", "b"], &[])).is_empty());
    }

    #[test]
    fn an_unreachable_witness_is_named_with_its_reason() {
        let got = warnings(&report(HeadSource::Witness, &["a"], &["b"]));
        assert_eq!(
            got,
            ["release log witness unreachable: b (HTTPS: path not found: head.json)"]
        );
    }

    #[test]
    fn a_verdict_from_the_cache_says_so() {
        let offline = warnings(&report(HeadSource::CacheWitnessUnreachable, &[], &["a"]));
        assert_eq!(offline.len(), 1);
        assert!(offline[0].starts_with("no release log witness reachable (a ("));
        assert!(offline[0].ends_with("confirmed from the cached head"));

        let lagging = warnings(&report(HeadSource::CacheAheadOfWitness, &["a"], &[]));
        assert_eq!(
            lagging,
            ["release log witnesses behind the cached head: a; confirmed from the cached head"]
        );
        // Several lagging witnesses read as a list.
        let several = warnings(&report(HeadSource::CacheAheadOfWitness, &["a", "b"], &[]));
        assert_eq!(
            several,
            ["release log witnesses behind the cached head: a, b; confirmed from the cached head"]
        );
        // Both at once: one witness down, the other behind the cache.
        let both = warnings(&report(HeadSource::CacheAheadOfWitness, &["a"], &["b"]));
        assert_eq!(both.len(), 2, "{both:?}");
    }

    #[test]
    fn check_json_is_present_only_for_a_confirmed_release() {
        assert_eq!(check_json(&LogCheck::Inactive), None);
        assert_eq!(check_json(&LogCheck::Off), None);
        for (source, name) in [
            (HeadSource::Witness, "witness"),
            (HeadSource::CacheAheadOfWitness, "cache_ahead_of_witness"),
            (
                HeadSource::CacheWitnessUnreachable,
                "cache_witness_unreachable",
            ),
        ] {
            let json = check_json(&LogCheck::Confirmed(report(source, &["a"], &[]))).unwrap();
            assert_eq!(
                serde_json::to_value(&json).unwrap(),
                serde_json::json!({ "seq": 12, "source": name })
            );
        }
    }

    #[test]
    fn the_revoked_warning_is_a_fact_with_advice_only_where_it_helps() {
        const FACT: &str =
            "warning: this fuz 0.3.0 is revoked in the release log (cached head, seq 9)";
        let revoked = InstalledStanding {
            seq: 9,
            revoked: true,
        };
        let standing = InstalledStanding {
            seq: 9,
            revoked: false,
        };
        // `upgrade` and `bootstrap`: the fact alone.
        assert_eq!(
            revoked_line(revoked, "0.3.0", Advice::Omit).as_deref(),
            Some(FACT)
        );
        assert_eq!(remedy_warning(revoked, "0.3.0").as_deref(), Some(FACT));
        // `version` and `status`: the fact, then the way out.
        assert_eq!(
            revoked_line(revoked, "0.3.0", Advice::Give).unwrap(),
            format!("{FACT} - run 'fuz self upgrade' to replace it")
        );
        for advice in [Advice::Give, Advice::Omit] {
            assert_eq!(revoked_line(standing, "0.3.0", advice), None);
        }
    }

    /// With no artifact installed the version a command reports is this
    /// binary's own, and that is the version whose standing it looks up.
    #[test]
    fn the_reported_version_falls_back_to_this_binary() {
        assert_eq!(reported_version(None), env!("CARGO_PKG_VERSION"));
        let meta = ArtifactMeta::new_bootstrap(
            "9.8.7".to_string(),
            fuz_artifact::ContentHash::blake3(b"x"),
        );
        assert_eq!(reported_version(Some(&meta)), "9.8.7");
    }

    /// The diagnostics never fail: every state is zero or one line.
    #[test]
    fn a_diagnostic_is_silent_or_one_warning_line() {
        let version = "0.3.0";
        assert!(diagnostic_lines(&Ok(None), version).is_empty());
        let standing = |revoked| Ok(Some(InstalledStanding { seq: 9, revoked }));
        assert!(diagnostic_lines(&standing(false), version).is_empty());
        let lines = diagnostic_lines(&standing(true), version);
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(lines[0].starts_with("warning: this fuz 0.3.0 is revoked"));
        assert!(lines[0].ends_with("run 'fuz self upgrade' to replace it"));
        assert_eq!(
            diagnostic_lines(
                &Err("cached release log head /x is unusable: y".to_string()),
                version
            ),
            ["warning: cached release log head /x is unusable: y"]
        );
    }
}
