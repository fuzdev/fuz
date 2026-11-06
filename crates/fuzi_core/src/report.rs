//! The structured outcome an install produces.
//!
//! Presentation lives in the `fuzi` binary (human / `--json` / `--quiet`) —
//! `fuzi_core` returns this value and prints nothing. Dry-run and real-run share
//! the shape: a dry-run populates `cached` vs. would-fetch by probing the cache
//! and skips the download (and the `placed` / `fetched` counts read as "would").

use serde::Serialize;

/// How a single unique tarball was satisfied.
///
/// A typed fold target so the `142 cached · 12 fetched` summary is a sum over
/// outcomes, not an ad-hoc counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchOutcome {
    /// Already present in the CAS and re-verified on read.
    CacheHit,
    /// Downloaded, verified, and committed this run, transferring `bytes`.
    Fetched {
        /// Bytes transferred for this tarball.
        bytes: u64,
    },
}

/// The install phase's structured result: the fetch [`FetchOutcome`] fold, the
/// materialization tallies, and the plan-derived informational counts.
///
/// `fuzi_core` returns this value and prints nothing; the `fuzi` binary renders
/// it (human / `--json` / `--quiet`). Under `--json` the fields print as keys
/// sorted by name, not in declaration order (the binary renders through
/// `serde_json::Value`, whose map is ordered by key).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct InstallReport {
    /// Whether this is a `--dry-run` (no download, no `node_modules` written): the
    /// `fetched` / `placed` counts then read as "would fetch" / "would place".
    pub dry_run: bool,
    /// Unique tarballs already cached (re-verified, not re-downloaded).
    pub cached: usize,
    /// Unique tarballs downloaded + verified this run (would-fetch under dry-run).
    pub fetched: usize,
    /// Total bytes transferred for the `fetched` tarballs.
    pub fetched_bytes: u64,
    /// Packages extracted into `node_modules` (would-place under dry-run).
    pub placed: usize,
    /// Sibling `link: true` packages placed as symlinks (would-link under
    /// dry-run). Never fetched, extracted, or written into.
    pub linked: usize,
    /// `node_modules/.bin/<cmd>` symlinks created. Under dry-run, the count of
    /// *declared* bins that would be linked (an upper bound — a real run also
    /// skips any whose target file the tarball does not ship).
    pub bins_linked: usize,
    /// Declared bin links skipped because the target *file* is absent from the
    /// tarball — a benign package inconsistency (a malformed/escaping bin is
    /// refused upstream at classify, never reaching here) — or, for a linked
    /// package, is not an executable regular file reached through real
    /// directories: fuzi never chmods a link target, so a non-executable linked
    /// bin is skipped rather than fixed, and one that is a symlink (or sits
    /// under one) is skipped rather than followed.
    pub bins_skipped: usize,
    /// Optional packages skipped on host platform mismatch (informational).
    pub skipped_optional: usize,
    /// Distinct package names whose `install` scripts fuzi declined to run
    /// (a name present at multiple depths is listed once) — summarized loudly
    /// (one line), detail behind `--verbose`.
    pub skipped_scripts: Vec<String>,
    /// A non-fatal host-detection warning to surface loudly. Currently set only
    /// when the libc fs-probe found no loader, so libc is treated as
    /// unconstrained (a safe superset install). `None` in the common case; the
    /// binary renders it on stderr, and it is omitted from `--json` when absent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub libc_warning: Option<String>,
    /// Non-fatal link-target warnings — a linked package whose `package.json`
    /// `version` differs from (or is missing against) the lockfile's. The name
    /// matched (a name mismatch refuses), so the link is placed; the version is
    /// local source the user may be editing. Omitted from `--json` when empty.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub link_warnings: Vec<String>,
    /// Packages whose cached tarball failed re-verification and was discarded
    /// and refetched from the registry this run (each also counts in
    /// `fetched`), sorted. Under `--dry-run`, the ones a real run would
    /// discard and refetch — the entries themselves are left in place.
    ///
    /// The heal is what keeps the install correct — the CAS is
    /// content-addressed, so the registry's bytes are the truth — but a cached
    /// file that stopped matching its hash is local corruption or tampering, and
    /// must not be repaired silently. The binary prints one stderr warning per
    /// entry; the exit stays 0. Omitted from `--json` when empty.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub healed: Vec<String>,
    /// Lockfile entry fields fuzi neither models nor has reviewed as inert.
    ///
    /// Empty for every lockfile npm produces today. Non-empty means this lockfile
    /// carries a field fuzi parses into nothing — which is how `inBundle` went
    /// unmodeled through all of v0 — so it is surfaced loudly rather than
    /// refused: npm adding inert metadata must not break installs, but a field
    /// that might change what an entry *means* must not stay invisible. Omitted
    /// from `--json` when empty.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub unknown_entry_fields: Vec<String>,
}

impl InstallReport {
    /// Record one tarball's outcome.
    pub const fn record(&mut self, outcome: FetchOutcome) {
        match outcome {
            FetchOutcome::CacheHit => self.cached += 1,
            FetchOutcome::Fetched { bytes } => {
                self.fetched += 1;
                self.fetched_bytes = self.fetched_bytes.saturating_add(bytes);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(report: &InstallReport) -> Vec<String> {
        let serde_json::Value::Object(map) = serde_json::to_value(report).unwrap() else {
            panic!("an InstallReport serializes as an object");
        };
        map.into_iter().map(|(key, _)| key).collect()
    }

    /// The counts always serialize; the optional detail fields only when set,
    /// so a clean install's `--json` carries no empty warning lists.
    #[test]
    fn json_keys_omit_only_the_empty_detail_fields() {
        let always = [
            "bins_linked",
            "bins_skipped",
            "cached",
            "dry_run",
            "fetched",
            "fetched_bytes",
            "linked",
            "placed",
            "skipped_optional",
            "skipped_scripts",
        ];
        assert_eq!(keys(&InstallReport::default()), always);

        let full = InstallReport {
            libc_warning: Some("w".to_string()),
            link_warnings: vec!["l".to_string()],
            healed: vec!["h".to_string()],
            unknown_entry_fields: vec!["u".to_string()],
            ..InstallReport::default()
        };
        let mut expected: Vec<&str> = always.to_vec();
        expected.extend([
            "healed",
            "libc_warning",
            "link_warnings",
            "unknown_entry_fields",
        ]);
        expected.sort_unstable();
        assert_eq!(keys(&full), expected);
    }
}
