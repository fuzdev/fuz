//! Remote release retention — the pure "which published versions to prune"
//! decision.
//!
//! Read-only + pure; listing and the delete execution live producer-side in
//! `fuz_sign::prune` so the delete-capable flow stays out of the consumer `fuz`
//! graph. A [`RemoteRelease`] is one published version+target (its manifest key
//! plus the tarball key the manifest points at); [`select_prune_releases`]
//! chooses which to remove.

use std::collections::HashSet;

/// One published release artifact on storage.
///
/// A specific version for a specific target, with the two keys that make it up.
#[derive(Debug, Clone)]
pub struct RemoteRelease {
    /// The release's semver version (from the signed manifest, authoritative —
    /// not parsed from the filename, which is ambiguous across semver-prerelease
    /// and target-triple hyphens).
    pub version: semver::Version,
    /// The target triple this manifest is for.
    pub target: String,
    /// Storage key of the manifest.
    pub manifest_key: String,
    /// Storage key of the tarball (the manifest's `tarball.path` under the
    /// stream prefix).
    pub tarball_key: String,
}

/// Select which releases to prune.
///
/// Keeps the `keep` most-recent *versions* (by semver, counted across all
/// targets), always keeps every `protected` version (the ones the stream's
/// per-target `latest-<target>.json` pointers name), and returns every release
/// belonging to an older/unprotected version.
///
/// Retention is by **version**, not by artifact — keeping 5 versions keeps every
/// target of those 5. A `protected` version is kept even if it falls outside
/// the top `keep` (a pointer naming an old version — one target's latest,
/// behind another's — is never pruned out from under itself).
#[must_use]
pub fn select_prune_releases<'a>(
    releases: &'a [RemoteRelease],
    keep: usize,
    protected: &[semver::Version],
) -> Vec<&'a RemoteRelease> {
    // Distinct versions, newest first.
    let mut versions: Vec<&semver::Version> = releases.iter().map(|r| &r.version).collect();
    versions.sort_unstable();
    versions.dedup();
    versions.reverse();

    // The versions we keep: the newest `keep`, plus the protected ones.
    let mut kept: HashSet<&semver::Version> = versions.into_iter().take(keep).collect();
    kept.extend(protected);

    releases
        .iter()
        .filter(|r| !kept.contains(&r.version))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn release(version: &str, target: &str) -> RemoteRelease {
        RemoteRelease {
            version: semver::Version::parse(version).unwrap(),
            target: target.to_string(),
            manifest_key: format!("{version}-{target}.manifest.json"),
            tarball_key: format!("{version}-{target}.tar.gz"),
        }
    }

    fn pruned_versions(pruned: &[&RemoteRelease]) -> Vec<String> {
        let mut v: Vec<String> = pruned.iter().map(|r| r.version.to_string()).collect();
        v.sort();
        v.dedup();
        v
    }

    #[test]
    fn keeps_newest_n_versions() {
        let releases = [
            release("0.1.0", "t"),
            release("0.2.0", "t"),
            release("0.3.0", "t"),
            release("0.4.0", "t"),
        ];
        let pruned = select_prune_releases(&releases, 2, &[]);
        // Keep 0.4.0 + 0.3.0; prune 0.2.0 + 0.1.0.
        assert_eq!(pruned_versions(&pruned), vec!["0.1.0", "0.2.0"]);
    }

    #[test]
    fn retention_is_by_version_across_targets() {
        let releases = [
            release("0.1.0", "linux"),
            release("0.1.0", "macos"),
            release("0.2.0", "linux"),
            release("0.2.0", "macos"),
        ];
        // Keep 1 version → keep both targets of 0.2.0, prune both of 0.1.0.
        let pruned = select_prune_releases(&releases, 1, &[]);
        assert_eq!(pruned.len(), 2, "both 0.1.0 targets pruned");
        assert!(pruned.iter().all(|r| r.version.to_string() == "0.1.0"));
    }

    #[test]
    fn protected_version_is_never_pruned() {
        let releases = [
            release("0.1.0", "t"),
            release("0.2.0", "t"),
            release("0.3.0", "t"),
        ];
        let protected = semver::Version::parse("0.1.0").unwrap();
        // Keep only 1 (0.3.0), but 0.1.0 is protected → only 0.2.0 is pruned.
        let pruned = select_prune_releases(&releases, 1, std::slice::from_ref(&protected));
        assert_eq!(pruned_versions(&pruned), vec!["0.2.0"]);
    }

    /// Each target's latest is protected: two pointers naming two old
    /// versions keep both.
    #[test]
    fn every_protected_version_is_kept() {
        let releases = [
            release("0.1.0", "a"),
            release("0.2.0", "b"),
            release("0.3.0", "a"),
            release("0.4.0", "a"),
        ];
        let protected = [
            semver::Version::parse("0.1.0").unwrap(),
            semver::Version::parse("0.2.0").unwrap(),
        ];
        let pruned = select_prune_releases(&releases, 1, &protected);
        assert_eq!(pruned_versions(&pruned), vec!["0.3.0"]);
    }

    #[test]
    fn keep_at_or_above_count_prunes_nothing() {
        let releases = [release("0.1.0", "t"), release("0.2.0", "t")];
        assert!(select_prune_releases(&releases, 2, &[]).is_empty());
        assert!(select_prune_releases(&releases, 5, &[]).is_empty());
    }

    #[test]
    fn semver_ordering_not_lexicographic() {
        // 0.10.0 > 0.9.0 by semver (lexicographic would get this wrong).
        let releases = [
            release("0.9.0", "t"),
            release("0.10.0", "t"),
            release("0.2.0", "t"),
        ];
        let pruned = select_prune_releases(&releases, 1, &[]);
        // Newest is 0.10.0; prune 0.9.0 + 0.2.0.
        assert_eq!(pruned_versions(&pruned), vec!["0.2.0", "0.9.0"]);
    }
}
