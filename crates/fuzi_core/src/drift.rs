//! Conservative `npm ci`-style drift check: string-compare the four declared
//! dependency maps (`dependencies` / `devDependencies` / `optionalDependencies`
//! / `peerDependencies`) on the on-disk `package.json` against the lockfile root
//! entry. Any difference is drift.
//!
//! The manifest side is read the way npm normalizes it before writing the
//! lock: a name in both `dependencies` and `optionalDependencies` is dropped
//! from `dependencies` (`@npmcli/package-json`'s `optionalDedupe` step), so
//! the lock root lists it only as optional. Comparing the raw manifest would
//! refuse every in-sync project that lists an optional dependency in both
//! maps, the pre-npm-7 convention.
//!
//! `overrides` is deliberately **not** compared. npm never writes `overrides`
//! into `package-lock.json` — not at the top level, not in `packages[""]` — so
//! there is nothing on the lock side to compare against, and a manifest that
//! declares `overrides` (a common npm feature) would always read as drift on a
//! freshly-generated, in-sync lock. The four declared dep maps are the drift
//! signal, matching `npm ci`: npm bakes the `overrides` result into resolved
//! versions rather than surfacing it as a comparable field, so dropping the
//! check loses no real drift detection.

use std::collections::BTreeMap;
use std::path::Path;

use serde_json::Value;

use crate::error::{FuziError, ProjectFile, read_project_file};
use crate::lockfile::raw::RawLockfile;

/// A human-readable list of every drift difference found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriftReport {
    /// One line per difference.
    pub diffs: Vec<String>,
}

/// Compare on-disk `package.json` against the lockfile root entry.
///
/// Reads `<dir>/package.json` (the only drift IO). Returns `Ok(None)` for no
/// drift, `Ok(Some(report))` when the manifest and lock disagree.
///
/// # Errors
///
/// Returns `FuziError::MissingInput` if there is no `package.json`,
/// `FuziError::Io` if it cannot be read (not a regular file, or over the read
/// cap — see `read_project_file`), or `FuziError::Lockfile` if it is not
/// valid JSON.
pub fn drift_check(dir: &Path, raw: &RawLockfile) -> Result<Option<DriftReport>, FuziError> {
    let text = read_project_file(dir, ProjectFile::Manifest)?;
    let manifest: Value = serde_json::from_str(&text).map_err(|e| FuziError::Lockfile {
        message: format!("package.json is not valid JSON: {e}"),
    })?;
    Ok(drift_against(&manifest, raw))
}

/// The pure comparison half of `drift_check` (exposed for tests).
#[must_use]
pub fn drift_against(manifest: &Value, raw: &RawLockfile) -> Option<DriftReport> {
    let mut diffs = Vec::new();

    let Some(root) = raw.packages.get("") else {
        // A lockfile with no root entry cannot back `npm ci`.
        return Some(DriftReport {
            diffs: vec!["lockfile has no root (\"\") packages entry".to_string()],
        });
    };

    compare_map(
        &mut diffs,
        "dependencies",
        manifest,
        root.dependencies.as_ref(),
    );
    compare_map(
        &mut diffs,
        "devDependencies",
        manifest,
        root.dev_dependencies.as_ref(),
    );
    compare_map(
        &mut diffs,
        "optionalDependencies",
        manifest,
        root.optional_dependencies.as_ref(),
    );
    compare_map(
        &mut diffs,
        "peerDependencies",
        manifest,
        root.peer_dependencies.as_ref(),
    );

    if diffs.is_empty() {
        None
    } else {
        Some(DriftReport { diffs })
    }
}

/// Compare one dependency map between manifest and lock as opaque
/// (name → range) string pairs. Version ranges stay opaque (no semver).
fn compare_map(
    diffs: &mut Vec<String>,
    field: &str,
    manifest: &Value,
    lock_map: Option<&BTreeMap<String, String>>,
) {
    let mut manifest_map = manifest_dep_map(manifest, field);
    if field == "dependencies" {
        // npm's `optionalDedupe`: every name `optionalDependencies` declares
        // (whatever its value) leaves `dependencies`. An emptied map reads as
        // absent, as npm deletes it — both compare equal to an absent lock map.
        if let Some(optional) = manifest
            .get("optionalDependencies")
            .and_then(Value::as_object)
        {
            manifest_map.retain(|name, _| !optional.contains_key(name));
        }
    }
    let empty = BTreeMap::new();
    let lock_map = lock_map.unwrap_or(&empty);

    // Keys present in the manifest but missing/different in the lock.
    for (name, range) in &manifest_map {
        match lock_map.get(name) {
            None => diffs.push(format!("{field}: `{name}` in package.json, missing from lockfile")),
            Some(lock_range) if lock_range != range => diffs.push(format!(
                "{field}: `{name}` range differs (package.json `{range}` vs lockfile `{lock_range}`)"
            )),
            Some(_) => {}
        }
    }
    // Keys present in the lock but missing from the manifest.
    for name in lock_map.keys() {
        if !manifest_map.contains_key(name) {
            diffs.push(format!(
                "{field}: `{name}` in lockfile, missing from package.json"
            ));
        }
    }
}

/// Pull a `package.json` dependency map as a `BTreeMap<String, String>`,
/// ignoring non-string values (defensive — a malformed entry just won't match).
fn manifest_dep_map(manifest: &Value, field: &str) -> BTreeMap<String, String> {
    manifest
        .get(field)
        .and_then(Value::as_object)
        .map(|obj| {
            obj.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // `root` is moved into the `json!` macro expansion, so it is consumed.
    #[allow(clippy::needless_pass_by_value)]
    fn lock_with_root(root: Value) -> RawLockfile {
        serde_json::from_value(json!({
            "lockfileVersion": 3,
            "packages": {"": root}
        }))
        .unwrap()
    }

    #[test]
    fn in_sync_no_drift() {
        let manifest = json!({"dependencies": {"a": "^1.0.0"}});
        let raw = lock_with_root(json!({"dependencies": {"a": "^1.0.0"}}));
        assert_eq!(drift_against(&manifest, &raw), None);
    }

    #[test]
    fn manifest_adds_dep_drifts() {
        let manifest = json!({"dependencies": {"a": "^1.0.0", "b": "^2.0.0"}});
        let raw = lock_with_root(json!({"dependencies": {"a": "^1.0.0"}}));
        let report = drift_against(&manifest, &raw).unwrap();
        assert!(report.diffs.iter().any(|d| d.contains('b')));
    }

    #[test]
    fn lock_has_dep_manifest_dropped_drifts() {
        let manifest = json!({"dependencies": {"a": "^1.0.0"}});
        let raw = lock_with_root(json!({"dependencies": {"a": "^1.0.0", "b": "^2.0.0"}}));
        let report = drift_against(&manifest, &raw).unwrap();
        assert!(
            report
                .diffs
                .iter()
                .any(|d| d.contains("missing from package.json"))
        );
    }

    #[test]
    fn differing_range_drifts() {
        let manifest = json!({"dependencies": {"a": "^1.0.0"}});
        let raw = lock_with_root(json!({"dependencies": {"a": "^1.1.0"}}));
        let report = drift_against(&manifest, &raw).unwrap();
        assert!(report.diffs.iter().any(|d| d.contains("range differs")));
    }

    #[test]
    fn peer_deps_not_exempt() {
        let manifest = json!({"peerDependencies": {"svelte": "^5.0.0"}});
        let raw = lock_with_root(json!({"peerDependencies": {"svelte": "^4.0.0"}}));
        assert!(drift_against(&manifest, &raw).is_some());
    }

    #[test]
    fn empty_dep_maps_are_not_drift() {
        let manifest = json!({"dependencies": {}});
        let raw = lock_with_root(json!({"dependencies": {}}));
        assert_eq!(drift_against(&manifest, &raw), None);
    }

    #[test]
    fn overrides_in_manifest_only_is_not_drift() {
        // The real npm shape: `overrides` is declared in package.json but npm
        // records nothing to compare against in the lock (not top-level, not
        // `packages[""]`). With the dep maps in sync this must NOT drift — the
        // regression guard for the false positive that refused any project
        // declaring `overrides` on a freshly-generated, in-sync lock.
        let manifest = json!({
            "dependencies": {"a": "^1.0.0"},
            "overrides": {"foo": "1.0.0"}
        });
        let raw = lock_with_root(json!({"dependencies": {"a": "^1.0.0"}}));
        assert_eq!(drift_against(&manifest, &raw), None);
    }

    #[test]
    fn accumulates_multiple_diffs() {
        let manifest = json!({"dependencies": {"a": "^1.0.0", "b": "^2.0.0"}});
        let raw = lock_with_root(json!({"dependencies": {"a": "^9.0.0"}}));
        let report = drift_against(&manifest, &raw).unwrap();
        assert!(report.diffs.len() >= 2);
    }

    #[test]
    fn dep_in_both_dependencies_and_optional_is_compared_as_optional() {
        // npm 11 on this manifest writes the root entry with `is-number` only
        // under `optionalDependencies` (`optionalDedupe`) — in sync, not drift.
        let manifest = json!({
            "dependencies": {"is-number": "^7.0.0", "is-odd": "^3.0.1"},
            "optionalDependencies": {"is-number": "^7.0.0"}
        });
        let raw = lock_with_root(json!({
            "dependencies": {"is-odd": "^3.0.1"},
            "optionalDependencies": {"is-number": "^7.0.0"}
        }));
        assert_eq!(drift_against(&manifest, &raw), None);
    }

    #[test]
    fn dedupe_that_empties_dependencies_reads_as_absent() {
        // The optional range wins even where the two differ; npm drops the
        // emptied `dependencies` from the lock root altogether.
        let manifest = json!({
            "dependencies": {"is-number": "^7.0.0"},
            "optionalDependencies": {"is-number": "^6.0.0"}
        });
        let raw = lock_with_root(json!({
            "optionalDependencies": {"is-number": "^6.0.0"}
        }));
        assert_eq!(drift_against(&manifest, &raw), None);
    }

    #[test]
    fn dedupe_only_drops_from_dependencies() {
        // A name the lock still lists under `dependencies` while the manifest
        // also marks it optional is real drift — the lock predates the move.
        let manifest = json!({
            "dependencies": {"a": "^1.0.0"},
            "optionalDependencies": {"a": "^1.0.0"}
        });
        let raw = lock_with_root(json!({
            "dependencies": {"a": "^1.0.0"},
            "optionalDependencies": {"a": "^1.0.0"}
        }));
        let report = drift_against(&manifest, &raw).unwrap();
        assert_eq!(
            report.diffs,
            vec!["dependencies: `a` in lockfile, missing from package.json"]
        );
    }

    #[test]
    fn non_string_dep_value_degrades_to_drift() {
        // A manifest range that is not a string can't match the lock's string:
        // the entry reads as absent from package.json, so a lock carrying it
        // drifts (fail-loud), never a silent match.
        let manifest = json!({"dependencies": {"a": 1, "b": "^2.0.0"}});
        let raw = lock_with_root(json!({"dependencies": {"a": "1", "b": "^2.0.0"}}));
        let report = drift_against(&manifest, &raw).unwrap();
        assert_eq!(
            report.diffs,
            vec!["dependencies: `a` in lockfile, missing from package.json"]
        );
    }

    #[test]
    fn non_object_dependencies_value_degrades_to_drift() {
        // A malformed `dependencies` that isn't an object reads as empty, so a
        // lock carrying real deps surfaces as drift (fail-loud), not a silent match.
        let manifest = json!({"dependencies": "oops"});
        let raw = lock_with_root(json!({"dependencies": {"a": "^1.0.0"}}));
        assert!(drift_against(&manifest, &raw).is_some());
    }

    #[test]
    fn missing_manifest_is_missing_input() {
        let dir = tempfile::tempdir().unwrap();
        let raw = lock_with_root(json!({}));
        let err = drift_check(dir.path(), &raw).unwrap_err();
        assert!(
            matches!(
                err,
                FuziError::MissingInput {
                    file: ProjectFile::Manifest,
                    ..
                }
            ),
            "{err:?}"
        );
        assert_eq!(err.exit_code(), 66);
        assert!(err.to_string().contains("--ignore-manifest"), "{err}");
    }

    #[test]
    fn no_root_entry_is_drift() {
        let raw: RawLockfile =
            serde_json::from_value(json!({"lockfileVersion": 3, "packages": {}})).unwrap();
        let manifest = json!({});
        assert!(drift_against(&manifest, &raw).is_some());
    }
}
