//! The `InstallPlan` — fuzi's central, format-agnostic output (the pnpm-reader
//! seam is *this type*, not a reader trait) — and the orchestration that
//! assembles it from a parsed lockfile.

use std::collections::BTreeMap;

use crate::classify::{EntryDisposition, classify};
use crate::drift::drift_check;
use crate::entry::{BinCommand, BinTarget, InstallPath, Integrity, LinkTarget};
use crate::error::FuziError;
use crate::lockfile::raw::RawLockfile;
use crate::platform::Platform;
use crate::{InstallOptions, Omit};

/// What to fetch for one unique tarball.
///
/// Just the `resolved` URL: the fetch phase verifies bytes against the
/// `Integrity` key (not this) and reports skipped scripts from
/// `InstallPlan::skipped_scripts` (keyed by install path), so the per-tarball
/// `hasInstallScript` bool is dead here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchInfo {
    /// The `https://` tarball URL.
    pub resolved: String,
}

/// One package to materialize: extract the tarball keyed by `integrity` into
/// `path`, then link its `bins` into the enclosing `node_modules/.bin`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackagePlacement {
    /// Where the package's tree lands (a `node_modules/…` key).
    pub path: InstallPath,
    /// The locked `version` (used by `fuzi verify`; `None` if the lock omitted it).
    pub version: Option<String>,
    /// Which unique tarball supplies it (the `fetch_set` key).
    pub integrity: Integrity,
    /// Validated `command → in-package target` bins (parsed at classify time, so
    /// every pair is chmod/symlink-safe). Empty when the package ships no binaries.
    pub bins: BTreeMap<BinCommand, BinTarget>,
}

/// One symlink to place: `path` → the sibling directory `target`, plus the
/// target's bins to link through it.
///
/// Never fetched or extracted, and never written *into*: materialization creates
/// the symlink after every extraction has finished, and links the bins only when
/// the target file is already executable (it never chmods outside the project).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkPlacement {
    /// Where the symlink lands (a depth-1 `node_modules/…` key).
    pub path: InstallPath,
    /// The validated sibling directory it points at.
    pub target: LinkTarget,
    /// The target entry's `name`, or `None` when npm omitted it as equal to its
    /// folder default (resolved by the link-target check).
    pub name: Option<String>,
    /// The target entry's `version` (a mismatch warns).
    pub version: Option<String>,
    /// Validated bins from the target entry.
    pub bins: BTreeMap<BinCommand, BinTarget>,
}

/// The dedup-by-integrity fetch list plus the depth-sorted placement list.
///
/// Both are deterministic. The remaining fields are not instructions but
/// observations worth *reporting* about the lockfile this was built from — what
/// was skipped, whose install scripts will not run, which entry fields fuzi does
/// not model. They ride here because `build_plan` is the one pass that reads
/// every entry.
#[derive(Debug, Clone, Default)]
pub struct InstallPlan {
    /// Dedup by integrity: fetch each unique tarball once.
    pub fetch_set: BTreeMap<Integrity, FetchInfo>,
    /// Place many, sorted parent-before-child by `InstallPath::depth` (stable
    /// sort — no topo-sort).
    pub placements: Vec<PackagePlacement>,
    /// Sibling links to place, in lockfile-key order. Never in `fetch_set` or
    /// `placements`: a link has no tarball and no extraction.
    pub links: Vec<LinkPlacement>,
    /// Optional entries skipped on platform mismatch (informational).
    pub skipped: Vec<InstallPath>,
    /// `hasInstallScript` package paths whose scripts fuzi will NOT run.
    pub skipped_scripts: Vec<InstallPath>,
    /// Lockfile entry fields fuzi neither models nor has reviewed as inert —
    /// deduped, sorted. Empty for every lockfile npm produces today; non-empty
    /// means the schema moved under fuzi (see `lockfile::unknown_entry_fields`).
    pub unknown_entry_fields: Vec<String>,
}

/// Build an `InstallPlan` from an already-parsed lockfile.
///
/// Classifies every entry (host-filtered, `omit`-applied), assembles the fetch +
/// placement sets, and returns `FuziError::Refused` if any entry was refused.
/// Drift is checked separately (it needs the project dir); see
/// `build_plan_with_drift`.
///
/// Takes the `omit` set directly rather than an `InstallOptions`: the plan is a
/// pure function of (lockfile, host, omit), and the install-mode switches
/// (`dir` / `dry_run` / `offline` / `ignore_manifest`) mean nothing here. That
/// keeps non-install callers (`fuzi verify`) honest — they pass their own omit
/// set instead of fabricating an options struct whose other fields are lies.
///
/// # Errors
///
/// Returns `FuziError::Refused` if `classify` produced any refusals.
pub fn build_plan(
    raw: &RawLockfile,
    host: &Platform,
    omit: &[Omit],
) -> Result<InstallPlan, FuziError> {
    let (dispositions, refusals) = classify(raw, host, omit);
    if !refusals.is_empty() {
        return Err(FuziError::Refused { refusals });
    }
    let mut plan = assemble(dispositions);
    plan.unknown_entry_fields = crate::lockfile::unknown_entry_fields(raw);
    Ok(plan)
}

/// Drift-check + classify + assemble an already-read lockfile.
///
/// The lockfile is read and version-gated by the caller (`read_lockfile`);
/// this reads only `options.dir`'s `package.json`, for the drift guard — and
/// not even that under `ignore_manifest` — then builds the plan as
/// [`build_plan`] does, under `options.omit`.
///
/// # Errors
///
/// Returns `FuziError::MissingInput`/`FuziError::Io` when `package.json`
/// cannot be read, `FuziError::Lockfile` when it cannot be parsed,
/// `FuziError::Drift` on manifest↔lock drift, and `FuziError::Refused` on any
/// classify refusal.
pub fn build_plan_with_drift(
    raw: &RawLockfile,
    host: &Platform,
    options: &InstallOptions,
) -> Result<InstallPlan, FuziError> {
    if !options.ignore_manifest
        && let Some(report) = drift_check(&options.dir, raw)?
    {
        // Drift is its own EX_DATAERR variant (kind "drift" in --json) so an agent
        // can branch it apart from a malformed/unsupported `Lockfile`.
        return Err(FuziError::Drift {
            diffs: report.diffs,
        });
    }
    build_plan(raw, host, &options.omit)
}

/// Assemble dispositions into a plan. Pure.
fn assemble(dispositions: Vec<EntryDisposition>) -> InstallPlan {
    let mut plan = InstallPlan::default();
    for disposition in dispositions {
        match disposition {
            EntryDisposition::Install(entry) => {
                let integrity = entry.integrity.clone();
                plan.fetch_set
                    .entry(integrity.clone())
                    .or_insert_with(|| FetchInfo {
                        resolved: entry.resolved.clone(),
                    });
                if entry.has_install_script {
                    plan.skipped_scripts.push(entry.path.clone());
                }
                plan.placements.push(PackagePlacement {
                    path: entry.path,
                    version: entry.version,
                    integrity,
                    bins: entry.bins,
                });
            }
            EntryDisposition::Link(link) => {
                if link.has_install_script {
                    plan.skipped_scripts.push(link.path.clone());
                }
                plan.links.push(LinkPlacement {
                    path: link.path,
                    target: link.target,
                    name: link.name,
                    version: link.version,
                    bins: link.bins,
                });
            }
            EntryDisposition::SkipOptionalMismatch(path) => plan.skipped.push(path),
            EntryDisposition::Omitted(_) | EntryDisposition::Skip(_) => {}
        }
    }
    // Stable sort, parent-before-child by depth.
    plan.placements.sort_by_key(|p| p.path.depth());
    plan
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{host_linux_x64_glibc, sha512_sri};
    use serde_json::json;

    /// The default (empty) omit set — most plan tests exercise the full tree.
    const NO_OMIT: &[Omit] = &[];

    fn raw_from(value: serde_json::Value) -> RawLockfile {
        serde_json::from_value(value).unwrap()
    }

    #[test]
    fn one_tarball_two_paths_dedups() {
        // Same integrity at two install paths.
        let integrity = sha512_sri(b"shared");
        let raw = raw_from(json!({
            "lockfileVersion": 3,
            "packages": {
                "node_modules/a": {
                    "resolved": "https://registry.npmjs.org/shared/-/shared-1.0.0.tgz",
                    "integrity": integrity
                },
                "node_modules/b/node_modules/shared": {
                    "resolved": "https://registry.npmjs.org/shared/-/shared-1.0.0.tgz",
                    "integrity": integrity
                }
            }
        }));
        let plan = build_plan(&raw, &host_linux_x64_glibc(), NO_OMIT).unwrap();
        assert_eq!(plan.fetch_set.len(), 1);
        assert_eq!(plan.placements.len(), 2);
    }

    #[test]
    fn lock_with_only_root_is_empty_plan() {
        // A project with no dependencies — the root entry is skipped, nothing to
        // fetch or place. Must not error or fabricate placements.
        let raw = raw_from(json!({
            "lockfileVersion": 3,
            "packages": {"": {"name": "solo"}}
        }));
        let plan = build_plan(&raw, &host_linux_x64_glibc(), NO_OMIT).unwrap();
        assert!(plan.placements.is_empty());
        assert!(plan.fetch_set.is_empty());
    }

    #[test]
    fn placements_sorted_parent_before_child() {
        let raw = raw_from(json!({
            "lockfileVersion": 3,
            "packages": {
                "node_modules/parent/node_modules/child": {
                    "resolved": "https://registry.npmjs.org/child/-/child-1.0.0.tgz",
                    "integrity": sha512_sri(b"child")
                },
                "node_modules/parent": {
                    "resolved": "https://registry.npmjs.org/parent/-/parent-1.0.0.tgz",
                    "integrity": sha512_sri(b"parent")
                }
            }
        }));
        let plan = build_plan(&raw, &host_linux_x64_glibc(), NO_OMIT).unwrap();
        // Depth-1 parent must precede the depth-2 child.
        assert_eq!(plan.placements[0].path.depth(), 1);
        assert_eq!(plan.placements[1].path.depth(), 2);
    }

    #[test]
    fn clean_plan_ok_refusal_errs() {
        let clean = raw_from(json!({
            "lockfileVersion": 3,
            "packages": {
                "node_modules/a": {
                    "resolved": "https://registry.npmjs.org/a/-/a-1.0.0.tgz",
                    "integrity": sha512_sri(b"a")
                }
            }
        }));
        assert!(build_plan(&clean, &host_linux_x64_glibc(), NO_OMIT).is_ok());

        let dirty = raw_from(json!({
            "lockfileVersion": 3,
            "packages": {
                "node_modules/g": {"resolved": "git+https://x/y.git", "integrity": sha512_sri(b"g")}
            }
        }));
        assert!(matches!(
            build_plan(&dirty, &host_linux_x64_glibc(), NO_OMIT),
            Err(FuziError::Refused { .. })
        ));
    }

    #[test]
    fn bin_object_normalized_into_placement() {
        let raw = raw_from(json!({
            "lockfileVersion": 3,
            "packages": {
                "node_modules/esbuild": {
                    "resolved": "https://registry.npmjs.org/esbuild/-/esbuild-0.20.0.tgz",
                    "integrity": sha512_sri(b"esbuild"),
                    "bin": {"esbuild": "bin/esbuild"}
                }
            }
        }));
        let plan = build_plan(&raw, &host_linux_x64_glibc(), NO_OMIT).unwrap();
        assert_eq!(plan.placements.len(), 1);
        assert_eq!(
            plan.placements[0]
                .bins
                .get(&BinCommand::parse("esbuild").unwrap())
                .map(BinTarget::as_str),
            Some("bin/esbuild")
        );
    }

    #[test]
    fn bin_string_uses_unscoped_name() {
        // The bare-string form: command = the unscoped package name.
        let raw = raw_from(json!({
            "lockfileVersion": 3,
            "packages": {
                "node_modules/@scope/cli": {
                    "resolved": "https://registry.npmjs.org/@scope/cli/-/cli-1.0.0.tgz",
                    "integrity": sha512_sri(b"cli"),
                    "bin": "dist/run.js"
                }
            }
        }));
        let plan = build_plan(&raw, &host_linux_x64_glibc(), NO_OMIT).unwrap();
        assert_eq!(
            plan.placements[0]
                .bins
                .get(&BinCommand::parse("cli").unwrap())
                .map(BinTarget::as_str),
            Some("dist/run.js")
        );
    }

    #[test]
    fn install_script_entries_collected() {
        let raw = raw_from(json!({
            "lockfileVersion": 3,
            "packages": {
                "node_modules/esbuild": {
                    "resolved": "https://registry.npmjs.org/esbuild/-/esbuild-0.20.0.tgz",
                    "integrity": sha512_sri(b"esbuild"),
                    "hasInstallScript": true
                }
            }
        }));
        let plan = build_plan(&raw, &host_linux_x64_glibc(), NO_OMIT).unwrap();
        assert_eq!(plan.skipped_scripts.len(), 1);
    }

    #[test]
    fn optional_mismatch_collected_not_placed() {
        let raw = raw_from(json!({
            "lockfileVersion": 3,
            "packages": {
                "node_modules/@esbuild/darwin-x64": {
                    "resolved": "https://registry.npmjs.org/@esbuild/darwin-x64/-/darwin-x64-0.20.0.tgz",
                    "integrity": sha512_sri(b"darwin"),
                    "os": ["darwin"],
                    "cpu": ["x64"],
                    "optional": true
                }
            }
        }));
        let plan = build_plan(&raw, &host_linux_x64_glibc(), NO_OMIT).unwrap();
        assert_eq!(plan.skipped.len(), 1);
        assert!(plan.placements.is_empty());
    }

    /// A sibling-link lockfile: a registry dep beside a dev link to `../lib`.
    fn link_lock(target: serde_json::Value) -> RawLockfile {
        let mut lock = json!({
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "app"},
                "node_modules/a": {
                    "resolved": "https://registry.npmjs.org/a/-/a-1.0.0.tgz",
                    "integrity": sha512_sri(b"a")
                },
                "node_modules/lib": {"resolved": "../lib", "link": true}
            }
        });
        lock["packages"]["../lib"] = target;
        raw_from(lock)
    }

    #[test]
    fn links_are_planned_apart_from_fetch_and_placements() {
        let raw = link_lock(json!({"name": "lib", "version": "1.0.0", "dev": true}));
        let plan = build_plan(&raw, &host_linux_x64_glibc(), NO_OMIT).unwrap();
        assert_eq!(plan.links.len(), 1);
        assert_eq!(plan.links[0].path.as_str(), "node_modules/lib");
        assert_eq!(plan.links[0].name.as_deref(), Some("lib"));
        // Only the registry dep is fetched and extracted.
        assert_eq!(plan.fetch_set.len(), 1);
        assert_eq!(plan.placements.len(), 1);
        assert_eq!(plan.placements[0].path.as_str(), "node_modules/a");
    }

    #[test]
    fn omitted_link_is_dropped_from_the_plan() {
        let raw = link_lock(json!({"name": "lib", "dev": true}));
        let plan = build_plan(&raw, &host_linux_x64_glibc(), &[Omit::Dev]).unwrap();
        assert!(plan.links.is_empty());
        assert_eq!(plan.placements.len(), 1);
    }

    #[test]
    fn link_target_install_script_is_reported_not_run() {
        let raw = link_lock(json!({"name": "lib", "hasInstallScript": true}));
        let plan = build_plan(&raw, &host_linux_x64_glibc(), NO_OMIT).unwrap();
        assert_eq!(plan.skipped_scripts.len(), 1);
        assert_eq!(plan.skipped_scripts[0].as_str(), "node_modules/lib");
    }

    #[test]
    fn end_to_end_trimmed_gro_subtree() {
        // A trimmed real gro lock subtree: a prod dep, esbuild + two platform
        // optionals (one matching the host, one not), and the root entry.
        let raw = raw_from(json!({
            "lockfileVersion": 3,
            "packages": {
                "": {
                    "name": "gro",
                    "dependencies": {"esbuild": "^0.20.0"}
                },
                "node_modules/esbuild": {
                    "resolved": "https://registry.npmjs.org/esbuild/-/esbuild-0.20.0.tgz",
                    "integrity": sha512_sri(b"esbuild"),
                    "hasInstallScript": true,
                    "optionalDependencies": {
                        "@esbuild/linux-x64": "0.20.0",
                        "@esbuild/darwin-x64": "0.20.0"
                    }
                },
                "node_modules/@esbuild/linux-x64": {
                    "resolved": "https://registry.npmjs.org/@esbuild/linux-x64/-/linux-x64-0.20.0.tgz",
                    "integrity": sha512_sri(b"linux-x64"),
                    "cpu": ["x64"],
                    "os": ["linux"],
                    "optional": true
                },
                "node_modules/@esbuild/darwin-x64": {
                    "resolved": "https://registry.npmjs.org/@esbuild/darwin-x64/-/darwin-x64-0.20.0.tgz",
                    "integrity": sha512_sri(b"darwin-x64"),
                    "cpu": ["x64"],
                    "os": ["darwin"],
                    "optional": true
                },
                "node_modules/prod-dep": {
                    "resolved": "https://registry.npmjs.org/prod-dep/-/prod-dep-1.0.0.tgz",
                    "integrity": sha512_sri(b"prod")
                }
            }
        }));
        let plan = build_plan(&raw, &host_linux_x64_glibc(), NO_OMIT).unwrap();
        // Installed: esbuild + @esbuild/linux-x64 + prod-dep = 3 placements.
        assert_eq!(plan.placements.len(), 3);
        assert_eq!(plan.fetch_set.len(), 3);
        // darwin optional skipped on this linux host.
        assert_eq!(plan.skipped.len(), 1);
        assert_eq!(plan.skipped[0].as_str(), "node_modules/@esbuild/darwin-x64");
        // esbuild's install script reported.
        assert_eq!(plan.skipped_scripts.len(), 1);
        assert_eq!(plan.skipped_scripts[0].as_str(), "node_modules/esbuild");
    }
}
