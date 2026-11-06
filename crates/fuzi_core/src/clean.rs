//! `fuzi clean` — sweep crash-leaked staging artifacts from a project.
//!
//! A `fuzi install` that is interrupted mid-run can leave a
//! `.fuzi-installing-<rand>` staging tree or a `.fuzi-old-<rand>` displaced tree
//! beside `node_modules`. A normal return (success *or* an `Err` unwound to the
//! CLI) removes them — the [`StagingTree`](crate::staging::StagingTree) cleanup
//! guard fires on drop and the swap deletes the displaced tree. But `Drop` runs
//! only on an unwound return, so anything that ends the process without unwinding
//! would leave the artifacts behind.
//!
//! `SIGINT` (Ctrl-C), `SIGTERM`, and `SIGHUP` are handled: the `fuzi` binary's signal
//! listener drains the live staging roots
//! ([`drain_staging_roots`](crate::drain_staging_roots)) before exiting
//! `128 + signum` — see `crate::interrupt` for the registry and the swap race
//! it resolves. That leaves the exits nothing in-process can catch: **`SIGKILL`,
//! power loss, and — in release builds — *any* panic** (the workspace sets
//! `panic = "abort"`, so a panic terminates without running destructors). The
//! drain is also best effort: a tree it can't empty before its deadline
//! survives an interrupt too. fuzi deliberately does
//! **not** sweep at install startup (that would race a concurrent install in the
//! same project), so this stays the explicit, opt-in reaper for all of it.
//!
//! **Not while an install runs.** `clean` has no way to tell a crash-leaked
//! `.fuzi-installing-*` from the live staging tree of an install running in
//! another terminal, and sweeps both. The install usually notices — it refuses
//! to publish a tree missing a package, a shipped `package.json`, a link, or a
//! `.bin` link, and exits 75 ([`FuziError::StagingIncomplete`]) with
//! `node_modules` unchanged — but its work is lost, and two cases still get
//! through: a sweep landing in the instant before the publish rename, and one
//! that stops part-way and leaves a package missing files (files within a
//! package are not checked). The planned project-level install lock, which
//! `clean` would honor, is the real fix; until then, run `clean` only when no
//! install is running in the project.
//!
//! Scope: **project staging artifacts only.** `clean` never touches the shared
//! tarball CAS at `~/.fuz/cache/npm/` — cache eviction is a distinct concern
//! (the planned `fuzi cache prune`).

use std::io;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::error::{FuziError, NodeModulesObstruction, io_err};

/// Prefix of a crash-leaked staging tree (mirrors `crate::staging`'s
/// `STAGING_PREFIX`) — never anything but fuzi's scratch, always swept.
const STAGING_PREFIX: &str = ".fuzi-installing-";

/// Prefix of a displaced tree (mirrors `crate::staging`'s `OLD_PREFIX`) — the
/// previous `node_modules`, parked by the swap's first rename.
const OLD_PREFIX: &str = ".fuzi-old-";

/// The tree a displaced `.fuzi-old-*` is restored to.
const NODE_MODULES: &str = "node_modules";

/// What [`clean`] removed — or, under `dry_run`, would remove — and what it
/// deliberately kept.
///
/// `fuzi_core` returns this; the `fuzi` binary renders it (human / `--json`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct CleanReport {
    /// Whether this was a `--dry-run` (nothing removed; `removed` lists what
    /// *would* be).
    pub dry_run: bool,
    /// The swept (or would-sweep) artifact names, relative to the project dir, in
    /// deterministic order.
    pub removed: Vec<String>,
    /// `.fuzi-old-*` trees kept because `node_modules` is not a directory —
    /// each may be the user's only copy of their tree (see [`clean`]), in
    /// deterministic order.
    pub skipped: Vec<SkippedArtifact>,
    /// What occupies `node_modules` when it is there but not a directory (a
    /// symlink, or a file) — the obstruction a restore has to move aside
    /// first. Omitted from `--json` when `node_modules` is absent or a
    /// directory.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_modules_obstruction: Option<NodeModulesObstruction>,
}

/// A `.fuzi-old-*` tree [`clean`] refused to delete, with how to put it back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SkippedArtifact {
    /// The kept artifact's name, relative to the project dir.
    pub name: String,
    /// A POSIX shell command, run in the project dir, that restores it as
    /// `node_modules` (the name single-quoted for `sh`). Guarded by
    /// `[ -e node_modules ] ||`, so it does nothing once a `node_modules`
    /// exists — running a second tree's command can't nest it inside the first.
    pub restore_command: String,
}

/// Sweep crash-leaked `.fuzi-installing-*` / `.fuzi-old-*` entries from
/// `project_dir`. With `dry_run`, lists them without removing.
///
/// Entries are matched by prefix and removed with `symlink_metadata` (no-follow),
/// so a `.fuzi-*` symlink is unlinked rather than followed into its target.
///
/// **A `.fuzi-old-*` tree is swept only beside a real `node_modules`
/// directory.** The swap renames the live `node_modules` aside *before*
/// publishing the staging tree, so a process killed between the two renames
/// (or a swap whose restore also failed) leaves the user's tree parked under
/// that name with nothing in its place — deleting it would destroy their only
/// copy. A `node_modules` directory (what a finished swap publishes) means the
/// parked trees are stale, and they are swept. Any other form keeps them:
/// absent, or something else in the place — a symlink (dangling or not) or a
/// file, which a fuzi swap never publishes, so it says nothing about whether
/// the parked tree has a successor; [`CleanReport::node_modules_obstruction`]
/// names it so the restore can say to move it aside first. A kept tree is
/// reported in [`CleanReport::skipped`] with its restore command and never
/// restored automatically: which tree should come back is the user's call
/// (there may be several), and a reaper that silently renames is a surprise.
///
/// An entry that vanishes between the listing and its removal (a concurrent
/// clean, or an install's own cleanup getting there first) counts as removed,
/// and the sweep continues.
///
/// **Must not run during an install in the same project**: a live staging
/// tree looks exactly like a leaked one and is swept too (see the module docs).
///
/// # Errors
///
/// [`FuziError::Io`] if the project directory cannot be read, what
/// `node_modules` is cannot be determined, or an entry cannot be removed.
pub fn clean(project_dir: &Path, dry_run: bool) -> Result<CleanReport, FuziError> {
    let entries =
        std::fs::read_dir(project_dir).map_err(io_err("read project directory for clean"))?;

    // Collect first (deterministic order), then act — so the report is stable and
    // independent of readdir order.
    let mut targets: Vec<(String, PathBuf)> = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with(STAGING_PREFIX) || name.starts_with(OLD_PREFIX) {
            targets.push((name, entry.path()));
        }
    }
    targets.sort_by(|a, b| a.0.cmp(&b.0));

    // Asked once, after the listing, without following a symlink: an
    // unknowable answer refuses the sweep rather than guessing that a
    // displaced tree is safe to delete.
    let (node_modules_is_dir, node_modules_obstruction) =
        match std::fs::symlink_metadata(project_dir.join(NODE_MODULES)) {
            Ok(meta) if meta.is_dir() => (true, None),
            Ok(meta) if meta.file_type().is_symlink() => {
                (false, Some(NodeModulesObstruction::Symlink))
            }
            Ok(_) => (false, Some(NodeModulesObstruction::File)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => (false, None),
            Err(e) => return Err(io_err("check node_modules before clean")(e)),
        };

    let mut report = CleanReport {
        dry_run,
        node_modules_obstruction,
        ..CleanReport::default()
    };
    for (name, path) in targets {
        if !node_modules_is_dir && name.starts_with(OLD_PREFIX) {
            report.skipped.push(SkippedArtifact {
                restore_command: restore_command(&name),
                name,
            });
            continue;
        }
        if !dry_run {
            remove_artifact(&path)?;
        }
        report.removed.push(name);
    }
    Ok(report)
}

/// The POSIX command that puts the parked tree `name` back as `node_modules` —
/// and does nothing when a `node_modules` already exists, where `mv` would
/// move the tree *into* that directory instead of replacing it.
fn restore_command(name: &str) -> String {
    format!(
        "[ -e {NODE_MODULES} ] || mv -- {} {NODE_MODULES}",
        sh_single_quote(name)
    )
}

/// `text` as one `sh` word: single-quoted, each `'` closed, escaped, reopened.
fn sh_single_quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', "'\\''"))
}

/// Remove a swept artifact, choosing `remove_dir_all` vs `remove_file` by a
/// no-follow stat (a staging tree is a directory; a stray symlink is unlinked,
/// not followed).
///
/// Already gone — at the stat or at the removal — is success: the goal is
/// absence, and someone else reached it first.
fn remove_artifact(path: &Path) -> Result<(), FuziError> {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(io_err("stat clean target")(e)),
    };
    let result = if meta.is_dir() {
        std::fs::remove_dir_all(path)
    } else {
        std::fs::remove_file(path)
    };
    match result {
        Err(e) if e.kind() != io::ErrorKind::NotFound => Err(io_err("remove clean target")(e)),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::tree_listing;
    use std::fs;
    use std::os::unix::fs::symlink;
    use tempfile::TempDir;

    #[test]
    fn sweeps_staging_and_old_dirs_leaving_node_modules() {
        let project = TempDir::new().unwrap();
        let p = project.path();
        fs::create_dir(p.join(".fuzi-installing-abc123")).unwrap();
        fs::create_dir(p.join(".fuzi-old-def456")).unwrap();
        fs::create_dir(p.join("node_modules")).unwrap();
        fs::write(p.join("package.json"), b"{}").unwrap();

        let report = clean(p, false).unwrap();
        assert_eq!(
            report.removed,
            vec![
                ".fuzi-installing-abc123".to_string(),
                ".fuzi-old-def456".to_string()
            ]
        );
        assert!(!p.join(".fuzi-installing-abc123").exists());
        assert!(!p.join(".fuzi-old-def456").exists());
        // Real project contents are untouched.
        assert!(p.join("node_modules").is_dir());
        assert!(p.join("package.json").is_file());
    }

    #[test]
    fn displaced_tree_is_kept_when_node_modules_is_absent() {
        // Killed between the swap's two renames: the user's tree is parked at
        // `.fuzi-old-*` with no `node_modules`. Deleting it would destroy their
        // only copy, so it is kept with a restore command — while the staging
        // scratch beside it is still swept.
        let project = TempDir::new().unwrap();
        let p = project.path();
        fs::create_dir(p.join(".fuzi-installing-abc")).unwrap();
        fs::create_dir(p.join(".fuzi-old-def")).unwrap();
        fs::write(p.join(".fuzi-old-def/sentinel"), b"keep").unwrap();

        for dry_run in [true, false] {
            let report = clean(p, dry_run).unwrap();
            assert_eq!(report.removed, vec![".fuzi-installing-abc".to_string()]);
            assert_eq!(
                report.skipped,
                vec![SkippedArtifact {
                    name: ".fuzi-old-def".to_string(),
                    restore_command: "[ -e node_modules ] || mv -- '.fuzi-old-def' node_modules"
                        .to_string(),
                }]
            );
            assert_eq!(report.node_modules_obstruction, None);
        }
        assert!(!p.join(".fuzi-installing-abc").exists());
        assert_eq!(fs::read(p.join(".fuzi-old-def/sentinel")).unwrap(), b"keep");
    }

    #[test]
    fn displaced_tree_is_kept_beside_a_node_modules_that_is_not_a_directory() {
        type Case = (&'static str, fn(&Path), NodeModulesObstruction);
        // A fuzi swap only ever publishes a directory, so a symlink (dangling
        // or not) or a file at `node_modules` is no successor to the parked
        // tree — it may still be the user's only copy. Kept, with the
        // obstruction named so the restore can say to move it aside.
        let w = TempDir::new().unwrap();
        fs::create_dir(w.path().join("elsewhere")).unwrap();
        let cases: [Case; 3] = [
            (
                "dangling",
                |nm| symlink("nowhere", nm).unwrap(),
                NodeModulesObstruction::Symlink,
            ),
            (
                "to-a-dir",
                |nm| symlink("../elsewhere", nm).unwrap(),
                NodeModulesObstruction::Symlink,
            ),
            (
                "file",
                |nm| fs::write(nm, b"").unwrap(),
                NodeModulesObstruction::File,
            ),
        ];
        for (label, make, kind) in cases {
            let p = w.path().join(label);
            fs::create_dir(&p).unwrap();
            fs::create_dir(p.join(".fuzi-old-a")).unwrap();
            make(&p.join("node_modules"));
            let report = clean(&p, false).unwrap();
            assert!(report.removed.is_empty(), "{label}");
            assert_eq!(report.skipped.len(), 1, "{label}");
            assert_eq!(report.node_modules_obstruction, Some(kind), "{label}");
            assert!(p.join(".fuzi-old-a").is_dir(), "{label}");
        }
    }

    #[test]
    fn displaced_tree_is_swept_beside_a_node_modules_directory() {
        let project = TempDir::new().unwrap();
        let p = project.path();
        fs::create_dir(p.join(".fuzi-old-a")).unwrap();
        fs::create_dir(p.join("node_modules")).unwrap();
        let report = clean(p, false).unwrap();
        assert_eq!(report.removed, vec![".fuzi-old-a".to_string()]);
        assert!(report.skipped.is_empty());
        assert_eq!(report.node_modules_obstruction, None);
        assert!(!p.join(".fuzi-old-a").exists());
    }

    #[test]
    fn restore_command_does_nothing_once_node_modules_exists() {
        // A bare `mv` onto an existing directory moves the tree *into* it; the
        // guard makes a second tree's command a no-op instead. (Run end to end
        // through `sh` in the `fuzi` crate's `tests/clean.rs`.)
        assert_eq!(
            restore_command(".fuzi-old-it's"),
            "[ -e node_modules ] || mv -- '.fuzi-old-it'\\''s' node_modules"
        );
    }

    #[test]
    fn restore_command_quotes_the_name_for_sh() {
        assert_eq!(
            sh_single_quote(".fuzi-old-it's; rm -rf ~"),
            "'.fuzi-old-it'\\''s; rm -rf ~'"
        );
    }

    #[test]
    fn an_artifact_already_gone_counts_as_removed() {
        // A concurrent clean (or an install's own cleanup) got there between
        // the listing and the removal: absence is the goal, not an error.
        let project = TempDir::new().unwrap();
        remove_artifact(&project.path().join(".fuzi-installing-gone")).unwrap();
    }

    #[test]
    fn dry_run_lists_without_removing() {
        let project = TempDir::new().unwrap();
        let p = project.path();
        fs::create_dir(p.join(".fuzi-installing-x")).unwrap();

        let report = clean(p, true).unwrap();
        assert!(report.dry_run);
        assert_eq!(report.removed, vec![".fuzi-installing-x".to_string()]);
        // Still there — dry run.
        assert!(p.join(".fuzi-installing-x").exists());
    }

    #[test]
    fn nothing_to_sweep_is_empty_report() {
        let project = TempDir::new().unwrap();
        fs::create_dir(project.path().join("node_modules")).unwrap();
        let report = clean(project.path(), false).unwrap();
        assert!(report.removed.is_empty());
    }

    #[test]
    fn sweeping_a_staging_tree_with_a_link_leaves_the_target_intact() {
        // Pin: the sweep's `remove_dir_all` unlinks a sibling link inside the
        // leaked tree; it never descends into the link's target.
        let w = TempDir::new().unwrap();
        let lib = w.path().join("lib");
        fs::create_dir(&lib).unwrap();
        fs::write(lib.join("sentinel"), b"keep").unwrap();
        let app = w.path().join("app");
        let leaked = app.join(".fuzi-installing-abc");
        fs::create_dir_all(&leaked).unwrap();
        symlink("../../lib", leaked.join("lib")).unwrap();
        assert!(
            leaked.join("lib/sentinel").is_file(),
            "sanity: the link resolves"
        );

        let report = clean(&app, false).unwrap();

        assert_eq!(report.removed, vec![".fuzi-installing-abc".to_string()]);
        assert!(!leaked.exists());
        assert_eq!(fs::read(lib.join("sentinel")).unwrap(), b"keep");
    }

    #[test]
    fn sweeping_a_displaced_tree_with_a_link_leaves_the_target_intact() {
        // Pin: the same for a `.fuzi-old-*` tree — a displaced `node_modules`
        // that held a package link, a scoped one, and a `.bin` link through it.
        let w = TempDir::new().unwrap();
        let lib = w.path().join("lib");
        fs::create_dir_all(lib.join("bin")).unwrap();
        fs::write(lib.join("bin/run.js"), b"keep").unwrap();
        let before = tree_listing(&lib);
        let app = w.path().join("app");
        let old = app.join(".fuzi-old-abc");
        fs::create_dir_all(old.join("@s")).unwrap();
        fs::create_dir(old.join(".bin")).unwrap();
        symlink("../../lib", old.join("lib")).unwrap();
        symlink("../../../lib", old.join("@s/lib")).unwrap();
        symlink("../lib/bin/run.js", old.join(".bin/run")).unwrap();
        assert!(old.join("@s/lib/bin/run.js").is_file(), "sanity: resolves");
        // A live tree beside it, so the displaced one is stale (and swept).
        fs::create_dir(app.join("node_modules")).unwrap();

        let report = clean(&app, false).unwrap();

        assert_eq!(report.removed, vec![".fuzi-old-abc".to_string()]);
        assert!(fs::symlink_metadata(&old).is_err());
        assert_eq!(tree_listing(&lib), before);
    }

    #[test]
    fn a_swept_name_that_is_a_symlink_is_unlinked_not_followed() {
        // Pin: a top-level `.fuzi-*` entry that is itself a symlink — to a
        // directory, to a file, or dangling — is removed as a link. What it
        // points at is never opened.
        let w = TempDir::new().unwrap();
        let precious = w.path().join("precious");
        fs::create_dir_all(precious.join("deep")).unwrap();
        fs::write(precious.join("deep/file"), b"keep").unwrap();
        let before = tree_listing(&precious);
        let app = w.path().join("app");
        fs::create_dir(&app).unwrap();
        symlink(&precious, app.join(".fuzi-installing-dir")).unwrap();
        symlink("../precious", app.join(".fuzi-old-rel")).unwrap();
        symlink(precious.join("deep/file"), app.join(".fuzi-old-file")).unwrap();
        symlink("nowhere", app.join(".fuzi-old-dangling")).unwrap();
        // A live tree beside them, so the displaced names are stale (and swept).
        fs::create_dir(app.join("node_modules")).unwrap();

        let listed = clean(&app, true).unwrap();
        assert_eq!(listed.removed.len(), 4);
        assert_eq!(
            fs::read_dir(&app).unwrap().count(),
            5,
            "dry run removes nothing"
        );

        let report = clean(&app, false).unwrap();
        assert_eq!(report.removed, listed.removed);
        assert_eq!(fs::read_dir(&app).unwrap().count(), 1, "only node_modules");
        assert_eq!(tree_listing(&precious), before);
    }
}
