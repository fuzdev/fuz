//! `fuzi verify` — a structural, cache-independent check that a materialized
//! `node_modules` matches the lockfile.
//!
//! The lockfile pins *tarball* hashes, not per-file hashes, so v0 verify is
//! deliberately **structural** rather than cryptographic (mode/mtime-noise-free):
//!
//! 1. **Presence** — every host-needed placement is a directory under
//!    `node_modules`. A `node_modules` that does not exist at all is one
//!    [`VerifyProblemKind::NodeModulesAbsent`] (run `fuzi install`), not a
//!    missing package per placement.
//! 2. **Version** — each present package's `package.json` `version` matches the lock.
//! 3. **Links** — every sibling `link: true` package is a symlink whose text is
//!    exactly the relative path install writes (string compare, no
//!    canonicalization), and its target still passes the install-time check
//!    (a real directory whose `package.json` names the package). Each `.bin`
//!    entry install links for it — a declared bin that is an executable
//!    regular file in the target — is a symlink with exactly install's text.
//! 4. **Platform assertion** — for every package that declares platform-variant
//!    `optionalDependencies` the host *expects* (os+cpu match), at least one
//!    host-compatible variant is installed. This catches the wrong-*libc*
//!    lockfile (e.g. a glibc-generated lock with no `…-musl` rollup variant) at
//!    verify time, not at first `vite build`.
//!
//! Every one of those is a no-follow look at a *final* path component, so each
//! is only as good as the directories leading to it: `node_modules`, every
//! `@scope` directory, every enclosing package and its `node_modules`, and —
//! when a linked bin is expected there — the top-level `.bin` must be **real
//! directories** ([`VerifyProblemKind::ParentNotDirectory`] otherwise — a
//! symlinked parent would have every check below it read some other tree).
//! The same holds for extracted packages and for links. Once any such
//! directory — or a package's own directory — is found to be there as
//! something else, the platform assertion is skipped: it reasons from which
//! packages are present, and would blame the lockfile for a tree that was
//! edited.
//!
//! Not checked: entries the lockfile does not name (an extra package, a stray
//! `.bin` link), the contents of a link's target beyond its `package.json`
//! name, and registry packages' `.bin` entries.
//!
//! Known limitation — **wrong-*OS* locks are not caught.** A lockfile generated
//! on another OS lists only that OS's platform variants (npm host-prunes them),
//! so the host's needed variant is simply *absent* from the lock and the
//! assertion has nothing to require → it passes (the build then fails for the
//! real reason). Catching this would need a required-vs-truly-optional heuristic
//! that is inherently noisy — a package legitimately offering only darwin/win
//! optionals would false-positive — so v0 keeps it a documented gap rather than a
//! noisy check; the precise fix is the post-v0 resolver/manifest cross-reference.
//!
//! Cryptographic per-file verification is the post-v0 extracted-content manifest
//! (which also unlocks the deferred `.package-lock.json` marker).

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use fuz_sys::fs::{DirProbe, NonDirKind, is_real_dir, probe_real_dir};
use fuz_sys::secure_file::load_bounded_file;
use serde::Serialize;

use crate::entry::{BinCommand, package_portion_of};
use crate::error::FuziError;
use crate::link::{check_link_target, linked_bin_is_linkable};
use crate::lockfile::{RawLockfile, read_lockfile};
use crate::plan::{LinkPlacement, build_plan};
use crate::platform::Platform;
use crate::{Omit, VerifyOptions};

/// The structured success result of `fuzi verify`: the tree matched the lock.
///
/// Failure is [`FuziError::VerifyFailed`] (carrying the structured problems);
/// presentation lives in the `fuzi` binary.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct VerifyReport {
    /// Placements checked present-and-version-matched.
    pub checked: usize,
    /// Sibling links checked (symlink text + target).
    pub links_checked: usize,
    /// Linked packages' `.bin` entries checked (symlink text) — the declared
    /// bins an install links: an executable regular file in the target.
    pub link_bins_checked: usize,
    /// Packages whose platform-variant `optionalDependencies` were asserted.
    pub platform_parents_checked: usize,
}

/// One way the materialized tree diverged from the lockfile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VerifyProblem {
    /// The package the problem concerns (install path, or parent name for the
    /// platform assertion).
    pub package: String,
    /// The machine-readable problem class.
    pub kind: VerifyProblemKind,
    /// A human-readable detail.
    pub detail: String,
}

/// The class of a [`VerifyProblem`] — a closed set an agent can branch on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifyProblemKind {
    /// A host-needed placement's directory is absent from `node_modules`, or
    /// is there as something else (a symlink, a file). In the second case the
    /// packages nested under it are neither checked nor reported: this problem
    /// covers them.
    Missing,
    /// A present package's `package.json` `version` differs from the lock (or is
    /// unreadable).
    VersionMismatch,
    /// A package declares platform-variant `optionalDependencies` but no
    /// host-compatible variant is installed — the build would fail at runtime.
    MissingPlatformBinary,
    /// A sibling link is absent, is not a symlink, points somewhere other than
    /// the relative path install writes, or its target no longer passes the
    /// install-time check (missing, a symlink, the wrong package) — or one of
    /// the `.bin` entries install links for it is absent, not a symlink, or
    /// points somewhere else.
    LinkMismatch,
    /// A directory on the way to a package, a link, or a linked bin —
    /// `node_modules` itself, an `@scope` directory, an enclosing package or
    /// its `node_modules`, the top-level `.bin` — is there but is not a real
    /// directory (a symlink, or a file). Everything beneath it would be read
    /// from wherever it leads, so nothing beneath it is checked. `package` is
    /// that directory's path, reported once however many packages sit under
    /// it. An enclosing package that is itself a placement is reported as
    /// [`Missing`](Self::Missing) instead, once.
    ParentNotDirectory,
    /// `node_modules` does not exist at all, though the lockfile places
    /// packages or links — nothing was installed (or the tree was removed).
    /// The whole report: one problem, not a [`Missing`](Self::Missing) per
    /// placement. `package` is `node_modules`.
    NodeModulesAbsent,
}

impl VerifyProblemKind {
    /// The kind's stable name — the string it serializes to in `--json`, and
    /// the heading of its group in the human rendering.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::VersionMismatch => "version_mismatch",
            Self::MissingPlatformBinary => "missing_platform_binary",
            Self::LinkMismatch => "link_mismatch",
            Self::ParentNotDirectory => "parent_not_directory",
            Self::NodeModulesAbsent => "node_modules_absent",
        }
    }
}

/// Verify a materialized `node_modules` against the lockfile.
///
/// Builds the same host-filtered plan an install would, under the *same*
/// [`VerifyOptions::omit`] set the tree was installed with — a tree installed
/// with `--omit dev` legitimately lacks every dev package, so verifying it
/// against the full plan would report each one `Missing`. Manifest drift is
/// irrelevant here: verify checks the *tree* against the lock, not
/// `package.json`. Then it runs the structural checks above.
///
/// # Errors
///
/// Returns [`FuziError::Io`]/[`FuziError::Lockfile`] if the lockfile cannot be
/// read, [`FuziError::Refused`] if the lockfile itself does not classify cleanly,
/// or [`FuziError::VerifyFailed`] if the tree diverges from the lock.
pub fn verify(options: &VerifyOptions) -> Result<VerifyReport, FuziError> {
    let raw = read_lockfile(&options.dir)?;
    verify_against(&raw, &Platform::current(), &options.omit, &options.dir)
}

/// The host-injected half of [`verify`]: check `<dir>/node_modules` against an
/// already-parsed lockfile for a *given* host.
///
/// Splits the host probe out the way `read_lockfile`/`parse_lockfile` and
/// `drift_check`/`drift_against` split their IO — and for the same reason the
/// install path injects into `build_plan`: every one of verify's checks reads a
/// host-filtered plan, so a caller (notably a test) must be able to name the host
/// rather than inherit whatever machine it runs on. Still reads `node_modules`
/// from disk; only the host detection is lifted.
///
/// # Errors
///
/// Returns [`FuziError::Refused`] if the lockfile does not classify cleanly, or
/// [`FuziError::VerifyFailed`] if the tree diverges from the lock.
pub fn verify_against(
    raw: &RawLockfile,
    host: &Platform,
    omit: &[Omit],
    dir: &Path,
) -> Result<VerifyReport, FuziError> {
    let plan = build_plan(raw, host, omit)?;

    let nm = dir.join("node_modules");
    let mut problems = Vec::new();

    // `node_modules` itself first: if it is a symlink (or a file), every path
    // below is some other tree's, so that is the whole report. If it is absent
    // while the lock places anything, nothing was installed — one problem that
    // says so, not a `Missing` per placement.
    let mut parents = Parents::new(&nm);
    if parents.root_is_not_a_directory(&mut problems) {
        return Err(FuziError::VerifyFailed { problems });
    }
    if (!plan.placements.is_empty() || !plan.links.is_empty())
        && matches!(probe_real_dir(&nm), Ok(DirProbe::Absent))
    {
        return Err(FuziError::VerifyFailed {
            problems: vec![VerifyProblem {
                package: "node_modules".to_string(),
                kind: VerifyProblemKind::NodeModulesAbsent,
                detail: format!(
                    "does not exist, but the lockfile places {} package(s) and {} link(s) — run fuzi install",
                    plan.placements.len(),
                    plan.links.len()
                ),
            }],
        });
    }

    // (1) + (2): each host-needed placement present + version match. Record the
    // package portions actually present, for the platform assertion below.
    let mut present_portions: BTreeSet<&str> = BTreeSet::new();
    for placement in &plan.placements {
        let Some(rel) = placement.path.nm_relative() else {
            continue; // root / sibling-escape never reach a placement
        };
        if parents.blocked(rel, &mut problems) {
            continue; // reported once, on the parent
        }
        let pkg_dir = nm.join(rel);
        if !is_real_dir(&pkg_dir) {
            problems.push(VerifyProblem {
                package: placement.path.as_str().to_string(),
                kind: VerifyProblemKind::Missing,
                detail: "package directory absent, or not a real directory (symlink/file)"
                    .to_string(),
            });
            // A package that is there as something else is also a parent of
            // whatever nests under it. This problem covers it: the packages
            // beneath are skipped without a second report on the same path.
            if not_a_directory(&pkg_dir).is_some() {
                parents.note_blocked(rel);
            }
            continue;
        }
        present_portions.insert(placement.path.package_portion());
        if let Some(expected) = &placement.version {
            check_version(&pkg_dir, placement.path.as_str(), expected, &mut problems);
        }
    }

    // (3): sibling links — lstat + read_link only, never followed for the
    // presence check; the target check reads package.json no-follow. Then the
    // `.bin` entries of the links that passed.
    let sound_links: Vec<&LinkPlacement> = plan
        .links
        .iter()
        .filter(|link| check_link(&nm, dir, link, &mut parents, &mut problems))
        .collect();
    let link_bins_checked = check_link_bins(&nm, dir, &sound_links, &mut parents, &mut problems);

    // (4): platform assertion. The set of package portions that are platform
    // variants (carry os/cpu/libc) is derived from the lock; a parent whose
    // platform-variant optionalDependencies have no present host-compatible
    // member fails loud. Skipped when a directory on the way to any package was
    // not a real one: the packages under it were not counted present, so the
    // assertion would report a platform binary the lockfile "cannot supply" —
    // and advise regenerating it — for a tree that was edited.
    let platform_parents_checked = if parents.any_blocked() {
        0
    } else {
        check_platform_assertions(raw, host, omit, &present_portions, &mut problems)
    };

    if problems.is_empty() {
        Ok(VerifyReport {
            checked: plan.placements.len(),
            links_checked: plan.links.len(),
            link_bins_checked,
            platform_parents_checked,
        })
    } else {
        Err(FuziError::VerifyFailed { problems })
    }
}

/// The directories leading to what verify checks, each probed once.
///
/// Every check in this module looks at a final path component without
/// following it, which says nothing about the components before it: with
/// `node_modules/@s` a symlink, `node_modules/@s/lib` is whatever the directory
/// it points at holds. So each parent — relative to `node_modules`: an `@scope`
/// directory, an enclosing package, its `node_modules`, `.bin` — must be a real
/// directory before anything under it is trusted. One `lstat` per distinct
/// parent, however many packages share it; an unscoped top-level package has
/// none.
struct Parents<'a> {
    /// `<project>/node_modules`.
    nm: &'a Path,
    /// Each probed parent (relative to `nm`) and whether it blocks the checks
    /// beneath it.
    seen: BTreeMap<String, bool>,
}

impl<'a> Parents<'a> {
    const fn new(nm: &'a Path) -> Self {
        Self {
            nm,
            seen: BTreeMap::new(),
        }
    }

    /// True — with the problem pushed — iff `node_modules` itself is there but
    /// is not a real directory.
    fn root_is_not_a_directory(&self, problems: &mut Vec<VerifyProblem>) -> bool {
        let what = not_a_directory(self.nm);
        if let Some(what) = what {
            problems.push(parent_problem("node_modules".to_string(), what));
        }
        what.is_some()
    }

    /// True iff some parent directory of `rel` (a path relative to
    /// `node_modules`) is there but is not a real directory. The problem is
    /// pushed the first time that parent is met; the caller skips its own
    /// checks, which would only repeat it.
    ///
    /// An *absent* parent does not block: the entry under it then reads as
    /// absent to the caller's own check, which reports it as such.
    fn blocked(&mut self, rel: &str, problems: &mut Vec<VerifyProblem>) -> bool {
        // Each `/` ends one parent: `a/node_modules/@s/b` → `a`,
        // `a/node_modules`, `a/node_modules/@s`.
        rel.match_indices('/')
            .any(|(end, _)| self.directory_blocks(&rel[..end], problems))
    }

    /// Record `rel` as blocking what is under it without reporting it: the
    /// caller has reported the same path as a problem of its own.
    fn note_blocked(&mut self, rel: &str) {
        self.seen.insert(rel.to_string(), true);
    }

    /// True iff any directory probed or noted so far blocks what is under it.
    fn any_blocked(&self) -> bool {
        self.seen.values().any(|blocks| *blocks)
    }

    /// True iff the directory `parent` (relative to `node_modules`) is there
    /// but is not a real directory; probed and reported on first sight only.
    fn directory_blocks(&mut self, parent: &str, problems: &mut Vec<VerifyProblem>) -> bool {
        if let Some(blocks) = self.seen.get(parent) {
            return *blocks;
        }
        let what = not_a_directory(&self.nm.join(parent));
        if let Some(what) = what {
            problems.push(parent_problem(format!("node_modules/{parent}"), what));
        }
        self.seen.insert(parent.to_string(), what.is_some());
        what.is_some()
    }
}

/// What `path` is, when it exists but is not a real directory; `None` for a
/// real directory and for an absent path. An unreadable one counts as not a
/// directory: nothing under it can be vouched for.
fn not_a_directory(path: &Path) -> Option<&'static str> {
    match probe_real_dir(path) {
        Ok(DirProbe::RealDir | DirProbe::Absent) => None,
        Ok(DirProbe::NotDir(NonDirKind::Symlink)) => Some("a symlink"),
        Ok(DirProbe::NotDir(_)) => Some("not a directory"),
        Err(_) => Some("unreadable"),
    }
}

fn parent_problem(package: String, what: &str) -> VerifyProblem {
    VerifyProblem {
        package,
        kind: VerifyProblemKind::ParentNotDirectory,
        detail: format!(
            "is {what}, not a real directory; nothing under it was checked — remove it and reinstall"
        ),
    }
}

/// Check one sibling link: a symlink (not a directory or file) whose text is
/// exactly [`LinkTarget::relative_from`](crate::entry::LinkTarget::relative_from),
/// whose target still passes the install-time check. Every divergence is a
/// [`VerifyProblemKind::LinkMismatch`]. A target version mismatch only warns at
/// install, so it is not a problem here either.
///
/// Returns whether the link is sound — the links whose `.bin` entries are then
/// worth checking.
fn check_link(
    nm: &Path,
    dir: &Path,
    link: &LinkPlacement,
    parents: &mut Parents<'_>,
    problems: &mut Vec<VerifyProblem>,
) -> bool {
    let Some(rel) = link.path.nm_relative() else {
        return false; // classify admits only node_modules/… link keys
    };
    if parents.blocked(rel, problems) {
        return false;
    }
    let at = nm.join(rel);
    let expected = link.target.relative_from(&link.path);
    let detail = match fs::symlink_metadata(&at) {
        Err(_) => Some(format!("link absent (expected a symlink to {expected})")),
        Ok(meta) if !meta.file_type().is_symlink() => {
            Some(format!("not a symlink (expected a symlink to {expected})"))
        }
        Ok(_) => match fs::read_link(&at) {
            Ok(actual) if actual.as_os_str() == expected.as_str() => {
                check_link_target(link, dir).err()
            }
            Ok(actual) => Some(format!(
                "points at {}, expected {expected}",
                actual.display()
            )),
            Err(e) => Some(format!("cannot read link: {e}")),
        },
    };
    let sound = detail.is_none();
    if let Some(detail) = detail {
        problems.push(VerifyProblem {
            package: link.path.as_str().to_string(),
            kind: VerifyProblemKind::LinkMismatch,
            detail,
        });
    }
    sound
}

/// Check the `.bin` entries install links for `links` (the sound ones),
/// returning how many were checked.
///
/// The expectation is rebuilt the way install builds the entries: a declared
/// bin gets a link only when its target is linkable *now*
/// ([`linked_bin_is_linkable`] — the same test, so a bin install skipped is not
/// demanded), linked bins are written after every registry bin, and in
/// lockfile-key order, so on a shared command name the last link wins. Each
/// expected entry must be a symlink whose text is exactly install's
/// ([`BinTarget::bin_link_text`](crate::entry::BinTarget::bin_link_text));
/// anything else is a
/// [`VerifyProblemKind::LinkMismatch`] on the link that owns the command.
///
/// A target whose bin gained or lost its exec bit since the install therefore
/// reads as a mismatch or as nothing to check, respectively: the tree is
/// compared to what an install would write today.
fn check_link_bins(
    nm: &Path,
    dir: &Path,
    links: &[&LinkPlacement],
    parents: &mut Parents<'_>,
    problems: &mut Vec<VerifyProblem>,
) -> usize {
    let mut expected: BTreeMap<&BinCommand, (&LinkPlacement, String)> = BTreeMap::new();
    for link in links {
        let target_dir = link.target.dir_in(dir);
        for (command, bin) in &link.bins {
            if linked_bin_is_linkable(&target_dir, bin) {
                expected.insert(command, (link, bin.bin_link_text(&link.path)));
            }
        }
    }
    if expected.is_empty() {
        return 0;
    }
    // A link key is depth 1, so every linked bin lives in the top-level `.bin`.
    if parents.directory_blocks(".bin", problems) {
        return 0;
    }
    for (command, (link, text)) in &expected {
        let command = command.as_str();
        let at = nm.join(".bin").join(command);
        let detail = match fs::symlink_metadata(&at) {
            Err(_) => format!(
                ".bin/{command} is absent (expected a symlink to {text}; a linked bin that became executable after the install is linked by the next fuzi install)"
            ),
            Ok(meta) if !meta.file_type().is_symlink() => {
                format!(".bin/{command} is not a symlink (expected a symlink to {text})")
            }
            Ok(_) => match fs::read_link(&at) {
                Ok(actual) if actual.as_os_str() == text.as_str() => continue,
                Ok(actual) => format!(
                    ".bin/{command} points at {}, expected {text}",
                    actual.display()
                ),
                Err(e) => format!("cannot read .bin/{command}: {e}"),
            },
        };
        problems.push(VerifyProblem {
            package: link.path.as_str().to_string(),
            kind: VerifyProblemKind::LinkMismatch,
            detail,
        });
    }
    expected.len()
}

/// Compare a present package's `package.json` `version` against the lock,
/// pushing a [`VerifyProblemKind::VersionMismatch`] on any divergence.
fn check_version(pkg_dir: &Path, package: &str, expected: &str, problems: &mut Vec<VerifyProblem>) {
    let detail = match read_package_version(pkg_dir) {
        Some(actual) if actual == expected => return,
        Some(actual) => format!("expected version {expected}, found {actual}"),
        None => {
            format!(
                "expected version {expected}, but package.json is missing, unreadable, or has no version"
            )
        }
    };
    problems.push(VerifyProblem {
        package: package.to_string(),
        kind: VerifyProblemKind::VersionMismatch,
        detail,
    });
}

/// Read `<pkg_dir>/package.json`'s `version` string, or `None` if the file is
/// absent / not a real file / over [`fuz_sys::limits::MAX_BUFFERED_SIZE`] /
/// unparseable / has no string `version`.
///
/// Read through [`load_bounded_file`]: the open refuses a symlink
/// (`O_NOFOLLOW`), so a `package.json` swapped for one (a post-install tamper)
/// reads as `None` → surfaces as a version mismatch, rather than silently
/// following the symlink to a planted version; the regular-file check runs on
/// the open descriptor, opened non-blocking, so a FIFO cannot hang `verify` and
/// nothing can swap the path between the check and the read. `verify` walks
/// trees fuzi may not have installed, so the read is capped too.
fn read_package_version(pkg_dir: &Path) -> Option<String> {
    read_package_version_capped(pkg_dir, fuz_sys::limits::MAX_BUFFERED_SIZE)
}

/// [`read_package_version`] with the read cap a parameter, so a test can cross
/// it without writing the real cap's worth of bytes.
fn read_package_version_capped(pkg_dir: &Path, cap: u64) -> Option<String> {
    let bytes = load_bounded_file(&pkg_dir.join("package.json"), cap).ok()?;
    let value: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    value.get("version")?.as_str().map(str::to_string)
}

/// Run the platform assertion for every *present* lock entry that declares
/// `optionalDependencies` whose platform variants the host expects, returning
/// the number of parents actually asserted.
///
/// "The host expects a variant" means the parent declares a platform-variant
/// optional whose `os`+`cpu` match this host (libc aside). That scoping is what
/// distinguishes a genuinely off-host optional — darwin-only `fsevents` on
/// Linux, which has no os/cpu match and so is *correctly* absent — from a
/// host-expected one that is missing. When the host expects a variant but none
/// is present in `node_modules`, the tree has no runtime binary for the parent:
/// a loud [`VerifyProblemKind::MissingPlatformBinary`].
///
/// This also catches the wrong-libc lock the assertion was designed for:
/// `@rollup/rollup-linux-x64-gnu` matches os+cpu on a musl host (so a variant is
/// expected), but it is libc-filtered out of the install and no `-musl` variant
/// exists in the lock to take its place — present-set empty → fail loud.
///
/// Respects `omit`: platform variants are *only ever reached as
/// `optionalDependency` edges* (this function looks at nothing but each parent's
/// `optional_dependencies`), so under `--omit optional` every variant it would
/// demand is a legitimately-absent optional. Asserting their presence there would
/// contradict the very plan [`verify_against`] built (`build_plan` drops the whole
/// optional class), so the assertion does not fire at all — it returns `0`
/// asserted. The no-omit / `--omit dev` / `--omit peer` paths are untouched, so
/// the wrong-libc catch this exists for still fires. (`--omit dev` was already
/// safe by a different route: a dropped dev parent is absent from
/// `present_portions`, so its optionals were never asserted.)
//
// NOTE (v0 approximation): optional-name → entry resolution is still by package
// portion across the whole lock (platform packages are hoisted singletons in
// practice), not a precise hoisting walk — the resolver-shaped work v0 omits.
// So a portion shared by two distinct packages at different depths collapses:
// the host "expects" the name if *any* entry under it matches (and the present
// one may not be the parent's copy). Low risk on real trees (platform variants
// are unique top-level hoists); revisit only if a real lock ever trips it.
fn check_platform_assertions(
    raw: &RawLockfile,
    host: &Platform,
    omit: &[Omit],
    present_portions: &BTreeSet<&str>,
    problems: &mut Vec<VerifyProblem>,
) -> usize {
    // Every platform variant is an optionalDependency, so under `--omit optional`
    // the tree legitimately lacks them all — asserting their presence would
    // contradict the plan (`build_plan` retained none of them). Skip the whole
    // assertion; there is nothing host-expected left to demand.
    if omit.contains(&Omit::Optional) {
        return 0;
    }
    // The platform-variant package portions this host *expects* a binary for: an
    // entry carrying any os/cpu/libc token (e.g. `@esbuild/linux-x64`,
    // `@rollup/rollup-linux-x64-musl`) whose os+cpu match the host, libc aside.
    // Resolved once, so the per-parent, per-optional-name lookups below are set
    // probes rather than a re-parse of the axes each time.
    let host_expected: BTreeSet<&str> = raw
        .packages
        .iter()
        .filter(|(_, e)| !e.os.is_empty() || !e.cpu.is_empty() || !e.libc.is_empty())
        // malformed can't reach here (build_plan refused) — `expects_os_cpu_raw`
        // stays safe by reading a malformed axis as not-expected anyway.
        .filter(|(_, e)| host.expects_os_cpu_raw(&e.os, &e.cpu))
        .map(|(key, _)| package_portion_of(key))
        .collect();

    let mut asserted = 0;
    for (key, entry) in &raw.packages {
        // Only assert for a parent that is itself present (root is always present);
        // a platform-skipped parent's optionals are irrelevant.
        if !key.is_empty() && !present_portions.contains(package_portion_of(key)) {
            continue;
        }
        let Some(optdeps) = &entry.optional_dependencies else {
            continue;
        };
        // the parent's platform-variant optionals this host actually expects
        let expected: Vec<&str> = optdeps
            .keys()
            .map(String::as_str)
            .filter(|name| host_expected.contains(name))
            .collect();
        if expected.is_empty() {
            continue; // no host-expected platform variant (e.g. fsevents on Linux)
        }
        asserted += 1;
        if !expected.iter().any(|name| present_portions.contains(name)) {
            let parent = parent_label(key);
            problems.push(VerifyProblem {
                package: parent,
                kind: VerifyProblemKind::MissingPlatformBinary,
                detail: format!(
                    "declares platform-specific optionalDependencies ({}) for this host but none is installed — regenerate the lockfile on this host",
                    expected.join(", ")
                ),
            });
        }
    }
    asserted
}

/// A readable parent label for the platform assertion: the package portion, or
/// `<root>` for the root entry.
fn parent_label(key: &str) -> String {
    if key.is_empty() {
        "<root>".to_string()
    } else {
        package_portion_of(key).to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{host_linux_x64_glibc, sha512_sri};
    use serde_json::json;
    use std::fs;
    use std::os::unix::fs::symlink;
    use tempfile::TempDir;

    /// A FIFO `package.json` reads as no version, without blocking: a plain
    /// open would wait for a writer forever. On a thread with a deadline so a
    /// regression fails, not hangs.
    #[test]
    fn a_fifo_package_json_reads_as_no_version_without_blocking() {
        let dir = tempfile::tempdir().unwrap();
        nix::unistd::mkfifo(
            &dir.path().join("package.json"),
            nix::sys::stat::Mode::S_IRWXU,
        )
        .unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let pkg = dir.path().to_path_buf();
        std::thread::spawn(move || tx.send(read_package_version(&pkg)).unwrap());
        let version = rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("read blocked on a FIFO package.json");
        assert_eq!(version, None);
    }

    /// The version read is capped: a valid manifest padded to exactly the cap
    /// reads, one byte more reads as no version (never a truncated parse).
    #[test]
    fn a_package_json_over_the_cap_reads_as_no_version() {
        let dir = tempfile::tempdir().unwrap();
        let json = r#"{"version":"1.2.3"}"#;
        let cap = 64;
        let pad = usize::try_from(cap).unwrap() - json.len();
        fs::write(
            dir.path().join("package.json"),
            format!("{json}{}", " ".repeat(pad)),
        )
        .unwrap();
        assert_eq!(
            read_package_version_capped(dir.path(), cap).as_deref(),
            Some("1.2.3")
        );
        fs::write(
            dir.path().join("package.json"),
            format!("{json}{} ", " ".repeat(pad)),
        )
        .unwrap();
        assert_eq!(read_package_version_capped(dir.path(), cap), None);
    }

    /// Verify `<dir>` against its own lockfile for an explicit host — the
    /// host-independent form of [`verify`] the platform-assertion tests use.
    fn verify_here(dir: &Path, host: &Platform, omit: &[Omit]) -> Result<VerifyReport, FuziError> {
        let raw = read_lockfile(dir)?;
        verify_against(&raw, host, omit, dir)
    }

    /// Every count is a key of the `--json` success document, zero or not.
    #[test]
    fn report_json_keys_are_every_count() {
        let serde_json::Value::Object(map) = serde_json::to_value(VerifyReport::default()).unwrap()
        else {
            panic!("a VerifyReport serializes as an object");
        };
        let keys: Vec<&str> = map.keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            [
                "checked",
                "link_bins_checked",
                "links_checked",
                "platform_parents_checked"
            ]
        );
    }

    /// Write `<dir>/package-lock.json` from a JSON value.
    fn write_lock(dir: &Path, value: &serde_json::Value) {
        fs::write(
            dir.join("package-lock.json"),
            serde_json::to_string(value).unwrap(),
        )
        .unwrap();
    }

    /// Create `<dir>/node_modules/<rel>/package.json` with `version`.
    fn write_pkg(dir: &Path, rel: &str, version: &str) {
        let pkg = dir.join("node_modules").join(rel);
        fs::create_dir_all(&pkg).unwrap();
        fs::write(
            pkg.join("package.json"),
            json!({"version": version}).to_string(),
        )
        .unwrap();
    }

    fn opts(dir: &Path) -> VerifyOptions {
        VerifyOptions {
            dir: dir.to_path_buf(),
            omit: Vec::new(),
        }
    }

    #[test]
    fn clean_tree_verifies() {
        let d = TempDir::new().unwrap();
        write_lock(
            d.path(),
            &json!({
                "lockfileVersion": 3,
                "packages": {
                    "node_modules/foo": {
                        "version": "1.2.3",
                        "resolved": "https://registry.npmjs.org/foo/-/foo-1.2.3.tgz",
                        "integrity": sha512_sri(b"foo")
                    }
                }
            }),
        );
        write_pkg(d.path(), "foo", "1.2.3");
        let report = verify(&opts(d.path())).unwrap();
        assert_eq!(report.checked, 1);
    }

    /// A lockfile placing `n` registry packages `p0`…, plus a sibling link.
    fn lock_with_packages(dir: &Path, n: usize) {
        let mut packages = json!({
            "": {"name": "app"},
            "node_modules/lib": {"resolved": "../lib", "link": true},
            "../lib": {"name": "lib"}
        });
        for i in 0..n {
            packages[format!("node_modules/p{i}")] = json!({
                "version": "1.0.0",
                "resolved": format!("https://registry.npmjs.org/p{i}/-/p{i}-1.0.0.tgz"),
                "integrity": sha512_sri(format!("p{i}").as_bytes())
            });
        }
        write_lock(dir, &json!({"lockfileVersion": 3, "packages": packages}));
    }

    #[test]
    fn absent_node_modules_is_one_problem_not_one_per_placement() {
        let w = TempDir::new().unwrap();
        let app = w.path().join("app");
        fs::create_dir(&app).unwrap();
        lock_with_packages(&app, 20);
        let err = verify(&opts(&app)).unwrap_err();
        let FuziError::VerifyFailed { problems } = &err else {
            panic!("expected VerifyFailed, got {err:?}");
        };
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert_eq!(problems[0].kind, VerifyProblemKind::NodeModulesAbsent);
        assert_eq!(problems[0].package, "node_modules");
        assert!(
            problems[0].detail.ends_with("— run fuzi install"),
            "{}",
            problems[0].detail
        );
        assert!(problems[0].detail.contains("20 package(s) and 1 link(s)"));
        assert_eq!(err.exit_code(), 65);
        assert_eq!(
            err.to_string(),
            "node_modules does not match package-lock.json:\n  node_modules_absent (1):\n    node_modules · does not exist, but the lockfile places 20 package(s) and 1 link(s) — run fuzi install"
        );
    }

    #[test]
    fn absent_node_modules_with_nothing_to_place_verifies() {
        // An empty plan has nothing that should be there.
        let d = TempDir::new().unwrap();
        write_lock(
            d.path(),
            &json!({"lockfileVersion": 3, "packages": {"": {"name": "app"}}}),
        );
        assert_eq!(verify(&opts(d.path())).unwrap(), VerifyReport::default());
    }

    #[test]
    fn present_but_empty_node_modules_still_reports_each_placement() {
        // The short-circuit is for a tree never installed; an empty
        // `node_modules` is a tree whose packages are each missing.
        let d = TempDir::new().unwrap();
        lock_with_packages(d.path(), 2);
        fs::create_dir(d.path().join("node_modules")).unwrap();
        let err = verify(&opts(d.path())).unwrap_err();
        let FuziError::VerifyFailed { problems } = &err else {
            panic!("expected VerifyFailed, got {err:?}");
        };
        let missing = problems
            .iter()
            .filter(|p| p.kind == VerifyProblemKind::Missing)
            .count();
        assert_eq!(missing, 2, "{problems:?}");
    }

    #[test]
    fn human_rendering_groups_by_kind_and_caps_each_group() {
        let d = TempDir::new().unwrap();
        lock_with_packages(d.path(), 11);
        fs::create_dir(d.path().join("node_modules")).unwrap();
        write_pkg(d.path(), "p0", "9.9.9");
        let shown = verify(&opts(d.path())).unwrap_err().to_string();
        let lines: Vec<&str> = shown.lines().collect();
        // Groups in first-seen order (`p0` sorts first), each under its heading.
        assert_eq!(lines[0], "node_modules does not match package-lock.json:");
        assert_eq!(lines[1], "  version_mismatch (1):", "{shown}");
        assert_eq!(
            lines[2],
            "    node_modules/p0 · expected version 1.0.0, found 9.9.9"
        );
        assert_eq!(lines[3], "  missing (10):", "{shown}");
        // Eight examples, then the remainder collapsed.
        assert!(lines[4].starts_with("    node_modules/p1 · "), "{shown}");
        assert!(lines[11].starts_with("    node_modules/"), "{shown}");
        assert_eq!(lines[12], "    … (+2 more)", "{shown}");
        assert_eq!(lines[13], "  link_mismatch (1):", "{shown}");
        assert!(lines[14].starts_with("    node_modules/lib · "), "{shown}");
        assert_eq!(lines.len(), 15, "{shown}");
    }

    #[test]
    fn problem_kind_names_match_their_serialization() {
        for kind in [
            VerifyProblemKind::Missing,
            VerifyProblemKind::VersionMismatch,
            VerifyProblemKind::MissingPlatformBinary,
            VerifyProblemKind::LinkMismatch,
            VerifyProblemKind::ParentNotDirectory,
            VerifyProblemKind::NodeModulesAbsent,
        ] {
            assert_eq!(serde_json::to_value(kind).unwrap(), json!(kind.as_str()));
        }
    }

    #[test]
    fn omitted_class_is_not_reported_missing() {
        // A tree installed with `--omit dev` legitimately has no dev packages.
        // Verifying it against the full plan would report every one as `Missing`,
        // so verify takes the same omit set the install ran under.
        let d = TempDir::new().unwrap();
        write_lock(
            d.path(),
            &json!({
                "lockfileVersion": 3,
                "packages": {
                    "node_modules/prod": {
                        "version": "1.0.0",
                        "resolved": "https://registry.npmjs.org/prod/-/prod-1.0.0.tgz",
                        "integrity": sha512_sri(b"prod")
                    },
                    "node_modules/devtool": {
                        "version": "2.0.0",
                        "resolved": "https://registry.npmjs.org/devtool/-/devtool-2.0.0.tgz",
                        "integrity": sha512_sri(b"devtool"),
                        "dev": true
                    }
                }
            }),
        );
        write_pkg(d.path(), "prod", "1.0.0"); // devtool deliberately absent

        // Full-set verify correctly flags the absent dev package…
        let err = verify(&opts(d.path())).unwrap_err();
        assert!(matches!(err, FuziError::VerifyFailed { .. }));

        // …but under the install's own `--omit dev` the tree is correct.
        let report = verify(&VerifyOptions {
            dir: d.path().to_path_buf(),
            omit: vec![Omit::Dev],
        })
        .unwrap();
        assert_eq!(report.checked, 1);
    }

    #[test]
    fn missing_placement_fails() {
        let d = TempDir::new().unwrap();
        write_lock(
            d.path(),
            &json!({
                "lockfileVersion": 3,
                "packages": {
                    "node_modules/foo": {
                        "version": "1.0.0",
                        "resolved": "https://registry.npmjs.org/foo/-/foo-1.0.0.tgz",
                        "integrity": sha512_sri(b"foo")
                    }
                }
            }),
        );
        // node_modules/foo absent from an installed tree.
        fs::create_dir(d.path().join("node_modules")).unwrap();
        let err = verify(&opts(d.path())).unwrap_err();
        assert_eq!(err.exit_code(), 65);
        match err {
            FuziError::VerifyFailed { problems } => {
                assert_eq!(problems.len(), 1);
                assert_eq!(problems[0].kind, VerifyProblemKind::Missing);
            }
            other => panic!("expected VerifyFailed, got {other:?}"),
        }
    }

    #[test]
    fn symlinked_package_dir_is_a_divergence() {
        // A package dir replaced by a symlink (even to a valid package) is not a
        // fuzi-materialized tree — the no-follow presence check flags it.
        let d = TempDir::new().unwrap();
        write_lock(
            d.path(),
            &json!({
                "lockfileVersion": 3,
                "packages": {
                    "node_modules/foo": {
                        "version": "1.0.0",
                        "resolved": "https://registry.npmjs.org/foo/-/foo-1.0.0.tgz",
                        "integrity": sha512_sri(b"foo")
                    }
                }
            }),
        );
        // A real package elsewhere, symlinked in where node_modules/foo should be.
        let real = d.path().join("elsewhere");
        fs::create_dir_all(&real).unwrap();
        fs::write(
            real.join("package.json"),
            json!({"version": "1.0.0"}).to_string(),
        )
        .unwrap();
        fs::create_dir_all(d.path().join("node_modules")).unwrap();
        symlink(&real, d.path().join("node_modules/foo")).unwrap();

        let err = verify(&opts(d.path())).unwrap_err();
        match err {
            FuziError::VerifyFailed { problems } => {
                assert_eq!(problems[0].kind, VerifyProblemKind::Missing);
                assert!(problems[0].detail.contains("not a real directory"));
            }
            other => panic!("expected VerifyFailed, got {other:?}"),
        }
    }

    #[test]
    fn symlinked_package_json_is_a_version_mismatch() {
        // A real package dir but its package.json swapped for a symlink (even to a
        // file with the right version) — the no-follow read treats it as unreadable
        // → version mismatch, not a silent pass through the symlink.
        let d = TempDir::new().unwrap();
        write_lock(
            d.path(),
            &json!({
                "lockfileVersion": 3,
                "packages": {
                    "node_modules/foo": {
                        "version": "1.0.0",
                        "resolved": "https://registry.npmjs.org/foo/-/foo-1.0.0.tgz",
                        "integrity": sha512_sri(b"foo")
                    }
                }
            }),
        );
        let pkg = d.path().join("node_modules/foo");
        fs::create_dir_all(&pkg).unwrap();
        let planted = d.path().join("planted.json");
        fs::write(&planted, json!({"version": "1.0.0"}).to_string()).unwrap();
        symlink(&planted, pkg.join("package.json")).unwrap();

        let err = verify(&opts(d.path())).unwrap_err();
        match err {
            FuziError::VerifyFailed { problems } => {
                assert_eq!(problems[0].kind, VerifyProblemKind::VersionMismatch);
                assert_eq!(
                    problems[0].detail,
                    "expected version 1.0.0, but package.json is missing, unreadable, or has no version"
                );
            }
            other => panic!("expected VerifyFailed, got {other:?}"),
        }
    }

    #[test]
    fn version_mismatch_fails() {
        let d = TempDir::new().unwrap();
        write_lock(
            d.path(),
            &json!({
                "lockfileVersion": 3,
                "packages": {
                    "node_modules/foo": {
                        "version": "2.0.0",
                        "resolved": "https://registry.npmjs.org/foo/-/foo-2.0.0.tgz",
                        "integrity": sha512_sri(b"foo")
                    }
                }
            }),
        );
        write_pkg(d.path(), "foo", "1.0.0"); // on-disk differs from lock
        let err = verify(&opts(d.path())).unwrap_err();
        match err {
            FuziError::VerifyFailed { problems } => {
                assert_eq!(problems[0].kind, VerifyProblemKind::VersionMismatch);
            }
            other => panic!("expected VerifyFailed, got {other:?}"),
        }
    }

    // --- links ---

    /// `<w>/app` with a lock linking `node_modules/@s/lib` to `<w>/lib`, the
    /// target's manifest named `lib`. Returns (workspace, app dir).
    fn link_project(target_name: &str) -> (TempDir, std::path::PathBuf) {
        let w = TempDir::new().unwrap();
        let app = w.path().join("app");
        fs::create_dir(&app).unwrap();
        write_lock(
            &app,
            &json!({
                "lockfileVersion": 3,
                "packages": {
                    "": {"name": "app"},
                    "node_modules/@s/lib": {"resolved": "../lib", "link": true},
                    "../lib": {"name": "lib", "version": "1.0.0"}
                }
            }),
        );
        let lib = w.path().join("lib");
        fs::create_dir(&lib).unwrap();
        fs::write(
            lib.join("package.json"),
            json!({"name": target_name, "version": "1.0.0"}).to_string(),
        )
        .unwrap();
        fs::create_dir_all(app.join("node_modules/@s")).unwrap();
        (w, app)
    }

    fn link_problem(app: &Path) -> VerifyProblem {
        match verify(&opts(app)).unwrap_err() {
            FuziError::VerifyFailed { mut problems } => {
                assert_eq!(problems.len(), 1, "{problems:?}");
                let p = problems.remove(0);
                assert_eq!(p.kind, VerifyProblemKind::LinkMismatch);
                p
            }
            other => panic!("expected VerifyFailed, got {other:?}"),
        }
    }

    #[test]
    fn correct_link_verifies() {
        let (_w, app) = link_project("lib");
        symlink("../../../lib", app.join("node_modules/@s/lib")).unwrap();
        let report = verify(&opts(&app)).unwrap();
        assert_eq!(report.links_checked, 1);
        assert_eq!(report.checked, 0);
    }

    #[test]
    fn missing_link_is_a_link_mismatch() {
        let (_w, app) = link_project("lib");
        assert!(link_problem(&app).detail.contains("absent"));
    }

    #[test]
    fn real_directory_instead_of_link_is_a_link_mismatch() {
        let (_w, app) = link_project("lib");
        fs::create_dir(app.join("node_modules/@s/lib")).unwrap();
        fs::write(
            app.join("node_modules/@s/lib/package.json"),
            json!({"name": "lib", "version": "1.0.0"}).to_string(),
        )
        .unwrap();
        assert!(link_problem(&app).detail.contains("not a symlink"));
    }

    #[test]
    fn link_pointing_elsewhere_is_a_link_mismatch() {
        // An absolute link to the right directory still fails: the text must be
        // exactly what install writes.
        let (w, app) = link_project("lib");
        symlink(w.path().join("lib"), app.join("node_modules/@s/lib")).unwrap();
        assert!(link_problem(&app).detail.contains("points at"));
    }

    #[test]
    fn link_whose_target_names_another_package_is_a_link_mismatch() {
        let (_w, app) = link_project("impostor");
        symlink("../../../lib", app.join("node_modules/@s/lib")).unwrap();
        assert!(link_problem(&app).detail.contains("impostor"));
    }

    // --- parent directories ---

    fn problems_of(err: FuziError) -> Vec<VerifyProblem> {
        match err {
            FuziError::VerifyFailed { problems } => problems,
            other => panic!("expected VerifyFailed, got {other:?}"),
        }
    }

    #[test]
    fn symlinked_scope_dir_of_a_link_fails_verify() {
        // The link itself is lstat-correct — a symlink with exactly the text
        // install writes — but its `@s` parent is a symlink to a decoy
        // directory, so the tree under `node_modules/@s` is not the tree fuzi
        // built.
        let (_w, app) = link_project("lib");
        fs::remove_dir(app.join("node_modules/@s")).unwrap();
        let decoy = app.join("decoy");
        fs::create_dir(&decoy).unwrap();
        symlink("../../../lib", decoy.join("lib")).unwrap();
        symlink("../decoy", app.join("node_modules/@s")).unwrap();
        assert!(
            fs::symlink_metadata(app.join("node_modules/@s/lib"))
                .unwrap()
                .file_type()
                .is_symlink(),
            "sanity: the link is found through the symlinked parent"
        );

        let problems = problems_of(verify(&opts(&app)).unwrap_err());
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert_eq!(problems[0].kind, VerifyProblemKind::ParentNotDirectory);
        assert_eq!(problems[0].package, "node_modules/@s");
        assert!(problems[0].detail.contains("symlink"), "{problems:?}");
    }

    #[test]
    fn symlinked_node_modules_fails_verify() {
        // A whole correct tree, reached through a symlinked `node_modules`.
        let (_w, app) = link_project("lib");
        symlink("../../../lib", app.join("node_modules/@s/lib")).unwrap();
        verify(&opts(&app)).unwrap();
        fs::rename(app.join("node_modules"), app.join("real-nm")).unwrap();
        symlink("real-nm", app.join("node_modules")).unwrap();

        let err = verify(&opts(&app)).unwrap_err();
        assert_eq!(err.exit_code(), 65);
        let problems = problems_of(err);
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert_eq!(problems[0].kind, VerifyProblemKind::ParentNotDirectory);
        assert_eq!(problems[0].package, "node_modules");
    }

    #[test]
    fn node_modules_that_is_a_file_fails_verify() {
        let (_w, app) = link_project("lib");
        fs::remove_dir_all(app.join("node_modules")).unwrap();
        fs::write(app.join("node_modules"), b"").unwrap();
        let problems = problems_of(verify(&opts(&app)).unwrap_err());
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert_eq!(problems[0].kind, VerifyProblemKind::ParentNotDirectory);
    }

    #[test]
    fn symlinked_parents_of_registry_packages_fail_verify() {
        // The same rule for extracted packages: a scope directory or a nested
        // `node_modules` that is a symlink, with real, version-matching package
        // directories behind it. Each bad parent is reported once, however many
        // packages sit under it.
        let d = TempDir::new().unwrap();
        let entry = |name: &str| {
            json!({
                "version": "1.0.0",
                "resolved": format!("https://registry.npmjs.org/{name}/-/{name}-1.0.0.tgz"),
                "integrity": sha512_sri(name.as_bytes())
            })
        };
        write_lock(
            d.path(),
            &json!({
                "lockfileVersion": 3,
                "packages": {
                    "node_modules/@s/a": entry("a"),
                    "node_modules/@s/b": entry("b"),
                    "node_modules/p": entry("p"),
                    "node_modules/p/node_modules/c": entry("c"),
                    "node_modules/plain": entry("plain")
                }
            }),
        );
        for rel in ["@s/a", "@s/b", "p", "p/node_modules/c", "plain"] {
            write_pkg(d.path(), rel, "1.0.0");
        }
        let report = verify_here(d.path(), &host_linux_x64_glibc(), &[]).unwrap();
        assert_eq!(report.checked, 5);

        let nm = d.path().join("node_modules");
        fs::rename(nm.join("@s"), d.path().join("scope")).unwrap();
        symlink("../scope", nm.join("@s")).unwrap();
        fs::rename(nm.join("p/node_modules"), d.path().join("nested")).unwrap();
        symlink("../../nested", nm.join("p/node_modules")).unwrap();
        assert!(nm.join("@s/a/package.json").is_file(), "sanity: resolves");
        assert!(nm.join("p/node_modules/c/package.json").is_file());

        let problems =
            problems_of(verify_here(d.path(), &host_linux_x64_glibc(), &[]).unwrap_err());
        let got: Vec<(&str, VerifyProblemKind)> = problems
            .iter()
            .map(|p| (p.package.as_str(), p.kind))
            .collect();
        assert_eq!(
            got,
            [
                ("node_modules/@s", VerifyProblemKind::ParentNotDirectory),
                (
                    "node_modules/p/node_modules",
                    VerifyProblemKind::ParentNotDirectory
                ),
            ]
        );
    }

    /// `esbuild` and its host platform variant under the `@esbuild` scope, both
    /// installed; plus `esbuild/node_modules/inner`. Returns the project dir.
    fn platform_tree() -> TempDir {
        let d = TempDir::new().unwrap();
        write_lock(
            d.path(),
            &json!({
                "lockfileVersion": 3,
                "packages": {
                    "node_modules/esbuild": {
                        "version": "0.20.0",
                        "resolved": "https://registry.npmjs.org/esbuild/-/esbuild-0.20.0.tgz",
                        "integrity": sha512_sri(b"esbuild"),
                        "optionalDependencies": {"@esbuild/linux-x64": "0.20.0"}
                    },
                    "node_modules/esbuild/node_modules/inner": {
                        "version": "1.0.0",
                        "resolved": "https://registry.npmjs.org/inner/-/inner-1.0.0.tgz",
                        "integrity": sha512_sri(b"inner")
                    },
                    "node_modules/@esbuild/linux-x64": {
                        "version": "0.20.0",
                        "resolved": "https://registry.npmjs.org/@esbuild/linux-x64/-/linux-x64-0.20.0.tgz",
                        "integrity": sha512_sri(b"linux-x64"),
                        "cpu": ["x64"], "os": ["linux"], "optional": true
                    }
                }
            }),
        );
        write_pkg(d.path(), "esbuild", "0.20.0");
        write_pkg(d.path(), "esbuild/node_modules/inner", "1.0.0");
        write_pkg(d.path(), "@esbuild/linux-x64", "0.20.0");
        let report = verify_here(d.path(), &host_linux_x64_glibc(), &[]).unwrap();
        assert_eq!((report.checked, report.platform_parents_checked), (3, 1));
        d
    }

    #[test]
    fn symlinked_scope_of_a_platform_variant_is_one_problem_not_a_lockfile_complaint() {
        // With `@esbuild` a symlink the variant is not counted present. The
        // platform assertion would then say the lockfile supplies no binary for
        // this host and advise regenerating it — wrong on both counts — so it
        // does not run once a parent is found not to be a directory.
        let d = platform_tree();
        let nm = d.path().join("node_modules");
        fs::rename(nm.join("@esbuild"), d.path().join("scope")).unwrap();
        symlink("../scope", nm.join("@esbuild")).unwrap();

        let problems =
            problems_of(verify_here(d.path(), &host_linux_x64_glibc(), &[]).unwrap_err());
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert_eq!(problems[0].kind, VerifyProblemKind::ParentNotDirectory);
        assert_eq!(problems[0].package, "node_modules/@esbuild");
    }

    #[test]
    fn absent_platform_variant_still_fails_the_platform_assertion() {
        // Pin: the skip is for a parent that is *not a directory*. A variant
        // that is simply absent is still missing and still fails the assertion.
        let d = platform_tree();
        fs::remove_dir_all(d.path().join("node_modules/@esbuild")).unwrap();
        let problems =
            problems_of(verify_here(d.path(), &host_linux_x64_glibc(), &[]).unwrap_err());
        let kinds: Vec<VerifyProblemKind> = problems.iter().map(|p| p.kind).collect();
        assert_eq!(
            kinds,
            [
                VerifyProblemKind::Missing,
                VerifyProblemKind::MissingPlatformBinary
            ]
        );
    }

    #[test]
    fn symlinked_platform_variant_is_missing_alone() {
        // Pin: a package that is there as a symlink blocks the platform
        // assertion too, so the one problem is its own `missing` — not that
        // plus a "regenerate the lockfile" complaint about an edited tree.
        let d = platform_tree();
        let nm = d.path().join("node_modules");
        fs::rename(nm.join("@esbuild/linux-x64"), d.path().join("moved")).unwrap();
        symlink("../../moved", nm.join("@esbuild/linux-x64")).unwrap();

        let problems =
            problems_of(verify_here(d.path(), &host_linux_x64_glibc(), &[]).unwrap_err());
        let got: Vec<(&str, VerifyProblemKind)> = problems
            .iter()
            .map(|p| (p.package.as_str(), p.kind))
            .collect();
        assert_eq!(
            got,
            [(
                "node_modules/@esbuild/linux-x64",
                VerifyProblemKind::Missing
            )]
        );
    }

    #[test]
    fn symlinked_enclosing_package_is_reported_once() {
        // `node_modules/esbuild` is both a package and the parent of the
        // package nested in it. As a symlink it is one problem — the package's
        // own — not that plus a parent problem on the same path, and the nested
        // package is not reported at all.
        let d = platform_tree();
        let nm = d.path().join("node_modules");
        fs::rename(nm.join("esbuild"), d.path().join("moved")).unwrap();
        symlink("../moved", nm.join("esbuild")).unwrap();
        assert!(
            nm.join("esbuild/node_modules/inner/package.json").is_file(),
            "sanity: resolves"
        );

        let problems =
            problems_of(verify_here(d.path(), &host_linux_x64_glibc(), &[]).unwrap_err());
        let got: Vec<(&str, VerifyProblemKind)> = problems
            .iter()
            .map(|p| (p.package.as_str(), p.kind))
            .collect();
        assert_eq!(got, [("node_modules/esbuild", VerifyProblemKind::Missing)]);
    }

    #[test]
    fn problem_kinds_serialize_as_stable_snake_case() {
        for (kind, wire) in [
            (VerifyProblemKind::Missing, "missing"),
            (VerifyProblemKind::VersionMismatch, "version_mismatch"),
            (
                VerifyProblemKind::MissingPlatformBinary,
                "missing_platform_binary",
            ),
            (VerifyProblemKind::LinkMismatch, "link_mismatch"),
            (
                VerifyProblemKind::ParentNotDirectory,
                "parent_not_directory",
            ),
        ] {
            assert_eq!(serde_json::to_value(kind).unwrap(), json!(wire));
        }
    }

    #[test]
    fn absent_parent_is_still_a_missing_package_not_a_parent_problem() {
        // Pin: a scope directory that is simply not there reads as the packages
        // under it being missing — only a parent that exists as something else
        // is a parent problem.
        let d = TempDir::new().unwrap();
        write_lock(
            d.path(),
            &json!({
                "lockfileVersion": 3,
                "packages": {
                    "node_modules/@s/a": {
                        "version": "1.0.0",
                        "resolved": "https://registry.npmjs.org/a/-/a-1.0.0.tgz",
                        "integrity": sha512_sri(b"a")
                    }
                }
            }),
        );
        fs::create_dir(d.path().join("node_modules")).unwrap();
        let problems =
            problems_of(verify_here(d.path(), &host_linux_x64_glibc(), &[]).unwrap_err());
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert_eq!(problems[0].kind, VerifyProblemKind::Missing);
    }

    // --- linked bins ---

    /// [`link_project`] whose target declares `run` → `bin/run.js` (executable)
    /// and `plain` → `bin/plain.js` (not), with the link and the one `.bin`
    /// entry an install writes. Returns (workspace, app dir).
    fn link_project_with_bins() -> (TempDir, std::path::PathBuf) {
        use std::os::unix::fs::PermissionsExt as _;
        let (w, app) = link_project("lib");
        write_lock(
            &app,
            &json!({
                "lockfileVersion": 3,
                "packages": {
                    "": {"name": "app"},
                    "node_modules/@s/lib": {"resolved": "../lib", "link": true},
                    "../lib": {
                        "name": "lib", "version": "1.0.0",
                        "bin": {"run": "bin/run.js", "plain": "bin/plain.js"}
                    }
                }
            }),
        );
        let bin = w.path().join("lib/bin");
        fs::create_dir(&bin).unwrap();
        for (name, mode) in [("run.js", 0o755), ("plain.js", 0o644)] {
            fs::write(bin.join(name), b"#!/usr/bin/env node\n").unwrap();
            fs::set_permissions(bin.join(name), fs::Permissions::from_mode(mode)).unwrap();
        }
        symlink("../../../lib", app.join("node_modules/@s/lib")).unwrap();
        fs::create_dir(app.join("node_modules/.bin")).unwrap();
        symlink("../@s/lib/bin/run.js", app.join("node_modules/.bin/run")).unwrap();
        (w, app)
    }

    #[test]
    fn correct_linked_bin_verifies() {
        // The executable bin is expected; the non-executable one install skips
        // is not.
        let (_w, app) = link_project_with_bins();
        let report = verify(&opts(&app)).unwrap();
        assert_eq!(report.links_checked, 1);
        assert_eq!(report.link_bins_checked, 1);
    }

    #[test]
    fn linked_bin_pointing_elsewhere_is_a_link_mismatch() {
        let (w, app) = link_project_with_bins();
        let run = app.join("node_modules/.bin/run");
        fs::remove_file(&run).unwrap();
        // An absolute path to the very same file still fails: the text is exact.
        symlink(w.path().join("lib/bin/run.js"), &run).unwrap();
        let p = link_problem(&app);
        assert_eq!(p.package, "node_modules/@s/lib");
        assert!(p.detail.contains(".bin/run points at"), "{}", p.detail);
    }

    #[test]
    fn missing_or_non_symlink_linked_bin_is_a_link_mismatch() {
        let (_w, app) = link_project_with_bins();
        let run = app.join("node_modules/.bin/run");
        fs::remove_file(&run).unwrap();
        assert!(link_problem(&app).detail.contains(".bin/run is absent"));
        fs::write(&run, b"#!/bin/sh\n").unwrap();
        assert!(
            link_problem(&app)
                .detail
                .contains(".bin/run is not a symlink")
        );
        // No `.bin` at all reads the same as the entry being absent.
        fs::remove_dir_all(app.join("node_modules/.bin")).unwrap();
        assert!(link_problem(&app).detail.contains(".bin/run is absent"));
    }

    #[test]
    fn symlinked_dot_bin_fails_verify() {
        let (_w, app) = link_project_with_bins();
        let nm = app.join("node_modules");
        fs::rename(nm.join(".bin"), app.join("bins")).unwrap();
        symlink("../bins", nm.join(".bin")).unwrap();
        let problems = problems_of(verify(&opts(&app)).unwrap_err());
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert_eq!(problems[0].kind, VerifyProblemKind::ParentNotDirectory);
        assert_eq!(problems[0].package, "node_modules/.bin");
    }

    #[test]
    fn linked_bin_expectation_follows_install_on_a_shared_command() {
        // Two links declaring `run`: install writes them in lockfile-key order,
        // so the later key's shim is the one in `.bin`.
        let (w, app) = link_project_with_bins();
        let mut lock: serde_json::Value =
            serde_json::from_slice(&fs::read(app.join("package-lock.json")).unwrap()).unwrap();
        lock["packages"]["node_modules/zed"] = json!({"resolved": "../zed", "link": true});
        lock["packages"]["../zed"] = json!({"name": "zed", "bin": {"run": "run.js"}});
        write_lock(&app, &lock);
        let zed = w.path().join("zed");
        fs::create_dir(&zed).unwrap();
        fs::write(zed.join("package.json"), json!({"name": "zed"}).to_string()).unwrap();
        fs::copy(w.path().join("lib/bin/run.js"), zed.join("run.js")).unwrap();
        symlink("../../zed", app.join("node_modules/zed")).unwrap();

        // `.bin/run` still names the earlier link's bin.
        let p = link_problem(&app);
        assert_eq!(p.package, "node_modules/zed");
        assert!(p.detail.contains("expected ../zed/run.js"), "{}", p.detail);

        let run = app.join("node_modules/.bin/run");
        fs::remove_file(&run).unwrap();
        symlink("../zed/run.js", &run).unwrap();
        let report = verify(&opts(&app)).unwrap();
        assert_eq!(report.link_bins_checked, 1);
    }

    #[test]
    fn platform_binary_present_verifies() {
        // esbuild + its host-matching @esbuild/linux-x64 both installed. Pinned
        // to the fixed linux/x64/glibc test host: probing the *real* host made
        // this assert nothing on a darwin or arm64 dev box (the lock's variant
        // would be platform-skipped instead), so the check silently stopped
        // running off the CI architecture.
        let d = TempDir::new().unwrap();
        write_lock(
            d.path(),
            &json!({
                "lockfileVersion": 3,
                "packages": {
                    "node_modules/esbuild": {
                        "version": "0.20.0",
                        "resolved": "https://registry.npmjs.org/esbuild/-/esbuild-0.20.0.tgz",
                        "integrity": sha512_sri(b"esbuild"),
                        "optionalDependencies": {"@esbuild/linux-x64": "0.20.0"}
                    },
                    "node_modules/@esbuild/linux-x64": {
                        "version": "0.20.0",
                        "resolved": "https://registry.npmjs.org/@esbuild/linux-x64/-/linux-x64-0.20.0.tgz",
                        "integrity": sha512_sri(b"linux-x64"),
                        "cpu": ["x64"], "os": ["linux"], "optional": true
                    }
                }
            }),
        );
        write_pkg(d.path(), "esbuild", "0.20.0");
        write_pkg(d.path(), "@esbuild/linux-x64", "0.20.0");
        let report = verify_here(d.path(), &host_linux_x64_glibc(), &[]).unwrap();
        assert_eq!(report.platform_parents_checked, 1);
        assert_eq!(report.checked, 2);
    }

    #[test]
    fn off_host_optional_is_not_asserted() {
        // The fsevents-class case: vite declares a darwin-only optional. On a
        // non-darwin host there is no host binary to install — correctly absent,
        // NOT a failure. (Modeled with an os no real host matches so the test is
        // host-independent.) The assertion must not fire.
        let d = TempDir::new().unwrap();
        write_lock(
            d.path(),
            &json!({
                "lockfileVersion": 3,
                "packages": {
                    "node_modules/watcher": {
                        "version": "1.0.0",
                        "resolved": "https://registry.npmjs.org/watcher/-/watcher-1.0.0.tgz",
                        "integrity": sha512_sri(b"watcher"),
                        "optionalDependencies": {"@watcher/aix-ppc64": "1.0.0"}
                    },
                    "node_modules/@watcher/aix-ppc64": {
                        "version": "1.0.0",
                        "resolved": "https://registry.npmjs.org/@watcher/aix-ppc64/-/aix-ppc64-1.0.0.tgz",
                        "integrity": sha512_sri(b"aix-ppc64"),
                        "cpu": ["ppc64"], "os": ["aix"], "optional": true
                    }
                }
            }),
        );
        write_pkg(d.path(), "watcher", "1.0.0");
        let report = verify(&opts(d.path())).unwrap();
        assert_eq!(
            report.platform_parents_checked, 0,
            "off-host optional must not be asserted"
        );
    }

    #[test]
    fn wrong_libc_lock_fails() {
        // A lock whose only linux-x64 variant carries the *other* libc — the
        // classic glibc-lock-installed-on-musl (or vice-versa). The host's
        // os+cpu match, so a binary is expected, but the libc-matching variant
        // is absent → MissingPlatformBinary. Pinned to the fixed glibc test host
        // rather than probed: on anything that is not a libc-bearing linux-x64
        // box a probing test would `return` and pass having asserted nothing — the
        // one check the whole platform assertion exists for.
        let other_libc = "musl";
        let d = TempDir::new().unwrap();
        write_lock(
            d.path(),
            &json!({
                "lockfileVersion": 3,
                "packages": {
                    "node_modules/rollup": {
                        "version": "4.0.0",
                        "resolved": "https://registry.npmjs.org/rollup/-/rollup-4.0.0.tgz",
                        "integrity": sha512_sri(b"rollup"),
                        "optionalDependencies": {"@rollup/rollup-linux-x64": "4.0.0"}
                    },
                    "node_modules/@rollup/rollup-linux-x64": {
                        "version": "4.0.0",
                        "resolved": "https://registry.npmjs.org/@rollup/rollup-linux-x64/-/rollup-linux-x64-4.0.0.tgz",
                        "integrity": sha512_sri(b"rollup-linux-x64"),
                        "cpu": ["x64"], "os": ["linux"], "libc": [other_libc], "optional": true
                    }
                }
            }),
        );
        write_pkg(d.path(), "rollup", "4.0.0");
        // The off-libc variant is platform-skipped (not a placement), so the only
        // surfaced problem is the platform assertion, not a generic Missing.
        let err = verify_here(d.path(), &host_linux_x64_glibc(), &[]).unwrap_err();
        match err {
            FuziError::VerifyFailed { problems } => {
                assert!(
                    problems
                        .iter()
                        .any(|p| p.kind == VerifyProblemKind::MissingPlatformBinary),
                    "expected MissingPlatformBinary, got {problems:?}"
                );
            }
            other => panic!("expected VerifyFailed, got {other:?}"),
        }
    }

    #[test]
    fn platform_variant_absent_under_omit_optional_verifies() {
        // Regression: `fuzi install --omit optional` produces a tree WITHOUT the
        // host platform variant (it is an optionalDependency, so the whole class is
        // dropped). `fuzi verify --omit optional` must accept that tree — a
        // platform assertion that ignored `omit` would demand the variant anyway,
        // emitting a MissingPlatformBinary that contradicts the plan the same
        // `build_plan(raw, host, &[Omit::Optional])` call produced. Same esbuild
        // lock as `platform_binary_present_verifies`, but the variant is NOT
        // materialized.
        let d = TempDir::new().unwrap();
        write_lock(
            d.path(),
            &json!({
                "lockfileVersion": 3,
                "packages": {
                    "node_modules/esbuild": {
                        "version": "0.20.0",
                        "resolved": "https://registry.npmjs.org/esbuild/-/esbuild-0.20.0.tgz",
                        "integrity": sha512_sri(b"esbuild"),
                        "optionalDependencies": {"@esbuild/linux-x64": "0.20.0"}
                    },
                    "node_modules/@esbuild/linux-x64": {
                        "version": "0.20.0",
                        "resolved": "https://registry.npmjs.org/@esbuild/linux-x64/-/linux-x64-0.20.0.tgz",
                        "integrity": sha512_sri(b"linux-x64"),
                        "cpu": ["x64"], "os": ["linux"], "optional": true
                    }
                }
            }),
        );
        write_pkg(d.path(), "esbuild", "0.20.0"); // the variant is deliberately absent
        let report = verify_here(d.path(), &host_linux_x64_glibc(), &[Omit::Optional]).unwrap();
        assert_eq!(
            report.platform_parents_checked, 0,
            "under --omit optional the platform assertion must not fire"
        );
        assert_eq!(report.checked, 1); // only esbuild is a placement under --omit optional
    }

    #[test]
    fn omit_optional_still_reports_missing_required() {
        // The `--omit optional` skip is scoped to the *platform assertion*, not the
        // presence check: a required (non-optional, non-omitted) package that is
        // absent from the tree is still `Missing` under --omit optional.
        let d = TempDir::new().unwrap();
        write_lock(
            d.path(),
            &json!({
                "lockfileVersion": 3,
                "packages": {
                    "node_modules/prod": {
                        "version": "1.0.0",
                        "resolved": "https://registry.npmjs.org/prod/-/prod-1.0.0.tgz",
                        "integrity": sha512_sri(b"prod")
                    }
                }
            }),
        );
        // node_modules/prod deliberately absent from an installed tree.
        fs::create_dir(d.path().join("node_modules")).unwrap();
        let err = verify_here(d.path(), &host_linux_x64_glibc(), &[Omit::Optional]).unwrap_err();
        match err {
            FuziError::VerifyFailed { problems } => {
                assert_eq!(problems.len(), 1);
                assert_eq!(problems[0].kind, VerifyProblemKind::Missing);
            }
            other => panic!("expected VerifyFailed, got {other:?}"),
        }
    }
}
