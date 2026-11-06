//! fuzi core — the lockfile-driven npm installer's engine.
//!
//! Reads an existing `package-lock.json` (v2 or v3), verifies and
//! content-addresses npm tarballs into a local cache under
//! `~/.fuz/cache/npm/`, then materializes `node_modules`. No resolver, no
//! install/lifecycle scripts, no compilation — the mechanical half of a
//! package manager. The `fuzi` binary is a thin CLI over this crate.
//!
//! The npm trees fuzi installs are *unsealed* (trust-anchored by npm's own
//! `integrity` metadata, not an @fuzdev signature); the fuzi binary itself
//! is sealed.
//!
//! # Pipeline and extension points
//!
//! The engine is three pure stages: `read_lockfile` (lenient serde + the
//! `lockfileVersion` gate) → `classify` (per-entry disposition, accumulating
//! refusals rather than failing fast) → `build_plan` (assemble the
//! dedup-by-`Integrity` `fetch_set`, the depth-sorted `placements`, and the
//! sibling `links`). Then the effects: `check_link_targets` (every sibling
//! `link: true` target name-checked through a bounded no-follow `package.json`
//! read) and `check_node_modules_target` (no symlinked, non-directory, or
//! mounted `node_modules`), both before any network and under `--dry-run` too
//! → the fetch phase →
//! `materialize` (extract every placement, *then* place the links as relative
//! symlinks, link the bins, check the link targets once more, check the tree is
//! complete, swap). A link target is local source fuzi never writes to — no
//! extraction through it, no chmod of its bins. The `link` module's docs carry the link threat notes.
//!
//! Lockfile and sibling text is untrusted in two ways the `text` module owns:
//! a name fuzi would create is refused when it holds the wrong characters (a
//! placed key anything but npm's package-name characters; a link's sibling
//! segment or a bin's command or target a control or invisible character), and
//! every human rendering of a payload string goes through
//! [`fuz_sys::text::escape_untrusted`].
//!
//! `InstallPlan` is the stable, format-agnostic seam. The second lockfile
//! format, `fuzi.lock`, plugs in as another *producer* of `InstallPlan`, not
//! behind a reader trait; the fetch / extract / `node_modules` materialization work attaches
//! *downstream* by consuming `fetch_set`, `placements`, and `links`. The heterogeneous
//! lockfile entry is modeled by `EntryDisposition` alone — there is
//! deliberately no parallel "kind of entry" enum to keep in sync.

mod cache;
mod classify;
mod clean;
mod drift;
mod entry;
mod error;
mod extract;
mod fetch;
mod interrupt;
mod link;
mod lockfile;
mod materialize;
mod plan;
mod platform;
mod prune;
mod report;
mod resolved;
mod staging;
#[cfg(test)]
mod test_support;
mod text;
mod verify;

// Every type that appears in an exported signature is itself exported — a
// `pub` item in a private module is otherwise unnameable to a consumer (e.g. a
// `PackagePlacement`'s `bins` map, or whatever `InstallPath::containment` returns).
pub use cache::{CacheError, MAX_NPM_TARBALL_SIZE, NpmCache};
pub use classify::{EntryDisposition, Refusal, RefuseReason, classify};
pub use clean::{CleanReport, SkippedArtifact, clean};
pub use drift::{DriftReport, drift_against, drift_check};
pub use entry::{
    BinCommand, BinTarget, Containment, InstallPath, Integrity, IntegrityParse, LinkEntry,
    LinkTarget, LinkTargetParse, RegistryEntry,
};
pub use error::{
    CorruptCacheItem, EX_NOINPUT, EX_USAGE, FetchFailure, FuziError, IntegrityMismatchItem,
    LinkTargetProblem, NodeModulesObstruction, ProjectFile, StagingEntry,
};
pub use extract::{
    MAX_NPM_EXTRACTED_FILE, MAX_NPM_EXTRACTED_TOTAL, MAX_NPM_HEADER_SIZE, MAX_NPM_PATH_LENGTH,
    extract_package,
};
pub use fetch::{
    ClientInitError, DEFAULT_FETCH_CONCURRENCY, FetchError, FixtureSource, NpmTarballSource,
    TarballSource, run_fetch_phase,
};
// Re-export the archive types fuzi's public surface returns/carries, so `fuzi`
// doesn't depend on `fuz_archive` directly.
pub use fuz_archive::{ArchiveError, ExtractReport, ExtractedFile};
pub use interrupt::{DrainReport, drain_fired, drain_staging_roots};
pub use link::{MAX_LINK_PACKAGE_JSON, check_link_targets};
pub use lockfile::{
    KNOWN_INERT_ENTRY_FIELDS, RawLockfile, RawPackageEntry, parse_lockfile, read_lockfile,
    unknown_entry_fields,
};
pub use materialize::materialize;
pub use plan::{
    FetchInfo, InstallPlan, LinkPlacement, PackagePlacement, build_plan, build_plan_with_drift,
};
pub use platform::{
    Cpu, Libc, Os, Platform, PlatformToken, parse_cpu_axis, parse_libc_axis, parse_os_axis,
};
pub use prune::reachable_set;
pub use report::{FetchOutcome, InstallReport};
pub use staging::{StagingDir, StagingTree, check_node_modules_target};
pub use verify::{VerifyProblem, VerifyProblemKind, VerifyReport, verify, verify_against};

use std::path::PathBuf;

use cache::CacheProbe;
use fetch::PackageLabels;

/// Dependency classes a `fuzi install` can omit, mirroring npm's `--omit`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Omit {
    /// `devDependencies`.
    Dev,
    /// `optionalDependencies`.
    Optional,
    /// `peerDependencies`.
    Peer,
}

impl std::str::FromStr for Omit {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "dev" => Ok(Self::Dev),
            "optional" => Ok(Self::Optional),
            "peer" => Ok(Self::Peer),
            other => Err(format!(
                "unknown omit value `{other}` (expected `dev`, `optional`, or `peer`)"
            )),
        }
    }
}

/// Inputs for [`install`] — install exactly from the lockfile in `dir`.
// The flags mirror the CLI's install-mode switches (`--dry-run`, `--offline`,
// `--ignore-manifest`); presentation switches (`--json`, `--quiet`,
// `--verbose`) stay in the binary — the core prints nothing.
#[derive(Debug, Clone)]
pub struct InstallOptions {
    /// Project root holding `package.json` + `package-lock.json`.
    pub dir: PathBuf,
    /// Dependency classes to omit (empty = install dev + prod, matching `npm ci`).
    pub omit: Vec<Omit>,
    /// Install the lockfile as-is, skipping the `package.json` drift guard.
    pub ignore_manifest: bool,
    /// Report what would happen without writing `node_modules` or the cache.
    pub dry_run: bool,
    /// Use only cached tarballs; fail on a cache miss.
    pub offline: bool,
}

/// Inputs for [`verify()`] — re-check a materialized `node_modules` against the lockfile.
#[derive(Debug, Clone)]
pub struct VerifyOptions {
    /// Project root holding `package-lock.json` + `node_modules`.
    pub dir: PathBuf,
    /// Dependency classes the tree was installed *without*. Must match the
    /// install's `--omit`: an omitted class is legitimately absent from the
    /// tree, so verifying against the full plan would report every one of its
    /// packages `Missing`.
    pub omit: Vec<Omit>,
}

/// Install exactly from the lockfile into `node_modules`, returning the
/// structured [`InstallReport`] for the binary to render.
///
/// `--dry-run` builds the [`InstallPlan`] (read → version-gate → drift →
/// classify → assemble), runs the link-target and `node_modules` target checks,
/// and reports what *would* happen — probing the cache read-only for
/// cached-vs-would-fetch — without writing `node_modules` or the cache. A dry
/// run runs every pre-network check the real run does, and under `--offline`
/// it is the real run's verdict on the cache — a would-fetch tarball is
/// [`FuziError::OfflineCacheMiss`], a corrupt cached one
/// [`FuziError::OfflineCacheCorrupt`]. Online it re-hashes every cached
/// tarball as the real run does — a corrupt one is would-fetch and listed in
/// [`InstallReport::healed`], an unreadable one is [`FuziError::Io`] — but
/// neither creates the cache nor builds the HTTPS client, so an uncreatable
/// cache directory or a client-init failure surfaces only on the real run.
///
/// A real run additionally runs the **fetch phase** — populating the verified,
/// content-addressed cache under `~/.fuz/cache/npm/` from the plan's
/// `fetch_set` (each tarball downloaded once, hashed, and committed only on a
/// match) — then **materializes** `node_modules`: extracts every placement into
/// a fresh staging tree, places the sibling links, links the `.bin` shims,
/// re-checks the link targets, and atomically swaps the tree into place. The
/// fetch phase is an *async island*: `install` stays synchronous and owns a
/// `tokio` runtime for that phase alone (`block_on`) — the binary is not
/// `#[tokio::main]`; materialization is blocking, synchronous filesystem IO.
///
/// This is [`install_with`] over the real host, cache, and registry source,
/// each set up only once it is needed: the host is detected first; the cache
/// is opened (created, its stale download temps swept) and the HTTPS client
/// built only after every pre-network check passes, and never under
/// `--dry-run`, which reads the cache through a read-only probe. A warm dry run
/// re-hashes the whole cache serially, so it can take longer than the real
/// run's concurrent re-verify.
///
/// Presentation lives in the `fuzi` binary; this function prints nothing.
///
/// # Errors
/// Returns [`FuziError`] when the lockfile cannot be read, the manifest drifts,
/// an entry is refused, a link target or `node_modules` fails its check, the
/// fetch phase fails (transport / integrity / offline miss), or
/// materialization fails (insufficient space / bad tarball / IO), or an
/// interrupt drain fires first (`FuziError::Interrupted`).
pub fn install(options: &InstallOptions) -> Result<InstallReport, FuziError> {
    // Wiring only, twinned with `install_with`: add steps to `prepare` /
    // `fetch_and_materialize`, never here.
    let (host, libc_warning) = Platform::detect();
    let Prepared {
        plan,
        link_warnings,
    } = prepare(options, &host)?;
    let mut report = if options.dry_run {
        let probe = CacheProbe::open_default().map_err(error::io_from_cache)?;
        dry_run_report_with(&plan, &probe, options.offline)?
    } else {
        let cache = NpmCache::open_default().map_err(error::io_from_cache)?;
        let source = if options.offline {
            None
        } else {
            Some(NpmTarballSource::new().map_err(|e| FuziError::HttpClient { reason: e.reason })?)
        };
        fetch_and_materialize(&plan, &options.dir, &cache, source.as_ref())?
    };
    report.libc_warning = libc_warning;
    report.link_warnings = link_warnings;
    Ok(report)
}

/// [`install`] with the host, the cache, and the tarball source injected —
/// the seam a test drives end to end without the network or the user's
/// `~/.fuz`.
///
/// `source` is `None` for an offline install; `options.offline` wins over a
/// `Some` source (the run is offline either way). Under `options.dry_run` the
/// cache is only probed (read-only — presence and a re-hash) and `source` is
/// unused. The report carries no host-detection
/// warning (the host is given, not detected).
///
/// # Errors
/// As [`install`].
pub fn install_with<S: TarballSource>(
    options: &InstallOptions,
    host: &Platform,
    cache: &NpmCache,
    source: Option<&S>,
) -> Result<InstallReport, FuziError> {
    // Wiring only, twinned with `install`: add steps to `prepare` /
    // `fetch_and_materialize`, never here.
    let Prepared {
        plan,
        link_warnings,
    } = prepare(options, host)?;
    let mut report = if options.dry_run {
        dry_run_report_with(&plan, &cache.probe(), options.offline)?
    } else {
        let source = if options.offline { None } else { source };
        fetch_and_materialize(&plan, &options.dir, cache, source)?
    };
    report.link_warnings = link_warnings;
    Ok(report)
}

/// What the pre-network half of an install hands the rest: the plan, and the
/// link-target check's non-fatal warnings.
struct Prepared {
    plan: InstallPlan,
    link_warnings: Vec<String>,
}

/// The pre-network half of an install, shared by the real run and the dry
/// run: read the lockfile, build the plan (drift guard included), check the
/// link targets, and check the `node_modules` target. Touches no cache and no
/// network, and writes nothing.
fn prepare(options: &InstallOptions, host: &Platform) -> Result<Prepared, FuziError> {
    let raw = read_lockfile(&options.dir)?;
    let plan = build_plan_with_drift(&raw, host, options)?;
    // Before any network work, and under --dry-run too: a wrong or missing
    // sibling refuses before anything is fetched.
    let link_warnings = check_link_targets(&plan, &options.dir)?;
    // Fail fast — refuse a symlinked / non-directory node_modules, or a mount
    // point, before doing any network work, and under --dry-run too.
    // `StagingTree::commit` re-checks at publish time (race close).
    check_node_modules_target(&options.dir)?;
    Ok(Prepared {
        plan,
        link_warnings,
    })
}

/// The real run past [`prepare`]: populate the verified CAS, then
/// materialize `node_modules` from it.
fn fetch_and_materialize<S: TarballSource>(
    plan: &InstallPlan,
    dir: &std::path::Path,
    cache: &NpmCache,
    source: Option<&S>,
) -> Result<InstallReport, FuziError> {
    let mut report = fetch_blocking(plan, cache, source)?;
    materialize(plan, cache, dir, &mut report)?;
    fold_plan_counts(&mut report, plan);
    Ok(report)
}

/// The fetch phase's **async island**: build a `tokio` runtime, run the phase on
/// it, and return synchronously.
///
/// Networking is the only async work in an install, so `install` stays sync and
/// owns a runtime for this call alone rather than the binary being
/// `#[tokio::main]` (materialization is blocking filesystem IO on its own thread
/// pool). `--offline` rides the `Option<&S>` seam rather than branching the
/// orchestration: no source means a cache miss is an `OfflineCacheMiss`.
fn fetch_blocking<S: TarballSource>(
    plan: &InstallPlan,
    cache: &NpmCache,
    source: Option<&S>,
) -> Result<InstallReport, FuziError> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(error::io_err("start async runtime"))?;
    runtime.block_on(run_fetch_phase(
        plan,
        cache,
        source,
        DEFAULT_FETCH_CONCURRENCY,
    ))
}

/// Build a `--dry-run` report: what *would* happen. Probes the cache read-only
/// for cached-vs-would-fetch and counts would-place placements; no download,
/// no `node_modules` written, nothing in the cache created, swept, or removed.
///
/// The cache verdict is the real run's: every present tarball is re-hashed
/// ([`CacheProbe::verify`], no unlink). Online, a mismatch is counted
/// would-fetch and listed in [`InstallReport::healed`] (the real run discards
/// and refetches it); offline it is [`FuziError::OfflineCacheCorrupt`]. An
/// unreadable entry is [`FuziError::Io`] either way. Offline, corrupt outranks
/// unreadable as the real run's `outranking` does (the real run can report
/// only what it collected before an unreadable entry aborts it), then a
/// would-fetch tarball as [`FuziError::OfflineCacheMiss`]. Packages are named
/// as the fetch phase names them (sorted). An absent cache directory probes as
/// empty — everything would fetch — where the real run creates it.
///
/// Serial: a warm dry run hashes the whole cache on one thread, where the real
/// run hashes concurrently.
fn dry_run_report_with(
    plan: &InstallPlan,
    cache: &CacheProbe,
    offline: bool,
) -> Result<InstallReport, FuziError> {
    let mut report = InstallReport {
        dry_run: true,
        ..InstallReport::default()
    };
    let labels = PackageLabels::new(plan);
    let mut misses = Vec::new();
    let mut corrupt = Vec::new();
    let mut unreadable = None;
    for integrity in plan.fetch_set.keys() {
        if !cache.contains(integrity) {
            report.fetched += 1; // would fetch
            if offline {
                misses.push(labels.label(integrity));
            }
            continue;
        }
        // Re-hashed online too, as the real run re-verifies every hit.
        match cache.verify(integrity) {
            Ok(()) => report.cached += 1,
            // Online the real run discards and refetches it: would fetch, and
            // reported as healed so the tamper signal is not lost.
            Err(CacheError::Corrupt { .. }) if !offline => {
                report.fetched += 1;
                report.healed.push(labels.label(integrity));
            }
            Err(CacheError::Corrupt { .. }) => corrupt.push(CorruptCacheItem {
                package: labels.label(integrity),
                path: cache.entry_path(integrity).display().to_string(),
            }),
            Err(other) => {
                unreadable.get_or_insert_with(|| error::io_from_cache(other));
            }
        }
    }
    if !corrupt.is_empty() {
        corrupt.sort_by(|a, b| a.package.cmp(&b.package));
        return Err(FuziError::OfflineCacheCorrupt { entries: corrupt });
    }
    if let Some(e) = unreadable {
        return Err(e);
    }
    if !misses.is_empty() {
        misses.sort();
        return Err(FuziError::OfflineCacheMiss { packages: misses });
    }
    report.healed.sort();
    report.placed = plan.placements.len(); // would place
    report.linked = plan.links.len(); // would link
    // Would-link: every *declared* bin. An upper bound — a real run additionally
    // skips bins whose target file the tarball turns out not to ship (or, for a
    // linked package, that is not already a plain executable file) — but far
    // more honest than a flat `0`.
    report.bins_linked = plan.placements.iter().map(|p| p.bins.len()).sum::<usize>()
        + plan.links.iter().map(|l| l.bins.len()).sum::<usize>();
    fold_plan_counts(&mut report, plan);
    Ok(report)
}

/// Fold the plan's informational counts (platform-skipped optionals, skipped
/// install-script package names) into a report. Shared by the real and dry-run
/// paths so both surfaces report identically.
fn fold_plan_counts(report: &mut InstallReport, plan: &InstallPlan) {
    report.skipped_optional = plan.skipped.len();
    report
        .unknown_entry_fields
        .clone_from(&plan.unknown_entry_fields);
    // Distinct package names: a package present at multiple depths (e.g. a hoisted
    // `esbuild` and a nested `vite/node_modules/esbuild`) skips the same install
    // script, so collapse the names rather than reporting `esbuild` twice. Order
    // follows the depth-sorted plan (deterministic); the set only de-dups.
    let mut seen = std::collections::BTreeSet::new();
    report.skipped_scripts = plan
        .skipped_scripts
        .iter()
        .map(|p| p.package_portion().to_string())
        .filter(|name| seen.insert(name.clone()))
        .collect();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn omit_parses_known_values() {
        assert_eq!("dev".parse::<Omit>(), Ok(Omit::Dev));
        assert_eq!("optional".parse::<Omit>(), Ok(Omit::Optional));
        assert_eq!("peer".parse::<Omit>(), Ok(Omit::Peer));
    }

    #[test]
    fn omit_rejects_unknown_value() {
        assert!("prod".parse::<Omit>().is_err());
    }

    #[test]
    fn dry_run_counts_links_and_their_declared_bins() {
        let raw: RawLockfile = serde_json::from_value(serde_json::json!({
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "app"},
                "node_modules/lib": {"resolved": "../lib", "link": true},
                "../lib": {"name": "lib", "bin": {"lib": "cli.js"}}
            }
        }))
        .unwrap();
        let plan = build_plan(&raw, &test_support::host_linux_x64_glibc(), &[]).unwrap();
        let absent = tempfile::tempdir().unwrap();
        let probe = CacheProbe::at(absent.path().join("npm"));
        let report = dry_run_report_with(&plan, &probe, false).unwrap();
        assert!(report.dry_run);
        assert_eq!(report.linked, 1);
        assert_eq!(report.placed, 0);
        assert_eq!(report.bins_linked, 1);
    }

    /// `<w>/app` with a `package.json` + lock linking `node_modules/lib` to a
    /// `../lib` that does not exist, beside a registry dep whose `resolved` can
    /// never be fetched (`.invalid` never resolves). Returns (workspace, app).
    fn missing_link_project() -> (tempfile::TempDir, PathBuf) {
        let w = tempfile::tempdir().unwrap();
        let app = w.path().join("app");
        std::fs::create_dir(&app).unwrap();
        let deps = serde_json::json!({"lib": "file:../lib", "x": "1.0.0"});
        std::fs::write(
            app.join("package.json"),
            serde_json::json!({"name": "app", "dependencies": deps}).to_string(),
        )
        .unwrap();
        std::fs::write(
            app.join("package-lock.json"),
            serde_json::json!({
                "lockfileVersion": 3,
                "packages": {
                    "": {"name": "app", "dependencies": deps},
                    "node_modules/lib": {"resolved": "../lib", "link": true},
                    "../lib": {"name": "lib", "version": "1.0.0"},
                    "node_modules/x": {
                        "version": "1.0.0",
                        "resolved": "https://registry.invalid/x/-/x-1.0.0.tgz",
                        "integrity": test_support::sha512_sri(b"x")
                    }
                }
            })
            .to_string(),
        )
        .unwrap();
        (w, app)
    }

    fn options(dir: PathBuf, dry_run: bool) -> InstallOptions {
        InstallOptions {
            dir,
            omit: Vec::new(),
            ignore_manifest: false,
            dry_run,
            offline: false,
        }
    }

    /// The `--ignore-manifest` path skips the drift guard, which would
    /// otherwise catch a lock with no root entry — the reader alone must refuse
    /// a lock with no `packages` map, or the install exits 0 having placed
    /// nothing.
    #[test]
    fn lock_without_packages_map_refuses_under_ignore_manifest() {
        for version in [2, 3] {
            let dir = tempfile::tempdir().unwrap();
            std::fs::write(
                dir.path().join("package-lock.json"),
                serde_json::json!({"lockfileVersion": version}).to_string(),
            )
            .unwrap();
            for dry_run in [true, false] {
                let mut opts = options(dir.path().to_path_buf(), dry_run);
                opts.ignore_manifest = true;
                let err = install(&opts).unwrap_err();
                assert!(matches!(err, FuziError::Lockfile { .. }), "{err:?}");
                assert_eq!(err.exit_code(), 65);
            }
            assert!(!dir.path().join("node_modules").exists());
        }
    }

    #[test]
    fn dry_run_runs_the_link_target_check() {
        let (_w, app) = missing_link_project();
        let err = install(&options(app.clone(), true)).unwrap_err();
        assert!(matches!(err, FuziError::LinkTarget { .. }), "{err:?}");
        assert!(!app.join("node_modules").exists());
    }

    #[test]
    fn link_target_check_runs_before_the_network() {
        // A real run would otherwise reach the fetch phase and fail on the
        // unfetchable registry dep (a `Fetch` error), not on the missing sibling.
        let (_w, app) = missing_link_project();
        let err = install(&options(app.clone(), false)).unwrap_err();
        assert!(matches!(err, FuziError::LinkTarget { .. }), "{err:?}");
        assert!(!app.join("node_modules").exists());
    }

    /// A plan of two registry tarballs, `node_modules/b` and `node_modules/a`
    /// (lockfile order reversed, so the miss list's sort is observable).
    fn two_tarball_plan() -> InstallPlan {
        let entry = |name: &str| {
            serde_json::json!({
                "version": "1.0.0",
                "resolved": format!("https://registry.npmjs.org/{name}/-/{name}-1.0.0.tgz"),
                "integrity": test_support::sha512_sri(name.as_bytes())
            })
        };
        let raw: RawLockfile = serde_json::from_value(serde_json::json!({
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "app"},
                "node_modules/b": entry("b"),
                "node_modules/a": entry("a")
            }
        }))
        .unwrap();
        build_plan(&raw, &test_support::host_linux_x64_glibc(), &[]).unwrap()
    }

    #[test]
    fn offline_dry_run_reports_the_real_runs_cache_miss() {
        let plan = two_tarball_plan();
        // No cache at all, and an empty one: both are the miss the real
        // `--offline` run reports — the same variant, packages sorted.
        let root = tempfile::tempdir().unwrap();
        let absent = CacheProbe::at(root.path().join("absent"));
        let empty = NpmCache::open(root.path().join("npm")).unwrap();
        for probe in [&absent, &empty.probe()] {
            let err = dry_run_report_with(&plan, probe, true).unwrap_err();
            let FuziError::OfflineCacheMiss { packages } = &err else {
                panic!("expected OfflineCacheMiss, got {err:?}");
            };
            assert_eq!(packages, &["node_modules/a", "node_modules/b"]);
            assert_eq!(err.exit_code(), 69);
        }
        // Online, the same probe is a would-fetch count, never an error.
        let report = dry_run_report_with(&plan, &absent, false).unwrap();
        assert_eq!((report.cached, report.fetched), (0, 2));
        assert!(
            !root.path().join("absent").exists(),
            "a probe creates nothing"
        );
    }

    #[test]
    fn offline_dry_run_names_only_the_uncached() {
        let plan = two_tarball_plan();
        let root = tempfile::tempdir().unwrap();
        let cache = NpmCache::open(root.path().join("npm")).unwrap();
        let temp = cache.temp_path();
        std::fs::write(&temp, b"a").unwrap();
        cache
            .commit(&temp, &test_support::integrity_of(b"a"))
            .unwrap();

        let err = dry_run_report_with(&plan, &cache.probe(), true).unwrap_err();
        assert!(
            matches!(&err, FuziError::OfflineCacheMiss { packages } if packages == &["node_modules/b"]),
            "{err:?}"
        );
        // Cache the other one too: the offline dry run then succeeds.
        let temp = cache.temp_path();
        std::fs::write(&temp, b"b").unwrap();
        cache
            .commit(&temp, &test_support::integrity_of(b"b"))
            .unwrap();
        let report = dry_run_report_with(&plan, &cache.probe(), true).unwrap();
        assert_eq!((report.cached, report.fetched), (2, 0));
    }

    /// A dry run is the real run's verdict on the cache: a cached tarball that
    /// fails its key is, under `--offline`, the real run's
    /// `OfflineCacheCorrupt` (65), and online a would-fetch listed in `healed`
    /// — never "cached" — and the entry stays in place either way.
    #[test]
    fn offline_dry_run_reports_the_real_runs_corrupt_cache() {
        let plan = two_tarball_plan();
        let root = tempfile::tempdir().unwrap();
        let cache = NpmCache::open(root.path().join("npm")).unwrap();
        for data in [b"a", b"b"] {
            let temp = cache.temp_path();
            std::fs::write(&temp, data).unwrap();
            cache
                .commit(&temp, &test_support::integrity_of(data))
                .unwrap();
        }
        let entry = cache.entry_path(&test_support::integrity_of(b"b"));
        std::fs::write(&entry, b"tampered").unwrap();

        let err = dry_run_report_with(&plan, &cache.probe(), true).unwrap_err();
        let FuziError::OfflineCacheCorrupt { entries } = &err else {
            panic!("expected OfflineCacheCorrupt, got {err:?}");
        };
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].package, "node_modules/b");
        assert_eq!(entries[0].path, entry.display().to_string());
        assert_eq!(err.exit_code(), 65);
        assert_eq!(std::fs::read(&entry).unwrap(), b"tampered");

        // The real offline run agrees.
        let real = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(run_fetch_phase::<NpmTarballSource>(
                &plan,
                &cache,
                None,
                DEFAULT_FETCH_CONCURRENCY,
            ))
            .unwrap_err();
        assert_eq!(real.kind(), err.kind());

        let report = dry_run_report_with(&plan, &cache.probe(), false).unwrap();
        assert_eq!((report.cached, report.fetched), (1, 1));
        assert_eq!(report.healed, ["node_modules/b"]);
        assert_eq!(std::fs::read(&entry).unwrap(), b"tampered");

        // The real online run agrees: it heals the same entry.
        let source = FixtureSource::new().with("https://registry.npmjs.org/b/-/b-1.0.0.tgz", b"b");
        let real = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(run_fetch_phase(
                &plan,
                &cache,
                Some(&source),
                DEFAULT_FETCH_CONCURRENCY,
            ))
            .unwrap();
        assert_eq!(real.healed, report.healed);
        assert_eq!((real.cached, real.fetched), (report.cached, report.fetched));
    }

    /// `healed` rides `--json` sorted by package, as the real run sorts it — not
    /// in the cache's integrity order, which here is the reverse (`b`'s bytes
    /// hash below `a`'s).
    #[test]
    fn online_dry_run_lists_healed_packages_in_package_order() {
        let entry = |data: &[u8]| {
            serde_json::json!({
                "version": "1.0.0",
                "resolved": "https://registry.npmjs.org/x/-/x-1.0.0.tgz",
                "integrity": test_support::sha512_sri(data)
            })
        };
        let raw: RawLockfile = serde_json::from_value(serde_json::json!({
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "app"},
                "node_modules/a": entry(b"b"),
                "node_modules/b": entry(b"a")
            }
        }))
        .unwrap();
        let plan = build_plan(&raw, &test_support::host_linux_x64_glibc(), &[]).unwrap();
        let root = tempfile::tempdir().unwrap();
        let cache = NpmCache::open(root.path().join("npm")).unwrap();
        for data in [b"a", b"b"] {
            let temp = cache.temp_path();
            std::fs::write(&temp, data).unwrap();
            let integrity = test_support::integrity_of(data);
            cache.commit(&temp, &integrity).unwrap();
            std::fs::write(cache.entry_path(&integrity), b"tampered").unwrap();
        }
        let report = dry_run_report_with(&plan, &cache.probe(), false).unwrap();
        assert_eq!(report.healed, ["node_modules/a", "node_modules/b"]);
    }

    /// Online, an unreadable cached tarball fails the dry run with the real
    /// run's error class (`Io`, 74), not "cached".
    #[test]
    fn online_dry_run_reports_the_real_runs_unreadable_cache_entry() {
        use std::os::unix::fs::PermissionsExt as _;
        let plan = two_tarball_plan();
        let root = tempfile::tempdir().unwrap();
        let cache = NpmCache::open(root.path().join("npm")).unwrap();
        let temp = cache.temp_path();
        std::fs::write(&temp, b"a").unwrap();
        cache
            .commit(&temp, &test_support::integrity_of(b"a"))
            .unwrap();
        let entry = cache.entry_path(&test_support::integrity_of(b"a"));
        std::fs::set_permissions(&entry, std::fs::Permissions::from_mode(0o000)).unwrap();
        // Root reads a mode-000 file anyway: nothing to observe there.
        if std::fs::File::open(&entry).is_ok() {
            std::fs::set_permissions(&entry, std::fs::Permissions::from_mode(0o600)).unwrap();
            return;
        }
        let dry = dry_run_report_with(&plan, &cache.probe(), false);
        let source = FixtureSource::new().with("https://registry.npmjs.org/b/-/b-1.0.0.tgz", b"b");
        let real = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(run_fetch_phase(
                &plan,
                &cache,
                Some(&source),
                DEFAULT_FETCH_CONCURRENCY,
            ));
        std::fs::set_permissions(&entry, std::fs::Permissions::from_mode(0o600)).unwrap();
        let dry = dry.unwrap_err();
        assert!(matches!(dry, FuziError::Io { .. }), "{dry:?}");
        assert_eq!(dry.exit_code(), 74);
        assert_eq!(real.unwrap_err().kind(), dry.kind());
    }

    /// The offline dry run's precedence is the real run's: a tampered cached
    /// tarball is the corrupt-cache alarm even beside an uncached one (not the
    /// softer miss), and an unreadable one is the I/O failure over a miss.
    #[test]
    fn offline_dry_run_reports_corruption_and_unreadable_before_a_miss() {
        use std::os::unix::fs::PermissionsExt as _;
        let plan = two_tarball_plan();
        let root = tempfile::tempdir().unwrap();
        let cache = NpmCache::open(root.path().join("npm")).unwrap();
        let temp = cache.temp_path();
        std::fs::write(&temp, b"a").unwrap();
        cache
            .commit(&temp, &test_support::integrity_of(b"a"))
            .unwrap();
        let entry = cache.entry_path(&test_support::integrity_of(b"a"));
        std::fs::write(&entry, b"tampered").unwrap();

        let err = dry_run_report_with(&plan, &cache.probe(), true).unwrap_err();
        let FuziError::OfflineCacheCorrupt { entries } = &err else {
            panic!("expected OfflineCacheCorrupt, got {err:?}");
        };
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].package, "node_modules/a");

        // Unreadable: probe first, since root reads a mode-000 file anyway.
        std::fs::set_permissions(&entry, std::fs::Permissions::from_mode(0o000)).unwrap();
        let unreadable = std::fs::File::open(&entry).is_err();
        let result = dry_run_report_with(&plan, &cache.probe(), true);
        std::fs::set_permissions(&entry, std::fs::Permissions::from_mode(0o600)).unwrap();
        if !unreadable {
            return;
        }
        let err = result.unwrap_err();
        assert!(matches!(err, FuziError::Io { .. }), "{err:?}");
    }

    /// The real run refuses a `node_modules` that is a symlink or a file before
    /// any network work; the dry run must refuse it too, not report success.
    #[test]
    fn dry_run_refuses_an_obstructed_node_modules() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("package-lock.json"),
            serde_json::json!({"lockfileVersion": 3, "packages": {"": {"name": "app"}}})
                .to_string(),
        )
        .unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(elsewhere.path(), dir.path().join("node_modules")).unwrap();
        let mut opts = options(dir.path().to_path_buf(), true);
        opts.ignore_manifest = true;
        let err = install(&opts).unwrap_err();
        assert!(
            matches!(
                err,
                FuziError::NodeModulesNotDirectory {
                    kind: NodeModulesObstruction::Symlink
                }
            ),
            "{err:?}"
        );
        assert_eq!(err.exit_code(), 73);

        std::fs::remove_file(dir.path().join("node_modules")).unwrap();
        std::fs::write(dir.path().join("node_modules"), b"").unwrap();
        let err = install(&opts).unwrap_err();
        assert!(
            matches!(
                err,
                FuziError::NodeModulesNotDirectory {
                    kind: NodeModulesObstruction::File
                }
            ),
            "{err:?}"
        );
    }

    /// A registry tarball for `name@version`: a `package/package.json`, plus
    /// an executable `package/cli.js` when `bin` is set.
    fn package_tarball(name: &str, version: &str, bin: bool) -> Vec<u8> {
        let manifest = serde_json::json!({"name": name, "version": version}).to_string();
        let mut entries = vec![test_support::reg(
            "package/package.json",
            0o644,
            manifest.as_bytes(),
        )];
        if bin {
            entries.push(test_support::reg(
                "package/cli.js",
                0o755,
                b"#!/usr/bin/env node\n",
            ));
        }
        test_support::gz_tar(&entries)
    }

    /// The whole pipeline through the [`install_with`] seam, network-free:
    /// fetch from a fixture source into a fresh cache, materialize, and the
    /// tree verifies against its own lockfile. The lockfile carries a nested
    /// placement shadowing a hoisted one, a `.bin`, a platform-variant optional
    /// set with one host match and one skip, and a sibling link. Then an
    /// offline reinstall is served wholly from the cache, and an offline dry
    /// run agrees.
    #[test]
    fn install_with_fixture_source_round_trips_through_verify() {
        let w = tempfile::tempdir().unwrap();
        let app = w.path().join("app");
        let lib = w.path().join("lib");
        std::fs::create_dir(&app).unwrap();
        std::fs::create_dir(&lib).unwrap();
        std::fs::write(
            lib.join("package.json"),
            serde_json::json!({"name": "lib", "version": "1.0.0"}).to_string(),
        )
        .unwrap();

        // (lockfile key, name, version, bin, extra lockfile fields)
        let registry = [
            (
                "node_modules/a",
                "a",
                "1.0.0",
                true,
                serde_json::json!({"bin": {"a": "cli.js"}}),
            ),
            ("node_modules/b", "b", "2.0.0", false, serde_json::json!({})),
            (
                "node_modules/a/node_modules/b",
                "b",
                "1.0.0",
                false,
                serde_json::json!({}),
            ),
            (
                "node_modules/esb",
                "esb",
                "0.1.0",
                false,
                serde_json::json!({"optionalDependencies": {
                    "@esb/linux-x64": "0.1.0",
                    "@esb/darwin-arm64": "0.1.0"
                }}),
            ),
            (
                "node_modules/@esb/linux-x64",
                "@esb/linux-x64",
                "0.1.0",
                false,
                serde_json::json!({"optional": true, "os": ["linux"], "cpu": ["x64"]}),
            ),
            (
                "node_modules/@esb/darwin-arm64",
                "@esb/darwin-arm64",
                "0.1.0",
                false,
                serde_json::json!({"optional": true, "os": ["darwin"], "cpu": ["arm64"]}),
            ),
        ];
        let deps =
            serde_json::json!({"a": "1.0.0", "b": "2.0.0", "esb": "0.1.0", "lib": "file:../lib"});
        let mut packages = serde_json::json!({
            "": {"name": "app", "dependencies": deps},
            "node_modules/lib": {"resolved": "../lib", "link": true},
            "../lib": {"name": "lib", "version": "1.0.0"}
        });
        let mut source = FixtureSource::new();
        for (key, name, version, bin, extra) in &registry {
            let tarball = package_tarball(name, version, *bin);
            let url = format!("https://registry.npmjs.org/{name}/-/{version}.tgz");
            let mut entry = serde_json::json!({
                "version": version,
                "resolved": url,
                "integrity": test_support::sha512_sri(&tarball)
            });
            for (k, v) in extra.as_object().unwrap() {
                entry[k] = v.clone();
            }
            packages[*key] = entry;
            source = source.with(url, tarball);
        }
        std::fs::write(
            app.join("package.json"),
            serde_json::json!({"name": "app", "dependencies": deps}).to_string(),
        )
        .unwrap();
        let lock = serde_json::json!({"lockfileVersion": 3, "packages": packages});
        std::fs::write(app.join("package-lock.json"), lock.to_string()).unwrap();

        let host = test_support::host_linux_x64_glibc();
        let cache_root = tempfile::tempdir().unwrap();
        let cache = NpmCache::open(cache_root.path().join("npm")).unwrap();

        let report =
            install_with(&options(app.clone(), false), &host, &cache, Some(&source)).unwrap();
        assert_eq!((report.cached, report.fetched), (0, 5), "{report:?}");
        assert_eq!(report.placed, 5);
        assert_eq!(report.linked, 1);
        assert_eq!(report.bins_linked, 1);
        assert_eq!(report.skipped_optional, 1, "the darwin variant is skipped");
        assert!(report.healed.is_empty());

        let nm = app.join("node_modules");
        assert!(nm.join("a/node_modules/b/package.json").is_file());
        assert!(nm.join("@esb/linux-x64/package.json").is_file());
        assert!(!nm.join("@esb/darwin-arm64").exists());
        assert_eq!(
            std::fs::read_link(nm.join(".bin/a")).unwrap(),
            std::path::Path::new("../a/cli.js")
        );
        assert_eq!(
            std::fs::read_link(nm.join("lib")).unwrap(),
            std::path::Path::new("../../lib")
        );

        let raw: RawLockfile = serde_json::from_value(lock).unwrap();
        let verified = verify_against(&raw, &host, &[], &app).unwrap();
        assert_eq!(verified.checked, 5);
        assert_eq!(verified.links_checked, 1);
        assert_eq!(verified.platform_parents_checked, 1);

        // Offline (no source at all, and a source overridden by `offline`):
        // every tarball is a re-verified cache hit, and the tree still verifies.
        let mut offline = options(app.clone(), false);
        offline.offline = true;
        for source in [None, Some(&FixtureSource::new())] {
            let report = install_with(&offline, &host, &cache, source).unwrap();
            assert_eq!((report.cached, report.fetched), (5, 0), "{report:?}");
            verify_against(&raw, &host, &[], &app).unwrap();
        }
        offline.dry_run = true;
        let report = install_with::<FixtureSource>(&offline, &host, &cache, None).unwrap();
        assert!(report.dry_run);
        assert_eq!((report.cached, report.fetched), (5, 0));
    }

    #[test]
    fn skipped_scripts_dedup_by_package_name() {
        // gro's real tree carries two `esbuild` copies with install scripts — a
        // hoisted one and vite's nested one. Both skip the same script, so the
        // report names `esbuild` once, not twice.
        let plan = InstallPlan {
            skipped_scripts: vec![
                InstallPath::new("node_modules/esbuild"),
                InstallPath::new("node_modules/vite/node_modules/esbuild"),
                InstallPath::new("node_modules/other"),
            ],
            ..Default::default()
        };
        let mut report = InstallReport::default();
        fold_plan_counts(&mut report, &plan);
        assert_eq!(report.skipped_scripts, vec!["esbuild", "other"]);
    }
}
