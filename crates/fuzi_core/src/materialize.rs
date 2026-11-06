//! Materialize the verified CAS into `node_modules`.
//!
//! Builds a fresh [`StagingTree`], extracts every placement into it, links the
//! `node_modules/.bin/<cmd>` shims, then publishes the tree with one atomic
//! rename (see `crate::staging` for why the staging-swap is security-load-bearing).
//!
//! Extraction runs **concurrently** across placements (a scoped thread pool):
//! each placement's package directory is pre-allocated, then workers extract and
//! hash-verify in parallel — order-independent, since every placement's parents
//! are created on demand. `.bin` linking is a **second, sequential** pass in the
//! plan's depth-sorted order, so a cross-package command clash still resolves
//! last-writer-wins deterministically rather than by thread race.
//!
//! Sibling `link: true` packages are placed as relative symlinks **after** every
//! extraction and before the `.bin` pass, so no extraction ever writes through a
//! link (classify also refuses any key nested under one). Their bins link
//! through the package link after the registry bins — so a linked package's
//! bin wins a command-name clash with a registry package's — and only when the
//! target is already an executable regular file reached through real
//! directories (`crate::link::linked_bin_is_linkable`): fuzi never chmods — or
//! writes anything else — outside the project, so any other linked bin is a
//! counted skip. The link-target check then runs once more, immediately before
//! the publish rename.

use std::fs::{self, File};
use std::io::Read;
use std::num::NonZeroUsize;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use fuz_crypto::{HashAlgo, Hasher};
use fuz_sys::fs::{add_exec_bit_no_follow, free_space_bytes};

use crate::cache::NpmCache;
use crate::entry::{BinCommand, InstallPath};
use crate::error::{FuziError, StagingEntry, io_err};
use crate::extract::extract_package;
use crate::link::{bin_path_through_real_dirs, check_link_targets, linked_bin_is_linkable};
use crate::plan::{InstallPlan, LinkPlacement, PackagePlacement};
use crate::report::InstallReport;
use crate::staging::{StagingDir, StagingTree};

/// Conservative compressed→extracted multiplier for the disk pre-flight. npm
/// gzip tarballs typically expand ~3–4×; the slack covers the brief overlap
/// where the new staging tree and the old `node_modules` coexist during the
/// swap. A loose backstop, not a tight fit — the real ENOSPC path still applies.
// Measured against the gate corpus (esbuild/vite trees) the real expansion sits
// well under this; kept deliberately loose so a highly compressible package
// never trips a false pre-flight rejection — the kernel ENOSPC is the real guard.
const EXTRACT_RATIO_ESTIMATE: u64 = 5;

/// Upper bound on concurrent extraction threads, on top of the host's own
/// parallelism (see [`extract_concurrency`]).
///
/// Extraction is gzip-decode + sha512 (CPU) writing into the page cache, so it
/// scales with cores rather than saturating the disk — measured, not assumed: on
/// a 12-core host a warm 229-package install runs ~3–7% faster with this at 16
/// (i.e. letting all 12 cores work) than at 8, where the cap is the binding
/// constraint. The bound remains only to keep a very-many-core host from fanning
/// hundreds of decode threads at one filesystem; re-measure with
/// `scripts/fuzi-bench.sh` before moving it.
const MAX_EXTRACT_CONCURRENCY: usize = 16;

/// Materialize `plan` into `<project_dir>/node_modules`, folding extraction and
/// `.bin`-link tallies into `report`.
///
/// Pipeline: disk pre-flight → build a fresh staging tree → for each placement,
/// re-verify the cached tarball on read (closing the fetch→extract TOCTOU) and
/// extract it → place the sibling links → link the bins (registry, then linked)
/// → re-check the link targets → check every placed package, link, and bin
/// link is still there → atomically publish the tree. Any error before
/// publish drops the staging tree (the [`crate::staging::StagingTree`] cleanup
/// guard removes it), leaving the existing `node_modules` untouched.
///
/// The link targets were checked before the fetch phase; fetching and
/// extracting take long enough for a sibling to be swapped meanwhile, so the
/// same check runs again here, as late as it can. It narrows the window to the
/// publish itself rather than closing it: a link is a by-name symlink, and
/// nothing binds it to the directory that was checked (see `crate::link`).
///
/// # Errors
///
/// Returns [`FuziError::InsufficientSpace`] from the pre-flight,
/// [`FuziError::Extract`] on a bad tarball, [`FuziError::UnsafeStagingPath`] if
/// a placement or link would land at or under a link or a link's key fails the
/// `node_modules` key gate, [`FuziError::LinkTarget`] if a link's target fails
/// the pre-publish check, [`FuziError::Interrupted`] if the interrupt drain
/// fired before the staging tree was created or claimed it before the publish,
/// [`FuziError::StagingIncomplete`] if another process removed part of the
/// staging tree (checked before the publish, and the reading of a write that
/// failed `NotFound` because its directory was gone), or [`FuziError::Io`] on
/// a cache or filesystem failure.
pub fn materialize(
    plan: &InstallPlan,
    cache: &NpmCache,
    project_dir: &Path,
    report: &mut InstallReport,
) -> Result<(), FuziError> {
    check_links_are_disjoint(plan)?;
    preflight_space(plan, cache, project_dir)?;

    let mut tree = StagingTree::create(project_dir)?;
    fill_tree(&mut tree, plan, cache, project_dir, report)?;
    tree.commit()?;
    Ok(())
}

/// Fill `tree` with `plan`: extract every placement, place the links, link the
/// bins, and re-check the link targets — everything [`materialize`] does
/// between creating the staging tree and publishing it.
///
/// A failure is read against the tree: a `NotFound` because another process
/// removed part of it is reported as [`FuziError::StagingIncomplete`] (or
/// [`FuziError::Interrupted`], when the interrupt drain took it) rather than as
/// a bare I/O error — see [`StagingTree::explain_not_found`]. The work itself
/// is a nested function so nothing can call it without that reading.
fn fill_tree(
    tree: &mut StagingTree,
    plan: &InstallPlan,
    cache: &NpmCache,
    project_dir: &Path,
    report: &mut InstallReport,
) -> Result<(), FuziError> {
    fn build_tree(
        tree: &mut StagingTree,
        plan: &InstallPlan,
        cache: &NpmCache,
        project_dir: &Path,
        report: &mut InstallReport,
    ) -> Result<(), FuziError> {
        // Pre-allocate every placement's package directory on this thread, so the
        // parallel extraction below needs only `&NpmCache` + per-package `StagingDir`
        // values — never a shared `&StagingTree`. A placement with no `node_modules/`
        // component (the unreachable belt-and-suspenders case `classify` already
        // refuses) is dropped here. `jobs` stays in the plan's depth-sorted order, so
        // the sequential `.bin` pass below is deterministic.
        let mut jobs: Vec<(StagingDir, &PackagePlacement)> =
            Vec::with_capacity(plan.placements.len());
        for placement in &plan.placements {
            if let Some(staging) = tree.package_dir(&placement.path)? {
                jobs.push((staging, placement));
            }
        }

        let shipped_package_json = extract_all(cache, &jobs)?;
        report.placed += jobs.len();
        // Record each `package.json` a tarball shipped, for the publish's
        // completeness check: the file most likely to show a swept package.
        for ((staging, _), shipped) in jobs.iter().zip(shipped_package_json) {
            if shipped {
                tree.record(package_json_path(staging), StagingEntry::PackageJson);
            }
        }

        // Links only after every extraction has finished: nothing extracts through
        // a symlink fuzi just created.
        for link in &plan.links {
            tree.place_link(&link.path, &link.target)?;
            report.linked += 1;
        }

        // Second pass — link `.bin` in deterministic order (last-writer-wins on a
        // cross-package command clash stays order-stable, unlike a thread race).
        // Linked packages' bins go last, in lockfile-key order.
        for (staging, placement) in &jobs {
            link_bins(tree, placement, staging.path(), report)?;
        }
        for link in &plan.links {
            link_linked_bins(tree, link, project_dir, report)?;
        }

        // Last thing before the publish: every link target is still the package the
        // lockfile names. The warnings were reported by the first check.
        check_link_targets(plan, project_dir)?;
        Ok(())
    }

    build_tree(tree, plan, cache, project_dir, report).map_err(|err| tree.explain_not_found(err))
}

/// Where a placement's own `package.json` lands in its staging directory.
fn package_json_path(staging: &StagingDir) -> PathBuf {
    staging.path().join("package.json")
}

/// Extract + hash-verify every job, concurrently when there is more than one,
/// returning, per job in `jobs` order, whether its tarball shipped a
/// `package.json` at the package root.
///
/// Workers pull jobs off a shared cursor; the first error aborts further pickup
/// and is returned (every job is independent, so any failure fails the whole
/// install and the staging tree is discarded). A single job runs inline.
fn extract_all(
    cache: &NpmCache,
    jobs: &[(StagingDir, &PackagePlacement)],
) -> Result<Vec<bool>, FuziError> {
    let workers = extract_concurrency(jobs.len());
    if workers <= 1 {
        return jobs
            .iter()
            .map(|(staging, placement)| extract_into(cache, staging, placement))
            .collect();
    }

    let order = longest_first(cache, jobs);
    let cursor = AtomicUsize::new(0);
    let aborted = AtomicBool::new(false);
    let first_err: Mutex<Option<FuziError>> = Mutex::new(None);
    let shipped: Vec<AtomicBool> = jobs.iter().map(|_| AtomicBool::new(false)).collect();

    std::thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| {
                while !aborted.load(Ordering::Relaxed) {
                    let i = cursor.fetch_add(1, Ordering::Relaxed);
                    let Some(&j) = order.get(i) else {
                        break;
                    };
                    let (staging, placement) = &jobs[j];
                    match extract_into(cache, staging, placement) {
                        Ok(has_package_json) => {
                            shipped[j].store(has_package_json, Ordering::Relaxed);
                        }
                        Err(e) => {
                            aborted.store(true, Ordering::Relaxed);
                            let mut slot = first_err
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner);
                            if slot.is_none() {
                                *slot = Some(e);
                            }
                            break;
                        }
                    }
                }
            });
        }
    });

    first_err
        .into_inner()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .map_or_else(
            || Ok(shipped.into_iter().map(AtomicBool::into_inner).collect()),
            Err,
        )
}

/// Job indices ordered largest-compressed-tarball first — LPT (longest
/// processing time first) scheduling for the work-stealing pool.
///
/// A greedy pool that picks jobs up in depth order can hand the biggest tarball
/// to the last free worker, leaving every other thread idle through its tail.
/// Starting with the longest jobs bounds that tail: the classic LPT result is
/// that no schedule finishes worse than 4/3 of optimal, and compressed size is a
/// good proxy for decode+hash time (both are linear in the byte stream).
///
/// Only the *extraction* order changes. `jobs` itself stays depth-sorted, so the
/// sequential `.bin` pass in [`materialize`] still resolves a cross-package
/// command clash last-writer-wins deterministically. An unstattable entry sorts
/// as size 0 (it will fail in `extract_into` anyway — this is a scheduling hint,
/// not a validation step), and ties break on the job index so the order is a
/// deterministic function of the plan.
fn longest_first(cache: &NpmCache, jobs: &[(StagingDir, &PackagePlacement)]) -> Vec<usize> {
    let mut sized: Vec<(u64, usize)> = jobs
        .iter()
        .enumerate()
        .map(|(i, (_, placement))| {
            let size = fs::metadata(cache.entry_path(&placement.integrity)).map_or(0, |m| m.len());
            (size, i)
        })
        .collect();
    sized.sort_unstable_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
    sized.into_iter().map(|(_, i)| i).collect()
}

/// Worker-thread count for extracting `job_count` placements: the host
/// parallelism, clamped to `[1, MAX_EXTRACT_CONCURRENCY]` and never more than the
/// number of jobs.
fn extract_concurrency(job_count: usize) -> usize {
    let cores = std::thread::available_parallelism().map_or(1, NonZeroUsize::get);
    cores
        .clamp(1, MAX_EXTRACT_CONCURRENCY)
        .min(job_count.max(1))
}

/// Extract one placement's cached tarball into its (pre-allocated) staging
/// directory, verifying the bytes by **hashing exactly what is extracted**.
///
/// A [`HashingReader`] tees the compressed stream into a sha512 hasher as
/// `safe_extract` consumes it (one fd, one pass), and the digest is checked
/// against the integrity key after. This is the materialization-side TOCTOU
/// close: there is no verify-then-reopen gap (hashing the path, then
/// re-opening it, would leave a window a same-uid racer could exploit). Bytes land in
/// the *disposable* staging tree before the digest is checked; a mismatch returns
/// [`FuziError::CacheTampered`] and the [`StagingTree`] cleanup guard discards
/// everything, so unverified content never reaches the live tree. The digest
/// is checked even when extraction fails — the rest of the fd is hashed first —
/// so a mismatch outranks the extract error: a tampered entry is reported as
/// tampering whatever its bytes did to the extractor. A read failure in that
/// rest leaves the digest unchecked and is reported as the I/O error it is,
/// so a security-class [`FuziError::Extract`] always means the bytes matched.
///
/// Pure per-package work — no `&StagingTree`, no `&mut InstallReport` — so it is
/// safe to run on a worker thread (see [`extract_all`]). Directory allocation and
/// `.bin` linking happen on the orchestrating thread in [`materialize`].
// NOTE: the fetch phase and this phase hash the tarball at two distinct trust
// moments (download-commit vs. read-for-extract), so those two hashes are
// deliberately *not* fused — re-hashing at extract time is the whole point of
// the TOCTOU close.
// NOTE (resolved — extract-then-verify stays): bytes land in staging *before*
// this digest check, which reads as weaker than verify-then-write. It isn't, for
// this threat model. The bytes are already verified once — the fetch phase
// re-verifies every cache hit before materialization — so the only window this
// tee covers is a swap of the cached file *between* those two reads. Performing
// that swap requires same-uid write access to `~/.fuz/cache/npm` (mode 0700),
// and an actor with same-uid access can write the project tree directly; routing
// bytes through fuzi's staging dir, where they are hashed and then discarded on
// mismatch, gains them nothing they did not already have. The residual worth
// naming is narrower: extraction *parses* those bytes (tar + gzip) before the
// digest is known, so a crafted tarball would need a parse bug to matter — both
// layers are Rust (`tar`, `zlib-rs`), hardened but not memory-safe by
// construction: `unsafe_code = "forbid"` covers only this workspace's crates,
// and both dependencies carry internal `unsafe`. The planned seccomp no-exec
// profile is the backstop. Buffer-then-verify was rejected: it costs
// either the whole tarball in memory (up to the 512 MiB cap) or a third full
// read, to close a window that admits only an attacker who has already won.
fn extract_into(
    cache: &NpmCache,
    staging: &StagingDir,
    placement: &PackagePlacement,
) -> Result<bool, FuziError> {
    let entry_path = cache.entry_path(&placement.integrity);
    let file = File::open(&entry_path).map_err(io_err("open cached tarball for extraction"))?;
    let compressed_size = file
        .metadata()
        .map_err(io_err("stat cached tarball"))?
        .len();

    extract_verified(file, compressed_size, staging, placement)
}

/// Extract `reader`'s tarball into `staging`, hashing every byte read, then
/// check the digest against `placement`'s integrity: the body of
/// [`extract_into`], generic over the reader so a read failure can be tested.
/// Returns whether the tarball placed a `package.json` at the package root.
///
/// A security-class [`FuziError::Extract`] means the digest was verified: an
/// extraction that fails has the rest of `reader` hashed before its error is
/// reported, and a read failure there is reported as the I/O error it is.
fn extract_verified<R: Read>(
    reader: R,
    compressed_size: u64,
    staging: &StagingDir,
    placement: &PackagePlacement,
) -> Result<bool, FuziError> {
    let mut hasher = Hasher::new(HashAlgo::Sha512);
    let extracted = {
        let mut reader = HashingReader {
            inner: reader,
            hasher: &mut hasher,
        };
        let extracted = extract_package(&mut reader, compressed_size, staging).map_err(|source| {
            FuziError::Extract {
                package: placement.path.as_str().to_string(),
                source,
            }
        });
        // An extraction that failed stopped reading part-way. Hash the rest of
        // the same fd, so a swapped-in hostile tarball reports as the tamper
        // it is, not as whatever its bytes made the extractor trip on. A read
        // failure here leaves the digest unchecked, so the extract error can't
        // be reported as a bad package (that claims the bytes match the
        // lockfile): it is the read failure that is reported.
        if extracted.is_err() {
            std::io::copy(&mut reader, &mut std::io::sink()).map_err(io_err(
                "read cached tarball to verify it after a failed extraction",
            ))?;
        }
        extracted
    };
    let computed = hasher.finalize();
    if &computed != placement.integrity.content_hash() {
        return Err(FuziError::CacheTampered {
            package: placement.path.as_str().to_string(),
        });
    }
    extracted.map(|report| report.files.contains_key(Path::new("package.json")))
}

/// A `Read` adapter that tees every byte it yields into a borrowed [`Hasher`].
///
/// Lets the caller hash, in one pass, exactly the bytes a downstream reader
/// pulls — then finalize the borrowed hasher after that reader is dropped.
/// `safe_extract` is documented to consume its reader to EOF (past the tar
/// stream's end-of-archive marker), so the tee covers the **whole file**,
/// matching the whole-file integrity key [`NpmCache::commit`] /
/// [`NpmCache::verify_cached`] hash against; a reader left at the marker would
/// leave the digest covering only a prefix.
struct HashingReader<'a, R> {
    inner: R,
    hasher: &'a mut Hasher,
}

impl<R: Read> Read for HashingReader<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.hasher.update(&buf[..n]);
        Ok(n)
    }
}

/// Link `placement`'s declared bins into its enclosing `node_modules/.bin`.
///
/// Each entry chmods the (verified, in-package) target executable and creates a
/// relative `../<package>/<target>` symlink. A bin whose path crosses anything
/// but real directories is skipped before the chmod
/// ([`bin_path_through_real_dirs`]). The bins arrive **pre-validated** as
/// [`BinCommand`]/[`BinTarget`] (a path-bearing command or escaping/absolute
/// target — which npm never emits — was already refused loud at classify time as
/// [`crate::classify::RefuseReason::MalformedBin`]), so the only remaining skip is
/// the **benign** one: a bin whose target *file* the tarball does not ship. That
/// is a package's own inconsistency, not lockfile tampering — `report.bins_skipped`
/// counts it and links nothing dangling. So the two phases split it: hostile bin →
/// refuse the install; missing-target bin → skip + count.
///
/// [`BinCommand`]: crate::entry::BinCommand
/// [`BinTarget`]: crate::entry::BinTarget
fn link_bins(
    tree: &mut StagingTree,
    placement: &PackagePlacement,
    pkg_dir: &Path,
    report: &mut InstallReport,
) -> Result<(), FuziError> {
    if placement.bins.is_empty() {
        return Ok(());
    }
    let bin_dir = tree.bin_dir(&placement.path);

    for (command, rel_target) in &placement.bins {
        // Every directory between the package and the file must be a real one,
        // so the chmod below cannot follow a symlinked parent out of the
        // package (`O_NOFOLLOW` covers the final component only). Nothing fuzi
        // builds puts a symlink there; this does not depend on it.
        let Some(target_file) = bin_path_through_real_dirs(pkg_dir, rel_target) else {
            report.bins_skipped += 1;
            continue;
        };
        // Bin targets ship 0644 as often as 0755; the shim must be executable.
        // `add_exec_bit_no_follow` opens the target with `O_NOFOLLOW` and chmods
        // the descriptor, so the stat-and-chmod are one inode with no TOCTOU
        // window — a raced symlink (the only attack the fuzi-owned, same-uid
        // 0755 staging tree admits) can neither redirect the chmod outside the
        // package nor slip in between a check and the chmod. A symlink / missing
        // / non-regular target is a benign skip (`Ok(false)`); extraction never
        // produces an intra-tarball symlink, so a skip here is the raced-symlink
        // case, paired with the fresh-staging-then-atomic-swap install model.
        if !add_exec_bit_no_follow(&target_file).map_err(io_err("chmod bin target executable"))? {
            report.bins_skipped += 1;
            continue;
        }

        write_bin_link(
            tree,
            &bin_dir,
            command,
            &rel_target.bin_link_text(&placement.path),
        )?;
        report.bins_linked += 1;
    }
    Ok(())
}

/// Link a linked package's bins into the top-level `.bin`, through the package
/// link (`.bin/<cmd>` → `../<portion>/<target>`, npm's shape).
///
/// **Never chmods**: the target file lives in the sibling directory, outside
/// the project, and fuzi writes nothing there. A bin that
/// [`linked_bin_is_linkable`] accepts — an executable regular file (any exec
/// bit) reached through real directories only, every component `lstat`ed — is
/// linked; anything else — missing, not executable, a directory, or a symlink
/// at *any* component — is counted in `bins_skipped`, the same benign skip as a
/// registry bin whose file the tarball does not ship, and never an error. So a
/// `.bin` link never resolves out of the target through a symlink inside it.
/// (npm links and chmods a declared bin whatever it is; skipping a symlinked
/// one is a deliberate divergence.)
fn link_linked_bins(
    tree: &mut StagingTree,
    link: &LinkPlacement,
    project_dir: &Path,
    report: &mut InstallReport,
) -> Result<(), FuziError> {
    if link.bins.is_empty() {
        return Ok(());
    }
    let bin_dir = tree.bin_dir(&link.path);
    let target_dir = link.target.dir_in(project_dir);
    for (command, rel_target) in &link.bins {
        if !linked_bin_is_linkable(&target_dir, rel_target) {
            report.bins_skipped += 1;
            continue;
        }
        write_bin_link(
            tree,
            &bin_dir,
            command,
            &rel_target.bin_link_text(&link.path),
        )?;
        report.bins_linked += 1;
    }
    Ok(())
}

/// Write one `.bin/<command>` symlink with `relative_target`, creating the
/// `.bin` directory on demand, and record it for the publish's completeness
/// check. Last writer wins on a cross-package command clash: an existing entry
/// (only ever a fuzi-created `.bin` link in the fresh staging tree) is unlinked
/// first.
fn write_bin_link(
    tree: &mut StagingTree,
    bin_dir: &Path,
    command: &BinCommand,
    relative_target: &str,
) -> Result<(), FuziError> {
    tree.ensure_dir(bin_dir)?;
    let link = bin_dir.join(command.as_str());
    let _ = fs::remove_file(&link);
    symlink(relative_target, &link).map_err(io_err("create node_modules/.bin symlink"))?;
    tree.record(link, StagingEntry::BinLink);
    Ok(())
}

/// Refuse a plan whose links are not disjoint from everything else: a registry
/// placement or another link at or under a link key, or two links at one key.
///
/// Extraction into a path under a link, or a link placed under another link,
/// would write through the first symlink into its target (the parent `mkdir`
/// follows it). Classify already refuses such keys ([`NestedUnderLink`]) and
/// lockfile keys are unique, so this never fires on a plan `build_plan`
/// produced; it guards the materialization boundary against a hand-built
/// [`InstallPlan`], the way [`StagingTree::package_dir`] guards it against a
/// hand-built key.
///
/// It is one half of that boundary: this checks how the links sit relative to
/// everything else, and the staging entry points check each key on its own —
/// [`StagingTree::package_dir`] and [`StagingTree::place_link`] both apply the
/// `node_modules` key gate. Disjointness alone admits two shapes the gate
/// refuses: a link at `.bin`, which is disjoint from every package and would
/// still turn the bin pass's directory into the sibling, and a placement *at* a
/// scope directory (`node_modules/@s`) holding a link (`node_modules/@s/lib`),
/// whose own bin path would run through that link.
///
/// [`NestedUnderLink`]: crate::classify::RefuseReason::NestedUnderLink
fn check_links_are_disjoint(plan: &InstallPlan) -> Result<(), FuziError> {
    let at_or_under = |path: &InstallPath, link: &InstallPath| {
        path.as_str()
            .strip_prefix(link.as_str())
            .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
    };
    let unsafe_path = |path: &InstallPath| FuziError::UnsafeStagingPath {
        key: path.as_str().to_string(),
    };
    for (i, link) in plan.links.iter().enumerate() {
        if let Some(placement) = plan
            .placements
            .iter()
            .find(|placement| at_or_under(&placement.path, &link.path))
        {
            return Err(unsafe_path(&placement.path));
        }
        if let Some(other) = plan
            .links
            .iter()
            .enumerate()
            .find(|(j, other)| *j != i && at_or_under(&other.path, &link.path))
        {
            return Err(unsafe_path(&other.1.path));
        }
    }
    Ok(())
}

/// Reject obviously-insufficient disk before building the tree. A hint, not a
/// reservation (see [`free_space_bytes`]); a probe failure on an exotic FS skips
/// the check rather than blocking a valid install.
fn preflight_space(
    plan: &InstallPlan,
    cache: &NpmCache,
    project_dir: &Path,
) -> Result<(), FuziError> {
    let needed = estimated_extracted_bytes(plan, cache);
    let Ok(available) = free_space_bytes(project_dir) else {
        return Ok(()); // probe unsupported here — fall back to the ENOSPC backstop
    };
    space_verdict(needed, available)
}

/// The conservative extracted-tree estimate: every cached tarball in the fetch
/// set, scaled by [`EXTRACT_RATIO_ESTIMATE`]. A tarball not yet cached
/// contributes nothing (it is not on disk to stat).
///
/// Deliberately sums the *deduped* fetch set, so a tarball placed at N paths is
/// counted once while extracting N times — the estimate under-counts a
/// duplication-heavy tree, and the loose ratio slack absorbs it. Acceptable
/// because this is explicitly a hint with the kernel `ENOSPC` as the real guard.
fn estimated_extracted_bytes(plan: &InstallPlan, cache: &NpmCache) -> u64 {
    let compressed = plan.fetch_set.keys().fold(0u64, |sum, integrity| {
        fs::metadata(cache.entry_path(integrity)).map_or(sum, |meta| sum.saturating_add(meta.len()))
    });
    compressed.saturating_mul(EXTRACT_RATIO_ESTIMATE)
}

/// The pure pre-flight decision, split out from the disk probe so both arms are
/// directly testable (a filesystem short enough to fail the check is not
/// something a unit test can conjure).
const fn space_verdict(needed: u64, available: u64) -> Result<(), FuziError> {
    if available < needed {
        Err(FuziError::InsufficientSpace { needed, available })
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::{BinCommand, BinTarget, InstallPath, Integrity};
    use crate::plan::FetchInfo;
    use crate::test_support::{
        gz, gz_raw_tar, gz_tar, integrity_of, raw_header, reg, tree_listing,
    };
    use std::os::unix::fs::PermissionsExt as _;
    use tempfile::TempDir;

    /// `len` incompressible bytes (xorshift), so a gzip member of them is
    /// about as large as the bytes themselves.
    fn noise(len: usize) -> Vec<u8> {
        let mut state: u64 = 0x9e37_79b9_7f4a_7c15;
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state.to_le_bytes()[0]
            })
            .collect()
    }

    /// Commit `tarball` into a fresh cache and return `(cache, integrity)`.
    fn cache_with(tarball: &[u8], hold: &TempDir) -> (NpmCache, Integrity) {
        let cache = NpmCache::open(hold.path().join("npm")).unwrap();
        let integrity = integrity_of(tarball);
        let temp = cache.temp_path();
        fs::write(&temp, tarball).unwrap();
        cache.commit(&temp, &integrity).unwrap();
        (cache, integrity)
    }

    /// Build a placement; every `(cmd, target)` must be a valid bin pair (the
    /// malformed/escaping case is refused upstream at classify, not here).
    fn placement(path: &str, integrity: Integrity, bins: &[(&str, &str)]) -> PackagePlacement {
        PackagePlacement {
            path: InstallPath::new(path),
            version: None,
            integrity,
            bins: bins
                .iter()
                .map(|(k, v)| (BinCommand::parse(k).unwrap(), BinTarget::parse(v).unwrap()))
                .collect(),
        }
    }

    fn plan_of(integrity: &Integrity, url: &str, placements: Vec<PackagePlacement>) -> InstallPlan {
        let mut plan = InstallPlan::default();
        plan.fetch_set.insert(
            integrity.clone(),
            FetchInfo {
                resolved: url.to_string(),
            },
        );
        plan.placements = placements;
        plan
    }

    #[test]
    fn materializes_tree_and_links_bin_with_exec_bit() {
        let hold = TempDir::new().unwrap();
        let project = TempDir::new().unwrap();
        // A package shipping a 0644 bin target (npm often does) + package.json.
        let tarball = gz_tar(&[
            reg("package/package.json", 0o644, br#"{"name":"foo"}"#),
            reg("package/bin/cli.js", 0o644, b"#!/usr/bin/env node\n"),
        ]);
        let (cache, integrity) = cache_with(&tarball, &hold);
        let plan = plan_of(
            &integrity,
            "https://registry.npmjs.org/foo/-/foo-1.0.0.tgz",
            vec![placement(
                "node_modules/foo",
                integrity.clone(),
                &[("foo", "bin/cli.js")],
            )],
        );

        let mut report = InstallReport::default();
        materialize(&plan, &cache, project.path(), &mut report).unwrap();

        let nm = project.path().join("node_modules");
        assert!(nm.join("foo/package.json").is_file());
        // bin target is now executable.
        let mode = fs::metadata(nm.join("foo/bin/cli.js"))
            .unwrap()
            .permissions()
            .mode()
            & 0o111;
        assert_ne!(mode, 0, "bin target must be executable");
        // .bin/foo → ../foo/bin/cli.js (relative, resolves to the real file).
        let link = nm.join(".bin/foo");
        assert_eq!(
            fs::read_link(&link).unwrap().to_str().unwrap(),
            "../foo/bin/cli.js"
        );
        assert!(
            fs::metadata(&link).unwrap().is_file(),
            "symlink must resolve"
        );

        assert_eq!(report.placed, 1);
        assert_eq!(report.bins_linked, 1);
        assert_eq!(report.bins_skipped, 0);
    }

    /// Everything the install placed is checked before the publish: removing a
    /// package's directory, the `package.json` its tarball shipped, or a `.bin`
    /// link between the build and the commit refuses the publish as
    /// `StagingIncomplete`, naming what is missing, and `node_modules` stays as
    /// it was. A package whose tarball ships no `package.json` is not held to
    /// one.
    #[test]
    fn a_tree_missing_anything_it_placed_is_not_published() {
        let hold = TempDir::new().unwrap();
        let foo_tarball = gz_tar(&[
            reg("package/package.json", 0o644, br#"{"name":"foo"}"#),
            reg("package/bin/cli.js", 0o644, b"#!/usr/bin/env node\n"),
        ]);
        let bare_tarball = gz_tar(&[reg("package/index.js", 0o644, b"export {}")]);
        let cache = NpmCache::open(hold.path().join("cache")).unwrap();
        let mut integrities = Vec::new();
        for tarball in [&foo_tarball, &bare_tarball] {
            let integrity = integrity_of(tarball);
            let temp = cache.temp_path();
            fs::write(&temp, tarball).unwrap();
            cache.commit(&temp, &integrity).unwrap();
            integrities.push(integrity);
        }
        let mut plan = plan_of(
            &integrities[0],
            "https://registry.npmjs.org/foo/-/foo-1.0.0.tgz",
            vec![
                placement(
                    "node_modules/foo",
                    integrities[0].clone(),
                    &[("foo", "bin/cli.js")],
                ),
                placement("node_modules/bare", integrities[1].clone(), &[]),
            ],
        );
        plan.fetch_set.insert(
            integrities[1].clone(),
            FetchInfo {
                resolved: "https://registry.npmjs.org/bare/-/bare-1.0.0.tgz".to_string(),
            },
        );

        let build = |project: &Path| {
            let mut tree = StagingTree::create(project).unwrap();
            let mut report = InstallReport::default();
            fill_tree(&mut tree, &plan, &cache, project, &mut report).unwrap();
            tree
        };

        // Whole, it publishes — `bare` has no `package.json` and needs none.
        let project = TempDir::new().unwrap();
        build(project.path()).commit().unwrap();
        assert!(project.path().join("node_modules/bare/index.js").is_file());

        for (removed, expected) in [
            ("foo/package.json", StagingEntry::PackageJson),
            (".bin/foo", StagingEntry::BinLink),
            ("foo", StagingEntry::PackageDir),
            ("bare", StagingEntry::PackageDir),
        ] {
            let project = TempDir::new().unwrap();
            let nm = project.path().join("node_modules");
            fs::create_dir(&nm).unwrap();
            fs::write(nm.join("live.txt"), b"live").unwrap();
            let tree = build(project.path());
            let gone = tree.root().join(removed);
            if gone.symlink_metadata().unwrap().is_dir() {
                fs::remove_dir_all(&gone).unwrap();
            } else {
                fs::remove_file(&gone).unwrap();
            }

            let err = tree.commit().unwrap_err();
            match &err {
                FuziError::StagingIncomplete { missing, path } => {
                    assert_eq!(*missing, expected, "{removed}");
                    assert_eq!(path, &gone, "{removed}");
                }
                other => panic!("{removed}: expected StagingIncomplete, got {other:?}"),
            }
            assert_eq!(err.exit_code(), 75);
            let left: Vec<_> = fs::read_dir(project.path())
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .collect();
            assert_eq!(
                left,
                ["node_modules"],
                "{removed}: only the live tree is left"
            );
            let live: Vec<_> = fs::read_dir(&nm)
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .collect();
            assert_eq!(
                live,
                ["live.txt"],
                "{removed}: node_modules was not touched"
            );
        }
    }

    /// A staging root removed under the install (another process's sweep)
    /// fails the next write with `NotFound`, which the install reports as the
    /// vanished root it is — not a bare I/O error — and the root stays gone.
    #[test]
    fn a_removed_staging_root_fails_the_fill_as_staging_incomplete() {
        let hold = TempDir::new().unwrap();
        let project = TempDir::new().unwrap();
        let tarball = gz_tar(&[reg("package/package.json", 0o644, br#"{"name":"foo"}"#)]);
        let (cache, integrity) = cache_with(&tarball, &hold);
        let plan = plan_of(
            &integrity,
            "https://registry.npmjs.org/foo/-/foo-1.0.0.tgz",
            vec![placement("node_modules/foo", integrity.clone(), &[])],
        );

        let mut tree = StagingTree::create(project.path()).unwrap();
        fs::remove_dir_all(tree.root()).unwrap();
        let mut report = InstallReport::default();
        let err = fill_tree(&mut tree, &plan, &cache, project.path(), &mut report).unwrap_err();

        assert!(
            matches!(&err, FuziError::StagingIncomplete { missing: StagingEntry::Root, path }
                if path == tree.root()),
            "{err:?}"
        );
        assert_eq!(err.exit_code(), 75);
        assert!(!tree.root().exists(), "the removed root was re-created");
    }

    #[test]
    fn materializes_tarball_with_a_gzip_member_past_the_end_of_archive() {
        // A tarball can carry a second concatenated gzip member after the tar
        // stream's end-of-archive marker (node decodes and ignores it).
        // `commit` and `verify_cached` hash the *whole file*, so the
        // materialize-time re-verify must too: a tee covering only the prefix
        // the tar layer needs would hash such an entry to a mismatch and
        // falsely read it as `CacheTampered`. The trailing member is
        // incompressible and far larger than the gzip reader's read-ahead
        // window, so buffering cannot mask the bug.
        let hold = TempDir::new().unwrap();
        let project = TempDir::new().unwrap();
        let mut tarball = gz_tar(&[reg("package/index.js", 0o644, b"export {}")]);
        tarball.extend_from_slice(&gz(&noise(256 * 1024)));

        // `cache_with` keys on the whole-file sha512 and `commit` verifies it.
        let (cache, integrity) = cache_with(&tarball, &hold);
        let plan = plan_of(
            &integrity,
            "https://registry.npmjs.org/foo/-/foo-1.0.0.tgz",
            vec![placement("node_modules/foo", integrity.clone(), &[])],
        );

        let mut report = InstallReport::default();
        // Whole-file digest must match the committed key — no false CacheTampered.
        materialize(&plan, &cache, project.path(), &mut report).unwrap();

        let nm = project.path().join("node_modules");
        assert!(nm.join("foo/index.js").is_file());
        assert_eq!(report.placed, 1);
    }

    #[test]
    fn non_gzip_trailing_bytes_refuse_as_an_extract_error() {
        // Bytes past the last gzip member that are not another member fail the
        // gzip layer, as they fail node's zlib — an extract error, not a
        // tamper verdict: the file still hashes to its committed key.
        let hold = TempDir::new().unwrap();
        let project = TempDir::new().unwrap();
        let mut tarball = gz_tar(&[reg("package/index.js", 0o644, b"export {}")]);
        tarball.extend_from_slice(b"fuzi-trailing-bytes");
        let (cache, integrity) = cache_with(&tarball, &hold);
        let plan = plan_of(
            &integrity,
            "https://registry.npmjs.org/foo/-/foo-1.0.0.tgz",
            vec![placement("node_modules/foo", integrity.clone(), &[])],
        );

        let mut report = InstallReport::default();
        let err = materialize(&plan, &cache, project.path(), &mut report).unwrap_err();
        assert!(
            matches!(
                &err,
                FuziError::Extract {
                    package,
                    source: fuz_archive::ArchiveError::Malformed { .. },
                } if package == "node_modules/foo"
            ),
            "{err:?}"
        );
        // A bad package, named, and not worth a re-run.
        assert_eq!(err.exit_code(), 65);
        let message = err.to_string();
        assert!(
            message.starts_with("the tarball for node_modules/foo was refused:"),
            "{message}"
        );
        assert!(!project.path().join("node_modules").exists());
    }

    /// A reader that yields `data`, then fails with `EIO` — a disk error on
    /// the cached file partway through it.
    struct FailingReader<'a> {
        data: &'a [u8],
    }
    impl Read for FailingReader<'_> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.data.is_empty() {
                return Err(std::io::Error::from_raw_os_error(5));
            }
            let n = buf.len().min(self.data.len());
            buf[..n].copy_from_slice(&self.data[..n]);
            self.data = &self.data[n..];
            Ok(n)
        }
    }

    #[test]
    fn a_read_failure_after_a_refused_entry_is_an_io_error() {
        // The first entry trips a guard, so extraction stops early; the rest
        // of the file is hashed to check the digest, and that read fails. The
        // digest was never checked, so this is no verdict on the package — not
        // the 65 that says the bytes match the lockfile — but the read failure.
        let mut data = gz_raw_tar(&[(raw_header(b"../x", tar::EntryType::Regular, 1), b"x")]);
        // Far past the gzip reader's read-ahead, so extraction stops before the
        // failing read and only the drain reaches it.
        data.extend_from_slice(&noise(1024 * 1024));
        let integrity = integrity_of(&data);
        let staging_root = TempDir::new().unwrap();
        let staging = StagingDir::for_tests(staging_root.path().to_path_buf());
        let placement = placement("node_modules/foo", integrity, &[]);

        let err = extract_verified(
            FailingReader { data: &data },
            data.len() as u64,
            &staging,
            &placement,
        )
        .unwrap_err();
        assert_eq!(err.kind(), "io", "{err:?}");
        assert_eq!(err.exit_code(), 74);
        let message = err.to_string();
        assert!(!message.contains("integrity hash"), "{message}");
        assert!(
            message.contains("read cached tarball to verify it after a failed extraction"),
            "{message}"
        );

        // With the read intact the same bytes are the bad package they are.
        let err = extract_verified(&data[..], data.len() as u64, &staging, &placement).unwrap_err();
        assert!(
            matches!(
                &err,
                FuziError::Extract {
                    source: fuz_archive::ArchiveError::InvalidPath(_),
                    ..
                }
            ),
            "{err:?}"
        );
        assert_eq!(err.exit_code(), 65);
    }

    #[test]
    fn materializes_multiple_packages_concurrently() {
        // More than one placement exercises the threaded `extract_all` path
        // (single-placement tests take the sequential fallback). Each package has
        // distinct bytes so its integrity differs.
        let hold = TempDir::new().unwrap();
        let project = TempDir::new().unwrap();
        let cache = NpmCache::open(hold.path().join("npm")).unwrap();
        let mut plan = InstallPlan::default();
        for i in 0..6u32 {
            let data = format!("contents of package {i}");
            let tarball = gz_tar(&[reg("package/index.js", 0o644, data.as_bytes())]);
            let integrity = integrity_of(&tarball);
            let temp = cache.temp_path();
            fs::write(&temp, &tarball).unwrap();
            cache.commit(&temp, &integrity).unwrap();
            plan.fetch_set.insert(
                integrity.clone(),
                FetchInfo {
                    resolved: format!("https://registry.npmjs.org/p{i}/-/p{i}-1.0.0.tgz"),
                },
            );
            plan.placements
                .push(placement(&format!("node_modules/p{i}"), integrity, &[]));
        }

        let mut report = InstallReport::default();
        materialize(&plan, &cache, project.path(), &mut report).unwrap();

        let nm = project.path().join("node_modules");
        for i in 0..6u32 {
            assert!(
                nm.join(format!("p{i}/index.js")).is_file(),
                "p{i} should have extracted"
            );
        }
        assert_eq!(report.placed, 6);
    }

    #[test]
    fn a_tampered_entry_aborts_the_pool_and_leaves_the_live_tree() {
        // Several placements through the threaded `extract_all`, one cached
        // tarball swapped after the fetch: the pool stops, the error is the
        // tamper, the staging tree is gone, and the prior tree is untouched.
        let hold = TempDir::new().unwrap();
        let project = TempDir::new().unwrap();
        let nm = project.path().join("node_modules");
        fs::create_dir(&nm).unwrap();
        fs::write(nm.join("keep.txt"), b"keep").unwrap();

        let cache = NpmCache::open(hold.path().join("npm")).unwrap();
        let mut plan = InstallPlan::default();
        for i in 0..6u32 {
            let data = format!("contents of package {i}");
            let tarball = gz_tar(&[reg("package/index.js", 0o644, data.as_bytes())]);
            let integrity = integrity_of(&tarball);
            let temp = cache.temp_path();
            fs::write(&temp, &tarball).unwrap();
            cache.commit(&temp, &integrity).unwrap();
            if i == 3 {
                let evil = gz_tar(&[reg("package/index.js", 0o644, b"evil")]);
                fs::write(cache.entry_path(&integrity), &evil).unwrap();
            }
            plan.fetch_set.insert(
                integrity.clone(),
                FetchInfo {
                    resolved: format!("https://registry.npmjs.org/p{i}/-/p{i}-1.0.0.tgz"),
                },
            );
            plan.placements
                .push(placement(&format!("node_modules/p{i}"), integrity, &[]));
        }

        let mut report = InstallReport::default();
        let err = materialize(&plan, &cache, project.path(), &mut report).unwrap_err();
        assert!(
            matches!(&err, FuziError::CacheTampered { package } if package == "node_modules/p3"),
            "{err:?}"
        );
        assert_eq!(fs::read(nm.join("keep.txt")).unwrap(), b"keep");
        assert!(!nm.join("p0").exists(), "nothing was published");
        let leftovers: Vec<_> = fs::read_dir(project.path())
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with(".fuzi-"))
            .collect();
        assert!(leftovers.is_empty(), "no staging/old dirs left behind");
        assert_eq!(report.placed, 0);
    }

    #[test]
    fn a_registry_bin_clash_resolves_to_the_later_placement() {
        // Two registry packages declaring the same command into one `.bin`:
        // the sequential bin pass runs in plan order, so the later placement
        // wins — whichever order the plan holds, never a thread race.
        for (first, second) in [("a", "b"), ("b", "a")] {
            let hold = TempDir::new().unwrap();
            let project = TempDir::new().unwrap();
            let cache = NpmCache::open(hold.path().join("npm")).unwrap();
            let mut plan = InstallPlan::default();
            for name in [first, second] {
                let tarball = gz_tar(&[reg("package/cli.js", 0o644, name.as_bytes())]);
                let integrity = integrity_of(&tarball);
                let temp = cache.temp_path();
                fs::write(&temp, &tarball).unwrap();
                cache.commit(&temp, &integrity).unwrap();
                plan.fetch_set.insert(
                    integrity.clone(),
                    FetchInfo {
                        resolved: format!("https://registry.npmjs.org/{name}/-/{name}-1.0.0.tgz"),
                    },
                );
                plan.placements.push(placement(
                    &format!("node_modules/{name}"),
                    integrity,
                    &[("tool", "cli.js")],
                ));
            }

            let mut report = InstallReport::default();
            materialize(&plan, &cache, project.path(), &mut report).unwrap();

            let link = project.path().join("node_modules/.bin/tool");
            assert_eq!(
                fs::read_link(&link).unwrap().to_str().unwrap(),
                format!("../{second}/cli.js")
            );
            assert_eq!(fs::read(&link).unwrap(), second.as_bytes());
            assert_eq!((report.bins_linked, report.bins_skipped), (2, 0));
        }
    }

    #[test]
    fn a_registry_bin_naming_a_directory_is_a_counted_skip() {
        // A bin whose target is a directory: skipped and counted, no link,
        // and the directory's mode untouched (`add_exec_bit_no_follow` never
        // chmods a non-regular file). The mode is one the chmod would visibly
        // change.
        let project = TempDir::new().unwrap();
        let mut tree = StagingTree::create(project.path()).unwrap();
        let foo = placement(
            "node_modules/foo",
            integrity_of(b"unused"),
            &[("tool", "bin/tool")],
        );
        let staging = tree.package_dir(&foo.path).unwrap().unwrap();
        let target = staging.path().join("bin/tool");
        fs::create_dir_all(&target).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();

        let mut report = InstallReport::default();
        link_bins(&mut tree, &foo, staging.path(), &mut report).unwrap();

        assert_eq!((report.bins_linked, report.bins_skipped), (0, 1));
        assert!(fs::symlink_metadata(tree.root().join(".bin/tool")).is_err());
        assert_eq!(
            fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o600,
            "the directory was not chmodded"
        );
    }

    #[test]
    fn parent_vendored_child_does_not_overwrite_childs_own_placement() {
        // The race this slice fixes, made deterministic. Two placements:
        //   - the parent `node_modules/parent`, whose tarball *also ships* a
        //     vendored copy of the child at `node_modules/child/package.json`
        //     with bytes DISTINCT from the child's own tarball;
        //   - the child `node_modules/parent/node_modules/child`, backed by the
        //     child's OWN integrity-verified tarball.
        // The parent's vendored entry strips to
        // `<root>/parent/node_modules/child/package.json` — the exact staging
        // path the child placement owns. Were both written, the two extraction
        // workers would race there (truncating `File::create`, no ordering, engaged
        // only above 1 core), so the final bytes — and thus the whole tree — would be
        // non-deterministic and core-count dependent. The parent's
        // vendored entry is skipped, so the child placement is the sole writer and
        // the child's own bytes always win, regardless of thread timing.
        //
        // This is a regression assertion, not the load-bearing determinism
        // guard: on a single-core / sequential runner the depth-ordered placements
        // make the child's (later) write win even without the skip, so this test
        // alone would not catch the race. The guard that actually pins the behavior is
        // the `extract.rs` unit tests (`skips_node_modules_vendored_entries` /
        // `keeps_node_modules_substring_names_and_full_tree`), which assert the
        // vendored entry never lands regardless of scheduling.
        let hold = TempDir::new().unwrap();
        let project = TempDir::new().unwrap();
        let cache = NpmCache::open(hold.path().join("npm")).unwrap();

        let child_own = br#"{"name":"child","from":"childs-own-tarball"}"#;
        let parent_vendored = br#"{"name":"child","from":"parent-vendored-copy"}"#;

        // Parent ships its own package.json AND a vendored copy of the child.
        let parent_tarball = gz_tar(&[
            reg("package/package.json", 0o644, br#"{"name":"parent"}"#),
            reg(
                "package/node_modules/child/package.json",
                0o644,
                parent_vendored,
            ),
        ]);
        // Child ships only its own package.json (distinct bytes → distinct key).
        let child_tarball = gz_tar(&[reg("package/package.json", 0o644, child_own)]);

        let parent_integrity = integrity_of(&parent_tarball);
        let child_integrity = integrity_of(&child_tarball);

        let temp = cache.temp_path();
        fs::write(&temp, &parent_tarball).unwrap();
        cache.commit(&temp, &parent_integrity).unwrap();
        let temp = cache.temp_path();
        fs::write(&temp, &child_tarball).unwrap();
        cache.commit(&temp, &child_integrity).unwrap();

        let mut plan = InstallPlan::default();
        plan.fetch_set.insert(
            parent_integrity.clone(),
            FetchInfo {
                resolved: "https://registry.npmjs.org/parent/-/parent-1.0.0.tgz".to_string(),
            },
        );
        plan.fetch_set.insert(
            child_integrity.clone(),
            FetchInfo {
                resolved: "https://registry.npmjs.org/child/-/child-1.0.0.tgz".to_string(),
            },
        );
        // Depth-sorted parent-before-child (as `build_plan` emits them).
        plan.placements = vec![
            placement("node_modules/parent", parent_integrity, &[]),
            placement(
                "node_modules/parent/node_modules/child",
                child_integrity,
                &[],
            ),
        ];

        let mut report = InstallReport::default();
        materialize(&plan, &cache, project.path(), &mut report).unwrap();

        // The child directory holds the CHILD's own verified bytes, never the
        // parent's vendored copy — deterministically.
        let child_pkg = project
            .path()
            .join("node_modules/parent/node_modules/child/package.json");
        assert_eq!(
            fs::read(&child_pkg).unwrap().as_slice(),
            child_own.as_slice(),
            "child dir must hold the child's own bytes, not the parent's vendored copy"
        );
        // The parent's own file is present; its vendored `node_modules/` was dropped.
        assert!(
            project
                .path()
                .join("node_modules/parent/package.json")
                .is_file()
        );
        assert_eq!(report.placed, 2);
    }

    #[test]
    fn nested_bin_lands_in_inner_dot_bin() {
        let hold = TempDir::new().unwrap();
        let project = TempDir::new().unwrap();
        let tarball = gz_tar(&[
            reg("package/package.json", 0o644, b"{}"),
            reg("package/run", 0o755, b"x"),
        ]);
        let (cache, integrity) = cache_with(&tarball, &hold);
        let plan = plan_of(
            &integrity,
            "https://registry.npmjs.org/b/-/b-1.0.0.tgz",
            vec![placement(
                "node_modules/a/node_modules/b",
                integrity.clone(),
                &[("b", "run")],
            )],
        );

        let mut report = InstallReport::default();
        materialize(&plan, &cache, project.path(), &mut report).unwrap();

        let inner_bin = project.path().join("node_modules/a/node_modules/.bin/b");
        assert_eq!(
            fs::read_link(&inner_bin).unwrap().to_str().unwrap(),
            "../b/run"
        );
        assert_eq!(report.bins_linked, 1);
    }

    #[test]
    fn missing_bin_target_is_skipped_not_dangling() {
        let hold = TempDir::new().unwrap();
        let project = TempDir::new().unwrap();
        let tarball = gz_tar(&[reg("package/package.json", 0o644, b"{}")]);
        let (cache, integrity) = cache_with(&tarball, &hold);
        let plan = plan_of(
            &integrity,
            "https://registry.npmjs.org/foo/-/foo-1.0.0.tgz",
            // Declares a bin whose target file the tarball does not contain.
            vec![placement(
                "node_modules/foo",
                integrity.clone(),
                &[("foo", "bin/ghost.js")],
            )],
        );

        let mut report = InstallReport::default();
        materialize(&plan, &cache, project.path(), &mut report).unwrap();

        assert!(!project.path().join("node_modules/.bin").exists());
        assert_eq!(report.bins_linked, 0);
        assert_eq!(report.bins_skipped, 1);
    }

    #[test]
    fn cache_tampered_after_fetch_is_detected() {
        let hold = TempDir::new().unwrap();
        let project = TempDir::new().unwrap();
        // Commit an honest tarball, then swap the cached bytes for a *different*
        // but still-valid tarball under the same key (local tamper / corruption
        // between fetch and materialize).
        let honest = gz_tar(&[reg("package/package.json", 0o644, br#"{"name":"honest"}"#)]);
        let (cache, integrity) = cache_with(&honest, &hold);
        let evil = gz_tar(&[reg("package/package.json", 0o644, br#"{"name":"evil"}"#)]);
        fs::write(cache.entry_path(&integrity), &evil).unwrap();

        let plan = plan_of(
            &integrity,
            "https://registry.npmjs.org/foo/-/foo-1.0.0.tgz",
            vec![placement("node_modules/foo", integrity.clone(), &[])],
        );
        let mut report = InstallReport::default();
        let err = materialize(&plan, &cache, project.path(), &mut report).unwrap_err();
        assert!(matches!(err, FuziError::CacheTampered { .. }));
        assert_eq!(err.exit_code(), 65);
        // The hash-while-extract caught it; nothing was published.
        assert!(!project.path().join("node_modules").exists());
    }

    #[test]
    fn a_tampered_entry_that_fails_extraction_reports_as_tampered() {
        // Swapped after the fetch phase's re-verify for a hostile tarball the
        // extractor refuses part-way (a zip-slip entry, followed by more data
        // the failed extraction never reads): the verdict is the tamper, not
        // the extract error its bytes happened to trip.
        let hold = TempDir::new().unwrap();
        let project = TempDir::new().unwrap();
        let honest = gz_tar(&[reg("package/package.json", 0o644, b"{}")]);
        let (cache, integrity) = cache_with(&honest, &hold);
        let mut hostile = gz_raw_tar(&[(
            raw_header(b"package/../../evil.js", tar::EntryType::Regular, 1),
            b"x",
        )]);
        hostile.extend_from_slice(&gz(&vec![7u8; 64 * 1024]));
        fs::write(cache.entry_path(&integrity), &hostile).unwrap();

        let plan = plan_of(
            &integrity,
            "https://registry.npmjs.org/foo/-/foo-1.0.0.tgz",
            vec![placement("node_modules/foo", integrity.clone(), &[])],
        );
        let mut report = InstallReport::default();
        let err = materialize(&plan, &cache, project.path(), &mut report).unwrap_err();
        assert!(matches!(err, FuziError::CacheTampered { .. }), "{err:?}");
        assert_eq!(err.exit_code(), 65);
        assert!(!project.path().join("node_modules").exists());
    }

    #[test]
    fn an_untampered_entry_that_fails_extraction_keeps_the_extract_error() {
        // The digest still matches, so the extract error is the verdict. The
        // refused entry is followed by far more than the gzip reader's
        // read-ahead, so the digest matches only if the rest of the fd is
        // hashed after the failure.
        let hold = TempDir::new().unwrap();
        let project = TempDir::new().unwrap();
        let mut hostile = gz_raw_tar(&[(
            raw_header(b"package/../../evil.js", tar::EntryType::Regular, 1),
            b"x",
        )]);
        hostile.extend_from_slice(&gz(&noise(256 * 1024)));
        let (cache, integrity) = cache_with(&hostile, &hold);
        let plan = plan_of(
            &integrity,
            "https://registry.npmjs.org/foo/-/foo-1.0.0.tgz",
            vec![placement("node_modules/foo", integrity.clone(), &[])],
        );
        let mut report = InstallReport::default();
        let err = materialize(&plan, &cache, project.path(), &mut report).unwrap_err();
        assert!(
            matches!(
                err,
                FuziError::Extract {
                    source: fuz_archive::ArchiveError::InvalidPath(_),
                    ..
                }
            ),
            "{err:?}"
        );
    }

    #[test]
    fn space_verdict_rejects_only_when_short() {
        // The decision the pre-flight exists to make. A filesystem short enough
        // to fail is not something a unit test can conjure, so the reject arm
        // is pinned here on the pure verdict: an inverted comparison — or a
        // check that never rejects — fails this test.
        space_verdict(100, 100).unwrap(); // exactly enough is enough
        space_verdict(100, 1_000).unwrap();
        space_verdict(0, 0).unwrap();
        match space_verdict(1_000, 999).unwrap_err() {
            FuziError::InsufficientSpace { needed, available } => {
                assert_eq!((needed, available), (1_000, 999));
            }
            other => panic!("expected InsufficientSpace, got {other:?}"),
        }
    }

    #[test]
    fn estimate_scales_the_cached_fetch_set() {
        let hold = TempDir::new().unwrap();
        let tarball = gz_tar(&[reg("package/package.json", 0o644, b"{}")]);
        let (cache, integrity) = cache_with(&tarball, &hold);
        let plan = plan_of(
            &integrity,
            "https://registry.npmjs.org/foo/-/foo-1.0.0.tgz",
            vec![placement("node_modules/foo", integrity.clone(), &[])],
        );
        assert_eq!(
            estimated_extracted_bytes(&plan, &cache),
            tarball.len() as u64 * EXTRACT_RATIO_ESTIMATE
        );

        // A fetch-set entry with no cached tarball contributes nothing rather
        // than erroring — the estimate is a hint, not an inventory.
        let mut with_uncached = plan;
        with_uncached.fetch_set.insert(
            integrity_of(b"never cached"),
            FetchInfo {
                resolved: "https://registry.npmjs.org/x/-/x-1.0.0.tgz".to_string(),
            },
        );
        assert_eq!(
            estimated_extracted_bytes(&with_uncached, &cache),
            tarball.len() as u64 * EXTRACT_RATIO_ESTIMATE
        );
    }

    #[test]
    fn preflight_passes_on_a_real_filesystem() {
        let hold = TempDir::new().unwrap();
        let project = TempDir::new().unwrap();
        let tarball = gz_tar(&[reg("package/package.json", 0o644, b"{}")]);
        let (cache, integrity) = cache_with(&tarball, &hold);
        let plan = plan_of(
            &integrity,
            "https://registry.npmjs.org/foo/-/foo-1.0.0.tgz",
            vec![placement("node_modules/foo", integrity.clone(), &[])],
        );
        preflight_space(&plan, &cache, project.path()).unwrap();
    }

    // --- links ---

    /// A workspace `<w>/app` beside `<w>/lib`: the target carries a manifest, a
    /// sentinel, an executable bin, and a non-executable one.
    fn link_workspace() -> (TempDir, PathBuf, PathBuf) {
        let w = TempDir::new().unwrap();
        let app = w.path().join("app");
        let lib = w.path().join("lib");
        fs::create_dir(&app).unwrap();
        fs::create_dir_all(lib.join("bin")).unwrap();
        fs::write(lib.join("package.json"), br#"{"name":"lib"}"#).unwrap();
        fs::write(lib.join("sentinel"), b"keep").unwrap();
        fs::write(lib.join("bin/run.js"), b"#!/usr/bin/env node\n").unwrap();
        fs::set_permissions(lib.join("bin/run.js"), fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(lib.join("bin/plain.js"), b"#!/usr/bin/env node\n").unwrap();
        fs::set_permissions(lib.join("bin/plain.js"), fs::Permissions::from_mode(0o644)).unwrap();
        (w, app, lib)
    }

    fn lib_link(bins: &[(&str, &str)]) -> LinkPlacement {
        let crate::entry::LinkTargetParse::Ok(target) = crate::entry::LinkTarget::parse("../lib")
        else {
            panic!("sibling must parse");
        };
        LinkPlacement {
            path: InstallPath::new("node_modules/@s/lib"),
            target,
            name: Some("lib".to_string()),
            version: None,
            bins: bins
                .iter()
                .map(|(k, v)| (BinCommand::parse(k).unwrap(), BinTarget::parse(v).unwrap()))
                .collect(),
        }
    }

    /// A plan with one registry package `node_modules/foo` plus `links`.
    fn plan_with_links(hold: &TempDir, links: Vec<LinkPlacement>) -> (NpmCache, InstallPlan) {
        let tarball = gz_tar(&[reg("package/package.json", 0o644, br#"{"name":"foo"}"#)]);
        let (cache, integrity) = cache_with(&tarball, hold);
        let mut plan = plan_of(
            &integrity,
            "https://registry.npmjs.org/foo/-/foo-1.0.0.tgz",
            vec![placement("node_modules/foo", integrity.clone(), &[])],
        );
        plan.links = links;
        (cache, plan)
    }

    #[test]
    fn link_is_placed_and_resolves_after_commit() {
        let hold = TempDir::new().unwrap();
        let (_w, app, lib) = link_workspace();
        let (cache, plan) = plan_with_links(&hold, vec![lib_link(&[])]);
        let mut report = InstallReport::default();
        materialize(&plan, &cache, &app, &mut report).unwrap();

        let link = app.join("node_modules/@s/lib");
        assert!(
            fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(
            fs::read_link(&link).unwrap().to_str().unwrap(),
            "../../../lib"
        );
        assert_eq!(fs::read(link.join("sentinel")).unwrap(), b"keep");
        assert!(app.join("node_modules/foo/package.json").is_file());
        assert_eq!(report.linked, 1);
        assert_eq!(report.placed, 1);
        // Nothing was written into the target.
        let mut names: Vec<_> = fs::read_dir(&lib)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        assert_eq!(names, ["bin", "package.json", "sentinel"]);
    }

    #[test]
    fn reinstall_over_a_tree_with_a_link_leaves_the_target_intact() {
        // Pin: the displaced tree's removal unlinks the old link; it never
        // descends into the sibling.
        let hold = TempDir::new().unwrap();
        let (_w, app, lib) = link_workspace();
        let (cache, plan) = plan_with_links(&hold, vec![lib_link(&[])]);
        let mut report = InstallReport::default();
        materialize(&plan, &cache, &app, &mut report).unwrap();
        let mut again = InstallReport::default();
        materialize(&plan, &cache, &app, &mut again).unwrap();
        assert_eq!(fs::read(lib.join("sentinel")).unwrap(), b"keep");
        assert!(lib.join("package.json").is_file());
        assert_eq!(again.linked, 1);
    }

    #[test]
    fn linked_bins_link_only_executables_and_never_chmod() {
        let hold = TempDir::new().unwrap();
        let (_w, app, lib) = link_workspace();
        let (cache, plan) = plan_with_links(
            &hold,
            vec![lib_link(&[
                ("run", "bin/run.js"),
                ("plain", "bin/plain.js"),
                ("ghost", "bin/ghost.js"),
            ])],
        );
        let mut report = InstallReport::default();
        materialize(&plan, &cache, &app, &mut report).unwrap();

        let run = app.join("node_modules/.bin/run");
        assert_eq!(
            fs::read_link(&run).unwrap().to_str().unwrap(),
            "../@s/lib/bin/run.js"
        );
        assert!(
            fs::metadata(&run).unwrap().is_file(),
            "resolves through the link"
        );
        assert!(!app.join("node_modules/.bin/plain").exists());
        assert!(fs::symlink_metadata(app.join("node_modules/.bin/plain")).is_err());
        assert!(!app.join("node_modules/.bin/ghost").exists());
        assert_eq!(report.bins_linked, 1);
        assert_eq!(report.bins_skipped, 2);
        // The non-executable target keeps its mode — fuzi never writes there.
        let mode = fs::metadata(lib.join("bin/plain.js"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o644);
    }

    #[test]
    fn linked_bin_through_a_symlinked_parent_is_skipped() {
        // `.bin/x -> ../@s/lib/out/run.js` would resolve out of the target
        // through `out`. Every parent under the target must be a real directory.
        let hold = TempDir::new().unwrap();
        let (w, app, lib) = link_workspace();
        let outside = w.path().join("outside");
        fs::create_dir(&outside).unwrap();
        fs::copy(lib.join("bin/run.js"), outside.join("run.js")).unwrap();
        symlink(&outside, lib.join("out")).unwrap();
        // A parent symlink that stays inside the target is skipped the same way.
        symlink("bin", lib.join("alias")).unwrap();
        let before = (tree_listing(&lib), tree_listing(&outside));
        let (cache, plan) = plan_with_links(
            &hold,
            vec![lib_link(&[
                ("escapes", "out/run.js"),
                ("aliased", "alias/run.js"),
                ("run", "bin/run.js"),
            ])],
        );
        let mut report = InstallReport::default();
        materialize(&plan, &cache, &app, &mut report).unwrap();

        let bin = app.join("node_modules/.bin");
        assert!(fs::symlink_metadata(bin.join("escapes")).is_err());
        assert!(fs::symlink_metadata(bin.join("aliased")).is_err());
        assert!(fs::metadata(bin.join("run")).unwrap().is_file());
        assert_eq!((report.bins_linked, report.bins_skipped), (1, 2));
        assert_eq!((tree_listing(&lib), tree_listing(&outside)), before);
    }

    #[test]
    fn linked_bin_that_is_a_symlink_or_a_directory_is_skipped() {
        // A counted skip, never an error — and where npm would link (and chmod)
        // a symlinked bin, fuzi links nothing: the shim would run whatever the
        // symlink points at.
        let hold = TempDir::new().unwrap();
        let (w, app, lib) = link_workspace();
        let outside = w.path().join("outside.js");
        fs::write(&outside, b"#!/usr/bin/env node\n").unwrap();
        fs::set_permissions(&outside, fs::Permissions::from_mode(0o755)).unwrap();
        symlink(&outside, lib.join("bin/far.js")).unwrap();
        symlink("run.js", lib.join("bin/near.js")).unwrap();
        let before = tree_listing(&lib);
        let (cache, plan) = plan_with_links(
            &hold,
            vec![lib_link(&[
                ("far", "bin/far.js"),
                ("near", "bin/near.js"),
                ("dir", "bin"),
                ("run", "bin/run.js"),
            ])],
        );
        let mut report = InstallReport::default();
        materialize(&plan, &cache, &app, &mut report).unwrap();

        let bin = app.join("node_modules/.bin");
        for skipped in ["far", "near", "dir"] {
            assert!(
                fs::symlink_metadata(bin.join(skipped)).is_err(),
                "{skipped}"
            );
        }
        assert!(fs::metadata(bin.join("run")).unwrap().is_file());
        assert_eq!((report.bins_linked, report.bins_skipped), (1, 3));
        assert_eq!(tree_listing(&lib), before);
        assert_eq!(
            fs::metadata(&outside).unwrap().permissions().mode() & 0o777,
            0o755
        );
    }

    #[test]
    fn linked_bin_wins_a_name_collision_and_the_registry_package_is_untouched() {
        // Pin: linked bins are written after registry bins, so on a shared
        // command name the link's shim replaces the registry package's. Only
        // the `.bin` entry changes hands — both packages keep their files.
        let hold = TempDir::new().unwrap();
        let (_w, app, lib) = link_workspace();
        let before = tree_listing(&lib);
        let tarball = gz_tar(&[
            reg("package/package.json", 0o644, br#"{"name":"foo"}"#),
            reg("package/cli.js", 0o644, b"#!/usr/bin/env node\n// foo\n"),
        ]);
        let (cache, integrity) = cache_with(&tarball, &hold);
        let mut plan = plan_of(
            &integrity,
            "https://registry.npmjs.org/foo/-/foo-1.0.0.tgz",
            vec![placement(
                "node_modules/foo",
                integrity.clone(),
                &[("run", "cli.js"), ("foo", "cli.js")],
            )],
        );
        plan.links = vec![lib_link(&[("run", "bin/run.js")])];
        let mut report = InstallReport::default();
        materialize(&plan, &cache, &app, &mut report).unwrap();

        let nm = app.join("node_modules");
        assert_eq!(
            fs::read_link(nm.join(".bin/run"))
                .unwrap()
                .to_str()
                .unwrap(),
            "../@s/lib/bin/run.js",
            "the link's bin wins"
        );
        assert_eq!(
            fs::read_link(nm.join(".bin/foo"))
                .unwrap()
                .to_str()
                .unwrap(),
            "../foo/cli.js"
        );
        // The loser's package is whole: its bin target is still there, still
        // its own bytes, and still made executable.
        assert_eq!(
            fs::read(nm.join("foo/cli.js")).unwrap(),
            b"#!/usr/bin/env node\n// foo\n"
        );
        assert_ne!(
            fs::metadata(nm.join("foo/cli.js"))
                .unwrap()
                .permissions()
                .mode()
                & 0o111,
            0
        );
        assert_eq!(report.bins_linked, 3, "each write is counted");
        assert_eq!(tree_listing(&lib), before);
    }

    #[test]
    fn a_target_that_stops_passing_the_check_is_caught_before_publish() {
        // The link-target check runs again just before the tree is published:
        // a target that is no longer the lockfile's package (here, from the
        // start — `materialize` is handed the plan directly) stops the install
        // with the existing `node_modules` in place and no staging tree left.
        let hold = TempDir::new().unwrap();
        let (_w, app, lib) = link_workspace();
        fs::write(lib.join("package.json"), br#"{"name":"impostor"}"#).unwrap();
        let before = tree_listing(&lib);
        fs::create_dir(app.join("node_modules")).unwrap();
        fs::write(app.join("node_modules/keep.txt"), b"keep").unwrap();
        let project_before = tree_listing(&app);
        let (cache, plan) = plan_with_links(&hold, vec![lib_link(&[("run", "bin/run.js")])]);
        let mut report = InstallReport::default();
        let err = materialize(&plan, &cache, &app, &mut report).unwrap_err();
        match &err {
            FuziError::LinkTarget { problems } => {
                assert!(problems[0].detail.contains("impostor"), "{problems:?}");
            }
            other => panic!("expected LinkTarget, got {other:?}"),
        }
        assert_eq!(err.exit_code(), 65);
        assert_eq!(tree_listing(&lib), before);
        assert_eq!(
            tree_listing(&app),
            project_before,
            "the old tree is in place and no staging tree is left"
        );
    }

    #[test]
    fn a_target_linking_back_to_the_project_is_not_a_loop() {
        // The target's own `node_modules/app -> ../../app` points back at the
        // project, so `app/node_modules/@s/lib/node_modules/app/…` cycles
        // forever by name. fuzi never lists or descends into a target, so
        // install, reinstall, verify, and clean all finish, and the target —
        // back-link included — is exactly as it was.
        let hold = TempDir::new().unwrap();
        let (_w, app, lib) = link_workspace();
        fs::create_dir(lib.join("node_modules")).unwrap();
        symlink("../../app", lib.join("node_modules/app")).unwrap();
        let before = tree_listing(&lib);
        fs::write(
            app.join("package-lock.json"),
            serde_json::json!({
                "lockfileVersion": 3,
                "packages": {
                    "": {"name": "app"},
                    "node_modules/@s/lib": {"resolved": "../lib", "link": true},
                    "../lib": {"name": "lib", "bin": {"run": "bin/run.js"}}
                }
            })
            .to_string(),
        )
        .unwrap();
        let raw = crate::read_lockfile(&app).unwrap();
        let host = crate::test_support::host_linux_x64_glibc();
        let plan = crate::build_plan(&raw, &host, &[]).unwrap();
        let cache = NpmCache::open(hold.path().join("npm")).unwrap();

        for _ in 0..2 {
            check_link_targets(&plan, &app).unwrap();
            let mut report = InstallReport::default();
            materialize(&plan, &cache, &app, &mut report).unwrap();
            assert_eq!((report.linked, report.bins_linked), (1, 1));
            assert!(
                app.join("node_modules/@s/lib/node_modules/app/node_modules/@s/lib/sentinel")
                    .is_file(),
                "sanity: the cycle resolves by name"
            );
            let verified = crate::verify_against(&raw, &host, &[], &app).unwrap();
            assert_eq!(verified.links_checked, 1);
            // A leaked staging tree holding the same link, for `clean` to sweep.
            let leaked = app.join(".fuzi-installing-leak");
            fs::create_dir(&leaked).unwrap();
            symlink("../../lib", leaked.join("lib")).unwrap();
            let swept = crate::clean(&app, false).unwrap();
            assert_eq!(swept.removed, [".fuzi-installing-leak"]);
            assert_eq!(tree_listing(&lib), before);
        }
    }

    #[test]
    fn a_placement_under_a_link_is_refused_before_anything_is_built() {
        let hold = TempDir::new().unwrap();
        let (_w, app, lib) = link_workspace();
        let (cache, mut plan) = plan_with_links(&hold, vec![lib_link(&[])]);
        let integrity = plan.placements[0].integrity.clone();
        plan.placements.push(placement(
            "node_modules/@s/lib/node_modules/x",
            integrity,
            &[],
        ));
        let mut report = InstallReport::default();
        let err = materialize(&plan, &cache, &app, &mut report).unwrap_err();
        assert!(
            matches!(err, FuziError::UnsafeStagingPath { .. }),
            "{err:?}"
        );
        assert!(!app.join("node_modules").exists());
        assert!(!lib.join("node_modules").exists());
    }

    #[test]
    fn a_link_under_another_link_is_refused_and_the_target_untouched() {
        // A hand-built plan: `@s/lib/x` would be created through the `@s/lib`
        // symlink, i.e. inside the sibling target.
        let hold = TempDir::new().unwrap();
        let (_w, app, lib) = link_workspace();
        let mut nested = lib_link(&[]);
        nested.path = InstallPath::new("node_modules/@s/lib/x");
        let (cache, plan) = plan_with_links(&hold, vec![lib_link(&[]), nested]);
        let mut report = InstallReport::default();
        let err = materialize(&plan, &cache, &app, &mut report).unwrap_err();
        assert!(
            matches!(err, FuziError::UnsafeStagingPath { .. }),
            "{err:?}"
        );
        assert!(
            fs::symlink_metadata(lib.join("x")).is_err(),
            "nothing in the target"
        );
        assert!(!app.join("node_modules").exists());
    }

    #[test]
    fn a_link_at_dot_bin_is_refused_and_the_target_untouched() {
        // A hand-built plan: a link at `node_modules/.bin` makes the `.bin`
        // directory a symlink to the sibling, so the registry package's bin
        // link would be unlinked and created inside the target.
        let hold = TempDir::new().unwrap();
        let (_w, app, lib) = link_workspace();
        let before = tree_listing(&lib);
        let tarball = gz_tar(&[
            reg("package/package.json", 0o644, br#"{"name":"foo"}"#),
            reg("package/cli.js", 0o755, b"#!/usr/bin/env node\n"),
        ]);
        let (cache, integrity) = cache_with(&tarball, &hold);
        let mut plan = plan_of(
            &integrity,
            "https://registry.npmjs.org/foo/-/foo-1.0.0.tgz",
            // `sentinel` is a file the target already holds: the bin pass would
            // unlink it before writing its own link.
            vec![placement(
                "node_modules/foo",
                integrity.clone(),
                &[("sentinel", "cli.js")],
            )],
        );
        let mut dot_bin = lib_link(&[]);
        dot_bin.path = InstallPath::new("node_modules/.bin");
        plan.links = vec![dot_bin];

        let mut report = InstallReport::default();
        let err = materialize(&plan, &cache, &app, &mut report).unwrap_err();
        assert!(
            matches!(err, FuziError::UnsafeStagingPath { .. }),
            "{err:?}"
        );
        assert_eq!(tree_listing(&lib), before, "the target is untouched");
        assert!(!app.join("node_modules").exists());
    }

    #[test]
    fn a_placement_at_a_scope_directory_is_refused_and_the_target_untouched() {
        // A hand-built plan: a registry placement AT `node_modules/@s`, a link
        // inside it at `node_modules/@s/lib`, and a registry bin whose path
        // runs through that link — the bin pass would chmod the sibling's file.
        let hold = TempDir::new().unwrap();
        let (_w, app, lib) = link_workspace();
        let before = tree_listing(&lib);
        let tarball = gz_tar(&[reg("package/package.json", 0o644, br#"{"name":"foo"}"#)]);
        let (cache, integrity) = cache_with(&tarball, &hold);
        let mut plan = plan_of(
            &integrity,
            "https://registry.npmjs.org/foo/-/foo-1.0.0.tgz",
            vec![placement(
                "node_modules/@s",
                integrity.clone(),
                &[("x", "lib/bin/plain.js")],
            )],
        );
        plan.links = vec![lib_link(&[])];

        let mut report = InstallReport::default();
        let err = materialize(&plan, &cache, &app, &mut report).unwrap_err();
        assert!(
            matches!(err, FuziError::UnsafeStagingPath { .. }),
            "{err:?}"
        );
        assert_eq!(tree_listing(&lib), before, "the target is untouched");
        assert!(!app.join("node_modules").exists());
    }

    #[test]
    fn registry_bin_through_a_symlinked_directory_is_skipped_not_chmodded() {
        // Extraction rejects symlink entries and the key gates keep a link out
        // of a package's directory, so nothing fuzi builds puts a symlink on a
        // registry bin's path. The bin pass does not lean on that: planted here
        // by hand, a symlinked directory on the path makes the bin a counted
        // skip, and the file behind it keeps its mode.
        let project = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        let victim = outside.path().join("victim.js");
        fs::write(&victim, b"#!/usr/bin/env node\n").unwrap();
        fs::set_permissions(&victim, fs::Permissions::from_mode(0o644)).unwrap();

        let mut tree = StagingTree::create(project.path()).unwrap();
        let foo = placement(
            "node_modules/foo",
            integrity_of(b"unused"),
            &[("through", "out/victim.js"), ("direct", "cli.js")],
        );
        let staging = tree.package_dir(&foo.path).unwrap().unwrap();
        fs::write(staging.path().join("cli.js"), b"#!/usr/bin/env node\n").unwrap();
        symlink(outside.path(), staging.path().join("out")).unwrap();

        let mut report = InstallReport::default();
        link_bins(&mut tree, &foo, staging.path(), &mut report).unwrap();

        assert_eq!((report.bins_linked, report.bins_skipped), (1, 1));
        assert!(fs::symlink_metadata(tree.root().join(".bin/through")).is_err());
        assert!(fs::symlink_metadata(tree.root().join(".bin/direct")).is_ok());
        assert_eq!(
            fs::metadata(&victim).unwrap().permissions().mode() & 0o777,
            0o644,
            "nothing was chmodded through the symlink"
        );
    }

    #[test]
    fn duplicate_link_keys_are_refused() {
        let hold = TempDir::new().unwrap();
        let (_w, app, lib) = link_workspace();
        let (cache, plan) = plan_with_links(&hold, vec![lib_link(&[]), lib_link(&[])]);
        let mut report = InstallReport::default();
        let err = materialize(&plan, &cache, &app, &mut report).unwrap_err();
        assert!(
            matches!(err, FuziError::UnsafeStagingPath { .. }),
            "{err:?}"
        );
        assert!(lib.join("sentinel").is_file());
    }

    #[test]
    fn drop_on_extract_error_leaves_existing_node_modules() {
        let hold = TempDir::new().unwrap();
        let project = TempDir::new().unwrap();
        // Pre-existing node_modules that must survive a failed install.
        let nm = project.path().join("node_modules");
        fs::create_dir(&nm).unwrap();
        fs::write(nm.join("keep.txt"), b"keep").unwrap();

        // A plan whose integrity is NOT in the cache: the cached tarball is
        // absent, so `extract_into`'s open fails.
        let absent = integrity_of(b"never cached");
        let cache = NpmCache::open(hold.path().join("npm")).unwrap();
        let plan = plan_of(
            &absent,
            "https://registry.npmjs.org/x/-/x-1.0.0.tgz",
            vec![placement("node_modules/x", absent.clone(), &[])],
        );

        let mut report = InstallReport::default();
        let err = materialize(&plan, &cache, project.path(), &mut report).unwrap_err();
        assert!(matches!(err, FuziError::Io { .. }));
        // The prior tree is untouched; no staging dir was left behind.
        assert!(nm.join("keep.txt").exists());
        let leftovers: Vec<_> = fs::read_dir(project.path())
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with(".fuzi-"))
            .collect();
        assert!(leftovers.is_empty(), "no staging/old dirs left behind");
    }
}
