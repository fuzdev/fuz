//! Fetch + verify: turn an [`InstallPlan`]'s dedup-by-`Integrity` `fetch_set`
//! into a populated, verified [`NpmCache`].
//!
//! The transport is inverted behind [`TarballSource`] (the real
//! [`NpmTarballSource`] over `reqwest`, the test [`FixtureSource`] over an
//! in-memory map), so the verify→commit orchestration is exercisable with zero
//! network. Verification is *not* the source's job — it streams bytes; the cache
//! hashes them on `commit` (commit-is-verify). `--offline` rides the same seam
//! as `Option<&S>`: a miss with no source is [`FuziError::OfflineCacheMiss`], so
//! there is one orchestration path, not an offline branch.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use futures::StreamExt as _;

use crate::cache::{CacheError, NpmCache};
use crate::entry::Integrity;
use crate::error::{
    CorruptCacheItem, FetchFailure, FuziError, IntegrityMismatchItem, io_err, io_from_cache,
};
use crate::plan::InstallPlan;
use crate::report::{FetchOutcome, InstallReport};

mod npm;
pub use npm::{ClientInitError, NpmTarballSource};

/// Default bounded-download concurrency. The `fetch_set` is already deduped, so
/// there is no intra-process same-key race; the bound just caps open
/// connections + open file descriptors.
pub const DEFAULT_FETCH_CONCURRENCY: usize = 8;

/// A transport failure streaming a tarball. **Transport-only** — never an
/// integrity verdict (that lives in [`NpmCache::commit`]).
///
/// Split by *retryability*, because the exit-code taxonomy promises it: a
/// transient failure exits `EX_TEMPFAIL` ("re-run to retry") while a permanent
/// one must not, or an agent obeying the taxonomy retries a yanked tarball
/// forever. [`FetchError::is_permanent`] is the single source of that verdict.
#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    /// The HTTP request / response failed transiently (connection, timeout,
    /// mid-stream read, a 5xx, or a "not now" 408 / 429) — re-running is the
    /// retry.
    #[error("{0}")]
    Transport(String),

    /// The registry answered definitively: the tarball will not be served as
    /// requested (a 4xx other than 408 / 429 — yanked / renamed /
    /// auth-required, or a 425, which is no replay refusal since fuzi sends no
    /// early data — or a refused redirect). Re-running cannot fix it; the
    /// lockfile must change.
    #[error("{0}")]
    Permanent(String),

    /// The response exceeded the per-tarball byte cap.
    #[error("tarball exceeds the {max}-byte cap (received at least {got})")]
    TooLarge {
        /// Bytes received before the cap tripped.
        got: u64,
        /// The cap.
        max: u64,
    },

    /// The registry's TLS certificate was rejected (expired, untrusted issuer,
    /// wrong name …) — the same chain fails the same trust on every run, so
    /// this is neither transient nor the registry's answer about the tarball.
    #[error("TLS certificate rejected for {host}: {reason}")]
    TlsCertificate {
        /// The host whose certificate was rejected.
        host: String,
        /// rustls's verdict.
        reason: String,
    },

    /// Writing the temp file failed.
    #[error("{what}: {source}")]
    Io {
        /// The operation being attempted.
        what: &'static str,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },
}

impl FetchError {
    /// True when re-running the same install cannot succeed: the registry
    /// refused this URL outright, or the tarball is over fuzi's cap.
    ///
    /// Only meaningful for the *transport* outcomes. [`Io`](FetchError::Io) and
    /// [`TlsCertificate`](FetchError::TlsCertificate) are neither — a local disk
    /// failure or a rejected certificate is not a verdict about the tarball, so
    /// neither reaches this predicate: callers match them out first and raise
    /// [`FuziError::Io`] / [`FuziError::TlsCertificate`].
    #[must_use]
    pub const fn is_permanent(&self) -> bool {
        matches!(self, Self::Permanent(_) | Self::TooLarge { .. })
    }
}

/// A read-only source of npm tarball bytes, addressed by URL.
///
/// **Transport-only — never verifies** (hashing is the cache's job). The
/// per-tarball byte cap lives in the concrete impl, not this signature. **Not
/// object-safe** (RPITIT): consumed as a generic bound by [`run_fetch_phase`] /
/// `install` — never as `Arc<dyn>`.
pub trait TarballSource: Send + Sync {
    /// Stream the tarball at `url` into `dest`, returning the byte count.
    ///
    /// On **every** error the implementation removes whatever it left at
    /// `dest` — both impls route their write through `removing_dest_on_error`
    /// so no arm can forget it. Callers also remove `dest` defensively, which
    /// additionally covers a fetch cancelled mid-write.
    fn fetch_to_file(
        &self,
        url: &str,
        dest: &Path,
    ) -> impl Future<Output = Result<u64, FetchError>> + Send;
}

/// An in-memory, zero-network [`TarballSource`] for tests: a `url → bytes` map.
#[derive(Debug, Clone, Default)]
pub struct FixtureSource {
    tarballs: std::collections::HashMap<String, Vec<u8>>,
}

impl FixtureSource {
    /// An empty source (every fetch is a miss).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register `bytes` to serve for `url` (builder style).
    #[must_use]
    pub fn with(mut self, url: impl Into<String>, bytes: impl Into<Vec<u8>>) -> Self {
        self.tarballs.insert(url.into(), bytes.into());
        self
    }
}

impl TarballSource for FixtureSource {
    async fn fetch_to_file(&self, url: &str, dest: &Path) -> Result<u64, FetchError> {
        removing_dest_on_error(dest, async {
            let bytes = self
                .tarballs
                .get(url)
                .ok_or_else(|| FetchError::Transport(format!("no fixture registered for {url}")))?;
            tokio::fs::write(dest, bytes)
                .await
                .map_err(|source| FetchError::Io {
                    what: "write fixture tarball",
                    source,
                })?;
            Ok(bytes.len() as u64)
        })
        .await
    }
}

/// Await a source's write into `dest`, removing whatever it left there when it
/// fails — the single place the [`TarballSource`] cleanup contract is kept, so
/// a new error arm in an impl inherits it rather than having to remember it.
///
/// The removal is best effort (a lost unlink costs only disk: the temp is a
/// `.dl-*` name the cache's age-gated sweep reaps, and never a cache hit).
async fn removing_dest_on_error(
    dest: &Path,
    write: impl Future<Output = Result<u64, FetchError>>,
) -> Result<u64, FetchError> {
    let result = write.await;
    if result.is_err() {
        let _ = tokio::fs::remove_file(dest).await;
    }
    result
}

/// Run the fetch + verify phase: populate the CAS from `plan.fetch_set`.
///
/// For each unique tarball: a cache hit re-verifies on read (corrupt → heal
/// online, reported in [`InstallReport::healed`] / refuse loud offline); a miss streams through `source` and
/// commits-which-verifies. Outcomes are collected (not fail-fast): every
/// transport failure, every integrity mismatch, and every offline miss is
/// reported in one pass, and successful tarballs stay committed (a re-run is
/// incremental). The aggregate error favors the most severe class
/// (mismatch → offline-corrupt → permanent → offline miss → transient).
///
/// Two failures abort instead of being collected: a local disk failure —
/// writing a download temp, or the cache's own hashing, landing, or re-reading
/// — as [`FuziError::Io`], and a registry certificate this machine does not
/// trust as [`FuziError::TlsCertificate`]. Re-running fixes neither:
/// every further write meets the same disk, and every further tarball from
/// that host the same verdict (one from another host is cancelled with the
/// rest — the trust must be fixed either way). The abort is immediate, but it
/// does not outrank a hash alarm already collected: a mismatch or an
/// offline-corrupt entry in hand is returned in its place, so a late disk error
/// never hides a supply-chain alarm. (An alarm still in flight is cancelled
/// with the rest — the abort cannot wait on fetches that may never end.)
/// Returning drops the download stream, which cancels the in-flight fetches
/// (each one's temp is removed as its future drops — a create still running on
/// the blocking pool can outlive that, leaving a `.dl-*` the age-gated sweep
/// reaps); a hash-and-rename already handed to the blocking pool runs to its
/// own end, landing verified bytes or removing its temp.
///
/// `source` is `None` under `--offline`. Downloads run with bounded
/// concurrency.
///
/// # Errors
///
/// Returns [`FuziError::IntegrityMismatch`], [`FuziError::OfflineCacheCorrupt`],
/// [`FuziError::FetchPermanent`], [`FuziError::OfflineCacheMiss`],
/// [`FuziError::Fetch`], or [`FuziError::Io`] as described above.
pub async fn run_fetch_phase<S: TarballSource>(
    plan: &InstallPlan,
    cache: &NpmCache,
    source: Option<&S>,
    concurrency: usize,
) -> Result<InstallReport, FuziError> {
    let labels = PackageLabels::new(plan);
    let label_for = |integrity: &Integrity| labels.label(integrity);

    let tasks = plan.fetch_set.iter().map(|(integrity, info)| async move {
        let resolution = fetch_one(cache, source, integrity, &info.resolved).await?;
        Ok::<(&Integrity, TarballResolution), FuziError>((integrity, resolution))
    });

    let mut resolutions = futures::stream::iter(tasks).buffer_unordered(concurrency.max(1));

    let mut report = InstallReport::default();
    let mut failures = FetchFailures::default();

    while let Some(resolution) = resolutions.next().await {
        // A hard disk (or TLS trust) error aborts the phase now, not after every
        // other fetch: returning drops `resolutions`, cancelling what is still
        // in flight. A hash alarm already collected still outranks it.
        let (integrity, resolution) = match resolution {
            Ok(resolved) => resolved,
            Err(abort) => return Err(failures.outranking(abort)),
        };
        match resolution {
            TarballResolution::Done(outcome) => report.record(outcome),
            TarballResolution::Healed { bytes } => {
                report.record(FetchOutcome::Fetched { bytes });
                report.healed.push(label_for(integrity));
            }
            TarballResolution::Mismatch { expected, actual } => {
                failures.mismatches.push(IntegrityMismatchItem {
                    package: label_for(integrity),
                    expected,
                    actual,
                });
            }
            TarballResolution::Transport { reason } => failures.transient.push(FetchFailure {
                package: label_for(integrity),
                reason,
            }),
            TarballResolution::PermanentFetch { reason } => failures.permanent.push(FetchFailure {
                package: label_for(integrity),
                reason,
            }),
            TarballResolution::OfflineUnavailable => failures.offline.push(label_for(integrity)),
            TarballResolution::OfflineCorrupt => failures.corrupt.push(CorruptCacheItem {
                package: label_for(integrity),
                path: cache.entry_path(integrity).display().to_string(),
            }),
        }
    }

    // Completion order, like the failures below: sorted so `--json` is stable.
    report.healed.sort();
    failures.sort();
    failures.into_error().map_or(Ok(report), Err)
}

/// The human label of each unique tarball: its first placement's install path.
///
/// Users debug by name; the `fetch_set` is hash-keyed and a scoped tarball
/// basename drops the scope, so the install path is the reliable source. Falls
/// back to the SRI. Shared by the fetch phase and the `--dry-run --offline`
/// probe, so both name a cache miss the same way.
///
/// Indexed once rather than scanned per failure: a run where *every* tarball
/// fails (a cold `--offline`) would otherwise walk all placements once per
/// failure.
pub struct PackageLabels<'a>(BTreeMap<&'a Integrity, &'a str>);

impl<'a> PackageLabels<'a> {
    /// Index `plan`'s placements by integrity.
    pub fn new(plan: &'a InstallPlan) -> Self {
        // Reversed so the shallowest (first, depth-sorted) placement wins the
        // key — collecting keeps the last insert.
        Self(
            plan.placements
                .iter()
                .rev()
                .map(|p| (&p.integrity, p.path.as_str()))
                .collect(),
        )
    }

    /// The label for one tarball.
    pub fn label(&self, integrity: &Integrity) -> String {
        self.0
            .get(integrity)
            .map_or_else(|| integrity.to_sri(), |path| (*path).to_string())
    }
}

/// Per-tarball failures accumulated across the fetch phase (accumulate, don't
/// fail-fast — mirroring `classify`), collapsed at the end to the single
/// most-severe class. The payloads are structured so `--json` re-renders them.
#[derive(Default)]
struct FetchFailures {
    /// Supply-chain alarms (most severe).
    mismatches: Vec<IntegrityMismatchItem>,
    /// `--offline` found these cached tarballs failing re-verification — local
    /// corruption or tampering, with no source to heal from.
    corrupt: Vec<CorruptCacheItem>,
    /// Definitive registry refusals (4xx / oversize) — re-running cannot help.
    permanent: Vec<FetchFailure>,
    /// `--offline` could not satisfy these (package labels).
    offline: Vec<String>,
    /// Transient transport failures (least severe — re-run retries).
    transient: Vec<FetchFailure>,
}

impl FetchFailures {
    /// Order every class by package label.
    ///
    /// `buffer_unordered` yields resolutions in **completion** order — network
    /// timing on the online path, blocking-pool scheduling on the cache-hit path
    /// — so without this the `--json` `failures` / `packages` arrays differ run
    /// to run for the *same* failing lockfile. That churn is noise for the agent
    /// consumer the exit-code + `kind()` taxonomy exists to serve, so the report
    /// is sorted the way `classify`'s refusals already are (`BTreeMap` key
    /// order). Only failing runs pay for it.
    fn sort(&mut self) {
        self.mismatches.sort_by(|a, b| a.package.cmp(&b.package));
        self.corrupt.sort_by(|a, b| a.package.cmp(&b.package));
        self.permanent.sort_by(|a, b| a.package.cmp(&b.package));
        self.offline.sort();
        self.transient.sort_by(|a, b| a.package.cmp(&b.package));
    }

    /// The error an aborting failure (`Io`, `TlsCertificate`) ends the phase
    /// with: a collected [`FuziError::IntegrityMismatch`], else a collected
    /// [`FuziError::OfflineCacheCorrupt`], else `abort` itself. The hash
    /// alarms outrank it for the reason they lead [`into_error`](Self::into_error):
    /// "do not trust these bytes" must not be drowned by a quieter failure.
    fn outranking(mut self, abort: FuziError) -> FuziError {
        self.sort();
        if !self.mismatches.is_empty() {
            FuziError::IntegrityMismatch {
                mismatches: self.mismatches,
            }
        } else if !self.corrupt.is_empty() {
            FuziError::OfflineCacheCorrupt {
                entries: self.corrupt,
            }
        } else {
            abort
        }
    }

    /// The most-severe non-empty class as a [`FuziError`] (mismatch →
    /// offline-corrupt → permanent → offline miss → transient), or `None` if
    /// every tarball resolved.
    ///
    /// The two hash violations lead: bytes that fail their key are a security
    /// event, and a run that also lacks some tarball must not let the quieter
    /// "unavailable offline" stand in for "do not trust what is cached". (A
    /// corrupt entry only surfaces offline and a permanent fetch only online, so
    /// those two never meet in one run.)
    ///
    /// Permanent outranks offline and transient so a run mixing a yanked
    /// tarball with a flaky one reports the failure a re-run *won't* fix —
    /// exiting `EX_TEMPFAIL` there would send an agent into a retry loop.
    fn into_error(self) -> Option<FuziError> {
        if !self.mismatches.is_empty() {
            Some(FuziError::IntegrityMismatch {
                mismatches: self.mismatches,
            })
        } else if !self.corrupt.is_empty() {
            Some(FuziError::OfflineCacheCorrupt {
                entries: self.corrupt,
            })
        } else if !self.permanent.is_empty() {
            Some(FuziError::FetchPermanent {
                failures: self.permanent,
            })
        } else if !self.offline.is_empty() {
            Some(FuziError::OfflineCacheMiss {
                packages: self.offline,
            })
        } else if !self.transient.is_empty() {
            Some(FuziError::Fetch {
                failures: self.transient,
            })
        } else {
            None
        }
    }
}

/// How one tarball resolved.
///
/// Failures here are *accumulated* (not propagated) — only a hard disk error
/// escapes `fetch_one` as `FuziError`. The success arm reuses the public
/// [`FetchOutcome`] rather than re-spelling cache-hit / fetched, so the success
/// shape lives in exactly one type.
enum TarballResolution {
    /// Satisfied — fold into the report.
    Done(FetchOutcome),
    /// A cached copy failed re-verification, was discarded, and the refetch
    /// landed verified bytes — fold in as fetched, and surface it as a heal.
    Healed { bytes: u64 },
    /// Fetched bytes did not match the lock hash — a supply-chain alarm.
    Mismatch { expected: String, actual: String },
    /// Transport failure — transient; collected, re-run retries.
    Transport { reason: String },
    /// The registry refused this URL definitively (4xx / refused redirect) or
    /// the tarball exceeds fuzi's cap — collected, but a re-run cannot fix it.
    PermanentFetch { reason: String },
    /// `--offline` could not satisfy this tarball: it is not cached.
    OfflineUnavailable,
    /// `--offline` found this tarball cached but failing re-verification — a
    /// tamper/corruption alarm, never folded into the quiet miss above.
    OfflineCorrupt,
}

/// Resolve one unique tarball: re-verify the cache, else fetch-then-verify.
///
/// `source` is bound only on the paths that actually download, so the
/// offline-miss arms are explicit and there is no unreachable fallback branch.
async fn fetch_one<S: TarballSource>(
    cache: &NpmCache,
    source: Option<&S>,
    integrity: &Integrity,
    resolved: &str,
) -> Result<TarballResolution, FuziError> {
    if cache.contains(integrity) {
        // Re-verify before trusting (closes the TOCTOU npm ci ignores).
        let verdict = blocking_cache(cache, integrity, "re-verify cached tarball", |cache, i| {
            cache.verify_cached(&i)
        })
        .await?;
        return match verdict {
            Ok(()) => Ok(TarballResolution::Done(FetchOutcome::CacheHit)),
            // Corrupt: heal online (discard + refetch — the CAS is
            // content-addressed, the registry has the truth); offline can't
            // heal, and says so as the tamper alarm it is, not as a miss. The
            // entry is left in place offline, for inspection.
            Err(CacheError::Corrupt { .. }) => match source {
                Some(src) => {
                    let _ = std::fs::remove_file(cache.entry_path(integrity));
                    Ok(as_heal(
                        fetch_and_commit(cache, src, integrity, resolved).await?,
                    ))
                }
                None => Ok(TarballResolution::OfflineCorrupt),
            },
            Err(other) => Err(io_from_cache(other)),
        };
    }
    // Not cached: fetch if we have a source, else it's an offline miss.
    match source {
        Some(src) => fetch_and_commit(cache, src, integrity, resolved).await,
        None => Ok(TarballResolution::OfflineUnavailable),
    }
}

/// Mark the outcome of refetching a discarded, corrupt cache entry, so the
/// tamper signal is never lost: a landed refetch is a [`TarballResolution::Healed`]
/// (reported, not silent), and a failed one carries the discard in its reason.
/// A refetch whose bytes mismatch is already the louder supply-chain alarm.
fn as_heal(resolution: TarballResolution) -> TarballResolution {
    const DISCARDED: &str = "cached copy failed re-verification and was discarded; refetch: ";
    match resolution {
        TarballResolution::Done(FetchOutcome::Fetched { bytes }) => {
            TarballResolution::Healed { bytes }
        }
        TarballResolution::Transport { reason } => TarballResolution::Transport {
            reason: format!("{DISCARDED}{reason}"),
        },
        TarballResolution::PermanentFetch { reason } => TarballResolution::PermanentFetch {
            reason: format!("{DISCARDED}{reason}"),
        },
        other => other,
    }
}

/// Download into a temp and commit-which-verifies. A download failure is sorted
/// by [`classify_fetch_failure`] (collected as `Transport` / `PermanentFetch`,
/// or escaping as `Io`); a hash mismatch is a `Mismatch` (supply-chain alarm); a
/// disk failure during commit aborts the phase as `Io`.
async fn fetch_and_commit<S: TarballSource>(
    cache: &NpmCache,
    src: &S,
    integrity: &Integrity,
    resolved: &str,
) -> Result<TarballResolution, FuziError> {
    // The defensive second pass behind the source's own cleanup: removes the
    // temp on a failed download *and* on cancellation (the phase aborting on
    // another tarball's disk error drops this future mid-write), so a stranded
    // temp never has to wait out the cache's age-gated sweep.
    let guard = TempGuard::new(cache.temp_path());
    let bytes = match src.fetch_to_file(resolved, &guard.path).await {
        Ok(n) => n,
        Err(e) => return classify_fetch_failure(e),
    };
    // From here `commit` owns the temp: it lands it or removes it.
    let temp = guard.disarm();
    // commit-is-verify: hashes the temp, renames only on a match.
    let committed = blocking_cache(
        cache,
        integrity,
        "commit tarball into cache",
        move |cache, i| cache.commit(&temp, &i),
    )
    .await?;
    match committed {
        Ok(()) => Ok(TarballResolution::Done(FetchOutcome::Fetched { bytes })),
        Err(CacheError::IntegrityMismatch { expected, actual }) => {
            Ok(TarballResolution::Mismatch { expected, actual })
        }
        Err(other) => Err(io_from_cache(other)),
    }
}

/// A download temp that is removed when dropped, unless handed on with
/// [`disarm`](Self::disarm).
struct TempGuard {
    path: PathBuf,
    armed: bool,
}

impl TempGuard {
    const fn new(path: PathBuf) -> Self {
        Self { path, armed: true }
    }

    /// Release the temp to a new owner; the guard no longer removes it.
    fn disarm(mut self) -> PathBuf {
        self.armed = false;
        std::mem::take(&mut self.path)
    }
}

impl Drop for TempGuard {
    fn drop(&mut self) {
        if self.armed {
            // Best effort: a lost unlink costs disk, and the sweep reaps it.
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// Sort a failed download into one of the classes the exit-code taxonomy
/// promises, keyed by *who has to act*.
///
/// - [`FetchError::Io`] — nobody's answer, a local disk failure (`ENOSPC`,
///   `EIO`, a read-only filesystem). It escapes as [`FuziError::Io`]
///   (`EX_IOERR` 74) and aborts the phase at once, exactly like `CacheError::Io` on the
///   other side of the rename — the two are the same event moments apart.
///   Collecting it as transient would exit `EX_TEMPFAIL` "re-run to retry" and
///   send an agent obeying the taxonomy into an endless retry against a disk
///   that will never have room.
/// - [`FetchError::TlsCertificate`] — the registry's certificate failed this
///   machine's trust. It escapes as [`FuziError::TlsCertificate`] (`EX_CONFIG`
///   78) and aborts the phase like `Io`: every further fetch to that host meets
///   the same verdict, and whoever owns the trust store or proxy has to act.
/// - Permanent — the registry's definitive answer; the *lockfile* must change.
/// - Transient — accumulated, and a re-run really is the retry.
///
/// Only the registry's own answers are ever retryable, which is the whole rule
/// this function exists to state in one place.
fn classify_fetch_failure(e: FetchError) -> Result<TarballResolution, FuziError> {
    match e {
        FetchError::Io { what, source } => return Err(FuziError::Io { what, source }),
        FetchError::TlsCertificate { host, reason } => {
            return Err(FuziError::TlsCertificate { host, reason });
        }
        _ => {}
    }
    let reason = e.to_string();
    Ok(if e.is_permanent() {
        TarballResolution::PermanentFetch { reason }
    } else {
        TarballResolution::Transport { reason }
    })
}

/// Run one blocking [`NpmCache`] operation on tokio's blocking pool.
///
/// The per-tarball sha512 (`verify_cached` on a hit, `commit` on a miss) is tens
/// of milliseconds of CPU + IO. [`futures::StreamExt::buffer_unordered`] drives
/// every in-flight fetch future from a **single** task, so hashing inline pins
/// all of them to one thread — leaving the bounded-concurrency fetch phase
/// effectively serial for its most expensive step. Handing the hash to
/// `spawn_blocking` lets them overlap: measured at −15.6% wall clock on a warm
/// 229-package install (237 ms → 200 ms), about three quarters of the 21.5%
/// ceiling that dropping the warm re-verify entirely would buy.
///
/// Nothing about the verify changes — same call, same inputs, same position
/// relative to the rename. `commit` is still *the* verify and an unverified temp
/// still cannot enter the CAS; only the thread it runs on moves. `NpmCache` is a
/// `PathBuf` and `Integrity` a digest, so the clones the `'static` closure needs
/// are cheap next to the hash they enable.
async fn blocking_cache<T: Send + 'static>(
    cache: &NpmCache,
    integrity: &Integrity,
    what: &'static str,
    op: impl FnOnce(NpmCache, Integrity) -> T + Send + 'static,
) -> Result<T, FuziError> {
    let (cache, integrity) = (cache.clone(), integrity.clone());
    tokio::task::spawn_blocking(move || op(cache, integrity))
        .await
        // Only reachable if the hashing task itself panicked (the pool outlives
        // the phase) — surface it as a disk error rather than swallowing it.
        .map_err(|e| io_err(what)(std::io::Error::other(e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::InstallPath;
    use crate::entry::Integrity;
    use crate::plan::{FetchInfo, InstallPlan, PackagePlacement};
    use crate::test_support::integrity_of;
    use std::collections::BTreeMap;
    use tempfile::TempDir;

    fn cache() -> (TempDir, NpmCache) {
        let dir = TempDir::new().unwrap();
        let cache = NpmCache::open(dir.path().join("npm")).unwrap();
        (dir, cache)
    }

    /// A plan placing one tarball at `path` with the bytes' integrity + URL.
    fn plan_for(path: &str, url: &str, integrity: Integrity) -> InstallPlan {
        let mut plan = InstallPlan::default();
        plan.fetch_set.insert(
            integrity.clone(),
            FetchInfo {
                resolved: url.to_string(),
            },
        );
        plan.placements.push(PackagePlacement {
            path: InstallPath::new(path),
            version: None,
            integrity,
            bins: BTreeMap::new(),
        });
        plan
    }

    #[tokio::test]
    async fn fetches_verifies_and_commits() {
        let (_d, cache) = cache();
        let data = b"tarball bytes for foo";
        let integrity = integrity_of(data);
        let url = "https://registry.npmjs.org/foo/-/foo-1.0.0.tgz";
        let plan = plan_for("node_modules/foo", url, integrity.clone());
        let source = FixtureSource::new().with(url, data.to_vec());

        let report = run_fetch_phase(&plan, &cache, Some(&source), 4)
            .await
            .unwrap();
        assert_eq!(report.fetched, 1);
        assert_eq!(report.cached, 0);
        assert_eq!(report.fetched_bytes, data.len() as u64);
        assert!(cache.contains(&integrity));
        cache.verify_cached(&integrity).unwrap();
    }

    #[tokio::test]
    async fn second_run_is_a_cache_hit() {
        let (_d, cache) = cache();
        let data = b"cached on the second pass";
        let integrity = integrity_of(data);
        let url = "https://registry.npmjs.org/foo/-/foo-1.0.0.tgz";
        let plan = plan_for("node_modules/foo", url, integrity.clone());
        let source = FixtureSource::new().with(url, data.to_vec());

        run_fetch_phase(&plan, &cache, Some(&source), 4)
            .await
            .unwrap();
        // Second pass: present + re-verified, no download counted.
        let report = run_fetch_phase(&plan, &cache, Some(&source), 4)
            .await
            .unwrap();
        assert_eq!(report.cached, 1);
        assert_eq!(report.fetched, 0);
    }

    #[tokio::test]
    async fn tampered_bytes_are_an_integrity_mismatch() {
        let (_d, cache) = cache();
        // The lockfile expects "honest"; the source serves "evil".
        let integrity = integrity_of(b"honest");
        let url = "https://registry.npmjs.org/foo/-/foo-1.0.0.tgz";
        let plan = plan_for("node_modules/foo", url, integrity.clone());
        let source = FixtureSource::new().with(url, b"evil".to_vec());

        let err = run_fetch_phase(&plan, &cache, Some(&source), 4)
            .await
            .unwrap_err();
        assert_eq!(err.exit_code(), 65);
        match err {
            FuziError::IntegrityMismatch { mismatches } => {
                assert_eq!(mismatches.len(), 1);
                // Labeled by package path, not by hash.
                assert_eq!(mismatches[0].package, "node_modules/foo");
                assert!(mismatches[0].expected.starts_with("sha512-"));
            }
            other => panic!("expected IntegrityMismatch, got {other:?}"),
        }
        // Nothing entered the cache.
        assert!(!cache.contains(&integrity));
    }

    /// A source whose every fetch fails with a caller-chosen [`FetchError`],
    /// derived from the URL — for asserting how the phase classifies transient
    /// vs permanent failures without standing up an HTTP server (that layer is
    /// covered in `npm.rs`).
    struct FailingSource(fn(&str) -> FetchError);

    impl TarballSource for FailingSource {
        #[expect(
            clippy::unused_async_trait_impl,
            reason = "trait conformance: an `async fn` body runs when awaited; the `impl Future` rewrite would run it at call time"
        )]
        async fn fetch_to_file(&self, url: &str, _dest: &Path) -> Result<u64, FetchError> {
            Err((self.0)(url))
        }
    }

    #[tokio::test]
    async fn permanent_failure_is_not_the_retryable_class() {
        // A yanked tarball (4xx) must not exit EX_TEMPFAIL "re-run to retry" —
        // an agent branching on the taxonomy would retry it forever.
        let (_d, cache) = cache();
        let integrity = integrity_of(b"yanked");
        let url = "https://registry.npmjs.org/gone/-/gone-1.0.0.tgz";
        let plan = plan_for("node_modules/gone", url, integrity);
        let source = FailingSource(|_| FetchError::Permanent("HTTP 404 Not Found".to_string()));

        let err = run_fetch_phase(&plan, &cache, Some(&source), 4)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), "fetch_permanent");
        assert_eq!(err.exit_code(), 65);
        match err {
            FuziError::FetchPermanent { failures } => {
                assert_eq!(failures[0].package, "node_modules/gone");
            }
            other => panic!("expected FetchPermanent, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn permanent_outranks_transient_when_both_occur() {
        // Mixing a yanked tarball with a flaky one must report the failure a
        // re-run cannot fix, not the one it can.
        let (_d, cache) = cache();
        let gone = integrity_of(b"yanked");
        let flaky = integrity_of(b"flaky");
        let mut plan = plan_for(
            "node_modules/gone",
            "https://registry.npmjs.org/gone/-/gone-1.0.0.tgz",
            gone,
        );
        plan.fetch_set.insert(
            flaky.clone(),
            FetchInfo {
                resolved: "https://registry.npmjs.org/flaky/-/flaky-1.0.0.tgz".to_string(),
            },
        );
        plan.placements.push(PackagePlacement {
            path: InstallPath::new("node_modules/flaky"),
            version: None,
            integrity: flaky,
            bins: BTreeMap::new(),
        });
        // One source, two URLs: permanent for `gone`, transient for `flaky`.
        let source = FailingSource(|url| {
            if url.contains("gone") {
                FetchError::Permanent("HTTP 404 Not Found".to_string())
            } else {
                FetchError::Transport("HTTP 503".to_string())
            }
        });

        let err = run_fetch_phase(&plan, &cache, Some(&source), 4)
            .await
            .unwrap_err();
        assert_eq!(
            err.kind(),
            "fetch_permanent",
            "permanent must outrank transient"
        );
    }

    /// Fails every fetch, delaying longest for the *earliest* package name — so
    /// completion order is the reverse of package order.
    struct ReverseOrderSource;

    impl TarballSource for ReverseOrderSource {
        async fn fetch_to_file(&self, url: &str, _dest: &Path) -> Result<u64, FetchError> {
            let delay = if url.contains("/a/") {
                30
            } else if url.contains("/b/") {
                15
            } else {
                0
            };
            tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
            Err(FetchError::Transport("HTTP 503".to_string()))
        }
    }

    #[tokio::test]
    async fn failures_are_reported_in_package_order() {
        // `buffer_unordered` yields in *completion* order, so an unsorted report
        // reshuffles `--json`'s `failures` array between runs of the same failing
        // lockfile. Sorting by package label makes the agent-facing payload
        // stable. `ReverseOrderSource` inverts completion order relative to
        // package order, so an unsorted implementation fails this deterministically.
        let (_d, cache) = cache();
        let mut plan = InstallPlan::default();
        for name in ["a", "b", "c"] {
            let integrity = integrity_of(name.as_bytes());
            plan.fetch_set.insert(
                integrity.clone(),
                FetchInfo {
                    resolved: format!("https://registry.npmjs.org/{name}/-/{name}-1.0.0.tgz"),
                },
            );
            plan.placements.push(PackagePlacement {
                path: InstallPath::new(format!("node_modules/{name}")),
                version: None,
                integrity,
                bins: BTreeMap::new(),
            });
        }

        let err = run_fetch_phase(&plan, &cache, Some(&ReverseOrderSource), 4)
            .await
            .unwrap_err();
        match err {
            FuziError::Fetch { failures } => {
                let packages: Vec<&str> = failures.iter().map(|f| f.package.as_str()).collect();
                assert_eq!(
                    packages,
                    ["node_modules/a", "node_modules/b", "node_modules/c"],
                    "failures must be ordered by package, not by completion"
                );
            }
            other => panic!("expected Fetch, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn local_io_failure_is_not_the_retryable_class() {
        // A full or failing disk is not a transport verdict. Routing it into the
        // transient class would exit 75 EX_TEMPFAIL "re-run to retry" — an agent
        // obeying the taxonomy then retries forever against a disk that will
        // never have room. It must take exit 74, the same code the cache's own
        // disk failures take on the other side of the rename.
        let (_d, cache) = cache();
        let integrity = integrity_of(b"never written");
        let url = "https://registry.npmjs.org/foo/-/foo-1.0.0.tgz";
        let plan = plan_for("node_modules/foo", url, integrity);
        let source = FailingSource(|_| FetchError::Io {
            what: "write download temp",
            source: std::io::Error::from(std::io::ErrorKind::StorageFull),
        });

        let err = run_fetch_phase(&plan, &cache, Some(&source), 4)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), "io");
        assert_eq!(err.exit_code(), 74);
    }

    /// Fails `disk`'s fetch with a disk error at once; every other fetch writes
    /// a partial temp and then hangs forever — a stalled download that only
    /// cancellation can end.
    struct DiskErrorBesideHangSource;

    impl TarballSource for DiskErrorBesideHangSource {
        async fn fetch_to_file(&self, url: &str, dest: &Path) -> Result<u64, FetchError> {
            if url.contains("/disk/") {
                // Let the hanging fetches start their writes first.
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                return Err(FetchError::Io {
                    what: "write download temp",
                    source: std::io::Error::from(std::io::ErrorKind::StorageFull),
                });
            }
            tokio::fs::write(dest, b"partial").await.unwrap();
            std::future::pending().await
        }
    }

    #[tokio::test]
    async fn disk_error_aborts_without_waiting_for_other_fetches() {
        // The first disk error ends the phase: it does not wait out the other
        // downloads (here, ones that never finish), and the cancelled fetches'
        // partial temps are removed as they drop.
        let (dir, cache) = cache();
        let mut plan = InstallPlan::default();
        for name in ["disk", "hang1", "hang2"] {
            let integrity = integrity_of(name.as_bytes());
            plan.fetch_set.insert(
                integrity.clone(),
                FetchInfo {
                    resolved: format!("https://registry.npmjs.org/{name}/-/{name}-1.0.0.tgz"),
                },
            );
            plan.placements.push(PackagePlacement {
                path: InstallPath::new(format!("node_modules/{name}")),
                version: None,
                integrity,
                bins: BTreeMap::new(),
            });
        }

        let phase = run_fetch_phase(&plan, &cache, Some(&DiskErrorBesideHangSource), 4);
        let err = tokio::time::timeout(std::time::Duration::from_secs(10), phase)
            .await
            .expect("a disk error must abort the phase, not wait on the other fetches")
            .unwrap_err();
        assert_eq!(err.kind(), "io");
        assert_eq!(err.exit_code(), 74);
        let leftovers: Vec<_> = std::fs::read_dir(dir.path().join("npm"))
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert!(leftovers.is_empty(), "stranded temps: {leftovers:?}");
    }

    /// Serves `evil`'s URL wrong bytes at once; fails `disk`'s fetch with a disk
    /// error only after a delay, so the mismatch is collected first.
    struct MismatchThenDiskErrorSource;

    impl TarballSource for MismatchThenDiskErrorSource {
        async fn fetch_to_file(&self, url: &str, dest: &Path) -> Result<u64, FetchError> {
            if url.contains("/disk/") {
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                return Err(FetchError::Io {
                    what: "write download temp",
                    source: std::io::Error::from(std::io::ErrorKind::StorageFull),
                });
            }
            // Not the bytes `integrity_of(b"evil")` names.
            tokio::fs::write(dest, b"tampered").await.unwrap();
            Ok(8)
        }
    }

    #[tokio::test]
    async fn a_late_disk_error_does_not_hide_a_collected_mismatch() {
        // The supply-chain alarm was already in hand when the disk failed:
        // the abort must return it, not the quieter exit-74 `Io`.
        let (_d, cache) = cache();
        let mut plan = InstallPlan::default();
        for name in ["evil", "disk"] {
            let integrity = integrity_of(name.as_bytes());
            plan.fetch_set.insert(
                integrity.clone(),
                FetchInfo {
                    resolved: format!("https://registry.npmjs.org/{name}/-/{name}-1.0.0.tgz"),
                },
            );
            plan.placements.push(PackagePlacement {
                path: InstallPath::new(format!("node_modules/{name}")),
                version: None,
                integrity,
                bins: BTreeMap::new(),
            });
        }

        let err = run_fetch_phase(&plan, &cache, Some(&MismatchThenDiskErrorSource), 4)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), "integrity_mismatch", "{err}");
        match err {
            FuziError::IntegrityMismatch { mismatches } => {
                assert_eq!(mismatches.len(), 1);
                assert_eq!(mismatches[0].package, "node_modules/evil");
            }
            other => panic!("expected IntegrityMismatch, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn transport_failure_is_collected_as_fetch() {
        let (_d, cache) = cache();
        let integrity = integrity_of(b"never served");
        let url = "https://registry.npmjs.org/foo/-/foo-1.0.0.tgz";
        let plan = plan_for("node_modules/foo", url, integrity);
        let source = FixtureSource::new(); // empty → miss

        let err = run_fetch_phase(&plan, &cache, Some(&source), 4)
            .await
            .unwrap_err();
        assert!(matches!(err, FuziError::Fetch { .. }));
        assert_eq!(err.exit_code(), 75);
    }

    #[tokio::test]
    async fn offline_miss_when_uncached_and_no_source() {
        let (_d, cache) = cache();
        let integrity = integrity_of(b"not cached");
        let url = "https://registry.npmjs.org/foo/-/foo-1.0.0.tgz";
        let plan = plan_for("node_modules/foo", url, integrity);

        let err = run_fetch_phase::<FixtureSource>(&plan, &cache, None, 4)
            .await
            .unwrap_err();
        assert_eq!(err.exit_code(), 69);
        match err {
            FuziError::OfflineCacheMiss { packages } => {
                assert_eq!(packages, vec!["node_modules/foo".to_string()]);
            }
            other => panic!("expected OfflineCacheMiss, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn offline_hit_when_already_cached() {
        let (_d, cache) = cache();
        let data = b"pre-warmed";
        let integrity = integrity_of(data);
        let url = "https://registry.npmjs.org/foo/-/foo-1.0.0.tgz";
        let plan = plan_for("node_modules/foo", url, integrity.clone());

        // Warm the cache online, then a fresh offline run hits it.
        let source = FixtureSource::new().with(url, data.to_vec());
        run_fetch_phase(&plan, &cache, Some(&source), 4)
            .await
            .unwrap();
        let report = run_fetch_phase::<FixtureSource>(&plan, &cache, None, 4)
            .await
            .unwrap();
        assert_eq!(report.cached, 1);
    }

    #[tokio::test]
    async fn corrupt_cache_self_heals_online() {
        let (_d, cache) = cache();
        let data = b"will be corrupted then healed";
        let integrity = integrity_of(data);
        let url = "https://registry.npmjs.org/foo/-/foo-1.0.0.tgz";
        let plan = plan_for("node_modules/foo", url, integrity.clone());
        let source = FixtureSource::new().with(url, data.to_vec());

        run_fetch_phase(&plan, &cache, Some(&source), 4)
            .await
            .unwrap();
        // Corrupt the committed bytes in place.
        std::fs::write(cache.entry_path(&integrity), b"corrupt").unwrap();

        // Online run discards + refetches → counted as a fetch, reported as a
        // heal (a tamper signal is never repaired silently), and re-verifies.
        let report = run_fetch_phase(&plan, &cache, Some(&source), 4)
            .await
            .unwrap();
        assert_eq!(report.fetched, 1);
        assert_eq!(report.healed, vec!["node_modules/foo".to_string()]);
        cache.verify_cached(&integrity).unwrap();

        // A clean re-run is a plain hit: nothing to report.
        let report = run_fetch_phase(&plan, &cache, Some(&source), 4)
            .await
            .unwrap();
        assert!(report.healed.is_empty());
    }

    /// Serves a [`FixtureSource`], holding back any URL containing `/a/` so
    /// it completes last — package order inverted against completion order.
    struct SlowFirstSource(FixtureSource);

    impl TarballSource for SlowFirstSource {
        async fn fetch_to_file(&self, url: &str, dest: &Path) -> Result<u64, FetchError> {
            if url.contains("/a/") {
                tokio::time::sleep(std::time::Duration::from_millis(80)).await;
            }
            self.0.fetch_to_file(url, dest).await
        }
    }

    #[tokio::test]
    async fn healed_packages_are_reported_in_package_order() {
        // Two corrupt entries healed in one run: `healed` rides `--json`, so it
        // must not follow completion order. `node_modules/a`'s refetch finishes
        // last, so an unsorted report lists it second.
        let (_d, cache) = cache();
        let mut plan = InstallPlan::default();
        let mut fixtures = FixtureSource::new();
        for name in ["a", "b"] {
            let data = format!("tarball {name}");
            let integrity = integrity_of(data.as_bytes());
            let url = format!("https://registry.npmjs.org/{name}/-/{name}-1.0.0.tgz");
            plan.fetch_set.insert(
                integrity.clone(),
                FetchInfo {
                    resolved: url.clone(),
                },
            );
            plan.placements.push(PackagePlacement {
                path: InstallPath::new(format!("node_modules/{name}")),
                version: None,
                integrity,
                bins: BTreeMap::new(),
            });
            fixtures = fixtures.with(url, data.into_bytes());
        }
        let source = SlowFirstSource(fixtures);
        run_fetch_phase(&plan, &cache, Some(&source), 4)
            .await
            .unwrap();
        for integrity in plan.fetch_set.keys() {
            std::fs::write(cache.entry_path(integrity), b"corrupt").unwrap();
        }

        let report = run_fetch_phase(&plan, &cache, Some(&source), 4)
            .await
            .unwrap();
        assert_eq!(report.fetched, 2);
        assert_eq!(report.healed, ["node_modules/a", "node_modules/b"]);
    }

    #[tokio::test]
    async fn heal_refetch_that_fails_keeps_the_discard_in_its_reason() {
        // The corrupt entry is gone and the refetch failed: the failure must
        // still say the cache was tampered with, not read as a plain outage.
        let (_d, cache) = cache();
        let data = b"corrupted, then the registry is down";
        let integrity = integrity_of(data);
        let url = "https://registry.npmjs.org/foo/-/foo-1.0.0.tgz";
        let plan = plan_for("node_modules/foo", url, integrity.clone());
        run_fetch_phase(
            &plan,
            &cache,
            Some(&FixtureSource::new().with(url, data.to_vec())),
            4,
        )
        .await
        .unwrap();
        std::fs::write(cache.entry_path(&integrity), b"corrupt").unwrap();

        let down = FailingSource(|_| FetchError::Transport("HTTP 503".to_string()));
        let err = run_fetch_phase(&plan, &cache, Some(&down), 4)
            .await
            .unwrap_err();
        match err {
            FuziError::Fetch { failures } => assert_eq!(
                failures[0].reason,
                "cached copy failed re-verification and was discarded; refetch: HTTP 503"
            ),
            other => panic!("expected Fetch, got {other:?}"),
        }
        // Corrupt it again (the failed heal left the key absent), now with the
        // registry answering definitively.
        std::fs::write(cache.entry_path(&integrity), b"corrupt").unwrap();
        let gone = FailingSource(|_| FetchError::Permanent("HTTP 404".to_string()));
        let err = run_fetch_phase(&plan, &cache, Some(&gone), 4)
            .await
            .unwrap_err();
        match err {
            FuziError::FetchPermanent { failures } => assert!(
                failures[0]
                    .reason
                    .starts_with("cached copy failed re-verification and was discarded; refetch: "),
                "{}",
                failures[0].reason
            ),
            other => panic!("expected FetchPermanent, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn corrupt_cache_offline_is_a_tamper_alarm() {
        let (_d, cache) = cache();
        let data = b"corrupt under offline";
        let integrity = integrity_of(data);
        let url = "https://registry.npmjs.org/foo/-/foo-1.0.0.tgz";
        let plan = plan_for("node_modules/foo", url, integrity.clone());
        let source = FixtureSource::new().with(url, data.to_vec());

        run_fetch_phase(&plan, &cache, Some(&source), 4)
            .await
            .unwrap();
        std::fs::write(cache.entry_path(&integrity), b"corrupt").unwrap();

        let err = run_fetch_phase::<FixtureSource>(&plan, &cache, None, 4)
            .await
            .unwrap_err();
        // A tampered entry is a security event, not a cold miss: exit 65 (do
        // not trust these bytes), never 69's "re-run without --offline".
        assert_eq!(err.kind(), "offline_cache_corrupt");
        assert_eq!(err.exit_code(), 65);
        match err {
            FuziError::OfflineCacheCorrupt { entries } => {
                assert_eq!(entries.len(), 1);
                assert_eq!(entries[0].package, "node_modules/foo");
                assert_eq!(
                    entries[0].path,
                    cache.entry_path(&integrity).display().to_string()
                );
            }
            other => panic!("expected OfflineCacheCorrupt, got {other:?}"),
        }
        // Left in place for inspection — offline never deletes the evidence.
        assert!(cache.contains(&integrity));
    }

    #[tokio::test]
    async fn offline_corrupt_outranks_offline_miss() {
        // One tarball tampered, one simply absent: the alarm must not be
        // drowned by the quieter "unavailable offline".
        let (_d, cache) = cache();
        let data = b"warm then tampered";
        let warm = integrity_of(data);
        let url = "https://registry.npmjs.org/warm/-/warm-1.0.0.tgz";
        let mut plan = plan_for("node_modules/warm", url, warm.clone());
        let source = FixtureSource::new().with(url, data.to_vec());
        run_fetch_phase(&plan, &cache, Some(&source), 4)
            .await
            .unwrap();
        std::fs::write(cache.entry_path(&warm), b"tampered").unwrap();
        let cold = integrity_of(b"never cached");
        plan.fetch_set.insert(
            cold.clone(),
            FetchInfo {
                resolved: "https://registry.npmjs.org/cold/-/cold-1.0.0.tgz".to_string(),
            },
        );
        plan.placements.push(PackagePlacement {
            path: InstallPath::new("node_modules/cold"),
            version: None,
            integrity: cold,
            bins: BTreeMap::new(),
        });

        let err = run_fetch_phase::<FixtureSource>(&plan, &cache, None, 4)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), "offline_cache_corrupt");
    }

    #[tokio::test]
    async fn heal_refetch_that_mismatches_is_an_integrity_mismatch() {
        // A corrupt entry heals online by refetching — and the refetch is held
        // to the same gate: wrong bytes are the supply-chain alarm, and the
        // discarded entry is not resurrected.
        let (_d, cache) = cache();
        let data = b"honest bytes";
        let integrity = integrity_of(data);
        let url = "https://registry.npmjs.org/foo/-/foo-1.0.0.tgz";
        let plan = plan_for("node_modules/foo", url, integrity.clone());
        run_fetch_phase(
            &plan,
            &cache,
            Some(&FixtureSource::new().with(url, data.to_vec())),
            4,
        )
        .await
        .unwrap();
        std::fs::write(cache.entry_path(&integrity), b"corrupt").unwrap();

        let evil = FixtureSource::new().with(url, b"evil".to_vec());
        let err = run_fetch_phase(&plan, &cache, Some(&evil), 4)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), "integrity_mismatch");
        assert_eq!(err.exit_code(), 65);
        assert!(!cache.contains(&integrity), "the corrupt entry stays gone");
    }

    #[tokio::test]
    async fn dedup_one_fetch_many_placements() {
        let (_d, cache) = cache();
        let data = b"shared tarball";
        let integrity = integrity_of(data);
        let url = "https://registry.npmjs.org/shared/-/shared-1.0.0.tgz";
        // Two placements, one fetch_set entry.
        let mut plan = plan_for("node_modules/a", url, integrity.clone());
        plan.placements.push(PackagePlacement {
            path: InstallPath::new("node_modules/b/node_modules/a"),
            version: None,
            integrity: integrity.clone(),
            bins: BTreeMap::new(),
        });
        let source = FixtureSource::new().with(url, data.to_vec());

        let report = run_fetch_phase(&plan, &cache, Some(&source), 4)
            .await
            .unwrap();
        assert_eq!(report.fetched, 1);
    }

    #[tokio::test]
    async fn rejected_certificate_aborts_as_tls_certificate_not_transient() {
        // A certificate verdict repeats on every run: collected as transient it
        // would exit 75 "re-run to retry", so it aborts the phase as exit 78.
        let (_d, cache) = cache();
        let url = "https://registry.npmjs.org/foo/-/foo-1.0.0.tgz";
        let plan = plan_for("node_modules/foo", url, integrity_of(b"foo"));
        let source = FailingSource(|_| FetchError::TlsCertificate {
            host: "registry.npmjs.org".to_string(),
            reason: "invalid peer certificate: UnknownIssuer".to_string(),
        });
        let err = run_fetch_phase(&plan, &cache, Some(&source), 4)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), "tls_certificate", "{err}");
        assert_eq!(err.exit_code(), 78);
    }

    #[test]
    fn an_aborting_error_yields_to_a_collected_offline_corrupt_entry() {
        // Second in the alarm ranking: a corrupt cache entry already in hand
        // outranks a later abort, as a mismatch does.
        let mut failures = FetchFailures::default();
        failures.corrupt.push(CorruptCacheItem {
            package: "node_modules/foo".to_string(),
            path: "/cache/foo".to_string(),
        });
        let abort = FuziError::TlsCertificate {
            host: "registry.npmjs.org".to_string(),
            reason: "invalid peer certificate: UnknownIssuer".to_string(),
        };
        assert_eq!(failures.outranking(abort).kind(), "offline_cache_corrupt");
        let abort = FuziError::TlsCertificate {
            host: "registry.npmjs.org".to_string(),
            reason: "invalid peer certificate: UnknownIssuer".to_string(),
        };
        assert_eq!(
            FetchFailures::default().outranking(abort).kind(),
            "tls_certificate"
        );
    }
}
