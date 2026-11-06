//! fuzi error type + stable process exit codes.
//!
//! `exit_code` groups variants into stable classes so an agent (the
//! primary consumer) can branch on failure mode; the same taxonomy backs
//! `--json`. The set is intentionally small: one class per way the caller
//! must respond.
//!
//! The payloads carry their strings **raw** — a lockfile key, a sibling's
//! `name`, a symlink's text are whatever someone else chose — and every
//! `Display` body passes each one through `escape_untrusted`, so a rendered
//! error holds no control or invisible character and exactly the lines fuzi
//! composed. The structured `--json` payload keeps the raw values.

use serde::Serialize;
use thiserror::Error;

use fuz_sys::text::escape_untrusted;

/// sysexits `EX_USAGE` — the exit code of [`FuziError::Usage`], and of a
/// command line the `fuzi` binary can't parse.
pub const EX_USAGE: u8 = 64;

/// sysexits `EX_NOINPUT` — the exit code of [`FuziError::MissingInput`].
pub const EX_NOINPUT: u8 = 66;

/// A project file fuzi reads from the project directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectFile {
    /// `package-lock.json` — the install source, read by every verb but
    /// `clean`.
    Lockfile,
    /// `package.json` — read only by the install's drift guard.
    Manifest,
}

impl ProjectFile {
    /// The file's name in the project directory.
    #[must_use]
    pub const fn file_name(self) -> &'static str {
        match self {
            Self::Lockfile => "package-lock.json",
            Self::Manifest => "package.json",
        }
    }

    /// What to do when the file is absent.
    #[must_use]
    pub const fn next_step(self) -> &'static str {
        match self {
            Self::Lockfile => {
                "fuzi installs from an existing lockfile and never resolves one — run fuzi in the project root, or create the lockfile with npm (npm install --package-lock-only)"
            }
            Self::Manifest => {
                "run fuzi in the project root, or pass --ignore-manifest to install the lockfile as-is without the drift check"
            }
        }
    }
}

impl std::fmt::Display for ProjectFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.file_name())
    }
}

/// Read `<dir>/<file>` to a string: an absent file is
/// [`FuziError::MissingInput`], any other failure [`FuziError::Io`].
///
/// Opened with [`fuz_sys::secure_file::open_regular_nonblocking`], following a
/// symlink as npm does: a FIFO, device, or directory at the path is refused as
/// "not a regular file" without blocking (a socket fails the open itself; a
/// FIFO with no writer would otherwise hang the open). The read is capped at
/// [`fuz_sys::limits::MAX_BUFFERED_SIZE`] — the file is parsed whole in
/// memory — and a file over it is refused, never truncated.
///
/// # Errors
///
/// Returns `MissingInput` when the file does not exist, `Io` otherwise — a
/// non-regular file and one over the cap included.
pub fn read_project_file(dir: &std::path::Path, file: ProjectFile) -> Result<String, FuziError> {
    read_project_file_capped(dir, file, fuz_sys::limits::MAX_BUFFERED_SIZE)
}

/// [`read_project_file`] with the read cap a parameter, so a test can cross it
/// without writing the real cap's worth of bytes.
fn read_project_file_capped(
    dir: &std::path::Path,
    file: ProjectFile,
    cap: u64,
) -> Result<String, FuziError> {
    use std::io::Read as _;
    let io = |source| FuziError::Io {
        what: match file {
            ProjectFile::Lockfile => "read package-lock.json",
            ProjectFile::Manifest => "read package.json",
        },
        source,
    };
    // The size found: the file's own, or a lower bound when the read itself
    // crossed the cap.
    let too_large = |found: String| {
        const MIB: u64 = 1024 * 1024;
        let human = if cap >= MIB && cap.is_multiple_of(MIB) {
            format!(" ({} MiB)", cap / MIB)
        } else {
            String::new()
        };
        io(std::io::Error::other(format!(
            "is {found} bytes, over fuzi's read cap of {cap} bytes{human}"
        )))
    };
    let path = dir.join(file.file_name());
    let (handle, meta) =
        fuz_sys::secure_file::open_regular_nonblocking(&path).map_err(|source| {
            if source.kind() == std::io::ErrorKind::NotFound {
                FuziError::MissingInput {
                    file,
                    dir: dir.to_path_buf(),
                }
            } else {
                io(source)
            }
        })?;
    if meta.len() > cap {
        return Err(too_large(meta.len().to_string()));
    }
    // `cap + 1` bytes, so a file that grew past the cap after the size check
    // (or a procfs-style file reporting size 0) is refused, not truncated.
    let mut bytes = Vec::new();
    handle
        .take(cap.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(io)?;
    if bytes.len() as u64 > cap {
        return Err(too_large(format!("at least {}", bytes.len())));
    }
    String::from_utf8(bytes)
        .map_err(|e| io(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))
}

/// One tarball that failed to download. Transient — re-running retries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FetchFailure {
    /// Human package label (the install path; users debug by name, not hash).
    pub package: String,
    /// The transport failure detail.
    pub reason: String,
}

/// One tarball whose downloaded bytes did not match the lockfile hash — a
/// supply-chain alarm.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IntegrityMismatchItem {
    /// Human package label (the install path).
    pub package: String,
    /// The lockfile's expected SRI digest (`sha512-…`).
    pub expected: String,
    /// The digest actually computed over the downloaded bytes.
    pub actual: String,
}

/// One cached tarball that failed re-verification under `--offline`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CorruptCacheItem {
    /// Human package label (the install path).
    pub package: String,
    /// The cache entry's on-disk path — left in place for inspection.
    pub path: String,
}

/// One linked package whose sibling target failed the link-target check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LinkTargetProblem {
    /// The link's install path (`node_modules/…`).
    pub package: String,
    /// What is wrong with the target (teaching detail).
    pub detail: String,
}

/// Top-level fuzi error.
#[derive(Debug, Error)]
pub enum FuziError {
    /// Bad CLI usage (e.g. an unknown `--omit` value).
    #[error("{}", escape_untrusted(.message))]
    Usage {
        /// What was wrong with the invocation.
        message: String,
    },

    /// An OS / filesystem operation failed.
    #[error("{what}: {}", escaped(.source))]
    Io {
        /// The operation being attempted.
        what: &'static str,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },

    /// A project file fuzi needs is absent from the project directory — no
    /// `package-lock.json`, or no `package.json` for the drift guard. Usually
    /// fuzi was run outside the project root.
    #[error(
        "no {file} in {}; {}",
        escape_untrusted(&.dir.display().to_string()),
        .file.next_step()
    )]
    MissingInput {
        /// Which file is absent.
        file: ProjectFile,
        /// The project directory it was looked for in.
        dir: std::path::PathBuf,
    },

    /// The lockfile could not be parsed or its version is unsupported.
    #[error("{}", escape_untrusted(.message))]
    Lockfile {
        /// What was wrong with the lockfile (teaching message: what · why · next step).
        message: String,
    },

    /// `package.json`'s declared dependencies differ from the lockfile. `npm ci`
    /// semantics: fuzi has no resolver, so it refuses rather than guess.
    /// `--ignore-manifest` installs the lock as-is. Carries the structured diff
    /// lines so `--json` can surface each mismatch.
    #[error(
        "package.json drifted from package-lock.json (run with --ignore-manifest to install the lock as-is):\n  {}",
        render_block(.diffs, |diff| escape_untrusted(diff))
    )]
    Drift {
        /// One human-readable line per manifest↔lock mismatch.
        diffs: Vec<String>,
    },

    /// One or more lockfile entries were refused at classify time (a shape,
    /// source, or name fuzi will not install). Carries every refusal found in a
    /// single pass (never fail-fast). Manifest drift is [`FuziError::Drift`].
    #[error("{}", crate::classify::render_refusals(.refusals))]
    Refused {
        /// Every refusal accumulated across the whole lockfile.
        refusals: Vec<crate::classify::Refusal>,
    },

    /// One or more tarballs could not be downloaded. Transient — re-running is
    /// the retry (no auto-retry in v0); the partial CAS is left in place so a
    /// re-run cache-hits what landed. Accumulates every failure in one pass; the
    /// typed payload lets `--json` re-structure it (rendered at the binary edge).
    #[error("{} tarball fetch(es) failed (re-run to retry):\n  {}", .failures.len(), render_fetch_failures(.failures))]
    Fetch {
        /// Every tarball that failed transport, structured (not pre-rendered).
        failures: Vec<FetchFailure>,
    },

    /// The HTTPS client fetching tarballs could not be built — this machine's
    /// TLS setup (its certificate trust store, say) is unusable.
    ///
    /// Deterministic, so **not** [`FuziError::Fetch`]: its `EX_TEMPFAIL`
    /// promises "re-run to retry", and a re-run builds the same client from the
    /// same configuration. `EX_CONFIG` (78) names who acts — whoever owns the
    /// host's TLS configuration — and no tarball was contacted.
    #[error(
        "could not initialize the HTTPS client fetching tarballs: {}; fix this machine's TLS setup (its CA certificate store) — re-running will not help (--offline installs from a warm cache without it)",
        escape_untrusted(.reason)
    )]
    HttpClient {
        /// The client builder's failure detail.
        reason: String,
    },

    /// A registry's TLS certificate failed this machine's trust (expired,
    /// untrusted issuer, wrong name, revoked …) — often a TLS-intercepting proxy
    /// whose CA the host does not trust.
    ///
    /// Deterministic, so **not** [`FuziError::Fetch`]: the same chain fails the
    /// same trust on every run. `EX_CONFIG` (78), with [`FuziError::HttpClient`]:
    /// whoever owns the host's trust store or proxy acts. The phase stops at the
    /// first one (every tarball from that host would meet it).
    #[error(
        "TLS certificate rejected for {}: {}; check the proxy or CA trust between this machine and the registry — re-running will not help",
        escape_untrusted(.host),
        escape_untrusted(.reason)
    )]
    TlsCertificate {
        /// The host whose certificate was rejected.
        host: String,
        /// rustls's verdict.
        reason: String,
    },

    /// One or more tarballs were refused by the registry definitively (a 4xx
    /// other than the "not now" 408 / 429 — yanked, renamed, or auth-required —
    /// a refused redirect, or a tarball over fuzi's per-tarball cap). **Not** transient: re-running fetches the same
    /// answer, so this is deliberately kept out of [`FuziError::Fetch`]'s
    /// `EX_TEMPFAIL` class, which promises "re-run to retry".
    #[error("{} tarball fetch(es) failed permanently (re-running will not help):\n  {}", .failures.len(), render_fetch_failures(.failures))]
    FetchPermanent {
        /// Every tarball the registry refused, structured (not pre-rendered).
        failures: Vec<FetchFailure>,
    },

    /// A *fetched* tarball's bytes did not match the lockfile hash — a
    /// supply-chain alarm. Fatal, never retried into acceptance.
    #[error("{} tarball(s) failed integrity verification (possible supply-chain tampering):\n  {}", .mismatches.len(), render_mismatches(.mismatches))]
    IntegrityMismatch {
        /// Every tarball whose bytes mismatched, structured (not pre-rendered).
        mismatches: Vec<IntegrityMismatchItem>,
    },

    /// `--offline` could not satisfy one or more tarballs from the cache: they
    /// are not cached. (A cached tarball that fails re-verification is
    /// [`FuziError::OfflineCacheCorrupt`], never this.)
    #[error("{} tarball(s) unavailable offline (re-run without --offline to fetch):\n  {}", .packages.len(), render_block(.packages, |package| escape_untrusted(package)))]
    OfflineCacheMiss {
        /// Package labels that could not be satisfied from the cache.
        packages: Vec<String>,
    },

    /// `--offline` found one or more cached tarballs failing re-verification
    /// against their key — local corruption or tampering, with no source to
    /// heal from.
    ///
    /// A security event, so it is kept apart from the quiet
    /// [`FuziError::OfflineCacheMiss`]: exit 65 with the other hash violations
    /// (`IntegrityMismatch`, `CacheTampered`), not 69's "re-run without
    /// `--offline`". Online, the same entry is discarded and refetched (the
    /// registry has the truth); offline, the entries are left in place so they
    /// can be inspected.
    #[error(
        "{} cached tarball(s) failed re-verification under --offline (local corruption or tampering — do not trust these bytes; re-run without --offline to discard and refetch them):\n  {}",
        .entries.len(),
        render_block(.entries, |e| format!("{}: {}", escape_untrusted(&e.package), escape_untrusted(&e.path)))
    )]
    OfflineCacheCorrupt {
        /// Every cached tarball that failed re-verification, structured.
        entries: Vec<CorruptCacheItem>,
    },

    /// Extracting a package's cached tarball into the staging tree failed.
    ///
    /// A security-class `source` — a malformed archive, a guard violation (an
    /// oversized or bomb archive, a rejected entry type, a path, a directory, or
    /// a tar or PAX header refused) — is a bad package: the tarball's bytes matched
    /// the lockfile's integrity hash, so it is the published package that
    /// fails, and re-running reads the same bytes. The digest is checked
    /// before such an error is reported: a mismatch is reported as
    /// [`FuziError::CacheTampered`] instead, and a read failure that leaves it
    /// unchecked as [`FuziError::Io`]. Anything else is a filesystem or read
    /// failure.
    #[error("{}", render_extract(.package, .source))]
    Extract {
        /// The package label (install path) whose tarball failed.
        package: String,
        /// What the extractor refused or failed on.
        #[source]
        source: fuz_archive::ArchiveError,
    },

    /// The materialization pre-flight estimated `node_modules` would not fit on
    /// the filesystem. A hint, not a reservation — `needed` is a conservative
    /// estimate; the real ENOSPC backstop still applies if it slips through.
    #[error(
        "not enough disk space to materialize node_modules: need ~{needed} bytes, {available} available"
    )]
    InsufficientSpace {
        /// Conservative estimate of the extracted tree size.
        needed: u64,
        /// Bytes free on the target filesystem at pre-flight.
        available: u64,
    },

    /// A *cached* tarball's bytes did not match its integrity key while being
    /// extracted — local corruption or tampering between the fetch phase and
    /// materialization. Distinct from the fetch-time supply-chain
    /// [`FuziError::IntegrityMismatch`]: this is the cache changing *under* fuzi.
    /// Detected by hashing exactly the bytes extracted (one fd, one pass), so it
    /// is the materialization-side TOCTOU close.
    #[error(
        "cached tarball for {} changed under fuzi (hash mismatch during extraction); clear the npm cache and re-run",
        escape_untrusted(.package)
    )]
    CacheTampered {
        /// The package label (install path) whose cached tarball mismatched.
        package: String,
    },

    /// `<project>/node_modules` exists but is not a real directory — a symlink or
    /// a regular file. fuzi owns and replaces the whole tree, but refuses to
    /// silently delete or follow something the user placed deliberately.
    #[error("node_modules exists but is {kind}; remove it and re-run")]
    NodeModulesNotDirectory {
        /// What occupies the path instead of a directory.
        kind: NodeModulesObstruction,
    },

    /// `<project>/node_modules` is a mount point — on another device than the
    /// project directory (a container volume, a tmpfs, a btrfs subvolume), or
    /// a bind mount. fuzi publishes the tree by renaming the old one aside and
    /// a fresh one into place, and a mount point can be neither renamed nor
    /// replaced. Refused before any network work by the device check, and
    /// again at the swap, where the move-aside's `EBUSY` catches a bind mount
    /// from the same filesystem (which shares its parent's device).
    #[error(
        "node_modules is a mount point (on a different device from the project directory — a container volume, a tmpfs, a btrfs subvolume — or a bind mount), and fuzi replaces node_modules by renaming a fresh tree into its place, which a mount point refuses; unmount it (for a container volume, mount the project directory instead; for a btrfs subvolume, `btrfs subvolume delete node_modules`) and re-run"
    )]
    NodeModulesMountPoint,

    /// The move-aside of `<project>/node_modules` failed with `EXDEV`: the
    /// filesystem will not rename that directory in place, though it is not a
    /// mount point. On Linux the usual source is overlayfs refusing to rename a
    /// directory from a lower layer (a `node_modules` baked into a container
    /// image by `RUN npm ci`, without overlayfs `redirect_dir`). Nothing was
    /// changed; removing the directory lets the next install create it fresh.
    #[error(
        "node_modules can't be renamed on this filesystem (e.g. an overlayfs lower layer baked into a container image), and fuzi replaces node_modules by renaming a fresh tree into its place; remove it (rm -rf node_modules) and re-run"
    )]
    NodeModulesNotRenameable,

    /// A plan entry the staging boundary refuses: a placement or link key that
    /// fails the `node_modules` key gate (a character npm package names cannot
    /// contain, a dot-leading component, an improper nesting such as a bare
    /// `@scope`), a remainder that is absolute, empty, or escapes the staging
    /// root by `..` (`Path::join` would follow it *out of* the fuzi-owned
    /// tree), or a placement or link at or under another link. Classify
    /// refuses every such key before materialization, so this fires only as
    /// defense-in-depth at the [`StagingDir`](crate::staging::StagingDir) trust
    /// boundary — a caller must not be able to subvert it with a hand-built
    /// [`InstallPath`](crate::entry::InstallPath) or plan.
    #[error(
        "unsafe node_modules placement ({}); refusing to materialize it",
        escape_untrusted(.key)
    )]
    UnsafeStagingPath {
        /// The offending plan key, as given (`node_modules/…`).
        key: String,
    },

    /// The interrupt drain acted first, so the install stopped with
    /// `node_modules` exactly as it was: either the drain claimed the staging
    /// tree before the publish rename could run, or it had already fired when
    /// the staging tree was about to be created (and none was).
    ///
    /// Rarely seen: the `fuzi` binary's signal listener drains and then exits
    /// `128 + signum`, and usually wins the race to end the process. The variant
    /// exists so the refusal travels as an ordinary error — the library refuses
    /// to create a tree no drain would remove or to publish one a drain is
    /// deleting, and never panics or exits to say so.
    #[error("install interrupted before node_modules was published; nothing was changed")]
    Interrupted,

    /// Part of the staging tree vanished while the install was building it —
    /// another process removed it (a concurrent `fuzi clean` sweeps every
    /// `.fuzi-installing-*` it finds, live or not). Reported either before the
    /// publish, by the check that every placed package, link, and `.bin` link
    /// is still there, or when a write into the tree failed with `NotFound`
    /// because the directory it wrote into was gone. Either way nothing is
    /// published: `node_modules` is exactly as it was.
    ///
    /// `EX_TEMPFAIL` with [`FuziError::Fetch`]: nothing about the project is
    /// wrong, and re-running without the interference is the fix.
    #[error(
        "part of the staging tree vanished during the install ({} is missing: {}); {}, so nothing was published and node_modules is unchanged — {}",
        .missing,
        escape_untrusted(&.path.display().to_string()),
        .missing.why(),
        .missing.next_step()
    )]
    StagingIncomplete {
        /// What was missing (the first gap found).
        missing: StagingEntry,
        /// The missing path inside the staging tree.
        path: std::path::PathBuf,
    },

    /// One or more linked packages' sibling targets failed the link-target
    /// check: the target is missing, is a symlink, is not a directory, is the
    /// project itself (or the project has no parent directory to hold a
    /// sibling), or its `package.json` is absent, a symlink, oversized,
    /// unparseable, or names a different package than the lockfile.
    ///
    /// The check runs before any network or disk work, where nothing has been
    /// fetched or written, and again just before the staging tree is
    /// published, where the staging tree is discarded. Either way
    /// `node_modules` is exactly as it was.
    #[error(
        "{} linked package target(s) failed the link-target check:\n  {}",
        .problems.len(),
        render_link_problems(.problems)
    )]
    LinkTarget {
        /// Every link whose target failed, structured.
        problems: Vec<LinkTargetProblem>,
    },

    /// `fuzi verify` found the materialized `node_modules` diverging from the
    /// lockfile — no `node_modules` at all, a missing placement, a version
    /// mismatch, a host platform binary the lock cannot supply, a link (or a
    /// linked bin's `.bin` entry) that is not what install writes, or a parent
    /// directory that is not a real directory. Carries every problem in one
    /// pass; the human rendering groups them by kind and shows a few of each.
    #[error("node_modules does not match package-lock.json:\n  {}", render_verify_problems(.problems))]
    VerifyFailed {
        /// Every structural divergence found.
        problems: Vec<crate::verify::VerifyProblem>,
    },
}

/// What occupies the `node_modules` path when it is not a usable directory — a
/// closed set, so the error carries a typed value rather than a free-form string.
///
/// Serialized (in `fuzi clean`'s `--json`) as `"symlink"` / `"file"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeModulesObstruction {
    /// A symbolic link (deliberate pnpm-style, or pointed elsewhere by the user).
    Symlink,
    /// A regular (non-directory) file.
    File,
}

impl std::fmt::Display for NodeModulesObstruction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Symlink => "a symlink",
            Self::File => "a file",
        })
    }
}

/// What the staging completeness check found missing — the
/// [`FuziError::StagingIncomplete`] payload's `code`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StagingEntry {
    /// The staging root itself.
    Root,
    /// A registry package's directory.
    PackageDir,
    /// The `package.json` a package's tarball shipped.
    PackageJson,
    /// A sibling `link: true` package's symlink.
    Link,
    /// A `node_modules/.bin/<command>` symlink.
    BinLink,
}

impl StagingEntry {
    /// The stable machine-readable code for `--json`.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Root => "staging_root",
            Self::PackageDir => "package_dir",
            Self::PackageJson => "package_json",
            Self::Link => "link",
            Self::BinLink => "bin_link",
        }
    }

    /// Why the entry is missing — the same for every kind: fuzi does not
    /// remove anything from a tree it is still building.
    #[must_use]
    pub const fn why(self) -> &'static str {
        "another process removed part of the staging tree while fuzi was building it (e.g. a concurrent `fuzi clean`, which sweeps every .fuzi-installing-* directory)"
    }

    /// What to do about it.
    #[must_use]
    pub const fn next_step(self) -> &'static str {
        "re-run `fuzi install`, and don't run `fuzi clean` while an install is in progress"
    }
}

impl std::fmt::Display for StagingEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Root => "the staging root",
            Self::PackageDir => "a package directory",
            Self::PackageJson => "a package's package.json",
            Self::Link => "a linked package",
            Self::BinLink => "a .bin link",
        })
    }
}

/// Build a `.map_err` closure that tags an [`io::Error`](std::io::Error) with
/// `what` and wraps it in [`FuziError::Io`]. Single-sources the
/// `.map_err(|source| FuziError::Io { what, source })` dance repeated across the
/// crate's filesystem call sites.
pub fn io_err(what: &'static str) -> impl FnOnce(std::io::Error) -> FuziError {
    move |source| FuziError::Io { what, source }
}

/// Map a cache failure to the top-level `Io` error (the design's "cache IO
/// reuses `Io`"). Callers that care about `IntegrityMismatch` / `Corrupt` match
/// those before reaching this; the defensive arm — only reachable if a future
/// variant slips through — keeps the mapping total without a panic.
pub fn io_from_cache(e: crate::cache::CacheError) -> FuziError {
    use crate::cache::CacheError;
    match e {
        CacheError::Io { what, source } => FuziError::Io { what, source },
        other => FuziError::Io {
            what: "cache",
            source: std::io::Error::other(other.to_string()),
        },
    }
}

impl FuziError {
    /// Stable process exit code for this error's class (sysexits-style).
    #[must_use]
    pub const fn exit_code(&self) -> u8 {
        match self {
            Self::Usage { .. } => EX_USAGE,
            Self::Io { .. } => 74, // EX_IOERR
            // EX_DATAERR — well-formed-but-wrong data, none blind-retryable (the
            // input or the cache entry must be fixed): a malformed/unsupported
            // lockfile (`Lockfile`), manifest↔lock `Drift`, content fuzi refuses
            // (`Refused`), a fetched tarball whose bytes don't match the lock
            // (`IntegrityMismatch`), or a *cached* tarball that fails verification
            // at extraction (`CacheTampered`).
            //
            // `CacheTampered` deliberately shares 65 with the fetch-time
            // `IntegrityMismatch`: both are a content-hash violation against the
            // lockfile's cryptographic anchor — the same *class* of "do not trust
            // these bytes" — so they share the coarse exit code, and the finer
            // at-rest-tamper-vs-supply-chain distinction an agent wants rides the
            // precise `kind()` string in `--json` (`cache_tampered` vs
            // `integrity_mismatch`), not an overloaded code. `OfflineCacheCorrupt`
            // is the same event caught at the fetch phase's re-verify under
            // `--offline` (online, that re-verify self-heals instead).
            //
            // `VerifyFailed` joins the class too: a tree that diverges from the
            // lock is well-formed-but-wrong state — as does `FetchPermanent`
            // (the lockfile names a tarball the registry definitively will not
            // serve; the *input* must change, so it must not share `Fetch`'s
            // EX_TEMPFAIL "re-run to retry"). `LinkTarget` too: the lockfile and
            // the sibling directory disagree, and one of them must change.
            Self::Lockfile { .. }
            | Self::Drift { .. }
            | Self::Refused { .. }
            | Self::IntegrityMismatch { .. }
            | Self::CacheTampered { .. }
            | Self::OfflineCacheCorrupt { .. }
            | Self::FetchPermanent { .. }
            | Self::LinkTarget { .. }
            | Self::VerifyFailed { .. } => 65,
            Self::MissingInput { .. } => EX_NOINPUT,
            Self::OfflineCacheMiss { .. } => 69, // EX_UNAVAILABLE
            // EX_CONFIG — the host's TLS configuration (its client setup, or the
            // trust a registry's certificate fails) must change; a re-run fails
            // the same way.
            Self::HttpClient { .. } | Self::TlsCertificate { .. } => 78,
            // EX_TEMPFAIL — re-running is the retry: a failed fetch may succeed
            // next time, and an interrupted install changed nothing at all.
            // (`Interrupted` rarely reaches here — the signal listener's
            // `128 + signum` exit usually ends the process first.) A staging
            // tree another process cut into changed nothing either, and the
            // re-run succeeds once that process is out of the way.
            Self::Fetch { .. } | Self::Interrupted | Self::StagingIncomplete { .. } => 75,
            // A malformed/hostile tarball is a data error (65); a filesystem
            // failure during extraction is an I/O error (74).
            Self::Extract { source, .. } => {
                if source.is_security_violation() {
                    65
                } else {
                    74
                }
            }
            // EX_CANTCREAT — a materialization target fuzi cannot safely create
            // into: no room, an obstructed, mounted, or unrenameable
            // `node_modules`, or a placement path that would escape the staging
            // tree.
            Self::InsufficientSpace { .. }
            | Self::NodeModulesNotDirectory { .. }
            | Self::NodeModulesMountPoint
            | Self::NodeModulesNotRenameable
            | Self::UnsafeStagingPath { .. } => 73,
        }
    }

    /// A stable machine-readable kind string for the `--json` error contract.
    ///
    /// Finer-grained than [`exit_code`](Self::exit_code) (several variants share a
    /// code), so an agent can branch on the precise failure mode — e.g. distinguish
    /// `drift` from a bad `lockfile`, or at-rest `cache_tampered` from a fetch-time
    /// `integrity_mismatch`, even though each pair shares exit 65.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Usage { .. } => "usage",
            Self::Io { .. } => "io",
            Self::MissingInput { .. } => "missing_input",
            Self::Lockfile { .. } => "lockfile",
            Self::Drift { .. } => "drift",
            Self::Refused { .. } => "refused",
            Self::Fetch { .. } => "fetch",
            Self::FetchPermanent { .. } => "fetch_permanent",
            Self::HttpClient { .. } => "http_client",
            Self::TlsCertificate { .. } => "tls_certificate",
            Self::IntegrityMismatch { .. } => "integrity_mismatch",
            Self::OfflineCacheMiss { .. } => "offline_cache_miss",
            Self::OfflineCacheCorrupt { .. } => "offline_cache_corrupt",
            Self::Extract { .. } => "extract",
            Self::InsufficientSpace { .. } => "insufficient_space",
            Self::CacheTampered { .. } => "cache_tampered",
            Self::NodeModulesNotDirectory { .. } => "node_modules_not_directory",
            Self::NodeModulesMountPoint => "node_modules_mount_point",
            Self::NodeModulesNotRenameable => "node_modules_not_renameable",
            Self::UnsafeStagingPath { .. } => "unsafe_staging_path",
            Self::Interrupted => "interrupted",
            Self::StagingIncomplete { .. } => "staging_incomplete",
            Self::LinkTarget { .. } => "link_target",
            Self::VerifyFailed { .. } => "verify_failed",
        }
    }
}

/// Join one `line`-rendered entry per item into a `\n  `-indented block — the
/// shared shape of the per-class human renderers below (the `--json` path
/// serializes the structs directly instead).
///
/// The items' strings are lockfile, registry, or sibling text, carried raw in
/// the structs; each renderer escapes them field by field
/// ([`escape_untrusted`]), so a field can add neither a control sequence nor a
/// line to the block.
fn render_block<T>(items: &[T], line: impl Fn(&T) -> String) -> String {
    items.iter().map(line).collect::<Vec<_>>().join("\n  ")
}

/// A foreign error's message, escaped — an OS error or an archive error can
/// quote a path or a tarball entry name.
fn escaped(error: &dyn std::fmt::Display) -> String {
    escape_untrusted(&error.to_string())
}

/// Render [`FuziError::Extract`]: a bad package (the security class, exit 65)
/// says the bytes are the published package's and a re-run won't help; a
/// filesystem or read failure (exit 74) says only what failed.
fn render_extract(package: &str, source: &fuz_archive::ArchiveError) -> String {
    if source.is_security_violation() {
        format!(
            "the tarball for {} was refused: {}; it matches the lockfile's integrity hash, so the published package itself is bad — re-running won't help; update or replace the dependency",
            escape_untrusted(package),
            escaped(source)
        )
    } else {
        format!(
            "extracting the tarball for {} failed: {}",
            escape_untrusted(package),
            escaped(source)
        )
    }
}

/// Render structured fetch failures into the human-readable `package: reason` block.
fn render_fetch_failures(failures: &[FetchFailure]) -> String {
    render_block(failures, |f| {
        format!(
            "{}: {}",
            escape_untrusted(&f.package),
            escape_untrusted(&f.reason)
        )
    })
}

/// Render structured integrity mismatches into the human-readable
/// `package: expected … computed …` block.
fn render_mismatches(mismatches: &[IntegrityMismatchItem]) -> String {
    render_block(mismatches, |m| {
        format!(
            "{}: expected {}, computed {}",
            escape_untrusted(&m.package),
            escape_untrusted(&m.expected),
            escape_untrusted(&m.actual)
        )
    })
}

/// Render structured link-target problems into the human-readable `package · detail` block.
fn render_link_problems(problems: &[LinkTargetProblem]) -> String {
    render_block(problems, |p| {
        format!(
            "{} · {}",
            escape_untrusted(&p.package),
            escape_untrusted(&p.detail)
        )
    })
}

/// Example lines shown per problem kind in the human `fuzi verify` failure
/// before the rest collapse to `… (+N more)` — a tree missing hundreds of
/// packages reads as a summary, not a wall. `--json` carries every problem.
const VERIFY_EXAMPLE_CAP: usize = 8;

/// Render structured verify problems into the human-readable block: grouped
/// by kind in first-seen order, each group a `kind (n):` heading over at most
/// [`VERIFY_EXAMPLE_CAP`] `package · detail` lines.
fn render_verify_problems(problems: &[crate::verify::VerifyProblem]) -> String {
    use std::fmt::Write as _;
    let mut groups: Vec<(
        crate::verify::VerifyProblemKind,
        Vec<&crate::verify::VerifyProblem>,
    )> = Vec::new();
    for p in problems {
        match groups.iter_mut().find(|(kind, _)| *kind == p.kind) {
            Some((_, group)) => group.push(p),
            None => groups.push((p.kind, vec![p])),
        }
    }
    let mut out = Vec::new();
    for (kind, group) in &groups {
        let mut block = format!("{} ({}):", kind.as_str(), group.len());
        for p in group.iter().take(VERIFY_EXAMPLE_CAP) {
            // Writing to a String is infallible.
            let _ = write!(
                block,
                "\n    {} · {}",
                escape_untrusted(&p.package),
                escape_untrusted(&p.detail)
            );
        }
        if group.len() > VERIFY_EXAMPLE_CAP {
            let _ = write!(
                block,
                "\n    … (+{} more)",
                group.len() - VERIFY_EXAMPLE_CAP
            );
        }
        out.push(block);
    }
    out.join("\n  ")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A FIFO `package-lock.json` / `package.json` is refused as not a regular
    /// file, without blocking: a plain open would wait for a writer forever.
    /// Run on a thread with a deadline so a regression fails, not hangs.
    #[test]
    fn a_fifo_project_file_is_refused_without_blocking() {
        for file in [ProjectFile::Lockfile, ProjectFile::Manifest] {
            let dir = tempfile::tempdir().unwrap();
            nix::unistd::mkfifo(
                &dir.path().join(file.file_name()),
                nix::sys::stat::Mode::S_IRWXU,
            )
            .unwrap();
            let (tx, rx) = std::sync::mpsc::channel();
            let path = dir.path().to_path_buf();
            std::thread::spawn(move || tx.send(read_project_file(&path, file)).unwrap());
            let err = rx
                .recv_timeout(std::time::Duration::from_secs(10))
                .expect("read blocked on a FIFO project file")
                .unwrap_err();
            assert!(matches!(err, FuziError::Io { .. }), "{err:?}");
            assert_eq!(err.exit_code(), 74);
            let message = err.to_string();
            assert!(message.contains("not a regular file"), "{message}");
            assert!(message.contains(file.file_name()), "{message}");
        }
    }

    /// An absent project file stays the missing-input class (66).
    #[test]
    fn an_absent_project_file_is_missing_input() {
        let dir = tempfile::tempdir().unwrap();
        let err = read_project_file(dir.path(), ProjectFile::Lockfile).unwrap_err();
        assert!(matches!(err, FuziError::MissingInput { .. }), "{err:?}");
        assert_eq!(err.exit_code(), EX_NOINPUT);
    }

    /// The cap admits a file of exactly `cap` bytes and refuses one byte more
    /// — refused, never truncated into a parse of the prefix.
    #[test]
    fn a_project_file_over_the_cap_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("package-lock.json");
        std::fs::write(&path, b"12345").unwrap();
        assert_eq!(
            read_project_file_capped(dir.path(), ProjectFile::Lockfile, 5).unwrap(),
            "12345"
        );
        std::fs::write(&path, b"123456").unwrap();
        let err = read_project_file_capped(dir.path(), ProjectFile::Lockfile, 5).unwrap_err();
        assert!(matches!(err, FuziError::Io { .. }), "{err:?}");
        assert_eq!(
            err.to_string(),
            "read package-lock.json: is 6 bytes, over fuzi's read cap of 5 bytes"
        );
    }

    /// The bound holds on the read itself, not only the size check: a procfs
    /// file reports size 0 (as a file that grew after the check would read
    /// past its reported size), and is still refused past the cap.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_cap_bounds_the_read_not_only_the_size_check() {
        let dir = tempfile::tempdir().unwrap();
        let status = std::path::Path::new("/proc/self/status");
        assert_eq!(std::fs::metadata(status).unwrap().len(), 0);
        std::os::unix::fs::symlink(status, dir.path().join("package.json")).unwrap();
        let err = read_project_file_capped(dir.path(), ProjectFile::Manifest, 16).unwrap_err();
        assert_eq!(
            err.to_string(),
            "read package.json: is at least 17 bytes, over fuzi's read cap of 16 bytes"
        );
        // Under a cap it fits, the symlink is followed and the file read whole.
        let text = read_project_file_capped(dir.path(), ProjectFile::Manifest, 1 << 20).unwrap();
        assert!(text.contains("Pid:"), "{text}");
    }

    /// The public reader carries the real cap: a sparse file one byte over
    /// `MAX_BUFFERED_SIZE` is refused.
    #[test]
    fn read_project_file_caps_at_the_buffered_ceiling() {
        let dir = tempfile::tempdir().unwrap();
        let file = std::fs::File::create(dir.path().join("package-lock.json")).unwrap();
        file.set_len(fuz_sys::limits::MAX_BUFFERED_SIZE + 1)
            .unwrap();
        let err = read_project_file(dir.path(), ProjectFile::Lockfile).unwrap_err();
        assert_eq!(
            err.to_string(),
            "read package-lock.json: is 104857601 bytes, over fuzi's read cap of 104857600 bytes (100 MiB)"
        );
    }

    #[test]
    fn extract_exit_code_splits_hostile_from_io() {
        // A malformed/hostile tarball is a data error (65) an agent can branch on
        // as "do not retry"; a filesystem failure during extraction is I/O (74).
        let extract = |source| FuziError::Extract {
            package: "node_modules/p".to_string(),
            source,
        };
        let bomb = extract(fuz_archive::ArchiveError::CompressionBomb(200));
        assert_eq!(bomb.exit_code(), 65);
        let io = extract(fuz_archive::ArchiveError::Io(std::io::Error::other("disk")));
        assert_eq!(io.exit_code(), 74);
        // Bytes that don't parse are a bad package; an OS read error is I/O.
        let malformed = extract(fuz_archive::ArchiveError::Malformed {
            context: "reading entry",
            source: std::io::Error::new(std::io::ErrorKind::InvalidData, "bad header"),
        });
        assert_eq!(malformed.exit_code(), 65);
        let read = extract(fuz_archive::ArchiveError::Read {
            context: "reading entry",
            source: std::io::Error::from_raw_os_error(5),
        });
        assert_eq!(read.exit_code(), 74);
    }

    #[test]
    fn extract_names_the_package_and_teaches_by_class() {
        let malformed = FuziError::Extract {
            package: "node_modules/p".to_string(),
            source: fuz_archive::ArchiveError::Malformed {
                context: "reading entry",
                source: std::io::Error::new(std::io::ErrorKind::InvalidData, "bad header"),
            },
        };
        assert_eq!(
            malformed.to_string(),
            "the tarball for node_modules/p was refused: malformed archive (reading entry): bad header; it matches the lockfile's integrity hash, so the published package itself is bad — re-running won't help; update or replace the dependency"
        );
        let read = FuziError::Extract {
            package: "node_modules/p".to_string(),
            source: fuz_archive::ArchiveError::Read {
                context: "reading entry",
                source: std::io::Error::other("disk"),
            },
        };
        assert_eq!(
            read.to_string(),
            "extracting the tarball for node_modules/p failed: reading the archive failed (reading entry): disk"
        );
    }

    /// Every variant that carries text someone else chose, with that text
    /// hostile: an escape sequence, a newline that would forge a line, a bidi
    /// override, a C1 control. The rendered error holds none of it raw, and has
    /// exactly the lines fuzi composed.
    #[test]
    fn display_escapes_every_untrusted_field() {
        use crate::classify::{Refusal, RefuseReason};
        use crate::entry::InstallPath;
        use crate::verify::{VerifyProblem, VerifyProblemKind};
        use fuz_sys::text::is_unprintable;

        const EVIL: &str = "x\u{1b}[2J\n  forged · line\u{202e}\u{9b}31m\r";
        let evil = || EVIL.to_string();
        // (error, lines the message has when every field is one line)
        let cases: Vec<(FuziError, usize)> = vec![
            (FuziError::Usage { message: evil() }, 1),
            (
                FuziError::Io {
                    what: "x",
                    source: std::io::Error::other(evil()),
                },
                1,
            ),
            (FuziError::Lockfile { message: evil() }, 1),
            (
                FuziError::MissingInput {
                    file: ProjectFile::Lockfile,
                    dir: std::path::PathBuf::from(EVIL),
                },
                1,
            ),
            (
                FuziError::StagingIncomplete {
                    missing: StagingEntry::PackageDir,
                    path: std::path::PathBuf::from(EVIL),
                },
                1,
            ),
            (
                FuziError::Drift {
                    diffs: vec![evil(), evil()],
                },
                3,
            ),
            (
                FuziError::Refused {
                    refusals: vec![
                        Refusal {
                            path: InstallPath::new(EVIL),
                            reason: RefuseReason::InvalidNameCharacter(evil()),
                        },
                        Refusal {
                            path: InstallPath::new(EVIL),
                            reason: RefuseReason::MalformedLink(evil()),
                        },
                    ],
                },
                5,
            ),
            (
                FuziError::Fetch {
                    failures: vec![FetchFailure {
                        package: evil(),
                        reason: evil(),
                    }],
                },
                2,
            ),
            (
                FuziError::FetchPermanent {
                    failures: vec![FetchFailure {
                        package: evil(),
                        reason: evil(),
                    }],
                },
                2,
            ),
            (
                FuziError::IntegrityMismatch {
                    mismatches: vec![IntegrityMismatchItem {
                        package: evil(),
                        expected: evil(),
                        actual: evil(),
                    }],
                },
                2,
            ),
            (
                FuziError::OfflineCacheMiss {
                    packages: vec![evil(), evil()],
                },
                3,
            ),
            (
                FuziError::Extract {
                    package: evil(),
                    source: fuz_archive::ArchiveError::Io(std::io::Error::other(evil())),
                },
                1,
            ),
            (FuziError::CacheTampered { package: evil() }, 1),
            (FuziError::HttpClient { reason: evil() }, 1),
            (
                FuziError::TlsCertificate {
                    host: evil(),
                    reason: evil(),
                },
                1,
            ),
            (
                FuziError::OfflineCacheCorrupt {
                    entries: vec![CorruptCacheItem {
                        package: evil(),
                        path: evil(),
                    }],
                },
                2,
            ),
            (FuziError::UnsafeStagingPath { key: evil() }, 1),
            (
                FuziError::LinkTarget {
                    problems: vec![LinkTargetProblem {
                        package: evil(),
                        detail: evil(),
                    }],
                },
                2,
            ),
            (
                FuziError::VerifyFailed {
                    problems: vec![VerifyProblem {
                        package: evil(),
                        kind: VerifyProblemKind::LinkMismatch,
                        detail: evil(),
                    }],
                },
                3,
            ),
        ];
        for (err, lines) in &cases {
            let shown = err.to_string();
            let kind = err.kind();
            assert!(
                !shown.chars().any(|c| c != '\n' && is_unprintable(c)),
                "{kind}: {shown:?}"
            );
            assert_eq!(shown.lines().count(), *lines, "{kind}: {shown:?}");
            assert!(shown.contains("\\u{1b}[2J\\n"), "{kind}: {shown:?}");
        }
    }

    #[test]
    fn missing_input_names_the_file_the_dir_and_the_next_step() {
        let err = FuziError::MissingInput {
            file: ProjectFile::Lockfile,
            dir: "/home/u/proj".into(),
        };
        assert_eq!(
            err.to_string(),
            format!(
                "no package-lock.json in /home/u/proj; {}",
                ProjectFile::Lockfile.next_step()
            )
        );
        assert!(err.to_string().contains("npm install --package-lock-only"));
    }

    #[test]
    fn display_leaves_ordinary_text_alone() {
        // The escaping is invisible for what a real lockfile and sibling hold.
        let err = FuziError::LinkTarget {
            problems: vec![LinkTargetProblem {
                package: "node_modules/@fuzdev/zap".to_string(),
                detail: "link target ../zap is package `zap`, but the lockfile names `@fuzdev/zap`"
                    .to_string(),
            }],
        };
        assert_eq!(
            err.to_string(),
            "1 linked package target(s) failed the link-target check:\n  node_modules/@fuzdev/zap · link target ../zap is package `zap`, but the lockfile names `@fuzdev/zap`"
        );
    }

    /// The full agent-facing taxonomy: every variant's `(exit_code, kind)` pair.
    /// `kind` is the stable `--json` contract, pinned directly here:
    /// a renamed kind or a drifted code (e.g. flipping `cache_tampered`
    /// off the shared-65 with `integrity_mismatch`) turns this red. `Extract`
    /// is covered above (its code is computed, not a constant).
    #[test]
    fn exit_code_and_kind_taxonomy_is_stable() {
        let cases: &[(FuziError, u8, &str)] = &[
            (
                FuziError::Usage {
                    message: "x".into(),
                },
                64,
                "usage",
            ),
            (
                FuziError::Io {
                    what: "x",
                    source: std::io::Error::other("x"),
                },
                74,
                "io",
            ),
            (
                FuziError::Lockfile {
                    message: "x".into(),
                },
                65,
                "lockfile",
            ),
            (
                FuziError::MissingInput {
                    file: ProjectFile::Manifest,
                    dir: "/p".into(),
                },
                66,
                "missing_input",
            ),
            (FuziError::Drift { diffs: vec![] }, 65, "drift"),
            (FuziError::Refused { refusals: vec![] }, 65, "refused"),
            (
                FuziError::IntegrityMismatch { mismatches: vec![] },
                65,
                "integrity_mismatch",
            ),
            (
                FuziError::CacheTampered {
                    package: "x".into(),
                },
                65,
                "cache_tampered",
            ),
            (
                FuziError::VerifyFailed { problems: vec![] },
                65,
                "verify_failed",
            ),
            (
                FuziError::LinkTarget { problems: vec![] },
                65,
                "link_target",
            ),
            (
                FuziError::OfflineCacheMiss { packages: vec![] },
                69,
                "offline_cache_miss",
            ),
            // Deliberately NOT 69: a tampered entry is not a cold miss.
            (
                FuziError::OfflineCacheCorrupt { entries: vec![] },
                65,
                "offline_cache_corrupt",
            ),
            (FuziError::Fetch { failures: vec![] }, 75, "fetch"),
            // Shares 75 with `Fetch`: an interrupted install changed nothing,
            // so re-running is the whole remedy.
            (FuziError::Interrupted, 75, "interrupted"),
            // Shares 75 too: another process cut into the staging tree, nothing
            // was published, and a re-run without it succeeds.
            (
                FuziError::StagingIncomplete {
                    missing: StagingEntry::Root,
                    path: "/p/.fuzi-installing-0".into(),
                },
                75,
                "staging_incomplete",
            ),
            // Deliberately NOT 75: the same client config fails the same way.
            (
                FuziError::HttpClient { reason: "x".into() },
                78,
                "http_client",
            ),
            // Deliberately NOT 75: a rejected certificate is rejected again on
            // a re-run — the trust (or the proxy) must change.
            (
                FuziError::TlsCertificate {
                    host: "x".into(),
                    reason: "y".into(),
                },
                78,
                "tls_certificate",
            ),
            // Deliberately NOT 75: a 4xx is not "re-run to retry".
            (
                FuziError::FetchPermanent { failures: vec![] },
                65,
                "fetch_permanent",
            ),
            (
                FuziError::InsufficientSpace {
                    needed: 1,
                    available: 0,
                },
                73,
                "insufficient_space",
            ),
            (
                FuziError::NodeModulesNotDirectory {
                    kind: NodeModulesObstruction::File,
                },
                73,
                "node_modules_not_directory",
            ),
            (
                FuziError::NodeModulesMountPoint,
                73,
                "node_modules_mount_point",
            ),
            (
                FuziError::NodeModulesNotRenameable,
                73,
                "node_modules_not_renameable",
            ),
            (
                FuziError::UnsafeStagingPath { key: "/abs".into() },
                73,
                "unsafe_staging_path",
            ),
        ];
        for (err, code, kind) in cases {
            assert_eq!(err.exit_code(), *code, "exit_code for {kind}");
            assert_eq!(err.kind(), *kind, "kind for {kind}");
        }
    }
}
