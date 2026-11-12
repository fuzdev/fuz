//! Error types for release operations

use std::borrow::Cow;
use std::path::PathBuf;

use fuz_sys::text::quoted;

use crate::release_log::{
    HeadViolation, ReleaseLogError, TargetField, excerpt, parse_message, shown,
};
use crate::{MANIFEST_FORMAT_VERSION, MAX_FILE_SIZE, MAX_MANIFEST_SIZE, MAX_TOTAL_SIZE};

/// Errors from manifest parsing and validation
///
/// A manifest is read before its signature is checked, so the strings a
/// variant carries are whatever a store served, unescaped and at whatever
/// length. Each message shows such a string bounded and escaped
/// (`fuz_sys::text`), so none can drive the terminal the message is printed
/// to.
#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    #[error("unsupported manifest format version: {0} (max supported: {MANIFEST_FORMAT_VERSION})")]
    UnsupportedFormat(u32),
    #[error("manifest too large: {0} bytes (max {MAX_MANIFEST_SIZE})")]
    TooLarge(u64),
    /// The parser's message, bounded and escaped (`From<serde_json::Error>`).
    #[error("failed to parse manifest: {0}")]
    Parse(String),
    #[error("invalid tarball path: {}", shown(.0))]
    InvalidTarballPath(String),
    #[error("invalid content hash in manifest: {} (expected `v1-` and 64 lowercase hex)", quoted(&excerpt(.0)))]
    InvalidContentHash(String),
    #[error(
        "invalid binary name in manifest: {} (must be A-Za-z0-9._-, starting with a letter or digit)",
        quoted(&excerpt(.0))
    )]
    InvalidBinaryName(String),
    #[error("tarball too large: {0} bytes (max {MAX_TOTAL_SIZE})")]
    TarballTooLarge(u64),
    #[error("target mismatch: expected {expected}, got {}", shown(.actual))]
    TargetMismatch { expected: String, actual: String },
    /// The installed version is below the release's `minimum_version` floor.
    /// `tool` is whether the floor gates a per-tool install (the installed
    /// tool's version) rather than the fuz self artifact — the two recover
    /// differently, so the hint depends on it.
    #[error("version below minimum: {} < {}", shown(.current), shown(.minimum))]
    BelowMinimum {
        current: String,
        minimum: String,
        tool: bool,
    },
    #[error("downgrade not allowed: {} -> {}", shown(.current), shown(.target))]
    Downgrade { current: String, target: String },
    #[error("invalid version string: {}", shown(.0))]
    InvalidVersion(String),
    #[error("missing required binary in manifest: {0}")]
    MissingBinary(String),
    #[error("self artifact manifest declares a binary it does not ship: {}", shown(.0))]
    UnexpectedBinary(String),
    #[error("tool not in first-party allowlist: {}", shown(.0))]
    ToolNotAllowed(String),
    #[error("self artifact manifest must not declare a tool (found `{}`)", shown(.0))]
    UnexpectedTool(String),
    #[error("tool manifest declares no binaries: {}", shown(.0))]
    EmptyBinaries(String),
    /// A tool manifest declares a binary of the fuz self artifact
    /// (`SELF_BINARIES`, in any ASCII case): installed, it would be linked
    /// over the self artifact's own `bin/` link.
    #[error(
        "tool manifest for {} declares the binary {}, which belongs to the fuz self artifact",
        shown(.tool),
        shown(.binary)
    )]
    ReservedBinaryName { tool: String, binary: String },
    #[error("test binary in manifest: {} (test binaries must never ship in releases)", shown(.name))]
    TestBinaryRejected { name: String },
    /// Publisher side: a release's name, version, or target cannot be part of
    /// a storage key, so no store could hold the release. Refused before
    /// anything is packed, signed, or logged.
    #[error("release {field} cannot be part of a storage key: {} ({reason})", quoted(&excerpt(.value)))]
    UnpublishableField {
        /// `"name"`, `"version"`, or `"target"`.
        field: &'static str,
        value: String,
        /// The key rule the value breaks.
        reason: &'static str,
    },
    /// A manifest read from a storage key is not the release that key names:
    /// its `version` and `target` build another key. See
    /// [`Manifest::check_key`](crate::Manifest::check_key).
    #[error(
        "the manifest at {} is {} for {}, not the release its key names",
        shown(.key),
        shown(.version),
        shown(.target)
    )]
    KeyMismatch {
        /// The key the manifest was read from.
        key: String,
        /// The manifest's `version`.
        version: String,
        /// The manifest's `target`.
        target: String,
    },
    /// Publisher side: a release's `version` or `minimum_version` is not one
    /// a client can act on — not semver, or a floor with build metadata or
    /// above the release's own version. Every client orders releases and
    /// checks the floor by semver, so it would refuse the release (or, for a
    /// floor above it, refuse every upgrade to it), and a stream whose latest
    /// it was could not be upgraded or pruned. Refused before anything is
    /// packed, signed, or logged.
    #[error(
        "release {field} cannot be published: {} ({})",
        quoted(&excerpt(.value)),
        shown(.reason)
    )]
    UnpublishableVersion {
        /// `"version"` or `"minimum_version"`.
        field: &'static str,
        value: String,
        /// Why: the semver parser's message, which can repeat part of
        /// `value`, or the rule the floor breaks.
        reason: String,
    },
    /// Producer side: a manifest's `tarball.path` is not the tarball its
    /// release is stored as (`ReleaseLayout::tarball_filename`). The field is
    /// unsigned to a reader that checks no signature, so a prune refuses the
    /// manifest rather than delete what it names.
    #[error(
        "the manifest at {} names the tarball {}, not {}, the one its release is stored as",
        shown(.key),
        quoted(&excerpt(.actual)),
        shown(.expected)
    )]
    TarballMismatch {
        /// The key the manifest was read from.
        key: String,
        /// The tarball filename the release is stored as.
        expected: String,
        /// The manifest's `tarball.path`.
        actual: String,
    },
    /// A target triple outside the supported set: the build's own (a
    /// client or publisher built for a target no release is made for).
    #[error(transparent)]
    UnsupportedTarget(#[from] fuz_artifact::platform::UnsupportedTarget),
    #[error("signature verification failed: {0}")]
    Signature(#[from] fuz_crypto::VerifyError),
    #[error("canonical JSON error: {0}")]
    Canonical(#[from] fuz_crypto::CanonicalError),
}

impl From<serde_json::Error> for ManifestError {
    /// Keeps a bounded, escaped rendering of the parser's message rather than
    /// the error itself, as [`ReleaseLogError`]'s does: the message repeats a
    /// token of a document a store served, and an error kept as a `source()`
    /// would reach a printer of the source chain raw.
    fn from(e: serde_json::Error) -> Self {
        Self::Parse(parse_message(&e))
    }
}

/// How an install below a release's `minimum_version` floor recovers: the
/// fuz self artifact re-bootstraps, a tool (`tool`) reinstalls fresh — the
/// floor holds under `--allow-downgrade` and `--force`, and only an install
/// with no `current` link skips it.
///
/// Single-sourced for [`ManifestError::BelowMinimum`]'s hint and the
/// `update_required` reason of `compute_update_check`.
pub(crate) const fn below_minimum_recovery(tool: bool) -> &'static str {
    if tool {
        "The installed tool is too old to upgrade in place, and neither \
         --allow-downgrade nor --force waives the floor: remove \
         $FUZ_HOME/tools/<name>/current (FUZ_HOME defaults to ~/.fuz), then run \
         `fuz tool install <name>` for a fresh install (the tool's links in \
         $FUZ_HOME/bin dangle until it completes)"
    } else {
        "Re-bootstrap required: reinstall fuz, see https://github.com/fuzdev/fuz#usage"
    }
}

impl ManifestError {
    /// Returns user-facing hint for how to fix this error
    #[allow(clippy::missing_const_for_fn)] // calls non-const hint() methods
    pub fn hint(&self) -> Option<&'static str> {
        match self {
            Self::UnsupportedFormat(_) => {
                Some("Upgrade fuz to read this manifest: https://github.com/fuzdev/fuz#usage")
            }
            Self::TooLarge(_) => Some("Manifest exceeds size limit - possible attack"),
            Self::Parse(_) => Some("Manifest file is corrupted or malformed"),
            Self::InvalidTarballPath(_) => Some("Tarball path must be a simple filename"),
            Self::InvalidContentHash(_) | Self::InvalidBinaryName(_) => {
                Some("Manifest is malformed - possible path traversal; do not install")
            }
            Self::TarballTooLarge(_) => {
                Some("Manifest claims unreasonable tarball size - possible attack")
            }
            Self::TargetMismatch { .. } => Some("Download the correct release for your platform"),
            Self::BelowMinimum { tool, .. } => Some(below_minimum_recovery(*tool)),
            Self::Downgrade { .. } => Some("Use --allow-downgrade to override (not recommended)"),
            Self::InvalidVersion(_) => Some("Manifest contains malformed version string"),
            Self::MissingBinary(_) => Some("Manifest is incomplete - missing required binary"),
            Self::UnexpectedBinary(_) => Some(
                "The fuz self artifact ships `fuz` alone; other binaries are per-tool artifacts \
                 installed with `fuz tool install <name>`",
            ),
            Self::ToolNotAllowed(_) => {
                Some("Only first-party @fuzdev tools can be installed; check the name")
            }
            Self::UnexpectedTool(_) => {
                Some("This is a per-tool artifact; install it with `fuz tool install <name>`")
            }
            Self::EmptyBinaries(_) => Some("Tool manifest must declare at least one binary"),
            Self::ReservedBinaryName { .. } => Some(
                "A tool cannot ship a binary under a name the fuz self artifact links in \
                 ~/.fuz/bin - do not install",
            ),
            Self::TestBinaryRejected { .. } => Some(
                "Refusing to ship a test binary (name starts with `testing_`). Test binaries use \
                 weakened parameters (e.g. fast argon2) and must never reach production.",
            ),
            Self::UnpublishableField { .. } => Some(
                "A release's name, version, and target become part of its storage keys: \
                 letters, digits, and . _ - only, so semver build metadata (`+...`) cannot be \
                 published",
            ),
            Self::UnpublishableVersion { .. } => Some(
                "A release's version and minimum_version are semver (MAJOR.MINOR.PATCH, e.g. \
                 1.0.0; a pre-release such as 1.0.0-rc.1 is accepted): every client orders \
                 releases and checks the floor by them, and a floor is at most the release's own \
                 version, without build metadata",
            ),
            Self::TarballMismatch { .. } => Some(
                "The store holds a manifest that does not describe the release at its key - do \
                 not install from it; remove or repair it before pruning",
            ),
            Self::KeyMismatch { .. } => Some(
                "The store holds another release's manifest at this release's key - do not \
                 install from it; remove or repair it before pruning",
            ),
            Self::UnsupportedTarget(_) => Some(
                "Releases are made for the supported targets only; on a publisher, name one \
                 with --target",
            ),
            Self::Signature(e) => e.hint(),
            Self::Canonical(e) => e.hint(),
        }
    }
}

/// Errors from tarball extraction
///
/// The paths and names a variant carries are the tarball's and the manifest's
/// own; each message shows them bounded and escaped, as [`ManifestError`]'s do.
#[derive(Debug, thiserror::Error)]
pub enum TarballError {
    #[error("invalid path in tarball: {}", shown_path(.0))]
    InvalidPath(PathBuf),
    #[error("unsupported entry type in tarball: {} (only regular files allowed)", shown_path(.0))]
    UnsupportedEntryType(PathBuf),
    #[error("null byte in path: {}", shown_path(.0))]
    NullByte(PathBuf),
    #[error("path too long: {}", shown_path(.0))]
    PathTooLong(PathBuf),
    #[error("file too large: {} ({} bytes, max {MAX_FILE_SIZE})", shown_path(.0), .1)]
    FileTooLarge(PathBuf, u64),
    #[error("total extraction size exceeded: {0} bytes (max {MAX_TOTAL_SIZE})")]
    TotalTooLarge(u64),
    #[error("compression ratio exceeded: {0}x (max {MAX_COMPRESSION_RATIO}x)", MAX_COMPRESSION_RATIO = crate::MAX_COMPRESSION_RATIO)]
    CompressionBomb(u64),
    #[error("entry headers exceeded {0} bytes")]
    HeaderTooLarge(u64),
    #[error("setuid bit on file: {}", shown_path(.0))]
    SetuidBit(PathBuf),
    #[error("setgid bit on file: {}", shown_path(.0))]
    SetgidBit(PathBuf),
    #[error("directory entry declares a {size}-byte body: {} (directories carry no data)", shown_path(.0), size = .1)]
    DirectoryWithBody(PathBuf, u64),
    #[error(
        "PAX size record disagrees with the header size for {}: header {header_size}, PAX {pax_size}",
        shown_path(.path)
    )]
    PaxSizeMismatch {
        path: PathBuf,
        header_size: u64,
        pax_size: u64,
    },
    #[error("malformed PAX extended header for {}: {detail}", shown_path(.0), detail = .1)]
    MalformedPax(PathBuf, &'static str),
    #[error("malformed tar header for {}: {detail}", shown_path(.0), detail = .1)]
    MalformedHeader(PathBuf, &'static str),
    /// The tarball's bytes do not parse (a tar or gzip format error, a
    /// truncation). Its message can repeat text from the archive, so it is
    /// shown bounded and escaped, and the error is not this one's `source()`.
    #[error("malformed tarball ({context}): {}", shown(&.error.to_string()))]
    Malformed {
        context: &'static str,
        error: std::io::Error,
    },
    #[error("tarball hash mismatch: expected {expected}, got {actual}")]
    HashMismatch {
        expected: fuz_crypto::ContentHash,
        actual: fuz_crypto::ContentHash,
    },
    #[error("binary hash mismatch for {}: expected {expected}, got {actual}", shown(.name))]
    BinaryHashMismatch {
        name: String,
        expected: fuz_crypto::ContentHash,
        actual: fuz_crypto::ContentHash,
    },
    #[error("content hash mismatch: expected {}, got {}", shown(.expected), shown(.actual))]
    ContentHashMismatch { expected: String, actual: String },
    #[error("missing binary in tarball: {}", shown(.0))]
    MissingBinary(String),
    #[error("unexpected file in tarball: {}", shown_path(.0))]
    UnexpectedFile(PathBuf),
    #[error("tarball is empty")]
    Empty,
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// The tar or gzip layer failed outside a parse: writing a tarball, or
    /// reading one with an operating-system error. Its message can repeat text
    /// from the archive (an entry's path), so it is shown bounded and escaped,
    /// and the error is not this one's `source()`: a printer of the source
    /// chain would show it again, raw.
    #[error("tar error ({context}): {}", shown(&.error.to_string()))]
    Tar {
        context: &'static str,
        error: std::io::Error,
    },
}

/// A path from a tarball, for an error message: `shown`, over its lossy text.
fn shown_path(path: &std::path::Path) -> String {
    shown(&path.to_string_lossy())
}

impl TarballError {
    /// Returns user-facing hint for how to fix this error
    pub const fn hint(&self) -> Option<&'static str> {
        match self {
            Self::InvalidPath(_)
            | Self::UnsupportedEntryType(_)
            | Self::SetuidBit(_)
            | Self::SetgidBit(_)
            | Self::DirectoryWithBody(_, _)
            | Self::PaxSizeMismatch { .. }
            | Self::MalformedPax(_, _)
            | Self::MalformedHeader(_, _) => {
                Some("Tarball contains malicious content - do not install")
            }
            Self::NullByte(_) | Self::PathTooLong(_) | Self::Malformed { .. } => {
                Some("Tarball is malformed")
            }
            Self::FileTooLarge(_, _)
            | Self::TotalTooLarge(_)
            | Self::CompressionBomb(_)
            | Self::HeaderTooLarge(_) => Some("Tarball exceeds size limits - possible DoS attempt"),
            Self::HashMismatch { .. }
            | Self::BinaryHashMismatch { .. }
            | Self::ContentHashMismatch { .. } => {
                Some("Download corrupted or tampered - do not retry, re-bootstrap instead")
            }
            Self::MissingBinary(_) | Self::UnexpectedFile(_) | Self::Empty => {
                Some("Tarball contents don't match manifest")
            }
            Self::Io(_) | Self::Tar { .. } => None,
        }
    }

    /// Returns true if this error indicates a security violation (vs I/O failure).
    ///
    /// Exhaustive on purpose: a new variant must be classified explicitly rather
    /// than silently defaulting to non-violation (fail-open). The
    /// extraction-guard variants are kept in lockstep with
    /// `fuz_archive::ArchiveError::is_security_violation` — a malformed path,
    /// oversized entry, or bomb is hostile input, not a benign I/O hiccup — and
    /// so are bytes that do not parse, since the tarball reached extraction
    /// only after its blake3 matched the signed manifest. The hash- and
    /// manifest-mismatch variants are fuz_release-specific.
    pub const fn is_security_violation(&self) -> bool {
        match self {
            Self::InvalidPath(_)
            | Self::UnsupportedEntryType(_)
            | Self::NullByte(_)
            | Self::PathTooLong(_)
            | Self::FileTooLarge(_, _)
            | Self::TotalTooLarge(_)
            | Self::CompressionBomb(_)
            | Self::HeaderTooLarge(_)
            | Self::SetuidBit(_)
            | Self::SetgidBit(_)
            | Self::DirectoryWithBody(_, _)
            | Self::PaxSizeMismatch { .. }
            | Self::MalformedPax(_, _)
            | Self::MalformedHeader(_, _)
            | Self::Malformed { .. }
            | Self::HashMismatch { .. }
            | Self::BinaryHashMismatch { .. }
            | Self::ContentHashMismatch { .. } => true,
            // Content-vs-manifest mismatches and plain I/O are not, on their own,
            // evidence of hostile tarball bytes.
            Self::MissingBinary(_)
            | Self::UnexpectedFile(_)
            | Self::Empty
            | Self::Io(_)
            | Self::Tar { .. } => false,
        }
    }
}

/// Map `fuz_archive`'s extraction error onto the existing `TarballError`
/// surface, so factoring the streaming/guard core out to `fuz_archive` is
/// invisible to `fuz_release`'s callers (and tests): each shared guard keeps its
/// same-named variant.
impl From<fuz_archive::ArchiveError> for TarballError {
    fn from(e: fuz_archive::ArchiveError) -> Self {
        use fuz_archive::ArchiveError as A;
        match e {
            // fuz's flat placement can't escape root, but a placement escape
            // maps defensively to the invalid-path violation (same teaching
            // error + security classification) rather than adding a variant.
            A::InvalidPath(p) | A::PlacementEscapesRoot(p) => Self::InvalidPath(p),
            A::UnsupportedEntryType(p) => Self::UnsupportedEntryType(p),
            A::NullByte(p) => Self::NullByte(p),
            A::PathTooLong(p) => Self::PathTooLong(p),
            A::FileTooLarge(p, s) => Self::FileTooLarge(p, s),
            A::TotalTooLarge(s) => Self::TotalTooLarge(s),
            A::CompressionBomb(r) => Self::CompressionBomb(r),
            A::HeaderTooLarge(s) => Self::HeaderTooLarge(s),
            A::SetuidBit(p) => Self::SetuidBit(p),
            A::SetgidBit(p) => Self::SetgidBit(p),
            A::DirectoryWithBody(p, s) => Self::DirectoryWithBody(p, s),
            A::PaxSizeMismatch {
                path,
                header_size,
                pax_size,
            } => Self::PaxSizeMismatch {
                path,
                header_size,
                pax_size,
            },
            A::MalformedPax(p, detail) => Self::MalformedPax(p, detail),
            A::MalformedHeader(p, detail) => Self::MalformedHeader(p, detail),
            A::Malformed { context, source } => Self::Malformed {
                context,
                error: source,
            },
            A::Empty => Self::Empty,
            A::Io(e) => Self::Io(e),
            A::Read { context, source } => Self::Tar {
                context,
                error: source,
            },
        }
    }
}

/// Errors from recording a release in a release log checkout.
///
/// The release log is a git repository holding the signed `head.json`. A
/// producer records each release in a local checkout of it — extend the head,
/// sign it, commit, push — before the release is advertised, so every variant
/// here stops a publish short of its latest pointer. The write itself lives in
/// `fuz_sign` (the crate that holds the signing key); the error lives here so it
/// travels in [`ReleaseError`], the type the publish flows return.
#[derive(Debug, thiserror::Error)]
pub enum LogWriteError {
    /// A name, version, target, or binary name that is not a head token, so
    /// it is not used to build a path, a command argument, or a head.
    #[error("invalid release log entry {field}: {}", quoted(.value))]
    InvalidEntry { field: &'static str, value: String },
    #[error("release log checkout not found: {0}")]
    CheckoutMissing(PathBuf),
    #[error("not the root of a git work tree: {0}")]
    NotARepo(PathBuf),
    #[error("release log checkout has uncommitted changes: {paths}")]
    Dirty { paths: String },
    /// Git ignores a path the log write owns, so it cannot be committed.
    #[error("release log paths are ignored by git: {paths}")]
    Ignored { paths: String },
    #[error("release log checkout is not on a branch")]
    DetachedHead,
    #[error("release log branch {branch} has no upstream to push to")]
    NoUpstream { branch: String },
    #[error("release log branch {branch} has diverged from its upstream")]
    Diverged { branch: String },
    /// A path the log write owns is a symlink or some other non-regular entry.
    #[error("refusing {path}: not a plain {expected} in the release log checkout")]
    UnsafePath {
        path: PathBuf,
        expected: &'static str,
    },
    /// The checkout's work tree has no `head.json` while a commit — `held_by`
    /// says which — holds one. Read as a log with no head, the checkout would
    /// take a first head, written over the log's history.
    #[error("the release log checkout has no head.json in its work tree, but {held_by} holds one")]
    HeadMissing { held_by: &'static str },
    /// The `head.json` already in the checkout does not parse or verify. It is
    /// never overwritten.
    #[error("existing release log head is unusable: {0}")]
    ExistingHead(#[source] ReleaseLogError),
    #[error("{name} {version} {target} is already logged with a different {field}")]
    TargetConflict {
        name: String,
        version: String,
        target: String,
        field: TargetField,
    },
    #[error("{name} {version} is revoked and takes no further targets")]
    RevokedRow { name: String, version: String },
    #[error("release log seq is exhausted at {0}")]
    SeqExhausted(u64),
    /// The head this publish signed fails the checks a reader applies.
    #[error("the signed release log head does not verify: {0}")]
    SignedHead(#[source] ReleaseLogError),
    /// The head this publish signed breaks the append-only rules against the
    /// one it replaces.
    #[error("the signed release log head is not a successor of the logged one: {0}")]
    NotSuccessor(#[source] HeadViolation),
    #[error("the signed release log head does not advance the logged one")]
    NotAdvanced,
    /// `git` could not be run or exited non-zero. `output` is its bounded
    /// error output.
    #[error("git {command} failed in the release log checkout: {output}")]
    Git { command: String, output: String },
    #[error("release log push did not update the remote-tracking ref of {branch}")]
    PushUnconfirmed { branch: String },
    /// A plain `git push` on the branch would update something other than
    /// its upstream.
    #[error("a plain `git push` on release log branch {branch} would not update its upstream")]
    PushElsewhere { branch: String },
    /// The signing key is not one the publishing binary trusts, so no head it
    /// signs would verify.
    #[error("signing key {public_key} is not trusted by this binary")]
    UntrustedKey { public_key: String },
    /// The `head.json` in the pushed commit fails the checks a reader applies.
    #[error("the pushed release log head does not verify: {0}")]
    PublishedHead(#[source] ReleaseLogError),
    /// The push went through, but the pushed commit does not hold the entry.
    #[error("the pushed release log does not hold {name} {version} {target}: {detail}")]
    NotPublished {
        name: String,
        version: String,
        target: String,
        detail: &'static str,
    },
    /// The log has no head, so this publish would write its first — and
    /// storage already holds releases other than the one being published. A
    /// first head that left them out would be an incomplete log. `keys` is the
    /// manifest keys of those releases, one per line, already bounded and
    /// escaped.
    #[error("the release log has no head and storage already holds other releases:{keys}")]
    UnloggedReleases { keys: String },
    /// Storage could not be listed to find out whether a log with no head
    /// would be complete. The publish is refused, not waved through.
    #[error("could not list release storage for a release log with no head: {0}")]
    Storage(#[source] fuz_storage::StorageError),
    /// The push went through, but the pushed commit does not record the
    /// revocation.
    #[error("the pushed release log does not record the revocation of {name} {version}: {detail}")]
    NotRevoked {
        name: String,
        version: String,
        detail: &'static str,
    },
    #[error("release log I/O error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

impl LogWriteError {
    /// Returns user-facing hint for how to fix this error
    #[allow(clippy::missing_const_for_fn)] // calls non-const hint() methods
    pub fn hint(&self) -> Option<&'static str> {
        match self {
            Self::InvalidEntry { .. } => Some(
                "Names, versions, targets, and binary names are ASCII letters, digits, and \
                 . _ - starting with a letter or digit",
            ),
            Self::CheckoutMissing(_) | Self::NotARepo(_) => {
                Some("Pass the root of a clone of the release log repository")
            }
            Self::Dirty { .. } => Some(
                "Commit or discard the changes to head.json and latest/ in the log checkout, \
                 then re-run the same publish",
            ),
            Self::Ignored { .. } => Some(
                "Remove the ignore rule covering head.json or latest/ (.gitignore, \
                 .git/info/exclude, or core.excludesFile) and delete any ignored copy, \
                 then re-run the same publish",
            ),
            Self::DetachedHead => Some("Check out the log's branch in the log checkout"),
            Self::NoUpstream { .. } => Some(
                "Clone the log repository, or set the branch's upstream (git branch \
                 --set-upstream-to; where that refuses - no commit on the branch, or no \
                 such branch on the remote yet - git config branch.<name>.remote and \
                 branch.<name>.merge) - a release is advertised only after its log entry \
                 is pushed",
            ),
            Self::Diverged { .. } => Some(
                "If the local commits were never pushed, `git reset --hard @{upstream}` in the \
                 log checkout and re-run the same publish; never rewrite pushed history",
            ),
            Self::UnsafePath { .. } => {
                Some("The release log holds plain files; remove the link or special file")
            }
            Self::HeadMissing { .. } => Some(
                "The log has a head and this checkout's work tree does not. If a local commit \
                 removed head.json and was never pushed, `git reset --hard @{upstream}` in the \
                 log checkout; if the file is only missing from the work tree, clear any \
                 assume-unchanged or skip-worktree flag on it and `git checkout -- head.json`. \
                 Then run the same command again; never rewrite pushed history",
            ),
            // A head from before domain-separated signing: no revert reaches a
            // head this build verifies, since every one in the log's history
            // is format 1.
            Self::ExistingHead(ReleaseLogError::Signature(
                fuz_crypto::VerifyError::UnsupportedFormat(format),
            )) if *format < fuz_crypto::SIGNATURE_FORMAT_VERSION => Some(
                "The head.json in the log checkout is signed in a signature format this build \
                 no longer reads; no head this build signs can extend it. If `git log -p -- \
                 head.json` shows an earlier head in the current format, restore that one with a \
                 new commit instead. Otherwise republish (or prune) every release in storage, \
                 commit and push the removal of the log's head.json and latest/, recreate the \
                 log with `cargo xtask release-log backfill`, and run `cargo xtask release-log \
                 revoke` again for each release the old log revoked",
            ),
            Self::ExistingHead(_) => Some(
                "The head.json in the log checkout does not verify with this binary's trusted \
                 keys; it is never overwritten. If the last commit broke it, restore it with a \
                 new commit (git revert --no-edit HEAD) and re-run the same publish",
            ),
            Self::PublishedHead(_) => Some(
                "The pushed head.json does not verify - look for a hook that rewrites files in \
                 the log checkout, remove it, restore the head with a new commit (git revert \
                 --no-edit HEAD), and re-run the same publish",
            ),
            Self::SignedHead(e) => e.hint(),
            Self::TargetConflict { .. } => {
                Some("The log is append-only: publish a different build as a new version")
            }
            Self::RevokedRow { .. } => Some("Publish under a new version"),
            Self::NotSuccessor(_) | Self::NotAdvanced => {
                Some("Nothing was written to the log beyond the fast-forward")
            }
            Self::Git { .. } => Some(
                "Fix what git reports in the log checkout, then re-run the same publish - \
                 a commit that failed was rolled back, and one that was not pushed is \
                 pushed by the retry",
            ),
            Self::PushUnconfirmed { .. } => Some(
                "Check that a plain `git push` in the log checkout pushes the current branch \
                 to its upstream",
            ),
            Self::PushElsewhere { .. } => Some(
                "Check push.default, remote.pushDefault, branch.<name>.pushRemote, and any \
                 remote.<name>.push refspec in the log checkout (a refspec must name its \
                 destination, e.g. refs/heads/main:refs/heads/main), and that the local \
                 branch has the same name as its upstream",
            ),
            Self::UntrustedKey { .. } => Some(
                "The signing key must be one of the trusted keys built into this binary \
                 (crates/fuz_crypto/src/public_keys.json)",
            ),
            Self::NotPublished { .. } => Some(
                "Something kept the entry out of the pushed commit - look for a hook that \
                 rewrites files, or an assume-unchanged flag on head.json or latest/ in the \
                 log checkout",
            ),
            Self::UnloggedReleases { .. } => Some(
                "A log's first head must list every release. Create the log from the releases \
                 already in storage first - `cargo xtask release-log backfill --storage <uri> \
                 --log-repo <path>`, reviewed and then run with --wetrun - and re-run the same \
                 publish; nothing was written to the log",
            ),
            Self::Storage(e) => e.hint(),
            Self::NotRevoked { .. } => Some(
                "Something kept the revocation out of the pushed commit - look for a hook that \
                 rewrites files, or an assume-unchanged flag on head.json or latest/ in the \
                 log checkout",
            ),
            Self::SeqExhausted(_) | Self::Io { .. } => None,
        }
    }

    /// Returns true if this error indicates a security violation.
    ///
    /// Exhaustive on purpose. A head that fails its signature or the
    /// append-only rules is a violation — the wrapped [`ReleaseLogError`]
    /// decides for the variants that carry one — and so are a signing key the
    /// binary does not trust (the signature failure it would become) and a
    /// symlink where the log keeps a plain file. A checkout that is missing,
    /// dirty, behind, or unpushable is an operational failure, as is a pushed
    /// commit that lacks the entry or the revocation, and a conflicting or
    /// revoked entry is a publisher mistake. A first publish into a log with no
    /// head while storage holds other releases is a step taken out of order,
    /// and storage that cannot be listed is a storage fault.
    ///
    /// A checkout whose work tree lacks the head its commits hold is a
    /// violation. The cause may be an accident in the publisher's own clone,
    /// but what the refusal stops is not: a first head signed and pushed in
    /// place of the log's history — the head [`NotSuccessor`](Self::NotSuccessor)
    /// would refuse if the predecessor had been read — so it is classified
    /// with that one.
    pub const fn is_security_violation(&self) -> bool {
        match self {
            Self::ExistingHead(e) | Self::SignedHead(e) | Self::PublishedHead(e) => {
                e.is_security_violation()
            }
            Self::NotSuccessor(_)
            | Self::NotAdvanced
            | Self::UnsafePath { .. }
            | Self::HeadMissing { .. }
            | Self::UntrustedKey { .. } => true,
            Self::InvalidEntry { .. }
            | Self::CheckoutMissing(_)
            | Self::NotARepo(_)
            | Self::Dirty { .. }
            | Self::Ignored { .. }
            | Self::DetachedHead
            | Self::NoUpstream { .. }
            | Self::Diverged { .. }
            | Self::TargetConflict { .. }
            | Self::RevokedRow { .. }
            | Self::SeqExhausted(_)
            | Self::Git { .. }
            | Self::PushUnconfirmed { .. }
            | Self::PushElsewhere { .. }
            | Self::NotPublished { .. }
            | Self::UnloggedReleases { .. }
            | Self::Storage(_)
            | Self::NotRevoked { .. }
            | Self::Io { .. } => false,
        }
    }
}

/// Top-level error for release operations.
/// Wraps domain-specific errors for CLI/caller convenience.
#[derive(Debug, thiserror::Error)]
pub enum ReleaseError {
    #[error("manifest error: {0}")]
    Manifest(#[from] ManifestError),
    #[error("tarball error: {0}")]
    Tarball(#[from] TarballError),
    #[error("release log error: {0}")]
    ReleaseLog(#[from] ReleaseLogError),
    #[error("release log write failed: {0}")]
    LogWrite(#[from] LogWriteError),
    #[error("artifact error: {0}")]
    Artifact(#[from] fuz_artifact::ArtifactError),
    #[error("storage error: {0}")]
    Storage(#[from] fuz_storage::StorageError),
    #[error("home error: {0}")]
    FuzHome(#[from] fuz_home::FuzHomeError),
    /// A fetched tool manifest's `tool` field doesn't match the requested name.
    #[error(
        "tool manifest mismatch: requested {}, manifest declares {}",
        shown(.expected),
        actual.as_deref().map_or_else(|| "<self>".to_string(), shown)
    )]
    ToolManifestMismatch {
        expected: String,
        actual: Option<String>,
    },
    /// No install record for the requested tool.
    #[error("tool not installed: {0}")]
    ToolNotInstalled(String),
    /// The stream has no version pointer for this client's target
    /// (`latest-<target>.json`): nothing is published for it at this store,
    /// whatever is published for other targets. `tool` is the tool's name, or
    /// `None` for the fuz self artifact.
    #[error(
        "no release of {} is published for {target}: {} not found",
        tool.as_deref().map_or_else(|| "fuz".to_string(), shown),
        shown(.key)
    )]
    NoReleaseForTarget {
        tool: Option<String>,
        target: String,
        key: String,
    },
    /// Consumer side: a verified release labelled for this client's target
    /// carries a binary whose header says it is not for it (or is no
    /// executable at all). The signature vouches that the publisher signed the
    /// bytes, not that the label is right; installed, the binary could not
    /// run — and a self artifact would leave no working `fuz` to roll back
    /// with. Refused before anything is installed.
    #[error("{error}")]
    MislabelledBinary {
        /// This client's target, which the manifest is labelled with.
        target: fuz_artifact::platform::ReleaseTarget,
        /// [`fuz_artifact::ArtifactError::BinaryPlatform`] or
        /// [`fuz_artifact::ArtifactError::BinaryUnreadable`], naming the
        /// binary.
        error: fuz_artifact::ArtifactError,
    },
    /// The currently-installed version couldn't be read (a dangling `current`
    /// link or a corrupt `meta.json`), and `--force` was not given. Refused
    /// rather than silently reinstalling over an unknown state.
    #[error("current install is unreadable: {reason}")]
    CurrentUnreadable {
        /// Why the current install couldn't be read.
        reason: String,
    },
}

impl ReleaseError {
    /// Returns user-facing hint for how to fix this error.
    ///
    /// A `Cow` so the `ArtifactError` arm can carry its interpolated `Owned`
    /// hint; the static-leaf siblings lift theirs with `Cow::Borrowed`.
    pub fn hint(&self) -> Option<Cow<'static, str>> {
        match self {
            Self::Manifest(e) => e.hint().map(Cow::Borrowed),
            Self::Tarball(e) => e.hint().map(Cow::Borrowed),
            Self::ReleaseLog(e) => e.hint().map(Cow::Borrowed),
            Self::LogWrite(e) => e.hint().map(Cow::Borrowed),
            Self::Artifact(e) => e.hint(),
            Self::Storage(e) => e.hint().map(Cow::Borrowed),
            Self::FuzHome(e) => e.hint().map(Cow::Borrowed),
            Self::ToolManifestMismatch { .. } => Some(Cow::Borrowed(
                "the published manifest doesn't match the tool name - do not install",
            )),
            Self::ToolNotInstalled(_) => Some(Cow::Borrowed("run 'fuz tool install <name>' first")),
            Self::CurrentUnreadable { .. } => Some(Cow::Borrowed(
                "re-run with --force to reinstall over the unreadable state, or re-bootstrap",
            )),
            Self::NoReleaseForTarget { tool, target, .. } => {
                Some(Cow::Owned(tool.as_deref().map_or_else(
                    || format!("no release published for {target}; publish one"),
                    |tool| {
                        format!(
                            "no release published for {target}; publish one, or install a \
                             published version with `fuz tool install {} --version <version>`",
                            shown(tool)
                        )
                    },
                )))
            }
            Self::MislabelledBinary { target, .. } => Some(Cow::Owned(format!(
                "this release's binaries are not for {target}: the signature is valid but the \
                 label is wrong; report it to the publisher, don't retry"
            ))),
        }
    }

    /// Returns true if this error indicates a security violation.
    ///
    /// The enum-level counterpart to [`TarballError::is_security_violation`],
    /// classified with the same fail-closed discipline: every arm is decided
    /// explicitly, and wrapped errors delegate to their own classifiers.
    #[allow(clippy::missing_const_for_fn)] // Calls non-const methods
    pub fn is_security_violation(&self) -> bool {
        match self {
            Self::Tarball(e) => e.is_security_violation(),
            Self::ReleaseLog(e) => e.is_security_violation(),
            Self::LogWrite(e) => e.is_security_violation(),
            // A content hash or binary name shaped like a path is hostile input
            // that would name a location outside the store, the manifest twin of
            // `TarballError::InvalidPath`. A tool binary named for a self binary
            // names a link that is another artifact's, and classifies with them.
            // A manifest at another release's key is a substitution, as a tool
            // manifest under another tool's name is.
            // Every arm is named, so a new variant is classified where it is
            // added.
            Self::Manifest(e) => match e {
                ManifestError::Signature(_)
                | ManifestError::KeyMismatch { .. }
                | ManifestError::TarballMismatch { .. }
                | ManifestError::InvalidTarballPath(_)
                | ManifestError::InvalidContentHash(_)
                | ManifestError::InvalidBinaryName(_)
                | ManifestError::ReservedBinaryName { .. } => true,
                ManifestError::UnsupportedFormat(_)
                | ManifestError::TooLarge(_)
                | ManifestError::Parse(_)
                | ManifestError::TarballTooLarge(_)
                | ManifestError::TargetMismatch { .. }
                | ManifestError::BelowMinimum { .. }
                | ManifestError::Downgrade { .. }
                | ManifestError::InvalidVersion(_)
                | ManifestError::MissingBinary(_)
                | ManifestError::UnexpectedBinary(_)
                | ManifestError::ToolNotAllowed(_)
                | ManifestError::UnexpectedTool(_)
                | ManifestError::EmptyBinaries(_)
                | ManifestError::TestBinaryRejected { .. }
                | ManifestError::UnpublishableField { .. }
                | ManifestError::UnpublishableVersion { .. }
                | ManifestError::UnsupportedTarget(_)
                | ManifestError::Canonical(_) => false,
            },
            // A world-writable `~/.fuz` is a *refusal on security grounds*, not
            // a path lookup that happened to fail — the read/write/rename and
            // schema arms are the benign ones.
            Self::FuzHome(e) => match e {
                fuz_home::FuzHomeError::InsecureHome { .. } => true,
                fuz_home::FuzHomeError::HomeDir(_)
                | fuz_home::FuzHomeError::RelativeFuzHome { .. }
                | fuz_home::FuzHomeError::CreateDirFailed { .. }
                | fuz_home::FuzHomeError::ReadFailed { .. }
                | fuz_home::FuzHomeError::WriteFailed { .. }
                | fuz_home::FuzHomeError::DeleteFailed { .. }
                | fuz_home::FuzHomeError::RenameFailed { .. }
                | fuz_home::FuzHomeError::SerializeFailed(_)
                | fuz_home::FuzHomeError::DaemonInfoVersionMismatch { .. }
                | fuz_home::FuzHomeError::DaemonInfoInvalidPid(_)
                | fuz_home::FuzHomeError::InvalidToolName { .. } => false,
            },
            // A tool binary named for a self binary, or with a name that is not
            // a release token, reaches the store from a manifest's declared
            // set, and classifies as it does where the manifest refuses it
            // (`ManifestError::ReservedBinaryName` / `InvalidBinaryName`). The
            // store's integrity refusals — a binary that no longer hashes to
            // its meta, a symlink where an install directory or a file inside
            // one belongs — are same-uid corruption of a `0700` tree, not
            // hostile bytes from a release host, and stay benign with the rest.
            Self::Artifact(e) => matches!(
                e,
                fuz_artifact::ArtifactError::ReservedBinaryName { .. }
                    | fuz_artifact::ArtifactError::InvalidBinaryName { .. }
            ),
            // A mislabelled binary is signed bytes whose label is wrong: a
            // publisher's mistake the signature cannot catch, not bytes to
            // distrust. The release is refused (exit 1), and the hint sends it
            // back to the publisher.
            Self::Storage(_)
            | Self::ToolNotInstalled(_)
            | Self::CurrentUnreadable { .. }
            | Self::NoReleaseForTarget { .. }
            | Self::MislabelledBinary { .. } => false,
            // A manifest claiming to be a different tool than requested is a
            // provenance violation, not a benign mismatch.
            Self::ToolManifestMismatch { .. } => true,
        }
    }

    /// Returns true if the release could not be confirmed against the release
    /// log — a "try again later", not a verdict (see
    /// [`ReleaseLogError::is_unconfirmed`]).
    ///
    /// Exhaustive, and the release log arm forwards: this level decides
    /// nothing itself.
    pub const fn is_unconfirmed(&self) -> bool {
        match self {
            Self::ReleaseLog(e) => e.is_unconfirmed(),
            Self::Manifest(_)
            | Self::Tarball(_)
            | Self::LogWrite(_)
            | Self::Artifact(_)
            | Self::Storage(_)
            | Self::FuzHome(_)
            | Self::ToolManifestMismatch { .. }
            | Self::ToolNotInstalled(_)
            | Self::CurrentUnreadable { .. }
            | Self::NoReleaseForTarget { .. }
            | Self::MislabelledBinary { .. } => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn io() -> std::io::Error {
        std::io::Error::other("disk")
    }

    fn violation() -> HeadViolation {
        HeadViolation::SeqReused { seq: 3 }
    }

    /// Text that tries to clear the line, return to its start, reverse what
    /// follows, hide a character, close a quote, forge an escape, and add a
    /// line.
    const HOSTILE: &str = "x\u{1b}[2K\r\u{202e}\u{2800}\"\\n\nhint: y";
    /// [`HOSTILE`] as a message shows it, unquoted.
    const SHOWN: &str = "x\\u{1b}[2K\\r\\u{202e}\\u{2800}\"\\\\n\\nhint: y";
    /// [`HOSTILE`] as a message shows it in quotes.
    const QUOTED: &str = "\"x\\u{1b}[2K\\r\\u{202e}\\u{2800}\\\"\\\\n\\nhint: y\"";

    /// A manifest is read before its signature is checked: every string one of
    /// its errors carries is escaped in the message, once.
    #[test]
    fn a_manifest_error_escapes_every_string_it_carries_once() {
        let text = || HOSTILE.to_string();
        let cases = [
            (
                ManifestError::InvalidTarballPath(text()),
                format!("invalid tarball path: {SHOWN}"),
            ),
            (
                ManifestError::InvalidContentHash(text()),
                format!(
                    "invalid content hash in manifest: {QUOTED} (expected `v1-` and 64 lowercase \
                     hex)"
                ),
            ),
            (
                ManifestError::InvalidBinaryName(text()),
                format!(
                    "invalid binary name in manifest: {QUOTED} (must be A-Za-z0-9._-, starting with a letter or digit)"
                ),
            ),
            (
                ManifestError::TargetMismatch {
                    expected: "x86_64-unknown-linux-gnu".to_string(),
                    actual: text(),
                },
                format!("target mismatch: expected x86_64-unknown-linux-gnu, got {SHOWN}"),
            ),
            (
                ManifestError::BelowMinimum {
                    current: text(),
                    minimum: text(),
                    tool: false,
                },
                format!("version below minimum: {SHOWN} < {SHOWN}"),
            ),
            (
                ManifestError::Downgrade {
                    current: text(),
                    target: text(),
                },
                format!("downgrade not allowed: {SHOWN} -> {SHOWN}"),
            ),
            (
                ManifestError::InvalidVersion(text()),
                format!("invalid version string: {SHOWN}"),
            ),
            (
                ManifestError::UnexpectedBinary(text()),
                format!("self artifact manifest declares a binary it does not ship: {SHOWN}"),
            ),
            (
                ManifestError::ToolNotAllowed(text()),
                format!("tool not in first-party allowlist: {SHOWN}"),
            ),
            (
                ManifestError::UnexpectedTool(text()),
                format!("self artifact manifest must not declare a tool (found `{SHOWN}`)"),
            ),
            (
                ManifestError::EmptyBinaries(text()),
                format!("tool manifest declares no binaries: {SHOWN}"),
            ),
            (
                ManifestError::TestBinaryRejected { name: text() },
                format!(
                    "test binary in manifest: {SHOWN} (test binaries must never ship in releases)"
                ),
            ),
            (
                ManifestError::ReservedBinaryName {
                    tool: text(),
                    binary: text(),
                },
                format!(
                    "tool manifest for {SHOWN} declares the binary {SHOWN}, which belongs to the \
                     fuz self artifact"
                ),
            ),
            (
                ManifestError::UnpublishableVersion {
                    field: "minimum_version",
                    value: text(),
                    reason: text(),
                },
                format!("release minimum_version cannot be published: {QUOTED} ({SHOWN})"),
            ),
            (
                ManifestError::TarballMismatch {
                    key: text(),
                    expected: text(),
                    actual: text(),
                },
                format!(
                    "the manifest at {SHOWN} names the tarball {QUOTED}, not {SHOWN}, the one its \
                     release is stored as"
                ),
            ),
            (
                ManifestError::KeyMismatch {
                    key: text(),
                    version: text(),
                    target: text(),
                },
                format!(
                    "the manifest at {SHOWN} is {SHOWN} for {SHOWN}, not the release its key names"
                ),
            ),
        ];
        for (error, expected) in cases {
            assert_eq!(error.to_string(), expected);
            // Under the wrapper every command prints it through, too.
            assert_eq!(
                ReleaseError::Manifest(error).to_string(),
                format!("manifest error: {expected}")
            );
        }
    }

    /// A tool manifest mismatch shows both names escaped, as the manifest
    /// errors do, and a self manifest as `<self>`.
    #[test]
    fn a_tool_manifest_mismatch_escapes_both_names() {
        assert_eq!(
            ReleaseError::ToolManifestMismatch {
                expected: HOSTILE.to_string(),
                actual: Some(HOSTILE.to_string()),
            }
            .to_string(),
            format!("tool manifest mismatch: requested {SHOWN}, manifest declares {SHOWN}")
        );
        assert_eq!(
            ReleaseError::ToolManifestMismatch {
                expected: "fuzf".to_string(),
                actual: None,
            }
            .to_string(),
            "tool manifest mismatch: requested fuzf, manifest declares <self>"
        );
    }

    /// A string of any length is cut before it is escaped: the message is
    /// bounded, and an ordinary value reads as it is.
    #[test]
    fn a_manifest_error_bounds_the_strings_it_carries() {
        let long = "\u{1b}".repeat(1_000_000);
        for error in [
            ManifestError::InvalidTarballPath(long.clone()),
            ManifestError::InvalidContentHash(long.clone()),
            ManifestError::InvalidBinaryName(long.clone()),
            ManifestError::InvalidVersion(long.clone()),
            ManifestError::ToolNotAllowed(long.clone()),
            ManifestError::UnexpectedBinary(long.clone()),
            ManifestError::TestBinaryRejected { name: long.clone() },
            ManifestError::TargetMismatch {
                expected: "t".to_string(),
                actual: long,
            },
        ] {
            let message = error.to_string();
            assert!(message.len() < 1024, "{} bytes", message.len());
            assert!(message.contains("\\u{1b}..."), "{message}");
            assert!(!message.contains('\u{1b}'), "{message}");
        }
        assert_eq!(
            ManifestError::InvalidVersion("1.0".to_string()).to_string(),
            "invalid version string: 1.0"
        );
        assert_eq!(
            ManifestError::ToolNotAllowed("rando".to_string()).to_string(),
            "tool not in first-party allowlist: rando"
        );
    }

    /// The bound holds for the strings that test does not name, each on its
    /// own: a manifest's `tool` is read before its signature too.
    #[test]
    fn every_other_manifest_error_string_is_bounded() {
        let long = "\u{1b}".repeat(1_000_000);
        let short = || "1.0.0".to_string();
        for error in [
            ManifestError::UnexpectedTool(long.clone()),
            ManifestError::EmptyBinaries(long.clone()),
            ManifestError::ReservedBinaryName {
                tool: long.clone(),
                binary: short(),
            },
            ManifestError::ReservedBinaryName {
                tool: short(),
                binary: long.clone(),
            },
            ManifestError::BelowMinimum {
                current: long.clone(),
                minimum: short(),
                tool: false,
            },
            ManifestError::BelowMinimum {
                current: short(),
                minimum: long.clone(),
                tool: false,
            },
            ManifestError::Downgrade {
                current: long.clone(),
                target: short(),
            },
            ManifestError::Downgrade {
                current: short(),
                target: long.clone(),
            },
            ManifestError::UnpublishableVersion {
                field: "version",
                value: long.clone(),
                reason: short(),
            },
            ManifestError::UnpublishableVersion {
                field: "version",
                value: short(),
                reason: long.clone(),
            },
            ManifestError::TarballMismatch {
                key: long.clone(),
                expected: short(),
                actual: short(),
            },
            ManifestError::TarballMismatch {
                key: short(),
                expected: long.clone(),
                actual: short(),
            },
            ManifestError::TarballMismatch {
                key: short(),
                expected: short(),
                actual: long.clone(),
            },
            ManifestError::KeyMismatch {
                key: long.clone(),
                version: short(),
                target: short(),
            },
            ManifestError::KeyMismatch {
                key: short(),
                version: long.clone(),
                target: short(),
            },
            ManifestError::KeyMismatch {
                key: short(),
                version: short(),
                target: long,
            },
        ] {
            let message = error.to_string();
            assert!(message.len() < 1024, "{} bytes", message.len());
            assert!(message.contains("\\u{1b}..."), "{message}");
            assert!(!message.contains('\u{1b}'), "{message}");
        }
    }

    /// A tarball entry's path is as long as its headers allow, and the refusal
    /// of an overlong one carries it: every path and name is bounded.
    #[test]
    fn a_tarball_error_bounds_the_paths_and_names_it_carries() {
        let long = "\u{1b}".repeat(1_000_000);
        let path = || PathBuf::from(&long);
        let hash = fuz_crypto::ContentHash::blake3(b"x");
        for error in [
            TarballError::InvalidPath(path()),
            TarballError::UnsupportedEntryType(path()),
            TarballError::NullByte(path()),
            TarballError::PathTooLong(path()),
            TarballError::FileTooLarge(path(), 7),
            TarballError::SetuidBit(path()),
            TarballError::SetgidBit(path()),
            TarballError::DirectoryWithBody(path(), 7),
            TarballError::PaxSizeMismatch {
                path: path(),
                header_size: 7,
                pax_size: 8,
            },
            TarballError::MalformedPax(path(), "a key is repeated"),
            TarballError::MalformedHeader(path(), "the entry's path is empty"),
            TarballError::UnexpectedFile(path()),
            TarballError::MissingBinary(long.clone()),
            TarballError::BinaryHashMismatch {
                name: long.clone(),
                expected: hash.clone(),
                actual: hash,
            },
            TarballError::ContentHashMismatch {
                expected: long.clone(),
                actual: "v1-x".to_string(),
            },
            TarballError::ContentHashMismatch {
                expected: "v1-x".to_string(),
                actual: long.clone(),
            },
        ] {
            let message = error.to_string();
            assert!(message.len() < 1200, "{} bytes", message.len());
            assert!(message.contains("\\u{1b}..."), "{message}");
            assert!(!message.contains('\u{1b}'), "{message}");
        }
    }

    /// A manifest that does not parse repeats a token of the document in the
    /// parser's message: bounded, escaped once, and with its position kept.
    #[test]
    fn a_manifest_parse_error_is_bounded_and_escaped_once() {
        let field = format!("f\u{1b}[2K\\\u{2800}{}", "n".repeat(1_000_000));
        let document = serde_json::to_vec(&serde_json::json!({ field.as_str(): 1 })).unwrap();
        let error =
            ManifestError::from(serde_json::from_slice::<crate::Manifest>(&document).unwrap_err());
        let message = error.to_string();
        // kept as text, not a source: the chain a CLI prints shows it once
        assert!(std::error::Error::source(&error).is_none());
        assert!(
            message.starts_with(
                "failed to parse manifest: unknown field `f\\u{1b}[2K\\\\\\u{2800}nnn"
            ),
            "{}",
            &message[..message.len().min(200)]
        );
        assert!(
            message.contains("... at line 1 column "),
            "{}",
            message.len()
        );
        assert!(message.len() < 1024, "{} bytes", message.len());
        assert_eq!(
            fuz_sys::cli::format_error_chain(&ReleaseError::from(error)),
            format!("manifest error: {message}")
        );
    }

    /// A tar-layer error's own message repeats text from the archive (an
    /// entry's path, a header field), so it is cut and escaped like every
    /// other value from one: a long message is bounded, with the cut made
    /// before the escape, and the context the caller chose is shown whole.
    #[test]
    fn a_tar_error_cuts_and_escapes_its_source_message() {
        let tar = |message: String| TarballError::Tar {
            context: "reading entry",
            error: std::io::Error::other(message),
        };
        assert_eq!(
            tar(HOSTILE.to_string()).to_string(),
            format!("tar error (reading entry): {SHOWN}")
        );
        // not a source: the chain a CLI prints shows it once, escaped
        let wrapped = ReleaseError::from(tar(HOSTILE.to_string()));
        assert_eq!(
            fuz_sys::cli::format_error_chain(&wrapped),
            format!("tarball error: tar error (reading entry): {SHOWN}")
        );

        let long = tar("\u{1b}".repeat(4096)).to_string();
        let shown_part = long
            .strip_prefix("tar error (reading entry): ")
            .expect("names the context");
        assert!(shown_part.ends_with("..."), "{}", shown_part.len());
        let escapes = shown_part.trim_end_matches("...");
        assert!(
            !escapes.is_empty() && escapes.len() % "\\u{1b}".len() == 0,
            "an escape was cut in half: {} bytes",
            escapes.len()
        );
        assert_eq!(escapes.replace("\\u{1b}", ""), "");
        assert!(escapes.len() / "\\u{1b}".len() < 4096, "not cut");

        // A message that fits is shown whole.
        assert_eq!(
            tar("unexpected end of archive".to_string()).to_string(),
            "tar error (reading entry): unexpected end of archive"
        );
    }

    /// A tarball's entry paths and a manifest's binary names are shown the
    /// same way.
    #[test]
    fn a_tarball_error_escapes_the_paths_and_names_it_carries() {
        let path = || PathBuf::from(HOSTILE);
        let cases = [
            (
                TarballError::InvalidPath(path()),
                format!("invalid path in tarball: {SHOWN}"),
            ),
            (
                TarballError::UnsupportedEntryType(path()),
                format!("unsupported entry type in tarball: {SHOWN} (only regular files allowed)"),
            ),
            (
                TarballError::NullByte(path()),
                format!("null byte in path: {SHOWN}"),
            ),
            (
                TarballError::PathTooLong(path()),
                format!("path too long: {SHOWN}"),
            ),
            (
                TarballError::FileTooLarge(path(), 7),
                format!("file too large: {SHOWN} (7 bytes, max {MAX_FILE_SIZE})"),
            ),
            (
                TarballError::SetuidBit(path()),
                format!("setuid bit on file: {SHOWN}"),
            ),
            (
                TarballError::SetgidBit(path()),
                format!("setgid bit on file: {SHOWN}"),
            ),
            (
                TarballError::UnexpectedFile(path()),
                format!("unexpected file in tarball: {SHOWN}"),
            ),
            (
                TarballError::MissingBinary(HOSTILE.to_string()),
                format!("missing binary in tarball: {SHOWN}"),
            ),
            (
                TarballError::ContentHashMismatch {
                    expected: HOSTILE.to_string(),
                    actual: HOSTILE.to_string(),
                },
                format!("content hash mismatch: expected {SHOWN}, got {SHOWN}"),
            ),
        ];
        for (error, expected) in cases {
            assert_eq!(error.to_string(), expected);
        }
        let hash = fuz_crypto::ContentHash::blake3(b"x");
        assert_eq!(
            TarballError::BinaryHashMismatch {
                name: HOSTILE.to_string(),
                expected: hash.clone(),
                actual: hash.clone(),
            }
            .to_string(),
            format!("binary hash mismatch for {SHOWN}: expected {hash}, got {hash}")
        );
    }

    #[test]
    fn an_invalid_entry_shows_its_value_quoted_and_escaped() {
        let error = LogWriteError::InvalidEntry {
            field: "name",
            value: "fuz\u{2800}\u{202e}\"x".to_string(),
        };
        assert_eq!(
            error.to_string(),
            "invalid release log entry name: \"fuz\\u{2800}\\u{202e}\\\"x\""
        );
    }

    /// One of every [`LogWriteError`] shape, with whether it is a security
    /// violation. The variants that wrap a [`ReleaseLogError`] appear once
    /// with an inner error that is a violation and once with one that is not.
    fn log_write_table() -> Vec<(LogWriteError, bool)> {
        let unsigned = || ReleaseLogError::Signature(fuz_crypto::VerifyError::InvalidSignature);
        let malformed = || ReleaseLogError::UnsupportedFormat(2);
        let table = vec![
            (
                LogWriteError::InvalidEntry {
                    field: "name",
                    value: "../x".to_string(),
                },
                false,
            ),
            (LogWriteError::CheckoutMissing(PathBuf::from("/log")), false),
            (LogWriteError::NotARepo(PathBuf::from("/log")), false),
            (
                LogWriteError::Dirty {
                    paths: "M head.json".to_string(),
                },
                false,
            ),
            (
                LogWriteError::Ignored {
                    paths: "!! head.json".to_string(),
                },
                false,
            ),
            (LogWriteError::DetachedHead, false),
            (
                LogWriteError::NoUpstream {
                    branch: "main".to_string(),
                },
                false,
            ),
            (
                LogWriteError::Diverged {
                    branch: "main".to_string(),
                },
                false,
            ),
            (
                LogWriteError::UnsafePath {
                    path: PathBuf::from("/log/head.json"),
                    expected: "file",
                },
                true,
            ),
            (
                LogWriteError::HeadMissing {
                    held_by: "its upstream",
                },
                true,
            ),
            (LogWriteError::ExistingHead(unsigned()), true),
            (LogWriteError::ExistingHead(malformed()), false),
            (
                LogWriteError::ExistingHead(ReleaseLogError::Violation(violation())),
                true,
            ),
            (
                LogWriteError::TargetConflict {
                    name: "fuz".to_string(),
                    version: "0.1.0".to_string(),
                    target: "x86_64-unknown-linux-gnu".to_string(),
                    field: TargetField::ContentHash,
                },
                false,
            ),
            (
                LogWriteError::RevokedRow {
                    name: "fuz".to_string(),
                    version: "0.1.0".to_string(),
                },
                false,
            ),
            (LogWriteError::SeqExhausted(crate::MAX_HEAD_SEQ), false),
            (LogWriteError::SignedHead(unsigned()), true),
            (LogWriteError::SignedHead(malformed()), false),
            (
                LogWriteError::PushElsewhere {
                    branch: "main".to_string(),
                },
                false,
            ),
            (
                LogWriteError::UntrustedKey {
                    public_key: "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik=".to_string(),
                },
                true,
            ),
            (LogWriteError::PublishedHead(unsigned()), true),
            (LogWriteError::PublishedHead(malformed()), false),
            (
                LogWriteError::NotPublished {
                    name: "fuz".to_string(),
                    version: "0.1.0".to_string(),
                    target: "x86_64-unknown-linux-gnu".to_string(),
                    detail: "the pushed commit has no head.json",
                },
                false,
            ),
            (LogWriteError::NotSuccessor(violation()), true),
            (LogWriteError::NotAdvanced, true),
            (
                LogWriteError::Git {
                    command: "push".to_string(),
                    output: "rejected".to_string(),
                },
                false,
            ),
            (
                LogWriteError::PushUnconfirmed {
                    branch: "main".to_string(),
                },
                false,
            ),
            (
                LogWriteError::UnloggedReleases {
                    keys: "\n  fuz-0.1.0-x86_64-unknown-linux-gnu.manifest.json".to_string(),
                },
                false,
            ),
            (
                LogWriteError::Storage(fuz_storage::StorageError::PermissionDenied {
                    backend: fuz_storage::StorageBackendKind::File,
                    path: "releases".to_string(),
                }),
                false,
            ),
            (
                LogWriteError::NotRevoked {
                    name: "fuz".to_string(),
                    version: "0.1.0".to_string(),
                    detail: "the pushed head.json does not record the release as revoked",
                },
                false,
            ),
            (
                LogWriteError::Io {
                    path: PathBuf::from("/log/head.json"),
                    source: io(),
                },
                false,
            ),
        ];
        // Compile-time tripwire: a new variant fails to build here until it is
        // added to the table above.
        for (error, _) in &table {
            match error {
                LogWriteError::InvalidEntry { .. }
                | LogWriteError::CheckoutMissing(_)
                | LogWriteError::NotARepo(_)
                | LogWriteError::Dirty { .. }
                | LogWriteError::Ignored { .. }
                | LogWriteError::DetachedHead
                | LogWriteError::NoUpstream { .. }
                | LogWriteError::Diverged { .. }
                | LogWriteError::UnsafePath { .. }
                | LogWriteError::HeadMissing { .. }
                | LogWriteError::ExistingHead(_)
                | LogWriteError::TargetConflict { .. }
                | LogWriteError::RevokedRow { .. }
                | LogWriteError::SeqExhausted(_)
                | LogWriteError::SignedHead(_)
                | LogWriteError::NotSuccessor(_)
                | LogWriteError::NotAdvanced
                | LogWriteError::Git { .. }
                | LogWriteError::PushUnconfirmed { .. }
                | LogWriteError::PushElsewhere { .. }
                | LogWriteError::UntrustedKey { .. }
                | LogWriteError::PublishedHead(_)
                | LogWriteError::NotPublished { .. }
                | LogWriteError::UnloggedReleases { .. }
                | LogWriteError::Storage(_)
                | LogWriteError::NotRevoked { .. }
                | LogWriteError::Io { .. } => {}
            }
        }
        table
    }

    #[test]
    fn log_write_classification_holds_at_every_wrapper_level() {
        for (error, expected) in log_write_table() {
            let description = error.to_string();
            assert_eq!(
                error.is_security_violation(),
                expected,
                "LogWriteError: {description}"
            );
            // The wrapper forwards; it never re-decides.
            let wrapped = ReleaseError::from(error);
            assert_eq!(
                wrapped.is_security_violation(),
                expected,
                "ReleaseError: {description}"
            );
        }
    }

    #[test]
    fn log_write_wrapped_head_errors_classify_as_their_source() {
        // Whatever the head error decides, every wrapping variant reports. Only
        // the head this publish signed forwards the source's hint; the two
        // heads read from the log say what a publisher does about them.
        let sources: [fn() -> ReleaseLogError; 4] = [
            || ReleaseLogError::TooLarge(1),
            || ReleaseLogError::UnsupportedFormat(2),
            || ReleaseLogError::Signature(fuz_crypto::VerifyError::InvalidPublicKey),
            || ReleaseLogError::Violation(violation()),
        ];
        for source in sources {
            let expected = source().is_security_violation();
            let hint = source().hint();
            for wrap in [
                LogWriteError::ExistingHead,
                LogWriteError::SignedHead,
                LogWriteError::PublishedHead,
            ] {
                let wrapped = wrap(source());
                assert_eq!(wrapped.is_security_violation(), expected, "{wrapped}");
            }
            assert_eq!(LogWriteError::SignedHead(source()).hint(), hint);
            let existing = LogWriteError::ExistingHead(source())
                .hint()
                .unwrap_or_default();
            assert!(existing.contains("never overwritten"), "{existing}");
            assert!(existing.contains("git revert --no-edit HEAD"), "{existing}");
            let published = LogWriteError::PublishedHead(source())
                .hint()
                .unwrap_or_default();
            assert!(published.contains("pushed head.json"), "{published}");
            assert!(
                published.contains("git revert --no-edit HEAD"),
                "{published}"
            );
        }
    }

    #[test]
    fn log_write_hints_are_forwarded_unchanged() {
        for (error, _) in log_write_table() {
            let description = error.to_string();
            let hint = error.hint();
            // Every failure a publisher can act on says how; the two that
            // leave nothing to do say nothing.
            let silent = matches!(
                error,
                LogWriteError::SeqExhausted(_) | LogWriteError::Io { .. }
            );
            assert_eq!(hint.is_none(), silent, "hint for: {description}");
            let wrapped = ReleaseError::from(error);
            assert_eq!(
                wrapped.hint().as_deref(),
                hint,
                "wrapper hint differs for: {description}"
            );
        }
    }

    #[test]
    fn log_write_messages_name_what_failed() {
        assert_eq!(
            LogWriteError::TargetConflict {
                name: "fuz".to_string(),
                version: "0.1.0".to_string(),
                target: "x86_64-unknown-linux-gnu".to_string(),
                field: TargetField::Sha512,
            }
            .to_string(),
            "fuz 0.1.0 x86_64-unknown-linux-gnu is already logged with a different sha512"
        );
        // The refusal of a first head that would be incomplete names the
        // backfill, with both of its required flags.
        let unlogged = LogWriteError::UnloggedReleases {
            keys: "\n  fuz-0.1.0-x86_64-unknown-linux-gnu.manifest.json".to_string(),
        };
        assert_eq!(
            unlogged.to_string(),
            "the release log has no head and storage already holds other releases:\n  \
             fuz-0.1.0-x86_64-unknown-linux-gnu.manifest.json"
        );
        let hint = unlogged.hint().unwrap_or_default();
        for expected in [
            "cargo xtask release-log backfill",
            "--storage",
            "--log-repo",
        ] {
            assert!(hint.contains(expected), "{hint}");
        }
        assert_eq!(
            ReleaseError::from(LogWriteError::Git {
                command: "push".to_string(),
                output: "remote rejected".to_string(),
            })
            .to_string(),
            "release log write failed: git push failed in the release log checkout: remote rejected"
        );
    }

    /// An existing head in an older signature format names the way out — a
    /// recreated log — not the revert that fixes a broken last commit; one in
    /// a newer format, or failing any other way, keeps the revert hint.
    #[test]
    fn an_existing_head_in_an_older_signature_format_hints_at_recreating_the_log() {
        let existing = |format| {
            LogWriteError::ExistingHead(ReleaseLogError::Signature(
                fuz_crypto::VerifyError::UnsupportedFormat(format),
            ))
        };
        let older = existing(fuz_crypto::SIGNATURE_FORMAT_VERSION - 1)
            .hint()
            .unwrap_or_default();
        assert!(
            older.contains("cargo xtask release-log backfill"),
            "{older}"
        );
        assert!(!older.contains("git revert"), "{older}");
        for error in [
            existing(fuz_crypto::SIGNATURE_FORMAT_VERSION + 1),
            LogWriteError::ExistingHead(ReleaseLogError::Signature(
                fuz_crypto::VerifyError::InvalidSignature,
            )),
        ] {
            let hint = error.hint().unwrap_or_default();
            assert!(hint.contains("git revert"), "{hint}");
        }
    }
}
