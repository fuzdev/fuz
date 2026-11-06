//! Artifact-specific error types

use crate::platform::{
    BinaryFormatError, BinaryPlatform, PlatformMismatch, ReleaseTarget, UnsupportedTarget,
    publish_target_hint,
};
use crate::vcs::VcsError;
use fuz_crypto::ContentHash;
use fuz_home::FuzHomeError;
use fuz_sys::cli::HintMessage;
use fuz_sys::file_lock::FileLockError;
use std::path::PathBuf;

/// Errors specific to artifact operations
#[derive(Debug, thiserror::Error)]
pub enum ArtifactError {
    /// Home directory error
    #[error(transparent)]
    FuzHome(#[from] FuzHomeError),

    /// VCS operation failed
    #[error(transparent)]
    Vcs(#[from] VcsError),

    /// Rustc command failed
    #[error("rustc --version failed")]
    RustcFailed,

    /// Artifact lock held by another process — a `fuz artifact build`,
    /// `fuz self bootstrap`, `fuz artifact use`, `fuz artifact prune`,
    /// `fuz self upgrade`, or `cargo xtask install` is in flight. `pid` is `None` when the holder's
    /// content could not be read (raced acquire, or a hand-edited lock file).
    #[error("artifact operation already in progress ({})", format_pid(*pid))]
    InProgress { pid: Option<u32> },

    /// Failed to acquire artifact lock
    #[error("failed to acquire artifact lock: {0}")]
    LockFailed(std::io::Error),

    /// Artifact not found
    #[error("artifact not found: {0}")]
    NotFound(String),

    /// Hash prefix is ambiguous
    #[error("hash prefix '{prefix}' matches multiple artifacts: {candidates:?}")]
    AmbiguousPrefix {
        prefix: String,
        candidates: Vec<String>,
    },

    /// Hash prefix too short
    #[error("hash prefix too short ({given} chars, need at least {minimum})")]
    PrefixTooShort { given: usize, minimum: usize },

    /// Artifact integrity check failed (stored hash doesn't match computed)
    #[error("artifact integrity failed at {path}: expected {expected}, got {actual}")]
    IntegrityFailed {
        path: PathBuf,
        expected: String,
        actual: String,
    },

    /// Binary integrity check failed
    #[error("binary {binary} integrity failed: expected {expected}, got {actual}")]
    BinaryIntegrityFailed {
        binary: String,
        expected: ContentHash,
        actual: ContentHash,
    },

    /// An entry in the artifact or tool store that has to be a real directory —
    /// `artifacts/v1-<hash>/`, `tools/<name>/v1-<hash>/`, or the install a
    /// `current` link names — is a symlink (live or dangling), a file, or a
    /// special file. fuz never writes one there, and reading through it would
    /// read whatever it points at.
    #[error("{path} is {kind}, not a directory")]
    StoreEntryNotDir {
        path: PathBuf,
        kind: fuz_sys::fs::NonDirKind,
    },

    /// A `current` link — the self artifact's `~/.fuz/current` or a tool's
    /// `tools/<name>/current` — is not what fuz writes there: not a symlink at
    /// all, or a symlink whose target is outside the store it belongs to.
    /// Nothing is read through it, and fuz does not remove it (it did not
    /// write it).
    #[error("{path} is not a `current` link fuz wrote: {problem}")]
    CurrentNotStoreLink {
        path: PathBuf,
        problem: CurrentLinkProblem,
    },

    /// A name used to address an entry in the artifact or tool store is not a
    /// single plain path component (empty, `.`, `..`, or containing `/`), so
    /// the path built from it would leave the store. Refused before any
    /// filesystem access.
    #[error("not a store entry name: {name:?}")]
    InvalidStoreName { name: String },

    /// A file inside an artifact or tool install (`meta.json`, a binary) is a
    /// symlink or a special file rather than the regular file fuz wrote, so it
    /// is refused instead of read through.
    #[error("{0} is a symlink or special file, not a regular file")]
    NotRegularFile(PathBuf),

    /// Failed to read artifact metadata
    #[error("failed to read artifact metadata: {0}")]
    MetadataReadFailed(PathBuf, #[source] std::io::Error),

    /// Failed to parse artifact metadata
    #[error("failed to parse artifact metadata: {0}")]
    MetadataParseFailed(PathBuf, #[source] serde_json::Error),

    /// Failed to write artifact metadata
    #[error("failed to write artifact metadata")]
    MetadataWriteFailed(#[source] std::io::Error),

    /// Metadata file too large (size limit exceeded)
    #[error("metadata file too large at {path}: {size} bytes (max {max})")]
    MetadataTooLarge { path: PathBuf, size: u64, max: u64 },

    /// Symlink operation failed
    #[error("symlink operation failed: {0}")]
    SymlinkFailed(std::io::Error),

    /// Binary is missing
    #[error("missing binary {name} at {path}")]
    MissingBinary {
        name: String,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// Binary is invalid (symlink, wrong type, wrong size, bad header)
    #[error("invalid binary {name}: {reason}")]
    InvalidBinary { name: String, reason: String },

    /// A tool's binary set names a binary of the fuz self artifact
    /// (`SELF_BINARIES`, in any ASCII case). Every tool binary is linked into the `~/.fuz/bin/`
    /// that holds the self artifact's own links, so installing it would
    /// repoint `bin/fuz` at the tool. Refused before anything is written.
    #[error(
        "tool {} declares the binary {}, which belongs to the fuz self artifact",
        fuz_sys::text::quoted(.tool),
        fuz_sys::text::quoted(.binary)
    )]
    ReservedBinaryName { tool: String, binary: String },

    /// A tool's binary set names a binary that is not a release token
    /// (`is_release_token`). Each name becomes `<install dir>/<name>` and
    /// `bin/<name>`, and is joined into the content hash with `:` and `\n`, so
    /// it must be one short `A-Za-z0-9._-` path component. Refused before
    /// anything is written.
    #[error(
        "tool {} declares the binary {}, which is not a valid binary name",
        fuz_sys::text::quoted(.tool),
        fuz_sys::text::quoted(&fuz_sys::text::truncate(.binary, crate::MAX_RELEASE_TOKEN_LEN))
    )]
    InvalidBinaryName { tool: String, binary: String },

    /// A binary on its way to being published is not for the release's
    /// target: its header ([`crate::platform::inspect_binary`]) names another
    /// architecture, OS, or libc, or it is statically linked and nothing
    /// named its libc ([`crate::platform::check_binary_target`]). Refused
    /// before anything is signed or uploaded.
    #[error(
        "binary {} is not for {target}: it is {found}{}",
        fuz_sys::text::quoted(.name),
        mismatch_detail(*.mismatch)
    )]
    BinaryPlatform {
        /// The binary's name in the release.
        name: String,
        /// The target the release would be labelled with.
        target: ReleaseTarget,
        /// What the binary's header says it is.
        found: BinaryPlatform,
        /// The rule that refused it.
        mismatch: PlatformMismatch,
    },

    /// A binary on its way to being published or installed is not an
    /// executable [`crate::platform::inspect_binary`] can place on a
    /// supported target, or could not be read to find out.
    #[error(
        "binary {} is not a supported executable: {reason}",
        fuz_sys::text::quoted(.name)
    )]
    BinaryUnreadable {
        /// The binary's name in the release.
        name: String,
        /// Why it was refused.
        reason: BinaryFormatError,
    },

    /// A target triple outside the supported release targets.
    #[error(transparent)]
    UnsupportedTarget(#[from] UnsupportedTarget),

    /// Binary copy failed
    #[error("failed to copy binary {binary}: {source}")]
    CopyFailed {
        binary: &'static str,
        #[source]
        source: std::io::Error,
    },

    /// Directory rename failed
    #[error("failed to rename {from} to {to}")]
    RenameFailed {
        from: PathBuf,
        to: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// Out of disk space while creating an artifact
    #[error("not enough space to create artifact at {path}")]
    InsufficientSpace {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Why a `current` link is [`ArtifactError::CurrentNotStoreLink`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CurrentLinkProblem {
    /// `current` is a directory, file, or special file rather than a symlink.
    /// fuz only ever writes a link there, and an install cannot replace a
    /// directory with one.
    NotASymlink,
    /// The link's target names something outside its store: anything but
    /// `artifacts/v1-<hash>` (self) or `v1-<hash>` (a tool), or the absolute path of
    /// the same entry.
    OutsideStore {
        /// The link's target as stored.
        target: PathBuf,
    },
}

impl std::fmt::Display for CurrentLinkProblem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotASymlink => f.write_str("it is not a symlink"),
            Self::OutsideStore { target } => {
                write!(f, "its target {} is outside the store", target.display())
            }
        }
    }
}

/// The tail of [`ArtifactError::BinaryPlatform`]'s message: what a static
/// binary's header leaves unsaid.
const fn mismatch_detail(mismatch: PlatformMismatch) -> &'static str {
    match mismatch {
        PlatformMismatch::ArchOrOs | PlatformMismatch::Libc => "",
        PlatformMismatch::StaticUnconfirmed => {
            " (a musl build?), and no --target names the libc it was linked against"
        }
    }
}

/// Format an optional holder pid for the `InProgress` Display message.
fn format_pid(pid: Option<u32>) -> String {
    pid.map_or_else(|| "pid unknown".to_string(), |p| format!("pid {p}"))
}

/// Translate the generic file-lock error into an artifact-domain error so
/// `acquire_artifact_lock()` callers get a meaningful "in progress"
/// message via `?`.
impl From<FileLockError> for ArtifactError {
    fn from(e: FileLockError) -> Self {
        match e {
            FileLockError::Held { pid } => Self::InProgress { pid },
            FileLockError::Io(e) => Self::LockFailed(e),
            FileLockError::Flock(e) => Self::LockFailed(std::io::Error::other(e.to_string())),
        }
    }
}

impl ArtifactError {
    /// User-facing hint for how to resolve this error.
    ///
    /// Advice only — the print site (`fuz`'s `main`) owns the `hint:` label.
    /// This is the single source of truth for artifact hints: `fuz`'s
    /// `CliError::hint()` delegates here, and the release chain reaches it via
    /// `ReleaseError::hint()`, so the same error reads identically on every path.
    #[must_use]
    pub fn hint(&self) -> Option<HintMessage> {
        match self {
            // The holder pid is interpolated, so this case owns its `String`.
            Self::InProgress { pid } => Some(HintMessage::Owned(pid.map_or_else(
                || "wait for the other fuz operation to finish (holder pid unknown)".to_string(),
                |p| format!("wait for the other fuz operation to finish or kill pid {p}"),
            ))),
            Self::NotFound(_) => Some(HintMessage::Static(
                "use 'fuz artifact list' to see available artifacts",
            )),
            Self::AmbiguousPrefix { .. } => {
                Some(HintMessage::Static("use more characters to disambiguate"))
            }
            Self::PrefixTooShort { .. } => Some(HintMessage::Static(
                "use at least 8 characters (e.g. 'fuz artifact use abc123de')",
            )),
            Self::IntegrityFailed { .. } | Self::BinaryIntegrityFailed { .. } => {
                Some(HintMessage::Static(
                    "the artifact may be corrupted; run 'fuz artifact build' for a fresh one",
                ))
            }
            Self::StoreEntryNotDir { .. } => Some(HintMessage::Static(
                "fuz keeps each artifact and tool install as a real directory; remove this entry, then rebuild or reinstall",
            )),
            Self::CurrentNotStoreLink { .. } => Some(HintMessage::Static(
                "fuz did not write this `current`; remove it, then reinstall or switch with fuz",
            )),
            Self::InvalidStoreName { .. } => Some(HintMessage::Static(
                "an artifact or tool install is named by its content hash: `v1-` and 64 hex characters",
            )),
            Self::NotRegularFile(_) => Some(HintMessage::Static(
                "the install was modified after fuz wrote it; rebuild or reinstall it",
            )),
            Self::MetadataTooLarge { .. } => Some(HintMessage::Static(
                "the meta.json file appears corrupted or tampered",
            )),
            Self::ReservedBinaryName { .. } => Some(HintMessage::Static(
                "a tool cannot install a binary under a name the fuz self artifact links in ~/.fuz/bin; do not install it",
            )),
            Self::InvalidBinaryName { .. } => Some(HintMessage::Static(
                "a binary name is A-Za-z0-9._-, starting with a letter or digit; do not install it",
            )),
            // The producer-side refusal: the hint names the `--target` that
            // would label the binary as what it is.
            Self::BinaryPlatform {
                target,
                found,
                mismatch,
                ..
            } => Some(HintMessage::Owned(publish_target_hint(
                *found, *target, *mismatch,
            ))),
            Self::BinaryUnreadable { .. } => Some(HintMessage::Static(
                "a release binary is a 64-bit ELF (x86_64 or aarch64 Linux, glibc or musl) or \
                 Mach-O (x86_64 or arm64 macOS) executable; publish the built executable itself",
            )),
            Self::UnsupportedTarget(_) => Some(HintMessage::Static(
                "name one of the supported targets, exactly as listed",
            )),
            Self::MissingBinary { .. } | Self::InvalidBinary { .. } => Some(HintMessage::Static(
                "run 'fuz artifact build' to create a new artifact",
            )),
            Self::RustcFailed => Some(HintMessage::Static(
                "ensure rustc is installed and in your PATH",
            )),
            Self::InsufficientSpace { .. } => Some(HintMessage::Static(
                "free up disk space and re-run the command",
            )),
            Self::Vcs(VcsError::UnreadableFile { .. }) => Some(HintMessage::Static(
                "fix file permissions or add to .gitignore",
            )),
            Self::FuzHome(e) => e.hint().map(HintMessage::Static),
            _ => None,
        }
    }
}
