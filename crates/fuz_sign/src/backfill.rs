//! Release log backfill: creating the log from the releases already published.
//!
//! The release log's head lists every release as a row, and a reader that
//! holds a head can treat a release the byte host serves but the head does not
//! list as a failure. That only works if the log is complete from its first
//! head — so the first head is built from storage: one row for every release
//! storage holds, each target's pins taken from that release's signed
//! manifest.
//!
//! Backfill is **genesis only**. It writes a log's first head and refuses a
//! log that already has one; every later release enters the log through a
//! publish that is given the log checkout (`release_log::record_release`).
//!
//! Storage is only read. Everything read from it is checked before it is
//! recorded, and a release that fails a check fails the whole backfill — it is
//! never left out, because an unlogged release that storage still serves is
//! exactly what the log exists to expose. The operator fixes or removes what
//! the error names and runs the backfill again.
//!
//! The module is layered:
//!
//! - **Pure** — [`plan_genesis`] and [`sign_genesis`]: verified releases in, a
//!   head and its `latest/` pointers out. No storage, no clock, no `git`.
//! - **Storage reads** — the walk over the self stream and every first-party
//!   tool stream, verifying each manifest, the tarball it names, what the
//!   stream's `latest-<target>.json` pointers name, and, for the self artifact, the flat
//!   binary the install script downloads.
//! - **The log write** — the checkout checks, commit, push, and read-back that
//!   a publish uses (`release_log`), given a whole head instead of one entry.
//!
//! [`backfill_release_log`] runs the three in order.
//!
//! The head is read by `fuz_release::log_check`, which an install runs when
//! it is given a witness serving `head.json`. The install script reads
//! `latest/` when it is given a release log origin, and never the head.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::SigningKey;
use fuz_crypto::{ContentHash, HashAlgo, hash_file};
use fuz_release::{
    HEAD_FORMAT_VERSION, HeadUnsigned, KeyRecord, LatestInfo, LogWriteError, MAX_FILE_SIZE,
    MAX_HEAD_SIZE, MAX_MANIFEST_SIZE, ManifestError, ReleaseError, ReleaseLayout, ReleaseLogError,
    ReleaseRow, RowStatus, SELF_NAME, TargetRow, VerifiedHead, parse_sidecar,
};
use fuz_storage::{Storage, StorageError};

use crate::release_log::{
    LogRepo, PreparedLog, check_genesis, genesis_commit_message, self_latest_pointer,
    sign_successor,
};
use crate::scratch::{ScratchDir, ScratchError};
use crate::stream::{
    compare_versions, is_stream_manifest_key, printable, printable_message, printable_quoted,
    read_manifest, stream_key_prefix, streams,
};

/// Most bytes read of a `.sha512` sidecar: one digest, one file name.
const MAX_SIDECAR_SIZE: u64 = 4096;

/// Suffixes of the checksum files published beside a flat binary. A key that
/// ends in one is a checksum of a binary, never a binary.
///
/// Publishes write only `.sha512`; `.sha256` is a guard for a store that still
/// holds sidecars from an older layout, so a backfill never reads one as a
/// `latest` copy of the binary.
const CHECKSUM_SUFFIXES: [&str; 2] = [".sha512", ".sha256"];

/// How a backfill runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackfillOptions {
    /// Run every read and check and write nothing.
    pub dry_run: bool,
    /// Log a self release whose flat binary is not in storage, without a
    /// `sha512`. Unset, such a release fails the backfill
    /// ([`BackfillError::MissingFlatBinaries`]): a row never gains a `sha512`
    /// once written, so leaving one out is the operator's explicit choice.
    pub allow_missing_flat: bool,
}

/// One target of one published release, read from storage and verified: its
/// manifest's signature checked against the trusted keys, and the manifest
/// confirmed to be the one its storage key names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackfilledTarget {
    /// The row name: a tool name, or `fuz` for the self artifact.
    pub name: String,
    /// The release version.
    pub version: String,
    /// The target the manifest was signed for.
    pub target: String,
    /// The manifest signature's `signed_at`. Not covered by the signature —
    /// it is what the publisher wrote, and what the row's `published_at` is
    /// taken from.
    pub signed_at: String,
    /// What the release pins for the target.
    pub pins: TargetRow,
}

/// A target for which storage advertises a latest self artifact, and the
/// version it advertises.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LatestTarget {
    /// The target triple.
    pub target: String,
    /// The version the target's `latest-<target>.json` names.
    pub version: String,
}

/// A `latest/` pointer the backfill writes beside the head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackfillPointer {
    /// The pointer's path in the log repository.
    pub path: String,
    /// The pointer's content: one `sha512sum`-format line naming the versioned
    /// flat binary.
    pub content: String,
    /// The version the pointer names.
    pub version: String,
    /// The target the pointer is for.
    pub target: String,
}

/// The log's first head, unsigned, and the `latest/` pointers that go with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenesisPlan {
    /// The head: `seq` 1, one key record, every release as a row.
    pub head: HeadUnsigned,
    /// The pointers, sorted by target.
    pub pointers: Vec<BackfillPointer>,
}

/// What a backfill did — or, on a dry run, what it would do.
///
/// The keys in `missing_flat_binaries` and `unaccounted_keys` are storage's
/// own, unescaped: print them through `printable`.
#[derive(Debug, Clone)]
pub struct BackfillReport {
    /// Whether this was a dry run: every read and check ran, and nothing was
    /// written beyond the fast-forward of the checkout.
    pub dry_run: bool,
    /// The head's `seq`.
    pub seq: u64,
    /// The head's rows, in head order.
    pub rows: Vec<ReleaseRow>,
    /// The `latest/` pointers.
    pub pointers: Vec<BackfillPointer>,
    /// The `head.json` document.
    pub head_json: String,
    /// The size limit `head_json` is held to.
    pub head_size_max: u64,
    /// The subject of the commit that holds the head.
    pub commit_message: String,
    /// The streams that were walked: the self artifact and every first-party
    /// tool. Anything else in storage was not read.
    pub streams: Vec<String>,
    /// Flat-binary keys of self releases that have no flat binary in storage.
    /// Their rows carry no `sha512`. Non-empty only when the backfill was
    /// allowed to log them.
    pub missing_flat_binaries: Vec<String>,
    /// Keys under a walked stream's name that no verified release accounts
    /// for — neither a manifest, its tarball, a flat binary, nor a `.sha512`
    /// sidecar. Reported, not recorded.
    pub unaccounted_keys: Vec<String>,
    /// Whether the branch's remote-tracking ref was behind the commit before
    /// the push. Always false on a dry run.
    pub pushed: bool,
}

/// Something in storage that keeps the log from recording a release.
#[derive(Debug)]
pub struct BackfillProblem {
    /// The storage key at fault, as storage spells it.
    pub key: String,
    /// What is wrong with it.
    pub kind: BackfillProblemKind,
}

impl BackfillProblem {
    fn new(key: &str, kind: BackfillProblemKind) -> Self {
        Self {
            key: key.to_string(),
            kind,
        }
    }
}

/// What is wrong with a storage key.
///
/// The strings a variant carries are what storage held, unescaped; the
/// variant's message prints each through `printable`, or through
/// `printable_quoted` where it is shown in quotes. A wrapped error's message
/// has escaped its own strings already and goes through `printable_message`,
/// which bounds it to a line without escaping them again.
#[derive(Debug, thiserror::Error)]
pub enum BackfillProblemKind {
    /// The key could not be read, or its manifest does not parse, is too
    /// large, or fails its signature.
    #[error("{}", printable_message(&.0.to_string()))]
    Release(#[from] ReleaseError),
    /// The manifest declares a different stream than the one it is stored in.
    #[error("the manifest declares {}, not the stream it is stored in", declared_tool(.declared.as_deref()))]
    StreamMismatch { declared: Option<String> },
    /// The manifest's version and target are not the ones its key names.
    #[error(
        "the manifest is for version {} target {}, not the release its key names",
        printable_quoted(.version),
        printable_quoted(.target)
    )]
    KeyMismatch { version: String, target: String },
    #[error("the manifest's signed_at is not a timestamp: {}", printable_quoted(.0))]
    SignedAt(String),
    /// The manifest claims to have been signed after the backfill's own clock.
    #[error(
        "the manifest's signed_at {} is later than this machine's clock ({}): check the clock, \
         or run again once it has passed",
        printable(.signed_at),
        printable(.now)
    )]
    SignedAtInFuture { signed_at: String, now: String },
    /// The release's fields cannot be written as a head row.
    #[error("the release cannot be a release log row: {}", printable_message(&.0.to_string()))]
    Row(#[source] ReleaseLogError),
    #[error("the file is {size} bytes (max {max})")]
    FileTooLarge { size: u64, max: u64 },
    #[error("the tarball its manifest names is not in storage")]
    TarballMissing,
    #[error("the tarball is not the one the manifest pins: its BLAKE3 is {actual}")]
    TarballMismatch { actual: ContentHash },
    #[error("the flat binary is not the one the manifest pins: its BLAKE3 is {actual}")]
    FlatBinaryMismatch { actual: ContentHash },
    #[error("the sidecar has no binary beside it")]
    SidecarWithoutBinary,
    #[error("the sidecar is malformed: {0}")]
    SidecarMalformed(&'static str),
    #[error("the sidecar names {}, not the binary it sits beside", printable_quoted(.0))]
    SidecarWrongFile(String),
    #[error("the sidecar's digest is not the binary's")]
    SidecarMismatch,
    #[error("the latest pointer is unreadable: {}", printable(.0))]
    LatestUnreadable(String),
    #[error("the latest pointer names version {}, which has no verified manifest", printable_quoted(.version))]
    LatestVersionUnknown { version: String },
    #[error(
        "the latest pointer names version {}, which has no verified manifest for {}",
        printable_quoted(.version),
        printable_quoted(.target)
    )]
    LatestTargetUnknown { version: String, target: String },
    #[error(
        "version {} is the latest for {} and has no flat binary",
        printable_quoted(.version),
        printable_quoted(.target)
    )]
    LatestWithoutFlatBinary { version: String, target: String },
    #[error("the latest copy of the flat binary for {} is missing", printable_quoted(.target))]
    LatestBinaryMissing { target: String },
    #[error("the latest copy of the flat binary is not version {}'s binary", printable_quoted(.version))]
    LatestBinaryMismatch { version: String },
    /// A `latest` copy of the flat binary the install script would download,
    /// with no `latest-<target>.json` pointer to say which version it is.
    #[error(
        "a latest copy of the flat binary with no latest pointer for its target to say which version it is"
    )]
    LatestCopyWithoutPointer,
    #[error("the release appears twice")]
    Duplicate,
}

fn declared_tool(declared: Option<&str>) -> String {
    declared.map_or_else(
        || "the self artifact".to_string(),
        |tool| format!("tool {}", printable_quoted(tool)),
    )
}

impl BackfillProblemKind {
    /// Returns true if this problem indicates a security violation.
    ///
    /// Exhaustive on purpose. Signed bytes that do not verify, a signed
    /// manifest served as some other release, and a tarball, binary, or digest
    /// that is not the one a signed manifest pins are violations; a file that
    /// is missing, malformed, or unreadable is a storage fault, and a
    /// timestamp no signature covers is whatever was written there.
    pub const fn is_security_violation(&self) -> bool {
        match self {
            Self::Release(e) => e.is_security_violation(),
            Self::StreamMismatch { .. }
            | Self::KeyMismatch { .. }
            | Self::TarballMismatch { .. }
            | Self::FlatBinaryMismatch { .. }
            | Self::SidecarMismatch
            | Self::LatestBinaryMismatch { .. } => true,
            Self::SignedAt(_)
            | Self::SignedAtInFuture { .. }
            | Self::Row(_)
            | Self::FileTooLarge { .. }
            | Self::TarballMissing
            | Self::SidecarWithoutBinary
            | Self::SidecarMalformed(_)
            | Self::SidecarWrongFile(_)
            | Self::LatestUnreadable(_)
            | Self::LatestVersionUnknown { .. }
            | Self::LatestTargetUnknown { .. }
            | Self::LatestWithoutFlatBinary { .. }
            | Self::LatestBinaryMissing { .. }
            | Self::LatestCopyWithoutPointer
            | Self::Duplicate => false,
        }
    }
}

/// Errors from backfilling a release log.
#[derive(Debug, thiserror::Error)]
pub enum BackfillError {
    /// The log has a head already; backfill only ever writes the first.
    #[error("the release log already has a head")]
    HeadExists,
    /// The checkout's last commit holds a head its upstream does not: a log
    /// write committed it and the push did not land.
    #[error("the release log head is committed in the checkout and was never pushed")]
    HeadUnpublished,
    /// The checkout's last commit tracks files under `latest/` that the first
    /// head would not write: pointers no head vouched for.
    #[error("the log checkout tracks latest/ files the backfill would not write:{}", describe_keys(.paths))]
    StrayPointers { paths: Vec<String> },
    /// No walked stream holds a release.
    #[error("storage holds no releases to backfill")]
    NothingToBackfill,
    /// Storage holds releases the log cannot record. Every offending key is
    /// listed.
    #[error("storage holds releases the log cannot record:{}", describe_problems(.problems))]
    Releases { problems: Vec<BackfillProblem> },
    /// Self releases have no flat binary in storage, and the backfill was not
    /// told to log them without a `sha512`.
    #[error("self releases have no flat binary in storage:{}", describe_keys(.keys))]
    MissingFlatBinaries { keys: Vec<String> },
    #[error("the backfilled head would be {size} bytes (max {max})")]
    HeadTooLarge { size: u64, max: u64 },
    #[error("release log write failed: {0}")]
    Log(#[from] LogWriteError),
    /// The head is committed in the checkout and the push failed. The commit
    /// waits there, unpushed.
    #[error("the release log head is committed in the checkout but was not pushed: {0}")]
    Unpublished(#[source] LogWriteError),
    /// The push went through, and the pushed commit does not hold the head the
    /// backfill wrote. The commit is public.
    #[error("the pushed release log head is not the one the backfill wrote: {0}")]
    PublishedWrong(#[source] LogWriteError),
    /// The push went through, and reading the pushed commit back failed: `git`
    /// could not be run or a file could not be read. Whether the pushed commit
    /// holds the head is not known.
    #[error("the head was pushed but could not be read back: {0}")]
    ReadBackFailed(#[source] LogWriteError),
    /// A stream could not be listed.
    #[error("storage error: {0}")]
    Storage(#[from] StorageError),
    #[error("backfill I/O error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// One line per problem: the key, then what is wrong with it.
fn describe_problems(problems: &[BackfillProblem]) -> String {
    let mut out = String::new();
    for problem in problems {
        out.push_str("\n  ");
        out.push_str(&printable(&problem.key));
        out.push_str(": ");
        out.push_str(&problem.kind.to_string());
    }
    out
}

/// One line per key.
fn describe_keys(keys: &[String]) -> String {
    let mut out = String::new();
    for key in keys {
        out.push_str("\n  ");
        out.push_str(&printable(key));
    }
    out
}

impl BackfillError {
    /// Returns user-facing hint for how to fix this error
    pub fn hint(&self) -> Option<&'static str> {
        match self {
            Self::HeadExists => Some(
                "Backfill writes a release log's first head and this log has one; later \
                 releases are recorded by publishing with --log-repo",
            ),
            Self::HeadUnpublished => Some(
                "The commit that holds the head is in the clone but was not pushed: push it \
                 with `git push`, or publish the next release with --log-repo, which pushes it \
                 and reads it back",
            ),
            Self::StrayPointers { .. } => Some(
                "Remove the listed files with a commit (git rm, git commit), push it, and run \
                 the backfill again",
            ),
            Self::NothingToBackfill => Some(
                "Check --storage. A log with nothing to backfill needs no backfill: the first \
                 publish with --log-repo creates it",
            ),
            // Nothing in storage is at fault when every line is about the
            // clock.
            Self::Releases { problems }
                if problems.iter().all(|problem| {
                    matches!(problem.kind, BackfillProblemKind::SignedAtInFuture { .. })
                }) =>
            {
                Some(
                    "Check this machine's clock, or run the backfill again once the listed \
                     times have passed; nothing was written to the log",
                )
            }
            Self::Releases { .. } => Some(
                "Fix or remove each listed key in storage (a release past the retention count \
                 can be removed with `cargo xtask prune`; anything else by hand) and run the \
                 backfill again; nothing was written to the log",
            ),
            Self::MissingFlatBinaries { .. } => Some(
                "These rows can never gain a sha512. Restore the binaries, or pass \
                 --allow-missing-flat",
            ),
            Self::HeadTooLarge { .. } => Some(
                "Remove old releases from storage (`cargo xtask prune`) and run the backfill \
                 again; nothing was written to the log",
            ),
            // The log write's hints are worded for a publish. The ones that say
            // how to retry are said again for a backfill, which retries
            // differently: a backfill that committed is not run again.
            Self::Log(LogWriteError::Dirty { .. }) => Some(
                "Commit or discard the changes to head.json and latest/ in the log checkout, \
                 then run the backfill again",
            ),
            Self::Log(LogWriteError::Ignored { .. }) => Some(
                "Remove the ignore rule covering head.json or latest/ (.gitignore, \
                 .git/info/exclude, or core.excludesFile) and delete any ignored copy, \
                 then run the backfill again",
            ),
            Self::Log(LogWriteError::Diverged { .. }) => Some(
                "If the local commits were never pushed, `git reset --hard @{upstream}` in the \
                 log checkout and run the backfill again; never rewrite pushed history",
            ),
            Self::Log(LogWriteError::Git { .. }) => Some(
                "Fix what git reports in the log checkout, then run the backfill again - a \
                 commit that failed was rolled back",
            ),
            Self::Log(e) => e.hint(),
            Self::Unpublished(_) => Some(
                "Fix what the error reports, then push the commit with `git push` in the log \
                 checkout, or publish the next release with --log-repo, which pushes it and \
                 reads it back",
            ),
            Self::PublishedWrong(_) => Some(
                "The commit is on the remote. Remove the cause (a hook, an assume-unchanged \
                 flag), discard any uncommitted change `git status` shows for head.json and \
                 latest/, restore the log with a new commit (git revert --no-edit HEAD), push \
                 it, and run the backfill again",
            ),
            Self::ReadBackFailed(_) => Some(
                "The commit was pushed. Run the backfill again: it reports whether the log has \
                 its head",
            ),
            Self::Storage(e) => e.hint(),
            Self::Io { .. } => None,
        }
    }

    /// The error for a read-back of the pushed commit that failed.
    ///
    /// A read-back that read something other than the head that was written is
    /// [`PublishedWrong`](Self::PublishedWrong). One that could not read at
    /// all — `git` failed, or a file did — says nothing about the pushed
    /// commit, and is [`ReadBackFailed`](Self::ReadBackFailed).
    const fn from_read_back(error: LogWriteError) -> Self {
        match error {
            LogWriteError::Git { .. } | LogWriteError::Io { .. } => Self::ReadBackFailed(error),
            other => Self::PublishedWrong(other),
        }
    }

    /// Returns true if this error indicates a security violation.
    ///
    /// Exhaustive on purpose; the wrapped errors decide for the variants that
    /// carry one. A log that already has a head or a stray pointer, storage
    /// with nothing in it or with a flat binary missing, and a head past the
    /// size limit are operator conditions.
    pub fn is_security_violation(&self) -> bool {
        match self {
            Self::Releases { problems } => problems
                .iter()
                .any(|problem| problem.kind.is_security_violation()),
            Self::Log(e) | Self::Unpublished(e) | Self::PublishedWrong(e) => {
                e.is_security_violation()
            }
            Self::HeadExists
            | Self::HeadUnpublished
            | Self::StrayPointers { .. }
            | Self::NothingToBackfill
            | Self::MissingFlatBinaries { .. }
            | Self::HeadTooLarge { .. }
            | Self::ReadBackFailed(_)
            | Self::Storage(_)
            | Self::Io { .. } => false,
        }
    }
}

/// Build the log's first head and its `latest/` pointers from verified
/// releases.
///
/// One row per `(name, version)`, `ok`, holding every target of that release.
/// A row's `published_at` is the earliest `signed_at` among its targets.
///
/// **Row order is `published_at`, then name, then version** (semver order,
/// falling back to string order). The order of `targets` — the order storage
/// happened to list them in — has no effect: a head's rows never move once
/// written, so the first head must not depend on a listing.
///
/// The head is `seq` 1 with one key record: `public_key`, added at `now`.
///
/// `latest` names, per target, the self artifact version storage advertises;
/// each becomes a pointer naming that version's flat binary with the `sha512`
/// its row records.
///
/// # Errors
///
/// [`BackfillError::NothingToBackfill`] for no targets, and
/// [`BackfillError::Releases`] for a target given twice or a `latest` entry
/// with no row, no target, or no `sha512` to point at.
pub fn plan_genesis(
    targets: &[BackfilledTarget],
    latest: &[LatestTarget],
    public_key: &str,
    now: &str,
) -> Result<GenesisPlan, BackfillError> {
    if targets.is_empty() {
        return Err(BackfillError::NothingToBackfill);
    }
    let mut problems = Vec::new();

    let mut rows: BTreeMap<(&str, &str), ReleaseRow> = BTreeMap::new();
    for target in targets {
        let row = rows
            .entry((&target.name, &target.version))
            .or_insert_with(|| ReleaseRow {
                name: target.name.clone(),
                version: target.version.clone(),
                status: RowStatus::Ok,
                published_at: target.signed_at.clone(),
                targets: BTreeMap::new(),
            });
        if target.signed_at < row.published_at {
            row.published_at.clone_from(&target.signed_at);
        }
        if row
            .targets
            .insert(target.target.clone(), target.pins.clone())
            .is_some()
        {
            problems.push(BackfillProblem::new(
                &format!("{} {} {}", target.name, target.version, target.target),
                BackfillProblemKind::Duplicate,
            ));
        }
    }
    let mut rows: Vec<ReleaseRow> = rows.into_values().collect();
    rows.sort_by(|a, b| {
        a.published_at
            .cmp(&b.published_at)
            .then_with(|| a.name.cmp(&b.name))
            .then_with(|| compare_versions(&a.version, &b.version))
    });

    let mut pointers = Vec::new();
    let mut seen_targets = BTreeSet::new();
    let mut latest: Vec<&LatestTarget> = latest.iter().collect();
    latest.sort_by(|a, b| a.target.cmp(&b.target));
    for entry in latest {
        let key = ReleaseLayout::self_artifact().latest_binary_key(SELF_NAME, &entry.target);
        if !seen_targets.insert(&entry.target) {
            problems.push(BackfillProblem::new(&key, BackfillProblemKind::Duplicate));
            continue;
        }
        let pins = rows
            .iter()
            .find(|row| row.name == SELF_NAME && row.version == entry.version)
            .and_then(|row| row.targets.get(&entry.target));
        let Some(pins) = pins else {
            problems.push(BackfillProblem::new(
                &key,
                BackfillProblemKind::LatestTargetUnknown {
                    version: entry.version.clone(),
                    target: entry.target.clone(),
                },
            ));
            continue;
        };
        let Some(sha512) = &pins.sha512 else {
            problems.push(BackfillProblem::new(
                &key,
                BackfillProblemKind::LatestWithoutFlatBinary {
                    version: entry.version.clone(),
                    target: entry.target.clone(),
                },
            ));
            continue;
        };
        let (path, content) = self_latest_pointer(SELF_NAME, &entry.version, &entry.target, sha512);
        pointers.push(BackfillPointer {
            path,
            content,
            version: entry.version.clone(),
            target: entry.target.clone(),
        });
    }

    if !problems.is_empty() {
        return Err(BackfillError::Releases { problems });
    }
    Ok(GenesisPlan {
        head: HeadUnsigned {
            format: HEAD_FORMAT_VERSION,
            seq: 1,
            keys: vec![KeyRecord {
                public_key: public_key.to_string(),
                added_at: now.to_string(),
                retired_at: None,
            }],
            rows,
        },
        pointers,
    })
}

/// Sign the log's first head and verify it as a reader would.
///
/// # Errors
///
/// [`BackfillError::HeadTooLarge`] if the signed `head.json` would be past
/// `MAX_HEAD_SIZE`; otherwise [`BackfillError::Log`] with the signing
/// failure — a structurally invalid head, or a key this binary does not trust.
pub fn sign_genesis(
    head: HeadUnsigned,
    key: &SigningKey,
    signed_at: &str,
) -> Result<VerifiedHead, BackfillError> {
    sign_successor(None, head, key, signed_at).map_err(|error| match error {
        LogWriteError::SignedHead(ReleaseLogError::TooLarge(size)) => BackfillError::HeadTooLarge {
            size,
            max: MAX_HEAD_SIZE,
        },
        other => BackfillError::Log(other),
    })
}

/// Create the release log in the checkout `repo` from the releases published
/// in `storage`.
///
/// In order:
///
/// 1. **Check the store and the log.** `storage` has a listing — a read-only
///    backend is refused ([`StorageError::Unsupported`]) before the checkout
///    is touched. The checkout meets every requirement of a publish's log
///    write (`release_log::record_release`), the log has no head, and `key`
///    is one this binary trusts.
/// 2. **Walk storage.** For the self stream and every first-party tool stream,
///    list the stream and read each manifest: under the manifest size cap,
///    parsed, its signature verified against the trusted keys, confirmed to be
///    the manifest of the stream, version, and target its key names, and with
///    a `signed_at` that is a timestamp no later than `now`. The tarball the
///    manifest names is downloaded and its BLAKE3 required to be the one the
///    manifest pins. For the self artifact, the flat binary the install script
///    fetches is downloaded too: its BLAKE3 must be the one the manifest pins,
///    its SHA-512 becomes the row's `sha512`, and a `.sha512` sidecar beside
///    it must be the line a publish writes for that binary.
/// 3. **Check what is advertised.** Each of a stream's `latest-<target>.json`
///    pointers must parse and name a version with a verified manifest for its
///    target. For the self stream, for each target with a pointer or a
///    `latest` copy of the flat binary: the pointed-at version has a flat
///    binary for the target, and the `latest` copy is byte for byte that
///    binary (compared by SHA-512 of the downloaded copy), with a sidecar that
///    says so if it has one. A `latest` copy with no pointer for its target is
///    refused: the install script downloads that copy without reading one.
/// 4. **Require consent for a missing flat binary.** A self release with no
///    flat binary in storage can only be recorded without a `sha512`, for
///    good. That is refused ([`BackfillError::MissingFlatBinaries`]) unless
///    `options.allow_missing_flat` is set, and then listed in the report.
/// 5. **Build and sign the head** ([`plan_genesis`], [`sign_genesis`]).
/// 6. **Write, commit, push, and read back** — `head.json` and the `latest/`
///    pointers in one commit, by the same steps as a publish's log write. A
///    checkout that already tracks some other file under `latest/` is refused
///    first. A write or commit that fails is rolled back, and the backfill can
///    run again. A push that fails leaves the commit in the checkout
///    ([`BackfillError::Unpublished`]); a later run reports it as
///    [`BackfillError::HeadUnpublished`]. A read-back that reads something
///    other than the head means the commit is public and does not hold it
///    ([`BackfillError::PublishedWrong`]); one that cannot read at all leaves
///    that unknown ([`BackfillError::ReadBackFailed`]).
///
/// A failure in step 2 or 3 does not stop the walk: every key at fault is
/// collected, and the backfill fails with all of them, sorted by key
/// ([`BackfillError::Releases`]).
///
/// With `options.dry_run` set, steps 1–5 run in full and step 6 is skipped:
/// nothing is written to the checkout beyond the fast-forward the checks
/// perform, and the report describes what step 6 would write. Storage is
/// never written.
///
/// `now` is the key record's `added_at`, the head signature's `signed_at`,
/// and the latest `signed_at` a manifest may carry.
///
/// Blocking: runs `git` and waits for it, with no timeout.
///
/// # Errors
///
/// A [`BackfillError`] per the steps above.
pub async fn backfill_release_log(
    storage: &impl Storage,
    repo: &LogRepo,
    key: &SigningKey,
    now: &str,
    options: BackfillOptions,
) -> Result<BackfillReport, BackfillError> {
    // Before the checkout is touched: the walk lists every stream, and a
    // read-only store has no listing.
    storage.require_writable("list")?;
    // Before any release byte is read: a log that cannot take a first head
    // makes the walk pointless.
    check_genesis(repo, key)?;

    let mut survey = survey_storage(storage, now).await?;
    if !survey.problems.is_empty() {
        let mut problems = survey.problems;
        problems.sort_by(|a, b| a.key.cmp(&b.key));
        return Err(BackfillError::Releases { problems });
    }
    survey.missing_flat_binaries.sort();
    if !survey.missing_flat_binaries.is_empty() && !options.allow_missing_flat {
        return Err(BackfillError::MissingFlatBinaries {
            keys: survey.missing_flat_binaries,
        });
    }

    let public_key = STANDARD.encode(key.verifying_key().as_bytes());
    let plan = plan_genesis(&survey.targets, &survey.latest, &public_key, now)?;
    let head = sign_genesis(plan.head, key, now)?;
    let head_json = head
        .to_json()
        .map_err(|e| LogWriteError::SignedHead(ReleaseLogError::from(e)))?;

    // The checks of step 1 again, now with the pointer paths this write owns.
    let prepared = PreparedLog::prepare_genesis(
        repo,
        &head,
        plan.pointers
            .iter()
            .map(|pointer| (pointer.path.clone(), pointer.content.clone()))
            .collect(),
        key,
    )?;
    let pushed = if options.dry_run {
        false
    } else {
        prepared.write()?;
        let pushed = prepared.push().map_err(BackfillError::Unpublished)?;
        prepared
            .require_published()
            .map_err(BackfillError::from_read_back)?;
        pushed
    };

    Ok(BackfillReport {
        dry_run: options.dry_run,
        seq: head.seq(),
        commit_message: genesis_commit_message(head.rows().len(), head.seq()),
        rows: head.rows().to_vec(),
        pointers: plan.pointers,
        head_json,
        head_size_max: MAX_HEAD_SIZE,
        streams: survey.streams,
        missing_flat_binaries: survey.missing_flat_binaries,
        unaccounted_keys: survey.unaccounted_keys,
        pushed,
    })
}

/// Everything the walk over storage found.
#[derive(Debug, Default)]
struct Survey {
    streams: Vec<String>,
    targets: Vec<BackfilledTarget>,
    latest: Vec<LatestTarget>,
    missing_flat_binaries: Vec<String>,
    unaccounted_keys: Vec<String>,
    problems: Vec<BackfillProblem>,
}

impl Survey {
    fn problem(&mut self, key: &str, kind: impl Into<BackfillProblemKind>) {
        self.problems.push(BackfillProblem::new(key, kind.into()));
    }
}

/// A scratch file that tarballs and flat binaries are streamed to, one at a
/// time, to be hashed. It lives in a `ScratchDir`, which removes it.
#[derive(Debug)]
struct Scratch {
    file: PathBuf,
    _dir: ScratchDir,
}

impl Scratch {
    fn new() -> Result<Self, BackfillError> {
        let dir = ScratchDir::new("fuz-backfill")
            .map_err(|ScratchError { path, source }| BackfillError::Io { path, source })?;
        Ok(Self {
            file: dir.file("download"),
            _dir: dir,
        })
    }
}

/// The digests of a file in storage.
#[derive(Debug)]
struct Digests {
    blake3: ContentHash,
    sha512: ContentHash,
}

/// What reading a key from storage came to.
#[derive(Debug)]
enum Stored<T> {
    /// Storage has no such key.
    Absent,
    /// The read failed; the failure is recorded against the key.
    Failed,
    Present(T),
}

/// One stream of the walk.
#[derive(Debug)]
struct Stream<'a> {
    /// `fuz` for the self artifact, else the tool name.
    name: &'a str,
    layout: ReleaseLayout,
    is_self: bool,
    /// Where this stream's targets start in the survey.
    first_target: usize,
    /// Keys a verified release explains.
    accounted: BTreeSet<String>,
    /// Whether a release of this stream was refused.
    release_refused: bool,
}

/// The walk over storage: what it reads from, the clock it holds manifests
/// to, and what it has found.
#[derive(Debug)]
struct Walk<'a, S> {
    storage: &'a S,
    now: &'a str,
    scratch: Scratch,
    survey: Survey,
}

/// Walk the self stream and every first-party tool stream.
///
/// # Errors
///
/// Only what stops the walk: a stream that cannot be listed, or a local I/O
/// failure. What is wrong with a key is collected in the survey.
async fn survey_storage(storage: &impl Storage, now: &str) -> Result<Survey, BackfillError> {
    let mut walk = Walk {
        storage,
        now,
        scratch: Scratch::new()?,
        survey: Survey::default(),
    };
    for stream in streams() {
        walk.stream(stream.name, stream.layout, stream.is_self)
            .await?;
    }
    Ok(walk.survey)
}

impl<S: Storage> Walk<'_, S> {
    /// Walk one stream: every manifest, then what the stream advertises.
    async fn stream(
        &mut self,
        name: &str,
        layout: ReleaseLayout,
        is_self: bool,
    ) -> Result<(), BackfillError> {
        self.survey.streams.push(name.to_string());
        let stream_prefix = stream_key_prefix(&layout, name);
        let full_listing = self.storage.list(layout.prefix()).await?;
        // The targets the stream has a version pointer for.
        let pointers: BTreeSet<String> = full_listing
            .iter()
            .filter_map(|key| layout.latest_key_target(key))
            .map(str::to_string)
            .collect();
        let mut listing: Vec<String> = full_listing
            .into_iter()
            .filter(|key| key.starts_with(&stream_prefix))
            .collect();
        // The listing's own order decides nothing.
        listing.sort();

        let mut stream = Stream {
            name,
            layout,
            is_self,
            first_target: self.survey.targets.len(),
            accounted: BTreeSet::new(),
            release_refused: false,
        };
        for key in &listing {
            if is_stream_manifest_key(key, &stream.layout, name) {
                stream.accounted.insert(key.clone());
                let problems = self.survey.problems.len();
                self.release(&mut stream, key).await?;
                stream.release_refused |= self.survey.problems.len() > problems;
            }
        }
        self.advertised(&mut stream, &listing, pointers).await?;
        self.survey.unaccounted_keys.extend(
            listing
                .into_iter()
                .filter(|key| !stream.accounted.contains(key)),
        );
        Ok(())
    }

    /// Stream the file at `key` to the scratch file and hash it, refusing one
    /// past `MAX_FILE_SIZE`.
    async fn digests(&mut self, key: &str) -> Result<Stored<Digests>, BackfillError> {
        self.digests_within(key, MAX_FILE_SIZE).await
    }

    /// [`digests`](Self::digests) with the size limit as a parameter. A file
    /// past `max` is refused by the byte count of the download, before any of
    /// it is hashed.
    async fn digests_within(
        &mut self,
        key: &str,
        max: u64,
    ) -> Result<Stored<Digests>, BackfillError> {
        let size = match self.storage.download_to_file(key, &self.scratch.file).await {
            Ok(size) => size,
            Err(StorageError::NotFound { .. }) => return Ok(Stored::Absent),
            Err(error) => {
                self.survey.problem(key, ReleaseError::from(error));
                return Ok(Stored::Failed);
            }
        };
        let file = &self.scratch.file;
        if size > max {
            let _ = std::fs::remove_file(file);
            self.survey
                .problem(key, BackfillProblemKind::FileTooLarge { size, max });
            return Ok(Stored::Failed);
        }
        let hash = |algo| {
            hash_file(algo, file).map_err(|source| BackfillError::Io {
                path: file.clone(),
                source,
            })
        };
        let (blake3, _) = hash(HashAlgo::Blake3)?;
        let (sha512, _) = hash(HashAlgo::Sha512)?;
        let _ = std::fs::remove_file(file);
        Ok(Stored::Present(Digests { blake3, sha512 }))
    }

    /// Download the small file at `key` through the bounded read
    /// (`Storage::download_capped`). One past `max` bytes is a problem at
    /// `key` like any other storage failure, carrying
    /// `StorageError::TooLarge`.
    async fn small_file(&mut self, key: &str, max: u64) -> Stored<Vec<u8>> {
        match self.storage.download_capped(key, max).await {
            Ok(bytes) => Stored::Present(bytes),
            Err(StorageError::NotFound { .. }) => Stored::Absent,
            Err(error) => {
                self.survey.problem(key, ReleaseError::from(error));
                Stored::Failed
            }
        }
    }

    /// Check the `.sha512` sidecar beside the binary at `binary_key`, if
    /// storage has one: it parses as the line a publish writes, names that
    /// binary, and carries `digest`. With no `digest` — the binary is absent —
    /// a sidecar is itself the problem. Returns whether the sidecar is in
    /// order.
    async fn sidecar(&mut self, binary_key: &str, digest: Option<&ContentHash>) -> bool {
        let sidecar_key = format!("{binary_key}.sha512");
        let bytes = match self.small_file(&sidecar_key, MAX_SIDECAR_SIZE).await {
            Stored::Absent => return true,
            Stored::Failed => return false,
            Stored::Present(bytes) => bytes,
        };
        let kind = match (digest, parse_sidecar(&bytes)) {
            (None, _) => BackfillProblemKind::SidecarWithoutBinary,
            (_, Err(reason)) => BackfillProblemKind::SidecarMalformed(reason),
            (_, Ok((_, filename))) if filename != binary_key => {
                BackfillProblemKind::SidecarWrongFile(filename.to_string())
            }
            (Some(digest), Ok((recorded, _))) if recorded != *digest => {
                BackfillProblemKind::SidecarMismatch
            }
            (Some(_), Ok(_)) => return true,
        };
        self.survey.problem(&sidecar_key, kind);
        false
    }

    /// Read and verify the release whose manifest is at `key`, adding it to
    /// the survey's targets — or what is wrong with it to the survey's
    /// problems.
    async fn release(&mut self, stream: &mut Stream<'_>, key: &str) -> Result<(), BackfillError> {
        let manifest = match read_manifest(self.storage, key).await {
            Ok(manifest) => manifest,
            Err(error) => {
                self.survey.problem(key, error);
                return Ok(());
            }
        };
        // Nothing the manifest says is used before its signature is verified.
        let manifest = match manifest.verify_signature() {
            Ok(manifest) => manifest,
            Err(error) => {
                self.survey.problem(key, ReleaseError::from(error));
                return Ok(());
            }
        };

        // A validly signed manifest is still only the release it was signed
        // as: served under another stream, version, or target, it is not that
        // one.
        let expected_tool = (!stream.is_self).then_some(stream.name);
        if manifest.tool.as_deref() != expected_tool {
            self.survey.problem(
                key,
                BackfillProblemKind::StreamMismatch {
                    declared: manifest.tool.clone(),
                },
            );
            return Ok(());
        }
        let layout = &stream.layout;
        if let Err(error) = manifest.check_key(layout, stream.name, key) {
            let kind = match error {
                ManifestError::KeyMismatch {
                    version, target, ..
                } => BackfillProblemKind::KeyMismatch { version, target },
                other => BackfillProblemKind::Release(other.into()),
            };
            self.survey.problem(key, kind);
            return Ok(());
        }
        // No signature covers `signed_at`, and it becomes a row's
        // `published_at`, which never changes: it is held to the shape, and to
        // not being later than this run. The shape is fixed-width, most
        // significant field first, so comparing the strings compares the
        // times.
        let signed_at = &manifest.signature.signed_at;
        if !fuz_sys::is_rfc3339_utc_seconds(signed_at) {
            self.survey
                .problem(key, BackfillProblemKind::SignedAt(signed_at.clone()));
            return Ok(());
        }
        if signed_at.as_str() > self.now {
            self.survey.problem(
                key,
                BackfillProblemKind::SignedAtInFuture {
                    signed_at: signed_at.clone(),
                    now: self.now.to_string(),
                },
            );
            return Ok(());
        }

        let mut ok = true;

        // The tarball is what `fuz` installs from: it is logged only when
        // storage holds the bytes the manifest pins.
        let tarball_key = layout.tarball_key(&manifest.tarball.path);
        stream.accounted.insert(tarball_key.clone());
        match self.digests(&tarball_key).await? {
            Stored::Present(digests) if digests.blake3 == manifest.tarball.blake3 => {}
            Stored::Present(digests) => {
                self.survey.problem(
                    &tarball_key,
                    BackfillProblemKind::TarballMismatch {
                        actual: digests.blake3,
                    },
                );
                ok = false;
            }
            Stored::Absent => {
                self.survey
                    .problem(&tarball_key, BackfillProblemKind::TarballMissing);
                ok = false;
            }
            Stored::Failed => ok = false,
        }

        let mut pins = TargetRow {
            content_hash: manifest.content_hash.clone(),
            binaries: manifest.binaries.clone().into_iter().collect(),
            sha512: None,
        };
        let mut missing_flat = None;
        if stream.is_self {
            let binary_key = layout.binary_key(stream.name, &manifest.version, &manifest.target);
            stream.accounted.insert(binary_key.clone());
            stream.accounted.insert(format!("{binary_key}.sha512"));
            match self.digests(&binary_key).await? {
                Stored::Present(digests) => {
                    // The flat binary is the file the install script runs. It
                    // is logged only as the binary the signed manifest pins.
                    if manifest.binaries.get(SELF_NAME) != Some(&digests.blake3) {
                        self.survey.problem(
                            &binary_key,
                            BackfillProblemKind::FlatBinaryMismatch {
                                actual: digests.blake3.clone(),
                            },
                        );
                        ok = false;
                    }
                    ok &= self.sidecar(&binary_key, Some(&digests.sha512)).await;
                    pins.sha512 = Some(digests.sha512);
                }
                Stored::Absent => {
                    ok &= self.sidecar(&binary_key, None).await;
                    missing_flat = Some(binary_key);
                }
                Stored::Failed => ok = false,
            }
        }

        // The head's own rules, applied to this one release, so a field a head
        // cannot carry is reported against the key that holds it.
        let as_head = HeadUnsigned {
            format: HEAD_FORMAT_VERSION,
            seq: 1,
            keys: Vec::new(),
            rows: vec![ReleaseRow {
                name: stream.name.to_string(),
                version: manifest.version.clone(),
                status: RowStatus::Ok,
                published_at: signed_at.clone(),
                targets: BTreeMap::from([(manifest.target.clone(), pins.clone())]),
            }],
        };
        if let Err(error) = as_head.validate() {
            self.survey.problem(key, BackfillProblemKind::Row(error));
            ok = false;
        }
        if !ok {
            return Ok(());
        }

        self.survey.missing_flat_binaries.extend(missing_flat);
        self.survey.targets.push(BackfilledTarget {
            name: stream.name.to_string(),
            version: manifest.version.clone(),
            target: manifest.target.clone(),
            signed_at: signed_at.clone(),
            pins,
        });
        Ok(())
    }

    /// Check what the stream advertises as latest, target by target.
    ///
    /// Any stream: each `latest-<target>.json` it has (`pointers` names their
    /// targets) parses and names a version with a verified manifest for that
    /// target. The self stream as well: one [`LatestTarget`] per target whose
    /// `latest` copy of the flat binary is the binary of the version its
    /// pointer names, and a problem per copy that is not — or that has no
    /// pointer to say which version it is.
    async fn advertised(
        &mut self,
        stream: &mut Stream<'_>,
        listing: &[String],
        pointers: BTreeSet<String>,
    ) -> Result<(), BackfillError> {
        let layout = stream.layout.clone();

        // The targets storage holds a `latest` copy of the flat binary for.
        let mut copies: BTreeSet<String> = BTreeSet::new();
        if stream.is_self {
            let latest_prefix = layout.latest_binary_key(SELF_NAME, "");
            copies.extend(
                listing
                    .iter()
                    .filter(|key| !stream.accounted.contains(*key))
                    .filter(|key| !CHECKSUM_SUFFIXES.iter().any(|suffix| key.ends_with(suffix)))
                    .filter_map(|key| key.strip_prefix(&latest_prefix))
                    .map(str::to_string),
            );
        }

        // A `latest` copy with no pointer: nothing says which version it is,
        // and the install script downloads it without reading one.
        for target in copies.difference(&pointers) {
            let latest_binary_key = layout.latest_binary_key(SELF_NAME, target);
            stream.accounted.insert(latest_binary_key.clone());
            stream
                .accounted
                .insert(format!("{latest_binary_key}.sha512"));
            self.survey.problem(
                &latest_binary_key,
                BackfillProblemKind::LatestCopyWithoutPointer,
            );
        }

        for target in pointers {
            self.advertised_target(stream, &layout, target).await?;
        }
        Ok(())
    }

    /// Check one target's version pointer, and for the self stream its
    /// `latest` copy of the flat binary.
    async fn advertised_target(
        &mut self,
        stream: &mut Stream<'_>,
        layout: &ReleaseLayout,
        target: String,
    ) -> Result<(), BackfillError> {
        let latest_key = layout.latest_key(&target);
        let bytes = match self.small_file(&latest_key, MAX_MANIFEST_SIZE).await {
            Stored::Present(bytes) => bytes,
            // Listed and gone: nothing is advertised for the target now.
            Stored::Failed | Stored::Absent => return Ok(()),
        };
        let version = match serde_json::from_slice::<LatestInfo>(&bytes) {
            Ok(latest) => latest.version,
            Err(error) => {
                self.survey.problem(
                    &latest_key,
                    BackfillProblemKind::LatestUnreadable(error.to_string()),
                );
                return Ok(());
            }
        };

        // The stream's verified targets of that version, and their flat
        // digests.
        let of_version: BTreeMap<String, Option<ContentHash>> = self.survey.targets
            [stream.first_target..]
            .iter()
            .filter(|row| row.version == version)
            .map(|row| (row.target.clone(), row.pins.sha512.clone()))
            .collect();
        // A missing verified manifest is the pointer's fault only when every
        // manifest of the stream verified. When one was refused, it may be the
        // very release the pointer names: the refusal is the problem, and it
        // is already reported.
        // The `latest` copy and its sidecar belong to this pointer whatever
        // becomes of it below: a problem with the pointer is reported against
        // the pointer, not again as two stray keys.
        let latest_binary_key = layout.latest_binary_key(SELF_NAME, &target);
        if stream.is_self {
            stream.accounted.insert(latest_binary_key.clone());
            stream
                .accounted
                .insert(format!("{latest_binary_key}.sha512"));
        }
        let Some(recorded) = of_version.get(&target) else {
            if stream.release_refused {
                return Ok(());
            }
            let kind = if of_version.is_empty() {
                BackfillProblemKind::LatestVersionUnknown { version }
            } else {
                BackfillProblemKind::LatestTargetUnknown { version, target }
            };
            self.survey.problem(&latest_key, kind);
            return Ok(());
        };
        if !stream.is_self {
            return Ok(());
        }

        let Some(recorded) = recorded else {
            self.survey.problem(
                &layout.binary_key(SELF_NAME, &version, &target),
                BackfillProblemKind::LatestWithoutFlatBinary { version, target },
            );
            return Ok(());
        };
        let digests = match self.digests(&latest_binary_key).await? {
            Stored::Present(digests) => digests,
            Stored::Failed => return Ok(()),
            Stored::Absent => {
                self.survey.problem(
                    &latest_binary_key,
                    BackfillProblemKind::LatestBinaryMissing { target },
                );
                return Ok(());
            }
        };
        let is_version = digests.sha512 == *recorded;
        if !is_version {
            self.survey.problem(
                &latest_binary_key,
                BackfillProblemKind::LatestBinaryMismatch {
                    version: version.clone(),
                },
            );
        }
        let ok = self
            .sidecar(&latest_binary_key, Some(&digests.sha512))
            .await
            && is_version;
        if ok {
            self.survey.latest.push(LatestTarget { target, version });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const X86: &str = "x86_64-unknown-linux-gnu";
    const ARM: &str = "aarch64-unknown-linux-gnu";
    const KEY: &str = "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik=";
    const NOW: &str = "2025-06-01T00:00:00Z";

    fn target(name: &str, version: &str, target: &str, signed_at: &str) -> BackfilledTarget {
        let content = format!("{name} {version} {target}");
        let blake3 = ContentHash::blake3(content.as_bytes());
        BackfilledTarget {
            name: name.to_string(),
            version: version.to_string(),
            target: target.to_string(),
            signed_at: signed_at.to_string(),
            pins: TargetRow {
                content_hash: format!("v1-{}", blake3.to_hex()),
                binaries: BTreeMap::from([(name.to_string(), blake3)]),
                sha512: (name == SELF_NAME).then(|| ContentHash::sha512(content.as_bytes())),
            },
        }
    }

    fn latest(target: &str, version: &str) -> LatestTarget {
        LatestTarget {
            target: target.to_string(),
            version: version.to_string(),
        }
    }

    fn row_ids(plan: &GenesisPlan) -> Vec<(&str, &str)> {
        plan.head
            .rows
            .iter()
            .map(|row| (row.name.as_str(), row.version.as_str()))
            .collect()
    }

    fn sample_targets() -> Vec<BackfilledTarget> {
        vec![
            target("fuz", "0.10.0", X86, "2025-03-01T00:00:00Z"),
            target("fuz", "0.9.0", X86, "2025-03-01T00:00:00Z"),
            target("fuz", "0.2.0", ARM, "2025-01-05T00:00:00Z"),
            target("fuz", "0.2.0", X86, "2025-01-09T00:00:00Z"),
            target("fuzd", "0.2.0", X86, "2025-01-05T00:00:00Z"),
            target("zap", "1.0.0", X86, "2025-03-01T00:00:00Z"),
            target("fuzd", "0.1.0", X86, "2025-01-01T00:00:00Z"),
        ]
    }

    #[test]
    fn rows_are_one_per_release_in_a_fixed_order() {
        let plan = plan_genesis(&sample_targets(), &[], KEY, NOW).unwrap();

        // By published_at, then name, then version in semver order: 0.9.0
        // before 0.10.0, which string order would reverse.
        assert_eq!(
            row_ids(&plan),
            [
                ("fuzd", "0.1.0"),
                ("fuz", "0.2.0"),
                ("fuzd", "0.2.0"),
                ("fuz", "0.9.0"),
                ("fuz", "0.10.0"),
                ("zap", "1.0.0"),
            ]
        );
        assert_eq!(plan.head.format, HEAD_FORMAT_VERSION);
        assert_eq!(plan.head.seq, 1);
        assert_eq!(
            plan.head.keys,
            [KeyRecord {
                public_key: KEY.to_string(),
                added_at: NOW.to_string(),
                retired_at: None,
            }]
        );
        assert!(plan.pointers.is_empty());
        plan.head.validate().unwrap();

        // A release's targets share its row; the row is dated by the earliest.
        let row = &plan.head.rows[1];
        assert_eq!(row.status, RowStatus::Ok);
        assert_eq!(row.published_at, "2025-01-05T00:00:00Z");
        assert_eq!(
            row.targets.keys().map(String::as_str).collect::<Vec<_>>(),
            [ARM, X86]
        );
        assert_eq!(row.targets[X86], target("fuz", "0.2.0", X86, NOW).pins);
        // A tool's row carries no sha512.
        assert_eq!(plan.head.rows[0].targets[X86].sha512, None);
    }

    #[test]
    fn the_order_of_the_input_changes_nothing() {
        let targets = sample_targets();
        let pointers = [latest(X86, "0.10.0"), latest(ARM, "0.2.0")];
        let expected = plan_genesis(&targets, &pointers, KEY, NOW).unwrap();

        let mut reversed = targets.clone();
        reversed.reverse();
        let mut reversed_pointers = pointers.clone();
        reversed_pointers.reverse();
        assert_eq!(
            plan_genesis(&reversed, &reversed_pointers, KEY, NOW).unwrap(),
            expected
        );

        let mut rotated = targets;
        rotated.rotate_left(3);
        assert_eq!(
            plan_genesis(&rotated, &pointers, KEY, NOW).unwrap(),
            expected
        );
    }

    #[test]
    fn pointers_name_the_advertised_version_per_target() {
        let targets = sample_targets();
        let plan = plan_genesis(
            &targets,
            &[latest(X86, "0.10.0"), latest(ARM, "0.2.0")],
            KEY,
            NOW,
        )
        .unwrap();

        let digest = |version: &str, target: &str| {
            ContentHash::sha512(format!("fuz {version} {target}").as_bytes()).to_hex()
        };
        assert_eq!(
            plan.pointers,
            [
                BackfillPointer {
                    path: format!("latest/fuz-{ARM}.sha512"),
                    content: format!("{}  fuz-0.2.0-{ARM}\n", digest("0.2.0", ARM)),
                    version: "0.2.0".to_string(),
                    target: ARM.to_string(),
                },
                BackfillPointer {
                    path: format!("latest/fuz-{X86}.sha512"),
                    content: format!("{}  fuz-0.10.0-{X86}\n", digest("0.10.0", X86)),
                    version: "0.10.0".to_string(),
                    target: X86.to_string(),
                },
            ]
        );
    }

    #[test]
    fn a_pointer_with_nothing_to_name_is_refused() {
        let mut targets = sample_targets();
        // A self release recorded without a flat binary.
        targets[1].pins.sha512 = None;

        let problem = |latest: &[LatestTarget]| match plan_genesis(&targets, latest, KEY, NOW) {
            Err(BackfillError::Releases { mut problems }) => {
                assert_eq!(problems.len(), 1);
                problems.remove(0)
            }
            other => panic!("expected one problem, got {other:?}"),
        };

        let unknown_version = problem(&[latest(X86, "7.0.0")]);
        assert_eq!(unknown_version.key, format!("fuz-latest-{X86}"));
        assert!(matches!(
            unknown_version.kind,
            BackfillProblemKind::LatestTargetUnknown { .. }
        ));
        // 0.10.0 was published for one target only.
        assert!(matches!(
            problem(&[latest(ARM, "0.10.0")]).kind,
            BackfillProblemKind::LatestTargetUnknown { .. }
        ));
        assert!(matches!(
            problem(&[latest(X86, "0.9.0")]).kind,
            BackfillProblemKind::LatestWithoutFlatBinary { .. }
        ));
        assert!(matches!(
            problem(&[latest(X86, "0.10.0"), latest(X86, "0.2.0")]).kind,
            BackfillProblemKind::Duplicate
        ));
    }

    #[test]
    fn a_target_given_twice_is_refused() {
        let mut targets = sample_targets();
        targets.push(target("fuz", "0.2.0", X86, NOW));
        match plan_genesis(&targets, &[], KEY, NOW) {
            Err(BackfillError::Releases { problems }) => {
                assert_eq!(problems.len(), 1);
                assert_eq!(problems[0].key, format!("fuz 0.2.0 {X86}"));
                assert!(matches!(problems[0].kind, BackfillProblemKind::Duplicate));
            }
            other => panic!("expected a duplicate, got {other:?}"),
        }
    }

    #[test]
    fn no_releases_is_an_error_not_an_empty_head() {
        assert!(matches!(
            plan_genesis(&[], &[], KEY, NOW),
            Err(BackfillError::NothingToBackfill)
        ));
    }

    /// Storage keys and fields that try to add lines, colour the terminal, or
    /// reverse the text: every one prints as a single escaped line.
    #[test]
    fn problems_are_listed_one_per_line_whatever_storage_holds() {
        let hostile = "x\n  fuz 9.9.9  published_at 2025-01-01T00:00:00Z\x1b[31m\u{202e}";
        let error = BackfillError::Releases {
            problems: vec![
                BackfillProblem::new(
                    "fuz-0.1.0-x.manifest.json",
                    BackfillProblemKind::SidecarMismatch,
                ),
                BackfillProblem::new(
                    &format!("fuz-{hostile}.manifest.json"),
                    BackfillProblemKind::KeyMismatch {
                        version: hostile.to_string(),
                        target: hostile.to_string(),
                    },
                ),
                BackfillProblem::new(
                    &format!("tools/fuzd/{}", "k".repeat(5000)),
                    BackfillProblemKind::SidecarWrongFile("n".repeat(5000)),
                ),
                BackfillProblem::new(
                    "latest-x86_64-unknown-linux-gnu.json",
                    BackfillProblemKind::LatestUnreadable(hostile.to_string()),
                ),
                BackfillProblem::new(
                    "tools/zap/latest.json",
                    BackfillProblemKind::StreamMismatch {
                        declared: Some(hostile.to_string()),
                    },
                ),
            ],
        };
        let message = error.to_string();
        let lines: Vec<&str> = message.lines().collect();
        assert_eq!(lines.len(), 6, "{message}");
        assert_eq!(lines[0], "storage holds releases the log cannot record:");
        assert_eq!(
            lines[1],
            "  fuz-0.1.0-x.manifest.json: the sidecar's digest is not the binary's"
        );
        assert!(lines[2].starts_with("  fuz-x\\n  fuz 9.9.9"), "{message}");
        assert!(lines[3].starts_with("  tools/fuzd/kkkk"), "{message}");
        assert!(message.len() < 3000, "bounded: {}", message.len());
        for forbidden in ['\x1b', '\u{202e}', '\r'] {
            assert!(!message.contains(forbidden), "{message:?}");
        }

        // The other lists print the same way.
        for error in [
            BackfillError::MissingFlatBinaries {
                keys: vec![format!("fuz-{hostile}"), "fuz-0.1.0-x".to_string()],
            },
            BackfillError::StrayPointers {
                paths: vec![format!("latest/{hostile}"), "latest/b.sha512".to_string()],
            },
        ] {
            let message = error.to_string();
            assert_eq!(message.lines().count(), 3, "{message}");
            assert!(!message.contains('\x1b'), "{message:?}");
            assert!(!message.contains('\u{202e}'), "{message:?}");
        }
    }

    /// A blank filler prints as empty space: a field or key holding one is
    /// spelled out.
    #[test]
    fn a_field_that_shows_nothing_is_spelled_out() {
        assert_eq!(
            BackfillProblemKind::SidecarWrongFile("fuz\u{ffa0}\u{2800}x".to_string()).to_string(),
            "the sidecar names \"fuz\\u{ffa0}\\u{2800}x\", not the binary it sits beside"
        );
        let message = BackfillError::MissingFlatBinaries {
            keys: vec!["fuz-0.1.0\u{115f}-x\0".to_string()],
        }
        .to_string();
        assert_eq!(
            message.lines().nth(1),
            Some("  fuz-0.1.0\\u{115f}-x\\u{0}"),
            "{message}"
        );
    }

    /// Every message that shows a stored value in quotes: the value cannot
    /// close them, and a blank filler in it is spelled out.
    #[test]
    fn a_quoted_field_cannot_close_its_quotes_or_hide_a_character() {
        const RAW: &str = "a\u{2800}\" \"b";
        const SHOWN: &str = "\"a\\u{2800}\\\" \\\"b\"";
        let raw = || RAW.to_string();
        let cases = [
            (
                BackfillProblemKind::StreamMismatch {
                    declared: Some(raw()),
                },
                format!("the manifest declares tool {SHOWN}, not the stream it is stored in"),
            ),
            (
                BackfillProblemKind::KeyMismatch {
                    version: raw(),
                    target: raw(),
                },
                format!(
                    "the manifest is for version {SHOWN} target {SHOWN}, not the release its key \
                     names"
                ),
            ),
            (
                BackfillProblemKind::SignedAt(raw()),
                format!("the manifest's signed_at is not a timestamp: {SHOWN}"),
            ),
            (
                BackfillProblemKind::SidecarWrongFile(raw()),
                format!("the sidecar names {SHOWN}, not the binary it sits beside"),
            ),
            (
                BackfillProblemKind::LatestVersionUnknown { version: raw() },
                format!("the latest pointer names version {SHOWN}, which has no verified manifest"),
            ),
            (
                BackfillProblemKind::LatestTargetUnknown {
                    version: raw(),
                    target: raw(),
                },
                format!(
                    "the latest pointer names version {SHOWN}, which has no verified manifest \
                     for {SHOWN}"
                ),
            ),
            (
                BackfillProblemKind::LatestWithoutFlatBinary {
                    version: raw(),
                    target: raw(),
                },
                format!("version {SHOWN} is the latest for {SHOWN} and has no flat binary"),
            ),
            (
                BackfillProblemKind::LatestBinaryMissing { target: raw() },
                format!("the latest copy of the flat binary for {SHOWN} is missing"),
            ),
            (
                BackfillProblemKind::LatestBinaryMismatch { version: raw() },
                format!("the latest copy of the flat binary is not version {SHOWN}'s binary"),
            ),
        ];
        for (kind, expected) in cases {
            assert_eq!(kind.to_string(), expected);
        }
    }

    /// A wrapped error has escaped the strings it carries; the problem's line
    /// shows them escaped once, not twice.
    #[test]
    fn a_wrapped_error_is_not_escaped_a_second_time() {
        const RAW: &str = "a\u{1b}[2K\u{2800}\"\\b";
        let manifest = || ManifestError::InvalidBinaryName(RAW.to_string());
        let shown = "invalid binary name in manifest: \"a\\u{1b}[2K\\u{2800}\\\"\\\\b\" (must be \
                     A-Za-z0-9._-, starting with a letter or digit)";
        assert_eq!(manifest().to_string(), shown);
        assert_eq!(
            BackfillProblemKind::Release(manifest().into()).to_string(),
            format!("manifest error: {shown}")
        );

        let storage = || StorageError::InvalidKey {
            key: RAW.to_string(),
            reason: "key contains invalid characters",
        };
        assert_eq!(
            BackfillProblemKind::Release(storage().into()).to_string(),
            format!("storage error: {}", storage())
        );
        assert_eq!(
            storage().to_string(),
            "invalid storage key \"a\\u{1b}[2K\\u{2800}\\\"\\\\b\": key contains invalid characters"
        );

        // A row the head's rules refuse: the field is quoted and escaped by
        // the head's own error.
        let row = || {
            ReleaseLogError::Invalid(fuz_release::HeadInvalid::Field {
                field: fuz_release::HeadField::Name,
                value: RAW.to_string(),
            })
        };
        assert_eq!(
            BackfillProblemKind::Row(row()).to_string(),
            format!("the release cannot be a release log row: {}", row())
        );
        assert!(
            row()
                .to_string()
                .ends_with(": \"a\\u{1b}[2K\\u{2800}\\\"\\\\b\""),
            "{}",
            row()
        );
    }

    /// Text that tries to add a line, drive the terminal, and reverse itself.
    const HOSTILE: &str = "x\n  fuz 9.9.9  published_at\x1b[2K\u{202e}";

    /// One of every [`BackfillProblemKind`], with whether it is a security
    /// violation. Every string a variant carries is [`HOSTILE`].
    fn problem_table() -> Vec<(BackfillProblemKind, bool)> {
        let signature = || {
            ReleaseError::Manifest(ManifestError::Signature(
                fuz_crypto::VerifyError::InvalidSignature,
            ))
        };
        let text = || HOSTILE.to_string();
        let table = vec![
            (BackfillProblemKind::Release(signature()), true),
            (
                BackfillProblemKind::Release(ReleaseError::ToolNotInstalled(text())),
                false,
            ),
            (
                BackfillProblemKind::Row(ReleaseLogError::Parse(text())),
                false,
            ),
            (
                BackfillProblemKind::Release(ReleaseError::Manifest(ManifestError::TooLarge(1))),
                false,
            ),
            (
                BackfillProblemKind::StreamMismatch {
                    declared: Some(text()),
                },
                true,
            ),
            (
                BackfillProblemKind::KeyMismatch {
                    version: text(),
                    target: text(),
                },
                true,
            ),
            (BackfillProblemKind::SignedAt(text()), false),
            (
                BackfillProblemKind::Row(ReleaseLogError::UnsupportedFormat(2)),
                false,
            ),
            (
                BackfillProblemKind::SignedAtInFuture {
                    signed_at: text(),
                    now: text(),
                },
                false,
            ),
            (BackfillProblemKind::FileTooLarge { size: 2, max: 1 }, false),
            (BackfillProblemKind::TarballMissing, false),
            (
                BackfillProblemKind::TarballMismatch {
                    actual: ContentHash::blake3(b"b"),
                },
                true,
            ),
            (BackfillProblemKind::LatestCopyWithoutPointer, false),
            (
                BackfillProblemKind::FlatBinaryMismatch {
                    actual: ContentHash::blake3(b"b"),
                },
                true,
            ),
            (BackfillProblemKind::SidecarWithoutBinary, false),
            (BackfillProblemKind::SidecarMalformed("x"), false),
            (BackfillProblemKind::SidecarWrongFile(text()), false),
            (BackfillProblemKind::SidecarMismatch, true),
            (BackfillProblemKind::LatestUnreadable(text()), false),
            (
                BackfillProblemKind::LatestVersionUnknown { version: text() },
                false,
            ),
            (
                BackfillProblemKind::LatestTargetUnknown {
                    version: text(),
                    target: text(),
                },
                false,
            ),
            (
                BackfillProblemKind::LatestWithoutFlatBinary {
                    version: text(),
                    target: text(),
                },
                false,
            ),
            (
                BackfillProblemKind::LatestBinaryMissing { target: text() },
                false,
            ),
            (
                BackfillProblemKind::LatestBinaryMismatch { version: text() },
                true,
            ),
            (BackfillProblemKind::Duplicate, false),
        ];
        // Compile-time tripwire: a new variant fails to build here until it is
        // added to the table above.
        for (kind, _) in &table {
            match kind {
                BackfillProblemKind::Release(_)
                | BackfillProblemKind::StreamMismatch { .. }
                | BackfillProblemKind::KeyMismatch { .. }
                | BackfillProblemKind::SignedAt(_)
                | BackfillProblemKind::Row(_)
                | BackfillProblemKind::SignedAtInFuture { .. }
                | BackfillProblemKind::FileTooLarge { .. }
                | BackfillProblemKind::TarballMissing
                | BackfillProblemKind::TarballMismatch { .. }
                | BackfillProblemKind::LatestCopyWithoutPointer
                | BackfillProblemKind::FlatBinaryMismatch { .. }
                | BackfillProblemKind::SidecarWithoutBinary
                | BackfillProblemKind::SidecarMalformed(_)
                | BackfillProblemKind::SidecarWrongFile(_)
                | BackfillProblemKind::SidecarMismatch
                | BackfillProblemKind::LatestUnreadable(_)
                | BackfillProblemKind::LatestVersionUnknown { .. }
                | BackfillProblemKind::LatestTargetUnknown { .. }
                | BackfillProblemKind::LatestWithoutFlatBinary { .. }
                | BackfillProblemKind::LatestBinaryMissing { .. }
                | BackfillProblemKind::LatestBinaryMismatch { .. }
                | BackfillProblemKind::Duplicate => {}
            }
        }
        table
    }

    /// Whatever a variant carries, its message is one line with nothing
    /// non-printing in it.
    #[test]
    fn every_problem_prints_on_one_line_whatever_it_carries() {
        for (kind, _) in problem_table() {
            let message = kind.to_string();
            assert_eq!(message.lines().count(), 1, "{kind:?}: {message:?}");
            for forbidden in ['\n', '\r', '\x1b', '\u{202e}'] {
                assert!(!message.contains(forbidden), "{kind:?}: {message:?}");
            }
        }
    }

    /// A refusal that is only about the clock does not tell the operator to
    /// fix storage.
    #[test]
    fn a_clock_refusal_says_to_check_the_clock() {
        let future = |key: &str| {
            BackfillProblem::new(
                key,
                BackfillProblemKind::SignedAtInFuture {
                    signed_at: "2025-06-02T00:00:00Z".to_string(),
                    now: "2025-06-01T00:00:00Z".to_string(),
                },
            )
        };
        assert_eq!(
            future("k").kind.to_string(),
            "the manifest's signed_at 2025-06-02T00:00:00Z is later than this machine's clock \
             (2025-06-01T00:00:00Z): check the clock, or run again once it has passed"
        );
        let only_clock = BackfillError::Releases {
            problems: vec![future("a"), future("b")],
        };
        let hint = only_clock.hint().unwrap_or_default();
        assert!(hint.contains("clock"), "{hint}");
        assert!(!hint.contains("remove"), "{hint}");

        let mixed = BackfillError::Releases {
            problems: vec![
                future("a"),
                BackfillProblem::new("b", BackfillProblemKind::TarballMissing),
            ],
        };
        assert!(mixed.hint().unwrap_or_default().contains("Fix or remove"));
    }

    /// A read-back that could not read says nothing about the pushed commit;
    /// one that read something else does.
    #[test]
    fn a_read_back_that_could_not_read_is_not_a_wrong_head() {
        let could_not_read = [
            LogWriteError::Git {
                command: "cat-file".to_string(),
                output: "fatal: loose object is corrupt".to_string(),
            },
            LogWriteError::Io {
                path: PathBuf::from("/log/head.json"),
                source: std::io::Error::other("disk"),
            },
        ];
        for error in could_not_read {
            let mapped = BackfillError::from_read_back(error);
            assert!(
                matches!(mapped, BackfillError::ReadBackFailed(_)),
                "{mapped:?}"
            );
            assert!(!mapped.is_security_violation());
            let hint = mapped.hint().unwrap_or_default();
            assert!(hint.contains("Run the backfill again"), "{hint}");
            assert!(!hint.contains("revert"), "{hint}");
        }
        let read_something_else = [
            LogWriteError::NotPublished {
                name: "fuz".to_string(),
                version: "0.1.0".to_string(),
                target: X86.to_string(),
                detail: "the pushed head.json does not record this entry",
            },
            LogWriteError::PublishedHead(ReleaseLogError::UnsupportedFormat(2)),
        ];
        for error in read_something_else {
            let mapped = BackfillError::from_read_back(error);
            assert!(
                matches!(mapped, BackfillError::PublishedWrong(_)),
                "{mapped:?}"
            );
        }
    }

    /// A file past the limit is refused by the size of the download, without
    /// being hashed, and nothing of it is left in the scratch directory.
    /// A backfill lists every stream, and a read-only store has no listing:
    /// it is refused with the error its `list` would give, before the log
    /// checkout is looked at (the one given is not there, which would
    /// otherwise be the failure).
    #[tokio::test]
    async fn a_read_only_store_is_refused_before_the_checkout_is_touched() {
        let dir = tempfile::tempdir().unwrap();
        let storage = fuz_storage::HttpsStorage::new("https://releases.example.com/fuz").unwrap();
        let not_a_checkout = dir.path().join("log");
        let key = SigningKey::from_bytes(&[7u8; 32]);

        for dry_run in [true, false] {
            let options = BackfillOptions {
                dry_run,
                allow_missing_flat: false,
            };
            let err =
                backfill_release_log(&storage, &LogRepo::new(&not_a_checkout), &key, NOW, options)
                    .await
                    .unwrap_err();
            assert!(
                matches!(
                    &err,
                    BackfillError::Storage(StorageError::Unsupported {
                        backend: fuz_storage::StorageBackendKind::Https,
                        operation: "list",
                    })
                ),
                "{err:?}"
            );
            assert_eq!(
                err.to_string(),
                "storage error: HTTPS: list is not supported on a read-only backend"
            );
            assert_eq!(
                err.hint(),
                Some("Use a writable backend: a local path, forge://, or ssh://")
            );
        }
        assert!(!not_a_checkout.exists());
    }

    /// A self pointer the walk refuses — it names a version, or a target,
    /// with no verified manifest — still accounts for its target's `latest`
    /// copy and sidecar: the one problem is the pointer's, and the copy is not
    /// reported again as a stray key.
    #[tokio::test]
    async fn a_refused_pointer_still_accounts_for_its_latest_copy() {
        let dir = tempfile::tempdir().unwrap();
        let storage = fuz_storage::FileStorage::new(dir.path()).unwrap();
        let target = "x86_64-unknown-linux-gnu";
        let layout = ReleaseLayout::self_artifact();
        let copy = layout.latest_binary_key(SELF_NAME, target);
        storage
            .upload(&layout.latest_key(target), br#"{"version":"9.9.9"}"#)
            .await
            .unwrap();
        storage.upload(&copy, b"a binary").await.unwrap();
        storage
            .upload(&format!("{copy}.sha512"), b"a sidecar")
            .await
            .unwrap();

        let survey = survey_storage(&storage, NOW).await.unwrap();
        let problems: Vec<(&str, &BackfillProblemKind)> = survey
            .problems
            .iter()
            .map(|problem| (problem.key.as_str(), &problem.kind))
            .collect();
        assert!(
            matches!(
                problems.as_slice(),
                [(key, BackfillProblemKind::LatestVersionUnknown { version })]
                    if *key == layout.latest_key(target) && version == "9.9.9"
            ),
            "{problems:?}"
        );
        assert_eq!(survey.unaccounted_keys, Vec::<String>::new());
    }

    #[tokio::test]
    async fn a_file_past_the_size_limit_is_refused_unhashed() {
        let dir = tempfile::tempdir().unwrap();
        let storage = fuz_storage::FileStorage::new(dir.path()).unwrap();
        storage.upload("big", b"0123456789").await.unwrap();
        let mut walk = Walk {
            storage: &storage,
            now: NOW,
            scratch: Scratch::new().unwrap(),
            survey: Survey::default(),
        };

        assert!(matches!(
            walk.digests_within("big", 9).await.unwrap(),
            Stored::Failed
        ));
        assert_eq!(walk.survey.problems.len(), 1);
        assert_eq!(walk.survey.problems[0].key, "big");
        assert!(matches!(
            walk.survey.problems[0].kind,
            BackfillProblemKind::FileTooLarge { size: 10, max: 9 }
        ));
        assert!(!walk.scratch.file.exists());

        // At the limit it is hashed.
        match walk.digests_within("big", 10).await.unwrap() {
            Stored::Present(digests) => {
                assert_eq!(digests.blake3, ContentHash::blake3(b"0123456789"));
                assert_eq!(digests.sha512, ContentHash::sha512(b"0123456789"));
            }
            other => panic!("expected the digests, got {other:?}"),
        }
        assert_eq!(walk.survey.problems.len(), 1);
        assert!(matches!(
            walk.digests_within("absent", 10).await.unwrap(),
            Stored::Absent
        ));
    }

    #[test]
    fn classification_holds_at_every_wrapper_level() {
        for (kind, expected) in problem_table() {
            let description = kind.to_string();
            assert_eq!(kind.is_security_violation(), expected, "{description}");
            // One violation among the problems makes the backfill's failure one.
            let wrapped = BackfillError::Releases {
                problems: vec![
                    BackfillProblem::new("a", BackfillProblemKind::SidecarWithoutBinary),
                    BackfillProblem::new("b", kind),
                ],
            };
            assert_eq!(wrapped.is_security_violation(), expected, "{description}");
            assert!(wrapped.hint().is_some());
        }

        // The log write's own classifier and hint are forwarded, not re-decided.
        let untrusted = || LogWriteError::UntrustedKey {
            public_key: KEY.to_string(),
        };
        assert!(BackfillError::Log(untrusted()).is_security_violation());
        assert_eq!(BackfillError::Log(untrusted()).hint(), untrusted().hint());
        assert!(!BackfillError::Log(LogWriteError::DetachedHead).is_security_violation());
        // A failure after the commit classifies as its cause, and says what
        // to do about a commit that is local or one that is public.
        let rejected = || LogWriteError::Git {
            command: "push".to_string(),
            output: "rejected".to_string(),
        };
        assert!(BackfillError::Unpublished(untrusted()).is_security_violation());
        assert!(BackfillError::PublishedWrong(untrusted()).is_security_violation());
        let unpublished = BackfillError::Unpublished(rejected());
        assert!(!unpublished.is_security_violation());
        assert!(unpublished.to_string().contains("rejected"));
        let hint = unpublished.hint().unwrap_or_default();
        assert!(
            hint.contains("git push") && hint.contains("--log-repo"),
            "{hint}"
        );
        let wrong = BackfillError::PublishedWrong(rejected());
        assert!(!wrong.is_security_violation());
        let hint = wrong.hint().unwrap_or_default();
        assert!(hint.contains("on the remote"), "{hint}");
        assert!(hint.contains("git revert --no-edit HEAD"), "{hint}");
        // No hint tells the operator to drop a commit.
        for error in [&unpublished, &wrong, &BackfillError::HeadUnpublished] {
            assert!(
                !error.hint().unwrap_or_default().contains("drop"),
                "{error}"
            );
        }

        let plain = [
            BackfillError::HeadExists,
            BackfillError::HeadUnpublished,
            BackfillError::StrayPointers {
                paths: vec!["latest/x.sha512".to_string()],
            },
            BackfillError::NothingToBackfill,
            BackfillError::MissingFlatBinaries {
                keys: vec!["fuz-0.1.0-x".to_string()],
            },
            BackfillError::HeadTooLarge {
                size: MAX_HEAD_SIZE + 1,
                max: MAX_HEAD_SIZE,
            },
        ];
        for error in plain {
            assert!(!error.is_security_violation(), "{error}");
            assert!(error.hint().is_some(), "{error}");
        }
        let hint = BackfillError::HeadUnpublished.hint().unwrap_or_default();
        assert!(
            hint.contains("git push") && hint.contains("--log-repo"),
            "{hint}"
        );
        let hint = BackfillError::MissingFlatBinaries { keys: Vec::new() }
            .hint()
            .unwrap_or_default();
        assert!(hint.contains("--allow-missing-flat"), "{hint}");
        let io = BackfillError::Io {
            path: PathBuf::from("/scratch"),
            source: std::io::Error::other("disk"),
        };
        assert!(!io.is_security_violation());
        assert_eq!(io.hint(), None);
    }

    /// The log write's hints that say how to retry are worded for a publish;
    /// a backfill says its own.
    #[test]
    fn log_write_hints_that_describe_a_retry_are_worded_for_a_backfill() {
        let text = || "x".to_string();
        let reworded = [
            LogWriteError::Dirty { paths: text() },
            LogWriteError::Ignored { paths: text() },
            LogWriteError::Diverged { branch: text() },
            LogWriteError::Git {
                command: text(),
                output: text(),
            },
        ];
        for error in reworded {
            let publish_hint = error.hint().unwrap_or_default();
            assert!(publish_hint.contains("publish"), "{publish_hint}");
            let description = error.to_string();
            let hint = BackfillError::Log(error).hint().unwrap_or_default();
            assert!(!hint.contains("publish"), "{description}: {hint}");
            assert!(
                !hint.contains("pushed by the retry"),
                "{description}: {hint}"
            );
            assert!(
                hint.contains("run the backfill again"),
                "{description}: {hint}"
            );
        }
        // The rest say nothing a backfill contradicts, and are forwarded.
        for error in [
            LogWriteError::DetachedHead,
            LogWriteError::CheckoutMissing(PathBuf::from("/log")),
            LogWriteError::NoUpstream { branch: text() },
        ] {
            let expected = error.hint();
            assert_eq!(BackfillError::Log(error).hint(), expected);
        }
    }

    #[test]
    fn the_scratch_file_is_removed_with_its_directory() {
        let scratch = Scratch::new().unwrap();
        let dir = scratch.file.parent().unwrap().to_path_buf();
        assert!(dir.is_dir());
        std::fs::write(&scratch.file, b"binary").unwrap();
        drop(scratch);
        assert!(!dir.exists());
    }
}
