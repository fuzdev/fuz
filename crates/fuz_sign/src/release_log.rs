//! Release log writes: publishing a release records it in the log.
//!
//! The release log is a git repository holding one signed `head.json` — the
//! `fuz_release::release_log` head, every release as a row — plus flat files a
//! shell can read. A publish that is given a checkout of that repository
//! ([`LogRepo`]) records its release there as part of publishing: after the
//! release's bytes are uploaded and before the latest pointer advertises them. So a
//! release is never advertised while unlogged, and a log write that fails
//! leaves the latest pointer where it was. Before uploading anything the publish
//! also checks that the log can take the entry, so a release the log would
//! refuse never reaches storage.
//!
//! A log's first head has to list every release, because a reader treats a
//! release the head does not list as a failure. So a publish that would write
//! the first head lists storage first, and is refused if storage already holds
//! any release other than its own: that log is created from storage
//! (`crate::backfill`), not by a publish.
//!
//! A release with several targets is several publishes, each signing for one
//! target. The first creates the release's row; each later one adds its target
//! to that row. Every change to the head is its own commit.
//!
//! The module is two layers:
//!
//! - **Pure** — [`upsert_row`], [`record_key`], [`sign_successor`],
//!   [`next_head`], [`install_script_entry`]: values in, values out, no
//!   filesystem, no clock, no `git`.
//! - **Effects** — [`record_release`]: reads the checkout's head, calls the
//!   pure layer, writes the files, drives `git` (fast-forward, commit, push),
//!   and reads the pushed commit back. Its checking half runs alone as
//!   [`check_release`], which a publish calls before it uploads anything.
//!   Storage is read only for the first head, and only listed.
//!
//! A log's first head can also be written whole, from the releases already in
//! storage: `crate::backfill` builds that head and hands it to the same
//! checkout checks, commit, push, and read-back a publish's entry goes through.
//! So does a revocation (`crate::revoke`), which flips a row's status and moves
//! or removes the `latest/` pointers that name the revoked release.
//!
//! `git` is run as a subprocess with argument vectors, as
//! `fuz_artifact::vcs` does; those helpers read build provenance and have no
//! environment seam, so the runner here is its own.
//!
//! The head is read by `fuz_release::log_check`, which an install runs when
//! it is given a witness serving `head.json`. The install script reads
//! `latest/` when it is given a release log origin, and never the head.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::SigningKey;
use fuz_artifact::{content_hash_from_binaries, is_release_token};
use fuz_crypto::ContentHash;
use fuz_release::{
    HEAD_FORMAT_VERSION, Head, HeadUnsigned, KeyRecord, LogWriteError, MAX_HEAD_SEQ, MAX_HEAD_SIZE,
    ReleaseLayout, ReleaseLogError, ReleaseRow, RowStatus, SELF_NAME, Succession, TargetField,
    TargetRow, VerifiedHead, check_successor, parse_sidecar, sidecar_content,
};
use fuz_storage::Storage;
use fuz_sys::text::{is_unprintable, truncate};

use crate::backfill::BackfillError;
use crate::revoke::{
    PointerAfter, PointerChange, Revocation, RevokeError, TrackedPointer, next_revoked_head,
    plan_pointers,
};
use crate::sign_head;
use crate::stream::{layout_of, manifest_keys_except, printable};

/// The head document's path in the log repository.
pub const HEAD_FILE: &str = fuz_release::HEAD_KEY;

/// The directory of per-target `latest` pointers in the log repository.
const LATEST_DIR: &str = "latest";

/// The row name [`install_script_entry`] records the install script under.
pub const INSTALL_SCRIPT_NAME: &str = "install.sh";

/// The single target key of an install-script row: the script is one file for
/// every platform.
pub const INSTALL_SCRIPT_TARGET: &str = "any";

/// Mode requested for the files the log write creates. The log is public
/// data, so nothing here is owner-only; the process umask may narrow the
/// mode, and git records only the executable bit.
const LOG_FILE_MODE: u32 = 0o644;

/// Mode requested for the `latest/` directory, on the same terms.
const LOG_DIR_MODE: u32 = 0o755;

/// Most bytes of `git`'s output an error carries.
const MAX_GIT_OUTPUT_LEN: usize = 2048;

/// Most bytes read of a `latest` pointer already in the checkout — a one-line
/// file; anything longer is simply not the expected content.
const MAX_POINTER_READ: u64 = 4096;

/// Most bytes of a caller-supplied value an error carries.
const MAX_ERROR_VALUE_LEN: usize = 128;

/// Most storage keys a refusal of an incomplete first head lists.
const MAX_LISTED_KEYS: usize = 16;

/// A local checkout of the release log repository.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogRepo {
    /// The root of the checkout's work tree.
    pub path: PathBuf,
    /// Extra environment for every `git` process the log write runs, applied
    /// over the inherited environment. Empty in ordinary use — the publisher's
    /// own git configuration and identity apply. It exists so a caller that
    /// must not depend on ambient configuration (a test suite) can pin it.
    pub git_env: Vec<(OsString, OsString)>,
}

impl LogRepo {
    /// A checkout at `path`, with `git` run in the inherited environment.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            git_env: Vec::new(),
        }
    }
}

/// One target of one release, as the log records it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogEntry {
    /// The row name: a tool name, or `fuz` for the self artifact.
    pub name: String,
    /// The release version.
    pub version: String,
    /// The target this publish built for.
    pub target: String,
    /// What the release pins for that target.
    pub pins: TargetRow,
    /// Whether the release publishes a flat binary the shell installer
    /// downloads. When set, `latest/<name>-<target>.sha512` is written to name
    /// this version; it requires `pins.sha512`.
    pub flat_latest: bool,
}

/// What [`upsert_row`] did to the head.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Upsert {
    /// The release had no row; one was appended holding this target.
    RowAdded,
    /// The release's row gained this target.
    TargetAdded,
    /// The row already records this target with identical pins.
    Unchanged,
}

/// Record `entry` in `head`: append the release's row, or add the target to
/// the row it already has.
///
/// An existing target entry is never rewritten. When the row already records
/// the target with exactly these pins the call changes nothing — a repeated
/// publish of the same build is a no-op. When it records the target with any
/// field different the call fails: the log is append-only, and a different
/// build of a logged target is a new version. A revoked row takes nothing,
/// identical or not.
///
/// A new row is `ok` and takes `published_at`; an existing row keeps its own.
/// `seq` is not touched — see [`next_head`].
///
/// # Errors
///
/// [`LogWriteError::RevokedRow`] for a revoked row, and
/// [`LogWriteError::TargetConflict`] naming the first field that differs.
pub fn upsert_row(
    head: &mut HeadUnsigned,
    entry: &LogEntry,
    published_at: &str,
) -> Result<Upsert, LogWriteError> {
    let Some(row) = head
        .rows
        .iter_mut()
        .find(|row| row.name == entry.name && row.version == entry.version)
    else {
        head.rows.push(ReleaseRow {
            name: entry.name.clone(),
            version: entry.version.clone(),
            status: RowStatus::Ok,
            published_at: published_at.to_string(),
            targets: BTreeMap::from([(entry.target.clone(), entry.pins.clone())]),
        });
        return Ok(Upsert::RowAdded);
    };

    if row.status == RowStatus::Revoked {
        return Err(LogWriteError::RevokedRow {
            name: entry.name.clone(),
            version: entry.version.clone(),
        });
    }

    let Some(existing) = row.targets.get(&entry.target) else {
        row.targets.insert(entry.target.clone(), entry.pins.clone());
        return Ok(Upsert::TargetAdded);
    };

    let field = if existing.content_hash != entry.pins.content_hash {
        TargetField::ContentHash
    } else if existing.binaries != entry.pins.binaries {
        TargetField::Binaries
    } else if existing.sha512 != entry.pins.sha512 {
        TargetField::Sha512
    } else {
        return Ok(Upsert::Unchanged);
    };
    Err(LogWriteError::TargetConflict {
        name: entry.name.clone(),
        version: entry.version.clone(),
        target: entry.target.clone(),
        field,
    })
}

/// Record `public_key` in the head's key history if it is not there yet.
///
/// Appends a [`KeyRecord`] with `added_at`; an existing record is left exactly
/// as it is. Returns whether a record was appended. The list is a record for a
/// human reading the log — nothing decides trust from it.
pub fn record_key(head: &mut HeadUnsigned, public_key: &str, added_at: &str) -> bool {
    if head.keys.iter().any(|key| key.public_key == public_key) {
        return false;
    }
    head.keys.push(KeyRecord {
        public_key: public_key.to_string(),
        added_at: added_at.to_string(),
        retired_at: None,
    });
    true
}

/// Sign `next` and prove it may replace `previous`.
///
/// Signs with [`sign_head`], verifies the result as a reader would, and — when
/// there is a `previous` head — requires `check_successor` to report
/// [`Succession::Advanced`]. A publisher that would emit a head with a reused
/// `seq`, a missing row, or a rewritten target fails here, before it has
/// written anything.
///
/// # Errors
///
/// [`LogWriteError::SignedHead`] if the head is structurally invalid or its
/// signature does not verify (the signing key is not one this binary trusts),
/// [`LogWriteError::NotSuccessor`] / [`LogWriteError::NotAdvanced`] if it
/// breaks the append-only rules against `previous`.
pub fn sign_successor(
    previous: Option<&VerifiedHead>,
    next: HeadUnsigned,
    key: &SigningKey,
    signed_at: &str,
) -> Result<VerifiedHead, LogWriteError> {
    let next = sign_head(next, key, signed_at)
        .and_then(Head::verify_signature)
        .map_err(LogWriteError::SignedHead)?;
    if let Some(previous) = previous {
        match check_successor(previous, &next) {
            Ok(Succession::Advanced) => {}
            Ok(Succession::Unchanged) => return Err(LogWriteError::NotAdvanced),
            Err(violation) => return Err(LogWriteError::NotSuccessor(violation)),
        }
    }
    Ok(next)
}

/// The outcome of [`next_head`].
#[derive(Debug, Clone)]
pub enum NextHead {
    /// The head already records the entry; there is nothing to sign.
    Unchanged,
    /// The signed, verified head that records the entry.
    Advanced(Box<VerifiedHead>),
}

/// Build and sign the head that records `entry` on top of `previous`.
///
/// With no `previous` this is the log's first head: `seq` 1. Otherwise it is
/// `previous` with the entry upserted ([`upsert_row`]), the signing key
/// recorded ([`record_key`]), and `seq` one greater — signed and checked by
/// [`sign_successor`]. An entry the head already records identically yields
/// [`NextHead::Unchanged`]: no new `seq`, no signature.
///
/// `now` is the new row's `published_at`, a new key record's `added_at`, and
/// the signature's `signed_at`.
///
/// # Errors
///
/// The errors of [`upsert_row`] and [`sign_successor`], and
/// [`LogWriteError::SeqExhausted`] if `previous` is at the last `seq`.
pub fn next_head(
    previous: Option<&VerifiedHead>,
    entry: &LogEntry,
    key: &SigningKey,
    now: &str,
) -> Result<NextHead, LogWriteError> {
    let mut unsigned = previous.map_or_else(
        || HeadUnsigned {
            format: HEAD_FORMAT_VERSION,
            seq: 0,
            keys: Vec::new(),
            rows: Vec::new(),
        },
        VerifiedHead::to_unsigned,
    );
    if upsert_row(&mut unsigned, entry, now)? == Upsert::Unchanged {
        return Ok(NextHead::Unchanged);
    }
    record_key(&mut unsigned, &public_key_of(key), now);
    advance_seq(&mut unsigned)?;
    sign_successor(previous, unsigned, key, now).map(|head| NextHead::Advanced(Box::new(head)))
}

/// Give `head` the next `seq`.
///
/// # Errors
///
/// [`LogWriteError::SeqExhausted`] if it is at the last one.
pub(crate) fn advance_seq(head: &mut HeadUnsigned) -> Result<(), LogWriteError> {
    head.seq = head
        .seq
        .checked_add(1)
        .filter(|seq| *seq <= MAX_HEAD_SEQ)
        .ok_or(LogWriteError::SeqExhausted(head.seq))?;
    Ok(())
}

/// The base64 public key of `key`, as a head's key history records it.
pub(crate) fn public_key_of(key: &SigningKey) -> String {
    STANDARD.encode(key.verifying_key().as_bytes())
}

/// Build the log entry for an install script.
///
/// Row name [`INSTALL_SCRIPT_NAME`], the given `version`, the single target
/// [`INSTALL_SCRIPT_TARGET`]. It pins the script as a one-binary release:
/// `binaries` is `{"install.sh": blake3(script)}`, `content_hash` is the
/// content hash of that one-entry set (`content_hash_from_binaries`), and
/// `sha512` is the script's SHA-512. `flat_latest` is unset, so recording it
/// writes no `latest/` file. It goes through [`upsert_row`] like any entry: the
/// same script at the same version is a no-op, a changed script at the same
/// version is a conflict.
///
/// No command calls this. It is the building block for logging the script so
/// that a reader can download it, compare it against the log, and then run it.
#[must_use]
pub fn install_script_entry(version: &str, script: &[u8]) -> LogEntry {
    let binaries = BTreeMap::from([(INSTALL_SCRIPT_NAME.to_string(), ContentHash::blake3(script))]);
    LogEntry {
        name: INSTALL_SCRIPT_NAME.to_string(),
        version: version.to_string(),
        target: INSTALL_SCRIPT_TARGET.to_string(),
        pins: TargetRow {
            content_hash: content_hash_from_binaries(&binaries),
            binaries,
            sha512: Some(ContentHash::sha512(script)),
        },
        flat_latest: false,
    }
}

/// The path, relative to the log repository root, of the `latest` pointer for
/// `name` on `target`.
pub(crate) fn latest_pointer_path(name: &str, target: &str) -> String {
    format!("{LATEST_DIR}/{name}-{target}.sha512")
}

/// What [`record_release`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogOutcome {
    /// The row name.
    pub name: String,
    /// The release version.
    pub version: String,
    /// The target recorded.
    pub target: String,
    /// The `seq` of the head that records the entry.
    pub seq: u64,
    /// Whether this call signed a new head. False when the head already
    /// recorded the entry identically.
    pub advanced: bool,
    /// Whether the branch's remote-tracking ref was behind the commit before
    /// the push. False when it already named it.
    pub pushed: bool,
}

/// One line saying what a publish recorded in the release log — the `log:`
/// line both publish CLIs (`cargo xtask publish`, `fuzf tool publish`) print.
impl std::fmt::Display for LogOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} {} {} at seq {} ({}, {})",
            self.name,
            self.version,
            self.target,
            self.seq,
            if self.advanced {
                "head signed"
            } else {
                "already recorded"
            },
            if self.pushed {
                "pushed"
            } else {
                "remote-tracking ref already current"
            },
        )
    }
}

/// Check that the release log checkout `repo` can record `entry`, writing
/// nothing but a fast-forward.
///
/// The first half of [`record_release`], run on its own before a publish
/// uploads anything: every check that needs no release bytes in storage. A
/// publish whose log cannot take the entry — a missing or dirty checkout, an
/// unverifiable head, a conflicting or revoked entry, a signing key this binary
/// does not trust, a first head that would leave out releases storage already
/// holds — stops here, with release storage untouched.
///
/// `storage` is listed, never written, and only when the log has no head.
///
/// # Errors
///
/// A [`LogWriteError`] per steps 1–6 of [`record_release`].
pub async fn check_release(
    storage: &impl Storage,
    repo: &LogRepo,
    entry: &LogEntry,
    key: &SigningKey,
    now: &str,
) -> Result<(), LogWriteError> {
    let prepared = PreparedLog::prepare(repo, entry, key, now)?;
    prepared.require_complete_first_head(storage, entry).await
}

/// Record `entry` in the release log checkout `repo`, commit, and push.
///
/// In order:
///
/// 1. **Check the entry.** Name, version, and target must be head tokens
///    (`is_release_token`) — they become a file name and a commit message —
///    as must each binary name, which a head records; and only the self
///    artifact may ask for a `latest/` pointer.
/// 2. **Check the checkout.** `repo.path` is the root of a git work tree, on a
///    branch with an upstream, with no uncommitted change to `head.json` or
///    `latest/`, no ignore rule covering them, and none of them a symlink.
/// 3. **Fast-forward.** Fetch the upstream's remote and fast-forward to it. A
///    checkout that has diverged from its upstream is refused; nothing is
///    merged, rebased, or forced. Local commits the upstream lacks are kept —
///    they are an earlier log write whose push did not land. Then require that
///    a plain `git push` updates that upstream.
/// 4. **Read and verify the existing head.** A `head.json` that does not parse
///    or verify is never overwritten.
/// 5. **Check the key and sign the next head** ([`next_head`]). The signing key
///    must be one this binary trusts, whether or not a head is signed; nothing
///    is signed when the head already records the entry.
/// 6. **Require a first head to be complete.** When the log has no head, this
///    write would create it with one row. `storage` is listed — the self
///    stream and every first-party tool stream — and the write is refused
///    ([`LogWriteError::UnloggedReleases`]) if any stream holds a manifest
///    other than this entry's own: a first head that left a published release
///    out would be an incomplete log, which `crate::backfill` exists to
///    prevent. The entry's own manifest is allowed, so the first publish can
///    be run again after its upload. Manifests are not read; a listing that
///    fails is a refusal ([`LogWriteError::Storage`]). A log that has a head
///    is never held to storage, and storage is never written.
/// 7. **Write** `head.json` (`Head::to_json`, the one serializer) and, for an
///    entry with `flat_latest`, `latest/<name>-<target>.sha512`: one
///    `sha512sum`-format line whose file name is the versioned flat binary as
///    `ReleaseLayout` names it on release storage. A shell reads that file for
///    both the digest and the version.
/// 8. **Commit** the written files whose staged content changed, and only those,
///    with the message `log: <name> <version> <target> seq <seq>`. If a write,
///    the staging, or the commit fails, the files are restored to the last
///    commit before the error is returned.
/// 9. **Push** the current branch with a plain `git push`, and confirm the
///    branch's remote-tracking ref now names the commit.
/// 10. **Read the pushed log back.** The `head.json` in the commit the
///     remote-tracking ref names must verify and record this entry exactly,
///     and its `latest/` pointer, for an entry that has one, must name this
///     release. `Ok` means the pushed log holds the entry — whatever the work
///     tree, the index, or a hook did along the way.
///
/// Steps 1–6 write nothing but the fast-forward; [`check_release`] runs them
/// alone.
///
/// The `latest/` pointer moves on every call for a `flat_latest` entry, as
/// the target's latest pointer does on every publish — including a repeated publish of an
/// older version, which changes no head but still moves the pointer (its
/// commit message is `log: latest <name> <version> <target> seq <seq>`).
///
/// **Retry.** A failed commit is rolled back, so the same publish can simply
/// run again. A failure after the commit (a refused or unreachable push)
/// leaves the commit in the checkout; running the same publish again finds the
/// entry already recorded, signs nothing, and pushes the waiting commit. The
/// push runs on every call — git does nothing when a push URL is up to date —
/// so a remote with several push URLs, one of which refused, is completed by
/// the retry.
///
/// Only `head.json` and `latest/*.sha512` are written or staged. The signing
/// key is used in memory to sign; no path to it is known here.
///
/// Blocking: runs `git` and waits for it, with no timeout.
///
/// # Errors
///
/// A [`LogWriteError`] per the steps above.
pub async fn record_release(
    storage: &impl Storage,
    repo: &LogRepo,
    entry: &LogEntry,
    key: &SigningKey,
    now: &str,
) -> Result<LogOutcome, LogWriteError> {
    let prepared = PreparedLog::prepare(repo, entry, key, now)?;
    prepared.require_complete_first_head(storage, entry).await?;
    let seq = prepared.seq;
    let committed = prepared.commit()?;
    Ok(LogOutcome {
        name: entry.name.clone(),
        version: entry.version.clone(),
        target: entry.target.clone(),
        seq,
        advanced: committed.advanced,
        pushed: committed.pushed,
    })
}

/// A log write that has passed every check and is ready to modify the
/// checkout. Produced only by [`PreparedLog::prepare`] and consumed by
/// [`PreparedLog::commit`], so nothing is written to a checkout that was not
/// checked.
#[derive(Debug)]
pub(crate) struct PreparedLog<'a> {
    git: Git<'a>,
    subject: Subject<'a>,
    branch: String,
    /// The `seq` of the head that records what this write logs.
    seq: u64,
    /// The signed next head's document, when the log does not record it yet.
    head_json: Option<String>,
    /// The `latest` pointers this write owns: each one's repository-relative
    /// path and content.
    pointers: Vec<(String, String)>,
    /// The `latest` pointers this write removes, by repository-relative path.
    removed: Vec<String>,
    /// Every target entry the pushed head must record for the write to count
    /// as published.
    expected: Vec<ExpectedTarget>,
    /// Whether the log has no head, so that this write creates it from one
    /// entry.
    first_head: bool,
}

/// What a prepared log write records — it words the commit.
#[derive(Debug)]
enum Subject<'a> {
    /// One target of one release, recorded by a publish.
    Entry(&'a LogEntry),
    /// The log's first head, holding the releases already in storage.
    Genesis {
        /// How many releases — rows — the head holds.
        releases: usize,
    },
    /// The revocation of one release.
    Revoke {
        /// The row name.
        name: String,
        /// The release version.
        version: String,
    },
}

/// One target entry a log write records, as the read-back looks it up.
#[derive(Debug)]
struct ExpectedTarget {
    name: String,
    version: String,
    target: String,
    pins: TargetRow,
}

/// What [`PreparedLog::commit`] did.
#[derive(Debug, Clone, Copy)]
struct Committed {
    /// Whether a new head was written.
    advanced: bool,
    /// Whether the branch's remote-tracking ref was behind the commit before
    /// the push.
    pushed: bool,
}

/// The commit subject of the log's first head.
pub(crate) fn genesis_commit_message(releases: usize, seq: u64) -> String {
    format!("log: backfill {releases} releases seq {seq}")
}

/// The commit subject of a revocation: of the head that records it, or — when
/// the head already does (`advanced` unset) — of a commit that only moves or
/// removes `latest/` pointers still naming the revoked release.
pub(crate) fn revoke_commit_message(name: &str, version: &str, seq: u64, advanced: bool) -> String {
    let latest_only = if advanced { "" } else { "latest " };
    format!("log: {latest_only}revoke {name} {version} seq {seq}")
}

/// Steps 2–3 of [`record_release`]: open the checkout, check it, and bring it
/// up to its upstream. `pointers` are the `latest` pointers the write owns;
/// their paths are held to the same rules as `head.json`.
fn open_checkout<'a>(
    repo: &'a LogRepo,
    pointers: &[(String, String)],
) -> Result<(Git<'a>, String), LogWriteError> {
    // Checked before the fast-forward, and again once it has brought the tree
    // this write lands on.
    fn require_plain_paths(
        git: &Git<'_>,
        pointers: &[(String, String)],
    ) -> Result<(), LogWriteError> {
        require_plain(&git.root.join(HEAD_FILE), PathKind::File)?;
        for (path, _) in pointers {
            require_plain(&git.root.join(LATEST_DIR), PathKind::Directory)?;
            require_plain(&git.root.join(path), PathKind::File)?;
        }
        Ok(())
    }

    let git = Git::open(repo)?;
    git.require_clean()?;
    require_plain_paths(&git, pointers)?;
    git.require_not_ignored(HEAD_FILE)?;
    for (path, _) in pointers {
        git.require_not_ignored(path)?;
    }
    let branch = git.branch()?;
    let remote = git.upstream_remote(&branch)?;
    git.fast_forward(&branch, &remote)?;
    git.require_push_to_upstream(&branch)?;
    require_plain_paths(&git, pointers)?;
    Ok((git, branch))
}

/// Require the signing key to be one this binary trusts: no head it signs
/// would verify otherwise.
fn require_trusted(key: &SigningKey) -> Result<(), LogWriteError> {
    let public_key = key.verifying_key();
    if fuz_crypto::is_trusted_key(&public_key) {
        Ok(())
    } else {
        Err(LogWriteError::UntrustedKey {
            public_key: STANDARD.encode(public_key.as_bytes()),
        })
    }
}

/// Refuse a log that has a head: a `head.json` in the commit the branch's
/// upstream names, in the last commit, or in the work tree.
///
/// After the fast-forward the three agree for a checkout in step with its
/// upstream. They are read separately because they say different things when
/// they disagree: a head on the upstream is the log's head, whatever the
/// checkout holds, and a head only in the last commit is one that was written
/// here and never pushed.
fn require_no_head(git: &Git<'_>, branch: &str) -> Result<(), BackfillError> {
    match committed_head(git, branch)? {
        Some(CommittedHead::Upstream) => return Err(BackfillError::HeadExists),
        Some(CommittedHead::LastCommit) => return Err(BackfillError::HeadUnpublished),
        None => {}
    }
    if require_plain(&git.root.join(HEAD_FILE), PathKind::File)? {
        return Err(BackfillError::HeadExists);
    }
    Ok(())
}

/// A commit that holds a `head.json`.
#[derive(Debug, Clone, Copy)]
enum CommittedHead {
    /// The commit the branch's upstream names: the log's own head.
    Upstream,
    /// The checkout's last commit alone: a head written here and not pushed.
    LastCommit,
}

/// Which commit holds a `head.json`: the one the branch's upstream names, else
/// the checkout's last commit, else neither.
fn committed_head(git: &Git<'_>, branch: &str) -> Result<Option<CommittedHead>, LogWriteError> {
    let in_commit = |revision: &str| -> Result<bool, LogWriteError> {
        Ok(git.resolve(revision)?.is_some()
            && git.resolve(&format!("{revision}:{HEAD_FILE}"))?.is_some())
    };
    Ok(if in_commit(&upstream_of(branch))? {
        Some(CommittedHead::Upstream)
    } else if in_commit("HEAD")? {
        Some(CommittedHead::LastCommit)
    } else {
        None
    })
}

/// Read and verify the work tree's `head.json`, and refuse a work tree that
/// has none while a commit does.
///
/// A work tree with no `head.json` reads as a log with no head, and a write
/// into such a log signs a first head — `seq` 1, checked against no
/// predecessor. That is only true of the log when its commits agree. A clean
/// work tree can lack the file while the upstream or the last commit holds
/// it: a local commit that deleted it and was not pushed, or a file removed
/// behind an assume-unchanged or skip-worktree flag. Taking that for a log
/// with no head would push a first head over the log's history.
fn read_log_head(git: &Git<'_>, branch: &str) -> Result<Option<VerifiedHead>, LogWriteError> {
    let head = read_head(&git.root.join(HEAD_FILE))?;
    if head.is_none() {
        let held_by = match committed_head(git, branch)? {
            Some(CommittedHead::Upstream) => "its upstream",
            Some(CommittedHead::LastCommit) => "its last commit",
            None => return Ok(None),
        };
        return Err(LogWriteError::HeadMissing { held_by });
    }
    Ok(head)
}

/// Refuse a checkout whose last commit tracks a file under `latest/` that is
/// not one of `pointers`. The log's first commit would otherwise carry a
/// pointer its head never vouched for.
fn require_no_stray_pointers(
    git: &Git<'_>,
    pointers: &[(String, String)],
) -> Result<(), BackfillError> {
    if git.resolve("HEAD")?.is_none() {
        return Ok(());
    }
    // NUL-separated: git prints each path as it is, not quoted.
    let tracked = git.run_ok(&[
        "ls-tree",
        "-r",
        "-z",
        "--name-only",
        "HEAD",
        "--",
        LATEST_DIR,
    ])?;
    let paths: Vec<String> = tracked
        .split('\0')
        .filter(|tracked| !tracked.is_empty())
        .filter(|tracked| !pointers.iter().any(|(path, _)| path == tracked))
        .map(str::to_string)
        .collect();
    if paths.is_empty() {
        Ok(())
    } else {
        Err(BackfillError::StrayPointers { paths })
    }
}

/// Check that the checkout `repo` can take the log's first head, writing
/// nothing but a fast-forward: every checkout requirement of
/// [`record_release`], a log with no head, and a signing key this binary
/// trusts.
pub(crate) fn check_genesis(repo: &LogRepo, key: &SigningKey) -> Result<(), BackfillError> {
    let (git, branch) = open_checkout(repo, &[])?;
    require_no_head(&git, &branch)?;
    require_trusted(key)?;
    Ok(())
}

impl<'a> PreparedLog<'a> {
    /// Steps 1–5 of [`record_release`].
    fn prepare(
        repo: &'a LogRepo,
        entry: &'a LogEntry,
        key: &SigningKey,
        now: &str,
    ) -> Result<Self, LogWriteError> {
        check_entry(entry)?;
        let pointers: Vec<(String, String)> = latest_pointer(entry).into_iter().collect();
        let (git, branch) = open_checkout(repo, &pointers)?;
        let previous = read_log_head(&git, &branch)?;
        // Checked whether or not this run signs: a release the log already
        // records is still re-uploaded and re-advertised under this key's
        // manifest signature, and a key that could not have signed the log
        // must not do that either.
        require_trusted(key)?;
        let (seq, head_json) = match next_head(previous.as_ref(), entry, key, now)? {
            NextHead::Advanced(head) => {
                let json = head
                    .to_json()
                    .map_err(|e| LogWriteError::SignedHead(ReleaseLogError::from(e)))?;
                (head.seq(), Some(json))
            }
            NextHead::Unchanged => (previous.as_ref().map_or(0, VerifiedHead::seq), None),
        };
        Ok(Self {
            git,
            subject: Subject::Entry(entry),
            branch,
            seq,
            head_json,
            pointers,
            removed: Vec::new(),
            expected: vec![ExpectedTarget {
                name: entry.name.clone(),
                version: entry.version.clone(),
                target: entry.target.clone(),
                pins: entry.pins.clone(),
            }],
            // No head in the work tree, the last commit, or the upstream
            // (`read_log_head`): the log has none, and this write creates it.
            first_head: previous.is_none(),
        })
    }

    /// Step 6 of [`record_release`]: a write that would create the log's head
    /// from `entry` alone requires that storage holds no other release.
    async fn require_complete_first_head(
        &self,
        storage: &impl Storage,
        entry: &LogEntry,
    ) -> Result<(), LogWriteError> {
        if !self.first_head {
            return Ok(());
        }
        let own_key =
            layout_of(&entry.name).manifest_key(&entry.name, &entry.version, &entry.target);
        let others = manifest_keys_except(storage, &own_key)
            .await
            .map_err(LogWriteError::Storage)?;
        if others.is_empty() {
            Ok(())
        } else {
            Err(LogWriteError::UnloggedReleases {
                keys: describe_storage_keys(&others),
            })
        }
    }

    /// Prepare the revocation of `name` `version`: the checks of a publish's
    /// log write, a log that has a verifiable head with that release as a row,
    /// the head that records the row as revoked, and what becomes of each
    /// `latest/` pointer that names the release.
    ///
    /// Writes nothing but the fast-forward. Only the release's own pointers
    /// are read — `latest/<name>-<target>.sha512` for each of its targets —
    /// and from the last commit, what the log tracks, not from the work tree,
    /// whose bytes a line-ending conversion may have changed.
    pub(crate) fn prepare_revocation(
        repo: &'a LogRepo,
        name: &str,
        version: &str,
        key: &SigningKey,
        now: &str,
    ) -> Result<(Self, PreparedRevocation), RevokeError> {
        let (git, branch) = open_checkout(repo, &[])?;
        let Some(previous) = read_log_head(&git, &branch)? else {
            return Err(RevokeError::NoHead);
        };
        require_trusted(key)?;
        let Some(row) = previous.row(name, version) else {
            return Err(RevokeError::UnknownRelease {
                name: name.to_string(),
                version: version.to_string(),
            });
        };
        let targets: Vec<String> = row.targets.keys().cloned().collect();

        let (head, revocation) = match next_revoked_head(&previous, name, version, key, now)? {
            NextHead::Advanced(head) => (*head, Revocation::Revoked),
            NextHead::Unchanged => (previous, Revocation::AlreadyRevoked),
        };
        let advanced = revocation == Revocation::Revoked;
        let head_json = if advanced {
            Some(
                head.to_json()
                    .map_err(|e| LogWriteError::SignedHead(ReleaseLogError::from(e)))?,
            )
        } else {
            None
        };

        let tracked = consulted_pointers(&git, name, &targets)?;
        let changes = plan_pointers(head.rows(), &tracked, name, version);
        let mut pointers = Vec::new();
        let mut removed = Vec::new();
        for change in &changes {
            // Held to the rules of every path this write touches.
            require_plain(&git.root.join(LATEST_DIR), PathKind::Directory)?;
            require_plain(&git.root.join(&change.path), PathKind::File)?;
            git.require_not_ignored(&change.path)?;
            match &change.after {
                PointerAfter::Moved { content, .. } => {
                    pointers.push((change.path.clone(), content.clone()));
                }
                PointerAfter::Removed => removed.push(change.path.clone()),
            }
        }

        let commit_message = (advanced || !changes.is_empty())
            .then(|| revoke_commit_message(name, version, head.seq(), advanced));
        let prepared = Self {
            git,
            subject: Subject::Revoke {
                name: name.to_string(),
                version: version.to_string(),
            },
            branch,
            seq: head.seq(),
            head_json,
            pointers,
            removed,
            expected: Vec::new(),
            first_head: false,
        };
        Ok((
            prepared,
            PreparedRevocation {
                targets,
                seq: head.seq(),
                revocation,
                pointers: changes,
                commit_message,
            },
        ))
    }

    /// Prepare the write of the log's first head: `head`, already signed and
    /// verified, and the `latest` pointers that go with it.
    ///
    /// The checkout is held to every requirement of [`record_release`], and
    /// the log must have no head — this write creates the log, it never
    /// replaces a head.
    pub(crate) fn prepare_genesis(
        repo: &'a LogRepo,
        head: &VerifiedHead,
        pointers: Vec<(String, String)>,
        key: &SigningKey,
    ) -> Result<Self, BackfillError> {
        let (git, branch) = open_checkout(repo, &pointers)?;
        require_no_head(&git, &branch)?;
        require_no_stray_pointers(&git, &pointers)?;
        require_trusted(key)?;
        let json = head
            .to_json()
            .map_err(|e| LogWriteError::SignedHead(ReleaseLogError::from(e)))?;
        let expected = head
            .rows()
            .iter()
            .flat_map(|row| {
                row.targets.iter().map(|(target, pins)| ExpectedTarget {
                    name: row.name.clone(),
                    version: row.version.clone(),
                    target: target.clone(),
                    pins: pins.clone(),
                })
            })
            .collect();
        Ok(Self {
            git,
            subject: Subject::Genesis {
                releases: head.rows().len(),
            },
            branch,
            seq: head.seq(),
            head_json: Some(json),
            pointers,
            removed: Vec::new(),
            expected,
            first_head: false,
        })
    }

    /// Steps 7–10 of [`record_release`].
    fn commit(self) -> Result<Committed, LogWriteError> {
        let advanced = self.write()?;
        let pushed = self.push()?;
        self.require_published()?;
        Ok(Committed { advanced, pushed })
    }

    /// Steps 7–8 of [`record_release`]: write the head and the pointers,
    /// remove the pointers this write removes, and commit. Returns whether a
    /// new head was written. A failure leaves the checkout as it was.
    pub(crate) fn write(&self) -> Result<bool, LogWriteError> {
        let advanced = self.head_json.is_some();
        let mut files: Vec<(&str, &str)> = Vec::new();
        if let Some(json) = &self.head_json {
            files.push((HEAD_FILE, json));
        }
        for (path, content) in &self.pointers {
            let on_disk = read_plain(&self.git.root.join(path), MAX_POINTER_READ)?;
            if on_disk.as_deref() != Some(content.as_bytes()) {
                files.push((path, content));
            }
        }
        // Only what the last commit tracks is there to remove.
        let mut removals: Vec<&str> = Vec::new();
        for path in &self.removed {
            if self.git.resolve(&format!("HEAD:{path}"))?.is_some() {
                removals.push(path);
            }
        }

        if !files.is_empty() || !removals.is_empty() {
            let latest_dir = self.git.root.join(LATEST_DIR);
            let created_latest_dir = !latest_dir.exists();
            if let Err(error) = self.write_and_commit(&files, &removals, advanced) {
                let mut paths: Vec<&str> = files.iter().map(|(path, _)| *path).collect();
                paths.extend(&removals);
                let rolled_back = self
                    .git
                    .roll_back(&paths, created_latest_dir.then_some(&latest_dir));
                return Err(with_rollback_note(error, rolled_back));
            }
            if !removals.is_empty() {
                // Git tracks no empty directory; fails, harmlessly, when a
                // pointer is still in it.
                let _ = std::fs::remove_dir(&latest_dir);
            }
        }
        Ok(advanced)
    }

    /// Step 9 of [`record_release`]: push. Returns whether the remote-tracking
    /// ref was behind before the push. A failure leaves the commit in the
    /// checkout, unpushed.
    pub(crate) fn push(&self) -> Result<bool, LogWriteError> {
        self.git.push(&self.branch)
    }

    /// Write `files`, delete `removals`, stage both, then commit the paths
    /// whose staged content differs from the last commit.
    ///
    /// The index decides what changed, not a byte comparison of the work tree:
    /// a checkout that converts line endings holds a pointer whose bytes differ
    /// from the ones written here while its committed content is the same, and
    /// there is then nothing to commit.
    fn write_and_commit(
        &self,
        files: &[(&str, &str)],
        removals: &[&str],
        advanced: bool,
    ) -> Result<(), LogWriteError> {
        for (relative, content) in files {
            let path = self.git.root.join(relative);
            if let Some(parent) = path.parent() {
                fuz_sys::fs::create_dir_all_mode(parent, LOG_DIR_MODE)
                    .map_err(|source| io_error(parent, source))?;
            }
            fuz_sys::fs::write_atomic(&path, content.as_bytes(), LOG_FILE_MODE)
                .map_err(|source| io_error(&path, source))?;
        }
        for relative in removals {
            let path = self.git.root.join(relative);
            match std::fs::remove_file(&path) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(source) => return Err(io_error(&path, source)),
            }
        }
        let mut paths: Vec<&str> = files.iter().map(|(relative, _)| *relative).collect();
        paths.extend(removals);
        // Naming a tracked path whose file is gone stages its removal.
        self.git.stage(&paths)?;
        let mut changed = Vec::new();
        for path in paths {
            if self.git.is_staged_change(path)? {
                changed.push(path);
            }
        }
        if changed.is_empty() {
            return Ok(());
        }
        let message = match &self.subject {
            Subject::Entry(entry) => {
                let latest_only = if advanced { "" } else { "latest " };
                format!(
                    "log: {latest_only}{} {} {} seq {}",
                    entry.name, entry.version, entry.target, self.seq
                )
            }
            Subject::Genesis { releases } => genesis_commit_message(*releases, self.seq),
            Subject::Revoke { name, version } => {
                revoke_commit_message(name, version, self.seq, advanced)
            }
        };
        self.git.commit(&message, &changed)
    }

    /// Step 10 of [`record_release`]: the commit the branch's remote-tracking
    /// ref names holds what this write records — each entry, or the
    /// revocation, and each `latest/` pointer as the write left it, a removed
    /// one absent.
    ///
    /// Read from git's object store, not the work tree. A file git was told to
    /// ignore or to assume unchanged, or one a hook rewrote before the commit,
    /// leaves a work tree that looks right and a pushed commit that is not.
    pub(crate) fn require_published(&self) -> Result<(), LogWriteError> {
        // The error names what the write records: the revoked release, or an
        // entry — the one found missing, or the first when the failure is not
        // about any one of them.
        let not_published = |entry: Option<&ExpectedTarget>, detail| {
            if let Subject::Revoke { name, version } = &self.subject {
                return LogWriteError::NotRevoked {
                    name: name.clone(),
                    version: version.clone(),
                    detail,
                };
            }
            let name = |field: fn(&ExpectedTarget) -> &String| {
                entry
                    .or_else(|| self.expected.first())
                    .map(field)
                    .cloned()
                    .unwrap_or_default()
            };
            LogWriteError::NotPublished {
                name: name(|entry| &entry.name),
                version: name(|entry| &entry.version),
                target: name(|entry| &entry.target),
                detail,
            }
        };
        let Some(commit) = self.git.resolve(&upstream_of(&self.branch))? else {
            return Err(not_published(
                None,
                "the branch has no remote-tracking commit",
            ));
        };
        let too_large = "a file in the pushed commit is larger than the log allows";
        let document = match self.git.read_blob(&commit, HEAD_FILE, MAX_HEAD_SIZE)? {
            Blob::Content(document) => document,
            Blob::Absent => {
                return Err(not_published(None, "the pushed commit has no head.json"));
            }
            Blob::TooLarge => return Err(not_published(None, too_large)),
        };
        let head = Head::from_json(&document)
            .and_then(Head::verify_signature)
            .map_err(LogWriteError::PublishedHead)?;
        for entry in &self.expected {
            if head.target(&entry.name, &entry.version, &entry.target) != Some(&entry.pins) {
                return Err(not_published(
                    Some(entry),
                    "the pushed head.json does not record this entry",
                ));
            }
        }
        if let Subject::Revoke { name, version } = &self.subject {
            let is_revoked = head
                .row(name, version)
                .is_some_and(|row| row.status == RowStatus::Revoked);
            if !is_revoked {
                return Err(not_published(
                    None,
                    "the pushed head.json does not record the release as revoked",
                ));
            }
        }
        let wrong_pointer = match &self.subject {
            Subject::Revoke { .. } => {
                "a pushed latest/ pointer is not the one the revocation wrote"
            }
            Subject::Entry(_) | Subject::Genesis { .. } => {
                "the pushed latest/ pointer does not name this release"
            }
        };
        for (path, content) in &self.pointers {
            match self.git.read_blob(&commit, path, MAX_POINTER_READ)? {
                Blob::Content(pushed) if pushed == content.as_bytes() => {}
                Blob::TooLarge => return Err(not_published(None, too_large)),
                Blob::Content(_) | Blob::Absent => {
                    return Err(not_published(None, wrong_pointer));
                }
            }
        }
        for path in &self.removed {
            if self.git.resolve(&format!("{commit}:{path}"))?.is_some() {
                return Err(not_published(
                    None,
                    "the pushed commit still holds a latest/ pointer the revocation removes",
                ));
            }
        }
        Ok(())
    }
}

/// What [`PreparedLog::prepare_revocation`] worked out, for the report.
#[derive(Debug)]
pub(crate) struct PreparedRevocation {
    /// The targets of the revoked release.
    pub(crate) targets: Vec<String>,
    /// The `seq` of the head that records the revocation.
    pub(crate) seq: u64,
    /// Whether the head had to change.
    pub(crate) revocation: Revocation,
    /// What becomes of each pointer that names the revoked release.
    pub(crate) pointers: Vec<PointerChange>,
    /// The subject of the commit the write makes; `None` when there is nothing
    /// to commit.
    pub(crate) commit_message: Option<String>,
}

/// The mode git records for a regular, non-executable file — the only kind
/// of entry the log holds.
const PLAIN_FILE_MODE: &str = "100644";

/// The `latest/` pointers of `name` for `targets` that the last commit tracks,
/// each parsed.
///
/// Only these paths are read: they are the ones a revocation of `name` can
/// change, and anything else under `latest/` is not its concern. A consulted
/// path the last commit tracks as anything but a plain file — a symlink, an
/// executable, a directory — is refused as the unsafe path a publish refuses
/// in the work tree, and one that is not a `sha512sum`-format line is an
/// error rather than something to step over: the caller is deciding whether
/// the pointer names a release, and cannot for one it cannot read.
fn consulted_pointers(
    git: &Git<'_>,
    name: &str,
    targets: &[String],
) -> Result<Vec<TrackedPointer>, RevokeError> {
    if git.resolve("HEAD")?.is_none() {
        return Ok(Vec::new());
    }
    let mut pointers = Vec::new();
    for target in targets {
        let path = latest_pointer_path(name, target);
        // `<mode> <type> <object>\t<path>`, NUL-terminated; nothing when the
        // commit has no such path.
        let entry = git.run_ok(&["ls-tree", "-z", "HEAD", "--", path.as_str()])?;
        let Some(mode) = entry.split_whitespace().next() else {
            continue;
        };
        if mode != PLAIN_FILE_MODE {
            return Err(LogWriteError::UnsafePath {
                path: git.root.join(&path),
                expected: "file",
            }
            .into());
        }
        let unreadable = |reason| RevokeError::Pointer {
            path: path.clone(),
            reason,
        };
        let bytes = match git.read_blob("HEAD", &path, MAX_POINTER_READ)? {
            Blob::Content(bytes) => bytes,
            Blob::TooLarge => return Err(unreadable("too large")),
            Blob::Absent => return Err(unreadable("not a file")),
        };
        let (_, file_name) = parse_sidecar(&bytes).map_err(unreadable)?;
        pointers.push(TrackedPointer {
            path: path.clone(),
            file_name: file_name.to_string(),
        });
    }
    Ok(pointers)
}

/// Storage keys as the lines of an error message: each on its own line,
/// escaped and bounded, and no more than [`MAX_LISTED_KEYS`] of them.
fn describe_storage_keys(keys: &[String]) -> String {
    let mut out = String::new();
    for key in keys.iter().take(MAX_LISTED_KEYS) {
        out.push_str("\n  ");
        out.push_str(&printable(key));
    }
    if keys.len() > MAX_LISTED_KEYS {
        out.push_str("\n  (and ");
        out.push_str(&(keys.len() - MAX_LISTED_KEYS).to_string());
        out.push_str(" more)");
    }
    out
}

/// `error` with a note of what the rollback could not undo. The original error
/// stays the error: a rollback that fails explains the state it left, it does
/// not replace the reason the write failed.
fn with_rollback_note(error: LogWriteError, rolled_back: Result<(), String>) -> LogWriteError {
    let Err(failure) = rolled_back else {
        return error;
    };
    let note = format!(
        "(the log checkout was not fully restored: {})",
        bounded(&failure, MAX_ERROR_VALUE_LEN * 2)
    );
    match error {
        LogWriteError::Git { command, output } => LogWriteError::Git {
            command,
            output: format!("{output}\n{note}"),
        },
        LogWriteError::Io { path, source } => LogWriteError::Io {
            path,
            source: std::io::Error::new(source.kind(), format!("{source} {note}")),
        },
        other => other,
    }
}

/// Hold the entry's name, version, and target to the head's token rule before
/// any of them reaches a path or a command line, its binary names to the same
/// rule before a head is built from them, and require what a `latest` pointer
/// is written from.
///
/// A head with a binary name that is not a token would not sign; refusing the
/// entry here names the entry as what is wrong, before the checkout is opened.
fn check_entry(entry: &LogEntry) -> Result<(), LogWriteError> {
    let binaries = entry
        .pins
        .binaries
        .keys()
        .map(|binary| ("binary name", binary));
    for (field, value) in [
        ("name", &entry.name),
        ("version", &entry.version),
        ("target", &entry.target),
    ]
    .into_iter()
    .chain(binaries)
    {
        if !is_release_token(value) {
            // Cut only: the message quotes and escapes the value, so what makes
            // it invalid is shown rather than blanked.
            return Err(LogWriteError::InvalidEntry {
                field,
                value: truncate(value, MAX_ERROR_VALUE_LEN),
            });
        }
    }
    if entry.flat_latest {
        // `latest/<name>-<target>.sha512` splits into a name and a target only
        // when the name is known: both may contain `-`.
        if entry.name != SELF_NAME {
            return Err(LogWriteError::InvalidEntry {
                field: "flat_latest",
                value: truncate(&entry.name, MAX_ERROR_VALUE_LEN),
            });
        }
        if entry.pins.sha512.is_none() {
            return Err(LogWriteError::InvalidEntry {
                field: "sha512",
                value: String::new(),
            });
        }
    }
    Ok(())
}

/// The `latest` pointer for `entry` — its repository-relative path and its
/// content — when the entry publishes a flat binary.
fn latest_pointer(entry: &LogEntry) -> Option<(String, String)> {
    let sha512 = entry.pins.sha512.as_ref().filter(|_| entry.flat_latest)?;
    Some(self_latest_pointer(
        &entry.name,
        &entry.version,
        &entry.target,
        sha512,
    ))
}

/// The `latest` pointer naming `version` of the self artifact `name` on
/// `target`: its repository-relative path and its content.
pub(crate) fn self_latest_pointer(
    name: &str,
    version: &str,
    target: &str,
    sha512: &ContentHash,
) -> (String, String) {
    // The file name a shell downloads from release storage: the self layout's
    // flat binary key, not a spelling of its own.
    let binary = ReleaseLayout::self_artifact().binary_key(name, version, target);
    (
        latest_pointer_path(name, target),
        sidecar_content(&binary, &sha512.to_hex()),
    )
}

/// Read and verify the checkout's `head.json`, if it has one.
fn read_head(path: &Path) -> Result<Option<VerifiedHead>, LogWriteError> {
    // One byte past the limit, so an oversized file is reported by the head's
    // own size guard rather than read whole.
    let Some(bytes) = read_plain(path, MAX_HEAD_SIZE + 1)? else {
        return Ok(None);
    };
    Head::from_json(&bytes)
        .and_then(Head::verify_signature)
        .map(Some)
        .map_err(LogWriteError::ExistingHead)
}

/// What a path in the checkout is required to be.
#[derive(Debug, Clone, Copy)]
enum PathKind {
    File,
    Directory,
}

/// Require `path` to be absent or a plain entry of `kind` — never a symlink,
/// which would take a write out of the checkout. Returns whether it exists.
///
/// The check and the write that follows are separate system calls. The
/// checkout is the publisher's own directory, so this guards against a link
/// that was committed to the log or left behind, not against a concurrent
/// writer.
fn require_plain(path: &Path, kind: PathKind) -> Result<bool, LogWriteError> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(source) => return Err(io_error(path, source)),
    };
    let (is_kind, expected) = match kind {
        PathKind::File => (metadata.is_file(), "file"),
        PathKind::Directory => (metadata.is_dir(), "directory"),
    };
    if is_kind {
        Ok(true)
    } else {
        Err(LogWriteError::UnsafePath {
            path: path.to_path_buf(),
            expected,
        })
    }
}

/// Read at most `limit` bytes of the plain file at `path`; `None` if absent.
fn read_plain(path: &Path, limit: u64) -> Result<Option<Vec<u8>>, LogWriteError> {
    if !require_plain(path, PathKind::File)? {
        return Ok(None);
    }
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .and_then(|file| file.take(limit).read_to_end(&mut bytes))
        .map_err(|source| io_error(path, source))?;
    Ok(Some(bytes))
}

fn io_error(path: &Path, source: std::io::Error) -> LogWriteError {
    LogWriteError::Io {
        path: path.to_path_buf(),
        source,
    }
}

/// `text` cut to at most `max` bytes on a character boundary, with `...`
/// appended when cut, and every control or invisible character but a newline
/// (`fuz_sys::text::is_unprintable`) replaced by a space — so text from `git`
/// (which relays a remote's messages) can neither drive the terminal an error
/// is printed to nor reorder or hide what it shows. The lines of git's own
/// output stay lines, which is why this blanks where `printable` escapes. For
/// output to be read, not for a value an error names: that is cut and left for
/// its message to escape.
fn bounded(text: &str, max: usize) -> String {
    truncate(text, max)
        .chars()
        .map(|c| {
            if is_unprintable(c) && c != '\n' {
                ' '
            } else {
                c
            }
        })
        .collect()
}

/// A file read from a commit.
#[derive(Debug)]
enum Blob {
    /// The commit has no such path.
    Absent,
    /// The file is larger than the caller's limit and was not read.
    TooLarge,
    Content(Vec<u8>),
}

/// Variables that point git at a repository other than the one it is run in.
/// Dropped from the environment of every `git` process.
const GIT_REPOSITORY_VARIABLES: [&str; 7] = [
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_COMMON_DIR",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_NAMESPACE",
];

/// `git`, run in one checkout.
#[derive(Debug)]
struct Git<'a> {
    /// The checkout's canonical root.
    root: PathBuf,
    env: &'a [(OsString, OsString)],
}

impl<'a> Git<'a> {
    /// Resolve `repo.path` and require it to be the root of a git work tree.
    ///
    /// The root, not merely a directory inside a work tree: `head.json` lives
    /// at the repository root, and a path nested in some other repository must
    /// not have that repository committed to. Two layers hold that: every
    /// command is forbidden to discover a repository above the root (see
    /// [`command`](Self::command)), and the work tree git does find must be
    /// the root itself.
    fn open(repo: &'a LogRepo) -> Result<Self, LogWriteError> {
        let missing = || LogWriteError::CheckoutMissing(repo.path.clone());
        let root = match std::fs::canonicalize(&repo.path) {
            Ok(root) => root,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(missing()),
            Err(source) => return Err(io_error(&repo.path, source)),
        };
        if !root.is_dir() {
            return Err(missing());
        }
        let git = Self {
            root,
            env: &repo.git_env,
        };
        let output = git.run(&["rev-parse", "--show-toplevel"])?;
        let toplevel = String::from_utf8_lossy(&output.stdout);
        let is_root = output.status.success()
            && std::fs::canonicalize(toplevel.trim_end_matches('\n'))
                .is_ok_and(|toplevel| toplevel == git.root);
        if is_root {
            Ok(git)
        } else {
            Err(LogWriteError::NotARepo(repo.path.clone()))
        }
    }

    /// The `git <args>` command, ready to run in the checkout.
    ///
    /// Arguments are an argument vector, never a shell string. On top of the
    /// inherited environment: the variables that would point git at a different
    /// repository are dropped, terminal prompts are off so a credential prompt
    /// fails the publish instead of waiting on a terminal, the caller's
    /// `git_env` is applied, and — last, so nothing overrides it — repository
    /// discovery is stopped at the checkout's parent, so git run here can
    /// never operate on a repository that merely encloses the checkout.
    fn command<S: AsRef<OsStr>>(&self, args: &[S]) -> Command {
        let mut command = Command::new("git");
        command
            .args(args)
            .current_dir(&self.root)
            .stdin(Stdio::null())
            .env("GIT_TERMINAL_PROMPT", "0");
        for variable in GIT_REPOSITORY_VARIABLES {
            command.env_remove(variable);
        }
        command.envs(self.env.iter().map(|(name, value)| (name, value)));
        if let Some(parent) = self.root.parent() {
            command.env("GIT_CEILING_DIRECTORIES", parent);
        }
        command
    }

    /// Run `git <args>` in the checkout and capture its output.
    fn run<S: AsRef<OsStr>>(&self, args: &[S]) -> Result<Output, LogWriteError> {
        self.command(args).output().map_err(|e| LogWriteError::Git {
            command: subcommand(args),
            output: e.to_string(),
        })
    }

    /// The error for a `git <args>` that ran and failed.
    fn failure<S: AsRef<OsStr>>(args: &[S], output: &Output) -> LogWriteError {
        // git reports on stderr; a few commands explain themselves on stdout.
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let text = if stderr.trim().is_empty() {
            stdout.trim()
        } else {
            stderr.trim()
        };
        LogWriteError::Git {
            command: subcommand(args),
            output: bounded(text, MAX_GIT_OUTPUT_LEN),
        }
    }

    /// Run `git <args>` and require success; returns trimmed standard output.
    fn run_ok<S: AsRef<OsStr>>(&self, args: &[S]) -> Result<String, LogWriteError> {
        let output = self.run(args)?;
        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
        } else {
            Err(Self::failure(args, &output))
        }
    }

    /// Run a `git <args>` that answers a question with its exit status: 0 is
    /// yes (with trimmed standard output), 1 is no. Anything else — another
    /// exit code, death by signal — is a failure, never a "no".
    fn ask<S: AsRef<OsStr>>(&self, args: &[S]) -> Result<Option<String>, LogWriteError> {
        let output = self.run(args)?;
        match output.status.code() {
            Some(0) => Ok(Some(
                String::from_utf8_lossy(&output.stdout).trim().to_string(),
            )),
            Some(1) => Ok(None),
            _ => Err(Self::failure(args, &output)),
        }
    }

    /// The object `revision` names, or `None` if it names nothing.
    fn resolve(&self, revision: &str) -> Result<Option<String>, LogWriteError> {
        self.ask(&["rev-parse", "--verify", "--quiet", revision])
    }

    /// The content of `path` in `commit`. A blob larger than `limit` is
    /// reported by its size, without being read.
    fn read_blob(&self, commit: &str, path: &str, limit: u64) -> Result<Blob, LogWriteError> {
        let Some(blob) = self.resolve(&format!("{commit}:{path}"))? else {
            return Ok(Blob::Absent);
        };
        let size = self.run_ok(&["cat-file", "-s", blob.as_str()])?;
        if size.parse::<u64>().map_or(true, |size| size > limit) {
            return Ok(Blob::TooLarge);
        }
        let args = ["cat-file", "blob", blob.as_str()];
        let output = self.run(&args)?;
        if output.status.success() {
            Ok(Blob::Content(output.stdout))
        } else {
            Err(Self::failure(&args, &output))
        }
    }

    /// Refuse a checkout with any uncommitted change — staged, unstaged, or
    /// untracked — under the paths the log write owns, and one where git
    /// ignores a file that is there. An ignored file is invisible to a plain
    /// status and cannot be staged, so a log kept in one is never committed.
    fn require_clean(&self) -> Result<(), LogWriteError> {
        let status = self.run_ok(&[
            "status",
            "--porcelain",
            "--untracked-files=all",
            "--ignored",
            "--",
            HEAD_FILE,
            LATEST_DIR,
        ])?;
        let (ignored, dirty): (Vec<&str>, Vec<&str>) = status
            .lines()
            .map(str::trim)
            .partition(|line| line.starts_with("!!"));
        let join = |lines: &[&str]| bounded(&lines.join(", "), MAX_GIT_OUTPUT_LEN);
        if !dirty.is_empty() {
            Err(LogWriteError::Dirty {
                paths: join(&dirty),
            })
        } else if !ignored.is_empty() {
            Err(LogWriteError::Ignored {
                paths: join(&ignored),
            })
        } else {
            Ok(())
        }
    }

    /// Refuse a checkout whose ignore rules cover `path`, a file the log write
    /// is about to stage: git would refuse to.
    ///
    /// `--no-index` asks about the rules alone, tracked or not. Without it a
    /// tracked file is reported as not ignored, yet `git add` still refuses a
    /// tracked file inside an ignored directory.
    fn require_not_ignored(&self, path: &str) -> Result<(), LogWriteError> {
        match self.ask(&["check-ignore", "--quiet", "--no-index", "--", path])? {
            Some(_) => Err(LogWriteError::Ignored {
                paths: path.to_string(),
            }),
            None => Ok(()),
        }
    }

    /// Whether the staged content of `path` differs from the last commit's.
    fn is_staged_change(&self, path: &str) -> Result<bool, LogWriteError> {
        self.ask(&["diff", "--cached", "--quiet", "--", path])
            .map(|unchanged| unchanged.is_none())
    }

    /// The branch checked out, as its name under `refs/heads/`.
    ///
    /// Taken from the full ref: the short form git prints is `heads/<name>`
    /// whenever a tag shares the branch's name, which is not the name the
    /// branch's configuration is keyed by.
    ///
    /// The name goes on to be part of revision arguments and a configuration
    /// key. Git's own ref-name rules already forbid a leading `-` and the
    /// sequence `@{`; a `HEAD` edited by hand to break them is refused here
    /// rather than passed along.
    fn branch(&self) -> Result<String, LogWriteError> {
        let head = self.ask(&["symbolic-ref", "--quiet", "HEAD"])?;
        match head
            .as_deref()
            .and_then(|full| full.strip_prefix("refs/heads/"))
        {
            Some(branch)
                if !branch.is_empty() && !branch.starts_with('-') && !branch.contains("@{") =>
            {
                Ok(branch.to_string())
            }
            _ => Err(LogWriteError::DetachedHead),
        }
    }

    /// Refuse a checkout whose plain `git push` would not update the branch's
    /// upstream — `push.default`, `remote.pushDefault`, or
    /// `branch.<name>.pushRemote` sending it elsewhere, or a local branch named
    /// differently from its upstream.
    ///
    /// Before the upstream branch exists — a log with no pushed head yet —
    /// there is no remote-tracking ref to compare, and the push itself is the
    /// check.
    fn require_push_to_upstream(&self, branch: &str) -> Result<(), LogWriteError> {
        let full_name = |suffix: &str| -> Result<Option<String>, LogWriteError> {
            let output = self.run(&[
                "rev-parse",
                "--symbolic-full-name",
                &format!("{branch}@{{{suffix}}}"),
            ])?;
            Ok(output
                .status
                .success()
                .then(|| String::from_utf8_lossy(&output.stdout).trim().to_string()))
        };
        let Some(upstream) = full_name("upstream")? else {
            return Ok(());
        };
        if full_name("push")?.as_deref() == Some(upstream.as_str()) {
            Ok(())
        } else {
            Err(LogWriteError::PushElsewhere {
                branch: branch.to_string(),
            })
        }
    }

    /// The remote `branch` is configured to push to and merge from.
    ///
    /// Read from the branch's configuration rather than by resolving
    /// `@{upstream}`, which fails for a configured upstream whose branch does
    /// not exist on the remote yet — the state of a log before its first head.
    ///
    /// A branch with no upstream is an error, not a local-only log: the point
    /// of writing the log during publish is that the entry is public before
    /// the release is advertised, and a commit that goes nowhere is not.
    fn upstream_remote(&self, branch: &str) -> Result<String, LogWriteError> {
        let read = |key: &str| -> Result<Option<String>, LogWriteError> {
            Ok(self
                .ask(&["config", "--get", &format!("branch.{branch}.{key}")])?
                .filter(|value| !value.is_empty()))
        };
        match (read("remote")?, read("merge")?) {
            // `.` is a local branch as upstream: nothing would leave the machine.
            (Some(remote), Some(_)) if remote != "." && !remote.starts_with('-') => Ok(remote),
            _ => Err(LogWriteError::NoUpstream {
                branch: branch.to_string(),
            }),
        }
    }

    /// Bring the checkout up to its upstream by fast-forward only.
    fn fast_forward(&self, branch: &str, remote: &str) -> Result<(), LogWriteError> {
        self.run_ok(&["fetch", "--no-tags", "--", remote])?;
        let Some(upstream) = self.resolve(&upstream_of(branch))? else {
            // The remote has no such branch yet; there is nothing to catch up to.
            return Ok(());
        };
        let behind = match self.resolve("HEAD")? {
            None => true,
            Some(head) if head == upstream => return Ok(()),
            Some(head) => {
                if self.is_ancestor(&head, &upstream)? {
                    true
                } else if self.is_ancestor(&upstream, &head)? {
                    // Ahead only: commits from a log write whose push did not land.
                    false
                } else {
                    return Err(LogWriteError::Diverged {
                        branch: branch.to_string(),
                    });
                }
            }
        };
        if behind {
            self.run_ok(&["merge", "--ff-only", "--quiet", &upstream])?;
        }
        Ok(())
    }

    fn is_ancestor(&self, ancestor: &str, descendant: &str) -> Result<bool, LogWriteError> {
        self.ask(&["merge-base", "--is-ancestor", ancestor, descendant])
            .map(|answer| answer.is_some())
    }

    /// Stage exactly `paths`: they are named after `--`, so nothing else in
    /// the work tree is staged.
    fn stage(&self, paths: &[&str]) -> Result<(), LogWriteError> {
        self.run_ok(&[&["add", "--"], paths].concat())?;
        Ok(())
    }

    /// Commit exactly `paths`, already staged.
    ///
    /// The paths are named after `--`, so anything else already staged stays
    /// out of the commit. The committer identity and any signing are the
    /// publisher's own git configuration.
    fn commit(&self, message: &str, paths: &[&str]) -> Result<(), LogWriteError> {
        self.run_ok(&[&["commit", "--quiet", "-m", message, "--"], paths].concat())?;
        Ok(())
    }

    /// Undo a write that did not become a commit: unstage `paths`, and put
    /// each back as the last commit has it — or remove it, when the last
    /// commit has no such file. `created_dir` is a directory this write
    /// created, removed again if it is left empty.
    ///
    /// Best effort: every step runs whatever the others did. `Err` carries the
    /// first step that failed, for the caller to report beside the error that
    /// caused the rollback.
    fn roll_back(&self, paths: &[&str], created_dir: Option<&PathBuf>) -> Result<(), String> {
        let mut first_failure: Option<String> = None;
        let mut note = |failure: String| {
            first_failure.get_or_insert(failure);
        };
        if let Err(e) = self.run_ok(&[&["reset", "--quiet", "--"], paths].concat()) {
            note(e.to_string());
        }
        for path in paths {
            match self.resolve(&format!("HEAD:{path}")) {
                Ok(Some(_)) => {
                    if let Err(e) = self.run_ok(&["checkout", "--quiet", "HEAD", "--", path]) {
                        note(e.to_string());
                    }
                }
                Ok(None) => match std::fs::remove_file(self.root.join(path)) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => note(format!("removing {path}: {e}")),
                },
                Err(e) => note(e.to_string()),
            }
        }
        if let Some(dir) = created_dir {
            // Fails, harmlessly, when something else is in it.
            let _ = std::fs::remove_dir(dir);
        }
        first_failure.map_or(Ok(()), Err)
    }

    /// Push the current branch and confirm its remote-tracking ref now names
    /// the commit.
    ///
    /// A plain `git push`: no refspec, no force. Where it goes — including
    /// several push URLs on one remote — is the checkout's configuration. It
    /// runs even when the remote-tracking ref already names the commit: that
    /// ref moves as soon as one push URL accepts, so it cannot say that every
    /// URL has the commit, and git does nothing for a URL that is up to date.
    ///
    /// The confirmation reads git's local remote-tracking ref, which a
    /// successful push to the upstream updates; it does not query the remote.
    /// Returns whether the remote-tracking ref was behind before the push.
    fn push(&self, branch: &str) -> Result<bool, LogWriteError> {
        let Some(head) = self.resolve("HEAD")? else {
            return Ok(false);
        };
        let upstream = upstream_of(branch);
        let ahead = self.resolve(&upstream)?.as_deref() != Some(head.as_str());
        self.run_ok(&["push", "--quiet"])?;
        // A push that succeeded but sent the branch somewhere other than its
        // upstream would leave the entry unpublished.
        if self.resolve(&upstream)?.as_deref() == Some(head.as_str()) {
            Ok(ahead)
        } else {
            Err(LogWriteError::PushUnconfirmed {
                branch: branch.to_string(),
            })
        }
    }
}

/// The revision naming `branch`'s upstream.
///
/// The short name is the unambiguous one here: `@{upstream}` and `@{push}`
/// take what precedes them as a branch name, so a tag of the same name is
/// never what git resolves (and git does not accept `refs/heads/<name>` in
/// that position).
fn upstream_of(branch: &str) -> String {
    format!("{branch}@{{upstream}}")
}

/// The git subcommand of an argument vector, for an error message. Only the
/// subcommand: the arguments after it can carry paths and revisions.
fn subcommand<S: AsRef<OsStr>>(args: &[S]) -> String {
    args.first()
        .map(|arg| arg.as_ref().to_string_lossy().into_owned())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use fuz_crypto::HashAlgo;

    const X86: &str = "x86_64-unknown-linux-gnu";
    const ARM: &str = "aarch64-unknown-linux-gnu";
    const WHEN: &str = "2025-01-15T10:30:00Z";
    const LATER: &str = "2025-02-01T00:00:00Z";
    const KEY: &str = "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik=";

    fn pins(fill: &str, sha512: Option<&[u8]>) -> TargetRow {
        TargetRow {
            content_hash: format!("v1-{}", fill.repeat(64)),
            binaries: BTreeMap::from([(
                "fuz".to_string(),
                ContentHash::from_hex(HashAlgo::Blake3, &fill.repeat(64)).unwrap(),
            )]),
            sha512: sha512.map(ContentHash::sha512),
        }
    }

    fn entry(version: &str, target: &str, fill: &str) -> LogEntry {
        LogEntry {
            name: "fuz".to_string(),
            version: version.to_string(),
            target: target.to_string(),
            pins: pins(fill, Some(b"flat")),
            flat_latest: true,
        }
    }

    fn empty() -> HeadUnsigned {
        HeadUnsigned {
            format: HEAD_FORMAT_VERSION,
            seq: 1,
            keys: Vec::new(),
            rows: Vec::new(),
        }
    }

    #[test]
    fn upsert_appends_a_row_then_adds_targets_to_it() {
        let mut head = empty();
        assert_eq!(
            upsert_row(&mut head, &entry("0.1.0", X86, "a"), WHEN).unwrap(),
            Upsert::RowAdded
        );
        assert_eq!(
            upsert_row(&mut head, &entry("0.1.0", ARM, "b"), LATER).unwrap(),
            Upsert::TargetAdded
        );
        assert_eq!(
            upsert_row(&mut head, &entry("0.2.0", X86, "c"), LATER).unwrap(),
            Upsert::RowAdded
        );

        assert_eq!(head.rows.len(), 2);
        let row = &head.rows[0];
        assert_eq!((row.name.as_str(), row.version.as_str()), ("fuz", "0.1.0"));
        assert_eq!(row.status, RowStatus::Ok);
        // The row keeps the first publish's timestamp.
        assert_eq!(row.published_at, WHEN);
        assert_eq!(
            row.targets.keys().map(String::as_str).collect::<Vec<_>>(),
            [ARM, X86]
        );
        assert_eq!(row.targets[X86], pins("a", Some(b"flat")));
        assert_eq!(row.targets[ARM], pins("b", Some(b"flat")));
        assert_eq!(head.rows[1].published_at, LATER);
        // `seq` is the caller's to advance.
        assert_eq!(head.seq, 1);
        head.validate().unwrap();
    }

    #[test]
    fn upsert_of_an_identical_target_changes_nothing() {
        let mut head = empty();
        upsert_row(&mut head, &entry("0.1.0", X86, "a"), WHEN).unwrap();
        let before = head.clone();
        assert_eq!(
            upsert_row(&mut head, &entry("0.1.0", X86, "a"), LATER).unwrap(),
            Upsert::Unchanged
        );
        assert_eq!(head, before);
    }

    #[test]
    fn upsert_never_rewrites_a_recorded_target() {
        type Change = fn(&mut TargetRow);
        let recorded = entry("0.1.0", X86, "a");
        let cases: [(TargetField, Change); 4] = [
            (TargetField::ContentHash, |p| {
                p.content_hash = format!("v1-{}", "f".repeat(64));
            }),
            (TargetField::Binaries, |p| {
                p.binaries
                    .insert("extra".to_string(), ContentHash::blake3(b"another binary"));
            }),
            (TargetField::Sha512, |p| {
                p.sha512 = Some(ContentHash::sha512(b"other"));
            }),
            (TargetField::Sha512, |p| p.sha512 = None),
        ];
        for (field, change) in cases {
            let mut head = empty();
            upsert_row(&mut head, &recorded, WHEN).unwrap();
            let before = head.clone();
            let mut different = recorded.clone();
            change(&mut different.pins);

            match upsert_row(&mut head, &different, LATER) {
                Err(LogWriteError::TargetConflict {
                    name,
                    version,
                    target,
                    field: got,
                }) => {
                    assert_eq!((name.as_str(), version.as_str()), ("fuz", "0.1.0"));
                    assert_eq!(target, X86);
                    assert_eq!(got, field);
                }
                other => panic!("expected a {field} conflict, got {other:?}"),
            }
            assert_eq!(head, before, "a refused upsert must leave the head alone");
        }
    }

    #[test]
    fn upsert_refuses_a_revoked_row() {
        let mut head = empty();
        upsert_row(&mut head, &entry("0.1.0", X86, "a"), WHEN).unwrap();
        head.rows[0].status = RowStatus::Revoked;
        let before = head.clone();

        // A new target, and the identical one already recorded: both refused.
        for attempt in [entry("0.1.0", ARM, "b"), entry("0.1.0", X86, "a")] {
            assert!(matches!(
                upsert_row(&mut head, &attempt, LATER),
                Err(LogWriteError::RevokedRow { ref name, ref version })
                    if name == "fuz" && version == "0.1.0"
            ));
            assert_eq!(head, before);
        }
        // Another version of the same name is its own row.
        assert_eq!(
            upsert_row(&mut head, &entry("0.1.1", X86, "c"), LATER).unwrap(),
            Upsert::RowAdded
        );
    }

    #[test]
    fn record_key_appends_once_and_never_edits() {
        let mut head = empty();
        assert!(record_key(&mut head, KEY, WHEN));
        assert!(!record_key(&mut head, KEY, LATER));
        assert_eq!(
            head.keys,
            [KeyRecord {
                public_key: KEY.to_string(),
                added_at: WHEN.to_string(),
                retired_at: None,
            }]
        );

        // A retired record for the same key is still that key's record.
        head.keys[0].retired_at = Some(LATER.to_string());
        let before = head.keys.clone();
        assert!(!record_key(&mut head, KEY, LATER));
        assert_eq!(head.keys, before);
    }

    #[test]
    fn install_script_entry_pins_the_script_as_a_one_binary_release() {
        let script = b"#!/bin/sh\necho install\n";
        let entry = install_script_entry("3", script);

        assert_eq!(entry.name, "install.sh");
        assert_eq!(entry.version, "3");
        assert_eq!(entry.target, "any");
        assert!(!entry.flat_latest, "the script has no latest/ pointer");
        let binaries = BTreeMap::from([("install.sh".to_string(), ContentHash::blake3(script))]);
        assert_eq!(
            entry.pins.content_hash,
            content_hash_from_binaries(&binaries)
        );
        assert_eq!(entry.pins.binaries, binaries);
        assert_eq!(entry.pins.sha512, Some(ContentHash::sha512(script)));
        assert_eq!(latest_pointer(&entry), None);

        // It is an ordinary entry to the upsert: valid, idempotent, immutable.
        let mut head = empty();
        assert_eq!(
            upsert_row(&mut head, &entry, WHEN).unwrap(),
            Upsert::RowAdded
        );
        head.validate().unwrap();
        assert_eq!(
            upsert_row(&mut head, &install_script_entry("3", script), LATER).unwrap(),
            Upsert::Unchanged
        );
        assert!(matches!(
            upsert_row(&mut head, &install_script_entry("3", b"#!/bin/sh\n"), LATER),
            Err(LogWriteError::TargetConflict {
                field: TargetField::ContentHash,
                ..
            })
        ));
        assert_eq!(
            upsert_row(&mut head, &install_script_entry("4", b"#!/bin/sh\n"), LATER).unwrap(),
            Upsert::RowAdded
        );
    }

    #[test]
    fn latest_pointer_names_the_versioned_flat_binary() {
        let entry = entry("0.1.0", X86, "a");
        let (path, content) = latest_pointer(&entry).unwrap();
        assert_eq!(path, format!("latest/fuz-{X86}.sha512"));
        assert_eq!(
            content,
            format!(
                "{}  fuz-0.1.0-{X86}\n",
                ContentHash::sha512(b"flat").to_hex()
            )
        );

        let mut tool = entry;
        tool.flat_latest = false;
        assert_eq!(latest_pointer(&tool), None);
    }

    #[test]
    fn check_entry_refuses_values_that_are_not_tokens() {
        let cases = [
            ("name", "../fuz"),
            ("name", "-fuz"),
            ("name", ".fuz"),
            ("name", "a/b"),
            ("name", ""),
            ("version", "0.1.0 --force"),
            ("version", "0.1.0\n"),
            ("target", ".."),
            ("target", "x86/../.."),
            // `+` is not a token character: a version with build metadata is
            // one no publish produces.
            ("name", "fuz+x"),
            ("version", "0.1.0+b1"),
            ("target", "x86_64+avx"),
            ("binary name", "fuz+x"),
            ("binary name", "-fuz"),
            ("binary name", "fuz tool"),
        ];
        for (field, value) in cases {
            let mut entry = entry("0.1.0", X86, "a");
            match field {
                "name" => entry.name = value.to_string(),
                "version" => entry.version = value.to_string(),
                "target" => entry.target = value.to_string(),
                _ => {
                    let hash = entry.pins.binaries.pop_first().unwrap().1;
                    entry.pins.binaries.insert(value.to_string(), hash);
                }
            }
            assert!(
                matches!(
                    check_entry(&entry),
                    Err(LogWriteError::InvalidEntry { field: got, .. }) if got == field
                ),
                "{field} {value:?} must be refused"
            );
        }
        check_entry(&entry("0.1.0", X86, "a")).unwrap();

        // A latest/ pointer needs the digest it is written from.
        let mut no_digest = entry("0.1.0", X86, "a");
        no_digest.pins.sha512 = None;
        assert!(matches!(
            check_entry(&no_digest),
            Err(LogWriteError::InvalidEntry {
                field: "sha512",
                ..
            })
        ));
    }

    /// Every binary name is held to the token rule, not only the first or the
    /// last: an entry with several binaries is refused for the one that is
    /// not a token, wherever it sorts.
    #[test]
    fn check_entry_holds_every_binary_name_to_the_token_rule() {
        let hash = || ContentHash::from_hex(HashAlgo::Blake3, &"b".repeat(64)).unwrap();
        // `fuz` is the fixture's one binary; each bad name sorts to a
        // different side of the good ones.
        for (bad, others) in [
            ("+first", ["fuz-a", "fuz-b"]),
            ("fuz+middle", ["fuz-a", "fuzz"]),
            ("zzz+last", ["fuz-a", "fuz-b"]),
        ] {
            let mut entry = entry("0.1.0", X86, "a");
            for name in others {
                entry.pins.binaries.insert(name.to_string(), hash());
            }
            check_entry(&entry).unwrap();
            entry.pins.binaries.insert(bad.to_string(), hash());
            assert!(
                matches!(
                    check_entry(&entry),
                    Err(LogWriteError::InvalidEntry { field: "binary name", value }) if value == bad
                ),
                "{bad:?} must be refused"
            );
        }
    }

    /// A refused value is shown as it is, spelled out: what makes it invalid
    /// is in the message, not blanked out of it.
    #[test]
    fn check_entry_shows_the_refused_value_escaped_not_blanked() {
        let mut hostile = entry("0.1.0", X86, "a");
        hostile.name = "fuz\u{202e}x\u{2800}\u{1b}[2K".to_string();
        assert_eq!(
            check_entry(&hostile).unwrap_err().to_string(),
            "invalid release log entry name: \"fuz\\u{202e}x\\u{2800}\\u{1b}[2K\""
        );
    }

    /// A refused value of any length is cut before the error carries it: the
    /// message quotes what the error holds and does not bound it.
    #[test]
    fn check_entry_bounds_the_refused_value() {
        let mut long = entry("0.1.0", X86, "a");
        long.version = "\u{1b}".repeat(1_000_000);
        assert_eq!(
            check_entry(&long).unwrap_err().to_string(),
            format!(
                "invalid release log entry version: \"{}...\"",
                "\\u{1b}".repeat(MAX_ERROR_VALUE_LEN)
            )
        );
    }

    #[test]
    fn check_entry_keeps_the_latest_pointer_to_the_self_artifact() {
        for name in ["fuzd", "fuz-extra", "install.sh"] {
            let mut other = entry("0.1.0", X86, "a");
            other.name = name.to_string();
            assert!(
                matches!(
                    check_entry(&other),
                    Err(LogWriteError::InvalidEntry { field: "flat_latest", ref value })
                        if value == name
                ),
                "{name} must not get a latest/ pointer"
            );
            // The same entry without the pointer is fine.
            other.flat_latest = false;
            check_entry(&other).unwrap();
        }
        assert_eq!(SELF_NAME, "fuz");
    }

    /// The environment of every git process: what is removed, what is set, and
    /// that the ceiling is applied over the caller's own variables.
    #[test]
    fn git_commands_cannot_reach_another_repository() {
        let env = vec![
            (
                OsString::from("GIT_CONFIG_GLOBAL"),
                OsString::from("/dev/null"),
            ),
            // A caller cannot lift the ceiling.
            (
                OsString::from("GIT_CEILING_DIRECTORIES"),
                OsString::from("/"),
            ),
        ];
        let git = Git {
            root: PathBuf::from("/srv/logs/release-log"),
            env: &env,
        };
        let command = git.command(&["status", "--porcelain"]);

        assert_eq!(command.get_program(), "git");
        assert_eq!(
            command.get_args().collect::<Vec<_>>(),
            ["status", "--porcelain"]
        );
        assert_eq!(
            command.get_current_dir(),
            Some(Path::new("/srv/logs/release-log"))
        );

        let envs: BTreeMap<&OsStr, Option<&OsStr>> = command.get_envs().collect();
        let set = |name: &str| envs.get(OsStr::new(name)).copied().flatten();
        for variable in [
            "GIT_DIR",
            "GIT_WORK_TREE",
            "GIT_INDEX_FILE",
            "GIT_COMMON_DIR",
            "GIT_OBJECT_DIRECTORY",
            "GIT_ALTERNATE_OBJECT_DIRECTORIES",
            "GIT_NAMESPACE",
        ] {
            assert_eq!(
                envs.get(OsStr::new(variable)),
                Some(&None),
                "{variable} must be removed from the inherited environment"
            );
        }
        assert_eq!(set("GIT_TERMINAL_PROMPT"), Some(OsStr::new("0")));
        assert_eq!(set("GIT_CONFIG_GLOBAL"), Some(OsStr::new("/dev/null")));
        assert_eq!(
            set("GIT_CEILING_DIRECTORIES"),
            Some(OsStr::new("/srv/logs")),
            "discovery stops at the checkout's parent, whatever the caller passed"
        );
    }

    #[test]
    fn ask_takes_only_exit_one_as_no() {
        if Command::new("git").arg("--version").output().is_err() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let env = vec![
            (
                OsString::from("GIT_CONFIG_GLOBAL"),
                OsString::from("/dev/null"),
            ),
            (OsString::from("GIT_CONFIG_NOSYSTEM"), OsString::from("1")),
        ];
        let git = Git {
            root: dir.path().canonicalize().unwrap(),
            env: &env,
        };
        git.run_ok(&["init", "--quiet"]).unwrap();
        assert_eq!(git.resolve("HEAD").unwrap(), None);
        assert!(matches!(
            git.ask(&["merge-base", "--is-ancestor", "no-such-a", "no-such-b"]),
            Err(LogWriteError::Git { ref command, .. }) if command == "merge-base"
        ));
    }

    #[test]
    fn a_failed_rollback_is_noted_beside_the_original_error() {
        let original = || LogWriteError::Git {
            command: "commit".to_string(),
            output: "gpg failed to sign the data".to_string(),
        };
        // A clean rollback leaves the error as it was.
        assert_eq!(
            with_rollback_note(original(), Ok(())).to_string(),
            original().to_string()
        );
        // A failed one is appended, bounded; the original stays first.
        let noted = with_rollback_note(original(), Err("x".repeat(10_000)));
        match &noted {
            LogWriteError::Git { command, output } => {
                assert_eq!(command, "commit");
                assert!(
                    output.starts_with("gpg failed to sign the data\n"),
                    "{output}"
                );
                assert!(output.contains("not fully restored"), "{output}");
                assert!(output.len() < 400, "the note is bounded: {}", output.len());
            }
            other => panic!("the original error kind must survive, got {other:?}"),
        }
        let io = with_rollback_note(
            io_error(
                Path::new("/log/head.json"),
                std::io::Error::other("disk full"),
            ),
            Err("git reset failed".to_string()),
        );
        let message = io.to_string();
        assert!(message.contains("disk full"), "{message}");
        assert!(message.contains("git reset failed"), "{message}");
    }

    #[test]
    fn bounded_cuts_long_text_and_blanks_control_characters() {
        assert_eq!(bounded("plain", 16), "plain");
        assert_eq!(bounded("line one\nline two", 64), "line one\nline two");
        assert_eq!(bounded("a\x1b[31mb\rc", 64), "a [31mb c");
        // What shows nothing or reorders what is shown is blanked like a
        // control: a direction override, a zero-width space, a blank filler,
        // the line separator.
        assert_eq!(
            bounded("a\u{202e}b\u{200b}c\u{3164}d\u{2800}e\u{2028}f", 64),
            "a b c d e f"
        );
        assert_eq!(
            bounded("caf\u{e9} \u{65e5}\u{672c}", 64),
            "caf\u{e9} \u{65e5}\u{672c}"
        );
        assert_eq!(bounded("abcdef", 3), "abc...");
        // Cut on a character boundary, never inside one.
        assert_eq!(bounded("aé", 2), "a...");
    }

    #[test]
    fn log_outcome_displays_as_the_publish_log_line() {
        let outcome = LogOutcome {
            name: "fuzd".to_string(),
            version: "0.1.0".to_string(),
            target: "x86_64-unknown-linux-gnu".to_string(),
            seq: 7,
            advanced: true,
            pushed: false,
        };
        assert_eq!(
            outcome.to_string(),
            "fuzd 0.1.0 x86_64-unknown-linux-gnu at seq 7 \
             (head signed, remote-tracking ref already current)"
        );
        let repeat = LogOutcome {
            advanced: false,
            pushed: true,
            ..outcome
        };
        assert!(repeat.to_string().ends_with("(already recorded, pushed)"));
    }
}
