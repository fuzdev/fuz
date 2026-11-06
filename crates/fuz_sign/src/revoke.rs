//! Release log revocation: withdrawing a release the log records.
//!
//! A row of the release log's head is `ok` or `revoked`, and the one change a
//! row ever takes is `ok` to `revoked`. A reader that holds a head refuses to
//! install a revoked release, so revoking is how a publisher withdraws one:
//! the next head carries the row as revoked, signed and pushed like any other.
//!
//! A revocation is of a whole release — every target of one `(name, version)`.
//! It also settles the `latest/` pointers: a pointer that names the revoked
//! release moves to the newest release of that name that still stands and has
//! a flat binary for the target, or is removed when there is none. Pointers
//! that name another version are left alone.
//!
//! **Storage is not touched.** The byte host's `latest-<target>.json` pointers
//! and its `latest` copy of the flat binary keep naming the revoked version
//! until a new release is published; a client that runs the release log check refuses it in the
//! meantime. The remedy is to publish a fixed release.
//!
//! The module is two layers:
//!
//! - **Pure** — [`revoke_row`], [`next_revoked_head`], [`plan_pointers`]:
//!   values in, values out, no filesystem, no clock, no `git`.
//! - **The log write** — [`revoke_release`]: the checkout checks, commit,
//!   push, and read-back a publish's log write uses (`release_log`), given a
//!   status change and pointer changes instead of an entry.
//!
//! Running it again is safe. A release that is already revoked signs no new
//! head; the run still moves or removes a pointer that names it, pushes a
//! commit an earlier run left unpushed, and reads the pushed log back.

use ed25519_dalek::SigningKey;
use fuz_release::{LogWriteError, ReleaseLayout, ReleaseRow, RowStatus, VerifiedHead};

use crate::release_log::{
    LogRepo, NextHead, PreparedLog, advance_seq, latest_pointer_path, public_key_of, record_key,
    self_latest_pointer, sign_successor,
};
use crate::stream::{compare_versions, printable, printable_quoted};

/// How a revocation runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RevokeOptions {
    /// Run every read and check and write nothing.
    pub dry_run: bool,
}

/// What [`revoke_row`] found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Revocation {
    /// The row was `ok` and is now `revoked`.
    Revoked,
    /// The row was revoked already; nothing changed.
    AlreadyRevoked,
}

/// A `latest/` pointer the log tracks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrackedPointer {
    /// The pointer's path in the log repository.
    pub path: String,
    /// The file name its one line carries: the versioned flat binary it names.
    pub file_name: String,
}

/// What becomes of a `latest/` pointer that names a revoked release.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PointerAfter {
    /// The pointer names another release of the same name and target.
    Moved {
        /// The version it now names.
        version: String,
        /// The pointer's new content: one `sha512sum`-format line naming that
        /// version's flat binary.
        content: String,
    },
    /// No release that still stands has a flat binary for the target; the
    /// pointer is removed.
    Removed,
}

/// One `latest/` pointer a revocation changes. Before the change it names the
/// revoked version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PointerChange {
    /// The pointer's path in the log repository.
    pub path: String,
    /// The target the pointer is for.
    pub target: String,
    /// What the pointer becomes.
    pub after: PointerAfter,
}

/// What a revocation did — or, on a dry run, what it would do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevokeReport {
    /// Whether this was a dry run: every read and check ran, and nothing was
    /// written beyond the fast-forward of the checkout.
    pub dry_run: bool,
    /// The row name: a tool name, or `fuz` for the self artifact.
    pub name: String,
    /// The revoked version.
    pub version: String,
    /// The targets of the release. All of them are revoked together.
    pub targets: Vec<String>,
    /// The `seq` of the head that records the revocation.
    pub seq: u64,
    /// Whether the head had to change, or already recorded the revocation.
    pub revocation: Revocation,
    /// The `latest/` pointers that named the revoked version, and what each
    /// becomes.
    pub pointers: Vec<PointerChange>,
    /// The subject of the commit that holds the change; `None` when there was
    /// nothing to commit.
    pub commit_message: Option<String>,
    /// Whether the branch's remote-tracking ref was behind the commit before
    /// the push. Always false on a dry run.
    pub pushed: bool,
}

/// Errors from revoking a release in a release log.
///
/// The strings a variant carries are the caller's or the log's own, unescaped;
/// the variant's message prints each through `printable`, or through
/// `printable_quoted` where it is shown in quotes.
#[derive(Debug, thiserror::Error)]
pub enum RevokeError {
    /// The log has no head, so it records no release.
    #[error("the release log has no head")]
    NoHead,
    /// The head has no row for the release.
    #[error("the release log has no row for {} {}", printable_quoted(.name), printable_quoted(.version))]
    UnknownRelease { name: String, version: String },
    /// The file the log tracks at one of the release's own pointer paths is
    /// not a pointer line.
    #[error("the log's {} is not a latest pointer: {reason}", printable(.path))]
    Pointer { path: String, reason: &'static str },
    #[error("release log write failed: {0}")]
    Log(#[from] LogWriteError),
    /// The change is committed in the checkout and the push failed. The commit
    /// waits there, unpushed.
    #[error("the release log push failed; a revocation commit may be waiting in the checkout: {0}")]
    Unpublished(#[source] LogWriteError),
    /// The push went through, and the pushed commit does not hold the
    /// revocation as it was written. The commit is public.
    #[error("the pushed release log does not hold the revocation: {0}")]
    PublishedWrong(#[source] LogWriteError),
    /// The push went through, and reading the pushed commit back failed: `git`
    /// could not be run or a file could not be read. Whether the pushed commit
    /// holds the revocation is not known.
    #[error("the revocation was pushed but could not be read back: {0}")]
    ReadBackFailed(#[source] LogWriteError),
}

impl RevokeError {
    /// Returns user-facing hint for how to fix this error
    #[allow(clippy::missing_const_for_fn)] // calls non-const hint() methods
    pub fn hint(&self) -> Option<&'static str> {
        match self {
            Self::NoHead => Some(
                "A log with no head records no release to revoke. Create the log with `cargo \
                 xtask release-log backfill --storage <uri> --log-repo <path>`, or by publishing \
                 with --log-repo",
            ),
            Self::UnknownRelease { .. } => Some(
                "Check the name and version against head.json in the log checkout; the name is \
                 `fuz` for the self artifact and the tool name otherwise",
            ),
            Self::Pointer { .. } => Some(
                "A latest/ pointer is one sha512sum-format line, and this one is the revoked \
                 release's own. Restore or remove the file with a commit, push it, and run the \
                 revoke again",
            ),
            // The log write's hints are worded for a publish; the ones that say
            // how to retry are said again for a revoke.
            Self::Log(LogWriteError::Dirty { .. }) => Some(
                "Commit or discard the changes to head.json and latest/ in the log checkout, \
                 then run the revoke again",
            ),
            Self::Log(LogWriteError::Ignored { .. }) => Some(
                "Remove the ignore rule covering head.json or latest/ (.gitignore, \
                 .git/info/exclude, or core.excludesFile) and delete any ignored copy, \
                 then run the revoke again",
            ),
            Self::Log(LogWriteError::Diverged { .. }) => Some(
                "If the local commits were never pushed, `git reset --hard @{upstream}` in the \
                 log checkout and run the revoke again; never rewrite pushed history",
            ),
            // A head from before domain-separated signing: the log write's
            // hint, which is not about retrying, holds for a revoke as is.
            Self::Log(
                e @ LogWriteError::ExistingHead(fuz_release::ReleaseLogError::Signature(
                    fuz_crypto::VerifyError::UnsupportedFormat(format),
                )),
            ) if *format < fuz_crypto::SIGNATURE_FORMAT_VERSION => e.hint(),
            Self::Log(LogWriteError::ExistingHead(_)) => Some(
                "The head.json in the log checkout does not verify with this binary's trusted \
                 keys; it is never overwritten. If the last commit broke it, restore it with a \
                 new commit (git revert --no-edit HEAD) and run the revoke again",
            ),
            Self::Log(LogWriteError::Git { .. }) => Some(
                "Fix what git reports in the log checkout, then run the revoke again - a \
                 commit that failed was rolled back",
            ),
            Self::Log(e) => e.hint(),
            Self::Unpublished(_) => Some(
                "Fix what the error reports, then run the same revoke again: it signs nothing \
                 new, pushes the waiting commit, and reads it back",
            ),
            Self::PublishedWrong(_) => Some(
                "The commit is on the remote. Remove the cause (a hook, an assume-unchanged \
                 flag), discard any uncommitted change `git status` shows for head.json and \
                 latest/, and run the same revoke again",
            ),
            Self::ReadBackFailed(_) => Some(
                "The commit was pushed. Run the same revoke again: it reads the pushed log back",
            ),
        }
    }

    /// The error for a read-back of the pushed commit that failed.
    ///
    /// A read-back that read something other than what was written is
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
    /// carry one. A log with no head, a release it does not record, and a
    /// pointer that is not a pointer line are operator conditions, and a read-back
    /// that could not read says nothing either way.
    pub const fn is_security_violation(&self) -> bool {
        match self {
            Self::Log(e) | Self::Unpublished(e) | Self::PublishedWrong(e) => {
                e.is_security_violation()
            }
            Self::NoHead
            | Self::UnknownRelease { .. }
            | Self::Pointer { .. }
            | Self::ReadBackFailed(_) => false,
        }
    }
}

/// Mark the row `name` `version` of `head` as revoked.
///
/// The whole row: a revocation covers every target the release has. A row
/// that is revoked already is left exactly as it is. `seq` is not touched —
/// see [`next_revoked_head`].
///
/// # Errors
///
/// [`RevokeError::UnknownRelease`] if the head has no such row.
pub fn revoke_row(
    head: &mut fuz_release::HeadUnsigned,
    name: &str,
    version: &str,
) -> Result<Revocation, RevokeError> {
    let Some(row) = head
        .rows
        .iter_mut()
        .find(|row| row.name == name && row.version == version)
    else {
        return Err(RevokeError::UnknownRelease {
            name: name.to_string(),
            version: version.to_string(),
        });
    };
    match row.status {
        RowStatus::Revoked => Ok(Revocation::AlreadyRevoked),
        RowStatus::Ok => {
            row.status = RowStatus::Revoked;
            Ok(Revocation::Revoked)
        }
    }
}

/// Build and sign the head that records `name` `version` as revoked on top of
/// `previous`.
///
/// `previous` with the row revoked ([`revoke_row`]), the signing key recorded
/// if the head does not list it yet, and `seq` one greater — signed, verified,
/// and required to be a successor of `previous` (`sign_successor`) before it
/// is returned. A row that is revoked already yields
/// [`NextHead::Unchanged`]: no new `seq`, no signature.
///
/// `now` is a new key record's `added_at` and the signature's `signed_at`.
///
/// # Errors
///
/// [`RevokeError::UnknownRelease`] if `previous` has no such row, and
/// [`RevokeError::Log`] for a head at the last `seq`, one that does not
/// verify (the signing key is not one this binary trusts), or one that breaks
/// the append-only rules.
pub fn next_revoked_head(
    previous: &VerifiedHead,
    name: &str,
    version: &str,
    key: &SigningKey,
    now: &str,
) -> Result<NextHead, RevokeError> {
    let mut unsigned = previous.to_unsigned();
    if revoke_row(&mut unsigned, name, version)? == Revocation::AlreadyRevoked {
        return Ok(NextHead::Unchanged);
    }
    record_key(&mut unsigned, &public_key_of(key), now);
    advance_seq(&mut unsigned)?;
    Ok(NextHead::Advanced(Box::new(sign_successor(
        Some(previous),
        unsigned,
        key,
        now,
    )?)))
}

/// Decide what becomes of each `latest/` pointer that names `name` `version`.
///
/// `rows` are the head's rows with the release already revoked, and `tracked`
/// the pointers the log holds. For each target of the revoked release, the
/// pointer at `latest/<name>-<target>.sha512` is changed only if its line
/// names that version's flat binary; a pointer that names any other file is
/// not in the result.
///
/// A changed pointer moves to the newest release that is a row of the same
/// name, is not revoked, has a semver version, and records a `sha512` for the
/// target — newest by semver order, pre-releases included: with `0.2.0` and
/// `0.3.0-rc.1` standing, revoking `0.3.0` moves the pointer to `0.3.0-rc.1`.
/// That is the order a publish moves the pointer in, which names whatever was
/// published last, pre-release or not. With no such release the pointer is
/// removed. A row without the target, without a `sha512` for it, revoked, or
/// with a version that is not semver is never moved to.
///
/// Only the head is consulted. Whether the release moved to still has its flat
/// binary in storage is not known here.
///
/// The result is in target order. An unknown release yields no changes.
#[must_use]
pub fn plan_pointers(
    rows: &[ReleaseRow],
    tracked: &[TrackedPointer],
    name: &str,
    version: &str,
) -> Vec<PointerChange> {
    let Some(revoked) = rows
        .iter()
        .find(|row| row.name == name && row.version == version)
    else {
        return Vec::new();
    };
    let mut changes = Vec::new();
    for target in revoked.targets.keys() {
        let path = latest_pointer_path(name, target);
        // The file name a pointer to this release carries: the self layout's
        // flat binary key, as a publish writes it.
        let binary = ReleaseLayout::self_artifact().binary_key(name, version, target);
        let names_revoked = tracked
            .iter()
            .any(|pointer| pointer.path == path && pointer.file_name == binary);
        if !names_revoked {
            continue;
        }
        let successor = rows
            .iter()
            .filter(|row| row.name == name && row.status == RowStatus::Ok)
            .filter(|row| semver::Version::parse(&row.version).is_ok())
            .filter_map(|row| {
                let sha512 = row.targets.get(target)?.sha512.as_ref()?;
                Some((row.version.as_str(), sha512))
            })
            .max_by(|(a, _), (b, _)| compare_versions(a, b));
        let after = successor.map_or(PointerAfter::Removed, |(successor, sha512)| {
            let (_, content) = self_latest_pointer(name, successor, target, sha512);
            PointerAfter::Moved {
                version: successor.to_string(),
                content,
            }
        });
        changes.push(PointerChange {
            path,
            target: target.clone(),
            after,
        });
    }
    changes
}

/// Revoke the release `name` `version` in the release log checkout `repo`.
///
/// In order:
///
/// 1. **Check the checkout** and fast-forward it, as a publish's log write
///    does (`release_log::record_release`).
/// 2. **Read and verify the head.** A log with no head is refused
///    ([`RevokeError::NoHead`]), as is a head with no row for the release
///    ([`RevokeError::UnknownRelease`]). `key` must be one this binary trusts,
///    whether or not a head is signed.
/// 3. **Sign the next head** ([`next_revoked_head`]): the row revoked, every
///    target with it. Nothing is signed for a row that is revoked already.
/// 4. **Settle the `latest/` pointers** ([`plan_pointers`]). The release's
///    own pointers — `latest/<name>-<target>.sha512` for each of its targets,
///    where the last commit tracks one — are read, and nothing else under
///    `latest/` is. Each must be tracked as a plain file
///    ([`LogWriteError::UnsafePath`] for a symlink or any other mode) holding
///    a pointer line ([`RevokeError::Pointer`] otherwise). One that names the
///    revoked release moves to the newest release — by semver, pre-releases
///    included — that still stands and records a flat binary for the target,
///    or is removed.
/// 5. **Write, commit, push, and read back** — `head.json` and the pointer
///    changes in one commit, with the subject `log: revoke <name> <version>
///    seq <seq>` (`log: latest revoke …` when only pointers change). A write
///    or commit that fails is rolled back, and the revoke can run again. A
///    push that fails leaves the commit in the checkout
///    ([`RevokeError::Unpublished`]); the same revoke run again pushes it. The
///    read-back requires the pushed head to verify and show the row revoked,
///    each moved pointer to hold what was written, and each removed pointer
///    to be absent from the pushed commit ([`RevokeError::PublishedWrong`];
///    [`RevokeError::ReadBackFailed`] when the pushed commit could not be
///    read at all).
///
/// With `options.dry_run` set, steps 1–4 run in full and step 5 is skipped:
/// nothing is written to the checkout beyond the fast-forward, and the report
/// describes what step 5 would write.
///
/// Release storage is not read or written. What it advertises keeps naming
/// the revoked version until another release is published — and since storage
/// is not read, a pointer can move to a release whose flat binary has since
/// been pruned from it.
///
/// `now` is a new key record's `added_at` and the head signature's
/// `signed_at`. The head carries no time of revocation.
///
/// Blocking: runs `git` and waits for it, with no timeout.
///
/// # Errors
///
/// A [`RevokeError`] per the steps above.
pub fn revoke_release(
    repo: &LogRepo,
    name: &str,
    version: &str,
    key: &SigningKey,
    now: &str,
    options: RevokeOptions,
) -> Result<RevokeReport, RevokeError> {
    let (prepared, plan) = PreparedLog::prepare_revocation(repo, name, version, key, now)?;
    let pushed = if options.dry_run {
        false
    } else {
        prepared.write()?;
        let pushed = prepared.push().map_err(RevokeError::Unpublished)?;
        prepared
            .require_published()
            .map_err(RevokeError::from_read_back)?;
        pushed
    };
    Ok(RevokeReport {
        dry_run: options.dry_run,
        name: name.to_string(),
        version: version.to_string(),
        targets: plan.targets,
        seq: plan.seq,
        revocation: plan.revocation,
        pointers: plan.pointers,
        commit_message: plan.commit_message,
        pushed,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use fuz_crypto::ContentHash;
    use fuz_release::{HEAD_FORMAT_VERSION, HeadUnsigned, TargetRow};

    use super::*;

    const X86: &str = "x86_64-unknown-linux-gnu";
    const ARM: &str = "aarch64-unknown-linux-gnu";
    const WHEN: &str = "2025-01-15T10:30:00Z";

    fn pins(content: &[u8], flat: bool) -> TargetRow {
        let binaries = BTreeMap::from([("fuz".to_string(), ContentHash::blake3(content))]);
        TargetRow {
            content_hash: fuz_artifact::content_hash_from_binaries(&binaries),
            binaries,
            sha512: flat.then(|| ContentHash::sha512(content)),
        }
    }

    /// A row of `name` `version` with a flat binary for each of `targets`.
    fn row(name: &str, version: &str, targets: &[&str]) -> ReleaseRow {
        ReleaseRow {
            name: name.to_string(),
            version: version.to_string(),
            status: RowStatus::Ok,
            published_at: WHEN.to_string(),
            targets: targets
                .iter()
                .map(|target| {
                    let content = format!("{name} {version} {target}");
                    ((*target).to_string(), pins(content.as_bytes(), true))
                })
                .collect(),
        }
    }

    fn head(rows: Vec<ReleaseRow>) -> HeadUnsigned {
        HeadUnsigned {
            format: HEAD_FORMAT_VERSION,
            seq: 4,
            keys: Vec::new(),
            rows,
        }
    }

    /// The pointer the log holds for `name` on `target`, naming `version`.
    fn pointer(name: &str, version: &str, target: &str) -> TrackedPointer {
        TrackedPointer {
            path: format!("latest/{name}-{target}.sha512"),
            file_name: format!("{name}-{version}-{target}"),
        }
    }

    fn revoked(mut rows: Vec<ReleaseRow>, name: &str, version: &str) -> Vec<ReleaseRow> {
        let row = rows
            .iter_mut()
            .find(|row| row.name == name && row.version == version)
            .unwrap();
        row.status = RowStatus::Revoked;
        rows
    }

    fn moved(name: &str, version: &str, target: &str) -> PointerAfter {
        let content = format!("{name} {version} {target}");
        PointerAfter::Moved {
            version: version.to_string(),
            content: format!(
                "{}  {name}-{version}-{target}\n",
                ContentHash::sha512(content.as_bytes()).to_hex()
            ),
        }
    }

    #[test]
    fn revoke_row_flips_the_whole_row_once() {
        let mut head = head(vec![
            row("fuz", "0.1.0", &[X86, ARM]),
            row("fuz", "0.2.0", &[X86]),
            row("fuzd", "0.1.0", &[X86]),
        ]);
        let before = head.clone();

        assert_eq!(
            revoke_row(&mut head, "fuz", "0.1.0").unwrap(),
            Revocation::Revoked
        );
        // Only the status of that one row changed: both targets stay, every
        // other row and `seq` are as they were.
        let mut expected = before;
        expected.rows[0].status = RowStatus::Revoked;
        assert_eq!(head, expected);
        head.validate().unwrap();

        // A second revocation finds it done and changes nothing.
        assert_eq!(
            revoke_row(&mut head, "fuz", "0.1.0").unwrap(),
            Revocation::AlreadyRevoked
        );
        assert_eq!(head, expected);
    }

    #[test]
    fn revoke_row_refuses_a_release_the_head_does_not_record() {
        let mut head = head(vec![row("fuz", "0.1.0", &[X86])]);
        let before = head.clone();
        for (name, version) in [("fuz", "0.9.9"), ("fuzd", "0.1.0"), ("", "")] {
            assert!(matches!(
                revoke_row(&mut head, name, version),
                Err(RevokeError::UnknownRelease { name: ref n, version: ref v })
                    if n == name && v == version
            ));
            assert_eq!(head, before);
        }
    }

    #[test]
    fn a_pointer_moves_to_the_newest_release_that_still_stands() {
        let rows = revoked(
            vec![
                row("fuz", "0.1.0", &[X86]),
                row("fuz", "0.10.0", &[X86]),
                row("fuz", "0.9.0", &[X86]),
                row("fuz", "0.11.0", &[X86]),
            ],
            "fuz",
            "0.11.0",
        );
        let changes = plan_pointers(&rows, &[pointer("fuz", "0.11.0", X86)], "fuz", "0.11.0");
        // Semver order, not string order and not row order: 0.10.0 over 0.9.0.
        assert_eq!(
            changes,
            [PointerChange {
                path: format!("latest/fuz-{X86}.sha512"),
                target: X86.to_string(),
                after: moved("fuz", "0.10.0", X86),
            }]
        );
    }

    #[test]
    fn a_pre_release_is_a_release_to_move_to() {
        let rows = revoked(
            vec![
                row("fuz", "0.2.0", &[X86]),
                row("fuz", "0.3.0-rc.1", &[X86]),
                row("fuz", "0.3.0", &[X86]),
            ],
            "fuz",
            "0.3.0",
        );
        let changes = plan_pointers(&rows, &[pointer("fuz", "0.3.0", X86)], "fuz", "0.3.0");
        assert_eq!(changes.len(), 1);
        // Semver order with pre-releases in it: the release candidate is newer
        // than 0.2.0, and the pointer names whatever is newest.
        assert_eq!(changes[0].after, moved("fuz", "0.3.0-rc.1", X86));
    }

    #[test]
    fn a_pointer_may_move_to_a_newer_release() {
        // An older version was republished, so the pointer names it; revoking
        // it sends the pointer to the newest that stands, which is newer.
        let rows = revoked(
            vec![row("fuz", "0.1.0", &[X86]), row("fuz", "0.2.0", &[X86])],
            "fuz",
            "0.1.0",
        );
        let changes = plan_pointers(&rows, &[pointer("fuz", "0.1.0", X86)], "fuz", "0.1.0");
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].after, moved("fuz", "0.2.0", X86));
    }

    #[test]
    fn candidates_that_cannot_be_pointed_at_are_passed_over() {
        let mut no_sha512 = row("fuz", "0.5.0", &[X86]);
        no_sha512.targets.insert(X86.to_string(), pins(b"x", false));
        let rows = revoked(
            revoked(
                vec![
                    row("fuz", "0.1.0", &[X86]),
                    // Newer than 0.1.0, and each unusable for its own reason.
                    row("fuz", "0.2.0", &[X86]),
                    row("fuz", "0.3.0", &[ARM]),
                    no_sha512,
                    row("fuz", "nightly", &[X86]),
                    row("fuzd", "0.8.0", &[X86]),
                    row("fuz", "0.9.0", &[X86]),
                ],
                "fuz",
                "0.2.0",
            ),
            "fuz",
            "0.9.0",
        );
        let changes = plan_pointers(&rows, &[pointer("fuz", "0.9.0", X86)], "fuz", "0.9.0");
        assert_eq!(changes.len(), 1);
        assert_eq!(
            changes[0].after,
            moved("fuz", "0.1.0", X86),
            "a revoked row, one without the target, one without a sha512, one whose version \
             is not semver, and another name's row are never moved to"
        );
    }

    #[test]
    fn a_pointer_with_nothing_to_move_to_is_removed() {
        // The only other release is for another target.
        let rows = revoked(
            vec![row("fuz", "0.1.0", &[ARM]), row("fuz", "0.2.0", &[X86])],
            "fuz",
            "0.2.0",
        );
        let changes = plan_pointers(&rows, &[pointer("fuz", "0.2.0", X86)], "fuz", "0.2.0");
        assert_eq!(
            changes,
            [PointerChange {
                path: format!("latest/fuz-{X86}.sha512"),
                target: X86.to_string(),
                after: PointerAfter::Removed,
            }]
        );
    }

    #[test]
    fn each_target_is_settled_on_its_own() {
        let rows = revoked(
            vec![
                row("fuz", "0.1.0", &[X86]),
                row("fuz", "0.2.0", &[X86, ARM]),
            ],
            "fuz",
            "0.2.0",
        );
        let tracked = [pointer("fuz", "0.2.0", X86), pointer("fuz", "0.2.0", ARM)];
        let changes = plan_pointers(&rows, &tracked, "fuz", "0.2.0");
        // Target order; one moves, the other has nothing to move to.
        assert_eq!(
            changes,
            [
                PointerChange {
                    path: format!("latest/fuz-{ARM}.sha512"),
                    target: ARM.to_string(),
                    after: PointerAfter::Removed,
                },
                PointerChange {
                    path: format!("latest/fuz-{X86}.sha512"),
                    target: X86.to_string(),
                    after: moved("fuz", "0.1.0", X86),
                },
            ]
        );
    }

    #[test]
    fn pointers_that_name_another_version_are_left_alone() {
        let rows = revoked(
            vec![
                row("fuz", "0.1.0", &[X86, ARM]),
                row("fuz", "0.2.0", &[X86, ARM]),
            ],
            "fuz",
            "0.1.0",
        );
        // x86 names the newer release; arm has no pointer at all; and a
        // pointer of another name sits at an unrelated path.
        let tracked = [pointer("fuz", "0.2.0", X86), pointer("other", "0.1.0", X86)];
        assert_eq!(plan_pointers(&rows, &tracked, "fuz", "0.1.0"), []);

        // A release the head does not record changes nothing either.
        assert_eq!(plan_pointers(&rows, &tracked, "fuz", "9.9.9"), []);
    }

    #[test]
    fn a_tool_pointer_is_settled_like_any_other() {
        // Nothing here is particular to the self artifact's name.
        let rows = revoked(
            vec![row("fuzd", "0.1.0", &[X86]), row("fuzd", "0.2.0", &[X86])],
            "fuzd",
            "0.2.0",
        );
        let changes = plan_pointers(&rows, &[pointer("fuzd", "0.2.0", X86)], "fuzd", "0.2.0");
        assert_eq!(
            changes,
            [PointerChange {
                path: format!("latest/fuzd-{X86}.sha512"),
                target: X86.to_string(),
                after: moved("fuzd", "0.1.0", X86),
            }]
        );
    }

    #[test]
    fn errors_classify_and_hint_by_what_the_operator_does() {
        let unsigned = || {
            LogWriteError::ExistingHead(fuz_release::ReleaseLogError::Signature(
                fuz_crypto::VerifyError::InvalidSignature,
            ))
        };
        let git = || LogWriteError::Git {
            command: "push".to_string(),
            output: "refused".to_string(),
        };
        let table: Vec<(RevokeError, bool)> = vec![
            (RevokeError::NoHead, false),
            (
                RevokeError::UnknownRelease {
                    name: "fuz".to_string(),
                    version: "0.1.0".to_string(),
                },
                false,
            ),
            (
                RevokeError::Pointer {
                    path: "latest/notes".to_string(),
                    reason: "no trailing newline",
                },
                false,
            ),
            (RevokeError::Log(unsigned()), true),
            (RevokeError::Log(git()), false),
            (RevokeError::Unpublished(git()), false),
            (RevokeError::PublishedWrong(unsigned()), true),
            (RevokeError::ReadBackFailed(git()), false),
        ];
        for (error, violation) in &table {
            assert_eq!(error.is_security_violation(), *violation, "{error}");
            assert!(
                error.hint().is_some(),
                "every revoke error says what to do: {error}"
            );
        }
        // A head in an older signature format: the log write's recreate hint,
        // not the revoke's revert-and-retry one. A newer format keeps it.
        let existing = |format| {
            RevokeError::Log(LogWriteError::ExistingHead(
                fuz_release::ReleaseLogError::Signature(
                    fuz_crypto::VerifyError::UnsupportedFormat(format),
                ),
            ))
        };
        let older = existing(fuz_crypto::SIGNATURE_FORMAT_VERSION - 1);
        let hint = older.hint().unwrap();
        assert!(hint.contains("release-log backfill"), "{hint}");
        assert!(!hint.contains("git revert"), "{hint}");
        let newer = existing(fuz_crypto::SIGNATURE_FORMAT_VERSION + 1);
        let hint = newer.hint().unwrap();
        assert!(hint.contains("revoke again"), "{hint}");

        // The two ways into a log are both named for a log with no head.
        let hint = RevokeError::NoHead.hint().unwrap();
        assert!(hint.contains("release-log backfill"), "{hint}");
        assert!(hint.contains("--log-repo"), "{hint}");
        // Retry advice is worded for a revoke, not a publish.
        for error in [
            RevokeError::Log(git()),
            RevokeError::Log(unsigned()),
            RevokeError::Log(LogWriteError::Dirty {
                paths: "M head.json".to_string(),
            }),
            RevokeError::Unpublished(git()),
        ] {
            let hint = error.hint().unwrap();
            assert!(hint.contains("revoke again"), "{hint}");
            assert!(!hint.contains("publish"), "{hint}");
        }

        // A read-back that could not read is not a verdict on the pushed log.
        assert!(matches!(
            RevokeError::from_read_back(git()),
            RevokeError::ReadBackFailed(_)
        ));
        assert!(matches!(
            RevokeError::from_read_back(LogWriteError::NotRevoked {
                name: "fuz".to_string(),
                version: "0.1.0".to_string(),
                detail: "the pushed head.json does not record the release as revoked",
            }),
            RevokeError::PublishedWrong(_)
        ));
    }

    #[test]
    fn a_hostile_name_cannot_forge_an_error_line() {
        let hostile = "fuz\nerror: all is well\x1b[2K";
        let message = RevokeError::UnknownRelease {
            name: hostile.to_string(),
            version: hostile.to_string(),
        }
        .to_string();
        assert_eq!(message.lines().count(), 1, "{message:?}");
        assert!(!message.contains('\x1b'), "{message:?}");
        let message = RevokeError::Pointer {
            path: hostile.to_string(),
            reason: "not UTF-8",
        }
        .to_string();
        assert_eq!(message.lines().count(), 1, "{message:?}");
    }

    /// A blank filler prints as empty space: a name holding one is spelled
    /// out, and a `"` in it does not close the quotes it is shown in.
    #[test]
    fn a_name_is_shown_in_quotes_it_cannot_close_with_nothing_hidden() {
        assert_eq!(
            RevokeError::UnknownRelease {
                name: "fuz\u{3164}\" \"9.9.9".to_string(),
                version: "0.1.0\u{2800}\0\" \"x".to_string(),
            }
            .to_string(),
            "the release log has no row for \"fuz\\u{3164}\\\" \\\"9.9.9\" \
             \"0.1.0\\u{2800}\\u{0}\\\" \\\"x\""
        );
    }
}
