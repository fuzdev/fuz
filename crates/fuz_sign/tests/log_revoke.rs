//! Revoking a release in the release log: `revoke_release` against a real git
//! checkout whose upstream is a local bare repository, so every commit, push,
//! and read-back is genuine.
//!
//! The log each test revokes in is built by the publish path's own log write
//! (`record_release`), so the rows and `latest/` pointers are the ones a
//! publish leaves. Heads are signed and verified for real, with the signing
//! keys admitted through `fuz_crypto`'s dev-dependency-only `test_trust_anchor`
//! seam. The tests skip when `git` is absent.

#![expect(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test helpers outside `#[test]` fns panic on a failed setup or check"
)]

mod common;

use common::*;

use fuz_crypto::{ContentHash, VerifyError};
use fuz_release::{
    Head, HeadOrder, LogWriteError, ReleaseLogError, RowStatus, Succession, check_consistent,
    check_successor, check_superset, current_target, is_revoked, sidecar_content,
};
use fuz_sign::release_log::{HEAD_FILE, NextHead};
use fuz_sign::revoke::next_revoked_head;
use fuz_sign::{
    LogEntry, PointerAfter, PointerChange, Revocation, RevokeError, RevokeOptions, RevokeReport,
    SigningKey, revoke_release,
};

const AFTER: &str = "2025-03-01T00:00:00Z";

/// Something a test does to the pointer file at a path.
type BreakPointer = fn(&std::path::Path);

const DRY_RUN: RevokeOptions = RevokeOptions { dry_run: true };
const WETRUN: RevokeOptions = RevokeOptions { dry_run: false };

/// The bytes of the self artifact logged for `version` on `target`.
fn content(version: &str, target: &str) -> Vec<u8> {
    format!("fuz {version} {target}").into_bytes()
}

/// Log the self artifact `version` for `target`, as a publish does.
#[track_caller]
fn log_self(fixture: &Fixture, version: &str, target: &str) {
    record_release(
        &fixture.repo(),
        &self_entry(version, target, &content(version, target)),
        &trusted_key(),
        NOW,
    )
    .unwrap();
}

/// A fixture whose log holds the self artifact at each of `versions`, for the
/// host target, logged in that order — so the pointer names the last.
fn logged(versions: &[&str]) -> Fixture {
    let fixture = Fixture::new();
    for version in versions {
        log_self(&fixture, version, current_target());
    }
    fixture
}

fn pointer_path(target: &str) -> String {
    format!("latest/fuz-{target}.sha512")
}

/// The pointer line a publish writes for `version` on `target`.
fn pointer_line(version: &str, target: &str) -> String {
    sidecar_content(
        &format!("fuz-{version}-{target}"),
        &ContentHash::sha512(&content(version, target)).to_hex(),
    )
}

/// The pointer for `target` in the remote's `main`, if it has one.
fn remote_pointer(fixture: &Fixture, target: &str) -> Option<String> {
    let path = pointer_path(target);
    fixture
        .remote_tree()
        .contains(&path)
        .then(|| fixture.remote_git(&["show", &format!("main:{path}")]) + "\n")
}

fn revoke(
    fixture: &Fixture,
    version: &str,
    key: &SigningKey,
    options: RevokeOptions,
) -> Result<RevokeReport, RevokeError> {
    revoke_release(&fixture.repo(), "fuz", version, key, AFTER, options)
}

fn moved(version: &str, target: &str) -> PointerChange {
    PointerChange {
        path: pointer_path(target),
        target: target.to_string(),
        after: PointerAfter::Moved {
            version: version.to_string(),
            content: pointer_line(version, target),
        },
    }
}

fn removed(target: &str) -> PointerChange {
    PointerChange {
        path: pointer_path(target),
        target: target.to_string(),
        after: PointerAfter::Removed,
    }
}

//
// Dry run and wetrun
//

/// A dry run reads and checks everything, reports what it would write, and
/// writes nothing: not the head, not a pointer, not a commit.
#[test]
fn a_dry_run_reports_and_writes_nothing() {
    if !git_available() {
        return;
    }
    let host = current_target();
    let fixture = logged(&["0.1.0", "0.2.0"]);
    let before = fixture.state();
    let pointer_before = std::fs::read(fixture.checkout.join(pointer_path(host))).unwrap();

    let report = revoke(&fixture, "0.2.0", &trusted_key(), DRY_RUN).unwrap();
    assert_eq!(
        report,
        RevokeReport {
            dry_run: true,
            name: "fuz".to_string(),
            version: "0.2.0".to_string(),
            targets: vec![host.to_string()],
            seq: 3,
            revocation: Revocation::Revoked,
            pointers: vec![moved("0.1.0", host)],
            commit_message: Some("log: revoke fuz 0.2.0 seq 3".to_string()),
            pushed: false,
        }
    );

    assert_eq!(fixture.state(), before);
    assert_eq!(
        std::fs::read(fixture.checkout.join(pointer_path(host))).unwrap(),
        pointer_before
    );
    assert_eq!(fixture.remote_head("main").seq(), 2);
    assert!(!is_revoked(&fixture.remote_head("main"), "fuz", "0.2.0"));

    // A dry run still brings a checkout that is behind up to its upstream —
    // the one thing it writes — and decides from the log as it is now.
    let second = fixture.tmp.path().join("second");
    fixture.init_checkout(&second);
    record_release(
        &fixture.repo_at(&second),
        &self_entry("0.3.0", host, &content("0.3.0", host)),
        &trusted_key(),
        LATER,
    )
    .unwrap();
    let report = revoke(&fixture, "0.3.0", &trusted_key(), DRY_RUN).unwrap();
    assert_eq!(report.seq, 4);
    assert_eq!(report.pointers, [moved("0.2.0", host)]);
    assert_eq!(
        fixture.git(&["rev-parse", "HEAD"]),
        fixture.remote_git(&["rev-parse", "main"])
    );
    assert_eq!(fixture.remote_head("main").seq(), 3);
}

/// A wetrun signs the next head with the row revoked, moves the pointer that
/// named the release, and pushes one commit holding exactly those two files.
/// A reader's rules take the new head as a successor of the old one, and its
/// verdict for the release is revoked.
#[test]
fn a_wetrun_revokes_the_row_and_moves_the_pointer() {
    if !git_available() {
        return;
    }
    let host = current_target();
    let other = other_target();
    let fixture = logged(&["0.1.0", "0.2.0"]);
    // A second target of the release goes with it; it has its own pointer and
    // no earlier release to fall back to.
    log_self(&fixture, "0.2.0", other);
    let previous = fixture.remote_head("main");
    assert_eq!(previous.seq(), 3);

    let report = revoke(&fixture, "0.2.0", &trusted_key(), WETRUN).unwrap();
    let mut targets = vec![host.to_string(), other.to_string()];
    targets.sort();
    let mut pointers = vec![moved("0.1.0", host), removed(other)];
    pointers.sort_by(|a, b| a.target.cmp(&b.target));
    assert_eq!(
        report,
        RevokeReport {
            dry_run: false,
            name: "fuz".to_string(),
            version: "0.2.0".to_string(),
            targets,
            seq: 4,
            revocation: Revocation::Revoked,
            pointers,
            commit_message: Some("log: revoke fuz 0.2.0 seq 4".to_string()),
            pushed: true,
        }
    );

    // One commit, named for what it did, holding the head and both pointers.
    assert_eq!(
        fixture.remote_subjects().last().map(String::as_str),
        Some("log: revoke fuz 0.2.0 seq 4")
    );
    let mut files = vec![
        HEAD_FILE.to_string(),
        pointer_path(host),
        pointer_path(other),
    ];
    files.sort();
    assert_eq!(fixture.remote_commit_files("main"), files);

    // The head: the next seq, the row revoked with both targets intact, every
    // other row as it was — and a successor under the rules a reader applies.
    let head = fixture.remote_head("main");
    assert_eq!(head.seq(), 4);
    assert_eq!(
        check_successor(&previous, &head),
        Ok(Succession::Advanced),
        "a reader holding the old head accepts the new one"
    );
    // And never the other way: a mirror still serving the old head is a
    // lagging copy of the same log, and the old head cannot replace the new.
    assert_eq!(
        check_consistent(&head, &previous),
        Ok(HeadOrder::FirstNewer)
    );
    assert!(check_superset(&head, &previous).is_err());
    let row = head.row("fuz", "0.2.0").unwrap();
    assert_eq!(row.status, RowStatus::Revoked);
    assert_eq!(row.targets, previous.row("fuz", "0.2.0").unwrap().targets);
    assert_eq!(
        row.published_at,
        previous.row("fuz", "0.2.0").unwrap().published_at
    );
    assert_eq!(head.row("fuz", "0.1.0"), previous.row("fuz", "0.1.0"));
    assert_eq!(head.rows().len(), previous.rows().len());
    assert_eq!(
        head.keys(),
        previous.keys(),
        "the same key signed; no new record"
    );
    assert!(is_revoked(&head, "fuz", "0.2.0"));
    assert!(!is_revoked(&head, "fuz", "0.1.0"));

    // The pointers: one moved to the release that still stands, one removed.
    assert_eq!(
        remote_pointer(&fixture, host),
        Some(pointer_line("0.1.0", host))
    );
    assert_eq!(remote_pointer(&fixture, other), None);
    assert!(!fixture.checkout.join(pointer_path(other)).exists());

    // The checkout holds the pushed state and nothing uncommitted.
    assert_eq!(fixture.git(&["status", "--porcelain"]), "");
    assert_eq!(
        fixture.git(&["rev-parse", "HEAD"]),
        fixture.remote_git(&["rev-parse", "main"])
    );
}

/// With no other release to point at, the pointer is removed — and the
/// directory with it, since git tracks no empty one.
#[test]
fn a_pointer_with_no_successor_is_removed() {
    if !git_available() {
        return;
    }
    let host = current_target();
    let fixture = logged(&["0.1.0"]);

    let report = revoke(&fixture, "0.1.0", &trusted_key(), WETRUN).unwrap();
    assert_eq!(report.pointers, [removed(host)]);
    assert_eq!(report.seq, 2);

    assert_eq!(fixture.remote_tree(), [HEAD_FILE]);
    assert!(!fixture.checkout.join("latest").exists());
    assert!(is_revoked(&fixture.remote_head("main"), "fuz", "0.1.0"));
    assert_eq!(fixture.git(&["status", "--porcelain"]), "");
}

/// The pointer moves to the newest release it can name: a revoked row, a row
/// without the target, and a row without a `sha512` for it are passed over,
/// whatever their versions. Pointers that name another version stay put.
#[test]
fn unusable_candidates_are_passed_over_and_other_pointers_untouched() {
    if !git_available() {
        return;
    }
    let host = current_target();
    let other = other_target();
    let key = trusted_key();
    let fixture = logged(&["0.1.0", "0.2.0"]);
    // 0.3.0 exists only for the other target.
    log_self(&fixture, "0.3.0", other);
    // 0.4.0 has the host target but no flat binary: no sha512, no pointer.
    let mut flatless = self_entry("0.4.0", host, &content("0.4.0", host));
    flatless.pins.sha512 = None;
    flatless.flat_latest = false;
    record_release(&fixture.repo(), &flatless, &key, NOW).unwrap();
    log_self(&fixture, "0.5.0", host);

    // 0.2.0 goes first; its pointer has moved on, so nothing else changes.
    let report = revoke(&fixture, "0.2.0", &key, WETRUN).unwrap();
    assert_eq!(report.pointers, []);
    assert_eq!(
        report.commit_message.as_deref(),
        Some("log: revoke fuz 0.2.0 seq 6")
    );
    assert_eq!(fixture.remote_commit_files("main"), [HEAD_FILE]);
    assert_eq!(
        remote_pointer(&fixture, host),
        Some(pointer_line("0.5.0", host))
    );

    // Revoking 0.5.0 skips 0.4.0 (no sha512), 0.3.0 (no such target), and
    // 0.2.0 (revoked), and lands on 0.1.0. The other target's pointer names
    // 0.3.0 and is not this release's to move.
    let report = revoke(&fixture, "0.5.0", &key, WETRUN).unwrap();
    assert_eq!(report.pointers, [moved("0.1.0", host)]);
    assert_eq!(
        remote_pointer(&fixture, host),
        Some(pointer_line("0.1.0", host))
    );
    assert_eq!(
        remote_pointer(&fixture, other),
        Some(pointer_line("0.3.0", other))
    );
    let mut files = vec![HEAD_FILE.to_string(), pointer_path(host)];
    files.sort();
    assert_eq!(fixture.remote_commit_files("main"), files);
}

/// A tool's row has no `latest/` pointer: revoking it changes the head alone.
/// A key the head has not recorded is recorded by the revocation it signs.
#[test]
fn a_tool_release_is_revoked_without_pointers_and_a_new_key_is_recorded() {
    if !git_available() {
        return;
    }
    let host = current_target();
    let fixture = logged(&["0.1.0"]);
    let mut tool = self_entry("0.3.0", host, b"fuzd bytes");
    tool.name = "fuzd".to_string();
    tool.pins.sha512 = None;
    tool.flat_latest = false;
    record_release(&fixture.repo(), &tool, &trusted_key(), NOW).unwrap();
    let previous = fixture.remote_head("main");

    let key = second_trusted_key();
    let report = revoke_release(&fixture.repo(), "fuzd", "0.3.0", &key, AFTER, WETRUN).unwrap();
    assert_eq!(report.pointers, []);
    assert_eq!(report.targets, [host.to_string()]);
    assert_eq!(fixture.remote_commit_files("main"), [HEAD_FILE]);

    let head = fixture.remote_head("main");
    assert!(is_revoked(&head, "fuzd", "0.3.0"));
    assert!(!is_revoked(&head, "fuz", "0.1.0"));
    assert_eq!(check_successor(&previous, &head), Ok(Succession::Advanced));
    assert_eq!(head.keys().len(), 2);
    assert_eq!(head.keys()[0], previous.keys()[0]);
    assert_eq!(head.keys()[1].public_key, public_key(&key));
    assert_eq!(head.keys()[1].added_at, AFTER);
    // The self artifact's pointer is not the tool's.
    assert_eq!(
        remote_pointer(&fixture, host),
        Some(pointer_line("0.1.0", host))
    );
}

//
// Running it again
//

/// A second run finds the release revoked: it signs nothing, commits nothing,
/// and says so. The log is as the first run left it.
#[test]
fn a_second_run_signs_no_new_head() {
    if !git_available() {
        return;
    }
    let host = current_target();
    let fixture = logged(&["0.1.0", "0.2.0"]);
    revoke(&fixture, "0.2.0", &trusted_key(), WETRUN).unwrap();
    let before = fixture.state();
    let head_before = fixture.remote_git(&["show", &format!("main:{HEAD_FILE}")]);

    for options in [DRY_RUN, WETRUN] {
        let report = revoke(&fixture, "0.2.0", &trusted_key(), options).unwrap();
        assert_eq!(
            report,
            RevokeReport {
                dry_run: options.dry_run,
                name: "fuz".to_string(),
                version: "0.2.0".to_string(),
                targets: vec![host.to_string()],
                seq: 3,
                revocation: Revocation::AlreadyRevoked,
                pointers: Vec::new(),
                commit_message: None,
                pushed: false,
            }
        );
        assert_eq!(fixture.state(), before);
        assert_eq!(
            fixture.remote_git(&["show", &format!("main:{HEAD_FILE}")]),
            head_before
        );
    }
}

/// A push that fails leaves the revocation committed in the checkout. The same
/// revoke run again signs no second head, pushes the waiting commit, and reads
/// it back: one commit, one `seq`.
#[test]
fn a_failed_push_is_completed_by_the_same_revoke() {
    if !git_available() {
        return;
    }
    let host = current_target();
    let fixture = logged(&["0.1.0", "0.2.0"]);
    let remote_before = fixture.remote_git(&["rev-parse", "main"]);

    fixture.reject_pushes();
    let error = revoke(&fixture, "0.2.0", &trusted_key(), WETRUN).unwrap_err();
    assert!(
        matches!(&error, RevokeError::Unpublished(LogWriteError::Git { command, .. }) if command == "push"),
        "{error:?}"
    );
    assert!(error.hint().unwrap().contains("same revoke again"));
    assert!(!error.is_security_violation());
    // Committed here, not there.
    assert_eq!(fixture.remote_git(&["rev-parse", "main"]), remote_before);
    assert_eq!(
        fixture.git(&["log", "-1", "--format=%s"]),
        "log: revoke fuz 0.2.0 seq 3"
    );
    let waiting = fixture.git(&["rev-parse", "HEAD"]);

    fixture.accept_pushes();
    let report = revoke(&fixture, "0.2.0", &trusted_key(), WETRUN).unwrap();
    assert_eq!(report.revocation, Revocation::AlreadyRevoked);
    assert_eq!(report.seq, 3);
    assert_eq!(report.pointers, []);
    assert_eq!(report.commit_message, None);
    assert!(report.pushed, "the waiting commit went out");

    assert_eq!(fixture.git(&["rev-parse", "HEAD"]), waiting);
    assert_eq!(fixture.remote_git(&["rev-parse", "main"]), waiting);
    let subjects = fixture.remote_subjects();
    assert_eq!(
        subjects
            .iter()
            .filter(|subject| subject.contains("revoke"))
            .count(),
        1
    );
    let head = fixture.remote_head("main");
    assert_eq!(head.seq(), 3);
    assert!(is_revoked(&head, "fuz", "0.2.0"));
    assert_eq!(
        remote_pointer(&fixture, host),
        Some(pointer_line("0.1.0", host))
    );
}

/// A release that is already revoked while a pointer still names it — a
/// pointer put back by hand — signs no head and repairs the pointer in a
/// commit of its own.
#[test]
fn a_pointer_still_naming_a_revoked_release_is_repaired() {
    if !git_available() {
        return;
    }
    let host = current_target();
    let fixture = logged(&["0.1.0", "0.2.0"]);
    revoke(&fixture, "0.2.0", &trusted_key(), WETRUN).unwrap();
    std::fs::write(
        fixture.checkout.join(pointer_path(host)),
        pointer_line("0.2.0", host),
    )
    .unwrap();
    fixture.commit_all_and_push("put the pointer back");
    let head_before = fixture.remote_git(&["show", &format!("main:{HEAD_FILE}")]);

    let report = revoke(&fixture, "0.2.0", &trusted_key(), WETRUN).unwrap();
    assert_eq!(report.revocation, Revocation::AlreadyRevoked);
    assert_eq!(report.seq, 3);
    assert_eq!(report.pointers, [moved("0.1.0", host)]);
    assert_eq!(
        report.commit_message.as_deref(),
        Some("log: latest revoke fuz 0.2.0 seq 3")
    );
    assert!(report.pushed);

    assert_eq!(
        fixture.remote_subjects().last().map(String::as_str),
        Some("log: latest revoke fuz 0.2.0 seq 3")
    );
    assert_eq!(fixture.remote_commit_files("main"), [pointer_path(host)]);
    assert_eq!(
        fixture.remote_git(&["show", &format!("main:{HEAD_FILE}")]),
        head_before,
        "the head is not signed again"
    );
    assert_eq!(
        remote_pointer(&fixture, host),
        Some(pointer_line("0.1.0", host))
    );
}

/// A commit that fails is rolled back — a removed pointer is back, the head is
/// the old one — and the revoke can simply run again.
#[test]
fn a_failed_commit_restores_the_head_and_a_removed_pointer() {
    if !git_available() {
        return;
    }
    let host = current_target();
    let fixture = logged(&["0.1.0"]);
    let before = fixture.state();
    let pointer_before = std::fs::read(fixture.checkout.join(pointer_path(host))).unwrap();
    Fixture::install_hook(
        &fixture.checkout.join(".git"),
        "pre-commit",
        "#!/bin/sh\necho 'commit refused by the test hook' >&2\nexit 1\n",
    );

    let error = revoke(&fixture, "0.1.0", &trusted_key(), WETRUN).unwrap_err();
    assert!(
        matches!(&error, RevokeError::Log(LogWriteError::Git { command, .. }) if command == "commit"),
        "{error:?}"
    );
    assert!(error.hint().unwrap().contains("revoke again"));
    assert_eq!(fixture.state(), before);
    assert_eq!(
        std::fs::read(fixture.checkout.join(pointer_path(host))).unwrap(),
        pointer_before
    );

    std::fs::remove_file(fixture.checkout.join(".git/hooks/pre-commit")).unwrap();
    let report = revoke(&fixture, "0.1.0", &trusted_key(), WETRUN).unwrap();
    assert_eq!(report.revocation, Revocation::Revoked);
    assert_eq!(report.pointers, [removed(host)]);
    assert_eq!(fixture.remote_tree(), [HEAD_FILE]);
}

//
// Refusals
//

/// What cannot be revoked is refused before anything is written: a log with
/// no head, a release the head does not record, a key this binary does not
/// trust.
#[test]
fn a_revocation_that_cannot_be_made_writes_nothing() {
    if !git_available() {
        return;
    }
    // No head: a checkout that has never held one.
    let fixture = Fixture::new();
    let before = fixture.state();
    for options in [DRY_RUN, WETRUN] {
        let error = revoke(&fixture, "0.1.0", &trusted_key(), options).unwrap_err();
        assert!(matches!(error, RevokeError::NoHead), "{error:?}");
        let hint = error.hint().unwrap();
        assert!(hint.contains("release-log backfill"), "{hint}");
        assert!(hint.contains("publishing with --log-repo"), "{hint}");
        assert_eq!(fixture.state(), before);
    }

    // A release the head does not record: another version, another name, and
    // a name no head could hold, echoed escaped.
    let fixture = logged(&["0.1.0"]);
    let before = fixture.state();
    for (name, version) in [
        ("fuz", "0.9.0"),
        ("fuzd", "0.1.0"),
        ("fuz\n", "0.1.0\x1b[2K"),
    ] {
        for options in [DRY_RUN, WETRUN] {
            let error = revoke_release(
                &fixture.repo(),
                name,
                version,
                &trusted_key(),
                AFTER,
                options,
            )
            .unwrap_err();
            assert!(
                matches!(&error, RevokeError::UnknownRelease { name: n, version: v }
                    if n == name && v == version),
                "{error:?}"
            );
            let message = error.to_string();
            assert_eq!(message.lines().count(), 1, "{message:?}");
            assert!(!message.contains('\x1b'), "{message:?}");
            assert!(!error.is_security_violation());
            assert_eq!(fixture.state(), before);
        }
    }

    // An untrusted key: refused for a release it could revoke and for one that
    // is revoked already, where nothing would be signed.
    let fixture = logged(&["0.1.0", "0.2.0"]);
    revoke(&fixture, "0.2.0", &trusted_key(), WETRUN).unwrap();
    let before = fixture.state();
    for version in ["0.1.0", "0.2.0"] {
        for options in [DRY_RUN, WETRUN] {
            let error = revoke(&fixture, version, &untrusted_key(), options).unwrap_err();
            assert!(
                matches!(
                    &error,
                    RevokeError::Log(LogWriteError::UntrustedKey { public_key: recorded })
                        if *recorded == public_key(&untrusted_key())
                ),
                "{error:?}"
            );
            assert!(error.is_security_violation());
            assert_eq!(fixture.state(), before);
        }
    }
    assert!(!is_revoked(&fixture.remote_head("main"), "fuz", "0.1.0"));
}

/// The checkout is held to what a publish holds it to, and a head that does
/// not verify is never replaced.
#[test]
fn an_unfit_checkout_or_head_is_refused() {
    if !git_available() {
        return;
    }
    let host = current_target();

    let fixture = logged(&["0.1.0"]);
    let missing = fixture.tmp.path().join("no-such-checkout");
    let error = revoke_release(
        &fixture.repo_at(&missing),
        "fuz",
        "0.1.0",
        &trusted_key(),
        AFTER,
        WETRUN,
    )
    .unwrap_err();
    assert!(
        matches!(error, RevokeError::Log(LogWriteError::CheckoutMissing(_))),
        "{error:?}"
    );

    // An uncommitted change to a pointer.
    std::fs::write(fixture.checkout.join(pointer_path(host)), "edited\n").unwrap();
    let error = revoke(&fixture, "0.1.0", &trusted_key(), WETRUN).unwrap_err();
    assert!(
        matches!(error, RevokeError::Log(LogWriteError::Dirty { .. })),
        "{error:?}"
    );
    assert!(error.hint().unwrap().contains("revoke again"));
    fixture.git(&["checkout", "--quiet", "HEAD", "--", "latest"]);

    // A head that does not verify.
    let before_head = std::fs::read(fixture.checkout.join(HEAD_FILE)).unwrap();
    let tampered = String::from_utf8(before_head)
        .unwrap()
        .replace("\"ok\"", "\"revoked\"");
    std::fs::write(fixture.checkout.join(HEAD_FILE), &tampered).unwrap();
    fixture.commit_all_and_push("tamper with the head");
    let before = fixture.state();
    let error = revoke(&fixture, "0.1.0", &trusted_key(), WETRUN).unwrap_err();
    assert!(
        matches!(
            error,
            RevokeError::Log(LogWriteError::ExistingHead(ReleaseLogError::Signature(_)))
        ),
        "{error:?}"
    );
    assert!(error.is_security_violation());
    assert_eq!(fixture.state(), before);
}

/// A head signed before domain separation (envelope format 1) stops a revoke,
/// dry run or not, with the log write's recreate hint rather than the revoke's
/// revert-and-retry one: no head in the log's history is one this build reads.
#[test]
fn a_pre_tag_head_stops_the_revoke_with_the_recreate_hint() {
    if !git_available() {
        return;
    }
    trust();
    let fixture = logged(&["0.1.0"]);
    let current = Head::from_json(&fixture.checkout_head_bytes().unwrap())
        .unwrap()
        .verify_signature()
        .unwrap();
    fixture.seed_head(&pre_tag_head(current.to_unsigned()));
    let before = fixture.state();

    for options in [DRY_RUN, WETRUN] {
        let error = revoke(&fixture, "0.1.0", &trusted_key(), options).unwrap_err();
        assert!(
            matches!(
                error,
                RevokeError::Log(LogWriteError::ExistingHead(ReleaseLogError::Signature(
                    VerifyError::UnsupportedFormat(1)
                )))
            ),
            "{error:?}"
        );
        assert!(error.is_security_violation());
        let hint = error.hint().unwrap();
        assert!(hint.contains("release-log backfill"), "{hint}");
        assert!(!hint.contains("git revert"), "{hint}");
        assert_eq!(fixture.state(), before);
    }
}

/// The release's own pointer is read to decide whether it names the release.
/// One that is not a pointer line stops the revocation rather than being
/// stepped over.
#[test]
fn a_consulted_pointer_that_is_not_a_pointer_line_is_an_error() {
    if !git_available() {
        return;
    }
    let host = current_target();
    let crlf = pointer_line("0.2.0", host).replace('\n', "\r\n");
    let cases: [(&[u8], &str); 4] = [
        (b"not a pointer\n", "separator"),
        (b"", "newline"),
        (&[b'a'; 5000], "too large"),
        (crlf.as_bytes(), "one line"),
    ];
    for (bytes, reason) in cases {
        let fixture = logged(&["0.1.0", "0.2.0"]);
        // Committed as it is: no line-ending conversion on the way in.
        fixture.git(&["config", "core.autocrlf", "false"]);
        std::fs::write(fixture.checkout.join(pointer_path(host)), bytes).unwrap();
        fixture.commit_all_and_push("break the pointer");
        let before = fixture.state();

        for options in [DRY_RUN, WETRUN] {
            let error = revoke(&fixture, "0.2.0", &trusted_key(), options).unwrap_err();
            match &error {
                RevokeError::Pointer {
                    path: at,
                    reason: why,
                } => {
                    assert_eq!(*at, pointer_path(host));
                    assert!(why.contains(reason), "{reason}: {why}");
                }
                other => panic!("{reason}: expected a pointer error, got {other:?}"),
            }
            assert!(error.hint().is_some());
            assert!(!error.is_security_violation());
            assert_eq!(fixture.state(), before, "{reason}");
        }
        assert!(!is_revoked(&fixture.remote_head("main"), "fuz", "0.2.0"));
    }
}

/// Only the release's own pointers are read. Anything else under `latest/` —
/// a stray file, a malformed pointer for a target the release does not have —
/// neither blocks the revocation nor is touched by it.
#[test]
fn unrelated_files_under_latest_do_not_block_a_revocation() {
    if !git_available() {
        return;
    }
    let host = current_target();
    let other = other_target();
    let fixture = logged(&["0.1.0", "0.2.0"]);
    fixture.git(&["config", "core.autocrlf", "false"]);
    let crlf = pointer_line("0.1.0", other).replace('\n', "\r\n");
    let unrelated: [(String, &[u8]); 3] = [
        ("latest/notes.txt".to_string(), b"not a pointer\n"),
        (pointer_path(other), crlf.as_bytes()),
        ("latest/huge.sha512".to_string(), &[b'a'; 5000]),
    ];
    for (path, bytes) in &unrelated {
        std::fs::write(fixture.checkout.join(path), bytes).unwrap();
    }
    fixture.commit_all_and_push("add files under latest/");

    let report = revoke(&fixture, "0.2.0", &trusted_key(), DRY_RUN).unwrap();
    assert_eq!(report.pointers, [moved("0.1.0", host)]);
    let report = revoke(&fixture, "0.2.0", &trusted_key(), WETRUN).unwrap();
    assert_eq!(report.revocation, Revocation::Revoked);
    assert_eq!(report.pointers, [moved("0.1.0", host)]);

    assert!(is_revoked(&fixture.remote_head("main"), "fuz", "0.2.0"));
    let mut files = vec![HEAD_FILE.to_string(), pointer_path(host)];
    files.sort();
    assert_eq!(fixture.remote_commit_files("main"), files);
    for (path, bytes) in &unrelated {
        assert_eq!(
            std::fs::read(fixture.checkout.join(path)).unwrap(),
            *bytes,
            "{path} is left as it was"
        );
    }
    assert_eq!(fixture.git(&["status", "--porcelain"]), "");
}

/// A consulted pointer the log tracks as a symlink — or as anything but a
/// plain file — is the unsafe path a publish refuses, not a pointer with a
/// formatting problem.
#[test]
fn a_committed_symlink_at_a_pointer_path_is_refused_as_unsafe() {
    if !git_available() {
        return;
    }
    let host = current_target();
    let cases: [(&str, BreakPointer); 2] = [
        ("a symlink", |path| {
            std::fs::remove_file(path).unwrap();
            std::os::unix::fs::symlink("../head.json", path).unwrap();
        }),
        ("an executable", |path| {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }),
    ];
    for (case, break_pointer) in cases {
        let fixture = logged(&["0.1.0", "0.2.0"]);
        let path = fixture.checkout.join(pointer_path(host));
        break_pointer(&path);
        fixture.git(&["add", "-A"]);
        fixture.git(&["commit", "--quiet", "-m", "change the pointer's mode"]);
        fixture.git(&["push", "--quiet"]);
        let before = fixture.state();

        for options in [DRY_RUN, WETRUN] {
            let error = revoke(&fixture, "0.2.0", &trusted_key(), options).unwrap_err();
            match &error {
                RevokeError::Log(LogWriteError::UnsafePath { path: at, expected }) => {
                    assert!(at.ends_with(pointer_path(host)), "{case}: {at:?}");
                    assert_eq!(*expected, "file");
                }
                other => panic!("{case}: expected an unsafe path, got {other:?}"),
            }
            assert!(error.is_security_violation(), "{case}");
            assert_eq!(fixture.state(), before, "{case}");
        }
        assert!(!is_revoked(&fixture.remote_head("main"), "fuz", "0.2.0"));
    }
}

/// An ignore rule covering a pointer the revocation would change is refused
/// before anything is written: git would not stage the change.
#[test]
fn an_ignored_pointer_is_refused_before_anything_is_written() {
    if !git_available() {
        return;
    }
    let host = current_target();
    let fixture = logged(&["0.1.0", "0.2.0"]);
    std::fs::write(fixture.checkout.join(".gitignore"), "latest/\n").unwrap();
    fixture.commit_all_and_push("ignore latest");
    let before = fixture.state();
    let pointer_before = std::fs::read(fixture.checkout.join(pointer_path(host))).unwrap();

    for options in [DRY_RUN, WETRUN] {
        let error = revoke(&fixture, "0.2.0", &trusted_key(), options).unwrap_err();
        match &error {
            RevokeError::Log(LogWriteError::Ignored { paths }) => {
                assert_eq!(*paths, pointer_path(host));
            }
            other => panic!("expected an ignored pointer, got {other:?}"),
        }
        assert!(error.hint().unwrap().contains("revoke again"));
        assert_eq!(fixture.state(), before);
        assert_eq!(
            std::fs::read(fixture.checkout.join(pointer_path(host))).unwrap(),
            pointer_before
        );
    }
    assert!(!is_revoked(&fixture.remote_head("main"), "fuz", "0.2.0"));
}

/// A work tree with no `head.json` while the log's commits hold one is not a
/// log with no head: the revocation is refused for what it is, not sent to
/// the backfill.
#[test]
fn a_head_missing_from_the_work_tree_is_not_a_log_with_no_head() {
    if !git_available() {
        return;
    }
    let fixture = logged(&["0.1.0", "0.2.0"]);
    fixture.git(&["rm", "--quiet", HEAD_FILE]);
    fixture.git(&["commit", "--quiet", "-m", "drop the head"]);
    let before = fixture.state();
    for options in [DRY_RUN, WETRUN] {
        let error = revoke(&fixture, "0.2.0", &trusted_key(), options).unwrap_err();
        assert!(
            matches!(
                error,
                RevokeError::Log(LogWriteError::HeadMissing {
                    held_by: "its upstream"
                })
            ),
            "{error:?}"
        );
        assert!(!error.hint().unwrap().contains("backfill"));
        assert_eq!(fixture.state(), before);
    }
    assert_eq!(fixture.remote_head("main").seq(), 2);
}

//
// The read-back of the pushed commit
//

/// Require `error` to be a read-back that found the revocation missing, for
/// the reason `expected`.
#[track_caller]
fn not_revoked(error: &RevokeError, expected: &str) {
    match error {
        RevokeError::PublishedWrong(LogWriteError::NotRevoked {
            name,
            version,
            detail,
        }) => {
            assert_eq!(name, "fuz");
            assert!(version == "0.1.0" || version == "0.2.0", "{version}");
            assert!(detail.contains(expected), "{detail}");
        }
        other => panic!("expected an unpublished revocation, got {other:?}"),
    }
    assert!(error.hint().unwrap().contains("commit is on the remote"));
    assert!(!error.is_security_violation());
}

/// `Ok` means the pushed commit holds the revocation. A `pre-commit` hook that
/// puts the old head back, keeps a removed pointer, or rewrites a moved one
/// produces a commit and a push that both succeed; the read-back catches each.
#[test]
fn a_pushed_commit_without_the_revocation_is_an_error() {
    if !git_available() {
        return;
    }
    let host = current_target();

    // The hook restores the previous head: it verifies, and the row is `ok`.
    let fixture = logged(&["0.1.0", "0.2.0"]);
    let kept = fixture.tmp.path().join("kept-head.json");
    std::fs::copy(fixture.checkout.join(HEAD_FILE), &kept).unwrap();
    Fixture::install_hook(
        &fixture.checkout.join(".git"),
        "pre-commit",
        &format!(
            "#!/bin/sh\ncp '{}' head.json\ngit add head.json\n",
            kept.display()
        ),
    );
    let error = revoke(&fixture, "0.2.0", &trusted_key(), WETRUN).unwrap_err();
    not_revoked(&error, "revoked");
    assert!(!is_revoked(&fixture.remote_head("main"), "fuz", "0.2.0"));

    // The hook swaps the moved pointer.
    let fixture = logged(&["0.1.0", "0.2.0"]);
    let pointer = pointer_path(host);
    Fixture::install_hook(
        &fixture.checkout.join(".git"),
        "pre-commit",
        &format!("#!/bin/sh\nprintf 'not the digest\\n' > '{pointer}'\ngit add '{pointer}'\n"),
    );
    let error = revoke(&fixture, "0.2.0", &trusted_key(), WETRUN).unwrap_err();
    not_revoked(&error, "latest/ pointer");
    assert!(is_revoked(&fixture.remote_head("main"), "fuz", "0.2.0"));

    // The hook puts a removed pointer back.
    let fixture = logged(&["0.1.0"]);
    let kept = fixture.tmp.path().join("kept-pointer");
    std::fs::copy(fixture.checkout.join(&pointer), &kept).unwrap();
    Fixture::install_hook(
        &fixture.checkout.join(".git"),
        "pre-commit",
        &format!(
            "#!/bin/sh\nmkdir -p latest\ncp '{}' '{pointer}'\ngit add '{pointer}'\n",
            kept.display()
        ),
    );
    let error = revoke(&fixture, "0.1.0", &trusted_key(), WETRUN).unwrap_err();
    not_revoked(&error, "removes");
    assert!(fixture.remote_tree().contains(&pointer));

    // The hook replaces the head with something that is not one.
    let fixture = logged(&["0.1.0", "0.2.0"]);
    Fixture::install_hook(
        &fixture.checkout.join(".git"),
        "pre-commit",
        "#!/bin/sh\nprintf 'rewritten by a hook\\n' > head.json\ngit add head.json\n",
    );
    let error = revoke(&fixture, "0.2.0", &trusted_key(), WETRUN).unwrap_err();
    assert!(
        matches!(
            &error,
            RevokeError::PublishedWrong(LogWriteError::PublishedHead(ReleaseLogError::Parse(_)))
        ),
        "{error:?}"
    );
}

//
// Publishing after a revocation
//

/// A revoked release takes no further target; a new version is logged and
/// takes the pointer as usual; and an older release that still stands can be
/// published again, which moves the pointer back to it as before.
#[test]
fn publishing_after_a_revocation() {
    if !git_available() {
        return;
    }
    let host = current_target();
    let other = other_target();
    let key = trusted_key();
    let fixture = logged(&["0.1.0", "0.2.0"]);
    revoke(&fixture, "0.2.0", &key, WETRUN).unwrap();
    let before = fixture.state();

    // Another target of the revoked version, and the target it already has.
    let attempts: [LogEntry; 2] = [
        self_entry("0.2.0", other, &content("0.2.0", other)),
        self_entry("0.2.0", host, &content("0.2.0", host)),
    ];
    for entry in attempts {
        let error = record_release(&fixture.repo(), &entry, &key, AFTER).unwrap_err();
        assert!(
            matches!(
                &error,
                LogWriteError::RevokedRow { name, version } if name == "fuz" && version == "0.2.0"
            ),
            "{error:?}"
        );
        assert_eq!(fixture.state(), before);
    }

    // A new version: a row, the next seq, and the pointer.
    let recorded = record_release(
        &fixture.repo(),
        &self_entry("0.3.0", host, &content("0.3.0", host)),
        &key,
        AFTER,
    )
    .unwrap();
    assert_eq!((recorded.seq, recorded.advanced), (4, true));
    assert_eq!(
        remote_pointer(&fixture, host),
        Some(pointer_line("0.3.0", host))
    );
    let head = fixture.remote_head("main");
    assert!(is_revoked(&head, "fuz", "0.2.0"), "the revocation stays");
    assert!(!is_revoked(&head, "fuz", "0.3.0"));

    // The older release that still stands, published again: no new head, the
    // pointer moves to it.
    let recorded = record_release(
        &fixture.repo(),
        &self_entry("0.1.0", host, &content("0.1.0", host)),
        &key,
        AFTER,
    )
    .unwrap();
    assert_eq!((recorded.seq, recorded.advanced), (4, false));
    assert_eq!(
        fixture.remote_subjects().last().map(String::as_str),
        Some(format!("log: latest fuz 0.1.0 {host} seq 4").as_str())
    );
    assert_eq!(
        remote_pointer(&fixture, host),
        Some(pointer_line("0.1.0", host))
    );
}

//
// Pure: the next head
//

/// `next_revoked_head` over real signed heads: one `seq` on, the row revoked,
/// a new signing key recorded, and a successor of the head it was built on.
/// Nothing is signed for a row that is revoked already, and nothing an
/// untrusted key signs is returned.
#[test]
fn next_revoked_head_advances_once_and_only_under_a_trusted_key() {
    if !git_available() {
        return;
    }
    let fixture = logged(&["0.1.0", "0.2.0"]);
    let previous = fixture.remote_head("main");

    let next =
        match next_revoked_head(&previous, "fuz", "0.1.0", &second_trusted_key(), AFTER).unwrap() {
            NextHead::Advanced(head) => *head,
            NextHead::Unchanged => panic!("an ok row must be revoked by a new head"),
        };
    assert_eq!(next.seq(), previous.seq() + 1);
    assert_eq!(check_successor(&previous, &next), Ok(Succession::Advanced));
    assert!(is_revoked(&next, "fuz", "0.1.0"));
    assert!(!is_revoked(&next, "fuz", "0.2.0"));
    assert_eq!(next.keys().len(), previous.keys().len() + 1);
    assert_eq!(next.signature().signed_at, AFTER);

    // Built on the head that already revokes it: nothing to sign.
    assert!(matches!(
        next_revoked_head(&next, "fuz", "0.1.0", &trusted_key(), AFTER).unwrap(),
        NextHead::Unchanged
    ));

    let error = next_revoked_head(&previous, "fuz", "0.7.0", &trusted_key(), AFTER).unwrap_err();
    assert!(
        matches!(error, RevokeError::UnknownRelease { .. }),
        "{error:?}"
    );
    let error = next_revoked_head(&previous, "fuz", "0.1.0", &untrusted_key(), AFTER).unwrap_err();
    assert!(
        matches!(error, RevokeError::Log(LogWriteError::SignedHead(_))),
        "{error:?}"
    );
    assert!(error.is_security_violation());
}
