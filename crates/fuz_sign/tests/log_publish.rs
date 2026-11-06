//! Publish writes the release log: the real publish flows and
//! `record_release` against a real git checkout whose upstream is a local bare
//! repository, so every commit and push is genuine.
//!
//! Heads are signed and verified for real, with the signing key admitted
//! through `fuz_crypto`'s dev-dependency-only `test_trust_anchor` seam (as in
//! `release_log.rs`). No test touches `~/.fuz`: the publish functions used here
//! take the artifact directory explicitly.
//!
//! Every `git` process — the ones these tests run and, through
//! `LogRepo::git_env`, the ones the code under test runs — gets an environment
//! that ignores the developer's global and system configuration. Identity and
//! branch name are set per repository. The tests skip when `git` is absent.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use common::*;

use fuz_artifact::{ArtifactMeta, ArtifactOutputs};
use fuz_crypto::{ContentHash, VerifyError};
use fuz_release::{
    HeadViolation, LogWriteError, MAX_HEAD_SEQ, Manifest, ManifestError, ReleaseError,
    ReleaseLayout, ReleaseLogError, RowStatus, Succession, TargetField, VerifiedHead,
    check_successor, current_target, sidecar_content,
};
use fuz_sign::release_log::{HEAD_FILE, NextHead, install_script_entry, next_head, sign_successor};
use fuz_sign::{
    LogOutcome, PublishOptions, PublishResult, publish_artifact, publish_tool, serialize_key_file,
    sign_head,
};
use fuz_storage::{FileStorage, Storage, StorageBackendKind, StorageError};

fn outcome(
    name: &str,
    version: &str,
    target: &str,
    seq: u64,
    advanced: bool,
    pushed: bool,
) -> LogOutcome {
    LogOutcome {
        name: name.to_string(),
        version: version.to_string(),
        target: target.to_string(),
        seq,
        advanced,
        pushed,
    }
}

#[track_caller]
fn log_error(result: Result<PublishResult, ReleaseError>) -> LogWriteError {
    match result {
        Err(ReleaseError::LogWrite(e)) => e,
        other => panic!("expected a log write error, got {other:?}"),
    }
}

//
// The publish flows
//

/// One version, two targets: the first target's publish creates the row, the
/// second extends it, and each is its own verified head and its own commit.
///
/// A publish signs for the target it was built for, so the full
/// `publish_artifact` flow can only run for the host target. The second target
/// goes through `record_release` — the same function `publish_artifact` calls,
/// taking the target in its entry — so it runs the real upsert, signature,
/// write, commit, and push.
#[tokio::test]
async fn self_publish_logs_each_target_into_one_row() {
    if !git_available() {
        return;
    }
    let fixture = Fixture::new();
    let storage = fixture.storage();
    let key = trusted_key();
    let host = current_target();
    let other = other_target();
    let content = fuz_content("0.5.0");

    let published = publish_self(&fixture, "0.5.0").await.unwrap();
    assert_eq!(
        published.logged,
        Some(outcome("fuz", "0.5.0", host, 1, true, true))
    );

    let other_content = b"fuz binary bytes for the other target";
    let second = record_release(
        &fixture.repo(),
        &self_entry("0.5.0", other, other_content),
        &key,
        LATER,
    )
    .unwrap();
    assert_eq!(second, outcome("fuz", "0.5.0", other, 2, true, true));

    // Two commits on the remote, one per target, each naming what it logged.
    assert_eq!(
        fixture.remote_subjects(),
        [
            format!("log: fuz 0.5.0 {host} seq 1"),
            format!("log: fuz 0.5.0 {other} seq 2"),
        ]
    );
    // Each commit holds the head and that target's pointer, nothing else.
    assert_eq!(
        fixture.remote_commit_files("main~1"),
        [HEAD_FILE.to_string(), format!("latest/fuz-{host}.sha512")]
    );
    assert_eq!(
        fixture.remote_commit_files("main"),
        [HEAD_FILE.to_string(), format!("latest/fuz-{other}.sha512")]
    );

    // Both heads verify, and the second is a successor of the first.
    let first_head = fixture.remote_head("main~1");
    let second_head = fixture.remote_head("main");
    assert_eq!((first_head.seq(), second_head.seq()), (1, 2));
    assert_eq!(
        check_successor(&first_head, &second_head),
        Ok(Succession::Advanced)
    );

    // One row, both targets, created by the first publish.
    assert_eq!(second_head.rows().len(), 1);
    let row = second_head.row("fuz", "0.5.0").unwrap();
    assert_eq!(row.status, RowStatus::Ok);
    assert_eq!(
        row.published_at,
        first_head.signature().signed_at,
        "the row is dated by the publish that created it"
    );
    assert_eq!(row.targets.len(), 2);
    assert_eq!(first_head.row("fuz", "0.5.0").unwrap().targets.len(), 1);

    // The key that signed is recorded, once.
    assert_eq!(second_head.keys().len(), 1);
    assert_eq!(second_head.keys()[0].public_key, public_key(&key));
    assert_eq!(second_head.keys()[0].retired_at, None);

    // The host target's entry is the signed manifest's own pins.
    let manifest_bytes = storage.download(&published.manifest_path).await.unwrap();
    let manifest = Manifest::from_json(&manifest_bytes).unwrap();
    let logged = &row.targets[host];
    assert_eq!(
        row.published_at, manifest.signature.signed_at,
        "the row and the manifest carry the one timestamp of the publish"
    );
    assert_eq!(logged.content_hash, manifest.content_hash);
    assert_eq!(
        logged.binaries,
        manifest
            .binaries
            .clone()
            .into_iter()
            .collect::<BTreeMap<_, _>>()
    );

    // Its sha512 is the uploaded flat binary's, and `latest/` is byte for byte
    // the sidecar uploaded beside that binary: sha512sum format, naming the
    // versioned binary.
    let flat_key = ReleaseLayout::self_artifact().binary_key("fuz", "0.5.0", host);
    assert_eq!(flat_key, format!("fuz-0.5.0-{host}"));
    let flat = storage.download(&flat_key).await.unwrap();
    assert_eq!(flat, content);
    let digest = ContentHash::sha512(&flat);
    assert_eq!(logged.sha512.as_ref(), Some(&digest));
    let pointer =
        std::fs::read_to_string(fixture.checkout.join(format!("latest/fuz-{host}.sha512")))
            .unwrap();
    assert_eq!(pointer, format!("{}  fuz-0.5.0-{host}\n", digest.to_hex()));
    assert_eq!(digest.to_hex().len(), 128);
    assert_eq!(
        pointer.as_bytes(),
        storage
            .download(&format!("{flat_key}.sha512"))
            .await
            .unwrap()
    );

    // The other target's pointer names its own versioned binary and digest.
    assert_eq!(
        std::fs::read_to_string(fixture.checkout.join(format!("latest/fuz-{other}.sha512")))
            .unwrap(),
        sidecar_content(
            &format!("fuz-0.5.0-{other}"),
            &ContentHash::sha512(other_content).to_hex()
        )
    );

    // Plain, owner-writable, non-executable files; the rest is the umask's.
    for file in [HEAD_FILE.to_string(), format!("latest/fuz-{host}.sha512")] {
        let mode = std::fs::metadata(fixture.checkout.join(&file))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o711, 0o600, "{file}");
    }

    // The checkout holds the pushed state and nothing uncommitted.
    assert_eq!(fixture.git(&["status", "--porcelain"]), "");
    assert_eq!(
        fixture.git(&["rev-parse", "HEAD"]),
        fixture.remote_git(&["rev-parse", "main"])
    );
    assert_eq!(
        latest_version(&storage, &ReleaseLayout::self_artifact()).await,
        Some("0.5.0".to_string())
    );
}

/// A tool publishes no flat binary: its row has no `sha512` and the log gets
/// no `latest/` file.
#[tokio::test]
async fn tool_publish_logs_a_row_without_sha512_or_latest() {
    if !git_available() {
        return;
    }
    let fixture = Fixture::new();
    let storage = fixture.storage();
    let bin_path = fixture.tmp.path().join("fuzf");
    let content: &[u8] = &host_binary(b"fuzf binary bytes");
    std::fs::write(&bin_path, content).unwrap();

    let published = publish_tool(
        &storage,
        "fuzf",
        "0.1.0",
        &[("fuzf".to_string(), bin_path)],
        &trusted_key(),
        &fixture.options(),
    )
    .await
    .unwrap();
    let host = current_target();
    assert_eq!(
        published.logged,
        Some(outcome("fuzf", "0.1.0", host, 1, true, true))
    );

    assert_eq!(
        fixture.remote_subjects(),
        [format!("log: fuzf 0.1.0 {host} seq 1")]
    );
    assert_eq!(fixture.remote_tree(), [HEAD_FILE]);
    assert!(!fixture.checkout.join("latest").exists());

    let head = fixture.remote_head("main");
    let logged = head.target("fuzf", "0.1.0", host).unwrap();
    assert_eq!(logged.sha512, None);
    assert_eq!(logged.content_hash, published.content_hash);
    assert_eq!(
        logged.binaries,
        BTreeMap::from([("fuzf".to_string(), ContentHash::blake3(content))])
    );
    assert!(
        !String::from_utf8(fixture.checkout_head_bytes().unwrap())
            .unwrap()
            .contains("sha512")
    );
    assert_eq!(
        latest_version(&storage, &ReleaseLayout::tool("fuzf")).await,
        Some("0.1.0".to_string())
    );

    // A self release then joins the same log as the next head.
    let self_published = publish_self(&fixture, "0.5.0").await.unwrap();
    assert_eq!(
        self_published.logged,
        Some(outcome("fuz", "0.5.0", host, 2, true, true))
    );
    assert_eq!(fixture.remote_head("main").rows().len(), 2);
}

/// A binary name is a release token, in a manifest as in a head, and `+` is
/// not a token character. A tool whose binary is named with one is refused
/// before its first upload, with a log checkout or without one: storage holds
/// nothing of it, and the checkout is as it was.
#[tokio::test]
async fn a_binary_name_that_is_not_a_token_is_refused_before_upload() {
    if !git_available() {
        return;
    }
    let fixture = Fixture::new();
    let storage = fixture.storage();
    let bin_path = fixture.tmp.path().join("fuzf-bin");
    std::fs::write(&bin_path, host_binary(b"fuzf binary bytes")).unwrap();
    let before = fixture.state();

    let no_log = PublishOptions::default();
    for options in [&fixture.options(), &no_log] {
        for binary in ["fuzf+extra", "-fuzf", "fuzf tool"] {
            let error = publish_tool(
                &storage,
                "fuzf",
                "0.1.0",
                &[(binary.to_string(), bin_path.clone())],
                &trusted_key(),
                options,
            )
            .await
            .unwrap_err();
            assert!(
                matches!(
                    &error,
                    ReleaseError::Manifest(ManifestError::InvalidBinaryName(value)) if value == binary
                ),
                "{binary}: {error:?}"
            );
            assert_eq!(fixture.storage_files(), [], "{binary}");
            assert_eq!(fixture.state(), before, "{binary}");
        }
    }
}

/// With no log checkout, publish is exactly the storage upload: nothing is
/// logged and the latest pointer moves.
#[tokio::test]
async fn publish_without_a_log_repo_logs_nothing() {
    if !git_available() {
        return;
    }
    let fixture = Fixture::new();
    let published = publish_self_with(
        &fixture,
        "0.5.0",
        &fuz_content("0.5.0"),
        &trusted_key(),
        &PublishOptions::default(),
    )
    .await
    .unwrap();
    assert_eq!(published.logged, None);
    assert_eq!(fixture.remote_subjects(), Vec::<String>::new());
    assert_eq!(fixture.checkout_head_bytes(), None);
    assert_eq!(
        latest_version(&fixture.storage(), &ReleaseLayout::self_artifact()).await,
        Some("0.5.0".to_string())
    );
}

//
// Ordering: logged before advertised
//

/// The log commit is on the remote before anything advertises the release.
/// The remote's `pre-receive` hook refuses the push if the latest pointer or the
/// `latest` copy of the flat binary already exists in storage — so the publish
/// can only succeed if the log is pushed first.
#[tokio::test]
async fn the_log_is_pushed_before_latest_moves() {
    if !git_available() {
        return;
    }
    let fixture = Fixture::new();
    let storage = fixture.storage();
    let host = current_target();
    let latest_json = fixture
        .storage_dir
        .join(ReleaseLayout::self_artifact().latest_key(current_target()));
    let latest_binary = fixture.storage_dir.join(format!("fuz-latest-{host}"));
    let latest_sidecar = fixture
        .storage_dir
        .join(format!("fuz-latest-{host}.sha512"));
    let versioned_binary = fixture.storage_dir.join(format!("fuz-0.5.0-{host}"));
    fixture.install_pre_receive(&format!(
        "#!/bin/sh\n\
         for advertised in '{}' '{}' '{}'; do\n\
           if [ -e \"$advertised\" ]; then echo 'advertised before logged' >&2; exit 1; fi\n\
         done\n\
         if [ ! -e '{}' ]; then echo 'logged before uploaded' >&2; exit 1; fi\n",
        latest_json.display(),
        latest_binary.display(),
        latest_sidecar.display(),
        versioned_binary.display(),
    ));

    publish_self(&fixture, "0.5.0").await.unwrap();

    assert_eq!(
        fixture.remote_subjects(),
        [format!("log: fuz 0.5.0 {host} seq 1")]
    );
    assert!(latest_json.exists());
    assert!(latest_binary.exists());
    assert!(latest_sidecar.exists());
    assert_eq!(
        latest_version(&storage, &ReleaseLayout::self_artifact()).await,
        Some("0.5.0".to_string())
    );

    // The tool flow holds the same order.
    let tool_latest = fixture
        .storage_dir
        .join(ReleaseLayout::tool("fuzf").latest_key(current_target()));
    fixture.install_pre_receive(&format!(
        "#!/bin/sh\nif [ -e '{}' ]; then echo 'advertised before logged' >&2; exit 1; fi\n",
        tool_latest.display(),
    ));
    let bin_path = fixture.tmp.path().join("fuzf");
    std::fs::write(&bin_path, host_binary(b"fuzf binary bytes")).unwrap();
    publish_tool(
        &storage,
        "fuzf",
        "0.1.0",
        &[("fuzf".to_string(), bin_path)],
        &trusted_key(),
        &fixture.options(),
    )
    .await
    .unwrap();
    assert!(tool_latest.exists());
}

/// A refused push fails the publish with the latest pointer — and the `latest` copy
/// of the flat binary — where they were, while the new version's own bytes are
/// in storage. Running the same publish again pushes the commit that was
/// waiting: one commit for the release, one `seq`.
#[tokio::test]
async fn a_failed_push_leaves_latest_alone_and_the_retry_completes() {
    if !git_available() {
        return;
    }
    let fixture = Fixture::new();
    let storage = fixture.storage();
    let layout = ReleaseLayout::self_artifact();
    let host = current_target();

    publish_self(&fixture, "0.1.0").await.unwrap();
    assert_eq!(
        latest_version(&storage, &layout).await,
        Some("0.1.0".to_string())
    );

    let latest_sidecar_before = storage
        .download(&format!("{}.sha512", layout.latest_binary_key("fuz", host)))
        .await
        .unwrap();
    fixture.reject_pushes();
    let error = log_error(publish_self(&fixture, "0.2.0").await);
    match &error {
        LogWriteError::Git { command, output } => {
            assert_eq!(command, "push");
            assert!(output.contains("push refused by the test hook"), "{output}");
        }
        other => panic!("expected a failed push, got {other:?}"),
    }
    assert!(!error.is_security_violation());
    assert!(error.hint().is_some());

    // Nothing advertises 0.2.0 ...
    assert_eq!(
        latest_version(&storage, &layout).await,
        Some("0.1.0".to_string())
    );
    assert_eq!(
        storage
            .download(&layout.latest_binary_key("fuz", host))
            .await
            .unwrap(),
        fuz_content("0.1.0")
    );
    assert_eq!(
        storage
            .download(&format!("{}.sha512", layout.latest_binary_key("fuz", host)))
            .await
            .unwrap(),
        latest_sidecar_before,
        "the latest sidecar moves only with the latest binary"
    );
    // ... while its bytes are there to be fetched by version.
    for key in [
        layout.manifest_key("fuz", "0.2.0", host),
        layout.tarball_key(&format!("fuz-0.2.0-{host}.tar.gz")),
        layout.binary_key("fuz", "0.2.0", host),
    ] {
        assert!(storage.exists(&key).await.unwrap(), "{key}");
    }
    // The commit exists locally and not on the remote.
    assert_eq!(
        fixture.remote_subjects(),
        [format!("log: fuz 0.1.0 {host} seq 1")]
    );
    assert_eq!(
        fixture.git(&["log", "-1", "--format=%s"]),
        format!("log: fuz 0.2.0 {host} seq 2")
    );
    assert_eq!(fixture.git(&["status", "--porcelain"]), "");
    let head_after_failure = fixture.checkout_head_bytes();

    // Retry: the entry is already recorded, so nothing is signed — the waiting
    // commit is pushed and the release is advertised.
    fixture.accept_pushes();
    let retried = publish_self(&fixture, "0.2.0").await.unwrap();
    assert_eq!(
        retried.logged,
        Some(outcome("fuz", "0.2.0", host, 2, false, true))
    );
    assert_eq!(fixture.checkout_head_bytes(), head_after_failure);
    assert_eq!(
        fixture.remote_subjects(),
        [
            format!("log: fuz 0.1.0 {host} seq 1"),
            format!("log: fuz 0.2.0 {host} seq 2"),
        ]
    );
    assert_eq!(fixture.remote_head("main").seq(), 2);
    assert_eq!(
        latest_version(&storage, &layout).await,
        Some("0.2.0".to_string())
    );

    // And once more, with the remote already holding the commit: nothing to
    // sign, nothing to push, nothing new on the remote.
    let again = publish_self(&fixture, "0.2.0").await.unwrap();
    assert_eq!(
        again.logged,
        Some(outcome("fuz", "0.2.0", host, 2, false, false))
    );
    assert_eq!(fixture.remote_subjects().len(), 2);
    assert_eq!(fixture.checkout_head_bytes(), head_after_failure);
}

/// A log that cannot take the release stops the publish before its first
/// upload: storage holds nothing of the new version, and nothing is written to
/// the checkout.
#[tokio::test]
async fn a_log_that_cannot_take_the_release_uploads_nothing() {
    if !git_available() {
        return;
    }
    let cases: [(&str, Change); 6] = [
        ("dirty checkout", |f| {
            std::fs::write(f.checkout.join(HEAD_FILE), "left behind").unwrap();
        }),
        ("unverifiable existing head", |f| {
            std::fs::write(f.checkout.join(HEAD_FILE), "{}\n").unwrap();
            f.commit_all_and_push("seed head");
        }),
        ("no upstream", |f| {
            f.git(&["config", "--unset", "branch.main.merge"]);
        }),
        ("detached", |f| {
            std::fs::write(f.checkout.join("README"), "a log").unwrap();
            f.commit_all_and_push("readme");
            f.git(&["checkout", "--quiet", "--detach"]);
        }),
        ("ignored head", |f| {
            std::fs::write(f.checkout.join(".git/info/exclude"), "head.json\n").unwrap();
        }),
        ("symlinked latest", |f| {
            std::os::unix::fs::symlink(f.tmp.path(), f.checkout.join("latest")).unwrap();
            f.commit_all_and_push("seed link");
        }),
    ];
    for (case, break_log) in cases {
        let fixture = Fixture::new();
        break_log(&fixture);
        let before = fixture.state();

        let error = log_error(publish_self(&fixture, "0.1.0").await);
        assert!(error.hint().is_some(), "{case}: {error:?}");
        assert_eq!(fixture.storage_files(), [], "{case}: {error:?}");
        assert_eq!(fixture.state(), before, "{case}");

        // The tool flow stops at the same point. (A tool writes no `latest/`
        // pointer, so a link there is not its concern.)
        if case == "symlinked latest" {
            continue;
        }
        let bin_path = fixture.tmp.path().join("fuzf");
        std::fs::write(&bin_path, host_binary(b"fuzf binary bytes")).unwrap();
        let tool_error = log_error(
            publish_tool(
                &fixture.storage(),
                "fuzf",
                "0.1.0",
                &[("fuzf".to_string(), bin_path)],
                &trusted_key(),
                &fixture.options(),
            )
            .await,
        );
        assert_eq!(fixture.storage_files(), [], "{case}: {tool_error:?}");
        assert_eq!(fixture.state(), before, "{case}");
    }

    // A checkout path that does not exist.
    let fixture = Fixture::new();
    let options = PublishOptions {
        log_repo: Some(fixture.repo_at(&fixture.tmp.path().join("no-such-checkout"))),
        ..PublishOptions::default()
    };
    let error = log_error(
        publish_self_with(
            &fixture,
            "0.1.0",
            &host_binary(b"one"),
            &trusted_key(),
            &options,
        )
        .await,
    );
    assert!(
        matches!(error, LogWriteError::CheckoutMissing(_)),
        "{error:?}"
    );
    assert_eq!(fixture.storage_files(), []);

    // A signing key this binary does not trust: its head would not verify.
    let error = log_error(
        publish_self_with(
            &fixture,
            "0.1.0",
            &host_binary(b"one"),
            &untrusted_key(),
            &fixture.options(),
        )
        .await,
    );
    assert!(
        matches!(
            &error,
            LogWriteError::UntrustedKey { public_key: actual } if *actual == public_key(&untrusted_key())
        ),
        "{error:?}"
    );
    assert_eq!(fixture.storage_files(), []);
    assert_eq!(fixture.checkout_head_bytes(), None);
}

//
// Idempotence and immutability
//

/// Publishing the same build again changes no head: no new `seq`, no
/// signature, no commit.
#[tokio::test]
async fn an_identical_republish_is_a_no_op_for_the_head() {
    if !git_available() {
        return;
    }
    let fixture = Fixture::new();
    let host = current_target();
    publish_self(&fixture, "0.1.0").await.unwrap();
    let before = fixture.state();

    let again = publish_self(&fixture, "0.1.0").await.unwrap();
    assert_eq!(
        again.logged,
        Some(outcome("fuz", "0.1.0", host, 1, false, false))
    );
    assert_eq!(fixture.state(), before);
    assert_eq!(fixture.remote_subjects().len(), 1);
}

/// A different build of an already-logged target is refused, and the refusal
/// changes nothing in the checkout or on the remote.
#[tokio::test]
async fn a_republish_with_different_bytes_conflicts() {
    if !git_available() {
        return;
    }
    let fixture = Fixture::new();
    let storage = fixture.storage();
    let layout = ReleaseLayout::self_artifact();
    let host = current_target();
    publish_self(&fixture, "0.1.0").await.unwrap();
    let before = fixture.state();
    let stored_before = fixture.storage_files();
    let pointer_path = fixture.checkout.join(format!("latest/fuz-{host}.sha512"));
    let pointer_before = std::fs::read(&pointer_path).unwrap();

    let error = log_error(
        publish_self_with(
            &fixture,
            "0.1.0",
            &host_binary(b"a different build of 0.1.0"),
            &trusted_key(),
            &fixture.options(),
        )
        .await,
    );
    match &error {
        LogWriteError::TargetConflict {
            name,
            version,
            target,
            field,
        } => {
            assert_eq!((name.as_str(), version.as_str()), ("fuz", "0.1.0"));
            assert_eq!(target, host);
            assert_eq!(*field, TargetField::ContentHash);
        }
        other => panic!("expected a target conflict, got {other:?}"),
    }
    assert!(!error.is_security_violation());

    assert_eq!(fixture.state(), before);
    assert_eq!(std::fs::read(&pointer_path).unwrap(), pointer_before);

    // The logged version's bytes in storage are the logged ones still: the
    // refusal came before any upload.
    let binary_key = layout.binary_key("fuz", "0.1.0", host);
    for key in [
        binary_key.clone(),
        format!("{binary_key}.sha512"),
        layout.manifest_key("fuz", "0.1.0", host),
        layout.tarball_key(&format!("fuz-0.1.0-{host}.tar.gz")),
    ] {
        let stored = storage.download(&key).await.unwrap();
        let recorded = stored_before.iter().find(|(k, _)| *k == key).unwrap();
        assert_eq!(stored, recorded.1, "{key} was replaced");
    }
    assert_eq!(
        storage.download(&binary_key).await.unwrap(),
        fuz_content("0.1.0")
    );
    assert_eq!(fixture.storage_files(), stored_before);
}

/// `latest/` moves on every publish, as the latest pointer does: republishing an
/// older, already-logged version signs no head but points `latest/` back at
/// it, in a commit of its own.
#[tokio::test]
async fn republishing_an_older_version_moves_only_the_latest_pointer() {
    if !git_available() {
        return;
    }
    let fixture = Fixture::new();
    let host = current_target();
    let pointer_path = fixture.checkout.join(format!("latest/fuz-{host}.sha512"));
    publish_self(&fixture, "0.1.0").await.unwrap();
    let pointer_at_first = std::fs::read(&pointer_path).unwrap();
    publish_self(&fixture, "0.2.0").await.unwrap();
    assert_ne!(std::fs::read(&pointer_path).unwrap(), pointer_at_first);
    let head_before = fixture.checkout_head_bytes();

    let again = publish_self(&fixture, "0.1.0").await.unwrap();
    assert_eq!(
        again.logged,
        Some(outcome("fuz", "0.1.0", host, 2, false, true))
    );
    assert_eq!(fixture.checkout_head_bytes(), head_before);
    assert_eq!(std::fs::read(&pointer_path).unwrap(), pointer_at_first);
    assert_eq!(
        fixture.remote_subjects().last().unwrap(),
        &format!("log: latest fuz 0.1.0 {host} seq 2")
    );
    assert_eq!(
        fixture.remote_commit_files("main"),
        [format!("latest/fuz-{host}.sha512")]
    );
    assert_eq!(
        latest_version(&fixture.storage(), &ReleaseLayout::self_artifact()).await,
        Some("0.1.0".to_string())
    );
}

/// A revoked release takes no further targets.
#[test]
fn a_revoked_row_takes_no_new_target() {
    if !git_available() {
        return;
    }
    let fixture = Fixture::new();
    let key = trusted_key();
    let host = current_target();
    record_release(
        &fixture.repo(),
        &self_entry("0.1.0", host, b"one"),
        &key,
        NOW,
    )
    .unwrap();

    // Revoke the row the way a publisher would: the next head, signed.
    let previous = fixture.remote_head("main");
    let mut revoked = previous.to_unsigned();
    revoked.seq += 1;
    revoked.rows[0].status = RowStatus::Revoked;
    let revoked = sign_successor(Some(&previous), revoked, &key, NOW).unwrap();
    fixture.seed_head(&revoked.into_head());
    let before = fixture.state();

    let error = record_release(
        &fixture.repo(),
        &self_entry("0.1.0", other_target(), b"two"),
        &key,
        LATER,
    )
    .unwrap_err();
    assert!(
        matches!(&error, LogWriteError::RevokedRow { name, version }
            if name == "fuz" && version == "0.1.0"),
        "{error:?}"
    );
    assert!(!error.is_security_violation());
    assert_eq!(fixture.state(), before);
}

//
// The existing head
//

/// A `head.json` that cannot be verified is never built on or overwritten.
#[test]
fn an_unverifiable_existing_head_is_refused() {
    if !git_available() {
        return;
    }
    let key = trusted_key();
    let host = current_target();
    let valid = |seq: u64| {
        let NextHead::Advanced(head) =
            next_head(None, &self_entry("0.1.0", host, b"one"), &key, NOW).unwrap()
        else {
            panic!("a first head always advances");
        };
        let mut unsigned = head.to_unsigned();
        unsigned.seq = seq;
        unsigned
    };

    // Tampered: a valid signed head whose `seq` was edited afterwards.
    let tampered = {
        trust();
        let json = sign_head(valid(1), &key, NOW).unwrap().to_json().unwrap();
        assert!(json.contains("\"seq\": 1,"));
        json.replace("\"seq\": 1,", "\"seq\": 9,")
    };
    // Signed, correctly, by a key this binary does not trust.
    let untrusted = sign_head(valid(1), &untrusted_key(), NOW)
        .unwrap()
        .to_json()
        .unwrap();

    let cases: [(&str, String, bool); 4] = [
        ("tampered", tampered, true),
        ("untrusted key", untrusted, true),
        ("not json", "this is not a head\n".to_string(), false),
        ("empty", String::new(), false),
    ];
    for (case, document, violation) in cases {
        let fixture = Fixture::new();
        std::fs::write(fixture.checkout.join(HEAD_FILE), &document).unwrap();
        fixture.commit_all_and_push("seed head");
        let before = fixture.state();

        let error = record_release(
            &fixture.repo(),
            &self_entry("0.2.0", host, b"two"),
            &key,
            LATER,
        )
        .unwrap_err();
        match &error {
            LogWriteError::ExistingHead(inner) => {
                if violation {
                    assert!(
                        matches!(inner, ReleaseLogError::Signature(_)),
                        "{case}: {inner:?}"
                    );
                } else {
                    assert!(
                        matches!(inner, ReleaseLogError::Parse(_)),
                        "{case}: {inner:?}"
                    );
                }
            }
            other => panic!("{case}: expected an unusable existing head, got {other:?}"),
        }
        assert_eq!(error.is_security_violation(), violation, "{case}");
        assert_eq!(
            ReleaseError::from(error).is_security_violation(),
            violation,
            "{case}"
        );
        assert_eq!(fixture.state(), before, "{case}");
        assert_eq!(
            fixture.checkout_head_bytes().unwrap(),
            document.as_bytes(),
            "{case}"
        );
        assert!(!fixture.checkout.join("latest").exists(), "{case}");
    }
}

/// The same refusal through the publish flow: the release is not advertised.
#[tokio::test]
async fn an_unverifiable_existing_head_fails_the_publish_unadvertised() {
    if !git_available() {
        return;
    }
    let fixture = Fixture::new();
    std::fs::write(fixture.checkout.join(HEAD_FILE), "{}\n").unwrap();
    fixture.commit_all_and_push("seed head");

    let error = log_error(publish_self(&fixture, "0.1.0").await);
    assert!(matches!(error, LogWriteError::ExistingHead(_)), "{error:?}");
    assert_eq!(
        latest_version(&fixture.storage(), &ReleaseLayout::self_artifact()).await,
        None
    );
    assert_eq!(fixture.storage_files(), []);
    assert_eq!(fixture.checkout_head_bytes().unwrap(), b"{}\n");
}

/// A head signed before domain separation (envelope format 1) is refused
/// before anything is uploaded, and the hint says the log must be recreated:
/// every head in its history is format 1, so a revert reaches none this build
/// verifies.
#[tokio::test]
async fn a_pre_tag_existing_head_fails_the_publish_with_the_recreate_hint() {
    if !git_available() {
        return;
    }
    trust();
    let NextHead::Advanced(head) = next_head(
        None,
        &self_entry("0.1.0", current_target(), b"one"),
        &trusted_key(),
        NOW,
    )
    .unwrap() else {
        panic!("a first head always advances");
    };
    let fixture = Fixture::new();
    fixture.seed_head(&pre_tag_head(head.to_unsigned()));
    let before = fixture.state();

    let error = log_error(publish_self(&fixture, "0.2.0").await);
    assert!(
        matches!(
            error,
            LogWriteError::ExistingHead(ReleaseLogError::Signature(
                VerifyError::UnsupportedFormat(1)
            ))
        ),
        "{error:?}"
    );
    let hint = error.hint().unwrap();
    assert!(hint.contains("release-log backfill"), "{hint}");
    assert!(!hint.contains("git revert"), "{hint}");
    assert_eq!(
        ReleaseError::from(error)
            .hint()
            .map(|hint| hint.to_string()),
        Some(hint.to_string())
    );
    assert_eq!(fixture.storage_files(), []);
    assert_eq!(fixture.state(), before);
}

/// A head signed by a key this binary does not trust is not written: the
/// publisher's own head must pass the check a reader applies.
#[test]
fn a_head_signed_by_an_untrusted_key_is_not_written() {
    if !git_available() {
        return;
    }
    let fixture = Fixture::new();
    let before = fixture.state();
    let error = record_release(
        &fixture.repo(),
        &self_entry("0.1.0", current_target(), b"one"),
        &untrusted_key(),
        NOW,
    )
    .unwrap_err();
    assert!(
        matches!(
            &error,
            LogWriteError::UntrustedKey { public_key: actual } if *actual == public_key(&untrusted_key())
        ),
        "{error:?}"
    );
    assert!(error.is_security_violation());
    assert_eq!(fixture.state(), before);
    assert_eq!(fixture.checkout_head_bytes(), None);
}

/// A symlink where the log keeps a plain file or directory is refused, and
/// nothing is written through it.
#[test]
fn symlinked_log_paths_are_refused() {
    if !git_available() {
        return;
    }
    let key = trusted_key();
    let host = current_target();
    let entry = self_entry("0.1.0", host, b"one");
    let pointer = format!("latest/fuz-{host}.sha512");

    // (what is linked, a directory?) — committed and pushed, so the checkout
    // is clean and the link is all that stands out.
    for (linked, is_dir) in [
        (HEAD_FILE, false),
        ("latest", true),
        (pointer.as_str(), false),
    ] {
        let fixture = Fixture::new();
        let outside = fixture.tmp.path().join("outside");
        if is_dir {
            std::fs::create_dir(&outside).unwrap();
        } else {
            std::fs::write(&outside, "outside the checkout").unwrap();
        }
        let link = fixture.checkout.join(linked);
        std::fs::create_dir_all(link.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&outside, &link).unwrap();
        fixture.commit_all_and_push("seed link");
        let before = fixture.state();

        let error = record_release(&fixture.repo(), &entry, &key, NOW).unwrap_err();
        match &error {
            LogWriteError::UnsafePath { path, expected } => {
                assert!(path.ends_with(linked), "{linked}: {path:?}");
                assert_eq!(*expected, if is_dir { "directory" } else { "file" });
            }
            other => panic!("{linked}: expected a refused path, got {other:?}"),
        }
        assert!(error.is_security_violation(), "{linked}");

        assert_eq!(fixture.state(), before, "{linked}");
        assert!(
            std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink(),
            "{linked}: the link itself is left in place"
        );
        if is_dir {
            assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 0, "{linked}");
        } else {
            assert_eq!(
                std::fs::read_to_string(&outside).unwrap(),
                "outside the checkout",
                "{linked}"
            );
        }
        // No head was written beside a refused pointer either.
        if linked != HEAD_FILE {
            assert!(!fixture.checkout.join(HEAD_FILE).exists(), "{linked}");
        }
    }
}

//
// The checkout
//

/// Each way a checkout can be unfit for a log write is its own error, and none
/// writes anything.
#[test]
fn an_unfit_checkout_is_refused_by_cause() {
    if !git_available() {
        return;
    }
    let key = trusted_key();
    let entry = self_entry("0.1.0", current_target(), b"one");

    // Missing path.
    let fixture = Fixture::new();
    let missing = fixture.tmp.path().join("no-such-checkout");
    let error = record_release(&fixture.repo_at(&missing), &entry, &key, NOW).unwrap_err();
    assert!(
        matches!(&error, LogWriteError::CheckoutMissing(p) if p == &missing),
        "{error:?}"
    );
    assert!(!missing.exists());

    // A file, not a directory.
    let file = fixture.tmp.path().join("a-file");
    std::fs::write(&file, "x").unwrap();
    let error = record_release(&fixture.repo_at(&file), &entry, &key, NOW).unwrap_err();
    assert!(
        matches!(error, LogWriteError::CheckoutMissing(_)),
        "{error:?}"
    );

    // A directory that is no repository of its own. (The temp dir may itself
    // sit inside some other work tree; that repository must not be written to.)
    let plain = fixture.tmp.path().join("plain");
    std::fs::create_dir(&plain).unwrap();
    let error = record_release(&fixture.repo_at(&plain), &entry, &key, NOW).unwrap_err();
    assert!(
        matches!(&error, LogWriteError::NotARepo(p) if p == &plain),
        "{error:?}"
    );
    assert_eq!(std::fs::read_dir(&plain).unwrap().count(), 0);

    // A directory inside the checkout: a work tree, but not its root.
    let nested = fixture.checkout.join("nested");
    std::fs::create_dir(&nested).unwrap();
    let error = record_release(&fixture.repo_at(&nested), &entry, &key, NOW).unwrap_err();
    assert!(matches!(error, LogWriteError::NotARepo(_)), "{error:?}");
    assert_eq!(std::fs::read_dir(&nested).unwrap().count(), 0);

    // The bare remote: a repository with no work tree.
    let error = record_release(&fixture.repo_at(&fixture.remote), &entry, &key, NOW).unwrap_err();
    assert!(matches!(error, LogWriteError::NotARepo(_)), "{error:?}");

    // A repository whose work tree is configured to be somewhere else: the
    // path is a git directory's home, but not the tree git would write.
    let fixture = Fixture::new();
    let elsewhere = fixture.tmp.path().join("elsewhere");
    std::fs::create_dir(&elsewhere).unwrap();
    fixture.git(&["config", "core.worktree", elsewhere.to_str().unwrap()]);
    let error = record_release(&fixture.repo(), &entry, &key, NOW).unwrap_err();
    assert!(matches!(error, LogWriteError::NotARepo(_)), "{error:?}");
    assert_eq!(std::fs::read_dir(&elsewhere).unwrap().count(), 0);
    assert_eq!(fixture.checkout_head_bytes(), None);

    // No upstream configured.
    let fixture = Fixture::new();
    fixture.git(&["config", "--unset", "branch.main.merge"]);
    let before = fixture.state();
    let error = record_release(&fixture.repo(), &entry, &key, NOW).unwrap_err();
    assert!(
        matches!(&error, LogWriteError::NoUpstream { branch } if branch == "main"),
        "{error:?}"
    );
    assert_eq!(fixture.state(), before);

    // A local branch as upstream: nothing would leave the machine.
    let fixture = Fixture::new();
    fixture.git(&["config", "branch.main.remote", "."]);
    let before = fixture.state();
    let error = record_release(&fixture.repo(), &entry, &key, NOW).unwrap_err();
    assert!(
        matches!(error, LogWriteError::NoUpstream { .. }),
        "{error:?}"
    );
    assert_eq!(fixture.state(), before);

    // No remote at all.
    let fixture = Fixture::new();
    fixture.git(&["remote", "remove", "origin"]);
    let error = record_release(&fixture.repo(), &entry, &key, NOW).unwrap_err();
    assert!(
        matches!(error, LogWriteError::NoUpstream { .. }),
        "{error:?}"
    );
    assert_eq!(fixture.checkout_head_bytes(), None);

    // A detached HEAD.
    let fixture = Fixture::new();
    record_release(&fixture.repo(), &entry, &key, NOW).unwrap();
    fixture.git(&["checkout", "--quiet", "--detach"]);
    let before = fixture.state();
    let error = record_release(
        &fixture.repo(),
        &self_entry("0.2.0", current_target(), b"two"),
        &key,
        LATER,
    )
    .unwrap_err();
    assert!(matches!(error, LogWriteError::DetachedHead), "{error:?}");
    assert_eq!(fixture.state(), before);

    for error in [
        LogWriteError::CheckoutMissing(PathBuf::new()),
        LogWriteError::NotARepo(PathBuf::new()),
        LogWriteError::NoUpstream {
            branch: String::new(),
        },
        LogWriteError::DetachedHead,
    ] {
        assert!(!error.is_security_violation(), "{error:?}");
        assert!(error.hint().is_some(), "{error:?}");
    }
}

/// Uncommitted changes under the log's paths — modified, staged, or untracked
/// — refuse the write.
#[test]
fn a_dirty_checkout_is_refused_however_it_is_dirty() {
    if !git_available() {
        return;
    }
    let key = trusted_key();
    let host = current_target();
    let next = self_entry("0.2.0", host, b"two");

    let cases: [(&str, &str, Change); 4] = [
        ("modified head", HEAD_FILE, |f| {
            std::fs::write(f.checkout.join(HEAD_FILE), "edited by hand").unwrap();
        }),
        ("staged head", HEAD_FILE, |f| {
            std::fs::write(f.checkout.join(HEAD_FILE), "edited by hand").unwrap();
            f.git(&["add", HEAD_FILE]);
        }),
        ("untracked pointer", "latest/stray.sha512", |f| {
            std::fs::write(f.checkout.join("latest/stray.sha512"), "stray").unwrap();
        }),
        ("deleted pointer", "latest/", |f| {
            std::fs::remove_dir_all(f.checkout.join("latest")).unwrap();
        }),
    ];
    for (case, path, dirty) in cases {
        let fixture = Fixture::new();
        record_release(
            &fixture.repo(),
            &self_entry("0.1.0", host, b"one"),
            &key,
            NOW,
        )
        .unwrap();
        dirty(&fixture);
        let before = fixture.state();

        let error = record_release(&fixture.repo(), &next, &key, LATER).unwrap_err();
        assert!(
            matches!(&error, LogWriteError::Dirty { paths } if paths.contains(path)),
            "{case}: {error:?}"
        );
        assert_eq!(fixture.state(), before, "{case}");
    }

    // A change elsewhere in the checkout is not the log's business — and stays
    // out of the log's commit.
    let fixture = Fixture::new();
    std::fs::write(fixture.checkout.join("README"), "about this log").unwrap();
    record_release(&fixture.repo(), &next, &key, NOW).unwrap();
    assert_eq!(
        fixture.remote_tree(),
        [HEAD_FILE.to_string(), format!("latest/fuz-{host}.sha512")]
    );
}

/// A checkout behind its upstream is fast-forwarded and the write lands on
/// top; one that has diverged is refused, never merged or forced.
#[test]
fn a_behind_checkout_fast_forwards_and_a_diverged_one_is_refused() {
    if !git_available() {
        return;
    }
    let fixture = Fixture::new();
    let key = trusted_key();
    let host = current_target();
    record_release(
        &fixture.repo(),
        &self_entry("0.1.0", host, b"one"),
        &key,
        NOW,
    )
    .unwrap();

    // A second checkout — no commits, nothing fetched — records the other
    // target: it catches up to seq 1 first, then pushes seq 2.
    let second = fixture.tmp.path().join("second");
    fixture.init_checkout(&second);
    let recorded = record_release(
        &fixture.repo_at(&second),
        &self_entry("0.1.0", other_target(), b"one, other target"),
        &key,
        LATER,
    )
    .unwrap();
    assert_eq!(recorded.seq, 2);

    // The first checkout is now behind. Its next write fast-forwards to seq 2
    // and lands as seq 3.
    let recorded = record_release(
        &fixture.repo(),
        &self_entry("0.2.0", host, b"two"),
        &key,
        LATER,
    )
    .unwrap();
    assert_eq!(recorded, outcome("fuz", "0.2.0", host, 3, true, true));
    let head = fixture.remote_head("main");
    assert_eq!(head.rows().len(), 2);
    assert_eq!(head.row("fuz", "0.1.0").unwrap().targets.len(), 2);
    assert_eq!(fixture.remote_subjects().len(), 3);
    assert_eq!(
        check_successor(&fixture.remote_head("main~1"), &head),
        Ok(Succession::Advanced)
    );

    // Diverge: the second checkout (at seq 2) commits on its own while the
    // remote is at seq 3.
    std::fs::write(second.join("local-note"), "a local commit").unwrap();
    fixture.git_in(&second, &["add", "local-note"]);
    fixture.git_in(&second, &["commit", "--quiet", "-m", "local"]);
    let second_head = fixture.git_in(&second, &["rev-parse", "HEAD"]);
    let second_head_json = std::fs::read(second.join(HEAD_FILE)).unwrap();
    let remote_before = fixture.remote_git(&["rev-parse", "main"]);

    let error = record_release(
        &fixture.repo_at(&second),
        &self_entry("0.3.0", host, b"three"),
        &key,
        LATER,
    )
    .unwrap_err();
    assert!(
        matches!(&error, LogWriteError::Diverged { branch } if branch == "main"),
        "{error:?}"
    );
    assert!(!error.is_security_violation());
    assert_eq!(fixture.git_in(&second, &["rev-parse", "HEAD"]), second_head);
    assert_eq!(
        std::fs::read(second.join(HEAD_FILE)).unwrap(),
        second_head_json
    );
    assert_eq!(fixture.git_in(&second, &["status", "--porcelain"]), "");
    assert_eq!(fixture.remote_git(&["rev-parse", "main"]), remote_before);
}

/// The push is plain — never forced. Here the checkout fetches from one
/// repository and pushes to another whose `main` holds history the checkout
/// lacks, so the fetch sees nothing wrong and only the push can tell. The push
/// must be refused and the push target left exactly as it was.
#[test]
fn the_push_never_forces() {
    if !git_available() {
        return;
    }
    let fixture = Fixture::new();
    let key = trusted_key();
    let host = current_target();

    // A second bare repository with its own, unrelated `main`.
    let push_target = fixture.tmp.path().join("push-target.git");
    fixture.git_in(
        fixture.tmp.path(),
        &["init", "--quiet", "--bare", "-b", "main", "push-target.git"],
    );
    let seeder = fixture.tmp.path().join("seeder");
    fixture.init_checkout(&seeder);
    fixture.git_in(
        &seeder,
        &["remote", "set-url", "origin", push_target.to_str().unwrap()],
    );
    std::fs::write(seeder.join("existing"), "history the checkout lacks").unwrap();
    fixture.git_in(&seeder, &["add", "existing"]);
    fixture.git_in(&seeder, &["commit", "--quiet", "-m", "existing history"]);
    fixture.git_in(&seeder, &["push", "--quiet"]);
    let target_before = fixture.git_in(&push_target, &["rev-parse", "main"]);

    fixture.git(&[
        "remote",
        "set-url",
        "--push",
        "origin",
        push_target.to_str().unwrap(),
    ]);
    let error = record_release(
        &fixture.repo(),
        &self_entry("0.1.0", host, b"one"),
        &key,
        NOW,
    )
    .unwrap_err();
    assert!(
        matches!(&error, LogWriteError::Git { command, .. } if command == "push"),
        "{error:?}"
    );
    assert_eq!(
        fixture.git_in(&push_target, &["rev-parse", "main"]),
        target_before,
        "a refused push must leave the push target's history intact"
    );
    assert_eq!(
        fixture.git_in(&push_target, &["ls-tree", "-r", "--name-only", "main"]),
        "existing"
    );
}

//
// What reaches the log
//

/// Only `head.json` and `latest/*.sha512` are staged and committed, whatever
/// else is lying in or staged in the checkout, and nothing about the signing
/// key — its path or its secret — reaches the checkout or a commit message.
#[tokio::test]
async fn only_log_files_are_committed_and_nothing_about_the_key() {
    if !git_available() {
        return;
    }
    let fixture = Fixture::new();
    let host = current_target();

    // The key as a publisher holds it: a file, loaded, then used.
    let key = trusted_key();
    let key_dir = fixture.tmp.path().join("publisher-secrets");
    std::fs::create_dir(&key_dir).unwrap();
    let key_path = key_dir.join("signing.key");
    let key_file = serialize_key_file(&key, NOW);
    std::fs::write(&key_path, &key_file).unwrap();
    std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let (loaded, _) = fuz_sign::parse_key_file(&key_file).unwrap();
    let seed = std::str::from_utf8(&key_file)
        .unwrap()
        .lines()
        .find_map(|line| line.strip_prefix("seed: "))
        .unwrap()
        .to_string();
    assert_eq!(seed.len(), 44, "a base64 32-byte seed");

    // Other things in the checkout: one untracked, one staged.
    std::fs::write(fixture.checkout.join("scratch.txt"), "untracked").unwrap();
    std::fs::write(fixture.checkout.join("staged.txt"), "staged by hand").unwrap();
    fixture.git(&["add", "staged.txt"]);

    publish_self_with(
        &fixture,
        "0.1.0",
        &fuz_content("0.1.0"),
        &loaded,
        &fixture.options(),
    )
    .await
    .unwrap();
    record_release(
        &fixture.repo(),
        &self_entry("0.1.0", other_target(), b"other target"),
        &loaded,
        LATER,
    )
    .unwrap();

    let mut expected = vec![
        HEAD_FILE.to_string(),
        format!("latest/fuz-{host}.sha512"),
        format!("latest/fuz-{}.sha512", other_target()),
    ];
    expected.sort();
    assert_eq!(fixture.remote_tree(), expected);
    // The bystanders are exactly as they were left.
    assert_eq!(
        fixture.git(&["status", "--porcelain", "--untracked-files=all"]),
        "A  staged.txt\n?? scratch.txt"
    );

    // Nothing in any commit or in the work tree names the key file or holds
    // the secret.
    let secrets = [
        key_path.to_str().unwrap(),
        key_dir.to_str().unwrap(),
        seed.as_str(),
    ];
    let history = fixture.remote_git(&["log", "-p", "--format=%B%an%ae%cn%ce", "main"]);
    let mut texts = vec![("git history".to_string(), history)];
    for file in &expected {
        texts.push((
            file.clone(),
            std::fs::read_to_string(fixture.checkout.join(file)).unwrap(),
        ));
    }
    for (what, text) in &texts {
        for secret in secrets {
            assert!(!text.contains(secret), "{what} contains {secret}");
        }
    }
}

/// An entry whose name, version, or target is not a head token never reaches
/// a path or a command line.
#[test]
fn a_path_unsafe_entry_is_refused_before_anything_runs() {
    if !git_available() {
        return;
    }
    let fixture = Fixture::new();
    let key = trusted_key();
    let before = fixture.state();
    for (field, name, version, target) in [
        ("name", "../../escape", "0.1.0", X86),
        ("name", "-fuz", "0.1.0", X86),
        ("version", "fuz", "0.1.0/..", X86),
        ("target", "fuz", "0.1.0", "../x"),
        ("target", "fuz", "0.1.0", ".hidden"),
    ] {
        let mut entry = self_entry("0.1.0", X86, b"one");
        entry.name = name.to_string();
        entry.version = version.to_string();
        entry.target = target.to_string();
        let error = record_release(&fixture.repo(), &entry, &key, NOW).unwrap_err();
        assert!(
            matches!(&error, LogWriteError::InvalidEntry { field: got, .. } if *got == field),
            "{error:?}"
        );
        assert_eq!(fixture.state(), before);
    }
    assert_eq!(std::fs::read_dir(fixture.tmp.path()).unwrap().count(), 4);
}

/// The install-script entry is recorded like any release, and writes no
/// `latest/` file.
#[test]
fn the_install_script_entry_records_without_a_latest_pointer() {
    if !git_available() {
        return;
    }
    let fixture = Fixture::new();
    let key = trusted_key();
    let script = b"#!/bin/sh\nset -eu\n";

    let recorded = record_release(
        &fixture.repo(),
        &install_script_entry("1", script),
        &key,
        NOW,
    )
    .unwrap();
    assert_eq!(recorded, outcome("install.sh", "1", "any", 1, true, true));
    assert_eq!(fixture.remote_tree(), [HEAD_FILE]);
    let head = fixture.remote_head("main");
    let logged = head.target("install.sh", "1", "any").unwrap();
    assert_eq!(logged.sha512, Some(ContentHash::sha512(script)));
    assert_eq!(logged.binaries["install.sh"], ContentHash::blake3(script));

    // Idempotent, and immutable at a version.
    let again = record_release(
        &fixture.repo(),
        &install_script_entry("1", script),
        &key,
        LATER,
    )
    .unwrap();
    assert_eq!(again, outcome("install.sh", "1", "any", 1, false, false));
    let changed = record_release(
        &fixture.repo(),
        &install_script_entry("1", b"#!/bin/sh\necho changed\n"),
        &key,
        LATER,
    )
    .unwrap_err();
    assert!(
        matches!(changed, LogWriteError::TargetConflict { .. }),
        "{changed:?}"
    );
    assert_eq!(fixture.remote_subjects(), ["log: install.sh 1 any seq 1"]);
}

//
// What git does behind the write
//

/// A log path git ignores can never be committed, so it is refused up front —
/// whether the rule is in `.gitignore` or the checkout's own exclude file, and
/// whether or not an ignored copy is already lying there.
#[test]
fn ignored_log_paths_are_refused() {
    if !git_available() {
        return;
    }
    let key = trusted_key();
    let host = current_target();
    let entry = self_entry("0.1.0", host, b"one");
    let pointer = format!("latest/fuz-{host}.sha512");

    for rule_file in [".gitignore", ".git/info/exclude"] {
        for (ignored, lying_there) in [
            (HEAD_FILE, false),
            (HEAD_FILE, true),
            ("latest/", false),
            (pointer.as_str(), true),
            // Not a file this write creates, but an ignored one under a path
            // it owns.
            ("latest/stray.sha512", true),
        ] {
            let case = format!("{rule_file}: {ignored} (present: {lying_there})");
            let fixture = Fixture::new();
            std::fs::write(fixture.checkout.join(rule_file), format!("{ignored}\n")).unwrap();
            if lying_there {
                let path = fixture.checkout.join(ignored);
                std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                std::fs::write(&path, "an ignored copy").unwrap();
            }
            let before = fixture.state();

            let error = record_release(&fixture.repo(), &entry, &key, NOW).unwrap_err();
            assert!(
                matches!(&error, LogWriteError::Ignored { paths } if paths.contains(ignored.trim_end_matches('/'))),
                "{case}: {error:?}"
            );
            assert!(
                error.hint().unwrap().contains("ignore rule"),
                "{case}: the hint must name the fix"
            );
            assert_eq!(fixture.state(), before, "{case}");
            assert_eq!(fixture.remote_subjects(), Vec::<String>::new(), "{case}");
            if !lying_there {
                assert!(!fixture.checkout.join(HEAD_FILE).exists(), "{case}");
            }
        }
    }
}

/// `Ok` means the pushed commit holds the entry. A `pre-commit` hook that
/// swaps `head.json` for something else produces a commit and a push that both
/// succeed; the read-back of the pushed commit is what catches it.
#[test]
fn a_pushed_commit_without_the_entry_is_an_error() {
    if !git_available() {
        return;
    }
    let key = trusted_key();
    let host = current_target();

    // The hook replaces the head with a document that is not a head.
    let fixture = Fixture::new();
    Fixture::install_hook(
        &fixture.checkout.join(".git"),
        "pre-commit",
        "#!/bin/sh\nprintf 'rewritten by a hook\\n' > head.json\ngit add head.json\n",
    );
    let error = record_release(
        &fixture.repo(),
        &self_entry("0.1.0", host, b"one"),
        &key,
        NOW,
    )
    .unwrap_err();
    assert!(
        matches!(
            &error,
            LogWriteError::PublishedHead(ReleaseLogError::Parse(_))
        ),
        "{error:?}"
    );
    assert_eq!(
        fixture.remote_git(&["show", &format!("main:{HEAD_FILE}")]),
        "rewritten by a hook"
    );

    // The hook restores the previous, valid head: the pushed head verifies but
    // does not record the entry.
    let fixture = Fixture::new();
    record_release(
        &fixture.repo(),
        &self_entry("0.1.0", host, b"one"),
        &key,
        NOW,
    )
    .unwrap();
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
    let error = record_release(
        &fixture.repo(),
        &self_entry("0.2.0", host, b"two"),
        &key,
        LATER,
    )
    .unwrap_err();
    match &error {
        LogWriteError::NotPublished {
            name,
            version,
            target,
            detail,
        } => {
            assert_eq!((name.as_str(), version.as_str()), ("fuz", "0.2.0"));
            assert_eq!(target, host);
            assert!(detail.contains("head.json"), "{detail}");
        }
        other => panic!("expected an unpublished entry, got {other:?}"),
    }
    assert!(error.hint().is_some());
    assert_eq!(fixture.remote_head("main").row("fuz", "0.2.0"), None);

    // The hook leaves the head alone and swaps the `latest/` pointer.
    let fixture = Fixture::new();
    let pointer = format!("latest/fuz-{host}.sha512");
    Fixture::install_hook(
        &fixture.checkout.join(".git"),
        "pre-commit",
        &format!("#!/bin/sh\nprintf 'not the digest\\n' > '{pointer}'\ngit add '{pointer}'\n"),
    );
    let error = record_release(
        &fixture.repo(),
        &self_entry("0.1.0", host, b"one"),
        &key,
        NOW,
    )
    .unwrap_err();
    assert!(
        matches!(&error, LogWriteError::NotPublished { detail, .. } if detail.contains("latest/")),
        "{error:?}"
    );
    assert!(fixture.remote_head("main").row("fuz", "0.1.0").is_some());
}

/// The same read-back through the publish flow: the latest pointer does not move
/// for a release the pushed log does not hold.
#[tokio::test]
async fn an_unpublished_entry_fails_the_publish_unadvertised() {
    if !git_available() {
        return;
    }
    let fixture = Fixture::new();
    // The work tree keeps the real head, and the index is told to stop looking
    // at it — so a later write is never staged.
    publish_self(&fixture, "0.1.0").await.unwrap();
    fixture.git(&["update-index", "--skip-worktree", HEAD_FILE]);

    let error = log_error(publish_self(&fixture, "0.2.0").await);
    assert!(
        matches!(
            error,
            LogWriteError::NotPublished { .. } | LogWriteError::Git { .. }
        ),
        "{error:?}"
    );
    assert_eq!(
        latest_version(&fixture.storage(), &ReleaseLayout::self_artifact()).await,
        Some("0.1.0".to_string())
    );
    assert_eq!(fixture.remote_head("main").row("fuz", "0.2.0"), None);

    // And it stays an error on the retry, rather than turning into a success
    // because the work tree's head already records the entry.
    let error = log_error(publish_self(&fixture, "0.2.0").await);
    assert!(
        !matches!(error, LogWriteError::TargetConflict { .. }),
        "{error:?}"
    );
    assert_eq!(
        latest_version(&fixture.storage(), &ReleaseLayout::self_artifact()).await,
        Some("0.1.0".to_string())
    );
}

/// A remote with two push URLs, the second refusing: the first accepts, which
/// moves the remote-tracking ref. The retry must push again anyway — and fail
/// again while the mirror refuses — until both hold the commit.
#[test]
fn a_partial_push_fan_out_is_completed_by_the_retry() {
    if !git_available() {
        return;
    }
    let fixture = Fixture::new();
    let key = trusted_key();
    let host = current_target();
    let entry = self_entry("0.1.0", host, b"one");
    let mirror = fixture.init_bare("mirror.git");
    let reject = "#!/bin/sh\necho 'mirror refuses' >&2\nexit 1\n";
    Fixture::install_hook(&mirror, "pre-receive", reject);
    for url in [&fixture.remote, &mirror] {
        fixture.git(&[
            "remote",
            "set-url",
            "--add",
            "--push",
            "origin",
            url.to_str().unwrap(),
        ]);
    }
    let mirror_main = || {
        fixture
            .try_git_in(&mirror, &["rev-parse", "--verify", "--quiet", "main"])
            .status
            .success()
    };

    let error = record_release(&fixture.repo(), &entry, &key, NOW).unwrap_err();
    assert!(
        matches!(&error, LogWriteError::Git { command, output }
            if command == "push" && output.contains("mirror refuses")),
        "{error:?}"
    );
    // The first URL took the commit; the mirror did not.
    assert_eq!(fixture.remote_subjects().len(), 1);
    assert!(!mirror_main());

    // The retry has nothing to sign and the tracking ref is current — and it
    // still fails, because the mirror still refuses.
    let error = record_release(&fixture.repo(), &entry, &key, LATER).unwrap_err();
    assert!(
        matches!(&error, LogWriteError::Git { command, .. } if command == "push"),
        "{error:?}"
    );
    assert!(!mirror_main());

    std::fs::remove_file(mirror.join("hooks/pre-receive")).unwrap();
    let recorded = record_release(&fixture.repo(), &entry, &key, LATER).unwrap();
    assert_eq!(recorded, outcome("fuz", "0.1.0", host, 1, false, false));
    assert_eq!(
        fixture.git_in(&mirror, &["rev-parse", "main"]),
        fixture.remote_git(&["rev-parse", "main"])
    );
    assert_eq!(fixture.remote_subjects().len(), 1);
}

/// A push that succeeds but goes somewhere other than the branch's upstream
/// leaves the entry unpublished there, and is an error.
#[test]
fn a_push_that_misses_the_upstream_is_unconfirmed() {
    if !git_available() {
        return;
    }
    let fixture = Fixture::new();
    let elsewhere = fixture.init_bare("elsewhere.git");
    fixture.git(&["remote", "add", "elsewhere", elsewhere.to_str().unwrap()]);
    fixture.git(&["config", "branch.main.pushRemote", "elsewhere"]);

    let error = record_release(
        &fixture.repo(),
        &self_entry("0.1.0", current_target(), b"one"),
        &trusted_key(),
        NOW,
    )
    .unwrap_err();
    assert!(
        matches!(&error, LogWriteError::PushUnconfirmed { branch } if branch == "main"),
        "{error:?}"
    );
    assert_eq!(fixture.remote_subjects(), Vec::<String>::new());
}

/// A commit that fails — signing with no usable key, a hook that refuses — is
/// rolled back: the checkout is exactly as it was, and the same publish runs
/// again once the cause is fixed. With no commit yet, rolling back means
/// removing the files.
#[test]
fn a_failed_commit_is_rolled_back_and_can_be_retried() {
    if !git_available() {
        return;
    }
    let key = trusted_key();
    let host = current_target();

    let break_signing: Change = |f| {
        f.git(&["config", "commit.gpgsign", "true"]);
        f.git(&["config", "gpg.program", "/nonexistent/gpg-for-this-test"]);
    };
    let fix_signing: Change = |f| {
        f.git(&["config", "commit.gpgsign", "false"]);
    };
    let break_hook: Change = |f| {
        Fixture::install_hook(
            &f.checkout.join(".git"),
            "pre-commit",
            "#!/bin/sh\necho 'hook refuses' >&2\nexit 1\n",
        );
    };
    let fix_hook: Change = |f| {
        std::fs::remove_file(f.checkout.join(".git/hooks/pre-commit")).unwrap();
    };

    for (case, break_commit, fix_commit) in [
        ("signing", break_signing, fix_signing),
        ("hook", break_hook, fix_hook),
    ] {
        for genesis in [true, false] {
            let case = format!("{case}, genesis: {genesis}");
            let fixture = Fixture::new();
            if !genesis {
                record_release(
                    &fixture.repo(),
                    &self_entry("0.1.0", host, b"one"),
                    &key,
                    NOW,
                )
                .unwrap();
            }
            // Something of the publisher's own, staged: the rollback must
            // leave it staged.
            std::fs::write(fixture.checkout.join("notes"), "staged by hand").unwrap();
            fixture.git(&["add", "notes"]);
            break_commit(&fixture);
            let before = fixture.state();
            let pointer_path = fixture.checkout.join(format!("latest/fuz-{host}.sha512"));
            let pointer_before = std::fs::read(&pointer_path).ok();
            let entry = self_entry("0.2.0", host, b"two");

            let error = record_release(&fixture.repo(), &entry, &key, LATER).unwrap_err();
            match &error {
                LogWriteError::Git { command, output } => {
                    assert_eq!(command, "commit", "{case}");
                    assert!(!output.contains("not fully restored"), "{case}: {output}");
                }
                other => panic!("{case}: expected a failed commit, got {other:?}"),
            }
            assert_eq!(fixture.state(), before, "{case}");
            assert_eq!(std::fs::read(&pointer_path).ok(), pointer_before, "{case}");
            if genesis {
                assert!(!fixture.checkout.join(HEAD_FILE).exists(), "{case}");
                assert!(!fixture.checkout.join("latest").exists(), "{case}");
            }

            // Still failing: the same error again, not a dirty checkout.
            let error = record_release(&fixture.repo(), &entry, &key, LATER).unwrap_err();
            assert!(
                matches!(&error, LogWriteError::Git { command, .. } if command == "commit"),
                "{case}: {error:?}"
            );
            assert_eq!(fixture.state(), before, "{case}");

            fix_commit(&fixture);
            let recorded = record_release(&fixture.repo(), &entry, &key, LATER).unwrap();
            let seq = if genesis { 1 } else { 2 };
            assert_eq!(
                recorded,
                outcome("fuz", "0.2.0", host, seq, true, true),
                "{case}"
            );
            assert_eq!(
                fixture.git(&["status", "--porcelain"]),
                "A  notes",
                "{case}"
            );
        }
    }
}

/// A checkout that converts line endings holds a `latest/` pointer whose bytes
/// are not the committed ones. Republishing the version it already names has
/// nothing to commit, and succeeds.
#[test]
fn a_line_ending_converting_checkout_republishes_cleanly() {
    if !git_available() {
        return;
    }
    let fixture = Fixture::new();
    let key = trusted_key();
    let host = current_target();
    let entry = self_entry("0.1.0", host, b"one");
    record_release(&fixture.repo(), &entry, &key, NOW).unwrap();

    let converting = fixture.tmp.path().join("converting");
    fixture.init_checkout(&converting);
    fixture.git_in(&converting, &["config", "core.autocrlf", "true"]);

    let recorded = record_release(&fixture.repo_at(&converting), &entry, &key, LATER).unwrap();
    assert_eq!(recorded, outcome("fuz", "0.1.0", host, 1, false, false));
    assert_eq!(fixture.remote_subjects().len(), 1);
    assert_eq!(fixture.git_in(&converting, &["status", "--porcelain"]), "");

    // A new version from that checkout is committed with the log's own line
    // endings.
    let next = self_entry("0.2.0", host, b"two");
    let recorded = record_release(&fixture.repo_at(&converting), &next, &key, LATER).unwrap();
    assert_eq!(recorded, outcome("fuz", "0.2.0", host, 2, true, true));
    let pointer = fixture.remote_git(&[
        "cat-file",
        "blob",
        &format!("main:latest/fuz-{host}.sha512"),
    ]);
    assert!(!pointer.contains('\r'));
    assert!(
        !fixture
            .remote_git(&["cat-file", "blob", "main:head.json"])
            .contains('\r')
    );
}

/// The `latest/` pointer is the self artifact's: its file name splits into a
/// name and a target only when the name is known.
#[test]
fn a_latest_pointer_is_refused_for_any_other_name() {
    if !git_available() {
        return;
    }
    let fixture = Fixture::new();
    let before = fixture.state();
    let mut entry = self_entry("0.1.0", current_target(), b"one");
    entry.name = "fuz-extra".to_string();
    let error = record_release(&fixture.repo(), &entry, &trusted_key(), NOW).unwrap_err();
    assert!(
        matches!(&error, LogWriteError::InvalidEntry { field: "flat_latest", value } if value == "fuz-extra"),
        "{error:?}"
    );
    assert_eq!(fixture.state(), before);
    assert!(!fixture.checkout.join("latest").exists());
}

//
// Checked before upload
//

/// A tracked pointer under an ignore rule for its directory cannot be staged,
/// and is refused before anything is uploaded.
#[tokio::test]
async fn a_tracked_pointer_under_an_ignored_directory_is_refused_before_upload() {
    if !git_available() {
        return;
    }
    for rule in ["latest/", "latest", "head.json"] {
        let fixture = Fixture::new();
        publish_self(&fixture, "0.1.0").await.unwrap();
        std::fs::write(
            fixture.checkout.join(".git/info/exclude"),
            format!("{rule}\n"),
        )
        .unwrap();
        // Tracked, so a plain status sees nothing wrong.
        assert_eq!(
            fixture.git(&["status", "--porcelain", "--ignored"]),
            "",
            "{rule}"
        );
        let before = fixture.state();
        let stored_before = fixture.storage_files();

        let error = log_error(publish_self(&fixture, "0.2.0").await);
        assert!(
            matches!(&error, LogWriteError::Ignored { paths } if paths.contains(rule.trim_end_matches('/'))),
            "{rule}: {error:?}"
        );
        assert_eq!(fixture.storage_files(), stored_before, "{rule}");
        assert_eq!(fixture.state(), before, "{rule}");
    }
}

/// A checkout whose plain `git push` would not update the branch's upstream
/// is refused before anything is uploaded — it would otherwise upload, commit,
/// and then fail to push on every run.
#[tokio::test]
async fn a_push_configured_to_go_elsewhere_is_refused_before_upload() {
    if !git_available() {
        return;
    }
    let cases: [(&str, &str, Change); 3] = [
        ("branch named differently from its upstream", "local", |f| {
            f.git(&["branch", "--quiet", "-m", "main", "local"]);
            assert_eq!(f.git(&["config", "branch.local.merge"]), "refs/heads/main");
        }),
        ("remote.pushDefault", "main", |f| {
            let elsewhere = f.init_bare("elsewhere.git");
            f.git(&["remote", "add", "elsewhere", elsewhere.to_str().unwrap()]);
            f.git(&["config", "remote.pushDefault", "elsewhere"]);
        }),
        ("branch.main.pushRemote", "main", |f| {
            let elsewhere = f.init_bare("elsewhere.git");
            f.git(&["remote", "add", "elsewhere", elsewhere.to_str().unwrap()]);
            f.git(&["config", "branch.main.pushRemote", "elsewhere"]);
        }),
    ];
    for (case, branch, configure) in cases {
        let fixture = Fixture::new();
        publish_self(&fixture, "0.1.0").await.unwrap();
        configure(&fixture);
        let before = fixture.state();
        let stored_before = fixture.storage_files();

        let error = log_error(publish_self(&fixture, "0.2.0").await);
        assert!(
            matches!(&error, LogWriteError::PushElsewhere { branch: got } if got == branch),
            "{case}: {error:?}"
        );
        assert!(!error.is_security_violation(), "{case}");
        assert!(error.hint().unwrap().contains("push.default"), "{case}");
        assert_eq!(fixture.storage_files(), stored_before, "{case}");
        assert_eq!(fixture.state(), before, "{case}");
    }
}

/// A key this binary does not trust is refused even when it would sign no
/// head: republishing an already-logged release with it must not replace the
/// stored manifest or move the latest pointer.
#[tokio::test]
async fn an_untrusted_key_cannot_republish_a_logged_release() {
    if !git_available() {
        return;
    }
    let fixture = Fixture::new();
    let layout = ReleaseLayout::self_artifact();
    publish_self(&fixture, "0.1.0").await.unwrap();
    publish_self(&fixture, "0.2.0").await.unwrap();
    let before = fixture.state();
    let stored_before = fixture.storage_files();

    let error = log_error(
        publish_self_with(
            &fixture,
            "0.1.0",
            &fuz_content("0.1.0"),
            &untrusted_key(),
            &fixture.options(),
        )
        .await,
    );
    assert!(
        matches!(&error, LogWriteError::UntrustedKey { public_key: actual } if *actual == public_key(&untrusted_key())),
        "{error:?}"
    );
    assert!(error.is_security_violation());
    assert!(
        ReleaseError::from(log_error(
            publish_self_with(
                &fixture,
                "0.1.0",
                &fuz_content("0.1.0"),
                &untrusted_key(),
                &fixture.options(),
            )
            .await,
        ))
        .hint()
        .unwrap()
        .to_string()
        .contains("public_keys.json")
    );

    // The stored manifest is the trusted key's still, and nothing moved.
    assert_eq!(fixture.storage_files(), stored_before);
    let manifest = fixture
        .storage()
        .download(&layout.manifest_key("fuz", "0.1.0", current_target()))
        .await
        .unwrap();
    assert_eq!(
        Manifest::from_json(&manifest).unwrap().signature.public_key,
        public_key(&trusted_key())
    );
    assert_eq!(
        latest_version(&fixture.storage(), &layout).await,
        Some("0.2.0".to_string())
    );
    assert_eq!(fixture.state(), before);
}

/// Release storage that takes every upload and then denies having it.
struct Vanishing(FileStorage);

impl Storage for Vanishing {
    fn backend_kind(&self) -> StorageBackendKind {
        self.0.backend_kind()
    }
    async fn upload(&self, path: &str, data: &[u8]) -> Result<(), StorageError> {
        self.0.upload(path, data).await
    }
    async fn download(&self, path: &str) -> Result<Vec<u8>, StorageError> {
        self.0.download(path).await
    }
    async fn download_capped(&self, path: &str, max: u64) -> Result<Vec<u8>, StorageError> {
        self.0.download_capped(path, max).await
    }
    async fn download_to_file(&self, path: &str, dest: &Path) -> Result<u64, StorageError> {
        self.0.download_to_file(path, dest).await
    }
    async fn upload_file(&self, path: &str, src: &Path) -> Result<(), StorageError> {
        self.0.upload_file(path, src).await
    }
    #[allow(
        clippy::unused_async_trait_impl,
        reason = "trait conformance: an `async fn` body runs when awaited; the `impl Future` rewrite would run it at call time"
    )]
    async fn exists(&self, _path: &str) -> Result<bool, StorageError> {
        Ok(false)
    }
    async fn list(&self, prefix: &str) -> Result<Vec<String>, StorageError> {
        self.0.list(prefix).await
    }
    async fn delete(&self, path: &str) -> Result<(), StorageError> {
        self.0.delete(path).await
    }
}

/// An upload that cannot be confirmed is neither logged nor advertised, in
/// either flow.
#[tokio::test]
async fn an_unconfirmed_upload_is_not_logged() {
    if !git_available() {
        return;
    }
    let fixture = Fixture::new();
    let storage = Vanishing(fixture.storage());
    let content = fuz_content("0.1.0");
    let artifact_dir = tempfile::tempdir_in(fixture.tmp.path()).unwrap();
    std::fs::write(artifact_dir.path().join("fuz"), &content).unwrap();
    let outputs = ArtifactOutputs {
        fuz: ContentHash::blake3(&content),
    };
    let meta = ArtifactMeta::new_remote(outputs.content_hash(), "0.1.0".to_string(), outputs);
    meta.write(artifact_dir.path()).unwrap();
    let error = publish_artifact(
        &storage,
        &meta,
        artifact_dir.path(),
        &trusted_key(),
        &fixture.options(),
    )
    .await
    .unwrap_err();
    assert!(!matches!(error, ReleaseError::LogWrite(_)), "{error:?}");
    assert_eq!(fixture.remote_subjects(), Vec::<String>::new());
    assert_eq!(fixture.checkout_head_bytes(), None);
    assert_eq!(
        latest_version(&fixture.storage(), &ReleaseLayout::self_artifact()).await,
        None
    );

    // The tool flow, in storage of its own: the self release above left its
    // bytes behind, and a log with no head takes no release beside them.
    let fixture = Fixture::new();
    let storage = Vanishing(fixture.storage());
    let bin_path = fixture.tmp.path().join("fuzf");
    std::fs::write(&bin_path, host_binary(b"fuzf binary bytes")).unwrap();
    let error = publish_tool(
        &storage,
        "fuzf",
        "0.1.0",
        &[("fuzf".to_string(), bin_path)],
        &trusted_key(),
        &fixture.options(),
    )
    .await
    .unwrap_err();
    assert!(!matches!(error, ReleaseError::LogWrite(_)), "{error:?}");
    assert_eq!(fixture.remote_subjects(), Vec::<String>::new());
    assert_eq!(
        latest_version(&fixture.storage(), &ReleaseLayout::tool("fuzf")).await,
        None
    );
}

//
// A first head is complete
//

/// Place a manifest key in storage the way an unlogged publish leaves one.
/// The fail-safe reads keys, never manifests, so the bytes are not a manifest.
async fn place_manifest(fixture: &Fixture, layout: &ReleaseLayout, name: &str, version: &str) {
    fixture
        .storage()
        .upload(
            &layout.manifest_key(name, version, current_target()),
            b"not read",
        )
        .await
        .unwrap();
}

#[track_caller]
fn unlogged_keys(error: LogWriteError) -> String {
    assert!(!error.is_security_violation(), "{error:?}");
    let hint = error.hint().unwrap_or_default();
    assert!(
        hint.contains("cargo xtask release-log backfill --storage <uri> --log-repo <path>"),
        "{hint}"
    );
    match error {
        LogWriteError::UnloggedReleases { keys } => keys,
        other => panic!("expected the first head to be refused, got {other:?}"),
    }
}

/// A log with no head takes no release while storage holds another — in the
/// publishing stream or in any other. Nothing is uploaded and the checkout is
/// as it was.
#[tokio::test]
async fn a_first_head_is_refused_while_storage_holds_other_releases() {
    if !git_available() {
        return;
    }
    let host = current_target();
    let cases = [
        (
            "an earlier self release",
            ReleaseLayout::self_artifact().manifest_key("fuz", "0.1.0", host),
        ),
        (
            "a tool release",
            ReleaseLayout::tool("fuzd").manifest_key("fuzd", "0.3.0", host),
        ),
        // The same version for another target is another release target, and
        // a first head made of this publish alone would leave it out.
        (
            "another target of this version",
            ReleaseLayout::self_artifact().manifest_key("fuz", "0.5.0", other_target()),
        ),
    ];
    for (case, placed) in cases {
        let fixture = Fixture::new();
        // The fail-safe reads keys, never manifests.
        fixture
            .storage()
            .upload(&placed, b"not read")
            .await
            .unwrap();
        let stored = fixture.storage_files();
        let before = fixture.state();

        // The self flow.
        let error = log_error(publish_self(&fixture, "0.5.0").await);
        let keys = unlogged_keys(error);
        assert_eq!(keys, format!("\n  {placed}"), "{case}");
        assert_eq!(fixture.storage_files(), stored, "{case}: nothing uploaded");
        assert_eq!(fixture.state(), before, "{case}: the checkout is untouched");

        // The tool flow, publishing into a stream of its own.
        let bin_path = fixture.tmp.path().join("fuzf");
        std::fs::write(&bin_path, host_binary(b"fuzf binary bytes")).unwrap();
        let error = log_error(
            publish_tool(
                &fixture.storage(),
                "fuzf",
                "0.1.0",
                &[("fuzf".to_string(), bin_path)],
                &trusted_key(),
                &fixture.options(),
            )
            .await,
        );
        assert_eq!(unlogged_keys(error), format!("\n  {placed}"), "{case}");
        assert_eq!(fixture.storage_files(), stored, "{case}: nothing uploaded");
        assert_eq!(fixture.state(), before, "{case}: the checkout is untouched");
        assert!(!fixture.checkout.join("latest").exists(), "{case}");
    }
}

/// The first release of all still creates the log, and the same publish run
/// again after its upload — its own manifest now in storage, the log write
/// having failed — still goes through.
#[tokio::test]
async fn a_first_release_and_its_retry_create_the_log() {
    if !git_available() {
        return;
    }
    let fixture = Fixture::new();
    let host = current_target();

    // The commit fails, so the publish stops with its bytes uploaded and the
    // log still without a head.
    Fixture::install_hook(
        &fixture.checkout.join(".git"),
        "pre-commit",
        "#!/bin/sh\necho 'commit refused by the test hook' >&2\nexit 1\n",
    );
    let error = log_error(publish_self(&fixture, "0.5.0").await);
    assert!(matches!(error, LogWriteError::Git { .. }), "{error:?}");
    assert_eq!(fixture.checkout_head_bytes(), None);
    let own_manifest = ReleaseLayout::self_artifact().manifest_key("fuz", "0.5.0", host);
    assert!(fixture.storage().exists(&own_manifest).await.unwrap());

    // Run again: the only release storage holds is this one.
    std::fs::remove_file(fixture.checkout.join(".git/hooks/pre-commit")).unwrap();
    let published = publish_self(&fixture, "0.5.0").await.unwrap();
    assert_eq!(
        published.logged,
        Some(outcome("fuz", "0.5.0", host, 1, true, true))
    );
    assert_eq!(fixture.remote_head("main").rows().len(), 1);

    // With a head, the log is never held to storage again: an unlogged key
    // placed beside it does not stop the next release.
    place_manifest(&fixture, &ReleaseLayout::tool("fuzd"), "fuzd", "0.3.0").await;
    let next = publish_self(&fixture, "0.6.0").await.unwrap();
    assert_eq!(
        next.logged,
        Some(outcome("fuz", "0.6.0", host, 2, true, true))
    );
}

/// A first head committed here and never pushed is a head: the retry pushes it
/// without listing storage.
#[tokio::test]
async fn an_unpushed_first_head_is_not_held_to_storage() {
    if !git_available() {
        return;
    }
    let fixture = Fixture::new();
    let host = current_target();
    fixture.reject_pushes();
    let error = log_error(publish_self(&fixture, "0.5.0").await);
    assert!(matches!(error, LogWriteError::Git { .. }), "{error:?}");
    assert!(fixture.checkout_head_bytes().is_some());

    place_manifest(&fixture, &ReleaseLayout::tool("fuzd"), "fuzd", "0.3.0").await;
    fixture.accept_pushes();
    let published = publish_self(&fixture, "0.5.0").await.unwrap();
    assert_eq!(
        published.logged,
        Some(outcome("fuz", "0.5.0", host, 1, false, true))
    );
}

/// Release storage that cannot be listed.
struct Unlistable(FileStorage);

impl Storage for Unlistable {
    fn backend_kind(&self) -> StorageBackendKind {
        self.0.backend_kind()
    }
    async fn upload(&self, path: &str, data: &[u8]) -> Result<(), StorageError> {
        self.0.upload(path, data).await
    }
    async fn download(&self, path: &str) -> Result<Vec<u8>, StorageError> {
        self.0.download(path).await
    }
    async fn download_capped(&self, path: &str, max: u64) -> Result<Vec<u8>, StorageError> {
        self.0.download_capped(path, max).await
    }
    async fn download_to_file(&self, path: &str, dest: &Path) -> Result<u64, StorageError> {
        self.0.download_to_file(path, dest).await
    }
    async fn upload_file(&self, path: &str, src: &Path) -> Result<(), StorageError> {
        self.0.upload_file(path, src).await
    }
    async fn exists(&self, path: &str) -> Result<bool, StorageError> {
        self.0.exists(path).await
    }
    #[allow(
        clippy::unused_async_trait_impl,
        reason = "trait conformance: an `async fn` body runs when awaited; the `impl Future` rewrite would run it at call time"
    )]
    async fn list(&self, prefix: &str) -> Result<Vec<String>, StorageError> {
        Err(StorageError::PermissionDenied {
            backend: StorageBackendKind::File,
            path: prefix.to_string(),
        })
    }
    async fn delete(&self, path: &str) -> Result<(), StorageError> {
        self.0.delete(path).await
    }
}

/// A listing that fails is a refusal, not a pass: a first head is written only
/// when storage is known to hold nothing else. A log with a head needs no
/// listing at all.
#[tokio::test]
async fn a_first_head_is_refused_when_storage_cannot_be_listed() {
    if !git_available() {
        return;
    }
    let fixture = Fixture::new();
    let key = trusted_key();
    let host = current_target();
    let entry = self_entry("0.5.0", host, &fuz_content("0.5.0"));
    let storage = Unlistable(fixture.storage());
    let before = fixture.state();

    for attempt in ["check", "record"] {
        let error = if attempt == "check" {
            fuz_sign::check_release(&storage, &fixture.repo(), &entry, &key, NOW)
                .await
                .unwrap_err()
        } else {
            fuz_sign::record_release(&storage, &fixture.repo(), &entry, &key, NOW)
                .await
                .unwrap_err()
        };
        assert!(
            matches!(
                error,
                LogWriteError::Storage(StorageError::PermissionDenied { .. })
            ),
            "{attempt}: {error:?}"
        );
        assert!(!error.is_security_violation());
        assert_eq!(fixture.state(), before, "{attempt}");
        assert_eq!(fixture.storage_files(), Vec::new(), "{attempt}");
    }

    // Once the log has a head, storage is not listed.
    record_release(&fixture.repo(), &entry, &key, NOW).unwrap();
    let next = self_entry("0.6.0", host, &fuz_content("0.6.0"));
    fuz_sign::check_release(&storage, &fixture.repo(), &next, &key, LATER)
        .await
        .unwrap();
    let recorded = fuz_sign::record_release(&storage, &fixture.repo(), &next, &key, LATER)
        .await
        .unwrap();
    assert_eq!(recorded, outcome("fuz", "0.6.0", host, 2, true, true));
}

/// What storage holds reaches the refusal escaped and bounded: a key cannot
/// add a line to the error, and a storage full of releases is not listed whole.
#[tokio::test]
async fn the_refusal_lists_storage_keys_escaped_and_bounded() {
    if !git_available() {
        return;
    }
    let fixture = Fixture::new();
    let host = current_target();
    for patch in 0..40 {
        place_manifest(
            &fixture,
            &ReleaseLayout::self_artifact(),
            "fuz",
            &format!("0.1.{patch}"),
        )
        .await;
    }
    // A key only a hostile or broken storage would hold.
    let hostile = "fuz-0.0.0\u{1b}[2K.manifest.json";
    std::fs::write(fixture.storage_dir.join(hostile), b"not read").unwrap();

    let entry = self_entry("0.5.0", host, &fuz_content("0.5.0"));
    let error = fuz_sign::check_release(
        &fixture.storage(),
        &fixture.repo(),
        &entry,
        &trusted_key(),
        NOW,
    )
    .await
    .unwrap_err();
    let message = error.to_string();
    assert!(!message.contains('\u{1b}'), "{message:?}");
    assert!(
        message.contains("fuz-0.0.0\\u{1b}[2K.manifest.json"),
        "{message}"
    );
    assert!(message.contains("more)"), "{message}");
    assert!(
        message.lines().count() < 25,
        "the listing is bounded: {message}"
    );
}

/// A work tree with no `head.json` is a log with no head only when the log's
/// commits have none either. A committed deletion that was never pushed, or a
/// file removed behind a skip-worktree or assume-unchanged flag, leaves a clean
/// checkout whose work tree lacks the head the log has; a first head is not
/// signed over it, whatever storage holds.
#[tokio::test]
async fn a_head_missing_from_the_work_tree_is_not_a_first_head() {
    if !git_available() {
        return;
    }
    let host = current_target();
    let key = trusted_key();
    let cases: [(&str, &str, Change); 3] = [
        (
            "a committed, unpushed deletion",
            "its upstream",
            |fixture| {
                fixture.git(&["rm", "--quiet", HEAD_FILE]);
                fixture.git(&["commit", "--quiet", "-m", "drop the head"]);
            },
        ),
        ("a skip-worktree file removed", "its upstream", |fixture| {
            fixture.git(&["update-index", "--skip-worktree", HEAD_FILE]);
            std::fs::remove_file(fixture.checkout.join(HEAD_FILE)).unwrap();
        }),
        (
            "an assume-unchanged file removed",
            "its upstream",
            |fixture| {
                fixture.git(&["update-index", "--assume-unchanged", HEAD_FILE]);
                std::fs::remove_file(fixture.checkout.join(HEAD_FILE)).unwrap();
            },
        ),
    ];
    for (case, held_by, drop_head) in cases {
        for with_storage in [false, true] {
            let fixture = Fixture::new();
            for version in ["0.1.0", "0.2.0"] {
                record_release(
                    &fixture.repo(),
                    &self_entry(version, host, &fuz_content(version)),
                    &key,
                    NOW,
                )
                .unwrap();
            }
            drop_head(&fixture);
            if with_storage {
                place_manifest(&fixture, &ReleaseLayout::self_artifact(), "fuz", "0.1.0").await;
            }
            let stored = fixture.storage_files();
            let before = fixture.state();
            let entry = self_entry("0.3.0", host, &fuz_content("0.3.0"));

            let checked =
                fuz_sign::check_release(&fixture.storage(), &fixture.repo(), &entry, &key, LATER)
                    .await
                    .unwrap_err();
            let recorded =
                fuz_sign::record_release(&fixture.storage(), &fixture.repo(), &entry, &key, LATER)
                    .await
                    .unwrap_err();
            for error in [checked, recorded] {
                assert!(
                    matches!(error, LogWriteError::HeadMissing { held_by: at } if at == held_by),
                    "{case}: {error:?}"
                );
                assert!(error.is_security_violation(), "{case}");
                let hint = error.hint().unwrap();
                assert!(hint.contains("git reset --hard @{upstream}"), "{hint}");
                assert!(!hint.contains("backfill"), "{hint}");
            }
            assert_eq!(fixture.state(), before, "{case}");
            assert_eq!(fixture.storage_files(), stored, "{case}");
            let head = fixture.remote_head("main");
            assert_eq!((head.seq(), head.rows().len()), (2, 2), "{case}");

            // The full publish flow stops at the same place, before any upload.
            let error = log_error(publish_self(&fixture, "0.3.0").await);
            assert!(
                matches!(error, LogWriteError::HeadMissing { .. }),
                "{case}: {error:?}"
            );
            assert_eq!(fixture.storage_files(), stored, "{case}");
        }
    }

    // A head committed here and never pushed, then hidden the same way: the
    // last commit is what holds it.
    let fixture = Fixture::new();
    fixture.reject_pushes();
    let entry = self_entry("0.1.0", host, &fuz_content("0.1.0"));
    record_release(&fixture.repo(), &entry, &key, NOW).unwrap_err();
    fixture.git(&["update-index", "--skip-worktree", HEAD_FILE]);
    std::fs::remove_file(fixture.checkout.join(HEAD_FILE)).unwrap();
    fixture.accept_pushes();
    let error = record_release(&fixture.repo(), &entry, &key, LATER).unwrap_err();
    assert!(
        matches!(
            error,
            LogWriteError::HeadMissing {
                held_by: "its last commit"
            }
        ),
        "{error:?}"
    );
    assert_eq!(fixture.remote_subjects(), Vec::<String>::new());
}

//
// The read-back of the pushed commit
//

/// The read-back compares the pins, not only that the target has an entry.
#[test]
fn a_pushed_head_with_other_pins_is_an_error() {
    if !git_available() {
        return;
    }
    let fixture = Fixture::new();
    let key = trusted_key();
    let host = current_target();
    let other =
        advanced(next_head(None, &self_entry("0.1.0", host, b"other bytes"), &key, NOW).unwrap());
    let swapped = fixture.tmp.path().join("swapped-head.json");
    std::fs::write(&swapped, other.to_json().unwrap()).unwrap();
    Fixture::install_hook(
        &fixture.checkout.join(".git"),
        "pre-commit",
        &format!(
            "#!/bin/sh\ncp '{}' head.json\ngit add head.json\n",
            swapped.display()
        ),
    );
    let error = record_release(
        &fixture.repo(),
        &self_entry("0.1.0", host, b"one"),
        &key,
        NOW,
    )
    .unwrap_err();
    assert!(
        matches!(&error, LogWriteError::NotPublished { detail, .. } if detail.contains("head.json")),
        "{error:?}"
    );
}

/// The pointer is read back from the pushed commit, not the work tree: a hook
/// that changes only what is committed leaves the work tree looking right.
#[test]
fn a_pushed_pointer_that_differs_from_the_work_tree_is_an_error() {
    if !git_available() {
        return;
    }
    let fixture = Fixture::new();
    let host = current_target();
    let pointer = format!("latest/fuz-{host}.sha512");
    Fixture::install_hook(
        &fixture.checkout.join(".git"),
        "pre-commit",
        &format!(
            "#!/bin/sh\nblob=$(printf 'not the digest\\n' | git hash-object -w --stdin)\n\
             git update-index --add --cacheinfo \"100644,$blob,{pointer}\"\n"
        ),
    );
    let entry = self_entry("0.1.0", host, b"one");
    let error = record_release(&fixture.repo(), &entry, &trusted_key(), NOW).unwrap_err();
    assert!(
        matches!(&error, LogWriteError::NotPublished { detail, .. } if detail.contains("latest/")),
        "{error:?}"
    );
    // The work tree holds the right pointer; only the commit does not.
    assert_ne!(
        std::fs::read(fixture.checkout.join(&pointer)).unwrap(),
        b"not the digest\n"
    );
    assert_eq!(
        fixture.remote_git(&["show", &format!("main:{pointer}")]),
        "not the digest"
    );
}

/// A pushed `head.json` past the head size limit is refused by its size,
/// before it is read.
#[test]
fn an_oversized_pushed_head_is_refused_unread() {
    if !git_available() {
        return;
    }
    let fixture = Fixture::new();
    Fixture::install_hook(
        &fixture.checkout.join(".git"),
        "pre-commit",
        "#!/bin/sh\nhead -c 3000000 /dev/zero | tr '\\0' ' ' > head.json\ngit add head.json\n",
    );
    let error = record_release(
        &fixture.repo(),
        &self_entry("0.1.0", current_target(), b"one"),
        &trusted_key(),
        NOW,
    )
    .unwrap_err();
    assert!(
        matches!(&error, LogWriteError::NotPublished { detail, .. } if detail.contains("larger than the log allows")),
        "{error:?}"
    );
    assert!(error.hint().unwrap().contains("hook"));
}

//
// The checkout, continued
//

/// A link that arrives with the fast-forward is refused like one already in
/// the checkout: nothing is written through it.
#[test]
fn a_symlink_brought_by_the_fast_forward_is_refused() {
    if !git_available() {
        return;
    }
    let fixture = Fixture::new();
    let key = trusted_key();
    let host = current_target();
    // A first head with no `latest/` directory.
    record_release(
        &fixture.repo(),
        &install_script_entry("1", b"#!/bin/sh\n"),
        &key,
        NOW,
    )
    .unwrap();
    let outside = fixture.tmp.path().join("outside");
    std::fs::create_dir(&outside).unwrap();
    let other = fixture.tmp.path().join("other");
    fixture.init_checkout(&other);
    fixture.git_in(&other, &["pull", "--quiet", "--ff-only", "origin", "main"]);
    std::os::unix::fs::symlink(&outside, other.join("latest")).unwrap();
    fixture.git_in(&other, &["add", "latest"]);
    fixture.git_in(
        &other,
        &["commit", "--quiet", "-m", "a link where latest/ goes"],
    );
    fixture.git_in(&other, &["push", "--quiet"]);

    let error = record_release(
        &fixture.repo(),
        &self_entry("0.1.0", host, b"one"),
        &key,
        LATER,
    )
    .unwrap_err();
    assert!(
        matches!(
            &error,
            LogWriteError::UnsafePath {
                expected: "directory",
                ..
            }
        ),
        "{error:?}"
    );
    assert!(error.is_security_violation());
    assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 0);
    assert_eq!(fixture.git(&["status", "--porcelain"]), "");
}

/// The change detection is per path: something else staged does not make an
/// unchanged pointer look changed.
#[test]
fn a_converting_checkout_with_something_else_staged_republishes_cleanly() {
    if !git_available() {
        return;
    }
    let fixture = Fixture::new();
    let key = trusted_key();
    let host = current_target();
    let entry = self_entry("0.1.0", host, b"one");
    record_release(&fixture.repo(), &entry, &key, NOW).unwrap();
    let converting = fixture.tmp.path().join("converting");
    fixture.init_checkout(&converting);
    fixture.git_in(&converting, &["config", "core.autocrlf", "true"]);
    std::fs::write(converting.join("notes"), "staged by hand").unwrap();
    fixture.git_in(&converting, &["add", "notes"]);
    let recorded = record_release(&fixture.repo_at(&converting), &entry, &key, LATER).unwrap();
    assert_eq!(recorded, outcome("fuz", "0.1.0", host, 1, false, false));
    assert_eq!(fixture.remote_subjects().len(), 1);
    assert_eq!(
        fixture.git_in(&converting, &["status", "--porcelain"]),
        "A  notes"
    );
}

/// A rollback that cannot run is reported beside the error that caused it, and
/// the half-written checkout is refused on the next run.
#[test]
fn a_rollback_that_fails_is_reported_and_the_next_run_refuses() {
    if !git_available() {
        return;
    }
    let fixture = Fixture::new();
    let key = trusted_key();
    let host = current_target();
    record_release(
        &fixture.repo(),
        &self_entry("0.1.0", host, b"one"),
        &key,
        NOW,
    )
    .unwrap();
    let lock = fixture.checkout.join(".git/index.lock");
    std::fs::write(&lock, "").unwrap();
    let entry = self_entry("0.2.0", host, b"two");
    let error = record_release(&fixture.repo(), &entry, &key, LATER).unwrap_err();
    match &error {
        LogWriteError::Git { command, output } => {
            assert_eq!(command, "add");
            assert!(output.contains("index.lock"), "{output}");
            assert!(output.contains("not fully restored"), "{output}");
        }
        other => panic!("expected a failed add, got {other:?}"),
    }
    std::fs::remove_file(&lock).unwrap();
    assert!(matches!(
        record_release(&fixture.repo(), &entry, &key, LATER).unwrap_err(),
        LogWriteError::Dirty { .. }
    ));
    assert_eq!(fixture.remote_subjects().len(), 1);
}

/// Rolling back removes a `latest/` directory only when this run created it:
/// one that was already there, even empty, stays.
#[test]
fn a_rollback_keeps_a_latest_directory_it_did_not_create() {
    if !git_available() {
        return;
    }
    let fixture = Fixture::new();
    let latest = fixture.checkout.join("latest");
    std::fs::create_dir(&latest).unwrap();
    Fixture::install_hook(
        &fixture.checkout.join(".git"),
        "pre-commit",
        "#!/bin/sh\nexit 1\n",
    );
    let before = fixture.state();

    let error = record_release(
        &fixture.repo(),
        &self_entry("0.1.0", current_target(), b"one"),
        &trusted_key(),
        NOW,
    )
    .unwrap_err();
    assert!(
        matches!(&error, LogWriteError::Git { command, .. } if command == "commit"),
        "{error:?}"
    );
    assert!(latest.is_dir(), "a directory this run did not create stays");
    assert_eq!(std::fs::read_dir(&latest).unwrap().count(), 0);
    assert!(!fixture.checkout.join(HEAD_FILE).exists());
    assert_eq!(fixture.state(), before);
}

/// A tag named like the branch does not confuse which branch is checked out
/// or what its upstream is.
#[tokio::test]
async fn a_tag_named_like_the_branch_changes_nothing() {
    if !git_available() {
        return;
    }
    let fixture = Fixture::new();
    let host = current_target();
    publish_self(&fixture, "0.1.0").await.unwrap();
    fixture.git(&["tag", "main"]);

    let published = publish_self(&fixture, "0.2.0").await.unwrap();
    assert_eq!(
        published.logged,
        Some(outcome("fuz", "0.2.0", host, 2, true, true))
    );
    assert_eq!(
        fixture.remote_subjects(),
        [
            format!("log: fuz 0.1.0 {host} seq 1"),
            format!("log: fuz 0.2.0 {host} seq 2"),
        ]
    );
}

/// A pushed `latest/` pointer past its size limit is refused by its size.
#[test]
fn an_oversized_pushed_pointer_is_refused_unread() {
    if !git_available() {
        return;
    }
    let fixture = Fixture::new();
    let host = current_target();
    let pointer = format!("latest/fuz-{host}.sha512");
    Fixture::install_hook(
        &fixture.checkout.join(".git"),
        "pre-commit",
        &format!(
            "#!/bin/sh\nhead -c 5000 /dev/zero | tr '\\0' 'a' > '{pointer}'\ngit add '{pointer}'\n"
        ),
    );
    let error = record_release(
        &fixture.repo(),
        &self_entry("0.1.0", host, b"one"),
        &trusted_key(),
        NOW,
    )
    .unwrap_err();
    assert!(
        matches!(&error, LogWriteError::NotPublished { detail, .. } if detail.contains("larger than the log allows")),
        "{error:?}"
    );
}

/// The size limit on a pushed head is inclusive: a head exactly at it is read
/// (and here fails to parse), one byte past it is not read at all.
#[test]
fn a_pushed_head_at_the_size_limit_is_read_and_one_past_it_is_not() {
    if !git_available() {
        return;
    }
    for (size, over) in [
        (fuz_release::MAX_HEAD_SIZE, false),
        (fuz_release::MAX_HEAD_SIZE + 1, true),
    ] {
        let fixture = Fixture::new();
        Fixture::install_hook(
            &fixture.checkout.join(".git"),
            "pre-commit",
            &format!(
                "#!/bin/sh\nhead -c {size} /dev/zero | tr '\\0' ' ' > head.json\ngit add head.json\n"
            ),
        );
        let error = record_release(
            &fixture.repo(),
            &self_entry("0.1.0", current_target(), b"one"),
            &trusted_key(),
            NOW,
        )
        .unwrap_err();
        if over {
            assert!(
                matches!(&error, LogWriteError::NotPublished { detail, .. } if detail.contains("larger")),
                "{error:?}"
            );
        } else {
            assert!(
                matches!(&error, LogWriteError::PublishedHead(_)),
                "{error:?}"
            );
        }
    }
}

/// A `HEAD` edited by hand to name a branch git itself would refuse never
/// reaches a command line.
#[test]
fn a_hand_edited_head_naming_an_option_shaped_branch_is_refused() {
    if !git_available() {
        return;
    }
    let fixture = Fixture::new();
    std::fs::write(fixture.checkout.join(".git/HEAD"), "ref: refs/heads/-x\n").unwrap();
    let error = record_release(
        &fixture.repo(),
        &self_entry("0.1.0", current_target(), b"one"),
        &trusted_key(),
        NOW,
    )
    .unwrap_err();
    assert!(matches!(error, LogWriteError::DetachedHead), "{error:?}");
    assert_eq!(fixture.checkout_head_bytes(), None);
}

/// A `HEAD` that names a ref outside `refs/heads/` is not a branch, whatever
/// configuration exists under its name.
#[test]
fn a_head_naming_a_ref_that_is_not_a_branch_is_refused() {
    if !git_available() {
        return;
    }
    for target in ["refs/tags/x", "refs/remotes/origin/main"] {
        let fixture = Fixture::new();
        record_release(
            &fixture.repo(),
            &self_entry("0.1.0", current_target(), b"one"),
            &trusted_key(),
            NOW,
        )
        .unwrap();
        fixture.git(&["tag", "x"]);
        fixture.git(&["config", &format!("branch.{target}.remote"), "origin"]);
        fixture.git(&[
            "config",
            &format!("branch.{target}.merge"),
            "refs/heads/main",
        ]);
        std::fs::write(
            fixture.checkout.join(".git/HEAD"),
            format!("ref: {target}\n"),
        )
        .unwrap();
        let before = fixture.remote_subjects();
        let error = record_release(
            &fixture.repo(),
            &self_entry("0.2.0", current_target(), b"two"),
            &trusted_key(),
            LATER,
        )
        .unwrap_err();
        assert!(
            matches!(error, LogWriteError::DetachedHead),
            "{target}: {error:?}"
        );
        assert_eq!(fixture.remote_subjects(), before);
    }
}

/// The push-configuration check runs after the fetch, so a checkout that has
/// never fetched its upstream is still checked before upload.
#[tokio::test]
async fn a_push_elsewhere_is_caught_on_a_never_fetched_checkout() {
    if !git_available() {
        return;
    }
    let fixture = Fixture::new();
    publish_self(&fixture, "0.1.0").await.unwrap();
    let fresh = fixture.tmp.path().join("fresh");
    fixture.init_checkout(&fresh);
    let elsewhere = fixture.init_bare("elsewhere.git");
    fixture.git_in(
        &fresh,
        &["remote", "add", "elsewhere", elsewhere.to_str().unwrap()],
    );
    fixture.git_in(&fresh, &["config", "remote.pushDefault", "elsewhere"]);
    let stored_before = fixture.storage_files();
    let options = PublishOptions {
        log_repo: Some(fixture.repo_at(&fresh)),
        ..PublishOptions::default()
    };
    let error = log_error(
        publish_self_with(
            &fixture,
            "0.2.0",
            &fuz_content("0.2.0"),
            &trusted_key(),
            &options,
        )
        .await,
    );
    assert!(
        matches!(&error, LogWriteError::PushElsewhere { branch } if branch == "main"),
        "{error:?}"
    );
    assert_eq!(fixture.storage_files(), stored_before);
}

/// A configured remote shaped like an option is not passed to `git fetch`.
#[test]
fn an_option_shaped_upstream_remote_is_no_upstream() {
    if !git_available() {
        return;
    }
    let fixture = Fixture::new();
    fixture.git(&["config", "branch.main.remote", "--upload-pack=touch pwned"]);
    let error = record_release(
        &fixture.repo(),
        &self_entry("0.1.0", current_target(), b"one"),
        &trusted_key(),
        NOW,
    )
    .unwrap_err();
    assert!(
        matches!(error, LogWriteError::NoUpstream { .. }),
        "{error:?}"
    );
    assert!(!fixture.checkout.join("pwned").exists());
}

//
// The pure layer, through a real signature
//

fn advanced(next: NextHead) -> VerifiedHead {
    match next {
        NextHead::Advanced(head) => *head,
        NextHead::Unchanged => panic!("expected a new head"),
    }
}

#[test]
fn next_head_starts_at_seq_one_and_advances_by_one() {
    trust();
    let key = trusted_key();
    let first = advanced(next_head(None, &self_entry("0.1.0", X86, b"one"), &key, NOW).unwrap());
    assert_eq!(first.seq(), 1);
    assert_eq!(first.rows().len(), 1);
    assert_eq!(first.rows()[0].published_at, NOW);
    assert_eq!(first.signature().signed_at, NOW);
    assert_eq!(first.keys().len(), 1);
    assert_eq!(first.keys()[0].public_key, public_key(&key));
    assert_eq!(first.keys()[0].added_at, NOW);

    let second = advanced(
        next_head(
            Some(&first),
            &self_entry("0.1.0", ARM, b"one arm"),
            &key,
            LATER,
        )
        .unwrap(),
    );
    assert_eq!(second.seq(), 2);
    assert_eq!(second.rows().len(), 1);
    assert_eq!(second.rows()[0].published_at, NOW);
    assert_eq!(
        second.keys(),
        first.keys(),
        "a recorded key is not recorded again"
    );
    assert_eq!(check_successor(&first, &second), Ok(Succession::Advanced));

    // The same entry again: nothing to sign.
    assert!(matches!(
        next_head(
            Some(&second),
            &self_entry("0.1.0", ARM, b"one arm"),
            &key,
            LATER
        )
        .unwrap(),
        NextHead::Unchanged
    ));

    // A second key signing a later release is appended; the first stays put.
    let other = second_trusted_key();
    let third = advanced(
        next_head(
            Some(&second),
            &self_entry("0.2.0", X86, b"two"),
            &other,
            LATER,
        )
        .unwrap(),
    );
    assert_eq!(third.seq(), 3);
    assert_eq!(third.keys().len(), 2);
    assert_eq!(third.keys()[0], second.keys()[0]);
    assert_eq!(third.keys()[1].public_key, public_key(&other));
    assert_eq!(third.keys()[1].added_at, LATER);
    assert_eq!(check_successor(&second, &third), Ok(Succession::Advanced));
}

#[test]
fn next_head_refuses_to_run_past_the_last_seq() {
    trust();
    let key = trusted_key();
    let first = advanced(next_head(None, &self_entry("0.1.0", X86, b"one"), &key, NOW).unwrap());
    // One below the bound still advances, to the bound itself.
    let mut penultimate = first.to_unsigned();
    penultimate.seq = MAX_HEAD_SEQ - 1;
    let penultimate = sign_successor(Some(&first), penultimate, &key, NOW).unwrap();
    let last = advanced(
        next_head(
            Some(&penultimate),
            &self_entry("0.1.1", X86, b"one point one"),
            &key,
            LATER,
        )
        .unwrap(),
    );
    assert_eq!(last.seq(), MAX_HEAD_SEQ);

    let error = next_head(Some(&last), &self_entry("0.2.0", X86, b"two"), &key, LATER).unwrap_err();
    assert!(
        matches!(error, LogWriteError::SeqExhausted(seq) if seq == MAX_HEAD_SEQ),
        "{error:?}"
    );
}

/// The self-check: a head the publisher signed is held to the append-only
/// rules against the one it replaces, before anything is written.
#[test]
fn sign_successor_refuses_a_head_that_breaks_the_rules() {
    trust();
    let key = trusted_key();
    let previous = advanced(next_head(None, &self_entry("0.1.0", X86, b"one"), &key, NOW).unwrap());

    // An honest successor passes.
    let mut honest = previous.to_unsigned();
    honest.seq += 1;
    honest.rows[0]
        .targets
        .insert(ARM.to_string(), self_entry("0.1.0", ARM, b"one arm").pins);
    sign_successor(Some(&previous), honest.clone(), &key, LATER).unwrap();

    // A rewritten target.
    let mut rewritten = honest.clone();
    rewritten.rows[0].targets.get_mut(X86).unwrap().sha512 = Some(ContentHash::sha512(b"other"));
    let error = sign_successor(Some(&previous), rewritten, &key, LATER).unwrap_err();
    assert!(
        matches!(
            &error,
            LogWriteError::NotSuccessor(HeadViolation::TargetChanged {
                field: TargetField::Sha512,
                ..
            })
        ),
        "{error:?}"
    );
    assert!(error.is_security_violation());
    assert!(ReleaseError::from(error).is_security_violation());

    // A dropped row.
    let mut dropped = honest.clone();
    dropped.rows.clear();
    dropped.rows.push(fuz_release::ReleaseRow {
        name: "fuzd".to_string(),
        ..honest.rows[0].clone()
    });
    assert!(matches!(
        sign_successor(Some(&previous), dropped, &key, LATER),
        Err(LogWriteError::NotSuccessor(
            HeadViolation::RowRemoved { .. }
        ))
    ));

    // A reused seq.
    let mut reused = honest.clone();
    reused.seq = previous.seq();
    assert!(matches!(
        sign_successor(Some(&previous), reused, &key, LATER),
        Err(LogWriteError::NotSuccessor(HeadViolation::SeqReused {
            seq: 1
        }))
    ));

    // The same head again does not advance.
    let error = sign_successor(Some(&previous), previous.to_unsigned(), &key, LATER).unwrap_err();
    assert!(matches!(error, LogWriteError::NotAdvanced), "{error:?}");
    assert!(error.is_security_violation());

    // A key this binary does not trust.
    assert!(matches!(
        sign_successor(Some(&previous), honest, &untrusted_key(), LATER),
        Err(LogWriteError::SignedHead(ReleaseLogError::Signature(_)))
    ));
}
