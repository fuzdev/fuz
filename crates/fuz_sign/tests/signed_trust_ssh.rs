//! End-to-end signed-trust path **over the `ssh://` transport**: sign with a
//! trusted key → publish to a remote host over `scp`/`ssh` → fetch back over
//! `ssh` → pass the real ed25519 trust check → install into a temp home. The
//! `ssh`-backend twin of `signed_trust.rs` (which uses `FileStorage`).
//!
//! This is the only test that drives the full publish → fetch → verify → install
//! loop across the wire, so it guards the Phase-1 "fresh VPS deploy" flow. The
//! signed tarball is moved by `scp` (`upload_file` on publish,
//! `download_to_file` on fetch), so this also exercises the OpenSSH-9+ SFTP-mode
//! `scp` path at the release layer, above `fuz_storage`'s own round-trip test.
//!
//! Gated on `SSH_TEST_TARGET` (`ssh://user@host[:port]/path`, key/agent auth,
//! host already in `~/.ssh/known_hosts`) and `#[ignore]`, so CI without an SSH
//! host skips it:
//!
//! ```bash
//! export SSH_TEST_TARGET=ssh://$USER@localhost/tmp/fuz-ssh-test
//! cargo test -p fuz_sign --test signed_trust_ssh -- --ignored --nocapture
//! ```
//!
//! Uses the same two dev-dependency-only seams as `signed_trust.rs`
//! (`fuz_crypto/test_trust_anchor` + `fuz_home/test_home_override`), both
//! compiled out of every shipping binary (resolver-2 + `cargo tree -e features`).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fuz_artifact::platform::test_stubs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use fuz_artifact::{ArtifactMeta, ArtifactOutputs};
use fuz_crypto::ContentHash;
use fuz_release::{
    FetchOptions, ToolInstallOptions, ToolInstallOutcome, fetch_latest, fetch_latest_manifest,
    install_tool, verify_installed_tool,
};
use fuz_sign::{PublishOptions, SigningKey, publish_artifact, publish_tool};
use fuz_storage::{Storage, StorageBackend, parse_storage};
use fuz_sys::SECURE_DIR_MODE;

/// The trust anchor and home override are process globals, and cargo runs the
/// file's `#[test]`s on parallel threads. A tokio mutex (not std) so it can be
/// held across `.await` without tripping `await_holding_lock` or poisoning on a
/// panicking assertion.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// A fresh temp home, pinned to `0700` and installed as the process-wide
/// `~/.fuz` override for the test body. The returned `TempDir` must outlive it.
///
/// The mode is **set**, not inherited — `tempfile::tempdir()` creates at the std
/// default `0o777` masked by the process umask, and a world-writable home is
/// refused by the install paths below. Same reasoning as `signed_trust.rs`.
fn fresh_home() -> tempfile::TempDir {
    let home = tempfile::tempdir().unwrap();
    std::fs::set_permissions(
        home.path(),
        std::fs::Permissions::from_mode(SECURE_DIR_MODE),
    )
    .unwrap();
    fuz_home::set_fuz_home_override_for_testing(home.path());
    home
}

/// A deterministic signing key the test trusts via the anchor.
fn trusted_key() -> SigningKey {
    SigningKey::from_bytes(&[11u8; 32])
}

/// Reset the trust anchor to exactly `key` (called under `SERIAL`).
fn trust_only(key: &SigningKey) {
    fuz_crypto::clear_trusted_keys_for_testing();
    fuz_crypto::add_trusted_key_for_testing(&key.verifying_key());
}

/// Build a fuz-only self artifact on disk (binary + matching meta.json) for the
/// publish flow.
fn make_self_artifact(dir: &Path, version: &str, content: &[u8]) -> ArtifactMeta {
    std::fs::write(dir.join("fuz"), content).unwrap();
    let outputs = ArtifactOutputs {
        fuz: ContentHash::blake3(content),
    };
    let meta = ArtifactMeta::new_remote(outputs.content_hash(), version.to_string(), outputs);
    meta.write(dir).unwrap();
    meta
}

/// The `SSH_TEST_TARGET` root with a per-pid, per-tag subpath, so a run never
/// collides with the `fuz_storage` round-trip test or a parallel invocation
/// (and each test's remote tree is independently cleanable). Returns `None` when
/// `SSH_TEST_TARGET` is unset — the caller skips.
fn ssh_target(tag: &str) -> Option<String> {
    let base = std::env::var("SSH_TEST_TARGET").ok()?;
    Some(format!(
        "{}/signed-{}-{tag}",
        base.trim_end_matches('/'),
        std::process::id()
    ))
}

/// Best-effort remote cleanup: list every published key under the test's root
/// and delete it. The ssh backend leaves the (now-empty) dirs behind, which the
/// scratch path tolerates; this keeps the file tree from accumulating across
/// reruns.
async fn cleanup(backend: &StorageBackend) {
    if let Ok(keys) = backend.list("").await {
        for key in keys {
            let _ = backend.delete(&key).await;
        }
    }
}

/// Per-tool artifact, full round trip over `ssh://`: `publish_tool` (signs +
/// `scp`s the tarball) → `install_tool` (resolves latest over `ssh`, verifies the
/// signature, `scp`s + extracts the tarball, links into the temp `~/.fuz/bin`) →
/// `verify_installed_tool` re-hashes clean → a second install is a verified cache
/// hit. The `fuz tool install <name>` deploy loop, end to end across the wire.
#[tokio::test]
#[ignore = "requires an SSH host (set SSH_TEST_TARGET)"]
async fn publish_then_install_tool_over_ssh_end_to_end() {
    let _serial = SERIAL.lock().await;
    let Some(target) = ssh_target("tool") else {
        eprintln!("SSH_TEST_TARGET unset; skipping ssh signed-install test");
        return;
    };
    let backend = parse_storage(&target).expect("should parse ssh:// target");

    let key = trusted_key();
    trust_only(&key);

    let home = fresh_home();

    let bin_dir = tempfile::tempdir().unwrap();
    let bin_path = bin_dir.path().join("fuzf");
    let content: &[u8] = &test_stubs::host(b"fuzf binary bytes -- e2e ssh tool");
    std::fs::write(&bin_path, content).unwrap();

    // Sign + publish over scp/ssh.
    publish_tool(
        &backend,
        "fuzf",
        "0.1.0",
        &[("fuzf".to_string(), bin_path.clone())],
        &key,
        &PublishOptions::default(),
    )
    .await
    .expect("publish_tool over ssh must succeed");

    // Fetch back over ssh: real signature + blake3 verify, extract, link.
    let result = install_tool(&backend, "fuzf", &ToolInstallOptions::default())
        .await
        .expect("install_tool over ssh must succeed end to end");
    assert_eq!(result.name, "fuzf");
    assert_eq!(result.version, "0.1.0");
    assert_eq!(result.outcome, ToolInstallOutcome::Installed);
    assert!(result.install_dir.starts_with(home.path()));
    assert_eq!(result.binaries, vec!["fuzf".to_string()]);
    verify_installed_tool("fuzf").expect("verify_installed_tool must re-hash clean");

    // Second install: same content hash present and already current → re-verify +
    // relink onto itself, the one genuine no-op.
    let again = install_tool(&backend, "fuzf", &ToolInstallOptions::default())
        .await
        .unwrap();
    assert_eq!(again.outcome, ToolInstallOutcome::AlreadyCurrent);
    assert_eq!(again.content_hash, result.content_hash);

    cleanup(&backend).await;
    fuz_home::clear_fuz_home_override_for_testing();
    fuz_crypto::clear_trusted_keys_for_testing();
    println!("ssh signed tool install test passed");
}

/// Self artifact, full round trip over `ssh://`: `publish_artifact` (signs +
/// `scp`s the tarball) → `fetch_latest_manifest` (the read-only `fuz self upgrade
/// --check` seam: resolve + download + signature-verify, install nothing) →
/// `fetch_latest` (download + verify + extract into the temp home) → second fetch
/// is a verified cache hit. The `fuz self upgrade --storage ssh://…` deploy loop.
#[tokio::test]
#[ignore = "requires an SSH host (set SSH_TEST_TARGET)"]
async fn publish_then_fetch_self_over_ssh_end_to_end() {
    let _serial = SERIAL.lock().await;
    let Some(target) = ssh_target("self") else {
        eprintln!("SSH_TEST_TARGET unset; skipping ssh signed-self test");
        return;
    };
    let backend = parse_storage(&target).expect("should parse ssh:// target");

    let key = trusted_key();
    trust_only(&key);

    let home = fresh_home();

    let artifact_dir = tempfile::tempdir().unwrap();
    let content: &[u8] = &test_stubs::host(b"fuz binary bytes -- e2e ssh self artifact");
    let meta = make_self_artifact(artifact_dir.path(), "0.6.0", content);
    publish_artifact(
        &backend,
        &meta,
        artifact_dir.path(),
        &key,
        &PublishOptions::default(),
    )
    .await
    .expect("publish_artifact over ssh must succeed");

    // `fuz self upgrade --check` seam: resolve + verify the signed latest manifest
    // over ssh, mutating nothing under ~/.fuz.
    let manifest = fetch_latest_manifest(&backend)
        .await
        .expect("fetch_latest_manifest over ssh must resolve + verify");
    assert_eq!(manifest.version, "0.6.0");
    assert!(
        manifest.tool.is_none(),
        "the self manifest declares no tool"
    );
    assert!(
        !home.path().join("artifacts").exists(),
        "a read-only --check must not create the artifacts dir"
    );

    // Full self install: fetch + verify + extract the scp'd tarball into the home.
    let result = fetch_latest(&backend, &FetchOptions::default())
        .await
        .expect("fetch_latest over ssh must succeed end to end");
    assert_eq!(result.version, "0.6.0");
    assert!(!result.cache_hit);
    assert!(result.artifact_dir.starts_with(home.path()));
    assert_eq!(
        std::fs::read(result.artifact_dir.join("fuz")).unwrap(),
        content,
        "the extracted fuz binary must match the published bytes"
    );

    // Second fetch: verified cache hit.
    let again = fetch_latest(&backend, &FetchOptions::default())
        .await
        .unwrap();
    assert!(again.cache_hit);
    assert_eq!(again.content_hash, result.content_hash);

    cleanup(&backend).await;
    fuz_home::clear_fuz_home_override_for_testing();
    fuz_crypto::clear_trusted_keys_for_testing();
    println!("ssh signed self fetch test passed");
}
