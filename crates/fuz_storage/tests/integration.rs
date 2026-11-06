//! Integration tests for `fuz_storage`
//!
//! These tests verify that the storage backends work against real services.
//! They are ignored by default and require external services to be running.
//!
//! Run with: `cargo test -p fuz_storage --test integration -- --ignored`

// Test payload sizes are known-bounded; u64→usize is safe here.
#![allow(clippy::cast_possible_truncation)]

use fuz_storage::Storage;
use std::env;

//
// SSH Integration Test
//

/// Round-trip against a real SSH host.
///
/// # Setup
///
/// Requires an SSH host you can reach non-interactively (key/agent auth, host
/// key already in `~/.ssh/known_hosts`). The remote root directory is created on
/// first upload. Point `SSH_TEST_TARGET` at an `ssh://user@host[:port]/path`
/// URI, e.g.:
///
/// ```bash
/// export SSH_TEST_TARGET=ssh://$USER@localhost/tmp/fuz-ssh-test
/// cargo test -p fuz_storage --test integration ssh -- --ignored
/// ```
///
/// # Environment variables
///
/// - `SSH_TEST_TARGET`: `ssh://user@host[:port]/path` root (skips if unset)
#[tokio::test]
#[ignore = "requires an SSH host (set SSH_TEST_TARGET)"]
async fn test_ssh_round_trip() {
    let Ok(target) = env::var("SSH_TEST_TARGET") else {
        eprintln!("SSH_TEST_TARGET unset; skipping SSH integration test");
        return;
    };

    let backend = fuz_storage::parse_storage(&target).expect("should parse ssh:// target");

    let key = format!("fuz-ssh-{}.txt", std::process::id());
    let content = b"Hello from fuz SSH integration test!";

    // 1. Upload (bytes) + exists.
    backend.upload(&key, content).await.expect("should upload");
    assert!(backend.exists(&key).await.expect("should check exists"));

    // 2. Download (bytes) round-trip.
    let got = backend.download(&key).await.expect("should download");
    assert_eq!(got, content, "downloaded bytes should match");

    // 3. Streaming round-trip: upload_file (scp) then download_to_file (scp).
    let dir = env::temp_dir().join(format!("fuz-ssh-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("should create temp dir");
    let src = dir.join("src.bin");
    std::fs::write(&src, content).expect("should write src");
    let stream_key = format!("fuz-ssh-stream-{}.bin", std::process::id());
    backend
        .upload_file(&stream_key, &src)
        .await
        .expect("should upload_file");
    let dest = dir.join("dest.bin");
    let n = backend
        .download_to_file(&stream_key, &dest)
        .await
        .expect("should download_to_file");
    assert_eq!(n as usize, content.len(), "byte count should match");
    assert_eq!(
        std::fs::read(&dest).expect("read dest"),
        content,
        "streamed round-trip content should match"
    );

    // 3b. Interior-slash key (the `tools/zap/latest.json` shape) through the scp
    // path: exercises nested `mkdir -p`, scp of a multi-segment remote path, and
    // the `find -print0` + NUL-split + prefix-strip preserving interior slashes
    // in the returned root-relative key.
    let nested_key = format!("tools/zap/fuz-ssh-{}.json", std::process::id());
    backend
        .upload_file(&nested_key, &src)
        .await
        .expect("should upload_file to a nested key");
    assert!(
        backend.exists(&nested_key).await.expect("should exists"),
        "nested key should exist after upload"
    );
    let nested_dest = dir.join("nested.bin");
    let nn = backend
        .download_to_file(&nested_key, &nested_dest)
        .await
        .expect("should download_to_file from a nested key");
    assert_eq!(nn as usize, content.len(), "nested byte count should match");
    assert_eq!(
        std::fs::read(&nested_dest).expect("read nested dest"),
        content,
        "nested streamed round-trip content should match"
    );

    // 4. Missing key → NotFound.
    backend
        .download_to_file("does-not-exist.bin", &dest)
        .await
        .map_or_else(
            |e| assert!(matches!(e, fuz_storage::StorageError::NotFound { .. })),
            |_| panic!("missing key should be NotFound"),
        );

    // 5. List includes the flat keys (root-relative) and the nested key with its
    // interior slashes intact.
    let listed = backend.list("fuz-ssh-").await.expect("should list");
    assert!(listed.contains(&key), "listing should include {key}");
    assert!(
        listed.contains(&stream_key),
        "listing should include {stream_key}"
    );
    let nested_listed = backend.list("tools/").await.expect("should list nested");
    assert!(
        nested_listed.contains(&nested_key),
        "listing should include the interior-slash key {nested_key}"
    );

    // 6. Delete (idempotent) + gone.
    backend.delete(&key).await.expect("should delete");
    backend.delete(&stream_key).await.expect("should delete");
    backend
        .delete(&nested_key)
        .await
        .expect("should delete nested");
    backend.delete(&key).await.expect("delete is idempotent");
    assert!(!backend.exists(&key).await.expect("should check exists"));
    assert!(
        !backend
            .exists(&nested_key)
            .await
            .expect("should check exists"),
        "nested key should be gone after delete"
    );

    let _ = std::fs::remove_dir_all(&dir);
    println!("SSH integration test passed");
}
