//! Tests for the artifact module

// Test sizes are known-bounded literals; u64→usize is safe here.
#![allow(clippy::cast_possible_truncation)]

use super::error::ArtifactError;
use super::hash::hash_binary;
use super::history::History;
use super::ops::find_artifact;
use super::types::{
    ArtifactInputs, ArtifactMeta, ArtifactOutputs, ArtifactSource, RUSTFLAGS_ENV_VARS,
    compute_input_hash, content_hash_from_binaries,
};
use super::{
    CONTENT_HASH_PREFIX, FULL_HASH_LENGTH, MAX_HISTORY_ENTRIES, MAX_META_SIZE, META_FILE,
    SELF_BINARIES, SHORT_COMMIT_LENGTH, SHORT_HASH_LEN, is_self_binary_name,
};
use fuz_crypto::{ContentHash, HashAlgo};
use std::collections::BTreeMap;
use std::fs;

#[cfg(target_os = "linux")]
use super::hash::validate_and_hash_binary;
use super::platform::test_stubs::{self, ElfStub, host_target};
use super::platform::{Arch, Libc, ReleaseTarget};

//
// Reserved binary names
//

/// The comparison every reserved-name refusal shares: a self binary's name
/// in any ASCII case, and nothing else — not a longer or shorter name, and
/// not one that differs by a non-ASCII character.
#[test]
fn is_self_binary_name_ignores_ascii_case_only() {
    for name in SELF_BINARIES {
        assert!(is_self_binary_name(name), "{name}");
        assert!(is_self_binary_name(&name.to_ascii_uppercase()), "{name}");
    }
    for reserved in ["fuz", "Fuz", "fUz", "fuZ", "FUZ"] {
        assert!(is_self_binary_name(reserved), "{reserved}");
    }
    for free in ["fuzd", "Fuzd", "fu", "", "fuz ", " fuz", "fuz.", "zap"] {
        assert!(!is_self_binary_name(free), "{free:?}");
    }
    // Fullwidth letters, and a combining mark after the name: other names.
    for free in ["\u{ff46}\u{ff55}\u{ff5a}", "\u{ff26}uz", "fuz\u{301}"] {
        assert!(!is_self_binary_name(free), "{free:?}");
    }
}

//
// Test helpers
//

/// Build a blake3 `ContentHash` from a bare-hex string (test fixtures).
fn ch(hex: &str) -> ContentHash {
    ContentHash::from_hex(HashAlgo::Blake3, hex).unwrap()
}

fn test_inputs() -> ArtifactInputs {
    test_inputs_with(
        "abc123def456789012345678901234567890abcd",
        None,
        "rustc 1.75.0",
        "x86_64-unknown-linux-gnu",
    )
}

/// Every rustflags variable unset, as `ArtifactInputs::collect` passes them
/// when none is in the environment.
fn unset_rustflags() -> Vec<(&'static str, Option<&'static [u8]>)> {
    RUSTFLAGS_ENV_VARS
        .iter()
        .map(|name| (*name, None))
        .collect()
}

fn test_inputs_with(commit: &str, diff: Option<&str>, rustc: &str, target: &str) -> ArtifactInputs {
    let input_hash = compute_input_hash(commit, diff, rustc, target, &unset_rustflags());
    ArtifactInputs {
        input_hash,
        git_commit: commit.to_string(),
        git_diff_hash: diff.map(String::from),
        rustc_version: rustc.to_string(),
        target: target.to_string(),
    }
}

fn test_outputs() -> ArtifactOutputs {
    ArtifactOutputs {
        fuz: ch(&"a".repeat(64)),
    }
}

//
// Content hash stability - CRITICAL TEST
//

/// The pinned self-artifact content hash for `fuz = "a" * 64`.
///
/// A stable on-disk and on-wire address: every published self artifact is named
/// by `ArtifactOutputs::content_hash`, and `meta.json` integrity re-derives it. Changing
/// it orphans every existing artifact and breaks release verification.
const PINNED_SELF_CONTENT_HASH: &str =
    "v1-ac17a08631ed8b77dcf31c5670b7e8b9896fff9ceb7b9fdc17bc15ef63b207d3";

#[test]
fn content_hash_is_stable() {
    // This test MUST NOT be updated casually.
    // Changing expected output invalidates all existing artifacts
    // and breaks signature verification.
    //
    // The self artifact is fuz-only. This value is unchanged from the
    // pre-split-install fuz-only/bootstrap artifact, so existing artifacts
    // stay addressable across the carve.
    let outputs = ArtifactOutputs {
        fuz: ch(&"a".repeat(64)),
    };
    let hash = outputs.content_hash();

    // Input: "fuz:aaa...64" (no trailing newline)
    assert_eq!(hash, PINNED_SELF_CONTENT_HASH);
}

#[test]
fn content_hash_matches_the_general_binary_set_algorithm() {
    // `ArtifactOutputs::content_hash` is the one-entry case of
    // `content_hash_from_binaries` and delegates to it. Pin *both* against the
    // same literal so the delegation can't drift silently: a change to the
    // general algorithm that would re-address every published self artifact
    // fails here, on the value, not merely on the two sides agreeing with each
    // other.
    let fuz = ch(&"a".repeat(64));
    let outputs = ArtifactOutputs { fuz: fuz.clone() };

    let general = content_hash_from_binaries(&BTreeMap::from([("fuz".to_string(), fuz)]));

    assert_eq!(general, PINNED_SELF_CONTENT_HASH);
    assert_eq!(outputs.content_hash(), general);
}

#[test]
fn content_hash_is_deterministic() {
    let outputs = test_outputs();

    let hash1 = outputs.content_hash();
    let hash2 = outputs.content_hash();

    assert_eq!(hash1, hash2);
    assert!(hash1.starts_with(CONTENT_HASH_PREFIX));
}

#[test]
fn content_hash_differs_with_different_fuz() {
    let outputs1 = ArtifactOutputs {
        fuz: ch(&"a".repeat(64)),
    };
    let outputs2 = ArtifactOutputs {
        fuz: ch(&"c".repeat(64)),
    };

    assert_ne!(outputs1.content_hash(), outputs2.content_hash());
}

//
// Input hash determinism - important for caching
//

#[test]
fn input_hash_is_deterministic() {
    let inputs = test_inputs();

    let hash1 = &inputs.input_hash;
    let hash2 = compute_input_hash(
        &inputs.git_commit,
        inputs.git_diff_hash.as_deref(),
        &inputs.rustc_version,
        &inputs.target,
        &unset_rustflags(),
    );

    assert_eq!(hash1, &hash2);
    assert_eq!(hash1.len(), FULL_HASH_LENGTH);
}

/// The same source built with other rustc flags is another build: each
/// variable, and set-but-empty against unset, is its own input.
#[test]
fn input_hash_differs_with_rustflags() {
    let hash = |rustflags: &[(&str, Option<&[u8]>)]| {
        compute_input_hash(
            "abc123def456789012345678901234567890abcd",
            None,
            "rustc 1.75.0",
            "x86_64-unknown-linux-gnu",
            rustflags,
        )
    };
    let mut seen = vec![hash(&unset_rustflags())];
    for i in 0..RUSTFLAGS_ENV_VARS.len() {
        for value in [&b""[..], b"-Ctarget-cpu=native"] {
            let mut flags = unset_rustflags();
            flags[i].1 = Some(value);
            let h = hash(&flags);
            assert!(!seen.contains(&h), "{} = {value:?}", RUSTFLAGS_ENV_VARS[i]);
            seen.push(h);
        }
    }
    // A value's bytes cannot run into the next record.
    let a = [("A", Some(&b"x\nB=y"[..])), ("B", None)];
    let b = [("A", Some(&b"x"[..])), ("B", Some(&b"y"[..]))];
    assert_ne!(hash(&a), hash(&b));
}

#[test]
fn input_hash_differs_with_different_commit() {
    let inputs1 = test_inputs();
    let inputs2 = test_inputs_with(
        "def456789012345678901234567890abcdabc123",
        None,
        "rustc 1.75.0",
        "x86_64-unknown-linux-gnu",
    );

    assert_ne!(inputs1.input_hash, inputs2.input_hash);
}

#[test]
fn input_hash_differs_with_dirty_state() {
    let clean = test_inputs();
    let dirty = test_inputs_with(
        "abc123def456789012345678901234567890abcd",
        Some("somehash"),
        "rustc 1.75.0",
        "x86_64-unknown-linux-gnu",
    );

    assert_ne!(clean.input_hash, dirty.input_hash);
    assert!(!clean.is_dirty());
    assert!(dirty.is_dirty());
}

#[test]
fn input_hash_differs_with_different_rustc() {
    let inputs1 = test_inputs();
    let inputs2 = test_inputs_with(
        "abc123def456789012345678901234567890abcd",
        None,
        "rustc 1.76.0",
        "x86_64-unknown-linux-gnu",
    );

    assert_ne!(inputs1.input_hash, inputs2.input_hash);
}

#[test]
fn input_hash_differs_with_different_target() {
    let inputs1 = test_inputs();
    let inputs2 = test_inputs_with(
        "abc123def456789012345678901234567890abcd",
        None,
        "rustc 1.75.0",
        "aarch64-apple-darwin",
    );

    assert_ne!(inputs1.input_hash, inputs2.input_hash);
}

//
// short_commit edge cases
//

#[test]
fn short_commit_normal() {
    let inputs = test_inputs();
    assert_eq!(inputs.short_commit(), "abc123d");
    assert_eq!(inputs.short_commit().len(), SHORT_COMMIT_LENGTH);
}

#[test]
fn short_commit_short_input() {
    let inputs = test_inputs_with("abc", None, "rustc 1.75.0", "x86_64-unknown-linux-gnu");
    assert_eq!(inputs.short_commit(), "abc");
}

#[test]
fn short_commit_empty_input() {
    let inputs = test_inputs_with("", None, "rustc 1.75.0", "x86_64-unknown-linux-gnu");
    assert_eq!(inputs.short_commit(), "");
}

//
// Metadata serialization
//

#[test]
fn artifact_meta_roundtrip() {
    let inputs = test_inputs_with(
        "abc123def456789012345678901234567890abcd",
        Some("diffhash123"),
        "rustc 1.75.0",
        "x86_64-unknown-linux-gnu",
    );

    let outputs = ArtifactOutputs {
        fuz: ContentHash::blake3(b"fuzhash123"),
    };

    let meta = ArtifactMeta::new("0.1.0".to_string(), inputs.clone(), outputs.clone());

    let json = serde_json::to_string(&meta).unwrap();
    let parsed: ArtifactMeta = serde_json::from_str(&json).unwrap();

    assert_eq!(parsed.hash, meta.hash);
    assert_eq!(parsed.version, meta.version);
    assert_eq!(parsed.source, ArtifactSource::Local);
    let parsed_inputs = parsed.inputs.expect("local build should have inputs");
    assert_eq!(parsed_inputs.git_commit, inputs.git_commit);
    assert_eq!(parsed_inputs.git_diff_hash, inputs.git_diff_hash);
    assert_eq!(parsed.outputs.fuz, outputs.fuz);
}

#[test]
fn artifact_meta_requires_source() {
    // A meta.json without `source` is refused, not read as `local`.
    let json = r#"{
        "hash": "v1-8377df8a3806026a3767542a164fbb394343ba09229861ae442bfa8ded71f742",
        "version": "0.1.0",
        "created_at": "2025-01-15T10:30:00Z",
        "inputs": {
            "input_hash": "abc123",
            "git_commit": "abc123def456789012345678901234567890abcd",
            "git_diff_hash": null,
            "rustc_version": "rustc 1.75.0",
            "target": "x86_64-unknown-linux-gnu"
        },
        "outputs": {
            "fuz": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "fuzd": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        }
    }"#;

    let err = serde_json::from_str::<ArtifactMeta>(json).unwrap_err();
    assert!(err.to_string().contains("missing field `source`"), "{err}");
}

#[test]
fn artifact_meta_round_trip_local() {
    let inputs = test_inputs();
    let outputs = test_outputs();
    let meta = ArtifactMeta::new("0.1.0".to_string(), inputs, outputs.clone());

    let json = serde_json::to_string_pretty(&meta).unwrap();
    let parsed: ArtifactMeta = serde_json::from_str(&json).unwrap();

    assert!(parsed.inputs.is_some());
    assert_eq!(parsed.source, ArtifactSource::Local);
    assert_eq!(parsed.hash, outputs.content_hash());
}

#[test]
fn artifact_meta_round_trip_remote() {
    let outputs = test_outputs();
    let hash = outputs.content_hash();
    let meta = ArtifactMeta::new_remote(hash.clone(), "0.2.0".to_string(), outputs);

    let json = serde_json::to_string_pretty(&meta).unwrap();
    let parsed: ArtifactMeta = serde_json::from_str(&json).unwrap();

    assert!(parsed.inputs.is_none());
    assert_eq!(parsed.source, ArtifactSource::Remote);
    assert_eq!(parsed.hash, hash);
    // Wire format: local artifacts also emit "source": "local" explicitly.
    assert!(json.contains(r#""source": "remote""#));
}

#[test]
fn artifact_meta_local_wire_emits_source() {
    let inputs = test_inputs();
    let outputs = test_outputs();
    let meta = ArtifactMeta::new("0.1.0".to_string(), inputs, outputs);
    let json = serde_json::to_string_pretty(&meta).unwrap();
    // Always emit: a fresh local meta.json contains "source": "local".
    assert!(
        json.contains(r#""source": "local""#),
        "expected source field in local meta.json, got: {json}"
    );
}

#[test]
fn artifact_meta_hash_is_content_derived() {
    let inputs = test_inputs();
    let outputs = test_outputs();

    let meta = ArtifactMeta::new("0.1.0".to_string(), inputs, outputs.clone());

    // Hash should be derived from outputs, not inputs
    assert_eq!(meta.hash, outputs.content_hash());
    assert!(meta.hash.starts_with(CONTENT_HASH_PREFIX));
}

//
// Hash prefix matching
//

#[test]
fn prefix_too_short_error() {
    let result = find_artifact("abc123"); // 6 chars, need 8
    assert!(matches!(
        result,
        Err(ArtifactError::PrefixTooShort {
            given: 6,
            minimum: 8
        })
    ));
}

#[test]
fn normalize_prefix_strips_v1() {
    // Test through the public API by checking error messages
    let result1 = find_artifact("abc123de");
    let result2 = find_artifact("v1-abc123de");

    // Both should fail with NotFound (not PrefixTooShort), proving normalization worked
    assert!(matches!(result1, Err(ArtifactError::NotFound(_))));
    assert!(matches!(result2, Err(ArtifactError::NotFound(_))));
}

#[test]
fn short_hash_returns_8_chars_after_prefix() {
    let inputs = test_inputs();
    let outputs = test_outputs();

    let meta = ArtifactMeta::new("0.1.0".to_string(), inputs, outputs);

    // short_hash returns 8 chars AFTER the v1- prefix
    assert_eq!(meta.short_hash().len(), SHORT_HASH_LEN);
    // The full hash starts with v1- but short_hash doesn't include it
    assert!(meta.hash.starts_with(CONTENT_HASH_PREFIX));
    assert!(!meta.short_hash().starts_with("v1-"));
}

//
// Binary hashing
//

#[test]
fn hash_binary_deterministic() {
    use std::io::Write;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test_binary");

    let mut file = fs::File::create(&path).unwrap();
    file.write_all(b"test content for hashing").unwrap();
    drop(file);

    let hash1 = hash_binary(&path).unwrap();
    let hash2 = hash_binary(&path).unwrap();

    assert_eq!(hash1, hash2);
    assert_eq!(hash1.to_hex().len(), FULL_HASH_LENGTH);
}

#[test]
fn hash_binary_differs_with_different_content() {
    use std::io::Write;

    let dir = tempfile::tempdir().unwrap();

    let path1 = dir.path().join("file1");
    let mut file1 = fs::File::create(&path1).unwrap();
    file1.write_all(b"content A").unwrap();
    drop(file1);

    let path2 = dir.path().join("file2");
    let mut file2 = fs::File::create(&path2).unwrap();
    file2.write_all(b"content B").unwrap();
    drop(file2);

    let hash1 = hash_binary(&path1).unwrap();
    let hash2 = hash_binary(&path2).unwrap();

    assert_ne!(hash1, hash2);
}

// Build lock semantics are covered by `file_lock::tests` (which uses
// per-test lock paths for isolation); BuildLock itself is a thin
// FileLock wrapper whose only job is mapping FileLockError to
// ArtifactError variants, exercised end-to-end by `fuz artifact build` smoke
// tests.

//
// History
//

#[test]
fn history_add_prepends() {
    let mut history = History::default();

    history.add("hash1".to_string(), "0.1.0".to_string(), None);
    history.add(
        "hash2".to_string(),
        "0.2.0".to_string(),
        Some("hash1".to_string()),
    );

    assert_eq!(history.entries.len(), 2);
    assert_eq!(history.entries[0].hash, "hash2");
    assert_eq!(history.entries[1].hash, "hash1");
}

#[test]
fn history_previous_returns_second_entry() {
    let mut history = History::default();

    history.add("hash1".to_string(), "0.1.0".to_string(), None);
    assert!(history.previous().is_none());

    history.add(
        "hash2".to_string(),
        "0.2.0".to_string(),
        Some("hash1".to_string()),
    );
    assert_eq!(history.previous(), Some("hash1"));
}

#[test]
fn history_truncates_at_max() {
    let mut history = History::default();

    for i in 0..150 {
        history.add(format!("hash{i}"), "0.1.0".to_string(), None);
    }

    assert_eq!(history.entries.len(), MAX_HISTORY_ENTRIES);
    assert_eq!(history.entries[0].hash, "hash149"); // newest
}

//
// Input hash stability - CRITICAL TEST
//

#[test]
fn input_hash_is_stable() {
    // This test MUST NOT be updated casually.
    // Changing expected output causes cache misses for all users.
    // The input hash format is documented in docs/artifacts.md.
    let inputs = test_inputs_with(
        "abc123def456789012345678901234567890abcd",
        None,
        "rustc 1.75.0",
        "x86_64-unknown-linux-gnu",
    );

    // Input: "abc123...abcd\n\nrustc 1.75.0\nx86_64-unknown-linux-gnu" (empty
    // between the first two newlines for a clean repo), then each rustflags
    // variable unset: "\nCARGO_ENCODED_RUSTFLAGS!\nRUSTFLAGS!\nCARGO_BUILD_RUSTFLAGS!"
    assert_eq!(
        inputs.input_hash,
        "ad9559e2dc23ebeae9419cd24a144e49975f35781a708f23891c5bc218e9eff3"
    );
}

#[test]
fn input_hash_is_stable_dirty() {
    // Verify dirty repo hash is also stable
    let inputs = test_inputs_with(
        "abc123def456789012345678901234567890abcd",
        Some("dirtyhash123"),
        "rustc 1.75.0",
        "x86_64-unknown-linux-gnu",
    );

    // Input: "abc123...abcd\ndirtyhash123\nrustc 1.75.0\nx86_64-unknown-linux-gnu",
    // then the unset rustflags records as above
    assert_eq!(
        inputs.input_hash,
        "343df0963173250c8d9acb460d9f4d6069b768bace2f8d5ef7a861315765d616"
    );
}

//
// Binary validation - security critical
//

#[test]
#[cfg(target_os = "linux")]
fn validate_and_hash_rejects_symlink() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("target");
    let link = dir.path().join("link");

    // Create a real file and a symlink to it
    fs::write(&target, "content").unwrap();
    symlink(&target, &link).unwrap();

    // Attempt to validate the symlink
    let result = validate_and_hash_binary(&link, "test", host_target());
    assert!(
        matches!(result, Err(ArtifactError::InvalidBinary { name, reason })
        if name == "test" && reason.contains("symlink"))
    );
}

#[test]
#[cfg(target_os = "linux")]
fn validate_and_hash_rejects_too_small() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tiny");

    // Create file smaller than MIN_BINARY_SIZE (1KB)
    fs::write(&path, vec![0u8; 512]).unwrap();

    let result = validate_and_hash_binary(&path, "tiny", host_target());
    assert!(
        matches!(result, Err(ArtifactError::InvalidBinary { name, reason })
        if name == "tiny" && reason.contains("too small"))
    );
}

#[test]
#[cfg(target_os = "linux")]
fn validate_and_hash_rejects_too_large() {
    use super::MAX_BINARY_SIZE;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("huge");

    // Create sparse file larger than MAX_BINARY_SIZE (100MB)
    let file = fs::File::create(&path).unwrap();
    file.set_len(MAX_BINARY_SIZE + 1).unwrap();

    let result = validate_and_hash_binary(&path, "huge", host_target());
    assert!(
        matches!(result, Err(ArtifactError::InvalidBinary { name, reason })
        if name == "huge" && reason.contains("too large"))
    );
}

#[test]
#[cfg(target_os = "linux")]
fn validate_and_hash_rejects_directory() {
    let dir = tempfile::tempdir().unwrap();
    let subdir = dir.path().join("subdir");
    fs::create_dir(&subdir).unwrap();

    let result = validate_and_hash_binary(&subdir, "subdir", host_target());
    assert!(
        matches!(result, Err(ArtifactError::InvalidBinary { name, reason })
        if name == "subdir" && reason.contains("not a regular file"))
    );
}

#[test]
fn validate_and_hash_rejects_a_non_executable() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("not_elf");

    // Valid size, but no executable header.
    let mut content = vec![0u8; 2048];
    content[0..4].copy_from_slice(b"FAKE");
    fs::write(&path, content).unwrap();

    let result = validate_and_hash_binary(&path, "not_elf", host_target());
    assert!(
        matches!(&result, Err(ArtifactError::InvalidBinary { name, reason })
        if name == "not_elf" && reason == "not an ELF or Mach-O executable"),
        "{result:?}"
    );
}

/// A built binary for another target than the build's is refused: a dynamic
/// one for the other libc, or one for another architecture or OS.
#[test]
fn validate_and_hash_rejects_a_binary_for_another_target() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("fuz");
    let gnu = ReleaseTarget::linux(Arch::X86_64, Libc::Gnu);
    for other in [
        ReleaseTarget::linux(Arch::X86_64, Libc::Musl),
        ReleaseTarget::linux(Arch::Aarch64, Libc::Gnu),
        ReleaseTarget::darwin(Arch::X86_64),
    ] {
        fs::write(&path, test_stubs::for_target(other, b"")).unwrap();
        let result = validate_and_hash_binary(&path, "fuz", gnu);
        assert!(
            matches!(&result, Err(ArtifactError::InvalidBinary { reason, .. })
                if reason.ends_with("not a x86_64-unknown-linux-gnu executable")),
            "{other}: {result:?}"
        );
    }
    // A static build of the target's architecture passes: the build's target
    // is named, not guessed.
    fs::write(&path, ElfStub::static_pie(Arch::X86_64).build(b"")).unwrap();
    validate_and_hash_binary(&path, "fuz", gnu).unwrap();
}

#[test]
fn fuz_only_local_hash_matches_bootstrap() {
    // A fuz-only Local artifact and a Bootstrap artifact built from the same
    // fuz bytes canonicalize to the same content hash, so `create_artifact`
    // dedups them onto one dir. This collision is the accepted edge case of the
    // fuz-only self artifact — pin the equivalence so it stays intentional, not a surprise.
    let fuz = ch(&"a".repeat(64));
    let local = ArtifactOutputs { fuz: fuz.clone() };
    let bootstrap = ArtifactMeta::new_bootstrap("0.1.0".to_string(), fuz);
    assert_eq!(local.content_hash(), bootstrap.hash);
}

#[test]
fn validate_and_hash_accepts_a_host_executable() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("valid_elf");
    fs::write(&path, test_stubs::host(b"")).unwrap();

    let result = validate_and_hash_binary(&path, "valid_elf", host_target());
    assert_eq!(result.unwrap().to_hex().len(), FULL_HASH_LENGTH);
}

//
// Artifact operations
//
// Note: the store ops that resolve paths through get_artifacts_dir() —
// list_artifacts(), switch_current(), get_current_artifact(),
// cleanup_incomplete(), find_by_inputs(), find_artifact(),
// and the switch history — are covered by the tests/local_store.rs integration
// suite (alongside tests/round_trip.rs), which redirect ~/.fuz in-process via
// the fuz_home/test_home_override dev-dep feature (no unsafe set_var needed).
// The unit tests below stay focused on the home-agnostic helpers.

#[test]
fn meta_read_verifies_integrity() {
    let dir = tempfile::tempdir().unwrap();
    let inputs = test_inputs();
    let outputs = test_outputs();
    let meta = ArtifactMeta::new("0.1.0".to_string(), inputs, outputs);

    // Write valid meta.json
    meta.write(dir.path()).unwrap();

    // Reading should succeed and verify integrity
    let loaded = ArtifactMeta::read(dir.path()).unwrap();
    assert_eq!(loaded.hash, meta.hash);
}

#[test]
fn meta_read_detects_corrupt_hash() {
    use std::io::Write;

    let dir = tempfile::tempdir().unwrap();
    let inputs = test_inputs();
    let outputs = test_outputs();
    let mut meta = ArtifactMeta::new("0.1.0".to_string(), inputs, outputs);

    // Corrupt the hash
    meta.hash = "v1-badhash0000000000000000000000000000000000000000000000000000000".to_string();

    // Write corrupt meta.json manually
    let path = dir.path().join(META_FILE);
    let content = serde_json::to_string_pretty(&meta).unwrap();
    let mut file = fs::File::create(&path).unwrap();
    file.write_all(content.as_bytes()).unwrap();

    // Reading should fail integrity check
    let result = ArtifactMeta::read(dir.path());
    assert!(matches!(result, Err(ArtifactError::IntegrityFailed { .. })));
}

#[test]
fn meta_read_rejects_oversized_file() {
    use std::io::Write;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(META_FILE);

    // Create a file larger than MAX_META_SIZE (1MB)
    let mut file = fs::File::create(&path).unwrap();
    let large_content = vec![b' '; (MAX_META_SIZE + 1) as usize];
    file.write_all(&large_content).unwrap();

    let result = ArtifactMeta::read(dir.path());
    assert!(matches!(
        result,
        Err(ArtifactError::MetadataTooLarge { .. })
    ));
}

//
// History edge cases
//

#[test]
fn history_serialization_roundtrip() {
    let mut history = History::default();
    history.add("hash1".to_string(), "0.1.0".to_string(), None);
    history.add(
        "hash2".to_string(),
        "0.2.0".to_string(),
        Some("hash1".to_string()),
    );

    let json = serde_json::to_string(&history).unwrap();
    let parsed: History = serde_json::from_str(&json).unwrap();

    assert_eq!(parsed.entries.len(), 2);
    assert_eq!(parsed.entries[0].hash, "hash2");
    assert_eq!(parsed.entries[0].previous_hash, Some("hash1".to_string()));
    assert_eq!(parsed.entries[1].hash, "hash1");
    assert!(parsed.entries[1].previous_hash.is_none());
}

#[test]
fn history_previous_none_when_single_entry() {
    let mut history = History::default();
    history.add("hash1".to_string(), "0.1.0".to_string(), None);

    assert!(history.previous().is_none());
}

#[test]
fn history_previous_none_when_empty() {
    let history = History::default();
    assert!(history.previous().is_none());
}

//
// Error hints
//

#[test]
fn error_hint_for_common_errors() {
    let err = ArtifactError::NotFound("abc".to_string());
    assert!(err.hint().is_some());
    assert!(err.hint().unwrap().contains("fuz artifact list"));

    // InProgress interpolates the holder pid into an owned hint.
    let err = ArtifactError::InProgress { pid: Some(123) };
    let hint = err.hint().expect("InProgress has a hint");
    assert!(hint.contains("wait"));
    assert!(hint.contains("123"), "interpolates the holder pid");

    let err = ArtifactError::PrefixTooShort {
        given: 4,
        minimum: 8,
    };
    assert!(err.hint().is_some());
    assert!(err.hint().unwrap().contains("8 characters"));

    let err = ArtifactError::AmbiguousPrefix {
        prefix: "abc".to_string(),
        candidates: vec![],
    };
    assert!(err.hint().is_some());

    // Io error should not have a hint
    let err = ArtifactError::Io(std::io::Error::other("test"));
    assert!(err.hint().is_none());
}

/// `is_content_hash` accepts exactly what `content_hash_from_binaries` produces
/// — `v1-` and 64 lowercase hex — and nothing path-shaped.
#[test]
fn is_content_hash_accepts_only_the_v1_form() {
    let real = content_hash_from_binaries(&BTreeMap::from([(
        "fuz".to_string(),
        ContentHash::blake3(b"fuz"),
    )]));
    assert!(super::is_content_hash(&real), "{real}");
    for bad in [
        "../x".to_string(),
        "v1-short".to_string(),
        format!("v1-{}", "A".repeat(64)),
        format!("v1-{}", "a".repeat(65)),
        format!("v1-{}/", "a".repeat(64)),
        format!("v2-{}", "a".repeat(64)),
        "a".repeat(64),
        String::new(),
    ] {
        assert!(!super::is_content_hash(&bad), "{bad:?}");
    }
}
