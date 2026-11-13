//! Adversarial test suite for `fuz_release`
//!
//! Tests security-critical behavior with crafted malicious inputs.

// Tests import codec deps (tar/flate2) locally next to their use; the
// scope-hygiene lint adds no value in these test bodies.
#![allow(clippy::items_after_statements)]

use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;

use crate::error::{ManifestError, ReleaseError, TarballError};
use crate::manifest::{
    BinaryHashes, Manifest, ManifestUnsigned, TarballInfo, check_version_safety, current_target,
    validate_tarball_path,
};
use crate::tarball::{
    extract_tarball, verify_binary_hashes, verify_content_hash, verify_tarball_hash,
};
use crate::{MANIFEST_FORMAT_VERSION, MAX_MANIFEST_SIZE, MAX_TOTAL_SIZE};
use fuz_crypto::{ContentHash, HashAlgo};

//
// Test helpers
//

/// Build a blake3 `ContentHash` from a bare-hex string (test fixtures).
fn ch(hex: &str) -> ContentHash {
    ContentHash::from_hex(HashAlgo::Blake3, hex).unwrap()
}

fn test_binaries() -> BinaryHashes {
    let mut h = HashMap::new();
    h.insert("fuz".to_string(), ch(&"a".repeat(64)));
    h
}

fn test_unsigned(version: &str, minimum_version: Option<&str>) -> ManifestUnsigned {
    ManifestUnsigned {
        format: 1,
        version: version.to_string(),
        content_hash: "v1-abc1230000000000000000000000000000000000000000000000000000000000"
            .to_string(),
        target: current_target().to_string(),
        minimum_version: minimum_version.map(String::from),
        tarball: TarballInfo {
            path: "release.tar.gz".to_string(),
            blake3: ContentHash::blake3(b"tarball"),
            size: 1000,
        },
        binaries: test_binaries(),
        tool: None,
    }
}

/// Build a `Manifest` with a placeholder signature. These tests cover
/// parsing/validation/version-safety/tarball security — none verify the
/// signature — so the signature value is irrelevant. Real signing +
/// signature-verification round-trips live in `fuz_sign`.
fn build_manifest(unsigned: ManifestUnsigned) -> Manifest {
    Manifest::from_parts(
        unsigned,
        fuz_crypto::Signature {
            format: fuz_crypto::SIGNATURE_FORMAT_VERSION,
            public_key: String::new(),
            algorithm: fuz_crypto::SignatureAlgorithm::Ed25519,
            signed_at: "2025-01-15T10:30:00Z".to_string(),
            sig: String::new(),
        },
    )
}

fn test_manifest(version: &str, minimum_version: Option<&str>) -> Manifest {
    build_manifest(test_unsigned(version, minimum_version))
}

/// A manifest declaring two binaries, `fuz` and `fuzd`, for the extraction
/// tests that exercise a multi-binary bill of materials. `extract_tarball`
/// takes the manifest as already validated, so the fixture skips `validate`
/// (which would refuse `fuzd` in a self manifest).
fn two_binary_manifest() -> Manifest {
    let mut unsigned = test_unsigned("0.3.0", None);
    unsigned
        .binaries
        .insert("fuzd".to_string(), ch(&"b".repeat(64)));
    build_manifest(unsigned)
}

/// Create a minimal valid gzipped tarball containing the given files
fn create_test_tarball(files: &[(&str, &[u8])]) -> Vec<u8> {
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use tar::Builder;

    let mut tar_data = Vec::new();
    {
        let mut builder = Builder::new(&mut tar_data);
        for (name, content) in files {
            let mut header = tar::Header::new_gnu();
            header.set_path(name).expect("set path");
            header.set_size(content.len() as u64);
            header.set_mode(0o755);
            header.set_cksum();
            builder.append(&header, &content[..]).expect("append");
        }
        builder.finish().expect("finish");
    }

    let mut gz_data = Vec::new();
    {
        let mut encoder = GzEncoder::new(&mut gz_data, Compression::default());
        encoder.write_all(&tar_data).expect("write");
        encoder.finish().expect("finish");
    }
    gz_data
}

//
// Manifest format validation tests
//

#[test]
fn reject_manifest_unsupported_format_version() {
    let mut unsigned = test_unsigned("0.3.0", None);
    unsigned.format = MANIFEST_FORMAT_VERSION + 1;
    let json = serde_json::to_vec(&build_manifest(unsigned)).unwrap();

    let result = Manifest::from_json(&json);
    assert!(
        matches!(result, Err(ManifestError::UnsupportedFormat(v)) if v == MANIFEST_FORMAT_VERSION + 1)
    );
}

#[test]
fn reject_manifest_unknown_fields() {
    // Manifests with extra fields should be rejected (deny_unknown_fields)
    let json = br#"{
        "format": 1,
        "version": "0.3.0",
        "content_hash": "v1-abc1230000000000000000000000000000000000000000000000000000000000",
        "target": "x86_64-unknown-linux-gnu",
        "minimum_version": null,
        "tarball": {"path": "release.tar.gz", "blake3": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "size": 1000},
        "binaries": {"fuz": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "fuzd": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
        "signature": {
            "format": 2,
            "public_key": "AAAA",
            "algorithm": "ed25519",
            "signed_at": "2025-01-15T10:30:00Z",
            "sig": "AAAA"
        },
        "extra_field": "malicious"
    }"#;

    let result = Manifest::from_json(json);
    assert!(
        matches!(result, Err(ManifestError::Parse(_))),
        "expected Parse error for manifest with extra field"
    );
}

/// A repeated binary name is refused at parse. Read as a plain map, the last
/// of the two would win: the signature verifies over that one, while a reader
/// keeping the first — the documented `grep` of the manifest among them —
/// takes the digest the parse discarded.
#[test]
fn reject_manifest_repeating_a_binary_name() {
    let json = serde_json::to_string(&test_manifest("0.3.0", None)).unwrap();
    let first = ch(&"e".repeat(64)).to_hex();
    for (name, repeated) in [
        // The repeat ahead of the real entry, and after it.
        (
            "first",
            json.replacen(
                "\"binaries\":{",
                &format!("\"binaries\":{{\"fuz\":\"{first}\","),
                1,
            ),
        ),
        (
            "last",
            json.replacen(
                &format!("\"fuz\":\"{}\"", "a".repeat(64)),
                &format!("\"fuz\":\"{}\",\"fuz\":\"{first}\"", "a".repeat(64)),
                1,
            ),
        ),
    ] {
        assert_ne!(
            repeated, json,
            "{name}: the fixture must change the document"
        );
        let error = Manifest::from_json(repeated.as_bytes()).unwrap_err();
        assert!(
            matches!(&error, ManifestError::Parse(_))
                && error.to_string().contains("duplicate key \"fuz\""),
            "{name}: {error}"
        );
    }
}

/// A digest has one spelling, lowercase, as the publisher writes it: an
/// uppercase binary or tarball digest is refused at parse, not read as the
/// same hash.
#[test]
fn reject_manifest_uppercase_hex() {
    let json = serde_json::to_string(&test_manifest("0.3.0", None)).unwrap();
    let tarball = ContentHash::blake3(b"tarball").to_hex();
    for (name, upper) in [
        ("binary", json.replacen(&"a".repeat(64), &"A".repeat(64), 1)),
        (
            "tarball",
            json.replacen(&tarball, &tarball.to_ascii_uppercase(), 1),
        ),
    ] {
        assert_ne!(upper, json, "{name}: the fixture must change the document");
        let error = Manifest::from_json(upper.as_bytes()).unwrap_err();
        assert!(
            matches!(&error, ManifestError::Parse(_))
                && error
                    .to_string()
                    .contains("expected 64 lowercase hex characters for blake3"),
            "{name}: {error}"
        );
    }
}

/// A repeated field is refused too, by serde's own check on a struct — at the
/// top level and inside `tarball` — so no field of a manifest has two readings.
#[test]
fn reject_manifest_repeating_a_field() {
    let json = serde_json::to_string(&test_manifest("0.3.0", None)).unwrap();
    for (field, repeated) in [
        ("version", json.replacen('{', "{\"version\":\"9.9.9\",", 1)),
        (
            "path",
            json.replacen("\"tarball\":{", "\"tarball\":{\"path\":\"x.tar.gz\",", 1),
        ),
    ] {
        assert_ne!(
            repeated, json,
            "{field}: the fixture must change the document"
        );
        let error = Manifest::from_json(repeated.as_bytes()).unwrap_err();
        assert!(
            matches!(&error, ManifestError::Parse(_))
                && error
                    .to_string()
                    .contains(&format!("duplicate field `{field}`")),
            "{field}: {error}"
        );
    }
}

/// A manifest is the release of the key it was read from only when its own
/// `version` and `target` build that key back; one read from another release's
/// key is refused, and classified as the substitution it is.
#[test]
fn manifest_check_key_binds_version_and_target_to_the_key() {
    let target = current_target();
    let manifest = test_manifest("0.3.0", None);
    let layout = crate::ReleaseLayout::tool("fuzf");
    let own = layout.manifest_key("fuzf", "0.3.0", target);
    manifest.check_key(&layout, "fuzf", &own).unwrap();

    for (case, key) in [
        (
            "another version",
            layout.manifest_key("fuzf", "0.4.0", target),
        ),
        (
            "a version spelled differently",
            layout.manifest_key("fuzf", "0.3.00", target),
        ),
        (
            "another target",
            layout.manifest_key("fuzf", "0.3.0", "wrong-target-triple"),
        ),
        (
            "another stream",
            crate::ReleaseLayout::tool("fuzd").manifest_key("fuzd", "0.3.0", target),
        ),
        (
            "the self stream",
            crate::ReleaseLayout::self_artifact().manifest_key("fuz", "0.3.0", target),
        ),
    ] {
        let error = manifest.check_key(&layout, "fuzf", &key).unwrap_err();
        assert!(
            matches!(
                &error,
                ManifestError::KeyMismatch { key: k, version, target: t }
                    if *k == key && version == "0.3.0" && t == target
            ),
            "{case}: {error:?}"
        );
        assert!(
            ReleaseError::Manifest(error).is_security_violation(),
            "{case}"
        );
    }
}

/// Drift guard (TA.3): the unsigned projection used for signing must equal the
/// manifest minus its `signature`, field-for-field *and* value-for-value.
///
/// `verify_signature` trusts `canonical_json(ManifestUnsigned::from(&self))` as
/// "the bytes that were signed." `Manifest` and `ManifestUnsigned` duplicate 8
/// fields bridged by a hand-written `From`; if either field list or the `From`
/// body ever drifts, the signed bytes silently diverge from the manifest's
/// actual content — you would verify different bytes than you signed, a silent
/// signature break no other test catches. This pins the projection by comparing
/// the canonical projection against the manifest's own serialization with the
/// `signature` key removed and re-canonicalized: a dropped field, an added
/// field, or a mis-mapped value all break the equality. Populates *every*
/// optional field (`tool`, `minimum_version`) so a dropped optional can't hide
/// behind `skip_serializing_if` or a serialized `null`.
#[test]
fn unsigned_projection_matches_manifest_minus_signature() {
    let mut unsigned = test_unsigned("0.3.0", Some("0.2.0"));
    unsigned.tool = Some("fuzd".to_string());
    let manifest = build_manifest(unsigned);

    // The projection the signer/verifier actually hashes.
    let projected = fuz_crypto::canonical_json(&ManifestUnsigned::from(&manifest))
        .expect("canonical projection");

    // The manifest's own fields, with the signature stripped, re-canonicalized.
    let mut value = serde_json::to_value(&manifest).expect("manifest to value");
    let removed = value
        .as_object_mut()
        .expect("manifest serializes to a JSON object")
        .remove("signature");
    assert!(removed.is_some(), "manifest must carry a signature field");
    let manifest_minus_sig = fuz_crypto::canonical_json(&value).expect("canonical remainder");

    assert_eq!(
        projected, manifest_minus_sig,
        "ManifestUnsigned::from(&Manifest) drifted from Manifest minus signature — \
         signed bytes would diverge from manifest content (TA.3)"
    );
}

#[test]
fn reject_manifest_path_with_slash() {
    let result = validate_tarball_path("foo/bar.tar.gz");
    assert!(matches!(result, Err(ManifestError::InvalidTarballPath(_))));
}

#[test]
fn invalid_tarball_path_is_a_security_violation() {
    let err = validate_tarball_path("../x.tar.gz").unwrap_err();
    assert!(ReleaseError::Manifest(err).is_security_violation());
}

#[test]
fn reject_manifest_path_with_backslash() {
    let result = validate_tarball_path("foo\\bar.tar.gz");
    assert!(matches!(result, Err(ManifestError::InvalidTarballPath(_))));
}

#[test]
fn reject_manifest_path_with_dotdot() {
    let result = validate_tarball_path("..foo.tar.gz");
    assert!(matches!(result, Err(ManifestError::InvalidTarballPath(_))));

    let result = validate_tarball_path("foo..bar.tar.gz");
    assert!(matches!(result, Err(ManifestError::InvalidTarballPath(_))));
}

#[test]
fn reject_manifest_path_leading_dot() {
    let result = validate_tarball_path(".hidden.tar.gz");
    assert!(matches!(result, Err(ManifestError::InvalidTarballPath(_))));
}

#[test]
fn reject_manifest_path_empty() {
    let result = validate_tarball_path("");
    assert!(matches!(result, Err(ManifestError::InvalidTarballPath(_))));
}

/// The content hash names the install directory before the download verifies
/// it, so a signed manifest's `content_hash` must be `v1-` and 64 lowercase hex
/// — refused at parse, before any filesystem access, never a path. Classified
/// as a security violation (path-shaped hostile input, like
/// `TarballError::InvalidPath`).
#[test]
fn reject_manifest_content_hash_that_is_not_the_v1_form() {
    for bad in [
        "../x".to_string(),
        "../victim".to_string(),
        "v1-short".to_string(),
        format!("v1-{}", "A".repeat(64)),
        format!("v1-{}", "a".repeat(63)),
        format!("v1-{}/", "a".repeat(64)),
        format!("v2-{}", "a".repeat(64)),
        "a".repeat(64),
        String::new(),
    ] {
        let mut unsigned = test_unsigned("0.3.0", None);
        unsigned.content_hash.clone_from(&bad);
        let json = serde_json::to_vec(&build_manifest(unsigned)).unwrap();
        let result = Manifest::for_current_platform(&json);
        assert!(
            matches!(&result, Err(ManifestError::InvalidContentHash(h)) if *h == bad),
            "{bad:?}: got {result:?}"
        );
        let err = ReleaseError::Manifest(result.unwrap_err());
        assert!(err.is_security_violation(), "{bad:?}");
        assert!(err.hint().is_some());
    }
}

/// Every binary name becomes `<install dir>/<name>` and `bin/<name>`, and is
/// joined into the content hash with `:` and `\n`, so a signed manifest's
/// binary names must be release tokens.
#[test]
fn reject_manifest_binary_name_that_is_not_a_release_token() {
    let overlong = "a".repeat(fuz_artifact::MAX_RELEASE_TOKEN_LEN + 1);
    for bad in [
        "../x",
        "a/b",
        "..",
        ".",
        "",
        "a:b",
        "a\nb",
        "-a",
        ".a",
        "a b",
        "a+b",
        overlong.as_str(),
    ] {
        let mut unsigned = test_unsigned("0.3.0", None);
        unsigned.tool = Some("zap".to_string());
        unsigned
            .binaries
            .insert(bad.to_string(), ch(&"b".repeat(64)));
        let json = serde_json::to_vec(&build_manifest(unsigned)).unwrap();
        let result = Manifest::from_json(&json);
        assert!(
            matches!(&result, Err(ManifestError::InvalidBinaryName(n)) if n == bad),
            "{bad:?}: got {result:?}"
        );
        assert!(ReleaseError::Manifest(result.unwrap_err()).is_security_violation());
    }
}

/// A manifest's offending value is shown quoted, with nothing in it that
/// drives a terminal or prints as empty space.
#[test]
fn manifest_errors_show_the_offending_value_quoted_and_escaped() {
    let mut unsigned = test_unsigned("0.3.0", None);
    unsigned.content_hash = "v1-\u{2800}\u{1b}[2K\"".to_string();
    let json = serde_json::to_vec(&build_manifest(unsigned)).unwrap();
    assert_eq!(
        Manifest::for_current_platform(&json)
            .unwrap_err()
            .to_string(),
        "invalid content hash in manifest: \"v1-\\u{2800}\\u{1b}[2K\\\"\" \
         (expected `v1-` and 64 lowercase hex)"
    );

    let mut unsigned = test_unsigned("0.3.0", None);
    unsigned.tool = Some("zap".to_string());
    unsigned
        .binaries
        .insert("a\u{2800}\u{115f}/b".to_string(), ch(&"b".repeat(64)));
    let json = serde_json::to_vec(&build_manifest(unsigned)).unwrap();
    assert_eq!(
        Manifest::from_json(&json).unwrap_err().to_string(),
        "invalid binary name in manifest: \"a\\u{2800}\\u{115f}/b\" \
         (must be A-Za-z0-9._-, starting with a letter or digit)"
    );

    assert_eq!(
        ManifestError::UnpublishableField {
            field: "version",
            value: "0.1.0\u{2800}+b".to_string(),
            reason: "no `+`",
        }
        .to_string(),
        "release version cannot be part of a storage key: \"0.1.0\\u{2800}+b\" (no `+`)"
    );
}

#[test]
fn reject_manifest_tarball_too_large() {
    let mut unsigned = test_unsigned("0.3.0", None);
    unsigned.tarball.size = MAX_TOTAL_SIZE + 1;
    let json = serde_json::to_vec(&build_manifest(unsigned)).unwrap();

    let result = Manifest::from_json(&json);
    assert!(matches!(result, Err(ManifestError::TarballTooLarge(_))));
}

#[test]
fn reject_manifest_target_mismatch() {
    let mut unsigned = test_unsigned("0.3.0", None);
    unsigned.target = "wrong-target-triple".to_string();
    let manifest = build_manifest(unsigned);
    let json = serde_json::to_vec(&manifest).unwrap();

    let result = Manifest::for_current_platform(&json);
    assert!(matches!(result, Err(ManifestError::TargetMismatch { .. })));
}

#[test]
fn reject_manifest_missing_required_binary() {
    let mut unsigned = test_unsigned("0.3.0", None);
    unsigned.binaries.remove("fuz");
    let json = serde_json::to_vec(&build_manifest(unsigned)).unwrap();

    let result = Manifest::from_json(&json);
    assert!(matches!(result, Err(ManifestError::MissingBinary(b)) if b == "fuz"));
}

#[test]
fn reject_self_manifest_declaring_an_extra_binary() {
    // The self artifact ships `fuz` alone. A self manifest that also declared
    // `fuzd` would extract into an artifact whose recorded outputs (fuz only)
    // disagree with its hash (over both), so it is refused at parse.
    let mut unsigned = test_unsigned("0.3.0", None);
    unsigned
        .binaries
        .insert("fuzd".to_string(), ch(&"b".repeat(64)));
    let json = serde_json::to_vec(&build_manifest(unsigned)).unwrap();

    let result = Manifest::from_json(&json);
    assert!(
        matches!(result, Err(ManifestError::UnexpectedBinary(ref b)) if b == "fuzd"),
        "expected UnexpectedBinary, got: {result:?}",
    );
}

#[test]
fn reject_tool_manifest_declaring_a_self_binary() {
    // A tool's binaries are linked into the `bin/` that holds the self
    // artifact's `bin/fuz`: a tool manifest declaring `fuz` would take it.
    let mut unsigned = test_unsigned("0.3.0", None);
    unsigned.tool = Some("fuzd".to_string());
    unsigned
        .binaries
        .insert("fuzd".to_string(), ch(&"b".repeat(64)));
    let json = serde_json::to_vec(&build_manifest(unsigned.clone())).unwrap();

    let err = Manifest::from_json(&json).expect_err("a tool declaring `fuz` is refused");
    assert!(
        matches!(
            &err,
            ManifestError::ReservedBinaryName { tool, binary } if tool == "fuzd" && binary == "fuz"
        ),
        "got: {err:?}",
    );
    assert_eq!(
        err.to_string(),
        "tool manifest for fuzd declares the binary fuz, which belongs to the fuz self artifact"
    );
    assert!(ReleaseError::Manifest(err).is_security_violation());

    // The name in another ASCII case is the same link on a case-insensitive
    // filesystem, and is refused under the spelling the manifest gave.
    let mut cased = unsigned.clone();
    cased.binaries.remove("fuz");
    cased
        .binaries
        .insert("Fuz".to_string(), ch(&"c".repeat(64)));
    let json = serde_json::to_vec(&build_manifest(cased)).unwrap();
    let err = Manifest::from_json(&json).expect_err("a tool declaring `Fuz` is refused");
    assert!(
        matches!(
            &err,
            ManifestError::ReservedBinaryName { tool, binary } if tool == "fuzd" && binary == "Fuz"
        ),
        "got: {err:?}",
    );

    // The same tool without it parses.
    unsigned.binaries.remove("fuz");
    let json = serde_json::to_vec(&build_manifest(unsigned)).unwrap();
    let manifest = Manifest::from_json(&json).expect("a tool declaring its own binary parses");
    assert_eq!(manifest.tool.as_deref(), Some("fuzd"));
}

#[test]
fn reject_malformed_manifest_json() {
    let result = Manifest::from_json(b"not valid json");
    assert!(matches!(result, Err(ManifestError::Parse(_))));
}

#[test]
fn reject_manifest_declaring_test_binary() {
    // A manifest that declares a `testing_*` binary in its bill of
    // materials is rejected at parse time. This is the highest-leverage
    // chokepoint for the test-binary pattern: the wrong-thing-shipped
    // bug shows up here first, regardless of how the manifest was
    // produced.
    let mut unsigned = test_unsigned("0.3.0", None);
    unsigned
        .binaries
        .insert("testing_zzz_server".to_string(), ch(&"c".repeat(64)));
    let json = serde_json::to_vec(&build_manifest(unsigned)).unwrap();

    let result = Manifest::from_json(&json);
    assert!(
        matches!(result, Err(ManifestError::TestBinaryRejected { ref name }) if name == "testing_zzz_server"),
        "expected TestBinaryRejected, got: {result:?}",
    );
}

#[test]
fn reject_manifest_declaring_testing_spine_stub() {
    let mut unsigned = test_unsigned("0.3.0", None);
    unsigned
        .binaries
        .insert("testing_spine_stub".to_string(), ch(&"d".repeat(64)));
    let json = serde_json::to_vec(&build_manifest(unsigned)).unwrap();

    let result = Manifest::from_json(&json);
    assert!(matches!(
        result,
        Err(ManifestError::TestBinaryRejected { ref name }) if name == "testing_spine_stub"
    ));
}

//
// Version safety tests
//

#[test]
fn reject_manifest_below_minimum_version() {
    let current = semver::Version::parse("0.2.0").unwrap();
    let manifest = test_manifest("0.4.0", Some("0.3.0"));

    let result = check_version_safety(&current, &manifest);
    assert!(matches!(
        result,
        Err(ManifestError::BelowMinimum { tool: false, .. })
    ));

    // a per-tool manifest's floor is the tool's, which the error records
    let mut manifest = manifest;
    manifest.tool = Some("fuzi".to_string());
    let result = check_version_safety(&current, &manifest);
    assert!(matches!(
        result,
        Err(ManifestError::BelowMinimum { tool: true, .. })
    ));
}

#[test]
fn reject_manifest_invalid_minimum_version() {
    let current = semver::Version::parse("0.2.0").unwrap();
    let manifest = test_manifest("0.4.0", Some("not-semver"));

    let result = check_version_safety(&current, &manifest);
    assert!(matches!(result, Err(ManifestError::InvalidVersion(_))));
}

#[test]
fn reject_downgrade_without_flag() {
    // Installed 0.4.0, manifest (target) 0.3.0 → downgrade.
    let current = semver::Version::parse("0.4.0").unwrap();
    let manifest = test_manifest("0.3.0", None);

    let result = check_version_safety(&current, &manifest);
    assert!(matches!(result, Err(ManifestError::Downgrade { .. })));
}

#[test]
fn allow_upgrade() {
    let current = semver::Version::parse("0.2.0").unwrap();
    let manifest = test_manifest("0.3.0", None);

    let result = check_version_safety(&current, &manifest);
    assert!(result.is_ok());
}

//
// Tarball validation tests
//

#[test]
fn reject_tarball_empty() {
    let result = extract_tarball(
        &[],
        &test_manifest("0.3.0", None),
        std::path::Path::new("/tmp"),
    );
    assert!(matches!(result, Err(TarballError::Empty)));
}

#[test]
fn reject_tarball_zero_bytes() {
    let result = extract_tarball(
        &[],
        &test_manifest("0.3.0", None),
        std::path::Path::new("/tmp"),
    );
    assert!(matches!(result, Err(TarballError::Empty)));
}

#[test]
fn reject_tarball_hash_mismatch() {
    let content = b"test content";
    let wrong_hash = ContentHash::blake3(b"wrong");
    let result = verify_tarball_hash(content, &wrong_hash);
    assert!(matches!(result, Err(TarballError::HashMismatch { .. })));
}

#[test]
fn reject_binary_hash_mismatch() {
    let mut extracted = HashMap::new();
    extracted.insert("fuz".to_string(), ContentHash::blake3(b"wrong"));
    extracted.insert("fuzd".to_string(), ch(&"b".repeat(64)));

    let manifest = test_manifest("0.3.0", None);
    let result = verify_binary_hashes(&extracted, &manifest);
    assert!(matches!(result, Err(TarballError::BinaryHashMismatch { name, .. }) if name == "fuz"));
}

#[test]
fn reject_content_hash_mismatch() {
    let mut hashes = HashMap::new();
    hashes.insert("fuz".to_string(), ch(&"a".repeat(64)));
    hashes.insert("fuzd".to_string(), ch(&"b".repeat(64)));

    let result = verify_content_hash(&hashes, "v1-wronghash");
    assert!(matches!(
        result,
        Err(TarballError::ContentHashMismatch { .. })
    ));
}

#[test]
fn accept_content_hash_matching() {
    let mut hashes = HashMap::new();
    hashes.insert("fuz".to_string(), ch(&"a".repeat(64)));
    hashes.insert("fuzd".to_string(), ch(&"b".repeat(64)));

    // This is the known stable hash for these inputs
    let expected = "v1-8377df8a3806026a3767542a164fbb394343ba09229861ae442bfa8ded71f742";
    let result = verify_content_hash(&hashes, expected);
    assert!(result.is_ok());
}

#[test]
fn reject_tarball_symlink() {
    use tar::{Builder, Header};

    // Create tarball with symlink entry
    let mut tar_data = Vec::new();
    {
        let mut builder = Builder::new(&mut tar_data);
        let mut header = Header::new_gnu();
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_path("fuz").expect("set path");
        header.set_link_name("/etc/passwd").expect("set link");
        header.set_size(0);
        header.set_cksum();
        builder.append(&header, &[][..]).expect("append");
        builder.finish().expect("finish");
    }

    // Gzip it
    use flate2::Compression;
    use flate2::write::GzEncoder;
    let mut gz_data = Vec::new();
    {
        let mut encoder = GzEncoder::new(&mut gz_data, Compression::default());
        encoder.write_all(&tar_data).expect("write");
        encoder.finish().expect("finish");
    }

    let dir = tempfile::tempdir().unwrap();
    let result = extract_tarball(&gz_data, &test_manifest("0.3.0", None), dir.path());
    assert!(matches!(result, Err(TarballError::UnsupportedEntryType(_))));
}

#[test]
fn reject_tarball_hardlink() {
    use tar::{Builder, Header};

    let mut tar_data = Vec::new();
    {
        let mut builder = Builder::new(&mut tar_data);
        let mut header = Header::new_gnu();
        header.set_entry_type(tar::EntryType::Link);
        header.set_path("fuz").expect("set path");
        header.set_link_name("/etc/passwd").expect("set link");
        header.set_size(0);
        header.set_cksum();
        builder.append(&header, &[][..]).expect("append");
        builder.finish().expect("finish");
    }

    use flate2::Compression;
    use flate2::write::GzEncoder;
    let mut gz_data = Vec::new();
    {
        let mut encoder = GzEncoder::new(&mut gz_data, Compression::default());
        encoder.write_all(&tar_data).expect("write");
        encoder.finish().expect("finish");
    }

    let dir = tempfile::tempdir().unwrap();
    let result = extract_tarball(&gz_data, &test_manifest("0.3.0", None), dir.path());
    assert!(matches!(result, Err(TarballError::UnsupportedEntryType(_))));
}

#[test]
fn skips_directory_entries() {
    // The shared `fuz_archive` core skips directory entries (real tarballs carry
    // them); fuz_release's guarantees come from the signed-tarball hash + the
    // exact-match file allowlist, not from rejecting stray directory entries. A
    // bundle that carries a directory entry alongside the expected binaries
    // still extracts cleanly.
    use tar::{Builder, Header};

    let mut tar_data = Vec::new();
    {
        let mut builder = Builder::new(&mut tar_data);
        // A directory entry...
        let mut dir_header = Header::new_gnu();
        dir_header.set_entry_type(tar::EntryType::Directory);
        dir_header.set_path("subdir/").expect("set path");
        dir_header.set_size(0);
        dir_header.set_mode(0o755);
        dir_header.set_cksum();
        builder.append(&dir_header, &[][..]).expect("append dir");
        // ...alongside the two expected binaries.
        for name in ["fuz", "fuzd"] {
            let content = b"binary";
            let mut header = Header::new_gnu();
            header.set_path(name).expect("set path");
            header.set_size(content.len() as u64);
            header.set_mode(0o755);
            header.set_cksum();
            builder.append(&header, &content[..]).expect("append bin");
        }
        builder.finish().expect("finish");
    }

    use flate2::Compression;
    use flate2::write::GzEncoder;
    let mut gz_data = Vec::new();
    {
        let mut encoder = GzEncoder::new(&mut gz_data, Compression::default());
        encoder.write_all(&tar_data).expect("write");
        encoder.finish().expect("finish");
    }

    let dir = tempfile::tempdir().unwrap();
    let result = extract_tarball(&gz_data, &two_binary_manifest(), dir.path());
    let extracted = result.expect("directory entry skipped, binaries extracted");
    assert!(extracted.contains_key("fuz"));
    assert!(extracted.contains_key("fuzd"));
    // The directory entry contributed no file to the output.
    assert_eq!(extracted.len(), 2);
}

#[test]
fn tar_library_rejects_path_traversal() {
    // The tar library itself rejects paths with ".." - this is a good defense-in-depth.
    // Our extraction code provides a second layer via Component::Normal allowlisting.
    use tar::Header;

    let mut header = Header::new_gnu();
    let result = header.set_path("../../../etc/passwd");

    // The tar crate rejects paths with ".." at archive creation time
    assert!(result.is_err(), "tar library should reject path with ..");
}

#[test]
fn tar_library_rejects_absolute_path() {
    // The tar library itself rejects absolute paths - this is a good defense-in-depth.
    // Our extraction code provides a second layer via Component::Normal allowlisting.
    use tar::Header;

    let mut header = Header::new_gnu();
    let result = header.set_path("/etc/passwd");

    // The tar crate rejects absolute paths at archive creation time
    assert!(result.is_err(), "tar library should reject absolute paths");
}

#[test]
#[cfg(unix)]
fn reject_tarball_setuid() {
    use tar::{Builder, Header};

    let mut tar_data = Vec::new();
    {
        let mut builder = Builder::new(&mut tar_data);
        let mut header = Header::new_gnu();
        header.set_path("fuz").expect("set path");
        header.set_size(4);
        header.set_mode(0o4755); // setuid
        header.set_cksum();
        builder.append(&header, &b"evil"[..]).expect("append");
        builder.finish().expect("finish");
    }

    use flate2::Compression;
    use flate2::write::GzEncoder;
    let mut gz_data = Vec::new();
    {
        let mut encoder = GzEncoder::new(&mut gz_data, Compression::default());
        encoder.write_all(&tar_data).expect("write");
        encoder.finish().expect("finish");
    }

    let dir = tempfile::tempdir().unwrap();
    let result = extract_tarball(&gz_data, &test_manifest("0.3.0", None), dir.path());
    assert!(matches!(result, Err(TarballError::SetuidBit(_))));
}

#[test]
#[cfg(unix)]
fn reject_tarball_setgid() {
    use tar::{Builder, Header};

    let mut tar_data = Vec::new();
    {
        let mut builder = Builder::new(&mut tar_data);
        let mut header = Header::new_gnu();
        header.set_path("fuz").expect("set path");
        header.set_size(4);
        header.set_mode(0o2755); // setgid
        header.set_cksum();
        builder.append(&header, &b"evil"[..]).expect("append");
        builder.finish().expect("finish");
    }

    use flate2::Compression;
    use flate2::write::GzEncoder;
    let mut gz_data = Vec::new();
    {
        let mut encoder = GzEncoder::new(&mut gz_data, Compression::default());
        encoder.write_all(&tar_data).expect("write");
        encoder.finish().expect("finish");
    }

    let dir = tempfile::tempdir().unwrap();
    let result = extract_tarball(&gz_data, &test_manifest("0.3.0", None), dir.path());
    assert!(matches!(result, Err(TarballError::SetgidBit(_))));
}

#[test]
fn reject_tarball_missing_fuz() {
    let tarball = create_test_tarball(&[("fuzd", b"content")]);
    let dir = tempfile::tempdir().unwrap();
    let result = extract_tarball(&tarball, &test_manifest("0.3.0", None), dir.path());
    assert!(matches!(result, Err(TarballError::MissingBinary(b)) if b == "fuz"));
}

#[test]
fn reject_tarball_missing_fuzd() {
    let tarball = create_test_tarball(&[("fuz", b"content")]);
    let dir = tempfile::tempdir().unwrap();
    let result = extract_tarball(&tarball, &two_binary_manifest(), dir.path());
    assert!(matches!(result, Err(TarballError::MissingBinary(b)) if b == "fuzd"));
}

#[test]
fn reject_tarball_unexpected_file() {
    let tarball = create_test_tarball(&[
        ("fuz", b"content"),
        ("fuzd", b"content"),
        ("extra_malicious", b"evil"),
    ]);
    let dir = tempfile::tempdir().unwrap();
    let result = extract_tarball(&tarball, &two_binary_manifest(), dir.path());
    assert!(
        matches!(result, Err(TarballError::UnexpectedFile(p)) if p.as_path() == std::path::Path::new("extra_malicious"))
    );
}

//
// Error helper tests
//

#[test]
fn tarball_error_security_violations() {
    // These should be security violations
    assert!(TarballError::InvalidPath(PathBuf::from("test")).is_security_violation());
    assert!(TarballError::SetuidBit(PathBuf::from("test")).is_security_violation());
    assert!(TarballError::SetgidBit(PathBuf::from("test")).is_security_violation());
    assert!(TarballError::CompressionBomb(200).is_security_violation());
    // Hostile-input guard variants, kept in lockstep with `fuz_archive`.
    assert!(TarballError::NullByte(PathBuf::from("test")).is_security_violation());
    assert!(TarballError::PathTooLong(PathBuf::from("test")).is_security_violation());
    assert!(TarballError::FileTooLarge(PathBuf::from("test"), 1).is_security_violation());
    assert!(TarballError::TotalTooLarge(1).is_security_violation());
    assert!(TarballError::HeaderTooLarge(1).is_security_violation());
    assert!(
        TarballError::HashMismatch {
            expected: ContentHash::blake3(b"a"),
            actual: ContentHash::blake3(b"b")
        }
        .is_security_violation()
    );

    // These should NOT be security violations
    assert!(!TarballError::Empty.is_security_violation());
    assert!(!TarballError::Io(std::io::Error::other("test")).is_security_violation());
}

/// Every `fuz_archive` error keeps its classification through the
/// `TarballError` mapping, and every violation carries a hint: the guard
/// variants are kept in lockstep with `fuz_archive`'s own classifier.
#[test]
fn archive_errors_keep_their_classification_as_tarball_errors() {
    use fuz_archive::ArchiveError as A;
    let p = || PathBuf::from("x");
    let io = || std::io::Error::other("x");
    let all = [
        A::InvalidPath(p()),
        A::UnsupportedEntryType(p()),
        A::NullByte(p()),
        A::PathTooLong(p()),
        A::FileTooLarge(p(), 1),
        A::TotalTooLarge(1),
        A::CompressionBomb(2),
        A::HeaderTooLarge(1),
        A::SetuidBit(p()),
        A::SetgidBit(p()),
        A::PlacementEscapesRoot(p()),
        A::DirectoryWithBody(p(), 1),
        A::PaxSizeMismatch {
            path: p(),
            header_size: 1,
            pax_size: 2,
        },
        A::MalformedPax(p(), "x"),
        A::MalformedHeader(p(), "x"),
        A::Malformed {
            context: "t",
            source: io(),
        },
        A::Empty,
        A::Io(io()),
        A::Read {
            context: "t",
            source: std::io::Error::from_raw_os_error(5),
        },
    ];
    for archive in all {
        // Exhaustive, so a new variant breaks this match — add it to the table above too.
        match &archive {
            A::InvalidPath(_)
            | A::UnsupportedEntryType(_)
            | A::NullByte(_)
            | A::PathTooLong(_)
            | A::FileTooLarge(_, _)
            | A::TotalTooLarge(_)
            | A::CompressionBomb(_)
            | A::HeaderTooLarge(_)
            | A::SetuidBit(_)
            | A::SetgidBit(_)
            | A::PlacementEscapesRoot(_)
            | A::DirectoryWithBody(_, _)
            | A::PaxSizeMismatch { .. }
            | A::MalformedPax(_, _)
            | A::MalformedHeader(_, _)
            | A::Malformed { .. }
            | A::Empty
            | A::Io(_)
            | A::Read { .. } => {}
        }
        let expected = archive.is_security_violation();
        let description = archive.to_string();
        let tarball = TarballError::from(archive);
        assert_eq!(
            tarball.is_security_violation(),
            expected,
            "{description} -> {tarball}"
        );
        if expected {
            assert!(tarball.hint().is_some(), "{tarball}");
        }
    }
}

/// A directory entry that declares a body is refused in a signed bundle too:
/// node-tar would read the body as further entries.
#[test]
fn a_bundle_directory_with_a_body_is_refused() {
    let mut dir_header = tar::Header::new_ustar();
    dir_header.set_path("bin").unwrap();
    dir_header.set_entry_type(tar::EntryType::Directory);
    dir_header.set_mode(0o755);
    dir_header.set_size(512);
    dir_header.set_cksum();
    let mut builder = tar::Builder::new(Vec::new());
    builder.append(&dir_header, &[0u8; 512][..]).unwrap();
    let tar_data = builder.into_inner().unwrap();
    use flate2::Compression;
    use flate2::write::GzEncoder;
    let mut gz_data = Vec::new();
    {
        let mut encoder = GzEncoder::new(&mut gz_data, Compression::default());
        encoder.write_all(&tar_data).expect("write");
        encoder.finish().expect("finish");
    }
    let dir = tempfile::tempdir().unwrap();
    let result = extract_tarball(&gz_data, &test_manifest("0.3.0", None), dir.path());
    assert!(
        matches!(result, Err(TarballError::DirectoryWithBody(_, 512))),
        "{result:?}"
    );
}

/// An unusable home classifies the same whether it reaches the release chain
/// directly or through the artifact store; a home-layer failure while using a
/// usable home, and a release failure of its own, do not.
#[test]
fn release_error_unusable_home_forwards_through_both_wrappers() {
    let unusable = || fuz_home::FuzHomeError::RelativeFuzHome {
        path: PathBuf::from("relhome"),
    };
    assert!(ReleaseError::FuzHome(unusable()).is_unusable_home());
    assert!(
        ReleaseError::Artifact(fuz_artifact::ArtifactError::FuzHome(unusable())).is_unusable_home()
    );
    let insecure = ReleaseError::FuzHome(fuz_home::FuzHomeError::InsecureHome {
        path: PathBuf::from("/tmp/fuz"),
        mode: 0o777,
    });
    assert!(insecure.is_unusable_home());

    assert!(
        !ReleaseError::FuzHome(fuz_home::FuzHomeError::DaemonInfoInvalidPid(-1)).is_unusable_home()
    );
    assert!(
        !ReleaseError::Artifact(fuz_artifact::ArtifactError::InProgress { pid: None })
            .is_unusable_home()
    );
    assert!(!ReleaseError::ToolNotInstalled("zap".to_string()).is_unusable_home());
}

/// The enum-level classifier honors its wrapped errors' own classifications:
/// a world-writable `~/.fuz` is a refusal *on security grounds*, so it must
/// not read as a benign home-layer I/O failure.
#[test]
fn release_error_security_violations() {
    let insecure = ReleaseError::FuzHome(fuz_home::FuzHomeError::InsecureHome {
        path: PathBuf::from("/tmp/fuz"),
        mode: 0o777,
    });
    assert!(insecure.is_security_violation());

    // …while the ordinary home-layer failures around it stay benign.
    assert!(
        !ReleaseError::FuzHome(fuz_home::FuzHomeError::HomeDir(
            fuz_sys::HomeDirError::NotFound
        ))
        .is_security_violation()
    );
    assert!(
        !ReleaseError::FuzHome(fuz_home::FuzHomeError::RelativeFuzHome {
            path: PathBuf::from("relhome"),
        })
        .is_security_violation()
    );
    assert!(
        !ReleaseError::FuzHome(fuz_home::FuzHomeError::DaemonInfoInvalidPid(-1))
            .is_security_violation()
    );

    // A tool binary named for a self binary is the same refusal where the
    // store makes it as where the manifest does; the store's integrity
    // refusals and its lock stay benign.
    let reserved = || fuz_artifact::ArtifactError::ReservedBinaryName {
        tool: "zap".to_string(),
        binary: "fuz".to_string(),
    };
    assert!(ReleaseError::Artifact(reserved()).is_security_violation());
    assert!(
        ReleaseError::Manifest(ManifestError::ReservedBinaryName {
            tool: "zap".to_string(),
            binary: "fuz".to_string(),
        })
        .is_security_violation()
    );
    for benign in [
        fuz_artifact::ArtifactError::IntegrityFailed {
            path: PathBuf::from("/x"),
            expected: "a".to_string(),
            actual: "b".to_string(),
        },
        fuz_artifact::ArtifactError::NotRegularFile(PathBuf::from("/x")),
        fuz_artifact::ArtifactError::InvalidBinary {
            name: "fuz".to_string(),
            reason: "symlink".to_string(),
        },
        fuz_artifact::ArtifactError::InProgress { pid: None },
        fuz_artifact::ArtifactError::NotFound("v1-abc".to_string()),
    ] {
        let description = benign.to_string();
        assert!(
            !ReleaseError::Artifact(benign).is_security_violation(),
            "{description}"
        );
    }

    // Delegation through the tarball arm still works.
    assert!(
        ReleaseError::Tarball(TarballError::SetuidBit(PathBuf::from("x"))).is_security_violation()
    );
    assert!(!ReleaseError::Tarball(TarballError::Empty).is_security_violation());
}

#[test]
fn errors_have_hints() {
    // ManifestError hints
    assert!(ManifestError::UnsupportedFormat(2).hint().is_some());
    assert!(
        ManifestError::TooLarge(MAX_MANIFEST_SIZE + 1)
            .hint()
            .is_some()
    );
    // the floor's hint names the recovery for its stream: a re-bootstrap for
    // the fuz self artifact, a fresh tool install for a tool
    let below_minimum = |tool| {
        ManifestError::BelowMinimum {
            current: "0.1.0".to_string(),
            minimum: "0.2.0".to_string(),
            tool,
        }
        .hint()
        .unwrap()
    };
    assert!(below_minimum(false).contains("Re-bootstrap"));
    assert!(!below_minimum(false).contains("fuz tool install"));
    assert!(below_minimum(true).contains("fuz tool install"));
    assert!(!below_minimum(true).contains("Re-bootstrap"));
    assert!(
        ManifestError::Downgrade {
            current: "0.2.0".to_string(),
            target: "0.1.0".to_string()
        }
        .hint()
        .is_some()
    );

    // TarballError hints
    assert!(
        TarballError::InvalidPath(PathBuf::from("test"))
            .hint()
            .is_some()
    );
    assert!(
        TarballError::HashMismatch {
            expected: ContentHash::blake3(b"a"),
            actual: ContentHash::blake3(b"b")
        }
        .hint()
        .is_some()
    );
    assert!(TarballError::CompressionBomb(200).hint().is_some());
    assert!(TarballError::HeaderTooLarge(1).hint().is_some());

    // I/O errors don't have hints
    assert!(
        TarballError::Io(std::io::Error::other("test"))
            .hint()
            .is_none()
    );

    // The home layer's hint passes through
    let relative = ReleaseError::FuzHome(fuz_home::FuzHomeError::RelativeFuzHome {
        path: PathBuf::from("relhome"),
    });
    assert!(
        relative
            .hint()
            .is_some_and(|hint| hint.contains("FUZ_HOME"))
    );
}

//
// Compression bomb detection test
//

#[test]
fn reject_tarball_compression_bomb() {
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use tar::{Builder, Header};

    // Create a tarball with highly compressible content (all zeros)
    // to trigger compression bomb detection.
    //
    // MAX_COMPRESSION_RATIO is 100x, so if we compress 10KB of zeros
    // (which compress very well), we need the compressed size to be
    // small enough that ratio > 100.
    //
    // Zeros compress extremely well - ~1000:1 is typical for gzip.
    // We'll create a 1MB file of zeros which should compress to ~1KB.
    // When extracting, we check ratio every 64KB, so at 64KB decompressed
    // from ~1KB compressed, ratio = 64 (still ok). At 128KB, ratio = 128 (fails).

    let zero_content = vec![0u8; 1024 * 1024]; // 1MB of zeros

    let mut tar_data = Vec::new();
    {
        let mut builder = Builder::new(&mut tar_data);

        // Add "fuz" file with zeros
        let mut header = Header::new_gnu();
        header.set_path("fuz").expect("set path");
        header.set_size(zero_content.len() as u64);
        header.set_mode(0o755);
        header.set_cksum();
        builder
            .append(&header, zero_content.as_slice())
            .expect("append");
        builder.finish().expect("finish");
    }

    // Compress with maximum compression to get high ratio
    let mut gz_data = Vec::new();
    {
        let mut encoder = GzEncoder::new(&mut gz_data, Compression::best());
        encoder.write_all(&tar_data).expect("write");
        encoder.finish().expect("finish");
    }

    // Verify we have a high compression ratio setup
    let ratio = tar_data.len() / gz_data.len();
    assert!(
        ratio > 100,
        "Test setup failed: compression ratio {ratio} not high enough to trigger detection"
    );

    let dir = tempfile::tempdir().unwrap();
    let result = extract_tarball(&gz_data, &test_manifest("0.3.0", None), dir.path());

    assert!(
        matches!(result, Err(TarballError::CompressionBomb(_))),
        "Expected CompressionBomb error, got: {result:?}"
    );
}

/// A PAX body past the signed-bundle header cap is refused while `tar` reads
/// it, and maps onto `TarballError::HeaderTooLarge` (a security violation).
#[test]
fn reject_tarball_oversized_header() {
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use tar::{Builder, EntryType, Header};

    // Incompressible (xorshift), so the ratio guard stays out of the way.
    let mut state: u64 = 0x9e37_79b9_7f4a_7c15;
    let body: Vec<u8> = (0..256 * 1024)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state.to_le_bytes()[0]
        })
        .collect();

    let mut tar_data = Vec::new();
    {
        let mut builder = Builder::new(&mut tar_data);
        let mut pax = Header::new_ustar();
        pax.set_path("PaxHeader").expect("set path");
        pax.set_entry_type(EntryType::XHeader);
        pax.set_size(body.len() as u64);
        pax.set_cksum();
        builder.append(&pax, body.as_slice()).expect("append");
        let mut header = Header::new_gnu();
        header.set_path("fuz").expect("set path");
        header.set_size(1);
        header.set_mode(0o755);
        header.set_cksum();
        builder.append(&header, &b"x"[..]).expect("append");
        builder.finish().expect("finish");
    }
    let mut gz_data = Vec::new();
    {
        let mut encoder = GzEncoder::new(&mut gz_data, Compression::default());
        encoder.write_all(&tar_data).expect("write");
        encoder.finish().expect("finish");
    }

    let dir = tempfile::tempdir().unwrap();
    let result = extract_tarball(&gz_data, &test_manifest("0.3.0", None), dir.path());
    let Err(err) = result else {
        panic!("expected HeaderTooLarge, got: {result:?}");
    };
    assert!(
        matches!(err, TarballError::HeaderTooLarge(_)),
        "expected HeaderTooLarge, got: {err:?}"
    );
    assert!(err.is_security_violation());
}

//
// Manifest size limit test
//

#[test]
fn reject_manifest_too_large() {
    // The manifest size check happens before JSON parsing (at download time in 3c).
    // This test verifies the constant is reasonable and documents the check location.
    //
    // ManifestError::TooLarge is used when size > MAX_MANIFEST_SIZE (1MB).
    // The actual check will be in the storage layer, but we test the error here.

    let error = ManifestError::TooLarge(MAX_MANIFEST_SIZE + 1);
    assert!(error.hint().is_some());
    assert!(error.to_string().contains("1048576")); // 1MB

    // Verify constant is reasonable (manifests are small JSON, 1MB is plenty)
    assert_eq!(MAX_MANIFEST_SIZE, 1024 * 1024);
}

// Signature-verification round-trip tests (sign with a key, then
// verify_signature) live in `fuz_sign`, which owns the signing side. This
// suite uses a placeholder signature and covers parse/validate/tarball only.

//
// Additional tarball entry type tests
//

#[test]
fn reject_tarball_device_file() {
    use tar::{Builder, Header};

    let mut tar_data = Vec::new();
    {
        let mut builder = Builder::new(&mut tar_data);
        let mut header = Header::new_gnu();
        header.set_entry_type(tar::EntryType::Char); // Character device
        header.set_path("fuz").expect("set path");
        header.set_size(0);
        header.set_cksum();
        builder.append(&header, &[][..]).expect("append");
        builder.finish().expect("finish");
    }

    use flate2::Compression;
    use flate2::write::GzEncoder;
    let mut gz_data = Vec::new();
    {
        let mut encoder = GzEncoder::new(&mut gz_data, Compression::default());
        encoder.write_all(&tar_data).expect("write");
        encoder.finish().expect("finish");
    }

    let dir = tempfile::tempdir().unwrap();
    let result = extract_tarball(&gz_data, &test_manifest("0.3.0", None), dir.path());
    assert!(matches!(result, Err(TarballError::UnsupportedEntryType(_))));
}

#[test]
fn reject_tarball_fifo() {
    use tar::{Builder, Header};

    let mut tar_data = Vec::new();
    {
        let mut builder = Builder::new(&mut tar_data);
        let mut header = Header::new_gnu();
        header.set_entry_type(tar::EntryType::Fifo);
        header.set_path("fuz").expect("set path");
        header.set_size(0);
        header.set_cksum();
        builder.append(&header, &[][..]).expect("append");
        builder.finish().expect("finish");
    }

    use flate2::Compression;
    use flate2::write::GzEncoder;
    let mut gz_data = Vec::new();
    {
        let mut encoder = GzEncoder::new(&mut gz_data, Compression::default());
        encoder.write_all(&tar_data).expect("write");
        encoder.finish().expect("finish");
    }

    let dir = tempfile::tempdir().unwrap();
    let result = extract_tarball(&gz_data, &test_manifest("0.3.0", None), dir.path());
    assert!(matches!(result, Err(TarballError::UnsupportedEntryType(_))));
}

//
// Path validation tests
//

#[test]
fn reject_tarball_dot_prefix() {
    // Files starting with . are not recognized as valid binaries.
    // A tarball with only ".fuz" fails because required "fuz" binary is missing.
    let tarball = create_test_tarball(&[(".fuz", b"content")]);
    let dir = tempfile::tempdir().unwrap();
    let result = extract_tarball(&tarball, &test_manifest("0.3.0", None), dir.path());
    // Fails because required binaries are missing (dot-prefixed files don't count)
    assert!(
        matches!(result, Err(TarballError::MissingBinary(_))),
        "expected MissingBinary error for tarball with only dot-prefixed file, got: {result:?}"
    );
}

// Note: reject_tarball_null_byte_path and reject_tarball_long_path are difficult
// to test because the tar crate sanitizes paths during header construction.
// The validation code handles these cases, but crafting the raw bytes is complex.
// The protection is verified through code review of validate_tar_entry().

//
// Size limit tests
//

#[test]
fn reject_tarball_file_too_large() {
    use crate::MAX_FILE_SIZE;
    use tar::{Builder, Header};

    // Create a tarball with a file claiming to be larger than MAX_FILE_SIZE
    let mut tar_data = Vec::new();
    {
        let mut builder = Builder::new(&mut tar_data);
        let mut header = Header::new_gnu();
        header.set_path("fuz").expect("set path");
        header.set_size(MAX_FILE_SIZE + 1); // Exceeds limit
        header.set_mode(0o755);
        header.set_cksum();
        // Note: We don't actually write that much data, the size check happens on header
        builder.append(&header, &b"small"[..]).expect("append");
        builder.finish().expect("finish");
    }

    use flate2::Compression;
    use flate2::write::GzEncoder;
    let mut gz_data = Vec::new();
    {
        let mut encoder = GzEncoder::new(&mut gz_data, Compression::default());
        encoder.write_all(&tar_data).expect("write");
        encoder.finish().expect("finish");
    }

    let dir = tempfile::tempdir().unwrap();
    let result = extract_tarball(&gz_data, &test_manifest("0.3.0", None), dir.path());
    assert!(
        matches!(result, Err(TarballError::FileTooLarge(_, _))),
        "Expected FileTooLarge error, got: {result:?}"
    );
}

// Note: reject_tarball_total_too_large is tested indirectly by the compression bomb test.
// The TotalTooLarge check triggers when decompressed bytes > MAX_TOTAL_SIZE,
// but creating a test with that much data would be slow. The compression bomb
// test verifies the streaming size-check logic is working.

//
// Truncated tarball test
//

#[test]
fn reject_truncated_tarball() {
    // Create a valid tarball and truncate it
    let tarball = create_test_tarball(&[("fuz", b"content"), ("fuzd", b"content")]);

    // Truncate in the middle
    let truncated = &tarball[..tarball.len() / 2];

    let dir = tempfile::tempdir().unwrap();
    let result = extract_tarball(truncated, &test_manifest("0.3.0", None), dir.path());

    // The gzip layer's truncation: bytes that do not parse, behind a digest
    // that matched, so a security violation.
    assert!(
        matches!(result, Err(TarballError::Malformed { .. })),
        "expected a malformed-tarball error for a truncated tarball, got: {result:?}"
    );
    assert!(result.unwrap_err().is_security_violation());
}
