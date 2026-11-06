//! Release log heads through a real signature: the wire-format known answer,
//! the unverified → verified typestate, and the append-only rules.
//!
//! The rule functions accept only `VerifiedHead`, and the one way to obtain a
//! `VerifiedHead` is `Head::verify_signature` against a trusted key. So every
//! test here really signs (`sign_head`) and really verifies, with the signing
//! key admitted through `fuz_crypto`'s dev-dependency-only `test_trust_anchor`
//! seam — the same seam `signed_trust.rs` uses. Parsing and structural
//! validation, which need no signature, are covered beside the types in
//! `fuz_release::release_log`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::sync::Once;

use ed25519_dalek::{Signer, Verifier};
use fuz_crypto::{
    ContentHash, HashAlgo, SIGNATURE_FORMAT_VERSION, Signature, SignatureAlgorithm, SignedMessage,
    VerifyError,
};
use fuz_release::{
    Head, HeadField, HeadInvalid, HeadOrder, HeadUnsigned, HeadViolation, KeyRecord, MAX_HEAD_SIZE,
    Manifest, ManifestError, ManifestUnsigned, ReleaseError, ReleaseLogError, ReleaseRow,
    RowStatus, Succession, TarballInfo, TargetField, TargetRow, VerifiedHead, check_consistent,
    check_successor, check_superset,
};
use fuz_sign::{SigningKey, sign_head, sign_manifest};
use serde_json::{Value, json};

const X86: &str = "x86_64-unknown-linux-gnu";
const ARM: &str = "aarch64-unknown-linux-gnu";
const SIGNED_AT: &str = "2025-01-15T10:30:00Z";

/// Base64 public key of [`trusted_key`] (seed `[0u8; 32]`).
const TRUSTED_PUBLIC_KEY: &str = "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik=";
/// Base64 public key of seed `[7u8; 32]` — appears only as a key *record*.
const RETIRED_PUBLIC_KEY: &str = "6kpsY+KcUgq+9VB7Ey7F+ZVHdq6+vnuSQh7qaRRG0iw=";

/// The key every head here is signed with. Admitted by [`trust`].
fn trusted_key() -> SigningKey {
    SigningKey::from_bytes(&[0u8; 32])
}

/// A key this file never registers — it must stay untrusted.
fn untrusted_key() -> SigningKey {
    SigningKey::from_bytes(&[22u8; 32])
}

/// Register [`trusted_key`] with the trust anchor, once. The registry is
/// process-global and nothing in this file clears it, so the tests need no
/// serialization: the trusted key stays trusted and the untrusted key is never
/// added.
fn trust() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| fuz_crypto::add_trusted_key_for_testing(&trusted_key().verifying_key()));
}

fn base64_decode(text: &str) -> Vec<u8> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    STANDARD.decode(text).unwrap()
}

fn b3(fill: &str) -> ContentHash {
    ContentHash::from_hex(HashAlgo::Blake3, &fill.repeat(64)).unwrap()
}

fn target_row(fill: &str, binary: &str, sha512: Option<&[u8]>) -> TargetRow {
    TargetRow {
        content_hash: format!("v1-{}", fill.repeat(64)),
        binaries: BTreeMap::from([(binary.to_string(), b3(fill))]),
        sha512: sha512.map(ContentHash::sha512),
    }
}

fn row(name: &str, version: &str, status: RowStatus, targets: &[(&str, TargetRow)]) -> ReleaseRow {
    ReleaseRow {
        name: name.to_string(),
        version: version.to_string(),
        status,
        published_at: "2025-01-10T00:00:00Z".to_string(),
        targets: targets
            .iter()
            .map(|(target, entry)| ((*target).to_string(), entry.clone()))
            .collect(),
    }
}

/// The head most tests start from: one retired key record and one in use; a
/// self release with a `sha512`, a tool release without, and a revoked one.
fn base() -> HeadUnsigned {
    HeadUnsigned {
        format: 1,
        seq: 5,
        keys: vec![
            KeyRecord {
                public_key: RETIRED_PUBLIC_KEY.to_string(),
                added_at: "2024-06-01T00:00:00Z".to_string(),
                retired_at: Some("2025-01-01T00:00:00Z".to_string()),
            },
            KeyRecord {
                public_key: TRUSTED_PUBLIC_KEY.to_string(),
                added_at: "2025-01-01T00:00:00Z".to_string(),
                retired_at: None,
            },
        ],
        rows: vec![
            row(
                "fuz",
                "0.1.0",
                RowStatus::Ok,
                &[(X86, target_row("a", "fuz", Some(b"fuz x86")))],
            ),
            row(
                "fuzd",
                "0.1.0",
                RowStatus::Ok,
                &[(X86, target_row("b", "fuzd", None))],
            ),
            row(
                "fuzd",
                "0.0.9",
                RowStatus::Revoked,
                &[(X86, target_row("c", "fuzd", None))],
            ),
        ],
    }
}

/// Sign with the trusted key and verify — the only route to a `VerifiedHead`.
fn verified(unsigned: HeadUnsigned) -> VerifiedHead {
    trust();
    sign_head(unsigned, &trusted_key(), SIGNED_AT)
        .unwrap()
        .verify_signature()
        .unwrap()
}

/// [`base`] and a successor: `base` with `seq + 1` and `change` applied.
fn base_and_next(change: impl FnOnce(&mut HeadUnsigned)) -> (VerifiedHead, VerifiedHead) {
    let old = base();
    let mut new = old.clone();
    new.seq += 1;
    change(&mut new);
    (verified(old), verified(new))
}

/// The successor is refused with exactly `expected`, by every rule that sees
/// it: the superset rule, succession, and consistency in either argument order.
#[track_caller]
fn assert_violation(change: impl FnOnce(&mut HeadUnsigned), expected: &HeadViolation) {
    let (old, new) = base_and_next(change);
    assert_eq!(check_superset(&old, &new).as_ref(), Err(expected));
    assert_eq!(check_successor(&old, &new).as_ref(), Err(expected));
    assert_eq!(check_consistent(&old, &new).as_ref(), Err(expected));
    assert_eq!(check_consistent(&new, &old).as_ref(), Err(expected));
}

/// The successor is accepted by every rule.
#[track_caller]
fn assert_advances(change: impl FnOnce(&mut HeadUnsigned)) {
    let (old, new) = base_and_next(change);
    assert_eq!(check_superset(&old, &new), Ok(()));
    assert_eq!(check_successor(&old, &new), Ok(Succession::Advanced));
    assert_eq!(check_consistent(&old, &new), Ok(HeadOrder::SecondNewer));
    assert_eq!(check_consistent(&new, &old), Ok(HeadOrder::FirstNewer));
}

fn fuz_x86(head: &mut HeadUnsigned) -> &mut TargetRow {
    head.rows[0].targets.get_mut(X86).unwrap()
}

fn row_violation(
    make: fn(String, String) -> HeadViolation,
    name: &str,
    version: &str,
) -> HeadViolation {
    make(name.to_string(), version.to_string())
}

fn target_changed(field: TargetField) -> HeadViolation {
    HeadViolation::TargetChanged {
        name: "fuz".to_string(),
        version: "0.1.0".to_string(),
        target: X86.to_string(),
        field,
    }
}

//
// Known answer
//

/// The fixed head the known-answer test signs.
fn known_answer_head() -> HeadUnsigned {
    HeadUnsigned {
        format: 1,
        seq: 7,
        keys: vec![
            KeyRecord {
                public_key: RETIRED_PUBLIC_KEY.to_string(),
                added_at: "2024-06-01T00:00:00Z".to_string(),
                retired_at: Some("2025-01-01T00:00:00Z".to_string()),
            },
            KeyRecord {
                public_key: TRUSTED_PUBLIC_KEY.to_string(),
                added_at: "2025-01-01T00:00:00Z".to_string(),
                retired_at: None,
            },
        ],
        rows: vec![
            ReleaseRow {
                name: "fuz".to_string(),
                version: "0.1.0".to_string(),
                status: RowStatus::Ok,
                published_at: "2025-01-10T00:00:00Z".to_string(),
                targets: BTreeMap::from([
                    (X86.to_string(), target_row("a", "fuz", Some(b"abc"))),
                    (ARM.to_string(), target_row("b", "fuz", Some(b""))),
                ]),
            },
            ReleaseRow {
                name: "fuzd".to_string(),
                version: "0.1.0".to_string(),
                status: RowStatus::Revoked,
                published_at: "2025-01-12T00:00:00Z".to_string(),
                targets: BTreeMap::from([(X86.to_string(), target_row("c", "fuzd", None))]),
            },
        ],
    }
}

/// The canonical bytes the signature covers for [`known_answer_head`].
/// Sorted keys, no whitespace, bare lowercase hex, and unset optional fields
/// (`retired_at`, `sha512`) absent rather than `null`. The `sha512` values are
/// the NIST vectors for `""` and `"abc"`.
const KNOWN_ANSWER_CANONICAL: &str = concat!(
    r#"{"format":1,"keys":["#,
    r#"{"added_at":"2024-06-01T00:00:00Z","public_key":"6kpsY+KcUgq+9VB7Ey7F+ZVHdq6+vnuSQh7qaRRG0iw=","retired_at":"2025-01-01T00:00:00Z"},"#,
    r#"{"added_at":"2025-01-01T00:00:00Z","public_key":"O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik="}"#,
    r#"],"rows":["#,
    r#"{"name":"fuz","published_at":"2025-01-10T00:00:00Z","status":"ok","targets":{"#,
    r#""aarch64-unknown-linux-gnu":{"binaries":{"fuz":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},"#,
    r#""content_hash":"v1-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","#,
    r#""sha512":"cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"},"#,
    r#""x86_64-unknown-linux-gnu":{"binaries":{"fuz":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"#,
    r#""content_hash":"v1-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","#,
    r#""sha512":"ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"}"#,
    r#"},"version":"0.1.0"},"#,
    r#"{"name":"fuzd","published_at":"2025-01-12T00:00:00Z","status":"revoked","targets":{"#,
    r#""x86_64-unknown-linux-gnu":{"binaries":{"fuzd":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},"#,
    r#""content_hash":"v1-cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}"#,
    r#"},"version":"0.1.0"}"#,
    r#"],"seq":7}"#,
);

/// The head domain tag, spelled out: the signed bytes are this, then
/// [`KNOWN_ANSWER_CANONICAL`].
const HEAD_TAG: &[u8] = b"fuz-release-log-head-v1\0";

/// The manifest domain tag, spelled out.
const MANIFEST_TAG: &[u8] = b"fuz-manifest-v1\0";

/// The ed25519 signature of [`HEAD_TAG`] + [`KNOWN_ANSWER_CANONICAL`] under
/// seed `[0u8; 32]`.
const KNOWN_ANSWER_SIGNATURE: &str =
    "p6g0ZZd6F5VXDhTkvmOOMb3K6RTG7Y7/WD93A/FU/GsrkmiR8bjOGFi1kYz4YHl1FiKimPar9x5vda+QpNvTBw==";

/// KAT / wire-format tripwire. A fixed head signed with the seed-`[0u8; 32]`
/// key must canonicalize to exactly these bytes and produce exactly this
/// signature (ed25519 signing is deterministic, RFC 8032). A drift in either
/// — a renamed or reordered field, an optional field's wire form, a digest
/// spelling, canonical JSON itself — invalidates every published head.
/// **DO NOT update casually.**
#[test]
fn head_known_answer_locks_wire_format_and_signature() {
    trust();
    let unsigned = known_answer_head();

    let canonical = fuz_crypto::canonical_json(&unsigned).unwrap();
    assert_eq!(canonical, KNOWN_ANSWER_CANONICAL);
    let message = SignedMessage::new(&unsigned).unwrap();
    assert_eq!(
        message.as_bytes(),
        [HEAD_TAG, KNOWN_ANSWER_CANONICAL.as_bytes()].concat(),
        "a head's signed bytes are the head tag, then its canonical JSON"
    );

    // The pinned signature is over the tagged bytes, checked with raw ed25519
    // against the literal tag — independent of `SignedMessage`.
    let pinned =
        ed25519_dalek::Signature::from_slice(&base64_decode(KNOWN_ANSWER_SIGNATURE)).unwrap();
    trusted_key()
        .verifying_key()
        .verify(
            &[HEAD_TAG, KNOWN_ANSWER_CANONICAL.as_bytes()].concat(),
            &pinned,
        )
        .expect("the pinned signature covers the head tag + canonical JSON");

    let head = sign_head(unsigned.clone(), &trusted_key(), SIGNED_AT).unwrap();
    let json = head.to_json().unwrap();
    let wire: Value = serde_json::from_str(&json).unwrap();
    assert_eq!(wire["signature"]["format"], SIGNATURE_FORMAT_VERSION);
    assert_eq!(wire["signature"]["public_key"], TRUSTED_PUBLIC_KEY);
    assert_eq!(wire["signature"]["signed_at"], SIGNED_AT);
    assert_eq!(
        wire["signature"]["sig"], KNOWN_ANSWER_SIGNATURE,
        "signature over the canonical head drifted — every published head breaks"
    );

    // The file round-trips: parse → verify under the real trust check →
    // identical content, and re-serializing reproduces the file exactly.
    let verified = Head::from_json(json.as_bytes())
        .unwrap()
        .verify_signature()
        .unwrap();
    assert_eq!(verified.to_unsigned(), unsigned);
    assert_eq!(verified.signed_by(), &trusted_key().verifying_key());
    assert_eq!(verified.signature().sig, KNOWN_ANSWER_SIGNATURE);
    assert_eq!(verified.to_json().unwrap(), json);
}

/// The on-disk form of the known-answer head, pinned in full: field order,
/// indentation, and the trailing newline are what keep `head.json` diffs
/// minimal.
#[test]
fn head_known_answer_on_disk_form() {
    let head = sign_head(known_answer_head(), &trusted_key(), SIGNED_AT).unwrap();
    let json = head.to_json().unwrap();
    let expected_start = r#"{
  "format": 1,
  "seq": 7,
  "keys": [
    {
      "public_key": "6kpsY+KcUgq+9VB7Ey7F+ZVHdq6+vnuSQh7qaRRG0iw=",
      "added_at": "2024-06-01T00:00:00Z",
      "retired_at": "2025-01-01T00:00:00Z"
    },
    {
      "public_key": "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik=",
      "added_at": "2025-01-01T00:00:00Z"
    }
  ],
  "rows": [
    {
      "name": "fuz",
      "version": "0.1.0",
      "status": "ok",
      "published_at": "2025-01-10T00:00:00Z",
      "targets": {
        "aarch64-unknown-linux-gnu": {
          "content_hash": "v1-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
          "binaries": {
            "fuz": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
          },
          "sha512": "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        },
"#;
    assert!(json.starts_with(expected_start), "json:\n{json}");
    let expected_end = r#"        "x86_64-unknown-linux-gnu": {
          "content_hash": "v1-cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
          "binaries": {
            "fuzd": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
          }
        }
      }
    }
  ],
  "signature": {
    "format": 2,
    "public_key": "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik=",
    "algorithm": "ed25519",
    "signed_at": "2025-01-15T10:30:00Z",
    "sig": "p6g0ZZd6F5VXDhTkvmOOMb3K6RTG7Y7/WD93A/FU/GsrkmiR8bjOGFi1kYz4YHl1FiKimPar9x5vda+QpNvTBw=="
  }
}
"#;
    assert!(json.ends_with(expected_end), "json:\n{json}");
}

#[test]
fn key_record_constants_match_their_seeds() {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let encode = |key: &SigningKey| STANDARD.encode(key.verifying_key().as_bytes());
    assert_eq!(encode(&trusted_key()), TRUSTED_PUBLIC_KEY);
    assert_eq!(
        encode(&SigningKey::from_bytes(&[7u8; 32])),
        RETIRED_PUBLIC_KEY
    );
}

//
// Domain separation: a head signature is not a manifest signature
//

/// An envelope of `format` around a raw ed25519 signature, by the trusted
/// key, over exactly `bytes` — so a test chooses the signed bytes, tag and
/// all, without going through `SignedMessage`.
fn raw_signature(bytes: &[u8], format: u32) -> Signature {
    let key = trusted_key();
    Signature {
        format,
        public_key: TRUSTED_PUBLIC_KEY.to_string(),
        algorithm: SignatureAlgorithm::Ed25519,
        signed_at: SIGNED_AT.to_string(),
        sig: {
            use base64::{Engine, engine::general_purpose::STANDARD};
            STANDARD.encode(key.sign(bytes).to_bytes())
        },
    }
}

/// A self manifest, unsigned, that passes `Manifest::from_json`'s structural
/// rules.
fn sample_manifest() -> ManifestUnsigned {
    ManifestUnsigned {
        format: 1,
        version: "0.1.0".to_string(),
        content_hash: format!("v1-{}", "a".repeat(64)),
        target: X86.to_string(),
        minimum_version: None,
        tarball: TarballInfo {
            path: "release.tar.gz".to_string(),
            blake3: b3("b"),
            size: 1000,
        },
        binaries: std::collections::HashMap::from([("fuz".to_string(), b3("c"))]),
        tool: None,
    }
}

fn canonical(value: &impl fuz_crypto::SignedPayload) -> Vec<u8> {
    fuz_crypto::canonical_json(value).unwrap().into_bytes()
}

#[test]
fn a_head_signed_under_the_manifest_tag_is_refused() {
    trust();
    let unsigned = base();
    let json = canonical(&unsigned);

    // Control: the same bytes under the head tag verify.
    let as_head = raw_signature(&[HEAD_TAG, &json].concat(), SIGNATURE_FORMAT_VERSION);
    Head::from_parts(unsigned.clone(), as_head)
        .verify_signature()
        .expect("a head signed under the head tag verifies");

    let as_manifest = raw_signature(&[MANIFEST_TAG, &json].concat(), SIGNATURE_FORMAT_VERSION);
    let result = Head::from_parts(unsigned, as_manifest).verify_signature();
    assert!(
        matches!(
            result,
            Err(ReleaseLogError::Signature(VerifyError::InvalidSignature))
        ),
        "{result:?}"
    );
}

#[test]
fn a_manifest_signed_under_the_head_tag_is_refused() {
    trust();
    let unsigned = sample_manifest();
    let json = canonical(&unsigned);

    // Control: the same bytes under the manifest tag verify.
    let as_manifest = raw_signature(&[MANIFEST_TAG, &json].concat(), SIGNATURE_FORMAT_VERSION);
    Manifest::from_parts(unsigned.clone(), as_manifest)
        .verify_signature()
        .expect("a manifest signed under the manifest tag verifies");

    let as_head = raw_signature(&[HEAD_TAG, &json].concat(), SIGNATURE_FORMAT_VERSION);
    let result = Manifest::from_parts(unsigned, as_head).verify_signature();
    assert!(
        matches!(
            result,
            Err(ManifestError::Signature(VerifyError::InvalidSignature))
        ),
        "{result:?}"
    );
}

/// What `sign_manifest` and `sign_head` produce verifies only as the kind it
/// was made for: each signature, moved onto the other kind's document with
/// the same key, is refused.
#[test]
fn signer_output_verifies_only_as_its_own_kind() {
    trust();
    let manifest = sign_manifest(sample_manifest(), &trusted_key(), SIGNED_AT).unwrap();
    let head = sign_head(base(), &trusted_key(), SIGNED_AT).unwrap();
    let manifest_sig = manifest.signature.clone();
    let head_sig = head.verify_signature().unwrap().signature().clone();

    manifest.verify_signature().expect("manifest as manifest");
    assert!(matches!(
        Head::from_parts(base(), manifest_sig).verify_signature(),
        Err(ReleaseLogError::Signature(VerifyError::InvalidSignature))
    ));
    assert!(matches!(
        Manifest::from_parts(sample_manifest(), head_sig).verify_signature(),
        Err(ManifestError::Signature(VerifyError::InvalidSignature))
    ));
}

/// A current-format envelope over the canonical JSON alone is refused for
/// both kinds: the tag is part of what verification checks.
#[test]
fn an_untagged_signature_is_refused_for_both_kinds() {
    trust();
    let head = base();
    let head_sig = raw_signature(&canonical(&head), SIGNATURE_FORMAT_VERSION);
    assert!(matches!(
        Head::from_parts(head, head_sig).verify_signature(),
        Err(ReleaseLogError::Signature(VerifyError::InvalidSignature))
    ));

    let manifest = sample_manifest();
    let manifest_sig = raw_signature(&canonical(&manifest), SIGNATURE_FORMAT_VERSION);
    assert!(matches!(
        Manifest::from_parts(manifest, manifest_sig).verify_signature(),
        Err(ManifestError::Signature(VerifyError::InvalidSignature))
    ));
}

/// A document signed before domain separation — envelope format 1, the
/// canonical JSON alone — still parses, and is refused at verification by its
/// signature format: the error names the format rather than a failed
/// verification, and is classified with the signature failures.
#[test]
fn a_pre_tag_signature_is_refused_as_an_unsupported_format() {
    trust();
    let unsigned = base();
    let old = raw_signature(&canonical(&unsigned), 1);
    let stored = Head::from_parts(unsigned, old).to_json().unwrap();
    let error = Head::from_json(stored.as_bytes())
        .expect("a pre-tag head still parses")
        .verify_signature()
        .unwrap_err();
    assert!(
        matches!(
            error,
            ReleaseLogError::Signature(VerifyError::UnsupportedFormat(1))
        ),
        "{error:?}"
    );
    assert!(error.is_security_violation());

    let manifest = sample_manifest();
    let old = raw_signature(&canonical(&manifest), 1);
    let stored = serde_json::to_vec(&Manifest::from_parts(manifest, old)).unwrap();
    let error = Manifest::from_json(&stored)
        .expect("a pre-tag manifest still parses")
        .verify_signature()
        .unwrap_err();
    assert!(
        matches!(
            error,
            ManifestError::Signature(VerifyError::UnsupportedFormat(1))
        ),
        "{error:?}"
    );
    assert!(ReleaseError::from(error).is_security_violation());
}

//
// Typestate: nothing is trusted before the signature verifies
//

/// Sign [`base`], edit the serialized document, and parse it back.
fn tampered(edit: impl FnOnce(&mut Value)) -> Head {
    let head = sign_head(base(), &trusted_key(), SIGNED_AT).unwrap();
    let mut value: Value = serde_json::from_str(&head.to_json().unwrap()).unwrap();
    edit(&mut value);
    Head::from_json(&serde_json::to_vec(&value).unwrap()).unwrap()
}

#[track_caller]
fn assert_bad_signature(head: Head) {
    trust();
    let result = head.verify_signature();
    assert!(
        matches!(
            result,
            Err(ReleaseLogError::Signature(VerifyError::InvalidSignature))
        ),
        "expected a failed signature, got {result:?}"
    );
}

#[test]
fn untampered_head_verifies() {
    trust();
    let verified = tampered(|_| {}).verify_signature().unwrap();
    assert_eq!(verified.to_unsigned(), base());
}

#[test]
fn tampered_seq_fails_verification() {
    assert_bad_signature(tampered(|v| v["seq"] = json!(6)));
}

#[test]
fn tampered_row_status_fails_verification() {
    // Un-revoking a release by editing the file.
    assert_bad_signature(tampered(|v| v["rows"][2]["status"] = json!("ok")));
    assert_bad_signature(tampered(|v| v["rows"][0]["status"] = json!("revoked")));
}

#[test]
fn tampered_row_identity_fails_verification() {
    assert_bad_signature(tampered(|v| v["rows"][0]["version"] = json!("0.1.1")));
    assert_bad_signature(tampered(|v| v["rows"][0]["name"] = json!("fuzf")));
    assert_bad_signature(tampered(|v| {
        v["rows"][0]["published_at"] = json!("2025-01-11T00:00:00Z");
    }));
}

#[test]
fn tampered_target_digests_fail_verification() {
    fn target(v: &mut Value) -> &mut Value {
        &mut v["rows"][0]["targets"][X86]
    }
    assert_bad_signature(tampered(|v| {
        target(v)["binaries"]["fuz"] = json!("f".repeat(64));
    }));
    assert_bad_signature(tampered(|v| {
        target(v)["content_hash"] = json!(format!("v1-{}", "f".repeat(64)));
    }));
    assert_bad_signature(tampered(|v| {
        target(v)["sha512"] = json!(ContentHash::sha512(b"other").to_hex());
    }));
    assert_bad_signature(tampered(|v| {
        target(v).as_object_mut().unwrap().remove("sha512");
    }));
}

#[test]
fn tampered_target_set_fails_verification() {
    assert_bad_signature(tampered(|v| {
        let entry = v["rows"][0]["targets"][X86].clone();
        v["rows"][0]["targets"][ARM] = entry;
    }));
}

#[test]
fn tampered_row_set_fails_verification() {
    assert_bad_signature(tampered(|v| {
        v["rows"].as_array_mut().unwrap().pop();
    }));
    assert_bad_signature(tampered(|v| {
        v["rows"].as_array_mut().unwrap().swap(0, 1);
    }));
}

#[test]
fn tampered_key_record_fails_verification() {
    assert_bad_signature(tampered(|v| {
        v["keys"][0].as_object_mut().unwrap().remove("retired_at");
    }));
    assert_bad_signature(tampered(|v| {
        v["keys"][1]["retired_at"] = json!("2025-02-01T00:00:00Z");
    }));
    assert_bad_signature(tampered(|v| {
        v["keys"][1]["added_at"] = json!("2025-01-02T00:00:00Z");
    }));
    assert_bad_signature(tampered(|v| {
        v["keys"].as_array_mut().unwrap().remove(0);
    }));
}

#[test]
fn head_signed_by_untrusted_key_fails_verification() {
    trust();
    let head = sign_head(base(), &untrusted_key(), SIGNED_AT).unwrap();
    let result = head.verify_signature();
    assert!(
        matches!(
            result,
            Err(ReleaseLogError::Signature(VerifyError::UntrustedKey(_)))
        ),
        "{result:?}"
    );
}

#[test]
fn naming_a_key_in_the_key_list_does_not_make_it_trusted() {
    // The `keys` list is record-only: a head that lists its own signing key
    // is exactly as untrusted as one that does not.
    trust();
    let mut unsigned = base();
    let key = untrusted_key();
    unsigned.keys.push(KeyRecord {
        public_key: {
            use base64::{Engine, engine::general_purpose::STANDARD};
            STANDARD.encode(key.verifying_key().as_bytes())
        },
        added_at: "2025-01-02T00:00:00Z".to_string(),
        retired_at: None,
    });
    let result = sign_head(unsigned, &key, SIGNED_AT)
        .unwrap()
        .verify_signature();
    assert!(matches!(
        result,
        Err(ReleaseLogError::Signature(VerifyError::UntrustedKey(_)))
    ));
}

#[test]
fn retiring_a_key_in_the_key_list_does_not_make_it_untrusted() {
    // The converse: trust is the embedded key set alone, so a head recording
    // its signing key as retired still verifies.
    let mut unsigned = base();
    unsigned.keys[1].retired_at = Some("2025-01-14T00:00:00Z".to_string());
    let verified = verified(unsigned);
    assert_eq!(verified.signed_by(), &trusted_key().verifying_key());
}

#[test]
fn signature_claiming_a_trusted_key_it_was_not_made_by_fails_verification() {
    let head = sign_head(base(), &untrusted_key(), SIGNED_AT).unwrap();
    let mut value: Value = serde_json::from_str(&head.to_json().unwrap()).unwrap();
    value["signature"]["public_key"] = json!(TRUSTED_PUBLIC_KEY);
    assert_bad_signature(Head::from_json(&serde_json::to_vec(&value).unwrap()).unwrap());
}

#[test]
fn sign_head_refuses_a_structurally_invalid_head() {
    let mut unsigned = base();
    unsigned.rows.push(unsigned.rows[0].clone());
    let result = sign_head(unsigned, &trusted_key(), SIGNED_AT);
    assert!(matches!(result, Err(ReleaseLogError::Invalid(_))));

    let mut unsigned = base();
    unsigned.format = 2;
    let result = sign_head(unsigned, &trusted_key(), SIGNED_AT);
    assert!(matches!(result, Err(ReleaseLogError::UnsupportedFormat(2))));
}

#[test]
fn sign_head_refuses_a_digest_of_the_wrong_algorithm() {
    // A SHA-256 digest is as long as a BLAKE3 one, so its bare-hex wire form
    // reads back as BLAKE3: only the check on the typed head, made before
    // signing, can refuse it.
    let mut unsigned = base();
    fuz_x86(&mut unsigned)
        .binaries
        .insert("fuz".to_string(), ContentHash::sha256(b"fuz"));
    let result = sign_head(unsigned, &trusted_key(), SIGNED_AT);
    assert!(
        matches!(
            &result,
            Err(ReleaseLogError::Invalid(HeadInvalid::Field {
                field: HeadField::BinaryHash,
                ..
            }))
        ),
        "{result:?}"
    );
}

#[test]
fn sign_head_refuses_format_zero() {
    let mut unsigned = base();
    unsigned.format = 0;
    let result = sign_head(unsigned, &trusted_key(), SIGNED_AT);
    assert!(matches!(result, Err(ReleaseLogError::UnsupportedFormat(0))));
}

#[test]
fn sign_head_refuses_a_signed_at_that_is_not_a_timestamp() {
    let result = sign_head(base(), &trusted_key(), "nope");
    assert!(
        matches!(
            &result,
            Err(ReleaseLogError::Invalid(HeadInvalid::Field {
                field: HeadField::SignedAt,
                ..
            }))
        ),
        "{result:?}"
    );
}

#[test]
fn rewritten_signed_at_still_verifies_and_decides_nothing() {
    // `signed_at` is outside the signed bytes: a relay can replace it with
    // another well-formed timestamp and the head verifies as before. The
    // content, the signing key, and every rule outcome are unchanged.
    let original = verified(base());
    let relayed = tampered(|v| v["signature"]["signed_at"] = json!("1999-01-01T00:00:00Z"))
        .verify_signature()
        .unwrap();
    assert_eq!(relayed.signature().signed_at, "1999-01-01T00:00:00Z");
    assert_eq!(relayed.to_unsigned(), original.to_unsigned());
    assert_eq!(relayed.signed_by(), original.signed_by());
    assert_eq!(
        check_consistent(&original, &relayed),
        Ok(HeadOrder::Identical)
    );
}

#[test]
fn re_encoded_signature_fields_do_not_verify() {
    // The signature's other fields have one accepted spelling each: base64 is
    // decoded strictly (canonical padding, no stray trailing bits), and the
    // format and algorithm are fixed values.
    let sig_of = |v: &Value, field: &str| v["signature"][field].as_str().unwrap().to_string();
    let reject = |edit: &dyn Fn(&mut Value)| {
        trust();
        let result = tampered(|v| edit(v)).verify_signature();
        assert!(
            matches!(result, Err(ReleaseLogError::Signature(_))),
            "{result:?}"
        );
    };
    for field in ["sig", "public_key"] {
        // Padding dropped.
        reject(&|v| {
            let value = sig_of(v, field);
            v["signature"][field] = json!(value.trim_end_matches('='));
        });
        // The last data character changed within its unused low bits.
        reject(&|v| {
            let value = sig_of(v, field);
            let data = value.trim_end_matches('=');
            let (head, last) = data.split_at(data.len() - 1);
            let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            let index = alphabet.find(last).unwrap();
            let alias = alphabet.as_bytes()[index ^ 1] as char;
            let padding = &value[data.len()..];
            v["signature"][field] = json!(format!("{head}{alias}{padding}"));
        });
    }
    reject(&|v| v["signature"]["format"] = json!(SIGNATURE_FORMAT_VERSION - 1));
    reject(&|v| v["signature"]["format"] = json!(SIGNATURE_FORMAT_VERSION + 1));
    let head = sign_head(base(), &trusted_key(), SIGNED_AT).unwrap();
    let mut value: Value = serde_json::from_str(&head.to_json().unwrap()).unwrap();
    value["signature"]["algorithm"] = json!("ED25519");
    let result = Head::from_json(&serde_json::to_vec(&value).unwrap());
    assert!(matches!(result, Err(ReleaseLogError::Parse(_))));
}

//
// Size: a publisher cannot sign a head a reader would refuse
//

/// A head of `rows` equal-sized filler rows plus one final row whose tokens
/// carry `pad` extra bytes, so the document's size can be set to the byte.
fn sized_head(rows: usize, pad: usize) -> HeadUnsigned {
    /// Extra bytes one token can absorb and stay a valid token.
    const TOKEN_ROOM: usize = 120;
    assert!(
        pad <= 4 * TOKEN_ROOM,
        "pad {pad} exceeds the final row's room"
    );
    let token = |index: usize| {
        format!(
            "p{}",
            "x".repeat(pad.saturating_sub(index * TOKEN_ROOM).min(TOKEN_ROOM))
        )
    };

    let mut head = HeadUnsigned {
        format: 1,
        seq: 1,
        keys: Vec::new(),
        rows: (0..rows)
            .map(|index| {
                row(
                    "fuz",
                    &format!("0.0.{index:06}"),
                    RowStatus::Ok,
                    &[(X86, target_row("a", "fuz", None))],
                )
            })
            .collect(),
    };
    let mut entry = target_row("a", "fuz", None);
    entry.binaries = BTreeMap::from([(token(3), b3("a"))]);
    head.rows.push(row(
        &token(0),
        &token(1),
        RowStatus::Ok,
        &[(token(2).as_str(), entry)],
    ));
    head
}

/// The on-disk size `head` signs to. The signature's length does not depend
/// on the content, so this is measured without going through `sign_head`.
fn signed_size(head: HeadUnsigned) -> u64 {
    let signature = raw_signature(b"", SIGNATURE_FORMAT_VERSION);
    Head::from_parts(head, signature).to_json().unwrap().len() as u64
}

/// Filler-row count and final-row padding that put the signed document at
/// exactly `MAX_HEAD_SIZE`.
fn head_at_the_size_limit() -> (usize, usize) {
    let base = signed_size(sized_head(0, 0));
    let per_row = signed_size(sized_head(1, 0)) - base;
    let rows = (MAX_HEAD_SIZE - base) / per_row;
    let pad = MAX_HEAD_SIZE - base - rows * per_row;
    (
        usize::try_from(rows).unwrap(),
        usize::try_from(pad).unwrap(),
    )
}

#[test]
fn sign_head_accepts_a_head_at_the_size_limit_and_readers_accept_it() {
    trust();
    let (rows, pad) = head_at_the_size_limit();
    let head = sign_head(sized_head(rows, pad), &trusted_key(), SIGNED_AT).unwrap();
    let json = head.to_json().unwrap();
    assert_eq!(json.len() as u64, MAX_HEAD_SIZE);
    // What was signed is what a reader is handed, and the reader takes it.
    let verified = Head::from_json(json.as_bytes())
        .unwrap()
        .verify_signature()
        .unwrap();
    assert_eq!(verified.rows().len(), rows + 1);
}

#[test]
fn sign_head_refuses_a_head_one_byte_over_the_size_limit() {
    let (rows, pad) = head_at_the_size_limit();
    let unsigned = sized_head(rows, pad + 1);
    // Structurally valid, and its canonical form is well under the limit: only
    // the on-disk document is too large.
    unsigned.validate().unwrap();
    assert!((fuz_crypto::canonical_json(&unsigned).unwrap().len() as u64) < MAX_HEAD_SIZE);

    let result = sign_head(unsigned, &trusted_key(), SIGNED_AT);
    assert!(
        matches!(result, Err(ReleaseLogError::TooLarge(size)) if size == MAX_HEAD_SIZE + 1),
        "{result:?}"
    );
}

#[test]
fn verify_signature_refuses_a_head_it_could_not_write_back() {
    // Signed around `sign_head` and delivered compact: the bytes are under the
    // limit, so a reader parses them, while the head's own on-disk document is
    // one byte over.
    trust();
    let (rows, pad) = head_at_the_size_limit();
    let unsigned = sized_head(rows, pad + 1);
    let message = SignedMessage::new(&unsigned).unwrap();
    let signature = raw_signature(message.as_bytes(), SIGNATURE_FORMAT_VERSION);
    let pretty = Head::from_parts(unsigned, signature).to_json().unwrap();
    assert_eq!(pretty.len() as u64, MAX_HEAD_SIZE + 1);

    let compact = serde_json::to_vec(&serde_json::from_str::<Value>(&pretty).unwrap()).unwrap();
    assert!((compact.len() as u64) < MAX_HEAD_SIZE);
    let head = Head::from_json(&compact).unwrap();

    let result = head.verify_signature();
    assert!(
        matches!(result, Err(ReleaseLogError::TooLarge(size)) if size == MAX_HEAD_SIZE + 1),
        "{result:?}"
    );
}

#[test]
fn oversized_head_with_a_bad_signature_is_reported_as_a_bad_signature() {
    // The signature is checked before the write-back size: a head that fails
    // both is a forgery, not an oversized document.
    trust();
    let (rows, pad) = head_at_the_size_limit();
    let other = SignedMessage::new(&base()).unwrap();
    let signature = raw_signature(other.as_bytes(), SIGNATURE_FORMAT_VERSION);
    let result = Head::from_parts(sized_head(rows, pad + 1), signature).verify_signature();
    assert!(
        matches!(
            result,
            Err(ReleaseLogError::Signature(VerifyError::InvalidSignature))
        ),
        "{result:?}"
    );
}

#[test]
fn compact_delivery_of_a_head_within_the_limit_verifies_and_writes_back() {
    trust();
    let (rows, pad) = head_at_the_size_limit();
    let pretty = sign_head(sized_head(rows, pad), &trusted_key(), SIGNED_AT)
        .unwrap()
        .to_json()
        .unwrap();
    let compact = serde_json::to_vec(&serde_json::from_str::<Value>(&pretty).unwrap()).unwrap();
    let verified = Head::from_json(&compact)
        .unwrap()
        .verify_signature()
        .unwrap();
    assert_eq!(verified.to_json().unwrap(), pretty);
}

#[test]
fn verification_failure_is_a_security_violation_at_the_release_error_level() {
    trust();
    let error = sign_head(base(), &untrusted_key(), SIGNED_AT)
        .unwrap()
        .verify_signature()
        .unwrap_err();
    assert!(error.is_security_violation());
    assert!(ReleaseError::from(error).is_security_violation());
}

//
// Lookups
//

#[test]
fn row_and_target_lookups() {
    let head = verified(base());
    assert_eq!(head.seq(), 5);
    assert_eq!(head.rows().len(), 3);
    assert_eq!(head.keys().len(), 2);

    let row = head.row("fuz", "0.1.0").unwrap();
    assert_eq!(row.status, RowStatus::Ok);
    // Both halves of the identity must match.
    assert!(head.row("fuz", "0.0.9").is_none());
    assert!(head.row("fuzf", "0.1.0").is_none());
    // A revoked row is found, and says so.
    assert_eq!(
        head.row("fuzd", "0.0.9").unwrap().status,
        RowStatus::Revoked
    );

    let target = head.target("fuz", "0.1.0", X86).unwrap();
    assert_eq!(target.binaries["fuz"], b3("a"));
    assert_eq!(target.sha512, Some(ContentHash::sha512(b"fuz x86")));
    assert!(head.target("fuz", "0.1.0", ARM).is_none());
    assert!(head.target("fuz", "9.9.9", X86).is_none());
    assert!(head.target("fuzd", "0.1.0", X86).unwrap().sha512.is_none());
}

//
// Rule: seq
//

#[test]
fn cached_seq_greater_than_fresh_is_a_regression() {
    // The fresh head is an honest earlier state — a prefix of the cached one —
    // and is still refused as a successor.
    let (older, newer) = base_and_next(|h| {
        h.rows.push(row(
            "fuz",
            "0.2.0",
            RowStatus::Ok,
            &[(X86, target_row("d", "fuz", Some(b"fuz 0.2.0")))],
        ));
    });
    assert_eq!(
        check_successor(&newer, &older),
        Err(HeadViolation::SeqRegressed {
            cached: 6,
            fresh: 5
        })
    );
}

#[test]
fn same_seq_different_content_is_seq_reuse() {
    let a = verified(base());
    let mut other = base();
    other.rows.push(row(
        "fuz",
        "0.2.0",
        RowStatus::Ok,
        &[(X86, target_row("d", "fuz", None))],
    ));
    // A superset in content, but claiming the same `seq`.
    let b = verified(other);
    assert_eq!(check_superset(&a, &b), Ok(()));
    let expected = Err(HeadViolation::SeqReused { seq: 5 });
    assert_eq!(check_successor(&a, &b), expected);
    assert_eq!(check_successor(&b, &a), expected);
    assert_eq!(
        check_consistent(&a, &b),
        Err(HeadViolation::SeqReused { seq: 5 })
    );
}

#[test]
fn same_seq_identical_content_is_the_same_head() {
    let a = verified(base());
    // Signed again, at another time: still the same head.
    trust();
    let b = sign_head(base(), &trusted_key(), "2025-03-01T00:00:00Z")
        .unwrap()
        .verify_signature()
        .unwrap();
    assert_ne!(a.signature().signed_at, b.signature().signed_at);
    assert_eq!(check_successor(&a, &b), Ok(Succession::Unchanged));
    assert_eq!(check_consistent(&a, &b), Ok(HeadOrder::Identical));
    assert_eq!(check_superset(&a, &b), Ok(()));
}

#[test]
fn same_seq_differing_only_in_key_records_is_seq_reuse() {
    // Rows identical; one key record gains a `retired_at`. Still two different
    // heads under one `seq`.
    let a = verified(base());
    let mut other = base();
    other.keys[1].retired_at = Some("2025-02-01T00:00:00Z".to_string());
    let b = verified(other);
    let expected = HeadViolation::SeqReused { seq: 5 };
    assert_eq!(check_consistent(&a, &b).as_ref(), Err(&expected));
    assert_eq!(check_consistent(&b, &a).as_ref(), Err(&expected));
    assert_eq!(check_successor(&a, &b).as_ref(), Err(&expected));
    assert_eq!(check_successor(&b, &a).as_ref(), Err(&expected));
}

#[test]
fn seq_may_skip_ahead() {
    assert_advances(|h| h.seq += 40);
}

#[test]
fn seq_bump_alone_advances() {
    assert_advances(|_| {});
}

//
// Rule: rows
//

#[test]
fn row_added_at_the_end_advances() {
    assert_advances(|h| {
        h.rows.push(row(
            "fuz",
            "0.2.0",
            RowStatus::Ok,
            &[(X86, target_row("d", "fuz", Some(b"fuz 0.2.0")))],
        ));
    });
}

#[test]
fn row_added_already_revoked_advances() {
    assert_advances(|h| {
        h.rows.push(row(
            "zap",
            "0.1.0",
            RowStatus::Revoked,
            &[(X86, target_row("d", "zap", None))],
        ));
    });
}

#[test]
fn row_removed_is_a_violation() {
    assert_violation(
        |h| {
            h.rows.pop();
        },
        &row_violation(
            |name, version| HeadViolation::RowRemoved { name, version },
            "fuzd",
            "0.0.9",
        ),
    );
    assert_violation(
        |h| {
            h.rows.remove(0);
        },
        &row_violation(
            |name, version| HeadViolation::RowRemoved { name, version },
            "fuz",
            "0.1.0",
        ),
    );
}

#[test]
fn row_name_changed_is_a_removed_row() {
    // `(name, version)` is the row's identity, so renaming one is removing it.
    assert_violation(
        |h| h.rows[1].name = "fuzf".to_string(),
        &row_violation(
            |name, version| HeadViolation::RowRemoved { name, version },
            "fuzd",
            "0.1.0",
        ),
    );
}

#[test]
fn row_version_changed_is_a_removed_row() {
    assert_violation(
        |h| h.rows[0].version = "0.1.1".to_string(),
        &row_violation(
            |name, version| HeadViolation::RowRemoved { name, version },
            "fuz",
            "0.1.0",
        ),
    );
}

#[test]
fn row_published_at_changed_is_a_violation() {
    assert_violation(
        |h| h.rows[0].published_at = "2025-01-11T00:00:00Z".to_string(),
        &row_violation(
            |name, version| HeadViolation::PublishedAtChanged { name, version },
            "fuz",
            "0.1.0",
        ),
    );
}

#[test]
fn rows_reordered_is_a_violation() {
    assert_violation(
        |h| h.rows.swap(0, 1),
        &row_violation(
            |name, version| HeadViolation::RowMoved { name, version },
            "fuz",
            "0.1.0",
        ),
    );
}

#[test]
fn row_inserted_before_existing_rows_is_a_violation() {
    // Every old row is still present, but no longer at its position: rows are
    // appended, never inserted.
    assert_violation(
        |h| {
            h.rows.insert(
                0,
                row(
                    "fuz",
                    "0.0.1",
                    RowStatus::Ok,
                    &[(X86, target_row("d", "fuz", None))],
                ),
            );
        },
        &row_violation(
            |name, version| HeadViolation::RowMoved { name, version },
            "fuz",
            "0.1.0",
        ),
    );
}

#[test]
fn new_row_duplicating_an_existing_row_cannot_be_signed_or_read() {
    // A second row for an existing `(name, version)` — the way to shadow what
    // a release pins — is not a rule violation between two heads: no such
    // head exists. Signing refuses it, and so does parsing.
    let mut unsigned = base();
    unsigned.seq += 1;
    unsigned.rows.push(row(
        "fuz",
        "0.1.0",
        RowStatus::Ok,
        &[(X86, target_row("f", "fuz", Some(b"evil")))],
    ));
    let result = sign_head(unsigned.clone(), &trusted_key(), SIGNED_AT);
    assert!(matches!(result, Err(ReleaseLogError::Invalid(_))));

    // Hand-assembled around the signer's check, it is refused at parse.
    let duplicate = serde_json::to_value(&unsigned.rows[3]).unwrap();
    let head = sign_head(base(), &trusted_key(), SIGNED_AT).unwrap();
    let mut value: Value = serde_json::from_str(&head.to_json().unwrap()).unwrap();
    value["rows"].as_array_mut().unwrap().push(duplicate);
    let result = Head::from_json(&serde_json::to_vec(&value).unwrap());
    assert!(matches!(result, Err(ReleaseLogError::Invalid(_))));
}

//
// Rule: status
//

#[test]
fn ok_to_revoked_advances() {
    assert_advances(|h| h.rows[0].status = RowStatus::Revoked);
}

#[test]
fn revoked_to_ok_is_a_violation() {
    assert_violation(
        |h| h.rows[2].status = RowStatus::Ok,
        &row_violation(
            |name, version| HeadViolation::RevocationUndone { name, version },
            "fuzd",
            "0.0.9",
        ),
    );
}

//
// Rule: targets
//

#[test]
fn target_added_advances() {
    assert_advances(|h| {
        h.rows[0]
            .targets
            .insert(ARM.to_string(), target_row("e", "fuz", Some(b"fuz arm")));
    });
}

#[test]
fn target_removed_is_a_violation() {
    assert_violation(
        |h| {
            // Swap the target for another, so the row still has one.
            let entry = h.rows[0].targets.remove(X86).unwrap();
            h.rows[0].targets.insert(ARM.to_string(), entry);
        },
        &HeadViolation::TargetRemoved {
            name: "fuz".to_string(),
            version: "0.1.0".to_string(),
            target: X86.to_string(),
        },
    );
}

#[test]
fn target_content_hash_changed_is_a_violation() {
    assert_violation(
        |h| fuz_x86(h).content_hash = format!("v1-{}", "f".repeat(64)),
        &target_changed(TargetField::ContentHash),
    );
}

#[test]
fn every_target_of_a_row_is_held_fixed_not_only_the_first() {
    // Two targets recorded; the first in map order is untouched and the last
    // is changed.
    let mut old = base();
    old.rows[0]
        .targets
        .insert(ARM.to_string(), target_row("e", "fuz", Some(b"fuz arm")));
    assert_eq!(old.rows[0].targets.keys().next().unwrap(), ARM);
    let mut new = old.clone();
    new.seq += 1;
    fuz_x86(&mut new).content_hash = format!("v1-{}", "f".repeat(64));

    let (old, new) = (verified(old), verified(new));
    let expected = target_changed(TargetField::ContentHash);
    assert_eq!(check_superset(&old, &new).as_ref(), Err(&expected));
    assert_eq!(check_successor(&old, &new).as_ref(), Err(&expected));
    assert_eq!(check_consistent(&new, &old).as_ref(), Err(&expected));
}

#[test]
fn every_target_of_a_row_is_held_fixed_not_only_the_last() {
    // The mirror case: the last target in map order is untouched and the
    // first is changed.
    let mut old = base();
    old.rows[0]
        .targets
        .insert(ARM.to_string(), target_row("e", "fuz", Some(b"fuz arm")));
    assert_eq!(old.rows[0].targets.keys().next_back().unwrap(), X86);
    let mut new = old.clone();
    new.seq += 1;
    new.rows[0].targets.get_mut(ARM).unwrap().content_hash = format!("v1-{}", "f".repeat(64));

    let (old, new) = (verified(old), verified(new));
    let expected = HeadViolation::TargetChanged {
        name: "fuz".to_string(),
        version: "0.1.0".to_string(),
        target: ARM.to_string(),
        field: TargetField::ContentHash,
    };
    assert_eq!(check_superset(&old, &new).as_ref(), Err(&expected));
    assert_eq!(check_successor(&old, &new).as_ref(), Err(&expected));
    assert_eq!(check_consistent(&new, &old).as_ref(), Err(&expected));
}

#[test]
fn target_binary_hash_changed_is_a_violation() {
    assert_violation(
        |h| {
            fuz_x86(h).binaries.insert("fuz".to_string(), b3("f"));
        },
        &target_changed(TargetField::Binaries),
    );
}

#[test]
fn target_binary_added_is_a_violation() {
    // The target *map* grows; an existing target's entry does not.
    assert_violation(
        |h| {
            fuz_x86(h).binaries.insert("fuzx".to_string(), b3("f"));
        },
        &target_changed(TargetField::Binaries),
    );
}

#[test]
fn target_binary_removed_is_a_violation() {
    assert_violation(
        |h| {
            let entry = fuz_x86(h);
            entry.binaries.clear();
            entry.binaries.insert("fuzx".to_string(), b3("a"));
        },
        &target_changed(TargetField::Binaries),
    );
}

#[test]
fn target_sha512_changed_is_a_violation() {
    assert_violation(
        |h| fuz_x86(h).sha512 = Some(ContentHash::sha512(b"other")),
        &target_changed(TargetField::Sha512),
    );
}

#[test]
fn target_sha512_dropped_is_a_violation() {
    assert_violation(
        |h| fuz_x86(h).sha512 = None,
        &target_changed(TargetField::Sha512),
    );
}

#[test]
fn target_sha512_added_to_an_existing_entry_is_a_violation() {
    // Not growth: an existing entry is immutable in full, so a digest that
    // earlier readers were never shown cannot appear on it later.
    assert_violation(
        |h| h.rows[1].targets.get_mut(X86).unwrap().sha512 = Some(ContentHash::sha512(b"fuzd")),
        &HeadViolation::TargetChanged {
            name: "fuzd".to_string(),
            version: "0.1.0".to_string(),
            target: X86.to_string(),
            field: TargetField::Sha512,
        },
    );
}

//
// Rule: key records
//

fn key_violation(make: fn(String) -> HeadViolation, public_key: &str) -> HeadViolation {
    make(public_key.to_string())
}

#[test]
fn key_record_added_advances() {
    assert_advances(|h| {
        h.keys.push(KeyRecord {
            public_key: "A".repeat(43) + "=",
            added_at: "2025-02-01T00:00:00Z".to_string(),
            retired_at: None,
        });
    });
}

#[test]
fn key_record_retired_advances() {
    assert_advances(|h| h.keys[1].retired_at = Some("2025-02-01T00:00:00Z".to_string()));
}

#[test]
fn key_record_removed_is_a_violation() {
    assert_violation(
        |h| {
            h.keys.remove(0);
        },
        &key_violation(
            |public_key| HeadViolation::KeyRemoved { public_key },
            RETIRED_PUBLIC_KEY,
        ),
    );
}

#[test]
fn key_records_reordered_is_a_violation() {
    assert_violation(
        |h| h.keys.swap(0, 1),
        &key_violation(
            |public_key| HeadViolation::KeyMoved { public_key },
            RETIRED_PUBLIC_KEY,
        ),
    );
}

#[test]
fn key_record_added_at_changed_is_a_violation() {
    assert_violation(
        |h| h.keys[1].added_at = "2025-01-02T00:00:00Z".to_string(),
        &key_violation(
            |public_key| HeadViolation::KeyAddedAtChanged { public_key },
            TRUSTED_PUBLIC_KEY,
        ),
    );
}

#[test]
fn key_record_retired_at_changed_is_a_violation() {
    assert_violation(
        |h| h.keys[0].retired_at = Some("2025-01-02T00:00:00Z".to_string()),
        &key_violation(
            |public_key| HeadViolation::KeyRetiredAtChanged { public_key },
            RETIRED_PUBLIC_KEY,
        ),
    );
}

#[test]
fn key_record_retired_at_unset_is_a_violation() {
    assert_violation(
        |h| h.keys[0].retired_at = None,
        &key_violation(
            |public_key| HeadViolation::KeyRetiredAtChanged { public_key },
            RETIRED_PUBLIC_KEY,
        ),
    );
}

//
// Rule: consistency between two origins
//

/// Two successors of [`base`] that each add a different release.
fn diverged() -> (VerifiedHead, VerifiedHead) {
    let mut left = base();
    left.seq = 6;
    left.rows.push(row(
        "fuz",
        "0.2.0",
        RowStatus::Ok,
        &[(X86, target_row("d", "fuz", None))],
    ));
    let mut right = base();
    right.seq = 7;
    right.rows.push(row(
        "zap",
        "0.1.0",
        RowStatus::Ok,
        &[(X86, target_row("e", "zap", None))],
    ));
    (verified(left), verified(right))
}

#[test]
fn lagging_mirror_is_consistent_and_names_the_newer_head() {
    let (mirror, origin) = base_and_next(|h| {
        h.rows[0].status = RowStatus::Revoked;
        h.rows.push(row(
            "fuz",
            "0.1.1",
            RowStatus::Ok,
            &[(X86, target_row("d", "fuz", Some(b"fuz 0.1.1")))],
        ));
    });
    assert_eq!(
        check_consistent(&mirror, &origin),
        Ok(HeadOrder::SecondNewer)
    );
    assert_eq!(
        check_consistent(&origin, &mirror),
        Ok(HeadOrder::FirstNewer)
    );
}

#[test]
fn identical_heads_are_consistent() {
    let a = verified(base());
    let b = verified(base());
    assert_eq!(check_consistent(&a, &b), Ok(HeadOrder::Identical));
    assert_eq!(check_consistent(&a, &a), Ok(HeadOrder::Identical));
}

#[test]
fn diverged_heads_are_a_contradiction_in_either_order() {
    // Neither contains the other: each records a release the other lacks.
    let (left, right) = diverged();
    let expected = HeadViolation::RowRemoved {
        name: "fuz".to_string(),
        version: "0.2.0".to_string(),
    };
    assert_eq!(check_consistent(&left, &right).as_ref(), Err(&expected));
    assert_eq!(check_consistent(&right, &left).as_ref(), Err(&expected));
    assert_eq!(check_successor(&left, &right).as_ref(), Err(&expected));
}

#[test]
fn diverged_heads_at_the_same_seq_are_a_contradiction() {
    let (left, right) = diverged();
    let mut right = right.to_unsigned();
    right.seq = left.seq();
    let right = verified(right);
    assert_eq!(
        check_consistent(&left, &right),
        Err(HeadViolation::SeqReused { seq: 6 })
    );
}

#[test]
fn higher_seq_that_is_not_a_superset_is_a_contradiction() {
    // The newer-by-`seq` head is missing a revocation the older one records.
    let mut revoking = base();
    revoking.rows[0].status = RowStatus::Revoked;
    let older = verified(revoking);
    let mut newer = base();
    newer.seq = 9;
    let newer = verified(newer);
    let expected = Err(HeadViolation::RevocationUndone {
        name: "fuz".to_string(),
        version: "0.1.0".to_string(),
    });
    assert_eq!(check_consistent(&older, &newer), expected);
    assert_eq!(check_consistent(&newer, &older), expected);
}

#[test]
fn consistency_is_transitive_across_a_chain_of_heads() {
    let first = verified(base());
    let mut second = first.to_unsigned();
    second.seq += 1;
    second.rows[0]
        .targets
        .insert(ARM.to_string(), target_row("e", "fuz", Some(b"fuz arm")));
    let second = verified(second);
    let mut third = second.to_unsigned();
    third.seq += 1;
    third.rows[1].status = RowStatus::Revoked;
    let third = verified(third);

    assert_eq!(check_successor(&first, &second), Ok(Succession::Advanced));
    assert_eq!(check_successor(&second, &third), Ok(Succession::Advanced));
    // Skipping the intermediate head changes nothing.
    assert_eq!(check_successor(&first, &third), Ok(Succession::Advanced));
    assert_eq!(check_consistent(&third, &first), Ok(HeadOrder::FirstNewer));
}

#[test]
fn rule_violations_are_security_violations_at_every_wrapper_level() {
    let (left, right) = diverged();
    let violation = check_consistent(&left, &right).unwrap_err();
    let error = ReleaseLogError::from(violation);
    assert!(error.is_security_violation());
    assert!(ReleaseError::from(error).is_security_violation());
}
