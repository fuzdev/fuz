//! Signature creation.
//!
//! The signing half of the ed25519 surface (the verifying half stays in
//! `fuz_crypto`). `sign_manifest` signs a release manifest and `sign_head` a
//! release log head, each through the crate-private `sign_message`, which
//! signs a `fuz_crypto::SignedMessage` — a document kind's domain tag followed
//! by its canonical JSON — into a `fuz_crypto::Signature`. There is no public
//! signing entry point below the typed documents, and no raw sign-any-bytes
//! one: every signature this crate makes is over a typed document's signed
//! bytes, so a release key never signs bytes a verifier could read as another
//! kind.

use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signer, SigningKey};
use fuz_crypto::{SIGNATURE_FORMAT_VERSION, Signature, SignatureAlgorithm, SignedMessage};
use fuz_release::{Head, HeadUnsigned, Manifest, ManifestError, ManifestUnsigned, ReleaseLogError};

/// Sign a document's signed bytes with a signing key.
///
/// Returns a [`Signature`] in the current envelope format
/// ([`SIGNATURE_FORMAT_VERSION`]) with embedded public key, algorithm,
/// timestamp, and signature. The caller provides the timestamp to allow
/// testing with fixed times.
pub(crate) fn sign_message(
    message: &SignedMessage,
    key: &SigningKey,
    signed_at: &str,
) -> Signature {
    // ed25519-dalek handles hashing internally per RFC 8032
    let sig = key.sign(message.as_bytes());

    Signature {
        format: SIGNATURE_FORMAT_VERSION,
        public_key: STANDARD.encode(key.verifying_key().as_bytes()),
        algorithm: SignatureAlgorithm::Ed25519,
        signed_at: signed_at.to_string(),
        sig: STANDARD.encode(sig.to_bytes()),
    }
}

/// Create a signed manifest from unsigned data.
///
/// Signs the unsigned manifest's signed bytes (the manifest tag, then its
/// canonical JSON) with the provided key. The consumer side verifies with
/// `Manifest::verify_signature` (`fuz_crypto::verify_signature` against the
/// embedded public keys).
///
/// # Errors
///
/// Returns [`ManifestError::Canonical`] if canonical-JSON serialization fails.
pub fn sign_manifest(
    unsigned: ManifestUnsigned,
    key: &SigningKey,
    signed_at: &str,
) -> Result<Manifest, ManifestError> {
    let message = SignedMessage::new(&unsigned)?;
    let signature = sign_message(&message, key, signed_at);

    Ok(Manifest::from_parts(unsigned, signature))
}

/// Create a signed release log head from unsigned data.
///
/// Validates the head's structure, signs the unsigned head's signed bytes (the
/// head tag, then its canonical JSON) with the provided key — the manifest's
/// envelope under a different tag — and then reads the on-disk document
/// (`Head::to_json`, the single serializer) back through `Head::from_json`.
/// The head returned is one a reader accepted, so a publisher cannot sign a
/// head a reader would refuse — for its structure, its size, or its
/// `signed_at`. The consumer side verifies with `Head::verify_signature`.
///
/// # Errors
///
/// Returns [`ReleaseLogError::UnsupportedFormat`] / [`ReleaseLogError::Invalid`]
/// if the head or `signed_at` breaks a structural rule,
/// [`ReleaseLogError::Canonical`] if canonical-JSON serialization fails, and
/// [`ReleaseLogError::TooLarge`] if the signed document exceeds
/// `MAX_HEAD_SIZE`.
pub fn sign_head(
    unsigned: HeadUnsigned,
    key: &SigningKey,
    signed_at: &str,
) -> Result<Head, ReleaseLogError> {
    unsigned.validate()?;
    let message = SignedMessage::new(&unsigned)?;
    let signature = sign_message(&message, key, signed_at);
    let head = Head::from_parts(unsigned, signature);

    // Read the document back as a reader would: the same size guard, strict
    // parse, and structural rules, applied to the bytes `Head::to_json` writes.
    Head::from_json(head.to_json()?.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::generate_keypair;
    use ed25519_dalek::Verifier;
    use fuz_crypto::{ContentHash, HashAlgo};
    use std::collections::HashMap;

    /// Build a blake3 `ContentHash` from a bare-hex string (test fixtures).
    fn ch(hex: &str) -> ContentHash {
        ContentHash::from_hex(HashAlgo::Blake3, hex).unwrap()
    }

    /// A valid self (`tool: None`) unsigned manifest declaring `fuz`
    /// (`SELF_BINARIES`), so `Manifest::from_json` validation accepts it.
    fn sample_self_unsigned() -> ManifestUnsigned {
        ManifestUnsigned {
            format: 1,
            version: "0.3.0".to_string(),
            content_hash: "v1-abc1230000000000000000000000000000000000000000000000000000000000"
                .to_string(),
            target: fuz_release::current_target().to_string(),
            minimum_version: None,
            tarball: fuz_release::TarballInfo {
                path: "release.tar.gz".to_string(),
                blake3: ch(&"d".repeat(64)),
                size: 1000,
            },
            binaries: {
                let mut h = HashMap::new();
                h.insert("fuz".to_string(), ch(&"a".repeat(64)));
                h
            },
            tool: None,
        }
    }

    /// The manifest domain tag, spelled out (pinned as a literal; the
    /// definition is `fuz_crypto::SignedPayloadKind::tag`).
    const MANIFEST_TAG: &[u8] = b"fuz-manifest-v1\0";

    #[test]
    fn sign_message_produces_verifiable_signature() {
        let key = generate_keypair();
        let unsigned = sample_self_unsigned();
        let message = SignedMessage::new(&unsigned).expect("canonical");
        let sig = sign_message(&message, &key, "2025-01-15T12:00:00Z");

        assert_eq!(sig.format, SIGNATURE_FORMAT_VERSION);
        assert_eq!(sig.algorithm, SignatureAlgorithm::Ed25519);
        assert_eq!(sig.signed_at, "2025-01-15T12:00:00Z");
        assert_eq!(
            sig.public_key,
            STANDARD.encode(key.verifying_key().as_bytes())
        );

        // Raw ed25519 verification (bypasses the trust check, which only admits
        // keys embedded in fuz_crypto::PUBLIC_KEYS).
        let sig_bytes = STANDARD.decode(&sig.sig).expect("decode sig");
        let signature = ed25519_dalek::Signature::from_slice(&sig_bytes).expect("parse sig");
        let canonical = fuz_crypto::canonical_json(&unsigned).expect("canonical");
        key.verifying_key()
            .verify(&[MANIFEST_TAG, canonical.as_bytes()].concat(), &signature)
            .expect("the signature covers the manifest tag, then the canonical JSON");
        assert!(
            key.verifying_key()
                .verify(canonical.as_bytes(), &signature)
                .is_err(),
            "the signature does not cover the canonical JSON alone"
        );
    }

    #[test]
    fn sign_manifest_copies_fields_and_signs_the_tagged_canonical_json() {
        let key = generate_keypair();
        let unsigned = ManifestUnsigned {
            format: 1,
            version: "0.1.0".to_string(),
            content_hash: "v1-abc1230000000000000000000000000000000000000000000000000000000000"
                .to_string(),
            target: fuz_release::current_target().to_string(),
            minimum_version: None,
            tarball: fuz_release::TarballInfo {
                path: "release.tar.gz".to_string(),
                blake3: ch(&"d".repeat(64)),
                size: 1000,
            },
            binaries: {
                let mut h = HashMap::new();
                h.insert("zap".to_string(), ch(&"c".repeat(64)));
                h
            },
            tool: Some("zap".to_string()),
        };

        let manifest = sign_manifest(unsigned.clone(), &key, "2025-01-15T10:30:00Z")
            .expect("sign should succeed");

        // Fields copy through verbatim.
        assert_eq!(manifest.version, "0.1.0");
        assert_eq!(manifest.tool.as_deref(), Some("zap"));

        // The embedded signature is over the manifest tag, then the canonical
        // JSON of the unsigned data.
        let canonical = fuz_crypto::canonical_json(&unsigned).expect("canonical");
        let sig_bytes = STANDARD
            .decode(&manifest.signature.sig)
            .expect("decode sig");
        let signature = ed25519_dalek::Signature::from_slice(&sig_bytes).expect("parse sig");
        key.verifying_key()
            .verify(&[MANIFEST_TAG, canonical.as_bytes()].concat(), &signature)
            .expect("manifest signature should verify against the tagged canonical JSON");
    }

    #[test]
    fn canonical_json_uses_bare_hex_and_is_byte_stable() {
        // GATE: `ContentHash` must keep the signed canonical JSON
        // byte-identical to a bare-hex `String` shape — otherwise it
        // invalidates every existing manifest signature. A self manifest with
        // fixed inputs canonicalizes to exactly this, with hash fields as BARE
        // lowercase hex (no `blake3:` prefix). A drift here is a signature break.
        let unsigned = ManifestUnsigned {
            format: 1,
            version: "0.1.0".to_string(),
            // A short placeholder the known answer below is pinned to; this
            // manifest is only canonicalized and signed, never validated.
            content_hash: "v1-abc123".to_string(),
            target: "x86_64-unknown-linux-gnu".to_string(),
            minimum_version: None,
            tarball: fuz_release::TarballInfo {
                path: "release.tar.gz".to_string(),
                blake3: ch(&"a".repeat(64)),
                size: 1000,
            },
            binaries: {
                let mut h = HashMap::new();
                h.insert("fuz".to_string(), ch(&"b".repeat(64)));
                h
            },
            tool: None,
        };

        let canonical = fuz_crypto::canonical_json(&unsigned).expect("canonical");
        let expected = format!(
            "{{\"binaries\":{{\"fuz\":\"{b}\"}},\"content_hash\":\"v1-abc123\",\
             \"format\":1,\"minimum_version\":null,\
             \"tarball\":{{\"blake3\":\"{a}\",\"path\":\"release.tar.gz\",\"size\":1000}},\
             \"target\":\"x86_64-unknown-linux-gnu\",\"version\":\"0.1.0\"}}",
            a = "a".repeat(64),
            b = "b".repeat(64),
        );
        assert_eq!(canonical, expected);
        assert!(
            !canonical.contains("blake3:"),
            "hash fields must be bare hex, not the `blake3:` prefixed form"
        );
    }

    /// The signature [`signature_known_answer_locks_full_pipeline`] pins.
    const KAT_MANIFEST_SIGNATURE: &str =
        "CdJv1IJeNLLX+E6AFq4L4VbaVrDsHG33opBIQONUi8rnrriiqxDWfrsib9RmUvsbNeW1JUGg5suqUaYw0QoVAQ==";

    /// KAT / signature-break tripwire. A fixed seed key + fixed manifest must
    /// produce this EXACT ed25519 signature. ed25519-dalek signing is
    /// deterministic (RFC 8032), so the whole `tag + canonical_json → sign →
    /// base64` pipeline is reproducible — a drift here (the manifest tag,
    /// `serde_json` escaping, base64 alphabet, dalek encoding, or the canonical
    /// form) breaks every existing manifest signature. **DO NOT update
    /// casually**; pairs with `canonical_json_uses_bare_hex_and_is_byte_stable`
    /// (the manifest is the same one, so the canonical bytes after the tag are
    /// the pinned string there).
    #[test]
    fn signature_known_answer_locks_full_pipeline() {
        let key = SigningKey::from_bytes(&[0u8; 32]);
        let unsigned = ManifestUnsigned {
            format: 1,
            version: "0.1.0".to_string(),
            // A short placeholder the known answer below is pinned to; this
            // manifest is only canonicalized and signed, never validated.
            content_hash: "v1-abc123".to_string(),
            target: "x86_64-unknown-linux-gnu".to_string(),
            minimum_version: None,
            tarball: fuz_release::TarballInfo {
                path: "release.tar.gz".to_string(),
                blake3: ch(&"a".repeat(64)),
                size: 1000,
            },
            binaries: {
                let mut h = HashMap::new();
                h.insert("fuz".to_string(), ch(&"b".repeat(64)));
                h
            },
            tool: None,
        };
        let canonical = fuz_crypto::canonical_json(&unsigned).expect("canonical");
        let manifest = sign_manifest(unsigned, &key, "2025-01-15T10:30:00Z").unwrap();

        assert_eq!(
            manifest.signature.format, 2,
            "signature envelope format drifted"
        );
        assert_eq!(
            manifest.signature.public_key, "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik=",
            "seed [0u8;32] public key drifted"
        );
        assert_eq!(
            manifest.signature.sig, KAT_MANIFEST_SIGNATURE,
            "signature over the tagged canonical manifest drifted — every existing signature breaks"
        );

        // The pinned signature is over the literal tag + canonical JSON,
        // checked with raw ed25519 — independent of `SignedMessage`.
        let pinned = ed25519_dalek::Signature::from_slice(
            &STANDARD.decode(KAT_MANIFEST_SIGNATURE).expect("decode"),
        )
        .expect("parse");
        key.verifying_key()
            .verify(&[MANIFEST_TAG, canonical.as_bytes()].concat(), &pinned)
            .expect("the pinned signature covers the manifest tag + canonical JSON");
    }

    #[test]
    fn verify_signature_rejects_untrusted_key() {
        // The `[0u8; 32]` test key is not in `fuz_crypto::PUBLIC_KEYS` when
        // fuz_crypto is consumed as a dependency (its test-key trust is
        // `cfg(test)` of fuz_crypto only), so `verify_signature` rejects the
        // manifest as untrusted. Covers the `sign_manifest` → `verify_signature`
        // wiring through canonical JSON.
        let key = SigningKey::from_bytes(&[0u8; 32]);
        let manifest = sign_manifest(sample_self_unsigned(), &key, "2025-01-15T10:30:00Z").unwrap();
        let result = manifest.verify_signature();
        assert!(matches!(result, Err(ManifestError::Signature(_))));
    }

    /// A manifest signed by an untrusted key is rejected after a full JSON
    /// round trip (`sign_manifest` → serialize → `Manifest::from_json` →
    /// `verify_signature`), covering the serialize/parse path on top of
    /// `verify_signature_rejects_untrusted_key`.
    ///
    /// This does NOT exercise signature *tampering*: the `[0u8; 32]` key isn't
    /// in `fuz_crypto::PUBLIC_KEYS` (its test-key trust is `cfg(test)` of
    /// `fuz_crypto` only), so verification fails at the trust check before the
    /// signature is ever examined — a tampered sig would fail identically here.
    /// Tamper detection against a *trusted* key lives in `fuz_crypto`'s
    /// `verify_detects_tampering_with_trusted_key`.
    #[test]
    fn signed_manifest_json_round_trip_rejects_untrusted_key() {
        let key = SigningKey::from_bytes(&[0u8; 32]);
        let manifest = sign_manifest(sample_self_unsigned(), &key, "2025-01-15T10:30:00Z").unwrap();

        let bytes = serde_json::to_vec(&manifest).unwrap();
        let parsed = Manifest::from_json(&bytes).unwrap();

        assert!(matches!(
            parsed.verify_signature(),
            Err(ManifestError::Signature(_))
        ));
    }
}
