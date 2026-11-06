//! Signature verification
//!
//! Ed25519 verification primitives. Pure crypto - no file I/O. The signing
//! half (manifest and head signing, key generation, key-file I/O) lives in
//! the separate `fuz_sign` crate so the consumer `fuz` binary links
//! verification only.
//!
//! **Domain separation.** A release key signs more than one kind of document,
//! so a signature never covers a document's canonical JSON alone: it covers a
//! [`SignedMessage`] — the kind's fixed tag ([`SignedPayloadKind::tag`])
//! followed by the canonical JSON. A signature made for one kind therefore
//! cannot verify as another, whatever the two documents' bytes. The kind is
//! not passed loose: it is the [`SignedPayload::KIND`] of the document type,
//! and [`SignedMessage::new`] is the one way to build signed bytes, shared by
//! the signer and every verifier.

use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::{Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use crate::PUBLIC_KEYS;
use crate::canonical::canonical_json;
use crate::error::{CanonicalError, VerifyError};

/// The signature envelope format this build writes and reads.
///
/// Matched exactly. Format 2 signatures cover a [`SignedMessage`] (kind tag +
/// canonical JSON); format 1 signatures covered the canonical JSON alone and
/// are refused with [`VerifyError::UnsupportedFormat`] — the clear "re-sign
/// it" error rather than an opaque verification failure.
pub const SIGNATURE_FORMAT_VERSION: u32 = 2;

/// Every kind of document a release key signs.
///
/// One variant per signed document type, each with a fixed domain tag
/// ([`tag`](Self::tag)) that prefixes the signed bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignedPayloadKind {
    /// A release manifest — the fuz self artifact or a per-tool artifact
    /// (one document type; its `tool` field, inside the signed JSON, tells
    /// them apart).
    Manifest,
    /// A release log head (`head.json`).
    ReleaseLogHead,
}

impl SignedPayloadKind {
    /// The domain tag prefixed to this kind's signed bytes.
    ///
    /// ASCII, versioned, and NUL-terminated: no tag is a prefix of another,
    /// and none is a prefix of a JSON document (canonical JSON never contains
    /// a raw NUL). **Changing a tag invalidates every signature of that
    /// kind.**
    #[must_use]
    pub const fn tag(self) -> &'static [u8] {
        match self {
            Self::Manifest => b"fuz-manifest-v1\0",
            Self::ReleaseLogHead => b"fuz-release-log-head-v1\0",
        }
    }
}

/// A document type a release key signs.
///
/// Binds the type to its [`SignedPayloadKind`], so the kind a signature is
/// made or checked under comes from the document being signed or checked,
/// never from an argument a caller could get wrong. Implemented once per
/// signed type, beside the type (`fuz_release`'s `ManifestUnsigned` and
/// `HeadUnsigned`).
///
/// **Not object-safe** (an associated const and a `Serialize` supertrait).
pub trait SignedPayload: Serialize {
    /// The kind this type is signed as.
    const KIND: SignedPayloadKind;
}

/// The exact bytes a signature covers: the payload kind's tag followed by the
/// payload's canonical JSON.
///
/// Built only by [`new`](Self::new), from a typed [`SignedPayload`], so signed
/// bytes always carry the tag of the document they encode. `fuz_sign`'s signer
/// and [`verify_signature`] both take one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedMessage {
    bytes: Vec<u8>,
}

impl SignedMessage {
    /// Build the signed bytes of `payload`: `T::KIND`'s tag, then
    /// `canonical_json(payload)`.
    ///
    /// # Errors
    ///
    /// Returns [`CanonicalError`] if `payload` has no canonical JSON form
    /// (a non-ASCII string or a non-integer number).
    pub fn new<T: SignedPayload>(payload: &T) -> Result<Self, CanonicalError> {
        let canonical = canonical_json(payload)?;
        let tag = T::KIND.tag();
        let mut bytes = Vec::with_capacity(tag.len() + canonical.len());
        bytes.extend_from_slice(tag);
        bytes.extend_from_slice(canonical.as_bytes());
        Ok(Self { bytes })
    }

    /// The signed bytes, tag included.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Signature algorithm — ed25519 is the only supported value.
///
/// Modeled as a closed enum so an unsupported algorithm is **unrepresentable in
/// memory**: an unknown value is rejected at deserialize time (serde
/// unknown-variant), not re-checked at every `verify`. Mirrors the `HashAlgo`
/// serde pattern (lowercase wire form).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SignatureAlgorithm {
    /// Ed25519 (RFC 8032) — serializes as `"ed25519"`.
    Ed25519,
}

/// A signature with embedded public key and metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Signature {
    /// Envelope format version ([`SIGNATURE_FORMAT_VERSION`]).
    pub format: u32,
    /// Base64-encoded ed25519 public key (44 chars)
    pub public_key: String,
    /// Signature algorithm — only ed25519 is supported (see [`SignatureAlgorithm`]).
    pub algorithm: SignatureAlgorithm,
    /// RFC 3339 timestamp when signature was created (informational only)
    pub signed_at: String,
    /// Base64-encoded signature (88 chars)
    pub sig: String,
}

/// Verify a signature against a [`SignedMessage`].
///
/// Checks that the public key in the signature is trusted (in `PUBLIC_KEYS`),
/// then verifies the signature over the message's bytes — its kind's tag and
/// canonical JSON. Returns the verified public key on success, useful for
/// logging which key signed the content.
///
/// # Errors
///
/// Returns [`VerifyError`] if:
/// - Signature format version is not [`SIGNATURE_FORMAT_VERSION`]
/// - Public key is invalid or not in trusted set
/// - Base64 decoding fails
/// - Signature verification fails (content modified or corrupted, or signed
///   as another kind of document)
pub fn verify_signature(
    message: &SignedMessage,
    sig: &Signature,
) -> Result<VerifyingKey, VerifyError> {
    // Validate the format version. The algorithm is type-guaranteed
    // (`SignatureAlgorithm`), so there's no runtime algorithm check — an unknown
    // algorithm can't exist in memory; it's rejected when the signature is
    // deserialized.
    if sig.format != SIGNATURE_FORMAT_VERSION {
        return Err(VerifyError::UnsupportedFormat(sig.format));
    }

    // Decode and validate public key
    let pubkey_bytes = STANDARD
        .decode(&sig.public_key)
        .map_err(VerifyError::Base64Decode)?;
    let pubkey_array: [u8; 32] = pubkey_bytes
        .try_into()
        .map_err(|_| VerifyError::InvalidPublicKey)?;
    let pubkey =
        VerifyingKey::from_bytes(&pubkey_array).map_err(|_| VerifyError::InvalidPublicKey)?;

    // Check public key is trusted
    if !is_trusted_key(&pubkey) {
        return Err(VerifyError::UntrustedKey(sig.public_key.clone()));
    }

    // Verify signature (ed25519 signatures are 64 bytes)
    let sig_bytes = STANDARD
        .decode(&sig.sig)
        .map_err(VerifyError::Base64Decode)?;
    let signature = ed25519_dalek::Signature::from_slice(&sig_bytes)
        .map_err(|_| VerifyError::InvalidSignature)?;

    pubkey
        .verify(message.as_bytes(), &signature)
        .map_err(|_| VerifyError::InvalidSignature)?;

    Ok(pubkey)
}

/// Check if public key is in the embedded trusted set.
///
/// The constant-time comparison + full fold over all keys is **defense in depth,
/// not strictly required**: the trusted keys are public (embedded in the binary,
/// printed by `cargo xtask key list-trusted`), so neither the matched key nor its
/// position is secret. It's kept for consistency with the rest of the crypto
/// surface and to avoid per-callsite `==`-vs-`ct_eq` drift. O(n) linear scan —
/// fine for small key counts (expected: 1-3 keys); if the set grows much larger,
/// consider a compile-time set (the `build.rs` warns past 10).
///
/// In test builds, also trusts the deterministic test key from `test_keypair()`.
/// Under the `test_trust_anchor` feature (test-only, never enabled on a shipping
/// binary), also trusts any key registered via `add_trusted_key_for_testing`.
pub fn is_trusted_key(pubkey: &VerifyingKey) -> bool {
    let pubkey_bytes = pubkey.as_bytes();
    // fold (not any()) checks all keys in constant time — defense-in-depth; the
    // keys are public, so this guards no secret, but it keeps the surface uniform.
    let in_production_keys = PUBLIC_KEYS
        .iter()
        .fold(false, |found, k| found | bool::from(k.ct_eq(pubkey_bytes)));

    // In test builds, also trust the deterministic test key
    #[cfg(test)]
    let in_test_key = bool::from(TEST_PUBLIC_KEY.ct_eq(pubkey_bytes));
    #[cfg(not(test))]
    let in_test_key = false;

    // Under the test-only feature, also consult the runtime anchor registry.
    #[cfg(feature = "test_trust_anchor")]
    let in_anchor = is_extra_trusted_key(pubkey_bytes);
    #[cfg(not(feature = "test_trust_anchor"))]
    let in_anchor = false;

    in_production_keys | in_test_key | in_anchor
}

// --- Test-only trust anchor (feature `test_trust_anchor`) -------------------
//
// A runtime registry of additional trusted verifying keys, empty by default, so
// downstream test crates can drive the end-to-end sign→verify→install path with
// a key whose private half they hold (the embedded `PUBLIC_KEYS` are the
// operator's real keys; tests can't sign with those). This is the single most
// security-sensitive test seam in the workspace — it grants signing trust — so
// its exclusion from production is belt-and-suspenders:
//
//   * Compiled out of production. Every item below is `#[cfg(feature =
//     "test_trust_anchor")]`, and `is_trusted_key` ORs the registry in only
//     under that cfg. Feature-off, none of this code exists — so an accidental
//     production reference to `add_trusted_key_for_testing` is a *compile
//     error*, never a runtime weakness.
//   * Never reaches a normal build. The feature is enabled only as a
//     `[dev-dependencies]` feature of `fuz_sign` (its sole enabling site).
//     `resolver = "2"` does not unify dev-dependency features into normal
//     builds, so `fuz` / `fuzd` / `fuzf` / `xtask` link a feature-off
//     `fuz_crypto` even under `cargo test --workspace`.
//   * Verified, not assumed. `cargo tree -p {fuz,fuzd,xtask} -e features` shows
//     `fuz_crypto` with `default` only, and `nm` on the compiled `fuz`/`fuzd`
//     binaries finds zero `*_for_testing` symbols (they exist only in the
//     `signed_trust` test binary).
//
// MAINTAINER: only ever enable this feature from a `[dev-dependencies]` entry.
// Enabling it from `[dependencies]`, `[build-dependencies]`, or a crate's
// `default` feature set would route signing trust into a shipping binary and
// defeat every guarantee above.
//
// This is the feature-flag sibling of the `fuz_testing` / `fuz_sign`
// separate-crate discipline (weakened Argon2 + private signing kept out of
// production by dependency graph, audited by `cargo xtask check-release`); the
// feature form is used here because `is_trusted_key` sits on the production path
// and must consult the registry at its own callsite. `fuz_home`'s
// `test_home_override` is the parallel seam for `~/.fuz` resolution.

/// Process-global set of additional verifying keys trusted only under the
/// `test_trust_anchor` feature. Empty until `add_trusted_key_for_testing`.
#[cfg(feature = "test_trust_anchor")]
static EXTRA_TRUSTED_KEYS: std::sync::RwLock<Vec<[u8; 32]>> = std::sync::RwLock::new(Vec::new());

/// Register `key` as trusted for the remainder of the process.
///
/// **Test-only** — behind the `test_trust_anchor` feature, which no production
/// build enables. Lets a downstream test crate sign release manifests with a
/// key it controls and have [`verify_signature`] accept them, so the full
/// sign→fetch→verify→install path can be exercised against a real trust check.
#[cfg(feature = "test_trust_anchor")]
pub fn add_trusted_key_for_testing(key: &VerifyingKey) {
    EXTRA_TRUSTED_KEYS
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push(*key.as_bytes());
}

/// Drop every key registered via `add_trusted_key_for_testing`, restoring the
/// empty-trust baseline.
///
/// **Test-only** (see `add_trusted_key_for_testing`).
#[cfg(feature = "test_trust_anchor")]
pub fn clear_trusted_keys_for_testing() {
    EXTRA_TRUSTED_KEYS
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clear();
}

/// Whether `pubkey_bytes` was registered via `add_trusted_key_for_testing`.
#[cfg(feature = "test_trust_anchor")]
fn is_extra_trusted_key(pubkey_bytes: &[u8; 32]) -> bool {
    EXTRA_TRUSTED_KEYS
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .any(|k| k == pubkey_bytes)
}

/// Test-only public key for integration tests.
/// Generated from seed `[0u8; 32]` - deterministic and reproducible.
/// This key is ONLY trusted in test builds.
#[cfg(test)]
const TEST_PUBLIC_KEY: [u8; 32] = [
    59, 106, 39, 188, 206, 182, 164, 45, 98, 163, 168, 208, 42, 111, 13, 115, 101, 50, 21, 119, 29,
    226, 67, 166, 58, 192, 72, 161, 139, 89, 218, 41,
];

/// Generate test keypair from fixed seed (for tests only).
/// Returns the same keypair every time - deterministic.
#[cfg(test)]
pub fn test_keypair() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[0u8; 32])
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    /// A fixed, non-test-key signing key — deterministic and **untrusted**
    /// (not `[0u8; 32]`, not in `PUBLIC_KEYS`). Replaces the random
    /// `generate_keypair()` from the moved key module.
    fn untrusted_key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    /// A stand-in document signed as a manifest. The real signed types live in
    /// `fuz_release`, which depends on this crate.
    #[derive(Serialize)]
    struct TestManifest {
        body: &'static str,
    }

    impl SignedPayload for TestManifest {
        const KIND: SignedPayloadKind = SignedPayloadKind::Manifest;
    }

    /// The same JSON as [`TestManifest`], signed as a release log head — so a
    /// cross-kind test isolates the tag: the canonical JSON is identical.
    #[derive(Serialize)]
    #[serde(transparent)]
    struct TestHead(TestManifest);

    impl SignedPayload for TestHead {
        const KIND: SignedPayloadKind = SignedPayloadKind::ReleaseLogHead;
    }

    /// The signed bytes of a [`TestManifest`] carrying `body`.
    fn message(body: &'static str) -> SignedMessage {
        SignedMessage::new(&TestManifest { body }).expect("canonical")
    }

    /// The signed bytes of a [`TestHead`] carrying `body`.
    fn head_message(body: &'static str) -> SignedMessage {
        SignedMessage::new(&TestHead(TestManifest { body })).expect("canonical")
    }

    /// Wrap a raw ed25519 signature over `bytes` in an envelope of `format`.
    fn envelope(bytes: &[u8], key: &SigningKey, format: u32) -> Signature {
        Signature {
            format,
            public_key: STANDARD.encode(key.verifying_key().as_bytes()),
            algorithm: SignatureAlgorithm::Ed25519,
            signed_at: "2025-01-15T12:00:00Z".to_string(),
            sig: STANDARD.encode(key.sign(bytes).to_bytes()),
        }
    }

    /// Local sign helper. The production `sign_message` lives in `fuz_sign`;
    /// verification tests still need to produce signatures, so this mirrors it
    /// inline (`fuz_crypto` can't depend on `fuz_sign` — that's circular).
    fn sign_for_test(message: &SignedMessage, key: &SigningKey, signed_at: &str) -> Signature {
        let sig = key.sign(message.as_bytes());
        Signature {
            format: SIGNATURE_FORMAT_VERSION,
            public_key: STANDARD.encode(key.verifying_key().as_bytes()),
            algorithm: SignatureAlgorithm::Ed25519,
            signed_at: signed_at.to_string(),
            sig: STANDARD.encode(sig.to_bytes()),
        }
    }

    /// Tripwire: the tags are the signed-bytes definition. A change to either
    /// invalidates every signature of that kind, so they are pinned as
    /// literals here, not read back from [`SignedPayloadKind::tag`].
    #[test]
    fn signed_payload_tags_are_pinned() {
        assert_eq!(
            SignedPayloadKind::Manifest.tag(),
            b"fuz-manifest-v1\0".as_slice()
        );
        assert_eq!(
            SignedPayloadKind::ReleaseLogHead.tag(),
            b"fuz-release-log-head-v1\0".as_slice()
        );
        assert_eq!(SIGNATURE_FORMAT_VERSION, 2);
    }

    #[test]
    fn signed_payload_tags_are_distinct_and_prefix_free() {
        let tags = [
            SignedPayloadKind::Manifest.tag(),
            SignedPayloadKind::ReleaseLogHead.tag(),
        ];
        for (i, a) in tags.iter().enumerate() {
            assert!(a.is_ascii(), "a tag is ASCII");
            assert_eq!(a.last(), Some(&0), "a tag is NUL-terminated");
            assert_eq!(
                a.iter().position(|&b| b == 0),
                Some(a.len() - 1),
                "a tag's only NUL is its terminator"
            );
            for (j, b) in tags.iter().enumerate() {
                if i != j {
                    assert!(!b.starts_with(a), "no tag is a prefix of another");
                }
            }
        }
    }

    #[test]
    fn signed_message_is_the_tag_then_the_canonical_json() {
        let manifest = message("x");
        assert!(
            manifest
                .as_bytes()
                .starts_with(SignedPayloadKind::Manifest.tag())
        );
        assert_eq!(manifest.as_bytes(), b"fuz-manifest-v1\0{\"body\":\"x\"}");

        let head = head_message("x");
        assert!(
            head.as_bytes()
                .starts_with(SignedPayloadKind::ReleaseLogHead.tag())
        );
        assert_eq!(
            head.as_bytes(),
            b"fuz-release-log-head-v1\0{\"body\":\"x\"}"
        );
    }

    #[test]
    fn signed_message_refuses_a_payload_without_canonical_json() {
        #[derive(Serialize)]
        struct Accented {
            body: &'static str,
        }
        impl SignedPayload for Accented {
            const KIND: SignedPayloadKind = SignedPayloadKind::Manifest;
        }
        let result = SignedMessage::new(&Accented { body: "caf\u{e9}" });
        assert!(matches!(result, Err(CanonicalError::NonAsciiString(_))));
    }

    /// Verify-side known answers, one per kind: a signature pinned as a
    /// literal (seed `[0u8; 32]`, the trusted test key) over a fixed document
    /// must verify. Pairs with the sign-side known answers in `fuz_sign`, which
    /// pin what the signer produces for the real document types; this pins
    /// what the verifier accepts, independent of any signer in the workspace.
    #[test]
    fn known_answer_signature_verifies_for_each_kind() {
        let manifest_sig = Signature {
            format: 2,
            public_key: "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik=".to_string(),
            algorithm: SignatureAlgorithm::Ed25519,
            signed_at: "2025-01-15T12:00:00Z".to_string(),
            sig: "ROOhAsIQ0zWY7obTgqwNkLMTLGRipg8K12PgU/tPk04wd4mEEQUvX2PoEpu+jRaLxjoGdioBNqhalT1RyaQKCw==".to_string(),
        };
        let head_sig = Signature {
            sig: "unOd4WJq3VY6butV/aQkoe2EBhKqn/4qLELKd38au2QK1sGYhSnLkGIQPgBUitYYRBA/Rbs7A0r61gV4noR2Aw==".to_string(),
            ..manifest_sig.clone()
        };
        let key = test_keypair();
        assert_eq!(
            sign_for_test(&message("known answer"), &key, "2025-01-15T12:00:00Z").sig,
            manifest_sig.sig,
            "the manifest-kind signature over the fixed document drifted"
        );
        assert_eq!(
            sign_for_test(&head_message("known answer"), &key, "2025-01-15T12:00:00Z").sig,
            head_sig.sig,
            "the head-kind signature over the fixed document drifted"
        );
        verify_signature(&message("known answer"), &manifest_sig)
            .expect("the pinned manifest signature verifies");
        verify_signature(&head_message("known answer"), &head_sig)
            .expect("the pinned head signature verifies");
    }

    /// The domain separation itself: one document's canonical JSON, signed as
    /// one kind, never verifies as the other — in either direction — although
    /// the JSON bytes are identical and the key is trusted.
    #[test]
    fn a_signature_for_one_kind_does_not_verify_as_another() {
        let key = test_keypair();
        let as_manifest = sign_for_test(&message("same"), &key, "2025-01-15T12:00:00Z");
        let as_head = sign_for_test(&head_message("same"), &key, "2025-01-15T12:00:00Z");

        verify_signature(&message("same"), &as_manifest).expect("manifest as manifest");
        verify_signature(&head_message("same"), &as_head).expect("head as head");

        assert!(matches!(
            verify_signature(&head_message("same"), &as_manifest),
            Err(VerifyError::InvalidSignature)
        ));
        assert!(matches!(
            verify_signature(&message("same"), &as_head),
            Err(VerifyError::InvalidSignature)
        ));
    }

    /// A current-format envelope over the canonical JSON alone — no tag — is
    /// refused: the tag is part of what verification checks, not decoration.
    #[test]
    fn an_untagged_signature_is_refused() {
        let key = test_keypair();
        let canonical = br#"{"body":"same"}"#;
        let sig = envelope(canonical, &key, SIGNATURE_FORMAT_VERSION);
        assert!(matches!(
            verify_signature(&message("same"), &sig),
            Err(VerifyError::InvalidSignature)
        ));
    }

    /// A signature from before domain separation — format 1, over the
    /// canonical JSON alone — is refused by its format, with the error that
    /// says to re-sign, before any cryptography runs.
    #[test]
    fn a_pre_tag_signature_is_refused_as_an_unsupported_format() {
        let key = test_keypair();
        let sig = envelope(br#"{"body":"same"}"#, &key, 1);
        let error = verify_signature(&message("same"), &sig).unwrap_err();
        assert!(matches!(error, VerifyError::UnsupportedFormat(1)));
        assert_eq!(
            error.to_string(),
            "unsupported signature format 1 (this build reads format 2)"
        );
        assert!(
            error.hint().is_some_and(|hint| hint.contains("re-signed")),
            "an older format's hint says to re-sign, got {:?}",
            error.hint()
        );
        assert_eq!(
            VerifyError::UnsupportedFormat(3).hint(),
            Some("Signature may be from a newer version of fuz")
        );
    }

    #[test]
    fn test_keypair_is_deterministic() {
        let key1 = test_keypair();
        let key2 = test_keypair();
        assert_eq!(key1.to_bytes(), key2.to_bytes());
        assert_eq!(key1.verifying_key().as_bytes(), &TEST_PUBLIC_KEY);
    }

    #[test]
    fn test_keypair_is_trusted() {
        let key = test_keypair();
        assert!(is_trusted_key(&key.verifying_key()));
    }

    #[test]
    fn sign_verify_full_round_trip_with_trusted_key() {
        // Use the deterministic test keypair which is trusted in test builds
        let key = test_keypair();
        let content = message("test content to sign");
        let signed_at = "2025-01-15T12:00:00Z";

        let sig = sign_for_test(&content, &key, signed_at);

        // Full verification including trust check
        verify_signature(&content, &sig).expect("verify should succeed with trusted test key");
    }

    #[test]
    fn verify_detects_tampering_with_trusted_key() {
        let key = test_keypair();
        let content = message("original content");
        let sig = sign_for_test(&content, &key, "2025-01-15T12:00:00Z");

        // Verify original works
        verify_signature(&content, &sig).expect("original should verify");

        // Tampered content should fail
        let tampered = message("tampered content");
        let result = verify_signature(&tampered, &sig);
        assert!(matches!(result, Err(VerifyError::InvalidSignature)));
    }

    #[test]
    fn sign_verify_round_trip() {
        // Sign content, verify with raw ed25519 (bypasses trust check)
        let key = untrusted_key();
        let content = message("test content to sign");
        let signed_at = "2025-01-15T12:00:00Z";

        let sig = sign_for_test(&content, &key, signed_at);

        // Check signature metadata
        assert_eq!(sig.algorithm, SignatureAlgorithm::Ed25519);
        assert_eq!(sig.format, SIGNATURE_FORMAT_VERSION);
        assert_eq!(sig.signed_at, signed_at);

        // Verify signature is valid using raw ed25519 (not verify_signature() which checks trust)
        let sig_bytes = STANDARD.decode(&sig.sig).expect("decode sig");
        let signature = ed25519_dalek::Signature::from_slice(&sig_bytes).expect("parse sig");
        key.verifying_key()
            .verify(content.as_bytes(), &signature)
            .expect("verify should succeed");

        // Verify public key in signature matches
        let pubkey_bytes = STANDARD.decode(&sig.public_key).expect("decode pubkey");
        assert_eq!(pubkey_bytes, key.verifying_key().as_bytes());
    }

    #[test]
    fn sign_verify_detects_tampering() {
        let key = untrusted_key();
        let content = message("original content");
        let sig = sign_for_test(&content, &key, "2025-01-15T12:00:00Z");

        // Tampered content should fail verification
        let tampered = message("modified content");
        let sig_bytes = STANDARD.decode(&sig.sig).expect("decode sig");
        let signature = ed25519_dalek::Signature::from_slice(&sig_bytes).expect("parse sig");
        assert!(
            key.verifying_key()
                .verify(tampered.as_bytes(), &signature)
                .is_err()
        );
    }

    #[test]
    fn reject_invalid_signature() {
        let key = untrusted_key();
        let content = message("test content");
        let mut sig = sign_for_test(&content, &key, "2025-01-15T12:00:00Z");

        // Corrupt the signature
        sig.sig = STANDARD.encode([0u8; 64]); // Invalid signature bytes

        // verify_signature() would check trust first, so test with raw ed25519
        let sig_bytes = STANDARD.decode(&sig.sig).expect("decode sig");
        let signature = ed25519_dalek::Signature::from_slice(&sig_bytes).expect("parse sig");
        assert!(
            key.verifying_key()
                .verify(content.as_bytes(), &signature)
                .is_err()
        );
    }

    #[test]
    fn reject_truncated_signature() {
        let key = untrusted_key();
        let content = message("test content");
        let mut sig = sign_for_test(&content, &key, "2025-01-15T12:00:00Z");

        // Truncate the signature
        sig.sig = STANDARD.encode([0u8; 32]); // Too short

        let sig_bytes = STANDARD.decode(&sig.sig).expect("decode sig");
        assert!(ed25519_dalek::Signature::from_slice(&sig_bytes).is_err());
    }

    #[test]
    fn reject_untrusted_public_key() {
        let key = untrusted_key();
        let content = message("test content");
        let sig = sign_for_test(&content, &key, "2025-01-15T12:00:00Z");

        // verify_signature() should reject because key is not in PUBLIC_KEYS
        let result = verify_signature(&content, &sig);
        // The key is deterministically untrusted, so expect UntrustedKey error
        if !is_trusted_key(&key.verifying_key()) {
            assert!(matches!(result, Err(VerifyError::UntrustedKey(_))));
        }
    }

    #[test]
    fn reject_signature_with_substituted_trusted_public_key() {
        // Impersonation / misattribution defense: a signature made by one key
        // must NOT verify just because its `public_key` field is swapped to a
        // *different but trusted* key. The claimed key is trusted (so this is
        // not the `UntrustedKey` path), yet it never produced the signature, so
        // ed25519 verification fails. This pins the key `verify_signature`
        // returns (TA.5 `signed_by`) against cross-key misattribution: you
        // cannot borrow a trusted key's identity for another key's signature.
        let signer = untrusted_key();
        let content = message("release manifest canonical json");
        let mut sig = sign_for_test(&content, &signer, "2025-01-15T12:00:00Z");

        let trusted = test_keypair();
        assert!(
            is_trusted_key(&trusted.verifying_key()),
            "precondition: the substituted key must be trusted"
        );
        sig.public_key = STANDARD.encode(trusted.verifying_key().as_bytes());

        let result = verify_signature(&content, &sig);
        assert!(
            matches!(result, Err(VerifyError::InvalidSignature)),
            "a trusted key's identity must not validate another key's signature, got {result:?}"
        );
    }

    #[test]
    fn reject_invalid_public_key() {
        let sig = Signature {
            format: SIGNATURE_FORMAT_VERSION,
            public_key: STANDARD.encode([0u8; 10]), // Invalid: wrong length
            algorithm: SignatureAlgorithm::Ed25519,
            signed_at: "2025-01-15T12:00:00Z".to_string(),
            sig: STANDARD.encode([0u8; 64]),
        };

        let result = verify_signature(&message("content"), &sig);
        assert!(matches!(result, Err(VerifyError::InvalidPublicKey)));
    }

    #[test]
    fn reject_signature_unknown_algorithm_at_parse() {
        // Unknown algorithms are unrepresentable in memory (`SignatureAlgorithm`
        // is a closed enum), so one can only arrive over the wire — where serde
        // rejects it as an unknown variant at parse time. A `Signature` reaches
        // the verify path as a serde field on a manifest, so this pins the
        // deserialize itself.
        let json = br#"{
            "format": 2,
            "public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "algorithm": "ed448",
            "signed_at": "2025-01-15T12:00:00Z",
            "sig": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
        }"#;
        let result = serde_json::from_slice::<Signature>(json);
        assert!(
            result.is_err(),
            "unknown algorithm must be rejected at parse, got {result:?}"
        );
    }

    #[test]
    fn signature_algorithm_wire_form_is_stable() {
        // Tripwire: `SignatureAlgorithm` is embedded in every manifest signature,
        // so it must serialize to exactly the lowercase `"ed25519"` token — a
        // rename / serde-attr drift would break every existing signature's JSON.
        assert_eq!(
            serde_json::to_string(&SignatureAlgorithm::Ed25519).expect("serialize"),
            "\"ed25519\""
        );
        assert_eq!(
            serde_json::from_str::<SignatureAlgorithm>("\"ed25519\"").expect("parse"),
            SignatureAlgorithm::Ed25519
        );
    }

    #[test]
    fn reject_signature_newer_format() {
        let key = untrusted_key();
        let content = message("test content");
        let mut sig = sign_for_test(&content, &key, "2025-01-15T12:00:00Z");
        sig.format = 99;

        let result = verify_signature(&content, &sig);
        assert!(matches!(result, Err(VerifyError::UnsupportedFormat(99))));
    }

    #[test]
    fn reject_signature_modified_content() {
        let key = untrusted_key();
        let content = message("original content");
        let sig = sign_for_test(&content, &key, "2025-01-15T12:00:00Z");

        let modified = message("modified content");

        // Raw ed25519 verification should fail
        let sig_bytes = STANDARD.decode(&sig.sig).expect("decode sig");
        let signature = ed25519_dalek::Signature::from_slice(&sig_bytes).expect("parse sig");
        assert!(
            key.verifying_key()
                .verify(modified.as_bytes(), &signature)
                .is_err()
        );
    }

    #[test]
    fn reject_signature_invalid_base64() {
        let sig = Signature {
            format: SIGNATURE_FORMAT_VERSION,
            public_key: "not!valid!base64!".to_string(),
            algorithm: SignatureAlgorithm::Ed25519,
            signed_at: "2025-01-15T12:00:00Z".to_string(),
            sig: STANDARD.encode([0u8; 64]),
        };

        let result = verify_signature(&message("content"), &sig);
        assert!(matches!(result, Err(VerifyError::Base64Decode(_))));
    }

    #[test]
    fn signature_json_round_trip() {
        let key = untrusted_key();
        let content = message("test content");
        let sig = sign_for_test(&content, &key, "2025-01-15T12:00:00Z");

        let json = serde_json::to_vec(&sig).expect("serialize");
        let parsed: Signature = serde_json::from_slice(&json).expect("parse");

        assert_eq!(parsed.format, sig.format);
        assert_eq!(parsed.public_key, sig.public_key);
        assert_eq!(parsed.algorithm, sig.algorithm);
        assert_eq!(parsed.signed_at, sig.signed_at);
        assert_eq!(parsed.sig, sig.sig);
    }

    #[test]
    fn signature_rejects_unknown_fields() {
        // Signatures with extra fields should be rejected to prevent injection attacks
        let json = br#"{
            "format": 2,
            "public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "algorithm": "ed25519",
            "signed_at": "2025-01-15T12:00:00Z",
            "sig": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",
            "extra_field": "malicious"
        }"#;
        let result = serde_json::from_slice::<Signature>(json);
        assert!(
            result.is_err(),
            "expected a parse error for unknown fields, got {result:?}"
        );
    }

    /// The *production* trust branch: every embedded `PUBLIC_KEYS` entry must be
    /// accepted by `is_trusted_key`. Drift-proof (iterates the const, no
    /// hardcoded key), so a `build.rs` regression that emitted an empty/garbled
    /// `PUBLIC_KEYS`, or an `is_trusted_key` wiring bug, turns this red — neither
    /// of which the cfg(test)/anchor-key tests catch (they exercise only the
    /// test-key and runtime-registry branches).
    #[test]
    fn every_embedded_production_key_is_trusted() {
        assert!(
            !PUBLIC_KEYS.is_empty(),
            "at least one production verifying key must be embedded"
        );
        for bytes in PUBLIC_KEYS {
            let vk =
                VerifyingKey::from_bytes(bytes).expect("embedded key is a valid ed25519 point");
            assert!(
                is_trusted_key(&vk),
                "every embedded PUBLIC_KEYS entry must be trusted"
            );
        }
        // And the fold isn't accidentally returning true for everything: an
        // unrelated key stays untrusted.
        assert!(!is_trusted_key(&untrusted_key().verifying_key()));
    }
}
