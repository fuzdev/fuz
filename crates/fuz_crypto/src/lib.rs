//! Cryptographic primitives for Fuz (verification + content hashing)
//!
//! This crate provides:
//! - Signature verification against the embedded trusted public keys, over
//!   domain-separated signed bytes ([`SignedMessage`]: a per-kind tag + the
//!   canonical JSON)
//! - Canonical JSON serialization for deterministic signing/verification
//! - Content hashing — the canonical [`ContentHash`] digest type, its strict
//!   string parses ([`ContentHash::parse_fact_hash`] for a fact address), the
//!   serde adapters for each wire form, and the streaming [`Hasher`] with the
//!   [`hash_reader`] / [`hash_file`] helpers the rest of the workspace hashes
//!   through (`fuz_crypto` is the workspace's single hashing home; see the
//!   `hash` module docs)
//! - [`unique_map`], the serde adapter every map in a signed document is read
//!   through: a repeated key is refused, not read as its last value
//! - SSH signature verification ([`sshsig`]) and the embedded witness keys
//!   ([`witness`], [`WITNESS_KEYS`]) a release log co-signature is checked
//!   with — kept apart from the release keys: a witness key is never trusted
//!   to sign a release
//!
//! Verification and the digest type are pure crypto; the reader and file
//! helpers ([`hash_reader`], [`hash_file`]) are the only I/O. The
//! **signing** side (key generation, key-file I/O, manifest and head signing)
//! lives in the separate `fuz_sign` crate, kept out of the `fuz` consumer's
//! dependency graph so the consumer links verification only.

pub mod canonical;
pub mod error;
pub mod hash;
pub mod signing;
pub mod sshsig;
pub mod unique_map;
pub mod witness;

// Include the compile-time generated public keys
include!(concat!(env!("OUT_DIR"), "/public_keys.rs"));
// This generates: pub const PUBLIC_KEYS: &[[u8; 32]] = &[...];

// The compile-time generated witness keys — a separate item from the release
// keys above, and never consulted by `is_trusted_key`.
include!(concat!(env!("OUT_DIR"), "/witness_keys.rs"));
// This generates: pub const WITNESS_KEYS: &[(&str, [u8; 32])] = &[...];

pub use canonical::canonical_json;
pub use error::{CanonicalError, HashError, SshsigError, VerifyError};
pub use hash::{
    ContentHash, HashAlgo, Hasher, blake3_hex, blake3_hex_map, fact_hash, hash_file, hash_reader,
};
pub use signing::{
    SIGNATURE_FORMAT_VERSION, Signature, SignatureAlgorithm, SignedMessage, SignedPayload,
    SignedPayloadKind, is_trusted_key, verify_signature,
};
pub use sshsig::verify_sshsig;
pub use witness::{normalize_origin, parse_public_key_line, witness_key_for};

// Test-only trust anchor — present only under the `test_trust_anchor` feature,
// which production builds never enable (see `signing.rs`).
#[cfg(feature = "test_trust_anchor")]
pub use signing::{add_trusted_key_for_testing, clear_trusted_keys_for_testing};

// Test utilities - only available in test builds
#[cfg(test)]
pub use signing::test_keypair;

// Re-export the verifying-key type for callers that surface it.
pub use ed25519_dalek::VerifyingKey;
