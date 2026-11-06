//! Build script for `fuz_crypto`
//!
//! Parses `public_keys.json` at compile time and generates two Rust consts:
//! `PUBLIC_KEYS`, the decoded release keys, and `WITNESS_KEYS`, the decoded
//! co-signer keys with the origin each speaks for. They are written to
//! separate files and included as separate items: a witness key verifies a
//! co-signature and is never a release key.

// Build scripts are expected to panic on invalid input - these are compile-time checks
#![allow(clippy::expect_used, clippy::panic)]

use base64::{Engine, engine::general_purpose::STANDARD};
use serde::Deserialize;
use std::collections::HashSet;
use std::fmt::Write;

// The witness-key rules, shared with the crate itself so that what the build
// enforces is what the crate's tests cover. The build uses the validation
// entry point only.
#[allow(dead_code)]
#[path = "src/witness.rs"]
mod witness;

// `deny_unknown_fields` makes the trust anchor's config fail the build on a
// typo'd field (e.g. `keyz: [...]` during key rotation) instead of silently
// dropping it. The two human-readable doc fields are declared so they're
// tolerated rather than rejected.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicKeysFile {
    format: u32,
    keys: Vec<String>,
    /// Co-signer keys. Optional; absent or empty embeds none.
    #[serde(default)]
    witnesses: Vec<WitnessEntry>,
    #[serde(default)]
    _comment: Option<String>,
    #[serde(default)]
    _see: Option<String>,
}

/// One co-signer: the origin it serves its co-signature at, and its SSH
/// public key as `ssh-keygen` prints it.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WitnessEntry {
    origin: String,
    ssh_public_key: String,
}

fn main() {
    let json = include_str!("src/public_keys.json");
    let keys: PublicKeysFile =
        serde_json::from_str(json).expect("invalid public_keys.json: failed to parse JSON");

    // Validate format version
    assert_eq!(
        keys.format, 1,
        "unsupported public_keys.json format: {} (expected 1)",
        keys.format
    );

    // Reject empty keys array - would make all verifications fail with confusing error
    assert!(
        !keys.keys.is_empty(),
        "public_keys.json has no keys - at least one trusted key required"
    );

    // Warn if key count is getting large (is_trusted_key is O(n) linear scan)
    // This is a compile-time warning, not a hard error
    if keys.keys.len() > 10 {
        println!(
            "cargo::warning=public_keys.json has {} keys. Consider removing old rotated keys \
             or switching to a HashSet for is_trusted_key().",
            keys.keys.len()
        );
    }

    // Validate and decode keys
    let mut seen = HashSet::new();
    let mut decoded_keys = Vec::new();
    for key_b64 in &keys.keys {
        let bytes = STANDARD
            .decode(key_b64)
            .unwrap_or_else(|_| panic!("invalid base64 in public_keys.json: {key_b64}"));
        assert_eq!(
            bytes.len(),
            32,
            "invalid key length in public_keys.json: {} (expected 32 bytes)",
            bytes.len()
        );
        assert!(
            seen.insert(bytes.clone()),
            "duplicate key in public_keys.json: {key_b64}"
        );
        decoded_keys.push(bytes);
    }

    // Generate: pub const PUBLIC_KEYS: &[[u8; 32]] = &[...];
    let mut out = String::from("pub const PUBLIC_KEYS: &[[u8; 32]] = &[\n");
    for bytes in &decoded_keys {
        // Use writeln! instead of format! to avoid extra allocation
        writeln!(
            out,
            "    [{}],",
            bytes
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        )
        .expect("write to String cannot fail");
    }
    out.push_str("];\n");

    // Witness keys: validated against the release keys, so a key is never both.
    let release_keys: Vec<[u8; 32]> = decoded_keys
        .iter()
        .map(|bytes| <[u8; 32]>::try_from(bytes.as_slice()).expect("length checked above"))
        .collect();
    let entries: Vec<(&str, &str)> = keys
        .witnesses
        .iter()
        .map(|entry| (entry.origin.as_str(), entry.ssh_public_key.as_str()))
        .collect();
    let witnesses = witness::check_witnesses(&entries, &release_keys)
        .unwrap_or_else(|error| panic!("invalid public_keys.json: {error}"));

    // Generate: pub const WITNESS_KEYS: &[(&str, [u8; 32])] = &[...];
    // The origin is printable ASCII (checked), so its `Debug` form is a Rust
    // string literal of exactly its bytes.
    let mut witness_out = String::from("pub const WITNESS_KEYS: &[(&str, [u8; 32])] = &[\n");
    for (origin, key) in &witnesses {
        writeln!(
            witness_out,
            "    ({origin:?}, [{}]),",
            key.iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        )
        .expect("write to String cannot fail");
    }
    witness_out.push_str("];\n");

    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR not set");
    std::fs::write(format!("{out_dir}/public_keys.rs"), out)
        .expect("failed to write public_keys.rs");
    std::fs::write(format!("{out_dir}/witness_keys.rs"), witness_out)
        .expect("failed to write witness_keys.rs");
    println!("cargo::rerun-if-changed=src/public_keys.json");
    println!("cargo::rerun-if-changed=src/witness.rs");
}
