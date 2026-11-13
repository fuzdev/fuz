//! Binary hashing and validation
//!
//! Functions for hashing binaries and verifying artifact integrity.

use super::error::ArtifactError;
use super::platform::{INSPECT_PREFIX_LEN, ReleaseTarget, check_binary_target, inspect_binary};
use super::types::ArtifactMeta;
use super::{HASH_BUFFER_SIZE, MAX_BINARY_SIZE, MIN_BINARY_SIZE};
use fuz_crypto::{ContentHash, HashAlgo, Hasher, hash_reader};
use fuz_sys::secure_file::{SecureFileError, open_nofollow_regular};
use std::fs;
use std::io::{BufReader, Read};
use std::path::Path;

//
// Public API
//

/// Hash a binary file with blake3 (no size or header validation).
///
/// The file is opened without following a symlink and must be a regular file
/// (`fuz_sys::secure_file::open_nofollow_regular`); the hash streams through
/// that descriptor. A binary inside an artifact or tool install that is a link
/// — even one aimed at the right bytes — is something fuz never wrote, and
/// re-hashing through it would vouch for whatever it points at.
///
/// # Errors
///
/// [`ArtifactError::NotRegularFile`] for a symlink or special file;
/// [`ArtifactError::Io`] for a missing file or any other open or read failure.
pub fn hash_binary(path: &Path) -> Result<ContentHash, ArtifactError> {
    let (file, _meta) = open_nofollow_regular(path).map_err(|e| match e {
        SecureFileError::Symlink(path) | SecureFileError::NotRegularFile(path) => {
            ArtifactError::NotRegularFile(path)
        }
        SecureFileError::NotFound(_) => {
            ArtifactError::Io(std::io::Error::from(std::io::ErrorKind::NotFound))
        }
        SecureFileError::Io(_, source) => ArtifactError::Io(source),
        // Not produced by the open (no mode or size check); kept total rather
        // than folded into a wildcard so a new variant has to be classified here.
        e @ (SecureFileError::InsecurePermissions(..) | SecureFileError::FileTooLarge(..)) => {
            ArtifactError::Io(std::io::Error::other(e.to_string()))
        }
    })?;
    let (hash, _size) =
        hash_reader(HashAlgo::Blake3, BufReader::new(file)).map_err(ArtifactError::Io)?;
    Ok(hash)
}

/// Verify artifact integrity (re-hash the `fuz` binary against meta.json).
///
/// The self artifact is fuz-only, so this re-hashes `fuz` and compares it to
/// `meta.outputs.fuz`. Neither `meta.json` nor `fuz` is read through a symlink
/// ([`hash_binary`], `read_checked`). `artifact_dir` itself is taken as given —
/// a caller that has not already established it is a real directory classifies
/// it first (`inspect_store_entry` / `reclaim_store_entry`).
#[expect(
    clippy::missing_errors_doc,
    reason = "every error is a self-explanatory `ArtifactError` variant"
)]
pub fn verify_artifact(artifact_dir: &Path) -> Result<(), ArtifactError> {
    let meta = ArtifactMeta::read(artifact_dir)?;

    let fuz_actual = hash_binary(&artifact_dir.join("fuz"))?;
    if fuz_actual != meta.outputs.fuz {
        return Err(ArtifactError::BinaryIntegrityFailed {
            binary: "fuz".to_string(),
            expected: meta.outputs.fuz,
            actual: fuz_actual,
        });
    }

    Ok(())
}

//
// Internal validation functions (used by create.rs)
//

/// Open a **source** binary — one fuz is about to copy into the store — without
/// following a symlink, requiring a regular file.
///
/// The source-side twin of the open in [`hash_binary`], with the refusals
/// phrased for an input rather than for an install fuz wrote: a missing file is
/// [`ArtifactError::MissingBinary`], a symlink or non-regular file
/// [`ArtifactError::InvalidBinary`]. The open and the type check are on one
/// descriptor, so there is no window between a check and the read.
fn open_source_binary(path: &Path, name: &str) -> Result<(fs::File, fs::Metadata), ArtifactError> {
    let invalid = |reason: String| ArtifactError::InvalidBinary {
        name: name.to_string(),
        reason,
    };
    open_nofollow_regular(path).map_err(|e| match e {
        SecureFileError::NotFound(path) => ArtifactError::MissingBinary {
            name: name.to_string(),
            path,
            source: std::io::Error::from(std::io::ErrorKind::NotFound),
        },
        SecureFileError::Symlink(_) => invalid("symlink not allowed".to_string()),
        SecureFileError::NotRegularFile(_) => invalid("not a regular file".to_string()),
        SecureFileError::Io(_, source) => invalid(format!("cannot open: {source}")),
        // Not produced by the open (no mode or size check); kept total rather
        // than folded into a wildcard so a new variant has to be classified here.
        e @ (SecureFileError::InsecurePermissions(..) | SecureFileError::FileTooLarge(..)) => {
            invalid(e.to_string())
        }
    })
}

/// Hash a **source** binary (no size or header validation), refusing a symlink
/// or non-regular file as an invalid input.
///
/// [`hash_binary`] for a file fuz is about to install rather than one it
/// installed: `install_local_tool` hashes the binaries it is handed through
/// this, so a refusal reads as a bad input ([`ArtifactError::InvalidBinary`] /
/// [`ArtifactError::MissingBinary`]), not as a modified install.
pub fn hash_source_binary(path: &Path, name: &str) -> Result<ContentHash, ArtifactError> {
    let (file, _meta) = open_source_binary(path, name)?;
    let (hash, _size) =
        hash_reader(HashAlgo::Blake3, BufReader::new(file)).map_err(ArtifactError::Io)?;
    Ok(hash)
}

/// Validate binary and compute hash in single pass.
///
/// Checks, all on one descriptor opened without following a symlink:
/// - File exists and is a regular file (not symlink)
/// - Size is within bounds (1KB - 100MB)
/// - Its header is an executable for `target`: the first
///   [`INSPECT_PREFIX_LEN`] bytes go through
///   [`inspect_binary`] and
///   [`check_binary_target`], with the
///   target taken as named — it is the toolchain's own, not a guess — so a
///   static build of the target's architecture passes on either libc
///
/// Returns blake3 hash on success.
#[expect(
    clippy::large_stack_arrays,
    reason = "an intentional 64 KiB buffer for efficient file reads"
)]
pub fn validate_and_hash_binary(
    path: &Path,
    name: &str,
    target: ReleaseTarget,
) -> Result<ContentHash, ArtifactError> {
    let (mut file, meta) = open_source_binary(path, name)?;
    let invalid = |reason: String| ArtifactError::InvalidBinary {
        name: name.to_string(),
        reason,
    };

    let size = meta.len();
    if size < MIN_BINARY_SIZE {
        return Err(invalid(format!(
            "too small ({size} bytes, minimum {MIN_BINARY_SIZE})"
        )));
    }
    if size > MAX_BINARY_SIZE {
        return Err(invalid(format!(
            "too large ({size} bytes, maximum {MAX_BINARY_SIZE})"
        )));
    }

    // Hash through the shared streaming hasher, keeping the head of the file
    // for the platform check; the read loop stays local because of it.
    let mut hasher = Hasher::new(HashAlgo::Blake3);
    let mut buf = [0u8; HASH_BUFFER_SIZE];
    let mut prefix: Vec<u8> = Vec::with_capacity(INSPECT_PREFIX_LEN);

    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| invalid(format!("read error: {e}")))?;
        if n == 0 {
            break;
        }
        let room = INSPECT_PREFIX_LEN - prefix.len();
        prefix.extend_from_slice(&buf[..n.min(room)]);
        hasher.update(&buf[..n]);
    }

    let found = inspect_binary(&prefix).map_err(|e| invalid(e.to_string()))?;
    check_binary_target(found, target, true)
        .map_err(|_| invalid(format!("it is {found}, not a {target} executable")))?;

    Ok(hasher.finalize())
}
