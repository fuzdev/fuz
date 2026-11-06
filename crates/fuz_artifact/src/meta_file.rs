//! Shared meta.json I/O + integrity mechanism.
//!
//! [`ArtifactMeta`](super::ArtifactMeta) and
//! [`ToolMeta`](crate::tools::ToolMeta) stay distinct types, but their on-disk
//! record handling is identical: size-guard against [`MAX_META_SIZE`] → read →
//! parse → integrity-check (recompute the content hash, compare to the stored
//! one) → atomic write with ENOSPC mapping. This module owns that mechanism;
//! each record type supplies its content hash via [`MetaIntegrity`].

#![allow(clippy::missing_errors_doc)] // all errors are self-explanatory ArtifactError variants

use std::path::Path;

use fuz_sys::secure_file::{SecureFileError, load_bounded_file};

use serde::Serialize;
use serde::de::DeserializeOwned;

use super::MAX_META_SIZE;
use super::error::ArtifactError;

/// A meta record whose stored content hash can be recomputed from its own
/// fields, so [`read_checked`] can detect tampering.
///
/// **Not object-safe** — consumed only as a generic bound (`T: MetaIntegrity`
/// on [`read_checked`]), never as `dyn MetaIntegrity`, so it is free to gain
/// generic methods or RPITIT.
pub trait MetaIntegrity {
    /// The content hash as stored in the file.
    fn stored_hash(&self) -> &str;
    /// Recompute the content hash from the record's fields.
    fn compute_hash(&self) -> String;
}

/// Read, size-guard, parse, and integrity-check a meta record at
/// `dir/file_name`.
///
/// The file is opened without following a symlink and must be a regular file
/// (`fuz_sys::secure_file::load_bounded_file`): a `meta.json` that is a link —
/// even one aimed at a valid record — or a special file is refused with
/// [`ArtifactError::NotRegularFile`] rather than read through. The size bound
/// is checked on the open descriptor and again by the read.
///
/// Does NOT re-hash any referenced binaries on disk — that is the record
/// type's own `verify_*` responsibility.
pub fn read_checked<T>(dir: &Path, file_name: &str) -> Result<T, ArtifactError>
where
    T: DeserializeOwned + MetaIntegrity,
{
    let path = dir.join(file_name);

    let bytes = load_bounded_file(&path, MAX_META_SIZE).map_err(map_meta_read_error)?;
    let content = String::from_utf8(bytes).map_err(|e| {
        ArtifactError::MetadataReadFailed(
            path.clone(),
            std::io::Error::new(std::io::ErrorKind::InvalidData, e),
        )
    })?;
    let meta: T =
        serde_json::from_str(&content).map_err(|e| ArtifactError::MetadataParseFailed(path, e))?;

    // Integrity: stored hash must match the one derived from the record itself.
    let computed = meta.compute_hash();
    if meta.stored_hash() != computed {
        return Err(ArtifactError::IntegrityFailed {
            path: dir.to_path_buf(),
            expected: computed,
            actual: meta.stored_hash().to_string(),
        });
    }

    Ok(meta)
}

/// Map a bounded no-follow read failure onto the meta-record errors.
///
/// A missing file and any other I/O failure are
/// [`ArtifactError::MetadataReadFailed`] and an oversized one
/// [`ArtifactError::MetadataTooLarge`]; a symlink or special file is
/// [`ArtifactError::NotRegularFile`].
fn map_meta_read_error(e: SecureFileError) -> ArtifactError {
    match e {
        SecureFileError::NotFound(path) => ArtifactError::MetadataReadFailed(
            path,
            std::io::Error::from(std::io::ErrorKind::NotFound),
        ),
        SecureFileError::Symlink(path) | SecureFileError::NotRegularFile(path) => {
            ArtifactError::NotRegularFile(path)
        }
        SecureFileError::FileTooLarge(path, size, max) => {
            ArtifactError::MetadataTooLarge { path, size, max }
        }
        SecureFileError::Io(path, source) => ArtifactError::MetadataReadFailed(path, source),
        // `load_bounded_file` checks no permission bits; kept total rather than
        // folded into a wildcard so a new variant has to be classified here.
        SecureFileError::InsecurePermissions(path, mode) => ArtifactError::MetadataReadFailed(
            path,
            std::io::Error::other(format!("unexpected mode {mode:o}")),
        ),
    }
}

/// Serialize and atomically write a meta record to `dir/file_name` (mode
/// 0644).
///
/// Delegates to [`fuz_sys::fs::write_atomic`] (tmp + fsync + rename + parent
/// fsync). ENOSPC at any step maps to [`ArtifactError::InsufficientSpace`] so
/// callers can surface a "free up disk space" hint regardless of which step
/// failed.
pub fn write_atomic_meta<T: Serialize>(
    meta: &T,
    dir: &Path,
    file_name: &str,
) -> Result<(), ArtifactError> {
    let path = dir.join(file_name);
    let content = serde_json::to_string_pretty(meta)
        .map_err(|e| ArtifactError::MetadataWriteFailed(std::io::Error::other(e.to_string())))?;
    fuz_sys::fs::write_atomic(&path, content.as_bytes(), 0o644)
        .map_err(|e| map_meta_io_error(e, dir))
}

/// Map an IO error from a meta.json write step to the right `ArtifactError`.
///
/// ENOSPC becomes [`ArtifactError::InsufficientSpace`]; everything else stays
/// [`ArtifactError::MetadataWriteFailed`].
fn map_meta_io_error(source: std::io::Error, dir: &Path) -> ArtifactError {
    if source.kind() == std::io::ErrorKind::StorageFull {
        ArtifactError::InsufficientSpace {
            path: dir.to_path_buf(),
            source,
        }
    } else {
        ArtifactError::MetadataWriteFailed(source)
    }
}
