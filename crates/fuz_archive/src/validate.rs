//! The guards applied to every tar entry and every
//! [`Placement`](crate::Placement) result: only `Normal` path components, no
//! null byte, path length, file size, and no setuid/setgid.

use std::path::{Component, Path};

use crate::ExtractLimits;
use crate::error::{ArchiveError, tar_error};

/// Whether every component of `path` is `Normal` — i.e. no absolute root, `..`,
/// `.`, or (Windows) prefix. The shared zip-slip / containment primitive used to
/// guard both raw tar entry paths and [`Placement`](crate::Placement) results.
fn all_normal_components(path: &Path) -> bool {
    path.components().all(|c| matches!(c, Component::Normal(_)))
}

/// Validate a tar entry's path, effective `size`, and header against the guards
/// (manifest-agnostic).
pub fn validate_entry_path(
    path: &Path,
    size: u64,
    header: &tar::Header,
    limits: &ExtractLimits,
) -> Result<(), ArchiveError> {
    // Only `Normal` components (rejects absolute, `..`, `.`, Windows prefix).
    if !all_normal_components(path) {
        return Err(ArchiveError::InvalidPath(path.to_path_buf()));
    }

    if path.to_string_lossy().contains('\0') {
        return Err(ArchiveError::NullByte(path.to_path_buf()));
    }

    if path.as_os_str().len() > limits.max_path_length {
        return Err(ArchiveError::PathTooLong(path.to_path_buf()));
    }

    if size > limits.max_file_size {
        return Err(ArchiveError::FileTooLarge(path.to_path_buf(), size));
    }

    // setuid/setgid are privilege-escalation vectors and are Unix concepts.
    #[cfg(unix)]
    {
        let mode = header
            .mode()
            .map_err(|source| tar_error("reading entry mode", source))?;
        if mode & 0o4000 != 0 {
            return Err(ArchiveError::SetuidBit(path.to_path_buf()));
        }
        if mode & 0o2000 != 0 {
            return Err(ArchiveError::SetgidBit(path.to_path_buf()));
        }
    }

    Ok(())
}

/// Re-validate a [`Placement`](crate::Placement) result: must be relative with
/// only `Normal` components, so a buggy/hostile placement cannot escape the
/// root.
pub fn validate_placed_path(rel: &Path) -> Result<(), ArchiveError> {
    if all_normal_components(rel) {
        Ok(())
    } else {
        Err(ArchiveError::PlacementEscapesRoot(rel.to_path_buf()))
    }
}
