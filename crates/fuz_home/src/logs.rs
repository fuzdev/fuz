//! Log file utilities
//!
//! Provides log path resolution and rotation for the CLI.

use crate::error::FuzHomeError;
use crate::paths::{DAEMON_LOG_FILE, get_logs_dir};
use std::path::PathBuf;

/// Get path to daemon output log file
///
/// Returns `~/.fuz/state/logs/daemon_output.log`
///
/// # Errors
/// Returns an error if the fuz home cannot be resolved (see
/// [`get_fuz_home`](crate::get_fuz_home)).
pub fn get_daemon_log_path() -> Result<PathBuf, FuzHomeError> {
    Ok(get_logs_dir()?.join(DAEMON_LOG_FILE))
}

/// Rotate log files with a maximum number of rotations
///
/// Rotation scheme:
/// - `file.log` → `file.log.1` → `file.log.2` → ... → `file.log.{max}`
/// - Oldest file (`file.log.{max}`) is deleted
///
/// # Arguments
/// * `log_path` - Path to the main log file (e.g., `daemon_output.log`)
/// * `max_rotations` - Maximum number of rotated files to keep
///
/// # Errors
/// Returns an error if file operations fail.
pub fn rotate_logs(log_path: &PathBuf, max_rotations: u32) -> Result<(), FuzHomeError> {
    if !log_path.exists() {
        return Ok(());
    }

    // Delete oldest if at max
    let oldest = log_path.with_extension(format!("log.{max_rotations}"));
    if oldest.exists() {
        std::fs::remove_file(&oldest).map_err(|source| FuzHomeError::DeleteFailed {
            path: oldest,
            source,
        })?;
    }

    // Rotate existing: .{n-1} -> .{n}, ..., .1 -> .2
    for i in (1..max_rotations).rev() {
        let from = log_path.with_extension(format!("log.{i}"));
        let to = log_path.with_extension(format!("log.{}", i + 1));
        if from.exists() {
            std::fs::rename(&from, &to).map_err(|source| FuzHomeError::RenameFailed {
                from,
                to,
                source,
            })?;
        }
    }

    // Current -> .1
    let rotated = log_path.with_extension("log.1");
    std::fs::rename(log_path, &rotated).map_err(|source| FuzHomeError::RenameFailed {
        from: log_path.clone(),
        to: rotated,
        source,
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_rotate_logs_no_file() {
        let dir = TempDir::new().unwrap();
        let log = dir.path().join("test.log");

        // Should succeed even if file doesn't exist
        assert!(rotate_logs(&log, 3).is_ok());
    }

    #[test]
    fn test_rotate_logs_single_file() {
        let dir = TempDir::new().unwrap();
        let log = dir.path().join("test.log");

        // Create initial log file
        fs::write(&log, "content").unwrap();

        // Rotate
        rotate_logs(&log, 3).unwrap();

        // Original should be gone, .1 should exist
        assert!(!log.exists());
        assert!(log.with_extension("log.1").exists());
        assert_eq!(
            fs::read_to_string(log.with_extension("log.1")).unwrap(),
            "content"
        );
    }

    #[test]
    fn test_rotate_logs_cascading() {
        let dir = TempDir::new().unwrap();
        let log = dir.path().join("test.log");

        // Create files
        fs::write(&log, "new").unwrap();
        fs::write(log.with_extension("log.1"), "old1").unwrap();
        fs::write(log.with_extension("log.2"), "old2").unwrap();

        // Rotate with max 3
        rotate_logs(&log, 3).unwrap();

        // Check results
        assert!(!log.exists());
        assert_eq!(
            fs::read_to_string(log.with_extension("log.1")).unwrap(),
            "new"
        );
        assert_eq!(
            fs::read_to_string(log.with_extension("log.2")).unwrap(),
            "old1"
        );
        assert_eq!(
            fs::read_to_string(log.with_extension("log.3")).unwrap(),
            "old2"
        );
    }

    #[test]
    fn test_rotate_logs_deletes_oldest() {
        let dir = TempDir::new().unwrap();
        let log = dir.path().join("test.log");

        // Create files at max
        fs::write(&log, "new").unwrap();
        fs::write(log.with_extension("log.1"), "old1").unwrap();
        fs::write(log.with_extension("log.2"), "old2").unwrap();
        fs::write(log.with_extension("log.3"), "oldest").unwrap();

        // Rotate with max 3
        rotate_logs(&log, 3).unwrap();

        // oldest should be deleted
        assert!(!log.exists());
        assert_eq!(
            fs::read_to_string(log.with_extension("log.1")).unwrap(),
            "new"
        );
        assert_eq!(
            fs::read_to_string(log.with_extension("log.2")).unwrap(),
            "old1"
        );
        assert_eq!(
            fs::read_to_string(log.with_extension("log.3")).unwrap(),
            "old2"
        );
    }
}
