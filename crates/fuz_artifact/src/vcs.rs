//! VCS operations for artifact input collection.
//!
//! Shells the `git` CLI to derive the build-input provenance an artifact hash
//! covers: the current commit SHA plus a hash of any uncommitted working-tree
//! changes (staged, unstaged, and untracked, not ignored). Lives here, in its
//! sole consumer, rather than in the generic `fuz_sys` leaf — only the
//! distribution domain needs VCS state, so the HTTP spine that depends on
//! `fuz_sys` doesn't compile it. Diff hashing routes through
//! `fuz_crypto::Hasher`, the workspace hashing home.

use fuz_crypto::{HashAlgo, Hasher};
use std::ffi::OsStr;
use std::fs;
use std::io::BufReader;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use thiserror::Error;

//
// Error type
//

/// Errors from VCS operations.
#[derive(Debug, Error)]
pub enum VcsError {
    /// Not a git repository.
    #[error("not a git repository: {0}")]
    NotRepo(PathBuf),

    /// Git command failed.
    #[error("git command failed: {0}")]
    CommandFailed(String),

    /// Untracked file could not be read.
    #[error("cannot read untracked file '{file}': {reason}")]
    UnreadableFile { file: String, reason: String },
}

//
// Public API
//

/// Get the current commit SHA (40 hex chars).
///
/// # Errors
///
/// Returns an error if the git command fails (not a repo, git not installed, etc.)
pub fn get_commit(repo_path: &Path) -> Result<String, VcsError> {
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(repo_path)
        .output()
        .map_err(|e| VcsError::CommandFailed(e.to_string()))?;

    if !output.status.success() {
        return Err(VcsError::CommandFailed(
            String::from_utf8_lossy(&output.stderr).to_string(),
        ));
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Get a hash of all uncommitted changes (staged, unstaged, and untracked).
///
/// Returns `None` if the working directory is clean.
///
/// The hash covers:
/// - `git diff --binary HEAD` (every tracked change, binary files' bytes
///   included), prefixed with its length
/// - each untracked, non-ignored file (`git ls-files -z --others
///   --exclude-standard`), in byte order of its name: the name, a NUL, then
///   the BLAKE3 of its content (streamed)
///
/// The records are length-prefixed or fixed-width, so no file name or content
/// can be read as another's. Ignored files are not covered.
///
/// # Errors
///
/// [`VcsError::CommandFailed`] if either `git` command cannot run or exits
/// unsuccessfully (a failed diff never reads as a clean tree), and
/// [`VcsError::UnreadableFile`] if an untracked file cannot be read: every
/// input must be read for the hash to mean anything.
pub fn get_diff_hash(repo_path: &Path) -> Result<Option<String>, VcsError> {
    // Every tracked change (staged + unstaged) against HEAD. `--binary` puts a
    // binary file's bytes in the diff (without it, two edits to one binary
    // read the same); colour, external diff drivers, and textconv filters are
    // off so the output is the content, not a rendering of it.
    let diff = git_stdout(
        repo_path,
        &[
            "diff",
            "--binary",
            "--no-color",
            "--no-ext-diff",
            "--no-textconv",
            "HEAD",
        ],
    )?;

    // Untracked files, NUL-separated: a name is any bytes but NUL, so nothing
    // is unquoted, trimmed, or split on a newline.
    let untracked_output = git_stdout(
        repo_path,
        &["ls-files", "-z", "--others", "--exclude-standard"],
    )?;
    let mut untracked_files: Vec<&[u8]> = untracked_output
        .split(|b| *b == 0)
        .filter(|name| !name.is_empty())
        .collect();
    untracked_files.sort_unstable();

    if diff.is_empty() && untracked_files.is_empty() {
        return Ok(None);
    }

    let mut hasher = Hasher::new(HashAlgo::Blake3);
    hasher.update(&(diff.len() as u64).to_le_bytes());
    hasher.update(&diff);

    for name in untracked_files {
        let shown = || String::from_utf8_lossy(name).into_owned();
        let unreadable = |e: std::io::Error| VcsError::UnreadableFile {
            file: shown(),
            reason: e.to_string(),
        };
        let f = fs::File::open(repo_path.join(OsStr::from_bytes(name))).map_err(unreadable)?;
        let mut content = Hasher::new(HashAlgo::Blake3);
        content
            .update_reader(BufReader::new(f))
            .map_err(unreadable)?;

        hasher.update(name);
        hasher.update(b"\0");
        hasher.update(content.finalize().as_bytes());
    }

    Ok(Some(hasher.finalize().to_hex()))
}

/// Run `git` in `repo_path` and return its stdout, refusing a run that failed.
fn git_stdout(repo_path: &Path, args: &[&str]) -> Result<Vec<u8>, VcsError> {
    let output = Command::new("git")
        .args(args)
        .current_dir(repo_path)
        .output()
        .map_err(|e| VcsError::CommandFailed(e.to_string()))?;
    if !output.status.success() {
        return Err(VcsError::CommandFailed(format!(
            "git {} exited with {}: {}",
            args.first().copied().unwrap_or_default(),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(output.stdout)
}

/// Check if a path is a git repository.
#[must_use]
pub fn is_repo(path: &Path) -> bool {
    path.join(".git").exists()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to run git commands in a directory
    fn git(dir: &Path, args: &[&str]) -> bool {
        Command::new("git")
            .args(args)
            .current_dir(dir)
            .output()
            .is_ok_and(|o| o.status.success())
    }

    /// Create a minimal git repo with one commit (so HEAD exists)
    fn init_repo(dir: &Path) {
        git(dir, &["init"]);
        git(dir, &["config", "user.email", "test@test.com"]);
        git(dir, &["config", "user.name", "Test"]);
        // Create initial commit so HEAD exists
        fs::write(dir.join(".gitkeep"), "").unwrap();
        git(dir, &["add", ".gitkeep"]);
        git(dir, &["commit", "-m", "initial"]);
    }

    #[test]
    fn is_repo_true_for_git_dir() {
        let dir = tempfile::tempdir().unwrap();
        init_repo(dir.path());
        assert!(is_repo(dir.path()));
    }

    #[test]
    fn is_repo_false_for_non_git_dir() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!is_repo(dir.path()));
    }

    #[test]
    fn get_commit_returns_40_char_sha() {
        let dir = tempfile::tempdir().unwrap();
        init_repo(dir.path());

        let commit = get_commit(dir.path()).unwrap();
        assert_eq!(commit.len(), 40);
        assert!(commit.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn get_diff_hash_none_when_clean() {
        let dir = tempfile::tempdir().unwrap();
        init_repo(dir.path());

        let hash = get_diff_hash(dir.path()).unwrap();
        assert!(hash.is_none());
    }

    #[test]
    fn get_diff_hash_some_with_untracked_file() {
        let dir = tempfile::tempdir().unwrap();
        init_repo(dir.path());

        // Add untracked file
        fs::write(dir.path().join("untracked.txt"), "content").unwrap();

        let hash = get_diff_hash(dir.path()).unwrap();
        assert!(hash.is_some());
    }

    #[test]
    fn get_diff_hash_changes_when_untracked_content_changes() {
        let dir = tempfile::tempdir().unwrap();
        init_repo(dir.path());

        let file_path = dir.path().join("untracked.txt");

        // Create untracked file with content A
        fs::write(&file_path, "content A").unwrap();
        let hash_a = get_diff_hash(dir.path()).unwrap().unwrap();

        // Change content to B
        fs::write(&file_path, "content B").unwrap();
        let hash_b = get_diff_hash(dir.path()).unwrap().unwrap();

        // Hashes should differ
        assert_ne!(
            hash_a, hash_b,
            "hash should change when untracked file content changes"
        );
    }

    #[test]
    fn get_diff_hash_changes_when_tracked_file_modified() {
        let dir = tempfile::tempdir().unwrap();
        init_repo(dir.path());

        // Create and commit a tracked file
        let file_path = dir.path().join("tracked.txt");
        fs::write(&file_path, "original").unwrap();
        git(dir.path(), &["add", "tracked.txt"]);
        git(dir.path(), &["commit", "-m", "add tracked"]);

        // Should be clean
        assert!(get_diff_hash(dir.path()).unwrap().is_none());

        // Modify tracked file (unstaged)
        fs::write(&file_path, "modified").unwrap();
        let hash = get_diff_hash(dir.path()).unwrap();
        assert!(
            hash.is_some(),
            "should detect unstaged changes to tracked files"
        );
    }

    #[test]
    fn get_diff_hash_deterministic() {
        let dir = tempfile::tempdir().unwrap();
        init_repo(dir.path());

        fs::write(dir.path().join("file.txt"), "content").unwrap();

        let hash1 = get_diff_hash(dir.path()).unwrap().unwrap();
        let hash2 = get_diff_hash(dir.path()).unwrap().unwrap();

        assert_eq!(hash1, hash2);
    }

    /// Two edits to one tracked binary file differ: without `--binary` the
    /// diff reads "Binary files differ" for both.
    #[test]
    fn get_diff_hash_changes_when_tracked_binary_changes() {
        let dir = tempfile::tempdir().unwrap();
        init_repo(dir.path());
        let file_path = dir.path().join("blob.bin");
        fs::write(&file_path, b"\0\x01original").unwrap();
        git(dir.path(), &["add", "blob.bin"]);
        git(dir.path(), &["commit", "-m", "add blob"]);

        fs::write(&file_path, b"\0\x01edit a").unwrap();
        let hash_a = get_diff_hash(dir.path()).unwrap().unwrap();
        fs::write(&file_path, b"\0\x01edit b").unwrap();
        let hash_b = get_diff_hash(dir.path()).unwrap().unwrap();
        assert_ne!(hash_a, hash_b);
    }

    /// A diff that fails is an error, never a clean tree.
    #[test]
    fn get_diff_hash_fails_when_git_fails() {
        let dir = tempfile::tempdir().unwrap();
        // A repository with no commit has no `HEAD` to diff against.
        git(dir.path(), &["init"]);
        assert!(matches!(
            get_diff_hash(dir.path()),
            Err(VcsError::CommandFailed(_))
        ));
    }

    /// Untracked names are read whole: a newline or surrounding space in one
    /// is part of the name, not a separator to trim.
    #[test]
    fn get_diff_hash_reads_untracked_names_whole() {
        let dir = tempfile::tempdir().unwrap();
        init_repo(dir.path());
        fs::write(dir.path().join("a\nb"), "x").unwrap();
        fs::write(dir.path().join(" padded "), "y").unwrap();
        let hash = get_diff_hash(dir.path()).unwrap().unwrap();

        let other = tempfile::tempdir().unwrap();
        init_repo(other.path());
        fs::write(other.path().join("a"), "x").unwrap();
        fs::write(other.path().join("padded"), "y").unwrap();
        assert_ne!(hash, get_diff_hash(other.path()).unwrap().unwrap());
    }

    /// Ignored files are not inputs.
    #[test]
    fn get_diff_hash_skips_ignored_files() {
        let dir = tempfile::tempdir().unwrap();
        init_repo(dir.path());
        fs::write(dir.path().join(".gitignore"), "target/\n").unwrap();
        git(dir.path(), &["add", ".gitignore"]);
        git(dir.path(), &["commit", "-m", "ignore"]);
        fs::create_dir(dir.path().join("target")).unwrap();
        fs::write(dir.path().join("target/out"), "built").unwrap();
        assert!(get_diff_hash(dir.path()).unwrap().is_none());
    }

    #[test]
    fn get_diff_hash_differs_by_filename() {
        let dir1 = tempfile::tempdir().unwrap();
        let dir2 = tempfile::tempdir().unwrap();
        init_repo(dir1.path());
        init_repo(dir2.path());

        // Same content, different filename
        fs::write(dir1.path().join("file_a.txt"), "same content").unwrap();
        fs::write(dir2.path().join("file_b.txt"), "same content").unwrap();

        let hash1 = get_diff_hash(dir1.path()).unwrap().unwrap();
        let hash2 = get_diff_hash(dir2.path()).unwrap().unwrap();

        assert_ne!(hash1, hash2, "hash should differ when filename differs");
    }
}
