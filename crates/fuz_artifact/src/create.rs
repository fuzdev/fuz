//! Artifact creation
//!
//! One entry point — [`create_artifact`] — handles both local builds and
//! bootstrap self-installs. They share so much (temp dir, atomic rename,
//! collision recovery, fsync discipline) that two parallel functions kept
//! drifting apart in ways that mattered (ENOSPC mapping, post-write
//! re-check). The only real difference is *where the binaries come from*
//! and *whether `inputs` is recorded* — both captured by [`BuildSource`].

#![expect(
    clippy::missing_errors_doc,
    reason = "every error is a self-explanatory `ArtifactError` variant"
)]

use super::ARTIFACT_DIR_MODE;
use super::error::ArtifactError;
use super::hash::{hash_binary, validate_and_hash_binary, verify_artifact};
use super::platform::ReleaseTarget;
use super::store::{StoreSlot, reclaim_store_entry, store_entry_path};
use super::types::{ArtifactInputs, ArtifactMeta, ArtifactOutputs};
use fuz_crypto::ContentHash;
use fuz_home::get_artifacts_dir;
use fuz_sys::{EXECUTABLE_FILE_MODE, SECURE_DIR_MODE};
use std::fs;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::Path;

/// Minimum free space required before creating an artifact (50 MB).
///
/// Mirrors the threshold `scripts/install.sh` enforces on `$TMPDIR` before
/// downloading, so the pre-check refuses the same scenarios at the same size.
const MIN_FREE_SPACE_BYTES: u64 = 50 * 1024 * 1024;

//
// Public API
//

/// Where the binaries for a new artifact come from.
///
/// `Local` is the path used by `fuz artifact build` and `cargo xtask install` —
/// the `fuz` binary is where cargo reported building it and we have full build
/// provenance.
/// `Bootstrap` is the path used by `fuz self bootstrap` — the running fuz
/// binary is already in memory and there's no git state or fuzd.
#[derive(Debug, Clone, Copy)]
pub enum BuildSource<'a> {
    /// Build from the `fuz` binary on disk, capturing git/rustc provenance.
    /// The self artifact is fuz-only, so only `fuz_binary` is read.
    Local {
        /// The built `fuz` binary: the path cargo reported
        /// ([`cargo_build_release`](crate::cargo_build_release)), never a
        /// guessed `target/release/fuz`.
        fuz_binary: &'a Path,
        /// Git+rustc inputs recorded in meta.json.
        inputs: &'a ArtifactInputs,
    },
    /// Self-install from the running fuz binary's bytes.
    Bootstrap {
        /// The fuz binary contents, already in memory.
        fuz_bytes: &'a [u8],
    },
}

impl BuildSource<'_> {
    /// Temp-dir prefix used while building. `cleanup_incomplete()` sweeps
    /// both prefixes; the distinction is purely for human inspection
    /// (`ls ~/.fuz/artifacts/`).
    const fn temp_prefix(&self) -> &'static str {
        match self {
            Self::Local { .. } => ".building-",
            Self::Bootstrap { .. } => ".bootstrapping-",
        }
    }
}

/// Create a new artifact from `source`, returning the resulting meta.
///
/// Flow:
/// 1. ensure `~/.fuz/artifacts/`, fail fast on a clearly-full disk
/// 2. compute expected output hashes (validates binaries for `Local`;
///    just hashes bytes for `Bootstrap`)
/// 3. early-return if a valid duplicate already exists at the target hash
///    (the deduplication case — e.g. re-running bootstrap with the same
///    binary); only a real directory qualifies — a symlink or other
///    non-directory there is removed, never adopted
/// 4. create `<prefix>-<random>/` temp dir with mode 0700
/// 5. write binaries into the temp dir (copy for `Local`, atomic write
///    for `Bootstrap`)
/// 6. re-hash the written binaries and check they match step 2
/// 7. write `meta.json` (atomic, parent-fsynced)
/// 8. re-check the collision slot — another process may have produced
///    the same `content_hash` while we were working
/// 9. rename temp → `v1-<content_hash>/`
/// 10. chmod final dir to 0755
/// 11. fsync the artifacts directory so the rename is durable across a
///     host crash
///
/// Collisions return the existing artifact rather than failing — same
/// `content_hash` means same binaries, so the caller is happy either way.
pub fn create_artifact(
    version: &str,
    source: BuildSource<'_>,
) -> Result<ArtifactMeta, ArtifactError> {
    let artifacts_dir = get_artifacts_dir()?;
    fuz_sys::fs::create_dir_all_mode(&artifacts_dir, SECURE_DIR_MODE)
        .map_err(|e| map_io_disk_error(e, &artifacts_dir))?;
    check_free_space(&artifacts_dir, MIN_FREE_SPACE_BYTES)?;

    // Step 2: hash inputs and build the expected metadata up-front so we
    // know the final dir before doing any copies/writes.
    let (expected_outputs, meta) = build_meta(version, &source)?;
    let final_dir = store_entry_path(&artifacts_dir, &meta.hash)?;

    // Step 3: early dedup. If a valid artifact already lives at this hash,
    // skip the temp-dir dance entirely.
    if let Some(existing) = resolve_existing_artifact(&artifacts_dir, &meta.hash)? {
        return Ok(existing);
    }

    // Step 4: temp dir with secure mode (no umask window).
    let temp_dir = artifacts_dir.join(format!(
        "{}{}",
        source.temp_prefix(),
        fuz_sys::rand::random_hex_suffix()
    ));
    create_secure_dir(&temp_dir)?;
    let cleanup_guard = fuz_sys::fs::CleanupGuard::new(temp_dir.clone());

    // Step 5: write binaries.
    write_binaries(&source, &temp_dir)?;

    // Step 6: re-hash the written binaries against what we expected.
    // Catches disk/memory errors during copy or write.
    verify_written_binaries(&temp_dir, &expected_outputs)?;

    // Step 7: meta.json (atomic + parent fsync via fs::write_atomic).
    meta.write(&temp_dir)?;

    // Step 8: re-check collision. Another `fuz artifact build`/`fuz self bootstrap`
    // may have produced the same content_hash and landed at final_dir
    // while we were copying and hashing. With BuildLock this is rare,
    // but it's still possible across host boots that left stale state.
    if let Some(existing) = resolve_existing_artifact(&artifacts_dir, &meta.hash)? {
        drop(cleanup_guard);
        return Ok(existing);
    }

    // Step 9: rename temp → final.
    fs::rename(&temp_dir, &final_dir).map_err(|source_err| {
        if source_err.kind() == std::io::ErrorKind::StorageFull {
            ArtifactError::InsufficientSpace {
                path: final_dir.clone(),
                source: source_err,
            }
        } else {
            ArtifactError::RenameFailed {
                from: temp_dir.clone(),
                to: final_dir.clone(),
                source: source_err,
            }
        }
    })?;
    cleanup_guard.defuse();

    // Step 10: final dir mode (world-readable/executable). Only after
    // rename succeeds, so the temp dir stays 0700 until it's a real
    // artifact.
    #[cfg(unix)]
    fs::set_permissions(&final_dir, fs::Permissions::from_mode(ARTIFACT_DIR_MODE))
        .map_err(|e| map_io_disk_error(e, &final_dir))?;

    // Step 11: fsync parent so the rename is durable.
    fuz_sys::fs::fsync_dir(&artifacts_dir).map_err(|e| map_io_disk_error(e, &artifacts_dir))?;

    Ok(meta)
}

//
// Per-source helpers
//

/// Hash whatever binaries `source` provides and build the corresponding
/// `ArtifactMeta`. Returns the expected outputs alongside so the caller
/// can re-verify after writing.
fn build_meta(
    version: &str,
    source: &BuildSource<'_>,
) -> Result<(ArtifactOutputs, ArtifactMeta), ArtifactError> {
    match source {
        BuildSource::Local { fuz_binary, inputs } => {
            // The build's target (`rustc -vV`'s host): a supported one, and
            // the one `fuz_binary` was built for.
            let target: ReleaseTarget = inputs.target.parse()?;
            let outputs = ArtifactOutputs {
                fuz: validate_and_hash_binary(fuz_binary, "fuz", target)?,
            };
            let meta = ArtifactMeta::new(version.to_string(), (*inputs).clone(), outputs.clone());
            Ok((outputs, meta))
        }
        BuildSource::Bootstrap { fuz_bytes } => {
            let fuz_hash = ContentHash::blake3(fuz_bytes);
            let outputs = ArtifactOutputs {
                fuz: fuz_hash.clone(),
            };
            let meta = ArtifactMeta::new_bootstrap(version.to_string(), fuz_hash);
            Ok((outputs, meta))
        }
    }
}

/// Write the self artifact's `fuz` binary from `source` into `temp_dir`.
///
/// `Local` copies `fuz` from disk (the `fs::copy` stream avoids loading the
/// binary into RAM). `Bootstrap` writes the in-memory fuz bytes via the
/// atomic-write helper (which fsyncs both file and parent).
///
/// Either way the file lands at exactly [`EXECUTABLE_FILE_MODE`], set after the
/// write rather than left to whatever the two writers produce — the mode is a
/// property of the artifact, not of the environment that built it, so it is
/// stated once here for both arms.
///
/// The two arms need it for different reasons. `fs::copy` gives the destination
/// the **source** file's mode, so a release dir holding a non-executable `fuz`
/// would otherwise store one — a failure independent of the umask.
/// `write_atomic`
/// opens with `O_CREAT, mode`, which POSIX masks by the process umask, so the
/// `Bootstrap` arm's mode would otherwise track the builder's environment
/// (`0700` at `umask 077`, `0750` at `027`; the common `022` / `002` / `000`
/// have no bits in `0755` and leave it alone).
fn write_binaries(source: &BuildSource<'_>, temp_dir: &Path) -> Result<(), ArtifactError> {
    let dst = temp_dir.join("fuz");
    match source {
        BuildSource::Local { fuz_binary, .. } => {
            fs::copy(fuz_binary, &dst).map_err(|e| {
                if e.kind() == std::io::ErrorKind::StorageFull {
                    ArtifactError::InsufficientSpace {
                        path: dst.clone(),
                        source: e,
                    }
                } else {
                    ArtifactError::CopyFailed {
                        binary: "fuz",
                        source: e,
                    }
                }
            })?;
        }
        BuildSource::Bootstrap { fuz_bytes } => {
            fuz_sys::fs::write_atomic(&dst, fuz_bytes, EXECUTABLE_FILE_MODE)
                .map_err(|e| map_io_disk_error(e, &dst))?;
        }
    }
    #[cfg(unix)]
    fs::set_permissions(&dst, fs::Permissions::from_mode(EXECUTABLE_FILE_MODE))
        .map_err(|e| map_io_disk_error(e, &dst))?;
    Ok(())
}

/// Re-hash the binaries we just wrote in `temp_dir` and confirm they
/// match what we expected from the source. Catches disk/memory errors,
/// interrupted copies, and the (cosmic-ray) case where blake3 disagrees
/// with itself across two reads.
fn verify_written_binaries(
    temp_dir: &Path,
    expected: &ArtifactOutputs,
) -> Result<(), ArtifactError> {
    // The self artifact is fuz-only — re-hash the single binary and compare.
    let actual = hash_binary(&temp_dir.join("fuz"))?;
    if actual != expected.fuz {
        return Err(ArtifactError::BinaryIntegrityFailed {
            binary: "fuz".to_string(),
            expected: expected.fuz.clone(),
            actual,
        });
    }
    Ok(())
}

//
// Shared helpers
//

/// Create `path` with mode 0700 in a single syscall (no chmod-after
/// window where another user could see permissive perms).
fn create_secure_dir(path: &Path) -> Result<(), ArtifactError> {
    #[cfg(unix)]
    {
        fs::DirBuilder::new()
            .mode(SECURE_DIR_MODE)
            .create(path)
            .map_err(|e| map_io_disk_error(e, path))
    }
    #[cfg(not(unix))]
    {
        fs::create_dir(path).map_err(|e| map_io_disk_error(e, path))
    }
}

/// Inspect `final_dir` and resolve any pre-existing entry.
///
/// The entry is classified by [`reclaim_store_entry`], never read through.
/// Outcomes:
/// - **Absent**: returns `Ok(None)` — caller proceeds.
/// - **Not a directory** (a symlink — dangling or not, even one aimed at a
///   directory that would verify — a plain file, or any other kind): treated as
///   corrupt and never adopted. The entry itself is unlinked (the link, never
///   its target) and `Ok(None)` is returned so the build proceeds. An artifact
///   is the directory `create_artifact` renamed into place; a link at that name
///   would make every later read of the artifact a read of whatever the link
///   points at.
/// - **Valid duplicate** (a real directory, same hash, binaries verify):
///   returns the existing meta so the caller can adopt it instead of
///   completing the rename.
/// - **Corrupt** (a real directory): removed in place so the rename can land.
///   That is a `meta.json` that cannot be read or parsed for any reason, one
///   recording another hash, a `fuz` that is missing, is not a regular file,
///   or hashes to something else.
/// - **Unreadable** (a real directory whose `meta.json` reads and names this
///   hash, and whose `fuz` is there but fails to open or read — permission
///   denied, a device error): kept as it is, and the error returned. What the
///   entry holds is unknown, and it may be recoverable; a missing `fuz` is
///   not that case, since no retry finds it.
fn resolve_existing_artifact(
    artifacts_dir: &Path,
    expected_hash: &str,
) -> Result<Option<ArtifactMeta>, ArtifactError> {
    // The shared store policy: a non-directory entry is unlinked (never a
    // link's target) and the slot reads as vacant.
    if reclaim_store_entry(artifacts_dir, expected_hash)? == StoreSlot::Vacant {
        return Ok(None);
    }
    let final_dir = &store_entry_path(artifacts_dir, expected_hash)?;
    match ArtifactMeta::read(final_dir) {
        Ok(existing) if existing.hash == expected_hash => match verify_artifact(final_dir) {
            Ok(()) => Ok(Some(existing)),
            // A missing file is what the entry holds, not a read that failed.
            Err(ArtifactError::Io(e)) if e.kind() != std::io::ErrorKind::NotFound => {
                Err(ArtifactError::Io(e))
            }
            Err(_) => {
                fs::remove_dir_all(final_dir).map_err(|e| map_io_disk_error(e, final_dir))?;
                Ok(None)
            }
        },
        _ => {
            fs::remove_dir_all(final_dir).map_err(|e| map_io_disk_error(e, final_dir))?;
            Ok(None)
        }
    }
}

/// Map ENOSPC-style IO errors to `InsufficientSpace`, else generic Io.
fn map_io_disk_error(source: std::io::Error, path: &Path) -> ArtifactError {
    if source.kind() == std::io::ErrorKind::StorageFull {
        ArtifactError::InsufficientSpace {
            path: path.to_path_buf(),
            source,
        }
    } else {
        ArtifactError::Io(source)
    }
}

/// Reject up front if the filesystem holding `path` has less than `required`
/// bytes free.
///
/// If statvfs itself fails (rare — happens on exotic mount points), this
/// returns `Ok(())` rather than blocking the install: the existing
/// mid-write `map_io_disk_error` path still catches ENOSPC, so we don't
/// regress when the pre-check can't run.
fn check_free_space(path: &Path, required: u64) -> Result<(), ArtifactError> {
    let Ok(available) = fuz_sys::fs::free_space_bytes(path) else {
        return Ok(());
    };
    if available < required {
        return Err(ArtifactError::InsufficientSpace {
            path: path.to_path_buf(),
            source: std::io::Error::from_raw_os_error(libc::ENOSPC),
        });
    }
    Ok(())
}

/// Get version from Cargo.toml in repo
pub fn get_cargo_version(repo_path: &Path) -> Result<String, ArtifactError> {
    let cargo_toml = repo_path.join("Cargo.toml");
    let content = fs::read_to_string(&cargo_toml).map_err(ArtifactError::Io)?;

    for line in content.lines() {
        let line = line.trim();
        if line.starts_with("version")
            && line.contains('=')
            && let Some(version) = line.split('=').nth(1)
        {
            return Ok(version.trim().trim_matches('"').to_string());
        }
    }

    Err(ArtifactError::Io(std::io::Error::other(
        "version not found in Cargo.toml",
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_free_space_passes_under_actual_capacity() {
        // 1 byte is well under whatever /tmp reports.
        check_free_space(Path::new("/tmp"), 1).expect("1 byte should always fit");
    }

    #[test]
    fn check_free_space_rejects_when_under_threshold() {
        // u64::MAX is larger than any real filesystem.
        let err = check_free_space(Path::new("/tmp"), u64::MAX)
            .expect_err("u64::MAX should exceed available space");
        match err {
            ArtifactError::InsufficientSpace { path, source } => {
                assert_eq!(path, Path::new("/tmp"));
                assert_eq!(source.raw_os_error(), Some(libc::ENOSPC));
            }
            other => panic!("expected InsufficientSpace, got {other:?}"),
        }
    }

    #[test]
    fn check_free_space_treats_statvfs_failure_as_ok() {
        // Non-existent path → statvfs ENOENT → pre-check yields Ok so the
        // existing mid-write ENOSPC path stays in charge.
        let missing = Path::new("/this/path/should/never/exist/fuz-test");
        check_free_space(missing, u64::MAX).expect("statvfs failure should not block");
    }
}
