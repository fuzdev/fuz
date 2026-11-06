//! Build command - create artifact from source and optionally install

use crate::CliError;
use argh::FromArgs;
use fuz_artifact::platform::ReleaseTarget;
use fuz_artifact::{
    ArtifactInputs, ArtifactMeta, BuildSource, CargoBuildOptions, SHORT_HASH_LEN, SwitchOptions,
    acquire_artifact_lock, cargo_build_release, check_built_for, cleanup_incomplete,
    create_artifact, find_by_inputs, get_artifact_dir, get_cargo_version, get_current_artifact,
    hash_binary, switch_to_artifact,
};
use std::path::{Path, PathBuf};

//
// Constants
//

/// Default source repo path (relative to home)
pub const DEFAULT_REPO_PATH: &str = "dev/fuz";

/// Env var to override source repo path
pub const REPO_ENV_VAR: &str = "FUZ_DEV_REPO";

//
// CLI args
//

/// Build from source, create artifact, switch to it.
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "build")]
#[allow(clippy::struct_excessive_bools)] // CLI flags are naturally boolean
pub struct Build {
    /// build but don't switch to the artifact
    #[argh(switch)]
    pub no_install: bool,

    /// show what would happen without building
    #[argh(switch)]
    pub dry_run: bool,

    /// suppress progress output
    #[argh(switch, short = 'q')]
    pub quiet: bool,

    /// rebuild to a temp dir and compare hashes
    #[argh(switch)]
    pub verify: bool,
}

//
// Command entry point
//

pub fn cmd_build(args: &Build) -> Result<(), CliError> {
    // Find and validate source repo
    let repo_path = find_source_repo()?;

    // Collect inputs
    let inputs = ArtifactInputs::collect(&repo_path).map_err(CliError::Artifact)?;
    let version = get_cargo_version(&repo_path).map_err(CliError::Artifact)?;

    // Format inputs description
    let inputs_desc = format!(
        "git:{}, rustc:{}, {}",
        inputs.short_commit(),
        extract_rustc_short(&inputs.rustc_version),
        inputs.dirty_str()
    );

    if args.dry_run {
        // Just show what would happen
        println!("Would build fuz {version}");
        println!(
            "  inputs: {}... ({inputs_desc})",
            &inputs.input_hash[..SHORT_HASH_LEN]
        );

        let cached = find_by_inputs(&inputs.input_hash).map_err(CliError::Artifact)?;
        if let Some(existing) = cached {
            println!(
                "  status: cached (skip build) -> {}",
                existing.display_hash()
            );
        } else {
            println!("  status: new artifact (not cached)");
        }
        return Ok(());
    }

    // Acquire artifact lock — held through the whole build + switch flow
    // so we never compete with a concurrent use/upgrade/bootstrap.
    let lock = acquire_artifact_lock().map_err(CliError::Artifact)?;

    // Clean up any incomplete artifacts from previous crashes
    let cleaned = cleanup_incomplete().map_err(CliError::Artifact)?;
    if cleaned > 0 && !args.quiet {
        eprintln!("Cleaned up {cleaned} incomplete artifact(s)");
    }

    // Read the current artifact (the rollback target) before building, so an
    // unreadable `current` — one outside the store, a symlink at the artifact
    // it names, a corrupt meta — fails the command before a release build is
    // spent on a switch that could not run. The lock is held from here to the
    // switch, so it cannot move in between. `--no-install` switches nothing
    // and reads nothing.
    let previous = if args.no_install {
        None
    } else {
        get_current_artifact().map_err(CliError::Artifact)?
    };

    // Check cache for matching inputs
    let cached = find_by_inputs(&inputs.input_hash).map_err(CliError::Artifact)?;

    // Get content hash for the new artifact (if we need to build)
    let (_meta, content_hash) = if let Some(existing) = cached {
        if !args.quiet {
            println!(
                "Using cached artifact {} ({inputs_desc})",
                existing.display_hash()
            );
        }
        let hash = existing.hash.clone();
        (existing, hash)
    } else {
        // Build
        if !args.quiet {
            println!("Building fuz {version}");
            println!(
                "  inputs: {}... ({inputs_desc})",
                &inputs.input_hash[..SHORT_HASH_LEN]
            );
        }

        let fuz_binary = build_release(&repo_path, &inputs)?;

        // Create artifact (fuz-only — fuzd is a separately-installed tool).
        let m = create_artifact(
            &version,
            BuildSource::Local {
                fuz_binary: &fuz_binary,
                inputs: &inputs,
            },
        )
        .map_err(CliError::Artifact)?;

        if !args.quiet {
            println!("Stored: {}", m.display_hash());
            // A fuz-only Local artifact hashes identically to a bootstrap
            // artifact with the same fuz bytes, so `create_artifact` may
            // dedup onto an existing bootstrap dir and return its (provenance-
            // less) meta. Harmless, but note the lost git/rustc provenance.
            if m.is_bootstrap() {
                println!(
                    "note: matched an existing bootstrap artifact with identical fuz bytes (git/rustc provenance not recorded)"
                );
            }
        }

        let hash = m.hash.clone();
        (m, hash)
    };

    // Verify reproducibility if requested
    if args.verify {
        verify_reproducibility(&repo_path, &inputs, &content_hash, args.quiet)?;
    }

    // Stop here if --no-install
    if args.no_install {
        return Ok(());
    }

    // Full `v1-<64 hex>`, matching `HistoryEntry::hash` and the two other
    // writers (`fuz self upgrade`, `fuz self bootstrap`). A short hash here left
    // the one field holding two shapes.
    let previous_hash = previous.as_ref().map(|m| m.hash.clone());

    // Check if already current
    if let Some(ref prev) = previous
        && prev.hash == content_hash
    {
        if !args.quiet {
            println!("Already using {} ({version})", prev.display_hash());
        }
        return Ok(());
    }

    switch_to_artifact(
        SwitchOptions {
            hash: &content_hash,
            version: &version,
            previous_hash: previous_hash.as_deref(),
            quiet: args.quiet,
        },
        &lock,
    )
    .map_err(CliError::Artifact)
}

//
// Source repo detection
//

fn find_source_repo() -> Result<PathBuf, CliError> {
    // Check env var first
    if let Ok(path) = std::env::var(REPO_ENV_VAR) {
        let repo_path = PathBuf::from(&path);
        validate_repo(&repo_path)?;
        return Ok(repo_path);
    }

    // Fall back to default path
    // An unusable `$HOME` names no default rather than one under the cwd.
    let home = fuz_sys::home_dir().map_err(|reason| CliError::SourceRepoNotFound {
        searched: vec![
            format!("${REPO_ENV_VAR}"),
            format!("~/{DEFAULT_REPO_PATH} ({reason})"),
        ],
    })?;

    let repo_path = home.join(DEFAULT_REPO_PATH);
    validate_repo(&repo_path)?;
    Ok(repo_path)
}

fn validate_repo(path: &Path) -> Result<(), CliError> {
    // Must exist
    if !path.exists() {
        return Err(CliError::SourceRepoNotFound {
            searched: vec![path.display().to_string()],
        });
    }

    // Must have Cargo.toml
    let cargo_toml = path.join("Cargo.toml");
    if !cargo_toml.exists() {
        return Err(CliError::InvalidSourceRepo {
            path: path.to_path_buf(),
            reason: "missing Cargo.toml",
        });
    }

    // Must have the fuz crate (the self artifact is fuz-only; fuzd builds
    // and installs on its own track via `cargo xtask install` / `fuz tool`).
    let fuz_crate = path.join("crates/fuz/Cargo.toml");
    if !fuz_crate.exists() {
        return Err(CliError::InvalidSourceRepo {
            path: path.to_path_buf(),
            reason: "missing crates/fuz",
        });
    }

    // Must be a git repo
    let git_dir = path.join(".git");
    if !git_dir.exists() {
        return Err(CliError::InvalidSourceRepo {
            path: path.to_path_buf(),
            reason: "not a git repository (fuz artifact build requires git)",
        });
    }

    Ok(())
}

//
// Build
//

/// The host's target as the toolchain names it (`rustc -vV`'s host, recorded
/// in the inputs): what every binary built here is held to.
fn host_target(inputs: &ArtifactInputs) -> Result<ReleaseTarget, CliError> {
    Ok(inputs
        .target
        .parse()
        .map_err(fuz_artifact::ArtifactError::from)?)
}

/// Build `fuz` for release and return the binary's path as cargo reported it
/// — wherever `CARGO_TARGET_DIR`, `build.target-dir`, or a build target put
/// it. Cargo's progress streams to the terminal.
///
/// A cargo configured to build for another target (`CARGO_BUILD_TARGET`, a
/// `build.target`) builds a binary this host's artifact cannot hold: it is
/// refused here, naming both targets, before anything is stored.
/// `create_artifact` holds the same path to the same target again.
fn build_release(repo_path: &Path, inputs: &ArtifactInputs) -> Result<PathBuf, CliError> {
    let fuz = cargo_build_release(
        &CargoBuildOptions {
            workspace: repo_path,
            package: "fuz",
            target_dir: None,
            quiet: false,
        },
        "fuz",
    )?;
    check_built_for("fuz", &fuz, host_target(inputs)?)?;
    Ok(fuz)
}

//
// Helpers
//

/// Extract short rustc version (e.g., "1.75.0" from "rustc 1.75.0 (82e1608df 2023-12-21)")
fn extract_rustc_short(version: &str) -> &str {
    version
        .strip_prefix("rustc ")
        .and_then(|s| s.split_whitespace().next())
        .unwrap_or(version)
}

//
// Verify reproducibility
//

/// Rebuild to a temp directory and compare output hashes
fn verify_reproducibility(
    repo_path: &Path,
    inputs: &ArtifactInputs,
    content_hash: &str,
    quiet: bool,
) -> Result<(), CliError> {
    if !quiet {
        println!("Verifying reproducibility...");
    }

    // Get stored artifact outputs
    let artifact_dir = get_artifact_dir(content_hash).map_err(CliError::Artifact)?;
    let meta = ArtifactMeta::read(&artifact_dir).map_err(CliError::Artifact)?;
    let stored = &meta.outputs;

    // Rebuild into a fresh private target directory, removed on drop
    let temp_target = verify_target_dir().map_err(|source| CliError::VerifyTargetDir { source })?;

    // The rebuild's path comes from cargo too: a configured build target
    // nests it under `<temp>/<triple>/release/`.
    let rebuilt_fuz = cargo_build_release(
        &CargoBuildOptions {
            workspace: repo_path,
            package: "fuz",
            target_dir: Some(temp_target.path()),
            quiet,
        },
        "fuz",
    )?;
    // A rebuild for another target can't match, and isn't corruption: refuse
    // it as what it is (exit 1), not as a failed reproducibility check (65).
    check_built_for("fuz", &rebuilt_fuz, host_target(inputs)?)?;

    // Hash rebuilt binary. The self artifact is fuz-only, so we compare just fuz.
    let fuz_hash = hash_binary(&rebuilt_fuz).map_err(CliError::Artifact)?;

    if fuz_hash == stored.fuz {
        if !quiet {
            println!("  fuz:  reproducible");
        }
        // `temp_target` drops here, removing the rebuild
        Ok(())
    } else {
        println!("Reproducibility check FAILED:");
        println!("  fuz:");
        println!("    stored:  {}", stored.fuz);
        println!("    rebuilt: {fuz_hash}");
        // Keep the rebuild for investigation
        let kept = temp_target.keep();
        println!("Rebuild artifacts kept at: {}", kept.display());
        Err(CliError::IntegrityCheckFailed {
            hash: meta.display_hash(),
        })
    }
}

/// A new `CARGO_TARGET_DIR` for the verify rebuild: mode `0700`, a random name
/// under the temp directory, removed when the guard drops. A fixed shared path
/// could be pre-created by another local user.
fn verify_target_dir() -> std::io::Result<tempfile::TempDir> {
    use std::os::unix::fs::PermissionsExt;
    tempfile::Builder::new()
        .prefix("fuz-verify-")
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_target_dir_is_private_fresh_and_removed_on_drop() {
        use std::os::unix::fs::PermissionsExt;
        let a = verify_target_dir().unwrap();
        let b = verify_target_dir().unwrap();
        assert_ne!(a.path(), b.path());
        let name = a.path().file_name().unwrap().to_string_lossy().into_owned();
        assert!(name.starts_with("fuz-verify-"), "{name}");
        let mode = std::fs::metadata(a.path()).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700);
        let path = a.path().to_path_buf();
        drop(a);
        assert!(!path.exists());
    }

    #[test]
    fn extract_rustc_short_takes_the_version_token() {
        assert_eq!(
            extract_rustc_short("rustc 1.75.0 (82e1608df 2023-12-21)"),
            "1.75.0"
        );
        // No `rustc ` prefix → returned unchanged.
        assert_eq!(extract_rustc_short("weird-input"), "weird-input");
    }
}
