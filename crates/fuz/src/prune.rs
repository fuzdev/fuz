//! Prune command - remove old artifacts
//!
//! **Dry-run by default**, like `cargo xtask prune`: without `--wetrun` it
//! lists what it would remove and deletes nothing.

use crate::CliError;
use argh::FromArgs;
use fuz_artifact::{acquire_artifact_lock, get_artifact_dir, get_current_artifact, list_artifacts};
use fuz_home::get_artifacts_dir;
use fuz_sys::fs::DirProbe;
use std::fs;

//
// CLI args
//

/// Remove old artifacts (keep N most recent + current).
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "prune")]
pub struct Prune {
    /// number of recent artifacts to keep
    #[argh(option, short = 'k', default = "5")]
    pub keep: usize,

    /// actually delete (default is a dry-run preview)
    #[argh(switch)]
    pub wetrun: bool,

    /// suppress output
    #[argh(switch, short = 'q')]
    pub quiet: bool,
}

//
// Command entry point
//

pub fn cmd_prune(args: &Prune) -> Result<(), CliError> {
    // With no `artifacts/` directory there is nothing to delete, and taking
    // the lock would create `run/` — and `~/.fuz` itself on a machine that has
    // none. Only that absence is read before the lock; nothing about what a
    // prune removes is decided from it.
    if matches!(
        fuz_sys::fs::probe_real_dir(&get_artifacts_dir()?),
        Ok(DirProbe::Absent)
    ) {
        if !args.quiet {
            println!("No artifacts to prune.");
        }
        return Ok(());
    }

    // A prune deletes from the store, so it holds the artifact lock like every
    // other mutator — taken before the store's entries or `current` are read,
    // so what is removed is decided from the state the lock protects, never
    // from a snapshot a concurrent switch has since moved past. The preview
    // (no `--wetrun`) deletes nothing and takes no lock.
    let _lock = if args.wetrun {
        Some(acquire_artifact_lock().map_err(CliError::Artifact)?)
    } else {
        None
    };

    // Get all artifacts (sorted newest first)
    let artifacts = list_artifacts().map_err(CliError::Artifact)?;

    if artifacts.is_empty() {
        if !args.quiet {
            println!("No artifacts to prune.");
        }
        return Ok(());
    }

    // Get current artifact hash - never prune current
    let current_hash = get_current_artifact()
        .map_err(CliError::Artifact)?
        .map(|m| m.hash);

    // Determine which to keep vs prune
    // Artifacts are sorted newest first, so keep the first N
    let mut to_keep = Vec::new();
    let mut to_prune = Vec::new();

    for (i, meta) in artifacts.iter().enumerate() {
        // Always keep current artifact
        if current_hash.as_ref() == Some(&meta.hash) {
            to_keep.push(meta);
        } else if i < args.keep {
            // Keep the N most recent
            to_keep.push(meta);
        } else {
            to_prune.push(meta);
        }
    }

    if to_prune.is_empty() {
        if !args.quiet {
            println!(
                "Nothing to prune ({} artifact{}, keeping {})",
                artifacts.len(),
                if artifacts.len() == 1 { "" } else { "s" },
                args.keep
            );
        }
        return Ok(());
    }

    // Show what we're doing
    if !args.quiet {
        let action = if args.wetrun {
            "Removing"
        } else {
            "Would remove"
        };
        println!(
            "{} {} artifact{} (keeping {})",
            action,
            to_prune.len(),
            if to_prune.len() == 1 { "" } else { "s" },
            to_keep.len()
        );

        for meta in &to_prune {
            let date = meta
                .created_at
                .split('T')
                .next()
                .unwrap_or(&meta.created_at);
            println!("  {}...  {}  {date}", meta.short_hash(), meta.version);
        }
    }

    if !args.wetrun {
        // `-q` silences the preview, not the fact that nothing was deleted: a
        // quiet run that meant to delete would otherwise end silently.
        if args.quiet {
            eprintln!("(dry run — pass --wetrun to delete)");
        } else {
            println!("(dry run — pass --wetrun to delete)");
        }
        return Ok(());
    }

    // Actually remove artifacts
    let mut removed = 0;
    let mut failed = 0;

    for meta in &to_prune {
        // Addressed by name through the store, so the directory removed is
        // always a child of `artifacts/` (the meta's hash is integrity-checked
        // too, but this does not lean on that).
        let removal = get_artifact_dir(&meta.hash)
            .map_err(std::io::Error::other)
            .and_then(|artifact_path| fs::remove_dir_all(&artifact_path));
        match removal {
            Ok(()) => removed += 1,
            Err(e) => {
                eprintln!(
                    "warning: failed to remove {}: {}",
                    meta.short_hash(),
                    fuz_sys::cli::format_error_chain(&e)
                );
                failed += 1;
            }
        }
    }

    if !args.quiet {
        println!(
            "Removed {removed} artifact{}",
            if removed == 1 { "" } else { "s" }
        );
        if failed > 0 {
            eprintln!("{failed} artifact(s) could not be removed");
        }
    }

    Ok(())
}
