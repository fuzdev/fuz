//! Use command - switch to an artifact by hash prefix

use crate::CliError;
use argh::FromArgs;
use fuz_artifact::{
    ArtifactError, History, SwitchOptions, acquire_artifact_lock, find_artifact,
    get_current_artifact, switch_to_artifact,
};

//
// CLI args
//

/// Switch to an existing artifact by hash prefix.
///
/// Use '-' to toggle between current and previous artifact (like `cd -`).
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "use")]
pub struct UseCmd {
    /// suppress progress output
    #[argh(switch, short = 'q')]
    pub quiet: bool,

    /// hash prefix (8+ chars), or '-' for previous artifact
    #[argh(positional)]
    pub hash: String,
}

//
// Command entry point
//

pub fn cmd_use(args: &UseCmd) -> Result<(), CliError> {
    // Handle "-" for previous artifact (like cd -)
    let meta = if args.hash == "-" {
        let history = History::read().map_err(CliError::Artifact)?;
        let prev_hash = history.previous().ok_or_else(|| {
            CliError::Artifact(ArtifactError::NotFound(
                "no previous artifact in history".to_string(),
            ))
        })?;
        find_artifact(prev_hash).map_err(CliError::Artifact)?
    } else {
        find_artifact(&args.hash).map_err(CliError::Artifact)?
    };

    // Get current artifact for rollback info
    let previous = get_current_artifact().map_err(CliError::Artifact)?;
    // Full `v1-<64 hex>` — see the note in `build.rs`; the field is one shape.
    let previous_hash = previous.as_ref().map(|m| m.hash.clone());

    // Check if already current
    if let Some(ref current) = previous
        && current.hash == meta.hash
    {
        if !args.quiet {
            println!("Already using {}... ({})", meta.short_hash(), meta.version);
        }
        return Ok(());
    }

    // Serialize with any concurrent build/bootstrap/upgrade — see the
    // doc on `switch_to_artifact` for why this lock matters.
    let lock = acquire_artifact_lock().map_err(CliError::Artifact)?;

    switch_to_artifact(
        SwitchOptions {
            hash: &meta.hash,
            version: &meta.version,
            previous_hash: previous_hash.as_deref(),
            quiet: args.quiet,
        },
        &lock,
    )
    .map_err(CliError::Artifact)
}
