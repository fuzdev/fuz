//! List command - show local artifacts

use crate::CliError;
use argh::FromArgs;
use fuz_artifact::{ArtifactSource, SHORT_HASH_LEN, get_current_artifact, list_artifacts};
use serde::Serialize;

//
// CLI args
//

/// List local artifacts.
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "list")]
pub struct List {
    /// machine-readable JSON output
    #[argh(switch)]
    pub json: bool,
}

//
// JSON output format
//

#[derive(Serialize)]
struct ListOutput {
    current: Option<String>,
    artifacts: Vec<ArtifactEntry>,
}

#[derive(Serialize)]
struct ArtifactEntry {
    hash: String,
    version: String,
    created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    input_hash: Option<String>,
    source: ArtifactSource,
    is_current: bool,
    outputs: OutputHashes,
}

#[derive(Serialize)]
struct OutputHashes {
    fuz: String,
}

//
// Command entry point
//

pub fn cmd_list(args: &List) -> Result<(), CliError> {
    let artifacts = list_artifacts().map_err(CliError::Artifact)?;

    // Get current artifact hash for marking
    let current_hash = get_current_artifact()
        .map_err(CliError::Artifact)?
        .map(|m| m.hash);

    if args.json {
        return print_json(&artifacts, current_hash.as_deref());
    }

    if artifacts.is_empty() {
        println!("No artifacts found.");
        println!();
        println!("Run 'fuz artifact build' to create an artifact from source.");
        return Ok(());
    }

    println!("Local artifacts:");

    for meta in &artifacts {
        let marker = if current_hash.as_ref() == Some(&meta.hash) {
            "*"
        } else {
            " "
        };

        // Parse date from created_at (format: "2025-01-15T10:30:00Z")
        let date = meta
            .created_at
            .split('T')
            .next()
            .unwrap_or(&meta.created_at);

        // Short output hash (fuz binary, 8 chars) - shows when builds produce identical binaries
        let out_hash = format!("out:{}", &meta.outputs.fuz.to_hex()[..SHORT_HASH_LEN]);

        let current_label = if current_hash.as_ref() == Some(&meta.hash) {
            "  (current)"
        } else {
            ""
        };

        // Provenance hint: bootstrap artifacts have no git/build inputs.
        let kind_label = if meta.is_bootstrap() {
            "  (bootstrap)"
        } else {
            ""
        };

        println!(
            "  {marker} {}  {}  {date}  {out_hash}{kind_label}{current_label}",
            meta.display_hash(),
            meta.version
        );
    }

    Ok(())
}

fn print_json(
    artifacts: &[fuz_artifact::ArtifactMeta],
    current_hash: Option<&str>,
) -> Result<(), CliError> {
    let entries: Vec<ArtifactEntry> = artifacts
        .iter()
        .map(|m| ArtifactEntry {
            hash: m.hash.clone(),
            version: m.version.clone(),
            created_at: m.created_at.clone(),
            input_hash: m.inputs.as_ref().map(|i| i.input_hash.clone()),
            source: m.source,
            is_current: current_hash == Some(&m.hash),
            outputs: OutputHashes {
                fuz: m.outputs.fuz.to_hex(),
            },
        })
        .collect();

    let output = ListOutput {
        current: current_hash.map(String::from),
        artifacts: entries,
    };

    let json = serde_json::to_string_pretty(&output).map_err(CliError::Json)?;
    println!("{json}");
    Ok(())
}
