//! Verify command - check artifact integrity

use crate::CliError;
use argh::FromArgs;
use fuz_artifact::{ArtifactMeta, find_artifact, get_current_artifact, hash_binary};

//
// CLI args
//

/// Verify artifact integrity (re-hash binaries).
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "verify")]
pub struct Verify {
    /// hash prefix to verify (default: current artifact)
    #[argh(positional)]
    pub hash: Option<String>,
}

//
// Command entry point
//

pub fn cmd_verify(args: Verify) -> Result<(), CliError> {
    // Get artifact to verify
    let meta = if let Some(hash) = args.hash {
        // Verify specific artifact by prefix
        find_artifact(&hash).map_err(CliError::Artifact)?
    } else {
        // Verify current artifact
        get_current_artifact()
            .map_err(CliError::Artifact)?
            .ok_or(CliError::NoCurrentArtifact)?
    };

    verify_and_print(&meta)
}

fn verify_and_print(meta: &ArtifactMeta) -> Result<(), CliError> {
    println!("Verifying {}...", meta.display_hash());

    let artifact_dir = fuz_artifact::get_artifact_dir(&meta.hash).map_err(CliError::Artifact)?;

    // The self artifact is fuz-only.
    let fuz_ok = verify_binary("fuz", &artifact_dir.join("fuz"), &meta.outputs.fuz);

    if fuz_ok {
        Ok(())
    } else {
        Err(CliError::IntegrityCheckFailed {
            hash: meta.display_hash(),
        })
    }
}

/// Verify a single binary's hash and print result
fn verify_binary(name: &str, path: &std::path::Path, expected: &fuz_artifact::ContentHash) -> bool {
    match hash_binary(path) {
        Ok(actual) if actual == *expected => {
            println!("  {name}: ok");
            true
        }
        Ok(actual) => {
            println!("  {name}: FAILED");
            println!("    expected: {expected}");
            println!("    actual:   {actual}");
            false
        }
        Err(e) => {
            println!("  {name}: ERROR ({e})");
            false
        }
    }
}
