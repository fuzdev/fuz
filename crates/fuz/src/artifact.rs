//! The `artifact` noun — manage the local content-addressed artifact store.
//!
//! `fuz artifact build / use / list / verify / prune / log` operates on the
//! `~/.fuz/artifacts/` store and the `current` symlink: build a new artifact
//! from source and switch to it, switch between stored artifacts, list and
//! verify them, prune old ones, and show the switch history.
//!
//! Consumer-side only: `fuz artifact build` produces a local *unsigned*
//! artifact for self-deploy; signing and publishing are producer tooling
//! (`fuzf` / `cargo xtask`), kept out of the `fuz` binary's dependency graph.
//! Grouping these verbs under the `artifact` noun keeps the CLI noun-first and
//! uniform with `fuz tool …` and `fuz self …`, and disambiguates the
//! artifact-store `verify` / `list` from the installed-tool `fuz tool verify` /
//! `fuz tool list`.

use argh::FromArgs;

use crate::CliError;
use crate::{build, list, log, prune, use_cmd, verify};

/// Manage the local content-addressed artifact store.
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "artifact")]
pub struct Artifact {
    #[argh(subcommand)]
    pub nested: ArtifactSub,
}

#[derive(FromArgs, Debug)]
#[argh(subcommand)]
pub enum ArtifactSub {
    Build(build::Build),
    Use(use_cmd::UseCmd),
    List(list::List),
    Verify(verify::Verify),
    Prune(prune::Prune),
    Log(log::Log),
}

pub fn cmd_artifact(args: Artifact) -> Result<(), CliError> {
    match args.nested {
        ArtifactSub::Build(opts) => build::cmd_build(&opts),
        ArtifactSub::Use(opts) => use_cmd::cmd_use(&opts),
        ArtifactSub::List(opts) => list::cmd_list(&opts),
        ArtifactSub::Verify(opts) => verify::cmd_verify(opts),
        ArtifactSub::Prune(opts) => prune::cmd_prune(&opts),
        ArtifactSub::Log(opts) => log::cmd_log(&opts),
    }
}
