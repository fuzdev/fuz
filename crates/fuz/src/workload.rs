//! The `workload` noun — the consumer surface for fuzd's workloads.
//!
//! fuzd hosts long-running *workloads* (observer, watcher, …) tied to client
//! demand. This noun is how `fuz` consumes them. Today it carries the observer
//! kind's `observe <domain>` verb; the generic `list` / `status` / `stop`
//! management verbs and other per-kind surfaces land here as they ship, so the
//! CLI stays noun-first (`fuz workload …` alongside `fuz tool …` /
//! `fuz artifact …` / `fuz self …`).
//!
//! This is the workload-*consumer* surface, not daemon lifecycle: fuzd owns its
//! own lifecycle CLI (`fuzd start/stop/…`), and `fuz` only observes fuzd over
//! the wire — it never drives it.

use argh::FromArgs;

use crate::CliError;
use crate::observe;

/// Interact with fuzd's demand-driven workloads.
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "workload")]
pub struct Workload {
    #[argh(subcommand)]
    pub nested: WorkloadSub,
}

#[derive(FromArgs, Debug)]
#[argh(subcommand)]
pub enum WorkloadSub {
    Observe(observe::Observe),
}

pub async fn cmd_workload(args: Workload) -> Result<(), CliError> {
    match args.nested {
        WorkloadSub::Observe(opts) => observe::cmd_observe(opts).await,
    }
}
