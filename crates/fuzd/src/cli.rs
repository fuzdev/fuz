//! `fuzd` CLI surface.
//!
//! fuzd owns its own lifecycle (per the noun-first grammar): `fuzd start /
//! stop / restart / status / logs`. The subcommand is **optional** — running
//! bare `fuzd` (no subcommand) starts the daemon process in the foreground,
//! which is what `fuzd start` spawns as a detached child and what dev/spawn
//! paths rely on.

use argh::FromArgs;
use fuz_daemon::DaemonError;
use std::process::ExitCode;

/// Fuz daemon — workload host. Run with no subcommand to start the daemon in
/// the foreground; use the subcommands to manage a backgrounded daemon.
#[derive(FromArgs, Debug)]
pub struct Fuzd {
    #[argh(subcommand)]
    pub command: Option<FuzdCommand>,
}

#[derive(FromArgs, Debug)]
#[argh(subcommand)]
pub enum FuzdCommand {
    Start(Start),
    Stop(Stop),
    Restart(Restart),
    Status(Status),
    Logs(Logs),
}

/// Start the daemon in the background.
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "start")]
pub struct Start {
    /// suppress output
    #[argh(switch, short = 'q')]
    pub quiet: bool,
}

/// Stop the daemon.
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "stop")]
pub struct Stop {
    /// suppress output
    #[argh(switch, short = 'q')]
    pub quiet: bool,

    /// force-kill if graceful shutdown times out or the daemon does not answer
    #[argh(switch, short = 'f')]
    pub force: bool,
}

/// Restart the daemon.
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "restart")]
pub struct Restart {
    /// suppress output
    #[argh(switch, short = 'q')]
    pub quiet: bool,

    /// force-kill if graceful shutdown times out or the daemon does not answer
    #[argh(switch, short = 'f')]
    pub force: bool,
}

/// Show daemon status (exit 0 if the daemon answers, 1 otherwise).
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "status")]
pub struct Status {
    /// machine-readable JSON output
    #[argh(switch)]
    pub json: bool,

    /// suppress output (exit code only)
    #[argh(switch, short = 'q')]
    pub quiet: bool,

    /// per-sidecar detail: runtime versions, dependencies, tools (sidecar builds only)
    #[argh(switch, short = 'v')]
    pub verbose: bool,
}

/// Show daemon logs.
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "logs")]
pub struct Logs {
    /// don't follow the log file
    #[argh(switch)]
    pub no_follow: bool,

    /// show the last N lines first (default 10)
    #[argh(option, short = 'n', long = "lines")]
    pub lines: Option<usize>,
}

/// Run a lifecycle subcommand, returning its process exit code.
pub async fn dispatch(command: FuzdCommand) -> Result<ExitCode, DaemonError> {
    match command {
        FuzdCommand::Start(opts) => fuz_daemon::start(opts.quiet).await,
        FuzdCommand::Stop(opts) => fuz_daemon::stop(opts.quiet, opts.force).await,
        FuzdCommand::Restart(opts) => fuz_daemon::restart(opts.quiet, opts.force).await,
        FuzdCommand::Status(opts) => fuz_daemon::status(opts.json, opts.quiet, opts.verbose).await,
        FuzdCommand::Logs(opts) => fuz_daemon::logs(opts.no_follow, opts.lines).await,
    }
}
