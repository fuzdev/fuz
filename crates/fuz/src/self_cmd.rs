//! The `self` noun — operations that act on the fuz binary itself.
//!
//! `fuz self bootstrap` / `upgrade` / `version` / `status`. Per the
//! noun-first grammar, `self` namespaces "the fuz binary itself" so
//! `fuz self upgrade` reads parallel to `fuz tool install <name>` rather
//! than as a bare top-level verb. Daemon state lives on `fuzd status`;
//! `fuz self status` reports fuz's own state (version, current artifact)
//! plus a one-line daemon-presence summary.
//!
//! Every `self` command warns on stderr when the cached release log head
//! records as revoked the version it reports — the installed artifact's, or
//! this binary's own when nothing is installed (see `crate::release_log`).
//! `version` and `status` read that cache and nothing else, and report
//! whatever state it is in — they never fail on it.
//!
//! `version` and `status` are diagnostics, so a fuz home that cannot be
//! resolved (a relative `FUZ_HOME`, an unusable `HOME`) does not fail them
//! either: the home layer's error and its hint are a warning on stderr, the
//! command reports what it knows without a home — this binary's own version —
//! and exits 0. What lives under the home is then unknown, and is reported as
//! unknown rather than as absent: no artifact is named, `status` prints `fuzd:
//! unknown` with no install hint, and `status --json` carries `"fuzd": null`.

use crate::CliError;
use crate::bootstrap::{Bootstrap, cmd_bootstrap};
use crate::fuzd;
use crate::release::{Upgrade, cmd_upgrade};
use argh::FromArgs;
use fuz_artifact::{ArtifactMeta, get_current_artifact};
use fuz_home::read_daemon_info;

//
// CLI args
//

/// Manage the fuz binary itself (bootstrap, upgrade, version, status).
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "self")]
pub struct SelfCmd {
    #[argh(subcommand)]
    pub nested: SelfSub,
}

#[derive(FromArgs, Debug)]
#[argh(subcommand)]
pub enum SelfSub {
    Bootstrap(Bootstrap),
    Upgrade(Upgrade),
    Version(Version),
    Status(Status),
}

/// Show version info.
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "version")]
pub struct Version {}

/// Show fuz CLI state (version, current artifact, daemon presence).
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "status")]
pub struct Status {
    /// machine-readable JSON output
    #[argh(switch)]
    pub json: bool,
}

//
// Dispatch
//

pub async fn cmd_self(args: SelfCmd) -> Result<(), CliError> {
    match args.nested {
        SelfSub::Bootstrap(opts) => cmd_bootstrap(&opts).await,
        SelfSub::Upgrade(opts) => cmd_upgrade(opts).await,
        SelfSub::Version(_) => {
            cmd_version();
            Ok(())
        }
        SelfSub::Status(opts) => cmd_status(&opts),
    }
}

//
// version
//

/// Print version line with artifact info.
/// Format: "fuz 0.1.0 (cf71b2e-dirty, artifact 2321d645)".
/// For remote artifacts without git info: "fuz 0.1.0 (remote, artifact 2321d645)".
fn print_version_with_artifact(meta: &ArtifactMeta) {
    let git_info = meta.inputs.as_ref().map_or_else(
        || "remote".to_string(),
        |inputs| {
            let dirty_suffix = if inputs.is_dirty() { "-dirty" } else { "" };
            format!("{}{}", inputs.short_commit(), dirty_suffix)
        },
    );
    println!(
        "fuz {} ({}, artifact {})",
        env!("CARGO_PKG_VERSION"),
        git_info,
        meta.short_hash()
    );
}

/// Whether the fuz home resolves. When it does not, the home layer's error and
/// its hint are printed to stderr as a warning: the diagnostics go on, and
/// report what lives under the home as unknown.
fn home_resolves() -> bool {
    let Err(error) = fuz_home::get_fuz_home() else {
        return true;
    };
    for line in home_warning_lines(&error) {
        eprintln!("{line}");
    }
    false
}

/// The lines `home_resolves` prints: the error as a warning, then its hint.
fn home_warning_lines(error: &fuz_home::FuzHomeError) -> Vec<String> {
    let mut lines = vec![format!("warning: {error}")];
    if let Some(hint) = error.hint() {
        lines.push(format!("hint: {hint}"));
    }
    lines
}

/// The installed artifact and its standing in the cached release log head, for
/// a diagnostic. Without a fuz home neither can be read — both live under it —
/// so only the release log configuration is looked at.
fn installed_state(
    home_resolves: bool,
) -> (Option<ArtifactMeta>, Option<fuz_release::InstalledStanding>) {
    if !home_resolves {
        crate::release_log::diagnose_configuration();
        return (None, None);
    }
    let artifact = get_current_artifact().ok().flatten();
    let standing =
        crate::release_log::diagnose(crate::release_log::reported_version(artifact.as_ref()));
    (artifact, standing)
}

fn cmd_version() {
    // Show git commit from artifact metadata; fall back to compile-time
    // FUZ_GIT_INFO when no artifact is installed, or none can be looked for.
    let (artifact, _) = installed_state(home_resolves());
    if let Some(meta) = artifact {
        print_version_with_artifact(&meta);
    } else {
        let git_info = option_env!("FUZ_GIT_INFO").unwrap_or("unknown");
        println!("fuz {} ({})", env!("CARGO_PKG_VERSION"), git_info);
    }
}

//
// status
//

fn cmd_status(opts: &Status) -> Result<(), CliError> {
    let home_resolves = home_resolves();
    // The installed artifact, and what the cached release log head says about
    // the installed fuz; warnings go to stderr, so `--json` stdout stays one
    // JSON document.
    let (artifact, standing) = installed_state(home_resolves);
    // fuzd is a separately-installed tool — probe it passively (a bare UDS
    // connect, no frame) rather than linking the daemon-client. pid is read from daemon.json (best-effort)
    // only when fuzd reports itself running. `None` is a daemon whose state is
    // unknown: there is no home to look for it under, or the home resolves but
    // no daemon could listen under it (a socket path too long), which warns
    // like an unresolvable home.
    let daemon = if home_resolves {
        match fuzd::state() {
            Ok(state) => Some(state),
            Err(error) => {
                for line in home_warning_lines(&error) {
                    eprintln!("{line}");
                }
                None
            }
        }
    } else {
        None
    };
    let pid = if daemon == Some(fuzd::FuzdState::Running) {
        read_daemon_info().ok().flatten().map(|info| info.pid)
    } else {
        None
    };

    if opts.json {
        let mut output = serde_json::json!({ "version": env!("CARGO_PKG_VERSION") });
        if let Some(ref meta) = artifact {
            let mut artifact_json = serde_json::json!({ "hash": meta.hash });
            if let Some(ref inputs) = meta.inputs {
                artifact_json["dirty"] = serde_json::json!(inputs.is_dirty());
                artifact_json["commit"] = serde_json::json!(inputs.short_commit());
            }
            artifact_json["source"] = serde_json::json!(meta.source);
            output["artifact"] = artifact_json;
        }
        output["fuzd"] = match daemon {
            Some(fuzd::FuzdState::Running) => serde_json::json!({ "running": true, "pid": pid }),
            Some(fuzd::FuzdState::Stopped) => {
                serde_json::json!({ "running": false, "installed": true })
            }
            Some(fuzd::FuzdState::NotInstalled) => {
                serde_json::json!({ "running": false, "installed": false })
            }
            // Unknown, not absent: neither field is claimed.
            None => serde_json::Value::Null,
        };
        // Present only when a witness is configured and a head is cached.
        if let Some(standing) = standing {
            output["release_log"] = serde_json::json!({
                "seq": standing.seq,
                "installed_revoked": standing.revoked,
            });
        }
        println!("{}", serde_json::to_string_pretty(&output)?);
        return Ok(());
    }

    if let Some(ref meta) = artifact {
        print_version_with_artifact(meta);
    } else {
        println!("fuz {}", env!("CARGO_PKG_VERSION"));
    }

    match daemon {
        Some(fuzd::FuzdState::Running) => match pid {
            Some(pid) => println!("fuzd: running (pid {pid})"),
            None => println!("fuzd: running"),
        },
        Some(fuzd::FuzdState::Stopped) => {
            println!("fuzd: stopped");
            println!("  hint: fuzd start");
        }
        Some(fuzd::FuzdState::NotInstalled) => {
            println!("fuzd: not installed");
            println!("  hint: fuz tool install fuzd");
        }
        // No install hint: whether it is installed is what is not known.
        None => println!("fuzd: unknown"),
    }

    Ok(())
}
