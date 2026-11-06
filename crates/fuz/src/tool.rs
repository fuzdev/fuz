//! The `tool` noun — install and manage first-party @fuzdev binaries.
//!
//! `fuz tool install / upgrade / verify / list` is the distribution surface:
//! curated, signed, blake3-pinned @fuzdev binaries (the names in
//! `fuz_artifact::tools::FIRST_PARTY_TOOLS`) fetched from any `--storage`
//! backend. Each install is content-addressed under
//! `~/.fuz/tools/<name>/v1-<hash>/` with its own `meta.json`; the signed
//! manifest declares the binary set and the embedded ed25519 key + blake3
//! hashes gate trust. No auto-pull: `fuz tool install fuzf` fetches only
//! `fuzf`.
//!
//! A "tool" is a first-party binary, not a sidecar-hosted operation.
//!
//! When `FUZ_RELEASE_LOG_URL` names a witness, `install` and `upgrade` hold
//! the release to the release log first, and `upgrade --check` holds the
//! latest release to it before reporting (see `crate::release_log`).

use argh::FromArgs;
use fuz_release::{
    CurrentVersion, ReleaseError, ToolInstallOptions, ToolInstallOutcome, check_latest_tool,
    install_tool, installed_tool_meta, list_installed_tools, resolve_current_tool,
    verify_installed_tool,
};

use crate::CliError;
use crate::fuzd;
use crate::release::{
    ReleaseCommandError, UpgradeOutcome, open_storage, render_check, upgrade_outcome,
};

//
// CLI args
//

/// Install and manage first-party @fuzdev binaries.
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "tool")]
pub struct Tool {
    #[argh(subcommand)]
    pub nested: ToolSub,
}

#[derive(FromArgs, Debug)]
#[argh(subcommand)]
pub enum ToolSub {
    Install(Install),
    Upgrade(Upgrade),
    Verify(Verify),
    List(List),
}

/// Install a first-party binary by name, such as fuzd or zap.
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "install")]
pub struct Install {
    /// the binary name to install
    #[argh(positional)]
    pub name: String,

    /// storage location (e.g. `/path`, `forge://host`, `ssh://user@host/path`, or `https://host/path`)
    #[argh(option)]
    pub storage: String,

    /// specific version to install (default: latest)
    #[argh(option)]
    pub version: Option<String>,

    /// allow installing an older version than the one already installed
    #[argh(switch)]
    pub allow_downgrade: bool,

    /// reinstall over an unreadable/corrupt current install instead of refusing
    #[argh(switch)]
    pub force: bool,

    /// suppress informational output (release log warnings still print)
    #[argh(switch, short = 'q')]
    pub quiet: bool,
}

/// Upgrade an installed first-party binary to the latest version.
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "upgrade")]
#[allow(clippy::struct_excessive_bools)] // CLI flags are naturally boolean
pub struct Upgrade {
    /// the binary name to upgrade
    #[argh(positional)]
    pub name: String,

    /// storage location (e.g. `/path`, `forge://host`, `ssh://user@host/path`, or `https://host/path`)
    #[argh(option)]
    pub storage: String,

    /// allow upgrading to an older version than the one installed
    #[argh(switch)]
    pub allow_downgrade: bool,

    /// reinstall over an unreadable/corrupt current install instead of refusing
    #[argh(switch)]
    pub force: bool,

    /// check for a newer version without installing (read-only; exit 10 if an update is available)
    #[argh(switch)]
    pub check: bool,

    /// machine-readable JSON output (only with --check)
    #[argh(switch)]
    pub json: bool,

    /// suppress informational output (release log warnings still print)
    #[argh(switch, short = 'q')]
    pub quiet: bool,
}

/// Verify an installed first-party binary's artifact integrity.
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "verify")]
pub struct Verify {
    /// the binary name to verify
    #[argh(positional)]
    pub name: String,
}

/// List installed first-party binaries.
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "list")]
pub struct List {}

//
// Dispatch
//

pub async fn cmd_tool(args: Tool) -> Result<(), CliError> {
    match args.nested {
        ToolSub::Install(opts) => cmd_install(&opts).await,
        ToolSub::Upgrade(opts) => cmd_upgrade(&opts).await,
        ToolSub::Verify(opts) => cmd_verify(&opts),
        ToolSub::List(_) => cmd_list(),
    }
}

async fn cmd_install(opts: &Install) -> Result<(), CliError> {
    // The release log policy first, as on every command that holds a release
    // to the log: a configuration the check cannot run under exits 2 whatever
    // else is wrong with the invocation.
    let release_log = crate::release_log::policy_from_env()?;

    let storage = open_storage(&opts.storage)?;

    let options = ToolInstallOptions {
        version: opts.version.as_deref(),
        allow_downgrade: opts.allow_downgrade,
        force: opts.force,
        release_log,
    };
    let result = install_tool(&storage, &opts.name, &options)
        .await
        .map_err(ReleaseCommandError::Release)?;
    crate::release_log::render(&result.release_log, opts.quiet);

    if !opts.quiet {
        if let Some(reason) = &result.repaired_unreadable {
            eprintln!("warning: reinstalled over an unreadable current install ({reason})");
        }
        // Report what happened to the *active* binary, not whether the download
        // was skipped. `install_tool` relinks `current` unconditionally, so a
        // requested hash that was already unpacked but not current has just moved
        // `~/.fuz/bin/<binary>` — only `AlreadyCurrent` is a no-op.
        match &result.outcome {
            ToolInstallOutcome::AlreadyCurrent => println!(
                "already have {} {} ({})",
                result.name, result.version, result.content_hash
            ),
            ToolInstallOutcome::Relinked { previous } => {
                println!(
                    "switched {} to {} ({})",
                    result.name, result.version, result.content_hash
                );
                if let Some(previous) = previous {
                    println!("  from: {previous}");
                }
            }
            ToolInstallOutcome::Installed => println!(
                "installed {} {} ({})",
                result.name, result.version, result.content_hash
            ),
        }
        println!("  binaries: {}", result.binaries.join(", "));
        nudge_fuzd_restart(&result.name, result.outcome.changed_active_binary());
    }

    Ok(())
}

/// Print the daemon-restart nudge when the active `fuzd` binary just moved and
/// the daemon is up: it's still running the one it started with. fuz never drives
/// fuzd's lifecycle (no proxying), so the restart is the user's to run. Silent for
/// any other tool, for an unchanged active binary, and when fuzd isn't listening.
fn nudge_fuzd_restart(name: &str, changed_active_binary: bool) {
    if changed_active_binary && name == "fuzd" && fuzd::is_running() {
        println!(
            "note: fuzd is running a different binary — run `fuzd restart` to pick up this version"
        );
    }
}

async fn cmd_upgrade(opts: &Upgrade) -> Result<(), CliError> {
    if opts.json && !opts.check {
        return Err(CliError::InvalidUsage("--json applies only with --check"));
    }

    // The release log policy first: a configuration the check cannot run
    // under stops the command before any request, `--check` included.
    let release_log = crate::release_log::policy_from_env()?;

    let storage = open_storage(&opts.storage)?;

    // Read-only update check: resolve + verify the latest signed tool manifest
    // and report, installing nothing. Reports the resolved install state
    // (installed / not-installed / unreadable) against the signed version.
    if opts.check {
        let latest = check_latest_tool(&storage, &opts.name, &release_log)
            .await
            .map_err(ReleaseCommandError::Release)?;
        crate::release_log::render(latest.release_log(), opts.quiet);
        return render_check("tool", &opts.name, &latest, opts.json);
    }

    // Require an existing install — upgrade is not a backdoor install. One read
    // of `current/meta.json` yields both halves of the "before" state: the
    // version for the message and the content hash (the tool's unique identity)
    // for the change verdict, captured before the idempotent reinstall.
    //
    // An install that is there but can't be read is still an install: it goes
    // on to `install_tool`, which refuses it without `--force` (naming the
    // flag) and reinstalls over it with it — with no "before" state to report.
    let old_meta = installed_tool_meta(&opts.name);
    if old_meta.is_none()
        && matches!(
            resolve_current_tool(&opts.name),
            CurrentVersion::NotInstalled
        )
    {
        return Err(ReleaseCommandError::Release(ReleaseError::ToolNotInstalled(
            opts.name.clone(),
        ))
        .into());
    }

    let options = ToolInstallOptions {
        version: None,
        allow_downgrade: opts.allow_downgrade,
        force: opts.force,
        release_log,
    };
    let result = install_tool(&storage, &opts.name, &options)
        .await
        .map_err(ReleaseCommandError::Release)?;
    crate::release_log::render(&result.release_log, opts.quiet);

    if !opts.quiet
        && let Some(reason) = &result.repaired_unreadable
    {
        eprintln!("warning: reinstalled over an unreadable current install ({reason})");
    }

    // Key the "unchanged" verdict on content-hash identity, not version equality
    // — a same-version-but-different-content tool is a real change. (`install_tool`
    // is idempotent and always re-links `current`, so the switch already happened;
    // this only picks an honest message.) `Installed` occurs only for a forced
    // reinstall over an unreadable install, which has no "before" to compare.
    let outcome = upgrade_outcome(
        old_meta.as_ref().map(|m| m.content_hash.as_str()),
        old_meta.as_ref().map(|m| m.version.as_str()),
        &result.content_hash,
        &result.version,
    );

    if !opts.quiet {
        match outcome {
            UpgradeOutcome::AlreadyCurrent => {
                println!("{} already at latest version {}", opts.name, result.version);
            }
            UpgradeOutcome::Reinstalled => {
                println!(
                    "reinstalled {} {} (content changed)",
                    opts.name, result.version
                );
            }
            UpgradeOutcome::Upgraded { from } => {
                println!("upgraded {} {} -> {}", opts.name, from, result.version);
            }
            UpgradeOutcome::Installed => {
                println!("installed {} {}", opts.name, result.version);
            }
        }
        nudge_fuzd_restart(&opts.name, outcome != UpgradeOutcome::AlreadyCurrent);
    }

    Ok(())
}

fn cmd_verify(opts: &Verify) -> Result<(), CliError> {
    let meta = verify_installed_tool(&opts.name).map_err(ReleaseCommandError::Release)?;
    println!("{} {} ok ({})", meta.tool, meta.version, meta.content_hash);
    Ok(())
}

fn cmd_list() -> Result<(), CliError> {
    let tools = list_installed_tools().map_err(ReleaseCommandError::Release)?;
    if tools.is_empty() {
        println!("no tools installed");
        return Ok(());
    }
    for meta in tools {
        println!("{}  {}  {}", meta.tool, meta.version, meta.display_hash());
    }
    Ok(())
}
