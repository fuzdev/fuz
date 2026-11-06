//! Fuz development automation
//!
//! # Usage
//!
//! ```sh
//! cargo xtask install              # Build, install, restart daemon
//! cargo xtask install --no-restart # Build and install only
//! cargo xtask install --build-only # Build only (no install)
//! cargo xtask clean                # Stop daemon, remove ~/.fuz/
//! cargo xtask check-release        # Dep-graph audit: forbidden crates, layering, test_* features on release edges
//! cargo xtask key generate | info | export | list-trusted  # Signing keys (docs/signing.md)
//! cargo xtask publish self --storage <uri>            # Sign + publish the fuz-only self artifact
//! cargo xtask publish tool fuzd <bin> --version <v> --storage <uri>  # Bootstrap a tool artifact
//! cargo xtask publish tool fuzd <bin> --version <v> --storage <uri> --target <triple>  # ... labelled for another target
//! cargo xtask publish self --storage <uri> --log-repo <path>  # ... and record it in the release log
//! cargo xtask release-log backfill --storage <uri> --log-repo <path>  # Review: create the release log from published releases
//! cargo xtask release-log backfill --storage <uri> --log-repo <path> --wetrun  # ... write, commit, push
//! cargo xtask release-log revoke <name> <version> --log-repo <path>  # Review: revoke a logged release
//! cargo xtask release-log revoke <name> <version> --log-repo <path> --wetrun  # ... write, commit, push
//! cargo xtask prune --storage <uri> [--tool <name>] [--keep N]  # Review: old releases to delete
//! cargo xtask prune --storage <uri> [--tool <name>] [--keep N] --wetrun  # ... delete them
//! ```

mod check_release;
mod error;
mod key;
mod prune;
mod publish;
mod release_log;

use argh::FromArgs;
use error::XtaskError;
use fuz_artifact::platform::ReleaseTarget;
use fuz_artifact::tools::install_local_tool;
use fuz_artifact::{
    ArtifactError, ArtifactInputs, BuildSource, CargoBuildOptions, SwitchOptions,
    acquire_artifact_lock, cargo_build_release, check_built_for, create_artifact, find_by_inputs,
    get_cargo_version, get_current_artifact, switch_to_artifact,
};
use fuz_home::{get_bin_dir, get_fuz_home, verify_pid_is_fuzd};
use fuz_sys::cli::{EXIT_USAGE, parse_env_args, report_failure};
use fuz_sys::{Signal, send_signal};
use std::fs;
use std::path::PathBuf;
use std::process::{Command, ExitCode};
use std::time::Duration;

type Result<T> = std::result::Result<T, XtaskError>;

/// Time to wait for graceful shutdown before force kill
const GRACEFUL_SHUTDOWN_WAIT: Duration = Duration::from_millis(500);

/// Fuz development automation.
#[derive(FromArgs, Debug)]
struct TopLevel {
    #[argh(subcommand)]
    task: Task,
}

#[derive(FromArgs, Debug)]
#[argh(subcommand)]
enum Task {
    Install(Install),
    Clean(Clean),
    CheckRelease(CheckRelease),
    Key(key::Key),
    Publish(publish::Publish),
    Prune(prune::Prune),
    ReleaseLog(release_log::ReleaseLog),
}

/// Build, create artifact, and restart daemon.
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "install")]
struct Install {
    /// don't restart daemon after install
    #[argh(switch)]
    no_restart: bool,

    /// build only, don't install
    #[argh(switch)]
    build_only: bool,
}

/// Stop daemon and remove ~/.fuz/.
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "clean")]
struct Clean {}

/// Audit the workspace dep graph: no production binary (not `testing_`-prefixed,
/// not in a `dev_only` package) may reach `fuz_testing`, `fuz_audit`, or
/// `fuz_sign`; `fuz` / `fuzd` may not reach `fuzi` / `fuzi_core`; plus the
/// built-in per-crate layering rules. Walks `cargo metadata` and reports any dep
/// chain reaching a forbidden crate.
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "check-release")]
struct CheckRelease {}

fn main() -> ExitCode {
    // A command line argh can't parse exits 2, not argh's 1 (every task's
    // failure); `--help` prints to stdout and exits 0.
    let cmd = match parse_env_args::<TopLevel>(EXIT_USAGE) {
        Ok(cmd) => cmd,
        Err(code) => return code,
    };
    match cmd.task {
        Task::Install(opts) => result_to_exit(install(&opts)),
        Task::Clean(_) => result_to_exit(clean()),
        Task::CheckRelease(_) => check_release::check_release(),
        Task::Key(args) => result_to_exit(key::cmd_key(args).map_err(XtaskError::Key)),
        Task::Publish(args) => {
            result_to_exit(publish::cmd_publish(args).map_err(XtaskError::Publish))
        }
        // Prune shares `PublishError` (both are producer storage/release ops);
        // the `transparent` wrapper shows the real message, not a "publish" label.
        Task::Prune(args) => result_to_exit(prune::cmd_prune(&args).map_err(XtaskError::Publish)),
        Task::ReleaseLog(args) => {
            result_to_exit(release_log::cmd_release_log(args).map_err(XtaskError::Publish))
        }
    }
}

fn result_to_exit(result: Result<()>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            // `hint()` is a `HintMessage` (some hints interpolate), and
            // `report_failure` takes the text
            let hint = e.hint().map(|hint| hint.to_string());
            report_failure(&e, hint.as_deref(), 1)
        }
    }
}

/// Check if fish shell is available
fn has_fish() -> bool {
    Command::new("fish")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
}

/// Get path to fuzd binary (~/.fuz/bin/fuzd or fallback to PATH).
///
/// Daemon lifecycle lives on fuzd's own CLI, so dev automation drives the
/// daemon through `fuzd start` / `fuzd stop` rather than the (removed)
/// `fuz daemon` namespace.
fn get_fuzd_binary() -> PathBuf {
    get_bin_dir().map_or_else(|_| PathBuf::from("fuzd"), |p| p.join("fuzd"))
}

/// Kill a fuzd process by PID (SIGTERM, wait, then SIGKILL if needed)
///
/// Only kills if PID is verified to be fuzd.
fn kill_fuzd_pid(pid: i32) {
    if !verify_pid_is_fuzd(pid) {
        return;
    }

    let _ = send_signal(pid, Signal::SIGTERM);

    std::thread::sleep(GRACEFUL_SHUTDOWN_WAIT);

    // Re-verify before SIGKILL (PID could have been reused)
    if verify_pid_is_fuzd(pid) {
        let _ = send_signal(pid, Signal::SIGKILL);
    }
}

/// Stop daemon for clean operation - tries both strategies
///
/// Strategies are cumulative (not early-return) because daemon.json can be stale.
fn stop_daemon_for_clean() {
    // Strategy 1: graceful stop via the daemon's own CLI. UDS auth is
    // automatic (same-uid peer), so no env needed.
    let _ = Command::new(get_fuzd_binary())
        .args(["stop", "--force", "--quiet"])
        .status();

    // Strategy 2: Kill PID from daemon.json directly
    if let Ok(Some(info)) = fuz_home::read_daemon_info() {
        kill_fuzd_pid(info.pid);
    }
}

fn install(opts: &Install) -> Result<()> {
    // Verify we're in the project root
    let current_dir = std::env::current_dir().map_err(XtaskError::CreateDir)?;
    if !current_dir.join("Cargo.toml").exists() {
        return Err(XtaskError::NotWorkspaceRoot);
    }

    // Build release binaries, each taken from where cargo reports building it
    // — `CARGO_TARGET_DIR`, `build.target-dir`, and a build target all move
    // it from `target/release/`. One cargo run per package: a single
    // `-p fuz -p fuzd` run unifies features across both, linking a `fuz` with
    // fuzd's features of their shared deps — not the binary a `-p fuz` build
    // (`fuz artifact build`, its `--verify`) makes under the same input hash.
    println!("Building release binaries...");
    let build = |name| {
        cargo_build_release(
            &CargoBuildOptions {
                workspace: &current_dir,
                package: name,
                target_dir: None,
                quiet: false,
            },
            name,
        )
    };
    let fuz_binary = build("fuz")?;
    let fuzd_binary = build("fuzd")?;
    println!("  > Built release binaries");

    if opts.build_only {
        return Ok(());
    }

    // The artifact's inputs, read before `~/.fuz` is touched: their `target`
    // is the toolchain's host (`rustc -vV`), which the check below needs.
    let inputs = ArtifactInputs::collect(&current_dir).map_err(XtaskError::Artifact)?;
    let version = get_cargo_version(&current_dir).map_err(XtaskError::Artifact)?;

    // Both binaries are installed on this host, so both must be for it: a
    // cargo configured for another target (`CARGO_BUILD_TARGET`, a
    // `build.target`) is refused here, before `~/.fuz` is touched. The host
    // is the toolchain's, not xtask's own compiled target — `cargo xtask`
    // obeys the same build target setting, so it would agree with the cross
    // build it should refuse.
    let host: ReleaseTarget = inputs.target.parse().map_err(ArtifactError::from)?;
    for (name, path) in [("fuz", &fuz_binary), ("fuzd", &fuzd_binary)] {
        check_built_for(name, path, host)?;
    }

    // A missing bin/ means nothing has ever been installed here, so the PATH
    // instructions at the end are worth printing. Read it before
    // `ensure_fuz_home` creates the directory.
    let is_first_time = !get_bin_dir()?.exists();

    // Ensure fuz home structure exists
    fuz_home::ensure_fuz_home()?;

    // Acquire the artifact lock *after* the (potentially-long) cargo build, so
    // a concurrent `fuz artifact build` isn't blocked for the whole compile —
    // but before creating the artifact and switching, so we never race another
    // process on `~/.fuz/artifacts/`, `current`, `bin/fuz`, or `history.json`.
    // Released once the switch lands; see the `drop` below for why it doesn't
    // extend over the fuzd tool install.
    let lock = acquire_artifact_lock().map_err(XtaskError::Artifact)?;

    // Try cache lookup by input hash
    let cached = find_by_inputs(&inputs.input_hash).map_err(XtaskError::Artifact)?;

    let meta = if let Some(existing) = cached {
        println!(
            "Using cached artifact {}... (input hash hit)",
            existing.short_hash()
        );
        existing
    } else {
        println!("Creating artifact...");
        // The self artifact is fuz-only; fuzd lands as a separate tool below.
        let m = create_artifact(
            &version,
            BuildSource::Local {
                fuz_binary: &fuz_binary,
                inputs: &inputs,
            },
        )
        .map_err(XtaskError::Artifact)?;
        println!("  > Created artifact {}...", m.short_hash());
        m
    };

    // Capture what this replaces so the switch lands in `fuz artifact log` with
    // a real rollback target for `fuz artifact use -`. Tolerant like
    // `fuz self bootstrap`: an unreadable outgoing artifact must not block the
    // install that repairs it — it just costs the rollback pointer.
    //
    // Re-installing the already-current artifact records no rollback target.
    // The siblings (`fuz artifact build` / `use`) bail with "Already using ..."
    // before switching; xtask can't, since it still has the fuzd install and
    // the daemon restart to do, so it drops the pointer instead. `History::add`
    // dedups only when the *newest* entry is already this hash, so without the
    // filter a re-install over a `current` that history doesn't lead with would
    // append `{hash: X, previous_hash: X}` and `fuz artifact log` would render
    // "from X" on X's own entry.
    let previous_hash = get_current_artifact()
        .ok()
        .flatten()
        .map(|prev| prev.hash)
        .filter(|prev| *prev != meta.hash);

    // Verify -> switch `current` -> link bin/ -> record history, through the
    // one shared locked-switch helper. Quiet, so xtask keeps its own
    // bullet-style progress instead of the helper's "Switching.../Done.".
    //
    // This is the abort point: everything below (the fuzd tool install, the
    // daemon restart) runs against a `current` and a `bin/fuz` that have
    // already moved. The switch verifies first, so a refusal there changes
    // nothing; a failure *after* the `current` swap — an unreadable
    // `history.json`, a full disk — leaves a new `fuz` beside a stale
    // `bin/fuzd`. It aborts loudly and re-running `cargo xtask install` is
    // idempotent, which repairs it.
    switch_to_artifact(
        SwitchOptions {
            hash: &meta.hash,
            version: &version,
            previous_hash: previous_hash.as_deref(),
            quiet: true,
        },
        &lock,
    )
    .map_err(XtaskError::Artifact)?;
    println!(
        "  > Set current -> {} (bin/ symlinks, history recorded)",
        meta.short_hash()
    );

    // Everything the artifact lock covers — `~/.fuz/artifacts/`, `current`,
    // `bin/fuz`, `history.json` — is settled, so release it here. It covers
    // nothing below: the tool install writes `~/.fuz/tools/` and `bin/fuzd`,
    // and no artifact-lock holder writes either (`setup_bin_symlinks(&["fuz"])`
    // is the only `bin/` write under the lock, and `fuz tool install fuzd`
    // takes no artifact lock at all). Holding on would buy no mutual exclusion
    // and would extend contention across a `fuzd restart` whose worst case is
    // ~15s — and since `acquire_artifact_lock` is non-blocking, a concurrent
    // `fuz artifact build` / `use` / `self upgrade` / `self bootstrap` doesn't
    // wait it out, it fails with `InProgress`.
    drop(lock);

    // Install the freshly-built fuzd as a local tool artifact (no forge): it
    // lands under ~/.fuz/tools/fuzd/v1-<hash>/ with bin/fuzd linked through it —
    // the same layout `fuz tool install fuzd` will use from the forge.
    let fuzd_meta = install_local_tool("fuzd", &version, &[("fuzd", &fuzd_binary)])
        .map_err(XtaskError::Artifact)?;
    println!(
        "  > Installed fuzd tool {} ({})",
        version,
        fuzd_meta.short_hash()
    );

    // Restart daemon unless --no-restart. `restart` (not `start`) is what
    // picks up the freshly-installed binary — a daemon already running from
    // the previous install would make `start` a no-op.
    //
    // Not `--quiet`: that silences restart's refusals too (an unresponsive
    // daemon, one with no daemon.json that restart will not stop), so its
    // output is captured instead and shown only when the restart fails —
    // restart's own lines first, since they say what failed and what to run
    // (its hints name the `fuzd` command), then the one line saying the
    // install itself went through.
    if !opts.no_restart {
        println!("Restarting daemon...");

        let fuzd_path = get_fuzd_binary();
        let output = Command::new(&fuzd_path).arg("restart").output();

        match output {
            Ok(out) if out.status.success() => {
                println!("  > Restarted daemon");
            }
            Ok(out) => {
                for line in String::from_utf8_lossy(&out.stderr).lines() {
                    eprintln!("  {line}");
                }
                eprintln!(
                    "  warning: daemon restart failed ({}): the new fuzd is installed, but restart did not start it",
                    out.status
                );
            }
            Err(e) => {
                eprintln!("  warning: could not run fuzd: {e}");
            }
        }
    }

    // Print setup instructions
    println!();
    if has_fish() {
        if is_first_time {
            println!("Add to ~/.config/fish/config.fish:");
            println!("  fish_add_path ~/.fuz/bin");
            println!();
        }
    } else if is_first_time {
        println!("Add to your shell profile (~/.bashrc, ~/.zshrc):");
        println!("  export PATH=\"$HOME/.fuz/bin:$PATH\"");
        println!();
    }

    Ok(())
}

/// Remove ~/.fuz/ (and the daemon running out of it)
fn clean() -> Result<()> {
    println!("Cleaning fuz installation...");

    // 1. Stop daemon (best effort, multiple strategies)
    println!("  Stopping daemon...");
    stop_daemon_for_clean();

    // 2. Remove ~/.fuz/
    let fuz_home = get_fuz_home()?;
    if fuz_home.exists() {
        print!("  Removing {}...", fuz_home.display());
        fs::remove_dir_all(&fuz_home).map_err(|e| XtaskError::RemoveDir {
            path: fuz_home,
            source: e,
        })?;
        println!(" done");
    } else {
        println!("  {} does not exist, nothing to remove", fuz_home.display());
    }

    // 3. Print reminder
    println!();
    println!("Cleaned. Remove from your shell config (if applicable):");
    if has_fish() {
        println!("  - fish_add_path ~/.fuz/bin from ~/.config/fish/config.fish");
    } else {
        println!("  - PATH = ~/.fuz/bin lines from ~/.bashrc or ~/.zshrc");
    }

    Ok(())
}
