//! Fuz CLI
//!
//! Command-line client for the Fuz stack: installs first-party @fuzdev
//! binaries (`fuz tool …`), manages local artifacts (`fuz artifact build` /
//! `use` / `list` / …), consumes fuzd workloads (`fuz workload observe …`), and
//! manages the fuz binary itself (`fuz self …`). The daemon has its own CLI on
//! the `fuzd` binary (`fuzd start / stop / …`).

mod artifact;
mod bootstrap;
mod build;
mod error;
mod fuzd;
mod list;
mod log;
mod observe;
mod prune;
mod release;
mod release_log;
mod self_cmd;
mod tool;
mod use_cmd;
mod verify;
mod workload;

use argh::FromArgs;
pub use error::CliError;
use fuz_sys::cli::{EXIT_USAGE, format_error_chain, parse_env_args};
use std::process::ExitCode;

/// Fuz CLI — install first-party binaries, manage artifacts, manage fuz itself.
#[derive(FromArgs, Debug)]
struct TopLevel {
    #[argh(subcommand)]
    nested: Subcommand,
}

#[derive(FromArgs, Debug)]
#[argh(subcommand)]
enum Subcommand {
    Tool(tool::Tool),
    SelfCmd(self_cmd::SelfCmd),
    Artifact(artifact::Artifact),
    Workload(workload::Workload),
}

fn main() -> ExitCode {
    // Hidden typo-redirects for predictable mistakes (the no-aliases
    // carve-out). These redirect — they print a hint and exit non-zero, they
    // never execute — and are intentionally absent from `--help`.
    // Lossy, not `std::env::args()` (which panics on an argument that is not
    // UTF-8): the intercepts below match exact ASCII tokens, which a replaced
    // byte can never form. An argument that is not UTF-8 either follows a
    // redirect token (still exit 2) or reaches `parse_env_args`, which reports
    // it as a usage error.
    let argv: Vec<String> = std::env::args_os()
        .skip(1)
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect();
    if let Some(hint) = typo_redirect(&argv) {
        eprintln!("{hint}");
        return ExitCode::from(EXIT_USAGE);
    }

    // `fuz artifact use -` (the `cd -`-style toggle) can't reach argh: a bare
    // `-` is rejected as an unrecognized option before parsing. Intercept that
    // one documented form and dispatch `cmd_use` directly.
    if let Some(code) = handle_use_dash(&argv) {
        return code;
    }

    // Parse before the runtime starts. A command line argh can't parse exits 2
    // (the caller must fix it, like the redirects above), not argh's 1 — which
    // a release log refusal also exits; `--help` prints to stdout and exits 0.
    let cmd = match parse_env_args::<TopLevel>(EXIT_USAGE) {
        Ok(cmd) => cmd,
        Err(code) => return code,
    };
    report(run(cmd))
}

/// Print a `CliError` (its source chain, then its hint) and map it to a
/// process exit code.
fn report(result: Result<(), CliError>) -> ExitCode {
    let Err(e) = result else {
        return ExitCode::SUCCESS;
    };
    // A read-only `--check` that found an update is not a failure: the check
    // command already printed its own report (human or `--json`), so print
    // nothing extra — just carry the exit-10 signal.
    if matches!(e, CliError::UpdateAvailable) {
        return ExitCode::from(e.exit_code());
    }
    eprintln!("error: {}", format_error_chain(&e));
    if let Some(hint) = e.hint() {
        eprintln!("hint: {hint}");
    }
    ExitCode::from(e.exit_code())
}

/// Intercept `fuz artifact use -` (optionally with `-q`/`--quiet`).
///
/// argh treats a bare `-` as an unrecognized option and bails before
/// `cmd_use`'s `hash == "-"` branch can run, so this documented toggle is
/// unreachable through normal parsing. Match it here — every token after
/// `artifact use` must be a quiet flag or the single `-` — and dispatch
/// directly. Returns `None` (fall through to argh) for any other shape, so a
/// real hash, `--help`, or a missing argument is handled normally.
///
/// Coupled to `UseCmd`'s flag set: a new `use` flag must be handled here too.
fn handle_use_dash(argv: &[String]) -> Option<ExitCode> {
    if argv.first().map(String::as_str) != Some("artifact")
        || argv.get(1).map(String::as_str) != Some("use")
    {
        return None;
    }

    let mut quiet = false;
    let mut saw_dash = false;
    for arg in &argv[2..] {
        match arg.as_str() {
            "-" if !saw_dash => saw_dash = true,
            "-q" | "--quiet" => quiet = true,
            // a real hash, a repeated `-`, or an unknown flag → let argh report it
            _ => return None,
        }
    }
    if !saw_dash {
        return None;
    }

    Some(report(use_cmd::cmd_use(&use_cmd::UseCmd {
        quiet,
        hash: "-".to_string(),
    })))
}

/// Map a predictable-mistake first token (or `artifact prune --dry-run`) to a
/// "did you mean" hint.
///
/// Returns `None` for anything that should fall through to argh (real
/// subcommands, `--help`, no args, etc.).
fn typo_redirect(argv: &[String]) -> Option<String> {
    // `prune` previews by default and deletes only with `--wetrun`. A
    // `--dry-run` (the preview's name in other CLIs, `fuzi` and `fuz artifact
    // build` among them) is refused before anything runs, with this pointer
    // rather than argh's bare "Unrecognized argument".
    if argv.len() >= 2
        && argv[0] == "artifact"
        && argv[1] == "prune"
        && argv[2..].iter().any(|arg| arg == "--dry-run")
    {
        return Some(
            "fuz: `fuz artifact prune` is a dry run by default — drop `--dry-run` (pass `--wetrun` to delete)"
                .to_string(),
        );
    }
    let first = argv.first().map(String::as_str)?;
    let hint = match first {
        "bootstrap" => "fuz: did you mean `fuz self bootstrap`?",
        "upgrade" => "fuz: did you mean `fuz self upgrade`?",
        "version" => "fuz: did you mean `fuz self version`?",
        "status" => "fuz: did you mean `fuz self status` (or `fuzd status` for the daemon)?",
        "install" => "fuz: did you mean `fuz tool install <name>`?",
        "build" => "fuz: did you mean `fuz artifact build`?",
        "use" => "fuz: did you mean `fuz artifact use`?",
        "list" => "fuz: did you mean `fuz artifact list`?",
        "verify" => "fuz: did you mean `fuz artifact verify` (or `fuz tool verify <name>`)?",
        "prune" => "fuz: did you mean `fuz artifact prune`?",
        "log" => "fuz: did you mean `fuz artifact log`?",
        "observe" => "fuz: did you mean `fuz workload observe <domain>`?",
        "daemon" => {
            "fuz: the daemon is managed by fuzd — try `fuzd start|stop|restart|status|logs`"
        }
        "sidecar" => "fuz: there is no `fuz sidecar` — the daemon is managed by `fuzd`",
        "key" => {
            "fuz: there is no `fuz key` — signing keys are publisher tooling, try `cargo xtask key …`"
        }
        "publish" => {
            "fuz: there is no `fuz publish` — publishing is on the producer tools, try `fuzf tool publish <name>` (or `cargo xtask` for bootstrap signing); fuz only verifies"
        }
        "fetch" => {
            "fuz: there is no `fuz fetch` — `fuz self upgrade` and `fuz tool install` fetch + verify automatically"
        }
        _ => return None,
    };
    Some(hint.to_string())
}

#[tokio::main]
async fn run(cmd: TopLevel) -> Result<(), CliError> {
    match cmd.nested {
        Subcommand::Tool(args) => tool::cmd_tool(args).await,
        Subcommand::SelfCmd(args) => self_cmd::cmd_self(args).await,
        Subcommand::Artifact(args) => artifact::cmd_artifact(args),
        Subcommand::Workload(args) => workload::cmd_workload(args).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| (*s).to_string()).collect()
    }

    /// Each predictable-mistake first token redirects to the right noun-first
    /// form — the "no aliases, redirects only" grammar contract.
    #[test]
    fn typo_redirect_maps_bare_verbs_to_did_you_mean() {
        let cases = [
            ("bootstrap", "fuz self bootstrap"),
            ("upgrade", "fuz self upgrade"),
            ("version", "fuz self version"),
            ("status", "fuz self status"),
            ("install", "fuz tool install"),
            ("build", "fuz artifact build"),
            ("use", "fuz artifact use"),
            ("list", "fuz artifact list"),
            ("verify", "fuz tool verify"), // the verify hint names both artifact + tool
            ("prune", "fuz artifact prune"),
            ("log", "fuz artifact log"),
            ("observe", "fuz workload observe"),
            ("daemon", "fuzd"),
            ("sidecar", "fuzd"),
            ("key", "cargo xtask key"),
            ("publish", "fuzf tool publish"),
            ("fetch", "fuz self upgrade"),
        ];
        for (verb, expected) in cases {
            let hint = typo_redirect(&argv(&[verb])).expect("bare verb must redirect");
            assert!(
                hint.contains(expected),
                "`{verb}` -> {hint:?} should mention {expected:?}"
            );
        }
    }

    /// `artifact prune --dry-run` redirects to the dry-run-by-default
    /// surface; `artifact build --dry-run` is a real flag
    /// and falls through.
    #[test]
    fn typo_redirect_maps_prune_dry_run_to_the_wetrun_surface() {
        let hint = typo_redirect(&argv(&["artifact", "prune", "--keep", "1", "--dry-run"]))
            .expect("prune --dry-run must redirect");
        assert!(hint.contains("--wetrun"), "{hint:?}");
        for through in [
            &["artifact", "prune"][..],
            &["artifact", "prune", "--wetrun"],
            &["artifact", "build", "--dry-run"],
        ] {
            assert!(
                typo_redirect(&argv(through)).is_none(),
                "{through:?} must fall through to argh"
            );
        }
    }

    /// Real subcommands and empty argv fall through to argh (no redirect).
    #[test]
    fn typo_redirect_passes_through_real_subcommands_and_empty() {
        for real in [&["tool"][..], &["self"], &["artifact"], &["workload"], &[]] {
            assert!(
                typo_redirect(&argv(real)).is_none(),
                "{real:?} must fall through to argh"
            );
        }
    }

    /// Every non-toggle shape returns `None` (fall through to argh) without
    /// dispatching `cmd_use`. The positive `artifact use -` path executes and is
    /// covered end-to-end in `tests/artifact_cli.rs`, so it's intentionally not
    /// exercised here.
    #[test]
    fn handle_use_dash_returns_none_for_non_toggle_shapes() {
        for shape in [
            &["self", "status"][..],
            &["artifact", "list"],
            &["artifact"],
            &["artifact", "use"],             // no trailing args
            &["artifact", "use", "deadbeef"], // a real hash, not `-`
            &["artifact", "use", "-", "-"],   // a repeated dash
            &["artifact", "use", "--bogus"],  // an unknown flag
        ] {
            assert!(
                handle_use_dash(&argv(shape)).is_none(),
                "{shape:?} must not dispatch"
            );
        }
    }
}
