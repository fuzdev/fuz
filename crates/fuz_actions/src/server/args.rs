//! The spine server command line: `start`, `db-status`, `--help`.
//!
//! Strict: anything else — an unknown command, an extra argument, a flag the
//! server has never had — is refused before the env is read or a port bound,
//! so a typo never boots a server.

use std::process::ExitCode;

/// Whether the server needs `start` to serve.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartCommand {
    /// Serving needs `start`; no arguments is refused.
    Required,
    /// No arguments serves, as does `start`.
    Implicit,
}

/// What one invocation asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerInvocation {
    /// Serve in the foreground, configured by the process env.
    Start,
    /// Print the read-only database and migration status report.
    DbStatus,
    /// Print usage to stdout and exit `0`.
    Help,
}

/// Parse the arguments after the program name.
///
/// # Errors
///
/// The line to print above the usage — the caller prints both to stderr and
/// exits `2` (`fuz_sys::cli::EXIT_USAGE`).
pub fn parse_server_invocation(
    args: &[String],
    start: StartCommand,
) -> Result<ServerInvocation, String> {
    match args {
        [] => match start {
            StartCommand::Implicit => Ok(ServerInvocation::Start),
            StartCommand::Required => Err("missing command".to_owned()),
        },
        [arg] => match arg.as_str() {
            "start" => Ok(ServerInvocation::Start),
            "db-status" => Ok(ServerInvocation::DbStatus),
            "--help" | "-h" => Ok(ServerInvocation::Help),
            other => Err(format!("unknown command `{other}`")),
        },
        [_, extra, ..] => Err(format!("unexpected argument `{extra}`")),
    }
}

/// Read the process's command line: the invocation to run, or the exit to
/// take now.
///
/// `--help` prints [`server_usage`] to stdout and is `Err(ExitCode::SUCCESS)`;
/// a refused line prints `error: …` and the usage to stderr and is
/// `Err(fuz_sys::cli::EXIT_USAGE)` — before the env is read or a port bound.
/// A server's `main` returns the `Err` as is.
///
/// # Errors
///
/// The exit code when the invocation ends here.
pub fn server_invocation(binary: &str, start: StartCommand) -> Result<ServerInvocation, ExitCode> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match resolve_invocation(&args, binary, start) {
        Resolved::Run(invocation) => Ok(invocation),
        Resolved::Help(usage) => {
            print!("{usage}");
            Err(ExitCode::SUCCESS)
        }
        Resolved::Refused(text) => {
            eprint!("{text}");
            Err(ExitCode::from(fuz_sys::cli::EXIT_USAGE))
        }
    }
}

/// What [`server_invocation`] does with one command line.
#[derive(Debug, PartialEq, Eq)]
enum Resolved {
    /// Run it.
    Run(ServerInvocation),
    /// Print this to stdout and exit `0`.
    Help(String),
    /// Print this to stderr and exit `2`.
    Refused(String),
}

fn resolve_invocation(args: &[String], binary: &str, start: StartCommand) -> Resolved {
    match parse_server_invocation(args, start) {
        Ok(ServerInvocation::Help) => Resolved::Help(server_usage(binary, start)),
        Ok(invocation) => Resolved::Run(invocation),
        Err(message) => Resolved::Refused(format!(
            "error: {message}\n\n{}",
            server_usage(binary, start)
        )),
    }
}

/// The usage text for `binary`.
#[must_use]
pub fn server_usage(binary: &str, start: StartCommand) -> String {
    let synopsis = match start {
        StartCommand::Required => "<command>",
        StartCommand::Implicit => "[command]",
    };
    let start_line = match start {
        StartCommand::Required => {
            "  start      run the server in the foreground, configured by the process environment"
        }
        StartCommand::Implicit => {
            "  start      run the server in the foreground, configured by the process environment \
             (the default)"
        }
    };
    format!(
        "Usage: {binary} {synopsis}\n\
         \n\
         Commands:\n\
         {start_line}\n\
         \x20 db-status  print the read-only database and migration status report\n\
         \n\
         Options:\n\
         \x20 -h, --help  print this help\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str], start: StartCommand) -> Result<ServerInvocation, String> {
        parse_server_invocation(
            &args.iter().map(|a| (*a).to_owned()).collect::<Vec<_>>(),
            start,
        )
    }

    #[test]
    fn accepts_the_commands_and_help_in_both_styles() {
        for start in [StartCommand::Required, StartCommand::Implicit] {
            assert_eq!(parse(&["start"], start), Ok(ServerInvocation::Start));
            assert_eq!(parse(&["db-status"], start), Ok(ServerInvocation::DbStatus));
            assert_eq!(parse(&["--help"], start), Ok(ServerInvocation::Help));
            assert_eq!(parse(&["-h"], start), Ok(ServerInvocation::Help));
        }
    }

    #[test]
    fn no_arguments_serves_only_when_start_is_implicit() {
        assert_eq!(
            parse(&[], StartCommand::Implicit),
            Ok(ServerInvocation::Start)
        );
        assert!(parse(&[], StartCommand::Required).is_err());
    }

    #[test]
    fn refuses_everything_else() {
        for start in [StartCommand::Required, StartCommand::Implicit] {
            for args in [
                &["strat"][..],
                &["help"],
                &["--env_file"],
                &["start", "--port", "1"],
                &["db-status", "x"],
            ] {
                assert!(parse(args, start).is_err(), "{args:?} {start:?}");
            }
        }
    }

    #[test]
    fn the_invocation_prints_help_and_refusals_with_the_usage() {
        let args = |args: &[&str]| args.iter().map(|a| (*a).to_owned()).collect::<Vec<_>>();
        let usage = server_usage("talkd", StartCommand::Implicit);
        assert_eq!(
            resolve_invocation(&args(&[]), "talkd", StartCommand::Implicit),
            Resolved::Run(ServerInvocation::Start)
        );
        assert_eq!(
            resolve_invocation(&args(&["db-status"]), "talkd", StartCommand::Implicit),
            Resolved::Run(ServerInvocation::DbStatus)
        );
        assert_eq!(
            resolve_invocation(&args(&["-h"]), "talkd", StartCommand::Implicit),
            Resolved::Help(usage.clone())
        );
        assert_eq!(
            resolve_invocation(&args(&["strat"]), "talkd", StartCommand::Implicit),
            Resolved::Refused(format!("error: unknown command `strat`\n\n{usage}"))
        );
    }

    #[test]
    fn the_usage_names_the_binary_and_the_commands() {
        let usage = server_usage("fuzfd", StartCommand::Required);
        assert!(usage.starts_with("Usage: fuzfd <command>\n"), "{usage}");
        assert!(usage.contains("\n  db-status  "), "{usage}");
        assert!(usage.contains("\n  -h, --help  "), "{usage}");
        let usage = server_usage("talkd", StartCommand::Implicit);
        assert!(usage.starts_with("Usage: talkd [command]\n"), "{usage}");
        assert!(usage.contains("(the default)"), "{usage}");
    }
}
