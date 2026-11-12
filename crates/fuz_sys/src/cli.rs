//! Shared CLI primitives.
//!
//! Small types every fuz-ecosystem CLI binary reaches for when it parses its
//! arguments and renders errors and hints. Kept transport- and domain-free so
//! `fuz`, the forge client, and future CLIs share one shape rather than each
//! re-declaring it.
//!
//! Argument parsing (behind the `argh` feature) replaces `argh::from_env`,
//! which exits `1` on a command line it cannot parse — the code fuz binaries
//! give real outcomes (`fuzd status`'s "not running", a release log refusal),
//! so a script could not tell a typo from an answer. `parse_env_args` keeps
//! argh's text and streams but exits with the binary's usage code instead.
//!
//! [`format_error_chain`] is the message each binary prints after `error:`.

use crate::text::{escape_message, truncate};

/// Most bytes of one cause [`format_error_chain`] prints, before it is
/// escaped. A cause can be third-party text that repeats a document someone
/// else served (a JSON parser's `invalid type: string "..."` over a server's
/// body), at any length.
const MAX_CAUSE_LEN: usize = 2048;

/// Exit code for a command line the binary cannot parse, in the default dialect.
///
/// `2`: the caller must change the invocation before running it again. A
/// binary on the sysexits dialect passes its own `EX_USAGE` (`64`) to
/// `parse_env_args` instead.
pub const EXIT_USAGE: u8 = 2;

/// Why argument parsing ended without a command to run.
#[cfg(feature = "argh")]
#[derive(Debug, Clone, PartialEq, Eq)]
enum ArgsExit {
    /// A help request (`--help` or the `help` subcommand): the usage
    /// text, for stdout. The process exits `0`.
    Help(String),
    /// A command line that does not parse: argh's message followed by its
    /// `Run <cmd> --help for more information.` line, for stderr. The process
    /// exits the binary's usage code.
    Usage(String),
}

#[cfg(feature = "argh")]
impl ArgsExit {
    /// The process exit code: `0` for [`Help`](Self::Help), `usage_exit` for
    /// [`Usage`](Self::Usage).
    #[must_use]
    const fn exit_code(&self, usage_exit: u8) -> u8 {
        match self {
            Self::Help(_) => 0,
            Self::Usage(_) => usage_exit,
        }
    }

    /// Print the output to its stream — help to stdout, a usage error to
    /// stderr — and return the process exit code ([`Self::exit_code`]).
    #[must_use]
    fn report(&self, usage_exit: u8) -> std::process::ExitCode {
        match self {
            Self::Help(text) => println!("{text}"),
            Self::Usage(message) => eprintln!("{message}"),
        }
        std::process::ExitCode::from(self.exit_code(usage_exit))
    }
}

/// Parse `argv` (the program name first) into `T`, returning argh's early exit
/// instead of exiting the process.
///
/// The command name argh prints is the program path's file name, and a usage
/// error carries argh's `Run <cmd> --help` line — the same text
/// `argh::from_env` prints.
///
/// # Errors
///
/// [`ArgsExit::Help`] for a help request, [`ArgsExit::Usage`] for a command
/// line `T` does not accept or an empty `argv`.
#[cfg(feature = "argh")]
fn parse_args<T: argh::TopLevelCommand>(argv: &[String]) -> Result<T, ArgsExit> {
    let Some((program, rest)) = argv.split_first() else {
        return Err(ArgsExit::Usage(
            "No program name, argv is empty".to_string(),
        ));
    };
    let cmd = std::path::Path::new(program)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(program);
    let args: Vec<&str> = rest.iter().map(String::as_str).collect();
    T::from_args(&[cmd], &args).map_err(|early| match early.status {
        Ok(()) => ArgsExit::Help(early.output),
        Err(()) => ArgsExit::Usage(format!(
            "{}\nRun {cmd} --help for more information.",
            early.output
        )),
    })
}

/// Parse the process's arguments into `T` — the replacement for
/// `argh::from_env`.
///
/// A help request prints to stdout and yields exit `0`; a command line that
/// does not parse (including an argument that is not UTF-8) prints to stderr
/// and yields `usage_exit` — [`EXIT_USAGE`] in the default dialect. The caller
/// returns the code from `main`; nothing here exits the process.
///
/// # Errors
///
/// The process exit code, once the help text or usage error has been printed.
#[cfg(feature = "argh")]
pub fn parse_env_args<T: argh::TopLevelCommand>(
    usage_exit: u8,
) -> Result<T, std::process::ExitCode> {
    let argv = std::env::args_os()
        .map(std::ffi::OsString::into_string)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|arg| {
            ArgsExit::Usage(format!("Invalid utf8: {}", arg.to_string_lossy())).report(usage_exit)
        })?;
    parse_args(&argv).map_err(|exit| exit.report(usage_exit))
}

/// The message a CLI prints after `error:` — `error`'s text, then each cause
/// in its source chain, `: `-joined.
///
/// Most wrapped errors keep their cause as a `#[source]` rather than in their
/// text (`failed to write {path}`), so the top-level text alone drops the
/// reason (a planted symlink's errno, a refused connection). A cause is
/// skipped when the text so far already shows it — equal to it, or ending in
/// `: ` and it, as an error that prints its source does
/// (`file lock io error: {0}`, a transparent or `"{0}"` wrapper) — and when it
/// has no text.
///
/// Each cause appended is cut to `MAX_CAUSE_LEN` bytes ([`truncate`]) and
/// then passed through [`escape_message`]: a third-party error's text (an
/// I/O, parser, or HTTP client error) is printed by no type that bounds or
/// escapes it, while a fuz error's own escapes pass through unchanged. The
/// comparison is made on the text as printed, before escaping. An error
/// whose source carries text that must not be printed — a credential, bytes
/// its own message shows escaped or bounded — keeps it out of `source()`,
/// since this prints every cause it reaches.
#[must_use]
pub fn format_error_chain(error: &dyn std::error::Error) -> String {
    let mut message = error.to_string();
    // the chain as printed before escaping, which each cause is compared against
    let mut shown = message.clone();
    let mut source = error.source();
    while let Some(cause) = source {
        let cause_text = cause.to_string();
        let already_shown = shown == cause_text || shown.ends_with(&format!(": {cause_text}"));
        if !cause_text.is_empty() && !already_shown {
            // the cut text, so a cause whose tail the cut dropped is not skipped
            let cut = truncate(&cause_text, MAX_CAUSE_LEN);
            message.push_str(": ");
            message.push_str(&escape_message(&cut));
            shown.push_str(": ");
            shown.push_str(&cut);
        }
        source = cause.source();
    }
    message
}

/// The lines a binary prints to stderr for a failure: `error: ` and the
/// [`format_error_chain`] of `error`, then `hint: ` and `hint` when there is
/// one. Each line ends in a newline.
///
/// `hint` is advice for fixing the error, and only advice: this function owns
/// the `hint:` label, so the text doesn't carry one. An error's `hint()`
/// returns `Option<&'static str>` when every hint is a constant, or
/// `Option<Cow<'static, str>>` when some interpolate; a call site passes
/// `e.hint().as_deref()` for the latter.
#[must_use]
pub fn format_failure(error: &dyn std::error::Error, hint: Option<&str>) -> String {
    let mut text = format!("error: {}\n", format_error_chain(error));
    if let Some(hint) = hint {
        text.push_str("hint: ");
        text.push_str(hint);
        text.push('\n');
    }
    text
}

/// Print [`format_failure`] to stderr and return `exit_code` as the process
/// exit code — the tail of a `main() -> ExitCode` whose run failed.
pub fn report_failure(
    error: &dyn std::error::Error,
    hint: Option<&str>,
    exit_code: u8,
) -> std::process::ExitCode {
    eprint!("{}", format_failure(error, hint));
    std::process::ExitCode::from(exit_code)
}

#[cfg(test)]
mod tests {
    use std::fmt;

    use super::*;

    /// A CLI in the shape of the fuz binaries' top-level commands.
    #[cfg(feature = "argh")]
    #[derive(argh::FromArgs, Debug, PartialEq, Eq)]
    struct TestCli {
        #[argh(subcommand)]
        command: TestCommand,
    }

    #[cfg(feature = "argh")]
    #[derive(argh::FromArgs, Debug, PartialEq, Eq)]
    #[argh(subcommand)]
    enum TestCommand {
        Run(TestRun),
    }

    /// Run something.
    #[cfg(feature = "argh")]
    #[derive(argh::FromArgs, Debug, PartialEq, Eq)]
    #[argh(subcommand, name = "run")]
    struct TestRun {
        /// be quiet
        #[argh(switch, short = 'q')]
        quiet: bool,
    }

    #[cfg(feature = "argh")]
    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| (*s).to_string()).collect()
    }

    #[cfg(feature = "argh")]
    #[test]
    fn parse_args_returns_the_command_on_a_valid_line() {
        let cli: TestCli = parse_args(&argv(&["/usr/bin/tc", "run", "-q"])).unwrap();
        assert_eq!(
            cli,
            TestCli {
                command: TestCommand::Run(TestRun { quiet: true })
            }
        );
    }

    /// A help request — `--help` or the `help` subcommand, at either level — is
    /// `Help` (stdout, exit 0), named after the program path's file name.
    #[cfg(feature = "argh")]
    #[test]
    fn parse_args_maps_help_requests_to_help_exit_0() {
        for line in [
            &["/usr/bin/tc", "--help"][..],
            &["/usr/bin/tc", "help"],
            &["/usr/bin/tc", "run", "--help"],
            &["/usr/bin/tc", "help", "run"],
        ] {
            let exit = parse_args::<TestCli>(&argv(line)).unwrap_err();
            let ArgsExit::Help(text) = &exit else {
                panic!("{line:?} should be a help request: {exit:?}");
            };
            assert!(text.starts_with("Usage: tc"), "{line:?}: {text:?}");
            assert_eq!(exit.exit_code(EXIT_USAGE), 0);
        }
    }

    /// An unknown flag, a missing subcommand, and an empty argv are `Usage`
    /// (stderr, the caller's usage code) — never argh's exit 1.
    #[cfg(feature = "argh")]
    #[test]
    fn parse_args_maps_parse_errors_to_usage_with_the_callers_code() {
        let exit = parse_args::<TestCli>(&argv(&["/usr/bin/tc", "run", "--bogus"])).unwrap_err();
        assert_eq!(
            exit,
            ArgsExit::Usage(
                "Unrecognized argument: --bogus\n\nRun tc --help for more information.".to_string()
            )
        );
        assert_eq!(exit.exit_code(EXIT_USAGE), 2);
        assert_eq!(exit.exit_code(64), 64);

        let exit = parse_args::<TestCli>(&argv(&["tc"])).unwrap_err();
        assert!(matches!(exit, ArgsExit::Usage(_)), "{exit:?}");

        let exit = parse_args::<TestCli>(&[]).unwrap_err();
        assert!(matches!(exit, ArgsExit::Usage(_)), "{exit:?}");
    }

    /// An error with a fixed message and an optional source, standing in for
    /// the `thiserror` shapes the binaries print.
    #[derive(Debug)]
    struct Chained {
        message: &'static str,
        source: Option<Box<Self>>,
    }

    impl fmt::Display for Chained {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(self.message)
        }
    }

    impl std::error::Error for Chained {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            let cause: &Self = self.source.as_deref()?;
            Some(cause)
        }
    }

    /// `messages[0]` caused by `messages[1]`, and so on.
    fn chain(messages: &[&'static str]) -> Chained {
        let (first, rest) = messages.split_first().expect("a message");
        Chained {
            message: first,
            source: (!rest.is_empty()).then(|| Box::new(chain(rest))),
        }
    }

    /// The causes a wrapped error keeps as its source follow its own text.
    #[test]
    fn format_error_chain_appends_each_cause() {
        assert_eq!(
            format_error_chain(&chain(&["failed to write /a", "file is a symlink"])),
            "failed to write /a: file is a symlink"
        );
        assert_eq!(format_error_chain(&chain(&["a", "b", "c"])), "a: b: c");
        assert_eq!(format_error_chain(&chain(&["alone"])), "alone");
    }

    /// A cause the text already shows — the whole of it, or its tail after
    /// `: ` — is not printed twice, and neither is a cause with no text.
    #[test]
    fn format_error_chain_skips_a_cause_already_shown() {
        // an error that prints its source
        assert_eq!(
            format_error_chain(&chain(&[
                "failed to lock /l: file lock io error: denied",
                "file lock io error: denied",
                "denied"
            ])),
            "failed to lock /l: file lock io error: denied"
        );
        // a `"{0}"` wrapper: the cause is the whole text
        assert_eq!(
            format_error_chain(&chain(&["refused", "refused", "os error 111"])),
            "refused: os error 111"
        );
        // no text
        assert_eq!(
            format_error_chain(&chain(&["failed", "", "why"])),
            "failed: why"
        );
    }

    /// A message that ends with a cause's text without `: ` before it has not
    /// shown that cause.
    #[test]
    fn format_error_chain_needs_the_separator_to_skip() {
        assert_eq!(
            format_error_chain(&chain(&["read the denied", "denied"])),
            "read the denied: denied"
        );
        assert_eq!(
            format_error_chain(&chain(&["not:denied", "denied"])),
            "not:denied: denied"
        );
    }

    /// An appended cause cannot drive the terminal or add a line; a fuz
    /// error's own escapes in it are not escaped again, and the comparison
    /// is on the raw text, so a cause shown escaped is not appended again.
    #[test]
    fn format_error_chain_escapes_each_appended_cause() {
        assert_eq!(
            format_error_chain(&chain(&["failed", "bad \u{1b}[2J\nnext", "x\u{7}"])),
            "failed: bad \\u{1b}[2J\\nnext: x\\u{7}"
        );
        // a fuz error's message, its untrusted part escaped where rendered
        assert_eq!(
            format_error_chain(&chain(&["failed", "invalid key \"a\\u{1b}b\""])),
            "failed: invalid key \"a\\u{1b}b\""
        );
        assert_eq!(
            format_error_chain(&chain(&["failed", "a\u{1b}b: c\nd", "c\nd"])),
            "failed: a\\u{1b}b: c\\nd"
        );
    }

    /// A cause of any length is cut before it is escaped, so the line stays
    /// bounded and no escape is cut in half.
    #[test]
    fn format_error_chain_bounds_each_appended_cause() {
        let long: &'static str = "\u{1b}".repeat(MAX_CAUSE_LEN + 1).leak();
        let line = format_error_chain(&chain(&["failed", long]));
        let shown = line.strip_prefix("failed: ").expect("the cause follows");
        assert_eq!(shown, format!("{}...", "\\u{1b}".repeat(MAX_CAUSE_LEN)));
        // a cause at the bound is printed whole
        let fits: &'static str = "k".repeat(MAX_CAUSE_LEN).leak();
        assert_eq!(
            format_error_chain(&chain(&["failed", fits])),
            format!("failed: {fits}")
        );
    }

    /// A cause the cut dropped from the end of a long cause is still printed.
    #[test]
    fn format_error_chain_prints_a_cause_a_cut_dropped() {
        let long: &'static str = format!("{}: denied", "p".repeat(MAX_CAUSE_LEN)).leak();
        let line = format_error_chain(&chain(&["failed", long, "denied"]));
        assert_eq!(
            line,
            format!("failed: {}...: denied", "p".repeat(MAX_CAUSE_LEN))
        );
    }

    /// The `error:` line carries the chain, and the `hint:` line follows only
    /// when there is a hint.
    #[test]
    fn format_failure_renders_the_error_and_hint_lines() {
        let error = chain(&["database error", "connection refused"]);
        assert_eq!(
            format_failure(&error, None),
            "error: database error: connection refused\n"
        );
        assert_eq!(
            format_failure(&error, Some("is Postgres running?")),
            "error: database error: connection refused\nhint: is Postgres running?\n"
        );
    }
}
