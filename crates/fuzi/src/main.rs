//! fuzi — the lockfile-driven npm installer (the fuz-stack npm bridge).
//!
//! A thin CLI over `fuzi_core`. Verb-first grammar (`fuzi install` /
//! `fuzi verify`) for npm/pnpm muscle memory — the sealed `fuz` CLI is
//! noun-first, but the whole point of the bridge is to be a drop-in.
//!
//! This binary is the **presentation layer**: `fuzi_core` returns structured
//! values ([`fuzi_core::InstallReport`], [`fuzi_core::VerifyReport`]) and typed
//! errors ([`fuzi_core::FuziError`]); the rendering — human summary, `--json`,
//! `--quiet`, `--verbose` — lives here, so the library never prints.
//!
//! Much of what it prints is text someone else chose: lockfile keys and field
//! names, a linked sibling's `name` and `version`, the names of entries in the
//! project directory. None of it reaches the terminal raw. Human lines pass
//! each such string through [`escape_untrusted`] (an error's `Display` already
//! has), and `--json` output escapes every non-printing character as JSON's
//! `\uXXXX` ([`terminal_safe_json`]) — the same value to a parser, inert to a
//! terminal.

mod signal;

use std::process::ExitCode;
use std::str::FromStr;

use argh::FromArgs;
use fuz_sys::text::{escape_untrusted, needs_escape};
use fuzi_core::{
    CleanReport, EX_USAGE, FuziError, InstallOptions, InstallReport, NodeModulesObstruction, Omit,
    VerifyOptions, VerifyReport,
};
use serde_json::{Value, json};

/// Skipped-install-script names shown inline before `--verbose` uncaps the list.
const SKIPPED_SCRIPT_PREVIEW: usize = 5;

/// fuzi — install exactly from a `package-lock.json` into `node_modules`.
#[derive(FromArgs)]
struct Fuzi {
    #[argh(subcommand)]
    command: Command,
}

#[derive(FromArgs)]
#[argh(subcommand)]
enum Command {
    Install(InstallCmd),
    Verify(VerifyCmd),
    Clean(CleanCmd),
}

/// Install exactly from the lockfile in the current directory into
/// `node_modules` (npm-ci semantics: refuses on package.json/lockfile drift).
#[derive(FromArgs)]
#[argh(subcommand, name = "install")]
#[allow(clippy::struct_excessive_bools)] // CLI switches mirror the install modes
struct InstallCmd {
    /// dependency class to omit (`dev`, `optional`, or `peer`); repeatable
    #[argh(option)]
    omit: Vec<String>,

    /// install the lockfile as-is, skipping the package.json drift guard
    #[argh(switch)]
    ignore_manifest: bool,

    /// show what would happen without writing `node_modules` or the cache
    #[argh(switch)]
    dry_run: bool,

    /// use only cached tarballs; fail on a cache miss
    #[argh(switch)]
    offline: bool,

    /// emit machine-readable JSON
    #[argh(switch)]
    json: bool,

    /// suppress progress output
    #[argh(switch, short = 'q')]
    quiet: bool,

    /// show per-package detail (uncaps the skipped-script list)
    #[argh(switch, short = 'v')]
    verbose: bool,
}

/// Re-check a materialized `node_modules` against the lockfile and report drift.
#[derive(FromArgs)]
#[argh(subcommand, name = "verify")]
struct VerifyCmd {
    /// dependency class the tree was installed without (`dev`, `optional`, or
    /// `peer`); must match the install's --omit, repeatable
    #[argh(option)]
    omit: Vec<String>,

    /// emit machine-readable JSON
    #[argh(switch)]
    json: bool,
}

/// Sweep crash-leaked staging directories from the current project (never
/// `node_modules` or the cache). Do not run it while `fuzi install` is running
/// in this project: it would sweep that install's live staging tree too.
// What leaks them (kill -9, power loss, a release-build panic, a partial
// interrupt drain) and why install never sweeps at startup: `fuzi_core::clean`.
#[derive(FromArgs)]
#[argh(subcommand, name = "clean")]
struct CleanCmd {
    /// list what would be removed without removing anything
    #[argh(switch)]
    dry_run: bool,

    /// emit machine-readable JSON
    #[argh(switch)]
    json: bool,
}

fn main() -> ExitCode {
    // A command line argh can't parse exits `EX_USAGE` (64) — the code
    // `FuziError::Usage` gives an unknown `--omit` value — not argh's 1; `--help`
    // prints to stdout and exits 0. The message is argh's plain text even under
    // `--json`: the line did not parse, so nothing says `--json` was asked for.
    let args = match fuz_sys::cli::parse_env_args::<Fuzi>(EX_USAGE) {
        Ok(args) => args,
        Err(code) => return code,
    };
    let code = match args.command {
        Command::Install(cmd) => run_install(&cmd),
        Command::Verify(cmd) => run_verify(&cmd),
        Command::Clean(cmd) => run_clean(&cmd),
    };
    // A drain that fired after the last render check still owns the exit
    // status: returning would race its `128 + signum`.
    signal::yield_to_drain();
    code
}

/// Run one command body, mapping its outcome to a process exit code: success is
/// [`ExitCode::SUCCESS`], and any [`FuziError`] is rendered (human or `--json`)
/// and mapped through the sysexits taxonomy.
///
/// Every verb funnels through here so option-building and the command itself
/// share one error path — the body can just `?`, instead of each verb nesting a
/// match per fallible step with the same `render_error` in both arms.
///
/// An error is rendered only if no interrupt drain has fired
/// ([`signal::yield_to_drain`]): after one, the error is the drain's doing and
/// the signal task owns the output and the exit status. A body that renders a
/// success makes the same check first.
fn run(json: bool, body: impl FnOnce() -> Result<(), FuziError>) -> ExitCode {
    match body() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            signal::yield_to_drain();
            render_error(&e, json)
        }
    }
}

fn run_install(cmd: &InstallCmd) -> ExitCode {
    // A real install is the only thing that stages anything, so it is the only
    // caller that needs the interrupt drain — and it goes up before the first
    // staging root can exist. `verify` / `clean` / `--dry-run` write no
    // `node_modules` at all, so they keep the default signal disposition rather
    // than routing Ctrl-C through a listener with nothing to do.
    if !cmd.dry_run {
        signal::drain_staging_on_signal();
    }
    run(cmd.json, || {
        let report = fuzi_core::install(&install_options(cmd)?)?;
        signal::yield_to_drain();
        render_install_success(&report, cmd.json, cmd.quiet, cmd.verbose);
        Ok(())
    })
}

fn run_verify(cmd: &VerifyCmd) -> ExitCode {
    run(cmd.json, || {
        let report = fuzi_core::verify(&verify_options(cmd)?)?;
        render_verify_success(&report, cmd.json);
        Ok(())
    })
}

fn run_clean(cmd: &CleanCmd) -> ExitCode {
    run(cmd.json, || {
        let report = fuzi_core::clean(&current_dir()?, cmd.dry_run)?;
        render_clean_success(&report, cmd.json);
        Ok(())
    })
}

/// Build [`InstallOptions`] from the parsed CLI, surfacing an unknown `--omit`
/// value as a loud `FuziError::Usage` (the sysexits taxonomy, not argh's exit).
fn install_options(cmd: &InstallCmd) -> Result<InstallOptions, FuziError> {
    let omit = parse_omit(&cmd.omit)?;
    let dir = current_dir()?;
    Ok(InstallOptions {
        dir,
        omit,
        ignore_manifest: cmd.ignore_manifest,
        dry_run: cmd.dry_run,
        offline: cmd.offline,
    })
}

/// Build [`VerifyOptions`] from the parsed CLI, surfacing an unknown `--omit`
/// value the same way `install` does.
fn verify_options(cmd: &VerifyCmd) -> Result<VerifyOptions, FuziError> {
    let omit = parse_omit(&cmd.omit)?;
    let dir = current_dir()?;
    Ok(VerifyOptions { dir, omit })
}

fn parse_omit(values: &[String]) -> Result<Vec<Omit>, FuziError> {
    values
        .iter()
        .map(|v| Omit::from_str(v).map_err(|message| FuziError::Usage { message }))
        .collect()
}

fn current_dir() -> Result<std::path::PathBuf, FuziError> {
    std::env::current_dir().map_err(|source| FuziError::Io {
        what: "resolve current directory",
        source,
    })
}

// --- rendering -------------------------------------------------------------

/// Render a successful install (human summary / `--json` / `--quiet`).
fn render_install_success(report: &InstallReport, json: bool, quiet: bool, verbose: bool) {
    if json {
        print_ok_json(to_value(report));
        return;
    }
    let InstallLines { stderr, stdout } = install_lines(report, quiet, verbose);
    for line in stderr {
        eprintln!("{line}");
    }
    for line in stdout {
        println!("{line}");
    }
}

/// What a human (non-`--json`) install prints, by stream.
struct InstallLines {
    /// The warnings ([`warning_lines`]) — printed under `--quiet` too.
    stderr: Vec<String>,
    /// The summary, the skipped counts, and the skipped-script line — none of
    /// it under `--quiet`.
    stdout: Vec<String>,
}

/// The exact lines [`render_install_success`] prints for a human install.
/// Split from the printing so the `--quiet` contract — the warnings survive
/// it, the summary does not — is unit-testable.
fn install_lines(report: &InstallReport, quiet: bool, verbose: bool) -> InstallLines {
    let stderr = warning_lines(report);
    let mut stdout = Vec::new();
    if quiet {
        return InstallLines { stderr, stdout };
    }

    let (verb_fetch, verb_place, verb_link) = if report.dry_run {
        ("would fetch", "would place", "bins would link")
    } else {
        ("fetched", "placed", "bins linked")
    };
    let prefix = if report.dry_run {
        "fuzi (dry run)"
    } else {
        "fuzi"
    };
    stdout.push(format!(
        "{prefix}: {} cached · {} {verb_fetch} · {} {verb_place} · {} {verb_link}{}",
        report.cached,
        report.fetched,
        report.placed,
        report.bins_linked,
        linked_suffix(report)
    ));
    if report.skipped_optional > 0 {
        stdout.push(format!(
            "  {} optional package(s) skipped (platform mismatch)",
            report.skipped_optional
        ));
    }
    if report.bins_skipped > 0 {
        stdout.push(format!(
            "  {} declared bin(s) skipped (target file absent from the package, or a linked package's bin that is not a plain executable file)",
            report.bins_skipped
        ));
    }
    stdout.extend(skipped_scripts_line(&report.skipped_scripts, verbose));
    InstallLines { stderr, stdout }
}

/// The summary line's link count, present only when the lockfile links anything
/// (` · 1 linked` / ` · 1 would be linked`), so a link-free install's line is
/// unchanged.
fn linked_suffix(report: &InstallReport) -> String {
    match (report.linked, report.dry_run) {
        (0, _) => String::new(),
        (n, true) => format!(" · {n} would be linked"),
        (n, false) => format!(" · {n} linked"),
    }
}

/// The install's non-fatal warnings, one stderr line each.
///
/// Grouped here because they share a contract the summary does not: each one
/// means **the install may not be the install you asked for** — a wrong
/// platform selection, or a lockfile field fuzi parsed into nothing — or that
/// something changed under fuzi (a cached tarball that failed re-verification
/// and was refetched — or, under `--dry-run`, would be), so they print under
/// `--quiet` too. Under `--json` none
/// of this prints; there the same facts ride the structured payload.
///
/// Escaped: an unrecognized field's name is a lockfile key, and a link warning
/// quotes the sibling's own `version`.
fn warning_lines(report: &InstallReport) -> Vec<String> {
    let mut lines = Vec::new();
    if let Some(warning) = &report.libc_warning {
        lines.push(format!("warning: {}", escape_untrusted(warning)));
    }
    if !report.unknown_entry_fields.is_empty() {
        lines.push(format!(
            "warning: lockfile carries {} unrecognized entry field(s) fuzi ignored: {} — fuzi has not been reviewed against them; if any affects how a package installs, file an issue",
            report.unknown_entry_fields.len(),
            escaped_list(&report.unknown_entry_fields)
        ));
    }
    for warning in &report.link_warnings {
        lines.push(format!("warning: {}", escape_untrusted(warning)));
    }
    // A dry run changed nothing: the entry is still in the cache.
    let outcome = if report.dry_run {
        "an install would discard it and refetch from the registry"
    } else {
        "discarded and refetched from the registry"
    };
    for package in &report.healed {
        lines.push(format!(
            "warning: cached tarball for {} failed re-verification (local corruption or tampering); {outcome}",
            escape_untrusted(package)
        ));
    }
    lines
}

/// `items` joined with `, `, each one escaped — so an item can neither drive
/// the terminal nor pass for two.
fn escaped_list(items: &[String]) -> String {
    items
        .iter()
        .map(|item| escape_untrusted(item))
        .collect::<Vec<_>>()
        .join(", ")
}

/// One loud line naming the install scripts fuzi declined to run — capped
/// unless `--verbose` (loud once, not crying wolf) — or `None` when there are
/// no skipped scripts.
fn skipped_scripts_line(scripts: &[String], verbose: bool) -> Option<String> {
    if scripts.is_empty() {
        return None;
    }
    if verbose || scripts.len() <= SKIPPED_SCRIPT_PREVIEW {
        Some(format!(
            "  {} package(s) with install scripts fuzi did NOT run: {}",
            scripts.len(),
            escaped_list(scripts)
        ))
    } else {
        let shown = &scripts[..SKIPPED_SCRIPT_PREVIEW];
        Some(format!(
            "  {} package(s) with install scripts fuzi did NOT run: {}, … (+{} more, --verbose)",
            scripts.len(),
            escaped_list(shown),
            scripts.len() - SKIPPED_SCRIPT_PREVIEW
        ))
    }
}

/// Render a successful verify (human / `--json`).
fn render_verify_success(report: &VerifyReport, json: bool) {
    if json {
        print_ok_json(to_value(report));
        return;
    }
    let links = if report.links_checked > 0 {
        format!(", {} link(s)", report.links_checked)
    } else {
        String::new()
    };
    println!(
        "fuzi verify: ok — {} package(s){links} match the lockfile ({} platform set(s) checked)",
        report.checked, report.platform_parents_checked
    );
}

/// Render a successful clean (human / `--json`). Under `--json` the kept
/// trees ride the payload's `skipped` array (each with its `restore_command`).
fn render_clean_success(report: &CleanReport, json: bool) {
    if json {
        print_ok_json(to_value(report));
        return;
    }
    for line in clean_warning_lines(report) {
        eprintln!("{line}");
    }
    println!("{}", clean_line(report));
}

/// One stderr warning per `.fuzi-old-*` tree clean kept because `node_modules`
/// is not a directory — the tree may be the user's only copy, and the line says
/// how to put it back (moving an obstruction aside first, when one is there) —
/// plus, when more than one was kept, a line saying to restore only one.
/// Escaped: the names are whatever someone created.
fn clean_warning_lines(report: &CleanReport) -> Vec<String> {
    let (state, first) = report.node_modules_obstruction.map_or_else(
        || ("node_modules is absent".to_string(), String::new()),
        |kind| {
            let noun = match kind {
                NodeModulesObstruction::Symlink => "symlink",
                NodeModulesObstruction::File => "file",
            };
            (
                format!("node_modules is {kind}, not a directory"),
                format!("move the {noun} at node_modules aside first, then "),
            )
        },
    );
    let mut lines: Vec<String> = report
        .skipped
        .iter()
        .map(|kept| {
            format!(
                "warning: kept {}: {state}, so this may be your previous tree (an install interrupted mid-swap); {first}restore it with `{}`, or re-run fuzi clean once node_modules is a directory to sweep it",
                escape_untrusted(&kept.name),
                escape_untrusted(&kept.restore_command)
            )
        })
        .collect();
    if report.skipped.len() > 1 {
        lines.push(format!(
            "warning: {} displaced trees kept — restore only one of them (each restore command does nothing once node_modules exists); fuzi clean sweeps the rest once it does",
            report.skipped.len()
        ));
    }
    lines
}

/// The exact line a human `fuzi clean` prints. The swept names are directory
/// entries of the project — any `.fuzi-old-…` name someone created — so they
/// are escaped.
fn clean_line(report: &CleanReport) -> String {
    let verb = if report.dry_run {
        "would remove"
    } else {
        "removed"
    };
    if report.removed.is_empty() && !report.skipped.is_empty() {
        format!(
            "fuzi clean: nothing swept (kept {} displaced tree(s), see above)",
            report.skipped.len()
        )
    } else if report.removed.is_empty() {
        "fuzi clean: nothing to sweep".to_string()
    } else {
        format!(
            "fuzi clean: {verb} {} staging artifact(s): {}",
            report.removed.len(),
            escaped_list(&report.removed)
        )
    }
}

/// Print a report value as `{ "ok": true, …fields… }` on stdout.
fn print_ok_json(mut value: Value) {
    if let Value::Object(map) = &mut value {
        map.insert("ok".to_string(), json!(true));
    }
    println!("{}", to_pretty(&value));
}

/// Render an error: a teaching message on stderr, or a structured object on
/// stdout under `--json`. Returns the process exit code.
fn render_error(e: &FuziError, json: bool) -> ExitCode {
    if json {
        println!("{}", to_pretty(&error_json(e)));
    } else {
        eprintln!("error: {e}");
    }
    ExitCode::from(e.exit_code())
}

/// Build the `--json` error object: `{ ok: false, error: { kind, exit_code,
/// message, …payload… } }`. The payload mirrors each variant's structured fields
/// so an agent can branch without parsing the human message.
///
/// The match is exhaustive on purpose — no catch-all — so a new variant does
/// not compile until it says what it carries. Values are raw (a lockfile key, a
/// sibling's text); [`to_pretty`] makes the printed document terminal-safe.
fn error_json(e: &FuziError) -> Value {
    let mut obj = serde_json::Map::new();
    obj.insert("kind".to_string(), json!(e.kind()));
    obj.insert("exit_code".to_string(), json!(e.exit_code()));
    obj.insert("message".to_string(), json!(e.to_string()));
    let mut put = |key: &str, value: Value| {
        obj.insert(key.to_string(), value);
    };
    match e {
        // Nothing beneath the envelope: a usage or lockfile error's message is
        // its whole payload, and the unit variants' kind is the whole fact.
        FuziError::Usage { .. }
        | FuziError::Lockfile { .. }
        | FuziError::NodeModulesMountPoint
        | FuziError::NodeModulesNotRenameable
        | FuziError::Interrupted => {}
        FuziError::Io { what, source } => {
            put("what", json!(what));
            put("reason", json!(source.to_string()));
        }
        FuziError::MissingInput { file, dir } => {
            put("file", json!(file.file_name()));
            put("dir", json!(dir.to_string_lossy()));
            put("next_step", json!(file.next_step()));
        }
        FuziError::Drift { diffs } => put("diffs", json!(diffs)),
        FuziError::Refused { refusals } => {
            let items: Vec<Value> = refusals
                .iter()
                .map(|r| {
                    json!({
                        "path": if r.path.is_root() { "" } else { r.path.as_str() },
                        "code": r.reason.code(),
                        "why": r.reason.why(),
                        "next_step": r.reason.next_step(),
                    })
                })
                .collect();
            put("refusals", Value::Array(items));
        }
        FuziError::Fetch { failures } | FuziError::FetchPermanent { failures } => {
            put("failures", to_value(failures));
        }
        FuziError::HttpClient { reason } => put("reason", json!(reason)),
        FuziError::TlsCertificate { host, reason } => {
            put("host", json!(host));
            put("reason", json!(reason));
        }
        FuziError::IntegrityMismatch { mismatches } => put("mismatches", to_value(mismatches)),
        FuziError::OfflineCacheMiss { packages } => put("packages", json!(packages)),
        FuziError::OfflineCacheCorrupt { entries } => put("entries", to_value(entries)),
        FuziError::Extract { package, source } => {
            put("package", json!(package));
            put("reason", json!(source.to_string()));
        }
        FuziError::InsufficientSpace { needed, available } => {
            put("needed", json!(needed));
            put("available", json!(available));
        }
        FuziError::CacheTampered { package } => put("package", json!(package)),
        FuziError::NodeModulesNotDirectory { kind } => put("obstruction", to_value(kind)),
        FuziError::UnsafeStagingPath { key } => put("key", json!(key)),
        FuziError::StagingIncomplete { missing, path } => {
            put("path", json!(path.to_string_lossy()));
            put("code", json!(missing.code()));
            put("why", json!(missing.why()));
            put("next_step", json!(missing.next_step()));
        }
        FuziError::LinkTarget { problems } => put("problems", to_value(problems)),
        FuziError::VerifyFailed { problems } => put("problems", to_value(problems)),
    }
    json!({ "ok": false, "error": Value::Object(obj) })
}

/// Serialize a value, falling back to `null` (the structured payloads always
/// serialize; the fallback only guards against an impossible serde failure).
fn to_value<T: serde::Serialize>(value: &T) -> Value {
    serde_json::to_value(value).unwrap_or(Value::Null)
}

/// Pretty-print JSON for stdout, falling back to a compact object on the
/// impossible error. Terminal-safe: see [`terminal_safe_json`].
fn to_pretty(value: &Value) -> String {
    terminal_safe_json(&serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string()))
}

/// Serialized `json` with every non-printing character written as a JSON
/// `\uXXXX` escape.
///
/// `serde_json` escapes the C0 controls inside strings and nothing else, so a
/// DEL, a C1 control, or a bidi override in a lockfile key would otherwise
/// reach the terminal through `--json`. The raw payload values are what a
/// consumer wants, and this keeps them: an escaped character parses back to
/// the same one. Such a character can only sit inside a JSON string (the
/// newlines and spaces of the pretty layout are the document's own and are
/// left alone), which is exactly where a `\u` escape is valid.
fn terminal_safe_json(json: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(json.len());
    for c in json.chars() {
        if c == '\n' || !needs_escape(c) {
            out.push(c);
        } else {
            for unit in c.encode_utf16(&mut [0; 2]) {
                // Writing to a String is infallible.
                let _ = write!(out, "\\u{unit:04x}");
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use fuzi_core::{
        CorruptCacheItem, FetchFailure, InstallPath, IntegrityMismatchItem, LinkTargetProblem,
        Refusal, RefuseReason, SkippedArtifact, StagingEntry, VerifyProblem, VerifyProblemKind,
    };

    // --- error_json: the agent-facing `--json` error contract ----------------
    //
    // These pin the stable machine shape `{ ok: false, error: { kind, exit_code,
    // message, …payload… } }` that the exit-code taxonomy exists to serve — the
    // structured payload an agent branches on instead of parsing the human
    // message. Each asserts the envelope (`kind`/`exit_code` agree with
    // `FuziError`) plus the per-variant payload array's presence and item shape.

    /// The `kind`, `exit_code`, and `message` all mirror `FuziError`, and the top-level
    /// envelope is exactly `{ ok: false, error: {…} }`. Shared by every payload
    /// test below so each one only has to add the payload assertions.
    fn assert_envelope(v: &Value, e: &FuziError) {
        assert_eq!(v["ok"], json!(false));
        let top = v.as_object().expect("top-level object");
        assert_eq!(top.len(), 2, "top level is exactly {{ok, error}}");
        let error = &v["error"];
        assert_eq!(error["kind"], json!(e.kind()));
        assert_eq!(error["exit_code"], json!(e.exit_code()));
        assert_eq!(error["message"], json!(e.to_string()));
    }

    #[test]
    fn error_json_refused_carries_structured_refusals() {
        let err = FuziError::Refused {
            refusals: vec![Refusal {
                path: InstallPath::new("node_modules/foo"),
                reason: RefuseReason::Sha1Integrity,
            }],
        };
        let v = error_json(&err);
        assert_envelope(&v, &err);
        assert_eq!(v["error"]["kind"], json!("refused"));
        assert_eq!(v["error"]["exit_code"], json!(65));

        let refusals = v["error"]["refusals"].as_array().expect("refusals array");
        assert_eq!(refusals.len(), 1);
        let r = &refusals[0];
        // Exactly the four documented per-refusal fields, each sourced from the
        // public `RefuseReason` accessors.
        assert_eq!(r.as_object().expect("refusal object").len(), 4);
        assert_eq!(r["path"], json!("node_modules/foo"));
        assert_eq!(r["code"], json!("sha1_integrity"));
        assert_eq!(r["why"], json!("sha1-only integrity"));
        assert_eq!(
            r["next_step"],
            json!("regenerate the lockfile with npm 7+ (npm install)")
        );
    }

    /// The root `""` key is emitted as an empty string, not omitted — pins the
    /// `is_root()` branch in `error_json`'s refusal mapping.
    #[test]
    fn error_json_refused_maps_root_path_to_empty_string() {
        let err = FuziError::Refused {
            refusals: vec![Refusal {
                path: InstallPath::new(""),
                reason: RefuseReason::PlatformMismatchRequired,
            }],
        };
        let v = error_json(&err);
        let r = &v["error"]["refusals"][0];
        assert_eq!(r["path"], json!(""));
        assert_eq!(r["code"], json!("platform_mismatch_required"));
    }

    #[test]
    fn error_json_missing_input_carries_file_dir_and_next_step() {
        let err = FuziError::MissingInput {
            file: fuzi_core::ProjectFile::Lockfile,
            dir: "/home/u/proj".into(),
        };
        let v = error_json(&err);
        assert_envelope(&v, &err);
        assert_eq!(v["error"]["kind"], json!("missing_input"));
        assert_eq!(v["error"]["exit_code"], json!(66));
        assert_eq!(v["error"]["file"], json!("package-lock.json"));
        assert_eq!(v["error"]["dir"], json!("/home/u/proj"));
        assert_eq!(
            v["error"]["next_step"],
            json!(fuzi_core::ProjectFile::Lockfile.next_step())
        );
    }

    #[test]
    fn error_json_drift_carries_diffs_array() {
        let err = FuziError::Drift {
            diffs: vec!["react: 18.0.0 (manifest) vs 18.2.0 (lock)".to_string()],
        };
        let v = error_json(&err);
        assert_envelope(&v, &err);
        assert_eq!(v["error"]["kind"], json!("drift"));
        assert_eq!(v["error"]["exit_code"], json!(65));
        let diffs = v["error"]["diffs"].as_array().expect("diffs array");
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0], json!("react: 18.0.0 (manifest) vs 18.2.0 (lock)"));
    }

    #[test]
    fn error_json_fetch_and_permanent_carry_failures_array() {
        let failure = FetchFailure {
            package: "left-pad@1.3.0".to_string(),
            reason: "503 Service Unavailable".to_string(),
        };

        // Transient fetch — EX_TEMPFAIL (75), "re-run to retry".
        let fetch = FuziError::Fetch {
            failures: vec![failure.clone()],
        };
        let v = error_json(&fetch);
        assert_envelope(&v, &fetch);
        assert_eq!(v["error"]["kind"], json!("fetch"));
        assert_eq!(v["error"]["exit_code"], json!(75));
        let arr = v["error"]["failures"].as_array().expect("failures array");
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["package"], json!("left-pad@1.3.0"));
        assert_eq!(arr[0]["reason"], json!("503 Service Unavailable"));

        // Permanent fetch — same payload shape, but deliberately NOT 75 (a 4xx is
        // not "re-run to retry"); it joins the EX_DATAERR (65) class.
        let permanent = FuziError::FetchPermanent {
            failures: vec![failure],
        };
        let v2 = error_json(&permanent);
        assert_envelope(&v2, &permanent);
        assert_eq!(v2["error"]["kind"], json!("fetch_permanent"));
        assert_eq!(v2["error"]["exit_code"], json!(65));
        let arr2 = v2["error"]["failures"].as_array().expect("failures array");
        assert_eq!(arr2[0]["package"], json!("left-pad@1.3.0"));
    }

    #[test]
    fn error_json_http_client_is_config_not_retry() {
        // A client that cannot be built fails the same way on every run, so it
        // must not carry exit 75's "re-run to retry".
        let err = FuziError::HttpClient {
            reason: "no CA certificates found".to_string(),
        };
        let v = error_json(&err);
        assert_envelope(&v, &err);
        assert_eq!(v["error"]["kind"], json!("http_client"));
        assert_eq!(v["error"]["exit_code"], json!(78));
        assert_eq!(v["error"]["reason"], json!("no CA certificates found"));
        assert!(
            v["error"]["message"]
                .as_str()
                .unwrap()
                .contains("re-running will not help")
        );
    }

    #[test]
    fn error_json_tls_certificate_is_config_not_retry() {
        // A rejected certificate is rejected again on every run, so it must not
        // carry exit 75's "re-run to retry"; host and reason ride the payload.
        let err = FuziError::TlsCertificate {
            host: "registry.npmjs.org".to_string(),
            reason: "invalid peer certificate: UnknownIssuer".to_string(),
        };
        let v = error_json(&err);
        assert_envelope(&v, &err);
        assert_eq!(v["error"]["kind"], json!("tls_certificate"));
        assert_eq!(v["error"]["exit_code"], json!(78));
        assert_eq!(v["error"]["host"], json!("registry.npmjs.org"));
        assert_eq!(
            v["error"]["reason"],
            json!("invalid peer certificate: UnknownIssuer")
        );
        let message = v["error"]["message"].as_str().unwrap();
        assert!(message.contains("check the proxy or CA trust"), "{message}");
        assert!(message.contains("re-running will not help"), "{message}");
    }

    #[test]
    fn error_json_integrity_mismatch_carries_mismatches_array() {
        let err = FuziError::IntegrityMismatch {
            mismatches: vec![IntegrityMismatchItem {
                package: "lodash@4.17.21".to_string(),
                expected: "sha512-expected".to_string(),
                actual: "sha512-actual".to_string(),
            }],
        };
        let v = error_json(&err);
        assert_envelope(&v, &err);
        assert_eq!(v["error"]["kind"], json!("integrity_mismatch"));
        assert_eq!(v["error"]["exit_code"], json!(65));
        let arr = v["error"]["mismatches"]
            .as_array()
            .expect("mismatches array");
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["package"], json!("lodash@4.17.21"));
        assert_eq!(arr[0]["expected"], json!("sha512-expected"));
        assert_eq!(arr[0]["actual"], json!("sha512-actual"));
    }

    #[test]
    fn error_json_offline_cache_miss_carries_packages_array() {
        let err = FuziError::OfflineCacheMiss {
            packages: vec!["a@1.0.0".to_string(), "b@2.0.0".to_string()],
        };
        let v = error_json(&err);
        assert_envelope(&v, &err);
        assert_eq!(v["error"]["kind"], json!("offline_cache_miss"));
        assert_eq!(v["error"]["exit_code"], json!(69));
        let arr = v["error"]["packages"].as_array().expect("packages array");
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0], json!("a@1.0.0"));
        assert_eq!(arr[1], json!("b@2.0.0"));
    }

    #[test]
    fn error_json_offline_cache_corrupt_is_a_tamper_alarm_not_a_miss() {
        let err = FuziError::OfflineCacheCorrupt {
            entries: vec![CorruptCacheItem {
                package: "node_modules/a".to_string(),
                path: "/home/u/.fuz/cache/npm/sha512-ab/package.tgz".to_string(),
            }],
        };
        let v = error_json(&err);
        assert_envelope(&v, &err);
        assert_eq!(v["error"]["kind"], json!("offline_cache_corrupt"));
        assert_eq!(v["error"]["exit_code"], json!(65));
        let arr = v["error"]["entries"].as_array().expect("entries array");
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["package"], json!("node_modules/a"));
        assert_eq!(
            arr[0]["path"],
            json!("/home/u/.fuz/cache/npm/sha512-ab/package.tgz")
        );
        assert!(
            v["error"]["message"]
                .as_str()
                .unwrap()
                .contains("corruption or tampering")
        );
    }

    #[test]
    fn error_json_verify_failed_carries_problems_array() {
        let err = FuziError::VerifyFailed {
            problems: vec![VerifyProblem {
                package: "esbuild".to_string(),
                kind: VerifyProblemKind::Missing,
                detail: "directory absent from node_modules".to_string(),
            }],
        };
        let v = error_json(&err);
        assert_envelope(&v, &err);
        assert_eq!(v["error"]["kind"], json!("verify_failed"));
        assert_eq!(v["error"]["exit_code"], json!(65));
        let arr = v["error"]["problems"].as_array().expect("problems array");
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["package"], json!("esbuild"));
        // VerifyProblemKind serializes snake_case.
        assert_eq!(arr[0]["kind"], json!("missing"));
        assert_eq!(
            arr[0]["detail"],
            json!("directory absent from node_modules")
        );
    }

    #[test]
    fn error_json_link_target_carries_problems_array() {
        let err = FuziError::LinkTarget {
            problems: vec![LinkTargetProblem {
                package: "node_modules/@fuzdev/zap".to_string(),
                detail: "link target ../zap does not exist".to_string(),
            }],
        };
        let v = error_json(&err);
        assert_envelope(&v, &err);
        assert_eq!(v["error"]["kind"], json!("link_target"));
        assert_eq!(v["error"]["exit_code"], json!(65));
        let arr = v["error"]["problems"].as_array().expect("problems array");
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["package"], json!("node_modules/@fuzdev/zap"));
        assert_eq!(arr[0]["detail"], json!("link target ../zap does not exist"));
    }

    #[test]
    fn linked_suffix_only_when_something_links() {
        let mut report = InstallReport::default();
        assert_eq!(linked_suffix(&report), "");
        report.linked = 1;
        assert_eq!(linked_suffix(&report), " · 1 linked");
        report.dry_run = true;
        assert_eq!(linked_suffix(&report), " · 1 would be linked");
    }

    #[test]
    fn clean_reports_a_kept_displaced_tree_in_both_renderings() {
        // The skip is the safety arm — it must be visible, never silent: a
        // stderr warning naming the restore command, and the `skipped` array in
        // `--json`.
        const RESTORE: &str = "[ -e node_modules ] || mv -- '.fuzi-old-ab12' node_modules";
        let mut report = CleanReport {
            dry_run: false,
            removed: vec![],
            skipped: vec![SkippedArtifact {
                name: ".fuzi-old-ab12".to_string(),
                restore_command: RESTORE.to_string(),
            }],
            node_modules_obstruction: None,
        };
        let lines = clean_warning_lines(&report);
        assert_eq!(lines.len(), 1);
        assert!(lines[0].starts_with("warning: kept .fuzi-old-ab12: node_modules is absent"));
        assert!(lines[0].contains(&format!("`{RESTORE}`")), "{}", lines[0]);
        assert_eq!(
            clean_line(&report),
            "fuzi clean: nothing swept (kept 1 displaced tree(s), see above)"
        );
        let v = to_value(&report);
        assert_eq!(
            v["skipped"],
            json!([{ "name": ".fuzi-old-ab12", "restore_command": RESTORE }])
        );
        assert!(v.get("node_modules_obstruction").is_none());

        // An obstruction in the place: the line says to move it aside first,
        // and `--json` names it.
        report.node_modules_obstruction = Some(NodeModulesObstruction::Symlink);
        let lines = clean_warning_lines(&report);
        assert!(
            lines[0].starts_with(
                "warning: kept .fuzi-old-ab12: node_modules is a symlink, not a directory"
            ),
            "{}",
            lines[0]
        );
        assert!(
            lines[0].contains("move the symlink at node_modules aside first, then restore it with"),
            "{}",
            lines[0]
        );
        assert_eq!(
            to_value(&report)["node_modules_obstruction"],
            json!("symlink")
        );

        // Several kept: one more line, saying to restore only one.
        report.skipped.push(SkippedArtifact {
            name: ".fuzi-old-cd34".to_string(),
            restore_command: "[ -e node_modules ] || mv -- '.fuzi-old-cd34' node_modules"
                .to_string(),
        });
        let lines = clean_warning_lines(&report);
        assert_eq!(lines.len(), 3);
        assert!(
            lines[2].starts_with("warning: 2 displaced trees kept — restore only one of them"),
            "{}",
            lines[2]
        );

        assert!(clean_warning_lines(&CleanReport::default()).is_empty());
        assert_eq!(
            clean_line(&CleanReport::default()),
            "fuzi clean: nothing to sweep"
        );
    }

    #[test]
    fn error_json_extract_names_the_package_and_splits_its_class() {
        let malformed = FuziError::Extract {
            package: "node_modules/p".to_string(),
            source: fuzi_core::ArchiveError::Malformed {
                context: "reading entry",
                source: std::io::Error::new(std::io::ErrorKind::InvalidData, "bad header"),
            },
        };
        let v = error_json(&malformed);
        assert_envelope(&v, &malformed);
        assert_eq!(v["error"]["kind"], json!("extract"));
        assert_eq!(v["error"]["exit_code"], json!(65));
        assert_eq!(v["error"]["package"], json!("node_modules/p"));
        let read = FuziError::Extract {
            package: "node_modules/p".to_string(),
            source: fuzi_core::ArchiveError::Read {
                context: "reading entry",
                source: std::io::Error::from_raw_os_error(5),
            },
        };
        assert_eq!(error_json(&read)["error"]["exit_code"], json!(74));
    }

    #[test]
    fn error_json_no_payload_variant_has_only_envelope_fields() {
        let err = FuziError::Usage {
            message: "unknown omit value `prod`".to_string(),
        };
        let v = error_json(&err);
        assert_envelope(&v, &err);
        let error = v["error"].as_object().expect("error object");
        assert_eq!(error["kind"], json!("usage"));
        assert_eq!(error["exit_code"], json!(64));
        // No per-variant payload key — exactly kind/exit_code/message.
        assert_eq!(error.len(), 3);
    }

    /// Every variant, with exactly the payload keys it adds to the envelope and
    /// their values. The match in `error_json` is exhaustive at compile time;
    /// this pins what each arm emits, through the printed (terminal-safe) form.
    /// The table is not: a new variant compiles without a row here — the
    /// match is what forces it to say what it carries; add the row with it.
    #[test]
    fn error_json_emits_every_variants_structured_fields() {
        use fuzi_core::{NodeModulesObstruction, ProjectFile};
        let failure = || FetchFailure {
            package: "node_modules/f".to_string(),
            reason: "503".to_string(),
        };
        let cases: Vec<(FuziError, Value)> = vec![
            (
                FuziError::Usage {
                    message: "m".into(),
                },
                json!({}),
            ),
            (
                FuziError::Io {
                    what: "read package-lock.json",
                    source: std::io::Error::other("disk"),
                },
                json!({"what": "read package-lock.json", "reason": "disk"}),
            ),
            (
                FuziError::MissingInput {
                    file: ProjectFile::Manifest,
                    dir: "/p".into(),
                },
                json!({
                    "file": "package.json",
                    "dir": "/p",
                    "next_step": ProjectFile::Manifest.next_step()
                }),
            ),
            (
                FuziError::Lockfile {
                    message: "m".into(),
                },
                json!({}),
            ),
            (
                FuziError::Drift {
                    diffs: vec!["d".into()],
                },
                json!({"diffs": ["d"]}),
            ),
            (
                FuziError::Refused {
                    refusals: vec![Refusal {
                        path: InstallPath::new("node_modules/r"),
                        reason: RefuseReason::Sha1Integrity,
                    }],
                },
                json!({"refusals": [{
                    "path": "node_modules/r",
                    "code": "sha1_integrity",
                    "why": RefuseReason::Sha1Integrity.why(),
                    "next_step": RefuseReason::Sha1Integrity.next_step()
                }]}),
            ),
            (
                FuziError::Fetch {
                    failures: vec![failure()],
                },
                json!({"failures": [{"package": "node_modules/f", "reason": "503"}]}),
            ),
            (
                FuziError::FetchPermanent {
                    failures: vec![failure()],
                },
                json!({"failures": [{"package": "node_modules/f", "reason": "503"}]}),
            ),
            (
                FuziError::HttpClient { reason: "r".into() },
                json!({"reason": "r"}),
            ),
            (
                FuziError::TlsCertificate {
                    host: "h".into(),
                    reason: "r".into(),
                },
                json!({"host": "h", "reason": "r"}),
            ),
            (
                FuziError::IntegrityMismatch {
                    mismatches: vec![IntegrityMismatchItem {
                        package: "p".into(),
                        expected: "e".into(),
                        actual: "a".into(),
                    }],
                },
                json!({"mismatches": [{"package": "p", "expected": "e", "actual": "a"}]}),
            ),
            (
                FuziError::OfflineCacheMiss {
                    packages: vec!["p".into()],
                },
                json!({"packages": ["p"]}),
            ),
            (
                FuziError::OfflineCacheCorrupt {
                    entries: vec![CorruptCacheItem {
                        package: "p".into(),
                        path: "/c".into(),
                    }],
                },
                json!({"entries": [{"package": "p", "path": "/c"}]}),
            ),
            (
                FuziError::Extract {
                    package: "node_modules/x".into(),
                    source: fuzi_core::ArchiveError::CompressionBomb(200),
                },
                json!({
                    "package": "node_modules/x",
                    "reason": fuzi_core::ArchiveError::CompressionBomb(200).to_string()
                }),
            ),
            (
                FuziError::InsufficientSpace {
                    needed: 10,
                    available: 3,
                },
                json!({"needed": 10, "available": 3}),
            ),
            (
                FuziError::CacheTampered {
                    package: "node_modules/t".into(),
                },
                json!({"package": "node_modules/t"}),
            ),
            (
                FuziError::NodeModulesNotDirectory {
                    kind: NodeModulesObstruction::Symlink,
                },
                json!({"obstruction": "symlink"}),
            ),
            (
                FuziError::NodeModulesNotDirectory {
                    kind: NodeModulesObstruction::File,
                },
                json!({"obstruction": "file"}),
            ),
            (FuziError::NodeModulesMountPoint, json!({})),
            (FuziError::NodeModulesNotRenameable, json!({})),
            (
                FuziError::UnsafeStagingPath {
                    key: "node_modules/../x".into(),
                },
                json!({"key": "node_modules/../x"}),
            ),
            (FuziError::Interrupted, json!({})),
            (
                FuziError::StagingIncomplete {
                    missing: StagingEntry::PackageJson,
                    path: "/p/.fuzi-installing-0/a/package.json".into(),
                },
                json!({
                    "path": "/p/.fuzi-installing-0/a/package.json",
                    "code": "package_json",
                    "why": StagingEntry::PackageJson.why(),
                    "next_step": StagingEntry::PackageJson.next_step(),
                }),
            ),
            (
                FuziError::LinkTarget {
                    problems: vec![LinkTargetProblem {
                        package: "node_modules/l".into(),
                        detail: "d".into(),
                    }],
                },
                json!({"problems": [{"package": "node_modules/l", "detail": "d"}]}),
            ),
            (
                FuziError::VerifyFailed {
                    problems: vec![VerifyProblem {
                        package: "node_modules/v".into(),
                        kind: VerifyProblemKind::Missing,
                        detail: "d".into(),
                    }],
                },
                json!({"problems": [{"package": "node_modules/v", "kind": "missing", "detail": "d"}]}),
            ),
        ];
        for (err, payload) in &cases {
            let kind = err.kind();
            let printed = to_pretty(&error_json(err));
            let v: Value = serde_json::from_str(&printed).expect("valid JSON");
            assert_envelope(&v, err);
            let mut expected = payload.as_object().expect("payload object").clone();
            expected.insert("kind".into(), json!(kind));
            expected.insert("exit_code".into(), json!(err.exit_code()));
            expected.insert("message".into(), json!(err.to_string()));
            assert_eq!(v["error"], Value::Object(expected), "{kind}");
        }
    }

    // --- untrusted text never reaches the terminal raw ------------------------

    /// An escape sequence, a line-forging newline, a bidi override, a C1 CSI.
    const EVIL: &str = "x\u{1b}[2J\nforged\u{202e}\u{9b}31m\u{7f}";

    fn assert_inert(line: &str) {
        assert!(
            !line.chars().any(needs_escape),
            "raw non-printing text in {line:?}"
        );
        assert!(line.contains("x\\u{1b}[2J\\nforged"), "{line:?}");
    }

    #[test]
    fn warnings_escape_lockfile_and_sibling_text() {
        let report = InstallReport {
            unknown_entry_fields: vec![EVIL.to_string(), "plain".to_string()],
            link_warnings: vec![format!(
                "node_modules/lib: linked package ../lib is version {EVIL}, the lockfile recorded 1.0.0"
            )],
            ..InstallReport::default()
        };
        let lines = warning_lines(&report);
        assert_eq!(lines.len(), 2);
        for line in &lines {
            assert!(line.starts_with("warning: "));
            assert_inert(line);
        }
        assert!(lines[0].contains(", plain — fuzi has not been reviewed"));
    }

    #[test]
    fn a_healed_cache_entry_is_warned_not_silent() {
        // A cached tarball that failed re-verification is local corruption or
        // tampering: the refetch keeps the install correct, but the event must
        // reach the user — one stderr line per package, escaped — and ride
        // `--json` as `healed`.
        let report = InstallReport {
            healed: vec!["node_modules/foo".to_string(), EVIL.to_string()],
            ..InstallReport::default()
        };
        let lines = warning_lines(&report);
        assert_eq!(
            lines[0],
            "warning: cached tarball for node_modules/foo failed re-verification (local corruption or tampering); discarded and refetched from the registry"
        );
        assert_inert(&lines[1]);
        // A dry run discarded nothing, and says so.
        let dry = InstallReport {
            dry_run: true,
            ..report.clone()
        };
        assert_eq!(
            warning_lines(&dry)[0],
            "warning: cached tarball for node_modules/foo failed re-verification (local corruption or tampering); an install would discard it and refetch from the registry"
        );
        assert_eq!(
            to_value(&report)["healed"],
            json!(["node_modules/foo", EVIL])
        );
        assert!(to_value(&InstallReport::default()).get("healed").is_none());
    }

    #[test]
    fn quiet_keeps_the_warnings_and_drops_the_summary() {
        // A heal is a tamper signal: `--quiet` silences the summary, never it.
        let report = InstallReport {
            fetched: 2,
            placed: 2,
            healed: vec!["node_modules/a".to_string(), "node_modules/b".to_string()],
            skipped_scripts: vec!["esbuild".to_string()],
            ..InstallReport::default()
        };
        let quiet = install_lines(&report, true, false);
        assert_eq!(quiet.stderr.len(), 2);
        assert!(
            quiet.stderr[0].starts_with("warning: cached tarball for node_modules/a failed"),
            "{:?}",
            quiet.stderr
        );
        assert!(quiet.stdout.is_empty(), "{:?}", quiet.stdout);

        let loud = install_lines(&report, false, false);
        assert_eq!(loud.stderr, quiet.stderr);
        assert_eq!(
            loud.stdout,
            [
                "fuzi: 0 cached · 2 fetched · 2 placed · 0 bins linked",
                "  1 package(s) with install scripts fuzi did NOT run: esbuild"
            ]
        );
    }

    #[test]
    fn skipped_scripts_and_clean_lines_escape_names() {
        let scripts = vec![EVIL.to_string(), "esbuild".to_string()];
        for verbose in [false, true] {
            assert_inert(&skipped_scripts_line(&scripts, verbose).expect("some line"));
        }
        let many: Vec<String> = (0..=SKIPPED_SCRIPT_PREVIEW)
            .map(|_| EVIL.to_string())
            .collect();
        assert_inert(&skipped_scripts_line(&many, false).expect("some line"));

        let report = CleanReport {
            dry_run: false,
            removed: vec![
                format!(".fuzi-old-{EVIL}"),
                ".fuzi-installing-ab12".to_string(),
            ],
            skipped: vec![SkippedArtifact {
                name: format!(".fuzi-old-{EVIL}"),
                restore_command: format!(
                    "[ -e node_modules ] || mv -- '.fuzi-old-{EVIL}' node_modules"
                ),
            }],
            node_modules_obstruction: None,
        };
        for line in clean_warning_lines(&report) {
            assert_inert(&line);
        }
        let line = clean_line(&report);
        assert_inert(&line);
        assert!(line.ends_with(", .fuzi-installing-ab12"), "{line}");
        assert_eq!(
            clean_line(&CleanReport::default()),
            "fuzi clean: nothing to sweep"
        );
    }

    #[test]
    fn json_output_is_terminal_safe_and_parses_back_to_the_raw_values() {
        // The payload is raw (an agent gets the real key); the bytes printed
        // hold nothing a terminal acts on, and decode to the same document.
        let err = FuziError::Refused {
            refusals: vec![Refusal {
                path: InstallPath::new(format!("node_modules/{EVIL}")),
                reason: RefuseReason::InvalidNameCharacter(format!("node_modules/{EVIL}")),
            }],
        };
        let value = error_json(&err);
        assert_eq!(
            value["error"]["refusals"][0]["path"],
            json!(format!("node_modules/{EVIL}")),
            "the structured payload is raw"
        );
        let printed = to_pretty(&value);
        assert!(
            !printed.chars().any(|c| c != '\n' && needs_escape(c)),
            "{printed:?}"
        );
        assert!(printed.contains("\\u001b[2J\\nforged\\u202e\\u009b31m\\u007f"));
        let parsed: Value = serde_json::from_str(&printed).expect("still JSON");
        assert_eq!(parsed, value);
        // Astral characters take a surrogate pair; ordinary text is untouched.
        assert_eq!(terminal_safe_json("\"\u{e0001}\""), "\"\\udb40\\udc01\"");
        let plain = "{\n  \"message\": \"café — ok · 日本\"\n}";
        assert_eq!(terminal_safe_json(plain), plain);
    }

    #[test]
    fn error_message_is_escaped_for_the_terminal() {
        // What `render_error` prints after `error: ` is the `Display` body.
        let err = FuziError::LinkTarget {
            problems: vec![LinkTargetProblem {
                package: "node_modules/lib".to_string(),
                detail: format!(
                    "link target ../lib is package `{EVIL}`, but the lockfile names `lib`"
                ),
            }],
        };
        let shown = err.to_string();
        assert_eq!(shown.lines().count(), 2, "{shown:?}");
        assert!(
            !shown.chars().any(|c| c != '\n' && needs_escape(c)),
            "{shown:?}"
        );
    }

    // --- parse_omit ----------------------------------------------------------

    #[test]
    fn parse_omit_accepts_the_three_classes() {
        let omit = parse_omit(&[
            "dev".to_string(),
            "optional".to_string(),
            "peer".to_string(),
        ])
        .expect("all three are valid");
        assert_eq!(omit, vec![Omit::Dev, Omit::Optional, Omit::Peer]);
    }

    #[test]
    fn parse_omit_rejects_unknown_value_as_usage() {
        let err = parse_omit(&["prod".to_string()]).expect_err("`prod` is not a valid omit class");
        assert!(matches!(err, FuziError::Usage { .. }));
        // The sysexits taxonomy, not argh's exit — EX_USAGE.
        assert_eq!(err.kind(), "usage");
        assert_eq!(err.exit_code(), 64);
    }

    // --- skipped_scripts_line: the cap / `+N more` arithmetic ----------------

    fn names(n: usize) -> Vec<String> {
        (0..n).map(|i| format!("pkg{i}")).collect()
    }

    /// The full-list rendering (all names, no truncation marker).
    fn assert_full_list(line: &str, scripts: &[String]) {
        assert_eq!(
            line,
            format!(
                "  {} package(s) with install scripts fuzi did NOT run: {}",
                scripts.len(),
                scripts.join(", ")
            )
        );
        assert!(!line.contains("more"), "full list carries no `+N more`");
        for name in scripts {
            assert!(line.contains(name.as_str()), "every name is present");
        }
    }

    #[test]
    fn skipped_scripts_line_empty_is_none() {
        assert_eq!(skipped_scripts_line(&[], false), None);
        assert_eq!(skipped_scripts_line(&[], true), None);
    }

    #[test]
    fn skipped_scripts_line_at_or_under_cap_is_full_list() {
        // A handful well under the cap.
        let few = names(2);
        assert_full_list(&skipped_scripts_line(&few, false).expect("some line"), &few);
        // Exactly at the cap — the `<=` boundary where an off-by-one would truncate.
        let at_cap = names(SKIPPED_SCRIPT_PREVIEW);
        assert_full_list(
            &skipped_scripts_line(&at_cap, false).expect("some line"),
            &at_cap,
        );
    }

    #[test]
    fn skipped_scripts_line_over_cap_truncates_with_more() {
        let scripts = names(SKIPPED_SCRIPT_PREVIEW + 3);
        let line = skipped_scripts_line(&scripts, false).expect("some line");
        let shown = &scripts[..SKIPPED_SCRIPT_PREVIEW];
        assert_eq!(
            line,
            format!(
                "  {} package(s) with install scripts fuzi did NOT run: {}, … (+{} more, --verbose)",
                scripts.len(),
                shown.join(", "),
                3
            )
        );
        // The first cap names show; the ones past the cap do not.
        assert!(line.contains("pkg0"));
        assert!(!line.contains(scripts[SKIPPED_SCRIPT_PREVIEW].as_str()));
    }

    #[test]
    fn skipped_scripts_line_verbose_shows_full_list_over_cap() {
        let scripts = names(SKIPPED_SCRIPT_PREVIEW + 3);
        // Verbose uncaps: the full list even though len > cap.
        assert_full_list(
            &skipped_scripts_line(&scripts, true).expect("some line"),
            &scripts,
        );
    }
}
