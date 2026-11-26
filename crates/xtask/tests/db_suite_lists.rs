//! The hand-kept lists of database suites agree with the tree.
//!
//! Every DB test opens its database through `fuz_testing::fresh_test_db` (or
//! `TestingDbOptions::open` over it), on pglet in plain `cargo test` and on
//! PostgreSQL under `FUZ_TEST_POSTGRES_URL`.
//! The PostgreSQL leg runs only where a list names it: the `db-tests` job in
//! `.github/workflows/check.yml` (its env block and its `cargo test -p …`
//! line) and the recipe in `docs/testing.md` § Postgres suites (its `export`
//! line and its `cargo test -p …` line). A crate missing from a `-p` list
//! leaves the job green while its tests never meet PostgreSQL, and its
//! Postgres-only tests never run at all, so this test holds both lists to the
//! tree, in both directions.
//!
//! **Detection.** A workspace member has database tests when one of its `.rs`
//! files names `fresh_test_db` as a whole word outside a comment — a call, or
//! the `use` that imports it, so an `as` alias still counts — or carries one
//! of the two markers below, or when its `Cargo.toml` lists `fuz_testing`
//! under `[dev-dependencies]`, which catches an opener that never names
//! `fresh_test_db` (`TestingDbOptions::open`, a suite's own wrapper).
//! Each must be in both `-p` lists, and nothing else may be.
//!
//! **Markers.** In such a crate every `#[ignore` attribute (and every
//! `#[cfg_attr(…)]` that holds an `ignore`) is one of the two
//! the PostgreSQL leg is for: `#[ignore = "postgres-only: <why>"]` (a test of
//! what only PostgreSQL has) or `#[ignore = "pglet: <feature>"]` (a test
//! waiting on a pglet feature) — the leg runs with `--include-ignored`, so any
//! other ignored test there would run in it unasked. A crate carrying a marker
//! must name the Postgres engine (`TestEngine::Postgres` or
//! `.postgres_only()`), and a crate naming it must carry a marker, or its
//! Postgres-only test would either run on pglet or never be ignored.
//!
//! Both lists must also run what they name: the `cargo test` command takes
//! only `--locked` and `-p` flags before `--` and exactly `--include-ignored`
//! after it, holds no token the shell would read as a comment or operator, and
//! is the test step's whole `run:`; neither the job nor its test step may carry
//! `if:`, `continue-on-error:`, or `shell:`. Each list sets
//! `FUZ_TEST_POSTGRES_URL` and no other `*_TEST_URL`.
//!
//! The YAML and Markdown are read as text by small readers that skip blank and
//! comment lines and refuse any other shape they don't expect, so a reshaped
//! file fails here rather than reading as an empty list. Finding no suites at
//! all fails too.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

/// The one variable that moves the DB tests onto PostgreSQL.
const POSTGRES_URL_VARIABLE: &str = "FUZ_TEST_POSTGRES_URL";

/// The suffix a retired per-crate connection variable carries; neither list
/// may set one.
const TEST_URL_SUFFIX: &str = "_TEST_URL";

/// The function whose name, as a whole word, marks a crate as having database
/// tests.
const FRESH_DB_FN: &str = "fresh_test_db";

/// The two `#[ignore` reasons a database crate may carry.
const ENGINE_MARKERS: [&str; 2] = ["#[ignore = \"postgres-only: ", "#[ignore = \"pglet: "];

/// The spellings that declare a test's database Postgres-only.
const POSTGRES_ENGINE_SITES: [&str; 2] = ["TestEngine::Postgres", ".postgres_only()"];

/// The module that defines the engines, whose own code names them; not scanned
/// for engine sites.
const ENGINE_DEFINITION: &str = "crates/fuz_testing/src/fresh_db.rs";

/// This file, relative to the workspace root.
const THIS_FILE: &str = "crates/xtask/tests/db_suite_lists.rs";

fn workspace_root() -> Result<PathBuf, String> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .map_err(|e| format!("resolve the workspace root: {e}"))
}

fn read(path: &Path) -> Result<String, String> {
    fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))
}

//
// The tree
//

/// Each workspace member's package name and directory, from the root
/// `Cargo.toml`'s one-line `members = [...]`.
fn workspace_members(root: &Path) -> Result<Vec<(String, PathBuf)>, String> {
    let manifest = read(&root.join("Cargo.toml"))?;
    let lines: Vec<&str> = manifest
        .lines()
        .filter(|line| line.starts_with("members = ["))
        .collect();
    let [line] = lines[..] else {
        return Err(format!(
            "Cargo.toml: expected one `members = [...]` line, found {}",
            lines.len()
        ));
    };
    let list = line
        .strip_prefix("members = [")
        .and_then(|rest| rest.strip_suffix(']'))
        .ok_or_else(|| format!("Cargo.toml: `members` is not a one-line list: {line}"))?;
    let mut members = Vec::new();
    for entry in list.split(',') {
        let entry = entry.trim();
        let dir = entry
            .strip_prefix('"')
            .and_then(|rest| rest.strip_suffix('"'))
            .ok_or_else(|| format!("Cargo.toml: a member that is not a string: {entry}"))?;
        let dir = root.join(dir);
        members.push((package_name(&dir)?, dir));
    }
    if members.is_empty() {
        return Err("Cargo.toml: `members` is empty".to_string());
    }
    Ok(members)
}

/// The `name = "…"` of a member's `[package]` table.
fn package_name(dir: &Path) -> Result<String, String> {
    let path = dir.join("Cargo.toml");
    let manifest = read(&path)?;
    let mut in_package = false;
    for line in manifest.lines() {
        if line.starts_with('[') {
            in_package = line == "[package]";
        } else if in_package && let Some(value) = line.strip_prefix("name = ") {
            return value
                .strip_prefix('"')
                .and_then(|rest| rest.strip_suffix('"'))
                .map(str::to_string)
                .ok_or_else(|| format!("{}: unquoted package name: {line}", path.display()));
        }
    }
    Err(format!("{}: no `name` in `[package]`", path.display()))
}

/// Whether a member's `manifest` lists `fuz_testing` under
/// `[dev-dependencies]`, read line by line as [`package_name`] reads
/// `[package]`.
fn has_fuz_testing_dev_dependency(manifest: &str) -> bool {
    let mut in_dev_dependencies = false;
    for line in manifest.lines() {
        if line.starts_with('[') {
            in_dev_dependencies = line == "[dev-dependencies]";
        } else if in_dev_dependencies
            && (line.starts_with("fuz_testing ")
                || line.starts_with("fuz_testing.")
                || line.starts_with("fuz_testing="))
        {
            return true;
        }
    }
    false
}

/// Every `.rs` file under `dir`, skipping build output.
fn rust_files(dir: &Path, found: &mut Vec<PathBuf>) -> Result<(), String> {
    let entries = fs::read_dir(dir).map_err(|e| format!("read {}: {e}", dir.display()))?;
    for entry in entries {
        let path = entry
            .map_err(|e| format!("read {}: {e}", dir.display()))?
            .path();
        if path.is_dir() {
            if path.file_name().is_some_and(|name| name == "target") {
                continue;
            }
            rust_files(&path, found)?;
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            found.push(path);
        }
    }
    Ok(())
}

/// What the tree says about one crate's database tests.
#[derive(Debug, Default)]
struct Suite {
    /// Whether any of its files names `fresh_test_db` as a whole word.
    opens_databases: bool,
    /// Each `#[ignore` attribute that is not an [`ENGINE_MARKERS`] one, with
    /// its file.
    other_ignores: Vec<String>,
    /// Whether any of its files carries an [`ENGINE_MARKERS`] attribute.
    has_marker: bool,
    /// Whether any of its files names a [`POSTGRES_ENGINE_SITES`] spelling.
    names_postgres_engine: bool,
}

/// Whether `code` is a `#[cfg_attr(…)]` that can ignore a test — one that
/// would dodge the marker rule as `#[ignore` alone can't.
fn is_cfg_attr_ignore(code: &str) -> bool {
    code.starts_with("#[cfg_attr(") && names_word(code, "ignore")
}

/// Whether `line` holds `word` with no identifier character on either side.
fn names_word(line: &str, word: &str) -> bool {
    let is_ident = |c: char| c.is_ascii_alphanumeric() || c == '_';
    line.match_indices(word).any(|(at, _)| {
        !line[..at].ends_with(is_ident) && !line[at + word.len()..].starts_with(is_ident)
    })
}

/// Every workspace member with database tests, by package name.
fn suites_in_tree(root: &Path) -> Result<BTreeMap<String, Suite>, String> {
    let this_file = root.join(THIS_FILE);
    let engine_definition = root.join(ENGINE_DEFINITION);
    let mut suites = BTreeMap::new();
    for (name, dir) in workspace_members(root)? {
        let mut files = Vec::new();
        rust_files(&dir, &mut files)?;
        let dev_depends_on_fuz_testing =
            has_fuz_testing_dev_dependency(&read(&dir.join("Cargo.toml"))?);
        let mut suite = Suite::default();
        for file in files.iter().filter(|file| **file != this_file) {
            for line in read(file)?.lines() {
                let code = line.trim_start();
                if code.starts_with("//") {
                    continue;
                }
                suite.opens_databases |= names_word(code, FRESH_DB_FN);
                if code.starts_with("#[ignore") {
                    if ENGINE_MARKERS.iter().any(|marker| code.starts_with(marker)) {
                        suite.has_marker = true;
                    } else {
                        suite
                            .other_ignores
                            .push(format!("{}: {code}", file.display()));
                    }
                } else if is_cfg_attr_ignore(code) {
                    suite
                        .other_ignores
                        .push(format!("{}: {code}", file.display()));
                }
                if *file != engine_definition {
                    suite.names_postgres_engine |=
                        POSTGRES_ENGINE_SITES.iter().any(|site| code.contains(site));
                }
            }
        }
        if suite.opens_databases || suite.has_marker || dev_depends_on_fuz_testing {
            suites.insert(name, suite);
        }
    }
    Ok(suites)
}

/// Every way the tree's own suites break the marker rules.
fn tree_problems(tree: &BTreeMap<String, Suite>) -> Vec<String> {
    let mut problems = Vec::new();
    for (crate_name, suite) in tree {
        for ignore in &suite.other_ignores {
            problems.push(format!(
                "crate `{crate_name}` has database tests, so its ignored tests run in the \
                 PostgreSQL leg; an `#[ignore` there must be `postgres-only: …` or `pglet: …`: \
                 {ignore}"
            ));
        }
        if suite.has_marker && !suite.names_postgres_engine {
            problems.push(format!(
                "crate `{crate_name}` marks a test Postgres-only but never opens a database with \
                 `TestEngine::Postgres`: the test would run on pglet"
            ));
        }
        if suite.names_postgres_engine && !suite.has_marker {
            problems.push(format!(
                "crate `{crate_name}` opens a Postgres-only database but marks no test \
                 `postgres-only: …` or `pglet: …`: plain `cargo test` would run it and fail"
            ));
        }
    }
    problems
}

//
// The lists
//

/// One hand-kept list of the suites: what it runs and the variables it sets.
#[derive(Debug)]
struct SuiteList {
    /// Which list, for messages.
    name: &'static str,
    /// The `-p` crates of its `cargo test` line.
    crates: BTreeSet<String>,
    /// The connection variables it sets.
    variables: BTreeSet<String>,
}

/// The libtest arguments the PostgreSQL leg takes after `--`: exactly these. A
/// filter, `--exact`, or `--skip` would leave some or all of the tests unrun,
/// and without `--include-ignored` the Postgres-only ones never run.
const LIBTEST_ARGS: [&str; 1] = ["--include-ignored"];

/// The characters that make a shell token more than a word: a comment, a
/// pipe or `||`, a background or `&&`, a separator, a redirect, an expansion.
const SHELL_METACHARACTERS: [char; 7] = ['|', '&', ';', '<', '>', '$', '`'];

/// The crates of a `cargo test` command's `tokens` (everything after
/// `cargo test`), which must take the form `[--locked] -p <crate>… --
/// --include-ignored`. Any other token is refused: a flag such as `--no-run`
/// before `--` or a filter after it leaves tests unrun, and a token starting
/// with `#` or holding a shell metacharacter (`|| true`, `; exit 0`) comments
/// out or masks the run.
fn cargo_test_crates<'a>(
    tokens: impl Iterator<Item = &'a str>,
    context: &str,
) -> Result<BTreeSet<String>, String> {
    let tokens: Vec<&str> = tokens.collect();
    if let Some(token) = tokens
        .iter()
        .find(|token| token.starts_with('#') || token.contains(SHELL_METACHARACTERS))
    {
        return Err(format!(
            "{context}: the `cargo test` command holds `{token}`, which the shell would read \
             as a comment or an operator"
        ));
    }
    let mut crates = BTreeSet::new();
    let mut tokens = tokens.into_iter();
    let mut separated = false;
    while let Some(token) = tokens.next() {
        match token {
            "--locked" => {}
            "-p" => {
                let name = tokens
                    .next()
                    .ok_or_else(|| format!("{context}: `-p` with no crate"))?;
                if !crates.insert(name.to_string()) {
                    return Err(format!("{context}: `-p {name}` twice"));
                }
            }
            "--" => {
                separated = true;
                break;
            }
            other => {
                return Err(format!(
                    "{context}: unexpected `{other}` before `--` in the `cargo test` command"
                ));
            }
        }
    }
    if !separated {
        return Err(format!(
            "{context}: the `cargo test` command has no `--`, so no `--include-ignored`: the \
             Postgres-only tests would never run"
        ));
    }
    let mut libtest = BTreeSet::new();
    for arg in tokens {
        if !LIBTEST_ARGS.contains(&arg) {
            return Err(format!(
                "{context}: unexpected `{arg}` after `--` in the `cargo test` command \
                 (only {LIBTEST_ARGS:?} belong there)"
            ));
        }
        if !libtest.insert(arg) {
            return Err(format!("{context}: `{arg}` twice after `--`"));
        }
    }
    for required in LIBTEST_ARGS {
        if !libtest.contains(required) {
            return Err(format!(
                "{context}: the `cargo test` command lacks `{required}` after `--`"
            ));
        }
    }
    if crates.is_empty() {
        return Err(format!("{context}: no `-p` crates"));
    }
    Ok(crates)
}

/// Whether `name` is a connection variable a list must account for: the one
/// it must set, or a retired per-crate one it must not.
fn is_connection_variable(name: &str) -> bool {
    name == POSTGRES_URL_VARIABLE || name.ends_with(TEST_URL_SUFFIX)
}

/// The workflow keys that can switch the suite run off (`if`), turn its
/// failure green (`continue-on-error`), or change what runs the command
/// (`shell`), refused on the job and its test step.
const CONTROL_KEYS: [&str; 3] = ["if", "continue-on-error", "shell"];

/// Whether `line` is blank or a whole-line YAML / shell comment.
fn is_blank_or_comment(line: &str) -> bool {
    let trimmed = line.trim();
    trimmed.is_empty() || trimmed.starts_with('#')
}

/// The indentation of `line`, in spaces.
fn indent(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

/// The `db-tests` job of `.github/workflows/check.yml`.
fn ci_list(root: &Path) -> Result<SuiteList, String> {
    const FILE: &str = ".github/workflows/check.yml";
    let text = read(&root.join(FILE))?;
    let lines: Vec<&str> = text.lines().collect();
    let jobs = lines
        .iter()
        .position(|line| *line == "jobs:")
        .ok_or_else(|| format!("{FILE}: no top-level `jobs:`"))?;
    let start = lines[jobs..]
        .iter()
        .position(|line| *line == "  db-tests:")
        .map(|offset| jobs + offset + 1)
        .ok_or_else(|| format!("{FILE}: no `db-tests` job under `jobs:`"))?;
    // The job runs until the next key at job indentation or less.
    let end = lines[start..]
        .iter()
        .position(|line| !is_blank_or_comment(line) && indent(line) <= 2)
        .map_or(lines.len(), |offset| start + offset);
    let job = &lines[start..end];

    // A condition could switch the job off with every list intact, and
    // `continue-on-error` would hide its failures.
    if let Some(line) = job.iter().find(|line| {
        indent(line) == 4
            && CONTROL_KEYS
                .iter()
                .any(|key| line.trim_start().starts_with(&format!("{key}:")))
    }) {
        return Err(format!(
            "{FILE}: the `db-tests` job carries `{}`",
            line.trim()
        ));
    }

    // The job-level `env:` block: `NAME: value` entries at six spaces.
    let env_lines: Vec<usize> = job
        .iter()
        .enumerate()
        .filter(|(_, line)| **line == "    env:")
        .map(|(i, _)| i)
        .collect();
    let [env] = env_lines[..] else {
        return Err(format!(
            "{FILE}: expected one job-level `env:` in `db-tests`, found {}",
            env_lines.len()
        ));
    };
    let mut variables = BTreeSet::new();
    for line in &job[env + 1..] {
        if is_blank_or_comment(line) {
            continue;
        }
        if indent(line) < 6 {
            break;
        }
        if indent(line) > 6 {
            return Err(format!(
                "{FILE}: unexpected nesting in `db-tests` env: {line}"
            ));
        }
        let (name, value) = line
            .trim_start()
            .split_once(": ")
            .ok_or_else(|| format!("{FILE}: not a `NAME: value` env entry: {line}"))?;
        if is_connection_variable(name) {
            if !value.starts_with("postgres://") {
                return Err(format!(
                    "{FILE}: `{name}` is not a `postgres://` URL: {value}"
                ));
            }
            if !variables.insert(name.to_string()) {
                return Err(format!("{FILE}: `{name}` set twice in `db-tests` env"));
            }
        }
    }

    let crates = ci_cargo_test_crates(job, FILE)?;
    Ok(SuiteList {
        name: "the `db-tests` job in .github/workflows/check.yml",
        crates,
        variables,
    })
}

/// The `-p` crates of the one step in `job` whose `run:` is a `cargo test`,
/// refusing a condition on that step and a `run:` shape this reader does not
/// know.
///
/// Steps are list items at six spaces, their keys at eight. A folded
/// `run: >-` block's lines are joined with spaces, so a `-p` list may be folded
/// over several lines; a blank or `#` line inside it is refused, since there it
/// changes the command (a line break, or a shell comment that swallows the
/// rest). In a literal `run: |` block each line is its own command, and a
/// block that runs `cargo test` must hold that command alone (comment and
/// blank lines aside). Either way the `run:` is the one `cargo test` command
/// and nothing else.
fn ci_cargo_test_crates(job: &[&str], file: &str) -> Result<BTreeSet<String>, String> {
    // Each step: the index of its `- ` line, through the line before the next.
    let starts: Vec<usize> = job
        .iter()
        .enumerate()
        .filter(|(_, line)| indent(line) == 6 && line.trim_start().starts_with("- "))
        .map(|(i, _)| i)
        .collect();
    let mut found = Vec::new();
    for (n, &step_start) in starts.iter().enumerate() {
        let step_end = starts.get(n + 1).copied().unwrap_or(job.len());
        let step = &job[step_start..step_end];
        // A step's keys: the first after `- `, then each at eight spaces.
        let key_of = |line: &str| -> Option<String> {
            let trimmed = line.trim_start();
            let key_text = if indent(line) == 6 {
                trimmed.strip_prefix("- ")?
            } else if indent(line) == 8 {
                trimmed
            } else {
                return None;
            };
            key_text.split_once(':').map(|(key, _)| key.to_string())
        };
        let mut run = None;
        for (i, line) in step.iter().enumerate() {
            if key_of(line).as_deref() != Some("run") {
                continue;
            }
            let value = line
                .split_once("run:")
                .map_or("", |(_, value)| value)
                .trim();
            let text = if [">-", ">", "|", "|-"].contains(&value) {
                let mut body: Vec<&str> = step[i + 1..]
                    .iter()
                    .take_while(|inner| indent(inner) > 8 || inner.trim().is_empty())
                    .map(|inner| inner.trim())
                    .collect();
                while body.last().is_some_and(|last| last.is_empty()) {
                    body.pop();
                }
                if value.starts_with('>') {
                    // Folded: the lines are one command.
                    if let Some(bad) = body.iter().find(|inner| is_blank_or_comment(inner)) {
                        return Err(format!(
                            "{file}: a blank or `#` line inside a folded `run: {value}` block \
                             of `db-tests` changes the command; refusing it: {bad:?}"
                        ));
                    }
                    body.join(" ")
                } else {
                    // Literal: one command per line. A block that runs
                    // `cargo test` must run it alone: a `set +e` before it or
                    // an `exit 0` after it would hide its failure.
                    let commands: Vec<&str> = body
                        .into_iter()
                        .filter(|inner| !is_blank_or_comment(inner))
                        .collect();
                    if !commands
                        .iter()
                        .any(|command| command.contains("cargo test"))
                    {
                        String::new()
                    } else if let [command] = commands[..]
                        && !command.ends_with('\\')
                    {
                        command.to_string()
                    } else {
                        return Err(format!(
                            "{file}: the `db-tests` step that runs `cargo test` runs more than \
                             that one command: {commands:?}"
                        ));
                    }
                }
            } else {
                value.to_string()
            };
            run = Some(text);
        }
        let Some(run) = run else { continue };
        let Some(args) = run.strip_prefix("cargo test ") else {
            if run.contains("cargo test") {
                return Err(format!(
                    "{file}: a `db-tests` step runs `cargo test` but not as its whole `run:`: {run}"
                ));
            }
            continue;
        };
        if let Some(line) = step
            .iter()
            .find(|line| key_of(line).is_some_and(|key| CONTROL_KEYS.contains(&key.as_str())))
        {
            return Err(format!(
                "{file}: the `db-tests` test step carries `{}`",
                line.trim()
            ));
        }
        found.push(cargo_test_crates(args.split_whitespace(), file)?);
    }
    let mut found = found.into_iter();
    match (found.next(), found.next()) {
        (Some(crates), None) => Ok(crates),
        (None, _) => Err(format!("{file}: no `cargo test` step in `db-tests`")),
        (Some(_), Some(_)) => Err(format!(
            "{file}: more than one `cargo test` step in `db-tests`"
        )),
    }
}

/// The recipe in `docs/testing.md` § Postgres suites: the section's first
/// `bash` block. Blank lines and `#` comment lines are skipped, and a `#`
/// comment after a command is dropped; any other line is refused.
fn docs_list(root: &Path) -> Result<SuiteList, String> {
    const FILE: &str = "docs/testing.md";
    let text = read(&root.join(FILE))?;
    let lines: Vec<&str> = text.lines().collect();
    let section = lines
        .iter()
        .position(|line| *line == "## Postgres suites")
        .ok_or_else(|| format!("{FILE}: no `## Postgres suites` section"))?;
    let open = lines[section..]
        .iter()
        .position(|line| *line == "```bash")
        .map(|offset| section + offset + 1)
        .ok_or_else(|| format!("{FILE}: no ```bash block in § Postgres suites"))?;
    if lines[section + 1..open]
        .iter()
        .any(|line| line.starts_with("## "))
    {
        return Err(format!(
            "{FILE}: § Postgres suites has no ```bash block of its own"
        ));
    }
    let close = lines[open..]
        .iter()
        .position(|line| *line == "```")
        .map(|offset| open + offset)
        .ok_or_else(|| format!("{FILE}: unclosed ```bash block in § Postgres suites"))?;
    let block = &lines[open..close];

    let mut variables = BTreeSet::new();
    let mut crates = None;
    for line in block.iter().filter(|line| !is_blank_or_comment(line)) {
        // A trailing shell comment (` # once`) is not part of the command.
        let command = line
            .split_once(" #")
            .map_or(*line, |(command, _)| command)
            .trim_end();
        if command.ends_with('\\') {
            return Err(format!(
                "{FILE}: a continued line in the recipe, which this reader does not join: {line}"
            ));
        }
        if let Some(export) = command.strip_prefix("export ") {
            let (name, value) = export
                .split_once('=')
                .ok_or_else(|| format!("{FILE}: not an `export NAME=value`: {line}"))?;
            if !is_connection_variable(name) {
                return Err(format!(
                    "{FILE}: an export that is no connection variable: {line}"
                ));
            }
            if !value.starts_with("postgres://") {
                return Err(format!(
                    "{FILE}: `{name}` is not a `postgres://` URL: {value}"
                ));
            }
            if !variables.insert(name.to_string()) {
                return Err(format!("{FILE}: `{name}` exported twice"));
            }
        } else if let Some(rest) = command.strip_prefix("cargo test ") {
            if crates
                .replace(cargo_test_crates(rest.split_whitespace(), FILE)?)
                .is_some()
            {
                return Err(format!("{FILE}: two `cargo test` lines"));
            }
        } else {
            return Err(format!("{FILE}: unexpected line in the recipe: {line}"));
        }
    }
    Ok(SuiteList {
        name: "the recipe in docs/testing.md § Postgres suites",
        crates: crates.ok_or_else(|| format!("{FILE}: no `cargo test` line in the recipe"))?,
        variables,
    })
}

//
// The comparison
//

/// Every way `tree` and `list` disagree, one message each.
fn disagreements(tree: &BTreeMap<String, Suite>, list: &SuiteList) -> Vec<String> {
    let mut problems = Vec::new();
    let name = list.name;
    for crate_name in tree.keys() {
        if !list.crates.contains(crate_name) {
            problems.push(format!(
                "crate `{crate_name}` has database tests but is missing from the `-p` list of \
                 {name}"
            ));
        }
    }
    for crate_name in &list.crates {
        if !tree.contains_key(crate_name) {
            problems.push(format!(
                "{name} lists crate `{crate_name}` with `-p`, but it has no database tests"
            ));
        }
    }
    if !list.variables.contains(POSTGRES_URL_VARIABLE) {
        problems.push(format!("{name} does not set `{POSTGRES_URL_VARIABLE}`"));
    }
    for variable in &list.variables {
        if variable != POSTGRES_URL_VARIABLE {
            problems.push(format!(
                "{name} sets `{variable}`, which no test reads: `{POSTGRES_URL_VARIABLE}` is the \
                 one connection variable"
            ));
        }
    }
    problems
}

#[test]
fn the_postgres_suite_lists_match_the_tree() {
    let root = workspace_root().unwrap_or_else(|e| panic!("{e}"));
    let tree = suites_in_tree(&root).unwrap_or_else(|e| panic!("{e}"));
    assert!(
        !tree.is_empty(),
        "found no database tests in the workspace: the detection rule in this file's doc no \
         longer matches how the suites are written"
    );
    let mut problems = tree_problems(&tree);
    for list in [ci_list(&root), docs_list(&root)] {
        let list = list.unwrap_or_else(|e| panic!("{e}"));
        problems.extend(disagreements(&tree, &list));
    }
    assert!(
        problems.is_empty(),
        "the database suite lists disagree with the tree:\n- {}",
        problems.join("\n- ")
    );
}

#[test]
fn fresh_test_db_is_found_as_a_whole_word() {
    // a call, and the import an `as` alias hides the call behind
    assert!(names_word(
        "let pool = fresh_test_db(DB).await;",
        FRESH_DB_FN
    ));
    assert!(names_word(
        "use fuz_testing::{TestEngine, fresh_test_db as open_db};",
        FRESH_DB_FN
    ));
    assert!(names_word("use fuz_testing::fresh_test_db;", FRESH_DB_FN));
    // a longer identifier is another name
    assert!(!names_word("fn my_fresh_test_db_helper() {}", FRESH_DB_FN));
    assert!(!names_word("let x = fresh_test_dbs;", FRESH_DB_FN));
}

/// The reviewer's re-export probe: `fuz_testing` re-exports the opener under
/// another name and a crate's tests call only that name, so no file of the
/// crate names `fresh_test_db`; its `[dev-dependencies]` edge still counts it.
#[test]
fn a_crate_reaching_the_opener_through_a_re_export_is_found_by_its_manifest() {
    assert!(!names_word("let pool = open_db(DB).await;", FRESH_DB_FN));
    assert!(!names_word(
        "use fuz_testing::{TestEngine, open_db};",
        FRESH_DB_FN
    ));
    let manifest = "[package]\nname = \"fuz_http\"\n\n[dependencies]\nfuz_db.workspace = true\n\n\
                    [dev-dependencies]\ntokio = { workspace = true }\nfuz_testing.workspace = true\n";
    assert!(has_fuz_testing_dev_dependency(manifest));
    // a normal edge, as a `testing_*` binary has, is not a test suite's
    let normal =
        "[package]\nname = \"testing_x\"\n\n[dependencies]\nfuz_testing.workspace = true\n";
    assert!(!has_fuz_testing_dev_dependency(normal));
}

#[test]
fn a_cfg_attr_ignore_counts_as_an_ignore() {
    assert!(is_cfg_attr_ignore(
        "#[cfg_attr(not(feature = \"pg\"), ignore = \"needs pg\")]"
    ));
    assert!(is_cfg_attr_ignore("#[cfg_attr(ci, ignore)]"));
    assert!(!is_cfg_attr_ignore("#[cfg_attr(test, derive(Debug))]"));
}

#[test]
fn the_libtest_args_are_exactly_include_ignored() {
    let crates = |args: &str| cargo_test_crates(args.split_whitespace(), "probe");
    assert!(crates("--locked -p a -p b -- --include-ignored").is_ok());
    assert!(crates("-p a -- --ignored").is_err());
    assert!(crates("-p a -- --include-ignored --test-threads=1").is_err());
    assert!(crates("-p a").is_err());
    assert!(crates("-p a -- --include-ignored || true").is_err());
}
