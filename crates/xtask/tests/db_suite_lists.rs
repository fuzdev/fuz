//! The hand-kept lists of real-Postgres suites agree with the tree.
//!
//! The `#[ignore]` real-Postgres suites run only where a list names them: the
//! `db-tests` job in `.github/workflows/check.yml` (its env block, its
//! `CREATE DATABASE` step, and its `cargo test -p …` line) and the recipe in
//! `docs/testing.md` § Postgres suites (the `export` lines, the `createdb`
//! loop, and the `cargo test -p …` line). A crate missing from a `-p` list
//! leaves the job green while its suite never runs, so this test holds both
//! lists to the tree, in both directions.
//!
//! **Detection.** A workspace member has a real-Postgres suite when one of its
//! `.rs` files names a `*_TEST_URL` variable as a whole string literal outside
//! a comment — the `env_var: "…"` of a suite's `TestingDbOptions`, or the
//! `env::var("…")` of a suite that connects on its own (`fuz_db`'s
//! integration suite, `fuz_http`'s `ready`). Prose mentions (backticked in a
//! doc comment, inside an `#[ignore = "…"]` reason) are not literals of the
//! name and don't count. A crate found this way must also carry an
//! `#[ignore` attribute, or the suite would run under plain `cargo test`.
//! This file is not scanned: it names the variables it checks.
//!
//! A suite reads its own crate's variable (`fuz_auth` → `FUZ_AUTH_TEST_URL`),
//! except where [`SHARED_DATABASES`] says it shares another crate's: `fuz_http`
//! shares `fuz_db`'s, so it is in each `-p` list with no variable or database
//! of its own.
//!
//! Both lists must also run what they name: the `cargo test` command takes
//! only `--locked` and `-p` flags before `--` and exactly `--ignored` and
//! `--test-threads=1` after it, holds no token the shell would read as a
//! comment or operator, and is the test step's whole `run:`; neither the job
//! nor its test step may carry `if:`, `continue-on-error:`, or `shell:`.
//!
//! The YAML and Markdown are read as text by small readers that skip blank and
//! comment lines and refuse any other shape they don't expect, so a reshaped
//! file fails here rather than reading as an empty list. Finding no suites at
//! all fails too.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

/// The suffix of every real-Postgres suite's connection variable.
const TEST_URL_SUFFIX: &str = "_TEST_URL";

/// Crates whose suite reads another crate's database: `(crate, owner)`. Each
/// scopes its rows so the two can share it (`docs/testing.md` § Postgres
/// suites).
const SHARED_DATABASES: &[(&str, &str)] = &[("fuz_http", "fuz_db")];

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

/// The variable a crate's own suite reads: `fuz_auth` → `FUZ_AUTH_TEST_URL`.
fn own_variable(crate_name: &str) -> String {
    format!("{}{TEST_URL_SUFFIX}", crate_name.to_ascii_uppercase())
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

/// The `*_TEST_URL` names `line` holds as whole string literals (`"NAME"`).
fn test_url_literals(line: &str) -> Vec<String> {
    let needle = format!("{TEST_URL_SUFFIX}\"");
    let bytes = line.as_bytes();
    let mut names = Vec::new();
    let mut from = 0;
    while let Some(offset) = line[from..].find(&needle) {
        let end = from + offset + TEST_URL_SUFFIX.len();
        let mut start = from + offset;
        while start > 0
            && (bytes[start - 1].is_ascii_uppercase()
                || bytes[start - 1].is_ascii_digit()
                || bytes[start - 1] == b'_')
        {
            start -= 1;
        }
        if start > 0 && bytes[start - 1] == b'"' && start < from + offset {
            names.push(line[start..end].to_string());
        }
        from = end + 1;
    }
    names
}

/// What the tree says about one crate's real-Postgres suite.
#[derive(Debug, Default)]
struct Suite {
    /// The `*_TEST_URL` variables its code reads.
    variables: BTreeSet<String>,
    /// Whether any of its files carries an `#[ignore` attribute.
    has_ignore: bool,
}

/// Every workspace member with a real-Postgres suite, by package name.
fn suites_in_tree(root: &Path) -> Result<BTreeMap<String, Suite>, String> {
    let this_file = root.join(THIS_FILE);
    let mut suites = BTreeMap::new();
    for (name, dir) in workspace_members(root)? {
        let mut files = Vec::new();
        rust_files(&dir, &mut files)?;
        let mut suite = Suite::default();
        for file in files.iter().filter(|file| **file != this_file) {
            for line in read(file)?.lines() {
                let code = line.trim_start();
                if code.starts_with("//") {
                    continue;
                }
                suite.has_ignore |= code.starts_with("#[ignore");
                suite.variables.extend(test_url_literals(code));
            }
        }
        if !suite.variables.is_empty() {
            suites.insert(name, suite);
        }
    }
    Ok(suites)
}

//
// The lists
//

/// One hand-kept list of the suites: what it runs, the variables it sets, and
/// the databases it creates.
#[derive(Debug)]
struct SuiteList {
    /// Which list, for messages.
    name: &'static str,
    /// The `-p` crates of its `cargo test` line.
    crates: BTreeSet<String>,
    /// Each `*_TEST_URL` it sets, with the database its URL names.
    variables: BTreeMap<String, String>,
    /// The databases it creates.
    databases: BTreeSet<String>,
}

/// The database a `postgres://…/<db>` URL names.
fn database_of(url: &str) -> Result<String, String> {
    let db = url
        .strip_prefix("postgres://")
        .and_then(|rest| rest.rsplit_once('/'))
        .map(|(_, db)| db.split('?').next().unwrap_or(db))
        .filter(|db| !db.is_empty())
        .ok_or_else(|| format!("not a `postgres://…/<db>` URL: {url}"))?;
    Ok(db.to_string())
}

/// The libtest arguments a suite run takes after `--`: exactly these. A filter,
/// `--exact`, or `--skip` would leave some or all of the suites unrun.
const LIBTEST_ARGS: [&str; 2] = ["--ignored", "--test-threads=1"];

/// The characters that make a shell token more than a word: a comment, a
/// pipe or `||`, a background or `&&`, a separator, a redirect, an expansion.
const SHELL_METACHARACTERS: [char; 7] = ['|', '&', ';', '<', '>', '$', '`'];

/// The crates of a `cargo test` command's `tokens` (everything after
/// `cargo test`), which must take the form `[--locked] -p <crate>… --
/// --ignored --test-threads=1` (the last two in either order). Any other
/// token is refused: a flag such as `--no-run` before `--` or a filter after
/// it leaves suites unrun, and a token starting with `#` or holding a shell
/// metacharacter (`|| true`, `; exit 0`) comments out or masks the run.
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
            "{context}: the `cargo test` command has no `--`, so no `--ignored`: the suites \
             would never run"
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
    let mut variables = BTreeMap::new();
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
        if name.ends_with(TEST_URL_SUFFIX) {
            let db = database_of(value).map_err(|e| format!("{FILE}: `{name}`: {e}"))?;
            if variables.insert(name.to_string(), db).is_some() {
                return Err(format!("{FILE}: `{name}` set twice in `db-tests` env"));
            }
        }
    }
    if variables.is_empty() {
        return Err(format!("{FILE}: no `*{TEST_URL_SUFFIX}` in `db-tests` env"));
    }

    let mut databases = BTreeSet::new();
    for line in job.iter().filter(|line| !is_blank_or_comment(line)) {
        if let Some((_, rest)) = line.split_once("CREATE DATABASE ") {
            let db = rest
                .split_once(';')
                .map(|(db, _)| db.trim())
                .filter(|db| !db.is_empty() && !db.contains(' '))
                .ok_or_else(|| format!("{FILE}: unreadable `CREATE DATABASE`: {line}"))?;
            if !databases.insert(db.to_string()) {
                return Err(format!("{FILE}: `CREATE DATABASE {db}` twice"));
            }
        }
    }
    if databases.is_empty() {
        return Err(format!("{FILE}: no `CREATE DATABASE` in `db-tests`"));
    }

    let crates = ci_cargo_test_crates(job, FILE)?;
    Ok(SuiteList {
        name: "the `db-tests` job in .github/workflows/check.yml",
        crates,
        variables,
        databases,
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

    let mut variables = BTreeMap::new();
    let mut databases = None;
    let mut crates = None;
    for line in block.iter().filter(|line| !is_blank_or_comment(line)) {
        // A trailing shell comment (` # one-time`) is not part of the command.
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
            if !name.ends_with(TEST_URL_SUFFIX) {
                return Err(format!(
                    "{FILE}: an export that is no `*{TEST_URL_SUFFIX}`: {line}"
                ));
            }
            let db = database_of(value).map_err(|e| format!("{FILE}: `{name}`: {e}"))?;
            if variables.insert(name.to_string(), db).is_some() {
                return Err(format!("{FILE}: `{name}` exported twice"));
            }
        } else if let Some(rest) = command.strip_prefix("for db in ") {
            let names = rest
                .strip_suffix("; do createdb $db; done")
                .ok_or_else(|| format!("{FILE}: not a `createdb` loop: {line}"))?;
            let mut set = BTreeSet::new();
            for db in names.split_whitespace() {
                if !set.insert(db.to_string()) {
                    return Err(format!("{FILE}: `{db}` twice in the `createdb` loop"));
                }
            }
            if databases.replace(set).is_some() {
                return Err(format!("{FILE}: two `createdb` loops"));
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
    if variables.is_empty() {
        return Err(format!("{FILE}: no `export` lines in the recipe"));
    }
    Ok(SuiteList {
        name: "the recipe in docs/testing.md § Postgres suites",
        crates: crates.ok_or_else(|| format!("{FILE}: no `cargo test` line in the recipe"))?,
        variables,
        databases: databases.ok_or_else(|| format!("{FILE}: no `createdb` loop in the recipe"))?,
    })
}

//
// The comparison
//

/// Every way `tree` and `list` disagree, one message each.
fn disagreements(tree: &BTreeMap<String, Suite>, list: &SuiteList) -> Vec<String> {
    let mut problems = Vec::new();
    let name = list.name;
    let mut wanted_variables = BTreeSet::new();
    for (crate_name, suite) in tree {
        if !list.crates.contains(crate_name) {
            problems.push(format!(
                "crate `{crate_name}` has a real-Postgres suite but is missing from the `-p` \
                 list of {name}"
            ));
        }
        for variable in &suite.variables {
            wanted_variables.insert(variable.clone());
            match list.variables.get(variable) {
                None => problems.push(format!(
                    "crate `{crate_name}`'s suite reads `{variable}`, which {name} does not set"
                )),
                Some(db) if !list.databases.contains(db) => problems.push(format!(
                    "crate `{crate_name}`'s database `{db}` (`{variable}`) is not created by {name}"
                )),
                Some(_) => {}
            }
        }
    }
    for crate_name in &list.crates {
        if !tree.contains_key(crate_name) {
            problems.push(format!(
                "{name} lists crate `{crate_name}` with `-p`, but it has no real-Postgres suite"
            ));
        }
    }
    let mut wanted_databases = BTreeSet::new();
    for (variable, db) in &list.variables {
        wanted_databases.insert(db.clone());
        if !wanted_variables.contains(variable) {
            problems.push(format!(
                "{name} sets `{variable}`, which no crate's suite reads"
            ));
        }
    }
    for db in &list.databases {
        if !wanted_databases.contains(db) {
            problems.push(format!(
                "{name} creates database `{db}`, which no `*{TEST_URL_SUFFIX}` it sets names"
            ));
        }
    }
    problems
}

/// Every way the tree's own suites break the naming rule: a suite reads its
/// crate's variable, or the one [`SHARED_DATABASES`] names, and carries an
/// `#[ignore`.
fn tree_problems(tree: &BTreeMap<String, Suite>) -> Vec<String> {
    let mut problems = Vec::new();
    for (crate_name, suite) in tree {
        let owner = SHARED_DATABASES
            .iter()
            .find(|(sharer, _)| sharer == crate_name)
            .map_or(crate_name.as_str(), |(_, owner)| owner);
        let expected = BTreeSet::from([own_variable(owner)]);
        if suite.variables != expected {
            problems.push(format!(
                "crate `{crate_name}`'s suite reads {:?}, expected exactly {expected:?} \
                 (a suite sharing another crate's database is listed in SHARED_DATABASES)",
                suite.variables
            ));
        }
        if !suite.has_ignore {
            problems.push(format!(
                "crate `{crate_name}` reads {:?} but has no `#[ignore` test: the suite would \
                 run under plain `cargo test`",
                suite.variables
            ));
        }
    }
    for (sharer, owner) in SHARED_DATABASES {
        if !tree.contains_key(*sharer) || !tree.contains_key(*owner) {
            problems.push(format!(
                "SHARED_DATABASES names `{sharer}` sharing `{owner}`'s database, \
                 but the tree has no such pair of suites"
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
        "found no real-Postgres suite in the workspace: the detection rule in this \
         file's doc no longer matches how the suites are written"
    );
    let mut problems = tree_problems(&tree);
    for list in [ci_list(&root), docs_list(&root)] {
        let list = list.unwrap_or_else(|e| panic!("{e}"));
        problems.extend(disagreements(&tree, &list));
    }
    assert!(
        problems.is_empty(),
        "the real-Postgres suite lists disagree with the tree:\n- {}",
        problems.join("\n- ")
    );
}

#[test]
fn a_test_url_literal_is_found_only_whole_and_quoted() {
    let name = |stem: &str| format!("{stem}{TEST_URL_SUFFIX}");
    let a = name("FUZ_A");
    let b = name("FUZ_B");
    assert_eq!(
        test_url_literals(&format!("env_var: \"{a}\",")),
        std::slice::from_ref(&a)
    );
    assert_eq!(
        test_url_literals(&format!("env::var(\"{a}\").or(env::var(\"{b}\"))")),
        [a.clone(), b]
    );
    // Prose inside another string, or a bare suffix, is not a literal of a name.
    assert!(test_url_literals(&format!("#[ignore = \"needs Postgres ({a})\"]")).is_empty());
    assert!(test_url_literals(&format!("\"{TEST_URL_SUFFIX}\"")).is_empty());
    assert!(test_url_literals(&format!("\"x {a}\"")).is_empty());
}
