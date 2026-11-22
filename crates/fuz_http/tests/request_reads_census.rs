//! The request-reads census: a spine handler reads its query and its path
//! params only through `fuz_http`'s strict readers — [`read_query_pairs`]
//! over axum's `RawQuery`, and [`RouteParams`] — never a lenient extractor
//! that leaves an escape that doesn't decode as text or writes U+FFFD for it.
//! Twin of the query and path-param half of `fuz_app`'s
//! `request_reads_census.test.ts` (its header half has no Rust twin here).
//!
//! The enforcement is clippy's `disallowed-types` / `disallowed-methods` in the
//! workspace `clippy.toml` (`-D warnings` makes a hit an error). Clippy
//! resolves the paths, so an aliased or grouped import is caught; `RouteParams`
//! carries the one `#[expect]` in production code, over the axum `Path` it
//! wraps. This test holds that enforcement in place:
//!
//!  - **the config**: the root `clippy.toml` and every crate-level one (which
//!    replaces the root file rather than merging with it) list each lenient
//!    reader, spelled exactly — a misspelled path is only a clippy warning
//!    (`does not refer to a reachable type`) that `-D warnings` does not
//!    promote, and a dropped entry turns the census off with clippy green;
//!  - **resolution**: the positive controls below use each disallowed axum
//!    type under an `#[expect]`, so a path that stops resolving (an axum
//!    upgrade moving it) leaves the expectation unfulfilled — an error under
//!    `-D warnings`. The two disallowed methods live in `url` and its
//!    `form_urlencoded`, which this crate can't name (no direct dependency);
//!    their controls are `fuz_storage`'s `tests/request_reads_controls.rs`;
//!  - **suppressions**: every `.rs` file under `crates/` that names the
//!    disallow lints, a clippy group holding them, or `warnings` in an
//!    `allow`/`expect` is one [`SUPPRESSIONS`] lists, with its count of sites
//!    and its reason, and no `Cargo.toml` `[lints]` table allows them.
//!
//! What it cannot see:
//!
//!  - a hand-split query or path — `RawQuery`, `Uri::query()`, `OriginalUri`
//!    or `Uri::path()` read and decoded by hand outside the strict readers;
//!  - a lenient reader no entry names (another crate's query decoder), and a
//!    suppression from outside the source (`-A` flags, `CLIPPY_CONF_DIR`);
//!  - a `lints` key written under `[workspace]` or at a manifest's root rather
//!    than under a `[lints…]` header;
//!  - a lint written as its own sub-table (`[lints.clippy.all]` with
//!    `level = "allow"` under it) or a header spelled with spaces (`[ lints ]`);
//!  - a `"` in a trailing comment inside a multi-line `allow(…)` list, which
//!    unbalances the string scan;
//!  - consumers in other workspaces — zzz's `file_bytes.rs` (`Query`),
//!    visionesdelcaribe.org's `upload_route.rs` (`Query`), `fuz_forge`'s `Path`
//!    reads and `url::form_urlencoded` query parsing — which carry their own
//!    census once they move to the strict readers.
//!
//! [`read_query_pairs`]: fuz_http::read_query_pairs
//! [`RouteParams`]: fuz_http::RouteParams

#![expect(
    clippy::panic,
    clippy::expect_used,
    reason = "a guard test fails loud: the panic message is the operator-facing report"
)]

use std::fs;
use std::path::{Path, PathBuf};

/// Each lenient reader, with the list it belongs under.
const LENIENT_READERS: &[(&str, &str)] = &[
    ("disallowed-types", "axum::extract::Path"),
    ("disallowed-types", "axum::extract::RawPathParams"),
    ("disallowed-types", "axum::extract::Query"),
    // reads the query on `GET` / `HEAD`
    ("disallowed-types", "axum::extract::Form"),
    // `Query`'s decoder; also catches its `url::form_urlencoded` re-export
    ("disallowed-methods", "form_urlencoded::parse"),
    ("disallowed-methods", "url::Url::query_pairs"),
];

// Positive controls: each uses one disallowed type, so the `#[expect]` is
// fulfilled only while clippy resolves that entry. One item per type — a
// shared expectation is fulfilled by any one of them.

#[expect(
    dead_code,
    clippy::disallowed_types,
    reason = "positive control: unfulfilled once `axum::extract::Path` stops resolving"
)]
const fn path_control(_: &axum::extract::Path<String>) {}

#[expect(
    dead_code,
    clippy::disallowed_types,
    reason = "positive control: unfulfilled once `axum::extract::RawPathParams` stops resolving"
)]
const fn raw_path_params_control(_: &axum::extract::RawPathParams) {}

#[expect(
    dead_code,
    clippy::disallowed_types,
    reason = "positive control: unfulfilled once `axum::extract::Query` stops resolving"
)]
const fn query_control(_: &axum::extract::Query<Vec<(String, String)>>) {}

#[expect(
    dead_code,
    clippy::disallowed_types,
    reason = "positive control: unfulfilled once `axum::extract::Form` stops resolving"
)]
const fn form_control(_: &axum::extract::Form<Vec<(String, String)>>) {}

/// A file's suppressions of the disallow lints.
struct Suppression {
    /// The file, relative to `crates/`.
    file: &'static str,
    /// How many suppression sites its code holds (`count_suppression_sites`),
    /// so a new suppression in a listed file is caught too.
    sites: usize,
    reason: &'static str,
}

/// Every source file that suppresses the disallow lints, each with its reason.
/// Every other file names none. The exec-free disallows (`fuzi`'s
/// `clippy.toml`) share the lints, so their suppressions are listed here too.
const SUPPRESSIONS: &[Suppression] = &[
    Suppression {
        file: "fuz_http/src/request_target.rs",
        sites: 1,
        reason: "`RouteParams` wraps axum's `Path` after checking every escape",
    },
    Suppression {
        file: "fuz_http/tests/request_reads_census.rs",
        sites: 4,
        reason: "the positive controls of the axum type disallows",
    },
    Suppression {
        file: "fuz_storage/tests/request_reads_controls.rs",
        sites: 2,
        reason: "the positive controls of the `url` method disallows",
    },
    Suppression {
        file: "fuz_sys/src/path.rs",
        sites: 1,
        reason: "`home_dir`'s one `std::env::home_dir` read, its password-database fallback",
    },
    Suppression {
        file: "fuzi/tests/clean.rs",
        sites: 4,
        reason: "the harness spawns the built `fuzi` binary from outside its exec-free source",
    },
    Suppression {
        file: "fuzi/tests/json_contract.rs",
        sites: 2,
        reason: "the harness spawns the built `fuzi` binary from outside its exec-free source",
    },
    Suppression {
        file: "fuzi/tests/usage.rs",
        sites: 2,
        reason: "the harness spawns the built `fuzi` binary from outside its exec-free source",
    },
];

/// The lint paths a suppression names: the disallow lints, and the clippy
/// groups that hold them. Spelled through `concat!` so this file's own lists
/// don't count as sites.
const SUPPRESSED_LINTS: &[&str] = &[
    concat!("clippy::", "disallowed_types"),
    concat!("clippy::", "disallowed_methods"),
    concat!("clippy::", "style"),
    concat!("clippy::", "all"),
];

/// The `Cargo.toml` `[lints]` keys that would allow the disallow lints.
const LINTS_TABLE_KEYS: &[&str] = &[
    "disallowed_types",
    "disallowed-types",
    "disallowed_methods",
    "disallowed-methods",
    "style",
    "all",
    "warnings",
];

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

fn read(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_else(|e| {
        panic!(
            "request-reads census: cannot read `{}`: {e}",
            path.display()
        )
    })
}

/// The crate directories under `crates/`.
fn crate_dirs() -> Vec<PathBuf> {
    let crates = workspace_root().join("crates");
    let mut dirs: Vec<PathBuf> = fs::read_dir(&crates)
        .unwrap_or_else(|e| {
            panic!(
                "request-reads census: cannot read `{}`: {e}",
                crates.display()
            )
        })
        .map(|entry| entry.expect("a crates/ entry").path())
        .filter(|path| path.join("Cargo.toml").is_file())
        .collect();
    dirs.sort();
    assert!(
        dirs.len() > 1,
        "request-reads census: found no crates under `{}` — mis-pointed?",
        crates.display()
    );
    dirs
}

#[test]
fn every_clippy_config_disallows_the_lenient_readers() {
    let root = workspace_root();
    // Clippy reads the nearest config walking up from a crate's directory, by
    // either name, and does not merge: each one found must carry the census.
    let mut dirs = vec![root.clone(), root.join("crates")];
    dirs.extend(crate_dirs());
    let configs: Vec<PathBuf> = dirs
        .iter()
        .flat_map(|dir| [dir.join("clippy.toml"), dir.join(".clippy.toml")])
        .filter(|path| path.is_file())
        .collect();
    assert!(
        configs.contains(&root.join("clippy.toml")),
        "request-reads census: no workspace clippy.toml at `{}`",
        root.display()
    );
    for config in &configs {
        let entries = list_entries(&read(config));
        for (list, reader) in LENIENT_READERS {
            assert!(
                entries
                    .iter()
                    .filter(|(key, _)| key == list)
                    .any(|(_, entry)| entry_path(entry) == Some(*reader)),
                "request-reads census: `{}` lacks `{reader}` under `{list}` — \
                 without it a handler can read the request leniently with \
                 clippy green",
                config.display()
            );
        }
    }
}

#[test]
fn every_suppression_of_the_disallows_is_listed() {
    let crates = workspace_root().join("crates");
    let mut files = Vec::new();
    for dir in crate_dirs() {
        collect_rs_files(&dir, &mut files);
    }
    assert!(
        files.len() > SUPPRESSIONS.len(),
        "request-reads census: scanned only {} `.rs` files — mis-pointed?",
        files.len()
    );

    let mut found: Vec<(String, usize)> = Vec::new();
    for file in &files {
        let sites = count_suppression_sites(&read(file));
        if sites > 0 {
            let relative = file
                .strip_prefix(&crates)
                .expect("a file under crates/")
                .to_string_lossy()
                .replace('\\', "/");
            found.push((relative, sites));
        }
    }

    let mut failures = Vec::new();
    for (file, sites) in &found {
        match SUPPRESSIONS.iter().find(|s| s.file == file) {
            None => failures.push(format!(
                "crates/{file}: suppresses the disallow lints {sites} time(s) \
                 and is not listed — use the sanctioned reader or spawn path, \
                 or list it in `SUPPRESSIONS` with its reason"
            )),
            Some(listed) if listed.sites != *sites => failures.push(format!(
                "crates/{file}: names the disallow lints {sites} time(s), \
                 listed for {} ({})",
                listed.sites, listed.reason
            )),
            Some(_) => {}
        }
    }
    for listed in SUPPRESSIONS {
        if !found.iter().any(|(file, _)| file == listed.file) {
            failures.push(format!(
                "crates/{}: listed but suppresses nothing — drop the entry",
                listed.file
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "request-reads census: unlisted suppressions of the disallow lints:\n{}",
        failures.join("\n")
    );
}

#[test]
fn no_lints_table_allows_the_disallows() {
    let root = workspace_root();
    let mut manifests = vec![root.join("Cargo.toml")];
    manifests.extend(crate_dirs().iter().map(|dir| dir.join("Cargo.toml")));
    let mut failures = Vec::new();
    for manifest in &manifests {
        let mut in_lints = false;
        for (i, line) in read(manifest).lines().enumerate() {
            let code = strip_toml_comment(line);
            if code.starts_with('[') {
                // `[lints]`, `[lints.clippy]`, `[workspace.lints.rust]`, …
                in_lints = code.starts_with("[lints") || code.starts_with("[workspace.lints");
                continue;
            }
            if in_lints && lint_line_allows(line) {
                failures.push(format!("{}:{}: {}", manifest.display(), i + 1, line.trim()));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "request-reads census: a `[lints]` table allows the disallow lints:\n{}",
        failures.join("\n")
    );
}

/// The `[lints]` spellings the manifest scan must read.
#[test]
fn lint_settings_are_read_in_every_spelling() {
    for (line, allows) in [
        ("disallowed_types = \"allow\"", true),
        ("\"disallowed-methods\" = \"allow\"", true),
        ("clippy.disallowed_types = \"allow\"", true),
        ("all.level = \"allow\"", true),
        (
            "disallowed_methods = { level = \"allow\", priority = 1 }",
            true,
        ),
        ("clippy = { all = \"allow\" }", true),
        ("clippy = { all = \"allow\" } # for now", true),
        (
            "clippy = { pedantic = \"warn\", style = { level = \"allow\" } }",
            true,
        ),
        ("warnings = \"allow\"", true),
        ("all = { level = \"warn\", priority = -1 }", false),
        ("all = \"warn\" # allow nothing", false),
        ("module_name_repetitions = \"allow\"", false),
        (
            "clippy = { all = \"warn\", module_name_repetitions = \"allow\" }",
            false,
        ),
        ("workspace = true", false),
        ("# disallowed_types = \"allow\"", false),
    ] {
        assert_eq!(lint_line_allows(line), allows, "{line}");
    }
}

/// A manifest line without its `#` comment, trimmed.
fn strip_toml_comment(line: &str) -> &str {
    line.split_once('#').map_or(line, |(code, _)| code).trim()
}

/// Whether one line of a `[lints]` table allows a disallow lint
/// ([`lint_setting_allows`] over its `key = value`, comment stripped).
fn lint_line_allows(line: &str) -> bool {
    strip_toml_comment(line)
        .split_once('=')
        .is_some_and(|(key, value)| lint_setting_allows(key, value))
}

/// Whether one `key = value` line of a `[lints]` table allows a disallow lint:
/// any dotted segment of the key (`clippy.disallowed_types`, `all.level`) is one of
/// [`LINTS_TABLE_KEYS`] and the value (`"allow"`, `{ level = "allow", … }`)
/// says `allow`, or the value is an inline table (`clippy = { all = "allow" }`)
/// one of whose settings does.
fn lint_setting_allows(key: &str, value: &str) -> bool {
    let names_a_lint = key
        .split('.')
        .any(|segment| LINTS_TABLE_KEYS.contains(&segment.trim().trim_matches('"')));
    let value = value.trim();
    if names_a_lint {
        return value.contains("allow");
    }
    let Some(inner) = value.strip_prefix('{').and_then(|v| v.strip_suffix('}')) else {
        return false;
    };
    split_top_level(inner, ',').into_iter().any(|setting| {
        setting
            .split_once('=')
            .is_some_and(|(key, value)| lint_setting_allows(key, value))
    })
}

/// How many `warnings` identifiers an `allow(…)` / `expect(…)` argument list
/// holds outside its string literals, up to its closing `)` — nested parens and
/// strings (a `reason` may hold either) skipped.
fn warnings_in_list(list: &str) -> usize {
    let is_ident = |c: char| c.is_alphanumeric() || c == '_';
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    let mut count = 0;
    for (at, c) in list.char_indices() {
        if in_string {
            match c {
                _ if escaped => escaped = false,
                '\\' => escaped = true,
                '"' => in_string = false,
                _ => {}
            }
            continue;
        }
        match c {
            '"' => in_string = true,
            '(' => depth += 1,
            ')' if depth == 0 => break,
            ')' => depth -= 1,
            'w' if list[at..].starts_with("warnings")
                && !list[..at].ends_with(is_ident)
                && !list[at + "warnings".len()..].starts_with(is_ident) =>
            {
                count += 1;
            }
            _ => {}
        }
    }
    count
}

/// Split `text` on `separator` outside any `{}` / `()` nesting.
fn split_top_level(text: &str, separator: char) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut depth = 0usize;
    let mut start = 0;
    for (at, c) in text.char_indices() {
        match c {
            '{' | '(' => depth += 1,
            '}' | ')' => depth = depth.saturating_sub(1),
            c if c == separator && depth == 0 => {
                parts.push(&text[start..at]);
                start = at + c.len_utf8();
            }
            _ => {}
        }
    }
    parts.push(&text[start..]);
    parts
}

/// Recursively collect `.rs` files under `dir`, skipping build output.
fn collect_rs_files(dir: &Path, files: &mut Vec<PathBuf>) {
    let entries = fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("request-reads census: cannot read `{}`: {e}", dir.display()));
    for entry in entries {
        let path = entry.expect("a directory entry").path();
        if path.is_dir() {
            if path.file_name().is_some_and(|name| name == "target") {
                continue;
            }
            collect_rs_files(&path, files);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            files.push(path);
        }
    }
}

/// The suppression spellings the source scan must count. Spelled in capitals
/// and lowered at run time, so this file's own scan doesn't count them.
#[test]
fn suppression_sites_are_counted_in_every_spelling() {
    for (text, sites) in [
        ("#[ALLOW(warnings)]", 1),
        ("#![EXPECT(unused, warnings, reason = \"x\")]", 1),
        ("#[ALLOW(\n    warnings // for now\n)]", 1),
        ("#[ALLOW(warnings/*x*/)]", 1),
        ("#[cfg_attr(test, ALLOW(warnings))]", 1),
        (
            "#[ALLOW(dead_code, reason = \"dead code, warnings, more\")]",
            0,
        ),
        ("let x = Ok(warnings);", 0),
        ("x.EXPECT(\"no warnings\")", 0),
        ("#[ALLOW(nowarningshere)]", 0),
        ("// #[ALLOW(warnings)]", 0),
    ] {
        let text = text.to_lowercase();
        assert_eq!(count_suppression_sites(&text), sites, "{text}");
    }
}

/// How many times a file's code names a suppressed lint path, plus each
/// `warnings` named in an `allow(…)` / `expect(…)` list (a bare `warnings`
/// elsewhere is an identifier). Full-line comments are skipped, and whitespace
/// is dropped so `clippy :: x` counts.
fn count_suppression_sites(text: &str) -> usize {
    let code: String = text
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .flat_map(str::chars)
        .filter(|c| !c.is_whitespace())
        .collect();
    let lint_paths: usize = SUPPRESSED_LINTS
        .iter()
        .map(|lint| {
            code.match_indices(lint)
                .filter(|(at, _)| {
                    // a whole lint name, not a prefix of a longer one
                    // (`clippy::all` in `clippy::allow_attributes`)
                    !code[at + lint.len()..].starts_with(|c: char| c.is_alphanumeric() || c == '_')
                })
                .count()
        })
        .sum();
    let warnings_items: usize = ["allow(", "expect("]
        .iter()
        .flat_map(|open| code.match_indices(open))
        .filter(|(at, _)| {
            // `allow(` itself, not the tail of a longer name (`disallow(`)
            !code[..*at].ends_with(|c: char| c.is_alphanumeric() || c == '_')
        })
        .map(|(at, open)| warnings_in_list(&code[at + open.len()..]))
        .sum();
    lint_paths + warnings_items
}

/// The entries of each `key = [` list in a `clippy.toml`, each paired with its
/// list's key. Full-line `#` comments are skipped, so a commented-out entry is
/// missing. The same reading as `fuzi_core/tests/exec_free.rs`'s — duplicated,
/// since two test crates share no module and the workspace has no `toml` crate.
fn list_entries(text: &str) -> Vec<(String, String)> {
    let mut entries = Vec::new();
    let mut list: Option<&str> = None;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(key) = list {
            if line == "]" {
                list = None;
            } else {
                let entry = line.strip_suffix(',').unwrap_or(line).trim_end();
                entries.push((key.to_owned(), entry.to_owned()));
            }
        } else if let Some((key, value)) = line.split_once('=')
            && value.trim() == "["
        {
            list = Some(key.trim());
        }
    }
    assert!(
        list.is_none(),
        "request-reads census: a list in a clippy.toml is never closed"
    );
    entries
}

/// The `path = "..."` field of a disallow entry (`{ path = "...", reason = ... }`).
fn entry_path(entry: &str) -> Option<&str> {
    let rest = entry.split_once("path = \"")?.1;
    Some(rest.split_once('"')?.0)
}
