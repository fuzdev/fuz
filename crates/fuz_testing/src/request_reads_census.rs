//! The request-reads census, shared by the workspaces on the spine that run it.
//!
//! A handler reads its query and its path params only through `fuz_http`'s
//! strict readers — `fuz_http::read_query_pairs` over axum's `RawQuery`, and
//! `fuz_http::RouteParams` — never a lenient extractor that leaves an escape
//! that doesn't decode as text or writes U+FFFD for it. Twin of the query and
//! path-param half of `fuz_app`'s `request_reads_census.test.ts` (its header
//! half has no Rust twin here).
//!
//! The enforcement is clippy's `disallowed-types` / `disallowed-methods` in a
//! workspace's `clippy.toml` (`-D warnings` makes a hit an error), each entry
//! one of [`LENIENT_READERS`]. Clippy resolves the paths, so an aliased or
//! grouped import is caught. These checks hold that enforcement in place, each
//! over a workspace root (the directory holding its `Cargo.toml` and
//! `crates/`):
//!
//!  - **the config** ([`assert_clippy_configs_disallow_lenient_readers`]): the
//!    root `clippy.toml` and every one under `crates/` or a crate directory, by
//!    either name (a nearer one replaces the root file rather than merging with
//!    it), lists each lenient reader with its canonical reason, spelled exactly
//!    — a misspelled path is only a clippy warning (`does not refer to a
//!    reachable type`) that `-D warnings` does not promote, and a dropped entry
//!    turns the census off with clippy green;
//!  - **suppressions** ([`assert_suppressions_listed`]): every `.rs` file under
//!    `crates/` that names the disallow lints, a clippy group holding them, or
//!    `warnings` in an `allow`/`expect` is one the workspace's [`Suppression`]
//!    list names, with its count of sites and its reason;
//!  - **`[lints]` tables** ([`assert_no_lints_table_allows_disallows`]): no
//!    `Cargo.toml` `[lints]` table, root or crate, allows them.
//!
//! What stays in each workspace's own test crate is **resolution**: positive
//! controls that use each disallowed item under an `#[expect]`, so a path that
//! stops resolving (an axum upgrade moving it) leaves the expectation
//! unfulfilled — an error under `-D warnings`. A control proves resolution
//! only under the clippy config of the workspace it compiles in, so it can't
//! live here; its `#[expect]` is a suppression site the workspace lists.
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
//!    `level = "allow"` under it) or a header spelled with spaces
//!    (`[ lints ]`);
//!  - a `"` in a trailing comment inside a multi-line `allow(…)` list, which
//!    unbalances the string scan;
//!  - a workspace member outside `crates/<name>/`, which is neither scanned
//!    nor config-checked;
//!  - a workspace that doesn't run it — the spine, zzz and
//!    visionesdelcaribe.org do; the other spine consumers don't: `fuz_forge`'s
//!    `Path` reads and `url::form_urlencoded` query parsing await it, once
//!    they move to the strict readers, and the rest read nothing leniently
//!    today.

#![expect(
    clippy::panic,
    clippy::expect_used,
    reason = "a guard test fails loud: the panic message is the operator-facing report, and the in-tests carve-out doesn't reach a library module"
)]

use std::fs;
use std::path::{Path, PathBuf};

/// One lenient reader: the `clippy.toml` list it belongs under, its path, and
/// the reason every config gives it.
#[derive(Debug, Clone, Copy)]
pub struct LenientReader {
    /// `disallowed-types` or `disallowed-methods`.
    pub list: &'static str,
    /// The item's path, as clippy resolves it.
    pub path: &'static str,
    /// The entry's `reason`, naming the strict reader to use instead.
    pub reason: &'static str,
}

/// Each lenient reader, as every workspace's `clippy.toml` must spell it.
pub const LENIENT_READERS: &[LenientReader] = &[
    LenientReader {
        list: "disallowed-types",
        path: "axum::extract::Path",
        reason: "a lenient path-param read: use fuz_http::RouteParams",
    },
    LenientReader {
        list: "disallowed-types",
        path: "axum::extract::RawPathParams",
        reason: "a lenient path-param read: use fuz_http::RouteParams",
    },
    LenientReader {
        list: "disallowed-types",
        path: "axum::extract::Query",
        reason: "a lossy query read: use fuz_http::read_query_pairs over RawQuery",
    },
    // reads the query on `GET` / `HEAD`
    LenientReader {
        list: "disallowed-types",
        path: "axum::extract::Form",
        reason: "a lossy form read (the query, on GET): use fuz_http::read_query_pairs over RawQuery",
    },
    // `Query`'s decoder; also catches its `url::form_urlencoded` re-export
    LenientReader {
        list: "disallowed-methods",
        path: "form_urlencoded::parse",
        reason: "a lossy query read: use fuz_http::read_query_pairs over RawQuery",
    },
    LenientReader {
        list: "disallowed-methods",
        path: "url::Url::query_pairs",
        reason: "a lossy query read: use fuz_http::read_query_pairs over RawQuery",
    },
];

/// A file's suppressions of the disallow lints.
#[derive(Debug, Clone, Copy)]
pub struct Suppression {
    /// The file, relative to the workspace's `crates/`.
    pub file: &'static str,
    /// How many suppression sites its code holds, so a new suppression in a
    /// listed file is caught too.
    pub sites: usize,
    /// Why the file suppresses them, shown when its count drifts.
    pub reason: &'static str,
}

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

/// Assert that the workspace's root `clippy.toml`, and every `clippy.toml` /
/// `.clippy.toml` under `crates/` or a crate directory, lists each of
/// [`LENIENT_READERS`] under its list with its reason.
///
/// # Panics
///
/// Panics if a config is unreadable or a list in one is never closed, if the
/// root has no `clippy.toml`, and — the point — naming the first config that
/// lacks an entry.
pub fn assert_clippy_configs_disallow_lenient_readers(workspace_root: &Path) {
    // Clippy reads the nearest config walking up from a crate's directory, by
    // either name, and does not merge: each one found must carry the census.
    let mut dirs = vec![workspace_root.to_path_buf(), workspace_root.join("crates")];
    dirs.extend(crate_dirs(workspace_root));
    let configs: Vec<PathBuf> = dirs
        .iter()
        .flat_map(|dir| [dir.join("clippy.toml"), dir.join(".clippy.toml")])
        .filter(|path| path.is_file())
        .collect();
    assert!(
        configs.contains(&workspace_root.join("clippy.toml")),
        "request-reads census: no workspace clippy.toml at `{}`",
        workspace_root.display()
    );
    for config in &configs {
        let entries = list_entries(&read(config));
        for reader in LENIENT_READERS {
            assert!(
                entries
                    .iter()
                    .filter(|(key, _)| key == reader.list)
                    .any(|(_, entry)| entry_field(entry, "path") == Some(reader.path)
                        && entry_field(entry, "reason") == Some(reader.reason)),
                "request-reads census: `{}` lacks `{{ path = \"{}\", reason = \"{}\" }}` \
                 under `{}` — without it a handler can read the request leniently \
                 with clippy green",
                config.display(),
                reader.path,
                reader.reason,
                reader.list
            );
        }
    }
}

/// Assert that the `.rs` files under the workspace's `crates/` that suppress
/// the disallow lints are exactly `suppressions`, each with its count of sites.
///
/// # Panics
///
/// Panics if a directory or file is unreadable, if the scan finds too few files
/// to be pointed at a workspace, and — the point — listing every unlisted,
/// miscounted, or stale entry.
pub fn assert_suppressions_listed(workspace_root: &Path, suppressions: &[Suppression]) {
    let crates = workspace_root.join("crates");
    let mut files = Vec::new();
    for dir in crate_dirs(workspace_root) {
        collect_rs_files(&dir, &mut files);
    }
    assert!(
        files.len() > suppressions.len(),
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
        match suppressions.iter().find(|s| s.file == file) {
            None => failures.push(format!(
                "crates/{file}: suppresses the disallow lints {sites} time(s) \
                 and is not listed — use the sanctioned path, or list it in \
                 the census's suppressions with its reason"
            )),
            Some(listed) if listed.sites != *sites => failures.push(format!(
                "crates/{file}: names the disallow lints {sites} time(s), \
                 listed for {} ({})",
                listed.sites, listed.reason
            )),
            Some(_) => {}
        }
    }
    for listed in suppressions {
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

/// Assert that no `[lints]` table in the workspace's root `Cargo.toml` or a
/// crate's allows the disallow lints.
///
/// # Panics
///
/// Panics if a manifest is unreadable, and — the point — listing every line
/// that allows them.
pub fn assert_no_lints_table_allows_disallows(workspace_root: &Path) {
    let mut manifests = vec![workspace_root.join("Cargo.toml")];
    manifests.extend(
        crate_dirs(workspace_root)
            .iter()
            .map(|dir| dir.join("Cargo.toml")),
    );
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

fn read(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_else(|e| {
        panic!(
            "request-reads census: cannot read `{}`: {e}",
            path.display()
        )
    })
}

/// The crate directories under `crates/`.
fn crate_dirs(workspace_root: &Path) -> Vec<PathBuf> {
    let crates = workspace_root.join("crates");
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
/// missing. The same reading as `fuzi_core/tests/exec_free.rs`'s — duplicated
/// there, since `fuzi_core` doesn't link this crate and the workspace has no
/// `toml` crate.
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

/// A string field of a disallow entry (`{ path = "...", reason = "..." }`).
fn entry_field<'a>(entry: &'a str, field: &str) -> Option<&'a str> {
    let rest = entry.split_once(&format!("{field} = \""))?.1;
    Some(rest.split_once('"')?.0)
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;
    use std::fs;
    use std::path::Path;

    use super::{
        LENIENT_READERS, Suppression, assert_clippy_configs_disallow_lenient_readers,
        assert_no_lints_table_allows_disallows, assert_suppressions_listed,
        count_suppression_sites, entry_field, lint_line_allows,
    };

    /// A suppression of a disallow lint, spelled through `concat!` so the
    /// census's own scan of this file doesn't count it.
    const SUPPRESSION_SITE: &str = concat!("#[allow(clippy::", "disallowed_types)]\nfn x() {}\n");

    /// The root `clippy.toml` every config check here starts from: each of
    /// `LENIENT_READERS` under its list with its reason.
    fn canonical_clippy_toml() -> String {
        let mut text = String::new();
        for list in ["disallowed-methods", "disallowed-types"] {
            writeln!(text, "{list} = [").expect("write to a String");
            for reader in LENIENT_READERS.iter().filter(|r| r.list == list) {
                writeln!(
                    text,
                    "    {{ path = \"{}\", reason = \"{}\" }},",
                    reader.path, reader.reason
                )
                .expect("write to a String");
            }
            text.push_str("]\n");
        }
        text
    }

    /// A small workspace: a root `clippy.toml` and `Cargo.toml`, and crates
    /// `a` and `b` under `crates/`, `a`'s `src/lib.rs` holding `a_lib`.
    fn workspace(clippy_toml: &str, cargo_toml: &str, a_lib: &str) -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("a temp dir");
        let root = dir.path();
        fs::write(root.join("clippy.toml"), clippy_toml).expect("write clippy.toml");
        fs::write(root.join("Cargo.toml"), cargo_toml).expect("write Cargo.toml");
        for (name, lib) in [("a", a_lib), ("b", "pub fn b() {}\n")] {
            let src = root.join("crates").join(name).join("src");
            fs::create_dir_all(&src).expect("create a crate");
            fs::write(
                root.join("crates").join(name).join("Cargo.toml"),
                "[package]\nname = \"x\"\n\n[lints]\nworkspace = true\n",
            )
            .expect("write a crate's Cargo.toml");
            fs::write(src.join("lib.rs"), lib).expect("write lib.rs");
        }
        dir
    }

    const CARGO_TOML: &str = "[workspace]\nmembers = [\"crates/*\"]\n\n[workspace.lints.clippy]\nall = { level = \"warn\", priority = -1 }\n";

    fn listed_a(sites: usize) -> [Suppression; 1] {
        [Suppression {
            file: "a/src/lib.rs",
            sites,
            reason: "a fixture suppression",
        }]
    }

    fn run_all(root: &Path, suppressions: &[Suppression]) {
        assert_clippy_configs_disallow_lenient_readers(root);
        assert_suppressions_listed(root, suppressions);
        assert_no_lints_table_allows_disallows(root);
    }

    #[test]
    fn a_conforming_workspace_passes() {
        let ws = workspace(&canonical_clippy_toml(), CARGO_TOML, SUPPRESSION_SITE);
        run_all(ws.path(), &listed_a(1));
    }

    #[test]
    #[should_panic(expected = "lacks `{ path = \"axum::extract::Query\"")]
    fn a_missing_entry_fails() {
        let clippy_toml = canonical_clippy_toml()
            .lines()
            .filter(|line| !line.contains("axum::extract::Query"))
            .collect::<Vec<_>>()
            .join("\n");
        let ws = workspace(&clippy_toml, CARGO_TOML, "");
        assert_clippy_configs_disallow_lenient_readers(ws.path());
    }

    #[test]
    #[should_panic(expected = "lacks `{ path = \"axum::extract::Form\"")]
    fn a_wrong_reason_fails() {
        let clippy_toml = canonical_clippy_toml().replace("(the query, on GET)", "");
        let ws = workspace(&clippy_toml, CARGO_TOML, "");
        assert_clippy_configs_disallow_lenient_readers(ws.path());
    }

    #[test]
    #[should_panic(expected = "crates/b/.clippy.toml` lacks")]
    fn a_crate_level_config_is_checked() {
        let ws = workspace(&canonical_clippy_toml(), CARGO_TOML, "");
        fs::write(ws.path().join("crates/b/.clippy.toml"), "msrv = \"1.0\"\n")
            .expect("write a crate config");
        assert_clippy_configs_disallow_lenient_readers(ws.path());
    }

    #[test]
    #[should_panic(
        expected = "crates/a/src/lib.rs: suppresses the disallow lints 1 time(s) and is not listed"
    )]
    fn an_unlisted_suppression_fails() {
        let ws = workspace(&canonical_clippy_toml(), CARGO_TOML, SUPPRESSION_SITE);
        assert_suppressions_listed(ws.path(), &[]);
    }

    #[test]
    #[should_panic(
        expected = "crates/a/src/lib.rs: names the disallow lints 1 time(s), listed for 2 (a fixture suppression)"
    )]
    fn a_miscounted_suppression_fails() {
        let ws = workspace(&canonical_clippy_toml(), CARGO_TOML, SUPPRESSION_SITE);
        assert_suppressions_listed(ws.path(), &listed_a(2));
    }

    #[test]
    #[should_panic(expected = "crates/a/src/lib.rs: listed but suppresses nothing")]
    fn a_stale_suppression_fails() {
        let ws = workspace(&canonical_clippy_toml(), CARGO_TOML, "pub fn a() {}\n");
        assert_suppressions_listed(ws.path(), &listed_a(1));
    }

    #[test]
    #[should_panic(expected = "Cargo.toml:6: disallowed_methods = \"allow\"")]
    fn an_allowing_lints_line_fails() {
        let cargo_toml = format!("{CARGO_TOML}disallowed_methods = \"allow\"\n");
        let ws = workspace(&canonical_clippy_toml(), &cargo_toml, "");
        assert_no_lints_table_allows_disallows(ws.path());
    }

    #[test]
    #[should_panic(expected = "found no crates under")]
    fn a_mis_pointed_root_fails() {
        let dir = tempfile::tempdir().expect("a temp dir");
        fs::create_dir(dir.path().join("crates")).expect("create crates/");
        assert_suppressions_listed(dir.path(), &[]);
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

    /// The suppression spellings the source scan must count. Spelled in capitals
    /// and lowered at run time, so the census's own scan doesn't count them.
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

    /// An entry's `path` and `reason` are read whole, and a missing field is
    /// `None`.
    #[test]
    fn entry_fields_are_read() {
        let entry = "{ path = \"axum::extract::Path\", reason = \"a read: use x\" }";
        assert_eq!(entry_field(entry, "path"), Some("axum::extract::Path"));
        assert_eq!(entry_field(entry, "reason"), Some("a read: use x"));
        assert_eq!(entry_field("{ path = \"a::b\" }", "reason"), None);
    }
}
