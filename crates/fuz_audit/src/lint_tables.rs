//! The lint-table pass: a workspace member that re-declares its own
//! `[lints.<tool>]` tables keeps the workspace's lints.
//!
//! Cargo replaces a crate's `[lints]` table whole, so a crate that must differ
//! from the workspace (in practice one that needs `unsafe`) re-declares every
//! lint, and a hand-kept copy silently drifts. For every workspace member whose
//! manifest declares `[lints.<tool>]` tables instead of
//! `[lints] workspace = true`, the pass checks:
//!
//! - **Tools.** Its set of `[lints.<tool>]` tables equals the workspace's set of
//!   `[workspace.lints.<tool>]` tables.
//! - **Lints.** Every lint the workspace sets appears in the crate's table of
//!   the same tool at the same level and priority, with one exception:
//!   `unsafe_code` under `rust` ([`UNSAFE_CODE`]), whose difference is why the
//!   crate re-declares. Where the workspace sets it, the crate must declare it
//!   too, at `deny` or `forbid` and at the workspace's priority: `deny`, so
//!   each item that needs `unsafe` lifts it with its own `#[expect]`. `allow`
//!   or `warn` fails. There is no opt-out.
//! - **Additions.** Lints the crate sets beyond the workspace's are allowed
//!   (`clippy::undocumented_unsafe_blocks` in a boundary crate) and listed in
//!   the audit's output with the `unsafe_code` difference.
//! - **No crate-wide lift.** A crate whose `unsafe_code` is not `forbid` carries
//!   no inner attribute at the top of a lib or bin crate root whose `allow`,
//!   `expect`, or `warn` argument list names `unsafe_code`, a `cfg_attr`
//!   wrapping one included. The boundary is the crate root: a lift at the top
//!   of a submodule file, or on a `mod` declaration, is not seen (a module that
//!   is entirely ABI surface may lift the lint for itself).
//!
//! Lints are compared by level and priority only; a `check-cfg` list is read
//! past, not compared.
//!
//! Out of scope, and reported as such: a workspace whose root manifest has no
//! `[workspace.lints]` (its re-declaring members are listed as not checked),
//! and a member with neither form (no lint table applies to it, which the
//! audit notes on every run). The root manifest is read only once a member
//! re-declares, so a workspace where every member inherits never depends on
//! the reader understanding its `[workspace.lints]`.
//!
//! `cargo metadata` doesn't expose lint tables, so the manifests are read by a
//! small line-based reader ([`read_lints`]), not a TOML parser. Comments and
//! strings are skipped quote-aware, a multi-line string included. It
//! understands a lint as `name = "level"`, as an inline table
//! `name = { level = "…", priority = N, check-cfg = [ … ] }` (on one line, but
//! for the `check-cfg` array, which may span lines), or as a sub-table
//! `[lints.<tool>.<name>]` of `level`, `priority`, and `check-cfg` keys. It
//! refuses anything else under a lint header as a tooling failure, never a
//! pass: an inline table spanning lines outside its `check-cfg` array, a dotted
//! key, any other key in a lint's table, a value that isn't a level string or
//! a lint's table, a multi-line string, a table nested below a lint, a lint
//! table set outside a `[lints.<tool>]` header (`lints.rust.x = …`,
//! `lints = { … }`), and a multi-line string left open at the end of the file.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

use serde_json::Value;
use thiserror::Error;

use super::AuditError;

/// The lint whose level a re-declaring crate may set apart from the
/// workspace's: `(tool, lint)`.
pub const UNSAFE_CODE: (&str, &str) = ("rust", "unsafe_code");

/// The levels a re-declaring crate may give [`UNSAFE_CODE`].
const UNSAFE_CODE_LEVELS: &[&str] = &["deny", "forbid"];

/// Target kinds whose root file is a crate root a build ships: a library of any
/// kind, or a binary.
const CRATE_ROOT_KINDS: &[&str] = &[
    "lib",
    "rlib",
    "dylib",
    "cdylib",
    "staticlib",
    "proc-macro",
    "bin",
];

/// The levels Cargo accepts for a lint.
const LEVELS: &[&str] = &["allow", "warn", "deny", "forbid"];

/// One lint's setting, normalized: `"warn"` and
/// `{ priority = 0, level = "warn" }` are the same setting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LintSetting {
    /// `allow`, `warn`, `deny`, or `forbid`.
    pub level: String,
    /// The priority, `0` when unset.
    pub priority: i64,
}

impl fmt::Display for LintSetting {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.priority == 0 {
            write!(f, "\"{}\"", self.level)
        } else {
            write!(
                f,
                "{{ level = \"{}\", priority = {} }}",
                self.level, self.priority
            )
        }
    }
}

/// A manifest's lint tables: tool (`rust`, `rustdoc`, `clippy`) → lint →
/// setting.
pub type LintTables = BTreeMap<String, BTreeMap<String, LintSetting>>;

/// Which manifest's tables [`read_lints`] reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LintScope {
    /// The workspace root's `[workspace.lints.<tool>]` tables.
    Workspace,
    /// A package's `[lints.<tool>]` tables, or its `[lints] workspace = true`.
    Package,
}

impl LintScope {
    /// The table path the scope's lint tables hang off.
    const fn prefix(self) -> &'static [&'static str] {
        match self {
            Self::Workspace => &["workspace", "lints"],
            Self::Package => &["lints"],
        }
    }
}

/// What a manifest says about lints, as [`read_lints`] reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestLints {
    /// No lint table at all.
    Absent,
    /// `[lints] workspace = true` (package scope only).
    Inherits,
    /// Its own tables, one per tool header.
    Tables(LintTables),
}

/// A manifest shape the line-based reader doesn't understand. The audit
/// reports it as a tooling failure: the reader can't vouch for the table.
#[derive(Debug, Error, PartialEq, Eq)]
#[error("line {line}: {message}")]
pub struct LintShapeError {
    /// The 1-based line number.
    pub line: usize,
    /// What the reader refused.
    pub message: String,
}

/// A `[<prefix>.<tool>.<lint>]` sub-table being read: its keys so far.
#[derive(Debug)]
struct OpenSubTable {
    tool: String,
    lint: String,
    parts: SettingParts,
    line: usize,
}

/// Read the lint tables of `scope` from the manifest `text`.
///
/// Line-based: each line's comment is dropped (quote-aware), and lines inside
/// a multi-line string are skipped; a header line opens a section; a
/// `key = value` line under a `[<prefix>.<tool>]` header is one lint, its value
/// continued onto later lines only inside a `check-cfg` array. Header and key
/// paths are split on dots outside quotes, so
/// `[target.'cfg(unix)'.dependencies]` is an ordinary section.
///
/// # Errors
///
/// Returns a [`LintShapeError`] for any shape under a lint header the reader
/// doesn't understand (see the module docs), a repeated lint or header, a
/// level Cargo doesn't accept, a lint key set outside a `[<prefix>.<tool>]`
/// header, both `[lints] workspace = true` and `[lints.<tool>]` tables, an
/// unclosed string, or a multi-line string open at the end of the file.
pub fn read_lints(text: &str, scope: LintScope) -> Result<ManifestLints, LintShapeError> {
    let prefix = scope.prefix();
    let mut tables: Option<LintTables> = None;
    let mut inherits = false;
    // the line of the first `[<prefix>.<tool>…]` header, for the both-forms refusal
    let mut first_tool_line: Option<usize> = None;
    // the lint headers seen, so a repeated one is refused
    let mut headers: BTreeSet<Vec<String>> = BTreeSet::new();
    // the dotted path of the current section; the root table is empty
    let mut section: Vec<String> = Vec::new();
    let mut subtable: Option<OpenSubTable> = None;
    // a multi-line string left open: its delimiter and opening line
    let mut multiline: Option<(&str, usize)> = None;
    let mut lines = text.lines().enumerate();
    while let Some((index, raw)) = lines.next() {
        let line_no = index + 1;
        let err = |message: String| LintShapeError {
            line: line_no,
            message,
        };
        let raw = if let Some((delimiter, _)) = multiline {
            let Some(end) = find_close(raw, delimiter) else {
                continue;
            };
            multiline = None;
            &raw[end..]
        } else {
            raw
        };
        let scanned = scan_line(raw).map_err(err)?;
        if let Some(delimiter) = scanned.open {
            multiline = Some((delimiter, line_no));
        }
        let line = scanned.code.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(header) = parse_header(line) {
            if let Some(open) = subtable.take() {
                close_subtable(open, tables.get_or_insert_with(LintTables::new))?;
            }
            section = split_dotted(&header).map_err(err)?;
            let Some(rest) = strip_path(&section, prefix) else {
                continue;
            };
            if !headers.insert(section.clone()) {
                return Err(err(format!(
                    "the table `[{}]` is declared twice",
                    section.join(".")
                )));
            }
            let tables = tables.get_or_insert_with(LintTables::new);
            match rest {
                [] => {}
                [tool] => {
                    first_tool_line.get_or_insert(line_no);
                    tables.entry(tool.clone()).or_default();
                }
                [tool, lint] => {
                    first_tool_line.get_or_insert(line_no);
                    tables.entry(tool.clone()).or_default();
                    subtable = Some(OpenSubTable {
                        tool: tool.clone(),
                        lint: lint.clone(),
                        parts: SettingParts::default(),
                        line: line_no,
                    });
                }
                _ => {
                    return Err(err(format!(
                        "`[{}]` nests below a lint's table, which the lint-table reader \
                         doesn't understand",
                        section.join(".")
                    )));
                }
            }
            continue;
        }
        // a `key = value` line; anything else (an array's continuation line)
        // belongs to a value the reader skips
        let Some((key, value)) = split_key_value(line) else {
            if strip_path(&section, prefix).is_some() {
                return Err(err(format!(
                    "`{line}` under `[{}]` is not a `name = value` line, which the \
                     lint-table reader doesn't understand",
                    section.join(".")
                )));
            }
            continue;
        };
        let Some(rest) = strip_path(&section, prefix) else {
            // a lint table written as a dotted key or inline table from an
            // enclosing section (`lints.rust.x = …`, `lints = { … }`)
            let mut full = section.clone();
            full.extend(split_dotted(key).map_err(err)?);
            if strip_path(&full, prefix).is_some() {
                return Err(err(format!(
                    "`{}` sets a lint table outside a `[{}.<tool>]` header, which the \
                     lint-table reader doesn't understand",
                    full.join("."),
                    prefix.join(".")
                )));
            }
            continue;
        };
        let key_path = split_dotted(key).map_err(err)?;
        let [key] = key_path.as_slice() else {
            return Err(err(format!(
                "the dotted key `{key}` under `[{}]` — write each lint under its own \
                 `[{}.<tool>]` header",
                section.join("."),
                prefix.join(".")
            )));
        };
        match rest {
            [] if scope == LintScope::Package && key == "workspace" => {
                if value.trim() != "true" {
                    return Err(err(format!(
                        "`workspace = {value}` under `[lints]`; the reader understands \
                         only `workspace = true`"
                    )));
                }
                inherits = true;
            }
            [] => {
                return Err(err(format!(
                    "`{key}` set directly under `[{}]` — write each lint under its own \
                     `[{}.<tool>]` header",
                    section.join("."),
                    prefix.join(".")
                )));
            }
            [tool] => {
                let value = lint_value(value, &mut lines).map_err(err)?;
                let setting = parse_setting(&value).map_err(err)?;
                let table = tables
                    .get_or_insert_with(LintTables::new)
                    .entry(tool.clone())
                    .or_default();
                if table.insert(key.clone(), setting).is_some() {
                    return Err(err(format!(
                        "`{key}` is set twice in `[{}]`",
                        section.join(".")
                    )));
                }
            }
            _ => {
                let value = lint_value(value, &mut lines).map_err(err)?;
                let mut cursor = Cursor { rest: &value };
                let open = subtable
                    .as_mut()
                    .ok_or_else(|| err("a key outside any lint's table".to_owned()))?;
                open.parts.set(key, &mut cursor).map_err(err)?;
                cursor.finish().map_err(err)?;
            }
        }
    }
    if let Some((_, line)) = multiline {
        return Err(LintShapeError {
            line,
            message: "a multi-line string still open at the end of the file".to_owned(),
        });
    }
    if let Some(open) = subtable {
        close_subtable(open, tables.get_or_insert_with(LintTables::new))?;
    }
    if inherits {
        return first_tool_line.map_or(Ok(ManifestLints::Inherits), |line| {
            Err(LintShapeError {
                line,
                message: "both `[lints] workspace = true` and `[lints.<tool>]` tables".to_owned(),
            })
        });
    }
    Ok(tables.map_or(ManifestLints::Absent, ManifestLints::Tables))
}

/// Record a finished `[<prefix>.<tool>.<lint>]` sub-table's setting.
fn close_subtable(open: OpenSubTable, tables: &mut LintTables) -> Result<(), LintShapeError> {
    let err = |message: String| LintShapeError {
        line: open.line,
        message,
    };
    let setting = open.parts.finish().map_err(err)?;
    let table = tables.entry(open.tool.clone()).or_default();
    if table.insert(open.lint.clone(), setting).is_some() {
        return Err(err(format!(
            "`{}` is set twice in `{}`'s lints",
            open.lint, open.tool
        )));
    }
    Ok(())
}

/// The rest of the dotted `path` below `prefix`; `None` when `path` isn't
/// under it.
fn strip_path<'a>(path: &'a [String], prefix: &[&str]) -> Option<&'a [String]> {
    (path.len() >= prefix.len() && path.iter().zip(prefix).all(|(part, p)| part == p))
        .then(|| &path[prefix.len()..])
}

/// One line as [`scan_line`] reads it.
#[derive(Debug)]
struct ScannedLine<'a> {
    /// The line before its comment, strings intact.
    code: &'a str,
    /// The delimiter of a multi-line string the line opens and leaves open.
    open: Option<&'static str>,
}

/// Split `line` into its code and comment, skipping strings: a `#` inside a
/// string is no comment, and a `"""` or `'''` inside a single-line string or a
/// comment opens no multi-line string.
fn scan_line(line: &str) -> Result<ScannedLine<'_>, String> {
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'#' => {
                return Ok(ScannedLine {
                    code: &line[..i],
                    open: None,
                });
            }
            quote @ (b'"' | b'\'') => {
                let triple = if quote == b'"' { "\"\"\"" } else { "'''" };
                if line[i..].starts_with(triple) {
                    match find_close(&line[i + 3..], triple) {
                        Some(end) => i += 3 + end,
                        None => {
                            return Ok(ScannedLine {
                                code: line,
                                open: Some(triple),
                            });
                        }
                    }
                } else {
                    i = string_end(line, i).ok_or_else(|| "an unclosed string".to_owned())?;
                }
            }
            _ => i += 1,
        }
    }
    Ok(ScannedLine {
        code: line,
        open: None,
    })
}

/// The byte index just past the single-line string starting at `start` (a
/// basic `"…"` with escapes, or a literal `'…'`); `None` when the line ends
/// first.
const fn string_end(line: &str, start: usize) -> Option<usize> {
    let bytes = line.as_bytes();
    let quote = bytes[start];
    let mut i = start + 1;
    while i < bytes.len() {
        if quote == b'"' && bytes[i] == b'\\' {
            i += 2;
        } else if bytes[i] == quote {
            return Some(i + 1);
        } else {
            i += 1;
        }
    }
    None
}

/// The byte index in `text` just past the `delimiter` that closes a multi-line
/// string (an escaped quote in a basic one doesn't close it), past the up to
/// two quotes TOML lets the content end with right before it (`"""a""""`);
/// `None` when `text` doesn't close it.
fn find_close(text: &str, delimiter: &str) -> Option<usize> {
    let basic = delimiter.starts_with('"');
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if basic && bytes[i] == b'\\' {
            i += 2;
        } else if text[i..].starts_with(delimiter) {
            let quote = bytes[i];
            let extra = bytes[i + 3..]
                .iter()
                .take(2)
                .take_while(|&&b| b == quote)
                .count();
            return Some(i + 3 + extra);
        } else {
            i += 1;
        }
    }
    None
}

/// The table name of a header line (`[a.b]` or `[[a.b]]`); `None` when `line`
/// is not a header.
fn parse_header(line: &str) -> Option<String> {
    let array = line.starts_with("[[");
    let body = line.strip_prefix(if array { "[[" } else { "[" })?;
    let (end, _) = find_unquoted(body, |c| c == ']')?;
    let rest = body[end..]
        .strip_prefix(if array { "]]" } else { "]" })?
        .trim();
    rest.is_empty().then(|| body[..end].to_owned())
}

/// The first char of `text` outside a quoted string that `stop` accepts, with
/// its byte index.
fn find_unquoted(text: &str, stop: impl Fn(char) -> bool) -> Option<(usize, char)> {
    let mut quote: Option<char> = None;
    for (i, c) in text.char_indices() {
        match quote {
            Some(q) => {
                if c == q {
                    quote = None;
                }
            }
            None if stop(c) => return Some((i, c)),
            None => {
                if c == '"' || c == '\'' {
                    quote = Some(c);
                }
            }
        }
    }
    None
}

/// Split a dotted TOML key path on the dots outside quotes, trimming each part
/// and unquoting a quoted one.
fn split_dotted(path: &str) -> Result<Vec<String>, String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    for c in path.chars() {
        match quote {
            Some(q) => {
                if c == q {
                    quote = None;
                }
                current.push(c);
            }
            None => match c {
                '"' | '\'' => {
                    quote = Some(c);
                    current.push(c);
                }
                '.' => parts.push(unquote(&std::mem::take(&mut current))?),
                _ => current.push(c),
            },
        }
    }
    if quote.is_some() {
        return Err(format!("the key `{path}` has an unclosed quote"));
    }
    parts.push(unquote(&current)?);
    Ok(parts)
}

/// One trimmed key part, unquoted when quoted.
fn unquote(part: &str) -> Result<String, String> {
    let part = part.trim();
    let unquoted = part
        .strip_prefix('"')
        .and_then(|p| p.strip_suffix('"'))
        .or_else(|| part.strip_prefix('\'').and_then(|p| p.strip_suffix('\'')));
    match unquoted {
        Some(inner) => Ok(inner.to_owned()),
        None if part.is_empty() => Err("an empty key part".to_owned()),
        None => Ok(part.to_owned()),
    }
}

/// Split `key = value` (a comment already dropped) at the first `=` outside
/// quotes; `None` without one.
fn split_key_value(line: &str) -> Option<(&str, &str)> {
    let (i, _) = find_unquoted(line, |c| c == '=')?;
    Some((line[..i].trim(), line[i + 1..].trim()))
}

/// A lint's whole value: `first`, continued onto the following `lines` while
/// an array it opens is still open (a `check-cfg` list), each continuation's
/// comment dropped.
fn lint_value<'a>(
    first: &str,
    lines: &mut impl Iterator<Item = (usize, &'a str)>,
) -> Result<String, String> {
    let mut value = first.to_owned();
    let mut open = Vec::new();
    track_brackets(first, &mut open);
    while let Some(&innermost) = open.last() {
        if innermost == b'{' {
            return Err(MULTI_LINE_INLINE_TABLE.to_owned());
        }
        let Some((_, next)) = lines.next() else {
            return Err("an array still open at the end of the file".to_owned());
        };
        let scanned = scan_line(next)?;
        if scanned.open.is_some() {
            return Err(MULTI_LINE_STRING.to_owned());
        }
        value.push('\n');
        value.push_str(scanned.code);
        track_brackets(scanned.code, &mut open);
    }
    Ok(value)
}

/// Push each `{` / `[` of `code` outside strings onto `open` and pop it at its
/// close.
fn track_brackets(code: &str, open: &mut Vec<u8>) {
    let bytes = code.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'"' | b'\'' => i = string_end(code, i).unwrap_or(bytes.len()),
            c @ (b'{' | b'[') => {
                open.push(c);
                i += 1;
            }
            b'}' | b']' => {
                open.pop();
                i += 1;
            }
            _ => i += 1,
        }
    }
}

/// A cursor over one lint's value.
struct Cursor<'a> {
    rest: &'a str,
}

impl Cursor<'_> {
    fn skip_ws(&mut self) {
        self.rest = self.rest.trim_start();
    }

    fn eat(&mut self, c: char) -> bool {
        self.skip_ws();
        self.rest.strip_prefix(c).is_some_and(|rest| {
            self.rest = rest;
            true
        })
    }

    /// A basic (`"…"`, `\"` and `\\` escapes) or literal (`'…'`) string.
    fn string(&mut self) -> Result<String, String> {
        self.skip_ws();
        let mut chars = self.rest.char_indices();
        let Some((_, quote @ ('"' | '\''))) = chars.next() else {
            return Err(format!("expected a string at `{}`", self.rest));
        };
        if self.rest.starts_with("\"\"\"") || self.rest.starts_with("'''") {
            return Err(MULTI_LINE_STRING.to_owned());
        }
        let mut out = String::new();
        let mut escaped = false;
        for (i, c) in chars {
            if escaped {
                match c {
                    '"' | '\\' => out.push(c),
                    _ => return Err(format!("the escape `\\{c}` in a lint setting")),
                }
                escaped = false;
            } else if quote == '"' && c == '\\' {
                escaped = true;
            } else if c == quote {
                self.rest = &self.rest[i + c.len_utf8()..];
                return Ok(out);
            } else {
                out.push(c);
            }
        }
        Err("an unclosed string".to_owned())
    }

    /// A decimal integer, optionally signed.
    fn integer(&mut self) -> Result<i64, String> {
        self.skip_ws();
        let end = self
            .rest
            .char_indices()
            .find(|&(i, c)| !(c.is_ascii_digit() || (i == 0 && (c == '-' || c == '+'))))
            .map_or(self.rest.len(), |(i, _)| i);
        let (digits, rest) = self.rest.split_at(end);
        let value = digits
            .parse()
            .map_err(|_| format!("expected an integer at `{}`", self.rest))?;
        self.rest = rest;
        Ok(value)
    }

    /// An array, read past without its elements: brackets matched, strings
    /// skipped.
    fn skip_array(&mut self) -> Result<(), String> {
        self.skip_ws();
        if !self.rest.starts_with('[') {
            return Err(format!("expected an array at `{}`", self.rest));
        }
        let bytes = self.rest.as_bytes();
        let mut depth = 0usize;
        let mut i = 0;
        while i < bytes.len() {
            match bytes[i] {
                b'"' | b'\'' => {
                    i = string_end(self.rest, i).ok_or_else(|| "an unclosed string".to_owned())?;
                    continue;
                }
                b'[' => depth += 1,
                b']' => {
                    depth -= 1;
                    if depth == 0 {
                        self.rest = &self.rest[i + 1..];
                        return Ok(());
                    }
                }
                _ => {}
            }
            i += 1;
        }
        Err("an unclosed array".to_owned())
    }

    /// A bare or quoted key.
    fn key(&mut self) -> Result<String, String> {
        self.skip_ws();
        if self.rest.starts_with(['"', '\'']) {
            return self.string();
        }
        let end = self
            .rest
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '-'))
            .unwrap_or(self.rest.len());
        if end == 0 {
            return Err(format!("expected a key at `{}`", self.rest));
        }
        let (key, rest) = self.rest.split_at(end);
        self.rest = rest;
        Ok(key.to_owned())
    }

    /// Nothing left but whitespace.
    fn finish(&mut self) -> Result<(), String> {
        self.skip_ws();
        if self.rest.is_empty() {
            Ok(())
        } else {
            Err(format!("unexpected `{}` after the lint setting", self.rest))
        }
    }
}

/// The refusal of an inline table left open at the end of its line.
const MULTI_LINE_INLINE_TABLE: &str = "an inline table spanning lines outside its `check-cfg` \
                                       array, which the lint-table reader doesn't understand";

/// The refusal of a multi-line string in a lint's value.
const MULTI_LINE_STRING: &str =
    "a multi-line string in a lint's value, which the lint-table reader doesn't understand";

/// The keys of one lint's table (inline or a sub-table), as read so far.
#[derive(Debug, Default)]
struct SettingParts {
    level: Option<String>,
    priority: Option<i64>,
    check_cfg: bool,
}

impl SettingParts {
    /// Read the value of `key` at `cursor`.
    fn set(&mut self, key: &str, cursor: &mut Cursor<'_>) -> Result<(), String> {
        let repeated = match key {
            "level" => self.level.replace(cursor.string()?).is_some(),
            "priority" => self.priority.replace(cursor.integer()?).is_some(),
            "check-cfg" => {
                cursor.skip_array()?;
                std::mem::replace(&mut self.check_cfg, true)
            }
            other => {
                return Err(format!(
                    "the key `{other}` in a lint's table; the lint-table reader understands \
                     `level`, `priority`, and `check-cfg`"
                ));
            }
        };
        if repeated {
            Err(format!("`{key}` is set twice in one lint's table"))
        } else {
            Ok(())
        }
    }

    /// The setting, once every key is read.
    fn finish(self) -> Result<LintSetting, String> {
        let level = self.level.ok_or("a lint's table without a `level`")?;
        check_level(&level)?;
        Ok(LintSetting {
            level,
            priority: self.priority.unwrap_or(0),
        })
    }
}

/// Refuse a level Cargo doesn't accept.
fn check_level(level: &str) -> Result<(), String> {
    if LEVELS.contains(&level) {
        Ok(())
    } else {
        Err(format!("the lint level `{level}`"))
    }
}

/// One lint's value: `"level"` or an inline table of `level`, `priority`, and
/// `check-cfg`, keys in any order.
fn parse_setting(value: &str) -> Result<LintSetting, String> {
    let mut cursor = Cursor { rest: value };
    let setting = if cursor.eat('{') {
        let mut parts = SettingParts::default();
        if !cursor.eat('}') {
            loop {
                let key = cursor.key()?;
                if !cursor.eat('=') {
                    return Err(format!("expected `=` after `{key}`"));
                }
                parts.set(&key, &mut cursor)?;
                if cursor.eat('}') {
                    break;
                }
                if !cursor.eat(',') {
                    return Err(format!("expected `,` or `}}` at `{}`", cursor.rest));
                }
            }
        }
        parts.finish()?
    } else if cursor.rest.starts_with(['"', '\'']) {
        let level = cursor.string()?;
        check_level(&level)?;
        LintSetting { level, priority: 0 }
    } else {
        return Err(format!(
            "the lint value `{value}`; the lint-table reader understands a level string or \
             a `{{ level = …, priority = …, check-cfg = … }}` table"
        ));
    };
    cursor.finish()?;
    Ok(setting)
}

/// The lint-attribute names whose argument list, naming `unsafe_code`, lifts it.
const LIFTING_ATTRIBUTES: &[&str] = &["allow", "expect", "warn"];

/// The text of every crate-root inner attribute in `source` that lifts
/// `unsafe_code`, whitespace removed: one whose `allow(…)`, `expect(…)`, or
/// `warn(…)` argument list names it, at any depth (inside `cfg_attr`
/// included), so `#![cfg_attr(x, deny(unsafe_code), allow(dead_code))]` is
/// not one.
///
/// Reads only the file's leading run of inner attributes, comments, and
/// whitespace (past a byte-order mark and a first-line shebang): an inner
/// attribute anywhere else is not a crate-root attribute, and stopping at the
/// first item keeps the rest of the file out of the scan. Inside an attribute,
/// strings (raw ones included), char literals, and comments are skipped.
pub fn crate_root_unsafe_lifts(source: &str) -> Vec<String> {
    let mut lifts = Vec::new();
    let mut rest = source.strip_prefix('\u{feff}').unwrap_or(source);
    if rest.starts_with("#!") && !skip_trivia(&rest[2..]).starts_with('[') {
        rest = rest.find('\n').map_or("", |end| &rest[end..]);
    }
    loop {
        rest = skip_trivia(rest);
        let Some(body) = rest
            .strip_prefix('#')
            .map(skip_trivia)
            .and_then(|r| r.strip_prefix('!'))
            .map(skip_trivia)
        else {
            break;
        };
        let Some(inside) = body.strip_prefix('[') else {
            break;
        };
        let mut tokenizer = Tokenizer { rest: inside };
        let Some(tokens) = tokenizer.group(']') else {
            break;
        };
        if lifts_unsafe_code(&tokens) {
            let attribute = &body[..body.len() - tokenizer.rest.len()];
            let compact: String = attribute.chars().filter(|c| !c.is_whitespace()).collect();
            lifts.push(format!("#!{compact}"));
        }
        rest = tokenizer.rest;
    }
    lifts
}

/// Whether `tokens` hold a lifting attribute (`allow` / `expect` / `warn`)
/// whose argument list names `unsafe_code`, at any depth.
fn lifts_unsafe_code(tokens: &[Token]) -> bool {
    tokens.iter().enumerate().any(|(i, token)| match token {
        Token::Ident(name) if LIFTING_ATTRIBUTES.contains(&name.as_str()) => matches!(
            tokens.get(i + 1),
            Some(Token::Group(args))
                if args.iter().any(|arg| matches!(arg, Token::Ident(n) if n == UNSAFE_CODE.1))
        ),
        Token::Group(inner) => lifts_unsafe_code(inner),
        _ => false,
    })
}

/// `text` past its leading whitespace and comments.
fn skip_trivia(mut text: &str) -> &str {
    loop {
        text = text.trim_start();
        if let Some(comment) = text.strip_prefix("//") {
            text = comment.find('\n').map_or("", |end| &comment[end..]);
        } else if text.starts_with("/*") {
            text = skip_block_comment(text);
        } else {
            return text;
        }
    }
}

/// `text` (starting `/*`) past its block comment, nested ones included.
fn skip_block_comment(text: &str) -> &str {
    let mut depth = 0usize;
    let mut i = 0;
    let bytes = text.as_bytes();
    while i + 1 < bytes.len() {
        match (bytes[i], bytes[i + 1]) {
            (b'/', b'*') => {
                depth += 1;
                i += 2;
            }
            (b'*', b'/') => {
                depth -= 1;
                i += 2;
                if depth == 0 {
                    return &text[i..];
                }
            }
            _ => i += 1,
        }
    }
    ""
}

/// One token of an attribute, as far as the lift scan needs: an identifier, a
/// delimited group, or anything else (punctuation, a literal).
#[derive(Debug)]
enum Token {
    Ident(String),
    Group(Vec<Self>),
    Other,
}

/// A tokenizer over an attribute's text.
struct Tokenizer<'a> {
    rest: &'a str,
}

impl Tokenizer<'_> {
    /// The tokens up to `close`, consuming it; `None` when the text ends first
    /// or a different delimiter closes the group.
    fn group(&mut self, close: char) -> Option<Vec<Token>> {
        let mut tokens = Vec::new();
        loop {
            self.rest = skip_trivia(self.rest);
            let c = self.rest.chars().next()?;
            let after = &self.rest[c.len_utf8()..];
            match c {
                ')' | ']' | '}' => {
                    self.rest = after;
                    return (c == close).then_some(tokens);
                }
                '(' | '[' | '{' => {
                    self.rest = after;
                    let inner = self.group(match c {
                        '(' => ')',
                        '[' => ']',
                        _ => '}',
                    })?;
                    tokens.push(Token::Group(inner));
                }
                '"' => {
                    self.rest = skip_rust_string(after)?;
                    tokens.push(Token::Other);
                }
                '\'' => {
                    self.rest = skip_char_or_lifetime(after);
                    tokens.push(Token::Other);
                }
                c if c.is_alphabetic() || c == '_' => {
                    let end = self
                        .rest
                        .find(|c: char| !(c.is_alphanumeric() || c == '_'))
                        .unwrap_or(self.rest.len());
                    let (word, after_word) = self.rest.split_at(end);
                    self.rest = after_word;
                    match (word, after_word.chars().next()) {
                        ("r" | "br" | "cr", Some('"' | '#')) => {
                            if let Some(after_raw) = skip_raw_string(after_word) {
                                self.rest = after_raw;
                                tokens.push(Token::Other);
                            } else {
                                // a raw identifier, `r#name`
                                self.rest = &after_word[1..];
                            }
                        }
                        ("b" | "c", Some('"')) => {
                            self.rest = skip_rust_string(&after_word[1..])?;
                            tokens.push(Token::Other);
                        }
                        _ => tokens.push(Token::Ident(word.to_owned())),
                    }
                }
                _ => {
                    self.rest = after;
                    tokens.push(Token::Other);
                }
            }
        }
    }
}

/// `text` (just past a string's opening `"`) past its closing `"`, escapes
/// skipped; `None` when it never closes.
fn skip_rust_string(text: &str) -> Option<&str> {
    let mut chars = text.char_indices();
    while let Some((i, c)) = chars.next() {
        match c {
            '\\' => {
                chars.next();
            }
            '"' => return Some(&text[i + 1..]),
            _ => {}
        }
    }
    None
}

/// `text` (just past a raw string's `r` / `br` / `cr`) past the raw string
/// `#…#"…"#…#`; `None` when it isn't one (a raw identifier) or never closes.
fn skip_raw_string(text: &str) -> Option<&str> {
    let hashes = text.len() - text.trim_start_matches('#').len();
    let body = text[hashes..].strip_prefix('"')?;
    let closing = format!("\"{}", "#".repeat(hashes));
    body.find(&closing).map(|end| &body[end + closing.len()..])
}

/// `text` (just past a `'`) past a char literal (`'x'`, `'\n'`), or past just
/// the quote for a lifetime.
fn skip_char_or_lifetime(text: &str) -> &str {
    let mut chars = text.char_indices();
    match chars.next() {
        Some((_, '\\')) => {
            chars.next();
            chars
                .find(|&(_, c)| c == '\'')
                .map_or("", |(i, _)| &text[i + 1..])
        }
        Some((_, _)) => match chars.next() {
            Some((i, '\'')) => &text[i + 1..],
            _ => text,
        },
        None => text,
    }
}

/// A re-declaring crate breaking one of the pass's rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LintTableViolation {
    /// Its tool tables differ from the workspace's.
    Tools {
        /// The crate.
        package: String,
        /// Workspace tools the crate has no table for.
        missing: Vec<String>,
        /// Tools the crate has a table for and the workspace doesn't.
        extra: Vec<String>,
    },
    /// It doesn't declare a lint the workspace sets.
    Dropped {
        /// The crate.
        package: String,
        /// The lint's tool.
        tool: String,
        /// The lint.
        lint: String,
        /// The workspace's setting.
        workspace: LintSetting,
    },
    /// It sets a lint the workspace sets at another level or priority.
    Changed {
        /// The crate.
        package: String,
        /// The lint's tool.
        tool: String,
        /// The lint.
        lint: String,
        /// The workspace's setting.
        workspace: LintSetting,
        /// The crate's setting.
        own: LintSetting,
    },
    /// It sets [`UNSAFE_CODE`] below `deny`, or at a priority other than the
    /// workspace's.
    UnsafeCode {
        /// The crate.
        package: String,
        /// The workspace's setting.
        workspace: LintSetting,
        /// The crate's setting.
        own: LintSetting,
    },
    /// Its `unsafe_code` isn't `forbid` and a crate root lifts it crate-wide.
    CrateRootLift {
        /// The crate.
        package: String,
        /// The crate root file.
        path: PathBuf,
        /// The attribute, whitespace removed.
        attribute: String,
    },
}

/// The rule every drift message ends with.
const MIRROR_RULE: &str = "mirror every workspace lint; only `rust.unsafe_code` may differ, \
                           and only to \"deny\" or \"forbid\"";

impl fmt::Display for LintTableViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tools {
                package,
                missing,
                extra,
            } => {
                write!(
                    f,
                    "crate `{package}` re-declares its lint tables, but its tools differ \
                     from the workspace's:"
                )?;
                if !missing.is_empty() {
                    write!(f, " no [lints.{}]", missing.join("], [lints."))?;
                }
                if !extra.is_empty() {
                    if !missing.is_empty() {
                        write!(f, ";")?;
                    }
                    write!(
                        f,
                        " [lints.{}] has no [workspace.lints.*] counterpart",
                        extra.join("], [lints.")
                    )?;
                }
                write!(
                    f,
                    " — Cargo replaces a crate's [lints] whole, so the copy carries every \
                     workspace tool table and no other"
                )
            }
            Self::Dropped {
                package,
                tool,
                lint,
                workspace,
            } => write!(
                f,
                "crate `{package}` re-declares its lint tables but drops `{tool}.{lint}` \
                 (the workspace sets {workspace}) — {MIRROR_RULE}",
            ),
            Self::Changed {
                package,
                tool,
                lint,
                workspace,
                own,
            } => write!(
                f,
                "crate `{package}` sets `{tool}.{lint}` = {own}, but the workspace sets \
                 {workspace} — {MIRROR_RULE}",
            ),
            Self::UnsafeCode {
                package,
                workspace,
                own,
            } => write!(
                f,
                "crate `{package}` sets `rust.unsafe_code` = {own} (the workspace sets \
                 {workspace}); a re-declaring crate keeps it at \"deny\" or \"forbid\" at \
                 the workspace's priority ({}) — set it to \"deny\" and lift it on each item \
                 that needs `unsafe` with `#[expect(unsafe_code, reason = \"…\")]`",
                workspace.priority,
            ),
            Self::CrateRootLift {
                package,
                path,
                attribute,
            } => write!(
                f,
                "crate `{package}` relaxes `unsafe_code` from `forbid` and lifts it \
                 crate-wide with `{attribute}` in {} — lift it on each item that needs it \
                 with `#[expect(unsafe_code, reason = \"…\")]` instead",
                path.display(),
            ),
        }
    }
}

/// A re-declaring crate the pass checked, with how its tables differ from the
/// workspace's where they may.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckedCrate {
    /// The crate.
    pub package: String,
    /// Its permitted differences, one line each: the `unsafe_code` level and
    /// each added lint.
    pub differences: Vec<String>,
}

/// The lint-table pass's outcome. The default, empty, is also the report of
/// the dependency-graph passes alone, as their unit tests build.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LintTablesReport {
    /// The re-declaring members checked, in member order.
    pub checked: Vec<CheckedCrate>,
    /// The re-declaring members not checked because the workspace manifest has
    /// no `[workspace.lints]` to hold them to.
    pub unchecked: Vec<String>,
    /// The members that take `[lints] workspace = true`.
    pub inheriting: Vec<String>,
    /// The members with no lint table at all, to which no lint table applies.
    pub without_lints: Vec<String>,
    /// Every rule broken.
    pub violations: Vec<LintTableViolation>,
}

impl LintTablesReport {
    /// `true` when no rule is broken.
    pub const fn is_clean(&self) -> bool {
        self.violations.is_empty()
    }
}

/// Compare one re-declaring crate's tables to the workspace's: the violations,
/// and the permitted differences to list.
fn compare_tables(
    package: &str,
    workspace: &LintTables,
    own: &LintTables,
) -> (Vec<LintTableViolation>, Vec<String>) {
    let mut violations = Vec::new();
    let mut differences = Vec::new();
    let workspace_tools: BTreeSet<&String> = workspace.keys().collect();
    let own_tools: BTreeSet<&String> = own.keys().collect();
    if workspace_tools != own_tools {
        violations.push(LintTableViolation::Tools {
            package: package.to_owned(),
            missing: workspace_tools
                .difference(&own_tools)
                .map(|t| (*t).clone())
                .collect(),
            extra: own_tools
                .difference(&workspace_tools)
                .map(|t| (*t).clone())
                .collect(),
        });
    }
    for (tool, own_table) in own {
        let Some(workspace_table) = workspace.get(tool) else {
            continue;
        };
        for (lint, expected) in workspace_table {
            match own_table.get(lint) {
                None => violations.push(LintTableViolation::Dropped {
                    package: package.to_owned(),
                    tool: tool.clone(),
                    lint: lint.clone(),
                    workspace: expected.clone(),
                }),
                Some(actual) if actual == expected => {}
                Some(actual) if (tool.as_str(), lint.as_str()) == UNSAFE_CODE => {
                    if UNSAFE_CODE_LEVELS.contains(&actual.level.as_str())
                        && actual.priority == expected.priority
                    {
                        differences
                            .push(format!("{tool}.{lint} = {actual} (workspace: {expected})"));
                    } else {
                        violations.push(LintTableViolation::UnsafeCode {
                            package: package.to_owned(),
                            workspace: expected.clone(),
                            own: actual.clone(),
                        });
                    }
                }
                Some(actual) => violations.push(LintTableViolation::Changed {
                    package: package.to_owned(),
                    tool: tool.clone(),
                    lint: lint.clone(),
                    workspace: expected.clone(),
                    own: actual.clone(),
                }),
            }
        }
        for (lint, setting) in own_table {
            if !workspace_table.contains_key(lint) {
                differences.push(format!("adds {tool}.{lint} = {setting}"));
            }
        }
    }
    (violations, differences)
}

/// The lint-table pass over the workspace `metadata` (`cargo metadata`'s
/// output), reading each manifest and crate root through `read`. The root
/// manifest is read at the first re-declaring member, not before.
///
/// # Errors
///
/// [`AuditError::MetadataShape`] when the metadata lacks the workspace root or a
/// member's manifest path, [`AuditError::ReadFile`] when a file can't be read,
/// and [`AuditError::LintTableShape`] when a manifest's lint tables are in a
/// shape the reader doesn't understand.
pub fn audit_lint_tables(
    metadata: &Value,
    read: &dyn Fn(&Path) -> io::Result<String>,
) -> Result<LintTablesReport, AuditError> {
    let root = metadata
        .get("workspace_root")
        .and_then(Value::as_str)
        .ok_or(AuditError::MetadataShape("workspace_root missing"))?;
    let root_manifest = Path::new(root).join("Cargo.toml");
    // `None` until the first re-declaring member; then the workspace's
    // tables, `None` inside when it has no `[workspace.lints]`
    let mut workspace: Option<Option<LintTables>> = None;

    let members = super::workspace_member_ids(metadata)?;
    let packages = metadata
        .get("packages")
        .and_then(Value::as_array)
        .ok_or(AuditError::MetadataShape("packages array missing"))?;
    let mut report = LintTablesReport::default();
    for package in packages {
        let Some(id) = package.get("id").and_then(Value::as_str) else {
            continue;
        };
        if !members.contains(id) {
            continue;
        }
        let name = package
            .get("name")
            .and_then(Value::as_str)
            .ok_or(AuditError::MetadataShape("package name missing"))?
            .to_owned();
        let manifest = package
            .get("manifest_path")
            .and_then(Value::as_str)
            .ok_or(AuditError::MetadataShape("package manifest_path missing"))?;
        let own = match read_manifest_lints(read, Path::new(manifest), LintScope::Package)? {
            ManifestLints::Absent => {
                report.without_lints.push(name);
                continue;
            }
            ManifestLints::Inherits => {
                report.inheriting.push(name);
                continue;
            }
            ManifestLints::Tables(own) => own,
        };
        if workspace.is_none() {
            workspace = Some(
                match read_manifest_lints(read, &root_manifest, LintScope::Workspace)? {
                    ManifestLints::Tables(tables) => Some(tables),
                    ManifestLints::Absent | ManifestLints::Inherits => None,
                },
            );
        }
        let Some(Some(workspace)) = &workspace else {
            report.unchecked.push(name);
            continue;
        };
        let (violations, differences) = compare_tables(&name, workspace, &own);
        report.violations.extend(violations);

        let unsafe_code_forbidden = own
            .get(UNSAFE_CODE.0)
            .and_then(|table| table.get(UNSAFE_CODE.1))
            .is_some_and(|setting| setting.level == "forbid");
        if !unsafe_code_forbidden {
            for path in crate_roots(package) {
                for attribute in crate_root_unsafe_lifts(&read_audited(read, &path)?) {
                    report.violations.push(LintTableViolation::CrateRootLift {
                        package: name.clone(),
                        path: path.clone(),
                        attribute,
                    });
                }
            }
        }
        report.checked.push(CheckedCrate {
            package: name,
            differences,
        });
    }
    Ok(report)
}

/// `path`'s text through `read`, a failure as [`AuditError::ReadFile`].
fn read_audited(
    read: &dyn Fn(&Path) -> io::Result<String>,
    path: &Path,
) -> Result<String, AuditError> {
    read(path).map_err(|source| AuditError::ReadFile {
        path: path.to_owned(),
        source,
    })
}

/// The lint tables of `scope` in the manifest at `path`.
fn read_manifest_lints(
    read: &dyn Fn(&Path) -> io::Result<String>,
    path: &Path,
    scope: LintScope,
) -> Result<ManifestLints, AuditError> {
    read_lints(&read_audited(read, path)?, scope).map_err(|source| AuditError::LintTableShape {
        path: path.to_owned(),
        source,
    })
}

/// The root files of `package`'s lib and bin targets, each once.
fn crate_roots(package: &Value) -> Vec<PathBuf> {
    let mut roots: Vec<PathBuf> = Vec::new();
    for target in package
        .get("targets")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let is_root = target
            .get("kind")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .any(|kind| CRATE_ROOT_KINDS.contains(&kind));
        if let (true, Some(path)) = (is_root, target.get("src_path").and_then(Value::as_str)) {
            let path = PathBuf::from(path);
            if !roots.contains(&path) {
                roots.push(path);
            }
        }
    }
    roots
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn setting(level: &str, priority: i64) -> LintSetting {
        LintSetting {
            level: level.into(),
            priority,
        }
    }

    fn tables(text: &str, scope: LintScope) -> LintTables {
        match read_lints(text, scope).unwrap() {
            ManifestLints::Tables(tables) => tables,
            other => panic!("expected tables, got {other:?}"),
        }
    }

    // ── the reader ──────────────────────────────────────────────────

    #[test]
    fn reader_reads_tables_by_section_and_normalizes_values() {
        let text = "[package]\nname = \"x\"\n\n[workspace.lints.rust]\n# a comment\n\
                    unsafe_code = \"forbid\" # trailing\n\n[workspace.lints.clippy]\n\
                    all = { level = \"warn\", priority = -1 }\n\
                    pedantic = {priority=-1,level='warn'}\n\
                    one = { level = \"warn\", priority = 0 }\n\
                    [profile.release]\nlto = true\n";
        let read = tables(text, LintScope::Workspace);
        assert_eq!(read.len(), 2);
        assert_eq!(read["rust"]["unsafe_code"], setting("forbid", 0));
        assert_eq!(read["clippy"]["all"], setting("warn", -1));
        assert_eq!(read["clippy"]["all"], read["clippy"]["pedantic"]);
        assert_eq!(read["clippy"]["one"], setting("warn", 0));
        assert_eq!(
            read_lints(text, LintScope::Package),
            Ok(ManifestLints::Absent)
        );
    }

    #[test]
    fn reader_reads_a_package_s_inherit_and_own_forms() {
        assert_eq!(
            read_lints("[lints]\nworkspace = true # yes\n", LintScope::Package),
            Ok(ManifestLints::Inherits)
        );
        let own = tables(
            "[lints.rust]\nunsafe_code = \"deny\"\n[lints.rustdoc]\n",
            LintScope::Package,
        );
        assert_eq!(own["rust"]["unsafe_code"], setting("deny", 0));
        assert!(own["rustdoc"].is_empty());
        assert_eq!(
            read_lints("[package]\n", LintScope::Package),
            Ok(ManifestLints::Absent)
        );
    }

    #[test]
    fn reader_passes_quoted_headers_multiline_values_and_strings_elsewhere() {
        let text = "[package]\ndescription = \"\"\"\n[lints.rust]\nx = 1\n\"\"\"\n\
                    [target.'cfg(unix)'.dependencies]\nlibc = { version = \"0.2\" }\n\
                    [features]\ndefault = [\n  \"a\",\n]\n[lints.rust]\ny = \"warn\"\n";
        let own = tables(text, LintScope::Package);
        assert_eq!(own.len(), 1);
        assert_eq!(own["rust"].keys().collect::<Vec<_>>(), ["y"]);
    }

    #[test]
    fn reader_refuses_shapes_it_does_not_understand() {
        for (text, scope, needle) in [
            (
                "[lints.clippy]\nall = { level = \"warn\",\n  priority = -1 }\n",
                LintScope::Package,
                "spanning lines",
            ),
            (
                "[lints.clippy]\nall = {\n",
                LintScope::Package,
                "spanning lines",
            ),
            (
                "[lints]\nrust.unsafe_code = \"deny\"\n",
                LintScope::Package,
                "dotted key",
            ),
            (
                "[lints.rust]\na.b = \"warn\"\n",
                LintScope::Package,
                "dotted key",
            ),
            (
                "[workspace]\nlints.rust.unsafe_code = \"forbid\"\n",
                LintScope::Workspace,
                "outside",
            ),
            (
                "lints = { workspace = true }\n",
                LintScope::Package,
                "outside",
            ),
            (
                "[lints.rust]\nx = { level = \"warn\", other = 1 }\n",
                LintScope::Package,
                "the key `other`",
            ),
            (
                "[lints.rust.x]\nlevel = \"warn\"\nreason = \"y\"\n",
                LintScope::Package,
                "the key `reason`",
            ),
            (
                "[lints.rust]\nx = \"\"\"warn\"\"\"\n",
                LintScope::Package,
                "multi-line string in a lint's value",
            ),
            (
                "[lints.rust]\nx = { level = \"warn\", check-cfg = [\n",
                LintScope::Package,
                "still open at the end",
            ),
            (
                "[package]\ndescription = \"\"\"\nnever closed\n",
                LintScope::Package,
                "multi-line string still open",
            ),
            (
                "[lints.rust]\nx = \"warn\"\n[lints.rust.x]\nlevel = \"deny\"\n",
                LintScope::Package,
                "set twice",
            ),
            (
                "[lints.rust]\nx = [\"warn\"]\n",
                LintScope::Package,
                "understands a level",
            ),
            (
                "[lints.rust]\nx = \"loud\"\n",
                LintScope::Package,
                "level `loud`",
            ),
            (
                "[lints.rust]\nx = \"warn\"\nx = \"deny\"\n",
                LintScope::Package,
                "set twice",
            ),
            ("[lints.rust.x]\n", LintScope::Package, "without a `level`"),
            ("[lints.rust.x.y]\n", LintScope::Package, "nests"),
            (
                "[lints.rust]\n[lints.rust]\n",
                LintScope::Package,
                "declared twice",
            ),
            (
                "[lints]\nworkspace = true\n[lints.rust]\nx = \"warn\"\n",
                LintScope::Package,
                "both",
            ),
            ("[lints]\nworkspace = false\n", LintScope::Package, "only"),
            (
                "[workspace.lints]\nrust = { x = \"warn\" }\n",
                LintScope::Workspace,
                "directly under",
            ),
            (
                "[lints.clippy]\nall = { priority = -1 }\n",
                LintScope::Package,
                "without a `level`",
            ),
        ] {
            let err = read_lints(text, scope).expect_err(text);
            assert!(err.message.contains(needle), "{text:?}: {err}");
        }
    }

    #[test]
    fn reader_reads_check_cfg_inline_multi_line_and_as_a_sub_table() {
        let workspace = tables(
            "[workspace.lints.rust]\nunsafe_code = \"forbid\"\n\
             unexpected_cfgs = { level = \"warn\", check-cfg = ['cfg(foo)', \"cfg(b, values(\\\"]\\\"))\"] }\n\
             spread = { level = \"warn\", check-cfg = [\n  'cfg(a)', # a ] comment\n  'cfg(b)',\n], priority = 1 }\n\
             [workspace.lints.clippy.all]\nlevel = \"warn\"\npriority = -1\ncheck-cfg = [\n  'x',\n]\n\
             [workspace.lints.clippy]\npanic = \"warn\"\n",
            LintScope::Workspace,
        );
        assert_eq!(workspace["rust"]["unexpected_cfgs"], setting("warn", 0));
        assert_eq!(workspace["rust"]["spread"], setting("warn", 1));
        assert_eq!(workspace["clippy"]["all"], setting("warn", -1));
        assert_eq!(workspace["clippy"]["panic"], setting("warn", 0));

        // the sub-table form of a lint, its `check-cfg` list different, is the
        // same setting as the workspace's inline one
        let own = tables(
            "[lints.rust.unexpected_cfgs]\nlevel = 'warn'\ncheck-cfg = ['cfg(other)']\n",
            LintScope::Package,
        );
        assert_eq!(
            own["rust"]["unexpected_cfgs"],
            workspace["rust"]["unexpected_cfgs"]
        );
    }

    #[test]
    fn reader_skips_triple_quotes_inside_strings_and_comments() {
        let workspace = tables(
            "[workspace]\nx = '\"\"\"'\ny = \"a\\\"\\\"\\\"b\"\n\
             [workspace.lints.rust]\nunsafe_code = \"forbid\"\n",
            LintScope::Workspace,
        );
        assert_eq!(workspace["rust"]["unsafe_code"], setting("forbid", 0));
        let own = tables(
            "[package]\nname = \"a\" # see \"\"\"\n[lints.rust]\nunsafe_code = \"allow\"\n",
            LintScope::Package,
        );
        assert_eq!(own["rust"]["unsafe_code"], setting("allow", 0));
        // a multi-line string's content may end in one or two of its quotes,
        // closed on its opening line or a later one
        for text in [
            "[package]\ndescription = \"\"\"He said \"hi\"\"\"\"\n[lints.rust]\nx = \"warn\"\n",
            "[package]\nd = '''a''''\n[lints.rust]\nx = \"warn\"\n",
            "[package]\nd = '''\na'''''\n[lints.rust]\nx = \"warn\"\n",
            "[package]\nd = \"\"\"\na\"\"\"\"\" # c\n[lints.rust]\nx = \"warn\"\n",
        ] {
            let own = tables(text, LintScope::Package);
            assert_eq!(own["rust"]["x"], setting("warn", 0), "{text}");
        }
        // a real multi-line string still hides what it holds
        let own = tables(
            "[package]\nd = '''\n[lints.clippy]\n''' # closed\n[lints.rust]\nx = \"warn\"\n",
            LintScope::Package,
        );
        assert_eq!(own.keys().collect::<Vec<_>>(), ["rust"]);
    }

    #[test]
    fn crate_root_scan_handles_raw_strings_a_bom_and_cfg_attr_argument_lists() {
        assert_eq!(
            crate_root_unsafe_lifts("#![doc = r#\"a \" ]\"#]\n#![allow(unsafe_code)]\n"),
            ["#![allow(unsafe_code)]"]
        );
        assert_eq!(
            crate_root_unsafe_lifts("\u{feff}#![allow(unsafe_code)]\n"),
            ["#![allow(unsafe_code)]"]
        );
        assert!(
            crate_root_unsafe_lifts(
                "#![cfg_attr(x, deny(unsafe_code), allow(dead_code))]\n\
                 #![expect(dead_code, reason = \"unsafe_code\")]\nfn f() {}\n"
            )
            .is_empty()
        );
        assert_eq!(
            crate_root_unsafe_lifts("#![cfg_attr(x, deny(dead_code), warn(unsafe_code))]\n"),
            ["#![cfg_attr(x,deny(dead_code),warn(unsafe_code))]"]
        );
    }

    #[test]
    fn crate_root_lifts_are_read_from_the_leading_inner_attributes() {
        let source = "#!/usr/bin/env run\n//! docs quoting `#![allow(unsafe_code)]`\n\
                      /* a /* nested */ block */\n#![allow(unsafe_code)]\n\
                      #![expect(\n    unsafe_code,\n    reason = \"a ] bracket\"\n)]\n\
                      #![cfg_attr(test, allow(unsafe_code))]\n#![deny(unsafe_code)]\n\
                      #![warn(missing_docs)]\nfn f() {}\nconst S: &str = \"#![allow(unsafe_code)]\";\n";
        assert_eq!(
            crate_root_unsafe_lifts(source),
            [
                "#![allow(unsafe_code)]",
                "#![expect(unsafe_code,reason=\"a]bracket\")]",
                "#![cfg_attr(test,allow(unsafe_code))]",
            ]
        );
        assert!(crate_root_unsafe_lifts("//! no attributes\nuse std::fmt;\n").is_empty());
    }

    // ── the rules, over a workspace fixture ─────────────────────────

    const WORKSPACE: &str = "[workspace]\nmembers = [\"crates/*\"]\n\n\
                             [workspace.lints.rust]\nunsafe_code = \"forbid\"\n\
                             trivial_casts = \"warn\"\n\n[workspace.lints.rustdoc]\n\
                             bare_urls = \"deny\"\n\n[workspace.lints.clippy]\n\
                             all = { level = \"warn\", priority = -1 }\npanic = \"warn\"\n";

    /// The boundary-crate table: the workspace's, `unsafe_code` at `deny`, and
    /// `undocumented_unsafe_blocks` added.
    const BOUNDARY: &str = "[package]\nname = \"boundary\"\n\n[lints.rust]\n\
                            unsafe_code = \"deny\"\ntrivial_casts = \"warn\"\n\n\
                            [lints.rustdoc]\nbare_urls = \"deny\"\n\n[lints.clippy]\n\
                            all = { priority = -1, level = \"warn\" }\npanic = \"warn\"\n\
                            undocumented_unsafe_blocks = \"warn\"\n";

    const BOUNDARY_LIB: &str = "//! A boundary crate.\n\n#[expect(unsafe_code, reason = \"x\")]\n\
                                pub fn f() {}\n";

    /// A workspace of `boundary` (manifest `boundary`, lib root `lib`), an
    /// inheriting `plain`, and a lint-less `bare`; `root` replaces the
    /// workspace manifest.
    fn audit_fixture(root: &str, boundary: &str, lib: &str) -> LintTablesReport {
        audit_files(Some(root), boundary, lib).unwrap()
    }

    /// [`audit_fixture`]'s workspace, the root manifest absent when `root` is
    /// `None`.
    fn audit_files(
        root: Option<&str>,
        boundary: &str,
        lib: &str,
    ) -> Result<LintTablesReport, AuditError> {
        let metadata = serde_json::json!({
            "workspace_root": "/ws",
            "workspace_members": ["boundary#0.1.0", "plain#0.1.0", "bare#0.1.0"],
            "packages": [
                {
                    "name": "boundary",
                    "id": "boundary#0.1.0",
                    "manifest_path": "/ws/crates/boundary/Cargo.toml",
                    "targets": [
                        {"kind": ["lib"], "src_path": "/ws/crates/boundary/src/lib.rs"},
                        {"kind": ["test"], "src_path": "/ws/crates/boundary/tests/t.rs"},
                    ],
                },
                {
                    "name": "plain",
                    "id": "plain#0.1.0",
                    "manifest_path": "/ws/crates/plain/Cargo.toml",
                    "targets": [],
                },
                {
                    "name": "bare",
                    "id": "bare#0.1.0",
                    "manifest_path": "/ws/crates/bare/Cargo.toml",
                    "targets": [],
                },
                {
                    "name": "outside",
                    "id": "outside#0.1.0",
                    "manifest_path": "/elsewhere/Cargo.toml",
                    "targets": [],
                },
            ],
        });
        let files: HashMap<PathBuf, String> = [
            ("/ws/Cargo.toml", root.unwrap_or_default()),
            ("/ws/crates/boundary/Cargo.toml", boundary),
            ("/ws/crates/boundary/src/lib.rs", lib),
            ("/ws/crates/boundary/tests/t.rs", "#![allow(unsafe_code)]\n"),
            ("/ws/crates/plain/Cargo.toml", "[lints]\nworkspace = true\n"),
            ("/ws/crates/bare/Cargo.toml", "[package]\nname = \"bare\"\n"),
        ]
        .into_iter()
        .filter(|&(path, _)| root.is_some() || path != "/ws/Cargo.toml")
        .map(|(path, text)| (PathBuf::from(path), text.to_owned()))
        .collect();
        let read = |path: &Path| {
            files
                .get(path)
                .cloned()
                .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))
        };
        audit_lint_tables(&metadata, &read)
    }

    #[test]
    fn a_boundary_crate_passes_and_lists_its_differences() {
        let report = audit_fixture(WORKSPACE, BOUNDARY, BOUNDARY_LIB);
        assert!(report.is_clean(), "{:?}", report.violations);
        assert_eq!(
            report.checked,
            [CheckedCrate {
                package: "boundary".into(),
                differences: vec![
                    "adds clippy.undocumented_unsafe_blocks = \"warn\"".into(),
                    "rust.unsafe_code = \"deny\" (workspace: \"forbid\")".into(),
                ],
            }]
        );
        assert_eq!(report.inheriting, ["plain"]);
        assert_eq!(report.without_lints, ["bare"]);
    }

    #[test]
    fn rule_a_a_dropped_or_added_tool_table_fails() {
        let dropped = BOUNDARY.replace("[lints.rustdoc]\nbare_urls = \"deny\"\n", "");
        let report = audit_fixture(WORKSPACE, &dropped, BOUNDARY_LIB);
        assert_eq!(
            report.violations,
            [LintTableViolation::Tools {
                package: "boundary".into(),
                missing: vec!["rustdoc".into()],
                extra: vec![],
            }]
        );
        let message = report.violations[0].to_string();
        assert!(message.contains("no [lints.rustdoc]"), "{message}");

        let added = format!("{BOUNDARY}[lints.extra_tool]\nx = \"warn\"\n");
        let report = audit_fixture(WORKSPACE, &added, BOUNDARY_LIB);
        assert_eq!(
            report.violations,
            [LintTableViolation::Tools {
                package: "boundary".into(),
                missing: vec![],
                extra: vec!["extra_tool".into()],
            }]
        );
    }

    #[test]
    fn rule_b_a_dropped_lint_fails() {
        let dropped = BOUNDARY.replace("panic = \"warn\"\n", "");
        let report = audit_fixture(WORKSPACE, &dropped, BOUNDARY_LIB);
        assert_eq!(
            report.violations,
            [LintTableViolation::Dropped {
                package: "boundary".into(),
                tool: "clippy".into(),
                lint: "panic".into(),
                workspace: setting("warn", 0),
            }]
        );
        assert!(
            report.violations[0]
                .to_string()
                .contains("drops `clippy.panic`")
        );

        // `unsafe_code` may differ in level, not go undeclared
        let dropped = BOUNDARY.replace("unsafe_code = \"deny\"\n", "");
        let report = audit_fixture(WORKSPACE, &dropped, BOUNDARY_LIB);
        assert_eq!(report.violations.len(), 1, "{:?}", report.violations);
        assert!(matches!(
            &report.violations[0],
            LintTableViolation::Dropped { lint, .. } if lint == "unsafe_code"
        ));
    }

    #[test]
    fn rule_b_a_changed_level_or_priority_fails() {
        let changed = BOUNDARY.replace("trivial_casts = \"warn\"", "trivial_casts = \"allow\"");
        let report = audit_fixture(WORKSPACE, &changed, BOUNDARY_LIB);
        assert_eq!(
            report.violations,
            [LintTableViolation::Changed {
                package: "boundary".into(),
                tool: "rust".into(),
                lint: "trivial_casts".into(),
                workspace: setting("warn", 0),
                own: setting("allow", 0),
            }]
        );
        let message = report.violations[0].to_string();
        assert!(
            message.contains("`rust.trivial_casts` = \"allow\", but the workspace sets \"warn\""),
            "{message}"
        );

        let reprioritized = BOUNDARY.replace("priority = -1", "priority = 0");
        let report = audit_fixture(WORKSPACE, &reprioritized, BOUNDARY_LIB);
        assert!(matches!(
            report.violations.as_slice(),
            [LintTableViolation::Changed { lint, .. }] if lint == "all"
        ));
    }

    #[test]
    fn rule_c_added_lints_pass_and_are_listed() {
        let added = BOUNDARY.replace(
            "[lints.rustdoc]\n",
            "[lints.rustdoc]\nmissing_crate_level_docs = \"warn\"\n",
        );
        let report = audit_fixture(WORKSPACE, &added, BOUNDARY_LIB);
        assert!(report.is_clean(), "{:?}", report.violations);
        assert!(
            report.checked[0]
                .differences
                .contains(&"adds rustdoc.missing_crate_level_docs = \"warn\"".to_owned())
        );
    }

    #[test]
    fn rule_d_a_crate_root_lift_fails_unless_unsafe_code_is_forbidden() {
        let lifted = format!("#![allow(unsafe_code)]\n{BOUNDARY_LIB}");
        let report = audit_fixture(WORKSPACE, BOUNDARY, &lifted);
        assert_eq!(
            report.violations,
            [LintTableViolation::CrateRootLift {
                package: "boundary".into(),
                path: PathBuf::from("/ws/crates/boundary/src/lib.rs"),
                attribute: "#![allow(unsafe_code)]".into(),
            }]
        );
        assert!(
            report.violations[0]
                .to_string()
                .contains("lifts it crate-wide")
        );

        // a crate that keeps `forbid` (and re-declares for another reason)
        // isn't scanned: the attribute would be a compile error anyway
        let forbidding = BOUNDARY.replace("unsafe_code = \"deny\"", "unsafe_code = \"forbid\"");
        let report = audit_fixture(WORKSPACE, &forbidding, &lifted);
        assert!(report.is_clean(), "{:?}", report.violations);
    }

    #[test]
    fn unsafe_code_must_stay_deny_or_forbid_at_the_workspace_s_priority() {
        for (own, expected) in [
            ("\"allow\"", setting("allow", 0)),
            ("\"warn\"", setting("warn", 0)),
            ("{ level = \"deny\", priority = 1 }", setting("deny", 1)),
        ] {
            let manifest =
                BOUNDARY.replace("unsafe_code = \"deny\"", &format!("unsafe_code = {own}"));
            let report = audit_fixture(WORKSPACE, &manifest, BOUNDARY_LIB);
            assert_eq!(
                report.violations,
                [LintTableViolation::UnsafeCode {
                    package: "boundary".into(),
                    workspace: setting("forbid", 0),
                    own: expected,
                }],
                "{own}"
            );
            let message = report.violations[0].to_string();
            assert!(message.contains("set it to \"deny\""), "{message}");
        }
        // `forbid`, the workspace's own setting, is no difference
        let forbidding = BOUNDARY.replace("unsafe_code = \"deny\"", "unsafe_code = \"forbid\"");
        let report = audit_fixture(WORKSPACE, &forbidding, BOUNDARY_LIB);
        assert!(report.is_clean(), "{:?}", report.violations);
        assert_eq!(
            report.checked[0].differences,
            ["adds clippy.undocumented_unsafe_blocks = \"warn\""]
        );
    }

    #[test]
    fn a_workspace_without_workspace_lints_lists_its_re_declarers_unchecked() {
        let report = audit_fixture("[workspace]\nmembers = []\n", BOUNDARY, BOUNDARY_LIB);
        assert!(report.is_clean());
        assert!(report.checked.is_empty());
        assert_eq!(report.unchecked, ["boundary"]);
        assert_eq!(report.inheriting, ["plain"]);
        assert_eq!(report.without_lints, ["bare"]);
    }

    #[test]
    fn the_root_manifest_is_read_only_once_a_member_re_declares() {
        let unreadable_root = "[workspace.lints.clippy]\nall = {\n";
        let inheriting = "[lints]\nworkspace = true\n";
        // every member inherits: the root's shape, or its absence, never matters
        let report = audit_files(Some(unreadable_root), inheriting, BOUNDARY_LIB).unwrap();
        assert_eq!(report.inheriting, ["boundary", "plain"]);
        assert!(audit_files(None, inheriting, BOUNDARY_LIB).is_ok());

        let err = audit_files(Some(unreadable_root), BOUNDARY, BOUNDARY_LIB).unwrap_err();
        assert!(matches!(err, AuditError::LintTableShape { .. }), "{err:?}");
        assert_eq!(err.exit_code(), 70);
        let err = audit_files(None, BOUNDARY, BOUNDARY_LIB).unwrap_err();
        assert!(matches!(err, AuditError::ReadFile { .. }), "{err:?}");
        assert_eq!(err.exit_code(), 70);
    }
}
