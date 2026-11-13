//! Regression tripwire: fuzi's install path stays exec-free.
//!
//! fuzi installs *untrusted* npm trees with the property that **no code path
//! runs package code** — no install/lifecycle scripts, no compilation — so an
//! install is deterministic and exec-free *by construction* (the canonical
//! statement is the `fuzi_core` entry in `docs/crates.md`; the threat model is `docs/deferred_security.md` §
//! "fuzi no-exec enforcement (seccomp)"). That property has **no runtime
//! enforcement** today — the seccomp no-exec backstop is deferred, and it is
//! that seccomp profile, not this test, that will be the real runtime
//! guarantee. The threat this guard covers, listed first in the threat model,
//! is a **regression in our own code** that introduces a process spawn onto the
//! install path; it would otherwise break the invariant silently. This test
//! turns such a slip into a red test until seccomp lands.
//!
//! **Two layers, both tripwires for fuzi's own source, neither a proof.**
//! Each reaches `fuzi_core`, the sibling `fuzi` binary, and `fuz_archive` (the
//! extraction crate fuzi depends on):
//!
//!  - **clippy** (`disallowed_types` / `disallowed_methods`, in each of those
//!    crates' `clippy.toml`; `-D warnings` makes them errors) resolves paths,
//!    so it catches `std::process::Command` and `tokio::process::Command` (the
//!    type and `::new`) however they are imported — an aliased or grouped
//!    import (`use std::process::{Command as Cmd}`) or a type alias included —
//!    and `nix`'s `exec*` / `fork` / `posix_spawn*` the moment a crate depends on `nix` with
//!    them enabled. It sees only the paths it lists.
//!  - **this test** scans the text for the ordinary spawn surface below. It is
//!    the layer that needs no lint run and that survives a lint being turned
//!    off or a `clippy.toml` being dropped, but it is blind to an alias or a
//!    grouped import (`{Command as Cmd}` matches no needle).
//!
//! Both are scoped to those crates: the other spine crates on the install path
//! (`fuz_sys`, `fuz_crypto`, `fuz_home`) are trusted first-party code, out of
//! this guard's scope, and `fuz_sys` in particular legitimately references
//! process/signal primitives (`pid::send_signal` routes a `kill(2)` through
//! `nix`), so neither layer can sweep it naively. And neither is exhaustive:
//! a *safe* third-party exec wrapper neither lists runs no `unsafe`. Raw libc
//! `fork`/`execve`/`posix_spawn` and `CommandExt::pre_exec` are separately
//! compile-blocked by the workspace-wide `unsafe_code = "forbid"`. The real
//! runtime guarantee is the deferred seccomp profile.

#![expect(
    clippy::panic,
    reason = "a guard test fails loud: the panic message is the operator-facing report"
)]

use std::fs;
use std::path::{Path, PathBuf};

/// Substrings whose presence in fuzi's own source signals a process spawn —
/// the text layer (the clippy layer is in the crates' `clippy.toml`).
///
/// `process::Command` catches both `std::process::Command` and
/// `tokio::process::Command` (the type path and the `use`); `tokio::process`
/// catches the module by any route; `Command::new` catches the construction
/// even through a bare `use`. fuzi's own argh subcommand `enum Command` is only
/// ever constructed as `Command::Install` / `Command::Verify` / `Command::Clean`
/// — never `Command::new` — so it is not a false positive. `tokio::spawn` and
/// `std::thread::scope`'s `scope.spawn` (async tasks / worker threads, both
/// used on the install path) are not process spawns and match none of these.
const FORBIDDEN: &[&str] = &["process::Command", "tokio::process", "Command::new"];

#[test]
fn fuzi_install_path_is_exec_free() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    // fuzi_core's own src, the sibling `fuzi` binary's src, and `fuz_archive`'s
    // src (the extraction crate fuzi depends on) — the first-party source this
    // tripwire reaches. NOT the whole install path: the other spine crates
    // (`fuz_sys`/`fuz_crypto`/`fuz_home`) are out of scope, see the module doc.
    let roots = [
        manifest_dir.join("src"),
        manifest_dir.join("..").join("fuzi").join("src"),
        manifest_dir.join("..").join("fuz_archive").join("src"),
    ];

    let mut scanned = 0usize;
    let mut violations = Vec::new();
    for root in &roots {
        assert!(
            root.is_dir(),
            "exec-free guard: source root `{}` does not exist — did the crate \
             layout change? A guard that silently scans nothing is worse than none.",
            root.display(),
        );
        scan_dir(root, &mut scanned, &mut violations);
    }

    // Fail loud if the walk found (almost) nothing — a moved/renamed tree must
    // not turn the guard into a no-op green.
    assert!(
        scanned >= 5,
        "exec-free guard: only scanned {scanned} `.rs` files across {roots:?} — \
         expected the full fuzi_core + fuzi + fuz_archive source; the guard \
         appears mis-pointed.",
    );

    assert!(
        violations.is_empty(),
        "exec-free guard tripped — fuzi's install path must stay exec-free (no \
         process spawning). fuzi installs *untrusted* npm trees with \"no code \
         path runs package code\"; that safety is by construction, with no \
         runtime enforcement (the seccomp backstop is deferred — see \
         docs/deferred_security.md § \"fuzi no-exec enforcement (seccomp)\"). A \
         spawn cannot live on the install path: revisit the invariant (the \
         `fuzi_core` entry in docs/crates.md) and the deferred seccomp \
         plan before relaxing this guard.\nFound {} violation(s):\n{}",
        violations.len(),
        violations
            .iter()
            .map(|v| format!("  {v}"))
            .collect::<Vec<_>>()
            .join("\n"),
    );

    eprintln!("exec-free guard: scanned {scanned} `.rs` files, no process-spawn constructs");
}

/// Recursively collect `.rs` files under `dir`, scanning each for forbidden
/// process-spawn constructs.
fn scan_dir(dir: &Path, scanned: &mut usize, violations: &mut Vec<String>) {
    let entries = fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("exec-free guard: cannot read `{}`: {e}", dir.display()));
    for entry in entries {
        let entry = entry.unwrap_or_else(|e| {
            panic!(
                "exec-free guard: cannot read an entry under `{}`: {e}",
                dir.display()
            )
        });
        let path = entry.path();
        if path.is_dir() {
            scan_dir(&path, scanned, violations);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            scan_file(&path, scanned, violations);
        }
    }
}

/// Scan one source file. Full-line and doc comments (`//`, `///`, `//!`) are
/// skipped so a benign *mention* of the `Command` surface in prose isn't a
/// false positive — only code counts.
fn scan_file(path: &Path, scanned: &mut usize, violations: &mut Vec<String>) {
    let contents = fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("exec-free guard: cannot read `{}`: {e}", path.display()));
    *scanned += 1;
    for (i, line) in contents.lines().enumerate() {
        if line.trim_start().starts_with("//") {
            continue;
        }
        for needle in FORBIDDEN {
            if line.contains(needle) {
                violations.push(format!(
                    "{}:{}: `{needle}` — {}",
                    path.display(),
                    i + 1,
                    line.trim()
                ));
            }
        }
    }
}

/// The clippy layer is only as good as its config being there: each scoped
/// crate's `clippy.toml` must carry the exec-free disallows, each under its own
/// list — and, because a crate-level `clippy.toml` replaces the workspace one
/// rather than merging with it, every setting of the workspace file too, so a
/// workspace lint added later does not silently stop reaching the fuzi crates.
///
/// The three crate files are one file in three places, so they must be
/// byte-identical. Each is read by [`parse_clippy_toml`], which skips
/// full-line `#` comments (a trailing `# …` stays part of the value and reads
/// as a mismatch): a commented-out entry, or one moved under the wrong list, is
/// missing.
#[test]
fn clippy_layer_is_configured_in_every_scoped_crate() {
    /// Each exec-free disallow, with the list it belongs under.
    const EXEC_FREE: &[(&str, &str)] = &[
        ("disallowed-types", "std::process::Command"),
        ("disallowed-types", "tokio::process::Command"),
        ("disallowed-methods", "std::process::Command::new"),
        ("disallowed-methods", "tokio::process::Command::new"),
        // Every `nix` entry, one by one: `allow-invalid` (they do not resolve
        // while no fuzi crate depends on `nix`) also silences a typo, so the
        // spelling is pinned here instead.
        ("disallowed-methods", "nix::unistd::execv"),
        ("disallowed-methods", "nix::unistd::execve"),
        ("disallowed-methods", "nix::unistd::execvp"),
        ("disallowed-methods", "nix::unistd::execvpe"),
        ("disallowed-methods", "nix::unistd::execveat"),
        ("disallowed-methods", "nix::unistd::fexecve"),
        ("disallowed-methods", "nix::unistd::fork"),
        ("disallowed-methods", "nix::spawn::posix_spawn"),
        ("disallowed-methods", "nix::spawn::posix_spawnp"),
    ];

    let crates = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..");
    let read = |path: &Path| {
        fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("exec-free guard: cannot read `{}`: {e}", path.display()))
    };
    let workspace = parse_clippy_toml(&read(&crates.join("..").join("clippy.toml")), "clippy.toml");
    assert!(
        !workspace.settings.is_empty() && !workspace.entries.is_empty(),
        "exec-free guard: the workspace clippy.toml parsed to no settings or no \
         list entries — mis-pointed, or its shape changed?"
    );

    let names = ["fuzi_core", "fuzi", "fuz_archive"];
    let texts = names.map(|name| read(&crates.join(name).join("clippy.toml")));
    for (name, text) in names.iter().zip(&texts).skip(1) {
        assert!(
            *text == texts[0],
            "exec-free guard: crates/{name}/clippy.toml differs from \
             crates/{}/clippy.toml — the three are one file, keep them identical",
            names[0],
        );
    }

    for (name, text) in names.iter().zip(&texts) {
        let file = format!("crates/{name}/clippy.toml");
        let config = parse_clippy_toml(text, &file);
        for (list, path) in EXEC_FREE {
            assert!(
                config
                    .entries
                    .iter()
                    .filter(|(key, _)| key == list)
                    .any(|(_, entry)| entry_path(entry) == Some(*path)),
                "exec-free guard: {file} lacks `{path}` under `{list}`"
            );
        }
        for setting in &workspace.settings {
            assert!(
                config.settings.contains(setting),
                "exec-free guard: {file} replaces the workspace clippy.toml but \
                 lacks its `{} = {}` — copy it over",
                setting.0,
                setting.1,
            );
        }
        for entry in &workspace.entries {
            assert!(
                config.entries.contains(entry),
                "exec-free guard: {file} replaces the workspace clippy.toml but \
                 lacks its `{}` entry under `{}` — copy it over",
                entry.1,
                entry.0,
            );
        }
    }
}

/// A `clippy.toml` as this guard reads it: top-level `key = value` settings,
/// and the entries of its `key = [` lists, each paired with its list's key.
/// Values and entries are the trimmed line text (an entry without its trailing
/// comma).
struct ClippyConfig {
    settings: Vec<(String, String)>,
    entries: Vec<(String, String)>,
}

/// A line-based reading of the shape the workspace's `clippy.toml` files use —
/// not a TOML parser (no `toml` crate in the workspace). Blank lines and `#`
/// comment lines are skipped; `key = [` opens a list, a lone `]` closes it, and
/// each line between is one entry. Anything else outside a list must be
/// `key = value`. A line it can't place panics, so a reshaped file fails loud
/// rather than reading as empty.
fn parse_clippy_toml(text: &str, file: &str) -> ClippyConfig {
    let mut config = ClippyConfig {
        settings: Vec::new(),
        entries: Vec::new(),
    };
    let mut list: Option<String> = None;
    for (i, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(key) = &list {
            if line == "]" {
                list = None;
            } else {
                let entry = line.strip_suffix(',').unwrap_or(line).trim_end();
                config.entries.push((key.clone(), entry.to_owned()));
            }
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            panic!(
                "exec-free guard: {file}:{}: not `key = value`: {line}",
                i + 1
            );
        };
        let (key, value) = (key.trim(), value.trim());
        if value == "[" {
            list = Some(key.to_owned());
        } else if value.starts_with('[') {
            panic!(
                "exec-free guard: {file}:{}: a one-line list — put each entry on its \
                 own line: {line}",
                i + 1
            );
        } else {
            config.settings.push((key.to_owned(), value.to_owned()));
        }
    }
    if let Some(key) = list {
        panic!("exec-free guard: {file}: the `{key}` list is never closed");
    }
    config
}

/// The `path = "..."` field of a disallow entry (`{ path = "...", reason = ... }`).
fn entry_path(entry: &str) -> Option<&str> {
    let rest = entry.split_once("path = \"")?.1;
    Some(rest.split_once('"')?.0)
}
