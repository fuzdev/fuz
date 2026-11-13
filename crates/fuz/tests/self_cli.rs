//! CLI-level integration tests for `fuz self {status,version,bootstrap}` — the
//! `self`-noun surface the lib/unit suites don't reach end-to-end. They run the
//! real `fuz` binary (`CARGO_BIN_EXE_fuz`) against a throwaway `~/.fuz` pointed
//! at a tempdir via `FUZ_HOME` (honored unconditionally by
//! `fuz_home::get_fuz_home()`, so no test-only feature reaches the `fuz` graph).
//! `HOME` is also redirected so `bootstrap`'s shell-rc logic can never touch the
//! developer's real rc files (and `--no-modify-path` skips it entirely anyway).
//!
//! `self upgrade` is *not* covered here: it requires a signed release in remote
//! storage, so its end-to-end coverage lives at the library level in
//! `fuz_sign/tests/signed_trust.rs` (the producer-side signing seam).
//!
//! The release log surface of these commands is covered as far as the binary's
//! trust allows. It trusts only its embedded keys, so no test here can hand it
//! a head it accepts: what runs end to end is everything short of a confirmed
//! or revoked verdict — an inactive policy, the opt-out, a configuration error,
//! a witness with no head, a head that is not one, and a cache that cannot be
//! used. The verdicts themselves are driven at the library level in
//! `fuz_sign/tests/log_check.rs`.
#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test helpers outside `#[test]` fns panic on a failed setup or check"
)]

use std::os::unix::net::UnixListener;
use std::path::Path;
use std::process::Output;

mod common;
use common::{
    fresh_home, fresh_home_rc_safe, make_fifo, run as fuz, run_with_env, running_as_root,
    seed_artifact, stdout_json,
};

/// Pins `fuz self status --json` on a fresh home: no current artifact, and fuzd
/// reported as neither running nor installed.
#[test]
fn self_status_json_fresh_home_has_no_artifact_and_no_fuzd() {
    let home = fresh_home();

    let json = stdout_json(&fuz(home.path(), &["self", "status", "--json"]));

    assert!(json["version"].is_string(), "version reported");
    assert!(
        json["artifact"].is_null(),
        "no artifact block on a fresh home"
    );
    assert_eq!(json["fuzd"]["running"], false, "fuzd not running");
    assert_eq!(json["fuzd"]["installed"], false, "fuzd not installed");
}

/// Pins that `self status --json` surfaces a seeded current artifact, reporting
/// `source: "bootstrap"` and omitting `commit`/`dirty` (bootstrap artifacts have
/// no VCS inputs).
#[test]
fn self_status_json_reports_current_artifact() {
    let home = fresh_home();
    let a = seed_artifact(home.path(), 0x11, "2020-01-01T00:00:01Z");
    assert!(
        fuz(home.path(), &["artifact", "use", &a.hash])
            .status
            .success(),
        "use seeded artifact"
    );

    let json = stdout_json(&fuz(home.path(), &["self", "status", "--json"]));

    assert_eq!(json["artifact"]["hash"], a.hash, "artifact hash reported");
    assert_eq!(
        json["artifact"]["source"], "bootstrap",
        "seeded via new_bootstrap"
    );
    assert!(
        json["artifact"]["commit"].is_null(),
        "bootstrap artifact has no commit"
    );
    assert!(
        json["artifact"]["dirty"].is_null(),
        "bootstrap artifact has no dirty flag"
    );
}

/// Pins the fuzd `Stopped` state: a `bin/fuzd` file present but no listening
/// socket reads back as installed-but-not-running.
#[test]
fn self_status_json_reports_fuzd_installed_but_stopped() {
    let home = fresh_home();
    std::fs::create_dir_all(home.path().join("bin")).unwrap();
    std::fs::write(home.path().join("bin").join("fuzd"), b"#!/bin/sh\n").unwrap();

    let json = stdout_json(&fuz(home.path(), &["self", "status", "--json"]));

    assert_eq!(json["fuzd"]["running"], false, "no socket -> not running");
    assert_eq!(
        json["fuzd"]["installed"], true,
        "bin/fuzd present -> installed"
    );
}

/// Pins the fuzd `Running` state: a listener bound at `<home>/run/socket` makes
/// the passive connect-probe succeed, so status reports running (pid null with
/// no daemon.json present).
#[test]
fn self_status_json_reports_fuzd_running_when_socket_listens() {
    let home = fresh_home();
    std::fs::create_dir_all(home.path().join("run")).unwrap();
    // Bind a throwaway listener where fuzd would; the connect-probe only needs
    // something accepting connections, not the real daemon. Held alive across
    // the spawned command, dropped at end of scope.
    let _listener = UnixListener::bind(home.path().join("run").join("socket")).unwrap();

    let json = stdout_json(&fuz(home.path(), &["self", "status", "--json"]));

    assert_eq!(json["fuzd"]["running"], true, "listening socket -> running");
    assert!(
        json["fuzd"]["pid"].is_null(),
        "no daemon.json seeded -> pid null"
    );
}

/// Pins `fuz self version`: with a current artifact it prints the version line
/// referencing the artifact's short hash; exit 0.
#[test]
fn self_version_references_current_artifact() {
    let home = fresh_home();
    let a = seed_artifact(home.path(), 0x22, "2020-01-01T00:00:01Z");
    assert!(
        fuz(home.path(), &["artifact", "use", &a.hash])
            .status
            .success(),
        "use seeded artifact"
    );

    let out = fuz(home.path(), &["self", "version"]);
    assert!(
        out.status.success(),
        "version failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("fuz "), "version line names fuz: {stdout}");
    assert!(
        stdout.contains(a.short_hash()),
        "version line references the current artifact's short hash: {stdout}"
    );
}

/// Pins that `self version` still works with no current artifact — it falls back
/// to the compile-time version and exits 0.
#[test]
fn self_version_without_artifact_succeeds() {
    let home = fresh_home();
    let out = fuz(home.path(), &["self", "version"]);
    assert!(
        out.status.success(),
        "version on a fresh home failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("fuz "),
        "version line names fuz"
    );
}

/// Pins the real `self bootstrap` install path end-to-end: running the binary
/// with `--no-modify-path` creates a content-addressed artifact from its own
/// bytes, repoints `current`, wires `bin/fuz` through `current`, records a
/// history entry, and leaves a state `self status --json` then reflects. The
/// unit tests cover the rc-file logic in isolation; this covers the install.
#[test]
fn self_bootstrap_installs_artifact_and_status_reflects_it() {
    let home = fresh_home();

    let out = fuz(home.path(), &["self", "bootstrap", "--no-modify-path"]);
    assert!(
        out.status.success(),
        "bootstrap failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // current -> artifacts/v1-…, bin/fuz -> ../current/fuz, one artifact dir,
    // and a history entry all landed under the redirected home.
    let current = std::fs::read_link(home.path().join("current")).unwrap();
    assert!(
        current.to_string_lossy().starts_with("artifacts/v1-"),
        "current points at the bootstrapped artifact: {current:?}"
    );
    assert_eq!(
        std::fs::read_link(home.path().join("bin").join("fuz")).unwrap(),
        Path::new("../current/fuz"),
        "bin/fuz points through current"
    );
    assert!(
        home.path().join("state").join("history.json").exists(),
        "switch history recorded"
    );
    // No shell rc file was created under the redirected HOME (--no-modify-path).
    assert!(
        !home.path().join(".bashrc").exists(),
        "--no-modify-path must not write a shell rc"
    );

    let json = stdout_json(&fuz(home.path(), &["self", "status", "--json"]));
    assert!(
        json["artifact"]["hash"]
            .as_str()
            .is_some_and(|h| h.starts_with("v1-")),
        "status reports the bootstrapped artifact"
    );
    assert_eq!(
        json["artifact"]["source"], "bootstrap",
        "bootstrap artifact source"
    );
}

/// A failure that keeps its cause as a source prints that cause on its
/// `error:` line: a home whose `bin` is a file stops `self bootstrap` at the
/// directory it cannot create, with the reason after the path.
#[test]
fn self_bootstrap_error_line_carries_the_cause() {
    let home = fresh_home();
    std::fs::write(home.path().join("bin"), b"not a directory").unwrap();

    let out = fuz(home.path(), &["self", "bootstrap", "--no-modify-path"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    let line = stderr.lines().next().unwrap_or_default();
    assert_eq!(
        line,
        format!(
            "error: failed to create directory {}: File exists (os error 17)",
            home.path().join("bin").display()
        ),
        "{stderr}"
    );
}

/// Count `v1-`-prefixed (complete) artifact dirs under `<home>/artifacts`.
fn count_artifact_dirs(home: &Path) -> usize {
    std::fs::read_dir(home.join("artifacts")).map_or(0, |rd| {
        rd.filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().starts_with("v1-"))
            .count()
    })
}

/// Re-running `self bootstrap` from the same binary is idempotent: the second
/// run reports "already installed", reuses the one existing artifact dir (no
/// duplicate), and leaves `current` / `bin/fuz` valid. Covers the
/// "reinstall (same version, same hash → reuses artifact dir)" flow
/// end-to-end (the `ReplacedSameVersion` / `VersionChanged` variants can't be
/// driven E2E from a single binary — they're covered by the `InstallScenario`
/// unit tests above).
#[test]
fn self_bootstrap_rerun_is_idempotent_and_reuses_artifact() {
    let home = fresh_home();

    let first = fuz(home.path(), &["self", "bootstrap", "--no-modify-path"]);
    assert!(
        first.status.success(),
        "first bootstrap failed: {}",
        String::from_utf8_lossy(&first.stderr)
    );
    assert_eq!(
        count_artifact_dirs(home.path()),
        1,
        "one artifact after first"
    );

    let second = fuz(home.path(), &["self", "bootstrap", "--no-modify-path"]);
    assert!(
        second.status.success(),
        "second bootstrap failed: {}",
        String::from_utf8_lossy(&second.stderr)
    );
    assert!(
        String::from_utf8_lossy(&second.stdout).contains("already installed"),
        "re-run reports the idempotent scenario: {}",
        String::from_utf8_lossy(&second.stdout)
    );
    assert_eq!(
        count_artifact_dirs(home.path()),
        1,
        "re-run reuses the same artifact dir rather than duplicating it"
    );

    // The no-op re-run must not append a duplicate history entry — otherwise
    // `artifact use -` (which reads history by position) would toggle to the
    // same artifact.
    let history: serde_json::Value = serde_json::from_slice(
        &std::fs::read(home.path().join("state").join("history.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(
        history["entries"].as_array().map(Vec::len),
        Some(1),
        "idempotent re-run leaves a single history entry"
    );

    // Install is still coherent: status reports the current bootstrap artifact.
    let json = stdout_json(&fuz(home.path(), &["self", "status", "--json"]));
    assert!(
        json["artifact"]["hash"]
            .as_str()
            .is_some_and(|h| h.starts_with("v1-")),
        "status still reports a current artifact after the re-run"
    );
}

/// Bootstrap heals a corrupt `~/.fuz`: a **dangling `current`** symlink (target
/// artifact gone) plus a **dangling `bin/fuz`** are both atomically repointed at
/// a freshly-created artifact. Covers the "corrupt/partial `~/.fuz/`
/// (dangling symlinks)" edge case through the real binary.
#[test]
fn self_bootstrap_recovers_from_dangling_current_and_bin_symlinks() {
    use std::os::unix::fs::symlink;

    let home = fresh_home();
    // Point `current` at an artifact dir that doesn't exist.
    symlink("artifacts/v1-deadbeefdeadbeef", home.path().join("current")).unwrap();
    // And a `bin/fuz` that chains through the dangling `current`.
    std::fs::create_dir_all(home.path().join("bin")).unwrap();
    symlink("../current/fuz", home.path().join("bin").join("fuz")).unwrap();

    let out = fuz(home.path(), &["self", "bootstrap", "--no-modify-path"]);
    assert!(
        out.status.success(),
        "bootstrap should recover from a dangling current symlink: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // `current` now resolves to a real artifact dir.
    let current = std::fs::read_link(home.path().join("current")).unwrap();
    assert!(
        current.to_string_lossy().starts_with("artifacts/v1-"),
        "current repointed at a real artifact: {current:?}"
    );
    assert!(
        home.path().join(&current).join("fuz").exists(),
        "current's target artifact actually exists with a fuz binary"
    );
    // `bin/fuz` chains through `current` and now resolves to a real file.
    assert_eq!(
        std::fs::read_link(home.path().join("bin").join("fuz")).unwrap(),
        Path::new("../current/fuz"),
        "bin/fuz points back through current"
    );
    assert!(
        home.path().join("bin").join("fuz").exists(),
        "bin/fuz now resolves (no longer dangling)"
    );

    let json = stdout_json(&fuz(home.path(), &["self", "status", "--json"]));
    assert!(
        json["artifact"]["hash"]
            .as_str()
            .is_some_and(|h| h.starts_with("v1-")),
        "status reports the recovered artifact"
    );
}

/// Bootstrap sweeps orphaned `.bootstrapping-*` / `.building-*` temp dirs left
/// by a crashed prior run before installing, and reports how many it removed.
/// Covers the "orphaned `.bootstrapping-*` directories" edge case.
#[test]
fn self_bootstrap_sweeps_orphaned_incomplete_dirs() {
    let home = fresh_home();
    let artifacts = home.path().join("artifacts");
    std::fs::create_dir_all(&artifacts).unwrap();
    // Two orphans, one non-empty, from hypothetical crashed prior runs.
    std::fs::create_dir_all(artifacts.join(".bootstrapping-orphan1")).unwrap();
    std::fs::write(artifacts.join(".bootstrapping-orphan1").join("junk"), b"x").unwrap();
    std::fs::create_dir_all(artifacts.join(".building-orphan2")).unwrap();

    let out = fuz(home.path(), &["self", "bootstrap", "--no-modify-path"]);
    assert!(
        out.status.success(),
        "bootstrap failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("cleaned up") && stderr.contains("incomplete"),
        "bootstrap reports the incomplete-dir sweep: {stderr}"
    );

    assert!(
        !artifacts.join(".bootstrapping-orphan1").exists(),
        ".bootstrapping-* orphan removed"
    );
    assert!(
        !artifacts.join(".building-orphan2").exists(),
        ".building-* orphan removed"
    );
    // The real install still lands.
    assert_eq!(count_artifact_dirs(home.path()), 1, "install completed");
}

/// The PATH hint names the bin dir of the home fuz actually installed into. With
/// `FUZ_HOME` pointing away from `$HOME/.fuz` (here: a home outside `HOME`
/// entirely, so the path prints absolute rather than tilde-collapsed), a hint
/// hard-coding `~/.fuz/bin` would send the user to a directory holding no `fuz`.
#[test]
fn self_bootstrap_path_hint_names_the_fuz_home_bin_dir() {
    let home = fresh_home();
    let user_home = fresh_home();
    let user_home_str = user_home.path().to_str().unwrap();

    let out = run_with_env(
        home.path(),
        &["self", "bootstrap", "--no-modify-path"],
        &[("HOME", user_home_str)],
    );
    assert!(
        out.status.success(),
        "bootstrap failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let stdout = String::from_utf8_lossy(&out.stdout);
    let bin_dir = home.path().join("bin");
    assert!(
        stdout.contains(&format!("Add {} to your PATH", bin_dir.display())),
        "hint names the redirected home's bin dir: {stdout}"
    );
    assert!(
        !stdout.contains("~/.fuz/bin"),
        "hint does not fall back to the default home: {stdout}"
    );
}

const RC_BEGIN: &str = "# >>> fuz initialize >>>";
const RC_END: &str = "# <<< fuz initialize <<<";

/// The managed block exactly as bootstrap writes it around `line`.
fn rc_block(line: &str) -> String {
    format!("{RC_BEGIN}\n{line}\n{RC_END}\n")
}

/// Create `dir` (and parents) pinned to `0700` — set, never inherited from the
/// umask, for the same reason [`fresh_home`] pins its own mode.
fn secure_dir(dir: &Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(dir).unwrap();
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
}

/// Run the PATH-modifying `self bootstrap` with `FUZ_HOME`, `HOME`, and `SHELL`
/// each pinned, asserting it exits 0 (PATH setup never fails the install).
fn bootstrap_modifying_path(fuz_home: &Path, user_home: &Path, shell: &str) -> Output {
    let out = run_with_env(
        fuz_home,
        &["self", "bootstrap"],
        &[("HOME", user_home.to_str().unwrap()), ("SHELL", shell)],
    );
    assert!(
        out.status.success(),
        "bootstrap failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    out
}

/// The default (PATH-modifying) bootstrap path writes the marker block to the
/// detected shell's rc file, naming the bin dir fuz actually installed into,
/// and a re-run is idempotent (the file is byte-identical). `FUZ_HOME` sits
/// outside `HOME`, so the line is the absolute bin dir — a line hard-coding
/// `$HOME/.fuz/bin` would put a directory holding no `fuz` on PATH. `SHELL` is
/// pinned to bash for a deterministic `export PATH=…` line without shelling out
/// to `fish --version`. Also covers the "missing shell rc file" case (the rc
/// doesn't exist until bootstrap creates it).
#[test]
fn self_bootstrap_writes_shell_rc_and_is_idempotent() {
    let home = fresh_home_rc_safe();
    let user_home = fresh_home();
    let bin_dir = home.path().join("bin");
    let expected = rc_block(&format!(r#"export PATH="{}:$PATH""#, bin_dir.display()));

    let first = bootstrap_modifying_path(home.path(), user_home.path(), "/bin/bash");
    assert!(bin_dir.join("fuz").exists(), "fuz installed in the bin dir");

    let rc = user_home.path().join(".bashrc");
    let contents = std::fs::read_to_string(&rc).expect("bootstrap created ~/.bashrc");
    assert_eq!(contents, expected, "rc names the real bin dir");
    let stderr = String::from_utf8_lossy(&first.stderr);
    assert!(
        stderr.contains(&format!("added {} to PATH in ~/.bashrc", bin_dir.display())),
        "reports the addition: {stderr}"
    );
    let stdout = String::from_utf8_lossy(&first.stdout);
    assert!(
        stdout.contains("source ~/.bashrc"),
        "a fresh rc edit prompts for a new shell: {stdout}"
    );

    let second = bootstrap_modifying_path(home.path(), user_home.path(), "/bin/bash");
    assert_eq!(
        std::fs::read_to_string(&rc).unwrap(),
        expected,
        "re-run leaves the rc byte-identical"
    );
    let stderr = String::from_utf8_lossy(&second.stderr);
    assert!(
        !stderr.contains("added") && !stderr.contains("updated"),
        "a no-op re-run claims no rc change: {stderr}"
    );
    let stdout = String::from_utf8_lossy(&second.stdout);
    assert!(
        !stdout.contains("source ~/.bashrc"),
        "a no-op re-run does not prompt for a new shell: {stdout}"
    );
}

/// The default layout (`FUZ_HOME` = `$HOME/.fuz`) writes exactly the
/// home-relative line — the regression pin for the bytes every default install
/// already has in its rc, so a re-run there stays a no-op.
#[test]
fn self_bootstrap_default_layout_writes_home_relative_line() {
    let user_home = fresh_home();
    let home = user_home.path().join(".fuz");
    secure_dir(&home);

    bootstrap_modifying_path(&home, user_home.path(), "/bin/bash");
    assert_eq!(
        std::fs::read_to_string(user_home.path().join(".bashrc")).unwrap(),
        "# >>> fuz initialize >>>\nexport PATH=\"$HOME/.fuz/bin:$PATH\"\n# <<< fuz initialize <<<\n"
    );

    bootstrap_modifying_path(&home, user_home.path(), "/bin/zsh");
    assert_eq!(
        std::fs::read_to_string(user_home.path().join(".zshrc")).unwrap(),
        "# >>> fuz initialize >>>\nexport PATH=\"$HOME/.fuz/bin:$PATH\"\n# <<< fuz initialize <<<\n"
    );
}

/// A `$HOME` with shell-special characters is fine in the default layout: the
/// line says `$HOME/.fuz/bin` and the shell expands the prefix, so the unusual
/// name never becomes rc text.
#[test]
fn self_bootstrap_unsafe_home_name_stays_home_relative() {
    let parent = fresh_home();
    let user_home = parent.path().join("my $home");
    let home = user_home.join(".fuz");
    secure_dir(&user_home);
    secure_dir(&home);

    bootstrap_modifying_path(&home, &user_home, "/bin/bash");
    assert_eq!(
        std::fs::read_to_string(user_home.join(".bashrc")).unwrap(),
        rc_block(r#"export PATH="$HOME/.fuz/bin:$PATH""#)
    );
}

/// A bin dir whose path would need quoting is never written into an rc file,
/// nor offered as a copy-pasteable line: bootstrap succeeds, creates no rc,
/// and reports manual instructions with the reason.
#[test]
fn self_bootstrap_unsafe_bin_dir_writes_no_rc() {
    for name in ["fuz home", "fuz$HOME", "fuz\"q", "fuz;x", "fuz'q"] {
        // `/bin/dash` is the unknown-shell arm, whose note prints a line too.
        for shell in ["/bin/bash", "/usr/bin/fish", "/bin/dash"] {
            let parent = fresh_home();
            let user_home = fresh_home();
            let home = parent.path().join(name);
            secure_dir(&home);

            let out = bootstrap_modifying_path(&home, user_home.path(), shell);
            assert!(home.join("bin").join("fuz").exists(), "install landed");
            assert_eq!(
                std::fs::read_dir(user_home.path()).unwrap().count(),
                0,
                "nothing written under HOME for {name:?} / {shell}"
            );
            let stderr = String::from_utf8_lossy(&out.stderr);
            let stdout = String::from_utf8_lossy(&out.stdout);
            assert!(
                stderr.contains("note: not editing your shell config")
                    && stderr.contains("characters outside"),
                "says why for {name:?} / {shell}: {stderr}"
            );
            for text in [&stderr, &stdout] {
                assert!(
                    !text.contains("export PATH")
                        && !text.contains("fish_add_path")
                        && !text.contains("set -gx"),
                    "no copy-pasteable line for {name:?} / {shell}: {text}"
                );
            }
            assert!(
                stdout.contains("Next: add ") && stdout.contains("to your shell's PATH"),
                "manual next step for {name:?} / {shell}: {stdout}"
            );
        }
    }
}

/// The same refusal under `$HOME`: the remainder below `$HOME` is what would be
/// interpolated, so an unsafe one writes nothing.
#[test]
fn self_bootstrap_unsafe_bin_dir_under_home_writes_no_rc() {
    let user_home = fresh_home();
    let home = user_home.path().join("my fuz");
    secure_dir(&home);

    let out = bootstrap_modifying_path(&home, user_home.path(), "/bin/bash");
    assert!(
        !user_home.path().join(".bashrc").exists(),
        "no rc written for an unsafe remainder"
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("note: not editing your shell config"),
        "reports the refusal"
    );
}

/// The unknown-shell note is built from the real bin dir, not a hard-coded
/// `$HOME/.fuz/bin`.
#[test]
fn self_bootstrap_unknown_shell_note_names_the_real_bin_dir() {
    let home = fresh_home_rc_safe();
    let user_home = fresh_home();

    let out = bootstrap_modifying_path(home.path(), user_home.path(), "/bin/dash");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains(&format!(
            r#"  export PATH="{}:$PATH""#,
            home.path().join("bin").display()
        )),
        "note carries the real bin dir: {stderr}"
    );
    assert!(
        !stderr.contains(".fuz/bin"),
        "no default-home line: {stderr}"
    );
    assert_eq!(
        std::fs::read_dir(user_home.path()).unwrap().count(),
        0,
        "an unknown shell writes no rc"
    );
}

/// fish gets its own syntax around the same bin dir. Which of the two forms is
/// written depends on the `fish` found on PATH (or its absence), so both are
/// accepted; each must name the real directory.
#[test]
fn self_bootstrap_fish_rc_names_the_real_bin_dir() {
    // outside HOME: absolute
    let home = fresh_home_rc_safe();
    let user_home = fresh_home();
    bootstrap_modifying_path(home.path(), user_home.path(), "/usr/bin/fish");
    let bin_dir = home.path().join("bin");
    let contents =
        std::fs::read_to_string(user_home.path().join(".config/fish/config.fish")).unwrap();
    assert!(
        contents == rc_block(&format!("fish_add_path {}", bin_dir.display()))
            || contents == rc_block(&format!("set -gx PATH {} $PATH", bin_dir.display())),
        "fish rc names the real bin dir: {contents}"
    );

    // default layout: `~/.fuz/bin`
    let user_home = fresh_home();
    let home = user_home.path().join(".fuz");
    secure_dir(&home);
    bootstrap_modifying_path(&home, user_home.path(), "/usr/bin/fish");
    let contents =
        std::fs::read_to_string(user_home.path().join(".config/fish/config.fish")).unwrap();
    assert!(
        contents == rc_block("fish_add_path ~/.fuz/bin")
            || contents == rc_block("set -gx PATH ~/.fuz/bin $PATH"),
        "default fish rc is tilde-relative: {contents}"
    );
}

/// Re-running repairs a managed block that names the wrong directory: the body
/// between the markers is replaced and every byte outside it is preserved —
/// here a block mid-file with user content before it and an unterminated last
/// line after it. The repair is reported, and prompts for a new shell even
/// though the artifact itself was already installed.
#[test]
fn self_bootstrap_rewrites_a_stale_rc_block() {
    let home = fresh_home_rc_safe();
    let user_home = fresh_home();
    let rc = user_home.path().join(".bashrc");
    let before = "# user content\nalias ll='ls -la'\n\n";
    let after = "\n\texport EDITOR=vi  \n# no trailing newline";
    let stale = rc_block(r#"export PATH="$HOME/.fuz/bin:$PATH""#);
    std::fs::write(&rc, format!("{before}{stale}{after}")).unwrap();

    // Install first without touching the rc, so the repairing run below is an
    // "already installed" re-run.
    let install = run_with_env(
        home.path(),
        &["self", "bootstrap", "--no-modify-path"],
        &[("HOME", user_home.path().to_str().unwrap())],
    );
    assert!(install.status.success());

    let out = bootstrap_modifying_path(home.path(), user_home.path(), "/bin/bash");
    let fresh = rc_block(&format!(
        r#"export PATH="{}:$PATH""#,
        home.path().join("bin").display()
    ));
    assert_eq!(
        std::fs::read_to_string(&rc).unwrap(),
        format!("{before}{fresh}{after}"),
        "only the block body changed"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("updated the fuz block in ~/.bashrc"),
        "reports the repair: {stderr}"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("already installed") && stdout.contains("source ~/.bashrc"),
        "a repaired rc prompts for a new shell on an already-installed re-run: {stdout}"
    );
}

/// A malformed managed block (begin marker, no end marker) is never guessed
/// at: the rc is left byte-identical, bootstrap still succeeds, and the user
/// gets the reason plus the line to add by hand.
#[test]
fn self_bootstrap_leaves_a_malformed_rc_block_untouched() {
    let home = fresh_home_rc_safe();
    let user_home = fresh_home();
    let rc = user_home.path().join(".bashrc");
    let seed = format!("alias a=b\n{RC_BEGIN}\nexport PATH=\"$HOME/.fuz/bin:$PATH\"\nalias c=d\n");
    std::fs::write(&rc, &seed).unwrap();

    let out = bootstrap_modifying_path(home.path(), user_home.path(), "/bin/bash");
    assert_eq!(
        std::fs::read_to_string(&rc).unwrap(),
        seed,
        "malformed rc untouched"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("left ~/.bashrc unchanged") && stderr.contains("malformed"),
        "says why: {stderr}"
    );
    assert!(
        stderr.contains(&format!(
            r#"export PATH="{}:$PATH""#,
            home.path().join("bin").display()
        )),
        "offers the correct line: {stderr}"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Next: ~/.bashrc was left unchanged; add "),
        "manual next step: {stdout}"
    );
}

/// A relative `HOME` is unusable: joining it would put the rc under the
/// process cwd (`./h/.bashrc`). The empty-`HOME` row of the same rule is
/// pinned in-process (`fuz_sys`'s `resolve_home_dir` test), not here: a
/// regression to std's `home_dir` would read an empty `HOME` as unset and
/// write this test's PATH block into the developer's own rc file.
#[test]
fn self_bootstrap_relative_home_writes_no_rc() {
    let home = fresh_home_rc_safe();
    let cwd = fresh_home();
    // The directory exists, so a write through the relative path would land.
    secure_dir(&cwd.path().join("h"));

    let out = std::process::Command::new(env!("CARGO_BIN_EXE_fuz"))
        .args(["self", "bootstrap"])
        .env("FUZ_HOME", home.path())
        .env("HOME", "h")
        .env("SHELL", "/bin/bash")
        .current_dir(cwd.path())
        .output()
        .expect("spawn fuz");
    assert!(
        out.status.success(),
        "bootstrap failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        std::fs::read_dir(cwd.path().join("h")).unwrap().count(),
        0,
        "nothing written under the relative home"
    );
    assert_eq!(
        std::fs::read_dir(cwd.path()).unwrap().count(),
        1,
        "nothing else written under the cwd"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains(
            "skipping shell config: the home directory (HOME) is not an absolute path: h"
        ),
        "reports the relative home: {stderr}"
    );
}

/// A relative `FUZ_HOME` is refused before anything is written: resolved
/// against the cwd it would install a home that every other directory's
/// commands miss. It exits 2, the error names the variable, and the hint says
/// to make it absolute.
#[test]
fn self_bootstrap_relative_fuz_home_is_refused() {
    let cwd = fresh_home();
    let user_home = fresh_home();

    let out = std::process::Command::new(env!("CARGO_BIN_EXE_fuz"))
        .args(["self", "bootstrap"])
        .env("FUZ_HOME", "relhome")
        .env("HOME", user_home.path())
        .env("SHELL", "/bin/bash")
        .current_dir(cwd.path())
        .output()
        .expect("spawn fuz");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "bootstrap must fail: {stderr}");
    assert!(
        stderr.contains("error: FUZ_HOME must be an absolute path, got relhome"),
        "names the relative FUZ_HOME: {stderr}"
    );
    assert!(
        stderr.contains("hint: set FUZ_HOME to an absolute path"),
        "advises an absolute FUZ_HOME: {stderr}"
    );
    assert_eq!(
        std::fs::read_dir(cwd.path()).unwrap().count(),
        0,
        "nothing installed under the cwd"
    );
    assert_eq!(
        std::fs::read_dir(user_home.path()).unwrap().count(),
        0,
        "no home and no rc written"
    );
}

fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

fn mode_of(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).unwrap().permissions().mode() & 0o7777
}

fn is_symlink(path: &Path) -> bool {
    std::fs::symlink_metadata(path)
        .unwrap()
        .file_type()
        .is_symlink()
}

/// The bash line bootstrap writes for a fuz home outside `HOME`.
fn absolute_bash_line(fuz_home: &Path) -> String {
    format!(r#"export PATH="{}:$PATH""#, fuz_home.join("bin").display())
}

/// A symlinked rc (`~/.bashrc -> dotfiles/bashrc`, the dotfile-manager layout)
/// stays a symlink: the block is appended to the link's target, and a stale
/// block there is rewritten on a later run under another `FUZ_HOME`.
#[test]
fn self_bootstrap_writes_through_a_symlinked_rc() {
    let home = fresh_home_rc_safe();
    let user_home = fresh_home();
    let dotfiles = user_home.path().join("dotfiles");
    secure_dir(&dotfiles);
    let real = dotfiles.join("bashrc");
    let seed = "alias ll='ls -la'\n";
    std::fs::write(&real, seed).unwrap();
    set_mode(&real, 0o644);
    let rc = user_home.path().join(".bashrc");
    std::os::unix::fs::symlink("dotfiles/bashrc", &rc).unwrap();

    let out = bootstrap_modifying_path(home.path(), user_home.path(), "/bin/bash");
    assert!(is_symlink(&rc), "rc is still a symlink after an append");
    assert_eq!(
        std::fs::read_to_string(&real).unwrap(),
        format!("{seed}\n{}", rc_block(&absolute_bash_line(home.path()))),
        "the link target holds the block"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("to PATH in ~/.bashrc"), "{stderr}");

    // A second fuz home repoints the block, again through the link.
    let other = fresh_home_rc_safe();
    let out = bootstrap_modifying_path(other.path(), user_home.path(), "/bin/bash");
    assert!(is_symlink(&rc), "rc is still a symlink after a rewrite");
    assert_eq!(
        std::fs::read_link(&rc).unwrap(),
        Path::new("dotfiles/bashrc")
    );
    assert_eq!(
        std::fs::read_to_string(&real).unwrap(),
        format!("{seed}\n{}", rc_block(&absolute_bash_line(other.path()))),
        "the stale block was rewritten in the link target"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("updated the fuz block in ~/.bashrc"),
        "{stderr}"
    );
}

/// A dangling rc symlink is left exactly as found — not followed into a new
/// file, not replaced by a regular one — and the note says why.
#[test]
fn self_bootstrap_leaves_a_dangling_rc_symlink_untouched() {
    let home = fresh_home_rc_safe();
    let user_home = fresh_home();
    let rc = user_home.path().join(".bashrc");
    std::os::unix::fs::symlink("dotfiles/bashrc", &rc).unwrap();

    let out = bootstrap_modifying_path(home.path(), user_home.path(), "/bin/bash");
    assert!(is_symlink(&rc), "rc is still a symlink");
    assert_eq!(
        std::fs::read_link(&rc).unwrap(),
        Path::new("dotfiles/bashrc")
    );
    assert_eq!(
        std::fs::read_dir(user_home.path()).unwrap().count(),
        1,
        "nothing created beside the link"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("note: left ~/.bashrc unchanged: it is a dangling symlink"),
        "says why: {stderr}"
    );
    assert!(
        stderr.contains(&absolute_bash_line(home.path())),
        "offers the line: {stderr}"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Next: ~/.bashrc was left unchanged; add "),
        "manual next step: {stdout}"
    );
}

/// An existing rc keeps its mode through an append and through a rewrite. A
/// private `0600` file stays private rather than being reset to the mode fuz
/// creates rc files with; a wide-open `0666` one is not narrowed by the umask
/// the replacement file is created under. (That second half asserts nothing
/// extra under `umask 000`, where creation narrows nothing; under any umask
/// that masks a bit — the usual `022` and `002` — it is what pins the mode
/// being restored after the write.)
#[test]
fn self_bootstrap_preserves_the_rc_file_mode() {
    for mode in [0o600, 0o666] {
        let home = fresh_home_rc_safe();
        let user_home = fresh_home();
        let rc = user_home.path().join(".bashrc");
        std::fs::write(&rc, "export SECRET_TOKEN=x\n").unwrap();
        set_mode(&rc, mode);

        bootstrap_modifying_path(home.path(), user_home.path(), "/bin/bash");
        assert!(
            std::fs::read_to_string(&rc).unwrap().contains(RC_BEGIN),
            "block appended"
        );
        assert_eq!(mode_of(&rc), mode, "mode {mode:o} kept across an append");

        let other = fresh_home_rc_safe();
        bootstrap_modifying_path(other.path(), user_home.path(), "/bin/bash");
        assert!(
            std::fs::read_to_string(&rc)
                .unwrap()
                .contains(&absolute_bash_line(other.path())),
            "block rewritten"
        );
        assert_eq!(mode_of(&rc), mode, "mode {mode:o} kept across a rewrite");
    }
}

/// A read-only rc is respected: bootstrap succeeds, the file and its mode are
/// untouched, and the note carries the reason and the line.
#[test]
fn self_bootstrap_leaves_a_read_only_rc_untouched() {
    let home = fresh_home_rc_safe();
    let user_home = fresh_home();
    let rc = user_home.path().join(".bashrc");
    let seed = "alias a=b\n";
    std::fs::write(&rc, seed).unwrap();
    set_mode(&rc, 0o444);

    let out = bootstrap_modifying_path(home.path(), user_home.path(), "/bin/bash");
    assert_eq!(std::fs::read_to_string(&rc).unwrap(), seed, "rc untouched");
    assert_eq!(mode_of(&rc), 0o444, "mode untouched");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("note: left ~/.bashrc unchanged: it is read-only"),
        "says why: {stderr}"
    );
    assert!(
        stderr.contains(&absolute_bash_line(home.path())),
        "offers the line: {stderr}"
    );
}

/// A read-only rc whose block is already correct needs no write, so a re-run
/// says nothing about it being read-only and leaves it byte for byte.
#[test]
fn self_bootstrap_says_nothing_about_a_read_only_rc_it_need_not_write() {
    let home = fresh_home_rc_safe();
    let user_home = fresh_home();
    let rc = user_home.path().join(".bashrc");
    std::fs::write(&rc, "alias a=b\n").unwrap();
    set_mode(&rc, 0o644);

    bootstrap_modifying_path(home.path(), user_home.path(), "/bin/bash");
    let installed = std::fs::read_to_string(&rc).unwrap();
    assert!(
        installed.contains(&absolute_bash_line(home.path())),
        "block added: {installed}"
    );
    set_mode(&rc, 0o444);

    let out = bootstrap_modifying_path(home.path(), user_home.path(), "/bin/bash");
    assert_eq!(
        std::fs::read_to_string(&rc).unwrap(),
        installed,
        "rc untouched"
    );
    assert_eq!(mode_of(&rc), 0o444, "mode untouched");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("read-only") && !stderr.contains("note:"),
        "nothing to report: {stderr}"
    );
}

/// A managed block the user added a line to is not rewritten — doing so would
/// delete that line. The note calls it edited, not malformed, and offers the
/// line.
#[test]
fn self_bootstrap_leaves_an_edited_rc_block_untouched() {
    let home = fresh_home_rc_safe();
    let user_home = fresh_home();
    let rc = user_home.path().join(".bashrc");
    let seed = format!(
        "alias a=b\n{RC_BEGIN}\nexport PATH=\"$HOME/.fuz/bin:$PATH\"\nexport MINE=1\n{RC_END}\n"
    );
    std::fs::write(&rc, &seed).unwrap();
    set_mode(&rc, 0o644);

    let out = bootstrap_modifying_path(home.path(), user_home.path(), "/bin/bash");
    assert_eq!(std::fs::read_to_string(&rc).unwrap(), seed, "rc untouched");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("note: left ~/.bashrc unchanged: its fuz block has been edited"),
        "says why: {stderr}"
    );
    assert!(
        !stderr.contains("malformed"),
        "not called malformed: {stderr}"
    );
    assert!(
        stderr.contains(&absolute_bash_line(home.path())),
        "offers the line: {stderr}"
    );
}

/// A block holding a single line fuz did not write — the user's own, where
/// fuz's line used to be — is not replaced, however stale it looks. Only a
/// PATH line in the form fuz writes for the shell is fuz's to rewrite.
#[test]
fn self_bootstrap_leaves_a_users_single_line_block_untouched() {
    let home = fresh_home_rc_safe();
    for (shell, rc_relative, line) in [
        ("/bin/bash", ".bashrc", "source ~/paths.sh"),
        (
            "/bin/bash",
            ".bashrc",
            r#"export PATH="$HOME/.fuz/bin:$PATH" # mine"#,
        ),
        // a bash line is not something fuz wrote into a fish config
        (
            "/usr/bin/fish",
            ".config/fish/config.fish",
            r#"export PATH="$HOME/.fuz/bin:$PATH""#,
        ),
    ] {
        let user_home = fresh_home();
        let rc = user_home.path().join(rc_relative);
        secure_dir(rc.parent().unwrap());
        let seed = format!("alias a=b\n{}", rc_block(line));
        std::fs::write(&rc, &seed).unwrap();
        set_mode(&rc, 0o644);

        let out = bootstrap_modifying_path(home.path(), user_home.path(), shell);
        assert_eq!(
            std::fs::read_to_string(&rc).unwrap(),
            seed,
            "rc untouched for {line:?}"
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains(&format!(
                "note: left ~/{rc_relative} unchanged: its fuz block has been edited"
            )),
            "says why for {line:?}: {stderr}"
        );
        assert!(
            !stderr.contains("updated"),
            "no rewrite claimed for {line:?}: {stderr}"
        );
        assert!(
            stderr.contains(&home.path().join("bin").display().to_string()),
            "offers the line for {line:?}: {stderr}"
        );
    }
}

/// Like [`bootstrap_modifying_path`], under a deadline: a bootstrap that
/// blocks is killed and fails the test instead of hanging the suite.
///
/// The deadline bounds a hang, not a bootstrap. Each run first reads, writes,
/// fsyncs and re-hashes the test-built binary under `TMPDIR`, beside every other
/// bootstrap test doing the same in parallel, so how long it takes is set by
/// the disk and its load, not by fuz: on a contended disk one has taken over
/// a minute. A blocked open never finishes, so any bound above the slowest
/// real install still catches one, and libtest names a test that runs past
/// 60 seconds.
fn bootstrap_modifying_path_within_deadline(fuz_home: &Path, user_home: &Path) -> Output {
    use std::process::Stdio;
    use std::time::{Duration, Instant};

    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_fuz"))
        .args(["self", "bootstrap"])
        .env("FUZ_HOME", fuz_home)
        .env("HOME", user_home)
        .env("SHELL", "/bin/bash")
        .env_remove("FUZ_RELEASE_LOG_URL")
        .env_remove("FUZ_RELEASE_LOG")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn fuz");
    let deadline = Instant::now() + Duration::from_secs(300);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("bootstrap blocked instead of finishing");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "bootstrap failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    out
}

/// What bootstrap says about an rc path that is not a regular file.
fn assert_not_regular_file_note(out: &Output, fuz_home: &Path) {
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("note: left ~/.bashrc unchanged: it is not a regular file"),
        "says why: {stderr}"
    );
    assert!(
        stderr.contains(&absolute_bash_line(fuz_home)),
        "offers the line: {stderr}"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Next: ~/.bashrc was left unchanged; add "),
        "manual next step: {stdout}"
    );
}

/// A directory where the rc file would be is left alone and named for what it
/// is.
#[test]
fn self_bootstrap_leaves_a_directory_rc_untouched() {
    let home = fresh_home_rc_safe();
    let user_home = fresh_home();
    let rc = user_home.path().join(".bashrc");
    secure_dir(&rc);

    let out = bootstrap_modifying_path(home.path(), user_home.path(), "/bin/bash");
    assert!(rc.is_dir(), "still a directory");
    assert_eq!(std::fs::read_dir(&rc).unwrap().count(), 0, "still empty");
    assert_not_regular_file_note(&out, home.path());
}

/// A FIFO where the rc file would be is never opened — reading one blocks
/// until a writer appears, so bootstrap would hang with fuz already installed.
#[test]
fn self_bootstrap_leaves_a_fifo_rc_untouched() {
    use std::os::unix::fs::FileTypeExt;

    let home = fresh_home_rc_safe();
    let user_home = fresh_home();
    let rc = user_home.path().join(".bashrc");
    if !make_fifo(&rc) {
        eprintln!("skipping: mkfifo(1) unavailable");
        return;
    }

    let out = bootstrap_modifying_path_within_deadline(home.path(), user_home.path());
    assert!(
        std::fs::metadata(&rc).unwrap().file_type().is_fifo(),
        "still a FIFO"
    );
    assert_not_regular_file_note(&out, home.path());
}

/// `~/.bashrc -> /dev/null` (a way to keep a tool from growing an rc) is left
/// alone: the link stays, and nothing is renamed over its target.
#[test]
fn self_bootstrap_leaves_a_dev_null_rc_symlink_untouched() {
    // Only a regression reaches the write, and as root that write would
    // replace the system's `/dev/null`; a test must not carry that risk.
    if running_as_root() {
        eprintln!("skipping: running as root");
        return;
    }
    let home = fresh_home_rc_safe();
    let user_home = fresh_home();
    let rc = user_home.path().join(".bashrc");
    std::os::unix::fs::symlink("/dev/null", &rc).unwrap();

    let out = bootstrap_modifying_path(home.path(), user_home.path(), "/bin/bash");
    assert!(is_symlink(&rc), "rc is still a symlink");
    assert_eq!(std::fs::read_link(&rc).unwrap(), Path::new("/dev/null"));
    assert_eq!(
        std::fs::read_dir(user_home.path()).unwrap().count(),
        1,
        "nothing created beside the link"
    );
    assert_not_regular_file_note(&out, home.path());
}

/// Either fish form for the current bin dir is left alone, whichever one the
/// `fish` on PATH (or its absence) would have this run write.
#[test]
fn self_bootstrap_accepts_either_fish_form() {
    let home = fresh_home_rc_safe();
    let bin_dir = home.path().join("bin");
    for line in [
        format!("fish_add_path {}", bin_dir.display()),
        format!("set -gx PATH {} $PATH", bin_dir.display()),
    ] {
        let user_home = fresh_home();
        let rc = user_home.path().join(".config/fish/config.fish");
        secure_dir(rc.parent().unwrap());
        let seed = format!("set -g fish_greeting\n\n{}", rc_block(&line));
        std::fs::write(&rc, &seed).unwrap();
        set_mode(&rc, 0o644);

        let out = bootstrap_modifying_path(home.path(), user_home.path(), "/usr/bin/fish");
        assert_eq!(
            std::fs::read_to_string(&rc).unwrap(),
            seed,
            "rc untouched for {line:?}"
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            !stderr.contains("updated") && !stderr.contains("note:"),
            "no rewrite claimed for {line:?}: {stderr}"
        );
    }
}

/// When the rc can't be read or replaced, the note carries the underlying io
/// cause, not just "failed to update".
#[test]
fn self_bootstrap_rc_error_note_carries_the_io_cause() {
    let home = fresh_home_rc_safe();

    // a writable rc in a home directory that isn't: the replacement can't be
    // created beside it. Root writes there regardless, so it has no such case
    // to observe.
    if !running_as_root() {
        let user_home = fresh_home();
        let rc = user_home.path().join(".bashrc");
        std::fs::write(&rc, "alias a=b\n").unwrap();
        set_mode(&rc, 0o644);
        set_mode(user_home.path(), 0o500);
        let out = bootstrap_modifying_path(home.path(), user_home.path(), "/bin/bash");
        set_mode(user_home.path(), 0o700);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("note: couldn't update ~/.bashrc (") && stderr.contains("os error"),
            "names the io cause: {stderr}"
        );
        assert!(
            stderr.contains(&absolute_bash_line(home.path())),
            "offers the line: {stderr}"
        );
        assert_eq!(
            std::fs::read_to_string(&rc).unwrap(),
            "alias a=b\n",
            "rc untouched"
        );
    }

    // an rc that is not UTF-8
    let user_home = fresh_home();
    let rc = user_home.path().join(".bashrc");
    std::fs::write(&rc, b"alias a=\xff\n").unwrap();
    set_mode(&rc, 0o644);
    let out = bootstrap_modifying_path(home.path(), user_home.path(), "/bin/bash");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("note: couldn't update ~/.bashrc (") && stderr.contains("UTF-8"),
        "names the io cause: {stderr}"
    );
    assert_eq!(
        std::fs::read(&rc).unwrap(),
        b"alias a=\xff\n",
        "rc untouched"
    );
}

/// `--quiet` silences the PATH-setup notes along with the success output; the
/// rc is still left alone.
#[test]
fn self_bootstrap_quiet_suppresses_path_notes() {
    let home = fresh_home_rc_safe();
    let user_home = fresh_home();
    let rc = user_home.path().join(".bashrc");
    std::fs::write(&rc, "alias a=b\n").unwrap();
    set_mode(&rc, 0o444);

    let out = run_with_env(
        home.path(),
        &["self", "bootstrap", "--quiet"],
        &[
            ("HOME", user_home.path().to_str().unwrap()),
            ("SHELL", "/bin/bash"),
        ],
    );
    assert!(out.status.success());
    assert!(out.stdout.is_empty() && out.stderr.is_empty(), "{out:?}");
    assert_eq!(std::fs::read_to_string(&rc).unwrap(), "alias a=b\n");
}

/// PATH setup is best-effort: when the shell rc can't be read/written, bootstrap
/// still succeeds (exit 0 — the artifact is installed and runnable regardless)
/// and prints a manual-PATH note rather than hard-failing. A `.bashrc` that is
/// not UTF-8 forces the rc read to fail deterministically, even as root (mode
/// bits wouldn't block a root-run CI job; invalid UTF-8 does).
#[test]
fn self_bootstrap_soft_skips_when_rc_is_unwritable() {
    let home = fresh_home();
    // An rc that can't be read as text → the update fails before any write.
    std::fs::write(home.path().join(".bashrc"), b"alias a=\xff\n").unwrap();

    let out = run_with_env(
        home.path(),
        &["self", "bootstrap"],
        &[("SHELL", "/bin/bash")],
    );
    assert!(
        out.status.success(),
        "bootstrap must still succeed when rc editing fails: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // The artifact is installed and PATH-independent.
    let json = stdout_json(&fuz(home.path(), &["self", "status", "--json"]));
    assert!(
        json["artifact"]["hash"]
            .as_str()
            .is_some_and(|h| h.starts_with("v1-")),
        "artifact installed despite the rc failure"
    );

    // The user is told how to finish manually.
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("couldn't update"),
        "prints a manual-PATH note with the reason: {stderr}"
    );
}

//
// The release log surface of `fuz self`
//

const RELEASE_LOG_URL: &str = "FUZ_RELEASE_LOG_URL";
const RELEASE_LOG: &str = "FUZ_RELEASE_LOG";

/// Every file and symlink under `root` with its content or target, and every
/// directory. Content is recorded as a digest, so a failed comparison prints a
/// readable difference.
fn tree(root: &Path) -> std::collections::BTreeMap<String, String> {
    fn walk(root: &Path, path: &Path, out: &mut std::collections::BTreeMap<String, String>) {
        let meta = std::fs::symlink_metadata(path).unwrap();
        let key = path.strip_prefix(root).unwrap().display().to_string();
        if meta.file_type().is_symlink() {
            let target = std::fs::read_link(path).unwrap();
            out.insert(key, format!("-> {}", target.display()));
        } else if meta.is_dir() {
            out.insert(key, "dir".to_string());
            for entry in std::fs::read_dir(path).unwrap() {
                walk(root, &entry.unwrap().path(), out);
            }
        } else {
            let bytes = std::fs::read(path).unwrap();
            out.insert(key, fuz_artifact::ContentHash::blake3(&bytes).to_hex());
        }
    }
    let mut out = std::collections::BTreeMap::new();
    walk(root, root, &mut out);
    out
}

/// No fuz was installed into `fuz_home`: no artifact, no `current`, no
/// `bin/fuz`, no switch history.
#[track_caller]
fn assert_nothing_installed(fuz_home: &Path) {
    assert!(
        std::fs::symlink_metadata(fuz_home.join("bin").join("fuz")).is_err(),
        "bin/fuz must not exist"
    );
    assert!(
        std::fs::symlink_metadata(fuz_home.join("current")).is_err(),
        "current must not exist"
    );
    assert_eq!(count_artifact_dirs(fuz_home), 0, "no artifact dir");
    let leftovers: Vec<_> = std::fs::read_dir(fuz_home.join("artifacts"))
        .map(|entries| entries.map(|entry| entry.unwrap().file_name()).collect())
        .unwrap_or_default();
    assert!(leftovers.is_empty(), "artifacts/ holds {leftovers:?}");
    assert!(!fuz_home.join("state").join("history.json").exists());
}

/// A user home holding a `.bashrc` the user wrote, and that file's bytes.
fn user_home_with_rc() -> (tempfile::TempDir, std::path::PathBuf, Vec<u8>) {
    let user_home = fresh_home();
    let rc = user_home.path().join(".bashrc");
    let bytes = b"# the user's own rc\nalias ll='ls -l'\n".to_vec();
    std::fs::write(&rc, &bytes).unwrap();
    (user_home, rc, bytes)
}

/// The PATH-modifying `self bootstrap` under a release log configuration,
/// with `HOME` and `SHELL` pinned. Does not assert the exit code.
fn bootstrap_under_log(
    fuz_home: &Path,
    user_home: &Path,
    extra_args: &[&str],
    log_env: &[(&str, &str)],
) -> Output {
    let mut args = vec!["self", "bootstrap"];
    args.extend_from_slice(extra_args);
    let mut envs = vec![
        ("HOME", user_home.to_str().unwrap()),
        ("SHELL", "/bin/bash"),
    ];
    envs.extend_from_slice(log_env);
    run_with_env(fuz_home, &args, &envs)
}

/// With no witness configured `self bootstrap` is what it is without the
/// check: it installs, and reads, prints, and caches nothing about the log.
#[test]
fn self_bootstrap_without_a_witness_knows_nothing_of_the_release_log() {
    let home = fresh_home_rc_safe();
    let (user_home, rc, _) = user_home_with_rc();
    // The switch alone, with no witness, changes nothing either.
    for log_env in [&[][..], &[(RELEASE_LOG, "off")]] {
        let out = bootstrap_under_log(home.path(), user_home.path(), &[], log_env);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(0), "{stderr}");
        assert!(!stderr.contains("release log"), "{stderr}");
        assert!(home.path().join("bin").join("fuz").exists());
        assert!(!home.path().join("state").join("release_log").exists());
    }
    assert!(
        std::fs::read_to_string(&rc)
            .unwrap()
            .contains("# >>> fuz initialize >>>")
    );
}

/// The opt-out is visible and does not stop the install: one warning, under
/// `--quiet` too, and no head is fetched or cached.
#[test]
fn self_bootstrap_opt_out_warns_once_and_installs() {
    const WARNING: &str = "warning: the release log check is disabled by FUZ_RELEASE_LOG=off";
    for quiet in [&[][..], &["--quiet"]] {
        let home = fresh_home_rc_safe();
        let (user_home, _, _) = user_home_with_rc();
        // A witness that could not confirm anything: it is never asked.
        let witness = fresh_home();
        let out = bootstrap_under_log(
            home.path(),
            user_home.path(),
            quiet,
            &[
                (RELEASE_LOG_URL, witness.path().to_str().unwrap()),
                (RELEASE_LOG, "off"),
            ],
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(0), "{quiet:?}: {stderr}");
        assert_eq!(stderr.matches(WARNING).count(), 1, "{quiet:?}: {stderr}");
        assert!(home.path().join("bin").join("fuz").exists(), "{quiet:?}");
        assert!(!home.path().join("state").join("release_log").exists());
    }
}

/// A release log configuration the check cannot run under stops `self
/// bootstrap` before it reads or creates anything: exit 2, the fuz home still
/// empty, the rc file as the user left it.
#[test]
fn self_bootstrap_bad_release_log_configuration_exits_2_and_touches_nothing() {
    let home = fresh_home_rc_safe();
    let (user_home, rc, rc_bytes) = user_home_with_rc();
    let missing = home.path().join("no-such-witness");
    for log_env in [
        &[(RELEASE_LOG, "OFF")][..],
        &[(RELEASE_LOG_URL, "https://log.invalid"), (RELEASE_LOG, "0")],
        &[(RELEASE_LOG_URL, "nope://x")],
        &[(RELEASE_LOG_URL, missing.to_str().unwrap())],
    ] {
        let out = bootstrap_under_log(home.path(), user_home.path(), &[], log_env);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(2), "{log_env:?}: {stderr}");
        assert!(
            stderr.contains("release log configuration error"),
            "{stderr}"
        );
        assert!(stderr.contains("hint: "), "{log_env:?}: {stderr}");
        assert!(out.stdout.is_empty(), "{log_env:?}");
        assert!(tree(home.path()).len() == 1, "the fuz home stays empty");
        assert_eq!(std::fs::read(&rc).unwrap(), rc_bytes, "{log_env:?}");
    }
}

/// No witness serves a head and nothing is cached: the binary cannot be
/// confirmed, so it is not installed. Exit 75 — not a refusal, and the message
/// says so — with the rc file untouched.
#[test]
fn self_bootstrap_unreachable_witness_exits_75_and_installs_nothing() {
    for quiet in [&[][..], &["--quiet"]] {
        let home = fresh_home_rc_safe();
        let (user_home, rc, rc_bytes) = user_home_with_rc();
        // An existing directory with no head.json in it.
        let witness = fresh_home();
        let out = bootstrap_under_log(
            home.path(),
            user_home.path(),
            quiet,
            &[(RELEASE_LOG_URL, witness.path().to_str().unwrap())],
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(75), "{quiet:?}: {stderr}");
        assert!(
            stderr.contains("error: cannot confirm fuz ")
                && stderr.contains("in the release log yet"),
            "{quiet:?}: {stderr}"
        );
        assert!(
            stderr.contains("hint: This is not a refusal"),
            "{quiet:?}: {stderr}"
        );
        assert!(out.stdout.is_empty(), "{quiet:?}: nothing reports success");
        assert_nothing_installed(home.path());
        assert!(!home.path().join("state").join("release_log").exists());
        assert_eq!(std::fs::read(&rc).unwrap(), rc_bytes, "{quiet:?}");
    }
}

/// A witness that serves something other than a head is a hard failure: exit
/// 1, nothing installed, nothing cached, the rc file untouched. A document no
/// trusted key signed is the same failure — the binary trusts its embedded
/// keys alone.
#[test]
fn self_bootstrap_bad_head_exits_1_and_installs_nothing() {
    for body in [&b"not a head"[..], b"{}", b""] {
        let home = fresh_home_rc_safe();
        let (user_home, rc, rc_bytes) = user_home_with_rc();
        let witness = fresh_home();
        std::fs::write(witness.path().join("head.json"), body).unwrap();
        let out = bootstrap_under_log(
            home.path(),
            user_home.path(),
            &[],
            &[(RELEASE_LOG_URL, witness.path().to_str().unwrap())],
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(1), "{body:?}: {stderr}");
        assert!(
            stderr.contains("served an unusable head"),
            "{body:?}: {stderr}"
        );
        assert!(out.stdout.is_empty(), "{body:?}");
        assert_nothing_installed(home.path());
        assert!(!home.path().join("state").join("release_log").exists());
        assert_eq!(std::fs::read(&rc).unwrap(), rc_bytes, "{body:?}");
    }
}

/// A refused bootstrap leaves an existing install exactly as it was: the
/// artifact, `current`, `bin/`, and the history are not touched.
#[test]
fn self_bootstrap_refusal_leaves_an_existing_install_as_it_was() {
    let home = fresh_home_rc_safe();
    let (user_home, rc, rc_bytes) = user_home_with_rc();
    let a = seed_artifact(home.path(), 0x33, "2020-01-01T00:00:01Z");
    assert!(
        fuz(home.path(), &["artifact", "use", &a.hash])
            .status
            .success()
    );
    let before = tree(home.path());

    let witness = fresh_home();
    let out = bootstrap_under_log(
        home.path(),
        user_home.path(),
        &[],
        &[(RELEASE_LOG_URL, witness.path().to_str().unwrap())],
    );
    assert_eq!(
        out.status.code(),
        Some(75),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    // Everything that was there is as it was. The only additions are the empty
    // home directories bootstrap ensures before it asks the log.
    let mut after = tree(home.path());
    after.retain(|path, kind| before.contains_key(path) || kind != "dir");
    assert_eq!(after, before);
    assert_eq!(std::fs::read(&rc).unwrap(), rc_bytes);
}

/// Put `bytes` where the cached release log head lives.
fn write_head_cache(fuz_home: &Path, bytes: &[u8]) -> std::path::PathBuf {
    let dir = fuz_home.join("state").join("release_log");
    secure_dir(&dir);
    let path = dir.join("head.json");
    std::fs::write(&path, bytes).unwrap();
    path
}

/// `self version` and `self status` are diagnostics: a cached head that cannot
/// be used is one warning line naming the file, the exit code and stdout are
/// what they are without it, and `status --json` stays one JSON document with
/// no `release_log` key.
#[test]
fn self_version_and_status_survive_an_unusable_release_log_cache() {
    let home = fresh_home();
    let a = seed_artifact(home.path(), 0x44, "2020-01-01T00:00:01Z");
    assert!(
        fuz(home.path(), &["artifact", "use", &a.hash])
            .status
            .success()
    );
    let witness = fresh_home();
    let log_env = [(RELEASE_LOG_URL, witness.path().to_str().unwrap())];
    let cache = write_head_cache(home.path(), b"not a head");
    let warning = format!(
        "warning: cached release log head {} is unusable: ",
        cache.display()
    );

    for args in [
        &["self", "version"][..],
        &["self", "status"],
        &["self", "status", "--json"],
    ] {
        let plain = fuz(home.path(), args);
        assert!(plain.status.success(), "{args:?}");
        assert!(
            plain.stderr.is_empty(),
            "{args:?}: no witness configured, nothing is read: {}",
            String::from_utf8_lossy(&plain.stderr)
        );

        let out = run_with_env(home.path(), args, &log_env);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(0), "{args:?}: {stderr}");
        assert_eq!(stderr.matches(&warning).count(), 1, "{args:?}: {stderr}");
        assert_eq!(stderr.lines().count(), 1, "{args:?}: {stderr}");
        assert_eq!(out.stdout, plain.stdout, "{args:?}: stdout is unchanged");
    }
    let json = stdout_json(&run_with_env(
        home.path(),
        &["self", "status", "--json"],
        &log_env,
    ));
    assert!(json["release_log"].is_null(), "{json}");
    // The diagnostics repaired nothing: the file is as it was.
    assert_eq!(std::fs::read(&cache).unwrap(), b"not a head");
}

/// The diagnostics also survive a release log configuration nothing can run
/// under — one warning line, exit 0 — and say nothing under the opt-out, with
/// no witness configured, or with nothing cached.
#[test]
fn self_version_and_status_survive_any_release_log_configuration() {
    let home = fresh_home();
    let witness = fresh_home();
    let witness = witness.path().to_str().unwrap();
    for args in [&["self", "version"][..], &["self", "status", "--json"]] {
        let plain = fuz(home.path(), args);
        assert!(plain.status.success(), "{args:?}");

        let out = run_with_env(home.path(), args, &[(RELEASE_LOG, "OFF")]);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(0), "{args:?}: {stderr}");
        assert!(
            stderr.starts_with("warning: release log configuration error: "),
            "{args:?}: {stderr}"
        );
        assert_eq!(stderr.lines().count(), 1, "{args:?}: {stderr}");
        assert_eq!(out.stdout, plain.stdout, "{args:?}");

        for log_env in [
            // Enforced, nothing cached.
            &[(RELEASE_LOG_URL, witness)][..],
            // Opted out: these commands hold no release to the log.
            &[(RELEASE_LOG_URL, witness), (RELEASE_LOG, "off")],
            &[(RELEASE_LOG, "off")],
        ] {
            let out = run_with_env(home.path(), args, log_env);
            assert_eq!(out.status.code(), Some(0), "{args:?} {log_env:?}");
            assert!(
                out.stderr.is_empty(),
                "{args:?} {log_env:?}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            assert_eq!(out.stdout, plain.stdout, "{args:?} {log_env:?}");
        }
    }
    assert!(!home.path().join("state").join("release_log").exists());
}

/// With nothing installed, and with a `current` link that points nowhere, the
/// commands still look the release log up — for the version they report, this
/// binary's own — and still never fail on it: an unusable cache is the same
/// one warning line, and `status --json` is the same document it is without a
/// witness, with no `release_log` key.
#[test]
fn self_version_and_status_look_up_this_binary_when_nothing_is_installed() {
    for dangling in [false, true] {
        let home = fresh_home();
        if dangling {
            std::os::unix::fs::symlink("artifacts/v1-gone", home.path().join("current")).unwrap();
        }
        let witness = fresh_home();
        let log_env = [(RELEASE_LOG_URL, witness.path().to_str().unwrap())];
        let cache = write_head_cache(home.path(), b"not a head");
        let warning = format!(
            "warning: cached release log head {} is unusable: ",
            cache.display()
        );
        for args in [&["self", "version"][..], &["self", "status", "--json"]] {
            let plain = fuz(home.path(), args);
            assert!(plain.status.success(), "{dangling} {args:?}");
            let out = run_with_env(home.path(), args, &log_env);
            let stderr = String::from_utf8_lossy(&out.stderr);
            assert_eq!(out.status.code(), Some(0), "{dangling} {args:?}: {stderr}");
            assert_eq!(stderr.matches(&warning).count(), 1, "{dangling} {args:?}");
            assert_eq!(out.stdout, plain.stdout, "{dangling} {args:?}");
        }
        let json = stdout_json(&run_with_env(
            home.path(),
            &["self", "status", "--json"],
            &log_env,
        ));
        assert!(json["version"].is_string(), "{json}");
        assert!(json["artifact"].is_null(), "{json}");
        assert!(json["release_log"].is_null(), "{json}");
    }
}

/// Where a real check follows, an unusable cache is that check's hard
/// failure, said once: `self bootstrap` exits 1 with the error and its hint,
/// installs nothing, and leaves the cache file as it found it.
#[test]
fn self_bootstrap_refuses_on_an_unusable_release_log_cache() {
    let home = fresh_home_rc_safe();
    let (user_home, rc, rc_bytes) = user_home_with_rc();
    let witness = fresh_home();
    let cache = write_head_cache(home.path(), b"not a head");

    let out = bootstrap_under_log(
        home.path(),
        user_home.path(),
        &[],
        &[(RELEASE_LOG_URL, witness.path().to_str().unwrap())],
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    let needle = format!("cached release log head {} is unusable", cache.display());
    assert_eq!(stderr.matches(&needle).count(), 1, "{stderr}");
    assert!(stderr.contains(&format!("error: {needle}")), "{stderr}");
    assert!(stderr.contains("hint: "), "{stderr}");
    assert_nothing_installed(home.path());
    assert_eq!(std::fs::read(&cache).unwrap(), b"not a head");
    assert_eq!(std::fs::read(&rc).unwrap(), rc_bytes);
}

/// What a store serves is read before any signature is checked, and what a
/// refusal repeats of it is printed escaped: a latest pointer naming a version
/// built to drive the terminal, and a manifest whose field name is, reach
/// stderr with no control character, direction override, or blank filler in
/// them — on the update checks and on the installs.
#[test]
fn text_from_an_unverified_store_is_printed_escaped() {
    const HOSTILE: &str = "9.9.9\u{1b}[2K\r\u{202e}\u{2800}\"x";
    const SHOWN: &str = "9.9.9\\u{1b}[2K\\r\\u{202e}\\u{2800}\\\"x";
    let target = fuz_release::current_target();
    let home = fresh_home();
    let store = fresh_home();
    let storage = store.path().to_str().unwrap();
    let pointer = serde_json::to_vec(&serde_json::json!({ "version": HOSTILE })).unwrap();
    std::fs::create_dir_all(store.path().join("tools/fuzd")).unwrap();
    std::fs::write(store.path().join(format!("latest-{target}.json")), &pointer).unwrap();
    std::fs::write(
        store
            .path()
            .join(format!("tools/fuzd/latest-{target}.json")),
        &pointer,
    )
    .unwrap();

    let assert_printable = |stderr: &str, context: &str| {
        for raw in ['\u{1b}', '\r', '\u{202e}', '\u{2800}'] {
            assert!(!stderr.contains(raw), "{context}: {raw:?} in {stderr:?}");
        }
    };
    let cases: [(&[&str], &str); 5] = [
        (&["self", "upgrade", "--storage", storage, "--check"], "fuz"),
        (
            &["self", "upgrade", "--storage", storage, "--check", "--json"],
            "fuz",
        ),
        (&["self", "upgrade", "--storage", storage], "fuz"),
        (
            &["tool", "upgrade", "fuzd", "--storage", storage, "--check"],
            "tools/fuzd/fuzd",
        ),
        (
            &["tool", "install", "fuzd", "--storage", storage],
            "tools/fuzd/fuzd",
        ),
    ];
    for (args, stem) in cases {
        let out = fuz(home.path(), args);
        let stderr = String::from_utf8_lossy(&out.stderr);
        let context = format!("{args:?}");
        assert_eq!(out.status.code(), Some(1), "{context}: {stderr}");
        assert!(out.stdout.is_empty(), "{context}");
        assert_printable(&stderr, &context);
        assert!(
            stderr.starts_with(&format!(
                "error: storage error: invalid storage key \
                 \"{stem}-{SHOWN}-{target}.manifest.json\": key contains invalid characters"
            )),
            "{context}: {stderr}"
        );
        // The error and its hint, and no line the store added.
        assert_eq!(stderr.lines().count(), 2, "{context}: {stderr}");
        assert!(
            stderr.lines().nth(1).unwrap().starts_with("hint: "),
            "{context}"
        );
    }

    // A manifest served at the key the pointer names, which does not parse:
    // the parser's message repeats the field name.
    let pointer = serde_json::to_vec(&serde_json::json!({ "version": "0.1.0" })).unwrap();
    std::fs::write(store.path().join(format!("latest-{target}.json")), pointer).unwrap();
    let manifest = serde_json::to_vec(&serde_json::json!({ HOSTILE: 1 })).unwrap();
    std::fs::write(
        store
            .path()
            .join(format!("fuz-0.1.0-{target}.manifest.json")),
        manifest,
    )
    .unwrap();
    let out = fuz(
        home.path(),
        &["self", "upgrade", "--storage", storage, "--check"],
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert_printable(&stderr, "an unparseable manifest");
    // Unquoted, so the `"` in it is left as it is.
    let unquoted = SHOWN.replace("\\\"", "\"");
    assert!(
        stderr.starts_with(&format!(
            "error: manifest error: failed to parse manifest: unknown field `{unquoted}`, \
             expected one of "
        )),
        "{stderr}"
    );
    assert_eq!(stderr.lines().count(), 2, "{stderr}");
    assert_nothing_installed(home.path());
}

/// Pins the human form of `fuz self status` under a home that resolves: an
/// absent fuzd is "not installed" and a stopped one is "stopped", each with
/// its hint — never the "unknown" a home that cannot be resolved gets.
#[test]
fn self_status_names_an_absent_and_a_stopped_fuzd() {
    let version = env!("CARGO_PKG_VERSION");
    let home = fresh_home();

    let out = fuz(home.path(), &["self", "status"]);
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        format!("fuz {version}\nfuzd: not installed\n  hint: fuz tool install fuzd\n")
    );

    std::fs::create_dir_all(home.path().join("bin")).unwrap();
    std::fs::write(home.path().join("bin").join("fuzd"), b"#!/bin/sh\n").unwrap();
    let out = fuz(home.path(), &["self", "status"]);
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        format!("fuz {version}\nfuzd: stopped\n  hint: fuzd start\n")
    );
}
