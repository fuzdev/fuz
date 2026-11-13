//! End-to-end coverage of the home-directory rule every `$HOME` reader shares
//! (`fuz_sys::home_dir`: non-empty and absolute) and `FUZ_HOME`'s own (empty
//! is unset, relative is refused), through the real binary — the only way to
//! drive a process environment, since the workspace forbids `set_var`.
//!
//! Each case runs with the cwd at a tempdir seeded with whatever an empty or
//! relative home would have reached under it, so a regression shows as that
//! cwd-relative read or write rather than the refusal. No case can write to
//! the developer's own home: every empty-`HOME` case runs a read-only verb
//! (`artifact list`, `tool upgrade --check`, `artifact build --dry-run`, a
//! one-shot `workload observe`, `self status`, `self version`), because a
//! regression to std's `home_dir` would read an empty `HOME` as
//! unset and fall back to the password database's home.
#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test helpers outside `#[test]` fns panic on a failed setup or check"
)]

mod common;
use common::{fresh_home, fresh_home_rc_safe};

use std::path::Path;
use std::process::{Command, Output};

/// Spawn `fuz` in `cwd` with `HOME` and `FUZ_HOME` exactly as given (`None`
/// removes the variable), and none of the caller's variables that would steer
/// the commands below.
fn run_in(cwd: &Path, home: &str, fuz_home: Option<&Path>, args: &[&str]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_fuz"));
    cmd.args(args)
        .current_dir(cwd)
        .env("HOME", home)
        .env_remove("FUZ_HOME")
        .env_remove("FUZ_RELEASE_LOG_URL")
        .env_remove("FUZ_RELEASE_LOG")
        .env_remove("FUZ_FORGE_TOKEN")
        .env_remove("FUZ_FORGE_HOME")
        .env_remove("FUZ_FORGE_BASE_URL")
        .env_remove("FUZ_DEV_REPO");
    if let Some(fuz_home) = fuz_home {
        cmd.env("FUZ_HOME", fuz_home);
    }
    cmd.output().expect("spawn fuz")
}

/// With `FUZ_HOME` unset, an empty or relative `HOME` is an error naming the
/// reason, with the hint, and exits 2 (the caller's environment to fix) — not
/// a `.fuz` resolved under the cwd, and (for the empty one) not the password
/// database's home either.
#[test]
fn unusable_home_without_fuz_home_is_refused() {
    for (home, reason) in [
        ("", "the home directory (HOME) is empty"),
        ("h", "the home directory (HOME) is not an absolute path: h"),
    ] {
        let cwd = fresh_home();
        let out = run_in(cwd.path(), home, None, &["artifact", "list", "--json"]);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(2), "HOME={home:?}: {stderr}");
        assert!(
            stderr.contains(&format!("error: cannot resolve ~/.fuz: {reason}")),
            "HOME={home:?}: {stderr}"
        );
        assert!(
            stderr.contains("hint: set HOME to your home directory's absolute path"),
            "HOME={home:?}: {stderr}"
        );
        assert!(out.stdout.is_empty(), "HOME={home:?}: no listing printed");
    }
}

/// `fuz workload observe` finds the daemon's socket under the fuz home, so a
/// home the home layer refuses is that layer's error, its hint, and its exit
/// code `2` — what `fuzd` prints and exits for it — rather than a report that
/// the daemon is not running, and nothing is read or created under the cwd.
///
/// The cwd is seeded with the run directory a relative home would name, so a
/// path resolved under it would be answered with "daemon not running" there.
#[test]
fn workload_observe_refuses_a_home_it_cannot_resolve_with_the_hint() {
    let relative = (
        "error: FUZ_HOME must be an absolute path, got rel\n\
         hint: set FUZ_HOME to an absolute path, or unset it to use ~/.fuz\n",
        None,
        Some(Path::new("rel")),
    );
    let unusable = |reason: &str| {
        format!(
            "error: cannot resolve ~/.fuz: {reason}\n\
             hint: set HOME to your home directory's absolute path, \
             or FUZ_HOME to an absolute path\n"
        )
    };
    let empty_home = unusable("the home directory (HOME) is empty");
    let relative_home = unusable("the home directory (HOME) is not an absolute path: h");
    let cases: [(&str, Option<&str>, Option<&Path>); 3] = [
        relative,
        (&empty_home, Some(""), None),
        (&relative_home, Some("h"), None),
    ];
    for (expected, home, fuz_home) in cases {
        let cwd = fresh_home();
        for seeded in ["rel/run", "h/.fuz/run", ".fuz/run"] {
            std::fs::create_dir_all(cwd.path().join(seeded)).unwrap();
        }
        let before = tree(cwd.path());
        // With a relative `FUZ_HOME`, `HOME` is a usable directory: only the
        // variable under test is at fault.
        let home = home.unwrap_or_else(|| cwd.path().to_str().unwrap());
        // One-shot forms only under an unusable `HOME`: they read a snapshot
        // and exit, whatever home a regression would reach.
        for args in [
            &["workload", "observe", "process"][..],
            &["workload", "observe", "network"],
            &["workload", "observe", "services"],
        ] {
            let out = run_in(cwd.path(), home, fuz_home, args);
            let stderr = String::from_utf8_lossy(&out.stderr);
            let context = format!("HOME={home:?} FUZ_HOME={fuz_home:?} `fuz {args:?}`");
            assert_eq!(out.status.code(), Some(2), "{context}: {stderr}");
            assert_eq!(stderr, expected, "{context}");
            assert!(out.stdout.is_empty(), "{context}: nothing on stdout");
        }
        assert_eq!(tree(cwd.path()), before, "the cwd changed");
    }
}

/// A `FUZ_HOME` too long for the daemon socket under it is refused before any
/// connect, exit 2 with the hint to shorten it — not reported as a daemon that
/// is not running, whose hint would send the caller to `fuzd start`.
#[test]
fn workload_observe_refuses_a_fuz_home_too_long_for_the_socket() {
    let dir = fresh_home();
    let home = fresh_home();
    let fuz_home = dir.path().join("h".repeat(120));
    let out = run_in(
        dir.path(),
        home.path().to_str().unwrap(),
        Some(&fuz_home),
        &["workload", "observe", "process"],
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("107-byte limit"), "{stderr}");
    assert!(
        stderr.contains("hint: the socket lives at `$FUZ_HOME/run/socket`"),
        "{stderr}"
    );
    assert!(!stderr.contains("fuzd start"), "{stderr}");
    assert!(!fuz_home.exists(), "the home was created");
}

/// The three homes the home layer refuses, each with the warning `fuz self
/// version` / `status` print for it: the error, then its hint. `HOME` is
/// `None` where it is not the variable under test (the case then runs with a
/// usable one).
fn refused_homes() -> [(String, Option<&'static str>, Option<&'static Path>); 3] {
    let unusable = |reason: &str| {
        format!(
            "warning: cannot resolve ~/.fuz: {reason}\n\
             hint: set HOME to your home directory's absolute path, \
             or FUZ_HOME to an absolute path\n"
        )
    };
    [
        (
            "warning: FUZ_HOME must be an absolute path, got rel\n\
             hint: set FUZ_HOME to an absolute path, or unset it to use ~/.fuz\n"
                .to_string(),
            None,
            Some(Path::new("rel")),
        ),
        (
            unusable("the home directory (HOME) is empty"),
            Some(""),
            None,
        ),
        (
            unusable("the home directory (HOME) is not an absolute path: h"),
            Some("h"),
            None,
        ),
    ]
}

/// A cwd holding an installed `fuzd` at each place an unusable home would
/// resolve to under it — so a home resolved against the cwd reads as "fuzd:
/// stopped" rather than as unknown.
fn cwd_seeded_with_fuzd() -> tempfile::TempDir {
    let cwd = fresh_home();
    for home in ["rel", "h/.fuz", ".fuz"] {
        let bin = cwd.path().join(home).join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::write(bin.join("fuzd"), b"#!/bin/sh\n").unwrap();
    }
    cwd
}

/// `fuz self status` is a diagnostic: a fuz home it cannot resolve is a
/// warning — the home layer's error and its hint, on stderr — and exit 0. What
/// lives under the home is reported as unknown, not as absent: `fuzd: unknown`
/// with no install hint, and `"fuzd": null` under `--json`, whose stdout stays
/// one JSON document. Nothing is read or created under the cwd.
#[test]
fn self_status_warns_about_a_home_it_cannot_resolve_and_reports_fuzd_unknown() {
    let version = env!("CARGO_PKG_VERSION");
    for (warning, home, fuz_home) in refused_homes() {
        let cwd = cwd_seeded_with_fuzd();
        let before = tree(cwd.path());
        let home = home.unwrap_or_else(|| cwd.path().to_str().unwrap());
        let context = format!("HOME={home:?} FUZ_HOME={fuz_home:?}");

        let out = run_in(cwd.path(), home, fuz_home, &["self", "status"]);
        assert_eq!(out.status.code(), Some(0), "{context}");
        assert_eq!(String::from_utf8_lossy(&out.stderr), warning, "{context}");
        assert_eq!(
            String::from_utf8_lossy(&out.stdout),
            format!("fuz {version}\nfuzd: unknown\n"),
            "{context}"
        );

        let out = run_in(cwd.path(), home, fuz_home, &["self", "status", "--json"]);
        assert_eq!(out.status.code(), Some(0), "{context}");
        assert_eq!(String::from_utf8_lossy(&out.stderr), warning, "{context}");
        let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(
            json,
            serde_json::json!({ "version": version, "fuzd": null }),
            "{context}"
        );

        assert_eq!(tree(cwd.path()), before, "{context}: the cwd changed");
    }
}

/// `fuz self version` under a home it cannot resolve: the same warning, exit
/// 0, and this binary's own version line — no artifact is named.
#[test]
fn self_version_warns_about_a_home_it_cannot_resolve() {
    let version = env!("CARGO_PKG_VERSION");
    for (warning, home, fuz_home) in refused_homes() {
        let cwd = cwd_seeded_with_fuzd();
        let before = tree(cwd.path());
        let home = home.unwrap_or_else(|| cwd.path().to_str().unwrap());
        let context = format!("HOME={home:?} FUZ_HOME={fuz_home:?}");

        let out = run_in(cwd.path(), home, fuz_home, &["self", "version"]);
        assert_eq!(out.status.code(), Some(0), "{context}");
        assert_eq!(String::from_utf8_lossy(&out.stderr), warning, "{context}");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            stdout.starts_with(&format!("fuz {version} (")) && stdout.ends_with(")\n"),
            "{context}: {stdout}"
        );
        assert_eq!(stdout.lines().count(), 1, "{context}: {stdout}");
        assert!(!stdout.contains("artifact"), "{context}: {stdout}");

        assert_eq!(tree(cwd.path()), before, "{context}: the cwd changed");
    }
}

/// With a release log configured, a home that cannot be resolved is still
/// reported once: the cached head lives under the home, so it is not looked
/// for and adds no second line. A release log configuration the check cannot
/// run under keeps its own warning, after the home's.
#[test]
fn a_home_that_cannot_be_resolved_is_reported_once_beside_the_release_log() {
    let (home_warning, _, fuz_home) = &refused_homes()[0];
    let log = fresh_home();
    let configuration_warning = "warning: release log configuration error: invalid \
        FUZ_RELEASE_LOG_URL entry 1, counting non-empty entries (not a usable storage location)\n";
    for (origin, expected) in [
        (log.path().to_str().unwrap(), home_warning.clone()),
        (
            "not://an-origin",
            format!("{home_warning}{configuration_warning}"),
        ),
    ] {
        for args in [&["self", "status"][..], &["self", "version"]] {
            let cwd = cwd_seeded_with_fuzd();
            let before = tree(cwd.path());
            let mut cmd = Command::new(env!("CARGO_BIN_EXE_fuz"));
            cmd.args(args)
                .current_dir(cwd.path())
                .env("HOME", cwd.path())
                .env("FUZ_HOME", fuz_home.unwrap())
                .env("FUZ_RELEASE_LOG_URL", origin)
                .env_remove("FUZ_RELEASE_LOG")
                .env_remove("FUZ_FORGE_TOKEN")
                .env_remove("FUZ_FORGE_BASE_URL")
                .env_remove("FUZ_DEV_REPO");
            let out = cmd.output().expect("spawn fuz");
            let context = format!("FUZ_RELEASE_LOG_URL={origin:?} `fuz {args:?}`");
            assert_eq!(out.status.code(), Some(0), "{context}");
            assert_eq!(String::from_utf8_lossy(&out.stderr), expected, "{context}");
            assert_eq!(tree(cwd.path()), before, "{context}: the cwd changed");
        }
    }
}

/// Every path under `root`, relative to it, sorted.
fn tree(root: &Path) -> Vec<String> {
    fn walk(root: &Path, dir: &Path, found: &mut Vec<String>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            found.push(path.strip_prefix(root).unwrap().display().to_string());
            if path.is_dir() {
                walk(root, &path, found);
            }
        }
    }
    let mut found = Vec::new();
    walk(root, root, &mut found);
    found.sort();
    found
}

/// An empty `FUZ_HOME` reads as unset: bootstrap installs into `$HOME/.fuz`,
/// and nothing lands under the cwd (where the empty path would resolve).
#[test]
fn empty_fuz_home_falls_back_to_home() {
    let cwd = fresh_home();
    let home = fresh_home_rc_safe();
    let out = run_in(
        cwd.path(),
        home.path().to_str().unwrap(),
        Some(Path::new("")),
        &["self", "bootstrap", "--no-modify-path", "--quiet"],
    );
    assert!(
        out.status.success(),
        "bootstrap failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        home.path().join(".fuz/bin/fuz").exists(),
        "installed under $HOME/.fuz"
    );
    assert_eq!(
        std::fs::read_dir(cwd.path()).unwrap().count(),
        0,
        "nothing written under the cwd"
    );
}

/// A world-writable `FUZ_HOME` is refused as it stands: bootstrap exits 2
/// (the caller's `chmod` to fix) with the error naming the mode, and installs
/// nothing under it.
#[test]
fn a_world_writable_fuz_home_is_refused_with_exit_2() {
    use std::os::unix::fs::PermissionsExt;

    let cwd = fresh_home();
    let home = fresh_home();
    let fuz_home = fresh_home();
    std::fs::set_permissions(fuz_home.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
    let out = run_in(
        cwd.path(),
        home.path().to_str().unwrap(),
        Some(fuz_home.path()),
        &["self", "bootstrap", "--no-modify-path", "--quiet"],
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("is world-writable (mode 0777)"), "{stderr}");
    assert_eq!(
        tree(fuz_home.path()),
        Vec::<String>::new(),
        "nothing installed"
    );
}

/// The forge token file is read from under the home directory only: with an
/// empty or relative `HOME`, `forge://` storage is a configuration error,
/// even though a token sits where the cwd-relative path would find it.
#[test]
fn forge_token_is_not_read_through_an_unusable_home() {
    for (home, token_dir, reason) in [
        ("", ".fuz_forge", "the home directory (HOME) is empty"),
        (
            "h",
            "h/.fuz_forge",
            "the home directory (HOME) is not an absolute path: h",
        ),
    ] {
        let cwd = fresh_home();
        let fuz_home = fresh_home();
        let token_dir = cwd.path().join(token_dir);
        std::fs::create_dir_all(&token_dir).unwrap();
        std::fs::write(token_dir.join("api_token"), "cwd-token\n").unwrap();

        let out = run_in(
            cwd.path(),
            home,
            Some(fuz_home.path()),
            &[
                "tool",
                "upgrade",
                "fuzd",
                "--storage",
                "forge://fuz.invalid",
                "--check",
            ],
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(1), "HOME={home:?}: {stderr}");
        assert!(
            stderr.contains(&format!(
                "cannot resolve forge token: cannot resolve fuz_forge home \
                 (FUZ_FORGE_HOME is unset): {reason}"
            )),
            "HOME={home:?}: {stderr}"
        );
    }
}

/// Spawn `fuz tool upgrade fuzd --check` against a host-less `forge://` at
/// `base_url`, with `HOME`, `FUZ_HOME` and `FUZ_FORGE_HOME` as given and no
/// `FUZ_FORGE_TOKEN`, so the token comes from a token file.
fn forge_check_with_forge_home(home: &Path, forge_home: &Path, base_url: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_fuz"))
        .args([
            "tool",
            "upgrade",
            "fuzd",
            "--storage",
            "forge://",
            "--check",
        ])
        .current_dir(home)
        .env("HOME", home)
        .env("FUZ_HOME", home.join(".fuz"))
        .env("FUZ_FORGE_HOME", forge_home)
        .env("FUZ_FORGE_BASE_URL", base_url)
        .env_remove("FUZ_FORGE_TOKEN")
        .env_remove("FUZ_RELEASE_LOG_URL")
        .env_remove("FUZ_RELEASE_LOG")
        .env_remove("FUZ_DEV_REPO")
        .output()
        .expect("spawn fuz")
}

/// Accept one HTTP request on `listener`, answer it 404, and return its head;
/// `None` when no request arrives before the deadline.
fn accept_one_request_head(listener: &std::net::TcpListener) -> Option<String> {
    use std::io::{Read, Write};
    listener.set_nonblocking(true).unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    let mut stream = loop {
        match listener.accept() {
            Ok((stream, _)) => break stream,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if std::time::Instant::now() > deadline {
                    return None;
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Err(e) => panic!("accept: {e}"),
        }
    };
    stream.set_nonblocking(false).unwrap();
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .unwrap();
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") && head.len() < 16 * 1024 {
        if stream.read(&mut byte).unwrap() == 0 {
            break;
        }
        head.push(byte[0]);
    }
    let _ = stream
        .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    Some(String::from_utf8_lossy(&head).into_owned())
}

/// `FUZ_FORGE_HOME` names the directory the forge token file is read from,
/// as it does for `fuzf`: with a token there and a different one under
/// `~/.fuz_forge`, the bearer `fuz` sends is the `FUZ_FORGE_HOME` one.
#[test]
fn forge_home_steers_the_token_file() {
    let home = fresh_home();
    let forge_home = home.path().join("forge_home");
    std::fs::create_dir_all(&forge_home).unwrap();
    std::fs::write(forge_home.join("api_token"), "forge-home-token\n").unwrap();
    std::fs::create_dir_all(home.path().join(".fuz_forge")).unwrap();
    std::fs::write(home.path().join(".fuz_forge/api_token"), "home-token\n").unwrap();

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let server = std::thread::spawn(move || accept_one_request_head(&listener));
    let out = forge_check_with_forge_home(home.path(), &forge_home, &base_url);
    let head = server.join().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    let head = head.unwrap_or_else(|| panic!("no request reached the forge: {stderr}"));
    let bearer = head
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("authorization")
                .then(|| value.trim().to_string())
        })
        .unwrap_or_else(|| panic!("no authorization header: {head}"));
    assert_eq!(bearer, "Bearer forge-home-token", "{stderr}");
}

/// A missing token file under `FUZ_FORGE_HOME` is an error naming that file,
/// not a fall back to `~/.fuz_forge` — and nothing reaches the network.
#[test]
fn a_missing_token_under_forge_home_names_that_file() {
    let home = fresh_home();
    let forge_home = home.path().join("forge_home");
    std::fs::create_dir_all(&forge_home).unwrap();
    std::fs::create_dir_all(home.path().join(".fuz_forge")).unwrap();
    std::fs::write(home.path().join(".fuz_forge/api_token"), "home-token\n").unwrap();

    // the discard port: a regression that resolved some token sends it nowhere
    let out = forge_check_with_forge_home(home.path(), &forge_home, "http://127.0.0.1:9");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert!(
        stderr.contains(&format!(
            "error: no forge token: FUZ_FORGE_TOKEN is unset and {} cannot be read: ",
            forge_home.join("api_token").display()
        )),
        "{stderr}"
    );
    assert!(
        stderr.contains("; set FUZ_FORGE_TOKEN, or create a token"),
        "{stderr}"
    );
}

/// A token file holding two lines is refused naming the file, before any
/// request — not sent on as a header the HTTP client cannot build.
#[test]
fn a_malformed_token_file_is_refused_naming_it() {
    let home = fresh_home();
    let forge_home = home.path().join("forge_home");
    std::fs::create_dir_all(&forge_home).unwrap();
    std::fs::write(forge_home.join("api_token"), "first-line\nsecond-line\n").unwrap();

    let out = forge_check_with_forge_home(home.path(), &forge_home, "http://127.0.0.1:9");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert!(
        stderr.contains(&format!(
            "error: forge token from {} is malformed: it contains whitespace; ",
            forge_home.join("api_token").display()
        )),
        "{stderr}"
    );
    assert!(
        !stderr.contains("first-line"),
        "the token is not shown: {stderr}"
    );
}

/// A `FUZ_FORGE_TOKEN` that is not UTF-8 is refused naming the variable,
/// rather than read as unset and replaced by the token file.
#[test]
fn a_non_utf8_env_token_is_refused() {
    use std::os::unix::ffi::OsStrExt as _;
    let home = fresh_home();
    let forge_home = home.path().join("forge_home");
    std::fs::create_dir_all(&forge_home).unwrap();
    std::fs::write(forge_home.join("api_token"), "file-token\n").unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_fuz"))
        .args([
            "tool",
            "upgrade",
            "fuzd",
            "--storage",
            "forge://",
            "--check",
        ])
        .current_dir(home.path())
        .env("HOME", home.path())
        .env("FUZ_HOME", home.path().join(".fuz"))
        .env("FUZ_FORGE_HOME", &forge_home)
        .env("FUZ_FORGE_BASE_URL", "http://127.0.0.1:9")
        .env("FUZ_FORGE_TOKEN", std::ffi::OsStr::from_bytes(b"tok\xff"))
        .env_remove("FUZ_RELEASE_LOG_URL")
        .env_remove("FUZ_RELEASE_LOG")
        .env_remove("FUZ_DEV_REPO")
        .output()
        .expect("spawn fuz");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert!(
        stderr.contains(
            "error: forge token from FUZ_FORGE_TOKEN is malformed: it is not valid UTF-8"
        ),
        "{stderr}"
    );
}

/// A blank `FUZ_FORGE_BASE_URL` reads as unset, as a blank token does: a
/// host-less `forge://` then names the missing host rather than a malformed
/// URL.
#[test]
fn a_blank_forge_base_url_reads_as_unset() {
    let home = fresh_home();
    let out = Command::new(env!("CARGO_BIN_EXE_fuz"))
        .args([
            "tool",
            "upgrade",
            "fuzd",
            "--storage",
            "forge://",
            "--check",
        ])
        .current_dir(home.path())
        .env("HOME", home.path())
        .env("FUZ_HOME", home.path().join(".fuz"))
        .env("FUZ_FORGE_HOME", home.path().join("forge_home"))
        .env("FUZ_FORGE_BASE_URL", "  \n")
        .env("FUZ_FORGE_TOKEN", "token")
        .env_remove("FUZ_RELEASE_LOG_URL")
        .env_remove("FUZ_RELEASE_LOG")
        .env_remove("FUZ_DEV_REPO")
        .output()
        .expect("spawn fuz");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert!(
        stderr.contains(
            "forge:// requires a host (forge://<host>) or the FUZ_FORGE_BASE_URL env var"
        ),
        "{stderr}"
    );
}

/// `fuz artifact build` without `FUZ_DEV_REPO` looks under the home directory
/// only: an empty or relative `HOME` names no default repo (the reason is in
/// the searched list), rather than one under the cwd.
#[test]
fn build_default_repo_is_not_resolved_through_an_unusable_home() {
    for (home, repo_dir, reason) in [
        ("", "dev/fuz", "the home directory (HOME) is empty"),
        (
            "h",
            "h/dev/fuz",
            "the home directory (HOME) is not an absolute path: h",
        ),
    ] {
        let cwd = fresh_home();
        let fuz_home = fresh_home();
        // Present but invalid, so a cwd-relative lookup shows up as an
        // `invalid source repo` error and never reaches a build.
        std::fs::create_dir_all(cwd.path().join(repo_dir)).unwrap();

        let out = run_in(
            cwd.path(),
            home,
            Some(fuz_home.path()),
            &["artifact", "build", "--dry-run"],
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(1), "HOME={home:?}: {stderr}");
        assert!(
            stderr.contains("error: source repo not found"),
            "HOME={home:?}: {stderr}"
        );
        assert!(
            stderr.contains(&format!("~/dev/fuz ({reason})")),
            "HOME={home:?}: {stderr}"
        );
    }
}

/// A `~/…` storage path expands against the home directory only: with a
/// relative `HOME` it is refused, naming the reason — neither expanded to the
/// store under the cwd nor read as a literal `~` directory there. Only the
/// relative row runs here; the empty-`HOME` row is pinned in-process
/// (`fuz_storage`'s `expand_root` test).
#[test]
fn tilde_storage_is_refused_with_a_relative_home() {
    let cwd = fresh_home();
    let fuz_home = fresh_home();
    // What `~/store` would expand to under `HOME=h`, holding a pointer that
    // fails to parse.
    let reachable = cwd.path().join("h/store/tools/fuzd");
    std::fs::create_dir_all(&reachable).unwrap();
    std::fs::write(
        reachable.join(format!("latest-{}.json", fuz_release::current_target())),
        "not json",
    )
    .unwrap();

    let out = run_in(
        cwd.path(),
        "h",
        Some(fuz_home.path()),
        &["tool", "upgrade", "fuzd", "--storage", "~/store", "--check"],
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert!(
        stderr.contains(
            "cannot expand `~` in the local storage path: \
             the home directory (HOME) is not an absolute path: h"
        ),
        "{stderr}"
    );
    assert!(
        !cwd.path().join("~").exists(),
        "no literal `~` store created under the cwd"
    );
}

/// A `~/…` release log origin, a local directory that must already exist, is
/// refused with a relative `HOME` — not read from a literal `~` directory
/// under the cwd, which would otherwise be accepted as the witness. (The
/// read-only open is `FileStorage::open_existing`; the empty-`HOME` row is
/// pinned in-process, as for the storage path above.)
#[test]
fn tilde_release_log_origin_is_refused_with_a_relative_home() {
    let cwd = fresh_home();
    let fuz_home = fresh_home();
    let storage = fresh_home();
    // The literal directory a verbatim `~/log` would open.
    std::fs::create_dir_all(cwd.path().join("~/log")).unwrap();

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_fuz"));
    cmd.args(["tool", "install", "fuzd", "--storage"])
        .arg(storage.path())
        .current_dir(cwd.path())
        .env("HOME", "h")
        .env("FUZ_HOME", fuz_home.path())
        .env("FUZ_RELEASE_LOG_URL", "~/log")
        .env_remove("FUZ_RELEASE_LOG")
        .env_remove("FUZ_FORGE_TOKEN")
        .env_remove("FUZ_FORGE_BASE_URL");
    let out = cmd.output().expect("spawn fuz");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "{stderr}");
    assert!(
        stderr.contains("invalid FUZ_RELEASE_LOG_URL entry 1"),
        "{stderr}"
    );
}
