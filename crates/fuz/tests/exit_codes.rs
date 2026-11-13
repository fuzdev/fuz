//! End-to-end coverage of the agent-facing exit-code dialect and `report()`'s
//! error/hint rendering — the wiring the in-module `exit_code()`/`hint()` unit
//! tests can't observe: that `main`/`report` actually map an error to the
//! process exit code and print the `error:` / `hint:` lines. The `2`/`1`
//! distinction (caller-must-fix vs everything-else) is the contract here; the
//! local integrity `65` is pinned by `artifact_cli.rs`'s tamper test, and a
//! fetch-path security violation's `65` here.
#![expect(
    clippy::unwrap_used,
    reason = "test helpers outside `#[test]` fns panic on a failed setup or check"
)]

mod common;
use common::{fresh_home, run, run_with_env};

/// Predictable-mistake bare verbs print a "did you mean …" redirect and exit 2
/// (the caller must fix the invocation), never executing the guessed command.
#[test]
fn typo_redirect_exits_2_with_did_you_mean() {
    let home = fresh_home();
    for (args, mention) in [
        (&["status"][..], "fuz self status"),
        (&["install", "foo"], "fuz tool install"),
        (&["verify"], "fuz artifact verify"),
    ] {
        let out = run(home.path(), args);
        assert_eq!(out.status.code(), Some(2), "`fuz {args:?}` must exit 2");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("did you mean") && stderr.contains(mention),
            "`fuz {args:?}` -> {stderr:?} should redirect to {mention:?}"
        );
    }
}

/// A command line argh can't parse — an unknown flag, a missing argument or
/// subcommand — exits 2 with argh's message on stderr, not argh's own exit 1,
/// which a release log refusal also gives. Nothing reaches stdout.
#[test]
fn unparseable_command_line_exits_2_on_stderr() {
    let home = fresh_home();
    for (args, message) in [
        (
            &["self", "status", "--bogus"][..],
            "Unrecognized argument: --bogus",
        ),
        (
            &["tool", "install"],
            "Required positional arguments not provided",
        ),
        (&[], "One of the following subcommands must be present"),
    ] {
        let out = run(home.path(), args);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(2), "`fuz {args:?}`: {stderr}");
        assert!(stderr.contains(message), "`fuz {args:?}`: {stderr}");
        assert!(
            stderr.contains("Run fuz --help for more information."),
            "`fuz {args:?}` keeps argh's pointer: {stderr}"
        );
        assert!(
            out.stdout.is_empty(),
            "`fuz {args:?}` prints nothing to stdout"
        );
    }
}

/// An argument that is not UTF-8 is a usage error too (exit 2, argh's
/// `Invalid utf8` line), not a panic.
#[test]
fn non_utf8_argument_exits_2() {
    use std::os::unix::ffi::OsStrExt;
    let home = fresh_home();
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_fuz"))
        .args(["self".as_ref(), std::ffi::OsStr::from_bytes(b"\xff")])
        .env("FUZ_HOME", home.path())
        .env("HOME", home.path())
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("Invalid utf8"), "{stderr}");
}

/// A help request — `--help` or the `help` subcommand, at any level — prints
/// usage to stdout and exits 0.
#[test]
fn help_request_exits_0_on_stdout() {
    let home = fresh_home();
    for (args, usage) in [
        (&["--help"][..], "Usage: fuz <command>"),
        (&["help"], "Usage: fuz <command>"),
        (&["self", "status", "--help"], "Usage: fuz self status"),
        (&["help", "tool"], "Usage: fuz tool"),
    ] {
        let out = run(home.path(), args);
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert_eq!(out.status.code(), Some(0), "`fuz {args:?}`: {stdout}");
        assert!(stdout.starts_with(usage), "`fuz {args:?}`: {stdout}");
        assert!(
            out.stderr.is_empty(),
            "`fuz {args:?}` prints nothing to stderr"
        );
    }
}

/// An unknown observe domain exits 1 (not the caller-fix 2) and `report()`
/// renders both the `error:` line and the actionable `hint:` line.
#[test]
fn unknown_observe_domain_exits_1_with_hint() {
    let home = fresh_home();
    let out = run(home.path(), &["workload", "observe", "nonsense"]);
    assert_eq!(out.status.code(), Some(1), "an unknown domain exits 1");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("error: unknown observe domain 'nonsense'"),
        "report() prints the error line: {stderr:?}"
    );
    assert!(
        stderr.contains("hint: available domains:"),
        "report() prints the hint line: {stderr:?}"
    );
}

/// A daemon that answers the Hello and then ends the subscription without a
/// snapshot (shutting down, or failing mid-subscribe) is a failure, exit 1 like
/// any other daemon-client error, with the error and its hint — never exit 0
/// with nothing printed.
#[test]
fn observe_stream_ended_before_a_snapshot_exits_1() {
    use fuz_wire::{
        HEADER_BYTES, HelloOutcome, HelloResponse, PROTOCOL_VERSION, encode_payload, ids,
    };
    use std::io::{Read, Write};

    fn read_frame(stream: &mut std::os::unix::net::UnixStream) -> u32 {
        let mut len = [0u8; 4];
        stream.read_exact(&mut len).unwrap();
        let mut rest = vec![0u8; u32::from_be_bytes(len) as usize];
        stream.read_exact(&mut rest).unwrap();
        u32::from_be_bytes(rest[..4].try_into().unwrap())
    }

    let home = fresh_home();
    let run_dir = home.path().join("run");
    std::fs::create_dir(&run_dir).unwrap();
    let listener = std::os::unix::net::UnixListener::bind(run_dir.join("socket")).unwrap();
    let daemon = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let request_id = read_frame(&mut stream);
        let body = encode_payload(&HelloResponse {
            server_protocol_version: PROTOCOL_VERSION,
            server_version: "test".to_string(),
            outcome: HelloOutcome::Ok,
        })
        .unwrap();
        let mut frame = Vec::new();
        frame.extend_from_slice(&(HEADER_BYTES + u32::try_from(body.len()).unwrap()).to_be_bytes());
        frame.extend_from_slice(&request_id.to_be_bytes());
        frame.extend_from_slice(&ids::HELLO_RESPONSE.0.to_be_bytes());
        frame.push(fuz_wire::FrameFlags::FINAL.bits());
        frame.extend_from_slice(&body);
        stream.write_all(&frame).unwrap();
        // Read the subscribe request, then close without a snapshot.
        read_frame(&mut stream);
    });

    let out = run(home.path(), &["workload", "observe", "process"]);
    daemon.join().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert!(
        stderr.contains("error: the daemon ended the subscription before sending a snapshot"),
        "{stderr:?}"
    );
    assert!(stderr.contains("hint: see `fuzd logs`"), "{stderr:?}");
    assert!(out.stdout.is_empty(), "nothing was shown");
}

/// There is no S3-compatible backend: `self upgrade` against an `object://` URI
/// fails with a clear unknown-scheme message and a nonzero exit (1 — an
/// operational storage error, not a distinct config dialect).
#[test]
fn self_upgrade_object_scheme_unknown_exits_nonzero() {
    let home = fresh_home();
    let out = run(
        home.path(),
        &["self", "upgrade", "--storage", "object://bucket"],
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(1),
        "unknown object:// scheme must exit 1: {stderr}"
    );
    assert!(
        stderr.contains("unknown storage scheme"),
        "should name the unknown scheme: {stderr}"
    );
}

/// `FUZ_RELEASE_LOG` is a closed set: anything but `off` is refused before any
/// request to storage, whether or not a witness is configured — a typo is never
/// read as "on" or as "off". Exit 2: the caller must change it.
#[test]
fn release_log_switch_outside_its_set_is_a_configuration_error() {
    let home = fresh_home();
    let storage = tempfile::tempdir().unwrap();
    let storage = storage.path().to_str().unwrap();
    for (args, envs) in [
        (
            &["self", "upgrade", "--storage", storage][..],
            &[("FUZ_RELEASE_LOG", "OFF")][..],
        ),
        (
            &["tool", "install", "fuzd", "--storage", storage],
            &[
                ("FUZ_RELEASE_LOG", "false"),
                ("FUZ_RELEASE_LOG_URL", "https://log.invalid"),
            ],
        ),
    ] {
        let out = run_with_env(home.path(), args, envs);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(2), "{args:?}: {stderr}");
        assert!(
            stderr.contains("invalid FUZ_RELEASE_LOG value"),
            "{args:?}: {stderr}"
        );
        assert!(stderr.contains("hint: "), "{args:?}: {stderr}");
    }
}

/// An entry of `FUZ_RELEASE_LOG_URL` that is not an origin is refused by
/// position, before any request to storage, with exit 2 — and nothing of the
/// entry reaches the output, since a URL can carry a credential.
#[test]
fn release_log_url_that_is_not_an_origin_is_a_configuration_error() {
    let home = fresh_home();
    let storage = tempfile::tempdir().unwrap();
    let storage = storage.path().to_str().unwrap();
    let missing = home.path().join("hunter2-not-a-directory");
    for (entries, position) in [
        ("https://log.invalid, nope://hunter2", 2),
        ("https://h/a?token=hunter2", 1),
        ("HTTPS://u:hunter2@h", 1),
        ("https://u:hunter2@[bad", 1),
        ("forge://hunter2.example.com", 1),
        ("ssh://hunter2@h/log", 1),
        (missing.to_str().unwrap(), 1),
    ] {
        let out = run_with_env(
            home.path(),
            &["tool", "install", "fuzd", "--storage", storage],
            &[("FUZ_RELEASE_LOG_URL", entries)],
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(2), "{entries}: {stderr}");
        assert!(
            stderr.contains(&format!("invalid FUZ_RELEASE_LOG_URL entry {position}")),
            "{entries}: {stderr}"
        );
        assert!(!stderr.contains("hunter2"), "{entries}: leaked: {stderr}");
        assert!(out.stdout.is_empty(), "{entries}");
    }
    // Naming a missing local directory did not create it.
    assert!(!missing.exists());
}

/// A value that is not UTF-8 is refused like any other unusable configuration:
/// never read as unset, which would mean "no check".
#[test]
fn release_log_variable_that_is_not_utf8_is_a_configuration_error() {
    use std::os::unix::ffi::OsStrExt;
    use std::process::Command;

    let home = fresh_home();
    let storage = tempfile::tempdir().unwrap();
    for variable in ["FUZ_RELEASE_LOG_URL", "FUZ_RELEASE_LOG"] {
        let out = Command::new(env!("CARGO_BIN_EXE_fuz"))
            .args(["self", "upgrade", "--storage"])
            .arg(storage.path())
            .env("FUZ_HOME", home.path())
            .env("HOME", home.path())
            .env_remove("FUZ_RELEASE_LOG_URL")
            .env_remove("FUZ_RELEASE_LOG")
            .env(variable, std::ffi::OsStr::from_bytes(b"\xff\xfe"))
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(2), "{variable}: {stderr}");
        assert!(stderr.contains("not valid UTF-8"), "{variable}: {stderr}");
    }
}

/// The opt-out is visible: with a witness configured, `FUZ_RELEASE_LOG=off`
/// warns on stderr exactly once — under `--quiet` too — and the command goes
/// on to its ordinary outcome (here, an empty store has nothing to install).
/// Without a witness the same switch changes nothing and prints nothing.
#[test]
fn release_log_opt_out_warns_once_and_only_when_a_witness_is_configured() {
    const WARNING: &str = "warning: the release log check is disabled by FUZ_RELEASE_LOG=off";
    let home = fresh_home();
    let storage = tempfile::tempdir().unwrap();
    let storage = storage.path().to_str().unwrap();

    for args in [
        &["self", "upgrade", "--storage", storage][..],
        &["self", "upgrade", "--storage", storage, "--quiet"],
        &["tool", "install", "fuzd", "--storage", storage],
    ] {
        let out = run_with_env(
            home.path(),
            args,
            &[
                ("FUZ_RELEASE_LOG", "off"),
                ("FUZ_RELEASE_LOG_URL", "https://log.invalid"),
            ],
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(stderr.matches(WARNING).count(), 1, "{args:?}: {stderr}");
        // Past the policy, the command fails as it would with no log at all.
        assert_eq!(out.status.code(), Some(1), "{args:?}: {stderr}");
        assert!(stderr.contains("is published for"), "{args:?}: {stderr}");
        assert!(out.stdout.is_empty(), "{args:?}: stdout stays clean");

        let out = run_with_env(home.path(), args, &[("FUZ_RELEASE_LOG", "off")]);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(!stderr.contains("release log"), "{args:?}: {stderr}");
    }
}

/// With no witness configured nothing about the release log is read, printed,
/// or cached: the command's output and the home are what they are without it.
#[test]
fn release_log_is_silent_and_writes_nothing_when_unconfigured() {
    let home = fresh_home();
    let storage = tempfile::tempdir().unwrap();
    let out = run(
        home.path(),
        &[
            "self",
            "upgrade",
            "--storage",
            storage.path().to_str().unwrap(),
        ],
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert!(!stderr.contains("release log"), "{stderr}");
    assert!(!home.path().join("state").join("release_log").exists());
}

/// The read-only `--check` flows read the release log policy like the installs
/// do: a configuration the check cannot run under exits 2 before any request
/// to storage, with nothing on stdout — `--json` included — and nothing
/// written.
#[test]
fn release_log_configuration_errors_stop_the_check_flows() {
    let home = fresh_home();
    let storage = tempfile::tempdir().unwrap();
    let storage = storage.path().to_str().unwrap();
    for args in [
        &["self", "upgrade", "--storage", storage, "--check"][..],
        &["self", "upgrade", "--storage", storage, "--check", "--json"],
        &["tool", "upgrade", "fuzd", "--storage", storage, "--check"],
        &[
            "tool",
            "upgrade",
            "fuzd",
            "--storage",
            storage,
            "--check",
            "--json",
        ],
        &["tool", "upgrade", "fuzd", "--storage", storage],
    ] {
        for envs in [
            &[("FUZ_RELEASE_LOG", "OFF")][..],
            &[("FUZ_RELEASE_LOG_URL", "nope://hunter2")],
        ] {
            let out = run_with_env(home.path(), args, envs);
            let stderr = String::from_utf8_lossy(&out.stderr);
            assert_eq!(out.status.code(), Some(2), "{args:?} {envs:?}: {stderr}");
            assert!(
                stderr.contains("error: release log configuration error: "),
                "{args:?}: {stderr}"
            );
            assert!(!stderr.contains("hunter2"), "{args:?}: leaked: {stderr}");
            assert!(
                out.stdout.is_empty(),
                "{args:?} {envs:?}: stdout stays empty"
            );
        }
    }
    assert_eq!(std::fs::read_dir(home.path()).unwrap().count(), 0);
}

/// Under `--check`, the opt-out warns once and a configured-but-unneeded
/// witness changes nothing: the command reaches its ordinary outcome (an empty
/// store has no latest release), stdout carries no partial report, and the
/// read-only flow leaves the home empty.
#[test]
fn release_log_opt_out_and_inactive_leave_the_check_flows_as_they_are() {
    const WARNING: &str = "warning: the release log check is disabled by FUZ_RELEASE_LOG=off";
    let home = fresh_home();
    let storage = tempfile::tempdir().unwrap();
    let storage = storage.path().to_str().unwrap();
    let witness = tempfile::tempdir().unwrap();
    let witness = witness.path().to_str().unwrap();
    for args in [
        &["self", "upgrade", "--storage", storage, "--check"][..],
        &["self", "upgrade", "--storage", storage, "--check", "--json"],
        &[
            "self",
            "upgrade",
            "--storage",
            storage,
            "--check",
            "--quiet",
        ],
        &["tool", "upgrade", "fuzd", "--storage", storage, "--check"],
    ] {
        let plain = run(home.path(), args);
        assert_eq!(plain.status.code(), Some(1), "{args:?}");
        assert!(!String::from_utf8_lossy(&plain.stderr).contains("release log"));

        let off = run_with_env(
            home.path(),
            args,
            &[("FUZ_RELEASE_LOG", "off"), ("FUZ_RELEASE_LOG_URL", witness)],
        );
        let stderr = String::from_utf8_lossy(&off.stderr);
        assert_eq!(off.status.code(), Some(1), "{args:?}: {stderr}");
        assert_eq!(stderr.matches(WARNING).count(), 1, "{args:?}: {stderr}");
        assert!(off.stdout.is_empty(), "{args:?}");

        // Enforced: the manifest is fetched and verified first, and there is
        // none, so the outcome is the store's.
        let enforced = run_with_env(home.path(), args, &[("FUZ_RELEASE_LOG_URL", witness)]);
        assert_eq!(enforced.status.code(), Some(1), "{args:?}");
        assert_eq!(enforced.stderr, plain.stderr, "{args:?}");
        assert!(enforced.stdout.is_empty(), "{args:?}");
    }
    assert_eq!(std::fs::read_dir(home.path()).unwrap().count(), 0);
}

/// `fuz self bootstrap` under an enforced release log: every way the check can
/// fail to confirm the binary has its own exit code, and none of them is 0.
#[test]
fn self_bootstrap_release_log_outcomes_map_to_exit_codes() {
    let witness = tempfile::tempdir().unwrap();
    let no_head = witness.path().join("no-head");
    let bad_head = witness.path().join("bad-head");
    std::fs::create_dir(&no_head).unwrap();
    std::fs::create_dir(&bad_head).unwrap();
    std::fs::write(bad_head.join("head.json"), b"not a head").unwrap();

    for (envs, code) in [
        // Cannot be confirmed yet: retry later.
        (
            &[("FUZ_RELEASE_LOG_URL", no_head.to_str().unwrap())][..],
            75,
        ),
        // A refusal.
        (&[("FUZ_RELEASE_LOG_URL", bad_head.to_str().unwrap())], 1),
        // The caller must change the configuration.
        (&[("FUZ_RELEASE_LOG", "on")], 2),
    ] {
        let home = fresh_home();
        let out = run_with_env(
            home.path(),
            &["self", "bootstrap", "--no-modify-path"],
            envs,
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(code), "{envs:?}: {stderr}");
        assert!(stderr.contains("error: "), "{envs:?}: {stderr}");
        assert!(stderr.contains("hint: "), "{envs:?}: {stderr}");
        assert!(out.stdout.is_empty(), "{envs:?}");
        assert!(
            std::fs::symlink_metadata(home.path().join("bin").join("fuz")).is_err(),
            "{envs:?}: nothing installed"
        );
    }
}

/// The release log policy is read before `--storage` is parsed, on every
/// command that holds a release to the log: an invocation with both an
/// unusable configuration and an unusable storage location exits 2, the same
/// code everywhere, and names the configuration.
#[test]
fn release_log_configuration_is_read_before_storage_on_every_command() {
    const BAD_STORAGE: &str = "object://bucket";
    let home = fresh_home();
    for args in [
        &["self", "upgrade", "--storage", BAD_STORAGE][..],
        &["self", "upgrade", "--storage", BAD_STORAGE, "--check"],
        &["tool", "install", "fuzd", "--storage", BAD_STORAGE],
        &["tool", "upgrade", "fuzd", "--storage", BAD_STORAGE],
        &[
            "tool",
            "upgrade",
            "fuzd",
            "--storage",
            BAD_STORAGE,
            "--check",
        ],
    ] {
        let out = run_with_env(home.path(), args, &[("FUZ_RELEASE_LOG", "OFF")]);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(2), "{args:?}: {stderr}");
        assert!(
            stderr.contains("invalid FUZ_RELEASE_LOG value"),
            "{args:?}: {stderr}"
        );
        assert!(
            !stderr.contains("unknown storage scheme"),
            "{args:?}: {stderr}"
        );
        // Control: with a usable configuration the storage error is what is left.
        let out = run(home.path(), args);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(1), "{args:?}: {stderr}");
        assert!(
            stderr.contains("unknown storage scheme"),
            "{args:?}: {stderr}"
        );
    }
}

/// Every command that takes `--storage`, in the form each reads storage with.
/// `fuz` only reads a store, so none of them may create one.
fn storage_commands(storage: &str) -> [Vec<&str>; 6] {
    [
        vec!["tool", "install", "fuzd", "--storage", storage],
        vec!["tool", "upgrade", "fuzd", "--storage", storage],
        vec!["tool", "upgrade", "fuzd", "--storage", storage, "--check"],
        vec!["self", "upgrade", "--storage", storage],
        vec!["self", "upgrade", "--storage", storage, "--check"],
        vec!["self", "upgrade", "--storage", storage, "--check", "--json"],
    ]
}

/// Assert `out` is the refusal of a local `--storage` that is not an existing
/// directory: exit 1 (the storage class), the location as given, the hint,
/// and nothing on stdout — a `--check --json` report included.
fn assert_storage_not_a_directory(out: &std::process::Output, location: &str, context: &str) {
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{context}: {stderr}");
    assert!(
        stderr.contains(&format!(
            "error: --storage is not an existing directory: {location}\n"
        )),
        "{context}: {stderr}"
    );
    assert!(
        stderr.contains("hint: Check the path: fuz only reads a store and never creates one"),
        "{context}: {stderr}"
    );
    assert!(out.stdout.is_empty(), "{context}: nothing reported");
}

/// A local `--storage` that does not exist is refused by install, upgrade, and
/// `--check` alike, and naming it creates nothing — neither the directory nor
/// a parent of it. As a path and as a `file://` URI.
#[test]
fn missing_local_storage_is_refused_and_never_created() {
    let home = fresh_home();
    // Installed, so `tool upgrade` has something to upgrade.
    common::seed_tool(home.path(), "fuzd", "0.1.0", "fuzd", 0x51);
    let scratch = tempfile::tempdir().unwrap();
    let parent = scratch.path().join("no-such");
    let missing = parent.join("store");
    let path = missing.to_str().unwrap();
    let uri = format!("file://{path}");

    for location in [path, uri.as_str()] {
        for args in storage_commands(location) {
            let out = run(home.path(), &args);
            assert_storage_not_a_directory(&out, location, &format!("{args:?}"));
            assert!(!parent.exists(), "{args:?}: created {}", parent.display());
        }
    }
    assert!(
        std::fs::read_dir(scratch.path()).unwrap().next().is_none(),
        "nothing was created beside it either"
    );
}

/// The same refusal for the two forms that resolve against the environment: a
/// `~/…` path (the home directory) and a relative one (the working directory).
#[test]
fn missing_home_and_cwd_relative_storage_is_never_created() {
    let home = fresh_home();
    common::seed_tool(home.path(), "fuzd", "0.1.0", "fuzd", 0x51);
    let cwd = tempfile::tempdir().unwrap();

    for (location, base) in [
        ("~/no-such/store", home.path()),
        ("no-such/store", cwd.path()),
        ("./no-such/store", cwd.path()),
    ] {
        for args in storage_commands(location) {
            let out = std::process::Command::new(env!("CARGO_BIN_EXE_fuz"))
                .args(&args)
                .current_dir(cwd.path())
                .env("FUZ_HOME", home.path())
                .env("HOME", home.path())
                .env_remove("FUZ_RELEASE_LOG_URL")
                .env_remove("FUZ_RELEASE_LOG")
                .output()
                .expect("spawn fuz");
            assert_storage_not_a_directory(&out, location, &format!("{args:?}"));
            assert!(
                !base.join("no-such").exists(),
                "{args:?}: created under {}",
                base.display()
            );
        }
    }
    assert!(
        std::fs::read_dir(cwd.path()).unwrap().next().is_none(),
        "nothing was created in the working directory"
    );
}

/// A file where the store should be is refused the same way, and left as it
/// was: a store is a directory.
#[test]
fn storage_that_is_a_file_is_refused_and_left_intact() {
    let home = fresh_home();
    common::seed_tool(home.path(), "fuzd", "0.1.0", "fuzd", 0x51);
    let scratch = tempfile::tempdir().unwrap();
    let file = scratch.path().join("store");
    std::fs::write(&file, b"not a store").unwrap();
    let location = file.to_str().unwrap();

    for args in storage_commands(location) {
        let out = run(home.path(), &args);
        assert_storage_not_a_directory(&out, location, &format!("{args:?}"));
    }
    assert_eq!(std::fs::read(&file).unwrap(), b"not a store");
}

/// Seed an artifact, make it `current`, then replace its directory with a
/// symlink to a copy — the shape `fuz self upgrade` must read as unreadable.
fn seed_current_behind_a_symlink(home: &std::path::Path) {
    let meta = common::seed_artifact(home, 0x91, "2026-01-01T00:00:00Z");
    std::os::unix::fs::symlink(
        std::path::Path::new("artifacts").join(&meta.hash),
        home.join("current"),
    )
    .unwrap();
    let slot = home.join("artifacts").join(&meta.hash);
    let decoy = home.join("decoy");
    std::fs::rename(&slot, &decoy).unwrap();
    std::os::unix::fs::symlink(&decoy, &slot).unwrap();
}

/// `fuz self upgrade` applies the unreadable-current policy before any
/// request: without `--force` it refuses with the `--force` hint and never
/// reaches storage; with `--force` it goes on to the fetch (here an empty
/// store, so no release is published for this target) — the reinstall that repairs the state.
#[test]
fn self_upgrade_refuses_an_unreadable_current_unless_forced() {
    let home = fresh_home();
    seed_current_behind_a_symlink(home.path());
    let storage = tempfile::tempdir().unwrap();
    let storage = storage.path().to_str().unwrap();

    let out = run(home.path(), &["self", "upgrade", "--storage", storage]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert!(
        stderr.contains("current install is unreadable") && stderr.contains("--force"),
        "{stderr}"
    );
    assert!(!stderr.contains("is published for"), "no request: {stderr}");

    let out = run(
        home.path(),
        &["self", "upgrade", "--storage", storage, "--force"],
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert!(
        stderr.contains("is published for"),
        "--force reaches the fetch: {stderr}"
    );
}

/// A `current` that is a real directory can't be replaced by the switch, and
/// fuz did not write it, so `fuz self upgrade` refuses it even under `--force`
/// — before any request — and leaves it in place.
#[test]
fn self_upgrade_refuses_a_current_directory_even_when_forced() {
    let home = fresh_home();
    std::fs::create_dir(home.path().join("current")).unwrap();
    let storage = tempfile::tempdir().unwrap();
    let storage = storage.path().to_str().unwrap();

    for args in [
        &["self", "upgrade", "--storage", storage][..],
        &["self", "upgrade", "--storage", storage, "--force"],
    ] {
        let out = run(home.path(), args);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(65), "{args:?}: {stderr}");
        assert!(stderr.contains("not a symlink"), "{args:?}: {stderr}");
        assert!(!stderr.contains("is published for"), "{args:?}: {stderr}");
    }
    assert!(home.path().join("current").is_dir(), "left in place");
}

/// A manifest whose signature isn't by a trusted key is a security violation:
/// `EX_DATAERR` (65) on the check and the install alike, never the `1` a
/// retryable storage failure gets — a script must not retry its way past it.
#[test]
fn untrusted_manifest_signature_exits_65() {
    let target = fuz_release::current_target();
    let home = fresh_home();
    let store = tempfile::tempdir().unwrap();
    let hex = "a".repeat(64);
    let manifest = serde_json::json!({
        "format": 1,
        "version": "9.9.9",
        "content_hash": format!("v1-{hex}"),
        "target": target,
        "minimum_version": null,
        "tarball": {
            "path": format!("fuz-9.9.9-{target}.tar.gz"),
            "blake3": hex,
            "size": 1024,
        },
        "binaries": { "fuz": hex },
        "signature": {
            "format": 2,
            "public_key": "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik=", // the zero-seed test key, untrusted
            "algorithm": "ed25519",
            "signed_at": "2026-01-01T00:00:00Z",
            "sig": "CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQ==",
        },
    });
    std::fs::write(
        store
            .path()
            .join(format!("latest-{}.json", fuz_release::current_target())),
        br#"{"version": "9.9.9"}"#,
    )
    .unwrap();
    std::fs::write(
        store
            .path()
            .join(format!("fuz-9.9.9-{target}.manifest.json")),
        serde_json::to_vec(&manifest).unwrap(),
    )
    .unwrap();
    let storage = store.path().to_str().unwrap();

    for args in [
        &["self", "upgrade", "--storage", storage, "--check"][..],
        &["self", "upgrade", "--storage", storage],
    ] {
        let out = run(home.path(), args);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(65), "{args:?}: {stderr}");
        assert!(stderr.starts_with("error: "), "{args:?}: {stderr}");
        assert!(stderr.contains("untrusted"), "{args:?}: {stderr}");
    }
}
