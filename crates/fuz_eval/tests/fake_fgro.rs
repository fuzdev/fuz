//! The client against `testing_fake_fgro`, a stand-in for `fgro eval` that
//! writes canned envelopes: the reader's verdict on each kind of output, the
//! spawn's environment, descriptors, arguments, and working directory, and the
//! process-group kill. The driver's first line names the fake's mode (its
//! environment is cleared, so the driver is the one channel to it).
//!
//! The refusals that come before any spawn — the trust root, the pin, a
//! non-UTF-8 config path — run here too, against a binary that is never
//! reached.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use fuz_eval::{
    DumpFormat, DumpOrigin, EvalError, EvalErrorKind, EvalOutput, EvalRequest, FgroPin,
    MAX_STDOUT_SIZE, ProtocolViolation, TIMEOUT_GRACE, TrustRootProblem, WalkStop, eval_module,
    fgro_blake3,
};

use common::{Scratch, project, write};

/// The fake binary, built by Cargo for this suite.
fn fake() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_testing_fake_fgro"))
}

/// The fake's pin, hashed once.
fn fake_pin() -> &'static str {
    static PIN: OnceLock<String> = OnceLock::new();
    PIN.get_or_init(|| fgro_blake3(fake(), None).unwrap())
}

async fn eval_with(
    config: &Path,
    driver: &str,
    timeout: Duration,
) -> Result<EvalOutput, EvalError> {
    eval_module(&EvalRequest {
        config_path: config,
        driver_js: driver,
        timeout,
        fgro: FgroPin {
            path: fake(),
            expected_blake3: fake_pin(),
            cache_dir: None,
        },
    })
    .await
}

async fn eval(config: &Path, driver: &str) -> Result<EvalOutput, EvalError> {
    eval_with(config, driver, Duration::from_secs(10)).await
}

/// The violation an eval was refused with.
async fn violation(config: &Path, driver: &str) -> ProtocolViolation {
    match eval(config, driver).await {
        Err(EvalError::Protocol { violation, .. }) => *violation,
        other => panic!("{driver}: expected a protocol violation, got {other:?}"),
    }
}

#[tokio::test]
async fn an_ok_envelope_is_the_value_with_sorted_keys_and_the_typed_graph() {
    let (scratch, config) = project("fake_ok", "export default 1;\n");
    let output = eval(&config, "ok").await.unwrap();
    assert_eq!(
        output.value_json,
        r#"{"alpha":"x","zeta":[1,{"a":null,"b":true}]}"#
    );
    assert_eq!(output.config_path, config);
    let graph = output.graph;
    assert_eq!(graph.local.project, scratch.path().to_str().unwrap());
    assert_eq!(graph.roots, ["project:config.ts"]);
    assert_eq!(graph.modules[0].origin, DumpOrigin::Project);
    assert_eq!(graph.modules[0].format, Some(DumpFormat::Typescript));
    assert_eq!(
        graph.local.paths["project:config.ts"],
        config.to_str().unwrap()
    );
}

#[tokio::test]
async fn every_failure_kind_is_an_eval_error_carrying_what_fgro_said() {
    let (_scratch, config) = project("fake_kinds", "export default 1;\n");
    for (kind, name) in [
        (EvalErrorKind::Resolve, "resolve"),
        (EvalErrorKind::Link, "link"),
        (EvalErrorKind::ModuleThrew, "module_threw"),
        (EvalErrorKind::ExportMissing, "export_missing"),
        (EvalErrorKind::Serialize, "serialize"),
        (EvalErrorKind::LateRejection, "late_rejection"),
        (EvalErrorKind::Heap, "heap"),
        (EvalErrorKind::Memory, "memory"),
        (EvalErrorKind::Timeout, "timeout"),
        (EvalErrorKind::Environment, "environment"),
        (EvalErrorKind::Internal, "internal"),
    ] {
        for code in [1, 2] {
            let error = eval(&config, &format!("fail {name} {code}"))
                .await
                .unwrap_err();
            let EvalError::Eval { path, failure, .. } = &error else {
                panic!("{name}: expected an eval failure, got {error:?}");
            };
            assert_eq!(path, config.to_str().unwrap());
            assert_eq!(failure.kind, kind);
            assert_eq!(
                failure.message,
                format!("fake {name} failure\n    at file:///fake.ts:1:1")
            );
            assert_eq!(failure.at.as_deref(), Some("$.a"));
            assert_eq!(failure.specifier.as_deref(), Some("./missing.ts"));
            assert_eq!(failure.importer.as_deref(), Some("file:///fake.ts"));
            assert_eq!(failure.hint.as_deref(), Some("a fake hint"));
            let message = error.to_string();
            assert!(message.contains(&format!("({name})")), "{message}");
            assert!(message.contains("\nhint: a fake hint"), "{message}");
        }
    }
    // a failure before the graph was reached carries none
    let error = eval(&config, "fail-null-graph").await.unwrap_err();
    assert!(
        matches!(&error, EvalError::Eval { failure, .. } if failure.kind == EvalErrorKind::Resolve),
        "{error:?}"
    );
}

#[tokio::test]
async fn the_exit_code_must_agree_with_ok() {
    let (_scratch, config) = project("fake_exit", "export default 1;\n");
    assert_eq!(
        violation(&config, "fail-exit-0").await,
        ProtocolViolation::ExitMismatch { code: 0, ok: false }
    );
    for code in [1, 2] {
        assert_eq!(
            violation(&config, &format!("exit {code}")).await,
            ProtocolViolation::ExitMismatch { code, ok: true }
        );
    }
}

#[tokio::test]
async fn another_exit_code_or_a_signal_is_a_crash_whatever_stdout_holds() {
    let (_scratch, config) = project("fake_crash", "export default 1;\n");
    for (driver, status) in [
        ("exit 3", "exit status: 3"),
        ("exit 101", "exit status: 101"),
        ("abort", "SIGABRT"),
    ] {
        let error = eval(&config, driver).await.unwrap_err();
        assert!(
            matches!(&error, EvalError::FgroCrashed { status: found, .. } if found.contains(status)),
            "{driver}: {error:?}"
        );
    }
}

#[tokio::test]
async fn an_envelope_the_reader_does_not_know_is_refused() {
    let (_scratch, config) = project("fake_protocol", "export default 1;\n");
    for pointer in ["", "/runtime", "/entry", "/graph", "/graph/local"] {
        assert!(
            matches!(
                violation(&config, &format!("unknown-field {pointer}")).await,
                ProtocolViolation::Shape { reason } if reason.contains("unknown_field")
            ),
            "{pointer}"
        );
    }
    assert!(matches!(
        violation(&config, "wrong-id").await,
        ProtocolViolation::EntryId { found } if found == format!("{}.other", config.display())
    ));
    assert!(matches!(
        violation(&config, "wrong-driver").await,
        ProtocolViolation::DriverBlake3 { found: Some(_), .. }
    ));
    assert_eq!(
        violation(&config, "graph-version").await,
        ProtocolViolation::GraphVersion { found: Some(2) }
    );
    assert_eq!(
        violation(&config, "null-graph").await,
        ProtocolViolation::GraphNullOnSuccess
    );
    assert_eq!(
        violation(&config, "two-objects").await,
        ProtocolViolation::NotOneObject
    );
    assert_eq!(
        violation(&config, "silent").await,
        ProtocolViolation::NoEnvelope
    );
    assert!(matches!(
        eval(&config, "not-utf8").await,
        Err(EvalError::NotUtf8 { .. })
    ));
}

/// The envelope's project must be the trust root this crate settled (the D4c
/// cross-check), named in the refusal.
#[tokio::test]
async fn a_project_other_than_the_trust_root_is_refused() {
    let (scratch, config) = project("fake_project", "export default 1;\n");
    let elsewhere = scratch.path().join("elsewhere");
    let error = eval(&config, &format!("project {}", elsewhere.display()))
        .await
        .unwrap_err();
    let EvalError::Protocol { violation, .. } = &error else {
        panic!("expected a protocol violation, got {error:?}");
    };
    assert!(
        matches!(
            violation.as_ref(),
            ProtocolViolation::ProjectMismatch { trust_root, project, .. }
                if trust_root == scratch.path() && Path::new(project) == elsewhere
        ),
        "{violation:?}"
    );
    assert!(error.to_string().contains("not the trust root"), "{error}");
}

/// The child gets the arguments the protocol names, `fgro` as `argv[0]`, the
/// trust root as its working directory, `TZ=UTC` as its whole environment, and
/// no descriptor but stdin, stdout, and stderr — this suite's own environment
/// (`PATH`, `HOME`, Cargo's variables) included in what is withheld.
#[tokio::test]
async fn the_child_gets_its_arguments_the_trust_root_tz_alone_and_stdio_alone() {
    let (scratch, _) = project("fake_report", "export default 1;\n");
    // a type marker between the config and the project, so the trust root is
    // not the config's directory
    let config = scratch.path().join("deploy/config.ts");
    write(&config, "export default 1;\n");
    write(
        &scratch.path().join("deploy/package.json"),
        r#"{"type":"module"}"#,
    );
    assert!(
        std::env::var_os("PATH").is_some(),
        "the suite has a PATH to withhold"
    );

    // a descriptor this process holds open across the spawn
    let held = std::fs::File::open(&config).unwrap();
    let output = eval_with(&config, "report", Duration::from_millis(1500))
        .await
        .unwrap();
    drop(held);
    let report: serde_json::Value = serde_json::from_str(&output.value_json).unwrap();
    assert_eq!(
        report["argv"],
        serde_json::json!([
            "fgro",
            "eval",
            config.to_str().unwrap(),
            "--driver",
            "-",
            "--graph",
            "--timeout",
            "1500"
        ])
    );
    assert_eq!(report["cwd"], scratch.path().to_str().unwrap());
    assert_eq!(report["env"], serde_json::json!({"TZ": "UTC"}));
    assert_eq!(report["fds"], serde_json::json!([0, 1, 2]));
    // not root, so no drop: the child is this process's uid (the drop's own
    // suite is `uid_drop`, run as root)
    let euid = common::effective_uid();
    if euid != 0 {
        assert_eq!(
            report["ids"]["uid"],
            serde_json::json!([euid, euid, euid, euid])
        );
    }

    // a zero timeout is passed as the least fgro takes
    let output = eval_with(&config, "report", Duration::ZERO).await.unwrap();
    let report: serde_json::Value = serde_json::from_str(&output.value_json).unwrap();
    assert_eq!(report["argv"][7], "1");
}

/// A stderr flood past the capture cap is drained, not a deadlock, and doesn't
/// fail an eval that succeeds; a stdout flood past the cap kills the child.
#[tokio::test]
async fn a_flood_is_drained_or_cut_at_its_cap() {
    let (_scratch, config) = project("fake_flood", "export default 1;\n");
    let output = eval(&config, "stderr-flood 3").await.unwrap();
    assert!(output.value_json.starts_with('{'));
    // past the cap, which sits just above fgro's 64 MiB envelope cap
    let error = eval(&config, "stdout-flood 70").await.unwrap_err();
    assert!(
        matches!(error, EvalError::OutputTooLarge { limit, .. } if limit == MAX_STDOUT_SIZE),
        "{error:?}"
    );
}

/// An envelope larger than the shared capture cap (10 MiB) but within fgro's
/// own envelope cap is read whole: the stdout cap sits above fgro's.
#[tokio::test]
async fn an_envelope_within_fgro_s_cap_is_never_too_large() {
    let (_scratch, config) = project("fake_big", "export default 1;\n");
    let output = eval(&config, "big-value 12").await.unwrap();
    assert!(output.value_json.len() > 12 * 1024 * 1024);
}

/// A child that exits without reading a driver too large for the pipe breaks
/// it; the write's error is not the eval's. fgro fails that way before it reads
/// the driver (an inherited descriptor it couldn't close), naming the default
/// export and no driver hash: the eval failure it reports comes back as one.
#[tokio::test]
async fn a_failure_before_fgro_reads_the_driver_is_reported_as_itself() {
    let (_scratch, config) = project("fake_skip", "export default 1;\n");
    let driver = format!("skip-driver\n{}", "x".repeat(4 * 1024 * 1024));
    let error = eval(&config, &driver).await.unwrap_err();
    let EvalError::Eval { failure, .. } = &error else {
        panic!("expected the eval failure, got {error:?}");
    };
    assert_eq!(failure.kind, EvalErrorKind::Environment);
    assert!(
        failure.message.contains("cannot close the descriptors"),
        "{failure:?}"
    );
}

/// Past the timeout and its grace the whole process group is killed: the child,
/// and a grandchild it started that holds stdout open.
#[tokio::test]
async fn the_backstop_kills_the_whole_process_group() {
    let (scratch, config) = project("fake_group", "export default 1;\n");
    let pid_file = scratch.path().join("grandchild.pid");
    let timeout = Duration::from_millis(100);
    let started = Instant::now();
    let error = eval_with(
        &config,
        &format!("grandchild {}", pid_file.display()),
        timeout,
    )
    .await
    .unwrap_err();
    assert!(matches!(error, EvalError::Timeout { .. }), "{error:?}");
    assert!(
        started.elapsed() < timeout + TIMEOUT_GRACE + Duration::from_secs(5),
        "{:?}",
        started.elapsed()
    );
    let pid = std::fs::read_to_string(&pid_file).unwrap();
    assert_dies(pid.trim());
}

/// The trust root is settled before the pin or the spawn: a refusal there never
/// reaches the binary, here a path with nothing at it.
#[tokio::test]
async fn a_trust_root_refusal_comes_before_the_pin() {
    let (scratch, config) = project("fake_trust_root", "export default 1;\n");
    let unreached = FgroPin {
        path: Path::new("/nonexistent/fgro"),
        expected_blake3: "not a pin",
        cache_dir: None,
    };
    let refused = |config: PathBuf| async move {
        eval_module(&EvalRequest {
            config_path: &config,
            driver_js: "ok",
            timeout: Duration::from_secs(5),
            fgro: unreached,
        })
        .await
        .unwrap_err()
    };
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o666)).unwrap();
    let error = refused(config.clone()).await;
    assert!(
        matches!(
            error,
            EvalError::TrustRoot {
                problem: TrustRootProblem::WorldWritableConfigFile,
                ..
            }
        ),
        "{error:?}"
    );
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o644)).unwrap();
    write(&scratch.path().join("package.json"), r#"{"name":5}"#);
    let error = refused(config.clone()).await;
    assert!(
        matches!(
            error,
            EvalError::TrustRoot {
                problem: TrustRootProblem::InvalidPackageJson,
                ..
            }
        ),
        "{error:?}"
    );
    // with the root settled, the pin is next
    write(&scratch.path().join("package.json"), r#"{"name":"p"}"#);
    let error = refused(config).await;
    assert!(matches!(error, EvalError::InvalidPin { .. }), "{error:?}");
}

/// A config reached through a link is judged by the file it names: a link to a
/// world-writable file is refused, naming that file, and a link — whose own mode
/// is always `0777` — to a closed file evaluates, from a world-writable
/// directory too, since neither the link nor where it sits is what runs.
#[tokio::test]
async fn a_linked_config_is_judged_by_the_file_it_names() {
    let (scratch, config) = project("fake_linked_config", "export default 1;\n");
    let open = scratch.path().join("open.ts");
    write(&open, "export default 1;\n");
    std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o666)).unwrap();
    let links = scratch.path().join("links");
    std::fs::create_dir(&links).unwrap();
    std::fs::set_permissions(&links, std::fs::Permissions::from_mode(0o755)).unwrap();
    let to_open = links.join("open.ts");
    let to_config = links.join("config.ts");
    std::os::unix::fs::symlink(&open, &to_open).unwrap();
    std::os::unix::fs::symlink(&config, &to_config).unwrap();

    match eval(&to_open, "ok").await {
        Err(EvalError::TrustRoot {
            path,
            problem: TrustRootProblem::WorldWritableConfigFile,
            offending,
            reason,
        }) => {
            assert_eq!(path, open.display().to_string());
            assert_eq!(offending, open.display().to_string());
            assert_eq!(reason, "mode 0666");
        }
        other => panic!("expected the link's target refused, got {other:?}"),
    }
    for links_mode in [0o755, 0o777] {
        std::fs::set_permissions(&links, std::fs::Permissions::from_mode(links_mode)).unwrap();
        let output = eval(&to_config, "ok")
            .await
            .unwrap_or_else(|error| panic!("links at {links_mode:o}: {error:?}"));
        assert_eq!(output.config_path, config, "links at {links_mode:o}");
    }
}

/// A walk that finds no `package.json` setting the project refuses before the
/// pin and the spawn, naming where it stopped: fgro's own walk wouldn't stop
/// there. The fake, pinned and willing, writes a file when it runs; none
/// appears.
#[tokio::test]
async fn a_walk_that_finds_no_project_refuses_before_the_spawn() {
    let scratch = Scratch::new("fake_no_project");
    let marker = scratch.path().join("spawned");
    let driver = format!("touch {}", marker.display());

    // a package.json above a world-writable directory the walk stops below
    write(
        &scratch.path().join("package.json"),
        r#"{"name":"above","private":true}"#,
    );
    let shared = scratch.path().join("shared");
    let config = shared.join("project/zap.ts");
    write(&config, "export default 1;\n");
    std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o777)).unwrap();
    let error = eval(&config, &driver).await.unwrap_err();
    assert!(
        matches!(
            &error,
            EvalError::TrustRoot {
                problem: TrustRootProblem::WalkStopped(WalkStop::WorldWritable),
                offending,
                ..
            } if Path::new(offending) == shared
        ),
        "{error:?}"
    );
    assert!(
        error.to_string().contains("every user can write it"),
        "{error}"
    );
    assert!(!marker.exists(), "the fake ran");

    // no package.json at all: the walk stops below a directory another user
    // owns (root's, above the home directory) or reaches the filesystem root
    let lone = scratch.path().join("lone/zap.ts");
    std::fs::remove_file(scratch.path().join("package.json")).unwrap();
    write(&lone, "export default 1;\n");
    let error = eval(&lone, &driver).await.unwrap_err();
    assert!(
        matches!(
            error,
            EvalError::TrustRoot {
                problem: TrustRootProblem::WalkStopped(_) | TrustRootProblem::NoProject,
                ..
            }
        ),
        "{error:?}"
    );
    assert!(!marker.exists(), "the fake ran");

    // with a project of its own, the fake runs
    write(
        &scratch.path().join("lone/package.json"),
        r#"{"name":"lone"}"#,
    );
    eval(&lone, &driver).await.unwrap();
    assert!(marker.exists(), "the fake didn't run");
}

/// A caller that drops the eval's future mid-run takes down the whole process
/// group: the child, and a grandchild it started.
#[tokio::test]
async fn dropping_the_eval_kills_the_whole_process_group() {
    let (scratch, config) = project("fake_drop", "export default 1;\n");
    let pid_file = scratch.path().join("grandchild.pid");
    let driver = format!("grandchild {}", pid_file.display());
    let eval = eval_with(&config, &driver, Duration::from_secs(60));
    let written = async {
        while !pid_file.exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    };
    tokio::select! {
        result = eval => panic!("the eval finished: {result:?}"),
        () = written => {}
    }
    // the eval's future is dropped here, mid-run
    let pid = std::fs::read_to_string(&pid_file).unwrap();
    assert_dies(pid.trim());
}

/// Wait, a few seconds at most, for the process `pid` to be gone or a zombie
/// waiting on whatever adopted it.
fn assert_dies(pid: &str) {
    let stat = PathBuf::from(format!("/proc/{pid}/stat"));
    let dead = || {
        std::fs::read_to_string(&stat).map_or(true, |stat| {
            stat.rsplit_once(") ")
                .is_some_and(|(_, rest)| rest.starts_with('Z'))
        })
    };
    let deadline = Instant::now() + Duration::from_secs(5);
    while !dead() {
        assert!(
            Instant::now() < deadline,
            "the process {pid} outlived the kill"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// A pin that isn't the binary's blake3 refuses before the spawn, and so does a
/// config path that isn't UTF-8, which fgro can't take as an argument.
#[tokio::test]
async fn a_wrong_pin_or_a_non_utf8_path_refuses_before_the_spawn() {
    let (scratch, config) = project("fake_pin", "export default 1;\n");
    let wrong = "0".repeat(64);
    let error = eval_module(&EvalRequest {
        config_path: &config,
        driver_js: "ok",
        timeout: Duration::from_secs(5),
        fgro: FgroPin {
            path: fake(),
            expected_blake3: &wrong,
            cache_dir: None,
        },
    })
    .await
    .unwrap_err();
    assert!(
        matches!(&error, EvalError::PinMismatch { actual, .. } if actual == fake_pin()),
        "{error:?}"
    );

    let odd = scratch.path().join(OsStr::from_bytes(b"config\xff.ts"));
    std::fs::write(&odd, "export default 1;\n").unwrap();
    let error = eval(&odd, "ok").await.unwrap_err();
    assert!(
        matches!(error, EvalError::ConfigPathNotUtf8 { .. }),
        "{error:?}"
    );
}

/// The pin's cache directory, when given, is held to its rule on the eval path
/// too.
#[tokio::test]
async fn the_pin_cache_is_used_on_the_eval_path() {
    let (scratch, config) = project("fake_cache", "export default 1;\n");
    let cache = scratch.path().join("pins");
    let output = eval_module(&EvalRequest {
        config_path: &config,
        driver_js: "ok",
        timeout: Duration::from_secs(10),
        fgro: FgroPin {
            path: fake(),
            expected_blake3: fake_pin(),
            cache_dir: Some(&cache),
        },
    })
    .await
    .unwrap();
    assert!(output.value_json.starts_with('{'));
    let mode = std::fs::metadata(&cache).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o700);
}
