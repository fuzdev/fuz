//! A stand-in for `fgro eval`, for `fuz_eval`'s integration suites: it takes
//! the command line `fuz_eval` passes, reads the driver from stdin, and acts
//! out the mode the driver's first line names — a canned envelope, a broken
//! one, a crash, a flood, a hang, or a report of what it was given (its argv,
//! working directory, environment, open descriptors, and uids and groups) as an
//! `ok` value.
//!
//! Its environment is cleared by `fuz_eval`, so the driver is the one channel a
//! test has to steer it. Test-only: the `testing_` prefix keeps it out of every
//! release.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "a test fixture: a failure here is a failed test, reported by the suite"
)]

use std::io::{BufRead, Read, Write};
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use serde_json::{Value, json};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("sleep-forever") {
        sleep_forever();
    }
    let config = args.get(2).cloned().unwrap_or_default();
    let cwd = std::env::current_dir()
        .map(|dir| dir.display().to_string())
        .unwrap_or_default();

    let mut stdin = std::io::stdin().lock();
    let mut first = String::new();
    stdin.read_line(&mut first).unwrap();
    let line = first.trim().to_owned();
    let (mode, arg) = line.split_once(' ').unwrap_or((&line, ""));

    if mode == "skip-driver" {
        // exits before reading the rest of a driver too large for the pipe,
        // writing what gro's `eval::failed()` writes for a failure before the
        // read: the default export, no driver hash, an error with a kind and a
        // message alone, an empty access, and a null graph
        let envelope = json!({
            "eval_protocol": 2,
            "ok": false,
            "runtime": envelope(&config, None, &cwd)["runtime"],
            "entry": {"id": config, "export": "default", "driver_blake3": null},
            "error": {
                "kind": "environment",
                "message": "cannot close the descriptors the eval inherited: fake"
            },
            "access": {"dynamic": []},
            "graph": null
        });
        return emit(&envelope, 1);
    }
    if mode == "touch" {
        // proof the fake ran: a refusal before the spawn leaves no file
        std::fs::write(arg, b"spawned").unwrap();
    }

    let mut rest = Vec::new();
    stdin.read_to_end(&mut rest).unwrap();
    let mut driver = first.into_bytes();
    driver.extend_from_slice(&rest);
    let driver_blake3 = blake3::hash(&driver).to_hex().to_string();
    let mut envelope = envelope(&config, Some(&driver_blake3), &cwd);

    match mode {
        "ok" | "touch" => emit(&envelope, 0),
        "fail" => {
            let (kind, code) = arg.split_once(' ').unwrap_or((arg, "1"));
            fail(&mut envelope, kind);
            emit(&envelope, code.parse().unwrap())
        }
        "fail-null-graph" => {
            fail(&mut envelope, "resolve");
            envelope["graph"] = Value::Null;
            emit(&envelope, 2)
        }
        "exit" => emit(&envelope, arg.parse().unwrap()),
        "abort" => {
            write_line(&envelope);
            std::process::abort();
        }
        "fail-exit-0" => {
            fail(&mut envelope, "link");
            emit(&envelope, 0)
        }
        "unknown-field" => {
            let target = envelope.pointer_mut(arg).unwrap();
            target["unknown_field"] = json!(1);
            emit(&envelope, 0)
        }
        "wrong-id" => {
            envelope["entry"]["id"] = json!(format!("{config}.other"));
            emit(&envelope, 0)
        }
        "wrong-driver" => {
            envelope["entry"]["driver_blake3"] = json!(blake3::hash(b"another").to_hex().as_str());
            emit(&envelope, 0)
        }
        "graph-version" => {
            envelope["graph"]["graph_version"] = json!(2);
            emit(&envelope, 0)
        }
        "project" => {
            envelope["graph"]["local"]["project"] = json!(arg);
            emit(&envelope, 0)
        }
        "null-graph" => {
            envelope["graph"] = Value::Null;
            emit(&envelope, 0)
        }
        "two-objects" => {
            write_line(&envelope);
            emit(&envelope, 0)
        }
        "not-utf8" => {
            std::io::stdout()
                .write_all(b"{\"eval_protocol\":2,\xff}\n")
                .unwrap();
            ExitCode::from(0)
        }
        "silent" => ExitCode::from(1),
        "stderr-flood" => {
            flood(&mut std::io::stderr(), arg.parse().unwrap());
            emit(&envelope, 0)
        }
        "stdout-flood" => {
            flood(&mut std::io::stdout(), arg.parse().unwrap());
            ExitCode::from(0)
        }
        "big-value" => {
            let mib: usize = arg.parse().unwrap();
            envelope["value"] = json!("x".repeat(mib * 1024 * 1024));
            emit(&envelope, 0)
        }
        "hang" => sleep_forever(),
        "grandchild" => {
            // a grandchild in this process group that holds stdout open, then
            // a hang: only a kill of the whole group ends both
            #[expect(clippy::zombie_processes, reason = "the test kills the whole group")]
            let grandchild = std::process::Command::new("/proc/self/exe")
                .arg("sleep-forever")
                .stdin(std::process::Stdio::null())
                .spawn()
                .unwrap();
            std::fs::write(Path::new(arg), grandchild.id().to_string()).unwrap();
            sleep_forever();
        }
        "report" => {
            let env: serde_json::Map<String, Value> = std::env::vars_os()
                .map(|(name, value)| {
                    (
                        name.to_string_lossy().into_owned(),
                        json!(value.to_string_lossy()),
                    )
                })
                .collect();
            envelope["value"] = json!({
                "argv": args,
                "cwd": cwd,
                "env": env,
                "fds": open_fds(),
                "ids": ids(),
            });
            emit(&envelope, 0)
        }
        other => panic!("testing_fake_fgro: unknown mode {other:?}"),
    }
}

/// An `ok` envelope for `config`, its graph's project `cwd`.
fn envelope(config: &str, driver_blake3: Option<&str>, cwd: &str) -> Value {
    let config_blake3 = std::fs::read(config)
        .map(|bytes| blake3::hash(&bytes).to_hex().to_string())
        .ok();
    let name = Path::new(config)
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let id = format!("project:{name}");
    json!({
        "eval_protocol": 2,
        "ok": true,
        "runtime": {
            "fgro_version": "0.0.0",
            "commit": null,
            "dirty": null,
            "v8": "fake",
            "deno_core": "fake",
            "tsv_rev": "fake"
        },
        "entry": {"id": config, "export": null, "driver_blake3": driver_blake3},
        "value": {"zeta": [1, {"b": true, "a": null}], "alpha": "x"},
        "access": {"dynamic": []},
        "graph": {
            "graph_version": 1,
            "roots": [id],
            "modules": [{
                "id": id,
                "blake3": config_blake3,
                "origin": {"kind": "project"},
                "format": "typescript",
                "imports": []
            }],
            "consulted": [],
            "absent": [],
            "local": {"project": cwd, "box": [cwd], "paths": {id: config}}
        }
    })
}

/// Turn `envelope` into a failure of `kind`, with every optional field set.
fn fail(envelope: &mut Value, kind: &str) {
    let fields = envelope.as_object_mut().unwrap();
    fields.remove("value");
    fields.insert("ok".into(), json!(false));
    fields.insert(
        "error".into(),
        json!({
            "kind": kind,
            "message": format!("fake {kind} failure\n    at file:///fake.ts:1:1"),
            "at": "$.a",
            "specifier": "./missing.ts",
            "importer": "file:///fake.ts",
            "hint": "a fake hint"
        }),
    );
}

/// Write `envelope` on one line and exit with `code`.
fn emit(envelope: &Value, code: u8) -> ExitCode {
    write_line(envelope);
    ExitCode::from(code)
}

fn write_line(envelope: &Value) {
    let mut stdout = std::io::stdout().lock();
    writeln!(stdout, "{envelope}").unwrap();
    stdout.flush().unwrap();
}

/// Write `mib` MiB to `out`; a closed pipe ends it early.
fn flood(out: &mut impl Write, mib: usize) {
    let chunk = vec![b'x'; 1024 * 1024];
    for _ in 0..mib {
        if out.write_all(&chunk).is_err() {
            return;
        }
    }
}

/// The descriptors open in this process, apart from the one listing them.
fn open_fds() -> Vec<u32> {
    let mut fds: Vec<u32> = std::fs::read_dir("/proc/self/fd")
        .unwrap()
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let target = std::fs::read_link(entry.path()).ok()?;
            // the listing's own descriptor names the directory it lists
            if target.starts_with("/proc") && target.ends_with("fd") {
                return None;
            }
            entry.file_name().to_str()?.parse().ok()
        })
        .collect();
    fds.sort_unstable();
    fds
}

/// The `Uid:`, `Gid:`, and `Groups:` lines of `/proc/self/status`, each as its
/// fields: real, effective, saved, and filesystem ids, then the supplementary
/// groups.
fn ids() -> Value {
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    let mut ids = serde_json::Map::new();
    for line in status.lines() {
        if let Some((name @ ("Uid" | "Gid" | "Groups"), fields)) = line.split_once(':') {
            let fields: Vec<u32> = fields
                .split_whitespace()
                .map(|field| field.parse().unwrap())
                .collect();
            ids.insert(name.to_lowercase(), json!(fields));
        }
    }
    Value::Object(ids)
}

fn sleep_forever() -> ! {
    loop {
        std::thread::sleep(Duration::from_secs(3600));
    }
}
