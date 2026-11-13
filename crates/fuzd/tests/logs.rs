//! `fuzd logs` end to end: the last lines, a missing or planted log, and a
//! follow that prints appended lines and dies by SIGTERM — at once, even while
//! its stdout write is blocked.

#![expect(
    clippy::expect_used,
    reason = "test helpers outside `#[test]` fns panic on a failed setup or check"
)]

use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use fuz_sys::{Signal, send_signal};

const FUZD: &str = env!("CARGO_BIN_EXE_fuzd");

/// How long the follow test waits for one line before failing — far past
/// `LOG_POLL_INTERVAL`, so it trips only on a hang.
const LINE_TIMEOUT: Duration = Duration::from_secs(10);

/// SIGTERM's number, for comparing with `ExitStatus::signal`.
const SIGTERM: i32 = Signal::SIGTERM as i32;

/// How long a follow may take to be gone after SIGTERM.
const EXIT_TIMEOUT: Duration = Duration::from_secs(5);

/// A 0700 `FUZ_HOME` with its logs directory, and the log path in it.
fn home_with_logs() -> (tempfile::TempDir, PathBuf) {
    let home = tempfile::tempdir().expect("tempdir");
    let logs = home.path().join("state").join("logs");
    std::fs::create_dir_all(&logs).expect("create the logs dir");
    for dir in [home.path(), &home.path().join("state"), &logs] {
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).expect("chmod");
    }
    (home, logs.join("daemon_output.log"))
}

fn run_logs(home: &Path, args: &[&str]) -> Output {
    Command::new(FUZD)
        .env("FUZ_HOME", home)
        .arg("logs")
        .args(args)
        .stdin(Stdio::null())
        .output()
        .expect("run fuzd logs")
}

/// `line <i>` lines, each newline-terminated, for each `i` in `range`.
fn numbered_lines(range: std::ops::RangeInclusive<u32>) -> String {
    let mut text = String::new();
    for i in range {
        text.push_str("line ");
        text.push_str(&i.to_string());
        text.push('\n');
    }
    text
}

/// `--no-follow` prints the last N lines (10 by default) and exits `0`.
#[test]
fn logs_no_follow_prints_the_last_lines() {
    let (home, log) = home_with_logs();
    let text = numbered_lines(1..=12);
    std::fs::write(&log, &text).expect("write the log");

    let out = run_logs(home.path(), &["--no-follow", "-n", "2"]);
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    assert_eq!(String::from_utf8_lossy(&out.stdout), "line 11\nline 12\n");

    let out = run_logs(home.path(), &["--no-follow"]);
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    assert_eq!(String::from_utf8_lossy(&out.stdout), numbered_lines(3..=12));
}

/// No log file is exit `1` with a message naming the path.
#[test]
fn logs_without_a_log_file_exits_1() {
    let (home, log) = home_with_logs();
    let out = run_logs(home.path(), &["--no-follow"]);
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    assert!(
        String::from_utf8_lossy(&out.stderr)
            .contains(&format!("No log file found at {}", log.display())),
        "{out:?}"
    );
}

/// A symlink at the log path is refused by the open (exit `1`), and its target
/// is never printed.
#[test]
fn logs_refuses_a_planted_symlink() {
    let (home, log) = home_with_logs();
    let victim = home.path().join("victim");
    std::fs::write(&victim, b"secret\n").expect("write the victim");
    std::os::unix::fs::symlink(&victim, &log).expect("plant the link");

    for args in [&["--no-follow"][..], &[]] {
        let out = run_logs(home.path(), args);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(1), "{args:?}: {stderr}");
        assert!(
            stderr.contains(&format!(
                "error: cannot open log file: file is a symlink: {}",
                log.display()
            )),
            "{args:?}: {stderr}"
        );
        assert!(out.stdout.is_empty(), "{args:?}: printed the target");
    }
}

/// A follow prints the last lines, then appended ones — across a rotation to
/// a new file — and SIGTERM ends it by the signal's default disposition.
#[test]
fn logs_follow_prints_appends_and_dies_by_sigterm() {
    let (home, log) = home_with_logs();
    std::fs::write(&log, "old\n").expect("write the log");

    let mut child = Command::new(FUZD)
        .env("FUZ_HOME", home.path())
        .args(["logs", "-n", "1"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn fuzd logs");
    let stdout = child.stdout.take().expect("stdout");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            if tx.send(line.expect("read a line")).is_err() {
                break;
            }
        }
    });
    let next_line = || {
        rx.recv_timeout(LINE_TIMEOUT)
            .unwrap_or_else(|e| panic!("no line from fuzd logs: {e}"))
    };

    assert_eq!(next_line(), "old");
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(&log)
        .expect("open the log");
    file.write_all(b"appended\n").expect("append");
    assert_eq!(next_line(), "appended");

    // `fuzd start`'s rotation: rename aside, then a fresh file.
    std::fs::rename(&log, log.with_extension("log.1")).expect("rotate");
    std::fs::write(&log, "rotated in\n").expect("write the new log");
    assert_eq!(next_line(), "rotated in");

    let pid = i32::try_from(child.id()).expect("pid");
    assert_eq!(send_signal(pid, Signal::SIGTERM), Ok(true));
    let out = child.wait_with_output().expect("wait for fuzd logs");
    assert_eq!(
        out.status.signal(),
        Some(SIGTERM),
        "{:?}, stderr: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
}

/// A follow whose stdout reader has stopped reading is blocked in a write;
/// SIGTERM still ends it within [`EXIT_TIMEOUT`], not when the reader closes.
#[test]
fn logs_follow_dies_by_sigterm_while_its_write_is_blocked() {
    let (home, log) = home_with_logs();
    std::fs::write(&log, "old\n").expect("write the log");

    let mut child = Command::new(FUZD)
        .env("FUZ_HOME", home.path())
        .args(["logs", "-n", "1"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn fuzd logs");
    // Held open and never read: the pipe fills and the follow's write blocks.
    let mut stdout = child.stdout.take().expect("stdout");
    let mut first = [0u8; 4];
    std::io::Read::read_exact(&mut stdout, &mut first).expect("the first line");
    assert_eq!(&first, b"old\n");

    // Far past a pipe's buffer.
    let line = "x".repeat(1023) + "\n";
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(&log)
        .expect("open the log");
    for _ in 0..2048 {
        file.write_all(line.as_bytes()).expect("append");
    }
    // A few poll intervals, so the follow is in its blocked write.
    std::thread::sleep(Duration::from_secs(1));

    let pid = i32::try_from(child.id()).expect("pid");
    assert_eq!(send_signal(pid, Signal::SIGTERM), Ok(true));
    let deadline = Instant::now() + EXIT_TIMEOUT;
    let status = loop {
        if let Some(status) = child.try_wait().expect("try_wait") {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("fuzd logs outlived SIGTERM by {EXIT_TIMEOUT:?} with its write blocked");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    assert_eq!(status.signal(), Some(SIGTERM), "{status:?}");
    drop(stdout);
}
