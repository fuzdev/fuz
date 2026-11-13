//! The real `fuzd` binary against a throwaway `FUZ_HOME`. Beside a running
//! foreground daemon: a second foreground `fuzd` refuses with exit 75 and
//! names the holder; `fuzd start` — which finds no `daemon.json`, since a
//! foreground daemon writes none — reports the running daemon instead of
//! spawning a child beside it; and `fuzd restart` refuses rather than report a
//! restart it did not do. Beside a lock holder that does not answer, `fuzd
//! start` reports the holder as an error. On its own, a recorded daemon goes
//! through `fuzd start`, `restart`, and `stop`. And a recorded daemon that
//! stops answering — `SIGSTOP`ped, still holding the socket lock — is refused
//! by every command but `--force`, which kills it and waits for it to exit.
//! A `daemon.json` this fuzd can't read that names a live fuzd — the
//! version-skew guard — makes `fuzd start` refuse without spawning, as do a
//! world-writable home and a symlink or non-regular file at the daemon log
//! path. A link planted at `daemon.json`'s temp path fails the start without
//! being written through. A recorded daemon whose home is renamed to a path
//! too long for its socket is left alone by every command through that path,
//! and stopped through a short symlink to it.
//!
//! Every test runs its home under a [`Home`] guard, which kills any fuzd still
//! running on it when the test ends, and every `fuzd` invocation under a
//! deadline — a daemon these tests leak would otherwise outlive the deleted
//! tempdir, holding its lock and serving nothing anyone can reach.

#![expect(
    clippy::expect_used,
    clippy::panic,
    reason = "test helpers outside `#[test]` fns panic on a failed setup or check"
)]

use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use fuz_sys::file_lock::read_lock_holder;
use fuz_sys::{Signal, is_pid_alive, send_signal};

const FUZD: &str = env!("CARGO_BIN_EXE_fuzd");

/// How long one `fuzd` invocation may run before the test kills it — far past
/// any lifecycle command's own deadlines, so it trips only on a hang (a bare
/// `fuzd` that serves instead of refusing, a poll that never ends).
const RUN_TIMEOUT: Duration = Duration::from_secs(60);

/// A throwaway `FUZ_HOME` that kills the fuzd daemons left running on it.
///
/// Declare it first in a test so it drops last, after any [`Foreground`]
/// guard. On drop it reads the pids the home names — the socket lock's holder
/// and `daemon.json`'s — and `SIGKILL`s each that is still running with
/// `FUZ_HOME` set to this home, so a failed or regressed test cannot leave a
/// daemon running past its deleted tempdir. The environment check keeps it
/// from killing a pid that names no daemon of this home: the test process
/// itself when it holds the lock, or a pid reused since.
struct Home {
    dir: tempfile::TempDir,
}

impl Home {
    /// A home at 0700, whatever the runner's umask: the CLI refuses a
    /// world-writable `FUZ_HOME`, and `tempfile` creates the dir from the umask.
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        set_mode(dir.path(), 0o700);
        Self { dir }
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        let home = self.path();
        let holder = read_lock_holder(&lock_path(home)).and_then(|p| i32::try_from(p).ok());
        for pid in holder.into_iter().chain(recorded_pid(home)) {
            if runs_on_home(pid, home) && send_signal(pid, Signal::SIGKILL).unwrap_or(false) {
                eprintln!("killed fuzd pid {pid} left running on {}", home.display());
            }
        }
    }
}

fn set_mode(path: &Path, mode: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("chmod");
}

/// Whether `pid` runs with `FUZ_HOME` set to exactly `home`, per its
/// `/proc/<pid>/environ` (`false` when that can't be read — no such process).
fn runs_on_home(pid: i32, home: &Path) -> bool {
    let Ok(environ) = std::fs::read(format!("/proc/{pid}/environ")) else {
        return false;
    };
    let mut wanted = b"FUZ_HOME=".to_vec();
    wanted.extend_from_slice(home.as_os_str().as_bytes());
    environ
        .split(|&byte| byte == 0)
        .any(|entry| entry == wanted)
}

/// The pid `daemon.json` records, if it exists and parses.
fn recorded_pid(home: &Path) -> Option<i32> {
    let body = std::fs::read_to_string(home.join("run").join("daemon.json")).ok()?;
    serde_json::from_str::<fuz_home::DaemonInfo>(&body)
        .ok()
        .map(|info| info.pid)
}

/// A foreground `fuzd` that is killed when the test ends, pass or fail.
struct Foreground {
    child: Child,
}

impl Drop for Foreground {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Start a foreground `fuzd` on `home` and wait until its socket exists — it
/// binds only after taking the socket lock, so the lock is held from then on.
fn start_foreground(home: &Path) -> Foreground {
    let child = Command::new(FUZD)
        .env("FUZ_HOME", home)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn foreground fuzd");
    let foreground = Foreground { child };
    let socket = socket_path(home);
    let deadline = Instant::now() + Duration::from_secs(10);
    while !socket.exists() {
        assert!(
            Instant::now() < deadline,
            "foreground fuzd never bound {}",
            socket.display()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    foreground
}

fn socket_path(home: &Path) -> PathBuf {
    home.join("run").join("socket")
}

fn lock_path(home: &Path) -> PathBuf {
    fuz_home::socket_lock_path(&socket_path(home))
}

/// Run `fuzd <args>` on `home` to completion, killing it (and failing the
/// test) if it runs past [`RUN_TIMEOUT`].
fn run_fuzd(home: &Path, args: &[&str]) -> Output {
    let mut child = Command::new(FUZD)
        .args(args)
        .env("FUZ_HOME", home)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn fuzd");
    // Drain both pipes off-thread so a chatty child cannot block on a full one.
    let stdout = drain(child.stdout.take().expect("piped stdout"));
    let stderr = drain(child.stderr.take().expect("piped stderr"));
    let deadline = Instant::now() + RUN_TIMEOUT;
    let status = loop {
        if let Some(status) = child.try_wait().expect("try_wait fuzd") {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!(
                "`fuzd {}` still running after {RUN_TIMEOUT:?}",
                args.join(" ")
            );
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    Output {
        status,
        stdout: stdout.join().expect("stdout reader"),
        stderr: stderr.join().expect("stderr reader"),
    }
}

fn drain(mut pipe: impl Read + Send + 'static) -> std::thread::JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = pipe.read_to_end(&mut buf);
        buf
    })
}

#[test]
fn a_second_foreground_fuzd_exits_already_running() {
    let home = Home::new();
    let foreground = start_foreground(home.path());

    let out = run_fuzd(home.path(), &[]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(75), "stderr: {stderr}");
    let expected = format!(
        "error: another fuzd is already running on {} (pid {})",
        socket_path(home.path()).display(),
        foreground.child.id()
    );
    assert!(stderr.contains(&expected), "stderr: {stderr}");
    assert!(
        socket_path(home.path()).exists(),
        "the refused daemon must leave the running one's socket in place"
    );
}

#[test]
fn fuzd_start_beside_a_foreground_fuzd_reports_it_running() {
    let home = Home::new();
    let foreground = start_foreground(home.path());

    let out = run_fuzd(home.path(), &["start"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stdout: {stdout}\nstderr: {stderr}"
    );
    let expected = format!(
        "already running at {} (pid {})",
        socket_path(home.path()).display(),
        foreground.child.id()
    );
    assert!(stderr.contains(&expected), "stderr: {stderr}");
    assert!(
        !stdout.contains("started at"),
        "must not report a start: {stdout}"
    );
    assert!(
        !home.path().join("run").join("daemon.json").exists(),
        "no daemon.json: fuzd start spawned nothing it could record"
    );
    assert!(
        !home
            .path()
            .join("state")
            .join("logs")
            .join("daemon_output.log")
            .exists(),
        "no daemon log: fuzd start reported the running daemon before spawning a child"
    );
}

/// `fuzd restart` beside a daemon with no `daemon.json` — here a foreground one
/// — refuses (exit 1) and names it: it has no record to stop it by, and falling
/// through to `start` would report "already running" with exit 0 while the old
/// daemon kept serving. The daemon is left running and nothing is recorded.
#[test]
fn fuzd_restart_beside_a_foreground_fuzd_refuses() {
    let home = Home::new();
    let mut foreground = start_foreground(home.path());

    let out = run_fuzd(home.path(), &["restart"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(1),
        "stdout: {stdout}\nstderr: {stderr}"
    );
    let expected = format!(
        "error: a fuzd with no daemon.json is running at {} (pid {})",
        socket_path(home.path()).display(),
        foreground.child.id()
    );
    assert!(stderr.contains(&expected), "stderr: {stderr}");
    assert!(
        stderr.contains(
            "hint: restart stops only a daemon `fuzd start` recorded; stop this one (Ctrl-C in its terminal, or kill its pid), then re-run `fuzd restart`"
        ),
        "stderr: {stderr}"
    );
    assert!(
        foreground.child.try_wait().expect("try_wait").is_none(),
        "restart must not stop a daemon it did not start"
    );
    assert!(
        !home.path().join("run").join("daemon.json").exists(),
        "nothing recorded"
    );
}

/// A socket-lock holder that does not answer the health probe: `fuzd start`
/// spawns, the child exits 75, and start reports another fuzd running — naming
/// the holder's pid from the lock — as an error (exit 1), recording nothing.
#[test]
fn fuzd_start_beside_a_silent_lock_holder_reports_already_running() {
    use fuz_sys::file_lock::{FileLock, LockInfo};
    let home = Home::new();
    let run = home.path().join("run");
    // `acquire` creates the run dir (0700) it needs.
    let _held = FileLock::acquire(&lock_path(home.path()), &LockInfo::current())
        .expect("hold the socket lock");

    let out = run_fuzd(home.path(), &["start"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "stderr: {stderr}");
    let expected = format!(
        "error: another fuzd is already running on {} (pid {})",
        socket_path(home.path()).display(),
        std::process::id()
    );
    assert!(stderr.contains(&expected), "stderr: {stderr}");
    let hint = format!(
        "hint: it does not answer this fuzd's health check (another protocol version, hung, or still starting or stopping); `fuzd stop` cannot reach it — wait and re-run, or stop it with `kill {}`",
        std::process::id()
    );
    assert!(stderr.contains(&hint), "stderr: {stderr}");
    assert!(!run.join("daemon.json").exists(), "nothing recorded");
}

/// A daemon `fuzd start` records goes through `restart` and `stop`: start
/// records it and it holds the socket lock; restart replaces it with a new
/// recorded daemon that answers and holds the lock; stop shuts that one down,
/// returning only once it has let go of the lock, and clears the record.
#[test]
fn fuzd_start_restart_stop_cycles_a_recorded_daemon() {
    let home = Home::new();
    let socket = socket_path(home.path());
    let lock = lock_path(home.path());
    let started_at = format!("started at {} (pid ", socket.display());

    let out = run_fuzd(home.path(), &["start"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(0),
        "start\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(stdout.contains(&started_at), "start stdout: {stdout}");
    let first = recorded_pid(home.path()).expect("start recorded its daemon");
    assert_eq!(
        read_lock_holder(&lock).and_then(|p| i32::try_from(p).ok()),
        Some(first),
        "the recorded daemon holds the socket lock"
    );

    let out = run_fuzd(home.path(), &["restart"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(0),
        "restart\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(stdout.contains(&started_at), "restart stdout: {stdout}");
    let second = recorded_pid(home.path()).expect("restart recorded its daemon");
    assert_ne!(second, first, "restart started a new daemon");
    assert_eq!(
        read_lock_holder(&lock).and_then(|p| i32::try_from(p).ok()),
        Some(second),
        "the restarted daemon holds the socket lock"
    );
    let deadline = Instant::now() + Duration::from_secs(15);
    while is_pid_alive(first) {
        assert!(
            Instant::now() < deadline,
            "the replaced daemon (pid {first}) never exited"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    let out = run_fuzd(home.path(), &["status", "--quiet"]);
    assert_eq!(out.status.code(), Some(0), "the restarted daemon answers");

    let out = run_fuzd(home.path(), &["stop"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stop\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(stdout.contains("stopped"), "stop stdout: {stdout}");
    let holder = read_lock_holder(&lock).and_then(|p| i32::try_from(p).ok());
    assert!(
        holder != Some(second) || !is_pid_alive(second),
        "stop returned before the daemon let go of the socket lock"
    );
    assert!(
        recorded_pid(home.path()).is_none(),
        "stop cleared the record"
    );
    let out = run_fuzd(home.path(), &["status", "--quiet"]);
    assert_eq!(out.status.code(), Some(1), "no daemon answers after stop");
}

/// Kills `pid` on drop if it is still a fuzd — the guard for a daemon whose
/// home was renamed away from the path a [`Home`] guard watches, so the test
/// leaves none running on any path out of it.
struct KillOnDrop(i32);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let comm = std::fs::read_to_string(format!("/proc/{}/comm", self.0)).unwrap_or_default();
        if comm.trim() == "fuzd" {
            let _ = send_signal(self.0, Signal::SIGKILL);
        }
    }
}

/// A recorded daemon whose home is renamed to a path too long for its socket
/// is out of reach through that path: `status`, `stop`, `stop --force`, and
/// `restart` refuse the home with exit 2, signal nothing, and leave
/// `daemon.json` as it was, with a hint naming the pid it records. Reached
/// through a short symlink to the same home, `stop` stops it.
#[test]
fn a_recorded_daemon_in_a_home_renamed_too_long_is_left_alone() {
    let parent = Home::new();
    let short = parent.path().join("a");
    std::fs::create_dir(&short).expect("mkdir");
    set_mode(&short, 0o700);
    let out = run_fuzd(&short, &["start"]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "start: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let pid = recorded_pid(&short).expect("start recorded its daemon");
    let _guard = KillOnDrop(pid);

    let long = parent.path().join("l".repeat(120));
    std::fs::rename(&short, &long).expect("rename the home");
    let record = long.join("run").join("daemon.json");
    let recorded = std::fs::read(&record).expect("read daemon.json");

    for args in [
        &["status"][..],
        &["stop"],
        &["stop", "--force"],
        &["restart"],
    ] {
        let out = run_fuzd(&long, args);
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        let context = format!("`fuzd {args:?}`\nstdout: {stdout}\nstderr: {stderr}");
        assert_eq!(out.status.code(), Some(2), "{context}");
        assert!(stdout.is_empty(), "{context}");
        assert!(stderr.contains("107-byte limit"), "{context}");
        assert!(
            stderr.contains(&format!("pid {pid}, as recorded")),
            "{context}"
        );
        assert!(!stderr.contains("not running"), "{context}");
        assert!(is_pid_alive(pid), "{context}: the daemon was stopped");
        assert_eq!(
            std::fs::read(&record).expect("daemon.json is still there"),
            recorded,
            "{context}: daemon.json changed"
        );
    }

    let link = parent.path().join("s");
    std::os::unix::fs::symlink(&long, &link).expect("symlink the home");
    let out = run_fuzd(&link, &["stop"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stop through the symlink\nstdout: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(stdout.contains("stopped"), "{stdout}");
    let deadline = Instant::now() + Duration::from_secs(15);
    while is_pid_alive(pid) {
        assert!(
            Instant::now() < deadline,
            "pid {pid} still running after stop"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// A start whose daemon comes up but cannot be recorded — here because a
/// directory sits where the `daemon.json` write stages its temp file —
/// reports the failure (exit 1) and kills the daemon, rather than leaving it
/// serving with no record to stop it by.
#[test]
fn fuzd_start_kills_a_daemon_it_cannot_record() {
    let home = Home::new();
    let staged = home.path().join("run").join("daemon.json.tmp");
    std::fs::create_dir_all(&staged).expect("plant a directory at the temp path");
    set_mode(&home.path().join("run"), 0o700);

    let out = run_fuzd(home.path(), &["start"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(1),
        "stdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stderr.contains(&format!("failed to write {}", staged.display())),
        "stderr: {stderr}"
    );
    assert!(recorded_pid(home.path()).is_none(), "nothing recorded");
    let holder = read_lock_holder(&lock_path(home.path())).and_then(|p| i32::try_from(p).ok());
    assert!(
        holder.is_some(),
        "the daemon came up and took the socket lock before the record failed"
    );
    assert!(
        holder.is_none_or(|pid| !is_pid_alive(pid)),
        "the unrecorded daemon (pid {holder:?}) was left running"
    );
}

/// A link planted where the `daemon.json` write stages its temp file is
/// refused, not written through: the start fails (exit 1, the error naming the
/// symlink as its cause) and kills its daemon, and the link's target keeps its
/// contents.
#[test]
fn fuzd_start_refuses_a_planted_daemon_json_temp_link() {
    let home = Home::new();
    let run = home.path().join("run");
    std::fs::create_dir_all(&run).expect("create the run dir");
    set_mode(&run, 0o700);
    let victim = home.path().join("victim");
    std::fs::write(&victim, b"precious").expect("write the victim");
    let staged = run.join("daemon.json.tmp");
    std::os::unix::fs::symlink(&victim, &staged).expect("plant the link");

    let out = run_fuzd(home.path(), &["start"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "stderr: {stderr}");
    assert!(
        stderr.contains(&format!(
            "error: failed to write {0}: file is a symlink: {0}\n",
            staged.display()
        )),
        "the refusal names its cause: {stderr}"
    );
    assert_eq!(
        std::fs::read(&victim).expect("read the victim"),
        b"precious"
    );
    assert!(
        std::fs::symlink_metadata(&staged)
            .expect("the planted link")
            .file_type()
            .is_symlink(),
        "the planted link was replaced"
    );
    assert!(recorded_pid(home.path()).is_none(), "nothing recorded");
    let holder = read_lock_holder(&lock_path(home.path())).and_then(|p| i32::try_from(p).ok());
    assert!(
        holder.is_none_or(|pid| !is_pid_alive(pid)),
        "the unrecorded daemon (pid {holder:?}) was left running"
    );
}

/// A world-writable home is refused before anything is created under it, with
/// exit 2 (the caller's `chmod` to fix): no daemon is spawned (nothing takes
/// the socket lock) and no log is opened.
#[test]
fn fuzd_start_refuses_a_world_writable_home_before_spawning() {
    let home = Home::new();
    set_mode(home.path(), 0o777);

    let out = run_fuzd(home.path(), &["start"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "stderr: {stderr}");
    assert!(stderr.contains("world-writable"), "stderr: {stderr}");
    assert!(
        read_lock_holder(&lock_path(home.path())).is_none(),
        "a daemon was spawned"
    );
    assert!(
        !home.path().join("state").exists(),
        "the log tree was created under the refused home"
    );
}

/// What sits at the daemon log path when `fuzd start` runs: a link to a file
/// outside the logs, a dangling link, or a directory.
#[derive(Debug, Clone, Copy)]
enum PlantedLog {
    LinkToVictim,
    DanglingLink,
    Directory,
}

/// A symlink or non-regular file at the daemon log path refuses `fuzd start`
/// (exit 1, naming the path) before anything is spawned, rotated, or written:
/// the link's target keeps its contents, a dangling link's target is not
/// created, and the planted entry is left where it was.
#[test]
fn fuzd_start_refuses_a_planted_log_symlink_or_non_regular_file() {
    for planted in [
        PlantedLog::LinkToVictim,
        PlantedLog::DanglingLink,
        PlantedLog::Directory,
    ] {
        let home = Home::new();
        let logs = home.path().join("state").join("logs");
        std::fs::create_dir_all(&logs).expect("create the logs dir");
        set_mode(&home.path().join("state"), 0o700);
        set_mode(&logs, 0o700);
        let log = logs.join("daemon_output.log");
        let victim = home.path().join("victim");
        let absent = home.path().join("absent");
        std::fs::write(&victim, b"precious").expect("write the victim");
        let (reason, is_link) = match planted {
            PlantedLog::LinkToVictim => {
                std::os::unix::fs::symlink(&victim, &log).expect("plant the link");
                ("file is a symlink", true)
            }
            PlantedLog::DanglingLink => {
                std::os::unix::fs::symlink(&absent, &log).expect("plant the link");
                ("file is a symlink", true)
            }
            PlantedLog::Directory => {
                std::fs::create_dir(&log).expect("plant the directory");
                ("not a regular file", false)
            }
        };

        let out = run_fuzd(home.path(), &["start"]);
        let stderr = String::from_utf8_lossy(&out.stderr);
        let context = format!("{planted:?}: {stderr}");
        assert_eq!(out.status.code(), Some(1), "{context}");
        assert!(
            stderr.contains(&format!(
                "error: cannot open log file: {reason}: {}",
                log.display()
            )),
            "{context}"
        );
        assert_eq!(
            std::fs::read(&victim).expect("read the victim"),
            b"precious",
            "{context}"
        );
        assert!(
            std::fs::symlink_metadata(&absent).is_err(),
            "{context}: the link's target was created"
        );
        let meta = std::fs::symlink_metadata(&log).expect("the planted entry");
        let kept = if is_link {
            meta.file_type().is_symlink()
        } else {
            meta.is_dir()
        };
        assert!(kept, "{context}: the planted entry was moved or replaced");
        assert!(
            !logs.join("daemon_output.log.1").exists(),
            "{context}: the planted entry was rotated"
        );
        assert!(
            read_lock_holder(&lock_path(home.path())).is_none(),
            "{context}: a daemon was spawned"
        );
    }
}

/// `SIGSTOP` the daemon `pid` — it keeps its socket and lock but answers
/// nothing, the hung daemon the lifecycle commands must tell from a gone one.
fn stop_process(pid: i32) {
    assert_eq!(
        send_signal(pid, Signal::SIGSTOP),
        Ok(true),
        "SIGSTOP pid {pid}"
    );
}

/// The error line every command prints for a recorded daemon that holds the
/// socket lock but does not answer.
fn not_answering_error(pid: i32, home: &Path) -> String {
    format!(
        "error: fuzd (pid {pid}) holds {} but does not answer this fuzd's health check",
        socket_path(home).display()
    )
}

/// A recorded daemon that stops answering — `SIGSTOP`ped, so it still holds
/// the socket lock — is `Unresponsive`, not stale: `stop` and `restart` refuse
/// it (exit 1) with a hint naming their `--force`, `start` refuses rather than
/// spawn a child that would only lose the lock, and `status` reports it not
/// answering (exit 1). None of them deletes its `daemon.json`, the only handle
/// `--force` has on it. `restart --force` kills it and starts a new daemon;
/// `stop --force` kills that one once it too stops answering, and clears its
/// record.
#[test]
fn an_unresponsive_recorded_daemon_is_refused_until_forced() {
    let home = Home::new();
    let lock = lock_path(home.path());

    let out = run_fuzd(home.path(), &["start"]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "start stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let pid = recorded_pid(home.path()).expect("start recorded its daemon");
    stop_process(pid);
    let error = not_answering_error(pid, home.path());

    for (command, hint) in [
        ("stop", "; re-run `fuzd stop --force` to kill it"),
        ("restart", "; re-run `fuzd restart --force` to kill it"),
        (
            "start",
            "; `fuzd restart --force` kills it and starts a new one",
        ),
    ] {
        let out = run_fuzd(home.path(), &[command]);
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(
            out.status.code(),
            Some(1),
            "{command}\nstdout: {stdout}\nstderr: {stderr}"
        );
        assert!(stderr.contains(&error), "{command} stderr: {stderr}");
        assert!(
            stderr.contains("hint: it may be hung, or a daemon of another protocol version"),
            "{command} stderr: {stderr}"
        );
        assert!(stderr.contains(hint), "{command} stderr: {stderr}");
        assert!(
            !stdout.contains("not running") && !stderr.contains("stale"),
            "{command} must not take it for gone\nstdout: {stdout}\nstderr: {stderr}"
        );
        assert_eq!(
            recorded_pid(home.path()),
            Some(pid),
            "{command} kept daemon.json"
        );
        assert_eq!(
            read_lock_holder(&lock).and_then(|p| i32::try_from(p).ok()),
            Some(pid),
            "{command} started nothing that took the lock"
        );
    }

    let out = run_fuzd(home.path(), &["status"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(1), "status stdout: {stdout}");
    assert_eq!(stdout.trim(), format!("not answering (pid {pid})"));
    let out = run_fuzd(home.path(), &["status", "--quiet"]);
    assert_eq!(out.status.code(), Some(1), "status --quiet");
    assert!(
        out.stdout.is_empty() && out.stderr.is_empty(),
        "status --quiet prints nothing"
    );
    let out = run_fuzd(home.path(), &["status", "--json"]);
    assert_eq!(out.status.code(), Some(1), "status --json");
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).expect("status json");
    assert_eq!(json["running"], false);
    assert_eq!(json["reason"], "not_answering");
    assert_eq!(json["pid"], pid);
    assert_eq!(
        recorded_pid(home.path()),
        Some(pid),
        "status kept daemon.json"
    );

    let out = run_fuzd(home.path(), &["restart", "--force"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(0),
        "restart --force\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stderr.contains("SIGTERM timeout, sending SIGKILL"),
        "a stopped daemon needs the SIGKILL: {stderr}"
    );
    assert!(stdout.contains("started at"), "restart --force: {stdout}");
    let new = recorded_pid(home.path()).expect("restart --force recorded its daemon");
    assert_ne!(new, pid, "a new daemon");
    assert_eq!(
        read_lock_holder(&lock).and_then(|p| i32::try_from(p).ok()),
        Some(new),
        "the new daemon holds the socket lock"
    );
    let out = run_fuzd(home.path(), &["status", "--quiet"]);
    assert_eq!(out.status.code(), Some(0), "the new daemon answers");

    stop_process(new);
    let out = run_fuzd(home.path(), &["stop", "--force"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stop --force\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert_eq!(stdout.trim(), "stopped");
    assert!(
        recorded_pid(home.path()).is_none(),
        "stop --force cleared the record"
    );
    let holder = read_lock_holder(&lock).and_then(|p| i32::try_from(p).ok());
    assert!(
        holder != Some(new) || !is_pid_alive(new),
        "stop --force returned before the daemon let go of the socket lock"
    );
}

/// Whether `pid` is a zombie — exited, not yet reaped — per `/proc/<pid>/stat`.
fn is_zombie(pid: u32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|stat| {
        // The state follows the parenthesized command name.
        stat.rsplit_once(") ")
            .is_some_and(|(_, rest)| rest.starts_with('Z'))
    })
}

/// `fuzd stop --force` on an unresponsive daemon goes straight to the kill,
/// and returns only once the daemon is gone. The daemon here is this test's
/// own child — a foreground `fuzd` recorded by hand — so it stays a zombie,
/// still a live fuzd to the CLI, until the test reaps it a while after the
/// kill: a stop that returned on the `SIGKILL` itself, without waiting for the
/// lock to be let go, would leave the pid behind. While it waits, the record is
/// replaced by one naming another daemon — one started meanwhile — which the
/// stop leaves alone.
#[test]
fn fuzd_stop_force_kills_an_unresponsive_daemon_and_waits_for_its_exit() {
    let home = Home::new();
    let foreground = start_foreground(home.path());
    let child_pid = foreground.child.id();
    let pid = i32::try_from(child_pid).expect("pid fits i32");
    let record = home.path().join("run").join("daemon.json");
    std::fs::write(
        &record,
        format!(
            r#"{{"version":2,"pid":{pid},"socket_path":{}}}"#,
            serde_json::to_string(&socket_path(home.path())).expect("encode path")
        ),
    )
    .expect("record the daemon");
    set_mode(&record, 0o600);
    stop_process(pid);

    // The pid the replacement record names: this test process, so the home
    // guard, which kills only processes running on the home, leaves it be.
    let other = std::process::id();
    let replacement = format!(
        r#"{{"version":2,"pid":{other},"socket_path":{}}}"#,
        serde_json::to_string(&socket_path(home.path())).expect("encode path")
    );

    // Once the killed daemon turns zombie, replace the record, then reap the
    // daemon a second later, so the stop below can be seen waiting for it; the
    // guard reaps on drop.
    let reaper = std::thread::spawn(move || {
        let deadline = Instant::now() + RUN_TIMEOUT;
        while !is_zombie(child_pid) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        std::fs::write(&record, replacement).expect("replace the record");
        std::thread::sleep(Duration::from_secs(1));
        drop(foreground);
    });

    let out = run_fuzd(home.path(), &["stop", "--force"]);
    let gone = !is_pid_alive(pid);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stderr.contains("not answering, force killing..."),
        "stderr: {stderr}"
    );
    assert!(
        stderr.contains("SIGTERM timeout, sending SIGKILL"),
        "stderr: {stderr}"
    );
    assert_eq!(stdout.trim(), "stopped");
    assert!(
        gone,
        "stop --force returned while the killed daemon (pid {pid}) was still there"
    );
    reaper.join().expect("reaper thread");
    assert_eq!(
        recorded_pid(home.path()),
        i32::try_from(other).ok(),
        "stop --force removed a record naming another daemon"
    );
}

/// The version-skew guard, end to end: a daemon.json this fuzd can't read —
/// here an older schema's — that names a live fuzd makes `fuzd start` refuse
/// (exit 1) with the declared schema version and the pid in the error and
/// `kill <pid>` in the hint; it spawns nothing and keeps the file, the only
/// record of where that daemon is. The live fuzd is a stand-in: `/bin/sleep`
/// run through a symlink named `fuzd`, which gives it fuzd's command name.
#[test]
fn fuzd_start_refuses_beside_a_live_fuzd_daemon_json_it_cannot_read() {
    let home = Home::new();
    let run = home.path().join("run");
    std::fs::create_dir(&run).expect("create run dir");
    set_mode(&run, 0o700);
    let record = run.join("daemon.json");
    let stand_in_dir = tempfile::tempdir().expect("tempdir");
    let stand_in = stand_in_dir.path().join("fuzd");
    std::os::unix::fs::symlink("/bin/sleep", &stand_in).expect("symlink");
    let stand_in = Foreground {
        child: Command::new(&stand_in)
            .arg("30")
            .stdin(Stdio::null())
            .spawn()
            .expect("spawn the stand-in fuzd"),
    };
    let pid = stand_in.child.id();
    let body = format!(r#"{{"version":1,"pid":{pid},"port":1174}}"#);
    std::fs::write(&record, &body).expect("write the record");
    set_mode(&record, 0o600);

    let out = run_fuzd(home.path(), &["start"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(1),
        "stdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stderr.contains(&format!(
            "error: daemon.json (schema version 1) is not one this fuzd can read, and the fuzd it names (pid {pid}) is still running"
        )),
        "stderr: {stderr}"
    );
    assert!(
        stderr.contains(&format!("stop it (`kill {pid}`), then re-run `fuzd start`")),
        "stderr: {stderr}"
    );
    assert_eq!(
        std::fs::read_to_string(&record).expect("the record survives"),
        body,
        "the live fuzd's record is kept"
    );
    assert!(
        !socket_path(home.path()).exists() && read_lock_holder(&lock_path(home.path())).is_none(),
        "nothing spawned"
    );
    drop(stand_in);
}
