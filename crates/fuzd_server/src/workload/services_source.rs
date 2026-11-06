//! Services-domain acquisition — user-scoped systemd unit states.
//!
//! One `systemctl --user show '*.service' --property=…` subprocess yields all
//! properties incl. `MainPID` (the unit→pid cross-link `list-units` omits);
//! systemctl globs unit patterns itself, so no shell is needed. `unsafe_code`
//! is forbidden, ruling out the sd-journal / D-Bus C APIs, so a `systemctl`
//! subprocess is the no-new-dep path. An absent or failing `systemctl` (no user
//! bus, headless CI) degrades to an empty unit set — the daemon stays useful
//! without systemd. A `systemctl` that hangs (a wedged user bus) is killed at
//! [`SYSTEMCTL_SHOW_TIMEOUT`] and the sample errors, so the collector skips the
//! tick instead of reporting every unit gone. The journald tail is deferred to
//! a later slice.

use std::io::Read;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use fuz_wire::UnitActiveState;

use super::observer::SERVICES_SAMPLE_INTERVAL;
use super::source::ObserverError;

/// The unit properties requested from `systemctl show` (one block per unit).
const SHOW_PROPERTIES: &str = "--property=Id,LoadState,ActiveState,SubState,Description,MainPID";

/// How long one `systemctl show` may run before it is killed and reaped.
///
/// A healthy call takes well under 100ms. The deadline sits below the services
/// domain's sample interval (`SERVICES_SAMPLE_INTERVAL`, 3s), so a hung
/// `systemctl` costs the collector one skipped tick rather than holding its
/// loop — and the blocking-pool thread the sample runs on — for as long as the
/// subprocess hangs.
pub const SYSTEMCTL_SHOW_TIMEOUT: Duration = Duration::from_secs(2);

const _: () = assert!(
    SYSTEMCTL_SHOW_TIMEOUT.as_millis() < SERVICES_SAMPLE_INTERVAL.as_millis(),
    "the systemctl deadline must expire before the next services tick"
);

/// How often [`run_with_deadline`] checks whether its child has exited.
const CHILD_POLL_INTERVAL: Duration = Duration::from_millis(10);

/// Raw per-unit record for one sample.
#[derive(Debug, Clone)]
pub struct RawUnit {
    pub name: String,
    pub load_state: String,
    pub active_state: UnitActiveState,
    pub sub_state: String,
    pub description: String,
    pub main_pid: Option<i32>,
}

/// One raw sample of the services domain.
#[derive(Debug, Clone)]
pub struct RawServicesSample {
    pub units: Vec<RawUnit>,
}

/// Sample the services domain (user scope).
///
/// # Errors
///
/// Returns [`ObserverError::CommandTimeout`] when `systemctl` outlives
/// [`SYSTEMCTL_SHOW_TIMEOUT`] (it is killed and reaped first). An absent or
/// failing `systemctl` is not an error — it degrades to an empty unit set.
pub fn sample_services() -> Result<RawServicesSample, ObserverError> {
    let units = run_systemctl_show()?
        .map(|out| parse_show(&out))
        .unwrap_or_default();
    Ok(RawServicesSample { units })
}

/// Run the single `systemctl show` invocation under [`SYSTEMCTL_SHOW_TIMEOUT`].
/// `Ok(None)` when systemctl is absent or exits non-zero (no user bus, not
/// installed) — the caller degrades to an empty unit set.
fn run_systemctl_show() -> Result<Option<String>, ObserverError> {
    let mut cmd = Command::new("systemctl");
    cmd.args(["--user", "show", "*.service", SHOW_PROPERTIES, "--no-pager"]);
    let stdout = run_with_deadline("systemctl show", &mut cmd, SYSTEMCTL_SHOW_TIMEOUT)?;
    Ok(stdout.and_then(|out| String::from_utf8(out).ok()))
}

/// Run `cmd` to completion and return its stdout, killing it if it is still
/// running `timeout` after the spawn.
///
/// `Ok(Some(stdout))` on a successful exit; `Ok(None)` when it can't be spawned
/// or exits non-zero; [`ObserverError::CommandTimeout`] when the deadline
/// passes first — the child is `SIGKILL`ed and reaped before this returns, so a
/// hung run leaves neither a process nor a zombie. Stdin and stderr are null.
///
/// Stdout drains on its own thread, so a child blocked on a full pipe is never
/// mistaken for a hung one. The deadline also bounds that drain: a grandchild
/// that inherited the pipe and outlives the child is a timeout too, and the
/// drain thread is left to finish when the pipe closes. Only the reap of a
/// killed child is unbounded (a process in uninterruptible sleep can't die) —
/// the daemon's runtime shutdown bounds that, as it does the `/proc` reads.
fn run_with_deadline(
    command: &'static str,
    cmd: &mut Command,
    timeout: Duration,
) -> Result<Option<Vec<u8>>, ObserverError> {
    let started = Instant::now();
    let Ok(mut child) = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    else {
        return Ok(None);
    };
    let Some(stdout_rx) = child.stdout.take().and_then(spawn_drain) else {
        kill_and_reap(&mut child);
        return Ok(None);
    };
    let timed_out = || ObserverError::CommandTimeout { command, timeout };
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                let remaining = timeout.saturating_sub(started.elapsed());
                if remaining.is_zero() {
                    kill_and_reap(&mut child);
                    return Err(timed_out());
                }
                std::thread::sleep(remaining.min(CHILD_POLL_INTERVAL));
            }
            Err(_) => {
                kill_and_reap(&mut child);
                return Ok(None);
            }
        }
    };
    if !status.success() {
        return Ok(None);
    }
    match stdout_rx.recv_timeout(timeout.saturating_sub(started.elapsed())) {
        Ok(Ok(stdout)) => Ok(Some(stdout)),
        Ok(Err(_)) | Err(mpsc::RecvTimeoutError::Disconnected) => Ok(None),
        Err(mpsc::RecvTimeoutError::Timeout) => Err(timed_out()),
    }
}

/// Read `pipe` to EOF on a thread of its own; the result arrives on the
/// returned channel. `None` when the thread can't be spawned.
fn spawn_drain<R: Read + Send + 'static>(
    mut pipe: R,
) -> Option<mpsc::Receiver<std::io::Result<Vec<u8>>>> {
    let (tx, rx) = mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("fuzd-cmd-stdout".into())
        .spawn(move || {
            let mut buf = Vec::new();
            let read = pipe.read_to_end(&mut buf).map(|_| buf);
            let _ = tx.send(read);
        })
        .ok()?;
    Some(rx)
}

/// `SIGKILL` the child and wait for it, so no zombie outlives the call. Errors
/// are ignored: a kill that fails because the child already exited still
/// leaves it to the wait.
fn kill_and_reap(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

/// Parse `systemctl show`'s blank-line-separated `Key=Value` blocks into units.
fn parse_show(output: &str) -> Vec<RawUnit> {
    output.split("\n\n").filter_map(parse_block).collect()
}

/// Parse one property block. `None` when it carries no `Id` (the trailing blank
/// region). Property order isn't guaranteed, so each key is matched explicitly;
/// values may contain `=`, so only the first `=` splits.
fn parse_block(block: &str) -> Option<RawUnit> {
    let mut name = None;
    let mut load_state = String::new();
    let mut active_state = UnitActiveState::Unknown;
    let mut sub_state = String::new();
    let mut description = String::new();
    let mut main_pid = None;
    for line in block.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        match key {
            "Id" => name = Some(value.to_string()),
            "LoadState" => load_state = value.to_string(),
            "ActiveState" => active_state = UnitActiveState::from_systemd(value),
            "SubState" => sub_state = value.to_string(),
            "Description" => description = value.to_string(),
            // MainPID is 0 for units with no live main process.
            "MainPID" => main_pid = value.parse::<i32>().ok().filter(|&p| p > 0),
            _ => {}
        }
    }
    Some(RawUnit {
        name: name?,
        load_state,
        active_state,
        sub_state,
        description,
        main_pid,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real two-block `systemctl --user show '*.service'` excerpt, with the
    /// property order varying between blocks (`MainPID` first vs. last) and a
    /// dead unit (`MainPID=0`).
    const SHOW_FIXTURE: &str = "\
MainPID=2078
Id=filter-chain.service
Description=PipeWire filter chain daemon
LoadState=loaded
ActiveState=active
SubState=running

Id=dirmngr.service
LoadState=loaded
ActiveState=inactive
SubState=dead
Description=GnuPG network certificate management daemon
MainPID=0
";

    #[test]
    fn parses_blocks_in_any_property_order() {
        let units = parse_show(SHOW_FIXTURE);
        assert_eq!(units.len(), 2);

        let active = &units[0];
        assert_eq!(active.name, "filter-chain.service");
        assert_eq!(active.active_state, UnitActiveState::Active);
        assert_eq!(active.sub_state, "running");
        assert_eq!(
            active.main_pid,
            Some(2078),
            "MainPID-first block resolves the pid"
        );

        let dead = &units[1];
        assert_eq!(dead.name, "dirmngr.service");
        assert_eq!(dead.active_state, UnitActiveState::Inactive);
        assert!(dead.main_pid.is_none(), "MainPID=0 → no live main process");
    }

    #[test]
    fn description_with_equals_keeps_full_value() {
        let block = "Id=x.service\nDescription=A=B test\nActiveState=active\nSubState=running\nLoadState=loaded\nMainPID=1";
        let unit = parse_block(block).expect("parse");
        assert_eq!(unit.description, "A=B test", "only the first = splits");
    }

    #[test]
    fn block_without_id_is_skipped() {
        // The trailing blank block / a manager block has no Id.
        assert!(parse_block("Version=255\n").is_none());
        assert!(parse_block("").is_none());
    }

    #[test]
    fn active_state_maps_the_closed_set() {
        assert_eq!(
            UnitActiveState::from_systemd("active"),
            UnitActiveState::Active
        );
        assert_eq!(
            UnitActiveState::from_systemd("failed"),
            UnitActiveState::Failed
        );
        assert_eq!(
            UnitActiveState::from_systemd("activating"),
            UnitActiveState::Activating
        );
        assert_eq!(
            UnitActiveState::from_systemd("nonsense"),
            UnitActiveState::Unknown
        );
    }

    #[test]
    fn sample_services_succeeds_with_or_without_systemd() {
        // Whether or not systemd is reachable in the test env, sampling
        // succeeds (degrading to an empty set when systemctl is absent). A
        // loaded host can push a present systemctl past its deadline, and the
        // timeout is a typed outcome, not a failure of this contract — only
        // any other error fails.
        match sample_services() {
            // no content assertion — CI may have no user bus
            Ok(_) | Err(ObserverError::CommandTimeout { .. }) => {}
            Err(other) => panic!("sampling failed with a non-timeout error: {other}"),
        }
    }

    fn sh(script: &str) -> Command {
        let mut cmd = Command::new("sh");
        cmd.args(["-c", script]);
        cmd
    }

    #[test]
    fn run_with_deadline_returns_stdout_of_a_successful_exit() {
        let out = run_with_deadline(
            "sh",
            &mut sh("printf 'Id=x.service'"),
            SYSTEMCTL_SHOW_TIMEOUT,
        )
        .expect("no timeout");
        assert_eq!(out.as_deref(), Some(&b"Id=x.service"[..]));
    }

    #[test]
    fn run_with_deadline_drains_output_larger_than_a_pipe_buffer() {
        // 1 MiB overflows the 64 KiB pipe: without the concurrent drain the
        // child blocks on write and reads as hung.
        let out = run_with_deadline(
            "sh",
            &mut sh("head -c 1048576 /dev/zero"),
            SYSTEMCTL_SHOW_TIMEOUT,
        )
        .expect("no timeout")
        .expect("successful exit");
        assert_eq!(out.len(), 1_048_576);
    }

    #[test]
    fn run_with_deadline_degrades_a_failed_or_absent_command() {
        let failed = run_with_deadline("sh", &mut sh("exit 3"), SYSTEMCTL_SHOW_TIMEOUT);
        assert!(matches!(failed, Ok(None)), "non-zero exit: {failed:?}");
        let mut absent = Command::new("/nonexistent/fuzd-test-systemctl");
        let absent = run_with_deadline("absent", &mut absent, SYSTEMCTL_SHOW_TIMEOUT);
        assert!(matches!(absent, Ok(None)), "spawn failure: {absent:?}");
    }

    /// A hung command (a stand-in for a `systemctl` on a wedged user bus) is
    /// killed at the deadline and reaped: the call errors promptly, and the
    /// child's pid is gone from `/proc` — not left running, not a zombie.
    #[test]
    fn run_with_deadline_kills_and_reaps_a_command_past_its_deadline() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pid_file = dir.path().join("pid");
        // `exec` keeps the pid: the shell that records `$$` becomes the sleep.
        let script = format!("echo $$ > '{}'; exec sleep 30", pid_file.display());
        let deadline = Duration::from_millis(300);

        let started = Instant::now();
        let result = run_with_deadline("fake systemctl", &mut sh(&script), deadline);
        let elapsed = started.elapsed();

        assert!(
            matches!(
                result,
                Err(ObserverError::CommandTimeout {
                    command: "fake systemctl",
                    ..
                })
            ),
            "a command past its deadline is a timeout: {result:?}"
        );
        assert!(
            elapsed >= deadline,
            "returned before the deadline: {elapsed:?}"
        );
        assert!(
            elapsed < deadline + Duration::from_secs(2),
            "the deadline bounds the call: {elapsed:?}"
        );
        let pid = std::fs::read_to_string(&pid_file).expect("the child recorded its pid");
        let proc_dir = std::path::Path::new("/proc").join(pid.trim());
        assert!(
            !proc_dir.exists(),
            "the timed-out child must be killed and reaped, found {}: {:?}",
            proc_dir.display(),
            std::fs::read_to_string(proc_dir.join("stat")),
        );
    }
}
