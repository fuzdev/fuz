//! Interrupt honesty — drain fuzi's staging trees on SIGINT / SIGTERM / SIGHUP.
//!
//! Without a handler, Ctrl-C during an install ends the process with the
//! `.fuzi-installing-<rand>` tree still on disk: signals do not unwind, so no
//! `Drop` guard runs. [`drain_staging_on_signal`] installs a listener that
//! removes whatever `fuzi_core` still has registered
//! ([`fuzi_core::drain_staging_roots`]) and then exits `128 + signum` — 130 for
//! SIGINT, 143 for SIGTERM, 129 for SIGHUP (a closed terminal or a dropped ssh
//! session, the third ordinary way an interactive install ends).
//!
//! **A deliberate arm: an exit, not a death by signal.** `128 + signum` is the
//! number a shell reports for a signal-killed child, so `$?` and an agent
//! reading the status see what they would for the default disposition. A parent
//! that inspects *how* the child ended does not: the wait status says "exited
//! 130", not "killed by SIGINT" (`WIFSIGNALED` is false — Python's `returncode`
//! is `130`, not `-2`). The visible cost is bash's cooperative-exit rule: a
//! script loop running `fuzi install` keeps going after Ctrl-C, because bash
//! reads a child that *exited* on SIGINT as one that handled it — check the
//! status (`fuzi install || exit`). Being indistinguishable would take
//! restoring the default disposition and re-raising the signal after the drain,
//! and restoring a disposition (`sigaction` / `signal`) is `unsafe`, which the
//! workspace forbids. The drain is worth more than the wait-status detail.
//!
//! **The signal task owns the outcome.** Once a drain fires, the install
//! thread renders nothing and exits with nothing: it parks
//! ([`yield_to_drain`]) and the drain's `128 + signum` is the run's status.
//! An interrupted run's stdout is therefore not a document — empty, or cut
//! wherever a late signal found the install thread writing.
//!
//! **An inherited ignore is honored.** A signal the process started with
//! ignored — SIGHUP under `nohup`, SIGINT for a non-interactive shell's `&`
//! job — is left ignored rather than captured: installing a handler would
//! override the parent's choice, turning a `nohup fuzi install` into one a
//! closed terminal ends. The ignored set is read from `/proc/self/status`;
//! where it can't be read — off Linux, so only Linux drains SIGHUP — SIGHUP is
//! left alone (`nohup` is the common reason to inherit it ignored) and SIGINT /
//! SIGTERM are drained.
//!
//! **Why tokio rather than a raw handler.** `remove_dir_all` is not
//! async-signal-safe and the workspace forbids `unsafe_code`, so the cleanup
//! cannot live inside the handler itself. `tokio::signal` gives exactly the
//! shape needed: the real handler only writes to a self-pipe, and the removal
//! runs on an ordinary thread that a normal `.await` woke up.
//!
//! **Why a dedicated thread rather than an async `main`.** `fuzi_core::install`
//! is synchronous and owns a `tokio` runtime for the fetch phase alone
//! (`block_on`), so an async `main` would make that a runtime-inside-a-runtime
//! panic. A current-thread runtime parked on its own thread also outlives the
//! fetch island — the drain has to cover materialization, which is where the
//! staging tree spends most of its life.
//!
//! This closes the *signal* leak only. A release-build panic aborts without
//! unwinding, and SIGKILL / power loss run nothing at all: `fuzi clean` remains
//! the backstop.

use std::io::Write as _;
use std::process;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use fuzi_core::DrainReport;
use tokio::runtime::{Builder, Runtime};
use tokio::signal::unix::{Signal, SignalKind, signal};

/// What the calling thread hands the listener thread: the runtime to drive and
/// the signal streams already registered on it.
type Listener = (Runtime, Streams);

/// The drained signals' streams, each `None` when the OS refused it.
struct Streams {
    interrupt: Option<Signal>,
    terminate: Option<Signal>,
    hangup: Option<Signal>,
}

impl Streams {
    /// Whether no signal registered at all — then nothing is captured.
    const fn is_empty(&self) -> bool {
        self.interrupt.is_none() && self.terminate.is_none() && self.hangup.is_none()
    }
}

/// Exit-status offset for a signal-ended process (`128 + signum`) — the shell
/// numbering: 130 for SIGINT, 143 for SIGTERM, 129 for SIGHUP.
const SIGNAL_EXIT_BASE: i32 = 128;

/// Start the background listener that removes fuzi's live staging trees on the
/// first SIGINT, SIGTERM, or SIGHUP, then exits `128 + signum`.
///
/// Call once, before any staging tree can exist — and that is a fact about the
/// *call*, not a promise about scheduling: every handler is installed on the
/// calling thread before this returns, so an install that starts staging on the
/// next line is covered even if the listener thread has not been scheduled yet.
/// Only the awaiting moves to the thread.
///
/// Best effort by construction: if the runtime cannot be built, no signal
/// can be registered, or the OS refuses the thread, fuzi keeps the default
/// disposition (and the leak) rather than failing the install. What it must
/// never do is capture a signal and then stop reading it — `tokio::signal`
/// installs a process-wide handler that is not restored when its listener goes
/// away, so that would silently make fuzi unkillable by Ctrl-C. Hence: every
/// signal that registers is awaited, the listener gives up only when nothing
/// registered at all, and nothing registers until the awaiting thread exists —
/// the thread is spawned *first* and the registration handed to it.
///
/// After the first signal fires, further ones are swallowed while the drain
/// runs, and then the process is gone. `fuzi_core`'s **per-root** drain deadline
/// (one live tree per install, so one deadline) bounds most of that window, but
/// not all of it: the deadline covers the removals, and the drain takes the
/// staging registry's lock first — which an in-flight `commit` holds across its
/// renames, and an in-flight staging-root creation across its `mkdir`. So a
/// second Ctrl-C waits out that syscall and only then starts the bounded part,
/// which on a slow filesystem (NFS, fuse) is as long as a `rename(2)` or
/// `mkdir(2)` there takes.
pub fn drain_staging_on_signal() {
    // Building the runtime installs nothing; it is safe to give up on.
    let Ok(runtime) = Builder::new_current_thread().enable_all().build() else {
        return;
    };

    // Spawn *before* registering anything, and hand the registration over a
    // channel. Registering first would mean that a refused thread left signals
    // captured with nobody awaiting them — and tokio never restores a signal's
    // default disposition — so fuzi would ignore Ctrl-C outright, which is worse
    // than the leak this module exists to fix. `thread::Builder`, not
    // `thread::spawn`: the latter *panics* when the OS refuses a thread, and
    // this must never fail an install.
    let (tx, rx) = mpsc::channel::<Listener>();
    if thread::Builder::new()
        .name("fuzi-signal".to_owned())
        .spawn(move || {
            // `Err` means the sender was dropped: nothing registered, so there
            // is nothing to await.
            let Ok((runtime, mut streams)) = rx.recv() else {
                return;
            };
            runtime.block_on(async {
                let kind = tokio::select! {
                    () = first_signal(&mut streams.interrupt) => SignalKind::interrupt(),
                    () = first_signal(&mut streams.terminate) => SignalKind::terminate(),
                    () = first_signal(&mut streams.hangup) => SignalKind::hangup(),
                };

                report_drain(&fuzi_core::drain_staging_roots());
                process::exit(SIGNAL_EXIT_BASE + kind.as_raw_value());
            });
        })
        .is_err()
    {
        return;
    }

    // Register on the *calling* thread, inside the runtime context `signal()`
    // requires. Registration is what installs the process-wide handler, so doing
    // it here rather than on the spawned thread is what makes "call once, before
    // any staging tree can exist" a fact about the call instead of a race with
    // the scheduler. A signal delivered before the listener thread gets going is
    // not lost: the handler has already written to tokio's self-pipe, and the
    // stream yields it as soon as the runtime runs. All are registered before
    // any is awaited, so the process never has one signal captured and another
    // still defaulting.
    let ignored = inherited_ignored_mask();
    let streams = {
        let _enter = runtime.enter();
        let register = |kind: SignalKind| {
            should_capture(kind, ignored)
                .then(|| signal(kind).ok())
                .flatten()
        };
        Streams {
            interrupt: register(SignalKind::interrupt()),
            terminate: register(SignalKind::terminate()),
            hangup: register(SignalKind::hangup()),
        }
    };
    if streams.is_empty() {
        // Nothing captured — the default disposition still applies. Dropping
        // `tx` retires the listener thread.
        return;
    }
    // Unreachable failure: `send` only errors once the receiver is gone, and the
    // listener thread drops it by leaving `rx.recv()` — which cannot resolve
    // while this `tx` is alive — or by `process::exit`, which ends everything.
    let _ = tx.send((runtime, streams));
}

/// How long [`yield_to_drain`] waits for the signal task's exit once a drain
/// has finished — its stderr line and `process::exit` are all that is left.
/// Generous next to that, because it only ever elapses when something is
/// wrong (a stderr nobody reads, blocking the drain's report).
const YIELD_TO_DRAIN_BOUND: Duration = Duration::from_secs(5);

/// Leave the run's outcome to the signal task if a drain has fired: park until
/// its `process::exit(128 + signum)` ends the process, rendering nothing.
///
/// Called before the install thread renders a success or an error, and once
/// more before `main` returns its exit code. After a drain, what the install
/// thread holds is the drain's doing (a refused publish, a tree removed under
/// the extractor), and both rendering it and exiting with its code would race
/// the drain's own exit — a cut `--json` document, a second error line, or a
/// complete document whose `exit_code` contradicts the process's 130. So the
/// signal task owns stdout, stderr, and the status: an interrupted run's status
/// is `128 + signum`; its stdout is empty or whatever was written before the
/// signal — not a document. A signal that lands after the last check (the
/// install thread already writing) can still cut that write; nothing here can
/// close that window without making the drain wait on the install thread's
/// output, and a reader that stopped reading would then make Ctrl-C hang.
///
/// [`fuzi_core::drain_fired`] waits out an in-progress drain, so the park only
/// covers the report and the exit. It is bounded all the same: past
/// [`YIELD_TO_DRAIN_BOUND`] the install thread goes on as if no signal had
/// arrived, so a wedged signal task never hangs fuzi.
/// Each call parks at most this long; a run whose error-path park already
/// timed out parks once more before `main` returns.
pub fn yield_to_drain() {
    if !fuzi_core::drain_fired() {
        return;
    }
    let deadline = Instant::now() + YIELD_TO_DRAIN_BOUND;
    // A loop, because `park_timeout` may return early (spuriously).
    loop {
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        thread::park_timeout(deadline - now);
    }
}

/// The set of signals this process inherited as ignored — the `SigIgn` mask of
/// `/proc/self/status` (bit `n - 1` for signal `n`) — or `None` where it can't
/// be read.
fn inherited_ignored_mask() -> Option<u64> {
    parse_sig_ign(&std::fs::read_to_string("/proc/self/status").ok()?)
}

/// The `SigIgn:` hex mask from `/proc/<pid>/status` text.
fn parse_sig_ign(status: &str) -> Option<u64> {
    let hex = status
        .lines()
        .find_map(|line| line.strip_prefix("SigIgn:"))?;
    u64::from_str_radix(hex.trim(), 16).ok()
}

/// Whether to capture `kind`: never one the process inherited as ignored;
/// with the mask unknown, every drained signal but SIGHUP.
fn should_capture(kind: SignalKind, ignored: Option<u64>) -> bool {
    let signum = kind.as_raw_value();
    ignored.map_or_else(
        || signum != SignalKind::hangup().as_raw_value(),
        |mask| (1..=64).contains(&signum) && mask & (1 << (signum - 1)) == 0,
    )
}

/// Say on stderr what the interrupt cost, in the two cases worth a line: a tree
/// removed (so the user knows the interrupt was clean) and a tree that survived
/// (so they know to run `fuzi clean`).
///
/// Silence means the drain had nothing to report — nothing had been staged
/// yet (an interrupt during planning or fetching), the swap had already
/// published and deregistered, or a claimed root was already gone when the
/// drain reached it (another cleanup got there first — neither "removed" nor
/// work left for `fuzi clean`). The published case can still leave a `.fuzi-old-*`
/// tree behind, which the drain does not track and this does not report: the
/// registry covers staging roots, and `fuzi clean` covers the rest.
///
/// `writeln!` with the result discarded, not `eprintln!`: `eprintln!` panics on
/// a failed stderr write, and an `EPIPE` from a reader that went away
/// (`fuzi install 2>&1 | head`) — or an `EIO` from the terminal a SIGHUP just
/// closed — is an ordinary way for that to happen. A panic
/// *here* costs more than the line it was printing — this runs on the listener
/// thread, upstream of the `process::exit` that is the only thing turning the
/// signal into an exit status, so a debug build would unwind the listener away
/// and leave the drained signals captured with nobody awaiting them: exactly the
/// unkillable state this module's docs forbid.
fn report_drain(drained: &DrainReport) {
    let mut stderr = std::io::stderr();
    if !drained.removed.is_empty() {
        let _ = writeln!(
            stderr,
            "fuzi: interrupted — removed {} staging tree(s)",
            drained.removed.len()
        );
    }
    if !drained.remaining.is_empty() {
        let _ = writeln!(
            stderr,
            "fuzi: interrupted — {} staging tree(s) could not be removed; run `fuzi clean`",
            drained.remaining.len()
        );
    }
}

/// Await the first delivery of an installed signal, or never return when that
/// signal could not be installed.
///
/// The pending arm keeps a partial registration usable: one unavailable signal
/// disables its own branch of the `select!` instead of the whole listener.
async fn first_signal(stream: &mut Option<Signal>) {
    match stream {
        Some(stream) => {
            if stream.recv().await.is_none() {
                // `None` means the stream was closed, which cannot happen while
                // the listener owns it — but it must not read as a delivery
                // either: returning here would drain and exit 130 with no signal
                // in sight. Never resolving is the honest answer.
                std::future::pending::<()>().await;
            }
        }
        None => std::future::pending().await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exit statuses the drain reports are the shell's signal numbering —
    /// 130 for SIGINT, 143 for SIGTERM, 129 for SIGHUP — so `$?` reads an
    /// interrupted fuzi as it reads an interrupted anything else (the wait
    /// status still says "exited", see the module docs). Delivering a real
    /// signal would end the test process, so the arithmetic is what is pinned.
    #[test]
    fn signal_exit_codes_follow_the_128_plus_signum_convention() {
        assert_eq!(
            SIGNAL_EXIT_BASE + SignalKind::interrupt().as_raw_value(),
            130
        );
        assert_eq!(
            SIGNAL_EXIT_BASE + SignalKind::terminate().as_raw_value(),
            143
        );
        assert_eq!(SIGNAL_EXIT_BASE + SignalKind::hangup().as_raw_value(), 129);
    }

    #[test]
    fn an_inherited_ignore_is_never_captured() {
        // `nohup` hands fuzi SIGHUP ignored (bit 0); capturing it would let a
        // closed terminal end a `nohup fuzi install`.
        let status = "Name:\tfuzi\nSigBlk:\t0000000000000000\nSigIgn:\t0000000000000001\nSigCgt:\t0000000000000000\n";
        let mask = parse_sig_ign(status);
        assert_eq!(mask, Some(1));
        assert!(!should_capture(SignalKind::hangup(), mask));
        assert!(should_capture(SignalKind::interrupt(), mask));
        assert!(should_capture(SignalKind::terminate(), mask));
        // SIGINT ignored (bit 1) — a non-interactive shell's `&` job.
        assert!(!should_capture(SignalKind::interrupt(), Some(0b10)));
    }

    #[test]
    fn an_unknown_ignore_set_leaves_sighup_alone() {
        assert_eq!(parse_sig_ign("Name:\tfuzi\n"), None);
        assert!(!should_capture(SignalKind::hangup(), None));
        assert!(should_capture(SignalKind::interrupt(), None));
        assert!(should_capture(SignalKind::terminate(), None));
    }

    #[test]
    fn this_process_reads_its_own_ignore_set() {
        // The test harness reads `/proc` like any Linux process.
        assert!(inherited_ignored_mask().is_some());
    }
}
