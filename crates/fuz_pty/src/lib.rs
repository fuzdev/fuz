//! A safe PTY API (the [`Pty`] struct) over the libc PTY calls.
//!
//! Linux-only, kernel ≥ 4.13 (`TIOCGPTPEER`, `execvpe`, `pipe2`). The one
//! workspace crate allowed `unsafe`: its manifest sets `unsafe_code` to
//! `deny`, each item that needs `unsafe` lifts it with its own
//! `#[expect(unsafe_code, reason = "…")]` (no crate-wide lift), and every
//! `unsafe` block carries a `// SAFETY:` comment
//! (`clippy::undocumented_unsafe_blocks`).

use std::ffi::{CString, OsStr, OsString};
use std::os::unix::ffi::OsStrExt;
use std::ptr;

// == Internals ================================================================

/// The `TERM` every PTY child gets — it matches the xterm.js frontend that
/// renders the PTY output, so forcing it is correct regardless of the host's
/// own `TERM` or an explicit env that sets one.
const TERM_ENTRY: &std::ffi::CStr = c"TERM=xterm-256color";

/// Child-failure stage tags written to the spawn error pipe.
const STAGE_SETUP: i32 = 1;
const STAGE_CHDIR: i32 = 2;
const STAGE_EXEC: i32 = 3;

/// Build one `KEY=value` entry for the child's `envp`.
///
/// Returns `Ok(None)` for a `TERM` entry (the forced `TERM_ENTRY` replaces
/// it).
fn env_entry(key: &OsStr, value: &OsStr) -> Result<Option<CString>, PtyError> {
    let key_bytes = key.as_bytes();
    if key_bytes.is_empty() || key_bytes.contains(&b'=') {
        return Err(PtyError::InvalidEnv);
    }
    if key_bytes == b"TERM" {
        return Ok(None);
    }
    let value_bytes = value.as_bytes();
    let mut entry = Vec::with_capacity(key_bytes.len() + 1 + value_bytes.len());
    entry.extend_from_slice(key_bytes);
    entry.push(b'=');
    entry.extend_from_slice(value_bytes);
    CString::new(entry).map(Some).map_err(|_| PtyError::NulByte)
}

/// Build the child's full environment, always ending with `TERM_ENTRY`.
///
/// `None` snapshots this process's environment (entries that can't be
/// represented are skipped); `Some` uses exactly the given variables and
/// rejects an invalid one. Built in the parent so the post-fork child does no
/// allocation and never touches `environ` (fork-safety).
fn build_envp(env: Option<&[(OsString, OsString)]>) -> Result<Vec<CString>, PtyError> {
    let mut entries = Vec::new();
    match env {
        Some(vars) => {
            for (key, value) in vars {
                entries.extend(env_entry(key, value)?);
            }
        }
        None => {
            for (key, value) in std::env::vars_os() {
                if let Ok(Some(entry)) = env_entry(&key, &value) {
                    entries.push(entry);
                }
            }
        }
    }
    entries.push(TERM_ENTRY.to_owned());
    Ok(entries)
}

/// Null-terminated pointer array over `strings` for `argv` / `envp`.
fn to_ptr_array(strings: &[CString]) -> Vec<*const libc::c_char> {
    strings
        .iter()
        .map(|c| c.as_ptr())
        .chain(std::iter::once(ptr::null()))
        .collect()
}

/// The calling thread's `errno`. Async-signal-safe (a thread-local read, no
/// allocation), so the post-fork child can use it.
fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// Report a post-fork child failure to the parent over the error pipe, then
/// `_exit`.
///
/// Async-signal-safe: reads `errno`, builds a fixed 8-byte message on the
/// stack, and calls only `write` + `_exit`.
///
/// # Safety
///
/// The caller must be the child `spawn_raw` forked, before it execs: the
/// function ends the process with `_exit(127)`, skipping destructors and
/// `atexit` handlers, which is right only in a child that shares the parent's
/// memory image and must never return into it. `fd` must be a descriptor that
/// child holds open for writing, the spawn error pipe's write end, so the
/// report reaches the parent and no other descriptor is written.
#[expect(
    unsafe_code,
    reason = "an `unsafe fn` (its caller must be the post-fork child) whose body calls `write` \
              and `_exit`"
)]
unsafe fn report_child_failure(fd: libc::c_int, stage: i32) -> ! {
    let [s0, s1, s2, s3] = stage.to_ne_bytes();
    let [e0, e1, e2, e3] = errno().to_ne_bytes();
    let message = [s0, s1, s2, s3, e0, e1, e2, e3];
    // SAFETY: `write` reads `message.len()` (8) bytes through a pointer to
    // `message`, a live stack array of exactly that length, and writes them to
    // `fd`, the error pipe's write end per this function's contract. Its result
    // is ignored: the child exits next either way, and the parent reads a
    // missing report as EOF, that is, as a successful exec. `_exit` takes an
    // integer and never returns. Both are async-signal-safe and neither
    // allocates, as the post-fork child requires.
    unsafe {
        libc::write(fd, message.as_ptr().cast::<libc::c_void>(), message.len());
        libc::_exit(127);
    }
}

/// Read the child's failure report from the error pipe.
///
/// Returns `None` once the pipe closes with no report — the write end is
/// close-on-exec, so EOF means `execvpe` succeeded.
#[expect(
    unsafe_code,
    reason = "std has no read on a raw pipe descriptor, and a libc call is `unsafe`"
)]
fn read_child_failure(fd: libc::c_int) -> Option<(i32, i32)> {
    let mut message = [0u8; 8];
    let mut filled = 0;
    while filled < message.len() {
        let rest = &mut message[filled..];
        // SAFETY: `read` writes at most `rest.len()` bytes through a pointer to
        // `rest`, the live `&mut` tail of the local `message` with no other
        // borrow alive, so the pointer is valid and (as `u8`) aligned for that
        // length; on error it returns -1 and writes nothing. `fd` is the error
        // pipe's read end, which `spawn_raw`, the only caller, opened and closes
        // only after this returns.
        let n = unsafe { libc::read(fd, rest.as_mut_ptr().cast::<libc::c_void>(), rest.len()) };
        if n < 0 {
            if errno() == libc::EINTR {
                continue;
            }
            return None;
        }
        if n == 0 {
            // Pipe writes this small are atomic, so a short report can't
            // happen; EOF before a full report means exec succeeded.
            return None;
        }
        #[expect(clippy::cast_sign_loss, reason = "checked n > 0 above")]
        {
            filled += n as usize;
        }
    }
    let [s0, s1, s2, s3, e0, e1, e2, e3] = message;
    Some((
        i32::from_ne_bytes([s0, s1, s2, s3]),
        i32::from_ne_bytes([e0, e1, e2, e3]),
    ))
}

/// Close `fds`, ignoring errors (cleanup on a failed spawn).
#[expect(
    unsafe_code,
    reason = "closing a raw descriptor is a libc call, which is `unsafe`"
)]
fn close_all(fds: &[libc::c_int]) {
    for &fd in fds {
        // SAFETY: `close` takes an integer and reads or writes no memory of
        // this process. Every caller (`spawn_raw` and `move_above_stdio`)
        // passes descriptors it created in this spawn and still owns, each
        // once, and uses none of them afterwards, so no other owner's
        // descriptor is closed. An error is ignored: Linux releases the
        // descriptor even when `close` reports one.
        unsafe {
            libc::close(fd);
        }
    }
}

/// Move `fd` to a number above stdio (`>= 3`), keeping it close-on-exec.
///
/// If this process runs with fds 0-2 closed, a new fd can land on a stdio
/// number; the child's `dup2(slave, 0..=2)` would then be a no-op that leaves
/// close-on-exec set (stdio closed at exec) or clobber the error pipe. On
/// failure `fd` is closed.
#[expect(
    unsafe_code,
    reason = "`fcntl(F_DUPFD_CLOEXEC)` is a libc call, which is `unsafe`"
)]
fn move_above_stdio(fd: libc::c_int) -> Result<libc::c_int, PtyError> {
    if fd > libc::STDERR_FILENO {
        return Ok(fd);
    }
    // SAFETY: `fd` is a descriptor `spawn_raw`, the only caller, has just
    // created and hands over (the PTY slave or the error pipe's write end), so
    // it is open and owned here. `F_DUPFD_CLOEXEC` takes an integer argument
    // and reads or writes no memory of this process; on failure it returns -1
    // and creates nothing. `fd` is closed right after, either way.
    let moved = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, libc::STDERR_FILENO + 1) };
    close_all(&[fd]);
    if moved < 0 {
        Err(PtyError::SpawnFailed)
    } else {
        Ok(moved)
    }
}

/// Core PTY spawn logic behind [`Pty::spawn`].
///
/// Returns `(master_fd, pid)` on success. The master fd is non-blocking.
///
/// Both ends of the PTY pair (and the spawn error pipe) are created
/// close-on-exec **atomically** (`posix_openpt(O_CLOEXEC)` + `TIOCGPTPEER`,
/// Linux 4.13+) rather than via `forkpty` + a later `fcntl`: a process fork
/// on another thread in between would otherwise inherit the master (so
/// closing it here would never hang up the terminal) or the slave (so the
/// master would never see EOF when the child exits). The slave and the error
/// pipe's write end are kept off fds 0-2 (`move_above_stdio`).
///
/// The child becomes a session leader with the slave as its controlling
/// terminal and stdio, and starts with every catchable signal at its default
/// disposition and an empty signal mask. All signals are blocked in the
/// parent across `fork` (restored right after), so no inherited handler — a
/// tokio signal handler, say — can run in the child before its dispositions
/// are reset; and the Rust runtime's ignored `SIGPIPE` would otherwise survive
/// `exec` into the user's shell.
///
/// A failed `chdir` or `execvpe` in the child fails the spawn: the child
/// reports `errno` over the close-on-exec error pipe and exits, and the
/// parent reaps it, closes the master, and returns `ChdirFailed` /
/// `ExecFailed`. EOF on the pipe (the write end closed by a successful exec)
/// means success.
///
/// Fork-safety: the post-`fork` child branch allocates nothing, takes no
/// lock, and calls only `sigaction`, `sigprocmask`, `setsid`, `dup2`,
/// `chdir`, `write`, and `_exit`, which POSIX lists as async-signal-safe;
/// `ioctl`, which POSIX doesn't list but glibc implements as a plain
/// system-call wrapper; and `execvpe`, which POSIX doesn't list either:
/// glibc's builds each candidate path in a stack buffer, allocating nothing,
/// but reads `PATH` with `getenv` from the environment the child copied at
/// `fork`. The child's environment, signal sets, and default `sigaction` are
/// built by the caller or in the parent, so no `setenv` runs in the child.
///
/// # Safety
///
/// `argv_ptrs` and `envp_ptrs` must each be an array whose last element is
/// null and whose every other element points to a NUL-terminated string,
/// each string staying allocated and unmodified until this call returns (the
/// forked child reads them from its copy of the parent's memory, so the
/// parent must not free them while the call runs). `argv_ptrs` has at least
/// the null element.
#[expect(
    unsafe_code,
    reason = "an `unsafe fn` (its pointer arrays must be valid) over the PTY, pipe, signal-mask, \
              and fork libc calls"
)]
unsafe fn spawn_raw(
    command: &CString,
    argv_ptrs: &[*const libc::c_char],
    envp_ptrs: &[*const libc::c_char],
    cwd: Option<&CString>,
    ws: &libc::winsize,
) -> Result<(i32, i32), PtyError> {
    let pty_flags = libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC;

    // SAFETY: `posix_openpt` takes its flags by value and reads or writes no
    // memory of this process; it returns a new descriptor owned here, or -1,
    // checked below.
    let master_fd = unsafe { libc::posix_openpt(pty_flags) };
    if master_fd < 0 {
        return Err(PtyError::SpawnFailed);
    }
    // SAFETY: for both blocks, `master_fd` is the PTY master opened just above,
    // open and owned here and not yet shared. `grantpt` and `unlockpt` take
    // only the descriptor and write no memory of this process; on failure the
    // master is closed below before returning.
    if unsafe { libc::grantpt(master_fd) } != 0 || unsafe { libc::unlockpt(master_fd) } != 0 {
        close_all(&[master_fd]);
        return Err(PtyError::SpawnFailed);
    }
    // SAFETY: `master_fd` is the open master owned here. `TIOCGPTPEER` takes
    // its third argument, the open flags, by value as an integer and reads or
    // writes no memory of this process; it returns a new descriptor for the
    // slave, owned here, or -1, checked below.
    let slave_fd = unsafe { libc::ioctl(master_fd, libc::TIOCGPTPEER, pty_flags) };
    if slave_fd < 0 {
        close_all(&[master_fd]);
        return Err(PtyError::SpawnFailed);
    }
    let Ok(slave_fd) = move_above_stdio(slave_fd) else {
        close_all(&[master_fd]);
        return Err(PtyError::SpawnFailed);
    };
    // SAFETY: `master_fd` is the open PTY master owned here, a terminal, for
    // which the kernel reads exactly one `winsize` through the `TIOCSWINSZ`
    // pointer and writes nothing through it. The pointer comes from `ws`, a
    // live shared reference to a `libc::winsize`, so it is valid and aligned
    // for that read for the whole call.
    if unsafe { libc::ioctl(master_fd, libc::TIOCSWINSZ, &raw const *ws) } < 0 {
        close_all(&[master_fd, slave_fd]);
        return Err(PtyError::SpawnFailed);
    }

    let mut error_pipe: [libc::c_int; 2] = [-1, -1];
    // SAFETY: `pipe2` writes two `c_int`s through the pointer, which points at
    // `error_pipe`, a live local `[c_int; 2]` with no other borrow, valid and
    // aligned for exactly that write; the flags are taken by value. On failure
    // it returns -1, and the master and slave, owned here, are closed below.
    if unsafe { libc::pipe2(error_pipe.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
        close_all(&[master_fd, slave_fd]);
        return Err(PtyError::SpawnFailed);
    }
    let [error_read, error_write] = error_pipe;
    let Ok(error_write) = move_above_stdio(error_write) else {
        close_all(&[master_fd, slave_fd, error_read]);
        return Err(PtyError::SpawnFailed);
    };

    // Signal sets and the default disposition, built in the parent so the
    // child only installs them.
    // SAFETY: `libc::sigset_t` is a plain array of integers, for which
    // all-zero bytes are a valid value; `sigemptyset` initializes it below.
    let mut empty_mask: libc::sigset_t = unsafe { std::mem::zeroed() };
    // SAFETY: as for `empty_mask`; `sigfillset` initializes it below.
    let mut full_mask: libc::sigset_t = unsafe { std::mem::zeroed() };
    // SAFETY: as for `empty_mask`; `pthread_sigmask` fills it below.
    let mut parent_mask: libc::sigset_t = unsafe { std::mem::zeroed() };
    // SAFETY: `libc::sigaction` is a C struct of integers, a `sigset_t`, and
    // a nullable function pointer (`sa_restorer: Option<…>`), for all of which
    // all-zero bytes are a valid value (`SIG_DFL` and `None`).
    let mut default_action: libc::sigaction = unsafe { std::mem::zeroed() };
    // SAFETY: each call writes one `sigset_t` through a pointer to a live
    // local of that type (or to `default_action.sa_mask`, a field of one),
    // valid and aligned, with no other borrow alive; given a valid pointer
    // neither call can fail.
    unsafe {
        libc::sigemptyset(&raw mut empty_mask);
        libc::sigfillset(&raw mut full_mask);
        libc::sigemptyset(&raw mut default_action.sa_mask);
    }
    default_action.sa_sigaction = libc::SIG_DFL;
    let max_signal = libc::SIGRTMAX();

    // Block every signal across the fork: the child must not run an
    // inherited handler before it resets dispositions.
    // SAFETY: `pthread_sigmask` reads `full_mask`, initialized above, and
    // writes this thread's previous mask into `parent_mask`, a live local
    // `sigset_t`; both pointers are valid and aligned, and they point at
    // different locals. It changes only the calling thread's mask, and its one
    // error, EINVAL for a bad `how`, can't occur with `SIG_SETMASK`.
    unsafe {
        libc::pthread_sigmask(
            libc::SIG_SETMASK,
            &raw const full_mask,
            &raw mut parent_mask,
        );
    }

    // SAFETY: `fork` takes no arguments and touches no memory of this process
    // beyond duplicating it. In the child only this thread exists, and the
    // state of the parent's other threads (a lock held mid-operation, the
    // allocator's included) is frozen as `fork` found it, so the child branch
    // below allocates nothing and takes no lock before it execs or `_exit`s
    // (the calls it makes: this function's Fork-safety paragraph). All
    // signals are blocked, so no inherited handler runs in the child before
    // it resets them. In the parent, -1 is checked below.
    let pid = unsafe { libc::fork() };

    if pid == 0 {
        // child process — no allocation and no lock past this point
        // SAFETY: this is the forked child, alone in its copy of the parent's
        // memory, so nothing else can free or mutate what its pointers reach.
        // - `sigaction` reads one `sigaction` from `default_action`, a live
        //   local initialized above, and writes nothing (null old-action
        //   pointer); for SIGKILL, SIGSTOP, and libc's reserved realtime
        //   signals it fails with EINVAL, changing nothing. `sigprocmask`
        //   reads the initialized `empty_mask` and writes nothing.
        // - `setsid`, `ioctl(TIOCSCTTY, 0)`, and `dup2` take integers only
        //   (`ioctl` isn't on POSIX's async-signal-safe list; glibc's is a
        //   plain system-call wrapper that allocates and locks nothing).
        //   `slave_fd` is the child's copy of the slave, open (it is closed in
        //   the parent only after `fork`) and above fd 2 (`move_above_stdio`),
        //   so the `dup2`s replace the child's stdio without closing it (a
        //   descriptor they do replace is the child's copy of one it never
        //   uses: the master or the error pipe's read end).
        // - `chdir` reads the NUL-terminated buffer of `cwd_c`, a `CString`
        //   the caller holds for the call. `execvpe` reads `command`'s buffer
        //   and the `argv_ptrs` / `envp_ptrs` arrays, null-terminated arrays of
        //   NUL-terminated strings that stay allocated for the call per this
        //   function's contract. On success it replaces the process image; the
        //   master, the slave copy, and both pipe ends are close-on-exec.
        //   `execvpe` isn't on POSIX's async-signal-safe list: glibc's
        //   allocates nothing but reads `PATH` with `getenv` from the child's
        //   copy of the environment, which is consistent unless another
        //   parent thread was mid-way through changing the environment at
        //   `fork` (which `std::env::set_var`'s contract rules out in a
        //   multi-threaded process; this function does not hold std's
        //   environment lock across `fork` as `std::process::Command` does).
        // - Every failure path calls `report_child_failure`, which this child
        //   may call (its contract), with `error_write`, the child's copy of
        //   the error pipe's write end, open and above fd 2, so the `dup2`s
        //   never replaced it; it `_exit`s, so the child never returns into
        //   the parent's code.
        unsafe {
            // defaults for every catchable signal (SIGKILL / SIGSTOP and the
            // libc-reserved realtime signals just fail with EINVAL), then
            // unblock — ignored dispositions would otherwise survive exec
            for signal in 1..=max_signal {
                libc::sigaction(signal, &raw const default_action, ptr::null_mut());
            }
            libc::sigprocmask(libc::SIG_SETMASK, &raw const empty_mask, ptr::null_mut());

            // new session with the slave as controlling terminal + stdio
            // (the master, slave, and error pipe are all close-on-exec, and
            // the slave and error pipe sit above fd 2)
            if libc::setsid() < 0
                || libc::ioctl(slave_fd, libc::TIOCSCTTY, 0) < 0
                || libc::dup2(slave_fd, libc::STDIN_FILENO) < 0
                || libc::dup2(slave_fd, libc::STDOUT_FILENO) < 0
                || libc::dup2(slave_fd, libc::STDERR_FILENO) < 0
            {
                report_child_failure(error_write, STAGE_SETUP);
            }

            if let Some(cwd_c) = cwd
                && libc::chdir(cwd_c.as_ptr()) != 0
            {
                report_child_failure(error_write, STAGE_CHDIR);
            }
            libc::execvpe(command.as_ptr(), argv_ptrs.as_ptr(), envp_ptrs.as_ptr());
            // execvpe only returns on error
            report_child_failure(error_write, STAGE_EXEC);
        }
    }

    // parent — restore this thread's signal mask
    // SAFETY: `pthread_sigmask` reads `parent_mask`, a live local holding the
    // mask the call above wrote into it, through a valid, aligned pointer; the
    // old-mask pointer is null, so nothing is written. It changes only this
    // thread's mask and can't fail with `SIG_SETMASK`.
    unsafe {
        libc::pthread_sigmask(libc::SIG_SETMASK, &raw const parent_mask, ptr::null_mut());
    }

    if pid < 0 {
        close_all(&[master_fd, slave_fd, error_read, error_write]);
        return Err(PtyError::SpawnFailed);
    }

    // the child holds its own slave copies now
    close_all(&[slave_fd, error_write]);
    // SAFETY: `master_fd` is the open master owned here. `F_GETFL` takes no
    // argument and `F_SETFL` an integer; neither reads or writes memory of
    // this process. A failed `F_GETFL` skips the `F_SETFL`.
    unsafe {
        let flags = libc::fcntl(master_fd, libc::F_GETFL);
        if flags >= 0 {
            libc::fcntl(master_fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
    }

    let failure = read_child_failure(error_read);
    close_all(&[error_read]);

    if let Some((stage, child_errno)) = failure {
        // The child `_exit`s right after reporting — reap it so the failed
        // spawn leaves no zombie.
        let mut status: libc::c_int = 0;
        // SAFETY: `waitpid` writes one `c_int` through a pointer to `status`, a
        // live local, valid and aligned. `pid` is the child forked above, not
        // yet reaped and not yet known to any other code, so the call waits for
        // that child only; a failure other than EINTR (ECHILD, had something
        // else reaped it) ends the loop.
        while unsafe { libc::waitpid(pid, &raw mut status, 0) } < 0 && errno() == libc::EINTR {}
        close_all(&[master_fd]);
        return Err(match stage {
            STAGE_CHDIR => PtyError::ChdirFailed(child_errno),
            STAGE_EXEC => PtyError::ExecFailed(child_errno),
            _ => PtyError::SpawnFailed,
        });
    }

    Ok((master_fd, pid))
}

// == Safe Rust API ============================================================

use std::fmt;

/// Error from a PTY operation.
#[derive(Debug)]
pub enum PtyError {
    /// Opening the PTY pair, `pipe2`, `fork`, or the child's terminal setup
    /// (`setsid` / `TIOCSCTTY` / `dup2`) failed.
    SpawnFailed,
    /// The child couldn't `chdir` into the requested cwd (carries `errno`).
    ChdirFailed(i32),
    /// The child couldn't `execvpe` the command (carries `errno`).
    ExecFailed(i32),
    /// String argument contained an interior NUL byte.
    NulByte,
    /// An env variable name was empty or contained `=`.
    InvalidEnv,
    /// `write()` would block — the PTY input buffer is full. Retry once the
    /// master fd is writable.
    WouldBlock,
    /// `write()` returned an error.
    WriteFailed,
    /// `ioctl(TIOCSWINSZ)` failed.
    ResizeFailed,
    /// `kill()` failed.
    KillFailed,
    /// `close()` failed.
    CloseFailed,
}

impl fmt::Display for PtyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SpawnFailed => write!(f, "PTY spawn failed"),
            Self::ChdirFailed(errno) => write!(
                f,
                "PTY cwd change failed: {}",
                std::io::Error::from_raw_os_error(*errno)
            ),
            Self::ExecFailed(errno) => write!(
                f,
                "PTY command exec failed: {}",
                std::io::Error::from_raw_os_error(*errno)
            ),
            Self::NulByte => write!(f, "argument contains NUL byte"),
            Self::InvalidEnv => write!(f, "env variable name is empty or contains '='"),
            Self::WouldBlock => write!(f, "PTY write would block"),
            Self::WriteFailed => write!(f, "PTY write failed"),
            Self::ResizeFailed => write!(f, "PTY resize failed"),
            Self::KillFailed => write!(f, "PTY kill failed"),
            Self::CloseFailed => write!(f, "PTY close failed"),
        }
    }
}

impl std::error::Error for PtyError {}

/// Result of a non-blocking read.
#[derive(Debug)]
pub enum ReadResult {
    /// Got `n` bytes of data.
    Data(usize),
    /// No data available (EAGAIN/EWOULDBLOCK).
    WouldBlock,
    /// EOF — slave side closed (Linux reports this as `EIO`).
    Eof,
}

/// Result of a non-blocking waitpid.
#[derive(Debug)]
pub enum WaitResult {
    /// Process exited with the given status (`128 + signal` if killed by a
    /// signal).
    Exited(i32),
    /// Process still running.
    StillRunning,
    /// `waitpid` failed — typically `ECHILD`: the pid was already reaped (or
    /// isn't this process's child). Nothing is left to wait on, and the pid
    /// must not be signalled (it may have been reused).
    Unavailable,
}

/// A PTY process handle.
///
/// Wraps a master file descriptor and child PID.
/// The caller is responsible for closing the fd (via [`Pty::close`])
/// and reaping the child (via [`Pty::waitpid`] until it reports an exit).
///
/// # Soundness
///
/// This type is not sound as written. `master_fd` and `pid` are public plain
/// integers, not owned handles, and [`Pty::close`] takes `&self`, so the type
/// doesn't stop a second `close`, a [`Pty::read`] / [`Pty::write`] /
/// [`Pty::resize`] after `close`, or a `Pty` built by hand around another
/// descriptor or pid. And `Pty` is `Send + Sync` (two integers), so `close` on
/// one thread can race `read` or `resize` on another.
///
/// - **The descriptor.** Each of those acts on a descriptor the `Pty` doesn't
///   own, which the process may have reused for something else. That breaks
///   Rust's I/O-safety rules (closing or using a descriptor another owner
///   holds), and for `resize` it is memory unsoundness: `TIOCSWINSZ` goes to
///   whatever device the number then names, whose driver may read its request
///   number as one that writes through the pointer, into memory past the
///   8-byte `winsize` local it points at.
/// - **The pid.** [`Pty::kill`] and [`Pty::waitpid`] pass `pid` to the kernel
///   unchecked. A pid of `0` or below is no error: `kill` with `0` signals this
///   process's whole process group (this process included), with `-1` every
///   process the caller may signal but init and itself, and below `-1` the
///   process group `-pid`;
///   `waitpid` with `-1` reaps any child, with `0` any child in this process
///   group, and below `-1` any child in group `-pid`, so it can reap a child
///   other code owns and free its pid for reuse. Neither writes memory of this
///   process beyond `waitpid`'s status local, but both reach processes the
///   `Pty` doesn't own.
///
/// The methods are sound only for a `Pty` as [`Pty::spawn`] returned it, its
/// fields untouched, used from one thread at a time, and closed once, last.
#[derive(Debug)]
pub struct Pty {
    pub master_fd: i32,
    pub pid: i32,
}

impl Pty {
    /// Spawn a process in a new PTY.
    ///
    /// The master fd is non-blocking for async reads, and close-on-exec from
    /// creation so no other spawned process can inherit it.
    ///
    /// `env` is the child's exact environment; `None` inherits this
    /// process's. Either way the child gets `TERM=xterm-256color`, replacing
    /// any `TERM` entry.
    ///
    /// # Errors
    ///
    /// Returns `PtyError::NulByte` if any argument or env entry contains a NUL
    /// byte, `PtyError::InvalidEnv` for an empty or `=`-containing env name,
    /// `PtyError::ChdirFailed` if the child can't enter `cwd`,
    /// `PtyError::ExecFailed` if `command` can't be executed, or
    /// `PtyError::SpawnFailed` if the PTY pair, pipe, fork, or the child's
    /// terminal setup fails. A failed child is reaped before returning.
    #[expect(unsafe_code, reason = "calls `spawn_raw`, an `unsafe fn`")]
    pub fn spawn(
        command: &str,
        args: &[&str],
        cwd: Option<&str>,
        env: Option<&[(OsString, OsString)]>,
        cols: u16,
        rows: u16,
    ) -> Result<Self, PtyError> {
        let command_cstr = CString::new(command).map_err(|_| PtyError::NulByte)?;

        let mut argv_cstrings: Vec<CString> = Vec::with_capacity(1 + args.len());
        argv_cstrings.push(command_cstr.clone());
        for arg in args {
            argv_cstrings.push(CString::new(*arg).map_err(|_| PtyError::NulByte)?);
        }
        let argv_ptrs = to_ptr_array(&argv_cstrings);

        let envp_cstrings = build_envp(env)?;
        let envp_ptrs = to_ptr_array(&envp_cstrings);

        let cwd_cstr = cwd
            .map(|s| CString::new(s).map_err(|_| PtyError::NulByte))
            .transpose()?;

        let ws = libc::winsize {
            ws_row: rows,
            ws_col: cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };

        // SAFETY: `argv_ptrs` and `envp_ptrs` come from `to_ptr_array` over
        // `argv_cstrings` and `envp_cstrings`: each element but the last points
        // at the NUL-terminated buffer of a `CString` in those vectors, and the
        // last is null; `argv_ptrs` holds at least the command and the null.
        // Both vectors are locals of this function, neither moved nor mutated
        // until after `spawn_raw` returns, so every pointer stays valid for the
        // whole call, as `spawn_raw`'s contract requires.
        let (master_fd, pid) = unsafe {
            spawn_raw(
                &command_cstr,
                &argv_ptrs,
                &envp_ptrs,
                cwd_cstr.as_ref(),
                &ws,
            )
        }?;

        Ok(Self { master_fd, pid })
    }

    /// Non-blocking read from the PTY master fd.
    ///
    /// On success, returns `Data(n)` with `n` bytes written into `buf`.
    /// Returns `WouldBlock` if no data is available, `Eof` if the slave closed
    /// (or the read failed). Retries on `EINTR`.
    #[expect(
        unsafe_code,
        reason = "`read` on the master descriptor is a libc call, which is `unsafe`"
    )]
    pub fn read(&self, buf: &mut [u8]) -> ReadResult {
        loop {
            // SAFETY: `read` writes at most `buf.len()` bytes through a pointer
            // to `buf`, an exclusive `&mut [u8]`, so the pointer is valid and
            // (as `u8`) aligned for that length and nothing else aliases it; on
            // error it returns -1 and writes nothing. The descriptor is
            // `self.master_fd`, which this type doesn't own: it is the master
            // `spawn` opened only while `close` hasn't run (see the type's
            // Soundness section), but the buffer's safety holds for any number.
            let n = unsafe {
                libc::read(
                    self.master_fd,
                    buf.as_mut_ptr().cast::<libc::c_void>(),
                    buf.len(),
                )
            };
            if n < 0 {
                let errno = errno();
                if errno == libc::EINTR {
                    continue;
                }
                if errno == libc::EAGAIN || errno == libc::EWOULDBLOCK {
                    return ReadResult::WouldBlock;
                }
                return ReadResult::Eof;
            }
            if n == 0 {
                return ReadResult::Eof;
            }
            #[expect(
                clippy::cast_sign_loss,
                reason = "read() returns at most buf.len() which fits usize"
            )]
            return ReadResult::Data(n as usize);
        }
    }

    /// Write data to the PTY master fd.
    ///
    /// Non-blocking: may write only a prefix of `data` — callers loop on the
    /// returned count. Retries on `EINTR`.
    ///
    /// # Errors
    ///
    /// Returns `PtyError::WouldBlock` if the PTY input buffer is full, or
    /// `PtyError::WriteFailed` if the underlying `write()` call fails.
    #[expect(
        unsafe_code,
        reason = "`write` on the master descriptor is a libc call, which is `unsafe`"
    )]
    pub fn write(&self, data: &[u8]) -> Result<usize, PtyError> {
        loop {
            // SAFETY: `write` reads at most `data.len()` bytes through a pointer
            // to `data`, a live shared slice, valid and (as `u8`) aligned for
            // that length, and writes no memory of this process. The descriptor
            // is `self.master_fd`, which this type doesn't own: it is the master
            // `spawn` opened only while `close` hasn't run (see the type's
            // Soundness section).
            let n = unsafe {
                libc::write(
                    self.master_fd,
                    data.as_ptr().cast::<libc::c_void>(),
                    data.len(),
                )
            };
            if n < 0 {
                let errno = errno();
                if errno == libc::EINTR {
                    continue;
                }
                if errno == libc::EAGAIN || errno == libc::EWOULDBLOCK {
                    return Err(PtyError::WouldBlock);
                }
                return Err(PtyError::WriteFailed);
            }
            #[expect(clippy::cast_sign_loss, reason = "checked n >= 0 above")]
            return Ok(n as usize);
        }
    }

    /// Resize the PTY window.
    ///
    /// # Errors
    ///
    /// Returns `PtyError::ResizeFailed` if the `ioctl` call fails.
    #[expect(
        unsafe_code,
        reason = "`ioctl(TIOCSWINSZ)` is a libc call, which is `unsafe`"
    )]
    pub fn resize(&self, cols: u16, rows: u16) -> Result<(), PtyError> {
        let ws = libc::winsize {
            ws_row: rows,
            ws_col: cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        // SAFETY: the pointer is to `ws`, a live local `libc::winsize`, valid
        // and aligned for the one `winsize` a terminal's `TIOCSWINSZ` reads; a
        // terminal writes nothing through it. That `self.master_fd` is the PTY
        // master, a terminal, holds only while `close` hasn't run (on any
        // thread) and the field is as `spawn` set it. Otherwise this is not
        // sound: the number may name another device, whose driver may read
        // `TIOCSWINSZ`'s request number as one that writes through the
        // pointer, past the 8-byte local (see the type's Soundness section).
        let ret = unsafe { libc::ioctl(self.master_fd, libc::TIOCSWINSZ, &ws) };
        if ret < 0 {
            Err(PtyError::ResizeFailed)
        } else {
            Ok(())
        }
    }

    /// Send a signal to the child process.
    ///
    /// Only signal a child that hasn't been reaped yet — once
    /// [`Pty::waitpid`] reports `Exited` or `Unavailable`, the pid may be
    /// reused by an unrelated process.
    ///
    /// # Errors
    ///
    /// Returns `PtyError::KillFailed` if the `kill` syscall fails.
    #[expect(unsafe_code, reason = "`kill` is a libc call, which is `unsafe`")]
    pub fn kill(&self, signal: i32) -> Result<(), PtyError> {
        // SAFETY: `kill` takes two integers and reads or writes no memory of
        // this process. An invalid signal fails with EINVAL and a pid with no
        // process with ESRCH, but a pid of `0` or below is no error: it signals
        // this process's group (this process included), every process the
        // caller may signal but init and itself, or the group `-pid`, all
        // reachable through the public field (see the type's Soundness
        // section). Signalling a reused pid, the hazard this method's doc
        // states, reaches another process but writes no memory of this one.
        let ret = unsafe { libc::kill(self.pid, signal) };
        if ret < 0 {
            Err(PtyError::KillFailed)
        } else {
            Ok(())
        }
    }

    /// Non-blocking waitpid (`WNOHANG`). Reaps the child once it has exited.
    #[expect(unsafe_code, reason = "`waitpid` is a libc call, which is `unsafe`")]
    pub fn waitpid(&self) -> WaitResult {
        let mut status: libc::c_int = 0;
        let ret = loop {
            // SAFETY: `waitpid` writes one `c_int` through a pointer to
            // `status`, a live local, valid and aligned, and no other memory of
            // this process. A positive pid that isn't this process's unreaped
            // child fails with ECHILD, but a pid of `0` or below is no error:
            // `-1` reaps any child, `0` any child in this process group, and
            // below `-1` any child in the group `-pid`, reachable through the
            // public field. Reaping a child other code owns leaves that code an
            // ECHILD and frees the pid for reuse (see the type's Soundness
            // section).
            let ret = unsafe { libc::waitpid(self.pid, &raw mut status, libc::WNOHANG) };
            if ret < 0 && errno() == libc::EINTR {
                continue;
            }
            break ret;
        };
        match ret.cmp(&0) {
            std::cmp::Ordering::Greater => {
                if libc::WIFEXITED(status) {
                    WaitResult::Exited(libc::WEXITSTATUS(status))
                } else if libc::WIFSIGNALED(status) {
                    // Killed by signal — return 128 + signal (Unix convention)
                    WaitResult::Exited(128 + libc::WTERMSIG(status))
                } else {
                    WaitResult::Exited(-1)
                }
            }
            std::cmp::Ordering::Equal => WaitResult::StillRunning,
            std::cmp::Ordering::Less => WaitResult::Unavailable,
        }
    }

    /// Close the PTY master fd.
    ///
    /// # Errors
    ///
    /// Returns `PtyError::CloseFailed` if the `close` syscall fails.
    #[expect(
        unsafe_code,
        reason = "`close` on the master descriptor is a libc call, which is `unsafe`"
    )]
    pub fn close(&self) -> Result<(), PtyError> {
        // SAFETY: `close` takes an integer and reads or writes no memory of
        // this process. It is I/O-safe only on the first call for a `Pty` as
        // `spawn` returned it: `&self` allows a second call, and the public
        // field allows any number, either of which closes a descriptor this
        // `Pty` doesn't own (see the type's Soundness section).
        let ret = unsafe { libc::close(self.master_fd) };
        if ret < 0 {
            Err(PtyError::CloseFailed)
        } else {
            Ok(())
        }
    }
}

// == Tests ====================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_spawn_echo() {
        let pty = Pty::spawn("echo", &["hello"], None, None, 80, 24).expect("spawn failed");
        assert!(pty.master_fd >= 0);
        assert!(pty.pid > 0);

        thread::sleep(Duration::from_millis(100));

        let mut buf = [0u8; 4096];
        match pty.read(&mut buf) {
            ReadResult::Data(n) => {
                let output = String::from_utf8_lossy(&buf[..n]);
                assert!(output.contains("hello"), "expected 'hello', got: {output}");
            }
            other => panic!("expected Data, got: {other:?}"),
        }

        thread::sleep(Duration::from_millis(100));
        match pty.waitpid() {
            WaitResult::Exited(code) => assert_eq!(code, 0),
            other => panic!("expected process to have exited, got: {other:?}"),
        }

        pty.close().expect("close failed");
    }

    #[test]
    fn test_resize() {
        let pty = Pty::spawn("sh", &["-c", "sleep 1"], None, None, 80, 24).expect("spawn failed");
        pty.resize(120, 40).expect("resize failed");
        pty.kill(libc::SIGTERM).expect("kill failed");
        thread::sleep(Duration::from_millis(50));
        let _ = pty.waitpid();
        pty.close().expect("close failed");
    }

    #[test]
    fn test_write_and_read() {
        let pty = Pty::spawn("cat", &[], None, None, 80, 24).expect("spawn failed");

        pty.write(b"test input\n").expect("write failed");
        thread::sleep(Duration::from_millis(100));

        let mut buf = [0u8; 4096];
        match pty.read(&mut buf) {
            ReadResult::Data(n) => {
                let output = String::from_utf8_lossy(&buf[..n]);
                assert!(
                    output.contains("test input"),
                    "expected echoed input, got: {output}"
                );
            }
            other => panic!("expected Data, got: {other:?}"),
        }

        pty.kill(libc::SIGTERM).expect("kill failed");
        thread::sleep(Duration::from_millis(50));
        let _ = pty.waitpid();
        pty.close().expect("close failed");
    }

    #[test]
    fn test_term_inherited_by_child() {
        // The parent builds the child's envp (with TERM=xterm-256color)
        // pre-fork — no setenv runs in the post-fork child. Validates the
        // fork-safe TERM propagation end-to-end.
        let pty =
            Pty::spawn("sh", &["-c", "echo $TERM"], None, None, 80, 24).expect("spawn failed");

        thread::sleep(Duration::from_millis(100));

        let mut buf = [0u8; 4096];
        let output = match pty.read(&mut buf) {
            ReadResult::Data(n) => String::from_utf8_lossy(&buf[..n]).into_owned(),
            other => panic!("expected Data, got: {other:?}"),
        };
        assert!(
            output.contains("xterm-256color"),
            "expected TERM=xterm-256color in child, got: {output}"
        );

        let _ = pty.waitpid();
        pty.close().expect("close failed");
    }

    /// Read until EOF (or `timeout`), collecting output.
    fn read_to_eof(pty: &Pty, timeout: Duration) -> String {
        let deadline = std::time::Instant::now() + timeout;
        let mut out = Vec::new();
        let mut buf = [0u8; 4096];
        while std::time::Instant::now() < deadline {
            match pty.read(&mut buf) {
                ReadResult::Data(n) => out.extend_from_slice(&buf[..n]),
                ReadResult::WouldBlock => thread::sleep(Duration::from_millis(5)),
                ReadResult::Eof => break,
            }
        }
        String::from_utf8_lossy(&out).into_owned()
    }

    /// Poll `waitpid` until the child exits (or `timeout`).
    fn wait_exit(pty: &Pty, timeout: Duration) -> WaitResult {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            match pty.waitpid() {
                WaitResult::StillRunning if std::time::Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(5));
                }
                other => return other,
            }
        }
    }

    #[test]
    fn test_spawn_bad_cwd_fails() {
        let result = Pty::spawn(
            "pwd",
            &[],
            Some("/nonexistent/fuz_pty_test_cwd"),
            None,
            80,
            24,
        );
        match result {
            Err(PtyError::ChdirFailed(errno)) => assert_eq!(errno, libc::ENOENT),
            other => panic!("expected ChdirFailed(ENOENT), got: {other:?}"),
        }
    }

    #[test]
    fn test_spawn_missing_command_fails() {
        let result = Pty::spawn("/nonexistent/fuz_pty_test_bin", &[], None, None, 80, 24);
        match result {
            Err(PtyError::ExecFailed(errno)) => assert_eq!(errno, libc::ENOENT),
            other => panic!("expected ExecFailed(ENOENT), got: {other:?}"),
        }
    }

    #[test]
    fn test_spawn_explicit_env() {
        // Only the given variables reach the child (plus the forced TERM,
        // which replaces a caller-supplied one). `sh` is still found: the
        // command lookup uses this process's PATH, not the child env's.
        let env = vec![
            (
                OsString::from("FUZ_PTY_TEST_VAR"),
                OsString::from("present"),
            ),
            (OsString::from("TERM"), OsString::from("dumb")),
        ];
        let pty = Pty::spawn(
            "sh",
            &["-c", "echo \"[$FUZ_PTY_TEST_VAR][$HOME][$TERM]\""],
            None,
            Some(&env),
            80,
            24,
        )
        .expect("spawn failed");
        let output = read_to_eof(&pty, Duration::from_secs(5));
        assert!(
            output.contains("[present][][xterm-256color]"),
            "expected only the explicit env, got: {output}"
        );
        let _ = wait_exit(&pty, Duration::from_secs(5));
        pty.close().expect("close failed");
    }

    #[test]
    fn test_spawn_invalid_env_name_fails() {
        let env = vec![(OsString::from("A=B"), OsString::from("x"))];
        let result = Pty::spawn("true", &[], None, Some(&env), 80, 24);
        assert!(
            matches!(result, Err(PtyError::InvalidEnv)),
            "got: {result:?}"
        );
    }

    #[test]
    #[expect(
        unsafe_code,
        reason = "reads the master's descriptor flags with `fcntl`"
    )]
    fn test_master_fd_is_cloexec() {
        let pty = Pty::spawn("sleep", &["5"], None, None, 80, 24).expect("spawn failed");
        // SAFETY: `pty.master_fd` is the master `spawn` just returned, open
        // until the `close` at the end of this test; `F_GETFD` takes no
        // argument and reads or writes no memory of this process.
        let fd_flags = unsafe { libc::fcntl(pty.master_fd, libc::F_GETFD) };
        assert!(fd_flags >= 0);
        assert_ne!(
            fd_flags & libc::FD_CLOEXEC,
            0,
            "master fd must be close-on-exec"
        );
        pty.kill(libc::SIGKILL).expect("kill failed");
        assert!(matches!(
            wait_exit(&pty, Duration::from_secs(5)),
            WaitResult::Exited(_)
        ));
        pty.close().expect("close failed");
    }

    #[test]
    fn test_write_would_block_when_input_full() {
        // `sleep` never reads stdin, so the PTY input buffer fills and a
        // non-blocking write reports `WouldBlock` rather than a failure.
        let pty = Pty::spawn("sleep", &["5"], None, None, 80, 24).expect("spawn failed");
        let chunk = [b'x'; 4096];
        let mut saw_would_block = false;
        for _ in 0..1024 {
            match pty.write(&chunk) {
                Ok(_) => {}
                Err(PtyError::WouldBlock) => {
                    saw_would_block = true;
                    break;
                }
                Err(e) => panic!("unexpected write error: {e}"),
            }
        }
        assert!(saw_would_block, "expected the PTY input buffer to fill");
        pty.kill(libc::SIGKILL).expect("kill failed");
        assert!(matches!(
            wait_exit(&pty, Duration::from_secs(5)),
            WaitResult::Exited(_)
        ));
        pty.close().expect("close failed");
    }

    #[test]
    fn test_waitpid_after_reap_is_unavailable() {
        let pty = Pty::spawn("true", &[], None, None, 80, 24).expect("spawn failed");
        assert!(matches!(
            wait_exit(&pty, Duration::from_secs(5)),
            WaitResult::Exited(0)
        ));
        assert!(matches!(pty.waitpid(), WaitResult::Unavailable));
        pty.close().expect("close failed");
    }

    #[test]
    fn test_master_not_inherited_by_later_spawns() {
        // A later child must not hold an earlier terminal's master — if it
        // did, closing that master would never hang the earlier terminal up.
        let first = Pty::spawn("sleep", &["5"], None, None, 80, 24).expect("spawn failed");
        let script = format!("readlink /proc/$$/fd/{} || echo CLEAN", first.master_fd);
        let second = Pty::spawn("sh", &["-c", &script], None, None, 80, 24).expect("spawn failed");
        let output = read_to_eof(&second, Duration::from_secs(5));
        assert!(
            output.contains("CLEAN") && !output.contains("ptmx"),
            "earlier master leaked into a later child: {output}"
        );
        let _ = wait_exit(&second, Duration::from_secs(5));
        second.close().expect("close failed");
        first.kill(libc::SIGKILL).expect("kill failed");
        let _ = wait_exit(&first, Duration::from_secs(5));
        first.close().expect("close failed");
    }

    #[test]
    #[expect(
        unsafe_code,
        reason = "ignores `SIGUSR2` with `signal` to give the child something to reset"
    )]
    fn test_child_signal_state_is_default() {
        // The Rust runtime ignores SIGPIPE, and this process may ignore
        // others (SIGUSR2 here, harmless to the harness); the child must
        // start with no ignored and no blocked signals — `yes | head` would
        // otherwise report EPIPE instead of exiting.
        // SAFETY: `signal` takes an integer and `SIG_IGN`, not a handler, so no
        // code of this process runs when `SIGUSR2` arrives; it changes only
        // that signal's process-wide disposition, which no other test reads
        // or relies on.
        unsafe {
            libc::signal(libc::SIGUSR2, libc::SIG_IGN);
        }
        let pty = Pty::spawn(
            "grep",
            &["-E", "^Sig(Ign|Blk)", "/proc/self/status"],
            None,
            None,
            80,
            24,
        )
        .expect("spawn failed");
        let output = read_to_eof(&pty, Duration::from_secs(5));
        let mut seen = 0;
        for line in output.lines() {
            let mut fields = line.split_whitespace();
            let (Some(name), Some(mask_hex)) = (fields.next(), fields.next()) else {
                continue;
            };
            let mask = u64::from_str_radix(mask_hex, 16).expect("hex mask");
            assert_eq!(mask, 0, "{name} not empty in child: {output}");
            seen += 1;
        }
        assert_eq!(seen, 2, "expected SigBlk + SigIgn lines, got: {output}");
        let _ = wait_exit(&pty, Duration::from_secs(5));
        pty.close().expect("close failed");
    }

    const STDIO_CLOSED_CHILD_ENV: &str = "FUZ_PTY_TEST_STDIO_CLOSED_CHILD";
    const STDIO_CLOSED_CHILD_OK: i32 = 42;

    /// Helper for `test_spawn_with_stdio_closed`, run in a subprocess: closes
    /// this process's fds 0-2 so the PTY slave and error pipe get allocated
    /// on stdio numbers, then checks the child still gets working stdio.
    #[test]
    #[ignore = "subprocess helper for test_spawn_with_stdio_closed"]
    #[expect(unsafe_code, reason = "closes this process's fds 0-2 with `close`")]
    fn stdio_closed_child() {
        if std::env::var_os(STDIO_CLOSED_CHILD_ENV).is_none() {
            return;
        }
        // SAFETY: `close` takes an integer and reads or writes no memory of
        // this process. This runs only in the subprocess
        // `test_spawn_with_stdio_closed` starts for this one test, with its
        // output discarded; fds 0-2 there are the standard streams, which no
        // Rust value owns (std's stdio handles borrow them and treat a closed
        // descriptor's EBADF as success), and the process exits right after
        // the spawn below.
        unsafe {
            libc::close(libc::STDIN_FILENO);
            libc::close(libc::STDOUT_FILENO);
            libc::close(libc::STDERR_FILENO);
        }
        let ok = Pty::spawn("sh", &["-c", "echo STDIO_OK"], None, None, 80, 24)
            .is_ok_and(|pty| read_to_eof(&pty, Duration::from_secs(5)).contains("STDIO_OK"));
        std::process::exit(if ok { STDIO_CLOSED_CHILD_OK } else { 1 });
    }

    #[test]
    fn test_spawn_with_stdio_closed() {
        let exe = std::env::current_exe().expect("test executable");
        let status = std::process::Command::new(exe)
            .args(["--ignored", "--exact", "tests::stdio_closed_child"])
            .env(STDIO_CLOSED_CHILD_ENV, "1")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .expect("run helper");
        assert_eq!(
            status.code(),
            Some(STDIO_CLOSED_CHILD_OK),
            "spawn with fds 0-2 closed must still give the child working stdio"
        );
    }
}
