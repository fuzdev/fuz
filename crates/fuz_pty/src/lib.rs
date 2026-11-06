//! A safe PTY API (the [`Pty`] struct) over the libc PTY calls.
//!
//! Linux-only, kernel ≥ 4.13 (`TIOCGPTPEER`, `execvpe`, `pipe2`). The one
//! workspace crate that allows `unsafe_code`.

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
/// Must only be called in the forked child; `fd` must be the error pipe's
/// write end.
unsafe fn report_child_failure(fd: libc::c_int, stage: i32) -> ! {
    let [s0, s1, s2, s3] = stage.to_ne_bytes();
    let [e0, e1, e2, e3] = errno().to_ne_bytes();
    let message = [s0, s1, s2, s3, e0, e1, e2, e3];
    // SAFETY: `message` is a valid 8-byte buffer; `_exit` never returns.
    unsafe {
        libc::write(fd, message.as_ptr().cast::<libc::c_void>(), message.len());
        libc::_exit(127);
    }
}

/// Read the child's failure report from the error pipe.
///
/// Returns `None` once the pipe closes with no report — the write end is
/// close-on-exec, so EOF means `execvpe` succeeded.
fn read_child_failure(fd: libc::c_int) -> Option<(i32, i32)> {
    let mut message = [0u8; 8];
    let mut filled = 0;
    while filled < message.len() {
        let rest = &mut message[filled..];
        // SAFETY: `rest` is a valid writable buffer of `rest.len()` bytes.
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
fn close_all(fds: &[libc::c_int]) {
    for &fd in fds {
        // SAFETY: closing an fd this function's caller owns.
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
fn move_above_stdio(fd: libc::c_int) -> Result<libc::c_int, PtyError> {
    if fd > libc::STDERR_FILENO {
        return Ok(fd);
    }
    // SAFETY: `fd` is a valid open fd this function owns.
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
/// Fork-safety: the post-`fork` child branch calls only async-signal-safe
/// functions (`sigaction`, `sigprocmask`, `setsid`, `ioctl`, `dup2`,
/// `chdir`, `execvpe`, `write`, `_exit`); the environment, signal sets, and
/// default `sigaction` are built by the caller / in the parent, so no
/// allocation or `setenv` runs in the child.
///
/// # Safety
///
/// Caller must ensure `argv_ptrs` and `envp_ptrs` are null-terminated arrays
/// of valid C strings that outlive the call.
unsafe fn spawn_raw(
    command: &CString,
    argv_ptrs: &[*const libc::c_char],
    envp_ptrs: &[*const libc::c_char],
    cwd: Option<&CString>,
    ws: &libc::winsize,
) -> Result<(i32, i32), PtyError> {
    let pty_flags = libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC;

    // SAFETY: plain syscall; the returned fd is checked below.
    let master_fd = unsafe { libc::posix_openpt(pty_flags) };
    if master_fd < 0 {
        return Err(PtyError::SpawnFailed);
    }
    // SAFETY: `master_fd` is the valid PTY master opened above.
    if unsafe { libc::grantpt(master_fd) } != 0 || unsafe { libc::unlockpt(master_fd) } != 0 {
        close_all(&[master_fd]);
        return Err(PtyError::SpawnFailed);
    }
    // SAFETY: `TIOCGPTPEER` takes open flags by value and returns a new fd.
    let slave_fd = unsafe { libc::ioctl(master_fd, libc::TIOCGPTPEER, pty_flags) };
    if slave_fd < 0 {
        close_all(&[master_fd]);
        return Err(PtyError::SpawnFailed);
    }
    let Ok(slave_fd) = move_above_stdio(slave_fd) else {
        close_all(&[master_fd]);
        return Err(PtyError::SpawnFailed);
    };
    // SAFETY: `ws` is a valid `winsize` for the duration of the call.
    if unsafe { libc::ioctl(master_fd, libc::TIOCSWINSZ, &raw const *ws) } < 0 {
        close_all(&[master_fd, slave_fd]);
        return Err(PtyError::SpawnFailed);
    }

    let mut error_pipe: [libc::c_int; 2] = [-1, -1];
    // SAFETY: `error_pipe` is a valid 2-element `c_int` array.
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
    // SAFETY: `sigset_t` and `sigaction` are plain C data, valid when
    // zeroed; `sigemptyset` / `sigfillset` initialize the sets.
    let mut empty_mask: libc::sigset_t = unsafe { std::mem::zeroed() };
    let mut full_mask: libc::sigset_t = unsafe { std::mem::zeroed() };
    let mut parent_mask: libc::sigset_t = unsafe { std::mem::zeroed() };
    let mut default_action: libc::sigaction = unsafe { std::mem::zeroed() };
    unsafe {
        libc::sigemptyset(&raw mut empty_mask);
        libc::sigfillset(&raw mut full_mask);
        libc::sigemptyset(&raw mut default_action.sa_mask);
    }
    default_action.sa_sigaction = libc::SIG_DFL;
    let max_signal = libc::SIGRTMAX();

    // Block every signal across the fork: the child must not run an
    // inherited handler before it resets dispositions.
    // SAFETY: both sets are initialized; this only changes this thread's mask.
    unsafe {
        libc::pthread_sigmask(
            libc::SIG_SETMASK,
            &raw const full_mask,
            &raw mut parent_mask,
        );
    }

    // SAFETY: the child branch below only makes async-signal-safe calls.
    let pid = unsafe { libc::fork() };

    if pid == 0 {
        // child process — only async-signal-safe calls past this point
        // SAFETY: every pointer passed was prepared in the parent and is
        // still valid in the child's copy of the address space; `cwd`,
        // `command`, `argv_ptrs`, and `envp_ptrs` outlive the call per this
        // function's contract.
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
    // SAFETY: `parent_mask` was filled in by the `pthread_sigmask` above.
    unsafe {
        libc::pthread_sigmask(libc::SIG_SETMASK, &raw const parent_mask, ptr::null_mut());
    }

    if pid < 0 {
        close_all(&[master_fd, slave_fd, error_read, error_write]);
        return Err(PtyError::SpawnFailed);
    }

    // the child holds its own slave copies now
    close_all(&[slave_fd, error_write]);
    // SAFETY: `master_fd` is a valid open fd; F_GETFL / F_SETFL take ints.
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
        // SAFETY: `pid` is this process's unreaped child; `status` is valid.
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
    pub fn read(&self, buf: &mut [u8]) -> ReadResult {
        loop {
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
    pub fn write(&self, data: &[u8]) -> Result<usize, PtyError> {
        loop {
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
    pub fn resize(&self, cols: u16, rows: u16) -> Result<(), PtyError> {
        let ws = libc::winsize {
            ws_row: rows,
            ws_col: cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
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
    pub fn kill(&self, signal: i32) -> Result<(), PtyError> {
        let ret = unsafe { libc::kill(self.pid, signal) };
        if ret < 0 {
            Err(PtyError::KillFailed)
        } else {
            Ok(())
        }
    }

    /// Non-blocking waitpid (`WNOHANG`). Reaps the child once it has exited.
    pub fn waitpid(&self) -> WaitResult {
        let mut status: libc::c_int = 0;
        let ret = loop {
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
    pub fn close(&self) -> Result<(), PtyError> {
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
    fn test_master_fd_is_cloexec() {
        let pty = Pty::spawn("sleep", &["5"], None, None, 80, 24).expect("spawn failed");
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
    fn test_child_signal_state_is_default() {
        // The Rust runtime ignores SIGPIPE, and this process may ignore
        // others (SIGUSR2 here, harmless to the harness); the child must
        // start with no ignored and no blocked signals — `yes | head` would
        // otherwise report EPIPE instead of exiting.
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
    fn stdio_closed_child() {
        if std::env::var_os(STDIO_CLOSED_CHILD_ENV).is_none() {
            return;
        }
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
