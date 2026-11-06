//! `fuzd logs` — print and follow the daemon log in-process.
//!
//! The log is opened through [`open_nofollow_regular`], so a symlink or any
//! other non-regular file at the log path is refused by the open itself, with
//! no window between a check and the read. The last lines are found by reading
//! backward from the end in fixed chunks (memory bounded by the chunk, not the
//! file), and following polls the open descriptor for appended bytes every
//! [`LOG_POLL_INTERVAL`].
//!
//! **Rotation.** `fuzd start` renames `daemon_output.log` to `.1` and creates
//! a fresh file. Each poll compares the path's `lstat` identity (device and
//! inode) with the open descriptor's: once they differ, the rest of the old
//! file is printed and the new one is opened through the same no-follow open —
//! a symlink or non-regular file put in its place is refused. A file shorter
//! than what was already read was truncated in place and is re-read from its
//! start; a truncation that regrows past the read position within one poll
//! interval is not seen, and the follow goes on from that position (as `tail
//! -f` does). A path that is briefly absent (between the rename and the
//! create) keeps the old descriptor until the new file appears.
//!
//! **Output is the log's raw bytes**, unescaped. The file is
//! fuzd's own stdout/stderr (mode `0600`, the user's own); its lines come from
//! the tracing formatter, which escapes ESC and the other C0/C1 terminal
//! controls inside field values as it writes them, and colors its own level
//! and target with ANSI codes this reader must pass through for the lines to
//! read as the daemon wrote them. Escaping here would mangle those codes and
//! make the output differ from `cat` or `less` on the same file; the trust
//! boundary is the writer.
//!
//! **Signals.** No handler is installed: SIGINT and SIGTERM keep their
//! default disposition and end the process at once, a follow included, even
//! while a write to stdout is blocked on a reader that has stopped reading.
//! The shell sees death by that signal (`130` / `143`).
//!
//! **Exit codes.** `0` when a one-shot read reached the end, or when stdout's
//! reader went away (a closed pipe, `fuzd logs | head`). `1` when there is no
//! log file, and for every [`DaemonError`]: a refused log path or replacement,
//! or a failed read or write. A follow otherwise runs until a signal ends it.

// TODO: the tracing formatter leaves `\r`, `\n`, and bidi controls in a field
// value as they are, so a value derived from outside input can still forge a
// line here; escaping belongs in the daemon's writer (a fuzd `FormatEvent`, or
// field values escaped where they are logged), not in this reader.

use crate::DaemonError;
use fuz_home::get_daemon_log_path;
use fuz_sys::secure_file::{SecureFileError, open_nofollow_regular};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

/// How often a follow checks the log for appended bytes and for rotation.
const LOG_POLL_INTERVAL: Duration = Duration::from_millis(250);

/// Lines printed before following when `-n` is not given (`tail`'s default).
const DEFAULT_LOG_LINES: usize = 10;

/// Bytes read per step when scanning backward for the last lines.
const TAIL_CHUNK_SIZE: usize = 8192;

/// Print the last lines of the daemon log, then follow it unless `no_follow`.
///
/// `lines` defaults to 10. The exit-code, signal, and raw-bytes output
/// contracts are in the module doc.
///
/// # Errors
/// Returns a [`DaemonError`] if the log path can't be resolved, holds a symlink
/// or anything else but a regular file (at the start or as a rotation's
/// replacement), or reading the log or writing stdout fails.
pub async fn logs(no_follow: bool, lines: Option<usize>) -> Result<ExitCode, DaemonError> {
    let log_path = get_daemon_log_path()?;
    let file = match open_log(&log_path) {
        Ok(file) => file,
        Err(DaemonError::LogFile(SecureFileError::NotFound(_))) => {
            eprintln!("No log file found at {}", log_path.display());
            return Ok(ExitCode::FAILURE);
        }
        Err(e) => return Err(e),
    };

    let mut stdout = io::stdout();
    let mut follower = match LogFollower::start(
        log_path,
        file,
        lines.unwrap_or(DEFAULT_LOG_LINES),
        &mut stdout,
    ) {
        Ok(follower) => follower,
        Err(e) => return finish(Err(e)),
    };
    if no_follow {
        return finish(Ok(()));
    }

    // No signal handler: SIGINT/SIGTERM end the follow with their default
    // disposition, wherever it is — a blocked stdout write included.
    loop {
        tokio::time::sleep(LOG_POLL_INTERVAL).await;
        // A poll reads the log to its end and writes it to stdout, blocking
        // the runtime thread while stdout's reader is behind; nothing else
        // shares this runtime, and a signal still ends the process.
        if let Err(e) = follower.poll(&mut stdout) {
            return finish(Err(e));
        }
    }
}

/// Map the end of a print or follow to its exit: a closed stdout is a reader
/// that has all it wanted, not a failure.
fn finish(result: Result<(), DaemonError>) -> Result<ExitCode, DaemonError> {
    match result {
        Ok(()) => Ok(ExitCode::SUCCESS),
        Err(DaemonError::WriteOutput(e)) if e.kind() == io::ErrorKind::BrokenPipe => {
            Ok(ExitCode::SUCCESS)
        }
        Err(e) => Err(e),
    }
}

/// The no-follow regular-file open of the log, its error as a [`DaemonError`].
fn open_log(path: &Path) -> Result<File, DaemonError> {
    open_nofollow_regular(path)
        .map(|(file, _)| file)
        .map_err(DaemonError::LogFile)
}

/// The byte offset at which the last `n` lines of `reader` begin, `len` being
/// its length, found by reading backward from `len` in `chunk`-byte steps.
///
/// A line ends at a `\n`; the text after the final `\n` (a last line still
/// being written) is a line too, and a `\n` that is the final byte ends the
/// last line rather than starting an empty one — `tail -n`'s count. `n == 0`
/// is `len`; `n` past the file's line count is `0`, as is a file that shrank
/// below `len` before the scan read it (the follow then prints what is there).
fn last_lines_start<R: Read + Seek>(
    reader: &mut R,
    len: u64,
    n: usize,
    chunk: usize,
) -> io::Result<u64> {
    if n == 0 || len == 0 {
        return Ok(len);
    }
    let mut buf = vec![0u8; chunk];
    let mut found = 0usize;
    let mut end = len;
    while end > 0 {
        let start = end.saturating_sub(chunk as u64);
        // `end - start` is at most `chunk`, so it fits in `usize`.
        let size = usize::try_from(end - start).unwrap_or(chunk);
        let window = &mut buf[..size];
        reader.seek(SeekFrom::Start(start))?;
        match reader.read_exact(window) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(0),
            Err(e) => return Err(e),
        }
        for (i, byte) in window.iter().enumerate().rev() {
            let at = start + i as u64;
            if *byte == b'\n' && at != len - 1 {
                found += 1;
                if found == n {
                    return Ok(at + 1);
                }
            }
        }
        end = start;
    }
    Ok(0)
}

/// An open daemon log being followed: the descriptor, the path it was opened
/// from, and how far it has been read.
#[derive(Debug)]
struct LogFollower {
    path: PathBuf,
    file: File,
    /// Bytes of `file` already printed; the descriptor's offset.
    pos: u64,
}

impl LogFollower {
    /// Print the last `lines` lines of `file` (opened from `path`) and the
    /// rest of it, returning the follower positioned at its end.
    fn start(
        path: PathBuf,
        mut file: File,
        lines: usize,
        out: &mut impl Write,
    ) -> Result<Self, DaemonError> {
        let len = file
            .metadata()
            .map_err(|source| read_error(&path, source))?
            .len();
        let start = last_lines_start(&mut file, len, lines, TAIL_CHUNK_SIZE)
            .map_err(|source| read_error(&path, source))?;
        file.seek(SeekFrom::Start(start))
            .map_err(|source| read_error(&path, source))?;
        let mut follower = Self {
            path,
            file,
            pos: start,
        };
        follower.drain(out)?;
        Ok(follower)
    }

    /// One poll: print what was appended, then re-read a truncated file from
    /// its start, and switch to the new file once the path names another one
    /// (after printing the rest of the old).
    fn poll(&mut self, out: &mut impl Write) -> Result<(), DaemonError> {
        self.drain(out)?;

        let len = self
            .file
            .metadata()
            .map_err(|source| read_error(&self.path, source))?
            .len();
        if len < self.pos {
            self.file
                .seek(SeekFrom::Start(0))
                .map_err(|source| read_error(&self.path, source))?;
            self.pos = 0;
            self.drain(out)?;
        }

        if self.replaced()? {
            // Rotation stops the daemon first, but print anything that reached
            // the old file after the drain above before letting it go.
            self.drain(out)?;
            match open_log(&self.path) {
                Ok(file) => {
                    self.file = file;
                    self.pos = 0;
                    self.drain(out)?;
                }
                // Gone again between the `lstat` and the open: the next poll
                // looks once more.
                Err(DaemonError::LogFile(SecureFileError::NotFound(_))) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// Whether the path now names something other than the open file. An
    /// absent path is not (yet) a replacement.
    fn replaced(&self) -> Result<bool, DaemonError> {
        let at_path = match std::fs::symlink_metadata(&self.path) {
            Ok(meta) => meta,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(source) => return Err(read_error(&self.path, source)),
        };
        let open = self
            .file
            .metadata()
            .map_err(|source| read_error(&self.path, source))?;
        Ok(at_path.dev() != open.dev() || at_path.ino() != open.ino())
    }

    /// Copy the file from the current position to its end into `out`, then
    /// flush, so a line still being written shows as far as it goes.
    fn drain(&mut self, out: &mut impl Write) -> Result<(), DaemonError> {
        let mut buf = [0u8; TAIL_CHUNK_SIZE];
        loop {
            let n = match self.file.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(source) => return Err(read_error(&self.path, source)),
            };
            out.write_all(&buf[..n]).map_err(DaemonError::WriteOutput)?;
            self.pos += n as u64;
        }
        out.flush().map_err(DaemonError::WriteOutput)
    }
}

fn read_error(path: &Path, source: io::Error) -> DaemonError {
    DaemonError::ReadLog {
        path: path.to_path_buf(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// The last `n` lines of `text`, through [`last_lines_start`] at `chunk`.
    fn last(text: &str, n: usize, chunk: usize) -> String {
        let mut cursor = Cursor::new(text.as_bytes());
        let start = last_lines_start(&mut cursor, text.len() as u64, n, chunk).unwrap();
        text[usize::try_from(start).unwrap()..].to_string()
    }

    /// `tail -n`'s count: a final `\n` ends the last line, unterminated text
    /// at the end is a line, `0` is nothing, more than there are is all.
    #[test]
    fn last_lines_counts_as_tail_does() {
        for chunk in [1, 2, 3, 4, 5, 7, TAIL_CHUNK_SIZE] {
            assert_eq!(last("", 3, chunk), "", "empty, chunk {chunk}");
            assert_eq!(last("a\nb\nc\n", 2, chunk), "b\nc\n", "chunk {chunk}");
            assert_eq!(last("a\nb\nc", 2, chunk), "b\nc", "no final newline");
            assert_eq!(last("a\nb\nc\n", 0, chunk), "", "zero lines");
            assert_eq!(last("a\nb\nc\n", 3, chunk), "a\nb\nc\n", "exactly all");
            assert_eq!(last("a\nb\nc\n", 9, chunk), "a\nb\nc\n", "more than all");
            assert_eq!(last("abc", 1, chunk), "abc", "one unterminated line");
            assert_eq!(last("\n", 1, chunk), "\n", "one empty line");
            assert_eq!(last("\n\n\n", 2, chunk), "\n\n", "empty lines count");
            assert_eq!(
                last("a\n\nb\n", 2, chunk),
                "\nb\n",
                "an empty line in the middle"
            );
        }
    }

    /// A file that shrank below the length the scan was given starts at `0`
    /// rather than failing.
    #[test]
    fn last_lines_of_a_file_that_shrank_start_at_0() {
        let mut cursor = Cursor::new(b"a\nb\n".as_slice());
        assert_eq!(last_lines_start(&mut cursor, 100, 1, 8).unwrap(), 0);
        assert_eq!(last_lines_start(&mut cursor, 100, 1, 1).unwrap(), 0);
    }

    /// A newline that falls exactly on a chunk's first or last byte is
    /// counted once, whichever side of the boundary it sits on.
    #[test]
    fn last_lines_across_chunk_boundaries() {
        let text = "0123\n5678\nabcd\nefgh\n";
        for chunk in 1..=text.len() + 1 {
            assert_eq!(last(text, 1, chunk), "efgh\n", "chunk {chunk}");
            assert_eq!(last(text, 2, chunk), "abcd\nefgh\n", "chunk {chunk}");
            assert_eq!(last(text, 4, chunk), text, "chunk {chunk}");
        }
        // Lines longer than the chunk.
        let long = format!("{}\n{}\n", "x".repeat(20), "y".repeat(20));
        assert_eq!(last(&long, 1, 3), format!("{}\n", "y".repeat(20)));
    }

    struct Fixture {
        _dir: tempfile::TempDir,
        path: PathBuf,
    }

    impl Fixture {
        fn new(content: &str) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("daemon_output.log");
            std::fs::write(&path, content).unwrap();
            Self { _dir: dir, path }
        }

        fn append(&self, text: &str) {
            let mut file = std::fs::OpenOptions::new()
                .append(true)
                .open(&self.path)
                .unwrap();
            file.write_all(text.as_bytes()).unwrap();
        }

        fn follower(&self, lines: usize) -> (LogFollower, String) {
            let mut out = Vec::new();
            let file = open_log(&self.path).unwrap();
            let follower = LogFollower::start(self.path.clone(), file, lines, &mut out).unwrap();
            (follower, String::from_utf8(out).unwrap())
        }
    }

    fn poll(follower: &mut LogFollower) -> Result<String, DaemonError> {
        let mut out = Vec::new();
        follower.poll(&mut out)?;
        Ok(String::from_utf8(out).unwrap())
    }

    /// Start prints the last lines; each poll prints what was appended since,
    /// a partial line included, and nothing when nothing was.
    #[test]
    fn follow_prints_appended_bytes() {
        let fixture = Fixture::new("one\ntwo\nthree\n");
        let (mut follower, printed) = fixture.follower(2);
        assert_eq!(printed, "two\nthree\n");
        assert_eq!(poll(&mut follower).unwrap(), "");
        fixture.append("four\nfi");
        assert_eq!(poll(&mut follower).unwrap(), "four\nfi");
        fixture.append("ve\n");
        assert_eq!(poll(&mut follower).unwrap(), "ve\n");
    }

    /// `fuzd start`'s rotation — rename to `.1`, then a fresh file — is
    /// followed: the rest of the old file, then the new one from its start.
    /// While the path is absent the old descriptor is kept.
    #[test]
    fn follow_switches_to_the_rotated_in_file() {
        let fixture = Fixture::new("old 1\n");
        let (mut follower, printed) = fixture.follower(10);
        assert_eq!(printed, "old 1\n");

        fixture.append("old 2\n");
        std::fs::rename(&fixture.path, fixture.path.with_extension("log.1")).unwrap();
        assert_eq!(poll(&mut follower).unwrap(), "old 2\n", "absent: old kept");

        std::fs::write(&fixture.path, "new 1\n").unwrap();
        assert_eq!(poll(&mut follower).unwrap(), "new 1\n");
        fixture.append("new 2\n");
        assert_eq!(poll(&mut follower).unwrap(), "new 2\n");
    }

    /// A file truncated in place (a start that could not rotate truncates the
    /// same file) is re-read from its start.
    #[test]
    fn follow_rereads_a_truncated_file() {
        let fixture = Fixture::new("a long first line\n");
        let (mut follower, _) = fixture.follower(10);
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(&fixture.path)
            .unwrap();
        file.set_len(0).unwrap();
        drop(file);
        fixture.append("b\n");
        assert_eq!(poll(&mut follower).unwrap(), "b\n");
    }

    /// A symlink or a non-regular file put at the log path in place of the
    /// followed file is refused, not followed.
    #[test]
    fn follow_refuses_an_irregular_replacement() {
        for what in ["symlink", "dangling symlink", "directory"] {
            let fixture = Fixture::new("x\n");
            let (mut follower, _) = fixture.follower(10);
            std::fs::remove_file(&fixture.path).unwrap();
            match what {
                "symlink" => {
                    let target = fixture.path.with_extension("other");
                    std::fs::write(&target, "planted\n").unwrap();
                    std::os::unix::fs::symlink(&target, &fixture.path).unwrap();
                }
                "dangling symlink" => {
                    std::os::unix::fs::symlink("nowhere", &fixture.path).unwrap();
                }
                _ => std::fs::create_dir(&fixture.path).unwrap(),
            }
            let result = poll(&mut follower);
            assert!(
                matches!(
                    result,
                    Err(DaemonError::LogFile(
                        SecureFileError::Symlink(_) | SecureFileError::NotRegularFile(_)
                    ))
                ),
                "{what}: {result:?}"
            );
        }
    }

    /// The initial open refuses what the follow refuses.
    #[test]
    fn open_log_refuses_a_symlink() {
        let fixture = Fixture::new("x\n");
        let link = fixture.path.with_extension("link");
        std::os::unix::fs::symlink(&fixture.path, &link).unwrap();
        assert!(matches!(
            open_log(&link),
            Err(DaemonError::LogFile(SecureFileError::Symlink(_)))
        ));
    }

    /// A closed stdout ends the output cleanly; any other failure is an error.
    #[test]
    fn finish_takes_a_closed_pipe_as_done() {
        assert!(
            finish(Err(DaemonError::WriteOutput(io::Error::from(
                io::ErrorKind::BrokenPipe
            ))))
            .is_ok()
        );
        assert!(finish(Err(DaemonError::WriteOutput(io::Error::other("x")))).is_err());
    }
}
