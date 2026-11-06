//! SSH storage backend
//!
//! Reads and writes release artifacts on a remote host over `ssh`/`scp`, against
//! a "dumb" SSH server serving a directory tree (`ssh://user@host[:port]/path`).
//! Distribution uses it both ways: `cargo xtask publish … --storage
//! ssh://user@vps/var/www/releases` (upload) and `fuz tool install … --storage
//! ssh://…` (download). Like the other backends it is a pure byte store — `fuz`
//! verifies signatures against its embedded key after fetching, regardless of
//! transport.
//!
//! Authentication is the caller's `ssh` setup — the running `ssh-agent` or a
//! default-location key (`~/.ssh/id_*`); there is no token or `credentials.json`.
//! Every connection sets `-o BatchMode=yes` so a missing key / unknown host key
//! fails fast instead of hanging on a prompt, and `-F none` so a hostile host
//! string can never match a `Host` / `ProxyCommand` alias in the caller's
//! `~/.ssh/config`. The tradeoff of `-F none` is that `~/.ssh/config` is ignored
//! entirely, so a per-host `IdentityFile` / `ProxyJump` / `User` / `Port` there
//! does **not** apply — encode those in the `ssh://user@host:port/path` URI (or
//! use the agent). Host-key verification still uses `~/.ssh/known_hosts`
//! (unaffected by `-F none`), so the host must already be known.
//!
//! IPv6 literal hosts are not supported: the host charset (below) excludes `:`
//! and `[]`, so use a hostname or an IPv4 literal.
//!
//! # Security: command / option injection
//!
//! `ssh … <cmd>` re-enters a shell on the **remote** side; `scp` (OpenSSH 9+)
//! speaks SFTP and sends the remote path literally, with no remote shell. This
//! module defends both transports with the same primary guarantee plus a
//! transport-appropriate second layer:
//!
//! 1. **Charset validation (primary)** — the host, user, and root (from the URI)
//!    plus the per-operation on-store key (via [`crate::validate_forge_key`]) are
//!    each restricted to a metacharacter-free charset before any command is
//!    built. The joined remote path is always absolute (`/`-leading) and holds
//!    only `[A-Za-z0-9._/-]`: no shell metacharacter, whitespace, quote, glob
//!    (`*?[]`), or `~` survives. This alone makes every remote path safe under
//!    both remote-shell parsing and SFTP-client glob/tilde expansion.
//! 2. **Single-quoting — `ssh` only** — every remote path in an `ssh` remote
//!    command string is single-quoted ([`sq`]); the validated charset excludes
//!    `'`, so the quoting is airtight and the `sq` escape is a
//!    belt-and-suspenders no-op. `scp` paths are **not** quoted: SFTP mode would
//!    treat the quotes as literal filename bytes (a real transfer failure on any
//!    OpenSSH 9+ host), and with no remote shell there is nothing for quoting to
//!    defend — the charset guarantee stands alone.
//!
//! Anti-option-injection: the destination is one `format!("{user}@{host}")` arg
//! that always starts with the validated (non-`-`) username, so it can never be
//! read as a flag; fixed options come first, and `scp` gets a `--` before its
//! positionals. Commands are always built with separate args (never `sh -c`).

use std::ffi::OsStr;
use std::path::Path;
use std::process::{ExitStatus, Stdio};

use tokio::io::AsyncWriteExt;
use tokio::process::{Child, ChildStderr, Command};

use fuz_sys::limits::MAX_TRANSFER_SIZE;
use fuz_sys::rand::random_hex_suffix;

use crate::Storage;
use crate::error::{StorageBackendKind, StorageError};

/// Backend identity for error messages.
const BACKEND: StorageBackendKind = StorageBackendKind::Ssh;

/// Cap on captured stderr (per command). Error text is tiny; this bounds a
/// pathological remote so an error path can't accumulate unbounded memory.
/// Deliberately far below `fuz_sys::limits::MAX_CAPTURE_STDERR_SIZE` — a
/// tighter per-use cap on top of the shared ceiling, per that module's rule.
const STDERR_CAP: u64 = 64 * 1024;

/// SSH storage backend (`ssh://user@host[:port]/path`).
///
/// Construct via [`SshStorage::new`] or [`crate::parse_storage`]. All fields are
/// validated at construction; there are no secrets to redact (auth is the
/// caller's `ssh` agent / key file), so `Debug` is derived.
#[derive(Debug)]
pub struct SshStorage {
    /// Validated username (`[A-Za-z0-9._-]`, no leading `-`).
    user: String,
    /// Validated host (`[A-Za-z0-9.-]`, no leading `-`).
    host: String,
    /// TCP port (1..=65535; default 22).
    port: u16,
    /// Validated absolute storage root (no trailing slash except the bare `/`).
    root: String,
}

impl SshStorage {
    /// Create an SSH backend from an `ssh://user@host[:port]/path` URI.
    ///
    /// The username, host, port, and root path are validated (see the module
    /// docs); an empty username, a relative or metacharacter-bearing root, or a
    /// disallowed charset is rejected with [`StorageError::InvalidConfig`].
    pub fn new(location: &str) -> Result<Self, StorageError> {
        let (user, host, port, root) = parse_ssh_url(location)?;
        Ok(Self {
            user,
            host,
            port,
            root,
        })
    }

    /// Build an `ssh` [`Command`] with the fixed options + destination, plus the
    /// remote command as a single trailing arg. Stdio is left to the caller.
    fn ssh_command(&self, remote_cmd: &str) -> Command {
        let mut command = Command::new("ssh");
        command.args(ssh_base_args(&self.user, &self.host, self.port));
        command.arg(remote_cmd);
        command.kill_on_drop(true);
        command
    }

    /// Spawn an `ssh` [`Command`] with the caller's stdio, mapping an exec
    /// failure into `op`'s error variant. The streaming call sites
    /// (`upload`/`download`/`list`) drive the returned [`Child`] themselves.
    fn spawn_ssh(
        &self,
        remote_cmd: &str,
        stdin: Stdio,
        stdout: Stdio,
        op: SshOp,
    ) -> Result<Child, StorageError> {
        self.ssh_command(remote_cmd)
            .stdin(stdin)
            .stdout(stdout)
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| op.spawn_failed("ssh", &e))
    }

    /// Run a small control-plane `ssh` command (`mkdir`/`mv`/`test`/`rm`) that
    /// produces negligible output, capturing stdout+stderr and waiting. An exec
    /// failure maps into `op`'s error variant; a non-zero *remote* exit is left
    /// to the caller, since each control-plane command reads its status
    /// differently (`test -e` treats 1 as "absent", `rm -f` has its own
    /// message).
    async fn run_ssh(
        &self,
        remote_cmd: &str,
        op: SshOp,
    ) -> Result<std::process::Output, StorageError> {
        self.ssh_command(remote_cmd)
            .stdin(Stdio::null())
            .output()
            .await
            .map_err(|e| op.spawn_failed("ssh", &e))
    }

    /// Run a control-plane **write** command (`mkdir -p` / `mv`) and require it
    /// to succeed, classifying a non-zero exit via [`classify_write_failure`].
    ///
    /// `cleanup_tmp` names a remote temp to reap best-effort on failure — `mv`
    /// passes its source so a failed publish doesn't strand the staged bytes;
    /// the `mkdir` that runs before anything is staged passes `None`.
    async fn run_ssh_write_checked(
        &self,
        remote_cmd: &str,
        path: &str,
        cleanup_tmp: Option<&str>,
    ) -> Result<(), StorageError> {
        let output = self.run_ssh(remote_cmd, SshOp::Write).await?;
        if output.status.success() {
            return Ok(());
        }
        if let Some(tmp) = cleanup_tmp {
            self.best_effort_rm(tmp).await;
        }
        Err(classify_write_failure(path, output.status, &output.stderr))
    }

    /// `cat` the remote file at `path`, keeping at most `max` bytes: the one
    /// read behind [`Storage::download`] and [`Storage::download_capped`].
    ///
    /// The bound is held on this side, whatever the host sends. Reading stops
    /// at the first byte past `max`, the `ssh` child is killed and reaped, and
    /// the refusal is [`StorageError::TooLarge`] with `size` one past `max`:
    /// the length of the remote file is never learned.
    async fn read_remote(&self, path: &str, max: u64) -> Result<Vec<u8>, StorageError> {
        let remote = remote_path(&self.root, path)?;

        let child = self.spawn_ssh(
            &remote_cmd_download(&remote),
            Stdio::null(),
            Stdio::piped(),
            SshOp::Read,
        )?;

        let (status, out, err, truncated) = run_capture(child, max)
            .await
            .map_err(|e| SshOp::Read.io_failed(&e))?;

        if truncated {
            return Err(StorageError::TooLarge {
                backend: BACKEND,
                path: path.to_string(),
                size: max.saturating_add(1),
                max,
            });
        }
        if status.success() {
            return Ok(out);
        }
        Err(classify_read_failure(path, status, &err))
    }

    /// Best-effort remote unlink (used to reap a temp after a failed upload).
    async fn best_effort_rm(&self, remote: &str) {
        let _ = self.run_ssh(&remote_cmd_delete(remote), SshOp::Write).await;
    }
}

/// Which half of the [`StorageError`] taxonomy a failing `ssh`/`scp` invocation
/// reports under.
///
/// The transport can fail before the remote ever runs (no `ssh` binary, fork
/// failure, a broken pipe mid-transfer), and that failure has no read/write
/// character of its own — it inherits the operation's. Naming the operation once
/// per call site keeps the two error variants from being chosen by copy-paste.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SshOp {
    /// `download` / `download_to_file` / `list` / `exists` → `DownloadFailed`.
    Read,
    /// `upload` / `upload_file` / `delete` (and the `mkdir`/`mv` steps) →
    /// `UploadFailed`.
    Write,
}

impl SshOp {
    /// Wrap a transport-level failure message in this operation's error variant.
    const fn failed(self, message: String) -> StorageError {
        match self {
            Self::Read => StorageError::DownloadFailed {
                backend: BACKEND,
                message,
            },
            Self::Write => StorageError::UploadFailed {
                backend: BACKEND,
                message,
            },
        }
    }

    /// `program` could not be executed at all (`ssh` or `scp` missing, fork
    /// failure) — distinct from the remote exiting non-zero, which
    /// [`classify_read_failure`] / [`classify_write_failure`] handle.
    fn spawn_failed(self, program: &str, e: &std::io::Error) -> StorageError {
        self.failed(format!("failed to run {program}: {e}"))
    }

    /// An I/O failure while pumping an already-spawned child's pipes.
    fn io_failed(self, e: &std::io::Error) -> StorageError {
        self.failed(format!("ssh io error: {e}"))
    }
}

impl Storage for SshStorage {
    fn backend_kind(&self) -> StorageBackendKind {
        BACKEND
    }

    async fn upload(&self, path: &str, data: &[u8]) -> Result<(), StorageError> {
        let remote = remote_path(&self.root, path)?;

        let size = data.len() as u64;
        if size > MAX_TRANSFER_SIZE {
            return Err(StorageError::TooLarge {
                backend: BACKEND,
                path: path.to_string(),
                size,
                max: MAX_TRANSFER_SIZE,
            });
        }

        // Atomic: write to a same-dir temp via `cat >`, then `mv` into place.
        let dir = parent_dir(&remote);
        let tmp = temp_path(&remote);
        let cmd = remote_cmd_upload(dir, &tmp, &remote);

        let child = self.spawn_ssh(&cmd, Stdio::piped(), Stdio::null(), SshOp::Write)?;

        let (status, err) = write_stdin_capture_stderr(child, data)
            .await
            .map_err(|e| SshOp::Write.io_failed(&e))?;

        if status.success() {
            return Ok(());
        }

        // Reap a possibly-partial temp so it doesn't linger in the release dir.
        self.best_effort_rm(&tmp).await;
        Err(classify_write_failure(path, status, &err))
    }

    async fn download(&self, path: &str) -> Result<Vec<u8>, StorageError> {
        // Up to the transfer ceiling the capture is held in memory.
        self.read_remote(path, MAX_TRANSFER_SIZE).await
    }

    async fn download_capped(&self, path: &str, max: u64) -> Result<Vec<u8>, StorageError> {
        self.read_remote(path, max.min(MAX_TRANSFER_SIZE)).await
    }

    async fn download_to_file(&self, path: &str, dest: &Path) -> Result<u64, StorageError> {
        let remote = remote_path(&self.root, path)?;
        let src_arg = scp_remote_arg(&self.user, &self.host, &remote);

        // `scp -- host:remote dest` — options first, `--` before positionals.
        // The remote path is unquoted (SFTP mode sends it literally; see
        // `scp_remote_arg`); the source starts with the validated username
        // (never `-`), and the local dest is a plain filesystem arg.
        let output = scp_command(self.port, &src_arg, dest)
            .output()
            .await
            .map_err(|e| SshOp::Read.spawn_failed("scp", &e))?;

        if output.status.success() {
            let len = tokio::fs::metadata(dest)
                .await
                .map_err(|e| StorageError::DownloadFailed {
                    backend: BACKEND,
                    message: format!("stat {} failed: {e}", dest.display()),
                })?
                .len();
            // scp can't bound peak disk mid-transfer, so enforce the ceiling on
            // the finished file (delete an over-cap result).
            if len > MAX_TRANSFER_SIZE {
                let _ = tokio::fs::remove_file(dest).await;
                return Err(StorageError::TooLarge {
                    backend: BACKEND,
                    path: path.to_string(),
                    size: len,
                    max: MAX_TRANSFER_SIZE,
                });
            }
            return Ok(len);
        }

        // A failed scp may leave a partial local file behind — unlink it,
        // whatever the failure. Nothing here says whether scp got as far as
        // opening `dest` (the classification below reads stderr text), so a
        // file already at `dest` is removed even when the remote one is
        // missing — where the other backends, which see the refusal before
        // they create `dest`, leave it.
        let _ = tokio::fs::remove_file(dest).await;
        Err(classify_read_failure(path, output.status, &output.stderr))
    }

    async fn upload_file(&self, path: &str, src: &Path) -> Result<(), StorageError> {
        let remote = remote_path(&self.root, path)?;

        let size = tokio::fs::metadata(src)
            .await
            .map_err(|e| StorageError::UploadFailed {
                backend: BACKEND,
                message: format!("stat {} failed: {e}", src.display()),
            })?
            .len();
        if size > MAX_TRANSFER_SIZE {
            return Err(StorageError::TooLarge {
                backend: BACKEND,
                path: path.to_string(),
                size,
                max: MAX_TRANSFER_SIZE,
            });
        }

        let dir = parent_dir(&remote);
        let tmp = temp_path(&remote);

        // 1. Ensure the parent dir exists (matches `FileStorage`'s create_dir_all).
        //    Nothing is staged yet, so there is no temp to reap on failure.
        self.run_ssh_write_checked(&remote_cmd_mkdir(dir), path, None)
            .await?;

        // 2. Stream the file to a same-dir temp via scp (bounded memory).
        let dst_arg = scp_remote_arg(&self.user, &self.host, &tmp);
        let up = scp_command(self.port, src, &dst_arg)
            .output()
            .await
            .map_err(|e| SshOp::Write.spawn_failed("scp", &e))?;
        if !up.status.success() {
            self.best_effort_rm(&tmp).await;
            return Err(classify_write_failure(path, up.status, &up.stderr));
        }

        // 3. Atomic publish: `mv` temp into place, reaping the staged temp if it
        //    fails.
        self.run_ssh_write_checked(&remote_cmd_mv(&tmp, &remote), path, Some(&tmp))
            .await
    }

    async fn exists(&self, path: &str) -> Result<bool, StorageError> {
        let remote = remote_path(&self.root, path)?;
        let output = self
            .run_ssh(&remote_cmd_exists(&remote), SshOp::Read)
            .await?;

        // `test -e`: 0 → exists, 1 → absent, anything else → ssh/remote error.
        match output.status.code() {
            Some(0) => Ok(true),
            Some(1) => Ok(false),
            _ => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                if stderr_is_permission_denied(&stderr) {
                    Err(StorageError::PermissionDenied {
                        backend: BACKEND,
                        path: path.to_string(),
                    })
                } else {
                    Err(StorageError::DownloadFailed {
                        backend: BACKEND,
                        message: format!(
                            "ssh test failed ({}): {}",
                            exit_label(output.status),
                            stderr.trim()
                        ),
                    })
                }
            }
        }
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>, StorageError> {
        crate::validate_list_prefix(prefix)?;
        let child = self.spawn_ssh(
            &remote_cmd_list(&self.root),
            Stdio::null(),
            Stdio::piped(),
            SshOp::Read,
        )?;

        let (status, out, err, truncated) = run_capture(child, MAX_TRANSFER_SIZE)
            .await
            .map_err(|e| SshOp::Read.io_failed(&e))?;

        if truncated {
            return Err(StorageError::DownloadFailed {
                backend: BACKEND,
                message: "remote file listing exceeded the size cap".to_string(),
            });
        }
        if !status.success() {
            let stderr = String::from_utf8_lossy(&err);
            // A not-yet-created root lists as empty (nothing published), mirroring
            // `FileStorage::list` returning empty for a missing directory.
            if stderr_is_not_found(&stderr) {
                return Ok(Vec::new());
            }
            if stderr_is_permission_denied(&stderr) {
                return Err(StorageError::PermissionDenied {
                    backend: BACKEND,
                    path: prefix.to_string(),
                });
            }
            return Err(StorageError::DownloadFailed {
                backend: BACKEND,
                message: format!(
                    "ssh find failed ({}): {}",
                    exit_label(status),
                    stderr.trim()
                ),
            });
        }

        Ok(parse_list_output(&out, &self.root, prefix))
    }

    async fn delete(&self, path: &str) -> Result<(), StorageError> {
        let remote = remote_path(&self.root, path)?;
        let output = self
            .run_ssh(&remote_cmd_delete(&remote), SshOp::Write)
            .await?;

        // `rm -f`: a missing file is success (matches the trait's delete contract).
        if output.status.success() {
            return Ok(());
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr_is_permission_denied(&stderr) {
            Err(StorageError::PermissionDenied {
                backend: BACKEND,
                path: path.to_string(),
            })
        } else {
            Err(StorageError::UploadFailed {
                backend: BACKEND,
                message: format!(
                    "ssh rm failed ({}): {}",
                    exit_label(output.status),
                    stderr.trim()
                ),
            })
        }
    }
}

//
// URI parsing + validation (pure)
//

/// Parse and validate an `ssh://user@host[:port]/path` URI into its parts.
fn parse_ssh_url(location: &str) -> Result<(String, String, u16, String), StorageError> {
    let url = url::Url::parse(location)
        .map_err(|e| invalid_config(format!("invalid SSH URI '{location}': {e}")))?;
    if url.scheme() != "ssh" {
        return Err(invalid_config(format!(
            "SSH URI must use the ssh:// scheme (got '{}')",
            url.scheme()
        )));
    }
    if url.password().is_some_and(|p| !p.is_empty()) {
        return Err(invalid_config(
            "SSH URI must not embed a password; use key / agent auth".to_string(),
        ));
    }

    let user = url.username().to_string();
    validate_user(&user)?;

    let host = url
        .host_str()
        .ok_or_else(|| {
            invalid_config("SSH URI requires a host (ssh://user@host/path)".to_string())
        })?
        .to_string();
    validate_host(&host)?;

    let port = url.port().unwrap_or(22);
    if port == 0 {
        return Err(invalid_config("SSH port cannot be 0".to_string()));
    }

    let root = validate_root(url.path())?;
    Ok((user, host, port, root))
}

/// Shorthand for a config error.
const fn invalid_config(message: String) -> StorageError {
    StorageError::InvalidConfig { message }
}

/// Validate an SSH username: non-empty, no leading `-`, charset `[A-Za-z0-9._-]`.
fn validate_user(user: &str) -> Result<(), StorageError> {
    if user.is_empty() {
        return Err(invalid_config(
            "SSH URI requires a username (ssh://user@host/path)".to_string(),
        ));
    }
    if user.starts_with('-') {
        return Err(invalid_config(
            "SSH username cannot start with '-'".to_string(),
        ));
    }
    if !user
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        return Err(invalid_config(
            "SSH username contains invalid characters (allowed: a-z, A-Z, 0-9, '.', '_', '-')"
                .to_string(),
        ));
    }
    Ok(())
}

/// Validate an SSH host: non-empty, no leading `-`, charset `[A-Za-z0-9.-]`.
fn validate_host(host: &str) -> Result<(), StorageError> {
    if host.is_empty() {
        return Err(invalid_config("SSH host cannot be empty".to_string()));
    }
    if host.starts_with('-') {
        return Err(invalid_config("SSH host cannot start with '-'".to_string()));
    }
    if !host
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-'))
    {
        return Err(invalid_config(
            "SSH host contains invalid characters (allowed: a-z, A-Z, 0-9, '.', '-')".to_string(),
        ));
    }
    Ok(())
}

/// Validate the storage root from the URI path and return it normalized (no
/// trailing slash, except the bare `/`).
///
/// Requires an absolute path (leading `/`), charset `[A-Za-z0-9._/-]` (which
/// excludes every shell metacharacter, control char, and newline), and no `.` /
/// `..` segments.
fn validate_root(path: &str) -> Result<String, StorageError> {
    if !path.starts_with('/') {
        return Err(invalid_config(format!(
            "SSH root path must be absolute (got '{path}')"
        )));
    }
    if !path
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'/'))
    {
        return Err(invalid_config(
            "SSH root path contains invalid characters (allowed: a-z, A-Z, 0-9, '.', '_', '-', '/')"
                .to_string(),
        ));
    }
    for segment in path.split('/') {
        if segment == "." || segment == ".." {
            return Err(invalid_config(
                "SSH root path cannot contain '.' or '..' segments".to_string(),
            ));
        }
    }
    let normalized = path.trim_end_matches('/');
    Ok(if normalized.is_empty() {
        "/".to_string()
    } else {
        normalized.to_string()
    })
}

//
// Command construction (pure — the unit-tested seam)
//

/// The fixed `ssh` args: options first, then the `user@host` destination.
///
/// `-F none` ignores `~/.ssh/config`; `-o BatchMode=yes` fails fast rather than
/// prompting. `ssh` takes no `--`, but the destination starts with the validated
/// (non-`-`) username, so it can never be misread as an option.
fn ssh_base_args(user: &str, host: &str, port: u16) -> Vec<String> {
    vec![
        "-F".to_string(),
        "none".to_string(),
        "-o".to_string(),
        "BatchMode=yes".to_string(),
        "-p".to_string(),
        port.to_string(),
        format!("{user}@{host}"),
    ]
}

/// The fixed `scp` options (no positionals). `scp` uses `-P` for the port and
/// supports a `--` terminator, which [`scp_command`] adds before the positionals.
fn scp_base_args(port: u16) -> Vec<String> {
    vec![
        "-F".to_string(),
        "none".to_string(),
        "-o".to_string(),
        "BatchMode=yes".to_string(),
        "-P".to_string(),
        port.to_string(),
    ]
}

/// Build the `scp -F none -o BatchMode=yes -P <port> -- <from> <to>` command.
///
/// One builder for both directions (download passes a `user@host:` source and a
/// local dest, upload the reverse), so the option ordering and the `--`
/// terminator that keeps a positional from being read as a flag are stated once.
fn scp_command(port: u16, from: impl AsRef<OsStr>, to: impl AsRef<OsStr>) -> Command {
    let mut command = Command::new("scp");
    command.args(scp_base_args(port));
    command.arg("--");
    command.arg(from);
    command.arg(to);
    command.kill_on_drop(true);
    command
}

/// Single-quote a path for the remote shell.
///
/// Validated inputs contain no `'`, so this is airtight; the `'\''` close-escape
/// is defense-in-depth in case an unvalidated value ever reaches here.
fn sq(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Join the validated absolute `root` with a validated relative `key`.
fn join_root(root: &str, key: &str) -> String {
    if root == "/" {
        format!("/{key}")
    } else {
        format!("{root}/{key}")
    }
}

/// The parent directory of an absolute remote path (for `mkdir -p`).
fn parent_dir(remote: &str) -> &str {
    match remote.rsplit_once('/') {
        Some((dir, _)) if !dir.is_empty() => dir,
        _ => "/",
    }
}

/// A same-directory temp path (`<remote>.tmp-<random>`), so the subsequent `mv`
/// into `<remote>` is atomic. Built from already-validated components.
fn temp_path(remote: &str) -> String {
    format!("{remote}.tmp-{}", random_hex_suffix())
}

/// The `<root>/` prefix stripped from `find` output to yield root-relative keys.
fn list_strip_prefix(root: &str) -> String {
    if root == "/" {
        "/".to_string()
    } else {
        format!("{root}/")
    }
}

/// The keys in `find -print0` output: each path with the `<root>/` prefix
/// stripped, kept when it starts with `prefix`, sorted.
///
/// Split on NUL, never on a newline, which a remote file name can contain.
fn parse_list_output(out: &[u8], root: &str, prefix: &str) -> Vec<String> {
    let strip = list_strip_prefix(root);
    let mut results: Vec<String> = out
        .split(|&b| b == 0)
        .filter(|seg| !seg.is_empty())
        .filter_map(|seg| {
            let abs = String::from_utf8_lossy(seg);
            abs.strip_prefix(&strip).map(ToString::to_string)
        })
        .filter(|rel| rel.starts_with(prefix))
        .collect();
    results.sort();
    results
}

/// `mkdir -p <dir> && cat > <tmp> && mv <tmp> <final>` — atomic upload via a
/// same-dir temp; the bytes arrive on the remote `cat`'s stdin.
fn remote_cmd_upload(dir: &str, tmp: &str, final_path: &str) -> String {
    format!(
        "mkdir -p {} && cat > {} && mv {} {}",
        sq(dir),
        sq(tmp),
        sq(tmp),
        sq(final_path)
    )
}

/// `cat <remote>`.
fn remote_cmd_download(remote: &str) -> String {
    format!("cat {}", sq(remote))
}

/// `test -e <remote>`.
fn remote_cmd_exists(remote: &str) -> String {
    format!("test -e {}", sq(remote))
}

/// `mkdir -p <dir>`.
fn remote_cmd_mkdir(dir: &str) -> String {
    format!("mkdir -p {}", sq(dir))
}

/// `mv <tmp> <final>`.
fn remote_cmd_mv(tmp: &str, final_path: &str) -> String {
    format!("mv {} {}", sq(tmp), sq(final_path))
}

/// `find -H <root> -type f -print0`: every regular file under the root.
///
/// `-H` follows a symlink given as the path itself and no other, so a root
/// that is a link to where the files are lists like a real directory: without
/// it `find` does not descend a path operand that is a symlink, and such a
/// store lists as empty while `cat`, `mv`, and `test -e` all reach its files.
/// A symlink *inside* the root is not followed: a link to a file is not
/// listed, and a linked directory is not descended. POSIX, and in GNU and
/// busybox `find` alike; the paths printed keep the spelling given, so they
/// strip to keys either way.
fn remote_cmd_list(root: &str) -> String {
    format!("find -H {} -type f -print0", sq(root))
}

/// `rm -f <remote>` (missing-is-success).
fn remote_cmd_delete(remote: &str) -> String {
    format!("rm -f {}", sq(remote))
}

/// The `scp` remote positional `user@host:<remote>`.
///
/// The path is **not** single-quoted. Modern `scp` (OpenSSH 9+) defaults to the
/// SFTP protocol and sends the path literally over the wire — quotes would
/// become part of the filename (a real transfer failure on any current host).
/// There is no remote shell to defend against, and `remote` is charset-validated
/// and always absolute (no metacharacter, whitespace, glob, or `~`), so the
/// unquoted path is safe under both SFTP and legacy-`scp` transports.
fn scp_remote_arg(user: &str, host: &str, remote: &str) -> String {
    format!("{user}@{host}:{remote}")
}

/// Validate the on-store key and join it onto the root, yielding the absolute
/// remote path. The [`crate::validate_forge_key`] charset (`[A-Za-z0-9._/-]`,
/// relative, no traversal) contains no shell metacharacters.
fn remote_path(root: &str, key: &str) -> Result<String, StorageError> {
    crate::validate_forge_key(key)?;
    Ok(join_root(root, key))
}

//
// Exec helpers
//

/// Render an exit status as `exit N` or `terminated by signal`.
fn exit_label(status: ExitStatus) -> String {
    status.code().map_or_else(
        || "terminated by signal".to_string(),
        |c| format!("exit {c}"),
    )
}

/// True if remote stderr indicates a missing path.
fn stderr_is_not_found(stderr: &str) -> bool {
    let lower = stderr.to_ascii_lowercase();
    lower.contains("no such file") || lower.contains("not found")
}

/// True if remote/ssh stderr indicates an auth or permission failure.
fn stderr_is_permission_denied(stderr: &str) -> bool {
    stderr.to_ascii_lowercase().contains("permission denied")
}

/// Map a failed read-style command (download / list / exists) to an error.
fn classify_read_failure(path: &str, status: ExitStatus, stderr: &[u8]) -> StorageError {
    let stderr = String::from_utf8_lossy(stderr);
    if stderr_is_not_found(&stderr) {
        StorageError::NotFound {
            backend: BACKEND,
            path: path.to_string(),
        }
    } else if stderr_is_permission_denied(&stderr) {
        StorageError::PermissionDenied {
            backend: BACKEND,
            path: path.to_string(),
        }
    } else {
        StorageError::DownloadFailed {
            backend: BACKEND,
            message: format!("ssh/scp failed ({}): {}", exit_label(status), stderr.trim()),
        }
    }
}

/// Map a failed write-style command (upload / mkdir / mv) to an error.
fn classify_write_failure(path: &str, status: ExitStatus, stderr: &[u8]) -> StorageError {
    let stderr = String::from_utf8_lossy(stderr);
    if stderr_is_permission_denied(&stderr) {
        StorageError::PermissionDenied {
            backend: BACKEND,
            path: path.to_string(),
        }
    } else {
        StorageError::UploadFailed {
            backend: BACKEND,
            message: format!("ssh/scp failed ({}): {}", exit_label(status), stderr.trim()),
        }
    }
}

/// Drain a child's stderr into a bounded buffer on its own task, so the child
/// never blocks writing stderr while we read stdout / write stdin. Best-effort:
/// a read error yields an empty buffer — the exit status is the diagnostic.
fn spawn_drain_stderr(mut stderr: ChildStderr) -> tokio::task::JoinHandle<Vec<u8>> {
    tokio::spawn(async move {
        fuz_sys::capture::read_capped_draining(&mut stderr, STDERR_CAP)
            .await
            .map(|capture| capture.bytes)
            .unwrap_or_default()
    })
}

/// Run a spawned child that streams stdout: capture stdout (capped, killing the
/// child if it exceeds `stdout_cap`) while draining stderr concurrently, then
/// wait, so the child is reaped on every return but a failed read (where
/// `kill_on_drop` ends it). Avoids the stdout/stderr pipe-buffer deadlock. At
/// most `stdout_cap` bytes and one more are held.
async fn run_capture(
    mut child: Child,
    stdout_cap: u64,
) -> std::io::Result<(ExitStatus, Vec<u8>, Vec<u8>, bool)> {
    let Some(mut stdout) = child.stdout.take() else {
        return Err(std::io::Error::other("ssh stdout not piped"));
    };
    let Some(stderr) = child.stderr.take() else {
        return Err(std::io::Error::other("ssh stderr not piped"));
    };
    let stderr_task = spawn_drain_stderr(stderr);
    let capture = fuz_sys::capture::read_capped(&mut stdout, stdout_cap).await?;
    let (out, truncated) = (capture.bytes, capture.exceeded);
    if truncated {
        // We stopped reading stdout; kill the child so `wait` (and the stderr
        // drain) can't block on the full pipe.
        let _ = child.start_kill();
    }
    // Close the read end: a process the child started outlives the kill
    // holding both pipes, and would block on a full stdout — keeping stderr
    // open, and the drain below waiting — rather than fail its next write.
    drop(stdout);
    let status = child.wait().await?;
    let err = stderr_task.await.unwrap_or_default();
    Ok((status, out, err, truncated))
}

/// Write `data` to a spawned child's stdin (stdout expected null) while draining
/// stderr concurrently, then wait. Returns the status and captured stderr.
async fn write_stdin_capture_stderr(
    mut child: Child,
    data: &[u8],
) -> std::io::Result<(ExitStatus, Vec<u8>)> {
    let Some(mut stdin) = child.stdin.take() else {
        return Err(std::io::Error::other("ssh stdin not piped"));
    };
    let Some(stderr) = child.stderr.take() else {
        return Err(std::io::Error::other("ssh stderr not piped"));
    };
    let stderr_task = spawn_drain_stderr(stderr);

    // Write, then close stdin to signal EOF to the remote `cat`. A broken pipe
    // here means the remote failed early — the exit status/stderr below is the
    // real diagnostic, so only surface the write error on an otherwise-clean run.
    let write_res = async {
        stdin.write_all(data).await?;
        stdin.shutdown().await
    }
    .await;
    drop(stdin);

    let status = child.wait().await?;
    let err = stderr_task.await.unwrap_or_default();
    if status.success() {
        write_res?;
    }
    Ok((status, err))
}

#[cfg(test)]
mod tests {
    use super::*;

    //
    // URI parsing
    //

    #[test]
    fn new_parses_full_uri() {
        let s = SshStorage::new("ssh://deploy@vps.example.com:2222/var/www/releases").unwrap();
        assert_eq!(s.user, "deploy");
        assert_eq!(s.host, "vps.example.com");
        assert_eq!(s.port, 2222);
        assert_eq!(s.root, "/var/www/releases");
    }

    #[test]
    fn new_defaults_port_and_trims_trailing_slash() {
        let s = SshStorage::new("ssh://user@host/var/www/releases/").unwrap();
        assert_eq!(s.port, 22);
        assert_eq!(s.root, "/var/www/releases");
    }

    #[test]
    fn new_accepts_canonical_uri() {
        // The canonical accept case: user@host:22/var/www/releases.
        let s = SshStorage::new("ssh://user@host:22/var/www/releases").unwrap();
        assert_eq!(s.user, "user");
        assert_eq!(s.host, "host");
        assert_eq!(s.port, 22);
        assert_eq!(s.root, "/var/www/releases");
    }

    #[test]
    fn new_rejects_missing_user() {
        assert!(SshStorage::new("ssh://host/var/www/releases").is_err());
    }

    #[test]
    fn new_rejects_missing_root() {
        // No path → not absolute.
        assert!(SshStorage::new("ssh://user@host").is_err());
    }

    #[test]
    fn new_rejects_wrong_scheme() {
        assert!(SshStorage::new("http://user@host/path").is_err());
    }

    #[test]
    fn new_rejects_password() {
        assert!(SshStorage::new("ssh://user:secret@host/path").is_err());
    }

    #[test]
    fn new_rejects_port_zero() {
        assert!(SshStorage::new("ssh://user@host:0/path").is_err());
    }

    //
    // Validators — accept
    //

    #[test]
    fn validators_accept_reasonable_values() {
        assert!(validate_host("example.com").is_ok());
        assert!(validate_host("vps-1.example.com").is_ok());
        assert!(validate_host("127.0.0.1").is_ok());
        assert!(validate_user("deploy").is_ok());
        assert!(validate_user("deploy_user").is_ok());
        assert!(validate_user("deploy.user-1").is_ok());
        assert_eq!(
            validate_root("/var/www/releases").unwrap(),
            "/var/www/releases"
        );
        assert_eq!(validate_root("/").unwrap(), "/");
    }

    //
    // Validators — reject injection / metacharacters
    //

    #[test]
    fn host_rejects_option_and_metacharacters() {
        assert!(validate_host("-oProxyCommand=x").is_err()); // leading '-'
        assert!(validate_host("a b").is_err()); // space
        assert!(validate_host("a;b").is_err());
        assert!(validate_host("a|b").is_err());
        assert!(validate_host("$(x)").is_err());
        assert!(validate_host("a`b`").is_err()); // backtick
        assert!(validate_host("a\nb").is_err()); // newline
        assert!(validate_host("a\x01b").is_err()); // control char
        assert!(validate_host("").is_err());
    }

    #[test]
    fn user_rejects_option_and_metacharacters() {
        assert!(validate_user("-oProxyCommand=x").is_err()); // leading '-'
        assert!(validate_user("a b").is_err());
        assert!(validate_user("a;b").is_err());
        assert!(validate_user("a|b").is_err());
        assert!(validate_user("$(x)").is_err());
        assert!(validate_user("a`b`").is_err());
        assert!(validate_user("a\nb").is_err());
        assert!(validate_user("a\x01b").is_err());
        assert!(validate_user("").is_err()); // empty user
    }

    #[test]
    fn root_rejects_traversal_and_metacharacters() {
        assert!(validate_root("relative/path").is_err()); // not absolute
        assert!(validate_root("/a/../b").is_err()); // '..' segment
        assert!(validate_root("/a/./b").is_err()); // '.' segment
        assert!(validate_root("/a b").is_err()); // space
        assert!(validate_root("/a;b").is_err());
        assert!(validate_root("/a|b").is_err());
        assert!(validate_root("/a$(x)").is_err());
        assert!(validate_root("/a`b`").is_err());
        assert!(validate_root("/a'b").is_err()); // single quote
        assert!(validate_root("/a\nb").is_err()); // newline
        assert!(validate_root("/a\x01b").is_err()); // control char
    }

    //
    // Base args (option ordering, `--`, destination shape)
    //

    #[test]
    fn ssh_base_args_are_options_first_then_destination() {
        let args = ssh_base_args("deploy", "vps.example.com", 2222);
        assert_eq!(
            args,
            vec![
                "-F".to_string(),
                "none".to_string(),
                "-o".to_string(),
                "BatchMode=yes".to_string(),
                "-p".to_string(),
                "2222".to_string(),
                "deploy@vps.example.com".to_string(),
            ]
        );
        // Options are present, and the destination is last and never `-`-leading.
        assert!(args.iter().any(|a| a == "-F") && args.iter().any(|a| a == "none"));
        assert!(args.iter().any(|a| a == "BatchMode=yes"));
        let dest = args.last().unwrap();
        assert_eq!(dest, "deploy@vps.example.com");
        assert!(!dest.starts_with('-'));
    }

    #[test]
    fn scp_download_argv_has_options_then_dashdash_then_positionals() {
        let remote = scp_remote_arg("deploy", "vps.example.com", "/var/www/releases/x.tar.gz");

        // Read the argv off the real builder, not a hand-rolled replica, so the
        // ordering guarantees below are asserted about the command actually run.
        let command = scp_command(2222, &remote, "/local/dest");
        let argv: Vec<String> = command
            .as_std()
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();

        // Port flag is `-P` for scp.
        assert!(argv.iter().any(|a| a == "-P"));
        assert!(argv.iter().any(|a| a == "-F") && argv.iter().any(|a| a == "none"));
        assert!(argv.iter().any(|a| a == "BatchMode=yes"));

        // `--` precedes the positionals.
        let dd = argv.iter().position(|a| a == "--").unwrap();
        let src = argv.iter().position(|a| a == &remote).unwrap();
        assert!(dd < src, "`--` must come before the remote positional");
        let dest_pos = argv.iter().position(|a| a == "/local/dest").unwrap();
        assert!(src < dest_pos, "remote source precedes the local dest");

        // The remote source starts with the validated user (never `-`); the path
        // portion is unquoted (SFTP mode sends it literally over the wire, so a
        // quote would become part of the filename).
        assert_eq!(remote, "deploy@vps.example.com:/var/www/releases/x.tar.gz");
        assert!(!remote.contains('\''), "scp remote path must not be quoted");
        assert!(!remote.starts_with('-'));
    }

    //
    // Remote command construction (single-quoting)
    //

    #[test]
    fn sq_wraps_and_escapes() {
        assert_eq!(sq("/var/www/releases/x"), "'/var/www/releases/x'");
        // Defense-in-depth: an embedded quote is close-escaped (never reached
        // for validated inputs, but airtight if it were).
        assert_eq!(sq("a'b"), "'a'\\''b'");
    }

    #[test]
    fn remote_cmd_builders_single_quote_paths() {
        assert_eq!(
            remote_cmd_upload("/d", "/d/f.tmp-ab", "/d/f"),
            "mkdir -p '/d' && cat > '/d/f.tmp-ab' && mv '/d/f.tmp-ab' '/d/f'"
        );
        assert_eq!(remote_cmd_download("/d/f"), "cat '/d/f'");
        assert_eq!(remote_cmd_exists("/d/f"), "test -e '/d/f'");
        assert_eq!(remote_cmd_mkdir("/d"), "mkdir -p '/d'");
        assert_eq!(remote_cmd_mv("/d/t", "/d/f"), "mv '/d/t' '/d/f'");
        assert_eq!(remote_cmd_list("/root"), "find -H '/root' -type f -print0");
        assert_eq!(remote_cmd_delete("/d/f"), "rm -f '/d/f'");
    }

    /// The listing command, run as the remote shell would run it, against a
    /// root that is a symlink to the directory holding the files: it lists
    /// what the real root lists. A symlink inside the root is not followed —
    /// a link to a file is not listed, a linked directory is not descended.
    #[test]
    fn the_list_command_follows_a_symlinked_root_and_nothing_inside_it() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        std::fs::create_dir_all(real.join("tools/fuzd")).unwrap();
        std::fs::write(real.join("latest.json"), b"{}").unwrap();
        std::fs::write(real.join("tools/fuzd/latest.json"), b"{}").unwrap();
        // Inside the root: a link to a file, and a link to a directory that
        // holds one.
        let elsewhere = dir.path().join("elsewhere");
        std::fs::create_dir(&elsewhere).unwrap();
        std::fs::write(elsewhere.join("outside.json"), b"{}").unwrap();
        std::os::unix::fs::symlink(real.join("latest.json"), real.join("linked.json")).unwrap();
        std::os::unix::fs::symlink(&elsewhere, real.join("tools/linked")).unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let list = |root: &Path, prefix: &str| {
            let root = root.to_str().unwrap();
            let output = std::process::Command::new("sh")
                .args(["-c", &remote_cmd_list(root)])
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            parse_list_output(&output.stdout, root, prefix)
        };
        let whole = ["latest.json", "tools/fuzd/latest.json"];
        assert_eq!(list(&real, ""), whole);
        assert_eq!(list(&link, ""), whole);
        assert_eq!(list(&link, "tools/fuzd/"), ["tools/fuzd/latest.json"]);
        assert_eq!(list(&link, "tools/linked/"), [""; 0]);
    }

    /// Keys come out of the listing NUL-split, stripped of the root, filtered
    /// by the prefix, and sorted; a path that is not under the root is dropped.
    #[test]
    fn list_output_parses_to_sorted_root_relative_keys() {
        let out = b"/r/tools/zap/b\0/r/a\nb\0/r/tools/zap/a\0/elsewhere/x\0/r\0";
        assert_eq!(
            parse_list_output(out, "/r", ""),
            ["a\nb", "tools/zap/a", "tools/zap/b"]
        );
        assert_eq!(
            parse_list_output(out, "/r", "tools/zap/"),
            ["tools/zap/a", "tools/zap/b"]
        );
        assert_eq!(parse_list_output(b"/a\0/b/c\0", "/", "b/"), ["b/c"]);
        assert_eq!(parse_list_output(b"", "/r", ""), [""; 0]);
    }

    //
    // Path joining / stripping
    //

    #[test]
    fn join_and_parent_and_strip() {
        assert_eq!(
            join_root("/var/www/releases", "a/b.txt"),
            "/var/www/releases/a/b.txt"
        );
        assert_eq!(join_root("/", "a.txt"), "/a.txt");
        assert_eq!(
            parent_dir("/var/www/releases/a/b.txt"),
            "/var/www/releases/a"
        );
        assert_eq!(parent_dir("/b.txt"), "/");
        assert_eq!(list_strip_prefix("/var/www/releases"), "/var/www/releases/");
        assert_eq!(list_strip_prefix("/"), "/");
    }

    //
    // Key validation flows through remote_path
    //

    #[test]
    fn remote_path_validates_key_and_joins() {
        assert_eq!(
            remote_path("/var/www/releases", "tools/zap/latest.json").unwrap(),
            "/var/www/releases/tools/zap/latest.json"
        );
        // A traversal / metacharacter key is rejected by validate_forge_key.
        assert!(remote_path("/root", "../etc/passwd").is_err());
        assert!(remote_path("/root", "/abs").is_err());
        assert!(remote_path("/root", "a b").is_err()); // space
        assert!(remote_path("/root", "a;b").is_err());
    }

    #[test]
    fn temp_path_is_same_dir_sibling() {
        let tmp = temp_path("/var/www/releases/x.tar.gz");
        assert!(tmp.starts_with("/var/www/releases/x.tar.gz.tmp-"));
        assert_eq!(parent_dir(&tmp), "/var/www/releases");
    }

    //
    // Error classification (remote stderr → typed error; exit label)
    //

    #[test]
    fn stderr_predicates_match_remote_messages() {
        // Not-found — both remote phrasings, case-insensitive.
        assert!(stderr_is_not_found("cat: /d/f: No such file or directory"));
        assert!(stderr_is_not_found("find: '/root': not found"));
        assert!(stderr_is_not_found("NO SUCH FILE"));
        assert!(!stderr_is_not_found("Permission denied"));
        assert!(!stderr_is_not_found(""));
        // Permission denied — case-insensitive.
        assert!(stderr_is_permission_denied("bash: /d/f: Permission denied"));
        assert!(stderr_is_permission_denied("PERMISSION DENIED"));
        assert!(!stderr_is_permission_denied("No such file or directory"));
        assert!(!stderr_is_permission_denied(""));
    }

    #[test]
    fn exit_label_renders_code_and_signal() {
        use std::os::unix::process::ExitStatusExt;
        // A normal exit code N is encoded as N<<8 in the wait status.
        assert_eq!(exit_label(ExitStatus::from_raw(2 << 8)), "exit 2");
        assert_eq!(exit_label(ExitStatus::from_raw(0)), "exit 0");
        // Termination by signal has no exit code.
        assert_eq!(exit_label(ExitStatus::from_raw(9)), "terminated by signal");
    }

    #[test]
    fn ssh_op_routes_transport_failures_to_the_matching_variant() {
        // Transport-level failures (couldn't exec, pipe io) carry no read/write
        // character of their own — they inherit the operation's. This is the
        // routing every ssh/scp call site shares.
        let e = std::io::Error::other("boom");

        match SshOp::Read.spawn_failed("ssh", &e) {
            StorageError::DownloadFailed { message, .. } => {
                assert_eq!(message, "failed to run ssh: boom");
            }
            other => panic!("expected DownloadFailed, got {other:?}"),
        }
        match SshOp::Write.spawn_failed("scp", &e) {
            StorageError::UploadFailed { message, .. } => {
                assert_eq!(message, "failed to run scp: boom");
            }
            other => panic!("expected UploadFailed, got {other:?}"),
        }
        match SshOp::Read.io_failed(&e) {
            StorageError::DownloadFailed { message, .. } => {
                assert_eq!(message, "ssh io error: boom");
            }
            other => panic!("expected DownloadFailed, got {other:?}"),
        }
        match SshOp::Write.io_failed(&e) {
            StorageError::UploadFailed { message, .. } => {
                assert_eq!(message, "ssh io error: boom");
            }
            other => panic!("expected UploadFailed, got {other:?}"),
        }
    }

    #[test]
    fn classify_read_failure_maps_stderr_to_variant() {
        use std::os::unix::process::ExitStatusExt;
        let exit1 = ExitStatus::from_raw(1 << 8);
        // "No such file" → NotFound (the missing-key path the round-trip test hits).
        assert!(matches!(
            classify_read_failure("k", exit1, b"cat: /d/k: No such file or directory"),
            StorageError::NotFound { .. }
        ));
        // "Permission denied" → PermissionDenied.
        assert!(matches!(
            classify_read_failure("k", exit1, b"Permission denied"),
            StorageError::PermissionDenied { .. }
        ));
        // Anything else → DownloadFailed carrying the exit label + trimmed stderr.
        match classify_read_failure("k", ExitStatus::from_raw(3 << 8), b"  boom  ") {
            StorageError::DownloadFailed { message, .. } => {
                assert!(message.contains("exit 3"), "message: {message}");
                assert!(message.contains("boom") && !message.contains("  boom  "));
            }
            other => panic!("expected DownloadFailed, got {other:?}"),
        }
    }

    //
    // `download_to_file` against a stand-in `scp`, in a child process: the
    // program is found through `PATH`, which a test cannot set for itself.
    //

    /// Names the directory the child half works in.
    const SCP_CHILD_DIR_ENV: &str = "FUZ_STORAGE_TEST_SCP_CHILD_DIR";

    /// A stand-in `scp`: fails as `scp` does for a remote file that is not
    /// there (`missing` in the source), and otherwise writes part of a file to
    /// its destination before failing with a dropped connection.
    const FAKE_SCP: &str = r#"#!/bin/sh
for last; do :; done
case "$*" in
	*missing*)
		echo "scp: /srv/releases/missing.tar.gz: No such file or directory" >&2
		exit 1
		;;
esac
printf 'partial' >"$last"
echo "scp: Connection closed" >&2
exit 255
"#;

    /// Helper for `a_failed_scp_leaves_nothing_at_dest`, run in a subprocess
    /// whose `PATH` leads to [`FAKE_SCP`].
    #[tokio::test]
    #[ignore = "subprocess helper for a_failed_scp_leaves_nothing_at_dest"]
    async fn scp_download_child() {
        let Ok(dir) = std::env::var(SCP_CHILD_DIR_ENV) else {
            return;
        };
        let dest = Path::new(&dir).join("out.bin");
        let storage = SshStorage::new("ssh://deploy@vps.example.com/srv/releases").unwrap();

        // The transfer started and failed: what it left is unlinked.
        let err = storage
            .download_to_file("fuz.tar.gz", &dest)
            .await
            .unwrap_err();
        assert!(
            matches!(&err, StorageError::DownloadFailed { message, .. }
                if message == "ssh/scp failed (exit 255): scp: Connection closed"),
            "{err:?}"
        );
        assert!(!dest.exists(), "partial download left behind");

        // The remote file is not there: a file already at `dest` goes too.
        std::fs::write(&dest, b"already here").unwrap();
        let err = storage
            .download_to_file("missing.tar.gz", &dest)
            .await
            .unwrap_err();
        assert!(matches!(err, StorageError::NotFound { .. }), "{err:?}");
        assert!(!dest.exists(), "dest kept after a failed scp");
        std::fs::write(Path::new(&dir).join("child-ran"), b"").unwrap();
    }

    /// A failed `download_to_file` unlinks `dest`, so a caller never sees a
    /// partial download — after any failure, since nothing tells this backend
    /// whether `scp` had opened it. So a file already at `dest` does not
    /// survive a missing remote file here, as it does on the other backends.
    #[tokio::test]
    async fn a_failed_scp_leaves_nothing_at_dest() {
        let dir = run_child_with_stand_in("scp", FAKE_SCP, "ssh::tests::scp_download_child").await;
        // The child ran both halves, rather than returning at its guard.
        assert!(dir.path().join("child-ran").exists());
    }

    /// Run the `#[ignore]` test `child_test` of this binary in a subprocess
    /// whose `PATH` leads to `script` installed as `program`, with
    /// [`SCP_CHILD_DIR_ENV`] naming the directory returned. Panics unless the
    /// subprocess passes.
    async fn run_child_with_stand_in(
        program: &str,
        script: &str,
        child_test: &str,
    ) -> tempfile::TempDir {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("bin");
        std::fs::create_dir(&bin).unwrap();
        let stand_in = bin.join(program);
        std::fs::write(&stand_in, script).unwrap();
        std::fs::set_permissions(&stand_in, std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = std::env::join_paths(
            std::iter::once(bin).chain(std::env::split_paths(&std::env::var_os("PATH").unwrap())),
        )
        .unwrap();

        let exe = std::env::current_exe().unwrap();
        let output = Command::new(exe)
            .args(["--ignored", "--exact", child_test])
            .env(SCP_CHILD_DIR_ENV, dir.path())
            .env("PATH", path)
            .output()
            .await
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        dir
    }

    //
    // The buffered reads against a stand-in `ssh`, in a child process for the
    // same reason.
    //

    /// Bytes the stand-in `ssh` sends for a `flood` key: far more than a pipe
    /// holds, so a stand-in that sent all of it had a reader taking all of it.
    const SSH_FLOOD_BYTES: u64 = 64 * 1024 * 1024;

    /// How long the capped read of a `stall` key may take. Far below the
    /// stand-in's `sleep`, so a read that waits for the child to exit by
    /// itself fails here.
    const SSH_STALL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

    /// A stand-in `ssh`, answering the remote `cat` its last argument names:
    /// for a `flood` key, [`SSH_FLOOD_BYTES`] of body and then — only if every
    /// byte was taken — a `flood-sent` marker; for a `stall` key, the same
    /// body with the closed pipe ignored, after which the stand-in becomes a
    /// `sleep` that outlasts [`SSH_STALL_TIMEOUT`]; for a `missing` key, what
    /// `cat` prints for a file that is not there; otherwise a ten-byte body.
    /// The flood is written by a process the stand-in starts, which outlives
    /// a kill of the stand-in itself.
    const FAKE_SSH: &str = r#"#!/bin/sh
for last; do :; done
case "$last" in
	*flood*)
		head -c 67108864 /dev/zero && : >"$FUZ_STORAGE_TEST_SCP_CHILD_DIR/flood-sent"
		;;
	*stall*)
		trap '' PIPE
		head -c 67108864 /dev/zero 2>/dev/null
		exec sleep 120
		;;
	*missing*)
		echo "cat: /srv/releases/missing.json: No such file or directory" >&2
		exit 1
		;;
	*)
		printf '0123456789'
		;;
esac
"#;

    /// Helper for `ssh_download_capped_stops_reading_at_the_cap`, run in a
    /// subprocess whose `PATH` leads to [`FAKE_SSH`].
    #[tokio::test]
    #[ignore = "subprocess helper for ssh_download_capped_stops_reading_at_the_cap"]
    async fn ssh_download_capped_child() {
        let Ok(dir) = std::env::var(SCP_CHILD_DIR_ENV) else {
            return;
        };
        let storage = SshStorage::new("ssh://deploy@vps.example.com/srv/releases").unwrap();

        // A body at the cap is returned whole; one byte past it is refused.
        assert_eq!(
            storage.download_capped("latest.json", 10).await.unwrap(),
            b"0123456789"
        );
        let err = storage.download_capped("latest.json", 9).await.unwrap_err();
        assert!(
            matches!(&err, StorageError::TooLarge { backend: StorageBackendKind::Ssh, path, size: 10, max: 9 }
                if path == "latest.json"),
            "{err:?}"
        );
        let err = storage
            .download_capped("missing.json", 10)
            .await
            .unwrap_err();
        assert!(matches!(err, StorageError::NotFound { .. }), "{err:?}");

        // A flood is refused at the first byte past the cap: the call returns
        // with the stand-in reaped and nothing waiting on its pipes, and the
        // size reported is the cap's, not the body's.
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(60),
            storage.download_capped("flood.json", 1024),
        )
        .await
        .expect("a bounded read returns at the first overrun");
        match result {
            Err(StorageError::TooLarge { size, max, .. }) => {
                assert_eq!((size, max), (1025, 1024));
            }
            other => panic!(
                "expected TooLarge, got {:?}",
                other.map(|bytes| bytes.len())
            ),
        }
        // The body was not taken: the stand-in never got to the end of it.
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert!(
            !Path::new(&dir).join("flood-sent").exists(),
            "the whole flood was read"
        );

        // A stand-in that ignores the closed pipe and stays alive is ended
        // by the kill: the call returns at the overrun with the child reaped,
        // not when the child would have exited by itself.
        let result = tokio::time::timeout(
            SSH_STALL_TIMEOUT,
            storage.download_capped("stall.json", 1024),
        )
        .await
        .expect("an overrun kills the child");
        assert!(
            matches!(
                result,
                Err(StorageError::TooLarge {
                    size: 1025,
                    max: 1024,
                    ..
                })
            ),
            "{:?}",
            result.map(|bytes| bytes.len())
        );

        // The uncapped read takes all of it.
        let body = storage.download("flood.json").await.unwrap();
        assert_eq!(body.len() as u64, SSH_FLOOD_BYTES);
        assert!(Path::new(&dir).join("flood-sent").exists());
        std::fs::write(Path::new(&dir).join("child-ran"), b"").unwrap();
    }

    /// `download_capped` holds its bound on this side: against a host that
    /// sends far more than `max`, it stops reading at the first byte past it,
    /// ends the `ssh` child, and refuses with `TooLarge` — rather than taking
    /// the body and then measuring it.
    #[tokio::test]
    async fn ssh_download_capped_stops_reading_at_the_cap() {
        let dir =
            run_child_with_stand_in("ssh", FAKE_SSH, "ssh::tests::ssh_download_capped_child").await;
        assert!(dir.path().join("child-ran").exists());
    }

    /// What `ssh` prints when the host's key is not the one in `known_hosts`.
    const CHANGED_HOST_KEY: &str = "\
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!
Someone could be eavesdropping on you right now (man-in-the-middle attack)!
It is also possible that a host key has just been changed.
The fingerprint for the ED25519 key sent by the remote host is
SHA256:V6mUfxxZzuE4YHUCKC0JAhPTHZVZcgGv0aKUrZ1p0tw.
Please contact your system administrator.
Add correct host key in /home/deploy/.ssh/known_hosts to get rid of this message.
Offending ED25519 key in /home/deploy/.ssh/known_hosts:12
  remove with:
  ssh-keygen -f '/home/deploy/.ssh/known_hosts' -R 'vps.example.com'
Host key for vps.example.com has changed and you have requested strict checking.
Host key verification failed.
";

    /// A changed host key fails every command with a warning whose last lines
    /// are the ones to act on — which `known_hosts` entry, and that the check
    /// is what failed. The error's message shows them: the warning whole, and
    /// still its end when a login banner of several kilobytes is printed ahead of it.
    #[test]
    fn a_changed_host_key_error_shows_the_lines_that_say_what_failed() {
        use std::os::unix::process::ExitStatusExt;
        let exit255 = ExitStatus::from_raw(255 << 8);
        let last_lines = "Offending ED25519 key in /home/deploy/.ssh/known_hosts:12\\n  \
                          remove with:\\n  ssh-keygen -f '/home/deploy/.ssh/known_hosts' -R \
                          'vps.example.com'\\nHost key for vps.example.com has changed and you \
                          have requested strict checking.\\nHost key verification failed.";
        let banner = "Authorized use only. All activity is monitored and logged.\n".repeat(200);
        let behind_a_banner = format!("{banner}{CHANGED_HOST_KEY}");

        for stderr in [CHANGED_HOST_KEY, behind_a_banner.as_str()] {
            for error in [
                classify_read_failure("latest.json", exit255, stderr.as_bytes()),
                classify_write_failure("latest.json", exit255, stderr.as_bytes()),
            ] {
                let message = error.to_string();
                assert!(
                    matches!(
                        error,
                        StorageError::DownloadFailed { .. } | StorageError::UploadFailed { .. }
                    ),
                    "{message}"
                );
                assert!(message.contains("ssh/scp failed (exit 255): "), "{message}");
                assert!(message.ends_with(last_lines), "{message}");
                assert_eq!(message.lines().count(), 1, "{message}");
            }
        }
        // Without a banner the warning is not cut at all.
        let whole = classify_read_failure("k", exit255, CHANGED_HOST_KEY.as_bytes()).to_string();
        assert!(
            whole.contains("WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!")
                && !whole.contains("bytes not shown"),
            "{whole}"
        );
        // Behind one, the cut is marked.
        let cut = classify_read_failure("k", exit255, behind_a_banner.as_bytes()).to_string();
        assert!(cut.contains("bytes not shown ...] "), "{cut}");
    }

    #[test]
    fn classify_write_failure_maps_stderr_to_variant() {
        use std::os::unix::process::ExitStatusExt;
        let exit1 = ExitStatus::from_raw(1 << 8);
        // Write path: permission denied is distinguished; everything else is
        // UploadFailed (no NotFound branch — a missing parent is `mkdir -p`'s job).
        assert!(matches!(
            classify_write_failure("k", exit1, b"mkdir: Permission denied"),
            StorageError::PermissionDenied { .. }
        ));
        assert!(matches!(
            classify_write_failure("k", exit1, b"No such file or directory"),
            StorageError::UploadFailed { .. }
        ));
    }
}
