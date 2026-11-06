//! One-shot config evaluation through a pinned `fgro eval`.
//!
//! [`eval_module`] evaluates a TypeScript or JS config module to JSON data by
//! running `fgro eval` — Gro's runtime, a separate binary — once, and returns
//! the value with the module graph the run loaded. The shared primitive for
//! evaluating a config in a Rust parent; zap's `zap.ts` convergence configs
//! are its consumer.
//!
//! **One-shot, not warm.** Each call is a fresh process: crash-isolated, and it
//! sees current files with no import cache to go stale.
//!
//! **The walls are fgro's.** What evaluated code can reach is decided inside
//! `fgro eval`, not here: a kernel box (Landlock and seccomp) that admits reads
//! under the project root and the packages linked into it and nothing else — no
//! write, no network, no exec, no `/proc` — installed before any of the
//! module's code runs; no environment variable read for its own settings; every
//! `import()` refused; the clock, randomness, and timers refused
//! (`determinism: deny`); a capped heap and process memory; and its own
//! timeout. fgro's eval documentation is the reference for those rules. This
//! crate is a thin client: it chooses which binary runs, where, with what, and
//! how far its output is believed.
//!
//! **The sequence.** [`eval_module`]:
//!
//! 1. Canonicalizes the config path ([`EvalError::ConfigNotFound`]) and refuses
//!    one that isn't UTF-8 ([`EvalError::ConfigPathNotUtf8`]), which fgro
//!    refuses as an argument.
//! 2. Reads the effective uid and `SUDO_UID` and `SUDO_GID`, once: the next
//!    two steps both take this one reading.
//! 3. Settles the trust root (§ The trust root), or refuses
//!    ([`EvalError::TrustRoot`]).
//! 4. Settles who `fgro` runs as (§ Who it runs as), or refuses
//!    ([`EvalError::RunAs`]).
//! 5. Verifies the `fgro` pin (§ The `fgro` pin) and holds the binary open.
//! 6. `fstat`s the held descriptor again right before the spawn, and refuses
//!    when its stat key moved since the pin
//!    ([`FgroProblem::ChangedSincePin`]).
//! 7. Spawns it (§ The spawn), writes the driver to its stdin, and reads its
//!    stdout as one envelope (§ The envelope).
//!
//! **The trust root.** The canonical config's directory must not be writable by
//! every user ([`TrustRootProblem::WorldWritableConfigDir`]), nor the config file
//! itself ([`TrustRootProblem::WorldWritableConfigFile`]) — the canonical file's
//! mode, since that is the file that runs and a link's own mode is always `0777`;
//! who owns either is not checked. From the directory, walk up through the
//! directories an owner holds and no other user can write (no `o+w` bit),
//! stopping before the first that fails, and reading nothing in it. The owner is
//! the process's effective uid; under euid 0 with `SUDO_UID` set to a decimal
//! uid — `sudo zap …` — that uid too, so a user's project passes the walk under
//! `sudo`, where root alone would stop at the user's first directory. The root is
//! the first directory in that walk, outside every `node_modules` segment, whose
//! `package.json` holds more than a type marker (keys all within `"type"` and
//! `"sideEffects"`, such as a `{"type": "module"}` in a subdirectory). fgro
//! finds its project root by the same `package.json` rule, but its walk stops
//! only at a world-writable directory, not at another user's. So a walk that
//! finds no such `package.json` refuses the eval before the pin or the spawn:
//! one that stopped below a directory refuses naming it and why
//! ([`TrustRootProblem::WalkStopped`]) — fgro would look past another user's, and could
//! take a project, and run its packages' code, from a directory this process
//! doesn't trust — and one that reached the filesystem root refuses as having
//! no project ([`TrustRootProblem::NoProject`]), which fgro refuses too.
//! The envelope's project must then be this root (§ The envelope), which
//! catches a disk that changed between the two walks.
//! Every `package.json` the walk passes is read, and one
//! it can't read or that isn't valid — not a JSON object, a `"name"` or `"type"`
//! that isn't a string — refuses the eval, named
//! ([`TrustRootProblem::InvalidPackageJson`]). So does one that is a FIFO,
//! socket or device, found by a stat before any open, and a link to nothing or a
//! path through a non-directory, which gro's resolver treats as no `package.json`
//! at all: here they fail closed. The walk is read before fgro runs, and fgro
//! reads the disk again; the envelope's project check catches a root that moved
//! in between. The ownership bound does not inspect ACLs, and `SUDO_UID` is read
//! from the environment as given, which for a root process is root's to set.
//!
//! **Who it runs as.** `fgro` never runs as root, and a root eval drops only to
//! the user who owns the trust root:
//!
//! - **Not root** (effective uid other than `0`): the caller's own uid, with no
//!   drop; `SUDO_UID` and `SUDO_GID` are ignored.
//! - **Root under `sudo`, invoked by the project's owner** (`SUDO_UID` a
//!   decimal uid other than `0`, the trust root directory's owner): that user,
//!   with `SUDO_GID` as the group. A `SUDO_GID` that is unset or not a decimal
//!   gid refuses ([`RunAsProblem::SudoGidUnusable`]).
//! - **Root otherwise** (`SUDO_UID` unset, `0`, not a decimal uid, or a user
//!   other than the owner): the trust root directory's owner, with that user's
//!   primary group from the passwd database. Refused when root owns it
//!   ([`RunAsProblem::RootOwnedProject`]).
//!
//! Why only the owner: `fgro` is dumpable (its box refuses `PR_SET_DUMPABLE`),
//! so any process of the uid it runs as can attach to it — `ptrace`, or its
//! descriptors through `/proc/<pid>/fd` — and act with what it holds. So it
//! runs only as a user who could already edit the config. A `sudo` invocation
//! over a project that user doesn't own — a restricted `sudo` rule granting
//! `zap` over a root-owned config, say — is never run as the invoking user:
//! a root-owned project is refused, and another user's runs as that user.
//!
//! The group under `sudo` is `SUDO_GID`, not the passwd primary group: it is
//! the group the owner ran `sudo` with, so the eval keeps the identity the user
//! had before `sudo` (less the supplementary groups), as it would running the
//! eval without it. With no `sudo` there is no such session to follow, and the
//! passwd primary group is the user's own default. A drop to group `0` is
//! refused either way ([`RunAsProblem::RootGroup`]): the child would keep what
//! root's group can read.
//!
//! The user it runs as, dropped to or not, is looked up in the passwd database
//! (`getpwuid_r`), and the trust root must be neither that user's home
//! directory nor a directory holding it, compared canonically
//! ([`RunAsProblem::HomeProject`]): `fgro`'s box admits the whole project, and a
//! home as the project is everything the user keeps. A user with no entry, or a
//! lookup that fails, refuses, since neither the home nor the group is known
//! ([`RunAsProblem::NoPasswdEntry`], [`RunAsProblem::PasswdUnreadable`]). The
//! lookup is the C library's: a glibc build follows `nsswitch.conf`, while a
//! static musl build reads `/etc/passwd` and nscd only, so a user from LDAP,
//! sssd, or systemd-homed can have no entry there. `fgro` reads no environment
//! and no passwd database, so it can't make this check itself.
//!
//! A drop sets both the uid and the gid on the spawn, with no supplementary
//! groups: std clears them (`setgroups(0)`) before the `setuid`. Inside a user
//! namespace where `setgroups` is denied, std ignores that `EPERM` and the
//! supplementary groups stay. Under a rootless `unshare -r` it fails closed
//! either way: the unsharing user's own files read as root's, so their projects
//! are refused as root-owned, and an unmapped user's read as owned by the
//! overflow uid `65534`, so the eval drops to it and the spawn fails (`EINVAL`
//! from the `setuid`), naming "as uid 65534". The working directory
//! is entered after the drop, so every directory from `/` to the trust root,
//! the root included, must be searchable by the dropped user and group alone,
//! read from the mode bits (ACLs are not read); one that isn't refuses up
//! front, naming it ([`RunAsProblem::NotSearchable`]), rather than failing the
//! spawn. The exec goes through `/proc/self/fd/<n>`, which needs no search of
//! the binary's directories, but the dropped user needs execute permission on
//! the `fgro` file itself; a spawn that fails names the uid and gid it ran as
//! ([`EvalError::FgroSpawn`]). The kernel lets a process follow its own
//! descriptors' links whatever its credentials, so the exec through the held
//! descriptor still works after the drop. The drop's own files are the user's
//! to read: a config, or a package in the project, that user can't read fails
//! the eval as `fgro` reports it.
//!
//! **The spawn.** The pinned binary is exec'd through its held descriptor
//! (`/proc/self/fd/<n>`), with `argv[0]` `fgro` and the arguments
//! `eval <canonical config> --driver - --graph --timeout <ms>`:
//!
//! - **Working directory**: the trust root.
//! - **User**: as settled (§ Who it runs as); under root, the dropped uid and
//!   gid with no supplementary groups.
//! - **Environment**: cleared, then `TZ=UTC` alone, which fgro requires. fgro
//!   reads no variable for its own settings, and evaluated code can't read the
//!   environment, so nothing of the caller's is passed.
//! - **Descriptors**: stdin, stdout, and stderr, each a pipe. Everything else
//!   this process holds is close-on-exec (std and tokio open that way, and the
//!   pinned binary's descriptor closes as the exec completes), and fgro closes
//!   any inherited descriptor above stderr before it opens anything.
//! - **Process group**: its own, so a kill reaches anything it started, and a
//!   terminal's Ctrl-C, which signals the foreground group, doesn't reach it:
//!   its own timeout and this crate's backstop bound it instead.
//!
//! The driver ([`EvalRequest::driver_js`]) is written to stdin, which is then
//! closed, while stdout and stderr are read; all three run concurrently, so a
//! child that doesn't read its stdin, or fills stderr, can't stall the others.
//! Both captures are byte-capped: stdout at [`MAX_STDOUT_SIZE`], just above
//! fgro's own envelope cap so an envelope fgro writes always fits, and stderr at
//! `fuz_sys::limits::MAX_CAPTURE_STDERR_SIZE`. Past the stdout cap the group is
//! killed and the eval fails with [`EvalError::OutputTooLarge`]; stderr past its
//! cap is drained and dropped. fgro's own `--timeout` is [`EvalRequest::timeout`], which ends
//! a run as an `eval` failure of kind [`EvalErrorKind::Timeout`]; this crate's
//! wall clock runs [`TIMEOUT_GRACE`] longer, as a backstop for a process that
//! doesn't stop ([`EvalError::Timeout`]). On the backstop, on the stdout cap,
//! and when the caller drops the future mid-eval, the whole process group is
//! sent `SIGKILL` before the child is reaped (so its id can't have been reused
//! by then), and the reap waits at most a few seconds.
//!
//! **The envelope.** fgro writes one JSON object on stdout; the reader fails
//! closed on anything it doesn't know, and each refusal is an
//! [`EvalError::Protocol`] naming the [`ProtocolViolation`], with stderr:
//!
//! - stdout is exactly one JSON object on one line, then at most a newline;
//! - `eval_protocol` is `2`, and a graph's `graph_version` is `1`;
//! - every object is the shape this reader mirrors, with no unknown field;
//! - the exit code agrees with `ok`: `0` with `ok: true`, `1` or `2` with
//!   `ok: false`. Any other exit, or death by a signal, is a crash
//!   ([`EvalError::FgroCrashed`]), whatever stdout holds;
//! - every field fgro always writes is present (`null` where it may be), and
//!   the failure's optional fields are absent rather than `null`;
//! - `entry.id` is the canonical config path, `entry.export` is null, and
//!   `entry.driver_blake3` is the blake3 of the driver sent — except in a
//!   failure fgro hit before reading the driver, which names the `default`
//!   export and no driver hash, and is taken as the failure it reports;
//! - `graph` is present, and under `ok: true` not null, with every module's
//!   `blake3` and `format` set;
//! - `graph.local.project` is the trust root.
//!
//! Stdout that isn't UTF-8 is [`EvalError::NotUtf8`]. An `ok: false` envelope is an
//! [`EvalError::Eval`] carrying fgro's [`EvalErrorKind`], its message, and where
//! it gave them the location, the import, and a hint. An `ok: true` one is an
//! [`EvalOutput`]: the value, parsed and written again with its object keys
//! sorted, so its text depends only on the value, and the typed
//! [`GraphDump`].
//!
//! **What it leaves.** `SUDO_UID` and `SUDO_GID` are believed as given, which
//! for a root process is root's to set; the walk, the drop, and the home check
//! read the disk and the passwd database before `fgro` runs, and are not
//! re-read after. The pin is verified, then re-checked by its stat key right
//! before the spawn, not at the exec: a write in between, or within one
//! timestamp tick of the pin, is not seen (`pin` module docs). The trust root's
//! walk and fgro's own read of the disk are separate reads.
//!
//! **The `fgro` pin.** [`fgro_verify`] opens an `fgro` binary without following
//! a symlinked final component, requires a regular ELF file with no set-ID bit
//! (file capabilities are not checked), checks its blake3
//! against an expected pin, and returns it held open as a [`PinnedFgro`], whose
//! [`exec_path`](PinnedFgro::exec_path) (`/proc/self/fd/<n>`) execs the bytes
//! that were verified. [`fgro_blake3`] computes the pin to record. Both take an
//! optional cache directory that keys a binary's hash by its `fstat` (device,
//! inode, size, mtime, ctime) so an unchanged binary is not re-hashed, caching
//! only a binary whose times are settled well in the past; the directory must be
//! the effective uid's own, and is created or tightened to `0700`
//! ([`establish_cache_dir`]). The `pin` module docs carry the rules and what the
//! pin leaves.

mod envelope;
mod pin;
mod run_as;
mod trust_root;

pub use envelope::{
    DumpConsulted, DumpFormat, DumpImport, DumpLocal, DumpModule, DumpOrigin, DumpReach, DumpRole,
    EvalErrorKind, EvalFailure, GraphDump, ProtocolViolation,
};
pub use pin::{
    FgroProblem, PinCacheDirProblem, PinnedFgro, establish_cache_dir, fgro_blake3, fgro_verify,
};
pub use run_as::{DropBasis, DroppedTo, RunAsProblem};

use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::time::Duration;

use fuz_sys::capture::{CappedCapture, read_capped, read_capped_draining};
use fuz_sys::limits::MAX_CAPTURE_STDERR_SIZE;
use nix::sys::signal::{Signal, killpg};
use nix::unistd::Pid;
use tokio::io::AsyncWriteExt;
use tokio::process::{Child, Command};

use crate::envelope::{Expected, Outcome, read_envelope};
use crate::run_as::{Caller, RunAs};
use crate::trust_root::TrustRootBasis;

/// How much longer than [`EvalRequest::timeout`] the parent waits for `fgro` to
/// exit before it kills the process group itself.
///
/// fgro stops a run at its timeout, but a module load or a builtin call in
/// progress finishes first, so its stop can come seconds late; past this, the
/// process is taken as stuck.
pub const TIMEOUT_GRACE: Duration = Duration::from_secs(5);

/// fgro's cap on its envelope, in bytes, without the trailing newline: fgro
/// replaces an envelope that would pass it with a small failure.
const FGRO_MAX_ENVELOPE_SIZE: u64 = 64 * 1024 * 1024;

/// The most stdout [`eval_module`] reads from `fgro`.
///
/// fgro's envelope cap plus room for its newline and nothing like another
/// envelope, so every envelope fgro can write fits, and anything past it is a
/// process that isn't keeping to the protocol ([`EvalError::OutputTooLarge`]).
pub const MAX_STDOUT_SIZE: u64 = FGRO_MAX_ENVELOPE_SIZE + 1024 * 1024;

/// How long [`eval_module`] waits for a killed child to exit. `SIGKILL` ends a
/// child in well under this; the bound keeps one the kernel cannot end yet from
/// holding the caller past its timeout.
const REAP_TIMEOUT: Duration = Duration::from_secs(5);

/// Which `fgro` binary evaluates, and the blake3 it must hash to.
#[derive(Debug, Clone, Copy)]
pub struct FgroPin<'a> {
    /// The binary itself: not a symlink to it, not a wrapper script.
    pub path: &'a Path,
    /// Its expected blake3, 64 lowercase hex characters ([`fgro_blake3`]).
    pub expected_blake3: &'a str,
    /// The stat-keyed hash cache ([`establish_cache_dir`]); `None` hashes the
    /// binary on every eval.
    pub cache_dir: Option<&'a Path>,
}

/// A one-shot config-eval request.
#[derive(Debug, Clone, Copy)]
pub struct EvalRequest<'a> {
    /// The config module to evaluate. Canonicalized before anything else, and
    /// passed to `fgro` in that form; it must be UTF-8.
    pub config_path: &'a Path,
    /// The driver, an import-free ES module written to `fgro`'s stdin: its
    /// `default` export is called with the config's namespace, and what it
    /// returns is the value (fgro's eval documentation has the contract).
    pub driver_js: &'a str,
    /// The eval's time bound, passed to `fgro` as `--timeout` in milliseconds
    /// (at least `1`). The parent's own clock runs [`TIMEOUT_GRACE`] longer.
    pub timeout: Duration,
    /// The `fgro` binary and its pin.
    pub fgro: FgroPin<'a>,
}

/// The result of a successful [`eval_module`].
#[derive(Debug, Clone)]
pub struct EvalOutput {
    /// The value, as JSON text: parsed from the envelope and written again,
    /// compact, with every object's keys sorted.
    pub value_json: String,
    /// The canonical config path that was evaluated, the envelope's
    /// `entry.id`.
    pub config_path: PathBuf,
    /// The module graph the run loaded, its project the trust root.
    pub graph: GraphDump,
}

/// Why the config's trust root could not be settled, so the eval was refused
/// before `fgro` ran (crate docs § The trust root).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustRootProblem {
    /// Every user can write the config's own directory (its `o+w` bit), so what
    /// sits beside the config — a `package.json`, a `node_modules` — is not the
    /// operator's to vouch for.
    WorldWritableConfigDir,
    /// Every user can write the config file itself (its `o+w` bit, read from the
    /// canonical file), so what it holds is not the operator's to vouch for.
    WorldWritableConfigFile,
    /// A `package.json` in the walk up from the config can't be read or isn't
    /// valid: a link to nothing, a path through a non-directory, not a regular
    /// file, unreadable, too large, not a JSON object, or a `"name"` or `"type"`
    /// that isn't a string. Whether it is a type marker decides the root, so it is
    /// not skipped.
    InvalidPackageJson,
    /// The walk stopped below a directory, for this reason, before it found a
    /// `package.json` that sets the config's project. fgro's own walk would go
    /// on past it, into a directory this process doesn't trust.
    WalkStopped(WalkStop),
    /// The walk reached the filesystem root with no `package.json` that sets the
    /// config's project; fgro evaluates only a project's own module.
    NoProject,
}

/// Why the trust root's walk stopped below a directory
/// ([`TrustRootProblem::WalkStopped`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalkStop {
    /// Every user can write it (its `o+w` bit), whoever owns it.
    WorldWritable,
    /// A user other than the walk's owners holds it, or its owner can't be read.
    OtherOwner,
}

/// Errors from a one-shot config eval.
///
/// Thin (variants only) — a binary consumer wraps these and adds the
/// `.hint()`/`.exit_code()` helpers (see the fuz-stack Rust error conventions).
/// Display interpolates the detail, text `fgro` wrote escaped, so a consumer
/// that surfaces these directly (`error.to_string()`) loses nothing.
#[derive(Debug, thiserror::Error)]
pub enum EvalError {
    /// The config file couldn't be resolved on disk (canonicalization failed).
    #[error("config not found: {path} ({source})")]
    ConfigNotFound {
        /// The config path as given by the caller.
        path: String,
        /// The underlying filesystem error.
        #[source]
        source: std::io::Error,
    },

    /// The canonical config path isn't UTF-8, which `fgro` refuses as an
    /// argument. Refused before the spawn.
    #[error("the config path {path} is not UTF-8, which fgro can't take as an argument")]
    ConfigPathNotUtf8 {
        /// The canonical path, lossily decoded.
        path: String,
    },

    /// The config's trust root could not be settled (crate docs § The trust
    /// root), so the eval was refused before `fgro` ran.
    #[error("{}", trust_root_message(path, *problem, offending, reason))]
    TrustRoot {
        /// The config's absolute path.
        path: String,
        /// What is wrong.
        problem: TrustRootProblem,
        /// The directory or `package.json` at fault.
        offending: String,
        /// What is wrong with it: a directory's or the config's mode, why a
        /// `package.json` can't be used, or why the walk stopped.
        reason: String,
    },

    /// Who `fgro` would run as refuses the eval (crate docs § Who it runs as):
    /// root with no user to drop to, an unusable `SUDO_GID`, a drop that keeps
    /// root's group, a project that is the target user's home, or one the
    /// dropped user can't reach. Refused before the pin and the spawn.
    #[error("{}", run_as_message(path, root, problem))]
    RunAs {
        /// The config's absolute path.
        path: String,
        /// The trust root.
        root: String,
        /// What refuses it.
        problem: RunAsProblem,
    },

    /// `fgro` evaluated and reported a failure (`ok: false`): a throwing config,
    /// an import that didn't resolve, a value that isn't data, a read outside
    /// the box, its own timeout. [`EvalFailure::kind`] is the contract to branch
    /// on; the message is fgro's report, for a person.
    #[error("{}", eval_failure_message(path, failure, stderr))]
    Eval {
        /// The evaluated config's absolute path.
        path: String,
        /// What fgro reported.
        failure: Box<EvalFailure>,
        /// fgro's captured stderr: the config's console output, and fgro's own
        /// diagnostics.
        stderr: String,
    },

    /// `fgro` didn't exit within [`EvalRequest::timeout`] plus
    /// [`TIMEOUT_GRACE`], so its process group was killed. A run fgro stopped at
    /// its own timeout is an [`EvalError::Eval`] of kind
    /// [`EvalErrorKind::Timeout`] instead.
    #[error("config evaluation timed out for {path}: fgro did not exit, so it was killed")]
    Timeout {
        /// The evaluated config's absolute path.
        path: String,
    },

    /// `fgro` wrote more stdout than [`MAX_STDOUT_SIZE`],
    /// so its process group was killed at the cap.
    #[error("config evaluation output exceeded {limit} bytes for {path}")]
    OutputTooLarge {
        /// The evaluated config's absolute path.
        path: String,
        /// The stdout byte cap that was exceeded.
        limit: u64,
    },

    /// `fgro`'s stdout and exit code aren't an envelope this reader accepts
    /// (crate docs § The envelope). Nothing it wrote is used.
    #[error("{}", protocol_message(path, violation, stderr))]
    Protocol {
        /// The evaluated config's absolute path.
        path: String,
        /// What failed.
        violation: Box<ProtocolViolation>,
        /// fgro's captured stderr.
        stderr: String,
    },

    /// `fgro` exited with a code other than `0`, `1`, or `2`, or was ended by a
    /// signal: a crash, whatever its stdout holds.
    #[error("{}", crashed_message(path, status, stderr))]
    FgroCrashed {
        /// The evaluated config's absolute path.
        path: String,
        /// How it ended, as the platform describes it (`exit status: 101`,
        /// `signal: 6 (SIGABRT)`).
        status: String,
        /// fgro's captured stderr.
        stderr: String,
    },

    /// An IO error reading the trust root's walk, or communicating with the
    /// `fgro` process.
    #[error("config evaluation IO error: {0}")]
    Io(#[source] std::io::Error),

    /// `fgro` wrote stdout that isn't UTF-8 (an envelope is UTF-8 JSON).
    #[error("fgro wrote non-UTF-8 output for {path}")]
    NotUtf8 {
        /// The evaluated config's absolute path.
        path: String,
    },

    /// The `fgro` binary can't be pinned or run: it is missing, a symlink, not a
    /// regular file, a script or other non-ELF file, set-user-ID or
    /// set-group-ID, or it was written while
    /// being hashed or between the pin and the spawn; or it can't be exec'd
    /// through `/proc/self/fd` because `/proc` doesn't reach it (`pin` module
    /// docs).
    #[error("{}", fgro_unusable_message(path, *problem))]
    FgroUnusable {
        /// The binary's path as given.
        path: String,
        /// What is wrong with it.
        problem: FgroProblem,
    },

    /// Opening, stating, or reading the `fgro` binary failed for a reason
    /// [`EvalError::FgroUnusable`] doesn't name.
    #[error("could not read the fgro binary {path}: {source}")]
    FgroIo {
        /// The binary's path as given.
        path: String,
        /// The underlying filesystem error.
        #[source]
        source: std::io::Error,
    },

    /// The expected `fgro` pin isn't a blake3 as [`fgro_blake3`] writes one: 64
    /// lowercase hex characters. Refused before the binary is opened.
    #[error(
        "the expected fgro pin {} is not a blake3 (64 lowercase hex characters)",
        fuz_sys::text::quoted(&fuz_sys::text::truncate(pin, 80))
    )]
    InvalidPin {
        /// The pin as given.
        pin: String,
    },

    /// The `fgro` binary's blake3 is not its expected pin.
    #[error(
        "the fgro binary {path} does not match its pin: expected blake3 {expected}, found {actual}"
    )]
    PinMismatch {
        /// The binary's path as given.
        path: String,
        /// The pin the caller expected.
        expected: String,
        /// The blake3 of the bytes at the path.
        actual: String,
    },

    /// The pin cache directory breaks its rule ([`establish_cache_dir`]).
    #[error("{}", pin_cache_dir_message(path, *problem, source.as_ref()))]
    PinCacheDir {
        /// The directory as given.
        path: String,
        /// The rule it breaks.
        problem: PinCacheDirProblem,
        /// The filesystem error behind it, where there is one.
        #[source]
        source: Option<std::io::Error>,
    },

    /// Spawning a pinned `fgro` through its held descriptor failed
    /// ([`PinnedFgro::spawn_error`]).
    #[error("{}", fgro_spawn_message(path, *dropped_to, source))]
    FgroSpawn {
        /// The binary's path as given.
        path: String,
        /// The user and group the spawn dropped to from root, if it did.
        dropped_to: Option<DroppedTo>,
        /// The spawn error.
        #[source]
        source: std::io::Error,
    },
}

/// The hint every refusal of a non-binary `fgro` path carries.
const FGRO_BINARY_HINT: &str = "the path must be the fgro binary itself, not a wrapper script \
                                or a link to it";

/// The message of [`EvalError::FgroUnusable`].
fn fgro_unusable_message(path: &str, problem: FgroProblem) -> String {
    match problem {
        FgroProblem::NotFound => format!("the fgro binary {path} does not exist"),
        FgroProblem::Symlink => {
            format!("the fgro binary {path} is a symlink; {FGRO_BINARY_HINT}")
        }
        FgroProblem::NotRegularFile => {
            format!("the fgro binary {path} is not a regular file; {FGRO_BINARY_HINT}")
        }
        FgroProblem::Script => format!(
            "the fgro binary {path} is a script, which can't run through the descriptor its pin \
             was verified on; {FGRO_BINARY_HINT}"
        ),
        FgroProblem::NotElf => {
            format!("the fgro binary {path} is not an ELF binary; {FGRO_BINARY_HINT}")
        }
        FgroProblem::SetId => format!(
            "the fgro binary {path} is set-user-ID or set-group-ID, so it would not run with the \
             ids it is spawned with; clear the bits (chmod u-s,g-s)"
        ),
        FgroProblem::ProcUnavailable => format!(
            "the fgro binary {path} can't be run: it is exec'd through /proc/self/fd, which \
             does not reach it here; mount /proc"
        ),
        FgroProblem::ChangedWhileHashing => format!(
            "the fgro binary {path} changed while it was being hashed, so its pin can't be \
             checked; retry once nothing is writing it"
        ),
        FgroProblem::ChangedSincePin => format!(
            "the fgro binary {path} changed after its pin was checked, so it was not run; \
             retry once nothing is writing it"
        ),
    }
}

/// The message of [`EvalError::PinCacheDir`].
fn pin_cache_dir_message(
    path: &str,
    problem: PinCacheDirProblem,
    source: Option<&std::io::Error>,
) -> String {
    let what = match problem {
        PinCacheDirProblem::Uncreatable => "could not be created (its parent must exist)",
        PinCacheDirProblem::Symlink => "is a symlink",
        PinCacheDirProblem::NotDirectory => "is not a directory",
        PinCacheDirProblem::OtherOwner => "belongs to another user",
        PinCacheDirProblem::Unreadable => "could not be inspected",
        PinCacheDirProblem::Unopenable => "could not be opened as a directory",
        PinCacheDirProblem::Unrestrictable => {
            "is reachable by other users and could not be \
                                               restricted to 0700"
        }
    };
    let detail = source
        .map(|source| format!(" ({source})"))
        .unwrap_or_default();
    format!("refused the fgro pin cache directory {path}: it {what}{detail}")
}

/// The message of [`EvalError::FgroSpawn`]. The held descriptor is an ELF file
/// and `/proc` was checked at the pin, so `ENOENT` from `execve` means the
/// loader it names is missing.
fn fgro_spawn_message(
    path: &str,
    dropped_to: Option<DroppedTo>,
    source: &std::io::Error,
) -> String {
    let user = dropped_to
        .map(|to| format!(" as uid {} (gid {})", to.uid, to.gid))
        .unwrap_or_default();
    match source.kind() {
        std::io::ErrorKind::NotFound => format!(
            "could not run the fgro binary {path}{user} ({source}): the dynamic loader it names \
             is missing; {FGRO_BINARY_HINT}, built for this system"
        ),
        std::io::ErrorKind::PermissionDenied if dropped_to.is_some() => format!(
            "could not run the fgro binary {path}{user}: {source}; the user it drops to from \
             root needs execute permission on the binary"
        ),
        _ => format!("could not run the fgro binary {path}{user}: {source}"),
    }
}

/// The message of [`EvalError::TrustRoot`].
fn trust_root_message(
    path: &str,
    problem: TrustRootProblem,
    offending: &str,
    reason: &str,
) -> String {
    match problem {
        TrustRootProblem::WorldWritableConfigDir => format!(
            "refused to evaluate {path}: its directory {offending} is writable by every user \
             ({reason}), so what sits beside it is not the operator's to vouch for"
        ),
        TrustRootProblem::WorldWritableConfigFile => format!(
            "refused to evaluate {path}: the config file {offending} is writable by every user \
             ({reason}), so what it holds is not the operator's to vouch for"
        ),
        TrustRootProblem::InvalidPackageJson => format!(
            "refused to evaluate {path}: {offending}, which the walk to its project reads, is \
             not a valid package.json: {reason}"
        ),
        TrustRootProblem::WalkStopped(stop) => {
            // fgro's own walk stops at a world-writable directory too, but not at
            // another user's
            let past = match stop {
                WalkStop::OtherOwner => {
                    "fgro would look past that directory, whose contents are not the \
                     operator's to vouch for"
                }
                WalkStop::WorldWritable => {
                    "that directory's contents are not the operator's to vouch for"
                }
            };
            format!(
                "refused to evaluate {path}: no package.json that holds more than \"type\" and \
                 \"sideEffects\" sets its project below {offending}, where the walk up from it \
                 stopped because {reason}; {past} (give the project a package.json of its own)"
            )
        }
        TrustRootProblem::NoProject => format!(
            "refused to evaluate {path}: no package.json that holds more than \"type\" and \
             \"sideEffects\" sets its project between {offending} and {reason}, and fgro \
             evaluates only a project's own module (give the project a package.json)"
        ),
    }
}

/// The message of [`EvalError::RunAs`].
fn run_as_message(path: &str, root: &str, problem: &RunAsProblem) -> String {
    let refused = format!("refused to evaluate {path}");
    match problem {
        RunAsProblem::RootOwnedProject { sudo_uid } => format!(
            "{refused}: it runs as root, and root owns its project {root}{}; fgro runs only as \
             a user who could already edit the config, so there is none to run it as (evaluate \
             it as its owner, or give the project to a non-root user)",
            sudo_uid
                .map(|uid| format!(", not uid {uid}, who invoked sudo"))
                .unwrap_or_default()
        ),
        RunAsProblem::SudoGidUnusable { uid, sudo_gid } => format!(
            "{refused}: SUDO_UID names uid {uid}, its project's owner, but SUDO_GID {}, so the \
             group to run it as is unknown (run it through sudo, which sets both)",
            sudo_gid.as_deref().map_or_else(
                || "is unset".to_owned(),
                |gid| format!(
                    "is {}, not a decimal gid",
                    fuz_sys::text::quoted(&fuz_sys::text::truncate(gid, 40))
                )
            )
        ),
        RunAsProblem::RootGroup { uid, basis } => match basis {
            DropBasis::Sudo => format!(
                "{refused}: it would run as uid {uid} with group 0, root's, from SUDO_GID, the \
                 group sudo was invoked with (invoke sudo from a session whose group isn't \
                 root's)"
            ),
            DropBasis::ProjectOwner => format!(
                "{refused}: it would run as uid {uid}, the owner of its project {root}, whose \
                 primary group in the passwd database is 0, root's (evaluate it as that user, \
                 or give the user a primary group of its own)"
            ),
        },
        RunAsProblem::NoPasswdEntry { uid } => format!(
            "{refused}: uid {uid}, which it would run as, has no passwd entry as this binary's \
             C library looks it up (a glibc build follows nsswitch.conf; a static musl build \
             reads /etc/passwd and nscd only, so LDAP, sssd, or systemd-homed users are \
             missing), so its home and group are unknown"
        ),
        RunAsProblem::PasswdUnreadable { uid } => format!(
            "{refused}: the passwd lookup for uid {uid}, which it would run as, failed, so its \
             home and group are unknown"
        ),
        RunAsProblem::HomeProject { uid, home } => format!(
            "{refused}: its project {root} is or holds {home}, the home directory of uid {uid}, \
             which it would run as, so the eval could read everything there (give the config a \
             project directory of its own, with its own package.json)"
        ),
        RunAsProblem::NotSearchable { uid, gid, dir } => format!(
            "{refused}: uid {uid} (gid {gid}), which it drops to from root, can't search {dir} \
             on the way to or at its project {root}, so fgro couldn't start there (give that \
             user search permission on it, or evaluate as that user)"
        ),
    }
}

/// How continuation lines of text fgro wrote are indented in a message.
const CONTINUATION_INDENT: &str = "  | ";

/// `text` with each line escaped ([`fuz_sys::text::escape_untrusted`]) and the
/// lines kept, each after the first prefixed with [`CONTINUATION_INDENT`]: a
/// multi-line report (a stack trace, console output) stays readable, while
/// nothing in it can drive a terminal or start a line of the message as though
/// it were this crate's (`error: …` at column 0).
fn escape_lines(text: &str) -> String {
    text.split('\n')
        .map(fuz_sys::text::escape_untrusted)
        .collect::<Vec<_>>()
        .join(&format!("\n{CONTINUATION_INDENT}"))
}

/// `stderr`, when there is any, as a trailing section of a message.
fn stderr_section(stderr: &str) -> String {
    if stderr.is_empty() {
        String::new()
    } else {
        format!("\nstderr:\n{CONTINUATION_INDENT}{}", escape_lines(stderr))
    }
}

/// The message of [`EvalError::Eval`].
fn eval_failure_message(path: &str, failure: &EvalFailure, stderr: &str) -> String {
    use std::fmt::Write as _;
    let quoted = fuz_sys::text::quoted;
    let mut out = format!(
        "config evaluation failed for {path} ({}): {}",
        failure.kind,
        escape_lines(&failure.message)
    );
    if let Some(at) = &failure.at {
        let _ = write!(out, "\n  at {}", quoted(at));
    }
    match (&failure.specifier, &failure.importer) {
        (Some(specifier), Some(importer)) => {
            let _ = write!(
                out,
                "\n  import {} from {}",
                quoted(specifier),
                quoted(importer)
            );
        }
        (Some(specifier), None) => {
            let _ = write!(out, "\n  import {}", quoted(specifier));
        }
        (None, Some(importer)) => {
            let _ = write!(out, "\n  from {}", quoted(importer));
        }
        (None, None) => {}
    }
    if let Some(hint) = &failure.hint {
        let _ = write!(out, "\nhint: {}", fuz_sys::text::escape_untrusted(hint));
    }
    out.push_str(&stderr_section(stderr));
    out
}

/// The message of [`EvalError::Protocol`].
fn protocol_message(path: &str, violation: &ProtocolViolation, stderr: &str) -> String {
    format!(
        "refused fgro's output for {path}: {violation}{}",
        stderr_section(stderr)
    )
}

/// The message of [`EvalError::FgroCrashed`].
fn crashed_message(path: &str, status: &str, stderr: &str) -> String {
    format!(
        "fgro crashed evaluating {path} ({status}){}",
        stderr_section(stderr)
    )
}

/// Evaluate a config through a pinned `fgro eval` and return its value and
/// module graph.
///
/// Settles the trust root and who `fgro` runs as, verifies the pin, spawns
/// `fgro eval <config> --driver - --graph --timeout <ms>` in the trust root,
/// as that user, with only `TZ=UTC` in its environment and its own process
/// group, writes
/// [`EvalRequest::driver_js`] to its stdin, and reads its stdout as one
/// envelope, fail-closed (crate docs, which also list what this leaves).
///
/// # Errors
///
/// See [`EvalError`]: a config that doesn't resolve or isn't UTF-8, a trust root
/// that can't be settled, no user it may run as, a pin that doesn't hold, a
/// spawn or IO failure, the parent's timeout, over-cap or non-UTF-8 stdout, a
/// crash, an envelope the reader refuses, or the eval failure fgro reported.
pub async fn eval_module(request: &EvalRequest<'_>) -> Result<EvalOutput, EvalError> {
    eval_module_with(request, |_| {}).await
}

/// [`eval_module`], calling `after_pin` with the pinned binary between its
/// verification and the stat-key check before the spawn.
///
/// The one seam into the eval path, for the unit test that writes the binary in
/// that window: a plain parameter rather than a `cfg(test)` branch, so the path
/// under test is the one that ships, and `eval_module` passes a no-op.
async fn eval_module_with(
    request: &EvalRequest<'_>,
    after_pin: impl FnOnce(&PinnedFgro),
) -> Result<EvalOutput, EvalError> {
    let config_path = tokio::fs::canonicalize(request.config_path)
        .await
        .map_err(|source| EvalError::ConfigNotFound {
            path: request.config_path.display().to_string(),
            source,
        })?;
    let path = config_path.display().to_string();
    let config_id = config_path
        .to_str()
        .ok_or_else(|| EvalError::ConfigPathNotUtf8 { path: path.clone() })?
        .to_owned();
    // the one read of the process and its SUDO_UID and SUDO_GID, which the
    // trust root's walk and the uid drop both take
    let caller = blocking(Caller::of_process).await?.map_err(|source| {
        EvalError::Io(std::io::Error::new(
            source.kind(),
            format!("read the effective uid: {source}"),
        ))
    })?;
    let trust_root = settle_trust_root(&config_path, &caller).await?;
    let run_as = settle_run_as(&path, caller, &trust_root).await?;

    let FgroPin {
        path: fgro_path,
        expected_blake3,
        cache_dir,
    } = request.fgro;
    let (fgro_path, expected_blake3, cache_dir) = (
        fgro_path.to_path_buf(),
        expected_blake3.to_owned(),
        cache_dir.map(Path::to_path_buf),
    );
    let pinned =
        blocking(move || fgro_verify(&fgro_path, &expected_blake3, cache_dir.as_deref())).await??;
    after_pin(&pinned);

    let timeout_ms = u64::try_from(request.timeout.as_millis())
        .unwrap_or(u64::MAX)
        .max(1);
    let mut command = Command::new(pinned.exec_path());
    command
        .arg0("fgro")
        .arg("eval")
        .arg(&config_id)
        .args(["--driver", "-", "--graph", "--timeout"])
        .arg(timeout_ms.to_string())
        .current_dir(&trust_root)
        .env_clear()
        .env("TZ", "UTC")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .kill_on_drop(true);
    if let Some(to) = run_as.dropped_to() {
        // gid too, or the child keeps root's group; with no explicit groups,
        // std clears the supplementary ones before the setuid
        command.uid(to.uid).gid(to.gid);
    }
    pinned.check_unchanged()?;
    let mut child = command
        .spawn()
        .map_err(|source| pinned.spawn_error(source, run_as.dropped_to()))?;
    // the exec has completed (or failed) by the time `spawn` returns, so the
    // held descriptor is no longer needed
    drop(pinned);
    // declared after `child`, so on a dropped future the group is killed while
    // the child is still unreaped
    let mut group = ProcessGroup::of(&child);

    let wall_clock = request.timeout.saturating_add(TIMEOUT_GRACE);
    let outcome = capture_child(&mut child, &group, request.driver_js, wall_clock).await;
    if outcome.is_err() {
        // a timeout or an IO error leaves the child unreaped: kill its group
        // first, while its id is still held, then reap
        group.kill();
        let _ = tokio::time::timeout(REAP_TIMEOUT, child.wait()).await;
    }
    group.disarm();
    let (stdout_capture, stderr_capture, status) = match outcome {
        Ok(captured) => captured,
        Err(Captured::TimedOut) => return Err(EvalError::Timeout { path }),
        Err(Captured::Io(source)) => return Err(EvalError::Io(source)),
    };

    if stdout_capture.exceeded {
        return Err(EvalError::OutputTooLarge {
            path,
            limit: MAX_STDOUT_SIZE,
        });
    }
    let stderr = stderr_text(&stderr_capture);
    let Some(code @ 0..=2) = status.code() else {
        return Err(EvalError::FgroCrashed {
            path,
            status: status.to_string(),
            stderr,
        });
    };
    if std::str::from_utf8(&stdout_capture.bytes).is_err() {
        return Err(EvalError::NotUtf8 { path });
    }
    let driver_blake3 = blake3::hash(request.driver_js.as_bytes())
        .to_hex()
        .to_string();
    let outcome = read_envelope(
        &stdout_capture.bytes,
        code,
        &Expected {
            config_id: &config_id,
            driver_blake3: &driver_blake3,
            trust_root: &trust_root,
        },
    )
    .map_err(|violation| EvalError::Protocol {
        path: path.clone(),
        violation: Box::new(violation),
        stderr: stderr.clone(),
    })?;
    match outcome {
        Outcome::Value { value_json, graph } => Ok(EvalOutput {
            value_json,
            config_path,
            graph: *graph,
        }),
        Outcome::Failed(failure) => Err(EvalError::Eval {
            path,
            failure: Box::new(failure),
            stderr,
        }),
    }
}

/// The trust root of the canonical config at `config_path`, settled on the
/// blocking pool: a directory whose `package.json` sets the project, or a
/// refusal (crate docs § The trust root).
async fn settle_trust_root(config_path: &Path, caller: &Caller) -> Result<PathBuf, EvalError> {
    let path = config_path.display().to_string();
    let config = config_path.to_path_buf();
    let caller = caller.clone();
    let root = blocking(move || trust_root::find_trust_root(&config, &caller))
        .await?
        .map_err(|error| match error {
            trust_root::RootsError::Io(source) => EvalError::Io(std::io::Error::new(
                source.kind(),
                format!("find the trust root of {}: {source}", config_path.display()),
            )),
            trust_root::RootsError::Refused {
                problem,
                offending,
                reason,
            } => EvalError::TrustRoot {
                path: path.clone(),
                problem,
                offending: offending.display().to_string(),
                reason,
            },
        })?;
    // only a project a package.json sets: fgro's walk doesn't stop where this
    // one does, so with none found here it would bound the eval by a project this
    // process doesn't trust, or find none
    match root.basis {
        TrustRootBasis::PackageJson(_) => Ok(root.dir),
        TrustRootBasis::StoppedBelow { dir, stop } => Err(EvalError::TrustRoot {
            path,
            problem: TrustRootProblem::WalkStopped(stop),
            offending: dir.display().to_string(),
            reason: match stop {
                WalkStop::WorldWritable => "every user can write it",
                WalkStop::OtherOwner => "another user owns it",
            }
            .to_owned(),
        }),
        TrustRootBasis::ConfigDir => Err(EvalError::TrustRoot {
            path,
            problem: TrustRootProblem::NoProject,
            offending: root.dir.display().to_string(),
            reason: "the filesystem root".to_owned(),
        }),
    }
}

/// Who `fgro` runs as for the config at `path` with trust root `root`, settled
/// on the blocking pool (crate docs § Who it runs as).
async fn settle_run_as(path: &str, caller: Caller, root: &Path) -> Result<RunAs, EvalError> {
    let dir = root.to_path_buf();
    blocking(move || run_as::settle_run_as(&caller, &dir))
        .await?
        .map_err(|error| match error {
            run_as::SettleError::Io(source) => EvalError::Io(source),
            run_as::SettleError::Refused(problem) => EvalError::RunAs {
                path: path.to_owned(),
                root: root.display().to_string(),
                problem,
            },
        })
}

/// Run `work` on the blocking pool: the trust root's walk and the pin's hash.
async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> T + Send + 'static,
) -> Result<T, EvalError> {
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|source| EvalError::Io(std::io::Error::other(source)))
}

/// The child's process group, killed on [`ProcessGroup::kill`] and, while
/// armed, on drop: a caller that drops [`eval_module`]'s future mid-eval takes
/// down everything the child started, not only the child.
struct ProcessGroup(Option<Pid>);

impl ProcessGroup {
    /// The group `child` leads (spawned with `process_group(0)`), armed.
    fn of(child: &Child) -> Self {
        Self(
            child
                .id()
                .and_then(|id| i32::try_from(id).ok())
                .map(Pid::from_raw),
        )
    }

    /// `SIGKILL` the group, best effort: one already gone is not an error.
    /// Only while the leader is unreaped, so its id can't have been reused.
    fn kill(&self) {
        if let Some(pgid) = self.0 {
            let _ = killpg(pgid, Signal::SIGKILL);
        }
    }

    /// Stop killing the group on drop: the leader is reaped, or about to be.
    const fn disarm(&mut self) {
        self.0 = None;
    }
}

impl Drop for ProcessGroup {
    fn drop(&mut self) {
        self.kill();
    }
}

/// Why [`capture_child`] returned without a reaped child.
enum Captured {
    /// The wall clock ran out.
    TimedOut,
    /// Writing the driver, reading a pipe, or the reap failed.
    Io(std::io::Error),
}

/// Write the driver to a spawned child's stdin and close it, while capturing
/// its stdout and stderr, then reap it — all within `wall_clock`. On `Ok` the
/// child is reaped; on `Err` it may be running still, and the caller kills its
/// group and reaps it.
async fn capture_child(
    child: &mut Child,
    group: &ProcessGroup,
    driver_js: &str,
    wall_clock: Duration,
) -> Result<(CappedCapture, CappedCapture, ExitStatus), Captured> {
    let missing = |name: &str| {
        Captured::Io(std::io::Error::other(format!(
            "failed to open the fgro subprocess {name}"
        )))
    };
    let mut stdin = child.stdin.take().ok_or_else(|| missing("stdin"))?;
    let mut stdout_pipe = child.stdout.take().ok_or_else(|| missing("stdout"))?;
    let mut stderr_pipe = child.stderr.take().ok_or_else(|| missing("stderr"))?;

    // Byte-capped capture (in place of `wait_with_output`, which buffers both
    // pipes with no ceiling — the wall clock bounds time, not memory). The
    // three run concurrently so no pipe can block another; the stdout branch
    // kills the group at its cap so the other pipes see EOF instead of waiting
    // out the wall clock.
    tokio::time::timeout(wall_clock, async {
        let (written, stdout_capture, stderr_capture) = tokio::join!(
            async {
                let written = stdin.write_all(driver_js.as_bytes()).await;
                drop(stdin);
                match written {
                    // a child that exits without reading its driver closes the
                    // pipe; its envelope says why
                    Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
                    other => other,
                }
            },
            async {
                let capture = read_capped(&mut stdout_pipe, MAX_STDOUT_SIZE).await;
                if capture.as_ref().is_ok_and(|c| c.exceeded) {
                    // The envelope is unusable past the cap and the process
                    // may stream forever: kill it, and anything it started,
                    // rather than wait out the clock. The leader is unreaped
                    // until the `wait` below.
                    group.kill();
                }
                capture
            },
            read_capped_draining(&mut stderr_pipe, MAX_CAPTURE_STDERR_SIZE),
        );
        // Reap before propagating an error so no zombie outlives it.
        let status = child.wait().await?;
        written?;
        Ok::<_, std::io::Error>((stdout_capture?, stderr_capture?, status))
    })
    .await
    .map_err(|_| Captured::TimedOut)?
    .map_err(Captured::Io)
}

/// A capture of stderr as text: lossy, trimmed, and marked when it was cut at
/// the cap.
fn stderr_text(capture: &CappedCapture) -> String {
    let mut stderr = String::from_utf8_lossy(&capture.bytes).trim().to_owned();
    if capture.exceeded {
        stderr.push_str("\n[stderr truncated at the capture cap]");
    }
    stderr
}

#[cfg(test)]
mod tests {
    /// Only a stop at another user's directory says fgro would look past it: fgro's
    /// own walk stops at a world-writable one too.
    #[test]
    fn a_walk_stop_names_fgro_only_where_fgro_would_go_on() {
        use super::{TrustRootProblem, WalkStop, trust_root_message};
        let other = trust_root_message(
            "/p/zap.ts",
            TrustRootProblem::WalkStopped(WalkStop::OtherOwner),
            "/home",
            "another user owns it",
        );
        assert!(
            other.contains("fgro would look past that directory"),
            "{other}"
        );
        let open = trust_root_message(
            "/p/zap.ts",
            TrustRootProblem::WalkStopped(WalkStop::WorldWritable),
            "/tmp",
            "every user can write it",
        );
        assert!(!open.contains("fgro"), "{open}");
        assert!(open.contains("that directory's contents"), "{open}");
    }

    use super::*;

    /// A missing config resolves to `ConfigNotFound` before any pin or spawn.
    #[tokio::test]
    async fn missing_config_is_config_not_found() {
        let missing =
            std::env::temp_dir().join(format!("fuz_eval_missing_{}.ts", std::process::id()));
        let _ = std::fs::remove_file(&missing);
        let err = eval_module(&EvalRequest {
            config_path: &missing,
            driver_js: "",
            timeout: Duration::from_secs(5),
            fgro: FgroPin {
                path: Path::new("/nonexistent/fgro"),
                expected_blake3: "",
                cache_dir: None,
            },
        })
        .await
        .expect_err("a missing config must error");
        assert!(
            matches!(err, EvalError::ConfigNotFound { .. }),
            "expected ConfigNotFound, got {err:?}"
        );
    }

    /// Text fgro wrote can't drive a terminal through a message, while a
    /// multi-line report keeps its lines.
    #[test]
    fn an_eval_failure_escapes_what_fgro_wrote() {
        let failure = EvalFailure {
            kind: EvalErrorKind::ModuleThrew,
            message: "Error: boom\u{1b}[2J\n    at file:///p/zap.ts:1:7".to_owned(),
            at: Some("$.a\u{7}".to_owned()),
            specifier: Some("x\u{1b}".to_owned()),
            importer: Some("file:///p/zap.ts".to_owned()),
            hint: Some("do\u{1b}this".to_owned()),
        };
        let message = eval_failure_message("/p/zap.ts", &failure, "log\u{1b}[31m line\nsecond");
        assert!(
            !message.contains('\u{1b}') && !message.contains('\u{7}'),
            "{message}"
        );
        assert!(message.starts_with(
            "config evaluation failed for /p/zap.ts (module_threw): Error: boom\\u{1b}[2J\n  |     at file:///p/zap.ts:1:7"
        ), "{message}");
        assert!(message.contains("\nhint: do\\u{1b}this"), "{message}");
        assert!(
            message.ends_with("\nstderr:\n  | log\\u{1b}[31m line\n  | second"),
            "{message}"
        );
    }

    /// A line break in what fgro wrote — a thrown message, console output —
    /// can't start a line of the message at column 0, where it would read as a
    /// line of this crate's own (`error: …`, `hint: …`).
    #[test]
    fn text_fgro_wrote_cannot_forge_a_line_of_the_message() {
        let forged = "boom\nerror: fake\nhint: run this";
        let failure = EvalFailure {
            kind: EvalErrorKind::ModuleThrew,
            message: forged.to_owned(),
            at: None,
            specifier: None,
            importer: None,
            hint: None,
        };
        let message = eval_failure_message("/p/zap.ts", &failure, forged);
        let crashed = crashed_message("/p/zap.ts", "signal: 6 (SIGABRT)", forged);
        let protocol = protocol_message("/p/zap.ts", &ProtocolViolation::NoEnvelope, forged);
        for message in [message, crashed, protocol] {
            for line in message.lines().skip(1) {
                assert!(
                    line == "stderr:" || line.starts_with(CONTINUATION_INDENT),
                    "{line:?} in {message}"
                );
            }
        }
    }

    /// The seam between the pin and the spawn: a write to the binary there
    /// moves its stat key, and the eval refuses before running it. Without the
    /// check the copy of `/bin/true` would run and write no envelope.
    #[tokio::test]
    async fn a_write_after_the_pin_refuses_the_eval_before_the_spawn() {
        use std::os::unix::fs::PermissionsExt;
        let dir =
            std::env::temp_dir().join(format!("fuz_eval_changed_since_pin_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let dir = std::fs::canonicalize(&dir).unwrap();
        let config = dir.join("zap.ts");
        for (path, contents) in [
            (&config, "export default 1;\n"),
            (&dir.join("package.json"), r#"{"name":"p"}"#),
        ] {
            std::fs::write(path, contents).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        let fgro = dir.join("fgro");
        std::fs::copy("/bin/true", &fgro).unwrap();
        let pin = fgro_blake3(&fgro, None).unwrap();
        let request = EvalRequest {
            config_path: &config,
            driver_js: "",
            timeout: Duration::from_secs(5),
            fgro: FgroPin {
                path: &fgro,
                expected_blake3: &pin,
                cache_dir: None,
            },
        };
        let unchanged = eval_module_with(&request, |_| {}).await.unwrap_err();
        let changed = eval_module_with(&request, |pinned| {
            let mut file = std::fs::OpenOptions::new()
                .append(true)
                .open(pinned.path())
                .unwrap();
            std::io::Write::write_all(&mut file, b"\0").unwrap();
        })
        .await
        .unwrap_err();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            matches!(&unchanged, EvalError::Protocol { violation, .. } if **violation == ProtocolViolation::NoEnvelope),
            "{unchanged:?}"
        );
        assert!(
            matches!(
                changed,
                EvalError::FgroUnusable {
                    problem: FgroProblem::ChangedSincePin,
                    ..
                }
            ),
            "{changed:?}"
        );
    }
}
