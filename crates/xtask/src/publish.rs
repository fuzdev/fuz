//! Bootstrap publishing (`cargo xtask publish …`).
//!
//! The bootstrap-only signer for the first `fuz` / `fuzd` / `fuzf` binaries —
//! the chicken-and-egg case the forge client `fuzf tool publish` can't cover
//! (`fuzf` can't publish fuzf itself, and the first fuzd has to land before
//! a forge serves tools). Steady-state per-tool publishing is `fuzf`'s job;
//! this lives on xtask because xtask path-deps `fuz_sign` (kept out of the
//! `fuz`/`fuzd` graph) and already owns the signing-key surface (`cargo xtask
//! key …`).
//!
//! - `cargo xtask publish self` signs + uploads the **fuz-only** self artifact
//!   (the current `~/.fuz/current`) via `fuz_sign::publish_current`.
//! - `cargo xtask publish tool <name> <binary> --version <v>` signs + uploads a
//!   single-binary tool artifact via `fuz_sign::publish_tool` — the same path
//!   `fuzf tool publish` uses, for bootstrap fuzd / fuzf.
//!
//! `--log-repo <path>` on either command names a checkout of the release log
//! repository. The publish checks, before uploading anything, that the log can
//! take the release; then records it there (signs the next `head.json`,
//! commits, pushes) before it moves the target's `latest-<target>.json`, and
//! fails without moving it if that cannot be done. See `fuz_sign::release_log`.
//!
//! `--target <triple>` on either command labels the release with a supported
//! target other than this xtask's own — a cross-compiled or musl build. Named
//! or not, every binary's header is held to the target before anything is
//! signed or uploaded, and a statically linked binary passes a glibc target
//! only when it is named (`fuz_artifact::platform::check_binary_target`).
//!
//! `--storage` mirrors the consumer (`fuz self upgrade --storage`): a local
//! path (`/path`), `forge://<host>` (bearer token from `FUZ_FORGE_TOKEN`, else
//! `<fuz_forge_home>/api_token`),
//! or `ssh://user@host/path` (ambient ssh auth). Two differences. A local path
//! need not exist here ([`publish_storage`]): a publish is what creates a
//! local store — with its first upload, not by naming it — where the consumer
//! refuses a directory that is not there. And a read-only location
//! (`https://`), which the consumer reads, is refused: a publish has nothing
//! to upload to. Both are settled when `--storage` is resolved, which comes
//! first — before the signing key is loaded, and before anything is read,
//! packed, or signed. The producer commands that work on a store already
//! there (`prune`, `release-log backfill`) refuse a missing one too
//! ([`existing_storage`]).

use std::path::PathBuf;

use argh::FromArgs;
use fuz_artifact::platform::ReleaseTarget;
use fuz_release::{ReleaseError, StorageError};
use fuz_sign::{
    KeyFileError, LogRepo, PublishOptions, load_signing_key, publish_current, publish_tool,
};
use fuz_storage::{Storage, StorageBackend, parse_existing_storage, parse_storage};
use thiserror::Error;

/// Errors from `cargo xtask publish …`.
#[derive(Debug, Error)]
pub enum PublishError {
    /// Release/publish operation failed (signing, packaging, upload).
    #[error("{0}")]
    Release(#[from] ReleaseError),

    /// Creating the release log from published releases failed.
    #[error("{0}")]
    Backfill(#[from] fuz_sign::BackfillError),

    /// Revoking a release in the release log failed.
    #[error("{0}")]
    Revoke(#[from] fuz_sign::RevokeError),

    /// Storage operation failed (URI parse, transfer).
    #[error("{0}")]
    Storage(#[from] StorageError),

    /// The local `--storage` of a command that works on a store already there
    /// is not an existing directory. Nothing was created. `location` is the
    /// argument as given.
    #[error("--storage is not an existing directory: {location}")]
    StorageMissing { location: String },

    /// `prune --tool` was given something that is not a first-party tool name.
    /// Refused before a storage key is built from it.
    #[error("--tool is not a first-party tool name: {name}")]
    ToolNotFirstParty { name: String },

    /// The local `--storage` of a publish is taken by something that is not a
    /// directory, or sits under something that is not one, so the store could
    /// not be created there. Refused before anything is packed or signed.
    #[error("--storage is not a directory, and cannot be created as one: {location}")]
    StorageNotDir { location: String },

    /// The signing key could not be located, read, or parsed.
    #[error(transparent)]
    Key(#[from] KeyFileError),

    /// Could not start the async runtime for the upload.
    #[error("failed to start async runtime: {0}")]
    Runtime(#[source] std::io::Error),
}

/// Sign + publish bootstrap artifacts to storage (publisher-only).
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "publish")]
pub struct Publish {
    #[argh(subcommand)]
    nested: PublishSub,
}

#[derive(FromArgs, Debug)]
#[argh(subcommand)]
enum PublishSub {
    SelfArtifact(PublishSelf),
    Tool(PublishTool),
}

/// Sign + publish the fuz-only self artifact (the current `~/.fuz/current`).
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "self")]
struct PublishSelf {
    /// storage location (e.g. `/path`, `forge://host`, or `ssh://user@host/path`)
    #[argh(option)]
    storage: String,

    /// oldest installed fuz version allowed to upgrade to this release
    #[argh(option)]
    minimum_version: Option<String>,

    /// signing key file (default: `$FUZ_HOME/config/signing.key`)
    #[argh(option)]
    key_file: Option<PathBuf>,

    /// checkout of the release log repository: record the release there
    /// (sign head.json, commit, push) before the target's latest pointer moves
    #[argh(option)]
    log_repo: Option<PathBuf>,

    /// target triple to label the release with (default: this xtask's own);
    /// every binary must be an executable for it
    #[argh(option)]
    target: Option<ReleaseTarget>,

    /// suppress output
    #[argh(switch, short = 'q')]
    quiet: bool,
}

/// Sign + publish a single-binary tool artifact (bootstrap fuzd / fuzf / …).
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "tool")]
struct PublishTool {
    /// tool name (must be first-party; e.g. fuzd, fuzf)
    #[argh(positional)]
    name: String,

    /// path to the compiled binary to publish
    #[argh(positional)]
    binary: PathBuf,

    /// version to publish (e.g. 0.1.0)
    #[argh(option)]
    version: String,

    /// storage location (e.g. `/path`, `forge://host`, or `ssh://user@host/path`)
    #[argh(option)]
    storage: String,

    /// oldest installed version of this tool allowed to upgrade to it
    #[argh(option)]
    minimum_version: Option<String>,

    /// signing key file (default: `$FUZ_HOME/config/signing.key`)
    #[argh(option)]
    key_file: Option<PathBuf>,

    /// checkout of the release log repository: record the release there
    /// (sign head.json, commit, push) before the target's latest pointer moves
    #[argh(option)]
    log_repo: Option<PathBuf>,

    /// target triple to label the release with (default: this xtask's own);
    /// every binary must be an executable for it
    #[argh(option)]
    target: Option<ReleaseTarget>,

    /// suppress output
    #[argh(switch, short = 'q')]
    quiet: bool,
}

/// Dispatch `cargo xtask publish …`.
pub fn cmd_publish(args: Publish) -> Result<(), PublishError> {
    match args.nested {
        PublishSub::SelfArtifact(opts) => publish_self(opts),
        PublishSub::Tool(opts) => publish_tool_cmd(opts),
    }
}

fn publish_self(opts: PublishSelf) -> Result<(), PublishError> {
    let storage = publish_storage(&opts.storage)?;
    let key = load_signing_key(opts.key_file.as_deref())?.key;
    let options = publish_options(opts.minimum_version, opts.log_repo, opts.target);

    let result = runtime()?.block_on(publish_current(&storage, &key, &options))?;

    if !opts.quiet {
        println!(
            "published fuz self artifact {} for {} ({})",
            result.version, result.target, result.content_hash
        );
        println!("  manifest: {}", result.manifest_path);
        println!("  tarball:  {}", result.tarball_path);
        if let Some(logged) = &result.logged {
            println!("  log:      {logged}");
        }
    }
    Ok(())
}

fn publish_tool_cmd(opts: PublishTool) -> Result<(), PublishError> {
    let storage = publish_storage(&opts.storage)?;
    let key = load_signing_key(opts.key_file.as_deref())?.key;
    let options = publish_options(opts.minimum_version, opts.log_repo, opts.target);

    // The in-tarball binary name is the tool name, so it links into
    // `~/.fuz/bin/<name>` on the consumer side; the source path may be anything
    // (e.g. ./target/release/<name>).
    let binaries = [(opts.name.clone(), opts.binary)];
    let result = runtime()?.block_on(publish_tool(
        &storage,
        &opts.name,
        &opts.version,
        &binaries,
        &key,
        &options,
    ))?;

    if !opts.quiet {
        println!(
            "published {} {} for {} ({})",
            opts.name, result.version, result.target, result.content_hash
        );
        println!("  manifest: {}", result.manifest_path);
        println!("  tarball:  {}", result.tarball_path);
        if let Some(logged) = &result.logged {
            println!("  log:      {logged}");
        }
    }
    Ok(())
}

/// Resolve `--storage` for a publish: a local directory that is not there yet
/// is accepted, and the first upload creates it. Naming it creates nothing.
///
/// What a publish could only fail on at its first upload is refused here
/// instead, before the caller loads a key or does any work: something at a
/// local path that is not a directory (naming the location), and a read-only
/// backend (the error and hint its `upload` would give).
fn publish_storage(location: &str) -> Result<StorageBackend, PublishError> {
    let storage = parse_storage(location).map_err(|error| match error {
        // The storage error carries no path; the command line's own argument
        // is safe to repeat.
        StorageError::LocalRootNotDir => PublishError::StorageNotDir {
            location: location.to_string(),
        },
        error => PublishError::Storage(error),
    })?;
    storage.require_writable("upload")?;
    Ok(storage)
}

/// Resolve `--storage` for a command that works on a store already there
/// (`prune`, `release-log backfill`): a local path that is not an existing
/// directory is refused, naming the location, rather than read as a store
/// with nothing in it. Creates nothing.
pub fn existing_storage(location: &str) -> Result<StorageBackend, PublishError> {
    parse_existing_storage(location).map_err(|error| match error {
        StorageError::LocalRootNotDir => PublishError::StorageMissing {
            location: location.to_string(),
        },
        error => PublishError::Storage(error),
    })
}

/// The publish options both commands build from their flags.
fn publish_options(
    minimum_version: Option<String>,
    log_repo: Option<PathBuf>,
    target: Option<ReleaseTarget>,
) -> PublishOptions {
    PublishOptions {
        minimum_version,
        log_repo: log_repo.map(LogRepo::new),
        target,
    }
}

/// A current-thread tokio runtime to drive the async publish (one-shot CLI).
/// Build a current-thread tokio runtime for the one-shot async producer flows
/// (publish, prune). Crate-visible (the `publish` module is private) so `prune`
/// shares it.
pub fn runtime() -> Result<tokio::runtime::Runtime, PublishError> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(PublishError::Runtime)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_repo_flag_reaches_the_publish_options() {
        let args =
            PublishSelf::from_args(&["self"], &["--storage", "/s", "--log-repo", "/log"]).unwrap();
        let options = publish_options(args.minimum_version, args.log_repo, args.target);
        assert_eq!(options.log_repo, Some(LogRepo::new("/log")));

        let args = PublishTool::from_args(
            &["tool"],
            &[
                "fuzd",
                "/bin/fuzd",
                "--version",
                "0.1.0",
                "--storage",
                "/s",
                "--minimum-version",
                "0.0.9",
                "--log-repo",
                "/log",
            ],
        )
        .unwrap();
        let options = publish_options(args.minimum_version, args.log_repo, args.target);
        assert_eq!(options.log_repo, Some(LogRepo::new("/log")));
        assert_eq!(options.minimum_version.as_deref(), Some("0.0.9"));
    }

    /// `--target` parses to a supported target and reaches the options;
    /// omitted, the publish defaults to the host's; an unsupported triple is a
    /// parse error (exit 2) naming the supported set.
    #[test]
    fn target_flag_reaches_the_publish_options() {
        let args = PublishSelf::from_args(
            &["self"],
            &["--storage", "/s", "--target", "x86_64-unknown-linux-musl"],
        )
        .unwrap();
        let options = publish_options(args.minimum_version, args.log_repo, args.target);
        assert_eq!(
            options.target.map(ReleaseTarget::triple),
            Some("x86_64-unknown-linux-musl")
        );

        let args = PublishTool::from_args(
            &["tool"],
            &[
                "fuzd",
                "/bin/fuzd",
                "--version",
                "0.1.0",
                "--storage",
                "/s",
                "--target",
                "aarch64-apple-darwin",
            ],
        )
        .unwrap();
        assert_eq!(
            args.target.map(ReleaseTarget::triple),
            Some("aarch64-apple-darwin")
        );

        let args = PublishSelf::from_args(&["self"], &["--storage", "/s"]).unwrap();
        assert_eq!(args.target, None);

        let err = PublishSelf::from_args(&["self"], &["--storage", "/s", "--target", "riscv64"])
            .unwrap_err();
        assert!(
            err.output
                .contains("unsupported release target \"riscv64\""),
            "{}",
            err.output
        );
    }

    #[test]
    fn no_log_repo_flag_logs_nothing() {
        let args = PublishSelf::from_args(&["self"], &["--storage", "/s"]).unwrap();
        let options = publish_options(args.minimum_version, args.log_repo, args.target);
        assert_eq!(options.log_repo, None);
    }
}
