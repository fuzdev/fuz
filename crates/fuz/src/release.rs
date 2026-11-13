//! Release distribution CLI commands (consumer side)
//!
//! `fuz self upgrade` — fetch + verify + install the latest fuz. `fuz` has no
//! publish or fetch command: producing lives on the `fuzf` / `cargo xtask`
//! producer tools, so the `fuz` binary links no signing code at all — it only
//! ever fetches and verifies. The storage backend is resolved from the `--storage`
//! URI by [`open_storage`], the one place this binary parses a location; every
//! backend authenticates ambiently (forge bearer token / ssh agent / nothing),
//! so there is no credentials file.
//!
//! `fuz` only reads a store, so naming one never creates it: a local
//! `--storage` that is not an existing directory is refused, for an install,
//! an upgrade, and a `--check` alike.
//!
//! When `FUZ_RELEASE_LOG_URL` names a witness, an install is held to the
//! release log first, and `--check` holds the latest release to it before
//! reporting (see `crate::release_log`).

use argh::FromArgs;
use fuz_artifact::{
    ArtifactError, ArtifactMeta, CurrentLinkProblem, SwitchOptions, acquire_artifact_lock,
    get_current_artifact, switch_to_artifact,
};
use fuz_release::{
    CurrentVersion, FetchOptions, LatestCheck, ReleaseError, ReleaseLogError, StorageBackend,
    StorageError, UpdateCheck, UpdateStatus, check_latest_self, compute_update_check, fetch_latest,
    parse_existing_storage,
};
use fuz_sys::cli::EXIT_USAGE;
use serde::Serialize;
use std::borrow::Cow;
use thiserror::Error;

use crate::CliError;

/// Errors specific to release commands
#[derive(Debug, Error)]
pub enum ReleaseCommandError {
    /// Release operation failed
    #[error("{0}")]
    Release(#[from] ReleaseError),

    /// Storage operation failed
    #[error("{0}")]
    Storage(#[from] StorageError),

    /// The local `--storage` location is not an existing directory — missing,
    /// or something else is there. Nothing was created: `fuz` only reads a
    /// store. `location` is the argument as given.
    #[error("--storage is not an existing directory: {location}")]
    StorageNotDir { location: String },
}

impl ReleaseCommandError {
    /// Exit code for this error (for `ExitCode::from`).
    ///
    /// Reaches through [`ReleaseError::Artifact`] so the artifact-store
    /// failure classes keep their sysexits code on this side of the CLI too.
    /// They did not: `fuz artifact verify` on a tampered binary exited 65
    /// (`EX_DATAERR`) while `fuz tool verify` on the same
    /// `BinaryIntegrityFailed` exited 1, because the error reached the top
    /// through this wrapper instead of `CliError::Artifact`. The three arms
    /// mirror [`crate::CliError::exit_code`]'s exactly — an agent branching on
    /// the code should not have to know which noun it invoked.
    ///
    /// A security violation ([`ReleaseError::is_security_violation`] — a bad
    /// signature, a substituted manifest, hostile or mismatched download bytes,
    /// a release the log revokes, omits, or contradicts) is `65` with the local
    /// integrity failures: one "do not trust these bytes, do not retry" class,
    /// as in `fuzi`, never the `1` a retryable storage failure shares. A fuz
    /// home that cannot be used as configured ([`ReleaseError::is_unusable_home`])
    /// is `2`, checked first: a world-writable home is also classified a
    /// violation, but nothing untrusted was read, and the fix is the caller's
    /// `chmod`.
    pub const fn exit_code(&self) -> u8 {
        match self {
            Self::Release(ReleaseError::Artifact(
                ArtifactError::IntegrityFailed { .. }
                | ArtifactError::BinaryIntegrityFailed { .. }
                | ArtifactError::StoreEntryNotDir { .. }
                | ArtifactError::CurrentNotStoreLink { .. }
                | ArtifactError::NotRegularFile(_),
            )) => 65, // EX_DATAERR
            Self::Release(ReleaseError::Artifact(ArtifactError::InProgress { .. })) => 75, // EX_TEMPFAIL
            Self::Release(ReleaseError::Artifact(ArtifactError::InsufficientSpace { .. })) => 73, // EX_CANTCREAT
            // The release log could not be consulted and no cached head covers
            // the release: nothing refused it, so retrying may succeed. Every
            // other release log failure is a refusal: 65 below when it is a
            // security violation, 2 for a configuration the check cannot run
            // under, else 1.
            Self::Release(e) if e.is_unconfirmed() => 75, // EX_TEMPFAIL
            // A release log configuration the check cannot run under: the
            // caller must change it before re-running.
            Self::Release(ReleaseError::ReleaseLog(ReleaseLogError::Config(_))) => EXIT_USAGE,
            // A fuz home that cannot be used as configured, the same `2` as on
            // every other path to it.
            Self::Release(e) if e.is_unusable_home() => EXIT_USAGE,
            Self::Release(e) if e.is_security_violation() => 65, // EX_DATAERR
            // A store that is not there is the storage class, like a release
            // that is not in one.
            Self::Release(_) | Self::Storage(_) | Self::StorageNotDir { .. } => 1,
        }
    }

    /// User-facing hint
    pub fn hint(&self) -> Option<Cow<'static, str>> {
        match self {
            Self::Release(e) => e.hint(),
            Self::Storage(e) => e.hint().map(Cow::Borrowed),
            Self::StorageNotDir { .. } => Some(Cow::Borrowed(
                "Check the path: fuz only reads a store and never creates one. \
                 A local store exists once a release is published to it",
            )),
        }
    }
}

/// Resolve a `--storage` location into the backend a command reads from — the
/// one place the `fuz` binary parses one.
///
/// `fuz` only reads a store, so this is the existing-store parse
/// (`parse_existing_storage`): naming a location changes nothing on disk, and
/// a local path that is not an existing directory is
/// [`ReleaseCommandError::StorageNotDir`] rather than a store that reads as
/// empty. `forge://`, `ssh://`, and `https://` locations parse as they do for
/// a producer.
pub fn open_storage(location: &str) -> Result<StorageBackend, ReleaseCommandError> {
    parse_existing_storage(location).map_err(|error| match error {
        // The storage error carries no path; the command line's own argument
        // is safe to repeat.
        StorageError::LocalRootNotDir => ReleaseCommandError::StorageNotDir {
            location: location.to_string(),
        },
        error => ReleaseCommandError::Storage(error),
    })
}

//
// CLI args
//

/// Fetch and install latest from storage.
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "upgrade")]
#[expect(
    clippy::struct_excessive_bools,
    reason = "CLI flags are naturally boolean"
)]
pub struct Upgrade {
    /// storage location (e.g. `/path`, `forge://host`, `ssh://user@host/path`, or `https://host/path`)
    #[argh(option)]
    pub storage: String,

    /// allow installing older versions
    #[argh(switch)]
    pub allow_downgrade: bool,

    /// reinstall over an unreadable/corrupt current install instead of refusing
    #[argh(switch)]
    pub force: bool,

    /// check for a newer version without installing (read-only; exit 10 if an update is available)
    #[argh(switch)]
    pub check: bool,

    /// machine-readable JSON output (only with --check)
    #[argh(switch)]
    pub json: bool,

    /// suppress informational output (release log warnings still print)
    #[argh(switch, short = 'q')]
    pub quiet: bool,
}

/// Handle `fuz self upgrade` command
pub async fn cmd_upgrade(args: Upgrade) -> Result<(), CliError> {
    if args.json && !args.check {
        return Err(CliError::InvalidUsage("--json applies only with --check"));
    }

    // The release log policy first: a configuration the check cannot run
    // under stops the command before any request, `--check` included.
    let release_log = crate::release_log::policy_from_env()?;
    crate::release_log::warn_if_revoked(
        &release_log,
        crate::release_log::reported_version(get_current_artifact().ok().flatten().as_ref()),
    );

    let storage = open_storage(&args.storage)?;

    // Read-only update check: resolve + verify the latest signed manifest and
    // report whether an update is available, installing nothing. Reports the
    // signed `manifest.version`, never the unsigned latest pointer.
    if args.check {
        // The latest release, verified and held to the release log, with the
        // real install state (installed / not-installed / unreadable) rather
        // than a `"0.0.0"` sentinel, so `--check` reports honestly.
        let latest = check_latest_self(&storage, &release_log)
            .await
            .map_err(ReleaseCommandError::Release)?;
        crate::release_log::render(latest.release_log(), args.quiet);
        return render_check("self", "fuz", &latest, args.json);
    }

    // Get current version for comparison. An unreadable current install is
    // refused here without `--force` and set aside with it, so the forced
    // reinstall `fetch_latest` performs is reachable (and records no rollback
    // target — there is no readable artifact to roll back to).
    let current = current_for_upgrade(get_current_artifact(), args.force)?;
    let current_hash = current.as_ref().map(|m| m.hash.as_str());
    let current_version = current.as_ref().map(|m| m.version.as_str());

    // Fetch latest
    let options = FetchOptions {
        allow_downgrade: args.allow_downgrade,
        force: args.force,
        release_log,
    };
    let result = fetch_latest(&storage, &options)
        .await
        .map_err(ReleaseCommandError::Release)?;
    crate::release_log::render(&result.release_log, args.quiet);

    // Surface a forced reinstall over an unreadable install (the `--force` path).
    if !args.quiet
        && let Some(reason) = &result.repaired_unreadable
    {
        eprintln!("warning: reinstalled over an unreadable current install ({reason})");
    }

    // Classify by content-hash identity. `AlreadyCurrent` is the only skip case:
    // the artifact's unique identity is its content hash, not the (non-unique)
    // version string, and never the incidental `cache_hit` download flag.
    let outcome = upgrade_outcome(
        current_hash,
        current_version,
        &result.content_hash,
        &result.version,
    );
    if outcome == UpgradeOutcome::AlreadyCurrent {
        if !args.quiet {
            println!("already at latest version {}", result.version);
        }
        return Ok(());
    }

    // Switch to the new artifact (handles daemon restart). Acquire the
    // artifact lock *after* the (potentially-long) fetch so we don't
    // block builds for the full download window — but before the switch
    // so we never race on `current` / `history.json`.
    let lock = acquire_artifact_lock().map_err(CliError::Artifact)?;
    switch_to_artifact(
        SwitchOptions {
            hash: &result.content_hash,
            version: &result.version,
            previous_hash: current_hash,
            quiet: args.quiet,
        },
        &lock,
    )
    .map_err(CliError::Artifact)?;

    if !args.quiet {
        match outcome {
            UpgradeOutcome::Installed => println!("installed {}", result.version),
            // Same version, different content hash: an honest "changed" message
            // rather than a confusing `upgraded X -> X`.
            UpgradeOutcome::Reinstalled => {
                println!("reinstalled {} (content changed)", result.version);
            }
            UpgradeOutcome::Upgraded { from } => {
                println!("upgraded {} -> {}", from, result.version);
            }
            // Handled by the early return above; the switch only runs otherwise.
            UpgradeOutcome::AlreadyCurrent => {}
        }
    }

    Ok(())
}

/// The current artifact `fuz self upgrade` compares against, applying the
/// unreadable-install policy `fetch_latest` applies itself, before any request.
///
/// - A readable install, or none, passes through.
/// - A `current` that is not a symlink is refused with or without `--force`:
///   the switch could not replace it (a directory fails the rename), and fuz
///   does not remove what it did not write. A home that cannot be resolved is
///   refused as itself too.
/// - Anything else unreadable — a `current` outside `artifacts/`, a symlink
///   or file at the artifact it names, a corrupt `meta.json` — is
///   [`ReleaseError::CurrentUnreadable`] without `--force` (whose hint names
///   `--force`), and no current install with it.
fn current_for_upgrade(
    read: Result<Option<ArtifactMeta>, ArtifactError>,
    force: bool,
) -> Result<Option<ArtifactMeta>, CliError> {
    match read {
        Ok(current) => Ok(current),
        Err(
            e @ (ArtifactError::FuzHome(_)
            | ArtifactError::CurrentNotStoreLink {
                problem: CurrentLinkProblem::NotASymlink,
                ..
            }),
        ) => Err(CliError::Artifact(e)),
        Err(_) if force => Ok(None),
        Err(e) => Err(
            ReleaseCommandError::Release(ReleaseError::CurrentUnreadable {
                reason: e.to_string(),
            })
            .into(),
        ),
    }
}

/// Classification of a self/tool upgrade by the artifact's **content-hash
/// identity** — its unique id. The version string is *not* unique: a
/// locally-built and a published artifact can share a version yet differ in
/// content, so version-equality must never short-circuit the switch. Pure and
/// exhaustively testable; each caller renders its own message. Shared by
/// `fuz self upgrade` and `fuz tool upgrade`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpgradeOutcome<'a> {
    /// The current artifact's content hash equals the target's — nothing to do
    /// (the only skip case).
    AlreadyCurrent,
    /// No current artifact — a fresh install.
    Installed,
    /// Content hash differs but the version string is unchanged — a reinstall of
    /// the same version with different content.
    Reinstalled,
    /// Content hash and version both differ — an upgrade from `from`.
    Upgraded {
        /// The previously-installed version.
        from: &'a str,
    },
}

/// Classify an upgrade from the current artifact's identity vs. the fetched
/// target. Skips (`AlreadyCurrent`) **only** on exact content-hash identity.
#[must_use]
pub fn upgrade_outcome<'a>(
    current_hash: Option<&str>,
    current_version: Option<&'a str>,
    target_hash: &str,
    target_version: &str,
) -> UpgradeOutcome<'a> {
    if current_hash == Some(target_hash) {
        return UpgradeOutcome::AlreadyCurrent;
    }
    match current_version {
        None => UpgradeOutcome::Installed,
        Some(v) if v == target_version => UpgradeOutcome::Reinstalled,
        Some(from) => UpgradeOutcome::Upgraded { from },
    }
}

//
// Shared `--check` rendering (self + tool)
//

/// `--json` output shape for a read-only update check. Matches the documented
/// contract shared by `fuz self upgrade --check` and `fuz tool upgrade --check`.
#[derive(Serialize)]
struct CheckOutput<'a> {
    /// `"self"` or `"tool"`.
    kind: &'a str,
    /// `"fuz"` or the tool name.
    name: &'a str,
    /// Installed version; `null` when nothing is installed or the install is
    /// unreadable (the `status` field carries that distinction).
    #[serde(skip_serializing_if = "Option::is_none")]
    current: Option<String>,
    /// Latest signed version, from the verified manifest.
    latest: &'a str,
    /// The verdict.
    status: UpdateStatus,
    /// Always `true` — a `--check` only reports after the manifest's signature
    /// verified.
    verified: bool,
    /// Present for the `update_required` / `unreadable` cases.
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    /// The release log head that confirmed `latest`. Present only when a
    /// witness is configured and the release was confirmed; with none
    /// configured the report has no such key.
    #[serde(skip_serializing_if = "Option::is_none")]
    release_log: Option<crate::release_log::CheckLogJson>,
}

/// Compute + render a read-only update check from a **verified** manifest, and
/// signal the exit code: `Ok(())` when up to date (exit 0), or
/// `Err(CliError::UpdateAvailable)` for any other verdict (update available /
/// required, not installed, unreadable — exit 10). Installs nothing. Shared by
/// the self and tool `--check` paths.
///
/// `checked` is what `check_latest_self` / `check_latest_tool` returned: the
/// signed manifest, the resolved install state, and the release log check's
/// outcome. It exists only for a release the log did not refuse, so a report
/// cannot be rendered for one it did. `NotInstalled` / `Unreadable` are
/// reported distinctly rather than collapsed into a misleading
/// `update_required`.
pub fn render_check(
    kind: &str,
    name: &str,
    checked: &LatestCheck,
    json: bool,
) -> Result<(), CliError> {
    let (current, manifest) = (checked.current(), checked.manifest());
    // Installed → the normal version verdict; the other two states map straight
    // to their own status (no version to compare against).
    let (check, current_str) = match current {
        CurrentVersion::Installed(v) => {
            let installed = v.to_string();
            let check = compute_update_check(&installed, manifest)
                .map_err(|e| ReleaseCommandError::Release(e.into()))?;
            (check, Some(installed))
        }
        CurrentVersion::NotInstalled => (
            UpdateCheck {
                status: UpdateStatus::NotInstalled,
                reason: None,
            },
            None,
        ),
        CurrentVersion::Unreadable { reason } => (
            UpdateCheck {
                status: UpdateStatus::Unreadable,
                reason: Some(reason.clone()),
            },
            None,
        ),
    };
    let latest = manifest.version.as_str();

    if json {
        let output = CheckOutput {
            kind,
            name,
            current: current_str,
            latest,
            status: check.status,
            verified: true,
            reason: check.reason,
            release_log: crate::release_log::check_json(checked.release_log()),
        };
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        let current_label = current_str.as_deref().unwrap_or("(none)");
        match check.status {
            UpdateStatus::UpToDate => println!("{name} is up to date ({current_label})"),
            UpdateStatus::UpdateAvailable => {
                println!("{name}: update available {current_label} -> {latest}");
            }
            UpdateStatus::UpdateRequired => {
                println!("{name}: update required {current_label} -> {latest}");
                if let Some(reason) = &check.reason {
                    println!("  {reason}");
                }
            }
            UpdateStatus::NotInstalled => {
                println!("{name} is not installed; latest signed version is {latest}");
            }
            UpdateStatus::Unreadable => {
                println!("{name}: current install is unreadable (latest is {latest})");
                if let Some(reason) = &check.reason {
                    println!("  {reason}");
                }
            }
        }
    }

    if check.status.is_update() {
        Err(CliError::UpdateAvailable)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{UpgradeOutcome, current_for_upgrade, open_storage, upgrade_outcome};
    use crate::CliError;
    use crate::release::ReleaseCommandError;
    use fuz_artifact::{ArtifactError, CurrentLinkProblem};
    use fuz_release::{ReleaseError, StorageBackend, StorageError};
    use std::path::PathBuf;

    fn unreadable() -> ArtifactError {
        ArtifactError::StoreEntryNotDir {
            path: PathBuf::from("/h/artifacts/v1-a"),
            kind: fuz_sys::fs::NonDirKind::Symlink,
        }
    }

    /// The unreadable-current policy runs before any request: refused with the
    /// `--force` hint without it, set aside (no current, so no rollback target)
    /// with it — the forced reinstall `fetch_latest` performs is reachable.
    #[test]
    fn an_unreadable_current_is_refused_unless_forced() {
        let err = current_for_upgrade(Err(unreadable()), false).unwrap_err();
        assert!(
            matches!(
                &err,
                CliError::ReleaseCommand(ReleaseCommandError::Release(
                    ReleaseError::CurrentUnreadable { reason }
                )) if reason.contains("not a directory")
            ),
            "got {err:?}"
        );
        assert!(
            err.hint().is_some_and(|hint| hint.contains("--force")),
            "the refusal names --force"
        );
        assert!(
            current_for_upgrade(Err(unreadable()), true)
                .unwrap()
                .is_none(),
            "--force sets the unreadable install aside"
        );
        assert!(current_for_upgrade(Ok(None), false).unwrap().is_none());
    }

    /// A `current` the switch could not replace is refused even under
    /// `--force`, before any download is spent on it.
    #[test]
    fn a_current_that_is_not_a_symlink_is_refused_even_when_forced() {
        for force in [false, true] {
            let err = current_for_upgrade(
                Err(ArtifactError::CurrentNotStoreLink {
                    path: PathBuf::from("/h/current"),
                    problem: CurrentLinkProblem::NotASymlink,
                }),
                force,
            )
            .unwrap_err();
            assert!(
                matches!(
                    err,
                    CliError::Artifact(ArtifactError::CurrentNotStoreLink { .. })
                ),
                "force={force}: got {err:?}"
            );
        }
    }

    /// `--storage` goes through the existing-store parse: a local path that
    /// is not an existing directory is refused with the location as given and
    /// created by nothing, an existing one opens, and any other parse error
    /// stays a storage error.
    #[test]
    fn open_storage_refuses_a_missing_local_directory_and_creates_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("no-such").join("store");
        for location in [
            missing.to_str().unwrap().to_string(),
            format!("file://{}", missing.display()),
        ] {
            let err = open_storage(&location).unwrap_err();
            assert!(
                matches!(&err, ReleaseCommandError::StorageNotDir { location: named }
                    if *named == location),
                "{location}: {err:?}"
            );
            assert_eq!(err.exit_code(), 1);
        }
        assert!(!dir.path().join("no-such").exists());

        assert!(matches!(
            open_storage(dir.path().to_str().unwrap()),
            Ok(StorageBackend::File(_))
        ));
        assert!(matches!(
            open_storage("https://releases.example.com/fuz"),
            Ok(StorageBackend::Https(_))
        ));
        assert!(matches!(
            open_storage("ssh://deploy@vps.example.com/var/www/releases"),
            Ok(StorageBackend::Ssh(_))
        ));
        assert!(matches!(
            open_storage("object://bucket"),
            Err(ReleaseCommandError::Storage(
                StorageError::InvalidConfig { .. }
            ))
        ));
    }

    #[test]
    fn exact_content_hash_identity_skips() {
        // Same content hash → AlreadyCurrent (skip), regardless of version.
        assert_eq!(
            upgrade_outcome(Some("v1-aaa"), Some("0.3.0"), "v1-aaa", "0.3.0"),
            UpgradeOutcome::AlreadyCurrent,
        );
    }

    #[test]
    fn same_version_different_content_does_not_skip() {
        // The bug guard: a locally-built 0.3.0 (hash A) over a published 0.3.0
        // (hash B) is a real change — version-equality must NOT short-circuit.
        let outcome = upgrade_outcome(Some("v1-aaa"), Some("0.3.0"), "v1-bbb", "0.3.0");
        assert_ne!(
            outcome,
            UpgradeOutcome::AlreadyCurrent,
            "same version but different content must not skip the switch"
        );
        assert_eq!(outcome, UpgradeOutcome::Reinstalled);
    }

    #[test]
    fn different_version_upgrades_reporting_the_old_version() {
        assert_eq!(
            upgrade_outcome(Some("v1-aaa"), Some("0.3.0"), "v1-bbb", "0.4.0"),
            UpgradeOutcome::Upgraded { from: "0.3.0" },
        );
    }

    #[test]
    fn no_current_artifact_is_a_fresh_install() {
        assert_eq!(
            upgrade_outcome(None, None, "v1-bbb", "0.4.0"),
            UpgradeOutcome::Installed,
        );
    }
}
