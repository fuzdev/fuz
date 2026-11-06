//! Per-tool install: fetch, verify, and install first-party tool artifacts.
//!
//! The consumer half of the per-tool model — `fuz` fetches + verifies +
//! installs. A tool is a named, signed, one-or-more binary bundle stored under
//! `tools/<name>/` on the forge:
//!
//! ```text
//! tools/<name>/latest-<target>.json
//! tools/<name>/<name>-<version>-<target>.manifest.json
//! tools/<name>/<name>-<version>-<target>.tar.gz
//! ```
//!
//! Installed into a content-addressed dir `~/.fuz/tools/<name>/v1-<hash>/` with a
//! per-tool `meta.json` ([`ToolMeta`]) and a `current` symlink; binaries link
//! into `~/.fuz/bin/`. Signature + blake3 verification against the embedded
//! ed25519 key is identical to the self-artifact path. No central index — see
//! [`list_installed_tools`].
//!
//! The producer half (`publish_tool`) lives in the `fuz_sign` crate, kept out
//! of the `fuz` consumer's dependency graph.

use std::collections::BTreeMap;
use std::path::PathBuf;

use fuz_artifact::tools::{
    TOOL_INSTALL_TEMP_PREFIX, ToolMeta, cleanup_stale_tool_staging, is_first_party_tool,
};
use fuz_artifact::{
    StoreSlot, reclaim_store_entry, require_current_replaceable, setup_tool_symlinks,
    store_entry_path,
};
use fuz_crypto::ContentHash;
use fuz_home::{
    check_fuz_home_not_world_writable, get_tool_current_link, get_tool_dir, get_tools_dir,
};

use crate::current::{ToolCurrent, current_tool_hash, resolve_current_tool, tool_current_at};
use crate::error::{ManifestError, ReleaseError, TarballError};
use crate::fetch::{download_manifest, download_verify_extract, resolve_latest_version};
use crate::layout::ReleaseLayout;
use crate::log_check::{LogCheck, ReleaseLogPolicy, check_release_log};
use crate::manifest::{
    Manifest, VerifiedManifest, check_version_safety_with_downgrade, current_target,
};
use fuz_storage::Storage;
use fuz_sys::SECURE_DIR_MODE;
use fuz_sys::fs::CleanupGuard;
use fuz_sys::rand::random_hex_suffix;

/// Options for [`install_tool`].
#[derive(Debug, Default)]
pub struct ToolInstallOptions<'a> {
    /// The version to install; `None` resolves the tool's `latest-<target>.json` for this target.
    pub version: Option<&'a str>,
    /// Allow installing a version older than the installed one. The
    /// publisher's `minimum_version` floor is enforced either way.
    pub allow_downgrade: bool,
    /// Reinstall over an unreadable current install instead of refusing it.
    pub force: bool,
    /// Whether the release is held to the release log before its bytes are
    /// used. The default, [`ReleaseLogPolicy::Inactive`], checks nothing.
    /// Neither `allow_downgrade` nor `force` relaxes an enforced check.
    pub release_log: ReleaseLogPolicy,
}

/// Result of a tool install.
#[derive(Debug)]
pub struct ToolInstallResult {
    /// Tool name.
    pub name: String,
    /// Installed version.
    pub version: String,
    /// Content hash of the installed artifact.
    pub content_hash: String,
    /// Path to the per-tool install dir (`~/.fuz/tools/<name>/v1-<hash>/`).
    pub install_dir: PathBuf,
    /// Binary names installed (linked into `~/.fuz/bin/`).
    pub binaries: Vec<String>,
    /// What the install did to the tool's active binary — the classification a
    /// caller reports from. Not a download flag: a hash whose dir is already on
    /// disk still moves `current` when it wasn't the current one.
    pub outcome: ToolInstallOutcome,
    /// When `--force` reinstalled over an unreadable current install, the reason
    /// it was unreadable (so the caller can warn it repaired a broken state);
    /// `None` on a normal install.
    pub repaired_unreadable: Option<String>,
    /// What the release log check did: nothing (inactive or opted out), or
    /// the report of the head that confirmed this release.
    pub release_log: LogCheck,
}

/// What an [`install_tool`] call did to the tool's **active** binary.
///
/// [`install_tool`] always (re)points `~/.fuz/tools/<name>/current` — and through
/// it every `~/.fuz/bin/<binary>` — at the requested hash, so "the download was
/// skipped" and "nothing changed" are different questions. This answers the
/// second: [`AlreadyCurrent`](Self::AlreadyCurrent) is the only outcome a
/// caller may report as a no-op.
///
/// Only the already-on-disk branch needs to look — it reads where `current`
/// aimed before the relink, which is what separates
/// [`AlreadyCurrent`](Self::AlreadyCurrent) from
/// [`Relinked`](Self::Relinked). The download branch answers
/// [`Installed`](Self::Installed) without consulting `current` at all, and one
/// reachable state makes that the right answer while the link's target string
/// is unchanged: a `--force` over a dangling `current` whose dead target is
/// the very hash being installed. Nothing moved, but the active binary went
/// from broken to working, so it is not a no-op.
///
/// The `bin/<binary>` links `setup_tool_symlinks` writes alongside it are *not*
/// observed, so two residual states leave an `AlreadyCurrent` call still moving
/// what is on `PATH`. A crash between the `current` write and the `bin/` writes
/// leaves `current` correct with a `bin/<binary>` missing, which the next install
/// silently recreates while reporting the no-op. And nothing forbids two tools
/// declaring the same binary name — `Manifest::validate` checks only the tool
/// allowlist and a non-empty set — so reinstalling one tool's already-current
/// hash takes that shared name back from the other. Both need a prior crash or a
/// colliding manifest to reach; the routine `--version` rollback is covered by
/// the `current` observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolInstallOutcome {
    /// The requested hash was already installed *and* already `current` — the
    /// active binary is unchanged.
    AlreadyCurrent,
    /// The requested hash was already installed but `current` pointed elsewhere,
    /// so the relink moved the active binary. Nothing was downloaded.
    Relinked {
        /// The hash `current` pointed at before the relink, or `None` when
        /// `current_tool_hash` could read no target: there is no `current` entry
        /// at all (an install dir left behind by a removed link), `current` is
        /// present but is not a symlink, its target is outside the tool's store,
        /// or the hash it names is invalid UTF-8. A **dangling** `current` is not in that
        /// set — the read is a `readlink(2)` with no traversal, so a link aimed
        /// at a removed install dir still reports `Some(<the dead hash>)`,
        /// `--force`d reinstalls included.
        previous: Option<String>,
    },
    /// The artifact was fetched, verified, and extracted, then made current.
    Installed,
}

impl ToolInstallOutcome {
    /// Whether the active binary is now a different one than before the call —
    /// true for everything but [`AlreadyCurrent`](Self::AlreadyCurrent).
    #[must_use]
    pub const fn changed_active_binary(&self) -> bool {
        !matches!(self, Self::AlreadyCurrent)
    }

    /// Classify an install whose content-addressed dir was already on disk, from
    /// the hash `current` pointed at *before* the relink.
    fn from_relink(previous: Option<String>, target_hash: &str) -> Self {
        if previous.as_deref() == Some(target_hash) {
            Self::AlreadyCurrent
        } else {
            Self::Relinked { previous }
        }
    }
}

//
// Fetch + install
//

/// Resolve, download, and verify a tool manifest from storage.
///
/// Resolves `version` (or `tools/<name>/latest-<target>.json` for this target when `None`), downloads
/// the manifest, validates + verifies its signature, and confirms it declares
/// itself as `name` at that version ([`Manifest::check_key`]). Does NOT touch
/// `~/.fuz` — the testable verification seam.
pub async fn fetch_tool_manifest(
    storage: &impl Storage,
    name: &str,
    version: Option<&str>,
) -> Result<VerifiedManifest, ReleaseError> {
    if !is_first_party_tool(name) {
        return Err(ManifestError::ToolNotAllowed(name.to_string()).into());
    }
    let layout = ReleaseLayout::tool(name);

    let version = if let Some(v) = version {
        v.to_string()
    } else {
        resolve_latest_version(storage, &layout, Some(name)).await?
    };

    let target = current_target();
    let manifest_key = layout.manifest_key(name, &version, target);
    let manifest_bytes = download_manifest(storage, &manifest_key).await?;

    let manifest = Manifest::for_current_platform(&manifest_bytes)?;
    let manifest = manifest.verify_signature()?;

    // The manifest must declare itself as the tool we asked for. Validation
    // already gated the *name* against the allowlist; this catches a manifest
    // served under the wrong key (or the self manifest masquerading).
    if manifest.tool.as_deref() != Some(name) {
        return Err(ReleaseError::ToolManifestMismatch {
            expected: name.to_string(),
            actual: manifest.tool.clone(),
        });
    }
    // And it must be the version whose key it was read from: the one pinned,
    // or the one the latest pointer names.
    manifest.check_key(&layout, name, &manifest_key)?;

    Ok(manifest)
}

/// Read the currently-installed [`ToolMeta`] for `name`, or `None` if not
/// installed.
///
/// One integrity-checked read of `~/.fuz/tools/<name>/current/meta.json`,
/// returning the whole record — callers that want both the version *and* the
/// content hash (`fuz tool upgrade`) get a single consistent snapshot instead of
/// two reads that a concurrent install could straddle. Best-effort: a missing
/// `current` link, one naming something other than a real install directory,
/// or an unreadable meta reads as "not installed" (`None`) — the same treatment
/// [`list_installed_tools`] gives a partial entry.
///
/// The content hash on the returned meta is the tool artifact's unique identity;
/// the version string is not (a locally-built and a published tool can share a
/// version yet differ in content), so `fuz tool upgrade` keys its "unchanged"
/// verdict on the hash, not on version equality.
#[must_use]
pub fn installed_tool_meta(name: &str) -> Option<ToolMeta> {
    let current = get_tool_current_link(name).ok()?;
    match tool_current_at(&current) {
        ToolCurrent::Dir(dir) => ToolMeta::read(&dir).ok(),
        ToolCurrent::Missing | ToolCurrent::Dangling | ToolCurrent::Corrupt(_) => None,
    }
}

/// Install (or re-link a cached) tool from storage.
///
/// Fetches + verifies the manifest, applies version safety, downloads + verifies
/// the tarball, extracts to a content-addressed dir, writes [`ToolMeta`], and
/// sets up the per-tool `current` symlink + `~/.fuz/bin/` links. Idempotent in
/// effect: an already-present content hash is re-verified and re-linked rather
/// than re-downloaded. Already-present means a real directory: a symlink (live
/// or dangling) or file at `tools/<name>/v1-<hash>/` is unlinked, never its
/// target, and the tool is downloaded fresh. The relink is unconditional, so the returned
/// [`ToolInstallOutcome`] — not the skipped download — is what says whether the
/// active binary moved.
///
/// Version safety (symmetric with the self path's [`fetch_version`](crate::fetch::fetch_version)):
/// the verified manifest version is compared against the currently-installed
/// version (`None` when the tool isn't installed) via
/// [`check_version_safety_with_downgrade`]
/// *before* any download/cache work. A **fresh install** (nothing installed) of
/// any version is allowed — neither the downgrade guard nor the publisher's
/// `minimum_version` floor gates a first install. On an **upgrade** (something is
/// installed), an explicit `--version <older>` is a downgrade — blocked unless
/// `allow_downgrade` — and the `minimum_version` floor is enforced and never
/// waived by `allow_downgrade`.
///
/// Release log: after version safety and before the on-disk check, the release
/// is held to the release log under `options.release_log`
/// ([`check_release_log`]) — so a hash already unpacked is refused too once its
/// release is revoked. The default policy checks nothing.
pub async fn install_tool(
    storage: &impl Storage,
    name: &str,
    options: &ToolInstallOptions<'_>,
) -> Result<ToolInstallResult, ReleaseError> {
    // A write path into `~/.fuz` — refuse a world-writable home up front, before
    // the download, so the refusal is immediate and nothing lands in a tree any
    // local user can rewrite. The read-only `fetch_tool_manifest` (`--check`)
    // deliberately skips this.
    check_fuz_home_not_world_writable()?;

    // The name gates every path built from it — before `current` is inspected,
    // so a name outside the allowlist (`../x` included) is refused as such, with
    // no request and no filesystem access under it. `fetch_tool_manifest` makes
    // the same refusal for its own callers.
    if !is_first_party_tool(name) {
        return Err(ManifestError::ToolNotAllowed(name.to_string()).into());
    }

    // A `current` that is not a symlink can't be swapped for one (a directory
    // fails the rename `EISDIR`), and `--force` does not change that: refuse
    // before any request, and leave it — fuz did not write it.
    require_current_replaceable(&get_tool_current_link(name)?)?;

    let manifest = fetch_tool_manifest(storage, name, options.version).await?;

    // Version safety, before any download/cache work. A fresh install
    // (`NotInstalled`) skips the floor + downgrade guard; a readable install
    // gates the upgrade against its version; an unreadable install is refused
    // unless `force` reinstalls over it.
    let current = resolve_current_tool(name);
    let (current_version, repaired) = current.for_install(options.force)?;
    check_version_safety_with_downgrade(current_version, &manifest, options.allow_downgrade)?;
    let repaired_unreadable = repaired.map(str::to_string);

    // Hold the release to the release log: after version safety, so a
    // downgrade is reported as a downgrade; before the on-disk branch, so a
    // hash unpacked before its release was revoked is refused, not relinked.
    let release_log = check_release_log(&options.release_log, &manifest).await?;

    let tool_dir = get_tool_dir(name)?;
    let install_dir = store_entry_path(&tool_dir, &manifest.content_hash)?;
    let binaries: Vec<String> = manifest.binaries.keys().cloned().collect();
    let binary_refs: Vec<&str> = binaries.iter().map(String::as_str).collect();

    // Already on disk: re-verify the binaries, then (re)link. Only a real
    // directory is on disk in that sense — a symlink (live or dangling) or file
    // at the slot is unlinked, never its target, and the tool downloads fresh,
    // where a dangling link would otherwise fail the rename below with
    // `ENOTDIR` on every run and a live one would be verified through.
    if reclaim_store_entry(&tool_dir, &manifest.content_hash)? == StoreSlot::RealDir {
        let meta = ToolMeta::read(&install_dir)?;
        meta.verify_binaries(&install_dir)?;
        // Read where `current` aims *before* the relink: `setup_tool_symlinks`
        // repoints it unconditionally, so this is the last moment the previous
        // target is observable — and it is the whole basis of the outcome.
        let previous = current_tool_hash(name);
        setup_tool_symlinks(name, &manifest.content_hash, &binary_refs)?;
        let outcome = ToolInstallOutcome::from_relink(previous, &manifest.content_hash);
        let manifest = manifest.into_manifest();
        return Ok(ToolInstallResult {
            name: name.to_string(),
            version: manifest.version,
            content_hash: manifest.content_hash,
            install_dir,
            binaries,
            outcome,
            repaired_unreadable,
            release_log,
        });
    }

    // Stream + verify + extract the tarball into a temp dir (bounded memory),
    // then atomically rename. Same trust checks as the self-artifact path.
    // Moded, like the staging dir below and like the local path's own
    // (`fuz_artifact`'s `install_local_tool`): `~/.fuz/tools/` and
    // `~/.fuz/tools/<name>/` are dirs fuz owns, `ensure_fuz_home` creates
    // neither, and a plain `create_dir_all` would land them at the umask.
    tokio::fs::DirBuilder::new()
        .mode(SECURE_DIR_MODE)
        .recursive(true)
        .create(&tool_dir)
        .await
        .map_err(TarballError::Io)?;
    // Sweep crashed installs' staging dirs (age-gated: a concurrent install's
    // live one sits beside them) before staging this one.
    cleanup_stale_tool_staging(&tool_dir);
    let temp_dir = tool_dir.join(format!("{TOOL_INSTALL_TEMP_PREFIX}{}", random_hex_suffix()));
    // Moded and non-recursive — the same create the local path
    // (`fuz_artifact`'s `install_local_tool`) makes, since these two stage into
    // the same `~/.fuz/tools/<name>/` and this dir *becomes* the installed dir
    // at the rename below. `create_dir_all` would take the mode from the umask
    // and silently adopt a pre-existing directory; `create` fails `EEXIST`,
    // which is what makes the random suffix a real uniqueness claim rather than
    // a merge. `tool_dir` is created just above, so recursion buys nothing.
    tokio::fs::DirBuilder::new()
        .mode(SECURE_DIR_MODE)
        .create(&temp_dir)
        .await
        .map_err(TarballError::Io)?;
    let guard = CleanupGuard::new(temp_dir.clone());

    download_verify_extract(
        storage,
        &ReleaseLayout::tool(name).tarball_key(&manifest.tarball.path),
        &manifest,
        &temp_dir,
    )
    .await?;

    let binary_map: BTreeMap<String, ContentHash> = manifest
        .binaries
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let meta = ToolMeta::new(name.to_string(), manifest.version.clone(), binary_map);
    meta.write(&temp_dir)?;
    // Re-hash the extracted binaries against the meta before publishing the
    // dir, as the local path does: a staging tree that lost or changed a file
    // since extraction (a stale-staging sweep of a stalled install included)
    // fails here rather than landing as an install.
    meta.verify_binaries(&temp_dir)?;

    tokio::fs::rename(&temp_dir, &install_dir)
        .await
        .map_err(TarballError::Io)?;
    guard.defuse();

    setup_tool_symlinks(name, &manifest.content_hash, &binary_refs)?;

    let manifest = manifest.into_manifest();
    Ok(ToolInstallResult {
        name: name.to_string(),
        version: manifest.version,
        content_hash: manifest.content_hash,
        install_dir,
        binaries,
        outcome: ToolInstallOutcome::Installed,
        repaired_unreadable,
        release_log,
    })
}

/// Verify an installed tool: read its `current/meta.json` and re-hash its
/// binaries on disk.
///
/// `current` must be a symlink into the tool's store
/// ([`ArtifactError::CurrentNotStoreLink`](fuz_artifact::ArtifactError::CurrentNotStoreLink)
/// otherwise), and the install it names a real directory: a symlink or file at
/// `tools/<name>/v1-<hash>` is refused with
/// [`ArtifactError::StoreEntryNotDir`](fuz_artifact::ArtifactError::StoreEntryNotDir),
/// and a `meta.json` or binary inside that is a symlink with
/// [`ArtifactError::NotRegularFile`](fuz_artifact::ArtifactError::NotRegularFile)
/// — nothing is read through a link. No `current` link, or a dangling one, is
/// [`ReleaseError::ToolNotInstalled`].
pub fn verify_installed_tool(name: &str) -> Result<ToolMeta, ReleaseError> {
    let current = get_tool_current_link(name)?;
    let dir = match tool_current_at(&current) {
        ToolCurrent::Dir(dir) => dir,
        ToolCurrent::Missing | ToolCurrent::Dangling => {
            return Err(ReleaseError::ToolNotInstalled(name.to_string()));
        }
        ToolCurrent::Corrupt(e) => return Err(e.into()),
    };
    let meta = ToolMeta::read(&dir)?;
    meta.verify_binaries(&dir)?;
    Ok(meta)
}

/// List installed tools by scanning `~/.fuz/tools/*/current/meta.json`.
///
/// No central index: each tool's current install record is the source of
/// truth. Entries without a `current` symlink, with one naming something other
/// than a real install directory, or with an unreadable meta are skipped.
/// Sorted by tool name.
pub fn list_installed_tools() -> Result<Vec<ToolMeta>, ReleaseError> {
    let tools_dir = get_tools_dir()?;
    let mut out = Vec::new();

    let Ok(entries) = std::fs::read_dir(&tools_dir) else {
        return Ok(out); // No tools dir yet = nothing installed.
    };

    for entry in entries.flatten() {
        if !entry.file_type().is_ok_and(|t| t.is_dir()) {
            continue;
        }
        let current = entry.path().join(fuz_home::CURRENT_LINK);
        let ToolCurrent::Dir(dir) = tool_current_at(&current) else {
            continue;
        };
        if let Ok(meta) = ToolMeta::read(&dir) {
            out.push(meta);
        }
    }

    out.sort_by(|a, b| a.tool.cmp(&b.tool));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fuz_storage::FileStorage;

    #[test]
    fn relink_onto_the_same_hash_is_the_only_no_op() {
        assert_eq!(
            ToolInstallOutcome::from_relink(Some("v1-aaa".to_string()), "v1-aaa"),
            ToolInstallOutcome::AlreadyCurrent,
        );
        assert!(!ToolInstallOutcome::AlreadyCurrent.changed_active_binary());
    }

    #[test]
    fn relink_off_another_hash_reports_the_move() {
        // The case a skipped-download flag can't see: the bytes were cached, but
        // `current` (and every `bin/<binary>` through it) just moved.
        let outcome = ToolInstallOutcome::from_relink(Some("v1-aaa".to_string()), "v1-bbb");
        assert_eq!(
            outcome,
            ToolInstallOutcome::Relinked {
                previous: Some("v1-aaa".to_string()),
            },
        );
        assert!(outcome.changed_active_binary());
    }

    #[test]
    fn relink_with_no_previous_link_still_reports_the_move() {
        // An install dir present with no `current` link: the active binary went
        // from nothing to something, which is not "already have it".
        let outcome = ToolInstallOutcome::from_relink(None, "v1-bbb");
        assert_eq!(outcome, ToolInstallOutcome::Relinked { previous: None });
        assert!(outcome.changed_active_binary());
    }

    #[tokio::test]
    async fn fetch_tool_manifest_rejects_disallowed_name() {
        let storage_dir = tempfile::tempdir().unwrap();
        let storage = FileStorage::new(storage_dir.path()).unwrap();
        let err = fetch_tool_manifest(&storage, "rando", None)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            ReleaseError::Manifest(ManifestError::ToolNotAllowed(name)) if name == "rando"
        ));
    }
}
