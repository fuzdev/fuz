//! Resolving the currently-installed version.
//!
//! The self artifact and per-tool install state resolve to an explicit
//! three-way [`CurrentVersion`] rather than an `Option` + `"0.0.0"` sentinel +
//! swallowed read errors. The distinction drives both version-safety (a fresh
//! install skips the `minimum_version` floor; an unreadable state is refused
//! unless forced) and honest `--check` reporting (never claim "update required"
//! for something never installed).

use std::path::{Path, PathBuf};

use fuz_artifact::tools::ToolMeta;
use fuz_artifact::{
    ArtifactError, StoreSlot, current_link_target, get_current_artifact, inspect_store_entry,
};
use fuz_home::{get_current_link, get_tool_current_link};

use crate::error::ReleaseError;

/// The resolved state of a currently-installed self artifact or tool.
#[derive(Debug, Clone)]
pub enum CurrentVersion {
    /// A readable install at this version.
    Installed(semver::Version),
    /// Nothing installed — a genuine first install (no `current` link).
    NotInstalled,
    /// A `current` entry exists but the install can't be read: a dangling
    /// link, a `current` that is not a symlink or points outside its store, a
    /// symlink or file at the install it names, an unreadable/corrupt
    /// `meta.json`, or a non-semver version.
    Unreadable {
        /// A human-readable diagnostic for why the install couldn't be read.
        reason: String,
    },
}

impl CurrentVersion {
    /// The installed version for version-safety gating, or `None` for a fresh
    /// install. `Unreadable` maps to `None` here too, but callers on the install
    /// path route through [`for_install`](Self::for_install) so the corrupt-state
    /// policy stays explicit; this accessor is for read-only reporting.
    #[must_use]
    pub const fn installed(&self) -> Option<&semver::Version> {
        match self {
            Self::Installed(v) => Some(v),
            Self::NotInstalled | Self::Unreadable { .. } => None,
        }
    }

    /// Resolve the version-safety input for an install, applying the
    /// corrupt-state policy:
    ///
    /// - [`Installed`](Self::Installed) → gate against that version.
    /// - [`NotInstalled`](Self::NotInstalled) → fresh install (`None`, floor skipped).
    /// - [`Unreadable`](Self::Unreadable) → **refused** unless `force`; with
    ///   `force`, reinstalled from scratch (`None`) and the reason is returned so
    ///   the caller can warn that it repaired an unreadable state.
    ///
    /// Returns `(installed_version, repaired_reason)` — the second element is
    /// `Some` only on the forced-over-unreadable path.
    ///
    /// # Errors
    ///
    /// [`ReleaseError::CurrentUnreadable`] when the state is unreadable and
    /// `force` is not set.
    pub fn for_install(
        &self,
        force: bool,
    ) -> Result<(Option<&semver::Version>, Option<&str>), ReleaseError> {
        match self {
            Self::Installed(v) => Ok((Some(v), None)),
            Self::NotInstalled => Ok((None, None)),
            Self::Unreadable { reason } if force => Ok((None, Some(reason.as_str()))),
            Self::Unreadable { reason } => Err(ReleaseError::CurrentUnreadable {
                reason: reason.clone(),
            }),
        }
    }
}

/// Classify a meta version string into `Installed` (valid semver) or `Unreadable`
/// (a corrupt version field).
fn classify_version(version: &str) -> CurrentVersion {
    semver::Version::parse(version).map_or_else(
        |_| CurrentVersion::Unreadable {
            reason: format!("meta.json has an invalid version '{version}'"),
        },
        CurrentVersion::Installed,
    )
}

/// Whether a `current`-link path is a dangling symlink (the link exists but its
/// target doesn't) — a corruption signal distinct from "no link at all".
fn is_dangling(link: &Path) -> bool {
    link.symlink_metadata().is_ok() && !link.exists()
}

/// Resolve the currently-installed self (fuz) artifact version.
///
/// # Errors
///
/// Returns a [`ReleaseError`] only for a home-resolution failure; a corrupt or
/// dangling install is reported as [`CurrentVersion::Unreadable`], not an error.
pub fn resolve_current_self() -> Result<CurrentVersion, ReleaseError> {
    match get_current_artifact() {
        Ok(Some(meta)) => Ok(classify_version(&meta.version)),
        // `None` = no readable current: distinguish a dangling link (corrupt)
        // from a genuinely-absent one (fresh).
        Ok(None) => match get_current_link() {
            Ok(link) if is_dangling(&link) => Ok(CurrentVersion::Unreadable {
                reason: "the `current` symlink points to a missing artifact".to_string(),
            }),
            _ => Ok(CurrentVersion::NotInstalled),
        },
        Err(e) => Ok(CurrentVersion::Unreadable {
            reason: e.to_string(),
        }),
    }
}

/// Where a tool's `current` link leads, classified without reading through a
/// link at the install it names.
///
/// `current` is the one entry in a tool's store that is meant to be a symlink,
/// to a bare `v1-<hash>` (or the absolute path of `tools/<name>/v1-<hash>`);
/// what it names must be the real install directory fuz renamed into place. A
/// symlink there — live or dangling — or a file is [`Corrupt`](Self::Corrupt),
/// as is a target outside the tool's store, so no reader goes on to read
/// `meta.json` or a binary through it. A `current` that is not itself a symlink is
/// [`Corrupt`](Self::Corrupt): fuz only ever writes a link there, and an
/// install could not replace a directory with one.
#[derive(Debug)]
pub(crate) enum ToolCurrent {
    /// No `current` entry at all — the tool is not installed.
    Missing,
    /// `current` is a symlink whose target does not exist.
    Dangling,
    /// `current` is not a symlink, points outside the tool's store, or names
    /// something other than a real directory — or could not be inspected.
    Corrupt(ArtifactError),
    /// The real install directory `current` names.
    Dir(PathBuf),
}

/// Classify the tool `current` link at `link` — the shared front half of every
/// installed-tool reader ([`resolve_current_tool`],
/// [`installed_tool_meta`](crate::tool::installed_tool_meta),
/// [`verify_installed_tool`](crate::tool::verify_installed_tool),
/// [`list_installed_tools`](crate::tool::list_installed_tools)).
pub(crate) fn tool_current_at(link: &Path) -> ToolCurrent {
    // The tool's store is the directory `current` lives in.
    let store = link.parent().unwrap_or_else(|| Path::new("."));
    let name = match current_link_target(link, store) {
        Ok(Some(name)) => name,
        Ok(None) => return ToolCurrent::Missing,
        Err(e) => return ToolCurrent::Corrupt(e),
    };
    match inspect_store_entry(store, &name) {
        Ok(StoreSlot::RealDir) => ToolCurrent::Dir(store.join(name)),
        Ok(StoreSlot::Vacant) => ToolCurrent::Dangling,
        Err(e) => ToolCurrent::Corrupt(e),
    }
}

/// Resolve the currently-installed version of tool `name`.
///
/// Best-effort like [`resolve_current_self`]: a missing `current` link reads as
/// [`CurrentVersion::NotInstalled`]; a dangling link, a `current` that is not a
/// symlink or points outside the tool's store, one naming something other than
/// a real install directory (a symlink or file at `tools/<name>/v1-<hash>`),
/// or an unreadable `meta.json` reads as
/// [`CurrentVersion::Unreadable`] — never silently swallowed to
/// "not installed", and never read through.
#[must_use]
pub fn resolve_current_tool(name: &str) -> CurrentVersion {
    let Ok(link) = get_tool_current_link(name) else {
        return CurrentVersion::NotInstalled;
    };
    let dir = match tool_current_at(&link) {
        ToolCurrent::Missing => return CurrentVersion::NotInstalled,
        ToolCurrent::Dangling => {
            return CurrentVersion::Unreadable {
                reason: "the tool's `current` symlink points to a missing install".to_string(),
            };
        }
        ToolCurrent::Corrupt(e) => {
            return CurrentVersion::Unreadable {
                reason: e.to_string(),
            };
        }
        ToolCurrent::Dir(dir) => dir,
    };
    match ToolMeta::read(&dir) {
        Ok(meta) => classify_version(&meta.version),
        Err(e) => CurrentVersion::Unreadable {
            reason: e.to_string(),
        },
    }
}

/// The content hash a tool's `current` symlink points at, or `None` when there
/// is no readable link.
///
/// The hash-identity counterpart to [`resolve_current_tool`], which classifies by
/// *version*. A version is not an identity — two artifacts can share one — so any
/// "did the active binary move?" verdict has to read the link target, and that
/// target *is* the hash: [`setup_tool_symlinks`](fuz_artifact::setup_tool_symlinks)
/// writes a bare relative `v1-<hash>`. Read without following the link, so a dangling
/// `current` still reports what it aimed at. Only a link into the tool's own
/// store names a hash ([`current_link_target`], which also accepts the absolute
/// spelling of the same entry): a `current` that is not a symlink or points
/// elsewhere — even at a directory named like the hash — reads as `None`, so a
/// relink off it is reported as a change.
pub(crate) fn current_tool_hash(name: &str) -> Option<String> {
    let link = get_tool_current_link(name).ok()?;
    let store = link.parent()?;
    let name = current_link_target(&link, store).ok()??;
    Some(name.to_str()?.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> semver::Version {
        semver::Version::parse(s).unwrap()
    }

    #[test]
    fn installed_exposes_version_only_when_installed() {
        assert_eq!(
            CurrentVersion::Installed(v("1.2.3")).installed(),
            Some(&v("1.2.3"))
        );
        assert_eq!(CurrentVersion::NotInstalled.installed(), None);
        assert_eq!(
            CurrentVersion::Unreadable {
                reason: "x".to_string()
            }
            .installed(),
            None
        );
    }

    #[test]
    fn for_install_installed_gates_against_version() {
        let cv = CurrentVersion::Installed(v("0.4.0"));
        let (current, repaired) = cv.for_install(false).unwrap();
        assert_eq!(current, Some(&v("0.4.0")));
        assert!(repaired.is_none());
    }

    #[test]
    fn for_install_not_installed_is_fresh() {
        let (current, repaired) = CurrentVersion::NotInstalled.for_install(false).unwrap();
        assert!(current.is_none());
        assert!(repaired.is_none());
    }

    #[test]
    fn for_install_unreadable_refused_without_force() {
        let cv = CurrentVersion::Unreadable {
            reason: "dangling".to_string(),
        };
        let err = cv.for_install(false).unwrap_err();
        assert!(
            matches!(&err, ReleaseError::CurrentUnreadable { reason } if reason == "dangling"),
            "got {err:?}"
        );
    }

    #[test]
    fn for_install_unreadable_self_heals_with_force() {
        let cv = CurrentVersion::Unreadable {
            reason: "corrupt meta".to_string(),
        };
        let (current, repaired) = cv.for_install(true).unwrap();
        // Forced → treated as fresh (skip floor), and the reason surfaces so the
        // caller can warn it repaired an unreadable state.
        assert!(current.is_none());
        assert_eq!(repaired, Some("corrupt meta"));
    }

    #[test]
    fn classify_version_rejects_non_semver() {
        assert!(matches!(
            classify_version("not-semver"),
            CurrentVersion::Unreadable { .. }
        ));
        assert!(matches!(
            classify_version("1.0.0"),
            CurrentVersion::Installed(_)
        ));
    }
}
