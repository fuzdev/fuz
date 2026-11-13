//! Store-entry policy: what to do when a slot that should hold a real directory
//! holds something else.
//!
//! The artifact and tool stores keep each install as a directory fuz renamed
//! into place — `artifacts/v1-<hash>/`, `tools/<name>/v1-<hash>/`. A symlink,
//! file, or special file at one of those names is never something fuz wrote,
//! and a link there would make every later read of the install (verify,
//! `current`, `bin/<binary>`) a read of whatever it points at. Same-uid
//! hygiene, not a privilege boundary — the stores are `0700` — but the slot is
//! classified with [`fuz_sys::fs::probe_real_dir`] (no-follow) and never
//! through the entry.
//!
//! A slot is always addressed as `(store_dir, name)` and the name must be one
//! plain path component ([`store_entry_path`]), so a malformed name — a content
//! hash from a signed manifest, a hash a user typed — can never make either
//! policy act outside the store.
//!
//! Two policies, chosen by whether the caller has something to rebuild from:
//!
//! - [`reclaim_store_entry`] — the install paths (`create_artifact`,
//!   `install_local_tool`, `fuz_release`'s `install_tool` and the self-upgrade
//!   fetch), which are about to write the slot anyway: a non-directory entry is
//!   unlinked (the entry, never a link's target) and the slot reads as vacant.
//! - [`inspect_store_entry`] — the paths with nothing to rebuild from (switching
//!   `current`, reading a tool's `current` install): a non-directory entry is
//!   refused with [`ArtifactError::StoreEntryNotDir`] and left in place.
//!
//! The `current` links that name those slots get the same treatment from
//! [`current_link_target`] (followed only into their own store) and
//! [`require_current_replaceable`] (a `current` that is not a symlink is
//! refused, never removed).

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

use fuz_sys::fs::{DirProbe, probe_real_dir};

use crate::{ArtifactError, CurrentLinkProblem};

/// What a store slot holds once [`reclaim_store_entry`] or
/// [`inspect_store_entry`] has classified it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreSlot {
    /// Nothing is at the slot; an install may rename its staging dir onto it.
    Vacant,
    /// A real directory — an existing install, still to be verified by the
    /// caller.
    RealDir,
}

/// The path of the entry `name` in `store_dir`, refusing any `name` that is not
/// a single plain path component.
///
/// Every store slot is addressed this way rather than by a caller-built path,
/// so a name — a content hash from a signed manifest, a hash a user typed — can
/// never name the store itself, its parent, something deeper, or the entry with
/// a trailing `/` or `/.` (which the kernel resolves *through* the entry,
/// following a symlink there). See [`fuz_sys::fs::is_plain_file_name`].
///
/// # Errors
///
/// [`ArtifactError::InvalidStoreName`] for an empty name, `.`, `..`, or one
/// containing `/`.
pub fn store_entry_path(
    store_dir: &Path,
    name: impl AsRef<OsStr>,
) -> Result<PathBuf, ArtifactError> {
    let name = name.as_ref();
    if fuz_sys::fs::is_plain_file_name(name) {
        Ok(store_dir.join(name))
    } else {
        Err(ArtifactError::InvalidStoreName {
            name: name.to_string_lossy().into_owned(),
        })
    }
}

/// Classify the store slot `name` in `store_dir`, unlinking a non-directory
/// entry so the caller can install fresh.
///
/// A symlink (live or dangling), regular file, or special file at the slot is
/// removed with `remove_file`, which unlinks the entry itself and never a
/// link's target, and the slot reads as [`StoreSlot::Vacant`]. A dangling link
/// in particular has to go: `Path::exists` reads it as absent, and the install's
/// `rename` onto it then fails `ENOTDIR` on every run.
///
/// A real directory is returned as [`StoreSlot::RealDir`] untouched — whether it
/// is a valid install is the caller's verify step.
///
/// The slot is addressed by name ([`store_entry_path`]), so nothing outside
/// `store_dir` can be unlinked whatever the name says.
///
/// # Errors
///
/// [`ArtifactError::InvalidStoreName`] for a name that is not one plain path
/// component; [`ArtifactError::Io`] if the slot cannot be inspected (an `lstat`
/// error other than absence) or the entry cannot be unlinked.
pub fn reclaim_store_entry(
    store_dir: &Path,
    name: impl AsRef<OsStr>,
) -> Result<StoreSlot, ArtifactError> {
    let path = store_entry_path(store_dir, name)?;
    match probe_real_dir(&path).map_err(ArtifactError::Io)? {
        DirProbe::Absent => Ok(StoreSlot::Vacant),
        DirProbe::RealDir => Ok(StoreSlot::RealDir),
        DirProbe::NotDir(_) => {
            unlink_entry(&path).map_err(ArtifactError::Io)?;
            Ok(StoreSlot::Vacant)
        }
    }
}

/// Unlink the entry at `path` itself — never a link's target — treating an
/// entry that is already gone as unlinked.
///
/// The entry was classified a moment earlier; if it vanished in between, the
/// slot is vacant either way, which is what the caller wanted.
fn unlink_entry(path: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        result => result,
    }
}

/// Classify the store slot `name` in `store_dir`, refusing a non-directory
/// entry and leaving it in place.
///
/// For a caller with nothing to rebuild the install from, so removing the entry
/// would only turn a corrupt install into a missing one.
///
/// # Errors
///
/// [`ArtifactError::StoreEntryNotDir`] for a symlink (live or dangling),
/// regular file, or special file at the slot;
/// [`ArtifactError::InvalidStoreName`] for a name that is not one plain path
/// component; [`ArtifactError::Io`] if the slot cannot be inspected.
pub fn inspect_store_entry(
    store_dir: &Path,
    name: impl AsRef<OsStr>,
) -> Result<StoreSlot, ArtifactError> {
    let path = store_entry_path(store_dir, name)?;
    match probe_real_dir(&path).map_err(ArtifactError::Io)? {
        DirProbe::Absent => Ok(StoreSlot::Vacant),
        DirProbe::RealDir => Ok(StoreSlot::RealDir),
        DirProbe::NotDir(kind) => Err(ArtifactError::StoreEntryNotDir { path, kind }),
    }
}

/// Where a `current` link points, accepting only an entry directly inside
/// `store_dir` — the one place fuz ever points it.
///
/// `Ok(None)` when there is no entry at `link`. Otherwise `link` must be a
/// symlink whose target, resolved lexically (a relative target against the
/// link's own directory, as the kernel resolves it), names a child of
/// `store_dir`: `artifacts/v1-<hash>` for the self `current` and `v1-<hash>` for a
/// tool's, which is what fuz writes, or the absolute path of the same entry.
/// A `..` that leaves the store, a deeper path, or a target elsewhere is
/// refused rather than read through. Returns the entry's **name** in
/// `store_dir` (one plain component, whatever suffix the target carried), *not*
/// yet known to be a real directory — classify it with [`inspect_store_entry`].
///
/// # Errors
///
/// [`ArtifactError::CurrentNotStoreLink`] when `link` is not a symlink
/// ([`CurrentLinkProblem::NotASymlink`]) or its target is outside `store_dir`
/// ([`CurrentLinkProblem::OutsideStore`]); [`ArtifactError::Io`] if it cannot be
/// inspected or read.
pub fn current_link_target(
    link: &Path,
    store_dir: &Path,
) -> Result<Option<OsString>, ArtifactError> {
    match link.symlink_metadata() {
        Ok(meta) if meta.file_type().is_symlink() => {}
        Ok(_) => {
            return Err(ArtifactError::CurrentNotStoreLink {
                path: link.to_path_buf(),
                problem: CurrentLinkProblem::NotASymlink,
            });
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(ArtifactError::Io(e)),
    }
    let target = std::fs::read_link(link).map_err(ArtifactError::Io)?;
    let resolved = link
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(&target);
    // Lexical: `Path` equality compares components, so `..` never matches the
    // store dir, and a target ending in `..` has no file name. Only the bare
    // name is returned: a target ending in `/` or `/.` compares equal
    // component-wise, but an lstat of the raw path would follow a symlink at
    // the entry.
    match (resolved.file_name(), resolved.parent()) {
        (Some(name), Some(parent)) if parent == store_dir => Ok(Some(name.to_os_string())),
        _ => Err(ArtifactError::CurrentNotStoreLink {
            path: link.to_path_buf(),
            problem: CurrentLinkProblem::OutsideStore { target },
        }),
    }
}

/// Refuse a `current` that a link swap could not replace: anything at `link`
/// other than a symlink.
///
/// fuz moves `current` by renaming a fresh symlink over it, which fails
/// `EISDIR` on a directory — after any download or copy has been spent — and
/// would silently replace a file fuz did not write. Neither is removed here:
/// fuz did not write it. Absent or a symlink (wherever it points) is fine.
///
/// # Errors
///
/// [`ArtifactError::CurrentNotStoreLink`] with
/// [`CurrentLinkProblem::NotASymlink`]; [`ArtifactError::Io`] if `link` cannot
/// be inspected.
pub fn require_current_replaceable(link: &Path) -> Result<(), ArtifactError> {
    match link.symlink_metadata() {
        Ok(meta) if meta.file_type().is_symlink() => Ok(()),
        Ok(_) => Err(ArtifactError::CurrentNotStoreLink {
            path: link.to_path_buf(),
            problem: CurrentLinkProblem::NotASymlink,
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(ArtifactError::Io(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fuz_sys::fs::NonDirKind;
    use std::os::unix::fs::symlink;

    #[test]
    fn reclaim_unlinks_a_non_directory_entry_never_its_target() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        std::fs::create_dir(&target).unwrap();
        std::fs::write(target.join("keep"), b"x").unwrap();

        let live = dir.path().join("live");
        symlink(&target, &live).unwrap();
        assert_eq!(
            reclaim_store_entry(dir.path(), "live").unwrap(),
            StoreSlot::Vacant
        );
        assert!(live.symlink_metadata().is_err(), "the link is unlinked");
        assert_eq!(std::fs::read(target.join("keep")).unwrap(), b"x");

        let dangling = dir.path().join("dangling");
        symlink(dir.path().join("nowhere"), &dangling).unwrap();
        assert_eq!(
            reclaim_store_entry(dir.path(), "dangling").unwrap(),
            StoreSlot::Vacant
        );
        assert!(dangling.symlink_metadata().is_err());

        let file = dir.path().join("file");
        std::fs::write(&file, b"not a dir").unwrap();
        assert_eq!(
            reclaim_store_entry(dir.path(), "file").unwrap(),
            StoreSlot::Vacant
        );
        assert!(!file.exists());

        assert_eq!(
            reclaim_store_entry(dir.path(), "target").unwrap(),
            StoreSlot::RealDir
        );
        assert!(target.join("keep").is_file(), "a real dir is left alone");
        assert_eq!(
            reclaim_store_entry(dir.path(), "absent").unwrap(),
            StoreSlot::Vacant
        );
    }

    #[test]
    fn current_link_target_accepts_only_a_child_of_the_store() {
        let home = tempfile::tempdir().unwrap();
        let store = home.path().join("artifacts");
        std::fs::create_dir(&store).unwrap();
        let link = home.path().join("current");
        let target_of = |target: &Path| {
            let _ = std::fs::remove_file(&link);
            symlink(target, &link).unwrap();
            current_link_target(&link, &store)
        };

        // What fuz writes, and its absolute spelling.
        assert_eq!(
            target_of(Path::new("artifacts/v1-a")).unwrap(),
            Some(OsString::from("v1-a"))
        );
        assert_eq!(
            target_of(&store.join("v1-a")).unwrap(),
            Some(OsString::from("v1-a"))
        );
        // A trailing `/` or `/.` names the same entry, and what comes back is the
        // bare name — never the suffixed path, whose lstat would follow a
        // symlink at the entry.
        let outside = home.path().join("outside");
        std::fs::create_dir(&outside).unwrap();
        symlink(&outside, store.join("v1-a")).unwrap();
        for suffixed in ["artifacts/v1-a/", "artifacts/v1-a/."] {
            let name = target_of(Path::new(suffixed)).unwrap().unwrap();
            assert_eq!(name, OsString::from("v1-a"), "{suffixed}");
            assert!(
                matches!(
                    inspect_store_entry(&store, &name),
                    Err(ArtifactError::StoreEntryNotDir { .. })
                ),
                "{suffixed}: the symlink at the entry is refused, not followed"
            );
        }
        std::fs::remove_file(store.join("v1-a")).unwrap();

        // Anything else is outside the store.
        for outside in [
            Path::new("elsewhere/v1-a"),
            Path::new("artifacts/v1-a/deeper"),
            Path::new("artifacts/../v1-a"),
            Path::new("artifacts/.."),
            Path::new("/tmp/v1-a"),
            Path::new("artifacts"),
        ] {
            let err = target_of(outside).unwrap_err();
            assert!(
                matches!(
                    &err,
                    ArtifactError::CurrentNotStoreLink {
                        problem: CurrentLinkProblem::OutsideStore { target },
                        ..
                    } if target == outside
                ),
                "{outside:?}: got {err:?}"
            );
        }

        // No entry: nothing current. A directory: not a link fuz wrote.
        std::fs::remove_file(&link).unwrap();
        assert_eq!(current_link_target(&link, &store).unwrap(), None);
        std::fs::create_dir(&link).unwrap();
        assert!(matches!(
            current_link_target(&link, &store).unwrap_err(),
            ArtifactError::CurrentNotStoreLink {
                problem: CurrentLinkProblem::NotASymlink,
                ..
            }
        ));
    }

    #[test]
    fn require_current_replaceable_refuses_only_a_non_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let link = dir.path().join("current");
        require_current_replaceable(&link).expect("absent is replaceable");
        symlink(dir.path().join("anywhere"), &link).unwrap();
        require_current_replaceable(&link).expect("any symlink is replaceable");
        std::fs::remove_file(&link).unwrap();
        std::fs::create_dir(&link).unwrap();
        assert!(matches!(
            require_current_replaceable(&link).unwrap_err(),
            ArtifactError::CurrentNotStoreLink {
                problem: CurrentLinkProblem::NotASymlink,
                ..
            }
        ));
        assert!(link.is_dir(), "the directory is left in place");
    }

    /// A slot name that is not one plain component — `..`, a `../victim`
    /// traversal, a trailing `/` or `/.` that the kernel would resolve through a
    /// symlink at the entry — is refused before any filesystem access, by both
    /// policies, so nothing outside the store is unlinked or classified and the
    /// link at the entry and its target are left alone.
    #[test]
    fn a_name_that_is_not_one_component_is_refused() {
        let home = tempfile::tempdir().unwrap();
        let store = home.path().join("store");
        std::fs::create_dir(&store).unwrap();
        let victim = home.path().join("victim");
        std::fs::write(&victim, b"keep").unwrap();
        let target = home.path().join("target");
        std::fs::create_dir(&target).unwrap();
        symlink(&target, store.join("link")).unwrap();

        for name in ["..", "../victim", ".", "", "link/", "link/.", "a/b"] {
            for result in [
                reclaim_store_entry(&store, name),
                inspect_store_entry(&store, name),
            ] {
                assert!(
                    matches!(&result, Err(ArtifactError::InvalidStoreName { name: n }) if n == name),
                    "{name:?}: got {result:?}"
                );
            }
            assert!(
                matches!(
                    store_entry_path(&store, name),
                    Err(ArtifactError::InvalidStoreName { .. })
                ),
                "{name:?}"
            );
        }
        assert_eq!(std::fs::read(&victim).unwrap(), b"keep", "victim survives");
        assert!(
            store
                .join("link")
                .symlink_metadata()
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert!(target.is_dir());
    }

    /// An entry that vanished between the probe and the unlink leaves the slot
    /// vacant, not an I/O error.
    #[test]
    fn unlink_entry_treats_an_already_gone_entry_as_unlinked() {
        let dir = tempfile::tempdir().unwrap();
        unlink_entry(&dir.path().join("gone")).expect("ENOENT is success");

        // Any other failure still surfaces: a directory is not unlinked.
        let real = dir.path().join("real");
        std::fs::create_dir(&real).unwrap();
        unlink_entry(&real).expect_err("a directory is not removed");
        assert!(real.is_dir());
    }

    #[test]
    fn inspect_refuses_a_non_directory_entry_and_leaves_it() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        std::fs::create_dir(&target).unwrap();
        let live = dir.path().join("live");
        symlink(&target, &live).unwrap();

        let err = inspect_store_entry(dir.path(), "live").unwrap_err();
        assert!(
            matches!(
                &err,
                ArtifactError::StoreEntryNotDir { path, kind: NonDirKind::Symlink } if *path == live
            ),
            "got {err:?}"
        );
        assert!(err.hint().is_some(), "the refusal carries a hint");
        assert!(live.symlink_metadata().unwrap().file_type().is_symlink());

        assert_eq!(
            inspect_store_entry(dir.path(), "target").unwrap(),
            StoreSlot::RealDir
        );
        assert_eq!(
            inspect_store_entry(dir.path(), "absent").unwrap(),
            StoreSlot::Vacant
        );
    }
}
