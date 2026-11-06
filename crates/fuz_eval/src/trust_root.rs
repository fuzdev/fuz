//! The trust root: the project directory a config is evaluated in, settled
//! from the disk before `fgro` runs (crate docs § The trust root).
//!
//! Reads the filesystem and nothing else: the config's directory and file
//! modes, then the walk up through the directories the operator holds to the
//! nearest `package.json` that is more than a type marker.

use std::ffi::OsStr;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::run_as::Caller;
use crate::{TrustRootProblem, WalkStop};

/// The largest `package.json` the trust root's walk reads, as gro's resolver
/// bounds it.
const MAX_PACKAGE_JSON_SIZE: u64 = 16 * 1024 * 1024;

/// What set a config's trust root (crate docs § The trust root).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustRootBasis {
    /// The nearest `package.json` in the walk that holds more than a type marker;
    /// the root is its directory.
    PackageJson(PathBuf),
    /// The walk stopped below `dir`, for the reason `stop`, before it found such
    /// a `package.json`; the root is the config's own directory, and the eval is
    /// refused.
    StoppedBelow {
        /// The first directory above the config's that the walk refused.
        dir: PathBuf,
        /// Why the walk refused it.
        stop: WalkStop,
    },
    /// The walk reached the filesystem root with no such `package.json`; the root
    /// is the config's own directory, and the eval is refused.
    ConfigDir,
}

/// A config's trust root and what set it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustRoot {
    /// The root directory, canonical.
    pub dir: PathBuf,
    /// What set it.
    pub basis: TrustRootBasis,
}

/// Why the trust root could not be settled.
#[derive(Debug)]
pub enum RootsError {
    /// The config's directory or the config file could not be read.
    Io(std::io::Error),
    /// The trust root can't be settled: `offending` is the directory or the
    /// `package.json` at fault, and `reason` says what is wrong with it.
    Refused {
        problem: TrustRootProblem,
        offending: PathBuf,
        reason: String,
    },
}

/// The trust root of the config at `config_path`, which must be canonical, for
/// the process `caller` describes.
///
/// The config's own directory is refused when every user can write it, and then
/// the config file when every user can write that; the directory is otherwise
/// exempt from the ownership walk, which bounds only the directories above it.
/// The file's mode is read through `config_path`, which being canonical names the
/// file itself, never a link to it: a link's own mode on Linux is always `0777`,
/// and the bytes that run are the target's.
///
/// # Errors
/// [`RootsError::Io`] when the config's directory or the config file can't be
/// read; [`RootsError::Refused`] for a
/// config directory or config file with the `o+w` bit, or a `package.json` in the
/// walk that can't be read or isn't valid.
pub fn find_trust_root(config_path: &Path, caller: &Caller) -> Result<TrustRoot, RootsError> {
    let owners = Owners {
        euid: caller.euid,
        sudo_uid: caller.sudo_uid(),
    };
    let config_dir = config_path.parent().unwrap_or(config_path);
    for (path, problem) in [
        (config_dir, TrustRootProblem::WorldWritableConfigDir),
        (config_path, TrustRootProblem::WorldWritableConfigFile),
    ] {
        let mode = std::fs::metadata(path)
            .map_err(|source| {
                RootsError::Io(std::io::Error::new(
                    source.kind(),
                    format!("read {}: {source}", path.display()),
                ))
            })?
            .mode();
        if mode & 0o002 != 0 {
            return Err(RootsError::Refused {
                problem,
                offending: path.to_path_buf(),
                reason: format!("mode {:04o}", mode & 0o7777),
            });
        }
    }
    let (dir, basis) = trust_root(config_dir, |dir| walk_stop(dir, owners))?;
    Ok(TrustRoot { dir, basis })
}

/// The trust root for a config in `config_dir`, and the `package.json` that set
/// it: walking up from `config_dir`, the first directory outside every
/// `node_modules` segment whose `package.json` is more than a type marker (one
/// whose keys are all `"type"` or `"sideEffects"`, the empty object included) —
/// gro's resolver ends its package search at the same file. With none, the root
/// is `config_dir` itself. The walk stops before the first directory above
/// `config_dir` that `stop` refuses — one another user owns or every user can
/// write, `stop` saying which — since what such a directory holds is not the
/// operator's to vouch for, and nothing in it is read; the basis then names it
/// ([`TrustRootBasis::StoppedBelow`]).
///
/// Every `package.json` the walk passes is read, and one that can't be read or
/// isn't valid refuses the walk rather than being skipped: whether it is a marker
/// decides the root.
fn trust_root(
    config_dir: &Path,
    stop: impl Fn(&Path) -> Option<WalkStop>,
) -> Result<(PathBuf, TrustRootBasis), RootsError> {
    for dir in config_dir.ancestors() {
        if dir != config_dir
            && let Some(stop) = stop(dir)
        {
            return Ok((
                config_dir.to_path_buf(),
                TrustRootBasis::StoppedBelow {
                    dir: dir.to_path_buf(),
                    stop,
                },
            ));
        }
        if in_node_modules(dir) {
            continue;
        }
        let package_json = dir.join("package.json");
        match ends_walk(&package_json) {
            Ok(false) => {}
            Ok(true) => {
                return Ok((dir.to_path_buf(), TrustRootBasis::PackageJson(package_json)));
            }
            Err(reason) => {
                return Err(RootsError::Refused {
                    problem: TrustRootProblem::InvalidPackageJson,
                    offending: package_json,
                    reason,
                });
            }
        }
    }
    Ok((config_dir.to_path_buf(), TrustRootBasis::ConfigDir))
}

/// Whether `path` has a `node_modules` component.
fn in_node_modules(path: &Path) -> bool {
    path.components()
        .any(|component| component.as_os_str() == "node_modules")
}

/// Whether the `package.json` at `path` ends the trust root's walk: `false` when
/// there is none (or a directory of that name) or it is a type marker, `true`
/// for any other valid one. `Err` says why it can't be used: a link to nothing,
/// any other stat failure (a path through a non-directory, a loop of links), a
/// FIFO, socket or device, a read failure, over [`MAX_PACKAGE_JSON_SIZE`], not a
/// JSON object, or a `"name"` or `"type"` that isn't a string (Node's
/// `ERR_INVALID_PACKAGE_CONFIG`). A leading byte order mark is skipped, as Node
/// skips it.
///
/// A file that isn't regular is refused from its stat, never opened: opening a
/// device can act on it. The open is non-blocking and checks the file again, so
/// one swapped in after the stat is refused without waiting for a FIFO's writer.
///
/// gro's resolver reads a dangling link or a path through a non-directory as no
/// `package.json`, and goes on up; this refuses both instead, since the answer
/// decides what the eval trusts.
fn ends_walk(path: &Path) -> Result<bool, String> {
    let not_regular = || "it is not a regular file (a FIFO, a socket, or a device)".to_owned();
    match std::fs::metadata(path) {
        Ok(meta) if meta.is_dir() => return Ok(false),
        Ok(meta) if !meta.is_file() => return Err(not_regular()),
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return if std::fs::symlink_metadata(path).is_ok() {
                Err("it is a link to nothing".to_owned())
            } else {
                Ok(false)
            };
        }
        Err(error) => return Err(format!("it can't be read: {error}")),
    }
    let (file, meta) = fuz_sys::secure_file::open_regular_nonblocking(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::InvalidInput {
            not_regular()
        } else {
            format!("it can't be read: {error}")
        }
    })?;
    let too_large = || {
        format!(
            "it is larger than {} MiB, the most a package.json may be",
            MAX_PACKAGE_JSON_SIZE / (1024 * 1024)
        )
    };
    if meta.len() > MAX_PACKAGE_JSON_SIZE {
        return Err(too_large());
    }
    let mut bytes = Vec::new();
    file.take(MAX_PACKAGE_JSON_SIZE + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("it can't be read: {error}"))?;
    if bytes.len() as u64 > MAX_PACKAGE_JSON_SIZE {
        return Err(too_large());
    }
    package_json_ends_walk(&bytes)
}

/// [`ends_walk`] over the bytes of a `package.json`.
fn package_json_ends_walk(bytes: &[u8]) -> Result<bool, String> {
    let json = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes);
    let fields = match serde_json::from_slice(json) {
        Ok(Value::Object(fields)) => fields,
        Ok(_) => return Err("it is not a JSON object".to_owned()),
        Err(error) => return Err(format!("it is not JSON: {error}")),
    };
    for key in ["name", "type"] {
        if fields.get(key).is_some_and(|value| !value.is_string()) {
            return Err(format!("its \"{key}\" is not a string"));
        }
    }
    Ok(!fields
        .keys()
        .all(|key| matches!(key.as_str(), "type" | "sideEffects")))
}

/// The owners whose directories the trust root's walk passes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Owners {
    /// The process's effective uid.
    euid: u32,
    /// Under `sudo`, the invoking user's uid ([`sudo_uid_of`]).
    sudo_uid: Option<u32>,
}

impl Owners {
    /// Whether a directory owned by `uid` with permission bits `mode` passes:
    /// one of the owners holds it and no other user can write it.
    const fn pass(self, uid: u32, mode: u32) -> bool {
        mode & 0o002 == 0
            && (uid == self.euid || matches!(self.sudo_uid, Some(sudo_uid) if sudo_uid == uid))
    }
}

/// Why the walk refuses `dir`, or `None` when one of `owners` holds it and no
/// other user can write it. A directory whose owner can't be read is refused as
/// another user's.
fn walk_stop(dir: &Path, owners: Owners) -> Option<WalkStop> {
    match std::fs::metadata(dir) {
        Ok(meta) if owners.pass(meta.uid(), meta.mode()) => None,
        Ok(meta) if meta.mode() & 0o002 != 0 => Some(WalkStop::WorldWritable),
        _ => Some(WalkStop::OtherOwner),
    }
}

/// The invoking user's uid when the process runs as root under `sudo`: the value
/// of `SUDO_UID`, which `sudo` sets, when the effective uid is `0` and the value
/// is a plain decimal uid. `None` for any other euid, an unset variable, or one
/// that doesn't parse.
pub fn sudo_uid_of(euid: u32, sudo_uid: Option<&OsStr>) -> Option<u32> {
    if euid != 0 {
        return None;
    }
    let text = sudo_uid?.to_str()?;
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

/// The effective uid, the second field of `/proc/self/status`'s `Uid:` line.
pub fn effective_uid() -> std::io::Result<u32> {
    let status = std::fs::read_to_string("/proc/self/status")?;
    effective_uid_of(&status)
        .ok_or_else(|| std::io::Error::other("no effective uid in /proc/self/status"))
}

/// The effective uid in the text of a `/proc/<pid>/status`: the second of the
/// `Uid:` line's real, effective, saved and filesystem uids.
fn effective_uid_of(status: &str) -> Option<u32> {
    status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .and_then(|ids| ids.split_whitespace().nth(1))
        .and_then(|euid| euid.parse().ok())
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    /// A scratch directory, canonical, removed on drop.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir()
                .join(format!("fuz_eval_trust_root_{tag}_{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
            Self(std::fs::canonicalize(&dir).unwrap())
        }

        /// Create `rel` (and its parents) as a directory at mode `0755`.
        fn dir(&self, rel: &str) -> PathBuf {
            let dir = self.0.join(rel);
            std::fs::create_dir_all(&dir).unwrap();
            let mut at = dir.as_path();
            while at != self.0 {
                std::fs::set_permissions(at, std::fs::Permissions::from_mode(0o755)).unwrap();
                at = at.parent().unwrap();
            }
            dir
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// The effective uid is the `Uid:` line's second field, not the real one.
    #[test]
    fn the_effective_uid_is_the_second_uid_field() {
        assert_eq!(
            effective_uid_of("Name:\tzap\nUid:\t1000\t0\t0\t0\nGid:\t1000\t1000\t1000\t1000\n"),
            Some(0)
        );
        assert_eq!(effective_uid_of("Name:\tzap\n"), None);
    }

    /// `SUDO_UID` counts only under euid 0, and only as a plain decimal uid.
    #[test]
    fn the_sudo_uid_counts_only_for_root_and_only_when_it_parses() {
        let uid = |text: &'static str| Some(OsStr::new(text));
        assert_eq!(sudo_uid_of(0, uid("1000")), Some(1000));
        assert_eq!(sudo_uid_of(0, uid("0")), Some(0));
        assert_eq!(sudo_uid_of(1000, uid("1001")), None, "not root");
        assert_eq!(sudo_uid_of(0, None), None, "unset");
        for bad in ["", "+1000", "-1", " 1000", "1000 ", "10x", "4294967296"] {
            assert_eq!(sudo_uid_of(0, uid(bad)), None, "{bad:?}");
        }
        let invalid = OsString::from_vec(vec![b'1', 0xFF]);
        assert_eq!(sudo_uid_of(0, Some(&invalid)), None);
    }

    /// A directory passes when the euid or, under `sudo`, the invoking user owns it
    /// and no other user can write it.
    #[test]
    fn a_directory_passes_for_its_owners_when_closed() {
        let root = Owners {
            euid: 0,
            sudo_uid: None,
        };
        let sudo = Owners {
            euid: 0,
            sudo_uid: Some(1000),
        };
        let user = Owners {
            euid: 1000,
            sudo_uid: None,
        };
        assert!(root.pass(0, 0o755));
        assert!(
            !root.pass(1000, 0o755),
            "root alone stops at a user's directory"
        );
        assert!(
            sudo.pass(1000, 0o775),
            "under sudo the invoking user's passes"
        );
        assert!(sudo.pass(0, 0o755), "and root's still does");
        assert!(!sudo.pass(1001, 0o755), "another user's does not");
        assert!(
            !sudo.pass(1000, 0o757),
            "nor the user's when others can write it"
        );
        assert!(!sudo.pass(1000, 0o1777));
        assert!(user.pass(1000, 0o700));
        assert!(!user.pass(0, 0o755));
        assert!(!user.pass(1000, 0o777));
    }

    /// A `package.json` ends the walk unless it is a type marker; an invalid one
    /// is an error, not a skip.
    #[test]
    fn a_package_json_ends_the_walk_unless_it_is_a_type_marker() {
        let ends = |text: &str| package_json_ends_walk(text.as_bytes());
        for marker in [
            "{}",
            r#"{"type":"module"}"#,
            r#"{"sideEffects":false,"type":"commonjs"}"#,
        ] {
            assert_eq!(ends(marker), Ok(false), "{marker}");
        }
        for bound in [
            r#"{"name":"p"}"#,
            r#"{"dependencies":{}}"#,
            r#"{"type":"module","private":true}"#,
            r#"{"workspaces":["packages/*"]}"#,
        ] {
            assert_eq!(ends(bound), Ok(true), "{bound}");
        }
        assert_eq!(
            ends("\u{FEFF}{\"name\":\"p\"}"),
            Ok(true),
            "a BOM is skipped"
        );
        for invalid in [
            r#"{"name":5}"#,
            r#"{"type":null}"#,
            r#"{"type":{"x":1}}"#,
            "[]",
            "\"p\"",
            "{",
            "",
        ] {
            assert!(ends(invalid).is_err(), "{invalid}");
        }
    }

    /// The root of a walk that refuses nothing, else the error's offending path.
    fn root_of(config_dir: &Path, trusted: impl Fn(&Path) -> bool) -> Result<PathBuf, PathBuf> {
        match trust_root(config_dir, |dir| {
            (!trusted(dir)).then_some(WalkStop::OtherOwner)
        }) {
            Ok((root, _)) => Ok(root),
            Err(RootsError::Refused { offending, .. }) => Err(offending),
            Err(RootsError::Io(error)) => panic!("{error}"),
        }
    }

    /// The root is the nearest directory holding a `package.json` that isn't a
    /// type marker, else the config's own; the walk stops before a directory the
    /// predicate refuses.
    #[test]
    fn the_trust_root_is_the_nearest_package_json_within_the_trusted_walk() {
        let scratch = Scratch::new("root");
        let config_dir = scratch.dir("top/mid/project");
        let top = scratch.0.join("top");
        std::fs::write(top.join("package.json"), r#"{"name":"top"}"#).unwrap();
        assert_eq!(
            trust_root(&config_dir, |_| None).unwrap(),
            (
                top.clone(),
                TrustRootBasis::PackageJson(top.join("package.json"))
            )
        );
        // A refused `mid` stops the walk before `top`, and is named as where it
        // stopped.
        let mid = scratch.0.join("top/mid");
        assert_eq!(
            trust_root(&config_dir, |dir| (dir == mid)
                .then_some(WalkStop::WorldWritable))
            .unwrap(),
            (
                config_dir.clone(),
                TrustRootBasis::StoppedBelow {
                    dir: mid.clone(),
                    stop: WalkStop::WorldWritable
                }
            )
        );
        // A type marker on the way is walked past, the empty object included.
        std::fs::write(mid.join("package.json"), r#"{"type":"module"}"#).unwrap();
        std::fs::write(config_dir.join("package.json"), "{}").unwrap();
        assert_eq!(root_of(&config_dir, |_| true), Ok(top));
        // The config's own directory is never refused, and its `package.json` wins.
        std::fs::write(config_dir.join("package.json"), r#"{"private":true}"#).unwrap();
        assert_eq!(root_of(&config_dir, |_| false), Ok(config_dir.clone()));
    }

    /// A directory inside a `node_modules` segment is walked past, its
    /// `package.json` unread: a package's own is not a project.
    #[test]
    fn the_walk_passes_the_package_json_inside_node_modules() {
        let scratch = Scratch::new("in_node_modules");
        let config_dir = scratch.dir("top/node_modules/pkg/deploy");
        let top = scratch.0.join("top");
        std::fs::write(top.join("package.json"), r#"{"name":"top"}"#).unwrap();
        std::fs::write(top.join("node_modules/pkg/package.json"), r#"{"name":5}"#).unwrap();
        std::fs::write(config_dir.join("package.json"), r#"{"name":"pkg"}"#).unwrap();
        assert_eq!(root_of(&config_dir, |_| true), Ok(top));
    }

    /// A `package.json` the walk can't read or that isn't valid refuses it, named;
    /// it is never skipped. A directory of that name is no `package.json`.
    #[test]
    fn an_invalid_package_json_in_the_walk_refuses_it() {
        let scratch = Scratch::new("invalid");
        let config_dir = scratch.dir("top/project");
        let top = scratch.0.join("top");
        std::fs::write(top.join("package.json"), r#"{"name":"top"}"#).unwrap();
        let bad = config_dir.join("package.json");
        for text in [r#"{"type":1}"#, "not json"] {
            std::fs::write(&bad, text).unwrap();
            assert_eq!(root_of(&config_dir, |_| true), Err(bad.clone()), "{text}");
        }
        std::fs::remove_file(&bad).unwrap();
        std::os::unix::fs::symlink(scratch.0.join("absent"), &bad).unwrap();
        assert_eq!(
            root_of(&config_dir, |_| true),
            Err(bad.clone()),
            "a dangling link"
        );
        std::fs::remove_file(&bad).unwrap();
        // A path through a file: the stat fails with `ENOTDIR`, which gro reads as
        // no `package.json`; refused here like the dangling link.
        std::fs::write(scratch.0.join("plain"), "").unwrap();
        std::os::unix::fs::symlink(scratch.0.join("plain/package.json"), &bad).unwrap();
        assert_eq!(
            root_of(&config_dir, |_| true),
            Err(bad.clone()),
            "a path through a file"
        );
        std::fs::remove_file(&bad).unwrap();
        std::fs::create_dir(&bad).unwrap();
        assert_eq!(root_of(&config_dir, |_| true), Ok(top), "a directory");
        std::fs::remove_dir(&bad).unwrap();
        std::fs::write(&bad, r#"{"name":"p"}"#).unwrap();
        std::fs::set_permissions(&bad, std::fs::Permissions::from_mode(0o000)).unwrap();
        // Root reads a mode-000 file, so only an unprivileged run shows the refusal.
        if effective_uid().unwrap() != 0 {
            assert_eq!(
                root_of(&config_dir, |_| true),
                Err(bad.clone()),
                "unreadable"
            );
        }
        std::fs::set_permissions(&bad, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::remove_file(&bad).unwrap();
        // A FIFO is refused without being opened, which would wait for a writer.
        let made = std::process::Command::new("mkfifo")
            .arg(&bad)
            .status()
            .unwrap();
        assert!(made.success());
        assert_eq!(root_of(&config_dir, |_| true), Err(bad), "a FIFO");
    }

    /// The config's own directory is refused when every user can write it, and
    /// is otherwise exempt from the ownership walk.
    #[test]
    fn a_world_writable_config_directory_is_refused() {
        let scratch = Scratch::new("config_dir");
        let config_dir = scratch.dir("project");
        let config = config_dir.join("zap.ts");
        std::fs::write(&config, "").unwrap();
        // Pinned: under `umask 000` the file would be refused first.
        std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            find_trust_root(&config, &Caller::of_process().unwrap())
                .unwrap()
                .dir,
            config_dir
        );
        for mode in [0o777, 0o1777, 0o757] {
            std::fs::set_permissions(&config_dir, std::fs::Permissions::from_mode(mode)).unwrap();
            match find_trust_root(&config, &Caller::of_process().unwrap()) {
                Err(RootsError::Refused {
                    problem: TrustRootProblem::WorldWritableConfigDir,
                    offending,
                    reason,
                }) => {
                    assert_eq!(offending, config_dir);
                    assert_eq!(reason, format!("mode {mode:04o}"));
                }
                other => panic!("{mode:o}: expected the directory refused, got {other:?}"),
            }
        }
        std::fs::set_permissions(&config_dir, std::fs::Permissions::from_mode(0o775)).unwrap();
        assert!(
            find_trust_root(&config, &Caller::of_process().unwrap()).is_ok(),
            "group write is not refused"
        );
    }

    /// A world-writable directory (a `1777` one included) stops the walk; one of
    /// the process's own at `0755` does not. A directory another user owns stops it
    /// too, which needs a second uid to show and is not tested here.
    #[test]
    fn a_world_writable_directory_stops_the_walk() {
        let scratch = Scratch::new("sticky");
        let config_dir = scratch.dir("top/shared/project");
        let top = scratch.0.join("top");
        let shared = scratch.0.join("top/shared");
        std::fs::write(top.join("package.json"), r#"{"name":"top"}"#).unwrap();
        let owners = Owners {
            euid: effective_uid().unwrap(),
            sudo_uid: None,
        };
        let walk = || root_of(&config_dir, |dir| walk_stop(dir, owners).is_none()).unwrap();
        assert_eq!(walk(), top);
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o1777)).unwrap();
        assert_eq!(walk(), config_dir);
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o757)).unwrap();
        assert_eq!(
            walk(),
            config_dir,
            "o+w without the sticky bit stops it too"
        );
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o775)).unwrap();
        assert_eq!(walk(), top, "group write does not");
    }

    /// The config file is refused when every user can write it, whoever owns it;
    /// its mode is the canonical file's. A world-writable directory is reported
    /// ahead of it.
    #[test]
    fn a_world_writable_config_file_is_refused() {
        let scratch = Scratch::new("config_file");
        let config_dir = scratch.dir("project");
        let config = config_dir.join("zap.ts");
        std::fs::write(&config, "").unwrap();
        for mode in [0o666, 0o646, 0o1777, 0o602] {
            std::fs::set_permissions(&config, std::fs::Permissions::from_mode(mode)).unwrap();
            match find_trust_root(&config, &Caller::of_process().unwrap()) {
                Err(RootsError::Refused {
                    problem: TrustRootProblem::WorldWritableConfigFile,
                    offending,
                    reason,
                }) => {
                    assert_eq!(offending, config);
                    assert_eq!(reason, format!("mode {mode:04o}"));
                }
                other => panic!("{mode:o}: expected the file refused, got {other:?}"),
            }
        }
        std::fs::set_permissions(&config_dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(
            matches!(
                find_trust_root(&config, &Caller::of_process().unwrap()),
                Err(RootsError::Refused {
                    problem: TrustRootProblem::WorldWritableConfigDir,
                    ..
                })
            ),
            "the directory is reported first"
        );
        std::fs::set_permissions(&config_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        for mode in [0o664, 0o644, 0o600] {
            std::fs::set_permissions(&config, std::fs::Permissions::from_mode(mode)).unwrap();
            assert!(
                find_trust_root(&config, &Caller::of_process().unwrap()).is_ok(),
                "{mode:o} is not refused"
            );
        }
    }

    /// The walk stops before a refused directory: what another user keeps in its
    /// `package.json` neither sets the root nor refuses the walk.
    #[test]
    fn the_walk_reads_nothing_above_where_it_stops() {
        let scratch = Scratch::new("stop");
        let config_dir = scratch.dir("top/project");
        let top = scratch.0.join("top");
        std::fs::write(top.join("package.json"), r#"{"name":5}"#).unwrap();
        assert_eq!(
            root_of(&config_dir, |dir| dir != top),
            Ok(config_dir.clone())
        );
        assert_eq!(
            root_of(&config_dir, |_| true),
            Err(top.join("package.json")),
            "read when the walk reaches it"
        );
    }

    /// A `package.json` over the size bound is refused as too large, not read whole.
    #[test]
    fn an_oversized_package_json_is_refused_as_too_large() {
        let scratch = Scratch::new("oversized");
        let config_dir = scratch.dir("project");
        let file = std::fs::File::create(config_dir.join("package.json")).unwrap();
        file.set_len(MAX_PACKAGE_JSON_SIZE + 1).unwrap();
        drop(file);
        match trust_root(&config_dir, |_| None) {
            Err(RootsError::Refused { reason, .. }) => {
                assert!(reason.contains("larger than 16 MiB"), "{reason}");
            }
            other => panic!("expected the package.json refused, got {other:?}"),
        }
    }

    /// A FIFO at `package.json` is refused from its stat and never opened: a
    /// writer blocked in `open` until a reader arrives is still blocked after the
    /// walk, and the non-blocking open the walk would make is what releases it.
    #[test]
    fn a_fifo_package_json_is_refused_without_being_opened() {
        let scratch = Scratch::new("fifo");
        let config_dir = scratch.dir("project");
        let fifo = config_dir.join("package.json");
        let made = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap();
        assert!(made.success());
        let opened = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let writer = {
            let fifo = fifo.clone();
            let opened = std::sync::Arc::clone(&opened);
            std::thread::spawn(move || {
                // Blocks until some reader opens the FIFO.
                let file = std::fs::OpenOptions::new().write(true).open(&fifo);
                opened.store(true, std::sync::atomic::Ordering::SeqCst);
                drop(file);
            })
        };
        // Give the writer time to block in `open`.
        std::thread::sleep(std::time::Duration::from_millis(100));
        match trust_root(&config_dir, |_| None) {
            Err(RootsError::Refused {
                problem: TrustRootProblem::InvalidPackageJson,
                offending,
                reason,
            }) => {
                assert_eq!(offending, fifo);
                assert!(reason.contains("not a regular file"), "{reason}");
            }
            other => panic!("expected the FIFO refused, got {other:?}"),
        }
        std::thread::sleep(std::time::Duration::from_millis(300));
        let opened_by_walk = opened.load(std::sync::atomic::Ordering::SeqCst);
        // Release the writer with the open the walk would make: it refuses the
        // FIFO, but opens it first. Repeated until the writer is released: a writer
        // not yet blocked in `open` when one is made would otherwise wait forever.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !opened.load(std::sync::atomic::Ordering::SeqCst)
            && std::time::Instant::now() < deadline
        {
            let refused = fuz_sys::secure_file::open_regular_nonblocking(&fifo);
            assert!(refused.is_err());
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(
            opened.load(std::sync::atomic::Ordering::SeqCst),
            "that open releases the writer"
        );
        writer.join().unwrap();
        assert!(!opened_by_walk, "the walk opened the FIFO");
    }

    /// A socket at `package.json` is refused from its stat as not a regular file:
    /// opening one fails, which would read as a file that can't be read.
    #[test]
    fn a_socket_package_json_is_refused_as_not_regular() {
        let scratch = Scratch::new("socket");
        let config_dir = scratch.dir("project");
        let socket = config_dir.join("package.json");
        let _listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        match trust_root(&config_dir, |_| None) {
            Err(RootsError::Refused {
                problem: TrustRootProblem::InvalidPackageJson,
                offending,
                reason,
            }) => {
                assert_eq!(offending, socket);
                assert!(reason.contains("not a regular file"), "{reason}");
            }
            other => panic!("expected the socket refused, got {other:?}"),
        }
    }

    /// The walk says why it refuses a directory: every user can write it, whoever
    /// owns it, else another user holds it or its owner can't be read.
    #[test]
    fn walk_stop_names_why_a_directory_is_refused() {
        let scratch = Scratch::new("walk_stop");
        let dir = scratch.dir("d");
        let me = Owners {
            euid: effective_uid().unwrap(),
            sudo_uid: None,
        };
        let other = Owners {
            euid: me.euid.wrapping_add(1),
            sudo_uid: None,
        };
        assert_eq!(walk_stop(&dir, me), None);
        assert_eq!(walk_stop(&dir, other), Some(WalkStop::OtherOwner));
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o757)).unwrap();
        assert_eq!(walk_stop(&dir, me), Some(WalkStop::WorldWritable));
        assert_eq!(walk_stop(&dir, other), Some(WalkStop::WorldWritable));
        assert_eq!(
            walk_stop(&scratch.0.join("missing"), me),
            Some(WalkStop::OtherOwner)
        );
    }
}
