//! Who `fgro` runs as: the caller's own uid, or, under euid 0, a user dropped
//! to (crate docs § Who it runs as).
//!
//! [`decide_run_as`] is the rule, a pure function of what the process is, its
//! `SUDO_UID` and `SUDO_GID`, the trust root's owner, and the target user's
//! passwd entry; [`first_unsearchable`] is the dropped user's search check on
//! the way to the trust root, a pure function over a stat; [`settle_run_as`]
//! gathers their inputs from the system.

use std::ffi::{OsStr, OsString};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use crate::trust_root::{effective_uid, sudo_uid_of};

/// What the process is, read once per eval: its effective uid, and the
/// `SUDO_UID` and `SUDO_GID` it was given. The trust root's walk and
/// [`decide_run_as`] both take it, so they see one reading of the environment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caller {
    /// The process's effective uid.
    pub euid: u32,
    /// `SUDO_UID` as given, if set.
    pub sudo_uid: Option<OsString>,
    /// `SUDO_GID` as given, if set.
    pub sudo_gid: Option<OsString>,
}

impl Caller {
    /// The running process: its effective uid from `/proc/self/status`, and its
    /// `SUDO_UID` and `SUDO_GID`.
    ///
    /// # Errors
    /// When `/proc/self/status` can't be read or holds no effective uid.
    pub fn of_process() -> std::io::Result<Self> {
        Ok(Self {
            euid: effective_uid()?,
            sudo_uid: std::env::var_os("SUDO_UID"),
            sudo_gid: std::env::var_os("SUDO_GID"),
        })
    }

    /// The invoking user's uid under `sudo`, as the trust root's walk counts it
    /// (`0` included, which names root, an owner the walk passes anyway).
    pub fn sudo_uid(&self) -> Option<u32> {
        sudo_uid_of(self.euid, self.sudo_uid.as_deref())
    }
}

/// The user and group a root eval drops to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DroppedTo {
    /// The uid.
    pub uid: u32,
    /// The gid.
    pub gid: u32,
}

/// Who `fgro` runs as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunAs {
    /// The process's own uid, which isn't root: no drop.
    Caller {
        /// The effective uid.
        uid: u32,
    },
    /// Root drops to a user and group, with no supplementary groups.
    Drop {
        /// The user and group.
        to: DroppedTo,
        /// Where they came from.
        basis: DropBasis,
    },
}

impl RunAs {
    /// The user and group dropped to, when root drops.
    pub const fn dropped_to(self) -> Option<DroppedTo> {
        match self {
            Self::Caller { .. } => None,
            Self::Drop { to, .. } => Some(to),
        }
    }
}

/// Where a dropped-to user and group came from. The user is always the trust
/// root's owner (crate docs § Who it runs as).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropBasis {
    /// Root under `sudo`, invoked by the project's owner: `SUDO_UID` and
    /// `SUDO_GID`, the group that user ran `sudo` with.
    Sudo,
    /// Root otherwise: the project's owner, with that user's primary group
    /// from the passwd database.
    ProjectOwner,
}

/// Why the eval can't run as anyone: refused before the pin and the spawn
/// (crate docs § Who it runs as).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunAsProblem {
    /// The process is root and root owns the project, so there is no user who
    /// could already edit the config to run it as. `sudo_uid` is the user
    /// `SUDO_UID` names, if it names one, who doesn't own the project.
    RootOwnedProject {
        /// The uid `SUDO_UID` names, when it names one other than root.
        sudo_uid: Option<u32>,
    },
    /// `SUDO_UID` names `uid`, the project's owner, but `SUDO_GID` is missing
    /// or isn't a decimal gid, so the group to drop to is unknown.
    SudoGidUnusable {
        /// The uid `SUDO_UID` names.
        uid: u32,
        /// `SUDO_GID` as given, lossily decoded; `None` when unset.
        sudo_gid: Option<String>,
    },
    /// The drop would keep group `0`, root's, from `basis`, and with it what
    /// root's group can read.
    RootGroup {
        /// The uid it would drop to.
        uid: u32,
        /// Where the group came from.
        basis: DropBasis,
    },
    /// The user it would run as has no passwd entry, as this binary's lookup
    /// reads the database, so neither its home nor its group is known.
    NoPasswdEntry {
        /// The uid it would run as.
        uid: u32,
    },
    /// The passwd lookup for the user it would run as failed.
    PasswdUnreadable {
        /// The uid it would run as.
        uid: u32,
    },
    /// The project is the home directory of the user it would run as, or holds
    /// it, so the eval's box would admit everything there.
    HomeProject {
        /// The uid it would run as.
        uid: u32,
        /// That user's home directory, canonical when it resolves.
        home: String,
    },
    /// The user root drops to can't search `dir` (no `x` for it by owner, group,
    /// or other bits), on the way to the project or the project itself, so
    /// `fgro` couldn't start there: the working directory is entered after the
    /// drop.
    NotSearchable {
        /// The uid dropped to.
        uid: u32,
        /// The gid dropped to.
        gid: u32,
        /// The directory it can't search.
        dir: String,
    },
}

/// What [`decide_run_as`] reads about the trust root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RootStat<'a> {
    /// The trust root, canonical.
    pub dir: &'a Path,
    /// Its owner's uid.
    pub owner: u32,
}

/// A user's passwd entry, as much of it as the decision reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswdEntry {
    /// The home directory, canonical when it resolves.
    pub home: PathBuf,
    /// The primary group.
    pub gid: u32,
}

/// A passwd lookup's outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PasswdLookup {
    /// The user's entry.
    Entry(PasswdEntry),
    /// No entry for the uid.
    NoEntry,
    /// The lookup failed.
    Failed,
}

/// Who `fgro` runs as, or why it can't run (crate docs § Who it runs as).
///
/// - euid not `0`: the caller's own uid, no drop.
/// - euid `0`, `SUDO_UID` a decimal uid other than `0` that owns the trust
///   root: that uid, with `SUDO_GID`, which must be a decimal gid.
/// - euid `0` otherwise: the trust root's owner, with its passwd primary
///   group; refused when root owns the trust root.
///
/// The user it runs as is looked up with `passwd`, and must have an entry. A
/// drop to group `0` is refused, and so is a trust root that is the user's home
/// or holds it.
///
/// # Errors
/// The [`RunAsProblem`] that refuses the eval.
pub fn decide_run_as(
    caller: &Caller,
    root: RootStat<'_>,
    passwd: impl FnOnce(u32) -> PasswdLookup,
) -> Result<RunAs, RunAsProblem> {
    let (uid, basis) = if caller.euid == 0 {
        let sudo_uid = caller.sudo_uid().filter(|&uid| uid != 0);
        match sudo_uid {
            Some(uid) if uid == root.owner => (uid, Some(DropBasis::Sudo)),
            _ if root.owner == 0 => return Err(RunAsProblem::RootOwnedProject { sudo_uid }),
            _ => (root.owner, Some(DropBasis::ProjectOwner)),
        }
    } else {
        (caller.euid, None)
    };
    let sudo_gid = if basis == Some(DropBasis::Sudo) {
        Some(decimal_id(caller.sudo_gid.as_deref()).ok_or_else(|| {
            RunAsProblem::SudoGidUnusable {
                uid,
                sudo_gid: caller
                    .sudo_gid
                    .as_deref()
                    .map(|gid| gid.to_string_lossy().into_owned()),
            }
        })?)
    } else {
        None
    };
    let entry = match passwd(uid) {
        PasswdLookup::Entry(entry) => entry,
        PasswdLookup::NoEntry => return Err(RunAsProblem::NoPasswdEntry { uid }),
        PasswdLookup::Failed => return Err(RunAsProblem::PasswdUnreadable { uid }),
    };
    let run_as = match basis {
        None => RunAs::Caller { uid },
        Some(basis) => {
            let gid = sudo_gid.unwrap_or(entry.gid);
            if gid == 0 {
                return Err(RunAsProblem::RootGroup { uid, basis });
            }
            RunAs::Drop {
                to: DroppedTo { uid, gid },
                basis,
            }
        }
    };
    if entry.home.starts_with(root.dir) {
        return Err(RunAsProblem::HomeProject {
            uid,
            home: entry.home.display().to_string(),
        });
    }
    Ok(run_as)
}

/// A plain decimal id, as `sudo` writes `SUDO_GID`.
fn decimal_id(text: Option<&OsStr>) -> Option<u32> {
    let text = text?.to_str()?;
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

/// What the search check reads about a directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirStat {
    /// Its owner's uid.
    pub owner: u32,
    /// Its group's gid.
    pub group: u32,
    /// Its mode.
    pub mode: u32,
}

/// Whether `to`, with its group alone (a drop from root leaves no
/// supplementary groups), may search a directory. The first class that matches
/// decides, as the kernel's check does: the owner's bits for the owner even
/// when others' would allow it. ACLs are not read.
pub const fn may_search(to: DroppedTo, dir: DirStat) -> bool {
    let bit = if to.uid == dir.owner {
        0o100
    } else if to.gid == dir.group {
        0o010
    } else {
        0o001
    };
    dir.mode & bit != 0
}

/// The first directory from `/` down to `root` itself, inclusive, that `to`
/// can't search ([`may_search`]), each read through `stat`; `None` when every
/// one can be.
///
/// # Errors
/// The first `stat` error.
pub fn first_unsearchable(
    root: &Path,
    to: DroppedTo,
    mut stat: impl FnMut(&Path) -> std::io::Result<DirStat>,
) -> std::io::Result<Option<PathBuf>> {
    let mut dirs: Vec<&Path> = root.ancestors().collect();
    // outermost first, so the refusal names the first directory that bars it
    dirs.reverse();
    for dir in dirs {
        if !may_search(to, stat(dir)?) {
            return Ok(Some(dir.to_path_buf()));
        }
    }
    Ok(None)
}

/// Why [`settle_run_as`] failed.
#[derive(Debug)]
pub enum SettleError {
    /// A stat on the way to the trust root failed.
    Io(std::io::Error),
    /// The eval is refused.
    Refused(RunAsProblem),
}

/// Who `fgro` runs as for a config whose trust root is `root` (canonical):
/// [`decide_run_as`] over the root's owner and a passwd lookup, then, for a
/// drop, [`first_unsearchable`] must find none, since the working directory is
/// entered after the drop.
///
/// # Errors
/// [`SettleError::Io`] when a directory on the way can't be stat'd;
/// [`SettleError::Refused`] with the [`RunAsProblem`].
pub fn settle_run_as(caller: &Caller, root: &Path) -> Result<RunAs, SettleError> {
    let owner = dir_stat(root).map_err(SettleError::Io)?.owner;
    let run_as = decide_run_as(caller, RootStat { dir: root, owner }, passwd_of)
        .map_err(SettleError::Refused)?;
    if let Some(to) = run_as.dropped_to()
        && let Some(dir) = first_unsearchable(root, to, dir_stat).map_err(SettleError::Io)?
    {
        return Err(SettleError::Refused(RunAsProblem::NotSearchable {
            uid: to.uid,
            gid: to.gid,
            dir: dir.display().to_string(),
        }));
    }
    Ok(run_as)
}

/// The stat of `dir`, following links, an error naming it.
fn dir_stat(dir: &Path) -> std::io::Result<DirStat> {
    std::fs::metadata(dir)
        .map(|meta| DirStat {
            owner: meta.uid(),
            group: meta.gid(),
            mode: meta.mode(),
        })
        .map_err(|source| {
            std::io::Error::new(source.kind(), format!("stat {}: {source}", dir.display()))
        })
}

/// `uid`'s passwd entry (`getpwuid_r`), its home canonicalized when it resolves
/// (one that doesn't, a home that doesn't exist, is compared as written). A
/// failed lookup carries no reason: the binding reads `errno`, not the call's
/// return, so the reason it gives can be stale.
fn passwd_of(uid: u32) -> PasswdLookup {
    match nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid)) {
        Ok(Some(user)) => PasswdLookup::Entry(PasswdEntry {
            home: std::fs::canonicalize(&user.dir).unwrap_or(user.dir),
            gid: user.gid.as_raw(),
        }),
        Ok(None) => PasswdLookup::NoEntry,
        Err(_) => PasswdLookup::Failed,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn caller(euid: u32, sudo_uid: Option<&str>, sudo_gid: Option<&str>) -> Caller {
        Caller {
            euid,
            sudo_uid: sudo_uid.map(OsString::from),
            sudo_gid: sudo_gid.map(OsString::from),
        }
    }

    const ROOT_DIR: &str = "/home/u/dev/p";

    /// The uid `fgro` runs as.
    const fn uid_of(run_as: RunAs) -> u32 {
        match run_as {
            RunAs::Caller { uid }
            | RunAs::Drop {
                to: DroppedTo { uid, .. },
                ..
            } => uid,
        }
    }

    /// Every user has an entry, a home outside the project, and primary group
    /// `uid + 5`; uid 1009's primary group is root's.
    fn passwd(uid: u32) -> PasswdLookup {
        PasswdLookup::Entry(PasswdEntry {
            home: PathBuf::from(format!("/home/user{uid}")),
            gid: if uid == 1009 { 0 } else { uid + 5 },
        })
    }

    fn decide(caller: &Caller, owner: u32) -> Result<RunAs, RunAsProblem> {
        decide_run_as(
            caller,
            RootStat {
                dir: Path::new(ROOT_DIR),
                owner,
            },
            passwd,
        )
    }

    /// The drop table: euid, `SUDO_UID`, `SUDO_GID`, and the trust root's owner
    /// decide who `fgro` runs as. A drop is only ever to the project's owner.
    #[test]
    fn who_fgro_runs_as() {
        use DropBasis::{ProjectOwner, Sudo};
        let drop = |uid, gid, basis| {
            Ok(RunAs::Drop {
                to: DroppedTo { uid, gid },
                basis,
            })
        };
        let cases = [
            (
                "not root: no drop, SUDO_* ignored",
                caller(1000, Some("1001"), Some("1001")),
                0,
                Ok(RunAs::Caller { uid: 1000 }),
            ),
            (
                "not root, the owner another user",
                caller(1000, None, None),
                1001,
                Ok(RunAs::Caller { uid: 1000 }),
            ),
            (
                "sudo by the owner: SUDO_UID with SUDO_GID, not the passwd group",
                caller(0, Some("1000"), Some("100")),
                1000,
                drop(1000, 100, Sudo),
            ),
            (
                "sudo by the owner: SUDO_GID unset",
                caller(0, Some("1000"), None),
                1000,
                Err(RunAsProblem::SudoGidUnusable {
                    uid: 1000,
                    sudo_gid: None,
                }),
            ),
            (
                "sudo by the owner: SUDO_GID not decimal",
                caller(0, Some("1000"), Some("+1000")),
                1000,
                Err(RunAsProblem::SudoGidUnusable {
                    uid: 1000,
                    sudo_gid: Some("+1000".to_owned()),
                }),
            ),
            (
                "sudo by the owner: SUDO_GID empty",
                caller(0, Some("1000"), Some("")),
                1000,
                Err(RunAsProblem::SudoGidUnusable {
                    uid: 1000,
                    sudo_gid: Some(String::new()),
                }),
            ),
            (
                "sudo by the owner: SUDO_GID 0",
                caller(0, Some("1000"), Some("0")),
                1000,
                Err(RunAsProblem::RootGroup {
                    uid: 1000,
                    basis: Sudo,
                }),
            ),
            (
                "sudo, root owns the project: refused, never the sudo user",
                caller(0, Some("1000"), Some("1000")),
                0,
                Err(RunAsProblem::RootOwnedProject {
                    sudo_uid: Some(1000),
                }),
            ),
            (
                "sudo, another user owns the project: the owner, SUDO_GID unused",
                caller(0, Some("1000"), Some("bad")),
                1001,
                drop(1001, 1006, ProjectOwner),
            ),
            (
                "root, SUDO_UID unset: the owner and its passwd group",
                caller(0, None, None),
                1000,
                drop(1000, 1005, ProjectOwner),
            ),
            (
                "root, SUDO_UID 0 counts as unset",
                caller(0, Some("0"), Some("0")),
                1000,
                drop(1000, 1005, ProjectOwner),
            ),
            (
                "root, SUDO_UID not decimal counts as unset",
                caller(0, Some("me"), Some("1000")),
                1000,
                drop(1000, 1005, ProjectOwner),
            ),
            (
                "root, SUDO_UID unset, root owns the project",
                caller(0, None, None),
                0,
                Err(RunAsProblem::RootOwnedProject { sudo_uid: None }),
            ),
            (
                "root, SUDO_UID 0, root owns the project",
                caller(0, Some("0"), Some("0")),
                0,
                Err(RunAsProblem::RootOwnedProject { sudo_uid: None }),
            ),
            (
                "root, the owner's passwd group is root's",
                caller(0, None, None),
                1009,
                Err(RunAsProblem::RootGroup {
                    uid: 1009,
                    basis: ProjectOwner,
                }),
            ),
            (
                "sudo by an owner whose passwd group is root's: SUDO_GID wins",
                caller(0, Some("1009"), Some("1009")),
                1009,
                drop(1009, 1009, Sudo),
            ),
        ];
        for (name, caller, owner, expected) in cases {
            assert_eq!(decide(&caller, owner), expected, "{name}");
        }
    }

    /// The passwd entry of the user it runs as: the project must not be its
    /// home or hold it, and a user with no entry, or a lookup that fails, is
    /// refused. The lookup is for the uid the eval runs as.
    #[test]
    fn the_project_must_not_be_the_target_user_s_home() {
        let run = |caller: &Caller, lookup: PasswdLookup| {
            let mut asked = None;
            let result = decide_run_as(
                caller,
                RootStat {
                    dir: Path::new(ROOT_DIR),
                    owner: 1002,
                },
                |uid| {
                    asked = Some(uid);
                    lookup
                },
            );
            (result, asked)
        };
        let home = |path: &str| {
            PasswdLookup::Entry(PasswdEntry {
                home: PathBuf::from(path),
                gid: 7,
            })
        };
        let not_root = caller(1000, None, None);
        let sudo = caller(0, Some("1002"), Some("1002"));
        let owner = caller(0, None, None);
        for (caller, uid) in [(&not_root, 1000), (&sudo, 1002), (&owner, 1002)] {
            for (name, path, refused) in [
                ("the home itself", ROOT_DIR, true),
                ("a home below the project", "/home/u/dev/p/me", true),
                ("the project's parent", "/home/u/dev", false),
                ("a sibling sharing a prefix", "/home/u/dev/p2", false),
                ("elsewhere", "/home/other", false),
            ] {
                let (result, asked) = run(caller, home(path));
                assert_eq!(asked, Some(uid), "{name}");
                if refused {
                    assert_eq!(
                        result,
                        Err(RunAsProblem::HomeProject {
                            uid,
                            home: path.to_owned(),
                        }),
                        "{name}"
                    );
                } else {
                    assert_eq!(result.map(uid_of), Ok(uid), "{name}");
                }
            }
            assert_eq!(
                run(caller, PasswdLookup::NoEntry).0,
                Err(RunAsProblem::NoPasswdEntry { uid })
            );
            assert_eq!(
                run(caller, PasswdLookup::Failed).0,
                Err(RunAsProblem::PasswdUnreadable { uid })
            );
        }
        // a refusal before the lookup leaves it unasked
        for (caller, owner) in [
            (caller(0, None, None), 0),
            (caller(0, Some("1002"), None), 1002),
        ] {
            let result = decide_run_as(
                &caller,
                RootStat {
                    dir: Path::new(ROOT_DIR),
                    owner,
                },
                |uid| panic!("asked for {uid}'s entry"),
            );
            assert!(result.is_err(), "{result:?}");
        }
    }

    /// Search permission: the first class that matches decides, and a drop
    /// carries no supplementary group.
    #[test]
    fn may_search_takes_the_first_class_that_matches() {
        let to = DroppedTo {
            uid: 1000,
            gid: 1000,
        };
        for (owner, group, mode, expected) in [
            (1000, 1000, 0o700, true),
            (1000, 1000, 0o070, false), // the owner's bits decide for the owner
            (1000, 1000, 0o007, false),
            (0, 1000, 0o750, true),
            (0, 1000, 0o705, false), // the group's bits decide for the group
            (0, 0, 0o755, true),
            (0, 0, 0o750, false),
            (0, 0, 0o711, true),
            (0, 0, 0o1777, true),
            (0, 0, 0o644, false), // read is not search
        ] {
            assert_eq!(
                may_search(to, DirStat { owner, group, mode }),
                expected,
                "{owner}:{group} {mode:o}"
            );
        }
    }

    /// The search check reads every directory from `/` to the trust root, the
    /// root itself included, and names the outermost that bars the user.
    #[test]
    fn the_search_check_covers_every_directory_to_the_trust_root() {
        let to = DroppedTo {
            uid: 1000,
            gid: 1000,
        };
        let root = Path::new("/srv/team/p");
        let open = DirStat {
            owner: 0,
            group: 0,
            mode: 0o755,
        };
        let shut = DirStat {
            owner: 0,
            group: 0,
            mode: 0o700,
        };
        let check = |barred: &[&str]| {
            let mut read = Vec::new();
            let found = first_unsearchable(root, to, |dir| {
                read.push(dir.to_path_buf());
                Ok(if barred.iter().any(|b| Path::new(b) == dir) {
                    shut
                } else {
                    open
                })
            })
            .unwrap();
            (found, read)
        };
        let (found, read) = check(&[]);
        assert_eq!(found, None);
        assert_eq!(
            read,
            ["/", "/srv", "/srv/team", "/srv/team/p"].map(PathBuf::from)
        );
        for (barred, first) in [
            (&["/srv/team/p"][..], "/srv/team/p"),
            (&["/"][..], "/"),
            (&["/srv"][..], "/srv"),
            (&["/srv/team", "/srv/team/p"][..], "/srv/team"),
        ] {
            assert_eq!(check(barred).0, Some(PathBuf::from(first)), "{barred:?}");
        }
        // a stat that fails is the error
        let stats: HashMap<&str, DirStat> = HashMap::from([("/", open), ("/srv", open)]);
        let error = first_unsearchable(root, to, |dir| {
            stats
                .get(dir.to_str().unwrap())
                .copied()
                .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))
        })
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
    }

    /// Without a drop nothing past the trust root's stat and the passwd lookup
    /// is read: the caller already reached the project.
    #[test]
    fn settle_without_a_drop_is_the_caller() {
        let me = Caller::of_process().unwrap();
        if me.euid == 0 {
            return;
        }
        let root = std::fs::canonicalize(std::env::temp_dir()).unwrap();
        assert_eq!(
            settle_run_as(&me, &root).unwrap(),
            RunAs::Caller { uid: me.euid }
        );
    }
}
