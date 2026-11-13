//! Path-string helpers (no `~/.fuz` knowledge): the user's home directory and
//! the `~` forms rendered against it.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use thiserror::Error;

/// Why the user's home directory could not be resolved.
///
/// Every `$HOME` reader in the workspace resolves through [`home_dir`], so
/// these are the only ways a home lookup fails. The path in
/// [`HomeDirError::Relative`] is the user's own `$HOME`, so the message echoes
/// it.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum HomeDirError {
    /// `$HOME` is unset and the password database names no home either.
    #[error("HOME is not set and the user has no home directory entry")]
    NotFound,
    /// The home is empty — an exported-but-empty `$HOME`, or an empty home
    /// field in the password database.
    #[error("the home directory (HOME) is empty")]
    Empty,
    /// The home is a relative path, which would resolve against the process
    /// cwd rather than name a directory.
    #[error("the home directory (HOME) is not an absolute path: {}", path.display())]
    Relative {
        /// The relative home, verbatim.
        path: PathBuf,
    },
}

/// The user's home directory: `$HOME` when set, else the password database's
/// entry for the current user — and only ever a non-empty, absolute path.
///
/// The single `$HOME` lookup behind every fuz home-relative path (`~/.fuz`,
/// the default forge home `~/.fuz_forge`, the shell rc file, the default
/// source repo of `fuz artifact build`, `~` expansion). An unusable value is
/// an error rather than a path: joined onto, an empty or relative home would
/// silently name a location under the process cwd.
///
/// An exported-but-empty `$HOME` is [`HomeDirError::Empty`], not a cue to
/// consult the password database (which `std::env::home_dir` does): the
/// environment named a home, it just isn't usable, and quietly substituting a
/// different one would put state where the user didn't point. The value is
/// read as OS bytes, so a non-UTF-8 home works like any other.
///
/// # Errors
///
/// [`HomeDirError::NotFound`] when neither `$HOME` nor the password database
/// names a home, [`HomeDirError::Empty`] or [`HomeDirError::Relative`] when the
/// one found is unusable.
pub fn home_dir() -> Result<PathBuf, HomeDirError> {
    // `std::env::home_dir` is consulted only when `HOME` is unset, where it
    // falls back to `getpwuid_r` — the lookup `unsafe_code = "forbid"` keeps
    // this crate from making itself.
    #[expect(
        clippy::disallowed_methods,
        reason = "the workspace's one sanctioned `home_dir` use, for its password-database fallback"
    )]
    let passwd_home = std::env::home_dir;
    resolve_home_dir(std::env::var_os("HOME"), passwd_home)
}

/// The pure core of [`home_dir`], with `$HOME` and the password-database
/// fallback injected.
fn resolve_home_dir(
    home: Option<OsString>,
    fallback: impl FnOnce() -> Option<PathBuf>,
) -> Result<PathBuf, HomeDirError> {
    let home = match home {
        Some(home) => PathBuf::from(home),
        None => fallback().ok_or(HomeDirError::NotFound)?,
    };
    if home.as_os_str().is_empty() {
        Err(HomeDirError::Empty)
    } else if home.is_absolute() {
        Ok(home)
    } else {
        Err(HomeDirError::Relative { path: home })
    }
}

/// Expand a leading `~` against the home directory, refusing when that home is
/// unusable: `~/rest` → `<home>/rest`, bare `~` → `<home>`.
///
/// The fallible form, for a path fuz is about to read or create: an unusable
/// home is an error rather than the literal `~/rest`, which would resolve
/// under the process cwd. `home_dir` is consulted only for a `~` or `~/…`
/// path — any other path (`/abs`, `rel`, `~user/x`, an embedded `foo/~/bar`)
/// is returned unchanged without it. Production passes [`home_dir`]; tests
/// inject one.
///
/// # Errors
///
/// `home_dir`'s [`HomeDirError`] when the path starts with `~` and the home is
/// unusable.
pub fn expand_tilde_checked(
    path: &str,
    home_dir: impl FnOnce() -> Result<PathBuf, HomeDirError>,
) -> Result<PathBuf, HomeDirError> {
    let rest = match path.strip_prefix("~/") {
        Some(rest) => rest,
        None if path == "~" => "",
        None => return Ok(PathBuf::from(path)),
    };
    let home = home_dir()?;
    // `join("")` would append a trailing separator; bare `~` is the home itself.
    Ok(if rest.is_empty() {
        home
    } else {
        home.join(rest)
    })
}

/// Expand a leading `~` to the home directory: `~/rest` → `$HOME/rest`, bare
/// `~` → `$HOME`.
///
/// The infallible form of [`expand_tilde_checked`] over [`home_dir`]: a home it
/// refuses (empty, relative, or not found) leaves the path unchanged — a
/// literal `~/rest`, which resolves under the process cwd. Kept as the twin of
/// a consumer's TS `resolve_tilde`, which has the same literal-when-no-home
/// rule; a path fuz reads or creates takes [`expand_tilde_checked`] instead.
/// Only a leading `~` component is expanded (an embedded `foo/~/bar` is left
/// alone).
#[must_use]
pub fn expand_tilde(path: &str) -> PathBuf {
    expand_tilde_checked(path, home_dir).unwrap_or_else(|_| PathBuf::from(path))
}

/// Collapse a leading home directory to `~`: `$HOME/rest` → `~/rest`.
///
/// The display-side inverse of [`expand_tilde`] — that resolves a `~`-prefixed
/// string into a real path, this shortens a real path back into the `~/…` form
/// users recognize. The result is a rendered `String` for CLI output, not a
/// path to reopen.
///
/// The path is returned verbatim (`Path::display`) when [`home_dir`] refuses
/// the home, or when the path does not lie under it. The home itself renders
/// as `~/`, the trailing separator of an empty remainder. Both directions read
/// the home through [`home_dir`], so they agree on what counts as one.
#[must_use]
pub fn collapse_tilde(path: &Path) -> String {
    render_tilde(path, home_dir().ok().as_deref())
}

/// The pure half of [`collapse_tilde`], with the home directory injected.
fn render_tilde(path: &Path, home: Option<&Path>) -> String {
    strip_home(path, home).map_or_else(
        || path.display().to_string(),
        |relative| format!("~/{}", relative.display()),
    )
}

/// The part of `path` below `home`, when `path` lies under it.
///
/// The one definition of "under `$HOME`" this module's renderers share, with
/// the home directory injected: [`collapse_tilde`] renders the remainder as
/// `~/rest` for display, and a caller writing a shell line renders it as
/// `$HOME/rest`. The match is lexical and component-wise (`Path::strip_prefix`)
/// — `/home/u2` is not under `/home/u`, and no symlink is resolved. `home`
/// itself yields the empty remainder.
///
/// An empty `home` matches nothing, as [`home_dir`] refuses an empty `$HOME`;
/// the filter stays here because `home` is injected. Without it the empty
/// prefix strips from every path, so an absolute path would render as the
/// doubled-separator `~//foo/bar` and a relative one would gain a `~/` it has
/// no claim to.
#[must_use]
pub fn strip_home<'a>(path: &'a Path, home: Option<&Path>) -> Option<&'a Path> {
    home.filter(|home| !home.as_os_str().is_empty())
        .and_then(|home| path.strip_prefix(home).ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expand_tilde_leaves_non_tilde_paths() {
        assert_eq!(
            expand_tilde("/var/releases"),
            PathBuf::from("/var/releases")
        );
        assert_eq!(expand_tilde("./releases"), PathBuf::from("./releases"));
        assert_eq!(expand_tilde("releases"), PathBuf::from("releases"));
    }

    /// Every row of [`home_dir`]'s rule, with `$HOME` and the password
    /// database injected. The empty row is the one `std::env::home_dir`
    /// disagrees with: it reads an empty `$HOME` as unset and substitutes the
    /// password database's home, where this refuses it.
    #[test]
    fn resolve_home_dir_accepts_only_a_non_empty_absolute_home() {
        let passwd = || Some(PathBuf::from("/home/pw"));
        let unreachable = || -> Option<PathBuf> { panic!("fallback consulted with HOME set") };

        // `HOME` set: used as given, the fallback never consulted
        assert_eq!(
            resolve_home_dir(Some("/home/u".into()), unreachable),
            Ok(PathBuf::from("/home/u"))
        );
        assert_eq!(
            resolve_home_dir(Some("/".into()), unreachable),
            Ok(PathBuf::from("/"))
        );
        assert_eq!(
            resolve_home_dir(Some("".into()), unreachable),
            Err(HomeDirError::Empty)
        );
        for relative in ["h", "./h", "~", "home/u"] {
            assert_eq!(
                resolve_home_dir(Some(relative.into()), unreachable),
                Err(HomeDirError::Relative {
                    path: PathBuf::from(relative)
                }),
                "HOME={relative}"
            );
        }

        // `HOME` unset: the password database's entry, held to the same rule
        assert_eq!(
            resolve_home_dir(None, passwd),
            Ok(PathBuf::from("/home/pw"))
        );
        assert_eq!(resolve_home_dir(None, || None), Err(HomeDirError::NotFound));
        assert_eq!(
            resolve_home_dir(None, || Some(PathBuf::new())),
            Err(HomeDirError::Empty)
        );
        assert_eq!(
            resolve_home_dir(None, || Some(PathBuf::from("pw"))),
            Err(HomeDirError::Relative {
                path: PathBuf::from("pw")
            })
        );
    }

    /// A non-UTF-8 `$HOME` is a home like any other: read as OS bytes, not
    /// dropped as unset.
    #[test]
    fn resolve_home_dir_takes_a_non_utf8_home() {
        use std::os::unix::ffi::OsStrExt;
        let home = std::ffi::OsStr::from_bytes(b"/home/f\xffz");
        assert_eq!(
            resolve_home_dir(Some(home.to_owned()), || None),
            Ok(PathBuf::from(home))
        );
    }

    /// The error messages name `HOME` — the variable the user fixes — and the
    /// relative value itself.
    #[test]
    fn home_dir_error_names_the_variable() {
        for error in [
            HomeDirError::NotFound,
            HomeDirError::Empty,
            HomeDirError::Relative {
                path: PathBuf::from("rel/h"),
            },
        ] {
            assert!(error.to_string().contains("HOME"), "{error}");
        }
        assert!(
            HomeDirError::Relative {
                path: PathBuf::from("rel/h")
            }
            .to_string()
            .ends_with(": rel/h")
        );
    }

    #[test]
    fn expand_tilde_expands_leading_tilde_against_home_dir() {
        // Skipped when the test process has no usable home, where the
        // expansion is (correctly) not performed.
        if let Ok(home) = home_dir() {
            assert_eq!(expand_tilde("~/foo/bar"), home.join("foo/bar"));
            assert_eq!(expand_tilde("~"), home);
        }
    }

    /// Every shape the TS `resolve_tilde` suite pins, with the home injected.
    #[test]
    fn expand_tilde_checked_matches_the_ts_twin() {
        let home = || Ok(PathBuf::from("/home/u"));
        for (path, expected) in [
            ("~/foo/bar", "/home/u/foo/bar"),
            ("~", "/home/u"),
            ("~other/facts", "~other/facts"),
            ("/etc/config", "/etc/config"),
            ("relative/repos", "relative/repos"),
        ] {
            assert_eq!(
                expand_tilde_checked(path, home),
                Ok(PathBuf::from(expected))
            );
        }

        // A home with a trailing slash yields no doubled separator. The TS
        // twin strips it explicitly (`home.replace(/\/+$/, '')`); here it
        // falls out of `PathBuf::join` — pinned so a rewrite can't lose it.
        assert_eq!(
            expand_tilde_checked("~/foo/bar", || Ok(PathBuf::from("/home/u/"))),
            Ok(PathBuf::from("/home/u/foo/bar"))
        );
    }

    /// A `~` path with an unusable home is refused, never left as a literal
    /// `~/…` that would resolve under the cwd; any other path is returned
    /// without consulting the home at all.
    #[test]
    fn expand_tilde_checked_refuses_an_unusable_home_and_is_lazy() {
        for reason in [
            HomeDirError::NotFound,
            HomeDirError::Empty,
            HomeDirError::Relative {
                path: PathBuf::from("h"),
            },
        ] {
            for path in ["~/foo/bar", "~"] {
                assert_eq!(
                    expand_tilde_checked(path, || Err(reason.clone())),
                    Err(reason.clone()),
                    "{path}"
                );
            }
        }
        let unreachable = || -> Result<PathBuf, HomeDirError> {
            panic!("home consulted for a path with no leading `~`")
        };
        for path in ["/var/releases", "releases", "~other/facts", "a/~/b", ""] {
            assert_eq!(
                expand_tilde_checked(path, unreachable),
                Ok(PathBuf::from(path))
            );
        }
    }

    #[test]
    fn collapse_tilde_shortens_paths_under_home() {
        // Skipped when the test process has no usable home, where the path
        // is (correctly) left verbatim.
        if let Ok(home) = home_dir() {
            assert_eq!(collapse_tilde(&home.join("foo/bar")), "~/foo/bar");
        }
    }

    /// "Under `$HOME`" is component-wise, not a string prefix, and an unset or
    /// empty home matches nothing.
    #[test]
    fn strip_home_is_component_wise() {
        let home = Some(Path::new("/home/u"));
        assert_eq!(
            strip_home(Path::new("/home/u/.fuz/bin"), home),
            Some(Path::new(".fuz/bin"))
        );
        assert_eq!(strip_home(Path::new("/home/u"), home), Some(Path::new("")));
        assert_eq!(strip_home(Path::new("/home/u2/.fuz/bin"), home), None);
        assert_eq!(strip_home(Path::new("/var/fuz/bin"), home), None);
        for absent in [None, Some(Path::new(""))] {
            assert_eq!(strip_home(Path::new("/home/u/.fuz/bin"), absent), None);
            assert_eq!(strip_home(Path::new("rel/bin"), absent), None);
        }
    }

    /// The five rows [`collapse_tilde`] renders, with the home injected so the
    /// unset and exported-but-empty cases are reachable without touching the
    /// process environment.
    #[test]
    fn render_tilde_covers_every_home_relation() {
        let home = Some(Path::new("/home/u"));
        // under `$HOME`
        assert_eq!(
            render_tilde(Path::new("/home/u/foo/bar"), home),
            "~/foo/bar"
        );
        // `$HOME` itself — an empty remainder, so the separator is all that's left
        assert_eq!(render_tilde(Path::new("/home/u"), home), "~/");
        // not under `$HOME`
        assert_eq!(
            render_tilde(Path::new("/var/releases"), home),
            "/var/releases"
        );
        // `$HOME` unset or exported-but-empty — every path renders verbatim
        for absent in [None, Some(Path::new(""))] {
            for path in ["/home/u/foo/bar", "/home/u", "/var/releases", "releases"] {
                assert_eq!(
                    render_tilde(Path::new(path), absent),
                    path,
                    "path: {path}, home: {absent:?}"
                );
            }
        }
    }
}
