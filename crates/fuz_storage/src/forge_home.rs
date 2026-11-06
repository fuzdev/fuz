//! The forge home and the forge bearer token — one resolver for `fuz`'s
//! `forge://` backend and the forge's own CLI (`fuzf`), so both read the same
//! token file.
//!
//! `<fuz_forge_home>` is `FUZ_FORGE_HOME` when it is set and not blank (a
//! leading `~` expanded; it must be UTF-8 and absolute), else `.fuz_forge`
//! under [`fuz_sys::home_dir`] (non-empty and absolute). The token is
//! `FUZ_FORGE_TOKEN` when it is set and not blank, else the trimmed contents of
//! `<fuz_forge_home>/api_token` — a regular file (a link to one is followed) of
//! at most [`MAX_TOKEN_FILE_LEN`] bytes. Either way the token must be printable
//! ASCII with no whitespace inside it.
//!
//! The forge's base URL may be set by [`FORGE_BASE_URL_ENV`]
//! (`FUZ_FORGE_BASE_URL`), read by [`forge_base_url_env`] with the token's
//! rule: set and not blank, trimmed, else unset. It serves `fuz`'s host-less
//! `forge://` and is `fuzf`'s server URL ahead of its config file.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use fuz_sys::{HomeDirError, expand_tilde_checked};
use thiserror::Error;

use crate::error::StorageError;

/// The forge home's directory name under the user's home, when
/// `FUZ_FORGE_HOME` is unset.
const FORGE_HOME_DIR: &str = ".fuz_forge";

/// Bearer-token filename under `<fuz_forge_home>/`.
pub const FORGE_TOKEN_FILE: &str = "api_token";

/// Why `<fuz_forge_home>` could not be resolved.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ForgeHomeError {
    /// `FUZ_FORGE_HOME` is unset (or blank) and the home directory is
    /// unusable, so the default `.fuz_forge` has nowhere to live.
    #[error("cannot resolve fuz_forge home (FUZ_FORGE_HOME is unset): {0}")]
    NoHome(HomeDirError),

    /// `FUZ_FORGE_HOME` starts with `~` and the home directory is unusable —
    /// refused rather than read as a literal `~` directory under the cwd.
    #[error("cannot expand `~` in FUZ_FORGE_HOME: {0}")]
    OverrideTilde(HomeDirError),

    /// `FUZ_FORGE_HOME` is not valid UTF-8 — refused rather than read with
    /// its invalid bytes replaced, which would name a different directory.
    #[error("FUZ_FORGE_HOME is not valid UTF-8: {}", .0.to_string_lossy())]
    NotUnicode(OsString),

    /// `FUZ_FORGE_HOME` names a relative path (`~user/…` and a space-led path
    /// included), which would resolve against each command's cwd.
    #[error("FUZ_FORGE_HOME must be an absolute path, got {}", path.display())]
    RelativeOverride {
        /// The path as given, after `~` expansion.
        path: PathBuf,
    },
}

impl ForgeHomeError {
    /// User-facing fix suggestion.
    pub const fn hint(&self) -> &'static str {
        "set HOME to your home directory's absolute path, or FUZ_FORGE_HOME to an absolute path"
    }
}

/// The environment variable naming the forge's base URL.
pub const FORGE_BASE_URL_ENV: &str = "FUZ_FORGE_BASE_URL";

/// `FUZ_FORGE_BASE_URL` is set but not valid UTF-8 — refused rather than
/// read as unset, which would fall through to another server.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{FORGE_BASE_URL_ENV} is not valid UTF-8")]
pub struct ForgeBaseUrlNotUnicode;

/// A configuration error, with no hint channel to carry beyond its message.
impl From<ForgeBaseUrlNotUnicode> for StorageError {
    fn from(error: ForgeBaseUrlNotUnicode) -> Self {
        Self::InvalidConfig {
            message: error.to_string(),
        }
    }
}

/// Read `FUZ_FORGE_BASE_URL`: the trimmed value, or `None` when it is unset
/// or blank. The value is not validated here; its consumer validates it as a
/// base URL ([`crate::base_url::validate_base_url`]).
///
/// # Errors
///
/// [`ForgeBaseUrlNotUnicode`] when it is set but not UTF-8.
pub fn forge_base_url_env() -> Result<Option<String>, ForgeBaseUrlNotUnicode> {
    forge_base_url_from(std::env::var_os(FORGE_BASE_URL_ENV))
}

/// Pure core of [`forge_base_url_env`], with the variable's value injected.
fn forge_base_url_from(value: Option<OsString>) -> Result<Option<String>, ForgeBaseUrlNotUnicode> {
    let Some(value) = value else {
        return Ok(None);
    };
    let value = value.to_str().ok_or(ForgeBaseUrlNotUnicode)?.trim();
    Ok((!value.is_empty()).then(|| value.to_string()))
}

/// Most bytes a token file may hold; a forge token is far shorter.
pub const MAX_TOKEN_FILE_LEN: u64 = 4096;

/// Where a token was read from, for an error that names it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForgeTokenSource {
    /// The `FUZ_FORGE_TOKEN` environment variable.
    Env,
    /// The token file.
    File(PathBuf),
}

impl std::fmt::Display for ForgeTokenSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Env => f.write_str("FUZ_FORGE_TOKEN"),
            Self::File(path) => write!(f, "{}", path.display()),
        }
    }
}

/// Why a token is refused. The token itself is never shown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MalformedToken {
    /// Not valid UTF-8 (the environment variable).
    NotUnicode,
    /// A leading byte-order mark.
    ByteOrderMark,
    /// Whitespace inside the token (a second line, a space).
    Whitespace,
    /// An ASCII control character.
    Control,
    /// Any other character outside printable ASCII.
    NonAscii,
}

impl std::fmt::Display for MalformedToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::NotUnicode => "it is not valid UTF-8",
            Self::ByteOrderMark => "it starts with a byte-order mark",
            Self::Whitespace => "it contains whitespace",
            Self::Control => "it contains a control character",
            Self::NonAscii => "it contains a character outside printable ASCII",
        })
    }
}

/// Why the forge bearer token could not be resolved.
#[derive(Debug, Error)]
pub enum ForgeTokenError {
    /// The forge home, where the token file lives, did not resolve.
    #[error("cannot resolve forge token: {0}")]
    Home(#[from] ForgeHomeError),

    /// The token file could not be read: missing, unreadable, not a regular
    /// file, longer than [`MAX_TOKEN_FILE_LEN`], or not UTF-8.
    #[error(
        "no forge token: FUZ_FORGE_TOKEN is unset and {} cannot be read: {reason}",
        path.display()
    )]
    Unreadable {
        /// The token file.
        path: PathBuf,
        /// Why the read failed.
        reason: std::io::Error,
    },

    /// The token file holds only whitespace.
    #[error("no forge token: FUZ_FORGE_TOKEN is unset and {} is empty", path.display())]
    Empty {
        /// The token file.
        path: PathBuf,
    },

    /// The token, from either source, is not one a bearer header can carry.
    #[error("forge token from {from} is malformed: {reason}")]
    Malformed {
        /// Where it was read from.
        from: ForgeTokenSource,
        /// What is wrong with it.
        reason: MalformedToken,
    },
}

impl ForgeTokenError {
    /// User-facing fix suggestion.
    pub const fn hint(&self) -> &'static str {
        match self {
            Self::Home(_) => {
                "set FUZ_FORGE_TOKEN, or set HOME to your home directory's absolute path, \
                 or FUZ_FORGE_HOME to an absolute path"
            }
            Self::Malformed { .. } => {
                "a forge token is one word of printable ASCII; re-copy it from the forge's web UI \
                 at /admin/account"
            }
            Self::Unreadable { .. } | Self::Empty { .. } => {
                "set FUZ_FORGE_TOKEN, or create a token in the forge's web UI at /admin/account \
                 and write it to the api_token file"
            }
        }
    }
}

/// `fuz`'s storage layer has no hint channel for a configuration error, so the
/// hint rides in the message.
impl From<ForgeTokenError> for StorageError {
    fn from(error: ForgeTokenError) -> Self {
        Self::InvalidConfig {
            message: format!("{error}; {}", error.hint()),
        }
    }
}

/// Resolve `<fuz_forge_home>`: `FUZ_FORGE_HOME` (tilde-expanded) else
/// `.fuz_forge` under [`fuz_sys::home_dir`].
///
/// # Errors
///
/// [`ForgeHomeError`] when the home it needs is unusable.
pub fn forge_home_dir() -> Result<PathBuf, ForgeHomeError> {
    forge_home_dir_from(std::env::var_os("FUZ_FORGE_HOME"), fuz_sys::home_dir)
}

/// Pure core of [`forge_home_dir`], with `FUZ_FORGE_HOME` and the home lookup
/// injected. The lookup is lazy: a set override consults the home only to
/// expand a leading `~`. A set override must be UTF-8 and, once expanded,
/// absolute.
fn forge_home_dir_from(
    override_home: Option<OsString>,
    home_dir: impl FnOnce() -> Result<PathBuf, HomeDirError>,
) -> Result<PathBuf, ForgeHomeError> {
    if let Some(override_home) = override_home {
        let Some(s) = override_home.to_str() else {
            return Err(ForgeHomeError::NotUnicode(override_home));
        };
        if !s.trim().is_empty() {
            let path = expand_tilde_checked(s, home_dir).map_err(ForgeHomeError::OverrideTilde)?;
            if !path.is_absolute() {
                return Err(ForgeHomeError::RelativeOverride { path });
            }
            return Ok(path);
        }
    }
    let home = home_dir().map_err(ForgeHomeError::NoHome)?;
    Ok(home.join(FORGE_HOME_DIR))
}

/// Resolve the forge bearer token: `FUZ_FORGE_TOKEN`, else
/// `<fuz_forge_home>/api_token`.
///
/// # Errors
///
/// [`ForgeTokenError`] when neither yields a token; the error names the token
/// file it tried.
pub fn resolve_forge_token() -> Result<String, ForgeTokenError> {
    let env_token = std::env::var_os("FUZ_FORGE_TOKEN");
    let env_token = match env_token.as_deref().map(std::ffi::OsStr::to_str) {
        None => None,
        Some(Some(token)) => Some(token),
        Some(None) => {
            return Err(ForgeTokenError::Malformed {
                from: ForgeTokenSource::Env,
                reason: MalformedToken::NotUnicode,
            });
        }
    };
    resolve_forge_token_from(env_token, forge_home_dir)
}

/// Pure-ish core of [`resolve_forge_token`]: the env token and the forge home
/// injected (the home is resolved only when the env token is absent), the
/// token file read from disk.
fn resolve_forge_token_from(
    env_token: Option<&str>,
    forge_home: impl FnOnce() -> Result<PathBuf, ForgeHomeError>,
) -> Result<String, ForgeTokenError> {
    if let Some(token) = env_token.map(str::trim).filter(|t| !t.is_empty()) {
        return checked_token(token, ForgeTokenSource::Env);
    }
    let path = forge_home()?.join(FORGE_TOKEN_FILE);
    let contents = match read_token_file(&path) {
        Ok(contents) => contents,
        Err(reason) => return Err(ForgeTokenError::Unreadable { path, reason }),
    };
    let token = contents.trim();
    if token.is_empty() {
        return Err(ForgeTokenError::Empty { path });
    }
    checked_token(token, ForgeTokenSource::File(path))
}

/// A trimmed token, refused unless it is printable ASCII with no whitespace —
/// so a second line, a stray space, or a byte-order mark is named here rather
/// than surfacing later as a request the HTTP client cannot build.
fn checked_token(token: &str, source: ForgeTokenSource) -> Result<String, ForgeTokenError> {
    let reason = if token.starts_with('\u{feff}') {
        Some(MalformedToken::ByteOrderMark)
    } else {
        token.chars().find_map(|c| {
            if c.is_whitespace() {
                Some(MalformedToken::Whitespace)
            } else if c.is_ascii_control() {
                Some(MalformedToken::Control)
            } else if !c.is_ascii_graphic() {
                Some(MalformedToken::NonAscii)
            } else {
                None
            }
        })
    };
    if let Some(reason) = reason {
        return Err(ForgeTokenError::Malformed {
            from: source,
            reason,
        });
    }
    Ok(token.to_string())
}

/// Read the token file: a symlink is followed (a token kept elsewhere is
/// fine), but only a regular file is read — a FIFO or device there is refused
/// without waiting on it — and at most [`MAX_TOKEN_FILE_LEN`] bytes.
fn read_token_file(path: &Path) -> std::io::Result<String> {
    use std::io::Read as _;
    let (file, _) = fuz_sys::secure_file::open_regular_nonblocking(path)?;
    let mut contents = String::new();
    file.take(MAX_TOKEN_FILE_LEN + 1)
        .read_to_string(&mut contents)?;
    if contents.len() as u64 > MAX_TOKEN_FILE_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("longer than {MAX_TOKEN_FILE_LEN} bytes"),
        ));
    }
    Ok(contents)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `FUZ_FORGE_BASE_URL` follows the token's rule: trimmed, and blank reads
    /// as unset. Non-UTF-8 is refused rather than read as unset.
    #[test]
    fn base_url_env_is_trimmed_and_blank_is_unset() {
        assert_eq!(forge_base_url_from(None), Ok(None));
        for blank in ["", "   ", "\t\n"] {
            assert_eq!(
                forge_base_url_from(Some(blank.into())),
                Ok(None),
                "{blank:?}"
            );
        }
        assert_eq!(
            forge_base_url_from(Some("  http://localhost:4041 \n".into())),
            Ok(Some("http://localhost:4041".to_string()))
        );
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStringExt as _;
            assert_eq!(
                forge_base_url_from(Some(OsString::from_vec(vec![0xff]))),
                Err(ForgeBaseUrlNotUnicode)
            );
        }
    }

    /// A set `FUZ_FORGE_HOME` wins without consulting the home; unset or
    /// blank, the home's `.fuz_forge` — and an unusable home is `NoHome`
    /// carrying the reason, never a cwd-relative `.fuz_forge`.
    #[test]
    fn forge_home_takes_the_override_else_a_usable_home() {
        let unreachable = || -> Result<PathBuf, HomeDirError> {
            panic!("home consulted with FUZ_FORGE_HOME set")
        };
        assert_eq!(
            forge_home_dir_from(Some("/srv/forge".into()), unreachable).unwrap(),
            PathBuf::from("/srv/forge")
        );
        // A `~` override expands against the home, and an unusable home
        // refuses it rather than leaving a literal `~/x` under the cwd.
        assert_eq!(
            forge_home_dir_from(Some("~/x".into()), || Ok(PathBuf::from("/home/u"))).unwrap(),
            PathBuf::from("/home/u/x")
        );
        for override_home in ["~/x", "~"] {
            let error =
                forge_home_dir_from(Some(override_home.into()), || Err(HomeDirError::Empty))
                    .unwrap_err();
            assert_eq!(
                error,
                ForgeHomeError::OverrideTilde(HomeDirError::Empty),
                "{override_home}"
            );
        }
        for unset in [None, Some(OsString::new()), Some(OsString::from("  "))] {
            assert_eq!(
                forge_home_dir_from(unset.clone(), || Ok(PathBuf::from("/home/u"))).unwrap(),
                PathBuf::from("/home/u/.fuz_forge"),
                "FUZ_FORGE_HOME={unset:?}"
            );
            for reason in [
                HomeDirError::NotFound,
                HomeDirError::Empty,
                HomeDirError::Relative {
                    path: PathBuf::from("h"),
                },
            ] {
                let error = forge_home_dir_from(unset.clone(), || Err(reason.clone())).unwrap_err();
                assert_eq!(
                    error,
                    ForgeHomeError::NoHome(reason),
                    "FUZ_FORGE_HOME={unset:?}"
                );
            }
        }
    }

    /// A set env token wins, trimmed, without resolving the home; a blank one
    /// falls through to the token file.
    #[test]
    fn env_token_wins_and_blank_falls_through() {
        let unreachable = || -> Result<PathBuf, ForgeHomeError> {
            panic!("forge home resolved with FUZ_FORGE_TOKEN set")
        };
        assert_eq!(
            resolve_forge_token_from(Some("  env-token\n"), unreachable).unwrap(),
            "env-token"
        );
        let home = tempfile::tempdir().unwrap();
        std::fs::write(home.path().join(FORGE_TOKEN_FILE), " file-token\n").unwrap();
        for blank in [None, Some(""), Some(" \t")] {
            assert_eq!(
                resolve_forge_token_from(blank, || Ok(home.path().to_path_buf())).unwrap(),
                "file-token",
                "FUZ_FORGE_TOKEN={blank:?}"
            );
        }
    }

    /// A missing or blank token file is an error naming the file, and a home
    /// that does not resolve is the home's own error.
    #[test]
    fn token_file_errors_name_the_file() {
        let home = tempfile::tempdir().unwrap();
        let path = home.path().join(FORGE_TOKEN_FILE);

        let error = resolve_forge_token_from(None, || Ok(home.path().to_path_buf())).unwrap_err();
        assert!(
            matches!(&error, ForgeTokenError::Unreadable { path: found, .. } if *found == path),
            "{error}"
        );
        assert!(
            error.to_string().starts_with(&format!(
                "no forge token: FUZ_FORGE_TOKEN is unset and {} cannot be read: ",
                path.display()
            )),
            "{error}"
        );

        std::fs::write(&path, " \n").unwrap();
        let error = resolve_forge_token_from(None, || Ok(home.path().to_path_buf())).unwrap_err();
        assert_eq!(
            error.to_string(),
            format!(
                "no forge token: FUZ_FORGE_TOKEN is unset and {} is empty",
                path.display()
            )
        );
        assert!(error.hint().starts_with("set FUZ_FORGE_TOKEN"));

        let error =
            resolve_forge_token_from(None, || Err(ForgeHomeError::NoHome(HomeDirError::Empty)))
                .unwrap_err();
        assert_eq!(
            error.to_string(),
            "cannot resolve forge token: cannot resolve fuz_forge home (FUZ_FORGE_HOME is \
             unset): the home directory (HOME) is empty"
        );
        assert!(
            error
                .hint()
                .starts_with("set FUZ_FORGE_TOKEN, or set HOME to your home directory's")
        );
    }

    /// A non-UTF-8 `FUZ_FORGE_HOME` is refused, never read lossily as a
    /// different directory.
    #[test]
    fn a_non_utf8_override_is_refused() {
        use std::os::unix::ffi::OsStringExt as _;
        let raw = OsString::from_vec(b"/srv/forge\xff".to_vec());
        let error = forge_home_dir_from(Some(raw.clone()), || -> Result<PathBuf, HomeDirError> {
            panic!("home consulted for a non-UTF-8 override")
        })
        .unwrap_err();
        assert_eq!(error, ForgeHomeError::NotUnicode(raw));
    }

    /// A relative `FUZ_FORGE_HOME` — `~user/x` and a space-led absolute path
    /// among them — is refused, as a relative `FUZ_HOME` is.
    #[test]
    fn a_relative_override_is_refused() {
        for given in ["rel", "./rel", "~user/x", " /srv/forge"] {
            let error = forge_home_dir_from(Some(given.into()), || Ok(PathBuf::from("/home/u")))
                .unwrap_err();
            assert_eq!(
                error,
                ForgeHomeError::RelativeOverride {
                    path: PathBuf::from(given)
                },
                "{given:?}"
            );
        }
    }

    /// A FIFO at the token file is refused without waiting for a writer, a
    /// device is refused, and a file over the bound is refused, not truncated;
    /// one at the bound is read whole, and a link to a regular file is followed.
    #[test]
    fn token_file_must_be_a_bounded_regular_file() {
        let home = tempfile::tempdir().unwrap();
        let path = home.path().join(FORGE_TOKEN_FILE);
        let unreadable = |home: &Path| {
            let error = resolve_forge_token_from(None, || Ok(home.to_path_buf())).unwrap_err();
            assert!(
                matches!(error, ForgeTokenError::Unreadable { .. }),
                "{error}"
            );
        };

        nix::unistd::mkfifo(&path, nix::sys::stat::Mode::S_IRWXU).unwrap();
        let forge_home = home.path().to_path_buf();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(resolve_forge_token_from(None, || Ok(forge_home)).is_err());
        });
        assert!(
            rx.recv_timeout(std::time::Duration::from_secs(5))
                .expect("a FIFO token file was waited on")
        );

        std::fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink("/dev/zero", &path).unwrap();
        unreadable(home.path());

        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, "t".repeat(4097)).unwrap();
        unreadable(home.path());

        std::fs::write(&path, "t".repeat(4096)).unwrap();
        assert_eq!(
            resolve_forge_token_from(None, || Ok(home.path().to_path_buf()))
                .unwrap()
                .len(),
            4096
        );

        let elsewhere = home.path().join("kept-elsewhere");
        std::fs::write(&elsewhere, "linked-token\n").unwrap();
        std::fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(&elsewhere, &path).unwrap();
        assert_eq!(
            resolve_forge_token_from(None, || Ok(home.path().to_path_buf())).unwrap(),
            "linked-token"
        );
    }

    /// A token with whitespace inside it, a control character, a byte-order
    /// mark, or anything outside printable ASCII is refused, naming where it
    /// came from — from the file and from the environment alike.
    #[test]
    fn a_malformed_token_is_refused_naming_its_source() {
        let home = tempfile::tempdir().unwrap();
        let path = home.path().join(FORGE_TOKEN_FILE);
        for (token, reason) in [
            ("abc\ndef", MalformedToken::Whitespace),
            ("abc def", MalformedToken::Whitespace),
            ("abc\u{7f}def", MalformedToken::Control),
            ("abc\u{1b}[0m", MalformedToken::Control),
            ("\u{feff}abc", MalformedToken::ByteOrderMark),
            ("abc\u{e9}", MalformedToken::NonAscii),
        ] {
            std::fs::write(&path, format!("{token}\n")).unwrap();
            let error =
                resolve_forge_token_from(None, || Ok(home.path().to_path_buf())).unwrap_err();
            assert!(
                matches!(
                    &error,
                    ForgeTokenError::Malformed { from: ForgeTokenSource::File(found), reason: r }
                        if *found == path && *r == reason
                ),
                "{token:?}: {error}"
            );
            assert_eq!(
                error.to_string(),
                format!("forge token from {} is malformed: {reason}", path.display())
            );

            let error = resolve_forge_token_from(Some(token), || -> Result<PathBuf, _> {
                panic!("forge home resolved with FUZ_FORGE_TOKEN set")
            })
            .unwrap_err();
            assert_eq!(
                error.to_string(),
                format!("forge token from FUZ_FORGE_TOKEN is malformed: {reason}"),
                "{token:?}"
            );
            assert!(!error.to_string().contains("abc"), "the token is not shown");
        }
    }

    /// A token of the shape the forge mints — `secret_fuz_token_` and a
    /// 43-character base64url body, `-` and `_` included — passes, from the
    /// environment and from the file alike.
    #[test]
    fn a_minted_token_shape_passes() {
        let minted = format!("secret_fuz_token_{}x", "aZ09-_".repeat(7));
        assert_eq!(
            resolve_forge_token_from(Some(&minted), || -> Result<PathBuf, _> {
                panic!("forge home resolved with FUZ_FORGE_TOKEN set")
            })
            .unwrap(),
            minted
        );
        let home = tempfile::tempdir().unwrap();
        std::fs::write(home.path().join(FORGE_TOKEN_FILE), format!("{minted}\r\n")).unwrap();
        assert_eq!(
            resolve_forge_token_from(None, || Ok(home.path().to_path_buf())).unwrap(),
            minted
        );
    }

    /// As a storage error the hint rides in the message.
    #[test]
    fn storage_error_carries_the_hint() {
        let error = StorageError::from(ForgeTokenError::Empty {
            path: PathBuf::from("/h/api_token"),
        });
        assert_eq!(
            error.to_string(),
            "no forge token: FUZ_FORGE_TOKEN is unset and /h/api_token is empty; set \
             FUZ_FORGE_TOKEN, or create a token in the forge's web UI at /admin/account and \
             write it to the api_token file"
        );
    }
}
