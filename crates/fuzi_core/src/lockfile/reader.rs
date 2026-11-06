//! Read, parse, and version-gate `package-lock.json`.
//!
//! The lockfile read is fuzi's primary IO at plan time. A bad version fails the whole
//! read (distinct from per-entry refusals, which accumulate in
//! `crate::classify`).
//!
//! Versions 2 and 3 are read alike, through their `packages` map: npm 7+ writes
//! the same map into both, and a v2 file only adds the legacy v1
//! `dependencies` tree beside it, which fuzi never reads. Version 1 has no
//! `packages` map and is refused, and so is a v2 or v3 file without one: npm
//! would rebuild the tree from the legacy section, and fuzi has no reader for
//! it, so reading the absence as an empty tree would install nothing.

use std::collections::BTreeMap;
use std::path::Path;

use serde::Deserialize;

use crate::error::{FuziError, ProjectFile, read_project_file};
use crate::lockfile::raw::{RawLockfile, RawPackageEntry};

/// The document as read, before the gates — [`RawLockfile`] with `packages`
/// optional, so an absent map is told apart from an empty one.
#[derive(Deserialize)]
struct LockfileDocument {
    #[serde(rename = "lockfileVersion")]
    lockfile_version: Option<u32>,
    name: Option<String>,
    packages: Option<BTreeMap<String, RawPackageEntry>>,
}

/// The lockfile version at the decision point — an enum, not a bare `u32`.
///
/// `Unsupported(u32)` and `Missing` let the gate name what it found; the reader
/// maps both to `FuziError::Lockfile` immediately.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockfileVersion {
    /// `lockfileVersion: 2` — npm 7/8's default: the `packages` map v3 carries, plus
    /// the legacy `dependencies` tree, which fuzi ignores.
    V2,
    /// `lockfileVersion: 3` — npm 9+'s default.
    V3,
    /// No `lockfileVersion` field.
    Missing,
    /// Any other version (1, or one newer than fuzi knows).
    Unsupported(u32),
}

impl LockfileVersion {
    /// Classify a raw `lockfileVersion` value (absent encoded as `None`).
    #[must_use]
    pub const fn from_raw(version: Option<u32>) -> Self {
        match version {
            Some(2) => Self::V2,
            Some(3) => Self::V3,
            Some(n) => Self::Unsupported(n),
            None => Self::Missing,
        }
    }
}

/// Read, parse, and version-gate `<dir>/package-lock.json`.
///
/// # Errors
///
/// Returns `FuziError::MissingInput` if there is no lockfile, `FuziError::Io`
/// if it cannot be read (not a regular file, or over the read cap — see
/// `read_project_file`), or `FuziError::Lockfile` if the JSON is invalid or
/// misshapen, the `lockfileVersion` is not 2 or 3, or the `packages` map is
/// absent.
pub fn read_lockfile(dir: &Path) -> Result<RawLockfile, FuziError> {
    let text = read_project_file(dir, ProjectFile::Lockfile)?;
    parse_lockfile(&text)
}

/// Parse + version-gate already-read lockfile text (the pure half of
/// `read_lockfile`, exposed for tests).
///
/// # Errors
///
/// Returns `FuziError::Lockfile` if the JSON is invalid or misshapen, the
/// `lockfileVersion` is not 2 or 3, or the `packages` map is absent.
pub fn parse_lockfile(text: &str) -> Result<RawLockfile, FuziError> {
    let doc: LockfileDocument = serde_json::from_str(text).map_err(|e| FuziError::Lockfile {
        // A data error is valid JSON holding a value of the wrong type (a
        // string `lockfileVersion`, a numeric `os`) — say so, rather than
        // calling well-formed JSON invalid.
        message: if e.is_data() {
            format!(
                "package-lock.json has a field of an unexpected type: {e} — regenerate the lockfile (npm install)"
            )
        } else {
            format!("package-lock.json is not valid JSON: {e}")
        },
    })?;
    match LockfileVersion::from_raw(doc.lockfile_version) {
        LockfileVersion::V2 | LockfileVersion::V3 => Ok(()),
        LockfileVersion::Unsupported(1) => Err(FuziError::Lockfile {
            message: "lockfileVersion 1 is unsupported (it has no packages map) — regenerate with npm 9+, or npm install --lockfile-version 3".to_string(),
        }),
        LockfileVersion::Missing => Err(FuziError::Lockfile {
            message: "missing lockfileVersion — fuzi reads lockfileVersion 2 or 3; regenerate the lockfile (npm install)".to_string(),
        }),
        LockfileVersion::Unsupported(n) => Err(FuziError::Lockfile {
            message: format!(
                "unsupported lockfileVersion {n} — fuzi reads lockfileVersion 2 or 3"
            ),
        }),
    }?;
    let Some(packages) = doc.packages else {
        return Err(FuziError::Lockfile {
            message: "package-lock.json has no packages map — regenerate with npm 9+, or npm install --lockfile-version 3".to_string(),
        });
    };
    Ok(RawLockfile {
        lockfile_version: doc.lockfile_version,
        name: doc.name,
        packages,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_3_parses() {
        let raw = parse_lockfile(r#"{"lockfileVersion":3,"packages":{}}"#).unwrap();
        assert_eq!(raw.lockfile_version, Some(3));
    }

    /// The shape npm 7/8 writes: the `packages` map plus the legacy v1
    /// `dependencies` tree and `requires`. The map is read; the rest is ignored.
    #[test]
    fn version_2_reads_its_packages_map() {
        let raw = parse_lockfile(
            r#"{"lockfileVersion":2,"requires":true,
                "packages":{"":{"name":"p"},"node_modules/a":{"version":"1.0.0"}},
                "dependencies":{"a":{"version":"1.0.0","resolved":"https://r/a.tgz"}}}"#,
        )
        .unwrap();
        assert_eq!(raw.lockfile_version, Some(2));
        assert_eq!(
            raw.packages.keys().collect::<Vec<_>>(),
            vec!["", "node_modules/a"]
        );
    }

    #[test]
    fn version_1_rejected_with_regenerate_hint() {
        let err = parse_lockfile(r#"{"lockfileVersion":1}"#).unwrap_err();
        match err {
            FuziError::Lockfile { message } => {
                assert!(message.contains("npm 9+"), "{message}");
                assert!(message.contains("--lockfile-version 3"), "{message}");
            }
            other => panic!("expected Lockfile, got {other:?}"),
        }
    }

    #[test]
    fn missing_version_rejected() {
        let err = parse_lockfile(r#"{"packages":{}}"#).unwrap_err();
        match err {
            FuziError::Lockfile { message } => {
                assert!(message.contains("missing lockfileVersion"), "{message}");
                assert!(message.contains("2 or 3"), "{message}");
                assert!(message.contains("npm install"), "{message}");
            }
            other => panic!("expected Lockfile, got {other:?}"),
        }
    }

    #[test]
    fn future_version_rejected() {
        let err = parse_lockfile(r#"{"lockfileVersion":4}"#).unwrap_err();
        match err {
            FuziError::Lockfile { message } => {
                assert!(message.contains("lockfileVersion 4"), "{message}");
                assert!(message.contains("2 or 3"), "{message}");
            }
            other => panic!("expected Lockfile, got {other:?}"),
        }
    }

    /// npm rebuilds the tree from the legacy section when `packages` is absent;
    /// fuzi has no legacy reader, so the absence refuses rather than parsing as
    /// an empty tree that installs nothing.
    #[test]
    fn version_2_or_3_without_packages_map_rejected() {
        for text in [
            r#"{"lockfileVersion":2,"dependencies":{"a":{"version":"1.0.0"}}}"#,
            r#"{"lockfileVersion":3}"#,
        ] {
            match parse_lockfile(text).unwrap_err() {
                FuziError::Lockfile { message } => {
                    assert!(message.contains("no packages map"), "{message}");
                    assert!(message.contains("--lockfile-version 3"), "{message}");
                }
                other => panic!("expected Lockfile, got {other:?}"),
            }
        }
    }

    /// An empty map is a real (empty) tree, not an absent one.
    #[test]
    fn empty_packages_map_parses() {
        let raw = parse_lockfile(r#"{"lockfileVersion":2,"packages":{}}"#).unwrap();
        assert!(raw.packages.is_empty());
    }

    #[test]
    fn invalid_json_is_lockfile_error() {
        let err = parse_lockfile("{not json").unwrap_err();
        match err {
            FuziError::Lockfile { message } => {
                assert!(message.contains("not valid JSON"), "{message}");
            }
            other => panic!("expected Lockfile, got {other:?}"),
        }
    }

    #[test]
    fn wrong_typed_field_is_a_shape_error_not_invalid_json() {
        for text in [
            r#"{"lockfileVersion":"3","packages":{}}"#,
            r#"{"lockfileVersion":3,"packages":{"node_modules/a":{"cpu":7}}}"#,
        ] {
            match parse_lockfile(text).unwrap_err() {
                FuziError::Lockfile { message } => {
                    assert!(message.contains("unexpected type"), "{message}");
                    assert!(!message.contains("not valid JSON"), "{message}");
                }
                other => panic!("expected Lockfile, got {other:?}"),
            }
        }
    }

    #[test]
    fn string_form_platform_axis_parses() {
        let raw = parse_lockfile(
            r#"{"lockfileVersion":3,"packages":{"node_modules/fsevents":{"os":"darwin"}}}"#,
        )
        .unwrap();
        assert_eq!(raw.packages["node_modules/fsevents"].os, vec!["darwin"]);
    }

    #[test]
    fn missing_file_is_missing_input() {
        let dir = tempfile::tempdir().unwrap();
        let err = read_lockfile(dir.path()).unwrap_err();
        assert!(
            matches!(
                err,
                FuziError::MissingInput {
                    file: ProjectFile::Lockfile,
                    ..
                }
            ),
            "{err:?}"
        );
        assert_eq!(err.exit_code(), 66);
    }

    #[test]
    fn unreadable_file_stays_io() {
        // A lockfile that exists but cannot be read as a file is an IO failure,
        // not a missing input.
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("package-lock.json")).unwrap();
        let err = read_lockfile(dir.path()).unwrap_err();
        assert!(matches!(err, FuziError::Io { .. }), "{err:?}");
    }

    /// The version classifier directly: 2 and 3 are read, an absent version is
    /// its own `Missing` (no sentinel), and everything else is `Unsupported(n)`
    /// — including a literal 0.
    #[test]
    fn lockfile_version_from_raw_maps() {
        assert_eq!(LockfileVersion::from_raw(Some(2)), LockfileVersion::V2);
        assert_eq!(LockfileVersion::from_raw(Some(3)), LockfileVersion::V3);
        assert_eq!(
            LockfileVersion::from_raw(Some(1)),
            LockfileVersion::Unsupported(1)
        );
        assert_eq!(
            LockfileVersion::from_raw(Some(0)),
            LockfileVersion::Unsupported(0)
        );
        assert_eq!(
            LockfileVersion::from_raw(Some(99)),
            LockfileVersion::Unsupported(99)
        );
        assert_eq!(LockfileVersion::from_raw(None), LockfileVersion::Missing);
    }
}
