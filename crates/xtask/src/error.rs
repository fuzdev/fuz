//! Xtask error types

use fuz_artifact::ArtifactError;
use fuz_sys::cli::EXIT_USAGE;
use std::borrow::Cow;
use std::path::PathBuf;
use thiserror::Error;

/// Errors that can occur during xtask operations
#[derive(Debug, Error)]
pub enum XtaskError {
    /// `~/.fuz` operation failed
    #[error(transparent)]
    FuzHome(#[from] fuz_home::FuzHomeError),

    /// Artifact operation failed
    #[error(transparent)]
    Artifact(#[from] ArtifactError),

    /// Failed to create directory
    #[error("failed to create directory")]
    CreateDir(#[source] std::io::Error),

    /// Not running from workspace root
    #[error("run this from the workspace root")]
    NotWorkspaceRoot,

    /// The release build behind `cargo xtask install` failed, reported a
    /// binary missing, or built one for another target than this host's.
    #[error(transparent)]
    CargoBuild(#[from] fuz_artifact::CargoBuildError),

    /// Failed to remove directory
    #[error("failed to remove {path}")]
    RemoveDir {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// Key management error
    #[error(transparent)]
    Key(#[from] crate::key::KeyCommandError),

    /// Bootstrap publish error
    #[error(transparent)]
    Publish(#[from] crate::publish::PublishError),
}

impl XtaskError {
    /// Exit code for this error (for `ExitCode::from`), in the default
    /// dialect: `2` for a fuz home that cannot be used as configured (the
    /// caller must change `HOME`, `FUZ_HOME`, or the home's mode before running
    /// again), on every path that carries the home layer's error; `1` for
    /// every other failure.
    pub const fn exit_code(&self) -> u8 {
        if self.is_unusable_home() {
            EXIT_USAGE
        } else {
            1
        }
    }

    /// Returns true if the fuz home cannot be used as configured, forwarded
    /// from whichever layer hit it: the home layer itself, the artifact store,
    /// a key command, or a publish.
    ///
    /// Exhaustive, so a new variant is classified where it is added.
    const fn is_unusable_home(&self) -> bool {
        match self {
            Self::FuzHome(e) => e.is_unusable_home(),
            Self::Artifact(e) => e.is_unusable_home(),
            Self::Key(e) => e.is_unusable_home(),
            Self::Publish(e) => e.is_unusable_home(),
            Self::CreateDir(_)
            | Self::NotWorkspaceRoot
            | Self::CargoBuild(_)
            | Self::RemoveDir { .. } => false,
        }
    }

    /// User-facing hint for how to fix the error, where the failing operation
    /// has one to give. Delegates to the home layer's own hints, the artifact
    /// store's, the release build's, the signing key loader's, the release chain's, the backfill's,
    /// the revoke's, and the storage backend's; the `--storage` and `--tool`
    /// refusals carry theirs here.
    pub fn hint(&self) -> Option<Cow<'static, str>> {
        match self {
            Self::FuzHome(e) => e.hint().map(Cow::Borrowed),
            Self::Artifact(e) => e.hint(),
            Self::CargoBuild(e) => e.hint().map(Cow::Borrowed),
            Self::Publish(crate::publish::PublishError::Storage(e)) => e.hint().map(Cow::Borrowed),
            Self::Key(crate::key::KeyCommandError::Key(e))
            | Self::Publish(crate::publish::PublishError::Key(e)) => e.hint().map(Cow::Borrowed),
            Self::Publish(crate::publish::PublishError::Release(e)) => e.hint(),
            Self::Publish(crate::publish::PublishError::Backfill(e)) => e.hint().map(Cow::Borrowed),
            Self::Publish(crate::publish::PublishError::Revoke(e)) => e.hint().map(Cow::Borrowed),
            Self::Publish(crate::publish::PublishError::StorageMissing { .. }) => {
                Some(Cow::Borrowed(
                    "Check the path: this command works on a store that is already there and \
                     never creates one (`cargo xtask publish` does)",
                ))
            }
            Self::Publish(crate::publish::PublishError::ToolNotFirstParty { .. }) => Some(
                Cow::Borrowed("prune works on the stream of a first-party tool; check the name"),
            ),
            Self::Publish(crate::publish::PublishError::StorageNotDir { .. }) => {
                Some(Cow::Borrowed(
                    "A local store is a directory: check the path, or move what is there",
                ))
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fuz_release::{LogWriteError, ReleaseError};

    #[test]
    fn publish_release_errors_carry_the_release_hint() {
        let release = || ReleaseError::from(LogWriteError::DetachedHead);
        let expected = release().hint();
        assert!(expected.is_some());
        let error = XtaskError::Publish(crate::publish::PublishError::Release(release()));
        assert_eq!(error.hint(), expected);
    }

    #[test]
    fn backfill_errors_carry_the_backfill_hint() {
        let backfill = || fuz_sign::BackfillError::HeadExists;
        let expected = backfill().hint();
        assert!(expected.is_some());
        let error = XtaskError::Publish(crate::publish::PublishError::Backfill(backfill()));
        assert_eq!(error.hint().as_deref(), expected);

        // A log write failure inside a backfill keeps the log write's hint.
        let log = || fuz_sign::BackfillError::Log(LogWriteError::DetachedHead);
        let error = XtaskError::Publish(crate::publish::PublishError::Backfill(log()));
        assert_eq!(error.hint().as_deref(), LogWriteError::DetachedHead.hint());
    }

    #[test]
    fn revoke_errors_carry_the_revoke_hint() {
        let revoke = || fuz_sign::RevokeError::NoHead;
        let expected = revoke().hint();
        assert!(expected.is_some());
        let error = XtaskError::Publish(crate::publish::PublishError::Revoke(revoke()));
        assert_eq!(error.hint().as_deref(), expected);
    }

    /// A signing key that cannot be loaded carries the loader's hint through
    /// both wrappers: `key info` / `export`'s on one side, `publish` /
    /// `release-log`'s on the other.
    #[test]
    fn signing_key_errors_carry_the_key_loader_hint() {
        use fuz_sys::secure_file::SecureFileError;
        let missing = || fuz_sign::KeyFileError::Read {
            path: PathBuf::from("/k"),
            source: SecureFileError::NotFound(PathBuf::from("/k")),
        };
        let expected = missing().hint();
        assert!(expected.is_some());
        for error in [
            XtaskError::Key(crate::key::KeyCommandError::Key(missing())),
            XtaskError::Publish(crate::publish::PublishError::Key(missing())),
        ] {
            assert_eq!(error.hint().as_deref(), expected);
        }

        // A malformed key file: the parser's own hint, through the loader.
        let malformed = || fuz_sign::KeyFileError::from(fuz_sign::KeyError::TrailingContent);
        let expected = fuz_sign::KeyError::TrailingContent.hint();
        assert!(expected.is_some());
        let error = XtaskError::Publish(crate::publish::PublishError::Key(malformed()));
        assert_eq!(error.hint().as_deref(), expected);
    }

    #[test]
    fn home_errors_carry_the_home_hint() {
        let relative = || fuz_home::FuzHomeError::RelativeFuzHome {
            path: PathBuf::from("relhome"),
        };
        let expected = relative().hint();
        assert!(expected.is_some());
        assert_eq!(XtaskError::FuzHome(relative()).hint().as_deref(), expected);
        // The default key location is under the home: the same hint.
        let error = XtaskError::Key(crate::key::KeyCommandError::Key(
            fuz_sign::KeyFileError::ConfigDir(relative()),
        ));
        assert_eq!(error.hint().as_deref(), expected);
    }

    /// A fuz home that cannot be used as configured exits 2 on every path to
    /// it; a home-layer failure while using a usable home, a key file that
    /// cannot be read, and a failure of xtask's own exit 1.
    #[test]
    fn an_unusable_home_exits_2_on_every_path() {
        use crate::key::KeyCommandError;
        use crate::publish::PublishError;
        use fuz_home::FuzHomeError;
        let homes: [fn() -> FuzHomeError; 2] = [
            || FuzHomeError::RelativeFuzHome {
                path: PathBuf::from("relhome"),
            },
            || FuzHomeError::InsecureHome {
                path: PathBuf::from("/x/.fuz"),
                mode: 0o777,
            },
        ];
        for home in homes {
            for error in [
                XtaskError::FuzHome(home()),
                XtaskError::Artifact(ArtifactError::FuzHome(home())),
                XtaskError::Key(KeyCommandError::Key(fuz_sign::KeyFileError::ConfigDir(
                    home(),
                ))),
                XtaskError::Publish(PublishError::Key(fuz_sign::KeyFileError::ConfigDir(home()))),
                XtaskError::Publish(PublishError::Release(ReleaseError::FuzHome(home()))),
                XtaskError::Publish(PublishError::Release(ReleaseError::Artifact(
                    ArtifactError::FuzHome(home()),
                ))),
            ] {
                assert_eq!(error.exit_code(), EXIT_USAGE, "{error:?}");
            }
        }
        for error in [
            XtaskError::FuzHome(FuzHomeError::DaemonInfoInvalidPid(0)),
            XtaskError::Key(KeyCommandError::Key(fuz_sign::KeyFileError::Read {
                path: PathBuf::from("/k"),
                source: fuz_sys::secure_file::SecureFileError::NotFound(PathBuf::from("/k")),
            })),
            XtaskError::NotWorkspaceRoot,
        ] {
            assert_eq!(error.exit_code(), 1, "{error:?}");
        }
    }

    /// `cargo xtask install` works on the artifact store: its errors keep the
    /// store's own hint, the owned one (a holder pid) included.
    #[test]
    fn artifact_errors_carry_the_artifact_hint() {
        let busy = || ArtifactError::InProgress { pid: Some(4242) };
        let expected = busy().hint();
        assert!(
            expected
                .as_deref()
                .is_some_and(|hint| hint.contains("4242"))
        );
        assert_eq!(XtaskError::Artifact(busy()).hint(), expected);
    }

    /// A storage error keeps the backend's hint, where the backend has one.
    #[test]
    fn storage_errors_carry_the_storage_hint() {
        use fuz_release::StorageError;
        let unsupported = || StorageError::Unsupported {
            backend: fuz_storage::StorageBackendKind::Https,
            operation: "upload",
        };
        let expected = unsupported().hint();
        assert!(expected.is_some());
        let error = XtaskError::Publish(crate::publish::PublishError::Storage(unsupported()));
        assert_eq!(error.hint().as_deref(), expected);

        // A `--storage` that does not parse has none to give.
        let malformed = StorageError::InvalidConfig {
            message: "unknown storage scheme".to_string(),
        };
        let error = XtaskError::Publish(crate::publish::PublishError::Storage(malformed));
        assert!(error.hint().is_none());
    }

    #[test]
    fn errors_outside_the_release_chain_carry_no_hint() {
        assert!(XtaskError::NotWorkspaceRoot.hint().is_none());
    }

    /// A failed or cross-target release build keeps the build's own hint.
    #[test]
    fn cargo_build_errors_carry_the_build_hint() {
        let missing = || fuz_artifact::CargoBuildError::MissingBinary {
            name: "fuzd".to_string(),
        };
        let expected = missing().hint();
        assert!(expected.is_some());
        assert_eq!(
            XtaskError::CargoBuild(missing()).hint().as_deref(),
            expected
        );
    }
}
