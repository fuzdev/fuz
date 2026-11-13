//! CLI error types

use fuz_artifact::ArtifactError;
use fuz_home::FuzHomeError;
use fuz_sys::cli::EXIT_USAGE;
use std::borrow::Cow;
use std::path::PathBuf;
use thiserror::Error;

use crate::bootstrap::BootstrapError;
use crate::release::ReleaseCommandError;

/// Errors that can occur during CLI operations
#[derive(Debug, Error)]
pub enum CliError {
    /// `~/.fuz` operation failed
    #[error(transparent)]
    FuzHome(#[from] FuzHomeError),

    /// Artifact operation failed
    #[error(transparent)]
    Artifact(#[from] ArtifactError),

    /// Daemon client error (e.g. `fuz workload observe` over the UDS).
    #[error(transparent)]
    Client(#[from] fuz_client::ClientError),

    /// Bootstrap command error
    #[error(transparent)]
    Bootstrap(#[from] BootstrapError),

    /// Release command error
    #[error(transparent)]
    ReleaseCommand(#[from] ReleaseCommandError),

    /// Failed to create directory
    #[error("failed to create directory {path}")]
    CreateDirFailed {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// JSON serialization failed
    #[error("failed to serialize JSON")]
    Json(#[from] serde_json::Error),

    /// Source repo not found
    #[error("source repo not found")]
    SourceRepoNotFound { searched: Vec<String> },

    /// Invalid source repo
    #[error("invalid source repo at {path}: {reason}")]
    InvalidSourceRepo { path: PathBuf, reason: &'static str },

    /// The release build behind `fuz artifact build` (or its `--verify`
    /// rebuild) failed, reported no `fuz`, or built one for another target.
    #[error(transparent)]
    CargoBuild(#[from] fuz_artifact::CargoBuildError),

    /// Could not create the private target directory for `--verify`'s rebuild
    #[error("failed to create the verify rebuild's target directory")]
    VerifyTargetDir {
        #[source]
        source: std::io::Error,
    },

    /// No current artifact
    #[error("no current artifact (run 'fuz artifact build' first)")]
    NoCurrentArtifact,

    /// Integrity check failed
    #[error("artifact {hash} failed integrity check")]
    IntegrityCheckFailed { hash: String },

    /// `fuz workload observe` was given a domain that doesn't exist.
    #[error("unknown observe domain '{domain}'")]
    UnknownObserverDomain { domain: String },

    /// An invalid flag combination the caller must fix (e.g. `--json` without
    /// `--check`). Exit code 2 (needs-action), like a usage error.
    #[error("{0}")]
    InvalidUsage(&'static str),

    /// Not an error: a read-only `--check` determined an update is available or
    /// required. The check command already printed its own report (human or
    /// `--json`); this only carries the process exit code (10) that signals
    /// "update available" to scripts/agents. `report()` prints nothing extra
    /// for it.
    #[error("update available")]
    UpdateAvailable,
}

impl CliError {
    /// Exit code for this error (for `ExitCode::from`).
    ///
    /// fuz is agent-first, so the operationally-distinct artifact failures get
    /// sysexits codes a script/agent can branch on (matching `fuzi`'s taxonomy)
    /// rather than collapsing to a bare `1`: a held lock is transient (retry), a
    /// disk-full is "can't create", and an integrity mismatch is bad data.
    ///
    /// A fuz home that cannot be used as configured is `2` (the caller must
    /// change `HOME`, `FUZ_HOME`, or the home's mode) on every path that
    /// carries the home layer's error: directly, through the artifact store,
    /// the daemon client, or the release chain.
    pub const fn exit_code(&self) -> u8 {
        match self {
            // Release command errors have their own exit codes
            Self::ReleaseCommand(e) => e.exit_code(),
            Self::FuzHome(e) if e.is_unusable_home() => EXIT_USAGE,
            Self::Artifact(e) if e.is_unusable_home() => EXIT_USAGE,
            Self::Client(e) if e.is_unusable_home() => EXIT_USAGE,
            // Lock held by another fuz op — retrying later may succeed.
            Self::Artifact(ArtifactError::InProgress { .. }) => 75, // EX_TEMPFAIL
            // Out of disk space while creating the artifact.
            Self::Artifact(ArtifactError::InsufficientSpace { .. }) => 73, // EX_CANTCREAT
            // Corrupted/tampered artifact bytes (here or in `fuz artifact verify`),
            // including a store entry or a file inside one that is a symlink
            // where fuz wrote a real directory or file.
            Self::Artifact(
                ArtifactError::IntegrityFailed { .. }
                | ArtifactError::BinaryIntegrityFailed { .. }
                | ArtifactError::StoreEntryNotDir { .. }
                | ArtifactError::CurrentNotStoreLink { .. }
                | ArtifactError::NotRegularFile(_),
            )
            | Self::IntegrityCheckFailed { .. } => 65, // EX_DATAERR
            // Bad invocation the caller must fix (needs-action).
            Self::InvalidUsage(_) => EXIT_USAGE,
            // Read-only `--check` found a newer version — a status signal, not a
            // failure. Reserved code the caller/agent branches on.
            Self::UpdateAvailable => 10,
            // All other errors
            _ => 1,
        }
    }

    /// Get hint message if available.
    ///
    /// Artifact hints are single-sourced in `ArtifactError::hint()` and the
    /// release chain in `ReleaseError::hint()` — this just delegates to them;
    /// only the `fuz`-CLI-native variants carry their own hint here.
    pub fn hint(&self) -> Option<Cow<'static, str>> {
        match self {
            Self::FuzHome(e) => e.hint().map(Cow::Borrowed),
            Self::Artifact(e) => e.hint(),
            Self::ReleaseCommand(e) => e.hint(),
            // Surface the daemon-client hint (e.g. "fuzd start" when fuzd
            // isn't listening) so `fuz workload observe` degrades with an action.
            Self::Client(e) => e.hint().map(Cow::Borrowed),
            Self::SourceRepoNotFound { searched } => Some(Cow::Owned(format!(
                "set {} or clone to ~/{}\nsearched: {}",
                crate::build::REPO_ENV_VAR,
                crate::build::DEFAULT_REPO_PATH,
                searched.join(", ")
            ))),
            Self::InvalidSourceRepo { .. } => Some(Cow::Borrowed(
                "ensure the path points to the fuz repository",
            )),
            Self::CargoBuild(e) => e.hint().map(Cow::Borrowed),
            Self::VerifyTargetDir { .. } => Some(Cow::Borrowed(
                "check that the temp directory ($TMPDIR, default /tmp) exists and is writable",
            )),
            Self::NoCurrentArtifact => Some(Cow::Borrowed(
                "run 'fuz artifact build' to create and install an artifact",
            )),
            Self::IntegrityCheckFailed { .. } => Some(Cow::Borrowed(
                "rebuild with 'fuz artifact build' or use a different artifact",
            )),
            Self::UnknownObserverDomain { .. } => Some(Cow::Borrowed(
                "available domains: process, network, services",
            )),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fuz_artifact::ArtifactError;
    use fuz_release::StorageError;

    /// The agent-facing sysexits dialect: each operationally-distinct category
    /// maps to its own code so a script can branch, instead of collapsing to 1.
    #[test]
    fn exit_code_maps_each_category_to_its_sysexits_code() {
        let io = || std::io::Error::other("x");
        // lock held by another fuz op → EX_TEMPFAIL (retry may succeed)
        assert_eq!(
            CliError::Artifact(ArtifactError::InProgress { pid: None }).exit_code(),
            75
        );
        // out of disk → EX_CANTCREAT
        assert_eq!(
            CliError::Artifact(ArtifactError::InsufficientSpace {
                path: PathBuf::from("/x"),
                source: io(),
            })
            .exit_code(),
            73
        );
        // corrupted/tampered bytes → EX_DATAERR, on both the Artifact and the
        // CLI-native integrity paths
        assert_eq!(
            CliError::Artifact(ArtifactError::IntegrityFailed {
                path: PathBuf::from("/x"),
                expected: "a".to_string(),
                actual: "b".to_string(),
            })
            .exit_code(),
            65
        );
        assert_eq!(
            CliError::IntegrityCheckFailed {
                hash: "v1-abc".to_string()
            }
            .exit_code(),
            65
        );
        // a store entry or a file inside one that is not what fuz wrote is the
        // same bad-data class
        assert_eq!(
            CliError::Artifact(ArtifactError::StoreEntryNotDir {
                path: PathBuf::from("/x"),
                kind: fuz_sys::fs::NonDirKind::Symlink,
            })
            .exit_code(),
            65
        );
        assert_eq!(
            CliError::Artifact(ArtifactError::NotRegularFile(PathBuf::from("/x"))).exit_code(),
            65
        );
        assert_eq!(
            CliError::Artifact(ArtifactError::CurrentNotStoreLink {
                path: PathBuf::from("/x"),
                problem: fuz_artifact::CurrentLinkProblem::NotASymlink,
            })
            .exit_code(),
            65
        );
        // everything else → 1
        assert_eq!(CliError::NoCurrentArtifact.exit_code(), 1);
        assert_eq!(
            CliError::UnknownObserverDomain {
                domain: "bogus".to_string()
            }
            .exit_code(),
            1
        );
    }

    /// Release-command errors map both the release-op and storage/RPC failures
    /// to exit `1` (a malformed `--storage` URI, a missing artifact, a transfer
    /// error — all operational, none a distinct usage-config category).
    #[test]
    fn exit_code_delegates_to_release_command_dialect() {
        let storage = ReleaseCommandError::Storage(StorageError::InvalidConfig {
            message: "bad uri".to_string(),
        });
        assert_eq!(CliError::ReleaseCommand(storage).exit_code(), 1);
        // A local `--storage` that is not there is the same storage class.
        let missing = CliError::ReleaseCommand(ReleaseCommandError::StorageNotDir {
            location: "/no/such/store".to_string(),
        });
        assert_eq!(missing.exit_code(), 1);
        assert_eq!(
            missing.to_string(),
            "--storage is not an existing directory: /no/such/store"
        );
        assert!(
            missing
                .hint()
                .is_some_and(|hint| hint.contains("never creates one"))
        );

        // The store-shape refusals keep their bad-data code through the release
        // wrapper too (`fuz tool verify`, `fuz tool install`, `fuz self upgrade`),
        // matching `fuz artifact verify` / `use`.
        let release_artifact = |error: ArtifactError| {
            CliError::ReleaseCommand(ReleaseCommandError::Release(
                fuz_release::ReleaseError::Artifact(error),
            ))
            .exit_code()
        };
        assert_eq!(
            release_artifact(ArtifactError::StoreEntryNotDir {
                path: PathBuf::from("/x"),
                kind: fuz_sys::fs::NonDirKind::File,
            }),
            65
        );
        assert_eq!(
            release_artifact(ArtifactError::NotRegularFile(PathBuf::from("/x"))),
            65
        );
        assert_eq!(
            release_artifact(ArtifactError::CurrentNotStoreLink {
                path: PathBuf::from("/x"),
                problem: fuz_artifact::CurrentLinkProblem::OutsideStore {
                    target: PathBuf::from("/elsewhere"),
                },
            }),
            65
        );
    }

    /// The release log check's one soft failure is `EX_TEMPFAIL`, like a held
    /// lock: nothing refused the release, and a retry may confirm it. A refusal
    /// that is a security violation (revoked, missing, contradicted) is
    /// `EX_DATAERR`, so a script can't retry its way past a revocation; the
    /// benign refusals (an unusable cache, an oversized head) stay on `1`. A
    /// configuration error is `2`.
    #[test]
    fn exit_code_separates_an_unconfirmed_release_from_a_refused_one() {
        use fuz_release::{
            CacheProblem, LogConfigError, LogContradiction, PinnedBy, ReleaseError,
            ReleaseLogError, TargetField, UnreachableOrigin,
        };

        let code = |error: ReleaseLogError| {
            CliError::ReleaseCommand(ReleaseCommandError::Release(ReleaseError::ReleaseLog(
                error,
            )))
            .exit_code()
        };
        let (name, version, target) = (
            "fuz".to_string(),
            "0.3.0".to_string(),
            "x86_64-unknown-linux-gnu".to_string(),
        );

        assert_eq!(
            code(ReleaseLogError::Unconfirmed {
                name: name.clone(),
                version: version.clone(),
                target: target.clone(),
                witnesses: vec![UnreachableOrigin {
                    origin: "https://log.example.com".to_string(),
                    reason: "HTTPS: path not found: head.json".to_string(),
                }],
            }),
            75
        );

        let violations = [
            ReleaseLogError::Revoked {
                name: name.clone(),
                version: version.clone(),
            },
            ReleaseLogError::RowMissing {
                name: name.clone(),
                version: version.clone(),
                target: target.clone(),
                pinned_by: PinnedBy::LocalBinary,
            },
            LogContradiction::HashMismatch {
                name,
                version,
                target,
                field: TargetField::ContentHash,
                pinned_by: PinnedBy::SignedManifest,
            }
            .into(),
        ];
        for violation in violations {
            let description = violation.to_string();
            assert_eq!(code(violation), 65, "{description}");
        }

        let refusals = [
            ReleaseLogError::CacheUnusable {
                path: PathBuf::from("/x/state/release_log/head.json"),
                problem: CacheProblem::Write(std::io::Error::other("x")),
            },
            ReleaseLogError::WitnessHead {
                origin: "https://log.example.com".to_string(),
                source: Box::new(ReleaseLogError::TooLarge(u64::MAX)),
            },
        ];
        for refusal in refusals {
            let description = refusal.to_string();
            assert_eq!(code(refusal), 1, "{description}");
        }

        // A configuration the check cannot run under is the caller's to fix.
        let storage_error = || StorageError::InvalidConfig {
            message: "x".to_string(),
        };
        let configuration = [
            LogConfigError::InvalidSwitch {
                value: "OFF".to_string(),
            },
            LogConfigError::InvalidOrigin {
                position: 1,
                refusal: storage_error(),
            },
            LogConfigError::OriginUnusable {
                origin: "https://log.example.com".to_string(),
                source: storage_error(),
            },
        ];
        for error in configuration {
            let description = error.to_string();
            assert_eq!(code(error.into()), 2, "{description}");
        }
    }

    /// A fetch-path security violation shares `EX_DATAERR` with the local
    /// integrity failures — one "do not trust these bytes" class — never the
    /// `1` a retryable storage failure has. The world-writable home the
    /// classifier also counts read no untrusted bytes and is the caller's
    /// `chmod` to fix, so it is `2`.
    #[test]
    fn exit_code_gives_a_security_violation_the_bad_data_code() {
        use fuz_crypto::{ContentHash, VerifyError};
        use fuz_release::{ManifestError, ReleaseError, TarballError};

        let code = |error: ReleaseError| {
            CliError::ReleaseCommand(ReleaseCommandError::Release(error)).exit_code()
        };

        assert_eq!(
            code(ManifestError::Signature(VerifyError::InvalidSignature).into()),
            65
        );
        assert_eq!(
            code(
                TarballError::HashMismatch {
                    expected: ContentHash::blake3(b"published"),
                    actual: ContentHash::blake3(b"served"),
                }
                .into()
            ),
            65
        );
        // Bytes that do not parse are a bad tarball, not an I/O failure: the
        // archive reached extraction only after its digest matched.
        assert_eq!(
            code(
                TarballError::Malformed {
                    context: "reading entry",
                    error: std::io::Error::new(std::io::ErrorKind::InvalidData, "bad header"),
                }
                .into()
            ),
            65
        );
        // A tampered cache hit is `65` whichever layer catches it: the meta
        // disagreeing with the manifest, or the binary with its meta.
        assert_eq!(
            code(
                TarballError::BinaryHashMismatch {
                    name: "fuz".to_string(),
                    expected: ContentHash::blake3(b"published"),
                    actual: ContentHash::blake3(b"edited"),
                }
                .into()
            ),
            65
        );
        assert_eq!(
            code(ReleaseError::Artifact(
                ArtifactError::BinaryIntegrityFailed {
                    binary: "fuz".to_string(),
                    expected: ContentHash::blake3(b"meta"),
                    actual: ContentHash::blake3(b"edited"),
                }
            )),
            65
        );

        let insecure = ReleaseError::FuzHome(FuzHomeError::InsecureHome {
            path: PathBuf::from("/x/.fuz"),
            mode: 0o777,
        });
        assert!(insecure.is_security_violation());
        assert_eq!(code(insecure), 2);
        assert_eq!(
            code(
                ManifestError::Downgrade {
                    current: "0.4.0".to_string(),
                    target: "0.3.2".to_string(),
                }
                .into()
            ),
            1
        );
    }

    /// A fuz home that cannot be used as configured exits `2` however it is
    /// reached — directly, through the artifact store, the daemon client, or
    /// the release chain (bare or through the store) — and a home-layer
    /// failure while using a usable home exits `1` on each of those paths.
    #[test]
    fn exit_code_gives_an_unusable_home_the_usage_code_on_every_path() {
        use fuz_release::ReleaseError;

        let paths = |home: fn() -> FuzHomeError| -> [CliError; 5] {
            [
                CliError::FuzHome(home()),
                CliError::Artifact(ArtifactError::FuzHome(home())),
                CliError::Client(fuz_client::ClientError::FuzHome(home())),
                CliError::ReleaseCommand(ReleaseCommandError::Release(ReleaseError::FuzHome(
                    home(),
                ))),
                CliError::ReleaseCommand(ReleaseCommandError::Release(ReleaseError::Artifact(
                    ArtifactError::FuzHome(home()),
                ))),
            ]
        };
        let unusable: [fn() -> FuzHomeError; 5] = [
            || FuzHomeError::HomeDir(fuz_sys::HomeDirError::NotFound),
            || FuzHomeError::HomeDir(fuz_sys::HomeDirError::Empty),
            || {
                FuzHomeError::HomeDir(fuz_sys::HomeDirError::Relative {
                    path: PathBuf::from("h"),
                })
            },
            || FuzHomeError::RelativeFuzHome {
                path: PathBuf::from("rel"),
            },
            || FuzHomeError::InsecureHome {
                path: PathBuf::from("/x/.fuz"),
                mode: 0o777,
            },
        ];
        for home in unusable {
            for error in paths(home) {
                assert_eq!(error.exit_code(), EXIT_USAGE, "{error:?}");
            }
        }
        let usable: [fn() -> FuzHomeError; 2] = [
            || FuzHomeError::CreateDirFailed {
                path: PathBuf::from("/x/.fuz/bin"),
                source: std::io::Error::other("x"),
            },
            || FuzHomeError::DaemonInfoInvalidPid(0),
        ];
        for home in usable {
            for error in paths(home) {
                assert_eq!(error.exit_code(), 1, "{error:?}");
            }
        }
    }

    #[test]
    fn hint_surfaces_native_and_delegated_advice() {
        assert!(CliError::NoCurrentArtifact.hint().is_some());
        assert!(
            CliError::UnknownObserverDomain {
                domain: "x".to_string()
            }
            .hint()
            .is_some()
        );
        assert!(
            CliError::IntegrityCheckFailed {
                hash: "v1-x".to_string()
            }
            .hint()
            .is_some()
        );
        // cargo never ran, so the hint must not point at cargo output.
        let hint = CliError::VerifyTargetDir {
            source: std::io::Error::other("x"),
        }
        .hint()
        .unwrap();
        assert!(hint.contains("TMPDIR") && !hint.contains("cargo"));
        // SourceRepoNotFound interpolates the searched list into an Owned hint.
        let hint = CliError::SourceRepoNotFound {
            searched: vec!["repo-a".to_string(), "repo-b".to_string()],
        }
        .hint();
        assert!(
            matches!(hint, Some(Cow::Owned(ref s)) if s.contains("repo-a, repo-b")),
            "searched list interpolated: {hint:?}"
        );
    }
}
