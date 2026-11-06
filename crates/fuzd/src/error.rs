//! Daemon startup errors

use fuz_daemon::DaemonError;
use fuz_home::FuzHomeError;
use fuzd_server::ServerError;
use thiserror::Error;

/// Errors that can occur running `fuzd` (daemon startup or a lifecycle
/// subcommand).
#[derive(Debug, Error)]
pub enum StartupError {
    /// `~/.fuz` directory resolution failed
    #[error(transparent)]
    FuzHome(#[from] FuzHomeError),

    /// Server failed to start
    #[error(transparent)]
    Server(#[from] ServerError),

    /// A lifecycle subcommand (`start`/`stop`/`restart`/`status`/`logs`) failed
    #[error(transparent)]
    Daemon(#[from] DaemonError),

    /// The async runtime could not be built (e.g. no threads to spare), so
    /// neither the daemon nor a lifecycle subcommand ran
    #[error("failed to start the async runtime")]
    Runtime(#[source] std::io::Error),
}

impl StartupError {
    /// Exit code for this error (for `ExitCode::from`).
    ///
    /// Another fuzd owning the socket path is
    /// [`fuz_daemon::EXIT_ALREADY_RUNNING`], the one code `fuzd start` reads
    /// off the child it spawned; every other startup failure is `1`.
    pub const fn exit_code(&self) -> u8 {
        match self {
            Self::Server(ServerError::AlreadyRunning { .. }) => fuz_daemon::EXIT_ALREADY_RUNNING,
            Self::FuzHome(_) | Self::Server(_) | Self::Runtime(_) => 1,
            Self::Daemon(e) => e.exit_code(),
        }
    }

    /// User-facing hint, printed after the `error:` line when present.
    ///
    /// The home layer's error carries its hint whichever form hit it — bare
    /// `fuzd` directly, a lifecycle subcommand through [`DaemonError`]. A
    /// lifecycle failure of the daemon's own has none.
    pub const fn hint(&self) -> Option<&'static str> {
        match self {
            Self::Server(e) => e.hint(),
            Self::FuzHome(e) | Self::Daemon(DaemonError::FuzHome(e)) => e.hint(),
            Self::Daemon(_) | Self::Runtime(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fuz_sys::cli::format_error_chain;
    use fuz_sys::file_lock::FileLockError;

    #[test]
    fn already_running_exits_with_the_code_fuzd_start_reads() {
        let held = StartupError::Server(ServerError::AlreadyRunning {
            socket_path: "/run/socket".into(),
            pid: Some(1),
        });
        assert_eq!(held.exit_code(), fuz_daemon::EXIT_ALREADY_RUNNING);
        let other = StartupError::Server(ServerError::Uid(std::io::Error::other("x")));
        assert_eq!(other.exit_code(), 1);
        let runtime = StartupError::Runtime(std::io::Error::other("x"));
        assert_eq!(runtime.exit_code(), 1);
    }

    /// The `error:` line follows a wrapped error's text with the causes it
    /// keeps as its source, through the transparent wrappers.
    #[test]
    fn the_error_line_appends_each_cause() {
        let runtime = StartupError::Runtime(std::io::Error::other("no threads"));
        assert_eq!(
            format_error_chain(&runtime),
            "failed to start the async runtime: no threads"
        );
        let write = StartupError::Daemon(DaemonError::FuzHome(FuzHomeError::WriteFailed {
            path: "/home/.fuz/run/daemon.json.tmp".into(),
            source: std::io::Error::other("file is a symlink"),
        }));
        assert_eq!(
            format_error_chain(&write),
            "failed to write /home/.fuz/run/daemon.json.tmp: file is a symlink"
        );
    }

    /// A cause the message already ends with is not printed twice, and an
    /// error with no source prints its text alone.
    #[test]
    fn the_error_line_skips_a_cause_already_printed() {
        let lock = StartupError::Server(ServerError::Lock {
            path: "/home/.fuz/run/socket.lock".into(),
            source: FileLockError::Io(std::io::Error::other("permission denied")),
        });
        assert_eq!(
            format_error_chain(&lock),
            "failed to lock /home/.fuz/run/socket.lock: file lock io error: permission denied"
        );
        let held = StartupError::Server(ServerError::AlreadyRunning {
            socket_path: "/run/socket".into(),
            pid: Some(1),
        });
        assert_eq!(format_error_chain(&held), held.to_string());
    }

    #[test]
    fn an_overlong_socket_path_carries_the_server_hint_and_exits_1() {
        let too_long = StartupError::Server(ServerError::SocketPathTooLong {
            path: "/long/run/socket".into(),
            len: 108,
            max: 107,
        });
        assert_eq!(too_long.exit_code(), 1);
        let hint = too_long.hint().expect("a hint");
        assert!(hint.contains("FUZ_HOME"), "{hint}");
        let other = StartupError::Server(ServerError::Uid(std::io::Error::other("x")));
        assert_eq!(other.hint(), None);
    }

    /// An unusable home carries the home layer's hint and exits 1.
    #[test]
    fn an_unusable_home_carries_the_home_hint() {
        let unusable = StartupError::FuzHome(FuzHomeError::HomeDir(fuz_sys::HomeDirError::Empty));
        assert_eq!(unusable.exit_code(), 1);
        let hint = unusable.hint().expect("a hint");
        assert!(hint.contains("HOME"), "{hint}");
    }

    /// A lifecycle subcommand that hit the home layer's error carries the hint
    /// bare `fuzd` gives for the same error, and exits 1; a lifecycle failure
    /// of the daemon's own carries none.
    #[test]
    fn a_lifecycle_home_failure_carries_the_home_hint() {
        for home_error in [
            FuzHomeError::HomeDir(fuz_sys::HomeDirError::Empty),
            FuzHomeError::RelativeFuzHome { path: "rel".into() },
        ] {
            let hint = home_error.hint().expect("the home error has a hint");
            let lifecycle = StartupError::Daemon(DaemonError::FuzHome(home_error));
            assert_eq!(lifecycle.hint(), Some(hint), "{lifecycle}");
            assert_eq!(lifecycle.exit_code(), 1);
        }
        let hintless =
            StartupError::Daemon(DaemonError::FuzHome(FuzHomeError::DaemonInfoInvalidPid(0)));
        assert_eq!(hintless.hint(), None, "a home error with no hint adds none");
        let own = StartupError::Daemon(DaemonError::SpawnDaemonFailed(std::io::Error::other("x")));
        assert_eq!(own.hint(), None);
    }
}
