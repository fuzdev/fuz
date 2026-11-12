//! Generic OS/system primitives for the fuz workspace.
//!
//! The reusable, home-agnostic leaf: filesystem helpers, advisory file locks,
//! TOCTOU-safe secure-file ops, pid liveness and signal sending, randomness,
//! RFC 3339 timestamps, env parsing, CLI error rendering and argument parsing,
//! the escaping of untrusted text for a message (`text`), and the user's home
//! directory (`home_dir`, the one `$HOME` lookup) with its `~` renderings.
//! Nothing here knows about `~/.fuz` — those conventions live
//! in `fuz_home`, which depends on this crate. The HTTP spine (`fuz_http` and
//! everything above it) can depend on `fuz_sys` without inheriting fuz's home
//! layout.

#[cfg(feature = "capture")]
pub mod capture;
pub mod cli;
pub mod env;
pub mod file_lock;
pub mod fractional_index;
pub mod fs;
pub mod limits;
#[cfg(feature = "logging")]
pub mod logging;
mod path;
#[cfg(feature = "periodic")]
pub mod periodic;
mod pid;
pub mod rand;
pub mod secure_file;
#[cfg(feature = "signal")]
pub mod signal;
pub mod text;
mod time;
#[cfg(feature = "tls")]
pub mod tls;

pub use path::{
    HomeDirError, collapse_tilde, expand_tilde, expand_tilde_checked, home_dir, strip_home,
};
pub use pid::{Signal, is_pid_alive, send_signal};
pub use time::{is_rfc3339_utc_seconds, rfc3339_now};

//
// File permission constants (Unix)
//

/// Secure directory mode: owner only (rwx------)
pub const SECURE_DIR_MODE: u32 = 0o700;

/// Secure file mode: owner only (rw-------)
pub const SECURE_FILE_MODE: u32 = 0o600;

/// Executable file mode: owner rwx, group/other rx (rwxr-xr-x)
pub const EXECUTABLE_FILE_MODE: u32 = 0o755;
