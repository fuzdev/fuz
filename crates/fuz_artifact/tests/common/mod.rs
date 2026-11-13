//! Shared harness for the local artifact-store and tool-install integration
//! suites (`tests/round_trip.rs`, `tests/local_store.rs`, `tests/tool_install.rs`).
//!
//! Each `tests/*.rs` compiles as its own process, so the process-global
//! `FUZ_HOME` override (an `RwLock` in `fuz_home`, reached via the
//! `test_home_override` dev-dep feature) never contends across files. Within a
//! file, cargo runs `#[test]`s on parallel threads, so `SERIAL` serializes the
//! ones that share that single global.
#![expect(
    clippy::unwrap_used,
    reason = "test helpers outside `#[test]` fns panic on a failed setup or check"
)]

use std::os::unix::fs::PermissionsExt;
use std::sync::{Mutex, MutexGuard, PoisonError};

use fuz_home::set_fuz_home_override_for_testing;
use fuz_sys::SECURE_DIR_MODE;

/// The home override is a process global and cargo runs `#[test]`s on parallel
/// threads, so serialize the whole file. A lock poisoned by another test's
/// assertion panic is still usable — recover the guard.
static SERIAL: Mutex<()> = Mutex::new(());

/// A minimal `fuz` binary for the host target (the platform check accepts
/// it), padded past the size floor. `seed` lets a caller make the bytes (and
/// thus the content hash) distinct.
pub fn fake_fuz(seed: u8) -> Vec<u8> {
    fuz_artifact::platform::test_stubs::host(&[seed; 64])
}

/// The host's target triple, the one a build's inputs name.
#[allow(dead_code, reason = "each test binary uses only part of this module")]
pub fn host_triple() -> String {
    fuz_artifact::platform::test_stubs::host_target()
        .triple()
        .to_string()
}

/// Lock the serial guard and point `~/.fuz` at a fresh temp home for the test
/// body. The returned `TempDir` must stay alive for the duration of the test;
/// the guard is released (and the override left for the next test to overwrite)
/// on drop.
///
/// The mode is **set**, not inherited. `tempfile::tempdir()` creates at the std
/// default `0o777` masked by the process umask, so under a permissive runner
/// umask (`umask 000`, routine in containers) the home would arrive
/// world-writable and every install driven through it would refuse with
/// `InsecureHome` — a suite that passes or fails by whoever launched it. Pin it
/// at [`SECURE_DIR_MODE`] instead, the mode a real `ensure_fuz_home` creates;
/// a test that wants a different mode chmods after this call.
pub fn fresh_home() -> (tempfile::TempDir, MutexGuard<'static, ()>) {
    let guard = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let home = tempfile::tempdir().unwrap();
    std::fs::set_permissions(
        home.path(),
        std::fs::Permissions::from_mode(SECURE_DIR_MODE),
    )
    .unwrap();
    set_fuz_home_override_for_testing(home.path());
    (home, guard)
}
