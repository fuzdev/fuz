//! `testing_spine_stub` — test-only spine-stub binary entry point.
//!
//! **NEVER ship this in a release.** The binary wires
//! [`fuz_testing::TestingArgon2idHasher`] in place of
//! [`fuz_auth::Argon2idHasher`] so cross-process integration tests get
//! ~1-5 ms argon2 feedback instead of production's ~30-50 ms. Three
//! layered guardrails keep this from leaking into production:
//!
//! 1. The `testing_` prefix is enforced by `fuz_release`'s manifest
//!    filter (`is_test_binary_name`).
//! 2. `cargo xtask check-release` walks `cargo metadata` and asserts no
//!    production binary's package depends on `fuz_testing`. This crate is
//!    `publish = false` and has no production sibling, so nothing in the
//!    shippable tree reaches it.
//! 3. `TestingArgon2idHasher::new` logs `WARN: test-mode argon2 hasher
//!    active` at construction — a sentinel for log-scraping audits.
//!
//! Unlike `testing_zzz_server` and other consumers' test binaries, there is no
//! production sibling library: [`testing_spine_stub::run_app`] assembles
//! the spine directly because the stub mounts only the spine surface with
//! no domain on top. Default port 1177 (slots beside zzz's 1175/1176).
//!
//! The command line is strict: no arguments, or `--port <port>` (the
//! harness's form), serves; `--help` / `-h` prints usage. Anything else exits
//! `2` with usage on stderr before the env is read. A failed start prints its
//! error chain and a hint, and exits `2` when the operator must fix
//! configuration, `1` otherwise.

use std::process::ExitCode;

use testing_spine_stub::{
    DEFAULT_ADDR, RunAppOptions, StubInvocation, USAGE, parse_stub_args, run_app,
};

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let port = match parse_stub_args(&args) {
        Ok(StubInvocation::Help) => {
            print!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Ok(StubInvocation::Serve { port }) => port,
        Err(message) => {
            eprint!("error: {message}\n\n{USAGE}");
            return ExitCode::from(fuz_sys::cli::EXIT_USAGE);
        }
    };

    // Non-blocking stdout logging so a stalled stdout consumer can't starve
    // the async runtime. `_log_guard` must stay live for the whole process
    // (it flushes + stops the writer on drop); returning `ExitCode` lets it
    // flush on the error path too.
    let _log_guard = fuz_sys::logging::init_non_blocking_stdout("info,testing_spine_stub=info");

    // Always-visible startup sentinel — survives any RUST_LOG filter that
    // would suppress `info!`. The sister `WARN: test-mode argon2 hasher
    // active` line is emitted by `TestingArgon2idHasher::new` itself, which
    // `fuz_testing::testing_backend_options` builds.
    eprintln!("testing_spine_stub starting (test-mode argon2 active)");

    match run_app(RunAppOptions {
        default_addr: DEFAULT_ADDR,
        port,
        drain_timeout: fuz_http::DEFAULT_DRAIN_TIMEOUT,
    })
    .await
    {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => fuz_sys::cli::report_failure(&e, e.hint(), e.exit_code()),
    }
}
