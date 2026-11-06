//! Release builds through cargo, taking each binary's path from cargo itself.
//!
//! `fuz artifact build` and `cargo xtask install` run `cargo build --release`
//! and then package what it built. Where cargo writes a binary depends on more
//! than the workspace: `CARGO_TARGET_DIR` / `build.target-dir` move the target
//! directory, and `CARGO_BUILD_TARGET` / `build.target` (in any cargo config
//! file) add a `<triple>/` level. A guessed `target/release/<bin>` packages a
//! stale binary — or none — whenever one of those is set.
//!
//! So nothing guesses: [`cargo_build_release`] runs the build with
//! `--message-format=json-render-diagnostics` (cargo still renders its progress
//! and diagnostics on stderr; stdout carries one JSON message per line) and
//! takes the binary's path from the `executable` of its `compiler-artifact`
//! message. An up-to-date (`"fresh": true`) artifact reports its `executable`
//! too, so a no-op rebuild still names its binary.
//!
//! One package per cargo run, by construction: cargo unifies features across
//! every package one run builds, so `-p fuz -p fuzd` links a `fuz` with
//! fuzd's features of their shared deps — a different binary from the
//! `-p fuz` build its artifact's input hash stands for.
//!
//! A build for another target is not refused up front: its binary is where
//! cargo says, and [`check_built_for`] holds its header to the host's target
//! before it is packaged or installed.

use crate::platform::{
    BinaryFormatError, BinaryPlatform, INSPECT_PREFIX_LEN, PlatformMismatch, ReleaseTarget,
    check_binary_target, inspect_binary,
};
use serde::Deserialize;
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};

/// The longest cargo message line read whole: longer ones are skipped
/// unparsed, so a runaway line cannot grow the buffer without bound. Cargo's
/// artifact messages are a few KB; with `json-render-diagnostics`, the long
/// rustc diagnostics go to stderr, not into these lines.
const MAX_MESSAGE_LEN: u64 = 1024 * 1024;

/// What [`cargo_build_release`] builds: one package, alone in its cargo run.
#[derive(Debug, Clone, Copy)]
pub struct CargoBuildOptions<'a> {
    /// The workspace to build in (cargo's working directory).
    pub workspace: &'a Path,
    /// The one package to build (`-p <package>`). Never more than one: cargo
    /// unifies features across the packages of a run, which changes the
    /// binaries it links.
    pub package: &'a str,
    /// A `CARGO_TARGET_DIR` for this build only; `None` leaves cargo's own
    /// resolution (environment, then config, then `<workspace>/target`).
    pub target_dir: Option<&'a Path>,
    /// Silence cargo's stderr (its progress and diagnostics).
    pub quiet: bool,
}

/// Why a cargo release build did not yield the binary asked for.
#[derive(Debug, thiserror::Error)]
pub enum CargoBuildError {
    /// `cargo` could not be started.
    #[error("failed to run cargo")]
    Spawn(#[source] std::io::Error),

    /// Reading cargo's stdout, or waiting for it to exit, failed.
    #[error("failed to read cargo's build output")]
    Output(#[source] std::io::Error),

    /// `cargo build` exited unsuccessfully; its diagnostics are on stderr.
    #[error("cargo build failed ({status})")]
    Failed {
        /// Cargo's exit status.
        status: ExitStatus,
    },

    /// The build succeeded, but no `compiler-artifact` message named an
    /// executable for this binary.
    #[error("cargo build reported no executable for the binary {}", fuz_sys::text::quoted(.name))]
    MissingBinary {
        /// The binary asked for.
        name: String,
    },

    /// The build reported the binary at more than one path — a `build.target`
    /// naming several targets — so which one to take is not decidable.
    #[error(
        "cargo build reported the binary {} {count} times (several build targets?)",
        fuz_sys::text::quoted(.name)
    )]
    AmbiguousBinary {
        /// The binary asked for.
        name: String,
        /// How many distinct paths cargo reported for it.
        count: usize,
    },

    /// A built binary could not be read to check its platform.
    #[error("failed to read the built binary {name} at {}", .path.display())]
    ReadBinary {
        /// The binary's name.
        name: String,
        /// Where cargo reported it.
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// A built binary is not an executable the platform check can place.
    #[error("the built binary {name} is not a supported executable: {reason}")]
    UnreadableBinary {
        /// The binary's name.
        name: String,
        /// Why its header was refused.
        reason: BinaryFormatError,
    },

    /// Cargo built a binary that is not for this host's target — a
    /// `build.target` in a cargo config or a set `CARGO_BUILD_TARGET`, or a
    /// static glibc build (`+crt-static`).
    #[error(
        "cargo built {name} as {found} ({}), but this host is {host}",
        cross_build_cause(*.mismatch)
    )]
    CrossBuild {
        /// The binary's name.
        name: String,
        /// What its header says it is.
        found: BinaryPlatform,
        /// The host's target.
        host: ReleaseTarget,
        /// The rule that refused it.
        mismatch: PlatformMismatch,
    },
}

/// The likely cause [`CargoBuildError::CrossBuild`] names.
const fn cross_build_cause(mismatch: PlatformMismatch) -> &'static str {
    match mismatch {
        PlatformMismatch::ArchOrOs | PlatformMismatch::Libc => {
            "a build.target / CARGO_BUILD_TARGET setting?"
        }
        PlatformMismatch::StaticUnconfirmed => {
            "a musl build.target / CARGO_BUILD_TARGET, or `+crt-static` in RUSTFLAGS?"
        }
    }
}

impl CargoBuildError {
    /// User-facing hint for how to fix the error.
    #[must_use]
    pub const fn hint(&self) -> Option<&'static str> {
        match self {
            Self::Spawn(_) => Some("ensure cargo is installed and in your PATH"),
            Self::Failed { .. } => Some("check cargo output above for errors"),
            Self::MissingBinary { .. } => {
                Some("check that the package still builds a binary target of that name")
            }
            Self::AmbiguousBinary { .. } => Some(
                "build for one target: set build.target / CARGO_BUILD_TARGET to a single triple, \
                 or unset it",
            ),
            Self::CrossBuild {
                mismatch: PlatformMismatch::StaticUnconfirmed,
                ..
            } => Some(
                "unset a musl CARGO_BUILD_TARGET / build.target, or drop `+crt-static` from \
                 RUSTFLAGS; the artifact is the host's dynamically linked build",
            ),
            Self::CrossBuild { .. } => Some(
                "unset CARGO_BUILD_TARGET and any build.target in your cargo config; a build for \
                 another target is published with `cargo xtask publish tool … --target <triple>`",
            ),
            Self::Output(_) | Self::ReadBinary { .. } | Self::UnreadableBinary { .. } => None,
        }
    }
}

/// Run `cargo build --release -p <options.package>` and return the path of
/// `binary` as cargo reported it.
///
/// Cargo's stdout is read line by line as it streams; stderr is inherited
/// (cargo's usual progress and rendered diagnostics) unless `options.quiet`.
///
/// # Errors
///
/// [`CargoBuildError::Spawn`] / [`CargoBuildError::Output`] when cargo cannot
/// be run or read; [`CargoBuildError::Failed`] when the build fails;
/// [`CargoBuildError::MissingBinary`] / [`CargoBuildError::AmbiguousBinary`]
/// when it succeeds reporting `binary` at no path, or at several.
pub fn cargo_build_release(
    options: &CargoBuildOptions<'_>,
    binary: &str,
) -> Result<PathBuf, CargoBuildError> {
    let mut command = Command::new("cargo");
    command
        .args([
            "build",
            "--release",
            "--message-format=json-render-diagnostics",
            "-p",
            options.package,
        ])
        .current_dir(options.workspace)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(if options.quiet {
            Stdio::null()
        } else {
            Stdio::inherit()
        });
    if let Some(target_dir) = options.target_dir {
        command.env("CARGO_TARGET_DIR", target_dir);
    }

    let mut child = command.spawn().map_err(CargoBuildError::Spawn)?;
    // Read to the end before waiting, so cargo never blocks on a full pipe.
    let read = child.stdout.take().map_or_else(
        || Ok(Vec::new()),
        |stdout| collect_binary(BufReader::new(stdout), binary),
    );
    let status = child.wait().map_err(CargoBuildError::Output)?;
    // A failed build is reported as such, whatever happened to its output.
    if !status.success() {
        return Err(CargoBuildError::Failed { status });
    }
    take_binary(read.map_err(CargoBuildError::Output)?, binary)
}

/// Hold the binary cargo built at `path` to `host`, the host's target.
///
/// Its header must place it there ([`check_binary_target`], with the target
/// *not* named). Nothing named a target here, so a statically linked binary on a
/// glibc host is refused as the musl build it most likely is (a
/// `CARGO_BUILD_TARGET=…-musl`) — a binary the artifact's own check, which
/// takes the toolchain's host target as named, would accept. A static glibc
/// build (`+crt-static`) is refused with it.
///
/// # Errors
///
/// [`CargoBuildError::CrossBuild`] when it is not for the host;
/// [`CargoBuildError::ReadBinary`] / [`CargoBuildError::UnreadableBinary`]
/// when it cannot be read or placed.
pub fn check_built_for(
    name: &str,
    path: &Path,
    host: ReleaseTarget,
) -> Result<(), CargoBuildError> {
    let read_error = |source| CargoBuildError::ReadBinary {
        name: name.to_string(),
        path: path.to_path_buf(),
        source,
    };
    let mut prefix = Vec::with_capacity(INSPECT_PREFIX_LEN);
    std::fs::File::open(path)
        .and_then(|file| {
            file.take(INSPECT_PREFIX_LEN as u64)
                .read_to_end(&mut prefix)
        })
        .map_err(read_error)?;
    let found = inspect_binary(&prefix).map_err(|reason| CargoBuildError::UnreadableBinary {
        name: name.to_string(),
        reason,
    })?;
    check_binary_target(found, host, false).map_err(|mismatch| CargoBuildError::CrossBuild {
        name: name.to_string(),
        found,
        host,
        mismatch,
    })
}

//
// Message parsing
//

/// The fields of a cargo JSON message this module reads; serde skips the rest.
#[derive(Deserialize)]
struct CargoMessage {
    reason: String,
    target: Option<CargoTarget>,
    executable: Option<PathBuf>,
}

#[derive(Deserialize)]
struct CargoTarget {
    name: String,
    kind: Vec<String>,
}

/// A binary from one cargo message line: the `target.name` and `executable`
/// of a `compiler-artifact` whose `target.kind` includes `bin`. `None` for
/// any other line — another `reason`, a library or build script, no
/// `executable`, or text that is not a cargo message at all.
fn parse_binary_artifact(line: &[u8]) -> Option<(String, PathBuf)> {
    let message: CargoMessage = serde_json::from_slice(line).ok()?;
    if message.reason != "compiler-artifact" {
        return None;
    }
    let target = message.target?;
    if !target.kind.iter().any(|kind| kind == "bin") {
        return None;
    }
    Some((target.name, message.executable?))
}

/// Read cargo's message stream to the end, keeping each distinct path
/// reported for `wanted`, in order. A line over [`MAX_MESSAGE_LEN`] is skipped
/// unparsed.
fn collect_binary(mut reader: impl BufRead, wanted: &str) -> std::io::Result<Vec<PathBuf>> {
    let mut found: Vec<PathBuf> = Vec::new();
    let mut line = Vec::new();
    loop {
        line.clear();
        let read = reader
            .by_ref()
            .take(MAX_MESSAGE_LEN + 1)
            .read_until(b'\n', &mut line)?;
        if read == 0 {
            return Ok(found);
        }
        if line.last() != Some(&b'\n') && read as u64 > MAX_MESSAGE_LEN {
            reader.skip_until(b'\n')?;
            continue;
        }
        if let Some((name, path)) = parse_binary_artifact(&line)
            && name == wanted
            && !found.contains(&path)
        {
            found.push(path);
        }
    }
}

/// The one path [`collect_binary`] found for `binary`.
fn take_binary(mut found: Vec<PathBuf>, binary: &str) -> Result<PathBuf, CargoBuildError> {
    match found.len() {
        0 => Err(CargoBuildError::MissingBinary {
            name: binary.to_string(),
        }),
        1 => Ok(found.remove(0)),
        count => Err(CargoBuildError::AmbiguousBinary {
            name: binary.to_string(),
            count,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::test_stubs::{ElfStub, for_target, host, host_target};
    use crate::platform::{Arch, Libc};
    use std::io::Cursor;

    /// Captured from `cargo build --message-format=json-render-diagnostics`
    /// in this workspace (paths shortened).
    const FUZ_BIN: &str = r#"{"reason":"compiler-artifact","package_id":"path+file:///w/crates/fuz#0.1.0","manifest_path":"/w/crates/fuz/Cargo.toml","target":{"kind":["bin"],"crate_types":["bin"],"name":"fuz","src_path":"/w/crates/fuz/src/main.rs","edition":"2024","doc":true,"doctest":false,"test":true},"profile":{"opt_level":"3","debuginfo":0,"debug_assertions":false,"overflow_checks":false,"test":false},"features":[],"filenames":["/elsewhere/release/fuz"],"executable":"/elsewhere/release/fuz","fresh":false}"#;
    const FUZD_BIN_FRESH: &str = r#"{"reason":"compiler-artifact","package_id":"path+file:///w/crates/fuzd#0.1.0","manifest_path":"/w/crates/fuzd/Cargo.toml","target":{"kind":["bin"],"crate_types":["bin"],"name":"fuzd","src_path":"/w/crates/fuzd/src/main.rs","edition":"2024","doc":true,"doctest":false,"test":true},"profile":{"opt_level":"3","debuginfo":0,"debug_assertions":false,"overflow_checks":false,"test":false},"features":[],"filenames":["/elsewhere/x86_64-unknown-linux-musl/release/fuzd"],"executable":"/elsewhere/x86_64-unknown-linux-musl/release/fuzd","fresh":true}"#;
    const LIB: &str = r#"{"reason":"compiler-artifact","package_id":"path+file:///w/crates/fuz_artifact#0.1.0","manifest_path":"/w/crates/fuz_artifact/Cargo.toml","target":{"kind":["lib"],"crate_types":["lib"],"name":"fuz_artifact","src_path":"/w/crates/fuz_artifact/src/lib.rs","edition":"2024","doc":true,"doctest":true,"test":true},"profile":{"opt_level":"3","debuginfo":0,"debug_assertions":false,"overflow_checks":false,"test":false},"features":[],"filenames":["/elsewhere/release/deps/libfuz_artifact-50d14ca0e12f4887.rlib"],"executable":null,"fresh":true}"#;
    const BUILD_SCRIPT: &str = r#"{"reason":"compiler-artifact","package_id":"registry+https://github.com/rust-lang/crates.io-index#libc@0.2.186","manifest_path":"/r/libc-0.2.186/Cargo.toml","target":{"kind":["custom-build"],"crate_types":["bin"],"name":"build-script-build","src_path":"/r/libc-0.2.186/build.rs","edition":"2021","doc":false,"doctest":false,"test":false},"profile":{"opt_level":"0","debuginfo":0,"debug_assertions":true,"overflow_checks":true,"test":false},"features":["default"],"filenames":["/elsewhere/release/build/libc-ee77b03904dfefb0/build-script-build"],"executable":null,"fresh":true}"#;
    const SCRIPT_RAN: &str = r#"{"reason":"build-script-executed","package_id":"registry+https://github.com/rust-lang/crates.io-index#libc@0.2.186","linked_libs":[],"linked_paths":[],"cfgs":[],"env":[],"out_dir":"/elsewhere/release/build/libc-afc892e3f1158b57/out"}"#;
    const FINISHED: &str = r#"{"reason":"build-finished","success":true}"#;

    fn collect(lines: &[&str], wanted: &str) -> Vec<PathBuf> {
        collect_binary(Cursor::new(lines.join("\n")), wanted).unwrap()
    }

    #[test]
    fn takes_the_binarys_executable_fresh_or_not() {
        let lines = [
            BUILD_SCRIPT,
            SCRIPT_RAN,
            LIB,
            FUZD_BIN_FRESH,
            FUZ_BIN,
            FINISHED,
        ];
        let fuz = take_binary(collect(&lines, "fuz"), "fuz").unwrap();
        assert_eq!(fuz, Path::new("/elsewhere/release/fuz"));
        let fuzd = take_binary(collect(&lines, "fuzd"), "fuzd").unwrap();
        assert_eq!(
            fuzd,
            Path::new("/elsewhere/x86_64-unknown-linux-musl/release/fuzd")
        );
    }

    #[test]
    fn keeps_only_the_binary_asked_for() {
        let found = collect(&[FUZ_BIN, FUZD_BIN_FRESH], "fuz");
        assert_eq!(found, [Path::new("/elsewhere/release/fuz")]);
    }

    #[test]
    fn libraries_build_scripts_and_other_reasons_are_not_binaries() {
        for line in [LIB, BUILD_SCRIPT, SCRIPT_RAN, FINISHED] {
            assert_eq!(parse_binary_artifact(line.as_bytes()), None, "{line}");
        }
        // A bin target whose message names no executable.
        let no_exe = FUZ_BIN.replace(
            r#""executable":"/elsewhere/release/fuz""#,
            r#""executable":null"#,
        );
        assert_eq!(parse_binary_artifact(no_exe.as_bytes()), None);
        assert!(collect(&[&no_exe], "fuz").is_empty());
    }

    #[test]
    fn malformed_lines_are_skipped() {
        let found = collect(
            &[
                "",
                "not json",
                "{\"reason\":",
                r#"{"reason":"compiler-artifact","target":"fuz"}"#,
                "   Compiling fuz v0.1.0",
                FUZ_BIN,
            ],
            "fuz",
        );
        assert_eq!(found, [Path::new("/elsewhere/release/fuz")]);
    }

    #[test]
    fn a_final_line_without_a_newline_is_read() {
        let found = collect_binary(Cursor::new(FUZ_BIN), "fuz").unwrap();
        assert_eq!(found, [Path::new("/elsewhere/release/fuz")]);
    }

    #[test]
    fn an_oversized_line_is_skipped_and_the_stream_continues() {
        let len = usize::try_from(MAX_MESSAGE_LEN).unwrap() + 10;
        let huge = format!(
            r#"{{"reason":"compiler-artifact","pad":"{}"}}"#,
            "x".repeat(len)
        );
        let found = collect(&[&huge, FUZ_BIN], "fuz");
        assert_eq!(found, [Path::new("/elsewhere/release/fuz")]);
    }

    #[test]
    fn a_missing_binary_is_named() {
        let found = collect(&[LIB, FUZ_BIN, FINISHED], "fuzd");
        let error = take_binary(found, "fuzd").unwrap_err();
        assert!(
            matches!(&error, CargoBuildError::MissingBinary { name } if name == "fuzd"),
            "{error:?}"
        );
        assert!(error.to_string().contains("\"fuzd\""), "{error}");
    }

    /// A `build.target` array builds the binary once per target: two paths,
    /// refused rather than one picked. The same path reported twice is one.
    #[test]
    fn a_binary_reported_at_two_paths_is_refused() {
        let musl = FUZ_BIN.replace("/elsewhere/release/fuz", "/elsewhere/musl/release/fuz");
        let error = take_binary(collect(&[FUZ_BIN, &musl], "fuz"), "fuz").unwrap_err();
        assert!(
            matches!(&error, CargoBuildError::AmbiguousBinary { count: 2, .. }),
            "{error:?}"
        );
        assert!(error.hint().is_some());
        let same = take_binary(collect(&[FUZ_BIN, FUZ_BIN], "fuz"), "fuz").unwrap();
        assert_eq!(same, Path::new("/elsewhere/release/fuz"));
    }

    #[test]
    fn a_host_binary_passes_the_host_check() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fuz");
        std::fs::write(&path, host(b"")).unwrap();
        check_built_for("fuz", &path, host_target()).unwrap();
    }

    #[test]
    fn a_cross_built_binary_is_refused_naming_both_targets() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fuz");
        let host = ReleaseTarget::linux(Arch::X86_64, Libc::Gnu);
        std::fs::write(
            &path,
            for_target(ReleaseTarget::linux(Arch::Aarch64, Libc::Gnu), b""),
        )
        .unwrap();
        let error = check_built_for("fuz", &path, host).unwrap_err();
        assert!(
            matches!(error, CargoBuildError::CrossBuild { .. }),
            "{error:?}"
        );
        let message = error.to_string();
        assert!(message.contains("aarch64"), "{message}");
        assert!(
            message.contains("but this host is x86_64-unknown-linux-gnu"),
            "{message}"
        );
        assert!(
            error
                .hint()
                .is_some_and(|hint| hint.contains("build.target"))
        );
    }

    /// A `CARGO_BUILD_TARGET=x86_64-unknown-linux-musl` build (or a
    /// `+crt-static` one) on a glibc host is a static binary of the host's
    /// architecture: refused, though it would run, because the artifact is
    /// labelled with the host's target, and the message names both causes.
    #[test]
    fn a_static_build_on_a_glibc_host_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fuz");
        std::fs::write(&path, ElfStub::static_pie(Arch::X86_64).build(b"")).unwrap();
        let gnu = ReleaseTarget::linux(Arch::X86_64, Libc::Gnu);
        let error = check_built_for("fuz", &path, gnu).unwrap_err();
        let message = error.to_string();
        assert!(
            message.contains("statically linked x86_64 Linux executable"),
            "{message}"
        );
        assert!(
            message.contains("a musl build.target / CARGO_BUILD_TARGET, or `+crt-static`"),
            "{message}"
        );
        assert!(
            error
                .hint()
                .is_some_and(|hint| hint.contains("+crt-static")),
            "{error:?}"
        );
        // On a musl host the same binary is the host's.
        check_built_for("fuz", &path, ReleaseTarget::linux(Arch::X86_64, Libc::Musl)).unwrap();
    }

    #[test]
    fn an_unreadable_binary_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("gone");
        assert!(matches!(
            check_built_for("fuz", &missing, host_target()),
            Err(CargoBuildError::ReadBinary { .. })
        ));
        let text = dir.path().join("text");
        std::fs::write(&text, b"#!/bin/sh\n").unwrap();
        assert!(matches!(
            check_built_for("fuz", &text, host_target()),
            Err(CargoBuildError::UnreadableBinary { .. })
        ));
    }
}
