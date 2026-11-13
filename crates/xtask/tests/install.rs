//! `cargo xtask install` end to end, in a throwaway workspace and `FUZ_HOME`:
//! a dependency-free `fuz` and `fuzd` built by a real (tiny) `cargo build
//! --release`, never this repo's, and never the user's `~/.fuz` or daemon.

#![expect(
    clippy::expect_used,
    reason = "test helpers outside `#[test]` fns panic on a failed setup or check"
)]

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output};

/// A workspace with dependency-free `fuz` and `fuzd` binaries, committed to a
/// git repo (the artifact's inputs read git), with git's user and system
/// config ignored.
///
/// Both binaries print `shared::VALUE`, from a workspace library whose
/// feature `x` changes it: `fuzd` enables the feature, `fuz` does not. A
/// single cargo run building both would unify the feature into `fuz` too.
fn tiny_workspace(dir: &Path) {
    let file = |path: &str, contents: &str| {
        let path = dir.join(path);
        std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
        std::fs::write(path, contents).expect("write");
    };
    file(
        "Cargo.toml",
        "[workspace]\nmembers = [\"crates/fuz\", \"crates/fuzd\", \"crates/shared\"]\n\
         resolver = \"2\"\n\n[workspace.package]\nversion = \"0.1.0\"\n",
    );
    file(
        "crates/shared/Cargo.toml",
        "[package]\nname = \"shared\"\nversion.workspace = true\nedition = \"2024\"\n\n\
         [features]\nx = []\n",
    );
    file(
        "crates/shared/src/lib.rs",
        "#[cfg(feature = \"x\")]\npub const VALUE: &str = \"unified\";\n\
         #[cfg(not(feature = \"x\"))]\npub const VALUE: &str = \"plain\";\n",
    );
    for (name, shared) in [
        ("fuz", "{ path = \"../shared\" }"),
        ("fuzd", "{ path = \"../shared\", features = [\"x\"] }"),
    ] {
        file(
            &format!("crates/{name}/Cargo.toml"),
            &format!(
                "[package]\nname = \"{name}\"\nversion.workspace = true\nedition = \"2024\"\n\n\
                 [dependencies]\nshared = {shared}\n"
            ),
        );
        file(
            &format!("crates/{name}/src/main.rs"),
            "fn main() { println!(\"{}\", shared::VALUE); }\n",
        );
    }
    for args in [
        &["init", "-q"][..],
        &["add", "-A"],
        &[
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@t",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-q",
            "-m",
            "init",
        ],
    ] {
        let status = Command::new("git")
            .args(args)
            .current_dir(dir)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .status()
            .expect("git");
        assert!(status.success(), "git {args:?}");
    }
}

/// A fresh `0700` fuz home.
fn fresh_home() -> tempfile::TempDir {
    let home = tempfile::tempdir().expect("tempdir");
    std::fs::set_permissions(home.path(), std::fs::Permissions::from_mode(0o700)).expect("chmod");
    home
}

/// `cargo xtask install --no-restart` in `workspace`, against `home`.
fn install(workspace: &Path, home: &Path, envs: &[(&str, &Path)]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_xtask"));
    command
        .args(["install", "--no-restart"])
        .current_dir(workspace)
        .env("FUZ_HOME", home)
        .env("HOME", home)
        // A developer's global build target must not decide the test.
        .env_remove("CARGO_BUILD_TARGET");
    for (key, value) in envs {
        command.env(key, value);
    }
    command.output().expect("run xtask")
}

/// Both binaries come from where cargo built them: with `CARGO_TARGET_DIR`
/// elsewhere and stale (but executable) decoys at `target/release/`, the
/// installed `fuz` artifact and `fuzd` tool are the fresh builds.
#[test]
fn install_takes_the_binaries_cargo_reports() {
    let workspace = tempfile::tempdir().expect("tempdir");
    tiny_workspace(workspace.path());
    let decoy = fuz_artifact::platform::test_stubs::host(b"stale decoy");
    std::fs::create_dir_all(workspace.path().join("target/release")).expect("mkdir");
    for name in ["fuz", "fuzd"] {
        std::fs::write(workspace.path().join("target/release").join(name), &decoy).expect("decoy");
    }
    let target_dir = tempfile::tempdir().expect("tempdir");
    let home = fresh_home();

    let out = install(
        workspace.path(),
        home.path(),
        &[("CARGO_TARGET_DIR", target_dir.path())],
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");

    for name in ["fuz", "fuzd"] {
        let built = std::fs::read(target_dir.path().join("release").join(name)).expect("built");
        let installed = std::fs::read(home.path().join("bin").join(name)).expect("installed");
        assert_ne!(installed, decoy, "{name}: the stale decoy was installed");
        assert_eq!(installed, built, "{name}: the installed binary is cargo's");
    }

    // Each binary was built in its own cargo run: `fuz` without the feature
    // only `fuzd` enables — the binary a `-p fuz` build (`fuz artifact build
    // --verify`) reproduces.
    let run = |name: &str| {
        let out = Command::new(home.path().join("bin").join(name))
            .output()
            .expect("run installed binary");
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    };
    assert_eq!(run("fuz"), "plain", "fuz was built with fuzd's features");
    assert_eq!(run("fuzd"), "unified");
}

/// Whether this host is `x86_64` glibc with the `x86_64-unknown-linux-musl`
/// standard library installed: what the cross-build test needs to build.
fn musl_target_installed() -> bool {
    if !(cfg!(target_arch = "x86_64") && cfg!(target_env = "gnu")) {
        return false;
    }
    Command::new("rustc")
        .args([
            "--print",
            "target-libdir",
            "--target",
            "x86_64-unknown-linux-musl",
        ])
        .output()
        .ok()
        .filter(|out| out.status.success())
        .and_then(|out| {
            let dir = String::from_utf8(out.stdout).ok()?;
            std::fs::read_dir(dir.trim()).ok()?.next()
        })
        .is_some()
}

/// With `CARGO_BUILD_TARGET` naming another target, the build goes through
/// and the install refuses what it built, naming both targets, before the
/// fuz home is created. Skipped where the musl target is not installed.
#[test]
fn install_refuses_binaries_built_for_another_target() {
    if !musl_target_installed() {
        eprintln!("skipped: x86_64-unknown-linux-musl is not installed");
        return;
    }
    let workspace = tempfile::tempdir().expect("tempdir");
    tiny_workspace(workspace.path());
    let target_dir = tempfile::tempdir().expect("tempdir");
    let parent = tempfile::tempdir().expect("tempdir");
    let home = parent.path().join("home");

    let out = install(
        workspace.path(),
        &home,
        &[
            ("CARGO_TARGET_DIR", target_dir.path()),
            ("CARGO_BUILD_TARGET", Path::new("x86_64-unknown-linux-musl")),
        ],
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert!(
        stderr.contains(
            "error: cargo built fuz as a statically linked x86_64 Linux executable \
             (a musl build.target / CARGO_BUILD_TARGET, or `+crt-static` in RUSTFLAGS?), but \
             this host is x86_64-unknown-linux-gnu"
        ),
        "{stderr}"
    );
    assert!(
        stderr.contains("hint: unset a musl CARGO_BUILD_TARGET"),
        "{stderr}"
    );
    assert!(!home.exists(), "nothing was installed");
}
