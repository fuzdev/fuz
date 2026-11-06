//! Shared by the `fuz_eval` integration suites.

use std::path::{Path, PathBuf};

/// A scratch directory for one test, removed when the guard drops — on a failed
/// assertion too.
///
/// It lives under Cargo's per-package test scratch space (`CARGO_TARGET_TMPDIR`,
/// inside the target directory) rather than the system temp directory, so a tree
/// a killed run leaves behind goes with the next `cargo clean`. The path is
/// canonical, so it compares equal to the paths `fgro` reports.
#[derive(Debug)]
pub struct Scratch(PathBuf);

impl Scratch {
    /// Create an empty directory named for `tag` and the process id; `tag` must be
    /// unique within the test binary. A tree already at that name is removed
    /// first.
    pub fn new(tag: &str) -> Self {
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("fuz_eval_{tag}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create the scratch dir");
        // fixed, so a run under `umask 000` doesn't leave it world-writable,
        // which `fuz_eval`'s trust root refuses
        set_mode(&dir, 0o755);
        Self(std::fs::canonicalize(&dir).expect("canonicalize the scratch dir"))
    }

    /// The directory's canonical path.
    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A project in a fresh scratch directory: a `package.json` that sets it as the
/// trust root, and a `config.ts` holding `config`. Returns the guard and the
/// config's path.
#[allow(dead_code, reason = "not every suite builds a project")]
pub fn project(tag: &str, config: &str) -> (Scratch, PathBuf) {
    let scratch = Scratch::new(tag);
    write(
        &scratch.path().join("package.json"),
        r#"{"name":"p","private":true}"#,
    );
    let config_path = scratch.path().join("config.ts");
    write(&config_path, config);
    (scratch, config_path)
}

/// Write `contents` to `path`, a file in a [`Scratch`], creating its parent
/// directories. Every directory created is `0755` and the file `0644`, whatever
/// the umask, since `fuz_eval`'s trust root refuses a world-writable config or
/// config directory.
#[allow(dead_code, reason = "not every suite builds a project")]
pub fn write(path: &Path, contents: &str) {
    let tmp = std::fs::canonicalize(env!("CARGO_TARGET_TMPDIR")).expect("the target tmp dir");
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create the parent directories");
        assert!(
            parent.starts_with(&tmp),
            "{} is not in a scratch dir",
            path.display()
        );
        for dir in parent.ancestors().take_while(|dir| *dir != tmp) {
            set_mode(dir, 0o755);
        }
    }
    std::fs::write(path, contents).expect("write the file");
    set_mode(path, 0o644);
}

/// Set `path`'s permission bits to `mode`.
fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("set the mode");
}

/// This process's effective uid, the second field of `/proc/self/status`'s
/// `Uid:` line.
#[allow(dead_code, reason = "not every suite reads it")]
pub fn effective_uid() -> u32 {
    let status = std::fs::read_to_string("/proc/self/status").expect("read /proc/self/status");
    status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .and_then(|fields| fields.split_whitespace().nth(1))
        .and_then(|euid| euid.parse().ok())
        .expect("an effective uid in /proc/self/status")
}
