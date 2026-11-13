//! Build script to embed git version info

use std::path::Path;
use std::process::Command;

fn main() {
    // Re-run if git HEAD changes (workspace root, not crate dir)
    #[expect(
        clippy::unwrap_used,
        reason = "cargo always sets `CARGO_MANIFEST_DIR` for a build script"
    )]
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    #[expect(
        clippy::unwrap_used,
        reason = "the crate sits two levels under the workspace root"
    )]
    let workspace_root = Path::new(&manifest_dir).parent().unwrap().parent().unwrap();
    let git_dir = workspace_root.join(".git");

    println!("cargo::rerun-if-changed={}", git_dir.join("HEAD").display());
    println!(
        "cargo::rerun-if-changed={}",
        git_dir.join("index").display()
    );

    let git_hash = Command::new("git")
        .args(["describe", "--tags", "--dirty", "--always"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map_or_else(
            || "unknown".to_string(),
            |o| String::from_utf8_lossy(&o.stdout).trim().to_string(),
        );

    println!("cargo::rustc-env=FUZ_GIT_INFO={git_hash}");
}
