//! Build script to embed git version info

use std::path::Path;
use std::process::Command;

fn main() {
    // Re-run if git HEAD changes (workspace root, not crate dir)
    // unwrap is safe: CARGO_MANIFEST_DIR always set by cargo, parent paths always exist
    #[allow(clippy::unwrap_used)]
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    #[allow(clippy::unwrap_used)]
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
