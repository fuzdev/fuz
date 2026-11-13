//! Build script for `fuz_release`
//!
//! Sets the TARGET environment variable at compile time, allowing
//! `env!("TARGET")` to return the current build target triple.

fn main() {
    // Make TARGET available at compile time via env!("TARGET")
    #[expect(
        clippy::expect_used,
        reason = "cargo always sets `TARGET` for a build script"
    )]
    let target = std::env::var("TARGET").expect("TARGET env var not set by cargo");
    println!("cargo:rustc-env=TARGET={target}");
}
