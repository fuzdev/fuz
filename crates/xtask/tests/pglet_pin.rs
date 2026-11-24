//! The two workflows that check pglet out pin the same commit.
//!
//! `fuz_testing` path-depends on pglet's server crate, so every workflow job
//! that runs cargo checks pglet out beside this repo. `check.yml` pins it in
//! its workflow-level `PGLET_REF`, and `cross-contract.yml` repeats that SHA
//! as a literal, since a workflow can't read another's `env`. This test holds
//! the two to one full 40-hex SHA, so a bump that moves one and misses the
//! other fails here instead of building against two pglet commits.

use std::fs;
use std::path::Path;

fn read(relative: &str) -> Result<String, String> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(relative);
    fs::read_to_string(&path).map_err(|e| format!("read {}: {e}", path.display()))
}

/// Whether `value` is a full commit SHA: 40 lowercase hex digits.
fn is_full_sha(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The value of `check.yml`'s one `PGLET_REF:` line.
fn check_pglet_ref(text: &str) -> Result<String, String> {
    let values: Vec<&str> = text
        .lines()
        .filter_map(|line| line.trim_start().strip_prefix("PGLET_REF: "))
        .collect();
    let [value] = values[..] else {
        return Err(format!(
            "check.yml: expected one `PGLET_REF:` line, found {values:?}"
        ));
    };
    Ok(value.trim().to_string())
}

/// The `ref:` of the checkout step whose `repository:` is `fuzdev/pglet`: the
/// first `ref:` after that line, before the next step.
fn checkout_ref(text: &str, file: &str) -> Result<String, String> {
    let lines: Vec<&str> = text.lines().collect();
    let starts: Vec<usize> = lines
        .iter()
        .enumerate()
        .filter(|(_, line)| line.trim() == "repository: fuzdev/pglet")
        .map(|(i, _)| i)
        .collect();
    let [start] = starts[..] else {
        return Err(format!(
            "{file}: expected one `repository: fuzdev/pglet`, found {}",
            starts.len()
        ));
    };
    lines[start + 1..]
        .iter()
        .take_while(|line| !line.trim_start().starts_with("- "))
        .find_map(|line| line.trim().strip_prefix("ref: "))
        .map(|value| value.trim().to_string())
        .ok_or_else(|| format!("{file}: no `ref:` in the fuzdev/pglet checkout step"))
}

#[test]
fn the_pglet_pins_are_one_full_sha() {
    let pinned = read(".github/workflows/check.yml")
        .and_then(|text| check_pglet_ref(&text))
        .unwrap_or_else(|e| panic!("{e}"));
    assert!(
        is_full_sha(&pinned),
        "check.yml: `PGLET_REF` must be a full 40-hex SHA, found {pinned:?}"
    );
    let cross = read(".github/workflows/cross-contract.yml")
        .and_then(|text| checkout_ref(&text, "cross-contract.yml"))
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        cross, pinned,
        "cross-contract.yml checks out pglet at {cross}, check.yml's `PGLET_REF` is {pinned}: \
         move them together"
    );
}

#[test]
fn a_sha_is_forty_lowercase_hex_digits() {
    assert!(is_full_sha("12768a9670c217a650615a428d30e9e8fa92afb1"));
    assert!(!is_full_sha("main"));
    assert!(!is_full_sha("12768a9"));
    assert!(!is_full_sha("12768A9670C217A650615A428D30E9E8FA92AFB1"));
}
