//! The two workflows that check pglet out check out the same ref.
//!
//! `fuz_testing` path-depends on pglet's server crate, so every workflow job
//! that runs cargo checks pglet out beside this repo. `check.yml` names the
//! ref in its workflow-level `PGLET_REF` (pglet's `main`), and
//! `cross-contract.yml` repeats it as a literal, since a workflow can't read
//! another's `env`. This test holds the two equal, so a ref changed in one —
//! a branch, or a commit pinned while reacting to a pglet break — and missed
//! in the other fails here instead of building against two pglet commits.

use std::fs;
use std::path::Path;

fn read(relative: &str) -> Result<String, String> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(relative);
    fs::read_to_string(&path).map_err(|e| format!("read {}: {e}", path.display()))
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
fn the_workflows_check_out_one_pglet_ref() {
    let check_ref = read(".github/workflows/check.yml")
        .and_then(|text| check_pglet_ref(&text))
        .unwrap_or_else(|e| panic!("{e}"));
    assert!(!check_ref.is_empty(), "check.yml: `PGLET_REF` is empty");
    let cross = read(".github/workflows/cross-contract.yml")
        .and_then(|text| checkout_ref(&text, "cross-contract.yml"))
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        cross, check_ref,
        "cross-contract.yml checks out pglet at {cross}, check.yml's `PGLET_REF` is {check_ref}: \
         keep them equal"
    );
}
