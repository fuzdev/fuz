//! `cargo xtask prune` — remove old published releases from a storage backend.
//!
//! Producer-only: xtask path-deps `fuz_sign` (kept out of the consumer `fuz`
//! graph), which owns the delete-capable [`prune_stream`]. Prunes one release
//! stream — the fuz self artifact, or a `--tool <name>` — to the `--keep`
//! most-recent versions, always keeping the version each per-target latest pointer names.
//! The store must already be there (a missing local `--storage` is an error,
//! not "nothing to prune"), and `--tool` takes a first-party tool name, so the
//! name never becomes a key prefix outside `tools/<name>/`.
//!
//! **Dry-run by default.** It deletes *published* artifacts (remote, hard to
//! reverse), so it previews unless `--wetrun` is given, as `fuz artifact
//! prune` does for the local store.

use argh::FromArgs;
use fuz_artifact::tools::is_first_party_tool;
use fuz_release::ReleaseLayout;
use fuz_sign::{printable, prune_stream};

use crate::publish::{PublishError, existing_storage, runtime};

/// Default number of recent versions to keep per stream.
const DEFAULT_KEEP: usize = 5;

/// Remove old published releases from storage, keeping the most recent versions.
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "prune")]
pub struct Prune {
    /// storage location (e.g. `/path`, `forge://host`, or `ssh://user@host/path`)
    #[argh(option)]
    storage: String,

    /// prune a tool stream (e.g. fuzd, fuzf) instead of the fuz self artifact
    #[argh(option)]
    tool: Option<String>,

    /// number of most-recent versions to keep (default: 5)
    #[argh(option)]
    keep: Option<usize>,

    /// actually delete (default is a dry-run preview)
    #[argh(switch)]
    wetrun: bool,

    /// suppress per-release output
    #[argh(switch, short = 'q')]
    quiet: bool,
}

/// Dispatch `cargo xtask prune …`.
pub fn cmd_prune(opts: &Prune) -> Result<(), PublishError> {
    let (layout, name) = stream_layout(opts.tool.as_deref())?;
    // A store already there: a mistyped path is an error, not "nothing to
    // prune".
    let storage = existing_storage(&opts.storage)?;
    let keep = opts.keep.unwrap_or(DEFAULT_KEEP);

    let report = runtime()?.block_on(prune_stream(&storage, &layout, &name, keep, !opts.wetrun))?;

    if !opts.quiet {
        let verb = if report.dry_run {
            "would prune"
        } else {
            "pruned"
        };
        if report.pruned.is_empty() {
            println!(
                "{}: nothing to prune (kept {} version(s), keep={keep})",
                report.stream,
                report.kept_versions.len()
            );
        } else {
            println!(
                "{}: {verb} {} artifact(s) across {} old version(s); kept {} version(s)",
                report.stream,
                report.pruned.len(),
                distinct_versions(&report.pruned),
                report.kept_versions.len(),
            );
            for r in &report.pruned {
                println!("{}", pruned_line(verb, r));
            }
            if report.dry_run {
                println!("(dry run — pass --wetrun to delete)");
            }
        }
    }
    Ok(())
}

/// The layout and stream name `--tool` selects: the fuz self artifact without
/// it, else that tool's stream.
///
/// The name becomes a storage-key prefix (`tools/<name>/`) that is listed and
/// deleted under, so it is held to the rule a publish holds it to — a
/// first-party tool name — before any key is built from it: `--tool ..` or
/// `--tool ../x` never reaches storage.
fn stream_layout(tool: Option<&str>) -> Result<(ReleaseLayout, String), PublishError> {
    let Some(tool) = tool else {
        return Ok((ReleaseLayout::self_artifact(), "fuz".to_string()));
    };
    if !is_first_party_tool(tool) {
        return Err(PublishError::ToolNotFirstParty {
            name: tool.to_string(),
        });
    }
    Ok((ReleaseLayout::tool(tool), tool.to_string()))
}

/// The lines for one pruned release: its version and target, then each key
/// deleted (or, on a dry run, that would be) in the order the delete runs —
/// the tarball, a self release's flat binary sidecar and binary, the
/// manifest. The version and target are the fields of a manifest whose
/// signature a prune does not check, and the keys are a store's listing and
/// the key built from those fields, so every line is printed through
/// `printable`.
fn pruned_line(verb: &str, release: &fuz_sign::PrunedRelease) -> String {
    let mut line = format!(
        "  {verb}: {} [{}]",
        printable(&release.version),
        printable(&release.target)
    );
    let keys = std::iter::once(&release.tarball_key)
        .chain(&release.flat_keys)
        .chain(std::iter::once(&release.manifest_key));
    for key in keys {
        line.push_str("\n    ");
        line.push_str(&printable(key));
    }
    line
}

/// Count distinct versions among the pruned artifacts (for the summary line).
fn distinct_versions(pruned: &[fuz_sign::PrunedRelease]) -> usize {
    let mut v: Vec<&str> = pruned.iter().map(|r| r.version.as_str()).collect();
    v.sort_unstable();
    v.dedup();
    v.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The version is a field of the same unsigned manifest, escaped as the
    /// target is.
    #[test]
    fn a_pruned_line_escapes_the_manifest_version() {
        let release = fuz_sign::PrunedRelease {
            version: "9.9.9\u{1b}[2K\r\u{202e}\u{2800}\\\n  pruned: 0.0.1 [all]".to_string(),
            target: "x86_64-unknown-linux-gnu".to_string(),
            manifest_key: "m".to_string(),
            tarball_key: "t".to_string(),
            flat_keys: Vec::new(),
        };
        assert_eq!(
            pruned_line("pruned", &release),
            "  pruned: 9.9.9\\u{1b}[2K\\r\\u{202e}\\u{2800}\\\\\\n  pruned: 0.0.1 [all] \
             [x86_64-unknown-linux-gnu]\n    t\n    m"
        );
    }

    /// A dry run shows the keys it would delete, the tarball's among them, so
    /// a run can be read before `--wetrun`; a key is escaped as the fields are.
    #[test]
    fn a_pruned_line_names_both_keys_escaped() {
        let release = fuz_sign::PrunedRelease {
            version: "0.1.0".to_string(),
            target: "x86_64-unknown-linux-gnu".to_string(),
            manifest_key: "tools/fuzd/fuzd-0.1.0-x86_64-unknown-linux-gnu.manifest.json"
                .to_string(),
            tarball_key: "tools/fuzd/fuzd-0.1.0\u{1b}[2K\n.tar.gz".to_string(),
            flat_keys: Vec::new(),
        };
        assert_eq!(
            pruned_line("would prune", &release),
            "  would prune: 0.1.0 [x86_64-unknown-linux-gnu]\n    \
             tools/fuzd/fuzd-0.1.0\\u{1b}[2K\\n.tar.gz\n    \
             tools/fuzd/fuzd-0.1.0-x86_64-unknown-linux-gnu.manifest.json"
        );
    }

    /// A pruned release's line shows the unsigned manifest's fields escaped:
    /// one line, with nothing that drives the terminal.
    #[test]
    fn a_pruned_line_escapes_the_manifest_fields() {
        let release = fuz_sign::PrunedRelease {
            version: "0.1.0".to_string(),
            target: "x86\u{1b}[2K\r\u{202e}\u{2800}\"\\\n  pruned: 9.9.9 [all]".to_string(),
            manifest_key: "m".to_string(),
            tarball_key: "t".to_string(),
            flat_keys: Vec::new(),
        };
        assert_eq!(
            pruned_line("would prune", &release),
            "  would prune: 0.1.0 [x86\\u{1b}[2K\\r\\u{202e}\\u{2800}\"\\\\\\n  pruned: 9.9.9 [all]]\
             \n    t\n    m"
        );
        let ordinary = fuz_sign::PrunedRelease {
            version: "0.2.0".to_string(),
            target: "x86_64-unknown-linux-gnu".to_string(),
            manifest_key: "fuz-0.2.0-x86_64-unknown-linux-gnu.manifest.json".to_string(),
            tarball_key: "fuz-0.2.0-x86_64-unknown-linux-gnu.tar.gz".to_string(),
            flat_keys: vec![
                "fuz-0.2.0-x86_64-unknown-linux-gnu.sha512".to_string(),
                "fuz-0.2.0-x86_64-unknown-linux-gnu".to_string(),
            ],
        };
        assert_eq!(
            pruned_line("pruned", &ordinary),
            "  pruned: 0.2.0 [x86_64-unknown-linux-gnu]\n    \
             fuz-0.2.0-x86_64-unknown-linux-gnu.tar.gz\n    \
             fuz-0.2.0-x86_64-unknown-linux-gnu.sha512\n    \
             fuz-0.2.0-x86_64-unknown-linux-gnu\n    \
             fuz-0.2.0-x86_64-unknown-linux-gnu.manifest.json"
        );
    }
}
