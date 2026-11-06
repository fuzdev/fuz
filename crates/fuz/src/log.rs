//! Log command - show artifact switch history

use crate::CliError;
use argh::FromArgs;
use fuz_artifact::{
    CONTENT_HASH_PREFIX, History, SHORT_HASH_LEN, get_current_artifact, short_content_hash,
};

//
// CLI args
//

/// Show artifact switch history.
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "log")]
pub struct Log {
    /// number of entries to show
    #[argh(option, short = 'n', long = "count", default = "10")]
    pub count: usize,

    /// machine-readable JSON output
    #[argh(switch)]
    pub json: bool,
}

//
// Command entry point
//

pub fn cmd_log(args: &Log) -> Result<(), CliError> {
    let history = History::read().map_err(CliError::Artifact)?;

    if args.json {
        let entries: Vec<_> = history.entries.iter().take(args.count).collect();
        let output = serde_json::json!({ "entries": entries });
        println!("{}", serde_json::to_string_pretty(&output)?);
        return Ok(());
    }

    if history.entries.is_empty() {
        println!("No switch history.");
        println!();
        println!(
            "History is recorded when you switch artifacts with 'fuz artifact build' or 'fuz artifact use'."
        );
        return Ok(());
    }

    // Get current artifact hash for marking
    let current_hash = get_current_artifact()
        .map_err(CliError::Artifact)?
        .map(|m| m.hash);

    println!("Switch history (newest first):");

    for (i, entry) in history.entries.iter().take(args.count).enumerate() {
        let marker = if current_hash.as_ref() == Some(&entry.hash) {
            "*"
        } else {
            " "
        };

        // Parse timestamp for cleaner display
        let timestamp = format_timestamp(&entry.switched_at);

        println!(
            "  {marker} {}  {:8}  {timestamp}",
            display_prefix(&entry.hash),
            entry.version
        );

        // Show previous if this isn't the oldest entry shown
        if let Some(ref prev) = entry.previous_hash
            && i == 0
            && current_hash.as_ref() == Some(&entry.hash)
        {
            // Current entry - show that "-" would go to previous
            println!(
                "      └─ from {} (use '-' to switch back)",
                display_prefix(prev)
            );
        }
    }

    let total = history.entries.len();
    if total > args.count {
        println!();
        println!("  ({} more, use -n to show more)", total - args.count);
    }

    Ok(())
}

/// Render a stored hash as the prefix `fuz artifact use` accepts.
///
/// Both fields this renders are written full (`v1-<64 hex>`), and
/// `fuz artifact use` wants eight *bare* digits, counted after
/// `normalize_prefix` strips the version tag. Slicing `[..SHORT_HASH_LEN]` off
/// the stored value would take the `v1-` **with** the hash and print `v1-` plus
/// five hex digits, a prefix `use` refuses with `PrefixTooShort`.
///
/// `short_content_hash` strips the tag first, so a `previous_hash` stored as
/// bare hex renders the same way.
fn display_prefix(hash: &str) -> String {
    format!(
        "{CONTENT_HASH_PREFIX}{}",
        short_content_hash(hash, SHORT_HASH_LEN)
    )
}

/// Format ISO 8601 timestamp for display
fn format_timestamp(iso: &str) -> String {
    // Input: "2025-01-15T10:30:00Z"
    // Output: "2025-01-15 10:30"
    if let Some((date, time)) = iso.split_once('T') {
        let time_short = time.split(':').take(2).collect::<Vec<_>>().join(":");
        format!("{date} {time_short}")
    } else {
        iso.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_timestamp_shortens_iso_to_date_and_hh_mm() {
        assert_eq!(format_timestamp("2025-01-15T10:30:00Z"), "2025-01-15 10:30");
        // No `T` separator → returned unchanged.
        assert_eq!(format_timestamp("not-a-timestamp"), "not-a-timestamp");
    }
}
