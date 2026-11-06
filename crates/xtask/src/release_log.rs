//! `cargo xtask release-log …` — maintain the release log: `backfill` creates
//! it from the releases already published, and `revoke` withdraws a release it
//! records.
//!
//! # `backfill`
//!
//! The release log's signed head lists every release as a row, and it has to
//! be complete from its first head. `backfill` writes that first head: it reads
//! every release in `--storage` — the fuz self artifact and each first-party
//! tool — and records one row per release in the log checkout at `--log-repo`.
//! Before it records a release it verifies the release's signed manifest, the
//! tarball that manifest names, and for the self artifact the flat binary and
//! its `.sha512` sidecar; and it checks what each stream's
//! `latest-<target>.json` pointers name. See `fuz_sign::backfill`.
//!
//! **Dry-run by default**, like `cargo xtask prune`: without `--wetrun` it runs
//! every read and check, prints what it would write for review, and writes
//! nothing — not to storage, and not to the log beyond bringing the checkout up
//! to its upstream. With `--wetrun` it writes `head.json` and the `latest/`
//! pointers, commits, pushes, and reads the pushed commit back.
//!
//! A self release whose flat binary is not in storage can only be logged
//! without a `sha512`, for good; that takes `--allow-missing-flat`.
//!
//! It only ever creates a log. A log that has a head is refused; later
//! releases are recorded by `cargo xtask publish … --log-repo`.
//!
//! # `revoke`
//!
//! `revoke <name> <version>` marks a logged release — every target of it — as
//! revoked in the next head, so a client that checks the log refuses to
//! install it. A `latest/` pointer that names the revoked version moves to the
//! newest release that still stands and has a flat binary for the target, or
//! is removed when there is none. See `fuz_sign::revoke`.
//!
//! Dry-run by default, like `backfill`. With `--wetrun` it writes, commits,
//! pushes, and reads the pushed commit back. Running it again is safe: a
//! release that is already revoked signs no new head, and a commit an earlier
//! run could not push is pushed.
//!
//! It takes no `--storage`: storage is not touched. What the byte host
//! advertises keeps naming the revoked version until a fixed release is
//! published.

use std::fmt::Write as _;
use std::path::PathBuf;

use argh::FromArgs;
use fuz_release::SELF_NAME;
use fuz_sign::{
    BackfillOptions, BackfillReport, LogRepo, PointerAfter, Revocation, RevokeOptions,
    RevokeReport, backfill_release_log, load_signing_key, printable, revoke_release,
};

use crate::publish::{PublishError, existing_storage, runtime};

/// Hex characters of a content hash shown in the review table.
const CONTENT_HASH_PREFIX_LEN: usize = 12;

/// Maintain the release log (publisher-only).
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "release-log")]
pub struct ReleaseLog {
    #[argh(subcommand)]
    nested: ReleaseLogSub,
}

#[derive(FromArgs, Debug)]
#[argh(subcommand)]
enum ReleaseLogSub {
    Backfill(Backfill),
    Revoke(Revoke),
}

/// Create the release log from the releases already in storage: one row per
/// release in the log's first head.
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "backfill")]
struct Backfill {
    /// storage location (e.g. `/path`, `forge://host`, or `ssh://user@host/path`)
    #[argh(option)]
    storage: String,

    /// checkout of the release log repository, with no head.json yet
    #[argh(option)]
    log_repo: PathBuf,

    /// signing key file (default: `$FUZ_HOME/config/signing.key`)
    #[argh(option)]
    key_file: Option<PathBuf>,

    /// actually write, commit, and push (default is a dry-run review)
    #[argh(switch)]
    wetrun: bool,

    /// log self releases whose flat binary is not in storage, without a sha512
    #[argh(switch)]
    allow_missing_flat: bool,

    /// suppress output
    #[argh(switch, short = 'q')]
    quiet: bool,
}

impl Backfill {
    /// Whether this run only reviews: everything but `--wetrun`.
    const fn dry_run(&self) -> bool {
        !self.wetrun
    }

    const fn options(&self) -> BackfillOptions {
        BackfillOptions {
            dry_run: self.dry_run(),
            allow_missing_flat: self.allow_missing_flat,
        }
    }
}

/// Revoke a logged release: mark its row revoked in the next head, and move
/// or remove the latest/ pointers that name it.
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "revoke")]
struct Revoke {
    /// row name: `fuz` for the self artifact, else the tool name
    #[argh(positional)]
    name: String,

    /// version to revoke (every target of it)
    #[argh(positional)]
    version: String,

    /// checkout of the release log repository
    #[argh(option)]
    log_repo: PathBuf,

    /// signing key file (default: `$FUZ_HOME/config/signing.key`)
    #[argh(option)]
    key_file: Option<PathBuf>,

    /// actually write, commit, and push (default is a dry-run review)
    #[argh(switch)]
    wetrun: bool,

    /// suppress output
    #[argh(switch, short = 'q')]
    quiet: bool,
}

impl Revoke {
    const fn options(&self) -> RevokeOptions {
        RevokeOptions {
            dry_run: !self.wetrun,
        }
    }
}

/// Dispatch `cargo xtask release-log …`.
pub fn cmd_release_log(args: ReleaseLog) -> Result<(), PublishError> {
    match args.nested {
        ReleaseLogSub::Backfill(opts) => backfill(&opts),
        ReleaseLogSub::Revoke(opts) => revoke(&opts),
    }
}

fn revoke(opts: &Revoke) -> Result<(), PublishError> {
    let key = load_signing_key(opts.key_file.as_deref())?.key;
    let repo = LogRepo::new(&opts.log_repo);
    let now = fuz_sys::rfc3339_now();

    let report = revoke_release(&repo, &opts.name, &opts.version, &key, &now, opts.options())?;

    if !opts.quiet {
        print!("{}", render_revoke_report(&report));
    }
    Ok(())
}

/// The review of a revocation: the release and its targets, the head's `seq`,
/// each pointer before and after, the commit, and what is left to storage.
///
/// Names and versions are the command line's and the log's; each is printed
/// through `printable`.
fn render_revoke_report(report: &RevokeReport) -> String {
    let mut out = String::new();
    // Writing to a `String` cannot fail.
    let _ = write_revoke_report(&mut out, report);
    out
}

fn write_revoke_report(out: &mut String, report: &RevokeReport) -> std::fmt::Result {
    let name = printable(&report.name);
    let version = printable(&report.version);
    match (report.revocation, report.dry_run) {
        (Revocation::Revoked, true) => writeln!(
            out,
            "release log revoke: would revoke {name} {version} at seq {}",
            report.seq
        )?,
        (Revocation::Revoked, false) => writeln!(
            out,
            "release log revoke: revoked {name} {version} at seq {}",
            report.seq
        )?,
        (Revocation::AlreadyRevoked, _) => writeln!(
            out,
            "release log revoke: {name} {version} is already revoked (head at seq {}); no new \
             head is signed",
            report.seq
        )?,
    }
    writeln!(out, "targets (all revoked together):")?;
    for target in &report.targets {
        writeln!(out, "  {}", printable(target))?;
    }

    if report.pointers.is_empty() {
        writeln!(out, "latest/ pointers: none names {name} {version}")?;
    } else {
        let changed = if report.dry_run {
            "would change"
        } else {
            "changed"
        };
        writeln!(out, "latest/ pointers ({changed}):")?;
        for pointer in &report.pointers {
            let path = printable(&pointer.path);
            match &pointer.after {
                PointerAfter::Moved { version: after, .. } => {
                    writeln!(out, "  {path}: {version} -> {}", printable(after))?;
                }
                PointerAfter::Removed => writeln!(
                    out,
                    "  {path}: {version} -> removed (no release of {name} that still stands \
                     has a flat binary for this target)"
                )?,
            }
        }
    }

    match &report.commit_message {
        Some(message) => writeln!(out, "commit: {}", printable(message))?,
        None => writeln!(out, "commit: none (the log already holds all of this)")?,
    }
    writeln!(
        out,
        "storage is not touched: what it advertises as latest keeps naming a revoked version \
         until another release is published, and clients that check the release log refuse \
         it; publish a fixed release"
    )?;

    if report.dry_run {
        writeln!(out, "(dry run — pass --wetrun to write, commit, and push)")?;
    } else if report.pushed {
        writeln!(out, "pushed, and the pushed commit read back")?;
    } else {
        writeln!(
            out,
            "the remote-tracking ref was already current; the pushed commit read back"
        )?;
    }
    Ok(())
}

fn backfill(opts: &Backfill) -> Result<(), PublishError> {
    let key = load_signing_key(opts.key_file.as_deref())?.key;
    // The releases already in storage: a mistyped path is an error, not a
    // store with nothing to backfill.
    let storage = existing_storage(&opts.storage)?;
    let repo = LogRepo::new(&opts.log_repo);
    let now = fuz_sys::rfc3339_now();

    let report = runtime()?.block_on(backfill_release_log(
        &storage,
        &repo,
        &key,
        &now,
        opts.options(),
    ))?;

    if !opts.quiet {
        print!("{}", render_report(&report));
    }
    Ok(())
}

/// The review of a backfill: every row with its date and targets, the
/// pointers, what storage held that was not logged, and the commit.
///
/// Every value that came from storage is printed through `printable`, so a
/// storage key cannot add a line to the review or drive the terminal.
fn render_report(report: &BackfillReport) -> String {
    let mut out = String::new();
    // Writing to a `String` cannot fail.
    let _ = write_report(&mut out, report);
    out
}

fn write_report(out: &mut String, report: &BackfillReport) -> std::fmt::Result {
    let (will, wrote) = if report.dry_run {
        ("would log", "would write")
    } else {
        ("logged", "wrote")
    };
    writeln!(
        out,
        "release log backfill: {will} {} release(s) at seq {}",
        report.rows.len(),
        report.seq
    )?;
    for row in &report.rows {
        writeln!(
            out,
            "  {} {}  published_at {}",
            printable(&row.name),
            printable(&row.version),
            printable(&row.published_at)
        )?;
        for (target, pins) in &row.targets {
            let content_hash: String = printable(&pins.content_hash)
                .chars()
                .take("v1-".len() + CONTENT_HASH_PREFIX_LEN)
                .collect();
            // Only the self artifact publishes a flat binary, so only its
            // rows can be missing a `sha512`: said for those rows alone, a gap
            // stands out.
            let sha512 = match (&pins.sha512, row.name == SELF_NAME) {
                (Some(_), _) => "  sha512 present",
                (None, true) => "  NO sha512",
                (None, false) => "",
            };
            writeln!(out, "    {}  {content_hash}{sha512}", printable(target))?;
        }
    }

    if report.pointers.is_empty() {
        writeln!(out, "latest/ pointers: none")?;
    } else {
        writeln!(out, "latest/ pointers ({wrote}):")?;
        for pointer in &report.pointers {
            writeln!(
                out,
                "  {} -> fuz {} [{}]",
                printable(&pointer.path),
                printable(&pointer.version),
                printable(&pointer.target)
            )?;
        }
    }

    if !report.missing_flat_binaries.is_empty() {
        writeln!(
            out,
            "self releases with no flat binary in storage (logged without sha512, for good):"
        )?;
        for key in &report.missing_flat_binaries {
            writeln!(out, "  {}", printable(key))?;
        }
    }
    if !report.unaccounted_keys.is_empty() {
        writeln!(out, "keys no release accounts for (not logged):")?;
        for key in &report.unaccounted_keys {
            writeln!(out, "  {}", printable(key))?;
        }
    }
    writeln!(
        out,
        "streams read: {} (nothing else in storage was read)",
        report.streams.join(", ")
    )?;
    writeln!(
        out,
        "head.json: {} bytes (max {})",
        report.head_json.len(),
        report.head_size_max
    )?;
    writeln!(out, "commit: {}", report.commit_message)?;

    if report.dry_run {
        writeln!(
            out,
            "published_at is the earliest signed_at of a release's manifests, which no \
             signature covers: review the dates above"
        )?;
        writeln!(out, "(dry run — pass --wetrun to write, commit, and push)")?;
    } else if report.pushed {
        writeln!(out, "pushed, and the pushed commit read back")?;
    } else {
        writeln!(
            out,
            "the remote-tracking ref was already current; the pushed commit read back"
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use fuz_crypto::ContentHash;
    use fuz_release::{ReleaseRow, RowStatus, TargetRow};
    use fuz_sign::BackfillPointer;

    use super::*;

    const X86: &str = "x86_64-unknown-linux-gnu";

    fn parse(args: &[&str]) -> Result<Backfill, argh::EarlyExit> {
        match ReleaseLog::from_args(&["release-log"], args)?.nested {
            ReleaseLogSub::Backfill(backfill) => Ok(backfill),
            ReleaseLogSub::Revoke(_) => panic!("expected the backfill subcommand"),
        }
    }

    fn parse_revoke(args: &[&str]) -> Result<Revoke, argh::EarlyExit> {
        match ReleaseLog::from_args(&["release-log"], args)?.nested {
            ReleaseLogSub::Revoke(revoke) => Ok(revoke),
            ReleaseLogSub::Backfill(_) => panic!("expected the revoke subcommand"),
        }
    }

    #[test]
    fn backfill_is_a_dry_run_unless_told_otherwise() {
        let args = parse(&["backfill", "--storage", "/s", "--log-repo", "/log"]).unwrap();
        assert_eq!(args.storage, "/s");
        assert_eq!(args.log_repo, PathBuf::from("/log"));
        assert_eq!(args.key_file, None);
        assert!(!args.wetrun, "the default is a dry run");
        assert!(args.dry_run());
        assert!(!args.quiet);
        assert_eq!(
            args.options(),
            BackfillOptions {
                dry_run: true,
                allow_missing_flat: false,
            }
        );
    }

    #[test]
    fn backfill_takes_wetrun_key_file_and_quiet() {
        let args = parse(&[
            "backfill",
            "--storage",
            "ssh://deploy@host/releases",
            "--log-repo",
            "/log",
            "--wetrun",
            "--key-file",
            "/keys/signing.key",
            "-q",
        ])
        .unwrap();
        assert_eq!(args.storage, "ssh://deploy@host/releases");
        assert!(args.wetrun);
        assert!(!args.dry_run());
        assert_eq!(
            args.options(),
            BackfillOptions {
                dry_run: false,
                allow_missing_flat: false,
            }
        );
        assert_eq!(args.key_file, Some(PathBuf::from("/keys/signing.key")));
        assert!(args.quiet);
    }

    #[test]
    fn allow_missing_flat_is_its_own_flag() {
        let args = parse(&[
            "backfill",
            "--storage",
            "/s",
            "--log-repo",
            "/log",
            "--allow-missing-flat",
        ])
        .unwrap();
        assert!(args.allow_missing_flat);
        // It does not turn a review into a write.
        assert_eq!(
            args.options(),
            BackfillOptions {
                dry_run: true,
                allow_missing_flat: true,
            }
        );
    }

    #[test]
    fn backfill_requires_storage_and_a_log_repo() {
        for args in [
            &["backfill"][..],
            &["backfill", "--storage", "/s"],
            &["backfill", "--log-repo", "/log"],
            &[
                "backfill",
                "--storage",
                "/s",
                "--log-repo",
                "/log",
                "--dry-run",
            ],
        ] {
            let exit = parse(args).unwrap_err();
            assert!(exit.status.is_err(), "{args:?} must be refused");
        }
        // The bare namespace needs its subcommand.
        assert!(ReleaseLog::from_args(&["release-log"], &[]).is_err());
    }

    fn report(dry_run: bool) -> BackfillReport {
        let pins = |content: &[u8], flat: bool| TargetRow {
            content_hash: format!("v1-{}", ContentHash::blake3(content).to_hex()),
            binaries: BTreeMap::from([("fuz".to_string(), ContentHash::blake3(content))]),
            sha512: flat.then(|| ContentHash::sha512(content)),
        };
        let row = |name: &str, version: &str, published_at: &str, flat: bool| ReleaseRow {
            name: name.to_string(),
            version: version.to_string(),
            status: RowStatus::Ok,
            published_at: published_at.to_string(),
            targets: BTreeMap::from([(X86.to_string(), pins(version.as_bytes(), flat))]),
        };
        BackfillReport {
            dry_run,
            seq: 1,
            rows: vec![
                row("fuz", "0.1.0", "2025-01-01T00:00:00Z", false),
                row("fuzd", "0.1.0", "2025-01-15T10:30:00Z", false),
                row("fuz", "0.2.0", "2025-02-01T00:00:00Z", true),
            ],
            pointers: vec![BackfillPointer {
                path: format!("latest/fuz-{X86}.sha512"),
                content: "digest  file\n".to_string(),
                version: "0.2.0".to_string(),
                target: X86.to_string(),
            }],
            head_json: "{}\n".to_string(),
            head_size_max: 1_048_576,
            commit_message: "log: backfill 3 releases seq 1".to_string(),
            streams: vec!["fuz".to_string(), "fuzd".to_string()],
            missing_flat_binaries: vec![format!("fuz-0.1.0-{X86}")],
            unaccounted_keys: vec!["fuz-notes.txt".to_string()],
            pushed: !dry_run,
        }
    }

    #[test]
    fn the_dry_run_review_shows_everything_that_would_be_written() {
        let text = render_report(&report(true));
        let content_hash = format!(
            "v1-{}",
            &ContentHash::blake3(b"0.2.0").to_hex()[..CONTENT_HASH_PREFIX_LEN]
        );
        let expected = [
            "release log backfill: would log 3 release(s) at seq 1".to_string(),
            "  fuz 0.1.0  published_at 2025-01-01T00:00:00Z".to_string(),
            "  fuzd 0.1.0  published_at 2025-01-15T10:30:00Z".to_string(),
            "  fuz 0.2.0  published_at 2025-02-01T00:00:00Z".to_string(),
            format!("    {X86}  {content_hash}  sha512 present"),
            "latest/ pointers (would write):".to_string(),
            format!("  latest/fuz-{X86}.sha512 -> fuz 0.2.0 [{X86}]"),
            "self releases with no flat binary in storage (logged without sha512, for good):"
                .to_string(),
            format!("  fuz-0.1.0-{X86}"),
            "keys no release accounts for (not logged):".to_string(),
            "  fuz-notes.txt".to_string(),
            "streams read: fuz, fuzd (nothing else in storage was read)".to_string(),
            "head.json: 3 bytes (max 1048576)".to_string(),
            "commit: log: backfill 3 releases seq 1".to_string(),
            "(dry run — pass --wetrun to write, commit, and push)".to_string(),
        ];
        // Every expected line, in this order.
        let mut lines = text.lines();
        for line in &expected {
            assert!(
                lines.any(|candidate| candidate == line),
                "missing or out of order: {line:?}\n{text}"
            );
        }
        assert!(text.contains("review the dates above"), "{text}");

        // The sha512 status is said for self rows only: the self row without
        // one is marked, the tool row — which never has one — is not.
        let hash_of = |version: &str| {
            format!(
                "v1-{}",
                &ContentHash::blake3(version.as_bytes()).to_hex()[..CONTENT_HASH_PREFIX_LEN]
            )
        };
        let target_lines: Vec<&str> = text.lines().filter(|l| l.starts_with("    ")).collect();
        assert_eq!(
            target_lines,
            [
                format!("    {X86}  {}  NO sha512", hash_of("0.1.0")),
                format!("    {X86}  {}", hash_of("0.1.0")),
                format!("    {X86}  {}  sha512 present", hash_of("0.2.0")),
            ]
        );
    }

    /// Keys storage holds are printed as storage spells them — escaped, so one
    /// that carries a newline, an escape sequence, or a direction override is
    /// still one line that cannot pass for a row.
    #[test]
    fn a_hostile_storage_key_cannot_forge_a_review_line() {
        let clean = render_report(&report(true));
        let hostile = "fuz-x\n  fuz 9.9.9  published_at 2025-01-01T00:00:00Z\x1b[2K\u{202e}";
        let mut forged = report(true);
        forged.unaccounted_keys = vec![hostile.to_string()];
        forged.missing_flat_binaries = vec![hostile.to_string()];
        // A head's own rules keep these out of a row; the printer does not
        // lean on that.
        let row = &mut forged.rows[0];
        row.name = hostile.to_string();
        row.version = hostile.to_string();
        row.published_at = hostile.to_string();
        let mut pins = row.targets[X86].clone();
        pins.content_hash = hostile.to_string();
        row.targets = BTreeMap::from([(hostile.to_string(), pins)]);
        let pointer = &mut forged.pointers[0];
        pointer.path = hostile.to_string();
        pointer.version = hostile.to_string();
        pointer.target = hostile.to_string();
        let text = render_report(&forged);

        assert_eq!(text.lines().count(), clean.lines().count(), "{text}");
        for forbidden in ['\x1b', '\u{202e}', '\r'] {
            assert!(!text.contains(forbidden), "{text:?}");
        }
        assert!(
            !text.lines().any(|line| line.starts_with("  fuz 9.9.9")),
            "{text}"
        );
        let escaped = "  fuz-x\\n  fuz 9.9.9  published_at 2025-01-01T00:00:00Z\\u{1b}[2K\\u{202e}";
        assert_eq!(
            text.lines().filter(|line| *line == escaped).count(),
            2,
            "{text}"
        );
        // Every place the hostile text went prints it escaped, on its line.
        let escaped = escaped.trim_start();
        assert_eq!(text.matches("fuz-x\\n").count(), 10, "{text}");
        assert!(
            text.contains(&format!("  {escaped} {escaped}  published_at {escaped}\n")),
            "{text}"
        );
        assert!(
            text.contains(&format!("  {escaped} -> fuz {escaped} [{escaped}]\n")),
            "{text}"
        );
    }

    #[test]
    fn the_wetrun_report_says_what_was_written() {
        let text = render_report(&report(false));
        assert!(text.starts_with("release log backfill: logged 3 release(s) at seq 1\n"));
        assert!(text.contains("latest/ pointers (wrote):"), "{text}");
        assert!(text.ends_with("pushed, and the pushed commit read back\n"));
        assert!(!text.contains("dry run"), "{text}");

        let mut empty = report(false);
        empty.pointers.clear();
        empty.missing_flat_binaries.clear();
        empty.unaccounted_keys.clear();
        let text = render_report(&empty);
        assert!(text.contains("latest/ pointers: none"), "{text}");
        assert!(!text.contains("not logged"), "{text}");
    }

    #[test]
    fn revoke_is_a_dry_run_unless_told_otherwise() {
        let args = parse_revoke(&["revoke", "fuz", "0.2.0", "--log-repo", "/log"]).unwrap();
        assert_eq!(args.name, "fuz");
        assert_eq!(args.version, "0.2.0");
        assert_eq!(args.log_repo, PathBuf::from("/log"));
        assert_eq!(args.key_file, None);
        assert!(!args.quiet);
        assert_eq!(args.options(), RevokeOptions { dry_run: true });

        let args = parse_revoke(&[
            "revoke",
            "fuzd",
            "0.1.0",
            "--log-repo",
            "/log",
            "--wetrun",
            "--key-file",
            "/keys/signing.key",
            "-q",
        ])
        .unwrap();
        assert_eq!(args.options(), RevokeOptions { dry_run: false });
        assert_eq!(args.key_file, Some(PathBuf::from("/keys/signing.key")));
        assert!(args.quiet);
    }

    #[test]
    fn revoke_requires_a_release_and_a_log_repo_and_takes_no_storage() {
        for args in [
            &["revoke"][..],
            &["revoke", "fuz"],
            &["revoke", "fuz", "0.2.0"],
            &["revoke", "--log-repo", "/log"],
            &["revoke", "fuz", "--log-repo", "/log"],
            &["revoke", "fuz", "0.2.0", "--log-repo", "/log", "--dry-run"],
            // Revocation does not touch storage, so it has no flag for one.
            &[
                "revoke",
                "fuz",
                "0.2.0",
                "--log-repo",
                "/log",
                "--storage",
                "/s",
            ],
        ] {
            let exit = parse_revoke(args).unwrap_err();
            assert!(exit.status.is_err(), "{args:?} must be refused");
        }
    }

    fn revoke_report(dry_run: bool) -> RevokeReport {
        RevokeReport {
            dry_run,
            name: "fuz".to_string(),
            version: "0.2.0".to_string(),
            targets: vec!["aarch64-unknown-linux-gnu".to_string(), X86.to_string()],
            seq: 5,
            revocation: Revocation::Revoked,
            pointers: vec![
                fuz_sign::PointerChange {
                    path: "latest/fuz-aarch64-unknown-linux-gnu.sha512".to_string(),
                    target: "aarch64-unknown-linux-gnu".to_string(),
                    after: PointerAfter::Removed,
                },
                fuz_sign::PointerChange {
                    path: format!("latest/fuz-{X86}.sha512"),
                    target: X86.to_string(),
                    after: PointerAfter::Moved {
                        version: "0.1.0".to_string(),
                        content: "digest  file\n".to_string(),
                    },
                },
            ],
            commit_message: Some("log: revoke fuz 0.2.0 seq 5".to_string()),
            pushed: !dry_run,
        }
    }

    #[test]
    fn the_revoke_review_shows_the_row_the_seq_and_each_pointer() {
        let text = render_revoke_report(&revoke_report(true));
        let expected = [
            "release log revoke: would revoke fuz 0.2.0 at seq 5".to_string(),
            "targets (all revoked together):".to_string(),
            "  aarch64-unknown-linux-gnu".to_string(),
            format!("  {X86}"),
            "latest/ pointers (would change):".to_string(),
            "  latest/fuz-aarch64-unknown-linux-gnu.sha512: 0.2.0 -> removed (no release of fuz \
             that still stands has a flat binary for this target)"
                .to_string(),
            format!("  latest/fuz-{X86}.sha512: 0.2.0 -> 0.1.0"),
            "commit: log: revoke fuz 0.2.0 seq 5".to_string(),
            "(dry run — pass --wetrun to write, commit, and push)".to_string(),
        ];
        let mut lines = text.lines();
        for line in &expected {
            assert!(
                lines.any(|candidate| candidate == line),
                "missing or out of order: {line:?}\n{text}"
            );
        }
        // Storage is left as it is, and the review says so with the remedy.
        assert!(text.contains("storage is not touched"), "{text}");
        assert!(text.contains("publish a fixed release"), "{text}");

        let text = render_revoke_report(&revoke_report(false));
        assert!(text.starts_with("release log revoke: revoked fuz 0.2.0 at seq 5\n"));
        assert!(text.contains("latest/ pointers (changed):"), "{text}");
        assert!(text.ends_with("pushed, and the pushed commit read back\n"));
        assert!(!text.contains("dry run"), "{text}");
    }

    #[test]
    fn a_revoke_with_nothing_to_do_says_so() {
        let mut report = revoke_report(false);
        report.revocation = Revocation::AlreadyRevoked;
        report.pointers.clear();
        report.commit_message = None;
        report.pushed = false;
        let text = render_revoke_report(&report);
        assert!(
            text.starts_with(
                "release log revoke: fuz 0.2.0 is already revoked (head at seq 5); no new head \
                 is signed\n"
            ),
            "{text}"
        );
        assert!(
            text.contains("latest/ pointers: none names fuz 0.2.0\n"),
            "{text}"
        );
        assert!(
            text.contains("commit: none (the log already holds all of this)\n"),
            "{text}"
        );
        assert!(
            text.ends_with(
                "the remote-tracking ref was already current; the pushed commit read back\n"
            ),
            "{text}"
        );

        // Already revoked, with a pointer still to repair: a commit, no head.
        let mut repair = revoke_report(true);
        repair.revocation = Revocation::AlreadyRevoked;
        repair.commit_message = Some("log: latest revoke fuz 0.2.0 seq 5".to_string());
        let text = render_revoke_report(&repair);
        assert!(text.contains("is already revoked"), "{text}");
        assert!(text.contains("latest/ pointers (would change):"), "{text}");
        assert!(
            text.contains("commit: log: latest revoke fuz 0.2.0 seq 5\n"),
            "{text}"
        );
    }

    /// A key holding a blank filler would print as a gap; it is spelled out.
    #[test]
    fn a_storage_key_that_shows_nothing_is_spelled_out() {
        let mut blank = report(true);
        blank.unaccounted_keys = vec!["fuz\u{3164}\u{2800}x\0".to_string()];
        let text = render_report(&blank);
        assert!(
            text.lines()
                .any(|line| line == "  fuz\\u{3164}\\u{2800}x\\u{0}"),
            "{text}"
        );
    }

    /// What the command line and the log hand the review is printed escaped.
    #[test]
    fn a_hostile_release_name_cannot_forge_a_revoke_review_line() {
        let clean = render_revoke_report(&revoke_report(true));
        let hostile = "fuz\nrelease log revoke: revoked everything\x1b[2K\u{202e}";
        let mut forged = revoke_report(true);
        forged.name = hostile.to_string();
        forged.version = hostile.to_string();
        forged.targets = vec![hostile.to_string(), hostile.to_string()];
        forged.commit_message = Some(hostile.to_string());
        for pointer in &mut forged.pointers {
            pointer.path = hostile.to_string();
            if let PointerAfter::Moved { version, .. } = &mut pointer.after {
                *version = hostile.to_string();
            }
        }
        let text = render_revoke_report(&forged);
        assert_eq!(text.lines().count(), clean.lines().count(), "{text}");
        for forbidden in ['\x1b', '\u{202e}', '\r'] {
            assert!(!text.contains(forbidden), "{text:?}");
        }
        assert_eq!(
            text.lines()
                .filter(|line| line.starts_with("release log revoke:"))
                .count(),
            1,
            "{text}"
        );
    }
}
