//! Release log check: hold a release to the public log before using it.
//!
//! A manifest's signature says a release is authentic. It cannot say the
//! release is one the publisher still stands behind, or that the copy this
//! machine was handed is the one everyone else was. The release log
//! ([`crate::release_log`]) is the public record that answers both: every
//! release is a row in one signed, append-only head, and a withdrawn release
//! keeps its row with the status `revoked`.
//!
//! The head is a static file, `head.json`, served by one or more origins —
//! **witnesses**. Before a release's bytes are used, the check here:
//!
//! 1. fetches the head from every configured witness, giving each at most
//!    [`HEAD_FETCH_TIMEOUT`] to serve it, and verifies each one's signature
//!    against the trusted keys built into the binary;
//! 2. requires all the heads it holds — every witness's, and the one cached
//!    from the last check — to be one history at different lengths
//!    ([`check_consistent`]), so a witness can lag but cannot fork the log or
//!    roll it back;
//! 3. requires the release to be a row of the newest of them, not revoked, with
//!    the `content_hash` and binary hashes the signed manifest declares.
//!
//! A witness may also be a **co-signer**: an independent party whose SSH key is
//! built into the binary beside — never among — the release keys, paired with
//! its origin. For such a witness, and only for one, the check also fetches the
//! `witness` file it publishes ([`crate::co_sign`]) and, as part of step 1,
//! requires its co-signature to cover the `head.json` bytes that same witness
//! served, when the two name one `seq`. A co-signature is a beacon, not a gate:
//! one that is absent, or names another `seq` than its witness's head, changes
//! nothing and is never waited for. No witness key
//! is built in today, so no co-signature is requested.
//!
//! The check **fails closed**. A release the log does not record, records
//! differently, or has revoked is refused, and so is a log that contradicts
//! itself. One failure is soft: when no witness can be reached and no cached
//! head covers the release, the result is
//! [`ReleaseLogError::Unconfirmed`] — still an error, nothing is installed, but
//! it says "not confirmed yet", not "refused".
//!
//! # Configuration
//!
//! There is no built-in origin. The check runs only when the caller hands it a
//! [`ReleaseLogPolicy::Enforced`], which [`ReleaseLogPolicy::from_env_values`]
//! builds from the values of two environment variables:
//!
//! - [`RELEASE_LOG_URL_ENV`] — the witnesses: one or more origins separated by
//!   commas, each an `https://` URL (`http://` for a loopback host) or an
//!   existing local directory. Unset or empty leaves the check
//!   [`ReleaseLogPolicy::Inactive`].
//! - [`RELEASE_LOG_ENV`] — `off` is the per-user opt-out
//!   ([`ReleaseLogPolicy::Off`]). Any other value is a configuration error.
//!
//! This module never reads the environment; the binary does, and passes the
//! values in — with the witness keys ([`WitnessKeys`]) the origins are matched
//! against, which for the binary are `fuz_crypto::WITNESS_KEYS`.
//!
//! # Callers
//!
//! - **An install** — `fetch_version` and `install_tool` call
//!   [`check_release_log`] with the release's verified manifest, after version
//!   safety and before any of the release's bytes are fetched or reused.
//! - **A report** — an update check calls [`check_latest_self`] or
//!   [`check_latest_tool`], which resolve the latest release, verify its
//!   manifest, and hold it to the log with [`check_release_log_read_only`].
//!   Same verdicts; nothing under the fuz home is created or written. The
//!   [`LatestCheck`] they return is the only thing a report is rendered from,
//!   so no report exists for a release the log refused.
//! - **A first install** — [`check_bootstrap_binary`] holds a `fuz` binary
//!   that is a file on this machine to the log before it is installed. No
//!   manifest is involved: the row must record the binary's own hash
//!   ([`LocalSelfBinary`]).
//! - **A standing notice** — [`cached_installed_standing`] reads the cached
//!   head alone, with no request to a witness, to say whether the `fuz`
//!   version a command reports has been revoked.
//!
//! # Layers
//!
//! - **Pure** — [`reconcile_heads`] (which head is the effective one),
//!   [`row_verdict`] (what that head says about a release), and
//!   [`crate::co_sign`] (what a co-signature says about the head served
//!   beside it).
//!   Values in, values out.
//! - **Cache** — the last accepted head, at `state/release_log/head.json` under
//!   the fuz home. It is the baseline the next head must contain, and it keeps
//!   a revocation known while offline. Its signature makes it authentic; the
//!   fuz home's permissions keep it from being swapped for an older head.
//! - **Effects** — [`resolve_log`] and [`resolve_log_read_only`] fetch, read
//!   the cache, and reconcile; only [`resolve_log`] writes the cache.
//!   [`check_release_log`], [`check_release_log_read_only`], and
//!   [`check_bootstrap_binary`] put a release's verdict on top.
//!
//! Nothing here prints. A successful check returns a [`ReleaseLogReport`] for
//! the caller to render.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use fuz_crypto::ContentHash;

use fuz_home::{check_fuz_home_not_world_writable, get_state_dir};
use fuz_storage::{Storage, StorageBackend, StorageError, parse_existing_storage};

use crate::current::{CurrentVersion, resolve_current_self, resolve_current_tool};
use crate::fetch::fetch_latest_manifest;
use crate::tool::fetch_tool_manifest;
use fuz_sys::secure_file::{SecureFileError, load_bounded_file};
use fuz_sys::text::{escape_message, truncate};
use fuz_sys::{SECURE_DIR_MODE, SECURE_FILE_MODE};

use crate::co_sign::{
    CoSign, CoSignCoverage, CoSignProblem, CoSignReport, MAX_WITNESS_SIZE, WITNESS_KEY,
    compare_co_sign, verify_co_sign,
};
use crate::error::ReleaseError;
use crate::manifest::{BinaryHashes, VerifiedManifest, current_target};
use crate::release_log::{
    CacheProblem, Head, LogConfigError, LogContradiction, MAX_HEAD_SIZE, PinnedBy, ReleaseLogError,
    RowStatus, TargetField, UnreachableOrigin, VerifiedHead, check_consistent, excerpt, shown,
};

/// The environment variable naming the witnesses. Read by the binary, never
/// here.
pub const RELEASE_LOG_URL_ENV: &str = "FUZ_RELEASE_LOG_URL";

/// The environment variable carrying the opt-out. Read by the binary, never
/// here.
pub const RELEASE_LOG_ENV: &str = "FUZ_RELEASE_LOG";

/// The one value [`RELEASE_LOG_ENV`] takes.
const RELEASE_LOG_OFF: &str = "off";

/// The head document's key at the root of every witness, and its file name in
/// the cache directory.
pub const HEAD_KEY: &str = "head.json";

/// The cache directory's name under the fuz home's state directory.
const CACHE_DIR: &str = "release_log";

/// Longest one witness may take to serve its head — and, for a witness with an
/// embedded witness key that served one, the same again to serve its
/// co-signature.
///
/// So the longest a check waits on its witnesses is this bound once per
/// witness, plus once per witness that has a witness key. A co-signature that
/// has not arrived in time is treated as absent; it is never waited for longer.
///
/// A head is a small static file. The transport's own bounds are sized for
/// artifacts — an idle minute, a total of minutes — and the witnesses are asked
/// one after another, so without this a silent witness would hold an install
/// for as long as the transport allows, once per witness. A witness that runs
/// out the bound is unreachable, like one that refuses the connection.
///
/// The bound is on a network witness. A local directory is read with ordinary
/// file IO, which a filesystem that stops answering can hold past it.
pub const HEAD_FETCH_TIMEOUT: Duration = Duration::from_secs(20);

/// Most bytes of a transport failure's message a report or error carries.
const MAX_REASON_LEN: usize = 256;

//
// Configuration
//

/// The witness keys a list of origins is matched against.
///
/// Each is an origin and the 32-byte ed25519 SSH public key of the co-signer
/// serving it — the shape of `fuz_crypto::WITNESS_KEYS`, which is what the
/// `fuz` binary passes.
///
/// An origin is matched by `fuz_crypto::witness_key_for`: exactly as
/// configured (after the list's whitespace trimming), except that trailing
/// slashes are ignored on both sides. There is no case folding and no URL
/// equivalence, so a configured origin spelled differently from the embedded
/// one is a witness without a key — its co-signature is not requested.
pub type WitnessKeys<'a> = &'a [(&'a str, [u8; 32])];

/// One witness: an origin serving `head.json` at its root — an `https://` URL
/// (`http://` for a loopback host) or an existing local directory.
#[derive(Debug)]
pub struct LogOrigin {
    uri: String,
    storage: StorageBackend,
    /// The co-signer's key, when one is known for this origin.
    witness_key: Option<[u8; 32]>,
}

impl LogOrigin {
    /// The location as configured, bounded and escaped for display.
    #[must_use]
    pub fn uri(&self) -> &str {
        &self.uri
    }

    /// The witness key matched to this origin, if any. Only an origin with
    /// one is asked for a co-signature.
    #[must_use]
    pub const fn witness_key(&self) -> Option<&[u8; 32]> {
        self.witness_key.as_ref()
    }
}

/// The configured witnesses — never empty.
///
/// Built only by [`ReleaseLogPolicy::from_env_values`], so an enforced check
/// with nothing to consult is unrepresentable.
#[derive(Debug)]
pub struct LogOrigins(Vec<LogOrigin>);

impl LogOrigins {
    /// Parse a comma-separated list of origins. Whitespace around an entry is
    /// trimmed and empty entries are skipped; `None` when nothing is left.
    ///
    /// An origin is an `https://` URL (`http://` for a loopback host) or a
    /// local directory that exists. Naming one changes nothing on disk, and a
    /// missing directory is an error — otherwise a mistyped entry would read
    /// as a witness that is merely unreachable. `forge://` and `ssh://` are
    /// refused: a head is a public file, and neither is a way to serve one.
    ///
    /// Each origin is paired with its witness key from `witness_keys`, if it
    /// has one ([`WitnessKeys`]).
    fn parse(list: &str, witness_keys: WitnessKeys<'_>) -> Result<Option<Self>, LogConfigError> {
        let mut origins = Vec::new();
        for uri in list.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            let invalid = |refusal| LogConfigError::InvalidOrigin {
                position: origins.len() + 1,
                refusal,
            };
            // Refused by prefix, before the backend is built: constructing a
            // `forge://` backend resolves a bearer token.
            if uri.starts_with("forge://") || uri.starts_with("ssh://") {
                return Err(invalid(StorageError::InvalidConfig {
                    message: "a release log origin is an https:// URL or a local directory"
                        .to_string(),
                }));
            }
            let storage = parse_existing_storage(uri).map_err(invalid)?;
            origins.push(LogOrigin {
                uri: shown(uri),
                storage,
                // Matched on the entry itself, not on its display form.
                witness_key: fuz_crypto::witness_key_for(uri, witness_keys),
            });
        }
        Ok((!origins.is_empty()).then_some(Self(origins)))
    }

    /// The witnesses, in configuration order.
    #[must_use]
    pub fn as_slice(&self) -> &[LogOrigin] {
        &self.0
    }
}

/// Whether, and against which witnesses, a release is held to the release log.
#[derive(Debug, Default)]
pub enum ReleaseLogPolicy {
    /// No witness is configured. No check, no network, no cache, no output.
    #[default]
    Inactive,
    /// Witnesses are configured and the user opted out. No check; the caller
    /// says so once.
    Off,
    /// Every release is held to the log these witnesses serve.
    Enforced(LogOrigins),
}

impl ReleaseLogPolicy {
    /// Build the policy from the values of [`RELEASE_LOG_URL_ENV`] and
    /// [`RELEASE_LOG_ENV`] (`None` for an unset variable).
    ///
    /// - The switch is a closed set: unset, empty, or exactly `off`. Anything
    ///   else — `OFF`, `0`, `false`, ` off ` — is an error whatever the URL is,
    ///   so a typo never reads as "on" or as "off".
    /// - No URL (unset, empty, or only separators) is
    ///   [`Inactive`](Self::Inactive); `off` then changes nothing.
    /// - A URL with `off` is [`Off`](Self::Off). The list is not parsed: the
    ///   opt-out has to work when the list itself is what is broken.
    /// - Otherwise every entry must be an origin — an `https://` URL (`http://`
    ///   for a loopback host) or an existing local directory — and the result
    ///   is [`Enforced`](Self::Enforced).
    ///
    /// `witness_keys` are the co-signer keys the origins are matched against
    /// ([`WitnessKeys`]); an origin with a key has its co-signature checked.
    /// With none, no co-signature is ever requested.
    ///
    /// Building the policy makes no request and changes nothing on disk.
    ///
    /// # Errors
    ///
    /// [`ReleaseLogError::Config`] for a switch value outside the set or an
    /// entry that is not an origin.
    pub fn from_env_values(
        url: Option<&str>,
        switch: Option<&str>,
        witness_keys: WitnessKeys<'_>,
    ) -> Result<Self, ReleaseLogError> {
        let off = match switch {
            None | Some("") => false,
            Some(RELEASE_LOG_OFF) => true,
            Some(other) => {
                return Err(LogConfigError::InvalidSwitch {
                    value: excerpt(other),
                }
                .into());
            }
        };
        let list = url.unwrap_or_default();
        if list.split(',').all(|entry| entry.trim().is_empty()) {
            return Ok(Self::Inactive);
        }
        if off {
            return Ok(Self::Off);
        }
        Ok(LogOrigins::parse(list, witness_keys)?.map_or(Self::Inactive, Self::Enforced))
    }
}

//
// Pure: which head is effective
//

/// Where the head a verdict was read from came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeadSource {
    /// A witness, fetched by this check. It is at least as new as the cache.
    Witness,
    /// The cache, because every reachable witness serves an older head of the
    /// same history. The cached head is the newer verified statement.
    CacheAheadOfWitness,
    /// The cache, because no witness could be reached.
    CacheWitnessUnreachable,
}

/// The head a verdict is read from, and how it was chosen.
#[derive(Debug, Clone)]
pub struct EffectiveHead {
    head: VerifiedHead,
    source: HeadSource,
    /// The head is a witness's and is strictly newer than the cache (or there
    /// is no cache): the one case in which the cache is written.
    advances_cache: bool,
}

impl EffectiveHead {
    /// The head.
    #[must_use]
    pub const fn head(&self) -> &VerifiedHead {
        &self.head
    }

    /// Where it came from.
    #[must_use]
    pub const fn source(&self) -> HeadSource {
        self.source
    }

    /// Whether this head is newer than the cached one, or there is none.
    #[must_use]
    pub const fn advances_cache(&self) -> bool {
        self.advances_cache
    }
}

/// Choose the effective head from the cached head and the witnesses' heads.
///
/// Every head is held against every other, the cache included: any two must be
/// one history at different lengths ([`check_consistent`]). All pairs are
/// compared, not each head against the newest alone — two stale heads can each
/// be contained in a third and still disagree with one another.
///
/// Then the newest wins. Between a witness's head and an identical cached one
/// the witness's is used; a cached head that is ahead of every witness is
/// used in their place, since a witness that lags is not a contradiction and
/// the cache is the newer verified statement.
///
/// `witnessed` pairs each head with the origin that served it. Returns `None`
/// when there is no head at all.
///
/// # Errors
///
/// [`LogContradiction::SupersetViolated`] when a witness's head and the cached
/// one are irreconcilable, [`LogContradiction::HeadsDiverge`] when two
/// witnesses' heads are.
pub fn reconcile_heads(
    cached: Option<VerifiedHead>,
    witnessed: Vec<(String, VerifiedHead)>,
) -> Result<Option<EffectiveHead>, LogContradiction> {
    if let Some(cached) = &cached {
        for (origin, head) in &witnessed {
            check_consistent(cached, head).map_err(|violation| {
                LogContradiction::SupersetViolated {
                    origin: origin.clone(),
                    violation: Box::new(violation),
                }
            })?;
        }
    }
    for (index, (first, a)) in witnessed.iter().enumerate() {
        for (second, b) in &witnessed[index + 1..] {
            check_consistent(a, b).map_err(|violation| LogContradiction::HeadsDiverge {
                first: first.clone(),
                second: second.clone(),
                violation: Box::new(violation),
            })?;
        }
    }

    // The first of the witnesses' heads with the greatest `seq`; equal `seq`
    // was just shown to mean equal content.
    let mut newest: Option<VerifiedHead> = None;
    for (_, head) in witnessed {
        if newest.as_ref().is_none_or(|n| head.seq() > n.seq()) {
            newest = Some(head);
        }
    }

    Ok(match (cached, newest) {
        (None, None) => None,
        (None, Some(head)) => Some(EffectiveHead {
            head,
            source: HeadSource::Witness,
            advances_cache: true,
        }),
        (Some(head), None) => Some(EffectiveHead {
            head,
            source: HeadSource::CacheWitnessUnreachable,
            advances_cache: false,
        }),
        (Some(cached), Some(fresh)) => Some(match cached.seq().cmp(&fresh.seq()) {
            std::cmp::Ordering::Less => EffectiveHead {
                head: fresh,
                source: HeadSource::Witness,
                advances_cache: true,
            },
            std::cmp::Ordering::Equal => EffectiveHead {
                head: fresh,
                source: HeadSource::Witness,
                advances_cache: false,
            },
            std::cmp::Ordering::Greater => EffectiveHead {
                head: cached,
                source: HeadSource::CacheAheadOfWitness,
                advances_cache: false,
            },
        }),
    })
}

//
// Pure: what a head says about a release
//

/// What a release is held to the log with, as the log records it: the
/// release's name, version, and target, and the hashes compared against the
/// row.
///
/// Each thing that can vouch for those values has its own constructor: a
/// [`VerifiedManifest`] ([`of`](Self::of)), so a manifest whose signature was
/// never checked cannot be confirmed against the log, and the bytes of a binary
/// on this machine ([`of_local_self_binary`](Self::of_local_self_binary)).
#[derive(Debug, Clone, Copy)]
pub struct ReleasePins<'a> {
    name: &'a str,
    version: &'a str,
    target: &'a str,
    content_hash: &'a str,
    binaries: &'a BinaryHashes,
    pinned_by: PinnedBy,
}

impl<'a> ReleasePins<'a> {
    /// The pins of `manifest`. The row name is the manifest's tool, or
    /// [`crate::SELF_NAME`] for the self artifact.
    #[must_use]
    pub fn of(manifest: &'a VerifiedManifest) -> Self {
        Self {
            name: manifest.tool.as_deref().unwrap_or(crate::SELF_NAME),
            version: &manifest.version,
            target: &manifest.target,
            content_hash: &manifest.content_hash,
            binaries: &manifest.binaries,
            pinned_by: PinnedBy::SignedManifest,
        }
    }

    /// The pins of a `fuz` binary that is a file on this machine.
    ///
    /// **No signature vouches for these values.** The hashes are computed from
    /// local bytes and the version is the one the caller states for them. They
    /// only select a row and say what it must contain, so the statement a
    /// confirmation rests on is the log's alone: a trusted-signed head records
    /// exactly these bytes as that release. A binary the log does not record
    /// is refused, which is the point — and why a locally built binary is not
    /// confirmable.
    #[must_use]
    pub fn of_local_self_binary(binary: &'a LocalSelfBinary) -> Self {
        Self {
            name: crate::SELF_NAME,
            version: &binary.version,
            target: current_target(),
            content_hash: &binary.content_hash,
            binaries: &binary.binaries,
            pinned_by: PinnedBy::LocalBinary,
        }
    }

    /// The release's row name.
    #[must_use]
    pub const fn name(&self) -> &'a str {
        self.name
    }

    /// The release's version.
    #[must_use]
    pub const fn version(&self) -> &'a str {
        self.version
    }

    /// The release's target triple.
    #[must_use]
    pub const fn target(&self) -> &'a str {
        self.target
    }
}

/// A `fuz` binary on this machine, in the terms the log records a release in:
/// a version, and the hashes of a self artifact holding exactly that binary.
///
/// The self artifact is one binary ([`crate::SELF_BINARIES`]), so the binary's
/// BLAKE3 determines both compared fields: the `binaries` map is that one
/// entry, and `content_hash` is the artifact content hash of it
/// ([`fuz_artifact::content_hash_from_binaries`]).
#[derive(Debug, Clone)]
pub struct LocalSelfBinary {
    version: String,
    content_hash: String,
    binaries: BinaryHashes,
}

impl LocalSelfBinary {
    /// `version` is the version the binary carries; `blake3` is the BLAKE3 of
    /// its bytes — the bytes that are about to be installed, hashed by the
    /// caller from wherever it installs them from.
    #[must_use]
    pub fn new(version: &str, blake3: ContentHash) -> Self {
        let sorted = BTreeMap::from([(crate::SELF_NAME.to_string(), blake3.clone())]);
        Self {
            version: version.to_string(),
            content_hash: fuz_artifact::content_hash_from_binaries(&sorted),
            binaries: BinaryHashes::from([(crate::SELF_NAME.to_string(), blake3)]),
        }
    }
}

/// What one head says about one release.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RowVerdict {
    /// The row and target are recorded, in good standing, with the pinned
    /// hashes.
    Confirmed,
    /// The row is recorded as revoked.
    Revoked,
    /// The head has no row for the release, or its row lacks the target.
    Missing,
    /// The row and target are recorded with a different value in this field.
    Mismatch(TargetField),
}

/// Read `release`'s verdict off `head`.
///
/// A revoked row is [`RowVerdict::Revoked`] before its targets are looked at:
/// the release is withdrawn whatever was published for it. The compared fields
/// are `content_hash`, exactly, and `binaries` as whole maps — the same names
/// with the same hashes, so a binary the log does not list is a mismatch as
/// much as one it hashes differently. The row's `sha512` is not compared: it
/// pins the flat binary a shell installer downloads, which no manifest
/// declares.
///
/// The two fields are compared the same way whatever vouches for the pins. A
/// release's standing alone, with no hashes to compare, is [`is_revoked`].
#[must_use]
pub fn row_verdict(head: &VerifiedHead, release: &ReleasePins<'_>) -> RowVerdict {
    let Some(row) = head.row(release.name, release.version) else {
        return RowVerdict::Missing;
    };
    if row.status == RowStatus::Revoked {
        return RowVerdict::Revoked;
    }
    let Some(target) = row.targets.get(release.target) else {
        return RowVerdict::Missing;
    };
    if target.content_hash != release.content_hash {
        return RowVerdict::Mismatch(TargetField::ContentHash);
    }
    let same_binaries = target.binaries.len() == release.binaries.len()
        && target
            .binaries
            .iter()
            .all(|(name, hash)| release.binaries.get(name) == Some(hash));
    if !same_binaries {
        return RowVerdict::Mismatch(TargetField::Binaries);
    }
    RowVerdict::Confirmed
}

//
// The resolved log and its report
//

/// What a successful check consulted and concluded — for the caller to render.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseLogReport {
    /// The effective head's `seq` — the number two readers compare to tell
    /// whether they were shown the same log.
    pub seq: u64,
    /// The effective head's `signed_at`. **Publisher-asserted and not covered
    /// by the signature**: informational, and to be labelled so wherever it is
    /// shown.
    pub signed_at: String,
    /// Where the effective head came from.
    pub source: HeadSource,
    /// The witnesses that served a verified head, in configuration order.
    pub answered: Vec<String>,
    /// The witnesses that could not be reached.
    pub unreachable: Vec<UnreachableOrigin>,
    /// Whether this check wrote the cache.
    pub cache_written: bool,
    /// The verified co-signatures the check saw, in configuration order of
    /// the witnesses that served them. Empty unless a witness has a witness
    /// key and serves a co-signature.
    pub co_signs: Vec<CoSignReport>,
}

/// The outcome of a check that did not refuse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogCheck {
    /// The policy is [`ReleaseLogPolicy::Inactive`]: nothing was checked.
    Inactive,
    /// The policy is [`ReleaseLogPolicy::Off`]: nothing was checked, by the
    /// user's opt-out.
    Off,
    /// The release is confirmed by the log.
    Confirmed(ReleaseLogReport),
}

/// The log as one check sees it: the effective head, if any, and which
/// witnesses answered.
#[derive(Debug, Clone)]
pub struct ResolvedLog {
    effective: Option<EffectiveHead>,
    answered: Vec<String>,
    unreachable: Vec<UnreachableOrigin>,
    cache_written: bool,
    co_signs: Vec<CoSignReport>,
}

impl ResolvedLog {
    /// The effective head: the newest verified head among the witnesses' and
    /// the cached one. `None` when no witness answered and nothing is cached.
    #[must_use]
    pub fn head(&self) -> Option<&VerifiedHead> {
        self.effective.as_ref().map(EffectiveHead::head)
    }

    /// Where the effective head came from, if there is one.
    #[must_use]
    pub fn source(&self) -> Option<HeadSource> {
        self.effective.as_ref().map(EffectiveHead::source)
    }

    /// The witnesses that served a verified head.
    #[must_use]
    pub fn answered(&self) -> &[String] {
        &self.answered
    }

    /// The witnesses that could not be reached.
    #[must_use]
    pub fn unreachable(&self) -> &[UnreachableOrigin] {
        &self.unreachable
    }

    /// Whether resolving this log wrote the cache.
    #[must_use]
    pub const fn cache_written(&self) -> bool {
        self.cache_written
    }

    /// The verified co-signatures this check saw, each with what it was
    /// covers. A co-signature that did not cover the head served beside it is
    /// not here: it failed the resolve.
    #[must_use]
    pub fn co_signs(&self) -> &[CoSignReport] {
        &self.co_signs
    }

    /// Hold `release` to this log.
    ///
    /// | Effective head | Row | Result |
    /// |---|---|---|
    /// | any | recorded, `ok`, same hashes | the report |
    /// | any | `revoked` | [`ReleaseLogError::Revoked`] |
    /// | any | recorded, different hashes | [`LogContradiction::HashMismatch`] |
    /// | a witness answered | row or target absent | [`ReleaseLogError::RowMissing`] |
    /// | cache only, no witness reachable | row or target absent | [`ReleaseLogError::Unconfirmed`] |
    /// | none | — | [`ReleaseLogError::Unconfirmed`] |
    ///
    /// An absent row is a refusal only when a witness was reachable: a cached
    /// head predating the release cannot say the release is unlogged.
    ///
    /// # Errors
    ///
    /// Per the table.
    pub fn confirm(&self, release: &ReleasePins<'_>) -> Result<ReleaseLogReport, ReleaseLogError> {
        let name = || shown(release.name);
        let version = || shown(release.version);
        let target = || shown(release.target);
        let unconfirmed = || ReleaseLogError::Unconfirmed {
            name: name(),
            version: version(),
            target: target(),
            witnesses: self.unreachable.clone(),
        };

        let Some(effective) = &self.effective else {
            return Err(unconfirmed());
        };
        match row_verdict(&effective.head, release) {
            RowVerdict::Confirmed => Ok(ReleaseLogReport {
                seq: effective.head.seq(),
                signed_at: effective.head.signature().signed_at.clone(),
                source: effective.source,
                answered: self.answered.clone(),
                unreachable: self.unreachable.clone(),
                cache_written: self.cache_written,
                co_signs: self.co_signs.clone(),
            }),
            RowVerdict::Revoked => Err(ReleaseLogError::Revoked {
                name: name(),
                version: version(),
            }),
            RowVerdict::Mismatch(field) => Err(LogContradiction::HashMismatch {
                name: name(),
                version: version(),
                target: target(),
                field,
                pinned_by: release.pinned_by,
            }
            .into()),
            RowVerdict::Missing => match effective.source {
                HeadSource::Witness | HeadSource::CacheAheadOfWitness => {
                    Err(ReleaseLogError::RowMissing {
                        name: name(),
                        version: version(),
                        target: target(),
                        pinned_by: release.pinned_by,
                    })
                }
                HeadSource::CacheWitnessUnreachable => Err(unconfirmed()),
            },
        }
    }
}

//
// Effects: fetch, cache, resolve
//

/// The cached head's path: `state/release_log/head.json` under the fuz home.
///
/// # Errors
///
/// Fails only when the fuz home cannot be resolved.
pub fn head_cache_path() -> Result<PathBuf, ReleaseError> {
    Ok(get_state_dir()?.join(CACHE_DIR).join(HEAD_KEY))
}

/// Resolve the log for a caller that is about to write under the fuz home: an
/// install.
///
/// Fetches `head.json` from every witness, reads the cached head, and
/// reconciles them ([`reconcile_heads`]). When a witness's head is strictly
/// newer than the cache, or nothing is cached, that head is written to the
/// cache — before any release is held to it, so a revocation seen once stays
/// known offline whatever the verdict on this release.
///
/// Refuses a world-writable fuz home first, before any request to a witness:
/// the cache lives under it.
///
/// # Errors
///
/// [`ReleaseError::FuzHome`] for an unusable home; otherwise a
/// [`ReleaseLogError`]: `WitnessHead` when a witness serves an unusable head
/// and `WitnessCoSign` when one with a witness key serves an unusable
/// co-signature (neither is ever skipped in favor of another witness),
/// `Contradiction` when the heads are not one history or a witness serves a
/// head its own co-signature does not cover, `CacheUnusable` when the cached head exists and cannot
/// be used or a newer one cannot be written, `Config` when an origin cannot
/// serve a head at all. Unreachable witnesses are not an error here.
pub async fn resolve_log(origins: &LogOrigins) -> Result<ResolvedLog, ReleaseError> {
    check_fuz_home_not_world_writable()?;
    let path = head_cache_path()?;
    let mut log = observe_log(origins, &path, HEAD_FETCH_TIMEOUT).await?;
    if let Some(effective) = &log.effective
        && effective.advances_cache
    {
        write_cached_head(&path, &effective.head)?;
        log.cache_written = true;
    }
    Ok(log)
}

/// Resolve the log without writing anything: [`resolve_log`] for a caller that
/// only reports.
///
/// Reads the cached head and uses it exactly as [`resolve_log`] does, and
/// leaves it as it is — no directory is created, no file written, and the fuz
/// home's mode is not checked, since nothing lands in it.
///
/// # Errors
///
/// As [`resolve_log`], without the home refusal and the cache write failure.
pub async fn resolve_log_read_only(origins: &LogOrigins) -> Result<ResolvedLog, ReleaseError> {
    Ok(observe_log(origins, &head_cache_path()?, HEAD_FETCH_TIMEOUT).await?)
}

/// Hold the release `manifest` describes to the log, for an install.
///
/// [`ReleaseLogPolicy::Inactive`] and [`ReleaseLogPolicy::Off`] return at once
/// — no request, no cache read. Under [`ReleaseLogPolicy::Enforced`] the log is
/// resolved with [`resolve_log`] and the release confirmed with
/// [`ResolvedLog::confirm`].
///
/// # Errors
///
/// As [`resolve_log`] and [`ResolvedLog::confirm`].
pub async fn check_release_log(
    policy: &ReleaseLogPolicy,
    manifest: &VerifiedManifest,
) -> Result<LogCheck, ReleaseError> {
    match policy {
        ReleaseLogPolicy::Inactive => Ok(LogCheck::Inactive),
        ReleaseLogPolicy::Off => Ok(LogCheck::Off),
        ReleaseLogPolicy::Enforced(origins) => {
            let log = resolve_log(origins).await?;
            Ok(LogCheck::Confirmed(
                log.confirm(&ReleasePins::of(manifest))?,
            ))
        }
    }
}

/// [`check_release_log`] for a caller that only reports: the log is resolved
/// with [`resolve_log_read_only`], so nothing under the fuz home changes.
///
/// An update check reaches it through [`check_latest_self`] /
/// [`check_latest_tool`].
///
/// # Errors
///
/// As [`resolve_log_read_only`] and [`ResolvedLog::confirm`].
pub async fn check_release_log_read_only(
    policy: &ReleaseLogPolicy,
    manifest: &VerifiedManifest,
) -> Result<LogCheck, ReleaseError> {
    match policy {
        ReleaseLogPolicy::Inactive => Ok(LogCheck::Inactive),
        ReleaseLogPolicy::Off => Ok(LogCheck::Off),
        ReleaseLogPolicy::Enforced(origins) => {
            let log = resolve_log_read_only(origins).await?;
            Ok(LogCheck::Confirmed(
                log.confirm(&ReleasePins::of(manifest))?,
            ))
        }
    }
}

/// The latest release of one stream, held to the release log, with the install
/// state it is compared against: what an update check reports.
///
/// Built only by [`check_latest_self`] / [`check_latest_tool`], so no report
/// exists for a release the log refused.
#[derive(Debug)]
pub struct LatestCheck {
    manifest: VerifiedManifest,
    current: CurrentVersion,
    release_log: LogCheck,
}

impl LatestCheck {
    /// The latest release's verified manifest.
    #[must_use]
    pub const fn manifest(&self) -> &VerifiedManifest {
        &self.manifest
    }

    /// The install state the latest release is compared against.
    #[must_use]
    pub const fn current(&self) -> &CurrentVersion {
        &self.current
    }

    /// What the release log check did for the latest release.
    #[must_use]
    pub const fn release_log(&self) -> &LogCheck {
        &self.release_log
    }
}

/// Resolve the latest self release, verify its manifest, and hold it to the
/// log. Writes nothing under the fuz home.
///
/// The log is consulted whatever the install state is — when the latest
/// release is the installed one too: the latest release is what the report
/// vouches for, and that is where a revocation of the installed version
/// surfaces. A release the log refuses is an error here, so it is never
/// reported as an available update or as up to date.
///
/// # Errors
///
/// As [`fetch_latest_manifest`] and [`check_release_log_read_only`].
pub async fn check_latest_self(
    storage: &impl Storage,
    policy: &ReleaseLogPolicy,
) -> Result<LatestCheck, ReleaseError> {
    let manifest = fetch_latest_manifest(storage).await?;
    let release_log = check_release_log_read_only(policy, &manifest).await?;
    let current = resolve_current_self()?;
    Ok(LatestCheck {
        manifest,
        current,
        release_log,
    })
}

/// [`check_latest_self`] for the tool `name`.
///
/// # Errors
///
/// As [`fetch_tool_manifest`] and [`check_release_log_read_only`].
pub async fn check_latest_tool(
    storage: &impl Storage,
    name: &str,
    policy: &ReleaseLogPolicy,
) -> Result<LatestCheck, ReleaseError> {
    let manifest = fetch_tool_manifest(storage, name, None).await?;
    let release_log = check_release_log_read_only(policy, &manifest).await?;
    Ok(LatestCheck {
        manifest,
        current: resolve_current_tool(name),
        release_log,
    })
}

/// Hold a `fuz` binary on this machine to the log before it is installed: the
/// check of a first install, where there is no manifest and no earlier `fuz`.
///
/// The row for [`crate::SELF_NAME`] at the binary's version must exist, be in
/// good standing, and record this target with exactly the binary's hashes (see
/// [`LocalSelfBinary`]). The log is resolved with [`resolve_log`] — the caller
/// is about to write under the fuz home, so the home guard runs and a newer
/// head is cached — and the verdict is [`ResolvedLog::confirm`]'s, unchanged:
/// a revoked or unrecorded binary and a hash mismatch are refusals, and no
/// reachable witness with no covering cache is
/// [`ReleaseLogError::Unconfirmed`].
///
/// [`ReleaseLogPolicy::Inactive`] and [`ReleaseLogPolicy::Off`] return at once.
///
/// # Errors
///
/// As [`resolve_log`] and [`ResolvedLog::confirm`].
pub async fn check_bootstrap_binary(
    policy: &ReleaseLogPolicy,
    binary: &LocalSelfBinary,
) -> Result<LogCheck, ReleaseError> {
    match policy {
        ReleaseLogPolicy::Inactive => Ok(LogCheck::Inactive),
        ReleaseLogPolicy::Off => Ok(LogCheck::Off),
        ReleaseLogPolicy::Enforced(origins) => {
            let log = resolve_log(origins).await?;
            Ok(LogCheck::Confirmed(
                log.confirm(&ReleasePins::of_local_self_binary(binary))?,
            ))
        }
    }
}

//
// The installed release's standing, from the cache alone
//

/// Whether `head` records release `(name, version)` as revoked.
///
/// Standing belongs to the row, not to a target: a revocation withdraws the
/// release for every target it was published for. A release the head does not
/// record is not revoked.
#[must_use]
pub fn is_revoked(head: &VerifiedHead, name: &str, version: &str) -> bool {
    head.row(name, version)
        .is_some_and(|row| row.status == RowStatus::Revoked)
}

/// What the cached head says about one version of `fuz` — the one a `fuz self`
/// command reports: the installed artifact's, or the running binary's own when
/// nothing is installed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InstalledStanding {
    /// The cached head's `seq`.
    pub seq: u64,
    /// The version is a row of the cached head, and that row is revoked.
    /// `false` when no version was given or the head has no such row.
    pub revoked: bool,
}

/// Read a `fuz` version's standing off `head`. `installed_version` is the
/// version the caller reports, or `None` when it has none to report.
///
/// The release is identified by its version alone, as a row is: a locally
/// built `fuz` carrying a revoked release's version reads as revoked too.
#[must_use]
pub fn installed_standing(
    head: &VerifiedHead,
    installed_version: Option<&str>,
) -> InstalledStanding {
    InstalledStanding {
        seq: head.seq(),
        revoked: installed_version
            .is_some_and(|version| is_revoked(head, crate::SELF_NAME, version)),
    }
}

/// A `fuz` version's standing according to the cached head — no witness is
/// asked and nothing is written.
///
/// `Ok(None)` unless the policy is [`ReleaseLogPolicy::Enforced`] and a cached
/// head exists: an inactive or opted-out policy reads nothing, and a machine
/// that has never completed a check has no head to read. The cached head is
/// read exactly as a check reads it — no-follow, bounded, signature verified.
///
/// # Errors
///
/// [`ReleaseLogError::CacheUnusable`] for a cache that exists and cannot be
/// used; [`ReleaseError::FuzHome`] when the fuz home cannot be resolved.
pub fn cached_installed_standing(
    policy: &ReleaseLogPolicy,
    installed_version: Option<&str>,
) -> Result<Option<InstalledStanding>, ReleaseError> {
    if !matches!(policy, ReleaseLogPolicy::Enforced(_)) {
        return Ok(None);
    }
    let cached = read_cached_head(&head_cache_path()?)?;
    Ok(cached.map(|head| installed_standing(&head, installed_version)))
}

/// Read the cache, fetch every witness, and reconcile. Writes nothing — the
/// shared body of [`resolve_log`] and [`resolve_log_read_only`]; no
/// co-signature is ever stored. `fetch_timeout` is the time each witness has to
/// serve its head, and again to serve its co-signature
/// ([`HEAD_FETCH_TIMEOUT`]).
async fn observe_log(
    origins: &LogOrigins,
    cache: &Path,
    fetch_timeout: Duration,
) -> Result<ResolvedLog, ReleaseLogError> {
    // The cache first: an unusable one refuses the check on its own, so there
    // is nothing to ask a witness.
    let cached = read_cached_head(cache)?;

    let mut witnessed = Vec::new();
    let mut unreachable = Vec::new();
    let mut co_signs: Vec<SeenCoSign> = Vec::new();
    // One witness at a time, in configuration order. A bad head stops the
    // check at once: it is never passed over in favor of the next witness.
    // The same holds for a bad co-signature, and for one that does not cover
    // the head served beside it.
    for origin in origins.as_slice() {
        match fetch_head(origin, fetch_timeout).await? {
            Fetched::Head { head, served } => {
                // Only a witness with a key, and only once it has served a
                // usable head: without a key there is no request at all.
                if let Some(key) = &origin.witness_key
                    && let Some(co_sign) = fetch_co_sign(origin, key, fetch_timeout).await?
                {
                    // Against this witness's own served bytes, and no other
                    // head: what its co-signer hashed.
                    let covers_served_head =
                        compare_co_sign(&origin.uri, &co_sign, head.seq(), &served)?;
                    co_signs.push(SeenCoSign {
                        origin: origin.uri.clone(),
                        seq: co_sign.seq(),
                        covers_served_head,
                    });
                }
                witnessed.push((origin.uri.clone(), *head));
            }
            Fetched::Unreachable(reason) => unreachable.push(UnreachableOrigin {
                origin: origin.uri.clone(),
                reason,
            }),
        }
    }

    let answered = witnessed.iter().map(|(origin, _)| origin.clone()).collect();
    let effective = reconcile_heads(cached, witnessed)?;
    let co_signs = report_co_signs(co_signs, effective.as_ref());
    Ok(ResolvedLog {
        effective,
        answered,
        unreachable,
        cache_written: false,
        co_signs,
    })
}

/// A verified co-signature, held to the head its own witness served.
struct SeenCoSign {
    origin: String,
    seq: u64,
    /// It names the `seq` and the digest of the head served beside it.
    covers_served_head: bool,
}

/// Say what each verified co-signature covers, now that the effective head is
/// known.
///
/// A co-signature covers its own witness's served head or nothing. When it
/// does, that head has passed [`reconcile_heads`] with every other head held,
/// so one with the effective head's `seq` has the effective head's signed
/// content; one with a lower `seq` is an older state of the same history.
fn report_co_signs(seen: Vec<SeenCoSign>, effective: Option<&EffectiveHead>) -> Vec<CoSignReport> {
    seen.into_iter()
        .map(|co_sign| {
            let coverage = if !co_sign.covers_served_head {
                CoSignCoverage::Uncompared
            } else if effective.is_some_and(|e| e.head.seq() == co_sign.seq) {
                CoSignCoverage::EffectiveHead
            } else {
                CoSignCoverage::OlderHead
            };
            CoSignReport {
                origin: co_sign.origin,
                seq: co_sign.seq,
                coverage,
            }
        })
        .collect()
}

/// Fetch and verify the co-signature of a witness that has a witness key: its
/// `witness` file, bounded at [`MAX_WITNESS_SIZE`].
///
/// `Ok(None)` when the witness serves none: the file is absent, the witness
/// cannot be reached for it, or it has not arrived within `timeout`. A
/// co-signature is a beacon — its absence says nothing and is never an error.
///
/// Exhaustive on purpose, like [`classify_fetch_failure`], and with the same
/// classes: what makes a witness unreachable for its head makes its
/// co-signature absent.
///
/// # Errors
///
/// [`ReleaseLogError::WitnessCoSign`] when the file was served and is not a
/// co-signature by `key`, or is oversized.
async fn fetch_co_sign(
    origin: &LogOrigin,
    key: &[u8; 32],
    timeout: Duration,
) -> Result<Option<CoSign>, ReleaseLogError> {
    let unusable = |source| ReleaseLogError::WitnessCoSign {
        origin: origin.uri.clone(),
        source,
    };
    let fetched = tokio::time::timeout(
        timeout,
        origin
            .storage
            .download_capped(WITNESS_KEY, MAX_WITNESS_SIZE),
    )
    .await;
    let witness = match fetched {
        Ok(Ok(bytes)) => bytes,
        // Out of time, or not served: no co-signature.
        Err(_)
        | Ok(Err(
            StorageError::NotFound { .. }
            | StorageError::DownloadFailed { .. }
            | StorageError::PermissionDenied { .. }
            | StorageError::Io(..)
            | StorageError::UploadFailed { .. },
        )) => return Ok(None),
        // A served file, and too large to be one: a bad co-signature.
        Ok(Err(StorageError::TooLarge { size, .. })) => {
            return Err(unusable(CoSignProblem::TooLarge { size }));
        }
        Ok(Err(
            error @ (StorageError::Unsupported { .. }
            | StorageError::InvalidKey { .. }
            | StorageError::InvalidConfig { .. }
            | StorageError::LocalRootNotDir),
        )) => {
            return Err(LogConfigError::OriginUnusable {
                origin: origin.uri.clone(),
                source: error,
            }
            .into());
        }
    };
    verify_co_sign(&witness, key).map(Some).map_err(unusable)
}

/// One witness's answer.
enum Fetched {
    /// The verified head, and the bytes it was served as — what a co-signer
    /// of this witness hashed.
    Head {
        head: Box<VerifiedHead>,
        served: Vec<u8>,
    },
    /// The witness served nothing; the reason, bounded.
    Unreachable(String),
}

/// Fetch and verify one witness's head.
///
/// The size limit is the backend's to enforce while it reads
/// (`Storage::download_capped`), and [`Head::from_json`] applies it again to
/// the bytes it is handed, before parsing. A witness that has not served its
/// head within `timeout` is unreachable.
async fn fetch_head(origin: &LogOrigin, timeout: Duration) -> Result<Fetched, ReleaseLogError> {
    let fetched = tokio::time::timeout(
        timeout,
        origin.storage.download_capped(HEAD_KEY, MAX_HEAD_SIZE),
    )
    .await;
    let bytes = match fetched {
        Err(_) => return Ok(Fetched::Unreachable("timed out".to_string())),
        Ok(Ok(bytes)) => bytes,
        Ok(Err(error)) => {
            return classify_fetch_failure(&origin.uri, error).map(Fetched::Unreachable);
        }
    };
    let head = Head::from_json(&bytes)
        .and_then(Head::verify_signature)
        .map_err(|source| ReleaseLogError::WitnessHead {
            origin: origin.uri.clone(),
            source: Box::new(source),
        })?;
    Ok(Fetched::Head {
        head: Box::new(head),
        served: bytes,
    })
}

/// Decide what a failed `head.json` download means: the witness is
/// unreachable (`Ok`, with the reason), or the check cannot continue (`Err`).
///
/// Exhaustive on purpose — a new [`StorageError`] variant must be classified,
/// never defaulted into "unreachable", the one class that is a soft failure.
fn classify_fetch_failure(origin: &str, error: StorageError) -> Result<String, ReleaseLogError> {
    match &error {
        // The witness has no head. That is not evidence about any release — a
        // witness with nothing to show cannot confirm a row or deny one.
        StorageError::NotFound { .. }
        // Transport: connection refused or reset, timeout, a 5xx or any other
        // non-success status, a refused redirect, a failed `ssh`.
        | StorageError::DownloadFailed { .. }
        // 401/403, or an unreadable local file. Static hosts answer 403 for an
        // object that is not there, and the head is public by design, so this
        // says "not served", like 404 — not "misconfigured".
        | StorageError::PermissionDenied { .. }
        // A local failure starting the transfer (spawning `ssh`, a socket).
        | StorageError::Io(..)
        // Not produced by a download; a transfer failure by name, classed with
        // the one above it.
        | StorageError::UploadFailed { .. } => Ok(reason_text(&error)),
        // The witness answered with more than a head can be. A served
        // document, so a bad head — never transient.
        StorageError::TooLarge { size, .. } => Err(ReleaseLogError::WitnessHead {
            origin: origin.to_string(),
            source: Box::new(ReleaseLogError::TooLarge(*size)),
        }),
        // No backend refuses a download as unsupported, refuses the constant
        // key, or fails configuration this late (a local origin that is not a
        // directory is refused when the origins are parsed). If one does, the
        // origin can never serve a head and a retry changes nothing: a
        // configuration error, not "unreachable".
        StorageError::Unsupported { .. }
        | StorageError::InvalidKey { .. }
        | StorageError::InvalidConfig { .. }
        | StorageError::LocalRootNotDir => Err(LogConfigError::OriginUnusable {
            origin: origin.to_string(),
            source: error,
        }
        .into()),
    }
}

/// Read the cached head. `Ok(None)` when there is no cache file — no baseline,
/// which is the state of a first check.
///
/// The file is opened without following a symlink and read bounded at
/// [`MAX_HEAD_SIZE`]; then it is parsed and its signature verified, exactly as
/// a witness's head is. The signature makes the cached head authentic; its
/// mode and location keep it from being swapped for an older valid head, so
/// freshness rests on the fuz home's permissions. Only the final path
/// component is opened no-follow: a symlinked `release_log` directory is
/// followed, and the home guard is the boundary.
///
/// # Errors
///
/// [`ReleaseLogError::CacheUnusable`] for a cache that exists and is a
/// symlink, not a regular file, oversized, unreadable, unparseable, or not
/// signed by a trusted key. It is never read as absent and never replaced:
/// either would let whatever damaged the file discard the baseline unnoticed.
fn read_cached_head(path: &Path) -> Result<Option<VerifiedHead>, ReleaseLogError> {
    let unusable = |problem| ReleaseLogError::CacheUnusable {
        path: path.to_path_buf(),
        problem,
    };
    let bytes = match load_bounded_file(path, MAX_HEAD_SIZE) {
        Ok(bytes) => bytes,
        Err(SecureFileError::NotFound(_)) => return Ok(None),
        Err(e) => return Err(unusable(CacheProblem::File(e))),
    };
    Head::from_json(&bytes)
        .and_then(Head::verify_signature)
        .map(Some)
        .map_err(|e| unusable(CacheProblem::Head(Box::new(e))))
}

/// Write `head` as the cached head: the directory at `0700` if it is missing,
/// the file at `0600`, atomically.
///
/// Two checks running at once each write the head they resolved, and the later
/// rename wins. Either file is a verified head of the same history, so the
/// cache can end one check behind; the next check advances it.
fn write_cached_head(path: &Path, head: &VerifiedHead) -> Result<(), ReleaseLogError> {
    let unusable = |source| ReleaseLogError::CacheUnusable {
        path: path.to_path_buf(),
        problem: CacheProblem::Write(source),
    };
    let json = head.to_json()?;
    if let Some(dir) = path.parent() {
        fuz_sys::fs::create_dir_all_mode(dir, SECURE_DIR_MODE).map_err(unusable)?;
    }
    fuz_sys::fs::write_atomic(path, json.as_bytes(), SECURE_FILE_MODE).map_err(unusable)
}

/// A transport failure's message as one bounded line of a report.
///
/// The error's own message escapes the strings it carries, so nothing is
/// escaped a second time here: `escape_message` leaves those escapes alone and
/// spells out only what is still unprintable. The bound is taken on the
/// message as rendered.
fn reason_text(error: &StorageError) -> String {
    escape_message(&truncate(&error.to_string(), MAX_REASON_LEN))
}

#[cfg(test)]
mod tests {
    use super::*;
    use fuz_storage::StorageBackendKind;

    fn enforced(policy: ReleaseLogPolicy) -> Vec<String> {
        match policy {
            ReleaseLogPolicy::Enforced(origins) => origins
                .as_slice()
                .iter()
                .map(|origin| origin.uri().to_string())
                .collect(),
            other => panic!("expected an enforced policy, got {other:?}"),
        }
    }

    #[track_caller]
    fn assert_invalid_switch(url: Option<&str>, switch: &str) {
        let result = ReleaseLogPolicy::from_env_values(url, Some(switch), &[]);
        assert!(
            matches!(
                result,
                Err(ReleaseLogError::Config(
                    LogConfigError::InvalidSwitch { .. }
                ))
            ),
            "switch {switch:?} with url {url:?}: {result:?}"
        );
    }

    //
    // Policy
    //

    #[test]
    fn no_url_is_inactive_whatever_the_switch() {
        for url in [None, Some(""), Some("   "), Some(","), Some(" , ,, ")] {
            for switch in [None, Some(""), Some("off")] {
                let policy = ReleaseLogPolicy::from_env_values(url, switch, &[]).unwrap();
                assert!(
                    matches!(policy, ReleaseLogPolicy::Inactive),
                    "url {url:?} switch {switch:?}: {policy:?}"
                );
            }
        }
    }

    #[test]
    fn a_url_enforces_and_the_list_is_split_and_trimmed() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a");
        let b = dir.path().join("b");
        std::fs::create_dir(&a).unwrap();
        std::fs::create_dir(&b).unwrap();
        let (a, b) = (a.to_str().unwrap(), b.to_str().unwrap());

        for switch in [None, Some("")] {
            let policy = ReleaseLogPolicy::from_env_values(Some(a), switch, &[]).unwrap();
            assert_eq!(enforced(policy), [a]);
        }
        // Whitespace around entries is trimmed; empty entries are skipped.
        let list = format!("  {a} ,, {b}  , ");
        let policy = ReleaseLogPolicy::from_env_values(Some(&list), None, &[]).unwrap();
        assert_eq!(enforced(policy), [a, b]);
        // The URL forms.
        let policy = ReleaseLogPolicy::from_env_values(
            Some("https://log.example.com/base, http://127.0.0.1:9/log"),
            None,
            &[],
        )
        .unwrap();
        assert_eq!(
            enforced(policy),
            ["https://log.example.com/base", "http://127.0.0.1:9/log"]
        );
    }

    /// A witness key is attached to the origin it is embedded for, matched on
    /// the configured entry up to trailing slashes and exactly otherwise.
    #[test]
    fn a_witness_key_is_attached_to_its_origin_and_to_no_other() {
        let keys: WitnessKeys<'_> = &[
            ("https://cosigner.example.com/log", [1; 32]),
            ("https://mirror.example.org", [2; 32]),
        ];
        let list = "https://cosigner.example.com/log/ , https://mirror.example.org, \
                    https://MIRROR.example.org, https://cosigner.example.com, \
                    https://cosigner.example.com/log/x";
        let ReleaseLogPolicy::Enforced(origins) =
            ReleaseLogPolicy::from_env_values(Some(list), None, keys).unwrap()
        else {
            panic!("expected an enforced policy");
        };
        let matched: Vec<Option<&[u8; 32]>> = origins
            .as_slice()
            .iter()
            .map(LogOrigin::witness_key)
            .collect();
        assert_eq!(matched, [Some(&[1; 32]), Some(&[2; 32]), None, None, None]);
        // What is shown is the entry as configured.
        assert_eq!(
            origins.as_slice()[0].uri(),
            "https://cosigner.example.com/log/"
        );

        // With no keys, no origin has one.
        let ReleaseLogPolicy::Enforced(origins) =
            ReleaseLogPolicy::from_env_values(Some(list), None, &[]).unwrap()
        else {
            panic!("expected an enforced policy");
        };
        assert!(origins.as_slice().iter().all(|o| o.witness_key().is_none()));
    }

    /// The match is on the entry itself: an origin whose display form was cut
    /// short does not match a key embedded for the cut text.
    #[test]
    fn a_witness_key_is_matched_on_the_origin_not_on_its_display_form() {
        let long = format!("https://log.example.com/{}", "x".repeat(10 * 1024));
        let ReleaseLogPolicy::Enforced(shown) =
            ReleaseLogPolicy::from_env_values(Some(&long), None, &[]).unwrap()
        else {
            panic!("expected an enforced policy");
        };
        let display = shown.as_slice()[0].uri().to_string();
        assert_ne!(display, long);
        let policy = |keys: WitnessKeys<'_>| {
            let ReleaseLogPolicy::Enforced(origins) =
                ReleaseLogPolicy::from_env_values(Some(&long), None, keys).unwrap()
            else {
                panic!("expected an enforced policy");
            };
            origins.as_slice()[0].witness_key().copied()
        };
        assert_eq!(policy(&[(&display, [3; 32])]), None);
        assert_eq!(policy(&[(&long, [3; 32])]), Some([3; 32]));
    }

    #[test]
    fn off_with_a_url_is_off_and_does_not_parse_the_list() {
        for url in [
            "https://log.example.com",
            "no-such-scheme://x",
            "/no/such/directory,b",
        ] {
            let policy = ReleaseLogPolicy::from_env_values(Some(url), Some("off"), &[]).unwrap();
            assert!(matches!(policy, ReleaseLogPolicy::Off), "{url}: {policy:?}");
        }
    }

    #[test]
    fn the_switch_is_a_closed_set() {
        for switch in [
            "OFF", "Off", "0", "false", "no", "on", "1", "true", " off", "off ", " ",
        ] {
            // With or without a URL: a typo is never read as a setting.
            assert_invalid_switch(Some("https://log.example.com"), switch);
            assert_invalid_switch(None, switch);
        }
    }

    #[test]
    fn an_invalid_switch_value_is_bounded_and_escaped() {
        let hostile = format!("\u{1b}[31m{}", "x".repeat(4096));
        let error = ReleaseLogPolicy::from_env_values(None, Some(&hostile), &[]).unwrap_err();
        let message = error.to_string();
        assert!(!message.contains('\u{1b}'), "{message:?}");
        assert!(message.len() < 512, "{}", message.len());
    }

    #[test]
    fn an_invalid_switch_value_is_shown_quoted_and_escaped_once() {
        let error =
            ReleaseLogPolicy::from_env_values(None, Some("o\u{1b}f\u{2800}f\\"), &[]).unwrap_err();
        assert_eq!(
            error.to_string(),
            "release log configuration error: invalid FUZ_RELEASE_LOG value \
             \"o\\u{1b}f\\u{2800}f\\\\\" (the only value is \"off\")"
        );
    }

    #[test]
    fn an_entry_that_is_not_a_storage_location_is_a_configuration_error() {
        let cases = [
            ("no-such-scheme://x", 1),
            ("https://ok.example.com, http://plaintext.example.com", 2),
            (", ,https://ok.example.com,,ftp://x", 2),
            (
                "https://ok.example.com,https://ok.example.org,/no/such/directory",
                3,
            ),
        ];
        for (url, expected) in cases {
            let result = ReleaseLogPolicy::from_env_values(Some(url), None, &[]);
            assert!(
                matches!(
                    result,
                    Err(ReleaseLogError::Config(LogConfigError::InvalidOrigin { position, .. }))
                        if position == expected
                ),
                "{url}: {result:?}"
            );
        }
    }

    #[test]
    fn an_invalid_entry_is_named_by_position_and_never_echoed() {
        for url in [
            "https://user:hunter2@log.example.com",
            "https://h/a?token=hunter2",
            "HTTPS://u:hunter2@h",
            "https://u:hunter2@[bad",
            "forge://hunter2.example.com",
            "ssh://hunter2@h/path",
            "/no/such/hunter2/directory",
        ] {
            let error = ReleaseLogPolicy::from_env_values(Some(url), None, &[]).unwrap_err();
            let wrapped = ReleaseError::from(error);
            let message = wrapped.to_string();
            let hint = wrapped.hint().map(|h| h.to_string()).unwrap_or_default();
            assert!(message.contains("entry 1"), "{url}: {message}");
            assert!(
                !message.contains("hunter2"),
                "{url}: secret leaked: {message}"
            );
            assert!(!hint.contains("hunter2"), "{url}: secret leaked: {hint}");
        }
    }

    /// The refusal is of the two schemes, not of names that contain them.
    #[test]
    fn only_the_forge_and_ssh_schemes_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let mut list = vec![
            "https://forge.example.com".to_string(),
            "https://ssh.example.com/forge".to_string(),
        ];
        for name in ["forge:", "ssh:x", "forge", "ssh"] {
            let path = dir.path().join(name);
            std::fs::create_dir(&path).unwrap();
            list.push(path.to_str().unwrap().to_string());
        }
        let policy = ReleaseLogPolicy::from_env_values(Some(&list.join(",")), None, &[]).unwrap();
        assert_eq!(enforced(policy), list);
    }

    /// Refused by scheme, before a backend is built — so the result does not
    /// depend on whether a forge token can be resolved.
    #[test]
    fn forge_and_ssh_are_refused_before_a_backend_is_built() {
        for url in [
            "forge://forge.example.com",
            "forge://",
            "ssh://user@host/log",
        ] {
            let error = ReleaseLogPolicy::from_env_values(Some(url), None, &[]).unwrap_err();
            let ReleaseLogError::Config(LogConfigError::InvalidOrigin {
                position, refusal, ..
            }) = error
            else {
                panic!("{url}: not InvalidOrigin");
            };
            assert_eq!(position, 1, "{url}");
            assert_eq!(
                refusal.to_string(),
                "a release log origin is an https:// URL or a local directory",
                "{url}"
            );
        }
    }

    /// An origin is shown in the summary, in warnings, and in errors. What is
    /// shown is bounded and cannot drive the terminal; what is read is the
    /// location as it was given.
    #[test]
    fn an_origin_is_bounded_and_escaped_for_display() {
        let dir = tempfile::tempdir().unwrap();
        let hostile = dir.path().join("log\u{1b}[31m");
        std::fs::create_dir(&hostile).unwrap();
        let long = format!("https://log.example.com/{}", "x".repeat(10 * 1024));
        let list = format!("{},{long}", hostile.to_str().unwrap());

        let ReleaseLogPolicy::Enforced(origins) =
            ReleaseLogPolicy::from_env_values(Some(&list), None, &[]).unwrap()
        else {
            panic!("expected an enforced policy");
        };
        let [local, remote] = origins.as_slice() else {
            panic!("expected two origins");
        };
        for origin in [local, remote] {
            assert!(!origin.uri().contains('\u{1b}'), "{:?}", origin.uri());
            assert!(origin.uri().len() < 512, "{}", origin.uri().len());
        }
        // Escaped, not dropped; cut, and marked as cut.
        assert!(local.uri().contains("\\u{1b}[31m"), "{}", local.uri());
        assert!(remote.uri().starts_with("https://log.example.com/xxx"));
        assert!(remote.uri().ends_with("..."), "{}", remote.uri());
    }

    /// The blank fillers print as empty space, so an origin holding one is
    /// spelled out like any other character that shows nothing.
    #[test]
    fn an_origin_with_a_blank_filler_is_escaped_for_display() {
        let dir = tempfile::tempdir().unwrap();
        let blank = dir.path().join("log\u{3164}\u{2800}\u{115f}x");
        std::fs::create_dir(&blank).unwrap();
        let ReleaseLogPolicy::Enforced(origins) =
            ReleaseLogPolicy::from_env_values(blank.to_str(), None, &[]).unwrap()
        else {
            panic!("expected an enforced policy");
        };
        let [origin] = origins.as_slice() else {
            panic!("expected one origin");
        };
        assert!(
            origin.uri().ends_with("/log\\u{3164}\\u{2800}\\u{115f}x"),
            "{}",
            origin.uri()
        );
    }

    /// Naming a local origin that is not there is a configuration error and
    /// creates nothing — relative, `~`-relative, or absolute.
    #[test]
    fn a_missing_local_origin_is_an_error_and_is_not_created() {
        let dir = tempfile::tempdir().unwrap();
        let absolute = dir.path().join("missing");
        let suffix = fuz_sys::rand::random_hex_suffix();
        let relative = format!("log-{suffix}.example.com");
        let home_relative = format!("~/.fuz-log-check-test-{suffix}");
        for url in [absolute.to_str().unwrap(), &relative, &home_relative] {
            let result = ReleaseLogPolicy::from_env_values(Some(url), None, &[]);
            assert!(
                matches!(
                    result,
                    Err(ReleaseLogError::Config(
                        LogConfigError::InvalidOrigin { .. }
                    ))
                ),
                "{url}: {result:?}"
            );
            // Never the soft failure: retrying does not make a directory.
            assert!(!result.unwrap_err().is_unconfirmed(), "{url}");
        }
        assert!(!absolute.exists());
        assert!(!Path::new(&relative).exists());
        assert!(!fuz_sys::expand_tilde(&home_relative).exists());
    }

    /// A witness that accepts the connection and never answers is unreachable
    /// once its time is up — it does not hold the check for as long as the
    /// transport would wait.
    #[tokio::test]
    async fn a_silent_witness_is_unreachable_after_the_fetch_timeout() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            // Hold every connection open, saying nothing.
            while let Ok((socket, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let _held = socket;
                    std::future::pending::<()>().await;
                });
            }
        });
        let policy = ReleaseLogPolicy::from_env_values(Some(&base), None, &[]).unwrap();
        let ReleaseLogPolicy::Enforced(origins) = policy else {
            panic!("expected an enforced policy");
        };
        let dir = tempfile::tempdir().unwrap();
        let cache = dir.path().join(HEAD_KEY);

        let started = std::time::Instant::now();
        // The outer bound makes a lost timeout a failure rather than a hang.
        let log = tokio::time::timeout(
            Duration::from_secs(30),
            observe_log(&origins, &cache, Duration::from_millis(300)),
        )
        .await
        .expect("the fetch timeout must end the wait")
        .unwrap();
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "{:?}",
            started.elapsed()
        );
        assert!(log.head().is_none());
        assert_eq!(
            log.unreachable(),
            [UnreachableOrigin {
                origin: base,
                reason: "timed out".to_string(),
            }]
        );
        assert!(!cache.exists());
    }

    /// Each witness gets its own bound: a second silent witness is cut off too.
    #[tokio::test]
    async fn every_witness_gets_its_own_fetch_timeout() {
        // A bound listener that never accepts: the connection completes in the
        // kernel's backlog and the request is never answered.
        let hold = || {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let base = format!("http://{}", listener.local_addr().unwrap());
            (listener, base)
        };
        let ((_first, a), (_second, b)) = (hold(), hold());
        let ReleaseLogPolicy::Enforced(origins) =
            ReleaseLogPolicy::from_env_values(Some(&format!("{a},{b}")), None, &[]).unwrap()
        else {
            panic!("expected an enforced policy");
        };
        let dir = tempfile::tempdir().unwrap();
        let started = std::time::Instant::now();
        let log = tokio::time::timeout(
            Duration::from_secs(30),
            observe_log(
                &origins,
                &dir.path().join(HEAD_KEY),
                Duration::from_millis(300),
            ),
        )
        .await
        .expect("each fetch timeout must end its wait")
        .unwrap();
        let reasons: Vec<&str> = log
            .unreachable()
            .iter()
            .map(|u| u.reason.as_str())
            .collect();
        assert_eq!(reasons, ["timed out", "timed out"]);
        // One after another: both bounds are spent.
        assert!(
            started.elapsed() >= Duration::from_millis(600),
            "{:?}",
            started.elapsed()
        );
    }

    /// A witness that serves its head and then never answers for `witness`
    /// has no co-signature, once the bound is up: a co-signature is not waited
    /// for and its absence is not an error.
    #[tokio::test]
    async fn a_witness_that_stalls_on_its_co_signature_has_none_after_the_timeout() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut request = Vec::new();
                    let mut chunk = [0u8; 1024];
                    while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                        match socket.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => request.extend_from_slice(&chunk[..n]),
                        }
                    }
                    if request.starts_with(b"GET /head.json ") {
                        let _ = socket
                            .write_all(
                                b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\
                                  Connection: close\r\n\r\nhead",
                            )
                            .await;
                    } else {
                        // `witness`: hold the connection open, saying nothing.
                        std::future::pending::<()>().await;
                    }
                });
            }
        });
        let ReleaseLogPolicy::Enforced(origins) =
            ReleaseLogPolicy::from_env_values(Some(&base), None, &[(&base, [7; 32])]).unwrap()
        else {
            panic!("expected an enforced policy");
        };
        let origin = &origins.as_slice()[0];
        let key = *origin.witness_key().unwrap();

        // The head is served, as it is before a co-signature is asked for.
        let served = origin
            .storage
            .download_capped(HEAD_KEY, MAX_HEAD_SIZE)
            .await
            .unwrap();
        assert_eq!(served, b"head");

        let started = std::time::Instant::now();
        let co_sign = tokio::time::timeout(
            Duration::from_secs(30),
            fetch_co_sign(origin, &key, Duration::from_millis(300)),
        )
        .await
        .expect("the fetch timeout must end the wait")
        .unwrap();
        assert_eq!(co_sign, None);
        assert!(
            started.elapsed() >= Duration::from_millis(300),
            "{:?}",
            started.elapsed()
        );
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "{:?}",
            started.elapsed()
        );
    }

    /// A `witness` file a witness does not serve is absent, not an error; one
    /// that is served and over its bound, or is not a co-signature, is a bad
    /// co-signature.
    #[tokio::test]
    async fn a_missing_witness_file_is_absent_and_a_bad_one_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let uri = dir.path().to_str().unwrap();
        let ReleaseLogPolicy::Enforced(origins) =
            ReleaseLogPolicy::from_env_values(Some(uri), None, &[(uri, [7; 32])]).unwrap()
        else {
            panic!("expected an enforced policy");
        };
        let origin = &origins.as_slice()[0];
        let key = [7; 32];
        let fetch = || fetch_co_sign(origin, &key, Duration::from_secs(5));
        let path = dir.path().join(WITNESS_KEY);

        assert_eq!(fetch().await.unwrap(), None);
        // Not a regular file: not served.
        std::fs::create_dir(&path).unwrap();
        assert!(matches!(fetch().await, Ok(None)));
        std::fs::remove_dir(&path).unwrap();

        // At the bound it is read, and is not a co-signature; one byte past,
        // it is too large to be one. Either way a refusal naming the witness.
        let at = usize::try_from(MAX_WITNESS_SIZE).unwrap();
        std::fs::write(&path, vec![b'A'; at]).unwrap();
        let result = fetch().await;
        assert!(
            matches!(
                &result,
                Err(ReleaseLogError::WitnessCoSign {
                    origin,
                    source: CoSignProblem::Signature(_),
                }) if origin == uri
            ),
            "{result:?}"
        );
        std::fs::write(&path, vec![b'A'; at + 1]).unwrap();
        let result = fetch().await;
        assert!(
            matches!(
                result,
                Err(ReleaseLogError::WitnessCoSign {
                    source: CoSignProblem::TooLarge { .. },
                    ..
                })
            ),
            "{result:?}"
        );
    }

    //
    // Fetch-failure classification
    //

    const KIND: StorageBackendKind = StorageBackendKind::Https;

    /// One of every [`StorageError`] shape with its class.
    fn storage_errors() -> Vec<(StorageError, &'static str)> {
        let table = vec![
            (
                StorageError::NotFound {
                    backend: KIND,
                    path: HEAD_KEY.to_string(),
                },
                "unreachable",
            ),
            (
                StorageError::DownloadFailed {
                    backend: KIND,
                    message: "HTTP 500 Internal Server Error".to_string(),
                },
                "unreachable",
            ),
            (
                StorageError::PermissionDenied {
                    backend: KIND,
                    path: HEAD_KEY.to_string(),
                },
                "unreachable",
            ),
            (
                StorageError::Io(KIND, std::io::Error::other("spawn failed")),
                "unreachable",
            ),
            (
                StorageError::UploadFailed {
                    backend: KIND,
                    message: "x".to_string(),
                },
                "unreachable",
            ),
            (
                StorageError::TooLarge {
                    backend: KIND,
                    path: HEAD_KEY.to_string(),
                    size: MAX_HEAD_SIZE + 1,
                    max: MAX_HEAD_SIZE,
                },
                "bad head",
            ),
            (
                StorageError::Unsupported {
                    backend: KIND,
                    operation: "download",
                },
                "config",
            ),
            (
                StorageError::InvalidKey {
                    key: HEAD_KEY.to_string(),
                    reason: "x",
                },
                "config",
            ),
            (
                StorageError::InvalidConfig {
                    message: "x".to_string(),
                },
                "config",
            ),
            (StorageError::LocalRootNotDir, "config"),
        ];
        // Compile-time tripwire: a new variant fails to build here until it is
        // added to the table above.
        for (error, _) in &table {
            match error {
                StorageError::NotFound { .. }
                | StorageError::UploadFailed { .. }
                | StorageError::DownloadFailed { .. }
                | StorageError::PermissionDenied { .. }
                | StorageError::TooLarge { .. }
                | StorageError::Unsupported { .. }
                | StorageError::Io(..)
                | StorageError::InvalidKey { .. }
                | StorageError::InvalidConfig { .. }
                | StorageError::LocalRootNotDir => {}
            }
        }
        table
    }

    #[test]
    fn every_storage_error_is_classified() {
        for (error, class) in storage_errors() {
            let description = error.to_string();
            let result = classify_fetch_failure("https://log.example.com", error);
            let got = match &result {
                Ok(_) => "unreachable",
                Err(ReleaseLogError::WitnessHead { source, .. })
                    if matches!(**source, ReleaseLogError::TooLarge(_)) =>
                {
                    "bad head"
                }
                Err(ReleaseLogError::Config(LogConfigError::OriginUnusable { .. })) => "config",
                Err(other) => panic!("{description}: unexpected {other:?}"),
            };
            assert_eq!(got, class, "{description}");
            // Only "unreachable" may ever become the soft failure.
            if let Err(e) = &result {
                assert!(!e.is_unconfirmed(), "{description}");
            }
        }
    }

    #[test]
    fn an_unreachable_reason_is_bounded_and_escaped() {
        let error = StorageError::DownloadFailed {
            backend: KIND,
            message: format!("\u{1b}[2J{}", "y".repeat(8192)),
        };
        let reason = classify_fetch_failure("o", error).unwrap();
        assert!(!reason.contains('\u{1b}'), "{reason:?}");
        assert!(reason.len() <= MAX_REASON_LEN + 16, "{}", reason.len());
        assert!(reason.ends_with("..."), "{reason}");
    }

    /// The storage error's message escapes what it carries; the reason is that
    /// message, with nothing in it escaped a second time.
    #[test]
    fn an_unreachable_reason_is_the_storage_message_escaped_once() {
        let message = "HTTP 500: x\u{1b}[2K\r\u{202e}\u{2800}\"\\n\nhint: y";
        let error = || StorageError::DownloadFailed {
            backend: KIND,
            message: message.to_string(),
        };
        let reason = classify_fetch_failure("o", error()).unwrap();
        assert_eq!(reason, error().to_string());
        assert_eq!(
            reason,
            format!(
                "{KIND}: download failed: HTTP 500: \
                 x\\u{{1b}}[2K\\r\\u{{202e}}\\u{{2800}}\"\\\\n\\nhint: y"
            )
        );
    }

    /// Whatever a storage error's message leaves raw — an OS error's text,
    /// say — is still spelled out in the reason, on one line.
    #[test]
    fn an_unreachable_reason_spells_out_what_the_storage_message_leaves_raw() {
        let error = StorageError::Io(KIND, std::io::Error::other("a\u{1b}[2K\nb\u{202e}"));
        let reason = classify_fetch_failure("o", error).unwrap();
        assert_eq!(
            reason,
            format!("{KIND}: I/O error: a\\u{{1b}}[2K\\nb\\u{{202e}}")
        );
    }

    #[test]
    fn an_unreachable_reason_spells_out_blank_fillers_and_nul() {
        for message in [
            "x\u{ffa0}\u{1160}\0y".to_string(),
            // Past the bound too: the cut text is escaped the same way.
            format!("x\u{ffa0}\u{1160}\0y{}", "z".repeat(MAX_REASON_LEN)),
        ] {
            let error = StorageError::DownloadFailed {
                backend: KIND,
                message,
            };
            let reason = classify_fetch_failure("o", error).unwrap();
            assert!(reason.contains("x\\u{ffa0}\\u{1160}\\u{0}y"), "{reason:?}");
        }
    }

    //
    // Cache file handling that needs no signed head
    //

    #[test]
    fn an_absent_cache_is_no_baseline() {
        let dir = tempfile::tempdir().unwrap();
        assert!(
            read_cached_head(&dir.path().join(HEAD_KEY))
                .unwrap()
                .is_none()
        );
        // A missing directory is the same state.
        let nested = dir.path().join("state").join(CACHE_DIR).join(HEAD_KEY);
        assert!(read_cached_head(&nested).unwrap().is_none());
    }

    #[track_caller]
    fn cache_problem(
        result: Result<Option<VerifiedHead>, ReleaseLogError>,
        path: &Path,
    ) -> CacheProblem {
        match result {
            Err(ReleaseLogError::CacheUnusable {
                path: named,
                problem,
            }) => {
                assert_eq!(named, path, "the error names the cache file");
                problem
            }
            other => panic!("expected an unusable cache, got {other:?}"),
        }
    }

    #[test]
    fn a_symlinked_cache_is_refused_and_its_target_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("elsewhere.json");
        std::fs::write(&target, b"{}").unwrap();
        let path = dir.path().join(HEAD_KEY);
        std::os::unix::fs::symlink(&target, &path).unwrap();

        let problem = cache_problem(read_cached_head(&path), &path);
        assert!(
            matches!(problem, CacheProblem::File(SecureFileError::Symlink(_))),
            "{problem:?}"
        );
        assert_eq!(std::fs::read(&target).unwrap(), b"{}");
        assert!(path.is_symlink());
    }

    #[test]
    fn an_oversized_cache_is_refused_not_truncated() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(HEAD_KEY);
        std::fs::write(&path, vec![b' '; 2 * 1024 * 1024]).unwrap();
        let problem = cache_problem(read_cached_head(&path), &path);
        assert!(
            matches!(
                problem,
                CacheProblem::File(SecureFileError::FileTooLarge(..))
            ),
            "{problem:?}"
        );
    }

    #[test]
    fn a_cache_that_is_not_a_regular_file_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(HEAD_KEY);
        std::fs::create_dir(&path).unwrap();
        let problem = cache_problem(read_cached_head(&path), &path);
        assert!(
            matches!(
                problem,
                CacheProblem::File(SecureFileError::NotRegularFile(_))
            ),
            "{problem:?}"
        );
    }

    #[test]
    fn a_garbage_cache_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(HEAD_KEY);
        for garbage in [&b""[..], b"not json", b"{}", b"{\"format\":9}"] {
            std::fs::write(&path, garbage).unwrap();
            let problem = cache_problem(read_cached_head(&path), &path);
            assert!(matches!(problem, CacheProblem::Head(_)), "{problem:?}");
        }
    }
}
