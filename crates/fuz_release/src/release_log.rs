//! Release log head: the signed record of every first-party release.
//!
//! The release log is a public, append-only record of what was released. Its
//! one load-bearing object is the **head** — a single signed document
//! (`head.json`) listing every release as a [`ReleaseRow`]: a name, a version,
//! a status, and per target the digests the release's manifest pins. The head
//! is signed with the release key in the manifest's own envelope — the
//! signature covers the head tag followed by `fuz_crypto::canonical_json` of
//! the unsigned fields (a `fuz_crypto::SignedMessage`, so a manifest signature
//! never verifies as a head or the reverse) and travels as an embedded
//! `fuz_crypto::Signature`.
//!
//! A signature proves a head came from the release key. It does not prove the
//! head is the *same history* another reader was shown: a holder of the key
//! could sign two heads that disagree, or serve an old head to hide a
//! revocation. The rules in this module close that gap without any history
//! store — two verified heads are compared directly:
//!
//! - [`check_superset`] — the log only grows. Every row and key record of the
//!   older head is still present, at the same position, in the newer one;
//!   what a row pins never changes; a revocation is never undone.
//! - [`check_successor`] — a head replacing a cached one has a strictly greater
//!   `seq` and is a superset of it, so a reader is never rolled back.
//! - [`check_consistent`] — two heads from different origins must be the same
//!   history at different lengths. A lagging mirror passes; two heads where
//!   neither contains the other are a contradiction.
//!
//! **Typestate.** [`Head`] is a parsed, structurally valid document whose
//! signature is unchecked. It is opaque: no field accessors, no serde
//! implementations, and a `Debug` that prints no content — its only outputs
//! are [`Head::to_json`] (the document itself) and [`Head::verify_signature`].
//! That method is the sole producer of [`VerifiedHead`], the only type that
//! has read accessors and the only type the rule functions accept — so neither
//! a lookup nor a comparison can run against a head whose signature was never
//! verified.
//!
//! The module is types and pure rules: no I/O, no clock, no global state.
//! Signing is `fuz_sign::sign_head`. The reader is [`crate::log_check`], which
//! fetches a head from the configured witnesses and holds a release to it
//! before the release's bytes are used or reported on. A co-signer's statement
//! about a head is [`crate::co_sign`].

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use fuz_artifact::{MAX_RELEASE_TOKEN_LEN, is_content_hash, is_release_token};
use fuz_crypto::{ContentHash, HashAlgo};
use fuz_sys::text::{escape_untrusted, quoted, truncate};

/// The head format version this client reads and writes.
///
/// Matched exactly: a head carrying any other value is refused with
/// [`ReleaseLogError::UnsupportedFormat`] rather than read under rules that
/// may not be the ones it was signed under.
pub const HEAD_FORMAT_VERSION: u32 = 1;

/// Maximum head size in bytes (the shared trusted-metadata ceiling).
pub const MAX_HEAD_SIZE: u64 = fuz_sys::limits::MAX_METADATA_SIZE;

/// Largest `seq` a head may carry: `2^53 - 1`.
///
/// The largest integer every JSON reader represents exactly. A head is read by
/// tools other than this crate, and a `seq` two readers disagree on would
/// defeat the ordering it exists to give.
pub const MAX_HEAD_SEQ: u64 = (1 << 53) - 1;

/// Most bytes of untrusted text an error excerpt carries — an offending value,
/// or the parser's message. The input is up to [`MAX_HEAD_SIZE`]; an error line
/// is not the place to repeat it in full. Every valid field value fits, so a
/// value is cut only when it is invalid; the parser's message is cut wherever
/// it runs past the bound.
const MAX_ERROR_VALUE_LEN: usize = MAX_RELEASE_TOKEN_LEN;

/// Whether a release is in good standing.
///
/// Closed set, lowercase on the wire. The only transition is
/// [`Ok`](Self::Ok) → [`Revoked`](Self::Revoked): a revocation is permanent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RowStatus {
    /// The release stands.
    Ok,
    /// The release was withdrawn and must not be installed.
    Revoked,
}

/// A release key's entry in the head's key history.
///
/// **Record only.** The list documents which keys have signed releases and
/// when each was introduced or retired, for a human reading the log. It never
/// feeds a trust decision: whether a key is trusted is decided by
/// `fuz_crypto::is_trusted_key` against the keys embedded in the binary, and
/// nothing else. A head naming a key here does not make that key trusted, and
/// a head omitting or retiring a key does not make it untrusted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyRecord {
    /// Base64-encoded ed25519 public key (the `Signature::public_key` form).
    pub public_key: String,
    /// When the key entered use (`YYYY-MM-DDTHH:MM:SSZ`, publisher-asserted).
    pub added_at: String,
    /// When the key left use; absent from the wire while the key is in use.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub retired_at: Option<String>,
}

/// What one release pins for one target.
///
/// Immutable once recorded: the superset rule refuses any later head that
/// changes a field of an existing entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetRow {
    /// The manifest's `content_hash` (`v1-<blake3 hex>`).
    pub content_hash: String,
    /// Binary name → BLAKE3, as the manifest's `binaries` records them. Bare
    /// lowercase hex on the wire.
    #[serde(with = "binary_hashes")]
    pub binaries: BTreeMap<String, ContentHash>,
    /// SHA-512 of the flat binary the install script downloads — the digest a
    /// shell compares before any fuz binary exists. Present only for the self
    /// artifact; absent from the wire otherwise. Bare lowercase hex.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "present_sha512"
    )]
    pub sha512: Option<ContentHash>,
}

/// One release: a `(name, version)` pair and what it pins per target.
///
/// `(name, version)` identifies the row and is unique within a head. The
/// target map only grows — a release's targets are published one at a time,
/// each adding an entry to the existing row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseRow {
    /// What was released: a tool name (`fuz`, `fuzd`) or a released file
    /// (`install.sh`).
    pub name: String,
    /// The release version.
    pub version: String,
    /// Whether the release stands.
    pub status: RowStatus,
    /// When the release was published (`YYYY-MM-DDTHH:MM:SSZ`,
    /// publisher-asserted — informational, never compared against a clock).
    pub published_at: String,
    /// Target → what the release pins for it.
    #[serde(deserialize_with = "fuz_crypto::unique_map::deserialize")]
    pub targets: BTreeMap<String, TargetRow>,
}

/// The unsigned head — the exact data the signature covers.
///
/// The producer-side type: a publisher builds or extends one and signs it with
/// `fuz_sign::sign_head`. It deliberately does not implement `Deserialize`: the
/// one reader of a head document is [`Head::from_json`], and the one way from a
/// read head to this type is [`VerifiedHead::to_unsigned`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HeadUnsigned {
    /// Format version ([`HEAD_FORMAT_VERSION`]).
    pub format: u32,
    /// Monotonic counter, incremented by every change to the head. Orders any
    /// two heads of one history.
    pub seq: u64,
    /// Release-key history, append-only. Record only — see [`KeyRecord`].
    pub keys: Vec<KeyRecord>,
    /// Every release, in insertion order. Append-only.
    pub rows: Vec<ReleaseRow>,
}

/// Signed as
/// [`SignedPayloadKind::ReleaseLogHead`](fuz_crypto::SignedPayloadKind::ReleaseLogHead).
impl fuz_crypto::SignedPayload for HeadUnsigned {
    const KIND: fuz_crypto::SignedPayloadKind = fuz_crypto::SignedPayloadKind::ReleaseLogHead;
}

impl HeadUnsigned {
    /// Check the structural rules every head obeys, independent of any other
    /// head.
    ///
    /// - `format` is [`HEAD_FORMAT_VERSION`]; `seq` is at least 1 and at most
    ///   [`MAX_HEAD_SEQ`]
    /// - no two rows share a `(name, version)`; no two key records share a key
    /// - names, versions, targets, and binary names are short ASCII tokens;
    ///   timestamps have the fixed `YYYY-MM-DDTHH:MM:SSZ` shape
    /// - every digest has its field's algorithm, and every row and target pins
    ///   something
    ///
    /// Passing leaves every string ASCII, so canonical-JSON serialization of a
    /// valid head cannot fail.
    ///
    /// # Errors
    ///
    /// [`ReleaseLogError::UnsupportedFormat`] for a foreign `format`, otherwise
    /// [`ReleaseLogError::Invalid`] naming the first offending field.
    pub fn validate(&self) -> Result<(), ReleaseLogError> {
        validate_body(self.format, self.seq, &self.keys, &self.rows)
    }
}

/// A parsed, structurally valid head whose signature is **unchecked**.
///
/// Opaque on purpose. It has no field accessors and implements neither
/// `Serialize` nor `Deserialize`: [`from_json`](Self::from_json) is the only
/// way to read one (so the size guard, the format check, and the structural
/// rules cannot be skipped) and [`to_json`](Self::to_json) the only way to
/// write one. Its `Debug` prints no content. The fields are reached only by
/// calling [`verify_signature`](Self::verify_signature) to obtain a
/// [`VerifiedHead`].
#[derive(Clone)]
pub struct Head(HeadWire);

impl fmt::Debug for Head {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Head").finish_non_exhaustive()
    }
}

/// The head document's wire shape. Private, so its serde implementations are
/// reachable only through [`Head::from_json`] / [`Head::to_json`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)] // an unknown field is unsigned data riding a signed document
struct HeadWire {
    format: u32,
    seq: u64,
    keys: Vec<KeyRecord>,
    rows: Vec<ReleaseRow>,
    /// Ed25519 signature of the unsigned head's `fuz_crypto::SignedMessage`
    /// — the head tag, then its canonical JSON.
    signature: fuz_crypto::Signature,
}

impl HeadWire {
    fn validate(&self) -> Result<(), ReleaseLogError> {
        validate_body(self.format, self.seq, &self.keys, &self.rows)?;
        // Outside the signed bytes, so anyone relaying the document can
        // rewrite it: held to the one shape a signer emits.
        check_field(
            HeadField::SignedAt,
            &self.signature.signed_at,
            fuz_sys::is_rfc3339_utc_seconds,
        )?;
        Ok(())
    }

    fn to_json(&self) -> Result<String, serde_json::Error> {
        let mut json = serde_json::to_string_pretty(self)?;
        json.push('\n');
        Ok(json)
    }

    /// The unsigned fields, as signed.
    fn unsigned(&self) -> HeadUnsigned {
        HeadUnsigned {
            format: self.format,
            seq: self.seq,
            keys: self.keys.clone(),
            rows: self.rows.clone(),
        }
    }

    /// Whether two heads carry the same unsigned content. The signature is not
    /// compared: its `signed_at` is informational, so one head signed twice is
    /// still one head.
    fn same_content(&self, other: &Self) -> bool {
        self.format == other.format
            && self.seq == other.seq
            && self.keys == other.keys
            && self.rows == other.rows
    }
}

/// The one field read before the strict parse, so a head from a different
/// format reports as unsupported rather than as whatever shape mismatch its
/// fields happen to cause.
#[derive(Deserialize)]
struct FormatProbe {
    format: u32,
}

impl Head {
    /// Assemble a `Head` from unsigned data plus a computed signature.
    ///
    /// Signing lives in `fuz_sign` (`sign_head` validates, computes the
    /// signature, then calls this). Nothing is checked here; a head assembled
    /// from parts is validated when its signature is verified.
    #[must_use]
    pub fn from_parts(unsigned: HeadUnsigned, signature: fuz_crypto::Signature) -> Self {
        Self(HeadWire {
            format: unsigned.format,
            seq: unsigned.seq,
            keys: unsigned.keys,
            rows: unsigned.rows,
            signature,
        })
    }

    /// Parse and structurally validate a head from JSON bytes.
    ///
    /// Strict: unknown fields are refused at every level, as are duplicate
    /// object keys — a reader that keeps the first of two keys and one that
    /// keeps the last would otherwise read different digests out of one signed
    /// document. Optional fields are absent, never `null`.
    ///
    /// Does NOT verify the signature (call
    /// [`verify_signature`](Self::verify_signature)).
    ///
    /// # Errors
    ///
    /// [`ReleaseLogError::TooLarge`] past [`MAX_HEAD_SIZE`],
    /// [`ReleaseLogError::Parse`] for malformed JSON or a shape mismatch,
    /// [`ReleaseLogError::UnsupportedFormat`] for a foreign `format`, and
    /// [`ReleaseLogError::Invalid`] for a structural-rule failure.
    pub fn from_json(bytes: &[u8]) -> Result<Self, ReleaseLogError> {
        let size = bytes.len() as u64;
        if size > MAX_HEAD_SIZE {
            return Err(ReleaseLogError::TooLarge(size));
        }
        let probe: FormatProbe = serde_json::from_slice(bytes)?;
        if probe.format != HEAD_FORMAT_VERSION {
            return Err(ReleaseLogError::UnsupportedFormat(probe.format));
        }
        let wire: HeadWire = serde_json::from_slice(bytes)?;
        wire.validate()?;
        Ok(Self(wire))
    }

    /// Serialize as the on-disk `head.json`: pretty-printed, newline-terminated,
    /// and deterministic — fields in declaration order, maps sorted by key,
    /// rows and keys in insertion order — so a change to the head is a minimal
    /// line diff.
    ///
    /// The single serializer of a head. `fuz_sign::sign_head` reads these bytes
    /// back through [`from_json`](Self::from_json), so the document a publisher
    /// writes is one a reader accepted.
    ///
    /// # Errors
    ///
    /// Propagates a serializer failure; none is reachable for this type.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        self.0.to_json()
    }

    /// Verify the embedded signature, **consuming** `self` and yielding a
    /// [`VerifiedHead`] — the sole producer of that type.
    ///
    /// Re-runs the structural validation (so a head assembled with
    /// [`from_parts`](Self::from_parts) is held to the same rules as a parsed
    /// one), builds the signed bytes of the unsigned fields (the head tag,
    /// then the canonical JSON — `fuz_crypto::SignedMessage`), and verifies
    /// the signature against the embedded trusted keys via
    /// `fuz_crypto::verify_signature`.
    ///
    /// Then checks that the head's own [`to_json`](Self::to_json) document is
    /// within [`MAX_HEAD_SIZE`]. The limit a reader applies is on the bytes it
    /// was given, and a compact encoding of a head is smaller than the document
    /// `to_json` writes — so a head can be read from compact bytes under the
    /// limit and still be too large to write back. Refusing it here means every
    /// [`VerifiedHead`] can be stored with [`VerifiedHead::to_json`] and read
    /// again.
    ///
    /// # Errors
    ///
    /// [`ReleaseLogError::Signature`] if the key is untrusted or the signature
    /// does not cover this content; the structural errors of
    /// [`from_json`](Self::from_json); [`ReleaseLogError::Canonical`] if
    /// canonical serialization fails; [`ReleaseLogError::TooLarge`] if the
    /// head's `to_json` document exceeds [`MAX_HEAD_SIZE`].
    pub fn verify_signature(self) -> Result<VerifiedHead, ReleaseLogError> {
        let head = self.0;
        head.validate()?;
        let message = fuz_crypto::SignedMessage::new(&head.unsigned())?;
        let signed_by = fuz_crypto::verify_signature(&message, &head.signature)?;
        // After the signature, so a forged document is reported as forged and
        // the on-disk document is built only for an authenticated head.
        let size = head.to_json()?.len() as u64;
        if size > MAX_HEAD_SIZE {
            return Err(ReleaseLogError::TooLarge(size));
        }
        Ok(VerifiedHead { head, signed_by })
    }
}

/// A [`Head`] whose embedded signature has been verified against the embedded
/// trusted keys (`fuz_crypto::PUBLIC_KEYS`).
///
/// **Typestate.** Produced *solely* by [`Head::verify_signature`], and the only
/// type with read accessors or accepted by [`check_superset`] /
/// [`check_successor`] / [`check_consistent`]. Holding one means the content
/// was signed by a trusted release key and is structurally valid. Its `Debug`
/// shows the content — there is nothing left to withhold once the signature
/// has verified. It has no serde implementations; [`to_json`](Self::to_json)
/// writes the document.
#[derive(Debug, Clone)]
pub struct VerifiedHead {
    head: HeadWire,
    signed_by: fuz_crypto::VerifyingKey,
}

impl VerifiedHead {
    /// The head's monotonic counter.
    #[must_use]
    pub const fn seq(&self) -> u64 {
        self.head.seq
    }

    /// The release-key history. Record only — see [`KeyRecord`]; trust is
    /// [`signed_by`](Self::signed_by) having passed `fuz_crypto::is_trusted_key`.
    #[must_use]
    pub fn keys(&self) -> &[KeyRecord] {
        &self.head.keys
    }

    /// Every release row, in insertion order.
    #[must_use]
    pub fn rows(&self) -> &[ReleaseRow] {
        &self.head.rows
    }

    /// The row for `(name, version)`, if the head records that release.
    ///
    /// A revoked release is still found — its row says so in
    /// [`ReleaseRow::status`].
    #[must_use]
    pub fn row(&self, name: &str, version: &str) -> Option<&ReleaseRow> {
        find_row(&self.head.rows, name, version)
    }

    /// What release `(name, version)` pins for `target`, if recorded.
    #[must_use]
    pub fn target(&self, name: &str, version: &str, target: &str) -> Option<&TargetRow> {
        self.row(name, version)?.targets.get(target)
    }

    /// The trusted key whose signature verified this head.
    #[must_use]
    pub const fn signed_by(&self) -> &fuz_crypto::VerifyingKey {
        &self.signed_by
    }

    /// The embedded signature.
    ///
    /// Its `signed_at` is **not covered by the signature**: anyone relaying the
    /// document can rewrite it, so it must never feed a decision. It is held
    /// to the timestamp shape and nothing more. Which key signed is
    /// [`signed_by`](Self::signed_by).
    #[must_use]
    pub const fn signature(&self) -> &fuz_crypto::Signature {
        &self.head.signature
    }

    /// A copy of the unsigned fields — what a publisher extends (append a row,
    /// add a target, bump `seq`) and signs as the next head.
    #[must_use]
    pub fn to_unsigned(&self) -> HeadUnsigned {
        self.head.unsigned()
    }

    /// Serialize as the on-disk `head.json` (see [`Head::to_json`]).
    ///
    /// # Errors
    ///
    /// Propagates a serializer failure; none is reachable for this type.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        self.head.to_json()
    }

    /// Reclaim the inner, opaque [`Head`].
    #[must_use]
    pub fn into_head(self) -> Head {
        Head(self.head)
    }
}

/// How a fresh head relates to the cached one it replaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Succession {
    /// Same `seq`, same content: the fresh head is the cached head.
    Unchanged,
    /// Greater `seq` and a superset: the log moved forward.
    Advanced,
}

/// Which of two consistent heads is the newer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeadOrder {
    /// Same `seq`, same content.
    Identical,
    /// The first head is ahead; the second is a lagging copy of the same log.
    FirstNewer,
    /// The second head is ahead; the first is a lagging copy of the same log.
    SecondNewer,
}

/// Rule: the log only grows. `new` must contain everything `old` records.
///
/// Compares content only — `seq` is the business of [`check_successor`] and
/// [`check_consistent`]. `new` is a superset of `old` when:
///
/// - **Rows are a prefix.** Row `i` of `old` is row `i` of `new`, matched by
///   `(name, version)`. Rows are added at the end and never removed, renamed,
///   or moved. Position is enforced, not just presence: insertion order is
///   part of the record, a publisher has no reason to reorder it, and holding
///   it fixed makes every honest head a literal prefix of its successors.
/// - **A row's facts are fixed.** `published_at` never changes.
/// - **Status is monotonic.** `ok` may become `revoked`; `revoked` never
///   becomes `ok`, so a withdrawn release cannot be quietly reinstated.
/// - **Targets only grow.** Every target `old` records is in `new` with an
///   identical entry — every field, including `sha512` being present or
///   absent. New targets may appear, because a release's targets are published
///   one at a time. An existing entry is immutable in full: its digests are
///   what earlier readers installed against.
/// - **Key records are a prefix too.** A record is never removed or moved, its
///   `added_at` never changes, and `retired_at` may go from absent to set but
///   never change or unset. (The list stays record-only — see [`KeyRecord`].)
///
/// # Errors
///
/// The first [`HeadViolation`] found, naming the row, target, or key and the
/// field at fault.
pub fn check_superset(old: &VerifiedHead, new: &VerifiedHead) -> Result<(), HeadViolation> {
    superset(&old.head, &new.head)
}

/// Rule: a head that replaces a cached one never moves a reader backwards.
///
/// - `fresh.seq > cached.seq` — `fresh` must be a superset of `cached`
///   ([`check_superset`]): [`Succession::Advanced`].
/// - `fresh.seq == cached.seq` — the content must be identical
///   ([`Succession::Unchanged`]); one `seq` naming two different heads is
///   [`HeadViolation::SeqReused`].
/// - `fresh.seq < cached.seq` — never a valid successor
///   ([`HeadViolation::SeqRegressed`]), even when its content is an honest
///   earlier state: accepting it would hide every row and revocation recorded
///   since.
///
/// # Errors
///
/// A [`HeadViolation`] per the cases above.
pub fn check_successor(
    cached: &VerifiedHead,
    fresh: &VerifiedHead,
) -> Result<Succession, HeadViolation> {
    if fresh.seq() < cached.seq() {
        return Err(HeadViolation::SeqRegressed {
            cached: cached.seq(),
            fresh: fresh.seq(),
        });
    }
    match check_consistent(cached, fresh)? {
        HeadOrder::Identical => Ok(Succession::Unchanged),
        HeadOrder::SecondNewer => Ok(Succession::Advanced),
        // Needs `cached.seq > fresh.seq`, refused above; refused here too so
        // this arm can never become an acceptance.
        HeadOrder::FirstNewer => Err(HeadViolation::SeqRegressed {
            cached: cached.seq(),
            fresh: fresh.seq(),
        }),
    }
}

/// Rule: two heads describe one history.
///
/// What a reader holding heads from two origins checks. They are consistent
/// when the one with the greater `seq` is a superset of the other
/// ([`check_superset`]), or when their `seq` is equal and their content
/// identical. An origin that is merely behind is **not** a contradiction — the
/// result says which head is newer. Two heads where the higher-`seq` one does
/// not contain the other, or that share a `seq` but differ, cannot both be
/// states of one append-only log.
///
/// # Errors
///
/// The [`HeadViolation`] that makes the two heads irreconcilable.
pub fn check_consistent(a: &VerifiedHead, b: &VerifiedHead) -> Result<HeadOrder, HeadViolation> {
    match a.seq().cmp(&b.seq()) {
        std::cmp::Ordering::Equal => {
            if a.head.same_content(&b.head) {
                Ok(HeadOrder::Identical)
            } else {
                Err(HeadViolation::SeqReused { seq: a.seq() })
            }
        }
        std::cmp::Ordering::Less => superset(&a.head, &b.head).map(|()| HeadOrder::SecondNewer),
        std::cmp::Ordering::Greater => superset(&b.head, &a.head).map(|()| HeadOrder::FirstNewer),
    }
}

fn find_row<'a>(rows: &'a [ReleaseRow], name: &str, version: &str) -> Option<&'a ReleaseRow> {
    rows.iter()
        .find(|row| row.name == name && row.version == version)
}

/// The superset rule over the head content. Both heads are structurally valid
/// (a [`VerifiedHead`] invariant), so row and key identities are unique.
fn superset(old: &HeadWire, new: &HeadWire) -> Result<(), HeadViolation> {
    for (index, old_key) in old.keys.iter().enumerate() {
        let public_key = || old_key.public_key.clone();
        let new_key = match new.keys.get(index) {
            Some(key) if key.public_key == old_key.public_key => key,
            _ if new
                .keys
                .iter()
                .any(|key| key.public_key == old_key.public_key) =>
            {
                return Err(HeadViolation::KeyMoved {
                    public_key: public_key(),
                });
            }
            _ => {
                return Err(HeadViolation::KeyRemoved {
                    public_key: public_key(),
                });
            }
        };
        if new_key.added_at != old_key.added_at {
            return Err(HeadViolation::KeyAddedAtChanged {
                public_key: public_key(),
            });
        }
        // Absent → set is the one allowed change; a set value is final.
        if old_key.retired_at.is_some() && new_key.retired_at != old_key.retired_at {
            return Err(HeadViolation::KeyRetiredAtChanged {
                public_key: public_key(),
            });
        }
    }

    for (index, old_row) in old.rows.iter().enumerate() {
        let name = || old_row.name.clone();
        let version = || old_row.version.clone();
        let new_row = match new.rows.get(index) {
            Some(row) if row.name == old_row.name && row.version == old_row.version => row,
            _ if find_row(&new.rows, &old_row.name, &old_row.version).is_some() => {
                return Err(HeadViolation::RowMoved {
                    name: name(),
                    version: version(),
                });
            }
            _ => {
                return Err(HeadViolation::RowRemoved {
                    name: name(),
                    version: version(),
                });
            }
        };
        if new_row.published_at != old_row.published_at {
            return Err(HeadViolation::PublishedAtChanged {
                name: name(),
                version: version(),
            });
        }
        if old_row.status == RowStatus::Revoked && new_row.status == RowStatus::Ok {
            return Err(HeadViolation::RevocationUndone {
                name: name(),
                version: version(),
            });
        }
        for (target, old_target) in &old_row.targets {
            let Some(new_target) = new_row.targets.get(target) else {
                return Err(HeadViolation::TargetRemoved {
                    name: name(),
                    version: version(),
                    target: target.clone(),
                });
            };
            let field = if new_target.content_hash != old_target.content_hash {
                TargetField::ContentHash
            } else if new_target.binaries != old_target.binaries {
                TargetField::Binaries
            } else if new_target.sha512 != old_target.sha512 {
                TargetField::Sha512
            } else {
                continue;
            };
            return Err(HeadViolation::TargetChanged {
                name: name(),
                version: version(),
                target: target.clone(),
                field,
            });
        }
    }
    Ok(())
}

/// The structural rules shared by [`HeadUnsigned::validate`] and [`Head`].
fn validate_body(
    format: u32,
    seq: u64,
    keys: &[KeyRecord],
    rows: &[ReleaseRow],
) -> Result<(), ReleaseLogError> {
    if format != HEAD_FORMAT_VERSION {
        return Err(ReleaseLogError::UnsupportedFormat(format));
    }
    if seq == 0 || seq > MAX_HEAD_SEQ {
        return Err(HeadInvalid::SeqOutOfRange(seq).into());
    }

    let mut seen_keys = BTreeSet::new();
    for key in keys {
        check_field(
            HeadField::KeyPublicKey,
            &key.public_key,
            is_public_key_shape,
        )?;
        check_field(
            HeadField::KeyAddedAt,
            &key.added_at,
            fuz_sys::is_rfc3339_utc_seconds,
        )?;
        if let Some(retired_at) = &key.retired_at {
            check_field(
                HeadField::KeyRetiredAt,
                retired_at,
                fuz_sys::is_rfc3339_utc_seconds,
            )?;
        }
        if !seen_keys.insert(key.public_key.as_str()) {
            return Err(HeadInvalid::DuplicateKey(key.public_key.clone()).into());
        }
    }

    let mut seen_rows = BTreeSet::new();
    for row in rows {
        check_field(HeadField::Name, &row.name, is_release_token)?;
        check_field(HeadField::Version, &row.version, is_release_token)?;
        check_field(
            HeadField::PublishedAt,
            &row.published_at,
            fuz_sys::is_rfc3339_utc_seconds,
        )?;
        if !seen_rows.insert((row.name.as_str(), row.version.as_str())) {
            return Err(HeadInvalid::DuplicateRow {
                name: row.name.clone(),
                version: row.version.clone(),
            }
            .into());
        }
        if row.targets.is_empty() {
            return Err(HeadInvalid::NoTargets {
                name: row.name.clone(),
                version: row.version.clone(),
            }
            .into());
        }
        for (target, entry) in &row.targets {
            check_field(HeadField::Target, target, is_release_token)?;
            check_field(HeadField::ContentHash, &entry.content_hash, is_content_hash)?;
            if entry.binaries.is_empty() {
                return Err(HeadInvalid::NoBinaries {
                    name: row.name.clone(),
                    version: row.version.clone(),
                    target: target.clone(),
                }
                .into());
            }
            for (binary, hash) in &entry.binaries {
                check_field(HeadField::BinaryName, binary, is_release_token)?;
                check_algo(HeadField::BinaryHash, hash, HashAlgo::Blake3)?;
            }
            if let Some(sha512) = &entry.sha512 {
                check_algo(HeadField::Sha512, sha512, HashAlgo::Sha512)?;
            }
        }
    }
    Ok(())
}

fn check_field(
    field: HeadField,
    value: &str,
    is_valid: fn(&str) -> bool,
) -> Result<(), HeadInvalid> {
    if is_valid(value) {
        Ok(())
    } else {
        Err(HeadInvalid::Field {
            field,
            value: excerpt(value),
        })
    }
}

/// `value` for an error message: whole when it fits [`MAX_ERROR_VALUE_LEN`],
/// otherwise its longest prefix that does (cut on a character boundary) with
/// `...` appended.
pub(crate) fn excerpt(value: &str) -> String {
    truncate(value, MAX_ERROR_VALUE_LEN)
}

/// Text from a document, a store, or the environment, for an error message:
/// cut as `excerpt` cuts it, then escaped. Unquoted; `quoted` over an
/// `excerpt` is the quoted form.
pub(crate) fn shown(text: &str) -> String {
    escape_untrusted(&excerpt(text))
}

/// A digest field holds the algorithm its wire form implies. Parsed heads
/// satisfy this by construction; it guards a producer-built [`HeadUnsigned`],
/// whose bare-hex wire form would otherwise carry a digest of the wrong
/// algorithm unlabeled.
fn check_algo(field: HeadField, hash: &ContentHash, algo: HashAlgo) -> Result<(), HeadInvalid> {
    if hash.algo() == algo {
        Ok(())
    } else {
        Err(HeadInvalid::Field {
            field,
            value: hash.to_prefixed(),
        })
    }
}

/// The base64 shape of a 32-byte ed25519 public key: 43 alphabet characters
/// and one `=` pad. Shape only — the list is record-only (see [`KeyRecord`]),
/// so nothing decodes the key or checks it is a curve point.
fn is_public_key_shape(s: &str) -> bool {
    let bytes = s.as_bytes();
    bytes.len() == 44
        && bytes[43] == b'='
        && bytes[..43]
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/'))
}

/// Parse a bare-hex digest in the one spelling a head carries
/// (`ContentHash::from_lower_hex`: full length, lowercase): a head's digests
/// are compared as text by readers that are not this crate (the install
/// script against `sha512sum` output), so there is one spelling.
fn parse_lower_hex<E: serde::de::Error>(algo: HashAlgo, hex: &str) -> Result<ContentHash, E> {
    // The excerpt goes in as it is: the message is escaped once, whole, on its
    // way into a `ReleaseLogError::Parse`.
    ContentHash::from_lower_hex(algo, hex)
        .map_err(|e| E::custom(format_args!("{e}, got \"{}\"", excerpt(hex))))
}

/// Deserialize an optional field that is omitted when unset: a present value
/// must be a real one, so `null` is refused. Paired with `default` (absent →
/// `None`) and `skip_serializing_if`, this leaves each head one spelling of
/// "unset" — the signed canonical bytes never contain a `null`.
fn deserialize_present<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

/// Serde adapter for [`TargetRow::binaries`]: the manifest's wire shape (bare
/// BLAKE3 hex per binary, via `fuz_crypto::blake3_hex_map`), read strictly —
/// unique keys and lowercase full-length hex.
mod binary_hashes {
    use super::{BTreeMap, ContentHash, Deserializer, HashAlgo, Serializer, parse_lower_hex};

    pub(super) fn serialize<S: Serializer>(
        map: &BTreeMap<String, ContentHash>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        fuz_crypto::blake3_hex_map::serialize(map, serializer)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<BTreeMap<String, ContentHash>, D::Error> {
        fuz_crypto::unique_map::deserialize::<D, String>(deserializer)?
            .into_iter()
            .map(|(name, hex)| parse_lower_hex(HashAlgo::Blake3, &hex).map(|hash| (name, hash)))
            .collect()
    }
}

/// Serde adapter for [`TargetRow::sha512`]: bare lowercase SHA-512 hex when
/// present. Absence is handled by the field's `default` /
/// `skip_serializing_if`, so `null` is refused here.
mod present_sha512 {
    use super::{ContentHash, Deserialize, Deserializer, HashAlgo, Serializer, parse_lower_hex};

    // `&Option<T>` is the signature serde's `with` calls.
    #[allow(clippy::ref_option)]
    pub(super) fn serialize<S: Serializer>(
        hash: &Option<ContentHash>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match hash {
            Some(hash) => serializer.serialize_str(&hash.to_hex()),
            // Unreachable through `skip_serializing_if`; kept total.
            None => serializer.serialize_none(),
        }
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<ContentHash>, D::Error> {
        let hex = String::deserialize(deserializer)?;
        parse_lower_hex(HashAlgo::Sha512, &hex).map(Some)
    }
}

/// A field of a head, named by a structural-validation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeadField {
    /// A row's `name`.
    Name,
    /// A row's `version`.
    Version,
    /// A row's `published_at`.
    PublishedAt,
    /// A key of a row's `targets` map.
    Target,
    /// A target's `content_hash`.
    ContentHash,
    /// A key of a target's `binaries` map.
    BinaryName,
    /// A value of a target's `binaries` map.
    BinaryHash,
    /// A target's `sha512`.
    Sha512,
    /// A key record's `public_key`.
    KeyPublicKey,
    /// A key record's `added_at`.
    KeyAddedAt,
    /// A key record's `retired_at`.
    KeyRetiredAt,
    /// The signature's `signed_at`.
    SignedAt,
}

impl fmt::Display for HeadField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Name => "row name",
            Self::Version => "row version",
            Self::PublishedAt => "row published_at",
            Self::Target => "target",
            Self::ContentHash => "target content_hash",
            Self::BinaryName => "binary name",
            Self::BinaryHash => "binary hash",
            Self::Sha512 => "target sha512",
            Self::KeyPublicKey => "key public_key",
            Self::KeyAddedAt => "key added_at",
            Self::KeyRetiredAt => "key retired_at",
            Self::SignedAt => "signature signed_at",
        })
    }
}

/// A head that breaks a structural rule on its own, before any comparison.
///
/// A malformed document, not evidence of a rewritten history — contrast
/// [`HeadViolation`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HeadInvalid {
    #[error("seq {0} is out of range (1..={MAX_HEAD_SEQ})")]
    SeqOutOfRange(u64),
    #[error("duplicate row: {name} {version}")]
    DuplicateRow { name: String, version: String },
    #[error("duplicate key record: {0}")]
    DuplicateKey(String),
    #[error("row {name} {version} has no targets")]
    NoTargets { name: String, version: String },
    #[error("row {name} {version} target {target} has no binaries")]
    NoBinaries {
        name: String,
        version: String,
        target: String,
    },
    #[error("invalid {field}: {}", quoted(.value))]
    Field { field: HeadField, value: String },
}

/// The field of an existing target entry that a later head changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetField {
    /// `content_hash`.
    ContentHash,
    /// The `binaries` map — a binary added, removed, or re-hashed.
    Binaries,
    /// `sha512` — changed, added, or dropped.
    Sha512,
}

impl fmt::Display for TargetField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ContentHash => "content_hash",
            Self::Binaries => "binaries",
            Self::Sha512 => "sha512",
        })
    }
}

/// What vouches for the hashes a release is held to the log with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinnedBy {
    /// A manifest whose signature verified against a trusted key.
    SignedManifest,
    /// The hash of a binary file on this machine. Nothing signed stands
    /// behind it: the log is the only statement about the release.
    LocalBinary,
}

impl fmt::Display for PinnedBy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::SignedManifest => "its signed manifest",
            Self::LocalBinary => "this binary",
        })
    }
}

/// Two verified heads that cannot both be states of one append-only log.
///
/// Every variant is a security violation: both heads carry a trusted
/// signature, so the disagreement is not corruption in transit — the history
/// one reader was shown is not the history another was shown.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HeadViolation {
    #[error("seq went backwards: cached {cached}, offered {fresh}")]
    SeqRegressed { cached: u64, fresh: u64 },
    #[error("two different heads share seq {seq}")]
    SeqReused { seq: u64 },
    #[error("row removed: {name} {version}")]
    RowRemoved { name: String, version: String },
    #[error("row moved from its recorded position: {name} {version}")]
    RowMoved { name: String, version: String },
    #[error("published_at changed for {name} {version}")]
    PublishedAtChanged { name: String, version: String },
    #[error("revocation undone for {name} {version}")]
    RevocationUndone { name: String, version: String },
    #[error("target removed: {name} {version} {target}")]
    TargetRemoved {
        name: String,
        version: String,
        target: String,
    },
    #[error("{field} changed for {name} {version} {target}")]
    TargetChanged {
        name: String,
        version: String,
        target: String,
        field: TargetField,
    },
    #[error("key record removed: {public_key}")]
    KeyRemoved { public_key: String },
    #[error("key record moved from its recorded position: {public_key}")]
    KeyMoved { public_key: String },
    #[error("added_at changed for key record {public_key}")]
    KeyAddedAtChanged { public_key: String },
    #[error("retired_at changed or unset for key record {public_key}")]
    KeyRetiredAtChanged { public_key: String },
}

/// A release log that contradicts itself, an earlier reading of it, or the
/// release it is asked about.
///
/// Every variant is a security violation. A head is authenticated by its
/// trusted signature, so none of these is damage in transit to the log; the
/// release it is asked about is pinned by a signed manifest or by the bytes of
/// a local binary ([`PinnedBy`]). A co-signature mismatch is one origin's
/// served bytes against the statement its own co-signer signed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LogContradiction {
    /// Two witnesses serve verified heads that are not one history at
    /// different lengths.
    #[error("witnesses {first} and {second} serve heads that are not one history: {violation}")]
    HeadsDiverge {
        /// The origin of one head.
        first: String,
        /// The origin of the other.
        second: String,
        violation: Box<HeadViolation>,
    },
    /// A witness serves a head that does not contain the head this machine
    /// cached from an earlier check.
    #[error("witness {origin} serves a head that does not contain the cached one: {violation}")]
    SupersetViolated {
        /// The origin whose head disagrees with the cache.
        origin: String,
        violation: Box<HeadViolation>,
    },
    /// The log records the release, with digests other than the ones it is
    /// held to the log with.
    #[error("the release log records other {field} for {name} {version} {target} than {pinned_by}")]
    HashMismatch {
        name: String,
        version: String,
        target: String,
        field: TargetField,
        /// What the compared digests came from.
        pinned_by: PinnedBy,
    },
    /// A witness serves a `head.json` at a `seq` for which its own co-signer
    /// signed the digest of other bytes. The comparison is of that origin's
    /// served bytes with that origin's co-signature, and of nothing else: it
    /// says the origin and its co-signer disagree, not that two heads were
    /// signed for one `seq`.
    #[error(
        "witness {origin} serves a head.json at seq {seq} that its own co-signature does not \
         cover"
    )]
    CoSignMismatch {
        /// The origin whose served head and co-signature disagree.
        origin: String,
        /// The `seq` both name.
        seq: u64,
    },
}

/// Why the cached head cannot be used.
#[derive(Debug, thiserror::Error)]
pub enum CacheProblem {
    /// The file could not be read as a plain bounded file: it is a symlink,
    /// not a regular file, over the size limit, or unreadable.
    #[error("{0}")]
    File(#[source] fuz_sys::secure_file::SecureFileError),
    /// The file was read, and is not a head this binary accepts.
    #[error("{0}")]
    Head(#[source] Box<ReleaseLogError>),
    /// A newer head could not be written.
    #[error("write failed: {0}")]
    Write(#[source] std::io::Error),
}

/// A release log configuration the check cannot run under.
#[derive(Debug, thiserror::Error)]
pub enum LogConfigError {
    /// `FUZ_RELEASE_LOG` holds something other than `off`.
    #[error("invalid FUZ_RELEASE_LOG value {} (the only value is \"off\")", quoted(.value))]
    InvalidSwitch {
        /// The value, bounded; the message escapes it.
        value: String,
    },
    /// An entry of `FUZ_RELEASE_LOG_URL` is not a usable origin. The message
    /// names the entry by its position and nothing else: a URL can carry a
    /// credential, and the storage error that explains the refusal can repeat
    /// the URL, so that error is kept beside the message and is neither part
    /// of it nor its `source()` — a printer of the source chain never reaches
    /// it.
    #[error(
        "invalid FUZ_RELEASE_LOG_URL entry {position}, counting non-empty entries \
         (not a usable storage location)"
    )]
    InvalidOrigin {
        /// 1-based position among the non-empty entries.
        position: usize,
        /// Why the entry was refused. It can repeat the entry, credential and
        /// all: not for printing.
        refusal: fuz_storage::StorageError,
    },
    /// A configured origin cannot serve a head at all — a failure that
    /// retrying does not change.
    #[error("release log origin {origin} cannot serve a head: {source}")]
    OriginUnusable {
        origin: String,
        #[source]
        source: fuz_storage::StorageError,
    },
}

/// A witness that did not serve a head, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnreachableOrigin {
    /// The origin as configured.
    pub origin: String,
    /// The transport failure, bounded and with control characters escaped.
    pub reason: String,
}

impl fmt::Display for UnreachableOrigin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.origin, self.reason)
    }
}

/// The witnesses of an [`ReleaseLogError::Unconfirmed`], for its message.
fn list_witnesses(witnesses: &[UnreachableOrigin]) -> String {
    witnesses
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// Errors from reading, verifying, and comparing release log heads, and from
/// holding a release to the log before installing it.
#[derive(Debug, thiserror::Error)]
pub enum ReleaseLogError {
    #[error("release log head too large: {0} bytes (max {MAX_HEAD_SIZE})")]
    TooLarge(u64),
    /// The parser's message, bounded and with control characters escaped (see
    /// the `From<serde_json::Error>` impl).
    #[error("failed to parse release log head: {0}")]
    Parse(String),
    #[error("unsupported release log head format: {0} (supported: {HEAD_FORMAT_VERSION})")]
    UnsupportedFormat(u32),
    #[error("invalid release log head: {0}")]
    Invalid(#[from] HeadInvalid),
    #[error("canonical JSON error: {0}")]
    Canonical(#[from] fuz_crypto::CanonicalError),
    #[error("release log head signature verification failed: {0}")]
    Signature(#[from] fuz_crypto::VerifyError),
    #[error("release log violation: {0}")]
    Violation(#[from] HeadViolation),
    /// A witness answered with a document that is not a usable head. The
    /// source says why; it is never the source's `WitnessHead` in turn.
    #[error("release log witness {origin} served an unusable head: {source}")]
    WitnessHead {
        origin: String,
        #[source]
        source: Box<Self>,
    },
    /// A witness with an embedded witness key serves a `witness` file that
    /// cannot be used: its signature does not verify against that key, or it
    /// is not in the form a co-signature has. Like an unusable head, never skipped in favor
    /// of another witness. A witness serving no co-signature is not this.
    #[error("release log witness {origin} served an unusable co-signature: {source}")]
    WitnessCoSign {
        origin: String,
        #[source]
        source: crate::co_sign::CoSignProblem,
    },
    /// The log says the release was withdrawn.
    #[error("{name} {version} is revoked in the release log")]
    Revoked { name: String, version: String },
    /// A reachable witness's log has no row for the release, or its row lacks
    /// this target.
    #[error("the release log does not record {name} {version} for {target}")]
    RowMissing {
        name: String,
        version: String,
        target: String,
        /// What the release was held to the log by — a release served by a
        /// storage host, or a binary on this machine.
        pinned_by: PinnedBy,
    },
    /// No witness could be reached and no cached head covers the release.
    /// **Not a refusal**: nothing says the release is bad, only that it could
    /// not be confirmed.
    #[error(
        "cannot confirm {name} {version} ({target}) in the release log yet: \
         no witness reachable (tried {})",
        list_witnesses(witnesses)
    )]
    Unconfirmed {
        name: String,
        version: String,
        target: String,
        /// Every configured witness, in configuration order, with why it
        /// could not be reached.
        witnesses: Vec<UnreachableOrigin>,
    },
    #[error("release log contradiction: {0}")]
    Contradiction(#[from] LogContradiction),
    /// The head cached from an earlier check exists and cannot be used. Never
    /// treated as absent: the cache is what a fresh head is compared against,
    /// so skipping it would drop that comparison silently.
    #[error("cached release log head {} is unusable: {problem}", path.display())]
    CacheUnusable {
        path: std::path::PathBuf,
        #[source]
        problem: CacheProblem,
    },
    #[error("release log configuration error: {0}")]
    Config(#[from] LogConfigError),
}

impl From<serde_json::Error> for ReleaseLogError {
    /// Keeps a bounded, escaped rendering of the parser's message rather than
    /// the error itself: the message repeats an offending token from the
    /// document — a field name, a variant, a string of the wrong type — at
    /// whatever length and with whatever bytes it has.
    fn from(e: serde_json::Error) -> Self {
        Self::Parse(parse_message(&e))
    }
}

/// A JSON parser's message for an error message: bounded, escaped, and with
/// its position kept.
///
/// The parser's message repeats an offending token from the document — a
/// field name, a variant, a string of the wrong type — at whatever length and
/// with whatever bytes it has. It is escaped here, whole and once: a message
/// this crate's own deserializers add carries its excerpt raw.
pub(crate) fn parse_message(e: &serde_json::Error) -> String {
    let message = e.to_string();
    // serde_json appends the position; split it off so truncating the
    // message never loses it.
    let position = format!(" at line {} column {}", e.line(), e.column());
    let (message, position) = message
        .strip_suffix(position.as_str())
        .map_or((message.as_str(), ""), |rest| (rest, position.as_str()));
    format!("{}{position}", shown(message))
}

impl ReleaseLogError {
    /// Returns user-facing hint for how to fix this error
    #[allow(clippy::missing_const_for_fn)] // calls non-const hint() methods
    pub fn hint(&self) -> Option<&'static str> {
        match self {
            Self::TooLarge(_) => Some("Release log head exceeds size limit - possible attack"),
            Self::Parse(_) | Self::Invalid(_) => Some("Release log head is corrupted or malformed"),
            Self::UnsupportedFormat(_) => {
                Some("Upgrade fuz to read this release log: https://github.com/fuzdev/fuz#usage")
            }
            Self::Canonical(_) => {
                Some("Release log head fields must be ASCII strings and integers")
            }
            Self::Signature(e) => e.hint(),
            Self::Violation(_)
            | Self::Contradiction(
                LogContradiction::HeadsDiverge { .. } | LogContradiction::SupersetViolated { .. },
            ) => Some(
                "The release log contradicts a head seen earlier or elsewhere - do not install",
            ),
            // The log against the manifest, not one head against another.
            Self::Contradiction(LogContradiction::HashMismatch {
                pinned_by: PinnedBy::SignedManifest,
                ..
            }) => Some(
                "The storage host serves bytes other than the ones the release log records \
                 for this release - do not install",
            ),
            Self::Contradiction(LogContradiction::HashMismatch {
                pinned_by: PinnedBy::LocalBinary,
                ..
            }) => Some(
                "This binary is not the one the release log records for its version - do not \
                 install it unless you built it yourself. A locally built fuz is not a \
                 published release: FUZ_RELEASE_LOG=off skips the check for it",
            ),
            // One origin's served bytes against that origin's co-signature.
            Self::Contradiction(LogContradiction::CoSignMismatch { .. }) => Some(
                "The co-signer at this origin signed other head.json bytes for this seq than \
                 the ones the origin serves - do not install",
            ),
            Self::WitnessHead { source, .. } => source.hint(),
            // One advice for every cause: the remedy is the same, and it
            // keeps the rest of the check rather than switching it off.
            Self::WitnessCoSign { .. } => Some(
                "This origin serves a co-signature (its witness file) that this fuz cannot \
                 use. Removing the origin from FUZ_RELEASE_LOG_URL keeps the rest of the \
                 release log check",
            ),
            Self::Revoked { .. } => Some(
                "The publisher withdrew this release - install a different version. \
                 No flag overrides a revocation",
            ),
            Self::RowMissing {
                pinned_by: PinnedBy::SignedManifest,
                ..
            } => Some(
                "The storage host serves a release the release log does not record - \
                 do not install it",
            ),
            Self::RowMissing {
                pinned_by: PinnedBy::LocalBinary,
                ..
            } => Some(
                "The release log has no release with this binary's version and target. A \
                 locally built fuz is not a published release: FUZ_RELEASE_LOG=off skips \
                 the check for it",
            ),
            Self::Unconfirmed { .. } => Some(
                "This is not a refusal: no release log witness answered and no cached head \
                 covers this release. Retry later, or check FUZ_RELEASE_LOG_URL",
            ),
            Self::CacheUnusable {
                problem: CacheProblem::Write(_),
                ..
            } => Some(
                "The release log cache directory state/release_log under the fuz home is not \
                 writable - fix its permissions or free space",
            ),
            Self::CacheUnusable {
                problem: CacheProblem::File(_) | CacheProblem::Head(_),
                ..
            } => Some(
                "The cached head is state/release_log/head.json under the fuz home (~/.fuz \
                 unless FUZ_HOME is set). Removing it resets the release log's continuity \
                 record: the next head a witness serves is accepted with nothing to compare \
                 it against",
            ),
            Self::Config(e) => e.hint(),
        }
    }

    /// Returns true if this error indicates a security violation.
    ///
    /// Exhaustive on purpose (a new variant must be classified, never
    /// defaulted), and classified as the manifest's equivalents are: a failed
    /// signature or an untrusted key is a violation, as is every
    /// [`HeadViolation`] — two trusted-signed heads that disagree. An
    /// oversized, unparseable, unsupported, or structurally invalid document
    /// is a bad input, not on its own evidence of an attack. A signature in an
    /// envelope format this build does not read is classified with the
    /// signature failures: it cannot be told apart from a downgrade attempt.
    ///
    /// The install-time verdicts follow the same split. A revoked release, a
    /// release the log does not record, and every [`LogContradiction`] are
    /// violations: the log and the release disagree. The log is signed; the
    /// release is pinned by a signed manifest or by a local binary's own bytes
    /// ([`PinnedBy`]), and the classification is the same for both. A
    /// witness's unusable head is classified as its cause is, and so is a
    /// cached head that does not parse or verify; a witness's unusable
    /// co-signature likewise — a signature that fails to verify is a
    /// violation, a file that is oversized or malformed is not; a cache path that is a
    /// symlink or not a regular file is a violation, as a symlink in a log
    /// checkout is. [`Unconfirmed`](Self::Unconfirmed) is not — nothing was
    /// contradicted — and neither is a configuration error.
    pub const fn is_security_violation(&self) -> bool {
        use fuz_sys::secure_file::SecureFileError;
        match self {
            Self::Signature(_)
            | Self::Violation(_)
            | Self::Revoked { .. }
            | Self::RowMissing { .. }
            | Self::Contradiction(_) => true,
            Self::WitnessHead { source, .. } => source.is_security_violation(),
            Self::WitnessCoSign { source, .. } => source.is_security_violation(),
            Self::CacheUnusable { problem, .. } => match problem {
                CacheProblem::Head(e) => e.is_security_violation(),
                CacheProblem::File(
                    SecureFileError::Symlink(_) | SecureFileError::NotRegularFile(_),
                ) => true,
                CacheProblem::File(
                    SecureFileError::NotFound(_)
                    | SecureFileError::InsecurePermissions(_, _)
                    | SecureFileError::FileTooLarge(_, _, _)
                    | SecureFileError::Io(_, _),
                )
                | CacheProblem::Write(_) => false,
            },
            Self::TooLarge(_)
            | Self::Parse(_)
            | Self::UnsupportedFormat(_)
            | Self::Invalid(_)
            | Self::Canonical(_)
            | Self::Unconfirmed { .. }
            | Self::Config(_) => false,
        }
    }

    /// Returns true if the release could not be confirmed against the log —
    /// the one soft failure of the check.
    ///
    /// Nothing refused the release: no witness answered, and no cached head
    /// covers it. A caller treats it as "try again later", not as a verdict.
    pub const fn is_unconfirmed(&self) -> bool {
        matches!(self, Self::Unconfirmed { .. })
    }
}

impl LogConfigError {
    /// Returns user-facing hint for how to fix this error
    pub const fn hint(&self) -> Option<&'static str> {
        match self {
            Self::InvalidSwitch { .. } => Some(
                "Unset FUZ_RELEASE_LOG to keep the release log check, or set it to exactly \
                 \"off\" to disable it",
            ),
            Self::InvalidOrigin { .. } => Some(
                "FUZ_RELEASE_LOG_URL is a comma-separated list of origins, each an \
                 https://host/path URL (http:// for a loopback host) or an existing local \
                 directory (a path or file:// URI)",
            ),
            Self::OriginUnusable { .. } => Some("Fix or remove this entry of FUZ_RELEASE_LOG_URL"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::co_sign::CoSignProblem;
    use serde_json::{Value, json};

    const TARGET: &str = "x86_64-unknown-linux-gnu";
    const WHEN: &str = "2025-01-15T10:30:00Z";
    const KEY: &str = "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik=";

    fn b3(fill: &str) -> ContentHash {
        ContentHash::from_hex(HashAlgo::Blake3, &fill.repeat(64)).unwrap()
    }

    fn content_hash(fill: &str) -> String {
        format!("v1-{}", fill.repeat(64))
    }

    /// A placeholder signature. These tests cover parsing and structural
    /// validation, which never read it; signing and the rules over verified
    /// heads are exercised in `fuz_sign`'s `release_log` suite, which holds a
    /// key the trust check admits.
    fn dummy_signature() -> fuz_crypto::Signature {
        fuz_crypto::Signature {
            format: fuz_crypto::SIGNATURE_FORMAT_VERSION,
            public_key: String::new(),
            algorithm: fuz_crypto::SignatureAlgorithm::Ed25519,
            signed_at: WHEN.to_string(),
            sig: String::new(),
        }
    }

    fn target_row(fill: &str, sha512: Option<&[u8]>) -> TargetRow {
        TargetRow {
            content_hash: content_hash(fill),
            binaries: BTreeMap::from([("fuz".to_string(), b3(fill))]),
            sha512: sha512.map(ContentHash::sha512),
        }
    }

    fn sample() -> HeadUnsigned {
        HeadUnsigned {
            format: HEAD_FORMAT_VERSION,
            seq: 3,
            keys: vec![KeyRecord {
                public_key: KEY.to_string(),
                added_at: WHEN.to_string(),
                retired_at: None,
            }],
            rows: vec![ReleaseRow {
                name: "fuz".to_string(),
                version: "0.1.0".to_string(),
                status: RowStatus::Ok,
                published_at: WHEN.to_string(),
                targets: BTreeMap::from([(TARGET.to_string(), target_row("a", Some(b"fuz")))]),
            }],
        }
    }

    /// The sample head as a JSON value, for per-field mutation.
    fn sample_value() -> Value {
        let json = Head::from_parts(sample(), dummy_signature())
            .to_json()
            .unwrap();
        serde_json::from_str(&json).unwrap()
    }

    fn parse_value(value: &Value) -> Result<Head, ReleaseLogError> {
        Head::from_json(&serde_json::to_vec(value).unwrap())
    }

    /// Parse the sample head after `mutate` edits its JSON.
    fn parse_mutated(mutate: impl FnOnce(&mut Value)) -> Result<Head, ReleaseLogError> {
        let mut value = sample_value();
        mutate(&mut value);
        parse_value(&value)
    }

    /// Validate the sample head after `mutate` edits it in memory.
    fn validate_mutated(mutate: impl FnOnce(&mut HeadUnsigned)) -> Result<(), ReleaseLogError> {
        let mut head = sample();
        mutate(&mut head);
        head.validate()
    }

    fn target_value(value: &mut Value) -> &mut Value {
        &mut value["rows"][0]["targets"][TARGET]
    }

    #[track_caller]
    fn assert_parse_error(result: Result<Head, ReleaseLogError>, needle: &str) {
        match result {
            Err(ReleaseLogError::Parse(e)) => {
                assert!(e.contains(needle), "unexpected message: {e}");
            }
            other => panic!("expected a parse error containing {needle:?}, got {other:?}"),
        }
    }

    #[track_caller]
    fn assert_invalid_field<T: fmt::Debug>(result: Result<T, ReleaseLogError>, field: HeadField) {
        match result {
            Err(ReleaseLogError::Invalid(HeadInvalid::Field { field: got, .. })) => {
                assert_eq!(got, field);
            }
            other => panic!("expected an invalid {field}, got {other:?}"),
        }
    }

    //
    // Serialization
    //

    #[test]
    fn sample_head_is_valid_and_round_trips() {
        sample().validate().unwrap();
        let head = Head::from_parts(sample(), dummy_signature());
        let json = head.to_json().unwrap();
        let parsed = Head::from_json(json.as_bytes()).unwrap();
        assert!(parsed.0.same_content(&head.0));
        // Re-serializing a parsed head reproduces the file byte for byte.
        assert_eq!(parsed.to_json().unwrap(), json);
    }

    #[test]
    fn to_json_is_pretty_ordered_and_newline_terminated() {
        let json = Head::from_parts(sample(), dummy_signature())
            .to_json()
            .unwrap();
        assert!(json.ends_with("}\n"));
        assert!(json.starts_with("{\n  \"format\": 1,\n  \"seq\": 3,\n  \"keys\": ["));
        let position = |needle: &str| json.find(needle).unwrap();
        assert!(position("\"keys\"") < position("\"rows\""));
        assert!(position("\"rows\"") < position("\"signature\""));
    }

    #[test]
    fn unset_optional_fields_are_absent_not_null() {
        let mut head = sample();
        head.rows[0].targets.get_mut(TARGET).unwrap().sha512 = None;
        let json = Head::from_parts(head.clone(), dummy_signature())
            .to_json()
            .unwrap();
        assert!(!json.contains("null"), "json: {json}");
        assert!(!json.contains("sha512"), "json: {json}");
        assert!(!json.contains("retired_at"), "json: {json}");
        let canonical = fuz_crypto::canonical_json(&head).unwrap();
        assert!(!canonical.contains("null"), "canonical: {canonical}");
    }

    #[test]
    fn null_optional_fields_are_rejected() {
        // One spelling of "unset": the field is absent. `null` would be a
        // second document for the same signed bytes.
        assert_parse_error(
            parse_mutated(|v| target_value(v)["sha512"] = Value::Null),
            "invalid type: null",
        );
        assert_parse_error(
            parse_mutated(|v| v["keys"][0]["retired_at"] = Value::Null),
            "invalid type: null",
        );
    }

    //
    // Shape: unknown fields, format, size, truncation
    //

    #[test]
    fn unknown_fields_are_rejected_at_every_level() {
        let cases: [fn(&mut Value) -> &mut Value; 5] = [
            |v| v,
            |v| &mut v["keys"][0],
            |v| &mut v["rows"][0],
            |v| target_value(v),
            |v| &mut v["signature"],
        ];
        for (index, select) in cases.into_iter().enumerate() {
            let result = parse_mutated(|v| select(v)["extra"] = json!("x"));
            match result {
                Err(ReleaseLogError::Parse(e)) => {
                    assert!(e.contains("unknown field `extra`"), "{e}");
                }
                other => panic!("level {index}: expected unknown-field error, got {other:?}"),
            }
        }
    }

    #[test]
    fn missing_required_field_is_rejected() {
        assert_parse_error(
            parse_mutated(|v| {
                v.as_object_mut().unwrap().remove("keys");
            }),
            "missing field `keys`",
        );
        assert_parse_error(
            parse_mutated(|v| {
                v.as_object_mut().unwrap().remove("signature");
            }),
            "missing field `signature`",
        );
    }

    #[test]
    fn foreign_format_is_unsupported() {
        for format in [0u32, 2, 99] {
            let result = parse_mutated(|v| v["format"] = json!(format));
            assert!(
                matches!(result, Err(ReleaseLogError::UnsupportedFormat(f)) if f == format),
                "format {format}: {result:?}"
            );
        }
    }

    #[test]
    fn foreign_format_with_unknown_shape_is_unsupported_not_a_parse_error() {
        // A later format is free to add or rename fields; the reader still
        // says "unsupported format", not "unknown field".
        let result = Head::from_json(br#"{"format":2,"sequence":7,"entries":[]}"#);
        assert!(matches!(result, Err(ReleaseLogError::UnsupportedFormat(2))));
    }

    #[test]
    fn validate_rejects_foreign_format() {
        for format in [0, 2] {
            let result = validate_mutated(|h| h.format = format);
            assert!(
                matches!(result, Err(ReleaseLogError::UnsupportedFormat(f)) if f == format),
                "format {format}: {result:?}"
            );
        }
    }

    #[test]
    fn oversized_document_is_rejected_before_parsing() {
        let size = usize::try_from(MAX_HEAD_SIZE).unwrap() + 1;
        // Not JSON at all: the size guard answers before the parser runs.
        let result = Head::from_json(&vec![b' '; size]);
        assert!(matches!(result, Err(ReleaseLogError::TooLarge(n)) if n == size as u64));
    }

    #[test]
    fn document_at_the_size_limit_reaches_the_parser() {
        let size = usize::try_from(MAX_HEAD_SIZE).unwrap();
        let result = Head::from_json(&vec![b' '; size]);
        assert!(matches!(result, Err(ReleaseLogError::Parse(_))));
    }

    #[test]
    fn truncated_json_is_a_parse_error() {
        let json = Head::from_parts(sample(), dummy_signature())
            .to_json()
            .unwrap();
        for len in [0, 1, json.len() / 2, json.len() - 3] {
            let result = Head::from_json(&json.as_bytes()[..len]);
            assert!(
                matches!(result, Err(ReleaseLogError::Parse(_))),
                "len {len}: {result:?}"
            );
        }
    }

    #[test]
    fn non_object_documents_are_parse_errors() {
        for doc in ["[]", "null", "1", "\"head\"", "{}"] {
            let result = Head::from_json(doc.as_bytes());
            assert!(
                matches!(result, Err(ReleaseLogError::Parse(_))),
                "{doc}: {result:?}"
            );
        }
    }

    //
    // Duplicate JSON keys
    //

    /// A raw head document with the given `targets` object body, for inputs
    /// `serde_json::Value` cannot represent (repeated keys).
    fn raw_head(top_extra: &str, row_extra: &str, targets: &str) -> String {
        let signature = serde_json::to_string(&dummy_signature()).unwrap();
        format!(
            r#"{{"format":1,"seq":1,{top_extra}"keys":[],"rows":[{{"name":"fuz",{row_extra}"version":"0.1.0","status":"ok","published_at":"{WHEN}","targets":{{{targets}}}}}],"signature":{signature}}}"#
        )
    }

    fn raw_target(fill: &str, binaries: &str) -> String {
        format!(
            r#""{TARGET}":{{"content_hash":"{}","binaries":{{{binaries}}}}}"#,
            content_hash(fill)
        )
    }

    fn raw_binary(fill: &str) -> String {
        format!(r#""fuz":"{}""#, fill.repeat(64))
    }

    #[test]
    fn raw_head_helper_produces_a_valid_head() {
        // The duplicate-key cases below differ from this document only by the
        // repeated key, so their rejections are about the repetition.
        let doc = raw_head("", "", &raw_target("a", &raw_binary("a")));
        Head::from_json(doc.as_bytes()).unwrap();
    }

    #[test]
    fn duplicate_top_level_field_is_rejected() {
        let doc = raw_head(r#""seq":2,"#, "", &raw_target("a", &raw_binary("a")));
        assert_parse_error(Head::from_json(doc.as_bytes()), "duplicate field `seq`");
    }

    #[test]
    fn duplicate_row_field_is_rejected() {
        let doc = raw_head("", r#""name":"fuzd","#, &raw_target("a", &raw_binary("a")));
        assert_parse_error(Head::from_json(doc.as_bytes()), "duplicate field `name`");
    }

    #[test]
    fn duplicate_target_key_is_rejected() {
        // A last-key-wins parse would silently drop the first entry; a
        // first-key-wins reader of the same file would install against it.
        let targets = format!(
            "{},{}",
            raw_target("b", &raw_binary("b")),
            raw_target("a", &raw_binary("a"))
        );
        let doc = raw_head("", "", &targets);
        assert_parse_error(
            Head::from_json(doc.as_bytes()),
            &format!("duplicate key \"{TARGET}\""),
        );
    }

    #[test]
    fn duplicate_binary_name_is_rejected() {
        let binaries = format!("{},{}", raw_binary("b"), raw_binary("a"));
        let doc = raw_head("", "", &raw_target("a", &binaries));
        assert_parse_error(Head::from_json(doc.as_bytes()), "duplicate key \"fuz\"");
    }

    //
    // seq
    //

    #[test]
    fn seq_must_be_a_json_integer_in_u64_range() {
        for seq in [
            json!(1.0),
            json!(1.5),
            json!(-1),
            json!("1"),
            json!(null),
            json!(true),
        ] {
            let result = parse_mutated(|v| v["seq"] = seq.clone());
            assert!(
                matches!(result, Err(ReleaseLogError::Parse(_))),
                "seq {seq}: {result:?}"
            );
        }
        // One past u64::MAX — serde_json reads it as a float.
        let doc = raw_head("", "", &raw_target("a", &raw_binary("a")))
            .replace("\"seq\":1,", "\"seq\":18446744073709551616,");
        let result = Head::from_json(doc.as_bytes());
        assert!(
            matches!(result, Err(ReleaseLogError::Parse(_))),
            "{result:?}"
        );
    }

    #[test]
    fn seq_out_of_range_is_invalid() {
        for seq in [0, MAX_HEAD_SEQ + 1, u64::MAX] {
            let result = parse_mutated(|v| v["seq"] = json!(seq));
            assert!(
                matches!(
                    result,
                    Err(ReleaseLogError::Invalid(HeadInvalid::SeqOutOfRange(s))) if s == seq
                ),
                "seq {seq}: {result:?}"
            );
        }
        parse_mutated(|v| v["seq"] = json!(1)).unwrap();
        parse_mutated(|v| v["seq"] = json!(MAX_HEAD_SEQ)).unwrap();
    }

    #[test]
    fn largest_seq_survives_canonical_json() {
        let mut head = sample();
        head.seq = MAX_HEAD_SEQ;
        let canonical = fuz_crypto::canonical_json(&head).unwrap();
        assert!(
            canonical.contains("\"seq\":9007199254740991"),
            "{canonical}"
        );
    }

    //
    // Closed sets and digests
    //

    #[test]
    fn status_is_a_closed_lowercase_set() {
        for status in ["Ok", "revokd", "REVOKED", "", "ok "] {
            let result = parse_mutated(|v| v["rows"][0]["status"] = json!(status));
            assert_parse_error(result, "unknown variant");
        }
        parse_mutated(|v| v["rows"][0]["status"] = json!("revoked")).unwrap();
        assert_eq!(serde_json::to_string(&RowStatus::Ok).unwrap(), "\"ok\"");
        assert_eq!(
            serde_json::to_string(&RowStatus::Revoked).unwrap(),
            "\"revoked\""
        );
    }

    /// Digest spellings every digest field refuses, for a digest of `len` hex
    /// characters.
    fn bad_digests(len: usize) -> Vec<String> {
        vec![
            "A".repeat(len),                          // uppercase
            format!("{}F", "a".repeat(len - 1)),      // one uppercase character
            "a".repeat(len - 2),                      // short
            "a".repeat(len + 2),                      // long
            "a".repeat(len - 1),                      // odd length
            format!("{}g", "a".repeat(len - 1)),      // non-hex
            format!("{}\u{e9}", "a".repeat(len - 2)), // non-ASCII, right byte length
            String::new(),
        ]
    }

    #[test]
    fn binary_hash_must_be_full_lowercase_blake3_hex() {
        for digest in bad_digests(64) {
            let result = parse_mutated(|v| target_value(v)["binaries"]["fuz"] = json!(digest));
            assert_parse_error(result, "expected 64 lowercase hex characters");
        }
        // A SHA-512-length digest is not a BLAKE3 digest.
        let result = parse_mutated(|v| target_value(v)["binaries"]["fuz"] = json!("a".repeat(128)));
        assert_parse_error(result, "expected 64 lowercase hex characters");
    }

    #[test]
    fn sha512_must_be_full_lowercase_hex() {
        for digest in bad_digests(128) {
            let result = parse_mutated(|v| target_value(v)["sha512"] = json!(digest));
            assert_parse_error(result, "expected 128 lowercase hex characters");
        }
        let result = parse_mutated(|v| target_value(v)["sha512"] = json!("a".repeat(64)));
        assert_parse_error(result, "expected 128 lowercase hex characters");
    }

    #[test]
    fn sha512_serializes_as_the_sha512sum_spelling() {
        let json = Head::from_parts(sample(), dummy_signature())
            .to_json()
            .unwrap();
        // SHA-512("fuz"), as `sha512sum` prints it.
        let expected = ContentHash::sha512(b"fuz").to_hex();
        assert_eq!(expected.len(), 128);
        assert!(json.contains(&format!("\"sha512\": \"{expected}\"")));
    }

    #[test]
    fn content_hash_must_be_the_manifest_form() {
        for value in [
            "a".repeat(64),                   // no prefix
            format!("v2-{}", "a".repeat(64)), // foreign version
            format!("v1-{}", "A".repeat(64)), // uppercase
            format!("v1-{}", "a".repeat(63)), // short
            format!("v1-{}", "a".repeat(65)), // long
            "v1-abc123".to_string(),
            String::new(),
        ] {
            let result = parse_mutated(|v| target_value(v)["content_hash"] = json!(value));
            assert_invalid_field(result, HeadField::ContentHash);
        }
    }

    #[test]
    fn validate_rejects_a_digest_of_the_wrong_algorithm() {
        // Unreachable from a parsed head; a producer-built one could carry it,
        // and the bare-hex wire form would not say so.
        assert_invalid_field(
            validate_mutated(|h| {
                h.rows[0].targets.get_mut(TARGET).unwrap().sha512 =
                    Some(ContentHash::blake3(b"fuz"));
            }),
            HeadField::Sha512,
        );
        assert_invalid_field(
            validate_mutated(|h| {
                h.rows[0]
                    .targets
                    .get_mut(TARGET)
                    .unwrap()
                    .binaries
                    .insert("fuz".to_string(), ContentHash::sha256(b"fuz"));
            }),
            HeadField::BinaryHash,
        );
    }

    //
    // Strings
    //

    /// Values no name, version, target, or binary name may take.
    const BAD_TOKENS: &[&str] = &[
        "",
        " ",
        "fuz ",
        "fu z",
        "-fuz",
        ".fuz",
        "fuz/d",
        "fuz\\d",
        "fuz\"d",
        "fuz\nd",
        "fuz\0d",
        "caf\u{e9}",
        "\u{442}\u{435}\u{441}\u{442}",
        // `+` is outside the storage-key characters a release is named in.
        "1.0.0+build.5",
        "a+b",
    ];

    #[test]
    fn row_name_must_be_a_token() {
        for value in BAD_TOKENS {
            assert_invalid_field(
                parse_mutated(|v| v["rows"][0]["name"] = json!(value)),
                HeadField::Name,
            );
        }
        for value in ["fuz", "fuzd", "install.sh", "fuz_forge", "a"] {
            parse_mutated(|v| v["rows"][0]["name"] = json!(value)).unwrap();
        }
    }

    #[test]
    fn row_version_must_be_a_token() {
        for value in BAD_TOKENS {
            assert_invalid_field(
                parse_mutated(|v| v["rows"][0]["version"] = json!(value)),
                HeadField::Version,
            );
        }
        for value in ["0.1.0", "1.0.0-rc.1", "1.0.0-rc.1.build_5"] {
            parse_mutated(|v| v["rows"][0]["version"] = json!(value)).unwrap();
        }
    }

    #[test]
    fn target_and_binary_name_must_be_tokens() {
        for value in BAD_TOKENS {
            assert_invalid_field(
                validate_mutated(|h| {
                    let entry = h.rows[0].targets.remove(TARGET).unwrap();
                    h.rows[0].targets.insert((*value).to_string(), entry);
                }),
                HeadField::Target,
            );
            assert_invalid_field(
                validate_mutated(|h| {
                    let entry = h.rows[0].targets.get_mut(TARGET).unwrap();
                    entry.binaries = BTreeMap::from([((*value).to_string(), b3("a"))]);
                }),
                HeadField::BinaryName,
            );
        }
    }

    /// A head carrying `+` in a name, a version, a target, or a binary name
    /// does not parse: a reader refuses the whole head, whichever field holds
    /// it and wherever in the value it sits. The same value without the `+`
    /// reads.
    #[test]
    fn a_head_with_a_plus_in_any_token_field_is_refused_by_a_reader() {
        /// Rename the one key of the object `map` to `key`.
        fn rename_only_key(map: &mut Value, key: &str) {
            let object = map.as_object_mut().unwrap();
            assert_eq!(object.len(), 1);
            let (_, entry) = object.clone().into_iter().next().unwrap();
            object.clear();
            object.insert(key.to_string(), entry);
        }
        type Edit = fn(&mut Value, &str);
        let fields: [(HeadField, Edit); 4] = [
            (HeadField::Name, |v, token| {
                v["rows"][0]["name"] = json!(token);
            }),
            (HeadField::Version, |v, token| {
                v["rows"][0]["version"] = json!(token);
            }),
            (HeadField::Target, |v, token| {
                rename_only_key(&mut v["rows"][0]["targets"], token);
            }),
            (HeadField::BinaryName, |v, token| {
                rename_only_key(target_value(v).get_mut("binaries").unwrap(), token);
            }),
        ];
        for (field, edit) in fields {
            for token in ["1.0.0+build.5", "a+", "a+b", "fuz+"] {
                assert_invalid_field(parse_mutated(|v| edit(v, token)), field);
                let without = token.replace('+', "");
                parse_mutated(|v| edit(v, &without))
                    .unwrap_or_else(|e| panic!("{field} {without:?}: {e}"));
            }
        }
        assert!(!is_release_token("1.0.0+build.5"));
        assert!(is_release_token("1.0.0-build.5"));
    }

    #[test]
    fn overlong_token_is_rejected() {
        parse_mutated(|v| v["rows"][0]["name"] = json!("a".repeat(MAX_RELEASE_TOKEN_LEN))).unwrap();
        assert_invalid_field(
            parse_mutated(|v| v["rows"][0]["name"] = json!("a".repeat(MAX_RELEASE_TOKEN_LEN + 1))),
            HeadField::Name,
        );
    }

    #[test]
    fn timestamps_must_have_the_fixed_utc_shape() {
        for value in [
            "",
            "2025-01-15",
            "2025-01-15T10:30:00",
            "2025-01-15T10:30:00+00:00",
            "2025-01-15T10:30:00.123Z",
            "2025-01-15 10:30:00Z",
            "yesterday",
            "2025-01-15T10:30:\u{e9}Z",
        ] {
            assert_invalid_field(
                parse_mutated(|v| v["rows"][0]["published_at"] = json!(value)),
                HeadField::PublishedAt,
            );
            assert_invalid_field(
                parse_mutated(|v| v["keys"][0]["added_at"] = json!(value)),
                HeadField::KeyAddedAt,
            );
            assert_invalid_field(
                parse_mutated(|v| v["keys"][0]["retired_at"] = json!(value)),
                HeadField::KeyRetiredAt,
            );
        }
        parse_mutated(|v| v["keys"][0]["retired_at"] = json!("2026-02-01T00:00:00Z")).unwrap();
    }

    #[test]
    fn key_record_public_key_must_have_the_ed25519_base64_shape() {
        for value in [
            "",
            "not a key",
            &KEY[..43],                  // unpadded
            &format!("{KEY}="),          // overlong
            &KEY.replace('O', "*"),      // outside the base64 alphabet
            &KEY.replace('O', "\u{e9}"), // non-ASCII
            &KEY.replace('=', "A"),      // no pad
        ] {
            assert_invalid_field(
                parse_mutated(|v| v["keys"][0]["public_key"] = json!(value)),
                HeadField::KeyPublicKey,
            );
        }
    }

    #[test]
    fn non_ascii_strings_never_reach_canonical_json() {
        // Canonical JSON refuses non-ASCII; validation refuses it first, as an
        // error, so signing and verifying never see such a head. Demonstrated
        // for a producer-built head, where no parser stands in front.
        let mut head = sample();
        head.rows[0].name = "caf\u{e9}".to_string();
        assert_invalid_field(head.validate(), HeadField::Name);
        // And were validation skipped, canonical JSON errors — it does not
        // panic.
        assert!(matches!(
            fuz_crypto::canonical_json(&head),
            Err(fuz_crypto::CanonicalError::NonAsciiString(_))
        ));
    }

    //
    // Whole-head structure
    //

    #[test]
    fn duplicate_row_is_invalid() {
        let result = validate_mutated(|h| {
            let mut copy = h.rows[0].clone();
            // Differing content does not make it a different row.
            copy.status = RowStatus::Revoked;
            h.rows.push(copy);
        });
        assert!(matches!(
            result,
            Err(ReleaseLogError::Invalid(HeadInvalid::DuplicateRow { name, version }))
                if name == "fuz" && version == "0.1.0"
        ));
    }

    #[test]
    fn same_name_or_same_version_alone_is_not_a_duplicate() {
        validate_mutated(|h| {
            let mut other_version = h.rows[0].clone();
            other_version.version = "0.2.0".to_string();
            let mut other_name = h.rows[0].clone();
            other_name.name = "fuzd".to_string();
            h.rows.extend([other_version, other_name]);
        })
        .unwrap();
    }

    #[test]
    fn row_identity_is_the_pair_not_its_joined_text() {
        // `("a-b", "c")` and `("a", "b-c")` join to the same text and are still
        // two releases.
        validate_mutated(|h| {
            let mut first = h.rows[0].clone();
            first.name = "a-b".to_string();
            first.version = "c".to_string();
            let mut second = h.rows[0].clone();
            second.name = "a".to_string();
            second.version = "b-c".to_string();
            h.rows.extend([first, second]);
        })
        .unwrap();
    }

    #[test]
    fn duplicate_key_record_is_invalid() {
        let result = validate_mutated(|h| {
            let mut copy = h.keys[0].clone();
            copy.retired_at = Some(WHEN.to_string());
            h.keys.push(copy);
        });
        assert!(matches!(
            result,
            Err(ReleaseLogError::Invalid(HeadInvalid::DuplicateKey(key))) if key == KEY
        ));
    }

    #[test]
    fn row_without_targets_is_invalid() {
        let result = parse_mutated(|v| v["rows"][0]["targets"] = json!({}));
        assert!(matches!(
            result,
            Err(ReleaseLogError::Invalid(HeadInvalid::NoTargets { .. }))
        ));
    }

    #[test]
    fn target_without_binaries_is_invalid() {
        let result = parse_mutated(|v| target_value(v)["binaries"] = json!({}));
        assert!(matches!(
            result,
            Err(ReleaseLogError::Invalid(HeadInvalid::NoBinaries { target, .. }))
                if target == TARGET
        ));
    }

    #[test]
    fn empty_head_is_valid() {
        // The log before its first release: no rows, no key records.
        validate_mutated(|h| {
            h.seq = 1;
            h.keys.clear();
            h.rows.clear();
        })
        .unwrap();
    }

    //
    // The unverified head
    //

    #[test]
    fn verify_signature_validates_a_head_assembled_from_parts() {
        // `from_parts` checks nothing; the structural rules still hold for
        // every `VerifiedHead`, because verification runs them first.
        let mut unsigned = sample();
        unsigned.seq = 0;
        let result = Head::from_parts(unsigned, dummy_signature()).verify_signature();
        assert!(matches!(
            result,
            Err(ReleaseLogError::Invalid(HeadInvalid::SeqOutOfRange(0)))
        ));
    }

    #[test]
    fn verify_signature_rejects_a_head_without_a_real_signature() {
        let result = Head::from_parts(sample(), dummy_signature()).verify_signature();
        assert!(matches!(result, Err(ReleaseLogError::Signature(_))));
    }

    #[test]
    fn unverified_head_debug_prints_no_content() {
        let head = Head::from_parts(sample(), dummy_signature());
        assert_eq!(format!("{head:?}"), "Head { .. }");
        assert_eq!(format!("{head:#?}"), "Head { .. }");
    }

    //
    // Error values are bounded
    //

    #[test]
    fn offending_value_in_an_error_is_bounded() {
        // A megabyte of name is refused with a short error, not a megabyte one.
        let huge = "x ".repeat(400_000);
        let error = validate_mutated(|h| h.rows[0].name.clone_from(&huge)).unwrap_err();
        match &error {
            ReleaseLogError::Invalid(HeadInvalid::Field { field, value }) => {
                assert_eq!(*field, HeadField::Name);
                assert_eq!(value.len(), MAX_ERROR_VALUE_LEN + 3);
                assert!(value.ends_with("..."));
                assert!(huge.starts_with(value.trim_end_matches('.')));
            }
            other => panic!("unexpected error: {other:?}"),
        }
        assert!(error.to_string().len() < 2 * MAX_ERROR_VALUE_LEN + 100);
    }

    #[test]
    fn an_invalid_field_shows_its_value_quoted_and_escaped() {
        let error =
            validate_mutated(|h| h.rows[0].name = "fuz\u{3164}\u{2800}x".to_string()).unwrap_err();
        assert_eq!(
            error.to_string(),
            "invalid release log head: invalid row name: \"fuz\\u{3164}\\u{2800}x\""
        );
    }

    #[test]
    fn value_at_the_bound_is_reported_whole() {
        let value = " ".repeat(MAX_ERROR_VALUE_LEN);
        assert_eq!(excerpt(&value), value);
        assert_eq!(excerpt(""), "");
    }

    #[test]
    fn excerpt_cuts_on_a_character_boundary() {
        // A two-byte character straddles the bound; the cut backs up before it.
        let value = format!(
            "{}\u{e9}{}",
            "a".repeat(MAX_ERROR_VALUE_LEN - 1),
            "b".repeat(50)
        );
        assert_eq!(
            excerpt(&value),
            format!("{}...", "a".repeat(MAX_ERROR_VALUE_LEN - 1))
        );
    }

    #[test]
    fn parse_errors_carry_bounded_values() {
        let huge = "Z".repeat(200_000);
        for result in [
            parse_mutated(|v| target_value(v)["sha512"] = json!(huge)),
            parse_mutated(|v| target_value(v)["binaries"]["fuz"] = json!(huge)),
        ] {
            match result {
                Err(ReleaseLogError::Parse(e)) => {
                    assert!(e.len() < 400, "{} bytes", e.len());
                }
                other => panic!("unexpected: {other:?}"),
            }
        }
        // A repeated key of any length is named by its excerpt.
        let key = "k".repeat(100_000);
        let binaries = format!(r#""{key}":"{0}","{key}":"{0}""#, "a".repeat(64));
        let doc = raw_head("", "", &raw_target("a", &binaries));
        match Head::from_json(doc.as_bytes()) {
            Err(ReleaseLogError::Parse(message)) => {
                assert!(
                    message.contains("duplicate key \"kkk"),
                    "{}",
                    &message[..80]
                );
                assert!(message.len() < 400, "{} bytes", message.len());
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn duplicate_detection_reports_the_first_repeat() {
        // Rows repeat earlier ones; the one named is the first whose identity
        // was already seen, in row order.
        let result = validate_mutated(|h| {
            let mut second = h.rows[0].clone();
            second.version = "0.2.0".to_string();
            let repeat_second = second.clone();
            let repeat_first = h.rows[0].clone();
            h.rows.extend([second, repeat_second, repeat_first]);
        });
        assert!(matches!(
            result,
            Err(ReleaseLogError::Invalid(HeadInvalid::DuplicateRow { name, version }))
                if name == "fuz" && version == "0.2.0"
        ));
    }

    #[test]
    fn parse_error_is_bounded_and_escaped_however_long_the_token() {
        // A megabyte-scale unknown field name carrying an ESC and a newline.
        let name = format!("\u{1b}[31m\n{}", "n".repeat(1_000_000));
        let error = parse_mutated(|v| v[name.as_str()] = json!(1)).unwrap_err();
        assert!(matches!(error, ReleaseLogError::Parse(_)));
        for rendered in [error.to_string(), format!("{error:?}")] {
            assert!(rendered.len() < 1024, "{} bytes", rendered.len());
            assert!(
                !rendered.chars().any(char::is_control),
                "raw control character in: {rendered}"
            );
        }
        let display = error.to_string();
        assert!(
            display.contains("unknown field `\\u{1b}[31m\\nnnn"),
            "{display}"
        );
        // The position survives the truncation.
        assert!(display.contains("... at line 1 column "), "{display}");
    }

    #[test]
    fn parse_error_escapes_non_ascii_controls_and_invisible_characters() {
        // A C1 control (U+009B is a one-character CSI), the bidi override, a
        // zero-width space, and the line separator. None is an ASCII control,
        // and only the first is a control character at all.
        let name = "\u{9b}31m\u{202e}\u{200b}\u{2028}";
        let display = parse_mutated(|v| v[name] = json!(1))
            .unwrap_err()
            .to_string();
        assert!(
            display.contains("unknown field `\\u{9b}31m\\u{202e}\\u{200b}\\u{2028}`"),
            "{display}"
        );
    }

    /// The blank fillers and NUL: characters the standard library's own
    /// escaping leaves alone on one toolchain or spells another way.
    #[test]
    fn parse_error_escapes_the_blank_fillers_and_nul() {
        let name = "a\u{115f}\u{1160}\u{3164}\u{ffa0}\u{2800}\0b";
        let display = parse_mutated(|v| v[name] = json!(1))
            .unwrap_err()
            .to_string();
        assert!(
            display
                .contains("unknown field `a\\u{115f}\\u{1160}\\u{3164}\\u{ffa0}\\u{2800}\\u{0}b`"),
            "{display}"
        );
    }

    /// A key or a digest this module's own parse messages repeat is escaped
    /// once, with the rest of the message: an ESC is spelled out, a backslash
    /// doubled, and neither a second time.
    #[test]
    fn a_parse_message_of_this_module_escapes_its_excerpt_once() {
        // The key is `f`, ESC, a backslash, and a braille blank, twice.
        let binaries = format!(
            r#""f\u001b\\\u2800":"{0}","f\u001b\\\u2800":"{0}""#,
            "a".repeat(64)
        );
        let doc = raw_head("", "", &raw_target("a", &binaries));
        let error = Head::from_json(doc.as_bytes()).unwrap_err().to_string();
        assert!(
            error.starts_with(
                "failed to parse release log head: duplicate key \"f\\u{1b}\\\\\\u{2800}\" at line 1 "
            ),
            "{error}"
        );

        let digest = "g\u{1b}\\\u{2800}";
        let error = parse_mutated(|v| target_value(v)["sha512"] = json!(digest))
            .unwrap_err()
            .to_string();
        assert!(
            error.starts_with(
                "failed to parse release log head: expected 128 lowercase hex characters for \
                 sha512, got \"g\\u{1b}\\\\\\u{2800}\" at line 1 "
            ),
            "{error}"
        );
    }

    #[test]
    fn parse_error_keeps_a_short_message_whole() {
        let error = Head::from_json(b"{").unwrap_err();
        assert_eq!(
            error.to_string(),
            "failed to parse release log head: EOF while parsing an object at line 1 column 1"
        );
    }

    #[test]
    fn wrong_typed_string_in_a_parse_error_is_bounded_and_escaped() {
        let value = format!("\u{7}\r{}", "s".repeat(500_000));
        let error = parse_mutated(|v| v["seq"] = json!(value)).unwrap_err();
        let display = error.to_string();
        assert!(display.len() < 1024, "{} bytes", display.len());
        assert!(!display.chars().any(char::is_control), "{display}");
    }

    //
    // The signature's unsigned `signed_at`
    //

    #[test]
    fn signed_at_must_have_the_timestamp_shape() {
        for value in ["x", "", "2025-01-15", "2025-01-15T10:30:00+00:00"] {
            assert_invalid_field(
                parse_mutated(|v| v["signature"]["signed_at"] = json!(value)),
                HeadField::SignedAt,
            );
        }
    }

    #[test]
    fn oversized_signed_at_is_refused_with_a_bounded_error() {
        let huge = "9".repeat(900_000);
        let error = parse_mutated(|v| v["signature"]["signed_at"] = json!(huge)).unwrap_err();
        assert!(matches!(
            &error,
            ReleaseLogError::Invalid(HeadInvalid::Field {
                field: HeadField::SignedAt,
                ..
            })
        ));
        assert!(error.to_string().len() < 400);
        assert!(format!("{error:?}").len() < 400);
    }

    #[test]
    fn verify_signature_checks_signed_at_of_a_head_assembled_from_parts() {
        let mut signature = dummy_signature();
        signature.signed_at = "nope".to_string();
        assert_invalid_field(
            Head::from_parts(sample(), signature).verify_signature(),
            HeadField::SignedAt,
        );
    }

    //
    // Error classification
    //

    fn row_id() -> (String, String) {
        ("fuz".to_string(), "0.1.0".to_string())
    }

    /// One of every [`HeadViolation`].
    fn every_violation() -> Vec<HeadViolation> {
        let (name, version) = row_id();
        let target = TARGET.to_string();
        let public_key = KEY.to_string();
        let all = vec![
            HeadViolation::SeqRegressed {
                cached: 2,
                fresh: 1,
            },
            HeadViolation::SeqReused { seq: 2 },
            HeadViolation::RowRemoved {
                name: name.clone(),
                version: version.clone(),
            },
            HeadViolation::RowMoved {
                name: name.clone(),
                version: version.clone(),
            },
            HeadViolation::PublishedAtChanged {
                name: name.clone(),
                version: version.clone(),
            },
            HeadViolation::RevocationUndone {
                name: name.clone(),
                version: version.clone(),
            },
            HeadViolation::TargetRemoved {
                name: name.clone(),
                version: version.clone(),
                target: target.clone(),
            },
            HeadViolation::TargetChanged {
                name,
                version,
                target,
                field: TargetField::Sha512,
            },
            HeadViolation::KeyRemoved {
                public_key: public_key.clone(),
            },
            HeadViolation::KeyMoved {
                public_key: public_key.clone(),
            },
            HeadViolation::KeyAddedAtChanged {
                public_key: public_key.clone(),
            },
            HeadViolation::KeyRetiredAtChanged { public_key },
        ];
        // Compile-time tripwire: a new variant fails this match until it is
        // added to the list above.
        for violation in &all {
            match violation {
                HeadViolation::SeqRegressed { .. }
                | HeadViolation::SeqReused { .. }
                | HeadViolation::RowRemoved { .. }
                | HeadViolation::RowMoved { .. }
                | HeadViolation::PublishedAtChanged { .. }
                | HeadViolation::RevocationUndone { .. }
                | HeadViolation::TargetRemoved { .. }
                | HeadViolation::TargetChanged { .. }
                | HeadViolation::KeyRemoved { .. }
                | HeadViolation::KeyMoved { .. }
                | HeadViolation::KeyAddedAtChanged { .. }
                | HeadViolation::KeyRetiredAtChanged { .. } => {}
            }
        }
        all
    }

    /// One of every [`ReleaseLogError`] shape, with whether it is a security
    /// violation.
    fn classification_table() -> Vec<(ReleaseLogError, bool)> {
        let (name, version) = row_id();
        let parse_error = serde_json::from_str::<Value>("{").unwrap_err();
        let mut table = vec![
            (ReleaseLogError::TooLarge(MAX_HEAD_SIZE + 1), false),
            (parse_error.into(), false),
            (ReleaseLogError::UnsupportedFormat(2), false),
            (HeadInvalid::SeqOutOfRange(0).into(), false),
            (HeadInvalid::DuplicateRow { name, version }.into(), false),
            (
                fuz_crypto::CanonicalError::NonAsciiString("caf\u{e9}".to_string()).into(),
                false,
            ),
            (fuz_crypto::VerifyError::InvalidSignature.into(), true),
            (
                fuz_crypto::VerifyError::UntrustedKey(KEY.to_string()).into(),
                true,
            ),
            (fuz_crypto::VerifyError::UnsupportedFormat(1).into(), true),
            (fuz_crypto::VerifyError::InvalidPublicKey.into(), true),
        ];
        table.extend(every_violation().into_iter().map(|v| (v.into(), true)));
        table.extend(check_errors());
        // Compile-time tripwire, as above.
        for (error, _) in &table {
            match error {
                ReleaseLogError::TooLarge(_)
                | ReleaseLogError::Parse(_)
                | ReleaseLogError::UnsupportedFormat(_)
                | ReleaseLogError::Invalid(_)
                | ReleaseLogError::Canonical(_)
                | ReleaseLogError::Signature(_)
                | ReleaseLogError::Violation(_)
                | ReleaseLogError::WitnessHead { .. }
                | ReleaseLogError::WitnessCoSign { .. }
                | ReleaseLogError::Revoked { .. }
                | ReleaseLogError::RowMissing { .. }
                | ReleaseLogError::Unconfirmed { .. }
                | ReleaseLogError::Contradiction(_)
                | ReleaseLogError::CacheUnusable { .. }
                | ReleaseLogError::Config(_) => {}
            }
        }
        table
    }

    const ORIGIN: &str = "https://log.example.com";

    fn unsigned() -> ReleaseLogError {
        fuz_crypto::VerifyError::InvalidSignature.into()
    }

    /// One of every shape the install-time check adds, with whether it is a
    /// security violation. The variants that wrap another error appear once
    /// with a source that is a violation and once with one that is not.
    fn check_errors() -> Vec<(ReleaseLogError, bool)> {
        use fuz_sys::secure_file::SecureFileError;
        use std::path::PathBuf;

        let (name, version) = row_id();
        let target = || TARGET.to_string();
        let violation = || Box::new(HeadViolation::SeqReused { seq: 3 });
        let witness_head = |source| ReleaseLogError::WitnessHead {
            origin: ORIGIN.to_string(),
            source: Box::new(source),
        };
        let path = || PathBuf::from("/home/u/.fuz/state/release_log/head.json");
        let cache = |problem| ReleaseLogError::CacheUnusable {
            path: path(),
            problem,
        };
        let storage_error = || fuz_storage::StorageError::InvalidConfig {
            message: "bad".to_string(),
        };

        let co_sign = |source| ReleaseLogError::WitnessCoSign {
            origin: ORIGIN.to_string(),
            source,
        };
        let sshsig = |e: fuz_crypto::SshsigError| co_sign(CoSignProblem::Signature(e));

        let table = vec![
            (co_sign(CoSignProblem::TooLarge { size: 9000 }), false),
            (co_sign(CoSignProblem::Line("no final newline")), false),
            (sshsig(fuz_crypto::SshsigError::Armor("x")), false),
            (sshsig(fuz_crypto::SshsigError::InvalidKey), false),
            (sshsig(fuz_crypto::SshsigError::WrongKey), true),
            (sshsig(fuz_crypto::SshsigError::WrongNamespace), true),
            (sshsig(fuz_crypto::SshsigError::InvalidSignature), true),
            (
                LogContradiction::CoSignMismatch {
                    origin: ORIGIN.to_string(),
                    seq: 7,
                }
                .into(),
                true,
            ),
            (
                witness_head(ReleaseLogError::TooLarge(MAX_HEAD_SIZE + 1)),
                false,
            ),
            (witness_head(ReleaseLogError::UnsupportedFormat(2)), false),
            (witness_head(unsigned()), true),
            (
                ReleaseLogError::Revoked {
                    name: name.clone(),
                    version: version.clone(),
                },
                true,
            ),
            (
                ReleaseLogError::RowMissing {
                    name: name.clone(),
                    version: version.clone(),
                    target: target(),
                    pinned_by: PinnedBy::SignedManifest,
                },
                true,
            ),
            (
                ReleaseLogError::RowMissing {
                    name: name.clone(),
                    version: version.clone(),
                    target: target(),
                    pinned_by: PinnedBy::LocalBinary,
                },
                true,
            ),
            (
                ReleaseLogError::Unconfirmed {
                    name: name.clone(),
                    version: version.clone(),
                    target: target(),
                    witnesses: vec![UnreachableOrigin {
                        origin: ORIGIN.to_string(),
                        reason: "HTTPS: path not found: head.json".to_string(),
                    }],
                },
                false,
            ),
            (
                LogContradiction::HeadsDiverge {
                    first: ORIGIN.to_string(),
                    second: "https://mirror.example.com".to_string(),
                    violation: violation(),
                }
                .into(),
                true,
            ),
            (
                LogContradiction::SupersetViolated {
                    origin: ORIGIN.to_string(),
                    violation: violation(),
                }
                .into(),
                true,
            ),
            (
                LogContradiction::HashMismatch {
                    name: name.clone(),
                    version: version.clone(),
                    target: target(),
                    field: TargetField::Binaries,
                    pinned_by: PinnedBy::SignedManifest,
                }
                .into(),
                true,
            ),
            (
                LogContradiction::HashMismatch {
                    name,
                    version,
                    target: target(),
                    field: TargetField::ContentHash,
                    pinned_by: PinnedBy::LocalBinary,
                }
                .into(),
                true,
            ),
            (
                cache(CacheProblem::File(SecureFileError::Symlink(path()))),
                true,
            ),
            (
                cache(CacheProblem::File(SecureFileError::NotRegularFile(path()))),
                true,
            ),
            (
                cache(CacheProblem::File(SecureFileError::FileTooLarge(
                    path(),
                    MAX_HEAD_SIZE + 1,
                    MAX_HEAD_SIZE,
                ))),
                false,
            ),
            (
                cache(CacheProblem::File(SecureFileError::Io(
                    path(),
                    std::io::Error::other("denied"),
                ))),
                false,
            ),
            (cache(CacheProblem::Head(Box::new(unsigned()))), true),
            (
                cache(CacheProblem::Head(Box::new(
                    ReleaseLogError::UnsupportedFormat(2),
                ))),
                false,
            ),
            (
                cache(CacheProblem::Write(std::io::Error::other("disk full"))),
                false,
            ),
            (
                LogConfigError::InvalidSwitch {
                    value: "OFF".to_string(),
                }
                .into(),
                false,
            ),
            (
                LogConfigError::InvalidOrigin {
                    position: 1,
                    refusal: storage_error(),
                }
                .into(),
                false,
            ),
            (
                LogConfigError::OriginUnusable {
                    origin: ORIGIN.to_string(),
                    source: storage_error(),
                }
                .into(),
                false,
            ),
        ];
        // Compile-time tripwires for the enums these variants carry: a new
        // variant fails to build here until it is added to the table above.
        for (error, _) in &table {
            match error {
                ReleaseLogError::Contradiction(contradiction) => match contradiction {
                    LogContradiction::HeadsDiverge { .. }
                    | LogContradiction::SupersetViolated { .. }
                    | LogContradiction::HashMismatch { .. }
                    | LogContradiction::CoSignMismatch { .. } => {}
                },
                ReleaseLogError::WitnessCoSign { source, .. } => match source {
                    CoSignProblem::TooLarge { .. }
                    | CoSignProblem::Signature(_)
                    | CoSignProblem::Line(_) => {}
                },
                ReleaseLogError::CacheUnusable { problem, .. } => match problem {
                    CacheProblem::File(_) | CacheProblem::Head(_) | CacheProblem::Write(_) => {}
                },
                ReleaseLogError::Config(config) => match config {
                    LogConfigError::InvalidSwitch { .. }
                    | LogConfigError::InvalidOrigin { .. }
                    | LogConfigError::OriginUnusable { .. } => {}
                },
                _ => {}
            }
        }
        table
    }

    #[test]
    fn only_unconfirmed_is_the_soft_failure_at_every_wrapper_level() {
        let mut seen = 0;
        for (error, security) in classification_table() {
            let description = error.to_string();
            let expected = matches!(error, ReleaseLogError::Unconfirmed { .. });
            assert_eq!(error.is_unconfirmed(), expected, "{description}");
            // Soft and a violation are never the same error.
            assert!(!(expected && security), "{description}");
            let wrapped = crate::ReleaseError::from(error);
            assert_eq!(wrapped.is_unconfirmed(), expected, "{description}");
            seen += usize::from(expected);
        }
        assert_eq!(seen, 1, "the table holds the one soft failure");
        // No other `ReleaseError` is the soft failure.
        assert!(!crate::ReleaseError::ToolNotInstalled("fuzd".to_string()).is_unconfirmed());
        assert!(
            !crate::ReleaseError::Storage(fuz_storage::StorageError::NotFound {
                backend: fuz_storage::StorageBackendKind::Https,
                path: "head.json".to_string(),
            })
            .is_unconfirmed()
        );
    }

    #[test]
    fn check_messages_name_the_release_and_the_witness() {
        let rendered: Vec<String> = check_errors()
            .into_iter()
            .map(|(error, _)| error.to_string())
            .collect();
        let has = |needle: &str| rendered.iter().any(|message| message == needle);
        assert!(
            has("fuz 0.1.0 is revoked in the release log"),
            "{rendered:#?}"
        );
        assert!(has(&format!(
            "the release log does not record fuz 0.1.0 for {TARGET}"
        )));
        assert!(has(&format!(
            "cannot confirm fuz 0.1.0 ({TARGET}) in the release log yet: no witness reachable \
             (tried {ORIGIN} (HTTPS: path not found: head.json))"
        )));
        assert!(has(&format!(
            "release log contradiction: the release log records other binaries for \
             fuz 0.1.0 {TARGET} than its signed manifest"
        )));
        assert!(has(&format!(
            "release log witness {ORIGIN} served an unusable head: release log head signature \
             verification failed: {}",
            fuz_crypto::VerifyError::InvalidSignature
        )));
    }

    #[test]
    fn co_sign_messages_name_the_witness_and_the_seq() {
        let rendered: Vec<String> = check_errors()
            .into_iter()
            .map(|(error, _)| error.to_string())
            .collect();
        let has = |needle: &str| rendered.iter().any(|message| message == needle);
        assert!(
            has(&format!(
                "release log contradiction: witness {ORIGIN} serves a head.json at seq 7 that \
                 its own co-signature does not cover"
            )),
            "{rendered:#?}"
        );
        assert!(has(&format!(
            "release log witness {ORIGIN} served an unusable co-signature: the witness file's \
             first line is not followed by a usable SSH signature of it: SSH signature was \
             made by a different key than the expected one"
        )));
        assert!(has(&format!(
            "release log witness {ORIGIN} served an unusable co-signature: the witness file \
             is too large: 9000 bytes (max {})",
            crate::co_sign::MAX_WITNESS_SIZE
        )));
    }

    /// An unusable co-signature has one remedy whatever its cause: drop that
    /// origin and keep the check. It never points at the opt-out.
    #[test]
    fn an_unusable_co_sign_hint_keeps_the_rest_of_the_check() {
        let mut seen = 0;
        for (error, _) in check_errors() {
            if !matches!(error, ReleaseLogError::WitnessCoSign { .. }) {
                continue;
            }
            let hint = error.hint().unwrap_or_default();
            assert!(hint.contains("FUZ_RELEASE_LOG_URL"), "{error}: {hint}");
            assert!(hint.contains("keeps the rest"), "{hint}");
            assert!(!hint.contains("FUZ_RELEASE_LOG=off"), "{hint}");
            assert!(!hint.contains("=off"), "{hint}");
            seen += 1;
        }
        assert!(seen > 1, "both classes of cause are in the table");
    }

    #[test]
    fn unusable_cache_names_the_file_and_what_removing_it_costs() {
        let error = ReleaseLogError::CacheUnusable {
            path: std::path::PathBuf::from("/home/u/.fuz/state/release_log/head.json"),
            problem: CacheProblem::Head(Box::new(unsigned())),
        };
        assert!(
            error.to_string().starts_with(
                "cached release log head /home/u/.fuz/state/release_log/head.json is unusable: "
            ),
            "{error}"
        );
        let hint = error.hint().unwrap_or_default();
        assert!(hint.contains("state/release_log/head.json"), "{hint}");
        assert!(hint.contains("continuity record"), "{hint}");
    }

    #[test]
    fn a_cache_write_failure_points_at_the_directory_not_at_removing_the_file() {
        let error = ReleaseLogError::CacheUnusable {
            path: std::path::PathBuf::from("/home/u/.fuz/state/release_log/head.json"),
            problem: CacheProblem::Write(std::io::Error::other("read-only file system")),
        };
        let hint = error.hint().unwrap_or_default();
        assert!(hint.contains("not writable"), "{hint}");
        assert!(!hint.contains("continuity"), "{hint}");
        assert!(!hint.contains("Removing"), "{hint}");
    }

    #[test]
    fn a_hash_mismatch_hint_blames_the_served_bytes_not_another_head() {
        for (error, _) in check_errors() {
            let ReleaseLogError::Contradiction(contradiction) = &error else {
                continue;
            };
            let hint = error.hint().unwrap_or_default();
            let about_bytes = hint.contains("serves bytes other than");
            let about_heads = hint.contains("seen earlier or elsewhere");
            match contradiction {
                LogContradiction::HashMismatch {
                    pinned_by: PinnedBy::SignedManifest,
                    ..
                } => {
                    assert!(about_bytes && !about_heads, "{hint}");
                }
                // No storage host is involved: the binary is on this machine.
                LogContradiction::HashMismatch {
                    pinned_by: PinnedBy::LocalBinary,
                    ..
                } => {
                    assert!(!about_bytes && !about_heads, "{hint}");
                    assert!(hint.contains("This binary is not the one"), "{hint}");
                    assert!(hint.contains("FUZ_RELEASE_LOG=off"), "{hint}");
                }
                LogContradiction::HeadsDiverge { .. }
                | LogContradiction::SupersetViolated { .. } => {
                    assert!(about_heads && !about_bytes, "{hint}");
                }
                // An origin's served bytes against its own co-signature: not
                // a claim about the release key or about another head.
                LogContradiction::CoSignMismatch { .. } => {
                    assert!(!about_bytes && !about_heads, "{hint}");
                    assert!(hint.contains("co-signer at this origin"), "{hint}");
                    assert!(hint.ends_with("do not install"), "{hint}");
                    assert!(!hint.contains("release key"), "{hint}");
                }
            }
        }
    }

    #[test]
    fn an_invalid_origin_message_carries_the_position_and_nothing_from_the_entry() {
        let error: ReleaseLogError = LogConfigError::InvalidOrigin {
            position: 2,
            refusal: fuz_storage::StorageError::InvalidConfig {
                message: "unknown storage scheme: HTTPS://user:hunter2@example.com".to_string(),
            },
        }
        .into();
        assert_eq!(
            error.to_string(),
            "release log configuration error: invalid FUZ_RELEASE_LOG_URL entry 2, counting \
             non-empty entries (not a usable storage location)"
        );
        let wrapped = crate::ReleaseError::from(error);
        assert!(!wrapped.to_string().contains("hunter2"));
        // the refusal is not a source either, so the `error:` line a CLI
        // prints from the whole chain shows the message alone
        assert!(std::error::Error::source(&wrapped).is_some());
        assert_eq!(
            fuz_sys::cli::format_error_chain(&wrapped),
            wrapped.to_string()
        );
        let hint = wrapped.hint().map(|h| h.to_string()).unwrap_or_default();
        assert!(hint.contains("https://"), "{hint}");
        assert!(
            hint.ends_with("or an existing local directory (a path or file:// URI)"),
            "{hint}"
        );
        assert!(!hint.contains("forge") && !hint.contains("ssh"), "{hint}");
    }

    /// A binary held to the log by its own bytes has no storage host and no
    /// manifest: its refusals say what a locally built binary needs to hear.
    #[test]
    fn a_local_binary_refusal_names_the_binary_and_the_opt_out() {
        let missing = |pinned_by| ReleaseLogError::RowMissing {
            name: "fuz".to_string(),
            version: "0.3.0".to_string(),
            target: "x86_64-unknown-linux-gnu".to_string(),
            pinned_by,
        };
        let served = missing(PinnedBy::SignedManifest);
        let local = missing(PinnedBy::LocalBinary);
        // One message; the hint is what differs.
        assert_eq!(served.to_string(), local.to_string());
        assert!(served.hint().unwrap().contains("storage host"));
        let hint = local.hint().unwrap();
        assert!(!hint.contains("storage host"), "{hint}");
        assert!(hint.contains("locally built"), "{hint}");
        assert!(hint.contains("FUZ_RELEASE_LOG=off"), "{hint}");

        let mismatch = |pinned_by| {
            ReleaseLogError::from(LogContradiction::HashMismatch {
                name: "fuz".to_string(),
                version: "0.3.0".to_string(),
                target: "x86_64-unknown-linux-gnu".to_string(),
                field: TargetField::Binaries,
                pinned_by,
            })
            .to_string()
        };
        assert!(mismatch(PinnedBy::SignedManifest).ends_with("than its signed manifest"));
        assert!(mismatch(PinnedBy::LocalBinary).ends_with("than this binary"));
    }

    #[test]
    fn unconfirmed_hint_says_it_is_not_a_refusal() {
        let hint = check_errors()
            .into_iter()
            .find(|(error, _)| error.is_unconfirmed())
            .and_then(|(error, _)| error.hint())
            .unwrap_or_default();
        assert!(hint.starts_with("This is not a refusal"), "{hint}");
        assert!(hint.contains("Retry"), "{hint}");
    }

    #[test]
    fn security_classification_holds_at_every_wrapper_level() {
        for (error, expected) in classification_table() {
            let description = error.to_string();
            assert_eq!(
                error.is_security_violation(),
                expected,
                "ReleaseLogError: {description}"
            );
            // The wrapper forwards; it never re-decides.
            let wrapped = crate::ReleaseError::from(error);
            assert_eq!(
                wrapped.is_security_violation(),
                expected,
                "ReleaseError: {description}"
            );
        }
    }

    #[test]
    fn hints_are_given_and_forwarded_unchanged() {
        for (error, _) in classification_table() {
            let description = error.to_string();
            let hint = error.hint();
            assert!(
                hint.is_some_and(|h| !h.is_empty()),
                "no hint for: {description}"
            );
            let wrapped = crate::ReleaseError::from(error);
            assert_eq!(
                wrapped.hint().map(|h| h.to_string()),
                hint.map(str::to_string),
                "wrapper hint differs for: {description}"
            );
        }
    }

    #[test]
    fn signature_hint_comes_from_its_source() {
        let verify = fuz_crypto::VerifyError::UntrustedKey(KEY.to_string());
        let expected = verify.hint();
        assert_eq!(ReleaseLogError::from(verify).hint(), expected);
    }

    #[test]
    fn canonical_hint_names_the_head_not_the_manifest() {
        let canonical = fuz_crypto::CanonicalError::NonAsciiString("x".to_string());
        assert_eq!(
            ReleaseLogError::from(canonical).hint(),
            Some("Release log head fields must be ASCII strings and integers")
        );
    }

    #[test]
    fn violation_messages_name_the_row_and_field() {
        let (name, version) = row_id();
        let violation = HeadViolation::TargetChanged {
            name,
            version,
            target: TARGET.to_string(),
            field: TargetField::Sha512,
        };
        assert_eq!(
            ReleaseLogError::from(violation).to_string(),
            format!("release log violation: sha512 changed for fuz 0.1.0 {TARGET}")
        );
    }
}
