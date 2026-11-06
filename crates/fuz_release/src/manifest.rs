//! Release manifest types and validation
//!
//! Manifest format for signed releases. Includes parsing, validation,
//! signature verification, and target platform checking.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use fuz_artifact::platform::ReleaseTarget;
use fuz_artifact::tools::is_first_party_tool;
use fuz_crypto::ContentHash;

use crate::error::{ManifestError, below_minimum_recovery};
use crate::layout::ReleaseLayout;
use crate::{MANIFEST_FORMAT_VERSION, MAX_TOTAL_SIZE, SELF_BINARIES};

/// Binary name -> blake3 hash mapping.
///
/// Validated on parse: a self manifest must carry exactly `SELF_BINARIES`; a
/// tool manifest must declare a non-empty set (the signed bill of materials).
/// Wire shape is bare-hex values via [`fuz_crypto::blake3_hex_map`] (the field
/// attribute on each carrier), so the signed canonical JSON is unchanged.
pub type BinaryHashes = HashMap<String, ContentHash>;

/// Tarball metadata within a manifest
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TarballInfo {
    /// Filename (simple name, no path components)
    pub path: String,
    /// Blake3 hash of the tarball file. Bare-hex on the wire (unchanged signed
    /// shape) via the [`fuz_crypto::blake3_hex`] serde adapter.
    #[serde(with = "fuz_crypto::blake3_hex")]
    pub blake3: ContentHash,
    /// Size in bytes
    pub size: u64,
}

/// Unsigned manifest data (for signing/verification).
/// Mirrors `Manifest` but without the `signature` field.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestUnsigned {
    /// Format version (currently 1)
    pub format: u32,
    /// Release version (semver)
    pub version: String,
    /// Content hash of the artifact (`v1-<hash>`)
    pub content_hash: String,
    /// Target platform triple (e.g., x86_64-unknown-linux-gnu)
    pub target: String,
    /// Minimum client version required to install this release
    pub minimum_version: Option<String>,
    /// Tarball metadata
    pub tarball: TarballInfo,
    /// Binary hashes (name -> blake3)
    #[serde(with = "fuz_crypto::blake3_hex_map")]
    pub binaries: BinaryHashes,
    /// Tool name when this is a per-tool artifact; `None` for the fuz self
    /// artifact. Omitted from the wire (and thus the signed canonical JSON)
    /// when `None`, so a self manifest's signed bytes carry no `tool` key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
}

/// Signed as [`SignedPayloadKind::Manifest`](fuz_crypto::SignedPayloadKind::Manifest)
/// — self and per-tool manifests alike, one document type.
impl fuz_crypto::SignedPayload for ManifestUnsigned {
    const KIND: fuz_crypto::SignedPayloadKind = fuz_crypto::SignedPayloadKind::Manifest;
}

impl From<&Manifest> for ManifestUnsigned {
    fn from(m: &Manifest) -> Self {
        Self {
            format: m.format,
            version: m.version.clone(),
            content_hash: m.content_hash.clone(),
            target: m.target.clone(),
            minimum_version: m.minimum_version.clone(),
            tarball: m.tarball.clone(),
            binaries: m.binaries.clone(),
            tool: m.tool.clone(),
        }
    }
}

/// Release manifest with embedded signature
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)] // Reject extra fields to prevent injection attacks
pub struct Manifest {
    /// Format version (currently 1)
    pub format: u32,
    /// Release version (semver)
    pub version: String,
    /// Content hash of the artifact (`v1-<hash>`)
    pub content_hash: String,
    /// Target platform triple (e.g., x86_64-unknown-linux-gnu)
    pub target: String,
    /// Minimum client version required to install this release
    pub minimum_version: Option<String>,
    /// Tarball metadata
    pub tarball: TarballInfo,
    /// Binary hashes (name -> blake3)
    #[serde(with = "fuz_crypto::blake3_hex_map")]
    pub binaries: BinaryHashes,
    /// Tool name when this is a per-tool artifact; `None` for the fuz self
    /// artifact. See [`ManifestUnsigned::tool`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    /// Ed25519 signature of the unsigned manifest's
    /// [`SignedMessage`](fuz_crypto::SignedMessage) — the manifest tag, then
    /// its canonical JSON
    pub signature: fuz_crypto::Signature,
}

impl Manifest {
    /// Assemble a signed `Manifest` from unsigned data plus a computed
    /// `fuz_crypto::Signature`.
    ///
    /// The inverse of `ManifestUnsigned::from(&Manifest)`. Signing lives in
    /// `fuz_sign` (`sign_manifest` computes the signature, then calls this);
    /// `fuz_release`'s own tests pass a placeholder signature. Keeping the
    /// field-copy here means adding a `Manifest` field doesn't ripple out to
    /// the signer or the test helpers.
    #[must_use]
    pub fn from_parts(unsigned: ManifestUnsigned, signature: fuz_crypto::Signature) -> Self {
        Self {
            format: unsigned.format,
            version: unsigned.version,
            content_hash: unsigned.content_hash,
            target: unsigned.target,
            minimum_version: unsigned.minimum_version,
            tarball: unsigned.tarball,
            binaries: unsigned.binaries,
            tool: unsigned.tool,
            signature,
        }
    }

    /// Parse and validate manifest from JSON bytes.
    ///
    /// Validates:
    /// - Format version is supported (≤ `MANIFEST_FORMAT_VERSION`)
    /// - Tarball path is a simple filename (no `/`, `\`, `..`, leading `.`)
    /// - Content hash is `v1-` + 64 lowercase hex; binary names are release
    ///   tokens (`fuz_artifact::is_release_token`)
    /// - Tarball size is within limits
    /// - All required binaries are present
    ///
    /// Does NOT verify signature (call `verify_signature()` separately).
    ///
    /// # Errors
    ///
    /// Returns [`ManifestError`] if JSON parsing fails or validation fails.
    pub fn from_json(bytes: &[u8]) -> Result<Self, ManifestError> {
        let manifest: Self = serde_json::from_slice(bytes)?;
        manifest.validate()?;
        Ok(manifest)
    }

    /// Parse, validate, and verify target matches current platform.
    /// Use this for upgrade/fetch flows where you only want matching manifests.
    ///
    /// # Errors
    ///
    /// Returns [`ManifestError`] if parsing, validation, or target check fails.
    pub fn for_current_platform(bytes: &[u8]) -> Result<Self, ManifestError> {
        let manifest = Self::from_json(bytes)?;
        manifest.check_target()?;
        Ok(manifest)
    }

    /// Hold the manifest to the storage key it was read from: its `version`
    /// and `target` must build that key back in `layout`, for the stream
    /// `name` (`fuz` for the self artifact, else the tool's name).
    ///
    /// A key is built from a release's name, version, and target, and is
    /// chosen before anything at it is read — from a `--version` the user
    /// pinned, or from the unsigned latest pointer. A manifest served there for
    /// another release, an older one included, is that other release: a
    /// signature says who published a manifest, not which key it belongs at.
    /// The name half is the caller's ([`ReleaseError::ToolManifestMismatch`],
    /// [`ManifestError::UnexpectedTool`]).
    ///
    /// [`ReleaseError::ToolManifestMismatch`]: crate::ReleaseError::ToolManifestMismatch
    ///
    /// # Errors
    ///
    /// [`ManifestError::KeyMismatch`] when the fields build another key.
    pub fn check_key(
        &self,
        layout: &ReleaseLayout,
        name: &str,
        key: &str,
    ) -> Result<(), ManifestError> {
        if layout.manifest_key(name, &self.version, &self.target) == key {
            Ok(())
        } else {
            Err(ManifestError::KeyMismatch {
                key: key.to_string(),
                version: self.version.clone(),
                target: self.target.clone(),
            })
        }
    }

    /// Validate manifest fields (called by `from_json()`).
    fn validate(&self) -> Result<(), ManifestError> {
        // Reject future format versions
        if self.format > MANIFEST_FORMAT_VERSION {
            return Err(ManifestError::UnsupportedFormat(self.format));
        }

        // Validate tarball path is simple filename
        validate_tarball_path(&self.tarball.path)?;

        // The content hash names the install directory (`artifacts/v1-<hash>`,
        // `tools/<name>/v1-<hash>`) before the download that verifies it, so its
        // shape is checked here, ahead of any filesystem access: `v1-` and 64
        // lowercase hex, never a path. Likewise every binary name becomes
        // `<install dir>/<name>` and `bin/<name>`, and is joined into the
        // content hash with `:` and `\n`, so each must be a release token: one
        // plain path component holding neither. The release log holds binary
        // names to the same rule. Defense in depth behind the signature, like
        // the tarball path.
        if !fuz_artifact::is_content_hash(&self.content_hash) {
            return Err(ManifestError::InvalidContentHash(self.content_hash.clone()));
        }
        if let Some(name) = self
            .binaries
            .keys()
            .find(|name| !fuz_artifact::is_release_token(name))
        {
            return Err(ManifestError::InvalidBinaryName(name.clone()));
        }

        // Reject unreasonably large tarballs before download
        if self.tarball.size > MAX_TOTAL_SIZE {
            return Err(ManifestError::TarballTooLarge(self.tarball.size));
        }

        // Refuse manifests that *declare* a test binary. The manifest is the
        // authoritative bill of materials — if a `testing_*` entry slipped
        // in, this is where the wrong-thing-shipped bug shows up first, ahead
        // of the binary-set checks so it is named as what it is.
        check_no_test_binaries(self.binaries.keys().map(String::as_str))?;

        // Validate the binary set. A self manifest (`tool: None`) must carry
        // exactly the fixed `SELF_BINARIES` — an extra binary would extract
        // into an artifact whose recorded outputs don't match its hash; a tool
        // manifest declares its own set (the signed bill of materials) and
        // needs the name allowlisted, a non-empty set, and no self binary in
        // it. fuz carries no per-tool "which binaries" table — the signed
        // manifest is that source of truth.
        match &self.tool {
            None => {
                for name in SELF_BINARIES {
                    if !self.binaries.contains_key(*name) {
                        return Err(ManifestError::MissingBinary((*name).to_string()));
                    }
                }
                if let Some(extra) = self
                    .binaries
                    .keys()
                    .filter(|name| !SELF_BINARIES.contains(&name.as_str()))
                    .min()
                {
                    return Err(ManifestError::UnexpectedBinary(extra.clone()));
                }
            }
            Some(tool) => {
                if !is_first_party_tool(tool) {
                    return Err(ManifestError::ToolNotAllowed(tool.clone()));
                }
                if self.binaries.is_empty() {
                    return Err(ManifestError::EmptyBinaries(tool.clone()));
                }
                // The set is the tool's to declare, but not a self binary's
                // name: every binary is linked into the one `bin/`.
                check_no_self_binaries(tool, self.binaries.keys().map(String::as_str))?;
            }
        }

        Ok(())
    }

    /// Check manifest target matches current platform.
    fn check_target(&self) -> Result<(), ManifestError> {
        let current = current_target();
        if self.target != current {
            return Err(ManifestError::TargetMismatch {
                expected: current.to_string(),
                actual: self.target.clone(),
            });
        }
        Ok(())
    }

    /// Verify the embedded signature, **consuming** `self` and yielding a
    /// [`VerifiedManifest`].
    ///
    /// This is the *sole* producer of [`VerifiedManifest`], the only type the
    /// download-and-trust funnels (`download_verify_extract`,
    /// `verify_cached_artifact`, and via them `fetch_version` / `install_tool`)
    /// accept. So "extract or install against a manifest whose signature was
    /// never checked" is unrepresentable: those funnels can't be reached without
    /// a token only this method mints.
    ///
    /// Extracts the unsigned portion, builds its signed bytes (the manifest
    /// tag, then the canonical JSON — `fuz_crypto::SignedMessage`), and
    /// verifies the signature via `fuz_crypto::verify_signature()`, capturing
    /// the trusted key that signed it (see [`VerifiedManifest::signed_by`]).
    ///
    /// # Errors
    ///
    /// Returns [`ManifestError::Signature`] or [`ManifestError::Canonical`]
    /// if verification fails.
    pub fn verify_signature(self) -> Result<VerifiedManifest, ManifestError> {
        let message = fuz_crypto::SignedMessage::new(&ManifestUnsigned::from(&self))?;
        let signed_by = fuz_crypto::verify_signature(&message, &self.signature)?;
        Ok(VerifiedManifest {
            manifest: self,
            signed_by,
        })
    }
}

/// A [`Manifest`] whose embedded signature has been verified against the
/// embedded trusted keys (`fuz_crypto::PUBLIC_KEYS`).
///
/// **Typestate.** Produced *solely* by [`Manifest::verify_signature`] and the
/// only type the download-and-trust funnels accept
/// (`download_verify_extract` / `verify_cached_artifact`, hence `fetch_version`
/// / `install_tool`). A manifest's pinned hashes therefore cannot be used as the
/// verification oracle for downloaded bytes until its signature is verified —
/// the ordering is enforced by the type system, not a doc comment.
///
/// Derefs to the inner [`Manifest`] for read access; call
/// [`into_manifest`](Self::into_manifest) to reclaim ownership when moving
/// fields into a result.
#[derive(Debug, Clone)]
pub struct VerifiedManifest {
    manifest: Manifest,
    signed_by: fuz_crypto::VerifyingKey,
}

impl VerifiedManifest {
    /// The trusted key whose signature verified this manifest (useful for
    /// logging / auditing *which* embedded key signed a release).
    #[must_use]
    pub const fn signed_by(&self) -> &fuz_crypto::VerifyingKey {
        &self.signed_by
    }

    /// Reclaim the inner [`Manifest`] by value — the deliberate valve out of the
    /// typestate, for moving fields into a result after the trust check is done.
    #[must_use]
    pub fn into_manifest(self) -> Manifest {
        self.manifest
    }

    /// Wrap a manifest as "verified" **without** checking its signature.
    ///
    /// Test-only — for unit tests that exercise the hash-verification mechanics
    /// (`download_verify_extract`, `verify_cached_artifact`) independently of the
    /// ed25519 trust check. `#[cfg(test)]`, so it never exists in a shipping
    /// build.
    #[cfg(test)]
    pub(crate) fn assume_verified_for_test(manifest: Manifest) -> Self {
        // A deterministic, valid key (a seed is always a valid keypair); these
        // tests never read `signed_by`.
        let signing = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        Self {
            manifest,
            signed_by: signing.verifying_key(),
        }
    }
}

impl std::ops::Deref for VerifiedManifest {
    type Target = Manifest;
    fn deref(&self) -> &Self::Target {
        &self.manifest
    }
}

// Manifest *signing* (`sign_manifest`) lives in the `fuz_sign` crate so the
// consumer `fuz` binary links verification only. The signer computes the
// signature and assembles the result via `Manifest::from_parts`.

/// Returns the current build target triple.
///
/// Requires `build.rs` to set `TARGET` env var at compile time.
pub const fn current_target() -> &'static str {
    env!("TARGET")
}

/// [`current_target`] as a [`ReleaseTarget`]: the target a publish defaults
/// to and every installed binary is held to.
///
/// # Errors
///
/// [`ManifestError::UnsupportedTarget`] when this build's target is outside
/// the supported set.
pub fn current_release_target() -> Result<ReleaseTarget, ManifestError> {
    Ok(current_target().parse()?)
}

/// Returns `true` when `name` is a test binary that must never ship in a
/// release.
///
/// The rule is strict: the binary's basename starts with the literal
/// prefix `testing_`. This is the convention enforced by the test-binary
/// pattern — per-consumer test binaries like `testing_zzz_server` and
/// `testing_spine_stub` link `fuz_testing`'s
/// `TestingArgon2idHasher` with weakened argon2 params (~1-5ms vs
/// production's ~30-50ms) and shipping one to production would be
/// catastrophic. Prefix matches the `Testing*` type-name pattern used
/// inside `fuz_testing` — the safety-critical word is the first thing
/// any audit site (deploy manifest, `ls target/release/`, log line, tab
/// completion) reads.
///
/// Examples (rejected): `testing_zzz_server`, `testing_spine_stub`,
/// `testing_`.
///
/// Examples (accepted): `fuz`, `fuzd`, `fuz_server`, `testingfuz` (no
/// underscore after `testing`), `testing` alone (no underscore — see
/// note below).
///
/// Note: A bare binary named `testing` is accepted by this filter. The
/// rule requires the trailing underscore so names like `testingfuz`,
/// `testing` itself, or unrelated names containing the substring
/// `testing` later in the name pass. A binary literally named `testing`
/// is exceedingly unlikely in this ecosystem; if one is ever proposed,
/// gate it explicitly at that time.
#[must_use]
pub fn is_test_binary_name(name: &str) -> bool {
    name.starts_with("testing_")
}

/// Reject any binary name in `names` that matches [`is_test_binary_name`].
///
/// Used at the publish-time enumeration step and inside manifest validation
/// so that both code paths (publishing a new release and parsing a fetched
/// manifest) refuse to handle test binaries.
///
/// # Errors
///
/// Returns [`ManifestError::TestBinaryRejected`] on the first match. Order
/// is unspecified for unordered inputs (e.g. `HashMap` keys); callers
/// should treat the returned name as "an example offender," not "the only
/// offender."
pub fn check_no_test_binaries<'a, I>(names: I) -> Result<(), ManifestError>
where
    I: IntoIterator<Item = &'a str>,
{
    for name in names {
        if is_test_binary_name(name) {
            return Err(ManifestError::TestBinaryRejected {
                name: name.to_string(),
            });
        }
    }
    Ok(())
}

/// Refuse a tool's binary set that declares a self binary
/// ([`SELF_BINARIES`]) in any ASCII case — the comparison the artifact store
/// makes where it links a tool ([`fuz_artifact::is_self_binary_name`]).
///
/// A tool's binaries are linked into the `~/.fuz/bin/` that holds the self
/// artifact's `bin/fuz`, so a tool manifest declaring `fuz` would take that
/// link over. Called by manifest validation and by the tool publish, so a
/// publisher cannot sign a manifest no client accepts. Two tools declaring
/// one name are not refused here.
///
/// # Errors
///
/// Returns [`ManifestError::ReservedBinaryName`] for the least such name.
pub fn check_no_self_binaries<'a, I>(tool: &str, names: I) -> Result<(), ManifestError>
where
    I: IntoIterator<Item = &'a str>,
{
    if let Some(binary) = names
        .into_iter()
        .filter(|name| fuz_artifact::is_self_binary_name(name))
        .min()
    {
        return Err(ManifestError::ReservedBinaryName {
            tool: tool.to_string(),
            binary: binary.to_string(),
        });
    }
    Ok(())
}

/// Validate tarball path is a simple filename (no path components).
///
/// Rejects:
/// - Empty paths
/// - Paths containing `/` or `\`
/// - Paths containing `..`
/// - Paths starting with `.`
pub fn validate_tarball_path(path: &str) -> Result<(), ManifestError> {
    // Must be non-empty simple filename
    if path.is_empty() {
        return Err(ManifestError::InvalidTarballPath(path.to_string()));
    }
    if path.contains('/') || path.contains('\\') {
        return Err(ManifestError::InvalidTarballPath(path.to_string()));
    }
    if path.contains("..") {
        return Err(ManifestError::InvalidTarballPath(path.to_string()));
    }
    if path.starts_with('.') {
        return Err(ManifestError::InvalidTarballPath(path.to_string()));
    }
    Ok(())
}

/// Check version safety: minimum version and downgrade protection.
///
/// The target is the manifest's own `version` — the release being installed — so
/// it is derived here rather than taken as a separate param a caller could set
/// inconsistently with the manifest.
///
/// # Arguments
///
/// * `current` - Currently installed version
/// * `manifest` - Manifest for the release being installed
///
/// # Errors
///
/// Returns [`ManifestError::BelowMinimum`] if the current version is below the
/// manifest's `minimum_version`, [`ManifestError::Downgrade`] if the manifest's
/// version is older than current, and [`ManifestError::InvalidVersion`] if the
/// manifest's version isn't valid semver.
pub(crate) fn check_version_safety(
    current: &semver::Version,
    manifest: &Manifest,
) -> Result<(), ManifestError> {
    // Publisher's minimum_version floor (server-side control).
    check_minimum_version(current, manifest)?;

    // Prevent downgrade (client-side control). The target is the manifest version.
    let target = parse_manifest_version(manifest)?;
    if target < *current {
        return Err(ManifestError::Downgrade {
            current: current.to_string(),
            target: target.to_string(),
        });
    }

    Ok(())
}

/// Parse the manifest's `version` field to a [`semver::Version`], mapping a
/// malformed value to [`ManifestError::InvalidVersion`]. The install-being
/// version is always the manifest's own `version`.
fn parse_manifest_version(manifest: &Manifest) -> Result<semver::Version, ManifestError> {
    semver::Version::parse(&manifest.version)
        .map_err(|_| ManifestError::InvalidVersion(manifest.version.clone()))
}

/// The publisher's `minimum_version` floor as a **verdict**: `Some(minimum)`
/// when `current` sits below the manifest's stated floor, `None` when the
/// manifest declares no floor or `current` clears it.
///
/// The single home of the floor comparison. Two surfaces want different
/// outcomes from the same question — `check_minimum_version` turns a `Some`
/// into [`ManifestError::BelowMinimum`], `compute_update_check` turns it into
/// [`UpdateStatus::UpdateRequired`] — so the shared piece is the verdict, not
/// the reaction. A change to where the floor sits (say inclusive vs exclusive)
/// happens here once and both surfaces move together.
///
/// # Errors
///
/// [`ManifestError::InvalidVersion`] if the manifest's `minimum_version` is not
/// valid semver.
fn below_minimum_version<'a>(
    current: &semver::Version,
    manifest: &'a Manifest,
) -> Result<Option<&'a str>, ManifestError> {
    let Some(min) = &manifest.minimum_version else {
        return Ok(None);
    };
    let min_ver =
        semver::Version::parse(min).map_err(|_| ManifestError::InvalidVersion(min.clone()))?;
    if current < &min_ver {
        return Ok(Some(min.as_str()));
    }
    Ok(None)
}

/// The publisher's `minimum_version` floor as an **error**: reject when
/// `current` is below the manifest's stated minimum. Shared by
/// `check_version_safety` and [`check_version_safety_with_downgrade`] so the
/// floor is enforced identically on both the monotonic and the downgrade-waived
/// path (a caller can waive monotonicity, never this floor). The comparison
/// itself lives in `below_minimum_version`, which the read-only
/// [`compute_update_check`] shares.
///
/// # Errors
///
/// [`ManifestError::BelowMinimum`] if below the floor; [`ManifestError::InvalidVersion`]
/// if the manifest's `minimum_version` is not valid semver.
fn check_minimum_version(
    current: &semver::Version,
    manifest: &Manifest,
) -> Result<(), ManifestError> {
    if let Some(minimum) = below_minimum_version(current, manifest)? {
        return Err(ManifestError::BelowMinimum {
            current: current.to_string(),
            minimum: minimum.to_string(),
            tool: manifest.tool.is_some(),
        });
    }
    Ok(())
}

/// Apply install-time version safety given the currently-installed version and
/// the caller's downgrade preference.
///
/// - `current == None` (**fresh install** — nothing is installed) → always
///   `Ok`. Neither guard applies: there is nothing to downgrade *from*, and the
///   publisher's `minimum_version` floor gates an *upgrade* path that doesn't
///   exist here. A `None` current is deliberately distinct from `Some(0.0.0)`;
///   collapsing them would make any tool that declares a `minimum_version`
///   uninstallable from scratch.
/// - `current == Some(v)`, `allow_downgrade == false` → full
///   `check_version_safety`: the manifest's `minimum_version` floor **and**
///   the no-downgrade (monotonicity) guard.
/// - `current == Some(v)`, `allow_downgrade == true` → the no-downgrade guard is
///   waived, but the `minimum_version` floor is **still** enforced. A caller can
///   opt out of monotonicity, never out of the publisher's hard minimum — so a
///   `--allow-downgrade` install of an ancient-but-signed release is still
///   refused when the *current* version is below that release's stated minimum.
///
/// This is the policy `fetch_version` / `install_tool` apply after resolving the
/// installed version; extracted as a pure function so every branch (notably the
/// fresh-install and the downgrade-still-enforces-minimum ones) is unit-testable
/// without touching `~/.fuz`.
///
/// # Errors
///
/// Returns [`ManifestError::BelowMinimum`] / [`ManifestError::Downgrade`] /
/// [`ManifestError::InvalidVersion`] per the rules above.
pub fn check_version_safety_with_downgrade(
    current: Option<&semver::Version>,
    manifest: &Manifest,
    allow_downgrade: bool,
) -> Result<(), ManifestError> {
    // Fresh install: no prior version to gate against, so both guards are moot.
    let Some(current) = current else {
        return Ok(());
    };

    if !allow_downgrade {
        return check_version_safety(current, manifest);
    }

    // Downgrade allowed: monotonicity is waived, but the minimum-version floor
    // still holds.
    check_minimum_version(current, manifest)
}

/// The verdict of a read-only update check (`fuz self upgrade --check` /
/// `fuz tool upgrade --check`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateStatus {
    /// The installed version is at or above the latest signed version.
    UpToDate,
    /// A newer signed version is available.
    UpdateAvailable,
    /// The installed version is below the latest release's `minimum_version`
    /// floor, so it cannot upgrade in place: fuz re-bootstraps, a tool
    /// reinstalls fresh (the `reason` says which).
    UpdateRequired,
    /// Nothing is installed — a first install is available (distinct from an
    /// out-of-date install; never reported as `update_required`).
    NotInstalled,
    /// The current install is unreadable (a dangling `current` link or a corrupt
    /// `meta.json`); repair with a `--force` reinstall or a re-bootstrap.
    Unreadable,
}

impl UpdateStatus {
    /// Whether this verdict means "an action is available/needed" — every case
    /// except `up_to_date` maps to the exit-10 signal. The specific action
    /// (update / first install / repair) is carried by the `status` field, not a
    /// separate exit integer.
    #[must_use]
    pub const fn is_update(self) -> bool {
        !matches!(self, Self::UpToDate)
    }
}

/// A computed update-check outcome: the [`UpdateStatus`] plus an optional
/// human-readable reason (populated for `update_required`).
#[derive(Debug, Clone)]
pub struct UpdateCheck {
    /// The verdict.
    pub status: UpdateStatus,
    /// A human-readable explanation, for the `update_required` case.
    pub reason: Option<String>,
}

/// Compute a read-only update-check verdict — the read-only twin of
/// `check_version_safety`.
///
/// Compares `installed` against a **verified** `manifest`'s version +
/// `minimum_version` floor, installing nothing:
///
/// - `installed` below the manifest's `minimum_version` → [`UpdateStatus::UpdateRequired`]
///   (you're below the floor the latest release demands; the `reason` names
///   the stream's recovery — a re-bootstrap for fuz, a fresh reinstall for a
///   tool).
/// - manifest version strictly newer than `installed` → [`UpdateStatus::UpdateAvailable`].
/// - otherwise → [`UpdateStatus::UpToDate`].
///
/// The minimum floor takes precedence: being below it is a stronger statement
/// than "a newer version exists" (and implies one). The version compared /
/// reported is the manifest's signed `version` — callers must pass a manifest
/// whose signature verified (the `VerifiedManifest` the fetch seams return), the
/// same contract `check_version_safety` carries.
///
/// # Errors
///
/// Returns [`ManifestError::InvalidVersion`] if `installed`, the manifest's
/// `version`, or its `minimum_version` is not valid semver.
pub fn compute_update_check(
    installed: &str,
    manifest: &Manifest,
) -> Result<UpdateCheck, ManifestError> {
    let current = semver::Version::parse(installed)
        .map_err(|_| ManifestError::InvalidVersion(installed.to_string()))?;
    let latest = parse_manifest_version(manifest)?;

    if let Some(min) = below_minimum_version(&current, manifest)? {
        return Ok(UpdateCheck {
            status: UpdateStatus::UpdateRequired,
            reason: Some(format!(
                "installed {current} is below the minimum {min} required by {latest}. {}",
                below_minimum_recovery(manifest.tool.is_some())
            )),
        });
    }

    let status = if latest > current {
        UpdateStatus::UpdateAvailable
    } else {
        UpdateStatus::UpToDate
    };
    Ok(UpdateCheck {
        status,
        reason: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_test_binary_name_rejects_testing_zzz_server() {
        assert!(is_test_binary_name("testing_zzz_server"));
    }

    #[test]
    fn is_test_binary_name_rejects_testing_fuz_forge_server() {
        assert!(is_test_binary_name("testing_fuz_forge_server"));
    }

    #[test]
    fn is_test_binary_name_rejects_testing_spine_stub() {
        assert!(is_test_binary_name("testing_spine_stub"));
    }

    #[test]
    fn is_test_binary_name_rejects_bare_testing_underscore() {
        // `testing_` itself starts with `testing_`.
        assert!(is_test_binary_name("testing_"));
    }

    #[test]
    fn is_test_binary_name_accepts_fuz() {
        assert!(!is_test_binary_name("fuz"));
    }

    #[test]
    fn is_test_binary_name_accepts_fuzd() {
        assert!(!is_test_binary_name("fuzd"));
    }

    #[test]
    fn is_test_binary_name_accepts_fuz_server() {
        // No `testing_` prefix.
        assert!(!is_test_binary_name("fuz_server"));
    }

    #[test]
    fn is_test_binary_name_accepts_testingfuz() {
        // Starts with `testing` but no trailing underscore.
        assert!(!is_test_binary_name("testingfuz"));
    }

    #[test]
    fn is_test_binary_name_accepts_bare_testing() {
        // Per the rule's strictness (`testing_` prefix), bare `testing`
        // passes. See doc-comment on `is_test_binary_name`.
        assert!(!is_test_binary_name("testing"));
    }

    #[test]
    fn is_test_binary_name_accepts_test_word_elsewhere_in_name() {
        // Only the `testing_` prefix matches. Names that contain `test`
        // or `testing` elsewhere — substring, suffix, or otherwise —
        // pass through.
        assert!(!is_test_binary_name("attest"));
        assert!(!is_test_binary_name("zzz_server_test"));
        assert!(!is_test_binary_name("fuz_forge_server_testing"));
    }

    #[test]
    fn check_no_test_binaries_accepts_production_set() {
        let names = ["fuz", "fuzd"];
        assert!(check_no_test_binaries(names.iter().copied()).is_ok());
    }

    #[test]
    fn check_no_test_binaries_rejects_when_any_match() {
        let names = ["fuz", "fuzd", "testing_zzz_server"];
        let err = check_no_test_binaries(names.iter().copied()).unwrap_err();
        match err {
            ManifestError::TestBinaryRejected { name } => assert_eq!(name, "testing_zzz_server"),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn validate_tarball_path_accepts_simple_filename() {
        assert!(validate_tarball_path("fuz-0.3.0-x86_64-unknown-linux-gnu.tar.gz").is_ok());
        assert!(validate_tarball_path("release.tar.gz").is_ok());
        assert!(validate_tarball_path("a").is_ok());
    }

    #[test]
    fn validate_tarball_path_rejects_empty() {
        let result = validate_tarball_path("");
        assert!(matches!(result, Err(ManifestError::InvalidTarballPath(p)) if p.is_empty()));
    }

    #[test]
    fn validate_tarball_path_rejects_slash() {
        let result = validate_tarball_path("foo/bar.tar.gz");
        assert!(matches!(result, Err(ManifestError::InvalidTarballPath(_))));
    }

    #[test]
    fn validate_tarball_path_rejects_backslash() {
        let result = validate_tarball_path("foo\\bar.tar.gz");
        assert!(matches!(result, Err(ManifestError::InvalidTarballPath(_))));
    }

    #[test]
    fn validate_tarball_path_rejects_dotdot() {
        let result = validate_tarball_path("..foo.tar.gz");
        assert!(matches!(result, Err(ManifestError::InvalidTarballPath(_))));

        let result = validate_tarball_path("foo..bar.tar.gz");
        assert!(matches!(result, Err(ManifestError::InvalidTarballPath(_))));
    }

    #[test]
    fn validate_tarball_path_rejects_leading_dot() {
        let result = validate_tarball_path(".hidden.tar.gz");
        assert!(matches!(result, Err(ManifestError::InvalidTarballPath(_))));
    }

    #[test]
    fn current_target_returns_valid_triple() {
        let target = current_target();
        assert!(!target.is_empty());
        // Should contain at least one hyphen (e.g., x86_64-unknown-linux-gnu)
        assert!(target.contains('-'), "target: {target}");
    }

    /// The build's triple is a supported release target, and the one the
    /// running binary's own header names.
    #[test]
    fn current_release_target_agrees_with_the_running_binary() {
        let target = current_release_target().unwrap();
        assert_eq!(target.triple(), current_target());
        assert_eq!(target, fuz_artifact::platform::test_stubs::host_target());
        let exe = std::fs::read(std::env::current_exe().unwrap()).unwrap();
        let found = fuz_artifact::platform::inspect_binary(&exe).unwrap();
        fuz_artifact::platform::check_binary_target(found, target, true).unwrap();
    }

    #[test]
    fn check_version_safety_allows_upgrade() {
        // The target is the manifest's version (0.3.0), installed over 0.2.0.
        let current = semver::Version::parse("0.2.0").unwrap();
        let manifest = test_manifest("0.3.0", None);

        let result = check_version_safety(&current, &manifest);
        assert!(result.is_ok());
    }

    #[test]
    fn check_version_safety_allows_same_version() {
        let current = semver::Version::parse("0.3.0").unwrap();
        let manifest = test_manifest("0.3.0", None);

        let result = check_version_safety(&current, &manifest);
        assert!(result.is_ok());
    }

    #[test]
    fn check_version_safety_rejects_downgrade() {
        // Installed 0.4.0, manifest (target) 0.3.0 → downgrade.
        let current = semver::Version::parse("0.4.0").unwrap();
        let manifest = test_manifest("0.3.0", None);

        let result = check_version_safety(&current, &manifest);
        assert!(matches!(result, Err(ManifestError::Downgrade { .. })));
    }

    #[test]
    fn check_version_safety_rejects_below_minimum() {
        let current = semver::Version::parse("0.2.0").unwrap();
        let manifest = test_manifest("0.4.0", Some("0.3.0"));

        let result = check_version_safety(&current, &manifest);
        assert!(matches!(result, Err(ManifestError::BelowMinimum { .. })));
    }

    #[test]
    fn check_version_safety_rejects_invalid_minimum() {
        let current = semver::Version::parse("0.2.0").unwrap();
        let manifest = test_manifest("0.4.0", Some("not-semver"));

        let result = check_version_safety(&current, &manifest);
        assert!(matches!(result, Err(ManifestError::InvalidVersion(_))));
    }

    #[test]
    fn check_version_safety_rejects_invalid_manifest_version() {
        // The manifest's own version is the target; a malformed one is InvalidVersion.
        let current = semver::Version::parse("0.2.0").unwrap();
        let manifest = test_manifest("not-semver", None);

        let result = check_version_safety(&current, &manifest);
        assert!(matches!(result, Err(ManifestError::InvalidVersion(_))));
    }

    //
    // check_version_safety_with_downgrade — the `fetch_version` install policy
    //

    #[test]
    fn with_downgrade_disabled_matches_check_version_safety() {
        // allow_downgrade == false delegates to check_version_safety: upgrade ok.
        let current = semver::Version::parse("0.2.0").unwrap();
        let manifest = test_manifest("0.3.0", None);
        assert!(check_version_safety_with_downgrade(Some(&current), &manifest, false).is_ok());
    }

    #[test]
    fn with_downgrade_disabled_still_rejects_downgrade() {
        let current = semver::Version::parse("0.4.0").unwrap();
        let manifest = test_manifest("0.3.0", None);
        let result = check_version_safety_with_downgrade(Some(&current), &manifest, false);
        assert!(matches!(result, Err(ManifestError::Downgrade { .. })));
    }

    #[test]
    fn fresh_install_ignores_minimum_floor() {
        // `current == None` (nothing installed) → a fresh install of any signed
        // version is allowed, even below the release's stated minimum. The floor
        // gates an *upgrade* path that a first install doesn't have; gating it
        // here would make any tool that sets a minimum uninstallable from scratch.
        let manifest = test_manifest("0.2.0", Some("9.9.9"));
        assert!(check_version_safety_with_downgrade(None, &manifest, false).is_ok());
        // ...and the escape hatch is irrelevant on a fresh install (nothing to waive).
        assert!(check_version_safety_with_downgrade(None, &manifest, true).is_ok());
    }

    #[test]
    fn with_downgrade_enabled_allows_downgrade_when_no_minimum() {
        // The whole point of --allow-downgrade: an older target (manifest 0.3.0
        // over installed 0.4.0) installs.
        let current = semver::Version::parse("0.4.0").unwrap();
        let manifest = test_manifest("0.3.0", None);
        assert!(check_version_safety_with_downgrade(Some(&current), &manifest, true).is_ok());
    }

    #[test]
    fn with_downgrade_enabled_still_enforces_minimum() {
        // THE branch: --allow-downgrade waives monotonicity but NOT the
        // publisher's minimum_version floor. An *installed* 0.1.0 < minimum 0.3.0
        // → refused even though downgrade is permitted.
        let current = semver::Version::parse("0.1.0").unwrap();
        let manifest = test_manifest("0.2.0", Some("0.3.0"));
        let result = check_version_safety_with_downgrade(Some(&current), &manifest, true);
        assert!(matches!(result, Err(ManifestError::BelowMinimum { .. })));
    }

    #[test]
    fn with_downgrade_enabled_allows_when_at_or_above_minimum() {
        // current 0.3.0 >= minimum 0.3.0, downgrading to manifest 0.2.0 → allowed.
        let current = semver::Version::parse("0.3.0").unwrap();
        let manifest = test_manifest("0.2.0", Some("0.3.0"));
        assert!(check_version_safety_with_downgrade(Some(&current), &manifest, true).is_ok());
    }

    #[test]
    fn with_downgrade_enabled_rejects_invalid_minimum() {
        let current = semver::Version::parse("0.2.0").unwrap();
        let manifest = test_manifest("0.1.0", Some("not-semver"));
        let result = check_version_safety_with_downgrade(Some(&current), &manifest, true);
        assert!(matches!(result, Err(ManifestError::InvalidVersion(_))));
    }

    //
    // compute_update_check — the read-only `--check` verdict
    //

    #[test]
    fn update_check_reports_available_when_newer() {
        let manifest = test_manifest("0.4.0", None);
        let check = compute_update_check("0.3.0", &manifest).unwrap();
        assert_eq!(check.status, UpdateStatus::UpdateAvailable);
        assert!(check.status.is_update());
        assert!(check.reason.is_none());
    }

    #[test]
    fn update_check_reports_up_to_date_when_equal() {
        let manifest = test_manifest("0.4.0", None);
        let check = compute_update_check("0.4.0", &manifest).unwrap();
        assert_eq!(check.status, UpdateStatus::UpToDate);
        assert!(!check.status.is_update());
    }

    #[test]
    fn update_check_reports_up_to_date_when_ahead() {
        // A latest pointer naming an older manifest than what's installed is
        // not "an update" — the installed version is ahead.
        let manifest = test_manifest("0.3.0", None);
        let check = compute_update_check("0.4.0", &manifest).unwrap();
        assert_eq!(check.status, UpdateStatus::UpToDate);
    }

    #[test]
    fn update_check_reports_required_below_minimum() {
        // installed 0.1.0 < the latest release's minimum 0.3.0 → required, with a
        // reason. The floor takes precedence over the plain newer-available case.
        let manifest = test_manifest("0.5.0", Some("0.3.0"));
        let check = compute_update_check("0.1.0", &manifest).unwrap();
        assert_eq!(check.status, UpdateStatus::UpdateRequired);
        assert!(check.status.is_update());
        assert!(check.reason.is_some(), "required must carry a reason");
    }

    #[test]
    fn update_check_available_when_at_or_above_minimum() {
        // installed 0.3.0 meets the 0.3.0 floor, and 0.5.0 is newer → available.
        let manifest = test_manifest("0.5.0", Some("0.3.0"));
        let check = compute_update_check("0.3.0", &manifest).unwrap();
        assert_eq!(check.status, UpdateStatus::UpdateAvailable);
    }

    #[test]
    fn update_check_rejects_invalid_installed_version() {
        let manifest = test_manifest("0.4.0", None);
        let err = compute_update_check("not-semver", &manifest).unwrap_err();
        assert!(matches!(err, ManifestError::InvalidVersion(_)));
    }

    #[test]
    fn update_check_invalid_version_names_manifest_version_not_minimum() {
        // The two consumers of the `minimum_version` floor evaluate their steps
        // in opposite orders, and the difference is observable: given a manifest
        // whose `version` *and* `minimum_version` are both malformed,
        // `compute_update_check` parses the manifest version first and so names
        // it, while `check_version_safety` consults the floor first and so names
        // the minimum. Both answers are correct for their surface, and each
        // ordering is load-bearing rather than incidental — moving either step
        // past the other silently changes which string a caller is handed, so
        // this pins both halves of the disagreement.
        let manifest = test_manifest("not-semver", Some("also-not-semver"));

        let err = compute_update_check("0.1.0", &manifest).unwrap_err();
        assert!(
            matches!(&err, ManifestError::InvalidVersion(v) if v == "not-semver"),
            "compute_update_check must name the manifest version, got {err:?}"
        );

        let current = semver::Version::parse("0.1.0").unwrap();
        let err = check_version_safety(&current, &manifest).unwrap_err();
        assert!(
            matches!(&err, ManifestError::InvalidVersion(v) if v == "also-not-semver"),
            "check_version_safety must name the minimum, got {err:?}"
        );
    }

    #[test]
    fn update_check_required_reason_names_installed_minimum_and_latest() {
        // The `reason` is user-facing: `fuz self upgrade --check` prints it under
        // the verdict line and `--json` carries it in the payload, so its content
        // is part of the contract — it must name what is installed, the floor
        // that install misses, and the release demanding that floor.
        let manifest = test_manifest("0.5.0", Some("0.3.0"));
        let check = compute_update_check("0.1.0", &manifest).unwrap();
        assert_eq!(check.status, UpdateStatus::UpdateRequired);
        assert_eq!(
            check.reason.as_deref(),
            Some(
                "installed 0.1.0 is below the minimum 0.3.0 required by 0.5.0. \
                 Re-bootstrap required: reinstall fuz, see https://github.com/fuzdev/fuz#usage"
            )
        );

        // a tool's floor is the tool's own: it reinstalls fresh, never
        // re-bootstraps fuz (`fuz tool upgrade --check`)
        let mut manifest = manifest;
        manifest.tool = Some("fuzi".to_string());
        let check = compute_update_check("0.1.0", &manifest).unwrap();
        assert_eq!(check.status, UpdateStatus::UpdateRequired);
        let reason = check.reason.unwrap();
        assert!(
            reason.starts_with("installed 0.1.0 is below the minimum 0.3.0 required by 0.5.0. "),
            "{reason}"
        );
        assert!(reason.ends_with(below_minimum_recovery(true)), "{reason}");
        assert!(reason.contains("fuz tool install <name>"), "{reason}");
        assert!(!reason.contains("Re-bootstrap"), "{reason}");
    }

    #[test]
    fn update_check_serializes_status_snake_case() {
        // The wire contract for `--json`: snake_case status literals.
        assert_eq!(
            serde_json::to_string(&UpdateStatus::UpToDate).unwrap(),
            "\"up_to_date\""
        );
        assert_eq!(
            serde_json::to_string(&UpdateStatus::UpdateAvailable).unwrap(),
            "\"update_available\""
        );
        assert_eq!(
            serde_json::to_string(&UpdateStatus::UpdateRequired).unwrap(),
            "\"update_required\""
        );
        assert_eq!(
            serde_json::to_string(&UpdateStatus::NotInstalled).unwrap(),
            "\"not_installed\""
        );
        assert_eq!(
            serde_json::to_string(&UpdateStatus::Unreadable).unwrap(),
            "\"unreadable\""
        );
    }

    #[test]
    fn update_status_is_update_is_true_for_everything_but_up_to_date() {
        // `--check` exits 10 for any non-up-to-date verdict; the specific action
        // is carried by the status, not a separate exit integer.
        assert!(!UpdateStatus::UpToDate.is_update());
        for s in [
            UpdateStatus::UpdateAvailable,
            UpdateStatus::UpdateRequired,
            UpdateStatus::NotInstalled,
            UpdateStatus::Unreadable,
        ] {
            assert!(s.is_update(), "{s:?} should count as an action");
        }
    }

    /// Build a `Manifest` with a placeholder signature. These tests cover
    /// parsing/validation/version-safety — none verify the signature — so the
    /// signature value is irrelevant. Real signing lives in `fuz_sign`.
    fn dummy_signature() -> fuz_crypto::Signature {
        fuz_crypto::Signature {
            format: fuz_crypto::SIGNATURE_FORMAT_VERSION,
            public_key: String::new(),
            algorithm: fuz_crypto::SignatureAlgorithm::Ed25519,
            signed_at: "2025-01-15T10:30:00Z".to_string(),
            sig: String::new(),
        }
    }

    fn manifest_from_unsigned(u: ManifestUnsigned) -> Manifest {
        Manifest::from_parts(u, dummy_signature())
    }

    // Helper to create a test manifest (placeholder signature; see above).
    fn test_manifest(version: &str, minimum_version: Option<&str>) -> Manifest {
        let unsigned = ManifestUnsigned {
            format: 1,
            version: version.to_string(),
            content_hash: "v1-abc1230000000000000000000000000000000000000000000000000000000000"
                .to_string(),
            target: current_target().to_string(),
            minimum_version: minimum_version.map(String::from),
            tarball: TarballInfo {
                path: "release.tar.gz".to_string(),
                blake3: ContentHash::blake3(b"tarball"),
                size: 1000,
            },
            binaries: {
                let mut h = HashMap::new();
                h.insert("fuz".to_string(), ContentHash::blake3(b"fuz"));
                h
            },
            tool: None,
        };

        manifest_from_unsigned(unsigned)
    }

    /// Build a single-binary tool manifest (placeholder signature) for the name.
    fn test_tool_manifest(tool: &str, binary: &str) -> Manifest {
        let unsigned = ManifestUnsigned {
            format: 1,
            version: "0.1.0".to_string(),
            content_hash: "v1-abc1230000000000000000000000000000000000000000000000000000000000"
                .to_string(),
            target: current_target().to_string(),
            minimum_version: None,
            tarball: TarballInfo {
                path: format!("{tool}-0.1.0-{}.tar.gz", current_target()),
                blake3: ContentHash::blake3(b"tarball"),
                size: 1000,
            },
            binaries: {
                let mut h = HashMap::new();
                h.insert(binary.to_string(), ContentHash::blake3(b"binary"));
                h
            },
            tool: Some(tool.to_string()),
        };
        manifest_from_unsigned(unsigned)
    }

    #[test]
    fn self_manifest_has_no_tool_field_in_json() {
        // Self manifests must serialize without a `tool` key so existing
        // published-manifest signatures stay valid (skip_serializing_if).
        let manifest = test_manifest("0.3.0", None);
        let json = serde_json::to_string(&manifest).unwrap();
        assert!(!json.contains("\"tool\""), "json: {json}");
    }

    #[test]
    fn tool_manifest_round_trips_and_validates() {
        // Signature verification needs a trusted key and is exercised end to end
        // in `fuz_sign/tests/signed_trust.rs`; here we cover parse + validation
        // of the generalized `tool` field.
        let manifest = test_tool_manifest("fuzf", "fuzf");
        let json = serde_json::to_vec(&manifest).unwrap();
        let parsed = Manifest::from_json(&json).expect("tool manifest should validate");
        assert_eq!(parsed.tool.as_deref(), Some("fuzf"));
    }

    #[test]
    fn tool_manifest_rejects_name_outside_allowlist() {
        // Build with a disallowed name (bypassing the publish-path name gate)
        // then parse — `from_json` validation must reject it.
        let unsigned = ManifestUnsigned {
            format: 1,
            version: "0.1.0".to_string(),
            content_hash: "v1-abc1230000000000000000000000000000000000000000000000000000000000"
                .to_string(),
            target: current_target().to_string(),
            minimum_version: None,
            tarball: TarballInfo {
                path: "rando-0.1.0.tar.gz".to_string(),
                blake3: ContentHash::blake3(b"tarball"),
                size: 1000,
            },
            binaries: {
                let mut h = HashMap::new();
                h.insert("rando".to_string(), ContentHash::blake3(b"rando"));
                h
            },
            tool: Some("rando".to_string()),
        };
        let manifest = manifest_from_unsigned(unsigned);
        let json = serde_json::to_vec(&manifest).unwrap();
        let err = Manifest::from_json(&json).unwrap_err();
        assert!(matches!(err, ManifestError::ToolNotAllowed(name) if name == "rando"));
    }
}
