//! End-to-end signed-trust path: sign with a trusted key → publish to storage →
//! fetch → pass the real ed25519 trust check → install into a temp home.
//!
//! This is the composition the unit suites can't reach. The verifying keys
//! embedded in `fuz_crypto` are the operator's real keys — no private half lives
//! in-repo — and the fetch/install flows resolve every path under `~/.fuz`. Two
//! dev-dependency-only seams make it driveable:
//!
//! - `fuz_crypto/test_trust_anchor` — register a key the test controls so the
//!   real `verify()` trust check admits it.
//! - `fuz_home/test_home_override` — redirect the home in-process, since edition
//!   2024 + the workspace `unsafe_code = "forbid"` rule out `std::env::set_var`.
//!
//! Both are compiled out of every shipping binary (resolver-2 keeps a dev-dep
//! feature off normal builds — verified with `cargo tree -e features`), the same
//! production-safety property `cargo xtask check-release` enforces by dependency
//! graph for the `fuz_testing` / `fuz_sign` crates.

#![expect(
    clippy::unwrap_used,
    reason = "test helpers outside `#[test]` fns panic on a failed setup or check"
)]

use fuz_artifact::platform::test_stubs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use fuz_artifact::{
    ARTIFACT_DIR_MODE, ArtifactError, ArtifactMeta, ArtifactOutputs, setup_bin_symlinks,
    setup_tool_symlinks,
};
use fuz_crypto::ContentHash;
use fuz_release::{
    BinaryHashes, FetchOptions, MANIFEST_FORMAT_VERSION, Manifest, ManifestError, ManifestUnsigned,
    ReleaseError, ReleaseLayout, TarballInfo, ToolInstallOptions, ToolInstallOutcome,
    current_target, fetch_latest, fetch_latest_manifest, fetch_tool_manifest, fetch_version,
    install_tool, verify_installed_tool,
};
use fuz_sign::{PublishOptions, SigningKey, publish_artifact, publish_tool, sign_manifest};
use fuz_storage::{FileStorage, Storage, StorageError};
use fuz_sys::SECURE_DIR_MODE;

/// Serializes the whole file. The trust anchor and home override are process
/// globals, and cargo runs `#[test]`s on parallel threads. A tokio mutex (not
/// std) so it can be held across `.await` without tripping `await_holding_lock`
/// and without poisoning when an assertion panics.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// A fresh temp home, pinned to `0700` and installed as the process-wide
/// `~/.fuz` override for the test body. The returned `TempDir` must outlive it.
///
/// The mode is **set**, not inherited. `tempfile::tempdir()` creates at the std
/// default `0o777` masked by the process umask, so under a permissive runner
/// umask (`umask 000`, routine in containers) the home would arrive
/// world-writable and every fetch/install below would refuse with
/// `InsecureHome` before reaching the trust path these tests exist to exercise.
/// [`SECURE_DIR_MODE`] is what a real `ensure_fuz_home` creates; the one test
/// that wants a world-writable home chmods after this call.
fn fresh_home() -> tempfile::TempDir {
    let home = tempfile::tempdir().unwrap();
    std::fs::set_permissions(
        home.path(),
        std::fs::Permissions::from_mode(SECURE_DIR_MODE),
    )
    .unwrap();
    fuz_home::set_fuz_home_override_for_testing(home.path());
    home
}

/// A deterministic, distinct signing key the test trusts via the anchor.
fn trusted_key() -> SigningKey {
    SigningKey::from_bytes(&[11u8; 32])
}

/// A deterministic key the test never registers — it must stay untrusted.
fn untrusted_key() -> SigningKey {
    SigningKey::from_bytes(&[22u8; 32])
}

/// Reset the trust anchor to exactly `key` (called under `SERIAL`).
fn trust_only(key: &SigningKey) {
    fuz_crypto::clear_trusted_keys_for_testing();
    fuz_crypto::add_trusted_key_for_testing(&key.verifying_key());
}

/// A valid fuz-only unsigned manifest (passes `Manifest` validation).
fn sample_self_unsigned(version: &str, minimum_version: Option<&str>) -> ManifestUnsigned {
    let mut binaries = BinaryHashes::new();
    binaries.insert("fuz".to_string(), ContentHash::blake3(b"fuz"));
    ManifestUnsigned {
        format: MANIFEST_FORMAT_VERSION,
        version: version.to_string(),
        content_hash: "v1-abc1230000000000000000000000000000000000000000000000000000000000"
            .to_string(),
        target: current_target().to_string(),
        minimum_version: minimum_version.map(String::from),
        tarball: TarballInfo {
            path: format!("fuz-{version}.tar.gz"),
            blake3: ContentHash::blake3(b"tarball"),
            size: 1,
        },
        binaries,
        tool: None,
    }
}

/// A valid per-tool unsigned manifest declaring `tool` (passes validation for
/// any allowlisted name).
fn sample_tool_unsigned(tool: &str, version: &str) -> ManifestUnsigned {
    let mut binaries = BinaryHashes::new();
    binaries.insert(tool.to_string(), ContentHash::blake3(tool.as_bytes()));
    ManifestUnsigned {
        format: MANIFEST_FORMAT_VERSION,
        version: version.to_string(),
        content_hash: "v1-abc1230000000000000000000000000000000000000000000000000000000000"
            .to_string(),
        target: current_target().to_string(),
        minimum_version: None,
        tarball: TarballInfo {
            path: format!("{tool}-{version}.tar.gz"),
            blake3: ContentHash::blake3(b"tarball"),
            size: 1,
        },
        binaries,
        tool: Some(tool.to_string()),
    }
}

/// Build a fuz-only self artifact on disk (binary + matching meta.json) for the
/// publish flows.
fn make_self_artifact(dir: &Path, version: &str, content: &[u8]) -> ArtifactMeta {
    std::fs::write(dir.join("fuz"), content).unwrap();
    let outputs = ArtifactOutputs {
        fuz: ContentHash::blake3(content),
    };
    let meta = ArtifactMeta::new_remote(outputs.content_hash(), version.to_string(), outputs);
    meta.write(dir).unwrap();
    meta
}

/// The headline composition: a manifest signed by the registered trusted key
/// verifies through the real `verify_signature` path; tamper or an unregistered
/// key is rejected. Proves the anchor is doing selective trust work, not
/// blanket-accepting.
#[tokio::test]
async fn signed_manifest_verifies_only_with_registered_trusted_key() {
    let _serial = SERIAL.lock().await;
    let key = trusted_key();
    trust_only(&key);

    // sign → serialize → parse → verify OK
    let manifest = sign_manifest(
        sample_self_unsigned("0.3.0", None),
        &key,
        "2025-01-15T10:30:00Z",
    )
    .unwrap();
    let bytes = serde_json::to_vec(&manifest).unwrap();
    let parsed = Manifest::from_json(&bytes).unwrap();
    parsed
        .clone()
        .verify_signature()
        .expect("a manifest signed by the registered trusted key must verify");

    // tamper after signing → canonical JSON changes → signature rejected
    let mut tampered = parsed;
    tampered.version = "9.9.9".to_string();
    assert!(matches!(
        tampered.verify_signature(),
        Err(ManifestError::Signature(_))
    ));

    // a different, unregistered key → untrusted → rejected
    let other = untrusted_key();
    let other_manifest = sign_manifest(
        sample_self_unsigned("0.3.0", None),
        &other,
        "2025-01-15T10:30:00Z",
    )
    .unwrap();
    assert!(matches!(
        other_manifest.verify_signature(),
        Err(ManifestError::Signature(_))
    ));

    fuz_crypto::clear_trusted_keys_for_testing();
}

/// A signed manifest with a second `fuz` entry spliced in ahead of the signed
/// one is refused before its signature is checked. Read as a plain map, the
/// last entry wins, the re-serialized value is the one that was signed, and
/// the document verifies — while a reader keeping the first entry, the
/// documented `grep` of the manifest among them, takes the spliced digest.
#[tokio::test]
async fn a_signed_manifest_repeating_a_binary_name_is_refused() {
    let _serial = SERIAL.lock().await;
    let key = trusted_key();
    trust_only(&key);

    let manifest = sign_manifest(
        sample_self_unsigned("0.3.0", None),
        &key,
        "2025-01-15T10:30:00Z",
    )
    .unwrap();
    let json = serde_json::to_string(&manifest).unwrap();
    let spliced = ContentHash::blake3(b"spliced").to_hex();
    let repeated = json.replacen(
        "\"binaries\":{",
        &format!("\"binaries\":{{\"fuz\":\"{spliced}\","),
        1,
    );
    assert_ne!(repeated, json);
    // The document as signed still verifies: only the repeat is refused.
    Manifest::from_json(json.as_bytes())
        .and_then(Manifest::verify_signature)
        .unwrap();

    let error = Manifest::from_json(repeated.as_bytes())
        .and_then(Manifest::verify_signature)
        .expect_err("a manifest repeating a binary name must be refused");
    assert!(
        matches!(&error, ManifestError::Parse(_))
            && error.to_string().contains("duplicate key \"fuz\""),
        "got {error:?}"
    );

    fuz_crypto::clear_trusted_keys_for_testing();
}

/// Self artifact, full round trip: publish (signs) → `fetch_latest` (resolves
/// the latest pointer, downloads + verifies the signature with the registered key,
/// extracts) → second fetch is a verified cache hit.
#[tokio::test]
async fn publish_then_fetch_latest_self_artifact_end_to_end() {
    let _serial = SERIAL.lock().await;
    let key = trusted_key();
    trust_only(&key);

    let home = fresh_home();

    let storage_dir = tempfile::tempdir().unwrap();
    let storage = FileStorage::new(storage_dir.path()).unwrap();

    let artifact_dir = tempfile::tempdir().unwrap();
    let content: &[u8] = &test_stubs::host(b"fuz binary bytes -- e2e self artifact");
    let meta = make_self_artifact(artifact_dir.path(), "0.5.0", content);

    publish_artifact(
        &storage,
        &meta,
        artifact_dir.path(),
        &key,
        &PublishOptions::default(),
    )
    .await
    .unwrap();

    // The whole point: sign → fetch → real signature verify → extract.
    let result = fetch_latest(&storage, &FetchOptions::default())
        .await
        .expect("fetch_latest must succeed end to end");
    assert_eq!(result.version, "0.5.0");
    assert!(!result.cache_hit);
    assert!(result.artifact_dir.starts_with(home.path()));
    assert_eq!(
        std::fs::read(result.artifact_dir.join("fuz")).unwrap(),
        content
    );

    // The downloaded artifact dir carries the same mode a locally built one
    // does, and its `artifacts/` parent the same 0700 `ensure_fuz_home` would
    // have made — both stated by the fetch, not inherited. The staging dir is
    // renamed into place, so without the explicit modes an upgrade run under
    // `umask 000` lands a world-writable artifact tree.
    assert_eq!(
        std::fs::metadata(&result.artifact_dir)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        ARTIFACT_DIR_MODE,
        "the fetched artifact dir carries an explicit 0755"
    );
    assert_eq!(
        std::fs::metadata(result.artifact_dir.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        SECURE_DIR_MODE,
        "~/.fuz/artifacts must be created at 0700, not at the runner's umask"
    );

    // Second fetch is a cache hit, routed through `verify_cached_artifact` with
    // the real trust check still in front of it.
    let again = fetch_latest(&storage, &FetchOptions::default())
        .await
        .unwrap();
    assert!(again.cache_hit);
    assert_eq!(again.content_hash, result.content_hash);

    fuz_home::clear_fuz_home_override_for_testing();
    fuz_crypto::clear_trusted_keys_for_testing();
}

/// Per-tool artifact, full round trip: `publish_tool` → `install_tool`
/// (resolves the per-tool latest, verifies the signature, extracts, links into
/// `~/.fuz/bin`) → `verify_installed_tool` → second install is a verified cache
/// hit.
#[tokio::test]
async fn publish_then_install_tool_end_to_end() {
    let _serial = SERIAL.lock().await;
    let key = trusted_key();
    trust_only(&key);

    let home = fresh_home();

    let storage_dir = tempfile::tempdir().unwrap();
    let storage = FileStorage::new(storage_dir.path()).unwrap();

    let bin_dir = tempfile::tempdir().unwrap();
    let bin_path = bin_dir.path().join("fuzf");
    let content: &[u8] = &test_stubs::host(b"fuzf binary bytes -- e2e tool");
    std::fs::write(&bin_path, content).unwrap();

    publish_tool(
        &storage,
        "fuzf",
        "0.1.0",
        &[("fuzf".to_string(), bin_path.clone())],
        &key,
        &PublishOptions::default(),
    )
    .await
    .unwrap();

    let result = install_tool(&storage, "fuzf", &ToolInstallOptions::default())
        .await
        .expect("install_tool must succeed end to end");
    assert_eq!(result.name, "fuzf");
    assert_eq!(result.version, "0.1.0");
    assert_eq!(result.outcome, ToolInstallOutcome::Installed);
    assert!(result.install_dir.starts_with(home.path()));
    assert_eq!(result.binaries, vec!["fuzf".to_string()]);
    verify_installed_tool("fuzf").expect("the installed tool must verify against its meta");

    // The staging dir is *renamed* into place, so its creation mode is the mode
    // the install lands at. The forge path and the local one
    // (`fuz_artifact::tools::install_local_tool`) must agree on it, and both set
    // it explicitly — so the expected value here doesn't move with the runner's
    // umask.
    assert_eq!(
        std::fs::metadata(&result.install_dir)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        SECURE_DIR_MODE,
        "the installed tool dir inherits the staging dir's explicit 0700"
    );

    // Second install: same content hash already present *and* already current →
    // re-verify + relink onto itself, the one genuine no-op.
    let again = install_tool(&storage, "fuzf", &ToolInstallOptions::default())
        .await
        .unwrap();
    assert_eq!(again.outcome, ToolInstallOutcome::AlreadyCurrent);
    assert_eq!(again.content_hash, result.content_hash);

    fuz_home::clear_fuz_home_override_for_testing();
    fuz_crypto::clear_trusted_keys_for_testing();
}

/// The relink a skipped download can't see: the requested content hash is already
/// unpacked, but `current` points at a *different* one — so `install_tool` moves
/// the active binary without fetching a byte. Driven through the real flow
/// (publish two versions, install both, then pin `--version` back to the older
/// one, whose install dir is still on disk) because that is how a user reaches the
/// state. The outcome must be `Relinked`, never `AlreadyCurrent`: `fuz tool
/// install` renders "already have …" for the no-op case, and here `~/.fuz/bin/fuzf`
/// really did change underneath it.
#[tokio::test]
async fn install_tool_relinking_off_another_hash_is_not_a_no_op() {
    let _serial = SERIAL.lock().await;
    let key = trusted_key();
    trust_only(&key);

    let home = fresh_home();

    let storage_dir = tempfile::tempdir().unwrap();
    let storage = FileStorage::new(storage_dir.path()).unwrap();
    let bin_dir = tempfile::tempdir().unwrap();

    let old_bytes: &[u8] = &test_stubs::host(b"fuzf binary bytes -- 0.1.0");
    let new_bytes: &[u8] = &test_stubs::host(b"fuzf binary bytes -- 0.2.0");
    publish_tool_version(&storage, &key, bin_dir.path(), "0.1.0", old_bytes, None).await;
    publish_tool_version(&storage, &key, bin_dir.path(), "0.2.0", new_bytes, None).await;

    let first = install_tool(
        &storage,
        "fuzf",
        &ToolInstallOptions {
            version: Some("0.1.0"),
            ..Default::default()
        },
    )
    .await
    .expect("installing 0.1.0 must succeed");
    assert_eq!(first.outcome, ToolInstallOutcome::Installed);
    let second = install_tool(
        &storage,
        "fuzf",
        &ToolInstallOptions {
            version: Some("0.2.0"),
            ..Default::default()
        },
    )
    .await
    .expect("installing 0.2.0 must succeed");
    assert_eq!(second.outcome, ToolInstallOutcome::Installed);
    assert_ne!(
        first.content_hash, second.content_hash,
        "the two versions must be distinct artifacts"
    );

    // The state under test: 0.1.0's content-addressed dir survived the upgrade, so
    // reinstalling it downloads nothing — and repoints `current` back onto it.
    assert!(
        first.install_dir.exists(),
        "the older install dir must still be on disk"
    );
    let back = install_tool(
        &storage,
        "fuzf",
        &ToolInstallOptions {
            version: Some("0.1.0"),
            allow_downgrade: true,
            ..Default::default()
        },
    )
    .await
    .expect("reinstalling the cached 0.1.0 must succeed");
    assert_eq!(
        back.outcome,
        ToolInstallOutcome::Relinked {
            previous: Some(second.content_hash.clone()),
        },
        "a cached hash that was not current is a relink, not a no-op"
    );
    assert_eq!(back.content_hash, first.content_hash);

    // The claim the outcome makes, checked on disk: the binary on PATH moved.
    let active = home.path().join("bin").join("fuzf");
    assert_eq!(
        std::fs::read(&active).unwrap().as_slice(),
        old_bytes,
        "bin/fuzf must resolve to the relinked version's bytes"
    );

    // Only now is it a genuine no-op: same hash, and already current.
    let again = install_tool(
        &storage,
        "fuzf",
        &ToolInstallOptions {
            version: Some("0.1.0"),
            allow_downgrade: true,
            ..Default::default()
        },
    )
    .await
    .expect("a second reinstall of the current hash must succeed");
    assert_eq!(again.outcome, ToolInstallOutcome::AlreadyCurrent);

    fuz_home::clear_fuz_home_override_for_testing();
    fuz_crypto::clear_trusted_keys_for_testing();
}

/// `--allow-downgrade` waives the no-downgrade guard but must NOT waive the
/// publisher's `minimum_version` floor — on the **upgrade path** (something is
/// installed). Driven through the real `fetch_version`: install a 0.4.0 base and
/// make it `current`, then a 0.5.0 release demanding minimum 0.5.0 is refused
/// with `BelowMinimum` whether or not `allow_downgrade` is set (the floor is
/// checked before the downgrade guard, so both cases surface `BelowMinimum`). A
/// *fresh* install is deliberately exempt from the floor — see the
/// `fresh_install_ignores_minimum_floor` unit test and
/// `fresh_tool_install_below_minimum_succeeds`.
#[tokio::test]
async fn fetch_version_enforces_minimum_even_with_allow_downgrade() {
    let _serial = SERIAL.lock().await;
    let key = trusted_key();
    trust_only(&key);

    let _home = fresh_home();

    let storage_dir = tempfile::tempdir().unwrap();
    let storage = FileStorage::new(storage_dir.path()).unwrap();

    // Publish a 0.4.0 base (no floor) and a 0.5.0 that demands minimum 0.5.0.
    let base_dir = tempfile::tempdir().unwrap();
    let base = make_self_artifact(
        base_dir.path(),
        "0.4.0",
        &test_stubs::host(b"fuz bytes -- base 0.4.0"),
    );
    publish_artifact(
        &storage,
        &base,
        base_dir.path(),
        &key,
        &PublishOptions::default(),
    )
    .await
    .unwrap();

    let next_dir = tempfile::tempdir().unwrap();
    let next = make_self_artifact(
        next_dir.path(),
        "0.5.0",
        &test_stubs::host(b"fuz bytes -- min-gated 0.5.0"),
    );
    publish_artifact(
        &storage,
        &next,
        next_dir.path(),
        &key,
        &PublishOptions {
            minimum_version: Some("0.5.0".to_string()),
            ..PublishOptions::default()
        },
    )
    .await
    .unwrap();

    // Install the 0.4.0 base and make it current — now we're on the upgrade path
    // (a real installed version below the floor, not the fresh-install sentinel).
    let installed = fetch_version(&storage, "0.4.0", &FetchOptions::default())
        .await
        .expect("base install must succeed");
    fuz_artifact::switch_current(&installed.content_hash).unwrap();

    // Default options: signature verifies (trusted key), then the floor rejects
    // (installed 0.4.0 is below the release's stated minimum 0.5.0).
    let err = fetch_version(&storage, "0.5.0", &FetchOptions::default())
        .await
        .expect_err("below-minimum must reject on the upgrade path");
    assert!(
        matches!(
            err,
            ReleaseError::Manifest(ManifestError::BelowMinimum { .. })
        ),
        "got {err:?}"
    );

    // allow_downgrade waives monotonicity but NOT the minimum floor.
    let err = fetch_version(
        &storage,
        "0.5.0",
        &FetchOptions {
            allow_downgrade: true,
            force: false,
            ..Default::default()
        },
    )
    .await
    .expect_err("below-minimum must reject even with allow_downgrade");
    assert!(
        matches!(
            err,
            ReleaseError::Manifest(ManifestError::BelowMinimum { .. })
        ),
        "got {err:?}"
    );

    fuz_home::clear_fuz_home_override_for_testing();
    fuz_crypto::clear_trusted_keys_for_testing();
}

/// `signed_at` is informational and lives OUTSIDE the signed canonical JSON
/// (`verify_signature` reconstructs `ManifestUnsigned`, which has no signature
/// field). Mutating it after signing must NOT break verification. If this ever
/// fails, someone folded `signed_at` into the signed bytes — which silently
/// invalidates every previously issued signature. Driven through the real trust
/// check (registered key) so it exercises the production verify path, contrast
/// to `signed_manifest_verifies_only_with_registered_trusted_key` where a
/// `version` tamper IS rejected.
#[tokio::test]
async fn signed_at_is_not_covered_by_the_signature() {
    let _serial = SERIAL.lock().await;
    let key = trusted_key();
    trust_only(&key);

    let mut manifest = sign_manifest(
        sample_self_unsigned("0.3.0", None),
        &key,
        "2025-01-15T10:30:00Z",
    )
    .unwrap();
    manifest
        .clone()
        .verify_signature()
        .expect("baseline: a freshly signed manifest verifies");

    // Mutate ONLY signed_at — unauthenticated metadata.
    manifest.signature.signed_at = "2099-12-31T23:59:59Z".to_string();
    manifest
        .verify_signature()
        .expect("signed_at is not signed; mutating it must not break verification");

    fuz_crypto::clear_trusted_keys_for_testing();
}

/// Key-rotation overlap: with two keys trusted at once (the old + the new during
/// a rotation window), a manifest signed by EITHER verifies, while an
/// unregistered key is still rejected. This is the multi-key trust the rotation
/// procedure (add new key, sign with new, later drop old) relies on — the real
/// `PUBLIC_KEYS` is a slice, exercised here through the anchor's OR-trust.
#[tokio::test]
async fn rotation_overlap_trusts_both_keys() {
    let _serial = SERIAL.lock().await;
    let key_a = trusted_key(); // "old" key
    let key_b = SigningKey::from_bytes(&[33u8; 32]); // "new" key
    fuz_crypto::clear_trusted_keys_for_testing();
    fuz_crypto::add_trusted_key_for_testing(&key_a.verifying_key());
    fuz_crypto::add_trusted_key_for_testing(&key_b.verifying_key());

    // Both trusted keys verify.
    for key in [&key_a, &key_b] {
        sign_manifest(
            sample_self_unsigned("0.3.0", None),
            key,
            "2025-01-15T10:30:00Z",
        )
        .unwrap()
        .verify_signature()
        .expect("a manifest signed by either trusted key must verify during rotation");
    }

    // A third, unregistered key is still rejected.
    let key_c = untrusted_key();
    assert!(matches!(
        sign_manifest(
            sample_self_unsigned("0.3.0", None),
            &key_c,
            "2025-01-15T10:30:00Z"
        )
        .unwrap()
        .verify_signature(),
        Err(ManifestError::Signature(_))
    ));

    fuz_crypto::clear_trusted_keys_for_testing();
}

/// Forensic attribution (TA.5): `VerifiedManifest::signed_by` must report the
/// key that ACTUALLY signed, not merely "some trusted key." With two keys
/// trusted at once (a rotation window), a manifest signed by B must verify *as*
/// B — so an audit log of "which embedded key signed this release" is correct.
/// `verify_signature` returns the pubkey carried in the signature after the
/// ed25519 check binds it to the bytes; a refactor that instead returned the
/// first `PUBLIC_KEYS` entry, or the wrong half of the pair, would misattribute
/// every release and is caught here. Complements
/// `rotation_overlap_trusts_both_keys` (which only asserts *that* either
/// verifies, not *which* signer is reported).
#[tokio::test]
async fn signed_by_reports_the_actual_signing_key() {
    let _serial = SERIAL.lock().await;
    let key_a = trusted_key();
    let key_b = SigningKey::from_bytes(&[33u8; 32]);
    fuz_crypto::clear_trusted_keys_for_testing();
    fuz_crypto::add_trusted_key_for_testing(&key_a.verifying_key());
    fuz_crypto::add_trusted_key_for_testing(&key_b.verifying_key());

    for key in [&key_a, &key_b] {
        let verified = sign_manifest(
            sample_self_unsigned("0.3.0", None),
            key,
            "2025-01-15T10:30:00Z",
        )
        .unwrap()
        .verify_signature()
        .expect("a manifest signed by a trusted key must verify");
        assert_eq!(
            verified.signed_by(),
            &key.verifying_key(),
            "signed_by must report the actual signer, not just any trusted key"
        );
    }

    fuz_crypto::clear_trusted_keys_for_testing();
}

/// Provenance gate: a validly-signed manifest whose declared `tool` doesn't
/// match the requested name must be rejected with `ToolManifestMismatch` —
/// even though its signature verifies against a trusted key. The name allowlist
/// gates the *requested* name; this catches a forge serving the wrong (but
/// genuinely signed) bundle at a tool's key — the **self** manifest masquerading
/// as a tool, or *another* tool's manifest. Without it, a key/path-confusion or
/// a compromised forge silently installs the wrong signed binary onto PATH.
#[tokio::test]
async fn fetch_tool_manifest_rejects_manifest_declaring_wrong_tool() {
    let _serial = SERIAL.lock().await;
    let key = trusted_key();
    trust_only(&key);

    let storage_dir = tempfile::tempdir().unwrap();
    let storage = FileStorage::new(storage_dir.path()).unwrap();
    let layout = ReleaseLayout::tool("fuzf");
    let manifest_key = layout.manifest_key("fuzf", "0.3.0", current_target());

    // Case A: a validly-signed SELF manifest (`tool: None`) served at fuzf's key.
    let self_manifest = sign_manifest(
        sample_self_unsigned("0.3.0", None),
        &key,
        "2025-01-15T10:30:00Z",
    )
    .unwrap();
    storage
        .upload(&manifest_key, &serde_json::to_vec(&self_manifest).unwrap())
        .await
        .unwrap();
    let err = fetch_tool_manifest(&storage, "fuzf", Some("0.3.0"))
        .await
        .expect_err("a self manifest served as a tool must be rejected");
    assert!(
        matches!(err, ReleaseError::ToolManifestMismatch { ref expected, actual: None } if expected == "fuzf"),
        "self-as-tool: got {err:?}"
    );

    // Case B: a validly-signed manifest declaring a *different* tool (`zap`).
    let zap_manifest = sign_manifest(
        sample_tool_unsigned("zap", "0.3.0"),
        &key,
        "2025-01-15T10:30:00Z",
    )
    .unwrap();
    storage
        .upload(&manifest_key, &serde_json::to_vec(&zap_manifest).unwrap())
        .await
        .unwrap();
    let err = fetch_tool_manifest(&storage, "fuzf", Some("0.3.0"))
        .await
        .expect_err("a zap manifest served as fuzf must be rejected");
    assert!(
        matches!(err, ReleaseError::ToolManifestMismatch { ref expected, ref actual } if expected == "fuzf" && actual.as_deref() == Some("zap")),
        "wrong-tool: got {err:?}"
    );

    fuz_crypto::clear_trusted_keys_for_testing();
}

/// Cache-hit integrity: a second `install_tool` for an already-present content
/// hash must re-hash the on-disk binaries and reject a tampered cache rather
/// than blindly relinking it onto PATH. Symmetric to the self path's
/// `verify_cached_artifact` tamper coverage — the tool cache-hit gate
/// (`ToolMeta::verify_binaries`) is the exact surface an attacker who swaps a
/// cached binary after first install would hit on the next install.
#[tokio::test]
async fn install_tool_cache_hit_rejects_tampered_binary() {
    let _serial = SERIAL.lock().await;
    let key = trusted_key();
    trust_only(&key);

    let _home = fresh_home();

    let storage_dir = tempfile::tempdir().unwrap();
    let storage = FileStorage::new(storage_dir.path()).unwrap();

    let bin_dir = tempfile::tempdir().unwrap();
    let bin_path = bin_dir.path().join("fuzf");
    std::fs::write(
        &bin_path,
        test_stubs::host(b"fuzf bytes -- cache tamper test"),
    )
    .unwrap();
    publish_tool(
        &storage,
        "fuzf",
        "0.1.0",
        &[("fuzf".to_string(), bin_path.clone())],
        &key,
        &PublishOptions::default(),
    )
    .await
    .unwrap();

    let result = install_tool(&storage, "fuzf", &ToolInstallOptions::default())
        .await
        .expect("first install must succeed");
    assert_eq!(result.outcome, ToolInstallOutcome::Installed);

    // Swap the cached binary, then re-install: the cache-hit re-verify must fire.
    std::fs::write(result.install_dir.join("fuzf"), b"malicious swapped bytes").unwrap();
    let err = install_tool(&storage, "fuzf", &ToolInstallOptions::default())
        .await
        .expect_err("a tampered cached binary must be rejected, not relinked");
    assert!(
        matches!(
            err,
            ReleaseError::Artifact(ArtifactError::BinaryIntegrityFailed { .. })
        ),
        "got {err:?}"
    );

    fuz_home::clear_fuz_home_override_for_testing();
    fuz_crypto::clear_trusted_keys_for_testing();
}

/// Symlink-chain correctness: `setup_tool_symlinks` must produce
/// `bin/<name>` → `../tools/<name>/current/<bin>` and `tools/<name>/current` →
/// `v1-<hash>` (a *relative* link, so the tree is relocatable), and the whole chain
/// must resolve to the installed binary's bytes. This load-bearing structure is
/// otherwise encoded only in a doc comment + path construction; a regression
/// (absolute target, wrong depth, pointing at `v1-<hash>` instead of `current`)
/// would dangle on PATH and the e2e suite — which only reads `current/meta.json`
/// — wouldn't catch it.
#[tokio::test]
async fn installed_tool_bin_link_resolves_through_current() {
    let _serial = SERIAL.lock().await;
    let _home = fresh_home();

    // Hand-place tools/fuzf/<hash>/fuzf, then link it the way install_tool does.
    let hash = "abc123def4567890";
    let install_dir = fuz_home::get_tool_dir("fuzf").unwrap().join(hash);
    std::fs::create_dir_all(&install_dir).unwrap();
    let bytes = b"fuzf binary bytes -- symlink chain";
    std::fs::write(install_dir.join("fuzf"), bytes).unwrap();

    setup_tool_symlinks("fuzf", hash, &["fuzf"]).unwrap();

    let bin_link = fuz_home::get_bin_dir().unwrap().join("fuzf");
    let expected_bin_target = Path::new("..")
        .join(fuz_home::TOOLS_DIR)
        .join("fuzf")
        .join(fuz_home::CURRENT_LINK)
        .join("fuzf");
    assert_eq!(
        std::fs::read_link(&bin_link).unwrap(),
        expected_bin_target,
        "bin link must be relative and route through `current`"
    );
    assert_eq!(
        std::fs::read_link(fuz_home::get_tool_current_link("fuzf").unwrap()).unwrap(),
        Path::new(hash),
        "current must be a relative link to <hash>"
    );
    // Following the whole chain resolves to the binary bytes.
    assert_eq!(std::fs::read(&bin_link).unwrap(), bytes);

    fuz_home::clear_fuz_home_override_for_testing();
}

/// The self-artifact symlink pass is fuz-only and must NOT clobber a
/// separately-installed `bin/fuzd` (owned by `fuz tool install fuzd`). The
/// guarantee rests entirely on `SELF_BINARIES = &["fuz"]` excluding `fuzd` from
/// the stale-cleanup pass; a future edit re-adding `fuzd` there would silently
/// uninstall it on every `fuz artifact build` / `fuz artifact use` /
/// `fuz self upgrade`. This pins that regression trap.
#[tokio::test]
async fn self_symlinks_preserve_separately_installed_fuzd() {
    let _serial = SERIAL.lock().await;
    let _home = fresh_home();

    let bin_dir = fuz_home::get_bin_dir().unwrap();
    std::fs::create_dir_all(&bin_dir).unwrap();
    // A separately-installed fuzd link, as the per-tool install path creates it.
    let fuzd_link = bin_dir.join("fuzd");
    let fuzd_target = Path::new("..")
        .join(fuz_home::TOOLS_DIR)
        .join("fuzd")
        .join(fuz_home::CURRENT_LINK)
        .join("fuzd");
    std::os::unix::fs::symlink(&fuzd_target, &fuzd_link).unwrap();

    // The fuz-only self-artifact symlink pass.
    setup_bin_symlinks(&["fuz"]).unwrap();

    assert_eq!(
        std::fs::read_link(&fuzd_link).unwrap(),
        fuzd_target,
        "the self-artifact symlink pass must not touch bin/fuzd"
    );
    assert_eq!(
        std::fs::read_link(bin_dir.join("fuz")).unwrap(),
        Path::new("..").join("current").join("fuz"),
        "bin/fuz must be (re)linked through current"
    );

    fuz_home::clear_fuz_home_override_for_testing();
}

/// `verify_installed_tool` reports the actionable `ToolNotInstalled` (not an
/// opaque IO/meta-read error) when there's no `current` link for the tool.
#[tokio::test]
async fn verify_installed_tool_reports_not_installed() {
    let _serial = SERIAL.lock().await;
    let _home = fresh_home();

    let err = verify_installed_tool("fuzf").expect_err("an uninstalled tool must error");
    assert!(
        matches!(err, ReleaseError::ToolNotInstalled(ref n) if n == "fuzf"),
        "got {err:?}"
    );

    fuz_home::clear_fuz_home_override_for_testing();
}

/// Seed a current self artifact at `version` so `fetch_version`'s on-disk
/// version check has a real "current" to compare against. Writes the binary +
/// meta under `<home>/artifacts/v1-<hash>/` and points the `current` symlink at it
/// (the same relative shape `switch_current` produces).
fn seed_current(home: &Path, version: &str, content: &[u8]) -> ArtifactMeta {
    let outputs = ArtifactOutputs {
        fuz: ContentHash::blake3(content),
    };
    let meta = ArtifactMeta::new_remote(outputs.content_hash(), version.to_string(), outputs);
    let dir = home.join("artifacts").join(&meta.hash);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("fuz"), content).unwrap();
    meta.write(&dir).unwrap();
    std::os::unix::fs::symlink(format!("artifacts/{}", meta.hash), home.join("current")).unwrap();
    meta
}

/// The self-side mirror of `fetch_tool_manifest_rejects_manifest_declaring_wrong_tool`:
/// the self-artifact fetch path (`fuz self upgrade`) must reject a manifest that
/// declares a `tool` — even one validly signed by a trusted key — rather than
/// install a per-tool bundle as the fuz self artifact. `validate()` can't catch
/// this: it's shared with the tool path, which legitimately sets `tool`, so the
/// self callsite enforces `tool: None`. Without the guard a key/path confusion or
/// a compromised forge that placed a signed tool manifest at the self key would
/// be installed as fuz itself.
#[tokio::test]
async fn fetch_version_rejects_tool_manifest_at_self_key() {
    let _serial = SERIAL.lock().await;
    let key = trusted_key();
    trust_only(&key);

    let _home = fresh_home();

    let storage_dir = tempfile::tempdir().unwrap();
    let storage = FileStorage::new(storage_dir.path()).unwrap();

    // A validly-signed *tool* manifest (`tool: Some("zap")`) uploaded at the
    // *self* artifact key.
    let layout = ReleaseLayout::self_artifact();
    let manifest_key = layout.manifest_key("fuz", "0.5.0", current_target());
    let tool_manifest = sign_manifest(
        sample_tool_unsigned("zap", "0.5.0"),
        &key,
        "2025-01-15T10:30:00Z",
    )
    .unwrap();
    storage
        .upload(&manifest_key, &serde_json::to_vec(&tool_manifest).unwrap())
        .await
        .unwrap();

    let err = fetch_version(&storage, "0.5.0", &FetchOptions::default())
        .await
        .expect_err("a tool manifest at the self key must be rejected");
    assert!(
        matches!(
            err,
            ReleaseError::Manifest(ManifestError::UnexpectedTool(ref t)) if t == "zap"
        ),
        "got {err:?}"
    );

    fuz_home::clear_fuz_home_override_for_testing();
    fuz_crypto::clear_trusted_keys_for_testing();
}

/// The real no-downgrade guard through `fetch_version` (the existing min-version
/// test only exercises `BelowMinimum` against an empty 0.0.0 home). With a 0.5.0
/// artifact installed as current, fetching 0.4.0 is refused as a `Downgrade` by
/// default; `allow_downgrade: true` waives it and the older version installs.
#[tokio::test]
async fn fetch_version_refuses_real_downgrade_unless_allowed() {
    let _serial = SERIAL.lock().await;
    let key = trusted_key();
    trust_only(&key);

    let home = fresh_home();
    // Current is a real 0.5.0 artifact, so the downgrade comparison has teeth.
    seed_current(home.path(), "0.5.0", b"fuz bytes -- current 0.5.0");

    let storage_dir = tempfile::tempdir().unwrap();
    let storage = FileStorage::new(storage_dir.path()).unwrap();
    let artifact_dir = tempfile::tempdir().unwrap();
    let meta = make_self_artifact(
        artifact_dir.path(),
        "0.4.0",
        &test_stubs::host(b"fuz bytes -- older 0.4.0"),
    );
    publish_artifact(
        &storage,
        &meta,
        artifact_dir.path(),
        &key,
        &PublishOptions::default(),
    )
    .await
    .unwrap();

    // Default: 0.4.0 < current 0.5.0 → refused as a downgrade.
    let err = fetch_version(&storage, "0.4.0", &FetchOptions::default())
        .await
        .expect_err("a real downgrade must be refused by default");
    assert!(
        matches!(err, ReleaseError::Manifest(ManifestError::Downgrade { .. })),
        "got {err:?}"
    );

    // allow_downgrade waives the monotonicity guard → the older version installs.
    let result = fetch_version(
        &storage,
        "0.4.0",
        &FetchOptions {
            allow_downgrade: true,
            force: false,
            ..Default::default()
        },
    )
    .await
    .expect("allow_downgrade must permit the older version");
    assert_eq!(result.version, "0.4.0");

    fuz_home::clear_fuz_home_override_for_testing();
    fuz_crypto::clear_trusted_keys_for_testing();
}

/// The tool install path enforces the trust anchor, not just the self path: a
/// per-tool manifest signed by an *untrusted* key (and otherwise valid) must be
/// rejected with a signature error rather than installed onto PATH.
#[tokio::test]
async fn install_tool_rejects_untrusted_signing_key() {
    let _serial = SERIAL.lock().await;
    // Trust only the good key; publish the tool signed by a key we never register.
    trust_only(&trusted_key());

    let _home = fresh_home();

    let storage_dir = tempfile::tempdir().unwrap();
    let storage = FileStorage::new(storage_dir.path()).unwrap();

    let bin_dir = tempfile::tempdir().unwrap();
    let bin_path = bin_dir.path().join("fuzf");
    std::fs::write(&bin_path, test_stubs::host(b"fuzf bytes -- untrusted key")).unwrap();
    publish_tool(
        &storage,
        "fuzf",
        "0.1.0",
        &[("fuzf".to_string(), bin_path.clone())],
        &untrusted_key(),
        &PublishOptions::default(),
    )
    .await
    .unwrap();

    let err = install_tool(&storage, "fuzf", &ToolInstallOptions::default())
        .await
        .expect_err("a tool signed by an untrusted key must be rejected");
    assert!(
        matches!(err, ReleaseError::Manifest(ManifestError::Signature(_))),
        "got {err:?}"
    );

    fuz_home::clear_fuz_home_override_for_testing();
    fuz_crypto::clear_trusted_keys_for_testing();
}

/// A malformed the latest pointer surfaces as a storage-layer error (the
/// download/parse mapping), not a panic or a silent success — the resolution
/// step `fetch_latest` does before any manifest work.
#[tokio::test]
async fn fetch_latest_rejects_malformed_latest_json() {
    let _serial = SERIAL.lock().await;
    trust_only(&trusted_key());

    let _home = fresh_home();

    let storage_dir = tempfile::tempdir().unwrap();
    let storage = FileStorage::new(storage_dir.path()).unwrap();

    // Garbage where the version-resolution JSON should be.
    let latest_key = ReleaseLayout::self_artifact().latest_key(current_target());
    storage
        .upload(&latest_key, b"this is not json")
        .await
        .unwrap();

    let err = fetch_latest(&storage, &FetchOptions::default())
        .await
        .expect_err("a malformed latest pointer must error, not succeed");
    assert!(
        matches!(
            err,
            ReleaseError::Storage(StorageError::DownloadFailed { .. })
        ),
        "got {err:?}"
    );

    fuz_home::clear_fuz_home_override_for_testing();
    fuz_crypto::clear_trusted_keys_for_testing();
}

/// The read-only self seam behind `fuz self upgrade --check`: `fetch_latest_manifest`
/// resolves + downloads + signature-verifies the latest self manifest and stops
/// — returning the **signed** version, and mutating nothing under `~/.fuz` (no
/// artifacts dir, no cache, no lock). The `--check` security contract: report
/// the signed `manifest.version`, install nothing.
#[tokio::test]
async fn fetch_latest_manifest_verifies_and_touches_no_home() {
    let _serial = SERIAL.lock().await;
    let key = trusted_key();
    trust_only(&key);

    let home = fresh_home();

    let storage_dir = tempfile::tempdir().unwrap();
    let storage = FileStorage::new(storage_dir.path()).unwrap();

    let artifact_dir = tempfile::tempdir().unwrap();
    let meta = make_self_artifact(
        artifact_dir.path(),
        "0.6.0",
        &test_stubs::host(b"fuz bytes -- check seam"),
    );
    publish_artifact(
        &storage,
        &meta,
        artifact_dir.path(),
        &key,
        &PublishOptions::default(),
    )
    .await
    .unwrap();

    let manifest = fetch_latest_manifest(&storage)
        .await
        .expect("fetch_latest_manifest must resolve + verify the latest self manifest");
    // The signed version — the only trustworthy version string.
    assert_eq!(manifest.version, "0.6.0");
    assert!(
        manifest.tool.is_none(),
        "the self manifest declares no tool"
    );

    // Mutated nothing under ~/.fuz: no artifacts dir, no `current`, no download temp.
    assert!(
        !home.path().join("artifacts").exists(),
        "a read-only check must not create the artifacts dir"
    );
    assert!(!home.path().join("current").exists());

    fuz_home::clear_fuz_home_override_for_testing();
    fuz_crypto::clear_trusted_keys_for_testing();
}

/// Publish `fuzf` at `version` with `bytes` (distinct bytes → distinct content
/// hash) and an optional `minimum_version`. A per-version source file keeps the
/// tarballs (and thus the install dirs) distinct across a downgrade sequence.
async fn publish_tool_version(
    storage: &FileStorage,
    key: &SigningKey,
    bin_dir: &Path,
    version: &str,
    bytes: &[u8],
    minimum_version: Option<&str>,
) {
    let bin_path = bin_dir.join(format!("fuzf-{version}"));
    std::fs::write(&bin_path, bytes).unwrap();
    let options = PublishOptions {
        minimum_version: minimum_version.map(String::from),
        ..PublishOptions::default()
    };
    publish_tool(
        storage,
        "fuzf",
        version,
        &[("fuzf".to_string(), bin_path)],
        key,
        &options,
    )
    .await
    .unwrap();
}

/// The per-tool install path enforces version safety symmetric with the
/// self path (`fetch_version`). An explicit `--version <older>` over a newer
/// install is a downgrade — blocked by default, permitted with
/// `allow_downgrade`. (A fresh install of any version is allowed, covered by
/// the other install tests.)
#[tokio::test]
async fn install_tool_blocks_downgrade_unless_allowed() {
    let _serial = SERIAL.lock().await;
    let key = trusted_key();
    trust_only(&key);

    let _home = fresh_home();

    let storage_dir = tempfile::tempdir().unwrap();
    let storage = FileStorage::new(storage_dir.path()).unwrap();
    let bin_dir = tempfile::tempdir().unwrap();

    // Install 0.5.0 → current is 0.5.0.
    publish_tool_version(
        &storage,
        &key,
        bin_dir.path(),
        "0.5.0",
        &test_stubs::host(b"fuzf 0.5.0 bytes"),
        None,
    )
    .await;
    let installed = install_tool(
        &storage,
        "fuzf",
        &ToolInstallOptions {
            version: Some("0.5.0"),
            ..Default::default()
        },
    )
    .await
    .expect("fresh install of 0.5.0 must succeed");
    assert_eq!(installed.version, "0.5.0");

    // Publish an older 0.3.0 (distinct bytes → distinct content hash).
    publish_tool_version(
        &storage,
        &key,
        bin_dir.path(),
        "0.3.0",
        &test_stubs::host(b"fuzf 0.3.0 bytes"),
        None,
    )
    .await;

    // Downgrade to 0.3.0 is blocked by default...
    let err = install_tool(
        &storage,
        "fuzf",
        &ToolInstallOptions {
            version: Some("0.3.0"),
            ..Default::default()
        },
    )
    .await
    .expect_err("an explicit downgrade must be blocked without allow_downgrade");
    assert!(
        matches!(err, ReleaseError::Manifest(ManifestError::Downgrade { .. })),
        "got {err:?}"
    );

    // ...and permitted with allow_downgrade.
    let downgraded = install_tool(
        &storage,
        "fuzf",
        &ToolInstallOptions {
            version: Some("0.3.0"),
            allow_downgrade: true,
            ..Default::default()
        },
    )
    .await
    .expect("allow_downgrade must permit the older version");
    assert_eq!(downgraded.version, "0.3.0");

    fuz_home::clear_fuz_home_override_for_testing();
    fuz_crypto::clear_trusted_keys_for_testing();
}

/// The publisher's `minimum_version` floor is enforced by the tool install
/// path even with `allow_downgrade` — the same contract the self path carries
/// (`fetch_version_enforces_minimum_even_with_allow_downgrade`), on the
/// **upgrade path**. Install a 0.4.0 base, then a 0.5.0 release demanding minimum
/// 0.5.0 is refused whether or not `allow_downgrade` is set. (A *fresh* install
/// is exempt — see `fresh_tool_install_below_minimum_succeeds`.)
#[tokio::test]
async fn install_tool_enforces_minimum_even_with_allow_downgrade() {
    let _serial = SERIAL.lock().await;
    let key = trusted_key();
    trust_only(&key);

    let _home = fresh_home();

    let storage_dir = tempfile::tempdir().unwrap();
    let storage = FileStorage::new(storage_dir.path()).unwrap();
    let bin_dir = tempfile::tempdir().unwrap();

    // Install a 0.4.0 base (no floor) → current is 0.4.0, an installed version
    // below the floor the next release will demand.
    publish_tool_version(
        &storage,
        &key,
        bin_dir.path(),
        "0.4.0",
        &test_stubs::host(b"fuzf 0.4.0 bytes"),
        None,
    )
    .await;
    install_tool(
        &storage,
        "fuzf",
        &ToolInstallOptions {
            version: Some("0.4.0"),
            ..Default::default()
        },
    )
    .await
    .expect("base install of 0.4.0 must succeed");

    // A 0.5.0 release demanding a minimum the installed 0.4.0 can't meet.
    publish_tool_version(
        &storage,
        &key,
        bin_dir.path(),
        "0.5.0",
        &test_stubs::host(b"fuzf 0.5.0 bytes"),
        Some("0.5.0"),
    )
    .await;

    // Default and allow_downgrade both refused: the floor holds on the upgrade
    // path and `allow_downgrade` never waives it.
    for allow_downgrade in [false, true] {
        let err = install_tool(
            &storage,
            "fuzf",
            &ToolInstallOptions {
                version: Some("0.5.0"),
                allow_downgrade,
                ..Default::default()
            },
        )
        .await
        .expect_err("the minimum floor must hold on the upgrade path");
        assert!(
            matches!(
                err,
                ReleaseError::Manifest(ManifestError::BelowMinimum { .. })
            ),
            "allow_downgrade={allow_downgrade}: got {err:?}"
        );
    }

    fuz_home::clear_fuz_home_override_for_testing();
    fuz_crypto::clear_trusted_keys_for_testing();
}

/// The bug guard for the fresh-install fix: a **first** `fuz tool install` of a
/// release that declares a `minimum_version` must succeed. Nothing is installed
/// (`current == None`), so the floor — which gates an *upgrade* path — does not
/// apply; treating the absent version as `0.0.0` would make any tool that ever
/// sets a minimum uninstallable from scratch. The signature + blake3 pins still
/// verify (it is the real signed-trust path), only the version floor is skipped.
#[tokio::test]
async fn fresh_tool_install_below_minimum_succeeds() {
    let _serial = SERIAL.lock().await;
    let key = trusted_key();
    trust_only(&key);

    let _home = fresh_home(); // empty → nothing installed (None)

    let storage_dir = tempfile::tempdir().unwrap();
    let storage = FileStorage::new(storage_dir.path()).unwrap();
    let bin_dir = tempfile::tempdir().unwrap();

    // A first release that already declares a floor far above 0.0.0.
    publish_tool_version(
        &storage,
        &key,
        bin_dir.path(),
        "0.5.0",
        &test_stubs::host(b"fuzf 0.5.0 bytes -- fresh below-min"),
        Some("0.5.0"),
    )
    .await;

    // Fresh install must land despite the floor, and verify clean end to end.
    let installed = install_tool(&storage, "fuzf", &ToolInstallOptions::default())
        .await
        .expect("a fresh install of a min-gated release must succeed");
    assert_eq!(installed.version, "0.5.0");
    verify_installed_tool("fuzf").expect("the fresh install must verify against its meta");

    fuz_home::clear_fuz_home_override_for_testing();
    fuz_crypto::clear_trusted_keys_for_testing();
}

/// The corrupt-state policy: an install over an **unreadable** current install is
/// refused loud by default (no silent swallow-to-fresh), and `--force`
/// reinstalls over it (self-heal), surfacing the reason. Drives the real
/// `install_tool` path end to end.
#[tokio::test]
async fn install_tool_refuses_unreadable_current_unless_forced() {
    let _serial = SERIAL.lock().await;
    let key = trusted_key();
    trust_only(&key);

    let _home = fresh_home();

    let storage_dir = tempfile::tempdir().unwrap();
    let storage = FileStorage::new(storage_dir.path()).unwrap();
    let bin_dir = tempfile::tempdir().unwrap();

    // Install a 0.4.0 base, then corrupt its `current/meta.json`.
    publish_tool_version(
        &storage,
        &key,
        bin_dir.path(),
        "0.4.0",
        &test_stubs::host(b"fuzf 0.4.0 bytes"),
        None,
    )
    .await;
    install_tool(
        &storage,
        "fuzf",
        &ToolInstallOptions {
            version: Some("0.4.0"),
            ..Default::default()
        },
    )
    .await
    .expect("base install must succeed");
    let current = fuz_home::get_tool_current_link("fuzf").unwrap();
    std::fs::write(current.join("meta.json"), b"not valid json").unwrap();

    // A newer release to install over the corrupt state.
    publish_tool_version(
        &storage,
        &key,
        bin_dir.path(),
        "0.5.0",
        &test_stubs::host(b"fuzf 0.5.0 bytes"),
        None,
    )
    .await;

    // Without --force: refused loud (not silently treated as a fresh install).
    let err = install_tool(&storage, "fuzf", &ToolInstallOptions::default())
        .await
        .expect_err("an unreadable current install must be refused without --force");
    assert!(
        matches!(err, ReleaseError::CurrentUnreadable { .. }),
        "got {err:?}"
    );

    // With --force: reinstalls (self-heal), reports the repaired reason, verifies.
    let result = install_tool(
        &storage,
        "fuzf",
        &ToolInstallOptions {
            force: true,
            ..Default::default()
        },
    )
    .await
    .expect("--force must reinstall over the unreadable state");
    assert_eq!(result.version, "0.5.0");
    assert!(
        result.repaired_unreadable.is_some(),
        "a forced repair must report why the state was unreadable"
    );
    verify_installed_tool("fuzf").expect("the repaired install must verify");

    fuz_home::clear_fuz_home_override_for_testing();
    fuz_crypto::clear_trusted_keys_for_testing();
}

/// The world-writable `~/.fuz` refusal with a **viable install behind it**: a
/// validly signed release is published and everything else about the flow works,
/// so the only thing standing between `install_tool` and a fresh binary on PATH
/// is the home's mode. That is what makes "nothing landed" meaningful — the
/// refusal test in `fuz_release`'s `insecure_home` suite runs against empty
/// storage, where the flow would abort anyway. Restoring `0700` and re-running
/// the same install proves the fixture was otherwise sound: drop the guard from
/// `install_tool` and the first leg installs instead of erroring.
#[tokio::test]
async fn install_tool_refuses_world_writable_home_and_installs_when_fixed() {
    let _serial = SERIAL.lock().await;
    let key = trusted_key();
    trust_only(&key);

    let home = fresh_home();

    let storage_dir = tempfile::tempdir().unwrap();
    let storage = FileStorage::new(storage_dir.path()).unwrap();

    let bin_dir = tempfile::tempdir().unwrap();
    let bin_path = bin_dir.path().join("fuzf");
    let content: &[u8] = &test_stubs::host(b"fuzf binary bytes -- world-writable home");
    std::fs::write(&bin_path, content).unwrap();
    publish_tool(
        &storage,
        "fuzf",
        "0.1.0",
        &[("fuzf".to_string(), bin_path.clone())],
        &key,
        &PublishOptions::default(),
    )
    .await
    .unwrap();

    // Any local user can write this home — refuse, and install nothing into it.
    std::fs::set_permissions(home.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
    let err = install_tool(&storage, "fuzf", &ToolInstallOptions::default())
        .await
        .expect_err("a world-writable home must refuse an otherwise-viable install");
    assert!(
        matches!(
            err,
            ReleaseError::FuzHome(fuz_home::FuzHomeError::InsecureHome { mode: 0o777, .. })
        ),
        "got {err:?}"
    );

    // Nothing landed: no tool tree, no PATH link, and the registry agrees.
    let entries: Vec<_> = std::fs::read_dir(home.path())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert!(
        entries.is_empty(),
        "a refused install must write nothing under the home, found {entries:?}"
    );
    assert!(matches!(
        verify_installed_tool("fuzf"),
        Err(ReleaseError::ToolNotInstalled(_))
    ));

    // Fix the mode and the exact same install succeeds — so the refusal above
    // was the guard, not a broken fixture.
    std::fs::set_permissions(home.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let result = install_tool(&storage, "fuzf", &ToolInstallOptions::default())
        .await
        .expect("a 0700 home must install the same release cleanly");
    assert_eq!(result.version, "0.1.0");
    assert!(result.install_dir.starts_with(home.path()));
    assert_eq!(
        std::fs::read(result.install_dir.join("fuzf")).unwrap(),
        content
    );
    verify_installed_tool("fuzf").expect("the install must verify against its meta");

    fuz_home::clear_fuz_home_override_for_testing();
    fuz_crypto::clear_trusted_keys_for_testing();
}

/// Pins the self-upgrade cache hit against a symlink at `artifacts/v1-<hash>/`:
/// a **live** link (aimed at a valid artifact, so it verifies if read through)
/// is not a cache hit, and a **dangling** one is not read as absent and then
/// renamed onto (`ENOTDIR` on every run). Either way the entry — never its
/// target — is unlinked and the artifact is downloaded fresh into a real
/// directory. Fails if the cache-hit check follows the link.
#[tokio::test]
async fn fetch_replaces_a_symlink_at_the_cached_artifact_dir() {
    let _serial = SERIAL.lock().await;
    let key = trusted_key();
    trust_only(&key);
    let home = fresh_home();

    let storage_dir = tempfile::tempdir().unwrap();
    let storage = FileStorage::new(storage_dir.path()).unwrap();
    let artifact_dir = tempfile::tempdir().unwrap();
    let content: &[u8] = &test_stubs::host(b"fuz binary bytes -- cache slot symlink");
    let meta = make_self_artifact(artifact_dir.path(), "0.5.0", content);
    publish_artifact(
        &storage,
        &meta,
        artifact_dir.path(),
        &key,
        &PublishOptions::default(),
    )
    .await
    .unwrap();

    let first = fetch_latest(&storage, &FetchOptions::default())
        .await
        .unwrap();
    let slot = first.artifact_dir.clone();

    // Live link to a valid copy of the artifact.
    let decoy = home.path().join("decoy");
    std::fs::rename(&slot, &decoy).unwrap();
    std::os::unix::fs::symlink(&decoy, &slot).unwrap();
    let again = fetch_latest(&storage, &FetchOptions::default())
        .await
        .expect("a symlinked cache slot is re-downloaded, not an error");
    assert!(!again.cache_hit, "a symlink is never a cache hit");
    assert!(
        std::fs::symlink_metadata(&slot)
            .unwrap()
            .file_type()
            .is_dir(),
        "the artifact is a real directory again"
    );
    assert_eq!(std::fs::read(slot.join("fuz")).unwrap(), content);
    assert_eq!(
        std::fs::read(decoy.join("fuz")).unwrap(),
        content,
        "the link's target is untouched"
    );

    // Dangling link.
    std::fs::remove_dir_all(&slot).unwrap();
    std::os::unix::fs::symlink(home.path().join("nowhere"), &slot).unwrap();
    let again = fetch_latest(&storage, &FetchOptions::default())
        .await
        .expect("a dangling cache slot is re-downloaded, not ENOTDIR");
    assert!(!again.cache_hit);
    assert!(
        std::fs::symlink_metadata(&slot)
            .unwrap()
            .file_type()
            .is_dir()
    );
    assert!(!home.path().join("nowhere").exists());

    fuz_home::clear_fuz_home_override_for_testing();
    fuz_crypto::clear_trusted_keys_for_testing();
}

/// Pins `install_tool` against a symlink at `tools/<name>/v1-<hash>/`, the slot
/// `current` names: a **live** link (aimed at a valid install) is not taken as
/// already installed and relinked onto, and a **dangling** one does not fail
/// the staging rename with `ENOTDIR`. The version resolver reads either as an
/// unreadable current install, so the reinstall is `--force`d; the entry —
/// never its target — is unlinked and the tool downloads fresh into a real
/// directory. Fails if the on-disk check follows the link.
#[tokio::test]
async fn install_tool_replaces_a_symlink_at_the_install_dir() {
    let _serial = SERIAL.lock().await;
    let key = trusted_key();
    trust_only(&key);
    let home = fresh_home();

    let storage_dir = tempfile::tempdir().unwrap();
    let storage = FileStorage::new(storage_dir.path()).unwrap();
    let bin_dir = tempfile::tempdir().unwrap();
    let bin_path = bin_dir.path().join("fuzf");
    let content: &[u8] = &test_stubs::host(b"fuzf bytes -- install slot symlink");
    std::fs::write(&bin_path, content).unwrap();
    publish_tool(
        &storage,
        "fuzf",
        "0.1.0",
        &[("fuzf".to_string(), bin_path.clone())],
        &key,
        &PublishOptions::default(),
    )
    .await
    .unwrap();

    let first = install_tool(&storage, "fuzf", &ToolInstallOptions::default())
        .await
        .unwrap();
    let slot = first.install_dir.clone();
    let force = ToolInstallOptions {
        force: true,
        ..ToolInstallOptions::default()
    };

    // Live link: refused as unreadable without --force, repaired with it.
    let decoy = home.path().join("decoy");
    std::fs::rename(&slot, &decoy).unwrap();
    std::os::unix::fs::symlink(&decoy, &slot).unwrap();
    let err = install_tool(&storage, "fuzf", &ToolInstallOptions::default())
        .await
        .expect_err("a symlinked current install is unreadable without --force");
    assert!(
        matches!(err, ReleaseError::CurrentUnreadable { .. }),
        "got {err:?}"
    );
    let again = install_tool(&storage, "fuzf", &force)
        .await
        .expect("a symlinked install dir is replaced under --force");
    assert_eq!(again.outcome, ToolInstallOutcome::Installed);
    assert!(again.repaired_unreadable.is_some());
    assert!(
        std::fs::symlink_metadata(&slot)
            .unwrap()
            .file_type()
            .is_dir(),
        "the install is a real directory again"
    );
    assert_eq!(std::fs::read(slot.join("fuzf")).unwrap(), content);
    assert_eq!(
        std::fs::read(decoy.join("fuzf")).unwrap(),
        content,
        "the link's target is untouched"
    );
    verify_installed_tool("fuzf").expect("the reinstalled tool verifies");

    // Dangling link.
    std::fs::remove_dir_all(&slot).unwrap();
    std::os::unix::fs::symlink(home.path().join("nowhere"), &slot).unwrap();
    let again = install_tool(&storage, "fuzf", &force)
        .await
        .expect("a dangling install dir is replaced, not ENOTDIR");
    assert_eq!(again.outcome, ToolInstallOutcome::Installed);
    assert!(
        std::fs::symlink_metadata(&slot)
            .unwrap()
            .file_type()
            .is_dir()
    );
    assert!(!home.path().join("nowhere").exists());
    verify_installed_tool("fuzf").expect("the reinstalled tool verifies");

    fuz_home::clear_fuz_home_override_for_testing();
    fuz_crypto::clear_trusted_keys_for_testing();
}

/// Pins `install_tool` against a tool `current` fuz did not write. A real
/// directory there can't be swapped for a link (`EISDIR`), so it is refused —
/// with or without `--force`, before any request — and left in place. A link
/// pointing outside the tool's store reads as an unreadable install: refused
/// without `--force`, repaired with it (the link is replaced by one into the
/// store).
#[tokio::test]
async fn install_tool_refuses_or_repairs_a_current_fuz_did_not_write() {
    let _serial = SERIAL.lock().await;
    let key = trusted_key();
    trust_only(&key);
    let home = fresh_home();

    let storage_dir = tempfile::tempdir().unwrap();
    let storage = FileStorage::new(storage_dir.path()).unwrap();
    let bin_dir = tempfile::tempdir().unwrap();
    let bin_path = bin_dir.path().join("fuzf");
    std::fs::write(
        &bin_path,
        test_stubs::host(b"fuzf bytes -- foreign current"),
    )
    .unwrap();
    publish_tool(
        &storage,
        "fuzf",
        "0.1.0",
        &[("fuzf".to_string(), bin_path.clone())],
        &key,
        &PublishOptions::default(),
    )
    .await
    .unwrap();
    let first = install_tool(&storage, "fuzf", &ToolInstallOptions::default())
        .await
        .unwrap();
    let current = fuz_home::get_tool_current_link("fuzf").unwrap();
    let force = ToolInstallOptions {
        force: true,
        ..ToolInstallOptions::default()
    };

    // A link outside the store, at a valid copy of the install — in a directory
    // named like the hash, so only the store check (not the final component)
    // tells it from the install.
    let outside = home.path().join("elsewhere").join(&first.content_hash);
    std::fs::create_dir_all(&outside).unwrap();
    for file in ["fuzf", "meta.json"] {
        std::fs::copy(first.install_dir.join(file), outside.join(file)).unwrap();
    }
    std::fs::remove_file(&current).unwrap();
    std::os::unix::fs::symlink(&outside, &current).unwrap();
    let err = install_tool(&storage, "fuzf", &ToolInstallOptions::default())
        .await
        .expect_err("a current outside the store is unreadable without --force");
    assert!(
        matches!(err, ReleaseError::CurrentUnreadable { .. }),
        "got {err:?}"
    );
    let repaired = install_tool(&storage, "fuzf", &force)
        .await
        .expect("--force repairs a current outside the store");
    assert!(repaired.repaired_unreadable.is_some());
    assert_eq!(
        repaired.outcome,
        ToolInstallOutcome::Relinked { previous: None },
        "a current outside the store names no hash, so the relink is a change"
    );
    assert_eq!(
        std::fs::read_link(&current).unwrap(),
        Path::new(&first.content_hash),
        "current points into the store again"
    );
    assert!(
        outside.join("fuzf").is_file(),
        "the old target is untouched"
    );

    // A real directory at `current`.
    std::fs::remove_file(&current).unwrap();
    std::fs::rename(&outside, &current).unwrap();
    for options in [&ToolInstallOptions::default(), &force] {
        let err = install_tool(&storage, "fuzf", options)
            .await
            .expect_err("a current directory is refused");
        assert!(
            matches!(
                &err,
                ReleaseError::Artifact(ArtifactError::CurrentNotStoreLink {
                    problem: fuz_artifact::CurrentLinkProblem::NotASymlink,
                    ..
                })
            ),
            "force={}: refused, not EISDIR: {err:?}",
            options.force
        );
    }
    assert!(current.join("fuzf").is_file(), "left in place");

    fuz_home::clear_fuz_home_override_for_testing();
    fuz_crypto::clear_trusted_keys_for_testing();
}

/// Pins the self-upgrade fetch over an unreadable current install of the new
/// shapes — here `current` names an artifact whose directory is a symlink:
/// refused without `--force`, and with it the slot is reclaimed, the artifact
/// re-downloaded into a real directory, and the repair reported.
#[tokio::test]
async fn fetch_force_repairs_a_current_behind_a_symlinked_artifact() {
    let _serial = SERIAL.lock().await;
    let key = trusted_key();
    trust_only(&key);
    let home = fresh_home();

    let storage_dir = tempfile::tempdir().unwrap();
    let storage = FileStorage::new(storage_dir.path()).unwrap();
    let artifact_dir = tempfile::tempdir().unwrap();
    let content: &[u8] = &test_stubs::host(b"fuz binary bytes -- forced repair");
    let meta = make_self_artifact(artifact_dir.path(), "0.5.0", content);
    publish_artifact(
        &storage,
        &meta,
        artifact_dir.path(),
        &key,
        &PublishOptions::default(),
    )
    .await
    .unwrap();
    let first = fetch_latest(&storage, &FetchOptions::default())
        .await
        .unwrap();
    fuz_artifact::switch_current(&first.content_hash).unwrap();

    let slot = first.artifact_dir.clone();
    let decoy = home.path().join("decoy");
    std::fs::rename(&slot, &decoy).unwrap();
    std::os::unix::fs::symlink(&decoy, &slot).unwrap();

    let err = fetch_latest(&storage, &FetchOptions::default())
        .await
        .expect_err("an unreadable current is refused without --force");
    assert!(
        matches!(err, ReleaseError::CurrentUnreadable { .. }),
        "got {err:?}"
    );
    let repaired = fetch_latest(
        &storage,
        &FetchOptions {
            force: true,
            ..FetchOptions::default()
        },
    )
    .await
    .expect("--force repairs it");
    assert!(repaired.repaired_unreadable.is_some());
    assert!(!repaired.cache_hit);
    assert!(
        std::fs::symlink_metadata(&slot)
            .unwrap()
            .file_type()
            .is_dir()
    );
    assert_eq!(std::fs::read(decoy.join("fuz")).unwrap(), content);

    fuz_home::clear_fuz_home_override_for_testing();
    fuz_crypto::clear_trusted_keys_for_testing();
}

/// Pins that a trusted-key-signed manifest whose `content_hash` is a path
/// (`../victim`) is refused at parse — before the install slot it would name is
/// touched — on both the self-upgrade fetch and the tool install, and that a
/// file at the path it names survives. The slot is reclaimed (a non-directory
/// unlinked) before the download that verifies the hash, so without the check
/// the victim would be deleted. The victims are scratch files inside this
/// test's temp home.
#[tokio::test]
async fn a_signed_manifest_with_a_path_for_a_content_hash_is_refused() {
    let _serial = SERIAL.lock().await;
    let key = trusted_key();
    trust_only(&key);
    let home = fresh_home();
    let storage_dir = tempfile::tempdir().unwrap();
    let storage = FileStorage::new(storage_dir.path()).unwrap();

    // Self: `artifacts/../victim` is `<home>/victim`.
    std::fs::create_dir(home.path().join("artifacts")).unwrap();
    let self_victim = home.path().join("victim");
    std::fs::write(&self_victim, b"keep").unwrap();
    let mut unsigned = sample_self_unsigned("0.5.0", None);
    unsigned.content_hash = "../victim".to_string();
    let manifest = sign_manifest(unsigned, &key, "2025-01-15T10:30:00Z").unwrap();
    let layout = ReleaseLayout::self_artifact();
    storage
        .upload(
            &layout.manifest_key("fuz", "0.5.0", current_target()),
            &serde_json::to_vec(&manifest).unwrap(),
        )
        .await
        .unwrap();
    let err = fetch_version(&storage, "0.5.0", &FetchOptions::default())
        .await
        .expect_err("a path-shaped content hash must be refused");
    // The victim first, so a regression reads as what it is.
    assert_eq!(
        std::fs::read(&self_victim).ok().as_deref(),
        Some(&b"keep"[..]),
        "victim survives: {err:?}"
    );
    assert!(
        matches!(
            &err,
            ReleaseError::Manifest(ManifestError::InvalidContentHash(h)) if h == "../victim"
        ),
        "got {err:?}"
    );
    assert!(err.is_security_violation());

    // Tool: `tools/fuzf/../victim` is `<home>/tools/victim`.
    std::fs::create_dir_all(home.path().join("tools/fuzf")).unwrap();
    let tool_victim = home.path().join("tools/victim");
    std::fs::write(&tool_victim, b"keep").unwrap();
    let mut unsigned = sample_tool_unsigned("fuzf", "0.1.0");
    unsigned.content_hash = "../victim".to_string();
    let manifest = sign_manifest(unsigned, &key, "2025-01-15T10:30:00Z").unwrap();
    let layout = ReleaseLayout::tool("fuzf");
    storage
        .upload(
            &layout.manifest_key("fuzf", "0.1.0", current_target()),
            &serde_json::to_vec(&manifest).unwrap(),
        )
        .await
        .unwrap();
    let err = install_tool(
        &storage,
        "fuzf",
        &ToolInstallOptions {
            version: Some("0.1.0"),
            ..ToolInstallOptions::default()
        },
    )
    .await
    .expect_err("a path-shaped content hash must be refused");
    assert!(
        matches!(
            &err,
            ReleaseError::Manifest(ManifestError::InvalidContentHash(h)) if h == "../victim"
        ),
        "got {err:?}"
    );
    assert_eq!(
        std::fs::read(&tool_victim).unwrap(),
        b"keep",
        "victim survives"
    );

    fuz_home::clear_fuz_home_override_for_testing();
    fuz_crypto::clear_trusted_keys_for_testing();
}

/// Whether `result` is the refusal of a manifest at another release's key —
/// one for `version` read from the key `key`.
fn is_key_mismatch<T>(result: &Result<T, ReleaseError>, key: &str, version: &str) -> bool {
    matches!(
        result,
        Err(ReleaseError::Manifest(ManifestError::KeyMismatch { key: k, version: v, .. }))
            if k == key && v == version
    )
}

/// A tool version asked for is the version installed: a validly signed
/// manifest of another release, served at the asked-for version's key, is
/// refused — by version pinned (`--version`), and by the version the latest pointer
/// names — and nothing is installed from it.
#[tokio::test]
async fn a_tool_manifest_at_another_versions_key_is_refused() {
    let _serial = SERIAL.lock().await;
    let key = trusted_key();
    trust_only(&key);
    let home = fresh_home();

    let storage_dir = tempfile::tempdir().unwrap();
    let storage = FileStorage::new(storage_dir.path()).unwrap();
    let bin_dir = tempfile::tempdir().unwrap();
    publish_tool_version(
        &storage,
        &key,
        bin_dir.path(),
        "0.1.0",
        &test_stubs::host(b"fuzf 0.1.0"),
        None,
    )
    .await;

    // The signed 0.1.0 manifest, served where 0.2.0's belongs.
    let layout = ReleaseLayout::tool("fuzf");
    let target = current_target();
    let old = storage
        .download(&layout.manifest_key("fuzf", "0.1.0", target))
        .await
        .unwrap();
    let pinned_key = layout.manifest_key("fuzf", "0.2.0", target);
    storage.upload(&pinned_key, &old).await.unwrap();

    // Pinned.
    let result = fetch_tool_manifest(&storage, "fuzf", Some("0.2.0")).await;
    assert!(
        is_key_mismatch(&result, &pinned_key, "0.1.0"),
        "got {result:?}"
    );
    assert!(result.unwrap_err().is_security_violation());
    let options = ToolInstallOptions {
        version: Some("0.2.0"),
        ..ToolInstallOptions::default()
    };
    let result = install_tool(&storage, "fuzf", &options).await;
    assert!(
        is_key_mismatch(&result, &pinned_key, "0.1.0"),
        "got {result:?}"
    );
    assert!(!home.path().join("tools").join("fuzf").exists());

    // Named by the latest pointer.
    storage
        .upload(
            &layout.latest_key(current_target()),
            br#"{"version":"0.2.0"}"#,
        )
        .await
        .unwrap();
    let result = fetch_tool_manifest(&storage, "fuzf", None).await;
    assert!(
        is_key_mismatch(&result, &pinned_key, "0.1.0"),
        "got {result:?}"
    );
    let result = install_tool(&storage, "fuzf", &ToolInstallOptions::default()).await;
    assert!(
        is_key_mismatch(&result, &pinned_key, "0.1.0"),
        "got {result:?}"
    );
    assert!(!home.path().join("tools").join("fuzf").exists());

    // The release at its own key still installs.
    let options = ToolInstallOptions {
        version: Some("0.1.0"),
        ..ToolInstallOptions::default()
    };
    assert_eq!(
        install_tool(&storage, "fuzf", &options)
            .await
            .unwrap()
            .version,
        "0.1.0"
    );

    fuz_home::clear_fuz_home_override_for_testing();
    fuz_crypto::clear_trusted_keys_for_testing();
}

/// The self path's twin: a signed self manifest of another release at the
/// key of the version fetched is refused — pinned (`fetch_version`), named by
/// the latest pointer (`fetch_latest`), and on the read-only `--check` seam
/// (`fetch_latest_manifest`) — before anything is downloaded or written.
#[tokio::test]
async fn a_self_manifest_at_another_versions_key_is_refused() {
    let _serial = SERIAL.lock().await;
    let key = trusted_key();
    trust_only(&key);
    let home = fresh_home();

    let storage_dir = tempfile::tempdir().unwrap();
    let storage = FileStorage::new(storage_dir.path()).unwrap();
    let artifact_dir = tempfile::tempdir().unwrap();
    let meta = make_self_artifact(
        artifact_dir.path(),
        "0.4.0",
        &test_stubs::host(b"fuz bytes -- 0.4.0"),
    );
    publish_artifact(
        &storage,
        &meta,
        artifact_dir.path(),
        &key,
        &PublishOptions::default(),
    )
    .await
    .unwrap();

    let layout = ReleaseLayout::self_artifact();
    let target = current_target();
    let old = storage
        .download(&layout.manifest_key("fuz", "0.4.0", target))
        .await
        .unwrap();
    let pinned_key = layout.manifest_key("fuz", "0.5.0", target);
    storage.upload(&pinned_key, &old).await.unwrap();

    let result = fetch_version(&storage, "0.5.0", &FetchOptions::default()).await;
    assert!(
        is_key_mismatch(&result, &pinned_key, "0.4.0"),
        "got {result:?}"
    );
    assert!(result.unwrap_err().is_security_violation());

    storage
        .upload(
            &layout.latest_key(current_target()),
            br#"{"version":"0.5.0"}"#,
        )
        .await
        .unwrap();
    let result = fetch_latest_manifest(&storage).await;
    assert!(
        is_key_mismatch(&result, &pinned_key, "0.4.0"),
        "got {result:?}"
    );
    let result = fetch_latest(&storage, &FetchOptions::default()).await;
    assert!(
        is_key_mismatch(&result, &pinned_key, "0.4.0"),
        "got {result:?}"
    );
    assert!(!home.path().join("artifacts").join(&meta.hash).exists());
    assert!(!home.path().join("current").exists());

    fuz_home::clear_fuz_home_override_for_testing();
    fuz_crypto::clear_trusted_keys_for_testing();
}

/// Sign and upload a release labelled for this client's target whose one
/// binary is `content` — whatever it is for — as a publisher that skipped the
/// platform check would: tarball, manifest, and the target's latest pointer.
/// `tool` is the tool's name, or `None` for the self artifact.
async fn upload_mislabelled(
    storage: &FileStorage,
    key: &SigningKey,
    tool: Option<&str>,
    version: &str,
    content: &[u8],
) {
    let (layout, name) = tool.map_or_else(
        || (ReleaseLayout::self_artifact(), "fuz"),
        |tool| (ReleaseLayout::tool(tool), tool),
    );
    let target = current_target();
    let scratch = tempfile::tempdir().unwrap();
    let tarball_path = scratch.path().join("release.tar.gz");
    let digest =
        fuz_release::pack_tarball_to_file(&[(name.to_string(), content.to_vec())], &tarball_path)
            .unwrap();
    let mut pins = std::collections::BTreeMap::new();
    pins.insert(name.to_string(), ContentHash::blake3(content));
    let content_hash = fuz_artifact::content_hash_from_binaries(&pins);
    let tarball_name = ReleaseLayout::tarball_filename(name, version, target);
    let unsigned = ManifestUnsigned {
        format: MANIFEST_FORMAT_VERSION,
        version: version.to_string(),
        content_hash,
        target: target.to_string(),
        minimum_version: None,
        tarball: TarballInfo {
            path: tarball_name.clone(),
            blake3: digest.blake3,
            size: digest.size,
        },
        binaries: pins.into_iter().collect(),
        tool: tool.map(str::to_string),
    };
    let manifest = sign_manifest(unsigned, key, "2025-01-15T10:30:00Z").unwrap();
    storage
        .upload_file(&layout.tarball_key(&tarball_name), &tarball_path)
        .await
        .unwrap();
    storage
        .upload(
            &layout.manifest_key(name, version, target),
            serde_json::to_string_pretty(&manifest).unwrap().as_bytes(),
        )
        .await
        .unwrap();
    storage
        .upload(
            &layout.latest_key(target),
            format!("{{\"version\":\"{version}\"}}").as_bytes(),
        )
        .await
        .unwrap();
}

/// A binary for another architecture than this client's, so the header can
/// never pass for it.
fn foreign_binary(payload: &[u8]) -> Vec<u8> {
    use fuz_artifact::platform::{Arch, Libc, ReleaseTarget};
    let host = test_stubs::host_target();
    let other = match host.arch() {
        Arch::X86_64 => Arch::Aarch64,
        Arch::Aarch64 => Arch::X86_64,
    };
    test_stubs::for_target(ReleaseTarget::linux(other, Libc::Gnu), payload)
}

/// A validly signed self release labelled for this target whose `fuz` is not
/// for it is refused after every hash checks out: exit-1 territory (not a
/// security violation), no artifact directory lands, and `current` keeps
/// pointing at the install that works.
#[tokio::test]
async fn fetch_refuses_a_self_release_whose_binary_is_not_for_this_target() {
    let _serial = SERIAL.lock().await;
    let key = trusted_key();
    trust_only(&key);
    let home = fresh_home();
    let installed = seed_current(home.path(), "0.1.0", &test_stubs::host(b"fuz 0.1.0"));
    let storage_dir = tempfile::tempdir().unwrap();
    let storage = FileStorage::new(storage_dir.path()).unwrap();
    let content = foreign_binary(b"fuz 0.2.0 for elsewhere");
    upload_mislabelled(&storage, &key, None, "0.2.0", &content).await;

    let err = fetch_latest(&storage, &FetchOptions::default())
        .await
        .unwrap_err();
    assert!(
        matches!(&err, ReleaseError::MislabelledBinary { error: ArtifactError::BinaryPlatform { name, .. }, .. } if name == "fuz"),
        "{err:?}"
    );
    assert!(!err.is_security_violation());
    let mut pins = std::collections::BTreeMap::new();
    pins.insert("fuz".to_string(), ContentHash::blake3(&content));
    let hash = fuz_artifact::content_hash_from_binaries(&pins);
    assert!(!home.path().join("artifacts").join(&hash).exists());
    let staged: Vec<_> = std::fs::read_dir(home.path().join("artifacts"))
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|name| name.starts_with('.'))
        .collect();
    assert!(staged.is_empty(), "{staged:?}");
    assert_eq!(
        std::fs::read_link(home.path().join("current")).unwrap(),
        Path::new(&format!("artifacts/{}", installed.hash))
    );
}

/// The tool twin: a validly signed tool release labelled for this target
/// whose binary is not for it installs nothing and leaves the tool's
/// `current` on the version that works.
#[tokio::test]
async fn install_tool_refuses_a_release_whose_binary_is_not_for_this_target() {
    let _serial = SERIAL.lock().await;
    let key = trusted_key();
    trust_only(&key);
    let home = fresh_home();
    let storage_dir = tempfile::tempdir().unwrap();
    let storage = FileStorage::new(storage_dir.path()).unwrap();
    let bin_dir = tempfile::tempdir().unwrap();
    publish_tool_version(
        &storage,
        &key,
        bin_dir.path(),
        "0.1.0",
        &test_stubs::host(b"fuzf 0.1.0"),
        None,
    )
    .await;
    let first = install_tool(&storage, "fuzf", &ToolInstallOptions::default())
        .await
        .unwrap();
    let current = home.path().join("tools/fuzf/current");
    let before = std::fs::read_link(&current).unwrap();

    upload_mislabelled(
        &storage,
        &key,
        Some("fuzf"),
        "0.2.0",
        &foreign_binary(b"fuzf"),
    )
    .await;
    let err = install_tool(&storage, "fuzf", &ToolInstallOptions::default())
        .await
        .unwrap_err();
    assert!(
        matches!(&err, ReleaseError::MislabelledBinary { error: ArtifactError::BinaryPlatform { name, .. }, .. } if name == "fuzf"),
        "{err:?}"
    );
    assert!(!err.is_security_violation());
    assert_eq!(std::fs::read_link(&current).unwrap(), before);
    let installs: Vec<String> = std::fs::read_dir(home.path().join("tools/fuzf"))
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|name| name != "current")
        .collect();
    assert_eq!(installs, std::slice::from_ref(&first.content_hash));
}
