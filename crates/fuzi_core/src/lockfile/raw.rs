//! Lenient raw deserialization of `package-lock.json` v2/v3.
//!
//! Every field is optional — real lockfiles carry extraneous entries that are a
//! bare `{"extraneous":true}` object, so any required field would make
//! `serde` reject real lockfiles. No semantic validation happens here; field
//! presence plus the map key drive classification (`crate::classify`).

use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;
use serde_json::Value;

/// The raw `package-lock.json` document, parsed leniently.
///
/// No semantic validation here — that is `crate::classify`'s job. `packages`
/// is a `BTreeMap` for deterministic iteration (deterministic errors +
/// reporting).
#[derive(Debug, Clone, Deserialize)]
pub struct RawLockfile {
    /// `lockfileVersion` — the gate. 2 and 3 accepted; 1, absent, and unknown refused.
    #[serde(rename = "lockfileVersion")]
    pub lockfile_version: Option<u32>,
    /// Root package name (metadata; ignored except for messages).
    pub name: Option<String>,
    /// The `packages` map: key = install path, value = entry.
    ///
    /// Required, with no empty-map default: a lock without one is refused, never
    /// read as an empty tree (`crate::lockfile::parse_lockfile` names it).
    pub packages: BTreeMap<String, RawPackageEntry>,
}

/// npm `packages`-map entry fields fuzi does **not** model, reviewed and deliberately inert.
///
/// The list is the other half of the `unknown` capture below: a field here has
/// been looked at and confirmed to carry no install semantics, so parsing it into
/// nothing is correct. The list tracks arborist's `pkgMetaKeys` (the fields
/// npm copies from a package's `package.json` into its lock entry) less the
/// ones modeled here; `acceptDependencies` widens the ranges npm's resolver
/// accepts, and fuzi never resolves. `bundleDependencies` earns its place indirectly — it only
/// *names* what the bundled children mark with `inBundle`, which classify already
/// refuses, so the parent's copy adds no decision.
///
/// Anything outside this list *and* outside the modeled fields is a field npm
/// emits that fuzi has never been reviewed against — see [`RawPackageEntry`].
pub const KNOWN_INERT_ENTRY_FIELDS: &[&str] = &[
    "acceptDependencies",
    "bundleDependencies",
    "deprecated",
    "engines",
    "funding",
    "hasShrinkwrap",
    "license",
    "peerDependenciesMeta",
    "workspaces",
];

/// One `packages`-map entry, every field optional.
///
/// Field presence plus the map KEY drive classification; this struct does no
/// interpretation. Metadata fields (`license`, `engines`, …) are intentionally
/// not modeled. Do **not** add `#[serde(deny_unknown_fields)]` — real lockfiles
/// carry metadata fuzi has no business failing on.
/// `version` is carried through for `fuzi verify`, and `name` for the link-target
/// check.
///
/// **The blind spot lenience creates, and how it is watched.** Serde's default
/// is to drop unknown fields silently, and that is exactly how a field like
/// `inBundle` — one that changes where a package's *bytes come from* — would
/// parse into nothing, leaving an installer to fetch bundled entries
/// separately. The failure is not "we didn't model a field"; it is that
/// nothing can tell a load-bearing new field from inert metadata. So unknown
/// fields are
/// **captured** (`unknown`) and checked against [`KNOWN_INERT_ENTRY_FIELDS`]:
/// a name on neither list surfaces as a non-fatal warning on the
/// [`InstallReport`](crate::InstallReport).
///
/// Warn rather than refuse, deliberately. Refusing is `deny_unknown_fields` with
/// extra steps — one inert field added by a future npm would break every install
/// in the ecosystem, and fuzi has no resolver to route around it. A warning costs
/// nothing when npm adds metadata and puts a name in front of a human the first
/// time a lockfile carries something that might matter, which is the whole
/// distance between this and the `inBundle` bug.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
// The boolean flags mirror npm's lockfile schema 1:1 (`dev`, `optional`,
// `peer`, `devOptional`, `hasInstallScript`, `extraneous`); folding them into
// an enum would lose the direct serde mapping.
#[allow(clippy::struct_excessive_bools)]
pub struct RawPackageEntry {
    // --- layout-relevant ---
    /// The locked package `version` (carried only for `fuzi verify`'s structural
    /// `package.json`-version match; not used while building the install plan).
    pub version: Option<String>,
    /// The package `name`. Inert on a registry entry (the key names where it
    /// lands), but load-bearing on a **link target** entry: it is what fuzi checks
    /// the target's `package.json` against, since an alias link key need not match
    /// it. npm writes it there only when it differs from its default for the
    /// target folder. A link entry itself never carries one.
    pub name: Option<String>,
    /// Where to fetch the tarball (a URL hint; the integrity is the trust gate).
    /// On a `link: true` entry, the target directory relative to the project root.
    pub resolved: Option<String>,
    /// SRI integrity string (may carry multiple space-separated tokens).
    pub integrity: Option<String>,
    /// `link: true` distinguishes a link (a symlink to local source) from a
    /// registry entry.
    ///
    /// `Option` (not `serde`-default) so absent (registry) differs from
    /// `link: true` (link).
    pub link: Option<bool>,
    /// `os` allowlist/denylist tokens (e.g. `["linux", "!win32"]`). npm copies
    /// the field from the package's `package.json` unchanged, so a package
    /// that wrote one token as a bare string (`"os": "darwin"`) leaves a string
    /// here; `platform_axis` reads either form.
    #[serde(default, deserialize_with = "platform_axis")]
    pub os: Vec<String>,
    /// `cpu` allowlist/denylist tokens (string or array, as `os`).
    #[serde(default, deserialize_with = "platform_axis")]
    pub cpu: Vec<String>,
    /// `libc` allowlist/denylist tokens (`glibc` / `musl`; string or array, as
    /// `os`).
    #[serde(default, deserialize_with = "platform_axis")]
    pub libc: Vec<String>,
    /// Present-as-`true` or absent — never literal `false` in the fuz projects'
    /// own lockfiles.
    #[serde(default)]
    pub optional: bool,
    /// Present-as-`true` or absent.
    #[serde(default)]
    pub dev: bool,
    /// `devOptional` — survives `--omit=dev` and `--omit=optional` alone.
    #[serde(default)]
    pub dev_optional: bool,
    /// Present-as-`true` or absent.
    #[serde(default)]
    pub peer: bool,
    /// `hasInstallScript` — surfaced in the plan's skipped-scripts report, never run.
    #[serde(default)]
    pub has_install_script: bool,
    /// `extraneous: true` — classify-and-skip.
    #[serde(default)]
    pub extraneous: bool,
    /// `inBundle: true` — the package ships *inside* an ancestor's tarball
    /// (`bundleDependencies`) rather than being fetched on its own. Modeled so
    /// classify can refuse loud; see [`RefuseReason::BundledUnsupported`].
    ///
    /// [`RefuseReason::BundledUnsupported`]: crate::classify::RefuseReason::BundledUnsupported
    #[serde(default)]
    pub in_bundle: bool,
    /// `bin` map — carried for `.bin` symlink creation during materialization;
    /// not used while building the plan.
    pub bin: Option<Value>,
    // --- root-only dep maps, drift uses these on packages[""] ---
    /// `dependencies` (root entry; drift comparison).
    pub dependencies: Option<BTreeMap<String, String>>,
    /// `devDependencies` (root entry; drift comparison).
    pub dev_dependencies: Option<BTreeMap<String, String>>,
    /// `optionalDependencies` (root entry; drift comparison).
    pub optional_dependencies: Option<BTreeMap<String, String>>,
    /// `peerDependencies` (root entry; drift comparison).
    pub peer_dependencies: Option<BTreeMap<String, String>>,
    /// The **names** of fields not matched above, so [`unknown_entry_fields`] can
    /// tell inert metadata from an unreviewed npm field.
    ///
    /// Values are [`IgnoredAny`](serde::de::IgnoredAny) — a ZST — on purpose: the
    /// capture exists to be *reported*, and nothing ever reads a value. Holding
    /// them as `Value` would keep a parsed copy of arbitrary lockfile content
    /// (`engines`, `funding`, `workspaces`, …) alive for the whole install —
    /// memory spent on untrusted input fuzi has no use for.
    ///
    /// Measured on a 394-entry lockfile (peak RSS, `--dry-run`, min of 7): no
    /// capture 3300 KiB · `Value` 4732 KiB · `IgnoredAny` 4248 KiB. So dropping
    /// the values recovers about a third of the capture's cost; the rest is
    /// `serde(flatten)` itself, which buffers each entry's unmatched pairs as
    /// `Content` before the flattened field sees them, whatever the target type.
    /// That residual (~1 MiB, transient and per-entry) is the price of keeping the
    /// derive: eliminating it means hand-writing a visitor over all 19 fields —
    /// a second model of this struct to keep in sync by hand, which is the trade
    /// this crate declines everywhere else.
    // clippy suggests a set for a zero-sized value type, and is right in general —
    // but `serde(flatten)` deserializes from a map and has no set form, so the
    // ZST value *is* how "keys only" is spelled here.
    #[allow(clippy::zero_sized_map_values)]
    #[serde(flatten)]
    pub unknown: BTreeMap<String, serde::de::IgnoredAny>,
}

/// Deserialize a platform axis (`os` / `cpu` / `libc`) the way
/// `npm-install-checks` reads one: an array of tokens, or a single token as a
/// bare string (`checkList` wraps a string in a one-element list). `null`
/// reads as absent — npm skips a falsy axis — and anything else is a shape
/// error naming what was expected.
///
/// # Errors
///
/// Returns the deserializer's error for a value that is neither a string, an
/// array of strings, nor `null`.
fn platform_axis<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct AxisVisitor;

    impl<'de> serde::de::Visitor<'de> for AxisVisitor {
        type Value = Vec<String>;

        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("a platform token string or an array of them")
        }

        fn visit_str<E: serde::de::Error>(self, token: &str) -> Result<Self::Value, E> {
            Ok(vec![token.to_string()])
        }

        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            mut seq: A,
        ) -> Result<Self::Value, A::Error> {
            let mut tokens = Vec::with_capacity(seq.size_hint().unwrap_or(0));
            while let Some(token) = seq.next_element::<String>()? {
                tokens.push(token);
            }
            Ok(tokens)
        }

        fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
            Ok(Vec::new())
        }

        fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
            Ok(Vec::new())
        }
    }

    deserializer.deserialize_any(AxisVisitor)
}

/// The lockfile field names that are neither modeled by [`RawPackageEntry`] nor
/// on [`KNOWN_INERT_ENTRY_FIELDS`], deduped across every entry.
///
/// Empty for every one of the fuz projects' own lockfiles surveyed so far. A
/// non-empty result means npm's schema moved and fuzi has not been reviewed
/// against the addition — the caller surfaces it as a warning (see the
/// [`RawPackageEntry`] docs for why a warning and not a refusal).
#[must_use]
pub fn unknown_entry_fields(raw: &RawLockfile) -> Vec<String> {
    let mut names: BTreeSet<&str> = BTreeSet::new();
    for entry in raw.packages.values() {
        for field in entry.unknown.keys() {
            if !KNOWN_INERT_ENTRY_FIELDS.contains(&field.as_str()) {
                names.insert(field);
            }
        }
    }
    names.into_iter().map(str::to_string).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn lockfile(value: Value) -> RawLockfile {
        serde_json::from_value(value).unwrap()
    }

    #[test]
    fn modeled_and_inert_fields_are_not_reported() {
        // The shape every one of the fuz projects' own lockfiles has: modeled
        // fields plus npm's reviewed-inert metadata. This must stay silent, or
        // the warning becomes noise on every install and gets ignored — which is
        // how the `inBundle` class of bug survives a second time.
        let raw = lockfile(json!({
            "lockfileVersion": 3,
            "packages": {
                "node_modules/x": {
                    "version": "1.0.0",
                    "resolved": "https://registry.npmjs.org/x/-/x-1.0.0.tgz",
                    "integrity": "sha512-abc",
                    "dev": true,
                    "license": "MIT",
                    "engines": {"node": ">=20"},
                    "funding": {"url": "https://example.com"},
                    "peerDependenciesMeta": {"y": {"optional": true}},
                    "acceptDependencies": {"y": "^2.0.0"}
                }
            }
        }));
        assert!(unknown_entry_fields(&raw).is_empty());
    }

    #[test]
    fn an_unreviewed_field_is_reported_deduped_and_sorted() {
        // The `inBundle` scenario replayed: a field with real install semantics
        // that fuzi does not model. Without the capture it would parse into nothing
        // and leave no trace anywhere; captured, it surfaces by name.
        let raw = lockfile(json!({
            "lockfileVersion": 3,
            "packages": {
                "node_modules/a": {"someFutureNpmField": true, "license": "MIT"},
                "node_modules/b": {"someFutureNpmField": false, "another": 1}
            }
        }));
        assert_eq!(
            unknown_entry_fields(&raw),
            vec!["another", "someFutureNpmField"]
        );
    }

    #[test]
    fn modeled_fields_never_land_in_the_unknown_capture() {
        // Guards the flatten wiring itself: if a `#[serde(rename_all)]` name ever
        // stopped matching, its field would go quietly missing *and* start showing
        // up as a warning. Asserting the capture is empty catches both halves.
        let raw = lockfile(json!({
            "lockfileVersion": 3,
            "packages": {
                "node_modules/x": {
                    "name": "x", "version": "1.0.0", "resolved": "https://r/x.tgz", "integrity": "sha512-a",
                    "link": false, "os": ["linux"], "cpu": ["x64"], "libc": ["glibc"],
                    "optional": true, "dev": true, "devOptional": true, "peer": true,
                    "hasInstallScript": true, "extraneous": false, "inBundle": false,
                    "bin": {"x": "cli.js"}, "dependencies": {"y": "^1"},
                    "devDependencies": {}, "optionalDependencies": {}, "peerDependencies": {}
                }
            }
        }));
        assert!(raw.packages["node_modules/x"].unknown.is_empty());
    }

    #[test]
    fn platform_axes_read_a_string_an_array_or_null() {
        // npm leaves a package's string-form `os` as a string in the lock; it
        // must parse (it used to fail the whole lockfile as invalid JSON).
        let raw = lockfile(json!({
            "lockfileVersion": 3,
            "packages": {
                "node_modules/a": {"os": "darwin", "cpu": ["arm64", "!x64"], "libc": null},
                "node_modules/b": {}
            }
        }));
        let a = &raw.packages["node_modules/a"];
        assert_eq!(a.os, vec!["darwin"]);
        assert_eq!(a.cpu, vec!["arm64", "!x64"]);
        assert!(a.libc.is_empty());
        assert!(a.unknown.is_empty());
        assert!(raw.packages["node_modules/b"].os.is_empty());
    }

    #[test]
    fn platform_axis_of_another_shape_is_an_error() {
        for os in [json!(7), json!({"x": 1}), json!(["linux", 7])] {
            let err = serde_json::from_value::<RawLockfile>(json!({
                "lockfileVersion": 3,
                "packages": {"node_modules/a": {"os": os}}
            }))
            .unwrap_err();
            assert!(err.is_data(), "{err}");
        }
    }

    #[test]
    fn inert_fields_are_disjoint_from_modeled_fields() {
        // Every reviewed-inert name must land in the `unknown` capture, i.e. no
        // modeled field answers to it. `name` moved from the inert list to a
        // modeled field (link targets are name-checked); a stale entry on both
        // would make the inert list lie about what fuzi reads.
        for field in KNOWN_INERT_ENTRY_FIELDS {
            let raw = lockfile(json!({
                "lockfileVersion": 3,
                "packages": {"node_modules/x": {(*field): "v"}}
            }));
            assert!(
                raw.packages["node_modules/x"].unknown.contains_key(*field),
                "inert field `{field}` is also a modeled field"
            );
        }
        assert!(!KNOWN_INERT_ENTRY_FIELDS.contains(&"name"));
    }
}
