//! The classified entry model: install paths, integrity, bins, and the
//! per-entry shapes a `package-lock.json` entry resolves to. The platform-axis
//! token type and its parsing live in the `platform` module.

use std::collections::BTreeMap;

use fuz_crypto::{ContentHash, HashAlgo, HashError};

use crate::Omit;
use crate::platform::{Cpu, Libc, Os, PlatformToken};
use fuz_sys::text::has_unprintable;

/// An install path = a `packages`-map key: `""` (root), `node_modules/foo`,
/// `node_modules/@scope/foo/node_modules/bar`, or an escapes-root `../x` key.
///
/// Stored verbatim; structure is derived on the `node_modules/` boundary (NOT
/// on `/`, since scoped names `@scope/pkg` contain a slash).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InstallPath(String);

impl InstallPath {
    /// Wrap a raw `packages`-map key.
    #[must_use]
    pub fn new(key: impl Into<String>) -> Self {
        Self(key.into())
    }

    /// The raw key.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// True for the root `""` entry.
    #[must_use]
    pub const fn is_root(&self) -> bool {
        self.0.is_empty()
    }

    /// Classify how this key sits relative to the project root. The key *is*
    /// the materialization target, so a key that escapes root must never reach
    /// `Install`. The only benign escape is a leading run of `..` components —
    /// the sibling form (`../x`) and the ancestor form (`..`, `../..`), both of
    /// which npm emits as link-target keys and neither of which is ever
    /// materialized; every other escape — embedded `..`, an absolute
    /// prefix, a NUL or backslash, or an empty (`//` / trailing-`/`) or `.`
    /// current-dir component — is corruption/tampering in a lockfile.
    ///
    /// This is the *structural* gate, run on every key. The name-level gates —
    /// only package-name characters, no dot-leading component, a proper
    /// package nesting — apply only to a key fuzi places, in classify's
    /// `validate_nm_key`.
    ///
    /// The empty- and `.`-component checks run on the **raw string** (not via
    /// `Path::components()`, which normalizes both away). That normalization is
    /// exactly what makes the escape dangerous: a `node_modules//x` key survives
    /// the raw-string `strip_prefix` in [`InstallPath::nm_relative`] as the
    /// absolute remainder `/x`, and a raw-string `join` then replaces the staging
    /// root with it — so the gate has to fire here, on the key, before any of that.
    #[must_use]
    pub fn containment(&self) -> Containment {
        let key = self.0.as_str();
        if key.starts_with('/') || key.contains('\0') || key.contains('\\') {
            return Containment::Malformed;
        }
        // An empty component (`//`, or a trailing `/`) or a `.` current-dir
        // component is never a well-formed `packages` key. The root `""` is the one
        // legitimate empty *whole* string (classify handles it before
        // containment), so exempt it; any non-empty key with an empty or `.`
        // component is malformed.
        if !key.is_empty() && key.split('/').any(|c| c.is_empty() || c == ".") {
            return Containment::Malformed;
        }
        if !key.split('/').any(|c| c == "..") {
            return Containment::Contained;
        }
        // Has a `..` component: benign only as a leading run of `..` with no
        // further traversal after it — a sibling (`../x`, `../../x`) or, when
        // the run is the whole key, an ancestor (`..`, `../..`). npm writes
        // both as link-target keys; neither is ever a materialization target.
        let mut rest = key;
        while let Some(r) = rest.strip_prefix("../") {
            rest = r;
        }
        if rest != ".." && rest.split('/').any(|c| c == "..") {
            Containment::Malformed
        } else {
            Containment::SiblingEscape
        }
    }

    /// Nesting depth = count of `node_modules/` path components — at the key's
    /// start or right after a `/`, never inside a name. Root = 0,
    /// `node_modules/foo` = 1, `…/node_modules/bar` = 2;
    /// `node_modules/@foo-node_modules/x` = 1.
    #[must_use]
    pub fn depth(&self) -> usize {
        node_modules_boundaries(&self.0).count()
    }

    /// The path relative to the *top-level* `node_modules` — the key with its
    /// leading `node_modules/` stripped. This is where the package's tree lands
    /// under the materialization staging root (which stands in for the top-level
    /// `node_modules`): `node_modules/@scope/foo` → `@scope/foo`,
    /// `node_modules/a/node_modules/b` → `a/node_modules/b`. `None` for any key
    /// not under `node_modules/` (root / sibling-escape — never an `Install`).
    #[must_use]
    pub fn nm_relative(&self) -> Option<&str> {
        self.0.strip_prefix("node_modules/")
    }

    /// The package portion — the substring after the FINAL `node_modules/`
    /// boundary (possibly scoped): `node_modules/a/node_modules/@s/b` → `@s/b`,
    /// `node_modules/foo` → `foo`. This is the package directory name as a
    /// sibling of its enclosing `.bin`, so a `.bin/<cmd>` symlink targets
    /// `../<package_portion>/<bin-path>`. For the root key, the whole string.
    #[must_use]
    pub fn package_portion(&self) -> &str {
        package_portion_of(&self.0)
    }
}

/// The package portion of a raw `packages`-map key — the substring after the
/// final `node_modules/` boundary, borrowed from `key`. The free-function form of
/// [`InstallPath::package_portion`], for callers (e.g. `verify`) that hold the raw
/// key and need a borrow that outlives a temporary `InstallPath`.
#[must_use]
pub fn package_portion_of(key: &str) -> &str {
    last_node_modules_boundary(key).map_or(key, |idx| &key[idx + NODE_MODULES_SLASH.len()..])
}

const NODE_MODULES_SLASH: &str = "node_modules/";

/// Byte offsets in `key` where a `node_modules/` **path component** begins —
/// at the key's start or right after a `/`. A substring match inside a name
/// segment (`@foo-node_modules/x`, `x-node_modules/…`) is no nesting boundary.
fn node_modules_boundaries(key: &str) -> impl Iterator<Item = usize> + '_ {
    key.match_indices(NODE_MODULES_SLASH)
        .map(|(idx, _)| idx)
        .filter(|&idx| is_component_start(key, idx))
}

/// The last of [`node_modules_boundaries`], found from the end.
fn last_node_modules_boundary(key: &str) -> Option<usize> {
    key.rmatch_indices(NODE_MODULES_SLASH)
        .map(|(idx, _)| idx)
        .find(|&idx| is_component_start(key, idx))
}

/// True iff byte `idx` of `key` starts a path component.
const fn is_component_start(key: &str, idx: usize) -> bool {
    idx == 0 || key.as_bytes()[idx - 1] == b'/'
}

/// How an [`InstallPath`] key sits relative to the project root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Containment {
    /// Stays within the project root (`""`, a `node_modules/…` key, or a clean
    /// subdir key like `packages/a`).
    Contained,
    /// Outside the project by a leading run of `..` and nothing else: npm's
    /// sibling form (`../x`, `../../x`) or an ancestor directory itself (`..`,
    /// `../..`). Never a materialization target — classify-and-skip.
    SiblingEscape,
    /// Escapes root or is otherwise not a well-formed `packages` key: embedded `..`, an
    /// absolute prefix, NUL, backslash, or an empty (`//` / trailing-`/`) or `.`
    /// current-dir component. Refuse loud.
    Malformed,
}

/// The sha512 trust gate for a registry tarball.
///
/// npm `integrity` may carry multiple space-separated SRI tokens
/// (`sha512-… sha256-…`); fuzi parses all, requires ≥1 sha512, keeps that, and
/// ignores every other algorithm. Wraps `fuz_crypto::ContentHash`; there is no
/// bespoke SRI parser.
#[derive(Debug, Clone)]
pub struct Integrity(ContentHash);

/// Outcome of parsing an `integrity` field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntegrityParse {
    /// A usable sha512 hash was selected.
    Ok(Integrity),
    /// Only sha1 token(s) present.
    Sha1Only,
    /// Field absent / empty / whitespace-only.
    Missing,
    /// A token failed base64 / length validation.
    Malformed(String),
}

impl Integrity {
    /// Parse an npm `integrity` field, selecting the sha512 token.
    ///
    /// Splits on whitespace first (npm packs multiple SRI tokens with a
    /// space), parses each via `ContentHash::parse_sri`, and selects the
    /// sha512. A `sha1-…` token surfaces as `HashError::UnknownAlgorithm`
    /// since sha1 is not a `HashAlgo` variant.
    ///
    /// Per SRI semantics an *unknown-algorithm* token is ignored rather than
    /// fatal — the sha512 is the trust gate, so a companion token `fuz_crypto`
    /// doesn't model must not void an otherwise-good entry. `sha1` is the one
    /// unknown algorithm tracked, purely so a sha1-*only* field reports the
    /// precise [`IntegrityParse::Sha1Only`] refusal instead of a vague
    /// "missing". A *malformed* token (bad base64, wrong digest length) is
    /// still fatal: that is corrupt data, not an unmodeled algorithm.
    #[must_use]
    pub fn parse(raw: Option<&str>) -> IntegrityParse {
        let Some(s) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
            return IntegrityParse::Missing;
        };
        let mut sha512: Option<ContentHash> = None;
        let mut saw_sha1 = false;
        for token in s.split_whitespace() {
            match ContentHash::parse_sri(token) {
                Ok(h) if h.algo() == HashAlgo::Sha512 => match &sha512 {
                    // Two *different* sha512 digests for one tarball is a tamper
                    // signal npm never emits — refuse rather than silently pick one
                    // (a duplicate of the same digest is harmless and accepted).
                    Some(existing) if existing != &h => {
                        return IntegrityParse::Malformed(
                            "conflicting sha512 integrity tokens".to_string(),
                        );
                    }
                    _ => sha512 = Some(h),
                },
                Ok(_) => {} // sha256 etc. — ignore weaker
                // An algorithm fuz_crypto doesn't model is ignored (SRI
                // semantics); `sha1` is remembered only so a sha1-only field
                // gets the precise refusal.
                Err(HashError::UnknownAlgorithm(a)) => saw_sha1 |= a == "sha1",
                Err(e) => return IntegrityParse::Malformed(e.to_string()),
            }
        }
        match (sha512, saw_sha1) {
            (Some(h), _) => IntegrityParse::Ok(Self(h)),
            (None, true) => IntegrityParse::Sha1Only,
            (None, false) => IntegrityParse::Missing,
        }
    }

    /// Render for cache key / reporting (`sha512-<base64>`).
    #[must_use]
    pub fn to_sri(&self) -> String {
        self.0.to_sri()
    }

    /// The underlying hash; the fetch step verifies tarball bytes by `==` against this.
    #[must_use]
    pub const fn content_hash(&self) -> &ContentHash {
        &self.0
    }
}

impl PartialEq for Integrity {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for Integrity {}

impl std::hash::Hash for Integrity {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

// `ContentHash` has no `Ord`. Order by (algorithm, digest bytes) — an arbitrary
// but stable total order for `BTreeMap<Integrity, _>` keys, allocation-free
// (unlike an SRI-string compare) and consistent with `ContentHash`'s algo-aware
// equality.
impl PartialOrd for Integrity {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Integrity {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (self.0.algo().as_str(), self.0.as_bytes())
            .cmp(&(other.0.algo().as_str(), other.0.as_bytes()))
    }
}

/// The materialization target — a registry tarball to fetch and place.
// The dependency-reason flags mirror npm's per-entry boolean schema (`dev`,
// `optional`, `devOptional`, `peer`, `hasInstallScript`); they drive
// `retained_under` directly.
#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)]
pub struct RegistryEntry {
    /// Where the entry lands in `node_modules`.
    pub path: InstallPath,
    /// The locked `version` string (metadata; `fuzi verify` matches it against
    /// the materialized `package.json`). `None` for the rare entry npm wrote
    /// without one.
    pub version: Option<String>,
    /// `https://…` tarball URL (validated at classify time).
    pub resolved: String,
    /// sha512 integrity, already selected.
    pub integrity: Integrity,
    /// `os` axis tokens.
    pub os: Vec<PlatformToken<Os>>,
    /// `cpu` axis tokens.
    pub cpu: Vec<PlatformToken<Cpu>>,
    /// `libc` axis tokens.
    pub libc: Vec<PlatformToken<Libc>>,
    /// `hasInstallScript` — reported, never run.
    pub has_install_script: bool,
    /// `dev` dependency-reason flag.
    pub dev: bool,
    /// `optional` dependency-reason flag.
    pub optional: bool,
    /// `devOptional` dependency-reason flag.
    pub dev_optional: bool,
    /// `peer` dependency-reason flag.
    pub peer: bool,
    /// Validated `command → in-package target` bins, linked into
    /// `node_modules/.bin` during materialization. Parsed (not raw): a malformed
    /// or escaping bin was refused at classify time ([`RefuseReason::MalformedBin`]),
    /// so every pair here is provably safe to chmod + symlink.
    ///
    /// [`RefuseReason::MalformedBin`]: crate::classify::RefuseReason::MalformedBin
    pub bins: BTreeMap<BinCommand, BinTarget>,
}

impl RegistryEntry {
    /// True iff this entry is kept under the given omit set — the one omit
    /// predicate, shared with link entries (which take their target's flags).
    #[must_use]
    pub fn retained_under(&self, omit: &[Omit]) -> bool {
        retained(
            DepFlags {
                dev: self.dev,
                optional: self.optional,
                dev_optional: self.dev_optional,
                peer: self.peer,
            },
            omit,
        )
    }
}

/// An entry's npm dependency-reason flags — the input to [`retained`].
///
/// A registry entry carries them itself; a `link: true` entry carries none, and
/// its flags come from the **target** entry npm writes beside it.
// The four bools mirror npm's per-entry flag schema 1:1.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct DepFlags {
    /// `dev`.
    pub dev: bool,
    /// `optional`.
    pub optional: bool,
    /// `devOptional` — survives `--omit dev` and `--omit optional` alone.
    pub dev_optional: bool,
    /// `peer`.
    pub peer: bool,
}

/// True iff an entry with `flags` is kept under the omit set.
///
/// `omitted = (Dev∈O && dev) || (Optional∈O && optional)
///            || (Dev∈O && Optional∈O && dev_optional) || (Peer∈O && peer)`
///
/// The one omit predicate: registry entries reach it through
/// [`RegistryEntry::retained_under`], links with their target entry's flags.
pub fn retained(flags: DepFlags, omit: &[Omit]) -> bool {
    let has = |o: Omit| omit.contains(&o);
    let omitted = (has(Omit::Dev) && flags.dev)
        || (has(Omit::Optional) && flags.optional)
        || (has(Omit::Dev) && has(Omit::Optional) && flags.dev_optional)
        || (has(Omit::Peer) && flags.peer);
    !omitted
}

/// The target of a `link: true` entry — a validated **sibling** directory,
/// `../<segment>`.
///
/// npm writes a link entry as `{resolved: <path from the project root to the
/// target's real path>, link: true}`. fuzi places only the sibling shape: one
/// leading `../` and one plain component that does not begin with `.`, is not
/// `node_modules` (the parent directory's own `node_modules`, where Node
/// resolves the project's bare imports — not a package beside the project),
/// carries no control or invisible character, and fits a directory name. Only
/// [`LinkTarget::parse`] constructs one, so the symlink fuzi creates can only
/// ever point at a directory beside the project — never into it, never further
/// up, never through a scheme.
///
/// The components are read **literally**: `resolved` is never percent-decoded,
/// Unicode-normalized, or trimmed, so `%2e%2e` and a lookalike dot are names,
/// not traversal, and an NFC and an NFD spelling are two different segments.
///
/// The segment is a directory name, not a package name, so it is held to a
/// denylist rather than the placed-key allowlist: any printable name passes,
/// non-ASCII letters and spaces included. The denylist is `fuz_sys::text`'s
/// `is_unprintable` set, which takes in the zero-width joiners and the
/// variation selectors — so a sibling directory whose name really holds one
/// (an emoji sequence, a script that joins with ZWNJ/ZWJ) refuses as a
/// malformed link. Regenerating the lockfile does not help there; renaming the
/// directory does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkTarget {
    /// The sibling directory's name — the one component after `../`.
    segment: String,
}

/// The longest sibling directory name [`LinkTarget::parse`] accepts, in bytes —
/// `NAME_MAX`, the longest name a directory can have on the filesystems fuzi
/// runs on. A longer segment is not a directory npm resolved a link to.
const MAX_LINK_SEGMENT_LEN: usize = 255;

/// Outcome of parsing a link entry's `resolved`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkTargetParse {
    /// A sibling directory fuzi links.
    Ok(LinkTarget),
    /// A well-formed shape fuzi does not place — an in-tree workspace
    /// (`packages/a`), a multi-level target (`../../x`), a multi-component
    /// one (`../a/b`), or an ancestor directory (`..`, `../..`, which npm
    /// writes for a project that depends on a directory it sits inside).
    /// Carries a teaching detail.
    Deferred(String),
    /// Not a path npm writes for a link: empty, absolute, home-relative, a
    /// scheme (`file:`), a control or invisible character (C0, DEL, C1, a bidi
    /// or zero-width format character — the `text` module's set) or
    /// backslash, an empty or `.` component, an embedded `..`, or a sibling
    /// that is dot-leading, named `node_modules` (any case), or longer than
    /// 255 bytes. Carries a teaching detail.
    Malformed(String),
}

impl LinkTarget {
    /// Parse a link entry's `resolved` (a path relative to the project root).
    ///
    /// Malformed outranks deferred: a target that is both (an in-tree path with
    /// an embedded `..`) reports as malformed, the tamper signal.
    #[must_use]
    pub fn parse(raw: &str) -> LinkTargetParse {
        use LinkTargetParse::{Deferred, Malformed};
        let malformed = |why: &str| Malformed(why.to_string());
        if raw.is_empty() {
            return malformed("empty path");
        }
        if raw.contains('\\') {
            return malformed("contains a backslash");
        }
        // NUL and every other control character (C0, DEL, C1), and the
        // invisible / direction-changing format characters: the segment becomes
        // a symlink's text and is printed in messages.
        if has_unprintable(raw) {
            return malformed(
                "contains a control or invisible character (if the directory's name really holds one, rename the directory — regenerating the lockfile will not change it)",
            );
        }
        // A `:` is how a scheme (`file:`, `git+https:`) or a drive prefix reads;
        // npm's link `resolved` is a bare relative path, so refuse rather than
        // guess what it means.
        if raw.contains(':') {
            return malformed("contains a `:` (a scheme like `file:` is not a link path)");
        }
        if raw.starts_with('/') {
            return malformed("absolute path");
        }
        if raw.starts_with('~') {
            return malformed("home-relative path");
        }
        let components: Vec<&str> = raw.split('/').collect();
        if components.iter().any(|c| c.is_empty() || *c == ".") {
            return malformed("empty or `.` path component");
        }
        let ups = components.iter().take_while(|c| **c == "..").count();
        let rest = &components[ups..];
        if rest.contains(&"..") {
            return malformed("embedded `..` component");
        }
        match (ups, rest) {
            (_, []) => {
                Deferred("ancestor directory target (only `../<dir>` is linked)".to_string())
            }
            (1, [segment]) if segment.starts_with('.') => {
                malformed("dot-leading sibling directory")
            }
            (1, [segment]) if segment.eq_ignore_ascii_case("node_modules") => {
                malformed("sibling directory named node_modules")
            }
            (1, [segment]) if segment.len() > MAX_LINK_SEGMENT_LEN => {
                malformed("sibling directory name longer than 255 bytes")
            }
            (1, [segment]) => LinkTargetParse::Ok(Self {
                segment: (*segment).to_string(),
            }),
            (0, _) => Deferred("in-tree workspace target".to_string()),
            (1, _) => Deferred("multi-component target (only `../<dir>` is linked)".to_string()),
            _ => Deferred("multi-level target (only `../<dir>` is linked)".to_string()),
        }
    }

    /// The sibling directory's name.
    #[must_use]
    pub fn segment(&self) -> &str {
        &self.segment
    }

    /// The target as the lockfile spells it — `../<segment>`, which is also the
    /// key of the target entry in the `packages` map.
    #[must_use]
    pub fn as_resolved(&self) -> String {
        format!("../{}", self.segment)
    }

    /// The target directory on disk for a project at `project_dir`:
    /// `<project_dir>/../<segment>`.
    #[must_use]
    pub fn dir_in(&self, project_dir: &std::path::Path) -> std::path::PathBuf {
        project_dir.join("..").join(&self.segment)
    }

    /// The symlink text for a link placed at `link` (a `node_modules/…` key):
    /// one `../` per component of the link's parent directory, then the target.
    ///
    /// `node_modules/@fuzdev/zap` + `../zap` → `../../../zap`,
    /// npm's own shape. Relative, so it resolves the same from the staging root
    /// as from `node_modules`: the two are siblings under the project.
    #[must_use]
    pub fn relative_from(&self, link: &InstallPath) -> String {
        let parent_components = link.as_str().split('/').count().saturating_sub(1);
        format!("{}../{}", "../".repeat(parent_components), self.segment)
    }
}

/// A `link: true` entry fuzi places: a symlink at `path` to a sibling directory.
///
/// Built only by classify, from the link entry (which npm writes as nothing but
/// `resolved` + `link`) and its target entry (which carries the package's
/// `version`, flags, `bin`, and — when it differs from the folder default — `name`).
#[derive(Debug, Clone)]
pub struct LinkEntry {
    /// Where the symlink lands — a depth-1 `node_modules/…` key.
    pub path: InstallPath,
    /// The validated sibling target.
    pub target: LinkTarget,
    /// The target entry's `name`. `None` when npm omitted it, which it does when
    /// the name equals npm's default for the target folder (`nameFromFolder`:
    /// the folder name, `@parent/<folder>` under an `@`-named parent); the
    /// link-target check resolves that default from the disk. Checked against
    /// the target's `package.json` before any network work; an alias link key
    /// may differ from it.
    pub name: Option<String>,
    /// The target entry's `version` (a mismatch with the target's
    /// `package.json` warns; it does not refuse).
    pub version: Option<String>,
    /// The target entry's `hasInstallScript` — reported, never run.
    pub has_install_script: bool,
    /// Validated bins from the target entry's `bin`, linked through the package
    /// link without ever touching the target.
    pub bins: BTreeMap<BinCommand, BinTarget>,
}

/// A `node_modules/.bin` command name — a validated *plain filename*.
///
/// Parsed, never raw: a `BinCommand` can never contain a path separator, `.`/`..`,
/// or backslash, so a `.bin/<command>` link can never escape the `.bin`
/// directory — nor a control or invisible character (NUL included; the `text`
/// module's set), so the name fuzi creates in a directory users put on `PATH`
/// reads as what it is. The `.bin`-surface counterpart of
/// [`InstallPath::containment`];
/// only [`BinCommand::parse`] constructs one, so materialization's path-join
/// receives a proven-safe filename rather than a raw lockfile string.
///
/// A denylist, not the placed-key allowlist: a bin name is whatever the
/// package's author chose, and npm does not hold it to the package-name rule.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct BinCommand(String);

impl BinCommand {
    /// Parse a raw lockfile bin command, or `None` if it is not a plain filename
    /// (empty, `.`/`..`, or containing `/`, `\`, or a control or invisible
    /// character).
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        if raw.is_empty()
            || raw == "."
            || raw == ".."
            || raw.contains('/')
            || raw.contains('\\')
            || has_unprintable(raw)
        {
            return None;
        }
        Some(Self(raw.to_string()))
    }

    /// The validated command name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A `bin` target — a validated *package-relative* path that cannot escape its
/// package directory.
///
/// Parsed so the target is always a relative path of `Normal`/`.` components only
/// (no absolute prefix, no `..`, no backslash, and no control or invisible
/// character — it becomes a symlink's text). The chmod-and-symlink target
/// is therefore provably inside the package; a hostile `bin` map cannot point
/// fuzi at a file outside the tree. Only [`BinTarget::parse`] constructs one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BinTarget(String);

impl BinTarget {
    /// Parse a raw lockfile bin target, or `None` if it is empty, absolute,
    /// escapes the package (`..`), or contains a backslash or a control or
    /// invisible character.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        use std::path::{Component, Path};
        if raw.is_empty() || raw.contains('\\') || has_unprintable(raw) {
            return None;
        }
        Path::new(raw)
            .components()
            .all(|c| matches!(c, Component::Normal(_) | Component::CurDir))
            .then(|| Self(raw.to_string()))
    }

    /// The validated, package-relative target path.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The text of the `.bin/<cmd>` symlink for this bin of the package (or
    /// link) at `package`: `../<package portion>/<target>`, npm's shape. `.bin`
    /// is a sibling of the package within its enclosing `node_modules`, so the
    /// text is the same for an extracted package and for a linked one.
    ///
    /// The one place the text is built: install writes it, and `fuzi verify`
    /// compares against it.
    #[must_use]
    pub fn bin_link_text(&self, package: &InstallPath) -> String {
        format!("../{}/{}", package.package_portion(), self.0)
    }
}

/// Parse + validate a lockfile `bin` field into typed `command → target` pairs.
///
/// npm normalizes `bin` to an object (`{cmd: path}`); the bare-string form
/// (`"bin": "cli.js"`, whose command is the package's *unscoped* name) is handled
/// defensively for hand-written or odd lockfiles.
///
/// Any **other** present shape — a non-string target inside the object, or a
/// `bin` that is an array/number/bool — is refused, not skipped. npm emits only
/// the two shapes above, so a third is the same "npm never emits this" signal the
/// escaping-target check already refuses on; silently dropping it would instead
/// produce a tree that installs clean and then fails at `vite: command not found`,
/// with nothing in the install output pointing at the cause. An **absent** or
/// explicitly `null` `bin` stays an honest absence (no bins declared) — that is a
/// package with no binaries, not a malformed one.
///
/// A path-bearing command or an escaping/absolute target is something **npm never
/// emits** (an attack or a corrupt lockfile), so it is a refuse-loud `Err` here,
/// not a silent skip. Validating at classify time means the returned map is
/// proven safe — every `BinCommand`/`BinTarget` is constructed, never raw — so
/// materialization receives only chmod/symlink-safe components. The
/// `.bin`-surface analog of the [`InstallPath::containment`] →
/// [`crate::classify::RefuseReason::MalformedInstallPath`] gate.
///
/// # Errors
///
/// Returns a teaching detail string naming the offending command or target.
pub fn parse_bins(
    bin: Option<&serde_json::Value>,
    path: &InstallPath,
) -> Result<BTreeMap<BinCommand, BinTarget>, String> {
    use serde_json::Value;
    let mut out = BTreeMap::new();
    match bin {
        Some(Value::Object(map)) => {
            for (cmd, target) in map {
                let Value::String(t) = target else {
                    return Err(format!(
                        "bin target for `{cmd}` is not a string ({})",
                        json_shape(target)
                    ));
                };
                insert_bin(&mut out, cmd, t)?;
            }
        }
        Some(Value::String(target)) => {
            insert_bin(&mut out, unscoped_name(path.package_portion()), target)?;
        }
        // Absent or explicitly null — the package declares no binaries.
        None | Some(Value::Null) => {}
        Some(other) => {
            return Err(format!(
                "bin is not an object or string ({})",
                json_shape(other)
            ));
        }
    }
    Ok(out)
}

/// The JSON type name of a value, for naming the offending shape in a
/// [`parse_bins`] refusal (the value itself may be arbitrary lockfile content, so
/// the error quotes its *shape*, not its bytes).
const fn json_shape(value: &serde_json::Value) -> &'static str {
    use serde_json::Value;
    match value {
        Value::Null => "null",
        Value::Bool(_) => "a boolean",
        Value::Number(_) => "a number",
        Value::String(_) => "a string",
        Value::Array(_) => "an array",
        Value::Object(_) => "an object",
    }
}

/// Validate one `command → target` pair into the typed map, or `Err` with a
/// teaching detail naming the offending value.
fn insert_bin(
    out: &mut BTreeMap<BinCommand, BinTarget>,
    cmd: &str,
    target: &str,
) -> Result<(), String> {
    // One reason per refusal: a control or invisible character is named as
    // such, everything else is the escape it would be.
    let why = |raw: &str, escapes: &str| {
        if has_unprintable(raw) {
            "has a control or invisible character"
        } else {
            escapes
        }
        .to_string()
    };
    let command = BinCommand::parse(cmd)
        .ok_or_else(|| format!("command {} ({cmd})", why(cmd, "escapes .bin")))?;
    let bin_target = BinTarget::parse(target)
        .ok_or_else(|| format!("target {} ({target})", why(target, "escapes the package")))?;
    out.insert(command, bin_target);
    Ok(())
}

/// The unscoped package name: `@scope/foo` → `foo`, `foo` → `foo`.
fn unscoped_name(portion: &str) -> &str {
    portion
        .strip_prefix('@')
        .and_then(|rest| rest.split_once('/'))
        .map_or(portion, |(_, name)| name)
}

// The live classification model is `classify::EntryDisposition` (Install / Link /
// SkipOptionalMismatch / Omitted / Skip) plus `classify::RefuseReason`. The
// classify precedence machine maps each entry straight to a disposition, so a
// separate "what kind of entry" enum would be a redundant parallel model.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{integrity_of, sha256_sri, sha512_sri};

    // --- B: InstallPath ---

    #[test]
    fn root_path() {
        let p = InstallPath::new("");
        assert!(p.is_root());
        assert_eq!(p.depth(), 0);
    }

    #[test]
    fn depth_one() {
        let p = InstallPath::new("node_modules/foo");
        assert_eq!(p.depth(), 1);
    }

    #[test]
    fn scoped_not_split_on_scope_slash() {
        let p = InstallPath::new("node_modules/@scope/foo");
        assert_eq!(p.depth(), 1);
    }

    #[test]
    fn nested_depth_two() {
        let p = InstallPath::new("node_modules/foo/node_modules/bar");
        assert_eq!(p.depth(), 2);
    }

    #[test]
    fn nested_scoped_depth_two() {
        let p = InstallPath::new("node_modules/@scope/foo/node_modules/@s2/bar");
        assert_eq!(p.depth(), 2);
    }

    #[test]
    fn node_modules_inside_a_name_is_not_a_boundary() {
        // `node_modules/` nests only as a whole path component — the key's
        // start or right after a `/` — never as the tail of a name segment.
        let p = InstallPath::new("node_modules/@foo-node_modules/x");
        assert_eq!(p.depth(), 1);
        assert_eq!(p.package_portion(), "@foo-node_modules/x");
        assert_eq!(package_portion_of(p.as_str()), "@foo-node_modules/x");

        let p = InstallPath::new("node_modules/@node_modules/x");
        assert_eq!(p.depth(), 1);
        assert_eq!(p.package_portion(), "@node_modules/x");

        let p = InstallPath::new("node_modules/x-node_modules/node_modules/@foo-node_modules/y");
        assert_eq!(p.depth(), 2);
        assert_eq!(p.package_portion(), "@foo-node_modules/y");
    }

    #[test]
    fn nm_relative_strips_top_level_prefix() {
        assert_eq!(
            InstallPath::new("node_modules/foo").nm_relative(),
            Some("foo")
        );
        assert_eq!(
            InstallPath::new("node_modules/@scope/foo").nm_relative(),
            Some("@scope/foo")
        );
        assert_eq!(
            InstallPath::new("node_modules/a/node_modules/b").nm_relative(),
            Some("a/node_modules/b")
        );
        // Root / sibling-escape never reach materialization.
        assert_eq!(InstallPath::new("").nm_relative(), None);
        assert_eq!(InstallPath::new("../sibling").nm_relative(), None);
    }

    #[test]
    fn package_portion_is_after_last_node_modules() {
        assert_eq!(
            InstallPath::new("node_modules/foo").package_portion(),
            "foo"
        );
        assert_eq!(
            InstallPath::new("node_modules/@scope/foo").package_portion(),
            "@scope/foo"
        );
        assert_eq!(
            InstallPath::new("node_modules/a/node_modules/@s/b").package_portion(),
            "@s/b"
        );
    }

    #[test]
    fn containment_classifies_keys() {
        use Containment::{Contained, Malformed, SiblingEscape};
        assert_eq!(InstallPath::new("").containment(), Contained);
        assert_eq!(
            InstallPath::new("node_modules/foo").containment(),
            Contained
        );
        assert_eq!(InstallPath::new("packages/a").containment(), Contained);
        assert_eq!(InstallPath::new("../fuz_app").containment(), SiblingEscape);
        assert_eq!(
            InstallPath::new("../../sibling").containment(),
            SiblingEscape
        );
        assert_eq!(
            InstallPath::new("node_modules/x/../../../y").containment(),
            Malformed
        );
        assert_eq!(InstallPath::new("/etc/cron.d/x").containment(), Malformed);
        // An ancestor directory itself — npm's key for the target of a
        // `file:..` link. Out of the tree and never materialized, like a sibling.
        assert_eq!(InstallPath::new("..").containment(), SiblingEscape);
        assert_eq!(InstallPath::new("../..").containment(), SiblingEscape);
        // Only when the run of `..` is the whole key or leads a plain path.
        assert_eq!(InstallPath::new("../x/..").containment(), Malformed);
        assert_eq!(InstallPath::new("../../x/../..").containment(), Malformed);
        assert_eq!(InstallPath::new("x/..").containment(), Malformed);
        assert_eq!(InstallPath::new("../").containment(), Malformed);
        assert_eq!(InstallPath::new("../../").containment(), Malformed);
        assert_eq!(InstallPath::new("foo/../bar").containment(), Malformed);
    }

    #[test]
    fn containment_refuses_empty_and_dot_components() {
        use Containment::Malformed;
        // Empty component from `//` — the double-slash escape vector: a raw-string
        // `strip_prefix` would leave an absolute remainder that `join` follows out
        // of the staging root. `Path::components()` normalizes it away, so the gate
        // must catch it on the raw string here.
        assert_eq!(
            InstallPath::new("node_modules//etc").containment(),
            Malformed
        );
        // Trailing slash — an empty final component (`nm_relative` → "").
        assert_eq!(InstallPath::new("node_modules/").containment(), Malformed);
        // Interior double slash.
        assert_eq!(
            InstallPath::new("node_modules/foo//bar").containment(),
            Malformed
        );
        // `.` current-dir components: interior and trailing.
        assert_eq!(
            InstallPath::new("node_modules/./x").containment(),
            Malformed
        );
        assert_eq!(
            InstallPath::new("node_modules/foo/.").containment(),
            Malformed
        );
    }

    #[test]
    fn containment_keeps_legitimate_keys_past_the_empty_dot_gate() {
        use Containment::{Contained, SiblingEscape};
        // The widened gate must not disturb well-formed keys.
        assert_eq!(InstallPath::new("").containment(), Contained); // root whole-string
        assert_eq!(
            InstallPath::new("node_modules/foo").containment(),
            Contained
        );
        assert_eq!(
            InstallPath::new("node_modules/@scope/foo").containment(),
            Contained
        );
        assert_eq!(
            InstallPath::new("node_modules/a/node_modules/b").containment(),
            Contained
        );
        assert_eq!(InstallPath::new("packages/a").containment(), Contained);
        assert_eq!(InstallPath::new("../fuz_app").containment(), SiblingEscape);
        assert_eq!(
            InstallPath::new("../../sibling").containment(),
            SiblingEscape
        );
        // `.bin` is a structurally-valid key (a leading-dot component, not empty
        // and not `.`), so it stays `Contained` — the reserved-name refusal lives
        // in classify, not here.
        assert_eq!(
            InstallPath::new("node_modules/.bin").containment(),
            Contained
        );
    }

    // --- A: Integrity::parse ---

    #[test]
    fn single_sha512() {
        let sri = sha512_sri(b"abc");
        assert!(matches!(
            Integrity::parse(Some(&sri)),
            IntegrityParse::Ok(_)
        ));
    }

    #[test]
    fn multi_hash_sha512_first() {
        let sri = format!("{} {}", sha512_sri(b"abc"), sha256_sri(b"abc"));
        match Integrity::parse(Some(&sri)) {
            IntegrityParse::Ok(i) => assert!(i.to_sri().starts_with("sha512-")),
            other => panic!("expected Ok, got {other:?}"),
        }
    }

    #[test]
    fn multi_hash_sha512_last() {
        let sri = format!("{} {}", sha256_sri(b"abc"), sha512_sri(b"abc"));
        match Integrity::parse(Some(&sri)) {
            IntegrityParse::Ok(i) => assert!(i.to_sri().starts_with("sha512-")),
            other => panic!("expected Ok, got {other:?}"),
        }
    }

    #[test]
    fn duplicate_identical_sha512_is_ok() {
        // The same digest twice is harmless (idempotent), not a conflict.
        let one = sha512_sri(b"abc");
        let sri = format!("{one} {one}");
        assert!(matches!(
            Integrity::parse(Some(&sri)),
            IntegrityParse::Ok(_)
        ));
    }

    #[test]
    fn conflicting_sha512_refused() {
        // Two *different* sha512 digests for one tarball — a tamper signal npm
        // never emits. Refuse rather than silently pick one.
        let sri = format!("{} {}", sha512_sri(b"abc"), sha512_sri(b"xyz"));
        assert!(matches!(
            Integrity::parse(Some(&sri)),
            IntegrityParse::Malformed(_)
        ));
    }

    #[test]
    fn sha1_only_refused() {
        // a sha1 SRI token: 20-byte digest, base64. Build a plausible one.
        let sri = "sha1-qZk+NkcGgWq6PiVxeFDCbJzQ2J0=";
        assert_eq!(Integrity::parse(Some(sri)), IntegrityParse::Sha1Only);
    }

    #[test]
    fn unknown_algorithm_beside_sha512_is_ignored() {
        // SRI allows tokens for algorithms a client doesn't model; the sha512 is
        // the trust gate, so a companion token must not void the entry (refusing
        // it would fail the whole install as MalformedIntegrity).
        let sri = format!("{} sha384-{}", sha512_sri(b"abc"), "A".repeat(64));
        assert!(matches!(
            Integrity::parse(Some(&sri)),
            IntegrityParse::Ok(_)
        ));
    }

    #[test]
    fn unknown_algorithm_alone_is_missing_not_malformed() {
        // No usable digest — but the honest report is "no integrity fuzi can
        // use", which teaches "regenerate the lockfile", not "malformed".
        let sri = format!("sha384-{}", "A".repeat(64));
        assert_eq!(Integrity::parse(Some(&sri)), IntegrityParse::Missing);
    }

    #[test]
    fn malformed_sha512_still_refused_beside_a_good_one() {
        // A *corrupt* token stays fatal — that is bad data, not an unmodeled
        // algorithm, and silently preferring the good one would hide tampering.
        let sri = format!("{} sha512-not_base64!!", sha512_sri(b"abc"));
        assert!(matches!(
            Integrity::parse(Some(&sri)),
            IntegrityParse::Malformed(_)
        ));
    }

    #[test]
    fn sha1_with_trailing_space_still_sha1_only() {
        let sri = "sha1-qZk+NkcGgWq6PiVxeFDCbJzQ2J0= ";
        assert_eq!(Integrity::parse(Some(sri)), IntegrityParse::Sha1Only);
    }

    #[test]
    fn missing_integrity() {
        assert_eq!(Integrity::parse(None), IntegrityParse::Missing);
        assert_eq!(Integrity::parse(Some("")), IntegrityParse::Missing);
        assert_eq!(Integrity::parse(Some("   ")), IntegrityParse::Missing);
    }

    #[test]
    fn malformed_base64() {
        assert!(matches!(
            Integrity::parse(Some("sha512-not_base64!!")),
            IntegrityParse::Malformed(_)
        ));
    }

    #[test]
    fn malformed_wrong_length() {
        // valid base64 but wrong digest length for sha512.
        assert!(matches!(
            Integrity::parse(Some("sha512-YWJj")),
            IntegrityParse::Malformed(_)
        ));
    }

    // --- F: retained_under truth table ---

    // The four bools mirror the dependency-reason flags under test.
    #[allow(clippy::fn_params_excessive_bools)]
    fn entry_with(dev: bool, optional: bool, dev_optional: bool, peer: bool) -> RegistryEntry {
        RegistryEntry {
            path: InstallPath::new("node_modules/x"),
            version: None,
            resolved: "https://registry.npmjs.org/x/-/x-1.0.0.tgz".to_string(),
            integrity: integrity_of(b"x"),
            os: vec![],
            cpu: vec![],
            libc: vec![],
            has_install_script: false,
            dev,
            optional,
            dev_optional,
            peer,
            bins: BTreeMap::new(),
        }
    }

    const ALL: &[Omit] = &[];
    const DEV: &[Omit] = &[Omit::Dev];
    const OPT: &[Omit] = &[Omit::Optional];
    const DEV_OPT: &[Omit] = &[Omit::Dev, Omit::Optional];
    const PEER: &[Omit] = &[Omit::Peer];

    #[test]
    fn truth_table_prod_required() {
        let e = entry_with(false, false, false, false);
        assert!(e.retained_under(ALL));
        assert!(e.retained_under(DEV));
        assert!(e.retained_under(OPT));
        assert!(e.retained_under(DEV_OPT));
        assert!(e.retained_under(PEER));
    }

    #[test]
    fn truth_table_dev() {
        let e = entry_with(true, false, false, false);
        assert!(e.retained_under(ALL));
        assert!(!e.retained_under(DEV));
        assert!(e.retained_under(OPT));
        assert!(!e.retained_under(DEV_OPT));
        assert!(e.retained_under(PEER));
    }

    #[test]
    fn truth_table_optional() {
        let e = entry_with(false, true, false, false);
        assert!(e.retained_under(ALL));
        assert!(e.retained_under(DEV));
        assert!(!e.retained_under(OPT));
        assert!(!e.retained_under(DEV_OPT));
        assert!(e.retained_under(PEER));
    }

    #[test]
    fn truth_table_dev_optional() {
        let e = entry_with(false, false, true, false);
        assert!(e.retained_under(ALL));
        assert!(e.retained_under(DEV)); // survives dev alone
        assert!(e.retained_under(OPT)); // survives optional alone
        assert!(!e.retained_under(DEV_OPT)); // only both drop it
        assert!(e.retained_under(PEER));
    }

    #[test]
    fn truth_table_peer() {
        let e = entry_with(false, false, false, true);
        assert!(e.retained_under(ALL));
        assert!(e.retained_under(DEV));
        assert!(e.retained_under(OPT));
        assert!(e.retained_under(DEV_OPT));
        assert!(!e.retained_under(PEER));
    }

    #[test]
    fn truth_table_peer_and_dev() {
        let e = entry_with(true, false, false, true);
        assert!(e.retained_under(ALL));
        assert!(!e.retained_under(DEV)); // dropped by dev
        assert!(e.retained_under(OPT));
        assert!(!e.retained_under(DEV_OPT));
        assert!(!e.retained_under(PEER)); // dropped by peer
    }

    // --- bin command / target reification ---

    #[test]
    fn bin_command_accepts_plain_filenames() {
        assert_eq!(BinCommand::parse("eslint").unwrap().as_str(), "eslint");
        assert_eq!(
            BinCommand::parse("svelte-kit").unwrap().as_str(),
            "svelte-kit"
        );
    }

    #[test]
    fn bin_command_refuses_path_bearing_or_dotted() {
        for bad in ["", ".", "..", "a/b", "..\\evil", "x\0y", "../escape"] {
            assert!(BinCommand::parse(bad).is_none(), "{bad:?} must be refused");
        }
        // A `.bin` name is created in a directory users put on `PATH`: no
        // control or invisible character.
        for bad in [
            "x\u{1b}[2J\nforged\u{202e}",
            "x\ny",
            "x\u{7f}",
            "x\u{9b}31m",
            "vi\u{200b}te",
            "\u{feff}vite",
            "vite\u{3164}",
            "vite\u{fe0f}",
        ] {
            assert!(BinCommand::parse(bad).is_none(), "{bad:?} must be refused");
        }
        // Not an allowlist: printable names outside the package-name set stay.
        for ok in ["c++", "a b", "x:y", "tool@2", "日本語", "caf\u{e9}"] {
            assert!(BinCommand::parse(ok).is_some(), "{ok:?}");
        }
    }

    #[test]
    fn bin_target_accepts_contained_relative_paths() {
        assert_eq!(
            BinTarget::parse("bin/cli.js").unwrap().as_str(),
            "bin/cli.js"
        );
        assert_eq!(
            BinTarget::parse("./dist/run").unwrap().as_str(),
            "./dist/run"
        );
    }

    #[test]
    fn bin_target_refuses_escaping_or_absolute() {
        for bad in ["", "/etc/passwd", "../../x", "a/../../../b", "x\0y", "a\\b"] {
            assert!(BinTarget::parse(bad).is_none(), "{bad:?} must be refused");
        }
        // The target becomes a symlink's text: no control or invisible character.
        for bad in [
            "bin/x\u{1b}[2J",
            "bin/x\ny",
            "bin\u{202e}/cli.js",
            "bin/cli\u{200d}.js",
            "bin/cli.js\u{115f}",
        ] {
            assert!(BinTarget::parse(bad).is_none(), "{bad:?} must be refused");
        }
    }

    #[test]
    fn bin_link_text_is_relative_to_the_enclosing_dot_bin() {
        let bin = BinTarget::parse("bin/cli.js").unwrap();
        for (package, text) in [
            ("node_modules/foo", "../foo/bin/cli.js"),
            ("node_modules/@s/foo", "../@s/foo/bin/cli.js"),
            ("node_modules/a/node_modules/@s/b", "../@s/b/bin/cli.js"),
        ] {
            assert_eq!(bin.bin_link_text(&InstallPath::new(package)), text);
        }
        // The target is kept as the lockfile spells it.
        assert_eq!(
            BinTarget::parse("./cli.js")
                .unwrap()
                .bin_link_text(&InstallPath::new("node_modules/foo")),
            "../foo/./cli.js"
        );
    }

    // --- parse_bins (classify-time bin validation) ---

    #[test]
    fn parse_bins_object_form() {
        let path = InstallPath::new("node_modules/esbuild");
        let bins = parse_bins(Some(&serde_json::json!({"esbuild": "bin/esbuild"})), &path).unwrap();
        assert_eq!(
            bins.get(&BinCommand::parse("esbuild").unwrap())
                .unwrap()
                .as_str(),
            "bin/esbuild"
        );
    }

    #[test]
    fn parse_bins_string_form_uses_unscoped_name() {
        let path = InstallPath::new("node_modules/@scope/cli");
        let bins = parse_bins(Some(&serde_json::json!("dist/run.js")), &path).unwrap();
        assert_eq!(
            bins.get(&BinCommand::parse("cli").unwrap())
                .unwrap()
                .as_str(),
            "dist/run.js"
        );
    }

    #[test]
    fn parse_bins_absent_or_null_is_an_honest_absence() {
        // No `bin` at all, and an explicit null, both mean "this package declares
        // no binaries" — the one shape that is genuinely an absence rather than a
        // malformed declaration.
        let path = InstallPath::new("node_modules/x");
        assert!(parse_bins(None, &path).unwrap().is_empty());
        assert!(
            parse_bins(Some(&serde_json::Value::Null), &path)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn parse_bins_non_string_target_refused() {
        // npm emits only `{cmd: "path"}` or `"path"`. A non-string target is the
        // same "npm never emits this" signal as an escaping one — and skipping it
        // silently would ship a tree whose `.bin/<cmd>` never appears, surfacing
        // much later as `command not found` with nothing pointing back here.
        let path = InstallPath::new("node_modules/x");
        let err = parse_bins(Some(&serde_json::json!({"x": 7})), &path).unwrap_err();
        assert!(err.contains("not a string"), "{err}");
        assert!(err.contains('x'), "must name the offending command: {err}");
    }

    #[test]
    fn parse_bins_non_object_non_string_shape_refused() {
        let path = InstallPath::new("node_modules/x");
        let err = parse_bins(Some(&serde_json::json!([1, 2])), &path).unwrap_err();
        assert!(err.contains("not an object or string"), "{err}");
        assert!(err.contains("an array"), "must name the shape: {err}");
    }

    #[test]
    fn parse_bins_mixed_object_refuses_rather_than_keeping_the_good_half() {
        // A half-valid bin map is a corrupt bin map: linking the string entries
        // and dropping the rest would produce a partially-wired `.bin` that looks
        // like a successful install.
        let path = InstallPath::new("node_modules/x");
        assert!(
            parse_bins(
                Some(&serde_json::json!({"good": "cli.js", "bad": 7})),
                &path,
            )
            .is_err()
        );
    }

    #[test]
    fn parse_bins_escaping_command_refused() {
        let path = InstallPath::new("node_modules/evil");
        let err = parse_bins(Some(&serde_json::json!({"../evil": "ok"})), &path).unwrap_err();
        assert!(err.contains("command escapes .bin"), "{err}");
    }

    #[test]
    fn parse_bins_escaping_target_refused() {
        let path = InstallPath::new("node_modules/evil");
        let err =
            parse_bins(Some(&serde_json::json!({"x": "../../etc/passwd"})), &path).unwrap_err();
        assert!(err.contains("target escapes the package"), "{err}");
    }

    #[test]
    fn parse_bins_refuses_control_or_invisible_characters() {
        // The reviewer's shape: a bin name that clears the screen, forges a
        // line, and flips direction — it would become a file name in `.bin`.
        let path = InstallPath::new("node_modules/picocolors");
        let err = parse_bins(
            Some(&serde_json::json!({"x\u{1b}[2J\nforged\u{202e}": "picocolors.js"})),
            &path,
        )
        .unwrap_err();
        assert!(
            err.contains("command has a control or invisible character"),
            "{err:?}"
        );
        let err =
            parse_bins(Some(&serde_json::json!({"x": "bin/cli\u{200b}.js"})), &path).unwrap_err();
        assert!(
            err.contains("target has a control or invisible character"),
            "{err:?}"
        );
        // The bare-string form's target is held to the same rule.
        assert!(parse_bins(Some(&serde_json::json!("cli\u{3164}.js")), &path).is_err());
    }

    // --- LinkTarget ---

    #[test]
    fn link_target_accepts_only_the_sibling_shape() {
        for raw in ["../zap", "../x", "../fuz-app", "../a.b"] {
            match LinkTarget::parse(raw) {
                LinkTargetParse::Ok(t) => {
                    assert_eq!(t.as_resolved(), raw);
                    assert_eq!(t.segment(), &raw[3..]);
                }
                other => panic!("{raw:?} should parse as a sibling, got {other:?}"),
            }
        }
    }

    #[test]
    fn link_target_defers_the_unsupported_well_formed_shapes() {
        for raw in [
            "packages/css6",            // in-tree workspace (webref)
            "_packages/native-preview", // in-tree, underscore dir
            "../../x",                  // multi-level
            "../../../a/b",             // multi-level, multi-component
            "../a/b",                   // multi-component sibling
            "..",                       // ancestor
            "../..",                    // ancestor (npm writes it for `file:../..`)
        ] {
            assert!(
                matches!(LinkTarget::parse(raw), LinkTargetParse::Deferred(_)),
                "{raw:?} should be deferred"
            );
        }
    }

    #[test]
    fn link_target_refuses_what_npm_never_writes() {
        for raw in [
            "",                // empty
            "/abs/x",          // absolute
            "~/x",             // home-relative
            "file:../x",       // scheme
            "git+https://h/x", // scheme
            "../x\0y",         // NUL
            "../x\ny",         // C0 control (newline)
            "../x\ty",         // C0 control (tab)
            "../x\u{1b}y",     // C0 control (escape)
            "../x\u{7f}y",     // DEL
            "..\\x",           // backslash
            "x/../..",         // embedded `..`
            "../a/../b",       // embedded `..` after the leading run
            "packages/../x",   // embedded `..` in-tree
            "../",             // trailing slash — empty component
            "..//x",           // empty component
            "./x",             // `.` component
            "../.hidden",      // dot-leading sibling
        ] {
            assert!(
                matches!(LinkTarget::parse(raw), LinkTargetParse::Malformed(_)),
                "{raw:?} should be malformed, got {:?}",
                LinkTarget::parse(raw)
            );
        }
    }

    #[test]
    fn link_target_refuses_control_and_invisible_characters() {
        // The segment becomes a symlink's text and is printed in messages: no
        // C1 control, bidi mark or override, zero-width character, separator,
        // or BOM — anywhere in `resolved`, not only in a sibling segment.
        for c in [
            '\u{85}', '\u{9b}', '\u{ad}', '\u{200b}', '\u{200e}', '\u{200f}', '\u{202a}',
            '\u{202e}', '\u{2028}', '\u{2029}', '\u{2066}', '\u{2069}', '\u{feff}',
        ] {
            for raw in [format!("../x{c}y"), format!("{c}../x"), format!("pkgs/{c}")] {
                assert!(
                    matches!(LinkTarget::parse(&raw), LinkTargetParse::Malformed(_)),
                    "{raw:?} should be malformed, got {:?}",
                    LinkTarget::parse(&raw)
                );
            }
        }
    }

    #[test]
    fn link_target_caps_the_sibling_segment_at_name_max() {
        // 255 bytes is the longest name a directory can have; a longer segment
        // is not a directory npm resolved a link to.
        let longest = format!("../{}", "a".repeat(255));
        assert!(matches!(
            LinkTarget::parse(&longest),
            LinkTargetParse::Ok(_)
        ));
        let over = format!("../{}", "a".repeat(256));
        assert!(matches!(
            LinkTarget::parse(&over),
            LinkTargetParse::Malformed(_)
        ));
        // Bytes, not characters: 128 two-byte characters are 256 bytes.
        let multibyte = format!("../{}", "é".repeat(128));
        assert!(matches!(
            LinkTarget::parse(&multibyte),
            LinkTargetParse::Malformed(_)
        ));
    }

    #[test]
    fn link_target_refuses_a_sibling_named_node_modules() {
        // `../node_modules` is the parent directory's own `node_modules`, where
        // Node resolves the project's bare imports — not a package beside the
        // project. Any case: a case-folding filesystem makes them one directory.
        for raw in ["../node_modules", "../Node_Modules", "../NODE_MODULES"] {
            assert!(
                matches!(LinkTarget::parse(raw), LinkTargetParse::Malformed(_)),
                "{raw:?}"
            );
        }
        // A name that merely contains it is an ordinary sibling.
        for raw in ["../node_modules2", "../my-node_modules", "../node-modules"] {
            assert!(
                matches!(LinkTarget::parse(raw), LinkTargetParse::Ok(_)),
                "{raw:?}"
            );
        }
    }

    #[test]
    fn link_target_reads_every_component_literally() {
        // Pin: `resolved` is never decoded, normalized, or trimmed. Each row is
        // judged on its raw `/`-separated components, so an encoded or
        // lookalike `..` is a name, never a traversal.
        use LinkTargetParse::{Deferred, Malformed};
        for (raw, expected) in [
            ("../.", "malformed"),    // `.` component
            ("../a/..", "malformed"), // embedded `..` after the leading run
            ("../a/", "malformed"),   // trailing slash — empty component
            ("./../a", "malformed"),  // leading `.` component
            ("%2e%2e/a", "deferred"), // percent-encoded `..`: an in-tree name
            ("..%2fa", "deferred"),   // percent-encoded `/`: one in-tree name
            ("%2e%2e%2fa", "deferred"),
            ("\u{2025}/a", "deferred"), // TWO DOT LEADER: an in-tree name
            ("\u{ff0e}\u{ff0e}/a", "deferred"), // fullwidth full stops
            ("\u{2024}\u{2024}/a", "deferred"), // ONE DOT LEADER twice
        ] {
            let parsed = LinkTarget::parse(raw);
            let got = match &parsed {
                LinkTargetParse::Ok(_) => "ok",
                Deferred(_) => "deferred",
                Malformed(_) => "malformed",
            };
            assert_eq!(got, expected, "{raw:?}: {parsed:?}");
        }
        // Accepted as literal sibling names — safe because fuzi never decodes
        // the segment and never hands it to a shell (it runs nothing).
        for raw in [
            "../-rf",
            "../--help",
            "../a%2fb",
            "../a%00b",
            "../\u{ff0e}hidden", // a fullwidth full stop is not a leading dot
            "../a b",
            "../$(x)",
        ] {
            match LinkTarget::parse(raw) {
                LinkTargetParse::Ok(t) => assert_eq!(t.segment(), &raw[3..], "{raw:?}"),
                other => panic!("{raw:?} should parse as a literal sibling, got {other:?}"),
            }
        }
    }

    #[test]
    fn link_target_does_not_normalize_unicode() {
        // Pin: an NFC and an NFD spelling of one name are two segments. The
        // target-entry lookup is byte-exact, so a link and a target entry that
        // disagree on the form do not pair up.
        let nfc = "../caf\u{e9}";
        let nfd = "../cafe\u{301}";
        let (LinkTargetParse::Ok(a), LinkTargetParse::Ok(b)) =
            (LinkTarget::parse(nfc), LinkTarget::parse(nfd))
        else {
            panic!("both forms are well-formed siblings");
        };
        assert_ne!(a, b);
        assert_eq!(a.as_resolved(), nfc);
        assert_eq!(b.as_resolved(), nfd);
    }

    #[test]
    fn link_target_relative_from_climbs_out_of_the_link_parent() {
        let LinkTargetParse::Ok(zap) = LinkTarget::parse("../zap") else {
            panic!("sibling must parse");
        };
        // npm's own shape in the fuz projects' lockfiles.
        assert_eq!(
            zap.relative_from(&InstallPath::new("node_modules/@fuzdev/zap")),
            "../../../zap"
        );
        assert_eq!(
            zap.relative_from(&InstallPath::new("node_modules/zap")),
            "../../zap"
        );
    }

    #[test]
    fn link_target_dir_in_is_the_sibling_of_the_project() {
        let LinkTargetParse::Ok(t) = LinkTarget::parse("../lib") else {
            panic!("sibling must parse");
        };
        assert_eq!(
            t.dir_in(std::path::Path::new("/w/app")),
            std::path::Path::new("/w/app/../lib")
        );
    }
}
