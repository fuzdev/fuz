//! Classify every `packages`-map entry into a disposition, accumulating
//! refusals rather than failing fast (report *every* problem in one pass).
//!
//! # Links
//!
//! A `link: true` entry is a symlink to local source, not a tarball. npm writes
//! one as `{resolved: <path from the project root to the target>, link: true}`
//! plus a **target entry** keyed by that path, carrying the package's
//! `version`, flags, and `bin` — and its `name` only when that differs from
//! npm's default for the target folder. fuzi places the sibling shape — a depth-1 link
//! key whose `resolved` is exactly `../<dir>` — and refuses every other shape
//! with a teaching reason ([`RefuseReason::LinkUnsupported`] for a well-formed
//! shape not placed yet, [`RefuseReason::MalformedLink`] for one npm never
//! writes). The target entry itself is skipped, so a refusal lands once, on the
//! link; a key nested *under* a link key is refused
//! ([`RefuseReason::NestedUnderLink`]), since installing it would extract through
//! the symlink into the target.

use std::collections::{BTreeMap, BTreeSet};

use crate::Omit;
use crate::entry::{
    Containment, DepFlags, InstallPath, Integrity, IntegrityParse, LinkEntry, LinkTarget,
    LinkTargetParse, RegistryEntry, parse_bins, retained,
};
use crate::lockfile::raw::{RawLockfile, RawPackageEntry};
use crate::platform::{Platform, parse_cpu_axis, parse_libc_axis, parse_os_axis};
use crate::resolved::{ResolvedKind, classify_resolved};
use crate::text::is_package_name_char;
use fuz_sys::text::escape_untrusted;

/// One refused entry with its teaching reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// The offending entry path.
    pub path: InstallPath,
    /// Why it was refused.
    pub reason: RefuseReason,
}

/// Why an entry (or the lockfile) was refused. Each renders to a teaching line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefuseReason {
    /// Only sha1 token(s) present in `integrity`.
    Sha1Integrity,
    /// No usable `integrity` (degraded entry — regenerate the lockfile).
    MissingIntegrity,
    /// Valid `integrity` but no `resolved` URL — not a fetchable tarball. npm
    /// writes registry entries this way under its
    /// `omit-lockfile-registry-resolved` config, leaving the URL to be derived
    /// from the configured registry at install time; fuzi reads no `.npmrc`,
    /// so it cannot derive one and teaches the config instead.
    MissingResolved,
    /// The `packages`-map key is not a well-formed install path: it escapes
    /// the project root by something other than a benign leading run of `..`
    /// (a sibling `../x` or an ancestor `../..`) — an embedded `..`, an
    /// absolute prefix — or carries a NUL, a backslash, or an empty (`//`,
    /// trailing `/`) or `.` component. Corruption/tampering in a lockfile.
    MalformedInstallPath(String),
    /// An `integrity` token failed base64/length validation.
    MalformedIntegrity(String),
    /// `resolved` is a `git+…` dependency.
    GitDep(String),
    /// `resolved` is a `file:` or bare relative dependency.
    FileDep(String),
    /// `resolved` is `http://` or any non-`https` scheme.
    NonHttpsResolved(String),
    /// `resolved` is an `https` URL whose host is an internal/SSRF target — an
    /// internal literal IP (loopback, link-local, private, multicast, … — an
    /// IPv6 form embedding an IPv4 is judged by that IPv4; the `resolved`
    /// module lists the classes), or an internal host named directly (`localhost`, a single-label dotless host, or a `.localhost` /
    /// `.local` / `.internal` domain such as `metadata.google.internal`). A
    /// tampered lockfile could use it to make fuzi fire a GET at an internal
    /// endpoint before the integrity check runs. Carries `url: reason`.
    BlockedResolvedHost(String),
    /// `link: true` in a well-formed shape fuzi does not place: an in-tree
    /// workspace target (`packages/a`), a multi-level or multi-component target
    /// (`../../x`, `../a/b`), an ancestor directory (`..`, `../..`), or a nested
    /// link key. npm writes all of these, so regenerating the lockfile
    /// reproduces them. Only a depth-1 link to a sibling directory (`../<dir>`)
    /// is placed. Carries a teaching detail.
    LinkUnsupported(String),
    /// A `link: true` entry in a shape npm never writes: a `resolved` that is
    /// missing, absolute, home-relative, a scheme (`file:`), carries a control
    /// or invisible character, backslash, empty/`.` component, or embedded `..`,
    /// or names a sibling that is dot-leading, named `node_modules`, or longer
    /// than a directory name; a link entry carrying any field besides
    /// `resolved` and `link`; or a target entry that is missing, empty-named,
    /// itself a link, extraneous, bundled, or a tarball
    /// (`resolved`/`integrity`). A tampered or corrupt lockfile. Carries a
    /// teaching detail.
    MalformedLink(String),
    /// An entry keyed *under* a link key (`node_modules/<link>/…`). Installing it
    /// would extract through the symlink into the link's target — a directory
    /// fuzi never writes to — and npm never writes such a key (a linked target's
    /// own dependencies are its business, not the linking project's). Checked
    /// before the `extraneous` skip, for the same reason containment is. Carries
    /// the offending key.
    NestedUnderLink(String),
    /// `inBundle: true` — the entry ships inside an ancestor's tarball
    /// (`bundleDependencies`). Deferred (model-and-refuse): none of the fuz
    /// projects' own lockfiles carry one, and *both* plausible behaviors are
    /// wrong without real data — fetching it separately double-writes the same
    /// paths the parent's own extraction produces (a race, since extraction is
    /// concurrent), while skipping it silently under-installs a root-level
    /// `bundleDependencies` entry, which has no parent tarball to come from.
    /// Refusing is honest until a real lockfile exercises it. (A bundling parent
    /// typically also ships intra-tarball `.bin` symlinks, which
    /// `SymlinkPolicy::Reject` fails anyway — this refusal replaces that opaque
    /// extraction error with a teaching one.)
    BundledUnsupported,
    /// A platform axis token npm never writes: empty, double-negated (`!!x`),
    /// or `!any`. npm reads `!any` as excluding a platform literally named
    /// "any" — a no-op — so fuzi refuses it rather than guess what was meant.
    /// Carries the offending token.
    MalformedPlatformToken(String),
    /// An *installed* entry's `bin` declares a path-bearing command, an
    /// escaping/absolute target, or a control or invisible character in either
    /// — something npm never emits (a tampered or corrupt lockfile). Carries a
    /// teaching detail naming the offender. Only raised for entries fuzi would
    /// actually link (not for omitted/skipped ones).
    MalformedBin(String),
    /// A placed entry (registry or link) whose key is *contained* but not a
    /// `node_modules/…` materialization target (e.g. a tampered `packages/x` key
    /// carrying `resolved`/`integrity`). npm only emits registry tarballs and
    /// links under `node_modules/`; a real `packages/…` workspace entry is local source with
    /// no integrity (and refuses earlier). Refusing makes "every `Install` is a
    /// `node_modules/` key" a real invariant rather than a fetch-then-silently-skip.
    NonNodeModulesInstall(String),
    /// A placed entry (registry or link) keyed under an in-tree workspace's own
    /// `node_modules` (`packages/a/node_modules/x`, typescript-go's
    /// `_packages/<pkg>/node_modules/<dep>`): a workspace dependency npm did
    /// not hoist. Real npm output, so regenerating reproduces it — fuzi does
    /// not install workspaces, and says so with the same line as
    /// [`LinkUnsupported`]. Distinct from [`NonNodeModulesInstall`], a
    /// non-`node_modules` key that is a tamper signal. Carries the key.
    ///
    /// [`LinkUnsupported`]: RefuseReason::LinkUnsupported
    /// [`NonNodeModulesInstall`]: RefuseReason::NonNodeModulesInstall
    WorkspaceInstall(String),
    /// A fetchable registry entry whose `node_modules`-relative path carries a
    /// component beginning with `.` — `node_modules/.bin`, `.package-lock.json`,
    /// `.cache`, or any hidden name at any nesting depth. npm package names may
    /// never begin with `.` (or `_`), so the only legitimate `nm_relative`
    /// components are the literal `node_modules`, a package name, or an `@scope`
    /// segment — none dot-leading. The path is structurally well-formed, so the
    /// [`Containment`] gate passes it; but a dot-leading component is not a valid
    /// npm package name, and materializing it would write into the `.bin`
    /// directory fuzi manages (or another hidden slot). Inherently
    /// case-independent — it never compares against a fixed name. Carries the
    /// offending key.
    DotLeadingComponent(String),
    /// A fetchable registry entry whose `node_modules`-relative path is *not* a
    /// proper package-nesting — the grammar `<pkg>(/node_modules/<pkg>)*`, where
    /// each `<pkg>` is a plain `name` or a scoped `@scope/name`. A key like
    /// `node_modules/foo/bar` (where `bar` follows no `node_modules/` boundary)
    /// passes [`Containment`] and the `node_modules/` prefix check, so it would
    /// classify to Install and stage under `<root>/foo/bar` — the *exact* path a
    /// `node_modules/foo` placement whose tarball ships `bar/…` also writes. Two
    /// concurrent workers would then race the same path, the very
    /// timing-dependent non-determinism the vendored-`node_modules` extraction
    /// skip removes, via a path that skip does not reach (it strips only
    /// `node_modules`-component entries, and `bar` is an ordinary directory).
    /// npm never emits such a key; refusing it at classify time keeps "every
    /// Install stages to a race-free, sole-writer path" a real invariant. Carries
    /// the offending key. Distinct from [`NonNodeModulesInstall`] (a key not under
    /// `node_modules/` at all) and [`DotLeadingComponent`] (a dot-leading name).
    ///
    /// [`NonNodeModulesInstall`]: RefuseReason::NonNodeModulesInstall
    /// [`DotLeadingComponent`]: RefuseReason::DotLeadingComponent
    MalformedInstallNesting(String),
    /// A placed entry (a registry tarball or a link) whose `node_modules` key
    /// holds a character an npm package name cannot: anything but an ASCII
    /// letter or digit or one of `-._~!'()*`, with `@` only opening a scope and
    /// `/` only separating components. That is npm's own rule (a name must
    /// survive `encodeURIComponent` unchanged), so no key npm writes for a real
    /// package is refused. What is refused is a key that would become a
    /// directory name reading as another package's — a lookalike letter, a
    /// space, an invisible or direction-changing character — or driving the
    /// terminal that prints it. Carries the offending key, raw — every human
    /// rendering escapes it.
    InvalidNameCharacter(String),
    /// A REQUIRED entry's `os`/`cpu`/`libc` excludes the host.
    PlatformMismatchRequired,
}

impl RefuseReason {
    /// A stable machine-readable code for the `--json` refusal contract — the
    /// per-refusal analog of [`crate::FuziError::kind`].
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Sha1Integrity => "sha1_integrity",
            Self::MissingIntegrity => "missing_integrity",
            Self::MissingResolved => "missing_resolved",
            Self::MalformedInstallPath(_) => "malformed_install_path",
            Self::MalformedIntegrity(_) => "malformed_integrity",
            Self::GitDep(_) => "git_dep",
            Self::FileDep(_) => "file_dep",
            Self::NonHttpsResolved(_) => "non_https_resolved",
            Self::BlockedResolvedHost(_) => "blocked_resolved_host",
            Self::LinkUnsupported(_) => "link_unsupported",
            Self::MalformedLink(_) => "malformed_link",
            Self::NestedUnderLink(_) => "nested_under_link",
            Self::BundledUnsupported => "bundled_unsupported",
            Self::MalformedPlatformToken(_) => "malformed_platform_token",
            Self::MalformedBin(_) => "malformed_bin",
            Self::NonNodeModulesInstall(_) => "non_node_modules_install",
            Self::WorkspaceInstall(_) => "workspace_install",
            Self::DotLeadingComponent(_) => "dot_leading_component",
            Self::MalformedInstallNesting(_) => "malformed_install_nesting",
            Self::InvalidNameCharacter(_) => "invalid_name_character",
            Self::PlatformMismatchRequired => "platform_mismatch_required",
        }
    }

    /// The human-readable reason fragment. Carries the offending lockfile text
    /// raw; a caller printing it for a person passes it through
    /// [`escape_untrusted`], as the refusal block
    /// rendered by [`FuziError::Refused`](crate::FuziError::Refused) does.
    #[must_use]
    pub fn why(&self) -> String {
        match self {
            Self::Sha1Integrity => "sha1-only integrity".to_string(),
            Self::MissingIntegrity => "missing integrity".to_string(),
            Self::MissingResolved => {
                "integrity present but no resolved url (omit-lockfile-registry-resolved)"
                    .to_string()
            }
            Self::MalformedInstallPath(k) => {
                format!("install path escapes the project root ({k})")
            }
            Self::MalformedIntegrity(e) => format!("malformed integrity ({e})"),
            Self::GitDep(r) => format!("git dependency ({r})"),
            Self::FileDep(r) => format!("file/relative dependency ({r})"),
            Self::NonHttpsResolved(r) => format!("non-https resolved url ({r})"),
            Self::BlockedResolvedHost(d) => format!("blocked resolved host — {d}"),
            Self::LinkUnsupported(t) => format!("link dependency in an unsupported shape ({t})"),
            Self::MalformedLink(d) => format!("malformed link entry — {d}"),
            Self::NestedUnderLink(k) => format!("entry nested under a linked package ({k})"),
            Self::BundledUnsupported => "bundled dependency (inBundle)".to_string(),
            Self::MalformedPlatformToken(t) => format!("malformed platform token ({t})"),
            Self::MalformedBin(d) => format!("malformed bin — {d}"),
            Self::NonNodeModulesInstall(k) => {
                format!("entry at a non-node_modules key ({k})")
            }
            Self::WorkspaceInstall(k) => {
                format!("entry inside an in-tree workspace's node_modules ({k})")
            }
            Self::DotLeadingComponent(k) => {
                format!(
                    "node_modules path has a dot-leading component ({k}); npm package names never begin with '.'"
                )
            }
            Self::MalformedInstallNesting(k) => {
                format!("install path is not a proper node_modules package-nesting ({k})")
            }
            Self::InvalidNameCharacter(k) => {
                format!("node_modules path has a character npm package names cannot contain ({k})")
            }
            Self::PlatformMismatchRequired => "required entry excludes this platform".to_string(),
        }
    }

    /// The next-step hint.
    #[must_use]
    pub const fn next_step(&self) -> &'static str {
        match self {
            Self::Sha1Integrity | Self::MissingIntegrity => {
                "regenerate the lockfile with npm 7+ (npm install)"
            }
            Self::MissingResolved => {
                "this lockfile was written under npm's omit-lockfile-registry-resolved config, and fuzi fetches only the resolved urls a lockfile records; turn the config off, then delete package-lock.json and regenerate it (npm install --package-lock-only) — npm keeps an existing lockfile's missing urls, and regenerating re-resolves versions"
            }
            Self::MalformedIntegrity(_) => "regenerate the lockfile (npm install)",
            Self::MalformedInstallPath(_) => {
                "this lockfile entry's path escapes the project root; regenerate it (npm install)"
            }
            Self::GitDep(_) | Self::FileDep(_) => {
                "fuzi installs registry tarballs only; remove or vendor this dependency"
            }
            Self::NonHttpsResolved(_) => "use an https registry url",
            Self::BlockedResolvedHost(_) => {
                "this lockfile's resolved url points at an internal/metadata host; regenerate it against the public registry"
            }
            Self::LinkUnsupported(_) | Self::WorkspaceInstall(_) => WORKSPACES_UNSUPPORTED,
            Self::MalformedLink(_) => {
                "npm writes a link as only {resolved: <relative path>, link: true} beside its target entry; regenerate the lockfile (npm install)"
            }
            Self::NestedUnderLink(_) => {
                "a linked package's own dependencies are not installed through the link, and npm never writes such a key; regenerate the lockfile (npm install)"
            }
            Self::BundledUnsupported => {
                "fuzi does not install bundled dependencies (bundleDependencies); unbundle the package or vendor it"
            }
            Self::MalformedPlatformToken(_) => "fix the os/cpu/libc field in the lockfile",
            Self::MalformedBin(_) => {
                "this package's bin is not a plain command name pointing at a file inside the package (it escapes its directory, or carries a control or invisible character); npm never emits this — regenerate the lockfile (npm install)"
            }
            Self::NonNodeModulesInstall(_) => {
                "a registry tarball must install under node_modules/; regenerate the lockfile (npm install)"
            }
            Self::DotLeadingComponent(_) => {
                "npm package names never begin with '.', so this node_modules path is not a valid package; regenerate the lockfile (npm install)"
            }
            Self::MalformedInstallNesting(_) => {
                "a node_modules install path must nest as <pkg>/node_modules/<pkg>…; regenerate the lockfile (npm install)"
            }
            Self::InvalidNameCharacter(_) => {
                "npm package names hold only ASCII letters, digits, and -._~!'()*, so this node_modules path is not a valid package; regenerate the lockfile (npm install)"
            }
            Self::PlatformMismatchRequired => {
                "this lockfile was generated for another platform; regenerate it on this host"
            }
        }
    }
}

/// The next step for a workspace-shaped lockfile — a link fuzi does not place
/// or a registry entry under an in-tree workspace's `node_modules`.
const WORKSPACES_UNSUPPORTED: &str = "fuzi links sibling packages only (a depth-1 link whose resolved is ../<dir>); in-tree workspaces, ancestor and multi-level targets, and nested links are not supported — install this project with npm";

/// The disposition of one classified entry.
#[derive(Debug, Clone)]
pub enum EntryDisposition {
    /// Fetch + place.
    Install(Box<RegistryEntry>),
    /// Place a symlink to a sibling directory (no fetch, no extraction).
    Link(Box<LinkEntry>),
    /// An OPTIONAL entry whose platform excludes the host — silently skip.
    SkipOptionalMismatch(InstallPath),
    /// Omitted by the `--omit` set.
    Omitted(InstallPath),
    /// Skip — extraneous / escapes-root / the root `""` entry.
    Skip(InstallPath),
}

/// Classify every entry.
///
/// Returns dispositions in deterministic (`BTreeMap`) order plus accumulated
/// refusals. A non-empty refusal list means the caller raises
/// `FuziError::Refused`; `classify` itself never fails fast.
#[must_use]
pub fn classify(
    raw: &RawLockfile,
    host: &Platform,
    omit: &[Omit],
) -> (Vec<EntryDisposition>, Vec<Refusal>) {
    let mut dispositions = Vec::with_capacity(raw.packages.len());
    let mut refusals = Vec::new();
    let links = LinkIndex::new(&raw.packages);

    for (key, entry) in &raw.packages {
        let path = InstallPath::new(key.clone());
        match classify_one(&path, entry, host, omit, &links) {
            Ok(disposition) => dispositions.push(disposition),
            Err(reason) => {
                refusals.push(Refusal {
                    path: path.clone(),
                    reason,
                });
            }
        }
    }

    (dispositions, refusals)
}

/// The lockfile's link structure, computed once per [`classify`]: every link
/// key, the target keys of the links that reach [`classify_link`], and the
/// `packages` map for looking target entries up.
///
/// The two sets are deliberately asymmetric, each on its conservative side:
///
/// - `keys` holds **every** `link: true` key — extraneous and refused ones too —
///   so anything under any of them refuses ([`RefuseReason::NestedUnderLink`]).
/// - `targets` holds only the `resolved` of **live** links: non-root, contained,
///   not extraneous. A live link that is not nested under another reaches
///   [`classify_link`], so a target it lets the skip swallow is either a sibling
///   (`../<dir>`, skipped as `SiblingEscape` anyway) or paired with that link's
///   own refusal. A link that skips before step 4 (the root, a `../` key, an
///   extraneous one) contributes no target, so it cannot make a registry entry
///   vanish without a refusal.
struct LinkIndex<'a> {
    /// Keys of `link: true` entries.
    keys: Vec<&'a str>,
    /// The `resolved` of every live `link: true` entry — their target keys.
    targets: BTreeSet<&'a str>,
    /// The whole map, for the target-entry lookup.
    packages: &'a BTreeMap<String, RawPackageEntry>,
}

impl<'a> LinkIndex<'a> {
    fn new(packages: &'a BTreeMap<String, RawPackageEntry>) -> Self {
        let links = || packages.iter().filter(|(_, e)| e.link == Some(true));
        let live = |key: &str, entry: &RawPackageEntry| {
            !key.is_empty()
                && !entry.extraneous
                && InstallPath::new(key).containment() == Containment::Contained
        };
        Self {
            keys: links().map(|(k, _)| k.as_str()).collect(),
            targets: links()
                .filter(|(k, e)| live(k, e))
                .filter_map(|(_, e)| e.resolved.as_deref())
                .collect(),
            packages,
        }
    }

    /// True iff `key` is some link's target entry.
    fn is_target(&self, key: &str) -> bool {
        self.targets.contains(key)
    }

    /// The link key `key` is nested under (`<link>/…`), if any.
    fn enclosing_link(&self, key: &str) -> Option<&'a str> {
        self.keys.iter().copied().find(|link| {
            key.strip_prefix(link)
                .is_some_and(|rest| rest.starts_with('/'))
        })
    }
}

/// Classify a single entry, applying the precedence machine. `Err` carries the
/// refusal reason.
fn classify_one(
    path: &InstallPath,
    entry: &RawPackageEntry,
    host: &Platform,
    omit: &[Omit],
    links: &LinkIndex<'_>,
) -> Result<EntryDisposition, RefuseReason> {
    // 1. Root key — drift handles it; never a materialization target.
    if path.is_root() {
        return Ok(EntryDisposition::Skip(path.clone()));
    }

    // 2. Containment — the key IS the materialization target, so it must stay
    // within root. The leading-`../` sibling is the benign npm form (skip);
    // every other escape is corruption/tampering — refuse loud, never silently
    // drop an entry the lockfile claims is installed.
    //
    // Ordered *before* the `extraneous` skip deliberately. `extraneous` is a
    // plain lockfile boolean, so an entry carrying a malformed path could
    // otherwise set it and have the tamper signal swallowed by a silent skip —
    // a refusal suppressible by attacker-supplied data is not a refusal. Nothing
    // changes for real trees: npm's extraneous `../<sibling>` keys are
    // `SiblingEscape`, which still skips here.
    match path.containment() {
        Containment::Contained => {}
        Containment::SiblingEscape => return Ok(EntryDisposition::Skip(path.clone())),
        Containment::Malformed => {
            return Err(RefuseReason::MalformedInstallPath(
                path.as_str().to_string(),
            ));
        }
    }

    // 2b. A link's target entry — local source the link points at, never a
    // materialization target of its own. Skipped so a refusal lands once, on the
    // link (an in-tree target would otherwise refuse again as MissingIntegrity).
    // A sibling `../<dir>` target already skipped as SiblingEscape above. Never
    // a link entry itself: a link naming its own key (or a cycle of links) must
    // still reach step 4 and refuse, not skip itself away.
    if entry.link != Some(true) && links.is_target(path.as_str()) {
        return Ok(EntryDisposition::Skip(path.clone()));
    }

    // 2c. Under a link key — installing it would extract through the symlink
    // into the target. Before the `extraneous` skip, for the reason step 2 is:
    // an attacker-set boolean must not silence a refusal.
    if links.enclosing_link(path.as_str()).is_some() {
        return Err(RefuseReason::NestedUnderLink(path.as_str().to_string()));
    }

    // 3. Extraneous — benign, classify-and-skip.
    if entry.extraneous {
        return Ok(EntryDisposition::Skip(path.clone()));
    }

    // 4. Link — a symlink to local source, before touching integrity.
    if entry.link == Some(true) {
        return classify_link(path, entry, host, omit, links);
    }

    // 4b. Bundled — the bytes come from an ancestor's tarball, not this entry's
    // `resolved`. Deferred (model-and-refuse); see the variant docs for why
    // neither fetching nor skipping is safe without real data.
    if entry.in_bundle {
        return Err(RefuseReason::BundledUnsupported);
    }

    // 5. Resolved scheme.
    if let Some(resolved) = entry.resolved.as_deref() {
        match classify_resolved(resolved) {
            ResolvedKind::Https => {}
            ResolvedKind::Git => return Err(RefuseReason::GitDep(resolved.to_string())),
            ResolvedKind::File => return Err(RefuseReason::FileDep(resolved.to_string())),
            ResolvedKind::NonHttps => {
                return Err(RefuseReason::NonHttpsResolved(resolved.to_string()));
            }
            ResolvedKind::Blocked(reason) => {
                return Err(RefuseReason::BlockedResolvedHost(format!(
                    "{resolved}: {reason}"
                )));
            }
        }
    }
    // absent `resolved` falls through to step 6 (the missing-integrity path).

    // 6. Integrity present + sha512.
    let integrity = match Integrity::parse(entry.integrity.as_deref()) {
        IntegrityParse::Ok(i) => i,
        IntegrityParse::Missing => return Err(RefuseReason::MissingIntegrity),
        IntegrityParse::Sha1Only => return Err(RefuseReason::Sha1Integrity),
        IntegrityParse::Malformed(e) => return Err(RefuseReason::MalformedIntegrity(e)),
    };

    // 6b. A valid sha512 with no `resolved` is not a fetchable tarball — refuse
    // loud in this pass rather than handing an empty URL to the fetch phase.
    let Some(resolved) = entry.resolved.clone() else {
        return Err(RefuseReason::MissingResolved);
    };

    // 7. Platform tokens.
    let os = parse_os_axis(&entry.os).map_err(RefuseReason::MalformedPlatformToken)?;
    let cpu = parse_cpu_axis(&entry.cpu).map_err(RefuseReason::MalformedPlatformToken)?;
    let libc = parse_libc_axis(&entry.libc).map_err(RefuseReason::MalformedPlatformToken)?;

    // Bins start empty; they are parsed + validated only on the Install branch
    // below, so a malformed bin on an entry fuzi would NOT link (omitted, or an
    // off-platform optional) never refuses the install.
    let mut registry = RegistryEntry {
        path: path.clone(),
        version: entry.version.clone(),
        resolved,
        integrity,
        os,
        cpu,
        libc,
        has_install_script: entry.has_install_script,
        dev: entry.dev,
        optional: entry.optional,
        dev_optional: entry.dev_optional,
        peer: entry.peer,
        bins: BTreeMap::new(),
    };

    // 8. Omit.
    if !registry.retained_under(omit) {
        return Ok(EntryDisposition::Omitted(path.clone()));
    }

    // 9. Platform match. Only an entry fuzi will actually place is finalized.
    if host.matches(&registry) {
        validate_nm_key(path)?;
        // Validate bins last — a malformed/escaping bin (npm never emits one) refuses loud.
        registry.bins = parse_bins(entry.bin.as_ref(), path).map_err(RefuseReason::MalformedBin)?;
        Ok(EntryDisposition::Install(Box::new(registry)))
    } else if registry.optional || registry.dev_optional {
        Ok(EntryDisposition::SkipOptionalMismatch(path.clone()))
    } else {
        Err(RefuseReason::PlatformMismatchRequired)
    }
}

/// The `node_modules` key gates every placed entry passes — a registry
/// placement and a link alike, since both write at the key.
///
/// The one key gate: classify runs it on every `Install` and `Link`, and the
/// staging entry points —
/// [`StagingTree::package_dir`](crate::staging::StagingTree::package_dir) and
/// [`StagingTree::place_link`](crate::staging::StagingTree::place_link) — run
/// it again at the staging boundary, so a key in a hand-built plan is held to
/// exactly what a lockfile's is.
pub fn validate_nm_key(path: &InstallPath) -> Result<(), RefuseReason> {
    // A placed entry must materialize under `node_modules/` — enforce the
    // invariant materialization relies on (a contained-but-non-`node_modules`
    // key with registry metadata is a tamper signal, not a fetch-then-skip).
    let Some(rel) = path.nm_relative() else {
        // A key with a `node_modules/` component that does not start with one
        // sits under a workspace directory (`packages/a/node_modules/x`) —
        // npm's own output for a workspace dependency it did not hoist.
        let key = path.as_str().to_string();
        return Err(if path.depth() > 0 {
            RefuseReason::WorkspaceInstall(key)
        } else {
            RefuseReason::NonNodeModulesInstall(key)
        });
    };
    // Only npm's own package-name characters: the key becomes a directory (or
    // symlink) name. A name must survive `encodeURIComponent` unchanged, so
    // every component — a name, an `@scope`, the literal `node_modules` — holds
    // ASCII letters, digits, and `-._~!'()*`, with `@` only as a scope's first
    // character (`has_only_name_characters`). An allowlist, so it refuses a
    // lookalike letter or an odd space as readily as a control or invisible
    // character, and nothing npm writes for a real package. First of the name
    // gates, so the reason names the character rather than a nesting it
    // happens to break too.
    if !has_only_name_characters(rel) {
        return Err(RefuseReason::InvalidNameCharacter(
            path.as_str().to_string(),
        ));
    }
    // No `node_modules`-relative component may begin with `.`. npm package
    // names never start with `.` (or `_`), so the only legitimate
    // `nm_relative` components are the literal `node_modules`, a package
    // name, or an `@scope` segment — none dot-leading. A dot-leading
    // component is a reserved npm slot (`.bin` / `.package-lock.json` /
    // `.cache`) or otherwise not a valid package name; materializing it
    // would write into the `.bin` directory fuzi manages. This is the
    // name-level analog of the containment gate — it subsumes the old
    // exact-match reserved-name list, catches a hidden name at ANY nesting
    // depth, and is inherently case-independent (no fixed-name compare).
    if rel.split('/').any(|c| c.starts_with('.')) {
        return Err(RefuseReason::DotLeadingComponent(path.as_str().to_string()));
    }
    // The `node_modules`-relative path must be a proper package-nesting:
    // `<pkg>(/node_modules/<pkg>)*`, each `<pkg>` a plain name or an
    // `@scope/name`. Containment + the `node_modules/` prefix admit a key like
    // `node_modules/foo/bar` whose `nm_relative` (`foo/bar`) has an extra path
    // segment (`bar`) that follows no `node_modules/` boundary. It would stage
    // to `<root>/foo/bar` — the same path a `node_modules/foo` placement whose
    // tarball ships `bar/…` writes — so two concurrent workers could race it,
    // the exact non-determinism the vendored-`node_modules` extraction skip
    // removes, reached by a path that skip doesn't cover (`bar` is an ordinary
    // component, not `node_modules`). npm never emits this; refusing it keeps
    // every Install's staging path a race-free sole-writer target. Runs after
    // the dot-leading gate so a `.bin/foo`-style key keeps its more specific
    // `DotLeadingComponent` reason.
    if rel
        .split("/node_modules/")
        .any(|seg| !valid_package_portion(seg))
    {
        return Err(RefuseReason::MalformedInstallNesting(
            path.as_str().to_string(),
        ));
    }
    Ok(())
}

/// True iff every `/`-separated component of a key's `node_modules`-relative
/// path holds only npm package-name characters ([`is_package_name_char`]),
/// where a component may open with one `@` — a scope — unless it directly
/// follows a scope (`@s/@x` is not a name).
///
/// Characters only: whether the components *nest* as packages is the next
/// gate's question.
fn has_only_name_characters(rel: &str) -> bool {
    let mut after_scope = false;
    rel.split('/').all(|component| {
        let scope = (!after_scope)
            .then(|| component.strip_prefix('@'))
            .flatten();
        after_scope = scope.is_some();
        scope.unwrap_or(component).chars().all(is_package_name_char)
    })
}

/// Classify a `link: true` entry (step 4 of [`classify_one`]).
///
/// Gate order: the shared key gates → the link entry carries nothing but
/// `resolved` + `link` → `resolved` parses (malformed outranks deferred) → the
/// key is depth 1 → the target entry exists and is local source (its `name` may
/// be absent: npm omits it when it equals the folder default) →
/// the target's platform tokens parse → omit (the **target's** flags) →
/// platform match → the target's bins.
fn classify_link(
    path: &InstallPath,
    entry: &RawPackageEntry,
    host: &Platform,
    omit: &[Omit],
    links: &LinkIndex<'_>,
) -> Result<EntryDisposition, RefuseReason> {
    validate_nm_key(path)?;
    if let Some(field) = link_entry_extra_field(entry) {
        return Err(RefuseReason::MalformedLink(format!(
            "a link entry carries only resolved + link, but this one also carries `{field}`"
        )));
    }
    let Some(resolved) = entry.resolved.as_deref() else {
        return Err(RefuseReason::MalformedLink(
            "link entry has no resolved".to_string(),
        ));
    };
    let target = match LinkTarget::parse(resolved) {
        LinkTargetParse::Ok(target) => target,
        LinkTargetParse::Deferred(why) => {
            return Err(RefuseReason::LinkUnsupported(format!("{resolved}: {why}")));
        }
        LinkTargetParse::Malformed(why) => {
            return Err(RefuseReason::MalformedLink(format!(
                "resolved `{resolved}`: {why}"
            )));
        }
    };
    if path.depth() != 1 {
        return Err(RefuseReason::LinkUnsupported(format!(
            "{resolved}: nested link key (only a top-level node_modules/<pkg> link is placed)"
        )));
    }

    let malformed_target = |why: &str| {
        Err(RefuseReason::MalformedLink(format!(
            "target entry `{resolved}` {why}"
        )))
    };
    let Some(target_entry) = links.packages.get(resolved) else {
        return malformed_target("is missing from the lockfile");
    };
    if target_entry.link.is_some() {
        return malformed_target("is itself a link");
    }
    if target_entry.extraneous {
        return malformed_target("is extraneous");
    }
    if target_entry.in_bundle {
        return malformed_target("is bundled (inBundle)");
    }
    if target_entry.resolved.is_some() || target_entry.integrity.is_some() {
        return malformed_target("carries resolved/integrity (a link target is local source)");
    }
    // arborist records a target's `name` only when it differs from the target
    // folder's default (`nameFromFolder(realpath) !== packageName`), so an absent
    // `name` carries through as `None` and the link-target check resolves the
    // default from the disk (it depends on the parent directory's name). An
    // empty one is not something npm writes.
    if target_entry.name.as_deref() == Some("") {
        return malformed_target("has an empty name");
    }
    let name = target_entry.name.clone();

    // The target's platform tokens refuse loud when malformed (as a registry
    // entry's do), rather than reading as a silent mismatch.
    let os = parse_os_axis(&target_entry.os).map_err(RefuseReason::MalformedPlatformToken)?;
    let cpu = parse_cpu_axis(&target_entry.cpu).map_err(RefuseReason::MalformedPlatformToken)?;
    let libc = parse_libc_axis(&target_entry.libc).map_err(RefuseReason::MalformedPlatformToken)?;

    // npm puts the dependency-reason flags on the target entry; the link entry
    // carries none (refused above if it did).
    let flags = DepFlags {
        dev: target_entry.dev,
        optional: target_entry.optional,
        dev_optional: target_entry.dev_optional,
        peer: target_entry.peer,
    };
    if !retained(flags, omit) {
        return Ok(EntryDisposition::Omitted(path.clone()));
    }
    if !host.matches_axes(&os, &cpu, &libc) {
        return if flags.optional || flags.dev_optional {
            Ok(EntryDisposition::SkipOptionalMismatch(path.clone()))
        } else {
            Err(RefuseReason::PlatformMismatchRequired)
        };
    }

    // Bins come from the target entry (never from the target's package.json).
    let bins = parse_bins(target_entry.bin.as_ref(), path).map_err(RefuseReason::MalformedBin)?;
    Ok(EntryDisposition::Link(Box::new(LinkEntry {
        path: path.clone(),
        target,
        name,
        version: target_entry.version.clone(),
        has_install_script: target_entry.has_install_script,
        bins,
    })))
}

/// The first modeled field a link entry carries besides `resolved` + `link`, if
/// any. npm writes a link entry as exactly those two (and `extraneous` skips
/// before this runs); anything else is a tampered or hand-edited entry.
/// Unmodeled fields are not checked here — they warn through the lockfile-wide
/// unknown-field capture, the same as on any entry.
fn link_entry_extra_field(entry: &RawPackageEntry) -> Option<&'static str> {
    let fields: [(&'static str, bool); 17] = [
        ("name", entry.name.is_some()),
        ("version", entry.version.is_some()),
        ("integrity", entry.integrity.is_some()),
        ("bin", entry.bin.is_some()),
        ("dependencies", entry.dependencies.is_some()),
        ("devDependencies", entry.dev_dependencies.is_some()),
        (
            "optionalDependencies",
            entry.optional_dependencies.is_some(),
        ),
        ("peerDependencies", entry.peer_dependencies.is_some()),
        ("dev", entry.dev),
        ("optional", entry.optional),
        ("devOptional", entry.dev_optional),
        ("peer", entry.peer),
        ("os", !entry.os.is_empty()),
        ("cpu", !entry.cpu.is_empty()),
        ("libc", !entry.libc.is_empty()),
        ("hasInstallScript", entry.has_install_script),
        ("inBundle", entry.in_bundle),
    ];
    fields
        .into_iter()
        .find_map(|(field, present)| present.then_some(field))
}

/// True iff `seg` is one valid package portion of a `node_modules` install
/// nesting — a plain `name` (no `/`) or a scoped `@scope/name` (leading `@`,
/// exactly one `/`, both parts non-empty) whose name part is not on npm's
/// exclusion list ([`EXCLUDED_PACKAGE_NAMES`]). Used to validate the segments of a
/// key's `nm_relative` split on `"/node_modules/"`, so a malformed nesting like
/// `node_modules/foo/bar` (segment `foo/bar`, a plain name that contains `/`) is
/// refused as [`RefuseReason::MalformedInstallNesting`] rather than staged to a
/// path a sibling placement could race.
pub fn valid_package_portion(seg: &str) -> bool {
    if seg.is_empty() {
        return false;
    }
    let name = match seg.strip_prefix('@') {
        None if seg.contains('/') => return false,
        None => seg,
        // `@scope/name` — exactly one `/`, both sides non-empty.
        Some(rest) => match rest.split_once('/') {
            Some((scope, name)) if !scope.is_empty() && !name.is_empty() && !name.contains('/') => {
                name
            }
            _ => return false,
        },
    };
    !EXCLUDED_PACKAGE_NAMES
        .iter()
        .any(|excluded| name.eq_ignore_ascii_case(excluded))
}

/// Names npm refuses — `validate-npm-package-name`'s exclusion list. npm
/// lowercases and compares the **whole** name, so it rejects only the bare
/// `node_modules` / `favicon.ico`. fuzi compares each key's name part (an
/// unscoped name, or the part after `@scope/`) case-insensitively, which is
/// deliberately stricter: a scoped `@a/node_modules` would make the key's
/// nesting ambiguous and makes Node resolve bare imports of every `@a/*` package
/// through it. `favicon.ico` carries no such hazard and is excluded for
/// symmetry; a key naming either is not one npm writes for a real package.
const EXCLUDED_PACKAGE_NAMES: &[&str] = &["node_modules", "favicon.ico"];

/// Number of example paths shown per reason group before collapsing to `+N more`.
const REFUSAL_EXAMPLE_CAP: usize = 8;

/// Format a refusal list into a teaching block **grouped by reason** ("loud once,
/// not crying wolf"): one header per reason (`<code> (<count>): <next step>`) then
/// up to [`REFUSAL_EXAMPLE_CAP`] example `<path> · <why>` lines, collapsing the
/// rest to `… (+N more)`. A degraded lock with 261 missing-integrity entries
/// becomes one group with a handful of examples, not a 261-line wall. (`--json`
/// still gets every refusal, structured.)
///
/// Not re-exported from the crate root: this is the `Display` body of
/// [`crate::FuziError::Refused`], not API. A consumer rendering refusals itself
/// reaches for the exported [`Refusal`] + [`RefuseReason::code`] /
/// [`why`](RefuseReason::why) / [`next_step`](RefuseReason::next_step) triple,
/// as the `fuzi` binary's `--json` path does.
#[must_use]
pub fn render_refusals(refusals: &[Refusal]) -> String {
    use std::fmt::Write as _;
    if refusals.is_empty() {
        return "refused (no details)".to_string();
    }
    // Group by reason code in first-seen (deterministic `BTreeMap`) order. An
    // association list, not a map + a parallel order vector: the codes are one
    // small closed set (`RefuseReason`'s variants), so the linear probe is free,
    // and the order *is* the structure rather than something a second
    // collection has to preserve.
    let mut groups: Vec<(&'static str, Vec<&Refusal>)> = Vec::new();
    for r in refusals {
        let code = r.reason.code();
        match groups.iter_mut().find(|(seen, _)| *seen == code) {
            Some((_, group)) => group.push(r),
            None => groups.push((code, vec![r])),
        }
    }

    let plural = if refusals.len() == 1 { "y" } else { "ies" };
    let mut out = format!("refused {} entr{plural}:", refusals.len());
    for (code, group) in &groups {
        // Writing to a String is infallible.
        let _ = write!(
            out,
            "\n  {code} ({}): {}",
            group.len(),
            group[0].reason.next_step()
        );
        for r in group.iter().take(REFUSAL_EXAMPLE_CAP) {
            // The key and the reason both carry lockfile text: escaped here, in
            // the human rendering (the structured refusal keeps them raw).
            let path = if r.path.is_root() {
                "<root>".to_string()
            } else {
                escape_untrusted(r.path.as_str())
            };
            let _ = write!(out, "\n    {path} · {}", escape_untrusted(&r.reason.why()));
        }
        if group.len() > REFUSAL_EXAMPLE_CAP {
            let _ = write!(out, "\n    … (+{} more)", group.len() - REFUSAL_EXAMPLE_CAP);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{host_linux_x64_glibc, sha512_sri};
    use serde_json::json;

    fn entry_from(value: serde_json::Value) -> RawPackageEntry {
        serde_json::from_value(value).unwrap()
    }

    fn classify_single(
        key: &str,
        value: serde_json::Value,
    ) -> Result<EntryDisposition, RefuseReason> {
        let host = host_linux_x64_glibc();
        let none = BTreeMap::new();
        classify_one(
            &InstallPath::new(key),
            &entry_from(value),
            &host,
            &[],
            &LinkIndex::new(&none),
        )
    }

    #[test]
    fn root_entry_skipped() {
        let d = classify_single("", json!({"name": "root"})).unwrap();
        assert!(matches!(d, EntryDisposition::Skip(_)));
    }

    #[test]
    fn extraneous_shape_a_ignored() {
        // Full metadata, no resolved/integrity.
        let d = classify_single(
            "../fuz_app",
            json!({"version": "0.1.0", "extraneous": true, "name": "fuz_app"}),
        )
        .unwrap();
        assert!(matches!(d, EntryDisposition::Skip(_)));
    }

    #[test]
    fn extraneous_shape_b_bare_ignored() {
        // The bare {"extraneous":true} object — must not panic.
        let d = classify_single("../some_site", json!({"extraneous": true})).unwrap();
        assert!(matches!(d, EntryDisposition::Skip(_)));
    }

    #[test]
    fn sibling_escape_without_extraneous_skipped() {
        let d = classify_single("../sibling", json!({})).unwrap();
        assert!(matches!(d, EntryDisposition::Skip(_)));
    }

    #[test]
    fn embedded_traversal_key_refused() {
        // A key that escapes root by embedded `..` (not the benign leading-`../`
        // form), carrying valid registry metadata — refuse loud, never Install.
        let err = classify_single(
            "node_modules/x/../../../y",
            json!({
                "resolved": "https://registry.npmjs.org/y/-/y-1.0.0.tgz",
                "integrity": sha512_sri(b"y")
            }),
        )
        .unwrap_err();
        assert!(matches!(err, RefuseReason::MalformedInstallPath(_)));
    }

    #[test]
    fn absolute_path_key_refused() {
        let err = classify_single(
            "/etc/cron.d/x",
            json!({
                "resolved": "https://registry.npmjs.org/x/-/x-1.0.0.tgz",
                "integrity": sha512_sri(b"x")
            }),
        )
        .unwrap_err();
        assert!(matches!(err, RefuseReason::MalformedInstallPath(_)));
    }

    #[test]
    fn libc_sole_mismatch_required_refused() {
        // os + cpu match the glibc-x64 host; libc is the only mismatching axis —
        // guards the libc conjunction term in Platform::matches.
        let err = classify_single(
            "node_modules/musl-only",
            json!({
                "resolved": "https://registry.npmjs.org/m/-/m-1.0.0.tgz",
                "integrity": sha512_sri(b"m"),
                "os": ["linux"], "cpu": ["x64"], "libc": ["musl"]
            }),
        )
        .unwrap_err();
        assert!(matches!(err, RefuseReason::PlatformMismatchRequired));
    }

    #[test]
    fn bundled_entry_refused() {
        // `inBundle: true` ships inside an ancestor's tarball. Fetching and
        // extracting it separately would double-write the very paths the
        // parent's own extraction produces (an unordered race, since
        // extraction is concurrent). Refuse loud instead.
        let err = classify_single(
            "node_modules/parent/node_modules/bundled",
            json!({
                "resolved": "https://registry.npmjs.org/bundled/-/bundled-1.0.0.tgz",
                "integrity": sha512_sri(b"bundled"),
                "inBundle": true
            }),
        )
        .unwrap_err();
        assert!(matches!(err, RefuseReason::BundledUnsupported));
    }

    #[test]
    fn non_bundled_entry_unaffected() {
        // The absent/false flag is the overwhelming common case — no regression.
        let d = classify_single(
            "node_modules/normal",
            json!({
                "resolved": "https://registry.npmjs.org/normal/-/normal-1.0.0.tgz",
                "integrity": sha512_sri(b"normal"),
                "inBundle": false
            }),
        )
        .unwrap();
        assert!(matches!(d, EntryDisposition::Install(_)));
    }

    #[test]
    fn git_dep_refused() {
        let err = classify_single(
            "node_modules/g",
            json!({"resolved": "git+https://github.com/x/y.git#abc", "integrity": sha512_sri(b"x")}),
        )
        .unwrap_err();
        assert!(matches!(err, RefuseReason::GitDep(_)));
    }

    #[test]
    fn file_dep_refused() {
        let err = classify_single(
            "node_modules/f",
            json!({"resolved": "file:../x", "integrity": sha512_sri(b"x")}),
        )
        .unwrap_err();
        assert!(matches!(err, RefuseReason::FileDep(_)));
    }

    #[test]
    fn bare_relative_resolved_is_file_dep() {
        let err = classify_single(
            "node_modules/f",
            json!({"resolved": "../x", "integrity": sha512_sri(b"x")}),
        )
        .unwrap_err();
        assert!(matches!(err, RefuseReason::FileDep(_)));
    }

    #[test]
    fn non_https_refused() {
        let err = classify_single(
            "node_modules/h",
            json!({"resolved": "http://registry.npmjs.org/h.tgz", "integrity": sha512_sri(b"x")}),
        )
        .unwrap_err();
        assert!(matches!(err, RefuseReason::NonHttpsResolved(_)));
    }

    #[test]
    fn degraded_missing_integrity() {
        // No resolved, no integrity, not extraneous — the fuz_ui degraded shape.
        let err = classify_single("node_modules/d", json!({"version": "1.0.0"})).unwrap_err();
        assert!(matches!(err, RefuseReason::MissingIntegrity));
    }

    #[test]
    fn integrity_without_resolved_refused() {
        // Valid sha512 but no resolved URL — not a fetchable tarball; must refuse
        // loud (MissingResolved), not Install with an empty URL.
        let err = classify_single(
            "node_modules/no-url",
            json!({"integrity": sha512_sri(b"x"), "version": "1.0.0"}),
        )
        .unwrap_err();
        assert!(matches!(err, RefuseReason::MissingResolved));
    }

    #[test]
    fn sha1_only_refused() {
        let err = classify_single(
            "node_modules/legacy",
            json!({
                "resolved": "https://registry.npmjs.org/legacy/-/legacy-1.0.0.tgz",
                "integrity": "sha1-qZk+NkcGgWq6PiVxeFDCbJzQ2J0="
            }),
        )
        .unwrap_err();
        assert!(matches!(err, RefuseReason::Sha1Integrity));
    }

    #[test]
    fn normal_registry_installs_with_script() {
        let d = classify_single(
            "node_modules/esbuild",
            json!({
                "resolved": "https://registry.npmjs.org/esbuild/-/esbuild-0.20.0.tgz",
                "integrity": sha512_sri(b"esbuild"),
                "hasInstallScript": true,
                "optionalDependencies": {"@esbuild/linux-x64": "0.20.0"}
            }),
        )
        .unwrap();
        match d {
            EntryDisposition::Install(e) => assert!(e.has_install_script),
            other => panic!("expected Install, got {other:?}"),
        }
    }

    #[test]
    fn optional_platform_mismatch_skipped() {
        // @rollup/rollup-linux-arm-gnueabihf: cpu arm, os linux, libc glibc, optional.
        let d = classify_single(
            "node_modules/@rollup/rollup-linux-arm-gnueabihf",
            json!({
                "resolved": "https://registry.npmjs.org/@rollup/x/-/x-4.0.0.tgz",
                "integrity": sha512_sri(b"rollup"),
                "cpu": ["arm"],
                "os": ["linux"],
                "libc": ["glibc"],
                "optional": true
            }),
        )
        .unwrap();
        assert!(matches!(d, EntryDisposition::SkipOptionalMismatch(_)));
    }

    #[test]
    fn required_platform_mismatch_refused() {
        let err = classify_single(
            "node_modules/mac-only",
            json!({
                "resolved": "https://registry.npmjs.org/m/-/m-1.0.0.tgz",
                "integrity": sha512_sri(b"m"),
                "os": ["darwin"]
            }),
        )
        .unwrap_err();
        assert!(matches!(err, RefuseReason::PlatformMismatchRequired));
    }

    #[test]
    fn dev_optional_platform_mismatch_skipped() {
        // `devOptional` alone (optional only through a dev edge, not `optional`)
        // still makes an off-host entry a skip, not a required refusal.
        let d = classify_single(
            "node_modules/fsevents",
            json!({
                "resolved": "https://registry.npmjs.org/fsevents/-/fsevents-2.3.3.tgz",
                "integrity": sha512_sri(b"fsevents"),
                "os": ["darwin"],
                "devOptional": true
            }),
        )
        .unwrap();
        assert!(
            matches!(d, EntryDisposition::SkipOptionalMismatch(_)),
            "{d:?}"
        );
    }

    #[test]
    fn malformed_integrity_refuses_as_malformed_not_missing() {
        // A corrupt sha512 token, and two different sha512 digests for one
        // tarball: both are `MalformedIntegrity`, never the "regenerate the
        // lockfile" `MissingIntegrity`.
        for integrity in [
            "sha512-!!!".to_string(),
            format!("{} {}", sha512_sri(b"one"), sha512_sri(b"two")),
        ] {
            let err = classify_single(
                "node_modules/m",
                json!({
                    "resolved": "https://registry.npmjs.org/m/-/m-1.0.0.tgz",
                    "integrity": integrity
                }),
            )
            .unwrap_err();
            assert!(
                matches!(err, RefuseReason::MalformedIntegrity(_)),
                "{integrity}: {err:?}"
            );
        }
    }

    #[test]
    fn esbuild_platform_pkg_no_libc_skipped() {
        // @esbuild/aix-ppc64: cpu ppc64, os aix, optional, NO libc.
        let d = classify_single(
            "node_modules/@esbuild/aix-ppc64",
            json!({
                "resolved": "https://registry.npmjs.org/@esbuild/aix-ppc64/-/aix-ppc64-0.20.0.tgz",
                "integrity": sha512_sri(b"aix"),
                "cpu": ["ppc64"],
                "os": ["aix"],
                "optional": true
            }),
        )
        .unwrap();
        assert!(matches!(d, EntryDisposition::SkipOptionalMismatch(_)));
    }

    #[test]
    fn escaping_bin_target_on_installed_entry_refused() {
        // A bin pointing the chmod/symlink outside the package — npm never emits
        // this, so an *installed* entry carrying it refuses loud (MalformedBin).
        let err = classify_single(
            "node_modules/evil",
            json!({
                "resolved": "https://registry.npmjs.org/evil/-/evil-1.0.0.tgz",
                "integrity": sha512_sri(b"evil"),
                "bin": {"evil": "../../../../etc/cron.d/x"}
            }),
        )
        .unwrap_err();
        assert!(matches!(err, RefuseReason::MalformedBin(_)));
    }

    #[test]
    fn bin_name_with_a_control_or_invisible_character_refuses_the_entry() {
        // A `.bin` name is a file fuzi creates in a directory users put on
        // `PATH`; a lockfile cannot make it an escape sequence or a lookalike.
        for (cmd, target) in [
            ("x\u{1b}[2J\nforged\u{202e}", "picocolors.js"),
            ("vi\u{200b}te", "bin/vite.js"),
            ("vite", "bin/vite\u{fe0f}.js"),
        ] {
            let err = classify_single(
                "node_modules/picocolors",
                json!({
                    "resolved": "https://registry.npmjs.org/picocolors/-/picocolors-1.1.1.tgz",
                    "integrity": sha512_sri(b"x"),
                    "bin": {cmd: target}
                }),
            )
            .unwrap_err();
            match err {
                RefuseReason::MalformedBin(detail) => {
                    assert!(detail.contains("control or invisible"), "{detail:?}");
                }
                other => panic!("{cmd:?}: expected MalformedBin, got {other:?}"),
            }
        }
    }

    #[test]
    fn malformed_bin_on_offplatform_optional_does_not_refuse() {
        // The same hostile bin on an optional dep for a DIFFERENT platform is
        // never linked here, so it skips silently rather than refusing the install.
        let d = classify_single(
            "node_modules/@evil/darwin-x64",
            json!({
                "resolved": "https://registry.npmjs.org/@evil/darwin-x64/-/x-1.0.0.tgz",
                "integrity": sha512_sri(b"d"),
                "os": ["darwin"],
                "optional": true,
                "bin": {"x": "/etc/passwd"}
            }),
        )
        .unwrap();
        assert!(matches!(d, EntryDisposition::SkipOptionalMismatch(_)));
    }

    #[test]
    fn non_node_modules_key_with_registry_metadata_refused() {
        // A contained-but-non-node_modules key (e.g. a tampered `packages/x`)
        // carrying valid registry metadata must refuse, not fetch-then-skip.
        let err = classify_single(
            "packages/evil",
            json!({
                "resolved": "https://registry.npmjs.org/evil/-/evil-1.0.0.tgz",
                "integrity": sha512_sri(b"evil")
            }),
        )
        .unwrap_err();
        assert!(matches!(err, RefuseReason::NonNodeModulesInstall(_)));
    }

    #[test]
    fn workspace_node_modules_key_teaches_workspaces_unsupported() {
        // typescript-go's shape: a workspace dependency npm left under the
        // workspace's own node_modules. Not a tamper signal — it gets the
        // workspace teaching line, not "regenerate".
        let err = classify_single(
            "_packages/native-preview/node_modules/@types/node",
            json!({
                "resolved": "https://registry.npmjs.org/@types/node/-/node-22.0.0.tgz",
                "integrity": sha512_sri(b"node")
            }),
        )
        .unwrap_err();
        assert_eq!(
            err,
            RefuseReason::WorkspaceInstall(
                "_packages/native-preview/node_modules/@types/node".to_string()
            )
        );
        assert_eq!(err.code(), "workspace_install");
        assert_eq!(
            err.next_step(),
            RefuseReason::LinkUnsupported(String::new()).next_step()
        );
        assert!(err.next_step().contains("install this project with npm"));
    }

    /// The key gate runs on links too, so the reason must not claim a
    /// registry entry: a `link: true` entry at either key shape gets it.
    #[test]
    fn link_at_a_non_node_modules_key_is_not_called_a_registry_entry() {
        let link = json!({"resolved": "../lib", "link": true});
        for (key, want) in [
            (
                "packages/a/node_modules/b",
                RefuseReason::WorkspaceInstall("packages/a/node_modules/b".to_string()),
            ),
            (
                "packages/b",
                RefuseReason::NonNodeModulesInstall("packages/b".to_string()),
            ),
        ] {
            let err = classify_single(key, link.clone()).unwrap_err();
            assert_eq!(err, want);
            assert!(!err.why().contains("registry"), "{}", err.why());
        }
        assert_eq!(
            RefuseReason::WorkspaceInstall("k".into()).why(),
            "entry inside an in-tree workspace's node_modules (k)"
        );
        assert_eq!(
            RefuseReason::NonNodeModulesInstall("k".into()).why(),
            "entry at a non-node_modules key (k)"
        );
    }

    #[test]
    fn missing_resolved_teaches_the_npm_config() {
        assert!(
            RefuseReason::MissingResolved
                .next_step()
                .contains("delete package-lock.json")
        );
        assert!(
            RefuseReason::MissingResolved
                .why()
                .contains("omit-lockfile-registry-resolved")
        );
    }

    #[test]
    fn double_slash_key_refused() {
        // `node_modules//<abs>` — the double-slash escape. Left unchecked,
        // `nm_relative` returns the absolute remainder `/home/…` and the staging
        // `root.join` replaces the tree root with it, writing the tarball outside
        // the project. The containment gate refuses it loud instead of Install.
        let err = classify_single(
            "node_modules//home/victim/.bashrc",
            json!({
                "resolved": "https://registry.npmjs.org/x/-/x-1.0.0.tgz",
                "integrity": sha512_sri(b"x")
            }),
        )
        .unwrap_err();
        assert!(matches!(err, RefuseReason::MalformedInstallPath(_)));
    }

    #[test]
    fn dot_component_key_refused() {
        // `node_modules/./x` — a `.` current-dir component. npm never emits one;
        // it is refused as a malformed install path.
        let err = classify_single(
            "node_modules/./x",
            json!({
                "resolved": "https://registry.npmjs.org/x/-/x-1.0.0.tgz",
                "integrity": sha512_sri(b"x")
            }),
        )
        .unwrap_err();
        assert!(matches!(err, RefuseReason::MalformedInstallPath(_)));
    }

    #[test]
    fn dot_leading_final_component_refused() {
        // `node_modules/.bin` is npm's bin-link directory, never a real package;
        // a tampered entry keyed there would materialize into the `.bin` dir fuzi
        // manages. The path is structurally valid (containment passes), so the
        // dot-leading-component gate in the Install branch is what refuses it.
        let err = classify_single(
            "node_modules/.bin",
            json!({
                "resolved": "https://registry.npmjs.org/x/-/x-1.0.0.tgz",
                "integrity": sha512_sri(b"x")
            }),
        )
        .unwrap_err();
        assert!(matches!(err, RefuseReason::DotLeadingComponent(_)));
    }

    #[test]
    fn dot_leading_non_final_component_refused() {
        // `node_modules/.bin/foo` — the bypass an exact-match check misses:
        // `package_portion()` is `.bin/foo` (≠ `.bin`), so the entry would pass and
        // materialize INTO the `.bin` directory at `<root>/.bin/foo/…`. The
        // per-component gate catches the leading `.bin` regardless of what follows.
        let err = classify_single(
            "node_modules/.bin/foo",
            json!({
                "resolved": "https://registry.npmjs.org/x/-/x-1.0.0.tgz",
                "integrity": sha512_sri(b"x")
            }),
        )
        .unwrap_err();
        assert!(matches!(err, RefuseReason::DotLeadingComponent(_)));
    }

    #[test]
    fn dot_leading_nested_node_modules_bypass_refused() {
        // `node_modules/.bin/node_modules/x` — `package_portion()` is `x` (after
        // the FINAL `node_modules/`), so an exact-match check passes it, letting it write
        // to `<root>/.bin/node_modules/x/…`. The per-component gate on `nm_relative`
        // (= `.bin/node_modules/x`) catches the leading `.bin` component.
        let err = classify_single(
            "node_modules/.bin/node_modules/x",
            json!({
                "resolved": "https://registry.npmjs.org/x/-/x-1.0.0.tgz",
                "integrity": sha512_sri(b"x")
            }),
        )
        .unwrap_err();
        assert!(matches!(err, RefuseReason::DotLeadingComponent(_)));
    }

    #[test]
    fn dot_leading_case_variant_refused() {
        // `node_modules/.BIN` — on case-insensitive macOS this IS the `.bin` dir,
        // which an exact-match `== ".bin"` compare misses. The gate never
        // compares against a fixed name — a leading `.` is refused case-independently.
        let err = classify_single(
            "node_modules/.BIN",
            json!({
                "resolved": "https://registry.npmjs.org/x/-/x-1.0.0.tgz",
                "integrity": sha512_sri(b"x")
            }),
        )
        .unwrap_err();
        assert!(matches!(err, RefuseReason::DotLeadingComponent(_)));
    }

    #[test]
    fn dot_leading_cache_and_hidden_lock_refused() {
        // `.cache` (a hidden name a fixed-name list would not carry) and
        // `.package-lock.json` (npm's hidden lock) are both refused by the single
        // dot-leading gate — there is no list of names to keep current.
        for key in ["node_modules/.cache", "node_modules/.package-lock.json"] {
            let err = classify_single(
                key,
                json!({
                    "resolved": "https://registry.npmjs.org/x/-/x-1.0.0.tgz",
                    "integrity": sha512_sri(b"x")
                }),
            )
            .unwrap_err();
            assert!(
                matches!(err, RefuseReason::DotLeadingComponent(_)),
                "{key} should refuse as a dot-leading component"
            );
        }
    }

    #[test]
    fn key_with_a_non_name_character_is_refused() {
        // A placed key becomes a directory name, so it is held to npm's own
        // package-name characters. `\n` and friends pass containment (which
        // refuses only NUL and backslash); this gate is the one that stops
        // them, along with everything that merely *looks* like a name.
        for key in [
            "node_modules/fo\u{202e}o",               // bidi override
            "node_modules/@s\u{200b}/x",              // zero-width space in a scope
            "node_modules/a/node_modules/b\u{9b}31m", // C1 CSI, nested
            "node_modules/x\ny",                      // C0
            "node_modules/x\u{1b}[2J",                // escape sequence
            "node_modules/x\u{7f}",                   // DEL
            "node_modules/\u{feff}x",                 // BOM
            "node_modules/x\u{2028}",                 // line separator
            "node_modules/x\u{3164}",                 // Hangul filler
            "node_modules/re\u{430}ct",               // Cyrillic `а` for `a`
            "node_modules/\u{ff52}eact",              // fullwidth `r`
            "node_modules/caf\u{e9}",                 // any non-ASCII letter
            "node_modules/x y",                       // space
            "node_modules/x\u{a0}y",                  // no-break space
            "node_modules/x\u{3000}y",                // ideographic space
            "node_modules/x%2fy",                     // percent
            "node_modules/x+y",
            "node_modules/x#y",
            "node_modules/x:y",
            "node_modules/x@1", // `@` anywhere but a scope's start
            "node_modules/@s/@x",
            "node_modules/@@s/x",
            "node_modules/a/node_modules/@s/x y",
        ] {
            let err = classify_single(
                key,
                json!({
                    "resolved": "https://registry.npmjs.org/x/-/x-1.0.0.tgz",
                    "integrity": sha512_sri(b"x")
                }),
            )
            .unwrap_err();
            assert!(
                matches!(err, RefuseReason::InvalidNameCharacter(_)),
                "{key:?}: {err:?}"
            );
        }
    }

    #[test]
    fn keys_of_every_name_npm_allows_still_install() {
        // The whole allowed set, legacy names included: capitals and `~!'()*`
        // are invalid for a *new* package and still installable.
        for key in [
            "node_modules/lodash",
            "node_modules/JSONStream",
            "node_modules/@types/node",
            "node_modules/@Scope/Name",
            "node_modules/a.b_c-d~e",
            "node_modules/x!y'z(1)*",
            "node_modules/0",
            "node_modules/a/node_modules/@s/b.js",
        ] {
            let d = classify_single(
                key,
                json!({
                    "resolved": "https://registry.npmjs.org/x/-/x-1.0.0.tgz",
                    "integrity": sha512_sri(b"x")
                }),
            );
            assert!(
                matches!(d, Ok(EntryDisposition::Install(_))),
                "{key}: {d:?}"
            );
        }
    }

    #[test]
    fn name_character_gate_is_on_placed_entries_only() {
        // Pin: the gate guards what fuzi creates. An extraneous entry, a
        // sibling-escape key, and an omitted entry are never placed, so an odd
        // character in one of those keys is skipped like any other, not refused.
        let registry = json!({
            "resolved": "https://registry.npmjs.org/x/-/x-1.0.0.tgz",
            "integrity": sha512_sri(b"x"),
            "dev": true
        });
        let host = host_linux_x64_glibc();
        let none = BTreeMap::new();
        let omitted = classify_one(
            &InstallPath::new("node_modules/x\u{200b}"),
            &entry_from(registry),
            &host,
            &[Omit::Dev],
            &LinkIndex::new(&none),
        )
        .unwrap();
        assert!(matches!(omitted, EntryDisposition::Omitted(_)));
        for (key, value) in [
            ("node_modules/x\u{200b}", json!({"extraneous": true})),
            ("../sib\u{200d}ling", json!({"extraneous": true})),
            ("../sib\u{200d}ling", json!({})),
        ] {
            assert!(
                matches!(classify_single(key, value), Ok(EntryDisposition::Skip(_))),
                "{key:?}"
            );
        }
    }

    #[test]
    fn committed_fixture_lockfiles_classify_clean() {
        // Real npm-written lockfiles: no key trips the name-character gate (or
        // any other), on the fixed linux/x64/glibc host.
        let gate = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/fuzi-gate");
        let mut keys = 0;
        for fixture in ["vite-rollup", "vite-rolldown", "link-sibling/app"] {
            let raw = crate::lockfile::read_lockfile(&gate.join(fixture)).unwrap();
            keys += raw.packages.len();
            let (_, refusals) = classify(&raw, &host_linux_x64_glibc(), &[]);
            assert!(refusals.is_empty(), "{fixture}: {refusals:?}");
        }
        assert!(keys > 100, "the fixtures were read ({keys} keys)");
    }

    #[test]
    fn nested_and_scoped_keys_have_no_dot_leading_false_positive() {
        // Regression guard: the per-component check must NOT fire on the literal
        // `node_modules` component of a nested key, nor on an `@scope` segment
        // (starts with `@`, not `.`). Both are ordinary Install targets.
        for key in ["node_modules/a/node_modules/b", "node_modules/@scope/pkg"] {
            let d = classify_single(
                key,
                json!({
                    "resolved": "https://registry.npmjs.org/x/-/x-1.0.0.tgz",
                    "integrity": sha512_sri(b"x")
                }),
            )
            .unwrap();
            assert!(
                matches!(d, EntryDisposition::Install(_)),
                "{key} should Install, not refuse"
            );
        }
    }

    #[test]
    fn malformed_install_nesting_extra_segment_refused() {
        // `node_modules/foo/bar` — `bar` follows NO `node_modules/` boundary, so
        // it is not a proper package-nesting. Containment passes (no `..`, no
        // empty/dot component) and the `node_modules/` prefix check passes, so
        // without this gate it would classify to Install and stage under
        // `<root>/foo/bar` — the exact path a `node_modules/foo` placement whose
        // tarball ships `bar/…` also writes, a concurrent write race the vendored-
        // `node_modules` skip does not cover (`bar` is an ordinary component). It
        // must refuse as MalformedInstallNesting.
        let err = classify_single(
            "node_modules/foo/bar",
            json!({
                "resolved": "https://registry.npmjs.org/x/-/x-1.0.0.tgz",
                "integrity": sha512_sri(b"x")
            }),
        )
        .unwrap_err();
        assert!(matches!(err, RefuseReason::MalformedInstallNesting(_)));
    }

    #[test]
    fn malformed_install_nesting_bad_intermediate_segment_refused() {
        // `node_modules/a/b/node_modules/c` — the FIRST segment (`a/b`) is not a
        // valid package portion (a plain name may not contain `/`), even though
        // the second (`c`) is. Any bad segment across the `/node_modules/` split
        // refuses.
        let err = classify_single(
            "node_modules/a/b/node_modules/c",
            json!({
                "resolved": "https://registry.npmjs.org/x/-/x-1.0.0.tgz",
                "integrity": sha512_sri(b"x")
            }),
        )
        .unwrap_err();
        assert!(matches!(err, RefuseReason::MalformedInstallNesting(_)));
    }

    #[test]
    fn malformed_install_nesting_scope_without_name_refused() {
        // `node_modules/@scope` — a scope with no `/name`. A scoped portion must be
        // `@scope/name` with both parts non-empty; a bare `@scope` is malformed.
        let err = classify_single(
            "node_modules/@scope",
            json!({
                "resolved": "https://registry.npmjs.org/x/-/x-1.0.0.tgz",
                "integrity": sha512_sri(b"x")
            }),
        )
        .unwrap_err();
        assert!(matches!(err, RefuseReason::MalformedInstallNesting(_)));
    }

    #[test]
    fn malformed_install_nesting_scope_three_parts_refused() {
        // `node_modules/@scope/pkg/extra` — a scoped portion has exactly one `/`
        // (`@scope/pkg`); a third segment (`extra`) makes it not a valid package
        // portion. Refuse rather than stage `<root>/@scope/pkg/extra`.
        let err = classify_single(
            "node_modules/@scope/pkg/extra",
            json!({
                "resolved": "https://registry.npmjs.org/x/-/x-1.0.0.tgz",
                "integrity": sha512_sri(b"x")
            }),
        )
        .unwrap_err();
        assert!(matches!(err, RefuseReason::MalformedInstallNesting(_)));
    }

    #[test]
    fn excluded_package_names_are_not_a_valid_nesting() {
        // npm's exclusion list (`node_modules`, `favicon.ico`), case-insensitive,
        // in the name part of a plain or scoped portion at any depth.
        for key in [
            "node_modules/node_modules",
            "node_modules/@a/node_modules",
            "node_modules/a/node_modules/Node_Modules",
            "node_modules/favicon.ico",
            "node_modules/@a/FAVICON.ICO",
        ] {
            let err = classify_single(
                key,
                json!({
                    "resolved": "https://registry.npmjs.org/x/-/x-1.0.0.tgz",
                    "integrity": sha512_sri(b"x")
                }),
            )
            .unwrap_err();
            assert!(
                matches!(err, RefuseReason::MalformedInstallNesting(_)),
                "{key}: {err:?}"
            );
        }
        // A scope named like an excluded name is not the name part.
        assert!(matches!(
            classify_single(
                "node_modules/@node_modules/x",
                json!({
                    "resolved": "https://registry.npmjs.org/x/-/x-1.0.0.tgz",
                    "integrity": sha512_sri(b"x")
                }),
            ),
            Ok(EntryDisposition::Install(_))
        ));
    }

    #[test]
    fn well_formed_nestings_still_install() {
        // Regression: every legit package-nesting shape must remain Install —
        // plain, scoped, nested, and nested-scoped. Verified against the fuz
        // projects' own lockfiles (zero false positives).
        for key in [
            "node_modules/foo",
            "node_modules/@scope/foo",
            "node_modules/a/node_modules/b",
            "node_modules/@s/p/node_modules/@s2/p2",
        ] {
            let d = classify_single(
                key,
                json!({
                    "resolved": "https://registry.npmjs.org/x/-/x-1.0.0.tgz",
                    "integrity": sha512_sri(b"x")
                }),
            )
            .unwrap();
            assert!(
                matches!(d, EntryDisposition::Install(_)),
                "{key} should Install, not refuse"
            );
        }
    }

    #[test]
    fn dot_leading_key_keeps_its_reason_over_malformed_nesting() {
        // `node_modules/.bin/foo` is caught by BOTH gates (its `nm_relative`
        // segment `.bin/foo` is dot-leading AND not a valid package portion). The
        // dot-leading gate runs first, so it keeps the more specific
        // `DotLeadingComponent` reason rather than the generic nesting one.
        let err = classify_single(
            "node_modules/.bin/foo",
            json!({
                "resolved": "https://registry.npmjs.org/x/-/x-1.0.0.tgz",
                "integrity": sha512_sri(b"x")
            }),
        )
        .unwrap_err();
        assert!(matches!(err, RefuseReason::DotLeadingComponent(_)));
    }

    #[test]
    fn extraneous_cannot_suppress_a_malformed_key_refusal() {
        // Containment is checked *before* the `extraneous` skip. Both orders end
        // with nothing installed at the path, so this is about the signal, not the
        // outcome: `extraneous` is an ordinary lockfile boolean, so letting it
        // short-circuit first would let tampered data silence the tamper refusal.
        let err = classify_single(
            "node_modules/x/../../../etc/evil",
            json!({"extraneous": true}),
        )
        .unwrap_err();
        assert!(matches!(err, RefuseReason::MalformedInstallPath(_)));
    }

    #[test]
    fn extraneous_sibling_escape_still_skips() {
        // The reorder must not disturb the shape real lockfiles have: npm's
        // extraneous `../<sibling>` keys are SiblingEscape, which skips before
        // `extraneous` is ever consulted.
        let d = classify_single("../fuz_app", json!({"extraneous": true})).unwrap();
        assert!(matches!(d, EntryDisposition::Skip(_)));
    }

    #[test]
    fn contradictory_platform_required_refused_optional_skipped() {
        // `os: ["linux", "!linux"]` can never match (the negation wins). Required
        // → refuse; optional → skip — guards the negation conjunction.
        let required = classify_single(
            "node_modules/contra",
            json!({
                "resolved": "https://registry.npmjs.org/c/-/c-1.0.0.tgz",
                "integrity": sha512_sri(b"c"),
                "os": ["linux", "!linux"]
            }),
        )
        .unwrap_err();
        assert!(matches!(required, RefuseReason::PlatformMismatchRequired));

        let optional = classify_single(
            "node_modules/contra-opt",
            json!({
                "resolved": "https://registry.npmjs.org/c/-/c-1.0.0.tgz",
                "integrity": sha512_sri(b"c"),
                "os": ["linux", "!linux"],
                "optional": true
            }),
        )
        .unwrap();
        assert!(matches!(
            optional,
            EntryDisposition::SkipOptionalMismatch(_)
        ));
    }

    #[test]
    fn peer_platform_mismatch_is_refused_as_required() {
        // A peer dep is neither optional nor devOptional, so a platform mismatch
        // is treated as a required mismatch (refuse loud), not a silent skip.
        let err = classify_single(
            "node_modules/peer-mac",
            json!({
                "resolved": "https://registry.npmjs.org/p/-/p-1.0.0.tgz",
                "integrity": sha512_sri(b"p"),
                "os": ["darwin"],
                "peer": true
            }),
        )
        .unwrap_err();
        assert!(matches!(err, RefuseReason::PlatformMismatchRequired));
    }

    #[test]
    fn bare_git_scheme_refused() {
        // `git://` (no `git+` prefix) is not a tarball — refused as a non-https
        // scheme (still refused, just via the scheme arm).
        let err = classify_single(
            "node_modules/g",
            json!({"resolved": "git://github.com/x/y.git", "integrity": sha512_sri(b"g")}),
        )
        .unwrap_err();
        assert!(matches!(err, RefuseReason::NonHttpsResolved(_)));
    }

    #[test]
    fn malformed_platform_token_refused() {
        let err = classify_single(
            "node_modules/bad",
            json!({
                "resolved": "https://registry.npmjs.org/bad/-/bad-1.0.0.tgz",
                "integrity": sha512_sri(b"bad"),
                "os": ["!!win32"]
            }),
        )
        .unwrap_err();
        assert!(matches!(err, RefuseReason::MalformedPlatformToken(_)));
    }

    #[test]
    fn string_form_os_is_one_token() {
        // `"os": "darwin"` (npm keeps a package's string form): an off-host
        // optional skips and an off-host required entry refuses, as the array
        // form would.
        let entry = |optional: bool| {
            json!({
                "resolved": "https://registry.npmjs.org/fsevents/-/fsevents-2.3.3.tgz",
                "integrity": sha512_sri(b"fsevents"),
                "os": "darwin",
                "optional": optional
            })
        };
        let d = classify_single("node_modules/fsevents", entry(true)).unwrap();
        assert!(matches!(d, EntryDisposition::SkipOptionalMismatch(_)));
        let err = classify_single("node_modules/fsevents", entry(false)).unwrap_err();
        assert!(matches!(err, RefuseReason::PlatformMismatchRequired));
    }

    #[test]
    fn negated_any_platform_token_refused() {
        let err = classify_single(
            "node_modules/bad",
            json!({
                "resolved": "https://registry.npmjs.org/bad/-/bad-1.0.0.tgz",
                "integrity": sha512_sri(b"bad"),
                "cpu": ["!any"]
            }),
        )
        .unwrap_err();
        assert_eq!(
            err,
            RefuseReason::MalformedPlatformToken("!any".to_string())
        );
    }

    #[test]
    fn non_npmjs_https_installs() {
        let d = classify_single(
            "node_modules/private",
            json!({
                "resolved": "https://npm.example.com/private/-/private-1.0.0.tgz",
                "integrity": sha512_sri(b"private")
            }),
        )
        .unwrap();
        assert!(matches!(d, EntryDisposition::Install(_)));
    }

    #[test]
    fn cloud_metadata_ip_resolved_refused() {
        // A tampered lock pointing at the cloud-metadata endpoint (link-local) is
        // an SSRF attempt — refused before any request fires.
        let err = classify_single(
            "node_modules/ssrf",
            json!({
                "resolved": "https://169.254.169.254/latest/meta-data/-/x-1.0.0.tgz",
                "integrity": sha512_sri(b"x")
            }),
        )
        .unwrap_err();
        assert!(matches!(err, RefuseReason::BlockedResolvedHost(_)));
    }

    #[test]
    fn localhost_resolved_refused() {
        let err = classify_single(
            "node_modules/local",
            json!({
                "resolved": "https://localhost:4873/local/-/local-1.0.0.tgz",
                "integrity": sha512_sri(b"x")
            }),
        )
        .unwrap_err();
        assert!(matches!(err, RefuseReason::BlockedResolvedHost(_)));
    }

    #[test]
    fn loopback_private_and_ipv6_resolved_refused() {
        for url in [
            "https://127.0.0.1/x/-/x-1.0.0.tgz",   // ipv4 loopback
            "https://10.0.0.5/x/-/x-1.0.0.tgz",    // ipv4 private
            "https://192.168.1.1/x/-/x-1.0.0.tgz", // ipv4 private
            "https://[::1]/x/-/x-1.0.0.tgz",       // ipv6 loopback
            "https://[fd00::1]/x/-/x-1.0.0.tgz",   // ipv6 unique-local
        ] {
            let err = classify_single(
                "node_modules/x",
                json!({ "resolved": url, "integrity": sha512_sri(b"x") }),
            )
            .unwrap_err();
            assert!(
                matches!(err, RefuseReason::BlockedResolvedHost(_)),
                "{url} should be a blocked host"
            );
        }
    }

    #[test]
    fn omit_dev_omits_dev_entry() {
        let host = host_linux_x64_glibc();
        let entry = entry_from(json!({
            "resolved": "https://registry.npmjs.org/d/-/d-1.0.0.tgz",
            "integrity": sha512_sri(b"d"),
            "dev": true
        }));
        let none = BTreeMap::new();
        let d = classify_one(
            &InstallPath::new("node_modules/d"),
            &entry,
            &host,
            &[Omit::Dev],
            &LinkIndex::new(&none),
        )
        .unwrap();
        assert!(matches!(d, EntryDisposition::Omitted(_)));
    }

    #[test]
    fn accumulates_all_refusals_in_one_pass() {
        let raw: RawLockfile = serde_json::from_value(json!({
            "lockfileVersion": 3,
            "packages": {
                "node_modules/git-dep": {
                    "resolved": "git+https://github.com/x/y.git",
                    "integrity": sha512_sri(b"g")
                },
                "node_modules/legacy": {
                    "resolved": "https://registry.npmjs.org/legacy/-/legacy-1.0.0.tgz",
                    "integrity": "sha1-qZk+NkcGgWq6PiVxeFDCbJzQ2J0="
                },
                "node_modules/degraded": {
                    "version": "1.0.0"
                }
            }
        }))
        .unwrap();
        let host = host_linux_x64_glibc();
        let (_dispositions, refusals) = classify(&raw, &host, &[]);
        assert_eq!(refusals.len(), 3);
        // Deterministic BTreeMap order: degraded, git-dep, legacy.
        assert!(matches!(refusals[0].reason, RefuseReason::MissingIntegrity));
        assert!(matches!(refusals[1].reason, RefuseReason::GitDep(_)));
        assert!(matches!(refusals[2].reason, RefuseReason::Sha1Integrity));
    }

    #[test]
    fn render_refusals_formats_lines() {
        let refusals = vec![Refusal {
            path: InstallPath::new("node_modules/foo"),
            reason: RefuseReason::Sha1Integrity,
        }];
        let s = render_refusals(&refusals);
        assert!(s.contains("node_modules/foo"));
        assert!(s.contains("sha1-only integrity"));
    }

    #[test]
    fn render_refusals_groups_and_caps_a_wall() {
        // 20 same-reason refusals collapse to one group with a capped example list
        // ("loud once, not crying wolf") — the fuz_ui degraded-lock shape.
        let refusals: Vec<Refusal> = (0..20)
            .map(|i| Refusal {
                path: InstallPath::new(format!("node_modules/p{i}")),
                reason: RefuseReason::MissingIntegrity,
            })
            .collect();
        let s = render_refusals(&refusals);
        assert!(s.contains("refused 20 entries"));
        assert!(s.contains("missing_integrity (20)"));
        assert!(s.contains("+12 more")); // 20 - REFUSAL_EXAMPLE_CAP(8)
        // The whole block is far shorter than 20 lines.
        assert!(s.lines().count() < 14);
    }

    // --- links ---

    const ZAP: &str = "node_modules/@fuzdev/zap";

    /// The owned-lockfile shape: npm's `{resolved, link}` link entry plus its
    /// named sibling target entry, with `link` and `target` overridable.
    fn zap_lock(link: serde_json::Value, target: serde_json::Value) -> RawLockfile {
        let mut lock = json!({
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "app", "devDependencies": {"@fuzdev/zap": "file:../zap"}}
            }
        });
        lock["packages"][ZAP] = link;
        lock["packages"]["../zap"] = target;
        serde_json::from_value(lock).unwrap()
    }

    fn zap_target() -> serde_json::Value {
        json!({
            "name": "@fuzdev/zap", "version": "0.0.1", "dev": true, "license": "MIT",
            "devDependencies": {"@fuzdev/gro": "^0.213.0"}
        })
    }

    fn zap_link() -> serde_json::Value {
        json!({"resolved": "../zap", "link": true})
    }

    /// Classify a whole lockfile on the fixed test host.
    fn classify_lock(raw: &RawLockfile, omit: &[Omit]) -> (Vec<EntryDisposition>, Vec<Refusal>) {
        classify(raw, &host_linux_x64_glibc(), omit)
    }

    /// The outcome for the entry at `key` in a whole-lockfile classify.
    fn outcome_at(
        raw: &RawLockfile,
        omit: &[Omit],
        key: &str,
    ) -> Result<EntryDisposition, RefuseReason> {
        let (dispositions, refusals) = classify_lock(raw, omit);
        if let Some(r) = refusals.into_iter().find(|r| r.path.as_str() == key) {
            return Err(r.reason);
        }
        let found = dispositions.into_iter().find(|d| {
            let p = match d {
                EntryDisposition::Install(e) => &e.path,
                EntryDisposition::Link(l) => &l.path,
                EntryDisposition::SkipOptionalMismatch(p)
                | EntryDisposition::Omitted(p)
                | EntryDisposition::Skip(p) => p,
            };
            p.as_str() == key
        });
        Ok(found.unwrap_or_else(|| panic!("no outcome for {key}")))
    }

    fn link_err(raw: &RawLockfile) -> RefuseReason {
        match outcome_at(raw, &[], ZAP) {
            Err(reason) => reason,
            Ok(d) => panic!("expected a refusal for the link, got {d:?}"),
        }
    }

    #[test]
    fn sibling_link_is_accepted_and_its_target_skipped() {
        // The exact shape the owned link lockfiles carry.
        let raw = zap_lock(zap_link(), zap_target());
        let (dispositions, refusals) = classify_lock(&raw, &[]);
        assert!(refusals.is_empty(), "{refusals:?}");
        let link = dispositions
            .iter()
            .find_map(|d| match d {
                EntryDisposition::Link(l) => Some(l),
                _ => None,
            })
            .expect("a Link disposition");
        assert_eq!(link.path.as_str(), ZAP);
        assert_eq!(link.target.as_resolved(), "../zap");
        assert_eq!(link.name.as_deref(), Some("@fuzdev/zap"));
        assert_eq!(link.version.as_deref(), Some("0.0.1"));
        assert!(link.bins.is_empty());
        assert!(matches!(
            outcome_at(&raw, &[], "../zap"),
            Ok(EntryDisposition::Skip(_))
        ));
    }

    #[test]
    fn link_flags_come_from_the_target_under_omit() {
        // The target carries `dev`, so `--omit dev` omits the link; with the
        // flag on the target cleared it survives.
        let raw = zap_lock(zap_link(), zap_target());
        assert!(matches!(
            outcome_at(&raw, &[Omit::Dev], ZAP),
            Ok(EntryDisposition::Omitted(_))
        ));
        let prod = zap_lock(
            zap_link(),
            json!({"name": "@fuzdev/zap", "version": "0.0.1"}),
        );
        assert!(matches!(
            outcome_at(&prod, &[Omit::Dev], ZAP),
            Ok(EntryDisposition::Link(_))
        ));
        let optional = zap_lock(zap_link(), json!({"name": "@fuzdev/zap", "optional": true}));
        assert!(matches!(
            outcome_at(&optional, &[Omit::Optional], ZAP),
            Ok(EntryDisposition::Omitted(_))
        ));
        // devOptional survives either class alone, falls to both.
        let dev_optional = zap_lock(
            zap_link(),
            json!({"name": "@fuzdev/zap", "devOptional": true}),
        );
        assert!(matches!(
            outcome_at(&dev_optional, &[Omit::Dev], ZAP),
            Ok(EntryDisposition::Link(_))
        ));
        assert!(matches!(
            outcome_at(&dev_optional, &[Omit::Optional], ZAP),
            Ok(EntryDisposition::Link(_))
        ));
        assert!(matches!(
            outcome_at(&dev_optional, &[Omit::Dev, Omit::Optional], ZAP),
            Ok(EntryDisposition::Omitted(_))
        ));
    }

    #[test]
    fn link_target_platform_mismatch_skips_optional_refuses_required() {
        let optional = zap_lock(
            zap_link(),
            json!({"name": "@fuzdev/zap", "os": ["darwin"], "optional": true}),
        );
        assert!(matches!(
            outcome_at(&optional, &[], ZAP),
            Ok(EntryDisposition::SkipOptionalMismatch(_))
        ));
        let dev_optional = zap_lock(
            zap_link(),
            json!({"name": "@fuzdev/zap", "os": ["darwin"], "devOptional": true}),
        );
        assert!(matches!(
            outcome_at(&dev_optional, &[], ZAP),
            Ok(EntryDisposition::SkipOptionalMismatch(_))
        ));
        let required = zap_lock(zap_link(), json!({"name": "@fuzdev/zap", "os": ["darwin"]}));
        assert_eq!(link_err(&required), RefuseReason::PlatformMismatchRequired);
        let malformed = zap_lock(zap_link(), json!({"name": "@fuzdev/zap", "os": ["!!x"]}));
        assert!(matches!(
            link_err(&malformed),
            RefuseReason::MalformedPlatformToken(_)
        ));
    }

    #[test]
    fn malformed_link_resolved_is_refused() {
        // The target entry sits at the very key `resolved` names, so the parse is
        // the only thing that can refuse (not a missing target entry).
        for resolved in [
            "/home/u/zap",
            "x/../..",
            "../.hidden",
            "../x\0y",
            "..\\x",
            "file:../x",
            "../x\u{202e}y",
            "../x\u{9b}y",
            "../node_modules",
            &format!("../{}", "a".repeat(256)),
        ] {
            let mut lock = json!({"lockfileVersion": 3, "packages": {}});
            lock["packages"][ZAP] = json!({"resolved": resolved, "link": true});
            lock["packages"][resolved] = zap_target();
            let raw: RawLockfile = serde_json::from_value(lock).unwrap();
            match link_err(&raw) {
                RefuseReason::MalformedLink(detail) => {
                    assert!(detail.contains("resolved"), "{resolved:?}: {detail}");
                }
                other => panic!("{resolved:?} must be a MalformedLink, got {other:?}"),
            }
        }
        let missing = zap_lock(json!({"link": true}), zap_target());
        assert!(matches!(link_err(&missing), RefuseReason::MalformedLink(_)));
    }

    #[test]
    fn link_entry_with_any_modeled_field_is_malformed() {
        for (field, value) in [
            ("integrity", json!(sha512_sri(b"x"))),
            ("version", json!("1.0.0")),
            ("name", json!("@fuzdev/zap")),
            ("bin", json!({"zap": "cli.js"})),
            ("dependencies", json!({"x": "^1"})),
            ("devDependencies", json!({"x": "^1"})),
            ("optionalDependencies", json!({"x": "^1"})),
            ("peerDependencies", json!({"x": "^1"})),
            ("dev", json!(true)),
            ("optional", json!(true)),
            ("devOptional", json!(true)),
            ("peer", json!(true)),
            ("os", json!(["linux"])),
            ("cpu", json!(["x64"])),
            ("libc", json!(["glibc"])),
            ("hasInstallScript", json!(true)),
            ("inBundle", json!(true)),
        ] {
            let mut link = zap_link();
            link[field] = value;
            let raw = zap_lock(link, zap_target());
            match link_err(&raw) {
                RefuseReason::MalformedLink(detail) => {
                    assert!(detail.contains(field), "{field}: {detail}");
                }
                other => panic!("{field}: expected MalformedLink, got {other:?}"),
            }
        }
    }

    #[test]
    fn link_with_a_bad_target_entry_is_malformed() {
        let missing: RawLockfile = serde_json::from_value(json!({
            "lockfileVersion": 3,
            "packages": {ZAP: zap_link()}
        }))
        .unwrap();
        assert!(matches!(link_err(&missing), RefuseReason::MalformedLink(_)));
        for target in [
            json!({"name": ""}),                                           // empty name
            json!({"name": "@fuzdev/zap", "link": true}),                  // a link
            json!({"name": "@fuzdev/zap", "extraneous": true}),            // extraneous
            json!({"name": "@fuzdev/zap", "inBundle": true}),              // bundled
            json!({"name": "@fuzdev/zap", "integrity": sha512_sri(b"z")}), // a tarball
            json!({"name": "@fuzdev/zap", "resolved": "https://r/z.tgz"}), // a tarball
        ] {
            let raw = zap_lock(zap_link(), target.clone());
            assert!(
                matches!(link_err(&raw), RefuseReason::MalformedLink(_)),
                "target {target} must refuse"
            );
        }
    }

    #[test]
    fn unnamed_target_entry_is_accepted_with_its_name_left_to_the_disk() {
        // npm omits a target's `name` when it equals the folder default — the
        // shape `"file:../localpkg"` deps produce. Classify accepts it and leaves
        // the default (which depends on the parent directory) to the link check.
        let raw = zap_lock(zap_link(), json!({"version": "0.0.1", "dev": true}));
        match outcome_at(&raw, &[], ZAP) {
            Ok(EntryDisposition::Link(link)) => assert_eq!(link.name, None),
            other => panic!("expected Link, got {other:?}"),
        }
    }

    #[test]
    fn deferred_link_shapes_refuse_as_unsupported() {
        for resolved in ["../../x", "../a/b"] {
            let raw: RawLockfile = serde_json::from_value(json!({
                "lockfileVersion": 3,
                "packages": {
                    ZAP: {"resolved": resolved, "link": true},
                    resolved: {"name": "@fuzdev/zap"}
                }
            }))
            .unwrap();
            assert!(
                matches!(link_err(&raw), RefuseReason::LinkUnsupported(_)),
                "{resolved}"
            );
        }
    }

    #[test]
    fn ancestor_key_is_skipped_whatever_it_carries() {
        // Pin: a `..`-only key is out of the tree like a sibling key, so it is
        // never fetched, placed, or linked — whatever the entry claims to be.
        let registry = json!({
            "resolved": "http://169.254.169.254/x.tgz",
            "integrity": sha512_sri(b"x"),
            "bin": {"x": "../../evil"},
            "hasInstallScript": true
        });
        for key in ["..", "../..", "../../.."] {
            for entry in [
                registry.clone(),
                json!({"resolved": "/etc", "link": true}),
                json!({"inBundle": true}),
            ] {
                assert!(
                    matches!(classify_single(key, entry), Ok(EntryDisposition::Skip(_))),
                    "{key}"
                );
            }
        }
    }

    #[test]
    fn ancestor_link_refuses_once_as_unsupported() {
        // The shape npm writes for an `examples/<x>` project that depends on
        // `"file:../.."`: a link whose `resolved` is an ancestor directory,
        // beside a target entry keyed by that same `../..`. It is a real
        // lockfile, so the refusal is "not supported — use npm", once, on the
        // link; the target entry is skipped like any other out-of-tree key.
        for ancestor in ["..", "../..", "../../.."] {
            let mut lock = json!({
                "lockfileVersion": 3,
                "packages": {
                    "": {"name": "example", "dependencies": {"pkg": "file:../.."}}
                }
            });
            lock["packages"]["node_modules/pkg"] = json!({"resolved": ancestor, "link": true});
            lock["packages"][ancestor] = json!({"name": "pkg", "version": "1.0.0"});
            let raw: RawLockfile = serde_json::from_value(lock).unwrap();
            let (dispositions, refusals) = classify_lock(&raw, &[]);
            assert_eq!(refusals.len(), 1, "{ancestor}: {refusals:?}");
            assert_eq!(refusals[0].path.as_str(), "node_modules/pkg");
            match &refusals[0].reason {
                RefuseReason::LinkUnsupported(detail) => {
                    assert!(detail.contains("ancestor"), "{detail}");
                }
                other => panic!("{ancestor}: expected LinkUnsupported, got {other:?}"),
            }
            // Nothing became installable: the root and the target entry skip.
            assert_eq!(dispositions.len(), 2, "{dispositions:?}");
            assert!(
                dispositions
                    .iter()
                    .all(|d| matches!(d, EntryDisposition::Skip(_))),
                "{dispositions:?}"
            );
        }
    }

    #[test]
    fn in_tree_workspace_link_refuses_once() {
        // webref's shape, including its alias (`css6` → `@webref/css`): the
        // in-tree target entry carries no integrity, so without the target skip
        // it would refuse a second time as MissingIntegrity.
        let raw: RawLockfile = serde_json::from_value(json!({
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "webref"},
                "node_modules/@webref/css6": {"resolved": "packages/css6", "link": true},
                "packages/css6": {"name": "@webref/css", "version": "6.23.14", "dev": true}
            }
        }))
        .unwrap();
        let (_, refusals) = classify_lock(&raw, &[]);
        assert_eq!(refusals.len(), 1, "{refusals:?}");
        assert_eq!(refusals[0].path.as_str(), "node_modules/@webref/css6");
        assert!(matches!(
            refusals[0].reason,
            RefuseReason::LinkUnsupported(_)
        ));
    }

    #[test]
    fn a_link_naming_itself_or_its_peer_still_refuses() {
        // Without the link-entry exemption, the target skip would swallow the
        // link entry itself and nothing would refuse.
        let raw: RawLockfile = serde_json::from_value(json!({
            "lockfileVersion": 3,
            "packages": {
                "node_modules/a": {"resolved": "node_modules/a", "link": true},
                "node_modules/b": {"resolved": "node_modules/c", "link": true},
                "node_modules/c": {"resolved": "node_modules/b", "link": true}
            }
        }))
        .unwrap();
        let (_, refusals) = classify_lock(&raw, &[]);
        let refused: Vec<&str> = refusals.iter().map(|r| r.path.as_str()).collect();
        assert_eq!(
            refused,
            ["node_modules/a", "node_modules/b", "node_modules/c"]
        );
    }

    #[test]
    fn a_link_that_skips_early_does_not_hide_its_target() {
        // Extraneous, root, and `../`-keyed links never reach classify_link, so
        // they must not make the registry entry they name skip silently.
        for (key, extra) in [
            ("node_modules/stale", json!({"extraneous": true})),
            ("", json!({})),
            ("../elsewhere", json!({})),
        ] {
            let mut link = json!({"resolved": "node_modules/foo", "link": true});
            if let Some(map) = extra.as_object() {
                for (k, v) in map {
                    link[k] = v.clone();
                }
            }
            let mut lock = json!({"lockfileVersion": 3, "packages": {
                "node_modules/foo": {
                    "resolved": "https://registry.npmjs.org/foo/-/foo-1.0.0.tgz",
                    "integrity": sha512_sri(b"foo")
                }
            }});
            lock["packages"][key] = link;
            let raw: RawLockfile = serde_json::from_value(lock).unwrap();
            assert!(
                matches!(
                    outcome_at(&raw, &[], "node_modules/foo"),
                    Ok(EntryDisposition::Install(_))
                ),
                "a link at {key:?} hid node_modules/foo"
            );
        }
    }

    #[test]
    fn nested_link_key_refuses_as_unsupported() {
        let raw: RawLockfile = serde_json::from_value(json!({
            "lockfileVersion": 3,
            "packages": {
                "node_modules/a/node_modules/zap": zap_link(),
                "../zap": zap_target()
            }
        }))
        .unwrap();
        match outcome_at(&raw, &[], "node_modules/a/node_modules/zap") {
            Err(RefuseReason::LinkUnsupported(detail)) => assert!(detail.contains("nested")),
            other => panic!("expected LinkUnsupported, got {other:?}"),
        }
    }

    #[test]
    fn entry_under_a_link_key_is_refused_even_extraneous() {
        for extra in [json!({}), json!({"extraneous": true})] {
            let mut nested = json!({
                "resolved": "https://registry.npmjs.org/x/-/x-1.0.0.tgz",
                "integrity": sha512_sri(b"x")
            });
            if let Some(map) = extra.as_object() {
                for (k, v) in map {
                    nested[k] = v.clone();
                }
            }
            let raw: RawLockfile = serde_json::from_value(json!({
                "lockfileVersion": 3,
                "packages": {
                    ZAP: zap_link(),
                    "../zap": zap_target(),
                    "node_modules/@fuzdev/zap/node_modules/x": nested
                }
            }))
            .unwrap();
            assert!(matches!(
                outcome_at(&raw, &[], "node_modules/@fuzdev/zap/node_modules/x"),
                Err(RefuseReason::NestedUnderLink(_))
            ));
        }
    }

    #[test]
    fn a_link_whose_scope_ends_in_node_modules_is_depth_one() {
        // `@foo-node_modules` is a scope, not a nesting boundary: the key is a
        // top-level link and is placed, while a real nested key still refuses
        // (`nested_link_key_refuses_as_unsupported`).
        const KEY: &str = "node_modules/@foo-node_modules/zap";
        let raw: RawLockfile = serde_json::from_value(json!({
            "lockfileVersion": 3,
            "packages": {
                KEY: zap_link(),
                "../zap": zap_target()
            }
        }))
        .unwrap();
        assert!(matches!(
            outcome_at(&raw, &[], KEY),
            Ok(EntryDisposition::Link(_))
        ));
    }

    #[test]
    fn a_name_sharing_a_link_prefix_is_not_nested() {
        // `node_modules/@fuzdev/zap-extra` is not under `node_modules/@fuzdev/zap`.
        let raw: RawLockfile = serde_json::from_value(json!({
            "lockfileVersion": 3,
            "packages": {
                ZAP: zap_link(),
                "../zap": zap_target(),
                "node_modules/@fuzdev/zap-extra": {
                    "resolved": "https://registry.npmjs.org/x/-/x-1.0.0.tgz",
                    "integrity": sha512_sri(b"x")
                }
            }
        }))
        .unwrap();
        assert!(matches!(
            outcome_at(&raw, &[], "node_modules/@fuzdev/zap-extra"),
            Ok(EntryDisposition::Install(_))
        ));
    }

    #[test]
    fn link_key_with_a_non_name_character_refuses() {
        for key in [
            "node_modules/za\u{202e}p",
            "node_modules/@fuz\u{200b}dev/zap",
            "node_modules/zap\u{85}",
            "node_modules/z\u{430}p",
            "node_modules/@fuzdev/zap 2",
        ] {
            let raw: RawLockfile = serde_json::from_value(json!({
                "lockfileVersion": 3,
                "packages": {key: zap_link(), "../zap": zap_target()}
            }))
            .unwrap();
            assert!(
                matches!(
                    outcome_at(&raw, &[], key),
                    Err(RefuseReason::InvalidNameCharacter(_))
                ),
                "{key:?}"
            );
        }
    }

    #[test]
    fn link_and_target_entry_pair_byte_exactly() {
        // Pin: no Unicode normalization. A link whose `resolved` is the NFC
        // spelling does not pair with a target entry keyed by the NFD one — the
        // target reads as missing, and the stray target entry skips as a sibling.
        let nfc = "../caf\u{e9}";
        let nfd = "../cafe\u{301}";
        let mut lock = json!({"lockfileVersion": 3, "packages": {}});
        lock["packages"][ZAP] = json!({"resolved": nfc, "link": true});
        lock["packages"][nfd] = zap_target();
        let raw: RawLockfile = serde_json::from_value(lock).unwrap();
        match link_err(&raw) {
            RefuseReason::MalformedLink(detail) => {
                assert!(detail.contains("is missing from the lockfile"), "{detail}");
            }
            other => panic!("expected MalformedLink, got {other:?}"),
        }
        // The same form on both sides pairs.
        let mut lock = json!({"lockfileVersion": 3, "packages": {}});
        lock["packages"][ZAP] = json!({"resolved": nfd, "link": true});
        lock["packages"][nfd] = zap_target();
        let raw: RawLockfile = serde_json::from_value(lock).unwrap();
        assert!(matches!(
            outcome_at(&raw, &[], ZAP),
            Ok(EntryDisposition::Link(_))
        ));
    }

    #[test]
    fn link_bins_come_from_the_target_entry() {
        let mut target = zap_target();
        target["bin"] = json!({"zap": "bin/zap.js"});
        let raw = zap_lock(zap_link(), target);
        match outcome_at(&raw, &[], ZAP) {
            Ok(EntryDisposition::Link(link)) => {
                assert_eq!(
                    link.bins
                        .get(&crate::entry::BinCommand::parse("zap").unwrap())
                        .map(crate::entry::BinTarget::as_str),
                    Some("bin/zap.js")
                );
            }
            other => panic!("expected Link, got {other:?}"),
        }
        let mut evil = zap_target();
        evil["bin"] = json!({"zap": "../../../etc/passwd"});
        let raw = zap_lock(zap_link(), evil);
        assert!(matches!(link_err(&raw), RefuseReason::MalformedBin(_)));
    }

    #[test]
    fn link_keys_pass_the_node_modules_key_gates() {
        for (key, expect_dot) in [
            ("node_modules/.bin", true),
            ("node_modules/@scope", false),
            ("node_modules/foo/bar", false),
            ("node_modules/@a/node_modules", false),
            ("node_modules/node_modules", false),
        ] {
            let raw: RawLockfile = serde_json::from_value(json!({
                "lockfileVersion": 3,
                "packages": {key: zap_link(), "../zap": zap_target()}
            }))
            .unwrap();
            let reason = outcome_at(&raw, &[], key).unwrap_err();
            if expect_dot {
                assert!(
                    matches!(reason, RefuseReason::DotLeadingComponent(_)),
                    "{key}"
                );
            } else {
                assert!(
                    matches!(reason, RefuseReason::MalformedInstallNesting(_)),
                    "{key}: {reason:?}"
                );
            }
        }
        let raw: RawLockfile = serde_json::from_value(json!({
            "lockfileVersion": 3,
            "packages": {"packages/zap": zap_link(), "../zap": zap_target()}
        }))
        .unwrap();
        assert!(matches!(
            outcome_at(&raw, &[], "packages/zap"),
            Err(RefuseReason::NonNodeModulesInstall(_))
        ));
    }

    /// Pins every `RefuseReason`'s stable `--json` `code()` string (and asserts a
    /// non-empty `why()`) — the per-refusal contract, the analog of
    /// `FuziError::kind`. Enumerating every variant explicitly here is what turns a
    /// renamed or dropped code into a test failure rather than a silent
    /// wire-contract break.
    #[test]
    fn refuse_reason_code_taxonomy_is_stable() {
        let cases: &[(RefuseReason, &str)] = &[
            (RefuseReason::Sha1Integrity, "sha1_integrity"),
            (RefuseReason::MissingIntegrity, "missing_integrity"),
            (RefuseReason::MissingResolved, "missing_resolved"),
            (
                RefuseReason::MalformedInstallPath("x".into()),
                "malformed_install_path",
            ),
            (
                RefuseReason::MalformedIntegrity("x".into()),
                "malformed_integrity",
            ),
            (RefuseReason::GitDep("x".into()), "git_dep"),
            (RefuseReason::FileDep("x".into()), "file_dep"),
            (
                RefuseReason::NonHttpsResolved("x".into()),
                "non_https_resolved",
            ),
            (
                RefuseReason::BlockedResolvedHost("x".into()),
                "blocked_resolved_host",
            ),
            (
                RefuseReason::LinkUnsupported("x".into()),
                "link_unsupported",
            ),
            (RefuseReason::MalformedLink("x".into()), "malformed_link"),
            (
                RefuseReason::NestedUnderLink("x".into()),
                "nested_under_link",
            ),
            (RefuseReason::BundledUnsupported, "bundled_unsupported"),
            (
                RefuseReason::MalformedPlatformToken("x".into()),
                "malformed_platform_token",
            ),
            (RefuseReason::MalformedBin("x".into()), "malformed_bin"),
            (
                RefuseReason::NonNodeModulesInstall("x".into()),
                "non_node_modules_install",
            ),
            (
                RefuseReason::WorkspaceInstall("x".into()),
                "workspace_install",
            ),
            (
                RefuseReason::DotLeadingComponent("x".into()),
                "dot_leading_component",
            ),
            (
                RefuseReason::MalformedInstallNesting("x".into()),
                "malformed_install_nesting",
            ),
            (
                RefuseReason::InvalidNameCharacter("x".into()),
                "invalid_name_character",
            ),
            (
                RefuseReason::PlatformMismatchRequired,
                "platform_mismatch_required",
            ),
        ];
        for (reason, code) in cases {
            assert_eq!(reason.code(), *code, "code for {code}");
            assert!(!reason.why().is_empty(), "why for {code} must be non-empty");
        }
    }
}
