//! The `node_modules` staging tree: build into a fresh, fuzi-owned
//! `.fuzi-installing-<rand>` directory, then publish it with one atomic rename.
//!
//! The staging swap is **security-load-bearing, not just idempotent**.
//! [`crate::extract::extract_package`] writes with no `O_NOFOLLOW`, so it is safe
//! only against a fuzi-owned destination: a pre-existing on-disk symlink under
//! the destination would be followed. Extracting into a fresh staging tree (that
//! no other writer has touched) and atomically renaming it over `node_modules`
//! guarantees the destination is always fuzi-owned and that a crash or a hostile
//! tarball can never leave a half-materialized tree a later run would trust.
//!
//! The trust precondition is reified in the type: a [`StagingDir`] (the only
//! thing `extract_package` accepts as a destination) is constructible **solely**
//! via [`StagingTree::package_dir`], so "never a live `node_modules`" is a
//! compile fact rather than a doc comment.
//!
//! Sibling `link: true` packages are placed here too, as relative symlinks
//! ([`StagingTree::place_link`]), and only **after** every extraction has
//! finished. Classify refuses any key nested under a link key, so no extraction
//! destination ever lies through a link; placing the links last makes that hold
//! even against a placement order a future change might introduce. Every key
//! — a placement's ([`StagingTree::package_dir`]) and a link's — passes the
//! same `node_modules` key gate here that classify applies, so a link can
//! never sit at `.bin` (or any dot-leading name) and turn a directory fuzi
//! writes into a symlink to the sibling, and a placement can never sit at a
//! bare `@scope` directory and so hold a link inside itself. The relative
//! symlink text resolves identically from the staging root and from
//! `node_modules` (siblings under the project), so the publish rename moves the
//! links as-is. Every removal path — the cleanup guard, the displaced-tree
//! removal, the interrupt drain, `fuzi clean` — goes through `remove_dir_all`,
//! which unlinks a symlink rather than descending into its target.
//!
//! Two guards cover the two ways an install can end early: a [`CleanupGuard`]
//! removes the staging root on an unwound return, and a registration with
//! `crate::interrupt` exposes it to the signal drain for the exits that never
//! unwind. The registration also refuses at both ends of the tree's life once
//! a drain has acted: no staging root is created after a drain fired (it would
//! be removed by no one), and no publish runs for a tree a drain claimed (the
//! swap would move a live `node_modules` aside for a tree that is being
//! deleted). Neither guard covers a release-build panic (`panic = "abort"`) or
//! a SIGKILL — `fuzi clean` is the backstop there.
//!
//! Nothing in fuzi removes part of a tree it is still building, but another
//! process can: `fuzi clean` sweeps every `.fuzi-installing-*` it finds, live
//! or not. The tree records what it placed — each package directory and the
//! `package.json` its tarball shipped, each link, each `.bin` link — and
//! [`StagingTree::commit`] refuses to publish while any of it is missing
//! ([`FuziError::StagingIncomplete`]), so a tree missing a package, a shipped
//! `package.json`, a link, or a `.bin` link never becomes `node_modules`
//! (files within a package are not checked: a sweep that stops part-way can
//! leave a package missing files and still publish, until the planned install
//! lock). Every directory is created below the root, so a fully swept root
//! fails the next write with `NotFound` rather than coming back, and
//! [`StagingTree::explain_not_found`] reports that the same way. Both are cheap
//! `lstat`s against a race the planned project-level install lock (shared with
//! `clean`) will close; until then a sweep landing between the check and the
//! publish rename still gets through.

use std::collections::BTreeMap;
use std::fs::{self, DirBuilder};
use std::io;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, symlink};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use fuz_archive::create_dir_all_below;
use fuz_sys::fs::{CleanupGuard, fsync_dir};
use fuz_sys::rand::random_hex_suffix;

use crate::classify::{valid_package_portion, validate_nm_key};
use crate::entry::{InstallPath, LinkTarget};
use crate::error::{FuziError, NodeModulesObstruction, StagingEntry, io_err};
use crate::interrupt::{
    PublishRefused, RegisterRefused, Registry, STAGING_ROOTS, StagingRegistration,
};

/// Mode for fuzi-created `node_modules` directories — the conventional `0o755`
/// (npm/pnpm default), not the `0o700` of `~/.fuz` (a project tree is not a
/// per-user secret store).
const NODE_MODULES_DIR_MODE: u32 = 0o755;

/// The directory name fuzi materializes into / publishes.
const NODE_MODULES: &str = "node_modules";

/// Prefix for the in-progress staging root (`<project>/.fuzi-installing-<rand>`).
const STAGING_PREFIX: &str = ".fuzi-installing-";

/// Prefix for a displaced prior `node_modules` during the swap
/// (`<project>/.fuzi-old-<rand>`), removed once the new tree is in place.
const OLD_PREFIX: &str = ".fuzi-old-";

/// The publishable state of a `node_modules` target path.
enum TargetState {
    /// Nothing there — publish directly.
    Absent,
    /// A real directory — move aside and replace.
    Directory,
}

/// Classify the publish target, refusing anything fuzi must not silently delete
/// or follow, or cannot replace. A real directory or an absent path is
/// publishable; a **symlink** or a **regular file** is refused loud
/// ([`FuziError::NodeModulesNotDirectory`]) — fuzi owns and replaces the whole
/// `node_modules` tree, but a deliberate symlink (pnpm-style, or pointed
/// elsewhere by the user) must not be swallowed, and following it would write
/// through `O_NOFOLLOW`-less extraction into an untrusted destination. A
/// directory on another device than its parent is a **mount point**
/// ([`FuziError::NodeModulesMountPoint`]): the swap's renames would fail on it
/// with a bare `EBUSY`, after the whole fetch.
///
/// Uses `symlink_metadata` (lstat — does not follow), so a symlink is detected
/// as a symlink, not as whatever it targets.
fn classify_target(final_path: &Path) -> Result<TargetState, FuziError> {
    match fs::symlink_metadata(final_path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(TargetState::Absent),
        Err(source) => Err(io_err("inspect node_modules target")(source)),
        Ok(meta) if meta.file_type().is_symlink() => Err(FuziError::NodeModulesNotDirectory {
            kind: NodeModulesObstruction::Symlink,
        }),
        Ok(meta) if meta.is_dir() => {
            let parent = final_path.parent().unwrap_or_else(|| Path::new("."));
            let parent_meta =
                fs::metadata(parent).map_err(io_err("inspect node_modules parent directory"))?;
            directory_state(meta.dev(), parent_meta.dev())
        }
        Ok(_) => Err(FuziError::NodeModulesNotDirectory {
            kind: NodeModulesObstruction::File,
        }),
    }
}

/// The publish state of a `node_modules` directory on device `dev` whose
/// parent is on `parent_dev`: the same device is an ordinary directory, a
/// different one a mount point. Split out of [`classify_target`] so the
/// mount-point arm is testable without mounting anything.
const fn directory_state(dev: u64, parent_dev: u64) -> Result<TargetState, FuziError> {
    if dev == parent_dev {
        Ok(TargetState::Directory)
    } else {
        Err(FuziError::NodeModulesMountPoint)
    }
}

/// The error for a failed move-aside of `node_modules`.
///
/// - `EBUSY` is a mount point the device check missed: a bind mount from the
///   same filesystem shares its parent's device, and the kernel refuses to
///   rename a mount point.
/// - `EXDEV` is not a mount point — the device check already refused those,
///   and renaming a mount root gives `EBUSY`. It is a filesystem that won't
///   rename this directory in place: on Linux, overlayfs refusing a directory
///   from a lower layer (a `node_modules` baked into a container image).
/// - Anything else is plain I/O.
fn move_aside_error(source: io::Error) -> FuziError {
    match source.kind() {
        io::ErrorKind::ResourceBusy => FuziError::NodeModulesMountPoint,
        io::ErrorKind::CrossesDevices => FuziError::NodeModulesNotRenameable,
        _ => io_err("move existing node_modules aside")(source),
    }
}

/// True iff `rel` is safe to `root.join(rel)` without the join escaping the
/// staging root: a **non-empty relative path of `Normal` components only** — no
/// root/prefix (an absolute arg would replace the base), no `..` (would walk
/// out), and not empty (would resolve to the root itself). The structural
/// counterpart of [`crate::entry::InstallPath::containment`] on the *joined*
/// side of the trust boundary. `Path::components()` normalizes `.` and empty
/// (`//`) components away, so those cannot appear here — they are refused on the
/// raw key by `containment`, upstream.
fn is_safe_relative(rel: &str) -> bool {
    use std::path::{Component, Path};
    let path = Path::new(rel);
    !rel.is_empty()
        && path.is_relative()
        && path.components().all(|c| matches!(c, Component::Normal(_)))
}

/// Create the staging root itself at the `node_modules` mode (`0o755`) —
/// one directory, never its parents, mapping failure to a typed
/// [`FuziError::Io`] tagged `what`. Only [`StagingTree::create`] calls it, under
/// the interrupt registry's lock; every other staging mkdir is
/// [`make_dir_below`].
fn make_root_dir(path: &Path, what: &'static str) -> Result<(), FuziError> {
    DirBuilder::new()
        .mode(NODE_MODULES_DIR_MODE)
        .create(path)
        .map_err(|source| FuziError::Io { what, source })
}

/// Create `path` and its missing parents at the `node_modules` mode, **strictly
/// below** the staging `root` — never the root itself (see
/// [`create_dir_all_below`]). Single-sources the dir-mode, the floor, and the
/// error shape for every staging mkdir after the root's.
///
/// The floor is what keeps a removed root removed. The interrupt drain (or
/// another process) can delete the root while this install is still writing
/// into it; a recursive `mkdir` would then re-create the root and leave a tree
/// no one removes. Floored, the writer gets `NotFound` instead, so the only
/// thing that ever creates a staging root is [`StagingTree::create`], which
/// refuses once a drain has fired.
fn make_dir_below(root: &Path, path: &Path, what: &'static str) -> Result<(), FuziError> {
    create_dir_all_below(root, path, NODE_MODULES_DIR_MODE)
        .map_err(|source| FuziError::Io { what, source })
}

/// The rename pair that publishes `root` as `final_path`: move any existing
/// tree aside, then rename the staging root into place, returning the displaced
/// tree for the caller to remove.
///
/// Split out of [`StagingTree::commit`] because it is the section that runs
/// **under the interrupt registry's lock** (see
/// [`StagingRegistration::publish`]) — keeping it a named unit keeps that
/// critical section as small and as visible as it is load-bearing. Everything
/// here is two renames (three on the restore-on-failure path) and an lstat; no
/// fsync, no recursive removal.
///
/// # Errors
///
/// [`FuziError::NodeModulesNotDirectory`] if the target turned into a symlink or
/// file since the fail-fast check; [`FuziError::NodeModulesMountPoint`] if it is
/// (or the move-aside finds it to be) a mount point;
/// [`FuziError::NodeModulesNotRenameable`] if the filesystem refuses to rename
/// it (`EXDEV`); [`FuziError::Io`] if either rename fails otherwise (the
/// displaced tree is restored first, and a failed restore is reported with the
/// path it was parked at).
fn swap_into_place(root: &Path, final_path: &Path) -> Result<Option<PathBuf>, FuziError> {
    swap_into_place_with(root, final_path, |from, to| fs::rename(from, to))
}

/// [`swap_into_place`] over an injected `rename` — the seam that lets a test
/// fail the publish *and* the restore, a state no filesystem setup reaches
/// deterministically (the restore reverses a rename that just succeeded).
fn swap_into_place_with(
    root: &Path,
    final_path: &Path,
    mut rename: impl FnMut(&Path, &Path) -> io::Result<()>,
) -> Result<Option<PathBuf>, FuziError> {
    let parent = final_path.parent().unwrap_or_else(|| Path::new("."));

    // Move an existing tree aside first (rename onto a non-empty dir fails).
    // Re-classify here (not just at the fail-fast precondition) so a symlink
    // that appeared between the early check and now is still refused, and so
    // we never `rename` a symlink the user placed deliberately.
    let displaced = match classify_target(final_path)? {
        TargetState::Absent => None,
        TargetState::Directory => {
            let aside = parent.join(format!("{OLD_PREFIX}{}", random_hex_suffix()));
            rename(final_path, &aside).map_err(move_aside_error)?;
            Some(aside)
        }
    };

    // Publish. On failure, restore the displaced tree before bailing.
    if let Err(source) = rename(root, final_path) {
        if let Some(ref aside) = displaced
            && rename(aside, final_path).is_err()
        {
            // Both renames failed: the prior `node_modules` is now parked at
            // `aside` and the path the user will look at is empty. That is a
            // recoverable state, but only if we say where the tree went — a
            // bare "publish failed" would read as "nothing happened" while
            // their tree silently sits under a dotfile name. Report the
            // rescue path instead of swallowing the restore failure.
            return Err(FuziError::Io {
                what: "publish node_modules staging tree",
                source: io::Error::other(format!(
                    "{source}; the previous node_modules could not be restored either and is now at {}",
                    aside.display()
                )),
            });
        }
        return Err(io_err("publish node_modules staging tree")(source));
    }
    Ok(displaced)
}

/// Fail-fast precondition guarding the publish target.
///
/// Refuses loudly *before* the fetch/extract work if `<project_dir>/node_modules`
/// is a symlink, a non-directory, or a mount point. The swap in
/// [`StagingTree::commit`] re-checks (closing the race between this probe and
/// the publish), so this is purely UX — surface the problem before downloading.
///
/// # Errors
///
/// [`FuziError::NodeModulesNotDirectory`] if the target is a symlink or file;
/// [`FuziError::NodeModulesMountPoint`] if it is a directory on another device
/// than the project; [`FuziError::Io`] if it cannot be inspected.
pub fn check_node_modules_target(project_dir: &Path) -> Result<(), FuziError> {
    classify_target(&project_dir.join(NODE_MODULES)).map(|_| ())
}

/// A per-package extraction destination inside a [`StagingTree`].
///
/// A fresh, fuzi-owned directory — never a live `node_modules`. Constructible
/// **only** via [`StagingTree::package_dir`]; the private field plus
/// module-private construction make that invariant un-bypassable from outside
/// (see the module docs on why this is load-bearing).
#[derive(Debug)]
pub struct StagingDir(PathBuf);

impl StagingDir {
    /// The absolute path to extract the package's tree into.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.0
    }

    /// Test-only constructor. Production code obtains a `StagingDir` solely from
    /// [`StagingTree::package_dir`]; tests are trusted to point it at a tempdir.
    #[cfg(test)]
    pub(crate) const fn for_tests(path: PathBuf) -> Self {
        Self(path)
    }
}

/// A `node_modules` tree being built under `<project>/.fuzi-installing-<rand>`.
///
/// The staging root stands in for the top-level `node_modules`, so a placement
/// at `node_modules/<rel>` maps to `<root>/<rel>`. A [`CleanupGuard`] removes the
/// root on drop unless [`commit`](StagingTree::commit) publishes it, and a
/// `StagingRegistration` makes the root visible to
/// [`drain_staging_roots`](crate::drain_staging_roots) — the interrupt path that
/// never reaches a `Drop` at all.
#[derive(Debug)]
pub struct StagingTree {
    /// `<project>/.fuzi-installing-<rand>` — the future `node_modules`.
    root: PathBuf,
    /// `<project>/node_modules` — where `commit` publishes the tree.
    final_path: PathBuf,
    /// Removes `root` on drop unless `commit` defuses it.
    ///
    /// Declared **before** `registration` so it drops first: the ordinary
    /// cleanup removes the tree and only then deregisters it, so a signal
    /// landing mid-cleanup finds the root still registered and the drain
    /// re-removes an already-removed path (a harmless `ENOENT`). The reverse
    /// order would open a window where the tree exists but nothing knows about
    /// it.
    ///
    /// That is the rule for the `Drop` path. [`commit`](StagingTree::commit)
    /// deregisters *before* the swap instead — the deliberate trade documented
    /// on [`StagingRegistration::publish`], which is also why the destructure
    /// there needs no drop order of its own.
    guard: CleanupGuard,
    /// Registers `root` with the interrupt drain for the tree's whole lifetime.
    registration: StagingRegistration,
    /// Everything placed in the tree so far, by path, with what is expected
    /// there — what [`commit`](StagingTree::commit) checks is still present.
    placed: BTreeMap<PathBuf, StagingEntry>,
}

impl StagingTree {
    /// Create a fresh staging root next to `<project_dir>/node_modules` (same
    /// filesystem, so the publish rename is atomic).
    ///
    /// The `mkdir` runs inside the interrupt registry's critical section, with
    /// the registration (see `crate::interrupt`'s creation race), so creation
    /// leaves no window in which a signal could leak the root: a drain that
    /// fired first refuses the creation, and one that fires during or after it
    /// finds the root registered. Nothing else creates a staging root: every
    /// later directory is created below it (`make_dir_below`), so a writer
    /// racing a drain that removed the root fails instead of re-creating it.
    ///
    /// # Errors
    ///
    /// [`FuziError::Io`] if the staging directory cannot be created.
    ///
    /// [`FuziError::Interrupted`] if the interrupt drain has already fired —
    /// nothing is created, and `node_modules` is untouched.
    pub fn create(project_dir: &Path) -> Result<Self, FuziError> {
        Self::create_in(&STAGING_ROOTS, project_dir)
    }

    /// [`create`](Self::create) registering into `registry` — the seam that
    /// lets a test stage a fired drain on a private registry instead of the
    /// process-global one the rest of the suite creates trees in.
    fn create_in(
        registry: &'static Mutex<Registry>,
        project_dir: &Path,
    ) -> Result<Self, FuziError> {
        let final_path = project_dir.join(NODE_MODULES);
        let root = project_dir.join(format!("{STAGING_PREFIX}{}", random_hex_suffix()));
        let registration = match StagingRegistration::register(registry, root.clone(), |root| {
            make_root_dir(root, "create node_modules staging directory")
        }) {
            Ok(created) => created?,
            Err(RegisterRefused) => return Err(FuziError::Interrupted),
        };
        // Armed after the registration, harmlessly: if a drain removes the
        // root in between, the guard's own removal is an `ENOENT`.
        let guard = CleanupGuard::new(root.clone());
        Ok(Self {
            root,
            final_path,
            guard,
            registration,
            placed: BTreeMap::new(),
        })
    }

    /// The extraction destination for `path`, with its parent directories
    /// created (so extraction is order-independent under any placement order —
    /// a nested `node_modules/a/node_modules/b` does not require `a` first) —
    /// below the staging root only, never the root itself.
    ///
    /// Returns `None` for a key not under `node_modules/` (root / sibling-escape
    /// — never an `Install` placement); the caller skips it.
    ///
    /// Defense-in-depth at the [`StagingDir`] trust boundary, for a caller that
    /// did not get its [`InstallPath`] from classify: the key passes the same
    /// `node_modules` key gate classify applies to every placed entry
    /// (`validate_nm_key` — only package-name characters, no dot-leading
    /// component, a proper `<pkg>(/node_modules/<pkg>)*` nesting), and its
    /// remainder is a non-empty relative path of `Normal` components only
    /// *before* it is joined to the root (`Path::join` silently *replaces* the
    /// base with an absolute argument). Neither fires in the normal pipeline.
    ///
    /// The gate is what keeps a placement's directory free of links: a
    /// placement at a bare scope directory (`node_modules/@s`) would hold any
    /// link placed at `node_modules/@s/<name>`, and its own bin path could then
    /// run through that link into the sibling.
    ///
    /// # Errors
    ///
    /// [`FuziError::UnsafeStagingPath`] if the key fails the `node_modules` key
    /// gate or its remainder is absolute, empty, or escapes the staging root;
    /// [`FuziError::Io`] if the destination directory cannot be created —
    /// `NotFound` if the staging root has been removed.
    pub fn package_dir(&mut self, path: &InstallPath) -> Result<Option<StagingDir>, FuziError> {
        let Some(rel) = path.nm_relative() else {
            return Ok(None);
        };
        if validate_nm_key(path).is_err() || !is_safe_relative(rel) {
            return Err(FuziError::UnsafeStagingPath {
                key: path.as_str().to_string(),
            });
        }
        let dest = self.root.join(rel);
        make_dir_below(&self.root, &dest, "create package staging directory")?;
        self.placed.insert(dest.clone(), StagingEntry::PackageDir);
        Ok(Some(StagingDir(dest)))
    }

    /// The `node_modules/.bin` directory that should hold `path`'s bin links: a
    /// sibling of the package within its enclosing `node_modules`.
    ///
    /// `node_modules/foo` → `<root>/.bin`; `node_modules/a/node_modules/b` →
    /// `<root>/a/node_modules/.bin`.
    #[must_use]
    pub fn bin_dir(&self, path: &InstallPath) -> PathBuf {
        // `nm_relative` = `<prefix>/<package_portion>` (or just the portion).
        // Strip the trailing portion to get the enclosing-node_modules prefix.
        let prefix = path.nm_relative().map_or("", |rel| {
            rel.strip_suffix(path.package_portion())
                .unwrap_or("")
                .trim_end_matches('/')
        });
        self.root.join(prefix).join(".bin")
    }

    /// Place a sibling link: a relative symlink at `path` (a depth-1
    /// `node_modules/…` key) to `target`, with the text
    /// [`LinkTarget::relative_from`] gives — npm's own shape.
    ///
    /// Called only after every extraction has finished. Never replaces anything:
    /// an existing entry at the link's path is an `EEXIST` error, not an
    /// overwrite. Creates nothing but the link and its parent scope directory;
    /// the target itself is never touched.
    ///
    /// # Errors
    ///
    /// [`FuziError::UnsafeStagingPath`] if the key fails the `node_modules` key
    /// gate classify applies (not under `node_modules/`, a character npm package
    /// names cannot contain, a dot-leading component — a link at `.bin` would make the
    /// directory the bin pass writes into a symlink to the sibling) or its
    /// remainder is not a single valid package portion (`name` or
    /// `@scope/name`) — empty, absolute, escaping, or deeper than one level,
    /// where the parent `mkdir` could follow an earlier link;
    /// [`FuziError::Io`] if the parent cannot be created or the symlink cannot
    /// be (including `EEXIST`, and `NotFound` once the staging root has been
    /// removed — the parent is created below the root only).
    pub(crate) fn place_link(
        &mut self,
        path: &InstallPath,
        target: &LinkTarget,
    ) -> Result<(), FuziError> {
        // The key gate classify runs (`validate_nm_key`: under `node_modules/`,
        // only package-name characters, no dot-leading component, a
        // proper nesting), then the two this boundary adds: one package
        // portion only, and a join that cannot leave the staging root.
        let Some(rel) = path.nm_relative().filter(|rel| {
            validate_nm_key(path).is_ok() && valid_package_portion(rel) && is_safe_relative(rel)
        }) else {
            return Err(FuziError::UnsafeStagingPath {
                key: path.as_str().to_string(),
            });
        };
        let dest = self.root.join(rel);
        if let Some(parent) = dest.parent() {
            make_dir_below(&self.root, parent, "create link parent directory")?;
        }
        symlink(target.relative_from(path), &dest).map_err(io_err("create node_modules link"))?;
        self.placed.insert(dest, StagingEntry::Link);
        Ok(())
    }

    /// Record that `path` holds a file this install wrote (`PackageJson`) or a
    /// symlink it made (`BinLink`), for the pre-publish completeness check.
    /// Package directories and links record themselves.
    pub(crate) fn record(&mut self, path: PathBuf, entry: StagingEntry) {
        self.placed.insert(path, entry);
    }

    /// The first thing missing from the tree: the root itself, then each
    /// recorded entry in path order — absent, or no longer the kind of entry
    /// that was placed there (`lstat`, so a link is checked as a link). `None`
    /// when everything is present.
    ///
    /// One `lstat` per entry, no reads and no hashing: this answers "did
    /// another process remove part of the tree", not "is every byte intact".
    fn first_missing(&self) -> Option<(StagingEntry, PathBuf)> {
        let present = |path: &Path, entry: StagingEntry| {
            fs::symlink_metadata(path).is_ok_and(|meta| {
                let kind = meta.file_type();
                match entry {
                    StagingEntry::Root | StagingEntry::PackageDir => kind.is_dir(),
                    StagingEntry::PackageJson => kind.is_file(),
                    StagingEntry::Link | StagingEntry::BinLink => kind.is_symlink(),
                }
            })
        };
        if !present(&self.root, StagingEntry::Root) {
            return Some((StagingEntry::Root, self.root.clone()));
        }
        self.placed
            .iter()
            .find(|&(path, &entry)| !present(path, entry))
            .map(|(path, &entry)| (entry, path.clone()))
    }

    /// Reword a `NotFound` that a write into this tree failed with, when the
    /// tree is missing something it had: another process removed it, and the
    /// error says so ([`FuziError::StagingIncomplete`]) rather than reporting
    /// a bare I/O failure — or, if the interrupt drain claimed this tree,
    /// [`FuziError::Interrupted`], since the removal was this process's own.
    ///
    /// Anything else passes through unchanged: an error other than a
    /// `NotFound` from the filesystem (a security-class extraction refusal
    /// stays one, whatever happened to the tree), and a `NotFound` while the
    /// tree is whole (some other path was missing).
    #[must_use]
    pub(crate) fn explain_not_found(&self, err: FuziError) -> FuziError {
        let not_found = match &err {
            FuziError::Io { source, .. }
            | FuziError::Extract {
                source: fuz_archive::ArchiveError::Io(source),
                ..
            } => source.kind() == io::ErrorKind::NotFound,
            _ => false,
        };
        if !not_found {
            return err;
        }
        if self.registration.is_claimed() {
            return FuziError::Interrupted;
        }
        match self.first_missing() {
            Some((missing, path)) => FuziError::StagingIncomplete { missing, path },
            None => err,
        }
    }

    /// Create a `node_modules` directory (mode `0o755`, parents as needed) under
    /// the staging root — e.g. a `.bin` directory. Crate-internal: keeps the
    /// `node_modules` dir-mode and the below-the-root floor owned by `staging`
    /// rather than duplicated in the materialization loop.
    ///
    /// # Errors
    ///
    /// [`FuziError::Io`] if the directory cannot be created — `NotFound` if the
    /// staging root has been removed; `InvalidInput` if `path` is not under it.
    pub(crate) fn ensure_dir(&self, path: &Path) -> Result<(), FuziError> {
        make_dir_below(&self.root, path, "create node_modules directory")
    }

    /// Publish the staging tree as `node_modules` with an atomic rename,
    /// displacing any existing tree, and return the published path.
    ///
    /// fuzi owns the whole tree (it does not write npm's `.package-lock.json`
    /// marker, so a re-run is the upgrade path); the existing `node_modules` is
    /// moved aside and removed rather than merged. There is a brief window where
    /// `node_modules` is absent between the move-aside and the publish — v0 does
    /// not support concurrent installs into one project, so this is acceptable.
    ///
    /// # Errors
    ///
    /// [`FuziError::Io`] if the swap fails. On a failed publish the displaced
    /// prior tree is restored; the staging tree is removed by the guard.
    ///
    /// [`FuziError::Interrupted`] if the interrupt drain claimed this staging
    /// root first — the swap does not run at all, so `node_modules` is left
    /// exactly as it was (see `crate::interrupt`).
    ///
    /// [`FuziError::StagingIncomplete`] if anything the tree recorded — the
    /// root, a package directory, a shipped `package.json`, a link, a `.bin`
    /// link — is missing: another process removed part of the tree, and
    /// publishing it would hand the user a partial `node_modules` as a
    /// success. The swap does not run, and the guard removes what is left.
    /// Files within a package are not checked (see the module docs).
    // The brief absent-`node_modules` window is acceptable for v0 (no concurrent
    // installs into one project). Closing it would take an atomic Linux
    // `renameat2(RENAME_EXCHANGE)` (via `nix::fcntl`), feature-gated since macOS
    // lacks it — deferred until concurrent installs are actually supported.
    pub fn commit(self) -> Result<PathBuf, FuziError> {
        // Destructure to move the pieces out by name. Locals drop in reverse
        // declaration order, so this is the mirror of the struct's field order
        // — but the "remove the tree, *then* deregister" rule that field order
        // encodes (see the `guard` field) governs the `Drop` path only.
        // `publish` below deregisters unconditionally, refusal included, so by
        // the time either local drops there is no registration left to order
        // against the cleanup.
        // The completeness check, before the lock: one `lstat` per placed
        // entry is too much to hold a drain behind, and the lock excludes
        // nothing the check guards against (the remover is another process).
        // Its verdict is applied inside the publish below, so a drain's claim
        // still wins over it and the swap never starts for an incomplete tree.
        let missing = self.first_missing();
        let Self {
            root,
            final_path,
            guard,
            registration,
            placed: _,
        } = self;
        // Derived here as well as inside `swap_into_place`, on purpose: this
        // copy is for the post-swap `fsync_dir`, which must stay *outside* the
        // registry lock. Handing the swap's parent back out would mean widening
        // the locked section (or its return type) to carry a value only the
        // unlocked half needs — two `Path::parent` calls are the cheaper half of
        // that trade.
        let parent = final_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();

        // Deregister and swap under the interrupt registry's lock, so a
        // concurrent drain can never delete through the descriptor of a
        // directory that has just become the live `node_modules` (see
        // `crate::interrupt`). Everything after the swap is ordinary cleanup and
        // stays outside the lock.
        //
        // A drain that got there first refuses the swap outright: its tree is
        // gone or half-gone, and the swap's *first* act is to move the live
        // `node_modules` aside — which on a process about to exit would park the
        // user's tree under a `.fuzi-old-*` name `clean` deletes. Returning here
        // leaves `guard` to drop, so whatever the drain left of the staging tree
        // is removed on the way out (an already-removed tree is a harmless
        // `ENOENT`).
        let displaced = match registration.publish(|| match missing {
            Some((missing, path)) => Err(FuziError::StagingIncomplete { missing, path }),
            None => swap_into_place(&root, &final_path),
        }) {
            Ok(swapped) => swapped?,
            Err(PublishRefused) => return Err(FuziError::Interrupted),
        };

        // The tree is in place: keep it (defuse), durably record the rename, and
        // drop the displaced tree (best-effort — its loss is harmless).
        guard.defuse();
        let _ = fsync_dir(&parent);
        if let Some(aside) = displaced {
            let _ = fs::remove_dir_all(aside);
        }
        Ok(final_path)
    }

    /// The staging root (tests and diagnostics).
    #[cfg(test)]
    pub(crate) fn root(&self) -> &Path {
        &self.root
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::tree_listing;

    #[test]
    fn package_dir_maps_nm_relative_under_root() {
        let project = tempfile::tempdir().unwrap();
        let mut tree = StagingTree::create(project.path()).unwrap();
        let staging = tree
            .package_dir(&InstallPath::new("node_modules/@scope/foo"))
            .unwrap()
            .unwrap();
        assert_eq!(staging.path(), tree.root().join("@scope/foo"));
        assert!(staging.path().is_dir());
    }

    #[test]
    fn package_dir_creates_nested_parents() {
        let project = tempfile::tempdir().unwrap();
        let mut tree = StagingTree::create(project.path()).unwrap();
        // Deep nested placement with no parent placed first — must still work.
        let staging = tree
            .package_dir(&InstallPath::new("node_modules/a/node_modules/b"))
            .unwrap()
            .unwrap();
        assert!(staging.path().is_dir());
        assert_eq!(staging.path(), tree.root().join("a/node_modules/b"));
    }

    #[test]
    fn package_dir_none_for_non_node_modules_key() {
        let project = tempfile::tempdir().unwrap();
        let mut tree = StagingTree::create(project.path()).unwrap();
        assert!(tree.package_dir(&InstallPath::new("")).unwrap().is_none());
        assert!(
            tree.package_dir(&InstallPath::new("../sibling"))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn package_dir_refuses_absolute_nm_relative_escape() {
        // The double-slash escape at the staging layer: `node_modules//<abs>` →
        // `nm_relative` is the absolute remainder `/…`, and `root.join(abs)` would
        // REPLACE the staging root, writing the tarball outside the project. The
        // StagingDir trust boundary refuses it before any directory is created.
        let project = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let mut tree = StagingTree::create(project.path()).unwrap();
        let target = outside.path().join("pwned");
        let key = format!("node_modules/{}", target.display());
        assert!(key.contains("//"), "sanity: the tampered key has a `//`");
        let err = tree.package_dir(&InstallPath::new(key)).unwrap_err();
        assert!(matches!(err, FuziError::UnsafeStagingPath { .. }));
        assert!(
            !target.exists(),
            "must not have materialized outside the staging root"
        );
        // Nothing landed at the escape target's parent either.
        assert!(!target.parent().unwrap().join("pwned").exists());
    }

    #[test]
    fn package_dir_refuses_empty_nm_relative() {
        // `node_modules/` (trailing slash) → `nm_relative` is "" → `root.join("")`
        // is the root itself, so extracting there clobbers the whole staging tree.
        let project = tempfile::tempdir().unwrap();
        let mut tree = StagingTree::create(project.path()).unwrap();
        let err = tree
            .package_dir(&InstallPath::new("node_modules/"))
            .unwrap_err();
        assert!(matches!(err, FuziError::UnsafeStagingPath { .. }));
    }

    #[test]
    fn package_dir_refuses_parent_traversal_nm_relative() {
        // An embedded `..` remainder would walk up out of the staging root. (This
        // key is `Malformed` at classify too; the guard is the second line.)
        let project = tempfile::tempdir().unwrap();
        let mut tree = StagingTree::create(project.path()).unwrap();
        let err = tree
            .package_dir(&InstallPath::new("node_modules/../../etc"))
            .unwrap_err();
        assert!(matches!(err, FuziError::UnsafeStagingPath { .. }));
    }

    #[test]
    fn is_safe_relative_accepts_only_normal_component_paths() {
        // Legitimate placements pass; every escape shape is refused.
        assert!(is_safe_relative("foo"));
        assert!(is_safe_relative("@scope/foo"));
        assert!(is_safe_relative("a/node_modules/b"));
        assert!(!is_safe_relative("")); // empty → the root itself
        assert!(!is_safe_relative("/abs")); // absolute → join replaces the base
        assert!(!is_safe_relative("../up")); // parent traversal
        assert!(!is_safe_relative("a/../../b")); // interior traversal escaping root
    }

    #[test]
    fn bin_dir_is_sibling_within_enclosing_node_modules() {
        let project = tempfile::tempdir().unwrap();
        let tree = StagingTree::create(project.path()).unwrap();
        assert_eq!(
            tree.bin_dir(&InstallPath::new("node_modules/foo")),
            tree.root().join(".bin")
        );
        assert_eq!(
            tree.bin_dir(&InstallPath::new("node_modules/@scope/foo")),
            tree.root().join(".bin")
        );
        assert_eq!(
            tree.bin_dir(&InstallPath::new("node_modules/a/node_modules/b")),
            tree.root().join("a/node_modules/.bin")
        );
        // A name ending in `node_modules` is no nesting boundary.
        assert_eq!(
            tree.bin_dir(&InstallPath::new("node_modules/@foo-node_modules/x")),
            tree.root().join(".bin")
        );
        assert_eq!(
            tree.bin_dir(&InstallPath::new(
                "node_modules/x-node_modules/node_modules/y"
            )),
            tree.root().join("x-node_modules/node_modules/.bin")
        );
    }

    #[test]
    fn commit_publishes_and_defuses_cleanup() {
        let project = tempfile::tempdir().unwrap();
        let mut tree = StagingTree::create(project.path()).unwrap();
        let root = tree.root().to_path_buf();
        tree.package_dir(&InstallPath::new("node_modules/foo"))
            .unwrap();
        let final_path = tree.commit().unwrap();
        assert_eq!(final_path, project.path().join("node_modules"));
        assert!(final_path.join("foo").is_dir());
        // Staging root consumed by the rename; not left behind.
        assert!(!root.exists());
    }

    #[test]
    fn commit_replaces_existing_node_modules() {
        let project = tempfile::tempdir().unwrap();
        // A stale prior tree with a file that must NOT survive the swap.
        let nm = project.path().join("node_modules");
        fs::create_dir(&nm).unwrap();
        fs::write(nm.join("stale.txt"), b"old").unwrap();

        let mut tree = StagingTree::create(project.path()).unwrap();
        tree.package_dir(&InstallPath::new("node_modules/fresh"))
            .unwrap();
        tree.commit().unwrap();

        assert!(nm.join("fresh").is_dir());
        assert!(!nm.join("stale.txt").exists(), "old tree must be gone");
    }

    /// The `.fuzi-old-*` entries in `dir`.
    fn parked(dir: &Path) -> Vec<std::ffi::OsString> {
        fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .filter(|name| name.to_string_lossy().starts_with(OLD_PREFIX))
            .collect()
    }

    #[test]
    fn a_failed_publish_restores_the_previous_tree() {
        // The staging root vanishes before the publish (past `commit`'s
        // completeness check, which would refuse it first), so the second
        // rename fails after the first moved the live tree aside: the restore
        // puts it back, and nothing is left parked under the name `fuzi clean`
        // reaps.
        let project = tempfile::tempdir().unwrap();
        let nm = project.path().join("node_modules");
        fs::create_dir(&nm).unwrap();
        fs::write(nm.join("live.txt"), b"live").unwrap();

        let root = project.path().join(".fuzi-installing-gone");
        let err = swap_into_place(&root, &nm).unwrap_err();

        assert!(
            matches!(
                err,
                FuziError::Io {
                    what: "publish node_modules staging tree",
                    ..
                }
            ),
            "{err:?}"
        );
        assert!(!err.to_string().contains("could not be restored"), "{err}");
        assert_eq!(fs::read(nm.join("live.txt")).unwrap(), b"live");
        assert!(parked(project.path()).is_empty());
    }

    #[test]
    fn a_failed_restore_names_where_the_previous_tree_went() {
        // Publish and restore both fail: the live tree is parked at
        // `.fuzi-old-*`, and the error is the only thing that says so.
        let project = tempfile::tempdir().unwrap();
        let nm = project.path().join("node_modules");
        fs::create_dir(&nm).unwrap();
        fs::write(nm.join("live.txt"), b"live").unwrap();
        let root = project.path().join(".fuzi-installing-test");
        fs::create_dir(&root).unwrap();

        let mut calls = 0;
        let err = swap_into_place_with(&root, &nm, |from, to| {
            calls += 1;
            if calls == 1 {
                fs::rename(from, to)
            } else {
                Err(io::Error::from(io::ErrorKind::PermissionDenied))
            }
        })
        .unwrap_err();

        assert_eq!(calls, 3, "move aside, publish, restore");
        let parked = parked(project.path());
        assert_eq!(parked.len(), 1, "{parked:?}");
        let aside = project.path().join(&parked[0]);
        assert_eq!(fs::read(aside.join("live.txt")).unwrap(), b"live");
        let message = err.to_string();
        assert!(
            message.contains(&format!(
                "the previous node_modules could not be restored either and is now at {}",
                aside.display()
            )),
            "{message}"
        );
        assert!(!nm.exists());
    }

    #[test]
    fn a_refused_move_aside_changes_nothing_and_says_why() {
        // The first rename — the move-aside — fails: a bind mount (`EBUSY`) or
        // an overlayfs lower-layer directory (`EXDEV`). Nothing is renamed, so
        // the live tree and the staging root stay where they are.
        for (kind, expected) in [
            (io::ErrorKind::ResourceBusy, "node_modules_mount_point"),
            (io::ErrorKind::CrossesDevices, "node_modules_not_renameable"),
        ] {
            let project = tempfile::tempdir().unwrap();
            let nm = project.path().join("node_modules");
            fs::create_dir(&nm).unwrap();
            fs::write(nm.join("live.txt"), b"live").unwrap();
            let root = project.path().join(".fuzi-installing-test");
            fs::create_dir(&root).unwrap();

            let mut calls = 0;
            let err = swap_into_place_with(&root, &nm, |_, _| {
                calls += 1;
                Err(io::Error::from(kind))
            })
            .unwrap_err();

            assert_eq!(calls, 1, "{kind:?}: no publish after a refused move-aside");
            assert_eq!(err.kind(), expected, "{kind:?}: {err:?}");
            assert_eq!(err.exit_code(), 73);
            assert_eq!(fs::read(nm.join("live.txt")).unwrap(), b"live");
            assert!(root.is_dir());
            assert!(parked(project.path()).is_empty());
        }
    }

    #[test]
    fn check_target_accepts_absent_and_dir_refuses_symlink_and_file() {
        let project = tempfile::tempdir().unwrap();
        // Absent → ok.
        check_node_modules_target(project.path()).unwrap();
        // Real directory → ok (contents irrelevant).
        let nm = project.path().join("node_modules");
        fs::create_dir(&nm).unwrap();
        check_node_modules_target(project.path()).unwrap();
        // Regular file → refused.
        fs::remove_dir(&nm).unwrap();
        fs::write(&nm, b"x").unwrap();
        assert!(matches!(
            check_node_modules_target(project.path()),
            Err(FuziError::NodeModulesNotDirectory {
                kind: NodeModulesObstruction::File
            })
        ));
        // Symlink → refused (detected as a symlink, not followed).
        fs::remove_file(&nm).unwrap();
        symlink("/tmp", &nm).unwrap();
        assert!(matches!(
            check_node_modules_target(project.path()),
            Err(FuziError::NodeModulesNotDirectory {
                kind: NodeModulesObstruction::Symlink
            })
        ));
    }

    #[test]
    fn a_directory_on_another_device_is_a_mount_point() {
        assert!(matches!(directory_state(7, 7), Ok(TargetState::Directory)));
        assert!(matches!(
            directory_state(7, 8),
            Err(FuziError::NodeModulesMountPoint)
        ));
    }

    /// `/proc` is a mount point on every Linux host: the real lstat-and-parent
    /// path reads it as one.
    #[cfg(target_os = "linux")]
    #[test]
    fn classify_target_refuses_a_real_mount_point() {
        let err = classify_target(Path::new("/proc"))
            .err()
            .expect("/proc is a mount point");
        assert!(matches!(err, FuziError::NodeModulesMountPoint), "{err:?}");
        assert_eq!(err.exit_code(), 73);
        assert_eq!(err.kind(), "node_modules_mount_point");
    }

    #[test]
    fn a_busy_move_aside_is_a_mount_point_and_a_cross_device_one_is_not() {
        assert!(matches!(
            move_aside_error(io::Error::from(io::ErrorKind::ResourceBusy)),
            FuziError::NodeModulesMountPoint
        ));
        let exdev = move_aside_error(io::Error::from(io::ErrorKind::CrossesDevices));
        assert!(
            matches!(exdev, FuziError::NodeModulesNotRenameable),
            "{exdev:?}"
        );
        assert_eq!(exdev.exit_code(), 73);
        assert_eq!(exdev.kind(), "node_modules_not_renameable");
        assert!(matches!(
            move_aside_error(io::Error::from(io::ErrorKind::PermissionDenied)),
            FuziError::Io {
                what: "move existing node_modules aside",
                ..
            }
        ));
    }

    #[test]
    fn commit_refuses_symlinked_node_modules_and_leaves_it_intact() {
        let project = tempfile::tempdir().unwrap();
        // A deliberate symlink where node_modules should be (pnpm-style / user).
        let real = project.path().join("real-deps");
        fs::create_dir(&real).unwrap();
        fs::write(real.join("precious"), b"keep").unwrap();
        symlink(&real, project.path().join("node_modules")).unwrap();

        let mut tree = StagingTree::create(project.path()).unwrap();
        tree.package_dir(&InstallPath::new("node_modules/foo"))
            .unwrap();
        let err = tree.commit().unwrap_err();
        assert!(matches!(
            err,
            FuziError::NodeModulesNotDirectory {
                kind: NodeModulesObstruction::Symlink
            }
        ));
        // The symlink and its target survive untouched.
        assert!(project.path().join("node_modules").exists());
        assert!(real.join("precious").exists());
    }

    // --- links ----------------------------------------------------------------

    fn sibling(raw: &str) -> LinkTarget {
        match LinkTarget::parse(raw) {
            crate::entry::LinkTargetParse::Ok(t) => t,
            other => panic!("{raw} must be a sibling: {other:?}"),
        }
    }

    /// A workspace `<w>/app` beside `<w>/lib`, the target holding a sentinel.
    fn link_workspace() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let w = tempfile::tempdir().unwrap();
        let app = w.path().join("app");
        let lib = w.path().join("lib");
        fs::create_dir(&app).unwrap();
        fs::create_dir(&lib).unwrap();
        fs::write(lib.join("sentinel"), b"keep").unwrap();
        (w, app, lib)
    }

    #[test]
    fn place_link_resolves_before_and_after_commit() {
        let (_w, app, lib) = link_workspace();
        let mut tree = StagingTree::create(&app).unwrap();
        let key = InstallPath::new("node_modules/@scope/lib");
        tree.place_link(&key, &sibling("../lib")).unwrap();
        let staged = tree.root().join("@scope/lib");
        assert_eq!(
            fs::read_link(&staged).unwrap().to_str().unwrap(),
            "../../../lib"
        );
        assert!(staged.join("sentinel").is_file(), "resolves from staging");
        tree.commit().unwrap();
        let published = app.join("node_modules/@scope/lib");
        assert!(
            fs::symlink_metadata(&published)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(
            fs::read(published.join("sentinel")).unwrap(),
            b"keep",
            "the same relative text resolves from node_modules"
        );
        assert!(lib.join("sentinel").is_file());
    }

    #[test]
    fn place_link_never_replaces_an_existing_entry() {
        let (_w, app, _lib) = link_workspace();
        let mut tree = StagingTree::create(&app).unwrap();
        tree.package_dir(&InstallPath::new("node_modules/lib"))
            .unwrap();
        let err = tree
            .place_link(&InstallPath::new("node_modules/lib"), &sibling("../lib"))
            .unwrap_err();
        assert!(matches!(err, FuziError::Io { .. }), "{err:?}");
        assert!(tree.root().join("lib").is_dir(), "the directory was kept");
    }

    #[test]
    fn place_link_refuses_a_key_deeper_than_one_package() {
        // `@s/lib/x` after `@s/lib` would mkdir through the first link.
        let (_w, app, lib) = link_workspace();
        let mut tree = StagingTree::create(&app).unwrap();
        tree.place_link(&InstallPath::new("node_modules/@s/lib"), &sibling("../lib"))
            .unwrap();
        for key in ["node_modules/@s/lib/x", "node_modules/a/node_modules/b"] {
            let err = tree
                .place_link(&InstallPath::new(key), &sibling("../lib"))
                .unwrap_err();
            assert!(matches!(err, FuziError::UnsafeStagingPath { .. }), "{key}");
        }
        assert!(fs::symlink_metadata(lib.join("x")).is_err());
    }

    #[test]
    fn place_link_refuses_a_dot_leading_key() {
        // A link at `.bin` would turn the directory the bin pass writes into a
        // symlink to the sibling, so every `.bin/<cmd>` would land inside it.
        // Classify refuses the key; this is the same gate at the staging
        // boundary, for a plan classify never saw.
        let (_w, app, lib) = link_workspace();
        let before = tree_listing(&lib);
        let mut tree = StagingTree::create(&app).unwrap();
        for key in [
            "node_modules/.bin",
            "node_modules/.cache",
            "node_modules/@s/.lib",
            "node_modules/.s/lib",
        ] {
            let err = tree
                .place_link(&InstallPath::new(key), &sibling("../lib"))
                .unwrap_err();
            assert!(matches!(err, FuziError::UnsafeStagingPath { .. }), "{key}");
        }
        assert_eq!(
            fs::read_dir(tree.root()).unwrap().count(),
            0,
            "nothing was created in the staging root"
        );
        assert_eq!(tree_listing(&lib), before);
    }

    #[test]
    fn place_link_refuses_a_non_node_modules_key() {
        let (_w, app, _lib) = link_workspace();
        let mut tree = StagingTree::create(&app).unwrap();
        let err = tree
            .place_link(&InstallPath::new("packages/lib"), &sibling("../lib"))
            .unwrap_err();
        assert!(matches!(err, FuziError::UnsafeStagingPath { .. }));
    }

    #[test]
    fn dropping_a_staging_tree_with_a_link_leaves_the_target_intact() {
        // Pin: CleanupGuard's `remove_dir_all` unlinks the symlink rather than
        // descending into the target.
        let (_w, app, lib) = link_workspace();
        {
            let mut tree = StagingTree::create(&app).unwrap();
            tree.place_link(&InstallPath::new("node_modules/lib"), &sibling("../lib"))
                .unwrap();
        }
        assert!(lib.join("sentinel").is_file());
    }

    #[test]
    fn displacing_a_tree_with_a_link_leaves_the_target_intact() {
        // Pin: the displaced prior tree is removed with `remove_dir_all`, which
        // must not follow the old tree's link into the sibling.
        let (_w, app, lib) = link_workspace();
        let mut first = StagingTree::create(&app).unwrap();
        first
            .place_link(&InstallPath::new("node_modules/lib"), &sibling("../lib"))
            .unwrap();
        first.commit().unwrap();
        let mut second = StagingTree::create(&app).unwrap();
        second
            .package_dir(&InstallPath::new("node_modules/x"))
            .unwrap();
        second.commit().unwrap();
        assert!(app.join("node_modules/x").is_dir());
        assert!(
            lib.join("sentinel").is_file(),
            "the old link was unlinked, not followed"
        );
    }

    // --- interrupt-drain registration ---------------------------------------

    /// A live staging tree is registered with the interrupt drain, and a commit
    /// takes it back out — so a signal during the install finds the tree and a
    /// signal after it finds nothing. Uses containment of this tree's own
    /// (random) root rather than draining, so the process-global registry is
    /// left alone for the rest of the suite.
    #[test]
    fn create_registers_and_commit_deregisters() {
        let project = tempfile::tempdir().unwrap();
        let tree = StagingTree::create(project.path()).unwrap();
        let root = tree.root().to_path_buf();
        assert!(
            crate::interrupt::is_staging_root_registered(&root),
            "a live staging tree must be visible to the drain"
        );
        tree.commit().unwrap();
        assert!(
            !crate::interrupt::is_staging_root_registered(&root),
            "the published tree must not be drainable"
        );
    }

    /// The error path deregisters too: dropping without committing removes the
    /// tree *and* its registration, so a later drain has nothing stale to chase.
    #[test]
    fn drop_without_commit_deregisters() {
        let project = tempfile::tempdir().unwrap();
        let root = {
            let tree = StagingTree::create(project.path()).unwrap();
            tree.root().to_path_buf()
        };
        assert!(!crate::interrupt::is_staging_root_registered(&root));
    }

    /// The swap runs **inside** the interrupt registry's critical section.
    ///
    /// Holding the registry lock must block `commit` — that mutual exclusion is
    /// the whole reason a concurrent drain cannot delete through a descriptor
    /// for a directory that just became the live `node_modules`. Pinned by
    /// taking the lock, racing a `commit` against it, and requiring that the
    /// commit does *not* complete until the lock is released. (A slow machine
    /// can only make the first `recv_timeout` more certainly a timeout, so the
    /// test cannot flake red; a regression that moved the swap outside the lock
    /// publishes within microseconds and fails it.)
    #[test]
    fn commit_swaps_under_the_interrupt_registry_lock() {
        use std::sync::mpsc;
        use std::time::Duration;

        let project = tempfile::tempdir().unwrap();
        let mut tree = StagingTree::create(project.path()).unwrap();
        tree.package_dir(&InstallPath::new("node_modules/foo"))
            .unwrap();
        let final_path = project.path().join("node_modules");

        // Hold the registry the way a drain does, then race a commit against it.
        let held = crate::interrupt::lock_roots_for_tests();
        let (tx, rx) = mpsc::channel();
        let committer = std::thread::spawn(move || {
            let published = tree.commit();
            let _ = tx.send(());
            published
        });

        assert!(
            rx.recv_timeout(Duration::from_millis(50)).is_err(),
            "commit must not publish while the interrupt registry is locked"
        );
        assert!(
            !final_path.exists(),
            "nothing may be published inside the drain's critical section"
        );

        drop(held);
        let published = committer.join().unwrap().unwrap();
        assert_eq!(published, final_path);
        assert!(final_path.join("foo").is_dir());
    }

    /// A commit that lost the race to a drain **refuses**, leaving the live
    /// `node_modules` untouched.
    ///
    /// The failure this pins: mutual exclusion alone orders the drain and the
    /// swap but does not cancel the swap, so a `commit` that blocked on the
    /// registry lock would wake up and run anyway — and its first act is to
    /// rename the live `node_modules` to `.fuzi-old-<rand>`, for a staging tree
    /// the drain has just deleted. On a process that is exiting `128 + signum`
    /// a moment later, that leaves the user's whole dependency tree parked
    /// under a name `fuzi clean` reaps. Here the drain's two effects are staged
    /// exactly (claim the root, remove the tree) and the commit must decline.
    #[test]
    fn commit_refuses_to_publish_after_a_drain_claimed_the_root() {
        let project = tempfile::tempdir().unwrap();
        // A live tree that must survive the interrupt in place, untouched.
        let nm = project.path().join("node_modules");
        fs::create_dir(&nm).unwrap();
        fs::write(nm.join("live.txt"), b"live").unwrap();

        let mut tree = StagingTree::create(project.path()).unwrap();
        tree.package_dir(&InstallPath::new("node_modules/foo"))
            .unwrap();
        // What a drain does, without draining the process-global registry the
        // rest of the suite is registering into: claim this root, remove its
        // tree.
        let root = tree.root().to_path_buf();
        crate::interrupt::mark_drained_for_tests(root.clone());
        fs::remove_dir_all(&root).unwrap();

        let err = tree.commit().unwrap_err();

        assert!(
            matches!(err, FuziError::Interrupted),
            "expected an interrupt refusal, got {err:?}"
        );
        // The swap never ran: the live tree is still live, still whole.
        assert!(nm.is_dir(), "node_modules must not have been moved aside");
        assert!(nm.join("live.txt").exists(), "the live tree must survive");
        assert!(!nm.join("foo").exists(), "nothing may have been published");
        // And nothing was parked under the name `fuzi clean` deletes.
        let parked: Vec<_> = fs::read_dir(project.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .filter(|name| name.to_string_lossy().starts_with(OLD_PREFIX))
            .collect();
        assert!(
            parked.is_empty(),
            "the live tree was displaced to {parked:?}"
        );
    }

    /// The same refusal for the *worse* half: a drain that blew its deadline
    /// and left the staging tree (partly) on disk.
    ///
    /// Here nothing fails the swap for us — both renames would succeed — so a
    /// `commit` that ran after the drain would publish a **half-materialized**
    /// tree over the live one, remove the good tree as the displaced `aside`,
    /// and return `Ok`. Silent, and the exact opposite of what an interrupt
    /// should cost. The refusal is what makes a partial drain degrade to a
    /// leaked staging dir (`fuzi clean`'s job) rather than a destroyed
    /// `node_modules`.
    #[test]
    fn commit_refuses_after_a_partial_drain_and_keeps_the_live_tree() {
        let project = tempfile::tempdir().unwrap();
        let nm = project.path().join("node_modules");
        fs::create_dir(&nm).unwrap();
        fs::write(nm.join("live.txt"), b"live").unwrap();

        let mut tree = StagingTree::create(project.path()).unwrap();
        tree.package_dir(&InstallPath::new("node_modules/foo"))
            .unwrap();
        // A `Remaining` drain: the root is claimed, but writers outlasted the
        // deadline so the (incomplete) tree is still on disk.
        crate::interrupt::mark_drained_for_tests(tree.root().to_path_buf());

        let err = tree.commit().unwrap_err();

        assert!(
            matches!(err, FuziError::Interrupted),
            "expected an interrupt refusal, got {err:?}"
        );
        assert!(nm.join("live.txt").exists(), "the live tree must survive");
        assert!(
            !nm.join("foo").exists(),
            "the partial tree must not publish"
        );
    }

    /// Once a drain has fired, `create` refuses with
    /// [`FuziError::Interrupted`] and leaves no `.fuzi-installing-*` tree —
    /// the fetch-phase interrupt whose drain had nothing to remove, followed by
    /// an install thread that reached materialization before the exit.
    #[test]
    fn create_refuses_after_a_drain_fired_and_leaves_no_tree() {
        let project = tempfile::tempdir().unwrap();
        let registry = crate::interrupt::fired_registry_for_tests();

        let err = StagingTree::create_in(registry, project.path()).unwrap_err();

        assert!(
            matches!(err, FuziError::Interrupted),
            "expected an interrupt refusal, got {err:?}"
        );
        let left: Vec<_> = fs::read_dir(project.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert!(left.is_empty(), "nothing may be created: {left:?}");
    }

    // --- the below-the-root floor ---------------------------------------------

    /// Assert `err` is the `NotFound` I/O error a floored mkdir gives once the
    /// staging root is gone.
    fn assert_root_gone_error(err: &FuziError) {
        assert!(
            matches!(err, FuziError::Io { source, .. } if source.kind() == io::ErrorKind::NotFound),
            "expected a NotFound I/O error, got {err:?}"
        );
    }

    /// A staging root removed under a live tree stays removed: neither a
    /// placement's directory (top-level or nested) nor a link re-creates it.
    #[test]
    fn a_removed_root_is_not_re_created_by_package_dir_or_place_link() {
        let (_w, app, _lib) = link_workspace();
        let mut tree = StagingTree::create(&app).unwrap();
        let root = tree.root().to_path_buf();
        fs::remove_dir_all(&root).unwrap();

        for key in ["node_modules/foo", "node_modules/a/node_modules/b"] {
            let err = tree.package_dir(&InstallPath::new(key)).unwrap_err();
            assert_root_gone_error(&err);
            assert!(!root.exists(), "{key} re-created the staging root");
        }
        for key in ["node_modules/lib", "node_modules/@scope/lib"] {
            let err = tree
                .place_link(&InstallPath::new(key), &sibling("../lib"))
                .unwrap_err();
            assert_root_gone_error(&err);
            assert!(!root.exists(), "{key} re-created the staging root");
        }
        let err = tree.ensure_dir(&root.join(".bin")).unwrap_err();
        assert_root_gone_error(&err);
        assert!(!root.exists(), ".bin re-created the staging root");
    }

    /// `ensure_dir` creates only under the staging root.
    #[test]
    fn ensure_dir_refuses_a_path_outside_the_staging_root() {
        let project = tempfile::tempdir().unwrap();
        let tree = StagingTree::create(project.path()).unwrap();
        let outside = project.path().join("elsewhere/.bin");
        let err = tree.ensure_dir(&outside).unwrap_err();
        assert!(
            matches!(&err, FuziError::Io { source, .. } if source.kind() == io::ErrorKind::InvalidInput),
            "{err:?}"
        );
        assert!(!project.path().join("elsewhere").exists());
    }

    // --- completeness ------------------------------------------------------------

    /// A live `node_modules` holding `live.txt`, beside the staging tree.
    fn live_node_modules(project: &Path) -> PathBuf {
        let nm = project.join("node_modules");
        fs::create_dir(&nm).unwrap();
        fs::write(nm.join("live.txt"), b"live").unwrap();
        nm
    }

    /// The live tree is exactly as `live_node_modules` made it, and nothing is
    /// parked or left staging beside it.
    fn assert_untouched(project: &Path, nm: &Path) {
        let names = |dir: &Path| -> Vec<_> {
            fs::read_dir(dir)
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .collect()
        };
        assert_eq!(names(nm), ["live.txt"]);
        assert_eq!(names(project), ["node_modules"]);
    }

    /// A placed link or package directory, or the root itself, removed before
    /// the commit refuses the publish and leaves `node_modules` alone.
    #[test]
    fn commit_refuses_a_tree_missing_a_link_a_package_or_its_root() {
        for (removed, expected) in [
            ("lib", StagingEntry::Link),
            ("foo", StagingEntry::PackageDir),
            ("", StagingEntry::Root),
        ] {
            let (_w, app, _lib) = link_workspace();
            let nm = live_node_modules(&app);
            let mut tree = StagingTree::create(&app).unwrap();
            tree.package_dir(&InstallPath::new("node_modules/foo"))
                .unwrap();
            tree.place_link(&InstallPath::new("node_modules/lib"), &sibling("../lib"))
                .unwrap();
            let gone = if removed.is_empty() {
                tree.root().to_path_buf()
            } else {
                tree.root().join(removed)
            };
            if gone.symlink_metadata().unwrap().is_dir() {
                fs::remove_dir_all(&gone).unwrap();
            } else {
                fs::remove_file(&gone).unwrap();
            }

            let err = tree.commit().unwrap_err();
            assert!(
                matches!(&err, FuziError::StagingIncomplete { missing, path }
                    if *missing == expected && *path == gone),
                "{removed:?}: {err:?}"
            );
            assert_untouched(&app, &nm);
        }
    }

    /// The check reads each entry's kind, not just its presence: a link
    /// replaced by a directory is missing too.
    #[test]
    fn commit_refuses_a_link_replaced_by_a_directory() {
        let (_w, app, _lib) = link_workspace();
        let mut tree = StagingTree::create(&app).unwrap();
        tree.place_link(&InstallPath::new("node_modules/lib"), &sibling("../lib"))
            .unwrap();
        let link = tree.root().join("lib");
        fs::remove_file(&link).unwrap();
        fs::create_dir(&link).unwrap();
        let err = tree.commit().unwrap_err();
        assert!(
            matches!(
                &err,
                FuziError::StagingIncomplete {
                    missing: StagingEntry::Link,
                    ..
                }
            ),
            "{err:?}"
        );
        assert!(!app.join("node_modules").exists());
    }

    /// A drain's claim outranks the completeness verdict: a tree the drain
    /// removed is an interrupt, not another process's doing.
    #[test]
    fn commit_reports_a_drained_incomplete_tree_as_interrupted() {
        let project = tempfile::tempdir().unwrap();
        let tree = StagingTree::create(project.path()).unwrap();
        fs::remove_dir_all(tree.root()).unwrap();
        crate::interrupt::mark_drained_for_tests(tree.root().to_path_buf());
        let err = tree.commit().unwrap_err();
        assert!(matches!(err, FuziError::Interrupted), "{err:?}");
    }

    /// A write that failed `NotFound` because the tree lost something reads as
    /// `StagingIncomplete` (or `Interrupted`, when the drain took it); anything
    /// else passes through.
    #[test]
    fn explain_not_found_names_a_vanished_tree_and_nothing_else() {
        let project = tempfile::tempdir().unwrap();
        let mut tree = StagingTree::create(project.path()).unwrap();
        let not_found = || FuziError::Io {
            what: "x",
            source: io::Error::from(io::ErrorKind::NotFound),
        };
        let extract_not_found = || FuziError::Extract {
            package: "node_modules/foo".to_string(),
            source: fuz_archive::ArchiveError::Io(io::Error::from(io::ErrorKind::NotFound)),
        };

        // Whole tree: a `NotFound` is about some other path.
        assert!(matches!(
            tree.explain_not_found(not_found()),
            FuziError::Io { .. }
        ));

        tree.package_dir(&InstallPath::new("node_modules/foo"))
            .unwrap();
        let foo = tree.root().join("foo");
        fs::remove_dir(&foo).unwrap();
        for err in [not_found(), extract_not_found()] {
            assert!(
                matches!(tree.explain_not_found(err), FuziError::StagingIncomplete {
                    missing: StagingEntry::PackageDir, ref path
                } if *path == foo)
            );
        }
        // Not a `NotFound`, or not from the filesystem: unchanged.
        let denied = FuziError::Io {
            what: "x",
            source: io::Error::from(io::ErrorKind::PermissionDenied),
        };
        assert!(matches!(
            tree.explain_not_found(denied),
            FuziError::Io { .. }
        ));
        let refused = FuziError::Extract {
            package: "node_modules/foo".to_string(),
            source: fuz_archive::ArchiveError::Empty,
        };
        assert!(matches!(
            tree.explain_not_found(refused),
            FuziError::Extract { .. }
        ));

        // The root gone is reported as the root; claimed by a drain, an interrupt.
        fs::remove_dir_all(tree.root()).unwrap();
        let err = tree
            .package_dir(&InstallPath::new("node_modules/bar"))
            .unwrap_err();
        assert!(
            matches!(tree.explain_not_found(err), FuziError::StagingIncomplete {
                missing: StagingEntry::Root, ref path
            } if path == tree.root())
        );
        crate::interrupt::mark_drained_for_tests(tree.root().to_path_buf());
        assert!(matches!(
            tree.explain_not_found(not_found()),
            FuziError::Interrupted
        ));
    }

    #[test]
    fn drop_without_commit_removes_staging() {
        let project = tempfile::tempdir().unwrap();
        let root = {
            let mut tree = StagingTree::create(project.path()).unwrap();
            tree.package_dir(&InstallPath::new("node_modules/foo"))
                .unwrap();
            tree.root().to_path_buf()
            // tree dropped here without commit
        };
        assert!(!root.exists(), "uncommitted staging must be cleaned up");
        // And no node_modules was published.
        assert!(!project.path().join("node_modules").exists());
    }
}
