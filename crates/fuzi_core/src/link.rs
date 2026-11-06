//! The link-target check: before any network or disk work, every sibling
//! `link: true` target must be the package the lockfile says it is.
//!
//! A link's target is local source fuzi does not control and never writes to,
//! so the check is read-only and no-follow at the ends that matter:
//!
//! - the project must have a parent directory (at `/`, `..` is `/` again and
//!   `../<dir>` would name a child of the project, not a sibling);
//! - the target directory is `lstat`ed and must be a **real directory** — a
//!   symlink there refuses, because npm records a link's *real* path in
//!   `resolved`, so a symlinked target means the lockfile and the disk disagree;
//! - it must not be the project itself (a `../<own-name>` link would make
//!   `node_modules/<pkg>` a cycle back into the project);
//! - its `package.json` is read with `O_NOFOLLOW` and a size cap
//!   ([`fuz_sys::secure_file::load_bounded_file`]), and its `name` must equal
//!   the lockfile target entry's `name` — not the link key, since an alias key
//!   (`node_modules/@webref/css6` → `@webref/css`) legitimately differs. A
//!   leading UTF-8 byte-order mark is skipped, as npm skips it; the name is
//!   compared exactly (no trimming, no case folding).
//!
//! A `version` mismatch only warns: the target is a sibling checkout the user
//! may be editing, and the name is what makes it the right package.
//!
//! The check runs before the network (and under `--dry-run`), again just
//! before the staging tree is published, and in `fuzi verify` against an
//! installed tree.
//!
//! # Threat notes
//!
//! The lockfile and the sibling directory are both inputs fuzi does not
//! control. What the link path does with them:
//!
//! **Refused.** A `resolved` that is anything but `../<dir>` — absolute,
//! home-relative, a scheme, an ancestor, further up, deeper, dot-leading,
//! `node_modules`,
//! over a directory name's length, or carrying a control or invisible
//! character (`LinkTarget::parse`; never decoded or normalized). A link key
//! that is not one `node_modules/<pkg>` — nested, dot-leading (`.bin`), or
//! holding a character npm package names cannot — at classify and again at
//! the staging boundary, and any key *under* a link key. A target that is
//! absent, a symlink, not a directory, or the project; a `package.json` that
//! is a symlink, not a regular file, over the cap, not JSON, or names another
//! package.
//!
//! **Never done.** fuzi creates nothing in a target, chmods nothing there, and
//! runs nothing from it — for any plan `materialize` accepts, not only one
//! classify built: both staging entry points apply the `node_modules` key
//! gate, so no placement can hold a link inside its own directory, and the
//! registry bin pass chmods only a file reached through real directories. It
//! reads one file — `package.json`, no-follow and
//! bounded — and `lstat`s the declared bin paths
//! ([`linked_bin_is_linkable`]); it never lists or descends into a target, so a
//! target whose own `node_modules` links back to the project is not a loop
//! fuzi can enter. Every removal (the staging guard, the displaced tree, the
//! interrupt drain, `fuzi clean`) unlinks a link rather than following it.
//!
//! **By design, and what remains.**
//!
//! - *The product is a by-name symlink.* The checks are pre-flights, not a
//!   lock: whoever can write the project's parent directory can swap the
//!   target after the last check, and the link then resolves to the swap.
//!   Re-checking just before publish narrows that window to the swap itself;
//!   nothing fuzi could hold open would bind a symlink to an inode. fuzi never
//!   writes through the link, so a swap changes what the link resolves to and
//!   nothing fuzi does. `fuzi verify` re-runs the check.
//! - *Mount points.* The project is recognized by device and inode, so a bind
//!   mount of the project at `../<dir>` refuses. A bind mount of an *ancestor*
//!   or a *subdirectory* of the project there is a different inode and is not
//!   detected; it takes privilege to create, and the link then points at a
//!   directory the mounter chose — which a plain directory there would too.
//! - *Ownership.* The target's owner is not checked. On a shared parent
//!   directory another user's `../<dir>` passes if its `package.json` names the
//!   package; a link is a pointer to that directory's current contents by
//!   design, so it is exactly as trustworthy as the directory beside the
//!   project.
//! - *Removal.* Leaving a target intact when a tree holding a link is removed
//!   rests on `std::fs::remove_dir_all` unlinking symlinks rather than
//!   descending through them, which every toolchain new enough to build this
//!   edition does. Tests pin it at each removal site.

use std::fs;
use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use fuz_sys::fs::is_real_dir;
use fuz_sys::secure_file::{SecureFileError, load_bounded_file};

use crate::entry::BinTarget;
use crate::error::{FuziError, LinkTargetProblem};
use crate::plan::{InstallPlan, LinkPlacement};

/// Size cap for a link target's `package.json`. Generous for a manifest (real
/// ones are a few KiB); the cap exists so a hostile or mistaken target cannot
/// make the check read an unbounded file.
pub const MAX_LINK_PACKAGE_JSON: u64 = 1024 * 1024;

/// The UTF-8 byte-order mark. npm strips a leading one before parsing a
/// `package.json`, so the target check does too.
const UTF8_BOM: &[u8] = b"\xEF\xBB\xBF";

/// Check every link in `plan` against its sibling target under `project_dir`,
/// returning the non-fatal warnings (version mismatches) for the report.
///
/// Runs right after the plan is built — before the network, and under
/// `--dry-run` too — so a wrong or missing sibling refuses before anything is
/// fetched, and again just before the staging tree is published. Every link is
/// checked; the problems are reported together.
///
/// The strings in the warnings and problems are raw — a target's `name` and
/// `version` are whatever its `package.json` holds — and are escaped where they
/// are rendered for a person (see the `text` module).
///
/// # Errors
///
/// [`FuziError::LinkTarget`] carrying every link whose target failed.
pub fn check_link_targets(
    plan: &InstallPlan,
    project_dir: &Path,
) -> Result<Vec<String>, FuziError> {
    let mut warnings = Vec::new();
    let mut problems = Vec::new();
    for link in &plan.links {
        match check_link_target(link, project_dir) {
            Ok(warning) => warnings.extend(warning),
            Err(detail) => problems.push(LinkTargetProblem {
                package: link.path.as_str().to_string(),
                detail,
            }),
        }
    }
    if problems.is_empty() {
        Ok(warnings)
    } else {
        Err(FuziError::LinkTarget { problems })
    }
}

/// Check one link's target: `Ok(Some(warning))` on a version mismatch,
/// `Ok(None)` when it matches, `Err(detail)` when the target is unusable.
pub fn check_link_target(
    link: &LinkPlacement,
    project_dir: &Path,
) -> Result<Option<String>, String> {
    let shown = link.target.as_resolved();
    let target_dir = link.target.dir_in(project_dir);

    // The project first: a sibling needs a parent directory to sit in. At the
    // filesystem root `..` resolves to the root itself, so `../<dir>` would be
    // a child of the project. Judged by device and inode, as the kernel
    // resolves it — not by the path's text.
    let project = fs::metadata(project_dir)
        .map_err(|e| format!("cannot inspect the project directory: {e}"))?;
    let parent = fs::metadata(project_dir.join(".."))
        .map_err(|e| format!("cannot inspect the project's parent directory: {e}"))?;
    if (parent.dev(), parent.ino()) == (project.dev(), project.ino()) {
        return Err(format!(
            "the project directory has no parent directory, so link target {shown} would be inside the project, not beside it"
        ));
    }

    let meta = match fs::symlink_metadata(&target_dir) {
        Ok(meta) => meta,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Err(format!("link target {shown} does not exist"));
        }
        Err(e) => return Err(format!("cannot inspect link target {shown}: {e}")),
    };
    if meta.file_type().is_symlink() {
        return Err(format!(
            "link target {shown} is a symlink; npm records a link's real path, so regenerate the lockfile against the real directory"
        ));
    }
    if !meta.is_dir() {
        return Err(format!("link target {shown} is not a directory"));
    }
    if (meta.dev(), meta.ino()) == (project.dev(), project.ino()) {
        return Err(format!(
            "link target {shown} is the project itself (a link back into the project would be a cycle)"
        ));
    }

    let manifest_path = target_dir.join("package.json");
    let bytes = load_bounded_file(&manifest_path, MAX_LINK_PACKAGE_JSON).map_err(|e| match e {
        SecureFileError::NotFound(_) => format!("link target {shown} has no package.json"),
        SecureFileError::Symlink(_) => format!("{shown}/package.json is a symlink"),
        SecureFileError::NotRegularFile(_) => {
            format!("{shown}/package.json is not a regular file")
        }
        SecureFileError::FileTooLarge(_, size, max) => {
            format!("{shown}/package.json is {size} bytes, over the {max}-byte cap")
        }
        other => format!("cannot read {shown}/package.json: {other}"),
    })?;
    let json = bytes.strip_prefix(UTF8_BOM).unwrap_or(&bytes);
    let manifest: serde_json::Value = serde_json::from_slice(json)
        .map_err(|e| format!("{shown}/package.json is not valid JSON ({e})"))?;

    let (expected, source) = match &link.name {
        Some(name) => (name.clone(), "the lockfile names"),
        None => (
            default_link_name(project_dir, link.target.segment())?,
            "npm's default name for that folder is",
        ),
    };
    match manifest.get("name").and_then(serde_json::Value::as_str) {
        Some(name) if name == expected => {}
        Some(name) => {
            return Err(format!(
                "link target {shown} is package `{name}`, but {source} `{expected}`"
            ));
        }
        None => {
            return Err(format!(
                "{shown}/package.json has no name ({source} `{expected}`)"
            ));
        }
    }

    let actual = manifest.get("version").and_then(serde_json::Value::as_str);
    Ok(match (link.version.as_deref(), actual) {
        (Some(expected), Some(actual)) if expected != actual => Some(format!(
            "{}: linked package {shown} is version {actual}, the lockfile recorded {expected}",
            link.path.as_str()
        )),
        (Some(expected), None) => Some(format!(
            "{}: linked package {shown} has no version, the lockfile recorded {expected}",
            link.path.as_str()
        )),
        _ => None,
    })
}

/// The path of the file `bin` names under `base`, when every directory on the
/// way to it is a **real directory**; `None` when one is a symlink, a file, or
/// absent, or when the path names a directory (it ends in `/` or `/.`, or is
/// `.` itself).
///
/// Each parent is `lstat`ed, never followed, so the returned path reaches the
/// file without crossing a symlink. The final component is not inspected here:
/// the caller judges it without following it (an `lstat` for a linked bin, an
/// `O_NOFOLLOW` open for a registry bin).
///
/// The one walk both bin passes use. For a linked package `base` is the
/// sibling directory, where it keeps a `.bin` link from resolving out of the
/// target through a link inside it. For a registry package `base` is its
/// staging directory, where it keeps the chmod from following a symlinked
/// directory: extraction rejects symlink entries and the key gates keep links
/// out of a package's directory, so nothing fuzi builds puts one there — the
/// bin pass does not depend on that.
pub fn bin_path_through_real_dirs(base: &Path, bin: &BinTarget) -> Option<PathBuf> {
    // `BinTarget` admits only plain and `.` components (no `..`, not
    // absolute); empty ones come from `//` or a trailing `/`.
    let mut names: Vec<&str> = bin.as_str().split('/').collect();
    // A path ending in `/` or `/.` names a directory, never a file.
    let file = names
        .pop()
        .filter(|name| !name.is_empty() && *name != ".")?;
    let mut at = base.to_path_buf();
    for name in names {
        if name.is_empty() || name == "." {
            continue;
        }
        at.push(name);
        if !is_real_dir(&at) {
            return None;
        }
    }
    at.push(file);
    Some(at)
}

/// Whether a linked package's declared bin may get a `.bin` link: the bin path
/// names an **executable regular file** reached through **real directories**
/// only, starting at `target_dir`.
///
/// Every component is `lstat`ed, never followed
/// ([`bin_path_through_real_dirs`], then the file itself): a symlink anywhere
/// on the path — a parent directory or the file — answers `false`, so a `.bin`
/// link fuzi writes never resolves out of the target through a link *inside*
/// it. So does a missing file, a directory, and a file with no exec bit (fuzi
/// never chmods a target). `false` is a counted skip for the caller, never an
/// error.
///
/// npm links a declared bin whatever it is (and chmods it), so a bin that is
/// itself a symlink is linked by `npm ci` and skipped here — a deliberate
/// divergence: linking it would make `node_modules/.bin/<cmd>` run whatever
/// that symlink points at, in or out of the package.
///
/// Read-only, and a snapshot like the rest of the target check: the path is
/// resolved by name again when the link is used.
pub fn linked_bin_is_linkable(target_dir: &Path, bin: &BinTarget) -> bool {
    bin_path_through_real_dirs(target_dir, bin).is_some_and(|file| {
        fs::symlink_metadata(file)
            .is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
    })
}

/// npm's default name for a target folder whose lockfile entry carries no
/// `name` — arborist's `nameFromFolder`: the folder name, or `@<parent>/<folder>`
/// when the folder's parent directory is `@`-named (a scope directory).
///
/// The target is `<project>/../<segment>`, so its parent is the project's
/// parent; the project path is canonicalized first, since `..` is resolved by
/// the kernel against the real directory, not a symlinked path's text.
fn default_link_name(project_dir: &Path, segment: &str) -> Result<String, String> {
    let project = fs::canonicalize(project_dir)
        .map_err(|e| format!("cannot resolve the project directory: {e}"))?;
    let parent = project
        .parent()
        .and_then(Path::file_name)
        .and_then(|name| name.to_str());
    Ok(match parent {
        Some(scope) if scope.starts_with('@') => format!("{scope}/{segment}"),
        _ => segment.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::{BinTarget, InstallPath, LinkTarget, LinkTargetParse};
    use std::collections::BTreeMap;
    use std::os::unix::fs::symlink;
    use tempfile::TempDir;

    /// A workspace `<w>/app` (the project) beside `<w>/lib` (a sibling).
    fn workspace() -> TempDir {
        let w = TempDir::new().unwrap();
        fs::create_dir(w.path().join("app")).unwrap();
        w
    }

    fn write_manifest(dir: &Path, value: &serde_json::Value) {
        fs::create_dir_all(dir).unwrap();
        fs::write(dir.join("package.json"), value.to_string()).unwrap();
    }

    /// A link placement; an empty `name` is a target entry npm wrote without one.
    fn link(key: &str, target: &str, name: &str, version: Option<&str>) -> LinkPlacement {
        let LinkTargetParse::Ok(target) = LinkTarget::parse(target) else {
            panic!("{target} must be a sibling");
        };
        LinkPlacement {
            path: InstallPath::new(key),
            target,
            name: (!name.is_empty()).then(|| name.to_string()),
            version: version.map(str::to_string),
            bins: BTreeMap::new(),
        }
    }

    fn plan_with(links: Vec<LinkPlacement>) -> InstallPlan {
        InstallPlan {
            links,
            ..InstallPlan::default()
        }
    }

    fn only_problem(err: FuziError) -> String {
        match err {
            FuziError::LinkTarget { mut problems } => {
                assert_eq!(problems.len(), 1, "{problems:?}");
                problems.remove(0).detail
            }
            other => panic!("expected LinkTarget, got {other:?}"),
        }
    }

    #[test]
    fn matching_target_passes_without_warnings() {
        let w = workspace();
        write_manifest(
            &w.path().join("lib"),
            &serde_json::json!({"name": "lib", "version": "1.0.0"}),
        );
        let plan = plan_with(vec![link(
            "node_modules/lib",
            "../lib",
            "lib",
            Some("1.0.0"),
        )]);
        let warnings = check_link_targets(&plan, &w.path().join("app")).unwrap();
        assert!(warnings.is_empty());
    }

    #[test]
    fn missing_target_refuses() {
        let w = workspace();
        let plan = plan_with(vec![link("node_modules/lib", "../lib", "lib", None)]);
        let detail = only_problem(check_link_targets(&plan, &w.path().join("app")).unwrap_err());
        assert!(detail.contains("does not exist"), "{detail}");
    }

    #[test]
    fn symlinked_target_refuses() {
        let w = workspace();
        write_manifest(&w.path().join("real"), &serde_json::json!({"name": "lib"}));
        symlink(w.path().join("real"), w.path().join("lib")).unwrap();
        let plan = plan_with(vec![link("node_modules/lib", "../lib", "lib", None)]);
        let detail = only_problem(check_link_targets(&plan, &w.path().join("app")).unwrap_err());
        assert!(detail.contains("is a symlink"), "{detail}");
    }

    #[test]
    fn symlinked_package_json_refuses() {
        let w = workspace();
        let lib = w.path().join("lib");
        fs::create_dir(&lib).unwrap();
        let planted = w.path().join("planted.json");
        fs::write(&planted, r#"{"name":"lib"}"#).unwrap();
        symlink(&planted, lib.join("package.json")).unwrap();
        let plan = plan_with(vec![link("node_modules/lib", "../lib", "lib", None)]);
        let detail = only_problem(check_link_targets(&plan, &w.path().join("app")).unwrap_err());
        assert!(detail.contains("package.json is a symlink"), "{detail}");
    }

    #[test]
    fn oversized_package_json_refuses() {
        let w = workspace();
        let lib = w.path().join("lib");
        fs::create_dir(&lib).unwrap();
        let padding = " ".repeat(usize::try_from(MAX_LINK_PACKAGE_JSON).unwrap());
        fs::write(
            lib.join("package.json"),
            format!(r#"{{"name":"lib"}}{padding}"#),
        )
        .unwrap();
        let plan = plan_with(vec![link("node_modules/lib", "../lib", "lib", None)]);
        let detail = only_problem(check_link_targets(&plan, &w.path().join("app")).unwrap_err());
        assert!(detail.contains("over the"), "{detail}");
    }

    #[test]
    fn name_mismatch_refuses_and_every_link_is_reported() {
        let w = workspace();
        write_manifest(&w.path().join("lib"), &serde_json::json!({"name": "other"}));
        write_manifest(
            &w.path().join("nameless"),
            &serde_json::json!({"version": "1"}),
        );
        let plan = plan_with(vec![
            link("node_modules/lib", "../lib", "lib", None),
            link("node_modules/nameless", "../nameless", "nameless", None),
        ]);
        match check_link_targets(&plan, &w.path().join("app")).unwrap_err() {
            FuziError::LinkTarget { problems } => {
                assert_eq!(problems.len(), 2);
                assert!(problems[0].detail.contains("is package `other`"));
                assert!(problems[1].detail.contains("has no name"));
            }
            other => panic!("expected LinkTarget, got {other:?}"),
        }
    }

    #[test]
    fn version_mismatch_warns() {
        let w = workspace();
        write_manifest(
            &w.path().join("lib"),
            &serde_json::json!({"name": "lib", "version": "2.0.0"}),
        );
        let plan = plan_with(vec![link(
            "node_modules/lib",
            "../lib",
            "lib",
            Some("1.0.0"),
        )]);
        let warnings = check_link_targets(&plan, &w.path().join("app")).unwrap();
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("version 2.0.0"), "{}", warnings[0]);
    }

    #[test]
    fn missing_version_warns() {
        let w = workspace();
        write_manifest(&w.path().join("lib"), &serde_json::json!({"name": "lib"}));
        let plan = plan_with(vec![link(
            "node_modules/lib",
            "../lib",
            "lib",
            Some("1.0.0"),
        )]);
        let warnings = check_link_targets(&plan, &w.path().join("app")).unwrap();
        assert_eq!(warnings.len(), 1);
        assert!(
            warnings[0].contains("has no version, the lockfile recorded 1.0.0"),
            "{}",
            warnings[0]
        );
    }

    #[test]
    fn file_target_refuses_as_not_a_directory() {
        let w = workspace();
        fs::write(w.path().join("lib"), b"not a package").unwrap();
        let plan = plan_with(vec![link("node_modules/lib", "../lib", "lib", None)]);
        let detail = only_problem(check_link_targets(&plan, &w.path().join("app")).unwrap_err());
        assert!(detail.contains("is not a directory"), "{detail}");
    }

    #[test]
    fn target_without_package_json_refuses() {
        let w = workspace();
        fs::create_dir(w.path().join("lib")).unwrap();
        let plan = plan_with(vec![link("node_modules/lib", "../lib", "lib", None)]);
        let detail = only_problem(check_link_targets(&plan, &w.path().join("app")).unwrap_err());
        assert!(detail.contains("has no package.json"), "{detail}");
    }

    #[test]
    fn alias_link_key_checks_the_target_entry_name() {
        // webref's alias shape: the key says `css6`, the package is `@webref/css`.
        let w = workspace();
        write_manifest(
            &w.path().join("css6"),
            &serde_json::json!({"name": "@webref/css"}),
        );
        let plan = plan_with(vec![link(
            "node_modules/@webref/css6",
            "../css6",
            "@webref/css",
            None,
        )]);
        check_link_targets(&plan, &w.path().join("app")).unwrap();
    }

    #[test]
    fn unnamed_target_defaults_to_the_folder_name() {
        let w = workspace();
        write_manifest(&w.path().join("lib"), &serde_json::json!({"name": "lib"}));
        let plan = plan_with(vec![link("node_modules/lib", "../lib", "", None)]);
        check_link_targets(&plan, &w.path().join("app")).unwrap();
        // A different package there still refuses against the default.
        write_manifest(&w.path().join("lib"), &serde_json::json!({"name": "other"}));
        let detail = only_problem(check_link_targets(&plan, &w.path().join("app")).unwrap_err());
        assert!(detail.contains("default name"), "{detail}");
    }

    #[test]
    fn unnamed_target_under_a_scope_directory_defaults_to_the_scoped_name() {
        // npm 11's nameFromFolder: `@scope/app` beside `@scope/lib` writes
        // `"../lib": {"version": ...}` with no name — the default is `@scope/lib`.
        let w = TempDir::new().unwrap();
        let scope = w.path().join("@scope");
        let app = scope.join("app");
        fs::create_dir_all(&app).unwrap();
        write_manifest(
            &scope.join("lib"),
            &serde_json::json!({"name": "@scope/lib"}),
        );
        let plan = plan_with(vec![link("node_modules/@scope/lib", "../lib", "", None)]);
        check_link_targets(&plan, &app).unwrap();
        write_manifest(&scope.join("lib"), &serde_json::json!({"name": "lib"}));
        let detail = only_problem(check_link_targets(&plan, &app).unwrap_err());
        assert!(detail.contains("`@scope/lib`"), "{detail}");
    }

    #[test]
    fn project_without_a_parent_directory_refuses() {
        // At `/`, `..` is `/` again, so `../<dir>` names a child of the project
        // rather than a sibling. Refused on the project alone, before the target
        // is looked at — nothing here reads beyond `/` and `/..`.
        let plan = plan_with(vec![link(
            "node_modules/lib",
            "../fuzi-test-no-such-sibling",
            "lib",
            None,
        )]);
        let detail = only_problem(check_link_targets(&plan, Path::new("/")).unwrap_err());
        assert!(detail.contains("no parent directory"), "{detail}");
    }

    #[test]
    fn bom_prefixed_package_json_is_accepted() {
        // npm strips a UTF-8 byte-order mark before parsing a package.json, so
        // a sibling npm installs must not refuse here.
        let w = workspace();
        let lib = w.path().join("lib");
        fs::create_dir(&lib).unwrap();
        fs::write(
            lib.join("package.json"),
            b"\xEF\xBB\xBF{\"name\":\"lib\",\"version\":\"1.0.0\"}",
        )
        .unwrap();
        let plan = plan_with(vec![link(
            "node_modules/lib",
            "../lib",
            "lib",
            Some("1.0.0"),
        )]);
        let warnings = check_link_targets(&plan, &w.path().join("app")).unwrap();
        assert!(warnings.is_empty(), "{warnings:?}");
        // Only a leading one: a second BOM is not JSON.
        fs::write(
            lib.join("package.json"),
            b"\xEF\xBB\xBF\xEF\xBB\xBF{\"name\":\"lib\"}",
        )
        .unwrap();
        let detail = only_problem(check_link_targets(&plan, &w.path().join("app")).unwrap_err());
        assert!(detail.contains("not valid JSON"), "{detail}");
    }

    #[test]
    fn package_json_shapes_that_are_not_a_named_manifest_refuse() {
        // Pin: every shape that is not "a regular file holding a JSON object
        // with a string `name`" refuses, each with its own reason.
        let w = workspace();
        let lib = w.path().join("lib");
        fs::create_dir(&lib).unwrap();
        let manifest = lib.join("package.json");
        let plan = plan_with(vec![link("node_modules/lib", "../lib", "lib", None)]);
        let check = || only_problem(check_link_targets(&plan, &w.path().join("app")).unwrap_err());

        // A directory where the file should be.
        fs::create_dir(&manifest).unwrap();
        let detail = check();
        assert!(detail.contains("not a regular file"), "{detail}");
        fs::remove_dir(&manifest).unwrap();

        for (bytes, expected) in [
            (&b""[..], "not valid JSON"),
            (b"\xff\xfe{\"name\":\"lib\"}", "not valid JSON"), // invalid UTF-8
            (b"{\"name\":\"l\xffb\"}", "not valid JSON"),      // invalid UTF-8 in a string
            (b"{\"name\":\"lib\"", "not valid JSON"),          // truncated
            (b"{\"name\":\"lib\"} x", "not valid JSON"),       // trailing garbage
            (b"[]", "has no name"),
            (b"\"lib\"", "has no name"),
            (b"42", "has no name"),
            (b"null", "has no name"),
            (b"{}", "has no name"),
            (b"{\"name\":7}", "has no name"),
            (b"{\"name\":null}", "has no name"),
            (b"{\"name\":[\"lib\"]}", "has no name"),
            (b"{\"name\":{\"lib\":true}}", "has no name"),
            (b"{\"name\":\"\"}", "is package ``"),
            (b"{\"name\":\"lib \"}", "is package `lib `"), // not trimmed
            (b"{\"name\":\"LIB\"}", "is package `LIB`"),   // not case-folded
            (b"{\"Name\":\"lib\"}", "has no name"),        // the key is exact too
        ] {
            fs::write(&manifest, bytes).unwrap();
            let detail = check();
            assert!(
                detail.contains(expected),
                "{:?}: {detail}",
                String::from_utf8_lossy(bytes)
            );
        }

        // A repeated key takes its last value, as `JSON.parse` does for npm.
        fs::write(&manifest, br#"{"name":"other","name":"lib"}"#).unwrap();
        check_link_targets(&plan, &w.path().join("app")).unwrap();
    }

    // --- linked bins ---

    /// A target `<w>/lib` holding `bin/run.js` (0755) and `bin/plain.js` (0644).
    fn bin_target() -> (TempDir, PathBuf) {
        use std::os::unix::fs::PermissionsExt as _;
        let w = TempDir::new().unwrap();
        let lib = w.path().join("lib");
        fs::create_dir_all(lib.join("bin")).unwrap();
        for (name, mode) in [("run.js", 0o755), ("plain.js", 0o644)] {
            fs::write(lib.join("bin").join(name), b"#!/usr/bin/env node\n").unwrap();
            fs::set_permissions(lib.join("bin").join(name), fs::Permissions::from_mode(mode))
                .unwrap();
        }
        (w, lib)
    }

    fn linkable(lib: &Path, bin: &str) -> bool {
        linked_bin_is_linkable(lib, &BinTarget::parse(bin).unwrap())
    }

    #[test]
    fn linkable_bin_is_an_executable_regular_file_under_real_directories() {
        let (_w, lib) = bin_target();
        for bin in ["bin/run.js", "./bin/run.js", "bin//run.js", "bin/./run.js"] {
            assert!(linkable(&lib, bin), "{bin}");
        }
        for bin in [
            "bin/plain.js", // no exec bit
            "bin/ghost.js", // absent
            "bin",          // a directory
            "bin/",         // names a directory
            "bin/run.js/",  // a file is not a directory
            "bin/run.js/.", // likewise
            "bin/run.js/x", // a file as a parent
            ".",            // the package itself
            "./",
        ] {
            assert!(!linkable(&lib, bin), "{bin}");
        }
    }

    #[test]
    fn linkable_bin_refuses_a_symlink_at_any_component() {
        let (w, lib) = bin_target();
        let outside = w.path().join("outside");
        fs::create_dir(&outside).unwrap();
        fs::copy(lib.join("bin/run.js"), outside.join("run.js")).unwrap();
        // A symlinked parent directory, leaving the target.
        symlink(&outside, lib.join("out")).unwrap();
        assert!(lib.join("out/run.js").is_file(), "sanity: it resolves");
        assert!(!linkable(&lib, "out/run.js"));
        // A symlinked parent that stays inside the target is refused the same
        // way: the rule is "real directories only", not "ends up inside".
        symlink("bin", lib.join("alias")).unwrap();
        assert!(!linkable(&lib, "alias/run.js"));
        // A symlink at the final component, executable target or not.
        symlink("run.js", lib.join("bin/link.js")).unwrap();
        assert!(!linkable(&lib, "bin/link.js"));
        symlink(outside.join("run.js"), lib.join("bin/far.js")).unwrap();
        assert!(!linkable(&lib, "bin/far.js"));
    }

    #[test]
    fn target_that_is_the_project_refuses() {
        let w = workspace();
        let app = w.path().join("app");
        write_manifest(&app, &serde_json::json!({"name": "app"}));
        let plan = plan_with(vec![link("node_modules/app", "../app", "app", None)]);
        let detail = only_problem(check_link_targets(&plan, &app).unwrap_err());
        assert!(detail.contains("the project itself"), "{detail}");
    }
}
