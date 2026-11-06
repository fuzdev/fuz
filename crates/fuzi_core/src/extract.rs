//! Extract one verified npm tarball into a package directory.
//!
//! The hardened streaming/guard core is `fuz_archive::safe_extract` (shared with
//! `fuz_release`). This module supplies fuzi's policy: a **nested-tree**
//! placement that strips npm's leading tarball component (`strip_components=1`
//! — node-tar's behavior, robust to non-`package/` roots) and preserves the
//! rest of the tree, a **tighter per-tarball cap** than the workspace's 10 GiB
//! signed-artifact ceiling, and the workspace [`SymlinkPolicy::Reject`] default
//! (no package in the fuz projects' own lockfiles ships intra-tarball symlinks;
//! the `.bin` symlinks are fuzi-created at materialization, not extracted).
//!
//! Owner-exec bits are preserved by the core (an npm `bin/<cmd>` 0755 ELF stays
//! executable; data files normalize to 0644) — so a script-skipped install of
//! e.g. esbuild still finds an executable binary where the runtime expects one.
//!
//! This is the per-tarball extractor. The whole-tree staging-swap, the
//! `.fuzi-installing-<rand>` rename, the free-space pre-flight, and `.bin`
//! linking are materialization and live in `crate::staging` / `crate::materialize`.

use std::io::Read;
use std::path::{Component, Path, PathBuf};

use fuz_archive::{
    ArchiveError, ExtractLimits, ExtractReport, Placement, SymlinkPolicy, safe_extract,
};

use crate::staging::StagingDir;

/// Per-tarball extracted-total ceiling.
///
/// `fuz_sys::limits` single-sources the 10 GiB workspace artifact ceiling
/// (sized for GB-scale signed artifacts); for a *single* npm package the
/// opposite tuning fits — anything over a few hundred MB extracted is
/// pathological — so fuzi caps far tighter and leans on the size-independent
/// compression-ratio bomb guard. Deliberately a loose ceiling (a
/// denial-of-service backstop, not a tight fit): generous enough for large
/// native packages (`playwright`, `@img/sharp` variants) without
/// false-rejecting them.
// Measured against the gate corpus (esbuild/vite/rollup trees) nothing came
// close to this; kept deliberately loose so the size-independent compression
// ratio guard does the real bomb-detection and a large-but-legitimate native
// package is never false-rejected.
pub const MAX_NPM_EXTRACTED_TOTAL: u64 = 1024 * 1024 * 1024;

/// Per-file extracted ceiling within a single npm tarball.
pub const MAX_NPM_EXTRACTED_FILE: u64 = 512 * 1024 * 1024;

/// Maximum entry-path length within an npm tarball. Looser than fuz's signed
/// bundles (256) — npm package paths nest deeper (`package/dist/.../foo.d.ts`).
pub const MAX_NPM_PATH_LENGTH: usize = 4096;

/// Compression-ratio bomb cap (matches the workspace signed-bundle cap; the
/// guard is size-independent, so it holds regardless of the size ceilings).
const MAX_NPM_COMPRESSION_RATIO: u64 = 100;

/// Header-window cap within an npm tarball: the most `tar` may read between
/// one entry's body and the next entry's data — header blocks plus the PAX /
/// GNU long-name bodies it buffers in memory.
///
/// Without it a hostile tarball's metadata is bounded only by
/// [`MAX_NPM_EXTRACTED_TOTAL`], held in memory once per concurrent extraction.
/// Real npm metadata is tiny — a scan of a local npm cache found no PAX body
/// over 1 KiB (the largest an old npm's `NODETAR.*` record set) and no GNU
/// long-name body — so the cap leaves three orders of magnitude of headroom for
/// the long tail of older packers while staying three orders below the total.
pub const MAX_NPM_HEADER_SIZE: u64 = 1024 * 1024;

/// Extraction limits for a single npm tarball.
const fn npm_extract_limits() -> ExtractLimits {
    ExtractLimits {
        max_file_size: MAX_NPM_EXTRACTED_FILE,
        max_total_size: MAX_NPM_EXTRACTED_TOTAL,
        max_compression_ratio: MAX_NPM_COMPRESSION_RATIO,
        max_header_size: MAX_NPM_HEADER_SIZE,
        max_path_length: MAX_NPM_PATH_LENGTH,
    }
}

/// Placement: strip the first path component (npm's `strip_components=1`),
/// preserve the rest of the nested tree, and **skip any entry vendored under a
/// nested `node_modules/`**.
///
/// # Strip-first-component
///
/// npm tarballs root every entry under a single top directory (`package/` by
/// convention, occasionally another name for old/git-sourced packages). Matching
/// node-tar, we strip whatever that first component is rather than a literal
/// `package/`. An entry that is *only* the root component (the top directory
/// itself) maps to `None` and is skipped.
///
/// # Why nested `node_modules/` entries are skipped
///
/// After the strip, any remaining `node_modules` path component (matched
/// case-insensitively, since a case-insensitive filesystem folds
/// `Node_Modules` onto it) means the tarball
/// carries its *own* vendored copy of a dependency's tree — e.g. a `package/`
/// tarball shipping `package/node_modules/<child>/…`. fuzi drops every such entry.
/// One reason is determinism and one is correctness; they reinforce each other.
///
/// - **Determinism — it removes a write race.** The staging dir for a nested
///   placement `node_modules/<parent>/node_modules/<child>` is
///   `<root>/<parent>/node_modules/<child>` — the *exact* path a
///   `node_modules/<child>/…` entry in the parent's tarball strips to. Extraction
///   runs concurrently across placements (`crate::materialize`), and whether the
///   pool engages at all is clamped by the host core count. So the parent's worker
///   and the child's worker would write the same staging paths with no ordering,
///   no locking, and a truncating `File::create`: a directory's final bytes could
///   be either package's, differing from run to run and — because concurrency is
///   core-count-gated — between a 1-core CI runner and a many-core dev box from one
///   lockfile. That is a direct violation of fuzi's determinism guarantee. Skipping
///   the vendored entries makes the child placement the *sole* writer of its path,
///   so the tree is identical regardless of thread timing or host parallelism.
/// - **Correctness — the child has its own verified placement.** fuzi's model is
///   that every installed package is its own lockfile placement backed by its own
///   integrity-verified tarball. A parent's vendored copy of a child rode in on the
///   *parent's* tarball, so it is unverified at the child's path; letting it land
///   would put unverified-at-that-path bytes over the child's real placement.
///   Dropping it leaves the child's own verified tarball as the single source of
///   the child's bytes — race-free *and* more correct.
///
/// # Why this is safe (a registry tarball never legitimately ships this)
///
/// A published npm **registry** tarball never carries `node_modules/` content
/// *except* for `bundledDependencies` — and npm marks every bundled child entry
/// `inBundle` in the lockfile, which fuzi **refuses** outright before any fetch or
/// extraction ([`RefuseReason::BundledUnsupported`]). An install that reaches
/// extraction therefore cannot be a legitimate bundled-deps install; a tarball
/// that still ships `node_modules/` here is anomalous — broken, git-sourced, or
/// hostile — so discarding its vendored entries never drops content a correct
/// install needed.
///
/// The drop is a **deliberate, silent** discard of anomalous content. It rides
/// [`safe_extract`]'s existing skip path (placement
/// returns `None`). The skipped body is still decompressed as `tar` advances past
/// it, through the budget reader that charges every decompressed byte to the
/// total-size and compression-ratio budget — so a `node_modules`-vendored gzip
/// bomb cannot dodge the guards. Surfacing a count on the
/// [`InstallReport`](crate::InstallReport) is deliberately left out: `safe_extract`
/// reports no per-entry skips to its caller, so a `vendored_node_modules_skipped`
/// tally would have to be threaded out of `ExtractReport` and up through the
/// concurrent extraction path into the binary's warning surface — invasive for a
/// count that is zero on every legitimate install.
///
/// A firing skip is a genuine tarball-vs-lockfile disagreement (the tarball ships
/// a dependency tree the lockfile doesn't account for), which is exactly why the
/// silent drop is acceptable *today*: the anomaly is unreachable on an npm-real
/// lock (bundled deps refuse at classify). If this class ever needs to be
/// surfaced, the right escalation is a loud refuse, not a silent count.
///
/// [`RefuseReason::BundledUnsupported`]: crate::classify::RefuseReason::BundledUnsupported
struct StripFirstComponent;

impl Placement for StripFirstComponent {
    fn place(&self, entry: &Path) -> Option<PathBuf> {
        let mut components = entry.components();
        components.next()?; // drop the leading tarball root component
        let rest = components.as_path();
        if rest.as_os_str().is_empty() {
            return None; // the root component alone (the top directory itself)
        }
        // Skip a dependency vendored inside this tarball: any remaining
        // `node_modules` path component. Whole-component match — a file whose
        // *name* merely contains the substring (`node_modules_helper.js`) is a
        // `Normal` component that does not equal `node_modules`, so it is kept.
        // Case-insensitive: on a case-insensitive filesystem (macOS default,
        // Windows) `Node_Modules/x` lands in the same directory as
        // `node_modules/x`, so it is the same collision. See the type-level doc
        // for why (race removal + the child's own verified placement is the
        // source of truth).
        if rest
            .components()
            .any(|c| matches!(c, Component::Normal(name) if is_node_modules(name)))
        {
            return None;
        }
        Some(rest.to_path_buf())
    }
}

/// Whether a path component names `node_modules` on a case-insensitive
/// filesystem: ASCII case folded, and, for a non-ASCII name, Unicode case
/// folded as well — `node_moduleſ` (U+017F, the long s, which upper-cases to
/// `S`) is the same directory as `node_modules` where the filesystem folds
/// case that way. The non-ASCII arm allocates, and only runs for a non-ASCII
/// component.
fn is_node_modules(name: &std::ffi::OsStr) -> bool {
    const NODE_MODULES: &str = "node_modules";
    name.eq_ignore_ascii_case(NODE_MODULES)
        || name.to_str().is_some_and(|name| {
            !name.is_ascii() && name.to_uppercase().to_lowercase() == NODE_MODULES
        })
}

/// Extract a single verified npm tarball (`reader`, `compressed_size` bytes of
/// `.tar.gz`) into `dest`, stripping the leading tarball component and
/// preserving the nested tree.
///
/// `dest` is a [`StagingDir`] — a fresh, fuzi-owned directory inside a
/// `StagingTree`, never a live `node_modules`. Taking the newtype rather than a
/// bare `&Path` reifies the destination-trust precondition: extraction uses no
/// `O_NOFOLLOW`, so it is safe only against a destination no other writer has
/// touched (a pre-existing on-disk symlink under `dest` would be followed). The
/// only constructor of a `StagingDir` is the staging allocator, so a caller
/// *cannot* point this at an existing tree. Intra-tarball traversal is contained
/// by the core (symlinks/hardlinks rejected, paths re-validated under the root).
///
/// # Errors
///
/// Returns the [`ArchiveError`] on a malformed/oversized archive, a rejected
/// entry type (symlink/hardlink/device), a compression bomb, or a read or
/// filesystem failure. The caller names the package when it wraps it as
/// [`FuziError::Extract`](crate::FuziError::Extract).
pub fn extract_package<R: Read>(
    reader: R,
    compressed_size: u64,
    dest: &StagingDir,
) -> Result<ExtractReport, ArchiveError> {
    safe_extract(
        reader,
        compressed_size,
        dest.path(),
        &npm_extract_limits(),
        &StripFirstComponent,
        SymlinkPolicy::Reject,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{gz_tar, reg};
    use std::io::Write as _; // the symlink test below builds a tarball inline

    /// Wrap a tempdir path as a `StagingDir` (extraction's only valid dest).
    fn staging(path: &Path) -> StagingDir {
        StagingDir::for_tests(path.to_path_buf())
    }

    #[test]
    fn strips_package_prefix_and_preserves_tree() {
        let dir = tempfile::tempdir().unwrap();
        let gz = gz_tar(&[
            reg("package/package.json", 0o644, br#"{"name":"x"}"#),
            reg("package/lib/sub/index.js", 0o644, b"export {}"),
        ]);
        let report = extract_package(&gz[..], gz.len() as u64, &staging(dir.path())).unwrap();
        // `package/` stripped; nested tree preserved.
        assert!(dir.path().join("package.json").is_file());
        assert!(dir.path().join("lib/sub/index.js").is_file());
        assert!(!dir.path().join("package").exists());
        assert_eq!(report.files.len(), 2);
    }

    #[test]
    fn strips_non_package_root_too() {
        // Old/git-sourced tarballs may root under a different dir name; node-tar
        // strips the first component regardless, and so do we.
        let dir = tempfile::tempdir().unwrap();
        let gz = gz_tar(&[reg("some-other-root/index.js", 0o644, b"x")]);
        extract_package(&gz[..], gz.len() as u64, &staging(dir.path())).unwrap();
        assert!(dir.path().join("index.js").is_file());
    }

    #[cfg(unix)]
    #[test]
    fn preserves_bin_exec_bit() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        // esbuild ships bin/esbuild as a 0755 ELF; a script-skipped install must
        // keep it executable.
        let gz = gz_tar(&[
            reg("package/bin/esbuild", 0o755, b"\x7fELF fake"),
            reg("package/package.json", 0o644, b"{}"),
        ]);
        extract_package(&gz[..], gz.len() as u64, &staging(dir.path())).unwrap();
        let bin_mode = std::fs::metadata(dir.path().join("bin/esbuild"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        let json_mode = std::fs::metadata(dir.path().join("package.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(bin_mode, 0o755, "bin/esbuild must stay executable");
        assert_eq!(json_mode, 0o644);
    }

    #[test]
    fn rejects_intra_tarball_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let mut tar_data = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_data);
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_path("package/evil").unwrap();
            header.set_link_name("/etc/passwd").unwrap();
            header.set_size(0);
            header.set_cksum();
            builder.append(&header, &[][..]).unwrap();
            builder.finish().unwrap();
        }
        let mut gz = Vec::new();
        {
            use flate2::Compression;
            use flate2::write::GzEncoder;
            let mut enc = GzEncoder::new(&mut gz, Compression::default());
            enc.write_all(&tar_data).unwrap();
            enc.finish().unwrap();
        }
        let err = extract_package(&gz[..], gz.len() as u64, &staging(dir.path())).unwrap_err();
        assert!(err.is_security_violation(), "{err:?}");
    }

    #[test]
    fn rejects_compression_bomb_via_tighter_cap() {
        // Sanity that fuzi's limits flow through: a > 100x-ratio payload trips
        // the bomb guard.
        let dir = tempfile::tempdir().unwrap();
        let gz = gz_tar(&[reg("package/zeros", 0o644, &vec![0u8; 4 * 1024 * 1024])]);
        let err = extract_package(&gz[..], gz.len() as u64, &staging(dir.path())).unwrap_err();
        match err {
            ArchiveError::CompressionBomb(_) => {}
            other => panic!("expected compression bomb, got {other:?}"),
        }
    }

    #[test]
    fn rejects_oversized_pax_body_via_header_cap() {
        // Sanity that fuzi's header cap flows through: a PAX body past
        // `MAX_NPM_HEADER_SIZE` is refused by the header window, not admitted
        // up to the total. The body is incompressible (xorshift), so the
        // ratio guard stays out of the way.
        let len = usize::try_from(2 * MAX_NPM_HEADER_SIZE).unwrap();
        let mut state: u64 = 0x9e37_79b9_7f4a_7c15;
        let body: Vec<u8> = (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state.to_le_bytes()[0]
            })
            .collect();
        let gz = gz_tar(&[
            ("PaxHeader", 0o644, tar::EntryType::XHeader, &body[..]),
            reg("package/index.js", 0o644, b"x"),
        ]);
        let dir = tempfile::tempdir().unwrap();
        let err = extract_package(&gz[..], gz.len() as u64, &staging(dir.path())).unwrap_err();
        match err {
            ArchiveError::HeaderTooLarge(MAX_NPM_HEADER_SIZE) => {}
            other => panic!("expected oversized headers, got {other:?}"),
        }
    }

    #[test]
    fn skips_node_modules_vendored_entries() {
        // A tarball that ships its own vendored dependency trees under
        // `node_modules/` — anomalous for a registry tarball (bundled deps are
        // refused at classify via `inBundle`), so every such entry is dropped.
        // The child's own verified placement is the source of those bytes, and
        // dropping them here removes the extraction write-race the concurrent
        // materializer would otherwise have.
        let dir = tempfile::tempdir().unwrap();
        let gz = gz_tar(&[
            reg("package/index.js", 0o644, b"real"),
            // Shallow: a dependency vendored directly under the package root.
            reg("package/node_modules/vendored/index.js", 0o644, b"vendored"),
            // Deeply nested: `node_modules` appearing below another directory.
            reg("package/lib/node_modules/x/index.js", 0o644, b"deep"),
            // Scoped: `node_modules/@scope/y`.
            reg("package/node_modules/@scope/y/index.js", 0o644, b"scoped"),
        ]);
        let report = extract_package(&gz[..], gz.len() as u64, &staging(dir.path())).unwrap();
        // The package's own file is present...
        assert!(dir.path().join("index.js").is_file());
        // ...but every entry with a `node_modules` component is dropped (and the
        // directories that would have held them are never created).
        assert!(!dir.path().join("node_modules").exists());
        assert!(!dir.path().join("lib").exists());
        // Only the single legitimate file was placed.
        assert_eq!(report.files.len(), 1);
        assert!(report.files.contains_key(Path::new("index.js")));
    }

    #[test]
    fn skips_vendored_node_modules_in_any_ascii_case() {
        // On a case-insensitive filesystem `Node_Modules/child` is the child's
        // own placement directory, so the skip must fold case too.
        let dir = tempfile::tempdir().unwrap();
        let gz = gz_tar(&[
            reg("package/index.js", 0o644, b"real"),
            reg("package/Node_Modules/child/index.js", 0o644, b"vendored"),
            reg("package/lib/NODE_MODULES/x/index.js", 0o644, b"deep"),
        ]);
        let report = extract_package(&gz[..], gz.len() as u64, &staging(dir.path())).unwrap();
        assert_eq!(report.files.len(), 1);
        assert!(report.files.contains_key(Path::new("index.js")));
        assert!(!dir.path().join("Node_Modules").exists());
        assert!(!dir.path().join("lib").exists());
    }

    #[test]
    fn the_vendored_skip_folds_non_ascii_case() {
        // `ſ` (U+017F) upper-cases to `S`: a filesystem that folds case by
        // Unicode rules puts `node_moduleſ/child` in the child's directory.
        // A non-ASCII name that folds to something else is kept.
        for name in [
            "node_moduleſ",
            "NODE_MODULEſ",
            "node_moduleſ".to_uppercase().as_str(),
        ] {
            assert!(is_node_modules(name.as_ref()), "{name}");
        }
        for name in ["node_modulé", "nøde_modules", "node_modules_ſ"] {
            assert!(!is_node_modules(name.as_ref()), "{name}");
        }
        let dir = tempfile::tempdir().unwrap();
        let gz = gz_tar(&[
            reg("package/index.js", 0o644, b"real"),
            reg("package/node_moduleſ/child/index.js", 0o644, b"vendored"),
        ]);
        let report = extract_package(&gz[..], gz.len() as u64, &staging(dir.path())).unwrap();
        assert_eq!(report.files.len(), 1);
        assert!(!dir.path().join("node_moduleſ").exists());
    }

    #[test]
    fn keeps_node_modules_substring_names_and_full_tree() {
        // The skip is an *exact component* match: a file or directory whose name
        // merely contains "node_modules" as a substring is a `Normal` component
        // that is not equal to `node_modules`, so it must survive. A legitimate
        // tree (no `node_modules` component at all) must extract fully.
        let dir = tempfile::tempdir().unwrap();
        let gz = gz_tar(&[
            reg("package/package.json", 0o644, b"{}"),
            reg("package/lib/sub/index.js", 0o644, b"x"),
            reg("package/node_modules_helper.js", 0o644, b"helper"),
            reg("package/node_modules_shim/index.js", 0o644, b"shim"),
        ]);
        let report = extract_package(&gz[..], gz.len() as u64, &staging(dir.path())).unwrap();
        assert!(dir.path().join("package.json").is_file());
        assert!(dir.path().join("lib/sub/index.js").is_file());
        assert!(dir.path().join("node_modules_helper.js").is_file());
        assert!(dir.path().join("node_modules_shim/index.js").is_file());
        // No entry dropped — the skip must not touch legitimate trees.
        assert_eq!(report.files.len(), 4);
    }

    #[test]
    fn vendored_node_modules_gzip_bomb_is_still_charged() {
        // A `node_modules`-vendored entry is skipped for *placement*, but its
        // body is still decompressed past, and `safe_extract` charges every
        // decompressed byte to the total/ratio DoS budget — so a gzip bomb
        // hidden under a vendored `node_modules/` cannot dodge the
        // compression-ratio guard.
        let dir = tempfile::tempdir().unwrap();
        let gz = gz_tar(&[reg(
            "package/node_modules/evil/zeros",
            0o644,
            &vec![0u8; 4 * 1024 * 1024],
        )]);
        let err = extract_package(&gz[..], gz.len() as u64, &staging(dir.path())).unwrap_err();
        match err {
            ArchiveError::CompressionBomb(_) => {}
            other => panic!("expected compression bomb, got {other:?}"),
        }
    }
}
