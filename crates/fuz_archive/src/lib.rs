//! Manifest-free, security-hardened streaming `.tar.gz` extraction.
//!
//! A leaf shared by `fuz_release` (signed bundles) and `fuzi_core` (npm
//! tarballs), so the npm bridge links the hardening without manifests, signing,
//! or storage; neither consumer depends on the other.
//!
//! The crate knows nothing about manifests, signing, or npm. Three seams let
//! each caller supply policy:
//!
//! - [`Placement`] — maps a validated tar entry to its destination relative to
//!   the extraction root, or `None` to skip. `fuz_release` flattens to a
//!   basename (then validates against its manifest allowlist); `fuzi_core`
//!   strips the leading tarball component and preserves the nested tree.
//! - [`ExtractLimits`] — per-file / total / ratio / header / path-length
//!   ceilings. The signed-bundle path uses the 10 GiB workspace ceiling;
//!   `fuzi_core` layers a tighter per-tarball cap.
//! - [`SymlinkPolicy`] — symlink/hardlink handling (reject only).
//!
//! The guards that are *not* policy — zip-slip (only `Normal` path components),
//! null bytes, path length, per-file/total size, the compression-ratio bomb
//! check, the header window, and setuid/setgid rejection — apply
//! unconditionally.
//!
//! # Decompression budget
//!
//! The total-size and ratio ceilings are enforced on the **decompressed stream
//! itself**, by a counting reader between the gzip decoder and the tar reader —
//! not per entry. `tar` decompresses bytes `safe_extract` never sees as file
//! data: GNU long-name / long-link and PAX extension bodies (which it buffers
//! whole, before yielding the entry they describe), the bodies of skipped
//! entries, headers, and padding. Charging at that one
//! choke point means none of those can inflate past the budget, and an entry's
//! declared size (which a PAX header can override) never decides what is
//! charged.
//!
//! The total alone would still let one extraction's metadata grow as large as
//! the whole budget, and `tar` holds an extension body in memory, so the same
//! reader also enforces a far tighter **header window**. Between yields, `tar`'s
//! entry iterator reads the unread rest of the previous entry's body and its
//! padding, then every header block up to the next real entry: the PAX
//! extension (`x`), GNU long-name (`L`) and long-link (`K`) bodies it buffers,
//! and any GNU sparse extension blocks. Before each step of that iterator,
//! [`safe_extract`] arms the reader with a limit: the stream offset where the
//! previous entry's padded body ends (from its data position and effective
//! size, so a skipped or directory body drains freely) plus
//! [`ExtractLimits::max_header_size`]. Reads are clamped to it, and a read at
//! it fails with [`ArchiveError::HeaderTooLarge`], so `tar` stops at the cap —
//! before a hostile body is buffered. The window is disarmed while `safe_extract` reads
//! a file's data, which only the per-file and total ceilings bound.
//!
//! A PAX global header (`g`) is not consumed by the iterator — `tar` yields it
//! as an entry, which the entry-type guard refuses.
//!
//! # One reading of the stream
//!
//! npm extracts with node-tar, and a tar stream two readers split differently
//! is two archives under one digest: the entries one reader sees as headers,
//! the other reads as some entry's body. These splits are refused here:
//!
//! - **An entry's size.** A PAX `size` record overrides the ustar size field —
//!   always, in node-tar and `tar` 0.4.46; only over a zero field, in earlier
//!   `tar`. An entry whose record disagrees with a non-zero field is refused
//!   ([`ArchiveError::PaxSizeMismatch`]), and so is a PAX header the two
//!   parsers could read different records from ([`ArchiveError::MalformedPax`]):
//!   `tar` stops at a bad record where node-tar skips it, so a record
//!   after it would apply under one only.
//! - **An entry's name.** `tar` takes a GNU long name (`L`) over a PAX `path`
//!   record, and a long link (`K`) over a `linkpath`; node-tar takes whichever
//!   came last. An entry named by both is refused
//!   ([`ArchiveError::MalformedPax`]), in either order.
//! - **A header node-tar skips.** node-tar decodes every field of every header
//!   and skips a header it cannot decode, reading the entry's body as the
//!   headers that follow; `tar` decodes only the fields it uses. A header —
//!   the entry's or an extension's — with a numeric field the two decode
//!   differently, a checksum field that isn't ASCII ending in a NUL or space,
//!   a name with bytes after its NUL terminator, a link target on
//!   a header other than a link, or an empty path is refused, as is an entry
//!   path that is not UTF-8, which node-tar decodes lossily
//!   ([`ArchiveError::MalformedHeader`]).
//! - **A directory's body** (see *Directory entries* below).
//!
//! `tar` does not expose the extension headers it parsed, so the header window
//! captures what each iterator step reads, and they are re-read from there.
//! Two extension headers of one kind and a PAX global header (`g`), which
//! node-tar applies to every later entry, need no check here: `tar` refuses
//! the first and yields the second as an entry, which the entry-type guard
//! refuses.
//!
//! These refusals exist for npm, but they hold for every caller: `fuz_release`'s
//! signed bundles meet them too. That costs nothing — its packer
//! (`tar::Builder`, GNU headers, flat names, no directories or PAX) emits none
//! of the refused shapes — and protects nothing there, since a signed bundle's
//! bytes are digest-pinned and every extracted file is hash-checked against the
//! manifest; one strict reader is simpler than a policy switch.
//!
//! # File modes
//!
//! Each extracted regular file's mode is derived from the tar header's
//! **owner-execute bit**: `0o755` if set, else `0o644`. This preserves the
//! executable bit on shipped binaries (e.g. an npm package's `bin/<cmd>` 0755
//! ELF) while normalizing everything else, and never grants setuid/setgid (those
//! entries are rejected before extraction). `fuz_release`'s bundles pack every
//! binary at 0o755.
//!
//! # Directory entries
//!
//! Directory entries are **skipped** — destination directories are created
//! lazily from each file's parent path, never above the extraction root (see
//! *Destination trust*). Real-world (npm) tarballs carry explicit
//! directory entries; rejecting them would break nested extraction, and skipping
//! them is safe because the file allowlist (consumer-side) and the path guards
//! are what gate content.
//!
//! A directory entry that **declares a body** is refused
//! ([`ArchiveError::DirectoryWithBody`]). node-tar forces a directory's size to
//! zero and parses the declared body as further headers, where `tar` skips it
//! as data — so entries hidden in that body would install under npm and not
//! here, or the reverse.
//!
//! A **regular** entry (type `0` or the old `\0`) whose name ends in `/` is a
//! directory too: pre-POSIX tar had no directory type and marked one that way,
//! and node-tar reads it so (as `tar`'s own `unpack` does for old-format
//! headers). Written as a file, it would sit where the next entry under it
//! needs a directory.
//!
//! # Destination trust
//!
//! The extractor writes with ordinary `File::create` and
//! [`create_dir_all_below`] (**no `O_NOFOLLOW`**), so it is safe **only when
//! the caller owns the destination root** — a fresh directory not influenced by
//! an attacker. *Intra-archive*
//! traversal is fully contained: symlinks and hardlinks are rejected, only real
//! directories are created (so no extracted entry can be a symlink a later entry
//! follows), and every placed path is re-validated to all-`Normal` components
//! under the root. But a *pre-existing* symlink already on disk in the
//! destination tree **would be followed**. A caller materializing into a live
//! tree (e.g. `node_modules`) must extract into a controlled staging directory
//! and atomically swap it into place — `safe_extract` does not defend a hostile
//! destination.
//!
//! The root must **already exist**, and the extractor never creates it: each
//! file's missing parents are created strictly below the root
//! ([`create_dir_all_below`]). A root removed mid-extraction — fuzi's interrupt
//! drain removing a staging tree, or another process sweeping it — therefore
//! fails the extraction with `NotFound` ([`ArchiveError::Io`]) instead of being
//! re-created by the next entry and outliving its removal.

mod budget;
mod dir;
mod error;
mod one_reading;
mod validate;

#[cfg(test)]
mod tests;

pub use dir::create_dir_all_below;
pub use error::ArchiveError;

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use fuz_crypto::{ContentHash, HashAlgo, Hasher};

use budget::{BudgetReader, HeaderWindow};
use error::{end_of_archive_error, entry_path_lossy, tar_error, trailing_data_error};
use one_reading::check_one_reading;
use validate::{validate_entry_path, validate_placed_path};

/// Buffer size for streaming extraction (64 KiB).
const EXTRACT_BUFFER_SIZE: usize = 64 * 1024;

/// The tar block size: headers are one block, and bodies are padded to a
/// multiple of it.
const TAR_BLOCK_SIZE: u64 = 512;

/// Tunable extraction ceilings.
///
/// Each is a disk-exhaustion, memory, or denial-of-service guard. The ratio cap
/// is the size-independent gzip-bomb guard and holds regardless of the size
/// ceilings.
#[derive(Debug, Clone, Copy)]
pub struct ExtractLimits {
    /// Maximum size of any single extracted file (the entry's effective size,
    /// PAX override included; tar entries are length-prefixed, so it bounds the
    /// actual data).
    pub max_file_size: u64,
    /// Maximum total decompressed bytes across the whole archive — the whole
    /// decompressed stream, tar headers and padding included.
    pub max_total_size: u64,
    /// Maximum decompressed-to-compressed ratio before a gzip bomb is declared.
    pub max_compression_ratio: u64,
    /// Maximum decompressed bytes `tar` may read past the end of one entry's
    /// padded body to reach the next entry's data (or the end of the archive):
    /// the next header block plus any PAX extension, GNU long-name / long-link,
    /// and GNU sparse extension blocks before it. `tar` buffers extension
    /// bodies whole, so this is what bounds the memory one entry's metadata can
    /// take (see the crate-level *Decompression budget* section). Real
    /// metadata is small: a PAX record set or a long name fits in a few blocks.
    pub max_header_size: u64,
    /// Maximum length (in bytes) of any entry path.
    pub max_path_length: usize,
}

/// How to handle non-regular, non-directory entries (symlinks, hardlinks).
///
/// v0 has one variant — [`SymlinkPolicy::Reject`] — validated against the fuz
/// projects' own lockfiles (no package they install ships intra-tarball
/// symlinks; the `.bin` symlinks an installer creates are not extracted from
/// the tarball). An `AllowValidated` variant (extract symlinks whose targets
/// stay within the root) is the future seam; it stays unbuilt until a real
/// package needs it, at which point the `match` below forces it to be handled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymlinkPolicy {
    /// Reject any symlink or hardlink entry as [`ArchiveError::UnsupportedEntryType`].
    Reject,
    // TODO: add `AllowValidated` — extract a symlink iff its resolved target
    // stays within the extraction root (canonicalize and compare, reject
    // absolute/escaping targets). Keep devices/fifos rejecting unconditionally.
    // Only build this once a real npm package needs intra-tarball symlinks;
    // the `match` in `safe_extract` will force it to be handled.
}

/// Maps a validated tar entry path to its destination **relative to the
/// extraction root**, or `None` to skip the entry.
///
/// Consumed by [`safe_extract`] as a generic bound (`P: Placement`) for
/// monomorphization. The returned path is re-validated for containment by the
/// core (all-`Normal` components), so a buggy or hostile implementation cannot
/// escape the root — the safety property lives in the core, not in impl
/// discipline.
///
/// Used only as a generic bound (`P: Placement` on [`safe_extract`],
/// monomorphized), never as `dyn Placement`.
pub trait Placement {
    /// Destination for `entry` relative to the root, or `None` to skip it.
    fn place(&self, entry: &Path) -> Option<PathBuf>;
}

/// One extracted file's content digest and size.
//
// Only `fuz_release` reads `hash` (verifying each file against its signed
// manifest), and no production caller reads `size` — this crate's tests do.
// `fuzi` ignores the report's contents entirely: `fuzi verify` shipped as a
// *structural* check (presence + `package.json` version + platform assertion),
// not a per-file cryptographic one — per-file hashes are the job of the post-v0
// extracted-content manifest, which would be `size`'s first production reader.
#[derive(Debug, Clone)]
pub struct ExtractedFile {
    /// blake3 of the file's bytes, computed during the streaming write (free —
    /// the bytes are already in hand). `fuz_release` verifies these against its
    /// manifest; `fuzi` ignores them.
    pub hash: ContentHash,
    /// Decompressed byte length of the file.
    pub size: u64,
}

/// What [`safe_extract`] wrote.
#[derive(Debug, Clone, Default)]
pub struct ExtractReport {
    /// Each placed file, keyed by its destination path **relative to the root**.
    pub files: BTreeMap<PathBuf, ExtractedFile>,
    /// Total decompressed bytes written across all files. No production caller
    /// reads it yet; it is the report's whole-archive tally beside the
    /// per-file [`ExtractedFile::size`].
    pub total_bytes: u64,
}

/// Decompress and extract a `.tar.gz` from `reader` into `root`, applying all
/// guards and the caller's placement/limits/symlink policy.
///
/// `compressed_size` is the on-disk `.tar.gz` byte length (the caller knows it
/// from the download or a `stat`); it feeds the compression-ratio bomb check.
/// Returns an [`ExtractReport`] of what was written. Directory entries are
/// skipped; parent directories are created as needed, below `root` only.
///
/// `root` **must be an existing, caller-owned destination** (a fresh
/// directory); a missing `root` fails the first file with `NotFound`. This
/// function uses no `O_NOFOLLOW` and will follow a pre-existing symlink already
/// on disk under `root`; see the crate-level *Destination trust* section.
/// Intra-archive traversal is contained regardless.
///
/// # Gzip members and the end of the archive
///
/// The gzip layer decodes **every member** (`MultiGzDecoder`), as node's zlib
/// does: a tar stream split across concatenated members extracts whole, where
/// a single-member decoder would stop at the first member boundary and report
/// the entries before it as the whole archive. Bytes after the last member
/// that are not another gzip member fail the gzip layer — node fails there
/// too, unless they start with a zero byte, which it ignores as padding and
/// this does not (none observed in the npm caches probed).
///
/// The tar stream must end with its **end-of-archive marker**, two all-zero
/// blocks. `tar` ends iteration at the first zero block, but also, silently,
/// at a clean EOF on a block boundary — which is what an archive truncated
/// between two entries looks like — so the marker is checked here: no marker
/// is a truncated archive, and a lone zero block followed by data is refused
/// too (node-tar reads on past one, so the entries after it would install
/// under npm and not here). Whatever follows the marker is decompressed — the
/// budget charged, each member's CRC checked — and discarded, as node-tar
/// ignores it.
///
/// # Reader consumption
///
/// `reader` is consumed to EOF. This lets a caller tee `reader` into a hasher
/// and obtain a faithful **whole-file** digest in one pass; without it, a
/// tarball with bytes past the marker would hash to only the prefix the
/// tar/gzip layers pulled. `fuzi`'s content-addressed-store re-verify relies
/// on this.
///
/// # Errors
///
/// Returns [`ArchiveError`] on an empty input, a guard violation (invalid path,
/// null byte, oversized file/total/headers, compression bomb, setuid/setgid,
/// rejected entry type, escaping placement, a directory with a body, a PAX
/// `size` that disagrees with the header, or a header readers could parse
/// differently), bytes that do not parse — a tar or gzip format error, a
/// missing end-of-archive marker, bytes past the last gzip member that are not
/// one ([`ArchiveError::Malformed`]) — an OS error from `reader`
/// ([`ArchiveError::Read`]), or a filesystem failure ([`ArchiveError::Io`]),
/// `NotFound` included when `root` is missing or removed part-way.
pub fn safe_extract<R: Read, P: Placement>(
    reader: R,
    compressed_size: u64,
    root: &Path,
    limits: &ExtractLimits,
    placement: &P,
    policy: SymlinkPolicy,
) -> Result<ExtractReport, ArchiveError> {
    if compressed_size == 0 {
        return Err(ArchiveError::Empty);
    }

    let header_window = Cell::new(None);
    let captured = RefCell::new(Vec::new());
    let gz = flate2::read::MultiGzDecoder::new(reader);
    let mut archive = tar::Archive::new(BudgetReader {
        inner: gz,
        decompressed_size: 0,
        compressed_size,
        limits: *limits,
        header_window: &header_window,
        captured: &captured,
    });

    let mut report = ExtractReport::default();

    let mut entries = archive
        .entries()
        .map_err(|source| tar_error("reading archive entries", source))?;

    // Where the previous entry's padded body ends in the decompressed stream —
    // the start of the stream before the first entry. Everything `tar` reads to
    // get there is body (bounded by the per-file and total ceilings); what it
    // reads past it, to reach the next entry, is metadata.
    let mut body_end: u64 = 0;

    loop {
        // Arm the header window for exactly the iterator step (see the
        // crate-level *Decompression budget* section); disarm it before any of
        // the entry's own data is read. The window also captures what `tar`
        // reads past `body_end`, the extension headers the PAX check re-reads.
        captured.borrow_mut().clear();
        header_window.set(Some(HeaderWindow {
            start: body_end,
            limit: body_end.saturating_add(limits.max_header_size),
        }));
        let next = entries.next();
        header_window.set(None);
        let Some(entry_result) = next else {
            break;
        };
        let mut entry = entry_result.map_err(|source| tar_error("reading entry", source))?;

        // Before `body_end` moves: the extension headers between the previous
        // body and this entry's header are `captured[..]` up to that header.
        check_one_reading(&entry, &captured.borrow(), body_end)?;

        // `tar` positions the next header at the entry's data offset plus its
        // effective size (PAX override included) rounded up to a block, whether
        // or not the body is read here. A GNU sparse entry is the one exception:
        // its `size()` is the logical `real_size` a hostile header sets freely,
        // and its data position omits the extension blocks `tar` read, so this
        // `body_end` is wrong for it. It is safe only because the type guard
        // below refuses the entry before another step — keep any `continue`
        // (a placement skip included) after that guard.
        body_end = entry.raw_file_position().saturating_add(
            entry
                .size()
                .div_ceil(TAR_BLOCK_SIZE)
                .saturating_mul(TAR_BLOCK_SIZE),
        );

        // `EntryType` is `Copy`, so this releases the header borrow immediately —
        // leaving `entry` free for the later mutable `read`.
        let entry_type = entry.header().entry_type();

        // Directory entries are structural; skip them (dirs are created lazily
        // from each file's parent path). A regular entry whose name ends in `/`
        // is the pre-POSIX directory form. A directory that declares a body is
        // refused: node-tar reads that body as further entries (see *Directory
        // entries* in the crate docs).
        if entry_type.is_dir() || (entry_type.is_file() && entry.path_bytes().ends_with(b"/")) {
            if entry.size() != 0 {
                return Err(ArchiveError::DirectoryWithBody(
                    entry_path_lossy(&entry),
                    entry.size(),
                ));
            }
            continue;
        }

        let path = entry
            .path()
            .map_err(|source| tar_error("reading entry path", source))?
            .into_owned();

        // Symlinks/hardlinks ride the symlink policy; any other non-regular
        // entry (device, fifo, …) is never legitimate in a package tarball.
        if !entry_type.is_file() {
            return match policy {
                SymlinkPolicy::Reject => Err(ArchiveError::UnsupportedEntryType(path)),
            };
        }

        // `entry.size()`, not `header().size()`: a PAX `size` record overrides
        // a zero ustar size field, and only the entry carries the override.
        validate_entry_path(&path, entry.size(), entry.header(), limits)?;

        // Placement decides the destination (relative to root) or skips. A
        // skipped entry's body (fuzi skips files under a vendored
        // `node_modules`) is drained by `tar` when it advances, through the
        // budget reader, so a skip can't dodge the DoS guards; it lies before
        // `body_end`, so the header window doesn't count it.
        let Some(rel) = placement.place(&path) else {
            continue;
        };
        validate_placed_path(&rel)?;

        // Capture the owner-exec bit before the mutable read borrows `entry`.
        #[cfg(unix)]
        let exec = header_owner_exec(entry.header())?;

        let dest = root.join(&rel);
        // TODO (defense-in-depth): these writes follow pre-existing symlinks in
        // the destination tree (see the crate-level "Destination trust" note).
        // Today safety relies on the caller owning a fresh root (fuzi: staging-
        // swap). A hardened path would resolve each component with
        // openat2(RESOLVE_BENEATH)/O_NOFOLLOW so even a subverted root is safe.
        // The parents are created below `root` only, never `root` itself (see
        // "Destination trust"); `0o777` before the umask, as `create_dir_all`.
        if let Some(parent) = dest.parent() {
            create_dir_all_below(root, parent, 0o777)?;
        }

        let mut hasher = Hasher::new(HashAlgo::Blake3);
        let mut file = std::fs::File::create(&dest)?;
        let mut file_size: u64 = 0;

        #[expect(
            clippy::large_stack_arrays,
            reason = "a 64 KiB stack buffer is fine here"
        )]
        let mut buf = [0u8; EXTRACT_BUFFER_SIZE];
        loop {
            let n = entry
                .read(&mut buf)
                .map_err(|source| tar_error("reading entry data", source))?;
            if n == 0 {
                break;
            }
            file_size += n as u64;
            report.total_bytes += n as u64;

            hasher.update(&buf[..n]);
            file.write_all(&buf[..n])?;
        }

        // Set the mode explicitly (don't trust the tarball): preserve the
        // owner-exec bit, normalize the rest. Chmod the **open descriptor**
        // (`fchmod`), not the path: the fd names the exact inode this loop just
        // wrote, so the mode can't land on a different file if the path is
        // swapped between the write and the chmod — and it skips a second path
        // resolution per entry.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = if exec { 0o755 } else { 0o644 };
            file.set_permissions(std::fs::Permissions::from_mode(mode))?;
        }

        report.files.insert(
            rel,
            ExtractedFile {
                hash: hasher.finalize(),
                size: file_size,
            },
        );
    }

    // The end-of-archive marker (see *Gzip members and the end of the archive*
    // above). `tar` stopped either at a zero block or at a clean EOF; how far it
    // read past the last entry's padded body tells them apart — exactly one
    // block is a zero block (a non-zero one is a header, which yields an entry
    // or an error). `tar` reads only through the budget reader, so its count is
    // `tar`'s stream position.
    let mut budget = archive.into_inner();
    if budget.decompressed_size.checked_sub(body_end) != Some(TAR_BLOCK_SIZE) {
        return Err(end_of_archive_error(
            "the archive ends without its end-of-archive marker (truncated)",
        ));
    }
    let mut second_block = [0u8; 512];
    match budget.read_exact(&mut second_block) {
        Ok(()) if second_block.iter().all(|&b| b == 0) => {}
        Ok(()) => {
            return Err(end_of_archive_error(
                "a lone zero block is followed by more data, not the end-of-archive marker",
            ));
        }
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            return Err(end_of_archive_error(
                "the archive ends after one zero block of its two-block end-of-archive marker",
            ));
        }
        Err(source) => return Err(tar_error("reading the end-of-archive marker", source)),
    }

    // Decompress the rest to EOF and discard it: record padding (GNU tar pads
    // the archive to a 10 KiB record), or anything a later gzip member holds.
    // It passes the budget reader (total and ratio still charged; the header
    // window is disarmed) and the gzip layer, so every member's CRC is checked
    // and non-gzip trailing bytes fail. Running the decoder to its EOF runs
    // `reader` to EOF, so a caller hashing `reader` as it is consumed (fuzi's
    // CAS re-verify tees the raw file through a `HashingReader`) digests the
    // whole file, not the prefix the tar layer pulled.
    std::io::copy(&mut budget, &mut std::io::sink()).map_err(trailing_data_error)?;
    // The decoder stops only at `reader`'s EOF; draining the raw reader keeps
    // the whole-file contract from resting on that. Whatever fails here is the
    // reader's own error (no tar or gzip layer sits between), so it is a read
    // failure, not a filesystem one.
    let mut reader = budget.inner.into_inner();
    std::io::copy(&mut reader, &mut std::io::sink()).map_err(|source| ArchiveError::Read {
        context: "draining the reader past the gzip stream",
        source,
    })?;

    Ok(report)
}

/// Whether the tar header's owner-execute bit is set.
#[cfg(unix)]
fn header_owner_exec(header: &tar::Header) -> Result<bool, ArchiveError> {
    let mode = header
        .mode()
        .map_err(|source| tar_error("reading entry mode", source))?;
    Ok(mode & 0o100 != 0)
}
