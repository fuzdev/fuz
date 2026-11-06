//! [`ArchiveError`], its security classification, and the helpers that map
//! tar- and gzip-layer failures into it.

use std::io::Read;
use std::path::PathBuf;

use thiserror::Error;

/// Errors from hardened archive extraction.
#[derive(Debug, Error)]
pub enum ArchiveError {
    /// An entry path had a non-`Normal` component (absolute, `..`, `.`, prefix).
    #[error("invalid path in archive: {0}")]
    InvalidPath(PathBuf),
    /// A symlink/hardlink under
    /// [`SymlinkPolicy::Reject`](crate::SymlinkPolicy::Reject), or a
    /// device/fifo (never legitimate in a package tarball).
    #[error("unsupported entry type in archive: {0} (only regular files and directories allowed)")]
    UnsupportedEntryType(PathBuf),
    /// An entry path contained a null byte.
    #[error("null byte in path: {0}")]
    NullByte(PathBuf),
    /// An entry path exceeded
    /// [`ExtractLimits::max_path_length`](crate::ExtractLimits::max_path_length).
    #[error("path too long: {0}")]
    PathTooLong(PathBuf),
    /// A single file's declared size exceeded
    /// [`ExtractLimits::max_file_size`](crate::ExtractLimits::max_file_size).
    #[error("file too large: {0} ({1} bytes)")]
    FileTooLarge(PathBuf, u64),
    /// The decompressed stream exceeded
    /// [`ExtractLimits::max_total_size`](crate::ExtractLimits::max_total_size).
    #[error("total extraction size exceeded: {0} bytes")]
    TotalTooLarge(u64),
    /// The decompression ratio exceeded
    /// [`ExtractLimits::max_compression_ratio`](crate::ExtractLimits::max_compression_ratio).
    #[error("compression ratio exceeded: {0}x")]
    CompressionBomb(u64),
    /// The header blocks and extension bodies before an entry exceeded
    /// [`ExtractLimits::max_header_size`](crate::ExtractLimits::max_header_size),
    /// which this carries. Raised while `tar` reads them, so an oversized body
    /// is never buffered whole.
    #[error("entry headers exceeded {0} bytes")]
    HeaderTooLarge(u64),
    /// A file carried the setuid bit.
    #[error("setuid bit on file: {0}")]
    SetuidBit(PathBuf),
    /// A file carried the setgid bit.
    #[error("setgid bit on file: {0}")]
    SetgidBit(PathBuf),
    /// A [`Placement`](crate::Placement) returned a path that escapes the extraction root.
    #[error("placement escapes extraction root: {0}")]
    PlacementEscapesRoot(PathBuf),
    /// A directory entry (type `5`, or the pre-POSIX regular entry whose name
    /// ends in `/`) declared a body, of the size this carries. node-tar forces
    /// a directory's size to zero and reads the declared body as further
    /// entries, where `tar` skips it, so one archive would extract as two
    /// different trees (see *Directory entries* in the crate docs).
    #[error("directory entry declares a {1}-byte body: {0} (directories carry no data)")]
    DirectoryWithBody(PathBuf, u64),
    /// An entry's PAX `size` record disagreed with its non-zero ustar size
    /// field. Tar readers differ on which one wins (`tar` before 0.4.46 kept
    /// the header's, node-tar always takes the record's), so the two sizes
    /// would split the stream in different places.
    #[error(
        "PAX size record disagrees with the header size for {path}: header {header_size}, PAX {pax_size}"
    )]
    PaxSizeMismatch {
        /// The entry the record describes.
        path: PathBuf,
        /// The ustar header's size field.
        header_size: u64,
        /// The PAX `size` record's value.
        pax_size: u64,
    },
    /// An entry's PAX extended header is not one every tar reader parses the
    /// same way — a malformed or duplicate record, a record after an empty
    /// line, a non-UTF-8 body, a `size` that is not a plain decimal, or a
    /// `path` (`linkpath`) beside a GNU long name (long link), which `tar`
    /// takes over the record where node-tar takes whichever came last. `tar`
    /// reads a `size` only up to the first bad record and any record only up
    /// to an empty line, where node-tar skips either and reads on, so the
    /// records after it would apply under one reader and not the other.
    #[error("malformed PAX extended header for {0}: {1}")]
    MalformedPax(PathBuf, &'static str),
    /// An entry's header, or an extension header before it, is not one every
    /// tar reader decodes the same way: a numeric field node-tar refuses or
    /// reads otherwise, a name with bytes after its NUL terminator, a link
    /// target on a header other than a link, or an empty or non-UTF-8 path.
    /// node-tar skips a header it cannot decode and reads the entry's body as
    /// the headers that follow, where `tar` reads the entry, so one archive
    /// would extract as two different trees.
    #[error("malformed tar header for {0}: {1}")]
    MalformedHeader(PathBuf, &'static str),
    /// The archive's bytes do not parse: a tar header or field the tar layer
    /// refuses, a gzip stream the decoder refuses (bad header, corrupt deflate
    /// data, a CRC mismatch, a truncation), or a missing end-of-archive marker.
    #[error("malformed archive ({context}): {source}")]
    Malformed {
        /// What was being read when the error occurred.
        context: &'static str,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },
    /// The input was empty (zero compressed bytes).
    #[error("archive is empty")]
    Empty,
    /// A filesystem operation failed.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// Reading the archive failed at the operating-system level — the caller's
    /// reader returned an OS error (an `EIO` on the cached file, say), not bytes
    /// that fail to parse. Past the gzip stream, where no format layer remains,
    /// any error from the reader is this.
    #[error("reading the archive failed ({context}): {source}")]
    Read {
        /// What was being read when the error occurred.
        context: &'static str,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },
}

impl ArchiveError {
    /// Whether this error indicates malicious/malformed archive content (vs a
    /// plain I/O failure). Lets a consumer map a security violation to a
    /// data-error exit code and an I/O failure to an I/O exit code.
    ///
    /// Bytes that fail to parse ([`Malformed`](Self::Malformed)) are in the
    /// class: both callers check the archive's digest before (`fuz_release`)
    /// or while (`fuzi`) extracting it, so an archive that reaches a parse
    /// error is the one its signature or lockfile names, and re-reading it
    /// fails the same way.
    #[must_use]
    pub const fn is_security_violation(&self) -> bool {
        // Exhaustive on purpose: a new variant must be classified explicitly
        // rather than silently defaulting to "not a violation" (fail-open). The
        // compiler forces the decision when a guard is added.
        match self {
            Self::InvalidPath(_)
            | Self::UnsupportedEntryType(_)
            | Self::NullByte(_)
            | Self::PathTooLong(_)
            | Self::FileTooLarge(_, _)
            | Self::TotalTooLarge(_)
            | Self::CompressionBomb(_)
            | Self::HeaderTooLarge(_)
            | Self::SetuidBit(_)
            | Self::SetgidBit(_)
            | Self::PlacementEscapesRoot(_)
            | Self::DirectoryWithBody(_, _)
            | Self::PaxSizeMismatch { .. }
            | Self::MalformedPax(_, _)
            | Self::MalformedHeader(_, _)
            | Self::Malformed { .. } => true,
            Self::Empty | Self::Io(_) | Self::Read { .. } => false,
        }
    }
}

/// An entry's path for an error message: its full (long-name or PAX) path
/// bytes, lossily decoded — available even where `Entry::path` would fail.
pub fn entry_path_lossy<R: Read>(entry: &tar::Entry<'_, R>) -> PathBuf {
    PathBuf::from(String::from_utf8_lossy(&entry.path_bytes()).into_owned())
}

/// A missing or malformed end-of-archive marker, as an
/// [`ArchiveError::Malformed`]: the same class as the truncations `tar` itself
/// reports (a body or header cut short), which this is the block-boundary case
/// of.
pub fn end_of_archive_error(detail: &'static str) -> ArchiveError {
    ArchiveError::Malformed {
        context: "reading the end-of-archive marker",
        source: std::io::Error::new(std::io::ErrorKind::UnexpectedEof, detail),
    }
}

/// Map a failure decoding the data past the end-of-archive marker: what the
/// gzip layer refuses there is bytes after the tar stream that are not a
/// well-formed gzip member, which its own message ("unexpected end of file",
/// "invalid gzip header") doesn't say.
pub fn trailing_data_error(source: std::io::Error) -> ArchiveError {
    const CONTEXT: &str = "past the end-of-archive marker";
    match tar_error(CONTEXT, source) {
        ArchiveError::Malformed { source, .. } => ArchiveError::Malformed {
            context: CONTEXT,
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "the bytes after the tar stream are not a complete gzip member \
                     (trailing garbage, or a corrupt or truncated member): {source}"
                ),
            ),
        },
        other => other,
    }
}

/// Map an error from the tar/gzip layer to an [`ArchiveError`]: a budget
/// violation raised by [`BudgetReader`](crate::budget::BudgetReader) comes
/// back as itself (so it keeps its security classification); an
/// operating-system error from the caller's reader (one with an `errno`) as
/// [`ArchiveError::Read`]; anything else — the tar layer's format errors, the
/// gzip decoder's `InvalidData` / `InvalidInput`, an `UnexpectedEof` at a
/// truncation — as [`ArchiveError::Malformed`].
///
/// The split rests on `raw_os_error`: both layers pass the reader's own errors
/// through unchanged and raise their format errors without one. A caller whose
/// reader fails with a non-OS error (a custom `io::Error`) gets
/// [`ArchiveError::Malformed`] for it.
pub fn tar_error(context: &'static str, source: std::io::Error) -> ArchiveError {
    match source.downcast::<ArchiveError>() {
        Ok(violation) => violation,
        Err(source) if source.raw_os_error().is_some() => ArchiveError::Read { context, source },
        Err(source) => ArchiveError::Malformed { context, source },
    }
}
