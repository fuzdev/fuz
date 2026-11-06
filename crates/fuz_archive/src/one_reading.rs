//! The node-tar parity checks: re-read the extension headers and entry header
//! `tar` consumed, and refuse any that the two readers could split differently
//! (see the crate-level *One reading of the stream* section).

use std::collections::BTreeSet;
use std::io::Read;

use crate::error::{ArchiveError, entry_path_lossy, tar_error};

/// Refuse an entry the tar readers could read differently — an extension or
/// entry header node-tar would decode otherwise or skip, two extensions that
/// both name it, or a PAX `size` record readable two ways — or whose PAX `size`
/// record disagrees with a non-zero ustar size field (see *One reading of the
/// stream* in the crate docs).
///
/// `captured` holds the decompressed bytes from `body_end` (the previous
/// entry's padded body end) through this entry's header: the extension
/// headers `tar` consumed before yielding it. `tar` does not expose them, so
/// they are found there again ([`scan_extensions`]) and the PAX body parsed
/// strictly ([`pax_records`]).
///
/// `tar` 0.4.46 and node-tar both let a well-formed PAX `size` override the
/// header's; the agreement check is defense in depth over that, and holds the
/// stream to one reading whatever a reader's precedence rule.
pub fn check_one_reading<R: Read>(
    entry: &tar::Entry<'_, R>,
    captured: &[u8],
    body_end: u64,
) -> Result<(), ArchiveError> {
    let malformed_header = |detail| ArchiveError::MalformedHeader(entry_path_lossy(entry), detail);
    let malformed_pax = |detail| ArchiveError::MalformedPax(entry_path_lossy(entry), detail);
    let extensions_len = entry.raw_header_position().saturating_sub(body_end);
    let extensions = usize::try_from(extensions_len)
        .ok()
        .and_then(|len| captured.get(..len))
        .ok_or_else(|| malformed_pax(UNREADABLE_EXTENSIONS))?;
    let scan = scan_extensions(extensions).map_err(|split| match split {
        Split::Header(detail) => malformed_header(detail),
        Split::Pax(detail) => malformed_pax(detail),
    })?;
    check_header_block(entry.header().as_bytes()).map_err(malformed_header)?;
    let records = scan
        .pax
        .map(pax_records)
        .transpose()
        .map_err(malformed_pax)?
        .unwrap_or_default();
    // `tar` reads the path from a long name, else a PAX `path`, else the ustar
    // fields; node-tar from the same place. It skips a header whose path is
    // empty, reading the body as headers, and decodes a path as UTF-8.
    let path = entry.path_bytes();
    if path.is_empty() {
        return Err(malformed_header("the entry's path is empty"));
    }
    if std::str::from_utf8(&path).is_err() {
        return Err(malformed_header("the entry's path is not UTF-8"));
    }
    // `tar` takes a GNU long name over a PAX `path` (and a long link over a
    // `linkpath`); node-tar takes whichever came last in the stream.
    if scan.long_name && records.path {
        return Err(malformed_pax(
            "a GNU long name and a PAX path both name the entry",
        ));
    }
    if scan.long_link && records.linkpath {
        return Err(malformed_pax(
            "a GNU long link and a PAX linkpath both name the link target",
        ));
    }
    let Some(pax_size) = records.size else {
        return Ok(());
    };
    let header_size = entry
        .header()
        .entry_size()
        .map_err(|source| tar_error("reading entry size", source))?;
    if header_size != 0 && header_size != pax_size {
        return Err(ArchiveError::PaxSizeMismatch {
            path: entry_path_lossy(entry),
            header_size,
            pax_size,
        });
    }
    Ok(())
}

/// The re-read extension headers do not match what `tar` parsed.
pub const UNREADABLE_EXTENSIONS: &str = "its extension headers could not be re-read";

/// Why [`scan_extensions`] refused: a header block, or the PAX body.
#[derive(Debug, PartialEq, Eq)]
pub enum Split {
    /// An extension header block node-tar would read differently
    /// ([`ArchiveError::MalformedHeader`]).
    Header(&'static str),
    /// The extensions as a whole ([`ArchiveError::MalformedPax`]).
    Pax(&'static str),
}

/// The extension headers before one entry, as [`scan_extensions`] finds them.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Extensions<'a> {
    /// The PAX extended header's (`x`) body, if there is one.
    pub pax: Option<&'a [u8]>,
    /// Whether a GNU long-name (`L`) header names the entry.
    pub long_name: bool,
    /// Whether a GNU long-link (`K`) header names its link target.
    pub long_link: bool,
}

/// The extension headers among `extensions`, the header blocks and padded
/// bodies `tar` read before an entry's own header (PAX `x`, GNU long-name `L`
/// and long-link `K`, in any order; `tar` refuses two of a kind), each held to
/// [`check_header_block`].
///
/// `tar` has already parsed each of these headers, so a block that does not
/// re-read means the re-read disagrees with it — refused rather than trusted.
pub fn scan_extensions(extensions: &[u8]) -> Result<Extensions<'_>, Split> {
    let mut rest = extensions;
    let mut scan = Extensions::default();
    while let Some((block, after)) = rest.split_first_chunk::<512>() {
        check_header_block(block).map_err(Split::Header)?;
        if block[0] == 0 && !(is_posix_ustar(block) && block[345] != 0) {
            return Err(Split::Header("an extension header's name is empty"));
        }
        let header = tar::Header::from_byte_slice(block);
        let size = header
            .entry_size()
            .ok()
            .and_then(|size| usize::try_from(size).ok())
            .ok_or(Split::Pax(UNREADABLE_EXTENSIONS))?;
        let padded = size
            .checked_next_multiple_of(512)
            .ok_or(Split::Pax(UNREADABLE_EXTENSIONS))?;
        if after.len() < padded {
            return Err(Split::Pax(UNREADABLE_EXTENSIONS));
        }
        let entry_type = header.entry_type();
        if entry_type.is_pax_local_extensions() {
            scan.pax = Some(&after[..size]);
        } else if entry_type.is_gnu_longname() {
            scan.long_name = true;
        } else if entry_type.is_gnu_longlink() {
            scan.long_link = true;
        }
        rest = &after[padded..];
    }
    if rest.is_empty() {
        Ok(scan)
    } else {
        Err(Split::Pax(UNREADABLE_EXTENSIONS))
    }
}

/// Whether a header block carries the POSIX ustar magic and version, the
/// form whose prefix and device fields both readers read.
fn is_posix_ustar(block: &[u8; 512]) -> bool {
    &block[257..265] == b"ustar\x0000"
}

/// The largest integer node-tar decodes from a base-256 field (JS's
/// `Number.MAX_SAFE_INTEGER`).
const NODE_TAR_MAX_NUMBER: u128 = (1 << 53) - 1;

/// Refuse a header block node-tar would decode differently from `tar`, or
/// skip — reading the entry's body as the headers that follow.
///
/// node-tar decodes every field of every header up front and skips one it
/// cannot (a base-256 number it does not take, a non-link carrying a link
/// target); `tar` decodes only the fields it uses, and only when asked. Each
/// field is held to the form both decode alike:
///
/// - **Numbers** (mode, uid, gid, size, mtime; the device numbers, and the
///   access and change times when present, of a POSIX ustar header): base-256
///   only behind `0x80` and below 2^53 — node-tar reads a `0xff` lead as a
///   negative number and refuses any other lead byte or anything larger, where
///   `tar` reads the low 8 bytes whatever leads them — else ASCII up to the
///   first NUL, where `tar` and node-tar trim different non-ASCII whitespace.
///   The checksum too: ASCII, with a NUL or space as its last byte, since
///   node-tar reads it from a 12-byte window and digits that run to the
///   field's end continue into the type flag.
/// - **Names** (name, link name, and a POSIX ustar header's prefix): NUL after
///   the first NUL. `tar` ends a name at its first NUL; node-tar deletes only
///   from there to the next line break, keeping what follows.
/// - **A link name on a header other than a link or a PAX header**: node-tar
///   refuses it ("linkpath forbidden"), where `tar` ignores it.
fn check_header_block(block: &[u8; 512]) -> Result<(), &'static str> {
    // node-tar reads the checksum from 12 bytes, through the type flag: digits
    // that run to the field's end continue into it.
    if !block[148..156].is_ascii() || !matches!(block[155], 0 | b' ') {
        return Err("the checksum field is not ASCII ending in a NUL or space");
    }
    let posix = is_posix_ustar(block);
    let mut numbers: Vec<&[u8]> = vec![
        &block[100..108],
        &block[108..116],
        &block[116..124],
        &block[124..136],
        &block[136..148],
    ];
    let mut names: Vec<&[u8]> = vec![&block[..100], &block[157..257]];
    if posix {
        numbers.extend([&block[329..337], &block[337..345]]);
        // node-tar reads a 155-byte prefix when its last byte is set, else a
        // 130-byte prefix followed by the access and change times.
        if block[475] == 0 {
            numbers.extend([&block[476..488], &block[488..500]]);
            names.push(&block[345..475]);
        } else {
            names.push(&block[345..500]);
        }
    }
    for field in numbers {
        if field[0] & 0x80 != 0 {
            if field[0] != 0x80 {
                return Err("a base-256 number is not a positive one both readers decode alike");
            }
            let mut value: u128 = 0;
            for &byte in &field[1..] {
                value = (value << 8) | u128::from(byte);
            }
            if value > NODE_TAR_MAX_NUMBER {
                return Err("a base-256 number is past node-tar's range");
            }
        } else if !field.iter().take_while(|&&b| b != 0).all(u8::is_ascii) {
            return Err("a numeric field is not ASCII");
        }
    }
    for field in names {
        if let Some(nul) = field.iter().position(|&b| b == 0)
            && field[nul..].iter().any(|&b| b != 0)
        {
            return Err("a name field holds bytes after its NUL terminator");
        }
    }
    if !matches!(block[156], b'1' | b'2' | b'x' | b'g') && block[157] != 0 {
        return Err("a header other than a link names a link target");
    }
    Ok(())
}

/// The records of a PAX extended header body that decide where an entry lies
/// and what it is named, as [`pax_records`] reads them.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct PaxRecords {
    /// The `size` record's value, if there is one.
    pub size: Option<u64>,
    /// Whether a `path` record names the entry.
    pub path: bool,
    /// Whether a `linkpath` record names its link target.
    pub linkpath: bool,
}

/// The `size`, `path` and `linkpath` records of the PAX extended header body
/// `pax` — parsed so strictly that `tar` and node-tar can only read the same
/// records.
///
/// Each record is `<len> <key>=<value>\n`, `len` counting the whole record.
/// The readers split on newlines alike but part on what follows a bad line:
/// `tar` stops its `size` lookup at the first malformed record, and every
/// lookup at an empty line, where node-tar skips either and reads on; node-tar
/// decodes the body as UTF-8 first (so a non-UTF-8 byte changes the length it
/// checks), re-slices a record by its *normalized* length (so `012 size=…`
/// yields a different key), lets a repeated key's last record win where `tar`
/// takes the first, and takes a `size` that is not all digits as a string.
/// Each of those is refused here, for every record: any of them would let a
/// later record (a `size`, a `path`) apply under one reader only. Linear in
/// the body's length.
pub fn pax_records(pax: &[u8]) -> Result<PaxRecords, &'static str> {
    let text = std::str::from_utf8(pax).map_err(|_| "the record body is not UTF-8")?;
    let mut parsed = PaxRecords::default();
    let Some(records) = text.strip_suffix('\n') else {
        return if text.is_empty() {
            Ok(parsed)
        } else {
            Err("the last record is not newline-terminated")
        };
    };
    let mut keys = BTreeSet::new();
    for record in records.split('\n') {
        let (len, key_value) = record
            .split_once(' ')
            .ok_or("a record has no length prefix")?;
        let canonical = !len.is_empty()
            && len.bytes().all(|b| b.is_ascii_digit())
            && (len == "0" || !len.starts_with('0'));
        if !canonical || len.parse::<usize>().ok() != Some(record.len() + 1) {
            return Err("a record's length prefix does not match its length");
        }
        let (key, value) = key_value.split_once('=').ok_or("a record has no `=`")?;
        if key.is_empty() {
            return Err("a record has an empty key");
        }
        if !keys.insert(key) {
            return Err("a key is repeated");
        }
        match key {
            "size" => {
                if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                    return Err("the `size` record is not a decimal number");
                }
                parsed.size = Some(
                    value
                        .parse::<u64>()
                        .map_err(|_| "the `size` record is out of range")?,
                );
            }
            "path" => parsed.path = true,
            "linkpath" => parsed.linkpath = true,
            _ => {}
        }
    }
    Ok(parsed)
}
