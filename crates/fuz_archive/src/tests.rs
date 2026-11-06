//! Tests for `safe_extract`: end to end over built archives, and directly on
//! the budget reader and the header and PAX parsers.

use super::*;
use crate::budget::charge;
use crate::one_reading::{
    Extensions, PaxRecords, Split, UNREADABLE_EXTENSIONS, pax_records, scan_extensions,
};

/// Generous limits for tests that aren't exercising a specific cap.
fn loose_limits() -> ExtractLimits {
    ExtractLimits {
        max_file_size: 1 << 30,
        max_total_size: 1 << 30,
        max_compression_ratio: 100,
        max_header_size: 1 << 30,
        max_path_length: 4096,
    }
}

/// Identity placement — keep the entry path verbatim (nested tree).
struct Identity;
impl Placement for Identity {
    fn place(&self, entry: &Path) -> Option<PathBuf> {
        Some(entry.to_path_buf())
    }
}

/// Flatten placement — keep only the basename.
struct Basename;
impl Placement for Basename {
    fn place(&self, entry: &Path) -> Option<PathBuf> {
        entry.file_name().map(PathBuf::from)
    }
}

/// Hostile placement — always escapes the root.
struct Escaping;
impl Placement for Escaping {
    fn place(&self, _entry: &Path) -> Option<PathBuf> {
        Some(PathBuf::from("../escape"))
    }
}

/// Build a gzipped tar from `(path, mode, type, data)` entries via the `tar`
/// builder. Use [`gz_raw_tar`] for adversarial paths the builder rejects.
fn gz_tar(entries: &[(&str, u32, tar::EntryType, &[u8])]) -> Vec<u8> {
    let mut tar_data = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_data);
        for (name, mode, ty, data) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_path(name).expect("set path");
            header.set_entry_type(*ty);
            header.set_size(data.len() as u64);
            header.set_mode(*mode);
            header.set_cksum();
            builder.append(&header, &data[..]).expect("append");
        }
        builder.finish().expect("finish tar");
    }
    gz(&tar_data)
}

/// gzip arbitrary (already-tarred) bytes.
fn gz(tar_data: &[u8]) -> Vec<u8> {
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::Write as _;
    let mut out = Vec::new();
    {
        let mut enc = GzEncoder::new(&mut out, Compression::default());
        enc.write_all(tar_data).expect("gz write");
        enc.finish().expect("gz finish");
    }
    out
}

/// Hand-roll a single ustar regular-file entry with an arbitrary raw name —
/// used for adversarial paths (`..`, null byte) the `tar` builder refuses to
/// write but a reader must still defend against.
fn gz_raw_tar(name: &[u8], data: &[u8]) -> Vec<u8> {
    let mut header = [0u8; 512];
    let n = name.len().min(100);
    header[..n].copy_from_slice(&name[..n]);
    // mode 0644, uid/gid 0, size, mtime 0.
    header[100..108].copy_from_slice(b"0000644\0");
    header[108..116].copy_from_slice(b"0000000\0");
    header[116..124].copy_from_slice(b"0000000\0");
    let size = format!("{:011o}\0", data.len());
    header[124..136].copy_from_slice(size.as_bytes());
    header[136..148].copy_from_slice(b"00000000000\0");
    header[156] = b'0'; // regular file
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    // checksum: sum of all bytes with the chksum field as spaces.
    header[148..156].copy_from_slice(b"        ");
    let sum: u32 = header.iter().map(|&b| u32::from(b)).sum();
    let chk = format!("{sum:06o}\0 ");
    header[148..156].copy_from_slice(chk.as_bytes());

    let mut tar_data = Vec::new();
    tar_data.extend_from_slice(&header);
    tar_data.extend_from_slice(data);
    let pad = (512 - data.len() % 512) % 512;
    tar_data.extend(std::iter::repeat_n(0u8, pad));
    tar_data.extend(std::iter::repeat_n(0u8, 1024)); // two zero end blocks
    gz(&tar_data)
}

#[cfg(unix)]
fn mode_of(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

fn reg<'a>(name: &'a str, mode: u32, data: &'a [u8]) -> (&'a str, u32, tar::EntryType, &'a [u8]) {
    (name, mode, tar::EntryType::Regular, data)
}

/// Extract whole `gz` bytes into `dir` under the default test shape:
/// [`loose_limits`], identity placement, reject-symlinks.
///
/// The cases that vary one of those — a custom limit, `Basename` /
/// `Escaping` placement, or a non-slice reader — call [`safe_extract`]
/// directly, so the varied argument stays visible at the call site.
fn extract_loose(gz: &[u8], dir: &Path) -> Result<ExtractReport, ArchiveError> {
    safe_extract(
        gz,
        gz.len() as u64,
        dir,
        &loose_limits(),
        &Identity,
        SymlinkPolicy::Reject,
    )
}

/// A reader that hands out **at most one byte per `read`** and counts how
/// many bytes it has yielded. The throttle defeats the gzip decoder's
/// internal read-ahead buffer (which would otherwise slurp a small whole
/// input in one fill and mask whether `safe_extract` truly drains to EOF),
/// so `bytes_read` is a faithful witness of total consumption.
struct ThrottledCounter<'a> {
    data: &'a [u8],
    bytes_read: usize,
}
impl Read for ThrottledCounter<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() || self.bytes_read >= self.data.len() {
            return Ok(0);
        }
        buf[0] = self.data[self.bytes_read];
        self.bytes_read += 1;
        Ok(1)
    }
}

#[test]
fn consumes_reader_to_eof_past_the_end_of_archive() {
    // A tee-hashing caller (fuzi's CAS re-verify) relies on `safe_extract`
    // pulling *every* byte of `reader` through it, not just the prefix the
    // tar layer needs. Otherwise bytes past the end-of-archive marker — a
    // second concatenated gzip member here — escape the tee and the digest
    // no longer matches the whole-file integrity key the cache committed
    // against.
    let dir = tempfile::tempdir().unwrap();
    let mut full = gz_tar(&[reg("package/index.js", 0o644, b"export {}")]);
    // A complete second member *after* the first's marker: decoded and
    // consumed (so a tee hashes it), never extracted — node-tar stops at
    // the marker too.
    full.extend_from_slice(&gz_tar(&[reg("package/UNREACHED", 0o644, b"x")]));

    let mut reader = ThrottledCounter {
        data: &full,
        bytes_read: 0,
    };
    let report = safe_extract(
        &mut reader,
        full.len() as u64,
        dir.path(),
        &loose_limits(),
        &Identity,
        SymlinkPolicy::Reject,
    )
    .unwrap();

    assert_eq!(
        reader.bytes_read,
        full.len(),
        "safe_extract must drain `reader` to EOF so a tee hash covers the whole file"
    );
    assert!(dir.path().join("package/index.js").is_file());
    assert!(!dir.path().join("package/UNREACHED").exists());
    assert_eq!(report.files.len(), 1);
}

/// The raw (ungzipped) tar of `entries`, without the end-of-archive marker
/// `finish` writes.
fn tar_without_marker(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    for (name, data) in entries {
        let mut header = tar::Header::new_gnu();
        header.set_path(name).unwrap();
        header.set_entry_type(tar::EntryType::Regular);
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        out.extend_from_slice(header.as_bytes());
        out.extend_from_slice(data);
        out.resize(out.len().next_multiple_of(512), 0);
    }
    out
}

/// The end-of-archive error's detail, or a panic naming what came back.
fn end_of_archive_detail(result: Result<ExtractReport, ArchiveError>) -> String {
    match result {
        Err(ArchiveError::Malformed {
            context: "reading the end-of-archive marker",
            source,
        }) => source.to_string(),
        other => panic!("expected an end-of-archive refusal, got {other:?}"),
    }
}

#[test]
fn a_tar_split_across_gzip_members_extracts_whole() {
    // npm's tarballs are single-member, but node's zlib decodes every
    // member, so a tar stream split across two concatenated members
    // installs whole under npm. A single-member decoder stopped at the
    // boundary — on an entry boundary, which `tar` reads as a clean end —
    // and reported the first member's entries as the whole archive.
    let first = tar_without_marker(&[("package/a.js", b"a")]);
    let mut second = tar_without_marker(&[("package/b.js", b"b")]);
    second.extend_from_slice(&[0u8; 1024]);
    let mut full = gz(&first);
    full.extend_from_slice(&gz(&second));

    let dir = tempfile::tempdir().unwrap();
    let report = extract_loose(&full, dir.path()).unwrap();
    assert!(dir.path().join("package/a.js").is_file());
    assert!(dir.path().join("package/b.js").is_file());
    assert_eq!(report.files.len(), 2);
}

#[test]
fn a_tar_without_its_end_of_archive_marker_is_refused() {
    // Cut on an entry boundary: `tar` sees a clean EOF where the next
    // header would be and ends iteration as if the archive were complete.
    let truncated = gz(&tar_without_marker(&[("package/a.js", b"a")]));
    let dir = tempfile::tempdir().unwrap();
    let detail = end_of_archive_detail(extract_loose(&truncated, dir.path()));
    assert!(detail.contains("truncated"), "{detail}");
    // An empty tar stream is the same truncation, at offset 0.
    let detail = end_of_archive_detail(extract_loose(&gz(&[]), dir.path()));
    assert!(detail.contains("truncated"), "{detail}");
}

#[test]
fn a_tar_with_one_zero_block_is_refused() {
    let mut tar_data = tar_without_marker(&[("package/a.js", b"a")]);
    tar_data.extend_from_slice(&[0u8; 512]);
    let dir = tempfile::tempdir().unwrap();
    let detail = end_of_archive_detail(extract_loose(&gz(&tar_data), dir.path()));
    assert!(detail.contains("one zero block"), "{detail}");
}

#[test]
fn data_after_a_lone_zero_block_is_refused() {
    // `tar` stops at the first zero block; node-tar reads on past a lone
    // one and would install `b.js`. Refused rather than installing a
    // different tree than npm.
    let mut tar_data = tar_without_marker(&[("package/a.js", b"a")]);
    tar_data.extend_from_slice(&[0u8; 512]);
    tar_data.extend_from_slice(&tar_without_marker(&[("package/b.js", b"b")]));
    tar_data.extend_from_slice(&[0u8; 1024]);
    let dir = tempfile::tempdir().unwrap();
    let detail = end_of_archive_detail(extract_loose(&gz(&tar_data), dir.path()));
    assert!(detail.contains("lone zero block"), "{detail}");
}

#[test]
fn record_padding_past_the_marker_is_accepted() {
    // GNU tar pads the archive to a 10 KiB record: zero blocks past the
    // two-block marker are ordinary.
    let mut tar_data = tar_without_marker(&[("package/a.js", b"a")]);
    tar_data.resize(10 * 1024, 0);
    let dir = tempfile::tempdir().unwrap();
    let report = extract_loose(&gz(&tar_data), dir.path()).unwrap();
    assert_eq!(report.files.len(), 1);
}

#[test]
fn non_gzip_bytes_after_the_last_member_are_refused() {
    // node's zlib fails on them too ("incorrect header check"). npm's
    // registry tarballs carry none.
    let mut full = gz_tar(&[reg("package/a.js", 0o644, b"a")]);
    full.extend_from_slice(b"fuzi-trailing-bytes");
    let dir = tempfile::tempdir().unwrap();
    let err = extract_loose(&full, dir.path()).unwrap_err();
    assert!(
        matches!(
            err,
            ArchiveError::Malformed {
                context: "past the end-of-archive marker",
                ..
            }
        ),
        "{err:?}"
    );
    assert!(err.is_security_violation());
    // The message says what the bytes are, not only the decoder's verdict.
    let message = err.to_string();
    assert!(
        message.contains("the bytes after the tar stream are not a complete gzip member"),
        "{message}"
    );
}

#[test]
fn a_corrupt_member_after_the_marker_is_refused() {
    // Everything past the marker is still decoded, so a later member's CRC
    // is checked rather than skipped.
    let mut full = gz_tar(&[reg("package/a.js", 0o644, b"a")]);
    let mut second = gz(b"padding");
    let crc_at = second.len() - 8;
    second[crc_at] ^= 0xff;
    full.extend_from_slice(&second);
    let dir = tempfile::tempdir().unwrap();
    assert!(matches!(
        extract_loose(&full, dir.path()),
        Err(ArchiveError::Malformed {
            context: "past the end-of-archive marker",
            ..
        })
    ));
}

#[test]
fn empty_input_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let err = extract_loose(&[], dir.path()).unwrap_err();
    assert!(matches!(err, ArchiveError::Empty));
}

/// The extractor never creates its root: a missing one fails the first file,
/// at the top level and nested alike, and leaves nothing behind.
#[test]
fn a_missing_root_fails_and_creates_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("gone");
    for entry in ["package.json", "package/lib/deep/index.js"] {
        let gz = gz_tar(&[reg(entry, 0o644, b"{}")]);
        let err = extract_loose(&gz, &root).unwrap_err();
        assert!(
            matches!(&err, ArchiveError::Io(e) if e.kind() == std::io::ErrorKind::NotFound),
            "{entry}: {err:?}"
        );
        assert!(!root.exists(), "{entry}: the root was created");
    }
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
}

/// Identity placement that removes the extraction root when it is asked to
/// place `trigger` — a removal racing the extraction, made deterministic.
struct RemovesRootAt<'a> {
    root: &'a Path,
    trigger: &'a str,
}
impl Placement for RemovesRootAt<'_> {
    fn place(&self, entry: &Path) -> Option<PathBuf> {
        if entry == Path::new(self.trigger) {
            std::fs::remove_dir_all(self.root).unwrap();
        }
        Some(entry.to_path_buf())
    }
}

/// A root removed part-way stays removed: the next entry's parent directories
/// are not re-created above the (now missing) root, so the extraction fails
/// rather than putting the tree back.
#[test]
fn a_root_removed_mid_extraction_stays_removed() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("root");
    std::fs::create_dir(&root).unwrap();
    let gz = gz_tar(&[
        reg("package/package.json", 0o644, b"{}"),
        reg("package/lib/deep/index.js", 0o644, b"export {}"),
    ]);
    let placement = RemovesRootAt {
        root: &root,
        trigger: "package/lib/deep/index.js",
    };
    let err = safe_extract(
        gz.as_slice(),
        gz.len() as u64,
        &root,
        &loose_limits(),
        &placement,
        SymlinkPolicy::Reject,
    )
    .unwrap_err();
    assert!(
        matches!(&err, ArchiveError::Io(e) if e.kind() == std::io::ErrorKind::NotFound),
        "{err:?}"
    );
    assert!(!root.exists(), "the removed root was re-created");
}

#[test]
fn nested_tree_is_preserved() {
    let dir = tempfile::tempdir().unwrap();
    let gz = gz_tar(&[
        reg("package/package.json", 0o644, b"{}"),
        reg("package/lib/deep/index.js", 0o644, b"export {}"),
    ]);
    let report = extract_loose(&gz, dir.path()).unwrap();
    assert!(dir.path().join("package/package.json").is_file());
    assert!(dir.path().join("package/lib/deep/index.js").is_file());
    assert_eq!(report.files.len(), 2);
    assert!(
        report
            .files
            .contains_key(Path::new("package/lib/deep/index.js"))
    );
}

#[test]
fn gnu_long_name_path_extracts() {
    // Real npm trees top out well under tar's 100-char ustar name field, so
    // the fuz projects' own lockfiles never exercise GNU long-name (`L`)
    // extended headers. This pins that the reader merges an `L` entry into
    // its real path rather than rejecting a legitimate long path — a wrong
    // assumption here would *reject* a valid package (loud fail), not breach
    // anything. `Builder::append_data` with a >100-char path on a gnu header
    // emits the `L` entry; the `tar` reader must hand `safe_extract` the full
    // path.
    let dir = tempfile::tempdir().unwrap();
    let long = format!("package/{}.js", "x".repeat(150)); // ~161-char entry path
    let mut tar_data = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_data);
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Regular);
        header.set_size(2);
        header.set_mode(0o644);
        builder
            .append_data(&mut header, &long, &b"{}"[..])
            .expect("append long-name entry");
        builder.finish().expect("finish tar");
    }
    let gz = gz(&tar_data);
    // Under the tight header window: the `L` body is metadata it admits.
    let report = safe_extract(
        &gz[..],
        gz.len() as u64,
        dir.path(),
        &header_limits(),
        &Identity,
        SymlinkPolicy::Reject,
    )
    .unwrap();
    assert!(
        dir.path().join(&long).is_file(),
        "long-name entry should extract to its full path"
    );
    assert!(report.files.contains_key(Path::new(&long)));
}

/// A PAX extension (`x`) entry whose `path` record is `path`.
fn pax_path_entry(path: &str) -> (tar::Header, Vec<u8>) {
    let tail = format!(" path={path}\n");
    // The decimal length prefix counts its own digits.
    let mut len = tail.len() + 1;
    while len.to_string().len() + tail.len() != len {
        len += 1;
    }
    let body = format!("{len}{tail}").into_bytes();
    (
        header("PaxHeader", tar::EntryType::XHeader, body.len() as u64),
        body,
    )
}

/// A GNU long-name (`L`) entry carrying `path`.
fn gnu_long_name_entry(path: &str) -> (tar::Header, Vec<u8>) {
    let mut body = path.as_bytes().to_vec();
    body.push(0);
    let mut header = tar::Header::new_gnu();
    header.as_old_mut().name[..13].copy_from_slice(b"././@LongLink");
    header.set_entry_type(tar::EntryType::GNULongName);
    header.set_size(body.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    (header, body)
}

#[test]
fn zip_slip_via_pax_path_and_gnu_long_name_is_rejected() {
    // The ustar name is benign; the extension `tar` merges over it is not.
    // The path guard reads the merged path, so neither form escapes.
    for evil in ["../evil.js", "package/../../evil.js", "/tmp/evil.js"] {
        for extension in [pax_path_entry(evil), gnu_long_name_entry(evil)] {
            let outer = tempfile::tempdir().unwrap();
            let dir = outer.path().join("root");
            std::fs::create_dir(&dir).unwrap();
            let gz_data = gz(&raw_tar(vec![
                extension,
                (
                    header("package/benign.js", tar::EntryType::Regular, 1),
                    b"x".to_vec(),
                ),
            ]));
            match extract_loose(&gz_data, &dir) {
                Err(ArchiveError::InvalidPath(path)) => assert_eq!(path, Path::new(evil)),
                other => panic!("{evil}: expected InvalidPath, got {other:?}"),
            }
            assert!(!outer.path().join("evil.js").exists());
            assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0, "{evil}");
        }
    }
}

#[test]
fn directory_entries_are_skipped_not_rejected() {
    let dir = tempfile::tempdir().unwrap();
    // An explicit directory entry alongside files (as real npm tarballs ship).
    let gz = gz_tar(&[
        ("package/lib", 0o755, tar::EntryType::Directory, &[][..]),
        reg("package/lib/a.js", 0o644, b"a"),
        reg("package/index.js", 0o644, b"i"),
    ]);
    let report = extract_loose(&gz, dir.path()).unwrap();
    // Two files extracted; the directory entry contributed nothing.
    assert_eq!(report.files.len(), 2);
    assert!(dir.path().join("package/lib/a.js").is_file());
}

#[cfg(unix)]
#[test]
fn old_format_directory_entries_are_directories() {
    // A regular entry named `…/` is a pre-POSIX directory. Written as a
    // file, `package/lib` would be a file and `package/lib/a.js` would fail
    // to create beneath it. Both the old `\0` type and `0` read so (node-tar
    // maps `\0` to `0` before the check).
    for type_byte in [0, b'0'] {
        let mut dir_header = tar::Header::new_old();
        dir_header.as_old_mut().name[..12].copy_from_slice(b"package/lib/");
        dir_header.as_old_mut().linkflag = [type_byte];
        dir_header.set_mode(0o755);
        dir_header.set_size(0);
        dir_header.set_cksum();
        let mut builder = tar::Builder::new(Vec::new());
        builder.append(&dir_header, &[][..]).unwrap();
        let mut file_header = tar::Header::new_gnu();
        file_header.set_path("package/lib/a.js").unwrap();
        file_header.set_mode(0o644);
        file_header.set_size(1);
        file_header.set_cksum();
        builder.append(&file_header, &b"a"[..]).unwrap();
        let gz_data = gz(&builder.into_inner().unwrap());

        let dir = tempfile::tempdir().unwrap();
        let report = extract_loose(&gz_data, dir.path()).unwrap();
        assert!(dir.path().join("package/lib").is_dir(), "type {type_byte}");
        assert!(dir.path().join("package/lib/a.js").is_file());
        assert_eq!(report.files.len(), 1, "the directory entry wrote no file");
    }
}

/// A ustar header block for `path` with a raw size field — the `tar`
/// builder would not write a directory that declares a body.
fn block(path: &str, type_byte: u8, size: u64) -> [u8; 512] {
    let mut header = tar::Header::new_ustar();
    header.set_path(path).unwrap();
    header.set_mode(0o644);
    header.set_size(size);
    header.as_mut_bytes()[156] = type_byte;
    header.set_cksum();
    *header.as_bytes()
}

#[test]
fn a_directory_entry_with_a_body_is_refused() {
    // node-tar forces a directory's size to zero and parses its declared
    // body as headers: the `smuggled.js` entry hidden there would install
    // under npm, while `tar` skips the body as data. One verified tarball,
    // two trees — refused, in both directory forms.
    for (path, type_byte) in [("package/lib", b'5'), ("package/lib/", b'0')] {
        let mut hidden = block("package/smuggled.js", b'0', 1).to_vec();
        hidden.extend_from_slice(&[b'x'; 512]);
        let mut tar_data = block(path, type_byte, hidden.len() as u64).to_vec();
        tar_data.extend_from_slice(&hidden);
        tar_data.extend_from_slice(&block("package/a.js", b'0', 1));
        tar_data.extend_from_slice(&[b'a'; 512]);
        tar_data.extend_from_slice(&[0u8; 1024]);

        let dir = tempfile::tempdir().unwrap();
        let err = extract_loose(&gz(&tar_data), dir.path()).unwrap_err();
        assert!(
            matches!(&err, ArchiveError::DirectoryWithBody(p, 1024) if p.as_path() == Path::new(path)),
            "{path}: {err:?}"
        );
        assert!(err.is_security_violation());
        assert!(!dir.path().join("package/smuggled.js").exists());
    }
}

#[test]
fn a_directory_entry_given_a_body_by_pax_is_refused() {
    // A zero ustar size with a PAX `size`: `tar` skips the PAX size as
    // body, node-tar zeroes it for a directory.
    let record = b"12 size=512\n".to_vec();
    let mut tar_data = block("PaxHeader", b'x', record.len() as u64).to_vec();
    tar_data.extend_from_slice(&record);
    tar_data.resize(1024, 0);
    tar_data.extend_from_slice(&block("package/lib", b'5', 0));
    tar_data.extend_from_slice(&block("package/smuggled.js", b'0', 0));
    tar_data.extend_from_slice(&[0u8; 1024]);
    let dir = tempfile::tempdir().unwrap();
    let err = extract_loose(&gz(&tar_data), dir.path()).unwrap_err();
    assert!(
        matches!(err, ArchiveError::DirectoryWithBody(_, 512)),
        "{err:?}"
    );
}

/// A tar stream of one PAX `x` header carrying `records`, then a regular
/// entry whose ustar size is `header_size` and whose body is `body`, then
/// the end-of-archive marker.
fn pax_tar(records: &[u8], header_size: u64, body: &[u8]) -> Vec<u8> {
    let mut tar_data = block("PaxHeader", b'x', records.len() as u64).to_vec();
    tar_data.extend_from_slice(records);
    tar_data.resize(tar_data.len().next_multiple_of(512), 0);
    tar_data.extend_from_slice(&block("package/a.js", b'0', header_size));
    tar_data.extend_from_slice(body);
    tar_data.resize(tar_data.len().next_multiple_of(512), 0);
    tar_data.extend_from_slice(&[0u8; 1024]);
    tar_data
}

#[test]
fn a_pax_size_disagreeing_with_the_header_size_is_refused() {
    // `tar` before 0.4.46 kept a non-zero header size over the record;
    // node-tar takes the record. Whichever wins, the two sizes split the
    // stream in different places.
    let tar_data = pax_tar(b"13 size=1024\n", 512, &[b'a'; 1024]);
    let dir = tempfile::tempdir().unwrap();
    let err = extract_loose(&gz(&tar_data), dir.path()).unwrap_err();
    assert!(
        matches!(
            &err,
            ArchiveError::PaxSizeMismatch {
                path,
                header_size: 512,
                pax_size: 1024,
            } if path.as_path() == Path::new("package/a.js")
        ),
        "{err:?}"
    );
    assert!(err.is_security_violation());
    assert!(!dir.path().join("package/a.js").exists());
}

#[test]
fn a_pax_size_agreeing_with_the_header_or_over_zero_is_accepted() {
    for header_size in [3, 0] {
        let tar_data = pax_tar(b"10 size=3\n", header_size, b"abc");
        let dir = tempfile::tempdir().unwrap();
        let report = extract_loose(&gz(&tar_data), dir.path()).unwrap();
        assert_eq!(report.files[Path::new("package/a.js")].size, 3);
    }
}

#[test]
fn a_pax_header_the_readers_part_on_is_refused() {
    // After an empty line `tar` stops reading records and node-tar reads
    // on: the `size` would apply under npm only, framing 1024 bytes where
    // `tar` sees a 1-byte file and a header inside them.
    let tar_data = pax_tar(b"12 path=abc\n\n13 size=1024\n", 1, &[b'a'; 1024]);
    let dir = tempfile::tempdir().unwrap();
    let err = extract_loose(&gz(&tar_data), dir.path()).unwrap_err();
    assert!(
        matches!(
            err,
            ArchiveError::MalformedPax(_, "a record has no length prefix")
        ),
        "{err:?}"
    );
    assert!(err.is_security_violation());
}

#[test]
fn pax_records_parse_only_where_both_readers_agree() {
    let size = |records: &[u8]| pax_records(records).map(|records| records.size);
    assert_eq!(size(b""), Ok(None));
    assert_eq!(size(b"12 path=abc\n"), Ok(None));
    assert_eq!(size(b"12 path=abc\n10 size=3\n"), Ok(Some(3)));
    // A value may hold `=`: both readers split on the first one.
    assert_eq!(size(b"12 path=a=b\n"), Ok(None));
    assert_eq!(
        pax_records(b"12 path=abc\n16 linkpath=abc\n10 size=3\n"),
        Ok(PaxRecords {
            size: Some(3),
            path: true,
            linkpath: true,
        })
    );
    assert_eq!(
        pax_records(b"12 path=abc\n"),
        Ok(PaxRecords {
            path: true,
            ..PaxRecords::default()
        })
    );
    for (records, why) in [
        (
            &b"12 path=abc"[..],
            "the last record is not newline-terminated",
        ),
        (b"\n", "a record has no length prefix"),
        (
            b"12 path=abc\n\n10 size=3\n",
            "a record has no length prefix",
        ),
        (
            b"13 path=abc\n",
            "a record's length prefix does not match its length",
        ),
        (
            b"012 path=ab\n",
            "a record's length prefix does not match its length",
        ),
        (
            b"+12 path=ab\n",
            "a record's length prefix does not match its length",
        ),
        (b"10 pathab\n", "a record has no `=`"),
        (b"8 =abcd\n", "a record has an empty key"),
        (b"10 size=3\n10 size=4\n", "a key is repeated"),
        (b"10 size=+\n", "the `size` record is not a decimal number"),
        (b"8 size=\n", "the `size` record is not a decimal number"),
        (b"11 size=-1\n", "the `size` record is not a decimal number"),
        (
            b"29 size=99999999999999999999\n",
            "the `size` record is out of range",
        ),
        (b"12 path=\xff\xfe\n", "the record body is not UTF-8"),
    ] {
        assert_eq!(
            size(records),
            Err(why),
            "{}",
            String::from_utf8_lossy(records)
        );
    }
}

#[test]
fn scan_extensions_finds_the_x_header_among_long_name_headers() {
    let mut extensions = block("././@LongLink", b'L', 3).to_vec();
    extensions.extend_from_slice(b"abc");
    extensions.resize(1024, 0);
    extensions.extend_from_slice(&block("PaxHeader", b'x', 10));
    extensions.extend_from_slice(b"10 size=3\n");
    extensions.resize(2048, 0);
    assert_eq!(
        scan_extensions(&extensions),
        Ok(Extensions {
            pax: Some(&b"10 size=3\n"[..]),
            long_name: true,
            long_link: false,
        })
    );
    assert_eq!(
        scan_extensions(&extensions[..1024]),
        Ok(Extensions {
            long_name: true,
            ..Extensions::default()
        })
    );
    assert_eq!(scan_extensions(&[]), Ok(Extensions::default()));
    // A body cut short, or bytes that are not a whole block, are not what
    // `tar` read.
    let unreadable = Err(Split::Pax(UNREADABLE_EXTENSIONS));
    assert_eq!(scan_extensions(&extensions[..1536]), unreadable);
    assert_eq!(scan_extensions(&extensions[..2047]), unreadable);
}

#[test]
fn a_pax_header_of_many_distinct_records_extracts() {
    // Every record's key is checked against every earlier one. A quadratic
    // check made a body near the header cap cost seconds of CPU per entry;
    // this one is under npm's 1 MiB cap and parses in linear-ish time.
    // The canary for a quadratic regression: it hangs rather than fails, so
    // a test run that stalls here has reintroduced one.
    const RECORDS: usize = 100_000;
    let mut records = Vec::with_capacity(RECORDS * 10);
    for i in 0..RECORDS {
        // `10 <5-letter key>=\n`: a distinct 10-byte record each.
        let mut key = [b'a'; 5];
        let mut n = i;
        for byte in key.iter_mut().rev() {
            *byte = b'a' + u8::try_from(n % 26).unwrap();
            n /= 26;
        }
        records.extend_from_slice(b"10 ");
        records.extend_from_slice(&key);
        records.extend_from_slice(b"=\n");
    }
    let mut limits = loose_limits();
    limits.max_header_size = 1024 * 1024;
    let gz_data = gz(&pax_tar(&records, 1, b"a"));
    let dir = tempfile::tempdir().unwrap();
    let report = safe_extract(
        &gz_data[..],
        gz_data.len() as u64,
        dir.path(),
        &limits,
        &Identity,
        SymlinkPolicy::Reject,
    )
    .unwrap();
    assert_eq!(report.files[Path::new("package/a.js")].size, 1);

    // The same body with its first key repeated at the end is refused.
    records.extend_from_slice(b"10 aaaaa=\n");
    let gz_data = gz(&pax_tar(&records, 1, b"a"));
    let dir = tempfile::tempdir().unwrap();
    let err = safe_extract(
        &gz_data[..],
        gz_data.len() as u64,
        dir.path(),
        &limits,
        &Identity,
        SymlinkPolicy::Reject,
    )
    .unwrap_err();
    assert!(
        matches!(err, ArchiveError::MalformedPax(_, "a key is repeated")),
        "{err:?}"
    );
}

#[test]
fn an_entry_named_by_a_long_name_and_a_pax_path_is_refused() {
    // `tar` takes the GNU long name, node-tar the later of the two: the
    // same entry would install under two names. Refused in either order,
    // and so is a long link beside a PAX `linkpath`.
    let long = |type_byte: u8, path: &str| {
        let mut body = path.as_bytes().to_vec();
        body.push(0);
        let mut bytes = block("././@LongLink", type_byte, body.len() as u64).to_vec();
        bytes.extend_from_slice(&body);
        bytes.resize(bytes.len().next_multiple_of(512), 0);
        bytes
    };
    let pax = |key: &str, value: &str| {
        let tail = format!(" {key}={value}\n");
        let mut len = tail.len() + 1;
        while len.to_string().len() + tail.len() != len {
            len += 1;
        }
        let body = format!("{len}{tail}").into_bytes();
        let mut bytes = block("PaxHeader", b'x', body.len() as u64).to_vec();
        bytes.extend_from_slice(&body);
        bytes.resize(bytes.len().next_multiple_of(512), 0);
        bytes
    };
    for (first, second, why) in [
        (
            long(b'L', "package/from_l.js"),
            pax("path", "package/from_pax.js"),
            "a GNU long name and a PAX path both name the entry",
        ),
        (
            pax("path", "package/from_pax.js"),
            long(b'L', "package/from_l.js"),
            "a GNU long name and a PAX path both name the entry",
        ),
        (
            long(b'K', "package/from_k.js"),
            pax("linkpath", "package/from_pax.js"),
            "a GNU long link and a PAX linkpath both name the link target",
        ),
        (
            pax("linkpath", "package/from_pax.js"),
            long(b'K', "package/from_k.js"),
            "a GNU long link and a PAX linkpath both name the link target",
        ),
    ] {
        let mut tar_data = first;
        tar_data.extend_from_slice(&second);
        tar_data.extend_from_slice(&block("package/ustar.js", b'0', 1));
        tar_data.extend_from_slice(&[b'a'; 512]);
        tar_data.extend_from_slice(&[0u8; 1024]);
        let dir = tempfile::tempdir().unwrap();
        let err = extract_loose(&gz(&tar_data), dir.path()).unwrap_err();
        assert!(
            matches!(&err, ArchiveError::MalformedPax(_, detail) if *detail == why),
            "{why}: {err:?}"
        );
        assert!(err.is_security_violation());
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0, "{why}");
    }
}

/// Recompute a raw header block's checksum after its bytes were edited.
fn reseal(block: &mut [u8; 512]) {
    block[148..156].fill(b' ');
    let sum: u32 = block.iter().map(|&b| u32::from(b)).sum();
    block[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
}

/// A tar stream whose first entry `package/a.js` has a 1024-byte body that
/// is itself a header for `package/hidden.js` and its 1-byte body, with
/// `edit` applied to the outer header block — the shape node-tar reads as
/// `hidden.js` when it skips the outer header.
fn smuggling_tar(edit: impl FnOnce(&mut [u8; 512])) -> Vec<u8> {
    let mut outer = block("package/a.js", b'0', 1024);
    edit(&mut outer);
    reseal(&mut outer);
    let mut tar_data = outer.to_vec();
    tar_data.extend_from_slice(&block("package/hidden.js", b'0', 1));
    tar_data.extend_from_slice(&[b'h'; 512]);
    tar_data.extend_from_slice(&[0u8; 1024]);
    tar_data
}

#[test]
fn a_header_node_tar_would_skip_is_refused() {
    // node-tar decodes every field of every header and skips one it
    // cannot, reading the body as headers: npm would install `hidden.js`
    // where `tar` reads `a.js`. Probed against npm 11's node-tar.
    type Edit = fn(&mut [u8; 512]);
    let cases: [(&str, Edit, &str); 9] = [
        (
            "mtime with a 0xc0 base-256 lead",
            |b| b[136] = 0xc0,
            "a base-256 number is not a positive one both readers decode alike",
        ),
        (
            "negative base-256 uid",
            |b| b[108..116].fill(0xff),
            "a base-256 number is not a positive one both readers decode alike",
        ),
        (
            "base-256 mtime past 2^53",
            |b| {
                b[136] = 0x80;
                b[137..148].fill(0xff);
            },
            "a base-256 number is past node-tar's range",
        ),
        (
            "a POSIX ustar devmajor with a 0xc0 lead",
            |b| b[329] = 0xc0,
            "a base-256 number is not a positive one both readers decode alike",
        ),
        (
            "a POSIX ustar atime with a 0xc0 lead",
            |b| b[476] = 0xc0,
            "a base-256 number is not a positive one both readers decode alike",
        ),
        (
            // `tar` trims U+0085 and reads 1024; node-tar does not, and
            // reads no size at all.
            "a size padded with U+0085",
            |b| b[124..136].copy_from_slice(b" \xc2\x85 0002000\0"),
            "a numeric field is not ASCII",
        ),
        (
            "a link name on a regular file",
            |b| b[157] = b'x',
            "a header other than a link names a link target",
        ),
        (
            // node-tar keeps what follows a line break after the NUL.
            "bytes after the name's NUL",
            |b| b[13..18].copy_from_slice(b"\0\nzzz"[..5].try_into().unwrap()),
            "a name field holds bytes after its NUL terminator",
        ),
        (
            "an empty name",
            |b| b[..100].fill(0),
            "the entry's path is empty",
        ),
    ];
    for (case, edit, why) in cases {
        let dir = tempfile::tempdir().unwrap();
        let err = extract_loose(&gz(&smuggling_tar(edit)), dir.path()).unwrap_err();
        assert!(
            matches!(&err, ArchiveError::MalformedHeader(_, detail) if *detail == why),
            "{case}: {err:?}"
        );
        assert!(err.is_security_violation());
        assert!(!dir.path().join("package/hidden.js").exists(), "{case}");
    }

    // A non-UTF-8 path, which node-tar decodes lossily.
    let tar_data = smuggling_tar(|b| b[8] = 0xff);
    let dir = tempfile::tempdir().unwrap();
    let err = extract_loose(&gz(&tar_data), dir.path()).unwrap_err();
    assert!(
        matches!(
            err,
            ArchiveError::MalformedHeader(_, "the entry's path is not UTF-8")
        ),
        "{err:?}"
    );
}

#[test]
fn an_extension_header_node_tar_would_skip_is_refused() {
    // A PAX header node-tar skips is one it never applies, so the `path`
    // below would name the entry under `tar` only.
    type Edit = fn(&mut [u8; 512]);
    let record = b"28 path=package/from_pax.js\n";
    let cases: [(&str, Edit, &str); 2] = [
        (
            "an empty name",
            |b| b[..100].fill(0),
            "an extension header's name is empty",
        ),
        (
            "an mtime with a 0xc0 lead",
            |b| b[136] = 0xc0,
            "a base-256 number is not a positive one both readers decode alike",
        ),
    ];
    for (case, edit, why) in cases {
        let mut x = block("PaxHeader", b'x', record.len() as u64);
        edit(&mut x);
        reseal(&mut x);
        let mut tar_data = x.to_vec();
        tar_data.extend_from_slice(record);
        tar_data.resize(1024, 0);
        tar_data.extend_from_slice(&block("package/ustar.js", b'0', 1));
        tar_data.extend_from_slice(&[b'a'; 512]);
        tar_data.extend_from_slice(&[0u8; 1024]);
        let dir = tempfile::tempdir().unwrap();
        let err = extract_loose(&gz(&tar_data), dir.path()).unwrap_err();
        assert!(
            matches!(&err, ArchiveError::MalformedHeader(_, detail) if *detail == why),
            "{case}: {err:?}"
        );
    }
}

#[test]
fn a_checksum_the_readers_could_read_differently_is_refused() {
    // node-tar reads the checksum from 12 bytes: an 8-digit field runs on
    // into the type flag `0`, the sum misreads, and node-tar skips the
    // header — installing `hidden.js` where `tar` reads `a.js`. Probed
    // against npm 11's node-tar.
    type Field = dyn Fn(u32) -> Vec<u8>;
    let sealed = |field: &Field| {
        let mut tar_data = smuggling_tar(|_| {});
        let outer: &mut [u8] = &mut tar_data[..512];
        outer[148..156].fill(b' ');
        let sum: u32 = outer.iter().map(|&b| u32::from(b)).sum();
        outer[148..156].copy_from_slice(&field(sum));
        tar_data
    };
    let cases: [(&str, &Field); 3] = [
        ("eight digits", &|sum| format!("{sum:08o}").into_bytes()),
        ("leading spaces, no terminator", &|sum| {
            format!("  {sum:06o}").into_bytes()
        }),
        ("a non-ASCII prefix", &|sum| {
            let mut f = vec![0xc2, 0x85];
            f.extend_from_slice(format!("{sum:05o}\0").as_bytes());
            f
        }),
    ];
    for (case, field) in cases {
        let tar_data = sealed(field);
        let dir = tempfile::tempdir().unwrap();
        let err = extract_loose(&gz(&tar_data), dir.path()).unwrap_err();
        assert!(
            matches!(&err, ArchiveError::MalformedHeader(_, detail)
                if *detail == "the checksum field is not ASCII ending in a NUL or space"),
            "{case}: {err:?}"
        );
    }
    // The shapes real producers write stay accepted.
    for field in [
        |sum: u32| format!("{sum:06o}\0 ").into_bytes(),
        |sum: u32| format!("{sum:07o}\0").into_bytes(),
        |sum: u32| format!("{sum:06o} \0").into_bytes(),
    ] {
        let tar_data = sealed(&field);
        let dir = tempfile::tempdir().unwrap();
        extract_loose(&gz(&tar_data), dir.path()).unwrap();
    }
}

#[test]
fn header_fields_both_readers_decode_alike_are_accepted() {
    // A base-256 size behind 0x80, and a ustar path split into a full
    // 155-byte prefix (its last byte set, so node-tar reads no times).
    let mut tar_data = smuggling_tar(|b| {
        b[124..136].copy_from_slice(&[0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x04, 0x00]);
    });
    let dir = tempfile::tempdir().unwrap();
    let report = extract_loose(&gz(&tar_data), dir.path()).unwrap();
    assert_eq!(report.files[Path::new("package/a.js")].size, 1024);

    let prefix = format!("package/{}", "p".repeat(147));
    assert_eq!(prefix.len(), 155);
    let path = format!("{prefix}/a.js");
    let mut header = tar::Header::new_ustar();
    header.set_path(&path).unwrap();
    header.set_mode(0o644);
    header.set_size(1);
    header.set_cksum();
    assert_ne!(header.as_bytes()[475], 0);
    tar_data = header.as_bytes().to_vec();
    tar_data.extend_from_slice(&[b'a'; 512]);
    tar_data.extend_from_slice(&[0u8; 1024]);
    let dir = tempfile::tempdir().unwrap();
    let report = extract_loose(&gz(&tar_data), dir.path()).unwrap();
    assert!(report.files.contains_key(Path::new(&path)));
}

/// A reader that yields `data`, then fails with `EIO` — a disk error on
/// the cached file, not bytes that fail to parse.
struct FailingReader<'a> {
    data: &'a [u8],
}
impl Read for FailingReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.data.is_empty() {
            return Err(std::io::Error::from_raw_os_error(5));
        }
        let n = buf.len().min(self.data.len());
        buf[..n].copy_from_slice(&self.data[..n]);
        self.data = &self.data[n..];
        Ok(n)
    }
}

#[test]
fn an_os_error_from_the_reader_is_a_read_failure_not_malformed() {
    let full = gz_tar(&[reg("package/a.js", 0o644, &noise(64 * 1024))]);
    let dir = tempfile::tempdir().unwrap();
    let err = safe_extract(
        FailingReader {
            data: &full[..full.len() / 2],
        },
        full.len() as u64,
        dir.path(),
        &loose_limits(),
        &Identity,
        SymlinkPolicy::Reject,
    )
    .unwrap_err();
    assert!(
        matches!(&err, ArchiveError::Read { source, .. } if source.raw_os_error() == Some(5)),
        "{err:?}"
    );
    assert!(!err.is_security_violation());
}

/// A reader that yields `data`, reports EOF once, then fails with `EIO` —
/// what the gzip decoder never reads past, so only the final raw-reader drain
/// meets the error.
struct EofThenFailingReader<'a> {
    data: &'a [u8],
    eof_reported: bool,
}
impl Read for EofThenFailingReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.data.is_empty() {
            if self.eof_reported {
                return Err(std::io::Error::from_raw_os_error(5));
            }
            self.eof_reported = true;
            return Ok(0);
        }
        let n = buf.len().min(self.data.len());
        buf[..n].copy_from_slice(&self.data[..n]);
        self.data = &self.data[n..];
        Ok(n)
    }
}

#[test]
fn an_os_error_from_the_final_drain_is_a_read_failure() {
    let full = gz_tar(&[reg("package/a.js", 0o644, b"a")]);
    let dir = tempfile::tempdir().unwrap();
    let err = safe_extract(
        EofThenFailingReader {
            data: &full,
            eof_reported: false,
        },
        full.len() as u64,
        dir.path(),
        &loose_limits(),
        &Identity,
        SymlinkPolicy::Reject,
    )
    .unwrap_err();
    assert!(
        matches!(
            &err,
            ArchiveError::Read { context: "draining the reader past the gzip stream", source }
                if source.raw_os_error() == Some(5)
        ),
        "{err:?}"
    );
    assert!(!err.is_security_violation());
}

#[test]
fn bytes_that_do_not_parse_are_malformed() {
    // A header whose checksum is wrong: a tar-layer format error.
    let mut tar_data = block("package/a.js", b'0', 1).to_vec();
    tar_data[148] ^= 1;
    tar_data.extend_from_slice(&[b'a'; 512]);
    tar_data.extend_from_slice(&[0u8; 1024]);
    // A gzip stream cut mid-member: the decoder's truncation.
    let full = gz_tar(&[reg("package/a.js", 0o644, &noise(64 * 1024))]);
    for input in [gz(&tar_data), full[..full.len() / 2].to_vec()] {
        let dir = tempfile::tempdir().unwrap();
        let err = extract_loose(&input, dir.path()).unwrap_err();
        assert!(matches!(err, ArchiveError::Malformed { .. }), "{err:?}");
        assert!(err.is_security_violation());
    }
}

#[test]
fn owner_exec_bit_is_preserved_else_normalized() {
    let dir = tempfile::tempdir().unwrap();
    let gz = gz_tar(&[
        reg("package/bin/cli", 0o755, b"#!/bin/sh\n"),
        reg("package/lib/data.json", 0o644, b"{}"),
    ]);
    extract_loose(&gz, dir.path()).unwrap();
    assert_eq!(mode_of(&dir.path().join("package/bin/cli")), 0o755);
    assert_eq!(mode_of(&dir.path().join("package/lib/data.json")), 0o644);
}

#[test]
fn flatten_placement_keeps_basename() {
    let dir = tempfile::tempdir().unwrap();
    let gz = gz_tar(&[reg("any/nested/fuz", 0o755, b"binary")]);
    let report = safe_extract(
        &gz[..],
        gz.len() as u64,
        dir.path(),
        &loose_limits(),
        &Basename,
        SymlinkPolicy::Reject,
    )
    .unwrap();
    assert!(dir.path().join("fuz").is_file());
    assert!(report.files.contains_key(Path::new("fuz")));
}

#[test]
fn symlink_is_rejected() {
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
    let gz = gz(&tar_data);
    let err = extract_loose(&gz, dir.path()).unwrap_err();
    assert!(matches!(err, ArchiveError::UnsupportedEntryType(_)));
}

#[test]
fn hardlink_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let mut tar_data = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_data);
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Link);
        header.set_path("package/evil").unwrap();
        header.set_link_name("/etc/passwd").unwrap();
        header.set_size(0);
        header.set_cksum();
        builder.append(&header, &[][..]).unwrap();
        builder.finish().unwrap();
    }
    let gz = gz(&tar_data);
    let err = extract_loose(&gz, dir.path()).unwrap_err();
    assert!(matches!(err, ArchiveError::UnsupportedEntryType(_)));
}

#[test]
fn device_and_fifo_entries_are_rejected() {
    // The shared chokepoint rejects every non-regular, non-dir, non-symlink
    // entry — char/fifo, not just the symlink/hardlink siblings above. This
    // pins the arm directly, not only through `fuz_release`'s wrapper.
    for ty in [tar::EntryType::Fifo, tar::EntryType::Char] {
        let dir = tempfile::tempdir().unwrap();
        let gz = gz_tar(&[("package/dev", 0o644, ty, b"")]);
        let err = extract_loose(&gz, dir.path()).unwrap_err();
        assert!(
            matches!(err, ArchiveError::UnsupportedEntryType(_)),
            "{ty:?} must be rejected as an unsupported entry type"
        );
    }
}

#[cfg(unix)]
#[test]
fn setuid_and_setgid_are_rejected() {
    for (mode, _label) in [(0o4755u32, "setuid"), (0o2755, "setgid")] {
        let dir = tempfile::tempdir().unwrap();
        let gz = gz_tar(&[reg("package/x", mode, b"data")]);
        let err = extract_loose(&gz, dir.path()).unwrap_err();
        assert!(matches!(
            err,
            ArchiveError::SetuidBit(_) | ArchiveError::SetgidBit(_)
        ));
    }
}

#[test]
fn path_too_long_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    // A short ustar-legal name, with a deliberately tiny path-length cap so
    // the guard fires (a genuinely >100-char tar name needs GNU long-name
    // framing; the cap is what we're exercising here).
    let gz = gz_tar(&[reg("package/index.js", 0o644, b"x")]);
    let mut limits = loose_limits();
    limits.max_path_length = 8; // "package/index.js" is longer
    let err = safe_extract(
        &gz[..],
        gz.len() as u64,
        dir.path(),
        &limits,
        &Identity,
        SymlinkPolicy::Reject,
    )
    .unwrap_err();
    assert!(matches!(err, ArchiveError::PathTooLong(_)));
}

#[test]
fn oversized_file_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let gz = gz_tar(&[reg("package/big", 0o644, &[0u8; 4096])]);
    let mut limits = loose_limits();
    limits.max_file_size = 1024;
    let err = safe_extract(
        &gz[..],
        gz.len() as u64,
        dir.path(),
        &limits,
        &Identity,
        SymlinkPolicy::Reject,
    )
    .unwrap_err();
    assert!(matches!(err, ArchiveError::FileTooLarge(_, _)));
}

#[test]
fn oversized_total_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let gz = gz_tar(&[
        reg("package/a", 0o644, &[1u8; 4096]),
        reg("package/b", 0o644, &[2u8; 4096]),
    ]);
    let mut limits = loose_limits();
    limits.max_total_size = 5000; // first file fits, the pair doesn't
    let err = safe_extract(
        &gz[..],
        gz.len() as u64,
        dir.path(),
        &limits,
        &Identity,
        SymlinkPolicy::Reject,
    )
    .unwrap_err();
    assert!(matches!(err, ArchiveError::TotalTooLarge(_)));
}

#[test]
fn compression_bomb_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    // Highly compressible: 256 KiB of zeros gzips tiny, so the ratio blows past 2x.
    let zeros = vec![0u8; 256 * 1024];
    let gz = gz_tar(&[reg("package/zeros", 0o644, &zeros)]);
    let mut limits = loose_limits();
    limits.max_compression_ratio = 2;
    let err = safe_extract(
        &gz[..],
        gz.len() as u64,
        dir.path(),
        &limits,
        &Identity,
        SymlinkPolicy::Reject,
    )
    .unwrap_err();
    assert!(matches!(err, ArchiveError::CompressionBomb(_)));
}

/// Skip placement — skips every entry (fuzi's `node_modules` skip, in the
/// limit).
struct SkipAll;
impl Placement for SkipAll {
    fn place(&self, _entry: &Path) -> Option<PathBuf> {
        None
    }
}

/// Build a tar stream from raw `(header, body)` pairs, where the header's
/// size field need not match the body — the shape a hostile tarball takes.
/// `Builder::append` writes the body as given and pads it to a block.
fn raw_tar(entries: Vec<(tar::Header, Vec<u8>)>) -> Vec<u8> {
    let mut tar_data = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_data);
        for (header, body) in entries {
            builder.append(&header, &body[..]).expect("append");
        }
        builder.finish().expect("finish tar");
    }
    tar_data
}

fn header(path: &str, ty: tar::EntryType, size: u64) -> tar::Header {
    let mut header = tar::Header::new_ustar();
    header.set_path(path).expect("set path");
    header.set_entry_type(ty);
    header.set_size(size);
    header.set_mode(0o644);
    header.set_cksum();
    header
}

/// Limits whose total ceiling sits well below a 1 MiB body, with the ratio
/// cap out of the way so the total is the guard that has to fire.
fn small_total_limits() -> ExtractLimits {
    let mut limits = loose_limits();
    limits.max_total_size = 64 * 1024;
    limits.max_compression_ratio = u64::MAX;
    limits
}

#[test]
fn oversized_pax_header_body_is_charged() {
    // `tar` buffers a PAX extension body whole, before yielding the entry it
    // describes, so `safe_extract` never sees it as an entry. The budget
    // reader must stop it mid-read.
    let dir = tempfile::tempdir().unwrap();
    let body = vec![b'a'; 1024 * 1024];
    let gz = gz(&raw_tar(vec![
        (
            header("PaxHeader", tar::EntryType::XHeader, body.len() as u64),
            body,
        ),
        (
            header("package/a.js", tar::EntryType::Regular, 1),
            b"a".to_vec(),
        ),
    ]));
    let err = safe_extract(
        &gz[..],
        gz.len() as u64,
        dir.path(),
        &small_total_limits(),
        &Identity,
        SymlinkPolicy::Reject,
    )
    .unwrap_err();
    assert!(matches!(err, ArchiveError::TotalTooLarge(_)), "{err:?}");
    assert!(err.is_security_violation());
}

#[test]
fn skipped_entry_body_is_charged() {
    let dir = tempfile::tempdir().unwrap();
    let body = vec![0u8; 1024 * 1024];
    let gz = gz(&raw_tar(vec![(
        header(
            "package/node_modules/x/big",
            tar::EntryType::Regular,
            body.len() as u64,
        ),
        body,
    )]));
    let err = safe_extract(
        &gz[..],
        gz.len() as u64,
        dir.path(),
        &small_total_limits(),
        &SkipAll,
        SymlinkPolicy::Reject,
    )
    .unwrap_err();
    assert!(matches!(err, ArchiveError::TotalTooLarge(_)), "{err:?}");
}

#[test]
fn data_past_the_marker_is_charged() {
    // Whatever follows the end-of-archive marker is decompressed to EOF
    // through the budget reader: a later member of zeros inflating far
    // past the total is refused, not drained uncounted.
    let mut full = gz_tar(&[reg("package/a.js", 0o644, b"a")]);
    full.extend_from_slice(&gz(&vec![0u8; 1024 * 1024]));
    let dir = tempfile::tempdir().unwrap();
    let err = safe_extract(
        &full[..],
        full.len() as u64,
        dir.path(),
        &small_total_limits(),
        &Identity,
        SymlinkPolicy::Reject,
    )
    .unwrap_err();
    assert!(matches!(err, ArchiveError::TotalTooLarge(_)), "{err:?}");
    // And under the ratio cap alone, a bomb past the marker is one.
    let mut limits = loose_limits();
    limits.max_compression_ratio = 100;
    let dir = tempfile::tempdir().unwrap();
    let err = safe_extract(
        &full[..],
        full.len() as u64,
        dir.path(),
        &limits,
        &Identity,
        SymlinkPolicy::Reject,
    )
    .unwrap_err();
    assert!(matches!(err, ArchiveError::CompressionBomb(_)), "{err:?}");
}

#[test]
fn pax_size_override_is_held_to_the_file_cap() {
    // A PAX `size` record overrides a zero ustar size field, so the header
    // reads 0 while the entry carries 4096 bytes. The per-file cap must
    // judge the effective size.
    let dir = tempfile::tempdir().unwrap();
    let record = b"13 size=4096\n".to_vec();
    let gz = gz(&raw_tar(vec![
        (
            header("PaxHeader", tar::EntryType::XHeader, record.len() as u64),
            record,
        ),
        (
            header("package/big", tar::EntryType::Regular, 0),
            vec![0u8; 4096],
        ),
    ]));
    let mut limits = loose_limits();
    limits.max_file_size = 1024;
    let err = safe_extract(
        &gz[..],
        gz.len() as u64,
        dir.path(),
        &limits,
        &Identity,
        SymlinkPolicy::Reject,
    )
    .unwrap_err();
    assert!(
        matches!(err, ArchiveError::FileTooLarge(_, 4096)),
        "{err:?}"
    );
}

/// The header window the window tests run under: far below their 1 MiB
/// bodies and the loose total, so the window is the guard that fires.
const TEST_HEADER_SIZE: u64 = 4096;

fn header_limits() -> ExtractLimits {
    let mut limits = loose_limits();
    limits.max_header_size = TEST_HEADER_SIZE;
    limits
}

/// Incompressible bytes (xorshift), so the compressed bytes a reader hands
/// out track the decompressed bytes `tar` asks for.
fn noise(len: usize) -> Vec<u8> {
    let mut state: u64 = 0x9e37_79b9_7f4a_7c15;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state.to_le_bytes()[0]
        })
        .collect()
}

/// A reader over a slice that counts the bytes it hands out.
struct CountingReader<'a> {
    data: &'a [u8],
    bytes_read: usize,
}
impl Read for CountingReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = (&self.data[self.bytes_read..]).read(buf)?;
        self.bytes_read += n;
        Ok(n)
    }
}

/// Skip placement for fuzi's vendored-`node_modules` case: skips any entry
/// with a `node_modules` component, keeps the rest verbatim.
struct SkipNodeModules;
impl Placement for SkipNodeModules {
    fn place(&self, entry: &Path) -> Option<PathBuf> {
        (!entry.components().any(|c| c.as_os_str() == "node_modules")).then(|| entry.to_path_buf())
    }
}

#[test]
fn oversized_extension_bodies_are_refused_while_read() {
    // `tar` reads a PAX, GNU long-name, or GNU long-link body whole into
    // memory inside its iterator. The header window must stop the read at
    // the cap — not at the total, which here would admit the whole body.
    const BODY_LEN: usize = 1024 * 1024;
    for ty in [
        tar::EntryType::XHeader,
        tar::EntryType::GNULongName,
        tar::EntryType::GNULongLink,
    ] {
        let dir = tempfile::tempdir().unwrap();
        let gz = gz(&raw_tar(vec![
            (header("PaxHeader", ty, BODY_LEN as u64), noise(BODY_LEN)),
            (
                header("package/a.js", tar::EntryType::Regular, 1),
                b"a".to_vec(),
            ),
        ]));
        assert!(gz.len() > BODY_LEN, "the body must not compress");
        let mut reader = CountingReader {
            data: &gz,
            bytes_read: 0,
        };
        let err = safe_extract(
            &mut reader,
            gz.len() as u64,
            dir.path(),
            &header_limits(),
            &Identity,
            SymlinkPolicy::Reject,
        )
        .unwrap_err();
        assert!(
            matches!(err, ArchiveError::HeaderTooLarge(TEST_HEADER_SIZE)),
            "{ty:?}: {err:?}"
        );
        assert!(err.is_security_violation());
        // The gzip decoder reads its input a buffer at a time, so the
        // consumption sits a buffer or two past the cap, far short of the
        // body.
        assert!(
            reader.bytes_read < 128 * 1024,
            "{ty:?}: read {} compressed bytes, the read did not stop at the cap",
            reader.bytes_read
        );
    }
}

#[test]
fn oversized_sparse_extension_chain_is_refused() {
    // A GNU sparse header can chain extension blocks without end; `tar`
    // reads them inside its iterator, before yielding the entry the type
    // guard would refuse. Each all-empty block costs nothing but the read,
    // so the window is what bounds the chain.
    let mut sparse = tar::Header::new_gnu();
    sparse.set_path("package/sparse").unwrap();
    sparse.set_entry_type(tar::EntryType::GNUSparse);
    sparse.set_size(0);
    sparse.set_mode(0o644);
    let gnu = sparse.as_gnu_mut().unwrap();
    gnu.isextended[0] = 1;
    gnu.set_real_size(0);
    sparse.set_cksum();

    let blocks = 64;
    let mut tar_data = sparse.as_bytes().to_vec();
    for i in 0..blocks {
        let mut block = [0u8; 512];
        // `isextended` follows the block's 21 24-byte sparse records.
        block[504] = u8::from(i + 1 < blocks);
        tar_data.extend_from_slice(&block);
    }
    tar_data.extend(std::iter::repeat_n(0u8, 1024));
    let gz = gz(&tar_data);

    let dir = tempfile::tempdir().unwrap();
    let err = safe_extract(
        &gz[..],
        gz.len() as u64,
        dir.path(),
        &header_limits(),
        &Identity,
        SymlinkPolicy::Reject,
    )
    .unwrap_err();
    assert!(
        matches!(err, ArchiveError::HeaderTooLarge(TEST_HEADER_SIZE)),
        "{err:?}"
    );
}

#[test]
fn sparse_entry_is_refused_where_placement_would_skip_it() {
    // A sparse entry's `size()` is its logical `real_size`, which the
    // header sets freely, so the `body_end` computed from it overshoots
    // `tar`'s next header. That is safe only because the type guard
    // refuses the entry before the next step — even where placement would
    // skip it. Were it skipped, this 1 GiB `real_size` would widen the next
    // window past the PAX body behind it.
    let mut sparse = tar::Header::new_gnu();
    sparse.set_path("package/node_modules/sparse").unwrap();
    sparse.set_entry_type(tar::EntryType::GNUSparse);
    sparse.set_size(0);
    sparse.set_mode(0o644);
    let gnu = sparse.as_gnu_mut().unwrap();
    // One record: offset 1 GiB, length 0 (non-empty: both first bytes set).
    gnu.sparse[0]
        .offset
        .copy_from_slice(format!("{:011o}\0", 1u64 << 30).as_bytes());
    gnu.sparse[0].numbytes.copy_from_slice(b"00000000000\0");
    gnu.set_real_size(1 << 30);
    sparse.set_cksum();

    let big = 512 * 1024;
    let mut tar_data = sparse.as_bytes().to_vec();
    tar_data.extend(raw_tar(vec![
        (
            header("PaxHeader", tar::EntryType::XHeader, big as u64),
            noise(big),
        ),
        (
            header("package/a.js", tar::EntryType::Regular, 1),
            b"a".to_vec(),
        ),
    ]));
    let gz = gz(&tar_data);
    let dir = tempfile::tempdir().unwrap();
    let err = safe_extract(
        &gz[..],
        gz.len() as u64,
        dir.path(),
        &header_limits(),
        &SkipNodeModules,
        SymlinkPolicy::Reject,
    )
    .unwrap_err();
    assert!(
        matches!(err, ArchiveError::UnsupportedEntryType(_)),
        "{err:?}"
    );
}

#[test]
fn header_window_is_exact_and_disarmed_for_file_data() {
    // Before the file's data: the PAX header block, its record padded to a
    // block, and the file's own header — three blocks. The PAX `size`
    // record frames a 4096-byte body behind a zero ustar size, larger than
    // the window, which must not apply while the body is read.
    let window = 3 * 512;
    let record = b"13 size=4096\n".to_vec();
    let body = noise(4096);
    let gz = gz(&raw_tar(vec![
        (
            header("PaxHeader", tar::EntryType::XHeader, record.len() as u64),
            record,
        ),
        (
            header("package/big", tar::EntryType::Regular, 0),
            body.clone(),
        ),
    ]));
    let extract = |max_header_size: u64, dir: &Path| {
        let mut limits = loose_limits();
        limits.max_header_size = max_header_size;
        safe_extract(
            &gz[..],
            gz.len() as u64,
            dir,
            &limits,
            &Identity,
            SymlinkPolicy::Reject,
        )
    };

    let dir = tempfile::tempdir().unwrap();
    let report = extract(window, dir.path()).unwrap();
    assert_eq!(report.files[Path::new("package/big")].size, 4096);
    assert_eq!(std::fs::read(dir.path().join("package/big")).unwrap(), body);

    let dir = tempfile::tempdir().unwrap();
    let err = extract(window - 1, dir.path()).unwrap_err();
    assert!(
        matches!(err, ArchiveError::HeaderTooLarge(n) if n == window - 1),
        "{err:?}"
    );
}

#[test]
fn header_window_starts_at_the_previous_padded_body_end() {
    // The exact-window test above measures from the stream start. Here the
    // window is armed after a 1-byte body, so it must start where `tar`
    // resumes — the body's padded end, not its data end or its header —
    // and admit exactly the PAX header block, its padded record, and the
    // file's own header.
    let window = 3 * 512;
    let record = b"13 size=4096\n".to_vec();
    let gz = gz(&raw_tar(vec![
        (
            header("package/one", tar::EntryType::Regular, 1),
            b"1".to_vec(),
        ),
        (
            header("PaxHeader", tar::EntryType::XHeader, record.len() as u64),
            record,
        ),
        (
            header("package/big", tar::EntryType::Regular, 0),
            noise(4096),
        ),
    ]));
    let extract = |max_header_size: u64, dir: &Path| {
        let mut limits = loose_limits();
        limits.max_header_size = max_header_size;
        safe_extract(
            &gz[..],
            gz.len() as u64,
            dir,
            &limits,
            &Identity,
            SymlinkPolicy::Reject,
        )
    };

    let dir = tempfile::tempdir().unwrap();
    extract(window, dir.path()).unwrap();

    let dir = tempfile::tempdir().unwrap();
    let err = extract(window - 1, dir.path()).unwrap_err();
    assert!(
        matches!(err, ArchiveError::HeaderTooLarge(n) if n == window - 1),
        "{err:?}"
    );
}

#[test]
fn unread_bodies_drain_outside_the_header_window() {
    // A skipped `node_modules` body and a skipped body framed by a PAX
    // `size` override are both far larger than the window. `tar` drains
    // them when it advances, and the window must start where each padded
    // body ends — so the file after them still extracts.
    let big = 256 * 1024;
    let record = format!("15 size={big}\n").into_bytes();
    assert_eq!(record.len(), 15, "a PAX record's length counts itself");
    let gz = gz(&raw_tar(vec![
        (
            header(
                "package/node_modules/x/big",
                tar::EntryType::Regular,
                big as u64,
            ),
            noise(big),
        ),
        (
            header("PaxHeader", tar::EntryType::XHeader, record.len() as u64),
            record,
        ),
        (
            header("package/node_modules/y/big", tar::EntryType::Regular, 0),
            noise(big),
        ),
        (
            header("package/a.js", tar::EntryType::Regular, 1),
            b"a".to_vec(),
        ),
    ]));
    let dir = tempfile::tempdir().unwrap();
    let report = safe_extract(
        &gz[..],
        gz.len() as u64,
        dir.path(),
        &header_limits(),
        &SkipNodeModules,
        SymlinkPolicy::Reject,
    )
    .unwrap();
    assert_eq!(report.files.len(), 1);
    assert!(dir.path().join("package/a.js").is_file());
    assert!(!dir.path().join("package/node_modules").exists());
}

#[test]
fn zip_slip_dotdot_path_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    // The `tar` builder refuses `..`; hand-roll the entry so the reader sees it.
    let gz = gz_raw_tar(b"../../../etc/passwd", b"pwned");
    let err = extract_loose(&gz, dir.path()).unwrap_err();
    assert!(matches!(err, ArchiveError::InvalidPath(_)));
    assert!(!dir.path().join("passwd").exists());
}

#[test]
fn bytes_after_a_ustar_name_terminator_are_refused() {
    // ustar header names are NUL-terminated fixed fields: the tar layer
    // reads `pkg/ev\0il` as `pkg/ev`, so a NUL never reaches a created
    // path via a ustar name. (The `NullByte` guard covers length-delimited
    // GNU/pax extended names, where a NUL could survive parsing.) node-tar
    // deletes only up to a line break after the NUL, so bytes after the
    // terminator are refused outright, and nothing is written.
    let dir = tempfile::tempdir().unwrap();
    let gz = gz_raw_tar(b"pkg/ev\0il", b"x");
    let err = extract_loose(&gz, dir.path()).unwrap_err();
    assert!(
        matches!(
            &err,
            ArchiveError::MalformedHeader(path, "a name field holds bytes after its NUL terminator")
                if path.as_path() == Path::new("pkg/ev")
        ),
        "{err:?}"
    );
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
}

#[test]
fn escaping_placement_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let gz = gz_tar(&[reg("package/ok.js", 0o644, b"x")]);
    let err = safe_extract(
        &gz[..],
        gz.len() as u64,
        dir.path(),
        &loose_limits(),
        &Escaping,
        SymlinkPolicy::Reject,
    )
    .unwrap_err();
    assert!(matches!(err, ArchiveError::PlacementEscapesRoot(_)));
    assert!(!dir.path().parent().unwrap().join("escape").exists());
}

#[test]
fn report_carries_blake3_and_total() {
    let dir = tempfile::tempdir().unwrap();
    let gz = gz_tar(&[reg("package/a.txt", 0o644, b"hello")]);
    let report = extract_loose(&gz, dir.path()).unwrap();
    let f = &report.files[Path::new("package/a.txt")];
    assert_eq!(f.size, 5);
    assert_eq!(f.hash, ContentHash::blake3(b"hello"));
    assert_eq!(report.total_bytes, 5);
}

#[test]
fn security_classification_is_stable() {
    let p = || PathBuf::from("x");
    // Hostile / malformed archive input — security violations.
    for e in [
        ArchiveError::InvalidPath(p()),
        ArchiveError::UnsupportedEntryType(p()),
        ArchiveError::NullByte(p()),
        ArchiveError::PathTooLong(p()),
        ArchiveError::FileTooLarge(p(), 1),
        ArchiveError::TotalTooLarge(1),
        ArchiveError::CompressionBomb(2),
        ArchiveError::HeaderTooLarge(1),
        ArchiveError::SetuidBit(p()),
        ArchiveError::SetgidBit(p()),
        ArchiveError::PlacementEscapesRoot(p()),
        ArchiveError::DirectoryWithBody(p(), 1),
        ArchiveError::PaxSizeMismatch {
            path: p(),
            header_size: 1,
            pax_size: 2,
        },
        ArchiveError::MalformedPax(p(), "x"),
        ArchiveError::Malformed {
            context: "t",
            source: std::io::Error::other("x"),
        },
    ] {
        assert!(e.is_security_violation(), "expected violation: {e:?}");
    }
    // Empty input and plain I/O are not, on their own, hostile bytes.
    for e in [
        ArchiveError::Empty,
        ArchiveError::Io(std::io::Error::other("x")),
        ArchiveError::Read {
            context: "t",
            source: std::io::Error::from_raw_os_error(5),
        },
    ] {
        assert!(!e.is_security_violation(), "unexpected violation: {e:?}");
    }
}

#[test]
fn budget_reader_clamps_reads_to_the_header_window() {
    // A read inside the window is cut at the limit, not checked after an
    // overshoot: one oversized read would otherwise decompress past the
    // cap (as far as the caller's buffer reaches) before the refusal.
    let data = [7u8; 4096];
    let window = Cell::new(Some(HeaderWindow {
        start: 0,
        limit: 1000,
    }));
    let captured = RefCell::new(Vec::new());
    let mut limits = loose_limits();
    limits.max_header_size = 1000;
    limits.max_compression_ratio = u64::MAX;
    let mut reader = BudgetReader {
        inner: &data[..],
        decompressed_size: 0,
        compressed_size: 1,
        limits,
        header_window: &window,
        captured: &captured,
    };
    let mut buf = [0u8; 4096];
    assert_eq!(reader.read(&mut buf).unwrap(), 1000);
    assert_eq!(
        captured.borrow().len(),
        1000,
        "the window captures its reads"
    );
    let err = reader.read(&mut buf).unwrap_err();
    assert!(
        matches!(
            err.downcast::<ArchiveError>(),
            Ok(ArchiveError::HeaderTooLarge(1000))
        ),
        "a read at the limit must be refused"
    );
    // Disarmed (an entry's data being read), the rest flows, uncaptured.
    window.set(None);
    assert_eq!(reader.read(&mut buf).unwrap(), 3096);
    assert_eq!(captured.borrow().len(), 1000);
}

#[test]
fn budget_reader_captures_only_from_the_window_start() {
    // The unread rest of a skipped body is drained inside the window but
    // lies before its start: header data begins at the start.
    let data: Vec<u8> = (0..=255).collect();
    let window = Cell::new(Some(HeaderWindow {
        start: 100,
        limit: 1000,
    }));
    let captured = RefCell::new(Vec::new());
    let mut reader = BudgetReader {
        inner: &data[..],
        decompressed_size: 0,
        compressed_size: 1,
        limits: ExtractLimits {
            max_compression_ratio: u64::MAX,
            ..loose_limits()
        },
        header_window: &window,
        captured: &captured,
    };
    let mut buf = [0u8; 64];
    // Wholly before the start, then straddling it, then after it.
    assert_eq!(reader.read(&mut buf).unwrap(), 64);
    assert!(captured.borrow().is_empty());
    assert_eq!(reader.read(&mut buf).unwrap(), 64);
    assert_eq!(*captured.borrow(), (100..128).collect::<Vec<u8>>());
    assert_eq!(reader.read(&mut buf).unwrap(), 64);
    assert_eq!(*captured.borrow(), (100..192).collect::<Vec<u8>>());
}

#[test]
fn charge_accumulates_and_checks_total_before_ratio() {
    let mut limits = loose_limits();
    limits.max_total_size = 100;
    limits.max_compression_ratio = 10;
    let mut total = 0u64;
    // Under both ceilings: bytes accumulate.
    charge(&mut total, 40, 10, &limits).unwrap();
    assert_eq!(total, 40);
    charge(&mut total, 40, 10, &limits).unwrap();
    assert_eq!(total, 80);
    // 80 + 30 = 110 violates the total ceiling (110 > 100) *and* the ratio
    // ceiling (110 / 10 = 11 > 10); total is checked first, so `TotalTooLarge`
    // wins — pinning the check order.
    let err = charge(&mut total, 30, 10, &limits).unwrap_err();
    assert!(matches!(err, ArchiveError::TotalTooLarge(110)));
}

#[test]
fn charge_ratio_uses_integer_division() {
    let mut limits = loose_limits();
    limits.max_compression_ratio = 2;
    let mut total = 0u64;
    // 20 / 10 = 2, not > 2 → accepted (integer division, boundary is inclusive).
    charge(&mut total, 20, 10, &limits).unwrap();
    // 30 / 10 = 3 > 2 → compression bomb, reported at the integer ratio.
    let err = charge(&mut total, 10, 10, &limits).unwrap_err();
    assert!(matches!(err, ArchiveError::CompressionBomb(3)));
}
