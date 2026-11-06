//! Security-hardened tarball extraction
//!
//! Implements defense-in-depth extraction with:
//! - Allowlist-based entry validation
//! - Compression bomb protection
//! - Size limits (per-file and total)
//! - Hash verification before trusting any file
//! - Atomic extraction (temp dir → verify → rename)

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use fuz_archive::{ExtractLimits, Placement, SymlinkPolicy, safe_extract};
use fuz_crypto::{ContentHash, HashAlgo, Hasher, hash_file};

use crate::error::TarballError;
use crate::manifest::Manifest;
use crate::{MAX_COMPRESSION_RATIO, MAX_FILE_SIZE, MAX_TOTAL_SIZE};

/// Maximum path length in tarball entries (denial-of-service prevention).
const MAX_PATH_LENGTH: usize = 256;

/// Maximum header window in tarball entries: what `tar` may read between one
/// entry's body and the next entry's data — header blocks plus any PAX /
/// GNU long-name / long-link body, which it buffers in memory. Signed bundles hold a few
/// flat binaries whose paths stay under [`MAX_PATH_LENGTH`], so their metadata
/// is a handful of blocks; without this cap it would be bounded only by
/// [`MAX_TOTAL_SIZE`].
const MAX_HEADER_SIZE: u64 = 64 * 1024;

/// Verify tarball bytes match expected hash from manifest.
/// Called after download, before extraction.
pub fn verify_tarball_hash(bytes: &[u8], expected: &ContentHash) -> Result<(), TarballError> {
    let actual = ContentHash::blake3(bytes);
    if actual != *expected {
        return Err(TarballError::HashMismatch {
            expected: expected.clone(),
            actual,
        });
    }
    Ok(())
}

/// Stream-hash a `.tar.gz` file and verify its blake3 against `expected`.
///
/// `expected` is the hash the signed manifest pins. Returns the byte length —
/// the compressed size [`extract_tarball_reader`] needs for its ratio check.
/// Bounded memory: reads in `EXTRACT_BUFFER_SIZE` chunks, never the whole
/// file. This is the streaming replacement for [`verify_tarball_hash`] on the
/// consumer download path (the tarball arrives as a temp file, not a slice).
pub fn verify_tarball_file(path: &Path, expected: &ContentHash) -> Result<u64, TarballError> {
    // Shared buffered-file hasher (bounded memory) — the per-crate 64 KiB loop
    // lives once in `fuz_crypto::hash_file`.
    let (hash, total) = hash_file(HashAlgo::Blake3, path).map_err(TarballError::Io)?;
    if hash != *expected {
        return Err(TarballError::HashMismatch {
            expected: expected.clone(),
            actual: hash,
        });
    }
    Ok(total)
}

/// blake3 hash + byte size of a packed tarball, returned by
/// [`pack_tarball_to_file`] so the producer fills the manifest without a second
/// pass over the bytes.
#[derive(Debug, Clone)]
pub struct TarballDigest {
    /// blake3 of the `.tar.gz`.
    pub blake3: ContentHash,
    /// `.tar.gz` byte length.
    pub size: u64,
}

/// `Write` adapter that hashes (blake3) and counts bytes as they flow to an
/// inner writer — lets [`pack_tarball_to_file`] compute the tarball hash + size
/// in the single packing pass (no buffer, no re-read).
struct HashingWriter<W> {
    inner: W,
    hasher: Hasher,
    bytes: u64,
}

impl<W: Write> Write for HashingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.hasher.update(&buf[..n]);
        self.bytes += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// Build a gzip-compressed tarball with each binary at root level, streaming it
/// to `dest` (never the whole `.tar.gz` in memory) and hashing + sizing it in
/// the same pass.
///
/// Each entry is mode 0755 with an epoch mtime (reproducible builds). The
/// caller supplies in-tarball name → bytes; this packer does no hashing or
/// verification of the *inputs*. Shared by the fuz-only self-artifact publish
/// path (just `fuz`) and per-tool publish (`tools/<name>/`, one or more
/// binaries). Each input binary is still held individually — fine for the small
/// first-party self/tool binaries; the GB-scale path is the raw file store, not
/// signed bundles.
pub fn pack_tarball_to_file(
    binaries: &[(String, Vec<u8>)],
    dest: &Path,
) -> Result<TarballDigest, TarballError> {
    use flate2::Compression;
    use flate2::write::GzEncoder;

    let file = std::fs::File::create(dest).map_err(TarballError::Io)?;
    let writer = HashingWriter {
        inner: std::io::BufWriter::new(file),
        hasher: Hasher::new(HashAlgo::Blake3),
        bytes: 0,
    };
    let encoder = GzEncoder::new(writer, Compression::default());
    let mut builder = tar::Builder::new(encoder);

    for (name, content) in binaries {
        let mut header = tar::Header::new_gnu();
        header.set_size(content.len() as u64);
        header.set_mode(0o755);
        header.set_mtime(0); // reproducible builds: use epoch
        header.set_cksum();
        builder
            .append_data(&mut header, name, content.as_slice())
            .map_err(|error| TarballError::Tar {
                context: "appending binary to tarball",
                error,
            })?;
    }

    let encoder = builder.into_inner().map_err(|error| TarballError::Tar {
        context: "finishing tar archive",
        error,
    })?;
    let mut writer = encoder.finish().map_err(|error| TarballError::Tar {
        context: "finishing gzip stream",
        error,
    })?;
    // Drain the BufWriter to the file; all bytes have already passed through
    // the hasher (it sits above the BufWriter), so the digest is complete.
    writer.flush().map_err(TarballError::Io)?;

    Ok(TarballDigest {
        blake3: writer.hasher.finalize(),
        size: writer.bytes,
    })
}

/// Validate tarball contains exactly the expected files.
/// Uses manifest.binaries keys as the allowlist.
fn validate_tarball_contents(
    found: &HashSet<String>,
    manifest: &Manifest,
) -> Result<(), TarballError> {
    // Check for missing binaries (must match manifest exactly)
    for name in manifest.binaries.keys() {
        if !found.contains(name) {
            return Err(TarballError::MissingBinary(name.clone()));
        }
    }

    // Check for unexpected files
    for name in found {
        if !manifest.binaries.contains_key(name) {
            return Err(TarballError::UnexpectedFile(PathBuf::from(name)));
        }
    }

    Ok(())
}

/// Extract and verify tarball contents.
///
/// Extracts to `temp_dir`, computing hashes during extraction.
/// Returns map of binary name -> blake3 hash for verification.
///
/// # Security
///
/// - Charges every decompressed byte to the total-size and compression-ratio
///   budget (`fuz_archive`'s budget reader), so a bomb is caught on the read
///   that crosses it
/// - Sets permissions explicitly (0755) - doesn't trust tarball
/// - Uses allowlist for entry validation
pub fn extract_tarball(
    tarball_bytes: &[u8],
    manifest: &Manifest,
    temp_dir: &Path,
) -> Result<HashMap<String, ContentHash>, TarballError> {
    extract_tarball_reader(
        tarball_bytes,
        tarball_bytes.len() as u64,
        manifest,
        temp_dir,
    )
}

/// Placement for the signed-bundle path: flatten every entry to its basename.
///
/// fuz's self/tool bundles are flat sets of binaries. The exact-match manifest
/// allowlist is enforced post-extraction by [`validate_tarball_contents`], so an
/// unexpected nested path collapses to a basename the allowlist then rejects.
struct FlattenToBasename;

impl Placement for FlattenToBasename {
    fn place(&self, entry: &Path) -> Option<PathBuf> {
        entry.file_name().map(PathBuf::from)
    }
}

/// Streaming variant of [`extract_tarball`] — decompress + extract from a [`Read`].
///
/// Reads from any [`Read`] (e.g. a downloaded temp file) instead of a
/// fully-buffered slice, so the consumer never holds the whole `.tar.gz` in
/// memory.
///
/// `compressed_size` is the on-disk `.tar.gz` byte length — the caller knows it
/// from the download (`Storage::download_to_file` returns it, or
/// [`verify_tarball_file`]) — and feeds the compression-ratio bomb check.
///
/// The hardened streaming/guard core lives in `fuz_archive::safe_extract`
/// (shared with `fuzi`); this wrapper supplies the flat-binary placement, the
/// signed-bundle size ceilings, and the manifest exact-match allowlist that is
/// specific to fuz's self/tool bundles. All the security properties hold
/// (only-`Normal` paths, null-byte/path-length/size/ratio guards,
/// setuid/setgid + symlink rejection, explicit perms).
pub fn extract_tarball_reader<R: Read>(
    reader: R,
    compressed_size: u64,
    manifest: &Manifest,
    temp_dir: &Path,
) -> Result<HashMap<String, ContentHash>, TarballError> {
    let limits = ExtractLimits {
        max_file_size: MAX_FILE_SIZE,
        max_total_size: MAX_TOTAL_SIZE,
        max_compression_ratio: MAX_COMPRESSION_RATIO,
        max_header_size: MAX_HEADER_SIZE,
        max_path_length: MAX_PATH_LENGTH,
    };
    let report = safe_extract(
        reader,
        compressed_size,
        temp_dir,
        &limits,
        &FlattenToBasename,
        SymlinkPolicy::Reject,
    )?;

    // Flatten placement → every key is a basename; rebuild the name→hash map and
    // the found-set the manifest allowlist checks against.
    let mut binary_hashes: HashMap<String, ContentHash> = HashMap::new();
    let mut found_files: HashSet<String> = HashSet::new();
    for (rel, file) in report.files {
        let name = rel.to_string_lossy().into_owned();
        found_files.insert(name.clone());
        binary_hashes.insert(name, file.hash);
    }

    // Validate we got exactly the expected files (manifest exact-match allowlist).
    validate_tarball_contents(&found_files, manifest)?;

    // A valid gzip carrying no file entries is still empty.
    if found_files.is_empty() {
        return Err(TarballError::Empty);
    }

    Ok(binary_hashes)
}

/// Verify extracted binaries match manifest hashes.
pub fn verify_binary_hashes(
    extracted: &HashMap<String, ContentHash>,
    manifest: &Manifest,
) -> Result<(), TarballError> {
    for (name, expected) in &manifest.binaries {
        let actual = extracted
            .get(name)
            .ok_or_else(|| TarballError::MissingBinary(name.clone()))?;
        if actual != expected {
            return Err(TarballError::BinaryHashMismatch {
                name: name.clone(),
                expected: expected.clone(),
                actual: actual.clone(),
            });
        }
    }
    Ok(())
}

/// Verify content hash matches (defense in depth).
///
/// Recomputes the content hash from binary hashes using the canonical
/// algorithm shared with local artifacts and tool installs
/// (`fuz_artifact::content_hash_from_binaries`).
pub fn verify_content_hash(
    binary_hashes: &HashMap<String, ContentHash>,
    expected: &str,
) -> Result<(), TarballError> {
    let sorted: BTreeMap<String, ContentHash> = binary_hashes
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let actual = fuz_artifact::content_hash_from_binaries(&sorted);
    if actual != expected {
        return Err(TarballError::ContentHashMismatch {
            expected: expected.to_string(),
            actual,
        });
    }
    Ok(())
}

/// Create meta.json from manifest data.
///
/// Creates a meta.json file compatible with the local artifact format,
/// using `ArtifactMeta::new_remote()`. The self artifact is **fuz-only**, so
/// only the manifest's `fuz` entry maps into `ArtifactOutputs`; any other
/// declared binary (a tool manifest is fetched through `fuz_release::tool`,
/// not here) is irrelevant to the self artifact's `meta.json`.
pub fn create_meta_json(manifest: &Manifest, dir: &Path) -> Result<(), TarballError> {
    use fuz_artifact::{ArtifactMeta, ArtifactOutputs};

    let outputs = ArtifactOutputs {
        fuz: manifest
            .binaries
            .get("fuz")
            .ok_or_else(|| TarballError::MissingBinary("fuz".to_string()))?
            .clone(),
    };

    let meta = ArtifactMeta::new_remote(
        manifest.content_hash.clone(),
        manifest.version.clone(),
        outputs,
    );

    meta.write(dir)
        .map_err(|e| TarballError::Io(std::io::Error::other(e.to_string())))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a blake3 `ContentHash` from a bare-hex string (test fixtures).
    fn ch(hex: &str) -> ContentHash {
        ContentHash::from_hex(HashAlgo::Blake3, hex).unwrap()
    }

    #[test]
    fn verify_tarball_hash_accepts_matching() {
        let content = b"test content";
        let expected = ContentHash::blake3(content);
        let result = verify_tarball_hash(content, &expected);
        assert!(result.is_ok());
    }

    #[test]
    fn verify_tarball_hash_rejects_mismatch() {
        let content = b"test content";
        let wrong_hash = ContentHash::blake3(b"wrong");
        let result = verify_tarball_hash(content, &wrong_hash);
        assert!(matches!(result, Err(TarballError::HashMismatch { .. })));
    }

    #[test]
    fn verify_tarball_file_roundtrips_and_rejects() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.tar.gz");
        let content = b"some tarball-ish bytes";
        std::fs::write(&path, content).unwrap();

        let expected = ContentHash::blake3(content);
        let size = verify_tarball_file(&path, &expected).unwrap();
        assert_eq!(size, content.len() as u64);

        let err = verify_tarball_file(&path, &ContentHash::blake3(b"wrong"));
        assert!(matches!(err, Err(TarballError::HashMismatch { .. })));
    }

    #[test]
    fn verify_content_hash_matches_artifact_format() {
        // Same test data as the `content_hash_is_stable` artifact-format test
        let mut hashes = HashMap::new();
        hashes.insert("fuz".to_string(), ch(&"a".repeat(64)));
        hashes.insert("fuzd".to_string(), ch(&"b".repeat(64)));

        let expected = "v1-8377df8a3806026a3767542a164fbb394343ba09229861ae442bfa8ded71f742";
        let result = verify_content_hash(&hashes, expected);
        assert!(result.is_ok(), "result: {result:?}");
    }

    #[test]
    fn verify_content_hash_rejects_mismatch() {
        let mut hashes = HashMap::new();
        hashes.insert("fuz".to_string(), ch(&"a".repeat(64)));
        hashes.insert("fuzd".to_string(), ch(&"b".repeat(64)));

        let result = verify_content_hash(&hashes, "v1-wronghash");
        assert!(matches!(
            result,
            Err(TarballError::ContentHashMismatch { .. })
        ));
    }

    /// The reproducible-build contract: identical inputs produce a byte-identical
    /// `.tar.gz` (same blake3), and each entry is normalized to mode 0o755 +
    /// mtime 0. A regression here (a non-epoch mtime, a mode drift) would make
    /// the build-twice reproducibility gate silently non-deterministic.
    #[test]
    fn pack_tarball_to_file_is_reproducible_and_normalizes_entries() {
        let dir = tempfile::tempdir().unwrap();
        let binaries = vec![
            ("fuz".to_string(), b"fuz binary bytes".to_vec()),
            ("fuzd".to_string(), b"fuzd binary bytes".to_vec()),
        ];

        let a = pack_tarball_to_file(&binaries, &dir.path().join("a.tar.gz")).unwrap();
        let b = pack_tarball_to_file(&binaries, &dir.path().join("b.tar.gz")).unwrap();

        // Same inputs → identical archive bytes; digest + reported size agree
        // with the file on disk.
        assert_eq!(a.blake3, b.blake3, "pack must be reproducible");
        assert_eq!(a.size, b.size);
        assert_eq!(
            a.size,
            std::fs::metadata(dir.path().join("a.tar.gz"))
                .unwrap()
                .len(),
            "reported size matches the file"
        );

        // Each entry carries the normalization knobs, in input order.
        let bytes = std::fs::read(dir.path().join("a.tar.gz")).unwrap();
        let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(&bytes[..]));
        let mut names = Vec::new();
        for entry in archive.entries().unwrap() {
            let e = entry.unwrap();
            let header = e.header();
            assert_eq!(header.mode().unwrap(), 0o755, "entry mode normalized");
            assert_eq!(header.mtime().unwrap(), 0, "entry mtime pinned to epoch");
            names.push(e.path().unwrap().to_string_lossy().into_owned());
        }
        assert_eq!(
            names,
            vec!["fuz", "fuzd"],
            "entries appended in input order"
        );
    }

    /// The tar layer's own error repeats the entry's path (`... when getting
    /// mode for <path>`): the message shows it escaped, like the paths this
    /// crate's own variants carry.
    #[test]
    fn a_tar_layer_error_shows_the_entry_path_escaped() {
        use std::io::Write as _;
        let mut header = tar::Header::new_gnu();
        header.set_path("a\u{1b}[2K\r\u{202e}b").unwrap();
        header.set_size(1);
        header.set_entry_type(tar::EntryType::Regular);
        header.as_old_mut().mode = *b"zzzzzzz\0";
        header.set_cksum();
        let mut builder = tar::Builder::new(Vec::new());
        builder.append(&header, &b"x"[..]).unwrap();
        let tar_bytes = builder.into_inner().unwrap();
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(&tar_bytes).unwrap();
        let bytes = gz.finish().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let limits = ExtractLimits {
            max_file_size: MAX_FILE_SIZE,
            max_total_size: MAX_TOTAL_SIZE,
            max_compression_ratio: MAX_COMPRESSION_RATIO,
            max_header_size: MAX_HEADER_SIZE,
            max_path_length: MAX_PATH_LENGTH,
        };
        let error = safe_extract(
            &bytes[..],
            bytes.len() as u64,
            dir.path(),
            &limits,
            &FlattenToBasename,
            SymlinkPolicy::Reject,
        )
        .unwrap_err();
        assert_eq!(
            TarballError::from(error).to_string(),
            "malformed tarball (reading entry mode): numeric field was not a number: zzzzzzz when \
             getting mode for a\\u{1b}[2K\\r\\u{202e}b"
        );
    }
}
