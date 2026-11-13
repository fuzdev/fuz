//! Content hashing — algorithm-tagged digests with constant-time equality.
//!
//! The canonical hashing home for the fuz workspace: [`ContentHash`] is the one
//! representation of a digest, and [`Hasher`] and [`hash_file`] the one way to
//! compute it, so a content-hashing call site needs no bare-hex `String`s,
//! inline `blake3::hash(x).to_hex()` calls, buffered-file read loops of their
//! own, or a plain `==` comparison.
//!
//! Three string forms are supported, matching what the ecosystem already emits:
//!
//! - **bare hex** ([`ContentHash::to_hex`]) — the signed manifest's per-field
//!   form, read through the [`blake3_hex`] / [`blake3_hex_map`] adapters,
//! - the **fuz form** `<algo>:<hex>` ([`ContentHash::to_prefixed`]); a fact
//!   address is the BLAKE3 case, `blake3:<hex>`, read through
//!   [`ContentHash::parse_fact_hash`] or the [`fact_hash`] adapter, and
//! - the **SRI form** `sha512-<base64>` ([`ContentHash::to_sri`]) — the
//!   Subresource-Integrity shape npm lockfiles use, which fuzi needs.
//!
//! Hex is written lowercase and read lowercase only: every hex parse except
//! [`ContentHash::from_hex`] goes through [`ContentHash::from_lower_hex`], so
//! one digest has one spelling wherever it is compared or re-signed as text.
//!
//! Equality is constant-time ([`ContentHash`]'s `PartialEq`). Content hashes
//! are public values, so this is defense-in-depth rather than a strict
//! requirement — but it removes the per-call-site `==`-vs-`ct_eq` drift in
//! which a verify helper *claims* constant-time while comparing `String`s
//! with `==`.

use std::fmt;
use std::fs::File;
use std::hash::{Hash, Hasher as StdHasher};
use std::io::{self, BufReader, Read};
use std::path::Path;
use std::str::FromStr;

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use subtle::ConstantTimeEq;

use crate::error::HashError;

/// Buffer size for the buffered-file / reader hashing loop (64 KiB).
///
/// Matches the chunk size every prior hand-rolled loop used
/// (`fuz_artifact`, `fuz_release::tarball`, `fact_store`).
const HASH_BUFFER_SIZE: usize = 64 * 1024;

/// A content-hash algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HashAlgo {
    /// BLAKE3 — the fuz-native content-addressing algorithm (32-byte digest).
    Blake3,
    /// SHA-256 — the weaker npm Subresource-Integrity digest, read so a
    /// lockfile that carries it beside `sha512` parses (32-byte digest).
    Sha256,
    /// SHA-512 — the release trust tier's secondary anchor beside blake3, the
    /// digest the pre-fuz install script compares (`sha512sum` / `shasum -a
    /// 512` are as ubiquitous as their 256 counterparts, while SHA-3 has no
    /// such tool), and the npm Subresource-Integrity algorithm (64-byte
    /// digest).
    Sha512,
}

impl HashAlgo {
    /// Lowercase algorithm token used in both the fuz form (`blake3:<hex>`)
    /// and the SRI form (`sha512-<base64>`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Blake3 => "blake3",
            Self::Sha256 => "sha256",
            Self::Sha512 => "sha512",
        }
    }

    /// Digest length in bytes.
    #[must_use]
    pub const fn digest_len(self) -> usize {
        match self {
            Self::Blake3 | Self::Sha256 => 32,
            Self::Sha512 => 64,
        }
    }

    /// Parse a lowercase algorithm token.
    fn from_token(token: &str) -> Result<Self, HashError> {
        match token {
            "blake3" => Ok(Self::Blake3),
            "sha256" => Ok(Self::Sha256),
            "sha512" => Ok(Self::Sha512),
            other => Err(HashError::UnknownAlgorithm(other.to_string())),
        }
    }
}

impl fmt::Display for HashAlgo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An algorithm-tagged content hash.
///
/// Holds the raw digest bytes plus the algorithm that produced them. The
/// algorithm is part of identity: a `blake3` digest never equals a `sha256`
/// digest even if the bytes coincide.
///
/// Construct from bytes via [`ContentHash::blake3`] / [`ContentHash::sha256`] /
/// [`ContentHash::sha512`] (or [`Hasher`] / [`hash_file`] for streamed input),
/// and from a string via [`ContentHash::parse_fact_hash`],
/// [`ContentHash::parse_prefixed`], [`ContentHash::parse_sri`],
/// [`ContentHash::from_lower_hex`], or [`FromStr`].
#[derive(Clone)]
pub struct ContentHash {
    algo: HashAlgo,
    bytes: Box<[u8]>,
}

impl ContentHash {
    /// BLAKE3 of `data`.
    #[must_use]
    pub fn blake3(data: &[u8]) -> Self {
        Self {
            algo: HashAlgo::Blake3,
            bytes: blake3::hash(data).as_bytes().to_vec().into_boxed_slice(),
        }
    }

    /// SHA-256 of `data`.
    #[must_use]
    pub fn sha256(data: &[u8]) -> Self {
        use sha2::{Digest, Sha256};
        Self {
            algo: HashAlgo::Sha256,
            bytes: Sha256::digest(data).to_vec().into_boxed_slice(),
        }
    }

    /// SHA-512 of `data`.
    #[must_use]
    pub fn sha512(data: &[u8]) -> Self {
        use sha2::{Digest, Sha512};
        Self {
            algo: HashAlgo::Sha512,
            bytes: Sha512::digest(data).to_vec().into_boxed_slice(),
        }
    }

    /// Build from raw digest bytes, validating the length against `algo`.
    ///
    /// # Errors
    ///
    /// Returns [`HashError::WrongLength`] if `bytes` isn't `algo.digest_len()`.
    pub fn from_bytes(algo: HashAlgo, bytes: impl Into<Box<[u8]>>) -> Result<Self, HashError> {
        let bytes = bytes.into();
        if bytes.len() != algo.digest_len() {
            return Err(HashError::WrongLength {
                algo: algo.as_str(),
                expected: algo.digest_len(),
                got: bytes.len(),
            });
        }
        Ok(Self { algo, bytes })
    }

    /// The algorithm that produced this digest.
    #[must_use]
    pub const fn algo(&self) -> HashAlgo {
        self.algo
    }

    /// The raw digest bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Lowercase hex of the digest bytes (no algorithm prefix).
    ///
    /// This is the **bare-hex** form the signed release manifest stores per
    /// field (`TarballInfo.blake3`, `BinaryHashes` values).
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(&self.bytes)
    }

    /// The fuz form: `<algo>:<hex>` (e.g. `blake3:<64 hex>`).
    ///
    /// This is the fact store's content-address wire format.
    #[must_use]
    pub fn to_prefixed(&self) -> String {
        format!("{}:{}", self.algo.as_str(), self.to_hex())
    }

    /// The Subresource-Integrity form: `<algo>-<base64>` (e.g. `sha512-…`).
    ///
    /// Standard (padded) base64, matching npm lockfile `integrity` fields.
    #[must_use]
    pub fn to_sri(&self) -> String {
        format!("{}-{}", self.algo.as_str(), BASE64.encode(&self.bytes))
    }

    /// Parse the bare-hex form for a known `algo` (no prefix), in either case.
    ///
    /// The lenient parse, for hex a tool outside fuz wrote; a digest fuz wrote
    /// is read with [`from_lower_hex`](Self::from_lower_hex).
    ///
    /// # Errors
    ///
    /// Returns [`HashError::InvalidHex`] for non-hex input or
    /// [`HashError::WrongLength`] if the decoded length is wrong for `algo`.
    pub fn from_hex(algo: HashAlgo, hex_str: &str) -> Result<Self, HashError> {
        let bytes = hex::decode(hex_str).map_err(|e| HashError::InvalidHex(e.to_string()))?;
        Self::from_bytes(algo, bytes)
    }

    /// Parse bare hex for a known `algo` in the one spelling a digest is
    /// written in: full length, lowercase.
    ///
    /// [`from_hex`](Self::from_hex) alone also accepts uppercase, which would
    /// give one digest two spellings in documents compared or re-signed as
    /// text, or read by tools that compare hex as text (`sha512sum`).
    ///
    /// # Errors
    ///
    /// Returns [`HashError::NotLowerHex`], whose message does not repeat
    /// `hex`, unless `hex` is exactly `2 * algo.digest_len()` characters of
    /// `0-9a-f`.
    pub fn from_lower_hex(algo: HashAlgo, hex: &str) -> Result<Self, HashError> {
        let is_lower_hex = hex.len() == algo.digest_len() * 2
            && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
        if !is_lower_hex {
            return Err(HashError::NotLowerHex { algo });
        }
        Self::from_hex(algo, hex)
    }

    /// Parse the fuz form `<algo>:<hex>` for any algorithm the type knows,
    /// with the hex read by [`from_lower_hex`](Self::from_lower_hex): full
    /// length, lowercase.
    ///
    /// Not a fact-address gate — it admits `sha256:` and `sha512:` too. A fact
    /// address is read with [`parse_fact_hash`](Self::parse_fact_hash).
    ///
    /// # Errors
    ///
    /// Returns [`HashError::Malformed`] without a `:`,
    /// [`HashError::UnknownAlgorithm`] for an algorithm token the type doesn't
    /// know, or [`HashError::NotLowerHex`] for any other hex.
    pub fn parse_prefixed(s: &str) -> Result<Self, HashError> {
        let (token, hex_str) = s
            .split_once(':')
            .ok_or_else(|| HashError::Malformed(s.to_string()))?;
        Self::from_lower_hex(HashAlgo::from_token(token)?, hex_str)
    }

    /// Parse a fact address: exactly `blake3:` followed by 64 lowercase hex
    /// characters, and nothing else — the fuz form of a BLAKE3 digest.
    ///
    /// The grammar of the TS twin's `FactHashSchema` (`fuz_util`'s
    /// `FACT_HASH_EXACT`, `/^blake3:[0-9a-f]{64}$/`): no other algorithm, no
    /// uppercase hex, no other length, no surrounding whitespace. A route
    /// segment, a JSON-RPC param, or a cell field that names a fact is read
    /// through this (or the [`fact_hash`] serde adapter), so both spines refuse
    /// the same strings. `fuz_auth::is_valid_fact_hash` is the same grammar
    /// over a `&str`, for callers that keep the string.
    ///
    /// # Errors
    ///
    /// Returns [`HashError::NotFactHash`], whose message does not repeat `s`,
    /// for anything off that grammar.
    pub fn parse_fact_hash(s: &str) -> Result<Self, HashError> {
        match Self::parse_prefixed(s) {
            Ok(hash) if hash.algo == HashAlgo::Blake3 => Ok(hash),
            _ => Err(HashError::NotFactHash),
        }
    }

    /// Parse the SRI form `<algo>-<base64>`.
    ///
    /// # Errors
    ///
    /// Returns [`HashError`] if the prefix, algorithm token, base64, or length
    /// is invalid.
    pub fn parse_sri(s: &str) -> Result<Self, HashError> {
        let (token, b64) = s
            .split_once('-')
            .ok_or_else(|| HashError::Malformed(s.to_string()))?;
        let algo = HashAlgo::from_token(token)?;
        let bytes = BASE64
            .decode(b64)
            .map_err(|e| HashError::InvalidBase64(e.to_string()))?;
        Self::from_bytes(algo, bytes)
    }
}

/// Constant-time equality. Compares the algorithm tag, then the digest bytes
/// with `subtle::ConstantTimeEq` (length is not secret; differing-length
/// digests short-circuit to unequal).
impl PartialEq for ContentHash {
    fn eq(&self, other: &Self) -> bool {
        self.algo == other.algo && bool::from(self.bytes.ct_eq(&other.bytes))
    }
}

impl Eq for ContentHash {}

impl Hash for ContentHash {
    fn hash<H: StdHasher>(&self, state: &mut H) {
        self.algo.hash(state);
        self.bytes.hash(state);
    }
}

impl fmt::Debug for ContentHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ContentHash({})", self.to_prefixed())
    }
}

/// `Display` renders the fuz form (`<algo>:<hex>`).
impl fmt::Display for ContentHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_prefixed())
    }
}

/// Accepts either the fuz form (`<algo>:<hex>`) or the SRI form
/// (`<algo>-<base64>`); the separator disambiguates (hex/base64 contain
/// neither `:` nor, for standard base64, `-`).
impl FromStr for ContentHash {
    type Err = HashError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.contains(':') {
            Self::parse_prefixed(s)
        } else if s.contains('-') {
            Self::parse_sri(s)
        } else {
            Err(HashError::Malformed(s.to_string()))
        }
    }
}

/// Serializes as the fuz form (`<algo>:<hex>`). Field sites that must preserve
/// a different wire shape (bare hex in the signed manifest) use per-field serde
/// adapters instead of this default.
impl Serialize for ContentHash {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_prefixed())
    }
}

impl<'de> Deserialize<'de> for ContentHash {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(D::Error::custom)
    }
}

/// A streaming hasher — the single streaming-hash implementation for the workspace.
///
/// Feed bytes with [`Hasher::update`] (or drain a reader with
/// [`Hasher::update_reader`]), then [`Hasher::finalize`] into a [`ContentHash`].
#[derive(Debug)]
pub struct Hasher {
    inner: HasherInner,
}

#[derive(Debug)]
enum HasherInner {
    Blake3(Box<blake3::Hasher>),
    Sha256(sha2::Sha256),
    Sha512(sha2::Sha512),
}

impl Hasher {
    /// A fresh hasher for `algo`.
    #[must_use]
    pub fn new(algo: HashAlgo) -> Self {
        let inner = match algo {
            HashAlgo::Blake3 => HasherInner::Blake3(Box::new(blake3::Hasher::new())),
            HashAlgo::Sha256 => HasherInner::Sha256(sha2::Sha256::default()),
            HashAlgo::Sha512 => HasherInner::Sha512(sha2::Sha512::default()),
        };
        Self { inner }
    }

    /// Feed a chunk of bytes.
    pub fn update(&mut self, data: &[u8]) {
        use sha2::Digest as _;
        match &mut self.inner {
            HasherInner::Blake3(h) => {
                h.update(data);
            }
            HasherInner::Sha256(h) => h.update(data),
            HasherInner::Sha512(h) => h.update(data),
        }
    }

    /// Drain `reader` in 64 KiB chunks, hashing each. Returns the number of
    /// bytes read.
    ///
    /// # Errors
    ///
    /// Propagates the first read error.
    pub fn update_reader<R: Read>(&mut self, mut reader: R) -> io::Result<u64> {
        #[expect(
            clippy::large_stack_arrays,
            reason = "an intentional 64 KiB read buffer"
        )]
        let mut buf = [0u8; HASH_BUFFER_SIZE];
        let mut total: u64 = 0;
        loop {
            let n = reader.read(&mut buf)?;
            if n == 0 {
                break;
            }
            self.update(&buf[..n]);
            total += n as u64;
        }
        Ok(total)
    }

    /// Finalize into a [`ContentHash`].
    #[must_use]
    pub fn finalize(self) -> ContentHash {
        use sha2::Digest as _;
        match self.inner {
            HasherInner::Blake3(h) => ContentHash {
                algo: HashAlgo::Blake3,
                bytes: h.finalize().as_bytes().to_vec().into_boxed_slice(),
            },
            HasherInner::Sha256(h) => ContentHash {
                algo: HashAlgo::Sha256,
                bytes: h.finalize().to_vec().into_boxed_slice(),
            },
            HasherInner::Sha512(h) => ContentHash {
                algo: HashAlgo::Sha512,
                bytes: h.finalize().to_vec().into_boxed_slice(),
            },
        }
    }
}

/// Hash an open `reader` with `algo` in bounded memory. Returns the hash and
/// the number of bytes read.
///
/// # Errors
///
/// Propagates the first read error.
pub fn hash_reader<R: Read>(algo: HashAlgo, reader: R) -> io::Result<(ContentHash, u64)> {
    let mut hasher = Hasher::new(algo);
    let total = hasher.update_reader(reader)?;
    Ok((hasher.finalize(), total))
}

/// Hash a file with `algo` in bounded memory (the canonical buffered-file
/// helper). Returns the hash and the file's byte length.
///
/// # Errors
///
/// Returns an [`io::Error`] if the file can't be opened or read.
pub fn hash_file(algo: HashAlgo, path: &Path) -> io::Result<(ContentHash, u64)> {
    let file = File::open(path)?;
    hash_reader(algo, BufReader::new(file))
}

/// Refuse to serialize a non-BLAKE3 hash through an adapter whose form only
/// a BLAKE3 digest may take.
fn require_blake3<S: Serializer>(hash: &ContentHash) -> Result<(), S::Error> {
    use serde::ser::Error as _;
    if hash.algo == HashAlgo::Blake3 {
        Ok(())
    } else {
        Err(S::Error::custom(format_args!(
            "expected a blake3 hash, got {}",
            hash.algo
        )))
    }
}

/// Serde adapter: (de)serializes a [`ContentHash`] as **bare lowercase hex**
/// (no `<algo>:` prefix), assuming BLAKE3.
///
/// This is the wire shape the signed release manifest and the on-disk artifact
/// meta use for their per-binary and tarball hashes. Use via
/// `#[serde(with = "fuz_crypto::blake3_hex")]`. Deserialization reads only the
/// one spelling [`ContentHash::from_lower_hex`] accepts — full length,
/// lowercase — so a malformed hash is rejected at parse rather than at a later
/// equality check.
pub mod blake3_hex {
    use serde::{Deserialize, Deserializer, Serializer, de::Error as _};

    use super::{ContentHash, HashAlgo};

    /// Serialize as bare lowercase hex.
    ///
    /// # Errors
    ///
    /// Refuses a hash that isn't BLAKE3 — bare hex carries no algorithm, so it
    /// would be read back as a BLAKE3 digest it isn't — and propagates the
    /// serializer's error.
    pub fn serialize<S: Serializer>(hash: &ContentHash, serializer: S) -> Result<S::Ok, S::Error> {
        super::require_blake3::<S>(hash)?;
        serializer.serialize_str(&hash.to_hex())
    }

    /// Deserialize bare hex as a BLAKE3 [`ContentHash`].
    ///
    /// # Errors
    ///
    /// Returns the deserializer's error if the value isn't a string or isn't
    /// 64 lowercase hex characters.
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<ContentHash, D::Error> {
        let s = String::deserialize(deserializer)?;
        ContentHash::from_lower_hex(HashAlgo::Blake3, &s).map_err(D::Error::custom)
    }
}

/// Serde adapter for a map from name to [`ContentHash`] whose values are
/// (de)serialized as **bare lowercase hex** BLAKE3 digests (keys unchanged).
///
/// Generic over the map type, so it serves both `HashMap<String, ContentHash>`
/// (the signed manifest's `binaries`) and `BTreeMap<String, ContentHash>` (the
/// on-disk `ToolMeta.binaries`). Use via
/// `#[serde(with = "fuz_crypto::blake3_hex_map")]`. A repeated key is refused
/// ([`crate::unique_map`]), as is an uppercase value.
pub mod blake3_hex_map {
    use serde::{Deserializer, Serializer, de::Error as _};

    use super::{ContentHash, HashAlgo};

    /// Serialize each value as bare lowercase hex (keys serialized as-is).
    ///
    /// # Errors
    ///
    /// Refuses a value that isn't BLAKE3, as [`super::blake3_hex::serialize`]
    /// does, and propagates the serializer's error.
    pub fn serialize<S, M>(map: &M, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        for<'a> &'a M: IntoIterator<Item = (&'a String, &'a ContentHash)>,
    {
        for (_, v) in map {
            super::require_blake3::<S>(v)?;
        }
        serializer.collect_map(map.into_iter().map(|(k, v)| (k, v.to_hex())))
    }

    /// Deserialize a map of bare-hex BLAKE3 digests, refusing a repeated key.
    ///
    /// # Errors
    ///
    /// Returns the deserializer's error if a key repeats or any value isn't 64
    /// lowercase hex characters.
    pub fn deserialize<'de, D, M>(deserializer: D) -> Result<M, D::Error>
    where
        D: Deserializer<'de>,
        M: FromIterator<(String, ContentHash)>,
    {
        crate::unique_map::deserialize::<D, String>(deserializer)?
            .into_iter()
            .map(|(k, v)| {
                ContentHash::from_lower_hex(HashAlgo::Blake3, &v)
                    .map(|h| (k, h))
                    .map_err(D::Error::custom)
            })
            .collect()
    }
}

/// Serde adapter: (de)serializes a [`ContentHash`] as a **fact address**,
/// `blake3:<64 lowercase hex>`.
///
/// Use via `#[serde(with = "fuz_crypto::fact_hash")]` on a field that names a
/// fact. Deserialization reads only what [`ContentHash::parse_fact_hash`]
/// accepts, where the default `Deserialize` also takes `sha256:` / `sha512:`
/// and the SRI form; serialization refuses a hash that isn't BLAKE3.
pub mod fact_hash {
    use serde::{Deserialize, Deserializer, Serializer, de::Error as _};

    use super::ContentHash;

    /// Serialize as `blake3:<hex>`.
    ///
    /// # Errors
    ///
    /// Refuses a hash that isn't BLAKE3, and propagates the serializer's
    /// error.
    pub fn serialize<S: Serializer>(hash: &ContentHash, serializer: S) -> Result<S::Ok, S::Error> {
        super::require_blake3::<S>(hash)?;
        serializer.serialize_str(&hash.to_prefixed())
    }

    /// Deserialize a fact address.
    ///
    /// # Errors
    ///
    /// Returns the deserializer's error if the value isn't a string or isn't
    /// `blake3:` followed by 64 lowercase hex characters.
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<ContentHash, D::Error> {
        let s = String::deserialize(deserializer)?;
        ContentHash::parse_fact_hash(&s).map_err(D::Error::custom)
    }
}

#[cfg(test)]
#[expect(
    clippy::items_after_statements,
    reason = "test fns declare their fixture types and imports beside the statements that use them"
)]
mod tests {
    use super::*;

    #[test]
    fn blake3_matches_raw() {
        let data = b"hello content hashing";
        let h = ContentHash::blake3(data);
        assert_eq!(h.algo(), HashAlgo::Blake3);
        assert_eq!(h.to_hex(), blake3::hash(data).to_hex().to_string());
    }

    #[test]
    fn sha256_known_vector_abc() {
        // NIST SHA-256("abc")
        assert_eq!(
            ContentHash::sha256(b"abc").to_hex(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn sha512_digest_len() {
        assert_eq!(ContentHash::sha512(b"x").as_bytes().len(), 64);
    }

    #[test]
    fn prefixed_round_trip() {
        let h = ContentHash::blake3(b"abc");
        let s = h.to_prefixed();
        assert!(s.starts_with("blake3:"));
        assert_eq!(ContentHash::parse_prefixed(&s).unwrap(), h);
        assert_eq!(s.parse::<ContentHash>().unwrap(), h);
    }

    #[test]
    fn sri_round_trip() {
        let h = ContentHash::sha512(b"abc");
        let s = h.to_sri();
        assert!(s.starts_with("sha512-"));
        assert_eq!(ContentHash::parse_sri(&s).unwrap(), h);
        assert_eq!(s.parse::<ContentHash>().unwrap(), h);
    }

    #[test]
    fn bare_hex_round_trip() {
        let h = ContentHash::blake3(b"abc");
        let hex_str = h.to_hex();
        assert!(!hex_str.contains(':'));
        assert_eq!(
            ContentHash::from_hex(HashAlgo::Blake3, &hex_str).unwrap(),
            h
        );
    }

    #[test]
    fn algo_is_part_of_identity() {
        // sha256 and blake3 of "abc" differ; even if they somehow shared bytes,
        // the algo tag keeps them distinct.
        let a = ContentHash::sha256(b"abc");
        let b = ContentHash::from_bytes(HashAlgo::Blake3, a.as_bytes().to_vec()).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn wrong_length_rejected() {
        let err = ContentHash::from_bytes(HashAlgo::Blake3, vec![0u8; 10]).unwrap_err();
        assert!(matches!(err, HashError::WrongLength { .. }));
    }

    /// The prefixed parse reads hex as `from_lower_hex` does: an uppercase or
    /// wrong-length spelling of a real digest is refused, not normalized.
    #[test]
    fn parse_prefixed_reads_only_lowercase_full_length_hex() {
        for hash in [
            ContentHash::blake3(b"abc"),
            ContentHash::sha256(b"abc"),
            ContentHash::sha512(b"abc"),
        ] {
            let algo = hash.algo();
            let hex = hash.to_hex();
            assert_eq!(
                ContentHash::parse_prefixed(&hash.to_prefixed()).unwrap(),
                hash
            );
            let one_upper = hex.replacen(|c: char| c.is_ascii_alphabetic(), "F", 1);
            for bad in [
                hex.to_ascii_uppercase(),
                one_upper,
                hex[..hex.len() - 2].to_string(),
                format!("{hex}00"),
            ] {
                let error = ContentHash::parse_prefixed(&format!("{algo}:{bad}")).unwrap_err();
                assert!(
                    matches!(error, HashError::NotLowerHex { algo: a } if a == algo),
                    "{algo}:{bad}: {error:?}"
                );
            }
        }
    }

    /// `parse_fact_hash` is the `FactHashSchema` grammar: what `to_prefixed`
    /// writes for a BLAKE3 digest, and nothing the wider parsers would also
    /// take.
    #[test]
    fn parse_fact_hash_accepts_only_the_fact_address_grammar() {
        let hash = ContentHash::blake3(b"abc");
        let address = hash.to_prefixed();
        assert!(address.starts_with("blake3:"));
        assert_eq!(ContentHash::parse_fact_hash(&address).unwrap(), hash);
        let hex = hash.to_hex();
        for bad in [
            // uppercase hex, whole or in one character
            format!("blake3:{}", hex.to_ascii_uppercase()),
            format!(
                "blake3:{}",
                hex.replacen(|c: char| c.is_ascii_alphabetic(), "F", 1)
            ),
            // the other algorithms the type knows, and the SRI form
            ContentHash::sha256(b"abc").to_prefixed(),
            ContentHash::sha512(b"abc").to_prefixed(),
            hash.to_sri(),
            // digest length, either side of the bound
            format!("blake3:{}", &hex[1..]),
            format!("blake3:{hex}0"),
            // missing, wrong-case, or detached prefix
            hex.clone(),
            format!("BLAKE3:{hex}"),
            format!("blake3-{hex}"),
            format!(" {address}"),
            format!("{address} "),
            "blake3:".to_string(),
            String::new(),
            // right length, outside hex, including a multibyte character
            format!("blake3:{}", "g".repeat(64)),
            format!("blake3:\u{FC}{}", "a".repeat(63)),
        ] {
            let error = ContentHash::parse_fact_hash(&bad).unwrap_err();
            assert!(
                matches!(error, HashError::NotFactHash),
                "{bad:?}: {error:?}"
            );
            assert_eq!(
                error.to_string(),
                "expected a fact hash: blake3: followed by 64 lowercase hex characters"
            );
        }
    }

    #[test]
    fn fact_hash_adapter_round_trips_and_refuses_the_wider_forms() {
        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct Wrap {
            #[serde(with = "super::fact_hash")]
            h: ContentHash,
        }
        let w = Wrap {
            h: ContentHash::blake3(b"abc"),
        };
        let json = serde_json::to_string(&w).unwrap();
        assert_eq!(json, format!(r#"{{"h":"{}"}}"#, w.h.to_prefixed()));
        assert_eq!(serde_json::from_str::<Wrap>(&json).unwrap(), w);
        // every one of these reads through the default `Deserialize`
        for wider in [
            format!("blake3:{}", w.h.to_hex().to_ascii_uppercase()),
            ContentHash::sha256(b"abc").to_prefixed(),
            ContentHash::sha512(b"abc").to_sri(),
        ] {
            let json = format!(r#"{{"h":"{wider}"}}"#);
            assert!(serde_json::from_str::<Wrap>(&json).is_err(), "{wider}");
        }
        let not_blake3 = Wrap {
            h: ContentHash::sha256(b"abc"),
        };
        assert!(serde_json::to_string(&not_blake3).is_err());
    }

    /// Bare hex names no algorithm, so the adapters refuse to write a
    /// non-BLAKE3 digest that would read back as a BLAKE3 one.
    #[test]
    fn blake3_hex_adapters_refuse_to_serialize_another_algorithm() {
        use std::collections::BTreeMap;

        #[derive(Serialize)]
        struct Wrap {
            #[serde(with = "super::blake3_hex")]
            h: ContentHash,
        }
        #[derive(Serialize)]
        struct WrapMap {
            #[serde(with = "super::blake3_hex_map")]
            m: BTreeMap<String, ContentHash>,
        }
        for h in [ContentHash::sha256(b"abc"), ContentHash::sha512(b"abc")] {
            let error = serde_json::to_string(&Wrap { h: h.clone() }).unwrap_err();
            assert_eq!(
                error.to_string(),
                format!("expected a blake3 hash, got {}", h.algo())
            );
            let mut m = BTreeMap::new();
            m.insert("fuz".to_string(), ContentHash::blake3(b"x"));
            m.insert("tsv".to_string(), h);
            assert!(serde_json::to_string(&WrapMap { m }).is_err());
        }
    }

    #[test]
    fn unknown_algorithm_rejected() {
        let err = ContentHash::parse_prefixed("md5:abcd").unwrap_err();
        assert!(matches!(err, HashError::UnknownAlgorithm(a) if a == "md5"));
    }

    #[test]
    fn streaming_matches_one_shot() {
        let data = b"the quick brown fox jumps over the lazy dog";
        let mut hasher = Hasher::new(HashAlgo::Blake3);
        hasher.update(&data[..10]);
        hasher.update(&data[10..]);
        assert_eq!(hasher.finalize(), ContentHash::blake3(data));
    }

    #[test]
    fn hash_reader_matches_one_shot_and_counts() {
        let data = vec![7u8; HASH_BUFFER_SIZE * 2 + 13];
        let (h, n) = hash_reader(HashAlgo::Sha256, &data[..]).unwrap();
        assert_eq!(h, ContentHash::sha256(&data));
        assert_eq!(n, data.len() as u64);
    }

    #[test]
    fn hash_file_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blob");
        let data = b"file bytes to hash";
        std::fs::write(&path, data).unwrap();
        let (h, n) = hash_file(HashAlgo::Blake3, &path).unwrap();
        assert_eq!(h, ContentHash::blake3(data));
        assert_eq!(n, data.len() as u64);
    }

    #[test]
    fn serde_default_is_prefixed_form() {
        let h = ContentHash::blake3(b"abc");
        let json = serde_json::to_string(&h).unwrap();
        assert_eq!(json, format!("\"{}\"", h.to_prefixed()));
        let back: ContentHash = serde_json::from_str(&json).unwrap();
        assert_eq!(back, h);
    }

    #[test]
    fn blake3_hex_adapter_is_bare_hex_round_trip() {
        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct Wrap {
            #[serde(with = "super::blake3_hex")]
            h: ContentHash,
        }
        let w = Wrap {
            h: ContentHash::blake3(b"abc"),
        };
        let json = serde_json::to_string(&w).unwrap();
        assert_eq!(json, format!("{{\"h\":\"{}\"}}", w.h.to_hex()));
        assert!(!json.contains("blake3:"), "must be bare hex: {json}");
        assert_eq!(serde_json::from_str::<Wrap>(&json).unwrap(), w);
    }

    #[test]
    fn blake3_hex_adapter_rejects_wrong_length_at_parse() {
        #[derive(Deserialize, Debug)]
        struct Wrap {
            #[serde(with = "super::blake3_hex")]
            #[expect(
                dead_code,
                reason = "deserialize-only: the parse result is the assertion"
            )]
            h: ContentHash,
        }
        // 66 hex chars — rejected at parse, not at a later equality check.
        let json = format!("{{\"h\":\"{}\"}}", "abc".repeat(22));
        assert!(serde_json::from_str::<Wrap>(&json).is_err());
    }

    /// The adapters write lowercase and read only lowercase: an uppercase
    /// spelling of the same digest is refused, wholly or in one character.
    #[test]
    fn blake3_hex_adapters_refuse_uppercase() {
        use std::collections::BTreeMap;

        #[derive(Deserialize, Debug)]
        struct Wrap {
            #[serde(with = "super::blake3_hex")]
            #[expect(
                dead_code,
                reason = "deserialize-only: the parse result is the assertion"
            )]
            h: ContentHash,
        }
        #[derive(Deserialize, Debug)]
        struct WrapMap {
            #[serde(with = "super::blake3_hex_map")]
            #[expect(
                dead_code,
                reason = "deserialize-only: the parse result is the assertion"
            )]
            m: BTreeMap<String, ContentHash>,
        }
        let lower = ContentHash::blake3(b"abc").to_hex();
        assert!(serde_json::from_str::<Wrap>(&format!(r#"{{"h":"{lower}"}}"#)).is_ok());
        let one_upper = lower.replacen(|c: char| c.is_ascii_alphabetic(), "F", 1);
        for spelling in [lower.to_ascii_uppercase(), one_upper] {
            for error in [
                serde_json::from_str::<Wrap>(&format!(r#"{{"h":"{spelling}"}}"#)).unwrap_err(),
                serde_json::from_str::<WrapMap>(&format!(r#"{{"m":{{"fuz":"{spelling}"}}}}"#))
                    .unwrap_err(),
            ] {
                assert!(
                    error
                        .to_string()
                        .starts_with("expected 64 lowercase hex characters for blake3"),
                    "{spelling}: {error}"
                );
            }
        }
    }

    /// `from_lower_hex` reads exactly the spelling `to_hex` writes, for each
    /// algorithm, and refuses every other shape without repeating it.
    #[test]
    fn from_lower_hex_accepts_only_the_canonical_spelling() {
        for (algo, hash) in [
            (HashAlgo::Blake3, ContentHash::blake3(b"abc")),
            (HashAlgo::Sha256, ContentHash::sha256(b"abc")),
            (HashAlgo::Sha512, ContentHash::sha512(b"abc")),
        ] {
            let lower = hash.to_hex();
            assert_eq!(ContentHash::from_lower_hex(algo, &lower).unwrap(), hash);
            let len = algo.digest_len() * 2;
            let one_upper = lower.replacen(|c: char| c.is_ascii_alphabetic(), "F", 1);
            let mut non_hex = lower.clone();
            non_hex.replace_range(..1, "g");
            for bad in [
                lower.to_ascii_uppercase(),
                one_upper,
                lower[..len - 2].to_string(),
                lower[..len - 1].to_string(),
                format!("{lower}00"),
                format!("{lower}0"),
                non_hex,
                format!(" {}", &lower[1..]),
                String::new(),
            ] {
                let error = ContentHash::from_lower_hex(algo, &bad).unwrap_err();
                assert!(
                    matches!(error, HashError::NotLowerHex { algo: a } if a == algo),
                    "{algo} {bad:?}: {error:?}"
                );
                assert_eq!(
                    error.to_string(),
                    format!("expected {len} lowercase hex characters for {algo}"),
                );
            }
        }
    }

    #[test]
    fn blake3_hex_map_adapter_round_trips_both_map_types() {
        use std::collections::{BTreeMap, HashMap};

        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct WrapB {
            #[serde(with = "super::blake3_hex_map")]
            m: BTreeMap<String, ContentHash>,
        }
        let mut b = BTreeMap::new();
        b.insert("fuz".to_string(), ContentHash::blake3(b"x"));
        let wb = WrapB { m: b };
        let json = serde_json::to_string(&wb).unwrap();
        assert!(!json.contains("blake3:"), "must be bare hex: {json}");
        assert_eq!(serde_json::from_str::<WrapB>(&json).unwrap(), wb);

        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct WrapH {
            #[serde(with = "super::blake3_hex_map")]
            m: HashMap<String, ContentHash>,
        }
        let mut h = HashMap::new();
        h.insert("fuz".to_string(), ContentHash::blake3(b"x"));
        let wh = WrapH { m: h };
        let json = serde_json::to_string(&wh).unwrap();
        assert_eq!(serde_json::from_str::<WrapH>(&json).unwrap(), wh);
    }

    /// A repeated name is refused, for either map type, rather than read as
    /// its last value: a reader that keeps the first would see another digest.
    #[test]
    fn blake3_hex_map_adapter_refuses_a_repeated_name() {
        use std::collections::{BTreeMap, HashMap};

        #[derive(Deserialize, Debug)]
        struct WrapB {
            #[serde(with = "super::blake3_hex_map")]
            #[expect(
                dead_code,
                reason = "deserialize-only: the parse result is the assertion"
            )]
            m: BTreeMap<String, ContentHash>,
        }
        #[derive(Deserialize, Debug)]
        struct WrapH {
            #[serde(with = "super::blake3_hex_map")]
            #[expect(
                dead_code,
                reason = "deserialize-only: the parse result is the assertion"
            )]
            m: HashMap<String, ContentHash>,
        }
        let (first, last) = (
            ContentHash::blake3(b"first").to_hex(),
            ContentHash::blake3(b"last").to_hex(),
        );
        let json = format!(r#"{{"m":{{"fuz":"{first}","fuz":"{last}"}}}}"#);
        for error in [
            serde_json::from_str::<WrapB>(&json).unwrap_err(),
            serde_json::from_str::<WrapH>(&json).unwrap_err(),
        ] {
            assert!(
                error.to_string().starts_with("duplicate key \"fuz\""),
                "{error}"
            );
        }
    }

    #[test]
    fn constant_time_eq_is_value_correct() {
        // ct_eq must still be functionally correct, not just timing-flat.
        let a = ContentHash::blake3(b"a");
        let a2 = ContentHash::blake3(b"a");
        let b = ContentHash::blake3(b"b");
        assert_eq!(a, a2);
        assert_ne!(a, b);
    }
}
