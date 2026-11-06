//! SSH signature (`sshsig`) verification.
//!
//! Verifies what `ssh-keygen -Y sign -n <namespace> -f <key> <file>` writes to
//! `<file>.sig`, against one expected ed25519 key. Verification only, pure, no
//! I/O — there is no signer here or anywhere in the production graph; the party
//! that signs runs `ssh-keygen`.
//!
//! # The accepted subset
//!
//! An armored signature is the line `-----BEGIN SSH SIGNATURE-----`, base64
//! lines, and the line `-----END SSH SIGNATURE-----`, with `\n` line endings
//! and at most one `\n` after the end marker. `ssh-keygen -Y verify` is laxer —
//! it reads past `\r\n` endings and ignores text after the end marker — and
//! this parser is not: the body's line breaks may fall anywhere; nothing else
//! varies.
//!
//! The decoded blob (SSH `string` = big-endian `uint32` length, then bytes):
//!
//! | Field | Requirement |
//! |---|---|
//! | magic | the six bytes `SSHSIG`, no length prefix |
//! | `uint32` version | 1 |
//! | `string` public key | `string` `ssh-ed25519`, `string` of 32 bytes, nothing after |
//! | `string` namespace | equal to the expected namespace |
//! | `string` reserved | empty |
//! | `string` hash algorithm | `sha512` or `sha256` |
//! | `string` signature | `string` `ssh-ed25519`, `string` of 64 bytes, nothing after |
//!
//! Nothing may follow the signature. The signed bytes are
//! `SSHSIG` ‖ `string` namespace ‖ `string` reserved ‖ `string` hash algorithm
//! ‖ `string` H(message).
//!
//! # What a successful verification means
//!
//! The signature was made over exactly `message`, under exactly `namespace`,
//! by exactly the key the caller expected. The key inside the blob is not
//! trusted for anything: it must *equal* the expected key, so a valid signature
//! by any other key is [`SshsigError::WrongKey`]. The namespace binds the
//! signature to its purpose — a signature the same key made for `git` or `file`
//! is [`SshsigError::WrongNamespace`].
//!
//! The ed25519 check is `ed25519_dalek`'s `Verifier::verify`, the same call
//! `verify_signature` makes for release signatures.

use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::{Verifier, VerifyingKey};
use sha2::{Digest, Sha256, Sha512};

use crate::error::SshsigError;
use crate::witness::SSH_ED25519;

/// Largest armored signature read, in bytes. An ed25519 signature is a few
/// hundred; the bound is applied before anything is decoded.
pub const MAX_ARMORED_SIZE: usize = 4096;

const BEGIN: &str = "-----BEGIN SSH SIGNATURE-----\n";
const END: &str = "\n-----END SSH SIGNATURE-----";
const MAGIC: &[u8] = b"SSHSIG";
const VERSION: u32 = 1;

/// Verify an armored SSH signature over `message`, made under `namespace` by
/// `key`.
///
/// `armored` is the content of the `.sig` file `ssh-keygen -Y sign` writes;
/// `message` is the exact content of the signed file; `key` is the 32-byte
/// ed25519 public key the signature must have been made with. See the module
/// docs for the accepted subset.
///
/// The checks run in this order: size, armor, blob structure (every field,
/// with exact lengths), key equality, namespace equality, then the ed25519
/// verification — so the error names the first thing wrong.
///
/// # Errors
///
/// An [`SshsigError`]. Never panics, whatever the input.
pub fn verify_sshsig(
    armored: &[u8],
    message: &[u8],
    namespace: &str,
    key: &[u8; 32],
) -> Result<(), SshsigError> {
    let blob = dearmor(armored)?;
    let parsed = parse_blob(&blob)?;
    if parsed.public_key != key {
        return Err(SshsigError::WrongKey);
    }
    if parsed.namespace != namespace.as_bytes() {
        return Err(SshsigError::WrongNamespace);
    }
    let signed = signed_data(parsed.namespace, parsed.hash, message);
    let verifying = VerifyingKey::from_bytes(key).map_err(|_| SshsigError::InvalidKey)?;
    let signature = ed25519_dalek::Signature::from_bytes(parsed.signature);
    verifying
        .verify(&signed, &signature)
        .map_err(|_| SshsigError::InvalidSignature)
}

/// The hash a signature was made over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SigHash {
    Sha512,
    Sha256,
}

impl SigHash {
    const fn name(self) -> &'static [u8] {
        match self {
            Self::Sha512 => b"sha512",
            Self::Sha256 => b"sha256",
        }
    }

    fn digest(self, message: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha512 => Sha512::digest(message).to_vec(),
            Self::Sha256 => Sha256::digest(message).to_vec(),
        }
    }
}

/// The fields of a structurally valid blob.
#[derive(Debug)]
struct Parsed<'a> {
    public_key: &'a [u8; 32],
    namespace: &'a [u8],
    hash: SigHash,
    signature: &'a [u8; 64],
}

/// Strip the armor and decode the base64 body.
fn dearmor(armored: &[u8]) -> Result<Vec<u8>, SshsigError> {
    if armored.len() > MAX_ARMORED_SIZE {
        return Err(SshsigError::TooLarge {
            size: armored.len(),
        });
    }
    let text = std::str::from_utf8(armored).map_err(|_| SshsigError::Armor("not UTF-8"))?;
    let rest = text
        .strip_prefix(BEGIN)
        .ok_or(SshsigError::Armor("missing begin marker"))?;
    let rest = rest.strip_suffix('\n').unwrap_or(rest);
    let body = rest
        .strip_suffix(END)
        .ok_or(SshsigError::Armor("missing end marker"))?;
    let mut encoded = String::with_capacity(body.len());
    for line in body.split('\n') {
        if line.is_empty() {
            return Err(SshsigError::Armor("empty line"));
        }
        encoded.push_str(line);
    }
    // Rejects everything outside the alphabet — `\r` and spaces included —
    // and a non-canonical or missing padding.
    STANDARD
        .decode(encoded)
        .map_err(|_| SshsigError::Armor("invalid base64"))
}

/// A reader over an SSH wire blob. Every read is bounds-checked.
struct Cursor<'a>(&'a [u8]);

impl<'a> Cursor<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8], SshsigError> {
        let (taken, rest) = self
            .0
            .split_at_checked(len)
            .ok_or(SshsigError::Malformed("truncated"))?;
        self.0 = rest;
        Ok(taken)
    }

    fn uint32(&mut self) -> Result<u32, SshsigError> {
        let bytes = self.take(4)?;
        <[u8; 4]>::try_from(bytes)
            .map(u32::from_be_bytes)
            .map_err(|_| SshsigError::Malformed("truncated"))
    }

    /// An SSH `string`: a `uint32` length, then that many bytes.
    fn string(&mut self) -> Result<&'a [u8], SshsigError> {
        let len =
            usize::try_from(self.uint32()?).map_err(|_| SshsigError::Malformed("truncated"))?;
        self.take(len)
    }

    const fn finish(&self, trailing: &'static str) -> Result<(), SshsigError> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(SshsigError::Malformed(trailing))
        }
    }
}

/// Parse the decoded blob, holding every field to its exact form.
fn parse_blob(blob: &[u8]) -> Result<Parsed<'_>, SshsigError> {
    let mut cursor = Cursor(blob);
    if cursor.take(MAGIC.len())? != MAGIC {
        return Err(SshsigError::Malformed("bad magic"));
    }
    let version = cursor.uint32()?;
    if version != VERSION {
        return Err(SshsigError::UnsupportedVersion(version));
    }
    let public_key = cursor.string()?;
    let namespace = cursor.string()?;
    let reserved = cursor.string()?;
    let hash = cursor.string()?;
    let signature = cursor.string()?;
    cursor.finish("trailing bytes after the signature")?;

    let mut key = Cursor(public_key);
    if key.string()? != SSH_ED25519.as_bytes() {
        return Err(SshsigError::UnsupportedKeyType);
    }
    let public_key = <&[u8; 32]>::try_from(key.string()?)
        .map_err(|_| SshsigError::Malformed("public key is not 32 bytes"))?;
    key.finish("trailing bytes after the public key")?;

    if !reserved.is_empty() {
        return Err(SshsigError::Malformed("reserved field is not empty"));
    }
    let hash = if hash == SigHash::Sha512.name() {
        SigHash::Sha512
    } else if hash == SigHash::Sha256.name() {
        SigHash::Sha256
    } else {
        return Err(SshsigError::UnsupportedHashAlgorithm);
    };

    let mut sig = Cursor(signature);
    if sig.string()? != SSH_ED25519.as_bytes() {
        return Err(SshsigError::UnsupportedSignatureType);
    }
    let signature = <&[u8; 64]>::try_from(sig.string()?)
        .map_err(|_| SshsigError::Malformed("signature is not 64 bytes"))?;
    sig.finish("trailing bytes inside the signature field")?;

    Ok(Parsed {
        public_key,
        namespace,
        hash,
        signature,
    })
}

/// The bytes an `sshsig` signature covers.
fn signed_data(namespace: &[u8], hash: SigHash, message: &[u8]) -> Vec<u8> {
    let digest = hash.digest(message);
    let mut out = Vec::with_capacity(MAGIC.len() + 16 + namespace.len() + 6 + digest.len());
    out.extend_from_slice(MAGIC);
    push_string(&mut out, namespace);
    push_string(&mut out, b"");
    push_string(&mut out, hash.name());
    push_string(&mut out, &digest);
    out
}

/// Append an SSH `string`. The lengths written here are a namespace that was
/// read out of a bounded blob, a fixed name, and a digest, so each fits.
fn push_string(out: &mut Vec<u8>, bytes: &[u8]) {
    let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
}

#[cfg(test)]
mod tests {
    //! The fixtures under `tests/fixtures/sshsig/` are real `ssh-keygen`
    //! output (OpenSSH 10), so the suite needs no `ssh-keygen` to run. To
    //! regenerate them, in an empty directory:
    //!
    //! ```sh
    //! ssh-keygen -q -t ed25519 -N '' -C 'fuz sshsig test fixture' -f key
    //! ssh-keygen -q -t ed25519 -N '' -C other -f other
    //! ssh-keygen -q -t rsa -b 2048 -N '' -C rsa -f rsa
    //! printf '7 %s\n' "$(printf 'head bytes' | sha512sum | cut -d' ' -f1)" > message
    //! ssh-keygen -q -Y sign -n fuz_release_log -f key - < message > message.sha512.sig
    //! ssh-keygen -q -Y sign -n fuz_release_log -O hashalg=sha256 -f key - < message > message.sha256.sig
    //! ssh-keygen -q -Y sign -n other_namespace -f key - < message > message.other-namespace.sig
    //! ssh-keygen -q -Y sign -n fuz_release_log -f other - < message > message.other-key.sig
    //! ssh-keygen -q -Y sign -n fuz_release_log -f rsa - < message > message.rsa.sig
    //! ```
    //!
    //! and keep `message`, the `.sig` files, `key.pub`, and `other.pub`. The
    //! private keys are thrown away; nothing here needs them.

    use super::*;
    use crate::witness::parse_public_key_line;
    use ed25519_dalek::{Signer, SigningKey};

    const NAMESPACE: &str = "fuz_release_log";
    const MESSAGE: &[u8] = include_bytes!("../tests/fixtures/sshsig/message");
    const SIG_SHA512: &str = include_str!("../tests/fixtures/sshsig/message.sha512.sig");
    const SIG_SHA256: &str = include_str!("../tests/fixtures/sshsig/message.sha256.sig");
    const SIG_OTHER_NAMESPACE: &str =
        include_str!("../tests/fixtures/sshsig/message.other-namespace.sig");
    const SIG_OTHER_KEY: &str = include_str!("../tests/fixtures/sshsig/message.other-key.sig");
    const SIG_RSA: &str = include_str!("../tests/fixtures/sshsig/message.rsa.sig");
    const KEY_PUB: &str = include_str!("../tests/fixtures/sshsig/key.pub");
    const OTHER_PUB: &str = include_str!("../tests/fixtures/sshsig/other.pub");

    fn fixture_key() -> [u8; 32] {
        parse_public_key_line(KEY_PUB.trim_end_matches('\n')).unwrap()
    }

    fn other_key() -> [u8; 32] {
        parse_public_key_line(OTHER_PUB.trim_end_matches('\n')).unwrap()
    }

    fn verify(armored: &str) -> Result<(), SshsigError> {
        verify_sshsig(armored.as_bytes(), MESSAGE, NAMESPACE, &fixture_key())
    }

    /// The decoded blob of an armored fixture.
    fn blob_of(armored: &str) -> Vec<u8> {
        dearmor(armored.as_bytes()).unwrap()
    }

    /// Armor a blob the way `ssh-keygen` does: 70 base64 characters a line.
    fn armor(blob: &[u8]) -> String {
        let encoded = STANDARD.encode(blob);
        let mut out = String::from(BEGIN);
        for chunk in encoded.as_bytes().chunks(70) {
            out.push_str(std::str::from_utf8(chunk).unwrap());
            out.push('\n');
        }
        out.push_str("-----END SSH SIGNATURE-----\n");
        out
    }

    fn string(bytes: &[u8]) -> Vec<u8> {
        let mut out = u32::try_from(bytes.len()).unwrap().to_be_bytes().to_vec();
        out.extend_from_slice(bytes);
        out
    }

    /// The parts of a blob, each replaceable, so one field can be wrong at a
    /// time.
    #[derive(Clone)]
    struct Parts {
        magic: Vec<u8>,
        version: u32,
        key_type: Vec<u8>,
        key: Vec<u8>,
        key_trailer: Vec<u8>,
        namespace: Vec<u8>,
        reserved: Vec<u8>,
        hash: Vec<u8>,
        sig_type: Vec<u8>,
        sig: Vec<u8>,
        sig_trailer: Vec<u8>,
        trailer: Vec<u8>,
    }

    impl Parts {
        /// A blob signed by `key` over `message` — built here, independently
        /// of the verifier's own `signed_data`.
        fn signed(key: &SigningKey, namespace: &str, hash: &str, message: &[u8]) -> Self {
            let digest = match hash {
                "sha256" => Sha256::digest(message).to_vec(),
                _ => Sha512::digest(message).to_vec(),
            };
            let mut signed = b"SSHSIG".to_vec();
            signed.extend(string(namespace.as_bytes()));
            signed.extend(string(b""));
            signed.extend(string(hash.as_bytes()));
            signed.extend(string(&digest));
            Self {
                magic: b"SSHSIG".to_vec(),
                version: 1,
                key_type: b"ssh-ed25519".to_vec(),
                key: key.verifying_key().as_bytes().to_vec(),
                key_trailer: Vec::new(),
                namespace: namespace.as_bytes().to_vec(),
                reserved: Vec::new(),
                hash: hash.as_bytes().to_vec(),
                sig_type: b"ssh-ed25519".to_vec(),
                sig: key.sign(&signed).to_bytes().to_vec(),
                sig_trailer: Vec::new(),
                trailer: Vec::new(),
            }
        }

        fn blob(&self) -> Vec<u8> {
            let mut key = string(&self.key_type);
            key.extend(string(&self.key));
            key.extend_from_slice(&self.key_trailer);
            let mut sig = string(&self.sig_type);
            sig.extend(string(&self.sig));
            sig.extend_from_slice(&self.sig_trailer);

            let mut out = self.magic.clone();
            out.extend_from_slice(&self.version.to_be_bytes());
            out.extend(string(&key));
            out.extend(string(&self.namespace));
            out.extend(string(&self.reserved));
            out.extend(string(&self.hash));
            out.extend(string(&sig));
            out.extend_from_slice(&self.trailer);
            out
        }

        fn armored(&self) -> String {
            armor(&self.blob())
        }
    }

    fn signer() -> SigningKey {
        SigningKey::from_bytes(&[5u8; 32])
    }

    fn sample() -> Parts {
        Parts::signed(&signer(), NAMESPACE, "sha512", MESSAGE)
    }

    fn verify_parts(parts: &Parts) -> Result<(), SshsigError> {
        verify_sshsig(
            parts.armored().as_bytes(),
            MESSAGE,
            NAMESPACE,
            signer().verifying_key().as_bytes(),
        )
    }

    //
    // Real ssh-keygen output
    //

    #[test]
    fn real_signatures_verify_with_either_hash() {
        assert_eq!(verify(SIG_SHA512), Ok(()));
        assert_eq!(verify(SIG_SHA256), Ok(()));
        assert_eq!(
            parse_blob(&blob_of(SIG_SHA512)).unwrap().hash,
            SigHash::Sha512
        );
        assert_eq!(
            parse_blob(&blob_of(SIG_SHA256)).unwrap().hash,
            SigHash::Sha256
        );
        // Without the final newline, too.
        assert_eq!(verify(SIG_SHA512.trim_end_matches('\n')), Ok(()));
        // The body's line breaks may fall anywhere: one line, and 64-character
        // lines, are the same signature as `ssh-keygen`'s 70.
        let encoded = STANDARD.encode(blob_of(SIG_SHA512));
        let wrapped = |width: usize| {
            let lines: Vec<&str> = encoded
                .as_bytes()
                .chunks(width)
                .map(|chunk| std::str::from_utf8(chunk).unwrap())
                .collect();
            format!("{BEGIN}{}\n-----END SSH SIGNATURE-----\n", lines.join("\n"))
        };
        assert_eq!(wrapped(70), SIG_SHA512);
        assert_eq!(verify(&wrapped(encoded.len())), Ok(()));
        assert_eq!(verify(&wrapped(64)), Ok(()));
        assert_eq!(verify(&wrapped(1)), Ok(()));
    }

    #[test]
    fn the_test_armor_is_the_armor_ssh_keygen_writes() {
        for fixture in [SIG_SHA512, SIG_SHA256, SIG_RSA] {
            assert_eq!(armor(&blob_of(fixture)), fixture);
        }
    }

    #[test]
    fn a_signature_over_a_different_message_does_not_verify() {
        let mut other = MESSAGE.to_vec();
        other[0] ^= 1;
        for sig in [SIG_SHA512, SIG_SHA256] {
            assert_eq!(
                verify_sshsig(sig.as_bytes(), &other, NAMESPACE, &fixture_key()),
                Err(SshsigError::InvalidSignature)
            );
            // The message without its newline is another message.
            assert_eq!(
                verify_sshsig(
                    sig.as_bytes(),
                    &MESSAGE[..MESSAGE.len() - 1],
                    NAMESPACE,
                    &fixture_key()
                ),
                Err(SshsigError::InvalidSignature)
            );
        }
    }

    #[test]
    fn a_signature_for_another_namespace_is_refused() {
        // Made by the right key over the right message with another `-n`.
        assert_eq!(
            verify(SIG_OTHER_NAMESPACE),
            Err(SshsigError::WrongNamespace)
        );
        // It is a good signature under its own namespace.
        assert_eq!(
            verify_sshsig(
                SIG_OTHER_NAMESPACE.as_bytes(),
                MESSAGE,
                "other_namespace",
                &fixture_key()
            ),
            Ok(())
        );
        // And the expected namespace is matched exactly.
        for namespace in ["fuz_release_lo", "fuz_release_log ", "FUZ_RELEASE_LOG", ""] {
            assert_eq!(
                verify_sshsig(SIG_SHA512.as_bytes(), MESSAGE, namespace, &fixture_key()),
                Err(SshsigError::WrongNamespace),
                "{namespace:?}"
            );
        }
    }

    #[test]
    fn a_valid_signature_by_another_key_is_refused() {
        // A good signature — by a key that is not the expected one.
        assert_eq!(verify(SIG_OTHER_KEY), Err(SshsigError::WrongKey));
        assert_eq!(
            verify_sshsig(SIG_OTHER_KEY.as_bytes(), MESSAGE, NAMESPACE, &other_key()),
            Ok(())
        );
        assert_eq!(
            verify_sshsig(SIG_SHA512.as_bytes(), MESSAGE, NAMESPACE, &other_key()),
            Err(SshsigError::WrongKey)
        );
    }

    #[test]
    fn a_real_rsa_signature_is_refused_by_key_type() {
        assert_eq!(verify(SIG_RSA), Err(SshsigError::UnsupportedKeyType));
    }

    #[test]
    fn swapping_the_embedded_key_for_the_expected_one_does_not_verify() {
        // The other key's signature, relabelled as the expected key's.
        let mut blob = blob_of(SIG_OTHER_KEY);
        let at = blob
            .windows(32)
            .position(|window| window == other_key())
            .unwrap();
        blob[at..at + 32].copy_from_slice(&fixture_key());
        assert_eq!(verify(&armor(&blob)), Err(SshsigError::InvalidSignature));
    }

    #[test]
    fn relabelling_the_hash_algorithm_does_not_verify() {
        // The sha512 fixture with its hash name flipped to sha256, and back.
        for (fixture, from, to) in [
            (SIG_SHA512, b"sha512", b"sha256"),
            (SIG_SHA256, b"sha256", b"sha512"),
        ] {
            let mut blob = blob_of(fixture);
            let at = blob.windows(6).position(|window| window == from).unwrap();
            blob[at..at + 6].copy_from_slice(to);
            assert_eq!(
                verify(&armor(&blob)),
                Err(SshsigError::InvalidSignature),
                "{fixture}"
            );
        }
    }

    #[test]
    fn every_truncation_of_a_real_blob_is_an_error() {
        for fixture in [SIG_SHA512, SIG_SHA256, SIG_RSA] {
            let blob = blob_of(fixture);
            for len in 0..blob.len() {
                let result = verify(&armor(&blob[..len]));
                assert!(
                    matches!(
                        result,
                        Err(SshsigError::Malformed(_) | SshsigError::Armor(_))
                    ),
                    "prefix {len} of {}: {result:?}",
                    blob.len()
                );
            }
        }
    }

    #[test]
    fn every_single_byte_change_to_a_real_blob_is_an_error() {
        let blob = blob_of(SIG_SHA512);
        for at in 0..blob.len() {
            let mut changed = blob.clone();
            changed[at] ^= 0x01;
            assert!(verify(&armor(&changed)).is_err(), "byte {at}");
        }
    }

    //
    // Armor
    //

    #[test]
    fn armor_outside_the_accepted_subset_is_refused() {
        let body = SIG_SHA512
            .strip_prefix(BEGIN)
            .unwrap()
            .strip_suffix("\n-----END SSH SIGNATURE-----\n")
            .unwrap();
        let cases: Vec<(&str, String)> = vec![
            ("empty", String::new()),
            ("no begin", format!("{body}\n-----END SSH SIGNATURE-----\n")),
            ("no end", format!("{BEGIN}{body}\n")),
            ("no body", format!("{BEGIN}-----END SSH SIGNATURE-----\n")),
            (
                "empty body",
                format!("{BEGIN}\n-----END SSH SIGNATURE-----\n"),
            ),
            ("leading newline", format!("\n{SIG_SHA512}")),
            ("leading space", format!(" {SIG_SHA512}")),
            ("two trailing newlines", format!("{SIG_SHA512}\n")),
            (
                "text after the end marker",
                format!("{SIG_SHA512}trailing\n"),
            ),
            ("crlf line endings", SIG_SHA512.replace('\n', "\r\n")),
            (
                "a blank line in the body",
                SIG_SHA512.replacen("\nplc", "\n\nplc", 1),
            ),
            (
                "a space in the body",
                SIG_SHA512.replacen("\nplc", " \nplc", 1),
            ),
            (
                "garbage base64",
                format!("{BEGIN}@@@@\n-----END SSH SIGNATURE-----\n"),
            ),
            (
                "padding dropped",
                SIG_SHA512.replacen("=\n-----END", "\n-----END", 1),
            ),
            (
                "another marker",
                SIG_SHA512.replace("SSH SIGNATURE", "PGP SIGNATURE"),
            ),
            ("doubled", format!("{SIG_SHA512}{SIG_SHA512}")),
        ];
        for (case, armored) in cases {
            let result = verify(&armored);
            assert!(
                matches!(result, Err(SshsigError::Armor(_))),
                "{case}: {result:?}"
            );
        }
        assert_eq!(
            verify_sshsig(&[0xff, 0xfe], MESSAGE, NAMESPACE, &fixture_key()),
            Err(SshsigError::Armor("not UTF-8"))
        );
    }

    #[test]
    fn an_oversized_input_is_refused_before_it_is_decoded() {
        // Valid armor around a body past the bound.
        let blob = vec![0u8; MAX_ARMORED_SIZE];
        let armored = armor(&blob);
        assert!(armored.len() > MAX_ARMORED_SIZE);
        assert_eq!(
            verify(&armored),
            Err(SshsigError::TooLarge {
                size: armored.len()
            })
        );
        // At the bound the size check passes and the armor is read.
        let at_bound = vec![b'x'; MAX_ARMORED_SIZE];
        assert!(matches!(
            verify_sshsig(&at_bound, MESSAGE, NAMESPACE, &fixture_key()),
            Err(SshsigError::Armor(_))
        ));
    }

    //
    // A blob built here, one field wrong at a time
    //

    #[test]
    fn a_blob_built_here_verifies_with_either_hash() {
        assert_eq!(verify_parts(&sample()), Ok(()));
        let sha256 = Parts::signed(&signer(), NAMESPACE, "sha256", MESSAGE);
        assert_eq!(verify_parts(&sha256), Ok(()));
        // An empty message is a message.
        let empty = Parts::signed(&signer(), NAMESPACE, "sha512", b"");
        assert_eq!(
            verify_sshsig(
                empty.armored().as_bytes(),
                b"",
                NAMESPACE,
                signer().verifying_key().as_bytes()
            ),
            Ok(())
        );
    }

    #[test]
    fn the_signed_bytes_are_the_documented_construction() {
        let digest = Sha512::digest(MESSAGE);
        let mut expected = b"SSHSIG".to_vec();
        expected.extend(string(NAMESPACE.as_bytes()));
        expected.extend(string(b""));
        expected.extend(string(b"sha512"));
        expected.extend(string(&digest));
        assert_eq!(
            signed_data(NAMESPACE.as_bytes(), SigHash::Sha512, MESSAGE),
            expected
        );
        // And they are what the real signature covers.
        let parsed_blob = blob_of(SIG_SHA512);
        let parsed = parse_blob(&parsed_blob).unwrap();
        let key = VerifyingKey::from_bytes(&fixture_key()).unwrap();
        key.verify(
            &expected,
            &ed25519_dalek::Signature::from_bytes(parsed.signature),
        )
        .unwrap();
    }

    #[test]
    fn each_malformed_field_is_refused() {
        type Change = fn(&mut Parts);
        let cases: Vec<(&str, Change, SshsigError)> = vec![
            (
                "bad magic",
                |p| p.magic = b"SSHSIX".to_vec(),
                SshsigError::Malformed("bad magic"),
            ),
            (
                "lowercase magic",
                |p| p.magic = b"sshsig".to_vec(),
                SshsigError::Malformed("bad magic"),
            ),
            (
                "version 2",
                |p| p.version = 2,
                SshsigError::UnsupportedVersion(2),
            ),
            (
                "version 0",
                |p| p.version = 0,
                SshsigError::UnsupportedVersion(0),
            ),
            (
                "rsa key type",
                |p| p.key_type = b"ssh-rsa".to_vec(),
                SshsigError::UnsupportedKeyType,
            ),
            (
                "ecdsa key type",
                |p| p.key_type = b"ecdsa-sha2-nistp256".to_vec(),
                SshsigError::UnsupportedKeyType,
            ),
            (
                "security-key type",
                |p| p.key_type = b"sk-ssh-ed25519@openssh.com".to_vec(),
                SshsigError::UnsupportedKeyType,
            ),
            (
                "31-byte key",
                |p| {
                    p.key.pop();
                },
                SshsigError::Malformed("public key is not 32 bytes"),
            ),
            (
                "33-byte key",
                |p| p.key.push(0),
                SshsigError::Malformed("public key is not 32 bytes"),
            ),
            (
                "bytes after the key",
                |p| p.key_trailer = vec![0],
                SshsigError::Malformed("trailing bytes after the public key"),
            ),
            (
                "reserved not empty",
                |p| p.reserved = b"x".to_vec(),
                SshsigError::Malformed("reserved field is not empty"),
            ),
            (
                "unknown hash",
                |p| p.hash = b"sha1".to_vec(),
                SshsigError::UnsupportedHashAlgorithm,
            ),
            (
                "uppercase hash",
                |p| p.hash = b"SHA512".to_vec(),
                SshsigError::UnsupportedHashAlgorithm,
            ),
            (
                "empty hash",
                |p| p.hash = Vec::new(),
                SshsigError::UnsupportedHashAlgorithm,
            ),
            (
                "rsa signature type",
                |p| p.sig_type = b"rsa-sha2-512".to_vec(),
                SshsigError::UnsupportedSignatureType,
            ),
            (
                "63-byte signature",
                |p| {
                    p.sig.pop();
                },
                SshsigError::Malformed("signature is not 64 bytes"),
            ),
            (
                "65-byte signature",
                |p| p.sig.push(0),
                SshsigError::Malformed("signature is not 64 bytes"),
            ),
            (
                "bytes inside the signature field",
                |p| p.sig_trailer = vec![0],
                SshsigError::Malformed("trailing bytes inside the signature field"),
            ),
            (
                "bytes after the signature",
                |p| p.trailer = vec![0],
                SshsigError::Malformed("trailing bytes after the signature"),
            ),
            (
                "a second blob after the first",
                |p| p.trailer = sample().blob(),
                SshsigError::Malformed("trailing bytes after the signature"),
            ),
            (
                "another namespace",
                |p| p.namespace = b"file".to_vec(),
                SshsigError::WrongNamespace,
            ),
            (
                "a zeroed signature",
                |p| p.sig = vec![0; 64],
                SshsigError::InvalidSignature,
            ),
        ];
        for (case, change, expected) in cases {
            let mut parts = sample();
            change(&mut parts);
            assert_eq!(verify_parts(&parts), Err(expected), "{case}");
        }
    }

    #[test]
    fn a_length_that_overruns_the_blob_is_refused() {
        let good = sample().blob();
        // Every length prefix in the blob, set past the end: the first four
        // bytes after the magic and version, then each field in turn.
        let mut offsets = vec![10];
        let mut cursor = Cursor(&good[10..]);
        for _ in 0..4 {
            let before = cursor.0.len();
            cursor.string().unwrap();
            offsets.push(offsets.last().unwrap() + (before - cursor.0.len()));
        }
        assert_eq!(offsets.len(), 5);
        for at in offsets {
            for len in [u32::MAX, u32::try_from(good.len()).unwrap(), 0x7fff_ffff] {
                let mut blob = good.clone();
                blob[at..at + 4].copy_from_slice(&len.to_be_bytes());
                let result = verify_sshsig(
                    armor(&blob).as_bytes(),
                    MESSAGE,
                    NAMESPACE,
                    signer().verifying_key().as_bytes(),
                );
                assert_eq!(
                    result,
                    Err(SshsigError::Malformed("truncated")),
                    "length at {at} = {len}"
                );
            }
        }
    }

    #[test]
    fn a_key_that_is_not_a_curve_point_is_refused_without_panicking() {
        // A blob claiming such a key, checked against that same key.
        let bad = (0..=255u8)
            .map(|fill| [fill; 32])
            .find(|key| VerifyingKey::from_bytes(key).is_err())
            .expect("some repeated byte is not a point");
        let mut parts = sample();
        parts.key = bad.to_vec();
        assert_eq!(
            verify_sshsig(parts.armored().as_bytes(), MESSAGE, NAMESPACE, &bad),
            Err(SshsigError::InvalidKey)
        );
    }

    #[test]
    fn errors_are_classified_and_bounded() {
        let all = [
            (SshsigError::TooLarge { size: 9999 }, false),
            (SshsigError::Armor("x"), false),
            (SshsigError::Malformed("x"), false),
            (SshsigError::UnsupportedVersion(2), false),
            (SshsigError::UnsupportedKeyType, false),
            (SshsigError::UnsupportedSignatureType, false),
            (SshsigError::UnsupportedHashAlgorithm, false),
            (SshsigError::InvalidKey, false),
            (SshsigError::WrongKey, true),
            (SshsigError::WrongNamespace, true),
            (SshsigError::InvalidSignature, true),
        ];
        for (error, expected) in all {
            assert_eq!(error.is_verification_failure(), expected, "{error}");
            assert!(error.to_string().len() < 128, "{error}");
        }
    }
}
