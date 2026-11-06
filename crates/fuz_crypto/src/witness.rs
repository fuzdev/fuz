//! Witness keys: the SSH public keys of release log co-signers.
//!
//! A **co-signer** is an independent party that fetches the release log head,
//! and publishes — at an origin of its own — a statement of which head it saw,
//! signed with an SSH key (`ssh-keygen -Y sign`, verified by
//! [`crate::sshsig`]). The public half of that key is embedded in the binary,
//! paired with the origin it speaks for: the `witnesses` list of
//! `public_keys.json`, generated into [`crate::WITNESS_KEYS`].
//!
//! **A witness key is never a release key.** It verifies a co-signature and
//! nothing else: [`crate::is_trusted_key`] reads [`crate::PUBLIC_KEYS`] alone,
//! so a manifest or a head signed by a witness key is refused as untrusted. The
//! two sets are generated as separate items, and the build refuses a key that
//! is in both ([`check_witnesses`]).
//!
//! This file is compiled twice: as this module, and — through a `#[path]`
//! include — by the crate's build script, which validates `public_keys.json`
//! with [`check_witnesses`]. The rules the build applies are therefore the
//! ones tested here. It depends on `std` and `base64` only, the build script's
//! own dependencies.

use std::fmt;

use base64::{Engine, engine::general_purpose::STANDARD};

/// The key-type token of an ed25519 SSH key, on a public-key line and inside
/// every SSH wire blob.
pub const SSH_ED25519: &str = "ssh-ed25519";

/// Longest public-key line read. A real line is under a hundred bytes plus its
/// comment.
const MAX_KEY_LINE_LEN: usize = 1024;

/// The wire blob of an ed25519 public key, up to the key bytes: the `string`
/// `ssh-ed25519`, then the length prefix of a 32-byte `string`.
const ED25519_BLOB_PREFIX: [u8; 19] = [
    0, 0, 0, 11, b's', b's', b'h', b'-', b'e', b'd', b'2', b'5', b'5', b'1', b'9', 0, 0, 0, 32,
];

/// Why a line is not an ed25519 SSH public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicKeyLineError {
    /// Longer than any public-key line.
    TooLong,
    /// A control character, a line break, or doubled or leading whitespace.
    NotOneLine,
    /// The key type is not `ssh-ed25519`.
    NotEd25519,
    /// No key follows the key type.
    MissingKey,
    /// The key is not base64.
    Base64,
    /// The decoded key is not the blob of one 32-byte ed25519 key.
    Blob,
}

impl fmt::Display for PublicKeyLineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::TooLong => "the line is too long",
            Self::NotOneLine => "not a single line of the form \"ssh-ed25519 <base64> [comment]\"",
            Self::NotEd25519 => "the key type is not ssh-ed25519",
            Self::MissingKey => "no key follows the key type",
            Self::Base64 => "the key is not valid base64",
            Self::Blob => "the key is not the blob of one 32-byte ed25519 key",
        })
    }
}

impl std::error::Error for PublicKeyLineError {}

/// Parse an SSH public-key line — what `ssh-keygen` writes to a `.pub` file —
/// into the 32 bytes of its ed25519 key.
///
/// The accepted form is `ssh-ed25519 <base64> [comment]`: the type token, one
/// space, the key, and optionally one space and a comment. No leading
/// whitespace, no options prefix, no line break. The decoded key must be
/// exactly the SSH wire blob of an ed25519 key: the `string` `ssh-ed25519`
/// followed by a 32-byte `string`, with nothing after it. The comment is not
/// interpreted.
///
/// Whether the 32 bytes are a valid curve point is not checked here; a
/// verification with the key is ([`crate::sshsig::verify_sshsig`]).
///
/// # Errors
///
/// A [`PublicKeyLineError`] naming the first rule the line breaks.
pub fn parse_public_key_line(line: &str) -> Result<[u8; 32], PublicKeyLineError> {
    if line.len() > MAX_KEY_LINE_LEN {
        return Err(PublicKeyLineError::TooLong);
    }
    if line.chars().any(char::is_control) {
        return Err(PublicKeyLineError::NotOneLine);
    }
    let mut parts = line.splitn(3, ' ');
    let key_type = parts.next().unwrap_or_default();
    if key_type.is_empty() {
        return Err(PublicKeyLineError::NotOneLine);
    }
    if key_type != SSH_ED25519 {
        return Err(PublicKeyLineError::NotEd25519);
    }
    let encoded = match parts.next() {
        None => return Err(PublicKeyLineError::MissingKey),
        // A doubled space after the type.
        Some("") => return Err(PublicKeyLineError::NotOneLine),
        Some(encoded) => encoded,
    };
    let blob = STANDARD
        .decode(encoded)
        .map_err(|_| PublicKeyLineError::Base64)?;
    let key = blob
        .strip_prefix(&ED25519_BLOB_PREFIX)
        .ok_or(PublicKeyLineError::Blob)?;
    <[u8; 32]>::try_from(key).map_err(|_| PublicKeyLineError::Blob)
}

/// The form of an origin that witness keys are matched in: the origin with its
/// trailing slashes removed.
///
/// Everything else is compared exactly — scheme, host, and path are matched
/// byte for byte, with no case folding and no default-port or percent-encoding
/// equivalence — so `https://log.example.com` and `https://log.example.com/`
/// are one origin and `https://LOG.example.com` is another. An origin that is
/// nothing but slashes (the local root directory) is kept as `/`.
#[must_use]
pub fn normalize_origin(origin: &str) -> &str {
    let trimmed = origin.trim_end_matches('/');
    if trimmed.is_empty() && !origin.is_empty() {
        "/"
    } else {
        trimmed
    }
}

/// Why an origin cannot be embedded with a witness key.
///
/// # Errors
///
/// The rule the origin breaks, as text for the build's error.
fn check_embedded_origin(origin: &str) -> Result<(), &'static str> {
    if origin.is_empty() {
        return Err("the origin is empty");
    }
    // What a configured origin can be told apart by: the client's list is
    // comma-separated and whitespace-trimmed.
    if !origin.bytes().all(|b| b.is_ascii_graphic() && b != b',') {
        return Err("the origin has a character outside printable ASCII, a space, or a comma");
    }
    let Some(rest) = origin.strip_prefix("https://") else {
        return Err("the origin is not an https:// URL");
    };
    if rest.is_empty() || rest.starts_with('/') {
        return Err("the origin has no host");
    }
    // A configured origin with any of these is refused or never equal, so an
    // embedded one could not match.
    let authority = rest.split('/').next().unwrap_or(rest);
    if authority.contains('@') || rest.contains(['?', '#']) {
        return Err("the origin has userinfo, a query, or a fragment");
    }
    if normalize_origin(origin) != origin {
        return Err("the origin ends with a slash (embed it without one)");
    }
    Ok(())
}

/// Why a `witnesses` list cannot be embedded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WitnessKeyError {
    /// The entry's origin is not in the form the client matches.
    Origin {
        /// 0-based position in the list.
        index: usize,
        /// The rule the origin breaks.
        reason: &'static str,
    },
    /// The entry's key is not an ed25519 SSH public-key line.
    KeyLine {
        /// 0-based position in the list.
        index: usize,
        /// Why the line was refused.
        source: PublicKeyLineError,
    },
    /// Two entries name the same origin.
    DuplicateOrigin {
        /// 0-based position of the second entry.
        index: usize,
    },
    /// The entry's key is also a release key. A key is one or the other.
    ReleaseKey {
        /// 0-based position in the list.
        index: usize,
    },
}

impl fmt::Display for WitnessKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Origin { index, reason } => write!(f, "witnesses[{index}]: {reason}"),
            Self::KeyLine { index, source } => {
                write!(f, "witnesses[{index}]: invalid ssh_public_key: {source}")
            }
            Self::DuplicateOrigin { index } => {
                write!(f, "witnesses[{index}]: the origin is already listed")
            }
            Self::ReleaseKey { index } => write!(
                f,
                "witnesses[{index}]: the key is also a release key - a witness key must never \
                 be trusted to sign a release"
            ),
        }
    }
}

impl std::error::Error for WitnessKeyError {}

/// Validate a `witnesses` list — `(origin, public-key line)` pairs — against
/// the release keys, returning each origin with its decoded key.
///
/// The check the build runs over `public_keys.json`:
///
/// - each origin is an `https://` URL with a host, in printable ASCII with no
///   comma, no userinfo, query, or fragment, and already in
///   [`normalize_origin`]'s form — so an origin that
///   could never match a configured one fails the build instead of leaving a
///   co-signature unchecked;
/// - each key is an ed25519 public-key line ([`parse_public_key_line`]);
/// - no origin is listed twice;
/// - no witness key is a release key.
///
/// One key may speak for several origins.
///
/// # Errors
///
/// A [`WitnessKeyError`] for the first entry that breaks a rule.
pub fn check_witnesses(
    entries: &[(&str, &str)],
    release_keys: &[[u8; 32]],
) -> Result<Vec<(String, [u8; 32])>, WitnessKeyError> {
    let mut checked: Vec<(String, [u8; 32])> = Vec::with_capacity(entries.len());
    for (index, (origin, line)) in entries.iter().enumerate() {
        check_embedded_origin(origin)
            .map_err(|reason| WitnessKeyError::Origin { index, reason })?;
        let key = parse_public_key_line(line)
            .map_err(|source| WitnessKeyError::KeyLine { index, source })?;
        if checked.iter().any(|(seen, _)| seen == origin) {
            return Err(WitnessKeyError::DuplicateOrigin { index });
        }
        if release_keys.contains(&key) {
            return Err(WitnessKeyError::ReleaseKey { index });
        }
        checked.push(((*origin).to_string(), key));
    }
    Ok(checked)
}

/// The witness key embedded for `origin`, if any: the first entry of `keys`
/// whose origin is `origin` once both are in [`normalize_origin`]'s form.
#[must_use]
pub fn witness_key_for(origin: &str, keys: &[(&str, [u8; 32])]) -> Option<[u8; 32]> {
    let origin = normalize_origin(origin);
    keys.iter()
        .find(|(embedded, _)| normalize_origin(embedded) == origin)
        .map(|(_, key)| *key)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The public half of the committed sshsig fixture key.
    const KEY_LINE: &str = include_str!("../tests/fixtures/sshsig/key.pub");
    const ORIGIN: &str = "https://cosigner.example.com/log";

    fn key_line() -> &'static str {
        KEY_LINE.trim_end_matches('\n')
    }

    /// A public-key line for `key` with an optional comment.
    fn line_for(key: &[u8; 32], comment: Option<&str>) -> String {
        let mut blob = ED25519_BLOB_PREFIX.to_vec();
        blob.extend_from_slice(key);
        let encoded = STANDARD.encode(blob);
        comment.map_or_else(
            || format!("{SSH_ED25519} {encoded}"),
            |comment| format!("{SSH_ED25519} {encoded} {comment}"),
        )
    }

    #[test]
    fn a_real_public_key_line_parses_with_or_without_a_comment() {
        let key = parse_public_key_line(key_line()).unwrap();
        // The same key with the comment cut off, and with a comment of several
        // words.
        let bare = line_for(&key, None);
        assert_eq!(parse_public_key_line(&bare).unwrap(), key);
        let wordy = line_for(&key, Some("a comment  with spaces"));
        assert_eq!(parse_public_key_line(&wordy).unwrap(), key);
        assert!(key_line().starts_with(&bare), "the fixture is that key");
    }

    #[test]
    fn a_line_that_is_not_one_ed25519_key_is_refused() {
        let key = [7u8; 32];
        let good = line_for(&key, None);
        let encoded = good.strip_prefix("ssh-ed25519 ").unwrap();

        // An RSA-typed blob under the right token, and the right blob under
        // another token.
        let mut rsa_blob = vec![0, 0, 0, 7];
        rsa_blob.extend_from_slice(b"ssh-rsa");
        rsa_blob.extend_from_slice(&[0, 0, 0, 32]);
        rsa_blob.extend_from_slice(&key);
        let blob_with = |len: usize| {
            let mut blob = ED25519_BLOB_PREFIX.to_vec();
            blob.extend_from_slice(&vec![7u8; len]);
            STANDARD.encode(blob)
        };
        // The length prefix says 32 and another length follows.
        let mut short_declared = ED25519_BLOB_PREFIX.to_vec();
        short_declared[18] = 31;
        short_declared.extend_from_slice(&[7u8; 31]);

        let cases: Vec<(String, PublicKeyLineError)> = vec![
            (String::new(), PublicKeyLineError::NotOneLine),
            (format!(" {good}"), PublicKeyLineError::NotOneLine),
            (format!("{good}\n"), PublicKeyLineError::NotOneLine),
            (format!("{good}\r"), PublicKeyLineError::NotOneLine),
            (
                format!("ssh-ed25519\t{encoded}"),
                PublicKeyLineError::NotOneLine,
            ),
            (
                format!("ssh-ed25519  {encoded}"),
                PublicKeyLineError::NotOneLine,
            ),
            ("ssh-ed25519".to_string(), PublicKeyLineError::MissingKey),
            (format!("ssh-rsa {encoded}"), PublicKeyLineError::NotEd25519),
            (
                format!("SSH-ED25519 {encoded}"),
                PublicKeyLineError::NotEd25519,
            ),
            (
                format!("no-pty ssh-ed25519 {encoded}"),
                PublicKeyLineError::NotEd25519,
            ),
            (
                format!("ecdsa-sha2-nistp256 {encoded}"),
                PublicKeyLineError::NotEd25519,
            ),
            ("ssh-ed25519 !!!".to_string(), PublicKeyLineError::Base64),
            (
                format!("ssh-ed25519 {}", STANDARD.encode(rsa_blob)),
                PublicKeyLineError::Blob,
            ),
            (
                format!("ssh-ed25519 {}", blob_with(31)),
                PublicKeyLineError::Blob,
            ),
            (
                format!("ssh-ed25519 {}", blob_with(33)),
                PublicKeyLineError::Blob,
            ),
            (
                format!("ssh-ed25519 {}", blob_with(0)),
                PublicKeyLineError::Blob,
            ),
            (
                format!("ssh-ed25519 {}", STANDARD.encode(short_declared)),
                PublicKeyLineError::Blob,
            ),
            (
                format!("ssh-ed25519 {}", "A".repeat(MAX_KEY_LINE_LEN)),
                PublicKeyLineError::TooLong,
            ),
        ];
        for (line, expected) in cases {
            assert_eq!(parse_public_key_line(&line), Err(expected), "{line:?}");
        }
        assert_eq!(parse_public_key_line(&good), Ok(key));
    }

    #[test]
    fn origins_match_up_to_trailing_slashes_and_exactly_otherwise() {
        assert_eq!(normalize_origin("https://h/log"), "https://h/log");
        assert_eq!(normalize_origin("https://h/log/"), "https://h/log");
        assert_eq!(normalize_origin("https://h/log///"), "https://h/log");
        assert_eq!(normalize_origin("/"), "/");
        assert_eq!(normalize_origin("///"), "/");
        assert_eq!(normalize_origin(""), "");
        assert_eq!(normalize_origin("/srv/log/"), "/srv/log");

        let keys: &[(&str, [u8; 32])] = &[(ORIGIN, [1; 32]), ("/srv/log/", [2; 32])];
        assert_eq!(witness_key_for(ORIGIN, keys), Some([1; 32]));
        assert_eq!(witness_key_for(&format!("{ORIGIN}/"), keys), Some([1; 32]));
        assert_eq!(witness_key_for("/srv/log", keys), Some([2; 32]));
        for other in [
            "https://COSIGNER.example.com/log",
            "https://cosigner.example.com/Log",
            "https://cosigner.example.com",
            "https://cosigner.example.com/log/x",
            "http://cosigner.example.com/log",
            "https://cosigner.example.com:443/log",
            "",
        ] {
            assert_eq!(witness_key_for(other, keys), None, "{other}");
        }
        assert_eq!(witness_key_for(ORIGIN, &[]), None);
    }

    #[test]
    fn a_valid_witness_list_decodes_to_its_keys() {
        let key = parse_public_key_line(key_line()).unwrap();
        let other = line_for(&[9; 32], Some("second"));
        let entries = [
            (ORIGIN, key_line()),
            ("https://mirror.example.org", other.as_str()),
            // One co-signer may serve several origins.
            ("https://mirror.example.net", key_line()),
        ];
        // An `@` in the path is a path, not userinfo.
        assert!(check_witnesses(&[("https://h.example/@log", key_line())], &[]).is_ok());
        let checked = check_witnesses(&entries, &[[3; 32]]).unwrap();
        assert_eq!(
            checked,
            [
                (ORIGIN.to_string(), key),
                ("https://mirror.example.org".to_string(), [9; 32]),
                ("https://mirror.example.net".to_string(), key),
            ]
        );
        assert_eq!(check_witnesses(&[], &[[3; 32]]).unwrap(), []);
    }

    #[test]
    fn an_origin_that_could_not_match_fails_the_build_check() {
        for origin in [
            "",
            "https://cosigner.example.com/log/",
            "https://",
            "https:///log",
            "https://u:p@h.example",
            "https://h.example/log?x=1",
            "https://h.example/log#f",
            "https://h.example?x=1",
            "http://cosigner.example.com",
            "/srv/log",
            "cosigner.example.com",
            " https://cosigner.example.com",
            "https://cosigner.example.com ",
            "https://a.example.com,https://b.example.com",
            "https://cosigner.example.com/l\u{f6}g",
            "https://cosigner.example.com/\u{1b}[31m",
        ] {
            let result = check_witnesses(&[(origin, key_line())], &[]);
            assert!(
                matches!(result, Err(WitnessKeyError::Origin { index: 0, .. })),
                "{origin:?}: {result:?}"
            );
        }
    }

    #[test]
    fn a_bad_entry_is_named_by_its_position() {
        let good = (ORIGIN, key_line());
        assert_eq!(
            check_witnesses(&[good, ("https://b.example.com", "ssh-rsa AAAA")], &[]),
            Err(WitnessKeyError::KeyLine {
                index: 1,
                source: PublicKeyLineError::NotEd25519,
            })
        );
        assert_eq!(
            check_witnesses(&[good, good], &[]),
            Err(WitnessKeyError::DuplicateOrigin { index: 1 })
        );
        for error in [
            WitnessKeyError::Origin {
                index: 2,
                reason: "the origin is empty",
            },
            WitnessKeyError::KeyLine {
                index: 2,
                source: PublicKeyLineError::Blob,
            },
            WitnessKeyError::DuplicateOrigin { index: 2 },
            WitnessKeyError::ReleaseKey { index: 2 },
        ] {
            assert!(error.to_string().starts_with("witnesses[2]: "), "{error}");
        }
    }

    /// A witness key must never be a release key: the build check refuses a
    /// list that would make one both.
    #[test]
    fn a_witness_key_that_is_a_release_key_is_refused() {
        let key = parse_public_key_line(key_line()).unwrap();
        assert_eq!(
            check_witnesses(&[(ORIGIN, key_line())], &[[3; 32], key]),
            Err(WitnessKeyError::ReleaseKey { index: 0 })
        );
        // Against the keys this binary embeds, through the same function.
        for release_key in crate::PUBLIC_KEYS {
            let line = line_for(release_key, None);
            assert_eq!(
                check_witnesses(&[(ORIGIN, line.as_str())], crate::PUBLIC_KEYS),
                Err(WitnessKeyError::ReleaseKey { index: 0 })
            );
        }
    }

    /// The embedded witness keys verify co-signatures and nothing else: none
    /// is a release key, none passes the release trust check, and each origin
    /// is in the form the client matches.
    #[test]
    fn no_embedded_witness_key_is_trusted_as_a_release_key() {
        for (origin, key) in crate::WITNESS_KEYS {
            assert!(!crate::PUBLIC_KEYS.contains(key), "{origin}");
            let verifying = crate::VerifyingKey::from_bytes(key)
                .unwrap_or_else(|_| panic!("{origin}: not a valid ed25519 key"));
            assert!(!verifying.is_weak(), "{origin}: a weak (small-order) key");
            assert!(!crate::is_trusted_key(&verifying), "{origin}");
            assert_eq!(check_embedded_origin(origin), Ok(()), "{origin}");
            assert_eq!(witness_key_for(origin, crate::WITNESS_KEYS), Some(*key));
        }
        // The property itself, with a key that is certainly not embedded as a
        // release key: a witness key does not pass `is_trusted_key`.
        // The sample goes through the function the build runs, and gets the
        // same point check the embedded keys do.
        let checked = check_witnesses(&[(ORIGIN, key_line())], crate::PUBLIC_KEYS).unwrap();
        let witness = checked[0].1;
        assert_eq!(witness, parse_public_key_line(key_line()).unwrap());
        let verifying = crate::VerifyingKey::from_bytes(&witness).unwrap();
        assert!(!verifying.is_weak());
        assert!(!crate::is_trusted_key(&verifying));
        assert!(!crate::PUBLIC_KEYS.contains(&witness));
    }
}
