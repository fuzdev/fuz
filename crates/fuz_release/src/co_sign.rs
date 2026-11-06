//! Release log co-signatures: an independent party's signed statement of which
//! head it saw.
//!
//! The release log head is signed by the release key. That proves where a head
//! came from, not that every reader is shown the same one. A **co-signer** is
//! a party with no access to that key who fetches the head on a schedule and
//! publishes, at an origin of its own beside the `head.json` it fetched, one
//! more file:
//!
//! - `witness` — a statement line followed immediately by its SSH signature:
//!
//!   ```text
//!   <seq> <sha512>\n
//!   -----BEGIN SSH SIGNATURE-----\n
//!   <base64 lines>\n
//!   -----END SSH SIGNATURE-----\n
//!   ```
//!
//!   The line is the head's `seq`, one space, and the SHA-512 of the
//!   `head.json` bytes as 128 lowercase hex characters — what
//!   `printf '%s %s\n' "$seq" "$(sha512sum < head.json | cut -d' ' -f1)"`
//!   writes. The signature is what `ssh-keygen -Y sign -n fuz_release_log`
//!   writes for a file holding exactly that line, newline included.
//!
//! One file, so a host that caches each file on its own schedule cannot serve
//! a statement beside the signature of another.
//!
//! The co-signer runs no code from this project: `curl`, `sha512sum`, and
//! `ssh-keygen` are the whole toolchain, so its statement does not depend on
//! software the publisher ships. It also means the co-signer attests to
//! *bytes* — nothing in that toolchain verifies the head's release signature.
//!
//! This module is the pure half of the client's check: verifying the file
//! against the co-signer's key ([`verify_co_sign`]) and comparing the verified
//! statement with the head its own origin served ([`compare_co_sign`]). The
//! fetch is in [`crate::log_check`].
//!
//! # What a co-signature is compared with
//!
//! Only the `head.json` **the same origin served in the same check**, as the
//! raw bytes it served — exactly what the co-signer's `sha512sum` hashed — and
//! only when that head has the co-signature's `seq`. Never another witness's
//! head and never the cached one: a head's bytes include its encoding and the
//! signature's `signed_at`, neither of which the release signature covers, so
//! two honest origins can serve one head as different bytes. Other witnesses
//! and the cache are tied to the co-signed head by its *signed content*,
//! through the consistency rules every check already applies
//! (`check_consistent`).
//!
//! # A beacon, not a gate
//!
//! A co-signature is checked only for an origin whose SSH key is embedded in
//! the binary (`fuz_crypto::WITNESS_KEYS`), and it can only ever refuse:
//!
//! - no `witness` file at the origin, or one for a `seq` other than its served
//!   head's — the co-signer lags, or its copy of the head does — is not an
//!   error and is never waited for;
//! - a `witness` file that is present and does not verify or parse is a
//!   refusal for that origin ([`CoSignProblem`]);
//! - a verified co-signature naming its origin's served `seq` with a different
//!   digest is [`LogContradiction::CoSignMismatch`]: the origin serves a
//!   `head.json` its own co-signer did not sign for that `seq`.
//!
//! It never confirms a release — the row verdict is read off a head signed by
//! a release key, as before — and the co-signer's key is never a release key.

use fuz_crypto::{ContentHash, HashAlgo, SshsigError, verify_sshsig};

use crate::release_log::{LogContradiction, MAX_HEAD_SEQ};

/// The co-signature's key at the root of an origin: the statement line and its
/// SSH signature, in one file.
pub const WITNESS_KEY: &str = "witness";

/// The `sshsig` namespace a co-signature is made under (`ssh-keygen -n`). A
/// signature the same key made for anything else does not verify here.
pub const CO_SIGN_NAMESPACE: &str = "fuz_release_log";

/// Longest statement line, newline included: a `seq` of at most 16 digits, a
/// space, 128 hex characters, and the newline.
const MAX_STATEMENT_LEN: u64 = 146;

/// Largest `witness` file read, in bytes: the longest statement line plus the
/// largest armored signature the verifier reads.
pub const MAX_WITNESS_SIZE: u64 = MAX_STATEMENT_LEN + fuz_crypto::sshsig::MAX_ARMORED_SIZE as u64;

/// Why a `witness` file an origin serves cannot be used.
///
/// Every message is fixed text plus, at most, a number: nothing from the
/// served file is repeated, so a host answering with some other document (an
/// HTML error page, say) yields a short, legible reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CoSignProblem {
    /// The file is larger than a statement and a signature can be.
    #[error("the witness file is too large: {size} bytes (max {MAX_WITNESS_SIZE})")]
    TooLarge {
        /// Its size, as far as the transport reported it.
        size: u64,
    },
    /// What follows the file's first line is not an SSH signature of that
    /// line by the origin's witness key under [`CO_SIGN_NAMESPACE`].
    #[error("the witness file's first line is not followed by a usable SSH signature of it: {0}")]
    Signature(#[from] SshsigError),
    /// The signature verifies and the signed first line is not the statement
    /// `<seq> <sha512>`.
    #[error("the witness file's signed first line is not \"<seq> <sha512 hex>\": {0}")]
    Line(&'static str),
}

impl CoSignProblem {
    /// Returns true if the file holds a signature that fails to vouch for its
    /// first line: it is by another key, for another namespace, or does not
    /// verify. A file that is oversized or malformed — not a co-signature at
    /// all — is a bad input, as an unparseable head is.
    #[must_use]
    pub const fn is_security_violation(&self) -> bool {
        match self {
            Self::Signature(e) => e.is_verification_failure(),
            Self::TooLarge { .. } | Self::Line(_) => false,
        }
    }
}

/// A co-signer's verified statement: at `seq`, the `head.json` it fetched had
/// this SHA-512.
///
/// Produced only by [`verify_co_sign`], so the two values were signed by the
/// witness key they were checked against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoSign {
    seq: u64,
    digest: ContentHash,
}

impl CoSign {
    /// The `seq` of the head the co-signer saw.
    #[must_use]
    pub const fn seq(&self) -> u64 {
        self.seq
    }

    /// The SHA-512 of the `head.json` bytes the co-signer saw.
    #[must_use]
    pub const fn digest(&self) -> &ContentHash {
        &self.digest
    }
}

/// Verify a `witness` file and read its statement.
///
/// The file is split at its first `\n`: everything up to and including it is
/// the statement line, and everything after it must be an SSH signature over
/// exactly that line, made under [`CO_SIGN_NAMESPACE`] by `key`, in the armor
/// `fuz_crypto::verify_sshsig` accepts. Nothing may come before the line,
/// between the line and the armor, or after the armor — except that the
/// armor's final newline is optional, as it is for a signature on its own.
///
/// The signature is checked first, so only bytes the witness key signed are
/// parsed. The line is held to one spelling:
///
/// - `<seq>`, one space, `<sha512>`, one `\n` — no `\r`;
/// - `<seq>` is a decimal integer from 1 to `MAX_HEAD_SEQ` (a head's own
///   range) with no sign and no leading zero;
/// - `<sha512>` is exactly 128 characters of `0-9a-f`.
///
/// `sha512sum`'s own two-space `<hex>  <name>` line is not accepted; the
/// statement names a `seq`, which that line does not carry.
///
/// # Errors
///
/// [`CoSignProblem::TooLarge`] past [`MAX_WITNESS_SIZE`],
/// [`CoSignProblem::Signature`] when the file has no line break or what
/// follows the first line does not verify as its signature, and
/// [`CoSignProblem::Line`] when the signed line is not the statement.
pub fn verify_co_sign(witness: &[u8], key: &[u8; 32]) -> Result<CoSign, CoSignProblem> {
    let size = witness.len() as u64;
    if size > MAX_WITNESS_SIZE {
        return Err(CoSignProblem::TooLarge { size });
    }
    // A file with no line break has no signature after its first line: the
    // whole of it is the line, and the armor is empty.
    let split = witness
        .iter()
        .position(|&byte| byte == b'\n')
        .map_or(witness.len(), |newline| newline + 1);
    let (line, armored) = witness.split_at_checked(split).unwrap_or((witness, &[]));
    verify_sshsig(armored, line, CO_SIGN_NAMESPACE, key)?;
    parse_statement(line)
}

/// Parse the statement line. Private: a statement is read only once its
/// signature has verified.
fn parse_statement(bytes: &[u8]) -> Result<CoSign, CoSignProblem> {
    let text = std::str::from_utf8(bytes).map_err(|_| CoSignProblem::Line("not ASCII"))?;
    let line = text
        .strip_suffix('\n')
        .ok_or(CoSignProblem::Line("no final newline"))?;
    let (seq, digest) = line
        .split_once(' ')
        .ok_or(CoSignProblem::Line("no space between seq and digest"))?;

    let canonical =
        !seq.is_empty() && seq.bytes().all(|b| b.is_ascii_digit()) && !seq.starts_with('0');
    if !canonical {
        return Err(CoSignProblem::Line(
            "seq is not a canonical decimal integer",
        ));
    }
    let seq: u64 = seq
        .parse()
        .map_err(|_| CoSignProblem::Line("seq is out of range"))?;
    if seq > MAX_HEAD_SEQ {
        return Err(CoSignProblem::Line("seq is out of range"));
    }

    let digest = ContentHash::from_lower_hex(HashAlgo::Sha512, digest)
        .map_err(|_| CoSignProblem::Line("digest is not 128 lowercase hex characters"))?;
    Ok(CoSign { seq, digest })
}

/// Compare a verified co-signature from `origin` with the head that same
/// origin served: its `seq`, and the raw `head.json` bytes as served.
///
/// Returns whether the co-signature covers that head — `true` when it names
/// the head's `seq` and the SHA-512 of the served bytes. `false` when it names
/// another `seq`: an older one means the co-signer lags behind its own copy of
/// the head, a newer one that the copy lags behind the co-signer; neither is
/// an error and nothing is compared.
///
/// The bytes are the served ones, not a re-serialization: they are what the
/// co-signer hashed.
///
/// # Errors
///
/// [`LogContradiction::CoSignMismatch`] when the co-signature names the served
/// head's `seq` with another digest.
pub fn compare_co_sign(
    origin: &str,
    co_sign: &CoSign,
    head_seq: u64,
    served_head: &[u8],
) -> Result<bool, LogContradiction> {
    if co_sign.seq != head_seq {
        return Ok(false);
    }
    if co_sign.digest != ContentHash::sha512(served_head) {
        return Err(LogContradiction::CoSignMismatch {
            origin: origin.to_string(),
            seq: head_seq,
        });
    }
    Ok(true)
}

/// What a verified co-signature covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoSignCoverage {
    /// It covers the `head.json` its origin served, and that head has the
    /// effective head's `seq` — so, by the consistency rules, the effective
    /// head's signed content: the co-signer saw the log this check read its
    /// verdict from.
    EffectiveHead,
    /// It covers the `head.json` its origin served, and that head is older
    /// than the effective one: the co-signer's origin lags behind another
    /// witness or the cached head.
    OlderHead,
    /// It names a `seq` other than the one its origin served. Verified, and
    /// compared with nothing.
    Uncompared,
}

/// A verified co-signature a successful check saw, for the caller to render.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoSignReport {
    /// The origin that served it, as configured.
    pub origin: String,
    /// The `seq` it names.
    pub seq: u64,
    /// What it covers.
    pub coverage: CoSignCoverage,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `fuz_crypto`'s `sshsig` fixtures: a statement line for `seq` 7 and real
    /// `ssh-keygen -Y sign -n fuz_release_log` output over it.
    const LINE: &[u8] = include_bytes!("../../fuz_crypto/tests/fixtures/sshsig/message");
    const KEY_PUB: &str = include_str!("../../fuz_crypto/tests/fixtures/sshsig/key.pub");
    const OTHER_PUB: &str = include_str!("../../fuz_crypto/tests/fixtures/sshsig/other.pub");
    const SIG: &[u8] = include_bytes!("../../fuz_crypto/tests/fixtures/sshsig/message.sha512.sig");
    const SIG_SHA256: &[u8] =
        include_bytes!("../../fuz_crypto/tests/fixtures/sshsig/message.sha256.sig");
    const SIG_OTHER_NAMESPACE: &[u8] =
        include_bytes!("../../fuz_crypto/tests/fixtures/sshsig/message.other-namespace.sig");

    fn key() -> [u8; 32] {
        fuz_crypto::parse_public_key_line(KEY_PUB.trim_end()).unwrap()
    }

    /// The `witness` file `cat line line.sig` makes.
    fn witness(line: &[u8], signature: &[u8]) -> Vec<u8> {
        [line, signature].concat()
    }

    fn digest(fill: u8) -> ContentHash {
        ContentHash::sha512(&[fill])
    }

    fn line(seq: &str, hex: &str) -> Vec<u8> {
        format!("{seq} {hex}\n").into_bytes()
    }

    /// A `witness` file made with `sha512sum`, `printf`,
    /// `ssh-keygen -Y sign -n fuz_release_log`, and `cat` — verifies and
    /// parses.
    #[test]
    fn a_witness_file_made_with_ssh_keygen_verifies() {
        for signature in [SIG, SIG_SHA256] {
            let co_sign = verify_co_sign(&witness(LINE, signature), &key()).unwrap();
            assert_eq!(co_sign.seq(), 7);
            assert_eq!(co_sign.digest(), &ContentHash::sha512(b"head bytes"));
        }
        let other = fuz_crypto::parse_public_key_line(OTHER_PUB.trim_end()).unwrap();
        assert_eq!(
            verify_co_sign(&witness(LINE, SIG), &other),
            Err(CoSignProblem::Signature(SshsigError::WrongKey))
        );
        assert_eq!(
            verify_co_sign(&witness(LINE, SIG_OTHER_NAMESPACE), &key()),
            Err(CoSignProblem::Signature(SshsigError::WrongNamespace))
        );
    }

    /// The split is strict: the line, then the armor, and nothing before,
    /// between, or after — but the armor's final newline is optional.
    #[test]
    fn the_file_is_the_line_then_the_armor_and_nothing_else() {
        type Expect = fn(CoSignProblem) -> bool;
        let armor: Expect =
            |problem| matches!(problem, CoSignProblem::Signature(SshsigError::Armor(_)));
        let invalid: Expect = |problem| {
            matches!(
                problem,
                CoSignProblem::Signature(SshsigError::InvalidSignature)
            )
        };
        let good = witness(LINE, SIG);
        assert!(verify_co_sign(&good, &key()).is_ok());
        // Without the armor's final newline.
        assert_eq!(good.last(), Some(&b'\n'));
        assert!(verify_co_sign(&good[..good.len() - 1], &key()).is_ok());

        let cases: Vec<(&str, Vec<u8>, Expect)> = vec![
            ("empty", Vec::new(), armor),
            ("the line alone", LINE.to_vec(), armor),
            (
                "the line without its newline",
                LINE[..LINE.len() - 1].to_vec(),
                armor,
            ),
            ("the signature alone", SIG.to_vec(), armor),
            ("two final newlines", witness(&good, b"\n"), armor),
            ("text after the armor", witness(&good, b"x\n"), armor),
            (
                "a second witness after the first",
                witness(&good, &good),
                armor,
            ),
            ("a blank line between", [LINE, b"\n", SIG].concat(), armor),
            // The first line is then empty, and the armor is not its signature.
            ("a blank line before", witness(b"\n", &good), armor),
            (
                "a space before the armor",
                [LINE, b" ", SIG].concat(),
                armor,
            ),
            (
                "crlf after the line",
                [&LINE[..LINE.len() - 1], b"\r\n", SIG].concat(),
                // The signed bytes would be the line with a `\r`: not signed.
                invalid,
            ),
            ("the signature first", witness(SIG, LINE), armor),
            (
                "a line that was not the one signed",
                witness(&line("8", &digest(1).to_hex()), SIG),
                invalid,
            ),
            (
                "an html page",
                b"<!DOCTYPE html>\n<html><body>Not Found</body></html>\n".to_vec(),
                armor,
            ),
        ];
        for (case, bytes, expect) in cases {
            let result = verify_co_sign(&bytes, &key());
            assert!(result.clone().is_err_and(expect), "{case}: {result:?}");
        }
    }

    #[test]
    fn an_oversized_file_is_refused_before_anything_is_read() {
        let at = usize::try_from(MAX_WITNESS_SIZE).unwrap();
        assert_eq!(
            verify_co_sign(&vec![b'7'; at + 1], &key()),
            Err(CoSignProblem::TooLarge {
                size: MAX_WITNESS_SIZE + 1
            })
        );
        // The bound docs/release_format.md states.
        assert_eq!(MAX_WITNESS_SIZE, 4242);
        // At the bound it is read, and is not a co-signature.
        assert!(matches!(
            verify_co_sign(&vec![b'7'; at], &key()),
            Err(CoSignProblem::Signature(SshsigError::Armor(_)))
        ));
        // The longest valid line fits beside the largest signature.
        let longest = line(&MAX_HEAD_SEQ.to_string(), &digest(1).to_hex());
        assert_eq!(u64::try_from(longest.len()).unwrap(), MAX_STATEMENT_LEN);
    }

    /// What a host that answers a missing file with a page says: a short
    /// reason, with nothing of the page in it.
    #[test]
    fn a_problem_message_repeats_nothing_from_the_file() {
        let page = b"<html>\x1b[31m secret-token </html>\n<p>more</p>\n";
        let problem = verify_co_sign(page, &key()).unwrap_err();
        let message = problem.to_string();
        assert_eq!(
            message,
            "the witness file's first line is not followed by a usable SSH signature of it: \
             malformed SSH signature armor: missing begin marker"
        );
        assert_eq!(
            CoSignProblem::TooLarge { size: 9000 }.to_string(),
            format!("the witness file is too large: 9000 bytes (max {MAX_WITNESS_SIZE})")
        );
        assert_eq!(
            CoSignProblem::Line("no final newline").to_string(),
            "the witness file's signed first line is not \"<seq> <sha512 hex>\": no final newline"
        );
    }

    #[test]
    fn the_line_a_cron_writes_parses() {
        let hash = digest(1);
        // What `printf '%s %s\n' "$seq" "$(sha512sum < head.json | cut -d' ' -f1)"`
        // writes.
        let co_sign = parse_statement(&line("7", &hash.to_hex())).unwrap();
        assert_eq!(co_sign.seq(), 7);
        assert_eq!(co_sign.digest(), &hash);
        // The ends of the range.
        assert_eq!(
            parse_statement(&line("1", &hash.to_hex())).unwrap().seq(),
            1
        );
        let max = MAX_HEAD_SEQ.to_string();
        assert_eq!(
            parse_statement(&line(&max, &hash.to_hex())).unwrap().seq(),
            MAX_HEAD_SEQ
        );
    }

    #[test]
    fn any_other_spelling_of_the_line_is_refused() {
        let hex = digest(1).to_hex();
        let over = (MAX_HEAD_SEQ + 1).to_string();
        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("empty", Vec::new()),
            ("newline only", b"\n".to_vec()),
            ("no final newline", format!("7 {hex}").into_bytes()),
            ("crlf", format!("7 {hex}\r\n").into_bytes()),
            ("two newlines", format!("7 {hex}\n\n").into_bytes()),
            ("a second line", format!("7 {hex}\n8 {hex}\n").into_bytes()),
            ("leading newline", format!("\n7 {hex}\n").into_bytes()),
            ("leading space", format!(" 7 {hex}\n").into_bytes()),
            ("trailing space", format!("7 {hex} \n").into_bytes()),
            ("two spaces", format!("7  {hex}\n").into_bytes()),
            ("a tab", format!("7\t{hex}\n").into_bytes()),
            ("no seq", format!(" {hex}\n").into_bytes()),
            ("digest only", format!("{hex}\n").into_bytes()),
            (
                "the sha512sum line",
                format!("{hex}  head.json\n").into_bytes(),
            ),
            ("digest first", format!("{hex} 7\n").into_bytes()),
            ("seq zero", line("0", &hex)),
            ("leading zero", line("07", &hex)),
            ("plus sign", line("+7", &hex)),
            ("minus sign", line("-7", &hex)),
            ("hex seq", line("0x7", &hex)),
            ("fraction", line("7.0", &hex)),
            ("exponent", line("7e0", &hex)),
            ("non-ascii digit", line("\u{0667}", &hex)),
            ("past the seq range", line(&over, &hex)),
            ("past u64", line("99999999999999999999999", &hex)),
            ("uppercase digest", line("7", &hex.to_uppercase())),
            ("short digest", line("7", &hex[..127])),
            ("long digest", line("7", &format!("{hex}0"))),
            (
                "sha256 digest",
                line("7", &ContentHash::sha256(b"x").to_hex()),
            ),
            (
                "non-hex digest",
                line("7", &hex.replacen(|_: char| true, "g", 1)),
            ),
            ("prefixed digest", line("7", &format!("sha512:{hex}"))),
            ("not utf-8", vec![b'7', b' ', 0xff, b'\n']),
            ("a nul", format!("7 {hex}\0\n").into_bytes()),
        ];
        for (case, bytes) in cases {
            let result = parse_statement(&bytes);
            assert!(
                matches!(result, Err(CoSignProblem::Line(_))),
                "{case}: {result:?}"
            );
        }
    }

    const CO_SIGNER: &str = "https://cosigner.example.com";

    #[test]
    fn a_co_sign_is_compared_with_its_own_origins_served_bytes_at_its_seq() {
        let served = b"{ the head.json bytes as served }\n";
        let covering = CoSign {
            seq: 7,
            digest: ContentHash::sha512(served),
        };
        assert_eq!(compare_co_sign(CO_SIGNER, &covering, 7, served), Ok(true));

        // Another seq, older or newer, is compared with nothing — whatever
        // the digest.
        for head_seq in [1, 6, 8, MAX_HEAD_SEQ] {
            assert_eq!(
                compare_co_sign(CO_SIGNER, &covering, head_seq, b"anything else"),
                Ok(false),
                "{head_seq}"
            );
        }

        // The served seq with other bytes — one byte is enough, and so is a
        // re-encoding of the same JSON.
        for other in [
            &b"{ the head.json bytes as served }"[..],
            b"{ the head.json bytes as served } \n",
            b"",
        ] {
            assert_eq!(
                compare_co_sign(CO_SIGNER, &covering, 7, other),
                Err(LogContradiction::CoSignMismatch {
                    origin: CO_SIGNER.to_string(),
                    seq: 7,
                })
            );
        }
    }

    #[test]
    fn problems_are_classified_by_whether_a_signature_failed() {
        let cases = [
            (CoSignProblem::TooLarge { size: 9000 }, false),
            (CoSignProblem::Line("no final newline"), false),
            (CoSignProblem::Signature(SshsigError::Armor("x")), false),
            (CoSignProblem::Signature(SshsigError::Malformed("x")), false),
            (CoSignProblem::Signature(SshsigError::InvalidKey), false),
            (CoSignProblem::Signature(SshsigError::WrongKey), true),
            (CoSignProblem::Signature(SshsigError::WrongNamespace), true),
            (
                CoSignProblem::Signature(SshsigError::InvalidSignature),
                true,
            ),
        ];
        for (problem, expected) in cases {
            assert_eq!(problem.is_security_violation(), expected, "{problem}");
        }
    }
}
