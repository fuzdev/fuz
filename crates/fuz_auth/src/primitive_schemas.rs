//! Cross-domain identity primitives — username and email shape and bounds.
//!
//! Mirrors `fuz_app/src/lib/primitive_schemas.ts`. Lives at the crate
//! root (not inside an auth-only module) because the same primitives
//! show up in invites, audit metadata, and future role-grant surfaces.
//!
//! [`is_valid_token_id`] and [`is_valid_fact_hash`] join them: the same
//! twin-of-a-Zod-schema shape, for the public id and content-address
//! primitives wire surfaces decode. The wire UUID grammar is generic to every
//! spine crate, so it lives lower, as `fuz_http::is_valid_uuid`.
//!
//! Username for *creation* sites (signup, bootstrap, admin-create) is
//! stricter than for *lookup* sites (login, search): creation enforces
//! a character class so what lands in the DB is predictable; lookup
//! accepts longer / odder strings so future format changes don't lock
//! out legitimate users mid-window.

/// Minimum username length on creation (3 chars: start + middle + end).
pub const USERNAME_LENGTH_MIN: usize = 3;

/// Maximum username length on creation (matches GitHub's limit).
pub const USERNAME_LENGTH_MAX: usize = 39;

/// Maximum username length on lookup paths (login, search) — looser
/// than [`USERNAME_LENGTH_MAX`] so a future creation-policy tightening
/// doesn't lock legitimate users out of lookup endpoints.
pub const USERNAME_PROVIDED_LENGTH_MAX: usize = 255;

/// Maximum email length in **bytes** — RFC 5321 §4.5.3.1.3 path-length
/// limit (the limit is octets).
///
/// The format rule lives in [`is_valid_email`], which bounds `s.len()`
/// (UTF-8 bytes) to this; the TS `Email` schema bounds the same UTF-8
/// byte length, so a multibyte address is accepted/rejected identically
/// on both spines.
pub const EMAIL_LENGTH_MAX: usize = 254;

/// Validate a username for *creation* (signup, bootstrap, admin-create).
///
/// Rules (mirrors the TS `Username` schema):
/// - ASCII only
/// - length in `[USERNAME_LENGTH_MIN, USERNAME_LENGTH_MAX]`
/// - first char: ASCII letter
/// - last char: ASCII alphanumeric (no `_` or `-`)
/// - middle chars: ASCII alphanumeric, `_`, or `-`
///
/// Hand-rolled instead of regex: the `regex` crate isn't a workspace
/// dependency and pulling it in for one validator is overkill. Byte
/// scan is also strictly faster (no DFA compile, no UTF-8 decode —
/// the ASCII check up front lets us treat the slice as bytes).
#[must_use]
pub fn is_valid_username_for_creation(s: &str) -> bool {
    if s.len() < USERNAME_LENGTH_MIN || s.len() > USERNAME_LENGTH_MAX {
        return false;
    }
    // `s.len()` is byte length; ASCII check below guarantees it equals
    // character count, so the bounds check above is correct.
    if !s.is_ascii() {
        return false;
    }
    let bytes = s.as_bytes();
    // Safe to index — length checked above (>= 3).
    if !bytes[0].is_ascii_alphabetic() {
        return false;
    }
    if !bytes[bytes.len() - 1].is_ascii_alphanumeric() {
        return false;
    }
    for &b in &bytes[1..bytes.len() - 1] {
        if !(b.is_ascii_alphanumeric() || b == b'_' || b == b'-') {
            return false;
        }
    }
    true
}

/// The stored form of a username submitted at a *creation* site, or `None`
/// when [`is_valid_username_for_creation`] refuses the raw value.
///
/// The TS `Username` schema validates the raw string and *then* lowercases —
/// nothing trims, so a padded name is refused, never repaired into a legal
/// one. Every creation site (signup, bootstrap, invite) canonicalizes through
/// here so storage is canonical and the refusals match the twin's.
#[must_use]
pub fn canonical_username_for_creation(raw: &str) -> Option<String> {
    is_valid_username_for_creation(raw).then(|| raw.to_ascii_lowercase())
}

/// Validate an email for *creation/storage* sites (signup, invite).
///
/// Intentionally permissive — a structural shape check, not RFC 5322
/// conformance or deliverability. Mirrors the TS `Email` schema (its
/// `EMAIL_REGEX`, with whitespace = `White_Space ∪ {U+FEFF}` on both spines,
/// plus the [`EMAIL_LENGTH_MAX`] byte bound):
///
/// - length in `1..=EMAIL_LENGTH_MAX`
/// - no whitespace anywhere (a surrounding-space address is rejected, not
///   silently trimmed — the stored form is verbatim, like TS)
/// - exactly one `@`, with a non-empty local part
/// - a domain that contains a `.` and neither starts nor ends with one, so
///   `b.c` and `b..c` pass but `b`, `.c`, `b.`, `.b.c`, and `b.c.` do not
///   (single-char TLDs like `a@b.c` are deliberately accepted — real delivery
///   is proven by a confirmation email, not by this check)
///
/// The rule exists to reject obvious garbage and to agree with the TS
/// spine so an address accepted on one backend is accepted on both.
/// Hand-rolled (no `regex` dependency), like
/// [`is_valid_username_for_creation`].
#[must_use]
pub fn is_valid_email(s: &str) -> bool {
    if s.is_empty() || s.len() > EMAIL_LENGTH_MAX {
        return false;
    }
    // Reject any whitespace anywhere — surrounding (so the address is stored
    // verbatim, never trimmed) and internal. Rejects Unicode `White_Space`
    // (`char::is_whitespace`) plus U+FEFF (BOM/ZWNBSP): JS's `\s` — which
    // the TS `EMAIL_REGEX` negates — treats U+FEFF as whitespace but Unicode
    // `White_Space` does not, and conversely omits U+0085 (NEL) which
    // `White_Space` includes. The TS regex also excludes U+0085, so both
    // spines reject exactly `White_Space ∪ {U+FEFF}`.
    if s.chars().any(|c| c.is_whitespace() || c == '\u{FEFF}') {
        return false;
    }
    let mut parts = s.split('@');
    // Exactly one `@`: two segments, and no third.
    let (Some(local), Some(domain)) = (parts.next(), parts.next()) else {
        return false;
    };
    if parts.next().is_some() || local.is_empty() {
        return false;
    }
    // The domain holds a `.` and has none at either edge. Given the
    // whitespace/`@`-free guarantee above, this is exactly the TS
    // `EMAIL_REGEX`'s domain clause, `[^\s@.]+\.[^\s@]*[^\s@.]`.
    domain.contains('.') && !domain.starts_with('.') && !domain.ends_with('.')
}

/// Algorithm prefix every wire-form fact hash carries, colon included.
/// Mirrors the TS `FACT_HASH_PREFIX` (`fuz_util/hash_schemas.ts`).
pub const FACT_HASH_PREFIX: &str = "blake3:";

/// Number of lowercase hex characters following [`FACT_HASH_PREFIX`] — a
/// blake3-256 digest.
pub const FACT_HASH_HEX_LENGTH: usize = 64;

/// Whether `s` is a valid wire fact hash — the `blake3:`-prefixed address the
/// spine decodes from a route segment or a JSON-RPC filter.
///
/// Twin of the TS `FactHashSchema` (`z.string().regex(FACT_HASH_EXACT)` in
/// `fuz_app`'s `primitive_schemas.ts`, with `FACT_HASH_EXACT` =
/// `/^blake3:[0-9a-f]{64}$/` from `fuz_util`'s `hash_schemas.ts`): the
/// literal `blake3:` prefix followed by
/// exactly sixty-four **lowercase** hex characters. Nothing else — no other
/// algorithm token, no uppercase hex, no other digest length, no surrounding
/// whitespace.
///
/// `fuz_crypto::ContentHash::parse_fact_hash` is the same grammar, returning
/// the parsed hash — the ingress gate for a caller that needs the digest. This
/// is the string form, for callers that keep the string (cell `refs`, a
/// declared ref). `ContentHash::parse_prefixed` is **not** a substitute: it
/// admits every algorithm token the type knows (`sha256:`, `sha512:`), so a
/// wrong-algorithm address would parse where the TS twin refuses it.
///
/// Hand-rolled instead of regex, for the same reason
/// [`is_valid_username_for_creation`] is: `regex` isn't a workspace
/// dependency, and a byte scan is faster than a DFA compile.
#[must_use]
pub fn is_valid_fact_hash(s: &str) -> bool {
    let Some(hex) = s.strip_prefix(FACT_HASH_PREFIX) else {
        return false;
    };
    // `len()` is byte length; the lowercase-hex class below is ASCII-only, so
    // a multibyte character fails the class check rather than slipping the
    // count.
    hex.len() == FACT_HASH_HEX_LENGTH
        && hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Prefix every public API token id carries. Mirrors the TS
/// `API_TOKEN_PREFIX`-derived id shape minted by `generate_api_token`.
pub const TOKEN_ID_PREFIX: &str = "tok_";

/// Number of base64url characters following [`TOKEN_ID_PREFIX`].
pub const TOKEN_ID_SUFFIX_LENGTH: usize = 12;

/// Whether `s` is a valid public API token id — the id `account_token_create`
/// hands back and `account_token_revoke` takes.
///
/// Twin of the TS `ApiTokenId` schema (`pipe(string, regex(API_TOKEN_ID_REGEX))`
/// in `auth/api_token.ts`), whose regex is `^tok_[A-Za-z0-9_-]{12}$`: the
/// literal `tok_` prefix followed by exactly twelve base64url characters
/// (ASCII alphanumerics plus `_` and `-`). Nothing else — no other length, no
/// `+` or `/`, no padding, no surrounding whitespace.
///
/// The id is the token's *public* half: it is stored verbatim, compared as an
/// opaque string, and never hashed, so a lookup with an off-grammar id is a
/// guaranteed miss. Gating on the grammar is a wire-parity rule rather than a
/// safety one — without it a mutation answers `{ok: true, revoked: false}`
/// for input the twin refuses with `invalid_params`, which is a success
/// envelope for a request that was never well-formed.
///
/// Hand-rolled instead of regex, for the same reason
/// [`is_valid_username_for_creation`] is: `regex` isn't a workspace
/// dependency, and a byte scan is faster than a DFA compile.
#[must_use]
pub fn is_valid_token_id(s: &str) -> bool {
    let Some(suffix) = s.strip_prefix(TOKEN_ID_PREFIX) else {
        return false;
    };
    // `len()` is byte length; the base64url class below is ASCII-only, so a
    // multibyte character fails the class check rather than slipping the
    // count.
    suffix.len() == TOKEN_ID_SUFFIX_LENGTH
        && suffix
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_standard_usernames() {
        assert!(is_valid_username_for_creation("alice"));
        assert!(is_valid_username_for_creation("Alice"));
        assert!(is_valid_username_for_creation("bob"));
        assert!(is_valid_username_for_creation("user_123"));
        assert!(is_valid_username_for_creation("a-b-c"));
        assert!(is_valid_username_for_creation("a1b2"));
    }

    #[test]
    fn rejects_too_short() {
        assert!(!is_valid_username_for_creation(""));
        assert!(!is_valid_username_for_creation("a"));
        assert!(!is_valid_username_for_creation("ab"));
    }

    #[test]
    fn rejects_too_long() {
        assert!(!is_valid_username_for_creation(
            &"a".repeat(USERNAME_LENGTH_MAX + 1)
        ));
    }

    #[test]
    fn accepts_max_length_boundary() {
        let max = "a".to_string() + &"b".repeat(USERNAME_LENGTH_MAX - 1);
        assert_eq!(max.len(), USERNAME_LENGTH_MAX);
        assert!(is_valid_username_for_creation(&max));
    }

    #[test]
    fn rejects_first_char_not_letter() {
        assert!(!is_valid_username_for_creation("1abc"));
        assert!(!is_valid_username_for_creation("_abc"));
        assert!(!is_valid_username_for_creation("-abc"));
    }

    #[test]
    fn rejects_last_char_punct() {
        assert!(!is_valid_username_for_creation("abc_"));
        assert!(!is_valid_username_for_creation("abc-"));
    }

    #[test]
    fn rejects_disallowed_middle_chars() {
        assert!(!is_valid_username_for_creation("ab cd"));
        assert!(!is_valid_username_for_creation("ab.cd"));
        assert!(!is_valid_username_for_creation("ab@cd"));
        assert!(!is_valid_username_for_creation("ab!cd"));
    }

    #[test]
    fn rejects_non_ascii() {
        assert!(!is_valid_username_for_creation("aliceé"));
        assert!(!is_valid_username_for_creation("北京1a"));
    }

    #[test]
    fn email_accepts_well_formed() {
        assert!(is_valid_email("user@example.com"));
        assert!(is_valid_email("user+tag@example.co.uk"));
        assert!(is_valid_email("Mixed.Case+Tag@Foo.Bar"));
        // Single-char TLD + consecutive dots are deliberately accepted by the
        // loose rule — all rejected by Zod's `z.email()`, the divergence the
        // TS side adopted. Pinned here so a future tighten is a visible change.
        assert!(is_valid_email("a@b.c")); // single-char TLD
        assert!(is_valid_email("a..b@c.d")); // consecutive dots in local
        assert!(is_valid_email("a@b..c")); // consecutive dots in domain
    }

    #[test]
    fn email_rejects_malformed_shape() {
        assert!(!is_valid_email("")); // empty
        assert!(!is_valid_email("notanemail")); // no `@`
        assert!(!is_valid_email("@example.com")); // empty local
        assert!(!is_valid_email("user@")); // empty domain
        assert!(!is_valid_email("user@host")); // no dot in domain
        assert!(!is_valid_email("user@.com")); // domain starts with dot
        assert!(!is_valid_email("user@com.")); // domain ends with dot
        assert!(!is_valid_email("a@.b.c")); // starts with dot, another inside
        assert!(!is_valid_email("a@b.c.")); // ends with dot, another inside
        assert!(!is_valid_email("a@.")); // a lone dot
        assert!(!is_valid_email("a@@b.c")); // two `@`
    }

    #[test]
    fn email_rejects_whitespace() {
        // Surrounding / internal whitespace is rejected, never trimmed —
        // the stored address is verbatim, mirroring the TS `Email` schema.
        assert!(!is_valid_email(" user@example.com"));
        assert!(!is_valid_email("user@example.com "));
        assert!(!is_valid_email("us er@example.com"));
        assert!(!is_valid_email("user@exa\tmple.com"));
        // U+0085 (NEL) is Unicode White_Space (is_whitespace) but JS `\s`
        // omits it; U+FEFF (BOM) is the reverse. Both spines reject both, so
        // each rejects the whitespace set `White_Space ∪ {U+FEFF}`.
        assert!(!is_valid_email("a\u{0085}b@c.d")); // NEL
        assert!(!is_valid_email("a\u{FEFF}b@c.d")); // BOM/ZWNBSP
    }

    #[test]
    fn email_enforces_length_bound() {
        // 254 ASCII chars total: a 242-char local + "@example.com" (12).
        let at_max = format!("{}@example.com", "a".repeat(EMAIL_LENGTH_MAX - 12));
        assert_eq!(at_max.len(), EMAIL_LENGTH_MAX);
        assert!(is_valid_email(&at_max));
        let over_max = format!("{}@example.com", "a".repeat(EMAIL_LENGTH_MAX - 11));
        assert_eq!(over_max.len(), EMAIL_LENGTH_MAX + 1);
        assert!(!is_valid_email(&over_max));
        // Multibyte: the bound is BYTES, not chars. `\u{FC}` (ü) is 2
        // UTF-8 bytes, so 121×ü (242 bytes) + "@example.com" (12) = 254 =
        // the bound, while 122×ü = 256 is over, though both are well under
        // 254 *chars*. Pins parity with the TS `Email` byte-length refine.
        let mb_at_max = format!("{}@example.com", "\u{FC}".repeat(121));
        assert_eq!(mb_at_max.len(), EMAIL_LENGTH_MAX);
        assert!(is_valid_email(&mb_at_max));
        let mb_over = format!("{}@example.com", "\u{FC}".repeat(122));
        assert_eq!(mb_over.len(), EMAIL_LENGTH_MAX + 2);
        assert!(!is_valid_email(&mb_over));
    }

    /// Twin of the TS `ApiTokenId` regex `^tok_[A-Za-z0-9_-]{12}$`. The
    /// accepted rows are the shapes `generate_api_token` actually mints (a
    /// base64url slice, so every class member is reachable); the rejected
    /// rows are the strings an ungated handler answers
    /// `{ok: true, revoked: false}` for.
    #[test]
    fn token_id_accepts_the_minted_shape() {
        assert!(is_valid_token_id("tok_abC0_d-3xyzA"));
        assert!(is_valid_token_id("tok_000000000000"));
        assert!(is_valid_token_id("tok_zzzzzzzzzzzz"));
        assert!(is_valid_token_id("tok_ZZZZZZZZZZZZ"));
        // The two non-alphanumeric class members, at full width — built from
        // the constants so the length bound and the literals can't drift.
        for filler in ['_', '-'] {
            let id = format!(
                "{TOKEN_ID_PREFIX}{}",
                filler.to_string().repeat(TOKEN_ID_SUFFIX_LENGTH)
            );
            assert_eq!(id.len(), TOKEN_ID_PREFIX.len() + TOKEN_ID_SUFFIX_LENGTH);
            assert!(is_valid_token_id(&id), "{id}");
        }
    }

    #[test]
    fn token_id_rejects_off_grammar_strings() {
        // Wrong / missing prefix.
        assert!(!is_valid_token_id(""));
        assert!(!is_valid_token_id("abC0_d-3xyzA"));
        assert!(!is_valid_token_id("tok-abC0_d-3xyzA"));
        assert!(!is_valid_token_id("TOK_abC0_d-3xyzA"));
        assert!(!is_valid_token_id(" tok_abC0_d-3xyzA"));
        // Wrong suffix length, either side of the bound.
        assert!(!is_valid_token_id("tok_abC0_d-3xyz"));
        assert!(!is_valid_token_id("tok_abC0_d-3xyzAB"));
        assert!(!is_valid_token_id("tok_"));
        // Characters outside base64url — including the base64 pair `+/` and
        // the `=` padding that base64url drops.
        assert!(!is_valid_token_id("tok_abC0+d-3xyzA"));
        assert!(!is_valid_token_id("tok_abC0/d-3xyzA"));
        assert!(!is_valid_token_id("tok_abC0=d-3xyzA"));
        assert!(!is_valid_token_id("tok_abC0 d-3xyzA"));
        // The shapes a caller actually sends when it has the wrong id: a
        // UUID, a bare word, and a SQL-injection probe.
        assert!(!is_valid_token_id("3f8a1c2e-1234-4abc-9def-0123456789ab"));
        assert!(!is_valid_token_id("not-a-token"));
        assert!(!is_valid_token_id("' OR 1=1--"));
        // Non-ASCII: twelve characters after the prefix, more than twelve
        // bytes, and outside the class either way.
        assert!(!is_valid_token_id("tok_\u{FC}bC0_d-3xyz"));
    }

    /// Twin of the TS `FactHashSchema` regex `^blake3:[0-9a-f]{64}$`.
    #[test]
    fn fact_hash_accepts_the_wire_form() {
        assert!(is_valid_fact_hash(&format!(
            "{FACT_HASH_PREFIX}{}",
            "0".repeat(FACT_HASH_HEX_LENGTH)
        )));
        assert!(is_valid_fact_hash(&format!(
            "{FACT_HASH_PREFIX}{}",
            "f".repeat(FACT_HASH_HEX_LENGTH)
        )));
        assert!(is_valid_fact_hash(&format!(
            "{FACT_HASH_PREFIX}{}",
            "abcdef0123456789".repeat(4)
        )));
    }

    #[test]
    fn fact_hash_rejects_off_grammar_addresses() {
        let hex = "abcdef0123456789".repeat(4);
        // Uppercase hex: a real digest never renders this way.
        assert!(!is_valid_fact_hash(&format!(
            "{FACT_HASH_PREFIX}{}",
            hex.to_uppercase()
        )));
        // The other algorithm tokens `ContentHash` knows.
        assert!(!is_valid_fact_hash(&format!("sha256:{hex}")));
        assert!(!is_valid_fact_hash(&format!(
            "sha512:{}",
            "abcdef0123456789".repeat(8)
        )));
        // Wrong digest length, either side of the bound.
        assert!(!is_valid_fact_hash(&format!(
            "{FACT_HASH_PREFIX}{}",
            "a".repeat(FACT_HASH_HEX_LENGTH - 1)
        )));
        assert!(!is_valid_fact_hash(&format!(
            "{FACT_HASH_PREFIX}{}",
            "a".repeat(FACT_HASH_HEX_LENGTH + 1)
        )));
        // Missing / wrong-case / detached prefix.
        assert!(!is_valid_fact_hash(&hex));
        assert!(!is_valid_fact_hash(&format!("BLAKE3:{hex}")));
        assert!(!is_valid_fact_hash(&format!("blake3-{hex}")));
        assert!(!is_valid_fact_hash(&format!(" {FACT_HASH_PREFIX}{hex}")));
        assert!(!is_valid_fact_hash(""));
        assert!(!is_valid_fact_hash(FACT_HASH_PREFIX));
        // Right length, outside hex — including a multibyte character, which
        // is more than one byte and outside the class either way.
        assert!(!is_valid_fact_hash(&format!(
            "{FACT_HASH_PREFIX}{}",
            "g".repeat(FACT_HASH_HEX_LENGTH)
        )));
        assert!(!is_valid_fact_hash(&format!(
            "{FACT_HASH_PREFIX}\u{FC}{}",
            "a".repeat(FACT_HASH_HEX_LENGTH - 1)
        )));
        assert!(!is_valid_fact_hash("not-a-hash"));
    }

    /// The string grammar and `fuz_crypto`'s typed fact-hash parse agree on
    /// every row: the two gates a spine surface picks between refuse the same
    /// strings.
    #[test]
    fn fact_hash_grammar_matches_the_typed_parse() {
        let hex = fuz_crypto::ContentHash::blake3(b"abc").to_hex();
        for s in [
            format!("{FACT_HASH_PREFIX}{hex}"),
            format!("{FACT_HASH_PREFIX}{}", hex.to_uppercase()),
            format!("sha256:{hex}"),
            format!("sha512:{hex}{hex}"),
            fuz_crypto::ContentHash::sha512(b"abc").to_sri(),
            format!("{FACT_HASH_PREFIX}{}", &hex[1..]),
            format!("{FACT_HASH_PREFIX}{hex}0"),
            format!(" {FACT_HASH_PREFIX}{hex}"),
            format!("{FACT_HASH_PREFIX}{hex}\n"),
            format!("BLAKE3:{hex}"),
            hex,
            FACT_HASH_PREFIX.to_owned(),
            String::new(),
        ] {
            assert_eq!(
                is_valid_fact_hash(&s),
                fuz_crypto::ContentHash::parse_fact_hash(&s).is_ok(),
                "{s:?}"
            );
        }
    }
}
