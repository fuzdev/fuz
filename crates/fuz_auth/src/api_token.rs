//! API token generation utilities.
//!
//! Mirrors `fuz_app`'s `src/lib/auth/api_token.ts`. Tokens issued by
//! either backend interoperate at the wire level — token format and
//! hash are stable.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// Prefix on every raw token (enables secret scanners to match the
/// literal).
pub const API_TOKEN_PREFIX: &str = "secret_fuz_token_";

/// Prefix on the public token id (e.g. `tok_abC0_d-3xyzA`). Twin of
/// `fuz_app`'s `API_TOKEN_ID_PREFIX`.
pub const API_TOKEN_ID_PREFIX: &str = "tok_";

/// Length of the public id's body — the raw token body's first characters.
/// Twin of `fuz_app`'s `API_TOKEN_ID_BODY_LENGTH`.
pub const API_TOKEN_ID_BODY_LENGTH: usize = 12;

/// Number of random bytes encoded into the raw token body — 32 bytes /
/// 256 bits of entropy (matches `fuz_app`'s default).
const TOKEN_ENTROPY_BYTES: usize = 32;

/// Length of the unpadded base64url body encoding [`TOKEN_ENTROPY_BYTES`].
const TOKEN_BODY_LEN: usize = (TOKEN_ENTROPY_BYTES * 4).div_ceil(3);

/// Length of a raw token: [`API_TOKEN_PREFIX`] plus the encoded body.
pub const API_TOKEN_LEN: usize = API_TOKEN_PREFIX.len() + TOKEN_BODY_LEN;

/// Whether `raw` has the shape of a raw API token — [`API_TOKEN_PREFIX`]
/// followed by exactly the generated body length of base64url characters.
///
/// The bearer path's precheck, so a value that cannot be a token costs no
/// pool checkout and no query. A `true` says nothing about whether the token
/// exists. Twin of `fuz_app`'s `is_api_token_shaped`.
#[must_use]
pub fn is_api_token_shaped(raw: &str) -> bool {
    raw.len() == API_TOKEN_LEN
        && raw.starts_with(API_TOKEN_PREFIX)
        && raw.as_bytes()[API_TOKEN_PREFIX.len()..]
            .iter()
            .all(|&b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Hash a raw API token to its storage key: the blake3 digest of the whole
/// token, prefix included, as 64 lowercase hex characters — the
/// `api_token.token_hash` column.
///
/// Twin of `fuz_app`'s `hash_api_token` (`auth/api_token.ts`): both spines
/// store and look up the same key, so a token minted by either authenticates
/// on both.
#[must_use]
pub fn hash_api_token(token: &str) -> String {
    blake3::hash(token.as_bytes()).to_hex().to_string()
}

/// The public id of a raw API token: [`API_TOKEN_ID_PREFIX`] and the first
/// [`API_TOKEN_ID_BODY_LENGTH`] characters of the body after
/// [`API_TOKEN_PREFIX`].
///
/// Twin of `fuz_app`'s `to_api_token_id` (`auth/api_token.ts`): both spines
/// derive the id the same way, so a token minted by either names the same id
/// on both. `None` when `token` is not [`is_api_token_shaped`], where the TS
/// twin throws — a caller holds a minted or prechecked token.
#[must_use]
pub fn to_api_token_id(token: &str) -> Option<String> {
    if !is_api_token_shaped(token) {
        return None;
    }
    let body_start = API_TOKEN_PREFIX.len();
    // a shaped token is ASCII, so the byte range is a char range
    let id_body = token.get(body_start..body_start + API_TOKEN_ID_BODY_LENGTH)?;
    Some(format!("{API_TOKEN_ID_PREFIX}{id_body}"))
}

/// Whether `s` is a valid public API token id — the id `account_token_create`
/// hands back and `account_token_revoke` takes.
///
/// Twin of the TS `ApiTokenId` schema (`pipe(string, regex(API_TOKEN_ID_REGEX))`
/// in `auth/api_token.ts`), whose regex is `^tok_[A-Za-z0-9_-]{12}$`: the
/// literal [`API_TOKEN_ID_PREFIX`] followed by exactly
/// [`API_TOKEN_ID_BODY_LENGTH`] base64url characters
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
/// [`is_valid_username_for_creation`](crate::is_valid_username_for_creation)
/// is: `regex` isn't a workspace dependency, and a byte scan is faster than a
/// DFA compile.
#[must_use]
pub fn is_valid_api_token_id(s: &str) -> bool {
    let Some(suffix) = s.strip_prefix(API_TOKEN_ID_PREFIX) else {
        return false;
    };
    // `len()` is byte length; the base64url class below is ASCII-only, so a
    // multibyte character fails the class check rather than slipping the
    // count.
    suffix.len() == API_TOKEN_ID_BODY_LENGTH
        && suffix
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// A freshly generated API token.
///
/// `Debug` redacts the raw token; the id and hash stay visible.
#[derive(Clone)]
pub struct GeneratedApiToken {
    /// Raw token — shown to the user exactly once. Wire format:
    /// `secret_fuz_token_<base64url(32 bytes, no padding)>`.
    pub token: String,
    /// Public id — wire format: `tok_<first 12 chars of base64url body>`.
    pub id: String,
    /// blake3 hex digest of `token` — stored in `api_token.token_hash`.
    pub token_hash: String,
}

impl std::fmt::Debug for GeneratedApiToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GeneratedApiToken")
            .field("token", &"<redacted>")
            .field("id", &self.id)
            .field("token_hash", &self.token_hash)
            .finish()
    }
}

/// Generate a new API token.
///
/// Byte-compatible with `fuz_app`'s `generate_api_token`.
///
/// # Panics
///
/// Panics if `getrandom::fill` fails — on supported platforms this is
/// effectively unreachable (the OS RNG is always available).
#[must_use]
pub fn generate_api_token() -> GeneratedApiToken {
    let mut bytes = [0u8; TOKEN_ENTROPY_BYTES];
    #[expect(
        clippy::expect_used,
        reason = "OS RNG availability is a platform invariant"
    )]
    getrandom::fill(&mut bytes).expect("getrandom should always succeed on supported platforms");
    let token = format!("{API_TOKEN_PREFIX}{}", URL_SAFE_NO_PAD.encode(bytes));
    let token_hash = hash_api_token(&token);
    #[expect(
        clippy::expect_used,
        reason = "a generated token is API-token shaped by construction"
    )]
    let id = to_api_token_id(&token).expect("a generated token is API-token shaped");
    GeneratedApiToken {
        token,
        id,
        token_hash,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_token_matches_fuz_app_shape() {
        let g = generate_api_token();

        assert!(g.token.starts_with(API_TOKEN_PREFIX));
        let body = &g.token[API_TOKEN_PREFIX.len()..];
        assert_eq!(body.len(), 43, "32 bytes base64url-encoded (unpadded)");
        assert!(
            body.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        );

        assert!(g.id.starts_with(API_TOKEN_ID_PREFIX));
        assert_eq!(
            g.id.len(),
            API_TOKEN_ID_PREFIX.len() + API_TOKEN_ID_BODY_LENGTH
        );
        assert_eq!(
            &g.id[API_TOKEN_ID_PREFIX.len()..],
            &body[..API_TOKEN_ID_BODY_LENGTH]
        );
        assert!(is_valid_api_token_id(&g.id), "{}", g.id);

        assert_eq!(g.token_hash.len(), 64);
        assert_eq!(
            g.token_hash,
            blake3::hash(g.token.as_bytes()).to_hex().to_string()
        );
    }

    #[test]
    fn debug_redacts_the_raw_token() {
        let g = generate_api_token();
        let body = &g.token[API_TOKEN_PREFIX.len()..];
        let rendered = format!("{g:?}");
        assert!(!rendered.contains(body), "{rendered}");
        assert!(!rendered.contains(API_TOKEN_PREFIX), "{rendered}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
        assert!(rendered.contains(&g.id), "{rendered}");
    }

    #[test]
    fn token_is_sixty_chars() {
        assert_eq!(TOKEN_BODY_LEN, 43);
        assert_eq!(API_TOKEN_LEN, 60);
        assert_eq!(generate_api_token().token.len(), API_TOKEN_LEN);
    }

    #[test]
    fn shaped_accepts_every_generated_token() {
        for _ in 0..200 {
            let g = generate_api_token();
            assert!(is_api_token_shaped(&g.token), "{}", g.token);
        }
    }

    #[test]
    fn shaped_refuses_malformed_values() {
        let valid = format!("{API_TOKEN_PREFIX}{}", "A".repeat(TOKEN_BODY_LEN));
        assert!(is_api_token_shaped(&valid));
        let body = &valid[API_TOKEN_PREFIX.len()..];
        let short = &valid[..valid.len() - 1];
        let refused = [
            ("empty", String::new()),
            ("prefix alone", API_TOKEN_PREFIX.to_owned()),
            ("body one char short", short.to_owned()),
            ("body one char long", format!("{valid}A")),
            ("no prefix", body.to_owned()),
            (
                "wrong prefix at the right length",
                format!("secret_fuz_tokem_{body}"),
            ),
            (
                "uppercased prefix",
                format!("{}{body}", API_TOKEN_PREFIX.to_uppercase()),
            ),
            ("padding char", format!("{short}=")),
            ("standard base64 char", format!("{short}+")),
            ("slash", format!("{short}/")),
            ("trailing whitespace", format!("{short} ")),
            ("leading whitespace", format!(" {}", &valid[1..])),
            ("a char before a whole token", format!("x{valid}")),
            ("newline", format!("{valid}\n")),
            // two bytes, so the byte length stays right only with one less char
            (
                "non-ASCII letter",
                format!("{}\u{e9}", &short[..short.len() - 1]),
            ),
        ];
        for (name, value) in refused {
            assert!(!is_api_token_shaped(&value), "{name}: {value:?}");
        }
    }

    /// The id is the prefix and the body's first characters, whatever they
    /// are — a fixed token pins the derivation byte for byte.
    #[test]
    fn to_api_token_id_takes_the_body_head() {
        let token = format!(
            "{API_TOKEN_PREFIX}abC0_d-3xyzA{}",
            "Z".repeat(TOKEN_BODY_LEN - API_TOKEN_ID_BODY_LENGTH)
        );
        assert_eq!(to_api_token_id(&token).as_deref(), Some("tok_abC0_d-3xyzA"));
        for _ in 0..50 {
            let g = generate_api_token();
            assert_eq!(to_api_token_id(&g.token), Some(g.id));
        }
    }

    /// Anything not API-token shaped has no id — a bare body, an id, a
    /// truncated or padded token.
    #[test]
    fn to_api_token_id_refuses_what_is_not_a_token() {
        let valid = format!("{API_TOKEN_PREFIX}{}", "A".repeat(TOKEN_BODY_LEN));
        for value in [
            String::new(),
            API_TOKEN_PREFIX.to_owned(),
            valid[API_TOKEN_PREFIX.len()..].to_owned(),
            valid[..valid.len() - 1].to_owned(),
            format!("{valid}A"),
            format!("{valid}\n"),
            "tok_AAAAAAAAAAAA".to_owned(),
        ] {
            assert_eq!(to_api_token_id(&value), None, "{value:?}");
        }
    }

    #[test]
    fn generated_tokens_are_unique() {
        let a = generate_api_token();
        let b = generate_api_token();
        assert_ne!(a.token, b.token);
        assert_ne!(a.id, b.id);
        assert_ne!(a.token_hash, b.token_hash);
    }

    /// Twin of the TS `ApiTokenId` regex `^tok_[A-Za-z0-9_-]{12}$`. The
    /// accepted rows are the shapes `generate_api_token` actually mints (a
    /// base64url slice, so every class member is reachable); the rejected
    /// rows are the strings an ungated handler answers
    /// `{ok: true, revoked: false}` for.
    #[test]
    fn api_token_id_accepts_the_minted_shape() {
        assert!(is_valid_api_token_id("tok_abC0_d-3xyzA"));
        assert!(is_valid_api_token_id("tok_000000000000"));
        assert!(is_valid_api_token_id("tok_zzzzzzzzzzzz"));
        assert!(is_valid_api_token_id("tok_ZZZZZZZZZZZZ"));
        // The two non-alphanumeric class members, at full width — built from
        // the constants so the length bound and the literals can't drift.
        for filler in ['_', '-'] {
            let id = format!(
                "{API_TOKEN_ID_PREFIX}{}",
                filler.to_string().repeat(API_TOKEN_ID_BODY_LENGTH)
            );
            assert_eq!(
                id.len(),
                API_TOKEN_ID_PREFIX.len() + API_TOKEN_ID_BODY_LENGTH
            );
            assert!(is_valid_api_token_id(&id), "{id}");
        }
    }

    #[test]
    fn api_token_id_rejects_off_grammar_strings() {
        // Wrong / missing prefix.
        assert!(!is_valid_api_token_id(""));
        assert!(!is_valid_api_token_id("abC0_d-3xyzA"));
        assert!(!is_valid_api_token_id("tok-abC0_d-3xyzA"));
        assert!(!is_valid_api_token_id("TOK_abC0_d-3xyzA"));
        assert!(!is_valid_api_token_id(" tok_abC0_d-3xyzA"));
        // Wrong suffix length, either side of the bound.
        assert!(!is_valid_api_token_id("tok_abC0_d-3xyz"));
        assert!(!is_valid_api_token_id("tok_abC0_d-3xyzAB"));
        assert!(!is_valid_api_token_id("tok_"));
        // Characters outside base64url — including the base64 pair `+/` and
        // the `=` padding that base64url drops.
        assert!(!is_valid_api_token_id("tok_abC0+d-3xyzA"));
        assert!(!is_valid_api_token_id("tok_abC0/d-3xyzA"));
        assert!(!is_valid_api_token_id("tok_abC0=d-3xyzA"));
        assert!(!is_valid_api_token_id("tok_abC0 d-3xyzA"));
        // The shapes a caller actually sends when it has the wrong id: a
        // UUID, a bare word, and a SQL-injection probe.
        assert!(!is_valid_api_token_id(
            "3f8a1c2e-1234-4abc-9def-0123456789ab"
        ));
        assert!(!is_valid_api_token_id("not-a-token"));
        assert!(!is_valid_api_token_id("' OR 1=1--"));
        // Non-ASCII: twelve characters after the prefix, more than twelve
        // bytes, and outside the class either way.
        assert!(!is_valid_api_token_id("tok_\u{FC}bC0_d-3xyz"));
    }
}
