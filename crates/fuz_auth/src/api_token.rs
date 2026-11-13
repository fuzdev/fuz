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

/// Prefix on the public token id (e.g. `tok_abC0_d-3xyzA`).
pub const API_TOKEN_ID_PREFIX: &str = "tok_";

/// Number of base64url chars taken from the raw token body for the
/// public id.
const ID_PREFIX_LEN: usize = 12;

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
    let raw = URL_SAFE_NO_PAD.encode(bytes);
    let token = format!("{API_TOKEN_PREFIX}{raw}");
    let token_hash = hash_api_token(&token);
    let id_body: String = raw.chars().take(ID_PREFIX_LEN).collect();
    let id = format!("{API_TOKEN_ID_PREFIX}{id_body}");
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
        assert_eq!(g.id.len(), API_TOKEN_ID_PREFIX.len() + ID_PREFIX_LEN);
        assert_eq!(&g.id[API_TOKEN_ID_PREFIX.len()..], &body[..ID_PREFIX_LEN]);

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

    #[test]
    fn generated_tokens_are_unique() {
        let a = generate_api_token();
        let b = generate_api_token();
        assert_ne!(a.token, b.token);
        assert_ne!(a.id, b.id);
        assert_ne!(a.token_hash, b.token_hash);
    }
}
