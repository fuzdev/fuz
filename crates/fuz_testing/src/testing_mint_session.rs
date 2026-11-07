//! `_testing_mint_session` action spec.
//!
//! Test binaries register this on their `ActionRegistry` alongside
//! `_testing_reset` / `_testing_drain_effects`. It mints an
//! *expired-by-construction* server-side session for an existing account
//! and returns its signed cookie value, so the cross-backend expiry
//! conformance cases (the `expired_session` principal) can assert the
//! authoritative server-side **DB-row** expiry gate.
//!
//! `expires_in_seconds` is **constrained negative** (the handler refuses
//! anything but a negative safe integer with `invalid_params`, mirroring the TS
//! spec's `pipe(number, safe_integer, max_value(-1))`): the action is structurally incapable of
//! minting a *usable* session — only an already-backdated, already-dead row.
//! The daemon-token gate (a credential only a test binary mounts) and the test
//! binary's default loopback bind already fence the backdoor — the bind is a
//! default, and nothing checks the peer address; the negative constraint is
//! the make-impossible-states floor so even a misuse can't forge a valid
//! session for an arbitrary `account_id`.
//!
//! The minted `auth_session` row's `expires_at` is offset from `NOW()` by
//! the caller's `expires_in_seconds` (negative → backdated), while the
//! returned cookie's own signed payload stays valid (future). Auth
//! resolution therefore clears the cookie-payload gate
//! (`parse_session_from_cookies`) and is refused by the DB-row gate
//! (`query_session_get_valid` — `WHERE expires_at > NOW()`) — the gate the
//! in-process payload-expiry tests never reach and the one that
//! structurally needs a server-side mint (the cross-process driver has no
//! keyring / DB access).
//!
//! Gated on the daemon-token credential — effectively keeper-only without
//! forcing the `actor: 'required'` biconditional, matching `_testing_reset`.
//! Mirrors `fuz_app`'s TS `_testing_mint_session`.

use std::sync::Arc;

use fuz_actions::{ActionContext, ActionHandler, ActionSpec};
use fuz_auth::hash::hash_session_token;
use fuz_auth::keyring::Keyring;
use fuz_auth::session_cookie::{generate_session_token, sign_session_cookie};
use fuz_http::{
    InputShape, JsonrpcError, SAFE_INTEGER_MAX, internal_error_with_source, invalid_input_params,
};
use serde_json::{Value, json};

/// Declared input keys — the exact key set of the TS twin's
/// `testing_mint_session_action_spec.input` strict object. Both fields are
/// required, so neither admits a `null`.
const TESTING_MINT_SESSION_KEYS: &[&str] = &["account_id", "expires_in_seconds"];

/// Parse + validate `_testing_mint_session` params
/// (`{account_id: string, expires_in_seconds: number}`).
///
/// `expires_in_seconds` is **constrained negative** — mirroring the TS spec's
/// `pipe(number, safe_integer, max_value(-1))`, whose `safe_integer` also
/// bounds it to the safe integers (no smaller than `-SAFE_INTEGER_MAX`) — so the action can only
/// mint an already-expired (backdated) row, never a usable session for an
/// arbitrary account, and never an offset past what Postgres can add to
/// `NOW()`. Returns the parsed pair, or the generic `invalid params` the twin's
/// schema answers ([`invalid_input_params`]) for a missing/ill-typed field or an
/// expiry outside that range. Pure (no DB), so the constraint is unit-testable
/// without a Postgres handle.
fn parse_mint_session_params(params: &Value) -> Result<(uuid::Uuid, f64), JsonrpcError> {
    fuz_http::reject_unknown_keys(params, TESTING_MINT_SESSION_KEYS)?;
    let account_id_str = params
        .get("account_id")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_input_params("account_id (string) is required", None))?;
    let account_id = Some(account_id_str)
        .filter(|s| fuz_http::is_valid_uuid(s))
        .and_then(|s| uuid::Uuid::parse_str(s).ok())
        .ok_or_else(|| invalid_input_params("account_id must be a valid UUID", None))?;
    let expires_in_seconds = params
        .get("expires_in_seconds")
        .and_then(Value::as_f64)
        .ok_or_else(|| invalid_input_params("expires_in_seconds (number) is required", None))?;
    #[allow(
        clippy::cast_precision_loss,
        reason = "`SAFE_INTEGER_MAX` is 2^53 - 1, exact as an `f64`"
    )]
    let safe_min = -(SAFE_INTEGER_MAX as f64);
    if expires_in_seconds.fract() != 0.0
        || expires_in_seconds >= 0.0
        || expires_in_seconds < safe_min
    {
        return Err(invalid_input_params(
            "expires_in_seconds must be a negative safe integer (this action only mints already-expired sessions)",
            None,
        ));
    }
    Ok((account_id, expires_in_seconds))
}

/// Build the `_testing_mint_session` action spec bound to `keyring`.
///
/// `cookie_name` is the per-app session cookie name (default
/// [`fuz_auth::SESSION_COOKIE_NAME`]) the minted cookie is signed under.
///
/// `side_effects: true` so the dispatcher wraps the row insert in a
/// transaction (committed on success). The handler reads
/// `{account_id: string, expires_in_seconds: number}` from the params,
/// inserts a backdated `auth_session` row, and returns
/// `{session_cookie: string}` — the signed cookie VALUE (name + attributes
/// stripped, matching `_testing_reset`'s seeded-account shape) for the
/// caller's cookie jar.
#[must_use]
pub fn create_testing_mint_session_action_spec(
    keyring: Arc<Keyring>,
    cookie_name: &'static str,
) -> ActionSpec {
    let handler: ActionHandler = Arc::new(move |params: Value, ctx: ActionContext<'_>| {
        let keyring = Arc::clone(&keyring);
        Box::pin(async move {
            let (account_id, expires_in_seconds) = parse_mint_session_params(&params)?;

            // Real session row, backdated expiry. `make_interval(secs => $3)`
            // offsets from NOW(); a negative value lands the row in the past so
            // the DB-row expiry gate refuses it. The signed cookie below keeps
            // a valid (future) payload, so resolution reaches that gate rather
            // than short-circuiting at the cookie-payload check.
            let session_token = generate_session_token();
            let session_hash = hash_session_token(&session_token);
            let session_hash_str = session_hash.as_str();
            ctx.db
                .execute(
                    "INSERT INTO auth_session (id, account_id, expires_at) \
                     VALUES ($1, $2, NOW() + ($3::double precision * INTERVAL '1 second'))",
                    &[&session_hash_str, &account_id, &expires_in_seconds],
                )
                .await
                .map_err(|e| internal_error_with_source("INSERT auth_session", &e))?;

            // `sign_session_cookie` returns the full `Set-Cookie` header value;
            // strip the `name=` prefix + trailing attributes so the response
            // carries just the signed VALUE (TS callers thread it into a jar).
            let signed_cookie = sign_session_cookie(&keyring, &session_token, cookie_name);
            let prefix = format!("{cookie_name}=");
            let after_prefix = signed_cookie
                .strip_prefix(&prefix)
                .unwrap_or(&signed_cookie);
            let cookie_value = after_prefix
                .split(';')
                .next()
                .unwrap_or(after_prefix)
                .to_owned();

            Ok(json!({ "session_cookie": cookie_value }))
        })
    });

    ActionSpec::with_side_effects(
        "_testing_mint_session",
        crate::TESTING_ACTION_AUTH,
        InputShape::Object,
        handler,
    )
}

#[cfg(test)]
mod tests {
    use super::{TESTING_MINT_SESSION_KEYS, parse_mint_session_params};
    use fuz_http::{INVALID_PARAMS_MESSAGE, JsonrpcErrorCode, SAFE_INTEGER_MAX};
    use serde_json::{Value, json};

    const NIL_UUID: &str = "00000000-0000-0000-0000-000000000000";

    #[test]
    fn accepts_a_negative_expiry() {
        let (_, secs) =
            parse_mint_session_params(&json!({"account_id": NIL_UUID, "expires_in_seconds": -60}))
                .expect("negative expiry must parse");
        assert!(secs < 0.0);
    }

    #[test]
    fn rejects_a_positive_expiry() {
        // A positive expiry would mint a *valid* session for an arbitrary
        // account — the constraint that closes that off.
        assert!(
            parse_mint_session_params(&json!({"account_id": NIL_UUID, "expires_in_seconds": 60}))
                .is_err(),
            "a positive expiry must be rejected"
        );
    }

    #[test]
    fn rejects_a_zero_expiry() {
        assert!(
            parse_mint_session_params(&json!({"account_id": NIL_UUID, "expires_in_seconds": 0}))
                .is_err(),
            "a zero expiry must be rejected"
        );
    }

    #[test]
    fn rejects_a_missing_expiry() {
        assert!(
            parse_mint_session_params(&json!({"account_id": NIL_UUID})).is_err(),
            "a missing expiry must be rejected"
        );
    }

    #[test]
    fn rejects_a_malformed_account_id() {
        assert!(
            parse_mint_session_params(
                &json!({"account_id": "not-a-uuid", "expires_in_seconds": -60})
            )
            .is_err(),
            "a malformed account_id must be rejected"
        );
    }

    /// The gate the `params.get` chain cannot carry: the twin's input is a
    /// strict `object`, so a key it does not declare — `acting` included, the
    /// spec having no actor axis — is `-32602` rather than ignored.
    #[test]
    fn rejects_an_unknown_key() {
        assert_eq!(
            TESTING_MINT_SESSION_KEYS,
            ["account_id", "expires_in_seconds"],
            "the twin's declared key set"
        );
        assert!(
            parse_mint_session_params(&json!({
                "account_id": NIL_UUID,
                "expires_in_seconds": -60,
                "acting": NIL_UUID,
            }))
            .is_err(),
            "an undeclared key must be refused"
        );
    }

    /// The twin's `pipe(number, safe_integer, max_value(-1))`: an integer,
    /// below zero, and no smaller than `-SAFE_INTEGER_MAX` (`safe_integer`
    /// refuses past the safe range) — so no offset reaches Postgres that it can't add to `NOW()`.
    /// Every refusal is the twin's generic reason-less `invalid params`.
    #[test]
    fn the_expiry_is_a_negative_safe_integer() {
        let parse = |expiry: Value| {
            parse_mint_session_params(
                &json!({"account_id": NIL_UUID, "expires_in_seconds": expiry}),
            )
        };
        assert!(parse(json!(-1)).is_ok());
        assert!(parse(json!(-SAFE_INTEGER_MAX)).is_ok());
        for refused in [
            json!(-SAFE_INTEGER_MAX - 1),
            json!(-9_007_199_254_740_992_i64),
            json!(-1e300),
            json!(-60.5),
            json!(-0.5),
            json!("-60"),
            Value::Null,
        ] {
            let error = parse(refused.clone()).expect_err(&format!("{refused} must be refused"));
            assert_eq!(error.code, JsonrpcErrorCode::InvalidParams, "{refused}");
            assert_eq!(error.message, INVALID_PARAMS_MESSAGE, "{refused}");
            assert!(error.data.is_none(), "{refused}: {error:?}");
        }
    }
}
