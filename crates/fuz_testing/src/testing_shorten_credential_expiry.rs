//! `_testing_shorten_credential_expiry` action spec.
//!
//! Pulls the expiry of an account's stored credentials — every `auth_session`
//! row and every `api_token` row it owns — in to `seconds` from now, so the
//! cross-backend credential-deadline cases can open a WebSocket or SSE stream
//! on a credential that expires a moment later, and watch the connection
//! close at its deadline (`fuz_auth::ResolvedAuth::credential_deadline`)
//! without waiting out a real lifetime.
//!
//! Applied **before the open**: it rewrites the stored rows, and a connection
//! reads its deadline when it resolves its credential, so only a connection
//! opened afterwards sees the near deadline. One already open keeps the
//! deadline it resolved.
//!
//! **Shorten-only.** The new expiry is `LEAST(expires_at, NOW() + seconds)` —
//! an eternal token (`expires_at IS NULL`) gains one, and nothing already due
//! sooner moves later, so the action cannot extend a credential's life or
//! revive an expired one. `seconds` is an integer in
//! `TESTING_SHORTEN_CREDENTIAL_EXPIRY_MIN_SECONDS..=TESTING_SHORTEN_CREDENTIAL_EXPIRY_MAX_SECONDS`.
//!
//! Reads `{account_id: string, seconds: number}`; answers
//! `{sessions, api_tokens}`, the row counts it rewrote. Gated on the
//! daemon-token credential, matching `_testing_reset`. Mirrors `fuz_app`'s TS
//! `_testing_shorten_credential_expiry`.

use std::sync::Arc;

use fuz_actions::{ActionContext, ActionHandler, ActionSpec};
use fuz_http::{InputShape, JsonrpcError, internal_error_with_source, invalid_input_params};
use serde_json::{Value, json};

/// The shortest expiry the action sets, in seconds from now.
pub(crate) const TESTING_SHORTEN_CREDENTIAL_EXPIRY_MIN_SECONDS: i32 = 1;

/// The longest expiry the action sets, in seconds from now — a minute: the
/// action exists to make a deadline arrive inside a test.
pub(crate) const TESTING_SHORTEN_CREDENTIAL_EXPIRY_MAX_SECONDS: i32 = 60;

/// Declared input keys — the exact key set of the TS twin's
/// `testing_shorten_credential_expiry_action_spec.input` strict object.
const TESTING_SHORTEN_CREDENTIAL_EXPIRY_KEYS: &[&str] = &["account_id", "seconds"];

/// Parse + validate `{account_id: string, seconds: number}`: a UUID, and an
/// integer within the action's range (the twin's
/// `pipe(number, safe_integer, min_value(1), max_value(60))`). Pure, so the bounds are unit-testable.
fn parse_shorten_params(params: &Value) -> Result<(uuid::Uuid, i32), JsonrpcError> {
    fuz_http::reject_unknown_keys(params, TESTING_SHORTEN_CREDENTIAL_EXPIRY_KEYS)?;
    let account_id = params
        .get("account_id")
        .and_then(Value::as_str)
        .filter(|s| fuz_http::is_valid_uuid(s))
        .and_then(|s| uuid::Uuid::parse_str(s).ok())
        .ok_or_else(|| invalid_input_params("account_id must be a valid UUID", None))?;
    let seconds = params
        .get("seconds")
        .and_then(Value::as_f64)
        .filter(|s| s.fract() == 0.0)
        .filter(|s| {
            (f64::from(TESTING_SHORTEN_CREDENTIAL_EXPIRY_MIN_SECONDS)
                ..=f64::from(TESTING_SHORTEN_CREDENTIAL_EXPIRY_MAX_SECONDS))
                .contains(s)
        })
        .ok_or_else(|| {
            invalid_input_params(
                "seconds must be an integer from 1 to 60 (this action only shortens a credential's life)",
                None,
            )
        })?;
    // in range, so exact
    #[allow(clippy::cast_possible_truncation)]
    Ok((account_id, seconds as i32))
}

/// The new expiry: `seconds` from now, unless the row is due sooner. `LEAST`
/// over the `COALESCE` gives an eternal token (`NULL`) the near expiry too.
const SHORTEN_EXPIRES_AT_SQL: &str = "LEAST(COALESCE(expires_at, 'infinity'::timestamptz), NOW() + ($2::int4 * INTERVAL '1 second'))";

/// Build the `_testing_shorten_credential_expiry` action spec.
///
/// `side_effects: true`, so the dispatcher wraps both updates in one
/// transaction.
#[must_use]
pub fn create_testing_shorten_credential_expiry_action_spec() -> ActionSpec {
    let handler: ActionHandler = Arc::new(move |params: Value, ctx: ActionContext<'_>| {
        Box::pin(async move {
            let (account_id, seconds) = parse_shorten_params(&params)?;
            let sessions = ctx
                .db
                .execute(
                    &format!(
                        "UPDATE auth_session SET expires_at = {SHORTEN_EXPIRES_AT_SQL} \
                         WHERE account_id = $1"
                    ),
                    &[&account_id, &seconds],
                )
                .await
                .map_err(|e| internal_error_with_source("UPDATE auth_session", &e))?;
            let api_tokens = ctx
                .db
                .execute(
                    &format!(
                        "UPDATE api_token SET expires_at = {SHORTEN_EXPIRES_AT_SQL} \
                         WHERE account_id = $1"
                    ),
                    &[&account_id, &seconds],
                )
                .await
                .map_err(|e| internal_error_with_source("UPDATE api_token", &e))?;
            Ok(json!({ "sessions": sessions, "api_tokens": api_tokens }))
        })
    });

    ActionSpec::with_side_effects(
        "_testing_shorten_credential_expiry",
        crate::TESTING_ACTION_AUTH,
        InputShape::Object,
        handler,
    )
}

#[cfg(test)]
mod tests {
    use super::{TESTING_SHORTEN_CREDENTIAL_EXPIRY_KEYS, parse_shorten_params};
    use serde_json::json;

    const NIL_UUID: &str = "00000000-0000-0000-0000-000000000000";

    #[test]
    fn accepts_the_range_bounds() {
        for seconds in [1, 2, 60] {
            let (_, parsed) =
                parse_shorten_params(&json!({"account_id": NIL_UUID, "seconds": seconds}))
                    .expect("an in-range integer parses");
            assert_eq!(parsed, seconds);
        }
    }

    /// The bounds hold the action to shortening a credential within a test:
    /// nothing at or below zero, nothing past a minute, nothing fractional.
    #[test]
    fn refuses_out_of_range_and_fractional_seconds() {
        for seconds in [
            json!(0),
            json!(-1),
            json!(61),
            json!(3_153_600_000_i64),
            json!(1.5),
        ] {
            assert!(
                parse_shorten_params(&json!({"account_id": NIL_UUID, "seconds": seconds})).is_err(),
                "{seconds} must be refused"
            );
        }
        assert!(parse_shorten_params(&json!({"account_id": NIL_UUID})).is_err());
        assert!(parse_shorten_params(&json!({"account_id": "nope", "seconds": 2})).is_err());
    }

    #[test]
    fn refuses_an_unknown_key() {
        assert_eq!(
            TESTING_SHORTEN_CREDENTIAL_EXPIRY_KEYS,
            ["account_id", "seconds"]
        );
        assert!(
            parse_shorten_params(&json!({"account_id": NIL_UUID, "seconds": 2, "extend": true}))
                .is_err()
        );
    }
}
