//! `_testing_origin_check` action spec.
//!
//! Runs the spine's origin allowlist over the wire, so a cross-backend
//! conformance table owned by the TS twin can check the Rust grammar and
//! matcher row by row against the same expectations it checks the TS ones
//! against. Pure: no database read, no state.
//!
//! Reads `{patterns: string, origin: string | null, hosts?: string[]}`.
//! `patterns` goes through
//! [`fuz_http::AllowedOrigins::parse`]; a refusal answers
//! `{ok: false, errors: [{index?, kind}]}` — one entry per reason, `index` the
//! 1-based entry position (absent for a list-level reason), `kind` the shared
//! wire name. A list that parses answers `{ok: true, allowed}`, where `allowed`
//! is the request-level answer for one `Origin` header carrying `origin`: an
//! absent `Origin` (`null`) passes, any other value must be one the list
//! allows. With `hosts`, the request also carries those `Host` header values
//! and must pass the host gate's check
//! ([`fuz_http::AllowedOrigins::allows_request_hosts`]; `[]` is a request
//! without one). Mirrors `fuz_app`'s TS `_testing_origin_check`.
//!
//! Gated on the daemon-token credential, matching `_testing_reset`.

use std::sync::Arc;

use fuz_actions::{ActionContext, ActionHandler, ActionSpec};
use fuz_http::{AllowedOrigins, InputShape, invalid_input_params};
use serde_json::{Map, Value, json};

/// Declared input keys — the exact key set of the TS twin's
/// `testing_origin_check_action_spec.input` strict object.
const TESTING_ORIGIN_CHECK_KEYS: &[&str] = &["patterns", "origin", "hosts"];

/// Build the `_testing_origin_check` action spec.
#[must_use]
pub fn create_testing_origin_check_action_spec() -> ActionSpec {
    let handler: ActionHandler = Arc::new(move |params: Value, _ctx: ActionContext<'_>| {
        Box::pin(async move {
            fuz_http::reject_unknown_keys(&params, TESTING_ORIGIN_CHECK_KEYS)?;
            let patterns = params
                .get("patterns")
                .and_then(Value::as_str)
                .ok_or_else(|| invalid_input_params("patterns (string) is required", None))?;
            // `nullable(string)` on the twin: required, `null` or a string
            let origin = match params.get("origin") {
                Some(Value::Null) => None,
                Some(Value::String(origin)) => Some(origin.as_str()),
                _ => {
                    return Err(invalid_input_params(
                        "origin (string or null) is required",
                        None,
                    ));
                }
            };
            // `optional(array(string))` on the twin
            let hosts: Option<Vec<&str>> = match params.get("hosts") {
                None => None,
                Some(Value::Array(values)) => Some(
                    values
                        .iter()
                        .map(Value::as_str)
                        .collect::<Option<Vec<_>>>()
                        .ok_or_else(|| {
                            invalid_input_params("hosts must be an array of strings", None)
                        })?,
                ),
                Some(_) => {
                    return Err(invalid_input_params(
                        "hosts must be an array of strings",
                        None,
                    ));
                }
            };
            Ok(match AllowedOrigins::parse(patterns) {
                Err(errors) => {
                    let errors: Vec<Value> = errors
                        .errors()
                        .iter()
                        .map(|error| {
                            let mut entry = Map::new();
                            if let Some(position) = error.position() {
                                entry.insert("index".to_owned(), json!(position));
                            }
                            entry.insert("kind".to_owned(), json!(error.kind()));
                            Value::Object(entry)
                        })
                        .collect();
                    json!({ "ok": false, "errors": errors })
                }
                Ok(allowed) => {
                    let allowed = origin.is_none_or(|origin| allowed.allows(origin))
                        && hosts
                            .as_deref()
                            .is_none_or(|hosts| allowed.allows_request_hosts(hosts));
                    json!({ "ok": true, "allowed": allowed })
                }
            })
        })
    });

    ActionSpec::read_only(
        "_testing_origin_check",
        crate::TESTING_ACTION_AUTH,
        InputShape::Object,
        handler,
    )
}
