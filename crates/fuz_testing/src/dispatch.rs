//! Drive the action dispatcher (`fuz_actions::perform_action`) directly, as a
//! transport would, for a suite that tests actions without HTTP or a socket.
//!
//! The overview is the crate doc § The dispatcher harness.

#![expect(
    clippy::expect_used,
    clippy::panic,
    reason = "a test harness: a setup fault or a failed check panics loudly, and the in-tests carve-out doesn't reach a library module"
)]

use std::sync::Arc;

use axum::http::StatusCode;
use fuz_actions::perform_action::{PerformActionInput, PerformActionOptions, perform_action};
use fuz_actions::{ActionOutput, ActionRegistry, ActionSpec};
use fuz_auth::ResolvedAuth;
use fuz_auth::{AuditEmitter, CredentialType, NoopConnectionCloser, NoopNotificationSender};
use fuz_db::Pool;
use fuz_http::JsonrpcError;
use serde_json::{Value, json};
use uuid::Uuid;

/// Dispatcher options over `specs` on `pool`: an audit emitter on the pool, a
/// no-op connection closer and notification sender, the HTTP no-op peer, and
/// no rate limiters.
///
/// A suite that observes a side channel, or shares the emitter or closer with
/// the specs it built, sets that field with the struct-update syntax
/// (`PerformActionOptions { connection_closer, ..dispatch_options(pool, specs) }`).
///
/// # Panics
///
/// When `specs` don't compile into a registry (a duplicate method).
#[must_use]
pub fn dispatch_options(pool: &Pool, specs: Vec<ActionSpec>) -> PerformActionOptions {
    PerformActionOptions {
        pool: pool.clone(),
        registry: Arc::new(ActionRegistry::compile(specs).expect("the specs compile")),
        audit: Arc::new(AuditEmitter::new(pool.clone(), Arc::default())),
        connection_closer: Arc::new(NoopConnectionCloser),
        notification_sender: Arc::new(NoopNotificationSender),
        peer: fuz_realtime::noop_action_peer(),
        account_rate_limiter: None,
        ip_rate_limiter: None,
    }
}

/// Dispatch `method` with `params` as `account_id`, over a fresh full-scope
/// credential of `credential_type` resolved through the credential walk.
///
/// # Errors
///
/// The dispatcher's refusal, or the handler's error.
///
/// # Panics
///
/// As [`crate::resolve_test_credential`]: the account doesn't resolve, or a
/// database fault minting its credential.
pub async fn perform_as(
    options: &PerformActionOptions,
    method: &str,
    params: Value,
    account_id: Uuid,
    credential_type: CredentialType,
) -> Result<ActionOutput, JsonrpcError> {
    let auth = crate::resolve_test_credential(&options.pool, account_id, credential_type).await;
    perform_with_auth(options, method, params, Some(&auth)).await
}

/// Dispatch `method` with `params` under `auth` — a credential the test
/// resolved itself, or `None` for an unauthenticated call.
///
/// # Errors
///
/// The dispatcher's refusal, or the handler's error.
pub async fn perform_with_auth(
    options: &PerformActionOptions,
    method: &str,
    params: Value,
    auth: Option<&ResolvedAuth>,
) -> Result<ActionOutput, JsonrpcError> {
    let request_id = json!(1);
    let signal = fuz_realtime::SignalToken::new();
    let span = tracing::Span::none();
    let notify: &(dyn Fn(&str, &Value) + Send + Sync) = &fuz_realtime::http_no_op_notify;
    let input = PerformActionInput {
        method,
        params: &params,
        request_id: &request_id,
        auth,
        client_ip: None,
        connection_id: None,
        notify,
        signal: &signal,
        log: &span,
    };
    perform_action(input, options).await
}

/// The success payload of a dispatched call, as its envelope's `result`
/// carries it.
///
/// # Panics
///
/// When the call failed, naming its status and error, or its output doesn't
/// render.
#[track_caller]
pub fn assert_rpc_ok(result: Result<ActionOutput, JsonrpcError>) -> Value {
    match result {
        Ok(output) => output.to_value().expect("the output renders"),
        Err(error) => {
            let status = fuz_http::error_code_to_http_status(error.code);
            panic!("expected Ok, got {status}: {error:?}")
        }
    }
}

/// The HTTP status and `data.reason` of a refused call — what a test of a
/// refusal compares.
///
/// # Panics
///
/// When the call succeeded.
#[track_caller]
pub fn rpc_refusal(result: &Result<ActionOutput, JsonrpcError>) -> (StatusCode, Option<&str>) {
    match result {
        Err(error) => (
            fuz_http::error_code_to_http_status(error.code),
            error
                .data
                .as_ref()
                .and_then(|data| data.get("reason"))
                .and_then(Value::as_str),
        ),
        Ok(output) => panic!("expected a refusal, got Ok: {output:?}"),
    }
}

/// Assert a call was refused with `status` and `data.reason` `reason`.
///
/// # Panics
///
/// When the call succeeded, or was refused with another status or reason.
#[track_caller]
pub fn assert_rpc_err(
    result: &Result<ActionOutput, JsonrpcError>,
    status: StatusCode,
    reason: &str,
) {
    assert_eq!(
        rpc_refusal(result),
        (status, Some(reason)),
        "the refusal: {result:?}"
    );
}
