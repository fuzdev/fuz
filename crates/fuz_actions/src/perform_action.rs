//! Transport-agnostic dispatch core.
//!
//! The dispatcher owns the transaction wrap, the audit emit boundary, and
//! the post-commit drain. Mirrors `fuz_app`'s `actions/perform_action.ts`
//! shape.
//!
//! ## Enforcement order (401 → authz → 403 → 429 → 400 → handler)
//!
//! 1. **Method lookup** — `method_not_found` (-32601 → HTTP 404) if no
//!    spec is registered.
//! 2. **401** — [`fuz_auth::check_action_auth_pre_authorization`]: a
//!    required-account / required-actor spec needs a resolved account.
//! 3. **Authorization phase** — [`fuz_auth::apply_authorization_phase`]
//!    resolves the acting actor from the account-grain identity + the request's
//!    `acting` input into a [`fuz_auth::ResolvedAuthContext`]. One pool checkout
//!    before the handler's tx. Resolution failures fold into the wire error
//!    (`actor_required` / `actor_not_on_account` 400, `no_actors_on_account` 500).
//!    `read_acting` supplies the selector, reading a malformed one as
//!    omitted — the twin of `fuz_app`'s `parse_acting`.
//! 4. **403** — [`fuz_auth::check_action_auth_post_authorization`]: the
//!    credential-type gate then the **role** gate, the latter over the
//!    *resolved* actor's `role_grants` (the security-critical ordering).
//! 5. **429** — the per-method rate-limit gate for every spec that declares a
//!    class on `ActionSpec::rate_limit`, the auth-family specs included. It
//!    sits **ahead** of validation so a flood of malformed input burns the
//!    budget it should, and so a throttled caller pays no validation work.
//! 6. **400** — input validation, of which the dispatcher owns the params
//!    shape, the prototype-key walk, one field, and the void rule: `params`
//!    must be absent or an object (see `check_params_shape` — the GET query
//!    string carries any JSON value there), must hold no own `__proto__` key
//!    at any depth (`check_params_proto_key`, `data.reason`
//!    [`fuz_http::ERROR_PARAMS_PROTO_KEY`] — a JS client copying stored JSON
//!    back would hit the prototype setter), a *present* `acting` must be a
//!    string passing [`fuz_http::is_valid_uuid`] (see
//!    `check_acting_selector`), and a spec
//!    declaring [`fuz_http::InputShape::Void`] takes only the no-arg call
//!    ([`fuz_http::require_void_params`]), each else `invalid_params`. Every
//!    other field is validated handler-side today.
//!    It sits **after** the authority gates and the rate limit,
//!    matching `fuz_app`'s step 5: a 400 describing the input's shape to a
//!    caller the gates refuse would confirm the method exists and hint at
//!    its schema, so the coarse authority facts are answered before the fine
//!    input ones. The pool checkout step 3 already paid is the cost the
//!    twin's ordering accepts.
//! 7. **Handler** — runs inside a DB transaction iff `spec.side_effects` is
//!    `true`. Audit rows emitted via [`ActionContext::audit_emit`] join the tx.
//! 8. **Post-commit drain** — `post_commit_effects` (audit listener fan-out,
//!    WS broadcasts, log lines) runs **after** the tx commits. On
//!    rollback the queue is dropped without running — and a failed commit is a
//!    rollback, including the one a bare `COMMIT` hides: a handler that
//!    swallowed a failed statement and returned `Ok` leaves the tx aborted,
//!    which [`fuz_db::commit_checked`] detects and refuses (`internal_error`,
//!    logged at `error` as the handler bug it is).
//!
//! ## DEV-only output validation
//!
//! DEV-vs-production output validation: TS gates it on `esm-env`, Rust on
//! `#[cfg(debug_assertions)]`. Currently a no-op — codegen lands the output schema and the validation
//! site is `#[cfg(debug_assertions)]` gated when it does.

use std::sync::Arc;

use deadpool_postgres::Pool;
use fuz_auth::{
    AuditEmitter, AuthGate, AuthSpec, ConnectionCloser, NotificationSender, ResolvedAuth,
    ResolvedAuthContext, apply_authorization_phase, check_action_auth_post_authorization,
    check_action_auth_pre_authorization,
};
use fuz_http::{
    JsonrpcError, db_unavailable_with_source, internal_error_with_source, method_not_found,
};
use fuz_realtime::{ActionPeer, SignalToken};
use serde_json::Value;
use uuid::Uuid;

use crate::action_context::ActionContext;
use crate::action_output::ActionOutput;
use crate::action_rate_limit::ActionRateLimits;
use crate::action_registry::ActionRegistry;
use crate::action_spec::ActionSpecHandler;
use crate::post_commit_effects::PostCommitEffects;
use fuz_db::ActionDb;

/// Inputs assembled by the transport before invoking [`perform_action`].
///
/// Borrowed lifetime `'a` keeps the envelope + auth references on the
/// stack of the calling frame so no `Arc::clone`s are paid here.
pub struct PerformActionInput<'a> {
    pub method: &'a str,
    pub params: &'a Value,
    pub request_id: &'a Value,
    /// The credential the request authenticated with — `None` on anonymous
    /// callers. The dispatcher's authorization phase resolves the acting actor
    /// from its account + the request's `acting` input (the transport does not
    /// bind an actor), the post-authorization gates read its type and scope,
    /// and the handler's [`ActionContext`] its type and session hash.
    pub auth: Option<&'a ResolvedAuth>,
    /// Resolved client IP from `fuz_http::client_ip_middleware`.
    pub client_ip: Option<String>,
    /// `Some(id)` on WS, `None` on HTTP.
    pub connection_id: Option<fuz_realtime::ConnectionId>,
    /// Borrowed notify closure — `&dyn Fn(&str, &Value)`.
    pub notify: &'a (dyn Fn(&str, &Value) + Send + Sync),
    /// Per-request cancellation token.
    pub signal: &'a SignalToken,
    /// Request tracing span.
    pub log: &'a tracing::Span,
}

impl std::fmt::Debug for PerformActionInput<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PerformActionInput")
            .field("method", &self.method)
            .field("request_id", &self.request_id)
            .field(
                "credential_type",
                &self.auth.map(ResolvedAuth::credential_type),
            )
            .field("client_ip", &self.client_ip)
            .field("connection_id", &self.connection_id)
            .finish_non_exhaustive()
    }
}

/// The long-lived state both transports dispatch through.
///
/// The HTTP RPC router ([`crate::create_rpc_router`]) takes it as its state,
/// and the WS endpoint ([`crate::WsRouteState::dispatch`]) holds it beside its
/// connection registry.
///
/// One value per server, built by `AppBackend::action_dispatch`: the same
/// registry, audit emitter, closer, notification fan-out, and limiter pair
/// reach both transports, so a method answers alike whichever one carried
/// it. [`Self::perform_action_options`] adds the one per-transport piece, the
/// server-initiated request capability.
#[derive(Clone)]
pub struct ActionDispatch {
    /// The front door the RPC handlers and the WS upgrade check a request at
    /// — the origin check, then the credential walk ([`AuthGate`]) — and the
    /// pool the dispatcher runs on.
    pub gate: AuthGate,
    pub registry: Arc<ActionRegistry>,
    pub audit: Arc<AuditEmitter>,
    pub connection_closer: Arc<dyn ConnectionCloser>,
    /// Notification fan-out capability. Must be the **same**
    /// `ConnectionRegistry` the WS endpoint populates, or a notification
    /// emitted on the HTTP path reaches an empty registry. `Noop` for
    /// WS-less consumers.
    pub notification_sender: Arc<dyn NotificationSender>,
    /// The action limiters [`perform_action`] charges for a spec that
    /// declares [`crate::ActionSpec::rate_limit`] — the server's one pair,
    /// shared by both transports and the auth spec set.
    pub rate_limits: ActionRateLimits,
}

impl ActionDispatch {
    /// The dispatcher's capabilities for one transport: everything here,
    /// plus `peer` — the registry-backed [`fuz_realtime::ConnectionPeer`] on
    /// the WS path, [`fuz_realtime::noop_action_peer`] (→ `NoTransport`) on
    /// HTTP. Cheap — all `Arc`s.
    #[must_use]
    pub fn perform_action_options(&self, peer: Arc<dyn ActionPeer>) -> PerformActionOptions {
        PerformActionOptions {
            pool: self.gate.pool.clone(),
            registry: Arc::clone(&self.registry),
            audit: Arc::clone(&self.audit),
            connection_closer: Arc::clone(&self.connection_closer),
            notification_sender: Arc::clone(&self.notification_sender),
            peer,
            account_rate_limiter: self.rate_limits.account(),
            ip_rate_limiter: self.rate_limits.ip(),
        }
    }
}

impl std::fmt::Debug for ActionDispatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ActionDispatch")
            .field("gate", &self.gate)
            .field("registry_size", &self.registry.len())
            .finish_non_exhaustive()
    }
}

/// Capabilities the dispatcher needs from the consumer.
///
/// All `Arc`-shared — these are long-lived state pieces composed once
/// at the consumer's composition root.
pub struct PerformActionOptions {
    pub pool: Pool,
    pub registry: Arc<ActionRegistry>,
    pub audit: Arc<AuditEmitter>,
    pub connection_closer: Arc<dyn ConnectionCloser>,
    pub notification_sender: Arc<dyn NotificationSender>,
    /// Server-initiated request capability. The registry-backed
    /// [`fuz_realtime::ConnectionPeer`] on the WS path;
    /// [`fuz_realtime::noop_action_peer`] (→ `NoTransport`) on HTTP — see
    /// [`ActionDispatch::perform_action_options`].
    pub peer: Arc<dyn ActionPeer>,
    /// Per-deployment limiters consulted for every spec that declares
    /// [`crate::ActionSpec::rate_limit`]. `None` on either axis skips it.
    /// Threaded from [`ActionDispatch::rate_limits`].
    pub account_rate_limiter: Option<Arc<fuz_auth::RateLimiter>>,
    pub ip_rate_limiter: Option<Arc<fuz_auth::RateLimiter>>,
}

impl std::fmt::Debug for PerformActionOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PerformActionOptions")
            .field("registry_size", &self.registry.len())
            .finish_non_exhaustive()
    }
}

impl Clone for PerformActionOptions {
    fn clone(&self) -> Self {
        Self {
            pool: self.pool.clone(),
            registry: Arc::clone(&self.registry),
            audit: Arc::clone(&self.audit),
            connection_closer: Arc::clone(&self.connection_closer),
            notification_sender: Arc::clone(&self.notification_sender),
            peer: Arc::clone(&self.peer),
            account_rate_limiter: self.account_rate_limiter.clone(),
            ip_rate_limiter: self.ip_rate_limiter.clone(),
        }
    }
}

/// Run the per-method dispatch pipeline.
///
/// See module-level docs for the enforcement order. The transport renders the
/// result to its wire shape: the success envelope, or the error envelope — at
/// the status [`fuz_http::error_code_to_http_status`] maps its code to on
/// HTTP (`fuz_http::jsonrpc_error_http_response`).
///
/// # Errors
///
/// The [`JsonrpcError`] of the first step that refused, or of the handler.
pub async fn perform_action(
    input: PerformActionInput<'_>,
    options: &PerformActionOptions,
) -> Result<ActionOutput, JsonrpcError> {
    perform_action_with(input, options, &|| {}).await
}

/// [`perform_action`] with a hook the dispatcher runs once the handler has
/// settled `Ok` (its transaction committed) and before the post-commit drain —
/// called only when that drain has effects to run, since only a drain can close
/// the caller's own connection. The WS dispatcher marks the request's
/// `fuz_realtime::ReplyOwed` there, so a handler that revokes its own
/// connection's credential still gets its response written ahead of the close.
pub(crate) async fn perform_action_with(
    input: PerformActionInput<'_>,
    options: &PerformActionOptions,
    on_settled: &(dyn Fn() + Send + Sync),
) -> Result<ActionOutput, JsonrpcError> {
    // 1. Method lookup.
    let Some(entry) = options.registry.get(input.method) else {
        return Err(method_not_found(input.method));
    };
    let spec = Arc::clone(&entry.spec);

    // 2. Pre-authorization 401 — a required-account / required-actor spec needs
    //    a resolved account.
    if let Some(error) = check_action_auth_pre_authorization(&spec.auth, input.auth.is_some()) {
        return Err(error);
    }

    // 3. Authorization phase — resolve the acting actor on a pooled client. The
    //    `acting` selector is read from the raw params (pre typed-input
    //    codegen) only when the spec declares an actor axis.
    let acting = read_acting(&spec.auth, input.params);
    let authz_client = match options.pool.get().await {
        Ok(c) => c,
        Err(e) => return Err(db_unavailable_with_source("db pool checkout failed", &e)),
    };
    let resolved = match apply_authorization_phase(
        &authz_client,
        input.auth.map(|a| &a.account),
        &spec.auth,
        acting,
    )
    .await
    {
        Ok(r) => r,
        Err(error) => return Err(error),
    };

    // 4. Post-authorization 403 — credential gate, then the token-scope gate,
    //    then the role gate over the RESOLVED actor's role_grants.
    if let Some(error) = check_action_auth_post_authorization(
        &spec.auth,
        resolved.as_context(),
        input.auth.map(ResolvedAuth::credential_type),
        input.method,
        input.auth.map(ResolvedAuth::scope),
    ) {
        return Err(error);
    }
    // Release the authz checkout before the handler opens its own tx / pool
    // client (one pool checkout for the authz phase, separate from the handler).
    drop(authz_client);

    // 5. Rate-limit gate for every spec that declares a class — consumer specs
    //    via `ActionSpec::with_rate_limit`, the auth-family specs from their
    //    `fuz_auth::AuthActionEntry` rows (`auth_adapter`). Runs after authz so
    //    the account key is the resolved credential account; fires ahead of
    //    validation so a flood of malformed input burns the budget it should,
    //    and before the handler's tx/pool checkout so a throttled call costs no
    //    DB work. The one enforcement point, as in the TS twin.
    crate::check_action_rate_limit(
        spec.rate_limit,
        input.auth.map(|a| &a.account.id),
        input.client_ip.as_deref(),
        options.account_rate_limiter.as_deref(),
        options.ip_rate_limiter.as_deref(),
    )?;

    // 6. Input validation — the params shape, the one field, and the void rule
    //    the dispatcher owns. AFTER the authority gates and the rate limit,
    //    matching the twin: a caller the credential / scope / role gates refuse
    //    must not learn the input's shape, and a throttled caller pays no
    //    validation work (see the module doc's step 6). The authorization
    //    phase's pool checkout is already spent by then, which is the trade
    //    the twin's ordering accepts.
    if let Some(error) = check_params_shape(input.params) {
        return Err(error);
    }
    if let Some(error) = check_params_proto_key(input.params) {
        return Err(error);
    }
    if let Some(error) = check_acting_selector(input.params) {
        return Err(error);
    }
    // the void rule, from the spec's declared shape rather than each void
    // handler opting in — the twin's void input refusing every shape but
    // the no-arg call
    spec.input.check(input.params)?;

    // Build the post-commit effects queue. Lives on this frame;
    // ActionContext borrows it. The dispatcher passes a `&Arc<AuditEmitter>`
    // straight from `options.audit` into `ActionContext::audit` — no
    // wrapper, since `fuz_auth::AuditEmitter` exposes both pool and
    // in-tx emits directly.
    let post_commit_effects = PostCommitEffects::new();
    let auth = resolved.as_context();

    // 7. Dispatch — transactional iff `spec.side_effects`. Drains
    //    `post_commit_effects` post-commit; clears them on rollback.
    let result = if spec.side_effects {
        dispatch_in_tx(
            &input,
            &spec,
            options,
            &post_commit_effects,
            auth,
            on_settled,
        )
        .await
    } else {
        dispatch_pooled(
            &input,
            &spec,
            options,
            &post_commit_effects,
            auth,
            on_settled,
        )
        .await
    };

    // 8. Output validation (DEV-only). No-op today — codegen lands it.
    #[cfg(debug_assertions)]
    let _ = &result;

    result
}

/// The dispatcher's params-shape check (the twin's step 5): `params` is
/// absent ([`Value::Null`], what an omitted `params` reaches here as) or an
/// object, else `invalid_params` — the twin's input schema refusing a
/// non-object, with its message and no `reason`.
///
/// The JSON-RPC envelope already holds a POST or WS request's `params` to
/// absent-or-object (`fuz_http::classify`), but `GET /rpc` reads `?params=` as
/// any JSON value. Refusing it here rather than at the GET handler keeps the
/// refusal behind the authority gates, where the twin answers it: an
/// anonymous `GET` with `?params=42` is the 401 of any anonymous call, not a
/// 400 that confirms the method takes input. Every handler past this point
/// may read `params` as an object.
fn check_params_shape(params: &Value) -> Option<JsonrpcError> {
    let kind = match params {
        Value::Null | Value::Object(_) => return None,
        Value::Bool(_) => "a boolean",
        Value::Number(_) => "a number",
        Value::String(_) => "a string",
        Value::Array(_) => "an array",
    };
    Some(fuz_http::invalid_input_params(
        &format!("params is {kind}, expected an object"),
        None,
    ))
}

/// The dispatcher's input-validation step (the twin's step 5): an own
/// `__proto__` key anywhere in `params` ([`fuz_http::json_has_own_proto_key`])
/// is `invalid_params` with `data.reason`
/// [`fuz_http::ERROR_PARAMS_PROTO_KEY`], for every spec, void ones included.
///
/// It runs after [`check_params_shape`], so a non-object `params` is that
/// check's reasonless refusal — the twin walks only object params for the same
/// answer — and ahead of the `acting` check and the void rule, as the twin
/// walks before its input schema judges either.
fn check_params_proto_key(params: &Value) -> Option<JsonrpcError> {
    fuz_http::json_has_own_proto_key(params).then(|| {
        fuz_http::invalid_input_params(
            "params hold an own `__proto__` key",
            Some(fuz_http::ERROR_PARAMS_PROTO_KEY),
        )
    })
}

/// The dispatcher's input-validation step (the twin's step 5): a *present*
/// `acting` must be a string passing [`fuz_http::is_valid_uuid`], else
/// `invalid_params`. Absent stays "omitted".
///
/// The second half of a two-step port. [`read_acting`] plays `fuz_app`'s
/// `parse_acting` — a malformed selector reads as omitted so the authorization
/// phase can still run — and this plays the typed input schema that follows
/// it, where `acting` is `ActingActor` (`Uuid.optional()`) and refuses the
/// value. Without this half an actor-axis call would fall back to the caller's
/// sole actor and **succeed** where the twin answers `-32602`.
///
/// The grammar is the `fuz_schema` `ActingActor`'s, which takes the max UUID in
/// any case; a Zod `ActingActor` input takes only the lowercase max. The
/// uppercase max never reaches this step on an actor-axis spec on either
/// spine: [`read_acting`] and `parse_acting` both read it as a selector, which
/// names no actor on the account, so step 3 refuses it first.
///
/// It runs for every spec, not only the actor-axis ones: on TS the input
/// schema judges an `acting` key whatever the spec's auth shape is, so
/// skipping account-grain specs here would ignore a value the twin rejects.
///
/// What it does **not** cover is the strict-object half: TS also refuses a
/// *well-formed* `acting` on an action whose input schema omits the field.
/// That belongs to each input struct's own `#[serde(deny_unknown_fields)]`,
/// which decides it per method — the twin's rule is the biconditional
/// "declare `acting` iff the spec carries an actor axis" — not to this gate,
/// which judges the value wherever the key is admitted.
fn check_acting_selector(params: &Value) -> Option<JsonrpcError> {
    match params.get("acting") {
        None => None,
        Some(Value::String(s)) if fuz_http::is_valid_uuid(s) => None,
        Some(_) => Some(fuz_http::invalid_input_params(
            "'acting' is not a valid uuid",
            None,
        )),
    }
}

/// Read the `acting` actor id from raw params for the authorization phase.
///
/// Consulted only when the spec declares an actor axis (`actor != None`). A
/// present-but-malformed `acting` reads as `None` (omitted), which is
/// `fuz_app`'s `parse_acting` semantics exactly: the authorization phase runs
/// on the caller's default actor so the **authority** gates can answer first,
/// and [`check_acting_selector`] refuses the value afterwards. Neither half
/// works alone.
///
/// "Malformed" is the [`fuz_http::is_valid_uuid`] grammar — the twin of the TS
/// `ActingActor` (`Uuid.optional()`), not `Uuid::parse_str`, which also admits
/// hyphenless, braced and URN spellings and any version/variant nibbles.
fn read_acting(spec: &AuthSpec, params: &Value) -> Option<Uuid> {
    if !spec.needs_actor() {
        return None;
    }
    params
        .get("acting")
        .and_then(Value::as_str)
        .filter(|s| fuz_http::is_valid_uuid(s))
        .and_then(|s| Uuid::parse_str(s).ok())
}

/// `side_effects: true` path — open tx, run handler with `&tx`, commit
/// on `Ok` then drain effects; on `Err` rollback + discard effects.
///
/// The commit is [`fuz_db::commit_checked`]: a handler that returned `Ok`
/// after swallowing a failed statement leaves the transaction aborted, where
/// a bare `COMMIT` rolls back without an error — so the action fails and its
/// effects are discarded instead of announcing rows that never committed.
async fn dispatch_in_tx<'a>(
    input: &PerformActionInput<'a>,
    spec: &Arc<crate::ActionSpec>,
    options: &PerformActionOptions,
    post_commit_effects: &PostCommitEffects,
    auth: ResolvedAuthContext<'a>,
    on_settled: &(dyn Fn() + Send + Sync),
) -> Result<ActionOutput, JsonrpcError> {
    let mut client = options
        .pool
        .get()
        .await
        .map_err(|e| db_unavailable_with_source("db pool checkout failed", &e))?;
    let tx = client
        .transaction()
        .await
        .map_err(|e| internal_error_with_source("db tx begin failed", &e))?;

    let outcome = run_handler(
        input,
        spec,
        ActionDb::Tx(&tx),
        post_commit_effects,
        &options.audit,
        &options.notification_sender,
        options.peer.as_ref(),
        auth,
    )
    .await;

    // Commit (or roll back) the handler's tx, then settle the post-commit
    // effects by outcome — a commit that fails is an `Err` like a handler's,
    // so its effects are discarded unrun (a failed commit is a rollback).
    let committed = match outcome {
        Ok(output) => match fuz_db::commit_checked(tx).await {
            Ok(()) => Ok(output),
            Err(e) => Err(commit_failure(spec.method, &e)),
        },
        Err(e) => {
            if let Err(rb) = tx.rollback().await {
                tracing::warn!(error = ?rb, method = spec.method, "db tx rollback failed");
            }
            Err(e)
        }
    };
    settle_effects(post_commit_effects, committed, on_settled).await
}

/// Map a failed [`fuz_db::commit_checked`] to the action's wire error.
///
/// Both failures answer the same opaque `internal_error` — the caller learns
/// only that the action did not commit. An aborted transaction is logged at
/// `error` with the method: the handler returned `Ok` after one of its
/// statements failed, having swallowed the error, so it is a handler bug the
/// dispatcher catches rather than an operational failure.
#[cold]
fn commit_failure(method: &str, error: &fuz_db::DbError) -> JsonrpcError {
    const DETAIL: &str = "db tx commit failed";
    match error {
        fuz_db::DbError::TransactionAborted(source) => {
            tracing::error!(
                method,
                error = ?source,
                "action handler returned Ok over an aborted transaction — it swallowed a failed \
                 statement; rolled back, post-commit effects discarded"
            );
            fuz_http::internal_error(DETAIL)
        }
        fuz_db::DbError::Postgres(source) => internal_error_with_source(DETAIL, source),
        other => internal_error_with_source(DETAIL, other),
    }
}

/// `side_effects: false` path — pooled client (no tx). Read-only
/// handlers don't open a tx; any audit emit happens against the pool
/// client directly. Post-commit drain still runs (the pool client
/// auto-commits each statement).
async fn dispatch_pooled<'a>(
    input: &PerformActionInput<'a>,
    spec: &Arc<crate::ActionSpec>,
    options: &PerformActionOptions,
    post_commit_effects: &PostCommitEffects,
    auth: ResolvedAuthContext<'a>,
    on_settled: &(dyn Fn() + Send + Sync),
) -> Result<ActionOutput, JsonrpcError> {
    let client = options
        .pool
        .get()
        .await
        .map_err(|e| db_unavailable_with_source("db pool checkout failed", &e))?;

    let outcome = run_handler(
        input,
        spec,
        ActionDb::Pool(&client),
        post_commit_effects,
        &options.audit,
        &options.notification_sender,
        options.peer.as_ref(),
        auth,
    )
    .await;

    // No commit barrier on the pooled path (each statement auto-commits), but
    // the post-commit contract still holds: settle effects by outcome so a
    // handler that queued effects then returned `Err` discards them.
    settle_effects(post_commit_effects, outcome, on_settled).await
}

/// Shared body: build the [`ActionContext`], call the handler closure.
#[allow(
    clippy::too_many_arguments,
    reason = "borrow-only context assembly — each is a distinct capability the ActionContext carries, not a bundle to group"
)]
async fn run_handler<'a>(
    input: &PerformActionInput<'a>,
    spec: &Arc<crate::ActionSpec>,
    db: ActionDb<'a>,
    post_commit_effects: &'a PostCommitEffects,
    audit: &'a Arc<AuditEmitter>,
    notification_sender: &'a Arc<dyn NotificationSender>,
    peer: &'a dyn ActionPeer,
    auth: ResolvedAuthContext<'a>,
) -> Result<ActionOutput, JsonrpcError> {
    let ctx = ActionContext {
        db,
        auth,
        credential_type: input.auth.map(ResolvedAuth::credential_type),
        session_hash: input.auth.and_then(ResolvedAuth::session_hash),
        request_id: input.request_id,
        connection_id: input.connection_id,
        client_ip: input.client_ip.clone(),
        log: input.log,
        notify: input.notify,
        signal: input.signal,
        post_commit_effects,
        audit,
        notification_sender,
        peer,
    };

    // The handler closure is `Arc::clone`-cheap; the future lives on
    // the stack of `run_handler` until awaited.
    match &spec.handler {
        ActionSpecHandler::Value(handler) => {
            let handler = Arc::clone(handler);
            handler(input.params.clone(), ctx)
                .await
                .map(ActionOutput::from)
        }
        ActionSpecHandler::Output(handler) => {
            let handler = Arc::clone(handler);
            handler(input.params.clone(), ctx).await
        }
    }
}

// -- Helpers ------------------------------------------------------------------

/// Settle the post-commit effect queue by handler outcome: drain (run) every
/// queued effect on `Ok`, discard them on `Err`.
///
/// The contract is "effects run **iff** the handler returned `Ok`" — i.e. iff
/// its transaction committed. Shared by both dispatch paths ([`dispatch_in_tx`],
/// [`dispatch_pooled`]) so the drain-vs-discard decision lives in one place.
/// The TS twin pins the same contract via `dispatch_with_post_commit_rollback`
/// in `http/pending_effects.ts`.
async fn settle_effects(
    post_commit_effects: &PostCommitEffects,
    outcome: Result<ActionOutput, JsonrpcError>,
    on_settled: &(dyn Fn() + Send + Sync),
) -> Result<ActionOutput, JsonrpcError> {
    match outcome {
        Ok(output) => {
            if !post_commit_effects.is_empty() {
                on_settled();
            }
            // Listeners + WS broadcasts + audit fan-out; concurrent via
            // `futures::future::join_all`, on a spawned task so a caller
            // dropped mid-drain (client disconnect) can't cancel them.
            post_commit_effects.drain_all().await;
            Ok(output)
        }
        Err(e) => {
            post_commit_effects.clear();
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{check_acting_selector, check_params_proto_key, check_params_shape, read_acting};
    use fuz_auth::{AuthSpec, CredentialGate};
    use serde_json::{Value, json};
    use uuid::Uuid;

    /// A `gen_random_uuid()`-shaped v4 — the all-ones id every hand-written
    /// fixture reaches for is itself refused by the `z.uuid()` grammar
    /// (variant nibble `1`), so it can't stand in for a well-formed one.
    const UUID: &str = "3f8a1c2e-1234-4abc-9def-0123456789ab";

    /// Absent (`null`) and object params pass; every other JSON type is the
    /// twin's schema refusal — `invalid_params`, its message, no reason.
    #[test]
    fn check_params_shape_admits_only_absent_or_object() {
        assert!(check_params_shape(&Value::Null).is_none());
        assert!(check_params_shape(&json!({})).is_none());
        assert!(check_params_shape(&json!({"acting": UUID})).is_none());
        for params in [
            json!(42),
            json!([1]),
            json!("x"),
            json!(true),
            json!(false),
            json!([]),
        ] {
            let error = check_params_shape(&params).expect("non-object refused");
            assert_eq!(
                error.code,
                fuz_http::JsonrpcErrorCode::InvalidParams,
                "{params}"
            );
            assert_eq!(error.message, fuz_http::INVALID_PARAMS_MESSAGE, "{params}");
            assert!(error.data.is_none(), "{params}");
        }
    }

    #[test]
    fn check_params_proto_key_refuses_with_its_reason() {
        for params in [
            json!({"__proto__": {"x": 1}}),
            json!({"acting": UUID, "data": {"a": [{"__proto__": null}]}}),
        ] {
            let error = check_params_proto_key(&params).expect("proto key refused");
            assert_eq!(
                error.code,
                fuz_http::JsonrpcErrorCode::InvalidParams,
                "{params}"
            );
            assert_eq!(error.message, fuz_http::INVALID_PARAMS_MESSAGE, "{params}");
            assert_eq!(
                error.data,
                Some(json!({"reason": fuz_http::ERROR_PARAMS_PROTO_KEY})),
                "{params}"
            );
        }
        for params in [
            Value::Null,
            json!({}),
            json!({"constructor": {"prototype": {}}, "a": "__proto__"}),
        ] {
            assert!(check_params_proto_key(&params).is_none(), "{params}");
        }
    }

    #[test]
    fn read_acting_skips_when_spec_has_no_actor_axis() {
        // A public spec never resolves an actor, so `acting` is ignored even
        // when present (no actor axis ⇒ no read).
        let params = json!({"acting": UUID});
        assert_eq!(read_acting(&AuthSpec::public(), &params), None);
    }

    /// `read_acting` runs *first* — it is step 3's input, and
    /// `check_acting_selector` only judges the value at step 6 — so its own
    /// grammar filter is what decides between a resolved actor and `None`.
    #[test]
    fn read_acting_parses_a_valid_uuid_when_actor_axis_present() {
        let params = json!({"acting": UUID});
        assert_eq!(
            read_acting(&AuthSpec::authenticated(CredentialGate::Any), &params),
            Some(UUID.parse::<Uuid>().unwrap())
        );
    }

    /// Either case is a selector, the max UUID too, and resolves the id its
    /// lowercase spelling names — what TS `parse_acting` returns.
    #[test]
    fn read_acting_reads_either_case() {
        for (raw, canonical) in [
            (UUID.to_uppercase(), UUID.to_owned()),
            (
                "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF".to_owned(),
                "ffffffff-ffff-ffff-ffff-ffffffffffff".to_owned(),
            ),
        ] {
            let params = json!({ "acting": raw });
            assert_eq!(
                read_acting(&AuthSpec::authenticated(CredentialGate::Any), &params)
                    .map(|id| id.to_string()),
                Some(canonical),
                "{raw}"
            );
        }
    }

    #[test]
    fn read_acting_absent_is_none() {
        assert_eq!(
            read_acting(&AuthSpec::authenticated(CredentialGate::Any), &json!({})),
            None
        );
    }

    /// The grammar filter here is load-bearing for **ordering**, not for the
    /// refusal — [`check_acting_selector`] owns that, three steps later.
    ///
    /// These are `parse_acting` semantics: a malformed selector reads as
    /// omitted so the authorization phase resolves the caller's default actor
    /// and the authority gates get to answer first. Drop the filter and a
    /// malformed spelling parses into a `Uuid` that names no actor on the
    /// account, so step 3 answers `actor_not_on_account` (`-32602`) to a
    /// roleless caller the twin refuses with a 403 — the whole point of
    /// validating the value after the gates.
    #[test]
    fn read_acting_reads_a_malformed_selector_as_omitted() {
        for params in [
            // Parses fine via `Uuid::parse_str`, fails the wire grammar.
            json!({"acting": "3f8a1c2e12344abc9def0123456789ab"}),
            json!({"acting": "{3f8a1c2e-1234-4abc-9def-0123456789ab}"}),
            json!({"acting": "urn:uuid:3f8a1c2e-1234-4abc-9def-0123456789ab"}),
            // Variant nibble out of range.
            json!({"acting": "11111111-1111-1111-1111-111111111111"}),
            json!({"acting": "not-a-uuid"}),
            // Non-string and null read as omitted too.
            json!({"acting": 42}),
            json!({"acting": null}),
        ] {
            assert_eq!(
                read_acting(&AuthSpec::authenticated(CredentialGate::Any), &params),
                None,
                "params: {params}"
            );
        }
    }

    /// The dispatcher gate, which runs for every spec **after** the authority
    /// gates (credential / scope / roles) and the rate limit — the twin's
    /// step 5. Each row is a spelling `Uuid::parse_str` or a permissive
    /// read would let through where the TS input schema answers `-32602`;
    /// letting any of them reach the handler would run the request on the
    /// caller's sole actor.
    #[test]
    fn check_acting_selector_refuses_everything_but_a_wire_uuid() {
        for params in [
            json!({"acting": "3f8a1c2e12344abc9def0123456789ab"}),
            json!({"acting": "{3f8a1c2e-1234-4abc-9def-0123456789ab}"}),
            json!({"acting": "urn:uuid:3f8a1c2e-1234-4abc-9def-0123456789ab"}),
            json!({"acting": "11111111-1111-1111-1111-111111111111"}),
            json!({"acting": "not-a-uuid"}),
            json!({"acting": null}),
            json!({"acting": 42}),
            json!({"acting": []}),
        ] {
            let error =
                check_acting_selector(&params).unwrap_or_else(|| panic!("must refuse {params}"));
            assert_eq!(
                error.code,
                fuz_http::JsonrpcErrorCode::InvalidParams,
                "params: {params}"
            );
        }
    }

    #[test]
    fn check_acting_selector_admits_absent_and_wire_uuids() {
        assert!(check_acting_selector(&json!({})).is_none());
        assert!(check_acting_selector(&json!({"other": 1})).is_none());
        assert!(check_acting_selector(&json!({"acting": UUID})).is_none());
        // The nil and max specials, the max in any case (RFC 9562 §4, as the
        // fuz_schema `ActingActor`; the Zod one takes only the lowercase max).
        for special in [
            "00000000-0000-0000-0000-000000000000",
            "ffffffff-ffff-ffff-ffff-ffffffffffff",
            "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF",
            "ffffffff-FFFF-ffff-FFFF-ffffffffffff",
        ] {
            assert!(
                check_acting_selector(&json!({ "acting": special })).is_none(),
                "{special}"
            );
        }
        // A non-object `params` carries no `acting` to judge.
        assert!(check_acting_selector(&Value::Null).is_none());
    }
}
