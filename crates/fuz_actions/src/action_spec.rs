//! [`ActionSpec`] — canonical per-action metadata.
//!
//! Composes [`fuz_auth::AuthSpec`] (auth + credential + role gates) with
//! the declared [`InputShape`], the dispatcher-side `side_effects` flag, and
//! an erased handler closure.
//! Mirrors `fuz_app`'s `ActionSpec` shape post-dispatcher unification
//! (v0.56+).
//!
//! ## Why a single struct, not three trait-objects per kind
//!
//! `fuz_app` TS distinguishes `request_response`, `remote_notification`,
//! and `local_call` kinds. Rust backend is one side of the wire — only
//! `request_response` and `remote_notification` (backend-initiated)
//! matter here. `local_call` is frontend-only.
//!
//! Registered specs are all the request/response shape: the
//! handler returns a `Value` (the JSON-RPC `result` field) or a typed
//! error. `remote_notification` actions don't enter the registry — they
//! are emitted from handlers via [`super::ActionContext::notify`] or
//! via consumer-side broadcast helpers, never dispatched into.
//!
//! ## Why no `Input` / `Output` generics on the spec itself
//!
//! The registry is generic over handler type at registry-build time,
//! **not** an erased `Box<dyn AsyncFn>` per call. We achieve that by
//! keeping the handler closure as the only thing the registry stores
//! — the closure
//! itself is monomorphized at registration. Per-spec Input/Output
//! validation (Zod equivalent) happens inside the closure where the
//! types are known; the spec carries just auth + the coarse [`InputShape`]
//! (void or object, which the dispatcher enforces) + `side_effects` + handler.
//!
//! ## Postcard caveat
//!
//! Action specs themselves are static-data routing entries (not wire
//! payloads), so they're postcard-irrelevant. Handler input/output
//! types DO flow over wire. Because of the postcard +
//! `skip_serializing_if` constraint: **do NOT add `#[serde(skip_serializing_if)]`
//! to action input/output types** — JSON null round-trips fine; postcard
//! can't reconstruct an omitted discriminant.

use std::sync::Arc;

use futures::future::BoxFuture;
use fuz_auth::{AuthSpec, RateLimitClass};
use fuz_http::{InputShape, JsonrpcError};
use serde_json::Value;

use crate::action_context::ActionContext;
use crate::action_registry::{ActionHandler, ActionOutputHandler};

/// One registered action: auth axes + input shape + side-effects flag + handler.
///
/// Constructed via [`ActionSpec::new`] or one of the builder methods.
/// Consumers usually register specs via a slice handed to
/// [`crate::ActionRegistry::compile`].
pub struct ActionSpec {
    /// Method name as it appears on the wire (e.g. `"account_login"`).
    pub method: &'static str,
    /// Auth + credential + role gates. Checked before the handler runs.
    pub auth: AuthSpec,
    /// Whether the method takes params — the twin of whether `fuz_app`'s
    /// `ActionSpec.input` is `z.void()`. [`fn@crate::perform_action`] holds an
    /// [`InputShape::Void`] method to the no-arg call before the handler runs;
    /// `_testing_action_manifest` reports it as the method's `input`.
    ///
    /// Required at construction, with no default: a parameterless handler
    /// that never reads `params` would otherwise answer any params at all.
    pub input: InputShape,
    /// `true` ⇒ [`fn@crate::perform_action`] opens a DB transaction,
    /// passes `&tx` to the handler via [`crate::ActionContext::db`],
    /// commits on `Ok`, rolls back on `Err`. `false` ⇒ handler gets a
    /// pooled client (acquired lazily) and any DB writes commit as
    /// they go.
    ///
    /// Mirrors `fuz_app`'s `ActionSpec.side_effects`.
    pub side_effects: bool,
    /// Optional per-method rate-limit class consulted by
    /// [`fn@crate::perform_action`] after authorization and ahead of params
    /// validation and the handler. `None` (the default) skips the gate.
    ///
    /// Consumer-owned specs opt in via [`ActionSpec::with_rate_limit`]; the
    /// built-in auth-family specs (`account_*` / `admin_*` / `actor_*` /
    /// `self_service_role_set`) carry their `fuz_auth::AuthActionEntry`'s
    /// class here, set by the `auth_adapter` builders. Read too by
    /// `_testing_action_manifest`, which reports it as the method's class.
    pub rate_limit: Option<RateLimitClass>,
    /// `true` ⇒ the method is served over WebSocket only; the HTTP RPC
    /// transport ([`crate::create_rpc_router`]) refuses it with
    /// `method_not_found`, emitting the wire answer an unregistered method
    /// would.
    ///
    /// The equivalence is on the wire, not in every channel: the refusal runs
    /// ahead of auth and so skips the credential lookup, which a timing
    /// measurement can see. Harmless — which methods are WS-only is a
    /// published protocol constant, not a secret.
    ///
    /// The Rust spine compiles **one** registry serving both transports, so a
    /// transport restriction has to live on the spec. `fuz_app` reaches the
    /// same contract by mounting per transport — its `heartbeat` is spread
    /// into a consumer's WS endpoint via `protocol_actions` and never appears
    /// in an HTTP-RPC mount — with `is_protocol_action_method` /
    /// `PROTOCOL_ACTION_METHODS` (`actions/action_codegen.ts`) naming the set.
    /// The marker is narrower than "protocol action": `peer/ping` is a
    /// protocol action that `fuz_app` deliberately *does* mount over HTTP, so
    /// an HTTP call reaches the handler and refuses with `peer_no_transport`
    /// rather than `method_not_found`.
    pub ws_only: bool,
    /// The dispatch closure. Receives owned params + context, returns the
    /// JSON-RPC `result` (a `Value`, or an [`crate::ActionOutput`]) or
    /// `error`.
    pub handler: ActionSpecHandler,
}

/// An [`ActionSpec`]'s dispatch closure, by what it returns.
#[derive(Clone)]
pub enum ActionSpecHandler {
    /// Returns a `Value` — the common form ([`ActionSpec::new`] and friends).
    Value(ActionHandler),
    /// Returns an [`crate::ActionOutput`], rendered once into the response
    /// ([`ActionSpec::new_output`]).
    Output(ActionOutputHandler),
}

impl std::fmt::Debug for ActionSpecHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Value(_) => "<value handler>",
            Self::Output(_) => "<output handler>",
        })
    }
}

impl std::fmt::Debug for ActionSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ActionSpec")
            .field("method", &self.method)
            .field("auth", &self.auth)
            .field("input", &self.input)
            .field("side_effects", &self.side_effects)
            .field("rate_limit", &self.rate_limit)
            .field("ws_only", &self.ws_only)
            .field("handler", &self.handler)
            .finish()
    }
}

impl ActionSpec {
    /// Construct a spec from its four fields plus the handler closure.
    #[must_use]
    pub fn new(
        method: &'static str,
        auth: AuthSpec,
        input: InputShape,
        side_effects: bool,
        handler: ActionHandler,
    ) -> Self {
        Self::with_handler(
            method,
            auth,
            input,
            side_effects,
            ActionSpecHandler::Value(handler),
        )
    }

    /// Construct a spec whose handler returns an [`crate::ActionOutput`] —
    /// for a large output the transport should render once, without an
    /// intermediate `Value` (see [`crate::ActionOutput::serialize`]).
    #[must_use]
    pub fn new_output(
        method: &'static str,
        auth: AuthSpec,
        input: InputShape,
        side_effects: bool,
        handler: ActionOutputHandler,
    ) -> Self {
        Self::with_handler(
            method,
            auth,
            input,
            side_effects,
            ActionSpecHandler::Output(handler),
        )
    }

    const fn with_handler(
        method: &'static str,
        auth: AuthSpec,
        input: InputShape,
        side_effects: bool,
        handler: ActionSpecHandler,
    ) -> Self {
        Self {
            method,
            auth,
            input,
            side_effects,
            rate_limit: None,
            ws_only: false,
            handler,
        }
    }

    /// Build a `side_effects: false` (read-only) spec.
    #[must_use]
    pub fn read_only(
        method: &'static str,
        auth: AuthSpec,
        input: InputShape,
        handler: ActionHandler,
    ) -> Self {
        Self::new(method, auth, input, false, handler)
    }

    /// Build a `side_effects: true` (transactional) spec.
    #[must_use]
    pub fn with_side_effects(
        method: &'static str,
        auth: AuthSpec,
        input: InputShape,
        handler: ActionHandler,
    ) -> Self {
        Self::new(method, auth, input, true, handler)
    }

    /// Set the per-method rate-limit class (builder form).
    ///
    /// For consumer-owned specs that want IP / account rate limiting through
    /// the dispatcher. The consumer must also wire the matching limiters into
    /// [`crate::ActionDispatch`] both transports run through; an unset limiter on
    /// the relevant axis skips it. An account-keyed class
    /// ([`RateLimitClass::Account`] / [`RateLimitClass::Both`]) needs
    /// `auth.account` = `Required`; [`crate::ActionRegistry::compile`] refuses
    /// it on any other account axis.
    #[must_use]
    pub const fn with_rate_limit(mut self, class: RateLimitClass) -> Self {
        self.rate_limit = Some(class);
        self
    }

    /// Mark the spec WebSocket-only (builder form).
    ///
    /// See [`ActionSpec::ws_only`]. `heartbeat` is the only spec that carries
    /// it today; a consumer whose method is meaningless without a socket may
    /// opt in the same way.
    #[must_use]
    pub const fn with_ws_only(mut self) -> Self {
        self.ws_only = true;
        self
    }
}

/// Build a public (no-auth), read-only [`ActionSpec`] from a bare handler
/// closure, folding the [`AuthSpec::public`] gate and the [`Arc`] wrapping of
/// the handler.
///
/// The shape of `peer/ping` — a liveness echo carries nothing sensitive, so
/// it gates nothing. Pass the closure directly — no `Arc::new`:
///
/// ```ignore
/// public_readonly_spec(PEER_PING_METHOD, InputShape::Object, |params, ctx| {
///     Box::pin(async move { handle(params, ctx).await })
/// })
/// ```
#[must_use]
pub fn public_readonly_spec<F>(method: &'static str, input: InputShape, handler: F) -> ActionSpec
where
    F: for<'a> Fn(Value, ActionContext<'a>) -> BoxFuture<'a, Result<Value, JsonrpcError>>
        + Send
        + Sync
        + 'static,
{
    ActionSpec::read_only(method, AuthSpec::public(), input, Arc::new(handler))
}

#[cfg(test)]
mod tests {
    use super::{ActionSpec, InputShape, RateLimitClass, public_readonly_spec};
    use serde_json::{Map, Value};

    fn noop_spec() -> ActionSpec {
        public_readonly_spec("test_method", InputShape::Object, |_params, _ctx| {
            Box::pin(async move { Ok(Value::Object(Map::new())) })
        })
    }

    #[test]
    fn rate_limit_defaults_to_none() {
        assert_eq!(noop_spec().rate_limit, None);
    }

    #[test]
    fn with_rate_limit_sets_the_class() {
        let spec = noop_spec().with_rate_limit(RateLimitClass::Account);
        assert_eq!(spec.rate_limit, Some(RateLimitClass::Account));
    }

    #[test]
    fn ws_only_defaults_to_false() {
        assert!(!noop_spec().ws_only);
    }

    #[test]
    fn with_ws_only_sets_the_marker() {
        assert!(noop_spec().with_ws_only().ws_only);
    }
}
