//! `fuz_actions` — action dispatch framework for the fuz spine.
//!
//! The framework that ties [`fuz_auth`] + [`fuz_db`] +
//! [`fuz_http`] + [`fuz_realtime`] into per-method dispatch over both
//! HTTP RPC and WebSocket transports.
//!
//! ## Wire contract: enforcement order
//!
//! Every transport (HTTP + WS) enforces the same order so consumers can rely
//! on identical responses regardless of how the request arrived:
//! `method_not_found` → 401 → authorization phase → 403 → 429 → 400 → handler
//! → post-commit drain. The 400 (the dispatcher's own `acting` grammar; the
//! handlers validate the rest) sits *after* the authority gates and the rate
//! limit on purpose — coarse authority facts before fine input ones, so a
//! refused caller learns nothing about the method's shape, and a malformed
//! flood burns the budget it should. The full step list and each ordering's
//! rationale live on [`mod@perform_action`]; the order mirrors `fuz_app`'s
//! `perform_action.ts`.
//!
//! ## No trait abstraction
//!
//! This crate ships **concrete types** ([`ActionRegistry`],
//! [`ActionContext`], [`fn@perform_action`]) without `trait ActionStore` /
//! `trait Dispatcher` indirection.
//!
//! ## Transactional audit boundary
//!
//! The audit log is the forensic source of truth, so
//! [`fn@perform_action`] opens a transaction iff [`ActionSpec::side_effects`]
//! is `true`, plumbs the in-tx client into `ActionContext.db`, and
//! drains the post-commit effects queue ([`PostCommitEffects`]) only after
//! the tx commits. A handler emitting an audit row gets a synchronous
//! in-transaction INSERT that commits-or-rolls-back with the auth/business
//! state. Effects that fire outside the DB (WS broadcasts, audit listener
//! fan-out, log lines) live on the queue and run post-commit.
//!
//! ## Notify shape (borrowed)
//!
//! [`ActionContext::notify`] is
//! `&dyn Fn(&str, &Value)` — borrowed reference, no `Arc`, no per-request
//! allocation on HTTP. The WS dispatcher builds the per-socket closure
//! once via [`fuz_realtime::ws_notify_for_connection`] and passes a
//! borrow into every dispatch frame.
//!
//! ## Pending effects: post-commit drain
//!
//! Handlers queue side-channel effects (audit listener fan-out, WS
//! broadcasts, log lines) onto `ActionContext.post_commit_effects`.
//! [`fn@perform_action`] drains the queue **after** the tx commits — if
//! the tx rolls back, effects don't fire. That includes the rollback a bare
//! `COMMIT` hides when a handler swallowed a failed statement: the commit is
//! [`fuz_db::commit_checked`], which fails the action instead. Audit listener
//! fan-out runs concurrently via [`futures::future::join_all`].
//!
//! ## Handler output
//!
//! A handler returns a `serde_json::Value` ([`ActionHandler`]), or — when its
//! output is large — an [`ActionOutput`] ([`ActionOutputHandler`], registered
//! via [`ActionSpec::new_output`]) wrapping its typed output, which the
//! transport serializes once, straight into the response, with no
//! intermediate `Value` tree. Both render through [`write_success_response`].
//!
//! ## Protocol actions
//!
//! [`heartbeat`] and [`peer_ping`] are the protocol specs every consumer
//! registers, by merging [`PROTOCOL_ACTION_SPECS`] alongside its own specs;
//! nothing registers them automatically. `cancel` has
//! no spec — it is a notification the WS read loop owns
//! ([`fuz_realtime::CANCEL_METHOD`]), never a dispatched method.
//!
//! The two registered ones differ by transport, matching the TS twin's mount
//! shape: [`heartbeat`] is [`ActionSpec::ws_only`] (an HTTP call answers
//! `method_not_found`), while [`peer_ping`] is reachable over HTTP so the
//! call reaches the handler and refuses with `peer_no_transport`.

// === core spec types ===
pub mod action_context;
pub mod action_output;
pub mod action_registry;
pub mod action_spec;
pub mod consumer_lifecycle;
pub mod post_commit_effects;

// === dispatcher gates + the fuz_auth action-entry adapter ===
pub mod action_rate_limit;
pub mod auth_adapter;

// === dispatch core ===
pub mod perform_action;

// === HTTP RPC binding ===
pub mod rpc_dispatch;
pub mod rpc_router;

// === WS binding ===
pub mod register_action_ws;
pub mod ws_dispatch;

// === spine-consumer server toolkit ===
pub mod server;

// === protocol actions ===
pub mod heartbeat;
pub mod peer_ping;
pub mod protocol;

// -- Public API re-exports ---------------------------------------------------

pub use action_context::ActionContext;
pub use action_output::{ActionOutput, write_success_response};
pub use action_rate_limit::{ActionRateLimits, check_action_rate_limit};
pub use action_registry::{
    ActionEntry, ActionHandler, ActionOutputHandler, ActionRegistry, RegistryBuildError,
};
pub use action_spec::{ActionSpec, ActionSpecHandler, public_readonly_spec};
pub use consumer_lifecycle::{ExtraActionSpecsFactory, ExtraActionSpecsRuntime, PreMigrationHook};
pub use heartbeat::{HEARTBEAT_METHOD, heartbeat_action_spec};
pub use peer_ping::{
    PEER_CONNECTION_GONE_MESSAGE, PEER_NO_TRANSPORT_MESSAGE, PEER_PING_INVALID_REPLY_MESSAGE,
    PEER_PING_METHOD, PEER_PING_NONCE_MISMATCH_MESSAGE, PEER_TIMEOUT_MESSAGE,
    PEER_TOO_MANY_IN_FLIGHT_MESSAGE, PingRequest, PingResponse, REASON_PEER_CONNECTION_GONE,
    REASON_PEER_NO_TRANSPORT, REASON_PEER_PING_INVALID_REPLY, REASON_PEER_PING_NONCE_MISMATCH,
    REASON_PEER_TIMEOUT, REASON_PEER_TOO_MANY_IN_FLIGHT, peer_ping_action_spec,
};
pub use perform_action::{ActionDispatch, PerformActionInput, perform_action};
pub use post_commit_effects::{PostCommitEffect, PostCommitEffects};
pub use protocol::PROTOCOL_ACTION_SPECS;
pub use register_action_ws::{
    ActionWsOptions, DEFAULT_WS_MAX_MESSAGE_BYTES, DEFAULT_WS_OUTBOUND_QUEUE_BYTES,
    DEFAULT_WS_RECEIVE_TIMEOUT, WsRouteState, admit_upgrade, register_action_ws,
    register_action_ws_with_options,
};
pub use rpc_dispatch::RPC_GET_CACHE_CONTROL;
pub use rpc_router::create_rpc_router;
