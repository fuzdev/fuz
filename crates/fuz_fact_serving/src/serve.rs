//! Content-addressed fact serving — cell-scoped per-reference reads + an
//! admin-only bare-hash read. The axum twin of `fuz_app`'s `serve_fact_route.ts`.
//!
//! Two routes serve fact bytes from `fuz_fact`'s store:
//!
//! - `GET /api/cells/{cell_id}/facts/{hash}` — the **per-reference read**. The
//!   request names the referencing cell; authz is scoped to that one edge:
//!   `(can_view_cell(caller, cell) OR the steward arm) AND cell.refs includes
//!   hash` — the steward arm being the governing root's manager reading a
//!   pending or rejected contribution (`fuz_cell::cell_steward`). This is the
//!   path non-admin callers use, and the only path for confidential content.
//! - `GET /api/facts/{hash}` — the **bare-hash read**, admin-only.
//!
//! Embedded facts stream from the `fact.bytes` column; external facts
//! (`file:<shard>/<rest>` URLs) either emit an `X-Accel-Redirect` into nginx's
//! internal facts location (production — set `x_accel` to a validated
//! [`XAccelConfig`](crate::nginx::XAccelConfig)) or stream from disk under
//! `facts_dir` (dev / tests).
//!
//! ## Authorization — authz lives on the cell→fact edge, not the hash
//!
//! Facts are global, content-addressed, owner-less bytes: identical bytes from
//! different owners dedup to **one** `fact` row. Keying access control on the
//! bare hash would union visibility across every owner that references it —
//! A's private bytes would leak the instant B referenced identical bytes from a
//! public cell. So authz is scoped to the `(cell, hash)` edge: a caller reads a
//! fact *through a specific cell it can view that references the hash*.
//!
//! The edge is only as safe as what may create it. A cell's `refs` derive from
//! its `data`, and any account that can write a cell writes its `data` — so
//! this route alone would make a known hash a read capability: name it in a
//! cell you own, flip the cell public, and the bytes serve to the world, while
//! a 200 against a 404 says whether the fact exists. What closes that is
//! **possession-gated ref admission** on the cell verbs (`fuz_cell_actions`): a
//! non-admin `cell_create` / `cell_update` / `cell_clone` may introduce a ref
//! only to a fact its acting actor holds — one it put the bytes of, recorded
//! in `fact_holder` on every put, a deduplicated put included — and is refused
//! `403 cell_ref_not_held` otherwise, the same answer whether or not a fact is
//! stored. Refs a cell already carries stay admitted through updates and
//! clones, so a viewer who clones a cell carries its refs: what a viewer can
//! read through a cell, it can republish — no more than downloading the bytes
//! and uploading them again. A serve is a snapshot of the edge at read time;
//! revoking someone's access to a cell does not withdraw refs they already
//! wrote elsewhere. Writers that bypass the verbs (seeds, raw inserts) are
//! trusted and not admitted.
//!
//! The bare-hash route is **admin-only**: an admin's reach already spans every
//! cell, so serving by bare hash grants no escalation.
//!
//! ## The public-route auth model (the subtle part)
//!
//! The cell-scoped route is a **pure-public** route — it does not reject
//! unauthenticated callers (a public cell's facts are world-readable). It
//! resolves the caller's [`fuz_auth::RequestActorContext`] via
//! [`fuz_auth::AuthGate::public_request_context`], which walks the same
//! daemon-token → cookie → bearer credential pipeline every other spine
//! surface walks and then applies the public-route disambiguation that mirrors
//! the TS `build_public_request_context`:
//!
//! - **unauthenticated** → `None` (anonymous): admitted only by a
//!   `visibility = 'public'` cell whose `moderation` admits an audience
//!   (unmoderated or `approved`).
//! - **single-actor account** → resolve that actor + its `role_grants`.
//! - **multi-actor account** → `None` (anonymous): a public route has no
//!   `acting` slot to disambiguate, so a multi-actor caller is treated as
//!   anonymous.
//! - **scope-narrowed API token** → `None` (anonymous), *not* a refusal: rule
//!   3 says a narrowed token reaches no non-RPC surface, but on a route that
//!   admits anonymous callers a `403` would enforce nothing — the holder drops
//!   the `Authorization` header and re-reads every public cell anyway. The
//!   downgrade hands the credential exactly the reach it could obtain
//!   regardless. Sessions and daemon tokens are `TokenScope::Full` by
//!   construction and keep their full visibility.
//!
//! The bare-hash route, being authed-admin, resolves the account-grain
//! [`fuz_auth::AuthGate::resolve_credential`] directly, adds the `?acting=`
//! selector for multi-actor admins, and — reading no anonymous surface —
//! *refuses* a narrowed token (403) rather than downgrading it.
//!
//! ## The origin check
//!
//! Both routes open with the gate's origin check
//! ([`fuz_auth::AuthGate::check_origin`]), ahead of the params: a page from a
//! foreign origin is refused `403` before anything is read, as the TS twin's
//! origin middleware refuses it ahead of the route. A request with no `Origin`
//! — an `<img>` load, a CLI fetch — is unaffected.
//!
//! ## 404-mask
//!
//! On the cell-scoped route, `404` is the universal "not viewable" response:
//! missing fact, missing / unviewable cell, or a cell that doesn't reference
//! the hash. We never distinguish `403` from `404` there — neither a fact's
//! existence nor a cell→fact edge should leak. The view check runs before the
//! edge check, so an unviewable cell does the same work whether or not it
//! references the hash — its refs don't leak through response timing either.
//!
//! ## Internal failures
//!
//! Past caller resolution, a failure of the handler's own — the cell, grant,
//! or fact read; the bare route's actor and role reads; opening an external
//! fact's file for a reason other than its absence — answers the spine's flat
//! 500 `{"error": "internal_error"}` ([`fuz_http::internal_error_response`])
//! on both routes, the detail logged and not sent; its own failed pool
//! checkout answers the flat 503 `{"error": "service_unavailable"}`
//! ([`fuz_http::db_unavailable_response`]). Neither is folded into the `404`
//! mask: each reports a server fault and names no fact or edge. Each of these
//! is decided before the response starts; a disk read that fails once the
//! bytes are streaming has no status left to change.
//!
//! A failed credential read answers [`fuz_auth::CredentialReadFault`]'s
//! response on both routes — 503 for a failed checkout, the plain-text 500
//! for a failed query — the TS twin's answer when a read throws out of its
//! auth middleware: the request goes on neither as anonymous nor as a
//! lower-priority credential. Past the credential read, a failure of
//! [`fuz_auth::AuthGate::public_request_context`]'s own pool checkout answers
//! the flat 503 ([`fuz_auth::PublicContextFault::CallerUnavailable`]) and of
//! its actor or role-grant read the flat 500
//! ([`fuz_auth::PublicContextFault::CallerRead`]) on the cell-scoped route,
//! never an anonymous caller.
//!
//! For the cell, grant, and fact reads, and the cell-scoped route's actor and
//! role-grant reads, the flat bodies are the ones `fuz_app`'s route pipeline
//! answers when the twin's handler throws.
//!
//! ## Params refusal
//!
//! Both path params are validated before anything else, under the grammars
//! the TS twin declares in `spec.params` (`cell_id: Uuid`, `hash:
//! FactHashSchema`): `cell_id` takes the wire UUID grammar
//! ([`fuz_http::is_valid_uuid`]) rather than `Uuid::parse_str`'s wider one,
//! which would normalize an off-grammar id onto a stored row, and `hash` is
//! read by [`ContentHash::parse_fact_hash`] — `blake3:` and 64 lowercase hex,
//! nothing else. A refusal is the spine's flat
//! 400 `{"error": "invalid_route_params"}`, the body `fuz_app`'s params
//! middleware emits, which is what lets a consumer put these routes on its
//! round-trip-validated surface.
//!
//! The twin declares that 400 with `error` and an optional `issues`
//! array of wire issues — `issues` is a development-only
//! diagnostic its own production build omits — so the flat body the spine
//! returns, carrying no `issues` like every other flat-REST refusal here,
//! satisfies the round-trip surface a consumer mounts both twins on.
//!
//! ## Untrusted-content hardening
//!
//! Fact bytes are served with a producer-supplied `content_type` emitted
//! verbatim, inline. To stop a fact stored as (or sniffable to) `text/html`
//! from executing as stored XSS for any reader of a referencing cell, **every**
//! served-fact response carries `X-Content-Type-Options: nosniff` +
//! `Content-Security-Policy: default-src 'none'; sandbox` (the
//! [`FACT_SECURITY_HEADERS`](crate::fact_security_headers::FACT_SECURITY_HEADERS)
//! set, byte-identical with the TS twin `serve_fact_route.ts`). The embedded
//! and disk-stream branches set them in `body_response`. On the
//! `X-Accel-Redirect` branch nginx serves the bytes, and the headers the client
//! sees come from the internal facts location, not this response — that
//! location must carry the lines
//! [`fact_security_header_directives`](crate::fact_security_headers::fact_security_header_directives)
//! renders, which [`XAccelConfig`](crate::nginx::XAccelConfig) enforces.
//! `Content-Disposition: attachment` is deliberately **not** added — it would
//! force-download and break legitimate inline image rendering.
//!
//! ## Defense-in-depth
//!
//! The `external_url` is re-validated before issuing `X-Accel-Redirect` or a
//! disk read, even though `fuz_fact` only ever writes the right one: it must be
//! the strict `file:<shard>/<rest>` shape, or a row-injection bug upstream
//! would hand nginx / the filesystem an attacker-controlled path, and it must
//! be the address of the requested hash
//! ([`fuz_fact::ParsedFactUrl::addresses`]), or a row whose URL names another
//! fact's file would serve those bytes under this hash — past this hash's
//! admission, and with no re-hash on this path to catch it. Either failure is
//! logged and answered as the masked `404`.

#![expect(
    clippy::result_large_err,
    reason = "the REST helpers return Result<_, Response>; the Err *is* the ready-to-return axum response — the spine's handler idiom"
)]

use std::path::PathBuf;

use axum::Router;
use axum::body::Body;
use axum::extract::{Extension, Path as AxumPath, Query, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use deadpool_postgres::GenericClient;
use fuz_auth::route_helpers::require_acting_actor;
use fuz_auth::{AuthGate, ROLE_ADMIN, parse_acting_query};
use fuz_cell::cell_grant_queries::query_cell_grant_list_for_cell;
use fuz_cell::cell_queries::query_cell_get;
use fuz_cell::{can_view_cell, cell_steward_admits};
use fuz_crypto::ContentHash;
use fuz_fact::{parse_fact_file_url, query_get_fact, query_get_fact_meta};
use fuz_http::{
    ClientIp, assert_known_query_keys, invalid_route_params_response, is_valid_uuid, query_first,
};
use uuid::Uuid;

use crate::fact_security_headers::{FACT_CONTENT_SECURITY_POLICY, FACT_X_CONTENT_TYPE_OPTIONS};

/// `Cache-Control` for fact responses — 5 min revocation window.
const CACHE_CONTROL: &str = "private, max-age=300";

/// State for the fact-serving routers.
#[derive(Clone)]
pub struct FactServingRouteState {
    /// The front door both routes check a request at — the origin check, then
    /// the credential walk under the consumer's session cookie name, its
    /// daemon-token state honored on both — and the pool for the `fact` /
    /// `cell` reads.
    pub gate: AuthGate,
    /// Absolute path of the facts directory (the dev/test disk-stream root).
    pub facts_dir: PathBuf,
    /// When set, external facts emit `X-Accel-Redirect: {prefix}<shard>/<rest>`
    /// (production); when unset, they stream from `facts_dir` (dev / tests). An
    /// [`XAccelConfig`](crate::nginx::XAccelConfig) can only be built by proving
    /// its nginx location is `internal;` and carries the fact hardening headers,
    /// so enabling X-Accel here structurally requires the fail-loud boot check.
    pub x_accel: Option<crate::nginx::XAccelConfig>,
}

impl std::fmt::Debug for FactServingRouteState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FactServingRouteState")
            .field("facts_dir", &self.facts_dir)
            .field("x_accel", &self.x_accel)
            .finish_non_exhaustive()
    }
}

/// The cell-scoped per-reference route: `GET /api/cells/{cell_id}/facts/{hash}`.
///
/// Merge at the app root (it carries its full `/api/...` path, like the audit
/// SSE router).
pub fn cell_fact_router(state: FactServingRouteState) -> Router {
    Router::new()
        .route("/api/cells/{cell_id}/facts/{hash}", get(cell_fact_handler))
        .with_state(state)
}

/// The admin-only bare-hash route: `GET /api/facts/{hash}`.
pub fn bare_fact_router(state: FactServingRouteState) -> Router {
    Router::new()
        .route("/api/facts/{hash}", get(bare_fact_handler))
        .with_state(state)
}

/// Both fact-serving routes (the default mount).
///
/// The cell-scoped per-reference read + the admin-only bare-hash read. Bundling
/// adds zero non-admin surface — the bare-hash route is admin-gated, and an
/// admin can already read every fact via the cell-scoped route.
pub fn fact_routers(state: FactServingRouteState) -> Router {
    cell_fact_router(state.clone()).merge(bare_fact_router(state))
}

/// Handler for `GET /api/cells/{cell_id}/facts/{hash}` — per-reference read.
///
/// Both path params are decoded as raw strings and judged here rather than by
/// a typed extractor: the TS twin declares `params: object({cell_id: Uuid,
/// hash: FactHashSchema})`, so a refusal has to be the spine's flat 400
/// `invalid_route_params` (an extractor rejection is axum's own plain-text
/// body), `cell_id` has to take the wire UUID grammar rather than
/// `Uuid::parse_str`'s wider one, and `hash` the `FactHashSchema` grammar
/// ([`ContentHash::parse_fact_hash`]). The grammar takes the max UUID in any
/// case, as the twin's `Uuid` does; it names no cell, so it is a 404.
async fn cell_fact_handler(
    State(state): State<FactServingRouteState>,
    AxumPath((cell_id_str, hash_str)): AxumPath<(String, String)>,
    client_ip: Option<Extension<ClientIp>>,
    headers: HeaderMap,
) -> Response {
    // The gate's origin check first (module doc, "The origin check").
    let origin = match state.gate.check_origin(&headers) {
        Ok(origin) => origin,
        Err(refused) => return refused,
    };

    // Params next — the TS phase order, and ahead of the pool
    // checkout either way. The body is the same flat 400 the twin's
    // `spec.params` validation emits, so a consumer can put these routes on
    // the round-trip-validated surface and have both backends answer alike.
    if !is_valid_uuid(&cell_id_str) {
        return invalid_route_params_response();
    }
    let Ok(cell_id) = Uuid::parse_str(&cell_id_str) else {
        return invalid_route_params_response();
    };
    let Ok(hash) = ContentHash::parse_fact_hash(&hash_str) else {
        return invalid_route_params_response();
    };

    // Resolve the caller **before** checking a client out of the pool: the
    // builder takes the pool (its credential walk and its actor reads each
    // need a connection), so doing it while holding one would have every
    // in-flight request on this route reserve two — a pool-exhaustion deadlock
    // under concurrency. It is also the TS phase order, where the session
    // middleware resolves the credential ahead of the handler body.
    //
    // Unauthenticated / multi-actor / narrowed-token callers resolve to `None`
    // and are admitted only by a public cell (which `can_view_cell` handles
    // without consulting grants). A fault answers per its kind: the credential
    // walk's 503 (checkout) or plain-text 500 (query), the caller checkout's
    // flat 503, or the flat 500 for the actor and role-grant reads.
    // The twin reads the actor after the cell, so with those reads failing it
    // answers a missing cell's 404 where this answers the 500.
    let client_ip = ClientIp::as_str_or_unresolved(client_ip.as_ref());
    let req_ctx = match state.gate.public_request_context(origin, client_ip).await {
        Ok(req_ctx) => req_ctx,
        Err(fault) => return fault.into_response(),
    };

    let client = match state.gate.pool.get().await {
        Ok(c) => c,
        Err(e) => return fuz_http::db_unavailable_response_with_source("cell_fact: pool get", &e),
    };

    // Resolve the named cell. Missing / soft-deleted → 404 (masked).
    let cell = match query_cell_get(&client, cell_id).await {
        Ok(Some(cell)) => cell,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(e) => return fuz_http::internal_error_response_with_source("cell_fact: cell_get", &e),
    };

    // Per-reference view check — scoped to *this* cell only. It runs before the
    // edge check, so a cell the caller can't view does the same work, and
    // answers the same 404, whether or not it references the hash — the edge
    // stays unobservable to a non-viewer. An anonymous caller skips the grant
    // fetch entirely: no grant can admit a `None` context, whose only admit
    // path is `can_view_cell`'s public-visibility branch, which reads no
    // grants.
    let grants = if req_ctx.is_some() {
        match query_cell_grant_list_for_cell(&client, cell.id).await {
            Ok(g) => Some(g),
            Err(e) => {
                return fuz_http::internal_error_response_with_source("cell_fact: grant_list", &e);
            }
        }
    } else {
        None
    };
    // The governing root's manager also reads a pending or rejected
    // contribution's facts (the steward arm, `fuz_cell::cell_steward`), checked
    // only once the view check denies.
    if !can_view_cell(req_ctx.as_ref(), &cell, grants.as_deref()) {
        match cell_steward_admits(&client, req_ctx.as_ref(), &cell).await {
            Ok(true) => {}
            // 404 (not 403) so an unviewable cell→fact edge doesn't leak.
            Ok(false) => return StatusCode::NOT_FOUND.into_response(),
            Err(e) => {
                return fuz_http::internal_error_response_with_source(
                    "cell_fact: steward root load",
                    &e,
                );
            }
        }
    }

    // The cell→fact edge: the cell must actually reference the hash. Missing
    // edge → 404 (masked), never "exists elsewhere".
    let hash_prefixed = hash.to_prefixed();
    let edge_present = cell
        .refs
        .as_ref()
        .is_some_and(|refs: &Vec<String>| refs.iter().any(|r| r == &hash_prefixed));
    if !edge_present {
        return StatusCode::NOT_FOUND.into_response();
    }

    serve_fact_bytes(&client, &hash, &state).await
}

/// Handler for `GET /api/facts/{hash}` — admin-only bare-hash read.
///
/// Phase order matches the TS pipeline: params (hash) → query shape → 401 →
/// token scope → acting resolution → 403 role. The TS twin declares
/// `query: object({acting: ActingActor})`, so an unknown query key or
/// a malformed `acting` is a 400 `invalid_query_params` **before** auth
/// resolves — the query is read as raw pairs (first occurrence wins on a
/// duplicated key, like Hono's `c.req.query()`) so a duplicated `acting`
/// never trips axum's pre-handler derived-serde "duplicate field" reject.
///
/// Every denial is the flat `{error}` body the TS guard emits: 401
/// `authentication_required`, 403 `token_scope_required` for a narrowed token,
/// 403 `insufficient_permissions` carrying `required_roles`.
async fn bare_fact_handler(
    State(state): State<FactServingRouteState>,
    AxumPath(hash_str): AxumPath<String>,
    Query(query_pairs): Query<Vec<(String, String)>>,
    client_ip: Option<Extension<ClientIp>>,
    headers: HeaderMap,
) -> Response {
    // The gate's origin check first (module doc, "The origin check").
    let origin = match state.gate.check_origin(&headers) {
        Ok(origin) => origin,
        Err(refused) => return refused,
    };

    // Malformed hash → the flat 400 `invalid_route_params`, as on the
    // cell-scoped route above.
    let Ok(hash) = ContentHash::parse_fact_hash(&hash_str) else {
        return invalid_route_params_response();
    };

    // Query shape before auth — the TS phase order (params → query → 401).
    if let Err(resp) = assert_known_query_keys(&query_pairs, &["acting"]) {
        return resp;
    }
    let acting = match parse_acting_query(query_first(&query_pairs, "acting")) {
        Ok(a) => a,
        Err(resp) => return resp,
    };

    // Authed path: resolve credentials (cookie / bearer / daemon-token).
    let client_ip = ClientIp::as_str_or_unresolved(client_ip.as_ref());
    // the bearer leg records `client_ip` as `api_token.last_used_ip`
    let auth = match state.gate.resolve_credential(origin, client_ip).await {
        Ok(Some(auth)) => auth,
        Ok(None) => return fuz_http::authentication_required_response(),
        Err(fault) => return fault.into_response(),
    };

    // Token-scope surface gate (rule 3) — a narrowed token gets no bare-hash
    // read. This route serves *any* stored fact by hash with no per-reference
    // cell check (that is `cell_fact_router`'s job), so it is the broad
    // capability of the pair; gating it here keeps a narrowed token to the
    // cell-scoped route its RPC methods can actually justify.
    if !auth.scope().admits_non_rpc_surface() {
        return fuz_auth::token_scope_surface_denied_response(
            fuz_auth::TokenSurface::FactBare.capability(),
        );
    }

    let client = match state.gate.pool.get().await {
        Ok(c) => c,
        Err(e) => return fuz_http::db_unavailable_response_with_source("bare_fact: pool get", &e),
    };

    // Admin check, honoring `?acting=` for multi-actor admins. No actor comes
    // out of the credential walk — it resolves account-grain identity
    // only — so the actor is bound here, by `resolve_admin`'s
    // `fuz_auth::resolve_acting_actor` call: a single-actor account auto-picks
    // its sole actor, and `acting`, when present, names the actor on the
    // account whose grants decide.
    let is_admin = match resolve_admin(&client, &auth, acting).await {
        Ok(ok) => ok,
        Err(resp) => return resp,
    };
    if !is_admin {
        return fuz_http::insufficient_permissions_response(&[ROLE_ADMIN]);
    }

    serve_fact_bytes(&client, &hash, &state).await
}

/// Decide whether the caller is an admin, resolving the acting actor from the
/// account-grain credential and reading **that persona's** grants.
///
/// A single-actor admin auto-resolves; a multi-actor admin disambiguates with
/// `?acting=`. The resolution and its three denials come from the shared
/// [`require_acting_actor`], so this route answers a selector exactly as
/// `fuz_db_admin` and `fuz_realtime`'s audit stream do — 400 `actor_required`
/// with the available list when a multi-actor account names no persona, an
/// opaque 400 `actor_not_on_account` for a foreign one, 500
/// `no_actors_on_account` for the signup-invariant violation.
async fn resolve_admin<C: GenericClient + ?Sized>(
    client: &C,
    auth: &fuz_auth::ResolvedAuth,
    acting: Option<Uuid>,
) -> Result<bool, Response> {
    let actor = require_acting_actor(client, &auth.account.id, acting, "bare_fact").await?;
    let role_grants =
        fuz_auth::actor_queries::query_role_grant_find_active_for_actor(client, &actor.id)
            .await
            .map_err(|e| {
                fuz_http::internal_error_response_with_source("bare_fact: role_grants", &e)
            })?;
    // The global grant only — a scoped `admin` row (which no grant path mints)
    // must not read every fact. Mirrors the TS route's `require_role` gate.
    Ok(role_grants
        .iter()
        .any(|g| g.role == ROLE_ADMIN && g.scope_id.is_none()))
}

/// Serve a fact's bytes by hash, **after** the caller has been authorized.
///
/// The shared tail of both routes — it never re-checks authz, so it MUST only
/// run once the caller is admitted. Embedded bytes stream from the PG row;
/// external facts emit `X-Accel-Redirect` (production) or stream from disk
/// (dev/test). 404 when the fact is absent or its embedded bytes have vanished
/// (a race), so the shape is identical whether the fact is genuinely absent or
/// merely unviewable.
async fn serve_fact_bytes<C: GenericClient + ?Sized>(
    client: &C,
    hash: &ContentHash,
    state: &FactServingRouteState,
) -> Response {
    let meta = match query_get_fact_meta(client, hash).await {
        Ok(Some(m)) => m,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(e) => return fuz_http::internal_error_response_with_source("serve_fact: get_meta", &e),
    };
    let content_type = meta
        .content_type
        .unwrap_or_else(|| "application/octet-stream".to_owned());

    let Some(external_url) = meta.external_url else {
        // Embedded — bytes live in the PG row.
        let row = match query_get_fact(client, hash).await {
            Ok(Some(r)) => r,
            Ok(None) => return StatusCode::NOT_FOUND.into_response(),
            Err(e) => {
                return fuz_http::internal_error_response_with_source("serve_fact: get_fact", &e);
            }
        };
        let Some(bytes) = row.bytes else {
            // Race: meta said embedded but bytes vanished. Treat as not-found.
            tracing::warn!(hash = %hash.to_prefixed(), "serve_fact: embedded bytes missing (meta said embedded)");
            return StatusCode::NOT_FOUND.into_response();
        };
        return body_response(Body::from(bytes), &content_type, meta.size, None);
    };

    // External — defense-in-depth re-validate the URL before trusting it to
    // address the filesystem / nginx: its shape, then that it is this hash's
    // own address (module doc, "Defense-in-depth").
    let Some(parsed) = parse_fact_file_url(&external_url) else {
        tracing::error!(hash = %hash.to_prefixed(), url = external_url, "serve_fact: rejecting malformed external_url");
        return StatusCode::NOT_FOUND.into_response();
    };
    if !parsed.addresses(hash) {
        tracing::error!(hash = %hash.to_prefixed(), url = external_url, "serve_fact: rejecting an external_url that addresses another fact");
        return StatusCode::NOT_FOUND.into_response();
    }

    if let Some(x_accel) = state.x_accel.as_ref() {
        // Production: hand off to nginx via the validated `internal;` facts location.
        // nginx answers with that location's own `add_header` set, not these
        // headers, which is why the validator requires the fact pair there.
        let redirect = format!(
            "{}{}/{}",
            x_accel.redirect_prefix(),
            parsed.shard,
            parsed.rest
        );
        return body_response(Body::empty(), &content_type, meta.size, Some(&redirect));
    }

    // Dev / tests: stream from disk.
    let path = state.facts_dir.join(&parsed.shard).join(&parsed.rest);
    match tokio::fs::File::open(&path).await {
        Ok(file) => {
            let stream = tokio_util::io::ReaderStream::new(file);
            body_response(Body::from_stream(stream), &content_type, meta.size, None)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            let error: &(dyn std::error::Error + 'static) = &e;
            tracing::error!(error, path = %path.display(), "serve_fact: disk open");
            fuz_http::internal_error_response()
        }
    }
}

/// Build a 200 response with the fact headers. `x_accel_redirect`, when set,
/// is emitted as `X-Accel-Redirect` (the body is then empty — nginx serves the
/// bytes). `Content-Disposition` is deliberately **not** set — facts serve
/// inline (e.g. images render in-page) — but the untrusted-content hardening
/// headers (`X-Content-Type-Options: nosniff` +
/// `Content-Security-Policy: default-src 'none'; sandbox`) are always set, so a
/// fact stored as `text/html` (or sniffable to it) can't execute as stored XSS.
/// The single funnel for every served-fact branch, byte-identical with the TS
/// twin (`serve_fact_route.ts`). On the embedded and disk-stream branches these
/// are the headers the client gets; on the `X-Accel-Redirect` branch nginx
/// replaces them with the internal facts location's own `add_header` set, which
/// must carry the same pair (the X-Accel validator enforces it).
fn body_response(
    body: Body,
    content_type: &str,
    size: i64,
    x_accel_redirect: Option<&str>,
) -> Response {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(content_type)
            .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream")),
    );
    if let Ok(len) = HeaderValue::from_str(&size.to_string()) {
        headers.insert(header::CONTENT_LENGTH, len);
    }
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(CACHE_CONTROL),
    );
    // untrusted-content hardening, see `fact_security_headers` — on the
    // X-Accel branch nginx serves the location's own copy of this pair
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static(FACT_X_CONTENT_TYPE_OPTIONS),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(FACT_CONTENT_SECURITY_POLICY),
    );
    if let Some(redirect) = x_accel_redirect
        && let Ok(value) = HeaderValue::from_str(redirect)
    {
        headers.insert(HeaderName::from_static("x-accel-redirect"), value);
    }
    (StatusCode::OK, headers, body).into_response()
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt as _;

    use super::{FactServingRouteState, StatusCode, bare_fact_router, cell_fact_router};

    /// A route state over a **lazily-created** pool: `fuz_db::create_pool`
    /// parses the URL and builds the deadpool manager without dialing, so a
    /// refusal that precedes the first checkout — which every params rejection
    /// does, by contract — is drivable with no database. So is the checkout
    /// itself failing: nothing listens on the port the URL names. Anything
    /// that reaches a query belongs in the `#[ignore]`d `tests/serve.rs` suite
    /// instead.
    fn no_db_state() -> FactServingRouteState {
        FactServingRouteState {
            gate: fuz_testing::testing_auth_gate(
                fuz_db::create_pool(
                    "postgres://fact_serving_params_test@127.0.0.1:1/none",
                    &fuz_db::PoolOptions::default(),
                )
                .expect("pool builds without connecting"),
            ),
            facts_dir: PathBuf::from("/nonexistent-facts-dir"),
            x_accel: None,
        }
    }

    /// Anonymous GET: status, `Content-Type`, body.
    async fn get(router: axum::Router, uri: &str) -> (StatusCode, Option<String>, String) {
        let response = router
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(uri)
                    .body(Body::empty())
                    .expect("request builds"),
            )
            .await
            .expect("router responds");
        let status = response.status();
        let content_type = response
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .map(|v| v.to_str().expect("content-type is ascii").to_owned());
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body collects");
        (
            status,
            content_type,
            String::from_utf8(bytes.to_vec()).expect("body is utf-8"),
        )
    }

    async fn get_body(router: axum::Router, uri: &str) -> (StatusCode, String) {
        let (status, _, body) = get(router, uri).await;
        (status, body)
    }

    /// A GET carrying `origin`: status and body.
    async fn get_with_origin(
        router: axum::Router,
        uri: &str,
        origin: &str,
    ) -> (StatusCode, String) {
        let response = router
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(uri)
                    .header(axum::http::header::ORIGIN, origin)
                    .body(Body::empty())
                    .expect("request builds"),
            )
            .await
            .expect("router responds");
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body collects");
        (
            status,
            String::from_utf8(bytes.to_vec()).expect("body is utf-8"),
        )
    }

    /// Both routes refuse a foreign `Origin` with the flat `forbidden_origin`
    /// 403 **first** — ahead of the params gate (malformed params beside it
    /// still answer 403) and of any pool work (the pool never dials). An
    /// allowed origin falls through to the next gate's answer.
    #[tokio::test]
    async fn both_routes_refuse_a_foreign_origin_before_any_other_gate() {
        const FORBIDDEN: &str = r#"{"error":"forbidden_origin"}"#;
        let valid_hash = format!("blake3:{}", "0".repeat(64));
        let valid_cell_id = "3f8a1c2e-1234-4abc-9def-0123456789ab";
        let cases = [
            (
                cell_fact_router(no_db_state()),
                format!("/api/cells/{valid_cell_id}/facts/{valid_hash}"),
            ),
            (
                cell_fact_router(no_db_state()),
                "/api/cells/not-a-uuid/facts/not-a-hash".to_owned(),
            ),
            (
                bare_fact_router(no_db_state()),
                format!("/api/facts/{valid_hash}"),
            ),
            (
                bare_fact_router(no_db_state()),
                "/api/facts/not-a-hash?foo=1".to_owned(),
            ),
        ];
        for (router, uri) in cases {
            assert_eq!(
                get_with_origin(router, &uri, "https://evil.example").await,
                (StatusCode::FORBIDDEN, FORBIDDEN.to_owned()),
                "{uri}"
            );
        }
        // the allowed origin reaches the bare route's 401
        assert_eq!(
            get_with_origin(
                bare_fact_router(no_db_state()),
                &format!("/api/facts/{valid_hash}"),
                fuz_testing::TESTING_ALLOWED_ORIGIN,
            )
            .await
            .0,
            StatusCode::UNAUTHORIZED
        );
    }

    /// A pool that cannot be checked out answers the spine's flat 503 on the
    /// cell-scoped route — status, `Content-Type`, and body byte for byte, the
    /// envelope the bare-hash route gives the same failure. An anonymous
    /// caller with well-formed params is what reaches the checkout: resolving
    /// no credential touches no connection.
    #[tokio::test]
    async fn cell_route_pool_failure_answers_the_flat_503() {
        let uri = format!(
            "/api/cells/3f8a1c2e-1234-4abc-9def-0123456789ab/facts/blake3:{}",
            "0".repeat(64)
        );
        let (status, content_type, body) = get(cell_fact_router(no_db_state()), &uri).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(content_type.as_deref(), Some("application/json"));
        assert_eq!(body, r#"{"error":"service_unavailable"}"#);
    }

    /// A nameless query pair is not an unknown key on the bare-hash route: the
    /// request clears the query gate and is answered by the next one, the 401
    /// an anonymous caller gets with no query at all. An undeclared key beside
    /// it is still refused at the query gate, and `acting` is still read.
    #[tokio::test]
    async fn bare_route_ignores_a_nameless_query_pair() {
        const UNAUTHENTICATED: &str = r#"{"error":"authentication_required"}"#;
        const INVALID_QUERY: &str = r#"{"error":"invalid_query_params"}"#;
        let base = format!("/api/facts/blake3:{}", "0".repeat(64));
        let cases = [
            ("", StatusCode::UNAUTHORIZED, UNAUTHENTICATED),
            ("?=x", StatusCode::UNAUTHORIZED, UNAUTHENTICATED),
            ("?=", StatusCode::UNAUTHORIZED, UNAUTHENTICATED),
            (
                "?=x&acting=3f8a1c2e-1234-4abc-9def-0123456789ab",
                StatusCode::UNAUTHORIZED,
                UNAUTHENTICATED,
            ),
            ("?=x&foo=1", StatusCode::BAD_REQUEST, INVALID_QUERY),
            (
                "?=x&acting=not-a-uuid",
                StatusCode::BAD_REQUEST,
                INVALID_QUERY,
            ),
        ];
        for (query, expected_status, expected_body) in cases {
            let uri = format!("{base}{query}");
            let (status, body) = get_body(bare_fact_router(no_db_state()), &uri).await;
            assert_eq!(status, expected_status, "{uri}");
            assert_eq!(body, expected_body, "{uri}");
        }
    }

    /// The params refusal is the spine's flat `invalid_route_params` envelope,
    /// pinned **byte-for-byte** on both routes and on both path params.
    ///
    /// The TS twin declares `params: object({cell_id: Uuid, hash:
    /// FactHashSchema})` and answers that body from its params middleware, so a
    /// consumer mounting these routes on the round-trip-validated surface gets
    /// the same bytes from either backend. A `Value` comparison would pass on a
    /// reordered or whitespace-padded body; the string won't.
    #[tokio::test]
    async fn malformed_path_params_answer_the_flat_invalid_route_params_body() {
        const EXPECTED: &str = r#"{"error":"invalid_route_params"}"#;
        let valid_hash = format!("blake3:{}", "0".repeat(64));
        let valid_cell_id = "3f8a1c2e-1234-4abc-9def-0123456789ab";
        let cases = [
            // Cell-scoped route: each param malformed in turn.
            (
                cell_fact_router(no_db_state()),
                format!("/api/cells/{valid_cell_id}/facts/not-a-hash"),
            ),
            (
                cell_fact_router(no_db_state()),
                format!("/api/cells/not-a-uuid/facts/{valid_hash}"),
            ),
            // The wire grammar, not `Uuid::parse_str`'s: the hyphenless
            // spelling of a real id parses for Rust and Postgres, and is
            // refused by the TS twin.
            (
                cell_fact_router(no_db_state()),
                format!(
                    "/api/cells/{}/facts/{valid_hash}",
                    valid_cell_id.replace('-', "")
                ),
            ),
            // The `FactHashSchema` grammar: uppercase hex, and the other
            // algorithms `ContentHash` knows.
            (
                cell_fact_router(no_db_state()),
                format!("/api/cells/{valid_cell_id}/facts/blake3:{}", "A".repeat(64)),
            ),
            (
                cell_fact_router(no_db_state()),
                format!("/api/cells/{valid_cell_id}/facts/sha256:{}", "0".repeat(64)),
            ),
            (
                cell_fact_router(no_db_state()),
                format!(
                    "/api/cells/{valid_cell_id}/facts/sha512:{}",
                    "0".repeat(128)
                ),
            ),
            // Digest length, either side of the bound.
            (
                cell_fact_router(no_db_state()),
                format!("/api/cells/{valid_cell_id}/facts/blake3:{}", "0".repeat(63)),
            ),
            (
                cell_fact_router(no_db_state()),
                format!("/api/cells/{valid_cell_id}/facts/blake3:{}", "0".repeat(65)),
            ),
            // Bare-hash route — the same grammar, the same refusal.
            (
                bare_fact_router(no_db_state()),
                "/api/facts/not-a-hash".to_owned(),
            ),
            (
                bare_fact_router(no_db_state()),
                format!("/api/facts/blake3:{}", "A".repeat(64)),
            ),
            (
                bare_fact_router(no_db_state()),
                format!("/api/facts/sha256:{}", "0".repeat(64)),
            ),
            (
                bare_fact_router(no_db_state()),
                format!("/api/facts/sha512:{}", "0".repeat(128)),
            ),
            (
                bare_fact_router(no_db_state()),
                format!("/api/facts/blake3:{}", "0".repeat(63)),
            ),
            (
                bare_fact_router(no_db_state()),
                format!("/api/facts/blake3:{}", "0".repeat(65)),
            ),
        ];
        for (router, uri) in cases {
            let (status, body) = get_body(router, &uri).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{uri}");
            assert_eq!(body, EXPECTED, "{uri}");
        }
    }
}
