//! Per-action auth — the four-axis [`AuthSpec`] and the split
//! pre-/post-authorization gates.
//!
//! The TS twin's single `RequestResponseActionSpec` is split across two
//! crates here: [`AuthSpec`] carries the four auth axes (`account` / `actor` /
//! `roles` / `credentials`) on a [`crate::AuthActionEntry`] row, while the
//! dispatcher-side `side_effects: bool` lives in `fuz_actions`'s `ActionSpec`.
//! Action specs that need both embed `auth: AuthSpec` and pair it with their
//! dispatcher-side metadata.
//!
//! ## Two-phase enforcement
//!
//! The actor (and thus its `role_grants`) is unknown until the dispatcher's
//! authorization phase resolves it from the `acting` input. So the auth gate
//! splits in two, mirroring `fuz_app`'s `perform_action.ts`:
//!
//! - [`check_action_auth_pre_authorization`] — the **401** (account / actor
//!   required + no resolved account). Runs before the authorization phase.
//! - [`check_action_auth_post_authorization`] — the **credential-type 403**
//!   and the **role 403**, the latter evaluated over the *resolved* actor's
//!   `role_grants`. Runs after the authorization phase resolves the actor.
//!
//! The role gate **must** run after actor resolution: evaluating it over a
//! different actor than the one the handler acts as is privilege confusion.

use crate::credential_type::{CredentialGate, CredentialType};
use crate::request_context::ResolvedAuthContext;
use crate::token_scope::TokenScope;
use fuz_http::{JsonrpcError, JsonrpcErrorCode, unauthenticated};

/// The token-scope 403 — one builder, so the RPC gate below and the non-RPC
/// surface gates emit a byte-identical body.
///
/// Shape takes the spine's `data.reason` discriminator (machine-dispatchable
/// alongside `credential_type_required` / `insufficient_permissions`, which
/// `fuz_forge`'s bare `{required}` is not) and `fuz_forge`'s capability-string
/// vocabulary for the value (`rpc:<method>`, `surface:<name>`) — already stable
/// and already in forge's audit rows.
#[must_use]
pub fn token_scope_denied(required_scope: &str) -> JsonrpcError {
    JsonrpcError {
        code: JsonrpcErrorCode::Forbidden,
        message: "forbidden".to_owned(),
        data: Some(serde_json::json!({
            "reason": "token_scope_required",
            "required_scope": required_scope,
        })),
    }
}

/// The credential-type 403 — one builder for the dispatcher's gate and the
/// handlers that gate a channel themselves.
///
/// A handler gates a credential channel on its input when the spec can't (the
/// `account_delete` self path), and must emit the dispatcher's body byte for
/// byte. `required_credential_types` lists `gate`'s allowlist by wire name.
#[must_use]
pub fn credential_type_required(gate: CredentialGate) -> JsonrpcError {
    let names: Vec<&'static str> = gate.allowed().iter().map(|c| c.name()).collect();
    JsonrpcError {
        code: JsonrpcErrorCode::Forbidden,
        message: "forbidden".to_owned(),
        data: Some(serde_json::json!({
            "reason": "credential_type_required",
            "required_credential_types": names,
        })),
    }
}

/// One auth axis — `account` and `actor` each take one of these.
///
/// Mirrors `fuz_app`'s `AuthAxisState` (`'none' | 'optional' | 'required'`):
///
/// - [`None`](Self::None) — explicitly skipped even when the credential
///   provides it (public actions; account-grain ⇒ `actor: None`).
/// - [`Optional`](Self::Optional) — resolved if the credential provides it,
///   anonymous / account-only fallback otherwise (identity-aware reads).
/// - [`Required`](Self::Required) — must be resolved; the dispatcher rejects
///   requests that can't provide it (401 for `account`, `actor_required` 400
///   for `actor`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthAxis {
    /// Explicitly skipped.
    None,
    /// Resolved if available, falls back otherwise.
    Optional,
    /// Must be resolved or the request is rejected.
    Required,
}

/// Four-axis auth shape for an action.
///
/// Names each axis the dispatcher walks independently, mirroring `fuz_app`'s
/// `RouteAuth` (`{account, actor, roles?, credential_types?}`). The shape is flat
/// rather than a `Public | Authenticated { … }` enum, whose conflation of
/// "authenticated" with "actor-bound" is untenable under multi-actor.
///
/// Construct via the [`Self::public`] / [`Self::authenticated`] helpers, or a
/// struct literal for shapes they don't cover. Registry-time invariants
/// (1/3/4/5) are enforced by [`Self::validate`], called when specs are compiled
/// into the `fuz_actions` registry — a violation is a hard startup error (fail
/// loud).
///
/// Every constructor takes its [`CredentialGate`] explicitly. There is no
/// permissive default to fall into: an action reachable by an API token says
/// [`CredentialGate::Any`], and the declaration is what a reviewer reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthSpec {
    /// Does the dispatcher require / surface / skip the account?
    pub account: AuthAxis,
    /// Does the dispatcher resolve / surface / skip the acting actor?
    pub actor: AuthAxis,
    /// `Some(roles)` → caller's resolved actor must hold one of these
    /// (any-of); `None` → no role check. Implies `actor: Required` (invariant 1).
    pub roles: Option<&'static [&'static str]>,
    /// Which credential channels admit — mandatory, so the permissive case is
    /// spelled rather than defaulted into. See [`CredentialGate`].
    pub credentials: CredentialGate,
}

impl AuthSpec {
    /// Public — no gates of any kind (`account: None, actor: None`).
    ///
    /// Takes no [`CredentialGate`]: a spec that resolves neither account nor
    /// actor has no credential to gate, which invariant 4 enforces.
    #[must_use]
    pub const fn public() -> Self {
        Self {
            account: AuthAxis::None,
            actor: AuthAxis::None,
            roles: None,
            credentials: CredentialGate::Any,
        }
    }

    /// Authenticated with a resolved actor and no role gate
    /// (`account: Required, actor: Required`).
    ///
    /// The common shape for actor-bound action handlers — the dispatcher
    /// resolves the acting actor before the handler runs, so `ctx.auth` is
    /// the `Actor` variant. `credentials` is mandatory: pass
    /// [`CredentialGate::Any`] for an action any credential may reach, or a
    /// narrower gate to keep a channel out.
    #[must_use]
    pub const fn authenticated(credentials: CredentialGate) -> Self {
        Self {
            account: AuthAxis::Required,
            actor: AuthAxis::Required,
            roles: None,
            credentials,
        }
    }

    /// Identity-aware optional auth (`account: Optional, actor: Optional`).
    ///
    /// The shape for public-but-identity-aware reads (`cell_get` / `cell_list`
    /// / `cell_field_list` / `cell_item_list`): an authenticated single-actor
    /// caller resolves to the `Actor` variant for per-row authz; an anonymous
    /// (or multi-actor-no-`acting`) caller falls back to anonymous /
    /// account-grain. Never 401s.
    ///
    /// A gate narrower than [`CredentialGate::Any`] rejects the *anonymous*
    /// caller too — [`CredentialGate::admits`] is false for `None` — which
    /// turns the never-401 read into a 403 for exactly the callers it exists
    /// to serve. Pass `Any` unless that is the intent.
    #[must_use]
    pub const fn optional_identity(credentials: CredentialGate) -> Self {
        Self {
            account: AuthAxis::Optional,
            actor: AuthAxis::Optional,
            roles: None,
            credentials,
        }
    }

    /// Authenticated with a resolved actor plus a **role** gate
    /// (`account: Required, actor: Required`).
    ///
    /// The role-gated shapes — admin (`roles: [admin]`), keeper
    /// (`CredentialGate::Only(&[DaemonToken])` + `roles: [keeper]`),
    /// session-only admin (`CredentialGate::SESSION_ONLY` + `roles: [admin]`).
    /// `roles` is a non-empty allowlist; for an ungated-by-role action use
    /// [`Self::authenticated`] rather than passing an empty slice, so
    /// "gated" never names a spec that gates nothing.
    #[must_use]
    pub const fn authenticated_gated(
        credentials: CredentialGate,
        roles: &'static [&'static str],
    ) -> Self {
        Self {
            account: AuthAxis::Required,
            actor: AuthAxis::Required,
            roles: Some(roles),
            credentials,
        }
    }

    /// Account-grain authenticated (`account: Required, actor: None`) — account
    /// self-service operations that act on the caller's own account (session /
    /// token management, `account_verify`, the authenticated actor reads) and
    /// never resolve a persona. The TS twin declares these `actor: 'none'`, so
    /// the dispatcher hands the handler the account-grain `Account` context.
    ///
    /// No `roles` parameter: a role gate implies `actor: Required`
    /// (invariant 1), which is incompatible with the account-grain shape. The
    /// credential-lifecycle mutations pass [`CredentialGate::SESSION_ONLY`]
    /// here.
    #[must_use]
    pub const fn account_grain(credentials: CredentialGate) -> Self {
        Self {
            account: AuthAxis::Required,
            actor: AuthAxis::None,
            roles: None,
            credentials,
        }
    }

    /// True iff fully public — both `account` and `actor` are `None`. Public
    /// actions skip the authorization phase entirely.
    #[must_use]
    pub const fn is_public(&self) -> bool {
        matches!(self.account, AuthAxis::None) && matches!(self.actor, AuthAxis::None)
    }

    /// True iff a credential must be present (401 otherwise). Either axis being
    /// `Required` forces an account — invariant 3 (no accountless actors)
    /// guarantees `actor: Required` implies an account.
    #[must_use]
    pub const fn account_required(&self) -> bool {
        matches!(self.account, AuthAxis::Required) || matches!(self.actor, AuthAxis::Required)
    }

    /// True iff the dispatcher resolves an acting actor (`actor` is `Optional`
    /// or `Required`).
    #[must_use]
    pub const fn needs_actor(&self) -> bool {
        !matches!(self.actor, AuthAxis::None)
    }

    /// Validate the cross-axis registry invariants (1, 3, 4, 5). Returns the
    /// violated invariant's message on failure.
    ///
    /// Mirrors `fuz_app`'s `RouteAuth` `.superRefine`. Invariant 2 (the
    /// `actor != None ⟺ input declares acting` biconditional) needs typed-input
    /// introspection the Rust spine lacks pre-codegen, so it stays deferred —
    /// the dispatcher reads `acting` from raw params instead.
    ///
    /// # Errors
    ///
    /// Returns a static message naming the violated invariant.
    pub const fn validate(&self) -> Result<(), &'static str> {
        // Invariant 1: roles imply actor: Required (the role check reads the
        // resolved actor's role_grants, so a role gate without an actor has
        // nothing to check).
        if let Some(roles) = self.roles
            && !roles.is_empty()
            && !matches!(self.actor, AuthAxis::Required)
        {
            return Err(
                "auth.roles requires auth.actor = Required (role checks read the resolved actor's role_grants)",
            );
        }
        // Invariant 3: no accountless actors in v1 (the credential resolver
        // always binds account before actor today).
        if matches!(self.account, AuthAxis::None) && !matches!(self.actor, AuthAxis::None) {
            return Err(
                "auth.account = None with auth.actor != None is unsupported (no accountless actors in v1)",
            );
        }
        // Invariant 4: the unrestricted leaf cannot declare roles or credential
        // gates (nothing left to gate).
        if matches!(self.account, AuthAxis::None) && matches!(self.actor, AuthAxis::None) {
            if let Some(roles) = self.roles
                && !roles.is_empty()
            {
                return Err(
                    "unrestricted auth (account = None, actor = None) cannot declare roles",
                );
            }
            if !self.credentials.is_any() {
                return Err(
                    "unrestricted auth (account = None, actor = None) cannot declare credential_types",
                );
            }
        }
        // Invariant 5: an empty credential allowlist admits nothing, which is
        // never what a spec means — it renders the action unreachable while
        // reading like a gate. `CredentialGate::Any` is how you spell
        // "unconstrained".
        if let CredentialGate::Only(types) = self.credentials
            && types.is_empty()
        {
            return Err(
                "auth.credentials = Only(&[]) admits no credential — use CredentialGate::Any",
            );
        }
        Ok(())
    }
}

/// Pre-authorization gate — the **401**.
///
/// Fires when the spec requires an account (or actor, which implies an
/// account) and the credential resolved none. Mirrors `fuz_app`'s
/// `check_action_auth_pre_authorization`. Runs before the authorization phase so
/// an unauthenticated caller never reaches actor resolution.
///
/// Returns `None` when the gate passes, `Some(error)` (401) otherwise.
#[inline]
#[must_use]
pub fn check_action_auth_pre_authorization(
    spec: &AuthSpec,
    has_account: bool,
) -> Option<JsonrpcError> {
    if spec.account_required() && !has_account {
        // Single source of truth for the 401 wire shape — the builder carries
        // `data.reason = "authentication_required"` (symmetric with the 403
        // gates below).
        return Some(unauthenticated());
    }
    None
}

/// Post-authorization gate — the **credential-type 403**, the **token-scope
/// 403**, then the **role 403**.
///
/// Runs after the authorization phase resolved the acting actor. The role
/// gate is evaluated over the *resolved* actor's `role_grants` (the
/// security-critical ordering) via the [`ResolvedAuthContext`]; a non-`Actor`
/// context holds no `role_grants`, so a role-gated spec rejects it. Only a
/// **global** grant (`scope_id IS NULL`) of a listed role passes — a scoped
/// grant never satisfies a spec-level role. Mirrors `fuz_app`'s
/// `check_action_auth_post_authorization`.
///
/// ## Gate order: credential → scope → role
///
/// **Credential first** because it is the coarser fact ("this channel may never
/// call me" outranks "this token may not"), because it preserves every existing
/// wire assertion — a session-only spec called over bearer keeps returning
/// `credential_type_required` — and because it leaks less: telling a bearer
/// caller *"your token lacks `rpc:X`"* on an endpoint no bearer may ever reach
/// confirms the endpoint to a channel that should not learn it.
///
/// **Scope before role** because scope is a fact about the credential, decided
/// without a DB read, while the role gate reads the resolved actor's grants.
/// Coarse → fine, and an under-scoped token learns nothing about the
/// deployment's role structure.
///
/// `scope` is `None` only for the anonymous caller, who holds no credential to
/// narrow — every resolved credential carries one (see
/// [`ResolvedAuth::scope`](crate::ResolvedAuth)). It mirrors the `Option` shape
/// the `credential_type` parameter already has for the same reason.
///
/// Returns `None` when all three gates pass, `Some(error)` (403) otherwise.
#[inline]
#[must_use]
pub fn check_action_auth_post_authorization(
    spec: &AuthSpec,
    context: ResolvedAuthContext<'_>,
    credential_type: Option<CredentialType>,
    method: &str,
    scope: Option<&TokenScope>,
) -> Option<JsonrpcError> {
    if !spec.credentials.admits(credential_type) {
        return Some(credential_type_required(spec.credentials));
    }

    if let Some(scope) = scope
        && !scope.admits_method(method)
    {
        return Some(token_scope_denied(&format!("rpc:{method}")));
    }

    if let Some(required_roles) = spec.roles {
        // The role gate reads the resolved actor's grants — the credential
        // binds no actor of its own. Only a **global** grant satisfies it: the
        // spec names a role with no scope, so a grant bound to one resource
        // must not pass (a scoped `admin` would otherwise reach every admin
        // action). Scoped capabilities are gated in handlers, against the
        // scope the input names. Mirrors TS
        // `has_any_scoped_role(request_context, auth.roles, null)`.
        let has_required = context
            .actor()
            .is_some_and(|ctx| ctx.has_any_scoped_role(required_roles, None));
        if !has_required {
            return Some(JsonrpcError {
                code: JsonrpcErrorCode::Forbidden,
                message: "forbidden".to_owned(),
                data: Some(serde_json::json!({
                    "reason": "insufficient_permissions",
                    "required_roles": required_roles,
                })),
            });
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::{
        AuthAxis, AuthSpec, check_action_auth_post_authorization,
        check_action_auth_pre_authorization,
    };
    use crate::account_schema::AccountRow;
    use crate::actor_schema::ActorRow;
    use crate::credential_type::{CredentialGate, CredentialType};
    use crate::request_context::{RequestActorContext, RequestContext, ResolvedAuthContext};
    use crate::role_grant_schema::RoleGrantRow;
    use crate::token_scope::TokenScope;
    use uuid::Uuid;

    const ADMIN: &[&str] = &["admin"];

    /// Stand-in method name for gates that aren't exercising the scope axis.
    const M: &str = "some_method";

    fn account() -> AccountRow {
        AccountRow {
            id: Uuid::nil(),
            username: "u".to_owned(),
        }
    }

    fn actor_ctx(roles: &[&str]) -> RequestActorContext {
        RequestActorContext {
            account: account(),
            actor: ActorRow {
                id: Uuid::nil(),
                account_id: Uuid::nil(),
                name: "a".to_owned(),
            },
            role_grants: roles
                .iter()
                .map(|r| RoleGrantRow {
                    id: Uuid::nil(),
                    actor_id: Uuid::nil(),
                    role: (*r).to_owned(),
                    scope_id: None,
                })
                .collect(),
        }
    }

    /// The machine-readable `error.data.reason` discriminator.
    fn reason(err: &fuz_http::JsonrpcError) -> String {
        err.data
            .as_ref()
            .and_then(|d| d.get("reason"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .to_owned()
    }

    // --- AuthSpec::validate (registry-time invariants 1/3/4/5) ---

    #[test]
    fn validate_accepts_every_constructor() {
        assert!(AuthSpec::public().validate().is_ok());
        assert!(
            AuthSpec::authenticated(CredentialGate::Any)
                .validate()
                .is_ok()
        );
        assert!(
            AuthSpec::optional_identity(CredentialGate::Any)
                .validate()
                .is_ok()
        );
        assert!(
            AuthSpec::authenticated_gated(
                CredentialGate::Only(&[CredentialType::DaemonToken]),
                ADMIN
            )
            .validate()
            .is_ok()
        );
        assert!(
            AuthSpec::account_grain(CredentialGate::SESSION_ONLY)
                .validate()
                .is_ok()
        );
    }

    #[test]
    fn validate_invariant_5_rejects_an_empty_credential_allowlist() {
        // `Only(&[])` admits nothing — it renders the action unreachable
        // while reading like a gate. Refused at registry compile so it fails
        // at startup, not in production traffic.
        let spec = AuthSpec::authenticated(CredentialGate::Only(&[]));
        assert!(spec.validate().is_err());
    }

    // --- CredentialGate semantics ---

    #[test]
    fn any_admits_every_channel_including_the_anonymous_caller() {
        let gate = CredentialGate::Any;
        assert!(gate.admits(None));
        assert!(gate.admits(Some(CredentialType::Session)));
        assert!(gate.admits(Some(CredentialType::ApiToken)));
        assert!(gate.admits(Some(CredentialType::DaemonToken)));
        assert!(gate.allowed().is_empty());
    }

    #[test]
    fn session_only_rejects_the_bearer_daemon_and_anonymous_callers() {
        let gate = CredentialGate::SESSION_ONLY;
        assert!(gate.admits(Some(CredentialType::Session)));
        assert!(!gate.admits(Some(CredentialType::ApiToken)));
        assert!(!gate.admits(Some(CredentialType::DaemonToken)));
        // No credential resolved is *not* admitted by a narrowed gate — the
        // reason `optional_identity` reads must stay `Any`.
        assert!(!gate.admits(None));
    }

    #[test]
    fn session_only_has_one_representation() {
        // The constant and the spelled-out form are the same value, so a
        // `==` comparison against either can't miss the other.
        assert_eq!(
            CredentialGate::SESSION_ONLY,
            CredentialGate::Only(&[CredentialType::Session]),
        );
    }

    #[test]
    fn validate_invariant_1_roles_imply_actor_required() {
        // roles declared but actor is only Optional → rejected.
        let spec = AuthSpec {
            account: AuthAxis::Required,
            actor: AuthAxis::Optional,
            roles: Some(ADMIN),
            credentials: CredentialGate::Any,
        };
        assert!(spec.validate().is_err());
    }

    #[test]
    fn validate_invariant_3_no_accountless_actors() {
        let spec = AuthSpec {
            account: AuthAxis::None,
            actor: AuthAxis::Required,
            roles: None,
            credentials: CredentialGate::Any,
        };
        assert!(spec.validate().is_err());
    }

    #[test]
    fn validate_invariant_4_unrestricted_leaf_declares_no_gates() {
        let roled = AuthSpec {
            account: AuthAxis::None,
            actor: AuthAxis::None,
            roles: Some(ADMIN),
            credentials: CredentialGate::Any,
        };
        assert!(roled.validate().is_err());
        let cred_gated = AuthSpec {
            account: AuthAxis::None,
            actor: AuthAxis::None,
            roles: None,
            credentials: CredentialGate::Only(&[CredentialType::Session]),
        };
        assert!(cred_gated.validate().is_err());
    }

    // --- pre-authorization 401 ---

    #[test]
    fn pre_authz_401_only_when_account_required_and_absent() {
        // account/actor Required + no account → 401.
        assert!(
            check_action_auth_pre_authorization(
                &AuthSpec::authenticated(CredentialGate::Any),
                false
            )
            .is_some()
        );
        // account present → pass.
        assert!(
            check_action_auth_pre_authorization(
                &AuthSpec::authenticated(CredentialGate::Any),
                true
            )
            .is_none()
        );
        // public → never 401.
        assert!(check_action_auth_pre_authorization(&AuthSpec::public(), false).is_none());
        // optional axis without a credential → no 401 (the authz phase decides).
        assert!(
            check_action_auth_pre_authorization(
                &AuthSpec::optional_identity(CredentialGate::Any),
                false
            )
            .is_none()
        );
    }

    // --- post-authorization 403: the role gate runs over the RESOLVED actor ---

    #[test]
    fn role_gate_denies_anonymous_and_account_grain_contexts() {
        let spec = AuthSpec::authenticated_gated(CredentialGate::Any, ADMIN);
        // Anonymous has no actor → no role_grants → denied.
        let anon = check_action_auth_post_authorization(
            &spec,
            ResolvedAuthContext::Anonymous,
            None,
            M,
            None,
        )
        .expect("anonymous is denied a role-gated action");
        assert_eq!(reason(&anon), "insufficient_permissions");
        // Account-grain (actor: None) also carries no role_grants → denied.
        let acct = RequestContext { account: account() };
        let denied = check_action_auth_post_authorization(
            &spec,
            ResolvedAuthContext::Account(&acct),
            None,
            M,
            None,
        )
        .expect("account-grain context is denied a role-gated action");
        assert_eq!(reason(&denied), "insufficient_permissions");
    }

    #[test]
    fn role_gate_reads_the_resolved_actors_grants() {
        let spec = AuthSpec::authenticated_gated(CredentialGate::Any, ADMIN);
        // Resolved actor WITHOUT the role → denied.
        let non_admin = actor_ctx(&["editor"]);
        let denied = check_action_auth_post_authorization(
            &spec,
            ResolvedAuthContext::Actor(&non_admin),
            None,
            M,
            None,
        )
        .expect("a non-admin resolved actor is denied");
        assert_eq!(reason(&denied), "insufficient_permissions");
        // Resolved actor WITH the role → admitted.
        let admin = actor_ctx(&["admin"]);
        assert!(
            check_action_auth_post_authorization(
                &spec,
                ResolvedAuthContext::Actor(&admin),
                None,
                M,
                None
            )
            .is_none(),
            "an admin resolved actor passes the role gate"
        );
    }

    /// A **scoped** grant never satisfies a spec-level role: the spec names no
    /// scope, so only the global grant counts. A scoped `admin` (legacy data —
    /// no grant path mints one) is denied every admin-gated action, and the
    /// same holds for app roles.
    #[test]
    fn role_gate_requires_a_global_grant() {
        let scoped = |role: &str| RoleGrantRow {
            id: Uuid::nil(),
            actor_id: Uuid::nil(),
            role: role.to_owned(),
            scope_id: Some(Uuid::from_u128(7)),
        };
        let check = |roles: &'static [&'static str], ctx: &RequestActorContext| {
            check_action_auth_post_authorization(
                &AuthSpec::authenticated_gated(CredentialGate::Any, roles),
                ResolvedAuthContext::Actor(ctx),
                None,
                M,
                None,
            )
        };

        let mut scoped_admin = actor_ctx(&[]);
        scoped_admin.role_grants.push(scoped("admin"));
        let denied = check(ADMIN, &scoped_admin).expect("a scoped admin is denied");
        assert_eq!(reason(&denied), "insufficient_permissions");

        let mut scoped_app = actor_ctx(&[]);
        scoped_app.role_grants.push(scoped("teacher"));
        assert!(
            check(&["teacher"], &scoped_app).is_some(),
            "a scoped app role doesn't satisfy a spec-level role"
        );
        assert!(
            check(&["teacher"], &actor_ctx(&["teacher"])).is_none(),
            "the global app-role grant does"
        );

        // A global grant beside a scoped one still admits — the scoped row
        // neither helps nor hurts.
        let mut both = actor_ctx(&["admin"]);
        both.role_grants.push(scoped("admin"));
        assert!(check(ADMIN, &both).is_none());
    }

    #[test]
    fn credential_gate_runs_before_role_gate() {
        // Spec gates BOTH credential type (daemon-token) and role (admin).
        let spec = AuthSpec::authenticated_gated(
            CredentialGate::Only(&[CredentialType::DaemonToken]),
            ADMIN,
        );
        // Caller is a fully-admin actor but arrived on the wrong credential — the
        // credential gate fires first, so the reason is credential, not role.
        let admin = actor_ctx(&["admin"]);
        let denied = check_action_auth_post_authorization(
            &spec,
            ResolvedAuthContext::Actor(&admin),
            Some(CredentialType::Session),
            M,
            None,
        )
        .expect("wrong credential is denied even when the role would pass");
        assert_eq!(reason(&denied), "credential_type_required");
    }

    // --- post-authorization 403: the token-scope gate ---

    fn narrow(methods: &[&str]) -> TokenScope {
        TokenScope::Methods(methods.iter().map(|m| (*m).to_owned()).collect())
    }

    #[test]
    fn scope_gate_denies_a_method_the_token_does_not_list() {
        let spec = AuthSpec::authenticated(CredentialGate::Any);
        let actor = actor_ctx(&[]);
        let scope = narrow(&["cell_get"]);
        // Listed → admitted.
        assert!(
            check_action_auth_post_authorization(
                &spec,
                ResolvedAuthContext::Actor(&actor),
                Some(CredentialType::ApiToken),
                "cell_get",
                Some(&scope),
            )
            .is_none()
        );
        // Unlisted → denied, with the capability string naming what was needed.
        let denied = check_action_auth_post_authorization(
            &spec,
            ResolvedAuthContext::Actor(&actor),
            Some(CredentialType::ApiToken),
            "cell_create",
            Some(&scope),
        )
        .expect("an unlisted method is denied");
        assert_eq!(reason(&denied), "token_scope_required");
        assert_eq!(
            denied
                .data
                .as_ref()
                .and_then(|d| d.get("required_scope"))
                .and_then(serde_json::Value::as_str),
            Some("rpc:cell_create"),
        );
    }

    #[test]
    fn full_scope_and_anonymous_are_unconstrained_by_the_scope_gate() {
        let spec = AuthSpec::authenticated(CredentialGate::Any);
        let actor = actor_ctx(&[]);
        assert!(
            check_action_auth_post_authorization(
                &spec,
                ResolvedAuthContext::Actor(&actor),
                Some(CredentialType::Session),
                "anything",
                Some(&TokenScope::Full),
            )
            .is_none()
        );
        // `None` is the anonymous caller — no credential, so nothing to narrow.
        // It must not be read as a permissive default for a *bearer* caller:
        // every resolved credential carries a scope, so `None` here can only
        // mean anonymous.
        assert!(
            check_action_auth_post_authorization(
                &AuthSpec::public(),
                ResolvedAuthContext::Anonymous,
                None,
                "anything",
                None,
            )
            .is_none()
        );
    }

    /// Gate order is credential → scope → role, and each step shadows the ones
    /// after it. Pinned because the order is a wire-compatibility contract, not
    /// just a preference: a scoped bearer hitting a session-only spec must keep
    /// returning `credential_type_required`, or the cross-backend conformance
    /// cases start asserting the wrong denial.
    #[test]
    fn gate_order_is_credential_then_scope_then_role() {
        let admin = actor_ctx(&["admin"]);
        let scope = narrow(&["something_else"]);

        // Credential gate shadows the scope gate: wrong channel *and* unlisted
        // method → the credential reason, because the channel fact is coarser
        // and telling this caller which scope it lacks would confirm an
        // endpoint no bearer may ever reach.
        let spec = AuthSpec::authenticated_gated(CredentialGate::SESSION_ONLY, ADMIN);
        let denied = check_action_auth_post_authorization(
            &spec,
            ResolvedAuthContext::Actor(&admin),
            Some(CredentialType::ApiToken),
            "role_grant_assign",
            Some(&scope),
        )
        .expect("wrong credential is denied");
        assert_eq!(reason(&denied), "credential_type_required");

        // Scope gate shadows the role gate: right channel, unlisted method, and
        // an actor that would fail the role check → the scope reason, so an
        // under-scoped token learns nothing about the role structure.
        let spec = AuthSpec::authenticated_gated(CredentialGate::Any, ADMIN);
        let non_admin = actor_ctx(&["editor"]);
        let denied = check_action_auth_post_authorization(
            &spec,
            ResolvedAuthContext::Actor(&non_admin),
            Some(CredentialType::ApiToken),
            "role_grant_assign",
            Some(&scope),
        )
        .expect("an unlisted method is denied before the role check");
        assert_eq!(reason(&denied), "token_scope_required");

        // ...and with the method listed, the role gate is reached normally.
        let listed = narrow(&["role_grant_assign"]);
        let denied = check_action_auth_post_authorization(
            &spec,
            ResolvedAuthContext::Actor(&non_admin),
            Some(CredentialType::ApiToken),
            "role_grant_assign",
            Some(&listed),
        )
        .expect("a listed method still faces the role gate");
        assert_eq!(reason(&denied), "insufficient_permissions");
    }

    /// A narrowed token is not a way around a credential gate: listing a
    /// session-only method in a token's scope does not make it callable over
    /// bearer. The two controls compose as an intersection, never a union.
    #[test]
    fn scope_cannot_widen_a_credential_gate() {
        let spec = AuthSpec::account_grain(CredentialGate::SESSION_ONLY);
        let acct = RequestContext { account: account() };
        let scope = narrow(&["account_token_create"]);
        let denied = check_action_auth_post_authorization(
            &spec,
            ResolvedAuthContext::Account(&acct),
            Some(CredentialType::ApiToken),
            "account_token_create",
            Some(&scope),
        )
        .expect("naming a session-only method in a scope does not unlock it");
        assert_eq!(reason(&denied), "credential_type_required");
    }

    #[test]
    fn credential_gate_admits_matching_credential() {
        let spec = AuthSpec::authenticated(CredentialGate::Only(&[CredentialType::Session]));
        let any = actor_ctx(&[]);
        assert!(
            check_action_auth_post_authorization(
                &spec,
                ResolvedAuthContext::Actor(&any),
                Some(CredentialType::Session),
                M,
                None,
            )
            .is_none(),
            "a matching credential with no role gate passes"
        );
    }
}

/// The `CredentialGate::Any` census over every `fuz_auth`-owned registry.
///
/// `Any` is a decision, but it's a decision spread across six files and
/// invisible unless you grep for it. This test is where the whole permissive
/// surface is readable at once — which is what makes it reviewable, and what
/// makes *widening* it (a new spec, or a new [`CredentialType`] that `Any`
/// silently admits) a diff someone has to look at.
///
/// Entries here are not defects. They record that an API token may drive the
/// action, which is correct for admin scripting and for the reads. Moving one
/// out of this list is the narrowing pass; moving one *in* should be argued.
#[cfg(test)]
mod any_credential_surface {
    use crate::auth_action_entry::{AUTH_ACTION_ENTRY_REGISTRIES, AuthActionEntry};

    fn every_registry() -> Vec<&'static AuthActionEntry> {
        AUTH_ACTION_ENTRY_REGISTRIES.into_iter().flatten().collect()
    }

    /// Every **mutation** an API token may drive.
    ///
    /// Two groups, and the distinction is the point of keeping the list:
    ///
    /// - **Deliberate.** The `admin_*` / `invite_*` / `app_settings_update`
    ///   rows exist because `fuz_app/docs/security.md` records that "admin
    ///   scripting from CLI/bearer is legitimate operator workflow" —
    ///   narrowing them breaks the operator path the gate exists to serve.
    /// - **Reviewed and left `Any`.** `role_grant_assign` / `role_grant_revoke`
    ///   are admin-role-gated *and* plausible operator scripting — an operator
    ///   who wants a CLI to assign roles mints a token scoped to
    ///   `rpc:role_grant_assign` rather than widening the spec — scoping a
    ///   token narrows, widening a spec would loosen every caller.
    ///   `role_grant_offer_decline` / `_retract` destroy a pending offer and
    ///   confer nothing.
    ///
    /// The verbs that confer a role on a consent act — `role_grant_offer_create`
    /// (the grantor's), `role_grant_offer_accept` and `self_service_role_set`
    /// (the caller's own authority) — are session-only and live in the gated
    /// set below. `account_delete` stays
    /// `Any` for an admin deleting another account; its self path is
    /// session-only in the handler.
    #[test]
    fn any_credential_mutations_are_the_expected_set() {
        let mut methods: Vec<&str> = every_registry()
            .into_iter()
            .filter(|e| e.auth.credentials.is_any() && e.side_effects)
            .map(|e| e.method)
            .collect();
        methods.sort_unstable();
        assert_eq!(
            methods,
            [
                "account_delete",
                "account_undelete",
                "admin_session_revoke_all",
                "admin_token_revoke_all",
                "app_settings_update",
                "invite_create",
                "invite_delete",
                "role_grant_assign",
                "role_grant_offer_decline",
                "role_grant_offer_retract",
                "role_grant_revoke",
            ],
        );
    }

    /// The gated complement — every method that is *not* reachable by any
    /// credential. Small by design; growing it is the narrowing pass.
    ///
    /// Two groups, both anti-pivot: the credential-lifecycle mutations (a
    /// leaked token can't mint another, revoke one, or kill a session) and the
    /// consent verbs that confer a role — offering one to another account
    /// (`role_grant_offer_create`) and moving the caller's *own* authority
    /// (`role_grant_offer_accept` / `self_service_role_set`). `account_purge`
    /// is the daemon-token/keeper outlier — see
    /// `admin_action_specs::account_purge_is_the_only_daemon_token_gated_spec`.
    #[test]
    fn gated_methods_are_the_expected_set() {
        let mut methods: Vec<&str> = every_registry()
            .into_iter()
            .filter(|e| !e.auth.credentials.is_any())
            .map(|e| e.method)
            .collect();
        methods.sort_unstable();
        assert_eq!(
            methods,
            [
                "account_purge",
                "account_session_revoke",
                "account_session_revoke_all",
                "account_token_create",
                "account_token_revoke",
                "role_grant_offer_accept",
                "role_grant_offer_create",
                "self_service_role_set",
            ],
        );
    }
}
