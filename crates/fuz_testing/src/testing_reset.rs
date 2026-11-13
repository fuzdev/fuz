//! `_testing_reset` action — full DB wipe + keeper re-seed.
//!
//! The cross-backend test binaries — `testing_spine_stub` and the spine
//! consumers' `testing_*` servers — register the action returned by
//! [`create_testing_reset_action_spec`] on their `ActionRegistry`.
//! Every cross-process per-test setup fires `_testing_reset` over the
//! keeper's daemon-token credential before the test body runs — this
//! converges in-process and cross-process keeper lifetimes so the
//! standard integration suites work uniformly across both transports.
//!
//! Reset semantics:
//!
//! 1. Fire the consumer-supplied `reset_state` callback for domain-state
//!    reset (zzz clears workspaces + terminals + scoped FS; the DB consumers
//!    empty their cell, fact, and domain tables). It runs first, while the
//!    previous test's accounts and actors still exist: domain rows depend on
//!    auth rows, so a domain table with a restricting FK to `actor` or
//!    `account` (no `ON DELETE` action) is emptied before the auth wipe
//!    deletes the rows it references.
//! 2. Wipe every auth-namespace row (no keeper-preserve filter).
//!    Mutation-cascade tests (password change, revoke-all) + hardcoded-
//!    username signup-uniqueness tests can't pollute siblings.
//! 3. Reset `app_settings` singleton row to production defaults.
//! 4. Flip `bootstrap_lock.bootstrapped = true` (final post-bootstrap state).
//! 5. Inline-seed the fresh keeper: account + actor + `role_grants`
//!    (`[ROLE_KEEPER, ROLE_ADMIN, ...extra_keeper_roles]`) + `api_token` +
//!    signed session cookie. Mirrors the production `bootstrap_handler`
//!    write set in `fuz_auth::bootstrap`.
//! 6. Queue the `DaemonTokenState.keeper_account_id` refresh as a
//!    post-commit effect, as soon as the keeper exists, so daemon-token auth
//!    resolves the freshly seeded keeper on subsequent calls once the reset
//!    commits — and a reset that rolls back at any later point (a failing
//!    extra seed, a failed `COMMIT`) leaves the previous (still present)
//!    keeper cached.
//! 7. Inline-seed any caller-requested `extra_accounts` (used by tests
//!    probing the keeper-vs-admin separation that need a non-admin
//!    keeper-only account — `ROLE_KEEPER`'s `grant_paths` is
//!    bootstrap-only, so the only way to grant it to a non-bootstrap
//!    account is at this same setup step).
//! 8. Inline-seed any caller-requested `extra_actors` on the keeper
//!    account, beyond its single bootstrap actor, in order. No
//!    production wire path mints a second actor, so this bootstrap-
//!    cradle insert is the only way into the multi-actor `acting`
//!    branches (omitted `acting` + >1 actor ⇒ `actor_required`). Same
//!    rationale as `extra_accounts`.
//!
//! Mirrors `fuz_app`'s `testing/cross_backend/testing_reset_actions.ts`.
//! Both spines run against a freshly bootstrapped keeper per test.
//!
//! **No free-form runtime bypass.** Earlier drafts considered a separate
//! `_testing_seed_role_grant` action for arbitrary direct grants; that
//! was rejected because a runtime bypass would let tests skip the
//! production consent flow's side-effects (audit emit, WS fan-out) and
//! silently mask bugs in those paths. The bypass that does exist —
//! `extra_accounts` — is framed as bootstrap-time seeding, the same
//! shape `bootstrap_handler` itself uses to grant the initial
//! `KEEPER` + `ADMIN` pair. Tests that want a role on a *post-bootstrap*
//! account route through `role_grant_offer_create` +
//! `role_grant_offer_accept` (the production path).
//!
//! Production safety: this module lives in `fuz_testing`, which
//! `cargo xtask check-release` blocks from entering production dep
//! graphs.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use fuz_actions::{ActionContext, ActionHandler, ActionSpec};
use fuz_auth::account_queries::query_create_account;
use fuz_auth::actor_queries::{
    query_create_actor, query_create_actor_with_clock_timestamp, query_create_role_grant,
};
use fuz_auth::api_token::generate_api_token;
use fuz_auth::api_token_queries::query_create_api_token;
use fuz_auth::keyring::Keyring;
use fuz_auth::password_hasher::PasswordHasher;
use fuz_auth::session_cookie::sign_session_cookie;
use fuz_auth::session_queries::create_capped_session;
use fuz_auth::token_scope::TokenScopeDocument;
use fuz_auth::{ROLE_ADMIN, ROLE_KEEPER, SharedDaemonTokenState};
use fuz_db::{ActionDb, action_db_dispatch};
use fuz_http::{InputShape, JsonrpcError, internal_error_with_source, invalid_input_params};
use serde_json::{Value, json};

/// The canonical test password the in-process + cross-process harnesses
/// share. Mirrors TS `DEFAULT_TEST_PASSWORD` so a future divergence
/// becomes a typecheck or runtime mismatch in the suite, not a silent
/// 401.
const DEFAULT_TEST_PASSWORD: &str = "test-password-123";

/// Type-erased reset-state callback future, borrowing the reset
/// transaction for `'a`.
///
/// Returns a boxed future so concrete async closures can be stored
/// behind a trait object without naming the future type. The future is
/// `+ 'a` so a consumer can hold the handed-in [`ActionDb`] across
/// `await` points (e.g. a `TRUNCATE` inside the reset transaction). The
/// `Result<(), JsonrpcError>` payload lets a fallible consumer reset
/// bubble up through the RPC dispatcher as a JSON-RPC error.
pub type BoxFutureResetResult<'a> =
    Pin<Box<dyn Future<Output = Result<(), JsonrpcError>> + Send + 'a>>;

/// Consumer-supplied closure invoked first, before the auth-table wipe and
/// keeper re-seed, handed the **reset transaction's** [`ActionDb`].
///
/// DB-domain consumers (e.g. one truncating its cell / fact tables) run their
/// domain reset on this same in-tx handle so the wipe and re-seed commit or
/// roll back atomically — mirrors the TS `reset_state(db)` shape. In-memory
/// consumers (zzz: workspaces + terminals + scratch) ignore the handle.
///
/// It runs while the previous test's accounts and actors still exist, so a
/// domain table holding a restricting FK to `actor` / `account` empties before
/// the auth wipe deletes what it references. The callback must not depend on
/// the fresh keeper: it doesn't exist yet.
///
/// `Send + Sync` because the closure is stored inside an `Arc<dyn Fn>`
/// shared across handler invocations. Concurrent reset calls each
/// construct a fresh future; the implementation must be safe to call
/// multiple times. Infallible consumers return `Ok(())`.
pub type ResetStateFn = Arc<dyn for<'a> Fn(ActionDb<'a>) -> BoxFutureResetResult<'a> + Send + Sync>;

/// Runtime state the reset action needs to seed credentials. Threaded
/// from the test binary's server-assembly site (`testing_zzz_server`,
/// etc.) so this crate never re-creates the production shapes.
#[expect(
    missing_debug_implementations,
    reason = "Arc-of-dyn fields don't auto-derive `Debug`"
)]
pub struct TestingResetOptions {
    /// Password hasher — the same instance the live server signs+verifies
    /// with. Production swaps in `Argon2idHasher`; the test binary uses
    /// [`crate::TestingArgon2idHasher`] for the ~1-5 ms argon2 fast path.
    pub password_hasher: Arc<dyn PasswordHasher>,
    /// Keyring used for signing the fresh keeper's (and extra accounts')
    /// session cookies. Same instance the live server uses for
    /// `account_login` cookies.
    pub keyring: Arc<Keyring>,
    /// Daemon-token runtime state — `keeper_account_id` is pointed at the
    /// freshly seeded keeper once a reset commits; a reset that rolls back
    /// leaves it unchanged.
    pub daemon_token_state: SharedDaemonTokenState,
    /// Per-app session cookie name (default
    /// [`fuz_auth::SESSION_COOKIE_NAME`]) — the seeded keeper/extra
    /// session cookies are signed under this name + the `name=` prefix
    /// stripped from the returned value, so the harness threads the cookie
    /// into its jar under the same name the live server reads.
    pub session_cookie_name: &'static str,
    /// Domain-state reset callback. `None` for binaries with no
    /// in-memory domain state.
    pub reset_state: Option<ResetStateFn>,
}

/// Build the `_testing_reset` RPC action spec for a test binary's
/// registry.
///
/// The returned spec has `side_effects: true` so the dispatcher wraps
/// the handler in a transaction; the wipe + re-seed commits or rolls
/// back together, ruling out partial-reset states under failure.
#[must_use]
pub fn create_testing_reset_action_spec(options: TestingResetOptions) -> ActionSpec {
    let TestingResetOptions {
        password_hasher,
        keyring,
        daemon_token_state,
        session_cookie_name,
        reset_state,
    } = options;

    let handler: ActionHandler = Arc::new(move |params: Value, ctx: ActionContext<'_>| {
        let password_hasher = Arc::clone(&password_hasher);
        let keyring = Arc::clone(&keyring);
        let daemon_token_state = Arc::clone(&daemon_token_state);
        let reset_state = reset_state.as_ref().map(Arc::clone);

        Box::pin(async move {
            fuz_http::reject_unknown_keys(&params, TESTING_RESET_KEYS)?;
            // Every declared field is `optional(...)` on the twin, so an
            // explicit `null` is refused rather than read as absent.
            fuz_http::reject_null_keys(&params, TESTING_RESET_KEYS)?;
            let extra_keeper_roles: Vec<String> =
                parse_string_array(&params, "extra_keeper_roles")?;

            // Additional actor names to seed on the keeper. Always parsed
            // (defaults to empty); the output always carries an
            // `extra_actors` array, matching the TS wire contract's
            // required field.
            let extra_actor_names: Vec<String> = parse_string_array(&params, "extra_actors")?;

            let extra_account_specs: Vec<ExtraAccountSpec> = match params.get("extra_accounts") {
                None => Vec::new(),
                Some(Value::Array(arr)) => arr
                    .iter()
                    .map(ExtraAccountSpec::from_value)
                    .collect::<Result<Vec<_>, _>>()?,
                Some(_) => {
                    return Err(invalid_input("`extra_accounts` must be an array"));
                }
            };

            tracing::info!("[_testing_reset] wiping domain + auth state + re-seeding keeper");

            // 1. Fire domain-state reset (zzz workspaces/terminals/scratch, a
            //    DB consumer's cell/fact/domain truncation) on the reset
            //    transaction's handle, so it commits or rolls back with the
            //    auth wipe. First, because domain rows depend on auth rows: a
            //    domain table with a restricting FK to `actor` would make the
            //    auth wipe below fail once it holds a row.
            if let Some(reset_state) = reset_state {
                reset_state(ctx.db.clone()).await?;
            }

            // 2. Wipe every auth-namespace row (no keeper-preserve
            //    filter), in the const's FK-respecting order.
            for table in fuz_auth::AUTH_INTEGRATION_TRUNCATE_TABLES {
                let sql = format!("DELETE FROM {table}");
                ctx.db
                    .execute(&sql, &[])
                    .await
                    .map_err(|e| internal_error_with_source(&sql, &e))?;
            }

            // 3. Reset `app_settings` singleton row to production defaults.
            ctx.db
                .execute(
                    "UPDATE app_settings SET open_signup = false, updated_at = NULL, updated_by = NULL \
                     WHERE open_signup = true OR updated_at IS NOT NULL",
                    &[],
                )
                .await
                .map_err(|e| internal_error_with_source("UPDATE app_settings", &e))?;

            // 4. Flip `bootstrap_lock` to post-bootstrap shape. The
            //    in-process counterpart (`bootstrap_test_keeper`) does the
            //    same; the seed below leaves the system in
            //    `bootstrapped = true` state.
            ctx.db
                .execute(
                    "UPDATE bootstrap_lock SET bootstrapped = true WHERE id = 1",
                    &[],
                )
                .await
                .map_err(|e| internal_error_with_source("UPDATE bootstrap_lock", &e))?;

            // 5–8. Seed the fresh keeper, queue the daemon-token cache
            //    refresh, then seed any extra accounts and extra keeper
            //    actors, all on the same DB handle. Keeper roles default to
            //    `[ROLE_KEEPER, ROLE_ADMIN]` to match production
            //    `bootstrap_handler`; `extra_keeper_roles` adds on top.
            //
            //    6. The cache refresh is a post-commit effect, queued as soon
            //    as the keeper exists, so subsequent daemon-token requests
            //    resolve the new keeper only once the reset commits: a reset
            //    that rolls back after it (a failing extra seed, a failed
            //    `COMMIT`) leaves the cache on the keeper still in the
            //    database rather than one that never landed, and the next
            //    reset can still authenticate.
            //
            //    The dispatch on `ctx.db` exists only to forward the
            //    concrete `&GenericClient` into `seed_keeper_plus_extras`
            //    — the seeding body is generic over that handle, so a
            //    single source body monomorphizes per concrete client
            //    type (same pattern `auth_adapter::AuthActionFamily::dispatch`
            //    uses to bridge dynamic-variant dispatch into generic
            //    family-level handlers).
            let keeper_roles: Vec<String> = std::iter::once(ROLE_KEEPER.to_owned())
                .chain(std::iter::once(ROLE_ADMIN.to_owned()))
                .chain(extra_keeper_roles)
                .collect();
            let post_commit_effects = &ctx.post_commit_effects;
            let queue_keeper_cache_refresh = move |keeper_account_id: uuid::Uuid| {
                post_commit_effects.push_fn(move || async move {
                    daemon_token_state.write().keeper_account_id = Some(keeper_account_id);
                });
            };

            let result = action_db_dispatch!(
                ctx.db,
                client => seed_keeper_plus_extras(
                    client,
                    &password_hasher,
                    &keyring,
                    session_cookie_name,
                    &keeper_roles,
                    queue_keeper_cache_refresh,
                    &extra_account_specs,
                    &extra_actor_names,
                )
                .await?
            );

            let SeededKeeper {
                keeper,
                extras,
                extra_actors,
            } = result;
            let mut response = keeper.json;
            if let Value::Object(ref mut map) = response {
                map.insert("extra_accounts".to_owned(), Value::Array(extras));
                map.insert("extra_actors".to_owned(), Value::Array(extra_actors));
            }
            Ok(response)
        })
    });

    ActionSpec::with_side_effects(
        "_testing_reset",
        crate::TESTING_ACTION_AUTH,
        InputShape::Object,
        handler,
    )
}

/// Bundle returned by [`seed_keeper_plus_extras`]: the keeper's
/// seeded row (JSON + typed `AccountRow`) plus any seeded extras' JSON. Local to this module —
/// the wrapper exists so the handler's `ActionDb` dispatch can return a
/// single concrete type into the outer closure regardless of which generic
/// client the helper monomorphized against.
struct SeededKeeper {
    keeper: SeededAccount,
    extras: Vec<Value>,
    /// The keeper's additional actors (from input `extra_actors`), in
    /// order. JSON `{ "id": <uuid>, "name": <string> }` objects matching
    /// the TS `array(object({id: Uuid, name: string}))` output shape. Empty when none were requested.
    extra_actors: Vec<Value>,
}

/// The refusal of a malformed `_testing_reset` input field.
///
/// The input fields (`extra_keeper_roles`, `extra_actors`, `extra_accounts`)
/// all reject malformed values rather than silently coercing, matching the TS
/// schema's strictness. The twin refuses them at its schema step, so the
/// wire carries the generic reason-less `invalid params`
/// ([`invalid_input_params`]); `detail` goes to the debug log.
fn invalid_input(detail: &str) -> JsonrpcError {
    invalid_input_params(detail, None)
}

/// Declared input keys — the exact key set of the TS twin's
/// `testing_reset_action_spec.input` strict object. All three are
/// `optional(array(...))`, so the same list serves as the non-nullable set.
const TESTING_RESET_KEYS: &[&str] = &["extra_keeper_roles", "extra_accounts", "extra_actors"];

/// Parse an optional JSON params field as an ordered array of strings.
///
/// Absent → empty vec: the field is optional on the wire
/// (`extra_*: optional(array(string))`), which admits a missing key
/// and nothing else. A present value that isn't an array — JSON `null`
/// included — or an array holding a non-string element is a malformed call
/// → loud [`invalid_input`], matching the TS schema's rejection rather
/// than silently coercing. (The handler's `reject_null_keys` walk refuses a
/// `null` before this runs.) Shared by the `extra_keeper_roles` and
/// `extra_actors` inputs — both plain ordered string lists.
fn parse_string_array(params: &Value, key: &str) -> Result<Vec<String>, JsonrpcError> {
    let Some(value) = params.get(key) else {
        return Ok(Vec::new());
    };
    let Some(arr) = value.as_array() else {
        return Err(invalid_input(&format!(
            "`{key}` must be an array of strings"
        )));
    };
    arr.iter()
        .enumerate()
        .map(|(i, v)| {
            v.as_str()
                .map(str::to_owned)
                .ok_or_else(|| invalid_input(&format!("`{key}[{i}]` must be a string")))
        })
        .collect()
}

/// Parsed shape of one `extra_accounts` entry in the action input.
struct ExtraAccountSpec {
    username: String,
    password_value: Option<String>,
    roles: Vec<String>,
}

/// Declared keys of one `extra_accounts` entry — the TS twin's strict object.
const EXTRA_ACCOUNT_KEYS: &[&str] = &["username", "password_value", "roles"];

impl ExtraAccountSpec {
    /// Parse one `extra_accounts` entry strictly, mirroring the TS twin's
    /// strict `object({username, password_value?, roles})`: an undeclared key,
    /// a missing `username`/`roles`, or a non-string anywhere, is a malformed
    /// call → loud [`invalid_input`] rather than a silently-dropped entry
    /// (which would seed fewer accounts than the fixture asked for).
    fn from_value(v: &Value) -> Result<Self, JsonrpcError> {
        fuz_http::reject_unknown_keys(v, EXTRA_ACCOUNT_KEYS)?;
        let username = v
            .get("username")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid_input("`extra_accounts[].username` must be a string"))?
            .to_owned();
        // `password_value` is optional (TS `optional(string)`): absent → None,
        // a present non-string — `null` included — → reject.
        let password_value = match v.get("password_value") {
            None => None,
            Some(Value::String(s)) => Some(s.clone()),
            Some(_) => {
                return Err(invalid_input(
                    "`extra_accounts[].password_value` must be a string",
                ));
            }
        };
        let roles = v
            .get("roles")
            .and_then(Value::as_array)
            .ok_or_else(|| invalid_input("`extra_accounts[].roles` must be an array of strings"))?
            .iter()
            .enumerate()
            .map(|(i, r)| {
                r.as_str().map(str::to_owned).ok_or_else(|| {
                    invalid_input(&format!("`extra_accounts[].roles[{i}]` must be a string"))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            username,
            password_value,
            roles,
        })
    }
}

/// Output of `seed_account` — JSON for the action response plus the
/// original `AccountRow` for downstream daemon-token-cache refresh
/// (so we don't re-parse the UUID from JSON).
struct SeededAccount {
    json: Value,
    account: fuz_auth::account_schema::AccountRow,
}

/// Seed a single account (keeper or extra) inline. Mirrors
/// `fuz_app`'s `create_test_account_with_credentials` write set so
/// in-process and cross-process keeper rows are structurally identical,
/// the username lowercased as every creation path stores it (the
/// `account_username_lowercase` CHECK requires it).
async fn seed_account<C>(
    db: &C,
    password_hasher: &Arc<dyn PasswordHasher>,
    keyring: &Arc<Keyring>,
    cookie_name: &str,
    username: &str,
    password: &str,
    roles: &[String],
) -> Result<SeededAccount, JsonrpcError>
where
    C: deadpool_postgres::GenericClient + ?Sized,
{
    let password_hash = password_hasher
        .hash(password.to_owned())
        .await
        .map_err(|e| internal_error_with_source("hash_password", &e))?;

    let username = username.to_lowercase();
    let account = query_create_account(db, &username, password_hash.as_str())
        .await
        .map_err(|e| internal_error_with_source("query_create_account", &e))?;
    let actor = query_create_actor(db, &account.id, &username)
        .await
        .map_err(|e| internal_error_with_source("query_create_actor", &e))?;

    for role in roles {
        query_create_role_grant(db, &actor.id, role, None, None, None, None)
            .await
            .map_err(|e| internal_error_with_source("query_create_role_grant", &e))?;
    }

    // API token: stored hash, returned raw to the caller.
    //
    // Seeded `TokenScope::Full` so the harness's `as: 'token'` credential keeps
    // the reach it had before scoping existed — the cross-backend conformance
    // cases assert `credential_type_required` on the session-only specs, and a
    // narrowed seed would make them fail on the scope gate instead, testing the
    // wrong thing. Suites that want a narrowed token mint one explicitly.
    let api_token = generate_api_token();
    let scope_json = TokenScopeDocument::full()
        .to_json()
        .map_err(|e| internal_error_with_source("token scope serialize", &e))?;
    query_create_api_token(
        db,
        &api_token.id,
        &account.id,
        "test-cli",
        &api_token.token_hash,
        &scope_json,
        None, // eternal — the cradle credential mirrors fuz_app's test mint
    )
    .await
    .map_err(|e| internal_error_with_source("query_create_api_token", &e))?;

    // Session: insert hash, sign cookie value for the caller. Routed through
    // the same minter production uses (`create_capped_session`) so the cradle's
    // write set can't drift from the real one — which is this helper's stated
    // job, per the fn doc above.
    // The account was created above in this same call, so the cap evicts
    // nothing and there are no connections to close.
    let session_token = create_capped_session(db, &account.id)
        .await
        .map_err(|e| internal_error_with_source("create_capped_session", &e))?
        .into_token_for_new_account();
    let signed_cookie = sign_session_cookie(keyring, &session_token, cookie_name);
    // `sign_session_cookie` returns the full `Set-Cookie` header value;
    // strip the `name=` prefix and trailing attributes so the response
    // carries just the signed VALUE (TS callers thread the value into
    // their own cookie jar). Format: `<cookie_name>=<value>; Path=...`.
    let prefix = format!("{cookie_name}=");
    let after_prefix = signed_cookie
        .strip_prefix(&prefix)
        .unwrap_or(&signed_cookie);
    let cookie_value = after_prefix
        .split(';')
        .next()
        .unwrap_or(after_prefix)
        .to_owned();

    let json = json!({
        "account": {"id": account.id, "username": account.username.clone()},
        "actor": {"id": actor.id},
        "api_token": api_token.token,
        "session_cookie": cookie_value,
    });
    Ok(SeededAccount { json, account })
}

/// Seed the fresh keeper plus any caller-requested extra accounts on a
/// single DB handle. Returns the `SeededKeeper` bundle the action
/// handler closes over.
///
/// `on_keeper_seeded` runs with the keeper's account id right after the
/// keeper is seeded and before any extra — the handler queues its
/// post-commit daemon-token cache refresh there, so every later failure
/// rolls back a reset whose refresh is already queued (and so never runs).
///
/// Generic over `C: GenericClient` so the handler's `ActionDb` match
/// can forward `*t` (Transaction) or `*c` (`PoolClient`) into one
/// source body; Cargo monomorphizes per concrete type at the call sites,
/// matching the inline-duplication shape this helper replaced without
/// the two-arm source cost.
#[expect(
    clippy::too_many_arguments,
    reason = "the seeding inputs plus the keeper-seeded hook; one private call site pair"
)]
async fn seed_keeper_plus_extras<C>(
    db: &C,
    password_hasher: &Arc<dyn PasswordHasher>,
    keyring: &Arc<Keyring>,
    cookie_name: &str,
    keeper_roles: &[String],
    on_keeper_seeded: impl FnOnce(uuid::Uuid),
    extra_specs: &[ExtraAccountSpec],
    extra_actor_names: &[String],
) -> Result<SeededKeeper, JsonrpcError>
where
    C: deadpool_postgres::GenericClient + ?Sized,
{
    let keeper = seed_account(
        db,
        password_hasher,
        keyring,
        cookie_name,
        "keeper",
        DEFAULT_TEST_PASSWORD,
        keeper_roles,
    )
    .await?;
    on_keeper_seeded(keeper.account.id);
    let mut extras: Vec<Value> = Vec::with_capacity(extra_specs.len());
    for spec in extra_specs {
        let pw = spec
            .password_value
            .as_deref()
            .unwrap_or(DEFAULT_TEST_PASSWORD);
        let seeded = seed_account(
            db,
            password_hasher,
            keyring,
            cookie_name,
            &spec.username,
            pw,
            &spec.roles,
        )
        .await?;
        extras.push(seeded.json);
    }

    // Seed any additional keeper actors. Same bootstrap-cradle bypass as
    // `extra_accounts` — no production wire path mints a second actor, so
    // the multi-actor `acting` branches need this direct insert. Order-
    // preserving so the fixture can address them positionally.
    //
    // Seed with `clock_timestamp()` (advances within the reset tx, unlike
    // the keeper actor's transaction-fixed `NOW()` default) so the keeper's
    // bootstrap actor sorts first and the extras sort in insert order —
    // `query_actors_by_account`'s `(created_at, id)` order stays stable, which
    // keeps the multi-actor `actor_required` `available` list snapshot-stable.
    let mut extra_actors: Vec<Value> = Vec::with_capacity(extra_actor_names.len());
    for name in extra_actor_names {
        let actor = query_create_actor_with_clock_timestamp(db, &keeper.account.id, name)
            .await
            .map_err(|e| internal_error_with_source("query_create_actor", &e))?;
        extra_actors.push(json!({"id": actor.id, "name": actor.name}));
    }

    Ok(SeededKeeper {
        keeper,
        extras,
        extra_actors,
    })
}

#[cfg(test)]
mod tests {
    use super::{ExtraAccountSpec, TESTING_RESET_KEYS, parse_string_array};
    use fuz_http::{INVALID_PARAMS_MESSAGE, JsonrpcErrorCode};
    use serde_json::json;

    #[test]
    fn parse_string_array_empty_when_key_absent() {
        let params = json!({});
        assert!(
            matches!(parse_string_array(&params, "extra_actors"), Ok(v) if v.is_empty()),
            "an absent key is the optional empty case",
        );
    }

    #[test]
    fn parse_string_array_rejects_null() {
        // The twin declares the field `optional(array(string))`, which admits an absent
        // key and nothing else — the handler's `reject_null_keys` walk refuses
        // a present `null` before this parser runs, and the parser itself
        // treats it as the non-array it is.
        let params = json!({"extra_actors": null});
        assert!(
            parse_string_array(&params, "extra_actors").is_err(),
            "a present null is not the optional empty case",
        );
        assert!(
            fuz_http::reject_null_keys(&params, TESTING_RESET_KEYS).is_err(),
            "the handler walk refuses it first",
        );
    }

    #[test]
    fn parse_string_array_rejects_non_array() {
        let params = json!({"extra_actors": "not-an-array"});
        assert!(
            parse_string_array(&params, "extra_actors").is_err(),
            "a present non-array must be rejected, not coerced",
        );
    }

    #[test]
    fn parse_string_array_rejects_non_string_element() {
        let params = json!({"extra_actors": ["alpha", 42, "beta"]});
        assert!(
            parse_string_array(&params, "extra_actors").is_err(),
            "a non-string element must be rejected, not silently dropped",
        );
    }

    #[test]
    fn parse_string_array_preserves_order() {
        let params = json!({"extra_actors": ["alpha", "beta", "gamma"]});
        assert_eq!(
            parse_string_array(&params, "extra_actors").ok(),
            Some(vec![
                "alpha".to_owned(),
                "beta".to_owned(),
                "gamma".to_owned()
            ]),
        );
    }

    #[test]
    fn extra_account_spec_parses_full_entry() {
        let v = json!({"username": "eve", "password_value": "pw", "roles": ["keeper", "admin"]});
        assert!(
            matches!(
                ExtraAccountSpec::from_value(&v),
                Ok(s) if s.username == "eve"
                    && s.password_value.as_deref() == Some("pw")
                    && s.roles.len() == 2
                    && s.roles[0] == "keeper"
                    && s.roles[1] == "admin"
            ),
            "a well-formed entry parses with all fields populated",
        );
    }

    #[test]
    fn extra_account_spec_password_optional() {
        let v = json!({"username": "eve", "roles": []});
        assert!(
            matches!(
                ExtraAccountSpec::from_value(&v),
                Ok(s) if s.password_value.is_none() && s.roles.is_empty()
            ),
            "password_value is optional and roles may be empty",
        );
    }

    #[test]
    fn extra_account_spec_rejects_missing_username() {
        let v = json!({"roles": ["keeper"]});
        assert!(ExtraAccountSpec::from_value(&v).is_err());
    }

    #[test]
    fn extra_account_spec_rejects_missing_roles() {
        let v = json!({"username": "eve"});
        assert!(ExtraAccountSpec::from_value(&v).is_err());
    }

    #[test]
    fn extra_account_spec_rejects_a_null_password_value() {
        // the twin's `optional(string)` admits an absent key and nothing else
        let v = json!({"username": "eve", "password_value": null, "roles": []});
        let error = ExtraAccountSpec::from_value(&v)
            .map(drop)
            .expect_err("a null password_value is refused, not read as absent");
        assert_eq!(error.code, JsonrpcErrorCode::InvalidParams);
    }

    #[test]
    fn extra_account_spec_rejects_an_unknown_key() {
        // the twin's entry is a strict object
        let v = json!({"username": "eve", "roles": [], "password": "pw"});
        let error = ExtraAccountSpec::from_value(&v)
            .map(drop)
            .expect_err("an undeclared key is refused");
        assert_eq!(error.code, JsonrpcErrorCode::InvalidParams);
        assert_eq!(error.message, INVALID_PARAMS_MESSAGE);
    }

    #[test]
    fn extra_account_spec_rejects_non_string_role() {
        let v = json!({"username": "eve", "roles": ["keeper", 7]});
        assert!(
            ExtraAccountSpec::from_value(&v).is_err(),
            "a non-string role must be rejected, not silently dropped",
        );
    }

    /// The twin refuses a malformed input field at its schema step, so every
    /// refusal is the generic `invalid params` with no `data.reason`.
    #[test]
    fn a_malformed_field_answers_the_generic_invalid_params() {
        let errors = [
            parse_string_array(&json!({"extra_keeper_roles": "x"}), "extra_keeper_roles"),
            parse_string_array(&json!({"extra_actors": [1]}), "extra_actors"),
        ]
        .into_iter()
        .map(|result| result.expect_err("a malformed string array is refused"))
        .chain([
            ExtraAccountSpec::from_value(&json!({"username": 1, "roles": []}))
                .map(drop)
                .expect_err("a non-string username is refused"),
            ExtraAccountSpec::from_value(&json!({"username": "eve", "roles": "x"}))
                .map(drop)
                .expect_err("a non-array roles is refused"),
        ]);
        for error in errors {
            assert_eq!(error.code, JsonrpcErrorCode::InvalidParams);
            assert_eq!(error.message, INVALID_PARAMS_MESSAGE);
            assert!(error.data.is_none(), "{error:?}");
        }
    }
}
