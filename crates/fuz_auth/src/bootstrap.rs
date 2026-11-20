//! Bootstrap — one-shot first-admin account creation.
//!
//! Mirrors `fuz_app`'s `bootstrap_account.ts` + `bootstrap_routes.ts`.
//! Reads a one-shot token from disk, then in one transaction flips the lock,
//! creates account + keeper + admin grants and the session, and burns the
//! token file last, just before the commit — a failed burn rolls it all back,
//! so a live token never outlives a successful bootstrap.
//!
//! ## `BootstrapOptions` callback
//!
//! The "set `daemon_token_state.keeper_account_id`" side effect is
//! consumer-specific — consumers without daemon-token state (headless
//! CLIs, future no-daemon-token deployments) skip it. The
//! [`BootstrapOptions::on_keeper_resolved`] callback lets consumers
//! plug in their daemon-token wiring without `fuz_auth` depending on
//! `SharedDaemonTokenState` directly; the canonical wiring is
//! [`crate::DaemonTokenKeeperResolved`]. Consumers without daemon-token
//! state leave it `None`.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use deadpool_postgres::Pool;
use fuz_db::commit_checked;
use fuz_sys::secure_file::BurnOutcome;
use serde::Deserialize;
use serde_json::json;
use subtle::ConstantTimeEq;

use crate::account_queries::query_create_account;
use crate::account_schema::AccountRow;
use crate::actor_queries::{query_create_actor, query_create_role_grant};
use crate::actor_schema::ActorRow;
use crate::audit_emitter::{AuditEmitter, AuditLogInput};
use crate::audit_event_type::AuditEventType;
use crate::bootstrap_keeper_resolved::BootstrapKeeperResolved;
use crate::bootstrap_token_store::{BootstrapTokenStore, read_bootstrap_token_file};
use crate::error::{BootstrapError, BootstrapErrorKind};
use crate::keyring::Keyring;
use crate::password_hasher::{HashedPassword, PasswordHasher};
use crate::rate_limiter::{RESERVATION_WAIT_MAX, RateLimiter, reserve_optional};
use crate::role::{ROLE_ADMIN, ROLE_KEEPER};
use crate::session_cookie::sign_session_cookie;
use crate::session_queries::create_capped_session;

// -- Input ----------------------------------------------------------------

/// `POST /bootstrap` body.
///
/// `deny_unknown_fields` mirrors the TS `BootstrapInput`, a strict
/// `fuz_schema` `object` (the canonical twin): an extra body key on this — the
/// highest-privilege, first-admin endpoint — fails deserialization rather than
/// being silently ignored, matching `SignupInput` / `LoginInput` and closing
/// the mass-assignment surface on future fields.
///
/// `Debug` redacts the token and the password.
#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct BootstrapInput {
    pub token: String,
    pub username: String,
    pub password: String,
}

impl std::fmt::Debug for BootstrapInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BootstrapInput")
            .field("token", &"<redacted>")
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .finish()
    }
}

/// Strip exactly one trailing `\n` from operator-written token bytes before the
/// constant-time compare.
///
/// NOT `trim()`: trimming is length-dependent (variable work) and would
/// undermine the `ct_eq` it precedes, and it would widen the set of accepted
/// token bytes. Tolerates the single trailing newline a POSIX editor appends;
/// anything else (a second newline, a trailing space, a leading newline) is
/// preserved and therefore fails the comparison — operators must write the
/// token bytes exactly.
fn strip_one_trailing_newline(mut bytes: Vec<u8>) -> Vec<u8> {
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
    }
    bytes
}

/// The fewest bytes a bootstrap token holds, counted after its one optional
/// trailing newline.
///
/// A shorter file reads as unreadable: an empty or `"\n"` file would
/// otherwise leave bootstrap advertised as open while nothing can ever match
/// it, and a short token is guessable. Every generator writes more (32 random
/// bytes as 64 lowercase hex characters); the readers accept any bytes that
/// clear this floor. Twin of `fuz_app`'s `BOOTSTRAP_TOKEN_MIN_BYTES`.
pub const BOOTSTRAP_TOKEN_MIN_BYTES: usize = 32;

/// The longest `token` the body takes, in UTF-16 code units.
///
/// Twin of `fuz_app`'s `BOOTSTRAP_TOKEN_LENGTH_MAX`, a `max_length`, which
/// counts `String.length`: the token file's cap, `fuz_sys`'s
/// `MAX_SECURE_FILE_SIZE` bytes. A token that can match the file is at most
/// that many bytes, and no more code units than bytes, so the bound refuses
/// none that could match. A longer one is a malformed body:
/// [`BootstrapErrorKind::InvalidInput`], refused before the window or the
/// token file is read, with no audit row.
pub const BOOTSTRAP_TOKEN_LENGTH_MAX: usize = 4096;

/// The token a file's bytes hold — less one trailing newline — or `None`
/// (logged as an error) when it is under [`BOOTSTRAP_TOKEN_MIN_BYTES`].
///
/// Shared by [`is_bootstrap_available`] and [`bootstrap_handler`], so the
/// availability check is exactly as strict as the request-time read. Twin of
/// `fuz_app`'s `read_bootstrap_token`.
fn bootstrap_token_from_file(bytes: Vec<u8>) -> Option<Vec<u8>> {
    let token = strip_one_trailing_newline(bytes);
    if token.len() < BOOTSTRAP_TOKEN_MIN_BYTES {
        tracing::error!(
            len = token.len(),
            min = BOOTSTRAP_TOKEN_MIN_BYTES,
            "bootstrap token rejected: shorter than the minimum — regenerate it"
        );
        return None;
    }
    Some(token)
}

/// Return value of [`bootstrap_handler`].
///
/// Carries the session — its raw token and its `Set-Cookie` line, signed
/// inside the bootstrap transaction — and the created account/actor rows; the
/// HTTP wrapper (`bootstrap_routes.rs`) builds the wire response from these.
/// `Debug` redacts the token and the cookie.
pub struct BootstrapSuccess {
    /// The raw session token (its hash is the `auth_session` row's id).
    pub session_token: String,
    /// The `Set-Cookie` line carrying the signed session cookie, written in
    /// the transaction. Twin of `fuz_app`'s `session_cookie_value`.
    pub set_cookie: String,
    pub account: AccountRow,
    pub actor: ActorRow,
}

impl std::fmt::Debug for BootstrapSuccess {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BootstrapSuccess")
            .field("session_token", &"<redacted>")
            .field("set_cookie", &"<redacted>")
            .field("account", &self.account)
            .field("actor", &self.actor)
            .finish()
    }
}

// -- Options --------------------------------------------------------------

/// Capabilities required by [`bootstrap_handler`].
///
/// `Clone` (every field is a handle) so the handler can move a copy onto the
/// task its write phase runs on.
#[derive(Clone)]
pub struct BootstrapOptions {
    /// `pool` for the bootstrap transaction.
    pub pool: Pool,
    /// Password hasher (Argon2id in production).
    pub password_hasher: Arc<dyn PasswordHasher>,
    /// Audit emitter. Only the legs reachable while the bootstrap window is
    /// open write a row — refusals outside it are deliberately silent, see
    /// [`bootstrap_handler`].
    pub audit: Arc<AuditEmitter>,
    /// Atomic flag flipped from `true` to `false` once the window closes —
    /// after the first successful bootstrap, or when the token file turns out
    /// to be unreadable and bootstrap therefore can't succeed. Read by
    /// `/api/account/status` so the frontend knows whether to show the
    /// bootstrap UI.
    pub bootstrap_available: Arc<AtomicBool>,
    /// One-shot bootstrap token store. `None` → bootstrap disabled; the
    /// handler answers `already_bootstrapped`, as the twin does with no token
    /// path, and writes no audit row. Production wires
    /// [`crate::FileBootstrapTokenStore`]; tests can supply an
    /// in-memory impl.
    pub token_store: Option<Arc<dyn BootstrapTokenStore>>,
    /// Optional callback fired after the keeper account is created.
    /// Consumers wire daemon-token state here.
    pub on_keeper_resolved: Option<Arc<dyn BootstrapKeeperResolved>>,
    /// Per-IP limiter on attempts inside the open window, keyed by the
    /// address's rate-limit key (an IPv6 client's `/64`); `None` turns it off
    /// (the testing binaries, as the twin's test spine). Its own instance, not
    /// login's, so a fumbled token can't spend the operator's login budget.
    /// The token is 32 bytes of CSPRNG compared in constant time, so guessing
    /// is not what it bounds: the `invalid_token` leg writes an unauthenticated
    /// `audit_log` row and leaves the window open (a wrong token must not lock
    /// the operator out), so without a limiter that leg is an unbounded write
    /// channel for as long as the window is open. A refused attempt, a wrong
    /// token or an unreadable or undeletable token file, is charged (an
    /// undeletable one only while its request is still waiting on the write
    /// task); the lock-race loser and a success are not. Twin of `fuz_app`'s
    /// `BootstrapRouteOptions.bootstrap_ip_rate_limiter`, at the same default
    /// budget ([`crate::DEFAULT_LOGIN_IP_RATE_LIMIT`]). With no resolved
    /// client IP the limiter is skipped, where the twin charges one shared
    /// `'unknown'` bucket — the difference signup has too, and one only a
    /// router mounted without the client-IP middleware can show.
    pub bootstrap_ip_rate_limiter: Option<Arc<RateLimiter>>,
    /// Signs the session cookie the bootstrap mints, inside its transaction.
    pub keyring: Arc<Keyring>,
    /// The session cookie's name (default [`crate::SESSION_COOKIE_NAME`]).
    pub session_cookie_name: &'static str,
}

impl std::fmt::Debug for BootstrapOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BootstrapOptions")
            .field("has_token_store", &self.token_store.is_some())
            .field("has_keeper_callback", &self.on_keeper_resolved.is_some())
            .field(
                "has_ip_rate_limiter",
                &self.bootstrap_ip_rate_limiter.is_some(),
            )
            .finish_non_exhaustive()
    }
}

// -- Handler --------------------------------------------------------------

/// Resolve whether bootstrap is currently available: a token path is
/// configured, the `bootstrap_lock` row says not yet bootstrapped, and the
/// token file passes the same read the request makes.
///
/// Consumers call this once at startup to seed the shared
/// `bootstrap_available` flag (returned on `/status` 401 + gating
/// `/bootstrap`). `token_path: None` (no bootstrap token configured)
/// resolves to `false` without touching the database. A token file that
/// can't be read resolves to `false` (logged). A failed lock read is an
/// error: the boot fails naming it, as the twin's boot throws, rather than
/// closing bootstrap silently for the life of the process.
///
/// The lock is read first, so the report fits the state:
///
/// - a missing `bootstrap_lock` row is unavailable, logged as an `error` — the
///   migration seeds it, and without it every bootstrap would be refused in
///   its transaction while `/status` advertised an open window;
/// - bootstrapped, no readable token file: `info`, the steady state;
/// - bootstrapped with a readable token file: a `warn` naming it — it would
///   reopen bootstrap on an empty database, so the operator should delete it;
/// - not bootstrapped and the file unreadable: a `warn` with the reason (and
///   the `error` [`BOOTSTRAP_TOKEN_MIN_BYTES`] logs for a short one).
///
/// Twin of `fuz_app`'s `check_bootstrap_status`, which logs the same states
/// at the same levels.
///
/// # Errors
///
/// [`fuz_db::DbError`] when the pool checkout or the `bootstrap_lock` read
/// fails.
pub async fn is_bootstrap_available(
    pool: &Pool,
    token_path: Option<&Path>,
) -> Result<bool, fuz_db::DbError> {
    let Some(path) = token_path else {
        return Ok(false);
    };
    let client = pool.get().await.map_err(fuz_db::DbError::PoolGet)?;
    let row = client
        .query_opt("SELECT bootstrapped FROM bootstrap_lock WHERE id = 1", &[])
        .await?;
    drop(client);
    let Some(row) = row else {
        tracing::error!(
            "bootstrap unavailable: the bootstrap_lock row is missing — the auth migration seeds it; restore it to bootstrap"
        );
        return Ok(false);
    };
    let bootstrapped: bool = row.try_get(0)?;
    // Validate with the *same* secure read the handler will perform, not a
    // bare `metadata` existence probe: an availability check laxer than the
    // read it gates reports green at boot and then fails every bootstrap
    // attempt.
    let read = read_bootstrap_token_file(path.to_path_buf()).await;
    if bootstrapped {
        if read.is_ok() {
            tracing::warn!(
                path = %path.display(),
                "bootstrap token file present on a bootstrapped server — it would reopen bootstrap on an empty database; delete it"
            );
        } else {
            tracing::info!("bootstrap unavailable: already bootstrapped");
        }
        return Ok(false);
    }
    let bytes = match read {
        Ok(bytes) => bytes,
        Err(e) => {
            tracing::warn!(
                path = %path.display(),
                error = %fuz_sys::cli::format_error_chain(&e),
                "bootstrap unavailable: token file unreadable"
            );
            return Ok(false);
        }
    };
    if bootstrap_token_from_file(bytes).is_none() {
        tracing::warn!(
            path = %path.display(),
            "bootstrap unavailable: token file under the minimum length"
        );
        return Ok(false);
    }
    tracing::info!(path = %path.display(), "bootstrap token available");
    Ok(true)
}

/// Run the bootstrap pipeline.
///
/// Transport-agnostic — REST handlers (`bootstrap_routes`) and future
/// CLI tooling share this core. The body is validated first, as on the
/// twin, so a malformed body answers `400` whatever the window's state.
/// Failures *inside the open bootstrap window*
/// emit typed audit rows matching `fuz_app`'s wire shape; refusals outside it
/// are silent, so a permanently-mounted route can't be turned into an
/// unauthenticated `audit_log` write channel.
///
/// # Errors
///
/// Returns [`BootstrapError::Classified`] with a [`BootstrapErrorKind`]
/// discriminant for the failure cases the operator-facing layer maps
/// to HTTP status codes.
pub async fn bootstrap_handler(
    options: &BootstrapOptions,
    client_ip: Option<String>,
    input: BootstrapInput,
) -> Result<BootstrapSuccess, BootstrapError> {
    // The body is validated first, as the twin's route schema (`BootstrapInput`)
    // refuses it before its handler runs: a malformed body answers `400` whether
    // or not the window is open, and costs no audit row. The username is the
    // raw value, validated and then lowercased — a padded name is refused,
    // never trimmed into a legal one.
    let Some(canonical_username) = bootstrap_input_canonical_username(&input) else {
        return Err(BootstrapError::Classified {
            kind: BootstrapErrorKind::InvalidInput,
        });
    };

    // The check below refuses *outside* the open bootstrap window — bootstrap
    // was never configured, or it already completed — and deliberately writes
    // no audit row. The route stays mounted for the life of the process
    // and the origin gate admits any caller sending no `Origin`, so an emit here
    // is an unauthenticated, unbounded `audit_log` write channel: one INSERT per
    // request, forever, from anyone who can reach the host. Nothing is learned
    // from the rows either — they record that a closed door stayed closed.
    //
    // The emits this handler does make (`token_file_missing`, `invalid_token`,
    // `token_file_undeletable`) fire only while the window is genuinely open,
    // which is the short-lived interval where a failed attempt is forensically
    // interesting. `token_file_missing` closes the window on its way out, so it
    // fires once; `invalid_token` and `token_file_undeletable` leave it open (a
    // wrong token or a fixable directory must not lock the operator out), so
    // the per-IP limiter below is what bounds them. Don't add an emit to this
    // check: a limiter would bound that channel without closing it.
    //
    // Both cases answer the twin's `403 already_bootstrapped`, which refuses a
    // missing token path and a closed window in one check, so an unconfigured
    // deployment reads exactly as a bootstrapped one.
    let Some(token_store) = options
        .token_store
        .as_ref()
        .filter(|_| options.bootstrap_available.load(Ordering::Relaxed))
    else {
        return Err(BootstrapError::Classified {
            kind: BootstrapErrorKind::AlreadyBootstrapped,
        });
    };

    // Reserved, not checked, before any token or DB work: the attempt counts
    // against the per-IP cap until it settles, so a concurrent burst can't all
    // pass before any of it records. A refusal records it; the lock-race loser,
    // a success, and an unclassified failure release it (an early return drops
    // the reservation, which releases). Keyed by the address's rate-limit key
    // (an IPv6 client's `/64`); the audit rows keep the full address. Mirrors
    // the twin's `bootstrap_routes.ts`.
    let ip_key = client_ip
        .as_deref()
        .map(fuz_http::rate_limit_ip_key)
        .unwrap_or_default();
    let ip_reservation = reserve_optional(
        options
            .bootstrap_ip_rate_limiter
            .as_deref()
            .filter(|_| client_ip.is_some()),
        &ip_key,
        RESERVATION_WAIT_MAX,
    )
    .await
    .map_err(|limited| BootstrapError::Classified {
        kind: BootstrapErrorKind::RateLimitExceeded {
            retry_after: limited.retry_after,
        },
    })?;

    // Read raw bytes — trim() is length-dependent (variable work)
    // and would undermine the ct_eq below. Bootstrap token files are
    // operator-written and may contain a trailing newline; we tolerate
    // exactly one trailing `\n` (POSIX convention) before the
    // constant-time comparison runs over the full bytes. Anything else
    // is rejected; operators must write the bytes exactly.
    // A token under the minimum length reads as unreadable, like a missing
    // file — it can never match (empty) or is guessable (short).
    let read = token_store.read_token().await.inspect_err(|e| {
        tracing::warn!(
            error = %fuz_sys::cli::format_error_chain(e),
            "bootstrap token file rejected"
        );
    });
    let Some(expected_token) = read.ok().and_then(bootstrap_token_from_file) else {
        // Close the window. Bootstrap cannot succeed without a readable token,
        // and `is_bootstrap_available` already reads an unreadable file as
        // closed at boot — so leaving the flag set means the two disagree, and
        // every later request takes this leg and writes another audit row.
        // This emit stays: it is the one that records the transition, and it
        // fires once.
        options.bootstrap_available.store(false, Ordering::Relaxed);
        ip_reservation.record();
        emit_failure(&options.audit, client_ip.as_deref(), "token_file_missing").await;
        return Err(BootstrapError::Classified {
            kind: BootstrapErrorKind::TokenFileMissing,
        });
    };

    if !bool::from(input.token.as_bytes().ct_eq(&expected_token)) {
        ip_reservation.record();
        emit_failure(&options.audit, client_ip.as_deref(), "invalid_token").await;
        return Err(BootstrapError::Classified {
            kind: BootstrapErrorKind::InvalidToken,
        });
    }

    let password_hash = options
        .password_hasher
        .hash(input.password)
        .await
        .map_err(BootstrapError::PasswordHash)?;

    // The write phase runs on its own task, which this request only awaits:
    // once the token is burned the bootstrap must commit or report, and a
    // client that disconnects drops the request's future — a drop between
    // the burn (which completes on its blocking thread regardless) and the
    // COMMIT would roll the transaction back silently, leaving the token gone,
    // nothing created, and the window open. Everything from the pool checkout
    // to the success audit row is on the task, so no await point of it is the
    // request's to cancel. A panic on the task answers the 500.
    let write = tokio::spawn(bootstrap_write(
        options.clone(),
        Arc::clone(token_store),
        canonical_username,
        password_hash,
        client_ip,
    ));
    let result = write.await.map_err(BootstrapError::Task)?;

    // Settle the reservation on the outcome: a failed burn is charged like
    // every refusal; the race loser, a success, and a fault release it (the
    // drop). A request dropped while the task runs releases it too.
    if matches!(
        result,
        Err(BootstrapError::Classified {
            kind: BootstrapErrorKind::TokenFileUndeletable
        })
    ) {
        ip_reservation.record();
    } else {
        drop(ip_reservation);
    }
    result
}

/// The write phase of [`bootstrap_handler`], spawned so the request can't
/// cancel it: the lock, the inserts, the session and its signed cookie, the
/// burn, the commit, then the post-commit flip, callback, and audit row.
async fn bootstrap_write(
    options: BootstrapOptions,
    token_store: Arc<dyn BootstrapTokenStore>,
    canonical_username: String,
    password_hash: HashedPassword,
    client_ip: Option<String>,
) -> Result<BootstrapSuccess, BootstrapError> {
    let mut client = options.pool.get().await?;

    let tx = client.transaction().await?;

    // Acquire the bootstrap lock atomically.
    let lock_row = tx
        .query_opt(
            "UPDATE bootstrap_lock SET bootstrapped = true
             WHERE id = 1 AND bootstrapped = false RETURNING id",
            &[],
        )
        .await?;
    if lock_row.is_none() {
        // Verify-write race loser — pre-check passed, UPDATE failed. Roll back
        // and flag bootstrap_available false so the early check catches the
        // next caller. No audit row and no limiter charge: this is reachable
        // only by a concurrent legitimate attempt during the open window, and
        // folding it into the same silent refusal as the steady-state case is
        // what keeps the post-bootstrap probe channel write-free (see the note
        // in `bootstrap_handler`).
        tx.rollback().await.ok();
        options.bootstrap_available.store(false, Ordering::Relaxed);
        return Err(BootstrapError::Classified {
            kind: BootstrapErrorKind::AlreadyBootstrapped,
        });
    }

    let account = query_create_account(&tx, &canonical_username, password_hash.as_str()).await?;
    let actor = query_create_actor(&tx, &account.id, &canonical_username).await?;
    query_create_role_grant(&tx, &actor.id, ROLE_KEEPER, None, None, None, None).await?;
    query_create_role_grant(&tx, &actor.id, ROLE_ADMIN, None, None, None, None).await?;

    // The account was created three statements above, so the cap evicts
    // nothing. Routed through the shared minter anyway: the cap is a property
    // of session creation, not of the login route.
    let session_token = create_capped_session(&tx, &account.id)
        .await?
        .into_token_for_new_account();
    // Signed inside the transaction, as the twin signs it: a cookie that
    // can't be written rolls the bootstrap back with the token unburned,
    // rather than answering 500 for a committed bootstrap.
    let set_cookie = sign_session_cookie(
        &options.keyring,
        &session_token,
        options.session_cookie_name,
    )
    .map_err(BootstrapError::SessionCookie)?;

    // Burn the token last inside the transaction, immediately before the
    // commit. After the lock UPDATE, so only the lock winner burns (its row
    // lock is held across the unlink, so a concurrent attempt waits on its
    // UPDATE); after the inserts, so a failed insert spends nothing; last, so
    // the window between a burn and a failed commit is one round trip. A
    // failed burn rolls everything back and leaves the window open: the
    // operator fixes the directory and retries the same token.
    match token_store.burn_token().await {
        Ok(BurnOutcome::Burned) => {}
        Ok(BurnOutcome::AlreadyGone) => {
            tracing::warn!("bootstrap token file was already gone at the burn — counted as burned");
        }
        Err(e) => {
            tx.rollback().await.ok();
            tracing::error!(
                error = %fuz_sys::cli::format_error_chain(&e),
                "bootstrap rolled back: could not delete the token file — the server user needs write access to its directory; nothing was created and the token is still valid, retry"
            );
            emit_failure(
                &options.audit,
                client_ip.as_deref(),
                "token_file_undeletable",
            )
            .await;
            return Err(BootstrapError::Classified {
                kind: BootstrapErrorKind::TokenFileUndeletable,
            });
        }
    }

    commit_checked(tx).await.map_err(|e| {
        // the burn already ran: the token is gone and nothing was created
        tracing::error!(
            error = %fuz_sys::cli::format_error_chain(&e),
            "bootstrap rolled back after its token file was deleted — write a new token and restart the server to bootstrap"
        );
        BootstrapError::Commit(e)
    })?;

    options.bootstrap_available.store(false, Ordering::Relaxed);

    if let Some(ref cb) = options.on_keeper_resolved {
        cb.on_keeper_resolved(account.id).await;
    }

    let _ = options
        .audit
        .emit(
            AuditLogInput::for_event(AuditEventType::Bootstrap)
                .actor(actor.id)
                .account(account.id)
                .ip(client_ip),
        )
        .await;

    Ok(BootstrapSuccess {
        session_token,
        set_cookie,
        account,
        actor,
    })
}

/// The first-admin body's shape gate, the twin's `BootstrapInput` bounds: a
/// token of 1 to [`BOOTSTRAP_TOKEN_LENGTH_MAX`] UTF-16 code units, the
/// canonical username under the creation grammar, and the password under the
/// twin's `Password` (12 to 300 units). Lengths count UTF-16 code units the way
/// `String.length` — and so the twin's `max_length` and `bounded_string` —
/// counts them. Returns the canonical username when all three hold.
fn bootstrap_input_canonical_username(input: &BootstrapInput) -> Option<String> {
    let password_ok = (crate::password::PASSWORD_LENGTH_MIN..=crate::password::PASSWORD_LENGTH_MAX)
        .contains(&crate::password_length(&input.password));
    let token_ok = (1..=BOOTSTRAP_TOKEN_LENGTH_MAX).contains(&input.token.encode_utf16().count());
    if !token_ok || !password_ok {
        return None;
    }
    crate::primitive_schemas::canonical_username_for_creation(&input.username)
}

async fn emit_failure(audit: &Arc<AuditEmitter>, client_ip: Option<&str>, error: &str) {
    let _ = audit
        .emit(
            AuditLogInput::for_event(AuditEventType::Bootstrap)
                .failure()
                .ip(client_ip.map(str::to_owned))
                .metadata(json!({"error": error})),
        )
        .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bootstrap_input_debug_redacts_token_and_password() {
        let input = BootstrapInput {
            token: "bootstrap-token-Hd3kR8".to_owned(),
            username: "first_admin".to_owned(),
            password: "bootstrap-password-Lm2tW5".to_owned(),
        };
        let rendered = format!("{input:?}");
        assert!(!rendered.contains("bootstrap-token-Hd3kR8"), "{rendered}");
        assert!(
            !rendered.contains("bootstrap-password-Lm2tW5"),
            "{rendered}"
        );
        assert!(rendered.contains("first_admin"), "{rendered}");
    }

    #[test]
    fn bootstrap_success_debug_redacts_the_session_token() {
        let account_id = uuid::Uuid::nil();
        let success = BootstrapSuccess {
            session_token: "bootstrap-session-Qx6yN1".to_owned(),
            set_cookie: "fuz_session=bootstrap-cookie-Wd4pZ8".to_owned(),
            account: AccountRow {
                id: account_id,
                username: "first_admin".to_owned(),
            },
            actor: ActorRow {
                id: account_id,
                account_id,
                name: "first_admin".to_owned(),
            },
        };
        let rendered = format!("{success:?}");
        assert!(!rendered.contains("bootstrap-session-Qx6yN1"), "{rendered}");
        assert!(!rendered.contains("bootstrap-cookie-Wd4pZ8"), "{rendered}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
        assert!(rendered.contains("first_admin"), "{rendered}");
    }

    #[test]
    fn bootstrap_input_rejects_unknown_field() {
        // `deny_unknown_fields` converges to the canonical TS strict `object`:
        // an extra key on the first-admin body must fail deserialization, not be
        // silently ignored. The DB suite builds `BootstrapInput` structurally
        // (bypassing serde), so this is the only guard on the attribute.
        assert!(
            serde_json::from_str::<BootstrapInput>(
                r#"{"token":"t","username":"a","password":"p"}"#
            )
            .is_ok(),
            "a well-formed body must deserialize"
        );
        assert!(
            serde_json::from_str::<BootstrapInput>(
                r#"{"token":"t","username":"a","password":"p","is_admin":true}"#
            )
            .is_err(),
            "an unknown field must fail deserialization (mass-assignment guard)"
        );
    }

    /// The first-admin body's password bound is the twin's `Password`
    /// (`.min(12).max(300)`), counted in UTF-16 code units. The two rows a
    /// byte count got backwards: eight `\u{00FC}` is 16 bytes, so a byte
    /// count admitted a password the twin refuses, and 151 of them is 302
    /// bytes, so a byte count refused one the twin admits.
    #[test]
    fn bootstrap_password_is_bounded_in_the_twins_units() {
        let admits = |password: &str| input_admits("t", "keeper", password);
        let eight = "\u{00FC}".repeat(8);
        assert_eq!(eight.len(), 16, "bytes");
        assert!(!admits(&eight), "8 code units is under the floor");
        let long = "\u{00FC}".repeat(151);
        assert_eq!(long.len(), 302, "bytes");
        assert!(admits(&long), "151 code units is under the ceiling");
    }

    /// The token's bound is the twin's `max_length(BOOTSTRAP_TOKEN_LENGTH_MAX)`,
    /// counted in UTF-16 code units: a two-byte token at the cap is twice the
    /// cap in bytes and admitted, and an astral one is half the cap in scalar
    /// values and refused one character past it.
    #[test]
    fn bootstrap_token_is_bounded_in_the_twins_units() {
        let admits = |token: &str| input_admits(token, "keeper", "a-long-enough-password");
        let max = BOOTSTRAP_TOKEN_LENGTH_MAX;
        assert!(admits(&"x".repeat(max)), "ASCII at the cap");
        assert!(!admits(&"x".repeat(max + 1)), "ASCII past the cap");
        let two_byte = "\u{00E9}".repeat(max);
        assert_eq!(two_byte.len(), max * 2, "bytes");
        assert!(
            admits(&two_byte),
            "a two-byte token at the cap in code units"
        );
        assert!(
            !admits(&"\u{00E9}".repeat(max + 1)),
            "two-byte past the cap"
        );
        let astral = "\u{1F600}".repeat(max / 2);
        assert_eq!(astral.chars().count(), max / 2, "scalar values");
        assert!(admits(&astral), "an astral token at the cap in code units");
        assert!(!admits(&format!("{astral}a")), "one unit past the cap");
        assert!(
            !admits(&"\u{1F600}".repeat(max / 2 + 1)),
            "one astral character, two units, past the cap"
        );
    }

    fn input_admits(token: &str, username: &str, password: &str) -> bool {
        bootstrap_input_canonical_username(&BootstrapInput {
            token: token.to_owned(),
            username: username.to_owned(),
            password: password.to_owned(),
        })
        .is_some()
    }

    /// The username is the twin's `Username`: validated raw, then lowercased.
    /// Padding is refused, not trimmed away, and the token must be non-empty.
    #[test]
    fn bootstrap_username_is_validated_raw() {
        let password = "a-long-enough-password";
        let canonical = |username: &str| {
            bootstrap_input_canonical_username(&BootstrapInput {
                token: "t".to_owned(),
                username: username.to_owned(),
                password: password.to_owned(),
            })
        };
        assert_eq!(canonical("Keeper").as_deref(), Some("keeper"));
        for padded in [
            " keeper",
            "keeper ",
            "\tkeeper",
            "keeper\n",
            "\u{85}keeper",
            "\u{FEFF}keeper",
        ] {
            assert_eq!(canonical(padded), None, "{padded:?}");
        }
        assert!(
            !input_admits("", "keeper", password),
            "an empty token is refused"
        );
    }

    #[test]
    fn strip_one_trailing_newline_strips_exactly_one() {
        // Tolerate the single POSIX trailing newline; reject everything else so
        // the byte set the ct_eq accepts stays exact.
        assert_eq!(strip_one_trailing_newline(b"token\n".to_vec()), b"token");
        // Exactly one — a second newline survives (and so fails the compare).
        assert_eq!(
            strip_one_trailing_newline(b"token\n\n".to_vec()),
            b"token\n"
        );
        // No trailing newline: unchanged.
        assert_eq!(strip_one_trailing_newline(b"token".to_vec()), b"token");
        // A trailing space is NOT a newline — preserved (must fail the compare).
        assert_eq!(strip_one_trailing_newline(b"token ".to_vec()), b"token ");
        // CRLF: only the LF goes, so a token file written with Windows line
        // endings fails the compare rather than matching.
        assert_eq!(
            strip_one_trailing_newline(b"token\r\n".to_vec()),
            b"token\r"
        );
        assert_eq!(
            strip_one_trailing_newline(b"token  \n".to_vec()),
            b"token  "
        );
        // A leading newline is not trailing — preserved.
        assert_eq!(strip_one_trailing_newline(b"\ntoken".to_vec()), b"\ntoken");
        // Empty stays empty (no panic on `last()`).
        assert_eq!(strip_one_trailing_newline(Vec::new()), b"");
    }
}
