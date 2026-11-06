//! Signup — public account creation (invite-gated or open).
//!
//! Mirrors `fuz_app`'s `auth/signup_routes.ts`: FOR UPDATE invite find
//! inside the signup tx, constant-time floor on 403/409 denials,
//! `internal_error` audit on every unclassified failure path
//! (pre-tx, in-tx, and a failed commit), `{ok, account, actor}` success
//! body matching `BootstrapOutput`. Input shape gated by
//! [`crate::primitive_schemas`] and [`crate::password`]; timing-floor
//! primitives live in [`crate::timing`].
//!
//! ## `app_settings.open_signup` resolution
//!
//! The handler loads `app_settings` from the DB on every signup
//! request, and hashes the password on every one that passes input
//! validation. Both are bounded per address by the per-IP limiter, which
//! is reserved before the load and charged by every classified failure and
//! every successful open signup; what escapes it is an invite-gated success
//! (which spends an invite), a 5xx other than a panic once signup reaches its
//! hash, and a request with no resolved client IP.
//! The per-account limiter bounds retries of one username only.

use std::sync::Arc;

use deadpool_postgres::Pool;
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::account_queries::query_create_account_with_actor;
use crate::account_schema::AccountRow;
use crate::actor_schema::ActorRow;
use crate::app_settings_queries::query_app_settings_load;
use crate::audit_emitter::{AuditEmitter, AuditLogInput};
use crate::audit_event_type::AuditEventType;
use crate::error::{SignupError, SignupErrorKind};
use crate::invite_queries::{
    query_invite_claim_unscoped, query_invite_find_unclaimed_match_for_update,
};
use crate::password::{PASSWORD_LENGTH_MAX, PASSWORD_LENGTH_MIN};
use crate::password_hasher::PasswordHasher;
use crate::primitive_schemas::{canonical_username_for_creation, is_valid_email};
use crate::rate_limiter::{
    RESERVATION_WAIT_MAX, RateLimitReservation, RateLimiter, reserve_optional,
};
use crate::session_queries::create_capped_session;
use crate::timing::{compute_fail_deadline, wait_for_deadline};
use fuz_db::{commit_checked, is_pg_unique_violation};

// -- Tunables -------------------------------------------------------------

/// Default minimum wall-clock time (ms) for a signup denial response.
///
/// Picked to exceed the p99 of every signup denial code path
/// (`no_matching_invite`, `signup_conflict`). 429 stays fast by design.
/// See [`crate::timing`] for the eager-deadline mechanism that makes
/// the observed response time `max(work, floor)` rather than
/// `work + floor`. Production consumers pass it as
/// [`SignupOptions::signup_fail_floor_ms`]; a `0` there is announced by
/// [`crate::signup_routes::signup_router`] with a stderr banner.
pub const DEFAULT_SIGNUP_FAIL_FLOOR_MS: u64 = 250;

/// Default uniform jitter window (±ms) layered on the floor.
pub const DEFAULT_SIGNUP_FAIL_JITTER_MS: u64 = 25;

// -- Input ----------------------------------------------------------------

/// `POST /signup` request body.
///
/// `deny_unknown_fields` mirrors the TS `SignupInput`, a strict `fuz_schema` `object` — an
/// extra body key fails deserialization and the route wrapper maps it to
/// `400 invalid_request_body` (not silently ignored), matching login's
/// `LoginInput` and the TS contract. `Debug` redacts the password.
#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct SignupInput {
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub email: Option<String>,
}

impl std::fmt::Debug for SignupInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignupInput")
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .field("email", &self.email)
            .finish()
    }
}

/// Successful signup result.
///
/// Carries the signed session token raw + created account + actor;
/// the HTTP wrapper builds the wire response shape and the
/// `Set-Cookie` header from these. Mirrors `BootstrapSuccess`, including its
/// redacting `Debug`.
pub struct SignupSuccess {
    pub session_token: String,
    pub account: AccountRow,
    pub actor: ActorRow,
}

impl std::fmt::Debug for SignupSuccess {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignupSuccess")
            .field("session_token", &"<redacted>")
            .field("account", &self.account)
            .field("actor", &self.actor)
            .finish()
    }
}

// -- Options --------------------------------------------------------------

/// Capabilities required by [`signup_handler`].
pub struct SignupOptions {
    /// Pool for the signup transaction + `app_settings` load.
    pub pool: Pool,
    /// Password hasher (Argon2id in production,
    /// `TestingArgon2idHasher` in test binaries).
    pub password_hasher: Arc<dyn PasswordHasher>,
    /// Audit emitter — both success and failure legs write rows.
    pub audit: Arc<AuditEmitter>,
    /// Per-IP rate limiter. Pass `None` to disable. 429 stays fast —
    /// the denial floor doesn't apply to rate-limit rejections. Charged by
    /// every classified failure and by every successful open signup (an
    /// invite-gated success spends an invite instead).
    pub signup_ip_rate_limiter: Option<Arc<RateLimiter>>,
    /// Per-account rate limiter, keyed by canonicalized username.
    pub signup_account_rate_limiter: Option<Arc<RateLimiter>>,
    /// Minimum wall-clock time (ms) for signup denial responses (403 /
    /// 409). Production passes [`DEFAULT_SIGNUP_FAIL_FLOOR_MS`]; set to `0`
    /// to disable (tests), which
    /// [`signup_router`](crate::signup_routes::signup_router) announces once
    /// per process with a `SIGNUP FAILURE TIMING FLOOR DISABLED` stderr
    /// banner. 429 responses are not floored.
    pub signup_fail_floor_ms: u64,
    /// Uniform jitter window (±ms) layered on the floor. Set to `0` to
    /// disable jitter while keeping the floor.
    pub signup_fail_jitter_ms: u64,
}

impl std::fmt::Debug for SignupOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignupOptions")
            .field(
                "has_ip_rate_limiter",
                &self.signup_ip_rate_limiter.is_some(),
            )
            .field(
                "has_account_rate_limiter",
                &self.signup_account_rate_limiter.is_some(),
            )
            .field("signup_fail_floor_ms", &self.signup_fail_floor_ms)
            .field("signup_fail_jitter_ms", &self.signup_fail_jitter_ms)
            .finish_non_exhaustive()
    }
}

// -- Handler --------------------------------------------------------------

/// Run the signup pipeline.
///
/// Transport-agnostic: the REST wrapper in `signup_routes` handles
/// origin checking, JSON parsing, cookie signing, and status-code
/// mapping. Failure variants carry a typed [`SignupErrorKind`] the
/// wrapper maps to wire-format error strings + HTTP statuses.
///
/// # Errors
///
/// Returns [`SignupError::Classified`] for classified failures
/// ([`SignupErrorKind`]). The internal variants ([`SignupError::Pool`],
/// [`SignupError::Query`], [`SignupError::PasswordHash`],
/// [`SignupError::Commit`]) escape after the handler emits a fallback failure
/// audit.
pub async fn signup_handler(
    options: &SignupOptions,
    client_ip: Option<String>,
    input: SignupInput,
) -> Result<SignupSuccess, SignupError> {
    // 429 stays fast — reserved before any work, no floor applied. Mirrors
    // login's rate-limit posture and fuz_app's signup pre-flight. Reserved,
    // not checked: the attempt counts against the cap until it settles below,
    // so a concurrent burst can't all pass before any of it records — and the
    // Argon2 hash every attempt pays is bounded with it. An early return
    // drops, and so releases, the reservation.
    // Keyed by the address's rate-limit key (an IPv6 client's `/64`).
    let ip_key = client_ip
        .as_deref()
        .map(fuz_http::rate_limit_ip_key)
        .unwrap_or_default();
    let mut ip_reservation = reserve_optional(
        options
            .signup_ip_rate_limiter
            .as_deref()
            .filter(|_| client_ip.is_some()),
        &ip_key,
        RESERVATION_WAIT_MAX,
    )
    .await
    .map_err(rate_limit_error)?;

    // Validate inputs before any rate-limit-record / DB work. Invalid
    // input doesn't touch the account-rate-limit bucket — attackers
    // can't burn it with garbage — and costs no IP attempt either: the
    // return drops the IP reservation, as the twin's schema refusal never
    // reaches its limiter.
    // `Username` on the twin: the raw value is validated, then lowercased —
    // a padded name is refused, never trimmed into a legal one.
    let canonical_username = canonical_username_for_creation(&input.username);
    // `Password` on the twin (12 to 300), counted in UTF-16 code units the way
    // `String.length` — and so its `bounded_string` — counts them.
    let password_len = crate::password_length(&input.password);
    let Some(canonical_username) = canonical_username.filter(|_| {
        (PASSWORD_LENGTH_MIN..=PASSWORD_LENGTH_MAX).contains(&password_len)
            && input.email.as_deref().is_none_or(is_valid_email)
    }) else {
        return Err(SignupError::Classified {
            kind: SignupErrorKind::InvalidInput,
        });
    };

    let mut account_reservation = reserve_optional(
        options.signup_account_rate_limiter.as_deref(),
        &canonical_username,
        RESERVATION_WAIT_MAX,
    )
    .await
    .map_err(rate_limit_error)?;

    // Eager deadline: capture the absolute `Instant` here so the
    // wall-clock budget runs concurrently with the app_settings load,
    // Argon2 hash, and DB work below. See `crate::timing` for the
    // invariant — the `Instant`-and-defer split is what preserves the
    // `max(work, floor)` property; constructing the sleep future
    // eagerly and awaiting later would degrade to `work + floor` and
    // re-open the enumeration oracle.
    let fail_deadline =
        compute_fail_deadline(options.signup_fail_floor_ms, options.signup_fail_jitter_ms);

    // Pre-tx phase: load app_settings + hash password concurrently. The
    // app_settings query holds a brief pool connection (~2ms) and the
    // Argon2 hash spins on a `spawn_blocking` thread (~30-50ms prod
    // params); the two are independent, so `try_join!` shaves the load
    // off the critical path. The load's `client` drops when its async
    // block completes, not when the join finishes — connection lifetime
    // stays scoped to the load itself.
    //
    // `input.password` is moved (not cloned) into the hash future via
    // `async move` — the trait takes owned `String` precisely so the
    // hash can run on a detached blocking thread. `input.email` stays
    // usable via partial-move.
    //
    // Every pre-tx failure (load / hash / pool / tx begin) emits an
    // `internal_error` audit row through this closure so the attempt
    // leaves a forensic trail. 5xx isn't a timing oracle, so no deadline
    // wait — the floor only pads classified 403 / 409 denials.
    // `open_signup` is unknown at this layer (load may not have
    // completed); pass `false`.
    let audit_pre_tx_failure = || {
        emit_pre_tx_failure_audit(
            &options.audit,
            client_ip.as_deref(),
            &canonical_username,
            input.email.as_deref(),
        );
    };

    let pool = &options.pool;
    let hasher = &options.password_hasher;
    let password = input.password;
    // From here a request dropped before it settles (a client that
    // disconnects) is charged to both buckets — mid-hash, queued for an
    // Argon2 permit, or in the database steps after the hash: the Argon2 work
    // it started runs on regardless, and is spent by the time the steps after
    // it run (see `RateLimitReservation::charge_if_cancelled`). Every
    // unclassified failure below releases both explicitly, so a 5xx costs
    // nothing — except a panic, which unwinds through the armed drop and is
    // charged.
    ip_reservation.arm_charge_on_drop();
    account_reservation.arm_charge_on_drop();
    let pre_tx = async {
        let (app_settings, password_hash) = tokio::try_join!(
            async move {
                let client = pool.get().await?;
                query_app_settings_load(&client)
                    .await
                    .map_err(SignupError::Query)
            },
            async move {
                hasher
                    .hash(password)
                    .await
                    .map_err(SignupError::PasswordHash)
            },
        )?;
        let client = pool.get().await.map_err(SignupError::Pool)?;
        Ok::<_, SignupError>((app_settings, password_hash, client))
    };
    let (app_settings, password_hash, mut client) = match pre_tx.await {
        Ok(ready) => ready,
        Err(e) => {
            audit_pre_tx_failure();
            release_rate_limits(ip_reservation, account_reservation);
            return Err(e);
        }
    };
    let tx = match client.transaction().await {
        Ok(tx) => tx,
        Err(e) => {
            audit_pre_tx_failure();
            release_rate_limits(ip_reservation, account_reservation);
            return Err(SignupError::Query(e));
        }
    };

    // `is_valid_email` already rejected surrounding whitespace and the
    // empty string at input validation, so the validated address is
    // stored verbatim (matching the TS `Email` schema — no trim, no
    // lowercase). `None` stays None: no email is fine.
    let email_opt: Option<&str> = input.email.as_deref();

    // Find + claim must run inside the same tx so the row lock makes
    // them atomic — concurrent signups for the same invite block on the
    // lock and observe the post-commit state. The loser's
    // `find_for_update` returns no row (winner flipped `claimed_at`)
    // and falls through to `no_matching_invite` — no race window.
    let invite_id: Option<Uuid> = if app_settings.open_signup {
        None
    } else {
        match query_invite_find_unclaimed_match_for_update(&tx, email_opt, &canonical_username)
            .await
        {
            Ok(Some(locked)) => Some(locked.id),
            Ok(None) => {
                record_failure_rate_limits(ip_reservation, account_reservation);
                tx.rollback().await.ok();
                emit_failure_audit(
                    &options.audit,
                    client_ip.as_deref(),
                    failure_metadata(
                        SignupErrorKind::NoMatchingInvite,
                        &canonical_username,
                        None,
                        input.email.as_deref(),
                        app_settings.open_signup,
                    ),
                );
                wait_for_deadline(fail_deadline).await;
                return Err(SignupError::Classified {
                    kind: SignupErrorKind::NoMatchingInvite,
                });
            }
            Err(e) => {
                // settled before the rollback await, so a client dropping
                // during it is not charged for a 5xx
                release_rate_limits(ip_reservation, account_reservation);
                tx.rollback().await.ok();
                emit_failure_audit(
                    &options.audit,
                    client_ip.as_deref(),
                    failure_metadata(
                        SignupErrorKind::InternalError,
                        &canonical_username,
                        None,
                        input.email.as_deref(),
                        app_settings.open_signup,
                    ),
                );
                return Err(SignupError::Query(e));
            }
        }
    };

    // Account + actor + (optional) invite claim + session — all inside
    // the same tx. Any error rolls back and routes through the
    // unclassified catch.
    let signup_tx_result = signup_inner_tx(
        &tx,
        &canonical_username,
        password_hash.as_str(),
        email_opt,
        invite_id.as_ref(),
    )
    .await;

    let (account, actor, session_token) = match signup_tx_result {
        Ok(triple) => triple,
        Err(e) => {
            // Classify the unique-violation conflict path; everything
            // else funnels through the fallback `internal_error` audit
            // before propagating. Both settle before the rollback await,
            // so a client dropping during it is charged only for a
            // classified denial, never for a 5xx.
            let conflict = matches!(&e, SignupError::Query(err) if is_pg_unique_violation(err));
            if conflict {
                record_failure_rate_limits(ip_reservation, account_reservation);
            } else {
                release_rate_limits(ip_reservation, account_reservation);
            }
            tx.rollback().await.ok();
            if conflict {
                emit_failure_audit(
                    &options.audit,
                    client_ip.as_deref(),
                    failure_metadata(
                        SignupErrorKind::SignupConflict,
                        &canonical_username,
                        invite_id,
                        input.email.as_deref(),
                        app_settings.open_signup,
                    ),
                );
                wait_for_deadline(fail_deadline).await;
                return Err(SignupError::Classified {
                    kind: SignupErrorKind::SignupConflict,
                });
            }
            // Unclassified failure: tx already rolled back so no
            // account persists, but the *attempt* should leave a
            // forensic trail. 5xx responses aren't floored — they
            // aren't response-time-controlled enumeration oracles.
            emit_failure_audit(
                &options.audit,
                client_ip.as_deref(),
                failure_metadata(
                    SignupErrorKind::InternalError,
                    &canonical_username,
                    invite_id,
                    input.email.as_deref(),
                    app_settings.open_signup,
                ),
            );
            return Err(e);
        }
    };

    // Still armed: a request dropped while its account commits is charged to
    // both buckets, the commit may land with no one left to settle it. That
    // holds for an invite-gated signup too, which costs the IP bucket one
    // attempt when dropped here though its success would have recorded none.
    if let Err(e) = commit_checked(tx).await {
        release_rate_limits(ip_reservation, account_reservation);
        // A failed commit is unclassified too, and the attempt leaves the same
        // `internal_error` trail as the in-tx path.
        emit_failure_audit(
            &options.audit,
            client_ip.as_deref(),
            failure_metadata(
                SignupErrorKind::InternalError,
                &canonical_username,
                invite_id,
                input.email.as_deref(),
                app_settings.open_signup,
            ),
        );
        return Err(SignupError::Commit(e));
    }

    // Reset the account-grain bucket only — the IP-aggregate one is deliberately
    // left alone (see `RateLimiter::reset`). Signup is the cheapest version of
    // the spray path it closes: where login at least costs the attacker a
    // credential, an open-signup deployment lets an *unauthenticated* caller
    // zero this budget by creating throwaway accounts. `signup_ip_rate_limiter`
    // is its own field, so what that bought depended on the consumer's wiring:
    // a distinct instance meant unbounded username enumeration through the
    // 403/409 split; the same `Arc` as `login_ip_rate_limiter` meant unbounded
    // credential guessing too. Neither is acceptable, so nothing is refunded
    // either way — and keeping the two instances distinct is the wiring
    // fuz_app mirrors (its `AppServerOptions` splits them).
    account_reservation.release();
    if let Some(ref limiter) = options.signup_account_rate_limiter {
        limiter.reset(&canonical_username);
    }
    // A successful *open* signup is charged to the IP bucket like a failure:
    // with no invite to spend, account creation is otherwise unbounded from a
    // single address — throwaway accounts, each one a session and a row. An
    // invite-gated success is bounded by the invites an admin minted, so it
    // records nothing (a class signing up on its invites from one NAT egress
    // would otherwise run the bucket dry).
    if app_settings.open_signup {
        ip_reservation.record();
    } else {
        ip_reservation.release();
    }

    drop(
        options.audit.emit(
            AuditLogInput::for_event(AuditEventType::Signup)
                .actor(actor.id)
                .account(account.id)
                .ip(client_ip)
                .metadata(success_metadata(
                    &canonical_username,
                    invite_id,
                    app_settings.open_signup,
                )),
        ),
    );

    Ok(SignupSuccess {
        session_token,
        account,
        actor,
    })
}

// -- Helpers --------------------------------------------------------------

async fn signup_inner_tx(
    tx: &deadpool_postgres::Transaction<'_>,
    canonical_username: &str,
    password_hash: &str,
    email_opt: Option<&str>,
    invite_id: Option<&Uuid>,
) -> Result<(AccountRow, ActorRow, String), SignupError> {
    let (account, actor) =
        query_create_account_with_actor(tx, canonical_username, password_hash, email_opt).await?;

    if let Some(invite_id) = invite_id {
        // FOR UPDATE held the row for the duration of the tx, so no
        // concurrent claim could flip `claimed_at` between the find and
        // this UPDATE. A miss means that invariant broke (a refactor that
        // split find + claim across transactions, or a non-locking
        // variant) — refuse loudly, in release builds too: the error rolls
        // the account back rather than mint one no invite admitted.
        let claimed = query_invite_claim_unscoped(tx, invite_id, &account.id).await?;
        if !claimed {
            tracing::error!(%invite_id, "invite already claimed despite the FOR UPDATE lock");
            return Err(SignupError::Classified {
                kind: SignupErrorKind::InternalError,
            });
        }
    }

    // `query_create_account_with_actor` above minted the account in this same
    // transaction, so the cap evicts nothing.
    let session_token = create_capped_session(tx, &account.id)
        .await?
        .into_token_for_new_account();

    Ok((account, actor, session_token))
}

fn emit_failure_audit(
    audit: &Arc<AuditEmitter>,
    client_ip: Option<&str>,
    metadata: serde_json::Value,
) {
    drop(
        audit.emit(
            AuditLogInput::for_event(AuditEventType::Signup)
                .failure()
                .ip(client_ip.map(str::to_owned))
                .metadata(metadata),
        ),
    );
}

/// Emit an `internal_error` failure audit for a pre-tx failure (pool
/// acquisition, `app_settings` load, password hash, transaction begin).
///
/// Pre-tx failures don't have `invite_id` (`find_for_update` hasn't run
/// yet) or known `open_signup` (`app_settings` load may have failed).
/// 5xx responses aren't enumeration oracles, so the deadline floor
/// doesn't apply here — the caller returns the underlying error
/// immediately after emitting.
fn emit_pre_tx_failure_audit(
    audit: &Arc<AuditEmitter>,
    client_ip: Option<&str>,
    canonical_username: &str,
    email: Option<&str>,
) {
    emit_failure_audit(
        audit,
        client_ip,
        failure_metadata(
            SignupErrorKind::InternalError,
            canonical_username,
            None,
            email,
            false,
        ),
    );
}

/// Charge a classified signup failure (403 / 409) to both buckets.
fn record_failure_rate_limits(
    ip_reservation: RateLimitReservation<'_>,
    account_reservation: RateLimitReservation<'_>,
) {
    ip_reservation.record();
    account_reservation.record();
}

/// Settle both reservations as costing nothing — an unclassified failure.
fn release_rate_limits(
    ip_reservation: RateLimitReservation<'_>,
    account_reservation: RateLimitReservation<'_>,
) {
    ip_reservation.release();
    account_reservation.release();
}

const fn rate_limit_error(limited: crate::rate_limiter::RateLimited) -> SignupError {
    SignupError::Classified {
        kind: SignupErrorKind::RateLimitExceeded {
            retry_after: limited.retry_after,
        },
    }
}

fn failure_metadata(
    kind: SignupErrorKind,
    username: &str,
    invite_id: Option<Uuid>,
    email: Option<&str>,
    open_signup: bool,
) -> serde_json::Value {
    // Exhaustive match — `RateLimitExceeded` and `InvalidInput` never
    // reach the audit-emit sites (rate-limit rejection and 400 bail
    // before the failure-audit branches), so they're `unreachable!()`
    // rather than a silent wildcard. Catches drift if a new
    // `SignupErrorKind` variant lands without explicit handling.
    let reason = match kind {
        SignupErrorKind::NoMatchingInvite => "no_match",
        SignupErrorKind::SignupConflict => "signup_conflict",
        SignupErrorKind::InternalError => "internal_error",
        SignupErrorKind::RateLimitExceeded { .. } | SignupErrorKind::InvalidInput => {
            unreachable!("rate-limit and invalid-input paths do not emit failure audit")
        }
    };
    let mut map = serde_json::Map::new();
    map.insert("username".into(), json!(username));
    map.insert("reason".into(), json!(reason));
    if let Some(id) = invite_id {
        map.insert("invite_id".into(), json!(id.to_string()));
    }
    if let Some(e) = email {
        map.insert("email".into(), json!(e));
    }
    if open_signup {
        map.insert("open_signup".into(), json!(true));
    }
    serde_json::Value::Object(map)
}

fn success_metadata(
    username: &str,
    invite_id: Option<Uuid>,
    open_signup: bool,
) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    map.insert("username".into(), json!(username));
    if let Some(id) = invite_id {
        map.insert("invite_id".into(), json!(id.to_string()));
    }
    if open_signup {
        map.insert("open_signup".into(), json!(true));
    }
    serde_json::Value::Object(map)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signup_input_debug_redacts_the_password() {
        let input = SignupInput {
            username: "new_user".to_owned(),
            password: "signup-password-Jf9cB4".to_owned(),
            email: None,
        };
        let rendered = format!("{input:?}");
        assert!(!rendered.contains("signup-password-Jf9cB4"), "{rendered}");
        assert!(rendered.contains("new_user"), "{rendered}");
    }

    #[test]
    fn signup_success_debug_redacts_the_session_token() {
        let account_id = Uuid::nil();
        let success = SignupSuccess {
            session_token: "signup-session-Tg5hP7".to_owned(),
            account: AccountRow {
                id: account_id,
                username: "new_user".to_owned(),
            },
            actor: ActorRow {
                id: account_id,
                account_id,
                name: "new_user".to_owned(),
            },
        };
        let rendered = format!("{success:?}");
        assert!(!rendered.contains("signup-session-Tg5hP7"), "{rendered}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
        assert!(rendered.contains("new_user"), "{rendered}");
    }

    #[test]
    fn signup_input_rejects_unknown_field() {
        // `deny_unknown_fields` is a mass-assignment guard mirroring login's
        // `LoginInput` (and the TS strict `object`): an extra body key fails
        // deserialization → 400, never silently ignored. Every DB-suite case
        // builds `SignupInput` structurally (bypassing serde), so without this
        // the attribute could be dropped in a refactor and no test would fail.
        // This pins the twin the login side already has.
        assert!(
            serde_json::from_str::<SignupInput>(r#"{"username":"a","password":"p"}"#).is_ok(),
            "a well-formed body must deserialize"
        );
        assert!(
            serde_json::from_str::<SignupInput>(
                r#"{"username":"a","password":"p","is_admin":true}"#
            )
            .is_err(),
            "an unknown field must fail deserialization (mass-assignment guard)"
        );
    }

    #[test]
    fn signup_error_kind_strings_match_ts_wire_shape() {
        assert_eq!(
            SignupErrorKind::NoMatchingInvite.as_str(),
            "no_matching_invite"
        );
        assert_eq!(SignupErrorKind::SignupConflict.as_str(), "signup_conflict");
        assert_eq!(
            SignupErrorKind::InvalidInput.as_str(),
            "invalid_request_body"
        );
        assert_eq!(
            SignupErrorKind::RateLimitExceeded { retry_after: 5 }.as_str(),
            "rate_limit_exceeded"
        );
        assert_eq!(SignupErrorKind::InternalError.as_str(), "internal_error");
    }

    #[test]
    fn failure_metadata_omits_unset_fields() {
        let m = failure_metadata(
            SignupErrorKind::NoMatchingInvite,
            "alice",
            None,
            None,
            false,
        );
        let obj = m.as_object().expect("object");
        assert_eq!(obj.get("username").and_then(|v| v.as_str()), Some("alice"));
        assert_eq!(obj.get("reason").and_then(|v| v.as_str()), Some("no_match"));
        assert!(!obj.contains_key("invite_id"));
        assert!(!obj.contains_key("email"));
        assert!(!obj.contains_key("open_signup"));
    }

    #[test]
    fn failure_metadata_includes_optional_fields() {
        let id = Uuid::new_v4();
        let m = failure_metadata(
            SignupErrorKind::SignupConflict,
            "bob",
            Some(id),
            Some("bob@example.com"),
            true,
        );
        let obj = m.as_object().expect("object");
        assert_eq!(
            obj.get("reason").and_then(|v| v.as_str()),
            Some("signup_conflict")
        );
        assert_eq!(
            obj.get("invite_id").and_then(|v| v.as_str()),
            Some(id.to_string()).as_deref()
        );
        assert_eq!(
            obj.get("email").and_then(|v| v.as_str()),
            Some("bob@example.com")
        );
        assert_eq!(
            obj.get("open_signup").and_then(serde_json::Value::as_bool),
            Some(true)
        );
    }

    #[test]
    fn success_metadata_includes_invite_id_when_invite_path() {
        let id = Uuid::new_v4();
        let m = success_metadata("alice", Some(id), false);
        let obj = m.as_object().expect("object");
        assert_eq!(obj.get("username").and_then(|v| v.as_str()), Some("alice"));
        assert!(obj.contains_key("invite_id"));
        assert!(!obj.contains_key("open_signup"));
    }

    #[test]
    fn success_metadata_flags_open_signup_path() {
        let m = success_metadata("alice", None, true);
        let obj = m.as_object().expect("object");
        assert!(!obj.contains_key("invite_id"));
        assert_eq!(
            obj.get("open_signup").and_then(serde_json::Value::as_bool),
            Some(true)
        );
    }
}
