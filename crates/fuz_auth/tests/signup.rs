//! Integration tests for `fuz_auth::signup` against a real `PostgreSQL`.
//!
//! Gated behind `#[ignore]` — run with:
//! ```text
//! createdb fuz_auth_test
//! cargo test -p fuz_auth -- --ignored signup
//! ```
//!
//! Override the DB URL with `FUZ_AUTH_TEST_URL=postgres://...`.

// Integration-test helpers assert via `expect`/`unwrap` (panic-on-failure is
// the test mechanism); `allow-*-in-tests` only covers `#[test]` fns, not the
// shared helper fns these files call.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use fuz_auth::{
    Argon2idHasher, AuditEmitter, PASSWORD_LENGTH_MAX, PasswordHasher, RateLimiter,
    RateLimiterOptions, SignupError, SignupErrorKind, SignupInput, SignupOptions,
    hash_session_token, signup_handler,
};
use fuz_db::Pool;

mod common;
use common::fresh_db_pool;

fn build_options(pool: Pool) -> SignupOptions {
    let hasher: Arc<dyn PasswordHasher> = Arc::new(Argon2idHasher::new());
    // Inflight tracking so `drain_inflight` is a real barrier: signup's
    // audit rows are fire-and-forget `emit` writes, so reading `audit_log`
    // without draining races the spawned INSERT.
    let audit = Arc::new(AuditEmitter::new_with_inflight_tracking(pool.clone()));
    SignupOptions {
        pool,
        password_hasher: hasher,
        audit,
        signup_ip_rate_limiter: None,
        signup_account_rate_limiter: None,
        // 0-ms floor in tests so denial paths don't add wall-clock.
        signup_fail_floor_ms: 0,
        signup_fail_jitter_ms: 0,
    }
}

async fn enable_open_signup(pool: &Pool) {
    let client = pool.get().await.expect("pool.get");
    client
        .execute(
            "UPDATE app_settings SET open_signup = true WHERE id = 1",
            &[],
        )
        .await
        .expect("update app_settings");
}

async fn seed_invite(pool: &Pool, email: Option<&str>, username: Option<&str>) -> uuid::Uuid {
    let client = pool.get().await.expect("pool.get");
    let row = client
        .query_one(
            "INSERT INTO invite (email, username) VALUES ($1, $2) RETURNING id",
            &[&email, &username],
        )
        .await
        .expect("insert invite");
    row.get(0)
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn signup_rejects_invalid_input() {
    let pool = fresh_db_pool().await;
    let options = build_options(pool);

    let err = signup_handler(
        &options,
        None,
        SignupInput {
            username: String::new(),
            password: "valid-password-123".into(),
            email: None,
        },
    )
    .await
    .expect_err("empty username should be rejected");

    assert!(matches!(
        err,
        SignupError::Classified {
            kind: SignupErrorKind::InvalidInput
        }
    ));

    let err = signup_handler(
        &options,
        None,
        SignupInput {
            username: "alice".into(),
            password: "short".into(),
            email: None,
        },
    )
    .await
    .expect_err("short password should be rejected");
    assert!(matches!(
        err,
        SignupError::Classified {
            kind: SignupErrorKind::InvalidInput
        }
    ));

    // Malformed email — rejected at input validation, before the invite
    // gate (so even un-gated it surfaces as InvalidInput, not
    // NoMatchingInvite). Mirrors the TS `Email` schema; `is_valid_email`
    // requires `local@domain.tld` shape.
    let err = signup_handler(
        &options,
        None,
        SignupInput {
            username: "alice".into(),
            password: "valid-password-123".into(),
            email: Some("notanemail".into()),
        },
    )
    .await
    .expect_err("malformed email should be rejected");
    assert!(matches!(
        err,
        SignupError::Classified {
            kind: SignupErrorKind::InvalidInput
        }
    ));
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn signup_no_matching_invite_when_invite_gated() {
    let pool = fresh_db_pool().await;
    let options = build_options(pool);

    let err = signup_handler(
        &options,
        None,
        SignupInput {
            username: "alice".into(),
            password: "valid-password-123".into(),
            email: None,
        },
    )
    .await
    .expect_err("no invite seeded");

    assert!(matches!(
        err,
        SignupError::Classified {
            kind: SignupErrorKind::NoMatchingInvite
        }
    ));
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn signup_succeeds_with_open_signup_and_creates_actor() {
    let pool = fresh_db_pool().await;
    enable_open_signup(&pool).await;
    let options = build_options(pool.clone());

    let success = signup_handler(
        &options,
        None,
        SignupInput {
            username: "Alice".into(),
            password: "valid-password-123".into(),
            email: None,
        },
    )
    .await
    .expect("open_signup success");

    assert_eq!(success.account.username, "alice", "username canonicalized");
    assert_eq!(success.actor.account_id, success.account.id);
    assert!(!success.session_token.is_empty());

    let client = pool.get().await.expect("pool.get");
    let row = client
        .query_one(
            "SELECT COUNT(*) FROM actor WHERE account_id = $1",
            &[&success.account.id],
        )
        .await
        .expect("actor count");
    let count: i64 = row.get(0);
    assert_eq!(count, 1, "exactly one actor per account");
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn signup_succeeds_with_matching_invite_and_claims_it() {
    let pool = fresh_db_pool().await;
    let invite_id = seed_invite(&pool, None, Some("alice")).await;
    let options = build_options(pool.clone());

    let success = signup_handler(
        &options,
        None,
        SignupInput {
            username: "alice".into(),
            password: "valid-password-123".into(),
            email: None,
        },
    )
    .await
    .expect("invite-gated signup");

    let client = pool.get().await.expect("pool.get");
    let row = client
        .query_one("SELECT claimed_by FROM invite WHERE id = $1", &[&invite_id])
        .await
        .expect("invite read");
    let claimed_by: Option<uuid::Uuid> = row.get(0);
    assert_eq!(claimed_by, Some(success.account.id));
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn signup_refuses_when_the_invite_claim_misses() {
    let pool = fresh_db_pool().await;
    let invite_id = seed_invite(&pool, None, Some("alice")).await;
    // A row trigger that skips every `invite` UPDATE: the claim matches no
    // row inside the signup tx, the state a broken FOR UPDATE invariant
    // would leave.
    pool.get()
        .await
        .expect("pool.get")
        .batch_execute(
            "CREATE FUNCTION skip_invite_update() RETURNS trigger LANGUAGE plpgsql AS \
             $$ BEGIN RETURN NULL; END $$; \
             CREATE TRIGGER skip_invite_update BEFORE UPDATE ON invite \
             FOR EACH ROW EXECUTE FUNCTION skip_invite_update();",
        )
        .await
        .expect("trigger DDL runs");
    let options = build_options(pool.clone());

    let err = signup_handler(
        &options,
        None,
        SignupInput {
            username: "alice".into(),
            password: "valid-password-123".into(),
            email: None,
        },
    )
    .await
    .expect_err("a missed claim refuses the signup");

    assert!(matches!(
        err,
        SignupError::Classified {
            kind: SignupErrorKind::InternalError
        }
    ));

    options.audit.drain_inflight().await;
    let client = pool.get().await.expect("pool.get");
    let accounts: i64 = client
        .query_one("SELECT count(*) FROM account WHERE username = 'alice'", &[])
        .await
        .expect("account count")
        .get(0);
    assert_eq!(accounts, 0, "the account rolled back");
    let claimed_by: Option<uuid::Uuid> = client
        .query_one("SELECT claimed_by FROM invite WHERE id = $1", &[&invite_id])
        .await
        .expect("invite read")
        .get(0);
    assert_eq!(claimed_by, None);
    let metadata_text: String = client
        .query_one(
            "SELECT metadata::text FROM audit_log
             WHERE event_type = 'signup' AND outcome = 'failure'
             ORDER BY seq DESC LIMIT 1",
            &[],
        )
        .await
        .expect("audit row")
        .get(0);
    let metadata: serde_json::Value =
        serde_json::from_str(&metadata_text).expect("parse audit metadata");
    assert_eq!(
        metadata.get("reason").and_then(|v| v.as_str()),
        Some("internal_error"),
        "metadata={metadata_text}"
    );
    let invite_id_text = invite_id.to_string();
    assert_eq!(
        metadata.get("invite_id").and_then(|v| v.as_str()),
        Some(invite_id_text.as_str()),
        "metadata={metadata_text}"
    );
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn signup_audits_a_failed_commit_as_internal_error() {
    let pool = fresh_db_pool().await;
    let invite_id = seed_invite(&pool, None, Some("alice")).await;
    // A deferred constraint trigger that raises at commit: every statement in
    // the signup tx succeeds and the `COMMIT` itself fails.
    pool.get()
        .await
        .expect("pool.get")
        .batch_execute(
            "CREATE FUNCTION fail_account_commit() RETURNS trigger LANGUAGE plpgsql AS \
             $$ BEGIN RAISE EXCEPTION 'commit refused'; END $$; \
             CREATE CONSTRAINT TRIGGER fail_account_commit AFTER INSERT ON account \
             DEFERRABLE INITIALLY DEFERRED \
             FOR EACH ROW EXECUTE FUNCTION fail_account_commit();",
        )
        .await
        .expect("trigger DDL runs");
    let ip_limiter = ip_limiter_of(1);
    let account_limiter = Arc::new(RateLimiter::new(RateLimiterOptions {
        max_attempts: 1,
        window_ms: 60_000,
        max_keys: None,
    }));
    let mut options = build_options(pool.clone());
    options.signup_ip_rate_limiter = Some(Arc::clone(&ip_limiter));
    options.signup_account_rate_limiter = Some(Arc::clone(&account_limiter));

    let err = signup_handler(&options, Some("10.0.0.9".to_owned()), signup_input("alice"))
        .await
        .expect_err("a failed commit refuses the signup");

    assert!(matches!(err, SignupError::Commit(_)), "{err:?}");
    // The attempt is released, not charged, on both buckets: a cap of one
    // still admits the next one.
    assert!(ip_limiter.check("10.0.0.9").is_allowed());
    assert!(account_limiter.check("alice").is_allowed());

    options.audit.drain_inflight().await;
    let client = pool.get().await.expect("pool.get");
    let accounts: i64 = client
        .query_one("SELECT count(*) FROM account WHERE username = 'alice'", &[])
        .await
        .expect("account count")
        .get(0);
    assert_eq!(accounts, 0, "the account rolled back");
    let claimed_by: Option<uuid::Uuid> = client
        .query_one("SELECT claimed_by FROM invite WHERE id = $1", &[&invite_id])
        .await
        .expect("invite read")
        .get(0);
    assert_eq!(claimed_by, None);
    let rows = client
        .query(
            "SELECT metadata::text FROM audit_log
             WHERE event_type = 'signup' AND outcome = 'failure'",
            &[],
        )
        .await
        .expect("audit rows");
    assert_eq!(rows.len(), 1, "one failure audit row");
    let metadata_text: String = rows[0].get(0);
    let metadata: serde_json::Value =
        serde_json::from_str(&metadata_text).expect("parse audit metadata");
    assert_eq!(
        metadata.get("reason").and_then(|v| v.as_str()),
        Some("internal_error"),
        "metadata={metadata_text}"
    );
    let invite_id_text = invite_id.to_string();
    assert_eq!(
        metadata.get("invite_id").and_then(|v| v.as_str()),
        Some(invite_id_text.as_str()),
        "metadata={metadata_text}"
    );
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn signup_conflict_on_duplicate_username() {
    let pool = fresh_db_pool().await;
    enable_open_signup(&pool).await;
    let options = build_options(pool.clone());

    signup_handler(
        &options,
        None,
        SignupInput {
            username: "alice".into(),
            password: "valid-password-123".into(),
            email: None,
        },
    )
    .await
    .expect("first signup");

    let err = signup_handler(
        &options,
        None,
        SignupInput {
            username: "Alice".into(), // case-insensitive collision
            password: "valid-password-123".into(),
            email: None,
        },
    )
    .await
    .expect_err("duplicate should conflict");

    assert!(matches!(
        err,
        SignupError::Classified {
            kind: SignupErrorKind::SignupConflict
        }
    ));
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn signup_rejects_oversized_password() {
    // `PASSWORD_LENGTH_MAX + 1` chars must bail with `InvalidInput`
    // without invoking Argon2 or hitting the DB — bounds the blake2b
    // ingestion cost on pathological inputs.
    let pool = fresh_db_pool().await;
    let options = build_options(pool);

    let err = signup_handler(
        &options,
        None,
        SignupInput {
            username: "alice".into(),
            password: "a".repeat(PASSWORD_LENGTH_MAX + 1),
            email: None,
        },
    )
    .await
    .expect_err("oversized password should be rejected");

    assert!(matches!(
        err,
        SignupError::Classified {
            kind: SignupErrorKind::InvalidInput
        }
    ));
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn signup_conflict_audit_preserves_invite_id() {
    // Conflict path on the invite branch must record `invite_id` in
    // audit metadata — forensic property tested in parallel to
    // `signup_emits_failure_audit_with_classified_reason` (which
    // covers the `no_match` path).
    let pool = fresh_db_pool().await;
    let invite_id = seed_invite(&pool, None, Some("alice")).await;
    let options = build_options(pool.clone());

    signup_handler(
        &options,
        Some("127.0.0.1".to_string()),
        SignupInput {
            username: "alice".into(),
            password: "valid-password-123".into(),
            email: None,
        },
    )
    .await
    .expect("first signup claims the invite");

    // Seed a second invite for the same username so the conflict path
    // (rather than `no_matching_invite`) fires on the retry.
    let _ = seed_invite(&pool, None, Some("alice")).await;

    let err = signup_handler(
        &options,
        Some("127.0.0.1".to_string()),
        SignupInput {
            username: "alice".into(),
            password: "valid-password-123".into(),
            email: None,
        },
    )
    .await
    .expect_err("duplicate username must conflict");

    assert!(matches!(
        err,
        SignupError::Classified {
            kind: SignupErrorKind::SignupConflict
        }
    ));

    options.audit.drain_inflight().await;

    let client = pool.get().await.expect("pool.get");
    // Filter on `outcome = 'failure'` so the assertion targets the
    // second signup's conflict row: the first signup's success row is
    // written fire-and-forget too, so `ORDER BY seq` alone doesn't pin
    // which of the two INSERTs landed last.
    let row = client
        .query_one(
            "SELECT outcome, metadata::text FROM audit_log
             WHERE event_type = 'signup' AND outcome = 'failure'
             ORDER BY seq DESC LIMIT 1",
            &[],
        )
        .await
        .expect("audit row");
    let outcome: String = row.get(0);
    let metadata_text: String = row.get(1);
    let metadata: serde_json::Value =
        serde_json::from_str(&metadata_text).expect("parse audit metadata");
    assert_eq!(outcome, "failure");
    assert_eq!(
        metadata.get("reason").and_then(|v| v.as_str()),
        Some("signup_conflict"),
        "metadata={metadata_text}"
    );
    // Both invite rows were unclaimed when the second signup ran; the
    // SQL ORDER BY picks the older one. Either id is acceptable —
    // assert presence.
    let observed_invite_id = metadata.get("invite_id").and_then(|v| v.as_str());
    assert!(
        observed_invite_id.is_some() || metadata_text.contains(&invite_id.to_string()),
        "metadata={metadata_text}"
    );
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn signup_rate_limit_bypasses_deadline_floor() {
    // 429 must short-circuit BEFORE the deadline floor — verifies the
    // fast-path contract. Set a non-zero floor so an applied floor
    // would be observable as wall-clock; assert the 429 returns well
    // under it.
    let pool = fresh_db_pool().await;
    let hasher: Arc<dyn PasswordHasher> = Arc::new(Argon2idHasher::new());
    let audit = Arc::new(AuditEmitter::new(pool.clone()));
    let ip_limiter = Arc::new(RateLimiter::new(RateLimiterOptions {
        max_attempts: 1,
        window_ms: 60_000,
        max_keys: None,
    }));
    let options = SignupOptions {
        pool,
        password_hasher: hasher,
        audit,
        signup_ip_rate_limiter: Some(Arc::clone(&ip_limiter)),
        signup_account_rate_limiter: None,
        // 500ms floor — if the 429 path applied it, the test would
        // observe a multi-hundred-ms wall-clock. The assertion below
        // catches that regression.
        signup_fail_floor_ms: 500,
        signup_fail_jitter_ms: 0,
    };

    // Burn the bucket.
    ip_limiter.record("10.0.0.1");

    let start = std::time::Instant::now();
    let err = signup_handler(
        &options,
        Some("10.0.0.1".to_string()),
        SignupInput {
            username: "alice".into(),
            password: "valid-password-123".into(),
            email: None,
        },
    )
    .await
    .expect_err("rate-limit exhausted");
    let elapsed = start.elapsed();

    assert!(matches!(
        err,
        SignupError::Classified {
            kind: SignupErrorKind::RateLimitExceeded { .. }
        }
    ));
    assert!(
        elapsed < std::time::Duration::from_millis(100),
        "429 took {elapsed:?} — floor was applied (should be fast-path)"
    );
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn signup_ip_limit_buckets_ipv6_by_64() {
    let pool = fresh_db_pool().await;
    let ip_limiter = Arc::new(RateLimiter::new(RateLimiterOptions {
        max_attempts: 1,
        window_ms: 60_000,
        max_keys: None,
    }));
    let options = SignupOptions {
        signup_ip_rate_limiter: Some(Arc::clone(&ip_limiter)),
        ..build_options(pool)
    };
    let input = |username: &str| SignupInput {
        username: username.into(),
        password: "valid-password-123".into(),
        email: None,
    };

    // Spend the /64's one attempt: invite-gated with no invite, it records.
    let err = signup_handler(
        &options,
        Some("2001:db8:1:2::1".to_string()),
        input("alice"),
    )
    .await
    .expect_err("no invite");
    assert!(matches!(
        err,
        SignupError::Classified {
            kind: SignupErrorKind::NoMatchingInvite
        }
    ));

    // Another address in the same /64 draws the same budget.
    let err = signup_handler(
        &options,
        Some("2001:db8:1:2:8000::2".to_string()),
        input("bob"),
    )
    .await
    .expect_err("same /64");
    assert!(
        matches!(
            err,
            SignupError::Classified {
                kind: SignupErrorKind::RateLimitExceeded { .. }
            }
        ),
        "{err:?}"
    );

    // The next /64 has its own.
    let err = signup_handler(
        &options,
        Some("2001:db8:1:3::1".to_string()),
        input("carol"),
    )
    .await
    .expect_err("no invite");
    assert!(matches!(
        err,
        SignupError::Classified {
            kind: SignupErrorKind::NoMatchingInvite
        }
    ));
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn signup_creates_session_row() {
    // Asserts the basic correctness chain — signup landing implies a
    // matching `auth_session` row keyed by the blake3 hash of the
    // returned session token.
    let pool = fresh_db_pool().await;
    enable_open_signup(&pool).await;
    let options = build_options(pool.clone());

    let success = signup_handler(
        &options,
        None,
        SignupInput {
            username: "alice".into(),
            password: "valid-password-123".into(),
            email: None,
        },
    )
    .await
    .expect("signup ok");

    let token_hash = hash_session_token(&success.session_token);
    let client = pool.get().await.expect("pool.get");
    // `auth_session.id` is the blake3 token-hash itself (TEXT PRIMARY KEY
    // per `migrations/full_auth_schema.sql`); there is no separate
    // `token_hash` column on this table.
    let row = client
        .query_one(
            "SELECT account_id FROM auth_session WHERE id = $1",
            &[&token_hash.as_str()],
        )
        .await
        .expect("session row");
    let account_id: uuid::Uuid = row.get(0);
    assert_eq!(account_id, success.account.id);
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn signup_email_only_invite_matches_email_only() {
    let pool = fresh_db_pool().await;
    let _invite_id = seed_invite(&pool, Some("alice@example.com"), None).await;
    let options = build_options(pool);

    // Wrong email — no match.
    let err = signup_handler(
        &options,
        None,
        SignupInput {
            username: "alice".into(),
            password: "valid-password-123".into(),
            email: Some("eve@example.com".into()),
        },
    )
    .await
    .expect_err("non-matching email");
    assert!(matches!(
        err,
        SignupError::Classified {
            kind: SignupErrorKind::NoMatchingInvite
        }
    ));

    // Correct email — any username — claims the invite.
    let success = signup_handler(
        &options,
        None,
        SignupInput {
            username: "anybody".into(),
            password: "valid-password-123".into(),
            email: Some("alice@example.com".into()),
        },
    )
    .await
    .expect("email-only invite");
    assert_eq!(success.account.username, "anybody");
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn signup_both_field_invite_requires_both_to_match() {
    let pool = fresh_db_pool().await;
    let _invite_id = seed_invite(&pool, Some("alice@example.com"), Some("alice")).await;
    let options = build_options(pool);

    // Matching username only — fails (invite requires email too).
    let err = signup_handler(
        &options,
        None,
        SignupInput {
            username: "alice".into(),
            password: "valid-password-123".into(),
            email: Some("other@example.com".into()),
        },
    )
    .await
    .expect_err("username matches but email doesn't");
    assert!(matches!(
        err,
        SignupError::Classified {
            kind: SignupErrorKind::NoMatchingInvite
        }
    ));

    // Matching email only — fails (invite requires username too).
    let err = signup_handler(
        &options,
        None,
        SignupInput {
            username: "bob".into(),
            password: "valid-password-123".into(),
            email: Some("alice@example.com".into()),
        },
    )
    .await
    .expect_err("email matches but username doesn't");
    assert!(matches!(
        err,
        SignupError::Classified {
            kind: SignupErrorKind::NoMatchingInvite
        }
    ));

    // Both match — succeeds and claims.
    signup_handler(
        &options,
        None,
        SignupInput {
            username: "alice".into(),
            password: "valid-password-123".into(),
            email: Some("alice@example.com".into()),
        },
    )
    .await
    .expect("both-field invite ok");
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn signup_concurrent_invite_claim_is_atomic() {
    // The load-bearing concurrency property — FOR UPDATE inside the
    // signup tx must serialize find + claim so at most one of two
    // concurrent signups for the same invite wins. Loser's
    // `find_for_update` returns no row after the winner commits and
    // falls through to `no_matching_invite`. No second account
    // persists.
    let pool = fresh_db_pool().await;
    let invite_id = seed_invite(&pool, None, Some("alice")).await;
    let options = Arc::new(build_options(pool.clone()));

    let options_a = Arc::clone(&options);
    let options_b = Arc::clone(&options);
    let (a, b) = tokio::join!(
        tokio::spawn(async move {
            signup_handler(
                &options_a,
                None,
                SignupInput {
                    username: "alice".into(),
                    password: "valid-password-123".into(),
                    email: None,
                },
            )
            .await
        }),
        tokio::spawn(async move {
            signup_handler(
                &options_b,
                None,
                SignupInput {
                    username: "alice".into(),
                    password: "valid-password-123".into(),
                    email: None,
                },
            )
            .await
        }),
    );
    let a = a.expect("task a panic");
    let b = b.expect("task b panic");

    // Exactly one succeeds; the other returns NoMatchingInvite (the
    // loser's find_for_update saw the post-commit row state) OR
    // SignupConflict (rarer ordering — winner committed account
    // creation just before loser's create runs).
    let (winner, loser) = match (a, b) {
        (Ok(s), Err(e)) | (Err(e), Ok(s)) => (s, e),
        (Ok(_), Ok(_)) => panic!("both signups succeeded — FOR UPDATE broken"),
        (Err(ea), Err(eb)) => panic!("both signups failed: {ea:?} / {eb:?}"),
    };
    assert!(matches!(
        loser,
        SignupError::Classified {
            kind: SignupErrorKind::NoMatchingInvite | SignupErrorKind::SignupConflict
        }
    ));

    // Invite must be claimed by the winner.
    let client = pool.get().await.expect("pool.get");
    let row = client
        .query_one("SELECT claimed_by FROM invite WHERE id = $1", &[&invite_id])
        .await
        .expect("invite read");
    let claimed_by: Option<uuid::Uuid> = row.get(0);
    assert_eq!(claimed_by, Some(winner.account.id));

    // Exactly one account row exists for the canonical username.
    let row = client
        .query_one("SELECT COUNT(*) FROM account WHERE username = 'alice'", &[])
        .await
        .expect("account count");
    let count: i64 = row.get(0);
    assert_eq!(count, 1, "exactly one account survived the race");
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn signup_emits_failure_audit_with_classified_reason() {
    let pool = fresh_db_pool().await;
    let options = build_options(pool.clone());

    let _ = signup_handler(
        &options,
        Some("127.0.0.1".to_string()),
        SignupInput {
            username: "alice".into(),
            password: "valid-password-123".into(),
            email: None,
        },
    )
    .await;

    // Audit emit is fire-and-forget — wait for the write to land.
    options.audit.drain_inflight().await;

    let client = pool.get().await.expect("pool.get");
    let row = client
        .query_one(
            "SELECT outcome, metadata::text FROM audit_log
             WHERE event_type = 'signup' AND outcome = 'failure'
             ORDER BY seq DESC LIMIT 1",
            &[],
        )
        .await
        .expect("audit row");
    let outcome: String = row.get(0);
    let metadata_text: String = row.get(1);
    let metadata: serde_json::Value =
        serde_json::from_str(&metadata_text).expect("parse audit metadata");
    assert_eq!(outcome, "failure");
    assert_eq!(
        metadata.get("reason").and_then(|v| v.as_str()),
        Some("no_match"),
        "metadata={metadata_text}"
    );
    assert_eq!(
        metadata.get("username").and_then(|v| v.as_str()),
        Some("alice"),
        "metadata={metadata_text}"
    );
}

fn ip_limiter_of(max_attempts: u32) -> Arc<RateLimiter> {
    Arc::new(RateLimiter::new(RateLimiterOptions {
        max_attempts,
        window_ms: 60_000,
        max_keys: None,
    }))
}

fn signup_input(username: &str) -> SignupInput {
    SignupInput {
        username: username.into(),
        password: "valid-password-123".into(),
        email: None,
    }
}

const fn is_rate_limited(result: &Result<fuz_auth::SignupSuccess, SignupError>) -> bool {
    matches!(
        result,
        Err(SignupError::Classified {
            kind: SignupErrorKind::RateLimitExceeded { .. }
        })
    )
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn signup_open_successes_count_toward_the_ip_limit() {
    // With no invite to spend, an open signup is charged to the IP bucket like
    // a failure — otherwise one address mints accounts without bound.
    let pool = fresh_db_pool().await;
    enable_open_signup(&pool).await;
    let ip_limiter = ip_limiter_of(2);
    let mut options = build_options(pool);
    options.signup_ip_rate_limiter = Some(Arc::clone(&ip_limiter));
    let ip = Some("10.0.0.7".to_owned());

    signup_handler(&options, ip.clone(), signup_input("open_one"))
        .await
        .expect("first open signup");
    signup_handler(&options, ip.clone(), signup_input("open_two"))
        .await
        .expect("second open signup");
    let third = signup_handler(&options, ip, signup_input("open_three")).await;

    assert!(is_rate_limited(&third), "{:?}", third.map(|s| s.account.id));
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn signup_invite_success_does_not_count_toward_the_ip_limit() {
    // An invite-gated success spends an invite an admin minted, so it charges
    // nothing: a class signing up on invites from one address keeps going.
    let pool = fresh_db_pool().await;
    seed_invite(&pool, None, Some("invited_one")).await;
    seed_invite(&pool, None, Some("invited_two")).await;
    let ip_limiter = ip_limiter_of(1);
    let mut options = build_options(pool);
    options.signup_ip_rate_limiter = Some(Arc::clone(&ip_limiter));
    let ip = Some("10.0.0.8".to_owned());

    signup_handler(&options, ip.clone(), signup_input("invited_one"))
        .await
        .expect("first invited signup");
    signup_handler(&options, ip, signup_input("invited_two"))
        .await
        .expect("second invited signup, past a cap of one");
    assert!(ip_limiter.check("10.0.0.8").is_allowed());
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn signup_burst_gets_at_most_the_ip_cap_past_the_limiter() {
    // Invite-gated with no invites: every attempt hashes and then fails
    // `no_matching_invite`. A check before the hash let the whole concurrent
    // burst through; the reservation lets exactly the cap through.
    let pool = fresh_db_pool().await;
    let ip_limiter = ip_limiter_of(2);
    let mut options = build_options(pool);
    options.signup_ip_rate_limiter = Some(Arc::clone(&ip_limiter));

    let results = futures::future::join_all((0..4).map(|i| {
        signup_handler(
            &options,
            Some("10.0.0.9".to_owned()),
            signup_input(&format!("burst_{i}")),
        )
    }))
    .await;

    let refused = results
        .iter()
        .filter(|r| {
            matches!(
                r,
                Err(SignupError::Classified {
                    kind: SignupErrorKind::NoMatchingInvite
                })
            )
        })
        .count();
    let limited = results.iter().filter(|r| is_rate_limited(r)).count();
    assert_eq!((refused, limited), (2, 2));
}

/// A [`PasswordHasher`] whose `hash` never finishes, signalling `started` once
/// it is first polled — the Argon2 work a request is dropped in the middle of.
struct ParkedHasher {
    started: Arc<tokio::sync::Notify>,
}

impl PasswordHasher for ParkedHasher {
    fn hash(
        &self,
        _password: String,
    ) -> futures::future::BoxFuture<
        'static,
        Result<fuz_auth::HashedPassword, fuz_auth::PasswordHashError>,
    > {
        let started = Arc::clone(&self.started);
        Box::pin(async move {
            started.notify_one();
            std::future::pending().await
        })
    }

    fn verify(
        &self,
        _password: String,
        _hash: String,
    ) -> futures::future::BoxFuture<'static, bool> {
        Box::pin(std::future::pending())
    }

    fn dummy_hash(&self) -> &'static str {
        "parked-dummy-hash"
    }
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn signup_dropped_mid_hash_costs_an_attempt_on_each_bucket() {
    // The Argon2 hash a dropped request started runs on regardless, so the
    // attempt is charged as a failure: releasing it would let one address keep
    // every Argon2 permit busy uncharged.
    let pool = fresh_db_pool().await;
    let started = Arc::new(tokio::sync::Notify::new());
    let ip_limiter = ip_limiter_of(1);
    let account_limiter = ip_limiter_of(1);
    let mut options = build_options(pool);
    options.password_hasher = Arc::new(ParkedHasher {
        started: Arc::clone(&started),
    });
    options.signup_ip_rate_limiter = Some(Arc::clone(&ip_limiter));
    options.signup_account_rate_limiter = Some(Arc::clone(&account_limiter));

    let parked = tokio::select! {
        _ = signup_handler(&options, Some("10.0.0.9".to_owned()), signup_input("dropped_mid_hash")) => false,
        () = started.notified() => true,
    };

    assert!(parked, "the signup finished before its hash started");
    assert!(!ip_limiter.check("10.0.0.9").is_allowed(), "IP bucket");
    assert!(
        !account_limiter.check("dropped_mid_hash").is_allowed(),
        "account bucket"
    );
}

/// A [`PasswordHasher`] whose `hash` checks out a connection from `pool` and
/// keeps it, then finishes at once — over a one-connection pool, the signup's
/// next checkout, the first after its hash, waits for good.
struct PoolHoldingHasher {
    pool: Pool,
    held: Arc<std::sync::Mutex<Vec<fuz_db::PoolClient>>>,
    hashed: Arc<tokio::sync::Notify>,
}

impl PasswordHasher for PoolHoldingHasher {
    fn hash(
        &self,
        _password: String,
    ) -> futures::future::BoxFuture<
        'static,
        Result<fuz_auth::HashedPassword, fuz_auth::PasswordHashError>,
    > {
        let pool = self.pool.clone();
        let held = Arc::clone(&self.held);
        let hashed = Arc::clone(&self.hashed);
        Box::pin(async move {
            let client = pool.get().await.expect("pool.get");
            held.lock().expect("held").push(client);
            hashed.notify_one();
            Ok(fuz_auth::HashedPassword::new("held-hash".to_owned()))
        })
    }

    fn verify(
        &self,
        _password: String,
        _hash: String,
    ) -> futures::future::BoxFuture<'static, bool> {
        Box::pin(std::future::pending())
    }

    fn dummy_hash(&self) -> &'static str {
        "held-dummy-hash"
    }
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn signup_dropped_after_its_hash_costs_an_attempt_on_each_bucket() {
    // The hash is spent by the time the database steps after it run, so a
    // request dropped there — here, parked on the checkout that follows the
    // hash — is charged as one dropped mid-hash is.
    let pool = fresh_db_pool().await;
    pool.resize(1);
    let hashed = Arc::new(tokio::sync::Notify::new());
    let held = Arc::new(std::sync::Mutex::new(Vec::new()));
    let ip_limiter = ip_limiter_of(1);
    let account_limiter = ip_limiter_of(1);
    let mut options = build_options(pool.clone());
    options.password_hasher = Arc::new(PoolHoldingHasher {
        pool,
        held: Arc::clone(&held),
        hashed: Arc::clone(&hashed),
    });
    options.signup_ip_rate_limiter = Some(Arc::clone(&ip_limiter));
    options.signup_account_rate_limiter = Some(Arc::clone(&account_limiter));

    let parked = tokio::select! {
        _ = signup_handler(&options, Some("10.0.0.10".to_owned()), signup_input("dropped_after_hash")) => false,
        () = hashed.notified() => true,
    };

    assert!(parked, "the signup finished before its hash did");
    assert_eq!(
        held.lock().expect("held").len(),
        1,
        "the hash holds the pool"
    );
    assert!(!ip_limiter.check("10.0.0.10").is_allowed(), "IP bucket");
    assert!(
        !account_limiter.check("dropped_after_hash").is_allowed(),
        "account bucket"
    );
}
