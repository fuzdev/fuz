//! Integration tests for `fuz_auth::bootstrap` against a real `PostgreSQL`.
//!
//! Twin of `fuz_app`'s `src/lib/auth/bootstrap_account.ts` +
//! `src/test/auth/bootstrap_account.db.test.ts`. The TS spine is canonical for
//! shape; these pin the same observable contract on the Rust side, drawing the
//! intended properties from `fuz_app/docs/security.md` §"Bootstrap":
//!
//! - **Constant-time token compare** — a wrong token is rejected, the correct
//!   token accepted (Rust uses `subtle::ConstantTimeEq`; TS `timingSafeEqual`).
//!   A single trailing `\n` on the stored token is tolerated (operator
//!   convention) before the compare.
//! - **Atomic `bootstrap_lock` race guard** — the single-row latch UPDATE
//!   serializes concurrent bootstraps so exactly one wins (TOCTOU close).
//! - **Fail-closed availability** — bootstrap refuses when no token store is
//!   configured, when the in-memory `bootstrap_available` flag is already
//!   cleared, and after it has been consumed once.
//! - **One-shot token deletion** — the token is deleted post-commit and the
//!   availability flag flips, permanently deactivating the endpoint.
//! - **Input validation** — the token, username, and password bounds are
//!   enforced before the window and the token are read: a malformed body is
//!   `InvalidInput` with no audit row, a token past
//!   `BOOTSTRAP_TOKEN_LENGTH_MAX` included.
//! - **Minimum token length** — a token file under `BOOTSTRAP_TOKEN_MIN_BYTES`
//!   (after its one trailing newline) reads as unreadable on both the request
//!   path and `is_bootstrap_available`, however exactly a caller matches it.
//!
//! Gated behind `#[ignore]` — run with:
//! ```text
//! createdb fuz_auth_test
//! cargo test -p fuz_auth --test bootstrap -- --ignored --test-threads=1
//! ```
//!
//! Override the DB URL with `FUZ_AUTH_TEST_URL=postgres://...`.

// Integration-test helpers assert via `expect`/`unwrap` (panic-on-failure is
// the test mechanism); `allow-*-in-tests` only covers `#[test]` fns, not the
// shared helper fns these files call.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use futures::future::BoxFuture;
use fuz_auth::error::BootstrapErrorKind;
use fuz_auth::{
    Argon2idHasher, AuditEmitter, BOOTSTRAP_TOKEN_LENGTH_MAX, BootstrapError, BootstrapInput,
    BootstrapKeeperResolved, BootstrapOptions, BootstrapTokenStore, PasswordHasher, ROLE_ADMIN,
    ROLE_KEEPER, bootstrap_handler, hash_session_token, is_bootstrap_available,
};
use fuz_db::Pool;
use uuid::Uuid;

mod common;
use common::fresh_db_pool;

/// In-memory [`BootstrapTokenStore`]. `read_token` returns the configured
/// bytes (or an I/O error to exercise `token_file_missing`); `delete_token`
/// flips a flag so the one-shot deletion is observable.
struct InMemoryTokenStore {
    token: Vec<u8>,
    read_fails: bool,
    deleted: Arc<AtomicBool>,
}

impl InMemoryTokenStore {
    /// Build a store returning `token`, plus the shared `deleted` flag.
    fn with_token(token: &[u8]) -> (Arc<dyn BootstrapTokenStore>, Arc<AtomicBool>) {
        let deleted = Arc::new(AtomicBool::new(false));
        let store = Arc::new(Self {
            token: token.to_vec(),
            read_fails: false,
            deleted: Arc::clone(&deleted),
        });
        (store, deleted)
    }

    /// Build a store whose `read_token` errors (simulates a missing file).
    fn missing() -> Arc<dyn BootstrapTokenStore> {
        Arc::new(Self {
            token: Vec::new(),
            read_fails: true,
            deleted: Arc::new(AtomicBool::new(false)),
        })
    }
}

impl BootstrapTokenStore for InMemoryTokenStore {
    fn read_token(&self) -> BoxFuture<'_, io::Result<Vec<u8>>> {
        let token = self.token.clone();
        let fails = self.read_fails;
        Box::pin(async move {
            if fails {
                Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "token file missing",
                ))
            } else {
                Ok(token)
            }
        })
    }

    fn delete_token(&self) -> BoxFuture<'_, io::Result<()>> {
        let deleted = Arc::clone(&self.deleted);
        Box::pin(async move {
            deleted.store(true, Ordering::SeqCst);
            Ok(())
        })
    }
}

/// Records the account id passed to `on_keeper_resolved` so tests can assert
/// the post-bootstrap keeper callback fired with the new keeper account.
struct RecordingKeeper {
    account_id: Arc<Mutex<Option<Uuid>>>,
}

impl RecordingKeeper {
    fn create() -> (Arc<dyn BootstrapKeeperResolved>, Arc<Mutex<Option<Uuid>>>) {
        let account_id = Arc::new(Mutex::new(None));
        let cb = Arc::new(Self {
            account_id: Arc::clone(&account_id),
        });
        (cb, account_id)
    }
}

impl BootstrapKeeperResolved for RecordingKeeper {
    fn on_keeper_resolved(&self, account_id: Uuid) -> BoxFuture<'static, ()> {
        let slot = Arc::clone(&self.account_id);
        Box::pin(async move {
            *slot.lock().unwrap() = Some(account_id);
        })
    }
}

/// Assemble `BootstrapOptions` from the supplied token store + availability
/// flag, with a real Argon2id hasher and a pool-routed audit emitter.
fn build_options(
    pool: Pool,
    token_store: Option<Arc<dyn BootstrapTokenStore>>,
    bootstrap_available: Arc<AtomicBool>,
    on_keeper_resolved: Option<Arc<dyn BootstrapKeeperResolved>>,
) -> BootstrapOptions {
    let password_hasher: Arc<dyn PasswordHasher> = Arc::new(Argon2idHasher::new());
    BootstrapOptions {
        pool: pool.clone(),
        password_hasher,
        // Inflight tracking so `drain_inflight` is a real barrier — `emit`
        // spawns a detached write, so asserting on `audit_log` without draining
        // races the spawn. That race is benign for a positive assertion (it
        // usually wins) and fatal for a negative one, which is what
        // `bootstrap_probe_after_success_writes_no_audit_row` needs.
        audit: Arc::new(AuditEmitter::new_with_inflight_tracking(pool)),
        bootstrap_available,
        token_store,
        on_keeper_resolved,
    }
}

fn input(token: &str, username: &str, password: &str) -> BootstrapInput {
    BootstrapInput {
        token: token.to_owned(),
        username: username.to_owned(),
        password: password.to_owned(),
    }
}

/// `COUNT(*)` over the `account` table — the one-account invariant guard.
async fn account_count(pool: &Pool) -> i64 {
    let client = pool.get().await.expect("pool.get");
    client
        .query_one("SELECT COUNT(*) FROM account", &[])
        .await
        .expect("account count")
        .get(0)
}

/// `COUNT(*)` over `bootstrap` failure audit rows.
///
/// Drain the emitter before calling this for a negative assertion — see
/// `build_options`.
async fn bootstrap_failure_count(pool: &Pool) -> i64 {
    let client = pool.get().await.expect("pool.get");
    client
        .query_one(
            "SELECT COUNT(*) FROM audit_log
             WHERE event_type = 'bootstrap' AND outcome = 'failure'",
            &[],
        )
        .await
        .expect("bootstrap failure count")
        .get(0)
}

/// Read the latest `bootstrap` failure audit row's `metadata.error`.
async fn latest_bootstrap_failure_error(pool: &Pool) -> String {
    let client = pool.get().await.expect("pool.get");
    let row = client
        .query_one(
            "SELECT metadata::text FROM audit_log
             WHERE event_type = 'bootstrap' AND outcome = 'failure'
             ORDER BY seq DESC LIMIT 1",
            &[],
        )
        .await
        .expect("audit row");
    let metadata: serde_json::Value =
        serde_json::from_str::<serde_json::Value>(&row.get::<_, String>(0)).expect("metadata json");
    metadata
        .get("error")
        .and_then(|v| v.as_str())
        .expect("error field")
        .to_owned()
}

// -- Constant-time token compare --------------------------------------------

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn bootstrap_rejects_invalid_token() {
    let pool = fresh_db_pool().await;
    let (token_store, _deleted) =
        InMemoryTokenStore::with_token(b"correct-token-0123456789abcdefghij");
    let available = Arc::new(AtomicBool::new(true));
    let options = build_options(
        pool.clone(),
        Some(token_store),
        Arc::clone(&available),
        None,
    );

    let err = bootstrap_handler(
        &options,
        Some("1.2.3.4".to_owned()),
        input("wrong-token", "admin", "valid-password-123"),
    )
    .await
    .expect_err("wrong token must be rejected");

    assert!(matches!(
        err,
        BootstrapError::Classified {
            kind: BootstrapErrorKind::InvalidToken
        }
    ));
    assert_eq!(latest_bootstrap_failure_error(&pool).await, "invalid_token");
    assert_eq!(
        account_count(&pool).await,
        0,
        "no account on a rejected token"
    );
    assert!(
        available.load(Ordering::SeqCst),
        "a rejected token must leave bootstrap available"
    );
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn bootstrap_tolerates_single_trailing_newline() {
    // Operator-written token files commonly carry a trailing `\n`; the handler
    // strips exactly one before the constant-time compare.
    let pool = fresh_db_pool().await;
    let (token_store, _deleted) =
        InMemoryTokenStore::with_token(b"correct-token-0123456789abcdefghij\n");
    let available = Arc::new(AtomicBool::new(true));
    let options = build_options(pool.clone(), Some(token_store), available, None);

    bootstrap_handler(
        &options,
        None,
        input(
            "correct-token-0123456789abcdefghij",
            "admin",
            "valid-password-123",
        ),
    )
    .await
    .expect("token with one trailing newline must match");
}

// -- Success: one-shot deletion + keeper callback + fail-closed flip ---------

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn bootstrap_succeeds_and_consumes_the_token() {
    let pool = fresh_db_pool().await;
    let (token_store, deleted) =
        InMemoryTokenStore::with_token(b"correct-token-0123456789abcdefghij");
    let available = Arc::new(AtomicBool::new(true));
    let (keeper_cb, keeper_seen) = RecordingKeeper::create();
    let options = build_options(
        pool.clone(),
        Some(token_store),
        Arc::clone(&available),
        Some(keeper_cb),
    );

    let success = bootstrap_handler(
        &options,
        Some("1.2.3.4".to_owned()),
        input(
            "correct-token-0123456789abcdefghij",
            "Keeper",
            "valid-password-123",
        ),
    )
    .await
    .expect("bootstrap success");

    assert_eq!(success.account.username, "keeper", "username canonicalized");
    assert_eq!(success.actor.account_id, success.account.id);

    let client = pool.get().await.expect("pool.get");

    // Keeper + admin role grants on the bootstrap actor.
    let roles: Vec<String> = client
        .query(
            "SELECT role FROM role_grant WHERE actor_id = $1 ORDER BY role",
            &[&success.actor.id],
        )
        .await
        .expect("role grants")
        .iter()
        .map(|r| r.get(0))
        .collect();
    assert_eq!(roles, vec![ROLE_ADMIN.to_owned(), ROLE_KEEPER.to_owned()]);

    // Session row keyed by the blake3 hash of the issued token.
    let token_hash = hash_session_token(&success.session_token);
    let session_account: Uuid = client
        .query_one(
            "SELECT account_id FROM auth_session WHERE id = $1",
            &[&token_hash.as_str()],
        )
        .await
        .expect("session row")
        .get(0);
    assert_eq!(session_account, success.account.id);

    // Success audit row attributed to the new actor + account.
    let row = client
        .query_one(
            "SELECT outcome, actor_id, account_id FROM audit_log
             WHERE event_type = 'bootstrap' AND outcome = 'success'
             ORDER BY seq DESC LIMIT 1",
            &[],
        )
        .await
        .expect("audit row");
    let outcome: String = row.get(0);
    let actor_id: Option<Uuid> = row.get(1);
    let account_id: Option<Uuid> = row.get(2);
    assert_eq!(outcome, "success");
    assert_eq!(actor_id, Some(success.actor.id));
    assert_eq!(account_id, Some(success.account.id));

    // One-shot: token deleted, availability flipped, lock latched.
    assert!(
        deleted.load(Ordering::SeqCst),
        "token must be deleted post-commit"
    );
    assert!(
        !available.load(Ordering::SeqCst),
        "bootstrap_available must flip to false after success"
    );
    assert_eq!(
        keeper_seen.lock().unwrap().as_ref(),
        Some(&success.account.id),
        "keeper callback must fire with the new keeper account id"
    );
    let bootstrapped: bool = client
        .query_one("SELECT bootstrapped FROM bootstrap_lock WHERE id = 1", &[])
        .await
        .expect("lock row")
        .get(0);
    assert!(bootstrapped, "bootstrap_lock must be latched");
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn bootstrap_second_call_after_success_refuses() {
    // After a successful bootstrap the in-memory flag is cleared, so a second
    // attempt with the same (still-readable) token is refused — refuses once
    // consumed, exactly one account survives.
    let pool = fresh_db_pool().await;
    let (token_store, _deleted) =
        InMemoryTokenStore::with_token(b"correct-token-0123456789abcdefghij");
    let available = Arc::new(AtomicBool::new(true));
    let options = build_options(
        pool.clone(),
        Some(token_store),
        Arc::clone(&available),
        None,
    );

    bootstrap_handler(
        &options,
        None,
        input(
            "correct-token-0123456789abcdefghij",
            "keeper",
            "valid-password-123",
        ),
    )
    .await
    .expect("first bootstrap succeeds");

    let err = bootstrap_handler(
        &options,
        None,
        input(
            "correct-token-0123456789abcdefghij",
            "intruder",
            "valid-password-123",
        ),
    )
    .await
    .expect_err("second bootstrap must be refused");
    assert!(matches!(
        err,
        BootstrapError::Classified {
            kind: BootstrapErrorKind::AlreadyBootstrapped
        }
    ));
    assert_eq!(
        account_count(&pool).await,
        1,
        "exactly one account survives"
    );
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn bootstrap_probe_after_success_writes_no_audit_row() {
    // A bootstrapped server writes nothing in response to bootstrap probes.
    //
    // The route stays mounted for the life of the process and the origin gate
    // admits any caller sending no `Origin`, so an audit emit on the
    // already-bootstrapped leg is an unauthenticated `audit_log` INSERT per
    // request — unbounded, permanent, and with no retention job to reclaim it.
    // Pinned as a property rather than as the absence of a specific call, so it
    // survives a refactor of the short-circuit.
    let pool = fresh_db_pool().await;
    let (token_store, _deleted) =
        InMemoryTokenStore::with_token(b"correct-token-0123456789abcdefghij");
    let available = Arc::new(AtomicBool::new(true));
    let options = build_options(
        pool.clone(),
        Some(token_store),
        Arc::clone(&available),
        None,
    );

    bootstrap_handler(
        &options,
        None,
        input(
            "correct-token-0123456789abcdefghij",
            "keeper",
            "valid-password-123",
        ),
    )
    .await
    .expect("first bootstrap succeeds");

    options.audit.drain_inflight().await;
    let baseline = bootstrap_failure_count(&pool).await;

    for i in 0..20 {
        let err = bootstrap_handler(
            &options,
            Some("1.2.3.4".to_owned()),
            input(&format!("junk-{i}"), "intruder", "valid-password-123"),
        )
        .await
        .expect_err("probe after success must be refused");
        assert!(matches!(
            err,
            BootstrapError::Classified {
                kind: BootstrapErrorKind::AlreadyBootstrapped
            }
        ));
    }

    options.audit.drain_inflight().await;
    assert_eq!(
        bootstrap_failure_count(&pool).await,
        baseline,
        "post-bootstrap probes must not grow the audit log"
    );
    assert_eq!(
        account_count(&pool).await,
        1,
        "exactly one account survives"
    );
}

// -- Fail-closed availability -----------------------------------------------

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn bootstrap_without_a_token_store_answers_already_bootstrapped() {
    // No token store ⇒ bootstrap disabled (fail-closed), refused as
    // `AlreadyBootstrapped` — the twin's answer with no token path, so an
    // unconfigured deployment reads as a bootstrapped one — no account, and
    // no audit row: this leg is reachable for the whole life of a process
    // that never configured bootstrap, so an emit here would be an
    // unauthenticated unbounded write channel.
    let pool = fresh_db_pool().await;
    let available = Arc::new(AtomicBool::new(true));
    let options = build_options(pool.clone(), None, available, None);

    let err = bootstrap_handler(
        &options,
        Some("1.2.3.4".to_owned()),
        input("anything", "admin", "valid-password-123"),
    )
    .await
    .expect_err("no token store ⇒ refused");
    assert!(matches!(
        err,
        BootstrapError::Classified {
            kind: BootstrapErrorKind::AlreadyBootstrapped
        }
    ));
    options.audit.drain_inflight().await;
    assert_eq!(
        bootstrap_failure_count(&pool).await,
        0,
        "an unconfigured refusal must write no audit row"
    );
    assert_eq!(account_count(&pool).await, 0);
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn bootstrap_refuses_when_unavailable() {
    // The early in-memory check short-circuits before any file read / crypto
    // when `bootstrap_available` is already false — refuses even with a valid
    // token (`fuz_app` `docs/security.md` §Bootstrap "Early in-memory check").
    let pool = fresh_db_pool().await;
    let (token_store, deleted) =
        InMemoryTokenStore::with_token(b"correct-token-0123456789abcdefghij");
    let available = Arc::new(AtomicBool::new(false));
    let options = build_options(pool.clone(), Some(token_store), available, None);

    let err = bootstrap_handler(
        &options,
        Some("1.2.3.4".to_owned()),
        input(
            "correct-token-0123456789abcdefghij",
            "admin",
            "valid-password-123",
        ),
    )
    .await
    .expect_err("unavailable ⇒ refused");
    assert!(matches!(
        err,
        BootstrapError::Classified {
            kind: BootstrapErrorKind::AlreadyBootstrapped
        }
    ));
    options.audit.drain_inflight().await;
    assert_eq!(
        bootstrap_failure_count(&pool).await,
        0,
        "a closed-window refusal must write no audit row"
    );
    assert_eq!(account_count(&pool).await, 0);
    assert!(
        !deleted.load(Ordering::SeqCst),
        "short-circuit must not touch the token file"
    );
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn bootstrap_token_file_missing() {
    let pool = fresh_db_pool().await;
    let available = Arc::new(AtomicBool::new(true));
    let options = build_options(
        pool.clone(),
        Some(InMemoryTokenStore::missing()),
        available,
        None,
    );

    let err = bootstrap_handler(
        &options,
        None,
        input("anything", "admin", "valid-password-123"),
    )
    .await
    .expect_err("token read failure ⇒ token_file_missing");
    assert!(matches!(
        err,
        BootstrapError::Classified {
            kind: BootstrapErrorKind::TokenFileMissing
        }
    ));
    assert_eq!(
        latest_bootstrap_failure_error(&pool).await,
        "token_file_missing"
    );
    assert_eq!(account_count(&pool).await, 0);
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn token_file_missing_closes_the_window() {
    // An unreadable token file means bootstrap can never succeed, so leaving
    // the window advertised as open reopens the exact channel the
    // closed-window legs exist to close: one `audit_log` INSERT per request,
    // forever, from any unauthenticated caller — here triggered by an operator
    // deleting the token or narrowing its permissions after boot.
    // `is_bootstrap_available` already reads an unreadable file as closed; the
    // request path has to agree, and closing the door is the fix rather than
    // rate-limiting the knocking.
    let pool = fresh_db_pool().await;
    let available = Arc::new(AtomicBool::new(true));
    let options = build_options(
        pool.clone(),
        Some(InMemoryTokenStore::missing()),
        Arc::clone(&available),
        None,
    );

    let first = bootstrap_handler(
        &options,
        None,
        input("anything", "admin", "valid-password-123"),
    )
    .await
    .expect_err("token read failure ⇒ token_file_missing");
    assert!(matches!(
        first,
        BootstrapError::Classified {
            kind: BootstrapErrorKind::TokenFileMissing
        }
    ));
    assert!(
        !available.load(Ordering::SeqCst),
        "an unreadable token file must close the window"
    );

    // The second attempt now takes the closed-window short-circuit, which is
    // the write-free one. Without the flip this would be a second INSERT, and
    // so would every request after it.
    let second = bootstrap_handler(
        &options,
        None,
        input("anything", "admin", "valid-password-123"),
    )
    .await
    .expect_err("closed window ⇒ already_bootstrapped");
    assert!(matches!(
        second,
        BootstrapError::Classified {
            kind: BootstrapErrorKind::AlreadyBootstrapped
        }
    ));

    options.audit.drain_inflight().await;
    assert_eq!(
        bootstrap_failure_count(&pool).await,
        1,
        "only the attempt that found the window open is forensically interesting"
    );
    assert_eq!(account_count(&pool).await, 0);
}

/// A token under the minimum length — empty, a lone newline, one byte short
/// with or without its newline — reads as unreadable: `token_file_missing`
/// and the window closes, even for a caller who presents its exact bytes.
/// One at exactly the minimum bootstraps.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn a_token_under_the_minimum_length_reads_as_missing() {
    // the minimum is 32 bytes, written out rather than derived from
    // `BOOTSTRAP_TOKEN_MIN_BYTES`, so changing the constant fails here
    let short = "k".repeat(31);
    for (stored, provided) in [
        // a provided token can't be empty (the body check answers first)
        (String::new(), "x".to_owned()),
        ("\n".to_owned(), "x".to_owned()),
        (short.clone(), short.clone()),
        (format!("{short}\n"), short.clone()),
    ] {
        let pool = fresh_db_pool().await;
        let available = Arc::new(AtomicBool::new(true));
        let (token_store, deleted) = InMemoryTokenStore::with_token(stored.as_bytes());
        let options = build_options(
            pool.clone(),
            Some(token_store),
            Arc::clone(&available),
            None,
        );
        let err = bootstrap_handler(
            &options,
            None,
            input(&provided, "admin", "valid-password-123"),
        )
        .await
        .expect_err("a short token never matches");
        assert!(
            matches!(
                err,
                BootstrapError::Classified {
                    kind: BootstrapErrorKind::TokenFileMissing
                }
            ),
            "{stored:?}: {err:?}"
        );
        assert!(
            !available.load(Ordering::SeqCst),
            "{stored:?} closes the window"
        );
        assert!(!deleted.load(Ordering::SeqCst), "{stored:?} stays on disk");
        assert_eq!(account_count(&pool).await, 0);
    }

    let pool = fresh_db_pool().await;
    let token = "k".repeat(32);
    let (token_store, _deleted) = InMemoryTokenStore::with_token(format!("{token}\n").as_bytes());
    let options = build_options(
        pool.clone(),
        Some(token_store),
        Arc::new(AtomicBool::new(true)),
        None,
    );
    bootstrap_handler(&options, None, input(&token, "admin", "valid-password-123"))
        .await
        .expect("a token at the minimum bootstraps");
}

/// `is_bootstrap_available` reads a token file under the minimum length as
/// unavailable, exactly as the request path does; one at the minimum is
/// available.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn availability_refuses_a_token_file_under_the_minimum_length() {
    use std::os::unix::fs::PermissionsExt;
    let pool = fresh_db_pool().await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("secret_bootstrap_token");
    let write = |contents: &str| {
        std::fs::write(&path, contents).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    };
    let path_str = path.to_str().unwrap();
    for contents in [
        String::new(),
        "\n".to_owned(),
        // the minimum written out, as in the request-path test above
        format!("{}\n", "k".repeat(31)),
    ] {
        write(&contents);
        assert!(
            !is_bootstrap_available(&pool, Some(path_str)).await,
            "{contents:?}"
        );
    }
    write(&format!("{}\n", "k".repeat(32)));
    assert!(is_bootstrap_available(&pool, Some(path_str)).await);
}

// -- Input validation (before the window and token checks) ------------------

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn bootstrap_rejects_invalid_input_before_the_token_check() {
    // The body is validated before the window and the token are: even with a
    // matching token, an out-of-bounds password (< 12 chars) is rejected, and
    // no account is created.
    let pool = fresh_db_pool().await;
    let (token_store, _deleted) =
        InMemoryTokenStore::with_token(b"correct-token-0123456789abcdefghij");
    let available = Arc::new(AtomicBool::new(true));
    let options = build_options(pool.clone(), Some(token_store), available, None);

    let err = bootstrap_handler(
        &options,
        None,
        input("correct-token-0123456789abcdefghij", "admin", "short"),
    )
    .await
    .expect_err("short password must be rejected");
    assert!(matches!(
        err,
        BootstrapError::Classified {
            kind: BootstrapErrorKind::InvalidInput
        }
    ));
    assert_eq!(account_count(&pool).await, 0);
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn bootstrap_refuses_a_token_past_its_maximum_as_invalid_input() {
    // A token past `BOOTSTRAP_TOKEN_LENGTH_MAX` UTF-16 code units is a
    // malformed body, as the twin's `max_length` makes it: refused in the open
    // window before the token is compared, with no failure audit row, and the
    // window left open. The control at the cap is a wrong token, refused at the
    // compare with its row.
    let pool = fresh_db_pool().await;
    let (token_store, _deleted) =
        InMemoryTokenStore::with_token(b"correct-token-0123456789abcdefghij");
    let available = Arc::new(AtomicBool::new(true));
    let options = build_options(
        pool.clone(),
        Some(token_store),
        Arc::clone(&available),
        None,
    );

    let astral = "\u{1F600}".repeat(BOOTSTRAP_TOKEN_LENGTH_MAX / 2);
    for token in [
        "x".repeat(BOOTSTRAP_TOKEN_LENGTH_MAX + 1),
        "\u{00E9}".repeat(BOOTSTRAP_TOKEN_LENGTH_MAX + 1),
        format!("{astral}a"),
    ] {
        let err = bootstrap_handler(
            &options,
            Some("1.2.3.4".to_owned()),
            input(&token, "admin", "valid-password-123"),
        )
        .await
        .expect_err("an over-long token must be refused");
        assert!(
            matches!(
                err,
                BootstrapError::Classified {
                    kind: BootstrapErrorKind::InvalidInput
                }
            ),
            "{} units: {err:?}",
            token.encode_utf16().count()
        );
    }
    options.audit.drain_inflight().await;
    assert_eq!(
        bootstrap_failure_count(&pool).await,
        0,
        "a malformed body writes no audit row"
    );
    assert!(
        available.load(Ordering::SeqCst),
        "a malformed body leaves the window open"
    );

    let err = bootstrap_handler(
        &options,
        Some("1.2.3.4".to_owned()),
        input(&astral, "admin", "valid-password-123"),
    )
    .await
    .expect_err("a wrong token at the cap must be refused at the compare");
    assert!(matches!(
        err,
        BootstrapError::Classified {
            kind: BootstrapErrorKind::InvalidToken
        }
    ));
    options.audit.drain_inflight().await;
    assert_eq!(latest_bootstrap_failure_error(&pool).await, "invalid_token");
    assert_eq!(account_count(&pool).await, 0);

    // The shape gate runs before the window check: with the window closed, a
    // token past the maximum is still a malformed body, and the control at the
    // cap is the closed window.
    available.store(false, Ordering::SeqCst);
    let err = bootstrap_handler(
        &options,
        Some("1.2.3.4".to_owned()),
        input(
            &"x".repeat(BOOTSTRAP_TOKEN_LENGTH_MAX + 1),
            "admin",
            "valid-password-123",
        ),
    )
    .await
    .expect_err("an over-long token must be refused in a closed window");
    assert!(
        matches!(
            err,
            BootstrapError::Classified {
                kind: BootstrapErrorKind::InvalidInput
            }
        ),
        "{err:?}"
    );
    let err = bootstrap_handler(
        &options,
        Some("1.2.3.4".to_owned()),
        input(&astral, "admin", "valid-password-123"),
    )
    .await
    .expect_err("a token at the cap meets the closed window");
    assert!(
        matches!(
            err,
            BootstrapError::Classified {
                kind: BootstrapErrorKind::AlreadyBootstrapped
            }
        ),
        "{err:?}"
    );
}

// -- Atomic bootstrap_lock race guard ---------------------------------------

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn bootstrap_lock_serializes_concurrent_attempts() {
    // The load-bearing concurrency property: the single-row `bootstrap_lock`
    // latch UPDATE (`... WHERE bootstrapped = false RETURNING id`) serializes
    // two concurrent bootstraps so exactly one wins; the loser's UPDATE matches
    // zero rows, rolls back, and returns AlreadyBootstrapped. One account total.
    let pool = fresh_db_pool().await;
    let (token_store, _deleted) =
        InMemoryTokenStore::with_token(b"correct-token-0123456789abcdefghij");
    let available = Arc::new(AtomicBool::new(true));
    let options = Arc::new(build_options(
        pool.clone(),
        Some(token_store),
        available,
        None,
    ));

    let options_a = Arc::clone(&options);
    let options_b = Arc::clone(&options);
    let (a, b) = tokio::join!(
        tokio::spawn(async move {
            bootstrap_handler(
                &options_a,
                None,
                input(
                    "correct-token-0123456789abcdefghij",
                    "keeper",
                    "valid-password-123",
                ),
            )
            .await
        }),
        tokio::spawn(async move {
            bootstrap_handler(
                &options_b,
                None,
                input(
                    "correct-token-0123456789abcdefghij",
                    "keeper",
                    "valid-password-123",
                ),
            )
            .await
        }),
    );
    let a = a.expect("task a panic");
    let b = b.expect("task b panic");

    let loser = match (a, b) {
        (Ok(_), Err(e)) | (Err(e), Ok(_)) => e,
        (Ok(_), Ok(_)) => panic!("both bootstraps succeeded — lock latch broken"),
        (Err(ea), Err(eb)) => panic!("both bootstraps failed: {ea:?} / {eb:?}"),
    };
    assert!(matches!(
        loser,
        BootstrapError::Classified {
            kind: BootstrapErrorKind::AlreadyBootstrapped
        }
    ));
    assert_eq!(
        account_count(&pool).await,
        1,
        "exactly one account survives the race"
    );
}
