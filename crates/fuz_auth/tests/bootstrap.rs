//! Integration tests for `fuz_auth::bootstrap` against a live database.
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
//! - **One-shot token burn** — the token is burned last inside the bootstrap
//!   transaction, before the commit; a failed burn rolls the bootstrap back
//!   and leaves the window open, and a success flips the availability flag,
//!   permanently deactivating the endpoint.
//! - **Per-IP limiter** — a refused attempt is charged, the lock-race loser
//!   is not.
//! - **Input validation** — the token, username, and password bounds are
//!   enforced before the window and the token are read: a malformed body is
//!   `InvalidInput` with no audit row, a token past
//!   `BOOTSTRAP_TOKEN_LENGTH_MAX` included.
//! - **Minimum token length** — a token file under `BOOTSTRAP_TOKEN_MIN_BYTES`
//!   (after its one trailing newline) reads as unreadable on both the request
//!   path and `is_bootstrap_available`, however exactly a caller matches it.

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test helpers outside `#[test]` fns panic on a failed setup or check"
)]

use std::io;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use futures::future::BoxFuture;
use fuz_auth::error::BootstrapErrorKind;
use fuz_auth::keyring::MIN_KEY_LENGTH;
use fuz_auth::{
    Argon2idHasher, AuditEmitter, BOOTSTRAP_TOKEN_LENGTH_MAX, BootstrapError, BootstrapInput,
    BootstrapKeeperResolved, BootstrapOptions, BootstrapTokenStore, FileBootstrapTokenStore,
    Keyring, PasswordHasher, ROLE_ADMIN, ROLE_KEEPER, RateLimiter, RateLimiterOptions,
    SESSION_COOKIE_NAME, bootstrap_handler, hash_session_token, is_bootstrap_available,
};
use fuz_db::Pool;
use fuz_sys::secure_file::BurnOutcome;
use uuid::Uuid;

mod common;
use common::{fresh_db, fresh_postgres_db};

/// In-memory [`BootstrapTokenStore`] that models the burn: `read_token`
/// returns the configured bytes until `burn_token` takes them, then fails as a
/// missing file does; a store built with [`Self::undeletable`] refuses the
/// burn and keeps the token, as a directory the server can't write does.
struct InMemoryTokenStore {
    token: Mutex<Option<Vec<u8>>>,
    burn_fails: bool,
    burned: Arc<AtomicBool>,
}

impl InMemoryTokenStore {
    fn build(
        token: Option<&[u8]>,
        burn_fails: bool,
    ) -> (Arc<dyn BootstrapTokenStore>, Arc<AtomicBool>) {
        let burned = Arc::new(AtomicBool::new(false));
        let store = Arc::new(Self {
            token: Mutex::new(token.map(<[u8]>::to_vec)),
            burn_fails,
            burned: Arc::clone(&burned),
        });
        (store, burned)
    }

    /// Build a store holding `token`, plus the shared `burned` flag.
    fn with_token(token: &[u8]) -> (Arc<dyn BootstrapTokenStore>, Arc<AtomicBool>) {
        Self::build(Some(token), false)
    }

    /// Build a store holding `token` whose burn fails and keeps it.
    fn undeletable(token: &[u8]) -> (Arc<dyn BootstrapTokenStore>, Arc<AtomicBool>) {
        Self::build(Some(token), true)
    }

    /// Build a store whose `read_token` errors (simulates a missing file).
    fn missing() -> Arc<dyn BootstrapTokenStore> {
        Self::build(None, false).0
    }
}

impl BootstrapTokenStore for InMemoryTokenStore {
    fn read_token(&self) -> BoxFuture<'_, io::Result<Vec<u8>>> {
        let token = self.token.lock().unwrap().clone();
        Box::pin(async move {
            token.ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "token file missing"))
        })
    }

    fn burn_token(&self) -> BoxFuture<'_, io::Result<BurnOutcome>> {
        let result = if self.burn_fails {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "token directory not writable",
            ))
        } else {
            self.burned.store(true, Ordering::SeqCst);
            let taken = self.token.lock().unwrap().take();
            Ok(if taken.is_some() {
                BurnOutcome::Burned
            } else {
                BurnOutcome::AlreadyGone
            })
        };
        Box::pin(async move { result })
    }
}

/// A [`BootstrapTokenStore`] whose burn looks at the database from another
/// connection, to pin where in the transaction the burn runs: the lock flip is
/// not yet committed (the burn precedes the commit), and the `bootstrap_lock`
/// row is already locked (the burn follows the lock UPDATE).
struct ProbingTokenStore {
    pool: Pool,
    token: Vec<u8>,
    seen: Arc<Mutex<Option<BurnProbe>>>,
}

/// What [`ProbingTokenStore`] saw at the burn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BurnProbe {
    committed_bootstrapped: bool,
    lock_row_held: bool,
}

impl BootstrapTokenStore for ProbingTokenStore {
    fn read_token(&self) -> BoxFuture<'_, io::Result<Vec<u8>>> {
        let token = self.token.clone();
        Box::pin(async move { Ok(token) })
    }

    fn burn_token(&self) -> BoxFuture<'_, io::Result<BurnOutcome>> {
        Box::pin(async move {
            let client = self.pool.get().await.expect("pool.get");
            let committed_bootstrapped: bool = client
                .query_one("SELECT bootstrapped FROM bootstrap_lock WHERE id = 1", &[])
                .await
                .expect("lock read")
                .get(0);
            let lock_row_held = client
                .query(
                    "SELECT id FROM bootstrap_lock WHERE id = 1 FOR UPDATE NOWAIT",
                    &[],
                )
                .await
                .is_err();
            *self.seen.lock().unwrap() = Some(BurnProbe {
                committed_bootstrapped,
                lock_row_held,
            });
            Ok(BurnOutcome::Burned)
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
/// flag, with a real Argon2id hasher.
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
        // A failure row is a spawned write, so asserting on `audit_log`
        // without `drain_inflight` races the spawn. That race is benign for a
        // positive assertion (it usually wins) and fatal for a negative one,
        // which is what `bootstrap_probe_after_success_writes_no_audit_row`
        // needs.
        audit: Arc::new(AuditEmitter::new(pool, Arc::default())),
        bootstrap_available,
        token_store,
        on_keeper_resolved,
        bootstrap_ip_rate_limiter: None,
        keyring: Arc::new(Keyring::new(&"k".repeat(MIN_KEY_LENGTH)).unwrap()),
        session_cookie_name: SESSION_COOKIE_NAME,
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

/// Read the latest `bootstrap` failure audit row's `metadata.error`, once
/// every failure row in flight has landed — a failure row is spawned, never
/// awaited by the handler.
async fn latest_bootstrap_failure_error(options: &BootstrapOptions) -> String {
    options.audit.drain_inflight().await;
    let client = options.pool.get().await.expect("pool.get");
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
async fn bootstrap_rejects_invalid_token() {
    let pool = fresh_db().await;
    let (token_store, _burned) =
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
    assert_eq!(
        latest_bootstrap_failure_error(&options).await,
        "invalid_token"
    );
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
async fn bootstrap_tolerates_single_trailing_newline() {
    // Operator-written token files commonly carry a trailing `\n`; the handler
    // strips exactly one before the constant-time compare.
    let pool = fresh_db().await;
    let (token_store, _burned) =
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
async fn bootstrap_succeeds_and_consumes_the_token() {
    let pool = fresh_db().await;
    let (token_store, burned) =
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

    // One-shot: token burned, availability flipped, lock latched.
    assert!(burned.load(Ordering::SeqCst), "token must be burned");
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
async fn bootstrap_second_call_after_success_refuses() {
    // After a successful bootstrap the in-memory flag is cleared, so a second
    // attempt with the same (still-readable) token is refused — refuses once
    // consumed, exactly one account survives.
    let pool = fresh_db().await;
    let (token_store, _burned) =
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
async fn bootstrap_probe_after_success_writes_no_audit_row() {
    // A bootstrapped server writes nothing in response to bootstrap probes.
    //
    // The route stays mounted for the life of the process and the origin gate
    // admits any caller sending no `Origin`, so an audit emit on the
    // already-bootstrapped leg is an unauthenticated `audit_log` INSERT per
    // request — unbounded, permanent, and with no retention job to reclaim it.
    // Pinned as a property rather than as the absence of a specific call, so it
    // survives a refactor of the short-circuit.
    let pool = fresh_db().await;
    let (token_store, _burned) =
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
async fn bootstrap_without_a_token_store_answers_already_bootstrapped() {
    // No token store ⇒ bootstrap disabled (fail-closed), refused as
    // `AlreadyBootstrapped` — the twin's answer with no token path, so an
    // unconfigured deployment reads as a bootstrapped one — no account, and
    // no audit row: this leg is reachable for the whole life of a process
    // that never configured bootstrap, so an emit here would be an
    // unauthenticated unbounded write channel.
    let pool = fresh_db().await;
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
async fn bootstrap_refuses_when_unavailable() {
    // The early in-memory check short-circuits before any file read / crypto
    // when `bootstrap_available` is already false — refuses even with a valid
    // token (`fuz_app` `docs/security.md` §Bootstrap "Early in-memory check").
    let pool = fresh_db().await;
    let (token_store, burned) =
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
        !burned.load(Ordering::SeqCst),
        "short-circuit must not touch the token file"
    );
}

#[tokio::test]
async fn bootstrap_token_file_missing() {
    let pool = fresh_db().await;
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
        latest_bootstrap_failure_error(&options).await,
        "token_file_missing"
    );
    assert_eq!(account_count(&pool).await, 0);
}

#[tokio::test]
async fn token_file_missing_closes_the_window() {
    // An unreadable token file means bootstrap can never succeed, so leaving
    // the window advertised as open reopens the exact channel the
    // closed-window legs exist to close: one `audit_log` INSERT per request,
    // forever, from any unauthenticated caller — here triggered by an operator
    // deleting the token or narrowing its permissions after boot.
    // `is_bootstrap_available` already reads an unreadable file as closed; the
    // request path has to agree, and closing the door is the fix rather than
    // rate-limiting the knocking.
    let pool = fresh_db().await;
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
        let pool = fresh_db().await;
        let available = Arc::new(AtomicBool::new(true));
        let (token_store, burned) = InMemoryTokenStore::with_token(stored.as_bytes());
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
        assert!(!burned.load(Ordering::SeqCst), "{stored:?} stays on disk");
        assert_eq!(account_count(&pool).await, 0);
        // the failure row lands before the next case resets the schema
        options.audit.drain_inflight().await;
    }

    let pool = fresh_db().await;
    let token = "k".repeat(32);
    let (token_store, _burned) = InMemoryTokenStore::with_token(format!("{token}\n").as_bytes());
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
async fn availability_refuses_a_token_file_under_the_minimum_length() {
    use std::os::unix::fs::PermissionsExt;
    let pool = fresh_db().await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("secret_bootstrap_token");
    let write = |contents: &str| {
        std::fs::write(&path, contents).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    };
    for contents in [
        String::new(),
        "\n".to_owned(),
        // the minimum written out, as in the request-path test above
        format!("{}\n", "k".repeat(31)),
    ] {
        write(&contents);
        assert!(
            !is_bootstrap_available(&pool, Some(&path)).await.unwrap(),
            "{contents:?}"
        );
    }
    write(&format!("{}\n", "k".repeat(32)));
    assert!(is_bootstrap_available(&pool, Some(&path)).await.unwrap());
}

// -- Input validation (before the window and token checks) ------------------

#[tokio::test]
async fn bootstrap_rejects_invalid_input_before_the_token_check() {
    // The body is validated before the window and the token are: even with a
    // matching token, an out-of-bounds password (< 12 chars) is rejected, and
    // no account is created.
    let pool = fresh_db().await;
    let (token_store, _burned) =
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
async fn bootstrap_refuses_a_token_past_its_maximum_as_invalid_input() {
    // A token past `BOOTSTRAP_TOKEN_LENGTH_MAX` UTF-16 code units is a
    // malformed body, as the twin's `max_length` makes it: refused in the open
    // window before the token is compared, with no failure audit row, and the
    // window left open. The control at the cap is a wrong token, refused at the
    // compare with its row.
    let pool = fresh_db().await;
    let (token_store, _burned) =
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
    assert_eq!(
        latest_bootstrap_failure_error(&options).await,
        "invalid_token"
    );
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
async fn bootstrap_lock_serializes_concurrent_attempts() {
    // The load-bearing concurrency property: the single-row `bootstrap_lock`
    // latch UPDATE (`... WHERE bootstrapped = false RETURNING id`) serializes
    // two concurrent bootstraps so exactly one wins; the loser's UPDATE matches
    // zero rows, rolls back, and returns AlreadyBootstrapped. One account total.
    let pool = fresh_db().await;
    let (token_store, _burned) =
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

// -- The burn: last inside the transaction, required -------------------------

const TOKEN: &str = "correct-token-0123456789abcdefghij";

/// `bootstrap_lock.bootstrapped` as committed.
async fn lock_bootstrapped(pool: &Pool) -> bool {
    let client = pool.get().await.expect("pool.get");
    client
        .query_one("SELECT bootstrapped FROM bootstrap_lock WHERE id = 1", &[])
        .await
        .expect("lock row")
        .get(0)
}

/// `COUNT(*)` over `auth_session`.
async fn session_count(pool: &Pool) -> i64 {
    let client = pool.get().await.expect("pool.get");
    client
        .query_one("SELECT COUNT(*) FROM auth_session", &[])
        .await
        .expect("session count")
        .get(0)
}

/// The burn runs after the lock UPDATE (the row is locked when it runs) and
/// before the commit (the flip is not yet visible to another connection).
#[tokio::test]
async fn the_burn_runs_after_the_lock_and_before_the_commit() {
    let pool = fresh_db().await;
    let seen = Arc::new(Mutex::new(None));
    let store: Arc<dyn BootstrapTokenStore> = Arc::new(ProbingTokenStore {
        pool: pool.clone(),
        token: TOKEN.as_bytes().to_vec(),
        seen: Arc::clone(&seen),
    });
    let options = build_options(
        pool.clone(),
        Some(store),
        Arc::new(AtomicBool::new(true)),
        None,
    );

    bootstrap_handler(&options, None, input(TOKEN, "keeper", "valid-password-123"))
        .await
        .expect("bootstrap succeeds");

    assert_eq!(
        *seen.lock().unwrap(),
        Some(BurnProbe {
            committed_bootstrapped: false,
            lock_row_held: true,
        }),
        "the burn ran inside the transaction, after the lock UPDATE"
    );
    assert!(lock_bootstrapped(&pool).await);
}

/// A failed burn rolls the whole bootstrap back — no account, no session, the
/// lock unflipped — answers `token_file_undeletable` with its audit row, and
/// leaves the window open, so a retry with the same token succeeds once the
/// file can be burned.
#[tokio::test]
async fn a_failed_burn_rolls_the_bootstrap_back_and_leaves_the_window_open() {
    let pool = fresh_db().await;
    let available = Arc::new(AtomicBool::new(true));
    let (token_store, _burned) = InMemoryTokenStore::undeletable(TOKEN.as_bytes());
    let options = build_options(
        pool.clone(),
        Some(token_store),
        Arc::clone(&available),
        None,
    );

    let err = bootstrap_handler(
        &options,
        Some("1.2.3.4".to_owned()),
        input(TOKEN, "keeper", "valid-password-123"),
    )
    .await
    .expect_err("an undeletable token refuses the bootstrap");
    assert!(
        matches!(
            err,
            BootstrapError::Classified {
                kind: BootstrapErrorKind::TokenFileUndeletable
            }
        ),
        "{err:?}"
    );
    assert_eq!(account_count(&pool).await, 0, "the account rolled back");
    assert_eq!(session_count(&pool).await, 0, "the session rolled back");
    assert!(!lock_bootstrapped(&pool).await, "the lock rolled back");
    assert!(available.load(Ordering::SeqCst), "the window stays open");
    options.audit.drain_inflight().await;
    assert_eq!(
        latest_bootstrap_failure_error(&options).await,
        "token_file_undeletable"
    );

    // the operator fixes the directory and retries the same token
    let (token_store, burned) = InMemoryTokenStore::with_token(TOKEN.as_bytes());
    let retry = build_options(pool.clone(), Some(token_store), available, None);
    bootstrap_handler(&retry, None, input(TOKEN, "keeper", "valid-password-123"))
        .await
        .expect("the retry bootstraps");
    assert!(burned.load(Ordering::SeqCst));
    assert_eq!(account_count(&pool).await, 1);
}

/// A token file gone by the time of the burn is burned: the postcondition —
/// no token at the path — holds, so the bootstrap commits.
#[tokio::test]
async fn a_token_already_gone_at_the_burn_counts_as_burned() {
    struct GoneAtBurn;
    impl BootstrapTokenStore for GoneAtBurn {
        fn read_token(&self) -> BoxFuture<'_, io::Result<Vec<u8>>> {
            Box::pin(async { Ok(TOKEN.as_bytes().to_vec()) })
        }
        fn burn_token(&self) -> BoxFuture<'_, io::Result<BurnOutcome>> {
            Box::pin(async { Ok(BurnOutcome::AlreadyGone) })
        }
    }
    let pool = fresh_db().await;
    let options = build_options(
        pool.clone(),
        Some(Arc::new(GoneAtBurn)),
        Arc::new(AtomicBool::new(true)),
        None,
    );
    bootstrap_handler(&options, None, input(TOKEN, "keeper", "valid-password-123"))
        .await
        .expect("an already-gone token is burned");
    assert_eq!(account_count(&pool).await, 1);
}

/// The lock-race loser — the window open in memory, the lock already flipped
/// in the database — burns nothing, writes no audit row, closes the window,
/// and is not charged to the limiter.
#[tokio::test]
async fn the_lock_race_loser_burns_nothing_writes_nothing_and_is_not_charged() {
    let pool = fresh_db().await;
    pool.get()
        .await
        .expect("pool.get")
        .execute(
            "UPDATE bootstrap_lock SET bootstrapped = true WHERE id = 1",
            &[],
        )
        .await
        .expect("flip the lock");
    let available = Arc::new(AtomicBool::new(true));
    let (token_store, burned) = InMemoryTokenStore::with_token(TOKEN.as_bytes());
    let limiter = Arc::new(RateLimiter::new(RateLimiterOptions {
        max_attempts: 1,
        window_ms: 60_000,
        max_keys: None,
    }));
    let mut options = build_options(
        pool.clone(),
        Some(token_store),
        Arc::clone(&available),
        None,
    );
    options.bootstrap_ip_rate_limiter = Some(Arc::clone(&limiter));

    let err = bootstrap_handler(
        &options,
        Some("1.2.3.4".to_owned()),
        input(TOKEN, "keeper", "valid-password-123"),
    )
    .await
    .expect_err("the loser is refused");
    assert!(
        matches!(
            err,
            BootstrapError::Classified {
                kind: BootstrapErrorKind::AlreadyBootstrapped
            }
        ),
        "{err:?}"
    );
    assert!(!burned.load(Ordering::SeqCst), "the loser burns nothing");
    assert!(!available.load(Ordering::SeqCst), "the window closes");
    options.audit.drain_inflight().await;
    assert_eq!(bootstrap_failure_count(&pool).await, 0, "no audit row");
    assert!(
        limiter
            .check(&fuz_http::rate_limit_ip_key("1.2.3.4"))
            .is_allowed(),
        "the loser is not charged"
    );
}

/// Every refusal inside the open window is charged to the per-IP limiter, and
/// past the cap the attempt answers `rate_limit_exceeded` before the token is
/// read, with no audit row.
#[tokio::test]
async fn the_ip_limiter_charges_refused_attempts() {
    let pool = fresh_db().await;
    let (token_store, _burned) = InMemoryTokenStore::with_token(TOKEN.as_bytes());
    let mut options = build_options(
        pool.clone(),
        Some(token_store),
        Arc::new(AtomicBool::new(true)),
        None,
    );
    options.bootstrap_ip_rate_limiter = Some(Arc::new(RateLimiter::new(RateLimiterOptions {
        max_attempts: 2,
        window_ms: 60_000,
        max_keys: None,
    })));
    for _ in 0..2 {
        let err = bootstrap_handler(
            &options,
            Some("1.2.3.4".to_owned()),
            input("wrong-token", "keeper", "valid-password-123"),
        )
        .await
        .expect_err("a wrong token is refused");
        assert!(matches!(
            err,
            BootstrapError::Classified {
                kind: BootstrapErrorKind::InvalidToken
            }
        ));
    }
    let err = bootstrap_handler(
        &options,
        Some("1.2.3.4".to_owned()),
        input(TOKEN, "keeper", "valid-password-123"),
    )
    .await
    .expect_err("past the cap");
    assert!(
        matches!(
            err,
            BootstrapError::Classified {
                kind: BootstrapErrorKind::RateLimitExceeded { .. }
            }
        ),
        "{err:?}"
    );
    options.audit.drain_inflight().await;
    assert_eq!(bootstrap_failure_count(&pool).await, 2);
    assert_eq!(account_count(&pool).await, 0);
}

/// A missing `bootstrap_lock` row reads as unavailable, even with a good
/// token file — the window would otherwise be advertised while every attempt
/// is refused in its transaction.
#[tokio::test]
async fn availability_refuses_a_missing_lock_row() {
    use std::os::unix::fs::PermissionsExt;
    let pool = fresh_db().await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("secret_bootstrap_token");
    std::fs::write(&path, format!("{TOKEN}\n")).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(
        is_bootstrap_available(&pool, Some(&path)).await.unwrap(),
        "control"
    );
    pool.get()
        .await
        .expect("pool.get")
        .execute("DELETE FROM bootstrap_lock", &[])
        .await
        .expect("delete the lock row");
    assert!(!is_bootstrap_available(&pool, Some(&path)).await.unwrap());
}

/// A bootstrapped database is unavailable whether or not a token file is
/// still there.
#[tokio::test]
async fn availability_is_closed_on_a_bootstrapped_database_with_a_token_file() {
    use std::os::unix::fs::PermissionsExt;
    let pool = fresh_db().await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("secret_bootstrap_token");
    std::fs::write(&path, format!("{TOKEN}\n")).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    pool.get()
        .await
        .expect("pool.get")
        .execute(
            "UPDATE bootstrap_lock SET bootstrapped = true WHERE id = 1",
            &[],
        )
        .await
        .expect("flip the lock");
    assert!(!is_bootstrap_available(&pool, Some(&path)).await.unwrap());
}

/// A store whose burn does the unlink, signals, then waits to be released
/// before it returns — the window a dropped request would cut: the token is
/// gone and the transaction not yet committed.
struct HeldBurnStore {
    burned: Arc<AtomicBool>,
    reached: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
}

impl BootstrapTokenStore for HeldBurnStore {
    fn read_token(&self) -> BoxFuture<'_, io::Result<Vec<u8>>> {
        Box::pin(async { Ok(TOKEN.as_bytes().to_vec()) })
    }

    fn burn_token(&self) -> BoxFuture<'_, io::Result<BurnOutcome>> {
        Box::pin(async move {
            self.burned.store(true, Ordering::SeqCst);
            self.reached.notify_one();
            self.release.notified().await;
            Ok(BurnOutcome::Burned)
        })
    }
}

/// A request dropped at the burn — the client went away — can't cut the
/// bootstrap in half: the token is already gone, so the bootstrap must still
/// commit, not roll back and leave the window open on a deleted token.
#[tokio::test]
async fn a_request_dropped_at_the_burn_still_commits() {
    let pool = fresh_db().await;
    let burned = Arc::new(AtomicBool::new(false));
    let reached = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let store: Arc<dyn BootstrapTokenStore> = Arc::new(HeldBurnStore {
        burned: Arc::clone(&burned),
        reached: Arc::clone(&reached),
        release: Arc::clone(&release),
    });
    let available = Arc::new(AtomicBool::new(true));
    let options = build_options(pool.clone(), Some(store), Arc::clone(&available), None);

    {
        let request =
            bootstrap_handler(&options, None, input(TOKEN, "keeper", "valid-password-123"));
        tokio::select! {
            _ = request => panic!("the bootstrap finished before its burn was released"),
            () = reached.notified() => {}
        }
        // leaving the block drops the request future mid-burn
    }
    assert!(burned.load(Ordering::SeqCst));
    release.notify_one();

    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    while !lock_bootstrapped(&pool).await {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the bootstrap rolled back after its token was burned"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert_eq!(account_count(&pool).await, 1);
    assert!(!available.load(Ordering::SeqCst), "the window closes");
}

// -- The burn is last ---------------------------------------------------------

/// A failed insert spends nothing: with the bootstrap username already taken
/// (the lock still unflipped), the account insert fails ahead of the burn, so
/// the token is not burned, the file keeps it, and the lock rolls back.
#[tokio::test]
async fn a_failed_insert_burns_nothing() {
    let pool = fresh_db().await;
    pool.get()
        .await
        .expect("pool.get")
        .execute(
            "INSERT INTO account (username, password_hash) VALUES ('keeper', 'hash')",
            &[],
        )
        .await
        .expect("pre-insert the username");
    let (token_store, burned) = InMemoryTokenStore::with_token(TOKEN.as_bytes());
    let store_probe = Arc::clone(&token_store);
    let options = build_options(
        pool.clone(),
        Some(token_store),
        Arc::new(AtomicBool::new(true)),
        None,
    );

    let err = bootstrap_handler(&options, None, input(TOKEN, "keeper", "valid-password-123"))
        .await
        .expect_err("the username is taken");
    assert!(matches!(err, BootstrapError::Query(_)), "{err:?}");
    assert!(!burned.load(Ordering::SeqCst), "nothing was burned");
    assert_eq!(
        store_probe.read_token().await.expect("still there"),
        TOKEN.as_bytes(),
        "the token is intact"
    );
    assert!(!lock_bootstrapped(&pool).await, "the lock rolled back");
}

// -- The limiter's charges ------------------------------------------------------

fn one_attempt_limiter() -> Arc<RateLimiter> {
    Arc::new(RateLimiter::new(RateLimiterOptions {
        max_attempts: 1,
        window_ms: 60_000,
        max_keys: None,
    }))
}

fn limiter_allows(limiter: &RateLimiter) -> bool {
    limiter
        .check(&fuz_http::rate_limit_ip_key("1.2.3.4"))
        .is_allowed()
}

/// A success is not charged; a failed burn and an unreadable token file are.
#[tokio::test]
async fn the_limiter_charges_refusals_and_not_a_success() {
    let pool = fresh_db().await;
    let cases: [(Arc<dyn BootstrapTokenStore>, bool, &str); 3] = [
        (
            InMemoryTokenStore::with_token(TOKEN.as_bytes()).0,
            true,
            "a success",
        ),
        (
            InMemoryTokenStore::undeletable(TOKEN.as_bytes()).0,
            false,
            "a failed burn",
        ),
        (InMemoryTokenStore::missing(), false, "a missing token file"),
    ];
    for (store, still_allowed, label) in cases {
        pool.get()
            .await
            .expect("pool.get")
            .execute(
                "UPDATE bootstrap_lock SET bootstrapped = false WHERE id = 1",
                &[],
            )
            .await
            .expect("reopen the lock");
        let limiter = one_attempt_limiter();
        let mut options = build_options(
            pool.clone(),
            Some(store),
            Arc::new(AtomicBool::new(true)),
            None,
        );
        options.bootstrap_ip_rate_limiter = Some(Arc::clone(&limiter));
        let _ = bootstrap_handler(
            &options,
            Some("1.2.3.4".to_owned()),
            input(
                TOKEN,
                &format!("keeper{}", label.len()),
                "valid-password-123",
            ),
        )
        .await;
        assert_eq!(limiter_allows(&limiter), still_allowed, "{label}");
    }
}

/// An exhausted bootstrap limiter answers the 429 on the wire: the
/// `rate_limit_exceeded` body with its integer `retry_after`, and the same
/// count in `Retry-After`. Reached before the token or the database is read,
/// so a pool that can't connect serves it.
#[tokio::test]
async fn an_exhausted_limiter_answers_the_429() {
    use axum::body::Body;
    use axum::http::{Request, StatusCode, header};
    use tower::ServiceExt;

    let pool = fuz_db::create_pool(
        "postgres://bootstrap_limiter@127.0.0.1:1/none",
        &fuz_db::PoolOptions::default(),
    )
    .expect("pool builds without connecting");
    let limiter = one_attempt_limiter();
    limiter.record(&fuz_http::rate_limit_ip_key("1.2.3.4"));
    let (token_store, _burned) = InMemoryTokenStore::with_token(TOKEN.as_bytes());
    let mut options = build_options(
        pool.clone(),
        Some(token_store),
        Arc::new(AtomicBool::new(true)),
        None,
    );
    options.bootstrap_ip_rate_limiter = Some(limiter);
    let router = fuz_auth::bootstrap_routes::bootstrap_router(fuz_auth::BootstrapRouteState {
        options: Arc::new(options),
        gate: fuz_testing::testing_auth_gate(pool),
    })
    .layer(axum::Extension(fuz_http::ClientIp("1.2.3.4".to_owned())));

    let body =
        serde_json::json!({"token": TOKEN, "username": "keeper", "password": "valid-password-123"});
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/bootstrap")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    let retry_after: u64 = response
        .headers()
        .get(header::RETRY_AFTER)
        .expect("Retry-After")
        .to_str()
        .unwrap()
        .parse()
        .expect("an integer of seconds");
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        body,
        serde_json::json!({"error": "rate_limit_exceeded", "retry_after": retry_after})
    );
    assert!(retry_after > 0);
}

// -- The cookie is signed in the transaction -------------------------------------

/// A session cookie that can't be written rolls the bootstrap back with the
/// token unburned — it is signed inside the transaction, ahead of the burn,
/// never after the commit.
#[tokio::test]
async fn a_cookie_that_cannot_be_signed_rolls_back_unburned() {
    let pool = fresh_db().await;
    let (token_store, burned) = InMemoryTokenStore::with_token(TOKEN.as_bytes());
    let mut options = build_options(
        pool.clone(),
        Some(token_store),
        Arc::new(AtomicBool::new(true)),
        None,
    );
    // no RFC 6265 cookie-name holds a space
    options.session_cookie_name = "not a cookie name";

    let err = bootstrap_handler(&options, None, input(TOKEN, "keeper", "valid-password-123"))
        .await
        .expect_err("the cookie can't be written");
    assert!(matches!(err, BootstrapError::SessionCookie(_)), "{err:?}");
    assert!(!burned.load(Ordering::SeqCst), "the token is not burned");
    assert_eq!(account_count(&pool).await, 0, "the bootstrap rolled back");
    assert!(!lock_bootstrapped(&pool).await);
}

// -- Logs ------------------------------------------------------------------------

/// A buffer a `fmt` subscriber writes into.
#[derive(Clone, Default)]
struct LogCapture(Arc<Mutex<Vec<u8>>>);

impl io::Write for LogCapture {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl LogCapture {
    /// Install a subscriber over this buffer on the current thread.
    fn install(&self) -> tracing::subscriber::DefaultGuard {
        let writer = self.clone();
        tracing::subscriber::set_default(
            tracing_subscriber::fmt()
                .with_writer(move || writer.clone())
                .with_ansi(false)
                .finish(),
        )
    }

    /// The captured lines at `level` (`"ERROR"`, `"WARN"`, `"INFO"`).
    fn lines(&self, level: &str) -> Vec<String> {
        String::from_utf8(std::mem::take(&mut *self.0.lock().unwrap()))
            .unwrap()
            .lines()
            .filter(|line| line.contains(&format!(" {level} ")))
            .map(str::to_owned)
            .collect()
    }
}

/// The boot report reads the lock first, and logs each state at the level
/// the twin does: a missing lock row an error, a bootstrapped server with no
/// token file info, one with the file still present a warning naming it, an
/// open window with an unreadable file a warning with the reason.
#[tokio::test]
async fn the_boot_report_logs_each_state_at_its_level() {
    use std::os::unix::fs::PermissionsExt;
    let pool = fresh_db().await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("secret_bootstrap_token");
    let client = pool.get().await.expect("pool.get");
    let capture = LogCapture::default();
    let _guard = capture.install();

    // open window, no file: a warning with the reason
    assert!(!is_bootstrap_available(&pool, Some(&path)).await.unwrap());
    assert_eq!(capture.lines("WARN").len(), 1, "unreadable: one warning");

    // bootstrapped, no file: info only
    client
        .execute(
            "UPDATE bootstrap_lock SET bootstrapped = true WHERE id = 1",
            &[],
        )
        .await
        .unwrap();
    assert!(!is_bootstrap_available(&pool, Some(&path)).await.unwrap());
    let captured = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
    assert!(!captured.contains(" WARN "), "{captured}");
    assert_eq!(capture.lines("INFO").len(), 1, "bootstrapped: info");

    // bootstrapped with the file still there: a warning naming it
    std::fs::write(&path, format!("{TOKEN}\n")).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(!is_bootstrap_available(&pool, Some(&path)).await.unwrap());
    let warnings = capture.lines("WARN");
    assert_eq!(warnings.len(), 1, "{warnings:?}");
    assert!(warnings[0].contains(path.to_str().unwrap()), "{warnings:?}");
    assert!(warnings[0].contains("delete it"), "{warnings:?}");

    // the lock row gone: an error, whatever the file
    client
        .execute("DELETE FROM bootstrap_lock", &[])
        .await
        .unwrap();
    assert!(!is_bootstrap_available(&pool, Some(&path)).await.unwrap());
    assert_eq!(
        capture.lines("ERROR").len(),
        1,
        "missing lock row: an error"
    );
}

/// A lock read that fails is an error, not a silent "unavailable": the boot
/// fails naming it, as the twin's boot throws.
#[tokio::test]
async fn a_failed_lock_read_is_an_error() {
    let pool = fuz_db::create_pool(
        "postgres://bootstrap_boot@127.0.0.1:1/none",
        &fuz_db::PoolOptions::default(),
    )
    .expect("pool builds without connecting");
    let path = std::path::Path::new("/nonexistent/bootstrap_token");
    assert!(is_bootstrap_available(&pool, Some(path)).await.is_err());
    // no token path: no database read at all
    assert!(!is_bootstrap_available(&pool, None).await.unwrap());
}

/// A store whose burn kills the bootstrap's own connection after the unlink,
/// so the COMMIT that follows fails: the token is gone and nothing committed.
struct ConnectionKillingStore {
    pool: Pool,
    burned: Arc<AtomicBool>,
}

impl BootstrapTokenStore for ConnectionKillingStore {
    fn read_token(&self) -> BoxFuture<'_, io::Result<Vec<u8>>> {
        Box::pin(async { Ok(TOKEN.as_bytes().to_vec()) })
    }

    fn burn_token(&self) -> BoxFuture<'_, io::Result<BurnOutcome>> {
        Box::pin(async move {
            self.burned.store(true, Ordering::SeqCst);
            // the bootstrap's transaction sits idle while its burn runs
            self.pool
                .get()
                .await
                .expect("pool.get")
                .execute(
                    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity
                     WHERE datname = current_database()
                       AND state = 'idle in transaction'
                       AND pid <> pg_backend_pid()",
                    &[],
                )
                .await
                .expect("terminate the bootstrap's backend");
            Ok(BurnOutcome::Burned)
        })
    }
}

/// A COMMIT that fails after the burn is a 500-class error with an `error`
/// log saying the token is gone and a new one must be written.
#[tokio::test]
#[ignore = "postgres-only: terminates a backend (pg_terminate_backend)"]
async fn a_commit_that_fails_after_the_burn_logs_that_the_token_is_gone() {
    let pool = fresh_postgres_db().await;
    let burned = Arc::new(AtomicBool::new(false));
    let store: Arc<dyn BootstrapTokenStore> = Arc::new(ConnectionKillingStore {
        pool: pool.clone(),
        burned: Arc::clone(&burned),
    });
    let options = build_options(
        pool.clone(),
        Some(store),
        Arc::new(AtomicBool::new(true)),
        None,
    );
    let capture = LogCapture::default();
    let _guard = capture.install();

    let err = bootstrap_handler(&options, None, input(TOKEN, "keeper", "valid-password-123"))
        .await
        .expect_err("the commit fails");
    assert!(matches!(err, BootstrapError::Commit(_)), "{err:?}");
    assert!(burned.load(Ordering::SeqCst));
    let errors = capture.lines("ERROR");
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert!(errors[0].contains("write a new token"), "{errors:?}");
    assert_eq!(account_count(&pool).await, 0, "nothing committed");
}

/// A store whose burn panics, as a fault on the write task would.
struct PanickingBurnStore;

impl BootstrapTokenStore for PanickingBurnStore {
    fn read_token(&self) -> BoxFuture<'_, io::Result<Vec<u8>>> {
        Box::pin(async { Ok(TOKEN.as_bytes().to_vec()) })
    }

    #[allow(
        clippy::panic,
        reason = "the fault under test is a panic on the write task"
    )]
    fn burn_token(&self) -> BoxFuture<'_, io::Result<BurnOutcome>> {
        Box::pin(async { panic!("the burn panicked") })
    }
}

/// A panic on the write task is the task error — a 500, never a domain
/// refusal — rolls the bootstrap back, and charges nothing.
#[tokio::test]
async fn a_panic_on_the_write_task_is_the_task_error() {
    let pool = fresh_db().await;
    let limiter = one_attempt_limiter();
    let mut options = build_options(
        pool.clone(),
        Some(Arc::new(PanickingBurnStore)),
        Arc::new(AtomicBool::new(true)),
        None,
    );
    options.bootstrap_ip_rate_limiter = Some(Arc::clone(&limiter));

    let err = bootstrap_handler(
        &options,
        Some("1.2.3.4".to_owned()),
        input(TOKEN, "keeper", "valid-password-123"),
    )
    .await
    .expect_err("the task panicked");
    assert!(matches!(err, BootstrapError::Task(_)), "{err:?}");
    assert_eq!(account_count(&pool).await, 0, "the bootstrap rolled back");
    assert!(!lock_bootstrapped(&pool).await);
    assert!(limiter_allows(&limiter), "a fault is not charged");
}

/// A token file with a second hard link is refused on both read sites: the
/// burn's unlink would leave the token readable under the other name. At boot
/// the window reads unavailable with a warning naming the link count; on a
/// request it answers as an unreadable token does — `token_file_missing`, the
/// window closed, its one audit row, nothing created, the file left as it was.
#[tokio::test]
async fn a_token_file_with_a_second_hard_link_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let pool = fresh_db().await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("secret_bootstrap_token");
    std::fs::write(&path, format!("{TOKEN}\n")).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(
        is_bootstrap_available(&pool, Some(&path)).await.unwrap(),
        "control: one link is available"
    );
    let other = dir.path().join("token_other_name");
    std::fs::hard_link(&path, &other).unwrap();

    {
        let capture = LogCapture::default();
        let _guard = capture.install();
        assert!(!is_bootstrap_available(&pool, Some(&path)).await.unwrap());
        let warnings = capture.lines("WARN");
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(warnings[0].contains("2 hard links"), "{warnings:?}");
    }

    let available = Arc::new(AtomicBool::new(true));
    let store: Arc<dyn BootstrapTokenStore> = Arc::new(FileBootstrapTokenStore::new(path.clone()));
    let options = build_options(pool.clone(), Some(store), Arc::clone(&available), None);
    let err = bootstrap_handler(&options, None, input(TOKEN, "admin", "valid-password-123"))
        .await
        .expect_err("two links ⇒ token_file_missing");
    assert!(
        matches!(
            err,
            BootstrapError::Classified {
                kind: BootstrapErrorKind::TokenFileMissing
            }
        ),
        "{err:?}"
    );
    assert!(
        !available.load(Ordering::SeqCst),
        "the refusal closes the window"
    );
    options.audit.drain_inflight().await;
    assert_eq!(
        latest_bootstrap_failure_error(&options).await,
        "token_file_missing"
    );
    assert_eq!(account_count(&pool).await, 0);
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        format!("{TOKEN}\n"),
        "the refused token is not burned"
    );

    // the other name removed, the file is available again
    std::fs::remove_file(&other).unwrap();
    assert!(is_bootstrap_available(&pool, Some(&path)).await.unwrap());
}
