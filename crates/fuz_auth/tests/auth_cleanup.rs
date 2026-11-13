//! Integration tests for `fuz_auth::auth_cleanup` against a real `PostgreSQL`
//! — the offer-expiry sweep's audit-once claim and the session sweep.
//!
//! The session sweep closes what it sweeps: a pass closes the connections of
//! exactly the sessions it deleted, by session id — never the account's other
//! sessions — and, on a successful pass, only once the delete has committed,
//! the rule every revocation close keeps. Without the close a swept
//! session's connections would have no per-session handle left
//! (`account_session_revoke` closes only for a row it deletes). A commit
//! that fails still closes — the sessions are expired either way — and the
//! next pass deletes the rows it left and closes again. The registry
//! end of the same close — a real WebSocket entry and SSE stream ending — is
//! `fuz_realtime`'s `tests/audit_stream.rs`.
//!
//! What these pin, beyond the per-row audit shape: a second pass audits
//! nothing (the `expire_audited_at` stamp), terminal offers are never
//! stamped, a re-offer clears the stamp so the refreshed expiry is audited
//! again under the same `offer_id`, a failed audit insert rolls the stamps
//! back, and a pass that meets a row another transaction has claimed waits on
//! its row lock and then skips it. Twin of `fuz_app`'s
//! `src/test/auth/cleanup.db.test.ts` (the offer sweep and the full pass) and
//! `src/test/auth/cleanup.sessions.db.test.ts` (the session sweep).
//!
//! Plus the scheduler's wiring (`spawn_auth_cleanup`): its startup pass runs
//! both sweeps, it sweeps again on its interval, and cancelling its token
//! ends it — twin of `src/test/auth/cleanup.schedule.test.ts`. The loop's own
//! timing rules are `fuz_sys::periodic`'s tests (twin:
//! `src/test/periodic.test.ts`).
//!
//! Gated behind `#[ignore]` — run with:
//! ```text
//! createdb fuz_auth_test
//! cargo test -p fuz_auth --test auth_cleanup -- --ignored --test-threads=1
//! ```
//!
//! Override the DB URL with `FUZ_AUTH_TEST_URL=postgres://...`.

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test helpers outside `#[test]` fns panic on a failed setup or check"
)]

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use fuz_auth::{
    AuditEmitter, AuditLogEvent, AuthCleanupOptions, AuthCleanupResult, ConnectionCloseTarget,
    ConnectionCloser, CreateRoleGrantOfferInput, NoopConnectionCloser, RoleGrantOffer,
    cleanup_expired_role_grant_offers, cleanup_expired_sessions, query_role_grant_offer_create,
    run_auth_cleanup, spawn_auth_cleanup,
};
use fuz_db::Pool;
use parking_lot::Mutex;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

mod common;
use common::{fresh_db_pool, seed_account_actor, seed_extra_actor, seed_role_grant_direct};

const HOUR: Duration = Duration::from_hours(1);

/// The grantor's actor plus two recipient accounts (the first with its actor).
struct Accounts {
    grantor_actor_id: Uuid,
    recipient_account_id: Uuid,
    recipient_actor_id: Uuid,
    recipient_account_id_2: Uuid,
}

async fn seed_accounts(pool: &Pool) -> Accounts {
    let (_, grantor_actor_id) = seed_account_actor(pool, "cleanup_grantor").await;
    let (recipient_account_id, recipient_actor_id) =
        seed_account_actor(pool, "cleanup_recipient").await;
    let (recipient_account_id_2, _) = seed_account_actor(pool, "cleanup_recipient_2").await;
    Accounts {
        grantor_actor_id,
        recipient_account_id,
        recipient_actor_id,
        recipient_account_id_2,
    }
}

/// Create (or upsert) a pending global offer with an explicit expiry.
async fn offer(
    pool: &Pool,
    from_actor_id: Uuid,
    to_account_id: Uuid,
    to_actor_id: Option<Uuid>,
    role: &str,
    expires_at: SystemTime,
) -> RoleGrantOffer {
    let client = pool.get().await.unwrap();
    query_role_grant_offer_create(
        &client,
        CreateRoleGrantOfferInput {
            from_actor_id,
            to_account_id,
            to_actor_id,
            role: role.to_owned(),
            scope_kind: None,
            scope_id: None,
            message: None,
            expires_at,
        },
    )
    .await
    .expect("create offer")
}

fn past() -> SystemTime {
    SystemTime::now() - HOUR
}

fn future() -> SystemTime {
    SystemTime::now() + HOUR
}

/// A `ConnectionCloser` recording every close it is asked for, by target. It
/// reports nothing closed, as a server with no live connection would.
#[derive(Default)]
struct RecordingCloser {
    closed: Mutex<Vec<ConnectionCloseTarget>>,
}

impl RecordingCloser {
    /// Every close so far, sorted — the sweep's delete returns ids in no
    /// order worth pinning.
    fn closed(&self) -> Vec<ConnectionCloseTarget> {
        let mut closed = self.closed.lock().clone();
        closed.sort_by_key(|target| format!("{target:?}"));
        closed
    }

    fn record(&self, target: ConnectionCloseTarget) -> usize {
        self.closed.lock().push(target);
        0
    }
}

impl fuz_http::ShutdownCloser for RecordingCloser {
    fn close_all_connections(&self) -> usize {
        0
    }
    fn wait_closed(&self) -> fuz_http::WaitClosedFuture<'_> {
        Box::pin(std::future::ready(()))
    }
}

impl ConnectionCloser for RecordingCloser {
    fn close_connections(&self, target: &ConnectionCloseTarget) -> usize {
        self.record(target.clone())
    }
}

fn session_target(id: &str) -> ConnectionCloseTarget {
    ConnectionCloseTarget::Session(id.to_owned())
}

/// Options over the test pool with a [`RecordingCloser`] — what the session
/// sweep cases drive.
fn options_with_closer(pool: &Pool) -> (AuthCleanupOptions, Arc<RecordingCloser>) {
    let closer = Arc::new(RecordingCloser::default());
    (
        AuthCleanupOptions {
            pool: pool.clone(),
            audit: Arc::new(AuditEmitter::new(pool.clone())),
            connection_closer: Arc::<RecordingCloser>::clone(&closer),
        },
        closer,
    )
}

/// Seed `auth_session` rows: `(id, account_id, expired)`, an expired one an
/// hour past its `expires_at` and a live one an hour short of it.
async fn seed_sessions(pool: &Pool, sessions: &[(&str, Uuid, bool)]) {
    let client = pool.get().await.unwrap();
    for (id, account_id, expired) in sessions {
        client
            .execute(
                "INSERT INTO auth_session (id, account_id, expires_at)
                 VALUES ($1, $2, CASE WHEN $3 THEN NOW() - INTERVAL '1 hour'
                                      ELSE NOW() + INTERVAL '1 hour' END)",
                &[id, account_id, expired],
            )
            .await
            .unwrap();
    }
}

/// The ids left in `auth_session`, sorted.
async fn remaining_sessions(pool: &Pool) -> Vec<String> {
    pool.get()
        .await
        .unwrap()
        .query("SELECT id FROM auth_session ORDER BY id", &[])
        .await
        .unwrap()
        .iter()
        .map(|r| r.get(0))
        .collect()
}

/// Options over the test pool, with a listener recording every fanned-out
/// event. The offer cases close nothing, so the closer is the no-op.
fn options_recording(pool: &Pool) -> (AuthCleanupOptions, Arc<Mutex<Vec<Arc<AuditLogEvent>>>>) {
    let audit = Arc::new(AuditEmitter::new(pool.clone()));
    let events: Arc<Mutex<Vec<Arc<AuditLogEvent>>>> = Arc::default();
    let sink = Arc::clone(&events);
    audit.add_listener(Arc::new(move |event| {
        sink.lock().push(event);
        Box::pin(async {})
    }));
    (
        AuthCleanupOptions {
            pool: pool.clone(),
            audit,
            connection_closer: Arc::new(NoopConnectionCloser),
        },
        events,
    )
}

/// The `role_grant_offer_expire` rows: `(actor_id, target_account_id,
/// target_actor_id, ip, offer_id)`, oldest first.
async fn expire_audits(pool: &Pool) -> Vec<(Uuid, Uuid, Option<Uuid>, Option<String>, String)> {
    let client = pool.get().await.unwrap();
    client
        .query(
            "SELECT actor_id, target_account_id, target_actor_id, ip::text,
                    metadata->>'offer_id'
             FROM audit_log WHERE event_type = 'role_grant_offer_expire' ORDER BY seq",
            &[],
        )
        .await
        .unwrap()
        .iter()
        .map(|r| (r.get(0), r.get(1), r.get(2), r.get(3), r.get(4)))
        .collect()
}

/// Ids of the offers carrying an expiry-audit stamp.
async fn stamped_offer_ids(pool: &Pool) -> Vec<Uuid> {
    let client = pool.get().await.unwrap();
    client
        .query(
            "SELECT id FROM role_grant_offer WHERE expire_audited_at IS NOT NULL ORDER BY id",
            &[],
        )
        .await
        .unwrap()
        .iter()
        .map(|r| r.get(0))
        .collect()
}

async fn backdate_expiry(pool: &Pool, offer_id: Uuid) {
    let client = pool.get().await.unwrap();
    client
        .execute(
            "UPDATE role_grant_offer SET expires_at = NOW() - INTERVAL '1 hour' WHERE id = $1",
            &[&offer_id],
        )
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "needs Postgres"]
async fn sweep_audits_each_expired_offer_and_stamps_it() {
    let pool = fresh_db_pool().await;
    let a = seed_accounts(&pool).await;
    let expired_1 = offer(
        &pool,
        a.grantor_actor_id,
        a.recipient_account_id,
        None,
        "teacher",
        past(),
    )
    .await;
    let expired_2 = offer(
        &pool,
        a.grantor_actor_id,
        a.recipient_account_id_2,
        None,
        "moderator",
        past(),
    )
    .await;
    let fresh = offer(
        &pool,
        a.grantor_actor_id,
        a.recipient_account_id,
        None,
        "admin",
        future(),
    )
    .await;
    assert_eq!(fresh.expire_audited_at, None);

    let (options, events) = options_recording(&pool);
    assert_eq!(
        cleanup_expired_role_grant_offers(&options).await.unwrap(),
        2
    );

    let audits = expire_audits(&pool).await;
    assert_eq!(audits.len(), 2);
    for (actor_id, _, target_actor_id, ip, _) in &audits {
        assert_eq!(*actor_id, a.grantor_actor_id, "the grantor is the actor");
        assert_eq!(*target_actor_id, None, "account-grain offers");
        assert_eq!(*ip, None, "no request is behind a sweep");
    }
    let mut audited_offers: Vec<(Uuid, String)> = audits
        .iter()
        .map(|(_, target_account, _, _, offer_id)| (*target_account, offer_id.clone()))
        .collect();
    audited_offers.sort();
    let mut expected = vec![
        (a.recipient_account_id, expired_1.id.to_string()),
        (a.recipient_account_id_2, expired_2.id.to_string()),
    ];
    expected.sort();
    assert_eq!(audited_offers, expected);

    // the metadata carries role + scope beside the offer id
    let first = Arc::clone(&events.lock()[0]);
    let metadata = first.metadata.as_ref().expect("metadata");
    assert!(
        metadata
            .get("role")
            .is_some_and(serde_json::Value::is_string)
    );
    assert!(
        metadata
            .get("scope_id")
            .is_some_and(serde_json::Value::is_null)
    );

    assert_eq!(events.lock().len(), 2, "each committed row fans out once");
    let mut expected_stamped = vec![expired_1.id, expired_2.id];
    expected_stamped.sort();
    assert_eq!(stamped_offer_ids(&pool).await, expected_stamped);
}

#[tokio::test]
#[ignore = "needs Postgres"]
async fn a_second_pass_audits_nothing() {
    let pool = fresh_db_pool().await;
    let a = seed_accounts(&pool).await;
    offer(
        &pool,
        a.grantor_actor_id,
        a.recipient_account_id,
        None,
        "teacher",
        past(),
    )
    .await;
    offer(
        &pool,
        a.grantor_actor_id,
        a.recipient_account_id_2,
        None,
        "moderator",
        past(),
    )
    .await;

    let (options, events) = options_recording(&pool);
    assert_eq!(
        cleanup_expired_role_grant_offers(&options).await.unwrap(),
        2
    );
    assert_eq!(
        cleanup_expired_role_grant_offers(&options).await.unwrap(),
        0
    );
    assert_eq!(expire_audits(&pool).await.len(), 2);
    assert_eq!(events.lock().len(), 2);
}

#[tokio::test]
#[ignore = "needs Postgres"]
async fn no_expired_offers_is_a_no_op() {
    let pool = fresh_db_pool().await;
    let a = seed_accounts(&pool).await;
    offer(
        &pool,
        a.grantor_actor_id,
        a.recipient_account_id,
        None,
        "teacher",
        future(),
    )
    .await;

    let (options, events) = options_recording(&pool);
    assert_eq!(
        cleanup_expired_role_grant_offers(&options).await.unwrap(),
        0
    );
    assert!(expire_audits(&pool).await.is_empty());
    assert!(events.lock().is_empty());
    assert!(stamped_offer_ids(&pool).await.is_empty());
}

#[tokio::test]
#[ignore = "needs Postgres"]
async fn terminal_offers_past_their_expiry_are_never_stamped() {
    let pool = fresh_db_pool().await;
    let a = seed_accounts(&pool).await;
    let mut ids = Vec::new();
    for role in ["teacher", "moderator", "admin", "editor"] {
        ids.push(
            offer(
                &pool,
                a.grantor_actor_id,
                a.recipient_account_id,
                None,
                role,
                past(),
            )
            .await
            .id,
        );
    }
    let grant_id = seed_role_grant_direct(&pool, a.recipient_actor_id, "teacher", None).await;
    let client = pool.get().await.unwrap();
    client
        .execute(
            "UPDATE role_grant_offer SET accepted_at = NOW(), resulting_role_grant_id = $2
             WHERE id = $1",
            &[&ids[0], &grant_id],
        )
        .await
        .unwrap();
    client
        .execute(
            "UPDATE role_grant_offer SET declined_at = NOW(), decline_reason = 'no' WHERE id = $1",
            &[&ids[1]],
        )
        .await
        .unwrap();
    client
        .execute(
            "UPDATE role_grant_offer SET retracted_at = NOW() WHERE id = $1",
            &[&ids[2]],
        )
        .await
        .unwrap();
    client
        .execute(
            "UPDATE role_grant_offer SET superseded_at = NOW() WHERE id = $1",
            &[&ids[3]],
        )
        .await
        .unwrap();
    drop(client);

    let (options, events) = options_recording(&pool);
    assert_eq!(
        cleanup_expired_role_grant_offers(&options).await.unwrap(),
        0
    );
    assert!(stamped_offer_ids(&pool).await.is_empty());
    assert!(expire_audits(&pool).await.is_empty());
    assert!(events.lock().is_empty());
}

#[tokio::test]
#[ignore = "needs Postgres"]
async fn an_actor_targeted_offer_audits_its_target_actor() {
    let pool = fresh_db_pool().await;
    let a = seed_accounts(&pool).await;
    // a second actor on the recipient account, so the target is not the
    // account's only actor
    let target_actor = seed_extra_actor(&pool, a.recipient_account_id, "recipient_alt").await;
    let targeted = offer(
        &pool,
        a.grantor_actor_id,
        a.recipient_account_id,
        Some(target_actor),
        "teacher",
        past(),
    )
    .await;
    let account_grain = offer(
        &pool,
        a.grantor_actor_id,
        a.recipient_account_id_2,
        None,
        "teacher",
        past(),
    )
    .await;

    let (options, _) = options_recording(&pool);
    assert_eq!(
        cleanup_expired_role_grant_offers(&options).await.unwrap(),
        2
    );

    let audits = expire_audits(&pool).await;
    let target_actor_of = |offer_id: Uuid| {
        audits
            .iter()
            .find(|(.., id)| *id == offer_id.to_string())
            .map(|(_, _, target_actor, ..)| *target_actor)
            .expect("an audit row for the offer")
    };
    assert_eq!(target_actor_of(targeted.id), Some(target_actor));
    assert_eq!(target_actor_of(account_grain.id), None);
}

#[tokio::test]
#[ignore = "needs Postgres"]
async fn run_auth_cleanup_deletes_only_expired_sessions_and_sweeps_offers() {
    let pool = fresh_db_pool().await;
    let a = seed_accounts(&pool).await;
    seed_sessions(
        &pool,
        &[
            ("cleanup-expired", a.recipient_account_id, true),
            ("cleanup-live", a.recipient_account_id, false),
        ],
    )
    .await;
    offer(
        &pool,
        a.grantor_actor_id,
        a.recipient_account_id,
        None,
        "teacher",
        past(),
    )
    .await;
    offer(
        &pool,
        a.grantor_actor_id,
        a.recipient_account_id_2,
        None,
        "moderator",
        past(),
    )
    .await;

    let (options, closer) = options_with_closer(&pool);
    assert_eq!(
        run_auth_cleanup(&options).await.unwrap(),
        AuthCleanupResult {
            expired_sessions: 1,
            expired_offers: 2,
        }
    );
    assert_eq!(remaining_sessions(&pool).await, ["cleanup-live"]);
    assert_eq!(
        closer.closed(),
        [session_target("cleanup-expired")],
        "the pass closes for the session it swept"
    );

    // nothing left to sweep on a second pass
    assert_eq!(
        run_auth_cleanup(&options).await.unwrap(),
        AuthCleanupResult::default()
    );
    assert_eq!(closer.closed().len(), 1, "and nothing more to close");
}

/// **One pass closes exactly the sessions it deleted.** Each swept session is
/// closed by its own id: the account's live session is not named, and no
/// account-wide or token close is made — the expired sessions' owner keeps
/// every connection its other sessions opened. Expired sessions on two
/// accounts go in the one pass.
#[tokio::test]
#[ignore = "needs Postgres"]
async fn the_session_sweep_closes_exactly_the_sessions_it_deletes() {
    let pool = fresh_db_pool().await;
    let a = seed_accounts(&pool).await;
    seed_sessions(
        &pool,
        &[
            ("sweep-expired-1", a.recipient_account_id, true),
            ("sweep-expired-2", a.recipient_account_id, true),
            ("sweep-live", a.recipient_account_id, false),
            ("sweep-other-expired", a.recipient_account_id_2, true),
            ("sweep-other-live", a.recipient_account_id_2, false),
        ],
    )
    .await;

    let (options, closer) = options_with_closer(&pool);
    assert_eq!(cleanup_expired_sessions(&options).await.unwrap(), 3);
    assert_eq!(
        closer.closed(),
        [
            session_target("sweep-expired-1"),
            session_target("sweep-expired-2"),
            session_target("sweep-other-expired"),
        ],
        "one close per swept session, by session id, and nothing else"
    );
    assert_eq!(
        remaining_sessions(&pool).await,
        ["sweep-live", "sweep-other-live"]
    );
}

/// **A second pass closes nothing.** The ids come from the delete itself
/// (`RETURNING`), so after a pass that committed, a session is closed for by
/// that pass and by no later one.
#[tokio::test]
#[ignore = "needs Postgres"]
async fn a_second_session_sweep_closes_nothing() {
    let pool = fresh_db_pool().await;
    let a = seed_accounts(&pool).await;
    seed_sessions(
        &pool,
        &[
            ("sweep-expired", a.recipient_account_id, true),
            ("sweep-live", a.recipient_account_id, false),
        ],
    )
    .await;

    let (options, closer) = options_with_closer(&pool);
    assert_eq!(cleanup_expired_sessions(&options).await.unwrap(), 1);
    assert_eq!(closer.closed(), [session_target("sweep-expired")]);

    assert_eq!(cleanup_expired_sessions(&options).await.unwrap(), 0);
    assert_eq!(
        closer.closed(),
        [session_target("sweep-expired")],
        "the second pass swept nothing and closed nothing"
    );
}

/// A pass with nothing expired deletes nothing and closes nothing.
#[tokio::test]
#[ignore = "needs Postgres"]
async fn no_expired_sessions_closes_nothing() {
    let pool = fresh_db_pool().await;
    let a = seed_accounts(&pool).await;
    seed_sessions(&pool, &[("sweep-live", a.recipient_account_id, false)]).await;

    let (options, closer) = options_with_closer(&pool);
    assert_eq!(cleanup_expired_sessions(&options).await.unwrap(), 0);
    assert!(closer.closed().is_empty());
    assert_eq!(remaining_sessions(&pool).await, ["sweep-live"]);
}

/// **A sweep whose commit fails still closes, and the next pass retries the
/// delete.** The delete returns its ids inside the sweep's transaction; a
/// deferred constraint trigger then refuses the commit, which rolls the
/// delete back. The swept session is expired whether or not its row is gone,
/// so its connections are closed anyway and the error is returned; the row
/// the commit left is deleted by the next pass, whose close is a repeat.
///
/// This is the commit's failure branch with a known outcome. The same branch
/// serves a commit whose answer never arrives (the row gone, the ids already
/// read), which no test here can stage without a seam in the query path.
#[tokio::test]
#[ignore = "needs Postgres"]
async fn a_session_sweep_whose_commit_fails_still_closes_and_the_next_pass_retries() {
    let pool = fresh_db_pool().await;
    let a = seed_accounts(&pool).await;
    seed_sessions(
        &pool,
        &[
            ("sweep-expired", a.recipient_account_id, true),
            ("sweep-live", a.recipient_account_id, false),
        ],
    )
    .await;
    let (options, closer) = options_with_closer(&pool);

    // deferred, so the DELETE succeeds and the COMMIT is what fails
    let client = pool.get().await.unwrap();
    client
        .batch_execute(
            "CREATE FUNCTION cleanup_test_refuse_commit() RETURNS trigger AS $$
               BEGIN RAISE EXCEPTION 'synthetic commit failure'; END;
             $$ LANGUAGE plpgsql;
             CREATE CONSTRAINT TRIGGER cleanup_test_refuse_commit
               AFTER DELETE ON auth_session DEFERRABLE INITIALLY DEFERRED
               FOR EACH ROW EXECUTE FUNCTION cleanup_test_refuse_commit();",
        )
        .await
        .unwrap();
    let failed = cleanup_expired_sessions(&options).await;
    client
        .batch_execute(
            "DROP TRIGGER cleanup_test_refuse_commit ON auth_session;
             DROP FUNCTION cleanup_test_refuse_commit();",
        )
        .await
        .unwrap();
    drop(client);

    assert!(failed.is_err(), "the commit failure propagates");
    assert_eq!(
        closer.closed(),
        [session_target("sweep-expired")],
        "the swept session is closed although its commit failed"
    );
    assert_eq!(
        remaining_sessions(&pool).await,
        ["sweep-expired", "sweep-live"],
        "the failed commit rolled the delete back"
    );

    assert_eq!(cleanup_expired_sessions(&options).await.unwrap(), 1);
    assert_eq!(remaining_sessions(&pool).await, ["sweep-live"]);
    assert_eq!(
        closer.closed(),
        [
            session_target("sweep-expired"),
            session_target("sweep-expired"),
        ],
        "the next pass deletes the row and closes again, never the live session"
    );
}

/// A `ConnectionCloser` that, at each session close, counts the `auth_session`
/// rows left for that id on a fresh pooled connection — `0` once the delete
/// has committed, `1` for a close made ahead of it.
struct CommitProbingCloser {
    pool: Pool,
    /// `(session id, rows seen at its close)`.
    seen_at_close: Mutex<Vec<(String, i64)>>,
}

impl fuz_http::ShutdownCloser for CommitProbingCloser {
    fn close_all_connections(&self) -> usize {
        0
    }
    fn wait_closed(&self) -> fuz_http::WaitClosedFuture<'_> {
        Box::pin(std::future::ready(()))
    }
}

impl ConnectionCloser for CommitProbingCloser {
    fn close_connections(&self, target: &ConnectionCloseTarget) -> usize {
        let ConnectionCloseTarget::Session(target_hash) = target else {
            unreachable!("the sweep closes sessions only")
        };
        let pool = self.pool.clone();
        let session_id = target_hash.to_owned();
        // `ConnectionCloser` is sync; `block_in_place` lets it read the DB from a
        // multi-thread runtime.
        let seen = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async move {
                pool.get()
                    .await
                    .unwrap()
                    .query_one(
                        "SELECT count(*) FROM auth_session WHERE id = $1",
                        &[&session_id],
                    )
                    .await
                    .unwrap()
                    .get::<_, i64>(0)
            })
        });
        self.seen_at_close
            .lock()
            .push((target_hash.to_owned(), seen));
        0
    }
}

/// **The sweep closes a session only once its delete has committed** — the
/// rule every revocation close keeps. For an expired session it is not what
/// refuses a recheck (`query_session_get_valid` already does, row or no
/// row); it keeps the sweep inside the invariant admission leans on — a
/// close that missed a registration belongs to a write the re-read can see
/// — without resting on the re-read's clock. The probe reads on its own
/// pooled connection, so it sees the row unless the delete is durable.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs Postgres"]
async fn the_session_sweep_closes_only_after_the_delete_commits() {
    let pool = fresh_db_pool().await;
    let a = seed_accounts(&pool).await;
    seed_sessions(
        &pool,
        &[
            ("sweep-expired-1", a.recipient_account_id, true),
            ("sweep-expired-2", a.recipient_account_id_2, true),
            ("sweep-live", a.recipient_account_id, false),
        ],
    )
    .await;

    let closer = Arc::new(CommitProbingCloser {
        pool: pool.clone(),
        seen_at_close: Mutex::default(),
    });
    let options = AuthCleanupOptions {
        pool: pool.clone(),
        audit: Arc::new(AuditEmitter::new(pool.clone())),
        connection_closer: Arc::<CommitProbingCloser>::clone(&closer),
    };
    assert_eq!(cleanup_expired_sessions(&options).await.unwrap(), 2);

    let mut seen = closer.seen_at_close.lock().clone();
    seen.sort();
    assert_eq!(
        seen,
        [
            ("sweep-expired-1".to_owned(), 0),
            ("sweep-expired-2".to_owned(), 0),
        ],
        "each close ran for a row already gone"
    );
}

#[tokio::test]
#[ignore = "needs Postgres"]
async fn a_re_offer_clears_the_stamp_so_the_refreshed_expiry_is_audited_again() {
    let pool = fresh_db_pool().await;
    let a = seed_accounts(&pool).await;
    let (options, _) = options_recording(&pool);

    let first = offer(
        &pool,
        a.grantor_actor_id,
        a.recipient_account_id,
        None,
        "teacher",
        past(),
    )
    .await;
    assert_eq!(
        cleanup_expired_role_grant_offers(&options).await.unwrap(),
        1
    );
    assert_eq!(stamped_offer_ids(&pool).await, [first.id]);

    // the expired row is still pending, so the same-tuple re-offer upserts it
    let reoffered = offer(
        &pool,
        a.grantor_actor_id,
        a.recipient_account_id,
        None,
        "teacher",
        future(),
    )
    .await;
    assert_eq!(
        reoffered.id, first.id,
        "the re-offer refreshed the same row"
    );
    assert_eq!(
        reoffered.expire_audited_at, None,
        "the re-offer cleared the stamp"
    );
    assert_eq!(
        cleanup_expired_role_grant_offers(&options).await.unwrap(),
        0
    );

    backdate_expiry(&pool, first.id).await;
    assert_eq!(
        cleanup_expired_role_grant_offers(&options).await.unwrap(),
        1
    );

    let audits = expire_audits(&pool).await;
    assert_eq!(audits.len(), 2);
    for (.., offer_id) in &audits {
        assert_eq!(*offer_id, first.id.to_string());
    }
}

#[tokio::test]
#[ignore = "needs Postgres"]
async fn a_failed_audit_insert_rolls_the_stamps_back() {
    let pool = fresh_db_pool().await;
    let a = seed_accounts(&pool).await;
    offer(
        &pool,
        a.grantor_actor_id,
        a.recipient_account_id,
        None,
        "teacher",
        past(),
    )
    .await;
    let (options, events) = options_recording(&pool);

    let client = pool.get().await.unwrap();
    client
        .batch_execute(
            "CREATE FUNCTION cleanup_test_refuse_audit() RETURNS trigger AS $$
               BEGIN RAISE EXCEPTION 'synthetic audit failure'; END;
             $$ LANGUAGE plpgsql;
             CREATE TRIGGER cleanup_test_refuse_audit BEFORE INSERT ON audit_log
               FOR EACH ROW EXECUTE FUNCTION cleanup_test_refuse_audit();",
        )
        .await
        .unwrap();
    let failed = cleanup_expired_role_grant_offers(&options).await;
    client
        .batch_execute(
            "DROP TRIGGER cleanup_test_refuse_audit ON audit_log;
             DROP FUNCTION cleanup_test_refuse_audit();",
        )
        .await
        .unwrap();
    drop(client);

    assert!(failed.is_err(), "the audit failure propagates");
    assert!(
        stamped_offer_ids(&pool).await.is_empty(),
        "the claim rolled back with the audit insert"
    );
    assert!(
        events.lock().is_empty(),
        "nothing fans out from a rolled-back pass"
    );

    assert_eq!(
        cleanup_expired_role_grant_offers(&options).await.unwrap(),
        1
    );
    assert_eq!(events.lock().len(), 1);
}

/// Two passes can't audit one expiry twice: a pass that meets a row another
/// transaction has claimed (stamped, uncommitted) blocks on its row lock, and
/// once that commits, the re-checked `expire_audited_at IS NULL` skips it.
#[tokio::test]
#[ignore = "needs Postgres"]
async fn a_pass_waits_on_a_claimed_row_then_skips_it() {
    let pool = fresh_db_pool().await;
    let a = seed_accounts(&pool).await;
    let held = offer(
        &pool,
        a.grantor_actor_id,
        a.recipient_account_id,
        None,
        "teacher",
        past(),
    )
    .await;
    let free = offer(
        &pool,
        a.grantor_actor_id,
        a.recipient_account_id_2,
        None,
        "moderator",
        past(),
    )
    .await;

    // the other "pass": claim `held` and keep the transaction open
    let mut other = pool.get().await.unwrap();
    let other_tx = other.transaction().await.unwrap();
    other_tx
        .execute(
            "UPDATE role_grant_offer SET expire_audited_at = NOW() WHERE id = $1",
            &[&held.id],
        )
        .await
        .unwrap();

    let (options, events) = options_recording(&pool);
    let sweep = tokio::spawn(async move { cleanup_expired_role_grant_offers(&options).await });

    // wait until the sweep's backend is blocked on a row lock
    let probe = pool.get().await.unwrap();
    let mut waited = false;
    for _ in 0..200 {
        let blocked: i64 = probe
            .query_one(
                "SELECT count(*) FROM pg_stat_activity
                 WHERE datname = current_database() AND wait_event_type = 'Lock'",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        if blocked > 0 {
            waited = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(waited, "the sweep blocked on the claimed row's lock");
    assert!(!sweep.is_finished(), "the sweep is still waiting");

    other_tx.commit().await.unwrap();
    let audited = sweep.await.unwrap().unwrap();
    assert_eq!(audited, 1, "only the free row is claimed");

    let audits = expire_audits(&pool).await;
    assert_eq!(audits.len(), 1);
    assert_eq!(audits[0].4, free.id.to_string());
    assert_eq!(events.lock().len(), 1);
}

/// Fan-out runs after the commit: a listener reading on a fresh pooled
/// connection sees its own audit row and the offer's stamp. Drained before
/// the commit, it would see neither (both still uncommitted).
#[tokio::test]
#[ignore = "needs Postgres"]
async fn listeners_fire_only_after_the_commit() {
    let pool = fresh_db_pool().await;
    let a = seed_accounts(&pool).await;
    let expired = offer(
        &pool,
        a.grantor_actor_id,
        a.recipient_account_id,
        None,
        "teacher",
        past(),
    )
    .await;

    let audit = Arc::new(AuditEmitter::new(pool.clone()));
    // `(audit row visible, offer stamp visible)` per event
    let observed: Arc<Mutex<Vec<(bool, bool)>>> = Arc::default();
    let sink = Arc::clone(&observed);
    let listener_pool = pool.clone();
    audit.add_listener(Arc::new(move |event| {
        let sink = Arc::clone(&sink);
        let pool = listener_pool.clone();
        Box::pin(async move {
            let client = pool.get().await.unwrap();
            let audit_rows: i64 = client
                .query_one("SELECT count(*) FROM audit_log WHERE id = $1", &[&event.id])
                .await
                .unwrap()
                .get(0);
            let offer_id: Uuid = event
                .metadata
                .as_ref()
                .and_then(|m| m.get("offer_id"))
                .and_then(serde_json::Value::as_str)
                .and_then(|s| Uuid::parse_str(s).ok())
                .expect("offer_id in metadata");
            let stamped: bool = client
                .query_one(
                    "SELECT expire_audited_at IS NOT NULL FROM role_grant_offer WHERE id = $1",
                    &[&offer_id],
                )
                .await
                .unwrap()
                .get(0);
            sink.lock().push((audit_rows == 1, stamped));
        })
    }));
    let options = AuthCleanupOptions {
        pool: pool.clone(),
        audit,
        connection_closer: Arc::new(NoopConnectionCloser),
    };

    assert_eq!(
        cleanup_expired_role_grant_offers(&options).await.unwrap(),
        1
    );
    assert_eq!(
        *observed.lock(),
        [(true, true)],
        "the listener saw the committed audit row and stamp for offer {}",
        expired.id
    );
}

/// Bounds each wait on the spawned cleanup, so a pass that never runs fails
/// the test instead of hanging it.
const SPAWNED_PASS_TIMEOUT: Duration = Duration::from_secs(30);

/// The `offer_id` an expiry event carries.
fn event_offer_id(event: &AuditLogEvent) -> String {
    event
        .metadata
        .as_ref()
        .and_then(|m| m.get("offer_id"))
        .and_then(serde_json::Value::as_str)
        .expect("offer_id in metadata")
        .to_owned()
}

/// The scheduler end to end: the startup pass runs both sweeps with no wait
/// — the session sweep closing for the session it deleted — a later pass
/// picks up what expired since, and cancelling the token ends the task.
/// Driven by the audit fan-out, so nothing here sleeps.
#[tokio::test]
#[ignore = "needs Postgres"]
async fn spawn_auth_cleanup_sweeps_at_startup_and_on_its_interval_until_cancelled() {
    let pool = fresh_db_pool().await;
    let a = seed_accounts(&pool).await;
    seed_sessions(
        &pool,
        &[
            ("cleanup-expired", a.recipient_account_id, true),
            ("cleanup-live", a.recipient_account_id, false),
        ],
    )
    .await;
    let at_startup = offer(
        &pool,
        a.grantor_actor_id,
        a.recipient_account_id,
        None,
        "teacher",
        past(),
    )
    .await;

    let audit = Arc::new(AuditEmitter::new(pool.clone()));
    let (tx, mut swept) = tokio::sync::mpsc::unbounded_channel::<Arc<AuditLogEvent>>();
    audit.add_listener(Arc::new(move |event| {
        // the receiver outlives the task; a send after the test's last
        // `recv` has nowhere to go and doesn't matter
        let _ = tx.send(event);
        Box::pin(async {})
    }));
    let shutdown = CancellationToken::new();
    let closer = Arc::new(RecordingCloser::default());
    let task = spawn_auth_cleanup(
        AuthCleanupOptions {
            pool: pool.clone(),
            audit,
            connection_closer: Arc::<RecordingCloser>::clone(&closer),
        },
        // short, so the second pass below arrives without a wait worth
        // naming; the startup pass must not need it
        Duration::from_millis(50),
        shutdown.clone(),
    );

    // the startup pass: the offer sweep fans its event out, and the session
    // sweep ran before it
    let event = tokio::time::timeout(SPAWNED_PASS_TIMEOUT, swept.recv())
        .await
        .expect("the startup pass sweeps the expired offer")
        .expect("the listener is registered");
    assert_eq!(event_offer_id(&event), at_startup.id.to_string());
    assert_eq!(
        remaining_sessions(&pool).await,
        ["cleanup-live"],
        "the session sweep ran too"
    );
    assert_eq!(
        closer.closed(),
        [session_target("cleanup-expired")],
        "and closed for the session it swept"
    );

    // an offer that expires afterwards is picked up by a later pass
    let later = offer(
        &pool,
        a.grantor_actor_id,
        a.recipient_account_id_2,
        None,
        "moderator",
        past(),
    )
    .await;
    let event = tokio::time::timeout(SPAWNED_PASS_TIMEOUT, swept.recv())
        .await
        .expect("a later pass sweeps the newly expired offer")
        .expect("the listener is registered");
    assert_eq!(event_offer_id(&event), later.id.to_string());
    assert_eq!(expire_audits(&pool).await.len(), 2, "each audited once");
    assert_eq!(
        closer.closed().len(),
        1,
        "later passes swept no session, so they closed nothing"
    );
    assert!(!task.is_finished(), "the task runs until shutdown");

    shutdown.cancel();
    tokio::time::timeout(SPAWNED_PASS_TIMEOUT, task)
        .await
        .expect("cancelling the token ends the task")
        .expect("the task ends cleanly");
}
