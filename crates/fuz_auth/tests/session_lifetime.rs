//! A session lives its lifetime in elapsed time: the insert adds seconds, not
//! days, so a DST change inside the lifetime in the session's time zone
//! neither lengthens nor shortens it. Twin of `fuz_app`'s
//! `session_queries.db.test.ts` case.

mod common;

use fuz_auth::{SESSION_AGE_MAX, create_capped_session};

#[tokio::test]
#[ignore = "postgres-only: a DST SET TIME ZONE"]
async fn session_lifetime_is_elapsed_time_across_a_dst_change() {
    let pool = common::fresh_postgres_db().await;
    let account_id = common::seed_account(&pool, "session_lifetime_user", None).await;
    let mut client = pool.get().await.expect("pool.get");
    let tx = client.transaction().await.expect("begin");

    let doy: i32 = tx
        .query_one(
            "SELECT EXTRACT(DOY FROM NOW() AT TIME ZONE 'UTC')::int",
            &[],
        )
        .await
        .expect("day of year")
        .get(0);
    // a POSIX zone that springs forward two weeks out and falls back half a
    // year on: a change inside the lifetime, whatever today is
    let start = (doy + 14) % 365 + 1;
    let end = (doy + 194) % 365 + 1;
    tx.batch_execute(&format!(
        "SET LOCAL TimeZone = '<-05>5<-04>,J{start},J{end}'"
    ))
    .await
    .expect("set time zone");

    let session = create_capped_session(&tx, &account_id)
        .await
        .expect("create_capped_session");
    let token_hash = fuz_auth::hash_session_token(&session.token);
    let lifetime_s: f64 = tx
        .query_one(
            "SELECT EXTRACT(EPOCH FROM expires_at - created_at)::float8
             FROM auth_session WHERE id = $1",
            &[&token_hash.as_str()],
        )
        .await
        .expect("session row")
        .get(0);
    tx.rollback().await.expect("rollback");

    #[expect(
        clippy::cast_precision_loss,
        reason = "a 30-day lifetime in seconds is exact in f64"
    )]
    let expected = SESSION_AGE_MAX as f64;
    assert!(
        (lifetime_s - expected).abs() < f64::EPSILON,
        "lifetime {lifetime_s} s, expected {expected} s"
    );
}
