//! [`fuz_realtime::RealtimeCloser`] — each `ConnectionCloser` close reaches
//! **both** registries, WS and SSE.
//!
//! **The gap this closes.** A revocation handler's direct close is the only
//! close guaranteed to run on the REST `/logout` / `/password` paths, whose
//! audit write is pool-routed and fail-open — the audit listeners fire only on
//! a written row. A closer over the WS registry alone skips SSE there, so a
//! failed audit INSERT would leave the account's audit streams open for their
//! lifetime (a stream never rechecks its credential).
//!
//! Each case opens one matching and one non-matching connection on each
//! transport, closes through the fan-out, and asserts the matching pair ended
//! — the SSE body completes, the WS signal is cancelled — while the other pair
//! is untouched. The distinct identity keys per connection also pin that each
//! target matches its own key (`ConnectionIdentity::matches`): a session close
//! read as the token predicate matches nothing here.
//!
//! The end-to-end companion (a real `/logout` / `/password` with the audit
//! INSERT made to fail) is the `#[ignore]` Postgres suite in
//! `tests/audit_stream.rs`.

#![expect(
    clippy::unwrap_used,
    reason = "test helpers outside `#[test]` fns panic on a failed setup or check"
)]

use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use futures::stream::Stream;
use fuz_auth::ConnectionCloseTarget;
use fuz_auth::ConnectionCloser;
use fuz_realtime::ConnectionIdentity;
use fuz_realtime::{Connection, ConnectionRegistry, RealtimeCloser, SseRegistry, SseSubscription};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

mod common;

type SseBody = Pin<Box<dyn Stream<Item = Result<String, std::convert::Infallible>> + Send>>;

/// One connection's identity keys, used for its WS socket and SSE stream alike.
struct Identity {
    account_id: Uuid,
    session_hash: &'static str,
    token_id: &'static str,
}

const TARGET: Identity = Identity {
    account_id: Uuid::from_u128(1),
    session_hash: "session_target",
    token_id: "tok_target",
};

const BYSTANDER: Identity = Identity {
    account_id: Uuid::from_u128(2),
    session_hash: "session_bystander",
    token_id: "tok_bystander",
};

/// The role every connection here is gated on — the role close's key.
const GATING_ROLE: &str = "admin";

/// Both registries, a matching and a non-matching connection on each, and the
/// fan-out closer over the same registry instances.
struct Fixture {
    ws: Arc<ConnectionRegistry>,
    sse: Arc<SseRegistry>,
    closer: Arc<dyn ConnectionCloser>,
    target_ws: Connection,
    bystander_ws: Connection,
    target_sse: SseBody,
    bystander_sse: SseBody,
}

fn add_ws(ws: &ConnectionRegistry, identity: &Identity) -> Connection {
    // The receiver is dropped; only the registry entry and its signal matter.
    let (tx, _rx) = fuz_realtime::connection_channel(1 << 20);
    ws.add_connection(
        tx,
        ConnectionIdentity {
            session_hash: Some(identity.session_hash.to_owned()),
            account_id: Some(identity.account_id),
            api_token_id: Some(identity.token_id.to_owned()),
            required_roles: vec![GATING_ROLE],
        },
        CancellationToken::new(),
    )
}

async fn add_sse(sse: &Arc<SseRegistry>, identity: &Identity) -> SseBody {
    let mut body: SseBody = Box::pin(common::subscribe_admitted(
        sse,
        SseSubscription {
            identity: ConnectionIdentity {
                account_id: Some(identity.account_id),
                session_hash: Some(identity.session_hash.to_owned()),
                api_token_id: Some(identity.token_id.to_owned()),
                required_roles: vec![GATING_ROLE],
            },
            credential_deadline: None,
        },
    ));
    assert!(body.next().await.is_some(), "connect comment");
    body
}

async fn fixture() -> Fixture {
    let ws = Arc::new(ConnectionRegistry::new());
    let sse = Arc::new(SseRegistry::new());
    let closer = RealtimeCloser::connection_closer(&ws, &sse);
    let target_ws = add_ws(&ws, &TARGET);
    let bystander_ws = add_ws(&ws, &BYSTANDER);
    let target_sse = add_sse(&sse, &TARGET).await;
    let bystander_sse = add_sse(&sse, &BYSTANDER).await;
    Fixture {
        ws,
        sse,
        closer,
        target_ws,
        bystander_ws,
        target_sse,
        bystander_sse,
    }
}

/// How long the closed stream may take to end before the test calls it never.
/// The close drops the sender synchronously, so a passing case never waits.
const CLOSE_TIMEOUT: Duration = Duration::from_secs(5);

/// Assert `closed` (the closer's return) counted one connection per transport,
/// that exactly the target pair ended, and that the bystander pair still runs.
async fn assert_only_the_target_closed(mut fx: Fixture, closed: usize, what: &str) {
    assert_eq!(closed, 2, "{what}: one WS socket plus one SSE stream");

    assert!(
        fx.target_ws.signal.is_cancelled(),
        "{what}: the WS socket was not closed"
    );
    assert!(!fx.ws.is_registered(fx.target_ws.id));
    let drained = async { while fx.target_sse.next().await.is_some() {} };
    assert!(
        tokio::time::timeout(CLOSE_TIMEOUT, drained).await.is_ok(),
        "{what}: the SSE stream was never closed"
    );
    assert_eq!(fx.sse.count(), 1, "{what}: only the target stream closed");

    assert!(!fx.bystander_ws.signal.is_cancelled());
    assert!(fx.ws.is_registered(fx.bystander_ws.id));
    assert_eq!(fx.sse.broadcast("data: kept\n\n"), 1);
    assert_eq!(
        fx.bystander_sse.next().await.unwrap().unwrap(),
        "data: kept\n\n",
        "{what}: the bystander stream still receives the fan-out"
    );
}

#[tokio::test]
async fn an_account_close_reaches_ws_and_sse() {
    let fx = fixture().await;
    let closed = fx
        .closer
        .close_connections(&ConnectionCloseTarget::Account(TARGET.account_id));
    assert_only_the_target_closed(fx, closed, "account").await;
}

#[tokio::test]
async fn a_session_close_reaches_ws_and_sse() {
    let fx = fixture().await;
    let closed = fx.closer.close_connections(&ConnectionCloseTarget::Session(
        TARGET.session_hash.to_owned(),
    ));
    assert_only_the_target_closed(fx, closed, "session").await;
}

#[tokio::test]
async fn a_role_close_reaches_ws_and_sse() {
    let fx = fixture().await;
    let closed = fx.closer.close_connections(&ConnectionCloseTarget::Role {
        account_id: TARGET.account_id,
        role: GATING_ROLE.to_owned(),
    });
    assert_only_the_target_closed(fx, closed, "role").await;
}

#[tokio::test]
async fn a_token_close_reaches_ws_and_sse() {
    let fx = fixture().await;
    let closed = fx
        .closer
        .close_connections(&ConnectionCloseTarget::Token(TARGET.token_id.to_owned()));
    assert_only_the_target_closed(fx, closed, "token").await;
}
