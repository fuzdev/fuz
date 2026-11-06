//! An SSE stream ends when the credential it was opened with expires
//! ([`fuz_realtime::SseSubscription::credential_deadline`]) — the close a
//! revocation makes: what was queued is still written, then the body ends with
//! no final frame and the registration is gone.
//!
//! The registry is credential-agnostic, so the deadline is pinned for both
//! identity shapes a stream carries — a session's (`session_hash`) and an API
//! token's (`api_token_id`). The token case is the one the cross-backend
//! suite cannot reach: the stock audit stream admits sessions only.
//!
//! The clock is paused, so a 30-day deadline is reached without waiting, and
//! the wait sleeps in bounded steps rather than once. Keep-alives are off
//! ([`SseRegistry::with_keep_alive`]): a stream idle for days on the paused
//! clock would otherwise read one every interval, and these cases watch for
//! the stream to end.

// `allow-*-in-tests` doesn't cover the non-`#[test]` helper fns.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Duration;

use futures::StreamExt;
use fuz_realtime::ConnectionIdentity;
use fuz_realtime::{SSE_CONNECTED_COMMENT, SseRegistry, SseSubscription};
use std::sync::Arc;

const DAY: Duration = Duration::from_hours(24);

/// Now on the paused clock, as the `std` instant a resolved credential
/// carries — `std::time::Instant::now()` does not move with the paused clock.
fn now() -> std::time::Instant {
    tokio::time::Instant::now().into_std()
}

fn session_subscription(deadline: Option<std::time::Instant>) -> SseSubscription {
    SseSubscription {
        identity: ConnectionIdentity {
            account_id: Some(uuid::Uuid::new_v4()),
            session_hash: Some("session-hash".to_owned()),
            api_token_id: None,
            required_roles: vec!["admin"],
        },
        credential_deadline: deadline,
    }
}

fn token_subscription(deadline: Option<std::time::Instant>) -> SseSubscription {
    SseSubscription {
        identity: ConnectionIdentity {
            account_id: Some(uuid::Uuid::new_v4()),
            session_hash: None,
            api_token_id: Some("tok_deadline".to_owned()),
            required_roles: vec!["admin"],
        },
        credential_deadline: deadline,
    }
}

/// Open `subscription` through the two-phase registration the audit route
/// runs, and read its connect comment.
async fn open_admitted(
    registry: &Arc<SseRegistry>,
    subscription: SseSubscription,
) -> std::pin::Pin<Box<dyn futures::Stream<Item = Result<String, std::convert::Infallible>> + Send>>
{
    let pending = registry.subscribe_pending(subscription);
    let mut stream: std::pin::Pin<Box<dyn futures::Stream<Item = _> + Send>> =
        Box::pin(registry.admit(pending).expect("admitted"));
    assert_eq!(
        stream
            .next()
            .await
            .expect("connect comment")
            .expect("infallible"),
        SSE_CONNECTED_COMMENT
    );
    stream
}

/// Whether `stream` ends within `wait` — `false` past it, so a stream that
/// never ends fails the case rather than hanging it (the paused clock has no
/// timer to advance to once a deadline wait is missing).
async fn ends_within<S>(stream: &mut S, wait: Duration) -> bool
where
    S: futures::Stream<Item = Result<String, std::convert::Infallible>> + Unpin,
{
    matches!(tokio::time::timeout(wait, stream.next()).await, Ok(None))
}

/// A stream opened on a credential with 30 days left runs for 29 of them and
/// ends at the 30th, for a session and for an API token alike.
#[tokio::test(start_paused = true)]
async fn a_stream_ends_at_its_credential_deadline() {
    for subscription in [session_subscription, token_subscription] {
        let registry = Arc::new(SseRegistry::new().with_keep_alive(None));
        let opened = tokio::time::Instant::now();
        let mut stream = open_admitted(&registry, subscription(Some(now() + 30 * DAY))).await;

        assert!(
            tokio::time::timeout(29 * DAY, stream.next()).await.is_err(),
            "the stream ended before its deadline"
        );
        assert_eq!(registry.count(), 1, "still registered before the deadline");
        assert!(
            ends_within(&mut stream, 2 * DAY).await,
            "the stream ends at its deadline"
        );
        assert!(
            opened.elapsed() >= 30 * DAY,
            "ended early: {:?}",
            opened.elapsed()
        );
        assert_eq!(registry.count(), 0, "the registration is gone");
    }
}

/// A frame queued before the deadline and not yet read is still written —
/// the stream ends as a revoked one does, draining what was queued.
#[tokio::test(start_paused = true)]
async fn a_frame_queued_before_the_deadline_is_still_written() {
    let registry = Arc::new(SseRegistry::new().with_keep_alive(None));
    let mut stream = open_admitted(&registry, token_subscription(Some(now() + DAY))).await;
    assert_eq!(registry.broadcast("data: {\"queued\":1}\n\n"), 1);
    tokio::time::advance(DAY + Duration::from_secs(1)).await;
    assert_eq!(
        stream
            .next()
            .await
            .expect("the queued frame")
            .expect("infallible"),
        "data: {\"queued\":1}\n\n"
    );
    assert!(ends_within(&mut stream, DAY).await);
    assert_eq!(registry.count(), 0);
}

/// A stream with no deadline — a daemon token, an eternal API token — does
/// not end on the clock.
#[tokio::test(start_paused = true)]
async fn a_stream_without_a_deadline_does_not_end() {
    let registry = Arc::new(SseRegistry::new().with_keep_alive(None));
    let mut stream = open_admitted(&registry, token_subscription(None)).await;
    assert!(
        tokio::time::timeout(400 * DAY, stream.next())
            .await
            .is_err()
    );
    assert_eq!(registry.count(), 1);
}
