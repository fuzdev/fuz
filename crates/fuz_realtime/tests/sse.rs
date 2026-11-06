//! Integration tests for the SSE registry primitive
//! ([`fuz_realtime::SseRegistry`]). Mirrors the WS-half coverage in
//! `connection_registry.rs`: connect comment, fan-out, account-scoped
//! close, subscriber cleanup on stream drop, the per-session stream cap
//! (evict-oldest, keyed on the session hash), two-phase registration
//! (`subscribe_pending` → `admit`): a pending stream is closeable and
//! otherwise inert, and the cap acts only at admission — and the outbound
//! bound: a stream nobody reads is ended at its queue budget, without
//! slowing the fan-out or the streams beside it — and the keep-alive comment
//! an idle stream writes on its interval.
//!
//! The registries are built with keep-alives off ([`SseRegistry::with_keep_alive`]),
//! except in the keep-alive cases: the rest drive a body by hand, outside a
//! runtime, and its clock needs one.

use std::convert::Infallible;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::{Arc, Barrier};

use futures::{FutureExt, Stream, StreamExt};
use fuz_auth::ConnectionCloseTarget;
use fuz_auth::ConnectionCloser as _;
use fuz_realtime::ConnectionIdentity;
use fuz_realtime::{
    AUDIT_LOG_SSE_MAX_PER_SCOPE, NotAdmitted, OUTBOUND_FRAME_OVERHEAD_BYTES, PendingSseStream,
    SSE_CONNECTED_COMMENT, SSE_KEEP_ALIVE_COMMENT, SSE_KEEP_ALIVE_INTERVAL,
    SSE_KEEP_ALIVE_INTERVAL_MAX, SSE_OUTBOUND_QUEUE_BYTES, SseRegistry, SseSubscription,
    sse_keep_alive_is_valid,
};

mod common;

#[tokio::test]
async fn subscribe_yields_connect_comment_then_broadcasts() {
    let registry = Arc::new(SseRegistry::new().with_keep_alive(None));
    let account = uuid::Uuid::new_v4();
    let mut stream = Box::pin(common::subscribe_admitted(
        &registry,
        SseSubscription {
            identity: ConnectionIdentity {
                account_id: Some(account),
                ..ConnectionIdentity::default()
            },
            ..SseSubscription::default()
        },
    ));

    let first = stream.next().await.unwrap().unwrap();
    assert_eq!(
        first, SSE_CONNECTED_COMMENT,
        "first frame is the connect comment"
    );
    assert_eq!(registry.count(), 1);

    let reached = registry.broadcast("data: {\"x\":1}\n\n");
    assert_eq!(reached, 1);
    let frame = stream.next().await.unwrap().unwrap();
    assert_eq!(frame, "data: {\"x\":1}\n\n");
}

#[tokio::test]
async fn an_account_close_ends_the_subscribers_stream() {
    let registry = Arc::new(SseRegistry::new().with_keep_alive(None));
    let account = uuid::Uuid::new_v4();
    let mut stream = Box::pin(common::subscribe_admitted(
        &registry,
        SseSubscription {
            identity: ConnectionIdentity {
                account_id: Some(account),
                ..ConnectionIdentity::default()
            },
            ..SseSubscription::default()
        },
    ));
    let _connect = stream.next().await;

    assert_eq!(
        registry.close_connections(&ConnectionCloseTarget::Account(account)),
        1
    );
    // sender dropped → the stream completes.
    assert!(stream.next().await.is_none(), "stream ends after close");
    assert_eq!(registry.count(), 0);
}

#[tokio::test]
async fn an_account_close_spares_other_accounts() {
    let registry = Arc::new(SseRegistry::new().with_keep_alive(None));
    let account_a = uuid::Uuid::new_v4();
    let account_b = uuid::Uuid::new_v4();
    let mut stream_a = Box::pin(common::subscribe_admitted(
        &registry,
        SseSubscription {
            identity: ConnectionIdentity {
                account_id: Some(account_a),
                ..ConnectionIdentity::default()
            },
            ..SseSubscription::default()
        },
    ));
    let mut stream_b = Box::pin(common::subscribe_admitted(
        &registry,
        SseSubscription {
            identity: ConnectionIdentity {
                account_id: Some(account_b),
                ..ConnectionIdentity::default()
            },
            ..SseSubscription::default()
        },
    ));
    let _ = stream_a.next().await;
    let _ = stream_b.next().await;

    assert_eq!(
        registry.close_connections(&ConnectionCloseTarget::Account(account_a)),
        1
    );
    assert_eq!(registry.count(), 1, "only account_a's stream closed");

    // account_b still receives the fan-out.
    assert_eq!(registry.broadcast("data: kept\n\n"), 1);
    assert_eq!(stream_b.next().await.unwrap().unwrap(), "data: kept\n\n");
}

#[tokio::test]
async fn a_session_close_closes_only_the_matching_session() {
    let registry = Arc::new(SseRegistry::new().with_keep_alive(None));
    let account = uuid::Uuid::new_v4();
    // two streams on the same account, opened under different sessions.
    let mut stream_a = Box::pin(common::subscribe_admitted(
        &registry,
        SseSubscription {
            identity: ConnectionIdentity {
                account_id: Some(account),
                session_hash: Some("hash_a".to_owned()),
                ..ConnectionIdentity::default()
            },
            ..SseSubscription::default()
        },
    ));
    let mut stream_b = Box::pin(common::subscribe_admitted(
        &registry,
        SseSubscription {
            identity: ConnectionIdentity {
                account_id: Some(account),
                session_hash: Some("hash_b".to_owned()),
                ..ConnectionIdentity::default()
            },
            ..SseSubscription::default()
        },
    ));
    let _ = stream_a.next().await;
    let _ = stream_b.next().await;

    assert_eq!(
        registry.close_connections(&ConnectionCloseTarget::Session("hash_a".to_owned())),
        1
    );
    assert_eq!(registry.count(), 1, "only session hash_a's stream closed");
    // session hash_b still receives the fan-out.
    assert_eq!(registry.broadcast("data: kept\n\n"), 1);
    assert_eq!(stream_b.next().await.unwrap().unwrap(), "data: kept\n\n");
}

#[tokio::test]
async fn a_role_close_matches_account_and_role() {
    let registry = Arc::new(SseRegistry::new().with_keep_alive(None));
    let account = uuid::Uuid::new_v4();
    let other = uuid::Uuid::new_v4();
    let mut admin_stream = Box::pin(common::subscribe_admitted(
        &registry,
        SseSubscription {
            identity: ConnectionIdentity {
                account_id: Some(account),
                required_roles: vec!["admin"],
                ..ConnectionIdentity::default()
            },
            ..SseSubscription::default()
        },
    ));
    let mut other_stream = Box::pin(common::subscribe_admitted(
        &registry,
        SseSubscription {
            identity: ConnectionIdentity {
                account_id: Some(other),
                required_roles: vec!["admin"],
                ..ConnectionIdentity::default()
            },
            ..SseSubscription::default()
        },
    ));
    let _ = admin_stream.next().await;
    let _ = other_stream.next().await;

    // a different role on the same account doesn't match.
    assert_eq!(
        registry.close_connections(&ConnectionCloseTarget::Role {
            account_id: account,
            role: "moderator".to_owned()
        }),
        0
    );
    // the matching account + role closes.
    assert_eq!(
        registry.close_connections(&ConnectionCloseTarget::Role {
            account_id: account,
            role: "admin".to_owned()
        }),
        1
    );
    assert_eq!(
        registry.count(),
        1,
        "only the account's admin stream closed"
    );
    assert_eq!(registry.broadcast("data: kept\n\n"), 1);
    assert_eq!(
        other_stream.next().await.unwrap().unwrap(),
        "data: kept\n\n"
    );
}

#[tokio::test]
async fn dropping_the_stream_removes_the_subscriber() {
    let registry = Arc::new(SseRegistry::new().with_keep_alive(None));
    let account = uuid::Uuid::new_v4();
    {
        let mut stream = Box::pin(common::subscribe_admitted(
            &registry,
            SseSubscription {
                identity: ConnectionIdentity {
                    account_id: Some(account),
                    ..ConnectionIdentity::default()
                },
                ..SseSubscription::default()
            },
        ));
        let _ = stream.next().await;
        assert_eq!(registry.count(), 1);
    }
    // the guard's Drop removed the subscriber.
    assert_eq!(registry.count(), 0);
}

// -- per-session stream cap ---------------------------------------------------

type SseBody = Pin<Box<dyn Stream<Item = Result<String, Infallible>> + Send>>;

fn capped(max: usize) -> Arc<SseRegistry> {
    Arc::new(
        SseRegistry::new()
            .with_keep_alive(None)
            .with_max_per_scope(NonZeroUsize::new(max)),
    )
}

/// Open a stream for `account` under `session_hash`, leaving its connect
/// comment unread.
fn open(registry: &Arc<SseRegistry>, account: uuid::Uuid, session_hash: Option<&str>) -> SseBody {
    Box::pin(common::subscribe_admitted(
        registry,
        SseSubscription {
            identity: ConnectionIdentity {
                account_id: Some(account),
                session_hash: session_hash.map(str::to_owned),
                ..ConnectionIdentity::default()
            },
            ..SseSubscription::default()
        },
    ))
}

/// Assert `stream` was ended by the registry: its next item is already `None`
/// (no pending wait — the sender is gone).
fn assert_ended(stream: &mut SseBody) {
    assert_eq!(
        stream
            .next()
            .now_or_never()
            .map(|item| item.map(Result::unwrap)),
        Some(None),
        "evicted: the body ends with no further frame"
    );
}

/// Read and check the connect comment every stream opens with.
fn read_connect(stream: &mut SseBody) {
    assert_eq!(
        stream.next().now_or_never().flatten().map(Result::unwrap),
        Some(SSE_CONNECTED_COMMENT.to_owned()),
    );
}

/// Assert each of `streams` (connect comment already read) is still
/// registered, by delivering one frame to it.
fn assert_all_live(registry: &SseRegistry, streams: &mut [SseBody]) {
    let reached = registry.broadcast("data: live\n\n");
    assert!(reached >= streams.len(), "broadcast reached {reached}");
    for stream in streams {
        assert_eq!(
            stream.next().now_or_never().flatten().map(Result::unwrap),
            Some("data: live\n\n".to_owned()),
            "live: still receives the fan-out"
        );
    }
}

/// The TS twin's audit-SSE cap case: one past the default on one session
/// ends the oldest stream — after its connect comment, with no final frame —
/// and leaves the newest ten open.
#[test]
fn new_caps_streams_per_session_at_the_audit_default() {
    let registry = Arc::new(SseRegistry::new().with_keep_alive(None));
    let account = uuid::Uuid::new_v4();
    let mut streams: Vec<SseBody> = (0..=AUDIT_LOG_SSE_MAX_PER_SCOPE)
        .map(|_| open(&registry, account, Some("session")))
        .collect();
    assert_eq!(registry.count(), AUDIT_LOG_SSE_MAX_PER_SCOPE);

    let mut oldest = streams.remove(0);
    read_connect(&mut oldest);
    assert_ended(&mut oldest);

    for stream in &mut streams {
        read_connect(stream);
    }
    assert_all_live(&registry, &mut streams);
}

#[test]
fn default_applies_the_same_cap_as_new() {
    let registry = Arc::new(SseRegistry::default().with_keep_alive(None));
    let account = uuid::Uuid::new_v4();
    let _streams: Vec<SseBody> = (0..AUDIT_LOG_SSE_MAX_PER_SCOPE * 2)
        .map(|_| open(&registry, account, Some("session")))
        .collect();
    assert_eq!(registry.count(), AUDIT_LOG_SSE_MAX_PER_SCOPE);
}

/// An override is respected, and eviction is per session: another session's
/// stream on the same account is never the one closed.
#[test]
fn cap_override_closes_only_the_sessions_oldest_stream() {
    let registry = capped(2);
    let account = uuid::Uuid::new_v4();
    let mut a1 = open(&registry, account, Some("session_a"));
    let b1 = open(&registry, account, Some("session_b"));
    let a2 = open(&registry, account, Some("session_a"));
    assert_eq!(registry.count(), 3, "two on session_a fit under a cap of 2");
    let a3 = open(&registry, account, Some("session_a"));

    assert_eq!(registry.count(), 3);
    read_connect(&mut a1);
    assert_ended(&mut a1);
    let mut live = vec![b1, a2, a3];
    for stream in &mut live {
        read_connect(stream);
    }
    assert_all_live(&registry, &mut live);
}

/// The cap counts tabs per session, not streams per account — an account's
/// total is bounded only transitively, by its session cap (TS parity: the
/// account id is an uncapped `groups` identity there).
#[test]
fn cap_never_counts_across_sessions_of_one_account() {
    let registry = capped(1);
    let account = uuid::Uuid::new_v4();
    let mut streams: Vec<SseBody> = (0..5)
        .map(|i| open(&registry, account, Some(&format!("session_{i}"))))
        .collect();
    assert_eq!(registry.count(), 5);
    for stream in &mut streams {
        read_connect(stream);
    }
    assert_all_live(&registry, &mut streams);
}

/// A stream with no session hash (bearer / daemon-token auth) is never
/// counted — TS parity: a null token hash leaves `scope` unset.
#[test]
fn cap_never_counts_a_stream_without_a_session_hash() {
    let registry = capped(1);
    let account = uuid::Uuid::new_v4();
    let mut streams: Vec<SseBody> = (0..5).map(|_| open(&registry, account, None)).collect();
    assert_eq!(registry.count(), 5);
    for stream in &mut streams {
        read_connect(stream);
    }
    assert_all_live(&registry, &mut streams);
}

#[test]
fn disabled_cap_admits_without_closing() {
    let registry = Arc::new(
        SseRegistry::new()
            .with_keep_alive(None)
            .with_max_per_scope(None),
    );
    let account = uuid::Uuid::new_v4();
    let mut streams: Vec<SseBody> = (0..AUDIT_LOG_SSE_MAX_PER_SCOPE * 2)
        .map(|_| open(&registry, account, Some("session")))
        .collect();
    assert_eq!(registry.count(), AUDIT_LOG_SSE_MAX_PER_SCOPE * 2);
    for stream in &mut streams {
        read_connect(stream);
    }
    assert_all_live(&registry, &mut streams);
}

/// Concurrent subscribes for one session never overshoot the cap: check,
/// evict, and insert share one write-lock window.
#[test]
fn concurrent_subscribes_never_exceed_the_cap() {
    const MAX: usize = 4;
    const THREADS: usize = 32;
    let registry = capped(MAX);
    let account = uuid::Uuid::new_v4();
    let barrier = Arc::new(Barrier::new(THREADS));
    #[allow(
        clippy::needless_collect,
        reason = "every thread must spawn before any join, or the barrier never releases"
    )]
    let handles: Vec<_> = (0..THREADS)
        .map(|_| {
            let registry = Arc::clone(&registry);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                let stream = open(&registry, account, Some("session"));
                let seen = registry.count();
                assert!(seen <= MAX, "saw {seen} streams, cap is {MAX}");
                stream
            })
        })
        .collect();
    let mut streams: Vec<SseBody> = handles
        .into_iter()
        .map(|h| h.join().expect("subscriber thread"))
        .collect();

    assert_eq!(registry.count(), MAX);
    registry.broadcast("data: live\n\n");
    let mut live = 0;
    for stream in &mut streams {
        read_connect(stream);
        match stream.next().now_or_never() {
            Some(Some(_)) => live += 1,
            Some(None) => {}
            None => panic!("a stream is neither live nor ended"),
        }
    }
    assert_eq!(
        live, MAX,
        "exactly the cap's worth of streams got the frame"
    );
}

/// An evicted stream drains what was queued before it ends, and dropping it
/// afterward — its guard removing an id the eviction already removed — never
/// touches the stream that took its slot.
#[test]
fn evicted_stream_drains_then_its_guard_drop_is_a_no_op() {
    let registry = capped(1);
    let account = uuid::Uuid::new_v4();
    let mut evicted = open(&registry, account, Some("session"));
    assert_eq!(registry.broadcast("data: queued\n\n"), 1);
    let mut newest = open(&registry, account, Some("session"));
    assert_eq!(registry.count(), 1);

    read_connect(&mut evicted);
    assert_eq!(
        evicted.next().now_or_never().flatten().map(Result::unwrap),
        Some("data: queued\n\n".to_owned()),
        "a frame queued before the eviction still arrives"
    );
    assert_ended(&mut evicted);
    drop(evicted);

    assert_eq!(registry.count(), 1, "the guard drop removed nothing");
    read_connect(&mut newest);
    assert_all_live(&registry, std::slice::from_mut(&mut newest));
}

/// The WS registry's per-account default is documented as the ceiling this
/// cap implies — the session cap times the per-session stream cap.
#[test]
fn ws_account_default_matches_the_ceiling_the_sse_cap_implies() {
    let sessions = usize::try_from(fuz_auth::DEFAULT_MAX_SESSIONS).unwrap();
    assert_eq!(
        fuz_realtime::DEFAULT_MAX_CONNECTIONS_PER_ACCOUNT,
        sessions * AUDIT_LOG_SSE_MAX_PER_SCOPE
    );
}

// -- two-phase registration ---------------------------------------------------

/// The role every pending stream below is gated by.
const GATING_ROLE: &str = "admin";

/// Register a pending stream for `account` under `session_hash`.
fn open_pending(
    registry: &Arc<SseRegistry>,
    account: uuid::Uuid,
    session_hash: Option<&str>,
) -> PendingSseStream {
    registry.subscribe_pending(SseSubscription {
        identity: ConnectionIdentity {
            account_id: Some(account),
            session_hash: session_hash.map(str::to_owned),
            api_token_id: None,
            required_roles: vec![GATING_ROLE],
        },
        credential_deadline: None,
    })
}

/// Admit `pending`, boxing the body.
fn admit(registry: &SseRegistry, pending: PendingSseStream) -> Result<SseBody, NotAdmitted> {
    let stream = registry.admit(pending)?;
    Ok(Box::pin(stream))
}

/// A pending stream is not an open stream: it is not counted and no frame is
/// fanned to it — not even queued for later. Admitted, it opens with the
/// connect comment and receives the fan-out from then on.
#[test]
fn a_pending_stream_receives_nothing_until_admitted() {
    let registry = Arc::new(SseRegistry::new().with_keep_alive(None));
    let account = uuid::Uuid::new_v4();
    let pending = open_pending(&registry, account, Some("session"));
    assert_eq!(registry.count(), 0, "pending: not an open stream");
    assert_eq!(registry.pending_count(), 1);
    assert_eq!(
        registry.broadcast("data: before\n\n"),
        0,
        "pending: the fan-out skips it"
    );

    let mut stream = admit(&registry, pending).expect("nothing closed it");
    assert_eq!(registry.count(), 1);
    assert_eq!(registry.pending_count(), 0);
    read_connect(&mut stream);
    assert!(
        stream.next().now_or_never().is_none(),
        "the frame fanned before admission was never queued"
    );
    assert_eq!(registry.broadcast("data: after\n\n"), 1);
    assert_eq!(
        stream.next().now_or_never().flatten().map(Result::unwrap),
        Some("data: after\n\n".to_owned()),
    );
}

/// Every close reaches a pending stream, and admission then refuses it —
/// one case per identity key the registry closes by.
#[test]
fn every_close_reaches_a_pending_stream() {
    type Close = fn(&SseRegistry, uuid::Uuid) -> usize;
    let closes: [(&str, Close); 4] = [
        ("session", |r, _| {
            r.close_connections(&ConnectionCloseTarget::Session("session".to_owned()))
        }),
        ("account", |r, account| {
            r.close_connections(&ConnectionCloseTarget::Account(account))
        }),
        ("role", |r, account| {
            r.close_connections(&ConnectionCloseTarget::Role {
                account_id: account,
                role: GATING_ROLE.to_owned(),
            })
        }),
        ("token", |r, _| {
            r.close_connections(&ConnectionCloseTarget::Token("tok_1".to_owned()))
        }),
    ];
    for (what, close) in closes {
        let registry = Arc::new(SseRegistry::new().with_keep_alive(None));
        let account = uuid::Uuid::new_v4();
        let pending = registry.subscribe_pending(SseSubscription {
            identity: ConnectionIdentity {
                account_id: Some(account),
                session_hash: Some("session".to_owned()),
                api_token_id: Some("tok_1".to_owned()),
                required_roles: vec![GATING_ROLE],
            },
            credential_deadline: None,
        });
        assert_eq!(close(&registry, account), 1, "{what}: closes the pending");
        assert_eq!(registry.pending_count(), 0, "{what}: removed");
        assert!(
            matches!(admit(&registry, pending), Err(NotAdmitted::Revoked)),
            "{what}: admission refuses"
        );
        assert_eq!(registry.count(), 0, "{what}: nothing opened");
    }
}

/// The race this exists for: a session at its cap, a stream registered
/// pending on it, and the session revoked before admission. The pending
/// stream is refused — and its refusal evicts nothing.
#[test]
fn a_stream_closed_while_pending_is_refused_and_evicts_nothing() {
    let registry = capped(1);
    let account = uuid::Uuid::new_v4();
    let mut live = open(&registry, account, Some("session_a"));
    read_connect(&mut live);

    let pending = open_pending(&registry, account, Some("session_a"));
    // a role close matches the pending stream alone — `live` is ungated
    assert_eq!(
        registry.close_connections(&ConnectionCloseTarget::Role {
            account_id: account,
            role: GATING_ROLE.to_owned()
        }),
        1
    );
    assert!(matches!(
        admit(&registry, pending),
        Err(NotAdmitted::Revoked)
    ));
    assert_eq!(registry.count(), 1);
    assert_all_live(&registry, std::slice::from_mut(&mut live));
}

/// Registering pending evicts nothing; the session's oldest stream ends at
/// admission, and only then.
#[test]
fn the_cap_evicts_at_admission_not_at_registration() {
    let registry = capped(1);
    let account = uuid::Uuid::new_v4();
    let mut live = open(&registry, account, Some("session"));
    read_connect(&mut live);

    let pending = open_pending(&registry, account, Some("session"));
    assert_eq!(registry.count(), 1);
    assert_all_live(&registry, std::slice::from_mut(&mut live));

    let mut admitted = admit(&registry, pending).unwrap();
    assert_ended(&mut live);
    read_connect(&mut admitted);
    assert_all_live(&registry, std::slice::from_mut(&mut admitted));
}

/// Pending streams never weigh on the cap, and are never its victims.
#[test]
fn pending_streams_do_not_count_toward_the_cap() {
    let registry = capped(2);
    let account = uuid::Uuid::new_v4();
    let pendings: Vec<_> = (0..5)
        .map(|_| open_pending(&registry, account, Some("session")))
        .collect();
    let mut first = open(&registry, account, Some("session"));
    let mut second = open(&registry, account, Some("session"));
    read_connect(&mut first);
    read_connect(&mut second);

    assert_eq!(registry.count(), 2, "two admitted fit under a cap of 2");
    assert_eq!(
        registry.pending_count(),
        5,
        "and no pending one was evicted"
    );
    let mut live = vec![first, second];
    assert_all_live(&registry, &mut live);
    drop(pendings);
    assert_eq!(registry.pending_count(), 0, "dropping a pending removes it");
}

/// Ids are per-registry counters, so a pending stream handed to the wrong
/// registry names a stranger's entry there. It must not admit it.
#[test]
fn admit_refuses_a_pending_stream_from_another_registry() {
    let ours = Arc::new(SseRegistry::new().with_keep_alive(None));
    let theirs = Arc::new(SseRegistry::new().with_keep_alive(None));
    let account = uuid::Uuid::new_v4();
    let foreign = open_pending(&theirs, account, None);
    let local = open_pending(&ours, account, None);

    assert!(matches!(admit(&ours, foreign), Err(NotAdmitted::Revoked)));
    assert_eq!(ours.count(), 0, "the stranger's entry stays pending");
    assert_eq!(ours.pending_count(), 1);
    assert!(admit(&ours, local).is_ok());
}

// -- outbound bound ------------------------------------------------------------

/// A complete SSE frame of exactly `bytes` bytes.
fn frame_of(bytes: usize) -> String {
    let frame = format!("data: {}\n\n", "x".repeat(bytes - "data: \n\n".len()));
    assert_eq!(frame.len(), bytes);
    frame
}

/// A stream that is never polled is ended at its budget — frames charged
/// exactly [`SSE_OUTBOUND_QUEUE_BYTES`] between them (each its bytes plus the
/// per-frame overhead) are queued, and the next frame ends it — while the
/// stream beside it, which is read, receives every frame and stays open. The
/// ended stream yields its connect comment and nothing queued.
#[test]
fn an_unpolled_stream_is_ended_at_its_budget_and_a_polled_one_is_unaffected() {
    const FRAMES: usize = 16;
    let registry = Arc::new(SseRegistry::new().with_keep_alive(None));
    let account = uuid::Uuid::new_v4();
    let mut unpolled = open(&registry, account, None);
    let mut polled = open(&registry, account, None);
    read_connect(&mut polled);

    assert_eq!(
        SSE_OUTBOUND_QUEUE_BYTES,
        1 << 20,
        "the default cap on one request body"
    );
    let frame = frame_of(SSE_OUTBOUND_QUEUE_BYTES / FRAMES - OUTBOUND_FRAME_OVERHEAD_BYTES);
    for _ in 0..FRAMES {
        assert_eq!(registry.broadcast(&frame), 2, "within the budget");
        assert_eq!(
            polled.next().now_or_never().flatten().map(Result::unwrap),
            Some(frame.clone())
        );
    }
    assert_eq!(registry.count(), 2, "exactly at the budget, still open");

    // the shortest frame there is: its overhead alone is past the budget
    assert_eq!(
        registry.broadcast("data: 1\n\n"),
        1,
        "the frame past the budget reaches only the polled stream"
    );
    assert_eq!(
        registry.count(),
        1,
        "the unpolled stream's registration ended"
    );
    assert_eq!(
        polled.next().now_or_never().flatten().map(Result::unwrap),
        Some("data: 1\n\n".to_owned())
    );

    read_connect(&mut unpolled);
    assert_ended(&mut unpolled);
    assert_all_live(&registry, std::slice::from_mut(&mut polled));
}

/// A single frame larger than the whole budget is delivered to a stream with
/// nothing queued, and ends one that has a frame waiting.
#[test]
fn an_oversized_frame_reaches_only_a_stream_with_an_empty_queue() {
    let registry = Arc::new(SseRegistry::new().with_keep_alive(None));
    let account = uuid::Uuid::new_v4();
    let mut empty = open(&registry, account, None);
    read_connect(&mut empty);
    let mut waiting = open(&registry, account, None);

    assert_eq!(registry.broadcast("data: small\n\n"), 2);
    assert_eq!(
        empty.next().now_or_never().flatten().map(Result::unwrap),
        Some("data: small\n\n".to_owned())
    );

    let oversized = frame_of(SSE_OUTBOUND_QUEUE_BYTES + 1);
    assert_eq!(registry.broadcast(&oversized), 1);
    assert_eq!(registry.count(), 1);
    assert_eq!(
        empty.next().now_or_never().flatten().map(Result::unwrap),
        Some(oversized)
    );
    read_connect(&mut waiting);
    assert_ended(&mut waiting);
}

/// A pending stream is never queued to, so no volume of fan-out can overflow
/// it before it is admitted.
#[test]
fn a_pending_stream_is_not_charged_for_the_fan_out() {
    let registry = Arc::new(SseRegistry::new().with_keep_alive(None));
    let pending = open_pending(&registry, uuid::Uuid::new_v4(), None);
    let frame = frame_of(SSE_OUTBOUND_QUEUE_BYTES);
    for _ in 0..4 {
        assert_eq!(registry.broadcast(&frame), 0);
    }
    assert_eq!(pending.closed(), None);
    let mut stream = admit(&registry, pending).expect("still admissible");
    read_connect(&mut stream);
    assert_all_live(&registry, std::slice::from_mut(&mut stream));
}

/// The stream's next item, within two default intervals — so a stream that
/// writes nothing fails the case rather than parking the paused clock.
#[allow(
    clippy::expect_used,
    reason = "a test helper: a missing item fails the test"
)]
async fn next_within(stream: &mut SseBody) -> String {
    tokio::time::timeout(2 * SSE_KEEP_ALIVE_INTERVAL, stream.next())
        .await
        .expect("an item within two intervals")
        .expect("the stream is open")
        .expect("infallible")
}

/// An idle admitted stream writes the keep-alive comment every interval from
/// its open — the TS twin's bytes, `SSE_KEEP_ALIVE_INTERVAL` by default — and
/// a data frame in between does not move the clock.
#[tokio::test(start_paused = true)]
async fn an_idle_stream_writes_the_keep_alive_on_its_interval() {
    assert_eq!(SSE_KEEP_ALIVE_COMMENT, ": keepalive\n\n");
    assert_eq!(SSE_KEEP_ALIVE_INTERVAL, std::time::Duration::from_secs(15));

    let registry = Arc::new(SseRegistry::new());
    let mut stream = open(&registry, uuid::Uuid::new_v4(), Some("session"));
    assert_eq!(stream.next().await.unwrap().unwrap(), SSE_CONNECTED_COMMENT);
    let started = tokio::time::Instant::now();

    assert_eq!(next_within(&mut stream).await, SSE_KEEP_ALIVE_COMMENT);
    assert_eq!(
        started.elapsed(),
        SSE_KEEP_ALIVE_INTERVAL,
        "one interval after the open"
    );

    tokio::time::advance(std::time::Duration::from_secs(5)).await;
    assert_eq!(registry.broadcast("data: row\n\n"), 1);
    assert_eq!(next_within(&mut stream).await, "data: row\n\n");
    assert_eq!(next_within(&mut stream).await, SSE_KEEP_ALIVE_COMMENT);
    assert_eq!(
        started.elapsed(),
        2 * SSE_KEEP_ALIVE_INTERVAL,
        "the data frame between did not move the clock"
    );
}

/// The interval is the registry's: a shorter one ticks sooner, and `None`
/// writes none.
#[tokio::test(start_paused = true)]
async fn the_keep_alive_interval_is_the_registrys() {
    let short =
        Arc::new(SseRegistry::new().with_keep_alive(Some(std::time::Duration::from_secs(2))));
    let mut stream = open(&short, uuid::Uuid::new_v4(), None);
    let _connect = stream.next().await;
    let started = tokio::time::Instant::now();
    assert_eq!(next_within(&mut stream).await, SSE_KEEP_ALIVE_COMMENT);
    assert_eq!(started.elapsed(), std::time::Duration::from_secs(2));

    let off = Arc::new(SseRegistry::new().with_keep_alive(None));
    let mut stream = open(&off, uuid::Uuid::new_v4(), None);
    let _connect = stream.next().await;
    assert!(
        tokio::time::timeout(10 * SSE_KEEP_ALIVE_INTERVAL, stream.next())
            .await
            .is_err(),
        "keep-alives off: an idle stream writes nothing"
    );
}

/// A zero interval is a wiring bug, refused at assembly.
#[test]
#[should_panic(expected = "zero interval")]
fn a_zero_keep_alive_interval_is_refused() {
    let _ = SseRegistry::new().with_keep_alive(Some(std::time::Duration::ZERO));
}

/// So is one past the max — the twin's timer ceiling, and far short of the
/// tick's `Instant` overflowing. The max itself is taken.
#[test]
#[should_panic(expected = "past SSE_KEEP_ALIVE_INTERVAL_MAX")]
fn a_keep_alive_interval_past_the_max_is_refused() {
    let _ = SseRegistry::new().with_keep_alive(Some(
        SSE_KEEP_ALIVE_INTERVAL_MAX + std::time::Duration::from_nanos(1),
    ));
}

/// The bounds [`sse_keep_alive_is_valid`] draws, which a boot checks before it
/// builds the registry: off, the smallest positive, and the max are valid.
#[test]
fn the_keep_alive_bounds() {
    use std::time::Duration;
    assert!(sse_keep_alive_is_valid(None));
    assert!(sse_keep_alive_is_valid(Some(Duration::from_nanos(1))));
    assert!(sse_keep_alive_is_valid(Some(SSE_KEEP_ALIVE_INTERVAL)));
    assert!(sse_keep_alive_is_valid(Some(SSE_KEEP_ALIVE_INTERVAL_MAX)));
    assert_eq!(
        SSE_KEEP_ALIVE_INTERVAL_MAX,
        Duration::from_millis(2_147_483_647)
    );
    assert!(!sse_keep_alive_is_valid(Some(Duration::ZERO)));
    assert!(!sse_keep_alive_is_valid(Some(
        SSE_KEEP_ALIVE_INTERVAL_MAX + Duration::from_nanos(1)
    )));
    let _ = SseRegistry::new().with_keep_alive(Some(SSE_KEEP_ALIVE_INTERVAL_MAX));
}
