//! Pins the close an upgrade refused at admission gets —
//! [`refuse_upgrade`] over an in-memory sink standing in for the socket:
//! the frame, and the linger that lets a client with an unread inbound
//! tail read it.

use std::time::Duration;

use axum::extract::ws::Message;
use futures::channel::mpsc;
use futures_util::StreamExt;

use crate::connection::NotAdmitted;
use crate::ws_close_codes::{
    WS_CLOSE_GOING_AWAY, WS_CLOSE_GOING_AWAY_REASON, WS_CLOSE_INTERNAL_ERROR,
    WS_CLOSE_INTERNAL_ERROR_REASON, WS_CLOSE_PERMISSION_REVOKED,
    WS_CLOSE_PERMISSION_REVOKED_REASON, WS_CLOSE_SESSION_REVOKED,
};
use crate::ws_endpoint::{LoopExit, REFUSED_UPGRADE_CLOSE_LINGER, UpgradeRefusal, refuse_upgrade};

/// Every frame [`refuse_upgrade`] writes for `refusal`, and how long it
/// took to return (on tokio's clock — the callers pause it, so the linger
/// costs no wall time).
async fn refuse(refusal: UpgradeRefusal) -> (Vec<Message>, Duration) {
    let (tx, rx) = mpsc::unbounded();
    let started = tokio::time::Instant::now();
    refuse_upgrade(tx, refusal).await;
    (rx.collect().await, started.elapsed())
}

/// A revoked upgrade gets exactly the frame a socket revoked mid-life
/// gets — a client cannot tell the two apart, and treats both as
/// permanently revoked.
#[tokio::test(start_paused = true)]
async fn a_revoked_upgrade_closes_with_the_loops_4001_frame() {
    let (frames, _) = refuse(UpgradeRefusal::Revoked).await;
    match frames.as_slice() {
        [Message::Close(Some(frame))] => {
            assert_eq!(frame.code, WS_CLOSE_SESSION_REVOKED);
            assert_eq!(Some(frame), LoopExit::Revoked.close_frame().as_ref());
        }
        other => panic!("expected exactly a 4001 close frame, got {other:?}"),
    }
    assert_eq!(
        UpgradeRefusal::Revoked.close_code(),
        WS_CLOSE_SESSION_REVOKED
    );
}

/// An upgrade refused for a lost gating role gets exactly the 4006 frame a
/// socket that lost the role mid-life gets — not a 4001, which would put
/// the client in its permanent `revoked` state.
#[tokio::test(start_paused = true)]
async fn a_permission_revoked_upgrade_closes_with_the_loops_4006_frame() {
    let (frames, _) = refuse(UpgradeRefusal::PermissionRevoked).await;
    match frames.as_slice() {
        [Message::Close(Some(frame))] => {
            assert_eq!(frame.code, WS_CLOSE_PERMISSION_REVOKED);
            assert_eq!(frame.reason.as_str(), WS_CLOSE_PERMISSION_REVOKED_REASON);
            assert_eq!(
                Some(frame),
                LoopExit::PermissionRevoked.close_frame().as_ref()
            );
        }
        other => panic!("expected exactly a 4006 close frame, got {other:?}"),
    }
    assert_eq!(
        UpgradeRefusal::PermissionRevoked.close_code(),
        WS_CLOSE_PERMISSION_REVOKED
    );
}

/// A re-check that could not run is not a revocation: 1011, so the client
/// retries rather than giving the credential up.
#[tokio::test(start_paused = true)]
async fn an_unavailable_recheck_closes_with_1011() {
    let (frames, _) = refuse(UpgradeRefusal::Unavailable).await;
    match frames.as_slice() {
        [Message::Close(Some(frame))] => {
            assert_eq!(frame.code, WS_CLOSE_INTERNAL_ERROR);
            assert_eq!(frame.reason.as_str(), WS_CLOSE_INTERNAL_ERROR_REASON);
        }
        other => panic!("expected exactly a 1011 close frame, got {other:?}"),
    }
    assert_eq!(
        UpgradeRefusal::Unavailable.close_code(),
        WS_CLOSE_INTERNAL_ERROR
    );
}

/// An upgrade refused because the server is shutting down gets exactly
/// the 1001 frame an admitted socket gets from the same shutdown — not a
/// 4001, which would put the client in its permanent `revoked` state.
#[tokio::test(start_paused = true)]
async fn a_shutting_down_upgrade_closes_with_the_loops_1001_frame() {
    let (frames, _) = refuse(UpgradeRefusal::ShuttingDown).await;
    match frames.as_slice() {
        [Message::Close(Some(frame))] => {
            assert_eq!(frame.code, WS_CLOSE_GOING_AWAY);
            assert_eq!(frame.reason.as_str(), WS_CLOSE_GOING_AWAY_REASON);
            assert_eq!(Some(frame), LoopExit::ShuttingDown.close_frame().as_ref());
        }
        other => panic!("expected exactly a 1001 close frame, got {other:?}"),
    }
    assert_eq!(
        UpgradeRefusal::ShuttingDown.close_code(),
        WS_CLOSE_GOING_AWAY
    );
}

/// A refused admission is closed for the reason it was refused.
#[test]
fn a_refused_admission_maps_to_its_close() {
    assert_eq!(
        UpgradeRefusal::from(NotAdmitted::Revoked),
        UpgradeRefusal::Revoked
    );
    assert_eq!(
        UpgradeRefusal::from(NotAdmitted::ShuttingDown),
        UpgradeRefusal::ShuttingDown
    );
    assert_eq!(
        UpgradeRefusal::from(NotAdmitted::PermissionRevoked),
        UpgradeRefusal::PermissionRevoked
    );
}

/// The socket is held after the close frame is written, for every
/// refusal: a refused upgrade is never read, so a client that sent a
/// frame on open has an unread tail on it, and dropping the socket at
/// once would reset the connection before the client read the frame.
#[tokio::test(start_paused = true)]
async fn a_refused_upgrade_lingers_after_its_close_frame() {
    for refusal in [
        UpgradeRefusal::Revoked,
        UpgradeRefusal::PermissionRevoked,
        UpgradeRefusal::Unavailable,
        UpgradeRefusal::ShuttingDown,
    ] {
        let (frames, elapsed) = refuse(refusal).await;
        assert_eq!(frames.len(), 1, "{refusal:?}: the close frame");
        assert!(
            elapsed >= REFUSED_UPGRADE_CLOSE_LINGER,
            "{refusal:?}: the socket lingers after the close, returned after {elapsed:?}"
        );
    }
}

/// A close that could not be written has nothing for the client to read,
/// so there is nothing to linger for.
#[tokio::test(start_paused = true)]
async fn a_failed_close_write_does_not_linger() {
    let (tx, rx) = mpsc::unbounded::<Message>();
    drop(rx);
    let started = tokio::time::Instant::now();
    refuse_upgrade(tx, UpgradeRefusal::Revoked).await;
    assert!(
        started.elapsed() < REFUSED_UPGRADE_CLOSE_LINGER,
        "no linger when the peer is already gone"
    );
}
