//! End-to-end watcher streaming over a real UDS: spin up the server, subscribe
//! to a filesystem watch of a tempdir, and assert the snapshot-then-event
//! stream flows on one `request_id` when a file changes. Uses the real
//! `notify` backend, so it asserts shape + that a write produces an event.

// Test harness: panicking via expect on setup failure is the intended
// behavior; the clippy `allow-expect-in-tests` config only reaches `#[test]`
// fns, not the plain `subscribe_watch` helper below.
#![allow(clippy::expect_used)]

use std::time::Duration;

use fuz_wire::{
    MAX_FRAME, WatcherEventFrame, WatcherSnapshotFrame, WatcherSubscribeRequest, WorkloadKind,
    WorkloadListRequest, WorkloadListResponse, decode_payload, ids, read_frame, write_frame,
};
use tokio::net::UnixStream;
use tokio::time::timeout;

mod common;
use common::{connect_hello, spawn_server};

async fn subscribe_watch(stream: &mut UnixStream, request_id: u32, root: &std::path::Path) {
    write_frame(
        stream,
        request_id,
        &WatcherSubscribeRequest {
            roots: vec![root.to_string_lossy().into_owned()],
            recursive: true,
        },
        MAX_FRAME,
    )
    .await
    .expect("write watch subscribe");
}

#[tokio::test]
async fn watch_streams_snapshot_then_event_on_file_change() {
    let (_dir, socket, shutdown, server) = spawn_server();
    let watch_dir = tempfile::tempdir().expect("watch dir");
    let mut stream = connect_hello(&socket).await;

    subscribe_watch(&mut stream, 7, watch_dir.path()).await;

    // First stream frame: the watch snapshot (config) on the same request_id.
    let (header, body) = timeout(Duration::from_secs(5), read_frame(&mut stream, MAX_FRAME))
        .await
        .expect("snapshot in time")
        .expect("read snapshot");
    assert_eq!(header.request_id, 7);
    assert_eq!(header.action, ids::WATCHER_SNAPSHOT_FRAME);
    assert!(!header.flags.is_final(), "subscription frames aren't FINAL");
    let snap: WatcherSnapshotFrame = decode_payload(&body).expect("decode snapshot");
    assert!(snap.workload_id >= 1);
    assert!(snap.snapshot.recursive);
    assert_eq!(snap.snapshot.roots.len(), 1);

    // Let the inotify watch establish, then change a file in the watched dir.
    tokio::time::sleep(Duration::from_millis(400)).await;
    std::fs::write(watch_dir.path().join("hello.txt"), b"hi").expect("write file");

    // An event frame mentioning hello.txt arrives within a few flush windows.
    let mut saw = false;
    for _ in 0..20 {
        let Ok(Ok((header, body))) =
            timeout(Duration::from_secs(5), read_frame(&mut stream, MAX_FRAME)).await
        else {
            break;
        };
        if header.action == ids::WATCHER_EVENT_FRAME {
            let frame: WatcherEventFrame = decode_payload(&body).expect("decode events");
            if frame.events.iter().any(|e| e.path.ends_with("hello.txt")) {
                saw = true;
                break;
            }
        }
    }
    assert!(
        saw,
        "a filesystem event for hello.txt streamed on the subscription"
    );

    shutdown.cancel();
    let _ = server.await;
}

#[tokio::test]
async fn watchers_with_the_same_roots_share_one_workload() {
    let (_dir, socket, shutdown, server) = spawn_server();
    let watch_dir = tempfile::tempdir().expect("watch dir");

    // Two connections subscribe the same root → one shared watcher workload.
    let mut conn_a = connect_hello(&socket).await;
    subscribe_watch(&mut conn_a, 7, watch_dir.path()).await;
    let (header, _) = timeout(Duration::from_secs(5), read_frame(&mut conn_a, MAX_FRAME))
        .await
        .expect("snapshot a")
        .expect("read");
    assert_eq!(header.action, ids::WATCHER_SNAPSHOT_FRAME);

    let mut conn_b = connect_hello(&socket).await;
    subscribe_watch(&mut conn_b, 7, watch_dir.path()).await;
    let (header, _) = timeout(Duration::from_secs(5), read_frame(&mut conn_b, MAX_FRAME))
        .await
        .expect("snapshot b")
        .expect("read");
    assert_eq!(header.action, ids::WATCHER_SNAPSHOT_FRAME);

    // A third connection lists workloads (no stream of its own).
    let mut conn_c = connect_hello(&socket).await;
    write_frame(&mut conn_c, 2, &WorkloadListRequest, MAX_FRAME)
        .await
        .expect("list request");
    let (header, body) = read_frame(&mut conn_c, MAX_FRAME)
        .await
        .expect("list response");
    assert_eq!(header.action, ids::WORKLOAD_LIST_RESPONSE);
    let list: WorkloadListResponse = decode_payload(&body).expect("decode list");
    assert_eq!(list.workloads.len(), 1, "same roots share one watcher");
    assert_eq!(list.workloads[0].kind, WorkloadKind::Watcher);
    assert_eq!(
        list.workloads[0].subscribers, 2,
        "both subscribers share it"
    );

    shutdown.cancel();
    let _ = server.await;
}

#[tokio::test]
async fn a_watch_whose_roots_cannot_fit_the_snapshot_frame_is_refused() {
    // One root about as long as a frame body: the request itself fits, the
    // snapshot echoing it (plus its id and coverage) would not. The daemon
    // answers with a FINAL refusal instead of a stream that never starts, and
    // the connection stays usable.
    let (_dir, socket, shutdown, server) = spawn_server();
    let mut stream = connect_hello(&socket).await;
    let budget = (MAX_FRAME - fuz_wire::HEADER_BYTES) as usize;
    write_frame(
        &mut stream,
        7,
        &WatcherSubscribeRequest {
            roots: vec![format!("/{}", "r".repeat(budget - 16))],
            recursive: true,
        },
        MAX_FRAME,
    )
    .await
    .expect("write subscribe");
    let (header, body) = timeout(Duration::from_secs(5), read_frame(&mut stream, MAX_FRAME))
        .await
        .expect("an answer in time")
        .expect("read the answer");
    assert_eq!(header.request_id, 7);
    assert_eq!(header.action, ids::WATCHER_SUBSCRIBE_REFUSED);
    assert!(header.flags.is_final(), "the refusal ends the request");
    let refused: fuz_wire::WatcherSubscribeRefused = decode_payload(&body).expect("decode");
    let fuz_wire::WatchRefusal::RootsTooLarge { encoded, limit } = refused.reason;
    assert!(encoded > limit, "{encoded} > {limit}");

    // No workload was registered for it.
    write_frame(&mut stream, 8, &WorkloadListRequest, MAX_FRAME)
        .await
        .expect("write list");
    let (header, body) = timeout(Duration::from_secs(5), read_frame(&mut stream, MAX_FRAME))
        .await
        .expect("list in time")
        .expect("read list");
    assert_eq!(header.request_id, 8);
    let list: WorkloadListResponse = decode_payload(&body).expect("decode list");
    assert!(
        list.workloads
            .iter()
            .all(|w| w.kind != WorkloadKind::Watcher),
        "{:?}",
        list.workloads
    );

    shutdown.cancel();
    let _ = server.await;
}
