//! End-to-end streaming over a real UDS: spin up the server with an empty
//! sidecar pool, subscribe to the `process` observer domain, and assert
//! the snapshot-then-delta stream flows on one `request_id`. Uses the live
//! `/proc` source, so it asserts shape (frames, ordering) not content.

use std::time::Duration;

use fuz_wire::{
    MAX_FRAME, ObserverDelta, ObserverDeltaFrame, ObserverDomain, ObserverSnapshot,
    ObserverSnapshotFrame, ObserverSubscribeRequest, WorkloadKind, WorkloadListRequest,
    WorkloadListResponse, decode_payload, ids, read_frame, write_frame,
};
use tokio::time::timeout;

mod common;
use common::{connect_hello, spawn_server};

#[tokio::test]
async fn observe_process_streams_snapshot_then_delta() {
    let (_dir, socket, shutdown, server) = spawn_server();
    let mut stream = connect_hello(&socket).await;

    // Subscribe to the process domain on request_id 7.
    write_frame(
        &mut stream,
        7,
        &ObserverSubscribeRequest {
            domain: ObserverDomain::Process,
        },
        MAX_FRAME,
    )
    .await
    .expect("write subscribe");

    // First stream frame: a snapshot on the same request_id, not FINAL.
    let (header, body) = timeout(Duration::from_secs(5), read_frame(&mut stream, MAX_FRAME))
        .await
        .expect("snapshot in time")
        .expect("read snapshot");
    assert_eq!(header.request_id, 7);
    assert_eq!(header.action, ids::OBSERVER_SNAPSHOT_FRAME);
    assert!(!header.flags.is_final(), "subscription frames aren't FINAL");
    let snap: ObserverSnapshotFrame = decode_payload(&body).expect("decode snapshot");
    assert!(snap.workload_id >= 1);
    let ObserverSnapshot::Process(process_snapshot) = snap.snapshot else {
        panic!("expected a process snapshot");
    };
    assert!(
        !process_snapshot.processes.is_empty(),
        "live /proc has at least this test process"
    );
    assert!(process_snapshot.system.mem_total_bytes > 0);

    // Next: a delta frame on the same request_id (system updates every
    // tick, so a delta arrives within a couple of sample intervals).
    let (header, body) = timeout(Duration::from_secs(5), read_frame(&mut stream, MAX_FRAME))
        .await
        .expect("delta in time")
        .expect("read delta");
    assert_eq!(header.request_id, 7);
    assert_eq!(header.action, ids::OBSERVER_DELTA_FRAME);
    let delta: ObserverDeltaFrame = decode_payload(&body).expect("decode delta");
    let ObserverDelta::Process(process_delta) = delta.delta else {
        panic!("expected a process delta");
    };
    assert!(process_delta.system.mem_total_bytes > 0);

    shutdown.cancel();
    let _ = server.await;
}

#[tokio::test]
async fn observe_network_streams_snapshot_then_delta() {
    let (_dir, socket, shutdown, server) = spawn_server();
    let mut stream = connect_hello(&socket).await;

    write_frame(
        &mut stream,
        7,
        &ObserverSubscribeRequest {
            domain: ObserverDomain::Network,
        },
        MAX_FRAME,
    )
    .await
    .expect("write subscribe");

    // First frame: a network snapshot. Live /proc/net always has loopback.
    let (header, body) = timeout(Duration::from_secs(5), read_frame(&mut stream, MAX_FRAME))
        .await
        .expect("snapshot in time")
        .expect("read snapshot");
    assert_eq!(header.action, ids::OBSERVER_SNAPSHOT_FRAME);
    let snap: ObserverSnapshotFrame = decode_payload(&body).expect("decode snapshot");
    let ObserverSnapshot::Network(network_snapshot) = snap.snapshot else {
        panic!("expected a network snapshot");
    };
    assert!(
        network_snapshot.interfaces.iter().any(|i| i.name == "lo"),
        "loopback interface is always present"
    );

    // Then a delta on the same request_id (interface counters refresh each tick).
    let (header, body) = timeout(Duration::from_secs(5), read_frame(&mut stream, MAX_FRAME))
        .await
        .expect("delta in time")
        .expect("read delta");
    assert_eq!(header.action, ids::OBSERVER_DELTA_FRAME);
    let delta: ObserverDeltaFrame = decode_payload(&body).expect("decode delta");
    assert!(
        matches!(delta.delta, ObserverDelta::Network(_)),
        "network delta"
    );

    shutdown.cancel();
    let _ = server.await;
}

#[tokio::test]
async fn observe_services_streams_snapshot() {
    let (_dir, socket, shutdown, server) = spawn_server();
    let mut stream = connect_hello(&socket).await;

    write_frame(
        &mut stream,
        7,
        &ObserverSubscribeRequest {
            domain: ObserverDomain::Services,
        },
        MAX_FRAME,
    )
    .await
    .expect("write subscribe");

    // A services snapshot arrives (units may be empty when the test env has no
    // user systemd bus — we assert shape, not content).
    let (header, body) = timeout(Duration::from_secs(5), read_frame(&mut stream, MAX_FRAME))
        .await
        .expect("snapshot in time")
        .expect("read snapshot");
    assert_eq!(header.action, ids::OBSERVER_SNAPSHOT_FRAME);
    let snap: ObserverSnapshotFrame = decode_payload(&body).expect("decode snapshot");
    assert!(
        matches!(snap.snapshot, ObserverSnapshot::Services(_)),
        "expected a services snapshot"
    );

    shutdown.cancel();
    let _ = server.await;
}

#[tokio::test]
async fn workload_list_reports_shared_observer() {
    let (_dir, socket, shutdown, server) = spawn_server();

    // Connection A subscribes and holds the stream open.
    let mut conn_a = connect_hello(&socket).await;
    write_frame(
        &mut conn_a,
        7,
        &ObserverSubscribeRequest {
            domain: ObserverDomain::Process,
        },
        MAX_FRAME,
    )
    .await
    .expect("subscribe");
    // Drain the snapshot so the subscription is established.
    let (header, _body) = timeout(Duration::from_secs(5), read_frame(&mut conn_a, MAX_FRAME))
        .await
        .expect("snapshot in time")
        .expect("read snapshot");
    assert_eq!(header.action, ids::OBSERVER_SNAPSHOT_FRAME);

    // Connection B lists workloads (no stream of its own, so the list
    // response isn't interleaved with deltas).
    let mut conn_b = connect_hello(&socket).await;
    write_frame(&mut conn_b, 2, &WorkloadListRequest, MAX_FRAME)
        .await
        .expect("list request");
    let (header, body) = read_frame(&mut conn_b, MAX_FRAME)
        .await
        .expect("list response");
    assert_eq!(header.action, ids::WORKLOAD_LIST_RESPONSE);
    assert!(header.flags.is_final());
    let list: WorkloadListResponse = decode_payload(&body).expect("decode list");
    assert_eq!(list.workloads.len(), 1);
    assert_eq!(list.workloads[0].kind, WorkloadKind::Observer);
    assert_eq!(list.workloads[0].description, "observer:process");
    assert_eq!(list.workloads[0].subscribers, 1);

    shutdown.cancel();
    let _ = server.await;
}
