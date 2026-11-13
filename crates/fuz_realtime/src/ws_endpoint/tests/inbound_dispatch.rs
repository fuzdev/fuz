//! Pins the loop's two refusals ahead of dispatch: a request reusing an id
//! still in flight (`invalid_request`, reason
//! [`ERROR_DUPLICATE_REQUEST_ID`]) and a request past the in-flight cap
//! ([`MAX_INBOUND_DISPATCHES_PER_CONNECTION`], `queue_overflow`), and their
//! order. Drives [`run_ws_loop`] over in-memory channels with a dispatch
//! that holds a request until its token is cancelled or the test releases
//! it — so "in flight" is a state the test controls, not a race.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::ws::Message;
use futures::channel::mpsc;
use futures_util::StreamExt;
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;

use crate::connection_registry::ConnectionRegistry;
use crate::peer::PendingPeerRequests;
use crate::ws_endpoint::{
    ERROR_DUPLICATE_REQUEST_ID, MAX_INBOUND_DISPATCHES_PER_CONNECTION,
    WS_INBOUND_DISPATCH_OVERFLOW_MESSAGE, WsDispatchFn, run_ws_loop,
};

/// `invalid_request` and `queue_overflow` on the wire.
const INVALID_REQUEST: i64 = -32600;
const QUEUE_OVERFLOW: i64 = -32009;

struct Harness {
    client_tx: mpsc::UnboundedSender<Result<Message, axum::Error>>,
    client_rx: mpsc::UnboundedReceiver<Message>,
    /// Cancelled to answer every `hold` request still waiting.
    release: CancellationToken,
    loop_task: tokio::task::JoinHandle<()>,
}

impl Harness {
    /// Spawn the loop with a dispatch answering `hold` (waits for its
    /// token to be cancelled, answering `"cancelled"`, or for `release`,
    /// answering `"released"`) and `quick` (answers `"quick"` at once).
    fn start() -> Self {
        let registry = Arc::new(ConnectionRegistry::new());
        let (notify_tx, notify_rx) = crate::connection_channel(1 << 20);
        let conn = registry.add_connection(
            notify_tx,
            crate::ConnectionIdentity::default(),
            CancellationToken::new(),
        );
        let release = CancellationToken::new();
        let dispatch_release = release.clone();
        let dispatch: WsDispatchFn = Arc::new(move |input| {
            let release = dispatch_release.clone();
            Box::pin(async move {
                let result = match input.method {
                    "hold" => {
                        tokio::select! {
                            () = input.signal.cancelled() => "cancelled",
                            () = release.cancelled() => "released",
                        }
                    }
                    _ => "quick",
                };
                Some(
                    json!({"jsonrpc": "2.0", "id": input.request_id, "result": result}).to_string(),
                )
            })
        });
        let (client_tx, server_rx) = mpsc::unbounded();
        let (server_tx, client_rx) = mpsc::unbounded();
        let loop_task = tokio::spawn(run_ws_loop(
            server_tx,
            server_rx,
            registry,
            conn,
            notify_rx,
            Arc::new(PendingPeerRequests::new(8)),
            dispatch,
            crate::ws_endpoint::WsLoopOptions::default(),
        ));
        Self {
            client_tx,
            client_rx,
            release,
            loop_task,
        }
    }

    fn send(&self, frame: &Value) {
        self.client_tx
            .unbounded_send(Ok(Message::Text(frame.to_string().into())))
            .expect("loop is reading");
    }

    fn request(&self, method: &str, id: &Value) {
        self.send(&json!({"jsonrpc": "2.0", "id": id, "method": method}));
    }

    fn cancel(&self, id: &Value) {
        self.send(&json!({"jsonrpc": "2.0", "method": "cancel", "params": {"request_id": id}}));
    }

    async fn next_json(&mut self) -> Value {
        let frame = tokio::time::timeout(Duration::from_secs(5), self.client_rx.next())
            .await
            .expect("frame within timeout");
        match frame {
            Some(Message::Text(text)) => serde_json::from_str(&text).expect("JSON frame"),
            other => panic!("expected a text frame, got {other:?}"),
        }
    }

    async fn finish(self) {
        self.client_tx.close_channel();
        self.loop_task.await.expect("loop exits cleanly");
    }
}

fn assert_duplicate_refusal(frame: &Value, id: &Value) {
    assert_eq!(&frame["id"], id, "frame: {frame}");
    assert_eq!(frame["error"]["code"], INVALID_REQUEST, "frame: {frame}");
    assert_eq!(
        frame["error"]["message"], "invalid request",
        "frame: {frame}"
    );
    assert_eq!(
        frame["error"]["data"],
        json!({"reason": ERROR_DUPLICATE_REQUEST_ID}),
        "frame: {frame}"
    );
}

fn assert_result(frame: &Value, id: &Value, result: &str) {
    assert_eq!(&frame["id"], id, "frame: {frame}");
    assert_eq!(frame["result"], result, "frame: {frame}");
}

/// A request reusing a live id is refused with that id and never
/// dispatched; the first request keeps its cancellation entry (a `cancel`
/// for the id still reaches it), and once it is answered the id is free.
#[tokio::test]
async fn a_request_reusing_a_live_id_is_refused_and_the_first_keeps_it() {
    let mut harness = Harness::start();
    let id = json!(7);

    harness.request("hold", &id);
    harness.request("quick", &id);
    assert_duplicate_refusal(&harness.next_json().await, &id);

    // The string "7" is a different id, so it dispatches.
    harness.request("quick", &json!("7"));
    assert_result(&harness.next_json().await, &json!("7"), "quick");

    harness.cancel(&id);
    assert_result(&harness.next_json().await, &id, "cancelled");

    harness.request("quick", &id);
    assert_result(&harness.next_json().await, &id, "quick");

    harness.finish().await;
}

/// Past the cap a new request is shed with `queue_overflow` and its id;
/// the socket stays open, the running requests still answer, and a slot
/// freed by a completion takes the next request. A duplicate of a live
/// id at the cap is refused as a duplicate — that check comes first.
#[tokio::test]
async fn past_the_cap_a_request_is_shed_and_the_socket_keeps_serving() {
    let mut harness = Harness::start();
    for n in 0..MAX_INBOUND_DISPATCHES_PER_CONNECTION {
        harness.request("hold", &json!(n));
    }

    harness.request("hold", &json!(0));
    assert_duplicate_refusal(&harness.next_json().await, &json!(0));

    let over = json!("over");
    harness.request("quick", &over);
    let frame = harness.next_json().await;
    assert_eq!(frame["id"], over, "frame: {frame}");
    assert_eq!(frame["error"]["code"], QUEUE_OVERFLOW, "frame: {frame}");
    assert_eq!(
        frame["error"]["message"], WS_INBOUND_DISPATCH_OVERFLOW_MESSAGE,
        "frame: {frame}"
    );
    assert_eq!(
        WS_INBOUND_DISPATCH_OVERFLOW_MESSAGE, "too many concurrent requests on this connection",
        "the twin's literal"
    );

    // one completion frees one slot
    harness.cancel(&json!(0));
    assert_result(&harness.next_json().await, &json!(0), "cancelled");
    harness.request("quick", &over);
    assert_result(&harness.next_json().await, &over, "quick");

    harness.release.cancel();
    let mut released = 0;
    for _ in 1..MAX_INBOUND_DISPATCHES_PER_CONNECTION {
        let frame = harness.next_json().await;
        assert_eq!(frame["result"], "released", "frame: {frame}");
        released += 1;
    }
    assert_eq!(released, MAX_INBOUND_DISPATCHES_PER_CONNECTION - 1);

    harness.finish().await;
}

/// The cap is exact: the last slot dispatches, the one after it does not.
#[tokio::test]
async fn the_cap_admits_exactly_its_value() {
    let mut harness = Harness::start();
    for n in 0..MAX_INBOUND_DISPATCHES_PER_CONNECTION - 1 {
        harness.request("hold", &json!(n));
    }
    // the last slot: dispatched and answered
    harness.request("quick", &json!("last"));
    assert_result(&harness.next_json().await, &json!("last"), "quick");

    // fill it with a held request, and the next is shed
    harness.request("hold", &json!("held"));
    harness.request("quick", &json!("shed"));
    let frame = harness.next_json().await;
    assert_eq!(frame["id"], "shed", "frame: {frame}");
    assert_eq!(frame["error"]["code"], QUEUE_OVERFLOW, "frame: {frame}");

    harness.finish().await;
}
