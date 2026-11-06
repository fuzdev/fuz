//! Per-frame dispatch table.
//!
//! Match on [`Header::action`], gate on the action's
//! [`AuthLevel`](fuz_wire::AuthLevel), decode the payload, call the handler, queue the
//! response. All in one place so the auth gate is impossible to skip.
//!
//! Responses are queued on the connection's outgoing channel (`out_tx`)
//! rather than written directly: the per-connection writer task owns the
//! socket, so streaming workloads and request/response share one wire
//! cleanly. Subscribe-style handlers register with a workload collector
//! and return without a `FINAL` response — the collector streams frames on
//! the same `request_id`.

use std::sync::atomic::Ordering;
use std::time::Instant;

use fuz_sidecar::Sidecar;
use fuz_wire::ToolInfo;
use fuz_wire::{
    Action, DaemonShutdownRequest, DaemonShutdownResponse, DaemonStatusRequest,
    DaemonStatusResponse, Goodbye, Header, HelloOutcome, HelloRequest, HelloResponse, MAX_FRAME,
    ObserverSubscribeRequest, ObserverUnsubscribeRequest, ObserverUnsubscribeResponse,
    PROTOCOL_VERSION, Ping, Pong, ShutdownStatus, SidecarCallListRequest, SidecarCallListResponse,
    SidecarCallOutcome, SidecarCallRunRequest, SidecarCallRunResponse, SidecarRestartRequest,
    SidecarRestartResponse, SidecarStartRequest, SidecarStartResponse, SidecarStatusRequest,
    SidecarStatusResponse, SidecarStopRequest, SidecarStopResponse, WatchCoverage, WatchRefusal,
    WatchSnapshot, WatcherSnapshotFrame, WatcherSubscribeRefused, WatcherSubscribeRequest,
    WatcherUnsubscribeRequest, WatcherUnsubscribeResponse, WorkloadId, WorkloadListRequest,
    WorkloadListResponse, WorkloadStatusRequest, WorkloadStatusResponse, WorkloadStopRequest,
    WorkloadStopResponse, decode_payload, encode_payload, ids,
};
use tracing::{debug, warn};

use crate::AppState;
use crate::auth::{AuthContext, check_auth};
use crate::error::ServerError;
use crate::out::{OutFrame, OutTx};
use crate::workload::frame_split::FRAME_BODY_BUDGET;

/// Queue a single-frame `FINAL` response on the connection's writer
/// channel. A closed channel means the peer is gone — surfaced as
/// [`ServerError::ConnectionClosed`] so the read loop ends cleanly.
async fn respond<A: Action + Sync>(
    out_tx: &OutTx,
    request_id: u32,
    payload: &A,
) -> Result<(), ServerError> {
    let frame = OutFrame::response(request_id, payload)?;
    out_tx
        .send(frame)
        .await
        .map_err(|_| ServerError::ConnectionClosed)
}

/// Dispatch one inbound frame to the matching handler.
///
/// Returns `Ok(false)` when the handler signals "done — close the
/// connection" (today: `Goodbye` + `DaemonShutdownRequest`). Otherwise
/// the per-connection read loop keeps cycling on the same socket.
pub async fn dispatch<S>(
    header: Header,
    payload: &[u8],
    ctx: AuthContext,
    state: &AppState<S>,
    out_tx: &OutTx,
    conn_id: u64,
) -> Result<bool, ServerError>
where
    S: Sidecar + 'static,
{
    match header.action {
        ids::HELLO_REQUEST => {
            authz::<HelloRequest>(ctx)?;
            let req: HelloRequest = decode_payload(payload)?;
            let outcome = if req.protocol_version == PROTOCOL_VERSION {
                HelloOutcome::Ok
            } else {
                HelloOutcome::VersionMismatch {
                    ours: PROTOCOL_VERSION,
                    theirs: req.protocol_version,
                }
            };
            let resp = HelloResponse {
                server_protocol_version: PROTOCOL_VERSION,
                server_version: state.version.to_string(),
                outcome,
            };
            respond(out_tx, header.request_id, &resp).await?;
            Ok(true)
        }
        ids::PING => {
            authz::<Ping>(ctx)?;
            let _req: Ping = decode_payload(payload)?;
            respond(out_tx, header.request_id, &Pong).await?;
            Ok(true)
        }
        ids::GOODBYE => {
            authz::<Goodbye>(ctx)?;
            debug!("peer sent Goodbye");
            Ok(false)
        }
        ids::DAEMON_STATUS_REQUEST => {
            authz::<DaemonStatusRequest>(ctx)?;
            let _req: DaemonStatusRequest = decode_payload(payload)?;
            let resp = DaemonStatusResponse {
                version: state.version.to_string(),
                sidecars: state.sidecar.sidecar_status(),
                tools: state
                    .sidecar
                    .tools()
                    .iter()
                    .map(|t| t.name.to_string())
                    .collect(),
            };
            respond(out_tx, header.request_id, &resp).await?;
            Ok(true)
        }
        ids::DAEMON_SHUTDOWN_REQUEST => {
            authz::<DaemonShutdownRequest>(ctx)?;
            let _req: DaemonShutdownRequest = decode_payload(payload)?;
            // Flip draining BEFORE cancelling — closes the race window
            // for any in-flight frame after this one to still get a
            // Draining response.
            state.draining.store(true, Ordering::Relaxed);
            state.shutdown.cancel();
            let resp = DaemonShutdownResponse {
                status: ShutdownStatus::ShuttingDown,
            };
            respond(out_tx, header.request_id, &resp).await?;
            Ok(false)
        }
        ids::SIDECAR_CALL_LIST_REQUEST => {
            authz::<SidecarCallListRequest>(ctx)?;
            let _req: SidecarCallListRequest = decode_payload(payload)?;
            let runtime = state.sidecar.runtime().to_string();
            let tools: Vec<ToolInfo> = state
                .sidecar
                .tools()
                .iter()
                .map(|t| ToolInfo {
                    name: t.name.to_string(),
                    description: t.description.to_string(),
                    runtime: runtime.clone(),
                })
                .collect();
            let resp = SidecarCallListResponse { tools };
            respond(out_tx, header.request_id, &resp).await?;
            Ok(true)
        }
        ids::SIDECAR_CALL_RUN_REQUEST => {
            authz::<SidecarCallRunRequest>(ctx)?;
            let req: SidecarCallRunRequest = decode_payload(payload)?;
            let outcome = run_sidecar_call(req, state).await;
            let resp = SidecarCallRunResponse { outcome };
            respond(out_tx, header.request_id, &resp).await?;
            Ok(true)
        }
        ids::SIDECAR_START_REQUEST => {
            authz::<SidecarStartRequest>(ctx)?;
            let req: SidecarStartRequest = decode_payload(payload)?;
            let result = state.sidecar.start_sidecars(req.target.id()).await;
            let resp = SidecarStartResponse { result };
            respond(out_tx, header.request_id, &resp).await?;
            Ok(true)
        }
        ids::SIDECAR_STOP_REQUEST => {
            authz::<SidecarStopRequest>(ctx)?;
            let req: SidecarStopRequest = decode_payload(payload)?;
            let result = state.sidecar.stop_sidecars(req.target.id()).await;
            let resp = SidecarStopResponse { result };
            respond(out_tx, header.request_id, &resp).await?;
            Ok(true)
        }
        ids::SIDECAR_RESTART_REQUEST => {
            authz::<SidecarRestartRequest>(ctx)?;
            let req: SidecarRestartRequest = decode_payload(payload)?;
            let result = state.sidecar.restart_sidecars(req.target.id()).await;
            let resp = SidecarRestartResponse { result };
            respond(out_tx, header.request_id, &resp).await?;
            Ok(true)
        }
        ids::SIDECAR_STATUS_REQUEST => {
            authz::<SidecarStatusRequest>(ctx)?;
            let req: SidecarStatusRequest = decode_payload(payload)?;
            let sidecars = match state.sidecar.get_sidecar_status(req.target.id()) {
                Ok(s) => s,
                Err(err) => {
                    warn!(error = %err, "sidecar.status failed");
                    Vec::new()
                }
            };
            let resp = SidecarStatusResponse { sidecars };
            respond(out_tx, header.request_id, &resp).await?;
            Ok(true)
        }
        ids::WORKLOAD_LIST_REQUEST => {
            authz::<WorkloadListRequest>(ctx)?;
            let _req: WorkloadListRequest = decode_payload(payload)?;
            let resp = WorkloadListResponse {
                workloads: state.workloads.list(),
            };
            respond(out_tx, header.request_id, &resp).await?;
            Ok(true)
        }
        ids::WORKLOAD_STATUS_REQUEST => {
            authz::<WorkloadStatusRequest>(ctx)?;
            let req: WorkloadStatusRequest = decode_payload(payload)?;
            let resp = WorkloadStatusResponse {
                workload: state.workloads.status(req.id),
            };
            respond(out_tx, header.request_id, &resp).await?;
            Ok(true)
        }
        ids::WORKLOAD_STOP_REQUEST => {
            authz::<WorkloadStopRequest>(ctx)?;
            let req: WorkloadStopRequest = decode_payload(payload)?;
            let resp = WorkloadStopResponse {
                outcome: state.workloads.stop(req.id),
            };
            respond(out_tx, header.request_id, &resp).await?;
            Ok(true)
        }
        ids::OBSERVER_SUBSCRIBE_REQUEST => {
            authz::<ObserverSubscribeRequest>(ctx)?;
            let req: ObserverSubscribeRequest = decode_payload(payload)?;
            // The collector streams a snapshot then deltas on this
            // request_id — no FINAL response frame here. The subscription
            // ends when the connection closes or the client unsubscribes.
            state
                .workloads
                .observer_subscribe(req.domain, conn_id, header.request_id, out_tx.clone())
                .await;
            Ok(true)
        }
        ids::OBSERVER_UNSUBSCRIBE_REQUEST => {
            authz::<ObserverUnsubscribeRequest>(ctx)?;
            let req: ObserverUnsubscribeRequest = decode_payload(payload)?;
            let outcome = state.workloads.unsubscribe(req.workload_id, conn_id).await;
            let resp = ObserverUnsubscribeResponse { outcome };
            respond(out_tx, header.request_id, &resp).await?;
            Ok(true)
        }
        ids::WATCHER_SUBSCRIBE_REQUEST => {
            authz::<WatcherSubscribeRequest>(ctx)?;
            let req: WatcherSubscribeRequest = decode_payload(payload)?;
            let (req, refusal) = watch_roots_refusal(req)?;
            if let Some(reason) = refusal {
                warn!(
                    ?reason,
                    "refused a watch subscribe: its roots cannot fit a frame"
                );
                respond(
                    out_tx,
                    header.request_id,
                    &WatcherSubscribeRefused { reason },
                )
                .await?;
                return Ok(true);
            }
            // The collector streams a snapshot then event frames on this
            // request_id — no FINAL response frame here. The subscription ends
            // when the connection closes or the client unsubscribes.
            let roots = req
                .roots
                .into_iter()
                .map(std::path::PathBuf::from)
                .collect();
            state
                .workloads
                .watch_subscribe(
                    roots,
                    req.recursive,
                    conn_id,
                    header.request_id,
                    out_tx.clone(),
                )
                .await;
            Ok(true)
        }
        ids::WATCHER_UNSUBSCRIBE_REQUEST => {
            authz::<WatcherUnsubscribeRequest>(ctx)?;
            let req: WatcherUnsubscribeRequest = decode_payload(payload)?;
            let outcome = state.workloads.unsubscribe(req.workload_id, conn_id).await;
            let resp = WatcherUnsubscribeResponse { outcome };
            respond(out_tx, header.request_id, &resp).await?;
            Ok(true)
        }
        unknown => Err(ServerError::UnknownAction(unknown)),
    }
}

async fn run_sidecar_call<S>(req: SidecarCallRunRequest, state: &AppState<S>) -> SidecarCallOutcome
where
    S: Sidecar + 'static,
{
    if state.draining.load(Ordering::Relaxed) {
        return SidecarCallOutcome::Draining;
    }
    let content_len = req.content.len() as u64;
    if content_len > u64::from(MAX_FRAME) {
        return SidecarCallOutcome::ContentTooLarge {
            len: content_len,
            max: u64::from(MAX_FRAME),
        };
    }
    // Validate the tool exists before invoking — gives a typed
    // `ToolNotFound` outcome instead of a generic sidecar error.
    let known = state.sidecar.tools().iter().any(|t| t.name == req.tool);
    if !known {
        return SidecarCallOutcome::ToolNotFound { tool: req.tool };
    }

    // Parse the opaque options string into a serde_json::Value for the
    // sidecar protocol (sidecars themselves still speak JSON over their
    // stdio). An invalid options string surfaces as a SidecarError.
    let options = match req.options {
        None => None,
        Some(ref raw) => match serde_json::from_str::<serde_json::Value>(raw) {
            Ok(v) => Some(v),
            Err(err) => {
                return SidecarCallOutcome::SidecarError {
                    message: format!("invalid options JSON: {err}"),
                };
            }
        },
    };

    let start = Instant::now();
    let result = state.sidecar.call(&req.tool, &req.content, options).await;
    match result {
        Ok(value) => {
            state.logger.record_tool_success(&req.tool, start.elapsed());
            // Re-serialize the JSON value back to a string for transport.
            // The client side parses again if it needs structured output;
            // most tools return a bare string, in which case the round-trip
            // through JSON preserves the contents (just with surrounding
            // quotes that the client strips).
            match serde_json::to_string(&value) {
                Ok(result) => SidecarCallOutcome::Ok { result },
                Err(err) => SidecarCallOutcome::SidecarError {
                    message: format!("serialize sidecar output failed: {err}"),
                },
            }
        }
        Err(err) => SidecarCallOutcome::SidecarError {
            message: err.to_string(),
        },
    }
}

/// Whether a watch over `req`'s roots must be refused: its snapshot frame echoes
/// the roots, so roots whose snapshot cannot fit one frame would leave the
/// subscriber waiting on a snapshot that never comes.
///
/// Measured at the widest the frame gets — the largest workload id and a
/// `Partial` coverage with the largest count. The registry only sorts and
/// dedups the roots, which never lengthens them. Hands the request back.
fn watch_roots_refusal(
    req: WatcherSubscribeRequest,
) -> Result<(WatcherSubscribeRequest, Option<WatchRefusal>), ServerError> {
    let widest = WatcherSnapshotFrame {
        workload_id: WorkloadId::MAX,
        snapshot: WatchSnapshot {
            roots: req.roots,
            recursive: req.recursive,
            coverage: WatchCoverage::Partial {
                unwatched: u32::MAX,
            },
        },
    };
    let encoded = encode_payload(&widest)?.len();
    let refusal = (encoded > FRAME_BODY_BUDGET).then_some(WatchRefusal::RootsTooLarge {
        encoded: encoded as u64,
        limit: FRAME_BODY_BUDGET as u64,
    });
    let req = WatcherSubscribeRequest {
        roots: widest.snapshot.roots,
        recursive: widest.snapshot.recursive,
    };
    Ok((req, refusal))
}

const fn authz<A: Action>(ctx: AuthContext) -> Result<(), ServerError> {
    if check_auth(A::AUTH, ctx) {
        Ok(())
    } else {
        Err(ServerError::AuthDenied {
            action: A::ID,
            have: ctx.level,
            required: A::AUTH,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(root_len: usize) -> WatcherSubscribeRequest {
        WatcherSubscribeRequest {
            roots: vec![format!("/{}", "r".repeat(root_len - 1))],
            recursive: true,
        }
    }

    fn widest_len(root_len: usize) -> usize {
        let req = request(root_len);
        encode_payload(&WatcherSnapshotFrame {
            workload_id: WorkloadId::MAX,
            snapshot: WatchSnapshot {
                roots: req.roots,
                recursive: req.recursive,
                coverage: WatchCoverage::Partial {
                    unwatched: u32::MAX,
                },
            },
        })
        .unwrap()
        .len()
    }

    #[test]
    fn a_watch_whose_widest_snapshot_is_exactly_the_budget_is_served() {
        // The overhead around the root, at a length with the budget's varint width.
        let probe = FRAME_BODY_BUDGET - 64;
        let at = FRAME_BODY_BUDGET - (widest_len(probe) - probe);
        assert_eq!(widest_len(at), FRAME_BODY_BUDGET);
        let (req, refusal) = watch_roots_refusal(request(at)).unwrap();
        assert!(refusal.is_none(), "a snapshot at the limit fits");
        assert_eq!(req.roots[0].len(), at, "the request is handed back whole");
        let (_, refusal) = watch_roots_refusal(request(at + 1)).unwrap();
        assert_eq!(
            refusal,
            Some(WatchRefusal::RootsTooLarge {
                encoded: FRAME_BODY_BUDGET as u64 + 1,
                limit: FRAME_BODY_BUDGET as u64,
            })
        );
    }
}
