//! [`RealtimeCloser`] — one [`ConnectionCloser`] over both live-connection
//! transports, WebSocket ([`ConnectionRegistry`]) and SSE ([`SseRegistry`]).
//!
//! ## Why a fan-out
//!
//! A revocation handler closes the revoked credential's connections itself,
//! through the `ConnectionCloser` it is handed, and the audit listeners repeat
//! the close once the audit row is written. On the REST `/logout` and
//! `/password` paths that audit write is pool-routed and fail-open, so the
//! handler's close is the only one guaranteed to run. Handed the WS registry
//! alone, that close skips SSE — and an audit stream is authorized once at
//! open and never rechecks, so a failed audit INSERT would leave the revoked
//! account's streams running for their lifetime. Binding this type makes
//! every direct close reach both transports.
//!
//! The one revocation listener (`fuz_auth::register_revocation_guard`)
//! is handed this closer too, so its close on a materialized row — the only
//! close a role revocation gets — reaches the streams as well as the sockets.
//! The audit fan-out listener
//! ([`register_audit_sse_listener`](crate::register_audit_sse_listener)) only
//! broadcasts.
//!
//! It is also the closer a consumer hands its scheduled auth cleanup
//! (`fuz_auth::AuthCleanupOptions::connection_closer`): the session sweep writes
//! no audit row, so its direct close is the sweep's only one — a repeat of the
//! close each connection already makes at its credential's deadline — and it
//! has to reach both transports for the same reason.
//!
//! And it is what the server hands `fuz_http::serve_with_shutdown`, as the
//! [`ShutdownCloser`] its `ConnectionCloser` extends: on shutdown it closes every
//! WebSocket and every stream, and waits for both registries to finish.

use std::sync::Arc;

use fuz_auth::{ConnectionCloseTarget, ConnectionCloser};
use fuz_http::{ShutdownCloser, WaitClosedFuture};

use crate::connection_registry::ConnectionRegistry;
use crate::sse::SseRegistry;

/// Fans each [`ConnectionCloser`] close out to a WS [`ConnectionRegistry`] and an
/// [`SseRegistry`], returning the sum of what each closed.
///
/// Build it with [`Self::connection_closer`] over the **same** registry instances
/// the WS upgrade handler and the audit stream route populate — a closer over
/// a fresh registry closes nothing.
///
/// **Object-safe** — consumed as `Arc<dyn ConnectionCloser>`, which is the only
/// form the constructor hands out.
#[derive(Debug)]
pub struct RealtimeCloser {
    ws: Arc<ConnectionRegistry>,
    sse: Arc<SseRegistry>,
}

impl RealtimeCloser {
    /// Build an `Arc<dyn ConnectionCloser>` closing on both `ws` and `sse`.
    #[must_use]
    pub fn connection_closer(
        ws: &Arc<ConnectionRegistry>,
        sse: &Arc<SseRegistry>,
    ) -> Arc<dyn ConnectionCloser> {
        Arc::new(Self {
            ws: Arc::clone(ws),
            sse: Arc::clone(sse),
        })
    }
}

impl ShutdownCloser for RealtimeCloser {
    fn close_all_connections(&self) -> usize {
        self.ws.close_all_connections() + self.sse.close_all_connections()
    }

    /// Both registries' waits, joined — resolves once both have.
    fn wait_closed(&self) -> WaitClosedFuture<'_> {
        Box::pin(async move {
            futures::future::join(self.ws.wait_closed(), self.sse.wait_closed()).await;
        })
    }
}

impl ConnectionCloser for RealtimeCloser {
    fn close_connections(&self, target: &ConnectionCloseTarget) -> usize {
        self.ws.close_connections(target) + self.sse.close_connections(target)
    }
}
