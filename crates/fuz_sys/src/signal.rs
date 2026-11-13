//! Graceful-shutdown signal primitive (transport-free).
//!
//! The SIGINT/SIGTERM → [`CancellationToken`] half shared by every fuz
//! server/daemon. `fuzd` (UDS, no axum) and `fuz_http`'s server lifecycle
//! both build their graceful shutdown on this, so the select lives in one
//! place. `fuz_http` adds the axum drain on top; `fuzd` hands the token
//! straight to its UDS server.

use tokio_util::sync::CancellationToken;

/// Return a [`CancellationToken`] that is cancelled on the first SIGINT
/// (Ctrl-C) or SIGTERM.
///
/// Spawns a detached task that selects on both signals and calls
/// [`CancellationToken::cancel`] when either fires. Clone the returned token
/// to observe the same shutdown from other tasks.
///
/// On non-Unix targets only Ctrl-C is observed (no SIGTERM).
#[must_use]
pub fn shutdown_token() -> CancellationToken {
    let token = CancellationToken::new();
    let signal_token = token.clone();
    tokio::spawn(async move {
        wait_for_shutdown_signal().await;
        tracing::info!("shutdown signal received");
        signal_token.cancel();
    });
    token
}

/// Await the first SIGINT (Ctrl-C) or SIGTERM. On non-Unix targets only
/// Ctrl-C is observed.
///
/// Crate-internal: [`shutdown_token`] is the only wrapper consumers need, so
/// the raw await stays behind it.
async fn wait_for_shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c().await.ok();
    };

    #[cfg(unix)]
    {
        let sigterm = async {
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(mut sig) => {
                    sig.recv().await;
                }
                Err(e) => {
                    tracing::warn!(
                        error = %crate::cli::format_error_chain(&e),
                        "failed to install SIGTERM handler"
                    );
                    std::future::pending::<()>().await;
                }
            }
        };
        tokio::select! {
            () = ctrl_c => {}
            () = sigterm => {}
        }
    }

    #[cfg(not(unix))]
    ctrl_c.await;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `shutdown_token` returns an uncancelled token; cancelling it (as the
    /// signal task would) is observable by a clone.
    #[tokio::test]
    async fn shutdown_token_is_uncancelled_until_signalled() {
        let token = shutdown_token();
        assert!(!token.is_cancelled());
        // Simulate the signal path so the assertion below is meaningful
        // without delivering a real OS signal to the test process.
        token.cancel();
        assert!(token.is_cancelled());
    }
}
