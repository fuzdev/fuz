//! Shared helpers for `fuz_realtime`'s integration tests.
//!
//! Lives under `tests/common/` so Cargo doesn't compile it as its own test
//! binary — each test file that needs it declares `mod common;`.

use std::convert::Infallible;
use std::sync::Arc;

use futures::Stream;
use fuz_realtime::{SseRegistry, SseSubscription};

/// Register a stream and admit it at once — the two phases a route runs once
/// its gates and its re-read pass, with nothing in between.
#[expect(
    clippy::expect_used,
    reason = "a test helper: a refused admission fails the test"
)]
pub fn subscribe_admitted(
    registry: &Arc<SseRegistry>,
    subscription: SseSubscription,
) -> impl Stream<Item = Result<String, Infallible>> + Send + 'static {
    registry
        .admit(registry.subscribe_pending(subscription))
        .expect("a live registry admits a fresh registration")
}
