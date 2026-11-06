//! The failure log of `fuz_sys::periodic::spawn_periodic`: a failed pass is
//! logged with its task name and the error's full source chain.
//!
//! Its own test binary, so the subscriber it installs is this process's
//! alone: no other test's events reach it, and no other test's thread can
//! cache the log callsite's interest before the subscriber exists.

#![cfg(feature = "periodic")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::error::Error;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use fuz_sys::periodic::spawn_periodic;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// What [`CauseCapture`] saw of one event: its `task` field and the `error`
/// field's messages, the error first and then each `source()`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct CapturedFailure {
    task: String,
    error_chain: Vec<String>,
}

impl tracing::field::Visit for CapturedFailure {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "task" {
            value.clone_into(&mut self.task);
        }
    }

    fn record_error(&mut self, field: &tracing::field::Field, value: &(dyn Error + 'static)) {
        if field.name() == "error" {
            let mut next = Some(value);
            while let Some(error) = next {
                self.error_chain.push(error.to_string());
                next = error.source();
            }
        }
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        // an `error` recorded any other way (`%e`, `?e`) lands here, as one
        // string with no chain to walk
        if field.name() == "error" {
            self.error_chain.push(format!("{value:?}"));
        }
    }
}

/// A subscriber that keeps the [`CapturedFailure`] of each event: the least
/// a test needs to read a log line's fields, with no subscriber crate.
struct CauseCapture(Arc<Mutex<Vec<CapturedFailure>>>);

impl tracing::Subscriber for CauseCapture {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        let mut captured = CapturedFailure::default();
        event.record(&mut captured);
        self.0.lock().unwrap().push(captured);
    }

    fn enter(&self, _: &tracing::span::Id) {}

    fn exit(&self, _: &tracing::span::Id) {}
}

/// An error shaped like the ones a pass returns: its `Display` names what
/// failed and leaves why to `source()`.
#[derive(Debug, thiserror::Error)]
#[error("failed to acquire pooled connection")]
struct PoolOutage(#[source] std::io::Error);

/// The failure log carries the cause, not only the outermost message: logged
/// with `%e`, an unreachable database reads as "failed to acquire pooled
/// connection" and nothing else.
#[tokio::test(start_paused = true)]
async fn a_failed_pass_is_logged_with_its_name_and_source_chain() {
    let failures = Arc::new(Mutex::new(Vec::new()));
    tracing::subscriber::set_global_default(CauseCapture(Arc::clone(&failures)))
        .expect("the only subscriber in this test binary");

    let (tx, mut rx) = mpsc::unbounded_channel();
    let shutdown = CancellationToken::new();
    let task = spawn_periodic(
        "the logged sweep",
        Duration::from_secs(10),
        shutdown.clone(),
        move || {
            tx.send(()).expect("the test holds the receiver");
            std::future::ready(Err::<(), _>(PoolOutage(std::io::Error::other(
                "connection refused",
            ))))
        },
    );

    // the second pass starting means the first one's failure was logged
    rx.recv().await.expect("the startup pass ran");
    rx.recv().await.expect("the next pass ran");
    shutdown.cancel();
    task.await.expect("the task ends cleanly");

    let logged = failures.lock().unwrap().first().cloned();
    assert_eq!(
        logged,
        Some(CapturedFailure {
            task: "the logged sweep".to_owned(),
            error_chain: vec![
                "failed to acquire pooled connection".to_owned(),
                "connection refused".to_owned(),
            ],
        })
    );
}
