//! `ObserverSource` — the acquisition seam for observer collectors.
//!
//! v1 ships one impl, [`UserScopedSource`], reading what the daemon's uid
//! exposes: `/proc` (the process tree, own socket→pid, world-readable bits,
//! system-wide CPU/mem/load + listening ports) and `systemctl --user` (unit
//! states). fuzd is per-uid (`SO_PEERCRED`), so user scope is the natural
//! ceiling. A later privileged impl (root / `CAP_SYS_PTRACE` / `CAP_NET_ADMIN`,
//! likely a separate helper) fills full-system detail behind the same trait —
//! collectors and the wire don't change.
//!
//! Acquisition is **raw and stateless**: a source returns counters (CPU ticks,
//! byte totals), and the collector derives rates (CPU % / throughput) across
//! successive samples. The per-domain readers live in [`super::proc_source`],
//! [`super::net_source`], and [`super::services_source`].

use thiserror::Error;

use super::net_source::{self, RawNetworkSample};
use super::proc_source::{self, RawProcessSample};
use super::services_source::{self, RawServicesSample};

/// Errors raised while sampling a domain. A single entity disappearing
/// mid-read is **not** an error (it's skipped); these are whole-sample
/// failures (e.g. `/proc/stat` unreadable).
#[derive(Debug, Error)]
pub enum ObserverError {
    /// A required `/proc` aggregate file could not be read.
    #[error("failed to read {path}")]
    Read {
        path: &'static str,
        #[source]
        source: std::io::Error,
    },

    /// A sampling subprocess, or its output, outlived its deadline; a child
    /// still running then was killed and reaped.
    #[error("{command} did not finish within {timeout:?}")]
    CommandTimeout {
        command: &'static str,
        timeout: std::time::Duration,
    },
}

/// One raw sample, tagged by domain — what an [`ObserverSource`] returns and
/// the collector folds into a snapshot / delta / events.
#[derive(Debug, Clone)]
pub enum RawSample {
    Process(RawProcessSample),
    Network(RawNetworkSample),
    Services(RawServicesSample),
}

/// Acquisition seam for observer collectors.
///
/// **Object-safe** — held as `Arc<dyn ObserverSource>` so the privilege tier
/// can be swapped without touching collectors or the wire.
pub trait ObserverSource: Send + Sync + std::fmt::Debug + 'static {
    /// Sample the process domain.
    ///
    /// # Errors
    ///
    /// Returns [`ObserverError`] only on whole-sample failure; vanished
    /// processes are silently skipped.
    fn sample_process(&self) -> Result<RawProcessSample, ObserverError>;

    /// Sample the network domain (connections + interface counters).
    ///
    /// # Errors
    ///
    /// Returns [`ObserverError`] when a required `/proc/net` aggregate is
    /// unreadable; per-protocol tables and `/proc/<pid>/fd` are best-effort.
    fn sample_network(&self) -> Result<RawNetworkSample, ObserverError>;

    /// Sample the services domain (systemd unit states).
    ///
    /// # Errors
    ///
    /// Returns [`ObserverError`] when the unit states can't be read in time (a
    /// hung `systemctl`, killed at its deadline); an absent / failing
    /// `systemctl` is not an error — it degrades to an empty unit set (the
    /// daemon stays useful without systemd).
    fn sample_services(&self) -> Result<RawServicesSample, ObserverError>;
}

/// User-scoped OS reader (the v1 [`ObserverSource`]): `/proc` for the process
/// and network domains, `systemctl --user` for services.
#[derive(Debug, Default)]
pub struct UserScopedSource;

impl UserScopedSource {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl ObserverSource for UserScopedSource {
    fn sample_process(&self) -> Result<RawProcessSample, ObserverError> {
        proc_source::sample_process()
    }

    fn sample_network(&self) -> Result<RawNetworkSample, ObserverError> {
        net_source::sample_network()
    }

    fn sample_services(&self) -> Result<RawServicesSample, ObserverError> {
        services_source::sample_services()
    }
}
