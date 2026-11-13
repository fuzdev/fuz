//! The observer collector task.
//!
//! One task per registered observer workload. It samples its domain on an
//! interval, diffs against the last-sent state to produce entity-level deltas
//! (+ discrete events), and fans frames out to every subscriber. Demand-driven:
//! it idles (no sampling) while it has no subscribers and exits when its
//! [`CancellationToken`] fires (idle-grace retire or daemon shutdown).
//!
//! The loop, subscriber fan-out, and resync-over-drop are **domain-generic**
//! (they operate on encoded [`ObserverSnapshot`] / [`ObserverDelta`] /
//! [`ObserverEvent`] frames), as is the entity diff itself
//! ([`diff_entities`]); the per-domain state, the rate math (CPU % /
//! throughput from successive raw samples), and the event constructors live
//! in the [`ProcessState`] / [`NetworkState`] / [`ServicesState`] variants of
//! [`CollectorState`]. Acquisition is stateless ([`ObserverSource`]).
//!
//! Two bounds hold whatever the source reports. Each string is cut to its
//! bound as a sample is folded in ([`super::bounds`]), and each frame fits the
//! frame limit: a delta or an event batch too large for one frame goes out as
//! several, and a snapshot too large for one as a snapshot of a prefix of its
//! entities followed by `added` deltas carrying the rest
//! ([`super::frame_split`]). A consumer that applies frames in order ends up
//! with the same view either way.

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Arc;
use std::time::Duration;

use fuz_wire::{
    ConnectionEvent, ConnectionInfo, ConnectionKey, InterfaceInfo, NetworkDelta, NetworkSnapshot,
    ObserverDelta, ObserverDeltaFrame, ObserverDomain, ObserverEvent, ObserverEventFrame,
    ObserverSnapshot, ObserverSnapshotFrame, ProcessDelta, ProcessEvent, ProcessInfo, ProcessKey,
    ProcessSnapshot, ServiceEvent, ServiceUnit, ServicesDelta, ServicesSnapshot, SocketState,
    SystemResources, WorkloadId, encode_payload,
};
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;
use tokio::time::MissedTickBehavior;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use super::bounds::{
    MAX_CMDLINE_BYTES, MAX_DESCRIPTION_BYTES, MAX_FIELD_BYTES, cap_opt_text, cap_text,
};
use super::collector::{
    CollectorCommand, EncodedFrame, ResyncOutcome, Subscriber, add_subscriber, drop_closed,
    drop_connection, remove_subscriber, send_resync_snapshot, try_send_frames,
};
use super::frame_split::{FRAME_BODY_BUDGET, SplitBodies, split_encode, split_lists, split_vec};
use super::net_source::RawNetworkSample;
use super::proc_source::RawProcessSample;
use super::services_source::RawServicesSample;
use super::source::{ObserverSource, RawSample};

/// Process-domain sample cadence (~1 Hz keeps `/proc` churn light).
pub const PROCESS_SAMPLE_INTERVAL: Duration = Duration::from_millis(1000);

/// Network-domain sample cadence (~1 Hz; `/proc/net` + a per-tick fd scan).
pub const NETWORK_SAMPLE_INTERVAL: Duration = Duration::from_millis(1000);

/// Services-domain sample cadence — slower: each tick spawns a `systemctl`
/// subprocess, and unit states change far less often than process / network.
pub const SERVICES_SAMPLE_INTERVAL: Duration = Duration::from_millis(3000);

/// The sample interval for a domain.
const fn sample_interval(domain: ObserverDomain) -> Duration {
    match domain {
        ObserverDomain::Process => PROCESS_SAMPLE_INTERVAL,
        ObserverDomain::Network => NETWORK_SAMPLE_INTERVAL,
        ObserverDomain::Services => SERVICES_SAMPLE_INTERVAL,
    }
}

/// Run a collector until its `stop` token fires.
///
/// The stop token is raced against the whole loop, not only polled between
/// commands: a command or tick in progress — the off-executor sample above all,
/// which can sit on a slow `systemctl` — is abandoned on stop, so the collector
/// drops its subscribers' channel senders at once and their connections can
/// close.
pub async fn run_collector(
    domain: ObserverDomain,
    workload_id: WorkloadId,
    source: Arc<dyn ObserverSource>,
    cmd_rx: mpsc::Receiver<CollectorCommand>,
    stop: CancellationToken,
) {
    debug!(workload_id, ?domain, "observer collector started");
    tokio::select! {
        biased;
        () = stop.cancelled() => {}
        () = collect(domain, workload_id, source, cmd_rx) => {}
    }
    debug!(workload_id, ?domain, "observer collector stopped");
}

/// The collector loop proper; returns when the command channel closes.
async fn collect(
    domain: ObserverDomain,
    workload_id: WorkloadId,
    source: Arc<dyn ObserverSource>,
    mut cmd_rx: mpsc::Receiver<CollectorCommand>,
) {
    let mut subs: Vec<Subscriber> = Vec::new();
    let mut state = CollectorState::new(domain);
    let mut interval = tokio::time::interval(sample_interval(domain));
    interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        if subs.is_empty() {
            // Idle: no sampling. Wait for a subscriber.
            match cmd_rx.recv().await {
                Some(c) => handle_cmd(c, &mut subs, &mut state, &source, domain, workload_id).await,
                None => break,
            }
        } else {
            tokio::select! {
                _ = interval.tick() => tick(&mut subs, &mut state, &source, domain, workload_id).await,
                cmd = cmd_rx.recv() => match cmd {
                    Some(c) => handle_cmd(c, &mut subs, &mut state, &source, domain, workload_id).await,
                    None => break,
                },
            }
        }
    }
}

/// Sample the domain off the async executor (the `/proc` reads + the
/// `systemctl` subprocess are blocking). Returns `None` on sample failure — a
/// failed sample is logged and skipped, never fatal to the collector.
async fn sample(source: &Arc<dyn ObserverSource>, domain: ObserverDomain) -> Option<RawSample> {
    let src = Arc::clone(source);
    let result = tokio::task::spawn_blocking(move || match domain {
        ObserverDomain::Process => src.sample_process().map(RawSample::Process),
        ObserverDomain::Network => src.sample_network().map(RawSample::Network),
        ObserverDomain::Services => src.sample_services().map(RawSample::Services),
    })
    .await;
    match result {
        Ok(Ok(sample)) => Some(sample),
        Ok(Err(err)) => {
            warn!(error = %err, ?domain, "observer sample failed");
            None
        }
        Err(err) => {
            warn!(error = %err, ?domain, "observer sample task failed");
            None
        }
    }
}

async fn handle_cmd(
    cmd: CollectorCommand,
    subs: &mut Vec<Subscriber>,
    state: &mut CollectorState,
    source: &Arc<dyn ObserverSource>,
    domain: ObserverDomain,
    workload_id: WorkloadId,
) {
    match cmd {
        CollectorCommand::AddSubscriber {
            conn_id,
            request_id,
            out_tx,
        } => {
            // A late subscriber must be immediately whole: ensure we have
            // sampled at least once, then send the current full snapshot.
            if !state.has_sampled()
                && let Some(raw) = sample(source, domain).await
            {
                state.ingest(raw);
            }
            let frames = snapshot_frames(state.snapshot(), workload_id, FRAME_BODY_BUDGET);
            // Never await room: a backed-up connection joins flagged for resync
            // and gets its snapshot on the next tick instead.
            add_subscriber(subs, conn_id, request_id, out_tx, frames.as_deref());
        }
        CollectorCommand::RemoveSubscriber {
            conn_id,
            request_id,
        } => remove_subscriber(subs, conn_id, request_id),
        CollectorCommand::DropConnection { conn_id } => drop_connection(subs, conn_id),
    }
}

async fn tick(
    subs: &mut Vec<Subscriber>,
    state: &mut CollectorState,
    source: &Arc<dyn ObserverSource>,
    domain: ObserverDomain,
    workload_id: WorkloadId,
) {
    let Some(raw) = sample(source, domain).await else {
        return;
    };
    let output = state.ingest(raw);
    fanout(subs, &output, state, workload_id, FRAME_BODY_BUDGET);
}

/// Fan one tick's delta (+ events) out to every subscriber. A subscriber
/// flagged `needs_resync` gets a fresh snapshot instead; on a full channel
/// we drop the frame and flag resync (never a silent delta drop — that
/// would corrupt the consumer's view).
///
/// The delta and the events go out in as many frames as `budget` needs. An
/// item too large for a frame on its own cannot reach the consumer, so it is
/// logged and every subscriber resyncs instead of reading a delta that lacks
/// it.
fn fanout(
    subs: &mut Vec<Subscriber>,
    output: &TickOutput,
    state: &CollectorState,
    workload_id: WorkloadId,
    budget: usize,
) {
    let delta = match split_encode(
        ObserverDeltaFrame {
            delta: output.delta.clone(),
        },
        budget,
        split_delta_frame,
    ) {
        Ok(delta) => delta,
        Err(err) => {
            warn!(error = %err, "encode delta frame failed");
            return;
        }
    };
    let events = if output.events.is_empty() {
        SplitBodies::default()
    } else {
        split_encode(
            ObserverEventFrame {
                events: output.events.clone(),
            },
            budget,
            split_event_frame,
        )
        .unwrap_or_else(|err| {
            warn!(error = %err, "encode event frame failed");
            SplitBodies::default()
        })
    };
    let dropped = delta.dropped + events.dropped;
    if dropped > 0 {
        warn!(
            workload_id,
            dropped, "observer items too large for a frame were left out; resyncing subscribers"
        );
        for sub in subs.iter_mut() {
            sub.needs_resync = true;
        }
    }
    let incremental: Vec<EncodedFrame> = delta
        .bodies
        .into_iter()
        .map(|body| (fuz_wire::ids::OBSERVER_DELTA_FRAME, body))
        .chain(
            events
                .bodies
                .into_iter()
                .map(|body| (fuz_wire::ids::OBSERVER_EVENT_FRAME, body)),
        )
        .collect();
    // Snapshot frames are encoded once, lazily, only if someone needs resync.
    let snapshot = if subs.iter().any(|s| s.needs_resync) {
        snapshot_frames(state.snapshot(), workload_id, budget)
    } else {
        None
    };

    let mut closed: Vec<usize> = Vec::new();
    for (idx, sub) in subs.iter_mut().enumerate() {
        match send_resync_snapshot(sub, snapshot.as_deref()) {
            ResyncOutcome::NotFlagged => {}
            ResyncOutcome::Handled => continue,
            ResyncOutcome::Closed => {
                closed.push(idx);
                continue;
            }
        }
        match try_send_frames(&sub.out_tx, sub.request_id, &incremental) {
            Ok(()) => {}
            Err(TrySendError::Full(())) => sub.needs_resync = true,
            Err(TrySendError::Closed(())) => closed.push(idx),
        }
    }
    drop_closed(subs, closed);
}

/// Encode `snapshot` as frames that each fit `budget`.
///
/// One snapshot frame when it fits. Otherwise a snapshot frame holding the
/// first `n/2` entities, or the first `n/4`, `n/8`, … — the first of those
/// prefixes that fits — then `added` deltas carrying the rest, their count in
/// the snapshot frame's `continues`: the snapshot resets the consumer's view
/// and the deltas complete it. `None` when it cannot be encoded at all, which
/// is logged; the caller leaves its subscribers flagged for the next pass.
///
/// An entity too large for any frame on its own is left out with a warn, and
/// the snapshot goes out without it: this is the resync path itself, so there
/// is nothing further to resync to.
fn snapshot_frames(
    snapshot: ObserverSnapshot,
    workload_id: WorkloadId,
    budget: usize,
) -> Option<Vec<EncodedFrame>> {
    let encode = |frame: &ObserverSnapshotFrame| {
        encode_payload(frame)
            .map_err(|err| warn!(error = %err, "encode snapshot frame failed"))
            .ok()
    };
    let whole = ObserverSnapshotFrame {
        workload_id,
        continues: 0,
        snapshot,
    };
    let body = encode(&whole)?;
    if body.len() <= budget {
        return Some(vec![(fuz_wire::ids::OBSERVER_SNAPSHOT_FRAME, body)]);
    }
    let snapshot = whole.snapshot;
    let entities = snapshot_len(&snapshot);
    let mut keep = entities / 2;
    let mut head = loop {
        // Sized with the widest `continues`, so the real count still fits.
        let head = ObserverSnapshotFrame {
            workload_id,
            continues: u32::MAX,
            snapshot: snapshot_prefix(&snapshot, keep),
        };
        let body = encode(&head)?;
        if body.len() <= budget {
            break head;
        }
        if keep == 0 {
            warn!(
                workload_id,
                len = body.len(),
                "observer snapshot does not fit a frame even with no entities"
            );
            return None;
        }
        keep /= 2;
    };
    let rest = split_encode(snapshot_rest(snapshot, keep), budget, split_delta_frame)
        .map_err(|err| warn!(error = %err, "encode delta frame failed"))
        .ok()?;
    if rest.dropped > 0 {
        warn!(
            workload_id,
            dropped = rest.dropped,
            "observer snapshot entities too large for a frame were left out"
        );
    }
    head.continues = u32::try_from(rest.bodies.len()).ok()?;
    debug!(
        workload_id,
        entities,
        frames = 1 + rest.bodies.len(),
        "observer snapshot larger than one frame, sent as a snapshot and added deltas"
    );
    let mut frames = vec![(fuz_wire::ids::OBSERVER_SNAPSHOT_FRAME, encode(&head)?)];
    frames.extend(
        rest.bodies
            .into_iter()
            .map(|body| (fuz_wire::ids::OBSERVER_DELTA_FRAME, body)),
    );
    Some(frames)
}

/// The number of entities a snapshot carries.
const fn snapshot_len(snapshot: &ObserverSnapshot) -> usize {
    match snapshot {
        ObserverSnapshot::Process(s) => s.processes.len(),
        ObserverSnapshot::Network(s) => s.connections.len(),
        ObserverSnapshot::Services(s) => s.units.len(),
    }
}

/// `snapshot` with only its first `keep` entities.
fn snapshot_prefix(snapshot: &ObserverSnapshot, keep: usize) -> ObserverSnapshot {
    match snapshot {
        ObserverSnapshot::Process(s) => ObserverSnapshot::Process(ProcessSnapshot {
            system: s.system.clone(),
            processes: s.processes[..keep].to_vec(),
        }),
        ObserverSnapshot::Network(s) => ObserverSnapshot::Network(NetworkSnapshot {
            interfaces: s.interfaces.clone(),
            connections: s.connections[..keep].to_vec(),
        }),
        ObserverSnapshot::Services(s) => ObserverSnapshot::Services(ServicesSnapshot {
            units: s.units[..keep].to_vec(),
        }),
    }
}

/// The entities of `snapshot` after the first `keep`, as one delta adding them.
fn snapshot_rest(snapshot: ObserverSnapshot, keep: usize) -> ObserverDeltaFrame {
    let delta = match snapshot {
        ObserverSnapshot::Process(mut s) => ObserverDelta::Process(ProcessDelta {
            system: s.system,
            added: s.processes.split_off(keep),
            changed: Vec::new(),
            removed: Vec::new(),
        }),
        ObserverSnapshot::Network(mut s) => ObserverDelta::Network(NetworkDelta {
            interfaces: s.interfaces,
            added: s.connections.split_off(keep),
            changed: Vec::new(),
            removed: Vec::new(),
        }),
        ObserverSnapshot::Services(mut s) => ObserverDelta::Services(ServicesDelta {
            added: s.units.split_off(keep),
            changed: Vec::new(),
            removed: Vec::new(),
        }),
    };
    ObserverDeltaFrame { delta }
}

/// Halve a delta frame across its `added` / `changed` / `removed` entities;
/// each half carries the same system or interface figures. The split for
/// [`split_encode`].
fn split_delta_frame(
    frame: ObserverDeltaFrame,
) -> Result<(ObserverDeltaFrame, ObserverDeltaFrame), ObserverDeltaFrame> {
    let wrap = |delta| ObserverDeltaFrame { delta };
    match frame.delta {
        ObserverDelta::Process(d) => {
            let system = d.system;
            let process = |system, (added, changed, removed)| {
                wrap(ObserverDelta::Process(ProcessDelta {
                    system,
                    added,
                    changed,
                    removed,
                }))
            };
            match split_lists((d.added, d.changed, d.removed)) {
                Ok((first, second)) => {
                    Ok((process(system.clone(), first), process(system, second)))
                }
                Err(whole) => Err(process(system, whole)),
            }
        }
        ObserverDelta::Network(d) => {
            let interfaces = d.interfaces;
            let network = |interfaces, (added, changed, removed)| {
                wrap(ObserverDelta::Network(NetworkDelta {
                    interfaces,
                    added,
                    changed,
                    removed,
                }))
            };
            match split_lists((d.added, d.changed, d.removed)) {
                Ok((first, second)) => Ok((
                    network(interfaces.clone(), first),
                    network(interfaces, second),
                )),
                Err(whole) => Err(network(interfaces, whole)),
            }
        }
        ObserverDelta::Services(d) => {
            let services = |(added, changed, removed)| {
                wrap(ObserverDelta::Services(ServicesDelta {
                    added,
                    changed,
                    removed,
                }))
            };
            match split_lists((d.added, d.changed, d.removed)) {
                Ok((first, second)) => Ok((services(first), services(second))),
                Err(whole) => Err(services(whole)),
            }
        }
    }
}

/// Halve an event frame, keeping the events' order. The split for
/// [`split_encode`].
fn split_event_frame(
    frame: ObserverEventFrame,
) -> Result<(ObserverEventFrame, ObserverEventFrame), ObserverEventFrame> {
    split_vec(frame.events)
        .map(|(first, second)| {
            (
                ObserverEventFrame { events: first },
                ObserverEventFrame { events: second },
            )
        })
        .map_err(|events| ObserverEventFrame { events })
}

/// One tick's diff result — the domain-tagged delta + events the fan-out encodes.
struct TickOutput {
    delta: ObserverDelta,
    events: Vec<ObserverEvent>,
}

/// Per-domain collector state. The registry pairs a collector with one domain
/// and only ever feeds it that domain's samples, so the variant and the
/// [`RawSample`] always match.
enum CollectorState {
    Process(ProcessState),
    Network(NetworkState),
    Services(ServicesState),
}

impl CollectorState {
    fn new(domain: ObserverDomain) -> Self {
        match domain {
            ObserverDomain::Process => Self::Process(ProcessState::new()),
            ObserverDomain::Network => Self::Network(NetworkState::new()),
            ObserverDomain::Services => Self::Services(ServicesState::new()),
        }
    }

    const fn has_sampled(&self) -> bool {
        match self {
            Self::Process(s) => s.has_sampled,
            Self::Network(s) => s.has_sampled,
            Self::Services(s) => s.has_sampled,
        }
    }

    /// The current full snapshot (what a new / resyncing subscriber gets).
    fn snapshot(&self) -> ObserverSnapshot {
        match self {
            Self::Process(s) => ObserverSnapshot::Process(s.snapshot()),
            Self::Network(s) => ObserverSnapshot::Network(s.snapshot()),
            Self::Services(s) => ObserverSnapshot::Services(s.snapshot()),
        }
    }

    /// Fold one raw sample into the state, returning the domain-tagged delta +
    /// events vs. what subscribers last saw. The registry only ever feeds a
    /// collector its own domain's samples, so the variant always matches.
    fn ingest(&mut self, raw: RawSample) -> TickOutput {
        match raw {
            RawSample::Process(raw) => {
                let Self::Process(state) = self else {
                    unreachable!("process sample on a non-process collector")
                };
                let (delta, events) = state.ingest(raw);
                TickOutput {
                    delta: ObserverDelta::Process(delta),
                    events: events.into_iter().map(ObserverEvent::Process).collect(),
                }
            }
            RawSample::Network(raw) => {
                let Self::Network(state) = self else {
                    unreachable!("network sample on a non-network collector")
                };
                let (delta, events) = state.ingest(raw);
                TickOutput {
                    delta: ObserverDelta::Network(delta),
                    events: events.into_iter().map(ObserverEvent::Network).collect(),
                }
            }
            RawSample::Services(raw) => {
                let Self::Services(state) = self else {
                    unreachable!("services sample on a non-services collector")
                };
                let (delta, events) = state.ingest(raw);
                TickOutput {
                    delta: ObserverDelta::Services(delta),
                    events: events.into_iter().map(ObserverEvent::Services).collect(),
                }
            }
        }
    }
}

//
// Entity diff (shared by every domain)
//

/// One tick's entity-level diff: the full records that appeared or changed,
/// the keys that vanished, and the discrete events those transitions emit.
struct EntityDiff<K, V, E> {
    added: Vec<V>,
    changed: Vec<V>,
    removed: Vec<K>,
    events: Vec<E>,
}

/// Diff `next` against `prev` by entity identity.
///
/// All three domains diff a keyed map the same way and differ only in the
/// events a transition emits, so the traversal lives here and each domain
/// supplies its three event constructors. An entity in `next` is new
/// (`on_add(key, next)`), changed (`on_change(prev, next)`, which returns
/// `None` when the domain doesn't consider that change event-worthy — services
/// emits a transition only on an `active_state` change), or unchanged; a key
/// `prev` has and `next` doesn't is removed (`on_remove(key, prev)`).
///
/// Appearances/changes are visited before removals, so the events of a tick
/// keep the order subscribers have always seen (per-loop order is `HashMap`
/// iteration order either way).
fn diff_entities<K, V, E>(
    prev: &HashMap<K, V>,
    next: &HashMap<K, V>,
    on_add: impl Fn(&K, &V) -> E,
    on_change: impl Fn(&V, &V) -> Option<E>,
    on_remove: impl Fn(&K, &V) -> E,
) -> EntityDiff<K, V, E>
where
    K: Eq + Hash + Clone,
    V: Clone + PartialEq,
{
    let mut added = Vec::new();
    let mut changed = Vec::new();
    let mut removed = Vec::new();
    let mut events = Vec::new();
    for (key, value) in next {
        match prev.get(key) {
            None => {
                added.push(value.clone());
                events.push(on_add(key, value));
            }
            Some(previous) if previous != value => {
                changed.push(value.clone());
                if let Some(event) = on_change(previous, value) {
                    events.push(event);
                }
            }
            Some(_) => {}
        }
    }
    for (key, previous) in prev {
        if !next.contains_key(key) {
            removed.push(key.clone());
            events.push(on_remove(key, previous));
        }
    }
    EntityDiff {
        added,
        changed,
        removed,
        events,
    }
}

//
// Process domain
//

/// Process collector state across samples: the current full set (what
/// subscribers have seen), plus the previous raw counters needed to compute
/// CPU rates.
struct ProcessState {
    /// Current full set, keyed for diffing. Equals what every healthy
    /// subscriber last received.
    current: HashMap<ProcessKey, ProcessInfo>,
    /// Previous per-process `utime+stime` ticks, for CPU deltas.
    prev_cpu_ticks: HashMap<ProcessKey, u64>,
    prev_total_ticks: u64,
    prev_idle_ticks: u64,
    last_system: SystemResources,
    has_sampled: bool,
}

impl ProcessState {
    fn new() -> Self {
        Self {
            current: HashMap::new(),
            prev_cpu_ticks: HashMap::new(),
            prev_total_ticks: 0,
            prev_idle_ticks: 0,
            last_system: SystemResources {
                cpu_pct: 0.0,
                ncpu: 1,
                mem_total_bytes: 0,
                mem_available_bytes: 0,
                load_1: 0.0,
                load_5: 0.0,
                load_15: 0.0,
                uptime_secs: 0,
            },
            has_sampled: false,
        }
    }

    /// The current full snapshot (what a new / resyncing subscriber gets).
    fn snapshot(&self) -> ProcessSnapshot {
        ProcessSnapshot {
            system: self.last_system.clone(),
            processes: self.current.values().cloned().collect(),
        }
    }

    /// Fold one raw sample into the state, returning the delta + events vs.
    /// what subscribers last saw. CPU rates are zero on the first sample (no
    /// prior counters to diff against).
    #[expect(
        clippy::cast_precision_loss,
        reason = "tick counts are small; f32 is ample for a percentage"
    )]
    fn ingest(&mut self, raw: RawProcessSample) -> (ProcessDelta, Vec<ProcessEvent>) {
        let first = !self.has_sampled;
        let d_total = raw
            .system
            .total_cpu_ticks
            .saturating_sub(self.prev_total_ticks);
        let d_idle = raw
            .system
            .idle_cpu_ticks
            .saturating_sub(self.prev_idle_ticks);
        let sys_cpu = if first || d_total == 0 {
            0.0
        } else {
            (100.0 * (d_total.saturating_sub(d_idle)) as f32 / d_total as f32).clamp(0.0, 100.0)
        };
        let system = SystemResources {
            cpu_pct: sys_cpu,
            ncpu: raw.system.ncpu,
            mem_total_bytes: raw.system.mem_total_bytes,
            mem_available_bytes: raw.system.mem_available_bytes,
            load_1: raw.system.load_1,
            load_5: raw.system.load_5,
            load_15: raw.system.load_15,
            uptime_secs: raw.system.uptime_secs,
        };

        let mut new_map: HashMap<ProcessKey, ProcessInfo> = HashMap::with_capacity(raw.procs.len());
        let mut new_cpu_ticks: HashMap<ProcessKey, u64> = HashMap::with_capacity(raw.procs.len());
        for mut proc in raw.procs {
            // Other users' text: bounded whatever the source read.
            cap_text(&mut proc.name, MAX_FIELD_BYTES);
            cap_opt_text(&mut proc.cmdline, MAX_CMDLINE_BYTES);
            let key = ProcessKey {
                pid: proc.pid,
                start_time: proc.start_time,
            };
            let cpu_pct = if first || d_total == 0 {
                0.0
            } else {
                self.prev_cpu_ticks.get(&key).map_or(0.0, |&prev| {
                    let d_proc = proc.cpu_ticks.saturating_sub(prev);
                    100.0 * raw.system.ncpu as f32 * d_proc as f32 / d_total as f32
                })
            };
            new_cpu_ticks.insert(key, proc.cpu_ticks);
            new_map.insert(
                key,
                ProcessInfo {
                    key,
                    ppid: proc.ppid,
                    name: proc.name,
                    state: proc.state,
                    cpu_pct,
                    mem_bytes: proc.mem_bytes,
                    cmdline: proc.cmdline,
                },
            );
        }

        let EntityDiff {
            added,
            changed,
            removed,
            events,
        } = diff_entities(
            &self.current,
            &new_map,
            |key, info| ProcessEvent::Spawn {
                key: *key,
                ppid: info.ppid,
                name: info.name.clone(),
                cmdline: info.cmdline.clone(),
            },
            // A live process's churn is delta-only; no discrete event.
            |_prev, _info| None,
            |key, prev| ProcessEvent::Exit {
                key: *key,
                name: prev.name.clone(),
            },
        );

        self.current = new_map;
        self.prev_cpu_ticks = new_cpu_ticks;
        self.prev_total_ticks = raw.system.total_cpu_ticks;
        self.prev_idle_ticks = raw.system.idle_cpu_ticks;
        self.last_system = system.clone();
        // On the first sample every process is "added"; that's a baseline,
        // not a spawn timeline, so callers discard the first delta/events.
        self.has_sampled = true;

        (
            ProcessDelta {
                system,
                added,
                changed,
                removed,
            },
            events,
        )
    }
}

//
// Network domain
//

/// Network collector state: the current connection set (for diffing by inode)
/// plus the previous per-interface byte counters (for throughput rates).
struct NetworkState {
    current: HashMap<ConnectionKey, ConnectionInfo>,
    prev_iface_bytes: HashMap<String, (u64, u64)>,
    last_interfaces: Vec<InterfaceInfo>,
    interval_secs: f32,
    has_sampled: bool,
}

impl NetworkState {
    fn new() -> Self {
        Self {
            current: HashMap::new(),
            prev_iface_bytes: HashMap::new(),
            last_interfaces: Vec::new(),
            interval_secs: NETWORK_SAMPLE_INTERVAL.as_secs_f32(),
            has_sampled: false,
        }
    }

    fn snapshot(&self) -> NetworkSnapshot {
        NetworkSnapshot {
            interfaces: self.last_interfaces.clone(),
            connections: self.current.values().cloned().collect(),
        }
    }

    /// Fold one raw sample into the state. Interface rates are zero on the
    /// first sample; connections diff by inode.
    #[expect(
        clippy::cast_precision_loss,
        reason = "byte counts; f32 is ample for a throughput rate"
    )]
    fn ingest(&mut self, mut raw: RawNetworkSample) -> (NetworkDelta, Vec<ConnectionEvent>) {
        let first = !self.has_sampled;
        // The system's text: bounded whatever the source read.
        for iface in &mut raw.interfaces {
            cap_text(&mut iface.name, MAX_FIELD_BYTES);
        }
        let interfaces: Vec<InterfaceInfo> = raw
            .interfaces
            .iter()
            .map(|iface| {
                let (rx_bps, tx_bps) = if first {
                    (0.0, 0.0)
                } else {
                    self.prev_iface_bytes
                        .get(&iface.name)
                        .map_or((0.0, 0.0), |&(prx, ptx)| {
                            let drx =
                                iface.rx_bytes.saturating_sub(prx) as f32 / self.interval_secs;
                            let dtx =
                                iface.tx_bytes.saturating_sub(ptx) as f32 / self.interval_secs;
                            (drx, dtx)
                        })
                };
                InterfaceInfo {
                    name: iface.name.clone(),
                    rx_bytes: iface.rx_bytes,
                    tx_bytes: iface.tx_bytes,
                    rx_bps,
                    tx_bps,
                }
            })
            .collect();

        let mut new_map: HashMap<ConnectionKey, ConnectionInfo> =
            HashMap::with_capacity(raw.connections.len());
        for mut conn in raw.connections {
            cap_text(&mut conn.local_addr, MAX_FIELD_BYTES);
            cap_text(&mut conn.peer_addr, MAX_FIELD_BYTES);
            let key = ConnectionKey { inode: conn.inode };
            new_map.insert(
                key,
                ConnectionInfo {
                    key,
                    protocol: conn.protocol,
                    local_addr: conn.local_addr,
                    peer_addr: conn.peer_addr,
                    state: SocketState::from_code(conn.state_code),
                    pid: conn.pid,
                },
            );
        }

        let EntityDiff {
            added,
            changed,
            removed,
            events,
        } = diff_entities(
            &self.current,
            &new_map,
            |key, info| ConnectionEvent::Open {
                key: *key,
                protocol: info.protocol,
                local_addr: info.local_addr.clone(),
                peer_addr: info.peer_addr.clone(),
                pid: info.pid,
            },
            // A socket's state/peer churn is delta-only; no discrete event.
            |_prev, _info| None,
            |key, prev| ConnectionEvent::Close {
                key: *key,
                peer_addr: prev.peer_addr.clone(),
            },
        );

        self.current = new_map;
        self.prev_iface_bytes = raw
            .interfaces
            .iter()
            .map(|i| (i.name.clone(), (i.rx_bytes, i.tx_bytes)))
            .collect();
        self.last_interfaces.clone_from(&interfaces);
        self.has_sampled = true;

        (
            NetworkDelta {
                interfaces,
                added,
                changed,
                removed,
            },
            events,
        )
    }
}

//
// Services domain
//

/// Services collector state: the current unit set, diffed by unit name.
struct ServicesState {
    current: HashMap<String, ServiceUnit>,
    has_sampled: bool,
}

impl ServicesState {
    fn new() -> Self {
        Self {
            current: HashMap::new(),
            has_sampled: false,
        }
    }

    fn snapshot(&self) -> ServicesSnapshot {
        ServicesSnapshot {
            units: self.current.values().cloned().collect(),
        }
    }

    /// Fold one raw sample into the state. A timeline transition is emitted on
    /// an `active_state` change (or a new unit) — sub-state / description churn
    /// alone is `changed` but not a transition event.
    fn ingest(&mut self, raw: RawServicesSample) -> (ServicesDelta, Vec<ServiceEvent>) {
        let mut new_map: HashMap<String, ServiceUnit> = HashMap::with_capacity(raw.units.len());
        for mut unit in raw.units {
            // The units' text: bounded whatever the source read.
            cap_text(&mut unit.name, MAX_FIELD_BYTES);
            cap_text(&mut unit.load_state, MAX_FIELD_BYTES);
            cap_text(&mut unit.sub_state, MAX_FIELD_BYTES);
            cap_text(&mut unit.description, MAX_DESCRIPTION_BYTES);
            new_map.insert(
                unit.name.clone(),
                ServiceUnit {
                    name: unit.name,
                    load_state: unit.load_state,
                    active_state: unit.active_state,
                    sub_state: unit.sub_state,
                    description: unit.description,
                    main_pid: unit.main_pid,
                },
            );
        }

        let EntityDiff {
            added,
            changed,
            removed,
            events,
        } = diff_entities(
            &self.current,
            &new_map,
            |_name, unit| transition_event(unit),
            // Sub-state / description / main_pid churn alone is `changed` but
            // not a transition — only `active_state` moves the timeline.
            |prev, unit| (prev.active_state != unit.active_state).then(|| transition_event(unit)),
            |name, _prev| ServiceEvent::Removed { name: name.clone() },
        );

        self.current = new_map;
        self.has_sampled = true;

        (
            ServicesDelta {
                added,
                changed,
                removed,
            },
            events,
        )
    }
}

/// Build a `Transition` event recording a unit's current state.
fn transition_event(unit: &ServiceUnit) -> ServiceEvent {
    ServiceEvent::Transition {
        name: unit.name.clone(),
        active_state: unit.active_state,
        sub_state: unit.sub_state.clone(),
        main_pid: unit.main_pid,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::out::OutFrame;
    use crate::workload::collector::{COLLECTOR_CMD_CAP, full_out_channel, send_add_subscriber};
    use crate::workload::net_source::{RawConnection, RawInterface};
    use crate::workload::proc_source::{RawProc, RawSystem};
    use crate::workload::services_source::RawUnit;
    use crate::workload::source::ObserverError;
    use fuz_wire::FrameFlags;
    use fuz_wire::{SocketProtocol, UnitActiveState};
    use std::sync::Mutex;

    //
    // Process domain
    //

    fn proc(pid: i32, start: u64, cpu: u64, mem: u64) -> RawProc {
        RawProc {
            pid,
            start_time: start,
            ppid: 1,
            name: format!("p{pid}"),
            state: 'S',
            cpu_ticks: cpu,
            mem_bytes: mem,
            cmdline: Some(format!("/bin/p{pid}")),
        }
    }

    fn sample_with(total: u64, idle: u64, procs: Vec<RawProc>) -> RawProcessSample {
        RawProcessSample {
            system: RawSystem {
                ncpu: 4,
                total_cpu_ticks: total,
                idle_cpu_ticks: idle,
                mem_total_bytes: 16_000,
                mem_available_bytes: 8_000,
                load_1: 0.5,
                load_5: 0.4,
                load_15: 0.3,
                uptime_secs: 100,
            },
            procs,
        }
    }

    #[test]
    fn first_ingest_is_baseline_zero_cpu() {
        let mut state = ProcessState::new();
        let (delta, _events) = state.ingest(sample_with(1000, 800, vec![proc(10, 5, 100, 2048)]));
        // First sample: everything is "added", CPU is 0 (no prior counters).
        assert_eq!(delta.added.len(), 1);
        assert!((delta.added[0].cpu_pct - 0.0).abs() < f32::EPSILON);
        assert!((delta.system.cpu_pct - 0.0).abs() < f32::EPSILON);
        assert_eq!(delta.added[0].mem_bytes, 2048);
    }

    #[test]
    fn second_ingest_computes_cpu_and_classifies_changes() {
        let mut state = ProcessState::new();
        // Baseline.
        state.ingest(sample_with(1000, 800, vec![proc(10, 5, 100, 2048)]));
        // Next tick: total advances 100 ticks (20 idle), pid10 burned 50
        // ticks, pid11 is new, pid10 unchanged-key.
        let (delta, events) = state.ingest(sample_with(
            1100,
            820,
            vec![proc(10, 5, 150, 2048), proc(11, 6, 0, 1024)],
        ));
        // system busy = (Δtotal 100 - Δidle 20) / 100 = 80%.
        assert!((delta.system.cpu_pct - 80.0).abs() < 0.01);
        // pid10 changed (cpu went up); pid11 added.
        assert_eq!(delta.added.len(), 1);
        assert_eq!(delta.added[0].key.pid, 11);
        assert_eq!(delta.changed.len(), 1);
        assert_eq!(delta.changed[0].key.pid, 10);
        // pid10 cpu = 100 * ncpu(4) * Δ50 / Δtotal100 = 200% (4-core scale).
        assert!((delta.changed[0].cpu_pct - 200.0).abs() < 0.01);
        // pid11 spawn event.
        assert_eq!(events.len(), 1);
        assert!(matches!(events[0], ProcessEvent::Spawn { .. }));
    }

    #[test]
    fn exit_emits_removed_and_event() {
        let mut state = ProcessState::new();
        state.ingest(sample_with(
            1000,
            800,
            vec![proc(10, 5, 100, 2048), proc(11, 6, 0, 1024)],
        ));
        let (delta, events) = state.ingest(sample_with(1100, 1000, vec![proc(10, 5, 100, 2048)]));
        assert_eq!(delta.removed.len(), 1);
        assert_eq!(delta.removed[0].pid, 11);
        assert_eq!(events.len(), 1);
        assert!(matches!(events[0], ProcessEvent::Exit { .. }));
        // pid10 cpu unchanged (Δ0) and mem same → not "changed".
        assert!(delta.changed.is_empty());
    }

    #[test]
    fn pid_reuse_is_a_different_entity() {
        let mut state = ProcessState::new();
        // pid 10 with start_time 5.
        state.ingest(sample_with(1000, 800, vec![proc(10, 5, 100, 2048)]));
        // Same pid, different start_time 9 → reuse: old exits, new spawns.
        let (delta, _events) = state.ingest(sample_with(1100, 1000, vec![proc(10, 9, 0, 512)]));
        assert_eq!(delta.added.len(), 1, "reused pid is a new entity");
        assert_eq!(delta.added[0].key.start_time, 9);
        assert_eq!(delta.removed.len(), 1, "old start_time exits");
        assert_eq!(delta.removed[0].start_time, 5);
    }

    //
    // Network domain
    //

    fn iface(name: &str, rx: u64, tx: u64) -> RawInterface {
        RawInterface {
            name: name.to_string(),
            rx_bytes: rx,
            tx_bytes: tx,
        }
    }

    fn conn(inode: u64, peer: &str, state_code: u8, pid: Option<i32>) -> RawConnection {
        RawConnection {
            inode,
            protocol: SocketProtocol::Tcp,
            local_addr: "127.0.0.1:5432".to_string(),
            peer_addr: peer.to_string(),
            state_code,
            pid,
        }
    }

    fn net_sample(
        interfaces: Vec<RawInterface>,
        connections: Vec<RawConnection>,
    ) -> RawNetworkSample {
        RawNetworkSample {
            interfaces,
            connections,
        }
    }

    #[test]
    fn network_first_sample_is_baseline_zero_throughput() {
        let mut state = NetworkState::new();
        let (delta, _events) = state.ingest(net_sample(
            vec![iface("lo", 1000, 2000)],
            vec![conn(8352, "0.0.0.0:0", 0x0A, None)],
        ));
        assert_eq!(delta.added.len(), 1);
        // No prior counters → zero throughput on the first sample.
        assert!((delta.interfaces[0].rx_bps - 0.0).abs() < f32::EPSILON);
        assert!((delta.interfaces[0].tx_bps - 0.0).abs() < f32::EPSILON);
    }

    #[test]
    fn network_computes_throughput_and_connection_diff() {
        let mut state = NetworkState::new();
        state.ingest(net_sample(
            vec![iface("lo", 1000, 2000)],
            vec![conn(8352, "1.2.3.4:80", 0x01, Some(42))],
        ));
        // Next tick: lo gained 1000 rx / 3000 tx over a 1s interval; a new
        // connection opened, the old one's peer changed (→ changed).
        let (delta, events) = state.ingest(net_sample(
            vec![iface("lo", 2000, 5000)],
            vec![
                conn(8352, "5.6.7.8:80", 0x01, Some(42)),
                conn(9001, "0.0.0.0:0", 0x0A, None),
            ],
        ));
        let lo = &delta.interfaces[0];
        // 1s interval → bps == byte delta.
        assert!((lo.rx_bps - 1000.0).abs() < 1.0, "rx_bps ≈ Δrx / interval");
        assert!((lo.tx_bps - 3000.0).abs() < 1.0, "tx_bps ≈ Δtx / interval");
        assert_eq!(delta.added.len(), 1, "inode 9001 is new");
        assert_eq!(delta.added[0].key.inode, 9001);
        assert_eq!(delta.changed.len(), 1, "inode 8352 peer changed");
        assert_eq!(delta.changed[0].key.inode, 8352);
        // One Open event for the new socket (the changed one isn't an Open).
        assert_eq!(events.len(), 1);
        assert!(matches!(events[0], ConnectionEvent::Open { .. }));
    }

    #[test]
    fn network_close_emits_removed_and_event() {
        let mut state = NetworkState::new();
        state.ingest(net_sample(
            vec![iface("lo", 0, 0)],
            vec![conn(8352, "1.2.3.4:80", 0x01, Some(42))],
        ));
        let (delta, events) = state.ingest(net_sample(vec![iface("lo", 0, 0)], vec![]));
        assert_eq!(delta.removed.len(), 1);
        assert_eq!(delta.removed[0].inode, 8352);
        assert_eq!(events.len(), 1);
        assert!(matches!(events[0], ConnectionEvent::Close { .. }));
    }

    #[test]
    fn socket_state_maps_listen_and_established() {
        assert_eq!(SocketState::from_code(0x01), SocketState::Established);
        assert_eq!(SocketState::from_code(0x0A), SocketState::Listen);
        assert_eq!(SocketState::from_code(0xFF), SocketState::Unknown);
    }

    //
    // Services domain
    //

    fn unit(name: &str, active: UnitActiveState, sub: &str, pid: Option<i32>) -> RawUnit {
        RawUnit {
            name: name.to_string(),
            load_state: "loaded".to_string(),
            active_state: active,
            sub_state: sub.to_string(),
            description: format!("{name} desc"),
            main_pid: pid,
        }
    }

    fn svc_sample(units: Vec<RawUnit>) -> RawServicesSample {
        RawServicesSample { units }
    }

    #[test]
    fn services_first_sample_adds_and_transitions() {
        let mut state = ServicesState::new();
        let (delta, events) = state.ingest(svc_sample(vec![
            unit("a.service", UnitActiveState::Active, "running", Some(7)),
            unit("b.service", UnitActiveState::Inactive, "dead", None),
        ]));
        assert_eq!(delta.added.len(), 2);
        // Both appearing units emit a transition event.
        assert_eq!(events.len(), 2);
        assert!(
            events
                .iter()
                .all(|e| matches!(e, ServiceEvent::Transition { .. }))
        );
    }

    #[test]
    fn services_transition_event_only_on_active_state_change() {
        let mut state = ServicesState::new();
        state.ingest(svc_sample(vec![unit(
            "a.service",
            UnitActiveState::Activating,
            "start",
            None,
        )]));
        // active_state changes activating → active: a transition.
        let (delta, events) = state.ingest(svc_sample(vec![unit(
            "a.service",
            UnitActiveState::Active,
            "running",
            Some(7),
        )]));
        assert_eq!(delta.changed.len(), 1);
        assert_eq!(events.len(), 1, "active_state change emits a transition");
        // The payload must carry the NEW state — a prev/next swap in the
        // change closure would emit the stale one with identical counts.
        assert!(
            matches!(
                &events[0],
                ServiceEvent::Transition {
                    active_state: UnitActiveState::Active,
                    ..
                }
            ),
            "transition carries the new active_state"
        );

        // Only sub_state / main_pid churn (same active_state): changed, no event.
        let (delta, events) = state.ingest(svc_sample(vec![unit(
            "a.service",
            UnitActiveState::Active,
            "running",
            Some(99),
        )]));
        assert_eq!(delta.changed.len(), 1, "main_pid changed → changed record");
        assert!(
            events.is_empty(),
            "no active_state change → no transition event"
        );
    }

    #[test]
    fn services_removed_emits_event() {
        let mut state = ServicesState::new();
        state.ingest(svc_sample(vec![unit(
            "a.service",
            UnitActiveState::Active,
            "running",
            Some(7),
        )]));
        let (delta, events) = state.ingest(svc_sample(vec![]));
        assert_eq!(delta.removed.len(), 1);
        assert_eq!(delta.removed[0], "a.service");
        assert_eq!(events.len(), 1);
        assert!(matches!(events[0], ServiceEvent::Removed { .. }));
    }

    //
    // Collector loop (generic)
    //

    /// A scripted source: each `sample_process` pops the next canned sample.
    #[derive(Debug)]
    struct ScriptedSource {
        samples: Mutex<Vec<RawProcessSample>>,
    }

    impl ObserverSource for ScriptedSource {
        fn sample_process(&self) -> Result<RawProcessSample, ObserverError> {
            let mut s = self.samples.lock().expect("lock");
            Ok(if s.is_empty() {
                empty_sample()
            } else {
                s.remove(0)
            })
        }

        fn sample_network(&self) -> Result<RawNetworkSample, ObserverError> {
            Ok(net_sample(vec![], vec![]))
        }

        fn sample_services(&self) -> Result<RawServicesSample, ObserverError> {
            Ok(svc_sample(vec![]))
        }
    }

    fn empty_sample() -> RawProcessSample {
        RawProcessSample {
            system: RawSystem {
                ncpu: 4,
                total_cpu_ticks: 0,
                idle_cpu_ticks: 0,
                mem_total_bytes: 1024,
                mem_available_bytes: 512,
                load_1: 0.0,
                load_5: 0.0,
                load_15: 0.0,
                uptime_secs: 1,
            },
            procs: vec![],
        }
    }

    #[tokio::test]
    async fn full_channel_flags_resync_then_sends_snapshot() {
        // The load-bearing resync-over-drop guarantee: a full subscriber
        // channel must drop the delta and resync with a fresh snapshot, never
        // silently drop a delta (which would corrupt the consumer's view).
        let mut state = CollectorState::new(ObserverDomain::Process);
        // Baseline so `current` is populated for a resync snapshot.
        state.ingest(RawSample::Process(sample_with(
            1000,
            800,
            vec![proc(10, 5, 100, 2048)],
        )));

        // A subscriber whose (capacity-1) channel is already full.
        let (out_tx, mut out_rx) = mpsc::channel::<OutFrame>(1);
        out_tx
            .try_send(OutFrame {
                request_id: 1,
                action: fuz_wire::ids::OBSERVER_DELTA_FRAME,
                flags: FrameFlags::EMPTY,
                body: vec![],
            })
            .expect("prefill the channel");
        let mut subs = vec![Subscriber {
            conn_id: 1,
            request_id: 1,
            out_tx,
            needs_resync: false,
        }];

        // Tick: the delta can't be sent (full) → dropped + flagged for resync.
        let out = state.ingest(RawSample::Process(sample_with(
            1100,
            820,
            vec![proc(10, 5, 150, 2048)],
        )));
        fanout(&mut subs, &out, &state, 7, FRAME_BODY_BUDGET);
        assert!(
            subs[0].needs_resync,
            "full channel flags resync, drops the delta"
        );

        // Make room, tick again: the subscriber resyncs with a snapshot.
        out_rx.recv().await.expect("drain the prefill");
        let out = state.ingest(RawSample::Process(sample_with(
            1200,
            840,
            vec![proc(10, 5, 200, 2048)],
        )));
        fanout(&mut subs, &out, &state, 7, FRAME_BODY_BUDGET);
        assert!(
            !subs[0].needs_resync,
            "resync clears once the snapshot is sent"
        );
        let frame = out_rx.try_recv().expect("a frame was sent");
        assert_eq!(
            frame.action,
            fuz_wire::ids::OBSERVER_SNAPSHOT_FRAME,
            "resync sends a snapshot, not a delta"
        );
    }

    #[tokio::test]
    async fn collector_streams_snapshot_to_subscriber() {
        let source: Arc<dyn ObserverSource> = Arc::new(ScriptedSource {
            samples: Mutex::new(vec![sample_with(1000, 800, vec![proc(10, 5, 100, 2048)])]),
        });
        let (cmd_tx, cmd_rx) = mpsc::channel(COLLECTOR_CMD_CAP);
        let stop = CancellationToken::new();
        let handle = tokio::spawn(run_collector(
            ObserverDomain::Process,
            7,
            source,
            cmd_rx,
            stop.clone(),
        ));

        let (out_tx, mut out_rx) = mpsc::channel::<OutFrame>(16);
        cmd_tx
            .send(CollectorCommand::AddSubscriber {
                conn_id: 1,
                request_id: 99,
                out_tx,
            })
            .await
            .expect("send add");

        let frame = out_rx.recv().await.expect("snapshot frame");
        assert_eq!(frame.request_id, 99);
        assert_eq!(frame.action, fuz_wire::ids::OBSERVER_SNAPSHOT_FRAME);
        assert!(!frame.flags.is_final(), "stream frames are not FINAL");
        let decoded: ObserverSnapshotFrame =
            fuz_wire::decode_payload(&frame.body).expect("decode snapshot");
        assert_eq!(decoded.workload_id, 7);
        let ObserverSnapshot::Process(snap) = decoded.snapshot else {
            panic!("expected a process snapshot");
        };
        assert_eq!(snap.processes.len(), 1);

        stop.cancel();
        handle.await.expect("collector joins");
    }

    /// Spawn a process-domain collector over `source`; returns the command
    /// sender, the stop token, and the join handle.
    fn spawn_process_collector(
        source: Arc<dyn ObserverSource>,
    ) -> (
        mpsc::Sender<CollectorCommand>,
        CancellationToken,
        tokio::task::JoinHandle<()>,
    ) {
        let (cmd_tx, cmd_rx) = mpsc::channel(COLLECTOR_CMD_CAP);
        let stop = CancellationToken::new();
        let handle = tokio::spawn(run_collector(
            ObserverDomain::Process,
            7,
            source,
            cmd_rx,
            stop.clone(),
        ));
        (cmd_tx, stop, handle)
    }

    #[tokio::test]
    async fn a_stuck_subscriber_does_not_hold_up_another_subscribers_frames() {
        // One collector serves every subscriber, so it must never wait on one:
        // a subscriber joining with a full channel (a client that stopped
        // reading) leaves the next tick's delta reaching the healthy one.
        let (cmd_tx, stop, handle) = spawn_process_collector(Arc::new(ScriptedSource {
            samples: Mutex::new(Vec::new()),
        }));
        let (healthy_tx, mut healthy_rx) = mpsc::channel::<OutFrame>(16);
        send_add_subscriber(&cmd_tx, 1, healthy_tx).await;
        let frame = healthy_rx.recv().await.expect("healthy snapshot");
        assert_eq!(frame.action, fuz_wire::ids::OBSERVER_SNAPSHOT_FRAME);
        // The interval's first tick fires at once; take its delta so the one
        // awaited below comes from a tick after the stuck subscriber joined.
        let frame = healthy_rx.recv().await.expect("first-tick delta");
        assert_eq!(frame.action, fuz_wire::ids::OBSERVER_DELTA_FRAME);

        let (stuck_tx, mut stuck_rx) = full_out_channel();
        send_add_subscriber(&cmd_tx, 2, stuck_tx).await;

        let frame = tokio::time::timeout(PROCESS_SAMPLE_INTERVAL * 3, healthy_rx.recv())
            .await
            .expect("the healthy subscriber's delta arrived despite the stuck one")
            .expect("delta frame");
        assert_eq!(frame.action, fuz_wire::ids::OBSERVER_DELTA_FRAME);

        // Once the stuck client reads again, its first frame is a snapshot.
        stuck_rx.recv().await.expect("the prefill");
        let frame = tokio::time::timeout(PROCESS_SAMPLE_INTERVAL * 3, stuck_rx.recv())
            .await
            .expect("the late snapshot in time")
            .expect("snapshot frame");
        assert_eq!(
            frame.action,
            fuz_wire::ids::OBSERVER_SNAPSHOT_FRAME,
            "a subscriber that joined backed up still starts on a snapshot"
        );
        assert_eq!(frame.request_id, 99);

        stop.cancel();
        handle.await.expect("collector joins");
    }

    #[tokio::test]
    async fn stop_ends_the_collector_promptly_with_a_stuck_subscriber() {
        let (cmd_tx, stop, handle) = spawn_process_collector(Arc::new(ScriptedSource {
            samples: Mutex::new(Vec::new()),
        }));
        let (stuck_tx, _stuck_rx) = full_out_channel();
        send_add_subscriber(&cmd_tx, 1, stuck_tx).await;
        // Let the collector take the command before stopping it.
        tokio::time::sleep(Duration::from_millis(50)).await;

        stop.cancel();
        tokio::time::timeout(Duration::from_secs(1), handle)
            .await
            .expect("the collector exits on stop despite a stuck subscriber")
            .expect("collector joins");
    }

    /// A source whose process sample blocks until its gate is released (or
    /// dropped) — a `systemctl` / `/proc` read that hangs.
    #[derive(Debug)]
    struct GatedSource {
        gate: Mutex<std::sync::mpsc::Receiver<()>>,
    }

    impl ObserverSource for GatedSource {
        fn sample_process(&self) -> Result<RawProcessSample, ObserverError> {
            let _ = self.gate.lock().expect("lock").recv();
            Ok(empty_sample())
        }

        fn sample_network(&self) -> Result<RawNetworkSample, ObserverError> {
            Ok(net_sample(vec![], vec![]))
        }

        fn sample_services(&self) -> Result<RawServicesSample, ObserverError> {
            Ok(svc_sample(vec![]))
        }
    }

    #[tokio::test]
    async fn stop_ends_the_collector_promptly_mid_sample() {
        // The first subscriber makes the collector sample; a hung sample must
        // not keep it (and its subscribers' channel senders) alive past stop.
        let (release, gate) = std::sync::mpsc::channel::<()>();
        let (cmd_tx, stop, handle) = spawn_process_collector(Arc::new(GatedSource {
            gate: Mutex::new(gate),
        }));
        let (out_tx, _out_rx) = mpsc::channel::<OutFrame>(16);
        send_add_subscriber(&cmd_tx, 1, out_tx).await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        stop.cancel();
        let joined = tokio::time::timeout(Duration::from_secs(1), handle).await;
        // Release the blocking thread either way, so the runtime can shut down.
        drop(release);
        joined
            .expect("the collector exits on stop while a sample hangs")
            .expect("collector joins");
    }

    //
    // Frame bounds
    //

    /// A source whose every process sample is `procs` — what a hostile local
    /// user, or a source other than the shipped one, can make the observer see.
    #[derive(Debug)]
    struct FixedSource {
        procs: Vec<RawProc>,
    }

    impl ObserverSource for FixedSource {
        fn sample_process(&self) -> Result<RawProcessSample, ObserverError> {
            let mut sample = empty_sample();
            sample.procs.clone_from(&self.procs);
            Ok(sample)
        }

        fn sample_network(&self) -> Result<RawNetworkSample, ObserverError> {
            Ok(net_sample(vec![], vec![]))
        }

        fn sample_services(&self) -> Result<RawServicesSample, ObserverError> {
            Ok(svc_sample(vec![]))
        }
    }

    fn proc_with_cmdline(pid: i32, cmdline: String) -> RawProc {
        RawProc {
            cmdline: Some(cmdline),
            ..proc(pid, 1, 0, 0)
        }
    }

    /// A process collector serving one subscriber through a real connection
    /// writer and socket.
    struct SocketSubscription {
        client: tokio::net::UnixStream,
        writer: tokio::task::JoinHandle<()>,
        /// Held so the collector keeps running.
        _cmd_tx: mpsc::Sender<CollectorCommand>,
        stop: CancellationToken,
        collector: tokio::task::JoinHandle<()>,
    }

    /// Subscribe to a process collector over `source` through a real
    /// connection writer and socket.
    async fn subscribe_over_socket(source: Arc<dyn ObserverSource>) -> SocketSubscription {
        let (daemon_end, client_end) = tokio::net::UnixStream::pair().expect("socket pair");
        let (_daemon_read, daemon_write) = daemon_end.into_split();
        let (out_tx, out_rx) = mpsc::channel(crate::out::OUT_CHANNEL_CAP);
        let writer = tokio::spawn(crate::conn::writer_task(daemon_write, out_rx));
        let (cmd_tx, stop, collector) = spawn_process_collector(source);
        send_add_subscriber(&cmd_tx, 1, out_tx).await;
        SocketSubscription {
            client: client_end,
            writer,
            _cmd_tx: cmd_tx,
            stop,
            collector,
        }
    }

    async fn read_stream_frame(stream: &mut tokio::net::UnixStream) -> (fuz_wire::Header, Vec<u8>) {
        tokio::time::timeout(
            Duration::from_secs(10),
            fuz_wire::read_frame(stream, fuz_wire::MAX_FRAME),
        )
        .await
        .expect("a frame in time")
        .expect("the connection is still up")
    }

    #[tokio::test]
    async fn huge_cmdlines_still_reach_the_subscriber_as_a_bounded_snapshot() {
        // Four 3 MiB command lines: 12 MiB of other users' text, more than one
        // frame holds. Each is cut to its bound, the snapshot arrives, and the
        // connection stays up for the deltas after it.
        let huge = "a".repeat(3 * 1024 * 1024);
        let mut procs: Vec<RawProc> = (0..4)
            .map(|pid| proc_with_cmdline(pid, huge.clone()))
            .collect();
        procs.push(proc(9, 1, 0, 0));
        let SocketSubscription {
            mut client,
            writer,
            _cmd_tx,
            stop,
            collector,
        } = subscribe_over_socket(Arc::new(FixedSource { procs })).await;

        let (header, body) = read_stream_frame(&mut client).await;
        assert_eq!(header.action, fuz_wire::ids::OBSERVER_SNAPSHOT_FRAME);
        let frame: ObserverSnapshotFrame = fuz_wire::decode_payload(&body).expect("decode");
        let ObserverSnapshot::Process(snapshot) = frame.snapshot else {
            panic!("expected a process snapshot");
        };
        assert_eq!(snapshot.processes.len(), 5, "every process is reported");
        for info in snapshot.processes.iter().filter(|p| p.key.pid < 4) {
            let cmdline = info.cmdline.as_deref().expect("a cmdline");
            assert!(cmdline.len() <= MAX_CMDLINE_BYTES, "{}", cmdline.len());
            assert!(cmdline.ends_with(super::super::bounds::CUT_MARKER));
        }

        let (header, _) = read_stream_frame(&mut client).await;
        assert_eq!(header.action, fuz_wire::ids::OBSERVER_DELTA_FRAME);
        assert!(!writer.is_finished(), "the writer is still serving");

        stop.cancel();
        collector.await.expect("collector joins");
        writer.abort();
    }

    #[tokio::test]
    async fn a_snapshot_larger_than_a_frame_arrives_whole_across_frames() {
        // Enough processes with command lines at their bound that the snapshot
        // outgrows one frame: it arrives as a snapshot and `added` deltas, every
        // process once, each frame within the limit.
        let count: i32 = 3000;
        let cmdline = "b".repeat(MAX_CMDLINE_BYTES);
        let procs = (0..count)
            .map(|pid| proc_with_cmdline(pid, cmdline.clone()))
            .collect();
        let SocketSubscription {
            mut client,
            writer,
            _cmd_tx,
            stop,
            collector,
        } = subscribe_over_socket(Arc::new(FixedSource { procs })).await;

        let (header, body) = read_stream_frame(&mut client).await;
        assert_eq!(header.action, fuz_wire::ids::OBSERVER_SNAPSHOT_FRAME);
        let frame: ObserverSnapshotFrame = fuz_wire::decode_payload(&body).expect("decode");
        let ObserverSnapshot::Process(snapshot) = frame.snapshot else {
            panic!("expected a process snapshot");
        };
        assert!(
            snapshot.processes.len() < usize::try_from(count).expect("count"),
            "the snapshot frame alone cannot hold them all"
        );
        let continues = frame.continues;
        assert!(continues > 0, "the snapshot says more frames complete it");
        let mut seen: std::collections::HashSet<i32> =
            snapshot.processes.iter().map(|p| p.key.pid).collect();
        let mut frames = 1;
        while seen.len() < usize::try_from(count).expect("count") {
            let (header, body) = read_stream_frame(&mut client).await;
            assert_eq!(header.action, fuz_wire::ids::OBSERVER_DELTA_FRAME);
            let frame: ObserverDeltaFrame = fuz_wire::decode_payload(&body).expect("decode");
            let ObserverDelta::Process(delta) = frame.delta else {
                panic!("expected a process delta");
            };
            for info in delta.added {
                assert!(seen.insert(info.key.pid), "pid {} twice", info.key.pid);
            }
            frames += 1;
            assert!(frames < 64, "the rest arrives in a few frames");
        }
        assert_eq!(
            frames - 1,
            continues,
            "exactly `continues` deltas complete it"
        );
        assert!(!writer.is_finished(), "the writer is still serving");

        stop.cancel();
        collector.await.expect("collector joins");
        writer.abort();
    }

    #[test]
    fn snapshot_frames_split_to_the_budget_and_keep_every_entity() {
        let mut state = ProcessState::new();
        let procs = (0..40).map(|pid| proc(pid, 1, 0, 0)).collect();
        state.ingest(sample_with(1000, 800, procs));
        let snapshot = ObserverSnapshot::Process(state.snapshot());
        let budget = 600;
        let frames = snapshot_frames(snapshot, 7, budget).expect("frames");
        assert!(frames.len() > 1, "{} frames", frames.len());
        let mut pids = Vec::new();
        for (idx, (action, body)) in frames.iter().enumerate() {
            assert!(body.len() <= budget, "frame {idx}: {}", body.len());
            if idx == 0 {
                assert_eq!(*action, fuz_wire::ids::OBSERVER_SNAPSHOT_FRAME);
                let frame: ObserverSnapshotFrame = fuz_wire::decode_payload(body).unwrap();
                assert_eq!(
                    frame.continues as usize,
                    frames.len() - 1,
                    "the snapshot counts the deltas that complete it"
                );
                let ObserverSnapshot::Process(s) = frame.snapshot else {
                    panic!("process snapshot");
                };
                pids.extend(s.processes.iter().map(|p| p.key.pid));
            } else {
                assert_eq!(*action, fuz_wire::ids::OBSERVER_DELTA_FRAME);
                let frame: ObserverDeltaFrame = fuz_wire::decode_payload(body).unwrap();
                let ObserverDelta::Process(d) = frame.delta else {
                    panic!("process delta");
                };
                assert!(d.changed.is_empty() && d.removed.is_empty());
                pids.extend(d.added.iter().map(|p| p.key.pid));
            }
        }
        pids.sort_unstable();
        assert_eq!(pids, (0..40).collect::<Vec<_>>(), "every process once");
    }

    #[test]
    fn a_delta_larger_than_the_budget_goes_out_in_several_frames() {
        let mut state = CollectorState::new(ObserverDomain::Process);
        state.ingest(RawSample::Process(sample_with(1000, 800, vec![])));
        let procs = (0..40).map(|pid| proc(pid, 1, 0, 0)).collect();
        let out = state.ingest(RawSample::Process(sample_with(1100, 820, procs)));
        let (out_tx, mut out_rx) = mpsc::channel::<OutFrame>(64);
        let mut subs = vec![Subscriber {
            conn_id: 1,
            request_id: 1,
            out_tx,
            needs_resync: false,
        }];
        let budget = 600;
        fanout(&mut subs, &out, &state, 7, budget);
        let mut added = 0;
        let mut spawns = 0;
        while let Ok(frame) = out_rx.try_recv() {
            assert!(frame.body.len() <= budget, "{}", frame.body.len());
            match frame.action {
                fuz_wire::ids::OBSERVER_DELTA_FRAME => {
                    let f: ObserverDeltaFrame = fuz_wire::decode_payload(&frame.body).unwrap();
                    let ObserverDelta::Process(d) = f.delta else {
                        panic!("process delta");
                    };
                    added += d.added.len();
                }
                fuz_wire::ids::OBSERVER_EVENT_FRAME => {
                    let f: ObserverEventFrame = fuz_wire::decode_payload(&frame.body).unwrap();
                    spawns += f.events.len();
                }
                other => panic!("unexpected {other}"),
            }
        }
        assert_eq!((added, spawns), (40, 40), "every entity and event once");
        assert!(!subs[0].needs_resync);
    }

    #[test]
    fn ingest_bounds_every_string_a_source_reports() {
        let long = "x".repeat(MAX_DESCRIPTION_BYTES * 8);

        let mut process = ProcessState::new();
        let (delta, _) = process.ingest(sample_with(
            1000,
            800,
            vec![RawProc {
                name: long.clone(),
                cmdline: Some(long.clone()),
                ..proc(1, 1, 0, 0)
            }],
        ));
        assert!(delta.added[0].name.len() <= MAX_FIELD_BYTES);
        assert!(delta.added[0].cmdline.as_ref().unwrap().len() <= MAX_CMDLINE_BYTES);

        let mut network = NetworkState::new();
        let (delta, _) = network.ingest(net_sample(
            vec![iface(&long, 0, 0)],
            vec![RawConnection {
                local_addr: long.clone(),
                peer_addr: long.clone(),
                ..conn(1, "", 1, None)
            }],
        ));
        assert!(delta.interfaces[0].name.len() <= MAX_FIELD_BYTES);
        assert!(delta.added[0].local_addr.len() <= MAX_FIELD_BYTES);
        assert!(delta.added[0].peer_addr.len() <= MAX_FIELD_BYTES);

        let mut services = ServicesState::new();
        let (delta, _) = services.ingest(svc_sample(vec![RawUnit {
            name: long.clone(),
            load_state: long.clone(),
            sub_state: long.clone(),
            description: long,
            ..unit("a.service", UnitActiveState::Active, "running", None)
        }]));
        let unit = &delta.added[0];
        assert!(unit.name.len() <= MAX_FIELD_BYTES);
        assert!(unit.load_state.len() <= MAX_FIELD_BYTES);
        assert!(unit.sub_state.len() <= MAX_FIELD_BYTES);
        assert!(unit.description.len() <= MAX_DESCRIPTION_BYTES);
    }

    #[test]
    fn a_process_too_large_for_a_frame_resyncs_instead_of_leaving_a_silent_gap() {
        let mut state = CollectorState::new(ObserverDomain::Process);
        state.ingest(RawSample::Process(sample_with(1000, 800, vec![])));
        let procs = vec![proc(1, 1, 0, 0), proc_with_cmdline(2, "c".repeat(1024))];
        let out = state.ingest(RawSample::Process(sample_with(1100, 820, procs)));
        let (out_tx, mut out_rx) = mpsc::channel::<OutFrame>(64);
        let mut subs = vec![Subscriber {
            conn_id: 1,
            request_id: 1,
            out_tx,
            needs_resync: false,
        }];
        fanout(&mut subs, &out, &state, 7, 512);
        let first = out_rx.try_recv().expect("a frame");
        assert_eq!(
            first.action,
            fuz_wire::ids::OBSERVER_SNAPSHOT_FRAME,
            "the gap signal, not a delta missing a process"
        );
    }
}
