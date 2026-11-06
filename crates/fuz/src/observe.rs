//! `fuz workload observe <domain> [--follow]` — a terminal view of fuzd's
//! observer workloads.
//!
//! A real consumer of the same shared collector other fuzd clients
//! subscribe to: it validates "sharing is the point" end-to-end and
//! gives a headless / debug view of live machine state without a browser.
//! One-shot prints a snapshot; `--follow` streams the live delta + event
//! heartbeat until interrupted.
//!
//! Every string a frame carries was chosen by someone else — another user's
//! process name and command line, a unit's name, an address — so each is
//! printed through [`cell`]: escaped (`fuz_sys::text::escape_untrusted`) and
//! cut to its column, never raw.

use std::fmt::Write as _;
use std::io::Write as _;

use argh::FromArgs;
use fuz_client::{ObserverFrame, observe_subscribe};
use fuz_sys::text::escape_untrusted;
use fuz_wire::{
    ConnectionEvent, ConnectionInfo, NetworkDelta, NetworkSnapshot, ObserverDelta, ObserverDomain,
    ObserverEvent, ObserverSnapshot, ProcessDelta, ProcessEvent, ProcessInfo, ProcessSnapshot,
    ServiceEvent, ServiceUnit, ServicesDelta, ServicesSnapshot, SystemResources,
};

use crate::error::CliError;

/// Observe live machine state: processes, network, or services.
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "observe")]
pub struct Observe {
    /// domain to observe: `process`, `network`, or `services`
    #[argh(positional)]
    pub domain: String,

    /// keep streaming live updates until interrupted (Ctrl-C)
    #[argh(switch)]
    pub follow: bool,
}

/// Processes shown in the snapshot table (busiest first).
const TOP_N: usize = 30;

/// Width the command column is cut to.
const CMD_WIDTH: usize = 60;

/// Width an address is cut to in the connection table.
const ADDR_WIDTH: usize = 22;

/// Width an address is cut to in an event line (an IPv6 address and port fit).
const EVENT_ADDR_WIDTH: usize = 48;

/// Width a unit name is cut to.
const UNIT_WIDTH: usize = 60;

/// Width a unit's sub-state is cut to.
const SUB_STATE_WIDTH: usize = 10;

/// Width an interface name is cut to in the throughput summary.
const IFACE_WIDTH: usize = 16;

/// Run `fuz workload observe`.
///
/// # Errors
///
/// Returns [`CliError::UnknownObserverDomain`] for an unknown domain, or a
/// [`CliError::Client`] (with an actionable hint) when fuzd isn't running.
pub async fn cmd_observe(args: Observe) -> Result<(), CliError> {
    let domain = parse_domain(&args.domain)?;
    let follow = args.follow;
    observe_subscribe(domain, follow, move |frame| {
        if let Some(text) = render(&frame, follow) {
            print_or_exit(&text);
        }
    })
    .await?;
    Ok(())
}

/// Write rendered output to stdout. A streaming observe is meant to be piped
/// (`fuz workload observe process | head`); when the downstream consumer closes the
/// pipe we exit cleanly rather than letting `println!` panic on `EPIPE`
/// (Rust ignores `SIGPIPE`, and resetting it needs `unsafe`).
fn print_or_exit(text: &str) {
    let mut out = std::io::stdout().lock();
    if out
        .write_all(text.as_bytes())
        .and_then(|()| out.flush())
        .is_err()
    {
        std::process::exit(0);
    }
}

fn parse_domain(raw: &str) -> Result<ObserverDomain, CliError> {
    match raw {
        "process" | "processes" | "proc" => Ok(ObserverDomain::Process),
        "network" | "net" | "connections" | "conns" => Ok(ObserverDomain::Network),
        "services" | "service" | "svc" | "units" => Ok(ObserverDomain::Services),
        _ => Err(CliError::UnknownObserverDomain {
            domain: raw.to_string(),
        }),
    }
}

/// Render a frame to a printable block, or `None` when there's nothing to
/// show (deltas/events outside `--follow`).
fn render(frame: &ObserverFrame, follow: bool) -> Option<String> {
    match frame {
        ObserverFrame::Snapshot { snapshot, .. } => Some(render_snapshot(snapshot)),
        ObserverFrame::Delta(delta) => follow.then(|| render_delta_line(delta)),
        ObserverFrame::Events(events) if follow => {
            let mut out = String::new();
            for event in events {
                render_event(&mut out, event);
            }
            (!out.is_empty()).then_some(out)
        }
        ObserverFrame::Events(_) => None,
    }
}

/// Render any domain's snapshot.
fn render_snapshot(snapshot: &ObserverSnapshot) -> String {
    match snapshot {
        ObserverSnapshot::Process(s) => render_process_snapshot(s),
        ObserverSnapshot::Network(s) => render_network_snapshot(s),
        ObserverSnapshot::Services(s) => render_services_snapshot(s),
    }
}

/// Render any domain's `--follow` delta heartbeat line.
fn render_delta_line(delta: &ObserverDelta) -> String {
    match delta {
        ObserverDelta::Process(d) => render_process_delta_line(d),
        ObserverDelta::Network(d) => render_network_delta_line(d),
        ObserverDelta::Services(d) => render_services_delta_line(d),
    }
}

/// Render any domain's discrete event line.
fn render_event(out: &mut String, event: &ObserverEvent) {
    match event {
        ObserverEvent::Process(e) => render_process_event(out, e),
        ObserverEvent::Network(e) => render_network_event(out, e),
        ObserverEvent::Services(e) => render_services_event(out, e),
    }
}

fn render_process_snapshot(snapshot: &ProcessSnapshot) -> String {
    let mut out = String::new();
    render_system_line(&mut out, &snapshot.system, snapshot.processes.len());
    let _ = writeln!(
        out,
        "{:>7}  {:>6}  {:>6}  {:>10}  {:>1}  COMMAND",
        "PID", "PPID", "CPU%", "MEM", "S"
    );
    let mut procs: Vec<&ProcessInfo> = snapshot.processes.iter().collect();
    // Busiest first, then by memory.
    procs.sort_by(|a, b| {
        b.cpu_pct
            .total_cmp(&a.cpu_pct)
            .then(b.mem_bytes.cmp(&a.mem_bytes))
    });
    for proc in procs.into_iter().take(TOP_N) {
        let command = proc.cmdline.as_deref().unwrap_or(&proc.name);
        let _ = writeln!(
            out,
            "{:>7}  {:>6}  {:>6.1}  {:>10}  {:>1}  {}",
            proc.key.pid,
            proc.ppid,
            proc.cpu_pct,
            format_bytes(proc.mem_bytes),
            proc.state,
            cell(command, CMD_WIDTH),
        );
    }
    out
}

fn render_system_line(out: &mut String, system: &SystemResources, process_count: usize) {
    let used = system
        .mem_total_bytes
        .saturating_sub(system.mem_available_bytes);
    let _ = writeln!(
        out,
        "machine — {} cpu · {:.1}% busy · mem {}/{} · load {:.2} {:.2} {:.2} · up {} · {} procs",
        system.ncpu,
        system.cpu_pct,
        format_bytes(used),
        format_bytes(system.mem_total_bytes),
        system.load_1,
        system.load_5,
        system.load_15,
        format_uptime(system.uptime_secs),
        process_count,
    );
}

fn render_process_delta_line(delta: &ProcessDelta) -> String {
    let system = &delta.system;
    let used = system
        .mem_total_bytes
        .saturating_sub(system.mem_available_bytes);
    let mut out = String::new();
    let _ = writeln!(
        out,
        "[live] cpu {:.1}% · mem {}/{} · +{} ~{} -{}",
        system.cpu_pct,
        format_bytes(used),
        format_bytes(system.mem_total_bytes),
        delta.added.len(),
        delta.changed.len(),
        delta.removed.len(),
    );
    out
}

fn render_process_event(out: &mut String, event: &ProcessEvent) {
    match event {
        ProcessEvent::Spawn {
            key, name, cmdline, ..
        } => {
            let command = cmdline.as_deref().unwrap_or(name);
            let _ = writeln!(
                out,
                "  + spawn pid {:<7} {}",
                key.pid,
                cell(command, CMD_WIDTH)
            );
        }
        ProcessEvent::Exit { key, name } => {
            let _ = writeln!(
                out,
                "  - exit  pid {:<7} {}",
                key.pid,
                cell(name, CMD_WIDTH)
            );
        }
    }
}

//
// Network domain
//

fn render_network_snapshot(snapshot: &NetworkSnapshot) -> String {
    let mut out = String::new();
    let mut ifaces: Vec<&_> = snapshot.interfaces.iter().collect();
    ifaces.sort_by(|a, b| (b.rx_bps + b.tx_bps).total_cmp(&(a.rx_bps + a.tx_bps)));
    let summary = ifaces
        .iter()
        .filter(|i| i.rx_bps + i.tx_bps > 0.0)
        .take(4)
        .map(|i| {
            format!(
                "{} ↓{}/s ↑{}/s",
                cell(&i.name, IFACE_WIDTH),
                format_bps(i.rx_bps),
                format_bps(i.tx_bps)
            )
        })
        .collect::<Vec<_>>()
        .join("  ·  ");
    let _ = writeln!(
        out,
        "network — {} connections · {} interfaces{}",
        snapshot.connections.len(),
        snapshot.interfaces.len(),
        if summary.is_empty() {
            String::new()
        } else {
            format!(" · {summary}")
        },
    );
    let _ = writeln!(
        out,
        "{:<6}  {:>7}  {:<22}  {:<22}  {:<11}  PID",
        "PROTO", "INODE", "LOCAL", "PEER", "STATE"
    );
    let mut conns: Vec<&ConnectionInfo> = snapshot.connections.iter().collect();
    // Owned (pid-resolved) first, then by inode for stability.
    conns.sort_by(|a, b| {
        b.pid
            .is_some()
            .cmp(&a.pid.is_some())
            .then(a.key.inode.cmp(&b.key.inode))
    });
    for conn in conns.into_iter().take(TOP_N) {
        let _ = writeln!(
            out,
            "{:<6}  {:>7}  {:<22}  {:<22}  {:<11}  {}",
            conn.protocol.label(),
            conn.key.inode,
            cell(&conn.local_addr, ADDR_WIDTH),
            cell(&conn.peer_addr, ADDR_WIDTH),
            format!("{:?}", conn.state),
            conn.pid.map_or_else(|| "-".to_string(), |p| p.to_string()),
        );
    }
    out
}

fn render_network_delta_line(delta: &NetworkDelta) -> String {
    let (rx, tx) = delta
        .interfaces
        .iter()
        .fold((0.0, 0.0), |(rx, tx), i| (rx + i.rx_bps, tx + i.tx_bps));
    let mut out = String::new();
    let _ = writeln!(
        out,
        "[live] ↓{}/s ↑{}/s · conns +{} ~{} -{}",
        format_bps(rx),
        format_bps(tx),
        delta.added.len(),
        delta.changed.len(),
        delta.removed.len(),
    );
    out
}

fn render_network_event(out: &mut String, event: &ConnectionEvent) {
    match event {
        ConnectionEvent::Open {
            protocol,
            local_addr,
            peer_addr,
            pid,
            ..
        } => {
            let owner = pid.map_or_else(String::new, |p| format!(" (pid {p})"));
            let _ = writeln!(
                out,
                "  + open  {} {} → {}{}",
                protocol.label(),
                cell(local_addr, EVENT_ADDR_WIDTH),
                cell(peer_addr, EVENT_ADDR_WIDTH),
                owner
            );
        }
        ConnectionEvent::Close { key, peer_addr } => {
            let _ = writeln!(
                out,
                "  - close inode {} → {}",
                key.inode,
                cell(peer_addr, EVENT_ADDR_WIDTH)
            );
        }
    }
}

//
// Services domain
//

fn render_services_snapshot(snapshot: &ServicesSnapshot) -> String {
    let mut out = String::new();
    let active = snapshot
        .units
        .iter()
        .filter(|u| u.main_pid.is_some())
        .count();
    let _ = writeln!(
        out,
        "services — {} units · {} with a live main process",
        snapshot.units.len(),
        active,
    );
    let _ = writeln!(out, "{:<10}  {:<10}  {:>7}  UNIT", "ACTIVE", "SUB", "PID");
    let mut units: Vec<&ServiceUnit> = snapshot.units.iter().collect();
    // Running units (with a pid) first, then by name.
    units.sort_by(|a, b| {
        b.main_pid
            .is_some()
            .cmp(&a.main_pid.is_some())
            .then(a.name.cmp(&b.name))
    });
    for unit in units.into_iter().take(TOP_N) {
        let _ = writeln!(
            out,
            "{:<10}  {:<10}  {:>7}  {}",
            format!("{:?}", unit.active_state),
            cell(&unit.sub_state, SUB_STATE_WIDTH),
            unit.main_pid
                .map_or_else(|| "-".to_string(), |p| p.to_string()),
            cell(&unit.name, UNIT_WIDTH),
        );
    }
    out
}

fn render_services_delta_line(delta: &ServicesDelta) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "[live] units +{} ~{} -{}",
        delta.added.len(),
        delta.changed.len(),
        delta.removed.len(),
    );
    out
}

fn render_services_event(out: &mut String, event: &ServiceEvent) {
    match event {
        ServiceEvent::Transition {
            name,
            active_state,
            sub_state,
            ..
        } => {
            let _ = writeln!(
                out,
                "  ~ {} → {active_state:?} ({})",
                cell(name, UNIT_WIDTH),
                cell(sub_state, SUB_STATE_WIDTH)
            );
        }
        ServiceEvent::Removed { name } => {
            let _ = writeln!(out, "  - removed {}", cell(name, UNIT_WIDTH));
        }
    }
}

/// Human-readable bytes-per-second.
#[allow(
    clippy::cast_precision_loss,
    reason = "display only; f32 throughput is already approximate"
)]
fn format_bps(bps: f32) -> String {
    const UNITS: [&str; 4] = ["B", "KiB", "MiB", "GiB"];
    if bps < 1024.0 {
        return format!("{bps:.0} B");
    }
    let mut value = bps;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.1} {}", UNITS[unit])
}

/// `text` from another process or the system, ready for a column: escaped by
/// `escape_untrusted` and cut to `width` characters, ending in `…` when cut.
///
/// The width counts the escaped form — what lands on the terminal — so a
/// value full of escapes keeps its column as plain text does, and the cut falls
/// between escapes, never inside one. Only as much of `text` as the column can
/// show is escaped.
fn cell(text: &str, width: usize) -> String {
    let mut pieces: Vec<String> = Vec::new();
    let mut used = 0;
    let mut cut = false;
    let mut buf = [0u8; 4];
    for c in text.chars() {
        let piece = escape_untrusted(c.encode_utf8(&mut buf));
        used += piece.chars().count();
        pieces.push(piece);
        if used > width {
            cut = true;
            break;
        }
    }
    if cut {
        // Room for the `…`.
        while used + 1 > width {
            let Some(piece) = pieces.pop() else { break };
            used -= piece.chars().count();
        }
        pieces.push("…".to_string());
    }
    pieces.concat()
}

/// Human-readable byte size (binary units).
#[allow(
    clippy::cast_precision_loss,
    reason = "display only; f64 mantissa covers realistic memory sizes"
)]
fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.1} {}", UNITS[unit])
}

/// Compact uptime like `3d 4h`, `4h 5m`, `5m`.
fn format_uptime(secs: u64) -> String {
    let days = secs / 86_400;
    let hours = (secs % 86_400) / 3_600;
    let mins = (secs % 3_600) / 60;
    if days > 0 {
        format!("{days}d {hours}h")
    } else if hours > 0 {
        format!("{hours}h {mins}m")
    } else {
        format!("{mins}m")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_domain_aliases() {
        assert!(matches!(
            parse_domain("process"),
            Ok(ObserverDomain::Process)
        ));
        assert!(matches!(parse_domain("proc"), Ok(ObserverDomain::Process)));
        assert!(matches!(
            parse_domain("network"),
            Ok(ObserverDomain::Network)
        ));
        assert!(matches!(parse_domain("net"), Ok(ObserverDomain::Network)));
        assert!(matches!(
            parse_domain("services"),
            Ok(ObserverDomain::Services)
        ));
        assert!(matches!(parse_domain("svc"), Ok(ObserverDomain::Services)));
        assert!(parse_domain("nonsense").is_err());
    }

    #[test]
    fn formats_bytes_in_binary_units() {
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(2048), "2.0 KiB");
        assert_eq!(format_bytes(5 * 1024 * 1024), "5.0 MiB");
    }

    #[test]
    fn formats_bps_in_binary_units() {
        assert_eq!(format_bps(512.0), "512 B");
        assert_eq!(format_bps(2048.0), "2.0 KiB");
        assert_eq!(format_bps(5.0 * 1024.0 * 1024.0), "5.0 MiB");
    }

    #[test]
    fn formats_uptime_buckets() {
        assert_eq!(format_uptime(90), "1m");
        assert_eq!(format_uptime(3_700), "1h 1m");
        assert_eq!(format_uptime(90_000), "1d 1h");
    }

    #[test]
    fn cell_is_char_safe() {
        assert_eq!(cell("short", 10), "short");
        assert_eq!(cell("0123456789", 5), "0123…");
        assert_eq!(cell("0123456789", 10), "0123456789");
        assert_eq!(cell("ééééé", 3), "éé…");
    }

    #[test]
    fn cell_counts_the_escaped_form_and_never_cuts_an_escape() {
        // `\u{1b}` is six characters on the terminal.
        assert_eq!(cell("\u{1b}", 6), "\\u{1b}");
        let cut = cell("ab\u{1b}cd", 6);
        assert_eq!(
            cut, "ab…",
            "the escape does not fit whole, so it is left out"
        );
        assert!(cut.chars().count() <= 6);
        let long = "\u{7}".repeat(100);
        let cut = cell(&long, CMD_WIDTH);
        assert!(cut.chars().count() <= CMD_WIDTH, "{cut}");
        assert!(cut.ends_with('…'));
        assert!(cut.trim_end_matches('…').split("\\u{7}").all(str::is_empty));
    }

    /// One string per field, carrying ESC (an OSC title and an SGR colour),
    /// BEL, a one-character CSI, a newline, and a bidi override.
    fn hostile(field: &str) -> String {
        format!("{field}\u{1b}]0;pwned\u{7}\u{1b}[31m\u{9b}2J\n\u{202e}x")
    }

    fn assert_no_raw_control(rendered: &str) {
        for line in rendered.lines() {
            assert!(
                !line.chars().any(fuz_sys::text::is_unprintable),
                "raw control or invisible character in {line:?}"
            );
        }
    }

    #[test]
    fn every_frame_renders_other_processes_text_escaped() {
        use fuz_wire::{
            ConnectionKey, InterfaceInfo, ProcessKey, SocketProtocol, SocketState, UnitActiveState,
        };
        let system = SystemResources {
            cpu_pct: 1.0,
            ncpu: 1,
            mem_total_bytes: 1,
            mem_available_bytes: 1,
            load_1: 0.0,
            load_5: 0.0,
            load_15: 0.0,
            uptime_secs: 1,
        };
        let key = ProcessKey {
            pid: 7,
            start_time: 1,
        };
        let process = ProcessInfo {
            key,
            ppid: 1,
            name: hostile("name"),
            state: 'S',
            cpu_pct: 0.0,
            mem_bytes: 0,
            cmdline: Some(hostile("cmdline")),
        };
        let nameless = ProcessInfo {
            key: ProcessKey {
                pid: 8,
                start_time: 1,
            },
            cmdline: None,
            ..process.clone()
        };
        let connection = ConnectionInfo {
            key: ConnectionKey { inode: 9 },
            protocol: SocketProtocol::Tcp,
            local_addr: hostile("local"),
            peer_addr: hostile("peer"),
            state: SocketState::Established,
            pid: Some(7),
        };
        let unit = ServiceUnit {
            name: hostile("unit"),
            load_state: hostile("load"),
            active_state: UnitActiveState::Active,
            sub_state: hostile("sub"),
            description: hostile("description"),
            main_pid: Some(7),
        };
        let frames = [
            ObserverFrame::Snapshot {
                workload_id: 1,
                snapshot: ObserverSnapshot::Process(ProcessSnapshot {
                    system,
                    processes: vec![process, nameless],
                }),
            },
            ObserverFrame::Snapshot {
                workload_id: 1,
                snapshot: ObserverSnapshot::Network(NetworkSnapshot {
                    interfaces: vec![InterfaceInfo {
                        name: hostile("iface"),
                        rx_bytes: 1,
                        tx_bytes: 1,
                        rx_bps: 10.0,
                        tx_bps: 10.0,
                    }],
                    connections: vec![connection],
                }),
            },
            ObserverFrame::Snapshot {
                workload_id: 1,
                snapshot: ObserverSnapshot::Services(ServicesSnapshot { units: vec![unit] }),
            },
            ObserverFrame::Events(vec![
                ObserverEvent::Process(ProcessEvent::Spawn {
                    key,
                    ppid: 1,
                    name: hostile("name"),
                    cmdline: Some(hostile("cmdline")),
                }),
                ObserverEvent::Process(ProcessEvent::Spawn {
                    key,
                    ppid: 1,
                    name: hostile("name"),
                    cmdline: None,
                }),
                ObserverEvent::Process(ProcessEvent::Exit {
                    key,
                    name: hostile("name"),
                }),
                ObserverEvent::Network(ConnectionEvent::Open {
                    key: ConnectionKey { inode: 9 },
                    protocol: SocketProtocol::Tcp,
                    local_addr: hostile("local"),
                    peer_addr: hostile("peer"),
                    pid: Some(7),
                }),
                ObserverEvent::Network(ConnectionEvent::Close {
                    key: ConnectionKey { inode: 9 },
                    peer_addr: hostile("peer"),
                }),
                ObserverEvent::Services(ServiceEvent::Transition {
                    name: hostile("unit"),
                    active_state: UnitActiveState::Active,
                    sub_state: hostile("sub"),
                    main_pid: Some(7),
                }),
                ObserverEvent::Services(ServiceEvent::Removed {
                    name: hostile("unit"),
                }),
            ]),
        ];
        for frame in &frames {
            let rendered = render(frame, true).expect("something to show");
            assert_no_raw_control(&rendered);
            assert!(
                rendered.contains("\\u{1b}"),
                "the escape is spelled out: {rendered}"
            );
        }
    }
}
