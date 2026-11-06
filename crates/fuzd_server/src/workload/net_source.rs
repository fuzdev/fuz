//! Network-domain acquisition — user-scoped `/proc/net` reading.
//!
//! Connections come from `/proc/net/{tcp,tcp6,udp,udp6}` (inode + 4-tuple +
//! state); the owning pid is resolved by matching each socket inode against
//! `/proc/<pid>/fd/*` symlinks (`socket:[<inode>]`). User scope means only our
//! own `/proc/<pid>/fd` is readable, so only our own sockets get a pid
//! cross-link — other connections (including world-readable listening ports)
//! show with `pid: None`, the documented v1 ceiling. Interface throughput comes
//! from `/proc/net/dev` (cumulative byte counters; the collector derives rates).
//!
//! Read with `std::fs` only — no `procfs`/`netlink` crate, no unsafe.

use std::collections::HashMap;
use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr};

use fuz_wire::SocketProtocol;

use super::source::ObserverError;

/// Raw per-interface counters for one sample (rates derived by the collector).
#[derive(Debug, Clone)]
pub struct RawInterface {
    pub name: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

/// Raw per-connection record for one sample (pid resolved post-parse).
#[derive(Debug, Clone)]
pub struct RawConnection {
    pub inode: u64,
    pub protocol: SocketProtocol,
    pub local_addr: String,
    pub peer_addr: String,
    /// `/proc/net/*` `st` hex code (mapped to `SocketState` by the collector).
    pub state_code: u8,
    /// Owning pid, resolved via `/proc/<pid>/fd` (user scope; `None` for
    /// sockets owned by processes this uid can't see).
    pub pid: Option<i32>,
}

/// One raw sample of the network domain.
#[derive(Debug, Clone)]
pub struct RawNetworkSample {
    pub interfaces: Vec<RawInterface>,
    pub connections: Vec<RawConnection>,
}

/// The protocol tables sampled, with their address width.
const TABLES: [(&str, SocketProtocol, bool); 4] = [
    ("/proc/net/tcp", SocketProtocol::Tcp, false),
    ("/proc/net/tcp6", SocketProtocol::Tcp6, true),
    ("/proc/net/udp", SocketProtocol::Udp, false),
    ("/proc/net/udp6", SocketProtocol::Udp6, true),
];

/// Sample the network domain (user scope).
///
/// # Errors
///
/// Returns [`ObserverError`] when `/proc/net/dev` is unreadable. A
/// missing/unreadable per-protocol socket table (e.g. IPv6 disabled) is skipped
/// rather than fatal, and the inode→pid map reads only what this uid can see.
pub fn sample_network() -> Result<RawNetworkSample, ObserverError> {
    let dev = fs::read_to_string("/proc/net/dev").map_err(|source| ObserverError::Read {
        path: "/proc/net/dev",
        source,
    })?;
    let interfaces = parse_proc_net_dev(&dev);

    let inode_pids = inode_to_pid_map();

    let mut connections = Vec::new();
    for (path, protocol, ipv6) in TABLES {
        let Ok(content) = fs::read_to_string(path) else {
            continue;
        };
        for mut conn in parse_proc_net_conns(&content, protocol, ipv6) {
            conn.pid = inode_pids.get(&conn.inode).copied();
            connections.push(conn);
        }
    }

    Ok(RawNetworkSample {
        interfaces,
        connections,
    })
}

/// Parse `/proc/net/dev` into per-interface cumulative byte counters.
///
/// Two header lines, then `  name: rxbytes rxpkts … txbytes txpkts …` — 8
/// receive columns then 8 transmit columns, so `rx_bytes` is column 0 and
/// `tx_bytes` is column 8.
fn parse_proc_net_dev(content: &str) -> Vec<RawInterface> {
    content
        .lines()
        .skip(2)
        .filter_map(|line| {
            let (name, rest) = line.split_once(':')?;
            let cols: Vec<&str> = rest.split_whitespace().collect();
            let rx_bytes = cols.first()?.parse().ok()?;
            let tx_bytes = cols.get(8)?.parse().ok()?;
            Some(RawInterface {
                name: name.trim().to_string(),
                rx_bytes,
                tx_bytes,
            })
        })
        .collect()
}

/// Parse one `/proc/net/{tcp,udp}{,6}` table (skipping the header line) into
/// raw connections (pid left `None` for the caller to resolve).
fn parse_proc_net_conns(content: &str, protocol: SocketProtocol, ipv6: bool) -> Vec<RawConnection> {
    content
        .lines()
        .skip(1)
        .filter_map(|line| parse_conn_line(line, protocol, ipv6))
        .collect()
}

/// Parse one socket-table row.
///
/// Whitespace columns: `0:sl 1:local 2:rem 3:st 4:tx:rx 5:tr:tm 6:retrnsmt
/// 7:uid 8:timeout 9:inode …`.
fn parse_conn_line(line: &str, protocol: SocketProtocol, ipv6: bool) -> Option<RawConnection> {
    let f: Vec<&str> = line.split_whitespace().collect();
    let local_addr = decode_addr(f.get(1)?, ipv6)?;
    let peer_addr = decode_addr(f.get(2)?, ipv6)?;
    let state_code = u8::from_str_radix(f.get(3)?, 16).ok()?;
    let inode = f.get(9)?.parse().ok()?;
    Some(RawConnection {
        inode,
        protocol,
        local_addr,
        peer_addr,
        state_code,
        pid: None,
    })
}

/// Decode a `/proc/net/*` `HEXADDR:HEXPORT` token to a displayable `ip:port`.
fn decode_addr(token: &str, ipv6: bool) -> Option<String> {
    let (addr_hex, port_hex) = token.split_once(':')?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    if ipv6 {
        let ip = decode_ipv6(addr_hex)?;
        Some(format!("[{ip}]:{port}"))
    } else {
        let ip = decode_ipv4(addr_hex)?;
        Some(format!("{ip}:{port}"))
    }
}

/// Decode an 8-hex-char little-endian IPv4 (`0100007F` → `127.0.0.1`).
fn decode_ipv4(hex: &str) -> Option<Ipv4Addr> {
    let b = hex_to_bytes::<4>(hex)?;
    // Stored little-endian: reverse the 4 bytes to network order.
    Some(Ipv4Addr::new(b[3], b[2], b[1], b[0]))
}

/// Decode a 32-hex-char IPv6 (four little-endian 32-bit words).
fn decode_ipv6(hex: &str) -> Option<Ipv6Addr> {
    let raw = hex_to_bytes::<16>(hex)?;
    let mut out = [0u8; 16];
    // Each 4-byte word is little-endian; reverse the bytes within the word.
    for word in 0..4 {
        for byte in 0..4 {
            out[word * 4 + byte] = raw[word * 4 + (3 - byte)];
        }
    }
    Some(Ipv6Addr::from(out))
}

/// Parse exactly `N` bytes from a hex string (big-endian char order).
fn hex_to_bytes<const N: usize>(hex: &str) -> Option<[u8; N]> {
    if hex.len() != N * 2 {
        return None;
    }
    let mut out = [0u8; N];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(hex.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

/// Build a socket-inode → owning-pid map by scanning `/proc/<pid>/fd`.
///
/// User scope: only our own pids' fd directories are readable; others yield
/// `EACCES` and are silently skipped (so their connections stay `pid: None`).
fn inode_to_pid_map() -> HashMap<u64, i32> {
    let mut map = HashMap::new();
    let Ok(entries) = fs::read_dir("/proc") else {
        return map;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(pid) = name.to_str().and_then(|s| s.parse::<i32>().ok()) else {
            continue;
        };
        let Ok(fds) = fs::read_dir(format!("/proc/{pid}/fd")) else {
            continue; // not ours / vanished — skip
        };
        for fd in fds.flatten() {
            if let Ok(target) = fs::read_link(fd.path())
                && let Some(inode) = parse_socket_inode(&target.to_string_lossy())
            {
                map.insert(inode, pid);
            }
        }
    }
    map
}

/// Extract the inode from a `socket:[12345]` fd symlink target.
fn parse_socket_inode(target: &str) -> Option<u64> {
    target
        .strip_prefix("socket:[")?
        .strip_suffix(']')?
        .parse()
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_ipv4_little_endian() {
        // 0100007F (LE) → 127.0.0.1; 00000000 → 0.0.0.0.
        assert_eq!(decode_ipv4("0100007F"), Some(Ipv4Addr::LOCALHOST));
        assert_eq!(decode_ipv4("00000000"), Some(Ipv4Addr::UNSPECIFIED));
        // 0101A8C0 (LE) → 192.168.1.1.
        assert_eq!(decode_ipv4("0101A8C0"), Some(Ipv4Addr::new(192, 168, 1, 1)));
    }

    #[test]
    fn decode_ipv6_word_reversed() {
        // postgres on [::1]:5432 from the real /proc/net/tcp6.
        let loopback = "00000000000000000000000001000000";
        assert_eq!(decode_ipv6(loopback), Some(Ipv6Addr::LOCALHOST));
        // all-zero → unspecified.
        let any = "00000000000000000000000000000000";
        assert_eq!(decode_ipv6(any), Some(Ipv6Addr::UNSPECIFIED));
    }

    #[test]
    fn decode_addr_formats_ip_and_port() {
        // 127.0.0.1:5432 (port 1538 hex).
        assert_eq!(
            decode_addr("0100007F:1538", false).as_deref(),
            Some("127.0.0.1:5432")
        );
        // ipv6 is bracketed; port 14EB = 5355.
        assert_eq!(
            decode_addr("00000000000000000000000001000000:14EB", true).as_deref(),
            Some("[::1]:5355")
        );
    }

    #[test]
    fn parse_conn_line_real_tcp_row() {
        // A real /proc/net/tcp data line: listener on 127.0.0.1:5432, state 0A
        // (LISTEN), inode 12201.
        let line = "   1: 0100007F:1538 00000000:0000 0A 00000000:00000000 00:00000000 00000000   105        0 12201 1 00000000e94c04b0 100 0 0 10 0";
        let conn = parse_conn_line(line, SocketProtocol::Tcp, false).expect("parse");
        assert_eq!(conn.inode, 12201);
        assert_eq!(conn.local_addr, "127.0.0.1:5432");
        assert_eq!(conn.peer_addr, "0.0.0.0:0");
        assert_eq!(conn.state_code, 0x0A);
        assert_eq!(conn.protocol, SocketProtocol::Tcp);
        assert!(conn.pid.is_none(), "pid is resolved post-parse");
    }

    #[test]
    fn parse_conn_line_rejects_short_row() {
        assert!(
            parse_conn_line(
                "  sl  local_address rem_address",
                SocketProtocol::Tcp,
                false
            )
            .is_none()
        );
    }

    #[test]
    fn parse_proc_net_dev_extracts_rx_tx_bytes() {
        // Two header lines then interfaces; rx = col 0, tx = col 8.
        let content = "Inter-|   Receive                                                |  Transmit\n \
            face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n    \
            lo: 277625718  299570    0    0    0     0          0         0 277625718  299570    0    0    0     0       0          0\n\
            wlp6s0: 592493086  824561    0    1    0     0          0         0 3091953849 2421598    0   16    0     0       0          0\n";
        let ifaces = parse_proc_net_dev(content);
        assert_eq!(ifaces.len(), 2);
        assert_eq!(ifaces[0].name, "lo");
        assert_eq!(ifaces[0].rx_bytes, 277_625_718);
        assert_eq!(ifaces[0].tx_bytes, 277_625_718);
        assert_eq!(ifaces[1].name, "wlp6s0");
        assert_eq!(ifaces[1].rx_bytes, 592_493_086);
        assert_eq!(ifaces[1].tx_bytes, 3_091_953_849);
    }

    #[test]
    fn socket_inode_parsed_from_fd_symlink() {
        assert_eq!(parse_socket_inode("socket:[8352]"), Some(8352));
        assert_eq!(parse_socket_inode("anon_inode:[eventpoll]"), None);
        assert_eq!(parse_socket_inode("/dev/null"), None);
    }

    #[test]
    fn net_source_samples_the_live_machine() {
        // Smoke test against the real /proc/net: there is always at least the
        // loopback interface.
        let sample = sample_network().expect("sample /proc/net");
        assert!(
            sample.interfaces.iter().any(|i| i.name == "lo"),
            "loopback interface is always present"
        );
    }
}
