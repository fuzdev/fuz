//! Process-domain acquisition — user-scoped `/proc` reading.
//!
//! `/proc` is read with `std::fs` only — no `procfs` crate, and no
//! `libc::sysconf` (unsafe is forbidden): per-proc memory comes from `VmRSS`,
//! CPU % from tick *ratios* (the `CLK_TCK` unit cancels), so neither page size
//! nor clock tick is needed. Acquisition is raw and stateless — counters out,
//! rates derived by the collector. The
//! [`ObserverSource`](super::source::ObserverSource) seam (and its user-scoped
//! v1 impl) lives in [`super::source`].

use std::fs;
use std::io::Read;

use super::bounds::{MAX_CMDLINE_BYTES, cap_text, cut_text};
use super::source::ObserverError;

/// Raw machine-wide counters for one sample (rates derived by the collector).
#[derive(Debug, Clone)]
pub struct RawSystem {
    pub ncpu: u32,
    /// Sum of all fields on the `/proc/stat` `cpu` aggregate line (ticks).
    pub total_cpu_ticks: u64,
    /// Idle + iowait ticks (the non-busy portion of `total_cpu_ticks`).
    pub idle_cpu_ticks: u64,
    pub mem_total_bytes: u64,
    pub mem_available_bytes: u64,
    pub load_1: f32,
    pub load_5: f32,
    pub load_15: f32,
    pub uptime_secs: u64,
}

/// Raw per-process counters for one sample.
#[derive(Debug, Clone)]
pub struct RawProc {
    pub pid: i32,
    pub start_time: u64,
    pub ppid: i32,
    pub name: String,
    pub state: char,
    /// `utime + stime` from `/proc/<pid>/stat` (ticks).
    pub cpu_ticks: u64,
    /// `VmRSS` from `/proc/<pid>/status`, in bytes.
    pub mem_bytes: u64,
    pub cmdline: Option<String>,
}

/// One raw sample of the process domain.
#[derive(Debug, Clone)]
pub struct RawProcessSample {
    pub system: RawSystem,
    pub procs: Vec<RawProc>,
}

/// Sample the process domain (user scope).
///
/// # Errors
///
/// Returns [`ObserverError`] only on whole-sample failure (e.g. `/proc/stat`
/// unreadable); vanished processes are silently skipped.
pub fn sample_process() -> Result<RawProcessSample, ObserverError> {
    let stat = fs::read_to_string("/proc/stat").map_err(|source| ObserverError::Read {
        path: "/proc/stat",
        source,
    })?;
    let (total_cpu_ticks, idle_cpu_ticks, ncpu) = parse_proc_stat(&stat);

    let meminfo = fs::read_to_string("/proc/meminfo").map_err(|source| ObserverError::Read {
        path: "/proc/meminfo",
        source,
    })?;
    let (mem_total_bytes, mem_available_bytes) = parse_meminfo(&meminfo);

    // loadavg / uptime are best-effort niceties: default to zero rather
    // than failing the whole sample if they can't be read.
    let (load_1, load_5, load_15) = fs::read_to_string("/proc/loadavg")
        .ok()
        .and_then(|s| parse_loadavg(&s))
        .unwrap_or((0.0, 0.0, 0.0));
    let uptime_secs = fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|s| parse_uptime(&s))
        .unwrap_or(0);

    let system = RawSystem {
        ncpu,
        total_cpu_ticks,
        idle_cpu_ticks,
        mem_total_bytes,
        mem_available_bytes,
        load_1,
        load_5,
        load_15,
        uptime_secs,
    };

    let mut procs = Vec::new();
    let entries = fs::read_dir("/proc").map_err(|source| ObserverError::Read {
        path: "/proc",
        source,
    })?;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(pid) = name.to_str().and_then(|s| s.parse::<i32>().ok()) else {
            continue; // non-pid entries (e.g. /proc/stat)
        };
        if let Some(raw) = read_proc(pid) {
            procs.push(raw);
        }
        // A process that vanished between readdir and read is skipped.
    }

    Ok(RawProcessSample { system, procs })
}

/// Read one process's raw counters, or `None` if it vanished / its stat is
/// unparseable.
fn read_proc(pid: i32) -> Option<RawProc> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let parsed = parse_stat(&stat)?;
    let mem_bytes = fs::read_to_string(format!("/proc/{pid}/status"))
        .ok()
        .map_or(0, |s| parse_vmrss_bytes(&s));
    let cmdline = read_cmdline(pid);
    Some(RawProc {
        pid,
        start_time: parsed.start_time,
        ppid: parsed.ppid,
        name: parsed.comm,
        state: parsed.state,
        cpu_ticks: parsed.cpu_ticks,
        mem_bytes,
        cmdline,
    })
}

/// Read + flatten `/proc/<pid>/cmdline` (NUL-separated argv) to a
/// space-joined string. `None` for kernel threads (empty cmdline) or when
/// unreadable.
///
/// Any local user's argument vector is readable here and as long as its owner
/// made it, so the read stops past [`MAX_CMDLINE_BYTES`]: a longer one is
/// reported cut to that bound, ending in the cut marker ([`super::bounds`]).
fn read_cmdline(pid: i32) -> Option<String> {
    let file = fs::File::open(format!("/proc/{pid}/cmdline")).ok()?;
    let mut raw = Vec::new();
    // The bound, the argument vector's trailing NUL, and one byte to tell a
    // longer one apart.
    file.take(MAX_CMDLINE_BYTES as u64 + 2)
        .read_to_end(&mut raw)
        .ok()?;
    flatten_cmdline(&raw)
}

/// Flatten a raw cmdline read of at most `MAX_CMDLINE_BYTES + 2` bytes. Its one
/// trailing NUL, the argument vector's terminator, does not count: a read still
/// longer than the bound was stopped short, so its text is marked as cut.
fn flatten_cmdline(raw: &[u8]) -> Option<String> {
    let raw = raw.strip_suffix(&[0]).unwrap_or(raw);
    let cut = raw.len() > MAX_CMDLINE_BYTES;
    let raw = &raw[..raw.len().min(MAX_CMDLINE_BYTES)];
    let mut joined = raw
        .split(|&b| b == 0)
        .filter(|seg| !seg.is_empty())
        .map(String::from_utf8_lossy)
        .collect::<Vec<_>>()
        .join(" ");
    if joined.is_empty() {
        return None;
    }
    // Lossy decoding can lengthen the text (a stray byte becomes U+FFFD).
    if cut {
        cut_text(&mut joined, MAX_CMDLINE_BYTES);
    } else {
        cap_text(&mut joined, MAX_CMDLINE_BYTES);
    }
    Some(joined)
}

/// Fields extracted from `/proc/<pid>/stat`.
#[derive(Debug, PartialEq, Eq)]
struct ParsedStat {
    ppid: i32,
    state: char,
    comm: String,
    cpu_ticks: u64,
    start_time: u64,
}

/// Parse `/proc/<pid>/stat`, defending against `comm` (field 2) containing
/// spaces and parentheses — the classic `/proc` parsing footgun.
///
/// `comm` is wrapped in parens; everything after the **last** `)` is the
/// fixed space-separated tail starting at field 3 (`state`). So tail index
/// `i` is field `3 + i`: ppid (4) → `tail[1]`, utime (14) → `tail[11]`,
/// stime (15) → `tail[12]`, starttime (22) → `tail[19]`.
fn parse_stat(content: &str) -> Option<ParsedStat> {
    let open = content.find('(')?;
    let close = content.rfind(')')?;
    if close < open {
        return None;
    }
    let comm = content.get(open + 1..close)?.to_string();
    let tail: Vec<&str> = content.get(close + 1..)?.split_whitespace().collect();
    let state = tail.first()?.chars().next()?;
    let ppid = tail.get(1)?.parse().ok()?;
    let utime: u64 = tail.get(11)?.parse().ok()?;
    let stime: u64 = tail.get(12)?.parse().ok()?;
    let start_time: u64 = tail.get(19)?.parse().ok()?;
    Some(ParsedStat {
        ppid,
        state,
        comm,
        cpu_ticks: utime.saturating_add(stime),
        start_time,
    })
}

/// Parse `VmRSS` (kB) from `/proc/<pid>/status` into bytes. `0` for kernel
/// threads (no `VmRSS` line).
fn parse_vmrss_bytes(status: &str) -> u64 {
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:")
            && let Some(kb) = rest
                .split_whitespace()
                .next()
                .and_then(|s| s.parse::<u64>().ok())
        {
            return kb.saturating_mul(1024);
        }
    }
    0
}

/// Parse the `/proc/stat` aggregate `cpu` line + count online CPUs.
/// Returns `(total_ticks, idle_ticks, ncpu)`.
fn parse_proc_stat(content: &str) -> (u64, u64, u32) {
    let mut total = 0;
    let mut idle = 0;
    let mut ncpu = 0u32;
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("cpu ") {
            // user nice system idle iowait irq softirq steal guest guest_nice
            let fields: Vec<u64> = rest
                .split_whitespace()
                .filter_map(|x| x.parse().ok())
                .collect();
            total = fields.iter().sum();
            idle = fields.get(3).copied().unwrap_or(0) + fields.get(4).copied().unwrap_or(0);
        } else if let Some(rest) = line.strip_prefix("cpu")
            && rest.as_bytes().first().is_some_and(u8::is_ascii_digit)
        {
            ncpu += 1;
        }
    }
    (total, idle, ncpu.max(1))
}

/// Parse `MemTotal` / `MemAvailable` (kB) from `/proc/meminfo` into bytes.
fn parse_meminfo(content: &str) -> (u64, u64) {
    let mut total = 0;
    let mut available = 0;
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            total = parse_kb_bytes(rest);
        } else if let Some(rest) = line.strip_prefix("MemAvailable:") {
            available = parse_kb_bytes(rest);
        }
    }
    (total, available)
}

/// Parse a leading `"   1234 kB"` value (kB) into bytes.
fn parse_kb_bytes(rest: &str) -> u64 {
    rest.split_whitespace()
        .next()
        .and_then(|s| s.parse::<u64>().ok())
        .map_or(0, |kb| kb.saturating_mul(1024))
}

/// Parse the three load averages from `/proc/loadavg`.
fn parse_loadavg(content: &str) -> Option<(f32, f32, f32)> {
    let mut it = content.split_whitespace();
    let l1 = it.next()?.parse().ok()?;
    let l5 = it.next()?.parse().ok()?;
    let l15 = it.next()?.parse().ok()?;
    Some((l1, l5, l15))
}

/// Parse system uptime (seconds, truncated) from `/proc/uptime`.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn parse_uptime(content: &str) -> Option<u64> {
    let secs: f64 = content.split_whitespace().next()?.parse().ok()?;
    Some(secs as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_short_cmdline_is_flattened_whole() {
        assert_eq!(
            flatten_cmdline(b"/bin/sh\0-c\0echo hi\0").as_deref(),
            Some("/bin/sh -c echo hi")
        );
        assert_eq!(flatten_cmdline(b""), None, "a kernel thread has none");
        assert_eq!(flatten_cmdline(b"\0\0"), None);
    }

    #[test]
    fn a_cmdline_past_the_bound_is_cut_and_marked() {
        // What a read capped at one byte past the bound returns for a longer one.
        let raw = vec![b'a'; MAX_CMDLINE_BYTES + 1];
        let text = flatten_cmdline(&raw).expect("text");
        assert!(text.len() <= MAX_CMDLINE_BYTES, "{}", text.len());
        assert!(text.ends_with(super::super::bounds::CUT_MARKER));
        // Exactly at the bound is whole, with the trailing NUL `/proc` gives
        // it as much as without.
        let raw = vec![b'a'; MAX_CMDLINE_BYTES];
        assert_eq!(
            flatten_cmdline(&raw).expect("text"),
            "a".repeat(MAX_CMDLINE_BYTES)
        );
        let mut raw = vec![b'a'; MAX_CMDLINE_BYTES];
        raw.push(0);
        assert_eq!(
            flatten_cmdline(&raw).expect("text"),
            "a".repeat(MAX_CMDLINE_BYTES),
            "a 4096-byte argument vector and its terminator are not cut"
        );
        // One byte more, terminator included, is cut.
        let mut raw = vec![b'a'; MAX_CMDLINE_BYTES + 1];
        raw.push(0);
        assert!(
            flatten_cmdline(&raw)
                .expect("text")
                .ends_with(super::super::bounds::CUT_MARKER)
        );
    }

    #[test]
    fn lossy_decoding_stays_within_the_bound() {
        // Every byte invalid UTF-8: each becomes a three-byte U+FFFD.
        let raw = vec![0xff; MAX_CMDLINE_BYTES];
        let text = flatten_cmdline(&raw).expect("text");
        assert!(text.len() <= MAX_CMDLINE_BYTES, "{}", text.len());
    }

    #[test]
    fn parse_stat_handles_comm_with_spaces_and_parens() {
        // comm = "a (weird) name" — spaces AND nested parens inside field 2.
        // tail after the last ')': state ppid pgrp ... starttime ...
        // field:  3   4    5     6  7  8 9 10 11 12 13 14 15 ...      22
        let line =
            "1234 (a (weird) name) S 1 1234 1234 0 -1 4194560 100 0 0 0 7 8 0 0 20 0 1 0 99999 ...";
        let p = parse_stat(line).expect("should parse");
        assert_eq!(p.comm, "a (weird) name");
        assert_eq!(p.state, 'S');
        assert_eq!(p.ppid, 1);
        // utime=7 (field14, tail[11]) + stime=8 (field15, tail[12]) = 15
        assert_eq!(p.cpu_ticks, 15);
        // starttime=99999 (field22, tail[19])
        assert_eq!(p.start_time, 99_999);
    }

    #[test]
    fn parse_stat_simple_comm() {
        let line = "1 (systemd) S 0 1 1 0 -1 4194304 200 0 0 0 11 22 0 0 20 0 1 0 42 ...";
        let p = parse_stat(line).expect("should parse");
        assert_eq!(p.comm, "systemd");
        assert_eq!(p.ppid, 0);
        assert_eq!(p.cpu_ticks, 33);
        assert_eq!(p.start_time, 42);
    }

    #[test]
    fn parse_stat_rejects_garbage() {
        assert!(parse_stat("not a stat line").is_none());
        assert!(parse_stat("1234 no-close-paren S 1").is_none());
    }

    #[test]
    fn vmrss_parses_kb_to_bytes() {
        let status = "Name:\tbash\nState:\tS\nVmRSS:\t   2048 kB\nThreads:\t1\n";
        assert_eq!(parse_vmrss_bytes(status), 2048 * 1024);
    }

    #[test]
    fn vmrss_absent_is_zero() {
        // Kernel threads have no VmRSS line.
        assert_eq!(parse_vmrss_bytes("Name:\tkworker\nState:\tI\n"), 0);
    }

    #[test]
    fn proc_stat_aggregate_and_ncpu() {
        let content = "cpu  100 0 50 1000 30 0 0 0 0 0\ncpu0 50 0 25 500 15 0 0 0 0 0\ncpu1 50 0 25 500 15 0 0 0 0 0\nintr 123\n";
        let (total, idle, ncpu) = parse_proc_stat(content);
        assert_eq!(total, 100 + 50 + 1000 + 30); // user+system+idle+iowait
        assert_eq!(idle, 1000 + 30); // idle + iowait
        assert_eq!(ncpu, 2);
    }

    #[test]
    fn proc_stat_defaults_ncpu_to_one() {
        let (_, _, ncpu) = parse_proc_stat("cpu  1 2 3 4 5 6 7 8 9 10\n");
        assert_eq!(ncpu, 1);
    }

    #[test]
    fn meminfo_parses_total_and_available() {
        let content =
            "MemTotal:       16384 kB\nMemFree:         1000 kB\nMemAvailable:    8192 kB\n";
        let (total, available) = parse_meminfo(content);
        assert_eq!(total, 16384 * 1024);
        assert_eq!(available, 8192 * 1024);
    }

    #[test]
    fn loadavg_parses_three() {
        let (l1, l5, l15) = parse_loadavg("0.50 1.25 2.00 1/234 5678").expect("parse");
        assert!((l1 - 0.50).abs() < f32::EPSILON);
        assert!((l5 - 1.25).abs() < f32::EPSILON);
        assert!((l15 - 2.00).abs() < f32::EPSILON);
    }

    #[test]
    fn uptime_truncates_to_secs() {
        assert_eq!(parse_uptime("12345.67 9999.00"), Some(12345));
    }

    #[test]
    fn proc_source_samples_the_live_machine() {
        // Smoke test against the real /proc on the test host: there is
        // always at least one process (this test), and total CPU ticks
        // advance from boot.
        let sample = sample_process().expect("sample /proc");
        assert!(
            !sample.procs.is_empty(),
            "should see at least our own process"
        );
        assert!(sample.system.ncpu >= 1);
        assert!(sample.system.mem_total_bytes > 0);
    }
}
