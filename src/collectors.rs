//! Live local collection (read-only).
//!
//! Takes snapshots of local system state from `/proc` and `/proc/net` and
//! turns *changes* between snapshots into events. Nothing is modified,
//! no privileges are requested, and anything unreadable is reported as
//! unavailable rather than worked around.
//!
//! Snapshot cadence is driven by the `live` subcommand.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};

use chrono::{DateTime, FixedOffset, Local};

use crate::analysis::ProcessInfo;
use crate::errors::{Error, Result};
use crate::events::{Event, EventId, EventType, Severity, TimestampPrecision};
use crate::linux;

/// One observed socket.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SocketInfo {
    pub proto: String, // "tcp" / "udp"
    pub local: Option<(IpAddr, u16)>,
    pub remote: Option<(IpAddr, u16)>,
    pub state: String, // "LISTEN", "ESTABLISHED", ...
}

/// A point-in-time view of the local system.
#[derive(Debug, Clone)]
pub struct SystemSnapshot {
    pub at: DateTime<FixedOffset>,
    pub hostname: Option<String>,
    pub processes: Vec<ProcessInfo>,
    pub sockets: Vec<SocketInfo>,
    pub mem_total_kb: Option<u64>,
    pub mem_available_kb: Option<u64>,
}

/// What changed between two snapshots.
#[derive(Debug, Clone)]
pub enum SnapshotChange {
    ProcessCreated(ProcessInfo),
    ProcessExited { pid: u32, exe: String },
    SocketAppeared(SocketInfo),
    SocketDisappeared(SocketInfo),
}

/// Collect one snapshot. Never fails outright: individual unreadable
/// sources degrade to `None`/empty with no exception.
pub fn collect_snapshot() -> Result<SystemSnapshot> {
    let offset = FixedOffset::east_opt(Local::now().offset().local_minus_utc())
        .unwrap_or(FixedOffset::east_opt(0).unwrap());
    let at = Local::now().with_timezone(&offset);
    let mut processes = Vec::new();
    let proc_dir = std::fs::read_dir("/proc").map_err(|e| {
        Error::LinuxInterface(format!("cannot list /proc (are you on Linux?): {e}"))
    })?;
    for entry in proc_dir.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        if let Some(info) = read_process(entry.path().to_string_lossy().as_ref()) {
            processes.push(info);
        }
    }
    processes.sort_by_key(|p| p.pid);

    let mut sockets = Vec::new();
    for (path, proto) in [("/proc/net/tcp", "tcp"), ("/proc/net/udp", "udp")] {
        if let Ok(text) = linux::read_proc_file(path) {
            sockets.extend(parse_proc_net(&text, proto));
        }
    }
    // IPv6 tables are best-effort: addresses may not decode cleanly on all
    // kernels, so undecodable entries keep None addresses.
    for (path, proto) in [("/proc/net/tcp6", "tcp"), ("/proc/net/udp6", "udp")] {
        if let Ok(text) = linux::read_proc_file(path) {
            sockets.extend(parse_proc_net(&text, proto));
        }
    }

    let (mem_total_kb, mem_available_kb) = linux::read_proc_file("/proc/meminfo")
        .ok()
        .map(|t| parse_meminfo(&t))
        .unwrap_or((None, None));

    Ok(SystemSnapshot {
        at,
        hostname: linux::hostname(),
        processes,
        sockets,
        mem_total_kb,
        mem_available_kb,
    })
}

/// Diff two snapshots into a change list.
pub fn diff_snapshots(prev: &SystemSnapshot, next: &SystemSnapshot) -> Vec<SnapshotChange> {
    let mut out = Vec::new();
    let prev_pids: HashMap<u32, &ProcessInfo> =
        prev.processes.iter().map(|p| (p.pid, p)).collect();
    let next_pids: HashMap<u32, &ProcessInfo> =
        next.processes.iter().map(|p| (p.pid, p)).collect();

    for (pid, info) in &next_pids {
        if !prev_pids.contains_key(pid) {
            out.push(SnapshotChange::ProcessCreated((*info).clone()));
        }
    }
    for (pid, info) in &prev_pids {
        if !next_pids.contains_key(pid) {
            out.push(SnapshotChange::ProcessExited {
                pid: *pid,
                exe: info.exe.clone(),
            });
        }
    }
    let prev_socks: HashSet<&SocketInfo> = prev.sockets.iter().collect();
    let next_socks: HashSet<&SocketInfo> = next.sockets.iter().collect();
    for s in next_socks.difference(&prev_socks) {
        out.push(SnapshotChange::SocketAppeared((*s).clone()));
    }
    for s in prev_socks.difference(&next_socks) {
        out.push(SnapshotChange::SocketDisappeared((*s).clone()));
    }
    out
}

/// Turn a change into a normalized event for the timeline.
pub fn change_to_event(
    id: EventId,
    at: DateTime<FixedOffset>,
    change: &SnapshotChange,
    uid_names: &HashMap<u32, String>,
) -> Event {
    let mut b = Event::builder(id, at, "live", "<live>", 0)
        .precision(TimestampPrecision::Second)
        .event_type(EventType::Snapshot)
        .confidence(0.95);
    match change {
        SnapshotChange::ProcessCreated(p) => {
            b = b
                .subtype("process_created")
                .severity(Severity::Info)
                .pid(p.pid)
                .ppid(p.ppid)
                .process_name(short(&p.exe))
                .message(format!("process created: {} (pid {})", short(&p.exe), p.pid))
                .meta("exe", p.exe.clone())
                .meta("uid", p.uid.to_string())
                .meta("state", p.state.clone());
            if let Some(name) = uid_names.get(&p.uid) {
                b = b.user(name.clone());
            }
            if !p.cmdline.is_empty() {
                b = b.meta("cmdline", truncate(&p.cmdline, 512));
            }
        }
        SnapshotChange::ProcessExited { pid, exe } => {
            b = b
                .subtype("process_exited")
                .severity(Severity::Info)
                .pid(*pid)
                .process_name(short(exe))
                .message(format!("process exited: {} (pid {})", short(exe), pid))
                .meta("exe", exe.clone());
        }
        SnapshotChange::SocketAppeared(s) => {
            // An ESTABLISHED socket appearing is a connection observation,
            // which is what the network rules look for.
            let subtype = if s.state == "ESTABLISHED" {
                "connection_observed"
            } else {
                "socket_appeared"
            };
            b = b
                .subtype(subtype)
                .severity(Severity::Info)
                .event_type(EventType::Network)
                .message(format!("socket appeared: {}", describe_socket(s)));
            b = with_socket_fields(b, s);
        }
        SnapshotChange::SocketDisappeared(s) => {
            b = b
                .subtype("socket_disappeared")
                .severity(Severity::Info)
                .event_type(EventType::Network)
                .message(format!("socket disappeared: {}", describe_socket(s)));
            b = with_socket_fields(b, s);
        }
    }
    b.build()
}

/// Fill address/port fields and metadata from a socket observation.
fn with_socket_fields(
    mut b: crate::events::EventBuilder,
    s: &SocketInfo,
) -> crate::events::EventBuilder {
    b = b.meta("proto", s.proto.clone()).meta("state", s.state.clone());
    if let Some((ip, port)) = s.local {
        b = b.meta("local", format!("{ip}:{port}"));
    }
    if let Some((ip, port)) = s.remote {
        b = b.dst_addr(ip).port(port).meta("remote", format!("{ip}:{port}"));
    }
    b
}

fn describe_socket(s: &SocketInfo) -> String {
    let local = s
        .local
        .map(|(ip, p)| format!("{ip}:{p}"))
        .unwrap_or_else(|| "?".into());
    let remote = s
        .remote
        .map(|(ip, p)| format!("{ip}:{p}"))
        .unwrap_or_else(|| "?".into());
    format!("{} {} -> {} [{}]", s.proto, local, remote, s.state)
}

// --- /proc parsing -------------------------------------------------------

fn read_process(dir: &str) -> Option<ProcessInfo> {
    let stat = std::fs::read_to_string(format!("{dir}/stat")).ok()?;
    // comm is in parentheses and may itself contain parens: find the last ')'.
    let end = stat.rfind(')')?;
    let comm = stat[stat.find('(')? + 1..end].to_string();
    let after: Vec<&str> = stat[end + 1..].split_whitespace().collect();
    if after.len() < 22 {
        return None;
    }
    let pid: u32 = dir.rsplit('/').next()?.parse().ok()?;
    let state = after[0].to_string();
    let ppid: u32 = after[1].parse().ok()?;
    let rss_pages: u64 = after[21].parse().ok().unwrap_or(0);
    let rss_kb = rss_pages.checked_mul(4); // 4 KiB pages on virtually all Linux

    let uid = std::fs::read_to_string(format!("{dir}/status"))
        .ok()?
        .lines()
        .find(|l| l.starts_with("Uid:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|u| u.parse::<u32>().ok())
        .unwrap_or(u32::MAX);

    let exe = std::fs::read_link(format!("{dir}/exe"))
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| format!("[{comm}]"));
    let cmdline = std::fs::read(format!("{dir}/cmdline"))
        .ok()
        .map(|bytes| {
            let s = String::from_utf8_lossy(&bytes).replace('\0', " ");
            s.trim().to_string()
        })
        .unwrap_or_default();

    Some(ProcessInfo {
        pid,
        ppid,
        exe,
        cmdline,
        uid,
        state,
        rss_kb,
    })
}

pub(crate) fn uid_name_map() -> HashMap<u32, String> {
    let mut map = HashMap::new();
    if let Ok(text) = std::fs::read_to_string("/etc/passwd") {
        for line in text.lines() {
            let mut parts = line.split(':');
            let (Some(name), _, Some(uid)) =
                (parts.next(), parts.next(), parts.next())
            else {
                continue;
            };
            if let Ok(uid) = uid.parse::<u32>() {
                map.insert(uid, name.to_string());
            }
        }
    }
    map
}

fn parse_meminfo(text: &str) -> (Option<u64>, Option<u64>) {
    let mut total = None;
    let mut avail = None;
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        match parts.next() {
            Some("MemTotal:") => total = parts.next().and_then(|v| v.parse().ok()),
            Some("MemAvailable:") => avail = parts.next().and_then(|v| v.parse().ok()),
            _ => {}
        }
    }
    (total, avail)
}

/// Parse /proc/net/tcp style tables.
fn parse_proc_net(text: &str, proto: &str) -> Vec<SocketInfo> {
    let mut out = Vec::new();
    for line in text.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 4 {
            continue;
        }
        let local = parse_addr(f[1]).and_then(|(ip, p)| ip.map(|ip| (ip, p)));
        let remote = parse_addr(f[2]).and_then(|(ip, p)| ip.map(|ip| (ip, p)));
        let state = tcp_state(f[3]);
        out.push(SocketInfo {
            proto: proto.to_string(),
            local,
            remote,
            state: state.to_string(),
        });
    }
    out
}

fn parse_addr(hex: &str) -> Option<(Option<IpAddr>, u16)> {
    let (ip_hex, port_hex) = hex.split_once(':')?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    let ip = if ip_hex.len() == 8 {
        let raw = u32::from_str_radix(ip_hex, 16).ok()?;
        Some(IpAddr::V4(Ipv4Addr::from(raw.to_be())))
    } else if ip_hex.len() == 32 {
        // Best-effort: interpret as big-endian 16 bytes.
        let bytes = (0..16)
            .map(|i| u8::from_str_radix(&ip_hex[i * 2..i * 2 + 2], 16).ok())
            .collect::<Option<Vec<u8>>>()?;
        let mut arr = [0u8; 16];
        arr.copy_from_slice(&bytes);
        Some(IpAddr::V6(arr.into()))
    } else {
        None
    };
    Some((ip, port))
}

fn tcp_state(hex: &str) -> &'static str {
    match hex {
        "01" => "ESTABLISHED",
        "02" => "SYN_SENT",
        "03" => "SYN_RECV",
        "04" => "FIN_WAIT1",
        "05" => "FIN_WAIT2",
        "06" => "TIME_WAIT",
        "07" => "CLOSE",
        "08" => "CLOSE_WAIT",
        "09" => "LAST_ACK",
        "0A" => "LISTEN",
        "0B" => "CLOSING",
        _ => "UNKNOWN",
    }
}

fn short(exe: &str) -> String {
    exe.rsplit('/').next().unwrap_or(exe).to_string()
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_proc_net_tcp_line() {
        let text = "  sl  local_address rem_address   st\n   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 123 1 0000000000000000 100 0 0 10 0\n";
        let socks = parse_proc_net(text, "tcp");
        assert_eq!(socks.len(), 1);
        let s = &socks[0];
        assert_eq!(s.state, "LISTEN");
        // 0100007F little-endian u32 -> bytes 01 00 00 7F -> 127.0.0.1 after to_be
        assert_eq!(
            s.local,
            Some(("127.0.0.1".parse::<IpAddr>().unwrap(), 8080))
        );
    }

    #[test]
    fn diff_finds_created_and_exited_processes() {
        let mk = |pid: u32| ProcessInfo {
            pid,
            ppid: 1,
            exe: "/bin/x".into(),
            cmdline: String::new(),
            uid: 1000,
            state: "S".into(),
            rss_kb: None,
        };
        let at = Local::now().fixed_offset();
        let prev = SystemSnapshot {
            at,
            hostname: None,
            processes: vec![mk(1), mk(2)],
            sockets: vec![],
            mem_total_kb: None,
            mem_available_kb: None,
        };
        let next = SystemSnapshot {
            at,
            hostname: None,
            processes: vec![mk(1), mk(3)],
            sockets: vec![],
            mem_total_kb: None,
            mem_available_kb: None,
        };
        let changes = diff_snapshots(&prev, &next);
        assert!(changes.iter().any(|c| matches!(c, SnapshotChange::ProcessCreated(p) if p.pid == 3)));
        assert!(changes.iter().any(|c| matches!(c, SnapshotChange::ProcessExited { pid: 2, .. })));
    }

    #[test]
    fn change_to_event_carries_provenance() {
        let at = Local::now().fixed_offset();
        let p = ProcessInfo {
            pid: 42,
            ppid: 1,
            exe: "/usr/bin/python3".into(),
            cmdline: "python3 app.py".into(),
            uid: 1000,
            state: "R".into(),
            rss_kb: Some(1024),
        };
        let e = change_to_event(7, at, &SnapshotChange::ProcessCreated(p), &HashMap::new());
        assert_eq!(e.id, 7);
        assert_eq!(e.subtype.as_deref(), Some("process_created"));
        assert_eq!(e.pid, Some(42));
        assert_eq!(e.metadata.get("exe").map(|s| s.as_str()), Some("/usr/bin/python3"));
    }
}
