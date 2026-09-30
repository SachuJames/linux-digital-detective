//! Syslog parser (RFC 3164 style).
//!
//! Handles lines like:
//!
//! ```text
//! <34>Sep 30 14:02:11 web01 sshd[8123]: Failed password for root from 203.0.113.7 port 51234 ssh2
//! Sep 30 14:02:11 web01 kernel: [12345.678] usb 1-1: new device found
//! 2026-09-30T14:02:11+05:30 web01 systemd[1]: Started Daily apt upgrade.
//! ```
//!
//! The priority prefix is optional; ISO-8601 timestamps are accepted too.

use regex::Regex;
use std::sync::LazyLock;

use crate::events::{Event, EventType, Severity};
use crate::evidence::EvidenceKind;
use crate::evidence::SkipReason;
use crate::parsers::timestamps::{parse_at_start, ParsedTimestamp};
use crate::parsers::{ParseContext, ParsedLine, Parser};

pub struct SyslogParser;

/// Optional `<pri>` prefix, e.g. `<34>`.
static PRI_PREFIX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^<(?P<pri>\d{1,3})>\s*").unwrap());

/// What follows the timestamp: `host proc[pid]: message`.
static ENVELOPE_REST: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?x)
        ^\s*
        (?P<host>[A-Za-z0-9_.\-]+)
        \s+
        (?P<proc>[A-Za-z0-9_@.\-/]+?)(?:\[(?P<pid>\d+)\])?:
        \s?(?P<msg>.*)$",
    )
    .unwrap()
});

/// Envelope components shared with the auth parser.
#[derive(Debug)]
pub(crate) struct Envelope {
    pub priority: Option<u8>,
    pub parsed: ParsedTimestamp,
    pub host: String,
    pub proc_name: String,
    pub pid: Option<u32>,
    pub message: String,
}

/// Strip `<pri>`, timestamp, and `host proc[pid]:` from a line.
///
/// Returns `None` when the line does not have the syslog envelope shape,
/// or `Some(Err(..))` when the timestamp portion is malformed.
pub(crate) fn strip_envelope(line: &str) -> Option<Result<Envelope, String>> {
    let mut rest = line;
    let mut priority = None;
    if let Some(caps) = PRI_PREFIX.captures(line) {
        priority = caps["pri"].parse::<u8>().ok();
        rest = &line[caps.get(0).unwrap().end()..];
    }
    let parsed = match parse_at_start(rest) {
        Some(Ok(p)) => p,
        Some(Err(e)) => return Some(Err(e)),
        None => return None,
    };
    let after = rest[parsed.consumed..].trim_start();
    let caps = ENVELOPE_REST.captures(after)?;
    Some(Ok(Envelope {
        priority,
        parsed,
        host: caps["host"].to_string(),
        proc_name: caps
            .name("proc")
            .map(|m| m.as_str())
            .unwrap_or("unknown")
            .to_string(),
        pid: caps
            .name("pid")
            .and_then(|m| m.as_str().parse::<u32>().ok()),
        message: caps
            .name("msg")
            .map(|m| m.as_str())
            .unwrap_or("")
            .to_string(),
    }))
}

impl Parser for SyslogParser {
    fn name(&self) -> &'static str {
        "syslog"
    }

    fn description(&self) -> &'static str {
        "RFC 3164 style syslog lines with optional priority prefix"
    }

    fn sniff(&self, line: &str, kind: EvidenceKind) -> f32 {
        let mut score = 0.0f32;
        if let Some(Ok(_)) = strip_envelope(line) {
            score += 0.6;
        }
        match kind {
            EvidenceKind::Syslog | EvidenceKind::KernelLog => score += 0.2,
            EvidenceKind::Json | EvidenceKind::JsonLines | EvidenceKind::Stdin => {}
            _ => {}
        }
        score.min(1.0)
    }

    fn parse_line(&self, ctx: &ParseContext, line: &str) -> Option<ParsedLine> {
        let env = match strip_envelope(line)? {
            Ok(env) => env,
            Err(_) => return Some(ParsedLine::Skipped(SkipReason::MalformedTimestamp)),
        };
        let parsed = env.parsed;

        let mut b = Event::builder(
            ctx.event_id,
            parsed.dt,
            self.name(),
            ctx.label(),
            ctx.line_no,
        )
        .precision(parsed.precision)
        .partial_timestamp(parsed.partial)
        .raw_timestamp(parsed.raw.clone())
        .offset_explicit(parsed.offset_explicit)
        .hostname(env.host)
        .process_name(env.proc_name.clone())
        .message(env.message.clone())
        .confidence(0.8);

        if let Some(pid) = env.pid {
            b = b.pid(pid);
        }
        if let Some(pri) = env.priority {
            b = b.severity(Severity::from_syslog_priority(pri & 0x07));
        } else {
            b = b.severity(Severity::Info);
        }

        // Coarse classification by process name; the auth parser handles
        // the auth-specific semantics when it claims the file.
        let lower = env.proc_name.to_ascii_lowercase();
        let event_type = if lower == "kernel" {
            EventType::Kernel
        } else if ["systemd", "cron", "crond", "init"].contains(&lower.as_str()) {
            EventType::Service
        } else {
            EventType::System
        };
        let event = b.event_type(event_type).build();
        Some(ParsedLine::Event(event))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::Evidence;
    use std::path::PathBuf;

    fn ctx<'a>(ev: &'a Evidence) -> ParseContext<'a> {
        ParseContext::new(ev, 1, 1)
    }

    fn ev() -> Evidence {
        Evidence {
            path: PathBuf::from("syslog"),
            label: "syslog".into(),
            kind: EvidenceKind::Syslog,
            is_stdin: false,
        }
    }

    #[test]
    fn parses_classic_syslog_line() {
        let e = ev();
        let p = SyslogParser;
        let line = "Sep 30 14:02:11 web01 sshd[8123]: Failed password for root";
        match p.parse_line(&ctx(&e), line) {
            Some(ParsedLine::Event(ev)) => {
                assert_eq!(ev.process_name.as_deref(), Some("sshd"));
                assert_eq!(ev.pid, Some(8123));
                assert_eq!(ev.hostname.as_deref(), Some("web01"));
                assert!(ev.partial_timestamp); // no year in syslog
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn parses_priority_prefix_and_maps_severity() {
        let e = ev();
        let p = SyslogParser;
        // <34> = facility 4 (auth), severity 2 (critical)
        let line = "<34>Sep 30 14:02:11 web01 sshd[1]: x";
        match p.parse_line(&ctx(&e), line) {
            Some(ParsedLine::Event(ev)) => assert_eq!(ev.severity, Severity::Critical),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn rejects_non_syslog_lines() {
        let e = ev();
        let p = SyslogParser;
        assert!(p.parse_line(&ctx(&e), "hello world").is_none());
    }
}
