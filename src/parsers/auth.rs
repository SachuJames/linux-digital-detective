//! Authentication log parser.
//!
//! Handles sshd / login / pam / sudo lines, with or without a syslog
//! envelope. Examples:
//!
//! ```text
//! Sep 30 14:02:11 web01 sshd[8123]: Failed password for root from 203.0.113.7 port 51234 ssh2
//! Sep 30 14:02:20 web01 sshd[8123]: Accepted password for deploy from 203.0.113.7 port 51234 ssh2
//! Sep 30 14:02:25 web01 sudo: deploy : TTY=pts/0 ; COMMAND=/usr/bin/systemctl restart app
//! ```

use regex::Regex;
use std::net::IpAddr;
use std::sync::LazyLock;

use crate::events::{Event, EventType, Severity};
use crate::evidence::{EvidenceKind, SkipReason};
use crate::parsers::syslog::strip_envelope;
use crate::parsers::timestamps::{parse_at_start, ParsedTimestamp};
use crate::parsers::{ParseContext, ParsedLine, Parser};

pub struct AuthLogParser;

static FAILED_PASSWORD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"Failed password for (invalid user )?(\S+) from (\S+) port (\d+)").unwrap()
});
static ACCEPTED: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"Accepted (?:password|publickey) for (\S+) from (\S+) port (\d+)").unwrap()
});
static FAILED_LOGIN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)failed login|authentication failure|bad password").unwrap());
static SESSION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"session (opened|closed) for user (\S+)").unwrap()
});
static SUDO: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"sudo:\s+(\S+)\s*:.*COMMAND=(.+)").unwrap()
});
/// sudo body after the syslog envelope was stripped ("deploy : ... COMMAND=...").
static SUDO_STRIPPED: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(\S+)\s*:.*COMMAND=(.+)").unwrap());
static PAM_USER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"user=(\S+)").unwrap());

/// Markers that make a body look like auth material even without the envelope.
static AUTH_MARKERS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)sshd|Failed password|Accepted password|authentication failure|session opened|session closed|sudo:",
    )
    .unwrap()
});

impl Parser for AuthLogParser {
    fn name(&self) -> &'static str {
        "auth"
    }

    fn description(&self) -> &'static str {
        "sshd / login / pam / sudo authentication lines"
    }

    fn sniff(&self, line: &str, kind: EvidenceKind) -> f32 {
        let mut score = 0.0f32;
        if matches!(kind, EvidenceKind::AuthLog) {
            score += 0.45;
        }
        if AUTH_MARKERS.is_match(line) {
            score += 0.5;
        }
        score.min(1.0)
    }

    fn parse_line(&self, ctx: &ParseContext, line: &str) -> Option<ParsedLine> {
        // Strip the syslog envelope when present; otherwise parse the raw body.
        let (body, parsed, proc_name, pid, host) = match strip_envelope(line) {
            Some(Ok(env)) => (
                env.message,
                Some(env.parsed),
                env.proc_name,
                env.pid,
                Some(env.host),
            ),
            Some(Err(_)) => {
                // Envelope-shaped line with a broken timestamp.
                return if looks_like_auth_line(line) {
                    Some(ParsedLine::Skipped(SkipReason::MalformedTimestamp))
                } else {
                    None
                };
            }
            None => (line.to_string(), None, "unknown".to_string(), None, None),
        };

        parse_auth_body(ctx, self.name(), &body, parsed, &proc_name, pid, host.as_deref())
    }
}

#[allow(clippy::too_many_arguments)]
fn parse_auth_body(
    ctx: &ParseContext,
    parser_name: &str,
    body: &str,
    parsed: Option<ParsedTimestamp>,
    proc_name: &str,
    pid: Option<u32>,
    host: Option<&str>,
) -> Option<ParsedLine> {
    // A timestamp is mandatory: never fabricate one.
    let parsed = parsed.or_else(|| match parse_at_start(body) {
        Some(Ok(p)) => Some(p),
        Some(Err(_)) => return None, // signal malformed below
        None => None,
    });

    // Distinguish "malformed timestamp" from "not my format".
    let failed_ts = parse_at_start(body).is_some_and(|r| r.is_err());
    let parsed = match parsed {
        Some(p) => p,
        None => {
            if failed_ts || looks_like_auth_line(body) {
                return Some(ParsedLine::Skipped(SkipReason::MalformedTimestamp));
            }
            return None;
        }
    };

    let mut classified: Option<(EventType, Option<&str>, Severity)> = None;
    let mut user: Option<String> = None;
    let mut src: Option<IpAddr> = None;
    let mut port: Option<u16> = None;

    if let Some(c) = FAILED_PASSWORD.captures(body) {
        user = Some(c[2].to_string());
        src = c[3].parse().ok();
        port = c[4].parse().ok();
        classified = Some((
            EventType::Auth,
            Some("ssh_failed_password"),
            Severity::Warning,
        ));
    } else if let Some(c) = ACCEPTED.captures(body) {
        user = Some(c[1].to_string());
        src = c[2].parse().ok();
        port = c[3].parse().ok();
        classified = Some((EventType::Auth, Some("ssh_accepted"), Severity::Notice));
    } else if let Some(c) = SESSION.captures(body) {
        user = Some(c[2].to_string());
        let opened = &c[1] == "opened";
        classified = Some((
            EventType::Auth,
            Some(if opened { "session_opened" } else { "session_closed" }),
            if opened { Severity::Notice } else { Severity::Info },
        ));
    } else if let Some(c) = SUDO.captures(body) {
        user = Some(c[1].to_string());
        classified = Some((EventType::Privilege, Some("sudo_command"), Severity::Notice));
    } else if proc_name.eq_ignore_ascii_case("sudo") {
        // The envelope strip removed the "sudo:" token; the body now looks
        // like "deploy : TTY=pts/0 ; COMMAND=...".
        if let Some(c) = SUDO_STRIPPED.captures(body) {
            user = Some(c[1].to_string());
            classified = Some((EventType::Privilege, Some("sudo_command"), Severity::Notice));
        }
    } else if FAILED_LOGIN.is_match(body) {
        user = PAM_USER
            .captures(body)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().to_string());
        classified = Some((EventType::Auth, Some("auth_failure"), Severity::Warning));
    }

    let (event_type, subtype, severity) = classified?;
    let mut b = Event::builder(ctx.event_id, parsed.dt, parser_name, ctx.label(), ctx.line_no)
        .precision(parsed.precision)
        .partial_timestamp(parsed.partial)
        .raw_timestamp(parsed.raw.clone())
        .offset_explicit(parsed.offset_explicit)
        .event_type(event_type)
        .severity(severity)
        .process_name(proc_name.to_string())
        .message(body.to_string())
        .confidence(0.9);
    if let Some(s) = subtype {
        b = b.subtype(s);
    }
    if let Some(u) = user {
        b = b.user(u);
    }
    if let Some(a) = src {
        b = b.src_addr(a);
    }
    if let Some(p) = port {
        b = b.port(p);
    }
    if let Some(p) = pid {
        b = b.pid(p);
    }
    if let Some(h) = host {
        b = b.hostname(h.to_string());
    }
    Some(ParsedLine::Event(b.build()))
}

fn looks_like_auth_line(body: &str) -> bool {
    AUTH_MARKERS.is_match(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::Evidence;
    use std::path::PathBuf;

    fn ev() -> Evidence {
        Evidence {
            path: PathBuf::from("auth.log"),
            label: "auth.log".into(),
            kind: EvidenceKind::AuthLog,
            is_stdin: false,
        }
    }

    fn parse(line: &str) -> Option<ParsedLine> {
        let e = ev();
        let p = AuthLogParser;
        p.parse_line(&ParseContext::new(&e, 1, 1), line)
    }

    fn event(line: &str) -> Event {
        match parse(line) {
            Some(ParsedLine::Event(e)) => e,
            other => panic!("expected event, got {other:?} for line: {line}"),
        }
    }

    #[test]
    fn parses_failed_password() {
        let e = event("Sep 30 14:02:11 web01 sshd[8123]: Failed password for root from 203.0.113.7 port 51234 ssh2");
        assert_eq!(e.subtype.as_deref(), Some("ssh_failed_password"));
        assert_eq!(e.user.as_deref(), Some("root"));
        assert_eq!(e.src_addr.map(|a| a.to_string()).as_deref(), Some("203.0.113.7"));
        assert_eq!(e.port, Some(51234));
        assert_eq!(e.severity, Severity::Warning);
    }

    #[test]
    fn parses_accepted_password() {
        let e = event("Sep 30 14:02:20 web01 sshd[8123]: Accepted password for deploy from 203.0.113.7 port 51234 ssh2");
        assert_eq!(e.subtype.as_deref(), Some("ssh_accepted"));
        assert_eq!(e.user.as_deref(), Some("deploy"));
    }

    #[test]
    fn parses_sudo_command_as_privilege() {
        let e = event("Sep 30 14:02:25 web01 sudo: deploy : TTY=pts/0 ; COMMAND=/usr/bin/systemctl restart app");
        assert_eq!(e.event_type, EventType::Privilege);
        assert_eq!(e.subtype.as_deref(), Some("sudo_command"));
        assert_eq!(e.user.as_deref(), Some("deploy"));
    }

    #[test]
    fn non_auth_line_is_not_claimed() {
        assert!(parse("Sep 30 14:02:11 web01 kernel: [1.2] usb device found").is_none());
    }

    #[test]
    fn auth_line_without_timestamp_is_skipped_not_dropped_silently() {
        // Looks like auth material but has no parseable timestamp.
        let line = "sshd: Failed password for root from 203.0.113.7";
        assert!(matches!(
            parse(line),
            Some(ParsedLine::Skipped(SkipReason::MalformedTimestamp))
        ));
    }
}
