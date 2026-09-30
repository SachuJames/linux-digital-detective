//! Normalized event model.
//!
//! Every parser produces [`Event`]s. The model is deliberately permissive:
//! any field may be absent, and absence is represented with `Option` rather
//! than invented data. See `docs/evidence-model.md` for the rationale.

use chrono::{DateTime, FixedOffset};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::IpAddr;

/// Unique identifier for an event within one investigation run.
pub type EventId = u64;

/// How serious the event looks, normalized across formats.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Debug,
    #[default]
    Info,
    Notice,
    Warning,
    Error,
    Critical,
    Unknown,
}

impl Severity {
    /// Parse a syslog-style or textual severity name.
    pub fn from_name(name: &str) -> Self {
        match name.to_ascii_lowercase().as_str() {
            "debug" => Severity::Debug,
            "info" => Severity::Info,
            "notice" => Severity::Notice,
            "warning" | "warn" => Severity::Warning,
            "error" | "err" => Severity::Error,
            "critical" | "crit" | "fatal" | "alert" | "emerg" => Severity::Critical,
            _ => Severity::Unknown,
        }
    }

    /// Map a syslog numeric priority (0-7) to a severity.
    pub fn from_syslog_priority(priority: u8) -> Self {
        match priority {
            0 | 1 | 2 => Severity::Critical,
            3 => Severity::Error,
            4 => Severity::Warning,
            5 => Severity::Notice,
            6 => Severity::Info,
            7 => Severity::Debug,
            _ => Severity::Unknown,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Debug => "debug",
            Severity::Info => "info",
            Severity::Notice => "notice",
            Severity::Warning => "warning",
            Severity::Error => "error",
            Severity::Critical => "critical",
            Severity::Unknown => "unknown",
        }
    }
}

/// Coarse category of an event. Fine-grained detail goes in [`Event::subtype`].
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    Auth,
    Process,
    Privilege,
    Network,
    Kernel,
    Service,
    Application,
    System,
    Snapshot,
    #[default]
    Unknown,
}

impl EventType {
    pub fn as_str(&self) -> &'static str {
        match self {
            EventType::Auth => "auth",
            EventType::Process => "process",
            EventType::Privilege => "privilege",
            EventType::Network => "network",
            EventType::Kernel => "kernel",
            EventType::Service => "service",
            EventType::Application => "application",
            EventType::System => "system",
            EventType::Snapshot => "snapshot",
            EventType::Unknown => "unknown",
        }
    }

    pub fn from_name(name: &str) -> Self {
        match name.to_ascii_lowercase().as_str() {
            "auth" | "authentication" => EventType::Auth,
            "process" | "proc" => EventType::Process,
            "privilege" | "priv" | "sudo" => EventType::Privilege,
            "network" | "net" | "socket" => EventType::Network,
            "kernel" | "kern" => EventType::Kernel,
            "service" | "daemon" | "systemd" => EventType::Service,
            "application" | "app" => EventType::Application,
            "system" | "sys" => EventType::System,
            "snapshot" => EventType::Snapshot,
            _ => EventType::Unknown,
        }
    }
}

/// Resolution of the timestamp attached to an event.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimestampPrecision {
    Nanosecond,
    Microsecond,
    Millisecond,
    #[default]
    Second,
    Minute,
    Unknown,
}

/// Where an event came from. This is the provenance chain that lets an
/// investigator answer "where did this event come from?".
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Provenance {
    /// Canonical path of the evidence file, or "<stdin>".
    pub file: String,
    /// 1-based line number within the file (0 when not applicable, e.g. snapshots).
    pub line: u64,
    /// Name of the parser that produced the event.
    pub parser: String,
    /// The timestamp string exactly as it appeared in the evidence, if any.
    pub raw_timestamp: Option<String>,
    /// True when the timestamp carried an explicit UTC offset / zone.
    pub offset_explicit: bool,
}

/// A single normalized event.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Event {
    /// Unique within one investigation run (assigned in parse order).
    pub id: EventId,
    /// Normalized timestamp.
    pub timestamp: DateTime<FixedOffset>,
    /// Resolution of the timestamp.
    pub precision: TimestampPrecision,
    /// True when the timestamp was partial (no year, no date, no time at all).
    /// Partial timestamps are never fabricated: the missing parts are
    /// documented in `provenance.raw_timestamp` and `metadata`.
    pub partial_timestamp: bool,
    /// Coarse category.
    pub event_type: EventType,
    /// Optional fine-grained label, e.g. "ssh_failed_password".
    pub subtype: Option<String>,
    pub severity: Severity,
    pub hostname: Option<String>,
    pub pid: Option<u32>,
    pub ppid: Option<u32>,
    pub user: Option<String>,
    pub process_name: Option<String>,
    pub src_addr: Option<IpAddr>,
    pub dst_addr: Option<IpAddr>,
    pub port: Option<u16>,
    /// Human-readable summary of the event.
    pub message: String,
    pub provenance: Provenance,
    /// Parser's self-reported confidence in this event (0.0 - 1.0).
    /// This is a parse-confidence heuristic, not a verdict.
    pub confidence: f32,
    /// Anything else the parser extracted, keyed deterministically.
    pub metadata: BTreeMap<String, String>,
}

impl Event {
    /// Start building an event; fills in parser-agnostic defaults.
    pub fn builder(
        id: EventId,
        timestamp: DateTime<FixedOffset>,
        parser: &str,
        file: &str,
        line: u64,
    ) -> EventBuilder {
        EventBuilder {
            id,
            timestamp,
            precision: TimestampPrecision::Second,
            partial_timestamp: false,
            event_type: EventType::Unknown,
            subtype: None,
            severity: Severity::Unknown,
            hostname: None,
            pid: None,
            ppid: None,
            user: None,
            process_name: None,
            src_addr: None,
            dst_addr: None,
            port: None,
            message: String::new(),
            provenance: Provenance {
                file: file.to_string(),
                line,
                parser: parser.to_string(),
                raw_timestamp: None,
                offset_explicit: false,
            },
            confidence: 0.5,
            metadata: BTreeMap::new(),
        }
    }
}

/// Fluent builder for [`Event`]; avoids a 20-argument constructor.
pub struct EventBuilder {
    id: EventId,
    timestamp: DateTime<FixedOffset>,
    precision: TimestampPrecision,
    partial_timestamp: bool,
    event_type: EventType,
    subtype: Option<String>,
    severity: Severity,
    hostname: Option<String>,
    pid: Option<u32>,
    ppid: Option<u32>,
    user: Option<String>,
    process_name: Option<String>,
    src_addr: Option<IpAddr>,
    dst_addr: Option<IpAddr>,
    port: Option<u16>,
    message: String,
    provenance: Provenance,
    confidence: f32,
    metadata: BTreeMap<String, String>,
}

#[allow(clippy::too_many_arguments)]
impl EventBuilder {
    pub fn precision(mut self, p: TimestampPrecision) -> Self {
        self.precision = p;
        self
    }
    pub fn partial_timestamp(mut self, partial: bool) -> Self {
        self.partial_timestamp = partial;
        self
    }
    pub fn event_type(mut self, t: EventType) -> Self {
        self.event_type = t;
        self
    }
    pub fn subtype(mut self, s: impl Into<String>) -> Self {
        self.subtype = Some(s.into());
        self
    }
    pub fn severity(mut self, s: Severity) -> Self {
        self.severity = s;
        self
    }
    pub fn hostname(mut self, h: impl Into<String>) -> Self {
        self.hostname = Some(h.into());
        self
    }
    pub fn pid(mut self, pid: u32) -> Self {
        self.pid = Some(pid);
        self
    }
    pub fn ppid(mut self, ppid: u32) -> Self {
        self.ppid = Some(ppid);
        self
    }
    pub fn user(mut self, u: impl Into<String>) -> Self {
        self.user = Some(u.into());
        self
    }
    pub fn process_name(mut self, n: impl Into<String>) -> Self {
        self.process_name = Some(n.into());
        self
    }
    pub fn src_addr(mut self, a: IpAddr) -> Self {
        self.src_addr = Some(a);
        self
    }
    pub fn dst_addr(mut self, a: IpAddr) -> Self {
        self.dst_addr = Some(a);
        self
    }
    pub fn port(mut self, p: u16) -> Self {
        self.port = Some(p);
        self
    }
    pub fn message(mut self, m: impl Into<String>) -> Self {
        self.message = m.into();
        self
    }
    pub fn raw_timestamp(mut self, raw: impl Into<String>) -> Self {
        self.provenance.raw_timestamp = Some(raw.into());
        self
    }
    pub fn offset_explicit(mut self, explicit: bool) -> Self {
        self.provenance.offset_explicit = explicit;
        self
    }
    pub fn confidence(mut self, c: f32) -> Self {
        self.confidence = c.clamp(0.0, 1.0);
        self
    }
    pub fn meta(mut self, k: impl Into<String>, v: impl Into<String>) -> Self {
        self.metadata.insert(k.into(), v.into());
        self
    }

    pub fn build(self) -> Event {
        Event {
            id: self.id,
            timestamp: self.timestamp,
            precision: self.precision,
            partial_timestamp: self.partial_timestamp,
            event_type: self.event_type,
            subtype: self.subtype,
            severity: self.severity,
            hostname: self.hostname,
            pid: self.pid,
            ppid: self.ppid,
            user: self.user,
            process_name: self.process_name,
            src_addr: self.src_addr,
            dst_addr: self.dst_addr,
            port: self.port,
            message: self.message,
            provenance: self.provenance,
            confidence: self.confidence,
            metadata: self.metadata,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn ts() -> DateTime<FixedOffset> {
        FixedOffset::east_opt(0)
            .unwrap()
            .with_ymd_and_hms(2026, 1, 1, 0, 0, 0)
            .unwrap()
    }

    #[test]
    fn builder_keeps_optional_fields_empty_by_default() {
        let e = Event::builder(1, ts(), "test", "f.log", 3)
            .message("hello")
            .build();
        assert_eq!(e.id, 1);
        assert!(e.hostname.is_none());
        assert!(e.pid.is_none());
        assert!(!e.partial_timestamp);
        assert_eq!(e.confidence, 0.5);
    }

    #[test]
    fn severity_from_syslog_priority_maps_ranges() {
        assert_eq!(Severity::from_syslog_priority(2), Severity::Critical);
        assert_eq!(Severity::from_syslog_priority(4), Severity::Warning);
        assert_eq!(Severity::from_syslog_priority(6), Severity::Info);
        assert_eq!(Severity::from_syslog_priority(9), Severity::Unknown);
    }

    #[test]
    fn severity_ordering_lets_filters_use_thresholds() {
        assert!(Severity::Warning >= Severity::Info);
        assert!(Severity::Critical > Severity::Error);
    }
}
