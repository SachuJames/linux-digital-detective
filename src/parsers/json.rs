//! JSON and JSONL parsers.
//!
//! [`JsonParser`] handles whole-file JSON documents (an array of objects or
//! a single object). [`JsonLinesParser`] handles newline-delimited JSON.
//!
//! Field mapping is best-effort across common key names; anything
//! unrecognized lands in `metadata` rather than being dropped.

use serde_json::Value;

use crate::errors::Result;
use crate::events::{Event, EventType, Severity};
use crate::evidence::{EvidenceKind, SkipReason};
use crate::parsers::timestamps::parse_at_start;
use crate::parsers::{ParseContext, ParsedLine, Parser, WholeContext};
use std::net::IpAddr;

/// Pull the first present string value among candidate keys.
fn str_field<'a>(v: &'a Value, keys: &[&str]) -> Option<&'a str> {
    keys.iter()
        .filter_map(|k| v.get(k))
        .filter_map(|v| v.as_str())
        .next()
}

/// Pull the first present u32 among candidate keys (numbers or strings).
fn u32_field(v: &Value, keys: &[&str]) -> Option<u32> {
    keys.iter().filter_map(|k| v.get(k)).find_map(|v| {
        v.as_u64()
            .and_then(|n| u32::try_from(n).ok())
            .or_else(|| v.as_str()?.parse::<u32>().ok())
    })
}

fn ip_field(v: &Value, keys: &[&str]) -> Option<IpAddr> {
    str_field(v, keys)?.parse().ok()
}

const KNOWN_KEYS: &[&str] = &[
    "timestamp",
    "time",
    "@timestamp",
    "ts",
    "datetime",
    "date",
    "message",
    "msg",
    "log",
    "level",
    "severity",
    "loglevel",
    "host",
    "hostname",
    "pid",
    "process_id",
    "user",
    "username",
    "uid",
    "process",
    "proc",
    "program",
    "app",
    "service",
    "src_ip",
    "source_ip",
    "client_ip",
    "remote_addr",
    "dst_ip",
    "dest_ip",
    "destination_ip",
    "port",
    "src_port",
    "dst_port",
    "type",
    "event_type",
    "category",
    "subtype",
];

/// Map one JSON object to an event. `None` = not a usable record.
fn object_to_event(
    parser_name: &str,
    v: &Value,
    ctx: &ParseContext,
    record_no: u64,
) -> Option<ParsedLine> {
    let obj = v.as_object()?;
    if obj.is_empty() {
        return Some(ParsedLine::Skipped(SkipReason::IncompleteRecord));
    }

    let ts_raw = str_field(
        v,
        &["timestamp", "time", "@timestamp", "ts", "datetime", "date"],
    );
    let parsed = match ts_raw {
        Some(raw) => match parse_at_start(raw) {
            Some(Ok(p)) => Some(p),
            Some(Err(_)) => {
                return Some(ParsedLine::Skipped(SkipReason::MalformedTimestamp))
            }
            None => None,
        },
        None => None,
    };
    // Epoch numbers are common in JSON logs.
    let parsed = parsed.or_else(|| {
        let n = ["timestamp", "time", "@timestamp", "ts"]
            .iter()
            .filter_map(|k| v.get(k))
            .find_map(|v| v.as_i64())?;
        match parse_at_start(&n.to_string()) {
            Some(Ok(p)) => Some(p),
            _ => None,
        }
    });
    let Some(parsed) = parsed else {
        return Some(ParsedLine::Skipped(SkipReason::IncompleteRecord));
    };

    let message = str_field(v, &["message", "msg", "log"])
        .unwrap_or("")
        .to_string();
    let mut b =
        Event::builder(ctx.event_id, parsed.dt, parser_name, ctx.label(), record_no)
            .precision(parsed.precision)
            .partial_timestamp(parsed.partial)
            .raw_timestamp(parsed.raw.clone())
            .offset_explicit(parsed.offset_explicit)
            .message(message)
            .confidence(0.85);

    if let Some(t) = str_field(v, &["type", "event_type", "category"]) {
        b = b.event_type(EventType::from_name(t));
    }
    if let Some(s) = str_field(v, &["subtype"]) {
        b = b.subtype(s);
    }
    if let Some(l) = str_field(v, &["level", "severity", "loglevel"]) {
        b = b.severity(Severity::from_name(l));
    }
    if let Some(h) = str_field(v, &["host", "hostname"]) {
        b = b.hostname(h);
    }
    if let Some(p) = u32_field(v, &["pid", "process_id"]) {
        b = b.pid(p);
    }
    if let Some(u) = str_field(v, &["user", "username"]) {
        b = b.user(u);
    }
    if let Some(p) = str_field(v, &["process", "proc", "program", "app"]) {
        b = b.process_name(p);
    }
    if let Some(a) = ip_field(v, &["src_ip", "source_ip", "client_ip", "remote_addr"]) {
        b = b.src_addr(a);
    }
    if let Some(a) = ip_field(v, &["dst_ip", "dest_ip", "destination_ip"]) {
        b = b.dst_addr(a);
    }
    if let Some(p) = u32_field(v, &["port", "dst_port", "src_port"]) {
        if let Ok(p16) = u16::try_from(p) {
            b = b.port(p16);
        }
    }
    // Keep everything else as metadata so nothing is silently dropped.
    for (k, val) in obj {
        if !KNOWN_KEYS.contains(&k.as_str()) {
            let s = match val {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            if s.len() <= 4096 {
                b = b.meta(k.clone(), s);
            }
        }
    }
    Some(ParsedLine::Event(b.build()))
}

pub struct JsonParser;

impl Parser for JsonParser {
    fn name(&self) -> &'static str {
        "json"
    }

    fn description(&self) -> &'static str {
        "whole-file JSON: an array of event objects or a single object"
    }

    fn sniff(&self, _line: &str, _kind: EvidenceKind) -> f32 {
        0.0 // whole-file only; see parse_whole
    }

    fn parse_line(&self, _ctx: &ParseContext, _line: &str) -> Option<ParsedLine> {
        None
    }

    fn parse_whole(
        &self,
        ctx: &WholeContext,
        lines: &[String],
    ) -> Result<Option<Vec<ParsedLine>>> {
        let text: String = lines.join("\n");
        let trimmed = text.trim_start();
        if !(trimmed.starts_with('[') || trimmed.starts_with('{')) {
            return Ok(None);
        }
        let value: Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(_) => return Ok(None), // not JSON; let other parsers try
        };
        let records: Vec<&Value> = match &value {
            Value::Array(items) => items.iter().collect(),
            Value::Object(_) => vec![&value],
            _ => return Ok(None),
        };
        let mut out = Vec::new();
        let mut id = ctx.first_id;
        for (i, record) in records.iter().enumerate() {
            let pctx = ParseContext::new(ctx.evidence, i as u64 + 1, id);
            match object_to_event(self.name(), record, &pctx, i as u64 + 1) {
                Some(ParsedLine::Event(mut e)) => {
                    e.id = id;
                    id += 1;
                    out.push(ParsedLine::Event(e));
                }
                Some(ParsedLine::Skipped(r)) => out.push(ParsedLine::Skipped(r)),
                None => out.push(ParsedLine::Skipped(SkipReason::UnsupportedFormat)),
            }
        }
        Ok(Some(out))
    }
}

pub struct JsonLinesParser;

impl Parser for JsonLinesParser {
    fn name(&self) -> &'static str {
        "jsonl"
    }

    fn description(&self) -> &'static str {
        "newline-delimited JSON, one event object per line"
    }

    fn sniff(&self, line: &str, kind: EvidenceKind) -> f32 {
        let t = line.trim_start();
        if !t.starts_with('{') {
            return 0.0;
        }
        let mut score = 0.4f32;
        if serde_json::from_str::<Value>(line).is_ok() {
            score += 0.3;
        }
        if matches!(kind, EvidenceKind::JsonLines) {
            score += 0.2;
        }
        score.min(1.0)
    }

    fn parse_line(&self, ctx: &ParseContext, line: &str) -> Option<ParsedLine> {
        let t = line.trim();
        if !t.starts_with('{') {
            return None;
        }
        match serde_json::from_str::<Value>(t) {
            Ok(v) => object_to_event(self.name(), &v, ctx, ctx.line_no),
            // Looks like JSON but does not parse: malformed input.
            Err(_) => Some(ParsedLine::Skipped(SkipReason::IncompleteRecord)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::Evidence;
    use std::path::PathBuf;

    fn ev(kind: EvidenceKind) -> Evidence {
        Evidence {
            path: PathBuf::from("app.json"),
            label: "app.json".into(),
            kind,
            is_stdin: false,
        }
    }

    #[test]
    fn jsonl_line_maps_common_fields() {
        let e = ev(EvidenceKind::JsonLines);
        let p = JsonLinesParser;
        let ctx = ParseContext::new(&e, 1, 1);
        let line = r#"{"timestamp":"2026-09-30T14:02:11Z","level":"error","host":"web01","user":"deploy","message":"disk nearly full","pid":123}"#;
        match p.parse_line(&ctx, line) {
            Some(ParsedLine::Event(ev)) => {
                assert_eq!(ev.severity, Severity::Error);
                assert_eq!(ev.hostname.as_deref(), Some("web01"));
                assert_eq!(ev.user.as_deref(), Some("deploy"));
                assert_eq!(ev.pid, Some(123));
                assert_eq!(ev.message, "disk nearly full");
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn jsonl_rejects_non_object_lines() {
        let e = ev(EvidenceKind::JsonLines);
        let p = JsonLinesParser;
        let ctx = ParseContext::new(&e, 1, 1);
        assert!(p.parse_line(&ctx, "not json").is_none());
    }

    #[test]
    fn whole_json_array_parses() {
        let e = ev(EvidenceKind::Json);
        let p = JsonParser;
        let lines = vec![
            r#"[{"timestamp":"2026-09-30T14:02:11Z","message":"a"},{"timestamp":"2026-09-30T14:02:12Z","message":"b"}]"#
                .to_string(),
        ];
        let wctx = WholeContext {
            evidence: &e,
            first_id: 1,
        };
        let parsed = p.parse_whole(&wctx, &lines).unwrap().unwrap();
        assert_eq!(parsed.len(), 2);
        assert!(matches!(parsed[0], ParsedLine::Event(_)));
    }

    #[test]
    fn json_object_without_timestamp_is_incomplete() {
        let e = ev(EvidenceKind::JsonLines);
        let p = JsonLinesParser;
        let ctx = ParseContext::new(&e, 1, 1);
        match p.parse_line(&ctx, r#"{"message":"no time"}"#) {
            Some(ParsedLine::Skipped(SkipReason::IncompleteRecord)) => {}
            other => panic!("unexpected: {other:?}"),
        }
    }
}
