//! Reporting: human-readable and machine-readable output.
//!
//! Formats:
//!
//! - `text`: the human investigation report.
//! - `json`: the whole [`Investigation`] as one JSON document.
//! - `jsonl`: one JSON object per line: `{"kind":"event",...}`,
//!   `{"kind":"finding",...}`, then a final `{"kind":"summary",...}`.
//! - `csv`: one row per event (findings are text/json only).
//!
//! Terminal output is sanitized: log content is untrusted, so ANSI escape
//! sequences and control characters are stripped before printing.

use std::collections::HashMap;
use std::str::FromStr;

use chrono::{DateTime, FixedOffset, Local};
use serde::Serialize;

use crate::correlation::Correlation;
use crate::errors::{Error, Result};
use crate::events::{Event, EventId, Severity};
use crate::evidence::ParseStats;
use crate::linux::sanitize_for_terminal;
use crate::rules::Finding;

/// Everything the pipeline produced, ready to render.
#[derive(Debug, Clone, Serialize)]
pub struct Investigation {
    pub events: Vec<Event>,
    pub findings: Vec<Finding>,
    pub correlations: Vec<Correlation>,
    pub files: Vec<FileReport>,
    pub window: Option<(DateTime<FixedOffset>, DateTime<FixedOffset>)>,
    pub generated_at: DateTime<FixedOffset>,
    pub evicted: u64,
}

/// Per-file parse statistics for the report.
#[derive(Debug, Clone, Serialize)]
pub struct FileReport {
    pub file: String,
    pub parser: String,
    pub stats: ParseStats,
}

/// Output format selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Text,
    Json,
    JsonLines,
    Csv,
}

impl FromStr for Format {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "text" => Ok(Format::Text),
            "json" => Ok(Format::Json),
            "jsonl" | "ndjson" => Ok(Format::JsonLines),
            "csv" => Ok(Format::Csv),
            other => Err(Error::Usage(format!(
                "unknown format '{other}'; expected text, json, jsonl, or csv"
            ))),
        }
    }
}

/// Render an investigation in the requested format.
pub fn render(inv: &Investigation, format: Format, color: bool) -> String {
    match format {
        Format::Text => render_text(inv, color),
        Format::Json => serde_json::to_string_pretty(inv).unwrap_or_default(),
        Format::JsonLines => render_jsonl(inv),
        Format::Csv => render_csv(inv),
    }
}

// --- text ---------------------------------------------------------------

struct Palette {
    enabled: bool,
}

impl Palette {
    fn paint(&self, code: &str, text: &str) -> String {
        if self.enabled {
            format!("\x1b[{code}m{text}\x1b[0m")
        } else {
            text.to_string()
        }
    }
    fn header(&self, t: &str) -> String {
        self.paint("1;36", t)
    }
    fn severity(&self, s: Severity) -> String {
        let code = match s {
            Severity::Critical | Severity::Error => "1;31",
            Severity::Warning => "1;33",
            Severity::Notice => "1;34",
            _ => "0",
        };
        self.paint(code, s.as_str())
    }
}

fn render_text(inv: &Investigation, color: bool) -> String {
    let pal = Palette { enabled: color };
    let mut out = String::new();
    let rule = "=".repeat(50);
    let thin = "-".repeat(50);

    out.push_str(&format!("{rule}\n"));
    out.push_str(&pal.header("LINUX DIGITAL DETECTIVE\n"));
    out.push_str("Investigation Report\n");
    out.push_str(&format!("{rule}\n\n"));

    let total_lines: u64 = inv.files.iter().map(|f| f.stats.lines).sum();
    let skipped: u64 = inv.files.iter().map(|f| f.stats.skipped_total()).sum();
    out.push_str("Evidence:\n");
    out.push_str(&format!("    {} files\n", inv.files.len()));
    out.push_str(&format!("    {} lines read\n", total_lines));
    out.push_str(&format!("    {} events\n", inv.events.len()));
    if skipped > 0 {
        out.push_str(&format!("    {skipped} lines skipped (see parsing statistics)\n"));
    }
    if inv.evicted > 0 {
        out.push_str(&format!(
            "    {} oldest events evicted (store cap reached)\n",
            inv.evicted
        ));
    }
    out.push('\n');

    out.push_str("Investigation window:\n");
    match inv.window {
        Some((from, to)) => out.push_str(&format!(
            "    {} → {}\n",
            from.format("%Y-%m-%d %H:%M:%S"),
            to.format("%Y-%m-%d %H:%M:%S")
        )),
        None => out.push_str("    (no events)\n"),
    }
    out.push('\n');

    out.push_str("Noteworthy sequences:\n");
    out.push_str(&format!("    {}\n\n", inv.findings.len()));

    let by_id: HashMap<EventId, &Event> = inv.events.iter().map(|e| (e.id, e)).collect();
    for (i, f) in inv.findings.iter().enumerate() {
        out.push_str(&format!("{thin}\n"));
        out.push_str(&format!("FINDING #{}\n", i + 1));
        out.push_str(&format!("{thin}\n\n"));
        out.push_str(&format!("{}\n\n", sanitize_for_terminal(&f.title)));
        out.push_str("Severity:\n");
        out.push_str(&format!("    {}\n\n", pal.severity(f.severity)));
        out.push_str(&format!("Rule: {}\n\n", f.rule_id));
        out.push_str(&format!("Confidence: {:.2} (heuristic)\n\n", f.confidence));
        out.push_str("Timeline:\n");
        for id in &f.event_ids {
            if let Some(e) = by_id.get(id) {
                out.push_str(&format!(
                    "    {} {}\n",
                    e.timestamp.format("%H:%M:%S"),
                    sanitize_for_terminal(&e.message).lines().next().unwrap_or("")
                ));
            }
        }
        out.push('\n');
        // Related correlation signals, if any. Time-only pairs are noise,
        // so only show pairs that share at least one identifying signal.
        let mut reasons: Vec<String> = Vec::new();
        for c in &inv.correlations {
            if !(f.event_ids.contains(&c.a) || f.event_ids.contains(&c.b)) {
                continue;
            }
            if c.reasons.iter().any(|r| r.starts_with("same ")) {
                reasons.extend(c.reasons.iter().cloned());
            }
        }
        reasons.sort();
        reasons.dedup();
        if !reasons.is_empty() {
            out.push_str("Correlation signals:\n");
            for r in reasons.iter().take(6) {
                out.push_str(&format!("    + {}\n", sanitize_for_terminal(r)));
            }
            out.push('\n');
        }
        out.push_str("Evidence:\n");
        for r in &f.evidence_refs {
            out.push_str(&format!("    {r}\n"));
        }
        out.push('\n');
        out.push_str("Interpretation:\n");
        out.push_str(&format!("    {}\n\n", sanitize_for_terminal(&f.explanation)));
    }

    // Process activity summary.
    let mut procs: HashMap<(u32, String), &Event> = HashMap::new();
    for e in &inv.events {
        if let Some(pid) = e.pid {
            let name = e.process_name.clone().unwrap_or_else(|| "?".into());
            procs.entry((pid, name)).or_insert(e);
        }
    }
    if !procs.is_empty() {
        out.push_str(&format!("{thin}\nPROCESS ACTIVITY\n{thin}\n\n"));
        let mut procs: Vec<_> = procs.into_iter().collect();
        procs.sort_by_key(|((pid, _), _)| *pid);
        for ((pid, name), e) in procs.iter().take(30) {
            let exe = e.metadata.get("exe").map(|s| s.as_str()).unwrap_or(name);
            out.push_str(&format!("PID {pid}\n"));
            out.push_str(&format!("    Executable: {}\n", sanitize_for_terminal(exe)));
            if let Some(ppid) = e.ppid {
                out.push_str(&format!("    Parent: {ppid}\n"));
            }
            if let Some(u) = &e.user {
                out.push_str(&format!("    User: {}\n", sanitize_for_terminal(u)));
            }
        }
        out.push('\n');
    }

    // Parse statistics.
    out.push_str(&format!("{thin}\nPARSING STATISTICS\n{thin}\n\n"));
    out.push_str(&format!("Processed:\n    {total_lines} lines\n\n"));
    out.push_str(&format!("Parsed:\n    {} events\n\n", inv.events.len()));
    out.push_str("Skipped:\n");
    out.push_str(&format!("    {skipped} lines\n"));
    let mut r_unsupported = 0;
    let mut r_ts = 0;
    let mut r_incomplete = 0;
    let mut r_long = 0;
    for f in &inv.files {
        r_unsupported += f.stats.skipped_unsupported;
        r_ts += f.stats.skipped_bad_timestamp;
        r_incomplete += f.stats.skipped_incomplete;
        r_long += f.stats.skipped_too_long;
    }
    if skipped > 0 {
        out.push_str("Reasons:\n");
        out.push_str(&format!("    - {r_unsupported} unsupported format\n"));
        out.push_str(&format!("    - {r_ts} malformed timestamp\n"));
        out.push_str(&format!("    - {r_incomplete} incomplete records\n"));
        out.push_str(&format!("    - {r_long} overlong lines\n"));
    }
    out.push('\n');
    out.push_str("Note: correlation scores and rule confidences are heuristics to\n");
    out.push_str("guide investigation, not verdicts. Verify against the evidence.\n");
    out
}

// --- jsonl / csv --------------------------------------------------------

fn render_jsonl(inv: &Investigation) -> String {
    let mut out = String::new();
    for e in &inv.events {
        let v = serde_json::json!({"kind": "event", "event": e});
        out.push_str(&serde_json::to_string(&v).unwrap_or_default());
        out.push('\n');
    }
    for f in &inv.findings {
        let v = serde_json::json!({"kind": "finding", "finding": f});
        out.push_str(&serde_json::to_string(&v).unwrap_or_default());
        out.push('\n');
    }
    let summary = serde_json::json!({
        "kind": "summary",
        "summary": {
            "events": inv.events.len(),
            "findings": inv.findings.len(),
            "files": inv.files.len(),
            "generated_at": inv.generated_at,
        }
    });
    out.push_str(&serde_json::to_string(&summary).unwrap_or_default());
    out.push('\n');
    out
}

fn csv_escape(s: &str) -> String {
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

fn render_csv(inv: &Investigation) -> String {
    let mut out = String::from(
        "id,timestamp,precision,partial_timestamp,event_type,subtype,severity,hostname,pid,ppid,user,process,src_addr,dst_addr,port,parser,file,line,message\n",
    );
    for e in &inv.events {
        let row = [
            e.id.to_string(),
            e.timestamp.to_rfc3339(),
            format!("{:?}", e.precision).to_ascii_lowercase(),
            e.partial_timestamp.to_string(),
            e.event_type.as_str().to_string(),
            e.subtype.clone().unwrap_or_default(),
            e.severity.as_str().to_string(),
            e.hostname.clone().unwrap_or_default(),
            e.pid.map(|p| p.to_string()).unwrap_or_default(),
            e.ppid.map(|p| p.to_string()).unwrap_or_default(),
            e.user.clone().unwrap_or_default(),
            e.process_name.clone().unwrap_or_default(),
            e.src_addr.map(|a| a.to_string()).unwrap_or_default(),
            e.dst_addr.map(|a| a.to_string()).unwrap_or_default(),
            e.port.map(|p| p.to_string()).unwrap_or_default(),
            e.provenance.parser.clone(),
            e.provenance.file.clone(),
            e.provenance.line.to_string(),
            e.message.replace('\n', " "),
        ];
        out.push_str(
            &row.iter()
                .map(|c| csv_escape(c))
                .collect::<Vec<_>>()
                .join(","),
        );
        out.push('\n');
    }
    out
}

/// Current time for `generated_at` fields.
pub fn now() -> DateTime<FixedOffset> {
    let offset = FixedOffset::east_opt(Local::now().offset().local_minus_utc())
        .unwrap_or(FixedOffset::east_opt(0).unwrap());
    Local::now().with_timezone(&offset)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{EventType, TimestampPrecision};
    use chrono::TimeZone;

    fn inv_with_events() -> Investigation {
        let dt = FixedOffset::east_opt(0)
            .unwrap()
            .timestamp_opt(1_700_000_000, 0)
            .unwrap();
        let e = Event::builder(1, dt, "syslog", "sys.log", 3)
            .precision(TimestampPrecision::Second)
            .event_type(EventType::System)
            .severity(Severity::Info)
            .message("hello, \"world\"")
            .build();
        Investigation {
            events: vec![e],
            findings: vec![],
            correlations: vec![],
            files: vec![],
            window: None,
            generated_at: dt,
            evicted: 0,
        }
    }

    #[test]
    fn text_report_contains_sections() {
        let text = render(&inv_with_events(), Format::Text, false);
        assert!(text.contains("LINUX DIGITAL DETECTIVE"));
        assert!(text.contains("Investigation Report"));
        assert!(text.contains("PARSING STATISTICS"));
        assert!(text.contains("heuristics"));
    }

    #[test]
    fn text_report_sanitizes_terminal_escapes() {
        let mut inv = inv_with_events();
        inv.events[0].message = "x\x1b[2Jevil".into();
        inv.findings.push(Finding {
            rule_id: "TEST-001".into(),
            title: "t".into(),
            description: "d".into(),
            severity: Severity::Info,
            event_ids: vec![1],
            evidence_refs: vec![],
            explanation: "e".into(),
            confidence: 0.5,
        });
        let text = render(&inv, Format::Text, false);
        assert!(!text.contains("\x1b[2J"));
        assert!(text.contains("xevil"));
    }

    #[test]
    fn json_round_trips() {
        let s = render(&inv_with_events(), Format::Json, false);
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["events"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn jsonl_has_one_object_per_line() {
        let s = render(&inv_with_events(), Format::JsonLines, false);
        let lines: Vec<&str> = s.lines().collect();
        assert_eq!(lines.len(), 2); // event + summary
        for l in lines {
            serde_json::from_str::<serde_json::Value>(l).unwrap();
        }
    }

    #[test]
    fn csv_escapes_commas_and_quotes() {
        let s = render(&inv_with_events(), Format::Csv, false);
        let data_line = s.lines().nth(1).unwrap();
        assert!(data_line.contains("\"hello, \"\"world\"\"\""));
    }

    #[test]
    fn format_parses_case_insensitively() {
        assert_eq!("JSON".parse::<Format>().unwrap(), Format::Json);
        assert!("yaml".parse::<Format>().is_err());
    }
}
