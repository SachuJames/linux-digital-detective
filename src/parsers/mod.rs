//! Log parsers.
//!
//! Each parser implements [`Parser`]: it declares a name, describes what it
//! handles, scores how likely it is to handle a line ([`Parser::sniff`]),
//! and parses lines into normalized [`Event`]s.
//!
//! Adding a new parser means implementing this trait and registering it in
//! [`default_registry`]; no other module needs to change.
//!
//! [`Event`]: crate::events::Event

pub mod auth;
pub mod generic;
pub mod json;
pub mod syslog;
pub mod timestamps;

use crate::errors::Result;
use crate::events::{Event, EventId};
use crate::evidence::{Evidence, EvidenceKind, ParseStats, SkipReason};

/// Context passed to every parse call.
pub struct ParseContext<'a> {
    pub evidence: &'a Evidence,
    pub line_no: u64,
    pub event_id: EventId,
}

impl<'a> ParseContext<'a> {
    pub fn new(evidence: &'a Evidence, line_no: u64, event_id: EventId) -> Self {
        Self {
            evidence,
            line_no,
            event_id,
        }
    }

    pub fn label(&self) -> &str {
        &self.evidence.label
    }
}

/// What one line (or one file, for whole-file parsers) produced.
#[derive(Debug)]
pub enum ParsedLine {
    /// A normalized event.
    Event(Event),
    /// Recognizably this parser's format, but this line/record was bad.
    Skipped(SkipReason),
}

/// A parser for one family of log formats.
pub trait Parser: Send + Sync {
    /// Short stable name, used in provenance (e.g. "syslog").
    fn name(&self) -> &'static str;
    /// One-line human description.
    fn description(&self) -> &'static str;
    /// How likely this parser handles `line` (0.0 = no, 1.0 = certain).
    /// Used to pick a parser per file; must be cheap.
    fn sniff(&self, line: &str, kind: EvidenceKind) -> f32;
    /// Parse one line. `None` means "not my format"; `Some(Skipped(_))`
    /// means "my format, but this line is unusable".
    fn parse_line(&self, ctx: &ParseContext, line: &str) -> Option<ParsedLine>;
    /// Whole-file parsing (JSON documents). `None` = fall back to line mode.
    fn parse_whole(
        &self,
        _ctx: &WholeContext,
        _lines: &[String],
    ) -> Result<Option<Vec<ParsedLine>>> {
        Ok(None)
    }
}

/// Context for whole-file parsers.
pub struct WholeContext<'a> {
    pub evidence: &'a Evidence,
    pub first_id: EventId,
}

/// The built-in parser set, in preference order.
pub fn default_registry() -> Vec<Box<dyn Parser>> {
    vec![
        Box::new(auth::AuthLogParser),
        Box::new(syslog::SyslogParser),
        Box::new(json::JsonLinesParser),
        Box::new(json::JsonParser),
        Box::new(generic::GenericTimestampParser),
    ]
}

/// Parse one evidence unit into events, updating `stats`.
///
/// Strategy:
/// 1. If a whole-file parser claims the content, use it.
/// 2. Otherwise sniff the first lines, lock in the best parser for the
///    file, and parse line by line. Lines the locked-in parser rejects are
///    retried against the other parsers before being counted as skipped.
pub fn parse_evidence(
    evidence: &Evidence,
    lines: &[String],
    first_id: EventId,
    stats: &mut ParseStats,
) -> Result<Vec<Event>> {
    let registry = default_registry();
    let mut events = Vec::new();
    let mut next_id = first_id;

    // 1. Whole-file parsers (JSON documents).
    {
        let wctx = WholeContext { evidence, first_id };
        for parser in &registry {
            if let Some(parsed) = parser.parse_whole(&wctx, lines)? {
                for p in parsed {
                    stats.lines += 1;
                    match p {
                        ParsedLine::Event(mut e) => {
                            e.id = next_id;
                            next_id += 1;
                            stats.events += 1;
                            events.push(e);
                        }
                        ParsedLine::Skipped(reason) => bump_skip(stats, reason),
                    }
                }
                return Ok(events);
            }
        }
    }

    // 2. Pick a line parser by sniffing a sample of non-empty lines.
    let sample: Vec<&str> = lines
        .iter()
        .filter(|l| !l.trim().is_empty())
        .take(20)
        .map(|s| s.as_str())
        .collect();
    let mut best_idx = registry.len() - 1; // generic fallback
    let mut best_score = 0.0f32;
    for (i, parser) in registry.iter().enumerate() {
        if sample.is_empty() {
            break;
        }
        let score: f32 =
            sample.iter().map(|l| parser.sniff(l, evidence.kind)).sum::<f32>() / sample.len() as f32;
        if score > best_score {
            best_score = score;
            best_idx = i;
        }
    }
    // Require a minimum signal; otherwise the generic parser owns the file.
    if best_score < 0.35 {
        best_idx = registry.len() - 1;
    }

    // 3. Parse line by line.
    let order: Vec<usize> = std::iter::once(best_idx)
        .chain((0..registry.len()).filter(|&i| i != best_idx))
        .collect();
    for (line_no, line) in lines.iter().enumerate() {
        let line_no = line_no as u64 + 1;
        if line.trim().is_empty() {
            continue;
        }
        stats.lines += 1;
        let mut handled = false;
        for &i in &order {
            let ctx = ParseContext::new(evidence, line_no, next_id);
            match registry[i].parse_line(&ctx, line) {
                Some(ParsedLine::Event(mut e)) => {
                    e.id = next_id;
                    next_id += 1;
                    stats.events += 1;
                    events.push(e);
                    handled = true;
                    break;
                }
                Some(ParsedLine::Skipped(reason)) => {
                    bump_skip(stats, reason);
                    handled = true;
                    break;
                }
                None => continue,
            }
        }
        if !handled {
            // Should be unreachable: the generic parser accepts anything
            // with a timestamp. Count defensively anyway.
            bump_skip(stats, SkipReason::UnsupportedFormat);
        }
    }
    Ok(events)
}

fn bump_skip(stats: &mut ParseStats, reason: SkipReason) {
    match reason {
        SkipReason::UnsupportedFormat => stats.skipped_unsupported += 1,
        SkipReason::MalformedTimestamp => stats.skipped_bad_timestamp += 1,
        SkipReason::IncompleteRecord => stats.skipped_incomplete += 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_contains_all_built_in_parsers() {
        let names: Vec<_> = default_registry().iter().map(|p| p.name()).collect();
        for want in ["auth", "syslog", "jsonl", "json", "generic"] {
            assert!(names.contains(&want), "missing parser {want}");
        }
    }
}
