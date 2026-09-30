//! Generic fallback parser.
//!
//! Accepts any line that starts with a recognizable timestamp and turns it
//! into a low-confidence event. This is the parser of last resort: it keeps
//! evidence usable instead of dropping it, but marks what it produced as
//! `unknown` type with low confidence so downstream consumers know the
//! provenance is weak.

use crate::events::Event;
use crate::evidence::{EvidenceKind, SkipReason};
use crate::parsers::timestamps::parse_at_start;
use crate::parsers::{ParseContext, ParsedLine, Parser};

pub struct GenericTimestampParser;

impl Parser for GenericTimestampParser {
    fn name(&self) -> &'static str {
        "generic"
    }

    fn description(&self) -> &'static str {
        "fallback: any line starting with a recognizable timestamp"
    }

    fn sniff(&self, line: &str, _kind: EvidenceKind) -> f32 {
        match parse_at_start(line) {
            Some(Ok(_)) => 0.3,
            Some(Err(_)) => 0.1,
            None => 0.0,
        }
    }

    fn parse_line(&self, ctx: &ParseContext, line: &str) -> Option<ParsedLine> {
        let parsed = match parse_at_start(line) {
            Some(Ok(p)) => p,
            Some(Err(_)) => return Some(ParsedLine::Skipped(SkipReason::MalformedTimestamp)),
            None => return Some(ParsedLine::Skipped(SkipReason::UnsupportedFormat)),
        };
        let rest = line[parsed.consumed..].trim().to_string();
        if rest.is_empty() {
            return Some(ParsedLine::Skipped(SkipReason::IncompleteRecord));
        }
        let event = Event::builder(ctx.event_id, parsed.dt, self.name(), ctx.label(), ctx.line_no)
            .precision(parsed.precision)
            .partial_timestamp(parsed.partial)
            .raw_timestamp(parsed.raw.clone())
            .offset_explicit(parsed.offset_explicit)
            .message(rest)
            .confidence(0.3)
            .build();
        Some(ParsedLine::Event(event))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::Evidence;
    use std::path::PathBuf;

    fn ev() -> Evidence {
        Evidence {
            path: PathBuf::from("app.log"),
            label: "app.log".into(),
            kind: EvidenceKind::Unknown,
            is_stdin: false,
        }
    }

    #[test]
    fn accepts_iso_prefixed_line() {
        let e = ev();
        let p = GenericTimestampParser;
        let ctx = ParseContext::new(&e, 1, 1);
        match p.parse_line(&ctx, "2026-09-30 14:02:11 something happened") {
            Some(ParsedLine::Event(ev)) => {
                assert_eq!(ev.message, "something happened");
                assert_eq!(ev.confidence, 0.3);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn timestamp_only_line_is_incomplete() {
        let e = ev();
        let p = GenericTimestampParser;
        let ctx = ParseContext::new(&e, 1, 1);
        assert!(matches!(
            p.parse_line(&ctx, "2026-09-30 14:02:11"),
            Some(ParsedLine::Skipped(SkipReason::IncompleteRecord))
        ));
    }

    #[test]
    fn dateless_line_is_unsupported() {
        let e = ev();
        let p = GenericTimestampParser;
        let ctx = ParseContext::new(&e, 1, 1);
        assert!(matches!(
            p.parse_line(&ctx, "no timestamp here at all"),
            Some(ParsedLine::Skipped(SkipReason::UnsupportedFormat))
        ));
    }
}
