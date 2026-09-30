//! Investigation timeline: chronological ordering plus filtering.
//!
//! Events are sorted by `(timestamp, id)`. The `id` tiebreak keeps the
//! original parse order for events that share a timestamp, which is
//! deterministic and documented.

use chrono::{DateTime, FixedOffset};

use crate::events::{Event, EventType, Severity};

/// Filters for timeline queries. Every field is optional.
#[derive(Debug, Default, Clone)]
pub struct Filter {
    pub from: Option<DateTime<FixedOffset>>,
    pub to: Option<DateTime<FixedOffset>>,
    pub min_severity: Option<Severity>,
    pub types: Vec<EventType>,
    pub process: Option<String>,
    pub source: Option<String>,
}

impl Filter {
    pub fn matches(&self, e: &Event) -> bool {
        if let Some(from) = self.from {
            if e.timestamp < from {
                return false;
            }
        }
        if let Some(to) = self.to {
            if e.timestamp > to {
                return false;
            }
        }
        if let Some(min) = self.min_severity {
            if e.severity < min {
                return false;
            }
        }
        if !self.types.is_empty() && !self.types.contains(&e.event_type) {
            return false;
        }
        if let Some(p) = &self.process {
            let name = e.process_name.as_deref().unwrap_or("");
            if !name.to_ascii_lowercase().contains(&p.to_ascii_lowercase()) {
                return false;
            }
        }
        if let Some(s) = &self.source {
            if !e.provenance.file.contains(s.as_str()) {
                return false;
            }
        }
        true
    }
}

/// Build the timeline: filtered events in chronological order.
pub fn build_timeline<'a>(events: &'a [Event], filter: &Filter) -> Vec<&'a Event> {
    let mut out: Vec<&Event> = events.iter().filter(|e| filter.matches(e)).collect();
    // Stable sort: timestamp, then id (parse order) for ties.
    out.sort_by(|a, b| a.timestamp.cmp(&b.timestamp).then_with(|| a.id.cmp(&b.id)));
    out
}

/// The investigation window covered by a set of events.
pub fn window(
    events: &[&Event],
) -> Option<(DateTime<FixedOffset>, DateTime<FixedOffset>)> {
    let mut iter = events.iter();
    let first = iter.next()?;
    let mut min = first.timestamp;
    let mut max = first.timestamp;
    for e in iter {
        if e.timestamp < min {
            min = e.timestamp;
        }
        if e.timestamp > max {
            max = e.timestamp;
        }
    }
    Some((min, max))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::TimestampPrecision;
    use chrono::TimeZone;

    fn ev(id: u64, secs: i64, sev: Severity, proc: Option<&str>) -> Event {
        let dt = FixedOffset::east_opt(0)
            .unwrap()
            .timestamp_opt(secs, 0)
            .unwrap();
        let mut b = Event::builder(id, dt, "test", "f.log", id)
            .severity(sev)
            .precision(TimestampPrecision::Second)
            .message("m");
        if let Some(p) = proc {
            b = b.process_name(p);
        }
        b.build()
    }

    #[test]
    fn sorts_chronologically_with_stable_tiebreak() {
        let a = ev(2, 100, Severity::Info, None);
        let b = ev(1, 100, Severity::Info, None); // same ts, lower id
        let c = ev(3, 50, Severity::Info, None);
        let events = vec![a, b, c];
        let tl = build_timeline(&events, &Filter::default());
        let ids: Vec<u64> = tl.iter().map(|e| e.id).collect();
        assert_eq!(ids, vec![3, 1, 2]);
    }

    #[test]
    fn severity_filter_uses_threshold() {
        let events = vec![
            ev(1, 100, Severity::Info, None),
            ev(2, 101, Severity::Warning, None),
            ev(3, 102, Severity::Error, None),
        ];
        let f = Filter {
            min_severity: Some(Severity::Warning),
            ..Default::default()
        };
        let tl = build_timeline(&events, &f);
        assert_eq!(tl.len(), 2);
    }

    #[test]
    fn process_filter_matches_substring_case_insensitively() {
        let events = vec![
            ev(1, 100, Severity::Info, Some("sshd")),
            ev(2, 101, Severity::Info, Some("nginx")),
        ];
        let f = Filter {
            process: Some("SSH".into()),
            ..Default::default()
        };
        let tl = build_timeline(&events, &f);
        assert_eq!(tl.len(), 1);
        assert_eq!(tl[0].id, 1);
    }

    #[test]
    fn time_window_filters_inclusively() {
        let events = vec![
            ev(1, 100, Severity::Info, None),
            ev(2, 200, Severity::Info, None),
        ];
        let base = FixedOffset::east_opt(0).unwrap();
        let f = Filter {
            from: Some(base.timestamp_opt(150, 0).unwrap()),
            to: Some(base.timestamp_opt(200, 0).unwrap()),
            ..Default::default()
        };
        let tl = build_timeline(&events, &f);
        assert_eq!(tl.len(), 1);
        assert_eq!(tl[0].id, 2);
    }
}
