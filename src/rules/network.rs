//! Network rules.

use std::collections::HashMap;

use crate::events::{Event, EventType, Severity};
use crate::rules::{Finding, Rule, RuleContext};

/// NET-001: repeated connection attempts to the same destination.
///
/// Groups network connection observations by (destination, port) and flags
/// groups with at least `connection_attempt_threshold` observations inside
/// the window. Port scans and aggressive retries both look like this, and
/// so do some legitimate polling loops, so the language stays cautious.
pub struct RepeatedConnectionAttempts;

fn is_connection(e: &Event) -> bool {
    e.event_type == EventType::Network
        && matches!(
            e.subtype.as_deref(),
            Some("connection_observed") | Some("connection_attempt")
        )
}

impl Rule for RepeatedConnectionAttempts {
    fn id(&self) -> &'static str {
        "NET-001"
    }

    fn title(&self) -> &str {
        "Repeated connection attempts to the same destination"
    }

    fn description(&self) -> &str {
        "Flags destinations that received many connection observations in a \
         short window. Can indicate scanning or retry storms, but also \
         matches legitimate polling; investigate before concluding anything."
    }

    fn default_severity(&self) -> Severity {
        Severity::Warning
    }

    fn evaluate(&self, ctx: &RuleContext) -> Vec<Finding> {
        let window = chrono::Duration::seconds(ctx.config.connection_window_secs);
        let mut groups: HashMap<(String, String), Vec<&Event>> = HashMap::new();
        for e in ctx.events.iter().filter(|e| is_connection(e)) {
            let dst = e.dst_addr.map(|a| a.to_string()).unwrap_or_default();
            let port = e.port.map(|p| p.to_string()).unwrap_or_default();
            groups.entry((dst, port)).or_default().push(e);
        }
        let mut out = Vec::new();
        for ((dst, port), mut events) in groups {
            if dst.is_empty() {
                continue;
            }
            events.sort_by_key(|a| a.timestamp);
            // Sliding window: any window-sized slice with enough hits fires once.
            let mut fired = false;
            for i in 0..events.len() {
                let start = events[i].timestamp;
                let count = events[i..]
                    .iter()
                    .take_while(|e| e.timestamp - start <= window)
                    .count();
                if count >= ctx.config.connection_attempt_threshold {
                    fired = true;
                    break;
                }
            }
            if !fired {
                continue;
            }
            let ids: Vec<_> = events.iter().map(|e| e.id).collect();
            let refs: Vec<_> =
                events.iter().copied().map(Finding::evidence_ref).collect();
            out.push(Finding {
                rule_id: self.id().to_string(),
                title: self.title().to_string(),
                description: self.description().to_string(),
                severity: self.default_severity(),
                event_ids: ids,
                evidence_refs: refs.clone(),
                explanation: format!(
                    "{} connection observations to {}:{} within {} seconds (first seen at {}). \
                     This volume of connection attempts is unusual and requires investigation: \
                     it can indicate scanning or a retry storm, but legitimate polling loops \
                     look similar. Correlate with the source processes before drawing conclusions.",
                    events.len(),
                    dst,
                    if port.is_empty() { "?" } else { &port },
                    ctx.config.connection_window_secs,
                    refs.first().map(|s| s.as_str()).unwrap_or("?"),
                ),
                confidence: 0.6,
            });
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RuleConfig;
    use crate::events::TimestampPrecision;
    use crate::rules::index_by_id;
    use chrono::{FixedOffset, TimeZone};
    use std::net::IpAddr;

    fn conn(id: u64, secs: i64) -> Event {
        let dt = FixedOffset::east_opt(0)
            .unwrap()
            .timestamp_opt(secs, 0)
            .unwrap();
        Event::builder(id, dt, "live", "<live>", 0)
            .precision(TimestampPrecision::Second)
            .event_type(EventType::Network)
            .subtype("connection_observed")
            .dst_addr("203.0.113.99".parse::<IpAddr>().unwrap())
            .port(22)
            .message("conn")
            .build()
    }

    fn run(events: &[Event]) -> Vec<Finding> {
        let by_id = index_by_id(events);
        let cfg = RuleConfig::default();
        let ctx = RuleContext {
            events,
            by_id: &by_id,
            config: &cfg,
        };
        RepeatedConnectionAttempts.evaluate(&ctx)
    }

    #[test]
    fn fires_on_many_attempts_in_window() {
        let events: Vec<_> = (0..12).map(|i| conn(i, 100 + i as i64 * 10)).collect();
        let findings = run(&events);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "NET-001");
        assert!(findings[0].explanation.contains("requires investigation"));
    }

    #[test]
    fn quiet_below_threshold() {
        let events: Vec<_> = (0..5).map(|i| conn(i, 100 + i as i64 * 10)).collect();
        assert!(run(&events).is_empty());
    }

    #[test]
    fn spread_out_attempts_do_not_fire() {
        // 12 attempts, but one per hour: never 10 within 300 seconds.
        let events: Vec<_> = (0..12).map(|i| conn(i, i as i64 * 3600)).collect();
        assert!(run(&events).is_empty());
    }
}
