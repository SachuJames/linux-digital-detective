//! Rule engine.
//!
//! A [`Rule`] is a small, isolated, testable detector over the normalized
//! timeline. Rules never declare maliciousness: every [`Finding`] uses
//! cautious language ("unusual", "requires investigation") and carries the
//! evidence references needed to check its work.
//!
//! New rules are added by implementing [`Rule`] and registering it in
//! [`all_rules`]; nothing else changes.

pub mod auth;
pub mod network;
pub mod privilege;
pub mod process;

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::config::RuleConfig;
use crate::events::{Event, EventId, Severity};

/// Input to every rule: the time-sorted event timeline plus config.
pub struct RuleContext<'a> {
    pub events: &'a [Event],
    pub by_id: &'a HashMap<EventId, &'a Event>,
    pub config: &'a RuleConfig,
}

/// What a rule reports when it fires.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub rule_id: String,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    /// Event ids involved, in chronological order.
    pub event_ids: Vec<EventId>,
    /// Provenance pointers like "auth.log:421".
    pub evidence_refs: Vec<String>,
    /// Plain-language explanation of what was observed and why it is
    /// noteworthy. Must not claim proven maliciousness.
    pub explanation: String,
    /// Heuristic confidence in [0.0, 1.0].
    pub confidence: f32,
}

impl Finding {
    /// "auth.log:421" style reference from an event's provenance.
    pub fn evidence_ref(e: &Event) -> String {
        let file = e
            .provenance
            .file
            .rsplit('/')
            .next()
            .unwrap_or(&e.provenance.file);
        format!("{}:{}", file, e.provenance.line)
    }
}

pub trait Rule: Send + Sync {
    fn id(&self) -> &'static str;
    fn title(&self) -> &str;
    fn description(&self) -> &str;
    fn default_severity(&self) -> Severity;
    fn evaluate(&self, ctx: &RuleContext) -> Vec<Finding>;
}

/// All built-in rules.
pub fn all_rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(auth::RepeatedAuthFailures),
        Box::new(privilege::SudoOutsideTrustedPaths),
        Box::new(process::ProcessAfterLogin),
        Box::new(process::UnexpectedExecutableLocation),
        Box::new(network::RepeatedConnectionAttempts),
    ]
}

/// Build the lookup map rules use.
pub fn index_by_id(events: &[Event]) -> HashMap<EventId, &Event> {
    events.iter().map(|e| (e.id, e)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_lists_five_rules_with_unique_ids() {
        let rules = all_rules();
        assert_eq!(rules.len(), 5);
        let mut ids: Vec<_> = rules.iter().map(|r| r.id()).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), 5);
    }

    #[test]
    fn evidence_ref_uses_basename_and_line() {
        use crate::events::TimestampPrecision;
        use chrono::{FixedOffset, TimeZone};
        let dt = FixedOffset::east_opt(0)
            .unwrap()
            .timestamp_opt(1, 0)
            .unwrap();
        let e = Event::builder(7, dt, "auth", "/var/log/auth.log", 421)
            .precision(TimestampPrecision::Second)
            .message("m")
            .build();
        assert_eq!(Finding::evidence_ref(&e), "auth.log:421");
    }
}
