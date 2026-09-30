//! Authentication rules.

use crate::events::{Event, EventType, Severity};
use crate::rules::{Finding, Rule, RuleContext};

/// AUTH-001: repeated authentication failures followed by a success.
///
/// Groups failures by (user, source address); when a successful
/// authentication for the same key follows at least `threshold` failures
/// inside the window, the sequence is reported as unusual.
pub struct RepeatedAuthFailures;

fn is_failure(e: &Event) -> bool {
    e.event_type == EventType::Auth
        && matches!(
            e.subtype.as_deref(),
            Some("ssh_failed_password") | Some("auth_failure")
        )
}

fn is_success(e: &Event) -> bool {
    e.event_type == EventType::Auth
        && matches!(
            e.subtype.as_deref(),
            Some("ssh_accepted") | Some("session_opened")
        )
}

fn key(e: &Event) -> (String, String) {
    (
        e.user.clone().unwrap_or_default(),
        e.src_addr.map(|a| a.to_string()).unwrap_or_default(),
    )
}

impl Rule for RepeatedAuthFailures {
    fn id(&self) -> &'static str {
        "AUTH-001"
    }

    fn title(&self) -> &str {
        "Repeated authentication failures followed by success"
    }

    fn description(&self) -> &str {
        "Flags accounts/sources where several failed logins are followed by a \
         successful authentication inside a short window. The pattern is \
         noteworthy and requires investigation; it does not prove an attack."
    }

    fn default_severity(&self) -> Severity {
        Severity::Warning
    }

    fn evaluate(&self, ctx: &RuleContext) -> Vec<Finding> {
        let cfg = ctx.config;
        let mut out = Vec::new();

        // For each success, count failures for the same key in the window before it.
        for success in ctx.events.iter().filter(|e| is_success(e)) {
            let k = key(success);
            if k.0.is_empty() {
                continue;
            }
            let window_start =
                success.timestamp - chrono::Duration::seconds(cfg.auth_window_secs);
            let failures: Vec<&Event> = ctx
                .events
                .iter()
                .filter(|e| {
                    is_failure(e)
                        && key(e) == k
                        && e.timestamp >= window_start
                        && e.timestamp <= success.timestamp
                })
                .collect();
            if failures.len() < cfg.auth_failure_threshold {
                continue;
            }
            let mut ids: Vec<_> = failures.iter().map(|e| e.id).collect();
            ids.push(success.id);
            let refs: Vec<String> = failures
                .iter()
                .map(|e| Finding::evidence_ref(e))
                .chain(std::iter::once(Finding::evidence_ref(success)))
                .collect();
            let span =
                (success.timestamp - failures.first().unwrap().timestamp).num_seconds();
            out.push(Finding {
                rule_id: self.id().to_string(),
                title: self.title().to_string(),
                description: self.description().to_string(),
                severity: self.default_severity(),
                event_ids: ids,
                evidence_refs: refs,
                explanation: format!(
                    "{} failed authentication attempts for user '{}' from {} were followed by a \
                     successful authentication within {} seconds. This sequence is unusual and \
                     should be investigated (for example: was this the legitimate user retrying \
                     a password, or something else?). This finding alone does not establish \
                     malicious activity.",
                    failures.len(),
                    k.0,
                    if k.1.is_empty() { "an unknown source" } else { &k.1 },
                    span.max(0),
                ),
                confidence: 0.75,
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

    fn auth_ev(id: u64, secs: i64, subtype: &str, user: &str) -> Event {
        let dt = FixedOffset::east_opt(0)
            .unwrap()
            .timestamp_opt(secs, 0)
            .unwrap();
        Event::builder(id, dt, "auth", "auth.log", id)
            .precision(TimestampPrecision::Second)
            .event_type(EventType::Auth)
            .subtype(subtype)
            .severity(Severity::Warning)
            .user(user)
            .src_addr("203.0.113.7".parse::<IpAddr>().unwrap())
            .message("m")
            .build()
    }

    #[test]
    fn fires_on_failures_then_success() {
        let events = vec![
            auth_ev(1, 100, "ssh_failed_password", "root"),
            auth_ev(2, 103, "ssh_failed_password", "root"),
            auth_ev(3, 106, "ssh_failed_password", "root"),
            auth_ev(4, 109, "ssh_accepted", "root"),
        ];
        let by_id = index_by_id(&events);
        let cfg = RuleConfig::default();
        let ctx = RuleContext {
            events: &events,
            by_id: &by_id,
            config: &cfg,
        };
        let findings = RepeatedAuthFailures.evaluate(&ctx);
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert_eq!(f.rule_id, "AUTH-001");
        assert_eq!(f.event_ids, vec![1, 2, 3, 4]);
        assert!(
            f.explanation.contains("requires investigation")
                || f.explanation.contains("should be investigated")
        );
        assert!(!f
            .explanation
            .to_ascii_lowercase()
            .contains("attack occurred"));
    }

    #[test]
    fn stays_quiet_below_threshold() {
        let events = vec![
            auth_ev(1, 100, "ssh_failed_password", "root"),
            auth_ev(2, 103, "ssh_failed_password", "root"),
            auth_ev(3, 106, "ssh_accepted", "root"),
        ];
        let by_id = index_by_id(&events);
        let cfg = RuleConfig::default();
        let ctx = RuleContext {
            events: &events,
            by_id: &by_id,
            config: &cfg,
        };
        assert!(RepeatedAuthFailures.evaluate(&ctx).is_empty());
    }

    #[test]
    fn different_source_does_not_group() {
        let mut events = vec![
            auth_ev(1, 100, "ssh_failed_password", "root"),
            auth_ev(2, 103, "ssh_failed_password", "root"),
            auth_ev(3, 106, "ssh_failed_password", "root"),
        ];
        let mut ok = auth_ev(4, 109, "ssh_accepted", "root");
        ok.src_addr = Some("198.51.100.9".parse().unwrap());
        events.push(ok);
        let by_id = index_by_id(&events);
        let cfg = RuleConfig::default();
        let ctx = RuleContext {
            events: &events,
            by_id: &by_id,
            config: &cfg,
        };
        assert!(RepeatedAuthFailures.evaluate(&ctx).is_empty());
    }
}
