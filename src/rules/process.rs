//! Process rules.

use std::collections::HashMap;

use crate::events::{Event, EventType, Severity};
use crate::rules::{Finding, Rule, RuleContext};

fn is_login(e: &Event) -> bool {
    e.event_type == EventType::Auth
        && matches!(
            e.subtype.as_deref(),
            Some("ssh_accepted") | Some("session_opened")
        )
}

/// PROC-001: process activity shortly after a successful login.
///
/// After a login for user U, process-ish events attributed to U within the
/// configured window are gathered. Session startup normally spawns
/// processes, so the finding explicitly says this may be benign.
pub struct ProcessAfterLogin;

impl Rule for ProcessAfterLogin {
    fn id(&self) -> &'static str {
        "PROC-001"
    }

    fn title(&self) -> &str {
        "Process activity shortly after login"
    }

    fn description(&self) -> &str {
        "Collects process-related events for a user in the minutes after a \
         successful login. Normal session startup looks exactly like this, \
         so the finding asks whether the activity matches expectations."
    }

    fn default_severity(&self) -> Severity {
        Severity::Notice
    }

    fn evaluate(&self, ctx: &RuleContext) -> Vec<Finding> {
        let window = chrono::Duration::seconds(ctx.config.login_process_window_secs);
        let mut out = Vec::new();
        for login in ctx.events.iter().filter(|e| is_login(e)) {
            let user = match login.user.clone() {
                Some(u) => u,
                None => continue,
            };
            let end = login.timestamp + window;
            let procs: Vec<&Event> = ctx
                .events
                .iter()
                .filter(|e| {
                    e.id != login.id
                        && e.timestamp > login.timestamp
                        && e.timestamp <= end
                        && e.user.as_deref() == Some(user.as_str())
                        && e.pid.is_some()
                        && matches!(
                            e.event_type,
                            EventType::Process | EventType::System | EventType::Service
                        )
                })
                .collect();
            if procs.is_empty() {
                continue;
            }
            let mut ids = vec![login.id];
            ids.extend(procs.iter().map(|e| e.id));
            let refs: Vec<String> = std::iter::once(login)
                .chain(procs.iter().copied())
                .map(Finding::evidence_ref)
                .collect();
            let names: Vec<String> = procs
                .iter()
                .filter_map(|e| e.process_name.clone())
                .take(5)
                .collect();
            out.push(Finding {
                rule_id: self.id().to_string(),
                title: self.title().to_string(),
                description: self.description().to_string(),
                severity: self.default_severity(),
                event_ids: ids,
                evidence_refs: refs,
                explanation: format!(
                    "{} process-related event(s) for user '{user}' occurred within {} seconds \
                     after a successful login ({}). This is often normal session startup; \
                     check whether the processes ({}) match what this user normally runs. \
                     Requires investigation only if the activity looks out of place.",
                    procs.len(),
                    ctx.config.login_process_window_secs,
                    Finding::evidence_ref(login),
                    if names.is_empty() { "unknown".to_string() } else { names.join(", ") },
                ),
                confidence: 0.45,
            });
        }
        out
    }
}

/// PROC-002: process executable in an unexpected location.
///
/// Looks at process snapshot events (live collection) carrying an `exe`
/// path in metadata, and flags absolute paths outside the trusted
/// directories. Interpreters and deleted executables get a mention rather
/// than a separate severity bump.
pub struct UnexpectedExecutableLocation;

impl Rule for UnexpectedExecutableLocation {
    fn id(&self) -> &'static str {
        "PROC-002"
    }

    fn title(&self) -> &str {
        "Process executable in an unexpected location"
    }

    fn description(&self) -> &str {
        "Flags observed processes whose executable path lies outside the \
         expected system directories. Containers, user tooling, and language \
         runtimes can do this legitimately, so treat it as a lead, not a \
         verdict."
    }

    fn default_severity(&self) -> Severity {
        Severity::Warning
    }

    fn evaluate(&self, ctx: &RuleContext) -> Vec<Finding> {
        let mut seen: HashMap<String, Vec<&Event>> = HashMap::new();
        for e in ctx.events.iter().filter(|e| {
            matches!(
                e.subtype.as_deref(),
                Some("process_snapshot") | Some("process_created")
            )
        }) {
            if let Some(exe) = e.metadata.get("exe") {
                if exe.starts_with('/')
                    && !under_trusted(exe, &ctx.config.trusted_exec_dirs)
                {
                    seen.entry(exe.clone()).or_default().push(e);
                }
            }
        }
        seen.into_iter()
            .map(|(exe, events)| {
                let ids: Vec<_> = events.iter().map(|e| e.id).collect();
                let refs: Vec<_> = events.iter().map(|e| Finding::evidence_ref(e)).collect();
                Finding {
                    rule_id: self.id().to_string(),
                    title: self.title().to_string(),
                    description: self.description().to_string(),
                    severity: self.default_severity(),
                    event_ids: ids,
                    evidence_refs: refs,
                    explanation: format!(
                        "Process executable '{exe}' was observed outside the expected system \
                         directories. This can be legitimate (user tooling, containers, \
                         interpreters), but executables running from unusual paths deserve a \
                         closer look. Requires investigation."
                    ),
                    confidence: 0.55,
                }
            })
            .collect()
    }
}

fn under_trusted(path: &str, trusted: &[String]) -> bool {
    trusted
        .iter()
        .any(|d| path == d || path.starts_with(&format!("{d}/")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RuleConfig;
    use crate::events::TimestampPrecision;
    use crate::rules::index_by_id;
    use chrono::{FixedOffset, TimeZone};

    fn base(id: u64, secs: i64) -> crate::events::EventBuilder {
        let dt = FixedOffset::east_opt(0)
            .unwrap()
            .timestamp_opt(secs, 0)
            .unwrap();
        Event::builder(id, dt, "test", "t.log", id)
            .precision(TimestampPrecision::Second)
    }

    fn run(events: &[Event], rule: &dyn Rule) -> Vec<Finding> {
        let by_id = index_by_id(events);
        let cfg = RuleConfig::default();
        let ctx = RuleContext {
            events,
            by_id: &by_id,
            config: &cfg,
        };
        rule.evaluate(&ctx)
    }

    #[test]
    fn proc_001_links_login_to_later_process() {
        let login = base(1, 100)
            .event_type(EventType::Auth)
            .subtype("ssh_accepted")
            .user("deploy")
            .message("login")
            .build();
        let proc = base(2, 150)
            .event_type(EventType::Process)
            .user("deploy")
            .pid(9001)
            .process_name("python3")
            .message("proc")
            .build();
        let findings = run(&[login, proc], &ProcessAfterLogin);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "PROC-001");
        assert!(findings[0]
            .explanation
            .contains("often normal session startup"));
    }

    #[test]
    fn proc_001_quiet_without_followup_process() {
        let login = base(1, 100)
            .event_type(EventType::Auth)
            .subtype("ssh_accepted")
            .user("deploy")
            .message("login")
            .build();
        assert!(run(&[login], &ProcessAfterLogin).is_empty());
    }

    #[test]
    fn proc_002_flags_tmp_executable() {
        let mut e = base(1, 100)
            .event_type(EventType::Snapshot)
            .subtype("process_snapshot")
            .message("snap")
            .build();
        e.metadata.insert("exe".into(), "/tmp/.hidden/miner".into());
        let findings = run(&[e], &UnexpectedExecutableLocation);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "PROC-002");
    }

    #[test]
    fn proc_002_ignores_usr_bin() {
        let mut e = base(1, 100)
            .event_type(EventType::Snapshot)
            .subtype("process_snapshot")
            .message("snap")
            .build();
        e.metadata.insert("exe".into(), "/usr/bin/python3".into());
        assert!(run(&[e], &UnexpectedExecutableLocation).is_empty());
    }
}
