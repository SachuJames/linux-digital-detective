//! Privilege rules.

use crate::events::{EventType, Severity};
use crate::rules::{Finding, Rule, RuleContext};

/// PRIV-001: sudo invocation of an executable outside expected system paths.
///
/// Running privileged commands from /tmp, a home directory, or other
/// unusual locations is worth a look: legitimate admin tooling usually
/// lives under /usr/bin, /usr/sbin, /bin, /sbin, /usr/local/* or /opt.
pub struct SudoOutsideTrustedPaths;

fn command_executable(body: &str) -> Option<String> {
    // Body form after envelope strip: "deploy : TTY=pts/0 ; COMMAND=/usr/bin/id arg"
    let idx = body.find("COMMAND=")?;
    let cmd = body[idx + "COMMAND=".len()..].trim();
    cmd.split_whitespace().next().map(|s| s.to_string())
}

fn under_trusted(path: &str, trusted: &[String]) -> bool {
    trusted.iter().any(|d| {
        path == d || path.starts_with(&format!("{d}/"))
    })
}

impl Rule for SudoOutsideTrustedPaths {
    fn id(&self) -> &'static str {
        "PRIV-001"
    }

    fn title(&self) -> &str {
        "Privileged command from an unusual location"
    }

    fn description(&self) -> &str {
        "Flags sudo invocations whose executable lives outside the expected \
         system directories. Worth investigating; admins do occasionally run \
         one-off tooling from elsewhere, so this is not proof of wrongdoing."
    }

    fn default_severity(&self) -> Severity {
        Severity::Warning
    }

    fn evaluate(&self, ctx: &RuleContext) -> Vec<Finding> {
        let mut out = Vec::new();
        for e in ctx.events.iter().filter(|e| {
            e.event_type == EventType::Privilege && e.subtype.as_deref() == Some("sudo_command")
        }) {
            let Some(exe) = command_executable(&e.message) else {
                continue;
            };
            if !exe.starts_with('/') || under_trusted(&exe, &ctx.config.trusted_exec_dirs) {
                continue;
            }
            out.push(Finding {
                rule_id: self.id().to_string(),
                title: self.title().to_string(),
                description: self.description().to_string(),
                severity: self.default_severity(),
                event_ids: vec![e.id],
                evidence_refs: vec![Finding::evidence_ref(e)],
                explanation: format!(
                    "User '{}' ran '{}' via sudo from '{}', which is outside the expected system \
                     directories ({}). Unusual executable locations for privileged commands \
                     merit a closer look, but there can be legitimate reasons (one-off admin \
                     scripts, mounted tooling). Requires investigation.",
                    e.user.as_deref().unwrap_or("unknown"),
                    exe,
                    parent_of(&exe),
                    ctx.config.trusted_exec_dirs.join(", "),
                ),
                confidence: 0.6,
            });
        }
        out
    }
}

fn parent_of(path: &str) -> &str {
    path.rsplit_once('/').map(|(p, _)| if p.is_empty() { "/" } else { p }).unwrap_or(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::Event;
    use crate::config::RuleConfig;
    use crate::events::TimestampPrecision;
    use crate::rules::index_by_id;
    use chrono::{FixedOffset, TimeZone};

    fn sudo_ev(id: u64, command: &str) -> Event {
        let dt = FixedOffset::east_opt(0)
            .unwrap()
            .timestamp_opt(100, 0)
            .unwrap();
        Event::builder(id, dt, "auth", "auth.log", id)
            .precision(TimestampPrecision::Second)
            .event_type(EventType::Privilege)
            .subtype("sudo_command")
            .user("deploy")
            .message(format!("deploy : TTY=pts/0 ; COMMAND={command}"))
            .build()
    }

    fn run(events: &[Event]) -> Vec<Finding> {
        let by_id = index_by_id(events);
        let cfg = RuleConfig::default();
        let ctx = RuleContext { events, by_id: &by_id, config: &cfg };
        SudoOutsideTrustedPaths.evaluate(&ctx)
    }

    #[test]
    fn flags_sudo_from_tmp() {
        let events = vec![sudo_ev(1, "/tmp/cleanup.sh --force")];
        let findings = run(&events);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "PRIV-001");
        assert!(findings[0].explanation.contains("Requires investigation"));
    }

    #[test]
    fn ignores_sudo_from_usr_bin() {
        let events = vec![sudo_ev(1, "/usr/bin/systemctl restart app")];
        assert!(run(&events).is_empty());
    }
}
