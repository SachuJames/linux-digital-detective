//! End-to-end pipeline test on synthetic fixtures:
//!
//! evidence -> parse -> normalize -> timeline -> correlate -> rules -> report
//!
//! Uses only the synthetic fixtures in `tests/fixtures/`. Never touches the
//! machine's real logs.

use std::collections::HashMap;

use lddetective_lib::config::Config;
use lddetective_lib::correlation;
use lddetective_lib::evidence;
use lddetective_lib::parsers;
use lddetective_lib::reporting::{self, Format, Investigation};
use lddetective_lib::rules;
use lddetective_lib::storage::EventStore;
use lddetective_lib::timeline;

fn fixture(name: &str) -> String {
    format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))
}

fn run_pipeline() -> Investigation {
    let cfg = Config::default();
    let dir = format!("{}/tests/fixtures", env!("CARGO_MANIFEST_DIR"));
    let units = evidence::collect(&dir, &dir).expect("fixtures must be collectable");
    assert!(!units.is_empty());

    let mut store = EventStore::default();
    let mut files = Vec::new();
    let mut first_id = 1u64;
    for unit in &units {
        let mut too_long = 0;
        let lines = evidence::read_text(unit, &mut too_long).unwrap();
        let mut stats = evidence::ParseStats::default();
        let parsed = parsers::parse_evidence(unit, &lines, first_id, &mut stats).unwrap();
        stats.skipped_too_long = too_long;
        first_id += parsed.events.len() as u64 + stats.skipped_total();
        store.extend(parsed.events);
        files.push(reporting::FileReport {
            file: unit.label.clone(),
            parser: parsed.parser,
            stats,
        });
    }

    let mut events: Vec<_> = store.events().to_vec();
    events.sort_by(|a, b| {
        a.timestamp
            .cmp(&b.timestamp)
            .then_with(|| a.id.cmp(&b.id))
    });
    let correlations = correlation::correlate(&events, correlation::DEFAULT_WINDOW_SECS);
    let by_id: HashMap<_, _> = events.iter().map(|e| (e.id, e)).collect();
    let ctx = rules::RuleContext {
        events: &events,
        by_id: &by_id,
        config: &cfg.rules,
    };
    let mut findings = Vec::new();
    for rule in rules::all_rules() {
        findings.extend(rule.evaluate(&ctx));
    }
    let refs: Vec<_> = events.iter().collect();
    let window = timeline::window(&refs);
    Investigation {
        events,
        findings,
        correlations,
        files,
        window,
        generated_at: reporting::now(),
        evicted: 0,
    }
}

#[test]
fn pipeline_parses_all_fixtures() {
    let inv = run_pipeline();
    // auth(9) + syslog(6) + app log(5 of 6) + json(3) + jsonl(11 of 12)
    assert!(inv.events.len() >= 30, "got {} events", inv.events.len());
    assert_eq!(inv.files.len(), 5);
    // The two noise lines were skipped, not silently dropped.
    let skipped: u64 = inv.files.iter().map(|f| f.stats.skipped_total()).sum();
    assert!(skipped >= 2, "skipped was {skipped}");
}

#[test]
fn pipeline_finds_auth_001_in_fixture() {
    let inv = run_pipeline();
    let auth = inv
        .findings
        .iter()
        .find(|f| f.rule_id == "AUTH-001")
        .expect("AUTH-001 should fire on auth_sample.log");
    assert_eq!(auth.event_ids.len(), 4);
    assert!(auth.evidence_refs.iter().all(|r| r.starts_with("auth_sample.log")));
}

#[test]
fn pipeline_finds_priv_001_in_fixture() {
    let inv = run_pipeline();
    assert!(
        inv.findings.iter().any(|f| f.rule_id == "PRIV-001"),
        "sudo from /tmp should fire PRIV-001"
    );
}

#[test]
fn pipeline_finds_net_001_in_fixture() {
    let inv = run_pipeline();
    assert!(
        inv.findings.iter().any(|f| f.rule_id == "NET-001"),
        "12 rapid connections to 203.0.113.99:22 should fire NET-001"
    );
}

#[test]
fn timeline_is_chronological() {
    let inv = run_pipeline();
    let tl = timeline::build_timeline(&inv.events, &timeline::Filter::default());
    for w in tl.windows(2) {
        assert!(w[0].timestamp <= w[1].timestamp);
    }
}

#[test]
fn report_renders_all_formats() {
    let inv = run_pipeline();
    let text = reporting::render(&inv, Format::Text, false);
    assert!(text.contains("AUTH-001"));
    assert!(text.contains("PARSING STATISTICS"));

    let json = reporting::render(&inv, Format::Json, false);
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(v["findings"].as_array().unwrap().len() >= 3);

    let jsonl = reporting::render(&inv, Format::JsonLines, false);
    assert!(jsonl.lines().count() >= inv.events.len() + 1);

    let csv = reporting::render(&inv, Format::Csv, false);
    assert!(csv.starts_with("id,timestamp,"));
    assert_eq!(csv.lines().count(), inv.events.len() + 1);
}
