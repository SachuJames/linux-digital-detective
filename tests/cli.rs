//! CLI tests: drive the built binary as a black box.
//!
//! Uses only the synthetic fixtures in `tests/fixtures/`. The `live` test
//! reads the test machine's own /proc (read-only), which is the point of
//! live mode; it never touches the machine's logs.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_lddetective"))
}

fn fixtures() -> String {
    format!("{}/tests/fixtures", env!("CARGO_MANIFEST_DIR"))
}

fn run(args: &[&str]) -> std::process::Output {
    Command::new(bin())
        .args(args)
        .arg("--no-color")
        .output()
        .expect("binary must run")
}

fn out(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn version_exits_zero_and_names_binary() {
    let o = run(&["version"]);
    assert_eq!(o.status.code(), Some(0));
    assert!(out(&o).contains("lddetective"));
}

#[test]
fn rules_list_shows_built_in_rules() {
    let o = run(&["rules", "list"]);
    assert_eq!(o.status.code(), Some(0));
    let text = out(&o);
    for id in ["AUTH-001", "PRIV-001", "PROC-001", "PROC-002", "NET-001"] {
        assert!(text.contains(id), "rules list missing {id}");
    }
}

#[test]
fn analyze_fixtures_exits_zero() {
    let o = run(&["analyze", &fixtures()]);
    assert_eq!(o.status.code(), Some(0));
    let text = out(&o);
    assert!(text.contains("Files: 5"));
    assert!(text.contains("Findings:"));
}

#[test]
fn analyze_json_is_parseable() {
    let o = run(&["analyze", &fixtures(), "--format", "json"]);
    assert_eq!(o.status.code(), Some(0));
    let v: serde_json::Value = serde_json::from_str(&out(&o)).unwrap();
    assert!(v["events"].as_u64().unwrap() >= 30);
}

#[test]
fn analyze_missing_file_is_evidence_error() {
    // Exit code 3 = evidence collection failure.
    let o = run(&["analyze", "/does/not/exist.log"]);
    assert_eq!(o.status.code(), Some(3));
}

#[test]
fn analyze_bad_format_is_usage_error() {
    // Exit code 2 = usage error.
    let o = run(&["analyze", &fixtures(), "--format", "xml"]);
    assert_eq!(o.status.code(), Some(2));
}

#[test]
fn timeline_text_shows_events() {
    let o = run(&["timeline", &fixtures()]);
    assert_eq!(o.status.code(), Some(0));
    assert!(out(&o).contains("sshd"));
}

#[test]
fn timeline_severity_filter_works() {
    let all = run(&["timeline", &fixtures()]);
    let filtered = run(&["timeline", &fixtures(), "--severity", "warning"]);
    assert_eq!(filtered.status.code(), Some(0));
    assert!(out(&filtered).lines().count() < out(&all).lines().count());
}

#[test]
fn timeline_type_filter_works() {
    let o = run(&["timeline", &fixtures(), "--type", "network"]);
    assert_eq!(o.status.code(), Some(0));
    for line in out(&o).lines() {
        assert!(line.contains("network"), "unexpected line: {line}");
    }
}

#[test]
fn timeline_jsonl_is_one_event_per_line() {
    let o = run(&["timeline", &fixtures(), "--format", "jsonl"]);
    assert_eq!(o.status.code(), Some(0));
    let mut events = 0;
    for line in out(&o).lines() {
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        if v["kind"] == "event" {
            events += 1;
            assert!(v["event"]["timestamp"].is_string());
        }
    }
    assert!(events > 30, "saw {events} event lines");
}

#[test]
fn timeline_bad_time_is_usage_error() {
    let o = run(&["timeline", &fixtures(), "--from", "not-a-time"]);
    assert_eq!(o.status.code(), Some(2));
}

#[test]
fn report_json_has_findings() {
    let o = run(&["report", &fixtures(), "--format", "json"]);
    assert_eq!(o.status.code(), Some(0));
    let v: serde_json::Value = serde_json::from_str(&out(&o)).unwrap();
    let findings = v["findings"].as_array().unwrap();
    let ids: Vec<_> = findings
        .iter()
        .map(|f| f["rule_id"].as_str().unwrap())
        .collect();
    assert!(ids.contains(&"AUTH-001"));
    assert!(ids.contains(&"PRIV-001"));
    assert!(ids.contains(&"NET-001"));
}

#[test]
fn report_csv_has_header_and_rows() {
    let o = run(&["report", &fixtures(), "--format", "csv"]);
    assert_eq!(o.status.code(), Some(0));
    let text = out(&o);
    assert!(text.starts_with("id,timestamp,"));
    assert!(text.lines().count() > 30);
}

#[test]
fn inspect_shows_per_file_parsers() {
    let o = run(&["inspect", &fixtures()]);
    assert_eq!(o.status.code(), Some(0));
    let text = out(&o);
    assert!(text.contains("parser: auth"));
    assert!(text.contains("parser: syslog"));
    assert!(text.contains("parser: json"));
}

#[test]
fn stdin_input_is_supported() {
    let mut child = Command::new(bin())
        .args(["timeline", "-", "--format", "jsonl", "--no-color"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("binary must run");
    let log = concat!(
        "Sep 30 14:02:11 web01 sshd[8123]: Failed password for root from 203.0.113.7 port 51234 ssh2\n",
        "Sep 30 14:02:20 web01 sshd[8123]: Accepted password for root from 203.0.113.7 port 51234 ssh2\n",
    );
    child
        .stdin
        .take()
        .unwrap()
        .write_all(log.as_bytes())
        .unwrap();
    let o = child.wait_with_output().unwrap();
    assert_eq!(o.status.code(), Some(0));
    let text = out(&o);
    let events: Vec<_> = text
        .lines()
        .filter(|l| l.contains("\"kind\":\"event\""))
        .collect();
    assert_eq!(events.len(), 2);
    assert!(events.iter().all(|l| l.contains("\"event_type\":\"auth\"")));
}

#[test]
fn live_mode_streams_snapshot_changes_with_duration() {
    // Runs against the test machine's own /proc (read-only). Short run.
    let o = run(&["live", "--interval", "1", "--duration", "3"]);
    assert_eq!(o.status.code(), Some(0));
}

#[test]
fn findings_language_is_cautious() {
    // The tool must never claim an attack occurred.
    let o = run(&["report", &fixtures()]);
    let text = out(&o).to_lowercase();
    assert!(!text.contains("you were attacked"));
    assert!(!text.contains("breach confirmed"));
    assert!(!text.contains("intrusion detected"));
}
