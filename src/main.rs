//! lddetective: local-first Linux incident investigation.
//!
//! See the library crate for the layered pipeline:
//! evidence -> parsers -> events -> timeline -> correlation -> rules -> reporting.

use std::collections::HashMap;
use std::io::IsTerminal as _;
use std::time::{Duration, Instant};

use chrono::{DateTime, FixedOffset};
use clap::Parser as _;

use lddetective_lib::cli::{Cli, Commands, RulesAction};
use lddetective_lib::collectors;
use lddetective_lib::config;
use lddetective_lib::correlation;
use lddetective_lib::errors::{Error, ExitCode, Result};
use lddetective_lib::events::{Event, EventType, Severity};
use lddetective_lib::evidence;
use lddetective_lib::linux::{self, sanitize_for_terminal};
use lddetective_lib::parsers::{self, timestamps};
use lddetective_lib::reporting::{self, FileReport, Format, Investigation};
use lddetective_lib::rules;
use lddetective_lib::storage::EventStore;
use lddetective_lib::timeline;

fn main() {
    let code: ExitCode = match run() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("lddetective: error: {e}");
            ExitCode::from(e)
        }
    };
    std::process::exit(code as i32);
}

fn run() -> Result<ExitCode> {
    let cli = Cli::parse();
    let cfg = config::load(cli.config.as_deref())?;
    let color = !cli.no_color
        && std::env::var("NO_COLOR").is_err()
        && cfg.output.color
        && !cli.quiet
        && std::io::stdout().is_terminal();

    match &cli.command {
        Commands::Version => {
            println!("lddetective {}", env!("CARGO_PKG_VERSION"));
            Ok(ExitCode::Success)
        }
        Commands::Rules(args) => match args.action {
            RulesAction::List => {
                for rule in rules::all_rules() {
                    println!("{}  [{}]", rule.id(), rule.default_severity().as_str());
                    println!("    {}", rule.title());
                    println!("    {}", rule.description());
                    println!();
                }
                Ok(ExitCode::Success)
            }
        },
        Commands::Live(args) => cmd_live(args, cli.quiet),
        Commands::Analyze(args) => {
            let inv = build_investigation(&args.input, &cfg)?;
            let format = args.format.as_deref().unwrap_or("text").parse::<Format>()?;
            match format {
                Format::Text | Format::Json => {
                    print_analyze(&inv, &args.input, format)?
                }
                _ => {
                    return Err(Error::Usage(
                        "analyze supports formats: text, json".to_string(),
                    ))
                }
            }
            Ok(ExitCode::Success)
        }
        Commands::Timeline(args) => {
            let inv = build_investigation(&args.input, &cfg)?;
            let filter = build_filter(args)?;
            let format = args.format.as_deref().unwrap_or("text").parse::<Format>()?;
            let events: Vec<&Event> = timeline::build_timeline(&inv.events, &filter);
            match format {
                Format::Text => {
                    for e in &events {
                        println!("{}", timeline_line(e, color));
                    }
                    if !cli.quiet {
                        eprintln!("{} events shown", events.len());
                    }
                }
                _ => {
                    let owned: Vec<Event> = events.into_iter().cloned().collect();
                    let sub = Investigation {
                        events: owned,
                        ..inv
                    };
                    print!("{}", reporting::render(&sub, format, color));
                }
            }
            Ok(ExitCode::Success)
        }
        Commands::Report(args) => {
            let inv = build_investigation(&args.input, &cfg)?;
            let format = args.format.as_deref().unwrap_or("text").parse::<Format>()?;
            print!("{}", reporting::render(&inv, format, color));
            Ok(ExitCode::Success)
        }
        Commands::Inspect(args) => {
            let inv = build_investigation(&args.input, &cfg)?;
            let format = args.format.as_deref().unwrap_or("text").parse::<Format>()?;
            match format {
                Format::Text => print_inspect_text(&inv),
                Format::Json => {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&inv.files).unwrap_or_default()
                    )
                }
                _ => {
                    return Err(Error::Usage(
                        "inspect supports formats: text, json".to_string(),
                    ))
                }
            }
            Ok(ExitCode::Success)
        }
    }
}

/// Run the full pipeline: evidence -> events -> timeline -> correlation -> rules.
fn build_investigation(input: &str, cfg: &config::Config) -> Result<Investigation> {
    let units = evidence::collect(input, input)?;
    let mut store = EventStore::default();
    let mut files = Vec::new();
    let mut first_id: u64 = 1;

    for unit in &units {
        let mut too_long = 0u64;
        let lines = evidence::read_text(unit, &mut too_long)?;
        let mut stats = evidence::ParseStats::default();
        let parsed = parsers::parse_evidence(unit, &lines, first_id, &mut stats)?;
        stats.skipped_too_long = too_long;
        first_id += parsed.events.len() as u64 + stats.skipped_total();
        store.extend(parsed.events);
        files.push(FileReport {
            file: unit.label.clone(),
            parser: parsed.parser,
            stats,
        });
    }

    if store.is_empty() {
        return Err(Error::Evidence(format!(
            "no events could be parsed from {input}"
        )));
    }

    let mut events: Vec<Event> = store.events().to_vec();
    events.sort_by(|a, b| a.timestamp.cmp(&b.timestamp).then_with(|| a.id.cmp(&b.id)));

    let correlations =
        correlation::correlate(&events, correlation::DEFAULT_WINDOW_SECS);
    let by_id = rules::index_by_id(&events);
    let rule_ctx = rules::RuleContext {
        events: &events,
        by_id: &by_id,
        config: &cfg.rules,
    };
    let mut findings = Vec::new();
    for rule in rules::all_rules() {
        findings.extend(rule.evaluate(&rule_ctx));
    }
    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.rule_id.cmp(&b.rule_id))
    });

    let refs: Vec<&Event> = events.iter().collect();
    let window = timeline::window(&refs);

    Ok(Investigation {
        events,
        findings,
        correlations,
        files,
        window,
        generated_at: reporting::now(),
        evicted: store.evicted,
    })
}

fn build_filter(args: &lddetective_lib::cli::TimelineArgs) -> Result<timeline::Filter> {
    let mut filter = timeline::Filter::default();
    if let Some(s) = &args.from {
        filter.from = Some(parse_time(s)?);
    }
    if let Some(s) = &args.to {
        filter.to = Some(parse_time(s)?);
    }
    if let Some(s) = &args.severity {
        filter.min_severity = Some(parse_severity(s)?);
    }
    for t in &args.r#type {
        filter.types.push(parse_event_type(t)?);
    }
    filter.process = args.process.clone();
    filter.source = args.source.clone();
    Ok(filter)
}

fn parse_time(s: &str) -> Result<DateTime<FixedOffset>> {
    let t = s.trim();
    match timestamps::parse_at_start(t) {
        Some(Ok(p)) if p.consumed == t.len() => Ok(p.dt),
        _ => Err(Error::Usage(format!(
            "could not parse time '{s}'; try '2026-09-30 14:02:11' or RFC 3339"
        ))),
    }
}

fn parse_severity(s: &str) -> Result<Severity> {
    let sev = Severity::from_name(s);
    if sev == Severity::Unknown && !s.eq_ignore_ascii_case("unknown") {
        return Err(Error::Usage(format!(
            "unknown severity '{s}'; expected debug, info, notice, warning, error, or critical"
        )));
    }
    Ok(sev)
}

fn parse_event_type(s: &str) -> Result<EventType> {
    let t = EventType::from_name(s);
    if t == EventType::Unknown && !s.eq_ignore_ascii_case("unknown") {
        return Err(Error::Usage(format!("unknown event type '{s}'")));
    }
    Ok(t)
}

fn timeline_line(e: &Event, color: bool) -> String {
    let sev = if color {
        let code = match e.severity {
            Severity::Critical | Severity::Error => "1;31",
            Severity::Warning => "1;33",
            Severity::Notice => "1;34",
            _ => "0",
        };
        format!("\x1b[{code}m{}\x1b[0m", e.severity.as_str())
    } else {
        e.severity.as_str().to_string()
    };
    let mut parts = vec![
        e.timestamp.format("%Y-%m-%d %H:%M:%S").to_string(),
        format!("[{sev}]"),
        e.event_type.as_str().to_string(),
    ];
    if let Some(s) = &e.subtype {
        parts.push(s.clone());
    }
    if let Some(h) = &e.hostname {
        parts.push(h.clone());
    }
    if let Some(p) = &e.process_name {
        parts.push(match e.pid {
            Some(pid) => format!("{p}[{pid}]"),
            None => p.clone(),
        });
    }
    if let Some(u) = &e.user {
        parts.push(format!("user={u}"));
    }
    if let Some(a) = e.src_addr {
        parts.push(format!("src={a}"));
    }
    parts.push(
        sanitize_for_terminal(&e.message)
            .lines()
            .next()
            .unwrap_or("")
            .to_string(),
    );
    parts.join(" ")
}

fn print_analyze(inv: &Investigation, input: &str, format: Format) -> Result<()> {
    match format {
        Format::Text => {
            println!("Evidence: {input}");
            println!("Files: {}", inv.files.len());
            let lines: u64 = inv.files.iter().map(|f| f.stats.lines).sum();
            let skipped: u64 = inv.files.iter().map(|f| f.stats.skipped_total()).sum();
            println!(
                "Lines: {lines}   Events: {}   Skipped: {skipped}",
                inv.events.len()
            );
            println!();
            let mut by_type: HashMap<&str, usize> = HashMap::new();
            let mut by_sev: HashMap<&str, usize> = HashMap::new();
            let mut by_parser: HashMap<&str, usize> = HashMap::new();
            for e in &inv.events {
                *by_type.entry(e.event_type.as_str()).or_default() += 1;
                *by_sev.entry(e.severity.as_str()).or_default() += 1;
            }
            for f in &inv.files {
                *by_parser.entry(f.parser.as_str()).or_default() +=
                    f.stats.events as usize;
            }
            println!("By type:");
            let mut types: Vec<_> = by_type.into_iter().collect();
            types.sort_by_key(|a| std::cmp::Reverse(a.1));
            for (t, n) in types {
                println!("    {t}: {n}");
            }
            println!("By severity:");
            let mut sevs: Vec<_> = by_sev.into_iter().collect();
            sevs.sort_by_key(|a| std::cmp::Reverse(a.1));
            for (s, n) in sevs {
                println!("    {s}: {n}");
            }
            println!("By parser:");
            let mut parsers: Vec<_> = by_parser.into_iter().collect();
            parsers.sort_by_key(|a| std::cmp::Reverse(a.1));
            for (p, n) in parsers {
                println!("    {p}: {n}");
            }
            println!();
            println!("Findings: {}", inv.findings.len());
            println!("Correlated pairs: {}", inv.correlations.len());
            Ok(())
        }
        Format::Json => {
            let v = serde_json::json!({
                "input": input,
                "files": inv.files,
                "events": inv.events.len(),
                "findings": inv.findings.len(),
                "correlations": inv.correlations.len(),
            });
            println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
            Ok(())
        }
        _ => unreachable!("analyze format validated by caller"),
    }
}

fn print_inspect_text(inv: &Investigation) {
    for f in &inv.files {
        println!("File: {}", f.file);
        println!("    parser: {}", f.parser);
        println!("    lines: {}", f.stats.lines);
        println!("    events: {}", f.stats.events);
        let skipped = f.stats.skipped_total();
        if skipped > 0 {
            println!("    skipped: {skipped} (unsupported: {}, bad timestamp: {}, incomplete: {}, too long: {})",
                f.stats.skipped_unsupported,
                f.stats.skipped_bad_timestamp,
                f.stats.skipped_incomplete,
                f.stats.skipped_too_long);
        }
        println!();
    }
}

/// Live mode: snapshot, diff, stream changes until interrupted or duration ends.
fn cmd_live(args: &lddetective_lib::cli::LiveArgs, quiet: bool) -> Result<ExitCode> {
    let format = args.format.as_deref().unwrap_or("text").parse::<Format>()?;
    if !matches!(format, Format::Text | Format::Json) {
        return Err(Error::Usage(
            "live supports formats: text, json".to_string(),
        ));
    }
    if args.interval == 0 {
        return Err(Error::Usage(
            "interval must be at least 1 second".to_string(),
        ));
    }
    let uid_names = collectors::uid_name_map();
    let mut prev = collectors::collect_snapshot()?;
    if !quiet {
        eprintln!(
            "watching local system (read-only), every {}s; Ctrl-C to stop",
            args.interval
        );
        if !linux::is_root() {
            eprintln!("note: not running as root; some processes may be invisible (marked unavailable, not an error)");
        }
    }
    let start = Instant::now();
    let mut id: u64 = 1;
    loop {
        std::thread::sleep(Duration::from_secs(args.interval));
        let next = collectors::collect_snapshot()?;
        for change in collectors::diff_snapshots(&prev, &next) {
            let e = collectors::change_to_event(id, next.at, &change, &uid_names);
            id += 1;
            match format {
                Format::Text => println!(
                    "[{}] {} {}",
                    e.timestamp.format("%H:%M:%S"),
                    e.subtype.as_deref().unwrap_or("event"),
                    sanitize_for_terminal(&e.message)
                        .lines()
                        .next()
                        .unwrap_or("")
                ),
                Format::Json => {
                    println!("{}", serde_json::to_string(&e).unwrap_or_default())
                }
                _ => unreachable!(),
            }
        }
        prev = next;
        if let Some(d) = args.duration {
            if start.elapsed() >= Duration::from_secs(d) {
                break;
            }
        }
    }
    Ok(ExitCode::Success)
}
