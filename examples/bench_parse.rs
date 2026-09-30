//! Lightweight parse benchmark: times the evidence -> event pipeline.
//!
//! Two workloads:
//! 1. The bundled fixtures (small, mixed formats).
//! 2. A generated 200,000-line syslog file (single format, bulk throughput).
//!
//! Not a micro-benchmark; it measures the real pipeline with real
//! (synthetic) log shapes. Run with: `cargo run --release --example bench_parse`

use std::time::Instant;

use lddetective_lib::evidence;
use lddetective_lib::parsers;

fn bench_units(label: &str, units: &[&evidence::Evidence]) -> (usize, u64, f64) {
    let mut inputs: Vec<Vec<String>> = Vec::new();
    let mut total_lines = 0usize;
    for unit in units {
        let mut too_long = 0;
        let lines = evidence::read_text(unit, &mut too_long).unwrap();
        total_lines += lines.len();
        inputs.push(lines);
    }

    let rounds = 20u64;
    let start = Instant::now();
    let mut total_events = 0u64;
    for _ in 0..rounds {
        let mut first_id = 1u64;
        for (unit, lines) in units.iter().zip(inputs.iter()) {
            let mut stats = evidence::ParseStats::default();
            let parsed =
                parsers::parse_evidence(unit, lines, first_id, &mut stats).expect("parse failed");
            total_events += parsed.events.len() as u64;
            first_id += parsed.events.len() as u64;
        }
    }
    let secs = start.elapsed().as_secs_f64();
    println!("{label}");
    println!("    files:      {}", units.len());
    println!("    lines:      {total_lines}");
    println!(
        "    lines/sec:  {:.0}",
        total_lines as f64 * rounds as f64 / secs
    );
    println!("    events/sec: {:.0}", total_events as f64 / secs);
    (total_lines, total_events, secs)
}

fn main() {
    let dir = format!("{}/tests/fixtures", env!("CARGO_MANIFEST_DIR"));
    let units = evidence::collect(&dir, &dir).expect("fixtures must be collectable");
    let refs: Vec<&evidence::Evidence> = units.iter().collect();
    bench_units("fixtures (mixed formats)", &refs);

    // Generated bulk workload: 200k realistic syslog lines, written once to
    // a temp file so the timed loop still measures parsing, not I/O.
    let big_path = "/tmp/lddetective_bench_big.log";
    {
        use std::io::Write as _;
        let mut f = std::fs::File::create(big_path).expect("temp file");
        for i in 0..200_000u64 {
            writeln!(
                f,
                "Sep 30 14:{:02}:{:02} web01 sshd[{}]: Failed password for user{} from 203.0.113.7 port 51234 ssh2",
                (i / 3600) % 60,
                (i / 60) % 60,
                8000 + (i % 500),
                i % 50,
            )
            .unwrap();
        }
    }
    let big_units = evidence::collect(big_path, big_path).expect("temp file collectable");
    let big_refs: Vec<&evidence::Evidence> = big_units.iter().collect();
    bench_units("generated 200k-line syslog", &big_refs);
    let _ = std::fs::remove_file(big_path);
}
