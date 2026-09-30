# Performance

Measured with `cargo run --release --example bench_parse` on a 2-vCPU VM
(AMD EPYC 9D25, 7 GB RAM). These are pipeline numbers — evidence read plus
full parse and normalization — not micro-benchmarks of individual regexes.

| Workload | Lines | Throughput |
|---|---|---|
| `tests/fixtures` (5 files, mixed: auth, syslog, generic, JSON, JSONL) | 38 | ~52k lines/sec, ~46k events/sec |
| Generated 200k-line syslog file (auth-flavored lines) | 200,000 | ~183k lines/sec, ~183k events/sec |

The small-fixture number is dominated by per-file overhead (sniffing,
setup); the bulk number reflects steady-state parsing. A million-line
syslog file parses in roughly six seconds on this hardware.

## Where the time goes

- Timestamp parsing and syslog envelope stripping dominate; both are
  precompiled-regex based.
- JSON parsing (`serde_json`) is the slowest per-line path, but only for
  JSON inputs.
- Correlation is O(n^2) within the time window — fine for thousands of
  events, and the place to optimize first if inputs grow (see
  [correlation-engine.md](correlation-engine.md)).

## Memory

The `EventStore` cap (`DEFAULT_MAX_EVENTS` = 100,000, configurable via
`max_events` in the config file) bounds memory: the oldest events are
evicted and counted rather than growing without limit. Evidence reading is
line-oriented; a single file is never loaded past `MAX_FILE_BYTES`.

## Reproducing

```sh
cargo run --release --example bench_parse
```

Treat published numbers as "measured on this fixture, on this machine" —
rerun on your own hardware and your own logs before making capacity
decisions.
