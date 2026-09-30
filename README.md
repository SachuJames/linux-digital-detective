# linux-digital-detective

A local-first Linux incident investigation tool. Point it at logs (or let
it watch the live system, read-only) and it parses the evidence, normalizes
events, orders them chronologically, correlates related ones, and reports
noteworthy sequences in plain, cautious language.

Everything runs locally: no network, no accounts, no telemetry. Findings
say "unusual" and "requires investigation" — never "you were attacked".

> **Note:** the binary is called `lddetective`, not `ldd`. `ldd` is the
> standard Linux tool that prints shared-library dependencies; shadowing it
> on `PATH` would be hostile.

## Quick start

```sh
cargo build --release
./target/release/lddetective analyze /var/log/auth.log
./target/release/lddetective timeline /var/log --severity warning --format jsonl
./target/release/lddetective report /var/log --format json > report.json
./target/release/lddetective live --interval 2 --duration 60
```

## Example

Analyzing the bundled synthetic fixtures:

```sh
$ lddetective analyze tests/fixtures --no-color
Evidence: tests/fixtures
Files: 5
Lines: 38   Events: 35   Skipped: 3

By type:
    network: 12
    auth: 8
    unknown: 8
    service: 5
    kernel: 1
    privilege: 1
By severity:
    unknown: 17
    info: 8
    notice: 5
    warning: 3
    critical: 1
    error: 1
By parser:
    jsonl: 12
    auth: 9
    syslog: 6
    generic: 5
    json: 3

Findings: 3
Correlated pairs: 115
```

A filtered timeline:

```sh
$ lddetective timeline tests/fixtures --severity warning --no-color
2026-09-30 14:02:11 [warning] auth ssh_failed_password web01 sshd[8123] user=root src=203.0.113.7 Failed password for root from 203.0.113.7 port 51234 ssh2
...
```

And a full report (`report`) renders findings with their timelines,
correlation signals, evidence references, and parsing statistics:

```text
Parsed:
    35 events

Skipped:
    3 lines
Reasons:
    - 3 unsupported format
    - 0 malformed timestamp
    - 0 incomplete records
    - 0 overlong lines

Note: correlation scores and rule confidences are heuristics to
guide investigation, not verdicts. Verify against the evidence.
```

## Commands

| Command | Purpose |
|---|---|
| `analyze <input>` | Parse evidence and print a summary (text, json) |
| `timeline <input>` | Chronological events with filters (text, json, jsonl, csv) |
| `report <input>` | Full investigation report (text, json, jsonl, csv) |
| `inspect <input>` | Per-file details: parsers used, statistics (text, json) |
| `live` | Watch the live system (read-only `/proc`) and stream changes |
| `rules list` | List the built-in detection rules |
| `version` | Print version information |

`<input>` is a file, a directory (walked recursively), or `-` for stdin.
Timeline filters: `--from`, `--to`, `--severity`, `--type`, `--process`,
`--source`.

Exit codes: `0` = completed (even with findings), `1` = internal error,
`2` = usage/config error, `3` = evidence error.

## Built-in rules

```sh
$ lddetective rules list
AUTH-001  [warning]
    Repeated authentication failures followed by success
    ...
PRIV-001  [warning]
    Privileged command from an unusual location
    ...
PROC-001  [notice]
    Process activity shortly after login
    ...
PROC-002  [warning]
    Process executable in an unexpected location
    ...
NET-001  [warning]
    Repeated connection attempts to the same destination
    ...
```

See [docs/threat-model.md](docs/threat-model.md) for what the tool claims
and does not claim.

## Documentation

- [docs/architecture.md](docs/architecture.md) — pipeline stages and design principles
- [docs/evidence-model.md](docs/evidence-model.md) — evidence units, safety caps, timezone policy
- [docs/parsers.md](docs/parsers.md) — parser registry, sniffing, field extraction
- [docs/correlation-engine.md](docs/correlation-engine.md) — signals, weights, limitations
- [docs/threat-model.md](docs/threat-model.md) — assumptions, defenses, scope
- [docs/performance.md](docs/performance.md) — measured throughput
- [docs/development.md](docs/development.md) — building, testing, adding parsers/rules

## Configuration

Optional TOML file at `~/.config/linux-digital-detective/config.toml`
(overridable with `--config`):

```toml
[rules]
auth_fail_threshold = 3
auth_fail_window_secs = 300

[output]
color = true

[limits]
max_events = 100000
```

All limits are validated against hard caps; out-of-range values are
rejected with a usage error rather than silently clamped.

## Development

```sh
cargo test                     # 92 tests: unit + integration + CLI
cargo clippy --all-targets -- -D warnings
cargo fmt --check
cargo run --release --example bench_parse
```

See [CONTRIBUTING.md](CONTRIBUTING.md) and
[docs/development.md](docs/development.md).

## Roadmap

- More parsers (journald export format, auditd)
- More rules (persistence mechanisms, lateral movement shapes)
- HTML report output
- Incremental / streaming analysis for very large inputs

## License

MIT. See [LICENSE](LICENSE).
