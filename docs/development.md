# Development guide

## Prerequisites

- A recent stable Rust toolchain (`rustup` is the recommended way to get
  one). The project is developed against stable; no nightly features.
- Linux for `live` mode and the `/proc` collectors. Everything else builds
  and tests on any platform.

## Common commands

```sh
cargo build                    # debug build
cargo build --release          # release build
cargo test                     # all tests (unit + integration + CLI)
cargo test --lib               # unit tests only
cargo clippy --all-targets -- -D warnings   # lint; CI fails on warnings
cargo fmt --check              # formatting; CI fails if not clean
cargo run --release --example bench_parse    # parse benchmark
```

## Project layout

```text
src/
  main.rs          CLI wiring: arg parsing, pipeline, exit codes
  cli.rs           clap command definitions
  errors.rs        Error type and process exit codes
  config.rs        optional TOML config (~/.config/linux-digital-detective/config.toml)
  evidence.rs      evidence collection, size caps, symlink guards
  events.rs        normalized Event model and provenance
  parsers/         Parser trait, registry, timestamp handling, format parsers
  timeline.rs      chronological ordering and filters
  storage.rs       bounded EventStore
  correlation.rs   heuristic event correlation
  rules/           detection rules (Rule trait + built-ins)
  reporting.rs     Investigation model and text/json/jsonl/csv renderers
  linux.rs         read-only /proc helpers
  collectors.rs    live system snapshots and diffs
  analysis.rs      process-tree analysis and text rendering
tests/
  fixtures/        synthetic logs (fictional hosts/users/IPs only)
  integration_pipeline.rs   evidence -> report end-to-end
  cli.rs           black-box CLI tests via std::process::Command
examples/
  bench_parse.rs   parse throughput benchmark
```

## Conventions

- **Honest language.** Findings and docs say "unusual" / "requires
  investigation", never "attack confirmed". Tests enforce this.
- **No silent loss.** Skipped lines, evicted events, and unreadable files
  are counted and surfaced.
- **Synthetic fixtures only.** Tests must never read the developer's real
  `/var/log` or `/proc` (except the `live` CLI test, which intentionally
  exercises live collection read-only).
- **Cautious dependencies.** Each dependency needs a justification; the
  current set is `clap`, `serde`/`serde_json`, `chrono`, `regex`,
  `thiserror`, `toml`.
- **Commit messages** are plain, human phrasing, no emojis, no trailers.

## Adding a parser

Implement the `Parser` trait in `src/parsers/`, add it to
`default_registry()`, and add fixture lines plus a round-trip test. See
[parsers.md](parsers.md).

## Adding a rule

Implement the `Rule` trait in `src/rules/`, register it in `all_rules()`,
and add unit tests asserting it fires on its scenario and stays silent on
benign variants. Keep the language cautious: describe what was observed
and why it is worth investigating. See [threat-model.md](threat-model.md).
