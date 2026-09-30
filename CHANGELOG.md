# Changelog

All notable changes to this project are documented here. The format is
based on Keep a Changelog, and the project adheres to Semantic Versioning.

## [Unreleased]

### Added
- Evidence collection with size caps, recursion limits, and symlink-escape
  guards; skipped lines counted with reasons instead of silently dropped.
- Parsers for syslog (RFC 3164 with optional priority prefix), sshd/auth
  lines, JSON documents and JSONL, and a generic timestamped-line parser;
  automatic per-file parser selection by sniffing.
- Normalized event model with provenance (source file, line, parser, raw
  timestamp, explicit-offset flag) and a documented timezone policy.
- Chronological timeline with filters (time range, severity, type, process,
  source).
- Heuristic correlation engine with documented signal weights and reason
  breakdowns.
- Built-in rules AUTH-001, PRIV-001, PROC-001, PROC-002, NET-001, written
  in deliberately cautious language.
- Read-only live system collection from `/proc` with snapshot diffing.
- Reports in text, JSON, JSONL, and CSV; terminal output sanitized against
  ANSI escape injection.
- CLI: `analyze`, `timeline`, `report`, `inspect`, `live`, `rules list`,
  `version`; documented exit codes (0/1/2/3).
- Optional TOML config file with validated limits.

### Planned
- journald export and auditd parsers.
- More detection rules (persistence mechanisms, lateral movement shapes).
- HTML report output.
- Streaming analysis for very large inputs.
