# Threat model

## What this tool is

A local-first log parser and event correlator. It reads logs you point it
at, normalizes them into events, orders them, correlates them, and flags
noteworthy sequences with built-in rules. It is an investigator's assistant,
not an oracle.

## What the tool claims (and does not claim)

Every built-in rule uses deliberately cautious language: "unusual",
"requires investigation", "should be investigated". Findings state what was
observed and why it is worth a look. No finding claims an attack occurred,
an intrusion was confirmed, or a host is compromised. The test suite
asserts this: `tests/cli.rs` fails the build if report output ever contains
phrases like "you were attacked" or "breach confirmed".

## Assumptions

- **The operator is trusted.** The person running the tool decides what
  evidence to feed it and interprets the findings.
- **Evidence may be incomplete or hostile.** Logs can be truncated,
  rotated, tampered with, or crafted to mislead. The tool reports what it
  sees; it does not verify log integrity. (Authenticity checks on evidence
  are out of scope for 0.1.0.)
- **The local machine is the trust boundary.** The tool makes no network
  calls, so it cannot leak evidence and cannot be tricked by a remote
  party at runtime. A malicious log file is the main untrusted input.

## Defenses against malicious input

- **Size caps** (`MAX_FILE_BYTES`, `MAX_LINE_BYTES`, file count, recursion
  depth) bound memory and time before parsing starts.
- **Symlink-escape guard**: directory walks never follow a symlink outside
  the evidence root.
- **ANSI stripping**: terminal output is sanitized so log content cannot
  inject escape sequences into the investigator's terminal.
- **No execution**: nothing from log content is executed, interpolated into
  commands, or passed to a shell. Regexes are precompiled and bounded.
- **Skip accounting**: malformed input is counted with reasons, not
  silently dropped and not fatal.

## What is explicitly out of scope

- Real-time intrusion detection or prevention. (`live` mode streams
  observations; it is not an IDS.)
- Verifying that logs are authentic, complete, or untampered.
- Automated response: the tool never kills processes, closes connections,
  or modifies the system. The only writer is the report renderer, and it
  writes to stdout.
- Windows/macOS event sources. The live collectors read Linux `/proc`.

## If you find a security issue

See [SECURITY.md](../SECURITY.md). Do not open a public issue for a
vulnerability; report it privately so it can be fixed before disclosure.
