# Evidence model

## What counts as evidence

An **evidence unit** is one input the tool reads: a regular file, a file
found while walking a directory, or standard input (`-`). Directories are
walked recursively up to `MAX_RECURSION_DEPTH` (8); at most
`MAX_FILES_PER_RUN` (10,000) files are accepted per run.

## Safety caps

| Cap | Value | Behavior when hit |
|---|---|---|
| `MAX_FILE_BYTES` | 512 MiB | file skipped, counted, run continues |
| `MAX_LINE_BYTES` | 1 MiB | line counted as `skipped_too_long`, run continues |
| `MAX_RECURSION_DEPTH` | 8 | deeper directories not descended |
| `MAX_FILES_PER_RUN` | 10,000 | further files ignored, counted |

## Symlink handling

Symlinks are followed only if their canonical target stays inside the
evidence root. A symlink pointing outside the root (e.g. into `/etc` when
investigating `./logs`) is skipped with a warning. This prevents a
directory walk from escaping into sensitive areas of the filesystem.

## Skipped-line accounting

Every line that does not become an event is counted in `ParseStats` with a
reason, and the totals are printed in reports under "PARSING STATISTICS":

- `unsupported` — no parser could make sense of the line
- `bad_timestamp` — the line looks like a log line but the timestamp is
  malformed (as opposed to having no timestamp at all)
- `incomplete` — a parser recognized the line but required fields were
  missing (e.g. a JSON object with no timestamp and no message)
- `too_long` — the line exceeded `MAX_LINE_BYTES`

The tool never silently drops input: the report says exactly how many lines
were skipped and why.

## The normalized event

Every parser emits the same `Event` record:

- `id` — per-run sequence number, assigned after parsing
- `timestamp` — `chrono::DateTime<FixedOffset>`; always an explicit offset
  internally (see the timezone policy below)
- `precision` — second, millisecond, microsecond, or nanosecond
- `partial_timestamp` — true when the timestamp was incomplete in the
  source (e.g. syslog has no year)
- `event_type` / `subtype` — e.g. `auth` / `ssh_failed_password`
- `severity` — debug, info, notice, warning, error, critical, unknown
- `hostname`, `process_name`, `pid`, `ppid`, `user`
- `src_addr`, `dst_addr`, `port`
- `message` — the human-readable remainder
- `confidence` — 0.0..1.0, how confident the parser is in its extraction
- `provenance` — source file label, line number, parser name, the raw
  timestamp string, and whether the offset was explicit in the source

## Timezone policy

- A timestamp with an **explicit offset** (`+0530`, `Z`) is honored as-is.
- A timestamp with **no offset** is interpreted in the machine's local
  timezone and recorded with `offset_explicit = false` in provenance.
- Syslog-style `MMM dd HH:MM:SS` timestamps have no year; the current year
  is assumed and `partial_timestamp = true` is set, so downstream consumers
  know the year is an assumption, not evidence.

These rules are documented here and in code because getting them wrong
silently is worse than getting them wrong loudly: every assumption is
carried in the event itself.
