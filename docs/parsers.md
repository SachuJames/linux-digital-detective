# Parsers

Parsers live in `src/parsers/`. Each implements the `Parser` trait:
`name`, `description`, `sniff` (line -> confidence score), `parse_line`,
and optionally `parse_whole` (for JSON documents that must be read as one
unit). Adding a parser means implementing the trait and registering it in
`default_registry()`; nothing else changes.

## The registry

| Name | Handles | Whole-file |
|---|---|---|
| `json` | JSON documents: a top-level array, or one JSON object per line (JSONL) | yes (arrays) |
| `syslog` | RFC 3164 `MMM dd HH:MM:SS host proc[pid]: msg`, optional `<pri>` prefix | no |
| `auth` | sshd / login / pam / sudo lines (with or without a syslog envelope) | no |
| `generic` | any line starting with a recognizable timestamp | no |

## How a file gets its parser

1. If a whole-file parser claims the content (currently: JSON arrays), it
   handles the entire file.
2. Otherwise the first non-empty lines (up to a small sample) are scored by
   every parser's `sniff`, the average wins, and that parser is locked in
   for the file.
3. Each line goes to the locked-in parser. If it returns `None`, the other
   parsers are tried in registry order before the line is counted as
   skipped. (This is how a stray JSON line inside a syslog file still
   becomes an event.)

If nothing scores above 0.35, the file is handled by `generic`, which
accepts any line with a parseable timestamp.

## Auth extraction

The `auth` parser recognizes, among others:

- `Failed password for <user> from <ip> port <port>` (OpenSSH)
- `Accepted password|publickey for <user> from <ip> port <port>`
- `pam_unix(sshd:session): session opened|closed for user <user>`
- `sudo: <user> : TTY=... ; COMMAND=<cmd>`

It fills `user`, `src_addr`, `port`, `process_name` (`sshd`/`sudo`),
`hostname`, and normalizes the subtype (`ssh_failed_password`,
`ssh_login_success`, `session_opened`, `sudo_command`, ...). Unmatched
fields stay `None`; the parser never guesses.

## JSON field mapping

JSON objects map common keys onto event fields: `timestamp`/`time`/`ts`,
`level`/`severity`, `host`/`hostname`, `service`/`process`/`proc`,
`pid`, `user`, `src_ip`/`src`/`source_ip`, `dst_ip`/`dst`/`dest_ip`,
`port`, `type`, `subtype`, `message`/`msg`. Unknown keys are kept in
`metadata`. An object with neither a timestamp nor a message is skipped as
incomplete.

## Timestamp formats

`src/parsers/timestamps.rs` recognizes, in order: RFC 3339 / ISO 8601,
`YYYY-MM-DD HH:MM:SS[.frac]`, `YYYY-MM-DDTHH:MM:SS[.frac]`, syslog
`MMM dd HH:MM:SS`, `MMM dd HH:MM:SS,mmm` (Java-style millis with comma),
epoch seconds (10 digits) and epoch milliseconds (13 digits). See
[evidence-model.md](evidence-model.md) for the timezone policy applied to
whatever is parsed.
