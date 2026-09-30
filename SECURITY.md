# Security policy

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | yes |

## Reporting a vulnerability

**Do not open a public issue for a security vulnerability.**

Instead, report it privately to the maintainer with:

- a description of the issue and its impact,
- steps to reproduce (a minimal log file or command line is ideal),
- any suggested fix, if you have one.

You will receive a response within a reasonable time. Once the issue is
fixed, it will be disclosed in the changelog.

## Scope notes

This tool processes untrusted input by design (log files can be hostile),
so the areas of most interest are:

- anything that lets crafted input escape its sandbox: path traversal in
  evidence collection, symlink handling, terminal escape injection in
  reports;
- denial of service via unbounded memory or CPU (size caps exist; bypasses
  are in scope);
- any network activity whatsoever (the tool must make none).

See [docs/threat-model.md](docs/threat-model.md) for the full threat
model.
