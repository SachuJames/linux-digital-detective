# Contributing

Thanks for considering a contribution. This project is deliberately small
and careful; the guidelines below keep it that way.

## Getting started

Read [docs/development.md](docs/development.md) for the build/test
commands and project layout.

## Ground rules

1. **Honest language.** Findings, docs, and comments describe what was
   observed and why it is worth investigating. Never claim an attack,
   intrusion, or compromise. The test suite enforces this for report
   output; hold yourself to it everywhere else.
2. **No silent loss.** If input is skipped, evicted, or unreadable, count
   it and surface it.
3. **Synthetic fixtures only.** Tests must not read the developer's real
   logs or `/proc` (the `live` CLI test is the deliberate exception, and
   it is read-only).
4. **Cautious dependencies.** Justify every new dependency; prefer the
   standard library.
5. **No AI/assistant mentions.** Do not reference AI assistants, code
   generators, or similar in code, docs, commits, or issues.

## Pull requests

- Keep them focused: one change, one PR.
- `cargo fmt --check` and `cargo clippy --all-targets -- -D warnings`
  must be clean.
- Add tests for new behavior; update docs when behavior changes.
- Use plain, human commit messages. No emojis, no trailers.

## Reporting issues

Use the issue templates. For security vulnerabilities, do **not** open a
public issue — see [SECURITY.md](SECURITY.md).

## Code of conduct

Be kind and professional. See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
