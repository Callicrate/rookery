# Rookery Repository Instructions

## Scope

This file governs the public source repository. The deployable harness has its
own [runtime instructions](rookery/AGENTS.md) for work inside that tree and for
authorized events.

## Context

The repository root is a thin development shell. Root wrappers validate and
delegate to the canonical release source. The old outer implementation and
historical event material belong outside this repository.

## Repository Map

- [`rookery/`](rookery/) is the only deployable source tree.
- [`tests/`](tests/) exercises that source and stays outside release archives.
- [`.agents/skills/`](.agents/skills/) holds repository Codex workflows.
- [`go`](go), [`run-codex`](run-codex), and [`bin/`](bin/) are strict delegating
  or refusal wrappers at the repository root.

## Local Commands

- `./go status` is a pure read from the repository root.
- On Linux or WSL, `cd rookery && PYTHONDONTWRITEBYTECODE=1 ./bin/rookery validate --release --source-checkout` checks a clean release source.
- `./bin/build-release --output-dir <empty external directory>` builds a handoff archive after strict validation.

## Project Rules

- Keep the root wrappers strict and keep their public operator interface at
  `./go`, `./go status`, and `./go stop`.
- Keep repository tests, CI, maintainer notes, skills, and local artifacts at
  the root. The nested release source is scanned and packaged as a whole.
- Do not add event runs, telemetry, credentials, captures, submissions,
  writeups, retrospective reports, or historical release artifacts to this
  public repository. Preserve exact evidence in private event storage.
- Keep the operator-edited .env private. It is the only file an operator
  edits to configure a normal event; only reviewed example configuration
  belongs in public Git history.
- Explain repository layout at the root; link to canonical operator docs for
  runtime behavior instead of duplicating those contracts.

## Related Docs

- [Operator guide](rookery/docs/operator.md) - read when changing event lifecycle behavior.
- [Upgrade guide](rookery/docs/upgrade.md) - read when changing packaging, installation, or rollback.
- [Measurement guide](rookery/docs/measurement.md) - read when changing baselines or telemetry.
- [Adapter guide](rookery/docs/adapters.md) - read when changing a platform integration.
