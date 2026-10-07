# Rookery

Rookery is a Codex based multi-agent harness for authorized capture-the-flag events and security labs. It coordinates specialized workers, preserves evidence, and separates solving from review, authorization, and platform mutation.

> [!CAUTION]
> Rookery launches Codex with the filesystem, process, and network authority of the operator account and with interactive approvals disabled. Run it only in a dedicated, disposable Linux or WSL workspace, with an event scope you are authorized to test. Review [`rookery/.codex/config.toml`](rookery/.codex/config.toml) before launch.

## Contents

- [What Rookery does](#what-rookery-does)
- [Supported environment](#supported-environment)
- [First read only check](#first-read-only-check)
- [Repository layout](#repository-layout)
- [Documentation](#documentation)
- [Project policies](#project-policies)

## What Rookery does

Rookery gives an operator three event controls:

```bash
./go          # prepare the workspace and start or resume the event
./go status   # read the current state without changing it
./go stop     # advance the stop generation and stop Rookery-owned work
```

Behind that small surface, Rookery:

- derives a normalized event manifest and authorized scope from shipped profiles and the private `.env`;
- discovers local capabilities and reports missing prerequisites;
- runs one Codex session whose main coordinator keeps the operator-selected
  number of challenges active through native coordinator subagents;
- lets each challenge coordinator delegate bounded questions to worker
  subagents under the session's shared 96-thread ceiling;
- records durable state and exact captured evidence, while bounded adapter
  summaries replace sensitive authentication and cookie headers;
- routes scoring candidates through independent review and separate authorization;
- checks scope and stop state immediately before Rookery-owned effects; and
- creates solve capsules, writeups, and post-event measurement artifacts.

Authorization for scoring mutations starts at zero. A solver can propose an action, but cannot execute it. Transport success is also kept separate from scorer truth.

## Supported environment

The operational runtime targets Linux. Ubuntu under WSL is supported when the workspace lives on the Linux filesystem, such as under `~/`, where private POSIX modes can be enforced. Native Windows is suitable for source inspection and portable-module development; it is not the supported effect-producing runtime.

Rookery requires Bash, Python 3.11 or newer, the Codex CLI with a working login, and the core commands listed in [`rookery/configs/preparation.json`](rookery/configs/preparation.json). Networked package and image acquisition is disabled by default.

## First read only check

From a clean checkout on Linux or WSL:

```bash
cd rookery
PYTHONDONTWRITEBYTECODE=1 ./bin/rookery validate --release --source-checkout
./go status
```

Source checkout validation checks the deployable tree without requiring a live
`.env`. An extracted release uses `validate --release` without
`--source-checkout` and requires its synthesized private `.env`. `./go status`
is a pure read and should report `uninitialized` before the first launch. It
does not prove event readiness.

Before starting an event, follow [Getting started](rookery/docs/getting-started.md). A clean source checkout may omit live configuration; the release builder creates one reviewed `.env` from `.env.example` for the extracted workspace. Edit only that private file, validate the resolved configuration, create a private measurement baseline outside the runtime directory, prepare any required external session, and then run `./go`. The launch path fails closed before runtime state is created when those requirements are unresolved.

## Repository layout

| Path | Purpose |
| --- | --- |
| [`rookery/`](rookery/) | Canonical deployable source, operator documentation, adapters, extensions, and release contract |
| [`tests/`](tests/) | Repository test suite; excluded from release archives |
| [`docs/`](docs/) | Contributor-facing design documentation |
| [`.agents/skills/`](.agents/skills/) | Maintainer workflows for building adapters and preparing source releases; excluded from deployed packages |
| [`rookery/.agents/skills/`](rookery/.agents/skills/) | Operational workflows shipped inside every deployed Rookery package |
| [`go`](go) and [`run-codex`](run-codex) | Thin root wrappers that validate and delegate to `rookery/` |

Release code must not depend on repository-only files. Runtime state, evidence, telemetry, event data, and retrospective datasets do not belong in this repository.

See [Architecture](docs/architecture.md) for the component and trust boundaries.

## Documentation

Start with the page that matches your task:

- [Get started](rookery/docs/getting-started.md)
- [Review release changes](rookery/CHANGELOG.md)
- [Browse the operator documentation](rookery/docs/README.md)
- [Understand the deployed source](rookery/README.md)
- [Understand the operator lifecycle](rookery/docs/operator.md)
- [Define event scope](rookery/docs/scope.md)
- [Select or build a platform adapter](rookery/docs/adapters.md)
- [Understand scoring review and execution](rookery/docs/scoring_review.md)
- [Understand evidence and state](rookery/docs/evidence_state.md)
- [Receive, upgrade, or roll back a release](rookery/docs/upgrade.md)
- [Contribute to the project](CONTRIBUTING.md)
- [Report a security issue](SECURITY.md)

## Project policies

Contributions are welcome under the process in [`CONTRIBUTING.md`](CONTRIBUTING.md). Participation is governed by [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md). Security-sensitive reports should follow [`SECURITY.md`](SECURITY.md).

Rookery is available under the [MIT License](LICENSE).
