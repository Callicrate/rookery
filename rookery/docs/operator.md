# Operator Guide

This guide covers an installed and configured Rookery workspace. For the first run, begin with [Getting started](getting-started.md). For release receiving and rollback, use [Install, upgrade, and rollback](upgrade.md).

## Contents

- [Before an event](#before-an-event)
- [Everyday commands](#everyday-commands)
- [What `./go` does](#what-go-does)
- [Status and stop](#status-and-stop)
- [Maintenance commands](#maintenance-commands)
- [Operating boundaries](#operating-boundaries)

## Before an event

The normal sequence is: edit `.env`, validate the resolved configuration, create the private release-bound baseline, prepare any required external session, then run `./go`.

Confirm all of the following before `./go`:

- the workspace is a fresh release extraction on Linux or WSL's Linux filesystem;
- the private `.env` describes the intended event and exact authorized scope, and the resolved configuration validates cleanly;
- `ROOKERY_MEASUREMENT_BASELINE_PATH` names the private baseline created for this release and configuration;
- the selected adapter can satisfy `scoring.completion_mode`: `scorer_truth` needs healthy scoring, while manual `evidence_only` cannot submit flags;
- `codex login status` succeeds for the default `CODEX_AUTH_MODE=local-login`;
- the full-access Codex settings in `.codex/config.toml` and `configs/codex-base.toml` are acceptable for this disposable workspace; and
- any required external VPN is already established and supervised outside Rookery.

`./go` fails before creating runtime state when the event, scope, baseline, Codex executable, login, or authentication configuration is unresolved.

## Everyday commands

```bash
./go
./go status
./go stop
```

| Command | Behavior |
| --- | --- |
| `./go` | Start a new event or explicitly resume a stopped workspace. |
| `./go status` | Read current state without installing, starting, stopping, repairing, or writing. |
| `./go stop` | Advance the stop generation, revoke unused authority, cancel retries, and request bounded shutdown of Rookery-owned work. |

These are the only everyday event-control commands.

## What `./go` does

After its read-only launch gate passes, `./go`:

1. binds the workspace, shipped source, live configuration, baseline, and selected Codex executable;
2. discovers or prepares declared capabilities;
3. resolves the selected adapter and extensions;
4. compiles the event scope;
5. renders only the active agents and tools;
6. writes `START_PROMPT.md`; and
7. launches Codex with that prompt.

Rookery launches one Codex session. The main coordinator asks the operator how
many distinct challenges to keep active, then creates one native challenge
coordinator subagent for each selected challenge. Each challenge coordinator
may delegate bounded work one further level. As coordinators finish, the main
coordinator harvests their reports, closes their attempts, and refills open
slots until the requested challenge count is active or no eligible challenge
remains. All of those agents share the configured 96 spawned-thread ceiling.

The main coordinator retains platform synchronization, challenge intake,
browser lifecycle, reviewer assignment, authorization, scoring execution, and
scorer reconciliation. Challenge coordinators investigate and propose; they do
not perform those event-wide actions.

The source and configuration binding is rechecked before later Rookery mutations. Moving the workspace, changing bound source or configuration, removing the binding, or replacing the Codex executable blocks normal work rather than silently rebinding it.

## Status and stop

The headline state is one of `uninitialized`, `unresolved`, `blocked`, `ready`, or `stopped`.

A stopped workspace resumes only through a new `./go`. Process restart alone does not resume it. When queue automation is explicitly enabled, `./go` owns one queue watcher and reports `ready` only when that watcher and required preparation are ready.

`./go stop` reports shutdown evidence by category. `closed` and `cancelled` mean a verified local process disappeared. `unmanaged` means Rookery could not prove local ownership. `unacknowledged` means a process was still present after the bounded wait. Inspect the latter two; the `stopped` headline alone is not proof that every external or unverifiable process ended.

On an uninitialized workspace, `./go stop` is a successful no-op and creates no state. If binding integrity is broken but canonical state exists, the emergency stop path can revoke authority and record terminal shutdown facts, but it cannot repair the workspace or promise the normal stop prompt and lessons output.

## Maintenance commands

The supported maintenance surface is separate from ordinary event control:

| Command | Use |
| --- | --- |
| `./bin/rookery validate --release --source-checkout` | Strictly validate a template-only source checkout before a build. |
| `./bin/rookery validate --release` | Strictly validate an extracted release, its private `.env`, selected typed adapter schema, and derived resolved configuration. |
| `./bin/build-release` | Build or safely receive a deterministic release archive. |
| `./bin/measurement-baseline` | Create the required private baseline before the first event start. |
| `./bin/telemetry-report` | Analyze one quiescent preserved runtime without modifying it. |
| `./bin/telemetry-compare` | Regenerate and descriptively compare two eligible preserved runtimes. |

Other `bin/` programs are coordinator, reviewer, adapter, compatibility, or test interfaces. `ACTIVE_SURFACE.md` is the event-specific authority after launch.

## Operating boundaries

- Unknown event facts stay unknown. Correct `.env`, validate the resolved configuration, and rerun the command.
- Solvers use proposals. They do not submit directly or mutate the platform.
- Review, authorization, execution, and scorer truth remain separate.
- Rookery-owned network and attachment helpers enforce their compiled-scope contracts. Raw shell remains subject to operator authorization and evidence requirements.
- Exact candidates, requests, responses, logs, sessions, and credentials can exist in the private runtime. Preserve and back up the whole directory as sensitive evidence.
- Queue automation is off by default. Enabling it does not bypass review, authorization, scope, cadence, or stop checks.

For the underlying contracts, see [State, policy, and stop](state_policy_stop.md), [Scoring review](scoring_review.md), [Evidence and state](evidence_state.md), and [Event scope](scope.md).
