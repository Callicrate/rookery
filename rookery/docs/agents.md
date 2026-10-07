# Agents And Roles

Rookery assigns bounded work to agents. It does not activate every specialist
or adapter role for every event. The resolved event, selected adapter, and
`ACTIVE_SURFACE.md` determine what is available.

## Authority Boundaries

| Role | Owns | Cannot do |
| --- | --- | --- |
| Operator | Event facts, scope acknowledgement, configuration, authorization, resume, and stop | Turn unknown facts into assumptions or bypass scope |
| Coordinator | Goals, assignments, report harvest, outcomes, retries, solve capsules, and explicitly opted-in bounded allowance grants | Review its own candidate, exact-authorize a proposal, grant an unconfigured action kind, or mutate a platform |
| Worker | One bounded investigation and its assigned evidence and report paths | Submit, claim, complete, or otherwise mutate a platform |
| Reviewer | An independent evidence-readiness decision and verifier report | Review a proposal it solved, grant authority, or execute |
| Authorizer | One exact approval or a bounded allowance | Treat a review as authority or extend authority across generations |
| Executor | A reviewed, authorized immutable plan and its recorded result | Execute an unreviewed, unauthorized, or stale plan |
| Closeout writer | A writeup, partial report, or lessons document | Invent provenance or take scoring actions |

The split is deliberate: a candidate can be technically convincing without
being authorized, and a successful transport response is not scorer truth. See
[Scoring and review](./scoring_review.md) for the mutation boundary.

The coordinator may act as the authorizer only for a small bounded allowance
whose action kind the operator already enabled through
`AUTOMATION_PERMITTED_ACTION_KINDS`. Independent review, current policy and stop
generations, and the normal sealed execution path still apply. This exception
does not permit exact proposal authorization, self-review, or direct platform
mutation.

## Worker Cards

Every worker starts with one owner, one question, one report path, and one stop
condition. A compact reconnaissance card is enough for most first passes:

For challenge-linked work, `objective_id` and `challenge_id` are the same exact
canonical challenge ID; prefixes and coordinator-local aliases are invalid.

```text
Goal: <one bounded reconnaissance question>
Scope: <targets, files, allowed actions, forbidden actions, and budget>
Source handoff: none for an initial route; otherwise <handoff ID and report path>
Source report SHA-256: none for an initial route; otherwise <exact 64hex report hash>
Report: analysis/<lane>/REPORT.md
Stop: <time, artifact, signal, or exact negative>
```

Recon workers collect evidence, preserve exact paths, and report the next
useful command. They do not carry the full scoring protocol. A deeper worker
also states allowed actions, forbidden actions, the current proof gap, rejected
routes, and a named discriminating test.

Every registered worker, including event-wide work, writes `REPORT.md` early
from `templates/REPORT.md`. Directly after its
title, `## Handoff` uses these exact one-line labels in order: `Status:`,
`Source handoff:`, `Source report SHA-256:`, `Observed result:`, `Route key:`,
`Proof gap:`,
`Discriminating test:`, `Next step or return trigger:`, `Evidence paths:`,
`Command/artifact paths:`, `Blocker:`, and `Cleanup/jobs:`. The two path fields
are JSON arrays containing only current-workspace-relative POSIX paths to
private regular artifacts below `analysis/`, `evidence/`, `work/`, `exploit/`,
`captures/`, or `downloads/`. `state/`, `platform/`, absolute,
outside-workspace, symlink, and prose entries are invalid; copy needed source
evidence into an allowed root first. `Route key` must match
`[a-z0-9][a-z0-9._:-]{0,127}` exactly. The report then contains
`## Evidence` and `## Commands`.

`Status` is one current outcome type: `supported_finding`,
`technical_negative`, `incomplete_evidence`, `generic_refusal`,
`capacity_failure`, `environment_failure`, `duplicate_trace`, `invalid_scope`,
`candidate`, `no_progress`, or `other`. Use `incomplete_evidence` while work is
active, then replace every placeholder with current facts before integration.
`Source handoff` and `Source report SHA-256` may be `none` only for an initial
route, including initial event-wide work. A successor opens and reads the exact
source report before acting, records its handoff ID and exact registered 64hex
hash, names a materially different route, and supplies a nonempty
`Discriminating test`.

Before a worker closes, the coordinator integrates its completed report as a
structured handoff. An unsolved challenge consumes that handoff in a current
assignment, retry, proposal, exploration campaign, or external boundary. A
flag-like value or scoring marker is preserved exactly with its source path; it
becomes a proposal through `./bin/score-propose`, never a direct submission.

## Ownership And Records

- `state/events.sqlite3` is canonical runtime truth. JSON and Markdown views
  are projections or handoffs.
- The operator owns the private `.env`. `state/resolved_event.json` and `state/scope.json` are generated, read-only runtime views.
- A worker owns only the paths in its assignment, normally
  `analysis/<lane>/REPORT.md` and accompanying evidence.
- Reviewers use separate verifier reports; they do not rewrite solver evidence.
- The executor records immutable plans under `state/execution_plans/` and exact
  request and response evidence under `submissions/executions/`.
- The coordinator creates `writeups/<id>/CAPSULE.json`; a closeout writer
  completes `writeups/<id>/WRITEUP.md`.

Agent registrations have stable attempt identifiers. Proposals and typed
outcomes carry those identifiers so later correlation does not depend on a
display name or chat transcript. A normal close requires an outcome; stop
records unproven shutdown as uncertainty instead of inventing a result.

Rookery uses one Codex session with three agent depths:

| Depth | Role | Responsibility |
| --- | --- | --- |
| 0 | Main coordinator | Asks how many challenges to keep active, assigns distinct challenges, harvests reports, and refills completed slots. |
| 1 | Challenge coordinator | Owns one challenge investigation and may delegate bounded worker tasks. |
| 2 | Worker | Answers one bounded question and returns evidence to its challenge coordinator. |

Register a depth-1 challenge owner with the canonical
`--role challenge-coordinator`. Legacy registry-style spellings normalize to
that stored role for compatibility, but new task cards should use the canonical
form.

All spawned agents share the `CODEX_SUBAGENT_THREADS=96` session ceiling. The
ceiling does not reserve 96 threads for each challenge. The main coordinator
keeps platform synchronization, intake, browser lifecycle, reviewer assignment,
authorization, scoring execution, and scorer reconciliation. Challenge
coordinators and their workers do not inherit any of that authority. See
[Configuration](./configuration.md) for capacity and
[Coordination](./coordination.md) for dispatch and refill behavior.

## Specialization

Add a specialist only when existing roles leave a demonstrated capability gap.
Its contract must be the smallest distinct one and include a regression
fixture. A new name for an existing capability is not a specialization.

Read [Coordination](./coordination.md) for the event loop, [Research](./research.md)
for investigation rotation, [Evidence and state](./evidence_state.md) for
retention, and [Writeups](./writeups.md) for closeout.
