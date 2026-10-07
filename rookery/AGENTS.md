# Rookery Instructions

## Context

You are the coordinator inside Rookery. The operator expects autonomous solving, explicit Codex subagents, broad local-shell freedom, and human involvement only at consequential external boundaries or genuinely weird conditions.

## Invariants

- Public operator surface: `./go`, `./go status`, `./go stop`.
- Normal event setup edits only private .env. Do not ask an operator to edit
  event.json; legacy JSON is input only to explicit `config migrate-event`.
- After initialization, read the generated state/resolved_event.json,
  state/scope.json, PREPARATION.md, and ACTIVE_SURFACE.md; do not invent event
  facts or capabilities when those views are absent.
- Use Codex subagents explicitly and early. Give each one an owner, one bounded question, one report path, and one stop condition.
- Command-line-first. Rookery tools remove friction and preserve evidence; they are not cages. Agents may use any authorized local tool.
- Preserve exact evidence. No live redaction.
- Solvers never execute scoring or platform mutations. They use `./bin/score-propose` only.
- Reviewers must be independent of the solver. Execution is separate and action-authorized.
- Authorization defaults to zero. A bounded allowance applies only to its declared action kind, count, policy generation, and stop generation.
- Scorer truth outranks transport success and relay acknowledgement.
- Platform-specific behavior exists only through the selected adapter. Generic controllers consume normalized artifacts.
- Rookery-owned network and attachment helpers enforce scope before access. Raw shell still obeys the operator-declared scope.
- Newest operator instruction supersedes stale goal or policy state.
- `./go status` is a pure read. Do not turn status into a transition trigger.
- `./go stop` advances the stop generation. Every Rookery-owned mutation checks that generation immediately before acting.
- Queue automation is off by default. When enabled by policy, `./go` owns one cadence-preserving watcher.
- A challenge is never unknowable. Parked work returns through a materially different method, bounded naive search, hard investigation, corpus research, or scheduled external-state retry.
- Every completed objective gets a solve capsule immediately and a complete writeup before final closeout. Follow `docs/voice.md`.

## Read first

- `README.md`
- `docs/operator.md`
- `docs/upgrade.md`
- `docs/preparation.md`
- `docs/event_profiles.md`
- `docs/adapters.md`
- `docs/scope.md`
- `docs/state_policy_stop.md`
- `docs/coordination.md`
- `docs/agents.md`
- `docs/scoring_review.md`
- `docs/evidence_state.md`
- `docs/measurement.md`
- `docs/research.md`
- `docs/tools_and_wrappers.md`
- `docs/writeups.md`
- `docs/lessons.md`
- `docs/voice.md`

## Worker cards

Register every worker before dispatch with required `--goal`, `--scope`,
`--report-path`, and `--stop-condition`. A successor also receives the exact
source `--handoff-id`. Send those same values in its card. Recon cards stay
tiny:

For challenge-linked work, `--objective-id` and `--challenge-id` are the same
exact canonical challenge ID. Do not prefix or relabel the objective ID.

```text
Goal: <one bounded reconnaissance question>
Scope: <targets, files, allowed actions, forbidden actions, and budget>
Parent attempt: none for a depth-1 worker; exact challenge-coordinator attempt ID for depth 2
Depth: 1 or 2
Source handoff: none for an initial route; otherwise <handoff ID and report path>
Source report SHA-256: none for an initial route; otherwise <exact 64hex report hash>
Report: analysis/<lane>/REPORT.md
Stop: <time, artifact, signal, or exact negative>
```

Recon workers collect evidence, save interesting files, and report exact paths and next commands. They do not carry the full scoring protocol. If they see a flag-like value or scoring marker, they preserve the exact value and source path; the coordinator handles proposals.

Every worker writes the exact report path early from `templates/REPORT.md`.
Directly after the title, keep `## Handoff` with these one-line labels in
order: Status, Source handoff, Source report SHA-256, Observed result, Route key, Proof gap,
Discriminating test, Next step or return trigger, Evidence paths,
Command/artifact paths, Blocker, Cleanup/jobs. The path fields are JSON arrays
of current-workspace-relative POSIX paths to private regular artifacts below
`analysis/`, `evidence/`, `work/`, `exploit/`, `captures/`, or `downloads/`;
`state/`, `platform/`, absolute, outside-workspace, symlink, and prose entries
are invalid. Copy needed state or platform evidence into an allowed root first.
`Route key` matches `[a-z0-9][a-z0-9._:-]{0,127}` exactly. The path fields are
JSON arrays; human-readable detail follows under `## Evidence` and `## Commands`. Use a
current typed outcome for Status and replace every placeholder before the
coordinator integrates the report.

`Source handoff: none` and `Source report SHA-256: none` are valid only for an
initial route. A successor opens and reads the exact source report before
acting, cites its handoff ID and exact registered 64hex hash, and names a
materially different route with a nonempty discriminating test. Depth-2 workers
register with `--parent-attempt-id` naming the exact active depth-1 challenge
coordinator for the same challenge and objective. They also carry prior
rejected routes and the current proof gap. Workers write reports;
only the coordinator runs `./bin/agent-harvest` for normal report integration, records the outcome and
continuation, and closes the attempt.

If a specialist fails to start because of model or service availability, retry the same bounded task immediately with the default worker and record one compact fallback note. Never request fixed model names or priority service.

## Autonomous modes

Choose modes internally; do not ask the operator to manage them:

- fast frontier for concrete technical wins;
- race for several fresh approaches to one promising lane;
- grind for checkpointable brute force, fuzzing, cracking, symbolic work, or dynamic analysis;
- research through local corpus and SearXNG;
- parked retry through a different method;
- near-miss split after a structured rejection;
- closeout, solve capsules, and writeup completion.

## Outcomes

Normalize worker results as supported finding, technical negative, incomplete evidence, generic refusal, capacity failure, environment failure, duplicate trace, invalid scope, candidate, no progress, or other. Retry generic refusal and capacity failure with shorter CTF-specific context and unchanged boundaries. After three materially equivalent traces, require a named discriminating test before repeating the mechanism.
