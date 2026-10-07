# Coordination

Rookery keeps event work moving through a small, auditable loop:

1. Edit the private `.env`, validate its resolved configuration, set `EVENT_SCOPE_ACK=1` only after scope review, create the release-bound baseline, and prepare required external sessions.
2. Start with `./go`; it prepares supported local capabilities and renders the
   active surface.
3. Read `PREPARATION.md` and `ACTIVE_SURFACE.md`, then collect normalized
   platform state when a selected adapter supports it.
   `challenge-unlock-watch check --ingest` reports newly visible challenge IDs
   separately from visible challenges whose details have never been ingested.
   It consumes that intake backlog in bounded batches and reports complete,
   partial, deferred, blocked, and failed rows separately. A complete row has
   immutable detail and capture artifacts whose paths, modes, sizes, and hashes
   pass the shared intake verifier.
   A failed detail read remains pending, but its recorded attempt moves behind
   unattempted rows so one broken challenge cannot starve the intake backlog.
   Read the event's current rules before handling challenge material, and use
   required offline isolation for untrusted binaries.
4. Rank the frontier and record why the next objective matters. Before solver
   dispatch, require verified complete intake. Agent registration, exploration,
   compute, and challenge-bound subagent dispatch recheck that condition. Ingest one
   selected pending or partial challenge directly when reviewed recovery is
   required.
5. Assign non-overlapping, report-first workers only after that intake gate.
6. Harvest reports, record typed outcomes, and change method when evidence
   stops moving.
7. Create a scoring proposal for a likely answer or action.
8. Have an independent reviewer decide whether the evidence supports it.
9. Grant bounded authority, compile an immutable plan, and execute only through
   the selected adapter.
10. Reconcile structured scorer truth.
11. Create the solve capsule immediately, finish the writeup, and close out.

The only everyday controls are `./go`, `./go status`, and `./go stop`.
`./go status` only reads state. `./go stop` advances the canonical stop
generation, revokes unused authority, and asks owned work to stop. A stopped
generation resumes only when the operator invokes `./go` again. Details and
failure states are in [State, policy, and stop](./state_policy_stop.md).

## Contents

- [Keep work bounded](#keep-work-bounded)
- [Make every handoff useful](#make-every-handoff-useful)
- [Shared artifacts](#shared-artifacts)
- [Conflict resolution](#conflict-resolution)
- [Explore a stalled challenge](#explore-a-stalled-challenge)
- [Coordinate several challenges](#coordinate-several-challenges)
- [Use idle CPU carefully](#use-idle-cpu-carefully)
- [Completion](#completion)
- [Scoring and closeout](#scoring-and-closeout)

## Keep Work Bounded

Use one report path per worker and harvest it once. Record a result as a
supported finding, technical negative, incomplete evidence, candidate, no
progress, capacity failure, environment failure, duplicate trace, invalid
scope, generic refusal, or another explicit outcome. A worker that sees a
candidate reports its evidence; it does not submit it.

When a route stalls, rotate the method: a fresh naive solver, bounded brute
force, hard investigation, local corpus research, public research, or a
scheduled external-state retry. After three materially equivalent traces, name
the discriminating test before repeating the mechanism. Work is parked with a
return condition, never declared unknowable.

## Make Every Handoff Useful

Register a worker with an explicit challenge ID or `--event-wide` before it
starts. Registration includes one bounded `--goal`, `--scope`, exact
`--report-path`, and `--stop-condition`. Give the worker the same values in its
card. The worker writes the report early and replaces every placeholder before
integration.

For challenge-linked registrations, pass the exact canonical challenge ID to
both `--objective-id` and `--challenge-id`.

Directly after the report title, require `## Handoff` with the exact labels and
order defined by `templates/REPORT.md`: Status, Source handoff, Source report
SHA-256, Observed result,
Route key, Proof gap, Discriminating test, Next step or return trigger, Evidence
paths, Command/artifact paths, Blocker, and Cleanup/jobs. Path fields are JSON
arrays of current-workspace-relative POSIX paths to private regular artifacts;
allowed roots are `analysis/`, `evidence/`, `work/`, `exploit/`, `captures/`,
and `downloads/`. `state/`, `platform/`, absolute, outside-workspace, symlink,
and prose entries are invalid; copy needed evidence first. Route keys use the exact ASCII grammar
`[a-z0-9][a-z0-9._:-]{0,127}`. Human-readable detail follows under
`## Evidence` and `## Commands`.
Use `./bin/agent-harvest` for normal integration so the report supplies its own
exact canonical fields. Use `./bin/rookery agent integrate` only for a diagnosed
manual repair. A file hash by itself is not a handoff.

For an unsolved challenge, open a current continuation that consumes that
handoff before recording the outcome and closing the attempt. The continuation
can be an active successor assignment, a scheduled retry, an approved proposal
with an explicit challenge link, an exploration campaign, or a named external
boundary with a return condition. Rookery rejects a new challenge-linked close
when the handoff or consuming route is missing. Read `agent`, `outcome`, and
`explore` command help for their exact bounded fields.

Harvest debt takes priority over new worker fanout. The coordinator reads each
handoff before assigning the next worker, passes its evidence and proof gap to
that worker, and records why the new route differs. A successor opens and reads
the exact source report before it acts, uses that handoff ID and exact
registered 64hex report hash rather than `none`, and names a materially
different route with a nonempty discriminating test in its own handoff.
Historical work without a safe link remains visible as legacy debt;
Rookery does not infer a challenge from an objective name or declare it solved.
After `./go stop`, a late worker report remains visible as reconciliation debt
with its exact report path in `./go status`. The old stop generation cannot
integrate it into a new handoff, record a new outcome, or open a continuation.

## Shared Artifacts

`state/events.sqlite3` is canonical runtime truth. A worker owns only its
assigned report and artifact paths; other workers read them as evidence and do
not rewrite them. The coordinator owns registration, report integration,
outcomes, continuations, and attempt closure. Generated JSON and Markdown views
remain projections or handoffs.

## Conflict Resolution

The newest operator instruction decides event facts, scope, authorization, and
stop. Canonical state decides lifecycle and generation facts. Structured scorer
truth decides scoring results. For technical disagreement, the coordinator
assigns a named discriminating test to a non-overlapping worker and records the
result; after three materially equivalent traces, do not repeat the mechanism
without that test.

## Explore A Stalled Challenge

When eligible untouched challenges wait, rank them ahead of a stalled
challenge. Keep the stalled challenge visible with a continuation and a
specific return condition. If spare capacity exists, open a campaign with
`./bin/rookery explore open` using the structured handoff and tried route keys.

The campaign gives four bounded ideation passes different context: `fresh`
starts from the challenge facts, `evidence` studies supported findings and
negatives, `artifact` inspects concrete local material, and `contrarian`
tests assumptions and neglected methods. Each pass produces exactly ten
structured ideas in a private `IDEAS.json`. A separate synthesizer states what
it learned from the handoff, classifies duplicates and tried routes, and picks
up to four untried ideas with discriminating tests. After all four lens batches
are recorded and their reports integrated, claim the synthesis packet with
`./bin/rookery explore claim-synthesis --campaign-id ID --agent-attempt-id ATTEMPT`
before dispatching the synthesizer. The synthesizer reads the source handoff
and all four batch reports first; selection is accepted only from that claimed
attempt and its integrated handoff. Selected ideas enter the existing compute
queue in the same state transaction.

An admitted idea goes to a fresh, registered native subagent. A depth-1
challenge coordinator may delegate one bounded idea to a depth-2 worker and
must bind that worker to the exact compute lease. If capacity is unavailable,
the campaign stays `capacity_wait`; if no novel route is ready, it stays parked
with a named recheck condition. Neither state means the challenge has failed.

## Coordinate Several Challenges

Rookery launches exactly one Codex session. Its main coordinator runs at depth
0 and asks the operator how many distinct challenges to keep active. It then
registers and creates one native depth-1 challenge coordinator for each
solver-ready, unsolved challenge up to that requested count.

Each challenge coordinator owns exactly one challenge investigation. It reads
the challenge's existing evidence and handoff, preserves new evidence, creates
proposals, and may create bounded worker subagents at depth 2. It does not sync
the platform, manage the browser session, assign independent reviews, grant
authority, execute scoring actions, or reconcile scorer truth. Those shared,
event-wide duties stay with the main coordinator.

The main coordinator tracks active native subagents directly. When a challenge
coordinator finishes, the main coordinator reads and integrates its report,
records its typed outcome and any continuation, and closes the exact attempt.
Only then does it refill the open slot with a successor or a different eligible
challenge. If the operator lowers the requested count, existing bounded work
finishes and the main coordinator stops refilling excess slots.

Challenge coordinators and their workers share one
`CODEX_SUBAGENT_THREADS=96` ceiling. Capacity is global to the session: active
coordinators, depth-2 workers, reviewers, and other native subagents all consume
the same spawned-thread allowance. The main coordinator must keep enough free
capacity to harvest work, review candidates, and respond to stop. The
low-priority compute queue remains separate from foreground coordinator
selection and may use only capacity that is actually idle.

## Use Idle CPU Carefully

Keep only useful, checkpointable work in the low-priority compute queue. It is
separate from scoring and cannot authorize, launch, signal, submit, or mutate a
platform. Enqueue one bounded idea with an exact report and stop condition:

```bash
./bin/rookery compute enqueue \
  --objective-id event-wide \
  --goal 'Test one bounded low-priority hypothesis' \
  --scope 'Local fixture and analysis/idle-lane only' \
  --report-path analysis/idle-lane/REPORT.md \
  --stop-condition 'Ten minutes or one exact negative' \
  --mechanism 'Bounded fixture search' \
  --dedupe-key event-wide:fixture-search \
  --dispatch-kind agent \
  --requested-cpu-threads 1 \
  --budget-seconds 900
```

After worker harvests and before an idle wait, sample CPU and request one
admission decision:

```bash
./bin/rookery compute tick
```

The default policy targets 75% CPU as a best-effort operating point. A tick
uses two adjacent one-second windows from affinity-visible Linux CPUs. It
admits at most one idea when both windows are below 70%, the requested threads
fit below the 80% ceiling, and the matching worker or job reserve remains. Two
windows at or above 85% produce at most one cooperative pause request. Missing
metrics admit nothing. Expected value plus evidence value ranks ideas first;
equal-value admissible ideas prefer predicted utilization closest to 75%
without crossing the ceiling.

A `lease` result includes an `idea_id`, `admission_id`, and 30-second default
expiry. The coordinator starts a normal registered agent or owned job of the
queued `dispatch_kind`, then binds it to that lease:

```bash
./bin/rookery compute start IDEA_ID --admission-id ADMISSION_ID --agent-attempt-id ATTEMPT_ID
```

Use `--job-id JOB_ID` instead for an idea enqueued with `--dispatch-kind job`.
An agent binding must also match the idea's objective, report path, and current
stop generation. Record the result:

```bash
./bin/rookery compute outcome IDEA_ID \
  --status completed \
  --summary 'Bounded search completed with a useful negative.' \
  --admission-id ADMISSION_ID \
  --agent-attempt-id ATTEMPT_ID
```

For a job lease, use the exact `job_label` from the tick result, then bind and
close the same owned job:

```bash
job_label='compute:IDEA_ID:ADMISSION_ID'
./bin/runbg --label "$job_label" -- command argument
./bin/rookery compute start IDEA_ID --admission-id ADMISSION_ID --job-id JOB_ID
./bin/rookery compute outcome IDEA_ID \
  --status completed \
  --summary 'Bounded job completed.' \
  --admission-id ADMISSION_ID \
  --job-id JOB_ID
```

Every outcome requires the admission ID and exactly the agent attempt or job
recorded at start. Duplicate terminal outcomes fail. A worker that receives a
pause request first writes its relative checkpoint path inside the workspace,
then records `paused` with `--checkpoint-path`. The final checkpoint must
already be a regular file with no group or other permission bits, have one
hard link, and have no symlink in its path; `compute requeue IDEA_ID` checks it again. Use `compute list` or
`compute status [IDEA_ID]` to inspect the queue. A stop-generation change makes
unfinished ideas stale and prevents new leases, starts, or outcomes. Never
invent work merely to raise CPU usage.

## Completion

The coordinator is the final owner of worker completion. Before closing an
attempt, it reads the completed report, integrates the structured handoff,
records the typed outcome and any required continuation, and verifies the exact
stop condition. Event completion additionally requires scorer truth or the
configured evidence-only record, an immediate solve capsule, and the required
writeup.

## Scoring And Closeout

Review, authorization, and execution are different actions. Authorization
starts at zero and applies only to its declared action kind, count, policy
generation, and stop generation. Scorer truth outranks a relay acknowledgement
or transport success. See [Scoring and review](./scoring_review.md).

A rejected execution produces a fingerprint derived from identifiers and
hashes, never the candidate value. A follow-up proposal may reference it only
when it names the discriminating change.

Every accepted objective needs a capsule. Every completed objective needs a
complete writeup before final closeout. `./go stop` also creates one
improvements-only lessons document for the new stop generation when normal
closeout can run. See [Writeups](./writeups.md), [Lessons](./lessons.md), and
[Voice](./voice.md).
