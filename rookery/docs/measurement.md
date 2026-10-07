# Event Measurement Protocol

Rookery measures operational reliability and evidence completeness across authorized events. It does not turn one event into a claim about general solving effectiveness, strategy quality, ideal concurrency, or solve rate.

The [README](../README.md) and [operator guide](./operator.md) contain the operator workflow. This page defines the baseline, evidence, eligibility, and interpretation contract behind it.

## Baseline

Before the first `./go`, create the required private measurement baseline from the verified release archive and its manifest. Set `ROOKERY_MEASUREMENT_BASELINE_PATH` to the same absolute output path in `.env`. The baseline must live outside the source and runtime directory; it is no-clobber and the command refuses a source tree that already contains runtime state.

The baseline binds:

- the release ZIP and per-file manifest;
- deployed source, strict tree identity, and release version;
- the live `.env` hash and byte count, `configuration_source: "env"`, and the canonical resolved-manifest hash;
- selected adapter and extensions, declared scope, queue settings, native
  worker, shared Codex subagent-thread, and background-job limits;
- UTC and local clock context; and
- declared availability, rather than values, for provider queue, token, and usage fields.

The archive contains the reviewed `.env.example`, never the live `.env`. At launch, `measurement.started` records the actual stop, policy, and compiled-scope generations alongside the value-free queue-automation flag and provider availability enums. If the baseline is missing or mismatched, launch stops before preparation, adapter access, or runtime writes.

`bin/measurement-baseline` requires `--archive`, `--manifest`, and `--output`. Its optional `--provider-field NAME=available|unavailable:reason` declarations describe whether a provider metric can be measured; they do not supply the metric. The implementation is [baseline.py](../lib/rookery/portable/baseline.py).

## Required measurements

Counts always travel with their denominators. A percentage without both is not an integrity measure.

| Area | Report together | Integrity question |
| --- | --- | --- |
| Canonical state | JSONL rows, SQLite rows, event types, first/last UTC | Do the durable representations agree and cover the event window? |
| Commands | starts, terminals, pairs, envelopes, termination classes, retained-output bytes | Does every schema-2 start have one terminal record and retained hashes? |
| Queue watcher | retained queue-watch file bytes and lines | The current reporter does not parse queue transitions, heartbeats, or tick duration into comparison evidence. |
| Attempts and scoring | registered attempts, typed outcomes, proposals, reviews, plans, authority, terminal lineage | Does every terminal have canonical lineage under the exact review and plan pinned when execution started? |
| Evidence | required/optional references, present/missing/rejected rows, bytes and files | Does the schema-3 evidence manifest cover every required retained path? |
| Stop and resources | confirmed/unmanaged/unacknowledged jobs, reconciliation time, local CPU/RSS coverage, provider coverage | Are locally owned work and externally supplied provider fields reported as separate cohorts? |

Also retain event duration and per-objective elapsed time. Raw totals from events of different length or workload do not become rates by implication.

### Current queue limitation

Queue automation currently makes an event ineligible for telemetry comparison. This release does not emit or consume canonical queue-timing events, even when a retained queue-watch log contains transitions, heartbeats, or tick-duration fields. The reporter therefore returns queue timing as unavailable and the eligibility gate fails. Treat queue-watch logs as private operational evidence; do not plan an automation-enabled event around comparison eligibility until the timing producer and consumer exist.

## Closeout and report eligibility

Before derived analysis, stop new mutation, reconcile owned jobs, require typed outcomes for terminal attempts, run `bin/evidence-manifest --require-complete`, and preserve the runtime. Analyze only a quiescent copy or a verified preserved tree; telemetry must not create SQLite sidecars or change source hashes.

`bin/telemetry-report` emits a report from canonical preserved evidence. It can be coherent while still ineligible for comparison. Comparison eligibility requires all of these gates:

- canonical state and command lifecycle coherence;
- complete evidence-manifest coverage;
- a verified baseline binding and complete scoring-chain lineage;
- typed attempt outcomes and valid temporal/generation replay; and
- applicable, complete queue, stop, resource, and provider coverage.

Missing data remains `not_available` with its reason. It is never silently converted to zero. An enabled queue without supported timing evidence is ineligible, not a zero-latency queue. A baseline-declared provider field with no terminal-job denominator is likewise ineligible rather than a misleading 0/0 coverage result.

## Comparison and interpretation

`bin/telemetry-compare` takes two preserved runtime roots and an output path outside both roots. It regenerates each input report twice and rejects a moving, internally inconsistent, or comparison-ineligible runtime. Separate `--left-source-root` and `--right-source-root` values are available only when the two preserved runtimes recorded different deployed root paths.

The comparison output is explicitly descriptive. It reports configuration, baseline, release, provider-availability, event-window, outcome, launch-generation, and operational-applicability differences alongside bounded counts, coverage denominators, and latency-quantile deltas. It does not prove improvement, regression, or causation.

Treat challenge mix, difficulty, platform behavior, and external-provider availability as confounders. The comparator can surface only confounders retained in the reports; it cannot infer context that an event did not record. Use a difference as a reason to investigate, then preserve the evidence and reasoning behind any conclusion.

The read-only reporter lives in [telemetry.py](../lib/rookery/portable/telemetry.py); the comparison gate lives in [telemetry_compare.py](../lib/rookery/portable/telemetry_compare.py).
