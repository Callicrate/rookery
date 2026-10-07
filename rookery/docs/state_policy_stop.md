# State, Policy, and Stop

`state/events.sqlite3` is Rookery's canonical runtime history. JSON, JSONL, and Markdown files under `state/` are deterministic projections from that database. They make the runtime inspectable, but they do not create an independent source of truth.

This page defines the lifecycle semantics. The small operator surface remains [`./go`, `./go status`, and `./go stop`](./operator.md).

## Canonical records and views

| Artifact | Role |
| --- | --- |
| `state/events.sqlite3` | Transactional event history and metadata |
| `state/events.jsonl` | Stable event projection for inspection and preserved analysis |
| `state/runtime.json`, `state/current.json` | Derived lifecycle and current-state views |
| `state/policy_effective.json`, `state/queue_state.json` | Derived policy and queue views |
| `state/resolved_event.json`, `state/scope.json` | Resolved configuration and compiled-scope cache, both checked against canonical authority before use |

Every normal mutation and projection write rechecks the launch binding. That binding ties the workspace, immutable shipped source, private `.env`, canonical resolved configuration, Codex executable, and measurement baseline together. A changed or copied workspace blocks normal mutation; a projection is never silently rebuilt from unverified inputs. The emergency stop path deliberately bypasses that normal check only to record revocation metadata and events in an existing database.

## Policy generation

Policy stores one effective value per supported key with its source, reason, time, generation, and supersession history. Current policy values are advisory and display-only. Controllers do not treat arbitrary `policy set` values as live configuration.

The policy generation is an enforced safety predicate. A change makes prior scoring authority and immutable execution plans stale. They must be reviewed, authorized, and compiled again under the current generation. This keeps an old approval from reaching an adapter after the policy that contextualized it has changed.

## Stop generation

`./go stop` advances the stop generation before its other shutdown work. Mutating helpers compare their observed generation immediately before a mutation. A stopped workspace resumes only through a later explicit `./go`; process restart cannot resume it by accident.

On a workspace with no canonical event database, `./go stop` is a successful no-op. It reports `owned_work=false` and `state=uninitialized`, then creates no runtime state or stop prompt. When canonical state exists but normal binding verification is unavailable, the emergency stop path can only revoke existing work; it cannot create a database, resume work, grant authority, or repair the integrity failure.

Execution consumes authority and records its durable start under the workspace mutation lock. It checks the stop generation again immediately before adapter dispatch. If execution obtains the lock first, its terminal event is committed before stop advances the generation. If stop obtains it first, the stale plan does not reach the adapter. A consumed allowance is not restored when that final generation check blocks dispatch.

The same transaction records authorization consumption and a plan's durable execution claim. One immutable plan therefore cannot be dispatched twice after a crash or through a multi-count allowance.

## Shutdown evidence

Stop records distinguish a requested signal from a proved result:

| Result | Meaning |
| --- | --- |
| `closed` or `cancelled` | A signalled, locally owned process identity disappeared. |
| `unmanaged` | No verifiable local ownership existed for the actor. |
| `unacknowledged` | A locally owned identity remained live after the bounded wait. |
| `command.stopped` | A signalled, locally owned command identity disappeared. |

`closed`, `cancelled`, and `command.stopped` are positive shutdown acknowledgement for their corresponding actor types. The stop result retains separate confirmation lists and a `not_confirmed` aggregate, so uncertainty cannot be mistaken for confirmed closure. The queue watcher exists only when the event policy enables it; Rookery owns its identity and stop behavior.

For the transactional implementation, see the [event store](../lib/rookery/portable/store.py). For the scoring side of these generation checks, see [Scoring review](./scoring_review.md).
