# Scoring Review

Rookery separates finding a candidate from changing an external scorer. A solver creates a proposal. An independent reviewer approves or rejects it. A separate executor compiles an immutable plan, performs its checks, consumes current authority, and reconciles the scorer's structured result. No role inherits another role's approval.

The operator flow belongs in the [operator guide](./operator.md). This page defines the contract that the flow enforces.

## Proposal envelope

A proposal records the objective, action kind, exact value or artifact reference, attempt/session scope, verifier evidence, adapter ID, policy generation, freshness requirements, source, and rationale. The canonical action kinds are:

| Kind | Intended effect |
| --- | --- |
| `flag`, `free_text`, `multi_objective` | Submit an event answer in the declared form |
| `handle_write` | Change or claim a rotating activity handle |
| `proof_artifact` | Submit or register a proof artifact |
| `no_submit_evidence` | Record local evidence without a scorer mutation |

The operator declares allowed action kinds with `SCORING_ACTION_KINDS` in `.env`; the resolved event carries that typed list. A proposal can name an active, registered solver attempt; when it does, Rookery validates that lineage. Missing attempt lineage prevents comparison eligibility later, but it does not turn a value into permission to submit it. Every proposal still carries current policy and stop context.

## Authority and execution

Authorization starts at zero. A mutating action needs either exact manual approval for that proposal or a current bounded allowance for its action kind. An allowance is limited by its declared kind, remaining count, policy generation, and stop generation. `no_submit_evidence` is non-mutating and does not consume a scorer-action allowance.

Each allowance use consumes one count and durably republishes any remainder
under the same authorization identity. Every plan still binds the exact count
state it observed, so concurrent or repeated execution cannot spend the same
count twice.

Before an external action, the executor creates a sealed plan with the proposal, review, authorization predicate, scope and generation bindings, and planned evidence locations. It performs offline validation and read-only preflight first. Authority is consumed only at the first mutation, then the executor rechecks stop generation immediately before adapter dispatch.

This is the only path that may invoke a selected adapter's submission operation. Stale review, policy, scope, freshness, authorization, or stop context blocks the plan rather than being repaired in place.

The plan pins one exact approved review event. A newer review before authority
claim makes that pending plan stale. A review recorded after the terminal
execution remains additional evidence; it cannot rewrite or invalidate the
historical review, authority, scorer truth, completion record, or capsule that
the completed plan already bound.

## Scorer truth

Transport success is not a scoring verdict. HTTP 200, a successful child process, or a relay acknowledgement records transport or relay truth only. A structured scorer rejection takes precedence.

Direct adapter response directories enter canonical state once through the reconciler. Their sibling request metadata binds objective, candidate, attempt, and adapter context; unbound wrapper noise is ignored by default. A repeated candidate, or a proposal explicitly marked as a follow-up, names the prior rejection fingerprint and a concrete discriminating change. A changed candidate can begin as a fresh proposal; comparison-eligible retry lineage must still satisfy the retained parent-fingerprint rules.

`answer-ledger` and `task-completion-audit` are projections of this canonical event stream. The correlation view connects proposal, review, plan, authorization consumption, durable start, terminal verdict, and evidence paths without returning the exact candidate value.

Exact values and raw scorer evidence remain in the private runtime; see [Evidence and state](./evidence_state.md). The implementation source for the proposal and authorization contract is [scoring.py](../lib/rookery/portable/scoring.py), with immutable-plan dispatch in [execution.py](../lib/rookery/portable/execution.py).

## Completion mode

`SCORING_COMPLETION_MODE` in `.env` resolves to `scoring.completion_mode` and states what can complete an objective. The
`scorer_truth` mode requires a healthy selected scoring capability before the
coordinator starts. A reviewed proposal, granted authority, transport success,
or a capsule file cannot substitute for an accepted scorer verdict.

The manual adapter uses `evidence_only`. It permits only
`no_submit_evidence`, which follows the normal proposal and independent review
path without making a platform mutation. Its completed plan can create an
evidence capsule, but cannot mark a platform challenge solved. A scoring
adapter must be selected in a new, baseline-bound workspace when actual flag
submission is required.

For a solve capsule, `action_reference` is the exact plan ID and the evidence
path must match the canonical accepted execution. Rookery checks the proposal,
review, plan, authority consumption, durable start, and structured terminal
verdict together. Legacy free-form capsules remain private evidence but do not
satisfy closeout until their chain can be verified. See [Writeups](writeups.md).
