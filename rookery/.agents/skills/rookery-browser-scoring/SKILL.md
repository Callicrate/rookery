---
name: rookery-browser-scoring
description: "Use when asked to prepare, diagnose, or execute reviewed scoring through Rookery's selected browser-backed adapter. Do not trigger for solving, raw browser control, or bridge operations."
metadata:
  short-description: Guide reviewed browser-backed scoring.
---

# Rookery Browser Scoring

## When to Use

- Prepare or diagnose reviewed scoring with the selected browser-backed adapter.
- Decide whether a selected browser-session adapter is ready for a reviewed candidate.
- Carry an independently reviewed candidate through Rookery's authorized scoring chain.

## When NOT to Use

- Solve a challenge, search for a candidate, or submit from a solver.
- Navigate, click, fetch, or submit through raw CDP or browser automation.
- Export, start, stop, or repair the external Windows bridge; use `rookery-browser-bridge`.
- Score through an adapter whose declared profile is not browser-backed.

## Workflow

1. Work from the installed Rookery root. Read the [canonical source map](references/canonical-source-map.md), then read `state/resolved_event.json`, `state/scope.json`, `PREPARATION.md`, and `ACTIVE_SURFACE.md`. Require the resolved adapter, proposal, plan, envelope, and dispatch adapter to agree. Do not edit generated views.
2. Require the selected adapter's loopback browser endpoint and authenticated profile, its identity configuration, current baseline and scope, and healthy selected capabilities. For a CDP or gateway-backed adapter, require the complete Chrome bridge tuple and, when applicable, the matching policy and gateway status; hand bridge lifecycle work to `rookery-browser-bridge`. For a BiDi-backed adapter, require its documented Firefox endpoint and profile contract instead.
3. Read the selected adapter's `README.md`, descriptor, and profile. Apply its exact typed transport, session, identity, event-proof, modality, and submission requirements. Require a current read-only health or sync proof when the adapter declares one. Never switch transport, infer a fallback condition, or construct adapter-specific branching outside that contract.
4. Require current normalized inventory and verified complete intake before review. The shared verifier must confirm immutable detail and capture paths, private modes, sizes, hashes, exact attachment coverage, complete resources, and one unsolved objective whose modality the selected adapter marks submittable. Read detail and attachment evidence through the selected adapter surface; do not use raw browser controls.
5. Keep the scoring chain separate:
   1. A solver uses `./bin/score-propose` only.
   2. An independent reviewer approves or rejects the proposal from preserved evidence.
   3. A separate authorized actor grants exact or bounded authority for the current policy and stop generation.
   4. The executor compiles the sealed plan and dispatches it through the selected adapter.
   5. Reconcile the structured scorer response. Transport success alone is not a verdict.
6. Fail closed on identity, event, scope, policy, session, CSRF, lease, target, redirect, or scorer-verdict ambiguity. Do not loosen scope, change browser tabs, bypass the adapter, retry an indeterminate committed attempt, or turn browser readiness into scoring authority.
7. Keep candidates, credentials, session values, authorization data, and raw scorer evidence in the private runtime. Return a value-free handoff naming the adapter, readiness, chain stage, blocker, and next authorized Rookery command.

## Boundaries

- Solvers never submit directly or control a browser directly.
- A prepared browser session grants no submission authority.
- The selected adapter ID stays stable even when it selects an internal transport.
- Do not start `./go`, grant authority, or execute a scoring action unless the task explicitly authorizes it.

## Deterministic Tools

This skill ships no helper scripts. Use only the documented commands and selected-adapter surface exposed by the installed Rookery release and `ACTIVE_SURFACE.md`.

## References

- Read the [canonical source map](references/canonical-source-map.md) for adapter, session, scope, review, evidence, and bridge contracts.
