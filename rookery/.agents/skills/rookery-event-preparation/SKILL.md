---
name: rookery-event-preparation
description: "Use when asked to prepare, configure, or check readiness for an authorized Rookery event. Do not trigger for active solving, bridge operations, retrospectives, or release publishing."
metadata:
  short-description: Prepare an authorized Rookery event.
---

# Rookery Event Preparation

## When to Use

- Prepare a new Rookery workspace for an authorized event.
- Check event configuration, scope, local capabilities, a baseline, or selected adapter readiness.
- Produce a factual readiness handoff before launch.

## When NOT to Use

- Run an active event, coordinate solvers, or submit an answer.
- Export, start, stop, or repair a Windows browser bridge; use `rookery-browser-bridge`.
- Review a completed runtime or publish a release.

## Workflow

1. Work from the installed Rookery root on Linux or WSL. Read the [canonical source map](references/canonical-source-map.md), then run only the documented commands whose effects the task authorizes.
2. Read the private `.env` as data; never source it or copy its values into a report. Use `./go status` only as a pure read. If runtime state exists, read `state/resolved_event.json`, `state/scope.json`, `PREPARATION.md`, and `ACTIVE_SURFACE.md` before drawing conclusions.
3. Confirm the release, resolved event, acknowledged scope, Codex authentication, selected adapter, required capabilities, and private release-bound measurement baseline. Record absent or unverified facts as blockers.
4. For a browser-backed adapter, require its selected loopback endpoint, dedicated profile, and documented session contract. Read `adapters/<selected-id>/README.md`, descriptor, and profile. When that contract declares CDP or a sealed gateway, require event authority, exact origin and identity binding, participation binding, event-card or session proof, and the complete release-bound Chrome bridge tuple: release, baseline, gateway policy, immutable Windows bundle, profile, and ownership record. For BiDi, require the adapter's documented Firefox endpoint and profile without inventing a Chrome tuple.
5. When the selected adapter declares an external bridge and a read-only production sync, require Windows bridge health and WSL `browser-health` before that sync. The sync must prove every documented account, event, and session invariant. Treat registration, team selection, SSO, or another unexpected interactive state as an operator-visible blocker; do not automate it.
6. Inspect normalized inventory before making an autonomy claim. Require every intended scoring modality to be supported by the selected adapter's declared contract. Treat rows the adapter marks already solved, locked, manual, choice-based, or unsupported as explicit coverage gaps unless the selected contract provides an approved path.
7. Establish the intake gate for solver work: immutable detail and capture artifacts must pass the shared path, mode, size, and digest checks, all required captures must be present, and resources must be complete. Use `./bin/challenge-unlock-watch check --ingest` for ordinary backfill; handle `intake_partial_ids` and `intake_errors` as explicit blockers. Reserve `./bin/challenge-ingest ID` for one selected pending challenge or reviewed recovery. Never re-ingest a verified complete ID.
8. Create a private baseline or gateway policy only when the task expressly authorizes that write. Otherwise report the missing artifact. Do not start `./go` as a preflight step.
9. Produce a concise handoff: confirmed facts, blockers, modality coverage, materialized-intake status, bridge tuple status where relevant, and the next authorized command.

## Boundaries

- `./go` starts or resumes Rookery and is never an implied preflight step.
- A browser bridge is external to `./go`; hand its lifecycle to `rookery-browser-bridge`.
- Adapter session readiness and inventory health do not grant scoring authority. Proposals, independent review, current authorization, stop checks, execution, and scorer truth remain separate.
- Keep live configuration, session material, runtime evidence, and baseline records private.

## Deterministic Tools

This skill ships no helper scripts. Use the documented Rookery commands and the selected adapter surface from the installed Rookery root.

## References

- Read the [canonical source map](references/canonical-source-map.md) for the maintained event, selected-adapter, bridge, scope, and intake contracts.
