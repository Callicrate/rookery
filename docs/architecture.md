# Architecture

## Contents

- [Summary](#summary)
- [Component map](#component-map)
- [Execution flow](#execution-flow)
- [Trust and authority boundaries](#trust-and-authority-boundaries)
- [State and evidence](#state-and-evidence)
- [Platform and network boundary](#platform-and-network-boundary)
- [Release boundary](#release-boundary)

## Summary

Rookery is a local coordination harness for authorized CTFs and security labs. It combines a small operator interface with a capability-selected set of Codex workers, durable evidence, explicit scope, and a separated scoring path.

The repository root is a development shell. [`rookery/`](../rookery/) is the canonical deployable source and the root wrappers validate that tree before delegating to it. Release code has no dependency on repository-only tests, contributor documentation, or maintenance skills.

## Component map

| Component | Source | Responsibility |
| --- | --- | --- |
| Operator surface | [`go`](../go), [`rookery/go`](../rookery/go) | Start or resume, read status, and advance the stop generation |
| Launch and validation | [`rookery/bin/rookery`](../rookery/bin/rookery), [`rookery/bin/validate_rookery.py`](../rookery/bin/validate_rookery.py) | Enforce configuration, release, privacy, baseline, Codex, and workspace gates |
| Event configuration | [`rookery/.env.example`](../rookery/.env.example), [`rookery/profiles/`](../rookery/profiles/), [`rookery/docs/event_profiles.md`](../rookery/docs/event_profiles.md) | Resolve event identity, capabilities, scope, scoring kinds, concurrency, and selected integrations from the operator's one editable file |
| Preparation | [`rookery/configs/preparation.json`](../rookery/configs/preparation.json), [`rookery/docs/preparation.md`](../rookery/docs/preparation.md) | Discover required and optional local capabilities; perform only explicitly enabled network installation |
| Coordination | [`rookery/agents/`](../rookery/agents/), [`rookery/docs/coordination.md`](../rookery/docs/coordination.md) | Assign bounded work, harvest reports, record outcomes, and rotate stalled approaches |
| Platform boundary | [`rookery/adapters/`](../rookery/adapters/), [`rookery/extensions/`](../rookery/extensions/) | Provide selected platform behavior and optional activity modes without leaking platform assumptions into generic controllers |
| State and evidence | [`rookery/lib/rookery/portable/`](../rookery/lib/rookery/portable/), [`rookery/docs/evidence_state.md`](../rookery/docs/evidence_state.md) | Store canonical runtime history in SQLite and publish deterministic projections and evidence references |
| Scoring path | [`rookery/docs/scoring_review.md`](../rookery/docs/scoring_review.md) | Separate proposals, independent review, authorization, immutable execution, and scorer verdicts |
| Release boundary | [`rookery/release.json`](../rookery/release.json), [`rookery/bin/build-release`](../rookery/bin/build-release) | Validate and build deterministic release archives without runtime residue |

## Execution flow

1. The operator edits `.env` to supply event facts, acknowledge authorized scope, and select an adapter and extensions, then creates the required external measurement baseline.
2. The launch gate validates the immutable source, editable configuration, baseline, Codex executable and login, workspace identity, and supported environment before runtime writes.
3. Preparation discovers local capabilities. Networked package work and managed service startup remain disabled unless explicitly enabled.
4. Rookery resolves the event, compiles scope, and renders only the selected agents and tools into the active surface.
5. The coordinator assigns each worker one owner, one bounded question, one report path, and one stop condition.
6. Workers preserve evidence and may create scoring proposals. Independent reviewers assess those proposals.
7. A separately authorized executor consumes an immutable plan, rechecks policy and stop generations, and dispatches through the selected adapter.
8. Structured scorer truth is reconciled independently of transport success. Completed objectives receive solve capsules and writeups.
9. `./go stop` advances the stop generation before shutdown work, revokes unused authority, and signals only verified Rookery-owned actors.

## Trust and authority boundaries

Rookery is designed for an authorized, disposable workspace. Its project-local Codex configuration uses full local access and disables interactive approvals. The harness narrows its own actions through scope, purpose-specific child environments, role separation, immutable execution plans, and generation checks. It does not claim to intercept arbitrary raw shell commands issued by an agent.

Authority belongs to distinct roles:

- the operator owns facts, scope, policy, authorization, resume, and stop;
- the coordinator owns assignments and lifecycle, but cannot review its own candidate or mutate a platform;
- workers solve bounded questions and propose actions;
- reviewers assess proposals independently;
- authorizers grant exact or bounded current-generation authority; and
- executors perform only reviewed, authorized, current plans.

See [`rookery/docs/agents.md`](../rookery/docs/agents.md) for the complete role contract.

## State and evidence

`state/events.sqlite3` is canonical runtime history. JSON and Markdown views are deterministic projections or handoffs. Each worker owns only its assigned report and artifact paths. Scoring requests, responses, plans, and verdicts are retained as separate evidence.

Rookery preserves exact captured evidence. Bounded adapter response summaries
replace sensitive authentication and cookie headers by design. Runtime
directories still contain sensitive event material and must remain private.
They are excluded from the release contract and from this public repository.

## Platform and network boundary

The base system is platform-neutral. `PLATFORM_ADAPTER` selects one adapter under `rookery/adapters/<id>/`; optional activity modes are selected independently from `rookery/extensions/<id>/`. Generic controllers consume normalized snapshots and capability reports.

Rookery-owned network and attachment helpers validate compiled scope before I/O. Hostnames, CIDRs, ports, protocols, file origins, byte bounds, expiry, and platform hosts are explicit authorities. Raw shell remains available and still has to obey the operator-declared event scope.

## Release boundary

The nested source layout is deliberate. Strict release validation and deterministic source hashing operate on [`rookery/`](../rookery/) without admitting repository metadata, tests, contribution files, or local maintenance workflows into the runtime archive.

`rookery/bin/build-release` rejects runtime residue, links, special files, source/output overlap, oversized inputs, and existing output names. It produces a deterministic ZIP, a per-file manifest, and a ZIP SHA-256 sidecar. Those artifacts establish content integrity; publisher authentication requires a separately trusted signature or index.
