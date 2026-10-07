# Event Configuration

Rookery resolves one normalized event before it creates runtime state. Edit only the private `.env` in the installed workspace. `state/resolved_event.json` and `state/scope.json` are generated runtime views; inspect them after launch, but never edit or reuse them as configuration.

The full reviewed catalog is [`.env.example`](../.env.example). Adapter and extension examples explain their own subsets, while the operator still copies values into the single workspace `.env`. The [operator guide](./operator.md) owns the launch procedure.

## Configuration sources

The [manifest resolver](../lib/rookery/portable/manifest.py) composes sources in this order:

1. [`profiles/generic.json`](../profiles/generic.json) supplies safe generic defaults.
2. `PLATFORM_ADAPTER` selects exactly one packaged adapter profile, or `manual` when blank.
3. Declared, typed values from the private `.env` replace matching fields.
4. Overlays for the selected `EVENT_EXTENSIONS` apply using their defined union rules.

Normal resolution reads no ambient parent values or implicit secondary configuration file. Blank values and the legacy placeholder `unknown` keep profile defaults. Unknown nonblank keys, removed selectors, invalid typed values, and nonblank fields owned by an unselected adapter fail before runtime state is created.

## Ownership

| Source | Owns | Keep out of it |
| --- | --- | --- |
| Private `.env` | Event identity, selected adapter and extensions, scope, answer and scoring shape, limits, local paths, declared child-environment names, and credentials | Shell expressions, candidates, runtime state, or copied example secrets |
| `profiles/*.json` and `adapters/*/profile.json` | Immutable reusable defaults, required capabilities, session behavior, and release polling | Event-specific facts or credentials |
| `adapters/*/adapter.json` | Reviewed typed schema for that adapter's accepted `.env` keys | Secret values or event data |
| `extensions/*/overlay.json` | Optional activity-mode additions | A second platform implementation |
| Generated runtime views | Resolved evidence for one bound runtime | Operator edits or templates for another event |

The dotenv parser accepts bounded literal data. It does not source shell code, expand commands, or inherit ambient values as event authority. Selected child processes receive only explicitly declared environment names.

## Resolved sections

The normalized manifest contains these top-level sections:

| Section | Purpose |
| --- | --- |
| `identity`, `adapter`, `capabilities`, `surface` | Event identity, selected normalized integration, active capabilities, bundles, categories, and extensions |
| `scope` | Authorized network and file boundary; see [Event scope](./scope.md) |
| `scoring`, `authorization`, `answer_morphology` | Completion mode, supported actions, zero-default authority, and answer validation; see [Scoring review](./scoring_review.md) |
| `session`, `release` | Profile-owned session freshness and event-release polling defaults unless a selected schema exposes an override |
| `concurrency`, `compute`, `queue`, `priority` | Coordination policy and observable limits; none grants mutation authority |
| `writeups` | Writeup timing and closeout behavior |

Typed `.env` lists replace inherited lists. Selected extension overlays alone union the capability, scoring-action, and surface lists defined by their overlay contract. The generic profile begins with `no_submit_evidence`; a scoring adapter declares each action kind it supports.

`SCORING_COMPLETION_MODE=scorer_truth` requires healthy selected scoring before launch. The manual profile uses `evidence_only` with `no_submit_evidence` and cannot submit flags or claim platform solves.

## Readiness and binding

Before launch, edit `.env`, validate the resolved configuration, create the release-bound baseline, and prepare required external sessions. After launch, Rookery records the canonical resolved manifest and compiled scope, then binds the workspace, immutable source, private `.env`, resolved-manifest digest, Codex executable, and measurement baseline. Later mutations recheck that binding.

Use generated `PREPARATION.md` and `ACTIVE_SURFACE.md` to inspect one runtime. They are evidence, not reusable configuration.

For the public setup sequence and legacy migration path, see [Configuration](./configuration.md). For the release boundary that excludes live configuration and runtime evidence, see [`release.json`](../release.json).
