# Rookery Documentation

Start with the operator path, then use the contract pages when you need the details behind a decision or failure.

## First run and operation

| Guide | Use it for |
| --- | --- |
| [Getting started](getting-started.md) | Trusted source checkout, validation, release build, WSL installation, baseline, and first authorized start. |
| [Release changes](../CHANGELOG.md) | Operator-visible changes in each immutable release. |
| [Configuration](configuration.md) | Live `.env`, event manifest, adapters, scope, authentication, and autonomous Codex settings. |
| [Operator guide](operator.md) | The three everyday commands, lifecycle, stop behavior, and supported maintenance commands. |
| [Preparation](preparation.md) | Capability discovery, optional installation, SearXNG, browser, and failure behavior. |
| [Install, upgrade, and rollback](upgrade.md) | Received archives, publisher trust, side-by-side upgrades, backup rehearsal, and rollback. |

## System contracts

| Guide | Contract |
| --- | --- |
| [Event profiles](event_profiles.md) | Profile, adapter, extension, and override composition. |
| [Platform adapters](adapters.md) | Platform-neutral core and selected adapter boundary. |
| [Event scope](scope.md) | Authorized targets and Rookery-owned network checks. |
| [Network and VPN](network_vpn.md) | External VPN boundary and supported network paths. |
| [Coordination](coordination.md) | Coordinator loop and retry behavior. |
| [Agents and roles](agents.md) | Authority roles, artifact ownership, and specialization. |
| [Shared interactive resources](console_workflows.md) | Lease and evidence rules for selected interactive extensions. |
| [Platform sessions](platform_sessions.md) | Session health, pauses, and event lifecycle boundaries. |
| [State, policy, and stop](state_policy_stop.md) | Canonical state, policy generations, and shutdown ordering. |
| [Scoring review](scoring_review.md) | Proposal, independent review, authorization, execution, and verdict truth. |
| [Evidence and state](evidence_state.md) | Private evidence, projections, manifests, and preserved runtimes. |
| [Tools and wrappers](tools_and_wrappers.md) | Supported boundaries and internal helper behavior. |

## Event work

| Guide | Use it for |
| --- | --- |
| [Research](research.md) | Local corpus and fresh public research. |
| [Solve capsules and writeups](writeups.md) | Required objective records and closeout writing. |
| [Voice guide](voice.md) | Reproducible technical writeup style. |
| [Event measurement](measurement.md) | Baseline creation, telemetry eligibility, and descriptive comparison. |
| [Stop-state lessons](lessons.md) | Improvements-only lessons generated at stop. |

Adapter and extension directories contain their own selected-integration documentation. Generated `PREPARATION.md` and `ACTIVE_SURFACE.md` files belong to a configured runtime and are not part of a clean source checkout.
