from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import sys
import time
import uuid
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .adapters import get_adapter
from .compute import (
    admit_compute_tick,
    compute_queue_status,
    enqueue_compute_idea,
    finish_compute_idea,
    requeue_compute_idea,
    sample_host_cpu,
    schedule_useful_jobs,
    start_compute_idea,
)
from .config_migration import migrate_event_configuration
from .control import resume, stop, write_stop_prompt
from .execution import compile_plan, execute_plan
from .exploration import (
    claim_ideation,
    claim_synthesis,
    close_campaign,
    open_campaign,
    park_campaign,
    record_dispatch_claim,
    record_idea_batch,
    synthesize_campaign,
)
from .lessons import create_lessons_document
from .intake import (
    capture_artifact_valid,
    capture_key,
    inspect_intake,
    platform_solver_eligibility,
    solver_eligibility,
)
from .environment import (
    EnvironmentPolicyError,
    LaunchBinding,
    LaunchGate,
    launch_binding_integrity_error,
    publish_or_verify_launch_binding,
    resolve_launch_gate,
)
from .manifest import ManifestResult, resolve_manifest, validate_manifest
from .owned_paths import objective_storage_component, opaque_identifier_component
from .outcomes import (
    close_current_agent_attempt,
    confusion_brake,
    harvest_report,
    record_continuation_boundary,
    record_outcome,
    register_agent_attempt,
    schedule_retry_continuation,
)
from .policy import effective_policy, set_policy
from .preparation import prepare, read_preparation
from .priority import rank_challenges
from .reducers import platform_inventory_is_authoritative
from .queue import build_queue, persist_schedules
from .reconciliation import (
    answer_ledger,
    correlation_ledger,
    import_response,
    reconcile_all,
    record_task_completion,
    task_completion_audit,
)
from .registry import render_surface
from .scope import check_cidr, check_file_origin, check_host, check_url, compile_scope
from .scoring import (
    REVIEW_VERDICTS,
    create_proposal,
    grant_allowance,
    grant_exact,
    morphology_score,
    record_review,
)
from .status import read_snapshot, refresh_snapshot, render_status
from .store import EventStore
from .util import (
    UTC,
    atomic_write_json,
    atomic_write_text,
    canonical_json,
    compact_now,
    contained_private_path,
    ensure_private_dir,
    ensure_private_file,
    file_lock,
    iso_now,
    load_json,
    parse_duration,
    parse_iso,
    private_storage_preflight,
    sha256_file,
)
from .validator import validate_tree
from .watchers import _ensure_queue_watcher_locked, watcher_lease_is_current
from .writeups import check_writeups, create_capsule, create_writeup


def workspace_root() -> Path:
    env = os.environ.get("ROOKERY_ROOT")
    if env:
        return Path(env).resolve()
    candidate = Path.cwd().resolve()
    if (candidate / "VERSION").exists() and (candidate / "bin").exists():
        return candidate
    return Path(__file__).resolve().parents[3]


def ensure_runtime_dirs(root: Path) -> None:
    for rel in [
        "state",
        "state/execution_plans",
        "state/challenges",
        "state/platform",
        "analysis",
        "evidence",
        "submissions",
        "submissions/executions",
        "submissions/proposals",
        "platform",
        "platform/runtime",
        "platform/challenges",
        "work",
        "writeups",
        "control",
        "logs",
        "research",
        "candidates",
        "exploit",
        "captures",
        "downloads",
        "handoffs",
    ]:
        ensure_private_dir(root / rel)
    for name, heading in [
        ("STATUS.md", "# STATUS"),
        ("FINDINGS.md", "# FINDINGS"),
        ("FLAGS.md", "# FLAGS"),
        ("DEAD_PATHS.md", "# REJECTED ROUTES"),
    ]:
        path = root / name
        if path.exists() or path.is_symlink():
            ensure_private_file(path)
        else:
            atomic_write_text(
                path,
                f"{heading}\n\nGenerated runtime view. Exact evidence is preserved; no live redaction is performed.\n",
                mode=0o600,
            )
            ensure_private_file(path)
    environment = root / ".env"
    if environment.exists() or environment.is_symlink():
        ensure_private_file(environment)


def load_context(
    root: Path,
    *,
    require_ready: bool = False,
    env: Mapping[str, str] | None = None,
    result: ManifestResult | None = None,
    store: EventStore | None = None,
) -> tuple[dict[str, Any], dict[str, Any], EventStore, ManifestResult]:
    if result is None:
        # The selected typed schema owns every event and adapter input.  A
        # reduced generic-key projection would silently discard selected
        # adapter configuration after the first launch.
        result = resolve_manifest(root) if env is None else resolve_manifest(root, env=env)
    if result.errors:
        raise RuntimeError("manifest errors: " + "; ".join(result.errors))
    if require_ready and result.unresolved_required:
        raise RuntimeError(
            "unresolved event configuration: " + ", ".join(result.unresolved_required)
        )
    store = store or EventStore(root)
    scope_generation = max(1, int(store.get_meta("scope_generation", "0")))
    scope = compile_scope(result.manifest, scope_generation)
    return result.manifest, scope, store, result


def _load_stop_context(
    root: Path,
    *,
    emergency_stop: bool = False,
) -> tuple[dict[str, Any], dict[str, Any], EventStore, ManifestResult]:
    """Load stop inputs from canonical state without consulting live dotenv."""

    stored = load_json(root / "state" / "resolved_event.json", None)
    if isinstance(stored, dict):
        manifest = stored
        result = validate_manifest(manifest)
    else:
        # An uninitialized workspace has no owned work, but stop still creates a
        # canonical stopped generation without requiring credential config.
        result = resolve_manifest(root, env={})
        manifest = result.manifest
    store = EventStore(root, emergency_stop=emergency_stop)
    saved_scope = load_json(root / "state" / "scope.json", None)
    if isinstance(saved_scope, dict):
        scope = saved_scope
    else:
        generation = max(1, int(store.get_meta("scope_generation", "0")))
        scope = compile_scope(manifest, generation)
    return manifest, scope, store, result


def write_setup_note(root: Path, result: ManifestResult) -> None:
    lines = [
        "# Rookery Setup",
        "",
        "Edit only the private `.env` in the installed workspace. Rookery combines shipped profile defaults, the adapter selected by `PLATFORM_ADAPTER`, typed `.env` values, and selected extension overlays into a resolved event. Do not edit `state/resolved_event.json` or `state/scope.json`; they are generated runtime views.",
        "",
        "Unknown event facts remain explicit; active solving stays blocked until required scope and adapter facts are resolved.",
        "",
        "## Configuration",
        "",
        "- Edit the private `.env` for event identity, scope, answer shape, adapter selection, credentials, and adapter settings.",
        "- Inspect `state/resolved_event.json` and `state/scope.json` after launch when you need to see generated runtime views.",
        "",
        f"Configuration: `{result.manifest.get('profile')}`",
        f"Adapter: `{result.manifest.get('adapter', {}).get('id')}`",
        "",
    ]
    if result.errors:
        lines += ["", "## Errors"] + [f"- {x}" for x in result.errors]
    if result.unresolved_required:
        lines += ["", "## Required before active solving"] + [
            f"- `{x}`" for x in result.unresolved_required
        ]
    if result.warnings:
        lines += ["", "## Warnings"] + [f"- {x}" for x in result.warnings]
    if result.ready:
        lines += ["", "Configuration is ready for the selected profile."]
    atomic_write_text(root / "NEW_CTF_SETUP.md", "\n".join(lines) + "\n")


_STARTER_COMMANDS = (
    ("bin/platform-sync", "./bin/platform-sync"),
    ("bin/challenge-unlock-watch", "./bin/challenge-unlock-watch check --ingest"),
    ("bin/frontier", "./bin/frontier --refresh"),
    ("bin/score-review", "./bin/score-review status"),
    ("bin/retry-due", "./bin/retry-due --write"),
    ("bin/agent-board", "./bin/agent-board list"),
)


def _starter_commands(inventory: dict[str, Any]) -> list[str]:
    active_paths = {
        str(tool.get("path", "")).lstrip("./")
        for tool in inventory.get("tools", [])
        if isinstance(tool, dict)
    }
    return [
        command for path, command in _STARTER_COMMANDS if path in active_paths
    ]


def render_start_prompt(
    root: Path,
    manifest: dict[str, Any],
    result: ManifestResult,
    inventory: dict[str, Any],
) -> Path:
    name = manifest.get("identity", {}).get("name", "unknown")
    unresolved = list(result.unresolved_required)
    first_goal = (
        "Resolve event configuration and scope before active solving."
        if unresolved
        else "Autonomously solve the event using bounded, evidence-producing Codex subagents."
    )
    lines = [
        f"/goal {first_goal}",
        "",
        f"Event: {name}",
        f"Configuration: {manifest.get('profile')}",
        f"Adapter: {manifest.get('adapter', {}).get('id')}",
        f"Completion mode: {manifest.get('scoring', {}).get('completion_mode', 'scorer_truth')}",
        "",
        "Read `AGENTS.md`, `README.md`, `NEW_CTF_SETUP.md`, `PREPARATION.md`, `ACTIVE_SURFACE.md`, and the canonical docs under `docs/`.",
        "",
        "Core behavior:",
        "- Use Codex subagents explicitly. Register each with one bounded goal, scope, exact report path, and stop condition, then send those exact values in its worker card.",
        "- Command-line-first. Rookery tools accelerate work; they do not restrict the local shell.",
        "- Preserve exact evidence. Do not redact during the event.",
        "- Solvers create scoring proposals only. Independent reviewers review; authorization remains separate, and a separate executor mutates platforms.",
        "- Authorization starts at zero. When the resolved `.env` explicitly lists an action kind in `AUTOMATION_PERMITTED_ACTION_KINDS`, the coordinator may, after independent review and current policy/stop checks, grant a small bounded allowance through Rookery as needed, for example `./bin/rookery score allowance flag N --reason REASON --actor coordinator`. The opt-in permits that grant; it does not itself grant authority. A browser response, relay acknowledgement, or transport success is never scorer truth.",
        "- Proposal approval, authorization, a browser request, and a capsule are not a solve. In scorer-truth mode, completion requires the selected adapter's accepted scorer verdict. In evidence-only mode, a completed no-submit evidence record remains analysis evidence, never a platform solve.",
        "- Use the selected adapter only through normalized platform artifacts.",
        "- Before Rookery-owned network or attachment access, enforce the compiled event scope.",
        "- Read the event's current rules before retrieving or executing challenge material. Follow any required offline isolation; never run untrusted binaries on the online coordinator when the rules prohibit it.",
        "- Before new worker fanout, harvest every completed report. Register each worker before it starts with `--goal`, `--scope`, `--report-path`, and `--stop-condition`; a successor also carries `--handoff-id` from its exact route. The coordinator alone integrates the completed report into a structured handoff while the attempt is active. Open the next route with that handoff, record the matching outcome and continuation, then close the exact attempt. A report hash alone is not a handoff.",
        "- Ask the operator how many challenges to coordinate concurrently, then keep that many distinct eligible challenges assigned to registered native challenge-coordinator subagents. Register each root with the canonical `--role challenge-coordinator`; compatibility aliases normalize to that stored role but are not the normal path. Each challenge coordinator owns one challenge, may delegate bounded solver or research work to its own child subagents, and must harvest and synthesize those children before returning its canonical report. Refill the operator-selected challenge count after integrating and closing completed coordinator reports. All agents share this one Codex session and its configured thread ceiling.",
        "- The main coordinator alone owns platform sync, intake, browser session lifecycle, review, authorization, scoring execution, and final reconciliation. Challenge coordinators and their children investigate, preserve evidence, and propose candidates only.",
        "- When a challenge is stuck and foreground challenges are waiting, deprioritize it and work the waiting frontier. Preserve its return path: `explore open` consumes the structured handoff, then claim four distinct lenses (fresh, evidence, artifact, contrarian). Each lens worker writes its report; the coordinator integrates its handoff, records its batch and handoff-bound outcome, and closes it. After all four batches, run `./bin/rookery explore claim-synthesis --campaign-id ID --agent-attempt-id ATTEMPT` before dispatching the independent synthesizer. The synthesizer reads the source handoff and all four batch reports first and writes its own report; the coordinator integrates that report, records synthesis with its handoff, records a handoff-bound `explore:CAMPAIGN_ID` outcome, and closes it. Each lens returns exactly ten structured ideas. Synthesis removes tried routes and duplicates, selects missed high-information ideas, and queues them for a fully capable solver through the normal compute lease.",
        "- Keep a bounded backlog of useful, checkpointable low-priority ideas. Run `./bin/rookery compute tick` after worker harvests and before idle waits; dispatch only its single lease, aim for the best-effort 75% CPU target, and never create synthetic busywork. Report campaign `capacity_wait` and `parked` states; a parked challenge remains a visible route, never an accepted failure.",
        "- Use registered native subagents for challenge work. The main coordinator is delegation depth 0, challenge coordinators are depth 1, and their children are depth 2. Children at depth 2 must not delegate. Before compute completion, integrate the owner's report, record its handoff-bound outcome and next route, and close the exact attempt.",
        "- For every challenge-linked registration, pass the exact canonical challenge ID unchanged to both `--challenge-id` and `--objective-id`. Do not prefix or relabel the objective ID.",
        "- Every completed objective gets an immediate solve capsule. Full writeups follow the configured writeup policy and `docs/voice.md`.",
        "- Newest operator instruction supersedes stale goals or policy text.",
        "",
        "Bounded worker card:",
        "```text",
        "Goal: <one bounded question>",
        "Scope: <targets, files, allowed actions, forbidden actions, and budget>",
        "Parent attempt: none for a depth-1 worker; exact challenge-coordinator attempt ID for depth 2",
        "Depth: 1 or 2",
        "Source handoff: none for an initial route; otherwise <handoff ID and report path>",
        "Source report SHA-256: none for an initial route; otherwise <exact registered 64hex report hash>",
        "Report: analysis/<lane>/REPORT.md",
        "Stop: <time, artifact, signal, or exact negative>",
        "```",
        "Every registered worker, including event-wide work, writes the report early. Directly after its title keep `## Handoff` with exact one-line labels in this order: `Status:`, `Source handoff:`, `Source report SHA-256:`, `Observed result:`, `Route key:`, `Proof gap:`, `Discriminating test:`, `Next step or return trigger:`, `Evidence paths:`, `Command/artifact paths:`, `Blocker:`, `Cleanup/jobs:`. `Route key` must match `[a-z0-9][a-z0-9._:-]{0,127}` exactly: ASCII lower case, no spaces, and at most 128 characters. Evidence paths and Command/artifact paths are JSON arrays containing only current-workspace-relative POSIX paths to private regular artifacts below `analysis/`, `evidence/`, `work/`, `exploit/`, `captures/`, or `downloads/`; never use `state/`, `platform/`, absolute paths, outside-workspace paths, symlinks, or prose. Copy needed state/platform evidence into an allowed root first. Replace every placeholder before integration, then finish `## Evidence` and `## Commands`.",
        "Use `./bin/agent-harvest` as the normal report-integration path so the canonical block supplies its own exact fields. Do not manually retype handoff fields unless repairing a specifically diagnosed report contract failure.",
        "A depth-2 worker must register with `--parent-attempt-id` naming the exact active depth-1 challenge coordinator for the same challenge and objective. A successor must open and read the exact source report before acting, cite that handoff ID and exact registered 64hex report hash, and name a materially different route with a nonempty discriminating test. `Source handoff: none` and `Source report SHA-256: none` are valid only for an initial route, including initial event-wide work.",
        "",
    ]
    if unresolved:
        lines += ["Active solving is blocked by unresolved configuration:"] + [
            f"- {x}" for x in unresolved
        ]
        lines += [
            "",
            "Update `.env`, validate the resolved configuration, and rerun `./go`.",
        ]
    else:
        commands = _starter_commands(inventory)
        if commands:
            lines += ["Start with a single lightweight truth pass:", "```bash"]
            lines += commands
            lines += ["```", ""]
        lines += [
            "Treat verified challenge intake as a solver-dispatch gate. `challenge-unlock-watch check --ingest` reports newly visible, ingested, pending, partial, deferred, blocked, and failed IDs separately. Agent registration and later dispatch paths recheck immutable detail and capture artifacts. Never re-ingest an `ingested_id`; use `./bin/challenge-ingest ID` only for one explicitly selected pending challenge or reviewed partial/error recovery. Do not dispatch when required material is missing, a capture is unverified, or resources are truncated.",
            "Use only the active tools and roles listed in `ACTIVE_SURFACE.md`.",
            "Then rank the frontier, spawn non-overlapping workers, and continue without waiting for routine operator input. Stop only for an explicit external boundary, unresolved scope, unavailable required capability, or `./go stop`.",
        ]
        if manifest.get("adapter", {}).get("id") == "ctfd_browser":
            lines += [
                "For scoring, use the selected adapter only through proposal, independent review, and execution. Solvers never submit through raw CDP. If pinned HTTP or Cloudflare leaves scoring unhealthy, report the exact capability blocker for an operator decision."
            ]
        elif manifest.get("adapter", {}).get("id") == "ctfd_browser_gateway":
            lines += [
                "The selected CTFd adapter uses token-first normalized reads and reviewed scoring. Its sealed browser path is an internal fallback only after a typed read-only availability failure; it is never a raw-CDP or manual scoring route. Use proposal, independent review, bounded authorization, sealed-plan execution, and structured scorer truth."
            ]
    path = root / "START_PROMPT.md"
    atomic_write_text(path, "\n".join(lines) + "\n")
    return path


def runtime_surface_manifest(
    manifest: dict[str, Any],
    snapshot: dict[str, Any] | None,
    preparation: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return a copy of the manifest augmented only by observed healthy capabilities/categories."""
    out = json.loads(json.dumps(manifest))
    surface = out.setdefault("surface", {})
    categories = list(surface.get("categories", []))
    available = list(surface.get("available_capabilities", []))
    if snapshot:
        for challenge in snapshot.get("challenges", []):
            category = str(challenge.get("category", "")).strip().lower()
            if category and category not in {"unknown", "none"}:
                categories.append(category)
        for name, cap in snapshot.get("capabilities", {}).items():
            if cap.get("availability") == "available" and cap.get("health") in {
                "healthy",
                "degraded",
            }:
                available.append(str(name))
    if preparation:
        available.extend(str(x) for x in preparation.get("capabilities", []))
    surface["categories"] = sorted(set(categories))
    surface["available_capabilities"] = sorted(set(available))
    return out


class LaunchGenerationRejected(RuntimeError):
    """A public launch lost its exact stop-generation admission."""


def _require_open_launch_generation(store: EventStore, expected_stop_generation: int) -> int:
    """Require one still-open canonical generation while ``mutation.lock`` is held."""

    if isinstance(expected_stop_generation, bool) or expected_stop_generation < 0:
        raise LaunchGenerationRejected("launch stop generation is malformed")
    snapshot = store.read_snapshot()
    projection = store.projection_from_snapshot(snapshot)
    current = projection.get("current", {})
    try:
        actual = int(snapshot.get("meta", {}).get("stop_generation", ""))
    except (TypeError, ValueError) as exc:
        raise LaunchGenerationRejected("canonical stop generation is unavailable") from exc
    if actual != expected_stop_generation:
        raise LaunchGenerationRejected(
            f"launch stop generation changed: expected={expected_stop_generation} current={actual}"
        )
    if current.get("stopped"):
        raise LaunchGenerationRejected("workspace is stopped; explicit resume is required")
    return actual


def _capture_open_launch_generation(root: Path, store: EventStore) -> int:
    """Linearize a public launch after any explicit resume transition."""

    with file_lock(root / "state" / "mutation.lock"):
        snapshot = store.read_snapshot()
        try:
            expected = int(snapshot.get("meta", {}).get("stop_generation", ""))
        except (TypeError, ValueError) as exc:
            raise LaunchGenerationRejected("canonical stop generation is unavailable") from exc
        return _require_open_launch_generation(store, expected)


def _run_launch_effect(
    root: Path,
    store: EventStore,
    expected_stop_generation: int,
    effect,
    *,
    exclusive: bool = True,
):
    """Run one launch effect only while the captured generation remains open."""

    with file_lock(root / "state" / "mutation.lock", exclusive=exclusive):
        _require_open_launch_generation(store, expected_stop_generation)
        result = effect()
        # A same-process test seam can commit stop re-entrantly; the post-effect
        # check also keeps any future local callback from returning ready after it.
        _require_open_launch_generation(store, expected_stop_generation)
        return result


def _persist_compiled_scope(
    root: Path,
    store: EventStore,
    manifest: dict[str, Any],
    scope: dict[str, Any],
    *,
    expected_stop_generation: int | None = None,
    publish_manifest: bool = False,
) -> dict[str, Any]:
    """Atomically publish scope only for an open, generation-bound launch."""

    with file_lock(root / "state" / "mutation.lock"):
        if expected_stop_generation is None:
            snapshot = store.read_snapshot()
            try:
                expected_stop_generation = int(
                    snapshot.get("meta", {}).get("stop_generation", "")
                )
            except (TypeError, ValueError) as exc:
                raise LaunchGenerationRejected(
                    "canonical stop generation is unavailable"
                ) from exc
        _require_open_launch_generation(store, expected_stop_generation)
        if publish_manifest:
            atomic_write_json(root / "state" / "resolved_event.json", manifest)
        prior_scope = load_json(root / "state" / "scope.json", {}) or {}
        comparable_prior = {
            k: v
            for k, v in prior_scope.items()
            if k not in {"generation", "compiled_at"}
        }
        comparable_new = {
            k: v for k, v in scope.items() if k not in {"generation", "compiled_at"}
        }
        scope_generation = int(store.get_meta("scope_generation", "0"))
        if comparable_prior != comparable_new or scope_generation <= 0:
            scope_generation += 1
            store.set_meta("scope_generation", scope_generation)
        compiled_scope = compile_scope(manifest, scope_generation)
        atomic_write_json(root / "state" / "scope.json", compiled_scope)
        _require_open_launch_generation(store, expected_stop_generation)
    return compiled_scope


def startup_checks(
    root: Path,
    manifest: dict[str, Any],
    scope: dict[str, Any],
    snapshot: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    checks = []
    required = set(manifest.get("capabilities", {}).get("required", []))
    optional = set(manifest.get("capabilities", {}).get("optional", []))
    completion_mode = str(
        manifest.get("scoring", {}).get("completion_mode", "scorer_truth")
    )
    if completion_mode == "scorer_truth":
        # Completion cannot be established from a proposal, authorization, or
        # local capsule. Make the selected adapter's scorer health a launch
        # requirement before a coordinator can be admitted.
        required.add("scoring")
        optional.discard("scoring")
    checks.append(
        {
            "name": "completion_mode",
            "classification": "required",
            "ok": completion_mode in {"scorer_truth", "evidence_only"},
            "detail": (
                f"completion_mode={completion_mode} "
                f"adapter={manifest.get('adapter', {}).get('id', 'unknown')}"
            ),
        }
    )
    checks.append(
        {
            "name": "scope",
            "classification": "required",
            "ok": bool(scope.get("acknowledged"))
            and bool(
                scope.get("allowed_hosts")
                or scope.get("allowed_cidrs")
                or scope.get("allowed_file_origins")
            ),
            "detail": "compiled event scope",
        }
    )
    if snapshot is None:
        adapter = get_adapter(root, manifest, scope)
        snapshot = adapter.sync()
    for name in sorted(required | optional):
        if name == "local_shell":
            checks.append(
                {
                    "name": name,
                    "classification": "required",
                    "ok": True,
                    "detail": "local shell available",
                }
            )
            continue
        cap = snapshot.get("capabilities", {}).get(name)
        classification = "required" if name in required else "optional"
        if cap is None:
            detail = "not declared by adapter"
            if name == "scoring":
                detail = (
                    f"completion_mode={completion_mode} "
                    f"adapter={manifest.get('adapter', {}).get('id', 'unknown')} {detail}"
                )
            checks.append(
                {
                    "name": name,
                    "classification": classification,
                    "ok": classification != "required",
                    "detail": detail,
                }
            )
        else:
            available = cap.get("availability") == "available"
            healthy = cap.get("health") in {"healthy", "degraded"}
            ok = available and healthy
            detail = cap.get("detail") or (
                f"availability={cap.get('availability')} health={cap.get('health')}"
            )
            if name == "scoring":
                detail = (
                    f"completion_mode={completion_mode} "
                    f"adapter={manifest.get('adapter', {}).get('id', 'unknown')} "
                    f"{detail}"
                )
            checks.append(
                {
                    "name": name,
                    "classification": classification,
                    "ok": ok or classification == "optional",
                    "detail": detail,
                }
            )
    return checks


def _record_measurement_started(store: EventStore, binding: LaunchBinding) -> None:
    """Record the bound measurement exactly once before any startup side effect."""

    contract = binding.record["measurement_contract"]
    if not isinstance(contract, Mapping):
        raise RuntimeError("launch binding measurement contract is invalid")
    provider_fields = contract.get("provider_fields")
    if not isinstance(provider_fields, Mapping):
        raise RuntimeError("launch binding measurement contract is invalid")
    payload = {
        "launch_binding_sha256": binding.sha256,
        "baseline_sha256": binding.record["baseline_sha256"],
        "configuration_digest": binding.record["baseline_configuration_digest"],
        "release_version": binding.record["release_version"],
        "stop_generation": int(store.get_meta("stop_generation", "0")),
        "policy_generation": int(store.get_meta("policy_generation", "0")),
        "scope_generation": int(store.get_meta("scope_generation", "0")),
        # The launch binding has already validated this value-free contract
        # against the private baseline.  Retain it in canonical history rather
        # than reopening configuration or the external baseline on resume.
        "measurement_contract": {
            "queue_automation_enabled": contract["queue_automation_enabled"],
            "provider_fields": {
                name: {"availability": field["availability"]}
                for name, field in provider_fields.items()
            },
        },
    }
    store.append(
        "measurement.started",
        payload,
        actor="system",
        generation=payload["stop_generation"],
        event_id=f"measurement.started:{binding.sha256}",
    )


def _bootstrap_launch(
    root: Path,
) -> tuple[LaunchGate, LaunchBinding, EventStore, dict[str, Any], dict[str, Any], ManifestResult]:
    """Perform the first-write sequence after the pure gate has succeeded."""

    gate = resolve_launch_gate(root)
    private_storage_preflight(root / "state")
    binding = publish_or_verify_launch_binding(root, gate)
    store = EventStore(root, launch_binding=binding)
    manifest, scope, store, result = load_context(
        root,
        require_ready=True,
        result=gate.result,
        store=store,
    )
    return gate, binding, store, manifest, scope, result


def _launch_is_stopped(store: EventStore) -> bool:
    snapshot = store.read_snapshot()
    return bool(store.projection_from_snapshot(snapshot).get("current", {}).get("stopped"))


def _launch_rejected_result(store: EventStore) -> int:
    """Return an accurate fail-closed public result without publishing state."""

    try:
        snapshot = store.read_snapshot()
        current = store.projection_from_snapshot(snapshot).get("current", {})
        stopped = bool(current.get("stopped"))
        generation = snapshot.get("meta", {}).get("stop_generation", "unknown")
    except (OSError, RuntimeError, ValueError):
        stopped = False
        generation = "unknown"
    state = "stopped" if stopped else "blocked"
    print(f"rookery_state={state} stop_generation={generation}")
    print("launch_blocker=stop_generation_changed")
    return 2


def _publish_start_prompt_and_attempt(
    root: Path,
    store: EventStore,
    binding: LaunchBinding,
    expected_stop_generation: int,
    manifest: dict[str, Any],
    result: ManifestResult,
    inventory: dict[str, Any],
) -> str:
    """Publish a prompt plus the exact launcher admission record under one lock."""

    with file_lock(root / "state" / "mutation.lock"):
        _require_open_launch_generation(store, expected_stop_generation)
        render_start_prompt(root, manifest, result, inventory)
        _require_open_launch_generation(store, expected_stop_generation)
        attempt_id = hashlib.sha256(
            f"{binding.sha256}:{expected_stop_generation}:{uuid.uuid4().hex}".encode(
                "utf-8"
            )
        ).hexdigest()
        atomic_write_json(
            root / "state" / "launch_attempt.json",
            {
                "schema_version": "1",
                "attempt_id": attempt_id,
                "launch_binding_sha256": binding.sha256,
                "stop_generation": expected_stop_generation,
            },
            mode=0o600,
        )
        _require_open_launch_generation(store, expected_stop_generation)
        return attempt_id


def cmd_go(args) -> int:
    root = workspace_root()
    if args.go_action == "status":
        snapshot = dict(read_snapshot(root))
        integrity_blocker = launch_binding_integrity_error(root)
        if integrity_blocker:
            snapshot["binding_integrity"] = integrity_blocker
            snapshot["lifecycle_state"] = "blocked"
            blockers = list(snapshot.get("blockers", []))
            blockers.append("launch binding integrity: " + integrity_blocker)
            snapshot["blockers"] = blockers
        text = render_status(snapshot)
        prep = read_preparation(root)
        if prep:
            services = prep.get("services", {})
            text += "\nPreparation: ready=" + str(prep.get("ready", False)).lower()
            text += " searxng=" + str(
                (services.get("searxng") or {}).get("health", "unknown")
            )
            text += " browser=" + str(
                (services.get("browser") or {}).get("health", "unknown")
            )
        print(text)
        return 0
    if args.go_action == "stop":
        state = root / "state"
        if not state.exists() or not (state / "events.sqlite3").exists():
            print(json.dumps({"ok": True, "owned_work": False, "state": "uninitialized"}))
            return 0
        integrity_blocker = launch_binding_integrity_error(root)
        if integrity_blocker:
            # A stop must still revoke known work after a binding loss or source
            # drift. This path opens only the already-existing canonical DB and
            # EventStore permits only stop/revocation events and metadata.
            manifest, _scope, store, _result = _load_stop_context(
                root, emergency_stop=True
            )
            outcome = stop(
                store,
                root,
                reason=args.reason or "operator requested emergency stop",
            )
            print(
                json.dumps(
                    {
                        **outcome,
                        "binding_integrity_blocker": integrity_blocker,
                        "emergency_stop": True,
                    },
                    indent=2,
                )
            )
            return 0
        private_storage_preflight(root / "state")
        ensure_runtime_dirs(root)
        manifest, _scope, store, result = _load_stop_context(root)
        stop_reason = args.reason or "operator requested stop"
        outcome = stop(store, root, reason=stop_reason)
        write_stop_prompt(root, outcome["generation"], stop_reason)
        lessons = create_lessons_document(store, root, reason=stop_reason)
        closeout = check_writeups(store, root, manifest, closeout=True)
        refresh_snapshot(store, root, manifest, result)
        print(
            json.dumps(
                {**outcome, "lessons": lessons, "closeout_writeups": closeout}, indent=2
            )
        )
        print(
            "Paste STOP_PROMPT.md into the live Codex session if it is still running."
        )
        return 0
    # The gate is fully read-only. Only after it proves the external baseline,
    # selected descriptor, local login, and Codex capability may state exist.
    try:
        gate, binding, store, manifest, scope, result = _bootstrap_launch(root)
    except EnvironmentPolicyError as exc:
        print(f"launch_error={exc}", file=sys.stderr)
        return 2
    ensure_runtime_dirs(root)
    try:
        if _launch_is_stopped(store):
            if args.go_action not in {"start", "resume"}:
                return _launch_rejected_result(store)
            resume(
                store,
                reason=(
                    getattr(args, "reason", "")
                    or "operator explicitly invoked ./go"
                ),
            )
        launch_generation = _capture_open_launch_generation(root, store)
        # Establish scope before the measurement record so its generation tuple
        # describes the actual launch state, but only after explicit resume and
        # under the same generation predicate used by every later handoff.
        scope = _persist_compiled_scope(
            root,
            store,
            manifest,
            scope,
            expected_stop_generation=launch_generation,
            publish_manifest=True,
        )
        _run_launch_effect(
            root,
            store,
            launch_generation,
            lambda: _record_measurement_started(store, binding),
        )
        # Preparation can start managed local capabilities.  It is therefore a
        # generation-bound effect, not an unguarded prelude to launch.
        preparation = _run_launch_effect(
            root,
            store,
            launch_generation,
            lambda: prepare(
                root,
                apply=True,
                env=gate.preparation_environment.values,
                environment_resolved=True,
                stage_c_environments=gate.stage_c_environments,
            ),
            exclusive=False,
        )
    except LaunchGenerationRejected:
        return _launch_rejected_result(store)
    if not preparation.get("ready", False):
        try:
            scope = _persist_compiled_scope(
                root,
                store,
                manifest,
                scope,
                expected_stop_generation=launch_generation,
                publish_manifest=True,
            )
        except LaunchGenerationRejected:
            return _launch_rejected_result(store)
        checks = [
            {
                "name": "preparation",
                "classification": "required",
                "ok": False,
                "detail": "required preparation capabilities are unavailable",
            }
        ]
        try:
            _run_launch_effect(
                root,
                store,
                launch_generation,
                lambda: atomic_write_json(
                    root / "state" / "startup_checks.json",
                    {"generated_at": iso_now(), "checks": checks},
                ),
            )
        except LaunchGenerationRejected:
            return _launch_rejected_result(store)
        watcher = {"running": False, "reason": "preparation is not ready"}
        try:
            status_snapshot = _run_launch_effect(
                root,
                store,
                launch_generation,
                lambda: refresh_snapshot(
                    store,
                    root,
                    manifest,
                    result,
                    watcher_startup=watcher,
                    preparation=preparation,
                ),
            )
        except LaunchGenerationRejected:
            return _launch_rejected_result(store)
        print(
            f"rookery_state={status_snapshot['lifecycle_state']} adapter={manifest.get('adapter', {}).get('id')} configuration={manifest.get('profile')}"
        )
        print("required_check_failures=preparation")
        return 2
    try:
        scope = _persist_compiled_scope(
            root,
            store,
            manifest,
            scope,
            expected_stop_generation=launch_generation,
            publish_manifest=True,
        )
        startup_snapshot = _run_launch_effect(
            root,
            store,
            launch_generation,
            lambda: get_adapter(root, manifest, scope).sync(),
            exclusive=False,
        )
    except LaunchGenerationRejected:
        return _launch_rejected_result(store)
    surface_manifest = runtime_surface_manifest(manifest, startup_snapshot, preparation)
    try:
        inventory = _run_launch_effect(
            root,
            store,
            launch_generation,
            lambda: render_surface(
                root,
                surface_manifest,
                strict_config_supported=gate.strict_config_supported,
            ),
        )
    except LaunchGenerationRejected:
        return _launch_rejected_result(store)
    checks = startup_checks(root, manifest, scope, startup_snapshot)
    try:
        _run_launch_effect(
            root,
            store,
            launch_generation,
            lambda: atomic_write_json(
                root / "state" / "startup_checks.json",
                {"generated_at": iso_now(), "checks": checks},
            ),
        )
    except LaunchGenerationRejected:
        return _launch_rejected_result(store)
    required_failures = [
        c for c in checks if c["classification"] == "required" and not c["ok"]
    ]
    try:
        _run_launch_effect(
            root,
            store,
            launch_generation,
            lambda: write_setup_note(root, result),
        )
    except LaunchGenerationRejected:
        return _launch_rejected_result(store)
    watcher = {"running": False, "reason": "not started"}
    if result.ready and not required_failures:
        try:
            watcher = _run_launch_effect(
                root,
                store,
                launch_generation,
                lambda: _ensure_queue_watcher_locked(store, root, manifest),
            )
        except LaunchGenerationRejected:
            return _launch_rejected_result(store)
    try:
        status_snapshot = _run_launch_effect(
            root,
            store,
            launch_generation,
            lambda: refresh_snapshot(
                store,
                root,
                manifest,
                result,
                watcher_startup=watcher,
                preparation=preparation,
            ),
        )
    except LaunchGenerationRejected:
        return _launch_rejected_result(store)
    if status_snapshot["lifecycle_state"] != "ready":
        print(
            f"rookery_state={status_snapshot['lifecycle_state']} adapter={manifest.get('adapter', {}).get('id')} configuration={manifest.get('profile')}"
        )
        if required_failures:
            print(
                "required_check_failures="
                + ",".join(c["name"] for c in required_failures)
            )
        return 2
    try:
        attempt_id = _publish_start_prompt_and_attempt(
            root,
            store,
            binding,
            launch_generation,
            manifest,
            result,
            inventory,
        )
        # Keep ready output in the same linearization interval as the prompt
        # and launcher record; a committed stop can only appear before or after
        # this complete result, never between ready and its admission record.
        with file_lock(root / "state" / "mutation.lock"):
            _require_open_launch_generation(store, launch_generation)
            print(
                f"rookery_state=ready adapter={manifest.get('adapter', {}).get('id')} configuration={manifest.get('profile')}"
            )
            print("preparation=PREPARATION.md")
            if manifest.get("queue", {}).get("automation_enabled", False):
                print(
                    f"queue_watcher_running={str(watcher.get('running', False)).lower()}"
                )
            print("start_prompt=START_PROMPT.md")
            print(f"launch_attempt={attempt_id}")
    except LaunchGenerationRejected:
        return _launch_rejected_result(store)
    return 0


def cmd_manifest(args) -> int:
    root = workspace_root()
    manifest, scope, store, result = load_context(root, require_ready=False)
    if args.manifest_action == "show":
        print(
            json.dumps(
                {
                    "manifest": manifest,
                    "errors": result.errors,
                    "warnings": result.warnings,
                    "unresolved_required": result.unresolved_required,
                },
                indent=2,
            )
        )
    elif args.manifest_action == "render":
        out = (
            Path(args.output) if args.output else root / "state" / "resolved_event.json"
        )
        if not out.is_absolute():
            out = root / out
        atomic_write_json(out, manifest)
        print(out)
    elif args.manifest_action == "validate":
        print(
            json.dumps(
                {
                    "ready": result.ready,
                    "errors": result.errors,
                    "warnings": result.warnings,
                    "unresolved_required": result.unresolved_required,
                },
                indent=2,
            )
        )
        return 0 if result.ready else 2
    return 0


def cmd_config(args) -> int:
    """Run the explicit, non-launch compatibility configuration tools."""

    root = workspace_root()
    if args.config_action != "migrate-event":  # pragma: no cover - argparse guards this
        raise ValueError("config action is invalid")

    def workspace_path(value: str) -> Path:
        path = Path(value)
        return path if path.is_absolute() else root / path

    result = migrate_event_configuration(
        root,
        input_path=workspace_path(args.input),
        environment_path=workspace_path(args.env),
        output_path=workspace_path(args.output),
    )
    print(json.dumps(result.presentation(), indent=2))
    return 0


def cmd_scope(args) -> int:
    root = workspace_root()
    manifest, scope, store, result = load_context(root, require_ready=False)
    overrides = [e["payload"] for e in store.events("scope.override")]
    if args.scope_action == "show":
        print(json.dumps(scope, indent=2))
        return 0
    if args.scope_action == "check-host":
        decision = check_host(
            scope,
            args.host,
            port=args.port,
            protocol=args.protocol,
            platform=args.platform,
            overrides=overrides,
        )
    elif args.scope_action == "check-url":
        decision = check_url(
            scope, args.url, platform=args.platform, overrides=overrides
        )
    elif args.scope_action == "check-file":
        decision = check_file_origin(scope, args.origin, size=args.size)
    elif args.scope_action == "check-cidr":
        decision = check_cidr(scope, args.cidr)
    elif args.scope_action == "override":
        expires = dt.datetime.now(UTC) + dt.timedelta(
            seconds=parse_duration(args.duration)
        )
        payload = {
            "id": "scope_" + uuid.uuid4().hex,
            "allowed_hosts": [args.host] if args.host else [],
            "allowed_cidrs": [args.cidr] if args.cidr else [],
            "reason": args.reason,
            "expires_at": expires.replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z"),
            "generation": scope["generation"],
        }
        store.append("scope.override", payload, actor="operator")
        store.rebuild()
        print(json.dumps(payload, indent=2))
        return 0
    else:
        raise RuntimeError("unknown scope action")
    print(json.dumps(decision.to_dict(), indent=2))
    return 0 if decision.allowed else 3


def _record_platform_snapshot(
    root: Path,
    store: EventStore,
    manifest: dict[str, Any],
    adapter: Any,
    snapshot: dict[str, Any],
) -> dict[str, Any]:
    """Publish one immutable private snapshot and append its canonical event."""

    artifact_dir = contained_private_path(root, root / "platform", "normalized")
    ensure_private_dir(artifact_dir)
    artifact = contained_private_path(
        root,
        artifact_dir,
        f"{compact_now()}-{adapter.id}-snapshot-{uuid.uuid4().hex}.json",
    )
    snapshot = {**snapshot, "artifact": artifact.relative_to(root).as_posix()}
    atomic_write_json(artifact, snapshot, mode=0o600)
    ensure_private_file(artifact)
    store.append("platform.snapshot", snapshot, actor="platform")
    render_surface(root, runtime_surface_manifest(manifest, snapshot))
    return snapshot


def _intake_attempt_count(challenge: dict[str, Any]) -> int:
    value = challenge.get("intake_attempt_count", 0)
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        return 0
    return value


def _ingest_challenge_locked(
    root: Path,
    manifest: dict[str, Any],
    scope: dict[str, Any],
    store: EventStore,
    adapter: Any,
    *,
    challenge_id: str,
    no_files: bool,
    quiet: bool,
) -> tuple[int, dict[str, Any]]:
    """Materialize one immutable challenge-intake attempt under the platform lock."""

    projection = store.rebuild()
    existing = projection["current"]["challenges"].get(challenge_id, {})
    if existing.get("classification") in {"policy_blocked", "operator_only"}:
        raise RuntimeError(
            f"challenge is {existing.get('classification')}: "
            f"{existing.get('policy_reason', '')}"
        )
    detail = adapter.detail(challenge_id)
    if not isinstance(detail, dict) or str(detail.get("id") or "") != challenge_id:
        raise RuntimeError("adapter detail does not match the requested challenge")
    file_items = detail.get("files", [])
    if not isinstance(file_items, list) or any(
        not isinstance(item, dict) for item in file_items
    ):
        raise RuntimeError("adapter detail files must be a list of objects")

    attempt_id = f"intake_{uuid.uuid4().hex}"
    challenge_dir = contained_private_path(
        root,
        root / "platform" / "challenges",
        objective_storage_component(challenge_id),
    )
    attempt_dir = contained_private_path(root, challenge_dir, "intake", attempt_id)
    files_dir = contained_private_path(root, attempt_dir, "files")
    detail_path = contained_private_path(root, attempt_dir, "detail.json")
    ensure_private_dir(attempt_dir)
    atomic_write_json(detail_path, detail, mode=0o600)
    ensure_private_file(detail_path)

    prior_captures: dict[str, dict[str, Any]] = {}
    for prior in existing.get("captured_files", []) or []:
        if not isinstance(prior, dict):
            continue
        key = prior.get("capture_key")
        if (
            isinstance(key, str)
            and key
            and key not in prior_captures
            and capture_artifact_valid(root, prior)
        ):
            prior_captures[key] = prior

    captured_files: list[dict[str, Any]] = []
    missing_material: list[str] = []
    if file_items and no_files:
        missing_material.append("attachments_skipped")
    for index, item in enumerate(file_items):
        key = capture_key(index, item)
        raw_name = str(item.get("name") or item.get("path") or f"file-{index}")
        prior = prior_captures.get(key)
        if prior is not None:
            captured_files.append(
                {
                    **prior,
                    "attachment_name": raw_name,
                    "capture_key": key,
                    "reused_existing": True,
                }
            )
            continue
        if no_files:
            captured_files.append(
                {
                    "attachment_name": raw_name,
                    "capture_key": key,
                    "origin": item.get("url") or item.get("path"),
                    "error": "attachment_capture_skipped",
                }
            )
            continue
        ensure_private_dir(files_dir)
        destination = contained_private_path(
            root,
            files_dir,
            opaque_identifier_component(
                f"{index}:{raw_name}",
                label="attachment_name",
                prefix="attachment",
            ),
        )
        try:
            captured_files.append(
                {
                    "attachment_name": raw_name,
                    "capture_key": key,
                    **adapter.capture_file(item, destination),
                }
            )
        except Exception as exc:
            missing_material.append("attachment_capture_failed")
            captured_files.append(
                {
                    "attachment_name": raw_name,
                    "capture_key": key,
                    "origin": item.get("url") or item.get("path"),
                    "error": str(exc)[:512],
                }
            )

    if detail.get("resources_truncated") is True:
        missing_material.append("resources_truncated")
    if detail.get("resources_complete") is False:
        missing_material.append("resources_incomplete")
    successful_captures = sum(
        1
        for capture in captured_files
        if capture.get("error") in (None, "")
        and capture_artifact_valid(root, capture)
    )
    if successful_captures != len(file_items):
        missing_material.append("attachment_count_mismatch")
    missing_material = sorted(set(missing_material))

    attempted_at = iso_now()
    intake_state = "complete" if not missing_material else "partial"
    detail_info = detail_path.stat()
    payload = {
        **detail,
        "id": challenge_id,
        "detail_path": detail_path.relative_to(root).as_posix(),
        "detail_sha256": sha256_file(detail_path),
        "detail_bytes": detail_info.st_size,
        "captured_files": captured_files,
        "expected_file_count": len(file_items),
        "captured_file_count": successful_captures,
        "classification": existing.get("classification", "untriaged"),
        "intake_attempt_id": attempt_id,
        "intake_attempt_count": _intake_attempt_count(existing) + 1,
        "intake_state": intake_state,
        "intake_missing_material": missing_material,
        "intake_last_attempt_at": attempted_at,
        "intake_last_error": ";".join(missing_material),
        "ingested_at": attempted_at if intake_state == "complete" else "",
    }
    store.append("challenge.upsert", payload, actor="platform")
    refresh_snapshot(store, root, manifest)
    if not quiet:
        print(json.dumps(payload, indent=2))
    return (0 if intake_state == "complete" else 2), payload


def cmd_platform(args) -> int:
    root = workspace_root()
    challenge_id = str(args.challenge_id) if args.platform_action == "ingest" else ""
    manifest, scope, store, result = load_context(root, require_ready=True)
    adapter = get_adapter(root, manifest, scope)
    if args.platform_action == "sync":
        with file_lock(root / "state" / "platform-intake.lock"):
            snapshot = _record_platform_snapshot(
                root,
                store,
                manifest,
                adapter,
                adapter.sync(),
            )
            refresh_snapshot(store, root, manifest)
        print(
            json.dumps(
                {
                    "adapter_id": adapter.id,
                    "challenges": len(snapshot.get("challenges", [])),
                    "artifact": snapshot["artifact"],
                    "capabilities": snapshot.get("capabilities", {}),
                },
                indent=2,
            )
        )
        return 0
    if args.platform_action == "ingest":
        with file_lock(root / "state" / "platform-intake.lock"):
            rc, _payload = _ingest_challenge_locked(
                root,
                manifest,
                scope,
                store,
                adapter,
                challenge_id=challenge_id,
                no_files=bool(args.no_files),
                quiet=bool(getattr(args, "quiet", False)),
            )
        return rc
    if args.platform_action == "unlock-check":
        if args.ingest and args.limit < 1:
            raise ValueError("unlock-check --limit must be a positive integer")
        with file_lock(root / "state" / "platform-intake.lock"):
            projection = store.rebuild()
            current_challenges = projection["current"].get("challenges", {})
            previous = projection["current"].get("authoritative_platform", {})
            old_ids = {
                challenge_id
                for challenge_id in (
                    previous.get("challenge_ids", []) if isinstance(previous, dict) else []
                )
                if isinstance(challenge_id, str) and challenge_id
            }
            snapshot = adapter.sync()
            authoritative_inventory = platform_inventory_is_authoritative(snapshot)
            snapshot_rows = {
                str(challenge.get("id")): challenge
                for challenge in snapshot.get("challenges", [])
                if isinstance(challenge, dict) and str(challenge.get("id") or "")
            }
            current_ids = set(snapshot_rows)
            new_ids = (
                sorted(current_ids - old_ids)
                if authoritative_inventory
                else []
            )
            pending_ids: list[str] = []
            partial_ids: list[str] = []
            blocked_ids: list[str] = []
            deferred: list[dict[str, str]] = []
            for cid in sorted(current_ids):
                existing = current_challenges.get(cid, {})
                platform_row = {
                    **existing,
                    **snapshot_rows[cid],
                    **({"platform_present": True} if authoritative_inventory else {}),
                }
                platform = platform_solver_eligibility(platform_row)
                if not platform["ready"]:
                    reason = str(platform.get("reason") or "unsupported")
                    deferred.append({"id": cid, "reason": reason})
                    if reason in {"policy_blocked", "operator_only"}:
                        blocked_ids.append(cid)
                    continue
                intake = inspect_intake(root, existing)
                if intake["ready"]:
                    continue
                if existing.get("intake_state") == "partial":
                    partial_ids.append(cid)
                    continue
                pending_ids.append(cid)

            snapshot = _record_platform_snapshot(
                root,
                store,
                manifest,
                adapter,
                snapshot,
            )
            ingested_ids: list[str] = []
            intake_errors: list[dict[str, str]] = []
            attempted_partial: list[str] = []
            if args.ingest:
                new_id_set = set(new_ids)
                ordered_pending = [cid for cid in new_ids if cid in pending_ids]
                existing_pending = [
                    cid for cid in pending_ids if cid not in new_id_set
                ]
                ordered_pending.extend(
                    cid
                    for cid in existing_pending
                    if _intake_attempt_count(current_challenges.get(cid, {})) == 0
                )
                ordered_pending.extend(
                    sorted(
                        (
                            cid
                            for cid in existing_pending
                            if _intake_attempt_count(current_challenges.get(cid, {}))
                            > 0
                        ),
                        key=lambda cid: (
                            _intake_attempt_count(current_challenges.get(cid, {})),
                            str(
                                current_challenges.get(cid, {}).get(
                                    "intake_last_attempt_at"
                                )
                                or ""
                            ),
                            cid,
                        ),
                    )
                )
                for cid in ordered_pending[: args.limit]:
                    try:
                        rc, payload = _ingest_challenge_locked(
                            root,
                            manifest,
                            scope,
                            store,
                            adapter,
                            challenge_id=cid,
                            no_files=False,
                            quiet=True,
                        )
                    except (
                        KeyError,
                        OSError,
                        RuntimeError,
                        TypeError,
                        ValueError,
                    ) as exc:
                        error = str(exc)[:512]
                        prior = current_challenges.get(cid, {})
                        store.append(
                            "challenge.upsert",
                            {
                                "id": cid,
                                "intake_attempt_count": _intake_attempt_count(prior)
                                + 1,
                                "intake_state": "pending",
                                "intake_missing_material": ["detail_unavailable"],
                                "intake_last_attempt_at": iso_now(),
                                "intake_last_error": error,
                                "ingested_at": "",
                            },
                            actor="platform",
                        )
                        intake_errors.append({"id": cid, "error": error})
                        continue
                    if rc == 0 and payload.get("intake_state") == "complete":
                        ingested_ids.append(cid)
                    else:
                        attempted_partial.append(cid)
                        intake_errors.append(
                            {
                                "id": cid,
                                "error": "challenge_intake_partial",
                            }
                        )
            completed = set(ingested_ids)
            remaining_ids = [
                cid for cid in pending_ids if cid not in completed and cid not in attempted_partial
            ]
            partial_ids = sorted(set(partial_ids) | set(attempted_partial))
            refresh_snapshot(store, root, manifest)
        print(
            json.dumps(
                {
                    "new_ids": new_ids,
                    "count": len(new_ids),
                    "ingested_ids": ingested_ids,
                    "ingested_count": len(ingested_ids),
                    "intake_pending_ids": remaining_ids,
                    "intake_pending_count": len(remaining_ids),
                    "intake_partial_ids": partial_ids,
                    "intake_partial_count": len(partial_ids),
                    "intake_blocked_ids": blocked_ids,
                    "intake_deferred": deferred,
                    "intake_errors": intake_errors,
                },
                indent=2,
            )
        )
        return 2 if intake_errors or partial_ids else 0
    raise RuntimeError("unknown platform action")


def cmd_frontier(args) -> int:
    root = workspace_root()
    manifest, scope, store, result = load_context(root, require_ready=False)
    projection = store.rebuild()
    challenges = []
    for challenge in projection["current"].get("challenges", {}).values():
        eligibility = solver_eligibility(root, challenge)
        challenges.append(
            {
                **challenge,
                "solver_eligible": bool(eligibility["ready"]),
                "solver_ineligible_reason": str(eligibility.get("reason") or ""),
            }
        )
    ranked = rank_challenges(
        [c for c in challenges if not c.get("solved")],
        {
            **manifest,
            "policy_generation": int(store.get_meta("policy_generation", "0")),
        },
        coordination=projection["current"].get("challenge_coordination", {}),
        source_event_count=int(projection["current"].get("event_count", 0)),
        source_stop_generation=int(projection["current"].get("stop_generation", 0)),
    )
    atomic_write_json(root / "state" / "priority.json", ranked)
    refresh_snapshot(store, root, manifest)
    if args.json:
        print(json.dumps(ranked, indent=2))
    else:
        for row in ranked[: args.limit]:
            print(
                f"{row.get('id')} score={row.get('priority_score'):.3f} category={row.get('category')} reason={row.get('priority_reason')}"
            )
    return 0


def cmd_policy(args) -> int:
    root = workspace_root()
    manifest, scope, store, result = load_context(root, require_ready=False)
    if args.policy_action == "show":
        print(json.dumps(effective_policy(store), indent=2))
        return 0
    value = json.loads(args.value) if args.json_value else args.value
    row = set_policy(store, args.key, value, source=args.source, reason=args.reason)
    refresh_snapshot(store, root, manifest)
    print(json.dumps(row, indent=2))
    return 0


def cmd_goal(args) -> int:
    root = workspace_root()
    manifest, scope, store, result = load_context(root, require_ready=False)
    if args.goal_action == "status":
        print(json.dumps(store.rebuild()["current"].get("active_goal"), indent=2))
        return 0
    if args.goal_action == "set":
        payload = {
            "goal_id": args.goal_id or "goal_" + uuid.uuid4().hex,
            "text": args.text,
            "source": args.source,
            "reason": args.reason,
            "set_at": iso_now(),
        }
        store.append("goal.set", payload, actor=args.source)
    else:
        current = store.rebuild()["current"].get("active_goal") or {}
        goal_id = args.goal_id or current.get("goal_id")
        if not goal_id:
            raise ValueError(
                "no active goal; provide --goal-id to supersede a specific goal"
            )
        payload = {
            "goal_id": goal_id,
            "reason": args.reason,
            "superseded_at": iso_now(),
        }
        store.append("goal.supersede", payload, actor=args.source)
    refresh_snapshot(store, root, manifest)
    print(json.dumps(payload, indent=2))
    return 0


def cmd_score(args) -> int:
    root = workspace_root()
    manifest, scope, store, result = load_context(root, require_ready=False)
    if args.score_action == "propose":
        attempt_scope = json.loads(args.attempt_scope) if args.attempt_scope else {}
        freshness = json.loads(args.freshness) if args.freshness else {}
        row = create_proposal(
            store,
            manifest,
            objective_id=args.objective_id,
            action_kind=args.kind,
            exact_value=args.value or "",
            artifact_reference=args.artifact or "",
            attempt_scope=attempt_scope,
            verifier_evidence=args.verifier or [],
            freshness_requirements=freshness,
            source=args.source,
            rationale=args.rationale,
            confidence=args.confidence,
            agent_attempt_id=args.agent_attempt_id or "",
            parent_rejection_fingerprint=args.parent_rejection or "",
            discriminator=args.discriminator or "",
            challenge_id=args.challenge_id or "",
            source_handoff_id=args.source_handoff_id or "",
            actor=args.actor,
        )
        print(
            json.dumps(
                {
                    **row,
                    "morphology": morphology_score(
                        manifest, row.get("exact_value", "")
                    ),
                },
                indent=2,
            )
        )
    elif args.score_action == "review":
        row = record_review(
            store,
            args.proposal_id,
            args.verdict,
            reviewer=args.reviewer,
            reason=args.reason,
            verifier_report=args.verifier_report or "",
        )
        print(json.dumps(row, indent=2))
    elif args.score_action == "authorize-exact":
        print(
            json.dumps(
                grant_exact(store, args.proposal_id, reason=args.reason), indent=2
            )
        )
    elif args.score_action == "allowance":
        print(
            json.dumps(
                grant_allowance(
                    store, manifest, args.kind, args.count,
                    reason=args.reason, actor=args.actor,
                ),
                indent=2,
            )
        )
    elif args.score_action == "status":
        projection = store.rebuild()
        print(
            json.dumps(
                {
                    "proposals": projection["current"]["proposals"],
                    "reviews": projection["current"]["reviews"],
                    "authorizations": projection["current"]["authorizations"],
                    "queue": build_queue(store, manifest),
                },
                indent=2,
            )
        )
    elif args.score_action == "plan":
        print(
            json.dumps(
                compile_plan(store, root, manifest, scope, args.proposal_id), indent=2
            )
        )
    elif args.score_action == "execute":
        result_obj, rc = execute_plan(store, root, manifest, scope, args.plan_id)
        refresh_snapshot(store, root, manifest)
        print(json.dumps(result_obj, indent=2))
        return rc
    refresh_snapshot(store, root, manifest)
    return 0


def _queue_tick(
    root: Path,
    manifest: dict[str, Any],
    scope: dict[str, Any],
    store: EventStore,
    args: argparse.Namespace,
    *,
    snapshot: dict[str, Any] | None = None,
) -> tuple[int, dict[str, Any], dict[str, Any]]:
    """Run one queue tick using an optional watcher-owned read snapshot."""

    if args.auto_execute and not manifest.get("queue", {}).get(
        "automation_enabled", False
    ):
        raise RuntimeError("queue automation is disabled by event policy")
    queue = persist_schedules(store, manifest, snapshot=snapshot)
    item = next((row for row in queue["items"] if row["eligible"]), None)
    if not item:
        return (
            0,
            {"executed": False, "reason": "no eligible item", "queue": queue},
            queue,
        )
    plan = compile_plan(store, root, manifest, scope, item["proposal_id"])
    if args.auto_execute:
        out, rc = execute_plan(store, root, manifest, scope, plan["plan_id"])
        refresh_snapshot(store, root, manifest)
        # Auto-execution is a mutation path. Refresh the advisory view for the
        # watch presentation so the next fingerprint reflects its terminal
        # state; this extra read never occurs on a warm idle tick.
        return rc, out, build_queue(store, manifest)
    return 0, {"executed": False, "plan": plan}, queue


def _queue_watch_state(queue: dict[str, Any]) -> dict[str, Any]:
    next_action = queue.get("next_action") or {}
    return {
        "depth": int(queue.get("depth", 0) or 0),
        "eligible": int(queue.get("eligible", 0) or 0),
        "next_proposal_id": str(next_action.get("proposal_id") or ""),
    }


def _queue_watch_record(
    state: dict[str, Any],
    *,
    reason: str,
    return_code: int,
    tick_duration_ms: int,
) -> str:
    """Render the compact, value-free watcher presentation record."""

    return canonical_json(
        {
            "event": "queue.watch",
            "reason": reason,
            "generated_at": iso_now(),
            "tick_duration_ms": max(0, tick_duration_ms),
            "return_code": return_code,
            **state,
        }
    )


def _queue_watch_presentation(
    state: dict[str, Any],
    *,
    last_fingerprint: str,
    last_heartbeat: float,
    now: float,
    heartbeat_seconds: int,
    return_code: int,
    tick_duration_ms: int,
) -> tuple[str | None, str, float]:
    """Return at most one transition, heartbeat, or error record per tick."""

    fingerprint = canonical_json(state)
    changed = fingerprint != last_fingerprint
    heartbeat_due = now - last_heartbeat >= heartbeat_seconds
    if not (changed or heartbeat_due or return_code != 0):
        return None, fingerprint, last_heartbeat
    reason = "error" if return_code != 0 else "transition" if changed else "heartbeat"
    return (
        _queue_watch_record(
            state,
            reason=reason,
            return_code=return_code,
            tick_duration_ms=tick_duration_ms,
        ),
        fingerprint,
        now,
    )


def cmd_queue(args) -> int:
    root = workspace_root()
    manifest, scope, store, result = load_context(root, require_ready=False)
    if args.queue_action == "status":
        print(json.dumps(build_queue(store, manifest), indent=2))
        return 0
    if args.queue_action == "schedule":
        print(json.dumps(persist_schedules(store, manifest), indent=2))
        refresh_snapshot(store, root, manifest)
        return 0
    if args.queue_action == "tick":
        rc, output, _ = _queue_tick(root, manifest, scope, store, args)
        if not getattr(args, "quiet", False):
            print(json.dumps(output, indent=2))
        return rc
    if args.queue_action == "watch":
        owner_token = str(getattr(args, "owner_token", "") or "")
        watcher_epoch = getattr(args, "watcher_epoch", None)
        diagnostic = bool(getattr(args, "diagnostic", False))
        automation_enabled = bool(
            manifest.get("queue", {}).get("automation_enabled", False)
        )
        if diagnostic:
            print(
                json.dumps(
                    {
                        "diagnostic": True,
                        "automation_enabled": automation_enabled,
                        "queue": build_queue(store, manifest),
                    },
                    indent=2,
                )
            )
            return 0
        if not automation_enabled:
            raise RuntimeError(
                "queue watch is disabled by event policy; use --diagnostic"
            )
        if not owner_token or watcher_epoch is None:
            raise RuntimeError(
                "automated queue watch requires --owner-token and --watcher-epoch"
            )
        interval = max(1, int(args.interval))
        heartbeat_seconds = max(1, int(args.heartbeat_seconds))
        last_fingerprint = ""
        last_heartbeat = 0.0
        while True:
            # A stale lease exits before any queue reduction, schedule write,
            # plan creation, or presentation work. The same snapshot is then
            # reused for the advisory queue tick below.
            snapshot = store.read_snapshot()
            if not watcher_lease_is_current(
                store, owner_token, watcher_epoch, snapshot=snapshot
            ):
                return 0
            if store.projection_from_snapshot(snapshot)["current"].get("stopped"):
                return 0
            tick_started = time.monotonic()
            rc, output, queue = _queue_tick(
                root, manifest, scope, store, args, snapshot=snapshot
            )
            if not args.quiet:
                print(json.dumps(output, indent=2))
            if args.quiet:
                state = _queue_watch_state(queue)
                now = time.monotonic()
                record, last_fingerprint, last_heartbeat = _queue_watch_presentation(
                    state,
                    last_fingerprint=last_fingerprint,
                    last_heartbeat=last_heartbeat,
                    now=now,
                    heartbeat_seconds=heartbeat_seconds,
                    return_code=rc,
                    tick_duration_ms=int((time.monotonic() - tick_started) * 1000),
                )
                if record is not None:
                    print(record, flush=True)
            if args.once:
                return rc
            time.sleep(interval)
    return 0


def cmd_retry(args) -> int:
    root = workspace_root()
    manifest, scope, store, result = load_context(root, require_ready=False)
    if args.retry_action == "add":
        when = parse_iso(args.earliest)
        if when is None:
            when = dt.datetime.now(UTC) + dt.timedelta(
                seconds=parse_duration(args.earliest)
            )
        payload = {
            "retry_id": "retry_" + uuid.uuid4().hex,
            "objective_id": str(args.objective_id),
            "challenge_id": str(args.challenge_id or ""),
            "source_handoff_id": str(args.handoff_id or ""),
            "earliest_at": when.replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z"),
            "trigger": args.trigger,
            "method": args.method,
            "negative_snapshot": args.snapshot or "",
            "command": args.command or "",
            "bounded_wave": int(args.bounded_wave),
            "status": "scheduled",
            "created_at": iso_now(),
        }
        payload = schedule_retry_continuation(store, payload, actor="coordinator")
        print(json.dumps(payload, indent=2))
    elif args.retry_action == "due":
        now = dt.datetime.now(UTC)
        rows = []
        for row in store.rebuild()["current"]["retries"].values():
            when = parse_iso(row.get("earliest_at"))
            if row.get("status") == "scheduled" and when and when <= now:
                rows.append(row)
        if args.write:
            atomic_write_json(root / "state" / "due_retries.json", rows)
        print(json.dumps(rows, indent=2))
    refresh_snapshot(store, root, manifest)
    return 0


def cmd_agent(args) -> int:
    root = workspace_root()
    manifest, scope, store, result = load_context(root, require_ready=False)
    output: dict[str, Any] = {"ok": True}
    if args.agent_action == "list":
        print(json.dumps(store.rebuild()["current"]["agents"], indent=2))
        return 0
    if args.agent_action == "register":
        max_workers = int(
            manifest.get("concurrency", {}).get("max_workers", 0) or 0
        )
        attempt_id = args.attempt_id or "attempt_" + uuid.uuid4().hex
        registration = {
            "agent_id": args.agent_id,
            "agent_attempt_id": attempt_id,
            "parent_agent_attempt_id": args.parent_attempt_id or "",
            "objective_id": args.objective_id,
            "challenge_id": args.challenge_id or "",
            "event_wide": bool(args.event_wide),
            "source_handoff_id": args.handoff_id or "",
            "goal": args.goal,
            "scope": args.scope,
            "stop_condition": args.stop_condition,
            "role": args.role,
            "report_path": args.report_path,
            "owner": args.owner,
            "pid": args.pid or 0,
            "pgid": args.pgid or 0,
            "process_starttime": args.process_starttime or "",
            "owner_token": args.owner_token or "",
            "started_at": iso_now(),
        }
        admission = register_agent_attempt(
            store,
            registration,
            max_workers=max_workers,
        )
        if not admission["admitted"]:
            raise RuntimeError("worker concurrency limit reached")
        output = admission["output"]
    elif args.agent_action == "close":
        output = close_current_agent_attempt(
            store,
            agent_id=args.agent_id,
            reason=args.reason,
        )
    elif args.agent_action == "integrate":
        out = harvest_report(
            store,
            root,
            args.report_path,
            agent_id=args.agent_id,
            agent_attempt_id=args.agent_attempt_id,
            challenge_id=args.challenge_id or "",
            objective_id=args.objective_id,
            status=args.status,
            observed_result=args.observed_result,
            route_key=args.route_key,
            proof_gap=args.proof_gap,
            next_step_or_return_trigger=args.next_step_or_return_trigger,
        )
        print(json.dumps(out, indent=2))
        refresh_snapshot(store, root, manifest)
        return 0
    refresh_snapshot(store, root, manifest)
    print(json.dumps(output, indent=2))
    return 0


def cmd_outcome(args) -> int:
    root = workspace_root()
    manifest, scope, store, result = load_context(root, require_ready=False)
    if args.outcome_action == "record":
        out = record_outcome(
            store,
            agent_id=args.agent_id,
            objective_id=args.objective_id,
            outcome_type=args.type,
            report_path=args.report_path,
            summary=args.summary,
            mechanism=args.mechanism or "",
            agent_attempt_id=args.agent_attempt_id or "",
            provenance=args.provenance or [],
            challenge_id=args.challenge_id or "",
            continuation=args.continuation or "",
            handoff_id=args.handoff_id or "",
        )
    elif args.outcome_action == "brake":
        out = confusion_brake(store, args.objective_id, args.mechanism)
    else:
        out = record_continuation_boundary(
            store,
            challenge_id=args.challenge_id,
            objective_id=args.objective_id,
            name=args.name,
            return_condition=args.return_condition,
            source_handoff_id=args.handoff_id,
        )
    refresh_snapshot(store, root, manifest)
    print(json.dumps(out, indent=2))
    return 0


def cmd_explore(args) -> int:
    """Operate one durable stalled-challenge exploration campaign.

    These commands preserve a route and feed the ordinary compute queue.  They
    never spawn a process, submit a candidate, or bypass reviewed scoring.
    """

    root = workspace_root()
    manifest, scope, store, result = load_context(root, require_ready=False)
    action = args.explore_action
    if action == "status":
        campaigns = store.rebuild()["current"].get("exploration_campaigns", {})
        if args.campaign_id:
            output = campaigns.get(args.campaign_id)
            if output is None:
                raise ValueError("exploration campaign was not found")
        else:
            output = list(campaigns.values())
        print(json.dumps(output, indent=2))
        return 0
    if action == "open":
        output = open_campaign(
            store,
            challenge_id=args.challenge_id,
            objective_id=args.objective_id,
            source_handoff_id=args.handoff_id,
            route_keys=args.route_key,
            campaign_id=args.campaign_id or "",
        )
    elif action == "claim":
        output = claim_ideation(
            store,
            campaign_id=args.campaign_id,
            lens=args.lens,
            agent_attempt_id=args.agent_attempt_id,
        )
    elif action == "claim-synthesis":
        output = claim_synthesis(
            store,
            campaign_id=args.campaign_id,
            agent_attempt_id=args.agent_attempt_id,
        )
    elif action == "record":
        output = record_idea_batch(
            store,
            root,
            campaign_id=args.campaign_id,
            lens=args.lens,
            agent_attempt_id=args.agent_attempt_id,
            handoff_id=args.handoff_id,
            ideas_file=args.ideas_file,
        )
    elif action == "synthesize":
        output = synthesize_campaign(
            store,
            root,
            campaign_id=args.campaign_id,
            synthesizer_attempt_id=args.agent_attempt_id,
            handoff_id=args.handoff_id,
            selection_file=args.selection_file,
        )
    elif action == "dispatch":
        output = record_dispatch_claim(
            store,
            campaign_id=args.campaign_id,
            idea_id=args.idea_id,
            compute_idea_id=args.compute_idea_id,
            agent_attempt_id=args.agent_attempt_id,
        )
    elif action == "park":
        output = park_campaign(
            store,
            campaign_id=args.campaign_id,
            reason=args.reason,
            recheck_condition=args.recheck_condition,
            boundary_id=args.boundary_id,
        )
    elif action == "close":
        output = close_campaign(store, campaign_id=args.campaign_id, reason=args.reason)
    else:  # pragma: no cover - argparse keeps this unreachable
        raise ValueError("exploration action is invalid")
    refresh_snapshot(store, root, manifest)
    print(json.dumps(output, indent=2))
    return 0


def cmd_compute(args) -> int:
    root = workspace_root()
    manifest, scope, store, result = load_context(root, require_ready=False)
    action = getattr(args, "compute_action", None)
    if action == "enqueue":
        output = enqueue_compute_idea(
            store,
            {
                "objective_id": args.objective_id,
                "goal": args.goal,
                "scope": args.scope,
                "report_path": args.report_path,
                "stop_condition": args.stop_condition,
                "mechanism": args.mechanism,
                "requested_cpu_threads": args.requested_cpu_threads,
                "budget_seconds": args.budget_seconds,
                "checkpointable": True,
                "dispatch_kind": args.dispatch_kind,
                "expected_value": args.expected_value,
                "evidence_value": args.evidence_value,
                "dedupe_key": args.dedupe_key,
            },
        )
    elif action in {"list", "status"}:
        status = compute_queue_status(store)
        if action == "list":
            output = status["ideas"]
        elif args.idea_id:
            output = next(
                (idea for idea in status["ideas"] if idea.get("idea_id") == args.idea_id),
                None,
            )
            if output is None:
                raise ValueError("compute idea was not found")
        else:
            output = status
    elif action == "tick":
        sample_seconds = float(
            manifest.get("compute", {}).get("sample_seconds", 1.0) or 1.0
        )
        observation = sample_host_cpu(sample_seconds=sample_seconds)
        output = admit_compute_tick(store, manifest, observation)
        atomic_write_json(root / "state" / "compute_schedule.json", output)
    elif action == "start":
        output = start_compute_idea(
            store,
            idea_id=args.idea_id,
            admission_id=args.admission_id,
            agent_attempt_id=args.agent_attempt_id or "",
            job_id=args.job_id or "",
        )
    elif action == "outcome":
        output = finish_compute_idea(
            store,
            idea_id=args.idea_id,
            status=args.status,
            summary=args.summary,
            admission_id=args.admission_id,
            agent_attempt_id=args.agent_attempt_id or "",
            job_id=args.job_id or "",
            report_path=args.report_path or "",
            checkpoint_path=args.checkpoint_path or "",
        )
    elif action == "requeue":
        output = requeue_compute_idea(store, idea_id=args.idea_id)
    else:
        # Compatibility for the original advisory ``compute --jobs`` surface.
        jobs = (
            load_json(Path(args.jobs), [])
            if args.jobs
            else list(store.rebuild()["current"].get("jobs", {}).values())
        )
        output = schedule_useful_jobs(
            jobs if isinstance(jobs, list) else [], manifest
        )
        atomic_write_json(root / "state" / "compute_schedule.json", output)
    refresh_snapshot(store, root, manifest)
    print(json.dumps(output, indent=2))
    return 0


def cmd_surface(args) -> int:
    root = workspace_root()
    manifest, scope, store, result = load_context(root, require_ready=False)
    snapshot = store.rebuild()["current"].get("platform") or None
    inventory = render_surface(root, runtime_surface_manifest(manifest, snapshot))
    print(json.dumps(inventory, indent=2))
    return 0


def cmd_writeup(args) -> int:
    root = workspace_root()
    manifest, scope, store, result = load_context(root, require_ready=False)
    if args.writeup_action == "capsule":
        out = create_capsule(
            store,
            root,
            objective_id=args.objective_id,
            action_reference=args.action_reference,
            scorer_evidence=args.scorer_evidence,
            reproduction_path=args.reproduction_path,
            material_provenance=args.provenance or [],
            dead_path_checkpoint=args.dead_path_checkpoint or "",
        )
        print(json.dumps(out, indent=2))
    elif args.writeup_action == "new":
        print(
            create_writeup(
                root,
                args.objective_id,
                args.title,
                manifest.get("writeups", {}).get("voice_file", "docs/voice.md"),
            )
        )
    elif args.writeup_action == "check":
        out = check_writeups(store, root, manifest, closeout=args.closeout)
        print(json.dumps(out, indent=2))
        return 0 if out["ok"] else 2
    return 0


def cmd_reconcile(args) -> int:
    root = workspace_root()
    manifest, scope, store, result = load_context(root, require_ready=False)
    if args.reconcile_action == "scan":
        out = reconcile_all(store, root, include_unbound=args.include_unbound)
    else:
        out = import_response(
            store, root, Path(args.path), include_unbound=args.include_unbound
        )
    refresh_snapshot(store, root, manifest)
    print(json.dumps(out, indent=2))
    return 0


def cmd_ledger(args) -> int:
    root = workspace_root()
    manifest, scope, store, result = load_context(root, require_ready=False)
    out = (
        correlation_ledger(store)
        if args.correlation
        else answer_ledger(store, include_unknown=args.include_unknown)
    )
    if args.json:
        print(json.dumps(out, indent=2))
    else:
        print(
            f"count={out['count']} "
            + " ".join(f"{k}={v}" for k, v in sorted(out["counts"].items()))
        )
        if args.correlation:
            return 0
        for row in out["rows"]:
            print(
                f"- objective={row['objective_id']} verdict={row['verdict']} proposal={row['proposal_id']} response={row['response_path']}"
            )
    return 0


def cmd_completion(args) -> int:
    root = workspace_root()
    manifest, scope, store, result = load_context(root, require_ready=False)
    if args.completion_action == "record":
        out = record_task_completion(store, plan_id=args.plan_id)
        refresh_snapshot(store, root, manifest)
        print(json.dumps(out, indent=2))
        return 0
    out = task_completion_audit(store)
    if args.json:
        print(json.dumps(out, indent=2))
    else:
        print(
            f"accepted_dynamic_actions={out['accepted_dynamic_actions']} completion_records={out['completion_records']} needs_completion_check={len(out['needs_completion_check'])}"
        )
    return 0 if out["ok"] else 2


def cmd_lessons(args) -> int:
    root = workspace_root()
    manifest, scope, store, result = load_context(root, require_ready=False)
    if args.lessons_action == "status":
        generation = store.current_stop_generation()
        rows = [
            e
            for e in store.events("lessons.created")
            if int(e.get("generation", -1)) == generation
        ]
        out = {
            "stop_generation": generation,
            "lessons": rows[-1]["payload"] if rows else None,
        }
        print(json.dumps(out, indent=2))
        return 0 if rows else 1
    out = create_lessons_document(store, root, reason=args.reason)
    print(json.dumps(out, indent=2))
    return 0


def cmd_prepare(args) -> int:
    root = workspace_root()
    if args.prepare_action == "status":
        out = read_preparation(root)
        print(json.dumps(out, indent=2))
        return 0 if out else 1
    gate, _binding, _store, _manifest, _scope, _result = _bootstrap_launch(root)
    ensure_runtime_dirs(root)
    out = prepare(
        root,
        apply=args.prepare_action == "apply",
        env=gate.preparation_environment.values,
        environment_resolved=True,
        stage_c_environments=gate.stage_c_environments,
    )
    print(json.dumps(out, indent=2))
    return 0 if out.get("ready") else 2


def cmd_validate(args) -> int:
    if args.source_checkout and not args.release:
        raise ValueError("--source-checkout requires --release")
    root = workspace_root()
    report = validate_tree(
        root,
        adapter=args.adapter,
        strict_release=args.release,
        source_checkout=args.source_checkout,
    )
    print(json.dumps(report, indent=2))
    return 0 if report["ok"] else 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="rookery")
    sub = p.add_subparsers(dest="command", required=True)

    go = sub.add_parser("go")
    go_sub = go.add_subparsers(dest="go_action")
    go_sub.required = False
    go.set_defaults(go_action="start")
    for action in ("status", "resume"):
        x = go_sub.add_parser(action)
        x.add_argument("--reason", default="")
    x = go_sub.add_parser("stop")
    x.add_argument("--reason", default="")

    man = sub.add_parser("manifest")
    ms = man.add_subparsers(dest="manifest_action", required=True)
    ms.add_parser("show")
    ms.add_parser("validate")
    x = ms.add_parser("render")
    x.add_argument("--output")

    config = sub.add_parser("config")
    configs = config.add_subparsers(dest="config_action", required=True)
    x = configs.add_parser("migrate-event")
    x.add_argument("--input", required=True)
    x.add_argument("--env", required=True)
    x.add_argument("--output", required=True)

    sc = sub.add_parser("scope")
    ss = sc.add_subparsers(dest="scope_action", required=True)
    ss.add_parser("show")
    x = ss.add_parser("check-host")
    x.add_argument("host")
    x.add_argument("--port", type=int)
    x.add_argument("--protocol")
    x.add_argument("--platform", action="store_true")
    x = ss.add_parser("check-url")
    x.add_argument("url")
    x.add_argument("--platform", action="store_true")
    x = ss.add_parser("check-file")
    x.add_argument("origin")
    x.add_argument("--size", type=int)
    x = ss.add_parser("check-cidr")
    x.add_argument("cidr")
    x = ss.add_parser("override")
    x.add_argument("--host")
    x.add_argument("--cidr")
    x.add_argument("--duration", required=True)
    x.add_argument("--reason", required=True)

    plat = sub.add_parser("platform")
    ps = plat.add_subparsers(dest="platform_action", required=True)
    ps.add_parser("sync")
    x = ps.add_parser("ingest")
    x.add_argument("challenge_id")
    x.add_argument("--no-files", action="store_true")
    x = ps.add_parser("unlock-check")
    x.add_argument("--ingest", action="store_true")
    x.add_argument("--limit", type=int, default=20)

    f = sub.add_parser("frontier")
    f.add_argument("--refresh", action="store_true")
    f.add_argument("--json", action="store_true")
    f.add_argument("--limit", type=int, default=30)

    pol = sub.add_parser("policy")
    pols = pol.add_subparsers(dest="policy_action", required=True)
    pols.add_parser("show")
    x = pols.add_parser("set")
    x.add_argument("key")
    x.add_argument("value")
    x.add_argument("--json-value", action="store_true")
    x.add_argument("--source", required=True)
    x.add_argument("--reason", required=True)

    goal = sub.add_parser("goal")
    gs = goal.add_subparsers(dest="goal_action", required=True)
    gs.add_parser("status")
    x = gs.add_parser("set")
    x.add_argument("text")
    x.add_argument("--goal-id")
    x.add_argument("--source", default="operator")
    x.add_argument("--reason", required=True)
    x = gs.add_parser("supersede")
    x.add_argument("--goal-id")
    x.add_argument("--source", default="operator")
    x.add_argument("--reason", required=True)

    score = sub.add_parser("score")
    ssub = score.add_subparsers(dest="score_action", required=True)
    x = ssub.add_parser("propose")
    x.add_argument("objective_id")
    x.add_argument("value", nargs="?")
    x.add_argument("--kind", required=True)
    x.add_argument("--artifact")
    x.add_argument("--source", required=True)
    x.add_argument("--rationale", required=True)
    x.add_argument("--confidence", default="candidate")
    x.add_argument("--agent-attempt-id")
    x.add_argument("--challenge-id")
    x.add_argument("--source-handoff-id")
    x.add_argument("--parent-rejection")
    x.add_argument("--discriminator")
    x.add_argument("--attempt-scope")
    x.add_argument("--freshness")
    x.add_argument("--verifier", action="append")
    x.add_argument("--actor", default="solver")
    x = ssub.add_parser("review")
    x.add_argument("proposal_id")
    x.add_argument("verdict", choices=sorted(REVIEW_VERDICTS))
    x.add_argument("--reviewer", required=True)
    x.add_argument("--reason", required=True)
    x.add_argument("--verifier-report")
    x = ssub.add_parser("authorize-exact")
    x.add_argument("proposal_id")
    x.add_argument("--reason", required=True)
    x = ssub.add_parser("allowance")
    x.add_argument("kind")
    x.add_argument("count", type=int)
    x.add_argument("--reason", required=True)
    x.add_argument("--actor", choices=("operator", "coordinator"), required=True)
    ssub.add_parser("status")
    x = ssub.add_parser("plan")
    x.add_argument("proposal_id")
    x = ssub.add_parser("execute")
    x.add_argument("plan_id")

    q = sub.add_parser("queue")
    qs = q.add_subparsers(dest="queue_action", required=True)
    qs.add_parser("status")
    qs.add_parser("schedule")
    x = qs.add_parser("tick")
    x.add_argument("--auto-execute", action="store_true")
    x = qs.add_parser("watch")
    x.add_argument("--auto-execute", action="store_true")
    x.add_argument("--interval", type=int, default=15)
    x.add_argument("--once", action="store_true")
    x.add_argument("--owner-token", default="")
    x.add_argument("--watcher-epoch", type=int, default=None)
    x.add_argument("--diagnostic", action="store_true")
    x.add_argument("--quiet", action="store_true")
    x.add_argument("--heartbeat-seconds", type=int, default=300)

    r = sub.add_parser("retry")
    rs = r.add_subparsers(dest="retry_action", required=True)
    x = rs.add_parser("add")
    x.add_argument("objective_id")
    x.add_argument("--challenge-id", required=True)
    x.add_argument("--handoff-id", required=True)
    x.add_argument("--earliest", required=True)
    x.add_argument("--trigger", required=True)
    x.add_argument("--method", required=True)
    x.add_argument("--snapshot")
    x.add_argument("--command")
    x.add_argument("--bounded-wave", type=int, default=1)
    x = rs.add_parser("due")
    x.add_argument("--write", action="store_true")

    a = sub.add_parser("agent")
    ass = a.add_subparsers(dest="agent_action", required=True)
    ass.add_parser("list")
    x = ass.add_parser("register")
    x.add_argument("agent_id")
    x.add_argument("--objective-id", required=True)
    x.add_argument("--role", required=True)
    x.add_argument("--report-path", required=True)
    x.add_argument("--goal", required=True)
    x.add_argument("--scope", required=True)
    x.add_argument("--stop-condition", required=True)
    x.add_argument("--owner", default="coordinator")
    x.add_argument("--attempt-id")
    x.add_argument("--parent-attempt-id")
    x.add_argument("--pid", type=int)
    x.add_argument("--pgid", type=int)
    x.add_argument("--process-starttime")
    x.add_argument("--owner-token")
    x.add_argument("--handoff-id")
    assignment = x.add_mutually_exclusive_group(required=True)
    assignment.add_argument("--challenge-id")
    assignment.add_argument("--event-wide", action="store_true")
    x = ass.add_parser("close")
    x.add_argument("agent_id")
    x.add_argument("--reason", required=True)
    x = ass.add_parser("integrate")
    x.add_argument("report_path")
    x.add_argument("--agent-id", required=True)
    x.add_argument("--agent-attempt-id", required=True)
    x.add_argument("--objective-id", required=True)
    handoff_scope = x.add_mutually_exclusive_group(required=True)
    handoff_scope.add_argument("--challenge-id")
    handoff_scope.add_argument("--event-wide", action="store_true")
    x.add_argument("--status", required=True)
    x.add_argument("--observed-result", required=True)
    x.add_argument("--route-key", required=True)
    x.add_argument("--proof-gap", required=True)
    x.add_argument("--next-step-or-return-trigger", required=True)

    o = sub.add_parser("outcome")
    osub = o.add_subparsers(dest="outcome_action", required=True)
    x = osub.add_parser("record")
    x.add_argument("--agent-id", required=True)
    x.add_argument("--objective-id", required=True)
    x.add_argument("--type", required=True)
    x.add_argument("--report-path", required=True)
    x.add_argument("--summary", required=True)
    x.add_argument("--agent-attempt-id")
    x.add_argument("--mechanism")
    x.add_argument("--provenance", action="append")
    x.add_argument("--challenge-id")
    x.add_argument("--continuation")
    x.add_argument("--handoff-id")
    x = osub.add_parser("brake")
    x.add_argument("objective_id")
    x.add_argument("mechanism")
    x = osub.add_parser("boundary")
    x.add_argument("--challenge-id", required=True)
    x.add_argument("--objective-id", required=True)
    x.add_argument("--handoff-id", required=True)
    x.add_argument("--name", required=True)
    x.add_argument("--return-condition", required=True)

    explore = sub.add_parser("explore")
    explores = explore.add_subparsers(dest="explore_action", required=True)
    x = explores.add_parser("open")
    x.add_argument("--challenge-id", required=True)
    x.add_argument("--objective-id", required=True)
    x.add_argument("--handoff-id", required=True)
    x.add_argument("--route-key", action="append", required=True)
    x.add_argument("--campaign-id")
    x = explores.add_parser("claim")
    x.add_argument("--campaign-id", required=True)
    x.add_argument("--lens", choices=("fresh", "evidence", "artifact", "contrarian"), required=True)
    x.add_argument("--agent-attempt-id", required=True)
    x = explores.add_parser("record")
    x.add_argument("--campaign-id", required=True)
    x.add_argument("--lens", choices=("fresh", "evidence", "artifact", "contrarian"), required=True)
    x.add_argument("--agent-attempt-id", required=True)
    x.add_argument("--handoff-id", required=True)
    x.add_argument("--ideas-file", required=True)
    x = explores.add_parser("claim-synthesis")
    x.add_argument("--campaign-id", required=True)
    x.add_argument("--agent-attempt-id", required=True)
    x = explores.add_parser("synthesize")
    x.add_argument("--campaign-id", required=True)
    x.add_argument("--agent-attempt-id", required=True)
    x.add_argument("--handoff-id", required=True)
    x.add_argument("--selection-file", required=True)
    x = explores.add_parser("dispatch")
    x.add_argument("--campaign-id", required=True)
    x.add_argument("--idea-id", required=True)
    x.add_argument("--compute-idea-id", required=True)
    x.add_argument("--agent-attempt-id", required=True)
    x = explores.add_parser("park")
    x.add_argument("--campaign-id", required=True)
    x.add_argument("--reason", required=True)
    x.add_argument("--recheck-condition", required=True)
    x.add_argument("--boundary-id", required=True)
    x = explores.add_parser("close")
    x.add_argument("--campaign-id", required=True)
    x.add_argument("--reason", required=True)
    x = explores.add_parser("status")
    x.add_argument("--campaign-id")

    c = sub.add_parser("compute")
    c.add_argument("--jobs")
    cs = c.add_subparsers(dest="compute_action")
    x = cs.add_parser("enqueue")
    x.add_argument("--objective-id", required=True)
    x.add_argument("--goal", required=True)
    x.add_argument("--scope", required=True)
    x.add_argument("--report-path", required=True)
    x.add_argument("--stop-condition", required=True)
    x.add_argument("--mechanism", required=True)
    x.add_argument("--requested-cpu-threads", type=int, default=1)
    x.add_argument("--dispatch-kind", choices=("agent", "job"), default="agent")
    x.add_argument("--budget-seconds", type=int, default=900)
    x.add_argument("--expected-value", type=float, default=1.0)
    x.add_argument("--evidence-value", type=float, default=1.0)
    x.add_argument("--dedupe-key", required=True)
    cs.add_parser("list")
    x = cs.add_parser("status")
    x.add_argument("idea_id", nargs="?")
    cs.add_parser("tick")
    x = cs.add_parser("start")
    x.add_argument("idea_id")
    x.add_argument("--admission-id", required=True)
    binding = x.add_mutually_exclusive_group(required=True)
    binding.add_argument("--agent-attempt-id")
    binding.add_argument("--job-id")
    x = cs.add_parser("outcome")
    x.add_argument("idea_id")
    x.add_argument(
        "--status",
        required=True,
        choices=("completed", "failed", "retired", "cancelled", "paused"),
    )
    x.add_argument("--summary", required=True)
    x.add_argument("--admission-id", required=True)
    outcome_binding = x.add_mutually_exclusive_group(required=True)
    outcome_binding.add_argument("--agent-attempt-id")
    outcome_binding.add_argument("--job-id")
    x.add_argument("--report-path")
    x.add_argument("--checkpoint-path")
    x = cs.add_parser("requeue")
    x.add_argument("idea_id")

    sub.add_parser("surface")

    w = sub.add_parser("writeup")
    ws = w.add_subparsers(dest="writeup_action", required=True)
    x = ws.add_parser("capsule")
    x.add_argument("objective_id")
    x.add_argument("--action-reference", required=True)
    x.add_argument("--scorer-evidence", required=True)
    x.add_argument("--reproduction-path", required=True)
    x.add_argument("--provenance", action="append")
    x.add_argument("--dead-path-checkpoint")
    x = ws.add_parser("new")
    x.add_argument("objective_id")
    x.add_argument("--title", required=True)
    x = ws.add_parser("check")
    x.add_argument("--closeout", action="store_true")

    prep = sub.add_parser("prepare")
    preps = prep.add_subparsers(dest="prepare_action", required=True)
    preps.add_parser("apply")
    preps.add_parser("check")
    preps.add_parser("status")

    rec = sub.add_parser("reconcile")
    recs = rec.add_subparsers(dest="reconcile_action", required=True)
    x = recs.add_parser("scan")
    x.add_argument("--include-unbound", action="store_true")
    x = recs.add_parser("import")
    x.add_argument("path")
    x.add_argument("--include-unbound", action="store_true")

    led = sub.add_parser("ledger")
    led.add_argument("--json", action="store_true")
    led.add_argument("--include-unknown", action="store_true")
    led.add_argument("--correlation", action="store_true")

    comp = sub.add_parser("completion")
    comps = comp.add_subparsers(dest="completion_action", required=True)
    x = comps.add_parser("audit")
    x.add_argument("--json", action="store_true")
    x = comps.add_parser("record")
    x.add_argument("plan_id")

    less = sub.add_parser("lessons")
    lesss = less.add_subparsers(dest="lessons_action", required=True)
    x = lesss.add_parser("create")
    x.add_argument("--reason", default="stop")
    lesss.add_parser("status")

    v = sub.add_parser("validate")
    v.add_argument("--adapter")
    v.add_argument("--release", action="store_true")
    v.add_argument("--source-checkout", action="store_true")
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "go":
            return cmd_go(args)
        if args.command == "manifest":
            return cmd_manifest(args)
        if args.command == "config":
            return cmd_config(args)
        if args.command == "scope":
            return cmd_scope(args)
        if args.command == "platform":
            return cmd_platform(args)
        if args.command == "frontier":
            return cmd_frontier(args)
        if args.command == "policy":
            return cmd_policy(args)
        if args.command == "goal":
            return cmd_goal(args)
        if args.command == "score":
            return cmd_score(args)
        if args.command == "queue":
            return cmd_queue(args)
        if args.command == "retry":
            return cmd_retry(args)
        if args.command == "agent":
            return cmd_agent(args)
        if args.command == "outcome":
            return cmd_outcome(args)
        if args.command == "explore":
            return cmd_explore(args)
        if args.command == "compute":
            return cmd_compute(args)
        if args.command == "surface":
            return cmd_surface(args)
        if args.command == "writeup":
            return cmd_writeup(args)
        if args.command == "prepare":
            return cmd_prepare(args)
        if args.command == "reconcile":
            return cmd_reconcile(args)
        if args.command == "ledger":
            return cmd_ledger(args)
        if args.command == "completion":
            return cmd_completion(args)
        if args.command == "lessons":
            return cmd_lessons(args)
        if args.command == "validate":
            return cmd_validate(args)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
