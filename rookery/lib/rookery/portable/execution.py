from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any

from rookery.verdict_parser import exit_code_for_verdict

from .adapters import get_adapter
from .control import mutation_guard
from .intake import solver_eligibility
from .scoring import (
    CHALLENGE_ELIGIBILITY_ERROR,
    TEXT_MUTATION_ACTION_KINDS,
    admission_snapshot_in_transaction,
    available_authorization,
    canonical_plan_for_execution,
    claim_plan_authority,
    lifecycle_from_events,
    manifest_adapter_id,
    mutation_challenge_is_ready,
    proposal_and_review_bind_current_generation,
    terminal_retry_metadata,
)
from .store import EventStore
from .util import atomic_write_json, canonical_json, file_lock, iso_now, sha256_bytes


def _require_current_mutation_challenge(
    root: Path,
    current: dict[str, Any],
    *,
    objective_id: object,
    action_kind: object,
) -> None:
    """Fail closed unless a text mutation still targets verified intake."""

    if action_kind not in TEXT_MUTATION_ACTION_KINDS:
        return
    challenges = current.get("challenges")
    challenge = (
        challenges.get(str(objective_id or ""))
        if isinstance(challenges, dict)
        else None
    )
    if not isinstance(challenge, dict) or not solver_eligibility(root, challenge)[
        "ready"
    ]:
        raise RuntimeError(CHALLENGE_ELIGIBILITY_ERROR)


def _adapter_binding_reason(
    manifest: dict[str, Any],
    plan: dict[str, Any],
    proposal: dict[str, Any],
) -> str:
    """Return a value-free reason when execution no longer names one adapter."""

    try:
        selected_adapter_id = manifest_adapter_id(manifest)
    except ValueError as exc:
        return f"current manifest adapter is invalid: {exc}"
    envelope = plan.get("envelope")
    if not isinstance(envelope, dict):
        return "execution plan envelope is invalid"
    identities = {
        "proposal": proposal.get("adapter_id"),
        "plan": plan.get("adapter_id"),
        "envelope": envelope.get("adapter_id"),
    }
    for label, adapter_id in identities.items():
        if not isinstance(adapter_id, str) or adapter_id != selected_adapter_id:
            return f"{label} adapter does not match the selected manifest adapter"
    return ""


def compile_plan(
    store: EventStore,
    root: Path,
    manifest: dict[str, Any],
    scope: dict[str, Any],
    proposal_id: str,
    *,
    actor: str = "reviewer",
) -> dict[str, Any]:
    projection = store.rebuild()
    proposal = projection["current"]["proposals"].get(proposal_id)
    if not proposal:
        raise KeyError(proposal_id)
    selected_adapter_id = manifest_adapter_id(manifest)
    if proposal.get("adapter_id") != selected_adapter_id:
        raise RuntimeError("proposal adapter does not match the selected manifest adapter")
    _require_current_mutation_challenge(
        root,
        projection["current"],
        objective_id=proposal.get("objective_id"),
        action_kind=proposal.get("action_kind"),
    )
    review = projection["current"]["reviews"].get(proposal_id, {})
    if projection["current"].get("stopped"):
        raise RuntimeError("workspace is stopped; explicit resume is required")
    if review.get("verdict") != "approved":
        raise RuntimeError("proposal is not independently approved")
    if not proposal_and_review_bind_current_generation(
        proposal,
        review,
        stop_generation=int(projection["current"].get("stop_generation", 0) or 0),
        policy_generation=int(projection["current"].get("policy_generation", 0) or 0),
    ):
        raise RuntimeError(
            "proposal or review belongs to a stale generation; "
            "no action-specific authorization is available"
        )
    terminal = next(
        (
            execution
            for execution in projection["current"]["executions"].values()
            if execution.get("proposal_id") == proposal_id
            and execution.get("status")
            in {"started", "completed", "rejected", "indeterminate"}
        ),
        None,
    )
    if terminal:
        raise RuntimeError(
            "durable execution claim requires reconciliation or a new proposal with retry lineage"
        )
    authorization = available_authorization(store, proposal)
    if proposal.get("action_kind") != "no_submit_evidence" and not authorization:
        raise RuntimeError("no action-specific authorization is available")
    stop_generation = store.current_stop_generation()
    plan_id = "plan_" + uuid.uuid4().hex
    stages = [
        {"name": "offline_validate", "mutation": False},
        {"name": "adapter_readonly_preflight", "mutation": False},
        {"name": "freshness_and_scope_check", "mutation": False},
        {"name": "consume_authority", "mutation": True},
        {"name": "adapter_execute", "mutation": True},
        {"name": "record_verdict", "mutation": False},
    ]
    plan = {
        "schema_version": "1",
        "plan_id": plan_id,
        "generation": stop_generation,
        "policy_generation": int(store.get_meta("policy_generation", "0")),
        "adapter_id": proposal.get("adapter_id"),
        "objective_id": proposal.get("objective_id"),
        "proposal_id": proposal_id,
        "semantic_action": proposal.get("action_kind"),
        "envelope": {
            "objective_id": proposal.get("objective_id"),
            "action_kind": proposal.get("action_kind"),
            "exact_value": proposal.get("exact_value", ""),
            "artifact_reference": proposal.get("artifact_reference", ""),
            "attempt_scope": proposal.get("attempt_scope", {}),
            "adapter_id": proposal.get("adapter_id"),
            "policy_generation": proposal.get("policy_generation"),
            "freshness_requirements": proposal.get("freshness_requirements", {}),
            "proposal_id": proposal_id,
        },
        "stages": stages,
        "predicates": {
            "proposal_event_id": proposal.get("event_id"),
            "review_event_id": review.get("event_id"),
            "authorization_id": authorization.get("authorization_id")
            if authorization
            else "",
            "scope_generation": scope.get("generation"),
            "attempt_scope": proposal.get("attempt_scope", {}),
        },
        "evidence_paths": list(
            filter(
                None,
                [
                    proposal.get("source"),
                    review.get("verifier_report"),
                    proposal.get("artifact_reference"),
                ],
            )
        ),
        "success_conditions": [
            "structured scorer verdict accepted or already-accepted",
            "all request/response artifacts preserved",
        ],
        "recovery": {
            "on_reject": "record rejection and near-miss context",
            "on_auth": "block-by-auth without consuming another action",
            "on_stale": "compile a fresh plan",
        },
        "lifecycle_refs": proposal.get("attempt_scope", {}),
        "created_at": iso_now(),
    }
    plan["plan_sha256"] = sha256_bytes(canonical_json(plan).encode("utf-8"))
    path = root / "state" / "execution_plans" / f"{plan_id}.json"
    binding_reason = _adapter_binding_reason(manifest, plan, proposal)
    if binding_reason:
        raise RuntimeError(binding_reason)
    with file_lock(root / "state" / "mutation.lock"):
        _append_plan_if_admissible(
            store,
            plan,
            manifest=manifest,
            path=path,
            actor=actor,
        )
        store.rebuild()
        # The JSON plan is a derived convenience copy. Publish it only after the
        # canonical event and projections succeed, while stop remains excluded.
        atomic_write_json(path, plan)
    return plan


def _append_plan_if_admissible(
    store: EventStore,
    plan: dict[str, Any],
    *,
    manifest: dict[str, Any],
    path: Path,
    actor: str,
) -> None:
    """Persist one plan only if its complete authority tuple is still current."""

    plan_id = str(plan.get("plan_id") or "")
    proposal_id = str(plan.get("proposal_id") or "")
    predicates = plan.get("predicates", {})
    if not plan_id or not proposal_id or not isinstance(predicates, dict):
        raise RuntimeError("execution plan is missing immutable authority predicates")

    def tx(con: Any) -> None:
        snapshot = admission_snapshot_in_transaction(con)
        if snapshot["stopped"]:
            raise RuntimeError("workspace is stopped; explicit resume is required")
        meta = snapshot["meta"]
        stop_generation = meta.get("stop_generation", 0)
        policy_generation = meta.get("policy_generation", 0)
        scope_generation = meta.get(
            "scope_generation", int(predicates.get("scope_generation", -1))
        )
        if int(plan.get("generation", -1)) != stop_generation:
            raise RuntimeError("stop generation changed before plan compilation")
        if int(plan.get("policy_generation", -1)) != policy_generation:
            raise RuntimeError("policy generation changed before plan compilation")
        if int(predicates.get("scope_generation", -1)) != scope_generation:
            raise RuntimeError("scope generation changed before plan compilation")
        proposals = [
            event
            for event in snapshot["events"]
            if event["event_type"] == "proposal.created"
            and str(event["payload"].get("proposal_id") or "") == proposal_id
        ]
        if len(proposals) != 1 or proposals[0]["event_id"] != str(
            predicates.get("proposal_event_id") or ""
        ):
            raise RuntimeError("plan proposal predicate is no longer canonical")
        proposal = proposals[0]["payload"]
        binding_reason = _adapter_binding_reason(manifest, plan, proposal)
        if binding_reason:
            raise RuntimeError(binding_reason)
        reviews = [
            event
            for event in snapshot["events"]
            if event["event_type"] == "review.recorded"
            and str(event["payload"].get("proposal_id") or "") == proposal_id
        ]
        review = reviews[-1] if reviews else None
        if (
            review is None
            or review["event_id"] != str(predicates.get("review_event_id") or "")
            or review["payload"].get("verdict") != "approved"
            or not proposal_and_review_bind_current_generation(
                proposal,
                review["payload"],
                stop_generation=stop_generation,
                policy_generation=policy_generation,
            )
        ):
            raise RuntimeError("plan review predicate is no longer the latest approval")
        if (
            str(plan.get("objective_id") or "")
            != str(proposal.get("objective_id") or "")
            or str(plan.get("semantic_action") or "")
            != str(proposal.get("action_kind") or "")
            or str(plan.get("adapter_id") or "")
            != str(proposal.get("adapter_id") or "")
            or not isinstance(plan.get("envelope"), dict)
            or str(plan["envelope"].get("adapter_id") or "")
            != str(proposal.get("adapter_id") or "")
            or canonical_json(plan.get("envelope", {}).get("attempt_scope", {}))
            != canonical_json(proposal.get("attempt_scope", {}))
            or canonical_json(plan.get("lifecycle_refs", {}))
            != canonical_json(proposal.get("attempt_scope", {}))
        ):
            raise RuntimeError("plan lifecycle or proposal tuple changed before compilation")
        current_lifecycle = lifecycle_from_events(
            snapshot["events"], str(proposal.get("objective_id") or "")
        )
        if (
            plan.get("lifecycle_refs")
            and current_lifecycle
            and canonical_json(plan["lifecycle_refs"])
            != canonical_json(current_lifecycle)
        ):
            raise RuntimeError("lifecycle state changed before plan compilation")
        if not mutation_challenge_is_ready(
            store.root,
            snapshot["events"],
            objective_id=proposal.get("objective_id"),
            action_kind=proposal.get("action_kind"),
        ):
            raise RuntimeError(CHALLENGE_ELIGIBILITY_ERROR)
        started = any(
            event["event_type"]
            in {
                "execution.started",
                "execution.completed",
                "execution.rejected",
                "execution.indeterminate",
            }
            and str(event["payload"].get("proposal_id") or "") == proposal_id
            for event in snapshot["events"]
        )
        if started:
            raise RuntimeError(
                "durable execution claim requires reconciliation or a new proposal with retry lineage"
            )
        authorization_id = str(predicates.get("authorization_id") or "")
        if plan.get("semantic_action") == "no_submit_evidence":
            if authorization_id:
                raise RuntimeError("no-submit evidence plan must not carry authorization")
        else:
            authorization = None
            authorization_type = ""
            for event in snapshot["events"]:
                if (
                    event["event_type"].startswith("authorization.")
                    and str(event["payload"].get("authorization_id") or "")
                    == authorization_id
                ):
                    authorization = event["payload"]
                    authorization_type = event["event_type"]
            if authorization_type != "authorization.granted" or authorization is None:
                raise RuntimeError("plan authorization predicate is unavailable")
            if (
                int(authorization.get("remaining", 0) or 0) <= 0
                or int(authorization.get("stop_generation", -1)) != stop_generation
                or int(authorization.get("policy_generation", -1)) != policy_generation
                or str(authorization.get("action_kind") or "")
                != str(plan.get("semantic_action") or "")
                or (
                    authorization.get("mode") == "exact"
                    and str(authorization.get("proposal_id") or "") != proposal_id
                )
            ):
                raise RuntimeError("plan authorization predicate is stale or unavailable")
        # Store.transaction verifies the launch binding at BEGIN IMMEDIATE, but
        # the admission snapshot above can be long enough for editable launch
        # configuration to drift. Revalidate immediately before publishing the
        # canonical plan event so this transaction rolls back cleanly.
        store._verify_mutation_integrity(con)
        store.insert_in_transaction(
            con,
            "execution.planned",
            {**plan, "plan_path": str(path.relative_to(store.root))},
            actor=actor,
            generation=stop_generation,
        )

    store.transaction(tx)


def _latest_lifecycle(store: EventStore, objective_id: str) -> dict[str, Any]:
    projection = store.rebuild()
    challenge = projection["current"]["challenges"].get(str(objective_id), {})
    return challenge.get("attempt_scope", challenge.get("session_scope", {})) or {}


def _canonical_plan_for_missing_file(store: EventStore, plan_id: str) -> dict[str, Any]:
    """Recover a missing derived plan from its sole canonical event record."""

    records = [
        dict(event["payload"])
        for event in store.events("execution.planned")
        if str(event["payload"].get("plan_id") or "") == plan_id
    ]
    if len(records) != 1:
        raise RuntimeError(
            "execution plan file is unavailable and has no unique canonical planned record"
        )
    plan = records[0]
    plan_path = str(plan.pop("plan_path", "")).replace("\\", "/")
    if plan_path != f"state/execution_plans/{plan_id}.json":
        raise RuntimeError("canonical execution plan path does not match plan id")
    if str(plan.get("plan_id") or "") != plan_id:
        raise RuntimeError("canonical execution plan identifier is invalid")
    expected_sha256 = str(plan.get("plan_sha256") or "")
    actual_sha256 = sha256_bytes(
        canonical_json(
            {key: value for key, value in plan.items() if key != "plan_sha256"}
        ).encode("utf-8")
    )
    if not expected_sha256 or expected_sha256 != actual_sha256:
        raise RuntimeError("canonical execution plan integrity check failed")
    return plan


def _retry_metadata(
    plan: dict[str, Any],
    proposal: dict[str, Any],
    verdict: dict[str, Any],
    *,
    terminal_state: str,
) -> dict[str, str]:
    return terminal_retry_metadata(
        plan, proposal, verdict, terminal_state=terminal_state
    )


def _record_indeterminate(
    store: EventStore,
    root: Path,
    plan: dict[str, Any],
    *,
    reason: str,
    actor: str,
    evidence_root: Path | None = None,
    verdict: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], int]:
    projection = store.rebuild()
    proposal = projection["current"]["proposals"].get(plan["proposal_id"], {})
    resolved_verdict = verdict or {"verdict": "unknown", "reason": reason}
    payload = {
        "plan_id": plan["plan_id"],
        "proposal_id": plan["proposal_id"],
        "objective_id": plan["objective_id"],
        "action_kind": plan["semantic_action"],
        "status": "indeterminate",
        "reason": reason,
        "verdict": resolved_verdict,
        "evidence_root": (
            str(evidence_root.relative_to(root)) if evidence_root is not None else ""
        ),
        "completed_at": iso_now(),
    }
    payload["retry"] = _retry_metadata(
        plan, proposal, resolved_verdict, terminal_state="indeterminate"
    )
    store.append("execution.indeterminate", payload, actor=actor)
    store.rebuild()
    return payload, 2


def _revalidate_volatile_predicates(
    store: EventStore,
    scope: dict[str, Any],
    plan: dict[str, Any],
) -> dict[str, Any]:
    """Check every mutable plan predicate immediately before adapter dispatch."""

    mutation_guard(store, int(plan["generation"]))
    predicates = plan.get("predicates", {})
    if int(plan.get("policy_generation", -1)) != int(
        store.get_meta("policy_generation", "0")
    ):
        raise RuntimeError("policy generation changed before adapter dispatch")
    current_scope_generation = int(
        store.get_meta("scope_generation", str(scope.get("generation", 0)))
    )
    if int(predicates.get("scope_generation", -1)) != current_scope_generation:
        raise RuntimeError("scope generation changed before adapter dispatch")
    latest_lifecycle = _latest_lifecycle(store, str(plan["objective_id"]))
    if (
        plan.get("lifecycle_refs")
        and latest_lifecycle
        and plan["lifecycle_refs"] != latest_lifecycle
    ):
        raise RuntimeError("lifecycle state changed before adapter dispatch")
    projection = store.rebuild()
    proposal = projection["current"]["proposals"].get(plan["proposal_id"])
    if not proposal:
        raise RuntimeError("proposal is unavailable before adapter dispatch")
    _require_current_mutation_challenge(
        store.root,
        projection["current"],
        objective_id=proposal.get("objective_id"),
        action_kind=proposal.get("action_kind"),
    )
    review = projection["current"]["reviews"].get(plan["proposal_id"], {})
    if (
        review.get("verdict") != "approved"
        or str(review.get("event_id") or "")
        != str(predicates.get("review_event_id") or "")
    ):
        raise RuntimeError("review changed or is no longer approved before adapter dispatch")
    plan_id = str(plan["plan_id"])
    review_event_id = str(predicates.get("review_event_id") or "")
    authorization_id = str(predicates.get("authorization_id") or "")
    starts = [
        event["payload"]
        for event in store.events("execution.started")
        if str(event["payload"].get("plan_id") or "") == plan_id
    ]
    if len(starts) != 1:
        raise RuntimeError("durable execution start claim is unavailable")
    start = starts[0]
    if (
        str(start.get("proposal_id") or "") != str(plan["proposal_id"])
        or str(start.get("review_event_id") or "") != review_event_id
        or str(start.get("authorization_id") or "") != authorization_id
    ):
        raise RuntimeError("durable execution start claim does not match plan predicates")
    if plan.get("semantic_action") != "no_submit_evidence":
        consumptions = [
            event["payload"]
            for event in store.events("authorization.consumed")
            if str(event["payload"].get("consumed_for_plan") or "") == plan_id
        ]
        if len(consumptions) != 1 or str(
            consumptions[0].get("authorization_id") or ""
        ) != authorization_id:
            raise RuntimeError(
                "durable authorization consumption does not match plan predicate"
            )
    return proposal


def _execute_plan_locked(
    store: EventStore,
    root: Path,
    manifest: dict[str, Any],
    scope: dict[str, Any],
    plan_id: str,
    *,
    actor: str = "executor",
) -> tuple[dict[str, Any], int]:
    projection = store.rebuild()
    prior = projection["current"]["executions"].get(plan_id)
    if prior and prior.get("status") in {
        "completed",
        "rejected",
        "indeterminate",
        "failed",
    }:
        return {
            "idempotent": True,
            "status": prior.get("status"),
            "verdict": prior.get("verdict", {}),
            "plan_id": plan_id,
        }, exit_code_for_verdict(
            str(prior.get("verdict", {}).get("verdict", "unknown"))
        )
    if prior and prior.get("status") == "started":
        return {
            "idempotent": True,
            "status": "in_progress",
            "plan_id": plan_id,
            "reason": "execution plan already has a durable start claim",
        }, 2
    path = root / "state" / "execution_plans" / f"{plan_id}.json"
    recovered_from_canonical = False
    try:
        plan = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        try:
            plan = _canonical_plan_for_missing_file(store, plan_id)
            recovered_from_canonical = True
        except RuntimeError as exc:
            reason = str(exc)
            store.append(
                "execution.blocked", {"plan_id": plan_id, "reason": reason}, actor=actor
            )
            store.rebuild()
            return {"status": "blocked", "reason": reason, "plan_id": plan_id}, 2
    except (OSError, json.JSONDecodeError) as exc:
        reason = f"execution plan file is unavailable or invalid: {exc}"
        store.append(
            "execution.blocked", {"plan_id": plan_id, "reason": reason}, actor=actor
        )
        store.rebuild()
        return {"status": "blocked", "reason": reason, "plan_id": plan_id}, 2
    if not isinstance(plan, dict):
        reason = "execution plan file is invalid: expected a JSON object"
        store.append(
            "execution.blocked", {"plan_id": plan_id, "reason": reason}, actor=actor
        )
        store.rebuild()
        return {"status": "blocked", "reason": reason, "plan_id": plan_id}, 2
    if plan.get("plan_sha256") != sha256_bytes(
        canonical_json({k: v for k, v in plan.items() if k != "plan_sha256"}).encode(
            "utf-8"
        )
    ):
        reason = "execution plan integrity check failed"
        store.append(
            "execution.blocked",
            {
                "plan_id": plan_id,
                "proposal_id": plan.get("proposal_id", ""),
                "reason": reason,
            },
            actor=actor,
        )
        store.rebuild()
        return {"status": "blocked", "reason": reason, "plan_id": plan_id}, 2
    loaded_plan = plan
    if not recovered_from_canonical:
        try:
            # The on-disk plan is mutable evidence, not dispatch authority.  Reject
            # it before adapter preflight unless it exactly matches its sole
            # canonical SQLite execution.planned record.
            plan = canonical_plan_for_execution(store, loaded_plan)
        except RuntimeError as exc:
            reason = str(exc)
            store.append(
                "execution.blocked",
                {
                    "plan_id": plan_id,
                    "proposal_id": loaded_plan.get("proposal_id", ""),
                    "reason": reason,
                },
                actor=actor,
            )
            store.rebuild()
            return {"status": "blocked", "reason": reason, "plan_id": plan_id}, 2
    try:
        mutation_guard(store, int(plan["generation"]))
    except RuntimeError as exc:
        return {"status": "blocked", "reason": str(exc), "plan_id": plan_id}, 2
    envelope = plan["envelope"]
    current_policy_generation = int(store.get_meta("policy_generation", "0"))
    if int(plan.get("policy_generation", -1)) != current_policy_generation:
        store.append(
            "execution.blocked",
            {
                "plan_id": plan_id,
                "proposal_id": plan["proposal_id"],
                "reason": "policy generation changed",
                "planned": plan.get("policy_generation"),
                "current": current_policy_generation,
            },
            actor=actor,
        )
        store.rebuild()
        return {
            "status": "blocked",
            "reason": "policy generation changed",
            "plan_id": plan_id,
        }, 2
    current_scope_generation = int(
        store.get_meta("scope_generation", str(scope.get("generation", 0)))
    )
    if (
        int(plan.get("predicates", {}).get("scope_generation", -1))
        != current_scope_generation
    ):
        store.append(
            "execution.blocked",
            {
                "plan_id": plan_id,
                "proposal_id": plan["proposal_id"],
                "reason": "scope generation changed",
                "planned": plan.get("predicates", {}).get("scope_generation"),
                "current": current_scope_generation,
            },
            actor=actor,
        )
        store.rebuild()
        return {
            "status": "blocked",
            "reason": "scope generation changed",
            "plan_id": plan_id,
        }, 2
    latest = _latest_lifecycle(store, str(plan["objective_id"]))
    planned_lifecycle = plan.get("lifecycle_refs", {})
    if planned_lifecycle and latest and planned_lifecycle != latest:
        store.append(
            "execution.blocked",
            {
                "plan_id": plan_id,
                "proposal_id": plan["proposal_id"],
                "reason": "lifecycle state changed",
                "planned": planned_lifecycle,
                "current": latest,
            },
            actor=actor,
        )
        store.rebuild()
        return {
            "status": "blocked",
            "reason": "lifecycle state changed",
            "plan_id": plan_id,
        }, 2
    if envelope.get("action_kind") == "no_submit_evidence":
        try:
            claim_plan_authority(store, plan, loaded_plan=loaded_plan, actor=actor)
        except RuntimeError as exc:
            reason = str(exc)
            store.append(
                "execution.blocked",
                {
                    "plan_id": plan_id,
                    "proposal_id": plan["proposal_id"],
                    "reason": reason,
                },
                actor=actor,
            )
            store.rebuild()
            return {"status": "blocked", "reason": reason, "plan_id": plan_id}, 2
        payload = {
            "plan_id": plan_id,
            "proposal_id": plan["proposal_id"],
            "objective_id": plan["objective_id"],
            "action_kind": plan["semantic_action"],
            "status": "completed",
            "verdict": {
                "verdict": "non_scoring",
                "scorer_truth": "non_scoring",
                "transport_truth": "not-applicable",
                "reason": "evidence recorded without mutation",
            },
            "response_path": "",
            "evidence_root": envelope.get("artifact_reference", ""),
            "completed_at": iso_now(),
        }
        store.append("execution.completed", payload, actor=actor)
        store.rebuild()
        return payload, 0
    projection = store.rebuild()
    proposal = projection["current"]["proposals"].get(plan["proposal_id"])
    if not proposal:
        reason = "proposal is unavailable before adapter preflight"
        store.append(
            "execution.blocked",
            {"plan_id": plan_id, "proposal_id": plan["proposal_id"], "reason": reason},
            actor=actor,
        )
        store.rebuild()
        return {"status": "blocked", "reason": reason, "plan_id": plan_id}, 2
    binding_reason = _adapter_binding_reason(manifest, plan, proposal)
    if binding_reason:
        store.append(
            "execution.blocked",
            {
                "plan_id": plan_id,
                "proposal_id": plan["proposal_id"],
                "reason": binding_reason,
            },
            actor=actor,
        )
        store.rebuild()
        return {"status": "blocked", "reason": binding_reason, "plan_id": plan_id}, 2
    try:
        _require_current_mutation_challenge(
            root,
            projection["current"],
            objective_id=proposal.get("objective_id"),
            action_kind=proposal.get("action_kind"),
        )
    except RuntimeError as exc:
        reason = str(exc)
        store.append(
            "execution.blocked",
            {"plan_id": plan_id, "proposal_id": plan["proposal_id"], "reason": reason},
            actor=actor,
        )
        store.rebuild()
        return {"status": "blocked", "reason": reason, "plan_id": plan_id}, 2
    adapter = get_adapter(root, manifest, scope)
    preflight = adapter.preflight_action(envelope)
    if not preflight.get("ok"):
        store.append(
            "execution.blocked",
            {
                "plan_id": plan_id,
                "proposal_id": plan["proposal_id"],
                "reason": preflight.get("reason", "preflight failed"),
            },
            actor=actor,
        )
        store.rebuild()
        return {
            "status": "blocked",
            "reason": preflight.get("reason"),
            "plan_id": plan_id,
        }, 2
    try:
        mutation_guard(store, int(plan["generation"]))
    except RuntimeError as exc:
        store.append(
            "execution.blocked",
            {
                "plan_id": plan_id,
                "proposal_id": plan["proposal_id"],
                "reason": str(exc),
            },
            actor=actor,
        )
        store.rebuild()
        return {"status": "blocked", "reason": str(exc), "plan_id": plan_id}, 2
    projection = store.rebuild()
    proposal = projection["current"]["proposals"].get(plan["proposal_id"])
    if not proposal:
        reason = "proposal is unavailable at mutation boundary"
        store.append(
            "execution.blocked",
            {"plan_id": plan_id, "proposal_id": plan["proposal_id"], "reason": reason},
            actor=actor,
        )
        store.rebuild()
        return {"status": "blocked", "reason": reason, "plan_id": plan_id}, 2
    binding_reason = _adapter_binding_reason(manifest, plan, proposal)
    if binding_reason:
        store.append(
            "execution.blocked",
            {
                "plan_id": plan_id,
                "proposal_id": plan["proposal_id"],
                "reason": binding_reason,
            },
            actor=actor,
        )
        store.rebuild()
        return {"status": "blocked", "reason": binding_reason, "plan_id": plan_id}, 2
    try:
        _require_current_mutation_challenge(
            root,
            projection["current"],
            objective_id=proposal.get("objective_id"),
            action_kind=proposal.get("action_kind"),
        )
    except RuntimeError as exc:
        reason = str(exc)
        store.append(
            "execution.blocked",
            {"plan_id": plan_id, "proposal_id": plan["proposal_id"], "reason": reason},
            actor=actor,
        )
        store.rebuild()
        return {"status": "blocked", "reason": reason, "plan_id": plan_id}, 2
    try:
        claim_plan_authority(store, plan, loaded_plan=loaded_plan, actor=actor)
    except RuntimeError as exc:
        store.append(
            "execution.blocked",
            {
                "plan_id": plan_id,
                "proposal_id": plan["proposal_id"],
                "reason": str(exc),
            },
            actor=actor,
        )
        store.rebuild()
        return {"status": "blocked", "reason": str(exc), "plan_id": plan_id}, 2
    try:
        # A durable start claim exists. Recheck every volatile predicate just
        # before the adapter can perform an external mutation.
        proposal = _revalidate_volatile_predicates(store, scope, plan)
    except RuntimeError as exc:
        return _record_indeterminate(
            store,
            root,
            plan,
            reason=str(exc),
            actor=actor,
        )
    binding_reason = _adapter_binding_reason(manifest, plan, proposal)
    if binding_reason:
        return _record_indeterminate(
            store,
            root,
            plan,
            reason=binding_reason,
            actor=actor,
        )
    evidence_root = root / "submissions" / "executions" / plan_id
    try:
        result = adapter.execute_action(envelope, evidence_root)
    except Exception as exc:
        return _record_indeterminate(
            store,
            root,
            plan,
            reason=str(exc),
            actor=actor,
            evidence_root=evidence_root,
        )
    if not isinstance(result, dict):
        return _record_indeterminate(
            store,
            root,
            plan,
            reason="adapter returned an invalid execution result",
            actor=actor,
            evidence_root=evidence_root,
        )
    verdict = result.get("verdict", {})
    if not isinstance(verdict, dict):
        return _record_indeterminate(
            store,
            root,
            plan,
            reason="adapter returned an invalid verdict",
            actor=actor,
            evidence_root=evidence_root,
        )
    if verdict.get("verdict") in {"accepted", "already-accepted"}:
        state = "completed"
    elif verdict.get("verdict") == "rejected":
        state = "rejected"
    else:
        state = "indeterminate"
    payload = {
        "plan_id": plan_id,
        "proposal_id": plan["proposal_id"],
        "objective_id": plan["objective_id"],
        "action_kind": plan["semantic_action"],
        "status": state,
        "verdict": verdict,
        "response_path": result.get("response_path", ""),
        "evidence_root": str(evidence_root.relative_to(root)),
        "completed_at": iso_now(),
    }
    if state in {"rejected", "indeterminate"}:
        retry = _retry_metadata(plan, proposal, verdict, terminal_state=state)
        payload["retry"] = retry
        if state == "rejected":
            payload["rejection"] = retry
    store.append(f"execution.{state}", payload, actor=actor)
    store.rebuild()
    return payload, exit_code_for_verdict(str(verdict.get("verdict", "unknown")))


def execute_plan(
    store: EventStore,
    root: Path,
    manifest: dict[str, Any],
    scope: dict[str, Any],
    plan_id: str,
    *,
    actor: str = "executor",
) -> tuple[dict[str, Any], int]:
    """Execute one plan under the workspace mutation linearization barrier."""

    with file_lock(root / "state" / "mutation.lock"):
        return _execute_plan_locked(
            store,
            root,
            manifest,
            scope,
            plan_id,
            actor=actor,
        )
