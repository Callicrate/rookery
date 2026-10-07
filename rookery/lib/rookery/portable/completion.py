"""Resolve the only execution chains that may support a completion capsule.

The event ledger is the authority.  Projections and caller supplied capsule
arguments are only convenience data, so this module deliberately reads neither
when deciding whether an objective is solved.
"""

from __future__ import annotations

from typing import Any

from .reconciliation import _admitted_execution_claim
from .store import EventStore
from .telemetry import EXECUTION_TERMINAL_TYPES, _authorization_grant_provenance_valid


def _denied(reason: str) -> dict[str, Any]:
    return {"state": "denied", "reason": reason}


def resolve_canonical_completion(
    store: EventStore, *, objective_id: str, plan_id: str
) -> dict[str, Any]:
    """Resolve one terminal plan as scorer truth or non-scoring evidence.

    ``plan_id`` is intentionally the action reference.  An objective label is
    not a durable execution identity, and it must never select a plan by text
    similarity or by its current projection.

    The reconciliation admission helper already validates the persisted plan,
    exact independent review, authority consumption, and durable start claim.
    This resolver adds the terminal verdict and evidence-root predicate without
    weakening those shared execution checks.
    """

    if not isinstance(objective_id, str) or not objective_id:
        return _denied("completion objective id is required")
    if not isinstance(plan_id, str) or not plan_id:
        return _denied("completion requires an explicit canonical plan id")

    snapshot = store.read_snapshot()
    events = snapshot.get("events")
    if not isinstance(events, list):
        return _denied("canonical completion events are unavailable")
    if not all(
        isinstance(event, dict) and isinstance(event.get("payload"), dict)
        for event in events
    ):
        return _denied("canonical completion events are malformed")

    plans = [
        event
        for event in events
        if event.get("event_type") == "execution.planned"
        and isinstance(event.get("payload"), dict)
        and event["payload"].get("plan_id") == plan_id
    ]
    if len(plans) != 1:
        return _denied("completion plan is not a unique canonical planned execution")
    plan = plans[0]["payload"]
    if plan.get("objective_id") != objective_id:
        return _denied("completion plan does not belong to the requested objective")
    proposal_id = plan.get("proposal_id")
    if not isinstance(proposal_id, str) or not proposal_id:
        return _denied("completion plan has no canonical proposal id")
    projection = store.projection_from_snapshot(snapshot)
    current = projection.get("current")
    if not isinstance(current, dict):
        return _denied("canonical completion projection is unavailable")
    proposal = current.get("proposals", {}).get(proposal_id)
    if not isinstance(proposal, dict):
        return _denied("completion proposal is unavailable")
    try:
        start_claim = _admitted_execution_claim(store, proposal)
    except (KeyError, TypeError, ValueError):
        return _denied("completion execution claim is malformed")
    if (
        not isinstance(start_claim, dict)
        or not isinstance(start_claim.get("payload"), dict)
        or start_claim["payload"].get("plan_id") != plan_id
    ):
        return _denied("completion plan has no canonical authorized start claim")

    predicates = plan.get("predicates")
    action_kind = plan.get("semantic_action")
    envelope = plan.get("envelope")
    if (
        not isinstance(predicates, dict)
        or not isinstance(envelope, dict)
        or not isinstance(action_kind, str)
        or not isinstance(envelope.get("attempt_scope"), dict)
    ):
        return _denied("completion plan authority predicates are malformed")
    authorization_id = predicates.get("authorization_id")
    if action_kind == "no_submit_evidence":
        if authorization_id not in {"", None}:
            return _denied("evidence completion unexpectedly carries authority")
    else:
        if not isinstance(authorization_id, str) or not authorization_id:
            return _denied("completion plan has no authorization predicate")
        consumptions = [
            event
            for event in events
            if event["event_type"] == "authorization.consumed"
            and event["payload"].get("consumed_for_plan") == plan_id
        ]
        if len(consumptions) != 1:
            return _denied("completion plan has no unique authority consumption")
        consumption = consumptions[0]
        if (
            consumption["payload"].get("authorization_id") != authorization_id
            or consumption["payload"].get("action_kind") != action_kind
            or consumption["seq"] >= start_claim["seq"]
            or consumption["seq"] <= plans[0]["seq"]
        ):
            return _denied("completion authority consumption does not match its plan")
        preceding = [
            event
            for event in events
            if event["event_type"] == "authorization.consumed"
            and event["payload"].get("authorization_id") == authorization_id
            and event["seq"] < consumption["seq"]
        ]
        prior_sequence = max((event["seq"] for event in preceding), default=0)
        grants = [
            event
            for event in events
            if event["event_type"] == "authorization.granted"
            and event["payload"].get("authorization_id") == authorization_id
            and prior_sequence < event["seq"] < consumption["seq"]
        ]
        if (
            len(grants) != 1
            or not _authorization_grant_provenance_valid(events, grants[0])
            or grants[0]["payload"].get("action_kind") != action_kind
        ):
            return _denied("completion authorization grant provenance is incomplete")

    terminals = [
        event
        for event in events
        if event.get("event_type") in EXECUTION_TERMINAL_TYPES
        and isinstance(event.get("payload"), dict)
        and event["payload"].get("plan_id") == plan_id
    ]
    if len(terminals) != 1:
        return _denied("completion plan does not have one canonical terminal verdict")
    terminal_event = terminals[0]
    terminal = terminal_event["payload"]
    if (
        terminal.get("objective_id") != objective_id
        or terminal.get("proposal_id") != plan.get("proposal_id")
        or terminal.get("action_kind") != plan.get("semantic_action")
    ):
        return _denied("completion terminal tuple does not match its canonical plan")

    verdict = terminal.get("verdict")
    if not isinstance(verdict, dict):
        return _denied("completion terminal verdict is malformed")
    evidence_root = terminal.get("evidence_root")
    if not isinstance(evidence_root, str) or not evidence_root:
        return _denied("completion terminal has no canonical evidence root")

    if action_kind == "no_submit_evidence":
        if (
            terminal_event.get("event_type") == "execution.completed"
            and terminal.get("status") == "completed"
            and verdict.get("verdict") == "non_scoring"
            and verdict.get("scorer_truth") == "non_scoring"
        ):
            return {
                "state": "evidence",
                "reason": "canonical non-scoring evidence execution",
                "objective_id": objective_id,
                "plan_id": plan_id,
                "action_kind": action_kind,
                "scorer_evidence": evidence_root,
            }
        return _denied("no-submit execution did not produce canonical evidence truth")

    if (
        terminal_event.get("event_type") == "execution.completed"
        and terminal.get("status") == "completed"
        and verdict.get("verdict") in {"accepted", "already-accepted"}
        and verdict.get("scorer_truth") == verdict.get("verdict")
    ):
        return {
            "state": "accepted",
            "reason": "canonical accepted scorer execution",
            "objective_id": objective_id,
            "plan_id": plan_id,
            "action_kind": str(action_kind or ""),
            "scorer_evidence": evidence_root,
            "attempt_scope": dict(envelope["attempt_scope"]),
            "terminal_evidence_path": terminal.get("response_path"),
        }
    return _denied("completion terminal has no accepted canonical scorer truth")


def resolve_canonical_plan_completion(store: EventStore, *, plan_id: str) -> dict[str, Any]:
    """Resolve a plan-selected completion without accepting a caller objective.

    Completion recording accepts only a plan ID.  Its objective is read from
    the unique canonical plan, so a CLI caller cannot pair another objective
    with an accepted terminal.
    """

    if not isinstance(plan_id, str) or not plan_id:
        return _denied("completion requires an explicit canonical plan id")
    snapshot = store.read_snapshot()
    events = snapshot.get("events")
    if not isinstance(events, list):
        return _denied("canonical completion events are unavailable")
    plans = [
        event
        for event in events
        if isinstance(event, dict)
        and event.get("event_type") == "execution.planned"
        and isinstance(event.get("payload"), dict)
        and event["payload"].get("plan_id") == plan_id
    ]
    if len(plans) != 1:
        return _denied("completion plan is not a unique canonical planned execution")
    objective_id = plans[0]["payload"].get("objective_id")
    if not isinstance(objective_id, str) or not objective_id:
        return _denied("completion plan has no canonical objective id")
    return resolve_canonical_completion(
        store, objective_id=objective_id, plan_id=plan_id
    )
