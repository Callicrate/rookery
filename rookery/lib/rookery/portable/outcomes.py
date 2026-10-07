from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import uuid
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

from .intake import solver_eligibility
from .reducers import canonical_challenges
from .store import EventStore
from .util import contained_private_path, file_lock, iso_now


MAX_HARVEST_REPORT_BYTES = 8 * 1024 * 1024
_REPORT_HASH_BLOCK_BYTES = 64 * 1024
SHA256 = re.compile(r"[0-9a-f]{64}\Z")

LOW_PROGRESS_OUTCOME_TYPES = frozenset(
    {"technical_negative", "incomplete_evidence", "duplicate_trace", "no_progress"}
)
CONTINUATION_KINDS = frozenset(
    {"assignment", "retry", "proposal", "explore", "boundary"}
)
_TERMINAL_EXECUTION_TYPES = frozenset(
    {
        "execution.completed",
        "execution.rejected",
        "execution.blocked",
        "execution.failed",
        "execution.indeterminate",
    }
)

OUTCOME_TYPES = {
    "supported_finding",
    "technical_negative",
    "incomplete_evidence",
    "generic_refusal",
    "capacity_failure",
    "environment_failure",
    "duplicate_trace",
    "invalid_scope",
    "candidate",
    "no_progress",
    "other",
}

TRANSITIONS = {
    "supported_finding": "advance_or_verify",
    "technical_negative": "record_and_change_method",
    "incomplete_evidence": "park_or_narrow",
    "generic_refusal": "requeue_shorter_ctf_context",
    "capacity_failure": "requeue_default_worker",
    "environment_failure": "repair_environment_or_reassign",
    "duplicate_trace": "require_discriminating_test",
    "invalid_scope": "close_lane_and_notify_coordinator",
    "candidate": "independent_verification",
    "no_progress": "record_negative_and_rotate",
    "other": "coordinator_review",
}


_ACTIVE_ATTEMPT_STATES = {"assigned", "running", "stopping"}
_HANDOFF_PLACEHOLDERS = frozenset({"", "none", "n/a", "na", "tbd", "todo", "no evidence"})
_SUBSTANTIVE_OUTCOME_TYPES = OUTCOME_TYPES - {
    "generic_refusal",
    "capacity_failure",
    "environment_failure",
}
_HANDOFF_LABELS = {
    "Status": "status",
    "Source handoff": "source_handoff_id",
    "Source report SHA-256": "source_report_sha256",
    "Observed result": "observed_result",
    "Route key": "route_key",
    "Proof gap": "proof_gap",
    "Discriminating test": "discriminating_test",
    "Next step or return trigger": "next_step_or_return_trigger",
    "Evidence paths": "evidence_paths",
    "Command/artifact paths": "command_artifact_paths",
    "Blocker": "blocker",
    "Cleanup/jobs": "cleanup_jobs",
}
_HANDOFF_ARTIFACT_ROOTS = frozenset(
    {"analysis", "evidence", "work", "exploit", "captures", "downloads"}
)


def _required_identifier(value: str, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be a non-empty string")
    return value


def _bounded_one_line(value: Any, label: str, *, maximum: int = 4096) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or value != value.strip()
        or len(value) > maximum
        or "\n" in value
        or "\r" in value
    ):
        raise ValueError(f"{label} must be a non-empty bounded one-line value")
    return value


def _assignment_packet(
    registration: dict[str, Any],
    *,
    source_handoff: dict[str, Any] | None,
    generation: int,
) -> dict[str, Any]:
    """Bind one dispatched attempt to its exact current purpose and source."""

    packet = {
        "schema_version": "1",
        "agent_id": str(registration["agent_id"]),
        "agent_attempt_id": str(registration["agent_attempt_id"]),
        "objective_id": str(registration["objective_id"]),
        "challenge_id": str(registration.get("challenge_id") or ""),
        "event_wide": registration.get("event_wide") is True,
        "role": str(registration["role"]),
        "parent_agent_attempt_id": str(
            registration.get("parent_agent_attempt_id") or ""
        ),
        "agent_depth": int(registration["agent_depth"]),
        "goal": str(registration["goal"]),
        "scope": str(registration["scope"]),
        "stop_condition": str(registration["stop_condition"]),
        "report_path": str(registration.get("report_path") or ""),
        "stop_generation": generation,
        "source_handoff_id": "none"
        if source_handoff is None
        else str(source_handoff["handoff_id"]),
        "source_report_path": ""
        if source_handoff is None
        else str(source_handoff["report_path"]),
        "source_report_sha256": "none"
        if source_handoff is None
        else str(source_handoff["sha256"]),
        "source_observed_result": ""
        if source_handoff is None
        else str(source_handoff["observed_result"]),
        "source_route_key": ""
        if source_handoff is None
        else str(source_handoff["route_key"]),
        "source_proof_gap": ""
        if source_handoff is None
        else str(source_handoff["proof_gap"]),
        "source_next_step_or_return_trigger": ""
        if source_handoff is None
        else str(source_handoff["next_step_or_return_trigger"]),
    }
    packet["sha256"] = hashlib.sha256(
        json.dumps(packet, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return packet


def parse_continuation_reference(value: str) -> tuple[str, str]:
    """Parse the public ``kind:identifier`` continuation reference."""

    if not isinstance(value, str) or not value or len(value) > 1024:
        raise ValueError("continuation must be a bounded kind:identifier value")
    kind, separator, identifier = value.partition(":")
    if separator != ":" or kind not in CONTINUATION_KINDS or not identifier:
        allowed = ", ".join(sorted(CONTINUATION_KINDS))
        raise ValueError(f"continuation must use one of: {allowed}")
    if len(identifier) > 512 or identifier != identifier.strip():
        raise ValueError("continuation identifier is invalid")
    return kind, identifier


def _events_in_transaction(con: Any) -> list[dict[str, Any]]:
    rows = con.execute(
        "SELECT seq,event_id,event_type,created_at,generation,actor,payload_json "
        "FROM events ORDER BY seq"
    ).fetchall()
    return [
        {
            "seq": int(row["seq"]),
            "event_id": str(row["event_id"]),
            "event_type": str(row["event_type"]),
            "created_at": str(row["created_at"]),
            "generation": int(row["generation"]),
            "actor": str(row["actor"]),
            "payload": json.loads(str(row["payload_json"])),
        }
        for row in rows
    ]


def _event_generation(event: dict[str, Any]) -> int:
    value = event.get("generation", event.get("payload", {}).get("stop_generation", -1))
    return int(value) if isinstance(value, int) and not isinstance(value, bool) else -1


def _canonical_challenges(events: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Return the reducer's canonical challenge projection for admission.

    Sparse platform inventory rows must not overwrite the verified detail and
    capture state that ``reduce_events`` intentionally preserves.  Using that
    exact projection keeps attempt registration aligned with every other
    dispatch gate instead of carrying a second merge contract here.
    """

    return canonical_challenges(events)


def _challenge_is_solved(challenge: dict[str, Any]) -> bool:
    return challenge.get("classification") == "solved" or challenge.get("solved") is True


def _validate_work_item(
    registration: dict[str, Any], events: list[dict[str, Any]], *, root: Path
) -> tuple[str, bool]:
    challenge_id = str(registration.get("challenge_id") or "")
    event_wide = registration.get("event_wide") is True
    if bool(challenge_id) == event_wide:
        raise ValueError(
            "agent registration requires exactly one of challenge_id or event_wide"
        )
    if challenge_id:
        if str(registration.get("objective_id") or "") != challenge_id:
            raise ValueError(
                "challenge-linked agent objective_id must equal challenge_id"
            )
        challenge = _canonical_challenges(events).get(challenge_id)
        if challenge is None:
            raise ValueError("agent registration challenge is not currently canonical")
        if not solver_eligibility(root, challenge)["ready"]:
            raise ValueError("challenge intake is not solver-ready")
    return challenge_id, event_wide


def _workspace_is_stopped(events: list[dict[str, Any]]) -> bool:
    """Return the current control state without trusting a derived projection."""

    stopped = False
    for event in events:
        if event["event_type"] == "control.stop":
            stopped = True
        elif event["event_type"] == "control.resume":
            stopped = False
    return stopped


def _latest_registered_attempts(
    events: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Map each display agent to its latest canonical registration event."""

    registrations: dict[str, dict[str, Any]] = {}
    for event in events:
        if event["event_type"] != "agent.running":
            continue
        agent_id = str(event["payload"].get("agent_id") or "")
        attempt_id = str(event["payload"].get("agent_attempt_id") or "")
        if agent_id and attempt_id:
            registrations[agent_id] = event
    return registrations


def _active_agent_displays(events: list[dict[str, Any]]) -> set[str]:
    """Return active display IDs without treating rejections as attempt state."""

    latest_registered = _latest_registered_attempts(events)
    latest_raw: dict[str, dict[str, Any]] = {}
    for event in events:
        if event["event_type"].startswith("agent."):
            agent_id = str(event["payload"].get("agent_id") or "")
            if agent_id:
                latest_raw[agent_id] = event

    active: set[str] = set()
    for agent_id, registration in latest_registered.items():
        attempt_id = str(registration["payload"]["agent_attempt_id"])
        _, _, latest_type = _attempt_state(events, attempt_id)
        if latest_type.rsplit(".", 1)[-1] in _ACTIVE_ATTEMPT_STATES:
            active.add(agent_id)
    for agent_id, event in latest_raw.items():
        registration = latest_registered.get(agent_id)
        if registration and event["seq"] <= registration["seq"]:
            continue
        if (
            str(event["payload"].get("agent_attempt_id") or "")
            and event["event_type"] != "agent.running"
        ):
            continue
        if event["event_type"].rsplit(".", 1)[-1] in _ACTIVE_ATTEMPT_STATES:
            active.add(agent_id)
    return active


def register_agent_attempt(
    store: EventStore,
    registration: dict[str, Any],
    *,
    max_workers: int,
    actor: str = "coordinator",
) -> dict[str, Any]:
    """Atomically admit one unique, currently inactive display-agent attempt."""

    agent_id = _required_identifier(registration.get("agent_id"), "agent_id")
    agent_attempt_id = _required_identifier(
        registration.get("agent_attempt_id"), "agent_attempt_id"
    )
    objective_id = _required_identifier(
        registration.get("objective_id"), "objective_id"
    )
    role = _bounded_one_line(registration.get("role"), "role", maximum=256)
    if role in {"challenge_coordinator", "ctf_autopilot_coordinator"}:
        role = "challenge-coordinator"
    parent_agent_attempt_id = str(
        registration.get("parent_agent_attempt_id") or ""
    )
    if parent_agent_attempt_id:
        parent_agent_attempt_id = _required_identifier(
            parent_agent_attempt_id, "parent_agent_attempt_id"
        )
    if not isinstance(max_workers, int) or max_workers < 0:
        raise ValueError("max_workers must be a non-negative integer")
    normalized_registration = {
        **registration,
        "agent_id": agent_id,
        "agent_attempt_id": agent_attempt_id,
        "objective_id": objective_id,
        "role": role,
        "parent_agent_attempt_id": parent_agent_attempt_id,
        "goal": _bounded_one_line(registration.get("goal"), "goal"),
        "scope": _bounded_one_line(registration.get("scope"), "scope"),
        "stop_condition": _bounded_one_line(
            registration.get("stop_condition"), "stop_condition"
        ),
    }

    def tx(con: Any) -> dict[str, Any]:
        events = _events_in_transaction(con)
        if _workspace_is_stopped(events):
            raise RuntimeError("workspace is stopped; explicit resume is required")
        challenge_id, event_wide = _validate_work_item(
            normalized_registration, events, root=store.root
        )
        if any(
            event["event_type"].startswith("agent.")
            and str(event["payload"].get("agent_attempt_id") or "")
            == agent_attempt_id
            for event in events
        ):
            raise ValueError("agent attempt ID is already registered")

        active_displays = _active_agent_displays(events)
        if agent_id in active_displays:
            raise ValueError("agent display ID already has an active attempt")

        active_before = len(active_displays)
        generation_row = con.execute(
            "SELECT value FROM meta WHERE key='stop_generation'"
        ).fetchone()
        generation = int(generation_row[0]) if generation_row else 0
        agent_depth = 1
        if parent_agent_attempt_id:
            parent_registration, parent_state, parent_latest_type = _attempt_state(
                events, parent_agent_attempt_id
            )
            if (
                parent_registration is None
                or parent_latest_type.rsplit(".", 1)[-1]
                not in _ACTIVE_ATTEMPT_STATES
                or int(parent_state.get("stop_generation", -1)) != generation
            ):
                raise ValueError(
                    "parent agent attempt must be active in the current generation"
                )
            if (
                str(parent_registration.get("role") or "")
                != "challenge-coordinator"
                or str(parent_registration.get("parent_agent_attempt_id") or "")
                or int(parent_registration.get("agent_depth", -1)) != 1
            ):
                raise ValueError(
                    "parent agent attempt must be a depth-1 challenge coordinator"
                )
            if (
                str(parent_registration.get("challenge_id") or "") != challenge_id
                or str(parent_registration.get("objective_id") or "")
                != objective_id
                or bool(parent_registration.get("event_wide")) != event_wide
            ):
                raise ValueError(
                    "parent agent attempt must own the same challenge and objective"
                )
            if role == "challenge-coordinator":
                raise ValueError("a challenge coordinator cannot have an agent parent")
            agent_depth = 2
        elif role == "challenge-coordinator" and event_wide:
            raise ValueError("a challenge coordinator must own one challenge")
        source_handoff_id = str(normalized_registration.get("source_handoff_id") or "none")
        if source_handoff_id != "none":
            if not challenge_id:
                raise ValueError("event-wide assignment cannot consume a challenge handoff")
            source_handoff = _require_structured_handoff(
                events,
                handoff_id=source_handoff_id,
                challenge_id=challenge_id,
                objective_id=objective_id,
                current_generation=generation,
            )
            if _bounded_report_sha256(
                _analysis_report_path(store.root, str(source_handoff["report_path"]))
            ) != str(source_handoff["sha256"]):
                raise ValueError("source handoff report is no longer current")
        else:
            source_handoff = None
            if challenge_id and any(
                event["event_type"] == "report.harvested"
                and bool(event["payload"].get("structured"))
                and _event_generation(event) == generation
                and _work_item_matches(
                    event["payload"], challenge_id=challenge_id, objective_id=objective_id
                )
                for event in events
            ):
                raise ValueError(
                    "challenge successor requires source_handoff_id after a current handoff exists"
                )
        if max_workers and active_before >= max_workers:
            rejected = {
                "agent_id": agent_id,
                "agent_attempt_id": agent_attempt_id,
                "parent_agent_attempt_id": str(
                    normalized_registration.get("parent_agent_attempt_id") or ""
                ),
                "agent_depth": agent_depth,
                "objective_id": objective_id,
                "challenge_id": challenge_id,
                "event_wide": event_wide,
                "stop_generation": generation,
                "status": "capacity_rejected",
                "outcome_type": "capacity_failure",
                "active_workers": active_before,
                "max_workers": max_workers,
                "reason": "worker concurrency limit reached",
                "rejected_at": iso_now(),
            }
            store.insert_in_transaction(
                con,
                "agent.capacity_rejected",
                rejected,
                actor=actor,
                generation=generation,
            )
            return {"admitted": False, "output": rejected}

        admitted = {
            **normalized_registration,
            "agent_id": agent_id,
            "agent_attempt_id": agent_attempt_id,
            "objective_id": objective_id,
            "challenge_id": challenge_id,
            "event_wide": event_wide,
            "source_handoff_id": source_handoff_id,
            "stop_generation": generation,
            "agent_depth": agent_depth,
            "assignment_packet": _assignment_packet(
                {
                    **normalized_registration,
                    "challenge_id": challenge_id,
                    "event_wide": event_wide,
                    "agent_depth": agent_depth,
                },
                source_handoff=source_handoff,
                generation=generation,
            ),
            "dispatch": {
                "active_workers_before": active_before,
                "max_workers": max_workers,
                "admission": "admitted",
            },
        }
        store.insert_in_transaction(
            con,
            "agent.running",
            admitted,
            actor=actor,
            generation=generation,
        )
        return {"admitted": True, "output": admitted}

    with file_lock(store.root / "state" / "mutation.lock"):
        result = store.transaction(tx)
    store.rebuild()
    return result


def _attempt_state(
    events: list[dict[str, Any]], agent_attempt_id: str
) -> tuple[dict[str, Any] | None, dict[str, Any], str]:
    """Return the immutable registration and latest state for one exact attempt.

    Events without an attempt ID are intentionally not associated with a newer
    attempt. They remain legacy/unknown evidence rather than inferred links.
    """

    registration: dict[str, Any] | None = None
    state: dict[str, Any] = {}
    latest_type = ""
    for event in events:
        payload = event["payload"]
        if str(payload.get("agent_attempt_id") or "") != agent_attempt_id:
            continue
        event_type = str(event["event_type"])
        if not event_type.startswith("agent."):
            continue
        if event_type == "agent.running":
            if registration is not None:
                raise ValueError("agent attempt has multiple registrations")
            registration = dict(payload)
        state = {**state, **payload}
        latest_type = event_type
    return registration, state, latest_type


def _require_active_registration(
    events: list[dict[str, Any]],
    *,
    agent_attempt_id: str,
    agent_id: str,
    objective_id: str,
    allow_stopped_closeout: bool = False,
) -> dict[str, Any]:
    registration, state, latest_type = _attempt_state(events, agent_attempt_id)
    if registration is None:
        raise ValueError("outcome requires an active registered agent attempt")
    if (
        str(registration.get("agent_id") or "") != agent_id
        or str(registration.get("objective_id") or "") != objective_id
    ):
        raise ValueError("outcome registration does not match agent attempt")
    attempt_status = latest_type.rsplit(".", 1)[-1]
    if attempt_status not in _ACTIVE_ATTEMPT_STATES and not (
        allow_stopped_closeout
        and attempt_status in {"closed", "stopping", "unacknowledged", "unmanaged"}
    ):
        raise ValueError("outcome requires an active registered agent attempt")
    return registration


def _typed_outcomes_for_attempt(
    events: list[dict[str, Any]], agent_attempt_id: str
) -> list[dict[str, Any]]:
    return [
        event["payload"]
        for event in events
        if event["event_type"] == "outcome.recorded"
        and str(event["payload"].get("agent_attempt_id") or "")
        == agent_attempt_id
        and event["payload"].get("outcome_type") in OUTCOME_TYPES
    ]


def _exact_outcomes_for_attempt(
    events: list[dict[str, Any]],
    *,
    agent_attempt_id: str,
    agent_id: str,
    objective_id: str,
) -> list[dict[str, Any]]:
    return [
        outcome
        for outcome in _typed_outcomes_for_attempt(events, agent_attempt_id)
        if str(outcome.get("agent_id") or "") == agent_id
        and str(outcome.get("objective_id") or "") == objective_id
    ]


def _work_item_matches(
    payload: dict[str, Any], *, challenge_id: str, objective_id: str
) -> bool:
    return (
        str(payload.get("challenge_id") or "") == challenge_id
        and str(payload.get("objective_id") or "") == objective_id
    )


def _route_consumes(payload: dict[str, Any], handoff_id: str) -> bool:
    return not handoff_id or str(payload.get("source_handoff_id") or "") == handoff_id


def _require_structured_handoff(
    events: list[dict[str, Any]],
    *,
    handoff_id: str,
    challenge_id: str,
    objective_id: str,
    current_generation: int,
) -> dict[str, Any]:
    matches = [
        event
        for event in events
        if event["event_type"] == "report.harvested"
        and str(event["payload"].get("handoff_id") or "") == handoff_id
    ]
    if len(matches) != 1:
        raise ValueError("route requires one exact structured handoff")
    event = matches[0]
    payload = event["payload"]
    required = (
        "report_path",
        "sha256",
        "agent_id",
        "agent_attempt_id",
        "challenge_id",
        "objective_id",
        "status",
        "source_handoff_id",
        "source_report_sha256",
        "observed_result",
        "route_key",
        "proof_gap",
        "source_handoff_id",
        "discriminating_test",
        "next_step_or_return_trigger",
        "blocker",
        "cleanup_jobs",
        "evidence_body_sha256",
    )
    if (
        _event_generation(event) != current_generation
        or not _work_item_matches(
            payload, challenge_id=challenge_id, objective_id=objective_id
        )
        or payload.get("status") not in OUTCOME_TYPES
        or any(not isinstance(payload.get(field), str) or not payload[field] for field in required)
        or not isinstance(payload.get("evidence_paths"), list)
        or not payload["evidence_paths"]
        or not isinstance(payload.get("command_artifact_paths"), list)
    ):
        raise ValueError("route handoff is incomplete, stale, or work-item mismatched")
    return payload


def validate_continuation(
    events: list[dict[str, Any]],
    *,
    reference: str,
    challenge_id: str,
    objective_id: str,
    current_generation: int,
    excluding_attempt_id: str = "",
    handoff_id: str = "",
) -> dict[str, Any]:
    """Validate one exact current route from canonical event evidence.

    Challenge links are always explicit.  In particular, an objective ID is
    never treated as a challenge ID when an older event lacks ``challenge_id``.
    """

    kind, identifier = parse_continuation_reference(reference)
    challenge_id = _required_identifier(challenge_id, "challenge_id")
    objective_id = _required_identifier(objective_id, "objective_id")

    if kind == "assignment":
        if identifier == excluding_attempt_id:
            raise ValueError("continuation assignment must be a different attempt")
        registration, state, latest_type = _attempt_state(events, identifier)
        registration_event = next(
            (
                event
                for event in events
                if event["event_type"] == "agent.running"
                and str(event["payload"].get("agent_attempt_id") or "")
                == identifier
            ),
            None,
        )
        if (
            registration is None
            or registration_event is None
            or _event_generation(registration_event) != current_generation
            or not _work_item_matches(
                registration, challenge_id=challenge_id, objective_id=objective_id
            )
            or not _route_consumes(registration, handoff_id)
            or latest_type.rsplit(".", 1)[-1] not in _ACTIVE_ATTEMPT_STATES
        ):
            raise ValueError("continuation assignment is not active and challenge-linked")
        return {"kind": kind, "id": identifier, "status": "active"}

    if kind == "retry":
        lifecycle = [
            event
            for event in events
            if event["event_type"].startswith("retry.")
            and str(event["payload"].get("retry_id") or "") == identifier
        ]
        latest = lifecycle[-1] if lifecycle else None
        if (
            latest is None
            or latest["event_type"] != "retry.scheduled"
            or _event_generation(latest) != current_generation
            or not _work_item_matches(
                latest["payload"], challenge_id=challenge_id, objective_id=objective_id
            )
            or not _route_consumes(latest["payload"], handoff_id)
        ):
            raise ValueError("continuation retry is not currently scheduled and linked")
        return {"kind": kind, "id": identifier, "status": "scheduled"}

    if kind == "proposal":
        proposals = [
            event
            for event in events
            if event["event_type"] == "proposal.created"
            and str(event["payload"].get("proposal_id") or "") == identifier
        ]
        proposal = proposals[0] if len(proposals) == 1 else None
        reviews = [
            event
            for event in events
            if event["event_type"] == "review.recorded"
            and str(event["payload"].get("proposal_id") or "") == identifier
        ]
        review = reviews[-1] if reviews else None
        terminal = any(
            event["event_type"] in _TERMINAL_EXECUTION_TYPES
            and str(event["payload"].get("proposal_id") or "") == identifier
            for event in events
        )
        if (
            proposal is None
            or review is None
            or terminal
            or proposal["seq"] >= review["seq"]
            or _event_generation(proposal) != current_generation
            or _event_generation(review) != current_generation
            or review["payload"].get("verdict") != "approved"
            or not _work_item_matches(
                proposal["payload"],
                challenge_id=challenge_id,
                objective_id=objective_id,
            )
            or not _route_consumes(proposal["payload"], handoff_id)
        ):
            raise ValueError(
                "continuation proposal is not current, independently approved, linked, and nonterminal"
            )
        return {"kind": kind, "id": identifier, "status": "approved"}

    if kind == "explore":
        lifecycle_types = {
            "exploration.campaign.opened",
            "exploration.campaign.parked",
            "exploration.campaign.closed",
        }
        lifecycle = [
            event
            for event in events
            if event["event_type"] in lifecycle_types
            and str(event["payload"].get("campaign_id") or "") == identifier
        ]
        opened = next(
            (
                event
                for event in lifecycle
                if event["event_type"] == "exploration.campaign.opened"
            ),
            None,
        )
        latest = lifecycle[-1] if lifecycle else None
        status = (
            latest["event_type"].rsplit(".", 1)[-1] if latest is not None else ""
        )
        consumption_types = {
            "exploration.idea_batch.recorded",
            "exploration.synthesis.recorded",
            "exploration.idea.selected",
        }
        consumption = next(
            (
                event
                for event in reversed(events)
                if event["event_type"] in consumption_types
                and str(event["payload"].get("campaign_id") or "") == identifier
                and _event_generation(event) == current_generation
                and _work_item_matches(
                    event["payload"],
                    challenge_id=challenge_id,
                    objective_id=objective_id,
                )
                and _route_consumes(event["payload"], handoff_id)
            ),
            None,
        )
        opened_consumes_handoff = opened is not None and _route_consumes(
            opened["payload"], handoff_id
        )
        consumes_handoff = (
            not handoff_id or opened_consumes_handoff or consumption is not None
        )
        if (
            opened is None
            or latest is None
            or status not in {"opened", "parked"}
            or _event_generation(opened) != current_generation
            or _event_generation(latest) != current_generation
            or not _work_item_matches(
                opened["payload"],
                challenge_id=challenge_id,
                objective_id=objective_id,
            )
            or not consumes_handoff
        ):
            raise ValueError("continuation campaign is not current and challenge-linked")
        return {
            "kind": kind,
            "id": identifier,
            "status": "active" if status == "opened" else "parked",
            "park_reason": str(
                latest["payload"].get("parked_reason")
                or latest["payload"].get("reason")
                or latest["payload"].get("return_condition")
                or ""
            )
            if status == "parked"
            else "",
            "consumption_event_type": str(consumption["event_type"])
            if handoff_id and consumption is not None
            else "exploration.campaign.opened"
            if handoff_id
            else "",
        }

    lifecycle = [
        event
        for event in events
        if event["event_type"].startswith("continuation.boundary.")
        and str(event["payload"].get("boundary_id") or "") == identifier
    ]
    latest = lifecycle[-1] if lifecycle else None
    if (
        latest is None
        or latest["event_type"] != "continuation.boundary.recorded"
        or _event_generation(latest) != current_generation
        or not _work_item_matches(
            latest["payload"], challenge_id=challenge_id, objective_id=objective_id
        )
        or not _route_consumes(latest["payload"], handoff_id)
    ):
        raise ValueError("continuation boundary is not current and challenge-linked")
    return {"kind": kind, "id": identifier, "status": "active"}


def record_continuation_boundary(
    store: EventStore,
    *,
    challenge_id: str,
    objective_id: str,
    name: str,
    return_condition: str,
    source_handoff_id: str,
    actor: str = "coordinator",
) -> dict[str, Any]:
    """Record a named external/evidence boundary as a durable current route."""

    challenge_id = _required_identifier(challenge_id, "challenge_id")
    objective_id = _required_identifier(objective_id, "objective_id")
    source_handoff_id = _required_identifier(source_handoff_id, "source_handoff_id")
    if not isinstance(name, str) or not name or len(name) > 512:
        raise ValueError("boundary name must be a non-empty bounded string")
    if (
        not isinstance(return_condition, str)
        or not return_condition
        or len(return_condition) > 4096
    ):
        raise ValueError("boundary return condition must be a non-empty bounded string")

    def tx(con: Any) -> dict[str, Any]:
        events = _events_in_transaction(con)
        if _workspace_is_stopped(events):
            raise RuntimeError("workspace is stopped; explicit resume is required")
        challenge = _canonical_challenges(events).get(challenge_id)
        if challenge is None:
            raise ValueError("continuation boundary challenge is not canonical")
        if _challenge_is_solved(challenge):
            raise ValueError("solved challenge does not accept a continuation boundary")
        generation_row = con.execute(
            "SELECT value FROM meta WHERE key='stop_generation'"
        ).fetchone()
        generation = int(generation_row[0]) if generation_row else 0
        _require_structured_handoff(
            events,
            handoff_id=source_handoff_id,
            challenge_id=challenge_id,
            objective_id=objective_id,
            current_generation=generation,
        )
        payload = {
            "boundary_id": "boundary_" + uuid.uuid4().hex,
            "challenge_id": challenge_id,
            "objective_id": objective_id,
            "name": name,
            "return_condition": return_condition,
            "source_handoff_id": source_handoff_id,
            "status": "active",
            "stop_generation": generation,
            "created_at": iso_now(),
        }
        store.insert_in_transaction(
            con,
            "continuation.boundary.recorded",
            payload,
            actor=actor,
            generation=generation,
        )
        return payload

    with file_lock(store.root / "state" / "mutation.lock"):
        payload = store.transaction(tx)
    store.rebuild()
    return payload


def schedule_retry_continuation(
    store: EventStore,
    retry: dict[str, Any],
    *,
    actor: str = "coordinator",
) -> dict[str, Any]:
    """Record one current retry only after validating its source handoff."""

    retry_id = _required_identifier(str(retry.get("retry_id") or ""), "retry_id")
    challenge_id = _required_identifier(
        str(retry.get("challenge_id") or ""), "challenge_id"
    )
    objective_id = _required_identifier(
        str(retry.get("objective_id") or ""), "objective_id"
    )
    source_handoff_id = _required_identifier(
        str(retry.get("source_handoff_id") or ""), "source_handoff_id"
    )

    def tx(con: Any) -> dict[str, Any]:
        events = _events_in_transaction(con)
        if _workspace_is_stopped(events):
            raise RuntimeError("workspace is stopped; explicit resume is required")
        challenge = _canonical_challenges(events).get(challenge_id)
        if challenge is None or _challenge_is_solved(challenge):
            raise ValueError("retry continuation requires a canonical unsolved challenge")
        if any(
            event["event_type"].startswith("retry.")
            and str(event["payload"].get("retry_id") or "") == retry_id
            for event in events
        ):
            raise ValueError("retry ID is already recorded")
        generation_row = con.execute(
            "SELECT value FROM meta WHERE key='stop_generation'"
        ).fetchone()
        generation = int(generation_row[0]) if generation_row else 0
        _require_structured_handoff(
            events,
            handoff_id=source_handoff_id,
            challenge_id=challenge_id,
            objective_id=objective_id,
            current_generation=generation,
        )
        payload = {
            **retry,
            "retry_id": retry_id,
            "challenge_id": challenge_id,
            "objective_id": objective_id,
            "source_handoff_id": source_handoff_id,
            "status": "scheduled",
            "stop_generation": generation,
        }
        store.insert_in_transaction(
            con,
            "retry.scheduled",
            payload,
            actor=actor,
            generation=generation,
        )
        return payload

    with file_lock(store.root / "state" / "mutation.lock"):
        payload = store.transaction(tx)
    store.rebuild()
    return payload


def close_current_agent_attempt(
    store: EventStore,
    *,
    agent_id: str,
    reason: str,
    actor: str = "coordinator",
) -> dict[str, Any]:
    """Close only the display agent's current registered attempt.

    A second close is idempotent only after the same exact attempt has already
    been closed with its own exact typed outcome.
    """

    agent_id = _required_identifier(agent_id, "agent_id")
    if not isinstance(reason, str) or not reason:
        raise ValueError("reason must be a non-empty string")

    def tx(con: Any) -> tuple[dict[str, Any], bool]:
        events = _events_in_transaction(con)
        registration = _latest_registered_attempts(events).get(agent_id)
        if registration is None:
            raise ValueError("agent close requires an active registered agent attempt")
        attempt_id = str(registration["payload"]["agent_attempt_id"])
        registration_payload, state, latest_type = _attempt_state(events, attempt_id)
        if (
            registration_payload is None
            or str(registration_payload.get("agent_id") or "") != agent_id
            or str(state.get("objective_id") or "")
            != str(registration_payload.get("objective_id") or "")
        ):
            raise ValueError("agent close requires an active registered agent attempt")
        objective_id = str(registration_payload.get("objective_id") or "")
        outcomes = _exact_outcomes_for_attempt(
            events,
            agent_attempt_id=attempt_id,
            agent_id=agent_id,
            objective_id=objective_id,
        )
        if len(outcomes) != 1:
            raise ValueError(
                "agent close requires a typed outcome for this exact agent attempt"
            )
        if latest_type == "agent.closed":
            return state, True
        if latest_type.rsplit(".", 1)[-1] not in _ACTIVE_ATTEMPT_STATES:
            raise ValueError("agent close requires an active registered agent attempt")
        outcome = outcomes[0]
        generation_row = con.execute(
            "SELECT value FROM meta WHERE key='stop_generation'"
        ).fetchone()
        generation = int(generation_row[0]) if generation_row else 0
        challenge_id = str(outcome.get("challenge_id") or "")
        handoff_id = str(outcome.get("handoff_id") or "")
        challenge = _canonical_challenges(events).get(challenge_id, {})
        if (
            challenge_id
            and not _challenge_is_solved(challenge)
            and not _current_continuations(
                events,
                challenge_id=challenge_id,
                objective_id=objective_id,
                current_generation=generation,
                excluding_attempt_id=attempt_id,
                handoff_id=handoff_id,
            )
        ):
            raise ValueError(
                "agent close requires a current challenge continuation that consumes "
                "its handoff"
            )
        outcome_event = next(
            event
            for event in events
            if event["event_type"] == "outcome.recorded"
            and str(event["payload"].get("outcome_id") or "")
            == str(outcome.get("outcome_id") or "")
        )
        report_path = str(outcome.get("report_path") or "")
        report = _analysis_report_path(store.root, report_path)
        current_report_sha256 = _bounded_report_sha256(report)
        canonical_event_wide = (
            registration_payload.get("event_wide") is True
            and isinstance(registration_payload.get("assignment_packet"), dict)
        )
        if challenge_id:
            handoff = _require_structured_handoff(
                events,
                handoff_id=handoff_id,
                challenge_id=challenge_id,
                objective_id=objective_id,
                current_generation=generation,
            )
            if (
                str(handoff.get("report_path") or "") != report_path
                or str(handoff.get("sha256") or "") != current_report_sha256
                or str(handoff.get("agent_id") or "") != agent_id
                or str(handoff.get("agent_attempt_id") or "") != attempt_id
                or handoff.get("status") != outcome.get("outcome_type")
                or str(handoff.get("route_key") or "")
                != str(outcome.get("mechanism") or "")
            ):
                raise ValueError(
                    "agent close requires the exact current structured handoff"
                )
        else:
            harvested = [
                event
                for event in events
                if event["event_type"] == "report.harvested"
                and (canonical_event_wide or event["seq"] > outcome_event["seq"])
                and str(event["payload"].get("report_path") or "") == report_path
                and str(event["payload"].get("sha256") or "")
                == current_report_sha256
                and str(event["payload"].get("agent_id") or "") == agent_id
                and str(event["payload"].get("objective_id") or "") == objective_id
                and (
                    not canonical_event_wide
                    or (
                        _event_generation(event) == generation
                        and str(event["payload"].get("agent_attempt_id") or "") == attempt_id
                        and event["payload"].get("status") == outcome.get("outcome_type")
                        and str(event["payload"].get("route_key") or "")
                        == str(outcome.get("mechanism") or "")
                        and event["payload"].get("reconciliation_debt") is not True
                    )
                )
            ]
            if not harvested:
                raise ValueError(
                    "agent close requires the current exact outcome report to be harvested"
                )
        payload = {
            **state,
            "agent_id": agent_id,
            "agent_attempt_id": attempt_id,
            "reason": reason,
            "stop_generation": generation,
            "closed_at": iso_now(),
        }
        store.insert_in_transaction(
            con,
            "agent.closed",
            payload,
            actor=actor,
            generation=generation,
        )
        return payload, False

    with file_lock(store.root / "state" / "mutation.lock"):
        payload, _ = store.transaction(tx)
    store.rebuild()
    return payload


def _analysis_report_path(root: Path, report_path: str) -> Path:
    """Resolve only a declared file below the workspace ``analysis/`` root."""

    if not isinstance(report_path, str) or not report_path:
        raise ValueError("report path must be a non-empty analysis-relative path")
    windows_path = PureWindowsPath(report_path)
    if (
        Path(report_path).is_absolute()
        or windows_path.is_absolute()
        or windows_path.drive
        or "\\" in report_path
    ):
        raise ValueError("report path must be analysis-relative, not absolute")
    raw_parts = report_path.split("/")
    if (
        len(raw_parts) < 2
        or raw_parts[0] != "analysis"
        or any(part in {"", ".", ".."} for part in raw_parts)
    ):
        raise ValueError("report path must name a file below analysis/")
    parts = PurePosixPath(report_path).parts
    analysis = contained_private_path(root, root, "analysis")
    return contained_private_path(root, analysis, *parts[1:])


def _bounded_report_sha256(path: Path) -> str:
    return _bounded_report_bytes(path)[1]


def _bounded_report_bytes(path: Path) -> tuple[bytes, str]:
    """Read one stable, bounded, nonempty regular report without following links."""

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError(f"report path is not a regular file: {path}")
        if not info.st_size or info.st_size > MAX_HARVEST_REPORT_BYTES:
            raise ValueError(
                "report must be nonempty and within the harvest byte limit"
            )
        digest = hashlib.sha256()
        remaining = MAX_HARVEST_REPORT_BYTES
        data = bytearray()
        while True:
            block = os.read(descriptor, min(_REPORT_HASH_BLOCK_BYTES, remaining))
            if not block:
                after = os.fstat(descriptor)
                if (
                    info.st_dev,
                    info.st_ino,
                    info.st_size,
                    info.st_mtime_ns,
                ) != (
                    after.st_dev,
                    after.st_ino,
                    after.st_size,
                    after.st_mtime_ns,
                ):
                    raise ValueError("report changed while being harvested")
                return bytes(data), digest.hexdigest()
            digest.update(block)
            data.extend(block)
            remaining -= len(block)
            if remaining == 0 and os.read(descriptor, 1):
                raise ValueError(
                    f"report exceeds {MAX_HARVEST_REPORT_BYTES}-byte harvest limit"
                )
    finally:
        os.close(descriptor)


def _parse_report_path_array(value: str, label: str) -> list[str]:
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{label} must be a JSON string array") from exc
    if (
        not isinstance(parsed, list)
        or len(parsed) > 128
        or any(
            not isinstance(item, str)
            or not item.strip()
            or item != item.strip()
            or len(item) > 2048
            or "\n" in item
            or "\r" in item
            for item in parsed
        )
        or len(set(parsed)) != len(parsed)
    ):
        raise ValueError(f"{label} must be a bounded unique JSON string array")
    return parsed


def _validate_handoff_artifact_paths(root: Path, paths: list[str], label: str) -> list[str]:
    """Require declared report artifacts to be contained current regular files."""

    checked: list[str] = []
    for value in paths:
        windows_path = PureWindowsPath(value)
        parts = PurePosixPath(value).parts
        if (
            Path(value).is_absolute()
            or windows_path.is_absolute()
            or windows_path.drive
            or "\\" in value
            or len(parts) < 2
            or parts[0] not in _HANDOFF_ARTIFACT_ROOTS
            or any(part in {"", ".", ".."} for part in parts)
        ):
            raise ValueError(f"{label} contains an invalid artifact path")
        try:
            candidate = contained_private_path(root, root, *parts)
            info = candidate.lstat()
        except OSError as exc:
            raise ValueError(f"{label} artifact is missing or unreadable") from exc
        if candidate.is_symlink() or not stat.S_ISREG(info.st_mode):
            raise ValueError(f"{label} artifact must be a regular non-link file")
        checked.append(value)
    return checked


def _parse_structured_handoff_report(raw: bytes, *, root: Path | None = None) -> dict[str, Any]:
    """Parse the exact bounded worker handoff block and evidence sections."""

    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise ValueError("report must be UTF-8") from exc
    headings = {heading: [index for index, line in enumerate(lines) if line == heading] for heading in ("## Handoff", "## Evidence", "## Commands")}
    if any(len(indices) != 1 for indices in headings.values()):
        raise ValueError("report requires exactly one ## Handoff, ## Evidence, and ## Commands section")
    handoff_index = headings["## Handoff"][0]
    evidence_index = headings["## Evidence"][0]
    commands_index = headings["## Commands"][0]
    if not handoff_index < evidence_index < commands_index:
        raise ValueError("report sections must be ordered Handoff, Evidence, Commands")
    fields: dict[str, str] = {}
    labels: list[str] = []
    for line in lines[handoff_index + 1 : evidence_index]:
        if not line.strip():
            continue
        label, separator, value = line.partition(":")
        if separator != ":" or label not in _HANDOFF_LABELS or label in fields:
            raise ValueError("report handoff block has an unknown, duplicate, or malformed label")
        fields[label] = _bounded_one_line(value.strip(), label)
        labels.append(label)
    if labels != list(_HANDOFF_LABELS):
        raise ValueError("report handoff block is missing or reorders a canonical label")
    if set(fields) != set(_HANDOFF_LABELS):
        raise ValueError("report handoff block is missing a canonical label")
    evidence_body = "\n".join(lines[evidence_index + 1 : commands_index]).strip()
    if (
        len(evidence_body) < 16
        or evidence_body.casefold() in _HANDOFF_PLACEHOLDERS
        or not any(character.isalnum() for character in evidence_body)
    ):
        raise ValueError("report requires a nonwhitespace evidence-bearing body")
    status = fields["Status"]
    if status not in OUTCOME_TYPES:
        raise ValueError("report Status must be a typed outcome")
    source_handoff_id = fields["Source handoff"]
    source_report_sha256 = fields["Source report SHA-256"]
    if source_handoff_id != "none":
        _required_identifier(source_handoff_id, "Source handoff")
        if SHA256.fullmatch(source_report_sha256) is None:
            raise ValueError("Source report SHA-256 must be a 64-character lowercase digest")
    elif source_report_sha256 != "none":
        raise ValueError("initial report Source report SHA-256 must be none")
    evidence_paths = _parse_report_path_array(
        fields["Evidence paths"], "Evidence paths"
    )
    if status in _SUBSTANTIVE_OUTCOME_TYPES and not evidence_paths:
        raise ValueError("substantive report status requires at least one evidence path")
    command_artifact_paths = _parse_report_path_array(
        fields["Command/artifact paths"], "Command/artifact paths"
    )
    if root is not None:
        evidence_paths = _validate_handoff_artifact_paths(
            root, evidence_paths, "Evidence paths"
        )
        command_artifact_paths = _validate_handoff_artifact_paths(
            root, command_artifact_paths, "Command/artifact paths"
        )
    return {
        "status": status,
        "source_handoff_id": source_handoff_id,
        "source_report_sha256": source_report_sha256,
        "observed_result": fields["Observed result"],
        "route_key": fields["Route key"],
        "proof_gap": fields["Proof gap"],
        "discriminating_test": fields["Discriminating test"],
        "next_step_or_return_trigger": fields["Next step or return trigger"],
        "evidence_paths": evidence_paths,
        "command_artifact_paths": command_artifact_paths,
        "blocker": fields["Blocker"],
        "cleanup_jobs": fields["Cleanup/jobs"],
        "evidence_body_sha256": hashlib.sha256(evidence_body.encode("utf-8")).hexdigest(),
    }


def parse_report_handoff(root: Path, report_path: str) -> dict[str, Any]:
    """Return the canonical, value-bearing handoff view for one bounded report.

    This is deliberately pure: callers still resolve registration and current
    generation under their own durable transaction before taking an action.
    """

    path = _analysis_report_path(root, report_path)
    raw, digest = _bounded_report_bytes(path)
    return {
        "report_path": path.relative_to(Path(root).absolute()).as_posix(),
        "sha256": digest,
        **_parse_structured_handoff_report(raw, root=Path(root)),
    }


def record_outcome(
    store: EventStore,
    *,
    agent_id: str,
    objective_id: str,
    outcome_type: str,
    report_path: str,
    summary: str,
    mechanism: str = "",
    agent_attempt_id: str = "",
    challenge_id: str = "",
    continuation: str = "",
    handoff_id: str = "",
    provenance: list[str] | None = None,
    actor: str = "worker",
) -> dict[str, Any]:
    agent_id = _required_identifier(agent_id, "agent_id")
    agent_attempt_id = _required_identifier(agent_attempt_id, "agent_attempt_id")
    objective_id = _required_identifier(str(objective_id), "objective_id")
    if outcome_type not in OUTCOME_TYPES:
        raise ValueError(f"unsupported outcome type: {outcome_type}")
    if not report_path or not summary:
        raise ValueError("report_path and summary are required")
    payload: dict[str, Any] = {
        "outcome_id": "out_" + uuid.uuid4().hex,
        "agent_id": agent_id,
        "agent_attempt_id": agent_attempt_id,
        "objective_id": str(objective_id),
        "outcome_type": outcome_type,
        "summary": summary,
        "report_path": report_path,
        "mechanism": mechanism,
        "provenance": provenance or [],
        "transition": TRANSITIONS[outcome_type],
        "recorded_at": iso_now(),
    }

    def tx(con: Any) -> dict[str, Any]:
        events = _events_in_transaction(con)
        registration = _require_active_registration(
            events,
            agent_attempt_id=agent_attempt_id,
            agent_id=agent_id,
            objective_id=objective_id,
            allow_stopped_closeout=_workspace_is_stopped(events),
        )
        if _typed_outcomes_for_attempt(events, agent_attempt_id):
            raise ValueError("typed outcome already recorded for agent attempt")
        generation_row = con.execute(
            "SELECT value FROM meta WHERE key='stop_generation'"
        ).fetchone()
        generation = int(generation_row[0]) if generation_row else 0
        registered_challenge_id = str(registration.get("challenge_id") or "")
        event_wide = registration.get("event_wide") is True
        legacy_unlinked = not registered_challenge_id and not event_wide
        auto_retry = outcome_type in {"generic_refusal", "capacity_failure"}
        scheduled_retry_id = (
            "retry_" + uuid.uuid4().hex if auto_retry and not continuation else ""
        )
        if challenge_id and challenge_id != registered_challenge_id:
            raise ValueError("outcome challenge does not match agent registration")
        if event_wide and challenge_id:
            raise ValueError("event-wide outcome cannot name a challenge")
        if registered_challenge_id:
            challenge = _canonical_challenges(events).get(registered_challenge_id)
            if challenge is None:
                raise ValueError("outcome challenge is not currently canonical")
            handoff_id_value = _required_identifier(handoff_id, "handoff_id")
            handoff = _require_structured_handoff(
                events,
                handoff_id=handoff_id_value,
                challenge_id=registered_challenge_id,
                objective_id=objective_id,
                current_generation=generation,
            )
            if (
                str(handoff.get("agent_id") or "") != agent_id
                or str(handoff.get("agent_attempt_id") or "") != agent_attempt_id
                or str(handoff.get("report_path") or "") != report_path
                or str(registration.get("report_path") or "") != report_path
                or handoff.get("status") != outcome_type
                or str(handoff.get("route_key") or "") != mechanism
                or _bounded_report_sha256(_analysis_report_path(store.root, report_path))
                != str(handoff.get("sha256") or "")
            ):
                raise ValueError(
                    "outcome does not match its exact structured handoff and current report"
                )
            payload["handoff_id"] = handoff_id_value
            needs_continuation = not _challenge_is_solved(challenge)
            if needs_continuation and not continuation and not auto_retry:
                raise ValueError(
                    "unsolved challenge outcome requires a continuation"
                )
            if continuation:
                route = validate_continuation(
                    events,
                    reference=continuation,
                    challenge_id=registered_challenge_id,
                    objective_id=objective_id,
                    current_generation=generation,
                    excluding_attempt_id=agent_attempt_id,
                    handoff_id=handoff_id_value,
                )
                payload["continuation_kind"] = route["kind"]
                payload["continuation_id"] = route["id"]
                payload["continuation_status"] = route["status"]
            elif auto_retry:
                payload["continuation_kind"] = "retry"
                payload["continuation_id"] = scheduled_retry_id
                payload["continuation_status"] = "scheduled"
        elif event_wide and isinstance(registration.get("assignment_packet"), dict):
            current_report_sha256 = _bounded_report_sha256(
                _analysis_report_path(store.root, report_path)
            )
            harvested = [
                event
                for event in events
                if event["event_type"] == "report.harvested"
                and _event_generation(event) == generation
                and str(event["payload"].get("report_path") or "") == report_path
                and str(event["payload"].get("sha256") or "") == current_report_sha256
                and str(event["payload"].get("agent_id") or "") == agent_id
                and str(event["payload"].get("agent_attempt_id") or "")
                == agent_attempt_id
                and str(event["payload"].get("objective_id") or "") == objective_id
                and event["payload"].get("status") == outcome_type
                and str(event["payload"].get("route_key") or "") == mechanism
                and event["payload"].get("reconciliation_debt") is not True
            ]
            if len(harvested) != 1:
                raise ValueError(
                    "event-wide outcome requires one exact current harvested report"
                )
        elif continuation:
            raise ValueError("unlinked or event-wide outcome cannot name a continuation")
        elif handoff_id:
            raise ValueError("unlinked or event-wide outcome cannot name a handoff")
        payload["challenge_id"] = registered_challenge_id
        payload["event_wide"] = event_wide
        payload["challenge_link_status"] = (
            "legacy_unrouted" if legacy_unlinked else "linked"
        )
        payload["stop_generation"] = generation
        store.insert_in_transaction(
            con,
            "outcome.recorded",
            payload,
            actor=actor,
            generation=generation,
        )
        if scheduled_retry_id:
            store.insert_in_transaction(
                con,
                "retry.scheduled",
                {
                    "retry_id": scheduled_retry_id,
                    "objective_id": objective_id,
                    "challenge_id": registered_challenge_id,
                    "source_handoff_id": str(payload.get("handoff_id") or ""),
                    "earliest_at": iso_now(),
                    "trigger": TRANSITIONS[outcome_type],
                    "method": "default-worker-short-context",
                    "status": "scheduled",
                    "stop_generation": generation,
                },
                actor="coordinator",
                generation=generation,
            )
        return payload

    with file_lock(store.root / "state" / "mutation.lock"):
        payload = store.transaction(tx)
    store.rebuild()
    return payload


def harvest_report(
    store: EventStore,
    root: Path,
    report_path: str,
    *,
    agent_id: str = "",
    agent_attempt_id: str = "",
    challenge_id: str = "",
    objective_id: str = "",
    status: str = "",
    observed_result: str = "",
    route_key: str = "",
    proof_gap: str = "",
    next_step_or_return_trigger: str = "",
    actor: str = "coordinator",
) -> dict[str, Any]:
    if Path(root).resolve() != store.root:
        raise ValueError("harvest root does not match the event store workspace")
    path = _analysis_report_path(root, report_path)
    rel = path.relative_to(Path(root).absolute()).as_posix()

    def tx(con: Any) -> dict[str, Any]:
        events = _events_in_transaction(con)
        raw, digest = _bounded_report_bytes(path)
        generation_row = con.execute(
            "SELECT value FROM meta WHERE key='stop_generation'"
        ).fetchone()
        generation = int(generation_row[0]) if generation_row else 0
        structured = False
        reconciliation_debt = False
        parsed: dict[str, Any] = {}
        if agent_attempt_id:
            stopped = _workspace_is_stopped(events)
            registration = _require_active_registration(
                events,
                agent_attempt_id=agent_attempt_id,
                agent_id=agent_id,
                objective_id=objective_id,
                allow_stopped_closeout=stopped,
            )
            registered_challenge_id = str(registration.get("challenge_id") or "")
            structured = bool(registered_challenge_id)
            canonical_attempt = structured or isinstance(
                registration.get("assignment_packet"), dict
            )
            if challenge_id and challenge_id != registered_challenge_id:
                raise ValueError("handoff challenge does not match agent registration")
            if canonical_attempt:
                parsed = _parse_structured_handoff_report(raw, root=Path(root))
                required_values = {
                    "status": status,
                    "observed_result": observed_result,
                    "route_key": route_key,
                    "proof_gap": proof_gap,
                    "next_step_or_return_trigger": next_step_or_return_trigger,
                }
                if status not in OUTCOME_TYPES or any(
                    not isinstance(value, str) or not value or len(value) > 4096
                    for value in required_values.values()
                ):
                    raise ValueError(
                        "challenge handoff requires a typed status and complete bounded "
                        "result, route, proof-gap, and next-step fields"
                    )
                if any(
                    parsed[field] != value
                    for field, value in {
                        "status": status,
                        "observed_result": observed_result,
                        "route_key": route_key,
                        "proof_gap": proof_gap,
                        "next_step_or_return_trigger": next_step_or_return_trigger,
                    }.items()
                ):
                    raise ValueError("handoff CLI fields do not match the canonical report block")
                registered_source = str(registration.get("source_handoff_id") or "none")
                if parsed["source_handoff_id"] != registered_source:
                    raise ValueError("report Source handoff does not match agent registration")
                packet = registration.get("assignment_packet")
                if isinstance(packet, dict) and parsed["source_report_sha256"] != str(
                    packet.get("source_report_sha256") or "none"
                ):
                    raise ValueError(
                        "report Source report SHA-256 does not match the assignment packet"
                    )
                if (
                    isinstance(packet, dict)
                    and
                    registered_source != "none"
                    and parsed["route_key"] == str(packet.get("source_route_key") or "")
                ):
                    raise ValueError("successor report Route key must differ from its source handoff")
            if structured:
                if (
                    str(registration.get("report_path") or "") != rel
                    or registered_challenge_id != challenge_id
                ):
                    raise ValueError("handoff report or challenge does not match registration")
                registration_event = next(
                    event
                    for event in events
                    if event["event_type"] == "agent.running"
                    and str(event["payload"].get("agent_attempt_id") or "")
                    == agent_attempt_id
                )
                if _event_generation(registration_event) != generation:
                    if not stopped:
                        raise ValueError("handoff agent attempt belongs to a stale generation")
                    reconciliation_debt = True
                if stopped:
                    reconciliation_debt = True
            elif canonical_attempt and stopped:
                reconciliation_debt = True

        match_fields = {
            "report_path": rel,
            "sha256": digest,
            "agent_id": agent_id,
            "agent_attempt_id": agent_attempt_id,
            "challenge_id": challenge_id,
            "objective_id": objective_id,
            "status": status,
            "observed_result": observed_result,
            "route_key": route_key,
            "proof_gap": proof_gap,
            "next_step_or_return_trigger": next_step_or_return_trigger,
            "source_handoff_id": parsed.get("source_handoff_id", ""),
            "source_report_sha256": parsed.get("source_report_sha256", ""),
            "discriminating_test": parsed.get("discriminating_test", ""),
            "evidence_paths": parsed.get("evidence_paths", []),
            "command_artifact_paths": parsed.get("command_artifact_paths", []),
            "blocker": parsed.get("blocker", ""),
            "cleanup_jobs": parsed.get("cleanup_jobs", ""),
            "evidence_body_sha256": parsed.get("evidence_body_sha256", ""),
            "reconciliation_debt": reconciliation_debt,
        }
        for event in events:
            if event["event_type"] != "report.harvested":
                continue
            if all(event["payload"].get(key, "") == value for key, value in match_fields.items()):
                return {**event["payload"], "idempotent": True}
        payload = {
            "handoff_id": "handoff_" + uuid.uuid4().hex
            if structured and not reconciliation_debt
            else "",
            **match_fields,
            "structured": structured and not reconciliation_debt,
            "stop_generation": generation,
            "harvested_at": iso_now(),
        }
        if reconciliation_debt:
            payload["debt_reason"] = "report arrived after stop; handoff and continuation remain closed"
        store.insert_in_transaction(
            con,
            "report.harvested",
            payload,
            actor=actor,
            generation=generation,
        )
        return payload

    with file_lock(store.root / "state" / "mutation.lock"):
        payload = store.transaction(tx)
    store.rebuild()
    return payload


def _current_continuations(
    events: list[dict[str, Any]],
    *,
    challenge_id: str,
    objective_id: str,
    current_generation: int,
    excluding_attempt_id: str = "",
    handoff_id: str = "",
) -> list[dict[str, Any]]:
    candidates: set[str] = set()
    for event in events:
        payload = event["payload"]
        event_type = event["event_type"]
        reference = ""
        if event_type == "agent.running":
            reference = f"assignment:{payload.get('agent_attempt_id', '')}"
        elif event_type.startswith("retry."):
            reference = f"retry:{payload.get('retry_id', '')}"
        elif event_type == "proposal.created":
            reference = f"proposal:{payload.get('proposal_id', '')}"
        elif event_type == "exploration.campaign.opened":
            reference = f"explore:{payload.get('campaign_id', '')}"
        elif event_type == "continuation.boundary.recorded":
            reference = f"boundary:{payload.get('boundary_id', '')}"
        if reference.endswith(":") or reference in candidates:
            continue
        if not _work_item_matches(
            payload, challenge_id=challenge_id, objective_id=objective_id
        ):
            continue
        candidates.add(reference)

    routes: list[dict[str, Any]] = []
    for reference in sorted(candidates):
        try:
            routes.append(
                validate_continuation(
                    events,
                    reference=reference,
                    challenge_id=challenge_id,
                    objective_id=objective_id,
                    current_generation=current_generation,
                    excluding_attempt_id=excluding_attempt_id,
                    handoff_id=handoff_id,
                )
            )
        except ValueError:
            continue
    return routes


def derive_challenge_coordination(
    events: list[dict[str, Any]], *, current_generation: int
) -> dict[str, dict[str, Any]]:
    """Derive foreground and continuation state without changing history."""

    challenges = _canonical_challenges(events)
    coordination: dict[str, dict[str, Any]] = {}
    for challenge_id, challenge in challenges.items():
        attempts = [
            event
            for event in events
            if event["event_type"] == "agent.running"
            and str(event["payload"].get("challenge_id") or "") == challenge_id
        ]
        outcomes = [
            event
            for event in events
            if event["event_type"] == "outcome.recorded"
            and str(event["payload"].get("challenge_id") or "") == challenge_id
        ]
        low_progress = [
            event
            for event in outcomes
            if event["payload"].get("outcome_type") in LOW_PROGRESS_OUTCOME_TYPES
        ]
        objective_ids = {
            str(event["payload"].get("objective_id") or "")
            for event in [*attempts, *outcomes]
            if str(event["payload"].get("objective_id") or "")
        }
        terminal_attempt_ids = {
            str(event["payload"].get("agent_attempt_id") or "")
            for event in outcomes
            if str(event["payload"].get("agent_attempt_id") or "")
        }
        routes: list[dict[str, Any]] = []
        for objective_id in sorted(objective_ids):
            for route in _current_continuations(
                events,
                challenge_id=challenge_id,
                objective_id=objective_id,
                current_generation=current_generation,
            ):
                if route["kind"] == "assignment" and route["id"] in terminal_attempt_ids:
                    continue
                routes.append({**route, "objective_id": objective_id})
        unique_routes = {
            (row["kind"], row["id"], row["objective_id"]): row for row in routes
        }
        routes = [unique_routes[key] for key in sorted(unique_routes)]
        mechanisms: dict[str, int] = {}
        for event in low_progress:
            if event["payload"].get("outcome_type") not in {
                "technical_negative",
                "no_progress",
                "duplicate_trace",
            }:
                continue
            mechanism = str(event["payload"].get("mechanism") or "")
            if mechanism:
                mechanisms[mechanism] = mechanisms.get(mechanism, 0) + 1
        latest_outcome = outcomes[-1] if outcomes else None
        latest_progress = next(
            (
                event
                for event in reversed(outcomes)
                if event["payload"].get("outcome_type")
                in {"supported_finding", "candidate"}
            ),
            None,
        )
        solved = _challenge_is_solved(challenge)
        untouched = not attempts and not outcomes
        exploration_routes = [row for row in routes if row["kind"] == "explore"]
        parked_routes = [
            row for row in exploration_routes if row.get("status") == "parked"
        ]
        stuck = bool(low_progress) and not routes and not solved
        if solved:
            state = "solved"
        elif untouched:
            state = "untouched"
        elif exploration_routes:
            state = "parked" if parked_routes else "exploring"
        elif routes:
            state = "routed"
        elif stuck:
            state = "stuck"
        else:
            state = "attempted"
        coordination[challenge_id] = {
            "challenge_id": challenge_id,
            "objective_ids": sorted(objective_ids),
            "attempt_count": len(attempts),
            "outcome_count": len(outcomes),
            "low_progress_outcome_count": len(low_progress),
            "latest_outcome_type": str(
                latest_outcome["payload"].get("outcome_type") or ""
            )
            if latest_outcome
            else "",
            "latest_outcome_at": str(latest_outcome.get("created_at") or "")
            if latest_outcome
            else "",
            "last_progress_at": str(latest_progress.get("created_at") or "")
            if latest_progress
            else "",
            "active_continuations": routes,
            "has_current_continuation": bool(routes),
            "parked_campaign_ids": sorted(row["id"] for row in parked_routes),
            "park_reason": "; ".join(
                str(row.get("park_reason") or "")
                for row in parked_routes
                if str(row.get("park_reason") or "")
            ),
            "frontier_state": state,
            "untouched": untouched,
            "stuck": stuck,
            "equivalent_trace_count": max(mechanisms.values(), default=0),
            "stop_generation": current_generation,
        }
    return coordination


def continuation_audit(
    events: list[dict[str, Any]],
    *,
    current_generation: int,
    coordination: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Return safe identifiers for linked gaps and deliberately unlinked history."""

    if coordination is None:
        coordination = derive_challenge_coordination(
            events, current_generation=current_generation
        )
    legacy = [
        event
        for event in events
        if event["event_type"] == "outcome.recorded"
        and event["payload"].get("outcome_type") in LOW_PROGRESS_OUTCOME_TYPES
        and not str(event["payload"].get("challenge_id") or "")
    ]
    linked_low_progress = sum(
        row["low_progress_outcome_count"] for row in coordination.values()
    )
    unrouted_ids = sorted(
        challenge_id
        for challenge_id, row in coordination.items()
        if row["stuck"]
    )
    routed_ids = sorted(
        challenge_id
        for challenge_id, row in coordination.items()
        if row["low_progress_outcome_count"] and row["has_current_continuation"]
    )
    active_attempts: list[str] = []
    for event in events:
        if (
            event["event_type"] != "agent.running"
            or _event_generation(event) != current_generation
            or not str(event["payload"].get("challenge_id") or "")
        ):
            continue
        attempt_id = str(event["payload"].get("agent_attempt_id") or "")
        _, _, latest_type = _attempt_state(events, attempt_id)
        if latest_type.rsplit(".", 1)[-1] in _ACTIVE_ATTEMPT_STATES:
            active_attempts.append(attempt_id)
    structured_handoffs = [
        event
        for event in events
        if event["event_type"] == "report.harvested"
        and _event_generation(event) == current_generation
        and bool(event["payload"].get("structured"))
        and str(event["payload"].get("handoff_id") or "")
    ]
    handed_off_attempts = {
        str(event["payload"].get("agent_attempt_id") or "")
        for event in structured_handoffs
    }
    harvested_attempts = {
        str(event["payload"].get("agent_attempt_id") or "")
        for event in events
        if event["event_type"] == "report.harvested"
        and str(event["payload"].get("agent_attempt_id") or "")
    }
    typed_outcome_attempts = {
        str(event["payload"].get("agent_attempt_id") or "")
        for event in events
        if event["event_type"] == "outcome.recorded"
        and event["payload"].get("outcome_type") in OUTCOME_TYPES
        and str(event["payload"].get("agent_attempt_id") or "")
    }
    reconciliation_debts = [
        event["payload"]
        for event in events
        if event["event_type"] == "report.harvested"
        and event["payload"].get("reconciliation_debt") is True
    ]
    reconciliation_debt_attempt_ids = sorted(
        {
            str(payload.get("agent_attempt_id") or "")
            for payload in reconciliation_debts
            if str(payload.get("agent_attempt_id") or "")
        }
    )
    reconciliation_debt_report_paths = sorted(
        {
            str(payload.get("report_path") or "")
            for payload in reconciliation_debts
            if str(payload.get("report_path") or "")
        }
    )
    closed_attempts = {
        str(event["payload"].get("agent_attempt_id") or "")
        for event in events
        if event["event_type"] == "agent.closed"
        and str(event["payload"].get("agent_attempt_id") or "")
        in typed_outcome_attempts
    }
    unharvested_attempt_ids = sorted(set(active_attempts) - handed_off_attempts)
    closed_without_handoff_ids = sorted(closed_attempts - harvested_attempts)
    unconsumed_handoff_ids: list[str] = []
    canonical_challenges = _canonical_challenges(events)
    for event in structured_handoffs:
        handoff = event["payload"]
        handoff_id = str(handoff["handoff_id"])
        challenge_id = str(handoff.get("challenge_id") or "")
        if _challenge_is_solved(canonical_challenges.get(challenge_id, {})):
            continue
        if not _current_continuations(
            events,
            challenge_id=challenge_id,
            objective_id=str(handoff.get("objective_id") or ""),
            current_generation=current_generation,
            handoff_id=handoff_id,
        ):
            unconsumed_handoff_ids.append(handoff_id)
    return {
        "current_generation": current_generation,
        "linked_low_progress": linked_low_progress,
        "routed": len(routed_ids),
        "routed_challenge_ids": routed_ids,
        "unrouted": len(unrouted_ids),
        "unrouted_challenge_ids": unrouted_ids,
        "legacy_unrouted": len(legacy),
        "legacy_unrouted_outcome_ids": sorted(
            str(event["payload"].get("outcome_id") or event.get("event_id") or "")
            for event in legacy
        ),
        "unharvested_active": len(unharvested_attempt_ids),
        "unharvested_active_attempt_ids": unharvested_attempt_ids,
        "unconsumed_handoffs": len(unconsumed_handoff_ids),
        "unconsumed_handoff_ids": sorted(unconsumed_handoff_ids),
        "closed_without_handoff": len(closed_without_handoff_ids),
        "closed_without_handoff_attempt_ids": closed_without_handoff_ids,
        "reconciliation_debts": len(reconciliation_debt_attempt_ids),
        "reconciliation_debt_attempt_ids": reconciliation_debt_attempt_ids,
        "reconciliation_debt_report_paths": reconciliation_debt_report_paths,
        "legacy_file_only_harvests": sum(
            1
            for event in events
            if event["event_type"] == "report.harvested"
            and not bool(event["payload"].get("structured"))
        ),
    }


def confusion_brake(
    store: EventStore, objective_id: str, mechanism: str
) -> dict[str, Any]:
    rows = [
        e
        for e in store.events("outcome.recorded")
        if str(e["payload"].get("objective_id")) == str(objective_id)
        and e["payload"].get("mechanism") == mechanism
    ]
    equivalent = [
        e
        for e in rows
        if e["payload"].get("outcome_type")
        in {"technical_negative", "no_progress", "duplicate_trace"}
    ]
    return {
        "objective_id": str(objective_id),
        "mechanism": mechanism,
        "equivalent_trace_count": len(equivalent),
        "brake": len(equivalent) >= 3,
        "required": "name one discriminating test before same-mechanism fanout"
        if len(equivalent) >= 3
        else "none",
    }
