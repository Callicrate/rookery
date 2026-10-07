from __future__ import annotations

import json
import re
import unicodedata
import uuid
from pathlib import Path
from typing import Any

from .intake import solver_eligibility
from .reducers import canonical_challenges, control_resume_is_current
from .store import EventStore
from .util import canonical_json, file_lock, iso_now, sha256_bytes

ACTION_KINDS = {
    "flag",
    "free_text",
    "multi_objective",
    "handle_write",
    "proof_artifact",
    "no_submit_evidence",
}
REVIEW_VERDICTS = {"approved", "hold", "rejected", "needs_verifier"}
MAX_CONTINUATION_REFERENCE_BYTES = 512
TEXT_MUTATION_ACTION_KINDS = frozenset({"flag", "free_text"})
CHALLENGE_ELIGIBILITY_ERROR = "challenge is not currently solver-eligible"


def mutation_challenge_is_ready(
    root: Path | str,
    events: list[dict[str, Any]],
    *,
    objective_id: object,
    action_kind: object,
) -> bool:
    """Return whether a text mutation still targets one verified challenge."""

    if action_kind not in TEXT_MUTATION_ACTION_KINDS:
        return True
    challenge = canonical_challenges(events).get(str(objective_id or ""))
    return bool(
        isinstance(challenge, dict)
        and solver_eligibility(root, challenge)["ready"]
    )


def manifest_adapter_id(manifest: dict[str, Any]) -> str:
    """Return the one adapter selected by a resolved event manifest."""

    adapter = manifest.get("adapter")
    if not isinstance(adapter, dict):
        raise ValueError("manifest adapter configuration must be an object")
    adapter_id = adapter.get("id")
    if not isinstance(adapter_id, str) or not adapter_id:
        raise ValueError("manifest adapter id must be a nonempty string")
    return adapter_id


def _explicit_continuation_reference(value: str, *, field: str) -> str:
    """Validate an opaque handoff or challenge identifier without inference."""

    if not isinstance(value, str):
        raise ValueError(f"{field} must be text")
    if len(value.encode("utf-8")) > MAX_CONTINUATION_REFERENCE_BYTES:
        raise ValueError(f"{field} exceeds its byte limit")
    if value and value != value.strip():
        raise ValueError(f"{field} must not have surrounding whitespace")
    return value


def _parent_continuation_challenge(
    events: list[dict[str, Any]], parent_fingerprint: str
) -> str:
    """Return the explicit parent challenge only for one canonical retry edge."""

    proposals = {
        str(event["payload"].get("proposal_id") or ""): event["payload"]
        for event in events
        if event["event_type"] == "proposal.created"
        and isinstance(event.get("payload"), dict)
        and str(event["payload"].get("proposal_id") or "")
    }
    parents: list[dict[str, Any]] = []
    for event in events:
        if event["event_type"] not in {"execution.rejected", "execution.indeterminate"}:
            continue
        payload = event["payload"]
        if not isinstance(payload, dict):
            continue
        retry = payload.get("retry") or payload.get("rejection")
        if not isinstance(retry, dict) or retry.get("fingerprint") != parent_fingerprint:
            continue
        proposal = proposals.get(str(payload.get("proposal_id") or ""))
        if isinstance(proposal, dict):
            parents.append(proposal)
    if len(parents) != 1:
        raise ValueError("parent rejection fingerprint has no unique canonical proposal")
    challenge_id = parents[0].get("challenge_id")
    if not isinstance(challenge_id, str) or not challenge_id:
        raise ValueError("parent continuation has no explicit challenge_id")
    return challenge_id


def _normalized_candidate_value(exact_value: str, artifact_reference: str) -> str:
    """Normalize representation without discarding candidate-significant bytes."""

    return unicodedata.normalize("NFC", exact_value or artifact_reference)


def _candidate_hashes(
    objective_id: str,
    action_kind: str,
    exact_value: str,
    artifact_reference: str,
    attempt_scope: dict[str, Any],
) -> dict[str, str]:
    normalized_value_sha256 = sha256_bytes(
        _normalized_candidate_value(exact_value, artifact_reference).encode("utf-8")
    )
    candidate_identity_sha256 = sha256_bytes(
        canonical_json(
            {
                "action_kind": action_kind,
                "attempt_scope_sha256": sha256_bytes(
                    canonical_json(attempt_scope).encode("utf-8")
                ),
                "normalized_value_sha256": normalized_value_sha256,
                "objective_id": str(objective_id),
            }
        ).encode("utf-8")
    )
    return {
        "value_sha256": sha256_bytes(exact_value.encode("utf-8"))
        if exact_value
        else "",
        "attempt_scope_sha256": sha256_bytes(
            canonical_json(attempt_scope).encode("utf-8")
        ),
        "normalized_value_sha256": normalized_value_sha256,
        "candidate_identity_sha256": candidate_identity_sha256,
    }


def _proposal_identity(proposal: dict[str, Any]) -> str:
    existing = str(proposal.get("candidate_identity_sha256") or "")
    if existing:
        return existing
    return _candidate_hashes(
        str(proposal.get("objective_id") or ""),
        str(proposal.get("action_kind") or ""),
        str(proposal.get("exact_value") or ""),
        str(proposal.get("artifact_reference") or ""),
        proposal.get("attempt_scope") or {},
    )["candidate_identity_sha256"]


def terminal_retry_metadata(
    plan: dict[str, Any],
    proposal: dict[str, Any],
    verdict: dict[str, Any],
    *,
    terminal_state: str,
) -> dict[str, str]:
    """Return privacy-safe retry lineage shared by execution and reconciliation."""

    verdict_sha256 = sha256_bytes(canonical_json(verdict).encode("utf-8"))
    candidate_identity_sha256 = str(proposal.get("candidate_identity_sha256") or "")
    return {
        "fingerprint": sha256_bytes(
            canonical_json(
                {
                    "candidate_identity_sha256": candidate_identity_sha256,
                    "objective_id": str(plan["objective_id"]),
                    "terminal_state": terminal_state,
                    "verdict_sha256": verdict_sha256,
                }
            ).encode("utf-8")
        ),
        "candidate_identity_sha256": candidate_identity_sha256,
        "normalized_value_sha256": str(
            proposal.get("normalized_value_sha256") or ""
        ),
        "verdict_sha256": verdict_sha256,
        "terminal_state": terminal_state,
    }


def _admission_history(
    con: Any, candidate_identity_sha256: str
) -> tuple[bool, bool, set[str], set[str]]:
    """Return accepted/nonterminal state and known retry fingerprints from canonical rows."""

    rows = con.execute(
        "SELECT event_type,payload_json FROM events ORDER BY seq"
    ).fetchall()
    proposals: dict[str, dict[str, Any]] = {}
    execution_states: dict[str, set[str]] = {}
    retry_fingerprints: set[str] = set()
    matching_retry_fingerprints: set[str] = set()
    for row in rows:
        event_type = str(row["event_type"])
        payload = json.loads(row["payload_json"])
        if event_type == "proposal.created":
            proposal_id = str(payload.get("proposal_id") or "")
            if proposal_id:
                proposals[proposal_id] = payload
            continue
        if not event_type.startswith("execution."):
            continue
        proposal_id = str(payload.get("proposal_id") or "")
        if not proposal_id:
            continue
        state = event_type.split(".", 1)[1]
        execution_states.setdefault(proposal_id, set()).add(state)
        if state not in {"rejected", "indeterminate"}:
            continue
        retry = payload.get("retry") or payload.get("rejection") or {}
        fingerprint = str(retry.get("fingerprint") or "")
        if not fingerprint:
            continue
        retry_fingerprints.add(fingerprint)
        prior = proposals.get(proposal_id, {})
        prior_identity = str(
            retry.get("candidate_identity_sha256") or ""
        ) or _proposal_identity(prior)
        if prior_identity == candidate_identity_sha256:
            matching_retry_fingerprints.add(fingerprint)

    has_accepted = False
    has_nonterminal = False
    for proposal_id, proposal in proposals.items():
        if _proposal_identity(proposal) != candidate_identity_sha256:
            continue
        states = execution_states.get(proposal_id, set())
        if "completed" in states:
            has_accepted = True
        elif states & {"rejected", "indeterminate"}:
            continue
        else:
            has_nonterminal = True
    return (
        has_accepted,
        has_nonterminal,
        retry_fingerprints,
        matching_retry_fingerprints,
    )


def _require_active_proposal_attempt(
    con: Any,
    *,
    agent_attempt_id: str,
    actor: str,
    objective_id: str,
) -> None:
    """Require proposal lineage to name the actor's live exact attempt."""

    rows = con.execute(
        "SELECT event_type,payload_json FROM events ORDER BY seq"
    ).fetchall()
    registration: dict[str, Any] | None = None
    latest_type = ""
    for row in rows:
        event_type = str(row["event_type"])
        if not event_type.startswith("agent."):
            continue
        payload = json.loads(row["payload_json"])
        if str(payload.get("agent_attempt_id") or "") != agent_attempt_id:
            continue
        if event_type == "agent.running":
            if registration is not None:
                raise ValueError("proposal agent attempt has multiple registrations")
            registration = payload
        latest_type = event_type
    if registration is None:
        raise ValueError("proposal requires an active registered agent attempt")
    if str(registration.get("agent_id") or "") != actor:
        raise ValueError("proposal agent registration does not match actor")
    if str(registration.get("objective_id") or "") != objective_id:
        raise ValueError("proposal agent registration does not match objective")
    if latest_type.rsplit(".", 1)[-1] not in {"assigned", "running"}:
        raise ValueError("proposal requires an active registered agent attempt")


def proposal_and_review_bind_current_generation(
    proposal: dict[str, Any] | None,
    review: dict[str, Any] | None,
    *,
    stop_generation: int,
    policy_generation: int,
) -> bool:
    """Require the proposal and latest approval to attest to current state."""

    if (
        not isinstance(proposal, dict)
        or not isinstance(review, dict)
        or not proposal
        or not review
        or review.get("verdict") != "approved"
    ):
        return False
    return (
        _generation_value_is_current(
            proposal.get("stop_generation"), stop_generation
        )
        and _generation_value_is_current(
            proposal.get("policy_generation"), policy_generation
        )
        and _generation_value_is_current(review.get("stop_generation"), stop_generation)
        and _generation_value_is_current(
            review.get("policy_generation"), policy_generation
        )
    )


def _is_generation(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _generation_value_is_current(value: Any, current: Any) -> bool:
    return _is_generation(value) and _is_generation(current) and value == current


def _generation_admission_reason(
    payload: dict[str, Any] | None,
    *,
    subject: str,
    field: str,
    current: Any,
) -> str:
    """Describe one generation predicate without coercing untrusted payloads."""

    if not isinstance(payload, dict) or field not in payload or payload[field] is None:
        return f"{subject} is missing {field}"
    if not _is_generation(payload[field]):
        return f"{subject} has malformed {field}"
    if not _is_generation(current):
        return f"current admission state has malformed {field}"
    if payload[field] != current:
        return f"{subject} belongs to a stale {field.replace('_', ' ')}"
    return ""


def admission_snapshot_in_transaction(con: Any) -> dict[str, Any]:
    """Read the complete admission state from the caller's SQLite transaction.

    Admission is deliberately derived from canonical control events rather than
    generated JSON.  A projection cannot safely turn a prior authorization
    into current authority merely because it was published after a stop.
    """

    rows = con.execute(
        "SELECT event_id,event_type,created_at,generation,actor,payload_json "
        "FROM events ORDER BY seq"
    ).fetchall()
    events = [
        {
            "event_id": str(row["event_id"]),
            "event_type": str(row["event_type"]),
            "created_at": str(row["created_at"]),
            "generation": int(row["generation"]),
            "actor": str(row["actor"]),
            "payload": json.loads(str(row["payload_json"])),
        }
        for row in rows
    ]
    stopped = False
    meta_rows = con.execute(
        "SELECT key,value FROM meta WHERE key IN "
        "('stop_generation','policy_generation','scope_generation')"
    ).fetchall()
    meta = {str(row["key"]): int(row["value"]) for row in meta_rows}
    stop_generation = meta.get("stop_generation", 0)
    for event in events:
        if event["event_type"] == "control.stop":
            stopped = True
        elif event["event_type"] == "control.resume":
            stopped = not control_resume_is_current(
                event, stop_generation=stop_generation
            )
    return {"events": events, "meta": meta, "stopped": stopped}


def _require_admission_open(snapshot: dict[str, Any]) -> None:
    if snapshot["stopped"]:
        raise RuntimeError("workspace is stopped; explicit resume is required")


def _generation_pair_matches(
    payload: dict[str, Any] | None,
    *,
    stop_generation: int,
    policy_generation: int,
) -> bool:
    return isinstance(payload, dict) and bool(payload) and _generation_value_is_current(
        payload.get("stop_generation"), stop_generation
    ) and _generation_value_is_current(
        payload.get("policy_generation"), policy_generation
    )


def admission_wait_reasons(
    current: dict[str, Any],
    proposal: dict[str, Any],
    review: dict[str, Any],
    authorization: dict[str, Any] | None,
) -> list[str]:
    """Return the shared display reasons for a proposal that cannot advance."""

    stop_generation = current.get("stop_generation")
    policy_generation = current.get("policy_generation")
    reasons: list[str] = []
    if current.get("stopped"):
        reasons.append("workspace is stopped; explicit resume is required")
    for subject, payload in (("proposal", proposal), ("review", review)):
        for field, generation in (
            ("stop_generation", stop_generation),
            ("policy_generation", policy_generation),
        ):
            reason = _generation_admission_reason(
                payload,
                subject=subject,
                field=field,
                current=generation,
            )
            if reason:
                reasons.append(reason)
    if not isinstance(review, dict) or review.get("verdict") != "approved":
        reasons.append("independent review is not approved")
    if (
        not isinstance(proposal, dict)
        or proposal.get("action_kind") != "no_submit_evidence"
    ) and not authorization:
        reasons.append("no action-specific authorization")
    return reasons


def lifecycle_from_events(events: list[dict[str, Any]], objective_id: str) -> dict[str, Any]:
    """Reduce only the lifecycle fields that execution pins in its plan."""

    challenge: dict[str, Any] = {}
    for event in events:
        payload = event["payload"]
        if event["event_type"] == "platform.snapshot":
            for candidate in payload.get("challenges", []):
                if str(candidate.get("id") or "") == objective_id:
                    challenge = {**challenge, **candidate}
        elif event["event_type"] == "challenge.upsert" and str(
            payload.get("id") or ""
        ) == objective_id:
            challenge = {**challenge, **payload}
    return challenge.get("attempt_scope", challenge.get("session_scope", {})) or {}


def create_proposal(
    store: EventStore,
    manifest: dict[str, Any],
    *,
    objective_id: str,
    action_kind: str,
    exact_value: str = "",
    artifact_reference: str = "",
    attempt_scope: dict[str, Any] | None = None,
    verifier_evidence: list[str] | None = None,
    adapter_id: str | None = None,
    policy_generation: int | None = None,
    freshness_requirements: dict[str, Any] | None = None,
    source: str,
    rationale: str,
    confidence: str = "candidate",
    agent_attempt_id: str = "",
    parent_rejection_fingerprint: str = "",
    discriminator: str = "",
    challenge_id: str = "",
    source_handoff_id: str = "",
    actor: str = "solver",
) -> dict[str, Any]:
    selected_adapter_id = manifest_adapter_id(manifest)
    if adapter_id is not None and adapter_id != selected_adapter_id:
        raise ValueError("proposal adapter_id must match the selected manifest adapter")
    if action_kind not in ACTION_KINDS:
        raise ValueError(f"unsupported action kind: {action_kind}")
    allowed = set(manifest.get("scoring", {}).get("action_kinds", []))
    if action_kind not in allowed:
        raise ValueError(f"action kind not declared by event: {action_kind}")
    if not objective_id or not source or not rationale:
        raise ValueError("objective_id, source, and rationale are required")
    if (
        action_kind != "proof_artifact"
        and action_kind != "no_submit_evidence"
        and exact_value == ""
    ):
        raise ValueError("exact_value is required for this action kind")
    if action_kind in {"proof_artifact", "no_submit_evidence"} and not (
        artifact_reference or exact_value
    ):
        raise ValueError("artifact_reference or exact_value is required")
    if parent_rejection_fingerprint and not re.fullmatch(
        r"[0-9a-f]{64}", parent_rejection_fingerprint
    ):
        raise ValueError(
            "parent rejection fingerprint must be 64 lowercase hex characters"
        )
    if parent_rejection_fingerprint and not discriminator.strip():
        raise ValueError("a follow-up proposal must name its discriminating change")
    if not parent_rejection_fingerprint and discriminator.strip():
        raise ValueError("a discriminator requires a parent rejection fingerprint")
    challenge_id = _explicit_continuation_reference(
        challenge_id, field="challenge_id"
    )
    source_handoff_id = _explicit_continuation_reference(
        source_handoff_id, field="source_handoff_id"
    )
    if parent_rejection_fingerprint and not challenge_id:
        raise ValueError("a continuation proposal requires an explicit challenge_id")
    if parent_rejection_fingerprint and not source_handoff_id:
        raise ValueError("a continuation proposal requires a source_handoff_id")
    pid = "prop_" + uuid.uuid4().hex
    normalized_attempt_scope = attempt_scope or {}
    hashes = _candidate_hashes(
        str(objective_id),
        action_kind,
        exact_value,
        artifact_reference,
        normalized_attempt_scope,
    )
    payload = {
        "proposal_id": pid,
        "solver": actor,
        "objective_id": str(objective_id),
        "action_kind": action_kind,
        "exact_value": exact_value,
        **hashes,
        "artifact_reference": artifact_reference,
        "attempt_scope": normalized_attempt_scope,
        "verifier_evidence": verifier_evidence or [],
        "adapter_id": selected_adapter_id,
        "freshness_requirements": freshness_requirements or {},
        "source": source,
        "rationale": rationale,
        "confidence": confidence,
        "agent_attempt_id": agent_attempt_id,
        "parent_rejection_fingerprint": parent_rejection_fingerprint,
        "discriminator": discriminator.strip(),
        "challenge_id": challenge_id,
        "source_handoff_id": source_handoff_id,
        "created_at": iso_now(),
    }

    def tx(con: Any) -> None:
        snapshot = admission_snapshot_in_transaction(con)
        _require_admission_open(snapshot)
        if not mutation_challenge_is_ready(
            store.root,
            snapshot["events"],
            objective_id=objective_id,
            action_kind=action_kind,
        ):
            raise ValueError(CHALLENGE_ELIGIBILITY_ERROR)
        if agent_attempt_id:
            _require_active_proposal_attempt(
                con,
                agent_attempt_id=agent_attempt_id,
                actor=actor,
                objective_id=str(objective_id),
            )
        has_accepted, has_nonterminal, known_retries, matching_retries = (
            _admission_history(con, hashes["candidate_identity_sha256"])
        )
        if (
            parent_rejection_fingerprint
            and parent_rejection_fingerprint not in known_retries
        ):
            raise ValueError(
                "parent rejection fingerprint is not present in canonical state"
            )
        if parent_rejection_fingerprint and _parent_continuation_challenge(
            snapshot["events"], parent_rejection_fingerprint
        ) != challenge_id:
            raise ValueError(
                "continuation challenge_id does not match its canonical parent"
            )
        if has_accepted or has_nonterminal:
            raise ValueError(
                "duplicate candidate already has a nonterminal or accepted attempt"
            )
        if matching_retries:
            if not parent_rejection_fingerprint:
                raise ValueError(
                    "identical candidate requires a parent rejection fingerprint"
                )
            if parent_rejection_fingerprint not in matching_retries:
                raise ValueError(
                    "parent rejection fingerprint does not identify this candidate"
                )
        stop_generation = snapshot["meta"].get("stop_generation", 0)
        current_policy_generation = snapshot["meta"].get("policy_generation", 0)
        if policy_generation is not None:
            try:
                supplied_policy_generation = int(policy_generation)
            except (TypeError, ValueError) as exc:
                raise ValueError("policy_generation must be an integer") from exc
            if supplied_policy_generation != current_policy_generation:
                raise ValueError("proposal policy_generation must match current state")
        payload["stop_generation"] = stop_generation
        payload["policy_generation"] = current_policy_generation
        payload["event_id"] = store.insert_in_transaction(
            con,
            "proposal.created",
            payload,
            actor=actor,
            generation=stop_generation,
        )

    # The control mutation lock orders proposal admission with stop and execution.
    with file_lock(store.root / "state" / "mutation.lock"):
        store.transaction(tx)
    return payload


def record_review(
    store: EventStore,
    proposal_id: str,
    verdict: str,
    *,
    reviewer: str,
    reason: str,
    verifier_report: str = "",
    actor: str = "reviewer",
) -> dict[str, Any]:
    if verdict not in REVIEW_VERDICTS:
        raise ValueError(f"unsupported review verdict: {verdict}")
    # Serialize review updates with execution so an approval cannot be withdrawn
    # between the mutation-boundary predicate check and adapter dispatch.
    with file_lock(store.root / "state" / "mutation.lock"):
        def tx(con: Any) -> dict[str, Any]:
            snapshot = admission_snapshot_in_transaction(con)
            _require_admission_open(snapshot)
            stop_generation = snapshot["meta"].get("stop_generation", 0)
            policy_generation = snapshot["meta"].get("policy_generation", 0)
            proposals = [
                event["payload"]
                for event in snapshot["events"]
                if event["event_type"] == "proposal.created"
                and str(event["payload"].get("proposal_id") or "") == proposal_id
            ]
            if len(proposals) != 1:
                raise KeyError(proposal_id)
            proposal = proposals[0]
            if not _generation_pair_matches(
                proposal,
                stop_generation=stop_generation,
                policy_generation=policy_generation,
            ):
                raise RuntimeError("proposal belongs to a stale generation")
            if not reviewer or not reason:
                raise ValueError("reviewer and reason are required")
            if reviewer == proposal.get("actor") or reviewer == proposal.get("solver"):
                raise ValueError("reviewer must be independent of the solver")
            payload = {
                "proposal_id": proposal_id,
                "verdict": verdict,
                "reviewer": reviewer,
                "reason": reason,
                "verifier_report": verifier_report,
                "reviewed_at": iso_now(),
                "stop_generation": stop_generation,
                "policy_generation": policy_generation,
            }
            payload["event_id"] = store.insert_in_transaction(
                con,
                "review.recorded",
                payload,
                actor=actor,
                generation=stop_generation,
            )
            return payload

        payload = store.transaction(tx)
    return payload


def grant_exact(
    store: EventStore,
    proposal_id: str,
    *,
    reason: str,
    actor: str = "operator",
    expected_stop_generation: int | None = None,
    expected_policy_generation: int | None = None,
) -> dict[str, Any]:
    aid = "auth_" + uuid.uuid4().hex
    with file_lock(store.root / "state" / "mutation.lock"):
        def tx(con: Any) -> dict[str, Any]:
            snapshot = admission_snapshot_in_transaction(con)
            _require_admission_open(snapshot)
            stop_generation = snapshot["meta"].get("stop_generation", 0)
            policy_generation = snapshot["meta"].get("policy_generation", 0)
            if (
                expected_stop_generation is not None
                and not _generation_value_is_current(
                    expected_stop_generation, stop_generation
                )
            ):
                raise RuntimeError("stop generation changed before authorization grant")
            if (
                expected_policy_generation is not None
                and not _generation_value_is_current(
                    expected_policy_generation, policy_generation
                )
            ):
                raise RuntimeError("policy generation changed before authorization grant")
            proposals = [
                event["payload"]
                for event in snapshot["events"]
                if event["event_type"] == "proposal.created"
                and str(event["payload"].get("proposal_id") or "") == proposal_id
            ]
            if len(proposals) != 1:
                raise KeyError(proposal_id)
            proposal = proposals[0]
            if not _generation_pair_matches(
                proposal,
                stop_generation=stop_generation,
                policy_generation=policy_generation,
            ):
                raise RuntimeError("proposal belongs to a stale generation")
            payload = {
                "authorization_id": aid,
                "mode": "exact",
                "proposal_id": proposal_id,
                "action_kind": proposal.get("action_kind"),
                "remaining": 1,
                "reason": reason,
                "granted_at": iso_now(),
                "stop_generation": stop_generation,
                "policy_generation": policy_generation,
            }
            store.insert_in_transaction(
                con,
                "authorization.granted",
                payload,
                actor=actor,
                generation=stop_generation,
            )
            return payload

        payload = store.transaction(tx)
    return payload


def grant_allowance(
    store: EventStore,
    manifest: dict[str, Any],
    action_kind: str,
    count: int,
    *,
    reason: str,
    actor: str = "operator",
    expected_stop_generation: int | None = None,
    expected_policy_generation: int | None = None,
) -> dict[str, Any]:
    if action_kind not in ACTION_KINDS or count <= 0:
        raise ValueError("valid action kind and positive count required")
    if actor not in {"operator", "coordinator"}:
        raise ValueError("allowance actor must be operator or coordinator")
    permitted = set(
        manifest.get("authorization", {}).get("automation_permitted_action_kinds", [])
    )
    if action_kind not in permitted:
        raise RuntimeError(
            f"bounded allowance is not automation-permitted for action kind: {action_kind}"
        )
    aid = "auth_" + uuid.uuid4().hex
    with file_lock(store.root / "state" / "mutation.lock"):
        def tx(con: Any) -> dict[str, Any]:
            snapshot = admission_snapshot_in_transaction(con)
            _require_admission_open(snapshot)
            stop_generation = snapshot["meta"].get("stop_generation", 0)
            policy_generation = snapshot["meta"].get("policy_generation", 0)
            if (
                expected_stop_generation is not None
                and not _generation_value_is_current(
                    expected_stop_generation, stop_generation
                )
            ):
                raise RuntimeError("stop generation changed before authorization grant")
            if (
                expected_policy_generation is not None
                and not _generation_value_is_current(
                    expected_policy_generation, policy_generation
                )
            ):
                raise RuntimeError("policy generation changed before authorization grant")
            payload = {
                "authorization_id": aid,
                "mode": "allowance",
                "action_kind": action_kind,
                "remaining": int(count),
                "reason": reason,
                "granted_at": iso_now(),
                "stop_generation": stop_generation,
                "policy_generation": policy_generation,
                "authority_source": (
                    "operator"
                    if actor == "operator"
                    else "operator_configured_automation"
                ),
            }
            store.insert_in_transaction(
                con,
                "authorization.granted",
                payload,
                actor=actor,
                generation=stop_generation,
            )
            return payload

        payload = store.transaction(tx)
    return payload


def available_authorization(
    store: EventStore,
    proposal: dict[str, Any],
    *,
    authorization_id: str | None = None,
    excluded_authorization_ids: set[str] | None = None,
) -> dict[str, Any] | None:
    snapshot = store.read_snapshot()
    projection = store.projection_from_snapshot(snapshot)
    current = projection["current"]
    if current.get("stopped"):
        return None
    current_generation = int(current.get("stop_generation", 0) or 0)
    current_policy_generation = int(current.get("policy_generation", 0) or 0)
    review = projection["current"]["reviews"].get(
        str(proposal.get("proposal_id") or ""), {}
    )
    if not proposal_and_review_bind_current_generation(
        proposal,
        review,
        stop_generation=current_generation,
        policy_generation=current_policy_generation,
    ):
        return None
    excluded = excluded_authorization_ids or set()
    exact: list[dict[str, Any]] = []
    allowance: list[dict[str, Any]] = []
    for row in current["authorizations"].values():
        if str(row.get("authorization_id") or "") in excluded:
            continue
        if (
            authorization_id is not None
            and row.get("authorization_id") != authorization_id
        ):
            continue
        if row.get("status") != "granted" or int(row.get("remaining", 0) or 0) <= 0:
            continue
        if int(row.get("stop_generation", -1)) != current_generation:
            continue
        if int(row.get("policy_generation", -1)) != current_policy_generation:
            continue
        if row.get("mode") == "exact" and row.get("proposal_id") == proposal.get(
            "proposal_id"
        ):
            exact.append(row)
        elif row.get("mode") == "allowance" and row.get("action_kind") == proposal.get(
            "action_kind"
        ):
            allowance.append(row)
    rows = exact or allowance
    return sorted(rows, key=lambda x: x.get("event_at", ""))[0] if rows else None


def _canonical_planned_plan(con: Any, plan_id: str) -> dict[str, Any]:
    rows = con.execute(
        "SELECT payload_json FROM events WHERE event_type='execution.planned' "
        "ORDER BY seq"
    ).fetchall()
    matching = []
    for row in rows:
        payload = json.loads(row["payload_json"])
        if str(payload.get("plan_id") or "") == plan_id:
            matching.append(payload)
    if len(matching) != 1:
        raise RuntimeError("execution plan has no unique canonical planned record")
    recorded = matching[0]
    plan_path = str(recorded.pop("plan_path", "")).replace("\\", "/")
    if plan_path != f"state/execution_plans/{plan_id}.json":
        raise RuntimeError("canonical execution plan path does not match plan id")
    if str(recorded.get("plan_id") or "") != plan_id:
        raise RuntimeError("canonical execution plan identifier is invalid")
    expected_sha256 = str(recorded.get("plan_sha256") or "")
    computed_sha256 = sha256_bytes(
        canonical_json(
            {key: value for key, value in recorded.items() if key != "plan_sha256"}
        ).encode("utf-8")
    )
    if not expected_sha256 or expected_sha256 != computed_sha256:
        raise RuntimeError("canonical execution plan integrity check failed")
    return recorded


def canonical_plan_for_execution(
    store: EventStore, loaded_plan: dict[str, Any]
) -> dict[str, Any]:
    """Return the canonical plan only when its mutable file is byte-equivalent."""

    plan_id = str(loaded_plan.get("plan_id") or "")
    if not plan_id:
        raise RuntimeError("execution plan is missing its plan id")

    def tx(con):
        canonical_plan = _canonical_planned_plan(con, plan_id)
        if canonical_json(canonical_plan) != canonical_json(loaded_plan):
            raise RuntimeError("execution plan file differs from canonical planned record")
        return canonical_plan

    return store.transaction(tx)


def claim_plan_authority(
    store: EventStore,
    plan: dict[str, Any],
    *,
    loaded_plan: dict[str, Any] | None = None,
    actor: str = "executor",
) -> dict[str, Any]:
    """Atomically revalidate immutable plan predicates and record its start."""

    plan_id = str(plan.get("plan_id") or "")
    proposal_id = str(plan.get("proposal_id") or "")
    action_kind = str(plan.get("semantic_action") or "")
    predicates = plan.get("predicates", {})
    envelope = plan.get("envelope")
    if not isinstance(predicates, dict):
        raise RuntimeError("execution plan predicates are invalid")
    if not isinstance(envelope, dict):
        raise RuntimeError("execution plan envelope is invalid")
    proposal_event_id = str(predicates.get("proposal_event_id") or "")
    review_event_id = str(predicates.get("review_event_id") or "")
    authorization_id = str(predicates.get("authorization_id") or "")
    if not plan_id or not proposal_id or not proposal_event_id or not review_event_id:
        raise RuntimeError("execution plan is missing immutable authority predicates")
    if action_kind == "no_submit_evidence":
        if authorization_id:
            raise RuntimeError("no-submit evidence plan must not carry authorization")
    elif not authorization_id:
        raise RuntimeError("execution plan is missing its authorization predicate")

    def tx(con):
        canonical_plan = _canonical_planned_plan(con, plan_id)
        source_plan = loaded_plan if loaded_plan is not None else plan
        if (
            canonical_json(canonical_plan) != canonical_json(plan)
            or canonical_json(canonical_plan) != canonical_json(source_plan)
        ):
            raise RuntimeError("execution plan file differs from canonical planned record")
        snapshot = admission_snapshot_in_transaction(con)
        _require_admission_open(snapshot)
        meta = snapshot["meta"]
        stop_generation = meta.get("stop_generation", 0)
        policy_generation = meta.get("policy_generation", 0)
        planned_scope_generation = int(predicates.get("scope_generation", -1))
        current_scope_generation = meta.get(
            "scope_generation", planned_scope_generation
        )
        if int(plan.get("generation", -1)) != stop_generation:
            raise RuntimeError("stop generation changed before authority claim")
        if int(plan.get("policy_generation", -1)) != policy_generation:
            raise RuntimeError("policy generation changed before authority claim")
        if planned_scope_generation != current_scope_generation:
            raise RuntimeError("scope generation changed before authority claim")

        rows = snapshot["events"]
        latest_review: tuple[str, dict[str, Any]] | None = None
        latest_authorization: tuple[str, dict[str, Any]] | None = None
        proposal: tuple[str, dict[str, Any]] | None = None
        planned_by_id: dict[str, dict[str, Any]] = {}
        started_by_plan: dict[str, dict[str, Any]] = {}
        indeterminate: list[dict[str, Any]] = []
        for row in rows:
            event_type = row["event_type"]
            payload = row["payload"]
            if (
                event_type == "proposal.created"
                and str(payload.get("proposal_id") or "") == proposal_id
            ):
                if proposal is not None:
                    raise RuntimeError("proposal has multiple canonical created records")
                proposal = (row["event_id"], payload)
            elif (
                event_type == "review.recorded"
                and str(payload.get("proposal_id") or "") == proposal_id
            ):
                latest_review = (row["event_id"], payload)
            elif (
                event_type.startswith("authorization.")
                and str(payload.get("authorization_id") or "") == authorization_id
            ):
                latest_authorization = (event_type, payload)
            elif event_type == "execution.planned":
                existing_plan_id = str(payload.get("plan_id") or "")
                if existing_plan_id:
                    planned_by_id[existing_plan_id] = payload
            elif event_type == "execution.started":
                existing_plan_id = str(payload.get("plan_id") or "")
                if existing_plan_id:
                    started_by_plan[existing_plan_id] = payload
            elif event_type in {"execution.indeterminate", "execution.failed"}:
                indeterminate.append(payload)

        if (
            latest_review is None
            or latest_review[0] != review_event_id
            or latest_review[1].get("verdict") != "approved"
        ):
            raise RuntimeError("plan review predicate is no longer the latest approval")
        if proposal is None or proposal[0] != proposal_event_id:
            raise RuntimeError("plan proposal predicate is no longer canonical")
        if not proposal_and_review_bind_current_generation(
            proposal[1],
            latest_review[1],
            stop_generation=stop_generation,
            policy_generation=policy_generation,
        ):
            raise RuntimeError(
                "proposal and latest approval must bind current generations"
            )
        if (
            str(plan.get("objective_id") or "")
            != str(proposal[1].get("objective_id") or "")
            or action_kind != str(proposal[1].get("action_kind") or "")
            or str(plan.get("adapter_id") or "")
            != str(proposal[1].get("adapter_id") or "")
            or str(envelope.get("adapter_id") or "")
            != str(proposal[1].get("adapter_id") or "")
            or canonical_json(plan.get("envelope", {}).get("attempt_scope", {}))
            != canonical_json(proposal[1].get("attempt_scope", {}))
        ):
            raise RuntimeError("plan envelope no longer matches its canonical proposal")
        if canonical_json(plan.get("lifecycle_refs", {})) != canonical_json(
            proposal[1].get("attempt_scope", {})
        ):
            raise RuntimeError("plan lifecycle no longer matches its canonical proposal")
        current_lifecycle = lifecycle_from_events(
            rows, str(plan.get("objective_id") or "")
        )
        if (
            plan.get("lifecycle_refs")
            and current_lifecycle
            and canonical_json(plan["lifecycle_refs"])
            != canonical_json(current_lifecycle)
        ):
            raise RuntimeError("lifecycle state changed before authority claim")
        if not mutation_challenge_is_ready(
            store.root,
            rows,
            objective_id=plan.get("objective_id"),
            action_kind=action_kind,
        ):
            raise RuntimeError(CHALLENGE_ELIGIBILITY_ERROR)

        for existing_plan_id, started in started_by_plan.items():
            if existing_plan_id == plan_id:
                raise RuntimeError("execution plan already has a durable start claim")
            if str(started.get("proposal_id") or "") != proposal_id:
                continue
            planned = planned_by_id.get(existing_plan_id, {})
            prior_review_event_id = str(
                started.get("review_event_id")
                or planned.get("predicates", {}).get("review_event_id")
                or ""
            )
            if prior_review_event_id == review_event_id:
                raise RuntimeError(
                    "proposal already has an execution claim for this review"
                )

        if action_kind == "no_submit_evidence":
            consumed = {
                "authorization_id": "",
                "remaining": 0,
                "mode": "none",
            }
        else:
            if (
                latest_authorization is None
                or latest_authorization[0] != "authorization.granted"
            ):
                raise RuntimeError("plan authorization predicate is unavailable")
            authorization = latest_authorization[1]
            remaining = int(authorization.get("remaining", 0) or 0)
            if remaining <= 0:
                raise RuntimeError("plan authorization predicate is exhausted")
            if int(authorization.get("stop_generation", -1)) != stop_generation:
                raise RuntimeError(
                    "plan authorization predicate belongs to a stale stop generation"
                )
            if int(authorization.get("policy_generation", -1)) != policy_generation:
                raise RuntimeError(
                    "plan authorization predicate belongs to a stale policy generation"
                )
            if str(authorization.get("action_kind") or "") != action_kind:
                raise RuntimeError(
                    "plan authorization predicate has an incompatible action kind"
                )
            mode = str(authorization.get("mode") or "")
            if (
                mode == "exact"
                and str(authorization.get("proposal_id") or "") != proposal_id
            ):
                raise RuntimeError(
                    "plan exact authorization predicate belongs to another proposal"
                )
            if mode not in {"exact", "allowance"}:
                raise RuntimeError(
                    "plan authorization predicate has an unsupported mode"
                )
            for terminal in indeterminate:
                if str(terminal.get("proposal_id") or "") != proposal_id:
                    continue
                terminal_plan_id = str(terminal.get("plan_id") or "")
                started = started_by_plan.get(terminal_plan_id, {})
                planned = planned_by_id.get(terminal_plan_id, {})
                prior_authorization_id = str(
                    started.get("authorization_id")
                    or planned.get("predicates", {}).get("authorization_id")
                    or ""
                )
                if prior_authorization_id == authorization_id:
                    raise RuntimeError(
                        "plan authorization predicate was already used by an indeterminate execution"
                    )

            consumed = {
                **authorization,
                "authorization_id": authorization_id,
                "remaining": remaining - 1,
                "consumed_for_plan": plan_id,
                "consumed_at": iso_now(),
            }
            store.insert_in_transaction(
                con,
                "authorization.consumed",
                consumed,
                actor=actor,
                generation=stop_generation,
            )
            if consumed["remaining"] > 0:
                store.insert_in_transaction(
                    con,
                    "authorization.granted",
                    consumed,
                    actor=actor,
                    generation=stop_generation,
                )

        store.insert_in_transaction(
            con,
            "execution.started",
            {
                "plan_id": plan_id,
                "proposal_id": proposal_id,
                "objective_id": plan.get("objective_id"),
                "action_kind": action_kind,
                "stop_generation": stop_generation,
                "policy_generation": policy_generation,
                "scope_generation": current_scope_generation,
                "review_event_id": review_event_id,
                "authorization_id": authorization_id,
                "started_at": iso_now(),
            },
            actor=actor,
            generation=stop_generation,
        )
        return consumed

    return store.transaction(tx)


def consume_authorization(
    store: EventStore,
    authorization: dict[str, Any],
    *,
    plan_id: str,
    execution_claim: dict[str, Any] | None = None,
    actor: str = "executor",
) -> dict[str, Any]:
    authorization_id = str(authorization.get("authorization_id") or "")
    if not authorization_id:
        raise RuntimeError("authorization id is required")

    def tx(con):
        snapshot = admission_snapshot_in_transaction(con)
        _require_admission_open(snapshot)
        if execution_claim is not None:
            execution_rows = con.execute(
                "SELECT event_type,payload_json FROM events "
                "WHERE event_type LIKE 'execution.%' ORDER BY seq DESC"
            ).fetchall()
            for execution_row in execution_rows:
                prior_execution = json.loads(execution_row["payload_json"])
                if str(prior_execution.get("plan_id") or "") != plan_id:
                    continue
                prior_status = str(execution_row["event_type"]).split(".", 1)[1]
                if prior_status in {
                    "started",
                    "completed",
                    "rejected",
                    "indeterminate",
                    "failed",
                }:
                    raise RuntimeError(f"execution plan is already {prior_status}")
        latest = None
        latest_status = ""
        rows = con.execute(
            "SELECT event_type,payload_json FROM events WHERE event_type LIKE 'authorization.%' ORDER BY seq DESC"
        ).fetchall()
        for row in rows:
            candidate = json.loads(row["payload_json"])
            if str(candidate.get("authorization_id") or "") == authorization_id:
                latest = candidate
                latest_status = str(row["event_type"]).split(".", 1)[1]
                break
        if latest is None or latest_status != "granted":
            raise RuntimeError("authorization unavailable")
        remaining = int(latest.get("remaining", 0) or 0)
        if remaining <= 0:
            raise RuntimeError("authorization exhausted")
        stop_generation = snapshot["meta"].get("stop_generation", 0)
        policy_generation = snapshot["meta"].get("policy_generation", 0)
        if int(latest.get("stop_generation", -1)) != stop_generation:
            raise RuntimeError("authorization belongs to a stale stop generation")
        if int(latest.get("policy_generation", -1)) != policy_generation:
            raise RuntimeError("authorization belongs to a stale policy generation")
        payload = {
            **latest,
            "authorization_id": authorization_id,
            "remaining": remaining - 1,
            "consumed_for_plan": plan_id,
            "consumed_at": iso_now(),
        }
        store.insert_in_transaction(
            con,
            "authorization.consumed",
            payload,
            actor=actor,
            generation=stop_generation,
        )
        if payload["remaining"] > 0:
            store.insert_in_transaction(
                con,
                "authorization.granted",
                payload,
                actor=actor,
                generation=stop_generation,
            )
        if execution_claim is not None:
            store.insert_in_transaction(
                con,
                "execution.started",
                execution_claim,
                actor=actor,
                generation=stop_generation,
            )
        return payload

    return store.transaction(tx)


def morphology_score(manifest: dict[str, Any], value: str) -> dict[str, Any]:
    regex = manifest.get("answer_morphology", {}).get("regex")
    examples = manifest.get("answer_morphology", {}).get("examples", [])
    if regex in {None, "", "unknown"}:
        return {"matched": None, "reason": "no morphology configured", "anomaly": False}
    matched = bool(re.fullmatch(str(regex), value))
    lengths = [len(str(x)) for x in examples if x]
    anomaly = not matched
    reason = "regex match" if matched else "value does not match configured morphology"
    if (
        matched
        and lengths
        and (len(value) < min(lengths) * 0.5 or len(value) > max(lengths) * 2.0)
    ):
        anomaly = True
        reason = "regex matched but length is anomalous versus accepted examples"
    return {"matched": matched, "reason": reason, "anomaly": anomaly}
