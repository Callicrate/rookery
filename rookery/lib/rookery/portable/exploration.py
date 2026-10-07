"""Durable, capacity-aware exploration campaigns for stalled challenges.

The controller records a small evidence-backed decision process.  It does not
start processes, read a platform, or cross the scoring boundary.  A selected
idea becomes an ordinary ``compute.idea.queued`` row and must still obtain a
current-generation compute lease before a capable worker can run it.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
import uuid
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

from .compute import (
    ACTIVE_AGENT_STATES,
    _queue_view,
    _transaction_snapshot,
    enqueue_compute_idea_in_transaction,
)
from .intake import solver_eligibility
from .store import EventStore
from .util import canonical_json, contained_private_path, file_lock, iso_now


LOW_PROGRESS_OUTCOMES = frozenset({"technical_negative", "no_progress", "incomplete_evidence", "duplicate_trace"})
LENS_ORDER = ("fresh", "evidence", "artifact", "contrarian")
MAX_ROUTE_KEYS = 64
MAX_IDEA_FILE_BYTES = 256 * 1024
MAX_SELECTED_IDEAS = 4
PACKET_SCHEMA_VERSION = "1"
IDEAS_TEMPLATE_PATH = "templates/IDEAS.json"
SELECTION_TEMPLATE_PATH = "templates/SELECTION.json"
_ROUTE_KEY_RE = re.compile(r"[a-z0-9][a-z0-9._:-]{0,127}\Z")
_ITEM_ID_RE = re.compile(r"[a-z][a-z0-9_-]{0,79}\Z")

IDEAS_REQUIRED_KEYS = (
    "campaign_id",
    "lens",
    "ideas",
)
IDEA_REQUIRED_KEYS = (
    "idea_id",
    "route_key",
    "next_step",
    "mechanism",
    "prerequisite_evidence",
    "discriminating_test",
    "estimated_cost_seconds",
    "expected_value",
    "evidence_value",
    "why_novel",
)
SELECTION_REQUIRED_KEYS = (
    "campaign_id",
    "selected_idea_ids",
    "rationale",
    "handoff_learning",
    "park_reason",
    "recheck_condition",
)

LENS_CONTRACTS: dict[str, dict[str, str]] = {
    "fresh": {
        "context": "title/category/hint, bounded inventory, and the proof gap",
        "lens": "Solve from first principles. Do not inherit a stale theory.",
    },
    "evidence": {
        "context": "current facts, evidence references, and negative route keys",
        "lens": "State what the evidence rules out and name a test that separates what remains.",
    },
    "artifact": {
        "context": "bounded local artifact references and metadata only; no chat recap",
        "lens": "Inspect concrete bytes, formats, code, or observed behavior.",
    },
    "contrarian": {
        "context": "evidence references plus the rejected-route index",
        "lens": "Find assumptions, missing prerequisite checks, and neglected technique families.",
    },
}


def _text(value: Any, label: str, *, maximum: int, minimum: int = 1) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be text")
    text = value.strip()
    if len(text) < minimum or len(text) > maximum:
        raise ValueError(f"{label} has an invalid length")
    if any(ord(character) < 0x20 for character in text):
        raise ValueError(f"{label} contains a control character")
    return text


def _route_key(value: Any, label: str = "route key") -> str:
    text = _text(value, label, maximum=128).lower()
    if not text.isascii() or not _ROUTE_KEY_RE.fullmatch(text):
        raise ValueError(f"{label} must be a lower-case portable route signature")
    return text


def _item_id(value: Any) -> str:
    text = _text(value, "idea ID", maximum=80).lower()
    if not text.isascii() or not _ITEM_ID_RE.fullmatch(text):
        raise ValueError("idea ID must be a lower-case portable identifier")
    return text


def _campaign_id(value: Any) -> str:
    text = _text(value, "campaign ID", maximum=128).lower()
    if not text.startswith("campaign_") or not _ITEM_ID_RE.fullmatch(text):
        raise ValueError("campaign ID must begin with campaign_ and be portable")
    return text


def _analysis_sidecar(root: Path, value: Any, *, label: str) -> tuple[Path, str]:
    """Resolve one existing, private JSON sidecar below ``analysis/`` safely."""

    text = _text(value, label, maximum=512).replace("\\", "/")
    windows = PureWindowsPath(text)
    path = PurePosixPath(text)
    if (
        path.is_absolute()
        or windows.is_absolute()
        or windows.drive
        or len(path.parts) < 2
        or path.parts[0] != "analysis"
        or any(part in {"", ".", ".."} for part in path.parts)
        or path.suffix.lower() != ".json"
    ):
        raise ValueError(f"{label} must be an analysis-relative JSON file")
    candidate = contained_private_path(root, root / "analysis", *path.parts[1:])
    try:
        info = candidate.lstat()
    except FileNotFoundError as exc:
        raise ValueError(f"{label} does not exist") from exc
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or info.st_size < 2
        or info.st_size > MAX_IDEA_FILE_BYTES
        or stat.S_IMODE(info.st_mode) & 0o077
    ):
        raise ValueError(f"{label} must be a bounded private regular file")
    return candidate, text


def _read_json_sidecar(root: Path, value: Any, *, label: str) -> tuple[dict[str, Any], str, str]:
    path, relative = _analysis_sidecar(root, value, label=label)
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > MAX_IDEA_FILE_BYTES:
            raise ValueError(f"{label} changed while opening")
        chunks: list[bytes] = []
        remaining = MAX_IDEA_FILE_BYTES + 1
        while remaining:
            block = os.read(descriptor, min(64 * 1024, remaining))
            if not block:
                break
            chunks.append(block)
            remaining -= len(block)
        data = b"".join(chunks)
        if len(data) > MAX_IDEA_FILE_BYTES:
            raise ValueError(f"{label} exceeds its byte limit")
    finally:
        os.close(descriptor)
    digest = hashlib.sha256(data).hexdigest()
    try:
        decoded = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is not valid UTF-8 JSON") from exc
    if not isinstance(decoded, dict):
        raise ValueError(f"{label} must contain a JSON object")
    return decoded, relative, digest


def _number(value: Any, label: str, *, minimum: float, maximum: float) -> float:
    if isinstance(value, bool):
        raise ValueError(f"{label} must be numeric")
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label} must be numeric") from exc
    if not math.isfinite(number) or not minimum <= number <= maximum:
        raise ValueError(f"{label} is outside its allowed range")
    return number


def _ideas_from_sidecar(
    root: Path,
    value: Any,
    *,
    campaign_id: str,
    lens: str,
) -> tuple[list[dict[str, Any]], str, str]:
    document, relative, digest = _read_json_sidecar(root, value, label="ideas file")
    if set(document) != {"campaign_id", "lens", "ideas"}:
        raise ValueError("ideas file must contain only campaign_id, lens, and ideas")
    if _campaign_id(document.get("campaign_id")) != campaign_id:
        raise ValueError("ideas file campaign ID does not match")
    if str(document.get("lens") or "").strip().lower() != lens:
        raise ValueError("ideas file lens does not match")
    raw_ideas = document.get("ideas")
    if not isinstance(raw_ideas, list) or len(raw_ideas) != 10:
        raise ValueError("each ideation pass must contain exactly ten ideas")
    ideas: list[dict[str, Any]] = []
    ids: set[str] = set()
    for raw in raw_ideas:
        if not isinstance(raw, dict):
            raise ValueError("every idea must be an object")
        required = {
            "idea_id",
            "route_key",
            "next_step",
            "mechanism",
            "prerequisite_evidence",
            "discriminating_test",
            "estimated_cost_seconds",
            "expected_value",
            "evidence_value",
            "why_novel",
        }
        if set(raw) != required:
            raise ValueError("idea fields do not match the exploration contract")
        item_id = _item_id(raw.get("idea_id"))
        if item_id in ids:
            raise ValueError("idea IDs must be distinct within their pass")
        ids.add(item_id)
        cost = int(_number(raw.get("estimated_cost_seconds"), "estimated cost", minimum=30, maximum=14_400))
        ideas.append(
            {
                "idea_id": item_id,
                "route_key": _route_key(raw.get("route_key")),
                "next_step": _text(raw.get("next_step"), "next step", maximum=1200, minimum=12),
                "mechanism": _text(raw.get("mechanism"), "mechanism", maximum=512, minimum=3),
                "prerequisite_evidence": _text(
                    raw.get("prerequisite_evidence"), "prerequisite evidence", maximum=1000, minimum=3
                ),
                "discriminating_test": _text(
                    raw.get("discriminating_test"), "discriminating test", maximum=1000, minimum=3
                ),
                "estimated_cost_seconds": cost,
                "expected_value": _number(raw.get("expected_value"), "expected value", minimum=0, maximum=100),
                "evidence_value": _number(raw.get("evidence_value"), "evidence value", minimum=0, maximum=100),
                "why_novel": _text(raw.get("why_novel"), "why novel", maximum=1000, minimum=3),
            }
        )
    return ideas, relative, digest


def _selection_from_sidecar(
    root: Path, value: Any, *, campaign_id: str
) -> tuple[list[str], str, str, str, str, str, str]:
    document, relative, digest = _read_json_sidecar(root, value, label="selection file")
    if set(document) != {
        "campaign_id",
        "selected_idea_ids",
        "rationale",
        "handoff_learning",
        "park_reason",
        "recheck_condition",
    }:
        raise ValueError(
            "selection file must contain campaign_id, selected_idea_ids, rationale, handoff_learning, park_reason, and recheck_condition"
        )
    if _campaign_id(document.get("campaign_id")) != campaign_id:
        raise ValueError("selection file campaign ID does not match")
    raw_ids = document.get("selected_idea_ids")
    if not isinstance(raw_ids, list) or len(raw_ids) > MAX_SELECTED_IDEAS:
        raise ValueError(f"selection must contain at most {MAX_SELECTED_IDEAS} ideas")
    selected = [_item_id(value) for value in raw_ids]
    if len(set(selected)) != len(selected):
        raise ValueError("selection has duplicate idea IDs")
    return (
        selected,
        _text(document.get("rationale"), "selection rationale", maximum=2000, minimum=3),
        _text(document.get("handoff_learning"), "handoff learning", maximum=2000, minimum=3),
        str(document.get("park_reason") or "").strip(),
        str(document.get("recheck_condition") or "").strip(),
        relative,
        digest,
    )


def _campaigns(current: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows = current.get("exploration_campaigns", {})
    if not isinstance(rows, dict):
        return {}
    return rows


def _active_campaign_for_challenge(current: dict[str, Any], challenge_id: str) -> bool:
    return any(
        str(row.get("challenge_id") or "") == challenge_id and str(row.get("status") or "") not in {"closed", "stale"}
        for row in _campaigns(current).values()
    )


def _current_generation(meta: dict[str, str]) -> int:
    return int(meta.get("stop_generation", "0"))


def _ensure_open(current: dict[str, Any], campaign_id: str) -> dict[str, Any]:
    campaign = _campaigns(current).get(campaign_id)
    if not campaign:
        raise ValueError("exploration campaign was not found")
    if campaign.get("effective_status") == "stale":
        raise RuntimeError("exploration campaign belongs to a stale stop generation")
    if campaign.get("status") != "active":
        raise RuntimeError("exploration campaign is not active")
    return campaign


def _active_campaign_attempt(
    current: dict[str, Any],
    campaign: dict[str, Any],
    *,
    agent_attempt_id: str,
) -> dict[str, Any]:
    """Require a real current worker carrying this campaign's handoff."""

    matches = [
        row
        for row in current.get("agents", {}).values()
        if str(row.get("agent_attempt_id") or "") == agent_attempt_id and row.get("status") in ACTIVE_AGENT_STATES
    ]
    if len(matches) != 1:
        raise ValueError("campaign work requires one active registered agent attempt")
    attempt = matches[0]
    if (
        str(attempt.get("challenge_id") or "") != str(campaign.get("challenge_id") or "")
        or str(attempt.get("objective_id") or "") != str(campaign.get("objective_id") or "")
        or str(attempt.get("source_handoff_id") or "") != str(campaign.get("source_handoff_id") or "")
        or int(attempt.get("stop_generation", -1)) != int(campaign.get("stop_generation", -1))
        or not str(attempt.get("report_path") or "").startswith("analysis/")
    ):
        raise ValueError("agent attempt does not match campaign challenge, handoff, and report contract")
    return attempt


def _attempt_structured_handoff(
    current: dict[str, Any],
    campaign: dict[str, Any],
    attempt: dict[str, Any],
    *,
    handoff_id: str,
) -> dict[str, Any]:
    """Require the exact useful handoff produced by a claimed campaign worker."""

    handoff_id = _text(handoff_id, "worker handoff ID", maximum=256)
    rows = [
        row for row in current.get("harvested_reports", {}).values() if str(row.get("handoff_id") or "") == handoff_id
    ]
    if len(rows) != 1:
        raise ValueError("campaign worker requires one exact structured handoff")
    handoff = rows[0]
    if (
        not handoff.get("structured")
        or str(handoff.get("agent_attempt_id") or "") != str(attempt.get("agent_attempt_id") or "")
        or str(handoff.get("agent_id") or "") != str(attempt.get("agent_id") or "")
        or str(handoff.get("report_path") or "") != str(attempt.get("report_path") or "")
        or str(handoff.get("challenge_id") or "") != str(campaign.get("challenge_id") or "")
        or str(handoff.get("objective_id") or "") != str(campaign.get("objective_id") or "")
        or int(handoff.get("stop_generation", -1)) != int(campaign.get("stop_generation", -1))
        or not str(handoff.get("sha256") or "")
        or not str(handoff.get("proof_gap") or "")
    ):
        raise ValueError("campaign worker handoff does not match its claimed attempt")
    return handoff


def _source_attempt_is_active(
    current: dict[str, Any],
    *,
    source_agent_attempt_id: str,
    challenge_id: str,
    objective_id: str,
    generation: int,
) -> bool:
    return any(
        str(row.get("agent_attempt_id") or "") == source_agent_attempt_id
        and str(row.get("challenge_id") or "") == challenge_id
        and str(row.get("objective_id") or "") == objective_id
        and row.get("status") in ACTIVE_AGENT_STATES
        and int(row.get("stop_generation", -1)) == generation
        for row in current.get("agents", {}).values()
    )


def _structured_handoff(
    current: dict[str, Any],
    *,
    handoff_id: str,
    challenge_id: str,
    objective_id: str,
    generation: int,
) -> dict[str, Any]:
    """Find one exact current structured handoff, never a hash-only report."""

    rows = [
        row for row in current.get("harvested_reports", {}).values() if str(row.get("handoff_id") or "") == handoff_id
    ]
    if len(rows) != 1:
        raise ValueError("campaign requires one exact structured handoff")
    handoff = rows[0]
    if (
        str(handoff.get("challenge_id") or "") != challenge_id
        or str(handoff.get("objective_id") or "") != objective_id
        or int(handoff.get("stop_generation", -1)) != generation
        or str(handoff.get("status") or "") not in LOW_PROGRESS_OUTCOMES
    ):
        raise ValueError("structured handoff is not current low-progress evidence for this challenge")
    required = (
        "agent_attempt_id",
        "report_path",
        "sha256",
        "route_key",
        "proof_gap",
        "next_step_or_return_trigger",
    )
    if any(not str(handoff.get(key) or "").strip() for key in required):
        raise ValueError("structured handoff is incomplete")
    return handoff


def _artifact_path(report_path: object, filename: str) -> str:
    """Derive the only sidecar location that one assigned worker may return."""

    report = PurePosixPath(_text(report_path, "worker report path", maximum=512))
    if (
        report.is_absolute()
        or report.parts[:1] != ("analysis",)
        or report.name != "REPORT.md"
        or any(part in {"", ".", ".."} for part in report.parts)
    ):
        raise ValueError("worker report path cannot derive an exploration artifact")
    return report.with_name(filename).as_posix()


def _packet_digest(packet: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(packet).encode("utf-8")).hexdigest()


def _campaign_source_packet(campaign: dict[str, Any]) -> dict[str, str]:
    return {
        "handoff_id": str(campaign["source_handoff_id"]),
        "report_path": str(campaign["source_handoff_report_path"]),
        "sha256": str(campaign["source_handoff_sha256"]),
        "proof_gap": str(campaign["source_handoff_proof_gap"]),
        "next_step_or_return_trigger": str(campaign["source_handoff_next_step_or_return_trigger"]),
    }


def _ideation_packet(
    campaign: dict[str, Any],
    attempt: dict[str, Any],
    *,
    lens: str,
    generation: int,
) -> dict[str, Any]:
    """Build the full no-score assignment contract before an ideator starts."""

    return {
        "schema_version": PACKET_SCHEMA_VERSION,
        "kind": "exploration.ideation",
        "campaign_id": campaign["campaign_id"],
        "challenge_id": campaign["challenge_id"],
        "objective_id": campaign["objective_id"],
        "stop_generation": generation,
        "worker": {
            "agent_id": attempt["agent_id"],
            "agent_attempt_id": attempt["agent_attempt_id"],
            "role": attempt["role"],
            "report_path": attempt["report_path"],
        },
        "source_handoff": _campaign_source_packet(campaign),
        "lens": {
            "id": lens,
            "context": LENS_CONTRACTS[lens]["context"],
            "instruction": LENS_CONTRACTS[lens]["lens"],
        },
        "known_route_keys": list(campaign.get("known_route_keys", [])),
        "artifact": {
            "path": _artifact_path(attempt["report_path"], "IDEAS.json"),
            "template": IDEAS_TEMPLATE_PATH,
            "required_keys": list(IDEAS_REQUIRED_KEYS),
            "idea_required_keys": list(IDEA_REQUIRED_KEYS),
            "exact_idea_count": 10,
        },
        "return_condition": "Write exactly ten distinct structured ideas to the assigned IDEAS.json path, then return its private relative path and the structured handoff.",
        "forbidden_actions": ["score", "dispatch"],
    }


def _synthesis_inputs(campaign: dict[str, Any]) -> list[dict[str, str]]:
    inputs: list[dict[str, str]] = []
    for lens in LENS_ORDER:
        batch = campaign.get("idea_batches", {}).get(lens)
        if not isinstance(batch, dict):
            raise ValueError("synthesis packet requires every ideation batch")
        inputs.append(
            {
                "lens": lens,
                "ideas_file": str(batch.get("ideas_file") or ""),
                "ideas_sha256": str(batch.get("ideas_sha256") or ""),
                "source_handoff_id": str(batch.get("source_handoff_id") or ""),
                "handoff_sha256": str(batch.get("handoff_sha256") or ""),
            }
        )
    if any(not all(row.values()) for row in inputs):
        raise ValueError("synthesis packet contains an incomplete ideation batch")
    return inputs


def _synthesis_packet(
    current: dict[str, Any],
    campaign: dict[str, Any],
    attempt: dict[str, Any],
    *,
    generation: int,
) -> dict[str, Any]:
    """Build the independent synthesis contract after all four batches exist."""

    ideator_attempt_ids = sorted(
        str(row.get("agent_attempt_id") or "") for row in campaign.get("ideation_claims", {}).values()
    )
    return {
        "schema_version": PACKET_SCHEMA_VERSION,
        "kind": "exploration.synthesis",
        "campaign_id": campaign["campaign_id"],
        "challenge_id": campaign["challenge_id"],
        "objective_id": campaign["objective_id"],
        "stop_generation": generation,
        "worker": {
            "agent_id": attempt["agent_id"],
            "agent_attempt_id": attempt["agent_attempt_id"],
            "role": attempt["role"],
            "report_path": attempt["report_path"],
        },
        "source_handoff": _campaign_source_packet(campaign),
        "ideation_inputs": _synthesis_inputs(campaign),
        "tried_route_keys": sorted(_route_keys_already_tried(current, campaign)),
        "artifact": {
            "path": _artifact_path(attempt["report_path"], "SELECTION.json"),
            "template": SELECTION_TEMPLATE_PATH,
            "required_keys": list(SELECTION_REQUIRED_KEYS),
            "maximum_selected_ideas": MAX_SELECTED_IDEAS,
        },
        "return_condition": "Write one structured SELECTION.json to the assigned path. Select only eligible ideas, or provide both park_reason and recheck_condition when none remain.",
        "independence": {"must_not_be_agent_attempt_ids": ideator_attempt_ids},
        "forbidden_actions": ["score", "dispatch"],
    }


def _require_current_campaign_source(
    current: dict[str, Any], campaign: dict[str, Any], *, generation: int
) -> dict[str, Any]:
    return _structured_handoff(
        current,
        handoff_id=str(campaign["source_handoff_id"]),
        challenge_id=str(campaign["challenge_id"]),
        objective_id=str(campaign["objective_id"]),
        generation=generation,
    )


def _require_current_packet(
    packet: object,
    packet_sha256: object,
    expected: dict[str, Any],
    *,
    label: str,
) -> dict[str, Any]:
    if not isinstance(packet, dict) or not isinstance(packet_sha256, str):
        raise ValueError(f"{label} assignment packet is missing")
    if _packet_digest(packet) != packet_sha256:
        raise ValueError(f"{label} assignment packet digest is invalid")
    if canonical_json(packet) != canonical_json(expected):
        raise ValueError(f"{label} assignment packet is stale or does not match the current campaign")
    return packet


def open_campaign(
    store: EventStore,
    *,
    challenge_id: str,
    objective_id: str,
    source_handoff_id: str,
    route_keys: list[str],
    campaign_id: str = "",
    actor: str = "coordinator",
) -> dict[str, Any]:
    """Open one durable route before an unsolved lane leaves the frontier.

    A campaign consumes a structured harvest before the source attempt records
    its matching outcome.  That makes the next route durable even if the
    coordinator stops between harvest, outcome, and close.
    """

    challenge_id = _text(challenge_id, "challenge ID", maximum=256)
    objective_id = _text(objective_id, "objective ID", maximum=256)
    source_handoff_id = _text(source_handoff_id, "source handoff ID", maximum=256)
    normalized_routes = [_route_key(value) for value in route_keys]
    if not normalized_routes or len(normalized_routes) > MAX_ROUTE_KEYS:
        raise ValueError(f"provide between one and {MAX_ROUTE_KEYS} known route keys")
    if len(set(normalized_routes)) != len(normalized_routes):
        raise ValueError("known route keys must be distinct")
    campaign_id = _campaign_id(campaign_id or "campaign_" + uuid.uuid4().hex)

    with file_lock(store.root / "state" / "mutation.lock"):

        def tx(connection: Any) -> dict[str, Any]:
            events, meta = _transaction_snapshot(connection)
            current, _ = _queue_view(events, meta)
            generation = _current_generation(meta)
            if current.get("stopped"):
                raise RuntimeError("workspace is stopped; explicit resume is required")
            challenge = current.get("challenges", {}).get(challenge_id)
            if not isinstance(challenge, dict):
                raise ValueError("exploration campaign requires a visible challenge")
            if challenge.get("solved") or challenge.get("classification") == "solved":
                raise ValueError("exploration campaign cannot target a solved challenge")
            if not solver_eligibility(store.root, challenge)["ready"]:
                raise ValueError("challenge intake is not solver-ready")
            if campaign_id in _campaigns(current):
                raise ValueError("exploration campaign ID already exists")
            if _active_campaign_for_challenge(current, challenge_id):
                raise ValueError("challenge already has a current exploration campaign")
            handoff = _structured_handoff(
                current,
                handoff_id=source_handoff_id,
                challenge_id=challenge_id,
                objective_id=objective_id,
                generation=generation,
            )
            source_agent_attempt_id = str(handoff["agent_attempt_id"])
            if not _source_attempt_is_active(
                current,
                source_agent_attempt_id=source_agent_attempt_id,
                challenge_id=challenge_id,
                objective_id=objective_id,
                generation=generation,
            ):
                raise ValueError("structured handoff source attempt is no longer active and cannot open a next route")
            handoff_route = _route_key(handoff["route_key"], "handoff route key")
            if handoff_route not in normalized_routes:
                normalized_routes.append(handoff_route)
            if len(normalized_routes) > MAX_ROUTE_KEYS:
                raise ValueError("known route keys exceed the campaign limit")
            payload = {
                "campaign_id": campaign_id,
                "challenge_id": challenge_id,
                "objective_id": objective_id,
                "continuation_kind": "exploration_campaign",
                "continuation_id": campaign_id,
                "known_route_keys": normalized_routes,
                "lenses": list(LENS_ORDER),
                "source_agent_attempt_id": source_agent_attempt_id,
                "source_handoff_id": source_handoff_id,
                "source_handoff_report_path": str(handoff["report_path"]),
                "source_handoff_sha256": str(handoff["sha256"]),
                "source_handoff_route_key": handoff_route,
                "source_handoff_proof_gap": _text(handoff["proof_gap"], "handoff proof gap", maximum=2000, minimum=3),
                "source_handoff_next_step_or_return_trigger": _text(
                    handoff["next_step_or_return_trigger"],
                    "handoff next step or return trigger",
                    maximum=2000,
                    minimum=3,
                ),
                "handoff_use": "exploration_campaign",
                "handoff_consumed_at": iso_now(),
                "status": "active",
                "stop_generation": generation,
                "opened_at": iso_now(),
            }
            store.insert_in_transaction(
                connection,
                "exploration.campaign.opened",
                payload,
                actor=actor,
                generation=generation,
            )
            return payload

        result = store.transaction(tx)
    store.rebuild()
    return result


def claim_ideation(
    store: EventStore,
    *,
    campaign_id: str,
    lens: str,
    agent_attempt_id: str,
    actor: str = "coordinator",
) -> dict[str, Any]:
    campaign_id = _campaign_id(campaign_id)
    lens = str(lens or "").strip().lower()
    if lens not in LENS_CONTRACTS:
        raise ValueError("ideation lens is invalid")
    agent_attempt_id = _text(agent_attempt_id, "ideation agent attempt ID", maximum=256)
    with file_lock(store.root / "state" / "mutation.lock"):

        def tx(connection: Any) -> dict[str, Any]:
            events, meta = _transaction_snapshot(connection)
            current, _ = _queue_view(events, meta)
            campaign = _ensure_open(current, campaign_id)
            attempt = _active_campaign_attempt(current, campaign, agent_attempt_id=agent_attempt_id)
            claims = campaign.get("ideation_claims", {})
            batches = campaign.get("idea_batches", {})
            if lens in claims or lens in batches:
                raise ValueError("ideation lens has already been claimed")
            if agent_attempt_id in {str(row.get("agent_attempt_id") or "") for row in claims.values()}:
                raise ValueError("each ideation lens requires a distinct worker")
            generation = _current_generation(meta)
            _require_current_campaign_source(current, campaign, generation=generation)
            assignment_packet = _ideation_packet(campaign, attempt, lens=lens, generation=generation)
            payload = {
                "campaign_id": campaign_id,
                "challenge_id": campaign["challenge_id"],
                "objective_id": campaign["objective_id"],
                "lens": lens,
                "agent_id": attempt["agent_id"],
                "agent_attempt_id": agent_attempt_id,
                "role": attempt["role"],
                "report_path": attempt["report_path"],
                "required_idea_count": 10,
                "context": LENS_CONTRACTS[lens]["context"],
                "required_lens": LENS_CONTRACTS[lens]["lens"],
                "source_handoff_id": campaign["source_handoff_id"],
                "source_handoff_report_path": campaign["source_handoff_report_path"],
                "source_handoff_sha256": campaign["source_handoff_sha256"],
                "source_handoff_proof_gap": campaign["source_handoff_proof_gap"],
                "source_handoff_next_step_or_return_trigger": campaign["source_handoff_next_step_or_return_trigger"],
                "assignment_packet": assignment_packet,
                "assignment_packet_sha256": _packet_digest(assignment_packet),
                "claimed_at": iso_now(),
            }
            store.insert_in_transaction(
                connection,
                "exploration.ideation.claimed",
                payload,
                actor=actor,
                generation=generation,
            )
            return dict(payload)

        result = store.transaction(tx)
    store.rebuild()
    return result


def record_idea_batch(
    store: EventStore,
    root: Path,
    *,
    campaign_id: str,
    lens: str,
    agent_attempt_id: str,
    handoff_id: str,
    ideas_file: str,
    actor: str = "coordinator",
) -> dict[str, Any]:
    campaign_id = _campaign_id(campaign_id)
    lens = str(lens or "").strip().lower()
    if lens not in LENS_CONTRACTS:
        raise ValueError("ideation lens is invalid")
    agent_attempt_id = _text(agent_attempt_id, "ideation agent attempt ID", maximum=256)
    ideas, relative, digest = _ideas_from_sidecar(root, ideas_file, campaign_id=campaign_id, lens=lens)
    with file_lock(store.root / "state" / "mutation.lock"):

        def tx(connection: Any) -> dict[str, Any]:
            events, meta = _transaction_snapshot(connection)
            current, _ = _queue_view(events, meta)
            campaign = _ensure_open(current, campaign_id)
            attempt = _active_campaign_attempt(current, campaign, agent_attempt_id=agent_attempt_id)
            handoff = _attempt_structured_handoff(current, campaign, attempt, handoff_id=handoff_id)
            claim = campaign.get("ideation_claims", {}).get(lens)
            if not claim or claim.get("agent_attempt_id") != agent_attempt_id:
                raise ValueError("ideas must be recorded by the exact claimed worker")
            if lens in campaign.get("idea_batches", {}):
                raise ValueError("ideation batch already recorded for this lens")
            generation = _current_generation(meta)
            _require_current_campaign_source(current, campaign, generation=generation)
            expected_packet = _ideation_packet(campaign, attempt, lens=lens, generation=generation)
            assignment_packet = _require_current_packet(
                claim.get("assignment_packet"),
                claim.get("assignment_packet_sha256"),
                expected_packet,
                label="ideation",
            )
            if relative != assignment_packet["artifact"]["path"]:
                raise ValueError("ideas file does not match the claimed assignment packet")
            seen = {
                str(idea.get("idea_id") or "")
                for batch in campaign.get("idea_batches", {}).values()
                for idea in batch.get("ideas", [])
            }
            if any(idea["idea_id"] in seen for idea in ideas):
                raise ValueError("idea IDs must be unique across the campaign")
            payload = {
                "campaign_id": campaign_id,
                "challenge_id": campaign["challenge_id"],
                "objective_id": campaign["objective_id"],
                "lens": lens,
                "agent_id": attempt["agent_id"],
                "agent_attempt_id": agent_attempt_id,
                "report_path": attempt["report_path"],
                "ideas_file": relative,
                "ideas_sha256": digest,
                "ideas": ideas,
                "source_handoff_id": handoff["handoff_id"],
                "campaign_source_handoff_id": campaign["source_handoff_id"],
                "handoff_report_path": handoff["report_path"],
                "handoff_sha256": handoff["sha256"],
                "handoff_proof_gap": handoff["proof_gap"],
                "recorded_at": iso_now(),
            }
            store.insert_in_transaction(
                connection,
                "exploration.idea_batch.recorded",
                payload,
                actor=actor,
                generation=generation,
            )
            return {key: value for key, value in payload.items() if key != "ideas"} | {"idea_count": len(ideas)}

        result = store.transaction(tx)
    store.rebuild()
    return result


def _route_keys_already_tried(current: dict[str, Any], campaign: dict[str, Any]) -> set[str]:
    route_keys = set(campaign.get("known_route_keys", []))
    challenge_id = str(campaign.get("challenge_id") or "")
    objective_id = str(campaign.get("objective_id") or "")

    def add(value: Any) -> None:
        try:
            route_keys.add(_route_key(value))
        except ValueError:
            return

    for outcome in current.get("outcomes", {}).values():
        if (
            str(outcome.get("challenge_id") or "") == challenge_id
            and str(outcome.get("objective_id") or "") == objective_id
        ):
            add(outcome.get("route_key") or outcome.get("mechanism"))
    for idea in current.get("compute_ideas", {}).values():
        if str(idea.get("objective_id") or "") == objective_id:
            add(idea.get("dedupe_key"))
    return route_keys


def _all_campaign_ideas(campaign: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for lens in LENS_ORDER:
        batch = campaign.get("idea_batches", {}).get(lens, {})
        for idea in batch.get("ideas", []):
            rows.append({**idea, "lens": lens})
    return rows


def claim_synthesis(
    store: EventStore,
    *,
    campaign_id: str,
    agent_attempt_id: str,
    actor: str = "coordinator",
) -> dict[str, Any]:
    """Claim the independent worker and sealed SELECTION contract before synthesis."""

    campaign_id = _campaign_id(campaign_id)
    agent_attempt_id = _text(agent_attempt_id, "synthesis agent attempt ID", maximum=256)
    with file_lock(store.root / "state" / "mutation.lock"):

        def tx(connection: Any) -> dict[str, Any]:
            events, meta = _transaction_snapshot(connection)
            current, _ = _queue_view(events, meta)
            campaign = _ensure_open(current, campaign_id)
            synthesizer = _active_campaign_attempt(current, campaign, agent_attempt_id=agent_attempt_id)
            if campaign.get("synthesis") or campaign.get("synthesis_claim"):
                raise ValueError("exploration campaign synthesis has already been claimed or recorded")
            if set(campaign.get("idea_batches", {})) != set(LENS_ORDER):
                raise ValueError("synthesis claim requires all four ten-idea batches")
            if len(_all_campaign_ideas(campaign)) != 40:
                raise RuntimeError("synthesis claim requires exactly forty ideas")
            ideators = {str(row.get("agent_attempt_id") or "") for row in campaign.get("ideation_claims", {}).values()}
            if agent_attempt_id in ideators:
                raise ValueError("synthesis must be independent of every ideator")
            generation = _current_generation(meta)
            _require_current_campaign_source(current, campaign, generation=generation)
            assignment_packet = _synthesis_packet(current, campaign, synthesizer, generation=generation)
            payload = {
                "campaign_id": campaign_id,
                "challenge_id": campaign["challenge_id"],
                "objective_id": campaign["objective_id"],
                "agent_id": synthesizer["agent_id"],
                "agent_attempt_id": agent_attempt_id,
                "role": synthesizer["role"],
                "report_path": synthesizer["report_path"],
                "assignment_packet": assignment_packet,
                "assignment_packet_sha256": _packet_digest(assignment_packet),
                "claimed_at": iso_now(),
            }
            store.insert_in_transaction(
                connection,
                "exploration.synthesis.claimed",
                payload,
                actor=actor,
                generation=generation,
            )
            return dict(payload)

        result = store.transaction(tx)
    store.rebuild()
    return result


def synthesize_campaign(
    store: EventStore,
    root: Path,
    *,
    campaign_id: str,
    synthesizer_attempt_id: str,
    handoff_id: str,
    selection_file: str,
    actor: str = "coordinator",
) -> dict[str, Any]:
    campaign_id = _campaign_id(campaign_id)
    synthesizer_attempt_id = _text(synthesizer_attempt_id, "synthesizer agent attempt ID", maximum=256)
    (
        selected_ids,
        rationale,
        handoff_learning,
        park_reason,
        recheck_condition,
        selection_relative,
        selection_digest,
    ) = _selection_from_sidecar(root, selection_file, campaign_id=campaign_id)
    with file_lock(store.root / "state" / "mutation.lock"):

        def tx(connection: Any) -> dict[str, Any]:
            events, meta = _transaction_snapshot(connection)
            current, _ = _queue_view(events, meta)
            campaign = _ensure_open(current, campaign_id)
            synthesizer = _active_campaign_attempt(current, campaign, agent_attempt_id=synthesizer_attempt_id)
            handoff = _attempt_structured_handoff(current, campaign, synthesizer, handoff_id=handoff_id)
            if campaign.get("synthesis"):
                raise ValueError("exploration campaign has already been synthesized")
            synthesis_claim = campaign.get("synthesis_claim")
            if (
                not isinstance(synthesis_claim, dict)
                or synthesis_claim.get("agent_attempt_id") != synthesizer_attempt_id
            ):
                raise ValueError("synthesis must be recorded by the exact claimed worker")
            batches = campaign.get("idea_batches", {})
            if set(batches) != set(LENS_ORDER):
                raise ValueError("synthesis requires all four ten-idea batches")
            ideators = {str(row.get("agent_attempt_id") or "") for row in campaign.get("ideation_claims", {}).values()}
            if synthesizer_attempt_id in ideators:
                raise ValueError("synthesis must be independent of every ideator")
            ideas = _all_campaign_ideas(campaign)
            if len(ideas) != 40:
                raise RuntimeError("campaign does not contain exactly forty ideas")
            generation = _current_generation(meta)
            _require_current_campaign_source(current, campaign, generation=generation)
            expected_packet = _synthesis_packet(current, campaign, synthesizer, generation=generation)
            assignment_packet = _require_current_packet(
                synthesis_claim.get("assignment_packet"),
                synthesis_claim.get("assignment_packet_sha256"),
                expected_packet,
                label="synthesis",
            )
            if selection_relative != assignment_packet["artifact"]["path"]:
                raise ValueError("selection file does not match the claimed assignment packet")
            tried = _route_keys_already_tried(current, campaign)
            classifications: list[dict[str, str]] = []
            eligible: dict[str, dict[str, Any]] = {}
            first_for_route: set[str] = set()
            for idea in ideas:
                idea_id = str(idea["idea_id"])
                route_key = str(idea["route_key"])
                if route_key in tried:
                    disposition = "duplicate_tried"
                elif route_key in first_for_route:
                    disposition = "duplicate_campaign"
                else:
                    disposition = "eligible"
                    first_for_route.add(route_key)
                    eligible[idea_id] = idea
                classifications.append({"idea_id": idea_id, "route_key": route_key, "disposition": disposition})
            missing = [idea_id for idea_id in selected_ids if idea_id not in eligible]
            if missing:
                raise ValueError("selection contains a tried, duplicate, or unknown idea")
            resolved_park_reason = park_reason
            resolved_recheck_condition = recheck_condition
            if not selected_ids and eligible:
                raise ValueError("synthesis must select an eligible idea before parking")
            if not selected_ids:
                resolved_park_reason = _text(resolved_park_reason, "park reason", maximum=1000, minimum=3)
                resolved_recheck_condition = _text(
                    resolved_recheck_condition,
                    "recheck condition",
                    maximum=1000,
                    minimum=3,
                )
            elif resolved_park_reason or resolved_recheck_condition:
                raise ValueError("park details are allowed only when synthesis has no eligible ideas")
            synthesis_payload = {
                "campaign_id": campaign_id,
                "challenge_id": campaign["challenge_id"],
                "objective_id": campaign["objective_id"],
                "synthesizer_agent_id": synthesizer["agent_id"],
                "synthesizer_attempt_id": synthesizer_attempt_id,
                "synthesizer_role": synthesizer["role"],
                "synthesizer_report_path": synthesizer["report_path"],
                "selection_file": selection_relative,
                "selection_sha256": selection_digest,
                "selection_rationale": rationale,
                "handoff_learning": handoff_learning,
                "source_handoff_id": handoff["handoff_id"],
                "campaign_source_handoff_id": campaign["source_handoff_id"],
                "source_handoff_report_path": handoff["report_path"],
                "source_handoff_sha256": handoff["sha256"],
                "source_handoff_proof_gap": handoff["proof_gap"],
                "tried_route_keys": sorted(tried),
                "classifications": classifications,
                "selected_idea_ids": selected_ids,
                "dispatch_kind": "agent",
                "park_reason": resolved_park_reason,
                "recheck_condition": resolved_recheck_condition,
                "recorded_at": iso_now(),
            }
            store.insert_in_transaction(
                connection,
                "exploration.synthesis.recorded",
                synthesis_payload,
                actor=actor,
                generation=generation,
            )
            if not selected_ids:
                store.insert_in_transaction(
                    connection,
                    "exploration.campaign.parked",
                    {
                        "campaign_id": campaign_id,
                        "challenge_id": campaign["challenge_id"],
                        "objective_id": campaign["objective_id"],
                        "source_handoff_id": campaign["source_handoff_id"],
                        "reason": resolved_park_reason,
                        "recheck_condition": resolved_recheck_condition,
                        "status": "parked",
                        "parked_at": iso_now(),
                    },
                    actor=actor,
                    generation=generation,
                )
                return {
                    "campaign_id": campaign_id,
                    "classification_counts": {
                        status: sum(1 for row in classifications if row["disposition"] == status)
                        for status in ("eligible", "duplicate_tried", "duplicate_campaign")
                    },
                    "selected": [],
                    "workflow_state": "parked",
                }
            queued: list[dict[str, Any]] = []
            for item_id in selected_ids:
                idea = eligible[item_id]
                compute_id = "idea_" + uuid.uuid4().hex
                report_path = f"analysis/exploration/{campaign_id}/{item_id}/REPORT.md"
                compute_payload = {
                    "idea_id": compute_id,
                    "objective_id": campaign["objective_id"],
                    "goal": idea["next_step"],
                    "scope": (
                        f"challenge={campaign['challenge_id']}; route={idea['route_key']}; "
                        f"handoff={handoff['handoff_id']}; "
                        f"evidence={handoff['report_path']}; "
                        "proof_gap=see_handoff; "
                        f"prerequisite={idea['prerequisite_evidence']}"
                    ),
                    "report_path": report_path,
                    "stop_condition": idea["discriminating_test"],
                    "mechanism": idea["mechanism"],
                    "requested_cpu_threads": 1,
                    "budget_seconds": int(idea["estimated_cost_seconds"]),
                    "checkpointable": True,
                    "dispatch_kind": "agent",
                    "expected_value": idea["expected_value"],
                    "evidence_value": idea["evidence_value"],
                    "dedupe_key": idea["route_key"],
                    "exploration_campaign_id": campaign_id,
                    "exploration_idea_id": item_id,
                    "challenge_id": campaign["challenge_id"],
                    "route_key": idea["route_key"],
                    "source_handoff_id": handoff["handoff_id"],
                    "source_handoff_report_path": handoff["report_path"],
                    "source_handoff_sha256": handoff["sha256"],
                    "source_handoff_proof_gap": handoff["proof_gap"],
                }
                queued_idea = enqueue_compute_idea_in_transaction(store, connection, compute_payload, actor=actor)
                selected_payload = {
                    "campaign_id": campaign_id,
                    "challenge_id": campaign["challenge_id"],
                    "objective_id": campaign["objective_id"],
                    "idea_id": item_id,
                    "route_key": idea["route_key"],
                    "compute_idea_id": compute_id,
                    "dispatch_kind": "agent",
                    "queued_stop_generation": generation,
                    "source_handoff_id": handoff["handoff_id"],
                    "selected_at": iso_now(),
                }
                store.insert_in_transaction(
                    connection,
                    "exploration.idea.selected",
                    selected_payload,
                    actor=actor,
                    generation=generation,
                )
                queued.append({"idea_id": item_id, "compute_idea_id": compute_id, "status": queued_idea["status"]})
            return {
                "campaign_id": campaign_id,
                "classification_counts": {
                    status: sum(1 for row in classifications if row["disposition"] == status)
                    for status in ("eligible", "duplicate_tried", "duplicate_campaign")
                },
                "selected": queued,
                "workflow_state": "capacity_wait",
            }

        result = store.transaction(tx)
    store.rebuild()
    return result


def record_dispatch_claim(
    store: EventStore,
    *,
    campaign_id: str,
    idea_id: str,
    compute_idea_id: str,
    agent_attempt_id: str,
    actor: str = "coordinator",
) -> dict[str, Any]:
    """Record a fully capable worker after the normal compute start succeeds."""

    campaign_id = _campaign_id(campaign_id)
    idea_id = _item_id(idea_id)
    compute_idea_id = _text(compute_idea_id, "compute idea ID", maximum=128)
    agent_attempt_id = _text(agent_attempt_id, "agent attempt ID", maximum=256)
    with file_lock(store.root / "state" / "mutation.lock"):

        def tx(connection: Any) -> dict[str, Any]:
            events, meta = _transaction_snapshot(connection)
            current, compute_ideas = _queue_view(events, meta)
            campaign = _ensure_open(current, campaign_id)
            selected = campaign.get("selected", {}).get(idea_id)
            if not selected or selected.get("compute_idea_id") != compute_idea_id:
                raise ValueError("dispatch must name a selected compute idea")
            if idea_id in campaign.get("dispatches", {}):
                raise ValueError("selected idea already has a dispatch claim")
            compute_idea = compute_ideas.get(compute_idea_id)
            if not compute_idea or compute_idea.get("effective_status") != "running":
                raise ValueError("selected work must be running through the compute queue")
            expected_provenance = {
                "exploration_campaign_id": campaign_id,
                "exploration_idea_id": idea_id,
                "challenge_id": str(campaign["challenge_id"]),
                "source_handoff_id": str(selected["source_handoff_id"]),
                "route_key": str(selected["route_key"]),
            }
            if any(str(compute_idea.get(key) or "") != value for key, value in expected_provenance.items()):
                raise ValueError("running compute work does not match selected campaign provenance")
            generation = _current_generation(meta)
            role = ""
            worker = next(
                (
                    row
                    for row in current.get("agents", {}).values()
                    if str(row.get("agent_attempt_id") or "") == agent_attempt_id
                    and row.get("status") in ACTIVE_AGENT_STATES
                ),
                None,
            )
            if worker is None:
                raise ValueError("dispatch requires an active worker attempt")
            if (
                str(compute_idea.get("dispatch_kind") or "") != "agent"
                or str(worker.get("objective_id") or "") != str(campaign.get("objective_id") or "")
                or str(worker.get("report_path") or "") != str(compute_idea.get("report_path") or "")
                or str(compute_idea.get("agent_attempt_id") or "") != agent_attempt_id
            ):
                raise ValueError("dispatch worker does not match the selected compute lease")
            role = _text(worker.get("role"), "worker role", maximum=256)
            lowered_role = role.lower()
            if not any(
                marker in lowered_role
                for marker in ("investigator", "naive", "disruptor", "solver", "breaker", "workbench", "grind")
            ):
                raise ValueError("selected idea requires a fully capable solver role")
            if int(worker.get("stop_generation", -1)) != generation:
                raise RuntimeError("dispatch worker belongs to a stale stop generation")
            payload = {
                "campaign_id": campaign_id,
                "challenge_id": campaign["challenge_id"],
                "objective_id": campaign["objective_id"],
                "idea_id": idea_id,
                "compute_idea_id": compute_idea_id,
                "source_handoff_id": selected["source_handoff_id"],
                "agent_attempt_id": agent_attempt_id,
                "runner_kind": "agent",
                "role": role,
                "claimed_at": iso_now(),
            }
            store.insert_in_transaction(
                connection,
                "exploration.dispatch.claimed",
                payload,
                actor=actor,
                generation=generation,
            )
            return payload

        result = store.transaction(tx)
    store.rebuild()
    return result


def park_campaign(
    store: EventStore,
    *,
    campaign_id: str,
    reason: str,
    recheck_condition: str,
    boundary_id: str,
    actor: str = "coordinator",
) -> dict[str, Any]:
    campaign_id = _campaign_id(campaign_id)
    reason = _text(reason, "park reason", maximum=1000, minimum=3)
    recheck_condition = _text(recheck_condition, "recheck condition", maximum=1000, minimum=3)
    boundary_id = _text(boundary_id, "boundary ID", maximum=256)
    with file_lock(store.root / "state" / "mutation.lock"):

        def tx(connection: Any) -> dict[str, Any]:
            events, meta = _transaction_snapshot(connection)
            current, _ = _queue_view(events, meta)
            campaign = _ensure_open(current, campaign_id)
            generation = _current_generation(meta)
            boundary_events = [
                event
                for event in events
                if event.get("event_type") == "continuation.boundary.recorded"
                and str(event.get("payload", {}).get("boundary_id") or "") == boundary_id
                and int(event.get("generation", -1)) == generation
            ]
            if len(boundary_events) != 1:
                raise ValueError("early campaign parking requires one current explicit boundary")
            boundary = boundary_events[0]["payload"]
            if (
                str(boundary.get("challenge_id") or "") != str(campaign["challenge_id"])
                or str(boundary.get("objective_id") or "") != str(campaign["objective_id"])
                or str(boundary.get("source_handoff_id") or "") != str(campaign["source_handoff_id"])
                or str(boundary.get("status") or "") != "active"
            ):
                raise ValueError("explicit boundary does not match the campaign handoff")
            payload = {
                "campaign_id": campaign_id,
                "challenge_id": campaign["challenge_id"],
                "objective_id": campaign["objective_id"],
                "reason": reason,
                "recheck_condition": recheck_condition,
                "boundary_id": boundary_id,
                "source_handoff_id": campaign["source_handoff_id"],
                "status": "parked",
                "parked_at": iso_now(),
            }
            store.insert_in_transaction(
                connection,
                "exploration.campaign.parked",
                payload,
                actor=actor,
                generation=generation,
            )
            return payload

        result = store.transaction(tx)
    store.rebuild()
    return result


def close_campaign(
    store: EventStore,
    *,
    campaign_id: str,
    reason: str,
    actor: str = "coordinator",
) -> dict[str, Any]:
    campaign_id = _campaign_id(campaign_id)
    reason = _text(reason, "close reason", maximum=1000, minimum=3)
    with file_lock(store.root / "state" / "mutation.lock"):

        def tx(connection: Any) -> dict[str, Any]:
            events, meta = _transaction_snapshot(connection)
            current, _ = _queue_view(events, meta)
            campaign = _campaigns(current).get(campaign_id)
            if not campaign:
                raise ValueError("exploration campaign was not found")
            if campaign.get("status") == "closed":
                return campaign
            generation = _current_generation(meta)
            if int(campaign.get("stop_generation", -1)) != generation:
                raise RuntimeError("exploration campaign belongs to a stale stop generation")
            payload = {
                "campaign_id": campaign_id,
                "challenge_id": campaign["challenge_id"],
                "objective_id": campaign["objective_id"],
                "reason": reason,
                "status": "closed",
                "closed_at": iso_now(),
            }
            store.insert_in_transaction(
                connection,
                "exploration.campaign.closed",
                payload,
                actor=actor,
                generation=generation,
            )
            return payload

        result = store.transaction(tx)
    store.rebuild()
    return result


def project_exploration_campaigns(
    events: list[dict[str, Any]], *, current_stop_generation: int
) -> dict[str, dict[str, Any]]:
    """Project only campaign state; invalid event detail stays visible as evidence."""

    campaigns: dict[str, dict[str, Any]] = {}
    for event in events:
        event_type = str(event.get("event_type") or "")
        if not event_type.startswith("exploration."):
            continue
        payload = dict(event.get("payload") or {})
        campaign_id = str(payload.get("campaign_id") or "")
        if not campaign_id:
            continue
        if event_type == "exploration.campaign.opened":
            campaigns[campaign_id] = {
                **payload,
                "status": "active",
                "workflow_state": "active",
                "ideation_claims": {},
                "idea_batches": {},
                "selected": {},
                "dispatches": {},
                "event_id": event.get("event_id"),
                "event_at": event.get("created_at"),
                "event_stop_generation": event.get("generation"),
            }
            continue
        campaign = campaigns.get(campaign_id)
        if not campaign:
            continue
        if event_type == "exploration.ideation.claimed":
            lens = str(payload.get("lens") or "")
            if lens:
                campaign["ideation_claims"][lens] = payload
                campaign["workflow_state"] = "ideating"
        elif event_type == "exploration.idea_batch.recorded":
            lens = str(payload.get("lens") or "")
            if lens:
                campaign["idea_batches"][lens] = payload
                campaign["workflow_state"] = (
                    "synthesis_wait" if set(campaign["idea_batches"]) == set(LENS_ORDER) else "ideating"
                )
        elif event_type == "exploration.synthesis.claimed":
            campaign["synthesis_claim"] = payload
            campaign["workflow_state"] = "synthesizing"
        elif event_type == "exploration.synthesis.recorded":
            campaign["synthesis"] = payload
            campaign["workflow_state"] = "capacity_wait"
        elif event_type == "exploration.idea.selected":
            idea_id = str(payload.get("idea_id") or "")
            if idea_id:
                campaign["selected"][idea_id] = payload
                campaign["workflow_state"] = "capacity_wait"
        elif event_type == "exploration.dispatch.claimed":
            idea_id = str(payload.get("idea_id") or "")
            if idea_id:
                campaign["dispatches"][idea_id] = payload
                campaign["workflow_state"] = "solving"
        elif event_type == "exploration.campaign.parked":
            campaign.update(payload)
            campaign["status"] = "parked"
            campaign["workflow_state"] = "parked"
        elif event_type == "exploration.campaign.closed":
            campaign.update(payload)
            campaign["status"] = "closed"
            campaign["workflow_state"] = "closed"
        campaign["event_id"] = event.get("event_id")
        campaign["event_at"] = event.get("created_at")
        campaign["event_stop_generation"] = event.get("generation")
    for campaign in campaigns.values():
        if campaign.get("status") == "active" and int(campaign.get("stop_generation", -1)) != int(
            current_stop_generation
        ):
            campaign["effective_status"] = "stale"
        else:
            campaign["effective_status"] = campaign.get("status", "unknown")
    return campaigns
