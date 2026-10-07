from __future__ import annotations

import datetime as dt
import hashlib
import json
import math
import os
import stat
import time
import uuid
from collections.abc import Callable
from pathlib import Path, PurePosixPath
from typing import Any

from .intake import solver_eligibility
from .store import EventStore
from .util import UTC, contained_private_path, file_lock, iso_now, parse_iso


DEFAULT_TARGET_PERCENT = 75.0
DEFAULT_ADMIT_PERCENT = 70.0
DEFAULT_CEILING_PERCENT = 80.0
DEFAULT_BACKOFF_PERCENT = 85.0
DEFAULT_SAMPLE_SECONDS = 1.0
DEFAULT_LEASE_SECONDS = 30
DEFAULT_ADMISSION_COOLDOWN_SECONDS = 5
TERMINAL_IDEA_STATES = frozenset({"completed", "failed", "retired", "cancelled"})
ACTIVE_AGENT_STATES = frozenset({"assigned", "running", "stopping"})
ACTIVE_JOB_STATES = frozenset({"queued", "running", "stopping", "unacknowledged", "unmanaged"})


def compute_job_label(idea_id: str, admission_id: str) -> str:
    """Return the exact runbg label that binds a job to one compute lease."""

    return f"compute:{idea_id}:{admission_id}"


def schedule_useful_jobs(jobs: list[dict[str, Any]], manifest: dict[str, Any]) -> dict[str, Any]:
    cfg = manifest.get("compute", {})
    total = int(cfg.get("total_units", 1) or 1)
    reserve = int(cfg.get("interactive_reserve_units", 0) or 0)
    available = max(0, total - reserve)
    ranked = []
    retired = []
    for job in jobs:
        if not job.get("checkpointable", True):
            retired.append({**job, "retire_reason": "not checkpointable"})
            continue
        if int(job.get("budget_remaining_seconds", 0) or 0) <= 0:
            retired.append({**job, "retire_reason": "budget exhausted"})
            continue
        if float(job.get("progress_rate", 1.0) or 0.0) <= 0 and int(job.get("no_progress_windows", 0) or 0) >= 2:
            retired.append({**job, "retire_reason": "non-progressing"})
            continue
        score = (
            float(job.get("expected_value", 0.0) or 0.0)
            + float(job.get("evidence_value", 0.0) or 0.0)
            - float(job.get("cost_units", 1) or 1) * 0.1
        )
        ranked.append({**job, "scheduler_score": score})
    ranked.sort(key=lambda x: (-x["scheduler_score"], str(x.get("job_id", ""))))
    selected = []
    used = 0
    for job in ranked:
        cost = max(1, int(job.get("cost_units", 1) or 1))
        if used + cost <= available:
            selected.append(job)
            used += cost
    return {
        "total_units": total,
        "interactive_reserve_units": reserve,
        "available_for_jobs": available,
        "used_units": used,
        "idle_units": available - used,
        "selected": selected,
        "retired": retired,
        "reason": "idle capacity is permitted when no justified job fits",
    }


def parse_proc_stat(text: str, visible_cpu_ids: set[int]) -> dict[int, tuple[int, int]]:
    """Return cumulative ``(total, idle)`` ticks for every visible Linux CPU."""

    if not visible_cpu_ids:
        raise ValueError("CPU affinity is empty")
    samples: dict[int, tuple[int, int]] = {}
    for line in text.splitlines():
        fields = line.split()
        if not fields or not fields[0].startswith("cpu") or fields[0] == "cpu":
            continue
        suffix = fields[0][3:]
        if not suffix.isdigit() or int(suffix) not in visible_cpu_ids:
            continue
        values = [int(value) for value in fields[1:]]
        if len(values) < 5 or any(value < 0 for value in values):
            raise ValueError("visible CPU counters are malformed")
        # Linux includes guest time in user/nice already, so only the first
        # eight counters participate in the total.
        total = sum(values[:8])
        idle = values[3] + values[4]
        samples[int(suffix)] = (total, idle)
    if visible_cpu_ids.difference(samples):
        raise ValueError("/proc/stat is missing an affinity-visible CPU")
    return samples


def cpu_window_busy_percent(
    before: dict[int, tuple[int, int]],
    after: dict[int, tuple[int, int]],
) -> float:
    """Calculate aggregate utilization for one bounded counter window."""

    if not before or set(before) != set(after):
        raise ValueError("CPU sample membership changed")
    total_delta = 0
    idle_delta = 0
    for cpu_id in sorted(before):
        old_total, old_idle = before[cpu_id]
        new_total, new_idle = after[cpu_id]
        if new_total < old_total or new_idle < old_idle:
            raise ValueError("CPU counters regressed")
        total_delta += new_total - old_total
        idle_delta += new_idle - old_idle
    if total_delta <= 0 or idle_delta > total_delta:
        raise ValueError("CPU counter window has no usable elapsed time")
    return round(100.0 * (1.0 - idle_delta / total_delta), 3)


def sample_host_cpu(
    *,
    sample_seconds: float = DEFAULT_SAMPLE_SECONDS,
    affinity_reader: Callable[[], set[int]] | None = None,
    stat_reader: Callable[[], str] | None = None,
    sleeper: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    """Read two adjacent affinity-visible Linux CPU utilization windows."""

    if not math.isfinite(sample_seconds) or sample_seconds <= 0 or sample_seconds > 30:
        raise ValueError("CPU sample interval must be in (0, 30] seconds")
    affinity_reader = affinity_reader or (lambda: set(os.sched_getaffinity(0)))
    stat_reader = stat_reader or (lambda: Path("/proc/stat").read_text(encoding="ascii", errors="strict"))
    try:
        visible = set(affinity_reader())
        samples = [parse_proc_stat(stat_reader(), visible)]
        for _ in range(2):
            sleeper(sample_seconds)
            samples.append(parse_proc_stat(stat_reader(), visible))
        windows = [
            cpu_window_busy_percent(samples[0], samples[1]),
            cpu_window_busy_percent(samples[1], samples[2]),
        ]
    except (AttributeError, OSError, TypeError, ValueError) as exc:
        return {
            "available": False,
            "reason": str(exc) or "CPU telemetry is unavailable",
            "sampled_at": iso_now(),
        }
    return {
        "available": True,
        "visible_cpu_count": len(visible),
        "visible_cpu_ids": sorted(visible),
        "window_busy_percent": windows,
        "busy_cores": round(max(windows) * len(visible) / 100.0, 3),
        "sample_seconds": sample_seconds,
        "sampled_at": iso_now(),
    }


def _bounded_text(value: Any, label: str, *, maximum: int) -> str:
    text = str(value or "").strip()
    if not text:
        raise ValueError(f"{label} is required")
    if len(text) > maximum or any(ord(character) < 0x20 for character in text):
        raise ValueError(f"{label} is malformed")
    return text


def _report_path(value: Any) -> str:
    text = _bounded_text(value, "report path", maximum=512).replace("\\", "/")
    path = PurePosixPath(text)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise ValueError("report path must stay relative to the workspace")
    return text


def _existing_private_checkpoint(root: Path, value: Any) -> str:
    text = _report_path(value)
    candidate = contained_private_path(root, root, *PurePosixPath(text).parts)
    try:
        info = candidate.lstat()
    except FileNotFoundError as exc:
        raise ValueError("checkpoint path must name an existing private file") from exc
    if (
        not stat.S_ISREG(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) & 0o077
    ):
        raise ValueError("checkpoint path must name an existing private file")
    return text


def validate_compute_idea(payload: dict[str, Any]) -> dict[str, Any]:
    """Validate and normalize one low-priority, authority-free work idea."""

    requested_threads = int(payload.get("requested_cpu_threads", 1))
    budget_seconds = int(payload.get("budget_seconds", 0))
    if requested_threads < 1 or requested_threads > 1024:
        raise ValueError("requested CPU threads must be between 1 and 1024")
    if budget_seconds < 1 or budget_seconds > 7 * 24 * 60 * 60:
        raise ValueError("budget seconds must be between 1 and 604800")
    if payload.get("checkpointable") is not True:
        raise ValueError("low-priority ideas must be checkpointable")
    dispatch_kind = str(payload.get("dispatch_kind") or "agent")
    if dispatch_kind not in {"agent", "job"}:
        raise ValueError("dispatch kind must be agent or job")
    idea_id = str(payload.get("idea_id") or "idea_" + uuid.uuid4().hex)
    if not idea_id.startswith("idea_") or len(idea_id) > 128:
        raise ValueError("idea ID is malformed")
    expected_value = float(payload.get("expected_value", 1.0))
    evidence_value = float(payload.get("evidence_value", 1.0))
    if not math.isfinite(expected_value) or not math.isfinite(evidence_value):
        raise ValueError("compute idea values must be finite")
    idea = {
        "idea_id": idea_id,
        "objective_id": _bounded_text(payload.get("objective_id"), "objective ID", maximum=128),
        "goal": _bounded_text(payload.get("goal"), "goal", maximum=2000),
        "scope": _bounded_text(payload.get("scope"), "scope", maximum=2000),
        "report_path": _report_path(payload.get("report_path")),
        "stop_condition": _bounded_text(payload.get("stop_condition"), "stop condition", maximum=1000),
        "mechanism": _bounded_text(payload.get("mechanism"), "mechanism", maximum=512),
        "requested_cpu_threads": requested_threads,
        "budget_seconds": budget_seconds,
        "checkpointable": True,
        "dispatch_kind": dispatch_kind,
        "expected_value": expected_value,
        "evidence_value": evidence_value,
        "dedupe_key": _bounded_text(payload.get("dedupe_key"), "dedupe key", maximum=256),
        "created_by": "coordinator",
        "created_at": iso_now(),
    }
    # These provenance fields make an exploration promotion auditable without
    # granting the compute queue any exploration or scoring authority.  They
    # are deliberately validated as bounded data, never interpreted as paths
    # or commands.
    for key, label, maximum in (
        ("exploration_campaign_id", "exploration campaign ID", 128),
        ("exploration_idea_id", "exploration idea ID", 128),
        ("challenge_id", "challenge ID", 256),
        ("route_key", "route key", 256),
        ("source_handoff_id", "source handoff ID", 256),
        ("source_handoff_report_path", "source handoff report path", 512),
        ("source_handoff_sha256", "source handoff SHA-256", 128),
        ("source_handoff_proof_gap", "source handoff proof gap", 2000),
    ):
        if key in payload and payload[key] not in {None, ""}:
            idea[key] = _bounded_text(payload[key], label, maximum=maximum)
    return idea


def project_compute_ideas(
    events: list[dict[str, Any]],
    *,
    current_stop_generation: int,
    now: dt.datetime | None = None,
) -> dict[str, dict[str, Any]]:
    """Project the distinct compute queue without touching the scoring queue."""

    now = now or dt.datetime.now(UTC)
    ideas: dict[str, dict[str, Any]] = {}
    for event in events:
        event_type = str(event.get("event_type") or "")
        if not event_type.startswith("compute.idea."):
            continue
        payload = dict(event.get("payload") or {})
        idea_id = str(payload.get("idea_id") or "")
        if not idea_id:
            continue
        action = event_type.rsplit(".", 1)[-1]
        old = ideas.get(idea_id, {})
        status = old.get("status", "queued")
        if action == "queued":
            status = "queued"
        elif action == "leased":
            status = "leased"
        elif action == "started":
            status = "running"
        elif action == "pause_requested":
            status = "pause_requested"
        elif action == "paused":
            status = "paused"
        elif action in TERMINAL_IDEA_STATES:
            status = action
        ideas[idea_id] = {
            **old,
            **payload,
            "status": status,
            "last_event_id": event.get("event_id"),
            "last_event_at": event.get("created_at"),
            "event_stop_generation": int(event.get("generation", 0)),
        }
    for row in ideas.values():
        queued_generation = int(row.get("queued_stop_generation", -1))
        if row.get("status") not in TERMINAL_IDEA_STATES and queued_generation != current_stop_generation:
            row["effective_status"] = "stale"
            continue
        if row.get("status") == "leased":
            expires_at = parse_iso(row.get("lease_expires_at"))
            if expires_at is None or expires_at <= now:
                row["effective_status"] = "queued"
                row["lease_expired"] = True
                continue
        row["effective_status"] = row.get("status")
    return ideas


class _Meta:
    def __init__(self, values: dict[str, str]):
        self.values = values

    def get_meta(self, key: str, default: str = "") -> str:
        return self.values.get(key, default)


def _transaction_snapshot(connection: Any) -> tuple[list[dict[str, Any]], dict[str, str]]:
    rows = connection.execute("SELECT * FROM events ORDER BY seq").fetchall()
    events = [
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
    meta = {str(row["key"]): str(row["value"]) for row in connection.execute("SELECT key,value FROM meta").fetchall()}
    return events, meta


def _queue_view(events: list[dict[str, Any]], meta: dict[str, str]) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    from .reducers import reduce_events

    generation = int(meta.get("stop_generation", "0"))
    current = reduce_events(events, _Meta(meta))["current"]
    ideas = project_compute_ideas(events, current_stop_generation=generation)
    return current, ideas


def _require_solver_eligible_challenge(
    root: Path, current: dict[str, Any], challenge_id: object
) -> None:
    """Reject challenge work whose current intake cannot support a solver."""

    challenge_key = str(challenge_id or "")
    if not challenge_key:
        return
    challenge = current.get("challenges", {}).get(challenge_key)
    if not isinstance(challenge, dict):
        raise ValueError("compute challenge is not currently canonical")
    if not solver_eligibility(root, challenge)["ready"]:
        raise ValueError("challenge intake is not solver-ready")


_EXPLORATION_BINDING_FIELDS = (
    "exploration_campaign_id",
    "exploration_idea_id",
    "challenge_id",
    "route_key",
    "source_handoff_id",
)


def selected_exploration_binding(
    current: dict[str, Any], idea: dict[str, Any]
) -> dict[str, Any] | None:
    """Return one exact selected campaign binding or reject partial provenance.

    Compute remains useful for generic background tasks.  Once an idea claims
    exploration provenance, every identifier is mandatory and must match the
    campaign's immutable selection record.  No caller can retarget a lease by
    changing only objective or report text.
    """

    supplied = {key: str(idea.get(key) or "") for key in _EXPLORATION_BINDING_FIELDS}
    if not any(supplied.values()):
        return None
    if any(not value for value in supplied.values()):
        raise ValueError("exploration compute idea has incomplete provenance")
    campaign = current.get("exploration_campaigns", {}).get(
        supplied["exploration_campaign_id"]
    )
    if not isinstance(campaign, dict) or campaign.get("effective_status") != "active":
        raise ValueError("exploration campaign is not current")
    selected = campaign.get("selected", {}).get(supplied["exploration_idea_id"])
    if not isinstance(selected, dict):
        raise ValueError("exploration compute idea was not selected")
    expected = {
        "compute_idea_id": str(idea.get("idea_id") or ""),
        "campaign_id": supplied["exploration_campaign_id"],
        "challenge_id": supplied["challenge_id"],
        "idea_id": supplied["exploration_idea_id"],
        "route_key": supplied["route_key"],
        "source_handoff_id": supplied["source_handoff_id"],
    }
    if any(str(selected.get(key) or "") != value for key, value in expected.items()):
        raise ValueError("exploration selection does not match the compute idea")
    if (
        str(campaign.get("challenge_id") or "") != supplied["challenge_id"]
        or str(campaign.get("objective_id") or "")
        != str(idea.get("objective_id") or "")
    ):
        raise ValueError("exploration campaign provenance does not match the compute idea")
    return {"campaign": campaign, "selected": selected, "provenance": supplied}


def _private_report_sha256(root: Path, report_path: str) -> str:
    """Hash one bounded private report without following a supplied path."""

    relative = _report_path(report_path)
    candidate = contained_private_path(root, root, *PurePosixPath(relative).parts)
    try:
        observed = candidate.lstat()
    except FileNotFoundError as exc:
        raise ValueError("compute completion report does not exist") from exc
    if (
        stat.S_ISLNK(observed.st_mode)
        or not stat.S_ISREG(observed.st_mode)
        or observed.st_nlink != 1
        or stat.S_IMODE(observed.st_mode) & 0o077
        or observed.st_size > 8 * 1024 * 1024
    ):
        raise ValueError("compute completion report must be one bounded private regular file")
    descriptor = os.open(
        candidate,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or opened.st_size != observed.st_size
            or opened.st_dev != observed.st_dev
            or opened.st_ino != observed.st_ino
        ):
            raise ValueError("compute completion report changed while opening")
        digest = hashlib.sha256()
        remaining = 8 * 1024 * 1024 + 1
        has_non_whitespace = False
        while remaining:
            block = os.read(descriptor, min(64 * 1024, remaining))
            if not block:
                if not has_non_whitespace:
                    raise ValueError(
                        "compute completion report must contain non-whitespace evidence"
                    )
                return digest.hexdigest()
            digest.update(block)
            has_non_whitespace = has_non_whitespace or bool(block.strip())
            remaining -= len(block)
        raise ValueError("compute completion report exceeds its byte limit")
    finally:
        os.close(descriptor)


def _require_agent_completion_closeout(
    events: list[dict[str, Any]],
    current: dict[str, Any],
    *,
    idea: dict[str, Any],
    generation: int,
    agent_attempt_id: str,
    report_sha256: str,
) -> dict[str, str]:
    """Require one closed agent's current report handoff and typed outcome.

    A compute completion claims useful work.  Its report and outcome must
    therefore belong to the exact agent that held the lease, rather than to a
    similarly named lane or an earlier report revision.
    """

    worker = next(
        (
            row
            for row in current.get("agents", {}).values()
            if str(row.get("agent_attempt_id") or "") == agent_attempt_id
        ),
        None,
    )
    if (
        not isinstance(worker, dict)
        or worker.get("status") != "closed"
        or int(worker.get("stop_generation", -1)) != generation
        or str(worker.get("objective_id") or "")
        != str(idea.get("objective_id") or "")
        or str(worker.get("report_path") or "")
        != str(idea.get("report_path") or "")
    ):
        raise ValueError(
            "compute completion requires its exact registered agent to close"
        )
    agent_id = str(worker.get("agent_id") or "")
    if not agent_id:
        raise ValueError("compute completion agent identity is missing")

    handoff_events = [
        event
        for event in events
        if event.get("event_type") == "report.harvested"
        and int(event.get("generation", -1)) == generation
        and str(event.get("payload", {}).get("agent_id") or "") == agent_id
        and str(event.get("payload", {}).get("agent_attempt_id") or "")
        == agent_attempt_id
        and str(event.get("payload", {}).get("objective_id") or "")
        == str(idea.get("objective_id") or "")
        and str(event.get("payload", {}).get("report_path") or "")
        == str(idea.get("report_path") or "")
        and str(event.get("payload", {}).get("sha256") or "") == report_sha256
    ]
    if len(handoff_events) != 1:
        raise ValueError(
            "compute completion requires one current exact worker report handoff"
        )
    handoff = dict(handoff_events[0].get("payload") or {})
    outcome_events = [
        event
        for event in events
        if event.get("event_type") == "outcome.recorded"
        and int(event.get("generation", -1)) == generation
        and str(event.get("payload", {}).get("agent_id") or "") == agent_id
        and str(event.get("payload", {}).get("agent_attempt_id") or "")
        == agent_attempt_id
        and str(event.get("payload", {}).get("objective_id") or "")
        == str(idea.get("objective_id") or "")
        and str(event.get("payload", {}).get("report_path") or "")
        == str(idea.get("report_path") or "")
    ]
    if len(outcome_events) != 1:
        raise ValueError(
            "compute completion requires one exact worker typed outcome"
        )
    outcome = dict(outcome_events[0].get("payload") or {})
    challenge_id = str(worker.get("challenge_id") or "")
    handoff_id = str(handoff.get("handoff_id") or "")
    if challenge_id and (
        handoff.get("structured") is not True
        or not handoff_id
        or str(outcome.get("handoff_id") or "") != handoff_id
        or str(outcome.get("challenge_id") or "") != challenge_id
        or str(handoff.get("challenge_id") or "") != challenge_id
        or str(handoff.get("status") or "")
        != str(outcome.get("outcome_type") or "")
    ):
        raise ValueError(
            "compute completion challenge handoff does not match its outcome"
        )
    return {
        "report_sha256": report_sha256,
        "handoff_id": handoff_id,
        "outcome_id": str(outcome.get("outcome_id") or ""),
        "continuation_id": str(outcome.get("continuation_id") or ""),
    }


def _require_selected_owner_closeout(
    events: list[dict[str, Any]],
    current: dict[str, Any],
    *,
    root: Path,
    idea: dict[str, Any],
    generation: int,
    exploration: dict[str, Any],
    agent_attempt_id: str,
) -> dict[str, str]:
    """Require either runner kind to finish through the normal handoff lifecycle."""

    attempt_id = str(agent_attempt_id or "")
    if not attempt_id:
        raise ValueError("selected compute work has no registered handoff owner")
    worker = next(
        (
            row
            for row in current.get("agents", {}).values()
            if str(row.get("agent_attempt_id") or "") == attempt_id
        ),
        None,
    )
    provenance = exploration["provenance"]
    if (
        not worker
        or worker.get("status") != "closed"
        or str(worker.get("objective_id") or "") != str(idea["objective_id"])
        or str(worker.get("report_path") or "") != str(idea["report_path"])
        or str(worker.get("challenge_id") or "") != provenance["challenge_id"]
        or str(worker.get("source_handoff_id") or "")
        != provenance["source_handoff_id"]
    ):
        raise ValueError("selected CLI job requires its exact registered owner to close")
    report_sha256 = _private_report_sha256(root, str(idea["report_path"]))
    handoffs = [
        event["payload"]
        for event in events
        if event.get("event_type") == "report.harvested"
        and int(event.get("generation", -1)) == generation
        and str(event.get("payload", {}).get("agent_attempt_id") or "") == attempt_id
        and str(event.get("payload", {}).get("report_path") or "") == str(idea["report_path"])
        and str(event.get("payload", {}).get("challenge_id") or "")
        == provenance["challenge_id"]
        and str(event.get("payload", {}).get("objective_id") or "")
        == str(idea["objective_id"])
        and str(event.get("payload", {}).get("sha256") or "") == report_sha256
        and bool(event.get("payload", {}).get("structured"))
    ]
    if len(handoffs) != 1:
        raise ValueError("selected CLI job requires one current structured report handoff")
    handoff = handoffs[0]
    handoff_id = str(handoff.get("handoff_id") or "")
    outcomes = [
        event["payload"]
        for event in events
        if event.get("event_type") == "outcome.recorded"
        and int(event.get("generation", -1)) == generation
        and str(event.get("payload", {}).get("agent_attempt_id") or "") == attempt_id
        and str(event.get("payload", {}).get("handoff_id") or "") == handoff_id
        and str(event.get("payload", {}).get("challenge_id") or "")
        == provenance["challenge_id"]
        and str(event.get("payload", {}).get("objective_id") or "")
        == str(idea["objective_id"])
        and str(event.get("payload", {}).get("continuation_id") or "")
    ]
    if len(outcomes) != 1:
        raise ValueError("selected CLI job requires one handoff-bound outcome and next route")
    return {
        "agent_attempt_id": attempt_id,
        "handoff_id": handoff_id,
        "outcome_id": str(outcomes[0].get("outcome_id") or ""),
        "continuation_id": str(outcomes[0].get("continuation_id") or ""),
    }


def enqueue_compute_idea_in_transaction(
    store: EventStore,
    connection: Any,
    payload: dict[str, Any],
    *,
    actor: str = "coordinator",
) -> dict[str, Any]:
    """Queue one validated idea in the caller's current mutation transaction.

    Exploration promotion uses this seam so its durable selection and the
    ordinary compute queue appear together.  It only persists a leaseable
    work description; it never launches a runner or gains scoring authority.
    """

    idea = validate_compute_idea(payload)
    events, meta = _transaction_snapshot(connection)
    current, ideas = _queue_view(events, meta)
    if current.get("stopped"):
        raise RuntimeError("workspace is stopped; explicit resume is required")
    _require_solver_eligible_challenge(store.root, current, idea.get("challenge_id"))
    if any(
        row.get("dedupe_key") == idea["dedupe_key"]
        and row.get("effective_status") not in TERMINAL_IDEA_STATES
        for row in ideas.values()
    ):
        raise ValueError("an active compute idea already has this dedupe key")
    generation = int(meta.get("stop_generation", "0"))
    queued = {**idea, "queued_stop_generation": generation}
    store.insert_in_transaction(
        connection,
        "compute.idea.queued",
        queued,
        actor=actor,
        generation=generation,
    )
    return {**queued, "status": "queued", "effective_status": "queued"}


def enqueue_compute_idea(store: EventStore, payload: dict[str, Any]) -> dict[str, Any]:
    with file_lock(store.root / "state" / "mutation.lock"):

        def tx(connection: Any) -> dict[str, Any]:
            return enqueue_compute_idea_in_transaction(store, connection, payload)

        result = store.transaction(tx)
    store.rebuild()
    return result


def _rank_queued(ideas: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    ranked = [
        row
        for row in ideas.values()
        if row.get("effective_status") == "queued"
        and row.get("checkpointable") is True
        and int(row.get("budget_seconds", 0) or 0) > 0
    ]
    for row in ranked:
        row["scheduler_score"] = float(row.get("expected_value", 0.0) or 0.0) + float(
            row.get("evidence_value", 0.0) or 0.0
        )
    return sorted(
        ranked,
        key=lambda row: (
            -float(row["scheduler_score"]),
            str(row.get("created_at") or ""),
            str(row.get("idea_id") or ""),
        ),
    )


def _thresholds(manifest: dict[str, Any]) -> dict[str, float]:
    config = manifest.get("compute", {})
    thresholds = {
        "target_percent": float(config.get("target_percent", DEFAULT_TARGET_PERCENT)),
        "admit_percent": float(config.get("admit_percent", DEFAULT_ADMIT_PERCENT)),
        "ceiling_percent": float(config.get("ceiling_percent", DEFAULT_CEILING_PERCENT)),
        "backoff_percent": float(config.get("backoff_percent", DEFAULT_BACKOFF_PERCENT)),
    }
    if (
        not all(math.isfinite(value) for value in thresholds.values())
        or not 0
        <= thresholds["admit_percent"]
        < thresholds["target_percent"]
        <= thresholds["ceiling_percent"]
        < thresholds["backoff_percent"]
        <= 100
    ):
        raise ValueError("compute CPU thresholds must satisfy 0 <= admit < target <= ceiling < backoff <= 100")
    return thresholds


def _tick_plan(
    *,
    current: dict[str, Any],
    ideas: dict[str, dict[str, Any]],
    observation: dict[str, Any],
    manifest: dict[str, Any],
    events: list[dict[str, Any]],
) -> dict[str, Any]:
    thresholds = _thresholds(manifest)
    base = {
        "thresholds": thresholds,
        "observation": observation,
    }
    if current.get("stopped"):
        return {**base, "action": "none", "reason": "workspace_stopped"}
    if observation.get("available") is not True:
        return {**base, "action": "none", "reason": "metrics_unavailable"}
    windows = observation.get("window_busy_percent")
    if not isinstance(windows, list) or len(windows) != 2:
        return {**base, "action": "none", "reason": "metrics_unavailable"}
    try:
        window_values = [float(value) for value in windows]
        visible_cpus = int(observation.get("visible_cpu_count", 0) or 0)
    except (TypeError, ValueError):
        return {**base, "action": "none", "reason": "metrics_unavailable"}
    if visible_cpus < 1 or any(not math.isfinite(value) or value < 0 or value > 100 for value in window_values):
        return {**base, "action": "none", "reason": "metrics_unavailable"}
    # Derive the capacity decision from the measured windows. The duplicated
    # summary field in an observation is evidence only, never admission truth.
    busy_cores = max(window_values) * visible_cpus / 100.0
    if all(value >= thresholds["backoff_percent"] for value in window_values):
        running = sorted(
            (
                row
                for row in ideas.values()
                if row.get("effective_status") == "running" and row.get("checkpointable") is True
            ),
            key=lambda row: str(row.get("started_at") or row.get("last_event_at") or ""),
            reverse=True,
        )
        return {
            **base,
            "action": "backoff" if running else "none",
            "reason": "sustained_high_cpu" if running else "no_checkpointable_background_work",
            "idea": running[0] if running else None,
        }
    if not all(value < thresholds["admit_percent"] for value in window_values):
        return {**base, "action": "hold", "reason": "cpu_hysteresis_hold"}

    concurrency = manifest.get("concurrency", {})
    compute = manifest.get("compute", {})
    reserve = max(0, int(compute.get("interactive_reserve_units", 0) or 0))
    active_workers = sum(1 for row in current.get("agents", {}).values() if row.get("status") in ACTIVE_AGENT_STATES)
    active_jobs = sum(1 for row in current.get("jobs", {}).values() if row.get("status") in ACTIVE_JOB_STATES)
    outstanding_agent_leases = sum(
        1
        for row in ideas.values()
        if row.get("effective_status") == "leased" and str(row.get("dispatch_kind") or "agent") == "agent"
    )
    outstanding_job_leases = sum(
        1
        for row in ideas.values()
        if row.get("effective_status") == "leased" and str(row.get("dispatch_kind") or "agent") == "job"
    )
    worker_slots = max(
        0,
        int(concurrency.get("max_workers", 1) or 0) - active_workers - outstanding_agent_leases - reserve,
    )
    job_slots = max(
        0,
        int(concurrency.get("max_jobs", 1) or 0) - active_jobs - outstanding_job_leases - reserve,
    )
    cooldown = max(0, int(compute.get("admission_cooldown_seconds", DEFAULT_ADMISSION_COOLDOWN_SECONDS) or 0))
    now = dt.datetime.now(UTC)
    lease_times = [
        parse_iso(event.get("created_at")) for event in events if event.get("event_type") == "compute.idea.leased"
    ]
    recent = max((stamp for stamp in lease_times if stamp is not None), default=None)
    if recent is not None and (now - recent).total_seconds() < cooldown:
        return {**base, "action": "none", "reason": "admission_cooldown"}

    ceiling_cores = visible_cpus * thresholds["ceiling_percent"] / 100.0
    capacity_blocked = False
    candidates = []
    target_cores = visible_cpus * thresholds["target_percent"] / 100.0
    for idea in _rank_queued(ideas):
        dispatch_kind = str(idea.get("dispatch_kind") or "agent")
        if (dispatch_kind == "agent" and worker_slots < 1) or (dispatch_kind == "job" and job_slots < 1):
            capacity_blocked = True
            continue
        requested = int(idea.get("requested_cpu_threads", 1) or 1)
        if busy_cores + requested <= ceiling_cores:
            candidates.append(
                {
                    **idea,
                    "target_distance_cores": round(abs(target_cores - (busy_cores + requested)), 3),
                }
            )
    if candidates:
        candidates.sort(
            key=lambda row: (
                -float(row["scheduler_score"]),
                float(row["target_distance_cores"]),
                str(row.get("created_at") or ""),
                str(row.get("idea_id") or ""),
            )
        )
        return {
            **base,
            "action": "lease",
            "reason": "useful_headroom",
            "idea": candidates[0],
        }
    if capacity_blocked:
        return {**base, "action": "none", "reason": "interactive_capacity_reserved"}
    return {**base, "action": "none", "reason": "cpu_prediction_exceeds_ceiling"}


def admit_compute_tick(
    store: EventStore,
    manifest: dict[str, Any],
    observation: dict[str, Any],
) -> dict[str, Any]:
    """Atomically admit at most one idea or request one cooperative backoff."""

    with file_lock(store.root / "state" / "mutation.lock"):

        def tx(connection: Any) -> dict[str, Any]:
            events, meta = _transaction_snapshot(connection)
            current, ideas = _queue_view(events, meta)
            plan = _tick_plan(current=current, ideas=ideas, observation=observation, manifest=manifest, events=events)
            generation = int(meta.get("stop_generation", "0"))
            if plan["action"] == "lease":
                idea = plan["idea"]
                admission_id = "admission_" + uuid.uuid4().hex
                lease_seconds = max(
                    5,
                    min(
                        300,
                        int(
                            manifest.get("compute", {}).get("lease_seconds", DEFAULT_LEASE_SECONDS)
                            or DEFAULT_LEASE_SECONDS
                        ),
                    ),
                )
                expires = (
                    (dt.datetime.now(UTC) + dt.timedelta(seconds=lease_seconds))
                    .replace(microsecond=0)
                    .isoformat()
                    .replace("+00:00", "Z")
                )
                payload = {
                    "idea_id": idea["idea_id"],
                    "admission_id": admission_id,
                    "lease_expires_at": expires,
                    "leased_at": iso_now(),
                    "cpu_observation": observation,
                }
                if str(idea.get("dispatch_kind") or "agent") == "job":
                    payload["job_label"] = compute_job_label(str(idea["idea_id"]), admission_id)
                store.insert_in_transaction(
                    connection,
                    "compute.idea.leased",
                    payload,
                    actor="coordinator",
                    generation=generation,
                )
                result = {
                    **plan,
                    "admission_id": admission_id,
                    "lease_expires_at": expires,
                }
                if payload.get("job_label"):
                    result["job_label"] = payload["job_label"]
                return result
            if plan["action"] == "backoff":
                idea = plan["idea"]
                store.insert_in_transaction(
                    connection,
                    "compute.idea.pause_requested",
                    {
                        "idea_id": idea["idea_id"],
                        "pause_requested_at": iso_now(),
                        "reason": "sustained CPU above backoff threshold",
                        "cpu_observation": observation,
                    },
                    actor="coordinator",
                    generation=generation,
                )
            return plan

        result = store.transaction(tx)
    store.rebuild()
    return result


def start_compute_idea(
    store: EventStore,
    *,
    idea_id: str,
    admission_id: str,
    agent_attempt_id: str = "",
    job_id: str = "",
) -> dict[str, Any]:
    if bool(agent_attempt_id) == bool(job_id):
        raise ValueError("bind exactly one agent attempt or owned job")
    with file_lock(store.root / "state" / "mutation.lock"):

        def tx(connection: Any) -> dict[str, Any]:
            events, meta = _transaction_snapshot(connection)
            current, ideas = _queue_view(events, meta)
            if current.get("stopped"):
                raise RuntimeError("workspace is stopped; explicit resume is required")
            idea = ideas.get(idea_id)
            if not idea or idea.get("effective_status") != "leased":
                raise ValueError("compute idea has no current lease")
            if idea.get("admission_id") != admission_id:
                raise ValueError("compute admission ID does not match")
            _require_solver_eligible_challenge(store.root, current, idea.get("challenge_id"))
            generation = int(meta.get("stop_generation", "0"))
            exploration = selected_exploration_binding(current, idea)
            if exploration and job_id:
                raise ValueError("selected exploration requires a native agent")
            dispatch_kind = str(idea.get("dispatch_kind") or "agent")
            if (dispatch_kind == "agent") != bool(agent_attempt_id):
                raise ValueError("compute binding does not match its dispatch kind")
            if agent_attempt_id:
                worker = next(
                    (
                        row
                        for row in current.get("agents", {}).values()
                        if row.get("agent_attempt_id") == agent_attempt_id and row.get("status") in ACTIVE_AGENT_STATES
                    ),
                    None,
                )
                if worker is None:
                    raise ValueError("compute worker attempt is not active")
                if (
                    worker.get("objective_id") != idea.get("objective_id")
                    or worker.get("report_path") != idea.get("report_path")
                    or worker.get("stop_generation") != current.get("stop_generation")
                ):
                    raise ValueError("compute worker binding does not match the leased idea")
                if exploration and (
                    str(worker.get("challenge_id") or "")
                    != exploration["provenance"]["challenge_id"]
                    or str(worker.get("source_handoff_id") or "")
                    != exploration["provenance"]["source_handoff_id"]
                ):
                    raise ValueError("compute worker does not match the selected campaign handoff")
            if job_id and not (
                job_id in current.get("jobs", {})
                and current["jobs"][job_id].get("status") in ACTIVE_JOB_STATES
                and current["jobs"][job_id].get("stop_generation") == current.get("stop_generation")
                and current["jobs"][job_id].get("label") == compute_job_label(idea_id, admission_id)
            ):
                raise ValueError("compute owned job is not active or lease-bound")
            payload = {
                "idea_id": idea_id,
                "admission_id": admission_id,
                "agent_attempt_id": agent_attempt_id,
                "job_id": job_id,
                "started_at": iso_now(),
            }
            store.insert_in_transaction(
                connection,
                "compute.idea.started",
                payload,
                actor="coordinator",
                generation=generation,
            )
            return {**idea, **payload, "status": "running", "effective_status": "running"}

        result = store.transaction(tx)
    store.rebuild()
    return result


def finish_compute_idea(
    store: EventStore,
    *,
    idea_id: str,
    status: str,
    summary: str,
    admission_id: str,
    agent_attempt_id: str = "",
    job_id: str = "",
    report_path: str = "",
    checkpoint_path: str = "",
) -> dict[str, Any]:
    allowed = TERMINAL_IDEA_STATES | {"paused"}
    if status not in allowed:
        raise ValueError("compute outcome status is invalid")
    if bool(agent_attempt_id) == bool(job_id):
        raise ValueError("bind outcome to exactly one agent attempt or owned job")
    summary = _bounded_text(summary, "outcome summary", maximum=2000)
    with file_lock(store.root / "state" / "mutation.lock"):

        def tx(connection: Any) -> dict[str, Any]:
            events, meta = _transaction_snapshot(connection)
            current, ideas = _queue_view(events, meta)
            if current.get("stopped"):
                raise RuntimeError("workspace is stopped; explicit resume is required")
            idea = ideas.get(idea_id)
            if not idea or idea.get("effective_status") not in {
                "running",
                "pause_requested",
            }:
                raise ValueError("compute work must start before an outcome")
            if idea.get("admission_id") != admission_id:
                raise ValueError("compute outcome admission ID does not match")
            if str(idea.get("agent_attempt_id") or "") != agent_attempt_id or str(idea.get("job_id") or "") != job_id:
                raise ValueError("compute outcome runner identity does not match")
            resolved_report = _report_path(report_path or idea.get("report_path"))
            generation = int(meta.get("stop_generation", "0"))
            exploration = selected_exploration_binding(current, idea)
            if exploration and job_id:
                raise ValueError("selected exploration requires a native agent")
            closeout: dict[str, str] = {}
            if status == "completed":
                if resolved_report != str(idea.get("report_path") or ""):
                    raise ValueError(
                        "compute completion report must match the leased work"
                    )
                if not exploration:
                    report_sha256 = _private_report_sha256(
                        store.root, resolved_report
                    )
                    closeout["report_sha256"] = report_sha256
                if agent_attempt_id and not exploration:
                    closeout.update(
                        _require_agent_completion_closeout(
                            events,
                            current,
                            idea=idea,
                            generation=generation,
                            agent_attempt_id=agent_attempt_id,
                            report_sha256=report_sha256,
                        )
                    )
            if exploration and status == "completed":
                if resolved_report != str(idea.get("report_path") or ""):
                    raise ValueError("selected compute completion report must match the leased task card")
                closeout.update(
                    _require_selected_owner_closeout(
                        events,
                        current,
                        root=store.root,
                        idea=idea,
                        generation=generation,
                        exploration=exploration,
                        agent_attempt_id=agent_attempt_id,
                    )
                )
            resolved_checkpoint = ""
            if status == "paused":
                if not checkpoint_path:
                    raise ValueError("paused compute work requires a checkpoint path")
                resolved_checkpoint = _existing_private_checkpoint(store.root, checkpoint_path)
            payload = {
                "idea_id": idea_id,
                "admission_id": admission_id,
                "agent_attempt_id": agent_attempt_id,
                "job_id": job_id,
                "summary": summary,
                "report_path": resolved_report,
                "checkpoint_path": resolved_checkpoint,
                **closeout,
                "finished_at": iso_now(),
            }
            store.insert_in_transaction(
                connection,
                f"compute.idea.{status}",
                payload,
                actor="coordinator",
                generation=generation,
            )
            return {**idea, **payload, "status": status, "effective_status": status}

        result = store.transaction(tx)
    store.rebuild()
    return result


def requeue_compute_idea(store: EventStore, *, idea_id: str) -> dict[str, Any]:
    """Return one durably checkpointed idea to the current generation."""

    with file_lock(store.root / "state" / "mutation.lock"):

        def tx(connection: Any) -> dict[str, Any]:
            events, meta = _transaction_snapshot(connection)
            current, ideas = _queue_view(events, meta)
            if current.get("stopped"):
                raise RuntimeError("workspace is stopped; explicit resume is required")
            idea = ideas.get(idea_id)
            if not idea or idea.get("status") != "paused" or not idea.get("checkpoint_path"):
                raise ValueError("compute idea has no durable paused checkpoint")
            _existing_private_checkpoint(store.root, idea["checkpoint_path"])
            generation = int(meta.get("stop_generation", "0"))
            payload = {
                "idea_id": idea_id,
                "queued_stop_generation": generation,
                "requeued_at": iso_now(),
            }
            store.insert_in_transaction(
                connection,
                "compute.idea.queued",
                payload,
                actor="coordinator",
                generation=generation,
            )
            return {**idea, **payload, "status": "queued", "effective_status": "queued"}

        result = store.transaction(tx)
    store.rebuild()
    return result


def compute_queue_status(store: EventStore) -> dict[str, Any]:
    snapshot = store.read_snapshot()
    generation = int(snapshot.get("meta", {}).get("stop_generation", "0"))
    events = snapshot.get("events", [])
    ideas = project_compute_ideas(events, current_stop_generation=generation)
    counts: dict[str, int] = {}
    for idea in ideas.values():
        status = str(idea.get("effective_status") or "unknown")
        counts[status] = counts.get(status, 0) + 1
    return {
        "schema_version": "1",
        "stop_generation": generation,
        "counts": counts,
        "ideas": sorted(
            ideas.values(), key=lambda row: (str(row.get("created_at") or ""), str(row.get("idea_id") or ""))
        ),
    }
