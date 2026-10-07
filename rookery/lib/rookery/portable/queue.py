from __future__ import annotations

import datetime as dt
import hashlib
from typing import Any

from .scoring import admission_wait_reasons
from .store import EventStore, SnapshotStopGenerationChanged
from .util import UTC, canonical_json, iso_now, parse_iso


def _schedule_time(
    proposal: dict[str, Any],
    queue_cfg: dict[str, Any],
    anchor: dt.datetime | None,
    persisted_at: str | None,
) -> str:
    cadence = max(0, int(queue_cfg.get("cadence_seconds", 0) or 0))
    jitter = max(0, int(queue_cfg.get("jitter_seconds", 0) or 0))
    created = parse_iso(
        proposal.get("created_at") or proposal.get("event_at")
    ) or dt.datetime.now(UTC)
    base = max(created, anchor) if anchor is not None else created
    seed = int(hashlib.sha256(proposal["proposal_id"].encode()).hexdigest()[:8], 16)
    offset = seed % (jitter + 1) if jitter > 0 else 0
    scheduled = base + dt.timedelta(seconds=cadence + offset)
    persisted = parse_iso(persisted_at)
    if persisted is not None:
        scheduled = max(scheduled, persisted)
    return (
        scheduled
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _available_authorization_from_current(
    current: dict[str, Any], proposal: dict[str, Any]
) -> dict[str, Any] | None:
    """Display authorization availability without reopening or mutating state.

    This mirrors the queue-facing subset of the execution policy. It is
    intentionally advisory: ``claim_plan_authority`` still rechecks exact
    review, authorization, policy, and stop predicates in its mutation lock.
    """

    current_stop_generation = int(current.get("stop_generation", 0) or 0)
    current_policy_generation = int(current.get("policy_generation", 0) or 0)
    exact: list[dict[str, Any]] = []
    allowance: list[dict[str, Any]] = []
    authorizations = current.get("authorizations", {})
    values = authorizations.values() if isinstance(authorizations, dict) else []
    for row in values:
        if not isinstance(row, dict):
            continue
        try:
            remaining = int(row.get("remaining", 0) or 0)
        except (TypeError, ValueError):
            continue
        if row.get("status") != "granted" or remaining <= 0:
            continue
        if not _generation_matches(
            row, "stop_generation", current_stop_generation
        ):
            continue
        if not _generation_matches(
            row, "policy_generation", current_policy_generation
        ):
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
    return min(rows, key=lambda row: str(row.get("event_at") or "")) if rows else None


def _generation_matches(
    row: dict[str, Any], key: str, current_generation: int
) -> bool:
    """Fail closed when advisory authorization generation evidence is malformed."""

    value = row.get(key, -1)
    return isinstance(value, int) and not isinstance(value, bool) and value == current_generation


def evaluate_queue(
    projection: dict[str, Any],
    manifest: dict[str, Any],
    *,
    now: dt.datetime | None = None,
) -> dict[str, Any]:
    """Purely derive advisory queue display state from one reduced snapshot."""

    current = projection["current"]
    queue_cfg = manifest.get("queue", {})
    now = now or dt.datetime.now(UTC)
    last_mutation: dt.datetime | None = None
    for execution in current["executions"].values():
        if execution.get("status") in {
            "started",
            "completed",
            "rejected",
            "indeterminate",
        }:
            stamp = parse_iso(execution.get("event_at"))
            if stamp is not None and (
                last_mutation is None or stamp > last_mutation
            ):
                last_mutation = stamp
    items = []
    schedules = projection.get("queue", {}).get("schedules", {})
    escalated = set(projection.get("queue", {}).get("escalated", []))
    pending: list[tuple[str, dict[str, Any]]] = []
    for pid, proposal in current["proposals"].items():
        executed = any(
            row.get("proposal_id") == pid
            and row.get("status")
            in {"started", "completed", "rejected", "indeterminate"}
            for row in current["executions"].values()
        )
        if not executed:
            pending.append((pid, proposal))
    pending.sort(
        key=lambda row: (
            row[1].get("created_at") or row[1].get("event_at") or "",
            row[0],
        )
    )
    schedule_cursor = last_mutation
    for pid, proposal in pending:
        review = current["reviews"].get(pid, {})
        authorization = _available_authorization_from_current(current, proposal)
        reasons = admission_wait_reasons(current, proposal, review, authorization)
        schedule = schedules.get(pid)
        persisted_at = (
            schedule.get("scheduled_at") if isinstance(schedule, dict) else None
        )
        scheduled_at = _schedule_time(
            proposal, queue_cfg, schedule_cursor, persisted_at
        )
        scheduled_dt = parse_iso(scheduled_at)
        if scheduled_dt is not None:
            schedule_cursor = scheduled_dt
        if scheduled_dt and scheduled_dt > now:
            reasons.append(f"cadence wait until {scheduled_at}")
        eligible = not reasons
        created = parse_iso(proposal.get("event_at")) or now
        age = max(0, int((now - created).total_seconds()))
        objective = int(queue_cfg.get("latency_objective_seconds", 0) or 0)
        breached = bool(objective and age > objective)
        items.append(
            {
                "proposal_id": pid,
                "objective_id": proposal.get("objective_id"),
                "action_kind": proposal.get("action_kind"),
                "age_seconds": age,
                "eligible": eligible,
                "wait_reasons": reasons,
                "scheduled_at": scheduled_at,
                "latency_objective_seconds": objective,
                "objective_breached": breached,
                "escalated": pid in escalated,
                "reviewer_state": review.get("verdict", "pending"),
                "adapter_id": proposal.get("adapter_id"),
            }
        )
    items.sort(
        key=lambda x: (
            not x["eligible"],
            x["scheduled_at"] or "",
            -x["age_seconds"],
            x["proposal_id"],
        )
    )
    return {
        "generated_at": iso_now(),
        "depth": len(items),
        "eligible": sum(1 for item in items if item["eligible"]),
        "oldest_eligible_age_seconds": max(
            [item["age_seconds"] for item in items if item["eligible"]] or [0]
        ),
        "items": items,
        "next_action": next(
            (item for item in items if item["eligible"]), items[0] if items else None
        ),
    }


def queue_from_snapshot(
    store: EventStore, manifest: dict[str, Any], snapshot: dict[str, Any]
) -> dict[str, Any]:
    """Evaluate a queue using only the supplied event/meta snapshot."""

    return evaluate_queue(store.projection_from_snapshot(snapshot), manifest)


def build_queue(store: EventStore, manifest: dict[str, Any]) -> dict[str, Any]:
    """Build a display queue from a single read-only event/meta snapshot."""

    return queue_from_snapshot(store, manifest, store.read_snapshot())


def _queue_event_id(event_type: str, payload: dict[str, Any]) -> str:
    digest = hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()
    return f"{event_type}:{digest}"


def persist_schedules(
    store: EventStore,
    manifest: dict[str, Any],
    *,
    snapshot: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Persist missing or rebased schedules in one idempotent mutation.

    A warm queue returns after its initial read snapshot. A changed queue batches
    all schedule/escalation evidence into one transaction, then emits one coherent
    post-mutation projection publication.
    """

    snapshot = store.read_snapshot() if snapshot is None else snapshot
    projection = store.projection_from_snapshot(snapshot)
    queue = evaluate_queue(projection, manifest)
    if projection["current"].get("stopped"):
        return queue
    existing = projection.get("queue", {}).get("schedules", {})
    events: list[dict[str, Any]] = []
    for item in queue["items"]:
        previous = existing.get(item["proposal_id"])
        if not isinstance(previous, dict) or previous.get("scheduled_at") != item[
            "scheduled_at"
        ]:
            payload = {
                "proposal_id": item["proposal_id"],
                "scheduled_at": item["scheduled_at"],
            }
            events.append(
                {
                    "event_type": "queue.scheduled",
                    "payload": payload,
                    "actor": "queue",
                    "event_id": _queue_event_id("queue.scheduled", payload),
                }
            )
        if (
            item["objective_breached"]
            and not item["escalated"]
            and item["reviewer_state"] == "approved"
        ):
            payload = {
                "proposal_id": item["proposal_id"],
                "reason": "latency objective breached",
            }
            events.append(
                {
                    "event_type": "queue.escalated",
                    "payload": payload,
                    "actor": "queue",
                    "event_id": _queue_event_id("queue.escalated", payload),
                }
            )
    if not events:
        return queue
    observed_stop_generation = int(projection["current"].get("stop_generation", 0) or 0)
    try:
        inserted = store.append_many(
            events,
            generation=observed_stop_generation,
            expected_stop_generation=observed_stop_generation,
        )
    except SnapshotStopGenerationChanged:
        # A stop that wins after the read snapshot invalidates the advisory
        # queue. Do not create schedules or plans from it; return a current
        # read-only view so the caller sees the stop-generation wait reason.
        return queue_from_snapshot(store, manifest, store.read_snapshot())
    if not any(written for _, written in inserted):
        return queue
    refreshed = store.read_snapshot()
    store.rebuild(refreshed)
    return queue_from_snapshot(store, manifest, refreshed)
