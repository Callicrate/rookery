from __future__ import annotations

from copy import deepcopy
from typing import Any

ACTIVE_AGENT_STATES = {"assigned", "running", "stopping"}
ACTIVE_JOB_STATES = {"queued", "running", "stopping", "unacknowledged", "unmanaged"}
ACTIVE_COMMAND_STATES = {"started", "stopping"}

# A projection only needs enough recent platform provenance to explain which
# snapshots led to the current view.  Canonical snapshots remain complete in
# SQLite; this cap bounds the rebuild output that status and agents consume.
PLATFORM_HISTORY_LIMIT = 32

# Platform inventory snapshots intentionally contain lightweight challenge
# summaries.  Once intake materializes a challenge, these fields belong to that
# immutable detail attempt and must not be replaced by summary placeholders.
INTAKE_OWNED_CHALLENGE_FIELDS = frozenset(
    {
        "captured_file_count",
        "captured_files",
        "description",
        "description_html",
        "description_text",
        "detail_bytes",
        "detail_metadata",
        "detail_path",
        "detail_sha256",
        "expected_file_count",
        "files",
        "hints",
        "html",
        "ingested_at",
        "manual_grade",
        "manual_grading",
        "metadata",
        "penalties",
        "points_graded",
        "ratings",
        "resources",
        "resources_complete",
        "resources_truncated",
        "solve_count",
        "solved_by",
        "tags",
        "teammates_solved",
        "text",
    }
)


def _is_nonnegative_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def platform_inventory_is_authoritative(payload: dict[str, Any]) -> bool:
    """Return whether an inventory row can retire omitted challenge IDs.

    Failed or legacy snapshots cannot distinguish an empty platform from an
    unavailable inventory.  Only a usable inventory capability makes omission
    meaningful.
    """

    capabilities = payload.get("capabilities")
    if not isinstance(capabilities, dict):
        return False
    inventory = capabilities.get("platform_inventory")
    return (
        isinstance(inventory, dict)
        and inventory.get("availability") == "available"
        and inventory.get("health") in {"healthy", "degraded"}
        and isinstance(payload.get("challenges"), list)
    )


def _apply_challenge_event(
    challenges: dict[str, dict[str, Any]],
    event_type: str,
    payload: dict[str, Any],
    *,
    stamp: dict[str, Any] | None = None,
) -> None:
    """Apply one challenge-bearing event using the canonical merge contract."""

    if event_type == "platform.snapshot":
        authoritative_inventory = platform_inventory_is_authoritative(payload)
        listed_challenge_ids: set[str] = set()
        for challenge in payload.get("challenges", []):
            if not isinstance(challenge, dict):
                continue
            cid = str(challenge.get("id", ""))
            if not cid:
                continue
            listed_challenge_ids.add(cid)
            old = challenges.get(cid, {})
            merged = {
                **old,
                **challenge,
                "source": payload.get("artifact", ""),
                "adapter_id": payload.get("adapter_id", ""),
            }
            if "intake_attempt_id" in old or "intake_state" in old:
                merged.update(
                    {
                        key: value
                        for key, value in old.items()
                        if key in INTAKE_OWNED_CHALLENGE_FIELDS
                        or key.startswith("intake_")
                    }
                )
            if authoritative_inventory:
                merged["platform_present"] = True
            challenges[cid] = merged
        if authoritative_inventory:
            for cid, challenge in challenges.items():
                if cid not in listed_challenge_ids:
                    challenge["platform_present"] = False
        return
    if event_type not in {"challenge.upsert", "challenge.classify"}:
        return
    cid = str(payload.get("id", ""))
    if not cid:
        return
    baseline = challenges.get(cid, {"id": cid})
    challenges[cid] = {**baseline, **payload, **(stamp or {})}


def canonical_challenges(events: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Project challenges with the same merge contract as ``reduce_events``."""

    challenges: dict[str, dict[str, Any]] = {}
    for event in events:
        payload = event.get("payload")
        if isinstance(payload, dict):
            _apply_challenge_event(challenges, str(event.get("event_type") or ""), payload)
    return challenges


def _authoritative_platform_baseline(
    event: dict[str, Any], payload: dict[str, Any]
) -> dict[str, Any]:
    """Keep only the authoritative inventory facts unlock detection needs."""

    challenge_ids = sorted(
        {
            str(challenge.get("id") or "")
            for challenge in payload["challenges"]
            if isinstance(challenge, dict) and str(challenge.get("id") or "")
        }
    )
    return {
        "event_id": event["event_id"],
        "event_at": event["created_at"],
        "stop_generation": event["generation"],
        "actor": event["actor"],
        "adapter_id": str(payload.get("adapter_id") or ""),
        "challenge_count": len(challenge_ids),
        "challenge_ids": challenge_ids,
    }


def control_resume_is_current(
    event: dict[str, Any], *, stop_generation: int
) -> bool:
    """Accept only the exact operator resume that belongs to current control.

    Control rows are canonical evidence but still originate at a trust boundary.
    A stale or malformed resume must never reopen admission merely because it is
    later in append order than a durable stop.
    """

    if (
        not isinstance(event, dict)
        or event.get("event_type") != "control.resume"
        or event.get("actor") != "operator"
        or not _is_nonnegative_int(stop_generation)
        or not _is_nonnegative_int(event.get("generation"))
        or event.get("generation") != stop_generation
    ):
        return False
    payload = event.get("payload")
    return (
        isinstance(payload, dict)
        and _is_nonnegative_int(payload.get("generation"))
        and payload.get("generation") == stop_generation
        and bool(str(payload.get("reason") or "").strip())
    )


def _latest_map(
    events: list[dict[str, Any]], prefix: str, key: str
) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for event in events:
        if not event["event_type"].startswith(prefix):
            continue
        payload = event["payload"]
        ident = str(payload.get(key, ""))
        if ident:
            out[ident] = {
                **payload,
                "event_id": event["event_id"],
                "event_at": event["created_at"],
                "event_type": event["event_type"],
                "stop_generation": event["generation"],
            }
    return out


def reduce_events(events: list[dict[str, Any]], store=None) -> dict[str, Any]:
    stop_generation = (
        int(store.get_meta("stop_generation", "0"))
        if store
        else max([e.get("generation", 0) for e in events] + [0])
    )
    policy_generation = int(store.get_meta("policy_generation", "0")) if store else 0
    current: dict[str, Any] = {
        "schema_version": "1",
        "updated_at": events[-1]["created_at"] if events else "1970-01-01T00:00:00Z",
        "stop_generation": stop_generation,
        "policy_generation": policy_generation,
        "event_count": len(events),
        "stopped": False,
        "active_goal": None,
        "platform": {},
        "authoritative_platform": {},
        "challenges": {},
        "proposals": {},
        "reviews": {},
        "authorizations": {},
        "agents": {},
        "jobs": {},
        "commands": {},
        "retries": {},
        "executions": {},
        "outcomes": {},
        "solve_capsules": {},
        "evidence_capsules": {},
        "harvested_reports": {},
        "task_completions": {},
        "compute_ideas": {},
        "exploration_campaigns": {},
        "continuation_audit": {},
        "challenge_coordination": {},
    }
    policy_history: dict[str, list[dict[str, Any]]] = {}
    effective_policy: dict[str, dict[str, Any]] = {}
    goal_history: list[dict[str, Any]] = []
    queue_schedules: dict[str, dict[str, Any]] = {}
    queue_escalations: set[str] = set()
    platform_history: list[dict[str, Any]] = []
    scoring_events: list[dict[str, Any]] = []

    for event in events:
        etype = event["event_type"]
        payload = deepcopy(event["payload"])
        stamp = {
            "event_id": event["event_id"],
            "event_at": event["created_at"],
            "stop_generation": event["generation"],
            "actor": event["actor"],
        }
        payload_stamp = {
            "event_id": event["event_id"],
            "event_at": event["created_at"],
            "event_stop_generation": event["generation"],
            "actor": event["actor"],
        }
        if etype == "control.stop":
            current["stopped"] = True
            current["stop"] = {**payload, **stamp}
        elif etype == "control.resume":
            if control_resume_is_current(event, stop_generation=stop_generation):
                current["stopped"] = False
                current["resume"] = {**payload, **stamp}
            else:
                # A malformed resume is not a benign no-op: it is a control
                # authority failure, so consumers fail closed until a later,
                # exact operator resume attests to the current generation.
                current["stopped"] = True
                current["invalid_resume"] = {**payload, **stamp}
        elif etype == "goal.set":
            row = {**payload, **stamp, "status": "active"}
            goal_history.append(row)
            current["active_goal"] = row
        elif etype == "goal.supersede":
            row = {**payload, **stamp, "status": "superseded"}
            goal_history.append(row)
            if current.get("active_goal") and payload.get("goal_id") in {
                None,
                "",
                current["active_goal"].get("goal_id"),
            }:
                current["active_goal"] = None
        elif etype == "policy.set":
            key = str(payload.get("key", ""))
            if key:
                row = {**payload, **stamp}
                policy_history.setdefault(key, []).append(row)
                effective_policy[key] = row
        elif etype == "platform.snapshot":
            row = {**payload, **stamp}
            current["platform"] = row
            challenges = payload.get("challenges", [])
            capabilities = payload.get("capabilities", {})
            authoritative_inventory = platform_inventory_is_authoritative(payload)
            platform_history.append(
                {
                    "event_id": event["event_id"],
                    "event_at": event["created_at"],
                    "stop_generation": event["generation"],
                    "actor": event["actor"],
                    "adapter_id": str(payload.get("adapter_id") or ""),
                    "challenge_count": len(challenges)
                    if isinstance(challenges, list)
                    else 0,
                    "capability_count": len(capabilities)
                    if isinstance(capabilities, dict)
                    else 0,
                }
            )
            if len(platform_history) > PLATFORM_HISTORY_LIMIT:
                del platform_history[0]
            if authoritative_inventory:
                current["authoritative_platform"] = _authoritative_platform_baseline(
                    event, payload
                )
            _apply_challenge_event(current["challenges"], etype, payload)
        elif etype == "challenge.upsert":
            _apply_challenge_event(current["challenges"], etype, payload, stamp=stamp)
        elif etype == "challenge.classify":
            _apply_challenge_event(current["challenges"], etype, payload, stamp=stamp)
        elif etype == "proposal.created":
            pid = str(payload.get("proposal_id", ""))
            if pid:
                current["proposals"][pid] = {
                    **payload,
                    **payload_stamp,
                    "status": "proposed",
                }
                scoring_events.append({"class": "proposal", **payload, **payload_stamp})
        elif etype == "proposal.verifier_attached":
            pid = str(payload.get("proposal_id", ""))
            if pid:
                old = current["proposals"].get(pid, {"proposal_id": pid})
                current["proposals"][pid] = {**old, **payload, **stamp}
        elif etype == "review.recorded":
            pid = str(payload.get("proposal_id", ""))
            if pid:
                current["reviews"][pid] = {**payload, **payload_stamp}
                if pid in current["proposals"]:
                    current["proposals"][pid]["status"] = payload.get(
                        "verdict", "reviewed"
                    )
        elif etype.startswith("authorization."):
            aid = str(payload.get("authorization_id", ""))
            if aid:
                status = etype.split(".", 1)[1]
                old = current["authorizations"].get(aid, {})
                current["authorizations"][aid] = {
                    **old,
                    **payload,
                    **payload_stamp,
                    "status": status,
                }
        elif etype.startswith("agent."):
            aid = str(payload.get("agent_id", ""))
            if aid:
                status = etype.split(".", 1)[1]
                old = current["agents"].get(aid, {})
                current["agents"][aid] = {**old, **payload, **stamp, "status": status}
        elif etype.startswith("job."):
            jid = str(payload.get("job_id", ""))
            if jid:
                status = etype.split(".", 1)[1]
                old = current["jobs"].get(jid, {})
                current["jobs"][jid] = {**old, **payload, **stamp, "status": status}
        elif etype.startswith("command."):
            command_id = str(payload.get("command_id", ""))
            if command_id:
                status = etype.split(".", 1)[1]
                old = current["commands"].get(command_id, {})
                current["commands"][command_id] = {
                    **old,
                    **payload,
                    **stamp,
                    "status": status,
                }
        elif etype.startswith("retry."):
            rid = str(payload.get("retry_id", ""))
            if rid:
                status = etype.split(".", 1)[1]
                old = current["retries"].get(rid, {})
                current["retries"][rid] = {**old, **payload, **stamp, "status": status}
        elif etype == "queue.scheduled":
            pid = str(payload.get("proposal_id", ""))
            if pid:
                queue_schedules[pid] = {**payload, **stamp}
        elif etype == "queue.escalated":
            pid = str(payload.get("proposal_id", ""))
            if pid:
                queue_escalations.add(pid)
        elif etype == "execution.planned":
            plan_id = str(payload.get("plan_id", ""))
            if plan_id:
                current["executions"][plan_id] = {
                    **payload,
                    **stamp,
                    "status": "planned",
                }
        elif etype.startswith("execution."):
            plan_id = str(payload.get("plan_id", ""))
            if plan_id:
                raw_status = etype.split(".", 1)[1]
                old = current["executions"].get(plan_id, {})
                # Historical event streams recorded post-dispatch uncertainty as
                # ``failed`` or ``blocked`` after a durable start claim.  Treat
                # them as terminal uncertainty without rewriting append-only
                # evidence, so an upgrade cannot make them queue-eligible.
                status = (
                    "indeterminate"
                    if raw_status == "failed"
                    or (raw_status == "blocked" and old.get("status") == "started")
                    else raw_status
                )
                current["executions"][plan_id] = {
                    **old,
                    **payload,
                    **stamp,
                    "status": status,
                }
                if status in {
                    "completed",
                    "rejected",
                    "indeterminate",
                    "blocked",
                    "failed",
                }:
                    scoring_events.append(
                        {"class": "scorer_truth", **payload, **stamp, "state": status}
                    )
        elif etype == "outcome.recorded":
            oid = str(payload.get("outcome_id", ""))
            if oid:
                current["outcomes"][oid] = {**payload, **stamp}
        elif etype == "report.harvested":
            path = str(payload.get("report_path", ""))
            if path:
                current["harvested_reports"][path] = {**payload, **stamp}
        elif etype == "solve.capsule":
            cid = str(payload.get("objective_id", ""))
            if cid:
                current["solve_capsules"][cid] = {**payload, **stamp}
        elif etype == "evidence.capsule":
            cid = str(payload.get("objective_id", ""))
            if cid:
                # Evidence-only completion records bounded analysis.  It is
                # intentionally separate from solve capsules and cannot alter
                # the platform-derived solved projection above.
                current["evidence_capsules"][cid] = {**payload, **stamp}
        elif etype == "task.completed":
            completion_id = str(payload.get("completion_id", ""))
            if completion_id:
                current["task_completions"][completion_id] = {**payload, **stamp}

    active_agents = [
        x for x in current["agents"].values() if x.get("status") in ACTIVE_AGENT_STATES
    ]
    active_jobs = [
        x for x in current["jobs"].values() if x.get("status") in ACTIVE_JOB_STATES
    ]
    active_commands = [
        x
        for x in current["commands"].values()
        if x.get("status") in ACTIVE_COMMAND_STATES
    ]
    visible = [
        challenge
        for challenge in current["challenges"].values()
        if challenge.get("platform_present") is not False
    ]
    solved = [
        x for x in visible if x.get("solved") or x.get("classification") == "solved"
    ]
    queue_items = []
    for pid, proposal in current["proposals"].items():
        review = current["reviews"].get(pid, {})
        executed = any(
            ex.get("proposal_id") == pid
            and ex.get("status")
            in {"started", "completed", "rejected", "indeterminate"}
            for ex in current["executions"].values()
        )
        if executed:
            continue
        queue_items.append(
            {
                "proposal_id": pid,
                "objective_id": proposal.get("objective_id"),
                "action_kind": proposal.get("action_kind"),
                "proposal_status": proposal.get("status"),
                "review_verdict": review.get("verdict", "pending"),
                "scheduled": queue_schedules.get(pid),
                "escalated": pid in queue_escalations,
                "created_at": proposal.get("event_at"),
            }
        )
    queue = {
        "items": sorted(
            queue_items, key=lambda x: (x.get("created_at") or "", x["proposal_id"])
        ),
        "depth": len(queue_items),
        "schedules": queue_schedules,
        "escalated": sorted(queue_escalations),
    }
    # Keep useful background work in its own namespace. It never contributes
    # proposals, reviews, authorizations, or the scoring queue above.
    from .compute import project_compute_ideas

    current["compute_ideas"] = project_compute_ideas(
        events,
        current_stop_generation=stop_generation,
    )
    from .exploration import project_exploration_campaigns

    current["exploration_campaigns"] = project_exploration_campaigns(
        events,
        current_stop_generation=stop_generation,
    )
    for campaign in current["exploration_campaigns"].values():
        if campaign.get("effective_status") != "active":
            continue
        selected_rows = list(campaign.get("selected", {}).values())
        selected_compute = [
            current["compute_ideas"].get(str(row.get("compute_idea_id") or ""), {})
            for row in selected_rows
        ]
        if any(row.get("effective_status") == "running" for row in selected_compute):
            campaign["workflow_state"] = "solving"
        elif selected_compute and any(
            row.get("effective_status") in {"queued", "leased"}
            for row in selected_compute
        ):
            campaign["workflow_state"] = "capacity_wait"
    from .outcomes import continuation_audit, derive_challenge_coordination

    current["challenge_coordination"] = derive_challenge_coordination(
        events,
        current_generation=stop_generation,
    )
    current["continuation_audit"] = continuation_audit(
        events,
        current_generation=stop_generation,
        coordination=current["challenge_coordination"],
    )
    current["counts"] = {
        "visible": len(visible),
        "solved": len(solved),
        "unsolved": len(visible) - len(solved),
        "active_agents": len(active_agents),
        "active_jobs": len(active_jobs),
        "active_commands": len(active_commands),
        "queue_depth": len(queue_items),
        "pending_retries": sum(
            1 for r in current["retries"].values() if r.get("status") == "scheduled"
        ),
        "compute_ideas": len(current["compute_ideas"]),
        "compute_ideas_queued": sum(
            1
            for idea in current["compute_ideas"].values()
            if idea.get("effective_status") == "queued"
        ),
        "exploration_campaigns": len(current["exploration_campaigns"]),
        "exploration_capacity_wait": sum(
            1
            for campaign in current["exploration_campaigns"].values()
            if campaign.get("workflow_state") == "capacity_wait"
        ),
        "exploration_parked": sum(
            1
            for campaign in current["exploration_campaigns"].values()
            if campaign.get("effective_status") == "parked"
        ),
    }
    return {
        "schema_version": "1",
        "generated_at": events[-1]["created_at"] if events else "1970-01-01T00:00:00Z",
        "current": current,
        "policy": {
            "generation": policy_generation,
            "effective": effective_policy,
            "history": policy_history,
        },
        "goals": goal_history,
        "queue": queue,
        "platform_history": platform_history,
        "scoring_events": scoring_events,
    }
