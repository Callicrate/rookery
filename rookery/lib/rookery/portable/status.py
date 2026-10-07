from __future__ import annotations

import datetime as dt
import json
import os
import sqlite3
import stat
from pathlib import Path
from typing import Any

from .control import process_identity_matches
from .manifest import ManifestResult, validate_manifest
from .queue import build_queue
from .reducers import control_resume_is_current
from .store import EventStore
from .util import UTC, atomic_write_json, iso_now, load_json, parse_iso
from .watchers import queue_watcher_status


_STATUS_CURRENT_MAX_BYTES = 4 * 1024 * 1024
_STATUS_CONTROL_PAYLOAD_MAX_BYTES = 64 * 1024
_STATUS_RECONCILIATION_DEBT_MAX_PATHS = 64
_STATUS_RECONCILIATION_DEBT_RENDERED_PATHS = 16
_STATUS_RECONCILIATION_DEBT_PATH_MAX_BYTES = 512
_ACTIVE_AGENT_STATUSES = frozenset({"assigned", "running", "stopping"})
_ACTIVE_JOB_STATUSES = frozenset({"queued", "running", "stopping"})


def _release_version(root: Path) -> str:
    path = root / "VERSION"
    return (
        path.read_text(encoding="utf-8", errors="replace").strip()
        if path.is_file()
        else "unknown"
    )


def derive_lifecycle_state(
    current: dict[str, Any],
    result: ManifestResult,
    startup_checks: list[dict[str, Any]],
    watcher_startup: dict[str, Any] | None = None,
    preparation: dict[str, Any] | None = None,
) -> str:
    """Derive the shared public lifecycle state from persisted facts."""

    if current.get("stopped"):
        return "stopped"
    if result.unresolved_required:
        return "unresolved"
    if result.errors:
        return "blocked"
    if any(
        check.get("classification") == "required" and not check.get("ok")
        for check in startup_checks
    ):
        return "blocked"
    if _preparation_blockers(preparation):
        return "blocked"
    if _watcher_startup_blocker(result, watcher_startup):
        return "blocked"
    return "ready"


def _preparation_blockers(preparation: dict[str, Any] | None) -> list[str]:
    """Return value-free lifecycle blockers from preparation evidence."""

    if not isinstance(preparation, dict) or not preparation:
        return []
    raw_missing = preparation.get("missing_required", [])
    if not isinstance(raw_missing, list):
        return ["preparation: missing_required is malformed"]
    missing = [str(name).strip() for name in raw_missing if str(name).strip()]
    if missing:
        return [f"preparation: missing required capability: {name}" for name in missing]
    if preparation.get("ready") is False:
        return ["preparation: required capability readiness is false"]
    return []


def _watcher_startup_blocker(
    result: ManifestResult, watcher_startup: dict[str, Any] | None
) -> str | None:
    if (
        watcher_startup is None
        or not result.manifest.get("queue", {}).get("automation_enabled", False)
        or watcher_startup.get("running", False)
    ):
        return None
    return "queue watcher: " + str(watcher_startup.get("reason") or "not running")


def refresh_snapshot(
    store: EventStore,
    root: Path,
    manifest: dict[str, Any],
    result: ManifestResult | None = None,
    watcher_startup: dict[str, Any] | None = None,
    preparation: dict[str, Any] | None = None,
) -> dict[str, Any]:
    result = result or validate_manifest(manifest)
    if preparation is None:
        persisted = load_json(root / "state" / "preparation.json", {})
        preparation = persisted if isinstance(persisted, dict) else {}
    if (
        watcher_startup is None
        and result.manifest.get("queue", {}).get("automation_enabled", False)
    ):
        watcher_startup = queue_watcher_status(store, root)
    projection = store.rebuild()
    current = projection["current"]
    queue = build_queue(store, manifest)
    now = dt.datetime.now(UTC)
    due_retries = []
    for retry in current.get("retries", {}).values():
        when = parse_iso(retry.get("earliest_at"))
        if retry.get("status") == "scheduled" and when and when <= now:
            due_retries.append(retry)
    blockers = []
    if current.get("stopped"):
        blockers.append("operator stop generation is active")
    blockers.extend(f"configuration: {reason}" for reason in result.errors)
    blockers.extend(
        f"configuration unresolved: {reason}" for reason in result.unresolved_required
    )
    blockers.extend(_preparation_blockers(preparation))
    watcher_blocker = _watcher_startup_blocker(result, watcher_startup)
    if watcher_blocker:
        blockers.append(watcher_blocker)
    for name, cap in current.get("platform", {}).get("capabilities", {}).items():
        if (
            cap.get("availability") in {"blocked", "unavailable"}
            or cap.get("health") == "unhealthy"
        ):
            blockers.append(f"{name}: {cap.get('detail') or cap.get('health')}")
    next_action = None
    ranked = load_json(root / "state" / "priority.json", [])
    if isinstance(ranked, list):
        next_action = next(
            (r for r in ranked if r.get("priority_score", -999) > -999), None
        )
    if queue.get("next_action"):
        next_action = {"type": "review-queue", **queue["next_action"]}
    elif due_retries:
        next_action = {"type": "retry", **due_retries[0]}
    startup = load_json(root / "state" / "startup_checks.json", {})
    checks = (
        startup.get("checks", [])
        if isinstance(startup, dict) and isinstance(startup.get("checks", []), list)
        else []
    )
    lifecycle_state = derive_lifecycle_state(
        current, result, checks, watcher_startup, preparation
    )
    scoring_config = result.manifest.get("scoring", {})
    completion_mode = (
        scoring_config.get("completion_mode", "unknown")
        if isinstance(scoring_config, dict)
        else "unknown"
    )
    snapshot = {
        "schema_version": "2",
        "lifecycle_state": lifecycle_state,
        "release_version": _release_version(root),
        "generated_at": iso_now(),
        "freshness": {
            "platform_at": current.get("platform", {}).get("generated_at", "unknown"),
            "runtime_at": current.get("updated_at", "unknown"),
        },
        "stop_generation": current.get("stop_generation", 0),
        "stopped": current.get("stopped", False),
        # This compact tuple lets the public read path compare a cache with one
        # immutable canonical SQLite snapshot without rebuilding projections.
        "canonical": {
            "event_count": int(current.get("event_count", 0) or 0),
            "stop_generation": int(current.get("stop_generation", 0) or 0),
            "stopped": bool(current.get("stopped", False)),
        },
        "policy_generation": projection.get("policy", {}).get("generation", 0),
        "completion_mode": (
            completion_mode if isinstance(completion_mode, str) else "unknown"
        ),
        "active_goal": current.get("active_goal"),
        "counts": current.get("counts", {}),
        "workers": list(current.get("agents", {}).values()),
        "jobs": list(current.get("jobs", {}).values()),
        "resources": load_json(root / "state" / "compute_schedule.json", {}),
        "compute_queue": {
            "ideas": list(current.get("compute_ideas", {}).values()),
            "queued": int(current.get("counts", {}).get("compute_ideas_queued", 0)),
            "total": int(current.get("counts", {}).get("compute_ideas", 0)),
        },
        "platform": current.get("platform", {}),
        "queue": queue,
        "queue_automation_enabled": bool(
            result.manifest.get("queue", {}).get("automation_enabled", False)
        ),
        "watcher": watcher_startup or {},
        "watcher_epoch": store.get_meta(
            "watcher_epoch", str(current.get("stop_generation", 0))
        ),
        "preparation": {
            "ready": preparation.get("ready") if preparation else None,
            "missing_required": list(preparation.get("missing_required", []))
            if isinstance(preparation.get("missing_required", []), list)
            else [],
        },
        "due_retries": due_retries,
        "blockers": blockers,
        "next_autonomous_action": next_action,
    }
    atomic_write_json(root / "state" / "status_snapshot.json", snapshot)
    return snapshot


def read_snapshot(root: Path) -> dict[str, Any]:
    snapshot = load_json(
        root / "state" / "status_snapshot.json",
        {
            "generated_at": "never",
            "lifecycle_state": "uninitialized",
            "release_version": _release_version(root),
            "message": "run ./go to initialize status",
        },
    )
    if not isinstance(snapshot, dict):
        return {
            "generated_at": "never",
            "lifecycle_state": "uninitialized",
            "release_version": _release_version(root),
            "message": "run ./go to initialize status",
        }
    snapshot = _attach_cached_status_truth(snapshot)
    snapshot = _revalidate_cached_watcher(root, snapshot)
    return _revalidate_cached_control(root, snapshot)


def _status_blocker(snapshot: dict[str, Any], reason: str) -> dict[str, Any]:
    """Return a fail-closed view without repairing the persisted cache."""

    out = dict(snapshot)
    out["lifecycle_state"] = "blocked"
    blockers = list(out.get("blockers", []))
    blocker = "canonical status freshness: " + reason
    if blocker not in blockers:
        blockers.append(blocker)
    out["blockers"] = blockers
    raw_truth = out.get("status_truth")
    truth = dict(raw_truth) if isinstance(raw_truth, dict) else {}
    truth.update(
        {
            "canonical_control_state": "unknown",
            "canonical_event_count": "unknown",
            "canonical_stop_generation": "unknown",
            "canonical_stopped": "unknown",
            "activity": {
                "source": "unknown",
                "reason": "canonical state is unavailable or unsafe",
            },
        }
    )
    out["status_truth"] = truth
    return out


def _cached_canonical_tuple(snapshot: dict[str, Any]) -> dict[str, Any] | None:
    """Return a well-typed cached control tuple, if one was persisted."""

    cached = snapshot.get("canonical")
    if not isinstance(cached, dict):
        return None
    event_count = cached.get("event_count")
    stop_generation = cached.get("stop_generation")
    stopped = cached.get("stopped")
    if (
        not isinstance(event_count, int)
        or isinstance(event_count, bool)
        or event_count < 0
        or not isinstance(stop_generation, int)
        or isinstance(stop_generation, bool)
        or stop_generation < 0
        or not isinstance(stopped, bool)
    ):
        return None
    return {
        "event_count": event_count,
        "stop_generation": stop_generation,
        "stopped": stopped,
    }


def _snapshot_age_seconds(snapshot: dict[str, Any]) -> int | str:
    """Return a non-negative cached snapshot age without treating bad time as fresh."""

    generated_at = parse_iso(snapshot.get("generated_at"))
    if generated_at is None:
        return "unknown"
    return max(0, int((dt.datetime.now(UTC) - generated_at).total_seconds()))


def _attach_cached_status_truth(snapshot: dict[str, Any]) -> dict[str, Any]:
    """Label cached facts before any read-only control revalidation overlays them."""

    out = dict(snapshot)
    cached = _cached_canonical_tuple(snapshot)
    lifecycle = snapshot.get("lifecycle_state")
    raw_truth = out.get("status_truth")
    truth = dict(raw_truth) if isinstance(raw_truth, dict) else {}
    truth.update(
        {
            "cached_lifecycle": lifecycle if isinstance(lifecycle, str) else "unknown",
            "cached_event_count": cached["event_count"] if cached else "unknown",
            "cached_stop_generation": cached["stop_generation"] if cached else "unknown",
            "cached_stopped": cached["stopped"] if cached else "unknown",
            "snapshot_age_seconds": _snapshot_age_seconds(snapshot),
        }
    )
    out["status_truth"] = truth
    return out


def _overlay_canonical_status_truth(
    snapshot: dict[str, Any],
    canonical: dict[str, Any],
    activity: dict[str, Any],
) -> dict[str, Any]:
    """Attach bounded canonical control and matching-projection activity evidence."""

    out = dict(snapshot)
    raw_truth = out.get("status_truth")
    truth = dict(raw_truth) if isinstance(raw_truth, dict) else {}
    truth.update(
        {
            "canonical_control_state": "stopped"
            if canonical["stopped"]
            else "not_stopped",
            # Immutable control metadata can prove a stop, but cannot safely
            # reconstruct a ready or blocked lifecycle without a full runtime read.
            "canonical_lifecycle": "stopped" if canonical["stopped"] else "unknown",
            "canonical_event_count": canonical["event_count"],
            "canonical_stop_generation": canonical["stop_generation"],
            "canonical_stopped": canonical["stopped"],
            "activity": activity,
        }
    )
    out["status_truth"] = truth
    return out


def _reconciliation_debt_report_paths(value: object) -> tuple[str, ...] | None:
    """Keep only bounded analysis-relative report paths from current projection."""

    if not isinstance(value, list) or len(value) > _STATUS_RECONCILIATION_DEBT_MAX_PATHS:
        return None
    paths: list[str] = []
    for path in value:
        if (
            not isinstance(path, str)
            or not path
            or len(path.encode("utf-8")) > _STATUS_RECONCILIATION_DEBT_PATH_MAX_BYTES
            or "\\" in path
            or any(ord(character) < 0x20 or ord(character) == 0x7F for character in path)
        ):
            return None
        parts = path.split("/")
        if (
            len(parts) < 2
            or parts[0] != "analysis"
            or any(part in {"", ".", ".."} for part in parts)
        ):
            return None
        paths.append(path)
    if len(set(paths)) != len(paths) or paths != sorted(paths):
        return None
    return tuple(paths)


def _read_matching_current_activity(
    root: Path, canonical: dict[str, Any]
) -> dict[str, Any]:
    """Read only a bounded current projection that matches immutable control facts."""

    state = root / "state"
    path = state / "current.json"
    descriptor: int | None = None
    try:
        state_info = state.lstat()
        before = path.lstat()
        if (
            not stat.S_ISDIR(state_info.st_mode)
            or stat.S_ISLNK(state_info.st_mode)
            or stat.S_IMODE(state_info.st_mode) & 0o077
            or not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) & 0o077
            or before.st_size < 0
            or before.st_size > _STATUS_CURRENT_MAX_BYTES
        ):
            raise OSError("current projection is unsafe")
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        opened = os.fstat(descriptor)
        if (
            opened.st_dev != before.st_dev
            or opened.st_ino != before.st_ino
            or not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or opened.st_size != before.st_size
        ):
            raise OSError("current projection changed while opening")
        remaining = before.st_size + 1
        chunks: list[bytes] = []
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(descriptor)
        if (
            after.st_dev != before.st_dev
            or after.st_ino != before.st_ino
            or after.st_size != before.st_size
            or sum(len(chunk) for chunk in chunks) != before.st_size
        ):
            raise OSError("current projection changed while reading")
        raw = json.loads(b"".join(chunks).decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return {
            "source": "unknown",
            "reason": "matching current projection is unavailable",
        }
    finally:
        if descriptor is not None:
            os.close(descriptor)
    if not isinstance(raw, dict):
        return {
            "source": "unknown",
            "reason": "matching current projection is malformed",
        }
    event_count = raw.get("event_count")
    stop_generation = raw.get("stop_generation")
    stopped = raw.get("stopped")
    if (
        not isinstance(event_count, int)
        or isinstance(event_count, bool)
        or not isinstance(stop_generation, int)
        or isinstance(stop_generation, bool)
        or not isinstance(stopped, bool)
        or {
            "event_count": event_count,
            "stop_generation": stop_generation,
            "stopped": stopped,
        }
        != canonical
    ):
        return {
            "source": "unknown",
            "reason": "current projection does not match immutable canonical metadata",
        }
    agents = raw.get("agents")
    jobs = raw.get("jobs")
    if not isinstance(agents, dict) or not isinstance(jobs, dict):
        return {
            "source": "unknown",
            "reason": "matching current projection has malformed work records",
        }

    def count_status(rows: dict[str, Any], statuses: frozenset[str] | set[str]) -> int:
        return sum(
            1
            for row in rows.values()
            if isinstance(row, dict) and row.get("status") in statuses
        )

    activity: dict[str, Any] = {
        "source": "matched_current_projection",
        "active_agents": count_status(agents, _ACTIVE_AGENT_STATUSES),
        "active_jobs": count_status(jobs, _ACTIVE_JOB_STATUSES),
        "unmanaged_agents": count_status(agents, {"unmanaged"}),
        "unmanaged_jobs": count_status(jobs, {"unmanaged"}),
        "unacknowledged_agents": count_status(agents, {"unacknowledged"}),
        "unacknowledged_jobs": count_status(jobs, {"unacknowledged"}),
    }
    harvested_reports = raw.get("harvested_reports")
    if isinstance(harvested_reports, dict):
        harvested_paths = set(harvested_reports)
        activity["harvest_debt"] = sum(
            1
            for row in agents.values()
            if isinstance(row, dict)
            and row.get("status") == "closed"
            and isinstance(row.get("report_path"), str)
            and bool(row["report_path"])
            and row["report_path"] not in harvested_paths
        )
    else:
        activity["harvest_debt"] = "unknown"

    continuation_audit = raw.get("continuation_audit")
    if isinstance(continuation_audit, dict):
        unharvested_active = continuation_audit.get("unharvested_active")
        unconsumed_handoffs = continuation_audit.get("unconsumed_handoffs")
        if (
            isinstance(unharvested_active, int)
            and not isinstance(unharvested_active, bool)
            and unharvested_active >= 0
            and isinstance(unconsumed_handoffs, int)
            and not isinstance(unconsumed_handoffs, bool)
            and unconsumed_handoffs >= 0
        ):
            activity.update(
                {
                    "unharvested_active_handoffs": unharvested_active,
                    "unconsumed_structured_handoffs": unconsumed_handoffs,
                }
            )
        else:
            activity["unharvested_active_handoffs"] = "unknown"
            activity["unconsumed_structured_handoffs"] = "unknown"
        reconciliation_debts = continuation_audit.get("reconciliation_debts")
        reconciliation_paths = _reconciliation_debt_report_paths(
            continuation_audit.get("reconciliation_debt_report_paths")
        )
        if (
            isinstance(reconciliation_debts, int)
            and not isinstance(reconciliation_debts, bool)
            and reconciliation_debts >= 0
            and reconciliation_paths is not None
            and reconciliation_debts >= len(reconciliation_paths)
        ):
            activity["reconciliation_debts"] = reconciliation_debts
            activity["reconciliation_debt_report_paths"] = reconciliation_paths
        else:
            activity["reconciliation_debts"] = "unknown"
            activity["reconciliation_debt_report_paths"] = "unknown"
    else:
        activity["unharvested_active_handoffs"] = "unknown"
        activity["unconsumed_structured_handoffs"] = "unknown"
        activity["reconciliation_debts"] = "unknown"
        activity["reconciliation_debt_report_paths"] = "unknown"

    proposals = raw.get("proposals")
    executions = raw.get("executions")
    platform = raw.get("platform")
    if (
        isinstance(proposals, dict)
        and isinstance(executions, dict)
        and isinstance(platform, dict)
    ):
        capabilities = platform.get("capabilities")
        scoring = capabilities.get("scoring") if isinstance(capabilities, dict) else None
        if isinstance(scoring, dict):
            executor_available = (
                scoring.get("availability") == "available"
                and scoring.get("health") in {"healthy", "degraded"}
            )
            terminal_proposal_ids = {
                str(execution.get("proposal_id"))
                for execution in executions.values()
                if isinstance(execution, dict)
                and execution.get("status")
                in {"started", "completed", "rejected", "indeterminate"}
                and isinstance(execution.get("proposal_id"), str)
                and execution.get("proposal_id")
            }
            approved_backlog = sum(
                1
                for proposal_id, proposal in proposals.items()
                if isinstance(proposal, dict)
                and proposal.get("status") == "approved"
                and proposal.get("action_kind") not in {None, "", "no_submit_evidence"}
                and str(proposal_id) not in terminal_proposal_ids
            )
            activity.update(
                {
                    "scoring_executor_state": (
                        "available" if executor_available else "unavailable_or_unhealthy"
                    ),
                    "review_approved_unterminal_backlog": approved_backlog,
                    "eligible_scoring_backlog": (
                        approved_backlog if executor_available and not stopped else 0
                    ),
                    "blocked_executions_without_scorer_verdict": sum(
                        1
                        for execution in executions.values()
                        if isinstance(execution, dict)
                        and execution.get("status") == "blocked"
                    ),
                }
            )
        else:
            activity["scoring_executor_state"] = "unknown"
    else:
        activity["scoring_executor_state"] = "unknown"
    return activity


def _completion_scoring_state(snapshot: dict[str, Any], activity: dict[str, Any]) -> str:
    """Describe whether the selected completion contract requires scorer truth."""

    completion_mode = snapshot.get("completion_mode")
    if completion_mode == "evidence_only":
        return "not_required_evidence_only"
    if completion_mode != "scorer_truth":
        return "unknown"
    executor_state = activity.get("scoring_executor_state")
    if executor_state == "unavailable_or_unhealthy":
        return "unavailable"
    if executor_state == "available":
        return "available"
    return "unknown"


def _is_uninitialized_snapshot(snapshot: dict[str, Any]) -> bool:
    return (
        snapshot.get("lifecycle_state") == "uninitialized"
        and snapshot.get("generated_at") == "never"
    )


def _read_canonical_status_metadata(root: Path) -> dict[str, Any] | None:
    """Read compact lifecycle truth from immutable SQLite without side effects.

    A WAL/SHM sidecar means an immutable connection could read an obsolete main
    database.  Status deliberately refuses that ambiguity rather than opening a
    writer or claiming that a cached ready state remains current.
    """

    state = root / "state"
    path = state / "events.sqlite3"
    try:
        state_info = state.lstat()
        info = path.lstat()
        if (
            not stat.S_ISDIR(state_info.st_mode)
            or stat.S_ISLNK(state_info.st_mode)
            or not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or path.with_name(path.name + "-wal").exists()
            or path.with_name(path.name + "-shm").exists()
        ):
            return None
        connection = sqlite3.connect(
            f"{path.resolve().as_uri()}?mode=ro&immutable=1", uri=True
        )
    except (OSError, ValueError, sqlite3.Error):
        return None
    try:
        connection.execute("PRAGMA query_only=ON")
        connection.execute("BEGIN")
        rows = connection.execute(
            "SELECT key,value FROM meta WHERE key='stop_generation'"
        ).fetchall()
        event_count = int(connection.execute("SELECT COUNT(*) FROM events").fetchone()[0])
        control = connection.execute(
            "SELECT seq,event_id,event_type,created_at,generation,actor,"
            "length(payload_json) "
            "FROM events WHERE event_type IN ('control.stop','control.resume') "
            "ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        values = {str(key): str(value) for key, value in rows}
        try:
            stop_generation = int(values["stop_generation"])
        except (KeyError, TypeError, ValueError):
            return None
        if stop_generation < 0 or event_count < 0:
            return None
        stopped = False
        if control is not None:
            event = {
                "seq": int(control[0]),
                "event_id": str(control[1]),
                "event_type": str(control[2]),
                "created_at": str(control[3]),
                "generation": int(control[4]),
                "actor": str(control[5]),
            }
            if event["event_type"] == "control.stop":
                stopped = True
            else:
                payload_size = control[6]
                if (
                    not isinstance(payload_size, int)
                    or payload_size < 0
                    or payload_size > _STATUS_CONTROL_PAYLOAD_MAX_BYTES
                ):
                    return None
                payload_row = connection.execute(
                    "SELECT payload_json FROM events WHERE seq=?", (event["seq"],)
                ).fetchone()
                payload = json.loads(str(payload_row[0])) if payload_row else None
                event["payload"] = payload
                stopped = not control_resume_is_current(
                    event, stop_generation=stop_generation
                )
        return {
            "event_count": event_count,
            "stop_generation": stop_generation,
            "stopped": stopped,
        }
    except (TypeError, ValueError, json.JSONDecodeError, sqlite3.Error):
        return None
    finally:
        try:
            connection.rollback()
        except sqlite3.Error:
            pass
        connection.close()


def _revalidate_cached_control(root: Path, snapshot: dict[str, Any]) -> dict[str, Any]:
    """Overlay provable stop truth or block on any unreadable/stale control cache."""

    canonical = _read_canonical_status_metadata(root)
    if canonical is None:
        if _is_uninitialized_snapshot(snapshot) and not (root / "state" / "events.sqlite3").exists():
            return snapshot
        return _status_blocker(snapshot, "canonical state is unavailable or unsafe")
    activity = _read_matching_current_activity(root, canonical)
    final_canonical = _read_canonical_status_metadata(root)
    if final_canonical is None:
        return _status_blocker(snapshot, "canonical state is unavailable or unsafe")
    if final_canonical != canonical:
        canonical = final_canonical
        activity = {
            "source": "unknown",
            "reason": "canonical metadata changed during status read",
        }
    cached = _cached_canonical_tuple(snapshot)
    if cached is None:
        if canonical["stopped"]:
            out = dict(snapshot)
            out.update(
                {
                    "lifecycle_state": "stopped",
                    "stop_generation": canonical["stop_generation"],
                    "stopped": True,
                    "canonical": canonical,
                }
            )
            blockers = list(out.get("blockers", []))
            blocker = "canonical status freshness: cached snapshot predates canonical stop"
            if blocker not in blockers:
                blockers.append(blocker)
            out["blockers"] = blockers
            return _overlay_canonical_status_truth(out, canonical, activity)
        return _overlay_canonical_status_truth(
            _status_blocker(snapshot, "cached snapshot has no canonical tuple"),
            canonical,
            activity,
        )
    if cached == canonical:
        return _overlay_canonical_status_truth(snapshot, canonical, activity)
    if canonical["stopped"]:
        out = dict(snapshot)
        out.update(
            {
                "lifecycle_state": "stopped",
                "stop_generation": canonical["stop_generation"],
                "stopped": True,
                "canonical": canonical,
            }
        )
        blockers = list(out.get("blockers", []))
        blocker = "canonical status freshness: cached snapshot predates canonical stop"
        if blocker not in blockers:
            blockers.append(blocker)
        out["blockers"] = blockers
        return _overlay_canonical_status_truth(out, canonical, activity)
    out = _status_blocker(snapshot, "cached lifecycle diverges from canonical state")
    out.update(
        {
            "stop_generation": canonical["stop_generation"],
            "stopped": False,
            "canonical": canonical,
        }
    )
    return _overlay_canonical_status_truth(out, canonical, activity)


def _revalidate_cached_watcher(root: Path, snapshot: dict[str, Any]) -> dict[str, Any]:
    """Fail closed on a stale cached automation watcher without writing state.

    ``go status`` must not instantiate an EventStore, because that can create
    state or refresh projections.  The cached job epoch must agree with the
    current canonical metadata, while the process helper validates PID, start
    time, process group, workspace, and owner token.
    """

    watcher = snapshot.get("watcher")
    automation_selected = bool(snapshot.get("queue_automation_enabled", False))
    if not automation_selected and isinstance(watcher, dict):
        automation_selected = watcher.get("running") is True
    if not automation_selected or not isinstance(watcher, dict):
        return snapshot
    if watcher.get("running") is not True:
        return snapshot
    job = watcher.get("job")
    try:
        cached_epoch = int(snapshot.get("watcher_epoch"))
        job_epoch = int(job.get("watcher_epoch")) if isinstance(job, dict) else -1
    except (TypeError, ValueError):
        cached_epoch = -1
        job_epoch = -2
    canonical_epoch = _read_current_watcher_epoch(root)
    valid = False
    if (
        canonical_epoch is not None
        and cached_epoch >= 0
        and cached_epoch == job_epoch == canonical_epoch
        and isinstance(job, dict)
    ):
        try:
            valid = process_identity_matches(root, job)
        except (OSError, ValueError):
            valid = False
    if valid:
        return snapshot
    out = dict(snapshot)
    out["lifecycle_state"] = "blocked"
    watcher_out = dict(watcher)
    watcher_out.update(
        {
            "running": False,
            "reason": "cached watcher is stale or dead",
            "revalidated": False,
        }
    )
    out["watcher"] = watcher_out
    blockers = list(out.get("blockers", []))
    blocker = "queue watcher: cached watcher is stale or dead"
    if blocker not in blockers:
        blockers.append(blocker)
    out["blockers"] = blockers
    return out


def _read_current_watcher_epoch(root: Path) -> int | None:
    """Read the durable watcher lease epoch without opening a writable store.

    ``mode=ro`` plus ``immutable=1`` and ``query_only`` ensure this check
    cannot initialize a WAL sidecar, publish projections, or advance metadata.
    A live WAL cannot be read safely under that contract, so it is a
    fail-closed condition rather than a reason to turn status into a writer.
    """

    path = root / "state" / "events.sqlite3"
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode):
            return None
        if path.with_name(path.name + "-wal").exists():
            return None
        connection = sqlite3.connect(
            f"{path.resolve().as_uri()}?mode=ro&immutable=1", uri=True
        )
    except (OSError, ValueError, sqlite3.Error):
        return None
    try:
        connection.execute("PRAGMA query_only=ON")
        rows = connection.execute(
            "SELECT key,value FROM meta WHERE key IN ('watcher_epoch','stop_generation')"
        ).fetchall()
    except sqlite3.Error:
        return None
    finally:
        connection.close()
    values = {str(key): str(value) for key, value in rows}
    raw = values.get("watcher_epoch", values.get("stop_generation", ""))
    try:
        epoch = int(raw)
    except ValueError:
        return None
    return epoch if epoch >= 0 else None


def _render_reconciliation_debt(activity: dict[str, Any]) -> str:
    """Render bounded report paths without opening any report file."""

    debts = activity.get("reconciliation_debts", "unknown")
    paths = activity.get("reconciliation_debt_report_paths", "unknown")
    if not isinstance(paths, tuple):
        return (
            "reconciliation_debt="
            f"attempts={debts} report_count=unknown report_paths=unknown"
        )
    visible = paths[:_STATUS_RECONCILIATION_DEBT_RENDERED_PATHS]
    rendered_paths = ",".join(visible) if visible else "none"
    return (
        "reconciliation_debt="
        f"attempts={debts} report_count={len(paths)} "
        f"report_paths={rendered_paths} "
        f"paths_truncated={str(len(paths) > len(visible)).lower()}"
    )


def render_status(snapshot: dict[str, Any]) -> str:
    counts = snapshot.get("counts", {})
    counts = counts if isinstance(counts, dict) else {}
    queue = snapshot.get("queue", {})
    queue = queue if isinstance(queue, dict) else {}
    truth = snapshot.get("status_truth", {})
    truth = truth if isinstance(truth, dict) else {}
    activity = truth.get("activity", {})
    activity = activity if isinstance(activity, dict) else {}
    completion_mode = snapshot.get("completion_mode", "unknown")
    completion_mode = completion_mode if isinstance(completion_mode, str) else "unknown"
    lines = [
        f"state={snapshot.get('lifecycle_state', 'unknown')}",
        f"version={snapshot.get('release_version', 'unknown')}",
        f"status_at={snapshot.get('generated_at', 'unknown')}",
        f"snapshot_age_seconds={truth.get('snapshot_age_seconds', _snapshot_age_seconds(snapshot))}",
        "cached_status="
        f"lifecycle={truth.get('cached_lifecycle', snapshot.get('lifecycle_state', 'unknown'))} "
        f"event_count={truth.get('cached_event_count', 'unknown')} "
        f"stop_generation={truth.get('cached_stop_generation', 'unknown')} "
        f"stopped={truth.get('cached_stopped', 'unknown')}",
        "canonical_status="
        f"lifecycle={truth.get('canonical_lifecycle', 'unknown')} "
        f"control_state={truth.get('canonical_control_state', 'unknown')} "
        f"event_count={truth.get('canonical_event_count', 'unknown')} "
        f"stop_generation={truth.get('canonical_stop_generation', 'unknown')} "
        f"stopped={truth.get('canonical_stopped', 'unknown')}",
        f"completion_mode={completion_mode} scorer_truth_capability={_completion_scoring_state(snapshot, activity)}",
        f"stop_generation={snapshot.get('stop_generation', 0)} stopped={str(snapshot.get('stopped', False)).lower()} policy_generation={snapshot.get('policy_generation', 0)}",
        "cached_work="
        f"visible={counts.get('visible', 0)} solved={counts.get('solved', 0)} "
        f"unsolved={counts.get('unsolved', 0)} "
        f"active_agents={counts.get('active_agents', 0)} "
        f"active_jobs={counts.get('active_jobs', 0)}",
        "cached_scoring_queue="
        f"depth={queue.get('depth', 0)} eligible={queue.get('eligible', 0)} "
        f"oldest_eligible_age_seconds={queue.get('oldest_eligible_age_seconds', 0)}",
        f"compute_ideas={counts.get('compute_ideas', 0)} compute_queued={counts.get('compute_ideas_queued', 0)}",
    ]
    if activity.get("source") == "matched_current_projection":
        lines.append(
            "activity_evidence=matched_current_projection "
            f"active_agents={activity.get('active_agents', 0)} "
            f"active_jobs={activity.get('active_jobs', 0)} "
            f"unmanaged_agents={activity.get('unmanaged_agents', 0)} "
            f"unmanaged_jobs={activity.get('unmanaged_jobs', 0)} "
            f"unacknowledged_agents={activity.get('unacknowledged_agents', 0)} "
            f"unacknowledged_jobs={activity.get('unacknowledged_jobs', 0)} "
            f"harvest_debt={activity.get('harvest_debt', 'unknown')} "
            f"scoring_executor={activity.get('scoring_executor_state', 'unknown')} "
            f"review_approved_unterminal_backlog={activity.get('review_approved_unterminal_backlog', 'unknown')} "
            f"eligible_scoring_backlog={activity.get('eligible_scoring_backlog', 'unknown')} "
            f"blocked_executions_without_scorer_verdict={activity.get('blocked_executions_without_scorer_verdict', 'unknown')}"
        )
        lines.append(
            "handoff_debt="
            f"closed_reports_without_harvest={activity.get('harvest_debt', 'unknown')} "
            f"unharvested_active={activity.get('unharvested_active_handoffs', 'unknown')} "
            f"unconsumed_structured={activity.get('unconsumed_structured_handoffs', 'unknown')}"
        )
        lines.append(_render_reconciliation_debt(activity))
    else:
        lines.append(
            "activity_evidence=unknown "
            f"reason={activity.get('reason', 'matching current projection is unavailable')}"
        )
        lines.append(
            "handoff_debt="
            "closed_reports_without_harvest=unknown "
            "unharvested_active=unknown unconsumed_structured=unknown"
        )
        lines.append(
            "reconciliation_debt="
            "attempts=unknown report_count=unknown report_paths=unknown"
        )
    lines.append("workspace_processes=unknown status_does_not_scan_processes=true")
    if snapshot.get("binding_integrity"):
        lines.append("binding_integrity=" + str(snapshot["binding_integrity"]))
    if snapshot.get("blockers"):
        lines.append("blockers=" + " | ".join(snapshot["blockers"]))
    if snapshot.get("message"):
        lines.append("message=" + str(snapshot["message"]))
    next_action = snapshot.get("next_autonomous_action")
    lines.append("next=" + (str(next_action) if next_action else "none"))
    return "\n".join(lines)
