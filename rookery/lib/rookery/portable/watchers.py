from __future__ import annotations

import os
import signal
import stat
import subprocess
import time
import uuid
from pathlib import Path
from typing import Any

from .control import process_identity_matches
from .environment import EnvClass, EnvKey, EnvSource, build_child_environment, purpose_policy
from .store import EventStore
from .util import ensure_private_dir, ensure_private_file, file_lock, iso_now

PRIVATE_DIRECTORY_MODE = 0o700
PRIVATE_FILE_MODE = 0o600


def _ensure_private_directory(root: Path, directory: Path) -> None:
    """Create and validate every private directory component below ``root``."""

    try:
        relative = directory.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"private directory must be below workspace root: {directory}") from exc
    if any(part in {".", ".."} for part in relative.parts):
        raise ValueError(f"private directory must be lexically below workspace root: {directory}")
    current = root
    for component in relative.parts:
        current = current / component
        ensure_private_dir(current)


def _open_private_append(root: Path, path: Path):
    """Open a watcher log privately before exposing its descriptor to a child."""

    _ensure_private_directory(root, path.parent)
    ensure_private_file(path)
    descriptor = os.open(
        path,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_APPEND
        | os.O_NONBLOCK
        | getattr(os, "O_NOFOLLOW", 0),
        PRIVATE_FILE_MODE,
    )
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise OSError(f"watcher log path is not a regular file: {path}")
        os.fchmod(descriptor, PRIVATE_FILE_MODE)
        return os.fdopen(descriptor, "ab")
    except Exception:
        os.close(descriptor)
        raise


def _proc_starttime(pid: int) -> str:
    try:
        return (Path("/proc") / str(pid) / "stat").read_text().split()[21]
    except Exception:
        return ""


def _record_start_failure(
    store: EventStore, payload: dict[str, Any], reason: str
) -> None:
    """Best-effort terminal truth without hiding the original launch failure."""

    try:
        store.append(
            "job.failed",
            {**payload, "reason": reason},
            actor="go",
        )
        store.rebuild()
    except Exception:
        # A failed checkpoint can mean the event store itself is unavailable.
        # Preserve the original error and never invent a durable terminal state.
        return


def _terminate_verified_watcher(
    root: Path, payload: dict[str, Any], proc: subprocess.Popen[bytes]
) -> bool:
    """Stop only the exact watcher identity that was verified just before use."""

    if not process_identity_matches(root, payload):
        return False
    try:
        os.killpg(int(payload["pgid"]), signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        return proc.poll() is not None
    try:
        proc.wait(timeout=1)
        return True
    except subprocess.TimeoutExpired:
        # Re-check before escalation: a post-signal identity change must never
        # authorize a second signal to a reused or otherwise unverified PID.
        if not process_identity_matches(root, payload):
            return False
    try:
        os.killpg(int(payload["pgid"]), signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        return proc.poll() is not None
    try:
        proc.wait(timeout=1)
        return True
    except subprocess.TimeoutExpired:
        return False


def current_watcher_epoch(
    store: EventStore, *, snapshot: dict[str, Any] | None = None
) -> int:
    """Return the durable epoch to which a newly spawned watcher must bind."""

    snapshot = store.read_snapshot() if snapshot is None else snapshot
    meta = snapshot.get("meta", {})
    raw_epoch = str(meta.get("watcher_epoch", "")) if isinstance(meta, dict) else ""
    if not raw_epoch:
        # Existing workspaces predate the dedicated epoch metadata.  Their
        # durable stop generation is the only safe epoch until the next stop
        # transaction creates the metadata.
        raw_epoch = (
            str(meta.get("stop_generation", "0"))
            if isinstance(meta, dict)
            else "0"
        )
    try:
        epoch = int(raw_epoch)
    except ValueError as exc:
        raise RuntimeError("watcher epoch metadata is invalid") from exc
    if epoch < 0:
        raise RuntimeError("watcher epoch metadata is invalid")
    return epoch


def watcher_lease_is_current(
    store: EventStore,
    owner_token: str,
    watcher_epoch: int,
    *,
    snapshot: dict[str, Any] | None = None,
) -> bool:
    """Return whether a watch-loop still owns the current durable lease.

    This is intentionally read-only so the queue watch loop can call it before
    each tick without changing canonical state or refreshing projections.
    """

    if not owner_token or isinstance(watcher_epoch, bool):
        return False
    try:
        epoch = int(watcher_epoch)
    except (TypeError, ValueError):
        return False
    snapshot = store.read_snapshot() if snapshot is None else snapshot
    if epoch < 0 or current_watcher_epoch(store, snapshot=snapshot) != epoch:
        return False
    events = snapshot.get("events", [])
    if not isinstance(events, list):
        return False
    for event in reversed(events):
        if not event["event_type"].startswith("job."):
            continue
        payload = event["payload"]
        if (
            payload.get("kind") == "queue-watcher"
            and payload.get("owner_token") == owner_token
            and payload.get("watcher_epoch") == epoch
        ):
            return event["event_type"] in {"job.starting", "job.running"}
    return False


def queue_watcher_status(store: EventStore, root: Path) -> dict[str, Any]:
    jobs = store.rebuild()["current"].get("jobs", {})
    rows = [row for row in jobs.values() if row.get("kind") == "queue-watcher"]
    if not rows:
        return {"running": False, "reason": "not registered"}

    # Process identity checks bind PID, start time, process group, and token in
    # one observation.  Perform that check immediately before deciding whether
    # a row is reusable, residual, or dead; stale event status alone cannot
    # safely authorize a replacement watcher.
    live_rows = [row for row in rows if process_identity_matches(root, row)]
    if not live_rows:
        return {"running": False, "reason": "no live owned watcher"}
    residual_rows = [row for row in live_rows if row.get("status") != "running"]
    if residual_rows:
        row = sorted(
            residual_rows, key=lambda item: str(item.get("event_at") or "")
        )[-1]
        return {
            "running": False,
            "reason": "blocked by residual watcher",
            "job": row,
            "residual_jobs": residual_rows,
        }
    if len(live_rows) != 1:
        return {
            "running": False,
            "reason": "blocked by multiple live watchers",
            "jobs": live_rows,
        }
    row = live_rows[0]
    return {
        "running": True,
        "job": row,
    }


def _ensure_queue_watcher_locked(
    store: EventStore, root: Path, manifest: dict[str, Any]
) -> dict[str, Any]:
    queue = manifest.get("queue", {})
    if not queue.get("automation_enabled", False):
        return {"running": False, "reason": "automation disabled"}
    if store.rebuild()["current"].get("stopped"):
        return {"running": False, "reason": "workspace is stopped"}
    status = queue_watcher_status(store, root)
    if status.get("running"):
        return {"running": True, "reused": True, "job": status["job"]}
    if status.get("reason", "").startswith("blocked by"):
        return status
    interval = max(1, int(queue.get("watch_interval_seconds", 15) or 15))
    token = "queuewatch_" + uuid.uuid4().hex
    job_id = "job_" + uuid.uuid4().hex
    watcher_epoch = current_watcher_epoch(store)
    log_dir = root / "logs" / "queue-watch"
    _ensure_private_directory(root, log_dir)
    command = [
        str(root / "bin" / "rookery"),
        "queue",
        "watch",
        "--auto-execute",
        "--interval",
        str(interval),
        "--owner-token",
        token,
        "--watcher-epoch",
        str(watcher_epoch),
        "--quiet",
        "--heartbeat-seconds",
        "300",
    ]
    watcher_environment = build_child_environment(
        root,
        policy=purpose_policy(
            "queue-watcher",
            (
                EnvKey(
                    "ROOKERY_OWNER_TOKEN",
                    EnvClass.OWNER_TOKEN,
                    sources=(EnvSource.INTERNAL,),
                ),
            ),
        ),
        internal={"ROOKERY_OWNER_TOKEN": token},
    )
    lease_payload = {
        "job_id": job_id,
        "kind": "queue-watcher",
        "owner": "go",
        "owner_token": token,
        "watcher_epoch": watcher_epoch,
        "command": command,
        "started_at": iso_now(),
    }
    # The child checks its lease before its first tick.  Publish that lease
    # before Popen so a fast child cannot self-retire in the startup window.
    store.append("job.starting", lease_payload, actor="go")
    try:
        with (
            _open_private_append(root, log_dir / "stdout.log") as stdout,
            _open_private_append(root, log_dir / "stderr.log") as stderr,
        ):
            proc = subprocess.Popen(
                command,
                cwd=root,
                stdout=stdout,
                stderr=stderr,
                start_new_session=True,
                env=watcher_environment.values,
            )
    except Exception as exc:
        store.append(
            "job.failed",
            {**lease_payload, "reason": f"queue watcher start failed: {exc}"},
            actor="go",
        )
        store.rebuild()
        raise
    pid = proc.pid
    pgid = os.getpgid(proc.pid)
    starttime = _proc_starttime(proc.pid)
    # This is an intentionally detached daemon. The event store owns its identity;
    # the short-lived ./go process must not retain a Popen lifecycle handle.
    payload = {
        **lease_payload,
        "pid": pid,
        "pgid": pgid,
        "process_starttime": starttime,
        "cleanup_command": f"kill -- -{pgid}",
    }
    deadline = time.monotonic() + 2.0
    consecutive_identity_matches = 0
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            _record_start_failure(
                store,
                lease_payload,
                "queue watcher exited before identity checkpoint "
                f"with code {proc.returncode}",
            )
            raise RuntimeError(
                "queue watcher exited before identity checkpoint "
                f"with code {proc.returncode}"
            )
        if process_identity_matches(root, payload):
            consecutive_identity_matches += 1
            if consecutive_identity_matches >= 3:
                break
        else:
            # The launcher execs through two shell wrappers before Python. A
            # single early match can observe a transient /proc identity.
            consecutive_identity_matches = 0
        time.sleep(0.02)
    else:
        # The Popen-to-checkpoint interval cannot be made durable without first
        # proving PID, process-group, start-time, root, and token ownership.
        # If that proof never stabilizes, revoke the lease but do not signal an
        # unverified PID; the watcher observes the failed lease before work.
        _record_start_failure(
            store,
            lease_payload,
            "queue watcher ownership was not observable before identity checkpoint",
        )
        raise RuntimeError(
            "queue watcher ownership was not observable before identity checkpoint"
        )
    if not process_identity_matches(root, payload):
        _record_start_failure(
            store,
            lease_payload,
            "queue watcher identity changed before identity checkpoint",
        )
        raise RuntimeError("queue watcher identity changed before identity checkpoint")
    try:
        # This closes the launcher-crash window after Popen. A stop that runs
        # after this append can use the same exact identity gate as a running
        # watcher, while a launcher crash still leaves a durable, signalable row.
        store.append("job.starting", payload, actor="go")
    except Exception:
        terminated = _terminate_verified_watcher(root, payload, proc)
        _record_start_failure(
            store,
            lease_payload,
            "queue watcher identity checkpoint failed; exact child termination "
            + ("confirmed" if terminated else "not confirmed"),
        )
        raise
    proc.returncode = 0
    store.append("job.running", payload, actor="go")
    store.rebuild()
    return {"running": True, "reused": False, "job": payload}


def ensure_queue_watcher(
    store: EventStore, root: Path, manifest: dict[str, Any]
) -> dict[str, Any]:
    """Start or reuse the sole owned watcher under a workspace lock."""

    with file_lock(root / "state" / "mutation.lock"):
        return _ensure_queue_watcher_locked(store, root, manifest)
