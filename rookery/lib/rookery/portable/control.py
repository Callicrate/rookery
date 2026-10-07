from __future__ import annotations

import hashlib
import json
import os
import re
import signal
import stat
import time
from pathlib import Path
from typing import Any

from .store import EventStore
from .util import (
    atomic_write_text,
    file_lock,
    iso_now,
)


_JOB_ID = re.compile(r"[A-Za-z0-9_.-]{1,128}\Z")
_DIRECTORY_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)
_METADATA_FLAGS = (
    os.O_RDWR
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_NONBLOCK", 0)
)
_MAX_JOB_METADATA_BYTES = 1024 * 1024


def _update_job_metadata(
    root: Path,
    job_id: str,
    *,
    status: str,
    reason: str,
    finished_at: str,
    resource_summary: dict[str, Any] | None = None,
) -> None:
    """Best-effort private metadata update anchored at the workspace root.

    Emergency stop must retain canonical revocation even when runtime paths are
    corrupt.  Metadata is therefore optional and is touched only when every
    component can be descriptor-walked below the canonical root without links.
    """

    if not isinstance(job_id, str) or not _JOB_ID.fullmatch(job_id):
        return
    if not getattr(os, "O_NOFOLLOW", 0) or not getattr(os, "O_DIRECTORY", 0):
        return
    descriptors: list[int] = []
    metadata_fd: int | None = None
    try:
        canonical_root = root.resolve(strict=True)
        root_info = canonical_root.lstat()
        if not stat.S_ISDIR(root_info.st_mode):
            return
        descriptors.append(os.open(canonical_root, _DIRECTORY_FLAGS))
        for component in ("logs", "jobs", job_id):
            descriptor = os.open(component, _DIRECTORY_FLAGS, dir_fd=descriptors[-1])
            info = os.fstat(descriptor)
            if not stat.S_ISDIR(info.st_mode):
                os.close(descriptor)
                return
            descriptors.append(descriptor)
        metadata_fd = os.open("meta.json", _METADATA_FLAGS, dir_fd=descriptors[-1])
        metadata_info = os.fstat(metadata_fd)
        if (
            not stat.S_ISREG(metadata_info.st_mode)
            or metadata_info.st_nlink != 1
            or metadata_info.st_size > _MAX_JOB_METADATA_BYTES
            or metadata_info.st_mode & 0o077
        ):
            return
        chunks: list[bytes] = []
        remaining = _MAX_JOB_METADATA_BYTES + 1
        while remaining:
            chunk = os.read(metadata_fd, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        if remaining == 0:
            return
        metadata = json.loads(b"".join(chunks).decode("utf-8"))
        if not isinstance(metadata, dict):
            return
        encoded = (
            json.dumps(
                {
                    **metadata,
                    "job_id": job_id,
                    "status": status,
                    "reason": reason,
                    "finished_at": finished_at,
                    "resource_summary": resource_summary or {},
                },
                indent=2,
                sort_keys=True,
                ensure_ascii=False,
            )
            + "\n"
        ).encode("utf-8")
        if len(encoded) > _MAX_JOB_METADATA_BYTES:
            return
        os.lseek(metadata_fd, 0, os.SEEK_SET)
        os.ftruncate(metadata_fd, 0)
        written = 0
        while written < len(encoded):
            written += os.write(metadata_fd, encoded[written:])
        os.fsync(metadata_fd)
    except (OSError, UnicodeDecodeError, ValueError, json.JSONDecodeError):
        return
    finally:
        if metadata_fd is not None:
            os.close(metadata_fd)
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def process_resource_snapshot(pid: int) -> dict[str, Any]:
    """Return one bounded Linux process resource snapshot when available."""

    if pid <= 1:
        return {}
    proc = Path("/proc") / str(pid)
    try:
        stat_fields = (proc / "stat").read_text().split()
        status_lines = (proc / "status").read_text(errors="replace").splitlines()
        ticks = int(os.sysconf("SC_CLK_TCK"))
        page_size = int(os.sysconf("SC_PAGE_SIZE"))
        user_ticks = int(stat_fields[13])
        system_ticks = int(stat_fields[14])
        resident_pages = int(stat_fields[23])
        high_water_kib = 0
        for line in status_lines:
            if line.startswith("VmHWM:"):
                parts = line.split()
                high_water_kib = int(parts[1]) if len(parts) >= 2 else 0
                break
        return {
            "cpu_seconds": round((user_ticks + system_ticks) / ticks, 6),
            "rss_bytes": resident_pages * page_size,
            "peak_rss_bytes": high_water_kib * 1024,
            "captured_at": iso_now(),
        }
    except (OSError, IndexError, TypeError, ValueError):
        return {}


def mutation_guard(store: EventStore, observed_generation: int) -> None:
    current = store.current_stop_generation()
    if int(observed_generation) != current:
        raise RuntimeError(
            f"stale stop generation: plan={observed_generation} current={current}"
        )
    projection = store.rebuild()
    if projection.get("current", {}).get("stopped"):
        raise RuntimeError("workspace is stopped; explicit resume is required")


def resume(store: EventStore, *, reason: str, actor: str = "operator") -> int:
    if actor != "operator":
        raise RuntimeError("control resume requires the attested operator actor")
    if not isinstance(reason, str) or not reason.strip():
        raise ValueError("control resume requires a non-empty reason")
    with file_lock(store.root / "state" / "mutation.lock"):
        def tx(con):
            row = con.execute(
                "SELECT value FROM meta WHERE key='stop_generation'"
            ).fetchone()
            generation = int(row[0]) if row else 0
            store.insert_in_transaction(
                con,
                "control.resume",
                {
                    "reason": reason,
                    "generation": generation,
                    "resumed_at": iso_now(),
                },
                actor=actor,
                generation=generation,
            )
            return generation

        generation = store.transaction(tx)
    store.rebuild()
    return generation


def process_identity_matches(root: Path, actor: dict[str, Any]) -> bool:
    pid = int(actor.get("pid", 0) or 0)
    pgid = int(actor.get("pgid", 0) or 0)
    expected_starttime = str(actor.get("process_starttime", ""))
    owner_token = str(actor.get("owner_token", ""))
    owner_token_sha256 = str(actor.get("owner_token_sha256", ""))
    if (
        pid <= 1
        or pgid <= 1
        or not expected_starttime
        or (not owner_token and not owner_token_sha256)
    ):
        return False
    proc = Path("/proc") / str(pid)
    try:
        raw_cmdline = (proc / "cmdline").read_bytes()
        cmdline = raw_cmdline.replace(b"\0", b" ").decode(
            "utf-8", errors="replace"
        )
        starttime = (proc / "stat").read_text().split()[21]
        environ = (proc / "environ").read_bytes().split(b"\0")
        actual_pgid = getattr(os, "getpgid")(pid)
    except (OSError, IndexError, ProcessLookupError):
        return False
    if expected_starttime != starttime or pgid != actual_pgid:
        return False
    resolved_root = root.resolve()
    argv_sha256 = str(actor.get("argv_sha256", ""))
    executable_sha256 = str(actor.get("executable_sha256", ""))
    workspace_root_sha256 = str(actor.get("workspace_root_sha256", ""))
    if any((argv_sha256, executable_sha256, workspace_root_sha256)):
        proofs = (argv_sha256, executable_sha256, workspace_root_sha256)
        if (
            any(
                len(proof) != 64
                or any(character not in "0123456789abcdef" for character in proof)
                for proof in proofs
            )
            or hashlib.sha256(str(resolved_root).encode("utf-8")).hexdigest()
            != workspace_root_sha256
        ):
            return False
    if owner_token:
        token_bytes = f"ROOKERY_OWNER_TOKEN={owner_token}".encode("utf-8")
        token_matches = token_bytes in environ or owner_token in cmdline
        if owner_token_sha256:
            token_matches = token_matches and hashlib.sha256(
                owner_token.encode("utf-8")
            ).hexdigest() == owner_token_sha256
    elif len(owner_token_sha256) == 64 and all(
        character in "0123456789abcdef" for character in owner_token_sha256
    ):
        token_matches = any(
            entry.startswith(b"ROOKERY_OWNER_TOKEN=")
            and hashlib.sha256(
                entry.removeprefix(b"ROOKERY_OWNER_TOKEN=")
            ).hexdigest()
            == owner_token_sha256
            for entry in environ
        )
    else:
        token_matches = False
    # Workspace association is established at the locked durable handoff by
    # ``workspace_root_sha256``. A child may legitimately ``chdir`` or exec
    # after handoff while its PID/start-time/PGID/owner proof remains valid;
    # launch argv and executable digests remain provenance, not later signal
    # authority.
    return token_matches


def _stop_locked(
    store: EventStore,
    root: Path,
    *,
    reason: str,
    actor: str = "operator",
    wait_seconds: float = 3.0,
) -> dict[str, Any]:
    def tx(con):
        generation = store.increment_meta_in_transaction(con, "stop_generation")
        watcher_epoch = store.increment_meta_in_transaction(con, "watcher_epoch")
        store.insert_in_transaction(
            con,
            "control.stop",
            {
                "reason": reason,
                "generation": generation,
                "watcher_epoch": watcher_epoch,
                "requested_at": iso_now(),
            },
            actor=actor,
            generation=generation,
        )
        rows = con.execute(
            "SELECT event_type,payload_json FROM events ORDER BY seq"
        ).fetchall()
        import json

        active_authorizations: dict[str, dict[str, Any]] = {}
        active_retries: dict[str, dict[str, Any]] = {}
        active_agents: dict[str, dict[str, Any]] = {}
        active_jobs: dict[str, dict[str, Any]] = {}
        active_commands: dict[str, dict[str, Any]] = {}
        for row in rows:
            payload = json.loads(row["payload_json"])
            etype = row["event_type"]
            if etype.startswith("authorization.") and payload.get("authorization_id"):
                active_authorizations[str(payload["authorization_id"])] = {
                    **payload,
                    "status": etype.split(".", 1)[1],
                }
            if etype.startswith("retry.") and payload.get("retry_id"):
                active_retries[str(payload["retry_id"])] = {
                    **payload,
                    "status": etype.split(".", 1)[1],
                }
            if etype.startswith("agent.") and payload.get("agent_id"):
                active_agents[str(payload["agent_id"])] = {
                    **payload,
                    "status": etype.split(".", 1)[1],
                }
            if etype.startswith("job.") and payload.get("job_id"):
                active_jobs[str(payload["job_id"])] = {
                    **payload,
                    "status": etype.split(".", 1)[1],
                }
            if etype.startswith("command.") and payload.get("command_id"):
                active_commands[str(payload["command_id"])] = {
                    **payload,
                    "status": etype.split(".", 1)[1],
                }
        # Capture only actors that were nonterminal when this stop generation
        # began.  The reconciliation phase below must never overwrite durable
        # historical closure or capacity-rejection evidence merely because it
        # lacks a live process identity.
        active_agents = {
            aid: row
            for aid, row in active_agents.items()
            if row.get("status") in {"assigned", "running", "stopping"}
        }
        active_jobs = {
            jid: row
            for jid, row in active_jobs.items()
            if row.get("status")
            in {"queued", "starting", "running", "stopping", "unacknowledged", "unmanaged"}
        }
        active_commands = {
            command_id: row
            for command_id, row in active_commands.items()
            if row.get("status") in {"started", "stopping"}
        }
        for aid, row in active_authorizations.items():
            if (
                row.get("status") in {"granted", "available"}
                and int(row.get("remaining", 0) or 0) > 0
            ):
                store.insert_in_transaction(
                    con,
                    "authorization.revoked",
                    {
                        **row,
                        "authorization_id": aid,
                        "remaining": 0,
                        "reason": "stop generation advanced",
                    },
                    actor=actor,
                    generation=generation,
                )
        for rid, row in active_retries.items():
            if row.get("status") == "scheduled":
                store.insert_in_transaction(
                    con,
                    "retry.cancelled",
                    {**row, "retry_id": rid, "reason": "stop generation advanced"},
                    actor=actor,
                    generation=generation,
                )
        for aid, row in active_agents.items():
            if row.get("status") in {"assigned", "running"}:
                store.insert_in_transaction(
                    con,
                    "agent.stopping",
                    {**row, "agent_id": aid, "reason": "stop generation advanced"},
                    actor=actor,
                    generation=generation,
                )
        for jid, row in active_jobs.items():
            if row.get("status") in {
                "queued",
                "running",
                "starting",
                "unacknowledged",
                "unmanaged",
            }:
                store.insert_in_transaction(
                    con,
                    "job.stopping",
                    {**row, "job_id": jid, "reason": "stop generation advanced"},
                    actor=actor,
                    generation=generation,
                )
        for command_id, row in active_commands.items():
            if row.get("status") == "started":
                store.insert_in_transaction(
                    con,
                    "command.stopping",
                    {
                        **row,
                        "command_id": command_id,
                        "reason": "stop generation advanced",
                    },
                    actor=actor,
                    generation=generation,
                )
        return generation, active_agents, active_jobs, active_commands

    generation, active_agents, active_jobs, active_commands = store.transaction(tx)
    signalled: list[int] = []
    resource_snapshots: dict[tuple[str, str], dict[str, Any]] = {}
    unacknowledged: list[str] = []
    unmanaged: list[str] = []
    confirmed_closed: list[str] = []
    confirmed_cancelled: list[str] = []
    confirmed_stopped: list[str] = []
    for collection_name, collection in (
        ("agent", active_agents),
        ("job", active_jobs),
        ("command", active_commands),
    ):
        for ident, row in collection.items():
            signalable_statuses = {"assigned", "running", "queued"}
            if collection_name == "job":
                # A watcher can acquire its process identity after ``job.starting``
                # but before its durable ``job.running`` transition. Stop still
                # requires the full identity match below; event status alone never
                # authorizes a signal.
                signalable_statuses.update(
                    {"starting", "unacknowledged", "unmanaged"}
                )
            elif collection_name == "command":
                signalable_statuses = {"started"}
            if row.get("status") not in signalable_statuses:
                continue
            pid = int(row.get("pid", 0) or 0)
            if pid and process_identity_matches(root, row):
                try:
                    resource_snapshots[(collection_name, ident)] = (
                        process_resource_snapshot(pid)
                    )
                    getattr(os, "killpg")(int(row.get("pgid", pid)), signal.SIGTERM)
                    signalled.append(pid)
                except (ProcessLookupError, PermissionError):
                    pass
    deadline = time.time() + wait_seconds
    while time.time() < deadline:
        projection = store.rebuild()
        active = [
            a
            for a in projection["current"]["agents"].values()
            if a.get("status") in {"assigned", "running", "stopping"}
        ]
        active += [
            j
            for j in projection["current"]["jobs"].values()
            if j.get("status")
            in {"queued", "running", "stopping", "unacknowledged", "unmanaged"}
        ]
        active += [
            command
            for command in projection["current"].get("commands", {}).values()
            if command.get("status") in {"started", "stopping"}
        ]
        if not active:
            break
        time.sleep(0.1)
    # Commands can be long-running external reconnaissance. Escalate only
    # after the caller's bounded wait and only after repeating the exact
    # identity check, preserving the no-signal rule for stale or reused PIDs.
    if wait_seconds > 0:
        for command_id, row in active_commands.items():
            pid = int(row.get("pid", 0) or 0)
            if pid not in signalled or not process_identity_matches(root, row):
                continue
            try:
                getattr(os, "killpg")(int(row.get("pgid", pid)), signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                continue
        deadline = time.time() + min(1.0, wait_seconds)
        while time.time() < deadline:
            if not any(
                process_identity_matches(root, row)
                for row in active_commands.values()
                if int(row.get("pid", 0) or 0) in signalled
            ):
                break
            time.sleep(0.05)
    # Reconcile each actor to a terminal truth. Only a signalled, now-absent
    # Rookery-owned identity counts as a positive shutdown acknowledgement.
    for collection_name, collection in (
        ("agent", active_agents),
        ("job", active_jobs),
        ("command", active_commands),
    ):
        for ident, row in collection.items():
            pid = int(row.get("pid", 0) or 0)
            still_owned_and_running = process_identity_matches(root, row)
            key = {
                "agent": "agent_id",
                "job": "job_id",
                "command": "command_id",
            }[collection_name]
            if pid in signalled and not still_owned_and_running:
                terminal = {
                    "agent": "closed",
                    "job": "cancelled",
                    "command": "stopped",
                }[collection_name]
                finished_at = iso_now()
                store.append(
                    f"{collection_name}.{terminal}",
                    {
                        **row,
                        key: ident,
                        "reason": "stop signal acknowledged",
                        "closed_at": finished_at,
                        "resource_summary": resource_snapshots.get(
                            (collection_name, ident), {}
                        ),
                    },
                    actor=actor,
                    generation=generation,
                )
                if terminal == "closed":
                    confirmed_closed.append(ident)
                elif terminal == "cancelled":
                    confirmed_cancelled.append(ident)
                    _update_job_metadata(
                        root,
                        ident,
                        status=terminal,
                        reason="stop signal acknowledged",
                        finished_at=finished_at,
                        resource_summary=resource_snapshots.get(
                            (collection_name, ident), {}
                        ),
                    )
                else:
                    confirmed_stopped.append(ident)
                continue
            status = "unacknowledged" if still_owned_and_running else "unmanaged"
            reason = (
                "owned process remained live after stop timeout"
                if still_owned_and_running
                else "no verifiable Rookery-owned process identity; closure is unknown"
            )
            store.append(
                f"{collection_name}.{status}",
                {
                    **row,
                    key: ident,
                    "reason": reason,
                    "reconciled_at": iso_now(),
                },
                actor=actor,
                generation=generation,
            )
            if collection_name == "job":
                _update_job_metadata(
                    root,
                    ident,
                    status=status,
                    reason=reason,
                    finished_at=iso_now(),
                    resource_summary=resource_snapshots.get(
                        (collection_name, ident), {}
                    ),
                )
            if status == "unacknowledged":
                unacknowledged.append(ident)
            else:
                unmanaged.append(ident)
    store.rebuild()
    return {
        "generation": generation,
        "signalled_pids": signalled,
        "unacknowledged": sorted(set(unacknowledged)),
        "unmanaged": sorted(set(unmanaged)),
        "confirmed_closed": sorted(set(confirmed_closed)),
        "confirmed_cancelled": sorted(set(confirmed_cancelled)),
        "confirmed_stopped": sorted(set(confirmed_stopped)),
        "not_confirmed": sorted(set(unacknowledged + unmanaged)),
    }


def stop(
    store: EventStore,
    root: Path,
    *,
    reason: str,
    actor: str = "operator",
    wait_seconds: float = 3.0,
) -> dict[str, Any]:
    """Advance stop while excluding concurrent mutation dispatch."""

    with file_lock(root / "state" / "mutation.lock"):
        return _stop_locked(
            store,
            root,
            reason=reason,
            actor=actor,
            wait_seconds=wait_seconds,
        )


def write_stop_prompt(root: Path, generation: int, reason: str) -> Path:
    path = root / "STOP_PROMPT.md"
    text = f"""/goal Stop this Rookery cleanly at generation {generation}.

Reason: {reason}

Do not spawn new workers or execute scoring/platform mutations. Checkpoint active work, record typed outcomes, close owned jobs, harvest each report once, preserve exact evidence, create missing solve capsules, enforce closeout writeups according to event policy, and write exactly one improvements-only `lessons-learned-YYYYMMDDThhmmss.md` document. Do not turn that document into a run-status report.
"""
    atomic_write_text(path, text)
    return path
