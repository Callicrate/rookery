"""Read-only, privacy-safe reporting for a completed Rookery runtime."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import logging
import math
import os
import sqlite3
import stat
import sys
import tempfile
import unicodedata
from collections import Counter
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Iterable, Sequence

from .util import canonical_json

logger = logging.getLogger(__name__)

REPORT_SCHEMA_VERSION = "2"
MAX_EVENT_LINE_BYTES = 1_048_576
MAX_EVENT_COUNT = 200_000
MAX_EVENT_BYTES = 268_435_456
MAX_SQLITE_FILE_BYTES = 536_870_912
MAX_JSON_DOCUMENT_BYTES = 1_048_576
MAX_COMMAND_DIRECTORIES = 100_000
MAX_COMMAND_METADATA_BYTES = 134_217_728
MAX_HASH_FILE_BYTES = 67_108_864
MAX_SUMMARY_FILES = 100_000
MAX_SUMMARY_BYTES = 536_870_912
STREAM_CHUNK_BYTES = 65_536
MAX_LAUNCH_BINDING_BYTES = 65_536
MAX_EVIDENCE_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_EVIDENCE_MANIFEST_REFERENCES = 20_000
MAX_EVIDENCE_MANIFEST_FILES = MAX_SUMMARY_FILES
MAX_EVIDENCE_MANIFEST_TOTAL_BYTES = MAX_SUMMARY_BYTES
LAUNCH_BINDING_SCHEMA_VERSION = "3"
LAUNCH_BINDING_COMMON_FIELDS = frozenset(
    {
        "schema_version",
        "workspace_identity",
        "immutable_source_sha256",
        "environment_sha256",
        "event_manifest_sha256",
        "release_version",
        "baseline_sha256",
        "baseline_configuration_digest",
        "selected_adapter",
        "selected_extensions",
        "codex",
        "auth_mode",
        "strict_config_supported",
    }
)
LAUNCH_BINDING_FIELDS = LAUNCH_BINDING_COMMON_FIELDS | {"measurement_contract"}
MEASUREMENT_PROVIDER_FIELDS = frozenset({"queue", "tokens", "usage"})
EVIDENCE_REFERENCE_STATUSES = frozenset(
    {"empty", "missing", "rejected", "present_file", "present_directory"}
)
EVIDENCE_PRESENT_STATUSES = frozenset({"present_file", "present_directory"})
EXECUTION_TERMINAL_TYPES = frozenset(
    {
        "execution.completed",
        "execution.rejected",
        "execution.blocked",
        "execution.failed",
        "execution.indeterminate",
    }
)
LOCAL_PROCESS_RESOURCE_FIELDS = ("cpu_seconds", "rss_bytes", "peak_rss_bytes")
PROVIDER_RESOURCE_FIELDS = {
    "queue": ("provider_queue_seconds", "seconds"),
    "tokens": ("provider_token_count", "tokens"),
    "usage": ("provider_usage_seconds", "seconds"),
}
JOB_TERMINAL_TYPES = frozenset(
    {
        "job.cancelled",
        "job.closed",
        "job.stale",
        "job.unacknowledged",
        "job.unmanaged",
    }
)
# Stale and unacknowledged records can be resolved by an observed later close.
# A closed or cancelled job must never be given a contradictory later terminal
# state in a comparison cohort.
JOB_IRREVOCABLE_TERMINAL_TYPES = frozenset({"job.cancelled", "job.closed"})
SCORING_ACTION_KINDS = frozenset(
    {
        "flag",
        "free_text",
        "multi_objective",
        "handle_write",
        "proof_artifact",
        "no_submit_evidence",
    }
)


def _measurement_contract(value: Any) -> dict[str, Any] | None:
    """Return a strict, value-free baseline applicability declaration."""

    if not isinstance(value, dict) or set(value) != {
        "queue_automation_enabled",
        "provider_fields",
    }:
        return None
    queue_automation = value.get("queue_automation_enabled")
    provider_fields = value.get("provider_fields")
    if not isinstance(queue_automation, bool) or not isinstance(provider_fields, dict):
        return None
    if set(provider_fields) != MEASUREMENT_PROVIDER_FIELDS:
        return None
    normalized: dict[str, dict[str, str]] = {}
    for name in sorted(MEASUREMENT_PROVIDER_FIELDS):
        field = provider_fields.get(name)
        if (
            not isinstance(field, dict)
            or set(field) != {"availability"}
            or field.get("availability") not in {"available", "unavailable"}
        ):
            return None
        normalized[name] = {"availability": str(field["availability"])}
    return {
        "queue_automation_enabled": queue_automation,
        "provider_fields": normalized,
    }


class TelemetryValidationError(ValueError):
    """Raised when a requested report output would violate report boundaries."""


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _error(errors: list[dict[str, str]], code: str) -> None:
    """Record a stable error code without carrying untrusted telemetry content."""

    errors.append({"code": code})


def _warning(warnings: list[dict[str, str]], code: str) -> None:
    """Record a stable warning code without carrying untrusted telemetry content."""

    warnings.append({"code": code})


def _inside_runtime(root: Path, candidate: Path) -> Path | None:
    """Resolve a local input only when symlinks still leave it inside ``root``."""

    try:
        resolved = candidate.resolve(strict=False)
        resolved.relative_to(root.resolve())
    except (OSError, ValueError):
        return None
    return resolved


def _event_from_value(value: Any) -> dict[str, Any] | None:
    """Return a validated logical event or ``None`` for an invalid JSON value."""

    if not isinstance(value, dict):
        return None
    required = ("seq", "event_id", "event_type", "created_at", "generation", "actor", "payload")
    if any(key not in value for key in required):
        return None
    if not _is_int(value["seq"]) or value["seq"] < 1:
        return None
    if not _is_int(value["generation"]):
        return None
    if not all(isinstance(value[key], str) and value[key] for key in ("event_id", "event_type", "created_at", "actor")):
        return None
    if not isinstance(value["payload"], dict):
        return None
    return {
        "seq": value["seq"],
        "event_id": value["event_id"],
        "event_type": value["event_type"],
        "created_at": value["created_at"],
        "generation": value["generation"],
        "actor": value["actor"],
        "payload": value["payload"],
    }


def read_canonical_events(root: Path) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    """Read canonical JSONL events while enforcing schema, order, and identity rules."""

    errors: list[dict[str, str]] = []
    path = _inside_runtime(root, root / "state" / "events.jsonl")
    if path is None:
        _error(errors, "events.outside_runtime")
        return [], errors
    if not path.is_file():
        _error(errors, "events.missing")
        return [], errors

    events: list[dict[str, Any]] = []
    event_ids: set[str] = set()
    previous_sequence = 0
    total_bytes = 0
    try:
        with path.open("rb") as handle:
            for _line_number in range(1, MAX_EVENT_COUNT + 2):
                raw = handle.readline(MAX_EVENT_LINE_BYTES + 1)
                if not raw:
                    break
                if len(raw) > MAX_EVENT_LINE_BYTES:
                    _error(errors, "events.line_too_large")
                    break
                total_bytes += len(raw)
                if total_bytes > MAX_EVENT_BYTES:
                    _error(errors, "events.aggregate_too_large")
                    break
                if not raw.strip():
                    continue
                try:
                    value = json.loads(raw.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    _error(errors, "events.invalid_json")
                    continue
                event = _event_from_value(value)
                if event is None:
                    _error(errors, "events.invalid_schema")
                    continue
                if event["seq"] <= previous_sequence:
                    _error(errors, "events.non_monotonic_sequence")
                previous_sequence = max(previous_sequence, event["seq"])
                if event["event_id"] in event_ids:
                    _error(errors, "events.duplicate_event_id")
                event_ids.add(event["event_id"])
                events.append(event)
            else:
                _error(errors, "events.too_many")
    except OSError:
        _error(errors, "events.unreadable")
    return events, errors


def _read_sqlite_events(path: Path) -> tuple[list[dict[str, Any]] | None, str | None]:
    """Open SQLite in URI read-only mode and return its ordered logical events."""

    try:
        if path.stat().st_size > MAX_SQLITE_FILE_BYTES:
            return None, "sqlite.file_too_large"
    except OSError:
        return None, "sqlite.unreadable"
    if any(
        path.with_name(path.name + suffix).exists() for suffix in ("-wal", "-shm")
    ):
        return None, "sqlite.sidecar_present"
    try:
        connection = sqlite3.connect(
            f"{path.resolve().as_uri()}?mode=ro&immutable=1",
            uri=True,
        )
        try:
            connection.execute("PRAGMA query_only=ON")
            count, largest_payload, total_payload = connection.execute(
                "SELECT COUNT(*), COALESCE(MAX(LENGTH(payload_json)), 0), "
                "COALESCE(SUM(LENGTH(payload_json)), 0) FROM events"
            ).fetchone()
            if int(count) > MAX_EVENT_COUNT:
                return None, "sqlite.too_many"
            if int(largest_payload) > MAX_EVENT_LINE_BYTES:
                return None, "sqlite.payload_too_large"
            if int(total_payload) > MAX_EVENT_BYTES:
                return None, "sqlite.aggregate_too_large"
            rows = connection.execute(
                "SELECT seq,event_id,event_type,created_at,generation,actor,payload_json "
                "FROM events ORDER BY seq"
            )
            events: list[dict[str, Any]] = []
            for row in rows:
                try:
                    payload = json.loads(row[6])
                except (TypeError, json.JSONDecodeError):
                    return None, "sqlite.invalid_payload"
                event = _event_from_value(
                    {
                        "seq": row[0],
                        "event_id": row[1],
                        "event_type": row[2],
                        "created_at": row[3],
                        "generation": row[4],
                        "actor": row[5],
                        "payload": payload,
                    }
                )
                if event is None:
                    return None, "sqlite.invalid_schema"
                events.append(event)
            return events, None
        finally:
            connection.close()
    except (OSError, sqlite3.Error, ValueError):
        return None, "sqlite.unreadable"


def compare_sqlite_events(root: Path, events: list[dict[str, Any]]) -> dict[str, Any]:
    """Compare an optional SQLite projection without changing it or creating a WAL."""

    path = _inside_runtime(root, root / "state" / "events.sqlite3")
    if path is None:
        return {"present": True, "matches_jsonl": False, "error": "sqlite.outside_runtime"}
    if not path.exists():
        return {"present": False, "matches_jsonl": None}
    rows, error = _read_sqlite_events(path)
    if error:
        return {"present": True, "matches_jsonl": False, "error": error}
    return {
        "present": True,
        "matches_jsonl": rows == events,
        "jsonl_rows": len(events),
        "sqlite_rows": len(rows or []),
    }


def _bounded_json_object(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    """Read a small JSON object only; no error details can leak envelope content."""

    try:
        if path.stat().st_size > MAX_JSON_DOCUMENT_BYTES:
            return None, "too_large"
        with path.open("rb") as handle:
            raw = handle.read(MAX_JSON_DOCUMENT_BYTES + 1)
        if len(raw) > MAX_JSON_DOCUMENT_BYTES:
            return None, "too_large"
        value = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None, "invalid"
    return (value, None) if isinstance(value, dict) else (None, "invalid")


def _source_relative(value: str, source_root: str | Path | None) -> tuple[str, ...] | None:
    """Map an absolute deployed path to its safe path parts under this runtime."""

    if source_root is None:
        return None
    for path_type in (PurePosixPath, PureWindowsPath):
        reference = path_type(value)
        source = path_type(str(source_root))
        if not reference.is_absolute() or not source.is_absolute():
            continue
        try:
            return reference.relative_to(source).parts
        except ValueError:
            continue
    return None


def resolve_evidence_path(
    root: Path,
    value: Any,
    source_root: str | Path | None = None,
) -> tuple[str, Path | None]:
    """Resolve a telemetry path only when it stays within the analyzed runtime root.

    The returned status is intentionally path-free so it can be included in a
    privacy-safe report.
    """

    if not isinstance(value, str) or not value.strip():
        return "empty", None
    if "\x00" in value or len(value) > 4_096:
        return "rejected", None
    analyzed_root = root.resolve()
    candidate: Path | None = None
    mapped = _source_relative(value, source_root)
    if mapped is not None:
        candidate = analyzed_root.joinpath(*mapped)
    else:
        local = Path(value)
        if local.is_absolute():
            candidate = local
        elif not PureWindowsPath(value).is_absolute():
            candidate = analyzed_root / local
    if candidate is None:
        return "rejected", None
    resolved = _inside_runtime(analyzed_root, candidate)
    if resolved is None:
        return "rejected", None
    return ("present", resolved) if resolved.exists() else ("missing", resolved)


def _new_completeness() -> Counter[str]:
    return Counter({"references": 0, "empty": 0, "present": 0, "missing": 0, "rejected": 0})


def _count_reference(
    counts: Counter[str], root: Path, value: Any, source_root: str | Path | None
) -> None:
    counts["references"] += 1
    status, _path = resolve_evidence_path(root, value, source_root)
    counts[status] += 1


def _no_submit_evidence_root(plan: Any, terminal_payload: dict[str, Any]) -> Any:
    """Return the retained no-submit proof path without exposing its content."""

    envelope = plan.get("envelope") if isinstance(plan, dict) else None
    if isinstance(envelope, dict) and envelope.get("artifact_reference") == "":
        return plan.get("plan_path") if isinstance(plan, dict) else None
    return terminal_payload.get("evidence_root")


def summarize_evidence(
    root: Path, events: Iterable[dict[str, Any]], source_root: str | Path | None
) -> dict[str, Any]:
    """Count evidence references without publishing the references themselves."""

    response_paths = _new_completeness()
    evidence_roots = _new_completeness()
    plan_paths = _new_completeness()
    event_list = list(events)
    plans = {
        event["payload"].get("plan_id"): event["payload"]
        for event in event_list
        if event["event_type"] == "execution.planned"
        and isinstance(event["payload"].get("plan_id"), str)
    }
    for event in event_list:
        payload = event["payload"]
        if event["event_type"] in EXECUTION_TERMINAL_TYPES:
            plan = plans.get(payload.get("plan_id"))
            no_submit = isinstance(plan, dict) and plan.get("semantic_action") == "no_submit_evidence"
            if not no_submit:
                _count_reference(response_paths, root, payload.get("response_path", ""), source_root)
            evidence_root = (
                _no_submit_evidence_root(plan, payload) if no_submit else payload.get("evidence_root", "")
            )
            if not no_submit or evidence_root:
                _count_reference(
                    evidence_roots, root, evidence_root, source_root
                )
        if event["event_type"] == "execution.planned":
            paths = payload.get("evidence_paths", [])
            if not isinstance(paths, list):
                paths = [None]
            for value in paths:
                _count_reference(plan_paths, root, value, source_root)
    return {
        "terminal_response_path": dict(response_paths),
        "terminal_evidence_root": dict(evidence_roots),
        "plan_evidence_paths": dict(plan_paths),
    }


def _read_evidence_manifest(root: Path) -> tuple[dict[str, Any] | None, str | None]:
    """Read one bounded, no-follow evidence manifest without exposing it."""

    evidence = _inside_runtime(root, root / "evidence")
    path = _inside_runtime(root, root / "evidence" / "latest-manifest.json")
    if evidence is None or path is None:
        return None, "evidence_manifest_outside_runtime"
    try:
        directory = evidence.lstat()
        initial = path.lstat()
    except OSError:
        return None, "evidence_manifest_missing"
    if (
        stat.S_ISLNK(directory.st_mode)
        or not stat.S_ISDIR(directory.st_mode)
        or stat.S_ISLNK(initial.st_mode)
        or not stat.S_ISREG(initial.st_mode)
    ):
        return None, "evidence_manifest_invalid"
    if initial.st_size > MAX_EVIDENCE_MANIFEST_BYTES:
        return None, "evidence_manifest_too_large"
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        return None, "evidence_manifest_unreadable"
    try:
        opened = os.fstat(descriptor)
        signature = (initial.st_dev, initial.st_ino, initial.st_size, initial.st_mtime_ns)
        if (
            not stat.S_ISREG(opened.st_mode)
            or (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
            != signature
        ):
            return None, "evidence_manifest_changed"
        raw = bytearray()
        while len(raw) <= MAX_EVIDENCE_MANIFEST_BYTES:
            chunk = os.read(
                descriptor,
                min(STREAM_CHUNK_BYTES, MAX_EVIDENCE_MANIFEST_BYTES + 1 - len(raw)),
            )
            if not chunk:
                break
            raw.extend(chunk)
        if len(raw) > MAX_EVIDENCE_MANIFEST_BYTES:
            return None, "evidence_manifest_too_large"
        final = os.fstat(descriptor)
        if (final.st_dev, final.st_ino, final.st_size, final.st_mtime_ns) != signature:
            return None, "evidence_manifest_changed"
    except OSError:
        return None, "evidence_manifest_unreadable"
    finally:
        os.close(descriptor)

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result

    try:
        value = json.loads(bytes(raw).decode("utf-8"), object_pairs_hook=unique_object)
    except (RecursionError, UnicodeDecodeError, json.JSONDecodeError, ValueError):
        return None, "evidence_manifest_invalid"
    return (value, None) if isinstance(value, dict) else (None, "evidence_manifest_invalid")


def _manifest_relative_parts(value: Any) -> tuple[str, ...] | None:
    """Accept only one normalized, portable relative manifest path."""

    if (
        not isinstance(value, str)
        or not value
        or len(value) > 4_096
        or "\x00" in value
        or "\\" in value
    ):
        return None
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or path.as_posix() != value:
        return None
    if any(part in {"", ".", ".."} for part in path.parts):
        return None
    return tuple(path.parts)


def _stable_descriptor_signature(info: os.stat_result) -> tuple[int, ...]:
    """Return the fields used to detect an in-place descriptor substitution."""

    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_uid,
        info.st_gid,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _manifest_open_flags(*, directory: bool) -> int | None:
    """Return no-follow descriptor flags, or fail closed where unavailable."""

    nofollow = getattr(os, "O_NOFOLLOW", None)
    directory_flag = getattr(os, "O_DIRECTORY", None)
    if not isinstance(nofollow, int) or (directory and not isinstance(directory_flag, int)):
        return None
    flags = os.O_RDONLY | nofollow | getattr(os, "O_CLOEXEC", 0)
    return flags | (directory_flag if directory else 0)


def _open_manifest_directory(root: Path, parts: tuple[str, ...]) -> tuple[int | None, str | None]:
    """Open a manifest directory component-by-component without following links."""

    flags = _manifest_open_flags(directory=True)
    if flags is None:
        return None, "evidence_manifest_nofollow_unsupported"
    descriptor: int | None = None
    handed_off = False
    try:
        descriptor = os.open(root, flags)
        for part in parts:
            initial = os.stat(part, dir_fd=descriptor, follow_symlinks=False)
            if stat.S_ISLNK(initial.st_mode) or not stat.S_ISDIR(initial.st_mode):
                return None, "evidence_manifest_reference_invalid"
            child: int | None = None
            try:
                child = os.open(part, flags, dir_fd=descriptor)
                opened = os.fstat(child)
            except OSError:
                if child is not None:
                    os.close(child)
                raise
            if (
                not stat.S_ISDIR(opened.st_mode)
                or _stable_descriptor_signature(opened)
                != _stable_descriptor_signature(initial)
            ):
                os.close(child)
                return None, "evidence_manifest_reference_changed"
            previous = descriptor
            descriptor = child
            os.close(previous)
        handed_off = True
        return descriptor, None
    except OSError:
        return None, "evidence_manifest_reference_unreadable"
    finally:
        if not handed_off and descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _read_manifest_file(
    root: Path, parts: tuple[str, ...]
) -> tuple[tuple[int, str] | None, str | None]:
    """Hash one retained regular file from a stable, no-follow descriptor."""

    if not parts:
        return None, "evidence_manifest_reference_invalid"
    parent, error = _open_manifest_directory(root, parts[:-1])
    if parent is None:
        return None, error
    flags = _manifest_open_flags(directory=False)
    if flags is None:
        os.close(parent)
        return None, "evidence_manifest_nofollow_unsupported"
    try:
        initial = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
        if stat.S_ISLNK(initial.st_mode) or not stat.S_ISREG(initial.st_mode):
            return None, "evidence_manifest_reference_invalid"
        if initial.st_size > MAX_HASH_FILE_BYTES:
            return None, "evidence_manifest_reference_too_large"
        descriptor = os.open(parts[-1], flags, dir_fd=parent)
        try:
            opened = os.fstat(descriptor)
            signature = _stable_descriptor_signature(initial)
            if (
                not stat.S_ISREG(opened.st_mode)
                or _stable_descriptor_signature(opened) != signature
            ):
                return None, "evidence_manifest_reference_changed"
            digest = hashlib.sha256()
            total = 0
            while True:
                chunk = os.read(descriptor, STREAM_CHUNK_BYTES)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_HASH_FILE_BYTES:
                    return None, "evidence_manifest_reference_too_large"
                digest.update(chunk)
            final = os.fstat(descriptor)
            if _stable_descriptor_signature(final) != signature:
                return None, "evidence_manifest_reference_changed"
            return (total, digest.hexdigest()), None
        finally:
            os.close(descriptor)
    except OSError:
        return None, "evidence_manifest_reference_unreadable"
    finally:
        os.close(parent)


def _read_manifest_json_file(
    root: Path, parts: tuple[str, ...]
) -> tuple[dict[str, Any] | None, str | None]:
    """Read one bounded JSON object through a stable no-follow descriptor."""

    if not parts:
        return None, "evidence_manifest_reference_invalid"
    parent, error = _open_manifest_directory(root, parts[:-1])
    if parent is None:
        return None, error
    flags = _manifest_open_flags(directory=False)
    if flags is None:
        os.close(parent)
        return None, "evidence_manifest_nofollow_unsupported"
    try:
        initial = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
        if stat.S_ISLNK(initial.st_mode) or not stat.S_ISREG(initial.st_mode):
            return None, "evidence_manifest_reference_invalid"
        if initial.st_size > MAX_JSON_DOCUMENT_BYTES:
            return None, "evidence_manifest_reference_too_large"
        descriptor = os.open(parts[-1], flags, dir_fd=parent)
        try:
            opened = os.fstat(descriptor)
            signature = _stable_descriptor_signature(initial)
            if (
                not stat.S_ISREG(opened.st_mode)
                or _stable_descriptor_signature(opened) != signature
            ):
                return None, "evidence_manifest_reference_changed"
            raw = bytearray()
            while len(raw) <= MAX_JSON_DOCUMENT_BYTES:
                chunk = os.read(
                    descriptor,
                    min(
                        STREAM_CHUNK_BYTES,
                        MAX_JSON_DOCUMENT_BYTES + 1 - len(raw),
                    ),
                )
                if not chunk:
                    break
                raw.extend(chunk)
            if len(raw) > MAX_JSON_DOCUMENT_BYTES:
                return None, "evidence_manifest_reference_too_large"
            if _stable_descriptor_signature(os.fstat(descriptor)) != signature:
                return None, "evidence_manifest_reference_changed"
        finally:
            os.close(descriptor)
    except OSError:
        return None, "evidence_manifest_reference_unreadable"
    finally:
        os.close(parent)

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result

    try:
        value = json.loads(bytes(raw).decode("utf-8"), object_pairs_hook=unique_object)
    except (RecursionError, UnicodeDecodeError, json.JSONDecodeError, ValueError):
        return None, "evidence_manifest_reference_invalid"
    return (value, None) if isinstance(value, dict) else (None, "evidence_manifest_reference_invalid")


def sealed_plan_file_matches(root: Path, plan: dict[str, Any]) -> bool:
    """Bind value-only no-submit evidence to its exact sealed canonical plan."""

    plan_id = plan.get("plan_id")
    plan_path = plan.get("plan_path")
    if (
        not isinstance(plan_id, str)
        or not plan_id
        or plan_path != f"state/execution_plans/{plan_id}.json"
    ):
        return False
    parts = _manifest_relative_parts(plan_path)
    if parts is None:
        return False
    sealed, error = _read_manifest_json_file(root, parts)
    if sealed is None or error is not None:
        return False
    expected = {key: value for key, value in plan.items() if key != "plan_path"}
    if not _canonical_values_match(sealed, expected):
        return False
    plan_sha256 = sealed.get("plan_sha256")
    canonical_plan = {key: value for key, value in sealed.items() if key != "plan_sha256"}
    return _valid_sha256(plan_sha256) and plan_sha256 == _canonical_sha256(canonical_plan)


def _manifest_file_table(
    manifest: dict[str, Any]
) -> tuple[dict[str, tuple[int, str]] | None, str | None]:
    """Validate the bounded, value-free file-hash table emitted by schema 3."""

    rows = manifest.get("files")
    declared_count = manifest.get("file_count")
    declared_bytes = manifest.get("total_bytes")
    if (
        not isinstance(rows, list)
        or len(rows) > MAX_EVIDENCE_MANIFEST_FILES
        or not _is_int(declared_count)
        or declared_count != len(rows)
        or not _is_int(declared_bytes)
        or declared_bytes < 0
    ):
        return None, "evidence_manifest_files_invalid"
    files: dict[str, tuple[int, str]] = {}
    total = 0
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"path", "bytes", "sha256"}:
            return None, "evidence_manifest_files_invalid"
        parts = _manifest_relative_parts(row.get("path"))
        byte_count = row.get("bytes")
        digest = row.get("sha256")
        if (
            parts is None
            or not _is_int(byte_count)
            or byte_count < 0
            or byte_count > MAX_HASH_FILE_BYTES
            or not _valid_sha256(digest)
            or digest != digest.lower()
        ):
            return None, "evidence_manifest_files_invalid"
        relative = "/".join(parts)
        if relative in files or relative == "evidence/latest-manifest.json":
            return None, "evidence_manifest_files_invalid"
        total += byte_count
        if total > MAX_EVIDENCE_MANIFEST_TOTAL_BYTES:
            return None, "evidence_manifest_files_too_large"
        files[relative] = (byte_count, digest)
    if total != declared_bytes:
        return None, "evidence_manifest_files_invalid"
    return files, None


def _manifest_directory_files(
    root: Path, parts: tuple[str, ...]
) -> tuple[dict[str, tuple[int, str]] | None, str | None]:
    """Hash all retained regular descendants of one manifest directory safely."""

    descriptor, error = _open_manifest_directory(root, parts)
    if descriptor is None:
        return None, error
    files: dict[str, tuple[int, str]] = {}
    total = 0

    def descend(directory: int, prefix: tuple[str, ...]) -> str | None:
        nonlocal total
        try:
            directory_initial = os.fstat(directory)
            if not stat.S_ISDIR(directory_initial.st_mode):
                return "evidence_manifest_reference_invalid"
            names = sorted(os.listdir(directory))
        except OSError:
            return "evidence_manifest_reference_unreadable"
        for name in names:
            if not name or name in {".", ".."} or "/" in name or "\\" in name:
                return "evidence_manifest_reference_invalid"
            try:
                initial = os.stat(name, dir_fd=directory, follow_symlinks=False)
            except OSError:
                return "evidence_manifest_reference_unreadable"
            relative_parts = (*prefix, name)
            relative = "/".join(relative_parts)
            if stat.S_ISLNK(initial.st_mode):
                return "evidence_manifest_reference_invalid"
            if stat.S_ISDIR(initial.st_mode):
                flags = _manifest_open_flags(directory=True)
                if flags is None:
                    return "evidence_manifest_nofollow_unsupported"
                child: int | None = None
                try:
                    child = os.open(name, flags, dir_fd=directory)
                    opened = os.fstat(child)
                except OSError:
                    if child is not None:
                        os.close(child)
                    return "evidence_manifest_reference_unreadable"
                try:
                    if (
                        not stat.S_ISDIR(opened.st_mode)
                        or _stable_descriptor_signature(opened)
                        != _stable_descriptor_signature(initial)
                    ):
                        return "evidence_manifest_reference_changed"
                    nested = descend(child, relative_parts)
                    if nested:
                        return nested
                finally:
                    os.close(child)
                continue
            if not stat.S_ISREG(initial.st_mode):
                return "evidence_manifest_reference_invalid"
            if initial.st_size > MAX_HASH_FILE_BYTES:
                return "evidence_manifest_reference_too_large"
            flags = _manifest_open_flags(directory=False)
            if flags is None:
                return "evidence_manifest_nofollow_unsupported"
            file_descriptor: int | None = None
            try:
                file_descriptor = os.open(name, flags, dir_fd=directory)
                opened = os.fstat(file_descriptor)
            except OSError:
                if file_descriptor is not None:
                    os.close(file_descriptor)
                return "evidence_manifest_reference_unreadable"
            try:
                signature = _stable_descriptor_signature(initial)
                if (
                    not stat.S_ISREG(opened.st_mode)
                    or _stable_descriptor_signature(opened) != signature
                ):
                    return "evidence_manifest_reference_changed"
                digest = hashlib.sha256()
                byte_count = 0
                while True:
                    chunk = os.read(file_descriptor, STREAM_CHUNK_BYTES)
                    if not chunk:
                        break
                    byte_count += len(chunk)
                    if byte_count > MAX_HASH_FILE_BYTES:
                        return "evidence_manifest_reference_too_large"
                    digest.update(chunk)
                if _stable_descriptor_signature(os.fstat(file_descriptor)) != signature:
                    return "evidence_manifest_reference_changed"
            finally:
                os.close(file_descriptor)
            if relative == "evidence/latest-manifest.json":
                continue
            if len(files) >= MAX_EVIDENCE_MANIFEST_FILES:
                return "evidence_manifest_reference_too_many_files"
            total += byte_count
            if total > MAX_EVIDENCE_MANIFEST_TOTAL_BYTES:
                return "evidence_manifest_reference_too_large"
            files[relative] = (byte_count, digest.hexdigest())
        try:
            if _stable_descriptor_signature(os.fstat(directory)) != _stable_descriptor_signature(directory_initial):
                return "evidence_manifest_reference_changed"
        except OSError:
            return "evidence_manifest_reference_unreadable"
        return None

    try:
        error = descend(descriptor, parts)
        return (files, None) if error is None else (None, error)
    finally:
        os.close(descriptor)


def _expected_required_evidence(
    events: Iterable[dict[str, Any]], root: Path, source_root: str | Path | None
) -> tuple[Counter[tuple[str, str, str]], set[str]] | None:
    """Return expected required references and completed/rejected terminal plans."""

    event_list = list(events)
    expected: Counter[tuple[str, str, str]] = Counter()

    def relative(value: Any) -> str | None:
        status, path = resolve_evidence_path(root, value, source_root)
        if status == "empty":
            return ""
        if path is None:
            return None
        try:
            return path.relative_to(root.resolve()).as_posix()
        except ValueError:
            return None

    plans = {
        event["payload"].get("plan_id"): event["payload"]
        for event in event_list
        if event["event_type"] == "execution.planned"
        and isinstance(event["payload"].get("plan_id"), str)
    }
    for event in event_list:
        if event["event_type"] != "execution.planned":
            continue
        plan_id = event["payload"].get("plan_id")
        if not isinstance(plan_id, str) or not plan_id:
            continue
        paths = event["payload"].get("evidence_paths", [])
        if not isinstance(paths, list) or not paths:
            paths = [None]
        for value in paths:
            path = relative(value)
            if path is None:
                return None
            expected[(plan_id, "plan_evidence", path)] += 1
    final = _latest_terminal_events(event_list)["latest"]
    terminal_plans: set[str] = set()
    for plan_id, event in final.items():
        if event["event_type"] in {"execution.completed", "execution.rejected"}:
            no_submit = plans.get(plan_id, {}).get("semantic_action") == "no_submit_evidence"
            evidence_root = (
                _no_submit_evidence_root(plans.get(plan_id), event["payload"])
                if no_submit
                else event["payload"].get("evidence_root")
            )
            references: list[tuple[str, Any]] = []
            if not no_submit:
                references.append(("response", event["payload"].get("response_path")))
            if not no_submit or evidence_root:
                terminal_plans.add(plan_id)
                references.append(("execution_evidence", evidence_root))
            for kind, value in references:
                path = relative(value)
                if path is None:
                    return None
                expected[(plan_id, kind, path)] += 1
    return expected, terminal_plans


def _evidence_manifest_gate(
    events: Iterable[dict[str, Any]], root: Path, source_root: str | Path | None
) -> dict[str, Any]:
    """Require a complete schema-3 manifest to cover terminal evidence exactly."""

    manifest, error = _read_evidence_manifest(root)
    if manifest is None:
        return _readiness_gate(False, error or "evidence_manifest_invalid")
    if manifest.get("schema_version") != "3":
        return _readiness_gate(False, "evidence_manifest_schema_invalid")
    references = manifest.get("references")
    if not isinstance(references, list) or len(references) > MAX_EVIDENCE_MANIFEST_REFERENCES:
        return _readiness_gate(False, "evidence_manifest_invalid")
    files, files_error = _manifest_file_table(manifest)
    if files is None:
        return _readiness_gate(False, files_error or "evidence_manifest_files_invalid")
    checked_files: dict[str, tuple[int, str]] = {}
    for relative, expected_file in files.items():
        actual_file, actual_error = _read_manifest_file(
            root, _manifest_relative_parts(relative) or ()
        )
        if actual_file is None:
            return _readiness_gate(
                False, actual_error or "evidence_manifest_reference_unreadable"
            )
        if actual_file != expected_file:
            return _readiness_gate(False, "evidence_manifest_file_hash_mismatch")
        checked_files[relative] = actual_file
    expected_result = _expected_required_evidence(events, root, source_root)
    if expected_result is None:
        return _readiness_gate(False, "evidence_references_incomplete")
    expected, terminal_plans = expected_result
    no_submit_plans = {
        event["payload"].get("plan_id")
        for event in events
        if event["event_type"] == "execution.planned"
        and event["payload"].get("semantic_action") == "no_submit_evidence"
    }
    required: list[dict[str, Any]] = []
    all_required: list[dict[str, Any]] = []
    observed_counts: Counter[tuple[str, str, str]] = Counter()
    observed_terminal_plans: set[str] = set()
    statuses: Counter[str] = Counter()
    for reference in references:
        if not isinstance(reference, dict):
            return _readiness_gate(False, "evidence_manifest_invalid")
        required_flag = reference.get("required")
        manifest_status = reference.get("status")
        kind = reference.get("kind")
        plan_id = reference.get("plan_id")
        if not isinstance(required_flag, bool) or not isinstance(manifest_status, str):
            return _readiness_gate(False, "evidence_manifest_invalid")
        if manifest_status not in EVIDENCE_REFERENCE_STATUSES:
            return _readiness_gate(False, "evidence_manifest_invalid")
        if required_flag:
            if kind not in {"plan_evidence", "response", "execution_evidence"}:
                return _readiness_gate(False, "evidence_manifest_invalid")
            if not isinstance(plan_id, str) or not plan_id:
                return _readiness_gate(False, "evidence_manifest_invalid")
            path = reference.get("path")
            resolved_status, resolved = resolve_evidence_path(root, path, None)
            if resolved_status == "empty":
                relative_path = ""
            elif resolved is None:
                return _readiness_gate(False, "evidence_manifest_reference_invalid")
            else:
                try:
                    relative_path = resolved.relative_to(root.resolve()).as_posix()
                except ValueError:
                    return _readiness_gate(False, "evidence_manifest_reference_invalid")
            all_required.append(reference)
            if kind == "response" and plan_id in no_submit_plans:
                return _readiness_gate(
                    False, "evidence_manifest_no_submit_response_not_applicable"
                )
            required.append(reference)
            observed_counts[(plan_id, str(kind), relative_path)] += 1
            statuses[manifest_status] += 1
            if kind in {"response", "execution_evidence"}:
                observed_terminal_plans.add(plan_id)
    required_counts = manifest.get("required_reference_counts")
    required_count = manifest.get("required_reference_count")
    if (
        not _is_int(required_count)
        or required_count != len(all_required)
        or not isinstance(required_counts, dict)
        or any(required_counts.get(status) != statuses[status] for status in EVIDENCE_REFERENCE_STATUSES)
    ):
        return _readiness_gate(False, "evidence_manifest_counts_invalid")
    if not required or not expected:
        return _readiness_gate(False, "evidence_required_references_absent")
    if manifest.get("truncated") is not False or manifest.get("complete") is not True:
        return _readiness_gate(False, "evidence_manifest_incomplete")
    if any(status not in EVIDENCE_PRESENT_STATUSES for status in statuses):
        return _readiness_gate(False, "evidence_manifest_incomplete")
    if observed_counts != expected or observed_terminal_plans != terminal_plans:
        return _readiness_gate(False, "evidence_manifest_terminal_coverage_incomplete")
    checked_directories: dict[str, dict[str, tuple[int, str]]] = {}
    for reference in required:
        relative = reference["path"]
        parts = _manifest_relative_parts(relative)
        if parts is None:
            return _readiness_gate(False, "evidence_manifest_reference_invalid")
        status = reference["status"]
        if status == "present_file":
            expected_file = files.get(relative)
            if expected_file is None:
                return _readiness_gate(False, "evidence_manifest_file_missing")
            actual = checked_files.get(relative)
            if actual != expected_file:
                return _readiness_gate(False, "evidence_manifest_file_hash_mismatch")
        elif status == "present_directory":
            expected_directory = {
                path: item
                for path, item in files.items()
                if path.startswith(relative + "/")
            }
            actual_directory = checked_directories.get(relative)
            if actual_directory is None:
                actual_directory, actual_error = _manifest_directory_files(root, parts)
                if actual_directory is None:
                    return _readiness_gate(
                        False, actual_error or "evidence_manifest_reference_unreadable"
                    )
                checked_directories[relative] = actual_directory
            if actual_directory != expected_directory:
                return _readiness_gate(False, "evidence_manifest_directory_hash_mismatch")

    planned_by_id = {
        event["payload"].get("plan_id"): event["payload"]
        for event in events
        if event["event_type"] == "execution.planned"
        and isinstance(event["payload"].get("plan_id"), str)
    }
    final_by_plan = _latest_terminal_events(events)["latest"]
    for plan_id in no_submit_plans:
        plan = planned_by_id.get(plan_id)
        envelope = plan.get("envelope") if isinstance(plan, dict) else None
        artifact_reference = (
            envelope.get("artifact_reference") if isinstance(envelope, dict) else None
        )
        if artifact_reference == "":
            terminal = final_by_plan.get(plan_id)
            if (
                terminal is None
                or terminal["payload"].get("evidence_root") != ""
                or not isinstance(plan, dict)
                or not sealed_plan_file_matches(root, plan)
            ):
                return _readiness_gate(
                    False, "evidence_manifest_no_submit_sealed_plan_mismatch"
                )
            continue
        artifact_status, artifact_path = resolve_evidence_path(
            root, artifact_reference, source_root
        )
        if artifact_status != "present" or artifact_path is None:
            return _readiness_gate(False, "evidence_manifest_no_submit_artifact_missing")
        try:
            artifact_relative = artifact_path.relative_to(root.resolve()).as_posix()
        except ValueError:
            return _readiness_gate(False, "evidence_manifest_no_submit_artifact_missing")
        if artifact_relative not in files:
            return _readiness_gate(False, "evidence_manifest_no_submit_artifact_missing")
        artifact_reference_present = any(
            reference.get("plan_id") == plan_id
            and reference.get("kind") == "plan_evidence"
            and reference.get("status") == "present_file"
            and reference.get("path") == artifact_relative
            for reference in required
        )
        terminal_root_present = any(
            reference.get("plan_id") == plan_id
            and reference.get("kind") == "execution_evidence"
            and (
                (
                    reference.get("status") == "present_file"
                    and reference.get("path") == artifact_relative
                )
                or (
                    reference.get("status") == "present_directory"
                    and isinstance(reference.get("path"), str)
                    and artifact_relative.startswith(reference["path"] + "/")
                )
            )
            for reference in required
        )
        if plan_id not in final_by_plan or not (
            artifact_reference_present or terminal_root_present
        ):
            return _readiness_gate(False, "evidence_manifest_no_submit_artifact_unjoined")
    gate = _readiness_gate(True)
    gate["required_reference_count"] = len(required)
    gate["required_terminal_objective_count"] = len(terminal_plans)
    return gate


def _safe_runtime_path(root: Path, value: Any, source_root: str | Path | None) -> Path | None:
    status, path = resolve_evidence_path(root, value, source_root)
    return path if status == "present" else None


def _sha256_file(path: Path) -> str | None:
    digest = hashlib.sha256()
    try:
        if path.stat().st_size > MAX_HASH_FILE_BYTES:
            return None
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(STREAM_CHUNK_BYTES), b""):
                digest.update(chunk)
    except OSError:
        return None
    return digest.hexdigest()


def _valid_sha256(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(character in "0123456789abcdef" for character in value.lower())


def _v2_envelope_valid(meta: dict[str, Any]) -> bool:
    command = meta.get("command")
    return (
        meta.get("schema_version") == "2"
        and meta.get("complete") is True
        and isinstance(command, list)
        and len(command) <= 1_000
        and all(isinstance(argument, str) and len(argument) <= 8_192 for argument in command)
        and _valid_sha256(meta.get("argv_sha256"))
        and _is_int(meta.get("exit_code"))
        and isinstance(meta.get("termination"), str)
        and _is_int(meta.get("stdout_bytes"))
        and _is_int(meta.get("stderr_bytes"))
        and meta.get("stdout_bytes", -1) >= 0
        and meta.get("stderr_bytes", -1) >= 0
        and isinstance(meta.get("stdout_path"), str)
        and isinstance(meta.get("stderr_path"), str)
        and _valid_sha256(meta.get("stdout_sha256"))
        and _valid_sha256(meta.get("stderr_sha256"))
    )


def _digest_valid(digest: dict[str, Any]) -> bool:
    """Accept only the bounded digest shapes emitted by command wrappers."""

    if not _is_int(digest.get("byte_count")) or digest.get("byte_count", -1) < 0:
        return False
    schema = digest.get("schema_version")
    if schema == "2":
        stderr = digest.get("stderr")
        return (
            digest.get("complete") is True
            and _valid_sha256(digest.get("sha256"))
            and isinstance(stderr, dict)
            and _is_int(stderr.get("byte_count"))
            and stderr.get("byte_count", -1) >= 0
            and _valid_sha256(stderr.get("sha256"))
        )
    stderr = digest.get("stderr")
    return not isinstance(stderr, dict) or (
        _is_int(stderr.get("byte_count")) and stderr.get("byte_count", -1) >= 0
    )


def _verify_v2_hashes(
    root: Path, meta: dict[str, Any], source_root: str | Path | None
) -> str:
    command = meta["command"]
    expected_argv = hashlib.sha256(canonical_json(command).encode("utf-8")).hexdigest()
    if expected_argv != meta["argv_sha256"]:
        return "invalid"
    for output_key, bytes_key, hash_key in (
        ("stdout_path", "stdout_bytes", "stdout_sha256"),
        ("stderr_path", "stderr_bytes", "stderr_sha256"),
    ):
        if meta[bytes_key] > MAX_HASH_FILE_BYTES:
            return "oversized"
        path = _safe_runtime_path(root, meta[output_key], source_root)
        if path is None:
            return "missing"
        try:
            if path.stat().st_size != meta[bytes_key]:
                return "invalid"
        except OSError:
            return "missing"
        if _sha256_file(path) != meta[hash_key]:
            return "invalid"
    return "verified"


def summarize_command_logs(
    root: Path,
    source_root: str | Path | None,
    events: Iterable[dict[str, Any]],
) -> dict[str, Any]:
    """Summarize command envelopes without returning argv, output, or digest previews."""

    base = root / "logs" / "commands"
    summary: dict[str, Any] = {
        "scan": {
            "availability": "not_available",
            "reason": "command_log_directory_absent",
        },
        "directories": 0,
        "meta": {"valid": 0, "missing": 0, "invalid": 0},
        "digest": {"valid": 0, "missing": 0, "invalid": 0},
        "schema_versions": {},
        "exit_codes": {},
        "termination_counts": {},
        "output_bytes": {"stdout": 0, "stderr": 0, "total": 0},
        "v2_hashes": {"verified": 0, "missing": 0, "invalid": 0},
    }
    summary["v2_hashes"]["oversized"] = 0
    envelope_ids: set[str] = set()
    metadata_bytes = 0
    base = _inside_runtime(root, base)
    if base is None:
        summary["scan_error"] = True
        summary["scan"] = {
            "availability": "not_available",
            "reason": "command_log_directory_outside_runtime",
        }
        return summary
    if not base.is_dir():
        return summary
    summary["scan"] = {"availability": "available"}
    try:
        directories = base.iterdir()
    except OSError:
        summary["scan_error"] = True
        summary["scan"] = {
            "availability": "not_available",
            "reason": "command_log_scan_failed",
        }
        return summary
    for directory in directories:
        if summary["directories"] >= MAX_COMMAND_DIRECTORIES:
            summary["truncated"] = True
            break
        safe_directory = _inside_runtime(root, directory)
        if safe_directory is None or not safe_directory.is_dir():
            summary["directories"] += 1
            summary["meta"]["invalid"] += 1
            summary["digest"]["invalid"] += 1
            continue
        directory = safe_directory
        summary["directories"] += 1
        meta_path = _inside_runtime(root, directory / "meta.json")
        digest_path = _inside_runtime(root, directory / "digest.json")
        try:
            metadata_bytes += sum(
                path.stat().st_size
                for path in (meta_path, digest_path)
                if path is not None and path.exists()
            )
        except OSError:
            summary["scan_error"] = True
            break
        if metadata_bytes > MAX_COMMAND_METADATA_BYTES:
            summary["truncated"] = True
            break
        meta, meta_error = _bounded_json_object(meta_path) if meta_path else (None, "invalid")
        digest, digest_error = _bounded_json_object(digest_path) if digest_path else (None, "invalid")
        if digest is None:
            summary["digest"]["missing" if digest_error == "invalid" and digest_path is not None and not digest_path.exists() else "invalid"] += 1
        elif not _digest_valid(digest):
            summary["digest"]["invalid"] += 1
        else:
            summary["digest"]["valid"] += 1
        if meta is None:
            summary["meta"]["missing" if meta_error == "invalid" and meta_path is not None and not meta_path.exists() else "invalid"] += 1
            continue
        command_id = meta.get("command_id")
        if isinstance(command_id, str) and command_id:
            envelope_ids.add(command_id)
        schema = str(meta.get("schema_version", "legacy"))
        summary["schema_versions"][schema] = summary["schema_versions"].get(schema, 0) + 1
        if meta.get("schema_version") == "2":
            if not _v2_envelope_valid(meta):
                summary["meta"]["invalid"] += 1
                summary["v2_hashes"]["invalid"] += 1
                continue
            summary["meta"]["valid"] += 1
            verification = _verify_v2_hashes(root, meta, source_root)
            summary["v2_hashes"][verification] += 1
        elif _is_int(meta.get("exit_code")):
            summary["meta"]["valid"] += 1
        else:
            summary["meta"]["invalid"] += 1
            continue
        exit_code = str(meta["exit_code"])
        summary["exit_codes"][exit_code] = summary["exit_codes"].get(exit_code, 0) + 1
        termination = str(meta.get("termination", "unknown"))
        summary["termination_counts"][termination] = summary["termination_counts"].get(termination, 0) + 1
        stdout_bytes = meta.get("stdout_bytes")
        stderr_bytes = meta.get("stderr_bytes")
        if not _is_int(stdout_bytes) and isinstance(digest, dict) and _digest_valid(digest):
            stdout_bytes = digest.get("byte_count")
        if (
            not _is_int(stderr_bytes)
            and isinstance(digest, dict)
            and _digest_valid(digest)
            and isinstance(digest.get("stderr"), dict)
        ):
            stderr_bytes = digest["stderr"].get("byte_count")
        for name, value in (("stdout", stdout_bytes), ("stderr", stderr_bytes)):
            if _is_int(value) and value >= 0:
                summary["output_bytes"][name] += value
                summary["output_bytes"]["total"] += value
    requested_events = [
        str(event["payload"]["command_id"])
        for event in events
        if event["event_type"] == "command.requested"
        and isinstance(event["payload"].get("command_id"), str)
        and event["payload"]["command_id"]
    ]
    completed_events = [
        str(event["payload"]["command_id"])
        for event in events
        if event["event_type"] == "command.completed"
        and isinstance(event["payload"].get("command_id"), str)
        and event["payload"]["command_id"]
    ]
    requested_ids = set(requested_events)
    completed_ids = set(completed_events)
    event_ids = requested_ids | completed_ids
    if summary.get("scan_error"):
        summary["scan"] = {
            "availability": "not_available",
            "reason": "command_log_scan_failed",
        }
    elif summary.get("truncated"):
        summary["scan"] = {
            "availability": "not_available",
            "reason": "command_log_scan_truncated",
        }
    summary["lifecycle"] = {
        "requested": len(requested_ids),
        "completed": len(completed_ids),
        "requested_event_count": len(requested_events),
        "completed_event_count": len(completed_events),
        "duplicate_requested_events": len(requested_events) - len(requested_ids),
        "duplicate_completed_events": len(completed_events) - len(completed_ids),
        "paired_events": len(requested_ids & completed_ids),
        "requested_only": len(requested_ids - completed_ids),
        "completed_only": len(completed_ids - requested_ids),
        "envelopes": len(envelope_ids),
        "envelopes_with_events": len(envelope_ids & event_ids),
        "envelope_only": len(envelope_ids - event_ids),
        "event_only": len(event_ids - envelope_ids),
    }
    return summary


def _iter_safe_files(base: Path) -> Iterable[Path]:
    """Yield regular files whose resolved locations remain under ``base``."""

    resolved_base = base.resolve()
    seen = 0
    for directory, _subdirectories, names in os.walk(base, followlinks=False):
        for name in names:
            if seen >= MAX_SUMMARY_FILES:
                return
            candidate = Path(directory) / name
            try:
                resolved = candidate.resolve(strict=False)
                resolved.relative_to(resolved_base)
                if not resolved.is_file():
                    continue
            except (OSError, ValueError):
                continue
            seen += 1
            yield resolved


def summarize_files(root: Path, base: Path) -> dict[str, int | bool]:
    """Count files, bytes, and lines using fixed-size reads only."""

    summary: dict[str, int | bool] = {"files": 0, "bytes": 0, "lines": 0, "unreadable": 0, "truncated": False}
    base = _inside_runtime(root, base)
    if base is None:
        summary["unreadable"] = 1
        return summary
    if not base.is_dir():
        return summary
    for path in _iter_safe_files(base):
        if int(summary["files"]) >= MAX_SUMMARY_FILES:
            summary["truncated"] = True
            break
        try:
            size = path.stat().st_size
            if int(summary["bytes"]) + size > MAX_SUMMARY_BYTES:
                summary["truncated"] = True
                break
            byte_count = 0
            line_count = 0
            final_byte = b""
            with path.open("rb") as handle:
                for chunk in iter(lambda: handle.read(STREAM_CHUNK_BYTES), b""):
                    byte_count += len(chunk)
                    line_count += chunk.count(b"\n")
                    final_byte = chunk[-1:]
            if byte_count and final_byte != b"\n":
                line_count += 1
            summary["files"] = int(summary["files"]) + 1
            summary["bytes"] = int(summary["bytes"]) + byte_count
            summary["lines"] = int(summary["lines"]) + line_count
        except OSError:
            summary["unreadable"] = int(summary["unreadable"]) + 1
    return summary


def summarize_queue_normalized_rates(
    queue_watch: dict[str, int | bool], event_window: dict[str, Any]
) -> dict[str, Any]:
    """Normalize observed queue-watch bytes and lines only with real denominators."""

    if queue_watch.get("truncated") or queue_watch.get("unreadable"):
        return {"availability": "not_available", "reason": "queue_watch_summary_incomplete"}
    files = queue_watch.get("files")
    events = event_window.get("denominator_events")
    duration = event_window.get("duration_seconds")
    if not _is_int(files) or files <= 0:
        return {"availability": "not_available", "reason": "queue_watch_files_absent"}
    if not _is_int(events) or events <= 0:
        return {"availability": "not_available", "reason": "canonical_event_denominator_unavailable"}
    if _numeric(duration) is None or float(duration) <= 0:
        return {"availability": "not_available", "reason": "event_duration_unavailable"}
    bytes_value = queue_watch.get("bytes")
    lines_value = queue_watch.get("lines")
    if not _is_int(bytes_value) or not _is_int(lines_value):
        return {"availability": "not_available", "reason": "queue_watch_summary_invalid"}
    hours = float(duration) / 3600
    return {
        "availability": "available",
        "canonical_event_denominator": events,
        "event_hour_denominator": hours,
        "bytes_per_canonical_event": bytes_value / events,
        "lines_per_canonical_event": lines_value / events,
        "bytes_per_event_hour": bytes_value / hours,
        "lines_per_event_hour": lines_value / hours,
    }


def _parse_utc(value: Any) -> dt.datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(dt.timezone.utc)


def _utc_text(value: dt.datetime) -> str:
    return value.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _numeric(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    numeric = float(value)
    return numeric if math.isfinite(numeric) and numeric >= 0 else None


def _metric_values(
    resources: Iterable[dict[str, Any]], key: str
) -> tuple[list[float], int]:
    """Return valid non-negative metric values and explicit invalid-field count."""

    values: list[float] = []
    invalid = 0
    for resource in resources:
        if key not in resource:
            continue
        value = _numeric(resource[key])
        if value is None:
            invalid += 1
        else:
            values.append(value)
    return values, invalid


def _percentile(values: list[float], fraction: float) -> float:
    """Return a deterministic linearly interpolated percentile for non-empty values."""

    ordered = sorted(values)
    position = (len(ordered) - 1) * fraction
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def _aggregate(values: list[float]) -> dict[str, float | int]:
    return {
        "count": len(values),
        "sum": sum(values),
        "min": min(values),
        "max": max(values),
        "mean": sum(values) / len(values),
        "p50": _percentile(values, 0.50),
        "p95": _percentile(values, 0.95),
    }


def _outcome_name(event: dict[str, Any]) -> str:
    payload = event["payload"]
    if event["event_type"] == "execution.indeterminate":
        return "indeterminate"
    verdict = payload.get("verdict")
    if isinstance(verdict, dict) and isinstance(verdict.get("verdict"), str):
        return verdict["verdict"]
    if isinstance(payload.get("status"), str):
        return payload["status"]
    return event["event_type"].rsplit(".", 1)[-1]


def _latest_terminal_events(events: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Select one latest terminal state per plan without inferring identifiers."""

    latest: dict[str, dict[str, Any]] = {}
    unkeyed: list[dict[str, Any]] = []
    terminal_event_count = 0
    duplicate_terminal_transitions = 0
    terminal_events_missing_plan_id = 0
    terminal_events_missing_proposal_id = 0
    for event in events:
        if event["event_type"] not in EXECUTION_TERMINAL_TYPES:
            continue
        terminal_event_count += 1
        plan_id = event["payload"].get("plan_id")
        proposal_id = event["payload"].get("proposal_id")
        if not isinstance(proposal_id, str) or not proposal_id:
            terminal_events_missing_proposal_id += 1
        if not isinstance(plan_id, str) or not plan_id:
            terminal_events_missing_plan_id += 1
            unkeyed.append(event)
            continue
        previous = latest.get(plan_id)
        if previous is not None:
            duplicate_terminal_transitions += 1
        if previous is None or event["seq"] >= previous["seq"]:
            latest[plan_id] = event
    final_events = sorted(
        [*latest.values(), *unkeyed],
        key=lambda event: (event["seq"], event["event_id"]),
    )
    return {
        "latest": latest,
        "final_events": final_events,
        "terminal_event_count": terminal_event_count,
        "duplicate_terminal_transitions": duplicate_terminal_transitions,
        "terminal_events_missing_plan_id": terminal_events_missing_plan_id,
        "terminal_events_missing_proposal_id": terminal_events_missing_proposal_id,
    }


def _terminal_job_states(events: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Reduce job terminals to one final state per stable job identifier."""

    latest: dict[str, dict[str, Any]] = {}
    missing_identifiers = 0
    forbidden_conflicts: set[str] = set()
    transition_count = 0
    for event in events:
        if event["event_type"] not in JOB_TERMINAL_TYPES:
            continue
        transition_count += 1
        job_id = event["payload"].get("job_id")
        if not isinstance(job_id, str) or not job_id or len(job_id) > 512:
            missing_identifiers += 1
            continue
        previous = latest.get(job_id)
        if (
            previous is not None
            and previous["event_type"] in JOB_IRREVOCABLE_TERMINAL_TYPES
            and event["event_type"] != previous["event_type"]
        ):
            forbidden_conflicts.add(job_id)
        if previous is None or event["seq"] >= previous["seq"]:
            latest[job_id] = event
    final = sorted(latest.values(), key=lambda event: (event["seq"], event["event_id"]))
    return {
        "final": final,
        "transition_count": transition_count,
        "missing_identifiers": missing_identifiers,
        "forbidden_conflicts": len(forbidden_conflicts),
        "final_state_counts": dict(
            sorted(Counter(event["event_type"].rsplit(".", 1)[-1] for event in final).items())
        ),
    }


def _plan_events(events: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Count explicit plan events without inferring plan identity from proposals."""

    latest: dict[str, dict[str, Any]] = {}
    plan_event_denominator = 0
    duplicate_plan_events = 0
    plan_events_missing_plan_id = 0
    for event in events:
        if event["event_type"] != "execution.planned":
            continue
        plan_event_denominator += 1
        plan_id = event["payload"].get("plan_id")
        if not isinstance(plan_id, str) or not plan_id:
            plan_events_missing_plan_id += 1
            continue
        previous = latest.get(plan_id)
        if previous is not None:
            duplicate_plan_events += 1
        if previous is None or event["seq"] >= previous["seq"]:
            latest[plan_id] = event
    return {
        "latest": latest,
        "plan_event_denominator": plan_event_denominator,
        "duplicate_plan_events": duplicate_plan_events,
        "plan_events_missing_plan_id": plan_events_missing_plan_id,
    }


def _valid_retry_fingerprint(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _terminal_retry_fingerprint(event: dict[str, Any]) -> str | None:
    """Return a declared retry fingerprint only from retry-capable terminals."""

    if event["event_type"] not in {
        "execution.rejected",
        "execution.indeterminate",
    }:
        return None
    payload = event["payload"]
    for key in ("retry", "rejection"):
        metadata = payload.get(key)
        fingerprint = metadata.get("fingerprint") if isinstance(metadata, dict) else None
        if _valid_retry_fingerprint(fingerprint):
            return fingerprint
    return None


def summarize_scoring_proposal_retry_lineage(
    events: Iterable[dict[str, Any]],
) -> dict[str, Any]:
    """Join follow-up proposals to earlier rejected or indeterminate terminals."""

    proposal_denominator = 0
    proposals_with_parent_fingerprint = 0
    proposals_missing_parent_fingerprint = 0
    proposals_with_invalid_parent_fingerprint = 0
    proposals_missing_discriminator = 0
    proposals_with_valid_parent_lineage = 0
    proposals_with_known_parent_fingerprint = 0
    proposals_with_unknown_parent_fingerprint = 0
    same_candidate_follow_ups = 0
    changed_candidate_follow_ups = 0
    event_list = list(events)
    known_parents: dict[str, tuple[str, str, int]] = {}
    for event in event_list:
        fingerprint = _terminal_retry_fingerprint(event)
        retry = event["payload"].get("retry")
        if fingerprint is not None and isinstance(retry, dict):
            known_parents[fingerprint] = (
                str(retry.get("candidate_identity_sha256") or ""),
                str(event["payload"].get("objective_id") or ""),
                event["seq"],
            )
    parent_uses: Counter[str] = Counter()
    for event in event_list:
        if event["event_type"] != "proposal.created":
            continue
        proposal_denominator += 1
        payload = event["payload"]
        parent = payload.get("parent_rejection_fingerprint")
        discriminator = payload.get("discriminator")
        if not isinstance(parent, str) or not parent:
            proposals_missing_parent_fingerprint += 1
            continue
        proposals_with_parent_fingerprint += 1
        if not _valid_retry_fingerprint(parent):
            proposals_with_invalid_parent_fingerprint += 1
            continue
        if not isinstance(discriminator, str) or not discriminator.strip():
            proposals_missing_discriminator += 1
            continue
        parent_uses[parent] += 1
        parent_info = known_parents.get(parent)
        matching_parent_fingerprints = {
            fingerprint
            for fingerprint, info in known_parents.items()
            if info[0] == str(payload.get("candidate_identity_sha256") or "")
            and info[2] < event["seq"]
        }
        if (
            parent_info is not None
            and parent_info[2] < event["seq"]
            and parent_info[1] == str(payload.get("objective_id") or "")
            and parent_uses[parent] == 1
            and (
                not matching_parent_fingerprints
                or parent in matching_parent_fingerprints
            )
        ):
            proposals_with_valid_parent_lineage += 1
            proposals_with_known_parent_fingerprint += 1
            if parent_info[0] == str(payload.get("candidate_identity_sha256") or ""):
                same_candidate_follow_ups += 1
            else:
                changed_candidate_follow_ups += 1
        else:
            proposals_with_unknown_parent_fingerprint += 1
    result: dict[str, Any] = {
        "availability": "available" if proposal_denominator else "not_available",
        "proposal_denominator": proposal_denominator,
        "proposals_with_parent_fingerprint": proposals_with_parent_fingerprint,
        "proposals_missing_parent_fingerprint": proposals_missing_parent_fingerprint,
        "proposals_with_invalid_parent_fingerprint": proposals_with_invalid_parent_fingerprint,
        "proposals_missing_discriminator": proposals_missing_discriminator,
        "proposals_with_valid_parent_lineage": proposals_with_valid_parent_lineage,
        "proposals_with_known_parent_fingerprint": proposals_with_known_parent_fingerprint,
        "proposals_with_unknown_parent_fingerprint": proposals_with_unknown_parent_fingerprint,
        "same_candidate_follow_up_denominator": same_candidate_follow_ups,
        "changed_candidate_follow_up_denominator": changed_candidate_follow_ups,
        "known_terminal_parent_fingerprint_denominator": len(
            known_parents
        ),
    }
    if not proposal_denominator:
        result["reason"] = "proposal_events_absent"
    return result


def summarize_measurement(events: list[dict[str, Any]]) -> dict[str, Any]:
    """Derive bounded, privacy-safe measurement aggregates from canonical events."""

    event_times = [_parse_utc(event["created_at"]) for event in events]
    valid_event_times = [value for value in event_times if value is not None]
    if valid_event_times:
        first = min(valid_event_times)
        last = max(valid_event_times)
        event_window: dict[str, Any] = {
            "availability": "available",
            "denominator_events": len(events),
            "events_with_valid_utc": len(valid_event_times),
            "first_utc": _utc_text(first),
            "last_utc": _utc_text(last),
            "duration_seconds": (last - first).total_seconds(),
        }
    else:
        event_window = {
            "availability": "not_available",
            "reason": "valid_event_timestamps_absent",
            "denominator_events": len(events),
            "events_with_valid_utc": 0,
        }

    proposals: dict[str, dict[str, Any]] = {}
    proposal_events = 0
    duplicate_proposal_events = 0
    proposal_events_missing_proposal_id = 0
    for event in events:
        payload = event["payload"]
        if event["event_type"] == "proposal.created":
            proposal_events += 1
            proposal_id = payload.get("proposal_id")
            if not isinstance(proposal_id, str) or not proposal_id:
                proposal_events_missing_proposal_id += 1
                continue
            previous = proposals.get(proposal_id)
            if previous is not None:
                duplicate_proposal_events += 1
            if previous is None or event["seq"] >= previous["seq"]:
                proposals[proposal_id] = event

    plan_summary = _plan_events(events)
    terminal_summary = _latest_terminal_events(events)
    terminals = terminal_summary["final_events"]
    latency_by_outcome: dict[str, dict[str, Any]] = {}
    matched_proposals: set[str] = set()
    matched_plans: set[str] = set()
    matched_terminal_events = 0
    final_terminal_proposals: set[str] = set()
    all_latency_values: list[float] = []
    for terminal in terminals:
        outcome = _outcome_name(terminal)
        bucket = latency_by_outcome.setdefault(
            outcome,
            {"terminal_denominator": 0, "matched": 0, "unmatched": 0, "latency_seconds": []},
        )
        bucket["terminal_denominator"] += 1
        plan_id = terminal["payload"].get("plan_id")
        proposal_id = terminal["payload"].get("proposal_id")
        if isinstance(proposal_id, str) and proposal_id:
            final_terminal_proposals.add(proposal_id)
        terminal_time = _parse_utc(terminal["created_at"])
        proposal = proposals.get(proposal_id) if isinstance(proposal_id, str) else None
        proposal_time = _parse_utc(proposal["created_at"]) if proposal is not None else None
        if proposal_time is None or terminal_time is None or terminal_time < proposal_time:
            bucket["unmatched"] += 1
            continue
        bucket["matched"] += 1
        matched_proposals.add(proposal_id)
        matched_terminal_events += 1
        if isinstance(plan_id, str) and plan_id:
            matched_plans.add(plan_id)
        latency_value = (terminal_time - proposal_time).total_seconds()
        bucket["latency_seconds"].append(latency_value)
        all_latency_values.append(latency_value)
    for bucket in latency_by_outcome.values():
        values = bucket.pop("latency_seconds")
        if values:
            bucket["latency_seconds"] = _aggregate(values)
        else:
            bucket["latency_seconds"] = {"availability": "not_available", "reason": "no_matched_timestamps"}
    latency: dict[str, Any] = {
        "availability": "available" if proposals or terminals else "not_available",
        "scope": "per_proposal_event",
        "entity_scope": "per_final_plan_joined_to_proposal",
        "proposal_event_denominator": proposal_events,
        "unique_proposal_denominator": len(proposals),
        "duplicate_proposal_events": duplicate_proposal_events,
        "proposal_events_missing_proposal_id": proposal_events_missing_proposal_id,
        "plan_event_denominator": plan_summary["plan_event_denominator"],
        "unique_plan_denominator": len(terminal_summary["latest"]),
        "planned_unique_plan_denominator": len(plan_summary["latest"]),
        "duplicate_plan_events": plan_summary["duplicate_plan_events"],
        "plan_events_missing_plan_id": plan_summary["plan_events_missing_plan_id"],
        "terminal_event_count": terminal_summary["terminal_event_count"],
        "terminal_denominator": len(terminals),
        "unique_final_plan_denominator": len(terminal_summary["latest"]),
        "duplicate_terminal_transitions": terminal_summary["duplicate_terminal_transitions"],
        "duplicate_terminal_events": terminal_summary["duplicate_terminal_transitions"],
        "terminal_events_missing_plan_id": terminal_summary["terminal_events_missing_plan_id"],
        "terminal_events_missing_proposal_id": terminal_summary["terminal_events_missing_proposal_id"],
        "proposals_missing_terminal_state": len(set(proposals) - final_terminal_proposals),
        "matched_proposal_denominator": len(matched_proposals),
        "matched_plan_denominator": len(matched_plans),
        "matched_terminal_denominator": matched_terminal_events,
        "unmatched_proposals": max(0, len(proposals) - len(matched_proposals)),
        "unmatched_terminal_events": len(terminals) - matched_terminal_events,
        "by_outcome": dict(sorted(latency_by_outcome.items())),
        "quantile_method": "linear_interpolation",
    }
    if all_latency_values:
        latency["latency_seconds"] = _aggregate(all_latency_values)
    else:
        latency["latency_seconds"] = {
            "availability": "not_available",
            "reason": "no_matched_timestamps",
        }
    if not (proposal_events or terminal_summary["terminal_event_count"]):
        latency["reason"] = "proposal_or_terminal_events_absent"
    elif not (proposals or terminals):
        latency["reason"] = "proposal_or_terminal_identifiers_absent"

    objective_ranges: dict[str, tuple[dt.datetime, dt.datetime]] = {}
    terminal_events_with_objective = 0
    terminal_events_missing_objective = 0
    terminal_events_without_elapsed = 0
    for terminal in terminals:
        payload = terminal["payload"]
        plan_id = payload.get("plan_id")
        proposal_id = payload.get("proposal_id")
        plan = plan_summary["latest"].get(plan_id) if isinstance(plan_id, str) else None
        proposal = proposals.get(proposal_id) if isinstance(proposal_id, str) else None
        candidates = {
            value
            for value in (
                payload.get("objective_id"),
                plan["payload"].get("objective_id") if plan is not None else None,
                proposal["payload"].get("objective_id") if proposal is not None else None,
            )
            if isinstance(value, str) and value
        }
        if len(candidates) != 1:
            terminal_events_missing_objective += 1
            continue
        terminal_events_with_objective += 1
        objective_id = next(iter(candidates))
        started = _parse_utc(proposal["created_at"]) if proposal is not None else None
        finished = _parse_utc(terminal["created_at"])
        if started is None or finished is None or finished < started:
            terminal_events_without_elapsed += 1
            continue
        existing = objective_ranges.get(objective_id)
        if existing is None:
            objective_ranges[objective_id] = (started, finished)
        else:
            objective_ranges[objective_id] = (min(existing[0], started), max(existing[1], finished))
    objective_elapsed = [
        (finished - started).total_seconds()
        for started, finished in objective_ranges.values()
    ]
    per_objective: dict[str, Any] = {
        "availability": "available"
        if terminals
        and not terminal_events_missing_objective
        and not terminal_events_without_elapsed
        and objective_elapsed
        else "not_available",
        "terminal_denominator": len(terminals),
        "terminal_events_with_objective": terminal_events_with_objective,
        "terminal_events_missing_objective": terminal_events_missing_objective,
        "terminal_events_without_elapsed": terminal_events_without_elapsed,
        "objective_denominator": len(objective_ranges),
        "objectives_with_elapsed": len(objective_elapsed),
    }
    if per_objective["availability"] == "available":
        per_objective["elapsed_seconds"] = _aggregate(objective_elapsed)
    elif not terminals:
        per_objective["reason"] = "terminal_events_absent"
    elif terminal_events_missing_objective:
        per_objective["reason"] = "objective_identifiers_incomplete"
    else:
        per_objective["reason"] = "objective_elapsed_timestamps_incomplete"

    retry_events = [event for event in events if event["event_type"].startswith("retry.")]
    retry_ids = {str(event["payload"].get("retry_id")) for event in retry_events if event["payload"].get("retry_id")}
    typed_retries = [
        event
        for event in retry_events
        if event["payload"].get("parent_retry_id") or event["payload"].get("parent_proposal_id")
    ]
    known_lineages = sum(
        1
        for event in typed_retries
        if (
            event["payload"].get("parent_retry_id") in retry_ids
            or event["payload"].get("parent_proposal_id") in proposals
        )
    )
    scheduled_retry_lineage: dict[str, Any] = {
        "availability": "available" if typed_retries else "not_available",
        "denominator_retry_events": len(retry_events),
        "typed_parent_denominator": len(typed_retries),
        "numerator_with_known_parent": known_lineages,
    }
    if not retry_events:
        scheduled_retry_lineage["reason"] = "retry_events_absent"
    elif not typed_retries:
        scheduled_retry_lineage["reason"] = "typed_retry_parent_fields_not_emitted"
    scoring_proposal_retry_lineage = summarize_scoring_proposal_retry_lineage(events)

    stop_events = [event for event in events if event["event_type"] == "control.stop"]
    stop_generations: dict[int, dict[str, Any]] = {}
    for stop in stop_events:
        candidate = stop["payload"].get("generation", stop["generation"])
        generation = candidate if _is_int(candidate) else stop["generation"]
        started = _parse_utc(stop["payload"].get("requested_at")) or _parse_utc(stop["created_at"])
        existing = stop_generations.get(generation)
        if existing is None or stop["seq"] < existing["seq"]:
            stop_generations[generation] = {"seq": stop["seq"], "started": started}

    terminal_categories = {
        "agent.closed": "closed",
        "job.closed": "closed",
        "job.cancelled": "cancelled",
        "agent.unacknowledged": "unacknowledged",
        "job.unacknowledged": "unacknowledged",
        "agent.unmanaged": "unmanaged",
        "job.unmanaged": "unmanaged",
        "job.stale": "stale",
    }
    final_actor_states: dict[int, dict[str, dict[str, Any]]] = {
        generation: {} for generation in stop_generations
    }
    for terminal in events:
        category = terminal_categories.get(terminal["event_type"])
        generation = terminal["generation"]
        stop = stop_generations.get(generation)
        if category is None or stop is None or terminal["seq"] <= stop["seq"]:
            continue
        payload = terminal["payload"]
        actor_id = payload.get("agent_id") or payload.get("job_id")
        if not isinstance(actor_id, str) or not actor_id:
            continue
        actor_key = f"{terminal['event_type'].split('.', 1)[0]}:{actor_id}"
        previous = final_actor_states[generation].get(actor_key)
        if previous is None or terminal["seq"] >= previous["seq"]:
            final_actor_states[generation][actor_key] = terminal

    category_records: dict[str, set[tuple[int, str]]] = {
        "closed": set(),
        "cancelled": set(),
        "unacknowledged": set(),
        "unmanaged": set(),
        "stale": set(),
    }
    confirmed_generations: set[int] = set()
    complete_generations: set[int] = set()
    unacknowledged_generations: set[int] = set()
    unmanaged_generations: set[int] = set()
    stale_generations: set[int] = set()
    stop_durations: list[float] = []
    for generation, states in final_actor_states.items():
        categories: dict[str, list[dict[str, Any]]] = {
            "closed": [],
            "cancelled": [],
            "unacknowledged": [],
            "unmanaged": [],
            "stale": [],
        }
        for actor_key, terminal in states.items():
            category = terminal_categories[terminal["event_type"]]
            categories[category].append(terminal)
            category_records[category].add((generation, actor_key))
        confirmed = [*categories["closed"], *categories["cancelled"]]
        if confirmed:
            confirmed_generations.add(generation)
        if categories["unacknowledged"]:
            unacknowledged_generations.add(generation)
        if categories["unmanaged"]:
            unmanaged_generations.add(generation)
        if categories["stale"]:
            stale_generations.add(generation)
        # Unmanaged actors are outside the owned closure obligation, but an
        # unacknowledged owned actor means the generation is not reconciled.
        if not confirmed or categories["unacknowledged"] or categories["stale"]:
            continue
        complete_generations.add(generation)
        started = stop_generations[generation]["started"]
        finished = [
            _parse_utc(terminal["payload"].get("closed_at"))
            or _parse_utc(terminal["payload"].get("finished_at"))
            or _parse_utc(terminal["created_at"])
            for terminal in confirmed
        ]
        valid_finished = [value for value in finished if value is not None]
        if started is not None and valid_finished:
            last_finished = max(valid_finished)
            if last_finished >= started:
                stop_durations.append((last_finished - started).total_seconds())

    confirmed_actor_count = len(category_records["closed"] | category_records["cancelled"])
    stop_reconciliation: dict[str, Any] = {
        "availability": "available" if stop_durations else "not_available",
        "stop_denominator": len(stop_generations),
        "stop_event_denominator": len(stop_events),
        "stop_generation_denominator": len(stop_generations),
        "stops_with_confirmed_closure": len(confirmed_generations),
        "stops_with_terminal_closure": len(complete_generations),
        "stop_generations_with_unacknowledged": len(unacknowledged_generations),
        "stop_generations_with_unmanaged": len(unmanaged_generations),
        "stop_generations_with_stale": len(stale_generations),
        "confirmed_closure_actor_denominator": confirmed_actor_count,
        "unique_owned_actors_closed": confirmed_actor_count,
        "unique_closed_actors": len(category_records["closed"]),
        "unique_cancelled_actors": len(category_records["cancelled"]),
        "unique_unacknowledged_actors": len(category_records["unacknowledged"]),
        "unique_unmanaged_actors_terminal": len(category_records["unmanaged"]),
        "unique_stale_actors_terminal": len(category_records["stale"]),
    }
    if stop_durations:
        stop_reconciliation["duration_seconds"] = _aggregate(stop_durations)
    elif not stop_events:
        stop_reconciliation["reason"] = "stop_events_absent"
    elif not confirmed_actor_count:
        stop_reconciliation["reason"] = "confirmed_closure_events_absent"
    elif not complete_generations:
        stop_reconciliation["reason"] = "stop_reconciliation_incomplete"
    else:
        stop_reconciliation["reason"] = "confirmed_closure_timestamps_absent"

    queue_timing: dict[str, Any] = {
        "availability": "not_available",
        "reason": "canonical_queue_timing_events_not_emitted",
    }

    job_terminals = _terminal_job_states(events)
    terminal_jobs = job_terminals["final"]
    resource_summaries = [
        event["payload"].get("resource_summary")
        for event in terminal_jobs
        if isinstance(event["payload"].get("resource_summary"), dict)
    ]
    known_resource_fields = (
        *LOCAL_PROCESS_RESOURCE_FIELDS,
        *(field for field, _unit in PROVIDER_RESOURCE_FIELDS.values()),
    )
    invalid_resource_summaries = [
        resource
        for resource in resource_summaries
        if any(
            key in resource and _numeric(resource[key]) is None
            for key in known_resource_fields
        )
    ]
    owned_jobs = [
        event
        for event in terminal_jobs
        if event["payload"].get("owned") is True or event["payload"].get("owner_token")
    ]
    owned_resource_summaries = [
        event["payload"].get("resource_summary")
        for event in owned_jobs
        if isinstance(event["payload"].get("resource_summary"), dict)
    ]
    local_process_resources = [
        resource
        for resource in owned_resource_summaries
        if any(
            _numeric(resource.get(key)) is not None
            for key in LOCAL_PROCESS_RESOURCE_FIELDS
        )
    ]
    provider_resources = [
        resource
        for resource in resource_summaries
        if any(
            _numeric(resource.get(field)) is not None
            for field, _unit in PROVIDER_RESOURCE_FIELDS.values()
        )
    ]
    resources = [
        resource
        for resource in resource_summaries
        if any(
            _numeric(resource.get(key)) is not None
            for key in LOCAL_PROCESS_RESOURCE_FIELDS
        )
        or any(
            _numeric(resource.get(field)) is not None
            for field, _unit in PROVIDER_RESOURCE_FIELDS.values()
        )
    ]
    owned_with_resources = [
        event
        for event in owned_jobs
        if isinstance(event["payload"].get("resource_summary"), dict)
        and any(
            _numeric(event["payload"]["resource_summary"].get(key)) is not None
            for key in LOCAL_PROCESS_RESOURCE_FIELDS
        )
    ]

    def local_resource_field(key: str, unit: str) -> dict[str, Any]:
        present, invalid = _metric_values(owned_resource_summaries, key)
        return {
            "unit": unit,
            "denominator_owned_terminal_jobs": len(owned_jobs),
            "numerator_owned_terminal_jobs_with_field": len(present),
            "invalid_owned_terminal_jobs_with_field": invalid,
            "availability": "available" if present else "not_available",
            **(
                {"values": _aggregate(present)}
                if present
                else {
                    "reason": (
                        f"{key}_invalid_or_not_emitted"
                        if invalid
                        else f"{key}_not_emitted"
                    )
                }
            ),
        }

    def provider_field(key: str, unit: str) -> dict[str, Any]:
        present, invalid = _metric_values(resource_summaries, key)
        return {
            "source_field": key,
            "unit": unit,
            "denominator_terminal_jobs": len(terminal_jobs),
            "numerator_terminal_jobs_with_field": len(present),
            "invalid_terminal_jobs_with_field": invalid,
            "availability": "available" if present else "not_available",
            **(
                {"values": _aggregate(present)}
                if present
                else {
                    "reason": (
                        f"{key}_invalid_or_not_emitted"
                        if invalid
                        else f"{key}_not_emitted"
                    )
                }
            ),
        }

    local_process = {
        "availability": "available" if local_process_resources else "not_available",
        "owned_terminal_jobs_with_local_process_resource": len(local_process_resources),
        "cpu_seconds": local_resource_field("cpu_seconds", "seconds"),
        "rss_bytes": local_resource_field("rss_bytes", "bytes"),
        "peak_rss_bytes": local_resource_field("peak_rss_bytes", "bytes"),
    }
    provider = {
        name: provider_field(field, unit)
        for name, (field, unit) in PROVIDER_RESOURCE_FIELDS.items()
    }
    resource_measurement = {
        "terminal_job_transition_count": job_terminals["transition_count"],
        "terminal_jobs": len(terminal_jobs),
        "terminal_jobs_missing_stable_id": job_terminals["missing_identifiers"],
        "terminal_jobs_with_forbidden_state_conflict": job_terminals[
            "forbidden_conflicts"
        ],
        "final_terminal_job_state_counts": job_terminals["final_state_counts"],
        "terminal_jobs_with_resource": len(resources),
        "terminal_jobs_with_local_process_resource": len(local_process_resources),
        "terminal_jobs_with_provider_resource": len(provider_resources),
        "terminal_jobs_with_invalid_resource_metric": len(invalid_resource_summaries),
        "owned_coverage": {
            "denominator_owned_terminal_jobs": len(owned_jobs),
            "numerator_owned_terminal_jobs_with_local_process_resource": len(owned_with_resources),
            # Kept for report-schema compatibility; it is deliberately local
            # process coverage, never a provider-only resource summary.
            "numerator_owned_terminal_jobs_with_resource": len(owned_with_resources),
            "availability": "available" if owned_jobs else "not_available",
            **({} if owned_jobs else {"reason": "owned_terminal_jobs_absent"}),
        },
        "local_process": local_process,
        "provider": provider,
        "cpu_seconds": local_process["cpu_seconds"],
        "rss_bytes": local_process["rss_bytes"],
        "peak_rss_bytes": local_process["peak_rss_bytes"],
        "provider_queue": provider["queue"],
        "provider_tokens": provider["tokens"],
        "provider_usage": provider["usage"],
    }
    return {
        "event_window": event_window,
        "proposal_to_terminal_latency": latency,
        "proposal_to_final_latency": latency,
        "per_objective_elapsed_latency": per_objective,
        "scheduled_retry_lineage": scheduled_retry_lineage,
        "retry_lineage": scheduled_retry_lineage,
        "scoring_proposal_retry_lineage": scoring_proposal_retry_lineage,
        "stop_reconciliation": stop_reconciliation,
        "queue_timing": queue_timing,
        "resources": resource_measurement,
    }


def summarize_events(events: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate event families and lifecycle outcomes without reporting payload values."""

    events = list(events)
    plan_summary = _plan_events(events)
    terminal_summary = _latest_terminal_events(events)
    final_outcomes = Counter(
        _outcome_name(event)
        for event in terminal_summary["final_events"]
    )
    event_types: Counter[str] = Counter()
    families: Counter[str] = Counter()
    reviews: Counter[str] = Counter()
    outcomes: Counter[str] = Counter()
    agent_transitions: Counter[str] = Counter()
    job_transitions: Counter[str] = Counter()
    agent_attempt_ids: set[str] = set()
    proposal_attempt_links = 0
    outcome_attempt_links = 0
    terminal_attempt_ids: set[str] = set()
    outcome_attempt_ids: set[str] = set()
    terminal_jobs_with_resources = 0
    proposals = 0
    plans = 0
    stops = 0
    resumes = 0
    stopped = False
    post_stop_executions = 0
    post_stop_terminal_outcomes = 0
    post_stop_closures = Counter()
    closure_types = {
        "agent.closed",
        "agent.unacknowledged",
        "agent.unmanaged",
        "job.cancelled",
        "job.closed",
        "job.unacknowledged",
        "job.unmanaged",
        "task.completed",
        "solve.capsule",
        "report.harvested",
    }
    for event in events:
        event_type = event["event_type"]
        payload = event["payload"]
        event_types[event_type] += 1
        families[event_type.split(".", 1)[0]] += 1
        if event_type == "proposal.created":
            proposals += 1
            if payload.get("agent_attempt_id"):
                proposal_attempt_links += 1
        elif event_type == "review.recorded":
            reviews[str(payload.get("verdict", "unknown"))] += 1
        elif event_type == "execution.planned":
            plans += 1
        if event_type in EXECUTION_TERMINAL_TYPES:
            outcomes[_outcome_name(event)] += 1
        if event_type.startswith("agent."):
            agent_transitions[event_type.split(".", 1)[1]] += 1
            if payload.get("agent_attempt_id"):
                agent_attempt_ids.add(str(payload["agent_attempt_id"]))
                if event_type in {
                    "agent.closed",
                    "agent.unacknowledged",
                    "agent.unmanaged",
                }:
                    terminal_attempt_ids.add(str(payload["agent_attempt_id"]))
        if event_type.startswith("job."):
            job_transitions[event_type.split(".", 1)[1]] += 1
            if event_type in {
                "job.cancelled",
                "job.closed",
                "job.unacknowledged",
                "job.unmanaged",
            } and payload.get("resource_summary"):
                terminal_jobs_with_resources += 1
        if event_type == "outcome.recorded" and payload.get("agent_attempt_id"):
            outcome_attempt_links += 1
            outcome_attempt_ids.add(str(payload["agent_attempt_id"]))
        if event_type == "control.stop":
            stops += 1
            stopped = True
            continue
        if event_type == "control.resume":
            resumes += 1
            stopped = False
            continue
        if stopped and event_type.startswith("execution."):
            post_stop_executions += 1
            if event_type in EXECUTION_TERMINAL_TYPES:
                post_stop_terminal_outcomes += 1
        if stopped and event_type in closure_types:
            post_stop_closures[event_type] += 1
    return {
        "count": sum(event_types.values()),
        "families": dict(sorted(families.items())),
        "types": dict(sorted(event_types.items())),
        "workflow": {
            "proposals": proposals,
            "reviews": dict(sorted(reviews.items())),
            "plans": plans,
            "plan_event_denominator": plan_summary["plan_event_denominator"],
            "unique_plan_denominator": len(terminal_summary["latest"]),
            "planned_unique_plan_denominator": len(plan_summary["latest"]),
            "duplicate_plan_events": plan_summary["duplicate_plan_events"],
            "plan_events_missing_plan_id": plan_summary["plan_events_missing_plan_id"],
            "terminal_outcomes": dict(sorted(outcomes.items())),
            "terminal_event_count": terminal_summary["terminal_event_count"],
            "terminal_denominator": len(terminal_summary["final_events"]),
            "unique_final_plan_denominator": len(terminal_summary["latest"]),
            "duplicate_terminal_transitions": terminal_summary["duplicate_terminal_transitions"],
            "duplicate_terminal_events": terminal_summary["duplicate_terminal_transitions"],
            "terminal_events_missing_plan_id": terminal_summary["terminal_events_missing_plan_id"],
            "terminal_events_missing_proposal_id": terminal_summary["terminal_events_missing_proposal_id"],
            "final_terminal_outcomes": dict(sorted(final_outcomes.items())),
            "proposal_attempt_links": proposal_attempt_links,
            "outcome_attempt_links": outcome_attempt_links,
        },
        "agents": {
            "transitions": dict(sorted(agent_transitions.items())),
            "attempt_ids": len(agent_attempt_ids),
            "terminal_attempts": len(terminal_attempt_ids),
            "terminal_attempts_with_outcome": len(
                terminal_attempt_ids & outcome_attempt_ids
            ),
            "terminal_attempts_missing_outcome": len(
                terminal_attempt_ids - outcome_attempt_ids
            ),
        },
        "jobs": {
            "transitions": dict(sorted(job_transitions.items())),
            "terminal_with_resource_summary": terminal_jobs_with_resources,
        },
        "stop": {
            "stops": stops,
            "resumes": resumes,
            "stopped_at_end": stopped,
            "post_stop_execution_events": post_stop_executions,
            "post_stop_terminal_outcomes": post_stop_terminal_outcomes,
            "post_stop_closures": dict(sorted(post_stop_closures.items())),
        },
    }


def _readiness_gate(passed: bool, reason: str | None = None) -> dict[str, Any]:
    gate: dict[str, Any] = {
        "availability": "available" if passed else "not_available",
        "passed": passed,
    }
    if not passed and reason is not None:
        gate["reason"] = reason
    return gate


def _not_applicable_gate(reason: str) -> dict[str, Any]:
    """Represent absent telemetry without treating it as a zero-valued measure."""

    return {
        "availability": "not_available",
        "applicable": False,
        "passed": True,
        "reason": reason,
    }


def _private_launch_binding(
    root: Path,
) -> tuple[dict[str, Any] | None, str | None, str | None]:
    """Read only the private binding record, never its external baseline input.

    The binding deliberately contains hashes and configuration identifiers, not
    environment values.  This reader is local, bounded, no-follow, and does
    not import launch admission helpers because those may inspect live config.
    """

    path = _inside_runtime(root, root / "state" / "launch_binding.json")
    if path is None:
        return None, None, "baseline_binding_outside_runtime"
    try:
        initial = path.lstat()
    except OSError:
        return None, None, "baseline_binding_missing"
    try:
        state = (root / "state").lstat()
    except OSError:
        return None, None, "baseline_binding_state_missing"
    if (
        not stat.S_ISDIR(state.st_mode)
        or stat.S_ISLNK(state.st_mode)
        or stat.S_IMODE(state.st_mode) != 0o700
    ):
        return None, None, "baseline_binding_state_not_private"
    if not stat.S_ISREG(initial.st_mode) or stat.S_ISLNK(initial.st_mode):
        return None, None, "baseline_binding_invalid"
    if stat.S_IMODE(initial.st_mode) != 0o600:
        return None, None, "baseline_binding_not_private"
    if initial.st_size > MAX_LAUNCH_BINDING_BYTES:
        return None, None, "baseline_binding_too_large"
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        return None, None, "baseline_binding_unreadable"
    try:
        opened = os.fstat(descriptor)
        signature = (initial.st_dev, initial.st_ino, initial.st_size, initial.st_mtime_ns)
        if (
            not stat.S_ISREG(opened.st_mode)
            or (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
            != signature
        ):
            return None, None, "baseline_binding_changed"
        raw = bytearray()
        while len(raw) <= MAX_LAUNCH_BINDING_BYTES:
            chunk = os.read(descriptor, min(STREAM_CHUNK_BYTES, MAX_LAUNCH_BINDING_BYTES + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        if len(raw) > MAX_LAUNCH_BINDING_BYTES:
            return None, None, "baseline_binding_too_large"
        final = os.fstat(descriptor)
        if (final.st_dev, final.st_ino, final.st_size, final.st_mtime_ns) != signature:
            return None, None, "baseline_binding_changed"
    except OSError:
        return None, None, "baseline_binding_unreadable"
    finally:
        os.close(descriptor)

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result

    try:
        record = json.loads(bytes(raw).decode("utf-8"), object_pairs_hook=unique_object)
    except (RecursionError, UnicodeDecodeError, json.JSONDecodeError, ValueError):
        return None, None, "baseline_binding_invalid"
    if not isinstance(record, dict):
        return None, None, "baseline_binding_invalid"
    version = record.get("schema_version")
    if version == "2":
        if set(record) != LAUNCH_BINDING_COMMON_FIELDS:
            return None, None, "baseline_binding_invalid"
    elif version == LAUNCH_BINDING_SCHEMA_VERSION:
        if set(record) != LAUNCH_BINDING_FIELDS or _measurement_contract(
            record.get("measurement_contract")
        ) is None:
            return None, None, "baseline_binding_invalid"
    else:
        return None, None, "baseline_binding_invalid"
    if not isinstance(record.get("release_version"), str) or not record["release_version"]:
        return None, None, "baseline_binding_invalid"
    if not all(
        _valid_sha256(record.get(name))
        for name in (
            "immutable_source_sha256",
            "environment_sha256",
            "event_manifest_sha256",
            "baseline_sha256",
            "baseline_configuration_digest",
        )
    ):
        return None, None, "baseline_binding_invalid"
    return record, hashlib.sha256(bytes(raw)).hexdigest(), None


def summarize_baseline_binding(
    root: Path,
    events: Iterable[dict[str, Any]],
    release_version: str = "unknown",
) -> dict[str, Any]:
    """Bind the one canonical measurement start to private hash-only state."""

    record, binding_sha256, error = _private_launch_binding(root)
    if record is None or binding_sha256 is None:
        return _readiness_gate(False, error or "baseline_binding_invalid")
    starts = [event for event in events if event["event_type"] == "measurement.started"]
    if not starts:
        return _readiness_gate(False, "measurement_started_absent")
    if len(starts) != 1:
        return _readiness_gate(False, "measurement_started_not_unique")
    event = starts[0]
    payload = event["payload"]
    required_payload = {
        "launch_binding_sha256",
        "baseline_sha256",
        "configuration_digest",
        "release_version",
        "stop_generation",
        "policy_generation",
        "scope_generation",
    }
    if record["schema_version"] == LAUNCH_BINDING_SCHEMA_VERSION:
        required_payload.add("measurement_contract")
    if (
        set(payload) != required_payload
        or event["event_id"] != f"measurement.started:{binding_sha256}"
        or event["actor"] != "system"
    ):
        return _readiness_gate(False, "measurement_started_invalid")
    if any(
        not _is_int(payload[name]) or payload[name] < 0
        for name in ("stop_generation", "policy_generation", "scope_generation")
    ) or event["generation"] != payload["stop_generation"]:
        return _readiness_gate(False, "measurement_started_generation_mismatch")
    if (
        payload["launch_binding_sha256"] != binding_sha256
        or payload["baseline_sha256"] != record["baseline_sha256"]
        or payload["configuration_digest"] != record["baseline_configuration_digest"]
        or payload["release_version"] != record["release_version"]
    ):
        return _readiness_gate(False, "measurement_started_binding_mismatch")
    if release_version != record["release_version"]:
        return _readiness_gate(False, "measurement_started_release_mismatch")
    contract = _measurement_contract(record.get("measurement_contract"))
    if contract is None:
        return _readiness_gate(False, "measurement_contract_unavailable")
    if payload.get("measurement_contract") != contract:
        return _readiness_gate(False, "measurement_started_measurement_contract_mismatch")
    gate = _readiness_gate(True)
    gate["binding"] = {
        "baseline_sha256": record["baseline_sha256"],
        "configuration_digest": record["baseline_configuration_digest"],
        "launch_binding_sha256": binding_sha256,
        "release_version": record["release_version"],
        "generations": {
            "policy": payload["policy_generation"],
            "scope": payload["scope_generation"],
            "stop": payload["stop_generation"],
        },
        "measurement_contract": contract,
    }
    return gate


def _canonical_sha256(value: Any) -> str | None:
    """Hash bounded canonical JSON without publishing or trusting its values."""

    try:
        return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()
    except (OverflowError, RecursionError, TypeError, ValueError):
        return None


def _canonical_values_match(left: Any, right: Any) -> bool:
    """Compare structured telemetry safely without rendering its content."""

    left_hash = _canonical_sha256(left)
    right_hash = _canonical_sha256(right)
    return left_hash is not None and left_hash == right_hash


def _proposal_candidate_integrity_valid(proposal: dict[str, Any]) -> bool:
    """Validate proposal candidate digests without returning candidate material."""

    required_strings = (
        "proposal_id",
        "solver",
        "objective_id",
        "action_kind",
        "exact_value",
        "artifact_reference",
        "adapter_id",
        "source",
        "rationale",
        "confidence",
        "agent_attempt_id",
        "parent_rejection_fingerprint",
        "discriminator",
        "created_at",
    )
    if any(
        not isinstance(proposal.get(name), str) or len(proposal[name]) > 65_536
        for name in required_strings
    ):
        return False
    if any(
        not proposal[name]
        for name in (
            "proposal_id",
            "solver",
            "objective_id",
            "action_kind",
            "adapter_id",
            "source",
            "rationale",
            "confidence",
            "agent_attempt_id",
        )
    ):
        return False
    action_kind = proposal["action_kind"]
    exact_value = proposal["exact_value"]
    artifact_reference = proposal["artifact_reference"]
    if action_kind not in SCORING_ACTION_KINDS:
        return False
    if (
        action_kind not in {"proof_artifact", "no_submit_evidence"}
        and not exact_value
    ) or (
        action_kind in {"proof_artifact", "no_submit_evidence"}
        and not (exact_value or artifact_reference)
    ):
        return False
    attempt_scope = proposal.get("attempt_scope")
    freshness = proposal.get("freshness_requirements")
    verifier_evidence = proposal.get("verifier_evidence")
    if (
        not isinstance(attempt_scope, dict)
        or not isinstance(freshness, dict)
        or not isinstance(verifier_evidence, list)
        or len(verifier_evidence) > MAX_EVIDENCE_MANIFEST_REFERENCES
        or any(
            not isinstance(item, str) or len(item) > 4_096
            for item in verifier_evidence
        )
    ):
        return False
    if _parse_utc(proposal["created_at"]) is None:
        return False
    normalized = unicodedata.normalize("NFC", exact_value or artifact_reference)
    value_sha256 = (
        hashlib.sha256(exact_value.encode("utf-8")).hexdigest()
        if exact_value
        else ""
    )
    attempt_scope_sha256 = _canonical_sha256(attempt_scope)
    if attempt_scope_sha256 is None:
        return False
    normalized_value_sha256 = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
    candidate_identity_sha256 = _canonical_sha256(
        {
            "action_kind": proposal["action_kind"],
            "attempt_scope_sha256": attempt_scope_sha256,
            "normalized_value_sha256": normalized_value_sha256,
            "objective_id": proposal["objective_id"],
        }
    )
    if candidate_identity_sha256 is None:
        return False
    return (
        proposal.get("value_sha256") == value_sha256
        and proposal.get("attempt_scope_sha256") == attempt_scope_sha256
        and proposal.get("normalized_value_sha256") == normalized_value_sha256
        and proposal.get("candidate_identity_sha256") == candidate_identity_sha256
    )


def _plan_tuple_integrity_valid(
    plan: dict[str, Any], proposal_event: dict[str, Any], review_event: dict[str, Any]
) -> bool:
    """Bind the persisted plan's complete immutable envelope to its proposal."""

    proposal = proposal_event["payload"]
    predicates = plan.get("predicates")
    envelope = plan.get("envelope")
    plan_id = plan.get("plan_id")
    if (
        not isinstance(plan_id, str)
        or not plan_id
        or not isinstance(predicates, dict)
        or not isinstance(envelope, dict)
        or set(predicates)
        != {
            "proposal_event_id",
            "review_event_id",
            "authorization_id",
            "scope_generation",
            "attempt_scope",
        }
        or set(envelope)
        != {
            "objective_id",
            "action_kind",
            "exact_value",
            "artifact_reference",
            "attempt_scope",
            "adapter_id",
            "policy_generation",
            "freshness_requirements",
            "proposal_id",
        }
        or plan.get("plan_path") != f"state/execution_plans/{plan_id}.json"
        or plan.get("schema_version") != "1"
        or not _valid_sha256(plan.get("plan_sha256"))
        or not _is_int(predicates.get("scope_generation"))
        or predicates.get("scope_generation", -1) < 0
        or not isinstance(predicates.get("authorization_id"), str)
        or not isinstance(predicates.get("attempt_scope"), dict)
        or not isinstance(envelope.get("attempt_scope"), dict)
        or not isinstance(envelope.get("freshness_requirements"), dict)
        or not isinstance(plan.get("lifecycle_refs"), dict)
        or not isinstance(plan.get("created_at"), str)
        or _parse_utc(plan.get("created_at")) is None
    ):
        return False
    canonical_plan = {
        key: value
        for key, value in plan.items()
        if key not in {"plan_path", "plan_sha256"}
    }
    if plan["plan_sha256"] != _canonical_sha256(canonical_plan):
        return False
    return (
        plan.get("proposal_id") == proposal.get("proposal_id")
        and plan.get("objective_id") == proposal.get("objective_id")
        and plan.get("semantic_action") == proposal.get("action_kind")
        and plan.get("adapter_id") == proposal.get("adapter_id")
        and plan.get("policy_generation") == proposal.get("policy_generation")
        and plan.get("generation") == proposal.get("stop_generation")
        and envelope.get("proposal_id") == proposal.get("proposal_id")
        and envelope.get("objective_id") == proposal.get("objective_id")
        and envelope.get("action_kind") == proposal.get("action_kind")
        and envelope.get("exact_value") == proposal.get("exact_value")
        and envelope.get("artifact_reference") == proposal.get("artifact_reference")
        and envelope.get("adapter_id") == proposal.get("adapter_id")
        and envelope.get("policy_generation") == proposal.get("policy_generation")
        and _canonical_values_match(
            envelope.get("attempt_scope"), proposal.get("attempt_scope")
        )
        and _canonical_values_match(
            envelope.get("freshness_requirements"),
            proposal.get("freshness_requirements"),
        )
        and predicates.get("proposal_event_id") == proposal_event["event_id"]
        and predicates.get("review_event_id") == review_event["event_id"]
        and _canonical_values_match(
            predicates.get("attempt_scope"), proposal.get("attempt_scope")
        )
        and _canonical_values_match(
            plan.get("lifecycle_refs"), proposal.get("attempt_scope")
        )
    )


def _retry_parent_metadata_valid(
    terminal: dict[str, Any], plan: dict[str, Any], proposal: dict[str, Any]
) -> bool:
    """Recompute the immutable rejection fingerprint before admitting a child."""

    if terminal["event_type"] not in {"execution.rejected", "execution.indeterminate"}:
        return False
    retry = terminal["payload"].get("retry")
    verdict = terminal["payload"].get("verdict")
    terminal_state = terminal["event_type"].rsplit(".", 1)[-1]
    if not isinstance(retry, dict) or not isinstance(verdict, dict):
        return False
    verdict_sha256 = _canonical_sha256(verdict)
    candidate_identity_sha256 = proposal.get("candidate_identity_sha256")
    if verdict_sha256 is None or not _valid_sha256(candidate_identity_sha256):
        return False
    fingerprint = _canonical_sha256(
        {
            "candidate_identity_sha256": candidate_identity_sha256,
            "objective_id": plan.get("objective_id"),
            "terminal_state": terminal_state,
            "verdict_sha256": verdict_sha256,
        }
    )
    return (
        fingerprint is not None
        and retry.get("fingerprint") == fingerprint
        and retry.get("candidate_identity_sha256") == candidate_identity_sha256
        and retry.get("normalized_value_sha256")
        == proposal.get("normalized_value_sha256")
        and retry.get("verdict_sha256") == verdict_sha256
        and retry.get("terminal_state") == terminal_state
    )


def _authorization_grant_provenance_valid(
    events: Iterable[dict[str, Any]], grant: dict[str, Any]
) -> bool:
    """Accept an operator grant and its canonical executor re-grant lineage."""

    authorization_id = grant["payload"].get("authorization_id")
    if not isinstance(authorization_id, str) or not authorization_id:
        return False
    lineage = sorted(
        (
            event
            for event in events
            if event["event_type"] in {"authorization.granted", "authorization.consumed"}
            and event["payload"].get("authorization_id") == authorization_id
        ),
        key=lambda event: (event["seq"], event["event_id"]),
    )
    try:
        position = next(
            index for index, event in enumerate(lineage) if event["event_id"] == grant["event_id"]
        )
    except StopIteration:
        return False
    while position:
        regrant = lineage[position]
        preceding_consumption = lineage[position - 1]
        if (
            regrant["event_type"] != "authorization.granted"
            or preceding_consumption["event_type"] != "authorization.consumed"
            or regrant["seq"] != preceding_consumption["seq"] + 1
            or regrant["actor"] != preceding_consumption["actor"]
            or regrant["generation"] != regrant["payload"].get("stop_generation")
            or preceding_consumption["generation"]
            != preceding_consumption["payload"].get("stop_generation")
            or not _canonical_values_match(
                regrant["payload"], preceding_consumption["payload"]
            )
        ):
            return False
        position -= 2
    origin = lineage[0] if lineage else None
    if (
        not origin
        or origin["event_type"] != "authorization.granted"
        or origin["generation"] != origin["payload"].get("stop_generation")
        or "consumed_for_plan" in origin["payload"]
        or "consumed_at" in origin["payload"]
    ):
        return False
    if origin["actor"] == "operator":
        return origin["payload"].get("authority_source") in {None, "operator"}
    return bool(
        origin["actor"] == "coordinator"
        and origin["payload"].get("mode") == "allowance"
        and origin["payload"].get("authority_source")
        == "operator_configured_automation"
    )


def _scoring_chain_gate(
    events: Iterable[dict[str, Any]],
    measurement_generations: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Require one current authorized decision chain for every final terminal."""

    event_list = list(events)
    minimum_generations: dict[str, int] | None = None
    if measurement_generations is not None:
        if any(
            not _is_int(measurement_generations.get(name))
            or measurement_generations[name] < 0
            for name in ("policy", "scope", "stop")
        ):
            return _readiness_gate(False, "measurement_generation_binding_invalid")
        minimum_generations = {
            name: int(measurement_generations[name])
            for name in ("policy", "scope", "stop")
        }
    proposals: dict[str, dict[str, Any]] = {}
    reviews: dict[str, list[dict[str, Any]]] = {}
    plans: dict[str, dict[str, Any]] = {}
    starts: dict[str, list[dict[str, Any]]] = {}
    consumptions: dict[str, list[dict[str, Any]]] = {}
    grants: dict[str, list[dict[str, Any]]] = {}
    proposal_events = plan_events = terminal_events = 0
    invalid_identifiers = False

    def identifier(value: Any) -> str | None:
        return value if isinstance(value, str) and 0 < len(value) <= 512 else None

    for event in event_list:
        payload = event["payload"]
        event_type = event["event_type"]
        if event_type == "proposal.created":
            proposal_events += 1
            proposal_id = identifier(payload.get("proposal_id"))
            if proposal_id is None or proposal_id in proposals:
                invalid_identifiers = True
            else:
                proposals[proposal_id] = event
        elif event_type == "review.recorded":
            proposal_id = identifier(payload.get("proposal_id"))
            if proposal_id is None:
                invalid_identifiers = True
            else:
                reviews.setdefault(proposal_id, []).append(event)
        elif event_type == "execution.planned":
            plan_events += 1
            plan_id = identifier(payload.get("plan_id"))
            proposal_id = identifier(payload.get("proposal_id"))
            if plan_id is None or proposal_id is None or plan_id in plans:
                invalid_identifiers = True
            else:
                plans[plan_id] = event
        elif event_type == "execution.started":
            plan_id = identifier(payload.get("plan_id"))
            if plan_id is None:
                invalid_identifiers = True
            else:
                starts.setdefault(plan_id, []).append(event)
        elif event_type == "authorization.granted":
            authorization_id = identifier(payload.get("authorization_id"))
            if authorization_id is None:
                invalid_identifiers = True
            else:
                grants.setdefault(authorization_id, []).append(event)
        elif event_type == "authorization.consumed":
            plan_id = identifier(payload.get("consumed_for_plan"))
            if plan_id is None:
                invalid_identifiers = True
            else:
                consumptions.setdefault(plan_id, []).append(event)
        elif event_type in EXECUTION_TERMINAL_TYPES:
            terminal_events += 1

    if not (proposal_events or plan_events or terminal_events):
        return _readiness_gate(False, "scoring_chain_events_absent")
    terminals = _latest_terminal_events(event_list)
    final_by_plan = terminals["latest"]
    if (
        invalid_identifiers
        or not proposals
        or proposal_events != len(proposals)
        or plan_events != len(plans)
        or terminal_events != len(final_by_plan)
        or terminals["terminal_events_missing_plan_id"]
        or terminals["terminal_events_missing_proposal_id"]
    ):
        return _readiness_gate(False, "scoring_chain_identifiers_incomplete")
    if set(reviews) - set(proposals) or set(starts) - set(plans) or set(consumptions) - set(plans):
        return _readiness_gate(False, "scoring_chain_unknown_parent")
    plan_counts = Counter(
        str(event["payload"].get("proposal_id")) for event in plans.values()
    )
    if set(plan_counts) - set(proposals) or any(
        plan_counts[proposal_id] != 1 for proposal_id in proposals
    ):
        return _readiness_gate(False, "scoring_chain_intermediate_links_incomplete")
    if set(final_by_plan) != set(plans):
        return _readiness_gate(False, "scoring_chain_final_terminal_incomplete")

    retry_parents: dict[str, dict[str, Any]] = {}
    for event in event_list:
        fingerprint = _terminal_retry_fingerprint(event)
        if fingerprint is None:
            continue
        retry = event["payload"].get("retry")
        parent_plan_id = identifier(event["payload"].get("plan_id"))
        parent_proposal_id = identifier(event["payload"].get("proposal_id"))
        parent_plan_event = plans.get(parent_plan_id) if parent_plan_id else None
        parent_proposal_event = (
            proposals.get(parent_proposal_id) if parent_proposal_id else None
        )
        if (
            event["event_type"] not in {"execution.rejected", "execution.indeterminate"}
            or fingerprint in retry_parents
            or not isinstance(retry, dict)
            or parent_plan_event is None
            or parent_proposal_event is None
            or not _retry_parent_metadata_valid(
                event, parent_plan_event["payload"], parent_proposal_event["payload"]
            )
        ):
            return _readiness_gate(False, "scoring_chain_retry_parent_invalid")
        retry_parents[fingerprint] = event
    parent_uses: Counter[str] = Counter()

    for plan_id, plan_event in plans.items():
        plan = plan_event["payload"]
        proposal_id = str(plan["proposal_id"])
        proposal_event = proposals[proposal_id]
        proposal = proposal_event["payload"]
        proposal_reviews = reviews.get(proposal_id, [])
        if not proposal_reviews:
            return _readiness_gate(False, "scoring_chain_review_absent")
        current_review = proposal_reviews[-1]
        review = current_review["payload"]
        if not _proposal_candidate_integrity_valid(proposal):
            return _readiness_gate(False, "scoring_chain_candidate_integrity_mismatch")
        parent = proposal.get("parent_rejection_fingerprint")
        discriminator = proposal.get("discriminator")
        if not isinstance(parent, str) or not isinstance(discriminator, str):
            return _readiness_gate(False, "scoring_chain_retry_lineage_incomplete")
        if not parent:
            if discriminator:
                return _readiness_gate(False, "scoring_chain_retry_lineage_incomplete")
        else:
            parent_event = retry_parents.get(parent)
            parent_retry = parent_event["payload"].get("retry") if parent_event else None
            parent_uses[parent] += 1
            matching_parent_fingerprints = {
                fingerprint
                for fingerprint, candidate in retry_parents.items()
                if candidate["seq"] < proposal_event["seq"]
                and candidate["payload"].get("retry", {}).get(
                    "candidate_identity_sha256"
                )
                == proposal.get("candidate_identity_sha256")
            }
            if (
                not _valid_retry_fingerprint(parent)
                or not discriminator.strip()
                or parent_event is None
                or parent_event["seq"] >= proposal_event["seq"]
                or not isinstance(parent_retry, dict)
                or parent_event["payload"].get("objective_id")
                != proposal.get("objective_id")
                or parent_uses[parent] != 1
                or (
                    matching_parent_fingerprints
                    and parent not in matching_parent_fingerprints
                )
            ):
                return _readiness_gate(False, "scoring_chain_retry_lineage_incomplete")
        if not _plan_tuple_integrity_valid(plan, proposal_event, current_review):
            return _readiness_gate(False, "scoring_chain_plan_tuple_integrity_mismatch")
        predicates = plan.get("predicates")
        envelope = plan.get("envelope")
        if (
            not isinstance(predicates, dict)
            or not isinstance(envelope, dict)
            or current_review["seq"] <= proposal_event["seq"]
            or plan_event["seq"] <= current_review["seq"]
            or review.get("verdict") != "approved"
            or not isinstance(review.get("reviewer"), str)
            or not review["reviewer"]
            or review["reviewer"] == proposal.get("solver")
            or not isinstance(review.get("reason"), str)
            or not review["reason"]
            or not isinstance(review.get("verifier_report"), str)
            or not isinstance(review.get("reviewed_at"), str)
            or _parse_utc(review["reviewed_at"]) is None
            or proposal_event["generation"] != proposal.get("stop_generation")
            or proposal.get("stop_generation") != plan["generation"]
            or proposal.get("policy_generation") != plan["policy_generation"]
            or current_review["generation"] != plan["generation"]
            or predicates.get("proposal_event_id") != proposal_event["event_id"]
            or predicates.get("review_event_id") != current_review["event_id"]
            or plan.get("generation") != plan_event["generation"]
            or not _is_int(plan.get("generation"))
            or plan.get("generation", -1) < 0
            or not _is_int(plan.get("policy_generation"))
            or plan.get("policy_generation", -1) < 0
            or review.get("stop_generation") != plan["generation"]
            or review.get("policy_generation") != plan["policy_generation"]
            or not _is_int(predicates.get("scope_generation"))
            or predicates.get("scope_generation", -1) < 0
            or plan.get("objective_id") != proposal.get("objective_id")
            or plan.get("semantic_action") != proposal.get("action_kind")
            or plan.get("adapter_id") != proposal.get("adapter_id")
            or envelope.get("objective_id") != proposal.get("objective_id")
            or envelope.get("action_kind") != proposal.get("action_kind")
            or envelope.get("adapter_id") != proposal.get("adapter_id")
            or not _canonical_values_match(
                envelope.get("attempt_scope"), proposal.get("attempt_scope")
            )
            or not _canonical_values_match(
                predicates.get("attempt_scope"), proposal.get("attempt_scope")
            )
            or (
                minimum_generations is not None
                and (
                    plan["generation"] < minimum_generations["stop"]
                    or plan["policy_generation"] < minimum_generations["policy"]
                    or predicates["scope_generation"] < minimum_generations["scope"]
                )
            )
        ):
            return _readiness_gate(False, "scoring_chain_plan_review_lineage_mismatch")

        plan_starts = starts.get(plan_id, [])
        if len(plan_starts) != 1:
            return _readiness_gate(False, "scoring_chain_execution_start_incomplete")
        start = plan_starts[0]
        start_payload = start["payload"]
        if (
            start["seq"] <= plan_event["seq"]
            or start["generation"] != plan["generation"]
            or start_payload.get("proposal_id") != proposal_id
            or start_payload.get("objective_id") != proposal.get("objective_id")
            or start_payload.get("action_kind") != proposal.get("action_kind")
            or start_payload.get("review_event_id") != current_review["event_id"]
            or start_payload.get("stop_generation") != plan["generation"]
            or start_payload.get("policy_generation") != plan["policy_generation"]
            or start_payload.get("scope_generation") != predicates["scope_generation"]
            or not isinstance(start_payload.get("started_at"), str)
            or _parse_utc(start_payload["started_at"]) is None
        ):
            return _readiness_gate(False, "scoring_chain_execution_start_lineage_mismatch")

        authorization_id = predicates.get("authorization_id")
        action_kind = proposal.get("action_kind")
        plan_consumptions = consumptions.get(plan_id, [])
        if action_kind == "no_submit_evidence":
            if (
                authorization_id != ""
                or start_payload.get("authorization_id") != ""
                or plan_consumptions
            ):
                return _readiness_gate(False, "scoring_chain_authorization_lineage_mismatch")
        elif (
            not identifier(authorization_id)
            or len(plan_consumptions) != 1
            or start_payload.get("authorization_id") != authorization_id
            or plan_consumptions[0]["seq"] <= plan_event["seq"]
            or plan_consumptions[0]["seq"] >= start["seq"]
            or plan_consumptions[0]["generation"] != plan["generation"]
            or plan_consumptions[0]["payload"].get("authorization_id") != authorization_id
            or plan_consumptions[0]["payload"].get("action_kind") != action_kind
            or plan_consumptions[0]["payload"].get("stop_generation") != plan["generation"]
            or plan_consumptions[0]["payload"].get("policy_generation")
            != plan["policy_generation"]
            or not isinstance(plan_consumptions[0]["payload"].get("mode"), str)
            or plan_consumptions[0]["payload"].get("mode") not in {"exact", "allowance"}
            or (
                plan_consumptions[0]["payload"].get("mode") == "exact"
                and plan_consumptions[0]["payload"].get("proposal_id") != proposal_id
            )
            or (
                plan_consumptions[0]["payload"].get("mode") == "allowance"
                and plan_consumptions[0]["payload"].get("proposal_id") not in {None, ""}
            )
            or not _is_int(plan_consumptions[0]["payload"].get("remaining"))
            or plan_consumptions[0]["payload"].get("remaining", -1) < 0
            or not isinstance(plan_consumptions[0]["payload"].get("consumed_at"), str)
            or _parse_utc(plan_consumptions[0]["payload"]["consumed_at"]) is None
        ):
            return _readiness_gate(False, "scoring_chain_authorization_lineage_mismatch")
        else:
            consumption = plan_consumptions[0]
            preceding_consumptions = [
                event
                for event in event_list
                if event["event_type"] == "authorization.consumed"
                and event["seq"] < consumption["seq"]
                and event["payload"].get("authorization_id") == authorization_id
            ]
            prior_consumption_seq = max(
                (event["seq"] for event in preceding_consumptions), default=0
            )
            applicable_grants = [
                event
                for event in grants.get(authorization_id, [])
                if prior_consumption_seq < event["seq"] < consumption["seq"]
            ]
            if len(applicable_grants) != 1:
                return _readiness_gate(False, "scoring_chain_authorization_grant_incomplete")
            grant = applicable_grants[0]
            grant_payload = grant["payload"]
            grant_time = _parse_utc(grant_payload.get("granted_at"))
            consumed_time = _parse_utc(consumption["payload"].get("consumed_at"))
            if (
                not _authorization_grant_provenance_valid(event_list, grant)
                or grant["generation"] != plan["generation"]
                or grant_payload.get("authorization_id") != authorization_id
                or grant_payload.get("action_kind") != action_kind
                or grant_payload.get("stop_generation") != plan["generation"]
                or grant_payload.get("policy_generation") != plan["policy_generation"]
                or grant_payload.get("mode") not in {"exact", "allowance"}
                or not _is_int(grant_payload.get("remaining"))
                or grant_payload.get("remaining", 0) <= 0
                or not isinstance(grant_payload.get("reason"), str)
                or not grant_payload["reason"].strip()
                or len(grant_payload["reason"]) > 4_096
                or grant_time is None
                or consumed_time is None
                or grant_time > consumed_time
                or consumption["payload"].get("remaining")
                != grant_payload["remaining"] - 1
                or (
                    grant_payload.get("mode") == "exact"
                    and grant_payload.get("proposal_id") != proposal_id
                )
                or (
                    grant_payload.get("mode") == "allowance"
                    and grant_payload.get("proposal_id") not in {None, ""}
                )
                or any(
                    key in grant_payload
                    and grant_payload.get(key) != proposal.get(key)
                    for key in (
                        "candidate_identity_sha256",
                        "normalized_value_sha256",
                        "value_sha256",
                        "artifact_reference",
                    )
                )
            ):
                return _readiness_gate(False, "scoring_chain_authorization_grant_mismatch")

        terminal = final_by_plan[plan_id]
        terminal_payload = terminal["payload"]
        verdict = terminal_payload.get("verdict")
        terminal_state = terminal["event_type"].rsplit(".", 1)[-1]
        scorer_truth = verdict.get("scorer_truth") if isinstance(verdict, dict) else None
        verdict_name = verdict.get("verdict") if isinstance(verdict, dict) else None
        expected_truth = {
            "completed": (
                {"non_scoring"}
                if action_kind == "no_submit_evidence"
                else {"accepted", "already-accepted"}
            ),
            "rejected": {"rejected"},
            "indeterminate": {"unknown", "transport_error", "non_scoring"},
        }
        if (
            terminal["seq"] <= start["seq"]
            or terminal["generation"] != plan["generation"]
            or terminal_payload.get("proposal_id") != proposal_id
            or terminal_payload.get("objective_id") != proposal.get("objective_id")
            or terminal_payload.get("action_kind") != action_kind
            or terminal_payload.get("status") != terminal_state
            or terminal_state not in expected_truth
            or verdict_name not in expected_truth.get(terminal_state, set())
            or scorer_truth != verdict_name
            or not isinstance(terminal_payload.get("completed_at"), str)
            or _parse_utc(terminal_payload["completed_at"]) is None
            or (
                action_kind == "no_submit_evidence"
                and terminal_payload.get("response_path") != ""
            )
            or (
                action_kind == "no_submit_evidence"
                and envelope.get("artifact_reference") == ""
                and terminal_payload.get("evidence_root") != ""
            )
        ):
            return _readiness_gate(False, "scoring_chain_terminal_lineage_mismatch")
    return _readiness_gate(True)


def _typed_attempt_coverage_gate(events: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Require registered attempts and exact terminal, outcome, and proposal links."""

    registrations: dict[str, dict[str, Any]] = {}
    terminals: dict[str, list[dict[str, Any]]] = {}
    outcomes: dict[str, list[dict[str, Any]]] = {}
    proposals: dict[str, list[dict[str, Any]]] = {}
    capacity_rejections: dict[str, dict[str, Any]] = {}
    invalid = False

    def attempt_id(payload: dict[str, Any]) -> str | None:
        value = payload.get("agent_attempt_id")
        return value if isinstance(value, str) and 0 < len(value) <= 512 else None

    for event in events:
        payload = event["payload"]
        event_type = event["event_type"]
        identifier = attempt_id(payload)
        if event_type == "agent.running":
            if (
                identifier is None
                or identifier in registrations
                or not isinstance(payload.get("agent_id"), str)
                or not payload["agent_id"]
                or not isinstance(payload.get("objective_id"), str)
                or not payload["objective_id"]
                or not isinstance(payload.get("role"), str)
                or not payload["role"]
                or not isinstance(payload.get("parent_agent_attempt_id", ""), str)
                or (
                    "agent_depth" in payload
                    and payload.get("agent_depth") not in {1, 2}
                )
            ):
                invalid = True
            else:
                registrations[identifier] = event
        elif event_type == "proposal.created":
            if identifier is None:
                invalid = True
            else:
                proposals.setdefault(identifier, []).append(event)
        elif event_type in {"agent.closed", "agent.unacknowledged", "agent.unmanaged"}:
            if identifier is None:
                invalid = True
            else:
                terminals.setdefault(identifier, []).append(event)
        elif event_type == "outcome.recorded":
            if identifier is None:
                invalid = True
            else:
                outcomes.setdefault(identifier, []).append(event)
        elif event_type == "agent.capacity_rejected":
            if (
                identifier is None
                or identifier in capacity_rejections
                or not isinstance(payload.get("agent_id"), str)
                or not payload["agent_id"]
                or not isinstance(payload.get("objective_id"), str)
                or not payload["objective_id"]
                or not isinstance(payload.get("parent_agent_attempt_id"), str)
                or payload.get("status") != "capacity_rejected"
                or payload.get("outcome_type") != "capacity_failure"
                or not _is_int(payload.get("active_workers"))
                or payload.get("active_workers", -1) < 0
                or not _is_int(payload.get("max_workers"))
                or payload.get("max_workers", 0) <= 0
                or payload["active_workers"] < payload["max_workers"]
                or event["generation"] < 0
                or not isinstance(payload.get("reason"), str)
                or not payload["reason"]
                or len(payload["reason"]) > 4_096
                or not isinstance(payload.get("rejected_at"), str)
                or _parse_utc(payload["rejected_at"]) is None
            ):
                invalid = True
            else:
                capacity_rejections[identifier] = event

    if not registrations and not terminals:
        return _readiness_gate(False, "agent_attempt_events_absent")
    if invalid:
        return _readiness_gate(False, "agent_attempt_identifiers_incomplete")
    if not terminals:
        return _readiness_gate(False, "terminal_agent_attempts_absent")
    if set(terminals) != set(registrations):
        return _readiness_gate(False, "agent_attempt_terminal_coverage_incomplete")
    if set(outcomes) != set(registrations):
        return _readiness_gate(False, "typed_outcome_coverage_incomplete")
    if set(proposals) - set(registrations):
        return _readiness_gate(False, "proposal_attempt_lineage_incomplete")
    if set(capacity_rejections) & (
        set(registrations) | set(terminals) | set(outcomes) | set(proposals)
    ):
        return _readiness_gate(False, "capacity_rejection_lineage_incomplete")
    for identifier, registration_event in registrations.items():
        registration = registration_event["payload"]
        if "parent_agent_attempt_id" in registration:
            parent_identifier = registration["parent_agent_attempt_id"]
            if not isinstance(parent_identifier, str):
                return _readiness_gate(False, "agent_attempt_parent_lineage_incomplete")
            if parent_identifier:
                parent = registrations.get(parent_identifier)
                parent_payload = parent["payload"] if parent is not None else {}
                if (
                    parent is None
                    or parent["seq"] >= registration_event["seq"]
                    or parent["generation"] != registration_event["generation"]
                    or parent_payload.get("role") != "challenge-coordinator"
                    or str(parent_payload.get("parent_agent_attempt_id") or "")
                    or parent_payload.get("agent_depth", 1) != 1
                    or registration.get("agent_depth", 2) != 2
                    or parent_payload.get("challenge_id")
                    != registration.get("challenge_id")
                    or parent_payload.get("objective_id")
                    != registration.get("objective_id")
                ):
                    return _readiness_gate(False, "agent_attempt_parent_lineage_incomplete")
            elif registration.get("agent_depth", 1) != 1:
                return _readiness_gate(False, "agent_attempt_parent_lineage_incomplete")
        terminal_rows = terminals.get(identifier, [])
        outcome_rows = outcomes.get(identifier, [])
        if len(terminal_rows) != 1 or len(outcome_rows) != 1:
            return _readiness_gate(False, "typed_outcome_coverage_incomplete")
        terminal = terminal_rows[0]
        outcome = outcome_rows[0]
        if (
            terminal["seq"] <= registration_event["seq"]
            or outcome["seq"] <= registration_event["seq"]
            or terminal["payload"].get("agent_id") != registration["agent_id"]
            or terminal["payload"].get("objective_id") != registration["objective_id"]
            or outcome["payload"].get("agent_id") != registration["agent_id"]
            or outcome["payload"].get("objective_id") != registration["objective_id"]
            or not isinstance(outcome["payload"].get("outcome_id"), str)
            or not outcome["payload"]["outcome_id"]
            or not isinstance(outcome["payload"].get("outcome_type"), str)
            or not outcome["payload"]["outcome_type"]
        ):
            return _readiness_gate(False, "agent_attempt_lineage_mismatch")
        for proposal in proposals.get(identifier, []):
            if (
                proposal["seq"] <= registration_event["seq"]
                or proposal["payload"].get("objective_id") != registration["objective_id"]
            ):
                return _readiness_gate(False, "proposal_attempt_lineage_incomplete")
    gate = _readiness_gate(True)
    gate["registered_attempt_denominator"] = len(registrations)
    gate["capacity_rejection_denominator"] = len(capacity_rejections)
    return gate


def _measurement_temporal_coverage_gate(events: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Require complete UTC coverage and ordered scorer-chain payload times."""

    event_list = list(events)
    if not event_list:
        return _readiness_gate(False, "measurement_event_timestamps_absent")
    if any(_parse_utc(event["created_at"]) is None for event in event_list):
        return _readiness_gate(False, "measurement_event_timestamps_incomplete")

    proposals: dict[str, dict[str, Any]] = {}
    reviews: dict[str, list[dict[str, Any]]] = {}
    plans: dict[str, dict[str, Any]] = {}
    starts: dict[str, list[dict[str, Any]]] = {}
    for event in event_list:
        payload = event["payload"]
        event_type = event["event_type"]
        if event_type == "proposal.created":
            proposal_id = payload.get("proposal_id")
            if isinstance(proposal_id, str) and proposal_id:
                proposals[proposal_id] = event
            if _parse_utc(payload.get("created_at")) is None:
                return _readiness_gate(False, "measurement_scoring_timestamps_incomplete")
        elif event_type == "review.recorded":
            proposal_id = payload.get("proposal_id")
            if isinstance(proposal_id, str) and proposal_id:
                reviews.setdefault(proposal_id, []).append(event)
            if _parse_utc(payload.get("reviewed_at")) is None:
                return _readiness_gate(False, "measurement_scoring_timestamps_incomplete")
        elif event_type == "execution.planned":
            plan_id = payload.get("plan_id")
            if isinstance(plan_id, str) and plan_id:
                plans[plan_id] = event
            if _parse_utc(payload.get("created_at")) is None:
                return _readiness_gate(False, "measurement_scoring_timestamps_incomplete")
        elif event_type == "execution.started":
            plan_id = payload.get("plan_id")
            if isinstance(plan_id, str) and plan_id:
                starts.setdefault(plan_id, []).append(event)
            if _parse_utc(payload.get("started_at")) is None:
                return _readiness_gate(False, "measurement_scoring_timestamps_incomplete")
        elif event_type in EXECUTION_TERMINAL_TYPES:
            if _parse_utc(payload.get("completed_at")) is None:
                return _readiness_gate(False, "measurement_scoring_timestamps_incomplete")
        elif event_type == "authorization.granted":
            if _parse_utc(payload.get("granted_at")) is None:
                return _readiness_gate(False, "measurement_scoring_timestamps_incomplete")
        elif event_type == "authorization.consumed":
            if _parse_utc(payload.get("consumed_at")) is None:
                return _readiness_gate(False, "measurement_scoring_timestamps_incomplete")

    terminals = _latest_terminal_events(event_list)["latest"]
    for plan_id, plan_event in plans.items():
        plan = plan_event["payload"]
        proposal_id = plan.get("proposal_id")
        proposal_event = proposals.get(proposal_id) if isinstance(proposal_id, str) else None
        proposal_reviews = reviews.get(proposal_id, []) if isinstance(proposal_id, str) else []
        start_events = starts.get(plan_id, [])
        terminal_event = terminals.get(plan_id)
        # Identifier/link completeness belongs to the scoring gate. When the
        # chain is complete, its declared timestamps must be chronological.
        if (
            proposal_event is None
            or len(proposal_reviews) != 1
            or len(start_events) != 1
            or terminal_event is None
        ):
            continue
        times = (
            _parse_utc(proposal_event["payload"].get("created_at")),
            _parse_utc(proposal_reviews[0]["payload"].get("reviewed_at")),
            _parse_utc(plan.get("created_at")),
            _parse_utc(start_events[0]["payload"].get("started_at")),
            _parse_utc(terminal_event["payload"].get("completed_at")),
        )
        if any(value is None for value in times) or any(
            times[index] > times[index + 1] for index in range(len(times) - 1)
        ):
            return _readiness_gate(False, "measurement_scoring_time_order_invalid")
    return _readiness_gate(True)


def _measurement_timeline_generation_gate(
    events: Iterable[dict[str, Any]], measurement_generations: dict[str, Any] | None
) -> dict[str, Any]:
    """Require one measured runtime timeline with no future-generation work."""

    event_list = list(events)
    starts = [event for event in event_list if event["event_type"] == "measurement.started"]
    if len(starts) != 1 or measurement_generations is None:
        return _readiness_gate(False, "measurement_timeline_unavailable")
    if any(
        not _is_int(measurement_generations.get(name))
        for name in ("stop", "policy", "scope")
    ):
        return _readiness_gate(False, "measurement_timeline_unavailable")
    start = starts[0]
    relevant_prefixes = (
        "agent.", "job.", "command.", "proposal.", "review.", "authorization.",
        "execution.", "outcome.", "retry.", "control.", "queue.", "platform.",
        "scope.", "policy.",
    )
    if any(
        event["seq"] < start["seq"]
        and event["event_type"].startswith(relevant_prefixes)
        for event in event_list
    ):
        return _readiness_gate(False, "measurement_started_not_first_relevant_event")
    current_generation = int(measurement_generations["stop"])
    active = True
    pre_stop_generations: list[int] = []
    closeout_types = {
        "agent.closed", "agent.unacknowledged", "agent.unmanaged", "job.cancelled",
        "job.closed", "job.stale", "job.unacknowledged", "job.unmanaged",
        "outcome.recorded", "report.harvested", "solve.capsule", "task.completed",
        "lessons.created", "authorization.revoked", "retry.cancelled",
    }
    for event in sorted((item for item in event_list if item["seq"] > start["seq"]), key=lambda item: item["seq"]):
        event_type = event["event_type"]
        if event_type == "control.stop":
            if not active or event["generation"] != current_generation + 1:
                return _readiness_gate(False, "measurement_generation_history_invalid")
            current_generation = event["generation"]
            active = False
            continue
        if event_type == "control.resume":
            if active or event["generation"] != current_generation or event["payload"].get("generation") != current_generation:
                return _readiness_gate(False, "measurement_generation_history_invalid")
            active = True
            continue
        if not event_type.startswith(relevant_prefixes):
            continue
        if not active:
            if event_type not in closeout_types or event["generation"] != current_generation:
                return _readiness_gate(False, "measurement_generation_context_incomplete")
            continue
        if event["generation"] != current_generation:
            return _readiness_gate(False, "measurement_generation_context_incomplete")
        pre_stop_generations.append(event["generation"])
    stop_events = [event for event in event_list if event["event_type"] == "control.stop"]
    if not stop_events or max(pre_stop_generations, default=int(measurement_generations["stop"])) >= stop_events[-1]["generation"]:
        return _readiness_gate(False, "final_stop_generation_not_upper_bound")
    return _readiness_gate(True)


def _operational_applicability_gate(
    events: dict[str, Any],
    measurement: dict[str, Any],
    canonical_events: Iterable[dict[str, Any]],
    measurement_contract: dict[str, Any] | None,
    measurement_generations: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Gate only applicable queue, stop, and resource measurements."""

    canonical = list(canonical_events)
    queue_timing = measurement.get("queue_timing", {})
    if measurement_contract is None:
        queue = _readiness_gate(False, "measurement_contract_unavailable")
    elif not measurement_contract["queue_automation_enabled"]:
        queue = _not_applicable_gate("queue_automation_disabled")
    elif not isinstance(queue_timing, dict) or queue_timing.get("availability") != "available":
        queue = _readiness_gate(False, "queue_timing_incomplete")
    else:
        queue = _readiness_gate(True)

    stop_records = [event for event in canonical if event["event_type"] == "control.stop"]
    prior_stop_generation = 0
    prior_watcher_epoch = 0
    stop_proof_valid = True
    for stop_record in stop_records:
        payload = stop_record["payload"]
        generation = payload.get("generation")
        if (
            stop_record["actor"] != "operator"
            or not isinstance(payload.get("reason"), str)
            or not payload["reason"]
            or len(payload["reason"]) > 4_096
            or not _is_int(generation)
            or generation != prior_stop_generation + 1
            or stop_record["generation"] != generation
            or not _is_int(payload.get("watcher_epoch"))
            or payload.get("watcher_epoch") != prior_watcher_epoch + 1
            or not isinstance(payload.get("requested_at"), str)
            or _parse_utc(payload["requested_at"]) is None
        ):
            stop_proof_valid = False
            break
        prior_stop_generation = generation
        prior_watcher_epoch = payload["watcher_epoch"]

    stop = events.get("stop", {})
    stops = stop.get("stops", 0) if isinstance(stop, dict) else 0
    reconciliation = measurement.get("stop_reconciliation", {})
    if not stops:
        stop_gate = _readiness_gate(False, "final_control_stop_absent")
    elif not stop_proof_valid:
        stop_gate = _readiness_gate(False, "final_control_stop_proof_invalid")
    elif (
        measurement_generations is not None
        and (
            not _is_int(measurement_generations.get("stop"))
            or stop_records[-1]["generation"] <= measurement_generations["stop"]
        )
    ):
        stop_gate = _readiness_gate(False, "final_control_stop_precedes_measurement")
    elif not isinstance(stop, dict) or stop.get("stopped_at_end") is not True:
        stop_gate = _readiness_gate(False, "runtime_not_stopped_at_end")
    else:
        final_stop_event = max(
            (event for event in canonical if event["event_type"] == "control.stop"),
            key=lambda event: event["seq"],
            default=None,
        )
        final_stop = final_stop_event["seq"] if final_stop_event is not None else 0
        final_generation = (
            final_stop_event["generation"] if final_stop_event is not None else -1
        )
        closeout_events = {
            "authorization.revoked",
            "retry.cancelled",
            "agent.stopping",
            "agent.closed",
            "agent.unacknowledged",
            "agent.unmanaged",
            "job.stopping",
            "job.cancelled",
            "job.closed",
            "job.stale",
            "job.unacknowledged",
            "job.unmanaged",
            "lessons.created",
            "outcome.recorded",
            "report.harvested",
            "solve.capsule",
            "task.completed",
        }
        after_stop = [event for event in canonical if event["seq"] > final_stop]
        lessons = [event for event in after_stop if event["event_type"] == "lessons.created"]
        closures = [
            event
            for event in after_stop
            if event["event_type"]
            in {
                "agent.closed",
                "agent.unacknowledged",
                "agent.unmanaged",
                "job.cancelled",
                "job.closed",
                "job.stale",
                "job.unacknowledged",
                "job.unmanaged",
            }
        ]
        terminal_attempts = {
            str(event["payload"].get("agent_attempt_id"))
            for event in canonical
            if event["event_type"]
            in {"agent.closed", "agent.unacknowledged", "agent.unmanaged"}
            and isinstance(event["payload"].get("agent_attempt_id"), str)
            and event["payload"]["agent_attempt_id"]
        }
        closeout_identifiers: dict[str, set[str]] = {
            "outcome.recorded": set(),
            "report.harvested": set(),
            "solve.capsule": set(),
            "task.completed": set(),
        }
        closeout_fields = {
            "report.harvested": "report_path",
            "solve.capsule": "objective_id",
            "task.completed": "completion_id",
        }
        closeout_invalid = False
        for event in after_stop:
            event_type = event["event_type"]
            payload = event["payload"]
            if event_type == "lessons.created":
                if payload.get("stop_generation") != final_generation:
                    closeout_invalid = True
            elif event_type == "outcome.recorded":
                attempt_id = payload.get("agent_attempt_id")
                outcome_id = payload.get("outcome_id")
                if (
                    not isinstance(attempt_id, str)
                    or not attempt_id
                    or attempt_id not in terminal_attempts
                    or not isinstance(outcome_id, str)
                    or not outcome_id
                    or outcome_id in closeout_identifiers[event_type]
                ):
                    closeout_invalid = True
                else:
                    closeout_identifiers[event_type].add(outcome_id)
            elif event_type in closeout_fields:
                identifier = payload.get(closeout_fields[event_type])
                if (
                    not isinstance(identifier, str)
                    or not identifier
                    or identifier in closeout_identifiers[event_type]
                ):
                    closeout_invalid = True
                else:
                    closeout_identifiers[event_type].add(identifier)
        if (
            any(
                event["event_type"] not in closeout_events
                or event["generation"] != final_generation
                for event in after_stop
            )
            or len(lessons) > 1
            or closeout_invalid
        ):
            stop_gate = _readiness_gate(False, "post_stop_mutation_detected")
        elif closures and (
            not isinstance(reconciliation, dict)
            or reconciliation.get("availability") != "available"
            or reconciliation.get("stops_with_terminal_closure")
            != reconciliation.get("stop_generation_denominator")
        ):
            stop_gate = _readiness_gate(False, "stop_reconciliation_incomplete")
        else:
            stop_gate = _readiness_gate(True)

    resources = measurement.get("resources", {})
    terminal_jobs = resources.get("terminal_jobs", 0) if isinstance(resources, dict) else 0
    if not isinstance(resources, dict):
        resource = _readiness_gate(False, "resource_measurement_invalid")
    elif resources.get("terminal_jobs_missing_stable_id", 0):
        resource = _readiness_gate(False, "terminal_job_identifier_incomplete")
    elif resources.get("terminal_jobs_with_forbidden_state_conflict", 0):
        resource = _readiness_gate(False, "terminal_job_state_conflict")
    elif not terminal_jobs:
        resource = _not_applicable_gate("terminal_job_resources_absent")
    else:
        owned_coverage = resources.get("owned_coverage")
        local_process = resources.get("local_process")
        owned_count = (
            owned_coverage.get("denominator_owned_terminal_jobs")
            if isinstance(owned_coverage, dict)
            else None
        )
        local_incomplete = (
            not isinstance(owned_count, int)
            or owned_count < 0
            or not isinstance(local_process, dict)
        )
        if not local_incomplete and owned_count:
            for key in LOCAL_PROCESS_RESOURCE_FIELDS:
                field = local_process.get(key)
                if (
                    not isinstance(field, dict)
                    or field.get("denominator_owned_terminal_jobs") != owned_count
                    or field.get("numerator_owned_terminal_jobs_with_field") != owned_count
                    or field.get("invalid_owned_terminal_jobs_with_field", 0) != 0
                ):
                    local_incomplete = True
                    break
        resource = _readiness_gate(
            not local_incomplete,
            "owned_local_process_resource_coverage_incomplete"
            if local_incomplete
            else None,
        )

    provider_components: dict[str, dict[str, Any]] = {}
    provider_measurements = resources.get("provider", {}) if isinstance(resources, dict) else {}
    if measurement_contract is None:
        provider_components["contract"] = _readiness_gate(
            False, "measurement_contract_unavailable"
        )
    else:
        for name, declaration in measurement_contract["provider_fields"].items():
            if declaration["availability"] != "available":
                provider_components[name] = _not_applicable_gate(
                    "provider_field_not_baseline_available"
                )
                continue
            field = provider_measurements.get(name) if isinstance(provider_measurements, dict) else None
            terminal_count = terminal_jobs if _is_int(terminal_jobs) else 0
            if terminal_count == 0:
                provider_components[name] = _readiness_gate(
                    False, f"provider_{name}_terminal_jobs_absent"
                )
            elif (
                not isinstance(field, dict)
                or field.get("availability") != "available"
                or field.get("numerator_terminal_jobs_with_field") != terminal_count
                or field.get("invalid_terminal_jobs_with_field", 0) != 0
            ):
                provider_components[name] = _readiness_gate(
                    False, f"provider_{name}_measurement_incomplete"
                )
            else:
                provider_components[name] = _readiness_gate(True)

    components = {
        "queue": queue,
        "resources": resource,
        "stop": stop_gate,
        "provider_fields": provider_components,
    }
    failed = next(
        (component.get("reason", "operational_measurement_incomplete")
         for component in (queue, resource, stop_gate, *provider_components.values())
         if not component["passed"]),
        None,
    )
    gate = _readiness_gate(failed is None, failed)
    gate["components"] = components
    return gate


def summarize_comparison_readiness(
    coherent: bool,
    commands: dict[str, Any],
    evidence: dict[str, dict[str, int]],
    *,
    root: Path | None = None,
    events: Iterable[dict[str, Any]] = (),
    event_summary: dict[str, Any] | None = None,
    measurement: dict[str, Any] | None = None,
    release_version: str = "unknown",
    source_root: str | Path | None = None,
) -> dict[str, Any]:
    """Report comparison prerequisites without treating canonical coherence as enough."""

    scan = commands.get("scan")
    if not isinstance(scan, dict) or scan.get("availability") != "available":
        command_scan = _readiness_gate(
            False,
            str(scan.get("reason"))
            if isinstance(scan, dict) and isinstance(scan.get("reason"), str)
            else "command_log_scan_unavailable",
        )
    elif commands.get("truncated"):
        command_scan = _readiness_gate(False, "command_log_scan_truncated")
    elif any(
        commands.get(group, {}).get(status, 0)
        for group in ("meta", "digest")
        for status in ("missing", "invalid")
    ):
        command_scan = _readiness_gate(False, "command_envelopes_incomplete")
    elif (
        commands.get("directories", 0)
        != commands.get("v2_hashes", {}).get("verified", 0)
        or any(
            commands.get("v2_hashes", {}).get(status, 0)
            for status in ("missing", "invalid", "oversized")
        )
    ):
        command_scan = _readiness_gate(False, "command_hashes_incomplete")
    else:
        command_scan = _readiness_gate(True)

    lifecycle = commands.get("lifecycle")
    if not isinstance(lifecycle, dict):
        command_lifecycle = _readiness_gate(False, "command_lifecycle_not_scanned")
    elif not lifecycle.get("paired_events"):
        command_lifecycle = _readiness_gate(
            False, "command_lifecycle_pairs_absent"
        )
    elif any(
        lifecycle.get(key)
        for key in (
            "requested_only",
            "completed_only",
            "envelope_only",
            "event_only",
            "duplicate_requested_events",
            "duplicate_completed_events",
        )
    ):
        command_lifecycle = _readiness_gate(
            False, "command_lifecycle_incomplete"
        )
    elif not (
        lifecycle.get("requested")
        == lifecycle.get("completed")
        == lifecycle.get("paired_events")
        == lifecycle.get("envelopes")
        == lifecycle.get("envelopes_with_events")
        == lifecycle.get("requested_event_count")
        == lifecycle.get("completed_event_count")
    ):
        command_lifecycle = _readiness_gate(
            False, "command_lifecycle_not_exact"
        )
    else:
        command_lifecycle = _readiness_gate(True)

    evidence_complete = True
    evidence_reason = "evidence_references_incomplete"
    event_list = list(events)
    no_submit_plans = {
        event["payload"].get("plan_id")
        for event in event_list
        if event["event_type"] == "execution.planned"
        and event["payload"].get("semantic_action") == "no_submit_evidence"
    }
    ordinary_terminal_present = any(
        event["event_type"] in EXECUTION_TERMINAL_TYPES
        and event["payload"].get("plan_id") not in no_submit_plans
        for event in event_list
    )
    terminal_evidence_present = any(
        event["event_type"] in EXECUTION_TERMINAL_TYPES
        and (
            event["payload"].get("plan_id") not in no_submit_plans
            or bool(event["payload"].get("evidence_root"))
        )
        for event in event_list
    )
    for group in (
        "terminal_response_path",
        "terminal_evidence_root",
        "plan_evidence_paths",
    ):
        counts = evidence.get(group, {})
        references = counts.get("references") if isinstance(counts, dict) else None
        if group == "terminal_response_path" and not ordinary_terminal_present and references == 0:
            continue
        if group == "terminal_evidence_root" and not terminal_evidence_present and references == 0:
            continue
        if not _is_int(references) or references == 0:
            evidence_complete = False
            evidence_reason = "evidence_references_absent"
            break
        if (
            counts.get("present") != references
            or any(counts.get(key) for key in ("empty", "missing", "rejected"))
        ):
            evidence_complete = False
            break
    manifest_evidence = (
        _evidence_manifest_gate(event_list, root, source_root)
        if root is not None
        else _readiness_gate(False, "evidence_manifest_not_supplied")
    )
    if not evidence_complete:
        evidence_gate = _readiness_gate(False, evidence_reason)
    elif not manifest_evidence["passed"]:
        evidence_gate = _readiness_gate(
            False, str(manifest_evidence.get("reason", "evidence_manifest_incomplete"))
        )
    else:
        evidence_gate = _readiness_gate(True)
    evidence_gate["manifest"] = manifest_evidence
    baseline_binding = (
        summarize_baseline_binding(root, event_list, release_version)
        if root is not None
        else _readiness_gate(False, "baseline_binding_not_supplied")
    )
    binding = baseline_binding.get("binding") if baseline_binding.get("passed") else None
    measurement_generations = (
        binding.get("generations") if isinstance(binding, dict) else None
    )
    scoring_chain = _scoring_chain_gate(event_list, measurement_generations)
    attempt_coverage = _typed_attempt_coverage_gate(event_list)
    temporal_coverage = _measurement_temporal_coverage_gate(event_list)
    timeline_generation = _measurement_timeline_generation_gate(
        event_list, measurement_generations
    )
    measurement_contract = (
        _measurement_contract(binding.get("measurement_contract"))
        if isinstance(binding, dict)
        else None
    )
    operational = _operational_applicability_gate(
        event_summary or {},
        measurement or {},
        event_list,
        measurement_contract,
        measurement_generations,
    )
    gates = {
        "canonical_coherence": _readiness_gate(
            coherent, None if coherent else "canonical_events_not_coherent"
        ),
        "command_scan": command_scan,
        "command_lifecycle": command_lifecycle,
        "evidence_completeness": evidence_gate,
        "baseline_binding": baseline_binding,
        "final_scoring_chain_lineage": scoring_chain,
        "typed_attempt_coverage": attempt_coverage,
        "measurement_temporal_coverage": temporal_coverage,
        "measurement_timeline_generation": timeline_generation,
        "queue_stop_resource_applicability": operational,
    }
    missing_gates = sorted(name for name, gate in gates.items() if not gate["passed"])
    comparison_eligible = not missing_gates
    return {
        "comparison_eligible": comparison_eligible,
        "missing_gates": missing_gates,
        "effectiveness_claims": {
            "availability": "not_available",
            "reason": "causal_effectiveness_not_established",
        },
        "gates": gates,
    }


def build_report(root: Path, source_root: str | Path | None = None) -> dict[str, Any]:
    """Build a versioned report using only read operations on ``root``."""

    root = root.resolve()
    events, errors = read_canonical_events(root)
    warnings: list[dict[str, str]] = []
    sqlite_comparison = compare_sqlite_events(root, events)
    if sqlite_comparison.get("present") and not sqlite_comparison.get("matches_jsonl"):
        _error(errors, str(sqlite_comparison.get("error", "sqlite.logical_mismatch")))
    elif not sqlite_comparison.get("present"):
        _warning(warnings, "sqlite.missing")
    version_path = _inside_runtime(root, root / "VERSION")
    release_version = "unknown"
    if version_path is not None and version_path.is_file():
        try:
            if version_path.stat().st_size <= 64:
                release_version = version_path.read_text(
                    encoding="utf-8", errors="replace"
                ).strip()
        except OSError:
            release_version = "unknown"
    event_summary = summarize_events(events)
    measurement = summarize_measurement(events)
    command_summary = summarize_command_logs(root, source_root, events)
    evidence_summary = summarize_evidence(root, events, source_root)
    queue_watch = summarize_files(root, root / "logs" / "queue-watch")
    measurement["queue_normalized_rates"] = summarize_queue_normalized_rates(
        queue_watch, measurement["event_window"]
    )
    coherent = not errors
    report = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "report_kind": "rookery.telemetry",
        "release_version": release_version,
        "coherent": coherent,
        "canonical": {
            "jsonl_rows": len(events),
            "sqlite": sqlite_comparison,
        },
        "events": event_summary,
        "measurement": measurement,
        "commands": command_summary,
        "queue_watch": queue_watch,
        "evidence": evidence_summary,
        "comparison_readiness": summarize_comparison_readiness(
            coherent,
            command_summary,
            evidence_summary,
            root=root,
            events=events,
            event_summary=event_summary,
            measurement=measurement,
            release_version=release_version,
            source_root=source_root,
        ),
        "errors": errors,
        "warnings": warnings,
    }
    logger.info("Built privacy-safe telemetry report with %d canonical events", len(events))
    return report


def write_report(report: dict[str, Any], output: Path, analyzed_root: Path) -> None:
    """Atomically write an explicit report output without modifying the analyzed root."""

    target = output.resolve()
    try:
        target.relative_to(analyzed_root.resolve())
    except ValueError:
        pass
    else:
        raise TelemetryValidationError("report output must be outside the analyzed runtime root")
    target.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{target.name}.", dir=str(target.parent))
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(report, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, target)
    finally:
        if temporary.exists():
            temporary.unlink(missing_ok=True)


def main(argv: Sequence[str] | None = None) -> int:
    """Run the standalone telemetry reporter."""

    parser = argparse.ArgumentParser(description="Read-only, privacy-safe Rookery telemetry report")
    parser.add_argument("runtime_root", type=Path, help="completed Rookery runtime root to analyze")
    parser.add_argument("--source-root", help="absolute deployed root used by telemetry evidence paths")
    parser.add_argument("--output", type=Path, help="atomic JSON output path outside the analyzed runtime")
    arguments = parser.parse_args(argv)
    report = build_report(arguments.runtime_root, arguments.source_root)
    try:
        if arguments.output is None:
            json.dump(report, sys.stdout, ensure_ascii=False, indent=2, sort_keys=True)
            sys.stdout.write("\n")
        else:
            write_report(report, arguments.output, arguments.runtime_root)
    except (OSError, TelemetryValidationError):
        logger.error("Unable to write telemetry report")
        return 2
    return 0 if report["coherent"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
