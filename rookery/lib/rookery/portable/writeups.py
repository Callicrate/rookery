from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
from typing import Any

from .completion import resolve_canonical_completion
from .owned_paths import objective_storage_component
from .store import EventStore
from .util import (
    atomic_write_json,
    atomic_write_text,
    canonical_json,
    contained_private_path,
    ensure_private_dir,
    ensure_private_file,
    file_lock,
    iso_now,
)


_CAPSULE_CANONICAL_FIELDS = (
    "objective_id",
    "action_reference",
    "scorer_evidence",
    "reproduction_path",
    "material_provenance",
    "dead_path_checkpoint",
)
_CAPSULE_FILE_FIELDS = frozenset(
    (*_CAPSULE_CANONICAL_FIELDS, "capsule_id", "canonical_sha256", "created_at")
)
_EVIDENCE_CAPSULE_FILE_FIELDS = frozenset(
    (
        *_CAPSULE_CANONICAL_FIELDS,
        "evidence_capsule_id",
        "canonical_sha256",
        "created_at",
    )
)


def _canonical_capsule_payload(payload: dict[str, Any]) -> dict[str, Any]:
    try:
        return {field: payload[field] for field in _CAPSULE_CANONICAL_FIELDS}
    except KeyError as exc:
        raise ValueError("existing capsule is missing canonical payload fields") from exc


def _capsule_hash(payload: dict[str, Any]) -> str:
    return hashlib.sha256(
        canonical_json(_canonical_capsule_payload(payload)).encode("utf-8")
    ).hexdigest()


def _capsule_id(canonical_hash: str, *, evidence_only: bool = False) -> str:
    prefix = "evidence_capsule" if evidence_only else "capsule"
    return f"{prefix}_{canonical_hash}"


def _capsule_event_id(canonical_hash: str, *, evidence_only: bool = False) -> str:
    prefix = "evidence.capsule" if evidence_only else "solve.capsule"
    return f"{prefix}:{canonical_hash}"


def _validate_capsule_file(
    payload: Any, *, evidence_only: bool = False
) -> dict[str, Any]:
    fields = _EVIDENCE_CAPSULE_FILE_FIELDS if evidence_only else _CAPSULE_FILE_FIELDS
    identity_field = "evidence_capsule_id" if evidence_only else "capsule_id"
    if not isinstance(payload, dict) or set(payload) != fields:
        raise ValueError("existing capsule has an invalid schema")
    canonical = _canonical_capsule_payload(payload)
    for field in _CAPSULE_CANONICAL_FIELDS:
        if field == "material_provenance":
            if not isinstance(canonical[field], list) or not all(
                isinstance(item, str) for item in canonical[field]
            ):
                raise ValueError("existing capsule has invalid material provenance")
        elif not isinstance(canonical[field], str):
            raise ValueError(f"existing capsule field {field} must be text")
    for field in (
        "objective_id",
        "action_reference",
        "scorer_evidence",
        "reproduction_path",
    ):
        if not canonical[field]:
            raise ValueError(f"existing capsule field {field} must not be empty")
    canonical_hash = _capsule_hash(canonical)
    if payload["canonical_sha256"] != canonical_hash:
        raise ValueError("existing capsule canonical_sha256 does not match payload")
    if payload[identity_field] != _capsule_id(
        canonical_hash, evidence_only=evidence_only
    ):
        raise ValueError("existing capsule has an unexpected capsule_id")
    if not isinstance(payload["created_at"], str) or not payload["created_at"]:
        raise ValueError("existing capsule has an invalid created_at")
    return payload


def _capsule_event_exists(
    store: EventStore, event_type: str, event_id: str, payload: dict[str, Any]
) -> bool:
    events = getattr(store, "events", None)
    if callable(events):
        try:
            capsule_events = events(event_type)
        except TypeError:
            return False
        if not isinstance(capsule_events, list):
            return False
        for event in capsule_events:
            if not isinstance(event, dict):
                continue
            event_payload = event.get("payload", {})
            if event.get("event_id") == event_id:
                if event_payload != payload:
                    raise ValueError("existing capsule event does not match capsule file")
                return True
    elif isinstance(events, list):
        for recorded_type, event_payload in events:
            if recorded_type != event_type:
                continue
            if event_payload == payload:
                return True
    return False


def _writeup_directory(root: Path, objective_id: str) -> Path:
    component = objective_storage_component(objective_id)
    writeups = contained_private_path(root, root, "writeups")
    return contained_private_path(root, writeups, component)


def _legacy_capsule_files(root: Path) -> list[tuple[Path, str]]:
    """Find existing private solve-capsule files without trusting the ledger.

    A historical file is evidence, not ownership.  The caller compares it to a
    canonical ``solve.capsule`` event and accepted execution before allowing it
    to satisfy closeout.
    """

    writeups = contained_private_path(root, root, "writeups")
    try:
        base_info = os.lstat(writeups)
    except FileNotFoundError:
        return []
    if stat.S_ISLNK(base_info.st_mode) or not stat.S_ISDIR(base_info.st_mode):
        raise ValueError("writeups root is not a private directory")
    files: list[tuple[Path, str]] = []
    try:
        entries = sorted(writeups.iterdir(), key=lambda item: item.name)
    except OSError as exc:
        raise ValueError("unable to enumerate private writeups") from exc
    for entry in entries:
        try:
            directory = contained_private_path(root, writeups, entry.name)
            directory_info = os.lstat(directory)
        except FileNotFoundError:
            continue
        except ValueError as exc:
            raise ValueError("writeup storage component is invalid") from exc
        if stat.S_ISLNK(directory_info.st_mode) or not stat.S_ISDIR(
            directory_info.st_mode
        ):
            raise ValueError("writeup storage component is not a private directory")
        capsule_path = contained_private_path(root, directory, "CAPSULE.json")
        try:
            capsule_info = os.lstat(capsule_path)
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(capsule_info.st_mode) or not stat.S_ISREG(capsule_info.st_mode):
            files.append((capsule_path, ""))
            continue
        try:
            ensure_private_file(capsule_path)
            payload = _validate_capsule_file(
                json.loads(capsule_path.read_text(encoding="utf-8"))
            )
        except (OSError, ValueError, json.JSONDecodeError):
            files.append((capsule_path, ""))
            continue
        files.append((capsule_path, str(payload.get("objective_id") or "")))
    return files


def create_capsule(
    store: EventStore,
    root: Path,
    *,
    objective_id: str,
    action_reference: str,
    scorer_evidence: str,
    reproduction_path: str,
    material_provenance: list[str],
    dead_path_checkpoint: str,
    actor: str = "coordinator",
) -> dict[str, Any]:
    if not all([objective_id, action_reference, scorer_evidence, reproduction_path]):
        raise ValueError(
            "objective, action reference, scorer evidence, and reproduction path are required"
        )
    capsule_dir = _writeup_directory(root, objective_id)
    writeups = contained_private_path(root, root, "writeups")
    state = contained_private_path(root, root, "state")
    lock_path = contained_private_path(root, state, "mutation.lock")
    ensure_private_dir(state)
    with file_lock(lock_path):
        resolution = resolve_canonical_completion(
            store, objective_id=objective_id, plan_id=action_reference
        )
        if resolution.get("state") == "denied":
            raise ValueError(
                "capsule requires canonical execution truth: "
                + str(resolution.get("reason") or "completion resolution failed")
            )
        if scorer_evidence != resolution.get("scorer_evidence"):
            raise ValueError(
                "scorer evidence must equal the canonical terminal evidence root"
            )
        evidence_only = resolution.get("state") == "evidence"
        canonical_payload = {
            "objective_id": objective_id,
            "action_reference": action_reference,
            "scorer_evidence": scorer_evidence,
            "reproduction_path": reproduction_path,
            "material_provenance": material_provenance,
            "dead_path_checkpoint": dead_path_checkpoint,
        }
        canonical_hash = _capsule_hash(canonical_payload)
        capsule_name = "EVIDENCE_CAPSULE.json" if evidence_only else "CAPSULE.json"
        capsule_path = contained_private_path(root, capsule_dir, capsule_name)
        ensure_private_dir(writeups)
        ensure_private_dir(capsule_dir)
        if capsule_path.exists() or capsule_path.is_symlink():
            ensure_private_file(capsule_path)
            try:
                payload = _validate_capsule_file(
                    json.loads(capsule_path.read_text(encoding="utf-8")),
                    evidence_only=evidence_only,
                )
            except (OSError, json.JSONDecodeError) as exc:
                raise ValueError(
                    f"unable to read existing capsule: {capsule_path}"
                ) from exc
            if payload["canonical_sha256"] != canonical_hash:
                raise ValueError("capsule already exists with a different canonical payload")
        else:
            payload = {
                (
                    "evidence_capsule_id" if evidence_only else "capsule_id"
                ): _capsule_id(canonical_hash, evidence_only=evidence_only),
                **canonical_payload,
                "canonical_sha256": canonical_hash,
                "created_at": iso_now(),
            }
            atomic_write_json(capsule_path, payload, mode=0o600)
            ensure_private_file(capsule_path)
        event_payload = {
            **payload,
            "path": capsule_path.relative_to(Path(root).absolute()).as_posix(),
        }
        event_type = "evidence.capsule" if evidence_only else "solve.capsule"
        event_id = _capsule_event_id(canonical_hash, evidence_only=evidence_only)
        if not _capsule_event_exists(store, event_type, event_id, event_payload):
            store.append(
                event_type,
                event_payload,
                actor=actor,
                event_id=event_id,
            )
        store.rebuild()
        return payload


def create_writeup(
    root: Path, objective_id: str, title: str, voice_file: str = "docs/voice.md"
) -> Path:
    directory = _writeup_directory(root, objective_id)
    writeups = contained_private_path(root, root, "writeups")
    path = contained_private_path(root, directory, "WRITEUP.md")
    ensure_private_dir(writeups)
    ensure_private_dir(directory)
    if path.exists() or path.is_symlink():
        ensure_private_file(path)
        return path
    text = f"""# {title}

> Writing authority: `{voice_file}`

## Summary

## Objective And Context

## Artifacts And Provenance

## Environment

## Method

## Commands And Reproduction

## Verification And Scorer Truth

## Final Action Or Answer Reference

## Rejected Near Misses And Dead Paths

## Lessons For Reproduction
"""
    atomic_write_text(path, text, mode=0o600)
    ensure_private_file(path)
    return path


def check_writeups(
    store: EventStore, root: Path, manifest: dict[str, Any], *, closeout: bool = False
) -> dict[str, Any]:
    projection = store.rebuild()
    capsules = projection["current"].get("solve_capsules", {})
    evidence_capsules = projection["current"].get("evidence_capsules", {})
    missing_capsules: list[str] = []
    missing_evidence_capsules: list[str] = []
    missing_writeups: list[str] = []
    invalid: list[dict[str, Any]] = []
    unverified_capsules: list[dict[str, str]] = []
    unverified_keys: set[str] = set()
    canonical_capsule_paths: set[Path] = set()
    completed: dict[str, dict[str, str]] = {}
    evidence_completed: dict[str, dict[str, str]] = {}

    def add_unverified(objective: str, *, key: str) -> None:
        if key in unverified_keys:
            return
        unverified_keys.add(key)
        unverified_capsules.append(
            {
                "objective_id": objective or "unknown",
                "status": "unverified_legacy",
            }
        )
    for execution in projection["current"].get("executions", {}).values():
        if not isinstance(execution, dict) or execution.get("status") != "completed":
            continue
        objective = execution.get("objective_id")
        plan_id = execution.get("plan_id")
        if not isinstance(objective, str) or not isinstance(plan_id, str):
            continue
        resolution = resolve_canonical_completion(
            store, objective_id=objective, plan_id=plan_id
        )
        if resolution.get("state") == "accepted":
            completed[objective] = resolution
        elif resolution.get("state") == "evidence":
            evidence_completed[objective] = resolution

    def verify_capsule(
        objective: str,
        capsule: Any,
        path: Path,
        resolution: dict[str, str],
        *,
        evidence_only: bool,
    ) -> bool:
        if not isinstance(capsule, dict) or not path.exists():
            return False
        try:
            path_info = os.lstat(path)
            if stat.S_ISLNK(path_info.st_mode) or not stat.S_ISREG(path_info.st_mode):
                raise ValueError("capsule file is not a private regular file")
            ensure_private_file(path)
            file_capsule = _validate_capsule_file(
                json.loads(path.read_text(encoding="utf-8")),
                evidence_only=evidence_only,
            )
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            invalid.append({"objective_id": objective, "error": str(exc)})
            return True
        identity_field = "evidence_capsule_id" if evidence_only else "capsule_id"
        expected_path = path.relative_to(Path(root).absolute()).as_posix()
        if (
            capsule.get("objective_id") != objective
            or capsule.get(identity_field) != file_capsule[identity_field]
            or capsule.get("canonical_sha256") != file_capsule["canonical_sha256"]
            or capsule.get("path") != expected_path
        ):
            invalid.append(
                {
                    "objective_id": objective,
                    "error": "capsule file lacks matching canonical ownership",
                }
            )
            return True
        if (
            file_capsule.get("action_reference") != resolution["plan_id"]
            or file_capsule.get("scorer_evidence") != resolution["scorer_evidence"]
        ):
            invalid.append(
                {
                    "objective_id": objective,
                    "error": "capsule does not bind its canonical completion",
                }
            )
        return True

    for objective, resolution in sorted(completed.items()):
        try:
            directory = _writeup_directory(root, objective)
            capsule_path = contained_private_path(root, directory, "CAPSULE.json")
            writeup_path = contained_private_path(root, directory, "WRITEUP.md")
        except ValueError as exc:
            invalid.append({"objective_id": objective, "error": str(exc)})
            continue
        capsule = capsules.get(objective)
        if not verify_capsule(
            objective, capsule, capsule_path, resolution, evidence_only=False
        ):
            missing_capsules.append(objective)
        required_now = manifest.get("writeups", {}).get("mode") == "immediate" or (
            closeout
            and manifest.get("writeups", {}).get("full_required_at_closeout", True)
        )
        if required_now and not writeup_path.exists():
            missing_writeups.append(objective)
        if writeup_path.exists():
            text = writeup_path.read_text(errors="replace")
            required = [
                "## Summary",
                "## Artifacts And Provenance",
                "## Commands And Reproduction",
                "## Verification And Scorer Truth",
            ]
            absent = [section for section in required if section not in text]
            if absent:
                invalid.append({"objective_id": objective, "missing_sections": absent})

    for objective, resolution in sorted(evidence_completed.items()):
        try:
            directory = _writeup_directory(root, objective)
            capsule_path = contained_private_path(
                root, directory, "EVIDENCE_CAPSULE.json"
            )
        except ValueError as exc:
            invalid.append({"objective_id": objective, "error": str(exc)})
            continue
        if not verify_capsule(
            objective,
            evidence_capsules.get(objective),
            capsule_path,
            resolution,
            evidence_only=True,
        ):
            missing_evidence_capsules.append(objective)

    for objective, capsule in sorted(capsules.items()):
        if not isinstance(objective, str) or not isinstance(capsule, dict):
            continue
        resolution = resolve_canonical_completion(
            store,
            objective_id=objective,
            plan_id=str(capsule.get("action_reference") or ""),
        )
        if (
            resolution.get("state") != "accepted"
            or capsule.get("action_reference") != resolution.get("plan_id")
            or capsule.get("scorer_evidence") != resolution.get("scorer_evidence")
        ):
            add_unverified(objective, key=f"objective:{objective}")
            continue
        try:
            expected_path = contained_private_path(
                root, _writeup_directory(root, objective), "CAPSULE.json"
            )
        except ValueError:
            add_unverified(objective, key=f"objective:{objective}")
            continue
        if (
            capsule.get("objective_id") != objective
            or capsule.get("path")
            != expected_path.relative_to(Path(root).absolute()).as_posix()
        ):
            add_unverified(objective, key=f"objective:{objective}")
            continue
        canonical_capsule_paths.add(expected_path)

    try:
        legacy_files = _legacy_capsule_files(root)
    except ValueError as exc:
        invalid.append({"objective_id": "unknown", "error": str(exc)})
    else:
        for path, objective in legacy_files:
            if path in canonical_capsule_paths:
                continue
            add_unverified(
                objective,
                key=(
                    f"objective:{objective}"
                    if objective
                    else f"path:{path.relative_to(Path(root).absolute()).as_posix()}"
                ),
            )
    return {
        "completed": sorted(completed),
        "evidence_completed": sorted(evidence_completed),
        "missing_capsules": missing_capsules,
        "missing_evidence_capsules": missing_evidence_capsules,
        "missing_writeups": missing_writeups,
        "invalid_writeups": invalid,
        "unverified_capsules": unverified_capsules,
        "ok": (
            not missing_capsules
            and not missing_evidence_capsules
            and not missing_writeups
            and not invalid
            and (not closeout or not unverified_capsules)
        ),
    }
