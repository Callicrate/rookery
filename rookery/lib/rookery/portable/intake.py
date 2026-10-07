"""Read-only proof that a challenge intake is complete enough for solver work."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from collections import Counter
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

from .util import contained_private_path


SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_MAX_MISSING_MATERIAL = 128
_HASH_BLOCK_BYTES = 64 * 1024


def _result(reasons: list[str]) -> dict[str, Any]:
    """Return the small, value-free public eligibility shape."""

    return {"ready": not reasons, "reasons": reasons}


def _relative_parts(value: object) -> tuple[str, ...] | None:
    if not isinstance(value, str) or not value or value != value.strip() or "\\" in value:
        return None
    posix = PurePosixPath(value)
    windows = PureWindowsPath(value)
    if posix.is_absolute() or windows.is_absolute() or windows.drive:
        return None
    parts = posix.parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        return None
    return parts


def _sha256(value: object) -> bool:
    return isinstance(value, str) and SHA256.fullmatch(value) is not None


def _nonnegative_integer(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _expected_attachment_names(files: object) -> list[str] | None:
    if not isinstance(files, list):
        return None
    names: list[str] = []
    for index, item in enumerate(files):
        if not isinstance(item, dict):
            return None
        name = item.get("name") or item.get("path") or f"file-{index}"
        if not isinstance(name, str) or not name:
            return None
        names.append(name)
    return names


def _attachment_keys(files: object) -> list[str] | None:
    if not isinstance(files, list):
        return None
    try:
        return [capture_key(index, item) for index, item in enumerate(files)]
    except ValueError:
        return None


def capture_key(index: int, item: object) -> str:
    """Return the durable identity for one declared attachment occurrence."""

    if not isinstance(index, int) or isinstance(index, bool) or index < 0:
        raise ValueError("capture index must be a non-negative integer")
    if not isinstance(item, dict):
        raise ValueError("capture item must be an object")
    try:
        encoded = json.dumps(
            {"index": index, "item": item},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError("capture item must be canonical JSON") from exc
    return hashlib.sha256(encoded).hexdigest()


def _missing_material_is_empty(value: object) -> bool:
    return (
        isinstance(value, list)
        and len(value) <= _MAX_MISSING_MATERIAL
        and all(
            isinstance(item, str)
            and item
            and len(item) <= 256
            and "\n" not in item
            and "\r" not in item
            for item in value
        )
        and not value
    )


def _challenge_field(row: dict[str, Any], *names: str) -> Any:
    """Read a normalized field, falling back to adapter raw data.

    Inventory adapters normally expose the normalized spellings, while older
    stored snapshots may only have their original platform keys in ``raw``.
    Admission must make the same decision for either representation.
    """

    for name in names:
        if name in row:
            return row[name]
    raw = row.get("raw")
    if isinstance(raw, dict):
        for name in names:
            if name in raw:
                return raw[name]
    return None


def _normalized_mode(row: dict[str, Any]) -> str:
    value = _challenge_field(row, "submission_mode", "submissionMode")
    return value.casefold() if isinstance(value, str) else ""


def _normalized_classification(row: dict[str, Any]) -> str:
    value = row.get("classification")
    return value.casefold() if isinstance(value, str) else ""


def _explicit_solver_reason(row: dict[str, Any]) -> str:
    """Return a persisted controller reason only when it is stable and known."""

    if row.get("solver_eligible") is not False:
        return ""
    value = row.get("solver_ineligible_reason")
    if not isinstance(value, str):
        return "solver_ineligible"
    reason = value.casefold()
    return reason if reason in {
        "hidden",
        "intake_invalid",
        "intake_partial",
        "intake_pending",
        "locked",
        "manual",
        "operator_only",
        "policy_blocked",
        "solved",
        "unsupported",
        "unavailable",
    } else "solver_ineligible"


def platform_solver_eligibility(row: object) -> dict[str, Any]:
    """Classify explicit platform restrictions without touching intake state."""

    if not isinstance(row, dict):
        return _result(["challenge_invalid"])
    classification = _normalized_classification(row)
    mode = _normalized_mode(row)
    reasons: list[str] = []
    if row.get("platform_present") is False:
        reasons.append("challenge_unavailable")
    if classification == "policy_blocked" or row.get("policy_blocked") is True:
        reasons.append("challenge_policy_blocked")
    if classification == "operator_only" or row.get("operator_only") is True:
        reasons.append("challenge_operator_only")
    if (
        classification == "solved"
        or _challenge_field(row, "solved", "isSolved") is True
        or mode == "already_solved"
    ):
        reasons.append("challenge_solved")
    if (
        _challenge_field(row, "hidden") is True
        or _challenge_field(row, "visible") is False
        or classification == "hidden"
    ):
        reasons.append("challenge_hidden")
    if _challenge_field(row, "locked") is True or mode == "locked":
        reasons.append("challenge_locked")
    if (
        _challenge_field(row, "solvable") is False
        or _challenge_field(row, "unsolvable") is True
        or classification == "unsolvable"
    ):
        reasons.append("challenge_unsupported")
    if mode == "manual":
        reasons.append("challenge_manual")
    if mode == "multiple_choice":
        reasons.append("challenge_multiple_choice")
    if mode == "unsupported":
        reasons.append("challenge_unsupported")
    if (
        _challenge_field(row, "submittable") is False
        or _challenge_field(row, "platform_submittable", "platformSubmittable")
        is False
    ):
        reasons.append("challenge_not_submittable")
    result = _result(list(dict.fromkeys(reasons)))
    result["reason"] = (
        _solver_ineligible_reason(row, True) if reasons else _explicit_solver_reason(row)
    )
    if not reasons and result["reason"]:
        result["ready"] = False
        result["reasons"] = ["challenge_explicitly_ineligible"]
    return result


def _intake_metadata_eligibility(row: object) -> dict[str, Any]:
    if not isinstance(row, dict):
        return _result(["intake_record_invalid"])
    reasons: list[str] = []
    if _relative_parts(row.get("detail_path")) is None:
        reasons.append("detail_path_invalid")
    if not isinstance(row.get("ingested_at"), str) or not row["ingested_at"].strip():
        reasons.append("ingested_at_missing")
    if row.get("intake_state") != "complete":
        reasons.append("intake_state_incomplete")
    if not _sha256(row.get("detail_sha256")):
        reasons.append("detail_sha256_invalid")
    if not _nonnegative_integer(row.get("detail_bytes")):
        reasons.append("detail_bytes_invalid")
    if not _missing_material_is_empty(row.get("intake_missing_material")):
        reasons.append("intake_missing_material")
    if row.get("resources_truncated") is True:
        reasons.append("resources_truncated")
    if row.get("resources_complete") is False:
        reasons.append("resources_incomplete")

    expected_names = _expected_attachment_names(row.get("files"))
    captured = row.get("captured_files")
    if expected_names is None:
        reasons.append("expected_files_invalid")
    if not isinstance(captured, list):
        reasons.append("captured_files_invalid")
        return _result(reasons)
    if not _nonnegative_integer(row.get("expected_file_count")):
        reasons.append("expected_file_count_invalid")
    elif expected_names is not None and row["expected_file_count"] != len(expected_names):
        reasons.append("expected_file_count_mismatch")
    if expected_names is not None:
        try:
            expected_keys = [
                capture_key(index, item) for index, item in enumerate(row["files"])
            ]
        except ValueError:
            expected_keys = []
            reasons.append("expected_files_invalid")
    else:
        expected_keys = []
    successful: list[dict[str, Any]] = []
    for item in captured:
        if not isinstance(item, dict):
            reasons.append("captured_file_invalid")
            continue
        if item.get("error") not in (None, ""):
            continue
        successful.append(item)
        if "capture_key" in item and (
            not isinstance(item["capture_key"], str) or not item["capture_key"]
        ):
            reasons.append("captured_file_key_invalid")
        if "capture_key" not in item:
            reasons.append("captured_file_key_invalid")
        if _relative_parts(item.get("path")) is None:
            reasons.append("captured_file_path_invalid")
        if not _sha256(item.get("sha256")):
            reasons.append("captured_file_sha256_invalid")
        if not _nonnegative_integer(item.get("bytes")):
            reasons.append("captured_file_bytes_invalid")
    if not _nonnegative_integer(row.get("captured_file_count")):
        reasons.append("captured_file_count_invalid")
    elif row["captured_file_count"] != len(successful):
        reasons.append("captured_file_count_mismatch")
    if expected_names is not None and Counter(expected_keys) != Counter(
        item.get("capture_key") for item in successful
    ):
        reasons.append("captured_files_mismatch")
    return _result(list(dict.fromkeys(reasons)))


def _read_private_stable(path: Path, *, expected_sha256: str, expected_bytes: int) -> bytes:
    """Read exactly one unchanged 0600 regular file without following a link."""

    try:
        before = path.lstat()
    except OSError as exc:
        raise ValueError("artifact_missing") from exc
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or stat.S_IMODE(before.st_mode) != 0o600
        or before.st_size != expected_bytes
    ):
        raise ValueError("artifact_unsafe")
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or stat.S_IMODE(opened.st_mode) != 0o600
            or opened.st_size != expected_bytes
            or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
        ):
            raise ValueError("artifact_unsafe")
        digest = hashlib.sha256()
        data = bytearray()
        while True:
            block = os.read(descriptor, _HASH_BLOCK_BYTES)
            if not block:
                break
            digest.update(block)
            data.extend(block)
        after = os.fstat(descriptor)
        if (
            (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            or digest.hexdigest() != expected_sha256
        ):
            raise ValueError("artifact_changed")
        return bytes(data)
    finally:
        os.close(descriptor)


def _artifact_path(root: Path, value: object) -> Path:
    parts = _relative_parts(value)
    if parts is None:
        raise ValueError("artifact_path_invalid")
    try:
        return contained_private_path(root, root, *parts)
    except (OSError, ValueError) as exc:
        raise ValueError("artifact_path_invalid") from exc


def capture_artifact_status(root: Path | str, capture: object) -> dict[str, Any]:
    """Verify one captured attachment for safe reuse during a later intake."""

    if not isinstance(capture, dict):
        return _result(["captured_file_invalid"])
    if capture.get("error") not in (None, ""):
        return _result(["captured_file_error"])
    if _relative_parts(capture.get("path")) is None:
        return _result(["captured_file_path_invalid"])
    if not _sha256(capture.get("sha256")):
        return _result(["captured_file_sha256_invalid"])
    if not _nonnegative_integer(capture.get("bytes")):
        return _result(["captured_file_bytes_invalid"])
    try:
        _read_private_stable(
            _artifact_path(Path(root).absolute(), capture["path"]),
            expected_sha256=str(capture["sha256"]),
            expected_bytes=int(capture["bytes"]),
        )
    except ValueError as exc:
        return _result([str(exc)])
    return _result([])


def capture_artifact_valid(root: Path | str, capture: object) -> bool:
    """Return a boolean form for intake reuse loops."""

    return bool(capture_artifact_status(root, capture)["ready"])


def inspect_intake(root: Path | str, row: object) -> dict[str, Any]:
    """Verify complete intake metadata against its immutable private artifacts."""

    eligibility = _intake_metadata_eligibility(row)
    if not eligibility["ready"]:
        return eligibility
    assert isinstance(row, dict)
    root_path = Path(root).absolute()
    reasons: list[str] = []
    try:
        detail = _read_private_stable(
            _artifact_path(root_path, row["detail_path"]),
            expected_sha256=str(row["detail_sha256"]),
            expected_bytes=int(row["detail_bytes"]),
        )
    except ValueError as exc:
        reasons.append(str(exc))
    else:
        try:
            parsed = json.loads(detail)
        except (UnicodeDecodeError, json.JSONDecodeError):
            reasons.append("detail_json_invalid")
        else:
            if not isinstance(parsed, dict) or str(parsed.get("id") or "") != str(
                row.get("id") or ""
            ):
                reasons.append("detail_challenge_mismatch")
            elif isinstance(parsed, dict):
                detail_keys = (
                    _attachment_keys(parsed.get("files")) if "files" in parsed else None
                )
                if "files" in parsed and detail_keys is None:
                    reasons.append("detail_files_invalid")
                elif detail_keys is not None and detail_keys != _attachment_keys(
                    row.get("files")
                ):
                    reasons.append("detail_files_mismatch")
                if "resources" in parsed:
                    if not isinstance(parsed["resources"], list):
                        reasons.append("detail_resources_invalid")
                    elif parsed["resources"] != row.get("resources"):
                        reasons.append("detail_resources_mismatch")
                for field in ("resources_complete", "resources_truncated"):
                    if field in parsed:
                        if not isinstance(parsed[field], bool):
                            reasons.append(f"detail_{field}_invalid")
                        elif parsed[field] is not row.get(field):
                            reasons.append(f"detail_{field}_mismatch")
    for capture in row["captured_files"]:
        if isinstance(capture, dict) and capture.get("error") not in (None, ""):
            continue
        status = capture_artifact_status(root_path, capture)
        reasons.extend(status["reasons"])
    return _result(list(dict.fromkeys(reasons)))


def solver_eligibility(root: Path | str, row: object) -> dict[str, Any]:
    """Return whether Rookery may send this challenge to a solver."""

    platform = platform_solver_eligibility(row)
    intake = inspect_intake(root, row)
    reasons = list(platform["reasons"])
    if not intake["ready"]:
        reasons.append("intake_invalid")
    result = _result(reasons)
    result["reason"] = _solver_ineligible_reason(row, bool(intake["ready"]))
    return result


def _solver_ineligible_reason(row: object, intake_ready: bool) -> str:
    """Choose one controller-facing reason without exposing artifact details."""

    if not isinstance(row, dict):
        return "intake_invalid"
    if row.get("platform_present") is False:
        return "unavailable"
    classification = _normalized_classification(row)
    mode = _normalized_mode(row)
    if classification == "policy_blocked" or row.get("policy_blocked") is True:
        return "policy_blocked"
    if classification == "operator_only" or row.get("operator_only") is True:
        return "operator_only"
    explicit_reason = _explicit_solver_reason(row)
    if explicit_reason:
        return explicit_reason
    if (
        classification == "solved"
        or _challenge_field(row, "solved", "isSolved") is True
        or mode == "already_solved"
    ):
        return "solved"
    if (
        _challenge_field(row, "hidden") is True
        or _challenge_field(row, "visible") is False
        or classification == "hidden"
    ):
        return "hidden"
    if _challenge_field(row, "locked") is True or mode == "locked":
        return "locked"
    if mode == "manual":
        return "manual"
    if (
        _challenge_field(row, "solvable") is False
        or _challenge_field(row, "unsolvable") is True
        or classification == "unsolvable"
        or mode in {"multiple_choice", "unsupported"}
    ):
        return "unsupported"
    if (
        _challenge_field(row, "submittable") is False
        or _challenge_field(row, "platform_submittable", "platformSubmittable")
        is False
    ):
        return "unsupported"
    if row.get("intake_state") == "pending":
        return "intake_pending"
    if row.get("intake_state") == "partial":
        return "intake_partial"
    if not intake_ready:
        return "intake_invalid"
    return ""


def challenge_intake_status(root: Path | str, challenge: object) -> dict[str, Any]:
    """Compatibility name for callers that need the verified intake status."""

    return solver_eligibility(root, challenge)
