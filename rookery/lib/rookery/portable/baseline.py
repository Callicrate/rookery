"""Bounded, privacy-safe pre-event measurement baseline records."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import stat
import tempfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Sequence

from .manifest import resolve_manifest
from .release import BUILDER_IDENTITY, MANIFEST_SCHEMA_VERSION
from .util import canonical_json, ensure_private_dir, ensure_private_file, tree_hash
from .validator import validate_tree

UTC = dt.timezone.utc
SCHEMA_VERSION = "1"
RECORD_KIND = "rookery.measurement_baseline"
STREAM_CHUNK_BYTES = 64 * 1024
MAX_ARCHIVE_BYTES = 512 * 1024 * 1024
MAX_ARCHIVE_CONTENT_BYTES = 512 * 1024 * 1024
MAX_MANIFEST_BYTES = 8 * 1024 * 1024
MAX_CONFIG_BYTES = 1024 * 1024
MAX_RELEASE_METADATA_BYTES = 1024 * 1024
MAX_SOURCE_NODES = 20_000
MAX_SOURCE_BYTES = 512 * 1024 * 1024
MAX_MANIFEST_FILES = 20_000
MAX_JSON_NODES = 200_000
MAX_JSON_DEPTH = 64
MAX_JSON_STRING_BYTES = 1024 * 1024
MAX_PROVIDER_FIELDS = 32
MAX_ENV_LINES = 4096
MAX_ENV_LINE_BYTES = 64 * 1024

SHA256 = re.compile(r"[0-9a-f]{64}\Z")
SAFE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
SAFE_PROVIDER_ID = re.compile(r"[a-z][a-z0-9_.-]{0,63}\Z")
SAFE_REASON = re.compile(r"[a-z0-9][a-z0-9_.-]{0,63}\Z")
SAFE_ENV_KEY = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}\Z")
CALVER = re.compile(r"\d{4}\.\d{2}\.\d{2}(?:\.\d+)?\Z")
KNOWN_PROVIDER_FIELDS = ("queue", "tokens", "usage")
PROVIDER_ALIASES = {
    "provider_queue": "queue",
    "token": "tokens",
    "provider_tokens": "tokens",
    "provider_usage": "usage",
}
BUILTIN_RUNTIME_PATHS = {
    "ACTIVE_SURFACE.md",
    "AUTH_PAUSED.md",
    "DEAD_PATHS.md",
    "FINDINGS.md",
    "FLAGS.md",
    "HANDOFF.md",
    "NEW_CTF_SETUP.md",
    "PREPARATION.md",
    "START_PROMPT.md",
    "STATUS.md",
    "STOP_PROMPT.md",
    "analysis",
    "captures",
    "control",
    "downloads",
    "evidence",
    "logs",
    "platform/runtime",
    "state",
    "submissions",
    "work",
    "writeups",
}
# A fresh release has exactly one private, operator-edited launch input.  A
# legacy event.json may exist beside it for explicit migration, but baseline
# creation neither reads nor binds that retired format.
EDITABLE_RELEASE_CONFIGS = {".env"}
LEGACY_EVENT_FILE = "event.json"


class MeasurementBaselineError(ValueError):
    """Raised when the baseline cannot be created without weakening its gate."""


def source_root_from_wrapper(wrapper_path: Path) -> Path:
    """Derive the source tree from the installed measurement-baseline wrapper."""

    wrapper = wrapper_path.resolve()
    if wrapper.name != "measurement-baseline" or wrapper.parent.name != "bin":
        raise MeasurementBaselineError("invalid_measurement_baseline_wrapper")
    return wrapper.parents[1]


def _stat_signature(info: os.stat_result) -> tuple[int, int, int, int]:
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)


def _regular_file(path: Path, label: str) -> os.stat_result:
    try:
        info = path.lstat()
    except OSError as exc:
        raise MeasurementBaselineError(f"{label}_missing_or_unreadable") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise MeasurementBaselineError(f"{label}_not_regular")
    return info


def _bounded_file_bytes(
    path: Path, maximum: int, label: str
) -> tuple[bytes, str, os.stat_result]:
    """Read one regular file with a hard byte ceiling and stability check."""

    before = _regular_file(path, label)
    if before.st_size > maximum:
        raise MeasurementBaselineError(f"{label}_too_large")
    digest = hashlib.sha256()
    data = bytearray()
    try:
        with path.open("rb") as handle:
            remaining = maximum + 1
            while remaining:
                chunk = handle.read(min(STREAM_CHUNK_BYTES, remaining))
                if not chunk:
                    break
                data.extend(chunk)
                digest.update(chunk)
                remaining -= len(chunk)
            if len(data) > maximum:
                raise MeasurementBaselineError(f"{label}_too_large")
    except MeasurementBaselineError:
        raise
    except OSError as exc:
        raise MeasurementBaselineError(f"{label}_unreadable") from exc
    after = _regular_file(path, label)
    if _stat_signature(before) != _stat_signature(after) or len(data) != before.st_size:
        raise MeasurementBaselineError(f"{label}_changed")
    return bytes(data), digest.hexdigest(), after


def _bounded_file_hash(
    path: Path, maximum: int, label: str
) -> tuple[str, int, os.stat_result]:
    """Hash one regular file without materializing it in memory."""

    before = _regular_file(path, label)
    if before.st_size > maximum:
        raise MeasurementBaselineError(f"{label}_too_large")
    digest = hashlib.sha256()
    byte_count = 0
    try:
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(STREAM_CHUNK_BYTES)
                if not chunk:
                    break
                byte_count += len(chunk)
                if byte_count > maximum:
                    raise MeasurementBaselineError(f"{label}_too_large")
                digest.update(chunk)
    except MeasurementBaselineError:
        raise
    except OSError as exc:
        raise MeasurementBaselineError(f"{label}_unreadable") from exc
    after = _regular_file(path, label)
    if (
        _stat_signature(before) != _stat_signature(after)
        or byte_count != before.st_size
    ):
        raise MeasurementBaselineError(f"{label}_changed")
    return digest.hexdigest(), byte_count, after


def _no_duplicate_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise MeasurementBaselineError("json_duplicate_key")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise MeasurementBaselineError(f"json_non_finite_number:{value}")


def _validate_json_shape(value: Any) -> None:
    stack: list[tuple[Any, int]] = [(value, 0)]
    nodes = 0
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES:
            raise MeasurementBaselineError("json_node_limit_exceeded")
        if depth > MAX_JSON_DEPTH:
            raise MeasurementBaselineError("json_depth_limit_exceeded")
        if isinstance(current, dict):
            for key, child in current.items():
                if not isinstance(key, str) or len(key) > 256:
                    raise MeasurementBaselineError("json_key_invalid")
                stack.append((child, depth + 1))
        elif isinstance(current, list):
            stack.extend((child, depth + 1) for child in current)
        elif (
            isinstance(current, str)
            and len(current.encode("utf-8")) > MAX_JSON_STRING_BYTES
        ):
            raise MeasurementBaselineError("json_string_too_large")
        elif current is not None and not isinstance(current, (str, int, float, bool)):
            raise MeasurementBaselineError("json_value_invalid")


def _parse_json_bytes(raw: bytes, label: str) -> Any:
    try:
        text = raw.decode("utf-8")
        value = json.loads(
            text,
            object_pairs_hook=_no_duplicate_object,
            parse_constant=_reject_json_constant,
        )
    except MeasurementBaselineError:
        raise
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        RecursionError,
        ValueError,
    ) as exc:
        raise MeasurementBaselineError(f"{label}_malformed") from exc
    _validate_json_shape(value)
    return value


def _read_json_object(
    path: Path, maximum: int, label: str
) -> tuple[dict[str, Any], str, int, os.stat_result]:
    raw, digest, info = _bounded_file_bytes(path, maximum, label)
    value = _parse_json_bytes(raw, label)
    if not isinstance(value, dict):
        raise MeasurementBaselineError(f"{label}_not_object")
    return value, digest, len(raw), info


def _parse_env(raw: bytes) -> dict[str, str]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise MeasurementBaselineError("environment_malformed") from exc
    environment: dict[str, str] = {}
    lines = text.splitlines()
    if len(lines) > MAX_ENV_LINES:
        raise MeasurementBaselineError("environment_line_limit_exceeded")
    for raw_line in lines:
        if len(raw_line.encode("utf-8")) > MAX_ENV_LINE_BYTES:
            raise MeasurementBaselineError("environment_line_too_large")
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise MeasurementBaselineError("environment_malformed")
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not SAFE_ENV_KEY.fullmatch(key) or key in environment:
            raise MeasurementBaselineError("environment_key_invalid")
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        environment[key] = value
    return environment


def _safe_relative_path(value: str, label: str) -> str:
    if not value or "\\" in value or "\x00" in value or len(value) > 1024:
        raise MeasurementBaselineError(f"{label}_path_invalid")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or value != path.as_posix()
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise MeasurementBaselineError(f"{label}_path_invalid")
    return value


def _validate_release_manifest(
    manifest: dict[str, Any], version: str
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], int]:
    legacy_required = {
        "schema_version",
        "identity",
        "version",
        "archive",
        "archive_root",
        "files",
    }
    current_required = legacy_required | {
        "builder_identity",
        "source_tree_sha256",
        "directories",
    }
    schema = manifest.get("schema_version")
    if schema == "1" and set(manifest) == legacy_required:
        directories: list[dict[str, Any]] = []
    elif schema == MANIFEST_SCHEMA_VERSION and set(manifest) == current_required:
        if manifest.get("builder_identity") != BUILDER_IDENTITY:
            raise MeasurementBaselineError("release_manifest_builder_identity_invalid")
        source_tree_sha256 = manifest.get("source_tree_sha256")
        if not isinstance(source_tree_sha256, str) or not SHA256.fullmatch(source_tree_sha256):
            raise MeasurementBaselineError("release_manifest_source_tree_hash_invalid")
        raw_directories = manifest.get("directories")
        if not isinstance(raw_directories, list):
            raise MeasurementBaselineError("release_manifest_directory_invalid")
        directories = []
        seen_directories: set[str] = set()
        for row in raw_directories:
            if not isinstance(row, dict) or set(row) != {"path", "mode"}:
                raise MeasurementBaselineError("release_manifest_directory_invalid")
            path = _safe_relative_path(
                row.get("path") if isinstance(row.get("path"), str) else "",
                "release_manifest",
            )
            if path in seen_directories or row.get("mode") != "0755":
                raise MeasurementBaselineError("release_manifest_directory_invalid")
            seen_directories.add(path)
            directories.append({"path": path, "mode": "0755"})
        if [row["path"] for row in directories] != sorted(seen_directories):
            raise MeasurementBaselineError("release_manifest_directories_not_sorted")
    else:
        raise MeasurementBaselineError("release_manifest_schema_invalid")
    if manifest.get("version") != version or not CALVER.fullmatch(version):
        raise MeasurementBaselineError("release_manifest_version_mismatch")
    for key in ("identity", "archive_root"):
        value = manifest.get(key)
        if (
            not isinstance(value, str)
            or not SAFE_ID.fullmatch(value)
            or value in {".", ".."}
        ):
            raise MeasurementBaselineError(f"release_manifest_{key}_invalid")
    archive_name = manifest.get("archive")
    if (
        not isinstance(archive_name, str)
        or Path(archive_name).name != archive_name
        or len(archive_name) > 255
    ):
        raise MeasurementBaselineError("release_manifest_archive_invalid")
    files = manifest.get("files")
    if (
        not isinstance(files, list)
        or len(files) + len(directories) + 1 > MAX_MANIFEST_FILES
    ):
        raise MeasurementBaselineError("release_manifest_file_limit_exceeded")
    normalized: list[dict[str, Any]] = []
    seen: set[str] = set()
    total_bytes = 0
    for row in files:
        if not isinstance(row, dict) or set(row) != {"path", "bytes", "sha256", "mode"}:
            raise MeasurementBaselineError("release_manifest_file_invalid")
        path = _safe_relative_path(
            row.get("path") if isinstance(row.get("path"), str) else "",
            "release_manifest",
        )
        byte_count = row.get("bytes")
        digest = row.get("sha256")
        mode = row.get("mode")
        if path in seen:
            raise MeasurementBaselineError("release_manifest_duplicate_path")
        if (
            isinstance(byte_count, bool)
            or not isinstance(byte_count, int)
            or byte_count < 0
        ):
            raise MeasurementBaselineError("release_manifest_size_invalid")
        if not isinstance(digest, str) or not SHA256.fullmatch(digest):
            raise MeasurementBaselineError("release_manifest_hash_invalid")
        if not isinstance(mode, str) or not re.fullmatch(r"0[0-7]{3}", mode):
            raise MeasurementBaselineError("release_manifest_mode_invalid")
        total_bytes += byte_count
        if total_bytes > MAX_ARCHIVE_CONTENT_BYTES:
            raise MeasurementBaselineError("release_manifest_bytes_exceeded")
        seen.add(path)
        normalized.append(
            {"path": path, "bytes": byte_count, "sha256": digest, "mode": mode}
        )
    if [row["path"] for row in normalized] != sorted(seen):
        raise MeasurementBaselineError("release_manifest_not_sorted")
    if (
        schema == MANIFEST_SCHEMA_VERSION
        and manifest["source_tree_sha256"]
        != hashlib.sha256(
            b"".join(
                str(row["path"]).encode("utf-8")
                + b"\0"
                + str(row["sha256"]).encode("ascii")
                + b"\0"
                for row in normalized
            )
        ).hexdigest()
    ):
        raise MeasurementBaselineError("release_manifest_source_tree_hash_mismatch")
    return normalized, directories, total_bytes


def _verify_archive(
    archive_path: Path,
    archive_info: os.stat_result,
    manifest: dict[str, Any],
    manifest_files: list[dict[str, Any]],
    manifest_directories: list[dict[str, Any]],
) -> None:
    archive_root = str(manifest["archive_root"])
    expected = {f"{archive_root}/{row['path']}": row for row in manifest_files}
    expected_directories = {
        archive_root,
        *(f"{archive_root}/{row['path']}" for row in manifest_directories),
    }
    seen: set[str] = set()
    seen_directories: set[str] = set()
    try:
        with zipfile.ZipFile(archive_path) as archive:
            infos = archive.infolist()
            if len(infos) > MAX_SOURCE_NODES + 1:
                raise MeasurementBaselineError("archive_entry_limit_exceeded")
            if len({info.filename for info in infos}) != len(infos):
                raise MeasurementBaselineError("archive_duplicate_entry")
            total_bytes = 0
            for info in infos:
                name = info.filename[:-1] if info.is_dir() else info.filename
                _safe_relative_path(name, "archive")
                if not (name == archive_root or name.startswith(f"{archive_root}/")):
                    raise MeasurementBaselineError("archive_root_mismatch")
                if info.flag_bits & 0x1:
                    raise MeasurementBaselineError("archive_encrypted_entry")
                unix_type = (info.external_attr >> 16) & 0o170000
                if unix_type not in {0, stat.S_IFREG, stat.S_IFDIR}:
                    raise MeasurementBaselineError("archive_special_entry")
                if info.is_dir():
                    if manifest.get("schema_version") == MANIFEST_SCHEMA_VERSION:
                        mode = (info.external_attr >> 16) & 0o777
                        if (
                            name not in expected_directories
                            or unix_type not in {0, stat.S_IFDIR}
                            or info.file_size != 0
                            or mode != 0o755
                        ):
                            raise MeasurementBaselineError("archive_directory_mismatch")
                        seen_directories.add(name)
                    continue
                row = expected.get(info.filename)
                if row is None:
                    raise MeasurementBaselineError("archive_unmanifested_entry")
                if info.file_size != row["bytes"]:
                    raise MeasurementBaselineError("archive_member_size_mismatch")
                mode = (info.external_attr >> 16) & 0o777
                if mode != int(row["mode"], 8):
                    raise MeasurementBaselineError("archive_member_mode_mismatch")
                total_bytes += info.file_size
                if total_bytes > MAX_ARCHIVE_CONTENT_BYTES:
                    raise MeasurementBaselineError("archive_content_bytes_exceeded")
                digest = hashlib.sha256()
                member_bytes = 0
                with archive.open(info, "r") as handle:
                    while True:
                        chunk = handle.read(STREAM_CHUNK_BYTES)
                        if not chunk:
                            break
                        member_bytes += len(chunk)
                        if member_bytes > row["bytes"]:
                            raise MeasurementBaselineError(
                                "archive_member_size_mismatch"
                            )
                        digest.update(chunk)
                if member_bytes != row["bytes"] or digest.hexdigest() != row["sha256"]:
                    raise MeasurementBaselineError("archive_member_hash_mismatch")
                seen.add(info.filename)
    except MeasurementBaselineError:
        raise
    except (OSError, zipfile.BadZipFile, RuntimeError, EOFError) as exc:
        raise MeasurementBaselineError("archive_malformed") from exc
    if seen != set(expected):
        raise MeasurementBaselineError("archive_manifest_members_mismatch")
    if (
        manifest.get("schema_version") == MANIFEST_SCHEMA_VERSION
        and seen_directories != expected_directories
    ):
        raise MeasurementBaselineError("archive_manifest_directories_mismatch")
    if _stat_signature(_regular_file(archive_path, "archive")) != _stat_signature(
        archive_info
    ):
        raise MeasurementBaselineError("archive_changed")


def _runtime_paths(release_metadata: dict[str, Any]) -> set[str]:
    result = set(BUILTIN_RUNTIME_PATHS)
    declared = release_metadata.get("forbidden_runtime_paths", [])
    if not isinstance(declared, list):
        raise MeasurementBaselineError("release_metadata_runtime_paths_invalid")
    for value in declared:
        if not isinstance(value, str):
            raise MeasurementBaselineError("release_metadata_runtime_paths_invalid")
        result.add(_safe_relative_path(value, "runtime"))
    return result


def _refuse_runtime_state(source: Path, release_metadata: dict[str, Any]) -> None:
    for relative in sorted(_runtime_paths(release_metadata)):
        if os.path.lexists(source / relative):
            raise MeasurementBaselineError("runtime_state_present")


def _bound_source_tree(source: Path) -> None:
    nodes = 0
    total_bytes = 0
    for current, directories, files in os.walk(source, topdown=True, followlinks=False):
        current_path = Path(current)
        for name in [*directories, *files]:
            path = current_path / name
            try:
                info = path.lstat()
            except OSError as exc:
                raise MeasurementBaselineError("source_tree_unreadable") from exc
            nodes += 1
            if nodes > MAX_SOURCE_NODES:
                raise MeasurementBaselineError("source_tree_node_limit_exceeded")
            if stat.S_ISLNK(info.st_mode):
                raise MeasurementBaselineError("source_tree_link_rejected")
            if stat.S_ISREG(info.st_mode):
                total_bytes += info.st_size
                if total_bytes > MAX_SOURCE_BYTES:
                    raise MeasurementBaselineError("source_tree_byte_limit_exceeded")
            elif not stat.S_ISDIR(info.st_mode):
                raise MeasurementBaselineError("source_tree_special_file")


def _verify_source_manifest(source: Path, manifest_files: list[dict[str, Any]]) -> None:
    """Bind the staged tree to the release, allowing only live config edits."""

    expected = {str(row["path"]): row for row in manifest_files}
    actual = {
        path.relative_to(source).as_posix()
        for path in source.rglob("*")
        if path.is_file()
        and not path.is_symlink()
        and path.relative_to(source).as_posix() != LEGACY_EVENT_FILE
    }
    if actual != set(expected):
        raise MeasurementBaselineError("source_manifest_inventory_mismatch")
    for relative, row in expected.items():
        if relative in EDITABLE_RELEASE_CONFIGS:
            continue
        digest, byte_count, _ = _bounded_file_hash(
            source / relative,
            MAX_SOURCE_BYTES,
            "source_release_file",
        )
        if byte_count != row["bytes"] or digest != row["sha256"]:
            raise MeasurementBaselineError("source_manifest_content_mismatch")


def _parse_provider_fields(declarations: Iterable[str]) -> dict[str, dict[str, str]]:
    result: dict[str, dict[str, str]] = {}
    count = 0
    for declaration in declarations:
        count += 1
        if count > MAX_PROVIDER_FIELDS or "=" not in declaration:
            raise MeasurementBaselineError("provider_field_invalid")
        raw_name, raw_status = declaration.split("=", 1)
        name = PROVIDER_ALIASES.get(raw_name, raw_name)
        if not SAFE_PROVIDER_ID.fullmatch(name) or name in result:
            raise MeasurementBaselineError("provider_field_invalid")
        if raw_status == "available":
            value = {"availability": "available"}
        elif raw_status.startswith("unavailable:"):
            reason = raw_status.split(":", 1)[1]
            if not SAFE_REASON.fullmatch(reason):
                raise MeasurementBaselineError("provider_field_invalid")
            value = {"availability": "unavailable", "reason": reason}
        else:
            raise MeasurementBaselineError("provider_field_invalid")
        result[name] = value
    for name in KNOWN_PROVIDER_FIELDS:
        result.setdefault(
            name, {"availability": "unavailable", "reason": "not_declared"}
        )
    return dict(sorted(result.items()))


def _bounded_integer(
    value: Any, label: str, *, minimum: int = 0, maximum: int = 1_000_000_000
) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= maximum
    ):
        raise MeasurementBaselineError(f"{label}_invalid")
    return value


def _safe_configuration(manifest: dict[str, Any]) -> dict[str, Any]:
    adapter = manifest.get("adapter", {}).get("id")
    extensions = manifest.get("surface", {}).get("extensions", [])
    if not isinstance(adapter, str) or not SAFE_ID.fullmatch(adapter):
        raise MeasurementBaselineError("selected_adapter_invalid")
    if not isinstance(extensions, list) or len(extensions) > 64:
        raise MeasurementBaselineError("selected_extensions_invalid")
    safe_extensions: list[str] = []
    for extension in extensions:
        if not isinstance(extension, str) or not SAFE_ID.fullmatch(extension):
            raise MeasurementBaselineError("selected_extensions_invalid")
        safe_extensions.append(extension)
    if len(set(safe_extensions)) != len(safe_extensions):
        raise MeasurementBaselineError("selected_extensions_invalid")
    concurrency = manifest.get("concurrency", {})
    queue = manifest.get("queue", {})
    if not isinstance(concurrency, dict) or not isinstance(queue, dict):
        raise MeasurementBaselineError("resolved_limits_invalid")
    automation_enabled = queue.get("automation_enabled", False)
    if not isinstance(automation_enabled, bool):
        raise MeasurementBaselineError("queue_automation_invalid")
    return {
        "selected_adapter": adapter,
        "selected_extensions": safe_extensions,
        "concurrency": {
            "max_workers": _bounded_integer(
                concurrency.get("max_workers"), "max_workers", minimum=1
            ),
            "max_jobs": _bounded_integer(
                concurrency.get("max_jobs"), "max_jobs", minimum=1
            ),
            "max_subagent_threads": _bounded_integer(
                concurrency.get("max_subagent_threads"),
                "max_subagent_threads",
                minimum=1,
                maximum=256,
            ),
            "max_agent_depth": _bounded_integer(
                concurrency.get("max_agent_depth"),
                "max_agent_depth",
                minimum=2,
                maximum=2,
            ),
        },
        "queue": {
            "automation_enabled": automation_enabled,
            "cadence_seconds": _bounded_integer(
                queue.get("cadence_seconds"), "queue_cadence"
            ),
            "latency_objective_seconds": _bounded_integer(
                queue.get("latency_objective_seconds"), "queue_latency"
            ),
            "watch_interval_seconds": _bounded_integer(
                queue.get("watch_interval_seconds"), "queue_watch_interval", minimum=1
            ),
            "jitter_seconds": _bounded_integer(
                queue.get("jitter_seconds", 0), "queue_jitter"
            ),
        },
    }


def _clock(now: dt.datetime | None) -> dict[str, str]:
    observed = now if now is not None else dt.datetime.now().astimezone()
    if observed.tzinfo is None or observed.utcoffset() is None:
        raise MeasurementBaselineError("clock_timezone_unavailable")
    offset = observed.utcoffset() or dt.timedelta(0)
    total_minutes = int(offset.total_seconds() // 60)
    sign = "+" if total_minutes >= 0 else "-"
    hours, minutes = divmod(abs(total_minutes), 60)
    if hours > 23:
        raise MeasurementBaselineError("clock_offset_invalid")
    observed_utc = observed.astimezone(UTC).replace(microsecond=0)
    return {
        "source": "system_wall_clock",
        "observed_at_utc": observed_utc.isoformat().replace("+00:00", "Z"),
        "utc_offset": f"{sign}{hours:02d}:{minutes:02d}",
    }


def configuration_digest(record: dict[str, Any]) -> str:
    """Return the stable digest, excluding the observation clock and any paths."""

    stable = {
        key: value
        for key, value in record.items()
        if key not in {"clock", "configuration_digest"}
    }
    return hashlib.sha256(canonical_json(stable).encode("utf-8")).hexdigest()


def _private_external_baseline(path: Path) -> None:
    """Reject a non-private baseline without changing its mode or location."""

    info = _regular_file(path, "measurement_baseline")
    if stat.S_IMODE(info.st_mode) != 0o600 or info.st_mode & 0o077:
        raise MeasurementBaselineError("measurement_baseline_not_private")


def verify_measurement_baseline(
    source_root: Path,
    baseline_path: Path,
    manifest: dict[str, Any],
    *,
    verify_source_tree: bool,
) -> dict[str, Any]:
    """Verify an immutable external baseline against the current launch inputs.

    This is deliberately read-only. A resumed run keeps its already-bound source
    tree, whose generated runtime files would otherwise make a fresh tree hash
    meaningless; it still verifies every live configuration hash and digest.
    """

    source = source_root.resolve()
    path = Path(os.path.abspath(os.fspath(baseline_path))).resolve(strict=False)
    try:
        path.relative_to(source)
    except ValueError:
        pass
    else:
        raise MeasurementBaselineError("measurement_baseline_inside_source")
    _private_external_baseline(path)
    record, baseline_sha256, _baseline_bytes, _ = _read_json_object(
        path, MAX_CONFIG_BYTES, "measurement_baseline"
    )
    required_record = {
        "schema_version",
        "record_kind",
        "release",
        "configuration",
        "provider_fields",
        "validator",
        "clock",
        "configuration_digest",
    }
    if set(record) != required_record:
        raise MeasurementBaselineError("measurement_baseline_invalid")
    if (
        record.get("schema_version") != SCHEMA_VERSION
        or record.get("record_kind") != RECORD_KIND
        or not isinstance(record.get("configuration_digest"), str)
        or not SHA256.fullmatch(str(record.get("configuration_digest")))
        or record["configuration_digest"] != configuration_digest(record)
    ):
        raise MeasurementBaselineError("measurement_baseline_invalid")
    release = record.get("release")
    configuration = record.get("configuration")
    validator = record.get("validator")
    if not isinstance(release, dict) or not isinstance(configuration, dict) or not isinstance(validator, dict):
        raise MeasurementBaselineError("measurement_baseline_invalid")
    version_raw, _, _ = _bounded_file_bytes(source / "VERSION", 64, "version")
    try:
        version = version_raw.decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise MeasurementBaselineError("version_invalid") from exc
    if not CALVER.fullmatch(version) or release.get("version") != version:
        raise MeasurementBaselineError("measurement_baseline_release_drift")
    environment_sha256, environment_bytes, _ = _bounded_file_hash(
        source / ".env", MAX_CONFIG_BYTES, "environment"
    )
    resolved_sha256 = hashlib.sha256(
        canonical_json(manifest).encode("utf-8")
    ).hexdigest()
    expected_configuration = {
        "configuration_source": "env",
        "environment_sha256": environment_sha256,
        "environment_bytes": environment_bytes,
        "resolved_manifest_sha256": resolved_sha256,
        **_safe_configuration(manifest),
    }
    for key, value in expected_configuration.items():
        if configuration.get(key) != value:
            raise MeasurementBaselineError("measurement_baseline_configuration_drift")
    event_identity = configuration.get("event_identity")
    if not isinstance(event_identity, dict) or set(configuration) != {
        *expected_configuration,
        "event_identity",
    }:
        raise MeasurementBaselineError("measurement_baseline_invalid")
    if (
        validator.get("ok") is not True
        or validator.get("strict_release") is not True
        or not isinstance(release.get("source_tree_sha256"), str)
        or not SHA256.fullmatch(str(release.get("source_tree_sha256")))
        or validator.get("tree_hash_before") != release["source_tree_sha256"]
        or validator.get("tree_hash_after") != release["source_tree_sha256"]
    ):
        raise MeasurementBaselineError("measurement_baseline_invalid")
    if (
        verify_source_tree
        and tree_hash(source, exclude={LEGACY_EVENT_FILE}) != release["source_tree_sha256"]
    ):
        raise MeasurementBaselineError("measurement_baseline_source_drift")
    provider_fields = record.get("provider_fields")
    queue = configuration.get("queue")
    if not isinstance(provider_fields, dict) or not isinstance(queue, dict):
        raise MeasurementBaselineError("measurement_baseline_invalid")
    measurement_provider_fields: dict[str, dict[str, str]] = {}
    for name in KNOWN_PROVIDER_FIELDS:
        field = provider_fields.get(name)
        availability = field.get("availability") if isinstance(field, dict) else None
        if availability not in {"available", "unavailable"}:
            raise MeasurementBaselineError("measurement_baseline_invalid")
        # Deliberately retain only the availability enum.  Baseline reasons can
        # be operator-specific and do not belong in the durable runtime record.
        measurement_provider_fields[name] = {"availability": availability}
    queue_automation = queue.get("automation_enabled")
    if not isinstance(queue_automation, bool):
        raise MeasurementBaselineError("measurement_baseline_invalid")
    return {
        "sha256": baseline_sha256,
        "configuration_digest": str(record["configuration_digest"]),
        "release_version": version,
        "measurement_contract": {
            "queue_automation_enabled": queue_automation,
            "provider_fields": measurement_provider_fields,
        },
    }


def _output_target(source: Path, output: Path) -> Path:
    target = Path(os.path.abspath(os.fspath(output))).resolve(strict=False)
    try:
        target.relative_to(source)
    except ValueError:
        pass
    else:
        raise MeasurementBaselineError("output_inside_source")
    if os.path.lexists(target):
        raise MeasurementBaselineError("output_already_exists")
    return target


def build_measurement_baseline(
    source_root: Path,
    archive_path: Path,
    manifest_path: Path,
    provider_fields: Iterable[str] = (),
    *,
    now: dt.datetime | None = None,
) -> dict[str, Any]:
    """Build a validated record entirely in memory without changing the source."""

    source = source_root.resolve()
    if not source.is_dir():
        raise MeasurementBaselineError("source_root_missing")
    release_metadata, _, _, _ = _read_json_object(
        source / "release.json", MAX_RELEASE_METADATA_BYTES, "release_metadata"
    )
    _refuse_runtime_state(source, release_metadata)
    _bound_source_tree(source)

    version_raw, _, _ = _bounded_file_bytes(source / "VERSION", 64, "version")
    try:
        version = version_raw.decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise MeasurementBaselineError("version_invalid") from exc
    if not CALVER.fullmatch(version) or release_metadata.get("version") != version:
        raise MeasurementBaselineError("version_invalid")

    env_raw, env_sha256, _ = _bounded_file_bytes(
        source / ".env", MAX_CONFIG_BYTES, "environment"
    )

    release_manifest, release_manifest_sha256, release_manifest_bytes, _ = (
        _read_json_object(manifest_path, MAX_MANIFEST_BYTES, "release_manifest")
    )
    manifest_files, manifest_directories, manifest_total_bytes = _validate_release_manifest(
        release_manifest, version
    )
    archive_sha256, archive_bytes, archive_info = _bounded_file_hash(
        archive_path, MAX_ARCHIVE_BYTES, "archive"
    )
    _verify_archive(
        archive_path,
        archive_info,
        release_manifest,
        manifest_files,
        manifest_directories,
    )
    _verify_source_manifest(source, manifest_files)

    try:
        # Resolve from the bounded private dotenv while supplying no ambient
        # parent environment. This keeps baseline creation deterministic and
        # prevents unrelated process settings from joining the launch binding.
        resolved = resolve_manifest(source, parent={})
    except Exception as exc:
        raise MeasurementBaselineError("event_configuration_invalid") from exc
    if resolved.errors or resolved.unresolved_required or not resolved.ready:
        raise MeasurementBaselineError("event_configuration_not_ready")
    safe_configuration = _safe_configuration(resolved.manifest)
    resolved_sha256 = hashlib.sha256(
        canonical_json(resolved.manifest).encode("utf-8")
    ).hexdigest()

    report = validate_tree(
        source,
        adapter=str(safe_configuration["selected_adapter"]),
        strict_release=True,
    )
    if not report.get("ok"):
        raise MeasurementBaselineError("strict_source_validation_failed")
    tree_before = str(report.get("tree_hash_before") or "")
    tree_after = str(report.get("tree_hash_after") or "")
    if not SHA256.fullmatch(tree_before) or tree_before != tree_after:
        raise MeasurementBaselineError("source_tree_changed")

    # Bind the record to one quiescent view of both the source and external
    # release artifacts. These repeat hashes detect changes during validation.
    final_env_sha256, final_env_bytes, _ = _bounded_file_hash(
        source / ".env", MAX_CONFIG_BYTES, "environment"
    )
    final_manifest_sha256, final_manifest_bytes, _ = _bounded_file_hash(
        manifest_path, MAX_MANIFEST_BYTES, "release_manifest"
    )
    final_archive_sha256, final_archive_bytes, _ = _bounded_file_hash(
        archive_path, MAX_ARCHIVE_BYTES, "archive"
    )
    if (
        (final_env_sha256, final_env_bytes) != (env_sha256, len(env_raw))
        or (final_manifest_sha256, final_manifest_bytes)
        != (release_manifest_sha256, release_manifest_bytes)
        or (final_archive_sha256, final_archive_bytes)
        != (archive_sha256, archive_bytes)
    ):
        raise MeasurementBaselineError("baseline_input_changed")
    _bound_source_tree(source)
    if tree_hash(source, exclude={LEGACY_EVENT_FILE}) != tree_after:
        raise MeasurementBaselineError("source_tree_changed")

    identity = resolved.manifest.get("identity", {})
    safe_event_identity = {
        "id": str(identity.get("id", "unknown"))[:256]
        if isinstance(identity, dict)
        else "unknown",
        "name": str(identity.get("name", "unknown"))[:256]
        if isinstance(identity, dict)
        else "unknown",
    }
    record: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "record_kind": RECORD_KIND,
        "release": {
            "version": version,
            "archive_sha256": archive_sha256,
            "archive_bytes": archive_bytes,
            "manifest_sha256": release_manifest_sha256,
            "manifest_bytes": release_manifest_bytes,
            "manifest_schema_version": str(release_manifest["schema_version"]),
            "manifest_file_count": len(manifest_files),
            "manifest_content_bytes": manifest_total_bytes,
            "source_tree_sha256": tree_after,
        },
        "configuration": {
            "configuration_source": "env",
            "environment_sha256": env_sha256,
            "environment_bytes": len(env_raw),
            "resolved_manifest_sha256": resolved_sha256,
            "event_identity": safe_event_identity,
            **safe_configuration,
        },
        "provider_fields": _parse_provider_fields(provider_fields),
        "validator": {
            "ok": True,
            "strict_release": True,
            "tree_hash_before": tree_before,
            "tree_hash_after": tree_after,
            "error_count": len(report.get("errors", [])),
            "warning_count": len(report.get("warnings", [])),
        },
        "clock": _clock(now),
    }
    record["configuration_digest"] = configuration_digest(record)
    return record


def _publish_private_json(target: Path, record: dict[str, Any]) -> None:
    data = (
        json.dumps(record, sort_keys=True, ensure_ascii=False, indent=2) + "\n"
    ).encode("utf-8")
    ensure_private_dir(target.parent)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{target.name}.", dir=str(target.parent)
    )
    temporary = Path(temporary_name)
    published = False
    try:
        ensure_private_file(temporary)
        handle = os.fdopen(descriptor, "wb")
        descriptor = -1
        with handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temporary, target)
        published = True
        ensure_private_file(target)
        temporary.unlink()
        directory_descriptor = os.open(target.parent, os.O_RDONLY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    except Exception:
        if published:
            target.unlink(missing_ok=True)
        raise
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)


def write_measurement_baseline(
    source_root: Path,
    archive_path: Path,
    manifest_path: Path,
    output_path: Path,
    provider_fields: Iterable[str] = (),
    *,
    now: dt.datetime | None = None,
) -> dict[str, Any]:
    """Validate, build, and atomically publish one immutable private record."""

    source = source_root.resolve()
    target = _output_target(source, output_path)
    from .environment import EnvironmentPolicyError, _codex_controls, normalize_measurement_baseline_path

    try:
        configured = normalize_measurement_baseline_path(
            source,
            _codex_controls(source, parent={}).get("ROOKERY_MEASUREMENT_BASELINE_PATH"),
        )
    except EnvironmentPolicyError as exc:
        raise MeasurementBaselineError("configured_baseline_path_invalid") from exc
    if configured != target:
        raise MeasurementBaselineError("configured_baseline_output_mismatch")
    record = build_measurement_baseline(
        source,
        archive_path,
        manifest_path,
        provider_fields,
        now=now,
    )
    try:
        _publish_private_json(target, record)
    except (OSError, ValueError) as exc:
        raise MeasurementBaselineError("output_publish_failed") from exc
    return record


# Short aliases for callers that use the command's noun rather than its full name.
build_baseline = build_measurement_baseline
write_baseline = write_measurement_baseline


def main(wrapper_path: Path, argv: Sequence[str] | None = None) -> int:
    """Run the shipped measurement-baseline command."""

    parser = argparse.ArgumentParser(
        description="Create a strict pre-event measurement baseline"
    )
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--provider-field",
        action="append",
        default=[],
        metavar="NAME=available|unavailable:reason",
    )
    arguments = parser.parse_args(argv)
    try:
        record = write_measurement_baseline(
            source_root_from_wrapper(wrapper_path),
            arguments.archive,
            arguments.manifest,
            arguments.output,
            arguments.provider_field,
        )
    except (MeasurementBaselineError, OSError, ValueError):
        print(
            json.dumps(
                {"error": "measurement_baseline_failed", "ok": False}, sort_keys=True
            )
        )
        return 2
    print(
        json.dumps(
            {
                "configuration_digest": record["configuration_digest"],
                "ok": True,
                "schema_version": record["schema_version"],
                "version": record["release"]["version"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(Path(__file__)))
