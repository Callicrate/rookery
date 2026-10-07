"""Private, no-clobber import of a legacy Rookery event JSON file.

Normal Rookery operation is deliberately environment-only.  This module is
the one compatibility boundary that may read a former event JSON input; it
never resolves a launch, contacts a platform, or writes runtime state.
"""

from __future__ import annotations

import json
import os
import re
import stat
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .environment import (
    DOTENV_MAX_ASSIGNMENTS,
    DOTENV_MAX_BYTES,
    DOTENV_MAX_LINE_BYTES,
    EnvironmentPolicyError,
    _read_dotenv_compat,
    _read_regular_file,
)

_LEGACY_ENV_RENAMES = {"EVENT_ADAPTER": "PLATFORM_ADAPTER"}
_LEGACY_ENV_DROPS = frozenset({"EVENT_MANIFEST"})
_MIGRATION_MAX_DEPTH = 32
_MIGRATION_MAX_NODES = 4096
_SAFE_FIELD_COMPONENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}\Z")


class ConfigurationMigrationError(ValueError):
    """A value-free migration failure suitable for the operator CLI."""

    def __init__(self, code: str, fields: Iterable[str] = ()) -> None:
        self.code = code
        self.fields = tuple(sorted(set(str(field) for field in fields)))
        message = code
        if self.fields:
            message += ": " + ", ".join(self.fields)
        super().__init__(message)


@dataclass(frozen=True)
class MigrationResult:
    """Value-free result information for one private draft."""

    migrated_keys: tuple[str, ...]
    retained_keys: tuple[str, ...]
    removed_legacy_keys: tuple[str, ...]

    def presentation(self) -> dict[str, Any]:
        return {
            "ok": True,
            "status": "draft_written",
            "migrated_keys": list(self.migrated_keys),
            "retained_keys": list(self.retained_keys),
            "removed_legacy_keys": list(self.removed_legacy_keys),
            "next_step": "review_private_env_draft_create_fresh_baseline",
        }


def _migration_error(code: str, fields: Iterable[str] = ()) -> ConfigurationMigrationError:
    return ConfigurationMigrationError(code, fields)


def _parse_legacy_json(path: Path) -> dict[str, Any]:
    """Read one bounded, regular, non-link JSON document without path output."""

    try:
        data = _read_regular_file(path)
    except EnvironmentPolicyError as exc:
        raise _migration_error("migration_input_invalid") from exc
    if data is None:
        raise _migration_error("migration_input_missing")

    def no_duplicate_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        output: dict[str, Any] = {}
        for key, value in pairs:
            if key in output:
                raise _migration_error("migration_input_duplicate_key")
            output[key] = value
        return output

    try:
        decoded = json.loads(
            data.decode("utf-8"), object_pairs_hook=no_duplicate_object
        )
    except ConfigurationMigrationError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise _migration_error("migration_input_invalid") from exc
    if not isinstance(decoded, dict):
        raise _migration_error("migration_input_invalid")
    _check_json_shape(decoded)
    return decoded


def _check_json_shape(value: Any, *, depth: int = 0, nodes: list[int] | None = None) -> None:
    """Bound recursive legacy data before walking its manifest paths."""

    if nodes is None:
        nodes = [0]
    nodes[0] += 1
    if depth > _MIGRATION_MAX_DEPTH or nodes[0] > _MIGRATION_MAX_NODES:
        raise _migration_error("migration_input_too_complex")
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str):
                raise _migration_error("migration_input_invalid")
            _check_json_shape(child, depth=depth + 1, nodes=nodes)
    elif isinstance(value, list):
        for child in value:
            _check_json_shape(child, depth=depth + 1, nodes=nodes)


def _parse_legacy_environment(path: Path) -> dict[str, str]:
    try:
        return _read_dotenv_compat(path)
    except EnvironmentPolicyError as exc:
        raise _migration_error("migration_environment_invalid") from exc


def _safe_adapter_id(environment: Mapping[str, str], event: Mapping[str, Any]) -> str:
    """Choose one local adapter schema without treating legacy JSON as launch input."""

    values: list[str] = []
    for key in ("PLATFORM_ADAPTER", "EVENT_ADAPTER"):
        value = environment.get(key, "").strip()
        if value:
            values.append(value)
    adapter = event.get("adapter")
    if isinstance(adapter, Mapping):
        value = adapter.get("id")
        if isinstance(value, str) and value.strip():
            values.append(value.strip())
        elif value not in {None, ""}:
            raise _migration_error("migration_input_invalid")
    if len(set(values)) > 1:
        raise _migration_error("migration_conflicting_fields", ("PLATFORM_ADAPTER",))
    return values[0] if values else "manual"


def _schema_for_adapter(root: Path, adapter_id: str) -> tuple[Any, ...]:
    """Load the pure typed schema exported by the normal env-only resolver."""

    try:
        from .event_env import event_environment_schema

        return tuple(event_environment_schema(root, adapter_id))
    except (EnvironmentPolicyError, ValueError, OSError, TypeError) as exc:
        raise _migration_error("migration_selected_adapter_invalid") from exc


def _field_target(field: Any) -> tuple[str, ...] | None:
    target = getattr(field, "target", None)
    if target is None:
        return None
    if not isinstance(target, tuple) or not target or any(
        not isinstance(part, str) or not part for part in target
    ):
        raise _migration_error("migration_schema_invalid")
    return target


def _field_legacy_import(field: Any) -> bool:
    value = getattr(field, "legacy_import", False)
    if not isinstance(value, bool):
        raise _migration_error("migration_schema_invalid")
    return value


def _field_name(field: Any) -> str:
    name = getattr(field, "name", None)
    if not isinstance(name, str) or not name:
        raise _migration_error("migration_schema_invalid")
    return name


def _field_kind(field: Any) -> str:
    kind = getattr(field, "kind", None)
    if not isinstance(kind, str) or not kind:
        raise _migration_error("migration_schema_invalid")
    return kind


def _target_fields(fields: Iterable[Any]) -> dict[tuple[str, ...], Any]:
    output: dict[tuple[str, ...], Any] = {}
    for field in fields:
        if not _field_legacy_import(field):
            continue
        target = _field_target(field)
        if target is None:
            continue
        if target in output:
            raise _migration_error("migration_schema_invalid")
        output[target] = field
    return output


def _legacy_leaf_paths(value: Any, prefix: tuple[str, ...] = ()) -> Iterable[tuple[tuple[str, ...], Any]]:
    if isinstance(value, dict):
        if not value:
            return
        for key, child in value.items():
            yield from _legacy_leaf_paths(child, prefix + (key,))
        return
    yield prefix, value


def _safe_field_path(path: tuple[str, ...]) -> str:
    """Keep unsupported-field reports useful without reflecting JSON data."""

    if path and all(_SAFE_FIELD_COMPONENT.fullmatch(part) for part in path):
        return ".".join(path)
    return "legacy_json_field"


def _serialise_legacy_value(field: Any, value: Any) -> str | None:
    """Translate one JSON field into a dotenv literal accepted by its schema."""

    if value is None or value == "" or value == "unknown":
        return None
    kind = _field_kind(field)
    if kind == "bool01":
        if not isinstance(value, bool):
            raise _migration_error("migration_input_type_invalid", (_field_name(field),))
        return "1" if value else "0"
    if kind == "positive_integer_or_auto" and value == "auto":
        return "auto"
    if kind in {"integer", "decimal", "positive_integer_or_auto"}:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise _migration_error("migration_input_type_invalid", (_field_name(field),))
        return str(value)
    if kind in {"csv", "csv_integer"}:
        if not isinstance(value, list) or any(
            isinstance(item, (dict, list, bool)) or item is None for item in value
        ):
            raise _migration_error("migration_input_type_invalid", (_field_name(field),))
        values = [str(item) for item in value]
        if any("," in item or "\r" in item or "\n" in item for item in values):
            raise _migration_error("migration_input_type_invalid", (_field_name(field),))
        return ",".join(values)
    if kind in {
        "json_string_array",
        "https_origin_array",
        "environment_name_array",
        "argv",
        "json",
    }:
        if not isinstance(value, list):
            raise _migration_error("migration_input_type_invalid", (_field_name(field),))
        return json.dumps(value, separators=(",", ":"), ensure_ascii=False)
    if kind == "json_number_object":
        if not isinstance(value, dict):
            raise _migration_error("migration_input_type_invalid", (_field_name(field),))
        return json.dumps(value, separators=(",", ":"), ensure_ascii=False)
    if kind in {
        "string",
        "enum",
        "environment_name",
        "https_origin",
        "https_url",
        "path",
        "timestamp",
        "identifier",
        "adapter_id",
        "absolute_path",
        "regex",
    }:
        if not isinstance(value, str):
            raise _migration_error("migration_input_type_invalid", (_field_name(field),))
        return value
    raise _migration_error("migration_schema_invalid")


def _merge_value(
    values: dict[str, str],
    origins: dict[str, str],
    *,
    key: str,
    value: str,
    origin: str,
) -> None:
    previous = values.get(key)
    if previous is not None and previous != value:
        raise _migration_error("migration_conflicting_fields", (key,))
    values[key] = value
    origins.setdefault(key, origin)


def _validate_supported_environment(
    root: Path, adapter_id: str, values: Mapping[str, str]
) -> None:
    try:
        from .event_env import resolve_event_environment

        resolved = resolve_event_environment(root, env=values, parent={})
        unsupported = set(values) - set(resolved.declared_names)
        if unsupported:
            raise _migration_error("migration_unsupported_environment_keys", unsupported)
    except ConfigurationMigrationError:
        raise
    except (EnvironmentPolicyError, ValueError, OSError, TypeError) as exc:
        raise _migration_error("migration_output_invalid") from exc


def _write_private_draft_no_clobber(path: Path, values: Mapping[str, str]) -> None:
    """Create one 0600 draft without following or replacing a target path."""

    if len(values) > DOTENV_MAX_ASSIGNMENTS:
        raise _migration_error("migration_output_invalid")
    lines: list[str] = []
    for key in sorted(values, key=str.casefold):
        value = values[key]
        if not isinstance(key, str) or not isinstance(value, str) or "\0" in value:
            raise _migration_error("migration_output_invalid")
        record = f"{key}={json.dumps(value, ensure_ascii=False)}"
        if len(record.encode("utf-8")) > DOTENV_MAX_LINE_BYTES:
            raise _migration_error("migration_output_invalid")
        lines.append(record)
    data = (("\n".join(lines) + "\n") if lines else "").encode("utf-8")
    if len(data) > DOTENV_MAX_BYTES:
        raise _migration_error("migration_output_invalid")
    try:
        parent_info = os.lstat(path.parent)
        target_info = os.lstat(path)
    except FileNotFoundError:
        target_info = None
        try:
            parent_info = os.lstat(path.parent)
        except OSError as exc:
            raise _migration_error("migration_output_parent_invalid") from exc
    except OSError as exc:
        raise _migration_error("migration_output_invalid") from exc
    if not stat.S_ISDIR(parent_info.st_mode) or stat.S_ISLNK(parent_info.st_mode):
        raise _migration_error("migration_output_parent_invalid")
    if target_info is not None:
        raise _migration_error("migration_output_exists")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    parent_descriptor = -1
    created = False
    completed = False
    try:
        if os.open in os.supports_dir_fd:
            parent_descriptor = os.open(
                path.parent,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
            )
            descriptor = os.open(
                path.name, flags, 0o600, dir_fd=parent_descriptor
            )
        else:  # pragma: no cover - native Windows fallback
            descriptor = os.open(path, flags, 0o600)
        created = True
        os.fchmod(descriptor, 0o600)
        if stat.S_IMODE(os.fstat(descriptor).st_mode) != 0o600:
            raise OSError("private draft mode is unavailable")
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("draft write failed")
            view = view[written:]
        os.fsync(descriptor)
        if parent_descriptor >= 0:
            os.fsync(parent_descriptor)
        completed = True
    except OSError as exc:
        raise _migration_error("migration_output_invalid") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if created and not completed:
            # A successful draft stays in place.  A write/open failure removes
            # only the file this call created, never an existing operator file.
            if parent_descriptor >= 0:
                try:
                    os.unlink(path.name, dir_fd=parent_descriptor)
                except OSError:
                    pass
            else:  # pragma: no cover - native Windows fallback
                try:
                    info = os.lstat(path)
                except OSError:
                    info = None
                if info is not None and stat.S_ISREG(info.st_mode):
                    try:
                        os.unlink(path)
                    except OSError:
                        pass
        if parent_descriptor >= 0:
            os.close(parent_descriptor)


def migrate_event_configuration(
    root: Path,
    *,
    input_path: Path,
    environment_path: Path,
    output_path: Path,
) -> MigrationResult:
    """Convert a supported legacy JSON/event environment pair into a new draft.

    This function is deliberately side-effect free until every field has been
    parsed, typed, mapped, and checked.  The final write is no-clobber and uses
    no network or runtime state.
    """

    event = _parse_legacy_json(input_path)
    existing = _parse_legacy_environment(environment_path)
    adapter_id = _safe_adapter_id(existing, event)
    fields = _schema_for_adapter(root, adapter_id)
    target_fields = _target_fields(fields)

    values: dict[str, str] = {}
    origins: dict[str, str] = {}
    removed: set[str] = set()
    for key, value in existing.items():
        if key in _LEGACY_ENV_DROPS:
            removed.add(key)
            continue
        if value == "":
            continue
        normalized = _LEGACY_ENV_RENAMES.get(key, key)
        _merge_value(values, origins, key=normalized, value=value, origin="environment")

    unsupported: list[str] = []
    migrated: set[str] = set()
    for path, legacy_value in _legacy_leaf_paths(event):
        if path == ("adapter", "id"):
            if isinstance(legacy_value, str) and legacy_value not in {"", "unknown"}:
                _merge_value(
                    values,
                    origins,
                    key="PLATFORM_ADAPTER",
                    value=legacy_value,
                    origin="event",
                )
                migrated.add("PLATFORM_ADAPTER")
            continue
        field = target_fields.get(path)
        if field is None:
            unsupported.append(_safe_field_path(path))
            continue
        serialised = _serialise_legacy_value(field, legacy_value)
        if serialised is None:
            continue
        key = _field_name(field)
        _merge_value(values, origins, key=key, value=serialised, origin="event")
        migrated.add(key)
    if unsupported:
        raise _migration_error("migration_unsupported_fields", unsupported)

    _validate_supported_environment(root, adapter_id, values)
    _write_private_draft_no_clobber(output_path, values)
    retained = set(values) - migrated
    return MigrationResult(
        migrated_keys=tuple(sorted(migrated)),
        retained_keys=tuple(sorted(retained)),
        removed_legacy_keys=tuple(sorted(removed)),
    )
