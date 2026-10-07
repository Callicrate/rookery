from __future__ import annotations

import json
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass, field as dataclass_field
from datetime import datetime
from pathlib import Path
from types import MappingProxyType
from typing import Any
from urllib.parse import urlsplit

from .environment import (
    EnvClass,
    EnvironmentPolicyError,
    _read_dotenv_compat,
    classify_environment_name,
    parse_name_array,
    resolve_browser_cdp_endpoint,
    resolve_browser_bidi_endpoint,
    resolve_browser_gateway_endpoint,
    validate_environment_name,
)
from .util import load_json, split_csv


_REMOVED_KEYS = frozenset({"EVENT_ADAPTER", "EVENT_MANIFEST"})
_ADAPTER_ID = re.compile(r"[A-Za-z0-9_.-]+")
_IDENTIFIER = re.compile(r"[A-Za-z0-9_.:@/-]{1,256}")
_ABSOLUTE_PATH = re.compile(r"/[A-Za-z0-9._~!$&'()*+,;=:@%/-]*")
_FIELD_KINDS = frozenset(
    {
        "absolute_path",
        "adapter_id",
        "argv",
        "bool01",
        "csv",
        "csv_integer",
        "decimal",
        "enum",
        "environment_name",
        "environment_name_array",
        "https_origin",
        "https_origin_array",
        "https_url",
        "identifier",
        "integer",
        "json_number_object",
        "json_string_array",
        "positive_integer_or_auto",
        "regex",
        "string",
        "timestamp",
    }
)
_KNOWN_NON_EVENT_NAMES = frozenset(
    {
        "BROWSER_CDP_URL",
        "BROWSER_BIDI_URL",
        "BROWSER_ENV_KEYS",
        "BROWSER_EXECUTABLE",
        "BROWSER_GATEWAY_URL",
        "BROWSER_MODE",
        "CHROME_BIN",
        "CODEX_AUTH_MODE",
        "CODEX_NETWORK_ENV_KEYS",
        "CODEX_PROVIDER_ENV_KEYS",
        "CREDENTIAL_HEALTH_ARGV",
        "NCQ_NETWORK_ENV_KEYS",
        "NEAR_MISS_PROBE_ARGV",
        "ROCKYOU_PATH",
        "ROOKERY_ALLOW_INSTALL_NETWORK",
        "ROOKERY_INSTALL_HEAVY",
        "ROOKERY_INSTALL_RECOMMENDED",
        "ROOKERY_MEASUREMENT_BASELINE_PATH",
        "ROOKERY_PREPARE_INSTALL",
        "ROOKERY_PREPARE_MODE",
        "ROOKERY_PREPARE_NETWORK_ENV_KEYS",
        "ROOKERY_PREPARE_TIMEOUT",
        "ROOKERY_SUDO",
        "SEARXNG_CONTAINER_ENGINE",
        "SEARXNG_IMAGE",
        "SEARXNG_LOCAL_PORT",
        "SEARXNG_MODE",
        "SEARXNG_NETWORK_ENV_KEYS",
        "SEARXNG_START_TIMEOUT",
        "SEARXNG_URL",
        "SECLISTS_PATH",
        "TRANSIT_SOURCE_NETWORK_ENV_KEYS",
    }
)
_DYNAMIC_NAME_SELECTORS = frozenset(
    {
        "BROWSER_ENV_KEYS",
        "CODEX_NETWORK_ENV_KEYS",
        "CODEX_PROVIDER_ENV_KEYS",
        "NCQ_NETWORK_ENV_KEYS",
        "ROOKERY_PREPARE_NETWORK_ENV_KEYS",
        "SEARXNG_NETWORK_ENV_KEYS",
        "TRANSIT_SOURCE_NETWORK_ENV_KEYS",
    }
)

# Release archives contain the selected adapter but ship the full public
# .env catalogue. Keep names for omitted adapters inert and reject any
# nonblank value for them. Full-source validation checks this fixed set
# against every reviewed adapter descriptor.
RELEASE_ADAPTER_CATALOG_ENV_KEYS = frozenset(
    {
        "ADAPTER_CONFIG_BASE_URL",
        "ADAPTER_CONFIG_BROWSER_SUPPORT_ORIGINS",
        "ADAPTER_CONFIG_CSRF_PAGE_PATH",
        "ADAPTER_CONFIG_EXPECTED_ACCOUNT_ID",
        "ADAPTER_CONFIG_EXPECTED_TEAM_ID",
        "ADAPTER_CONFIG_INVENTORY_ARGV",
        "ADAPTER_CONFIG_INVENTORY_ENV_KEYS",
        "ADAPTER_CONFIG_MAX_RESPONSE_BYTES",
        "ADAPTER_CONFIG_SCORING_MODE",
        "ADAPTER_CONFIG_SEQUENTIAL_UNLOCK",
        "ADAPTER_CONFIG_SESSION_LEASE_SECONDS",
        "ADAPTER_CONFIG_SUBMIT_ARGV",
        "ADAPTER_CONFIG_SUBMIT_ENV_KEYS",
        "ADAPTER_CONFIG_TARGET_ID",
        "ADAPTER_CONFIG_TIMEOUT",
        "ADAPTER_CONFIG_TOKEN_ENV",
        "CTFD_NETWORK_ENV_KEYS",
        "CTFD_TOKEN",
        "CTFD_URL",
        "IMMERSIVE_ACTIONCABLE_URL",
        "IMMERSIVE_COOKIES_FILE",
        "IMMERSIVE_GRAPHQL_URL",
        "IMMERSIVE_NETWORK_ENV_KEYS",
        "IMMERSIVE_ORIGIN",
        "IMMERSIVE_SELECTED_LAB_QUERY",
        "IMMERSIVE_SELECTED_LAB_REFRESH_ARGV",
        "IMMERSIVE_SELECTED_LAB_REFRESH_ENV_KEYS",
        "SKILLBIT_EMAIL",
        "SKILLBIT_ACCOUNT_ID",
        "SKILLBIT_PARTICIPATION_MODE",
        "SKILLBIT_TEAM_NAME",
        "SKILLBIT_EVENT_ID",
        "SKILLBIT_LOGIN_ORIGIN",
        "SKILLBIT_PASSWORD",
        "SKILLBIT_URL",
        "SKILLBIT_USER",
    }
)

RELEASE_EXTENSION_CATALOG_ENV_KEYS = frozenset(
    {
        "GUAC_REMOTE_FILE_EXPORT_ARGV",
        "GUAC_CLIPBOARD_EXPORT_ARGV",
        "GUAC_BASE64_EXPORT_ARGV",
        "GUAC_HTTP_EXPORT_ARGV",
        "GUAC_SCREENSHOT_TRANSCRIBE_ARGV",
        "GUAC_TERMINAL_CAPTURE_ARGV",
        "GUAC_SSH_EXEC_ARGV",
        "GUAC_REMOTE_FILE_EXPORT_ENV_KEYS",
        "GUAC_CLIPBOARD_EXPORT_ENV_KEYS",
        "GUAC_BASE64_EXPORT_ENV_KEYS",
        "GUAC_HTTP_EXPORT_ENV_KEYS",
        "GUAC_SCREENSHOT_TRANSCRIBE_ENV_KEYS",
        "GUAC_TERMINAL_CAPTURE_ENV_KEYS",
        "GUAC_SSH_EXEC_ENV_KEYS",
        "GUAC_STREAM_DIR",
        "GUAC_EXEC_TIMEOUT",
    }
)


@dataclass(frozen=True)
class EventEnvironmentField:
    name: str
    target: tuple[str, ...] | None
    kind: str
    minimum: float | int | None = None
    maximum: float | int | None = None
    choices: tuple[str, ...] = ()
    credential: bool = False
    legacy_import: bool = True


@dataclass(frozen=True)
class ResolvedEventEnvironment:
    adapter_id: str
    overlay: Mapping[str, Any] = dataclass_field(repr=False)
    values: Mapping[str, Any] = dataclass_field(repr=False)
    declared_names: frozenset[str]
    credential_names: frozenset[str]
    unresolved_required: tuple[str, ...]


def _field(
    name: str,
    target: str | None,
    kind: str,
    *,
    minimum: float | int | None = None,
    maximum: float | int | None = None,
    choices: tuple[str, ...] = (),
    credential: bool = False,
    legacy_import: bool = True,
) -> EventEnvironmentField:
    return EventEnvironmentField(
        name,
        tuple(target.split(".")) if target else None,
        kind,
        minimum,
        maximum,
        choices,
        credential,
        legacy_import,
    )


CORE_EVENT_ENVIRONMENT_SCHEMA = (
    _field("EVENT_ID", "identity.id", "string"),
    _field("EVENT_NAME", "identity.name", "string"),
    _field("EVENT_URL", "identity.url", "https_url"),
    _field("EVENT_START", "identity.starts_at", "timestamp"),
    _field("EVENT_END", "identity.ends_at", "timestamp"),
    _field("PLATFORM_ADAPTER", "adapter.id", "adapter_id", legacy_import=False),
    _field("EVENT_EXTENSIONS", "surface.extensions", "csv"),
    _field("EVENT_CATEGORIES", "surface.categories", "csv"),
    _field("EVENT_SCOPE_ACK", "scope.acknowledged", "bool01"),
    _field("ALLOWED_HOSTS", "scope.allowed_hosts", "csv"),
    _field("ALLOWED_CIDRS", "scope.allowed_cidrs", "csv"),
    _field("ALLOWED_PORTS", "scope.allowed_ports", "csv_integer", minimum=1, maximum=65535),
    _field("ALLOWED_PROTOCOLS", "scope.allowed_protocols", "csv"),
    _field("ALLOWED_FILE_ORIGINS", "scope.allowed_file_origins", "csv"),
    _field("PLATFORM_HOSTS", "scope.platform_hosts", "csv"),
    _field("SCOPE_MAX_BYTES", "scope.max_attachment_bytes", "integer", minimum=1),
    _field("SCOPE_EXPIRES_AT", "scope.expires_at", "timestamp"),
    _field("FLAG_REGEX", "answer_morphology.regex", "regex"),
    _field("ANSWER_EXAMPLES_JSON", "answer_morphology.examples", "json_string_array"),
    _field("SCORING_ACTION_KINDS", "scoring.action_kinds", "csv"),
    _field(
        "SCORING_COMPLETION_MODE",
        "scoring.completion_mode",
        "enum",
        choices=("scorer_truth", "evidence_only"),
    ),
    _field(
        "AUTOMATION_PERMITTED_ACTION_KINDS",
        "authorization.automation_permitted_action_kinds",
        "csv",
    ),
    _field("CONCURRENCY_MAX_WORKERS", "concurrency.max_workers", "positive_integer_or_auto"),
    _field("CONCURRENCY_MAX_JOBS", "concurrency.max_jobs", "integer", minimum=1, maximum=256),
    _field(
        "CODEX_SUBAGENT_THREADS",
        "concurrency.max_subagent_threads",
        "integer",
        minimum=1,
        maximum=256,
    ),
    _field("WRITEUP_MODE", "writeups.mode", "enum", choices=("immediate", "closeout")),
    _field("QUEUE_AUTOMATION", "queue.automation_enabled", "bool01"),
    _field("QUEUE_CADENCE_SECONDS", "queue.cadence_seconds", "integer", minimum=0, maximum=86400),
    _field("QUEUE_JITTER_SECONDS", "queue.jitter_seconds", "integer", minimum=0, maximum=86400),
    _field(
        "QUEUE_LATENCY_SECONDS",
        "queue.latency_objective_seconds",
        "integer",
        minimum=0,
        maximum=86400,
    ),
    _field("QUEUE_WATCH_INTERVAL_SECONDS", "queue.watch_interval_seconds", "integer", minimum=1, maximum=3600),
    _field("COMPUTE_TOTAL_UNITS", "compute.total_units", "integer", minimum=1, maximum=4096),
    _field("COMPUTE_INTERACTIVE_RESERVE", "compute.interactive_reserve_units", "integer", minimum=0, maximum=4096),
    _field("COMPUTE_ADMIT_PERCENT", "compute.admit_percent", "decimal", minimum=0, maximum=100),
    _field("COMPUTE_TARGET_PERCENT", "compute.target_percent", "decimal", minimum=0, maximum=100),
    _field("COMPUTE_CEILING_PERCENT", "compute.ceiling_percent", "decimal", minimum=0, maximum=100),
    _field("COMPUTE_BACKOFF_PERCENT", "compute.backoff_percent", "decimal", minimum=0, maximum=100),
    _field("COMPUTE_SAMPLE_SECONDS", "compute.sample_seconds", "decimal", minimum=0.001, maximum=30),
    _field(
        "COMPUTE_ADMISSION_COOLDOWN_SECONDS",
        "compute.admission_cooldown_seconds",
        "integer",
        minimum=0,
        maximum=3600,
    ),
    _field("COMPUTE_LEASE_SECONDS", "compute.lease_seconds", "integer", minimum=5, maximum=300),
    _field(
        "COMPUTE_DEFAULT_JOB_BUDGET_SECONDS",
        "compute.default_job_budget_seconds",
        "integer",
        minimum=1,
        maximum=86400,
    ),
    _field("PRIORITY_STRATEGY", "priority.strategy", "enum", choices=("balanced", "sequential")),
    _field("PRIORITY_WEIGHTS_JSON", "priority.weights", "json_number_object"),
)


def _adapter_descriptor(root: Path, adapter_id: str) -> Mapping[str, Any]:
    if _ADAPTER_ID.fullmatch(adapter_id) is None:
        raise EnvironmentPolicyError("platform_adapter_invalid")
    descriptor = load_json(root / "adapters" / adapter_id / "adapter.json")
    if not isinstance(descriptor, Mapping) or descriptor.get("id") != adapter_id:
        raise EnvironmentPolicyError("platform_adapter_invalid")
    return descriptor


def _descriptor_field(value: object) -> EventEnvironmentField:
    if not isinstance(value, Mapping) or set(value).difference(
        {"name", "target", "type", "minimum", "maximum", "choices", "credential", "legacy_import"}
    ):
        raise EnvironmentPolicyError("adapter_environment_schema_invalid")
    name = value.get("name")
    kind = value.get("type")
    target = value.get("target")
    if (
        not isinstance(name, str)
        or kind not in _FIELD_KINDS
        or target is not None
        and not isinstance(target, str)
    ):
        raise EnvironmentPolicyError("adapter_environment_schema_invalid")
    validate_environment_name(name, label="adapter environment key")
    if target is not None and not target.startswith("adapter.config."):
        raise EnvironmentPolicyError("adapter_environment_schema_invalid")
    if any(
        bound is not None and (isinstance(bound, bool) or not isinstance(bound, (int, float)))
        for bound in (value.get("minimum"), value.get("maximum"))
    ):
        raise EnvironmentPolicyError("adapter_environment_schema_invalid")
    if not isinstance(value.get("credential", False), bool) or not isinstance(value.get("legacy_import", True), bool):
        raise EnvironmentPolicyError("adapter_environment_schema_invalid")
    choices = value.get("choices", [])
    if not isinstance(choices, list) or any(not isinstance(item, str) for item in choices):
        raise EnvironmentPolicyError("adapter_environment_schema_invalid")
    if kind == "enum" and not choices:
        raise EnvironmentPolicyError("adapter_environment_schema_invalid")
    return _field(
        name,
        target,
        kind,
        minimum=value.get("minimum"),
        maximum=value.get("maximum"),
        choices=tuple(choices),
        credential=value.get("credential") is True,
        legacy_import=value.get("legacy_import", True) is True,
    )


def event_environment_schema(root: Path, adapter_id: str) -> tuple[EventEnvironmentField, ...]:
    if adapter_id == "manual":
        return CORE_EVENT_ENVIRONMENT_SCHEMA
    descriptor = _adapter_descriptor(root, adapter_id)
    adapter_schema = descriptor.get("environment_schema", [])
    if not isinstance(adapter_schema, list):
        raise EnvironmentPolicyError("adapter_environment_schema_invalid")
    fields = CORE_EVENT_ENVIRONMENT_SCHEMA + tuple(_descriptor_field(item) for item in adapter_schema)
    names: set[str] = set()
    for field in fields:
        if field.name in names:
            raise EnvironmentPolicyError("adapter_environment_schema_invalid")
        names.add(field.name)
    return fields


def event_environment_names(root: Path, adapter_id: str) -> frozenset[str]:
    return frozenset(field.name for field in event_environment_schema(root, adapter_id))


def declared_environment_names(root: Path, adapter_id: str) -> frozenset[str]:
    """Return the fixed public dotenv names accepted for one selected adapter."""

    return event_environment_names(root, adapter_id) | _KNOWN_NON_EVENT_NAMES


def adapter_environment_catalog_names(root: Path) -> frozenset[str]:
    """Return the reviewed union of adapter-owned dotenv names."""

    names: set[str] = set()
    adapters = root / "adapters"
    if not adapters.is_dir():
        return frozenset()
    for directory in sorted(adapters.iterdir(), key=lambda path: path.name):
        if not directory.is_dir() or not (directory / "adapter.json").is_file():
            continue
        descriptor = _adapter_descriptor(root, directory.name)
        schema = descriptor.get("environment_schema", [])
        if not isinstance(schema, list):
            raise EnvironmentPolicyError("adapter_environment_schema_invalid")
        names.update(_descriptor_field(item).name for item in schema)
    return frozenset(names)


def extension_environment_catalog_names(root: Path) -> frozenset[str]:
    """Return the schema names of extensions present in this source or release."""

    names: set[str] = set()
    for path in sorted((root / "extensions").glob("*/extension.json")):
        descriptor = load_json(path)
        if not isinstance(descriptor, Mapping) or descriptor.get("id") != path.parent.name:
            raise EnvironmentPolicyError("extension_environment_schema_invalid")
        schema = descriptor.get("environment_schema", [])
        if not isinstance(schema, list):
            raise EnvironmentPolicyError("extension_environment_schema_invalid")
        names.update(_descriptor_field(item).name for item in schema)
    return frozenset(names)


def _selected_extension_fields(root: Path, adapter_id: str, raw: Mapping[str, str]) -> tuple[EventEnvironmentField, ...]:
    descriptor = _adapter_descriptor(root, adapter_id) if adapter_id != "manual" else {}
    defaults = descriptor.get("default_extensions", [])
    if not isinstance(defaults, list) or any(not isinstance(value, str) for value in defaults):
        raise EnvironmentPolicyError("extension_environment_schema_invalid")
    explicit = [] if raw.get("EVENT_EXTENSIONS", "").strip().casefold() == "unknown" else split_csv(raw.get("EVENT_EXTENSIONS", ""))
    selected = tuple(dict.fromkeys((*defaults, *explicit)))
    if len(selected) > 64:
        raise EnvironmentPolicyError("extension_environment_schema_invalid")
    fields: list[EventEnvironmentField] = []
    for extension_id in selected:
        if _ADAPTER_ID.fullmatch(extension_id) is None:
            raise EnvironmentPolicyError("extension_environment_schema_invalid")
        descriptor_path = root / "extensions" / extension_id / "extension.json"
        extension = load_json(descriptor_path)
        if not isinstance(extension, Mapping) or extension.get("id") != extension_id:
            raise EnvironmentPolicyError("extension_environment_schema_invalid")
        schema = extension.get("environment_schema", [])
        if not isinstance(schema, list):
            raise EnvironmentPolicyError("extension_environment_schema_invalid")
        for value in schema:
            field = _descriptor_field(value)
            if field.target is not None:
                raise EnvironmentPolicyError("extension_environment_schema_invalid")
            fields.append(field)
    return tuple(fields)


def _required_environment(
    descriptor: Mapping[str, Any],
    declared: set[str],
    raw: Mapping[str, str],
) -> tuple[str, ...]:
    """Resolve adapter-owned readiness names without retaining their values."""

    requirements = descriptor.get("environment_requirements", {})
    if not isinstance(requirements, Mapping) or set(requirements).difference(
        {"all", "any", "conditional", "same", "fixed", "indirect", "allowed"}
    ):
        raise EnvironmentPolicyError("adapter_environment_requirements_invalid")
    all_names = requirements.get("all", [])
    any_groups = requirements.get("any", [])
    conditions = requirements.get("conditional", [])
    same_groups = requirements.get("same", [])
    fixed = requirements.get("fixed", [])
    indirect = requirements.get("indirect", [])
    allowed = requirements.get("allowed", [])
    if any(not isinstance(items, list) for items in (all_names, any_groups, conditions, same_groups, fixed, indirect, allowed)):
        raise EnvironmentPolicyError("adapter_environment_requirements_invalid")

    def valid_name(value: object) -> bool:
        return isinstance(value, str) and value in declared | _KNOWN_NON_EVENT_NAMES

    if any(not valid_name(name) for name in all_names):
        raise EnvironmentPolicyError("adapter_environment_requirements_invalid")
    if any(
        not isinstance(group, list) or not group or any(not valid_name(name) for name in group)
        for group in any_groups
    ):
        raise EnvironmentPolicyError("adapter_environment_requirements_invalid")
    if any(
        not isinstance(group, list) or len(group) < 2 or any(not valid_name(name) for name in group)
        for group in same_groups
    ):
        raise EnvironmentPolicyError("adapter_environment_requirements_invalid")
    if any(
        not isinstance(condition, Mapping)
        or set(condition) != {"when", "equals", "require"}
        or not valid_name(condition["when"])
        or not isinstance(condition["equals"], str)
        or not condition["equals"]
        or not valid_name(condition["require"])
        for condition in conditions
    ):
        raise EnvironmentPolicyError("adapter_environment_requirements_invalid")
    if any(
        not isinstance(rule, Mapping)
        or set(rule) != {"name", "value"}
        or not valid_name(rule["name"])
        or not isinstance(rule["value"], str)
        or not rule["value"]
        for rule in fixed
    ):
        raise EnvironmentPolicyError("adapter_environment_requirements_invalid")
    if any(
        not isinstance(rule, Mapping)
        or set(rule) != {"name", "values"}
        or not valid_name(rule["name"])
        or not isinstance(rule["values"], list)
        or not rule["values"]
        or any(not isinstance(value, str) or not value for value in rule["values"])
        for rule in allowed
    ):
        raise EnvironmentPolicyError("adapter_environment_requirements_invalid")
    if any(
        not isinstance(rule, Mapping)
        or set(rule) != {"selector", "default"}
        or rule["selector"] not in declared
        or not valid_name(rule["default"])
        for rule in indirect
    ):
        raise EnvironmentPolicyError("adapter_environment_requirements_invalid")

    def present(name: str) -> bool:
        value = raw.get(name, "")
        return bool(value and value.strip().casefold() != "unknown")

    for group in same_groups:
        configured = {raw[name].removesuffix("/") for name in group if present(name)}
        if len(configured) > 1:
            raise EnvironmentPolicyError("event_environment_conflict:" + "|".join(group))

    missing = [name for name in all_names if not present(name)]
    missing.extend("|".join(group) for group in any_groups if not any(present(name) for name in group))
    missing.extend(rule["name"] for rule in fixed if raw.get(rule["name"]) != rule["value"])
    missing.extend(rule["name"] for rule in allowed if raw.get(rule["name"]) not in rule["values"])
    for rule in indirect:
        selector_value = raw.get(rule["selector"], "")
        target = selector_value if selector_value and selector_value.strip().casefold() != "unknown" else rule["default"]
        validate_environment_name(target, label=rule["selector"])
        if classify_environment_name(target) not in {EnvClass.ADAPTER_SECRET, EnvClass.SESSION_SECRET_REF}:
            raise EnvironmentPolicyError("adapter_environment_requirements_invalid")
        if not present(target):
            missing.append(target)
    if present("BROWSER_CDP_URL") and "BROWSER_CDP_URL" in all_names:
        resolve_browser_cdp_endpoint(raw["BROWSER_CDP_URL"])
    if present("BROWSER_BIDI_URL") and "BROWSER_BIDI_URL" in all_names:
        resolve_browser_bidi_endpoint(raw["BROWSER_BIDI_URL"])
    if present("BROWSER_GATEWAY_URL") and "BROWSER_GATEWAY_URL" in all_names:
        resolve_browser_gateway_endpoint(raw["BROWSER_GATEWAY_URL"])
    missing.extend(
        condition["require"]
        for condition in conditions
        if raw.get(condition["when"]) == condition["equals"] and not present(condition["require"])
    )
    return tuple(dict.fromkeys(missing))


def _bounded_number(field: EventEnvironmentField, value: float | int) -> float | int:
    if field.minimum is not None and value < field.minimum or field.maximum is not None and value > field.maximum:
        raise EnvironmentPolicyError(f"event_environment_invalid:{field.name}")
    return value


def _json_string_array(field: EventEnvironmentField, raw: str) -> list[str]:
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise EnvironmentPolicyError(f"event_environment_invalid:{field.name}") from exc
    if not isinstance(value, list) or len(value) > 256 or any(
        not isinstance(item, str) or not item or len(item.encode("utf-8")) > 4096 for item in value
    ):
        raise EnvironmentPolicyError(f"event_environment_invalid:{field.name}")
    if len(set(value)) != len(value):
        raise EnvironmentPolicyError(f"event_environment_invalid:{field.name}")
    return value


def _https_origin(raw: str, *, name: str) -> str:
    parsed = urlsplit(raw)
    if (
        any(character.isspace() or ord(character) < 32 for character in raw)
        or parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or parsed.netloc != parsed.netloc.lower()
    ):
        raise EnvironmentPolicyError(f"event_environment_invalid:{name}")
    try:
        port = parsed.port
    except ValueError as exc:
        raise EnvironmentPolicyError(f"event_environment_invalid:{name}") from exc
    if port == 443:
        raise EnvironmentPolicyError(f"event_environment_invalid:{name}")
    return raw.removesuffix("/")


def _https_url(raw: str, *, name: str) -> str:
    parsed = urlsplit(raw)
    if (
        any(character.isspace() or ord(character) < 32 for character in raw)
        or parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or parsed.netloc != parsed.netloc.lower()
    ):
        raise EnvironmentPolicyError(f"event_environment_invalid:{name}")
    try:
        parsed.port
    except ValueError as exc:
        raise EnvironmentPolicyError(f"event_environment_invalid:{name}") from exc
    return raw


def _decode(field: EventEnvironmentField, raw: str) -> Any:
    if field.kind == "string":
        if not raw or "\0" in raw or len(raw.encode("utf-8")) > 4096:
            raise EnvironmentPolicyError(f"event_environment_invalid:{field.name}")
        return raw
    if field.kind == "identifier":
        if _IDENTIFIER.fullmatch(raw) is None:
            raise EnvironmentPolicyError(f"event_environment_invalid:{field.name}")
        return raw
    if field.kind == "adapter_id":
        if _ADAPTER_ID.fullmatch(raw) is None:
            raise EnvironmentPolicyError(f"event_environment_invalid:{field.name}")
        return raw
    if field.kind == "absolute_path":
        if (
            _ABSOLUTE_PATH.fullmatch(raw) is None
            or raw.startswith("//")
            or ".." in raw.split("/")
        ):
            raise EnvironmentPolicyError(f"event_environment_invalid:{field.name}")
        return raw
    if field.kind == "https_url":
        return _https_url(raw, name=field.name)
    if field.kind == "https_origin":
        return _https_origin(raw, name=field.name)
    if field.kind == "timestamp":
        candidate = raw.replace("Z", "+00:00")
        try:
            datetime.fromisoformat(candidate)
        except ValueError as exc:
            raise EnvironmentPolicyError(f"event_environment_invalid:{field.name}") from exc
        return raw
    if field.kind == "bool01":
        if raw not in {"0", "1"}:
            raise EnvironmentPolicyError(f"event_environment_invalid:{field.name}")
        return raw == "1"
    if field.kind == "integer":
        if re.fullmatch(r"-?[0-9]+", raw) is None:
            raise EnvironmentPolicyError(f"event_environment_invalid:{field.name}")
        return _bounded_number(field, int(raw))
    if field.kind == "positive_integer_or_auto":
        if raw == "auto":
            return raw
        if re.fullmatch(r"[0-9]+", raw) is None or int(raw) < 1:
            raise EnvironmentPolicyError(f"event_environment_invalid:{field.name}")
        return int(raw)
    if field.kind == "decimal":
        try:
            value = float(raw)
        except ValueError as exc:
            raise EnvironmentPolicyError(f"event_environment_invalid:{field.name}") from exc
        if not math.isfinite(value):
            raise EnvironmentPolicyError(f"event_environment_invalid:{field.name}")
        return _bounded_number(field, value)
    if field.kind == "enum":
        if raw not in field.choices:
            raise EnvironmentPolicyError(f"event_environment_invalid:{field.name}")
        return raw
    if field.kind == "csv":
        value = split_csv(raw)
        if len(set(value)) != len(value):
            raise EnvironmentPolicyError(f"event_environment_invalid:{field.name}")
        return value
    if field.kind == "csv_integer":
        values = split_csv(raw)
        if not values or any(re.fullmatch(r"[0-9]+", item) is None for item in values):
            raise EnvironmentPolicyError(f"event_environment_invalid:{field.name}")
        decoded = [int(item) for item in values]
        if len(set(decoded)) != len(decoded):
            raise EnvironmentPolicyError(f"event_environment_invalid:{field.name}")
        for value in decoded:
            _bounded_number(field, value)
        return decoded
    if field.kind in {"json_string_array", "argv"}:
        return _json_string_array(field, raw)
    if field.kind == "environment_name":
        return validate_environment_name(raw, label=field.name)
    if field.kind == "environment_name_array":
        return list(parse_name_array(raw, label=field.name))
    if field.kind == "https_origin_array":
        return [_https_origin(item, name=field.name) for item in _json_string_array(field, raw)]
    if field.kind == "regex":
        try:
            re.compile(raw)
        except re.error as exc:
            raise EnvironmentPolicyError(f"event_environment_invalid:{field.name}") from exc
        return raw
    if field.kind == "json_number_object":
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise EnvironmentPolicyError(f"event_environment_invalid:{field.name}") from exc
        if not isinstance(value, dict) or len(value) > 256 or any(
            not isinstance(key, str)
            or not key
            or len(key.encode("utf-8")) > 128
            or isinstance(item, bool)
            or not isinstance(item, (int, float))
            or not math.isfinite(float(item))
            for key, item in value.items()
        ):
            raise EnvironmentPolicyError(f"event_environment_invalid:{field.name}")
        return value
    raise EnvironmentPolicyError("adapter_environment_schema_invalid")


def _set_path(target: dict[str, Any], path: tuple[str, ...], value: Any) -> None:
    current = target
    for part in path[:-1]:
        current = current.setdefault(part, {})
    current[path[-1]] = value


def _raw_values(root: Path, supplied: Mapping[str, str] | None, parent: Mapping[str, str] | None) -> dict[str, str]:
    if supplied is not None:
        if any(not isinstance(key, str) or not isinstance(value, str) for key, value in supplied.items()):
            raise EnvironmentPolicyError("event_environment_invalid")
        return dict(supplied)
    # Event configuration is deliberately dotenv-only. ``parent`` remains in
    # the public call shape so launch callers can pass one shared context, but
    # ambient process values never become event authority.
    _ = parent
    return _read_dotenv_compat(root / ".env")


def resolve_event_environment(
    root: Path,
    *,
    profile: str | None = None,
    env: Mapping[str, str] | None = None,
    parent: Mapping[str, str] | None = None,
) -> ResolvedEventEnvironment:
    raw = _raw_values(root, env, parent)
    # Import here because preparation's static policy imports manifest through
    # scope; the pure validator itself performs no preparation or I/O.
    from .operational_env import validate_operational_environment

    operational_unresolved = validate_operational_environment(raw)
    if _REMOVED_KEYS.intersection(raw):
        raise EnvironmentPolicyError("event_manifest_removed_use_migrate_event")
    configured_adapter = raw.get("PLATFORM_ADAPTER")
    if configured_adapter and configured_adapter.strip().casefold() == "unknown":
        configured_adapter = None
    selected = profile or configured_adapter or "manual"
    if _ADAPTER_ID.fullmatch(selected) is None:
        raise EnvironmentPolicyError("platform_adapter_invalid")
    if profile is not None and configured_adapter not in {None, "", profile}:
        raise EnvironmentPolicyError("platform_adapter_profile_conflict")
    fields = event_environment_schema(root, selected) + _selected_extension_fields(root, selected, raw)
    indexed = {field.name: field for field in fields}
    declared = set(indexed) | set(_KNOWN_NON_EVENT_NAMES)
    adapter_catalog = (
        adapter_environment_catalog_names(root)
        | RELEASE_ADAPTER_CATALOG_ENV_KEYS
        | extension_environment_catalog_names(root)
        | RELEASE_EXTENSION_CATALOG_ENV_KEYS
    )
    for selector in _DYNAMIC_NAME_SELECTORS.intersection(raw):
        if raw[selector]:
            declared.update(parse_name_array(raw[selector], label=selector))
    for field in fields:
        if field.kind == "environment_name_array" and raw.get(field.name):
            declared.update(parse_name_array(raw[field.name], label=field.name))
        elif field.kind == "environment_name" and raw.get(field.name):
            declared.add(validate_environment_name(raw[field.name], label=field.name))
    if any(classify_environment_name(name) is EnvClass.OWNER_TOKEN for name in declared):
        raise EnvironmentPolicyError("event_environment_owner_token_forbidden")
    unselected = adapter_catalog.difference(indexed)
    forbidden_unselected = sorted(key for key, value in raw.items() if value and key in unselected)
    if forbidden_unselected:
        raise EnvironmentPolicyError(f"event_environment_unselected:{forbidden_unselected[0]}")
    unknown = sorted(key for key in raw if key not in declared and key not in unselected)
    if unknown:
        raise EnvironmentPolicyError(f"event_environment_undeclared:{unknown[0]}")
    overlay: dict[str, Any] = {}
    decoded: dict[str, Any] = {}
    for name, field in indexed.items():
        value = raw.get(name, "")
        if not value:
            continue
        if value.strip().casefold() == "unknown":
            continue
        item = _decode(field, value)
        if field.credential:
            continue
        decoded[name] = item
        if field.target is not None:
            _set_path(overlay, field.target, item)
    adapter_config = overlay.get("adapter", {}).get("config", {})
    if selected in {"ctfd_browser", "ctfd_browser_gateway"}:
        mode = adapter_config.get("scoring_mode")
        team = adapter_config.get("expected_team_id")
        if team and mode != "team":
            raise EnvironmentPolicyError("event_environment_browser_identity_invalid")
    required = _required_environment(_adapter_descriptor(root, selected), set(indexed), raw) if selected != "manual" else ()
    return ResolvedEventEnvironment(
        selected,
        MappingProxyType(overlay),
        MappingProxyType(decoded),
        frozenset(declared),
        frozenset(field.name for field in fields if field.credential),
        tuple(dict.fromkeys((*required, *operational_unresolved))),
    )
