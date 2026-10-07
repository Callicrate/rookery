from __future__ import annotations

import copy
import json
import math
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .environment import parse_name_array
from .event_env import resolve_event_environment
from .util import (
    bool_value,
    deep_merge,
    load_json,
    parse_iso,
    split_csv,
)

UNKNOWN = "unknown"
AUTO_WORKER_COUNT = "auto"

REQUIRED_TOP = {
    "schema_version": str,
    "identity": dict,
    "adapter": dict,
    "capabilities": dict,
    "scoring": dict,
    "authorization": dict,
    "scope": dict,
    "session": dict,
    "release": dict,
    "concurrency": dict,
    "answer_morphology": dict,
    "queue": dict,
    "writeups": dict,
    "compute": dict,
    "priority": dict,
    "surface": dict,
}

UNION_LIST_PATHS = {
    ("capabilities", "required"),
    ("capabilities", "optional"),
    ("surface", "bundles"),
    ("surface", "categories"),
    ("surface", "extensions"),
    ("scoring", "action_kinds"),
}


@dataclass(frozen=True)
class ManifestResult:
    manifest: dict[str, Any]
    errors: tuple[str, ...]
    warnings: tuple[str, ...]
    unresolved_required: tuple[str, ...]

    @property
    def ready(self) -> bool:
        return not self.errors and not self.unresolved_required


def profile_path(root: Path, profile: str) -> Path:
    base = root / "profiles" / f"{profile}.json"
    if base.exists():
        return base
    adapter = root / "adapters" / profile / "profile.json"
    return adapter


def load_profile(root: Path, profile: str) -> dict[str, Any]:
    path = profile_path(root, profile)
    obj = load_json(path)
    if not isinstance(obj, dict):
        raise ValueError(f"profile not found or invalid: {profile}")
    return obj


def extension_descriptor(root: Path, extension_id: str) -> dict[str, Any]:
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", extension_id):
        raise ValueError(f"invalid extension id: {extension_id}")
    path = root / "extensions" / extension_id / "extension.json"
    data = load_json(path)
    if not isinstance(data, dict) or data.get("id") != extension_id:
        raise ValueError(f"extension not found or invalid: {extension_id}")
    return data


def adapter_descriptor(root: Path, adapter_id: str) -> dict[str, Any] | None:
    path = root / "adapters" / adapter_id / "adapter.json"
    data = load_json(path)
    if data is None:
        return None
    if not isinstance(data, dict) or data.get("id") != adapter_id:
        raise ValueError(f"adapter descriptor invalid: {adapter_id}")
    return data


def merge_capability_overlay(
    base: dict[str, Any], overlay: dict[str, Any], path: tuple[str, ...] = ()
) -> dict[str, Any]:
    out = copy.deepcopy(base)
    for key, value in overlay.items():
        here = path + (key,)
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = merge_capability_overlay(out[key], value, here)
        elif here in UNION_LIST_PATHS and isinstance(value, list):
            existing = list(out.get(key, [])) if isinstance(out.get(key), list) else []
            out[key] = list(dict.fromkeys(existing + copy.deepcopy(value)))
        else:
            out[key] = copy.deepcopy(value)
    return out


def load_extension_overlay(root: Path, extension_id: str) -> dict[str, Any]:
    desc = extension_descriptor(root, extension_id)
    overlay_path = root / "extensions" / extension_id / str(desc.get("overlay", "overlay.json"))
    obj = load_json(overlay_path, {})
    if not isinstance(obj, dict):
        raise ValueError(f"invalid extension overlay: {extension_id}")
    return obj


def env_overlay(env: Mapping[str, str]) -> dict[str, Any]:
    overlay: dict[str, Any] = {}

    def set_path(path: list[str], value: Any) -> None:
        cur = overlay
        for part in path[:-1]:
            cur = cur.setdefault(part, {})
        cur[path[-1]] = value

    mapping = {
        "EVENT_NAME": ["identity", "name"],
        "EVENT_ID": ["identity", "id"],
        "EVENT_URL": ["identity", "url"],
        "EVENT_START": ["identity", "starts_at"],
        "EVENT_END": ["identity", "ends_at"],
        "PLATFORM_ADAPTER": ["adapter", "id"],
        "FLAG_REGEX": ["answer_morphology", "regex"],
        "EVENT_SCOPE_ACK": ["scope", "acknowledged"],
        "SCOPE_EXPIRES_AT": ["scope", "expires_at"],
        "SCOPE_MAX_BYTES": ["scope", "max_attachment_bytes"],
        "WRITEUP_MODE": ["writeups", "mode"],
        "QUEUE_AUTOMATION": ["queue", "automation_enabled"],
        "QUEUE_CADENCE_SECONDS": ["queue", "cadence_seconds"],
        "QUEUE_JITTER_SECONDS": ["queue", "jitter_seconds"],
        "QUEUE_LATENCY_SECONDS": ["queue", "latency_objective_seconds"],
        "QUEUE_WATCH_INTERVAL_SECONDS": ["queue", "watch_interval_seconds"],
        "CONCURRENCY_MAX_WORKERS": ["concurrency", "max_workers"],
        "CONCURRENCY_MAX_JOBS": ["concurrency", "max_jobs"],
        "CODEX_SUBAGENT_THREADS": [
            "concurrency",
            "max_subagent_threads",
        ],
        "COMPUTE_TOTAL_UNITS": ["compute", "total_units"],
        "COMPUTE_INTERACTIVE_RESERVE": ["compute", "interactive_reserve_units"],
    }
    for key, path in mapping.items():
        if key not in env or env[key] == "":
            continue
        # Placeholder values in local configuration must never shadow a concrete
        # value from the canonical event manifest. Operators can still override
        # any field by supplying an explicit non-placeholder value.
        if str(env[key]).strip().lower() == UNKNOWN:
            continue
        value: Any = env[key]
        if key in {"EVENT_SCOPE_ACK", "QUEUE_AUTOMATION"}:
            value = bool_value(value)
        elif key == "CONCURRENCY_MAX_WORKERS":
            value = AUTO_WORKER_COUNT if str(value).strip().lower() == AUTO_WORKER_COUNT else int(value)
        elif key == "CODEX_SUBAGENT_THREADS":
            if not re.fullmatch(r"[0-9]+", str(value)):
                raise ValueError(f"{key} must be an unsigned decimal integer")
            value = int(value)
        elif key in {
            "SCOPE_MAX_BYTES",
            "QUEUE_CADENCE_SECONDS",
            "QUEUE_JITTER_SECONDS",
            "QUEUE_LATENCY_SECONDS",
            "QUEUE_WATCH_INTERVAL_SECONDS",
            "CONCURRENCY_MAX_JOBS",
            "COMPUTE_TOTAL_UNITS",
            "COMPUTE_INTERACTIVE_RESERVE",
        }:
            value = int(value)
        set_path(path, value)
    lists = {
        "ALLOWED_HOSTS": ["scope", "allowed_hosts"],
        "ALLOWED_CIDRS": ["scope", "allowed_cidrs"],
        "ALLOWED_PORTS": ["scope", "allowed_ports"],
        "ALLOWED_PROTOCOLS": ["scope", "allowed_protocols"],
        "ALLOWED_FILE_ORIGINS": ["scope", "allowed_file_origins"],
        "PLATFORM_HOSTS": ["scope", "platform_hosts"],
        "SCORING_ACTION_KINDS": ["scoring", "action_kinds"],
        "AUTOMATION_PERMITTED_ACTION_KINDS": [
            "authorization",
            "automation_permitted_action_kinds",
        ],
        "EVENT_CATEGORIES": ["surface", "categories"],
        "EVENT_EXTENSIONS": ["surface", "extensions"],
    }
    for key, path in lists.items():
        if env.get(key):
            values: list[Any] = split_csv(env[key])
            if key == "ALLOWED_PORTS":
                values = [int(v) for v in values]
            set_path(path, values)
    adapter_cfg = {}
    for key, value in env.items():
        if key.startswith("ADAPTER_CONFIG_") and value != "":
            name = key[len("ADAPTER_CONFIG_") :].lower()
            if name.endswith("_argv"):
                parsed = json.loads(value)
                if not isinstance(parsed, list) or any(not isinstance(argument, str) for argument in parsed):
                    raise ValueError(f"{key} must be a JSON string array")
                adapter_cfg[name] = parsed
            elif name in {"inventory_env_keys", "submit_env_keys"}:
                # These are exact child-process declarations, never shell globs or
                # inherited environment selectors. Keep a structured list in the
                # manifest so CommandAdapter does not need to parse untrusted text.
                adapter_cfg[name] = list(parse_name_array(value, label=key))
            else:
                adapter_cfg[name] = value
    if adapter_cfg:
        set_path(["adapter", "config"], adapter_cfg)
    return overlay


def available_logical_cpu_count() -> int:
    """Return the logical CPUs available to this process."""

    affinity_reader = getattr(os, "sched_getaffinity", None)
    if callable(affinity_reader):
        try:
            affinity_count = len(affinity_reader(0))
        except (OSError, NotImplementedError):
            affinity_count = 0
        if affinity_count > 0:
            return affinity_count
    process_cpu_reader = getattr(os, "process_cpu_count", None)
    if callable(process_cpu_reader):
        try:
            process_cpu_count = process_cpu_reader()
        except (OSError, NotImplementedError):
            process_cpu_count = None
        if isinstance(process_cpu_count, int) and not isinstance(process_cpu_count, bool) and process_cpu_count > 0:
            return process_cpu_count
    return max(1, os.cpu_count() or 1)


def _resolve_worker_count(manifest: dict[str, Any]) -> None:
    concurrency = manifest.get("concurrency")
    if not isinstance(concurrency, dict):
        return
    configured = concurrency.get("max_workers")
    if isinstance(configured, str) and configured.strip().lower() == AUTO_WORKER_COUNT:
        concurrency["max_workers"] = available_logical_cpu_count()


def resolve_manifest(
    root: Path,
    *,
    profile: str | None = None,
    env: Mapping[str, str] | None = None,
    parent: Mapping[str, str] | None = None,
) -> ManifestResult:
    resolved_environment = resolve_event_environment(
        root,
        profile=profile,
        env=env,
        parent=parent,
    )
    selected_name = resolved_environment.adapter_id
    base = load_profile(root, "generic")
    selected = load_profile(root, selected_name)
    merged = deep_merge(base, selected)
    merged = deep_merge(merged, dict(resolved_environment.overlay))
    merged["profile"] = selected_name

    adapter_id = str(merged.get("adapter", {}).get("id") or selected_name)
    extensions = list(merged.get("surface", {}).get("extensions", []) or [])
    desc = adapter_descriptor(root, adapter_id)
    if desc:
        extensions.extend(desc.get("default_extensions", []) or [])
    extensions = list(dict.fromkeys(str(x) for x in extensions if str(x)))
    for extension_id in extensions:
        merged = merge_capability_overlay(merged, load_extension_overlay(root, extension_id))
    _resolve_worker_count(merged)
    merged.setdefault("surface", {})["extensions"] = extensions
    result = validate_manifest(merged)
    platform_errors: tuple[str, ...] = ()
    if not result.errors:
        platform_errors = _platform_origin_scope_errors(root, selected_name, resolved_environment.values, merged)
    return ManifestResult(
        result.manifest,
        (*result.errors, *platform_errors),
        result.warnings,
        tuple(dict.fromkeys((*result.unresolved_required, *resolved_environment.unresolved_required))),
    )


def _platform_origin_scope_errors(
    root: Path,
    adapter_id: str,
    values: Mapping[str, Any],
    manifest: dict[str, Any],
) -> tuple[str, ...]:
    """Check selected descriptor origins against the declared platform scope."""

    descriptor = adapter_descriptor(root, adapter_id)
    if not descriptor:
        return ()
    origin_fields = descriptor.get("platform_origin_environment", [])
    support_field = descriptor.get("platform_support_origins_environment")
    if not isinstance(origin_fields, list) or any(not isinstance(name, str) for name in origin_fields):
        return ("selected adapter platform origin contract invalid",)
    if support_field is not None and not isinstance(support_field, str):
        return ("selected adapter platform support contract invalid",)
    if not origin_fields and support_field is None:
        return ()

    from .scope import check_url, compile_scope

    try:
        scope = compile_scope(manifest, generation=0)
    except (TypeError, ValueError):
        return ("declared platform scope invalid",)
    errors: list[str] = []
    for name in origin_fields:
        value = values.get(name)
        if not value:
            continue
        if not isinstance(value, str) or not check_url(scope, value, platform=True).allowed:
            errors.append(f"selected platform origin outside scope: {name}")
    if support_field is not None:
        support_origins = values.get(support_field, [])
        if not isinstance(support_origins, list) or any(
            not isinstance(origin, str) or not check_url(scope, origin, platform=True).allowed
            for origin in support_origins
        ):
            errors.append(f"selected platform support origin outside scope: {support_field}")
    return tuple(dict.fromkeys(errors))


def validate_manifest(manifest: dict[str, Any]) -> ManifestResult:
    errors: list[str] = []
    warnings: list[str] = []
    unresolved: list[str] = []
    for key, typ in REQUIRED_TOP.items():
        if key not in manifest:
            errors.append(f"missing top-level field: {key}")
        elif not isinstance(manifest[key], typ):
            errors.append(f"{key} must be {typ.__name__}")
    if errors:
        return ManifestResult(manifest, tuple(errors), tuple(warnings), tuple(unresolved))
    if manifest["identity"].get("name") in {None, "", UNKNOWN}:
        unresolved.append("identity.name")
    adapter_id = manifest["adapter"].get("id")
    if adapter_id in {None, "", UNKNOWN}:
        unresolved.append("adapter.id")
    if not isinstance(manifest["capabilities"].get("required", []), list):
        errors.append("capabilities.required must be a list")
    if not isinstance(manifest["capabilities"].get("optional", []), list):
        errors.append("capabilities.optional must be a list")
    scoring_kinds = manifest["scoring"].get("action_kinds", [])
    if not isinstance(scoring_kinds, list) or not scoring_kinds:
        unresolved.append("scoring.action_kinds")
    allowed_action_kinds = {
        "flag",
        "free_text",
        "multi_objective",
        "handle_write",
        "proof_artifact",
        "no_submit_evidence",
    }
    if isinstance(scoring_kinds, list) and any(kind not in allowed_action_kinds for kind in scoring_kinds):
        errors.append("scoring.action_kinds contains an unsupported action kind")
    completion_mode = manifest["scoring"].get("completion_mode", "scorer_truth")
    if completion_mode not in {"scorer_truth", "evidence_only"}:
        errors.append("scoring.completion_mode must be scorer_truth or evidence_only")
    elif completion_mode == "evidence_only" and scoring_kinds != ["no_submit_evidence"]:
        errors.append("scoring.action_kinds must be exactly no_submit_evidence in evidence_only mode")
    auth = manifest["authorization"]
    if int(auth.get("default_allowance", 0)) != 0:
        errors.append("authorization.default_allowance must be zero")
    permitted = auth.get("automation_permitted_action_kinds", [])
    if not isinstance(permitted, list) or any(kind not in allowed_action_kinds for kind in permitted):
        errors.append("authorization.automation_permitted_action_kinds contains an unsupported action kind")
    elif isinstance(scoring_kinds, list) and not set(permitted).issubset(scoring_kinds):
        errors.append("authorization.automation_permitted_action_kinds must be declared scoring actions")
    scope = manifest["scope"]
    if not scope.get("acknowledged", False):
        unresolved.append("scope.acknowledged")
    if not any(scope.get(key) for key in ("allowed_hosts", "allowed_cidrs", "allowed_file_origins")):
        unresolved.append("scope.allowed_hosts|allowed_cidrs|allowed_file_origins")
    if scope.get("expires_at") not in {None, "", UNKNOWN} and parse_iso(str(scope.get("expires_at"))) is None:
        errors.append("scope.expires_at must be ISO-8601 or unknown")
    if int(scope.get("max_attachment_bytes", 0) or 0) <= 0:
        unresolved.append("scope.max_attachment_bytes")
    queue = manifest["queue"]
    concurrency = manifest["concurrency"]
    max_workers = concurrency.get("max_workers")
    if isinstance(max_workers, bool) or not isinstance(max_workers, int) or max_workers < 1:
        errors.append("concurrency.max_workers must be a positive integer")
    for name, minimum, maximum in (
        ("max_jobs", 1, 256),
        ("max_subagent_threads", 1, 256),
    ):
        value = concurrency.get(name)
        if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
            errors.append(f"concurrency.{name} must be an integer from {minimum} to {maximum}")
    depth = concurrency.get("max_agent_depth")
    if isinstance(depth, bool) or depth != 2:
        errors.append("concurrency.max_agent_depth must be 2")
    compute = manifest["compute"]
    for name, minimum, maximum in (
        ("total_units", 1, 4096),
        ("interactive_reserve_units", 0, 4096),
        ("default_job_budget_seconds", 1, 86400),
    ):
        value = compute.get(name)
        if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
            errors.append(f"compute.{name} must be an integer from {minimum} to {maximum}")
    if (
        isinstance(compute.get("total_units"), int)
        and isinstance(compute.get("interactive_reserve_units"), int)
        and compute["interactive_reserve_units"] > compute["total_units"]
    ):
        errors.append("compute.interactive_reserve_units must not exceed compute.total_units")
    compute_defaults = {
        "admit_percent": 70,
        "target_percent": 75,
        "ceiling_percent": 80,
        "backoff_percent": 85,
    }
    try:
        admit, target, ceiling, backoff = (
            float(compute.get(name, compute_defaults[name]))
            for name in (
                "admit_percent",
                "target_percent",
                "ceiling_percent",
                "backoff_percent",
            )
        )
        if not (
            all(math.isfinite(value) for value in (admit, target, ceiling, backoff))
            and 0 <= admit < target <= ceiling < backoff <= 100
        ):
            raise ValueError
    except (KeyError, TypeError, ValueError):
        errors.append("compute CPU thresholds must satisfy 0 <= admit < target <= ceiling < backoff <= 100")
    try:
        sample_seconds = float(compute.get("sample_seconds", 1))
        if not math.isfinite(sample_seconds) or not 0 < sample_seconds <= 30:
            raise ValueError
    except (KeyError, TypeError, ValueError):
        errors.append("compute.sample_seconds must be in (0, 30]")
    for name, default, lower, upper in (
        ("admission_cooldown_seconds", 5, 0, 3600),
        ("lease_seconds", 30, 5, 300),
    ):
        value = compute.get(name, default)
        if isinstance(value, bool) or not isinstance(value, int) or not lower <= value <= upper:
            errors.append(f"compute.{name} must be an integer from {lower} to {upper}")
    for field in ("cadence_seconds", "jitter_seconds", "latency_objective_seconds"):
        if int(queue.get(field, 0) or 0) < 0:
            errors.append(f"queue.{field} must be non-negative")
    if (queue.get("cadence_seconds", 0) or queue.get("jitter_seconds", 0)) and not queue.get(
        "automation_enabled", False
    ):
        warnings.append("queue pacing configured while automation is disabled")
    watch_interval = queue.get("watch_interval_seconds")
    if isinstance(watch_interval, bool) or not isinstance(watch_interval, int) or not 1 <= watch_interval <= 3600:
        errors.append("queue.watch_interval_seconds must be an integer from 1 to 3600")
    examples = manifest["answer_morphology"].get("examples", [])
    if not isinstance(examples, list) or any(not isinstance(item, str) for item in examples):
        errors.append("answer_morphology.examples must be a string list")
    regex = manifest["answer_morphology"].get("regex")
    if regex not in {None, "", UNKNOWN}:
        try:
            re.compile(str(regex))
        except re.error as exc:
            errors.append(f"invalid answer morphology regex: {exc}")
    priority = manifest["priority"]
    if priority.get("strategy") not in {"balanced", "sequential"}:
        errors.append("priority.strategy must be balanced or sequential")
    weights = priority.get("weights")
    if not isinstance(weights, dict) or any(
        not isinstance(name, str)
        or isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        for name, value in (weights.items() if isinstance(weights, dict) else ())
    ):
        errors.append("priority.weights must be an object of finite numbers")
    return ManifestResult(
        manifest,
        tuple(sorted(set(errors))),
        tuple(sorted(set(warnings))),
        tuple(sorted(set(unresolved))),
    )


def capability_required(manifest: dict[str, Any], name: str) -> bool:
    return name in set(manifest.get("capabilities", {}).get("required", []))


def profile_has_platform_assumption(manifest: dict[str, Any], adapter_ids: list[str]) -> bool:
    text = json.dumps(manifest, sort_keys=True).lower()
    return any(adapter_id.lower() in text for adapter_id in adapter_ids if adapter_id not in {"manual", "unknown"})
