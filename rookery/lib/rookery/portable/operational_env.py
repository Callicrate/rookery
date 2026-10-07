"""Pure validation for fixed, non-event operator controls.

This module intentionally receives already-parsed dotenv values.  It neither
opens files nor contacts local services, so launch admission can evaluate these
controls before a baseline or runtime state exists.
"""

from __future__ import annotations

import json
import shlex
from collections.abc import Mapping
from typing import Final

from .environment import (
    DOTENV_MAX_LINE_BYTES,
    EnvClass,
    EnvironmentPolicyError,
    classify_environment_name,
    parse_name_array,
    resolve_browser_cdp_endpoint,
    resolve_browser_bidi_endpoint,
    resolve_browser_gateway_endpoint,
)
from .preparation import (
    APPROVED_MANAGED_SEARXNG_IMAGE,
    _approved_managed_searxng_image,
    _validated_http_url,
)

_BOOL_VALUES: Final = frozenset({"0", "1", "true", "false", "yes", "no", "on", "off"})
_PREPARATION_MODES: Final = frozenset({"auto", "check", "off"})
_SEARXNG_MODES: Final = frozenset({"auto", "disabled"})
_BROWSER_MODES: Final = frozenset({"auto", "cdp", "bidi", "disabled"})
_CONTAINER_ENGINES: Final = frozenset({"", "auto", "docker", "podman"})
_NETWORK_CLASSES: Final = frozenset({EnvClass.PROXY_CREDENTIAL, EnvClass.CA_TRUST_PATH})
_BROWSER_CLASSES: Final = frozenset(
    {
        EnvClass.OS_RUNTIME,
        EnvClass.TERMINAL_SETTING,
        EnvClass.CAPABILITY_PATH,
        EnvClass.UNKNOWN_EXPLICIT,
    }
)
_CODEX_PROVIDER_FORBIDDEN: Final = frozenset(
    {
        EnvClass.ADAPTER_SECRET,
        EnvClass.SESSION_SECRET_REF,
        EnvClass.VPN_SECRET_REF,
        EnvClass.OWNER_TOKEN,
        EnvClass.AGENT_CAPABILITY,
        EnvClass.PROXY_CREDENTIAL,
        EnvClass.CA_TRUST_PATH,
    }
)
_PATH_KEYS: Final = frozenset(
    {
        "BROWSER_EXECUTABLE",
        "CHROME_BIN",
        "ROCKYOU_PATH",
        "SECLISTS_PATH",
        "ROOKERY_MEASUREMENT_BASELINE_PATH",
    }
)
_STAGE_C_SELECTORS: Final = {
    "ROOKERY_PREPARE_NETWORK_ENV_KEYS": _NETWORK_CLASSES,
    "SEARXNG_NETWORK_ENV_KEYS": _NETWORK_CLASSES,
    "BROWSER_ENV_KEYS": _BROWSER_CLASSES,
    "TRANSIT_SOURCE_NETWORK_ENV_KEYS": _NETWORK_CLASSES,
    "NCQ_NETWORK_ENV_KEYS": _NETWORK_CLASSES,
}
_OPTIONAL_ARGV_KEYS: Final = frozenset(
    {"CREDENTIAL_HEALTH_ARGV", "NEAR_MISS_PROBE_ARGV"}
)


def _invalid(name: str) -> None:
    raise EnvironmentPolicyError(f"operational_environment_invalid:{name}")


def _value(raw: Mapping[str, str], name: str) -> str:
    value = raw.get(name, "")
    if not isinstance(value, str):
        _invalid(name)
    return value


def _optional_integer(raw: Mapping[str, str], name: str, *, default: int, maximum: int) -> None:
    value = _value(raw, name).strip()
    if not value:
        return
    try:
        parsed = int(value)
    except ValueError:
        _invalid(name)
    if not 1 <= parsed <= maximum:
        _invalid(name)


def _optional_bool(raw: Mapping[str, str], name: str) -> None:
    value = _value(raw, name).strip().casefold()
    if value and value not in _BOOL_VALUES:
        _invalid(name)


def _selector(
    raw: Mapping[str, str],
    name: str,
    allowed: frozenset[EnvClass],
    unresolved: set[str],
    *,
    required: bool,
) -> None:
    value = _value(raw, name)
    try:
        names = parse_name_array(value, label=name)
    except EnvironmentPolicyError as exc:
        raise EnvironmentPolicyError(f"operational_environment_invalid:{name}") from exc
    for selected in names:
        try:
            classification = classify_environment_name(selected)
        except EnvironmentPolicyError as exc:
            raise EnvironmentPolicyError(f"operational_environment_invalid:{name}") from exc
        if classification not in allowed:
            _invalid(name)
        selected_value = _value(raw, selected)
        if required and (not selected_value or selected_value.strip().casefold() == "unknown"):
            unresolved.add(selected)


def _optional_argv(raw: Mapping[str, str], name: str) -> None:
    value = _value(raw, name)
    if not value:
        return
    try:
        argv = json.loads(value)
    except json.JSONDecodeError as exc:
        raise EnvironmentPolicyError(f"operational_environment_invalid:{name}") from exc
    if (
        not isinstance(argv, list)
        or not argv
        or len(argv) > 128
        or any(
            not isinstance(item, str)
            or not item
            or "\0" in item
            or len(item.encode("utf-8")) > 8_192
            for item in argv
        )
    ):
        _invalid(name)


def _optional_path(raw: Mapping[str, str], name: str) -> None:
    value = _value(raw, name)
    if not value:
        return
    if (
        len(value.encode("utf-8")) > DOTENV_MAX_LINE_BYTES
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        _invalid(name)


def _truth(value: str) -> bool:
    return value.strip().casefold() in {"1", "true", "yes", "on"}


def validate_operational_environment(raw: Mapping[str, str]) -> tuple[str, ...]:
    """Validate fixed controls without reading files, resolving paths, or I/O.

    The return value is the sorted names of configured controls whose values are
    required before baseline admission.  Invalid syntax and contradictory
    authority always raise value-private errors naming only their control.
    """

    if not isinstance(raw, Mapping):
        _invalid("environment")
    if any(not isinstance(name, str) or not isinstance(value, str) for name, value in raw.items()):
        _invalid("environment")
    unresolved: set[str] = set()

    prepare_mode = _value(raw, "ROOKERY_PREPARE_MODE").strip().casefold() or "auto"
    if prepare_mode not in _PREPARATION_MODES:
        _invalid("ROOKERY_PREPARE_MODE")
    searxng_mode = _value(raw, "SEARXNG_MODE").strip().casefold() or "auto"
    if searxng_mode not in _SEARXNG_MODES:
        _invalid("SEARXNG_MODE")
    browser_mode = _value(raw, "BROWSER_MODE").strip().casefold() or "auto"
    if browser_mode not in _BROWSER_MODES:
        _invalid("BROWSER_MODE")
    if _value(raw, "SEARXNG_CONTAINER_ENGINE").strip().casefold() not in _CONTAINER_ENGINES:
        _invalid("SEARXNG_CONTAINER_ENGINE")
    for name, default, maximum in (
        ("ROOKERY_PREPARE_TIMEOUT", 1200, 3600),
        ("SEARXNG_START_TIMEOUT", 120, 900),
        ("SEARXNG_LOCAL_PORT", 8080, 65535),
    ):
        _optional_integer(raw, name, default=default, maximum=maximum)
    for name in (
        "ROOKERY_PREPARE_INSTALL",
        "ROOKERY_INSTALL_RECOMMENDED",
        "ROOKERY_INSTALL_HEAVY",
        "ROOKERY_ALLOW_INSTALL_NETWORK",
    ):
        _optional_bool(raw, name)
    image = _value(raw, "SEARXNG_IMAGE") or APPROVED_MANAGED_SEARXNG_IMAGE
    try:
        _approved_managed_searxng_image({"SEARXNG_IMAGE": image})
    except EnvironmentPolicyError as exc:
        raise EnvironmentPolicyError("operational_environment_invalid:SEARXNG_IMAGE") from exc
    searxng_url = _value(raw, "SEARXNG_URL").strip()
    if searxng_url:
        try:
            _validated_http_url(searxng_url, label="SEARXNG")
        except EnvironmentPolicyError as exc:
            raise EnvironmentPolicyError("operational_environment_invalid:SEARXNG_URL") from exc

    cdp_url = _value(raw, "BROWSER_CDP_URL")
    if browser_mode == "cdp" and not cdp_url.strip():
        unresolved.add("BROWSER_CDP_URL")
    elif cdp_url.strip():
        try:
            resolve_browser_cdp_endpoint(cdp_url)
        except EnvironmentPolicyError as exc:
            raise EnvironmentPolicyError("operational_environment_invalid:BROWSER_CDP_URL") from exc
    bidi_url = _value(raw, "BROWSER_BIDI_URL")
    if browser_mode == "bidi" and not bidi_url.strip():
        unresolved.add("BROWSER_BIDI_URL")
    elif bidi_url.strip():
        try:
            resolve_browser_bidi_endpoint(bidi_url)
        except EnvironmentPolicyError as exc:
            raise EnvironmentPolicyError("operational_environment_invalid:BROWSER_BIDI_URL") from exc
    gateway_url = _value(raw, "BROWSER_GATEWAY_URL")
    if gateway_url.strip():
        try:
            resolve_browser_gateway_endpoint(gateway_url)
        except EnvironmentPolicyError as exc:
            raise EnvironmentPolicyError("operational_environment_invalid:BROWSER_GATEWAY_URL") from exc

    codex_mode = _value(raw, "CODEX_AUTH_MODE").strip() or "local-login"
    if codex_mode not in {"local-login", "environment"}:
        _invalid("CODEX_AUTH_MODE")
    try:
        provider_names = parse_name_array(_value(raw, "CODEX_PROVIDER_ENV_KEYS"), label="CODEX_PROVIDER_ENV_KEYS")
    except EnvironmentPolicyError as exc:
        raise EnvironmentPolicyError("operational_environment_invalid:CODEX_PROVIDER_ENV_KEYS") from exc
    try:
        network_names = parse_name_array(_value(raw, "CODEX_NETWORK_ENV_KEYS"), label="CODEX_NETWORK_ENV_KEYS")
    except EnvironmentPolicyError as exc:
        raise EnvironmentPolicyError("operational_environment_invalid:CODEX_NETWORK_ENV_KEYS") from exc
    if codex_mode == "local-login":
        if provider_names or network_names:
            _invalid("CODEX_AUTH_MODE")
    else:
        if not provider_names:
            unresolved.add("CODEX_PROVIDER_ENV_KEYS")
        for name in provider_names:
            if classify_environment_name(name) in _CODEX_PROVIDER_FORBIDDEN:
                _invalid("CODEX_PROVIDER_ENV_KEYS")
            if not _value(raw, name) or _value(raw, name).strip().casefold() == "unknown":
                unresolved.add(name)
        for name in network_names:
            if classify_environment_name(name) not in _NETWORK_CLASSES:
                _invalid("CODEX_NETWORK_ENV_KEYS")
            if not _value(raw, name) or _value(raw, name).strip().casefold() == "unknown":
                unresolved.add(name)

    stage_c_required = {
        "ROOKERY_PREPARE_NETWORK_ENV_KEYS": prepare_mode != "off"
        and _truth(_value(raw, "ROOKERY_ALLOW_INSTALL_NETWORK")),
        "SEARXNG_NETWORK_ENV_KEYS": searxng_mode != "disabled",
        "BROWSER_ENV_KEYS": browser_mode != "disabled",
        "TRANSIT_SOURCE_NETWORK_ENV_KEYS": True,
        "NCQ_NETWORK_ENV_KEYS": True,
    }
    for name, allowed in _STAGE_C_SELECTORS.items():
        _selector(raw, name, allowed, unresolved, required=stage_c_required[name])
    for name in _OPTIONAL_ARGV_KEYS:
        _optional_argv(raw, name)
    for name in _PATH_KEYS:
        _optional_path(raw, name)
    sudo = _value(raw, "ROOKERY_SUDO").strip()
    if sudo:
        try:
            argv = shlex.split(sudo)
        except ValueError as exc:
            raise EnvironmentPolicyError("operational_environment_invalid:ROOKERY_SUDO") from exc
        if not argv or any(arg == "-E" or arg.startswith("--preserve-env") for arg in argv):
            _invalid("ROOKERY_SUDO")
    return tuple(sorted(unresolved))
