"""Export one private, prelaunch policy for the browser scope gateway."""

from __future__ import annotations

import copy
import datetime as dt
import hashlib
import ipaddress
import os
import re
import stat
import urllib.parse
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .baseline import MeasurementBaselineError, verify_measurement_baseline
from .environment import (
    CODEX_CONTROL_KEYS,
    EnvironmentPolicyError,
    read_declared_environment,
)
from .event_env import resolve_event_environment
from .manifest import UNKNOWN, resolve_manifest
from .scope import canonical_hostname, check_url, compile_scope
from .util import canonical_json, parse_iso

POLICY_SCHEMA_VERSION = "1"
GATEWAY_ADAPTER_ID = "ctfd_browser_gateway"
GATEWAY_ADAPTER_IDS = frozenset({GATEWAY_ADAPTER_ID, "skillbit"})
_GATEWAY_ADAPTER_ORIGIN_ENVIRONMENT = {
    GATEWAY_ADAPTER_ID: "CTFD_URL",
    "skillbit": "SKILLBIT_URL",
}
SCOPE_GENERATION = 1
_SHA256_LENGTH = 64
_MAX_EVENT_ID_BYTES = 256
_MAX_ORIGIN_BYTES = 4096
_MAX_SUPPORT_ORIGINS = 8
_DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")


class BrowserGatewayPolicyError(RuntimeError):
    """A value-free refusal to export a browser gateway policy."""


def semantic_scope(scope: Mapping[str, Any]) -> dict[str, Any]:
    """Copy the compiled scope while omitting its nonsemantic timestamp."""

    if not isinstance(scope, Mapping):
        raise BrowserGatewayPolicyError("browser_gateway_policy_scope_invalid")
    return {
        key: copy.deepcopy(value)
        for key, value in scope.items()
        if key != "compiled_at"
    }


def scope_sha256(scope: Mapping[str, Any]) -> str:
    """Hash the canonical semantic compiled-scope representation."""

    try:
        encoded = canonical_json(semantic_scope(scope)).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise BrowserGatewayPolicyError("browser_gateway_policy_scope_invalid") from exc
    return hashlib.sha256(encoded).hexdigest()


def semantic_policy(policy: Mapping[str, Any]) -> dict[str, Any]:
    """Copy a policy while removing the scope publication timestamp."""

    if not isinstance(policy, Mapping):
        raise BrowserGatewayPolicyError("browser_gateway_policy_invalid")
    scope = policy.get("scope")
    if not isinstance(scope, Mapping):
        raise BrowserGatewayPolicyError("browser_gateway_policy_scope_invalid")
    out = {key: copy.deepcopy(value) for key, value in policy.items()}
    out["scope"] = semantic_scope(scope)
    return out


def policy_sha256(policy: Mapping[str, Any]) -> str:
    """Hash the canonical policy after removing nonsemantic scope metadata."""

    try:
        encoded = canonical_json(semantic_policy(policy)).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise BrowserGatewayPolicyError("browser_gateway_policy_invalid") from exc
    return hashlib.sha256(encoded).hexdigest()


def canonical_gateway_origin(value: object) -> str:
    """Return the one HTTPS DNS origin accepted by the browser gateway."""

    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > _MAX_ORIGIN_BYTES
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        raise BrowserGatewayPolicyError("browser_gateway_policy_origin_invalid")
    try:
        parsed = urllib.parse.urlsplit(value)
        host = canonical_hostname(parsed.hostname or "")
        port = parsed.port
        ipaddress.ip_address(host)
    except (UnicodeError, ValueError):
        try:
            parsed = urllib.parse.urlsplit(value)
            host = canonical_hostname(parsed.hostname or "")
            port = parsed.port
        except (UnicodeError, ValueError) as exc:
            raise BrowserGatewayPolicyError("browser_gateway_policy_origin_invalid") from exc
    else:
        raise BrowserGatewayPolicyError("browser_gateway_policy_origin_invalid")
    if (
        parsed.scheme.casefold() != "https"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or port not in {None, 443}
        or not host
        or any(not _DNS_LABEL.fullmatch(label) for label in host.split("."))
    ):
        raise BrowserGatewayPolicyError("browser_gateway_policy_origin_invalid")
    return f"https://{host}"


def _valid_digest(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == _SHA256_LENGTH
        and all(character in "0123456789abcdef" for character in value)
    )


def _event_id(manifest: Mapping[str, Any]) -> str:
    identity = manifest.get("identity")
    event_id = identity.get("id") if isinstance(identity, Mapping) else None
    if (
        not isinstance(event_id, str)
        or not event_id
        or event_id == UNKNOWN
        or len(event_id.encode("utf-8")) > _MAX_EVENT_ID_BYTES
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in event_id)
    ):
        raise BrowserGatewayPolicyError("browser_gateway_policy_event_invalid")
    return event_id


def _adapter_origin(manifest: Mapping[str, Any], environment_origin: str | None) -> str:
    adapter = manifest.get("adapter")
    config = adapter.get("config") if isinstance(adapter, Mapping) else None
    configured = config.get("base_url") if isinstance(config, Mapping) else None
    if configured is not None and not (
        isinstance(configured, str) and configured in {"", UNKNOWN}
    ):
        return canonical_gateway_origin(configured)
    return canonical_gateway_origin(environment_origin)


def browser_gateway_environment_origin_name(manifest: Mapping[str, Any]) -> str:
    """Return the declared platform-origin key for a reviewed gateway adapter."""

    adapter = manifest.get("adapter")
    adapter_id = adapter.get("id") if isinstance(adapter, Mapping) else None
    if not isinstance(adapter_id, str) or adapter_id not in GATEWAY_ADAPTER_IDS:
        raise BrowserGatewayPolicyError("browser_gateway_policy_adapter_invalid")
    return _GATEWAY_ADAPTER_ORIGIN_ENVIRONMENT[adapter_id]


def browser_gateway_origin(
    manifest: Mapping[str, Any], environment_origin: str | None = None
) -> str:
    """Resolve the selected gateway adapter's one canonical platform origin."""

    browser_gateway_environment_origin_name(manifest)
    return _adapter_origin(manifest, environment_origin)


def browser_gateway_origins(
    manifest: Mapping[str, Any], environment_origin: str | None = None
) -> tuple[str, ...]:
    """Return the main origin followed by sorted declared support origins."""

    main_origin = browser_gateway_origin(manifest, environment_origin)
    adapter = manifest.get("adapter")
    adapter_id = adapter.get("id") if isinstance(adapter, Mapping) else None
    config = adapter.get("config") if isinstance(adapter, Mapping) else None
    configured = (
        config.get("browser_support_origins") if isinstance(config, Mapping) else None
    )
    if configured is None:
        return (main_origin,)
    if not isinstance(configured, list) or len(configured) > _MAX_SUPPORT_ORIGINS:
        raise BrowserGatewayPolicyError("browser_gateway_policy_support_origins_invalid")
    supports: set[str] = set()
    for value in configured:
        try:
            origin = canonical_gateway_origin(value)
        except BrowserGatewayPolicyError as exc:
            raise BrowserGatewayPolicyError(
                "browser_gateway_policy_support_origins_invalid"
            ) from exc
        # Support origins are baseline-bound JSON values.  Requiring their
        # canonical spelling makes the sealed policy reproducible before it
        # reaches the gateway process.
        if value != origin or origin == main_origin or origin in supports:
            raise BrowserGatewayPolicyError("browser_gateway_policy_support_origins_invalid")
        supports.add(origin)
    if adapter_id == "skillbit":
        login_origin = config.get("login_origin") if isinstance(config, Mapping) else None
        try:
            canonical_login_origin = canonical_gateway_origin(login_origin)
        except BrowserGatewayPolicyError as exc:
            raise BrowserGatewayPolicyError(
                "browser_gateway_policy_support_origins_invalid"
            ) from exc
        if login_origin != canonical_login_origin or canonical_login_origin not in supports:
            raise BrowserGatewayPolicyError(
                "browser_gateway_policy_support_origins_invalid"
            )
    return (main_origin, *sorted(supports))


def compile_browser_gateway_policy(
    manifest: Mapping[str, Any],
    *,
    baseline_configuration_digest: str,
    origin: str,
    environment_origin: str | None = None,
    now: dt.datetime | None = None,
) -> dict[str, Any]:
    """Build a gateway policy from already-resolved, verified launch inputs."""

    browser_gateway_environment_origin_name(manifest)
    if not _valid_digest(baseline_configuration_digest):
        raise BrowserGatewayPolicyError("browser_gateway_policy_baseline_invalid")
    canonical_origin = canonical_gateway_origin(origin)
    origins = browser_gateway_origins(manifest, environment_origin)
    if canonical_origin != origins[0]:
        raise BrowserGatewayPolicyError("browser_gateway_policy_origin_mismatch")
    try:
        scope = compile_scope(dict(manifest), generation=SCOPE_GENERATION)
    except (TypeError, ValueError) as exc:
        raise BrowserGatewayPolicyError("browser_gateway_policy_scope_invalid") from exc
    expires_at = scope.get("expires_at")
    expires = parse_iso(expires_at if isinstance(expires_at, str) else None)
    reference = now or dt.datetime.now(dt.UTC)
    if expires is None or expires <= reference:
        raise BrowserGatewayPolicyError("browser_gateway_policy_scope_expired")
    for allowed_origin in origins:
        decision = check_url(scope, allowed_origin + "/", platform=True)
        if not decision.allowed:
            raise BrowserGatewayPolicyError("browser_gateway_policy_scope_denied")
    return {
        "schema_version": POLICY_SCHEMA_VERSION,
        "event_id": _event_id(manifest),
        "baseline_configuration_digest": baseline_configuration_digest,
        "scope_generation": SCOPE_GENERATION,
        "scope_sha256": scope_sha256(scope),
        "expires_at": expires_at,
        "origins": list(origins),
        "scope": scope,
    }


def resolve_browser_gateway_policy(
    root: Path,
    *,
    origin: str,
    parent: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Read and verify launch inputs without creating event state or using CDP."""

    workspace = Path(os.path.abspath(os.fspath(root)))
    try:
        controls = read_declared_environment(workspace, CODEX_CONTROL_KEYS, parent=parent)
        event_environment = resolve_event_environment(workspace, parent=parent)
    except EnvironmentPolicyError as exc:
        raise BrowserGatewayPolicyError("browser_gateway_policy_environment_invalid") from exc
    try:
        resolved = resolve_manifest(workspace, parent=parent)
    except (OSError, TypeError, ValueError) as exc:
        raise BrowserGatewayPolicyError("browser_gateway_policy_manifest_invalid") from exc
    if not resolved.ready:
        raise BrowserGatewayPolicyError("browser_gateway_policy_manifest_unresolved")
    baseline_value = controls.get("ROOKERY_MEASUREMENT_BASELINE_PATH")
    if not baseline_value:
        raise BrowserGatewayPolicyError("browser_gateway_policy_baseline_missing")
    baseline_path = Path(baseline_value)
    if not baseline_path.is_absolute():
        baseline_path = workspace / baseline_path
    try:
        baseline = verify_measurement_baseline(
            workspace,
            Path(os.path.abspath(os.fspath(baseline_path))),
            dict(resolved.manifest),
            verify_source_tree=True,
        )
    except (MeasurementBaselineError, OSError, ValueError) as exc:
        raise BrowserGatewayPolicyError("browser_gateway_policy_baseline_invalid") from exc
    return compile_browser_gateway_policy(
        resolved.manifest,
        baseline_configuration_digest=str(baseline.get("configuration_digest", "")),
        origin=origin,
        environment_origin=event_environment.values.get(
            browser_gateway_environment_origin_name(resolved.manifest)
        ),
    )


def _validate_output_path(root: Path, output: Path) -> Path:
    """Require a new external regular file below an existing non-link directory."""

    if not output.is_absolute() or "\x00" in os.fspath(output):
        raise BrowserGatewayPolicyError("browser_gateway_policy_output_path_invalid")
    normalized = Path(os.path.normpath(os.fspath(output)))
    if any(part in {"", ".", ".."} for part in normalized.parts[1:]):
        raise BrowserGatewayPolicyError("browser_gateway_policy_output_path_invalid")
    source = Path(os.path.abspath(os.fspath(root)))
    try:
        normalized.relative_to(source)
    except ValueError:
        pass
    else:
        raise BrowserGatewayPolicyError("browser_gateway_policy_output_inside_source")
    current = Path(normalized.anchor)
    for component in normalized.parent.parts[1:]:
        current /= component
        try:
            info = os.lstat(current)
        except FileNotFoundError as exc:
            raise BrowserGatewayPolicyError("browser_gateway_policy_output_parent_missing") from exc
        except OSError as exc:
            raise BrowserGatewayPolicyError("browser_gateway_policy_output_unavailable") from exc
        if stat.S_ISLNK(info.st_mode):
            raise BrowserGatewayPolicyError("browser_gateway_policy_output_symlink")
        if not stat.S_ISDIR(info.st_mode):
            raise BrowserGatewayPolicyError("browser_gateway_policy_output_parent_invalid")
    try:
        existing = os.lstat(normalized)
    except FileNotFoundError:
        return normalized
    except OSError as exc:
        raise BrowserGatewayPolicyError("browser_gateway_policy_output_unavailable") from exc
    if stat.S_ISLNK(existing.st_mode):
        raise BrowserGatewayPolicyError("browser_gateway_policy_output_symlink")
    raise BrowserGatewayPolicyError("browser_gateway_policy_output_already_exists")


def _write_private_policy(path: Path, policy: Mapping[str, Any]) -> None:
    """Create the output once, with mode 0600, after every validation succeeds."""

    data = (canonical_json(dict(policy)) + "\n").encode("utf-8")
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_BINARY", 0)
    )
    descriptor: int | None = None
    identity: tuple[int, int] | None = None
    completed = False
    try:
        descriptor = os.open(path, flags, 0o600)
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise BrowserGatewayPolicyError("browser_gateway_policy_output_invalid")
        identity = (info.st_dev, info.st_ino)
        os.fchmod(descriptor, 0o600)
        if stat.S_IMODE(os.fstat(descriptor).st_mode) != 0o600:
            raise BrowserGatewayPolicyError("browser_gateway_policy_output_private_mode")
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            descriptor = None
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        completed = True
    except BrowserGatewayPolicyError:
        raise
    except FileExistsError as exc:
        raise BrowserGatewayPolicyError("browser_gateway_policy_output_already_exists") from exc
    except OSError as exc:
        raise BrowserGatewayPolicyError("browser_gateway_policy_output_write_failed") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if identity is not None and not completed:
            try:
                current = os.lstat(path)
                if (current.st_dev, current.st_ino) == identity:
                    os.unlink(path)
            except FileNotFoundError:
                pass
            except OSError:
                pass


def export_browser_gateway_policy(
    root: Path,
    *,
    origin: str,
    output: Path,
    parent: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Verify first-launch inputs, then publish one private sealed policy file."""

    policy = resolve_browser_gateway_policy(root, origin=origin, parent=parent)
    target = _validate_output_path(root, output)
    _write_private_policy(target, policy)
    return policy
