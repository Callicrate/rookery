from __future__ import annotations

import hashlib
import json
import os
import re
import selectors
import signal
import shutil
import sqlite3
import stat
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request
from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from types import MappingProxyType
from typing import Any

from .reducers import control_resume_is_current
from .util import canonical_json

DOTENV_MAX_BYTES = 1024 * 1024
DOTENV_MAX_LINES = 4096
DOTENV_MAX_LINE_BYTES = 64 * 1024
DOTENV_MAX_ASSIGNMENTS = 2048
CHILD_MAX_KEYS = 256
POSIX_ENV_MAX_BYTES = 128 * 1024
WINDOWS_ENV_MAX_BYTES = 30 * 1024
CA_TRUST_MAX_BYTES = 16 * 1024 * 1024
CDP_ENDPOINT_MAX_BYTES = 512
CDP_RESPONSE_MAX_BYTES = 64 * 1024
CDP_TIMEOUT_SECONDS = 3
BROWSER_GATEWAY_STATUS_MAX_BYTES = 64 * 1024
BROWSER_GATEWAY_TIMEOUT_SECONDS = 3
ENV_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")


class EnvironmentPolicyError(ValueError):
    """A value-free configuration or child-environment policy failure."""


LAUNCH_BINDING_SCHEMA_VERSION = "4"
LAUNCH_BINDING_NAME = "launch_binding.json"
LAUNCH_ATTEMPT_SCHEMA_VERSION = "1"
LAUNCH_ATTEMPT_NAME = "launch_attempt.json"
LAUNCH_ATTEMPT_ARGUMENT = "--rookery-launch-attempt"
CODEX_PROBE_TIMEOUT_SECONDS = 10
CODEX_CAPABILITY_PROBE_TIMEOUT_SECONDS = 30
CODEX_PROBE_MAX_OUTPUT_BYTES = 64 * 1024
CODEX_EXECUTABLE_MAX_BYTES = 256 * 1024 * 1024
IMMUTABLE_SOURCE_MAX_FILES = 20_000
IMMUTABLE_SOURCE_MAX_BYTES = 512 * 1024 * 1024
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_LAUNCH_ATTEMPT_ID_RE = re.compile(r"[0-9a-f]{64}\Z")
_CODEX_VERSION_RE = re.compile(r"(?m)^codex-cli\s+([0-9]+(?:\.[0-9]+){1,3}(?:[-+][0-9A-Za-z.-]+)?)\s*$")
_MEASUREMENT_PROVIDER_FIELDS = frozenset({"queue", "tokens", "usage"})


class EnvClass(str, Enum):
    OS_RUNTIME = "os-runtime"
    TERMINAL_SETTING = "terminal-setting"
    ROOKERY_CONFIG = "rookery-config"
    CAPABILITY_PATH = "capability-path"
    PROVIDER_AUTH = "provider-auth"
    ADAPTER_SECRET = "adapter-secret"
    SESSION_SECRET_REF = "session-secret-reference"
    VPN_SECRET_REF = "vpn-secret-reference"
    PROXY_CREDENTIAL = "proxy-credential"
    CA_TRUST_PATH = "ca-trust-path"
    AGENT_CAPABILITY = "agent-capability"
    OWNER_TOKEN = "owner-token"
    UNKNOWN_EXPLICIT = "unknown-explicit"


class EnvSource(str, Enum):
    DOTENV = "dotenv"
    PREPARED = "prepared"
    PARENT = "parent"
    INTERNAL = "internal"


def validate_environment_name(name: str, *, label: str = "environment key") -> str:
    if not isinstance(name, str) or not ENV_NAME_RE.fullmatch(name):
        raise EnvironmentPolicyError(f"{label} is not an exact environment key name")
    if len(name.encode("ascii")) > DOTENV_MAX_LINE_BYTES:
        raise EnvironmentPolicyError(f"{label} exceeds the key-size limit")
    return name


@dataclass(frozen=True)
class EnvKey:
    name: str
    classification: EnvClass
    required: bool = False
    sources: tuple[EnvSource, ...] = (EnvSource.DOTENV, EnvSource.PARENT)

    def __post_init__(self) -> None:
        validate_environment_name(self.name)
        if not self.sources:
            raise EnvironmentPolicyError(f"{self.name}: no environment source declared")
        if len(set(self.sources)) != len(self.sources):
            raise EnvironmentPolicyError(f"{self.name}: duplicate environment source")


@dataclass(frozen=True)
class PassedKey:
    name: str
    classification: EnvClass

    def to_dict(self) -> dict[str, str]:
        return {"name": self.name, "class": self.classification.value}


@dataclass(frozen=True)
class ResolvedEnvironment:
    values: Mapping[str, str] = field(repr=False)
    declared: tuple[PassedKey, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "values", MappingProxyType(dict(self.values)))

    def get(self, name: str, default: str | None = None) -> str | None:
        return self.values.get(name, default)


@dataclass(frozen=True)
class ChildEnvPolicy:
    name: str
    declarations: tuple[EnvKey, ...] = ()
    include_prepared: bool = False
    include_minimal: bool = True
    allowed_classes: frozenset[EnvClass] | None = None

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", self.name):
            raise EnvironmentPolicyError("child environment policy name is invalid")


@dataclass(frozen=True)
class ChildEnvironment:
    values: Mapping[str, str] = field(repr=False)
    policy_name: str
    passed: tuple[PassedKey, ...]
    # Trust bytes are bound while the declared path is opened safely.  They are
    # intentionally not child-process environment values or metadata: Python
    # transports consume these bytes directly instead of reopening a pathname.
    trust_material: Mapping[str, bytes] = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "values", MappingProxyType(dict(self.values)))
        material: dict[str, bytes] = {}
        for name, value in self.trust_material.items():
            validate_environment_name(name)
            if not isinstance(value, bytes):
                raise EnvironmentPolicyError("CA trust material is invalid")
            material[name] = value
        object.__setattr__(self, "trust_material", MappingProxyType(material))

    def metadata(self) -> dict[str, Any]:
        return {
            "environment": {
                "schema_version": "1",
                "policy": self.policy_name,
                "passed": [item.to_dict() for item in self.passed],
            }
        }


def resolve_browser_cdp_endpoint(value: str | None) -> tuple[str, int]:
    """Normalize the only local DevTools endpoint Rookery may use."""

    if not isinstance(value, str):
        raise EnvironmentPolicyError("browser_cdp_url_invalid")
    endpoint = value.strip()
    if (
        not endpoint
        or len(endpoint.encode("utf-8")) > CDP_ENDPOINT_MAX_BYTES
        or any(ord(character) <= 0x20 or ord(character) == 0x7F for character in endpoint)
    ):
        raise EnvironmentPolicyError("browser_cdp_url_invalid")
    try:
        parsed = urllib.parse.urlsplit(endpoint)
        port = parsed.port
    except (UnicodeError, ValueError) as exc:
        raise EnvironmentPolicyError("browser_cdp_url_invalid") from exc
    if (
        parsed.scheme.casefold() != "http"
        or parsed.hostname != "127.0.0.1"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or port is None
        or not 1 <= port <= 65535
    ):
        raise EnvironmentPolicyError("browser_cdp_url_invalid")
    return f"http://127.0.0.1:{port}", port


def resolve_browser_bidi_endpoint(value: str | None) -> tuple[str, int]:
    """Normalize Firefox's exact loopback WebDriver BiDi session URL."""

    if not isinstance(value, str):
        raise EnvironmentPolicyError("browser_bidi_url_invalid")
    endpoint = value.strip()
    if (
        not endpoint
        or len(endpoint.encode("utf-8")) > CDP_ENDPOINT_MAX_BYTES
        or any(ord(character) <= 0x20 or ord(character) == 0x7F for character in endpoint)
    ):
        raise EnvironmentPolicyError("browser_bidi_url_invalid")
    try:
        parsed = urllib.parse.urlsplit(endpoint)
        port = parsed.port
    except (UnicodeError, ValueError) as exc:
        raise EnvironmentPolicyError("browser_bidi_url_invalid") from exc
    if (
        parsed.scheme.casefold() != "ws"
        or parsed.hostname != "127.0.0.1"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path != "/session"
        or parsed.query
        or parsed.fragment
        or port is None
        or not 1 <= port <= 65535
    ):
        raise EnvironmentPolicyError("browser_bidi_url_invalid")
    return f"ws://127.0.0.1:{port}/session", port


def _browser_cdp_scope(port: int) -> dict[str, Any]:
    """Build the fixed loopback authority for one DevTools version request."""

    return {
        "acknowledged": True,
        "generation": 0,
        "expires_at": "unknown",
        "allowed_hosts": ["127.0.0.1"],
        "allowed_cidrs": ["127.0.0.1/32"],
        "allowed_ports": [port],
        "allowed_protocols": ["http"],
        "allowed_file_origins": [],
        "platform_hosts": [],
        "max_attachment_bytes": 0,
    }


def _browser_cdp_websocket_is_bound(value: object, *, port: int) -> bool:
    """Require Chrome's advertised websocket to stay on the verified endpoint."""

    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > CDP_ENDPOINT_MAX_BYTES
        or any(ord(character) <= 0x20 or ord(character) == 0x7F for character in value)
    ):
        return False
    try:
        parsed = urllib.parse.urlsplit(value)
        websocket_port = parsed.port
    except (UnicodeError, ValueError):
        return False
    return (
        parsed.scheme.casefold() == "ws"
        and parsed.hostname == "127.0.0.1"
        and parsed.username is None
        and parsed.password is None
        and websocket_port == port
        and parsed.path.startswith("/devtools/browser/")
        and len(parsed.path) > len("/devtools/browser/")
        and not parsed.query
        and not parsed.fragment
    )


def verify_browser_cdp_endpoint(value: str | None) -> None:
    """Prove a bounded, direct Chrome DevTools endpoint is ready for launch.

    The endpoint is fixed to IPv4 loopback. It cannot inherit an operator
    proxy, follow a redirect, or become general browser-network authority.
    This checks readiness only; adapter operations retain their own scope,
    review, authorization, and verdict contracts.
    """

    base_url, port = resolve_browser_cdp_endpoint(value)
    version_url = f"{base_url}/json/version"
    from .network_policy import ExplicitNetworkPolicy
    from .scope import open_scoped_url

    scope = _browser_cdp_scope(port)
    policy = ExplicitNetworkPolicy.from_child_environment(ChildEnvironment({}, "browser-cdp-loopback", ()))
    request = urllib.request.Request(
        version_url,
        headers={"Accept": "application/json"},
        method="GET",
    )
    try:
        with open_scoped_url(
            scope,
            request,
            timeout=CDP_TIMEOUT_SECONDS,
            max_redirects=0,
            transport=policy.scoped_transport(scope),
        ) as response:
            if getattr(response, "status", None) != 200:
                raise EnvironmentPolicyError("browser_cdp_invalid_response")
            content_type = str(response.headers.get("Content-Type", "")).split(";", 1)[0]
            if content_type.strip().casefold() != "application/json":
                raise EnvironmentPolicyError("browser_cdp_invalid_response")
            payload = response.read(CDP_RESPONSE_MAX_BYTES + 1)
    except EnvironmentPolicyError:
        raise
    except RuntimeError as exc:
        if str(exc).startswith("HTTP redirect"):
            raise EnvironmentPolicyError("browser_cdp_redirected") from exc
        raise EnvironmentPolicyError("browser_cdp_unreachable") from exc
    except (OSError, TimeoutError) as exc:
        raise EnvironmentPolicyError("browser_cdp_unreachable") from exc
    if not isinstance(payload, bytes) or len(payload) > CDP_RESPONSE_MAX_BYTES:
        raise EnvironmentPolicyError("browser_cdp_response_too_large")
    try:
        document = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EnvironmentPolicyError("browser_cdp_invalid_response") from exc
    if not isinstance(document, dict):
        raise EnvironmentPolicyError("browser_cdp_invalid_response")
    if (
        not isinstance(document.get("Browser"), str)
        or not document["Browser"]
        or not isinstance(document.get("Protocol-Version"), str)
        or not document["Protocol-Version"]
        or not _browser_cdp_websocket_is_bound(document.get("webSocketDebuggerUrl"), port=port)
    ):
        raise EnvironmentPolicyError("browser_cdp_invalid_response")


@dataclass(frozen=True)
class BrowserGatewayReadiness:
    """Value-private evidence from one verified gateway status response."""

    boot_nonce: str
    policy_sha256: str
    expires_at: str
    proxy_port: int
    status_port: int


def resolve_browser_gateway_endpoint(value: str | None) -> tuple[str, int]:
    """Normalize the only local browser-gateway status endpoint Rookery uses."""

    if not isinstance(value, str):
        raise EnvironmentPolicyError("browser_gateway_url_invalid")
    endpoint = value.strip()
    if (
        not endpoint
        or len(endpoint.encode("utf-8")) > CDP_ENDPOINT_MAX_BYTES
        or any(ord(character) <= 0x20 or ord(character) == 0x7F for character in endpoint)
    ):
        raise EnvironmentPolicyError("browser_gateway_url_invalid")
    try:
        parsed = urllib.parse.urlsplit(endpoint)
        port = parsed.port
    except (UnicodeError, ValueError) as exc:
        raise EnvironmentPolicyError("browser_gateway_url_invalid") from exc
    if (
        parsed.scheme.casefold() != "http"
        or parsed.hostname != "127.0.0.1"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or port is None
        or not 1 <= port <= 65535
    ):
        raise EnvironmentPolicyError("browser_gateway_url_invalid")
    return f"http://127.0.0.1:{port}", port


def _browser_gateway_listener_port(value: object) -> int | None:
    """Accept only the canonical IPv4 loopback listener form from gateway status."""

    if not isinstance(value, str) or len(value.encode("utf-8")) > 64:
        return None
    match = re.fullmatch(r"127\.0\.0\.1:([1-9][0-9]{0,4})", value)
    if match is None:
        return None
    port = int(match.group(1))
    return port if port <= 65535 else None


def _browser_gateway_status_document(
    document: object,
    *,
    status_port: int,
    expected_policy_sha256: str | None,
    expected_expires_at: str | None,
    expected_boot_nonce: str | None,
) -> BrowserGatewayReadiness:
    """Validate the fixed status schema without retaining counters or targets."""

    if not isinstance(document, dict) or set(document) != {
        "schema_version",
        "boot_nonce",
        "policy_sha256",
        "expires_at",
        "listeners",
        "counters",
    }:
        raise EnvironmentPolicyError("browser_gateway_invalid_response")
    boot_nonce = document["boot_nonce"]
    policy_digest = document["policy_sha256"]
    expires_at = document["expires_at"]
    listeners = document["listeners"]
    counters = document["counters"]
    if (
        document["schema_version"] != "1"
        or not isinstance(boot_nonce, str)
        or _SHA256_RE.fullmatch(boot_nonce) is None
        or not isinstance(policy_digest, str)
        or _SHA256_RE.fullmatch(policy_digest) is None
        or not isinstance(expires_at, str)
        or not isinstance(listeners, dict)
        or set(listeners) != {"proxy", "status"}
        or not isinstance(counters, dict)
        or set(counters) != {"accepted", "refused", "connected", "completed", "failed", "bytes"}
        or any(isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in counters.values())
    ):
        raise EnvironmentPolicyError("browser_gateway_invalid_response")
    from .util import parse_iso

    expiry = parse_iso(expires_at)
    if expiry is None or expiry.timestamp() <= time.time():
        raise EnvironmentPolicyError("browser_gateway_invalid_response")
    proxy_port = _browser_gateway_listener_port(listeners["proxy"])
    advertised_status_port = _browser_gateway_listener_port(listeners["status"])
    if proxy_port is None or advertised_status_port != status_port or proxy_port == status_port:
        raise EnvironmentPolicyError("browser_gateway_invalid_response")
    if expected_policy_sha256 is not None and policy_digest != expected_policy_sha256:
        raise EnvironmentPolicyError("browser_gateway_policy_mismatch")
    if expected_expires_at is not None and expires_at != expected_expires_at:
        raise EnvironmentPolicyError("browser_gateway_policy_mismatch")
    if expected_boot_nonce is not None and boot_nonce != expected_boot_nonce:
        raise EnvironmentPolicyError("browser_gateway_restarted")
    return BrowserGatewayReadiness(
        boot_nonce=boot_nonce,
        policy_sha256=policy_digest,
        expires_at=expires_at,
        proxy_port=proxy_port,
        status_port=status_port,
    )


def verify_browser_gateway_endpoint(
    value: str | None,
    *,
    expected_policy_sha256: str | None = None,
    expected_expires_at: str | None = None,
    expected_boot_nonce: str | None = None,
) -> BrowserGatewayReadiness:
    """Verify a bounded loopback gateway status against an optional sealed policy."""

    base_url, port = resolve_browser_gateway_endpoint(value)
    if expected_policy_sha256 is not None and _SHA256_RE.fullmatch(expected_policy_sha256) is None:
        raise EnvironmentPolicyError("browser_gateway_policy_invalid")
    if expected_boot_nonce is not None and _SHA256_RE.fullmatch(expected_boot_nonce) is None:
        raise EnvironmentPolicyError("browser_gateway_policy_invalid")
    from .network_policy import ExplicitNetworkPolicy
    from .scope import open_scoped_url

    scope = _browser_cdp_scope(port)
    policy = ExplicitNetworkPolicy.from_child_environment(ChildEnvironment({}, "browser-gateway-loopback", ()))
    request = urllib.request.Request(
        f"{base_url}/status",
        headers={"Accept": "application/json"},
        method="GET",
    )
    try:
        with open_scoped_url(
            scope,
            request,
            timeout=BROWSER_GATEWAY_TIMEOUT_SECONDS,
            max_redirects=0,
            transport=policy.scoped_transport(scope),
        ) as response:
            if getattr(response, "status", None) != 200:
                raise EnvironmentPolicyError("browser_gateway_invalid_response")
            content_type = str(response.headers.get("Content-Type", "")).split(";", 1)[0]
            if content_type.strip().casefold() != "application/json":
                raise EnvironmentPolicyError("browser_gateway_invalid_response")
            payload = response.read(BROWSER_GATEWAY_STATUS_MAX_BYTES + 1)
    except EnvironmentPolicyError:
        raise
    except RuntimeError as exc:
        if str(exc).startswith("HTTP redirect"):
            raise EnvironmentPolicyError("browser_gateway_redirected") from exc
        raise EnvironmentPolicyError("browser_gateway_unreachable") from exc
    except (OSError, TimeoutError) as exc:
        raise EnvironmentPolicyError("browser_gateway_unreachable") from exc
    if not isinstance(payload, bytes) or len(payload) > BROWSER_GATEWAY_STATUS_MAX_BYTES:
        raise EnvironmentPolicyError("browser_gateway_response_too_large")
    try:
        document = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EnvironmentPolicyError("browser_gateway_invalid_response") from exc
    return _browser_gateway_status_document(
        document,
        status_port=port,
        expected_policy_sha256=expected_policy_sha256,
        expected_expires_at=expected_expires_at,
        expected_boot_nonce=expected_boot_nonce,
    )


@dataclass(frozen=True)
class LaunchBinding:
    """The first durable record proving a workspace passed launch admission."""

    record: Mapping[str, Any] = field(repr=False)
    sha256: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "record", MappingProxyType(dict(self.record)))


@dataclass(frozen=True)
class LaunchGate:
    """Pure launch admission result; publishing it is a separate operation."""

    manifest: Mapping[str, Any] = field(repr=False)
    result: Any = field(repr=False)
    workspace_identity: str
    immutable_source_sha256: str
    environment_sha256: str
    resolved_manifest_sha256: str
    baseline_path: Path = field(repr=False)
    core_environment: ResolvedEnvironment = field(repr=False)
    preparation_environment: ResolvedEnvironment = field(repr=False)
    stage_c_environments: Mapping[str, ChildEnvironment] = field(repr=False)
    baseline_sha256: str
    baseline_configuration_digest: str
    measurement_contract: Mapping[str, Any] = field(repr=False)
    release_version: str
    selected_adapter: str
    selected_extensions: tuple[str, ...]
    codex_executable: str
    codex_identity: Mapping[str, int | str]
    codex_version: str
    auth_mode: str
    strict_config_supported: bool
    browser_gateway_policy_sha256: str | None = field(default=None, repr=False)
    browser_gateway_expires_at: str | None = field(default=None, repr=False)
    browser_gateway_boot_nonce: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "manifest", MappingProxyType(dict(self.manifest)))
        object.__setattr__(self, "codex_identity", MappingProxyType(dict(self.codex_identity)))
        object.__setattr__(
            self,
            "stage_c_environments",
            MappingProxyType(dict(self.stage_c_environments)),
        )
        contract = _measurement_contract(self.measurement_contract)
        object.__setattr__(
            self,
            "measurement_contract",
            MappingProxyType(
                {
                    "queue_automation_enabled": contract["queue_automation_enabled"],
                    "provider_fields": MappingProxyType(
                        {name: MappingProxyType(dict(field)) for name, field in contract["provider_fields"].items()}
                    ),
                }
            ),
        )


# Runtime state must not turn a correctly deployed tree into a different source
# release.  These are the same generated roots that strict release validation
# rejects; editable event configuration is bound separately below.
_IMMUTABLE_SOURCE_RUNTIME_ROOTS = frozenset(
    {
        "ACTIVE_SURFACE.md",
        ".codex/agents",
        ".codex/config.toml",
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
        "candidates",
        "captures",
        "control",
        "downloads",
        "docs/retrospectives",
        "evidence",
        "exploit",
        "handoffs",
        "logs",
        "platform",
        "research",
        "state",
        "submissions",
        "work",
        "writeups",
    }
)
_IMMUTABLE_SOURCE_RUNTIME_DIRECTORY_NAMES = frozenset({"__pycache__", ".pytest_cache", ".ruff_cache"})
_IMMUTABLE_SOURCE_EDITABLE_FILES = frozenset({".env"})
# Retained solely so an operator can run the explicit migration command. A
# legacy file has no launch authority and must not alter or be read by the
# immutable-source binding used on normal paths.
_IMMUTABLE_SOURCE_IGNORED_LEGACY_FILES = frozenset({"event.json"})
_IMMUTABLE_SOURCE_GENERATED_PATHS = frozenset({".codex/config.toml"})
_IMMUTABLE_SOURCE_GENERATED_PREFIXES = (".codex/agents/",)


def canonical_workspace_identity(root: Path) -> str:
    """Return the stable absolute identity used to reject copied state trees."""

    try:
        return os.path.normcase(os.path.realpath(os.fspath(root.resolve(strict=True))))
    except OSError as exc:
        raise EnvironmentPolicyError("workspace_identity_unavailable") from exc


def is_deployed_workspace(root: Path) -> bool:
    """Identify a public Rookery root rather than a tiny library-only fixture."""

    return (root / "VERSION").is_file() and (root / "bin" / "rookery").is_file()


def _source_relative_is_excluded(relative: str) -> bool:
    if relative in _IMMUTABLE_SOURCE_EDITABLE_FILES | _IMMUTABLE_SOURCE_IGNORED_LEGACY_FILES:
        return True
    if relative in _IMMUTABLE_SOURCE_GENERATED_PATHS or relative.startswith(_IMMUTABLE_SOURCE_GENERATED_PREFIXES):
        return True
    if relative in _IMMUTABLE_SOURCE_RUNTIME_ROOTS:
        return True
    return any(
        relative.startswith(prefix.rstrip("/") + "/") for prefix in _IMMUTABLE_SOURCE_RUNTIME_ROOTS if "/" in prefix
    )


def _hash_open_regular_file(descriptor: int, info: os.stat_result, *, maximum: int, label: str) -> str:
    if not stat.S_ISREG(info.st_mode) or info.st_size < 0 or info.st_size > maximum:
        raise EnvironmentPolicyError(label)
    digest = hashlib.sha256()
    consumed = 0
    while True:
        block = os.read(descriptor, min(64 * 1024, maximum + 1 - consumed))
        if not block:
            break
        consumed += len(block)
        if consumed > maximum:
            raise EnvironmentPolicyError(label)
        digest.update(block)
    if consumed != info.st_size:
        raise EnvironmentPolicyError(label)
    return digest.hexdigest()


def _stable_regular_file_digest(path: Path, *, maximum: int, label: str) -> tuple[str, os.stat_result]:
    """Hash a non-link file through one descriptor and reject an unstable read."""

    try:
        before = path.lstat()
    except OSError as exc:
        raise EnvironmentPolicyError(label) from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise EnvironmentPolicyError(label)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise EnvironmentPolicyError(label) from exc
    try:
        opened = os.fstat(descriptor)
        signature = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        if (
            not stat.S_ISREG(opened.st_mode)
            or (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) != signature
        ):
            raise EnvironmentPolicyError(label)
        digest = _hash_open_regular_file(descriptor, opened, maximum=maximum, label=label)
        after = os.fstat(descriptor)
        if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != signature:
            raise EnvironmentPolicyError(label)
        return digest, opened
    finally:
        os.close(descriptor)


def immutable_source_digest(root: Path) -> str:
    """Hash the shipped source without mutable state or editable event inputs.

    The digest includes paths, content, and executable modes.  It is intentionally
    not a signature: a same-UID actor can rewrite both the source and binding.
    It does make stale/copy/tamper mistakes fail before Rookery mutates state.
    """

    workspace = Path(canonical_workspace_identity(root))
    digest = hashlib.sha256()
    file_count = 0
    byte_count = 0
    for directory_text, directories, filenames in os.walk(workspace, topdown=True, followlinks=False):
        directory = Path(directory_text)
        relative_directory = directory.relative_to(workspace).as_posix()
        if relative_directory != ".":
            try:
                directory_info = directory.lstat()
            except OSError as exc:
                raise EnvironmentPolicyError("immutable_source_unreadable") from exc
            if stat.S_ISLNK(directory_info.st_mode) or not stat.S_ISDIR(directory_info.st_mode):
                raise EnvironmentPolicyError("immutable_source_invalid")
            digest.update(("D:" + relative_directory).encode("utf-8") + b"\0")
            digest.update(f"{stat.S_IMODE(directory_info.st_mode):04o}".encode("ascii") + b"\0")
        kept_directories: list[str] = []
        for name in sorted(directories):
            relative = name if relative_directory == "." else f"{relative_directory}/{name}"
            if _source_relative_is_excluded(relative) or name in _IMMUTABLE_SOURCE_RUNTIME_DIRECTORY_NAMES:
                continue
            candidate = directory / name
            try:
                info = candidate.lstat()
            except OSError as exc:
                raise EnvironmentPolicyError("immutable_source_unreadable") from exc
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                raise EnvironmentPolicyError("immutable_source_invalid")
            kept_directories.append(name)
        directories[:] = kept_directories
        for name in sorted(filenames):
            relative = name if relative_directory == "." else f"{relative_directory}/{name}"
            if _source_relative_is_excluded(relative) or name.endswith((".pyc", ".pyo")):
                continue
            candidate = directory / name
            file_digest, info = _stable_regular_file_digest(
                candidate,
                maximum=IMMUTABLE_SOURCE_MAX_BYTES - byte_count,
                label="immutable_source_invalid",
            )
            file_count += 1
            byte_count += info.st_size
            if file_count > IMMUTABLE_SOURCE_MAX_FILES or byte_count > IMMUTABLE_SOURCE_MAX_BYTES:
                raise EnvironmentPolicyError("immutable_source_exceeds_limit")
            digest.update(relative.encode("utf-8") + b"\0")
            digest.update(f"{stat.S_IMODE(info.st_mode):04o}".encode("ascii") + b"\0")
            digest.update(file_digest.encode("ascii") + b"\0")
    return digest.hexdigest()


def _editable_configuration_digests(
    root: Path,
    manifest: Mapping[str, Any] | None = None,
) -> tuple[str, str]:
    """Hash the sole editable input and its canonical resolved event view."""

    workspace = Path(canonical_workspace_identity(root))
    environment_digest, _ = _stable_regular_file_digest(
        workspace / ".env", maximum=DOTENV_MAX_BYTES, label="launch_configuration_invalid"
    )
    if manifest is None:
        from .manifest import resolve_manifest

        result = resolve_manifest(workspace, parent={})
        if not result.ready:
            raise EnvironmentPolicyError("launch_configuration_unresolved")
        manifest = result.manifest
    resolved_digest = hashlib.sha256(canonical_json(dict(manifest)).encode("utf-8")).hexdigest()
    return environment_digest, resolved_digest


def _is_windows() -> bool:
    return os.name == "nt"


def _normal(name: str, windows: bool) -> str:
    return name.casefold() if windows else name


def _error(path: Path, reason: str, *, line: int | None = None, key: str | None = None) -> EnvironmentPolicyError:
    parts = [str(path)]
    if line is not None:
        parts.append(f"line {line}")
    if key is not None:
        parts.append(f"key {key}")
    parts.append(reason)
    return EnvironmentPolicyError(": ".join(parts))


def _read_regular_file(path: Path) -> bytes | None:
    try:
        before = os.lstat(path)
    except FileNotFoundError:
        return None
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise _error(path, "must be a non-link regular file")
    if before.st_size > DOTENV_MAX_BYTES:
        raise _error(path, "exceeds the file-size limit")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise _error(path, "could not be opened safely") from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise _error(path, "changed while opening")
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise _error(path, "changed while opening")
        data = b""
        while len(data) <= DOTENV_MAX_BYTES:
            block = os.read(descriptor, min(64 * 1024, DOTENV_MAX_BYTES + 1 - len(data)))
            if not block:
                break
            data += block
        if len(data) > DOTENV_MAX_BYTES:
            raise _error(path, "exceeds the file-size limit")
        return data
    finally:
        os.close(descriptor)


def _physical_lines(path: Path, data: bytes) -> list[str]:
    if b"\0" in data:
        raise _error(path, "contains NUL")
    raw_lines = data.split(b"\n")
    if data.endswith(b"\n"):
        raw_lines.pop()
    if len(raw_lines) > DOTENV_MAX_LINES:
        raise _error(path, "exceeds the physical-line limit")
    lines: list[str] = []
    for number, raw in enumerate(raw_lines, 1):
        if raw.endswith(b"\r"):
            raw = raw[:-1]
        if len(raw) > DOTENV_MAX_LINE_BYTES:
            raise _error(path, "exceeds the line-size limit", line=number)
        if b"\r" in raw:
            raise _error(path, "contains a bare carriage return", line=number)
        try:
            lines.append(raw.decode("utf-8", errors="strict"))
        except UnicodeDecodeError as exc:
            raise _error(path, "is not valid UTF-8", line=number) from exc
    return lines


def _decode_value(path: Path, line: int, key: str, remainder: str) -> str:
    value = remainder.strip()
    if not value:
        return ""
    if value.startswith("'"):
        if len(value) < 2 or not value.endswith("'"):
            raise _error(path, "has an unmatched single quote", line=line, key=key)
        return value[1:-1]
    if value.startswith('"'):
        try:
            decoded = json.loads(value)
        except json.JSONDecodeError as exc:
            raise _error(path, "has invalid JSON string quoting", line=line, key=key) from exc
        if not isinstance(decoded, str):
            raise _error(path, "double-quoted value must be a JSON string", line=line, key=key)
        return decoded
    return value


def _parse_dotenv(path: Path, declared_names: set[str] | None, *, windows: bool) -> dict[str, str]:
    data = _read_regular_file(path)
    if data is None:
        return {}
    retained: dict[str, str] = {}
    seen: dict[str, str] = {}
    assignments = 0
    for number, raw in enumerate(_physical_lines(path, data), 1):
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        line = raw
        line = line.removeprefix("export ")
        match = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_]*)=(.*)", line)
        if match is None:
            raise _error(path, "is not a valid assignment", line=number)
        key, remainder = match.groups()
        normalized = _normal(key, windows)
        if normalized in seen:
            raise _error(path, "is a duplicate assignment", line=number, key=key)
        seen[normalized] = key
        assignments += 1
        if assignments > DOTENV_MAX_ASSIGNMENTS:
            raise _error(path, "exceeds the assignment-count limit", line=number)
        value = _decode_value(path, number, key, remainder)
        if len(value.encode("utf-8")) > DOTENV_MAX_LINE_BYTES:
            raise _error(path, "exceeds the value-size limit", line=number, key=key)
        if declared_names is None:
            retained[key] = value
        elif normalized in declared_names:
            retained[normalized] = value
    return retained


def _declaration_index(declarations: Collection[EnvKey], *, windows: bool) -> dict[str, EnvKey]:
    indexed: dict[str, EnvKey] = {}
    for declaration in declarations:
        normalized = _normal(declaration.name, windows)
        if normalized in indexed:
            raise EnvironmentPolicyError(f"duplicate environment declaration: {declaration.name}")
        indexed[normalized] = declaration
    return indexed


def _parent_index(
    parent: Mapping[str, str],
    *,
    windows: bool,
    wanted: set[str] | None = None,
) -> dict[str, tuple[str, str]]:
    indexed: dict[str, tuple[str, str]] = {}
    for key, value in parent.items():
        if not isinstance(key, str) or not isinstance(value, str):
            continue
        normalized = _normal(key, windows)
        if wanted is not None and normalized not in wanted:
            continue
        if normalized in indexed and indexed[normalized][0] != key:
            raise EnvironmentPolicyError(f"ambiguous parent environment key: {key}")
        indexed[normalized] = (key, value)
    return indexed


def read_declared_environment(
    root: Path,
    declarations: Collection[EnvKey],
    *,
    include_prepared: bool = False,
    parent: Mapping[str, str] | None = None,
) -> ResolvedEnvironment:
    windows = _is_windows()
    indexed = _declaration_index(declarations, windows=windows)
    names = set(indexed)
    dotenv = _parse_dotenv(root / ".env", names, windows=windows)
    prepared = _parse_dotenv(root / "state" / "prepared.env", names, windows=windows) if include_prepared else {}
    parents = _parent_index(
        os.environ if parent is None else parent,
        windows=windows,
        wanted=names,
    )
    values: dict[str, str] = {}
    passed: list[PassedKey] = []
    for normalized, declaration in indexed.items():
        value = ""
        for source in declaration.sources:
            candidate = ""
            if source is EnvSource.DOTENV:
                candidate = dotenv.get(normalized, "")
            elif source is EnvSource.PREPARED and include_prepared:
                candidate = prepared.get(normalized, "")
            elif source is EnvSource.PARENT:
                candidate = parents.get(normalized, ("", ""))[1]
            if candidate:
                value = candidate
                break
        if not value:
            if declaration.required:
                raise EnvironmentPolicyError(
                    f"required environment key missing for {declaration.classification.value}: {declaration.name}"
                )
            continue
        values[declaration.name] = value
        passed.append(PassedKey(declaration.name, declaration.classification))
    return ResolvedEnvironment(values, tuple(passed))


def _read_dotenv_compat(path: Path) -> dict[str, str]:
    """Temporary legacy bridge. New callers must use declared-key resolution."""

    windows = _is_windows()
    parsed = _parse_dotenv(path, None, windows=windows)
    return dict(parsed)


def write_generated_environment(path: Path, values: Mapping[str, str]) -> None:
    if len(values) > DOTENV_MAX_ASSIGNMENTS:
        raise EnvironmentPolicyError("generated environment exceeds the assignment-count limit")
    records: list[str] = []
    seen: set[str] = set()
    for key in sorted(values, key=str.casefold):
        validate_environment_name(key)
        normalized = _normal(key, _is_windows())
        if normalized in seen:
            raise EnvironmentPolicyError(f"duplicate generated environment key: {key}")
        seen.add(normalized)
        value = values[key]
        if not isinstance(value, str) or "\0" in value:
            raise EnvironmentPolicyError(f"generated environment value is invalid for key: {key}")
        record = f"{key}={json.dumps(value, ensure_ascii=False)}"
        if len(record.encode("utf-8")) > DOTENV_MAX_LINE_BYTES:
            raise EnvironmentPolicyError(f"generated environment record exceeds the line-size limit: {key}")
        records.append(record)
    data = (("\n".join(records) + "\n") if records else "").encode("utf-8")
    if len(data) > DOTENV_MAX_BYTES:
        raise EnvironmentPolicyError("generated environment exceeds the file-size limit")
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and (path.is_symlink() or not path.is_file()):
        raise EnvironmentPolicyError(f"{path}: generated target must be a non-link regular file")
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            descriptor = -1
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def write_prepared_environment(
    root: Path,
    values: Mapping[str, str],
    declarations: Collection[EnvKey],
) -> None:
    """Write only declared, nonsecret generated capability values."""

    indexed = {item.name: item for item in declarations}
    if set(values) != set(indexed):
        raise EnvironmentPolicyError("prepared environment values must exactly match their declarations")
    for item in indexed.values():
        if item.classification is not EnvClass.CAPABILITY_PATH:
            raise EnvironmentPolicyError(f"prepared environment forbids class {item.classification.value}: {item.name}")
        if "\r" in values[item.name] or "\n" in values[item.name]:
            raise EnvironmentPolicyError(f"prepared environment capability value is invalid: {item.name}")
    write_generated_environment(root / "state" / "prepared.env", values)


def parse_name_array(raw: str | None, *, label: str, maximum: int = CHILD_MAX_KEYS) -> tuple[str, ...]:
    if raw in {None, ""}:
        return ()
    try:
        value = json.loads(str(raw))
    except json.JSONDecodeError as exc:
        raise EnvironmentPolicyError(f"{label} must be a JSON string array") from exc
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise EnvironmentPolicyError(f"{label} must be a JSON string array")
    if len(value) > maximum:
        raise EnvironmentPolicyError(f"{label} exceeds the key-count limit")
    names: list[str] = []
    seen: set[str] = set()
    for item in value:
        name = validate_environment_name(item, label=label)
        normalized = _normal(name, _is_windows())
        if normalized in seen:
            raise EnvironmentPolicyError(f"{label} contains a duplicate key: {name}")
        if normalized == _normal("ROOKERY_OWNER_TOKEN", _is_windows()):
            raise EnvironmentPolicyError(f"{label} contains a forbidden owner key")
        seen.add(normalized)
        names.append(name)
    return tuple(names)


_PROXY_NAMES = frozenset(
    {"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "all_proxy", "no_proxy"}
)
_CA_NAMES = frozenset(
    {
        "CODEX_CA_CERTIFICATE",
        "SSL_CERT_FILE",
        "REQUESTS_CA_BUNDLE",
        "CURL_CA_BUNDLE",
        "NODE_EXTRA_CA_CERTS",
        "GIT_SSL_CAINFO",
    }
)
_OS_NAMES = frozenset(
    {"PATH", "Path", "LANG", "LC_ALL", "LC_CTYPE", "TZ", "TMPDIR", "SystemRoot", "ComSpec", "PATHEXT", "TEMP", "TMP"}
)
_TERMINAL_NAMES = frozenset({"TERM", "COLORTERM", "NO_COLOR", "CLICOLOR", "CLICOLOR_FORCE", "EDITOR", "VISUAL"})
_PROVIDER_NAMES = frozenset(
    {
        "CODEX_API_KEY",
        "CODEX_ACCESS_TOKEN",
        "OPENAI_API_KEY",
        "OPENAI_FEDERATION_RULE_ID",
        "OPENAI_IDENTITY_TOKEN_FILE",
        "OPENAI_WORKLOAD_IDENTITY_CONTEXT",
    }
)
_ADAPTER_NAMES = frozenset(
    {
        "API_ACCESS_TOKEN",
        "CTFD_TOKEN",
        "HTB_MCP_TOKEN",
        "SKILLBIT_EMAIL",
        "SKILLBIT_PASSWORD",
        "SKILLBIT_USER",
    }
)
_SESSION_NAMES = frozenset({"IMMERSIVE_COOKIES_FILE", "COOKIES_FILE", "COOKIES_LATEST"})
_VPN_NAMES = frozenset({"VPN_AUTH_FILE"})
_AGENT_NAMES = frozenset(
    {"SSH_AUTH_SOCK", "SSH_AGENT_PID", "DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY", "DBUS_SESSION_BUS_ADDRESS"}
)


def classify_environment_name(name: str) -> EnvClass:
    validate_environment_name(name)
    if name in _OS_NAMES:
        return EnvClass.OS_RUNTIME
    if name in _TERMINAL_NAMES:
        return EnvClass.TERMINAL_SETTING
    if name in _PROVIDER_NAMES:
        return EnvClass.PROVIDER_AUTH
    if name in _PROXY_NAMES:
        return EnvClass.PROXY_CREDENTIAL
    if name in _CA_NAMES:
        return EnvClass.CA_TRUST_PATH
    if name in _ADAPTER_NAMES:
        return EnvClass.ADAPTER_SECRET
    if name in _SESSION_NAMES:
        return EnvClass.SESSION_SECRET_REF
    if name in _VPN_NAMES:
        return EnvClass.VPN_SECRET_REF
    if name in _AGENT_NAMES:
        return EnvClass.AGENT_CAPABILITY
    if name == "ROOKERY_OWNER_TOKEN":
        return EnvClass.OWNER_TOKEN
    return EnvClass.UNKNOWN_EXPLICIT


def purpose_policy(
    name: str,
    declarations: Collection[EnvKey] = (),
    *,
    include_prepared: bool = False,
    include_minimal: bool = True,
    allowed_classes: Collection[EnvClass] | None = None,
) -> ChildEnvPolicy:
    return ChildEnvPolicy(
        name=name,
        declarations=tuple(declarations),
        include_prepared=include_prepared,
        include_minimal=include_minimal,
        allowed_classes=frozenset(allowed_classes) if allowed_classes is not None else None,
    )


def _minimal_values(root: Path, parent: Mapping[str, str]) -> tuple[dict[str, str], dict[str, EnvClass]]:
    windows = _is_windows()
    names = (
        ("Path", "SystemRoot", "ComSpec", "PATHEXT", "TEMP", "TMP")
        if windows
        else ("PATH", "LANG", "LC_ALL", "LC_CTYPE", "TZ", "TMPDIR")
    )
    wanted = {_normal(name, windows) for name in names}
    parents = _parent_index(parent, windows=windows, wanted=wanted)
    values: dict[str, str] = {}
    classes: dict[str, EnvClass] = {}
    for name in names:
        entry = parents.get(_normal(name, windows))
        if entry and entry[1]:
            output_name = name if windows else entry[0]
            values[output_name] = entry[1]
            classes[output_name] = EnvClass.OS_RUNTIME
    if windows:
        for required in ("Path", "SystemRoot", "ComSpec"):
            if _normal(required, True) not in {_normal(key, True) for key in values}:
                raise EnvironmentPolicyError(f"minimal Windows environment is missing required key: {required}")
    elif "PATH" not in values:
        values["PATH"] = os.defpath
        classes["PATH"] = EnvClass.OS_RUNTIME
    values["ROOKERY_ROOT"] = str(root.resolve())
    values["PYTHONDONTWRITEBYTECODE"] = "1"
    classes["ROOKERY_ROOT"] = EnvClass.ROOKERY_CONFIG
    classes["PYTHONDONTWRITEBYTECODE"] = EnvClass.ROOKERY_CONFIG
    return values, classes


def _environment_block_size(values: Mapping[str, str], *, windows: bool) -> int:
    if windows:
        return sum(len(f"{key}={value}\0".encode("utf-16-le")) for key, value in values.items()) + 2
    return sum(len(key.encode()) + len(value.encode()) + 2 for key, value in values.items())


def read_ca_trust_material(name: str, value: str) -> bytes:
    """Bind one declared CA bundle to bytes through one stable descriptor.

    A certificate path is mutable operator input.  Validate the final component
    without following it, read the same descriptor under a hard byte bound, and
    verify the path still identifies that descriptor before returning.  Callers
    must give the returned bytes to their TLS context as ``cadata`` rather than
    reopening this pathname later.
    """

    error = f"CA trust path must be a readable regular file: {name}"
    path = Path(value)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not nofollow and os.name != "nt":
        # A path-based CA bundle is not safe to admit when the host cannot
        # promise that opening the final component does not follow a link.
        raise EnvironmentPolicyError(error)
    try:
        before = path.lstat()
    except OSError as exc:
        raise EnvironmentPolicyError(error) from exc
    signature = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_size < 0
        or before.st_size > CA_TRUST_MAX_BYTES
    ):
        raise EnvironmentPolicyError(error)
    # Windows lacks O_NOFOLLOW in CPython. Its lstat/fstat/final-lstat identity
    # checks below remain fail-closed for a changed link or replacement; POSIX
    # hosts additionally enforce no-follow at the kernel open boundary.
    flags = (
        os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0) | nofollow | getattr(os, "O_BINARY", 0)
    )
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise EnvironmentPolicyError(error) from exc
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) != signature
        ):
            raise EnvironmentPolicyError(error)
        data = bytearray()
        while len(data) <= CA_TRUST_MAX_BYTES:
            block = os.read(descriptor, min(64 * 1024, CA_TRUST_MAX_BYTES + 1 - len(data)))
            if not block:
                break
            data.extend(block)
        if len(data) > CA_TRUST_MAX_BYTES or len(data) != opened.st_size:
            raise EnvironmentPolicyError(error)
        after = os.fstat(descriptor)
        if after.st_nlink != 1 or (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != signature:
            raise EnvironmentPolicyError(error)
        final = path.lstat()
        if (
            stat.S_ISLNK(final.st_mode)
            or not stat.S_ISREG(final.st_mode)
            or final.st_nlink != 1
            or (final.st_dev, final.st_ino, final.st_size, final.st_mtime_ns) != signature
        ):
            raise EnvironmentPolicyError(error)
        return bytes(data)
    except OSError as exc:
        raise EnvironmentPolicyError(error) from exc
    finally:
        os.close(descriptor)


def _validate_proxy_aliases(values: Mapping[str, str], classes: Mapping[str, EnvClass]) -> None:
    aliases: dict[str, str] = {}
    for name, value in values.items():
        if classes.get(name) is not EnvClass.PROXY_CREDENTIAL:
            continue
        alias = name.upper()
        previous = aliases.get(alias)
        if previous is not None and previous != value:
            raise EnvironmentPolicyError(f"conflicting proxy aliases: {alias}")
        aliases[alias] = value


def build_child_environment(
    root: Path,
    *,
    policy: ChildEnvPolicy,
    pass_names: Sequence[str] = (),
    internal: Mapping[str, str] | None = None,
    parent: Mapping[str, str] | None = None,
) -> ChildEnvironment:
    parent_values = os.environ if parent is None else parent
    if len(pass_names) > CHILD_MAX_KEYS:
        raise EnvironmentPolicyError("explicit child environment exceeds the key-count limit")
    declarations = list(policy.declarations)
    declared_normal = {_normal(item.name, _is_windows()) for item in declarations}
    for name in pass_names:
        validate_environment_name(name)
        normalized = _normal(name, _is_windows())
        if normalized in declared_normal:
            raise EnvironmentPolicyError(f"duplicate child environment key: {name}")
        classification = classify_environment_name(name)
        if classification is EnvClass.OWNER_TOKEN:
            raise EnvironmentPolicyError("owner token cannot be explicitly passed")
        declarations.append(EnvKey(name, classification, required=True))
        declared_normal.add(normalized)
    if len(declarations) > CHILD_MAX_KEYS:
        raise EnvironmentPolicyError("child environment policy exceeds the key-count limit")
    if policy.allowed_classes is not None:
        for declaration in declarations:
            if declaration.classification not in policy.allowed_classes:
                raise EnvironmentPolicyError(
                    f"{policy.name} forbids class {declaration.classification.value}: {declaration.name}"
                )
    resolved = read_declared_environment(
        root,
        declarations,
        include_prepared=policy.include_prepared,
        parent=parent_values,
    )
    values, classes = _minimal_values(root, parent_values) if policy.include_minimal else ({}, {})
    for item in resolved.declared:
        values[item.name] = resolved.values[item.name]
        classes[item.name] = item.classification
    internal_values = {} if internal is None else dict(internal)
    by_name = {_normal(item.name, _is_windows()): item for item in declarations}
    for name, value in internal_values.items():
        validate_environment_name(name)
        declaration = by_name.get(_normal(name, _is_windows()))
        if declaration is None or EnvSource.INTERNAL not in declaration.sources:
            raise EnvironmentPolicyError(f"internal environment key is not declared: {name}")
        if not isinstance(value, str):
            raise EnvironmentPolicyError(f"internal environment value is invalid for key: {name}")
        values[declaration.name] = value
        classes[declaration.name] = declaration.classification
    _validate_proxy_aliases(values, classes)
    trust_material: dict[str, bytes] = {}
    for name, value in values.items():
        if classes[name] is EnvClass.CA_TRUST_PATH:
            trust_material[name] = read_ca_trust_material(name, value)
    for key, value in values.items():
        if len(key.encode()) > DOTENV_MAX_LINE_BYTES or len(value.encode()) > DOTENV_MAX_LINE_BYTES:
            raise EnvironmentPolicyError(f"child environment key exceeds size bounds: {key}")
    windows = _is_windows()
    limit = WINDOWS_ENV_MAX_BYTES if windows else POSIX_ENV_MAX_BYTES
    if _environment_block_size(values, windows=windows) > limit:
        raise EnvironmentPolicyError(f"{policy.name} child environment exceeds the block-size limit")
    passed = tuple(PassedKey(key, classes[key]) for key in sorted(values, key=str.casefold))
    return ChildEnvironment(values, policy.name, passed, trust_material)


def minimal_child_environment(
    root: Path,
    *,
    policy_name: str,
    parent: Mapping[str, str] | None = None,
) -> ChildEnvironment:
    """Build the fixed minimal environment for a non-credentialed child."""

    return build_child_environment(
        root,
        policy=purpose_policy(policy_name),
        parent=parent,
    )


STAGE_C_SELECTOR_NAMES = (
    "ROOKERY_PREPARE_NETWORK_ENV_KEYS",
    "SEARXNG_NETWORK_ENV_KEYS",
    "BROWSER_ENV_KEYS",
)
STAGE_C_CONTROL_KEYS = tuple(EnvKey(name, EnvClass.ROOKERY_CONFIG) for name in STAGE_C_SELECTOR_NAMES)
_STAGE_C_NETWORK_CLASSES = frozenset({EnvClass.PROXY_CREDENTIAL, EnvClass.CA_TRUST_PATH})
_STAGE_C_SAFE_CHILD_CLASSES = frozenset(
    {
        EnvClass.OS_RUNTIME,
        EnvClass.TERMINAL_SETTING,
        EnvClass.CAPABILITY_PATH,
        EnvClass.UNKNOWN_EXPLICIT,
    }
)
_BROWSER_INTERNAL_PATH_NAMES = (
    "HOME",
    "XDG_CONFIG_HOME",
    "XDG_CACHE_HOME",
    "XDG_DATA_HOME",
    "TMPDIR",
)


def _stage_c_controls(root: Path, *, parent: Mapping[str, str] | None = None) -> ResolvedEnvironment:
    """Read only names-only Stage-C controls with dotenv precedence."""

    return read_declared_environment(root, STAGE_C_CONTROL_KEYS, parent=parent)


def _stage_c_selector_declarations(
    root: Path,
    *,
    selector: str,
    allowed_classes: Collection[EnvClass],
    required: bool,
    parent: Mapping[str, str] | None,
) -> tuple[EnvKey, ...]:
    raw = _stage_c_controls(root, parent=parent).get(selector)
    names = parse_name_array(raw, label=selector)
    allowed = frozenset(allowed_classes)
    declarations: list[EnvKey] = []
    for name in names:
        classification = classify_environment_name(name)
        if classification not in allowed:
            raise EnvironmentPolicyError(f"{selector} forbids class {classification.value}: {name}")
        declarations.append(EnvKey(name, classification, required=required))
    return tuple(declarations)


def _stage_c_environment(
    root: Path,
    *,
    selector: str,
    policy_name: str,
    allowed_classes: Collection[EnvClass],
    required: bool,
    parent: Mapping[str, str] | None = None,
    internal: Mapping[str, str] | None = None,
    internal_declarations: Collection[EnvKey] = (),
    include_minimal: bool = True,
) -> ChildEnvironment:
    """Resolve one purpose's exact grants before any child or network effect.

    Selector values are names-only JSON arrays.  The actual values are resolved
    through the same dotenv-wins-parent path as all other child environments,
    never by copying the process environment.
    """

    selected = _stage_c_selector_declarations(
        root,
        selector=selector,
        allowed_classes=allowed_classes,
        required=required,
        parent=parent,
    )
    declarations = (*selected, *tuple(internal_declarations))
    return build_child_environment(
        root,
        policy=purpose_policy(
            policy_name,
            declarations,
            include_minimal=include_minimal,
            allowed_classes=frozenset(allowed_classes) | {item.classification for item in internal_declarations},
        ),
        internal=internal,
        parent=parent,
    )


def preparation_local_environment(root: Path, *, parent: Mapping[str, str] | None = None) -> ChildEnvironment:
    """The local preparation policy deliberately has no operator grant."""

    return minimal_child_environment(root, policy_name="preparation-local", parent=parent)


def preparation_network_environment(
    root: Path,
    *,
    parent: Mapping[str, str] | None = None,
    required: bool = True,
) -> ChildEnvironment:
    return _stage_c_environment(
        root,
        selector="ROOKERY_PREPARE_NETWORK_ENV_KEYS",
        policy_name="preparation-network",
        allowed_classes=_STAGE_C_NETWORK_CLASSES,
        required=required,
        parent=parent,
    )


def searxng_network_environment(
    root: Path,
    *,
    parent: Mapping[str, str] | None = None,
    required: bool = True,
) -> ChildEnvironment:
    return _stage_c_environment(
        root,
        selector="SEARXNG_NETWORK_ENV_KEYS",
        policy_name="searxng-network",
        allowed_classes=_STAGE_C_NETWORK_CLASSES,
        required=required,
        parent=parent,
    )


def browser_environment(
    root: Path,
    *,
    parent: Mapping[str, str] | None = None,
    required: bool = True,
    private_paths: Mapping[str, str] | None = None,
) -> ChildEnvironment:
    """Build the browser's nonsecret grants plus known private path inputs.

    Private paths are internal capability paths only.  They cannot be selected
    by ``BROWSER_ENV_KEYS`` and no owner token is accepted on this surface.
    """

    internal = {} if private_paths is None else dict(private_paths)
    unexpected = set(internal).difference(_BROWSER_INTERNAL_PATH_NAMES)
    if unexpected:
        raise EnvironmentPolicyError("browser private path name is not supported")
    declarations = tuple(EnvKey(name, EnvClass.CAPABILITY_PATH, sources=(EnvSource.INTERNAL,)) for name in internal)
    return _stage_c_environment(
        root,
        selector="BROWSER_ENV_KEYS",
        policy_name="browser",
        allowed_classes=_STAGE_C_SAFE_CHILD_CLASSES,
        required=required,
        parent=parent,
        internal=internal,
        internal_declarations=declarations,
        include_minimal=False,
    )


def _stage_c_truth(value: str | None) -> bool:
    return str(value or "").strip().casefold() in {"1", "true", "yes", "on"}


def browser_mode(value: str | None) -> str:
    """Validate the browser mode before any launch or preparation effect."""

    mode = str(value or "auto").strip().casefold()
    if mode not in {"auto", "cdp", "bidi", "disabled"}:
        raise EnvironmentPolicyError("browser_mode_invalid")
    return mode


def browser_cdp_required(preparation: ResolvedEnvironment, manifest: Mapping[str, Any] | None = None) -> bool:
    """Require CDP for explicit browser mode and reviewed browser-backed adapters."""

    mode = browser_mode(preparation.get("BROWSER_MODE"))
    if mode == "cdp":
        return True
    adapter = {} if manifest is None else manifest.get("adapter", {})
    if mode == "bidi" and isinstance(adapter, Mapping) and adapter.get("id") == "ctfd_browser":
        return False
    return isinstance(adapter, Mapping) and adapter.get("id") in {
        "ctfd_browser",
        "ctfd_browser_gateway",
        "skillbit",
    }


def verify_required_browser_cdp(preparation: ResolvedEnvironment, manifest: Mapping[str, Any] | None = None) -> None:
    """Require a ready CDP endpoint when the selected launch needs a browser."""

    if browser_cdp_required(preparation, manifest):
        verify_browser_cdp_endpoint(preparation.get("BROWSER_CDP_URL"))


def verify_required_browser_bidi(preparation: ResolvedEnvironment) -> None:
    """Require a ready Firefox BiDi endpoint for explicit BiDi mode."""

    if browser_mode(preparation.get("BROWSER_MODE")) == "bidi":
        from .browser_bidi import verify_browser_bidi_endpoint

        verify_browser_bidi_endpoint(preparation.get("BROWSER_BIDI_URL"))


def browser_gateway_required(manifest: Mapping[str, Any]) -> bool:
    """Return whether the selected adapter requires the sealed browser gateway."""

    adapter = manifest.get("adapter")
    return isinstance(adapter, Mapping) and adapter.get("id") in {
        "ctfd_browser_gateway",
        "skillbit",
    }


def verify_required_browser_gateway(
    root: Path,
    preparation: ResolvedEnvironment,
    manifest: Mapping[str, Any],
    *,
    baseline_configuration_digest: str,
    parent: Mapping[str, str] | None = None,
) -> BrowserGatewayReadiness | None:
    """Bind the selected gateway adapter to its sealed loopback status service."""

    if not browser_gateway_required(manifest):
        return None
    from .browser_gateway_policy import (
        BrowserGatewayPolicyError,
        browser_gateway_environment_origin_name,
        browser_gateway_origin,
        compile_browser_gateway_policy,
        policy_sha256,
    )

    try:
        origin_name = browser_gateway_environment_origin_name(manifest)
        adapter_environment = read_declared_environment(
            root,
            (EnvKey(origin_name, EnvClass.ROOKERY_CONFIG),),
            parent=parent,
        )
        environment_origin = adapter_environment.get(origin_name)
        origin = browser_gateway_origin(manifest, environment_origin)
        expected_policy = compile_browser_gateway_policy(
            manifest,
            baseline_configuration_digest=baseline_configuration_digest,
            origin=origin,
            environment_origin=environment_origin,
        )
        expected_digest = policy_sha256(expected_policy)
        expected_expiry = expected_policy["expires_at"]
    except (BrowserGatewayPolicyError, EnvironmentPolicyError, KeyError, TypeError) as exc:
        raise EnvironmentPolicyError("browser_gateway_policy_invalid") from exc
    if not isinstance(expected_expiry, str):
        raise EnvironmentPolicyError("browser_gateway_policy_invalid")
    return verify_browser_gateway_endpoint(
        preparation.get("BROWSER_GATEWAY_URL"),
        expected_policy_sha256=expected_digest,
        expected_expires_at=expected_expiry,
    )


def resolve_stage_c_launch_environment(
    root: Path,
    *,
    preparation: ResolvedEnvironment | None = None,
    parent: Mapping[str, str] | None = None,
) -> Mapping[str, ChildEnvironment]:
    """Purely resolve Stage-C purpose grants for launch admission.

    Disabled purposes still parse and classify their selectors.  They do not
    require absent selected values until the action that can use them is active.
    The returned environments are intentionally value-private.
    """

    prepared = preparation or read_declared_environment(root, PREPARATION_KEYS, parent=parent)
    preparation_active = (prepared.get("ROOKERY_PREPARE_MODE") or "auto").strip().casefold() not in {
        "off",
        "disabled",
    } and _stage_c_truth(prepared.get("ROOKERY_ALLOW_INSTALL_NETWORK") or "0")
    searxng_active = (prepared.get("SEARXNG_MODE") or "auto").strip().casefold() not in {"off", "disabled"}
    browser_active = browser_mode(prepared.get("BROWSER_MODE")) != "disabled"
    environments = {
        "preparation-local": preparation_local_environment(root, parent=parent),
        "preparation-network": preparation_network_environment(root, parent=parent, required=preparation_active),
        "searxng-network": searxng_network_environment(root, parent=parent, required=searxng_active),
        "browser": browser_environment(root, parent=parent, required=browser_active),
    }
    return MappingProxyType(environments)


CORE_MANIFEST_NAMES = (
    "EVENT_NAME",
    "EVENT_ID",
    "EVENT_URL",
    "EVENT_START",
    "EVENT_END",
    "PLATFORM_ADAPTER",
    "EVENT_EXTENSIONS",
    "EVENT_CATEGORIES",
    "FLAG_REGEX",
    "ANSWER_EXAMPLES_JSON",
    "EVENT_SCOPE_ACK",
    "SCOPE_EXPIRES_AT",
    "SCOPE_MAX_BYTES",
    "WRITEUP_MODE",
    "QUEUE_AUTOMATION",
    "QUEUE_CADENCE_SECONDS",
    "QUEUE_JITTER_SECONDS",
    "QUEUE_LATENCY_SECONDS",
    "QUEUE_WATCH_INTERVAL_SECONDS",
    "CONCURRENCY_MAX_WORKERS",
    "CONCURRENCY_MAX_JOBS",
    "CODEX_SUBAGENT_THREADS",
    "COMPUTE_TOTAL_UNITS",
    "COMPUTE_INTERACTIVE_RESERVE",
    "COMPUTE_ADMIT_PERCENT",
    "COMPUTE_TARGET_PERCENT",
    "COMPUTE_CEILING_PERCENT",
    "COMPUTE_BACKOFF_PERCENT",
    "COMPUTE_SAMPLE_SECONDS",
    "COMPUTE_ADMISSION_COOLDOWN_SECONDS",
    "COMPUTE_LEASE_SECONDS",
    "COMPUTE_DEFAULT_JOB_BUDGET_SECONDS",
    "PRIORITY_STRATEGY",
    "PRIORITY_WEIGHTS_JSON",
    "ALLOWED_HOSTS",
    "ALLOWED_CIDRS",
    "ALLOWED_PORTS",
    "ALLOWED_PROTOCOLS",
    "ALLOWED_FILE_ORIGINS",
    "PLATFORM_HOSTS",
    "SCORING_ACTION_KINDS",
    "SCORING_COMPLETION_MODE",
    "AUTOMATION_PERMITTED_ACTION_KINDS",
)
CORE_MANIFEST_KEYS = tuple(EnvKey(name, EnvClass.ROOKERY_CONFIG) for name in CORE_MANIFEST_NAMES)

PREPARATION_NAMES = (
    "PATH",
    "ROOKERY_PREPARE_MODE",
    "ROOKERY_PREPARE_INSTALL",
    "ROOKERY_INSTALL_RECOMMENDED",
    "ROOKERY_INSTALL_HEAVY",
    "ROOKERY_ALLOW_INSTALL_NETWORK",
    "ROOKERY_PREPARE_TIMEOUT",
    "ROOKERY_SUDO",
    "SEARXNG_MODE",
    "SEARXNG_URL",
    "SEARXNG_LOCAL_PORT",
    "SEARXNG_IMAGE",
    "SEARXNG_CONTAINER_ENGINE",
    "SEARXNG_START_TIMEOUT",
    "BROWSER_MODE",
    "BROWSER_CDP_URL",
    "BROWSER_BIDI_URL",
    "BROWSER_GATEWAY_URL",
    "BROWSER_EXECUTABLE",
    "CHROME_BIN",
    "ROCKYOU_PATH",
    "SECLISTS_PATH",
)
PREPARATION_KEYS = tuple(
    EnvKey(
        name,
        EnvClass.OS_RUNTIME
        if name == "PATH"
        else (
            EnvClass.CAPABILITY_PATH
            if name in {"BROWSER_EXECUTABLE", "CHROME_BIN", "ROCKYOU_PATH", "SECLISTS_PATH"}
            else EnvClass.ROOKERY_CONFIG
        ),
    )
    for name in PREPARATION_NAMES
)

CODEX_PROVIDER_NAMES = (
    "CODEX_API_KEY",
    "CODEX_ACCESS_TOKEN",
    "OPENAI_API_KEY",
    "OPENAI_FEDERATION_RULE_ID",
    "OPENAI_IDENTITY_TOKEN_FILE",
    "OPENAI_WORKLOAD_IDENTITY_CONTEXT",
)
CODEX_LOCATION_NAMES = ("HOME", "CODEX_HOME", "CODEX_SQLITE_HOME")
CODEX_TERMINAL_NAMES = ("TERM", "COLORTERM", "NO_COLOR", "CLICOLOR", "CLICOLOR_FORCE", "EDITOR", "VISUAL")
CODEX_CONTROL_KEYS = (
    EnvKey("CODEX_AUTH_MODE", EnvClass.ROOKERY_CONFIG),
    EnvKey("CODEX_PROVIDER_ENV_KEYS", EnvClass.ROOKERY_CONFIG),
    EnvKey("CODEX_NETWORK_ENV_KEYS", EnvClass.ROOKERY_CONFIG),
    EnvKey("ROOKERY_MEASUREMENT_BASELINE_PATH", EnvClass.ROOKERY_CONFIG),
)


def _codex_controls(root: Path, *, parent: Mapping[str, str] | None = None) -> ResolvedEnvironment:
    return read_declared_environment(root, CODEX_CONTROL_KEYS, parent=parent)


def normalize_measurement_baseline_path(root: Path, value: str | None) -> Path:
    """Resolve one final private baseline path outside the workspace."""

    if not isinstance(value, str) or not value or value.strip().casefold() == "unknown":
        raise EnvironmentPolicyError("measurement_baseline_path_missing")
    workspace = root.resolve()
    candidate = Path(value)
    if not candidate.is_absolute():
        candidate = workspace / candidate
    try:
        normalized = Path(os.path.abspath(os.fspath(candidate))).resolve(strict=False)
    except (OSError, ValueError) as exc:
        raise EnvironmentPolicyError("measurement_baseline_path_invalid") from exc
    if normalized.is_relative_to(workspace):
        raise EnvironmentPolicyError("measurement_baseline_path_inside_workspace")
    return normalized


def codex_auth_mode(root: Path, *, parent: Mapping[str, str] | None = None) -> str:
    mode = (_codex_controls(root, parent=parent).get("CODEX_AUTH_MODE") or "local-login").strip()
    if mode not in {"local-login", "environment"}:
        raise EnvironmentPolicyError("CODEX_AUTH_MODE must be local-login or environment")
    return mode


def codex_policy(root: Path, *, parent: Mapping[str, str] | None = None) -> ChildEnvPolicy:
    controls = _codex_controls(root, parent=parent)
    mode = (controls.get("CODEX_AUTH_MODE") or "local-login").strip()
    if mode not in {"local-login", "environment"}:
        raise EnvironmentPolicyError("CODEX_AUTH_MODE must be local-login or environment")
    # Parse declarations in both modes. Local login never receives them, but a
    # contradictory declaration must be rejected rather than silently dropped.
    provider_names = parse_name_array(
        controls.get("CODEX_PROVIDER_ENV_KEYS"),
        label="CODEX_PROVIDER_ENV_KEYS",
    )
    network_names = parse_name_array(
        controls.get("CODEX_NETWORK_ENV_KEYS"),
        label="CODEX_NETWORK_ENV_KEYS",
    )
    declarations: list[EnvKey] = []
    declarations.extend(EnvKey(name, EnvClass.OS_RUNTIME) for name in CODEX_LOCATION_NAMES)
    declarations.extend(EnvKey(name, EnvClass.TERMINAL_SETTING) for name in CODEX_TERMINAL_NAMES)
    if mode == "environment":
        declarations.extend(EnvKey(name, EnvClass.PROVIDER_AUTH) for name in CODEX_PROVIDER_NAMES)
        declarations.extend(EnvKey(name, EnvClass.CA_TRUST_PATH) for name in ("CODEX_CA_CERTIFICATE", "SSL_CERT_FILE"))
    seen = {_normal(item.name, _is_windows()) for item in declarations}
    forbidden = {
        EnvClass.ADAPTER_SECRET,
        EnvClass.SESSION_SECRET_REF,
        EnvClass.VPN_SECRET_REF,
        EnvClass.OWNER_TOKEN,
        EnvClass.AGENT_CAPABILITY,
    }
    if mode == "environment":
        for name in provider_names:
            classification = classify_environment_name(name)
            if classification in forbidden or classification in {EnvClass.PROXY_CREDENTIAL, EnvClass.CA_TRUST_PATH}:
                raise EnvironmentPolicyError(f"CODEX_PROVIDER_ENV_KEYS collides with forbidden class: {name}")
            if _normal(name, _is_windows()) in seen:
                continue
            declarations.append(EnvKey(name, EnvClass.PROVIDER_AUTH))
            seen.add(_normal(name, _is_windows()))
        for name in network_names:
            classification = classify_environment_name(name)
            if classification not in {EnvClass.PROXY_CREDENTIAL, EnvClass.CA_TRUST_PATH}:
                raise EnvironmentPolicyError(f"CODEX_NETWORK_ENV_KEYS is not a proxy or CA key: {name}")
            if _normal(name, _is_windows()) in seen:
                continue
            declarations.append(EnvKey(name, classification))
            seen.add(_normal(name, _is_windows()))
    elif provider_names or network_names:
        # Local-login must not silently discard declared environment authority:
        # it would make admission prove a different launch from the one the
        # operator configured.
        raise EnvironmentPolicyError("local-login forbids CODEX_PROVIDER_ENV_KEYS and CODEX_NETWORK_ENV_KEYS")
    return purpose_policy(
        "codex",
        declarations,
        allowed_classes={
            EnvClass.OS_RUNTIME,
            EnvClass.TERMINAL_SETTING,
            EnvClass.PROVIDER_AUTH,
            EnvClass.PROXY_CREDENTIAL,
            EnvClass.CA_TRUST_PATH,
        },
    )


CODEX_SHELL_POLICY_NAMES = (
    "PATH",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TZ",
    "TMPDIR",
    "SystemRoot",
    "ComSpec",
    "PATHEXT",
    "TEMP",
    "TMP",
    "ROOKERY_ROOT",
    "PYTHONDONTWRITEBYTECODE",
)


def codex_shell_policy_toml() -> str:
    lines = [
        "[shell_environment_policy]",
        'inherit = "core"',
        "experimental_use_profile = false",
        "ignore_default_excludes = false",
        "",
        "[shell_environment_policy.filters]",
    ]
    lines.extend(f'{json.dumps(name)} = "include"' for name in CODEX_SHELL_POLICY_NAMES)
    return "\n".join(lines) + "\n"


def codex_launcher_environment(root: Path, *, parent: Mapping[str, str] | None = None) -> ChildEnvironment:
    child = build_child_environment(root, policy=codex_policy(root, parent=parent), parent=parent)
    codex_home = child.values.get("CODEX_HOME")
    if codex_home and not Path(codex_home).expanduser().is_dir():
        raise EnvironmentPolicyError("CODEX_HOME must name an existing directory")
    return child


def _codex_file_identity(path: Path) -> dict[str, int | str]:
    """Return a bounded, descriptor-verified executable identity."""

    digest, info = _stable_regular_file_digest(
        path, maximum=CODEX_EXECUTABLE_MAX_BYTES, label="codex_executable_invalid"
    )
    return {
        "path": str(path),
        "device": int(info.st_dev),
        "inode": int(info.st_ino),
        "size": int(info.st_size),
        "mtime_ns": int(info.st_mtime_ns),
        "sha256": digest,
    }


def _absolute_codex_executable(child: ChildEnvironment) -> tuple[str, dict[str, int | str]]:
    declared_path = next(
        (value for key, value in child.values.items() if key.casefold() == "path"),
        None,
    )
    executable = shutil.which("codex", path=declared_path)
    if not executable:
        raise EnvironmentPolicyError("codex executable was not found in the declared PATH")
    absolute = Path(executable).resolve(strict=True)
    if not absolute.is_absolute():
        raise EnvironmentPolicyError("codex executable path is not absolute")
    return str(absolute), _codex_file_identity(absolute)


def _codex_process_group_exists(pgid: int) -> bool:
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _wait_for_codex_process_group_exit(process: subprocess.Popen[Any], pgid: int, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while True:
        process.poll()
        if not _codex_process_group_exists(pgid):
            return True
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        time.sleep(min(0.02, remaining))


def _stop_codex_process_group(process: subprocess.Popen[Any], pgid: int) -> bool:
    """Stop and verify the exact group owned by one admission probe.

    Process groups do not contain a descendant that deliberately escapes with
    setsid(); hostile-executable containment needs a cgroup or sandbox boundary.
    """

    if os.name != "posix":  # pragma: no cover - operational launch is POSIX-only.
        if process.poll() is not None:
            return True
        try:
            process.terminate()
            process.wait(timeout=1)
            return True
        except subprocess.TimeoutExpired:
            process.kill()
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                return False
            return True
        except ProcessLookupError:
            return process.poll() is not None

    try:
        os.killpg(pgid, signal.SIGTERM)
    except ProcessLookupError:
        process.poll()
        return True
    except OSError:
        return False
    if _wait_for_codex_process_group_exit(process, pgid, 1.0):
        return True
    try:
        os.killpg(pgid, signal.SIGKILL)
    except ProcessLookupError:
        process.poll()
        return True
    except OSError:
        return False
    return _wait_for_codex_process_group_exit(process, pgid, 1.0)


def _cleanup_failed_codex_probe(process: subprocess.Popen[Any], pgid: int) -> None:
    if not _stop_codex_process_group(process, pgid):
        raise EnvironmentPolicyError("codex_probe_process_group_cleanup_failed")


def _bounded_codex_probe(
    executable: str,
    arguments: Sequence[str],
    *,
    root: Path,
    environment: Mapping[str, str],
    timeout_seconds: int = CODEX_PROBE_TIMEOUT_SECONDS,
) -> tuple[int, bytes]:
    """Run one shell-free Codex admission probe with bounded captured output."""

    try:
        process = subprocess.Popen(
            [executable, *arguments],
            cwd=root,
            env=dict(environment),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    except OSError as exc:
        raise EnvironmentPolicyError("codex_probe_unavailable") from exc
    owned_pgid = process.pid
    output = bytearray()
    try:
        if process.stdout is None:
            _cleanup_failed_codex_probe(process, owned_pgid)
            raise EnvironmentPolicyError("codex_probe_capture_failed")
        if os.name == "posix" and process.stdout is not None:
            selector = selectors.DefaultSelector()
            try:
                selector.register(process.stdout, selectors.EVENT_READ)
                deadline = time.monotonic() + timeout_seconds
                eof = False
                while not eof:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise subprocess.TimeoutExpired(process.args, timeout_seconds)
                    events = selector.select(remaining)
                    if not events:
                        raise subprocess.TimeoutExpired(process.args, timeout_seconds)
                    chunk = os.read(process.stdout.fileno(), CODEX_PROBE_MAX_OUTPUT_BYTES + 1 - len(output))
                    if not chunk:
                        eof = True
                    else:
                        output.extend(chunk)
                        if len(output) > CODEX_PROBE_MAX_OUTPUT_BYTES:
                            raise EnvironmentPolicyError("codex_probe_output_exceeds_limit")
                process.wait(timeout=max(0.1, deadline - time.monotonic()))
            finally:
                selector.close()
        else:  # pragma: no cover - Windows cannot run the required WSL launch path.
            captured, _ = process.communicate(timeout=timeout_seconds)
            output.extend(captured or b"")
            if len(output) > CODEX_PROBE_MAX_OUTPUT_BYTES:
                raise EnvironmentPolicyError("codex_probe_output_exceeds_limit")
    except EnvironmentPolicyError:
        _cleanup_failed_codex_probe(process, owned_pgid)
        raise
    except subprocess.TimeoutExpired as exc:
        _cleanup_failed_codex_probe(process, owned_pgid)
        raise EnvironmentPolicyError("codex_probe_unavailable") from exc
    except Exception as exc:
        _cleanup_failed_codex_probe(process, owned_pgid)
        raise EnvironmentPolicyError("codex_probe_capture_failed") from exc
    finally:
        if process.stdout is not None:
            try:
                process.stdout.close()
            except OSError:
                pass
    if os.name == "posix" and _codex_process_group_exists(owned_pgid):
        _cleanup_failed_codex_probe(process, owned_pgid)
        raise EnvironmentPolicyError("codex_probe_process_group_outlived_leader")
    return int(process.returncode), bytes(output)


def _probe_codex(
    root: Path,
    child: ChildEnvironment,
    *,
    auth_mode: str = "local-login",
    require_agent_config: bool = False,
) -> tuple[str, Mapping[str, int | str], str, bool]:
    executable, identity = _absolute_codex_executable(child)
    version_code, version_output = _bounded_codex_probe(executable, ("--version",), root=root, environment=child.values)
    if version_code != 0:
        raise EnvironmentPolicyError("codex_version_unavailable")
    try:
        rendered = version_output.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise EnvironmentPolicyError("codex_version_invalid") from exc
    versions = _CODEX_VERSION_RE.findall(rendered)
    if len(versions) != 1:
        raise EnvironmentPolicyError("codex_version_invalid")
    strict_code, _ = _bounded_codex_probe(
        executable, ("--strict-config", "--version"), root=root, environment=child.values
    )
    strict_supported = strict_code == 0
    if auth_mode == "environment" and not strict_supported:
        raise EnvironmentPolicyError("codex_environment_auth_requires_strict_config")
    if require_agent_config:
        capability_code, capability_output = _bounded_codex_probe(
            executable,
            (
                "doctor",
                "--json",
                "-c",
                "agents.max_depth=2",
                "-c",
                "agents.max_concurrent_threads_per_session=96",
            ),
            root=root,
            environment=child.values,
            timeout_seconds=CODEX_CAPABILITY_PROBE_TIMEOUT_SECONDS,
        )
        try:
            capability = json.loads(capability_output.decode("utf-8", errors="strict"))
            config_check = capability["checks"]["config.load"]
        except (KeyError, TypeError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise EnvironmentPolicyError("codex_agent_config_capability_unavailable") from exc
        if capability_code != 0 or not isinstance(config_check, dict) or config_check.get("status") != "ok":
            raise EnvironmentPolicyError("codex_agent_config_capability_unavailable")
    login_arguments = ("--strict-config", "login", "status") if auth_mode == "environment" else ("login", "status")
    login_code, _ = _bounded_codex_probe(executable, login_arguments, root=root, environment=child.values)
    if login_code != 0:
        raise EnvironmentPolicyError("codex_login_unavailable")
    final_executable, final_identity = _absolute_codex_executable(child)
    if final_executable != executable or dict(final_identity) != dict(identity):
        raise EnvironmentPolicyError("codex_executable_changed_during_probe")
    return executable, identity, versions[0], strict_supported


def _selected_adapter_contract(root: Path, manifest: Mapping[str, Any]) -> None:
    """Validate only the selected descriptor's declared credential name.

    Loading an adapter class can run arbitrary module-level code. Launch admission
    deliberately reads the selected descriptor as data and checks no network path.
    """

    from .manifest import adapter_descriptor

    adapter = str(manifest.get("adapter", {}).get("id") or "")
    if not adapter:
        raise EnvironmentPolicyError("selected_adapter_invalid")
    descriptor = adapter_descriptor(root, adapter)
    if adapter != "manual" and descriptor is None:
        raise EnvironmentPolicyError("selected_adapter_descriptor_missing")
    if descriptor is not None:
        for key in ("id", "schema_version", "module", "class"):
            if not isinstance(descriptor.get(key), str) or not descriptor.get(key):
                raise EnvironmentPolicyError("selected_adapter_descriptor_invalid")
    configuration = manifest.get("adapter", {}).get("config", {})
    if not isinstance(configuration, Mapping):
        raise EnvironmentPolicyError("selected_adapter_descriptor_invalid")
    token_name = configuration.get("token_env")
    if token_name in {None, ""}:
        token_name = {
            "ctfd": "CTFD_TOKEN",
            "immersive": "IMMERSIVE_COOKIES_FILE",
        }.get(adapter)
    if token_name not in {None, ""}:
        exact_name = validate_environment_name(str(token_name), label="adapter token_env")
        classification = classify_environment_name(exact_name)
        if classification not in {
            EnvClass.ADAPTER_SECRET,
            EnvClass.SESSION_SECRET_REF,
        }:
            raise EnvironmentPolicyError("selected_adapter_descriptor_invalid")
        required = bool(set(manifest.get("capabilities", {}).get("required", [])) & {"platform_inventory", "scoring"})
        credential = read_declared_environment(
            root,
            (
                EnvKey(
                    exact_name,
                    classification,
                ),
            ),
            parent={},
        )
        value = credential.get(exact_name)
        if required and (not value or value.strip().casefold() == "unknown"):
            raise EnvironmentPolicyError(f"selected_adapter_credential_missing:{exact_name}")


def _launch_binding_path(root: Path) -> Path:
    return root / "state" / LAUNCH_BINDING_NAME


def _measurement_contract(value: Mapping[str, Any]) -> dict[str, Any]:
    """Validate the value-free availability facts retained from a baseline.

    The launch binding must carry enough information for a preserved telemetry
    report to determine applicability without reopening the private external
    baseline.  It intentionally excludes baseline paths, provider values, and
    operator-supplied explanations.
    """

    if not isinstance(value, Mapping) or set(value) != {
        "queue_automation_enabled",
        "provider_fields",
    }:
        raise EnvironmentPolicyError("launch_binding_invalid")
    queue_automation = value.get("queue_automation_enabled")
    providers = value.get("provider_fields")
    if not isinstance(queue_automation, bool) or not isinstance(providers, Mapping):
        raise EnvironmentPolicyError("launch_binding_invalid")
    if set(providers) != _MEASUREMENT_PROVIDER_FIELDS:
        raise EnvironmentPolicyError("launch_binding_invalid")
    result: dict[str, dict[str, str]] = {}
    for name in sorted(_MEASUREMENT_PROVIDER_FIELDS):
        field = providers.get(name)
        if (
            not isinstance(field, Mapping)
            or set(field) != {"availability"}
            or field.get("availability") not in {"available", "unavailable"}
        ):
            raise EnvironmentPolicyError("launch_binding_invalid")
        result[name] = {"availability": str(field["availability"])}
    return {
        "queue_automation_enabled": queue_automation,
        "provider_fields": result,
    }


def _read_bounded_binding(path: Path) -> LaunchBinding:
    try:
        info = path.lstat()
    except OSError as exc:
        raise EnvironmentPolicyError("launch_binding_missing") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise EnvironmentPolicyError("launch_binding_invalid")
    if stat.S_IMODE(info.st_mode) != 0o600 or info.st_mode & 0o077:
        raise EnvironmentPolicyError("launch_binding_not_private")
    if info.st_size > CODEX_PROBE_MAX_OUTPUT_BYTES:
        raise EnvironmentPolicyError("launch_binding_invalid")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise EnvironmentPolicyError("launch_binding_unreadable") from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) != (
            info.st_dev,
            info.st_ino,
            info.st_size,
            info.st_mtime_ns,
        ):
            raise EnvironmentPolicyError("launch_binding_changed")
        raw = os.read(descriptor, CODEX_PROBE_MAX_OUTPUT_BYTES + 1)
        if len(raw) > CODEX_PROBE_MAX_OUTPUT_BYTES:
            raise EnvironmentPolicyError("launch_binding_invalid")
    finally:
        os.close(descriptor)
    try:
        record = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EnvironmentPolicyError("launch_binding_invalid") from exc
    if not isinstance(record, dict):
        raise EnvironmentPolicyError("launch_binding_invalid")
    required = {
        "schema_version",
        "workspace_identity",
        "immutable_source_sha256",
        "environment_sha256",
        "resolved_manifest_sha256",
        "release_version",
        "baseline_sha256",
        "baseline_configuration_digest",
        "selected_adapter",
        "selected_extensions",
        "codex",
        "auth_mode",
        "strict_config_supported",
    }
    legacy_required = (required - {"resolved_manifest_sha256"}) | {"event_manifest_sha256"}
    version = record.get("schema_version")
    if version == "2":
        # Schema-2 evidence remains structurally readable for status and
        # preservation, but cannot support current comparison gates because it
        # did not retain the baseline's applicability declarations.
        if set(record) != legacy_required:
            raise EnvironmentPolicyError("launch_binding_invalid")
    elif version == "3":
        if set(record) != legacy_required | {"measurement_contract"}:
            raise EnvironmentPolicyError("launch_binding_invalid")
        _measurement_contract(record["measurement_contract"])
    elif version == LAUNCH_BINDING_SCHEMA_VERSION:
        if set(record) != required | {"measurement_contract"}:
            raise EnvironmentPolicyError("launch_binding_invalid")
        _measurement_contract(record["measurement_contract"])
    else:
        raise EnvironmentPolicyError("launch_binding_invalid")
    if (
        not isinstance(record["workspace_identity"], str)
        or not Path(record["workspace_identity"]).is_absolute()
        or not isinstance(record["release_version"], str)
        or not record["release_version"]
    ):
        raise EnvironmentPolicyError("launch_binding_invalid")
    digest_names = (
        "immutable_source_sha256",
        "environment_sha256",
        "event_manifest_sha256" if version in {"2", "3"} else "resolved_manifest_sha256",
        "baseline_sha256",
        "baseline_configuration_digest",
    )
    if not all(
        isinstance(record[name], str) and _SHA256_RE.fullmatch(record[name])
        for name in digest_names
    ):
        raise EnvironmentPolicyError("launch_binding_invalid")
    if not isinstance(record["selected_adapter"], str) or not isinstance(record["selected_extensions"], list):
        raise EnvironmentPolicyError("launch_binding_invalid")
    if any(not isinstance(item, str) for item in record["selected_extensions"]):
        raise EnvironmentPolicyError("launch_binding_invalid")
    if record["auth_mode"] not in {"local-login", "environment"} or not isinstance(
        record["strict_config_supported"], bool
    ):
        raise EnvironmentPolicyError("launch_binding_invalid")
    codex = record["codex"]
    if not isinstance(codex, dict) or set(codex) != {
        "path",
        "device",
        "inode",
        "size",
        "mtime_ns",
        "sha256",
        "version",
    }:
        raise EnvironmentPolicyError("launch_binding_invalid")
    if (
        not isinstance(codex["path"], str)
        or not Path(codex["path"]).is_absolute()
        or not isinstance(codex["version"], str)
        or not isinstance(codex["sha256"], str)
        or not _SHA256_RE.fullmatch(codex["sha256"])
    ):
        raise EnvironmentPolicyError("launch_binding_invalid")
    if any(
        isinstance(codex[name], bool) or not isinstance(codex[name], int) or codex[name] < 0
        for name in ("device", "inode", "size", "mtime_ns")
    ):
        raise EnvironmentPolicyError("launch_binding_invalid")
    return LaunchBinding(record, hashlib.sha256(raw).hexdigest())


def read_launch_binding(root: Path) -> LaunchBinding:
    """Read and structurally validate the already-published first-write record."""

    return _read_bounded_binding(_launch_binding_path(root))


def verify_launch_binding_integrity(root: Path) -> LaunchBinding:
    """Verify the durable binding against this exact deployed workspace.

    This check is intentionally independent of the SQLite handle so an already
    open store detects binding deletion, source/config drift, and copied roots
    before it starts a new mutation or writes a projection.
    """

    workspace = Path(canonical_workspace_identity(root))
    binding = read_launch_binding(workspace)
    if binding.record.get("schema_version") != LAUNCH_BINDING_SCHEMA_VERSION:
        raise EnvironmentPolicyError("launch_binding_schema_retired")
    if binding.record["workspace_identity"] != str(workspace):
        raise EnvironmentPolicyError("launch_workspace_identity_drift")
    if binding.record["immutable_source_sha256"] != immutable_source_digest(workspace):
        raise EnvironmentPolicyError("immutable_source_drift")
    environment_sha256, resolved_manifest_sha256 = _editable_configuration_digests(workspace)
    if (
        binding.record["environment_sha256"] != environment_sha256
        or binding.record["resolved_manifest_sha256"] != resolved_manifest_sha256
    ):
        raise EnvironmentPolicyError("launch_configuration_drift")
    return binding


def launch_binding_integrity_error(root: Path) -> str | None:
    """Return a value-free public blocker without changing the workspace."""

    workspace = Path(root).resolve()
    if not (workspace / "state" / "events.sqlite3").is_file():
        return None
    try:
        verify_launch_binding_integrity(workspace)
    except EnvironmentPolicyError as exc:
        return str(exc) or "launch_binding_invalid"
    return None


def _binding_record(gate: LaunchGate) -> dict[str, Any]:
    return {
        "schema_version": LAUNCH_BINDING_SCHEMA_VERSION,
        "workspace_identity": gate.workspace_identity,
        "immutable_source_sha256": gate.immutable_source_sha256,
        "environment_sha256": gate.environment_sha256,
        "resolved_manifest_sha256": gate.resolved_manifest_sha256,
        "release_version": gate.release_version,
        "baseline_sha256": gate.baseline_sha256,
        "baseline_configuration_digest": gate.baseline_configuration_digest,
        "measurement_contract": {
            "queue_automation_enabled": gate.measurement_contract["queue_automation_enabled"],
            "provider_fields": {
                name: dict(field) for name, field in gate.measurement_contract["provider_fields"].items()
            },
        },
        "selected_adapter": gate.selected_adapter,
        "selected_extensions": list(gate.selected_extensions),
        "codex": {**gate.codex_identity, "version": gate.codex_version},
        "auth_mode": gate.auth_mode,
        "strict_config_supported": gate.strict_config_supported,
    }


def _reverify_gate_inputs(gate: LaunchGate) -> None:
    """Repeat mutable launch checks after Codex probes and before publication."""

    from .baseline import MeasurementBaselineError, verify_measurement_baseline

    workspace = Path(canonical_workspace_identity(Path(gate.workspace_identity)))
    if workspace != Path(gate.workspace_identity):
        raise EnvironmentPolicyError("launch_workspace_identity_drift")
    if immutable_source_digest(workspace) != gate.immutable_source_sha256:
        raise EnvironmentPolicyError("immutable_source_drift")
    environment_sha256, resolved_manifest_sha256 = _editable_configuration_digests(
        workspace,
        gate.manifest,
    )
    if (
        environment_sha256 != gate.environment_sha256
        or resolved_manifest_sha256 != gate.resolved_manifest_sha256
    ):
        raise EnvironmentPolicyError("launch_configuration_drift")
    verify_required_browser_cdp(gate.preparation_environment, gate.manifest)
    verify_required_browser_bidi(gate.preparation_environment)
    try:
        baseline = verify_measurement_baseline(
            workspace,
            gate.baseline_path,
            dict(gate.manifest),
            verify_source_tree=False,
        )
    except MeasurementBaselineError as exc:
        raise EnvironmentPolicyError("measurement_baseline_invalid") from exc
    if (
        baseline["sha256"] != gate.baseline_sha256
        or baseline["configuration_digest"] != gate.baseline_configuration_digest
        or baseline["release_version"] != gate.release_version
        or _measurement_contract(baseline["measurement_contract"]) != _measurement_contract(gate.measurement_contract)
    ):
        raise EnvironmentPolicyError("measurement_baseline_drift")
    if browser_gateway_required(gate.manifest):
        if (
            gate.browser_gateway_policy_sha256 is None
            or gate.browser_gateway_expires_at is None
            or gate.browser_gateway_boot_nonce is None
        ):
            raise EnvironmentPolicyError("browser_gateway_policy_invalid")
        verify_browser_gateway_endpoint(
            gate.preparation_environment.get("BROWSER_GATEWAY_URL"),
            expected_policy_sha256=gate.browser_gateway_policy_sha256,
            expected_expires_at=gate.browser_gateway_expires_at,
            expected_boot_nonce=gate.browser_gateway_boot_nonce,
        )
    elif any(
        value is not None
        for value in (
            gate.browser_gateway_policy_sha256,
            gate.browser_gateway_expires_at,
            gate.browser_gateway_boot_nonce,
        )
    ):
        raise EnvironmentPolicyError("browser_gateway_policy_invalid")


def _publish_new_binding(path: Path, record: Mapping[str, Any]) -> LaunchBinding:
    """Publish the binding without replacing or following a pre-existing target."""

    if os.name != "posix":
        raise EnvironmentPolicyError("launch_binding_private_storage_unavailable")
    state = path.parent
    try:
        state_info = state.lstat()
    except OSError as exc:
        raise EnvironmentPolicyError("launch_binding_state_missing") from exc
    if stat.S_ISLNK(state_info.st_mode) or not stat.S_ISDIR(state_info.st_mode):
        raise EnvironmentPolicyError("launch_binding_state_invalid")
    if stat.S_IMODE(state_info.st_mode) != 0o700:
        raise EnvironmentPolicyError("launch_binding_state_invalid")
    if any(state.iterdir()):
        raise EnvironmentPolicyError("launch_bootstrap_incomplete")
    raw = (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    temporary: Path | None = None
    descriptor: int | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(prefix=".launch-binding-", dir=state)
        temporary = Path(temporary_name)
        os.fchmod(descriptor, 0o600)
        os.write(descriptor, raw)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        os.link(temporary, path)
        directory = os.open(state, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except FileExistsError as exc:
        raise EnvironmentPolicyError("launch_bootstrap_incomplete") from exc
    except OSError as exc:
        raise EnvironmentPolicyError("launch_binding_publish_failed") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return _read_bounded_binding(path)


def publish_or_verify_launch_binding(root: Path, gate: LaunchGate) -> LaunchBinding:
    """Create the first durable record, or compare a resumed workspace to it."""

    _reverify_gate_inputs(gate)
    path = _launch_binding_path(root)
    if path.exists() or path.is_symlink():
        binding = read_launch_binding(root)
        expected = _binding_record(gate)
        if dict(binding.record) != expected:
            raise EnvironmentPolicyError("launch_binding_drift")
        return binding
    return _publish_new_binding(path, _binding_record(gate))


def resolve_launch_gate(root: Path, *, parent: Mapping[str, str] | None = None) -> LaunchGate:
    """Prove launch eligibility before state or adapter contact.

    The only network effect is a bounded direct loopback CDP readiness check
    when the selected browser mode or adapter requires it.
    """

    from .baseline import MeasurementBaselineError, verify_measurement_baseline
    from .manifest import resolve_manifest

    workspace = Path(canonical_workspace_identity(root))
    state = workspace / "state"
    binding_exists = (state / LAUNCH_BINDING_NAME).exists() or (state / LAUNCH_BINDING_NAME).is_symlink()
    if state.exists() and not binding_exists:
        try:
            if any(state.iterdir()):
                raise EnvironmentPolicyError("launch_bootstrap_incomplete")
        except OSError as exc:
            raise EnvironmentPolicyError("launch_bootstrap_incomplete") from exc
    existing_binding = verify_launch_binding_integrity(workspace) if binding_exists else None
    core_environment = read_declared_environment(workspace, CORE_MANIFEST_KEYS, parent=parent)
    preparation_environment = read_declared_environment(workspace, PREPARATION_KEYS, parent=parent)
    # Selector syntax, class admission, selected proxy/CA paths, and required
    # active-purpose values are all checked before baseline publication, store
    # creation, adapter sync, or any preparation work.  The value-private
    # result remains attached to the gate for purpose owners to consume.
    stage_c_environments = resolve_stage_c_launch_environment(
        workspace,
        preparation=preparation_environment,
        parent=parent,
    )
    controls = _codex_controls(workspace, parent=parent)
    try:
        result = resolve_manifest(workspace, parent=parent)
    except Exception as exc:
        raise EnvironmentPolicyError("launch_configuration_invalid") from exc
    if result.errors or result.unresolved_required or not result.ready:
        raise EnvironmentPolicyError("launch_configuration_unresolved")
    verify_required_browser_cdp(preparation_environment, result.manifest)
    verify_required_browser_bidi(preparation_environment)
    baseline_path = normalize_measurement_baseline_path(
        workspace, controls.get("ROOKERY_MEASUREMENT_BASELINE_PATH")
    )
    try:
        baseline = verify_measurement_baseline(
            workspace,
            baseline_path,
            dict(result.manifest),
            verify_source_tree=existing_binding is None,
        )
    except MeasurementBaselineError as exc:
        raise EnvironmentPolicyError("measurement_baseline_invalid") from exc
    _selected_adapter_contract(workspace, result.manifest)
    browser_gateway = verify_required_browser_gateway(
        workspace,
        preparation_environment,
        result.manifest,
        baseline_configuration_digest=str(baseline["configuration_digest"]),
        parent=parent,
    )
    auth_mode = codex_auth_mode(workspace, parent=parent)
    immutable_digest = immutable_source_digest(workspace)
    environment_sha256, resolved_manifest_sha256 = _editable_configuration_digests(
        workspace,
        result.manifest,
    )
    # The login probe must observe exactly the environment later supplied to
    # Codex.  In environment-auth mode this includes only the explicitly named
    # provider/network keys; in local-login mode it contains no such authority.
    probe_environment = codex_launcher_environment(workspace, parent=parent)
    _executable, identity, version, strict_supported = _probe_codex(
        workspace,
        probe_environment,
        auth_mode=auth_mode,
        require_agent_config=True,
    )
    if auth_mode == "environment" and not strict_supported:
        raise EnvironmentPolicyError("codex_environment_auth_requires_strict_config")
    if immutable_source_digest(workspace) != immutable_digest:
        raise EnvironmentPolicyError("immutable_source_drift")
    if _editable_configuration_digests(workspace, result.manifest) != (
        environment_sha256,
        resolved_manifest_sha256,
    ):
        raise EnvironmentPolicyError("launch_configuration_drift")
    selected_extensions = tuple(str(item) for item in result.manifest.get("surface", {}).get("extensions", []) or [])
    gate = LaunchGate(
        manifest=result.manifest,
        result=result,
        workspace_identity=str(workspace),
        immutable_source_sha256=immutable_digest,
        environment_sha256=environment_sha256,
        resolved_manifest_sha256=resolved_manifest_sha256,
        baseline_path=baseline_path,
        core_environment=core_environment,
        preparation_environment=preparation_environment,
        stage_c_environments=stage_c_environments,
        baseline_sha256=str(baseline["sha256"]),
        baseline_configuration_digest=str(baseline["configuration_digest"]),
        measurement_contract=_measurement_contract(baseline["measurement_contract"]),
        release_version=str(baseline["release_version"]),
        selected_adapter=str(result.manifest["adapter"]["id"]),
        selected_extensions=selected_extensions,
        codex_executable=_executable,
        codex_identity=identity,
        codex_version=version,
        auth_mode=auth_mode,
        strict_config_supported=strict_supported,
        browser_gateway_policy_sha256=(browser_gateway.policy_sha256 if browser_gateway is not None else None),
        browser_gateway_expires_at=(browser_gateway.expires_at if browser_gateway is not None else None),
        browser_gateway_boot_nonce=(browser_gateway.boot_nonce if browser_gateway is not None else None),
    )
    if existing_binding is not None and dict(existing_binding.record) != _binding_record(gate):
        raise EnvironmentPolicyError("launch_binding_drift")
    # Probes are executable invocations, not a claim that the source is
    # read-only. Re-read source/config/baseline immediately before the caller
    # is allowed to publish its first durable record.
    _reverify_gate_inputs(gate)
    return gate


def _reject_launch_overrides(arguments: Sequence[str]) -> None:
    for index, argument in enumerate(arguments):
        if argument == "--strict-config" or argument.startswith("--strict-config="):
            raise EnvironmentPolicyError("direct strict-config overrides are forbidden")
        value: str | None = None
        if argument in {"-c", "--config"}:
            if index + 1 >= len(arguments):
                raise EnvironmentPolicyError("Codex config override is incomplete")
            value = arguments[index + 1]
        elif argument.startswith("--config="):
            value = argument.split("=", 1)[1]
        elif argument.startswith("-c") and len(argument) > 2:
            value = argument[2:]
        if value is not None and "shell_environment_policy" in value:
            raise EnvironmentPolicyError("direct shell_environment_policy overrides are forbidden")


def _verify_exec_binding(
    root: Path,
    child: ChildEnvironment,
    *,
    parent: Mapping[str, str] | None = None,
) -> LaunchBinding:
    binding = verify_launch_binding_integrity(root)
    _executable, identity, version, strict_supported = _probe_codex(
        root, child, auth_mode=str(binding.record["auth_mode"])
    )
    codex = binding.record["codex"]
    expected_identity = {key: identity[key] for key in ("path", "device", "inode", "size", "mtime_ns", "sha256")}
    if {key: codex[key] for key in expected_identity} != expected_identity:
        raise EnvironmentPolicyError("codex_executable_drift")
    if codex["version"] != version or bool(binding.record["strict_config_supported"]) != strict_supported:
        raise EnvironmentPolicyError("codex_capability_drift")
    if binding.record["auth_mode"] != codex_auth_mode(root, parent=parent):
        raise EnvironmentPolicyError("codex_auth_mode_drift")
    if binding.record["auth_mode"] == "environment" and not strict_supported:
        raise EnvironmentPolicyError("codex_environment_auth_requires_strict_config")
    # The last check is deliberately after all executable probes: a probe is
    # not assumed to be source/config read-only merely because it has no Rookery
    # write API.
    verified = verify_launch_binding_integrity(root)
    if verified.sha256 != binding.sha256:
        raise EnvironmentPolicyError("launch_binding_changed")
    return verified


def _open_verified_codex_descriptor(binding: LaunchBinding) -> int:
    """Open the exact bound executable and re-check it immediately before exec."""

    if os.name != "posix" or not Path("/proc/self/fd").is_dir():
        raise EnvironmentPolicyError("codex_descriptor_exec_unavailable")
    codex = binding.record["codex"]
    path = Path(str(codex["path"]))
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise EnvironmentPolicyError("codex_executable_drift") from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise EnvironmentPolicyError("codex_executable_drift")
        os.lseek(descriptor, 0, os.SEEK_SET)
        digest = _hash_open_regular_file(
            descriptor,
            opened,
            maximum=CODEX_EXECUTABLE_MAX_BYTES,
            label="codex_executable_drift",
        )
        current = {
            "path": str(path),
            "device": int(opened.st_dev),
            "inode": int(opened.st_ino),
            "size": int(opened.st_size),
            "mtime_ns": int(opened.st_mtime_ns),
            "sha256": digest,
        }
        if any(current[key] != codex[key] for key in current):
            raise EnvironmentPolicyError("codex_executable_drift")
        os.lseek(descriptor, 0, os.SEEK_SET)
        # Python opens descriptors non-inheritable by default.  The procfd path
        # is safe only while this descriptor stays open across exec.
        os.set_inheritable(descriptor, True)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _consume_launch_attempt_argument(arguments: Sequence[str], *, required: bool) -> tuple[str | None, list[str]]:
    """Consume exactly one private wrapper-to-launcher attempt argument."""

    values = list(arguments)
    positions = [index for index, value in enumerate(values) if value == LAUNCH_ATTEMPT_ARGUMENT]
    if any(value.startswith(f"{LAUNCH_ATTEMPT_ARGUMENT}=") for value in values):
        raise EnvironmentPolicyError("codex_launch_attempt_invalid")
    if not positions:
        if required:
            raise EnvironmentPolicyError("codex_launch_attempt_missing")
        return None, values
    if len(positions) != 1:
        raise EnvironmentPolicyError("codex_launch_attempt_invalid")
    position = positions[0]
    if position + 1 >= len(values):
        raise EnvironmentPolicyError("codex_launch_attempt_invalid")
    attempt_id = values[position + 1]
    if not _LAUNCH_ATTEMPT_ID_RE.fullmatch(attempt_id):
        raise EnvironmentPolicyError("codex_launch_attempt_invalid")
    return attempt_id, values[:position] + values[position + 2 :]


def _read_launch_attempt(path: Path) -> dict[str, Any]:
    """Descriptor-stably read the wrapper's private, bounded launch record."""

    try:
        observed = path.lstat()
    except OSError as exc:
        raise EnvironmentPolicyError("codex_launch_attempt_missing") from exc
    if (
        stat.S_ISLNK(observed.st_mode)
        or not stat.S_ISREG(observed.st_mode)
        or stat.S_IMODE(observed.st_mode) != 0o600
        or observed.st_size > CODEX_PROBE_MAX_OUTPUT_BYTES
    ):
        raise EnvironmentPolicyError("codex_launch_attempt_invalid")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise EnvironmentPolicyError("codex_launch_attempt_invalid") from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) != (
            observed.st_dev,
            observed.st_ino,
            observed.st_size,
            observed.st_mtime_ns,
        ):
            raise EnvironmentPolicyError("codex_launch_attempt_changed")
        raw = os.read(descriptor, CODEX_PROBE_MAX_OUTPUT_BYTES + 1)
    finally:
        os.close(descriptor)
    if len(raw) > CODEX_PROBE_MAX_OUTPUT_BYTES:
        raise EnvironmentPolicyError("codex_launch_attempt_invalid")
    try:
        record = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EnvironmentPolicyError("codex_launch_attempt_invalid") from exc
    if not isinstance(record, dict) or set(record) != {
        "schema_version",
        "attempt_id",
        "launch_binding_sha256",
        "stop_generation",
    }:
        raise EnvironmentPolicyError("codex_launch_attempt_invalid")
    if (
        record["schema_version"] != LAUNCH_ATTEMPT_SCHEMA_VERSION
        or not isinstance(record["attempt_id"], str)
        or not _LAUNCH_ATTEMPT_ID_RE.fullmatch(record["attempt_id"])
        or not isinstance(record["launch_binding_sha256"], str)
        or not _SHA256_RE.fullmatch(record["launch_binding_sha256"])
        or isinstance(record["stop_generation"], bool)
        or not isinstance(record["stop_generation"], int)
        or record["stop_generation"] < 0
    ):
        raise EnvironmentPolicyError("codex_launch_attempt_invalid")
    return record


def _verify_final_launch_attempt(
    workspace: Path,
    attempt_id: str,
    binding: LaunchBinding,
) -> None:
    """Verify canonical open-state truth while the mutation lock is held."""

    record = _read_launch_attempt(workspace / "state" / LAUNCH_ATTEMPT_NAME)
    if record["attempt_id"] != attempt_id or record["launch_binding_sha256"] != binding.sha256:
        raise EnvironmentPolicyError("codex_launch_attempt_stale")
    current_binding = verify_launch_binding_integrity(workspace)
    if current_binding.sha256 != binding.sha256:
        raise EnvironmentPolicyError("codex_launch_attempt_stale")

    database = workspace / "state" / "events.sqlite3"
    database_descriptor: int | None = None
    try:
        info = database.lstat()
        database_descriptor = os.open(
            database,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        opened = os.fstat(database_descriptor)
    except OSError as exc:
        raise EnvironmentPolicyError("codex_launch_attempt_state_unavailable") from exc
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) != 0o600
        or (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
            opened.st_mtime_ns,
        )
        != (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)
    ):
        os.close(database_descriptor)
        raise EnvironmentPolicyError("codex_launch_attempt_state_unavailable")
    try:
        connection = sqlite3.connect(f"{database.as_uri()}?mode=ro", uri=True, isolation_level=None)
        try:
            connection.execute("PRAGMA query_only=ON")
            connection.execute("BEGIN")
            metadata = {
                str(key): str(value)
                for key, value in connection.execute(
                    "SELECT key,value FROM meta WHERE key IN ('stop_generation','launch_binding_sha256')"
                ).fetchall()
            }
            control = connection.execute(
                "SELECT event_type,generation,actor,payload_json FROM events "
                "WHERE event_type IN ('control.stop','control.resume') "
                "ORDER BY seq DESC LIMIT 1"
            ).fetchone()
            connection.rollback()
        finally:
            connection.close()
        after = database.lstat()
        pinned = os.fstat(database_descriptor)
        if (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            pinned.st_dev,
            pinned.st_ino,
            pinned.st_size,
            pinned.st_mtime_ns,
        ) != (
            info.st_dev,
            info.st_ino,
            info.st_size,
            info.st_mtime_ns,
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
            opened.st_mtime_ns,
        ):
            raise EnvironmentPolicyError("codex_launch_attempt_state_changed")
    except sqlite3.Error as exc:
        raise EnvironmentPolicyError("codex_launch_attempt_state_unavailable") from exc
    except OSError as exc:
        raise EnvironmentPolicyError("codex_launch_attempt_state_changed") from exc
    finally:
        os.close(database_descriptor)
    try:
        current_generation = int(metadata["stop_generation"])
    except (KeyError, ValueError) as exc:
        raise EnvironmentPolicyError("codex_launch_attempt_state_unavailable") from exc
    resumed_open = control is None and current_generation == 0
    if control is not None:
        try:
            resume_payload = json.loads(str(control[3]))
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise EnvironmentPolicyError("codex_launch_attempt_state_unavailable") from exc
        resumed_open = control_resume_is_current(
            {
                "event_type": control[0],
                "generation": control[1],
                "actor": control[2],
                "payload": resume_payload,
            },
            stop_generation=current_generation,
        )
    if (
        metadata.get("launch_binding_sha256") != binding.sha256
        or current_generation != record["stop_generation"]
        or not resumed_open
    ):
        raise EnvironmentPolicyError("codex_launch_attempt_stale")


def codex_launcher_main(
    argv: Sequence[str] | None = None, *, root: Path | None = None, parent: Mapping[str, str] | None = None
) -> int:
    from .util import file_lock

    raw_arguments = list(argv if argv is not None else os.sys.argv[1:])
    workspace = (root or Path(__file__).resolve().parents[3]).resolve()
    try:
        attempt_id, arguments = _consume_launch_attempt_argument(
            raw_arguments,
            required=is_deployed_workspace(workspace),
        )
    except EnvironmentPolicyError:
        return 2
    _reject_launch_overrides(arguments)
    child = codex_launcher_environment(workspace, parent=parent)
    binding = _verify_exec_binding(workspace, child, parent=parent)
    descriptor = _open_verified_codex_descriptor(binding)
    executable = f"/proc/self/fd/{descriptor}"
    final_arguments = [executable]
    if binding.record["strict_config_supported"]:
        final_arguments.append("--strict-config")
    final_arguments.extend(arguments)
    try:
        if attempt_id is None:
            os.execve(executable, final_arguments, dict(child.values))
        else:
            with file_lock(workspace / "state" / "mutation.lock"):
                try:
                    _verify_final_launch_attempt(workspace, attempt_id, binding)
                except EnvironmentPolicyError:
                    return 2
                # The lock descriptor is non-inheritable.  A successful exec
                # closes it atomically with image replacement; a concurrent
                # stop cannot commit between this check and Codex exec.
                os.execve(executable, final_arguments, dict(child.values))
    finally:
        os.close(descriptor)
    return 127
