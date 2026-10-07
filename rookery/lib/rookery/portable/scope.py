from __future__ import annotations

import fnmatch
import hashlib
import ipaddress
import json
import os
import sqlite3
import stat
import urllib.parse
import urllib.request
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

from .environment import (
    CODEX_CONTROL_KEYS,
    EnvironmentPolicyError,
    _open_verified_codex_descriptor,
    is_deployed_workspace,
    read_declared_environment,
    verify_launch_binding_integrity,
)
from .manifest import UNKNOWN
from .manifest import resolve_manifest, validate_manifest
from .reducers import control_resume_is_current
from .util import canonical_json, file_lock, iso_now, parse_iso

HTTP_REDIRECT_CODES = frozenset({301, 302, 303, 307, 308})
DEFAULT_MAX_REDIRECTS = 5
MAX_REDIRECTS = 10
COMPILED_SCOPE_SCHEMA_VERSION = "2"
MAX_COMPILED_SCOPE_BYTES = 1024 * 1024
_CROSS_ORIGIN_SAFE_HEADERS = frozenset(
    {
        "accept",
        "accept-encoding",
        "accept-language",
        "cache-control",
        "range",
        "user-agent",
    }
)


@dataclass(frozen=True)
class ScopeDecision:
    allowed: bool
    reason: str
    kind: str
    target: str
    generation: int
    override_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ScopeAuthorityError(RuntimeError):
    """Value-free refusal for an unproven derived compiled-scope file."""


@dataclass(frozen=True)
class CompiledScopeBinding:
    """A canonical scope snapshot bound to generations and stable file bytes."""

    scope: dict[str, Any]
    scope_generation: int
    stop_generation: int
    file_sha256: str
    content_sha256: str
    launch_binding_sha256: str


def _scope_error() -> ScopeAuthorityError:
    return ScopeAuthorityError("canonical_compiled_scope_unavailable")


def _scope_digest(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _scope_normalized(scope: dict[str, Any]) -> dict[str, Any]:
    """Remove the publication timestamp from semantic compiled-scope equality."""

    return {name: value for name, value in scope.items() if name != "compiled_at"}


def _verified_launch_binding_sha256(root: Path) -> str:
    """Return the current launch identity or fail before derived scope use."""

    try:
        binding = verify_launch_binding_integrity(root)
    except EnvironmentPolicyError as exc:
        raise _scope_error() from exc
    if not _scope_digest(binding.sha256):
        raise _scope_error()
    if not is_deployed_workspace(root):
        # Non-deployed structural fixtures still require an explicitly
        # published test binding above. They cannot represent a public effect;
        # deployed scope admission additionally verifies the live Codex and
        # external measurement authority below.
        return binding.sha256
    descriptor: int | None = None
    try:
        from .baseline import verify_measurement_baseline

        descriptor = _open_verified_codex_descriptor(binding)
        controls = read_declared_environment(root, CODEX_CONTROL_KEYS).values
        baseline_value = controls.get("ROOKERY_MEASUREMENT_BASELINE_PATH")
        if not baseline_value:
            raise _scope_error()
        baseline_path = Path(str(baseline_value))
        if not baseline_path.is_absolute():
            baseline_path = root / baseline_path
        manifest = resolve_manifest(root)
        if manifest.errors or manifest.unresolved_required:
            raise _scope_error()
        baseline = verify_measurement_baseline(
            root,
            baseline_path,
            dict(manifest.manifest),
            verify_source_tree=False,
        )
        if (
            baseline["sha256"] != binding.record["baseline_sha256"]
            or baseline["configuration_digest"]
            != binding.record["baseline_configuration_digest"]
            or baseline["release_version"] != binding.record["release_version"]
        ):
            raise _scope_error()
    except (EnvironmentPolicyError, OSError, ValueError) as exc:
        raise _scope_error() from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
    return binding.sha256


def _stable_scope_bytes(path: Path) -> bytes:
    """Read one bounded regular scope file without accepting link/swap races."""

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        initial = os.lstat(path)
        if (
            not stat.S_ISREG(initial.st_mode)
            or initial.st_nlink != 1
            or not 0 < initial.st_size <= MAX_COMPILED_SCOPE_BYTES
        ):
            raise _scope_error()
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        signature = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
            before.st_nlink,
        )
        if signature != (
            initial.st_dev,
            initial.st_ino,
            initial.st_size,
            initial.st_mtime_ns,
            initial.st_ctime_ns,
            initial.st_nlink,
        ):
            raise _scope_error()
        chunks: list[bytes] = []
        remaining = before.st_size + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
        if len(raw) != before.st_size or signature != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
            after.st_nlink,
        ):
            raise _scope_error()
        return raw
    except OSError as exc:
        raise _scope_error() from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _scope_generations(root: Path) -> tuple[int, int, bool]:
    """Read scope/stop generations and canonical stopped state in one snapshot."""

    path = root / "state" / "events.sqlite3"
    try:
        info = os.lstat(path)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise _scope_error()
        connection = sqlite3.connect(
            f"{path.resolve().as_uri()}?mode=ro", uri=True, isolation_level=None
        )
    except (OSError, sqlite3.Error, ValueError) as exc:
        raise _scope_error() from exc
    try:
        connection.execute("PRAGMA query_only=ON")
        connection.execute("BEGIN")
        rows = connection.execute(
            "SELECT key,value FROM meta WHERE key IN ('scope_generation','stop_generation')"
        ).fetchall()
        stop_row = connection.execute(
            "SELECT event_type,actor,generation,payload_json FROM events "
            "WHERE event_type IN ('control.stop','control.resume') "
            "ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        values = {str(key): str(value) for key, value in rows}
        scope_generation = int(values["scope_generation"])
        stop_generation = int(values["stop_generation"])
        if scope_generation <= 0 or stop_generation < 0:
            raise _scope_error()
        connection.commit()
        stopped = False
        if stop_row is not None:
            if str(stop_row[0]) == "control.stop":
                stopped = True
            else:
                try:
                    resume_payload = json.loads(str(stop_row[3]))
                    resumed = control_resume_is_current(
                        {
                            "event_type": "control.resume",
                            "actor": str(stop_row[1]),
                            "generation": stop_row[2],
                            "payload": resume_payload,
                        },
                        stop_generation=stop_generation,
                    )
                except (TypeError, ValueError, json.JSONDecodeError):
                    resumed = False
                stopped = not resumed
        return scope_generation, stop_generation, stopped
    except (KeyError, ValueError, sqlite3.Error) as exc:
        connection.rollback()
        raise _scope_error() from exc
    finally:
        connection.close()


def _canonical_scope(root: Path, generation: int) -> dict[str, Any]:
    """Re-resolve the current bounded event manifest; never trust state JSON."""

    try:
        current = resolve_manifest(root)
        raw = _stable_scope_bytes(root / "state" / "resolved_event.json")
        stored_manifest = json.loads(raw.decode("utf-8"))
        stored = validate_manifest(stored_manifest)
        if (
            current.errors
            or current.unresolved_required
            or stored.errors
            or stored.unresolved_required
            or canonical_json(current.manifest) != canonical_json(stored.manifest)
        ):
            raise _scope_error()
        return compile_scope(stored.manifest, generation)
    except (OSError, UnicodeDecodeError, ValueError, TypeError, json.JSONDecodeError) as exc:
        raise _scope_error() from exc


def _load_compiled_scope_binding_locked(root: Path) -> CompiledScopeBinding:
    """Load only a scope file proven current while the scope writer is excluded."""

    launch_before = _verified_launch_binding_sha256(root)
    generation, stop_generation, stopped = _scope_generations(root)
    if stopped:
        raise _scope_error()
    expected_before = _canonical_scope(root, generation)
    raw = _stable_scope_bytes(root / "state" / "scope.json")
    try:
        stored = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise _scope_error() from exc
    if (
        not isinstance(stored, dict)
        or stored.get("schema_version") != COMPILED_SCOPE_SCHEMA_VERSION
        or stored.get("generation") != generation
        or not isinstance(stored.get("compiled_at"), str)
    ):
        raise _scope_error()
    # A second source compilation discriminates a manifest/profile/dotenv swap
    # while the derived file was being admitted.  The shared lock covers normal
    # scope publication; this catches writers that do not honor that protocol.
    expected_after = _canonical_scope(root, generation)
    launch_after = _verified_launch_binding_sha256(root)
    if (
        launch_before != launch_after
        or _scope_normalized(expected_before)
        != _scope_normalized(expected_after)
        or _scope_normalized(stored) != _scope_normalized(expected_after)
    ):
        raise _scope_error()
    return CompiledScopeBinding(
        scope=stored,
        scope_generation=generation,
        stop_generation=stop_generation,
        file_sha256=hashlib.sha256(raw).hexdigest(),
        content_sha256=hashlib.sha256(
            canonical_json(stored).encode("utf-8")
        ).hexdigest(),
        launch_binding_sha256=launch_after,
    )


def load_canonical_compiled_scope(root: Path) -> CompiledScopeBinding:
    """Return a schema-2 state scope only when it matches current authority.

    The shared lock is intentionally held only over the validation snapshot.
    Effects must carry this binding and recheck it immediately before spawning
    rather than retaining the lock across a long-running command.
    """

    try:
        with file_lock(root / "state" / "mutation.lock", exclusive=False):
            return _load_compiled_scope_binding_locked(root)
    except (OSError, ScopeAuthorityError):
        raise _scope_error() from None


def verify_canonical_compiled_scope_binding(
    root: Path,
    *,
    scope_generation: int,
    stop_generation: int,
    file_sha256: str,
    content_sha256: str,
    launch_binding_sha256: str,
) -> CompiledScopeBinding:
    """Recheck a planned scope/stop snapshot under one shared mutation lock."""

    if (
        isinstance(scope_generation, bool)
        or isinstance(stop_generation, bool)
        or not isinstance(scope_generation, int)
        or not isinstance(stop_generation, int)
        or not _scope_digest(file_sha256)
        or not _scope_digest(content_sha256)
        or not _scope_digest(launch_binding_sha256)
    ):
        raise _scope_error()
    try:
        with file_lock(root / "state" / "mutation.lock", exclusive=False):
            binding = _load_compiled_scope_binding_locked(root)
            if (
                binding.scope_generation != scope_generation
                or binding.stop_generation != stop_generation
                or binding.file_sha256 != file_sha256
                or binding.content_sha256 != content_sha256
                or binding.launch_binding_sha256 != launch_binding_sha256
            ):
                raise _scope_error()
            return binding
    except (OSError, ScopeAuthorityError):
        raise _scope_error() from None


def _verify_canonical_compiled_scope_binding_locked(
    root: Path,
    *,
    scope_generation: int,
    stop_generation: int,
    file_sha256: str,
    content_sha256: str,
    launch_binding_sha256: str,
) -> CompiledScopeBinding:
    binding = _load_compiled_scope_binding_locked(root)
    if (
        binding.scope_generation != scope_generation
        or binding.stop_generation != stop_generation
        or binding.file_sha256 != file_sha256
        or binding.content_sha256 != content_sha256
        or binding.launch_binding_sha256 != launch_binding_sha256
    ):
        raise _scope_error()
    return binding


@contextmanager
def verified_canonical_scope_effect(
    root: Path,
    *,
    scope_generation: int,
    stop_generation: int,
    file_sha256: str,
    content_sha256: str,
    launch_binding_sha256: str,
):
    """Exclude scope/stop rotation across a bound command's process handoff.

    This context is deliberately for the narrow pre-spawn interval only.  It
    must not surround command execution: that would block ``./go stop`` and
    scope rotation for the lifetime of an untrusted or slow child.
    """

    if (
        isinstance(scope_generation, bool)
        or isinstance(stop_generation, bool)
        or not isinstance(scope_generation, int)
        or not isinstance(stop_generation, int)
        or not _scope_digest(file_sha256)
        or not _scope_digest(content_sha256)
        or not _scope_digest(launch_binding_sha256)
    ):
        raise _scope_error()
    try:
        with file_lock(root / "state" / "mutation.lock", exclusive=False):
            yield _verify_canonical_compiled_scope_binding_locked(
                root,
                scope_generation=scope_generation,
                stop_generation=stop_generation,
                file_sha256=file_sha256,
                content_sha256=content_sha256,
                launch_binding_sha256=launch_binding_sha256,
            )
    except (OSError, ScopeAuthorityError):
        raise _scope_error() from None


def default_port_for_scheme(scheme: str) -> int:
    """Return the only implicit port for a supported URL scheme."""

    ports = {"http": 80, "https": 443, "ssh": 22, "ws": 80, "wss": 443}
    try:
        return ports[scheme.casefold()]
    except KeyError as exc:
        raise ValueError("unsupported URL scheme") from exc


def canonical_hostname(host: str) -> str:
    """Canonicalize an IP literal or DNS name without touching the resolver."""

    if not isinstance(host, str):
        raise ValueError("host is invalid")
    value = host.strip()
    if not value or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        raise ValueError("host is invalid")
    if "%" in value:
        raise ValueError("IPv6 zone identifiers are not supported")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    if value.endswith("."):
        value = value[:-1]
    if not value or value.endswith(".") or "/" in value or "@" in value:
        raise ValueError("host is invalid")
    try:
        canonical = value.encode("idna").decode("ascii").casefold()
    except UnicodeError as exc:
        raise ValueError("host is invalid") from exc
    if not canonical or len(canonical) > 253 or any(
        not label or len(label) > 63 for label in canonical.split(".")
    ):
        raise ValueError("host is invalid")
    return canonical


def _canonical_host_pattern(pattern: object) -> str | None:
    """Normalize an ASCII shell pattern without turning it into an authority."""

    if not isinstance(pattern, str):
        return None
    value = pattern.strip()
    if not value:
        return None
    if not any(token in value for token in "*?["):
        try:
            return canonical_hostname(value)
        except ValueError:
            return None
    # Scope compilation writes canonical patterns, but this pure guard also
    # receives existing in-memory and test scopes.  Retain the documented one
    # trailing-dot normalization for shell patterns without accepting a second
    # empty DNS label.
    if value.endswith("."):
        value = value[:-1]
    if not value or value.endswith(".") or not value.isascii() or any(
        ord(character) < 0x20 or ord(character) == 0x7F for character in value
    ):
        return None
    return value.casefold()


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def _host_pattern_matches(host: str, patterns: list[object]) -> bool:
    return any(
        pattern is not None and fnmatch.fnmatchcase(host, pattern)
        for item in patterns
        if (pattern := _canonical_host_pattern(item)) is not None
    )


def _active_overrides(overrides: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    from datetime import datetime, timezone

    active: list[dict[str, Any]] = []
    for override in overrides or []:
        expires = parse_iso(override.get("expires_at"))
        if expires is not None and datetime.now(timezone.utc) < expires:
            active.append(override)
    return active


def _cidr_matches(address: ipaddress._BaseAddress, cidrs: list[object]) -> bool:
    for value in cidrs:
        try:
            if address in ipaddress.ip_network(str(value), strict=False):
                return True
        except ValueError:
            continue
    return False


_NAT64_PREFIXES = (
    ipaddress.IPv6Network("64:ff9b::/96"),
    ipaddress.IPv6Network("64:ff9b:1::/48"),
)
_IPV4_SPECIAL_NETWORKS = (
    ipaddress.IPv4Network("100.64.0.0/10"),  # shared address space
    ipaddress.IPv4Network("192.0.2.0/24"),  # documentation
    ipaddress.IPv4Network("198.18.0.0/15"),  # benchmarking
    ipaddress.IPv4Network("198.51.100.0/24"),  # documentation
    ipaddress.IPv4Network("203.0.113.0/24"),  # documentation
)
_SIX_TO_FOUR_PREFIX = ipaddress.IPv6Network("2002::/16")
_IPV6_TRANSITION_PREFIXES = (
    ipaddress.IPv6Network("2001::/32"),  # Teredo
    ipaddress.IPv6Network("2001:10::/28"),  # ORCHIDv2
    ipaddress.IPv6Network("2001:20::/28"),  # ORCHID
)


def _embedded_ipv4(address: ipaddress.IPv6Address) -> ipaddress.IPv4Address | None:
    if address.ipv4_mapped is not None:
        return address.ipv4_mapped
    if address in _NAT64_PREFIXES[0]:
        return ipaddress.IPv4Address(int(address) & 0xFFFFFFFF)
    if address in _NAT64_PREFIXES[1]:
        # RFC 6052 /48 layout: |prefix(48)|v4[0:16]|u(8)|v4[16:32]|
        # suffix(40)|.  It is not a contiguous 32-bit field.  Hex groups
        # h3:h4:h5 therefore carry v4[0:16], u|v4[16:24],
        # v4[24:32]|suffix respectively.
        groups = tuple(int(part, 16) for part in address.exploded.split(":"))
        h3, h4, h5, h6, h7 = groups[3:]
        if h4 >> 8 or h5 & 0x00FF or h6 or h7:
            raise ValueError("RFC6052 /48 representation is malformed")
        return ipaddress.IPv4Address(
            bytes((h3 >> 8, h3 & 0xFF, h4 & 0xFF, h5 >> 8))
        )
    if address in _SIX_TO_FOUR_PREFIX:
        return ipaddress.IPv4Address((int(address) >> 80) & 0xFFFFFFFF)
    return None


def _requires_explicit_cidr(address: ipaddress._BaseAddress) -> bool:
    """Fail closed for every non-global or reviewed transition representation."""

    if (
        address.is_unspecified
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_private
        or address.is_reserved
    ):
        return True
    if isinstance(address, ipaddress.IPv4Address) and any(
        address in network for network in _IPV4_SPECIAL_NETWORKS
    ):
        return True
    if isinstance(address, ipaddress.IPv6Address):
        if address.ipv4_mapped is not None:
            return True
        if any(address in prefix for prefix in (*_NAT64_PREFIXES, *_IPV6_TRANSITION_PREFIXES, _SIX_TO_FOUR_PREFIX)):
            return True
    # ``is_global`` is intentionally the allow property: uncertain and special
    # classifications stay false and therefore require an explicit CIDR.
    return not address.is_global


def _resolved_address_allowed(
    scope: dict[str, Any],
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
    *,
    overrides: list[dict[str, Any]] | None,
) -> tuple[bool, str]:
    active = _active_overrides(overrides)
    cidrs: list[object] = list(scope.get("allowed_cidrs", []))
    for override in active:
        cidrs.extend(list(override.get("allowed_cidrs", [])))
    try:
        embedded = (
            _embedded_ipv4(address)
            if isinstance(address, ipaddress.IPv6Address)
            else None
        )
    except ValueError:
        return False, "resolved address representation is invalid"
    needs_cidr = _requires_explicit_cidr(address) or (
        embedded is not None and _requires_explicit_cidr(embedded)
    )
    if not needs_cidr:
        return True, "global resolved address"
    # Mapped/translation forms must be explicitly approved as the actual wire
    # address and, where applicable, as their decoded IPv4 authority.  A broad
    # NAT64 prefix alone must never silently re-enable metadata access.
    if not _cidr_matches(address, cidrs):
        return False, "resolved address requires an explicit CIDR"
    if (
        embedded is not None
        and _requires_explicit_cidr(embedded)
        and not _cidr_matches(embedded, cidrs)
    ):
        return False, "resolved address requires an explicit CIDR"
    return True, "explicit resolved CIDR"


def check_resolved_addresses(
    scope: dict[str, Any],
    host: str,
    addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address],
    *,
    overrides: list[dict[str, Any]] | None = None,
) -> ScopeDecision:
    """Authorize a complete DNS answer set without performing network I/O."""

    generation = int(scope.get("generation", 0))
    if reason := _base_guard(scope):
        return ScopeDecision(False, reason, "resolved-address", host, generation)
    if not addresses:
        return ScopeDecision(False, "DNS answer set is empty", "resolved-address", host, generation)
    for address in addresses:
        allowed, reason = _resolved_address_allowed(scope, address, overrides=overrides)
        if not allowed:
            return ScopeDecision(False, reason, "resolved-address", host, generation)
    return ScopeDecision(True, "resolved addresses are authorized", "resolved-address", host, generation)


def compile_scope(manifest: dict[str, Any], generation: int = 1) -> dict[str, Any]:
    src = manifest.get("scope", {})
    def patterns(values: object) -> list[str]:
        if not isinstance(values, list):
            raise ValueError("scope host patterns must be an array")
        compiled: list[str] = []
        for value in values:
            normalized = _canonical_host_pattern(value)
            if normalized is None:
                raise ValueError("scope contains an invalid host pattern")
            compiled.append(normalized)
        return compiled

    return {
        "schema_version": COMPILED_SCOPE_SCHEMA_VERSION,
        "generation": int(generation),
        "compiled_at": iso_now(),
        "acknowledged": bool(src.get("acknowledged", False)),
        "allowed_hosts": patterns(src.get("allowed_hosts", [])),
        "allowed_cidrs": list(src.get("allowed_cidrs", [])),
        "allowed_ports": [int(x) for x in src.get("allowed_ports", [])],
        "allowed_protocols": [str(x).lower() for x in src.get("allowed_protocols", [])],
        "allowed_file_origins": list(src.get("allowed_file_origins", [])),
        "platform_hosts": patterns(src.get("platform_hosts", [])),
        "max_attachment_bytes": int(src.get("max_attachment_bytes", 0) or 0),
        "expires_at": src.get("expires_at", UNKNOWN),
    }


def _base_guard(scope: dict[str, Any]) -> str | None:
    if not scope.get("acknowledged"):
        return "event scope is unresolved or not acknowledged"
    expires = parse_iso(scope.get("expires_at"))
    if expires is not None:
        from datetime import datetime, timezone

        if datetime.now(timezone.utc) >= expires:
            return "event scope has expired"
    return None


def check_host(
    scope: dict[str, Any],
    host: str,
    *,
    port: int | None = None,
    protocol: str | None = None,
    platform: bool = False,
    overrides: list[dict[str, Any]] | None = None,
) -> ScopeDecision:
    generation = int(scope.get("generation", 0))
    if reason := _base_guard(scope):
        return ScopeDecision(False, reason, "host", host, generation)
    try:
        canonical_host = canonical_hostname(host)
    except ValueError as exc:
        return ScopeDecision(False, str(exc), "host", host, generation)
    literal = _is_ip_literal(canonical_host)
    hosts = (
        list(scope.get("platform_hosts", []))
        if platform
        else list(scope.get("allowed_hosts", []))
    )
    active = _active_overrides(overrides)
    for override in active:
        override_hosts = list(override.get("allowed_hosts", []))
        override_cidrs = list(override.get("allowed_cidrs", []))
        host_allowed = _host_pattern_matches(canonical_host, override_hosts)
        cidr_allowed = (
            _cidr_matches(ipaddress.ip_address(canonical_host), override_cidrs)
            if literal
            else False
        )
        if (host_allowed and not literal) or (
            literal
            and cidr_allowed
            and (not platform or _host_pattern_matches(canonical_host, hosts))
        ):
            return ScopeDecision(
                True,
                "narrow expiring override",
                "host",
                canonical_host,
                generation,
                str(override.get("id", "")),
            )
    host_allowed = _host_pattern_matches(canonical_host, hosts)
    cidr_allowed = (
        _cidr_matches(ipaddress.ip_address(canonical_host), list(scope.get("allowed_cidrs", [])))
        if literal
        else False
    )
    # A numeric literal is never reclassified as a DNS label by a wildcard.
    # Platform literals retain their platform namespace in addition to CIDR
    # authorization; ordinary literals require only their explicit CIDR.
    if (not literal and not host_allowed) or (
        literal and not cidr_allowed
    ) or (literal and platform and not host_allowed):
        return ScopeDecision(
            False, "host is outside declared scope", "host", canonical_host, generation
        )
    ports = list(scope.get("allowed_ports", []))
    if port is not None and ports and int(port) not in ports:
        return ScopeDecision(
            False,
            "port is outside declared scope",
            "host",
            f"{canonical_host}:{port}",
            generation,
        )
    protocols = list(scope.get("allowed_protocols", []))
    if protocol and protocols and protocol.lower() not in protocols:
        return ScopeDecision(
            False,
            "protocol is outside declared scope",
            "host",
            f"{protocol}://{canonical_host}",
            generation,
        )
    return ScopeDecision(True, "declared scope", "host", canonical_host, generation)


def check_url(
    scope: dict[str, Any],
    url: str,
    *,
    platform: bool = False,
    overrides: list[dict[str, Any]] | None = None,
) -> ScopeDecision:
    generation = int(scope.get("generation", 0))
    try:
        parsed = urllib.parse.urlsplit(url)
        host = parsed.hostname or ""
        port = parsed.port
    except ValueError:
        return ScopeDecision(False, "invalid URL", "url", url, generation)
    scheme = parsed.scheme.casefold()
    if scheme not in {"http", "https", "ssh", "tcp", "udp", "ws", "wss"}:
        return ScopeDecision(
            False, "unsupported URL scheme", "url", url, generation
        )
    if scheme in {"http", "https", "ws", "wss"} and (
        parsed.username is not None or parsed.password is not None
    ):
        return ScopeDecision(
            False, "credentialed URLs are not allowed", "url", url, generation
        )
    if port is not None and not 1 <= port <= 65535:
        return ScopeDecision(False, "invalid URL", "url", url, generation)
    if port is None:
        try:
            port = default_port_for_scheme(scheme)
        except ValueError:
            return ScopeDecision(False, "URL port is required", "url", url, generation)
    result = check_host(
        scope,
        host,
        port=port,
        protocol=scheme,
        platform=platform,
        overrides=overrides,
    )
    return ScopeDecision(
        result.allowed, result.reason, "url", url, result.generation, result.override_id
    )


def normalize_file_origin(origin: str) -> str:
    """Return one canonical workspace-relative POSIX attachment path."""

    if not isinstance(origin, str) or not origin:
        raise ValueError("file origin must be a non-empty workspace-relative path")
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in origin):
        raise ValueError("file origin contains control characters")
    if "\\" in origin:
        raise ValueError("file origin must use POSIX separators, not backslashes")
    posix = PurePosixPath(origin)
    windows = PureWindowsPath(origin)
    if posix.is_absolute() or windows.is_absolute() or windows.drive:
        raise ValueError("file origin must be workspace-relative, not absolute")
    raw_parts = origin.split("/")
    if ".." in raw_parts:
        raise ValueError("file origin contains traversal components")
    normalized = posix.as_posix()
    if normalized in {"", "."}:
        raise ValueError("file origin must name a file below the workspace")
    if any(part in {"", ".", ".."} for part in PurePosixPath(normalized).parts):
        raise ValueError("file origin is not a normalized relative POSIX path")
    return normalized


def _normalized_origin_for_match(origin: str) -> tuple[str, bool]:
    parsed = urllib.parse.urlsplit(origin)
    if "://" in origin and parsed.scheme:
        if parsed.scheme.casefold() == "file":
            raise ValueError("file URL origins are not allowed")
        return origin, False
    return normalize_file_origin(origin), True


def check_file_origin(
    scope: dict[str, Any], origin: str, *, size: int | None = None
) -> ScopeDecision:
    generation = int(scope.get("generation", 0))
    if reason := _base_guard(scope):
        return ScopeDecision(False, reason, "file", origin, generation)
    max_bytes = int(scope.get("max_attachment_bytes", 0) or 0)
    if size is not None and (max_bytes <= 0 or int(size) > max_bytes):
        return ScopeDecision(
            False, "attachment exceeds declared byte bound", "file", origin, generation
        )
    try:
        normalized, is_local = _normalized_origin_for_match(origin)
    except ValueError as exc:
        return ScopeDecision(False, str(exc), "file", origin, generation)
    allowed = list(scope.get("allowed_file_origins", []))
    matched = False
    for pattern in allowed:
        pattern_text = str(pattern)
        if is_local:
            try:
                normalized_pattern = normalize_file_origin(pattern_text)
            except ValueError:
                continue
        else:
            normalized_pattern = pattern_text
        if fnmatch.fnmatchcase(normalized, normalized_pattern):
            matched = True
            break
    if not matched:
        return ScopeDecision(
            False,
            "file origin is outside declared scope",
            "file",
            normalized,
            generation,
        )
    return ScopeDecision(True, "declared file origin", "file", normalized, generation)


def _url_origin(url: str) -> tuple[str, str, int]:
    parsed = urllib.parse.urlsplit(url)
    host = canonical_hostname(parsed.hostname or "")
    port = parsed.port
    if port is None:
        port = default_port_for_scheme(parsed.scheme.casefold())
    return parsed.scheme.casefold(), host, port


def _request_headers(
    request: urllib.request.Request, *, strip_sensitive: bool
) -> dict[str, str]:
    headers = dict(request.unredirected_hdrs)
    headers.update(request.headers)
    if strip_sensitive:
        headers = {
            name: value
            for name, value in headers.items()
            if name.casefold() in _CROSS_ORIGIN_SAFE_HEADERS
        }
    return headers


def _has_header(request: urllib.request.Request, target: str) -> bool:
    return any(
        name.casefold() == target
        for name in (*request.unredirected_hdrs, *request.headers)
    )


def _scoped_http_decision(
    scope: dict[str, Any],
    url: str,
    *,
    platform: bool,
    overrides: list[dict[str, Any]] | None,
    attachment: bool,
) -> ScopeDecision:
    generation = int(scope.get("generation", 0))
    try:
        parsed = urllib.parse.urlsplit(url)
        _ = parsed.port
    except ValueError as exc:
        return ScopeDecision(False, f"invalid URL: {exc}", "url", url, generation)
    if parsed.scheme not in {"http", "https"}:
        return ScopeDecision(
            False,
            "attachment transport requires HTTP or HTTPS",
            "url",
            url,
            generation,
        )
    decision = check_url(scope, url, platform=platform, overrides=overrides)
    if not decision.allowed or not attachment:
        return decision
    file_decision = check_file_origin(scope, url)
    return ScopeDecision(
        file_decision.allowed,
        file_decision.reason,
        "url",
        url,
        file_decision.generation,
        file_decision.override_id,
    )


class _EndpointAwareTestTransport:
    """Private deterministic response sequence for scope redirect unit tests.

    It owns no resolver, socket, redirect handler, or callback surface.  Test
    code can exercise the outer redirect/header policy only by supplying fixed
    already-created responses; production accepts no arbitrary ``open``
    object.
    """

    def __init__(self, responses: list[Any]) -> None:
        self._responses = list(responses)
        self.requests: list[urllib.request.Request] = []

    def open(self, request: urllib.request.Request, *, timeout: float) -> Any:
        del timeout
        index = len(self.requests)
        if index >= len(self._responses):
            raise RuntimeError("test transport response sequence exhausted")
        self.requests.append(request)
        return self._responses[index]


def open_scoped_url(
    scope: dict[str, Any],
    url_or_request: str | urllib.request.Request,
    *,
    timeout: float = 30,
    platform: bool = False,
    overrides: list[dict[str, Any]] | None = None,
    max_redirects: int = DEFAULT_MAX_REDIRECTS,
    attachment: bool = False,
    transport: Any = None,
    _test_transport: _EndpointAwareTestTransport | None = None,
) -> Any:
    """Open direct HTTP(S), pinning each authorized DNS answer to its socket.

    Production consumers must provide the exact reviewed
    :class:`ScopedHTTPTransport` (usually from an explicit network policy) or
    use the direct default.  Generic urllib openers are deliberately rejected
    because they can resolve a hostname after scope admission.  The private
    response-sequence parameter exists only for deterministic unit tests.
    """

    if timeout <= 0:
        raise ValueError("HTTP timeout must be positive")
    if max_redirects < 0 or max_redirects > MAX_REDIRECTS:
        raise ValueError("HTTP redirect bound is outside the supported range")
    if isinstance(url_or_request, urllib.request.Request):
        request = url_or_request
    else:
        request = urllib.request.Request(str(url_or_request))
    if transport is not None and _test_transport is not None:
        raise TypeError("scoped transport selection is ambiguous")
    if _test_transport is not None:
        if type(_test_transport) is not _EndpointAwareTestTransport:
            raise TypeError("scoped test transport is invalid")
        selected_transport: Any = _test_transport
    else:
        from .network_policy import system_trust_context
        from .scoped_transport import ScopedHTTPTransport

        if transport is None:
            transport = ScopedHTTPTransport(
                scope,
                system_trust_context(),
                platform=platform,
                overrides=overrides,
            )
        if type(transport) is not ScopedHTTPTransport:
            raise TypeError("scoped transport must be the reviewed pinned transport")
        selected_transport = transport
    redirects = 0
    while True:
        current_url = request.full_url
        if _has_header(request, "host"):
            raise RuntimeError("custom Host headers are not allowed for scoped HTTP")
        decision = _scoped_http_decision(
            scope,
            current_url,
            platform=platform,
            overrides=overrides,
            attachment=attachment,
        )
        if not decision.allowed:
            raise RuntimeError(f"HTTP request blocked by scope: {decision.reason}")
        try:
            response = selected_transport.open(request, timeout=timeout)
        except RuntimeError:
            raise
        status = getattr(response, "status", None)
        if status is None:
            status = response.getcode()
        if status not in HTTP_REDIRECT_CODES:
            return response
        if request.get_method().upper() not in {"GET", "HEAD"}:
            response.close()
            raise RuntimeError("HTTP redirect rejected for non-idempotent request")
        location = response.headers.get("Location") if response.headers else None
        if not location:
            response.close()
            raise RuntimeError("HTTP redirect is missing a Location header")
        if redirects >= max_redirects:
            response.close()
            raise RuntimeError("HTTP redirect limit exceeded")
        redirected_url = urllib.parse.urljoin(current_url, location)
        current_origin = _url_origin(current_url)
        try:
            redirected_origin = _url_origin(redirected_url)
        except ValueError as exc:
            response.close()
            raise RuntimeError(f"HTTP redirect has an invalid URL: {exc}") from exc
        if current_origin[0] == "https" and redirected_origin[0] == "http":
            response.close()
            raise RuntimeError("HTTPS redirect downgrade is not allowed")
        redirect_decision = _scoped_http_decision(
            scope,
            redirected_url,
            platform=platform,
            overrides=overrides,
            attachment=attachment,
        )
        if not redirect_decision.allowed:
            response.close()
            raise RuntimeError(
                f"HTTP redirect blocked by scope: {redirect_decision.reason}"
            )
        headers = _request_headers(
            request, strip_sensitive=current_origin != redirected_origin
        )
        method = request.get_method().upper()
        response.close()
        request = urllib.request.Request(
            redirected_url,
            headers=headers,
            method=method,
        )
        redirects += 1


def check_cidr(scope: dict[str, Any], cidr: str) -> ScopeDecision:
    generation = int(scope.get("generation", 0))
    if reason := _base_guard(scope):
        return ScopeDecision(False, reason, "cidr", cidr, generation)
    try:
        requested = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return ScopeDecision(False, "invalid network", "cidr", cidr, generation)
    for value in scope.get("allowed_cidrs", []):
        try:
            allowed = ipaddress.ip_network(value, strict=False)
        except ValueError:
            continue
        if requested.version != allowed.version:
            continue
        if requested.subnet_of(allowed):
            return ScopeDecision(True, "declared CIDR scope", "cidr", cidr, generation)
    return ScopeDecision(
        False, "network is outside declared scope", "cidr", cidr, generation
    )
