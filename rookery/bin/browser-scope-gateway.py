#!/usr/bin/env -S python3 -I -S -B
"""Loopback-only CONNECT gateway for one sealed browser platform origin.

Chrome keeps its TLS session end to end.  This process only verifies the
CONNECT authority, resolves it once under Rookery's compiled-scope rules, and
relays opaque bytes to the resulting numeric peer.
"""

from __future__ import annotations

import argparse
import copy
import ipaddress
import json
import logging
import os
import secrets
import selectors
import socket
import socketserver
import stat
import sys
import threading
import time
import urllib.parse
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


if sys.version_info < (3, 11):
    raise SystemExit(2)

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from rookery.portable.scope import (  # noqa: E402
    canonical_hostname,
    check_url,
)
from rookery.portable.browser_gateway_policy import (  # noqa: E402
    BrowserGatewayPolicyError,
    canonical_gateway_origin,
    policy_sha256,
    scope_sha256,
)
from rookery.portable.scoped_transport import (  # noqa: E402
    ScopedConnectionPlan,
    connect_scoped_stream,
    resolve_scoped_addresses,
)
from rookery.portable.util import canonical_json, parse_iso  # noqa: E402


LOGGER = logging.getLogger("rookery.browser_scope_gateway")
POLICY_SCHEMA_VERSION = "1"
STATUS_SCHEMA_VERSION = "1"
LOOPBACK_HOST = "127.0.0.1"
DEFAULT_PROXY_PORT = 9002
DEFAULT_STATUS_PORT = 9003
MAX_POLICY_BYTES = 2 * 1024 * 1024
MAX_EVENT_ID_BYTES = 256
MAX_ORIGINS = 9
MAX_HEADER_BYTES = 8 * 1024
MAX_HEADERS = 64
MAX_INITIAL_BUFFER_BYTES = MAX_HEADER_BYTES + 4096
MAX_CONNECTIONS = 8
MAX_TUNNEL_BYTES = 8 * 1024 * 1024
CONNECT_TIMEOUT_SECONDS = 10.0
IDLE_TIMEOUT_SECONDS = 30.0
LIFETIME_SECONDS = 300.0
IO_CHUNK_BYTES = 16 * 1024


class GatewayError(RuntimeError):
    """A stable, value-free gateway refusal."""


class GatewayPolicyError(GatewayError):
    """A policy does not establish one safe gateway authority."""


@dataclass(frozen=True)
class SealedPolicy:
    """Validated, copied policy retained only in the gateway process."""

    event_id: str
    baseline_configuration_digest: str
    scope_generation: int
    scope_sha256: str
    expires_at: str
    expires_timestamp: float
    origin: str
    host: str
    origins: tuple[str, ...]
    hosts: frozenset[str]
    scope: dict[str, Any]
    policy_sha256: str


class GatewayCounters:
    """Thread-safe, value-free totals suitable for loopback status."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._values = {
            "accepted": 0,
            "refused": 0,
            "connected": 0,
            "completed": 0,
            "failed": 0,
            "bytes": 0,
        }

    def add(self, name: str, amount: int = 1) -> None:
        with self._lock:
            self._values[name] += amount

    def snapshot(self) -> dict[str, int]:
        with self._lock:
            return dict(self._values)


def _is_digest(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(character in "0123456789abcdef" for character in value)


def _contains_control(value: str) -> bool:
    return any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)


def _file_signature(info: os.stat_result) -> tuple[int, ...]:
    """Compare regular-file identity without Windows' open-time ctime rewrite."""

    values = (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_nlink)
    return values if os.name == "nt" else (*values, info.st_ctime_ns)


def _private_policy_bytes(value: Path) -> bytes:
    """Read one bounded regular policy file without following a link or swap."""

    if not value.is_absolute():
        raise GatewayPolicyError("browser_gateway_policy_path_invalid")
    try:
        initial = os.lstat(value)
    except OSError as exc:
        raise GatewayPolicyError("browser_gateway_policy_unavailable") from exc
    if (
        not stat.S_ISREG(initial.st_mode)
        or stat.S_ISLNK(initial.st_mode)
        or initial.st_size <= 0
        or initial.st_size > MAX_POLICY_BYTES
        or initial.st_nlink != 1
    ):
        raise GatewayPolicyError("browser_gateway_policy_invalid")
    if os.name == "posix" and stat.S_IMODE(initial.st_mode) & 0o077:
        raise GatewayPolicyError("browser_gateway_policy_private_mode_required")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_BINARY", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(value, flags)
        before = os.fstat(descriptor)
        signature = _file_signature(before)
        if signature != _file_signature(initial):
            raise GatewayPolicyError("browser_gateway_policy_invalid")
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
        if len(raw) != before.st_size or signature != _file_signature(after):
            raise GatewayPolicyError("browser_gateway_policy_invalid")
        return raw
    except GatewayPolicyError:
        raise
    except OSError as exc:
        raise GatewayPolicyError("browser_gateway_policy_unavailable") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _origin(value: object) -> tuple[str, str]:
    try:
        origin = canonical_gateway_origin(value)
        host = urllib.parse.urlsplit(origin).hostname
    except (BrowserGatewayPolicyError, UnicodeError, ValueError) as exc:
        raise GatewayPolicyError("browser_gateway_policy_invalid") from exc
    if not host:
        raise GatewayPolicyError("browser_gateway_policy_invalid")
    return origin, host


def _expiry(value: object) -> tuple[str, float]:
    if not isinstance(value, str) or value == "unknown":
        raise GatewayPolicyError("browser_gateway_policy_invalid")
    parsed = parse_iso(value)
    if parsed is None or parsed <= datetime.now(UTC):
        raise GatewayPolicyError("browser_gateway_policy_expired")
    return value, parsed.timestamp()


def _load_policy(path: Path) -> SealedPolicy:
    raw = _private_policy_bytes(path)
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GatewayPolicyError("browser_gateway_policy_invalid") from exc
    if not isinstance(document, dict) or set(document) != {
        "schema_version",
        "event_id",
        "baseline_configuration_digest",
        "scope_generation",
        "scope_sha256",
        "expires_at",
        "origins",
        "scope",
    }:
        raise GatewayPolicyError("browser_gateway_policy_invalid")
    event_id = document["event_id"]
    baseline = document["baseline_configuration_digest"]
    generation = document["scope_generation"]
    claimed_scope_sha = document["scope_sha256"]
    origins = document["origins"]
    scope = document["scope"]
    if (
        document["schema_version"] != POLICY_SCHEMA_VERSION
        or not isinstance(event_id, str)
        or not event_id
        or len(event_id.encode("utf-8")) > MAX_EVENT_ID_BYTES
        or _contains_control(event_id)
        or not _is_digest(baseline)
        or isinstance(generation, bool)
        or not isinstance(generation, int)
        or generation <= 0
        or not _is_digest(claimed_scope_sha)
        or not isinstance(origins, list)
        or not 1 <= len(origins) <= MAX_ORIGINS
        or not isinstance(scope, dict)
    ):
        raise GatewayPolicyError("browser_gateway_policy_invalid")
    expires_at, expires_timestamp = _expiry(document["expires_at"])
    normalized_origins: list[str] = []
    hosts: set[str] = set()
    for value in origins:
        origin_value, host_value = _origin(value)
        if value != origin_value or origin_value in normalized_origins or host_value in hosts:
            raise GatewayPolicyError("browser_gateway_policy_invalid")
        normalized_origins.append(origin_value)
        hosts.add(host_value)
    origin, host = normalized_origins[0], urllib.parse.urlsplit(normalized_origins[0]).hostname
    if not host:
        raise GatewayPolicyError("browser_gateway_policy_invalid")
    sealed_scope = copy.deepcopy(scope)
    if (
        sealed_scope.get("schema_version") != "2"
        or sealed_scope.get("generation") != generation
        or sealed_scope.get("expires_at") != expires_at
        or scope_sha256(sealed_scope) != claimed_scope_sha
    ):
        raise GatewayPolicyError("browser_gateway_policy_mismatch")
    for allowed_origin in normalized_origins:
        decision = check_url(sealed_scope, allowed_origin + "/", platform=True)
        if not decision.allowed:
            raise GatewayPolicyError("browser_gateway_policy_scope_denied")
    return SealedPolicy(
        event_id=event_id,
        baseline_configuration_digest=baseline,
        scope_generation=generation,
        scope_sha256=claimed_scope_sha,
        expires_at=expires_at,
        expires_timestamp=expires_timestamp,
        origin=origin,
        host=host,
        origins=tuple(normalized_origins),
        hosts=frozenset(hosts),
        scope=sealed_scope,
        policy_sha256=policy_sha256(document),
    )


def _port(value: str) -> int:
    try:
        port = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("port must be an integer") from exc
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("port must be between 1 and 65535")
    return port


def _read_proxy_headers(client: socket.socket) -> tuple[bytes, bytes]:
    """Return bounded HTTP headers and any opaque bytes received after them."""

    data = bytearray()
    while len(data) < MAX_INITIAL_BUFFER_BYTES:
        chunk = client.recv(min(4096, MAX_INITIAL_BUFFER_BYTES - len(data)))
        if not chunk:
            raise GatewayError("browser_gateway_request_invalid")
        data.extend(chunk)
        marker = data.find(b"\r\n\r\n")
        if marker >= 0:
            header_end = marker + 4
            if header_end > MAX_HEADER_BYTES:
                raise GatewayError("browser_gateway_request_too_large")
            return bytes(data[:header_end]), bytes(data[header_end:])
        if len(data) >= MAX_HEADER_BYTES:
            raise GatewayError("browser_gateway_request_too_large")
    raise GatewayError("browser_gateway_request_too_large")


def _parse_connect(headers: bytes, policy: SealedPolicy) -> str:
    try:
        text = headers[:-4].decode("ascii")
    except UnicodeDecodeError as exc:
        raise GatewayError("browser_gateway_request_invalid") from exc
    if "\n" in text.replace("\r\n", "") or "\r" in text.replace("\r\n", ""):
        raise GatewayError("browser_gateway_request_invalid")
    lines = text.split("\r\n")
    if not lines or len(lines) - 1 > MAX_HEADERS:
        raise GatewayError("browser_gateway_request_invalid")
    parts = lines[0].split(" ")
    if len(parts) != 3 or parts[0] != "CONNECT" or parts[2] != "HTTP/1.1":
        raise GatewayError("browser_gateway_request_forbidden")
    authority = parts[1]
    try:
        parsed = urllib.parse.urlsplit("//" + authority)
        host = canonical_hostname(parsed.hostname or "")
        port = parsed.port
        ipaddress.ip_address(host)
    except ValueError:
        try:
            parsed = urllib.parse.urlsplit("//" + authority)
            host = canonical_hostname(parsed.hostname or "")
            port = parsed.port
        except (UnicodeError, ValueError) as exc:
            raise GatewayError("browser_gateway_request_invalid") from exc
    else:
        raise GatewayError("browser_gateway_request_forbidden")
    if (
        parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
        or port != 443
        or host not in policy.hosts
    ):
        raise GatewayError("browser_gateway_destination_denied")
    seen: dict[str, str] = {}
    for line in lines[1:]:
        name, separator, value = line.partition(":")
        if (
            not separator
            or not name
            or any(
                character not in "!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
                for character in name
            )
            or "\x00" in value
        ):
            raise GatewayError("browser_gateway_request_invalid")
        lowered = name.casefold()
        if lowered in seen:
            raise GatewayError("browser_gateway_request_invalid")
        seen[lowered] = value.strip()
    host_header = seen.get("host")
    if host_header not in {host, f"{host}:443"}:
        raise GatewayError("browser_gateway_request_invalid")
    if any(name in seen for name in ("content-length", "transfer-encoding", "proxy-authorization")):
        raise GatewayError("browser_gateway_request_forbidden")
    return host


class ScopeGateway:
    """Serve one policy without exposing a mutable management operation."""

    def __init__(self, policy: SealedPolicy, *, proxy_port: int, status_port: int) -> None:
        if proxy_port == status_port:
            raise GatewayError("browser_gateway_listener_conflict")
        self.policy = policy
        self.proxy_port = proxy_port
        self.status_port = status_port
        self.boot_nonce = secrets.token_hex(32)
        self.counters = GatewayCounters()
        # Bind the wall-clock policy expiry once. Relay decisions must not be
        # extended by later wall-clock adjustments while a tunnel is alive.
        self._expiry_deadline = time.monotonic() + max(0.0, self.policy.expires_timestamp - time.time())

    def expired(self) -> bool:
        return time.monotonic() >= self._expiry_deadline

    def seconds_until_expiry(self) -> float:
        """Return the remaining sealed lifetime on the monotonic clock."""

        return max(0.0, self._expiry_deadline - time.monotonic())

    def status_document(self) -> dict[str, Any]:
        return {
            "schema_version": STATUS_SCHEMA_VERSION,
            "boot_nonce": self.boot_nonce,
            "policy_sha256": self.policy.policy_sha256,
            "expires_at": self.policy.expires_at,
            "listeners": {
                "proxy": f"{LOOPBACK_HOST}:{self.proxy_port}",
                "status": f"{LOOPBACK_HOST}:{self.status_port}",
            },
            "counters": self.counters.snapshot(),
        }

    def handle_proxy(self, client: socket.socket, client_address: tuple[str, int]) -> None:
        del client_address
        if self.expired():
            self.counters.add("refused")
            return
        remote: socket.socket | None = None
        try:
            client.settimeout(CONNECT_TIMEOUT_SECONDS)
            headers, initial = _read_proxy_headers(client)
            target_host = _parse_connect(headers, self.policy)
            if self.expired():
                raise GatewayError("browser_gateway_expired")
            # `https` is authorized first so the raw TCP plan cannot widen the
            # compiled protocol rule.  Passing scheme=tcp keeps Chrome's TLS
            # handshake, SNI, and certificate verification end to end.
            target_origin = f"https://{target_host}"
            decision = check_url(self.policy.scope, target_origin + "/", platform=True)
            if not decision.allowed:
                raise GatewayError("browser_gateway_destination_denied")
            candidates = resolve_scoped_addresses(self.policy.scope, target_host, 443)
            plan = ScopedConnectionPlan(
                url=f"tcp://{target_host}:443",
                scheme="tcp",
                host=target_host,
                port=443,
                candidates=candidates,
            )
            remote = connect_scoped_stream(plan, timeout=CONNECT_TIMEOUT_SECONDS)
            if self.expired():
                raise GatewayError("browser_gateway_expired")
            client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            self.counters.add("connected")
            self._relay(client, remote, initial)
            self.counters.add("completed")
        except (GatewayError, OSError, RuntimeError, ValueError):
            self.counters.add("failed")
            self.counters.add("refused")
        finally:
            if remote is not None:
                try:
                    remote.close()
                except OSError:
                    pass
            try:
                client.close()
            except OSError:
                pass

    def _relay(self, client: socket.socket, remote: socket.socket, initial: bytes) -> None:
        total = len(initial)
        if total > MAX_TUNNEL_BYTES:
            raise GatewayError("browser_gateway_byte_limit")
        if self.expired():
            raise GatewayError("browser_gateway_expired")
        client.setblocking(False)
        remote.setblocking(False)
        buffers: dict[socket.socket, bytearray] = {
            client: bytearray(),
            remote: bytearray(initial),
        }
        if initial:
            self.counters.add("bytes", len(initial))
        selector = selectors.DefaultSelector()
        selector.register(client, selectors.EVENT_READ)
        selector.register(
            remote,
            selectors.EVENT_READ | (selectors.EVENT_WRITE if initial else 0),
        )
        readable = {client: True, remote: True}
        shutdown_after_flush: set[socket.socket] = set()

        def update_events(stream: socket.socket) -> None:
            events = selectors.EVENT_READ if readable[stream] else 0
            if buffers[stream]:
                events |= selectors.EVENT_WRITE
            try:
                if events:
                    selector.modify(stream, events)
                else:
                    selector.unregister(stream)
            except KeyError:
                if events:
                    selector.register(stream, events)

        def flush_shutdown(stream: socket.socket) -> None:
            if stream not in shutdown_after_flush or buffers[stream]:
                return
            try:
                stream.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            shutdown_after_flush.remove(stream)

        started = time.monotonic()
        last_activity = started
        try:
            while True:
                if self.expired():
                    raise GatewayError("browser_gateway_expired")
                now = time.monotonic()
                if now - started >= LIFETIME_SECONDS:
                    raise GatewayError("browser_gateway_lifetime_limit")
                if now - last_activity >= IDLE_TIMEOUT_SECONDS:
                    raise GatewayError("browser_gateway_idle_timeout")
                timeout = min(
                    1.0,
                    self.seconds_until_expiry(),
                    LIFETIME_SECONDS - (now - started),
                    IDLE_TIMEOUT_SECONDS - (now - last_activity),
                )
                events = selector.select(timeout)
                if self.expired():
                    raise GatewayError("browser_gateway_expired")
                for key, mask in events:
                    source = key.fileobj
                    if not isinstance(source, socket.socket):
                        raise GatewayError("browser_gateway_relay_failed")
                    if mask & selectors.EVENT_READ:
                        if self.expired():
                            raise GatewayError("browser_gateway_expired")
                        remaining = MAX_TUNNEL_BYTES - total
                        if remaining <= 0:
                            raise GatewayError("browser_gateway_byte_limit")
                        data = source.recv(min(IO_CHUNK_BYTES, remaining + 1))
                        if self.expired():
                            raise GatewayError("browser_gateway_expired")
                        if not data:
                            readable[source] = False
                            destination = remote if source is client else client
                            shutdown_after_flush.add(destination)
                            flush_shutdown(destination)
                            update_events(source)
                            update_events(destination)
                            continue
                        destination = remote if source is client else client
                        buffers[destination].extend(data[:remaining])
                        if len(data) > remaining:
                            raise GatewayError("browser_gateway_byte_limit")
                        total += len(data)
                        self.counters.add("bytes", len(data))
                        last_activity = time.monotonic()
                        update_events(destination)
                    if mask & selectors.EVENT_WRITE:
                        if self.expired():
                            raise GatewayError("browser_gateway_expired")
                        pending = buffers[source]
                        if pending:
                            try:
                                sent = source.send(pending)
                            except BlockingIOError:
                                sent = 0
                            del pending[:sent]
                            last_activity = time.monotonic()
                        flush_shutdown(source)
                        update_events(source)
                if not selector.get_map():
                    return
        finally:
            selector.close()


class _BoundedThreadingMixIn(socketserver.ThreadingMixIn):
    """Acquire a request slot before creating a handler thread."""

    max_request_threads = 1

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self._request_slots = threading.BoundedSemaphore(self.max_request_threads)
        self._active_lock = threading.Lock()
        self._active_requests = 0
        self.max_observed_requests = 0
        super().__init__(*args, **kwargs)

    @property
    def active_requests(self) -> int:
        with self._active_lock:
            return self._active_requests

    def request_refused(self) -> None:
        """Let listeners account for an admission refusal without starting work."""

    def request_admitted(self) -> None:
        """Let listeners account for an admitted socket before its thread runs."""

    def process_request(self, request: socket.socket, client_address: tuple[str, int]) -> None:
        if not self._request_slots.acquire(blocking=False):
            self.request_refused()
            self.shutdown_request(request)
            return
        self.request_admitted()
        with self._active_lock:
            self._active_requests += 1
            self.max_observed_requests = max(self.max_observed_requests, self._active_requests)
        try:
            super().process_request(request, client_address)
        except BaseException:
            with self._active_lock:
                self._active_requests -= 1
            self._request_slots.release()
            self.shutdown_request(request)
            raise

    def process_request_thread(self, request: socket.socket, client_address: tuple[str, int]) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            with self._active_lock:
                self._active_requests -= 1
            self._request_slots.release()


class _ProxyServer(_BoundedThreadingMixIn, socketserver.TCPServer):
    address_family = socket.AF_INET
    allow_reuse_address = False
    daemon_threads = True
    request_queue_size = MAX_CONNECTIONS
    max_request_threads = MAX_CONNECTIONS

    def request_admitted(self) -> None:
        self.gateway.counters.add("accepted")  # type: ignore[attr-defined]

    def request_refused(self) -> None:
        gateway: ScopeGateway = self.gateway  # type: ignore[attr-defined]
        gateway.counters.add("accepted")
        gateway.counters.add("refused")


class _ProxyHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        gateway: ScopeGateway = self.server.gateway  # type: ignore[attr-defined]
        if self.client_address[0] != LOOPBACK_HOST:
            gateway.counters.add("refused")
            return
        gateway.handle_proxy(self.request, self.client_address)


class _StatusServer(_BoundedThreadingMixIn, socketserver.TCPServer):
    address_family = socket.AF_INET
    allow_reuse_address = False
    daemon_threads = True
    request_queue_size = 4
    max_request_threads = 4


def _read_status_headers(stream: socket.socket) -> bytes:
    """Read one body-free status request even when its header is split."""

    data = bytearray()
    while len(data) < MAX_HEADER_BYTES:
        chunk = stream.recv(min(4096, MAX_HEADER_BYTES - len(data)))
        if not chunk:
            raise GatewayError("browser_gateway_status_request_invalid")
        data.extend(chunk)
        marker = data.find(b"\r\n\r\n")
        if marker >= 0:
            if marker + 4 != len(data):
                raise GatewayError("browser_gateway_status_request_invalid")
            return bytes(data)
    raise GatewayError("browser_gateway_status_request_invalid")


class _StatusHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        gateway: ScopeGateway = self.server.gateway  # type: ignore[attr-defined]
        if self.client_address[0] != LOOPBACK_HOST:
            return
        try:
            self.request.settimeout(CONNECT_TIMEOUT_SECONDS)
            request = _read_status_headers(self.request)
            try:
                lines = request[:-4].decode("ascii").split("\r\n")
            except (GatewayError, UnicodeDecodeError):
                return
            if not request.endswith(b"\r\n\r\n") or not 2 <= len(lines) <= 32:
                return
            if lines[0] != "GET /status HTTP/1.1":
                return
            headers: dict[str, str] = {}
            for line in lines[1:]:
                name, separator, raw_value = line.partition(":")
                value = raw_value.strip()
                lowered = name.casefold()
                if (
                    not separator
                    or not name
                    or lowered in headers
                    or any(ord(character) < 0x20 and character != "\t" for character in value)
                    or any(ord(character) == 0x7F for character in value)
                ):
                    return
                headers[lowered] = value
            if headers.get("host") not in {
                "127.0.0.1",
                f"127.0.0.1:{gateway.status_port}",
            }:
                return
            if "content-length" in headers or "transfer-encoding" in headers:
                return
            payload = canonical_json(gateway.status_document()).encode("utf-8")
            response = (
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: application/json\r\n"
                b"Cache-Control: no-store\r\n"
                + f"Content-Length: {len(payload)}\r\n".encode("ascii")
                + b"Connection: close\r\n\r\n"
                + payload
            )
            self.request.sendall(response)
        except (GatewayError, OSError):
            return


def _servers(gateway: ScopeGateway) -> tuple[_ProxyServer, _StatusServer]:
    proxy = _ProxyServer((LOOPBACK_HOST, gateway.proxy_port), _ProxyHandler)
    proxy.gateway = gateway  # type: ignore[attr-defined]
    try:
        status = _StatusServer((LOOPBACK_HOST, gateway.status_port), _StatusHandler)
    except BaseException:
        proxy.server_close()
        raise
    status.gateway = gateway  # type: ignore[attr-defined]
    return proxy, status


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--proxy-port", type=_port, default=DEFAULT_PROXY_PORT)
    parser.add_argument("--status-port", type=_port, default=DEFAULT_STATUS_PORT)
    arguments = parser.parse_args(argv)
    try:
        policy = _load_policy(arguments.policy)
        gateway = ScopeGateway(policy, proxy_port=arguments.proxy_port, status_port=arguments.status_port)
        proxy, status = _servers(gateway)
    except GatewayError as exc:
        LOGGER.error("%s", exc)
        return 2
    except OSError:
        LOGGER.error("browser_gateway_listener_unavailable")
        return 2
    proxy_thread = threading.Thread(target=proxy.serve_forever, name="rookery-browser-proxy", daemon=True)
    status_thread = threading.Thread(target=status.serve_forever, name="rookery-browser-status", daemon=True)
    proxy_thread.start()
    status_thread.start()
    try:
        while proxy_thread.is_alive() and status_thread.is_alive() and not gateway.expired():
            time.sleep(min(0.25, gateway.seconds_until_expiry()))
        if gateway.expired():
            return 0
    except KeyboardInterrupt:
        return 0
    finally:
        proxy.shutdown()
        status.shutdown()
        proxy.server_close()
        status.server_close()
        proxy_thread.join(timeout=2)
        status_thread.join(timeout=2)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
