"""Bounded read-only access to one already-authenticated Chrome CDP target.

This module has no browser navigation or browser-network API.  It reads the
version and target list through a fixed loopback HTTP scope, then sends one
DevTools command over a DNS-pinned loopback WebSocket:
``Network.getCookies``.  Callers receive session headers in memory only.
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
import secrets
import struct
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any

from .environment import (
    ChildEnvironment,
    EnvironmentPolicyError,
    resolve_browser_cdp_endpoint,
    verify_browser_cdp_endpoint,
)
from .network_policy import ExplicitNetworkPolicy
from .scope import canonical_hostname, default_port_for_scheme, open_scoped_url
from .scoped_transport import connect_scoped_stream, scoped_connection_plan

CDP_TIMEOUT_SECONDS = 5
CDP_LIST_MAX_BYTES = 256 * 1024
CDP_MAX_TARGETS = 128
CDP_MAX_FRAME_BYTES = 128 * 1024
CDP_MAX_RESPONSE_FRAMES = 8
CDP_MAX_COOKIES = 64
CDP_MAX_COOKIE_HEADER_BYTES = 8 * 1024
CDP_MAX_USER_AGENT_BYTES = 2 * 1024
CDP_MAX_TARGET_ID_BYTES = 512
_COOKIE_NAME_FORBIDDEN = frozenset('()<>@,;:\\"/[]?={} \t')
_CTFD_SESSION_PATHS = (
    "/api/v1/users/me",
    "/api/v1/challenges",
    "/api/v1/challenges/attempt",
)


class BrowserCdpError(RuntimeError):
    """A value-free failure while reading the local browser session."""


@dataclass(frozen=True)
class BrowserSession:
    """Credential-bearing browser values that must remain process-memory only."""

    origin: str
    target_id: str
    cookie_header: str = field(repr=False)
    user_agent: str = field(repr=False)


@dataclass(frozen=True)
class _Origin:
    scheme: str
    host: str
    port: int

    @property
    def value(self) -> str:
        authority = self.host
        if self.port != default_port_for_scheme(self.scheme):
            authority = f"{authority}:{self.port}"
        return f"{self.scheme}://{authority}"


def _has_control(value: str) -> bool:
    return any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)


def _configured_origin(value: str) -> _Origin:
    """Return the exact HTTPS origin that CDP session data may serve."""

    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > 4_096:
        raise BrowserCdpError("browser_ctfd_origin_invalid")
    if _has_control(value):
        raise BrowserCdpError("browser_ctfd_origin_invalid")
    try:
        parsed = urllib.parse.urlsplit(value)
        host = canonical_hostname(parsed.hostname or "")
        port = parsed.port or default_port_for_scheme(parsed.scheme.casefold())
    except (UnicodeError, ValueError) as exc:
        raise BrowserCdpError("browser_ctfd_origin_invalid") from exc
    if (
        parsed.scheme.casefold() != "https"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or not host
        or not 1 <= port <= 65_535
    ):
        raise BrowserCdpError("browser_ctfd_origin_invalid")
    return _Origin("https", host, port)


def _cdp_scope(port: int) -> dict[str, Any]:
    """Construct the narrow synthetic authority required for one CDP endpoint."""

    return {
        "acknowledged": True,
        "generation": 0,
        "expires_at": "unknown",
        "allowed_hosts": ["127.0.0.1"],
        "allowed_cidrs": ["127.0.0.1/32"],
        "allowed_ports": [port],
        "allowed_protocols": ["http", "ws"],
        "allowed_file_origins": [],
        "platform_hosts": [],
        "max_attachment_bytes": 0,
    }


def _loopback_transport(scope: dict[str, Any]) -> Any:
    policy = ExplicitNetworkPolicy.from_child_environment(
        ChildEnvironment({}, "browser-cdp-loopback", ())
    )
    return policy.scoped_transport(scope)


def _bounded_json_response(response: Any, *, maximum: int, error: str) -> Any:
    if getattr(response, "status", None) != 200:
        raise BrowserCdpError(error)
    content_type = str(getattr(response, "headers", {}).get("Content-Type", ""))
    if content_type.split(";", 1)[0].strip().casefold() != "application/json":
        raise BrowserCdpError(error)
    payload = response.read(maximum + 1)
    if not isinstance(payload, bytes) or len(payload) > maximum:
        raise BrowserCdpError(error)
    try:
        return json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BrowserCdpError(error) from exc


def _read_targets(cdp_url: str, port: int) -> list[dict[str, Any]]:
    scope = _cdp_scope(port)
    list_url = f"{cdp_url}/json/list"
    request = urllib.request.Request(
        list_url,
        headers={"Accept": "application/json"},
        method="GET",
    )
    try:
        with open_scoped_url(
            scope,
            request,
            timeout=CDP_TIMEOUT_SECONDS,
            max_redirects=0,
            transport=_loopback_transport(scope),
        ) as response:
            document = _bounded_json_response(
                response,
                maximum=CDP_LIST_MAX_BYTES,
                error="browser_cdp_target_list_invalid",
            )
    except BrowserCdpError:
        raise
    except (OSError, RuntimeError, ValueError) as exc:
        raise BrowserCdpError("browser_cdp_target_list_unavailable") from exc
    if (
        not isinstance(document, list)
        or len(document) > CDP_MAX_TARGETS
        or not all(isinstance(target, dict) for target in document)
    ):
        raise BrowserCdpError("browser_cdp_target_list_invalid")
    return document


def _read_version_user_agent(cdp_url: str, port: int) -> str:
    """Read the CDP-reported browser user agent without attaching to a page."""

    scope = _cdp_scope(port)
    request = urllib.request.Request(
        f"{cdp_url}/json/version",
        headers={"Accept": "application/json"},
        method="GET",
    )
    try:
        with open_scoped_url(
            scope,
            request,
            timeout=CDP_TIMEOUT_SECONDS,
            max_redirects=0,
            transport=_loopback_transport(scope),
        ) as response:
            document = _bounded_json_response(
                response,
                maximum=CDP_LIST_MAX_BYTES,
                error="browser_cdp_version_invalid",
            )
    except BrowserCdpError:
        raise
    except (OSError, RuntimeError, ValueError) as exc:
        raise BrowserCdpError("browser_cdp_version_unavailable") from exc
    if not isinstance(document, dict):
        raise BrowserCdpError("browser_cdp_version_invalid")
    return _valid_user_agent(document.get("User-Agent"))


def _target_matches_origin(value: object, origin: _Origin) -> bool:
    if not isinstance(value, str) or not value or _has_control(value):
        return False
    try:
        parsed = urllib.parse.urlsplit(value)
        port = parsed.port or default_port_for_scheme(parsed.scheme.casefold())
        host = canonical_hostname(parsed.hostname or "")
    except (UnicodeError, ValueError):
        return False
    return (
        parsed.scheme.casefold() == origin.scheme
        and parsed.username is None
        and parsed.password is None
        and host == origin.host
        and port == origin.port
    )


def _target_websocket(value: object, *, port: int) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > CDP_MAX_TARGET_ID_BYTES
        or _has_control(value)
    ):
        raise BrowserCdpError("browser_cdp_target_invalid")
    try:
        parsed = urllib.parse.urlsplit(value)
        websocket_port = parsed.port
    except (UnicodeError, ValueError) as exc:
        raise BrowserCdpError("browser_cdp_target_invalid") from exc
    if (
        parsed.scheme.casefold() != "ws"
        or parsed.hostname != "127.0.0.1"
        or parsed.username is not None
        or parsed.password is not None
        or websocket_port != port
        or not parsed.path.startswith("/devtools/page/")
        or len(parsed.path) == len("/devtools/page/")
        or parsed.query
        or parsed.fragment
    ):
        raise BrowserCdpError("browser_cdp_target_invalid")
    return value


def _select_target(
    targets: list[dict[str, Any]],
    origin: _Origin,
    *,
    port: int,
    target_id: str | None,
) -> tuple[str, str]:
    matches = [
        target
        for target in targets
        if target.get("type") == "page" and _target_matches_origin(target.get("url"), origin)
    ]
    if target_id is not None:
        matches = [target for target in matches if target.get("id") == target_id]
    if not matches:
        raise BrowserCdpError("browser_cdp_target_missing")
    if len(matches) != 1:
        raise BrowserCdpError("browser_cdp_target_ambiguous")
    target = matches[0]
    identifier = target.get("id")
    if (
        not isinstance(identifier, str)
        or not identifier
        or len(identifier.encode("utf-8")) > CDP_MAX_TARGET_ID_BYTES
        or _has_control(identifier)
    ):
        raise BrowserCdpError("browser_cdp_target_invalid")
    return identifier, _target_websocket(target.get("webSocketDebuggerUrl"), port=port)


def _read_http_headers(stream: Any) -> dict[str, str]:
    maximum = 8 * 1024
    data = bytearray()
    while len(data) < maximum:
        # One-byte reads retain an empty post-header buffer without inventing a
        # second framing layer before the WebSocket parser takes ownership.
        chunk = stream.recv(1)
        if not chunk:
            raise BrowserCdpError("browser_cdp_websocket_handshake_failed")
        data.extend(chunk)
        marker = data.find(b"\r\n\r\n")
        if marker >= 0:
            if marker + 4 != len(data):
                raise BrowserCdpError("browser_cdp_websocket_handshake_failed")
            try:
                lines = data[:-4].decode("ascii").split("\r\n")
            except UnicodeDecodeError as exc:
                raise BrowserCdpError("browser_cdp_websocket_handshake_failed") from exc
            # HTTP reason phrases are not standardized. Chrome may say
            # "WebSocket Protocol Handshake" for the same 101 upgrade.
            status = lines[0].split(" ", 2) if lines else []
            if len(status) < 2 or status[:2] != ["HTTP/1.1", "101"]:
                raise BrowserCdpError("browser_cdp_websocket_handshake_failed")
            headers: dict[str, str] = {}
            for line in lines[1:]:
                name, separator, value = line.partition(":")
                if not separator or not name or _has_control(value.replace("\t", "")):
                    raise BrowserCdpError("browser_cdp_websocket_handshake_failed")
                lowered = name.casefold()
                if lowered in headers:
                    raise BrowserCdpError("browser_cdp_websocket_handshake_failed")
                headers[lowered] = value.strip()
            return headers
    raise BrowserCdpError("browser_cdp_websocket_handshake_failed")


def _websocket_acceptance(key: str) -> str:
    # RFC 6455 mandates SHA-1 for this non-secret server-handshake check.
    source = (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("ascii")
    return base64.b64encode(hashlib.sha1(source).digest()).decode("ascii")


def _send_frame(stream: Any, opcode: int, payload: bytes) -> None:
    if not 0 <= opcode <= 0x0F or len(payload) > CDP_MAX_FRAME_BYTES:
        raise BrowserCdpError("browser_cdp_frame_invalid")
    header = bytearray([0x80 | opcode])
    size = len(payload)
    if size < 126:
        header.append(0x80 | size)
    elif size <= 0xFFFF:
        header.append(0x80 | 126)
        header.extend(struct.pack("!H", size))
    else:
        header.append(0x80 | 127)
        header.extend(struct.pack("!Q", size))
    mask = secrets.token_bytes(4)
    masked = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
    stream.sendall(bytes(header) + mask + masked)


def _recv_exact(stream: Any, amount: int) -> bytes:
    if amount < 0 or amount > CDP_MAX_FRAME_BYTES:
        raise BrowserCdpError("browser_cdp_frame_invalid")
    data = bytearray()
    while len(data) < amount:
        chunk = stream.recv(amount - len(data))
        if not chunk:
            raise BrowserCdpError("browser_cdp_websocket_closed")
        data.extend(chunk)
    return bytes(data)


def _recv_frame(stream: Any) -> tuple[int, bytes]:
    first, second = _recv_exact(stream, 2)
    if first & 0x70 or not first & 0x80 or second & 0x80:
        raise BrowserCdpError("browser_cdp_frame_invalid")
    opcode = first & 0x0F
    length = second & 0x7F
    if length == 126:
        length = struct.unpack("!H", _recv_exact(stream, 2))[0]
    elif length == 127:
        length = struct.unpack("!Q", _recv_exact(stream, 8))[0]
    if length > CDP_MAX_FRAME_BYTES:
        raise BrowserCdpError("browser_cdp_frame_invalid")
    return opcode, _recv_exact(stream, length)


class _CdpSocket:
    """A minimal, one-target CDP WebSocket with one read-only command."""

    def __init__(self, stream: Any, websocket_url: str, *, port: int) -> None:
        self._stream = stream
        self._next_id = 1
        parsed = urllib.parse.urlsplit(websocket_url)
        key = base64.b64encode(secrets.token_bytes(16)).decode("ascii")
        host = f"127.0.0.1:{port}"
        request = (
            f"GET {parsed.path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            # Chrome rejects a non-browser CDP client Origin unless the browser
            # was started with an allowlist. The URL and Host remain exact
            # IPv4 loopback values checked before this request.
            "\r\n"
        ).encode("ascii")
        self._stream.sendall(request)
        headers = _read_http_headers(self._stream)
        if (
            headers.get("upgrade", "").casefold() != "websocket"
            or "upgrade" not in headers.get("connection", "").casefold()
            or headers.get("sec-websocket-accept", "") != _websocket_acceptance(key)
        ):
            raise BrowserCdpError("browser_cdp_websocket_handshake_failed")

    def command(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        if method != "Network.getCookies":
            raise BrowserCdpError("browser_cdp_command_forbidden")
        identifier = self._next_id
        self._next_id += 1
        payload = json.dumps(
            {"id": identifier, "method": method, "params": params},
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
        if len(payload) > CDP_MAX_FRAME_BYTES:
            raise BrowserCdpError("browser_cdp_command_invalid")
        _send_frame(self._stream, 0x1, payload)
        for _ in range(CDP_MAX_RESPONSE_FRAMES):
            opcode, frame = _recv_frame(self._stream)
            if opcode == 0x8:
                raise BrowserCdpError("browser_cdp_websocket_closed")
            if opcode == 0x9:
                _send_frame(self._stream, 0xA, frame)
                continue
            if opcode != 0x1:
                continue
            try:
                response = json.loads(frame.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise BrowserCdpError("browser_cdp_response_invalid") from exc
            if not isinstance(response, dict):
                raise BrowserCdpError("browser_cdp_response_invalid")
            if response.get("id") != identifier:
                continue
            result = response.get("result")
            if not isinstance(result, dict) or "error" in response:
                raise BrowserCdpError("browser_cdp_response_invalid")
            return result
        raise BrowserCdpError("browser_cdp_response_missing")

    def close(self) -> None:
        try:
            _send_frame(self._stream, 0x8, b"")
        except (BrowserCdpError, OSError):
            pass
        try:
            self._stream.close()
        except OSError:
            pass


def _open_target_socket(websocket_url: str, *, port: int) -> _CdpSocket:
    scope = _cdp_scope(port)
    try:
        plan = scoped_connection_plan(scope, websocket_url)
        stream = connect_scoped_stream(plan, timeout=CDP_TIMEOUT_SECONDS)
    except (OSError, RuntimeError, ValueError) as exc:
        raise BrowserCdpError("browser_cdp_websocket_unavailable") from exc
    try:
        return _CdpSocket(stream, websocket_url, port=port)
    except (BrowserCdpError, OSError, ValueError):
        try:
            stream.close()
        except OSError:
            pass
        raise


def _valid_user_agent(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > CDP_MAX_USER_AGENT_BYTES
        or _has_control(value)
    ):
        raise BrowserCdpError("browser_cdp_user_agent_invalid")
    try:
        value.encode("latin-1")
    except UnicodeEncodeError as exc:
        raise BrowserCdpError("browser_cdp_user_agent_invalid") from exc
    return value


def _cookie_path_matches(cookie_path: str, request_path: str) -> bool:
    """Apply the RFC 6265 path boundary before reusing a browser cookie."""

    if request_path == cookie_path:
        return True
    if not request_path.startswith(cookie_path):
        return False
    return cookie_path.endswith("/") or request_path[len(cookie_path)] == "/"


def _cookie_header(cookies: object, origin: _Origin) -> str:
    if not isinstance(cookies, list) or not cookies or len(cookies) > CDP_MAX_COOKIES:
        raise BrowserCdpError("browser_cdp_cookie_invalid")
    names: set[str] = set()
    selected: list[tuple[str, str]] = []
    now = time.time()
    for cookie in cookies:
        if not isinstance(cookie, dict):
            raise BrowserCdpError("browser_cdp_cookie_invalid")
        name = cookie.get("name")
        value = cookie.get("value")
        domain = cookie.get("domain")
        cookie_path = cookie.get("path")
        secure = cookie.get("secure")
        expires = cookie.get("expires", -1)
        if (
            not isinstance(name, str)
            or not name
            or _has_control(name)
            or any(character in _COOKIE_NAME_FORBIDDEN for character in name)
            or not isinstance(value, str)
            or _has_control(value)
            or ";" in value
            or not isinstance(domain, str)
            or not isinstance(cookie_path, str)
            or not cookie_path.startswith("/")
            or not all(
                _cookie_path_matches(cookie_path, request_path)
                for request_path in _CTFD_SESSION_PATHS
            )
            or secure is not True
            or cookie.get("partitionKey") not in {None, ""}
            or cookie.get("partitionKeyOpaque") is True
        ):
            raise BrowserCdpError("browser_cdp_cookie_invalid")
        try:
            canonical_domain = canonical_hostname(domain.lstrip("."))
            expires_value = float(expires)
        except (TypeError, ValueError):
            raise BrowserCdpError("browser_cdp_cookie_invalid") from None
        if not canonical_domain or not (
            origin.host == canonical_domain
            or origin.host.endswith("." + canonical_domain)
        ):
            raise BrowserCdpError("browser_cdp_cookie_invalid")
        if not math.isfinite(expires_value):
            raise BrowserCdpError("browser_cdp_cookie_invalid")
        if expires_value >= 0 and expires_value <= now:
            continue
        if name in names:
            raise BrowserCdpError("browser_cdp_cookie_invalid")
        names.add(name)
        selected.append((name, value))
    if not selected:
        raise BrowserCdpError("browser_cdp_cookie_expired")
    header = "; ".join(f"{name}={value}" for name, value in sorted(selected))
    try:
        header_bytes = header.encode("latin-1")
    except UnicodeEncodeError as exc:
        raise BrowserCdpError("browser_cdp_cookie_invalid") from exc
    if len(header_bytes) > CDP_MAX_COOKIE_HEADER_BYTES:
        raise BrowserCdpError("browser_cdp_cookie_invalid")
    return header


def read_browser_session(
    cdp_url: str,
    base_url: str,
    *,
    target_id: str | None = None,
) -> BrowserSession:
    """Read one unique CTFd browser session without causing browser network I/O."""

    origin = _configured_origin(base_url)
    if target_id is not None and (
        not isinstance(target_id, str)
        or not target_id
        or len(target_id.encode("utf-8")) > CDP_MAX_TARGET_ID_BYTES
        or _has_control(target_id)
    ):
        raise BrowserCdpError("browser_cdp_target_invalid")
    try:
        normalized_url, port = resolve_browser_cdp_endpoint(cdp_url)
        verify_browser_cdp_endpoint(cdp_url)
    except EnvironmentPolicyError as exc:
        raise BrowserCdpError(str(exc)) from exc
    user_agent = _read_version_user_agent(normalized_url, port)
    targets = _read_targets(normalized_url, port)
    identifier, websocket_url = _select_target(
        targets,
        origin,
        port=port,
        target_id=target_id,
    )
    socket = _open_target_socket(websocket_url, port=port)
    try:
        cookies = socket.command(
            "Network.getCookies",
            {"urls": [origin.value + path for path in _CTFD_SESSION_PATHS]},
        )
    finally:
        socket.close()
    return BrowserSession(
        origin=origin.value,
        target_id=identifier,
        cookie_header=_cookie_header(cookies.get("cookies"), origin),
        user_agent=user_agent,
    )
