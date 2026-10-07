"""Portable, bounded CDP transport for adapter-owned browser UI targets.

The public surface is intentionally small.  ``open_owned_browser_target``
creates one disposable ``about:blank`` page through Chrome's browser CDP
socket and returns an allowlisted page channel.  Browser-level target creation
and closure are never exposed to adapter callers.

All deadlines accepted by this module are absolute ``time.monotonic()`` values.
Closing an owned target succeeds only after both Chrome's target registry and
the loopback target list confirm that the exact target is absent.  Context
manager cleanup raises if that confirmation cannot be obtained; it never
silently detaches from an unclosed target.
"""

from __future__ import annotations

import base64
import json
import math
import re
import secrets
import socket
import struct
import time
import urllib.parse
import urllib.request
from collections import deque
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, TypeAlias

from . import browser_cdp as _browser_cdp
from .environment import EnvironmentPolicyError, resolve_browser_cdp_endpoint
from .scope import open_scoped_url
from .scoped_transport import connect_scoped_stream, scoped_connection_plan

JsonValue: TypeAlias = (
    None
    | bool
    | int
    | float
    | str
    | list["JsonValue"]
    | dict[str, "JsonValue"]
)

MAX_OPERATION_SECONDS = 60.0
MAX_CHANNEL_MESSAGES = 4_096
MAX_BUFFERED_EVENTS = 256
MAX_JSON_DEPTH = 32
MAX_JSON_ITEMS = 8_192
MAX_JSON_STRING_BYTES = 64 * 1024
MAX_TARGETS = 128
MAX_CONTROL_FRAMES = 8
MAX_EXPRESSION_BYTES = 64 * 1024
MAX_WEBSOCKET_URL_BYTES = 4_096
_CLEANUP_SECONDS = 2.0
_HTTP_JSON_MAX_BYTES = 256 * 1024
_HTTP_HEADERS_MAX_BYTES = 8 * 1024
_MAX_SAFE_INTEGER = (1 << 53) - 1
_IDENTIFIER = re.compile(r"[A-Za-z0-9_.:-]{1,512}")
_REFERRER_POLICIES = frozenset(
    {
        "noReferrer",
        "noReferrerWhenDowngrade",
        "origin",
        "originWhenCrossOrigin",
        "sameOrigin",
        "strictOrigin",
        "strictOriginWhenCrossOrigin",
        "unsafeUrl",
    }
)
_BROWSER_METHODS = frozenset(
    {
        "Target.closeTarget",
        "Target.createTarget",
        "Target.getTargets",
    }
)
_PAGE_METHODS = frozenset(
    {
        "Fetch.continueRequest",
        "Fetch.continueResponse",
        "Fetch.enable",
        "Fetch.failRequest",
        "Fetch.getResponseBody",
        "Network.disable",
        "Network.enable",
        "Network.getCookies",
        "Network.setBypassServiceWorker",
        "Network.setCacheDisabled",
        "Page.createIsolatedWorld",
        "Page.disable",
        "Page.enable",
        "Page.getFrameTree",
        "Page.navigate",
        "Page.setDownloadBehavior",
        "Runtime.callFunctionOn",
        "Runtime.disable",
        "Runtime.enable",
        "Runtime.evaluate",
        "Runtime.releaseObject",
        "Target.getTargetInfo",
        "Target.getTargets",
        "Target.setAutoAttach",
    }
)


class BrowserUiCdpError(RuntimeError):
    """Value-free failure from the portable browser UI CDP boundary."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class RuntimeValue:
    """One JSON-compatible value returned by a runtime helper.

    ``type`` and ``subtype`` retain CDP's type information, including the
    distinction between JavaScript ``undefined`` and ``null``.  The value is
    hidden from representations because page results may contain credentials
    or other session data.
    """

    type: str
    subtype: str | None
    value: JsonValue = field(repr=False)


@dataclass(frozen=True)
class NavigationResult:
    """Identifiers returned after Chrome accepts a top-level navigation."""

    frame_id: str
    loader_id: str | None


def deadline_after(timeout_seconds: float) -> float:
    """Return a bounded absolute monotonic deadline.

    Args:
        timeout_seconds: Positive duration no greater than 60 seconds.

    Raises:
        BrowserUiCdpError: If the duration is non-finite or outside the bound.
    """

    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not math.isfinite(float(timeout_seconds))
        or not 0 < float(timeout_seconds) <= MAX_OPERATION_SECONDS
    ):
        raise BrowserUiCdpError("browser_ui_cdp_deadline_invalid")
    return time.monotonic() + float(timeout_seconds)


def _remaining(deadline: float) -> float:
    if (
        isinstance(deadline, bool)
        or not isinstance(deadline, (int, float))
        or not math.isfinite(float(deadline))
    ):
        raise BrowserUiCdpError("browser_ui_cdp_deadline_invalid")
    remaining = float(deadline) - time.monotonic()
    if remaining <= 0:
        raise BrowserUiCdpError("browser_ui_cdp_timeout")
    if remaining > MAX_OPERATION_SECONDS:
        raise BrowserUiCdpError("browser_ui_cdp_deadline_invalid")
    return remaining


def _has_control(value: str) -> bool:
    return any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)


def _valid_identifier(value: object, *, error: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise BrowserUiCdpError(error)
    return value


def _validate_json_value(value: object) -> JsonValue:
    items = 0
    stack: list[tuple[object, int]] = [(value, 1)]
    while stack:
        current, depth = stack.pop()
        items += 1
        if items > MAX_JSON_ITEMS or depth > MAX_JSON_DEPTH:
            raise BrowserUiCdpError("browser_ui_cdp_value_invalid")
        if current is None or isinstance(current, bool):
            continue
        if isinstance(current, int):
            if abs(current) > _MAX_SAFE_INTEGER:
                raise BrowserUiCdpError("browser_ui_cdp_value_invalid")
            continue
        if isinstance(current, float):
            if not math.isfinite(current):
                raise BrowserUiCdpError("browser_ui_cdp_value_invalid")
            continue
        if isinstance(current, str):
            if len(current.encode("utf-8")) > MAX_JSON_STRING_BYTES:
                raise BrowserUiCdpError("browser_ui_cdp_value_invalid")
            continue
        if isinstance(current, list):
            stack.extend((child, depth + 1) for child in current)
            continue
        if isinstance(current, dict):
            for key, child in current.items():
                if (
                    not isinstance(key, str)
                    or len(key.encode("utf-8")) > MAX_JSON_STRING_BYTES
                ):
                    raise BrowserUiCdpError("browser_ui_cdp_value_invalid")
                stack.append((child, depth + 1))
            continue
        raise BrowserUiCdpError("browser_ui_cdp_value_invalid")
    return value  # type: ignore[return-value]


def _valid_navigation_url(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > MAX_JSON_STRING_BYTES
        or _has_control(value)
    ):
        raise BrowserUiCdpError("browser_ui_cdp_navigation_invalid")
    try:
        parsed = urllib.parse.urlsplit(value)
        port = parsed.port
    except (UnicodeError, ValueError) as exc:
        raise BrowserUiCdpError("browser_ui_cdp_navigation_invalid") from exc
    if (
        parsed.scheme.casefold() not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
        and not 1 <= port <= 65_535
    ):
        raise BrowserUiCdpError("browser_ui_cdp_navigation_invalid")
    return value


def _read_http_json(
    cdp_url: str,
    port: int,
    path: str,
    *,
    deadline: float,
) -> object:
    scope = _browser_cdp._cdp_scope(port)
    request = urllib.request.Request(
        f"{cdp_url}{path}",
        headers={"Accept": "application/json"},
        method="GET",
    )
    try:
        with open_scoped_url(
            scope,
            request,
            timeout=_remaining(deadline),
            max_redirects=0,
            transport=_browser_cdp._loopback_transport(scope),
        ) as response:
            document = _browser_cdp._bounded_json_response(
                response,
                maximum=_HTTP_JSON_MAX_BYTES,
                error="browser_ui_cdp_http_invalid",
            )
    except BrowserUiCdpError:
        raise
    except (_browser_cdp.BrowserCdpError, OSError, RuntimeError, TimeoutError, ValueError) as exc:
        raise BrowserUiCdpError("browser_ui_cdp_http_unavailable") from exc
    _remaining(deadline)
    return document


def _validate_websocket_url(
    value: object,
    *,
    port: int,
    path_prefix: str,
    exact_path: str | None = None,
) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > MAX_WEBSOCKET_URL_BYTES
        or _has_control(value)
    ):
        raise BrowserUiCdpError("browser_ui_cdp_websocket_invalid")
    try:
        parsed = urllib.parse.urlsplit(value)
        websocket_port = parsed.port
    except (UnicodeError, ValueError) as exc:
        raise BrowserUiCdpError("browser_ui_cdp_websocket_invalid") from exc
    if (
        parsed.scheme.casefold() != "ws"
        or parsed.hostname != "127.0.0.1"
        or websocket_port != port
        or parsed.username is not None
        or parsed.password is not None
        or not parsed.path.startswith(path_prefix)
        or len(parsed.path) == len(path_prefix)
        or exact_path is not None
        and parsed.path != exact_path
        or parsed.query
        or parsed.fragment
    ):
        raise BrowserUiCdpError("browser_ui_cdp_websocket_invalid")
    return value


def _browser_websocket(cdp_url: str, port: int, *, deadline: float) -> str:
    document = _read_http_json(cdp_url, port, "/json/version", deadline=deadline)
    if not isinstance(document, dict):
        raise BrowserUiCdpError("browser_ui_cdp_version_invalid")
    if not isinstance(document.get("Browser"), str) or not isinstance(
        document.get("Protocol-Version"), str
    ):
        raise BrowserUiCdpError("browser_ui_cdp_version_invalid")
    return _validate_websocket_url(
        document.get("webSocketDebuggerUrl"),
        port=port,
        path_prefix="/devtools/browser/",
    )


def _target_list(cdp_url: str, port: int, *, deadline: float) -> list[dict[str, Any]]:
    document = _read_http_json(cdp_url, port, "/json/list", deadline=deadline)
    if (
        not isinstance(document, list)
        or len(document) > MAX_TARGETS
        or not all(isinstance(item, dict) for item in document)
    ):
        raise BrowserUiCdpError("browser_ui_cdp_target_list_invalid")
    return document


def _set_socket_timeout(stream: socket.socket, deadline: float) -> None:
    stream.settimeout(_remaining(deadline))


def _recv_exact(stream: socket.socket, amount: int, *, deadline: float) -> bytes:
    if amount < 0 or amount > _browser_cdp.CDP_MAX_FRAME_BYTES:
        raise BrowserUiCdpError("browser_ui_cdp_frame_invalid")
    data = bytearray()
    while len(data) < amount:
        _set_socket_timeout(stream, deadline)
        try:
            chunk = stream.recv(amount - len(data))
        except TimeoutError as exc:
            raise BrowserUiCdpError("browser_ui_cdp_timeout") from exc
        except OSError as exc:
            raise BrowserUiCdpError("browser_ui_cdp_disconnected") from exc
        if not chunk:
            raise BrowserUiCdpError("browser_ui_cdp_disconnected")
        data.extend(chunk)
    return bytes(data)


def _recv_frame(stream: socket.socket, *, deadline: float) -> tuple[int, bytes]:
    first, second = _recv_exact(stream, 2, deadline=deadline)
    if first & 0x70 or not first & 0x80 or second & 0x80:
        raise BrowserUiCdpError("browser_ui_cdp_frame_invalid")
    opcode = first & 0x0F
    length = second & 0x7F
    if length == 126:
        length = struct.unpack("!H", _recv_exact(stream, 2, deadline=deadline))[0]
    elif length == 127:
        encoded_length = _recv_exact(stream, 8, deadline=deadline)
        if encoded_length[0] & 0x80:
            raise BrowserUiCdpError("browser_ui_cdp_frame_invalid")
        length = struct.unpack("!Q", encoded_length)[0]
    if length > _browser_cdp.CDP_MAX_FRAME_BYTES:
        raise BrowserUiCdpError("browser_ui_cdp_frame_invalid")
    return opcode, _recv_exact(stream, length, deadline=deadline)


def _read_http_headers(stream: socket.socket, *, deadline: float) -> dict[str, str]:
    data = bytearray()
    while len(data) < _HTTP_HEADERS_MAX_BYTES:
        data.extend(_recv_exact(stream, 1, deadline=deadline))
        if data.endswith(b"\r\n\r\n"):
            try:
                lines = data[:-4].decode("ascii").split("\r\n")
            except UnicodeDecodeError as exc:
                raise BrowserUiCdpError("browser_ui_cdp_handshake_failed") from exc
            status = lines[0].split(" ", 2) if lines else []
            if len(status) < 2 or status[:2] != ["HTTP/1.1", "101"]:
                raise BrowserUiCdpError("browser_ui_cdp_handshake_failed")
            headers: dict[str, str] = {}
            for line in lines[1:]:
                name, separator, raw_value = line.partition(":")
                value = raw_value.strip()
                lowered = name.casefold()
                if (
                    not separator
                    or not name
                    or lowered in headers
                    or _has_control(value.replace("\t", ""))
                ):
                    raise BrowserUiCdpError("browser_ui_cdp_handshake_failed")
                headers[lowered] = value
            return headers
    raise BrowserUiCdpError("browser_ui_cdp_handshake_failed")


def _open_websocket(
    websocket_url: str,
    *,
    port: int,
    deadline: float,
) -> socket.socket:
    scope = _browser_cdp._cdp_scope(port)
    stream: socket.socket | None = None
    try:
        plan = scoped_connection_plan(scope, websocket_url)
        stream = connect_scoped_stream(plan, timeout=_remaining(deadline))
        parsed = urllib.parse.urlsplit(websocket_url)
        key = base64.b64encode(secrets.token_bytes(16)).decode("ascii")
        request = (
            f"GET {parsed.path} HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{port}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "\r\n"
        ).encode("ascii")
        _set_socket_timeout(stream, deadline)
        stream.sendall(request)
        headers = _read_http_headers(stream, deadline=deadline)
        if (
            headers.get("upgrade", "").casefold() != "websocket"
            or "upgrade" not in headers.get("connection", "").casefold()
            or headers.get("sec-websocket-accept", "")
            != _browser_cdp._websocket_acceptance(key)
        ):
            raise BrowserUiCdpError("browser_ui_cdp_handshake_failed")
        return stream
    except BrowserUiCdpError:
        if stream is not None:
            stream.close()
        raise
    except (OSError, RuntimeError, TimeoutError, ValueError) as exc:
        if stream is not None:
            stream.close()
        raise BrowserUiCdpError("browser_ui_cdp_websocket_unavailable") from exc


def _validate_command_policy(method: str, params: dict[str, JsonValue]) -> None:
    if method == "Page.setDownloadBehavior" and params != {"behavior": "deny"}:
        raise BrowserUiCdpError("browser_ui_cdp_download_forbidden")
    if method == "Target.createTarget" and params != {"url": "about:blank"}:
        raise BrowserUiCdpError("browser_ui_cdp_command_forbidden")
    if method == "Target.closeTarget":
        if set(params) != {"targetId"}:
            raise BrowserUiCdpError("browser_ui_cdp_command_invalid")
        _valid_identifier(params.get("targetId"), error="browser_ui_cdp_command_invalid")
    if method == "Page.navigate":
        _valid_navigation_url(params.get("url"))
    if method in {"Runtime.evaluate", "Runtime.callFunctionOn"}:
        source_key = "expression" if method == "Runtime.evaluate" else "functionDeclaration"
        source = params.get(source_key)
        if (
            not isinstance(source, str)
            or not source
            or len(source.encode("utf-8")) > MAX_EXPRESSION_BYTES
        ):
            raise BrowserUiCdpError("browser_ui_cdp_runtime_invalid")
    if method == "Runtime.callFunctionOn":
        arguments = params.get("arguments", [])
        if not isinstance(arguments, list):
            raise BrowserUiCdpError("browser_ui_cdp_runtime_invalid")
        for argument in arguments:
            if not isinstance(argument, dict) or set(argument) != {"value"}:
                raise BrowserUiCdpError("browser_ui_cdp_runtime_invalid")


class BrowserUiCdpChannel:
    """Bounded, allowlisted CDP message channel for one owned page.

    Instances are created by ``open_owned_browser_target``.  ``send_command``
    and ``receive_message`` support event-driven adapter state machines;
    ``command`` is the sequential request/response helper.  Each operation
    requires an absolute monotonic deadline, and the channel enforces fixed
    frame, message, JSON, and buffered-event limits.
    """

    def __init__(
        self,
        stream: socket.socket,
        allowed_methods: frozenset[str],
        *,
        role: str,
    ) -> None:
        self._stream = stream
        self._allowed_methods = allowed_methods
        self._role = role
        self._next_id = 1
        self._sent = 0
        self._received = 0
        self._buffered: deque[dict[str, Any]] = deque()
        self._closed = False

    def send_command(
        self,
        method: str,
        params: Mapping[str, JsonValue],
        *,
        deadline: float,
    ) -> int:
        """Send one allowlisted command and return its positive request ID."""

        _remaining(deadline)
        if self._closed:
            raise BrowserUiCdpError("browser_ui_cdp_disconnected")
        if not isinstance(method, str) or method not in self._allowed_methods:
            raise BrowserUiCdpError("browser_ui_cdp_command_forbidden")
        if not isinstance(params, Mapping):
            raise BrowserUiCdpError("browser_ui_cdp_command_invalid")
        normalized = dict(params)
        _validate_json_value(normalized)
        _validate_command_policy(method, normalized)
        if self._sent >= MAX_CHANNEL_MESSAGES or self._next_id > _MAX_SAFE_INTEGER:
            raise BrowserUiCdpError("browser_ui_cdp_message_limit")
        identifier = self._next_id
        payload = json.dumps(
            {"id": identifier, "method": method, "params": normalized},
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
        if len(payload) > _browser_cdp.CDP_MAX_FRAME_BYTES:
            raise BrowserUiCdpError("browser_ui_cdp_command_invalid")
        try:
            _set_socket_timeout(self._stream, deadline)
            _browser_cdp._send_frame(self._stream, 0x1, payload)
        except BrowserUiCdpError:
            raise
        except TimeoutError as exc:
            raise BrowserUiCdpError("browser_ui_cdp_timeout") from exc
        except (_browser_cdp.BrowserCdpError, OSError) as exc:
            raise BrowserUiCdpError("browser_ui_cdp_disconnected") from exc
        self._next_id += 1
        self._sent += 1
        return identifier

    def _receive_raw(self, *, deadline: float) -> dict[str, Any]:
        if self._closed:
            raise BrowserUiCdpError("browser_ui_cdp_disconnected")
        if self._received >= MAX_CHANNEL_MESSAGES:
            raise BrowserUiCdpError("browser_ui_cdp_message_limit")
        for _ in range(MAX_CONTROL_FRAMES + 1):
            opcode, payload = _recv_frame(self._stream, deadline=deadline)
            if opcode == 0x8:
                raise BrowserUiCdpError("browser_ui_cdp_disconnected")
            if opcode == 0x9:
                try:
                    _set_socket_timeout(self._stream, deadline)
                    _browser_cdp._send_frame(self._stream, 0xA, payload)
                except (_browser_cdp.BrowserCdpError, OSError, TimeoutError) as exc:
                    raise BrowserUiCdpError("browser_ui_cdp_disconnected") from exc
                continue
            if opcode == 0xA:
                continue
            if opcode != 0x1:
                raise BrowserUiCdpError("browser_ui_cdp_frame_invalid")
            try:
                message = json.loads(payload.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise BrowserUiCdpError("browser_ui_cdp_response_invalid") from exc
            if not isinstance(message, dict):
                raise BrowserUiCdpError("browser_ui_cdp_response_invalid")
            identifier = message.get("id")
            method = message.get("method")
            if identifier is not None and (
                isinstance(identifier, bool)
                or not isinstance(identifier, int)
                or identifier <= 0
                or not (isinstance(message.get("result"), dict) or isinstance(message.get("error"), dict))
            ):
                raise BrowserUiCdpError("browser_ui_cdp_response_invalid")
            if identifier is None and (
                not isinstance(method, str)
                or not method
                or not isinstance(message.get("params", {}), dict)
            ):
                raise BrowserUiCdpError("browser_ui_cdp_response_invalid")
            self._received += 1
            return message
        raise BrowserUiCdpError("browser_ui_cdp_control_frame_limit")

    def receive_message(self, *, deadline: float) -> dict[str, Any]:
        """Receive one response or event before an absolute deadline."""

        _remaining(deadline)
        if self._buffered:
            return self._buffered.popleft()
        return self._receive_raw(deadline=deadline)

    def command(
        self,
        method: str,
        params: Mapping[str, JsonValue],
        *,
        deadline: float,
    ) -> dict[str, Any]:
        """Run one command while retaining intervening events for the caller."""

        identifier = self.send_command(method, params, deadline=deadline)
        while True:
            message = self._receive_raw(deadline=deadline)
            response_id = message.get("id")
            if response_id == identifier:
                result = message.get("result")
                if "error" in message or not isinstance(result, dict):
                    raise BrowserUiCdpError("browser_ui_cdp_command_failed")
                return result
            if response_id is not None:
                raise BrowserUiCdpError("browser_ui_cdp_response_invalid")
            if message.get("method") == "Fetch.requestPaused":
                if len(self._buffered) >= MAX_BUFFERED_EVENTS:
                    raise BrowserUiCdpError("browser_ui_cdp_event_limit")
                self._buffered.append(message)

    def deny_downloads(self, *, deadline: float) -> None:
        """Set Chrome's page download behavior to deny."""

        self.command("Page.setDownloadBehavior", {"behavior": "deny"}, deadline=deadline)

    def navigate(
        self,
        url: str,
        *,
        deadline: float,
        referrer_policy: str = "noReferrer",
    ) -> NavigationResult:
        """Navigate the owned page to one validated HTTP(S) URL."""

        target = _valid_navigation_url(url)
        if referrer_policy not in _REFERRER_POLICIES:
            raise BrowserUiCdpError("browser_ui_cdp_navigation_invalid")
        self.deny_downloads(deadline=deadline)
        result = self.command(
            "Page.navigate",
            {"url": target, "referrerPolicy": referrer_policy},
            deadline=deadline,
        )
        if result.get("errorText") not in {None, ""}:
            error_text = result.get("errorText")
            suffix = (
                error_text.removeprefix("net::").casefold()
                if isinstance(error_text, str)
                and re.fullmatch(r"net::[A-Z0-9_]{1,128}", error_text)
                else "unknown"
            )
            raise BrowserUiCdpError(
                f"browser_ui_cdp_navigation_failed:{suffix}"
            )
        frame_id = _valid_identifier(
            result.get("frameId"), error="browser_ui_cdp_navigation_failed"
        )
        raw_loader_id = result.get("loaderId")
        loader_id = (
            None
            if raw_loader_id in {None, ""}
            else _valid_identifier(raw_loader_id, error="browser_ui_cdp_navigation_failed")
        )
        return NavigationResult(frame_id=frame_id, loader_id=loader_id)

    def cookies_for_url(self, url: str, *, deadline: float) -> dict[str, Any]:
        """Return the bounded raw cookie result for one exact HTTP(S) URL.

        This is deliberately limited to one caller-provided URL and uses the
        existing owned-page channel.  Callers remain responsible for checking
        the returned cookie records and must not log their values.
        """

        target = _valid_navigation_url(url)
        result = self.command(
            "Network.getCookies", {"urls": [target]}, deadline=deadline
        )
        _validate_json_value(result)
        return result

    def evaluate(
        self,
        expression: str,
        *,
        deadline: float,
        await_promise: bool = True,
    ) -> RuntimeValue:
        """Evaluate fixed adapter JavaScript and return a typed by-value result."""

        if not isinstance(await_promise, bool):
            raise BrowserUiCdpError("browser_ui_cdp_runtime_invalid")
        result = self.command(
            "Runtime.evaluate",
            {
                "expression": expression,
                "awaitPromise": await_promise,
                "returnByValue": True,
                "userGesture": False,
                "includeCommandLineAPI": False,
            },
            deadline=deadline,
        )
        return _runtime_value(result)

    def call_function(
        self,
        function_declaration: str,
        arguments: Sequence[JsonValue],
        *,
        deadline: float,
        await_promise: bool = True,
    ) -> RuntimeValue:
        """Call fixed adapter JavaScript with JSON values bound as arguments."""

        if isinstance(arguments, (str, bytes)) or not isinstance(arguments, Sequence):
            raise BrowserUiCdpError("browser_ui_cdp_runtime_invalid")
        if not isinstance(await_promise, bool):
            raise BrowserUiCdpError("browser_ui_cdp_runtime_invalid")
        typed_arguments: list[dict[str, JsonValue]] = []
        for argument in arguments:
            typed_arguments.append({"value": _validate_json_value(argument)})
        global_result = self.command(
            "Runtime.evaluate",
            {
                "expression": "globalThis",
                "awaitPromise": False,
                "returnByValue": False,
                "userGesture": False,
                "includeCommandLineAPI": False,
            },
            deadline=deadline,
        )
        if "exceptionDetails" in global_result:
            raise BrowserUiCdpError("browser_ui_cdp_runtime_failed")
        remote = global_result.get("result")
        object_id = remote.get("objectId") if isinstance(remote, dict) else None
        if not isinstance(object_id, str) or not object_id:
            raise BrowserUiCdpError("browser_ui_cdp_runtime_failed")
        active_error: BaseException | None = None
        try:
            result = self.command(
                "Runtime.callFunctionOn",
                {
                    "objectId": object_id,
                    "functionDeclaration": function_declaration,
                    "arguments": typed_arguments,
                    "awaitPromise": await_promise,
                    "returnByValue": True,
                    "userGesture": False,
                },
                deadline=deadline,
            )
            return _runtime_value(result)
        except BaseException as exc:
            active_error = exc
            raise
        finally:
            try:
                self.command(
                    "Runtime.releaseObject",
                    {"objectId": object_id},
                    deadline=deadline,
                )
            except BrowserUiCdpError:
                if active_error is None:
                    raise
                active_error.add_note("browser_ui_cdp_object_release_failed")

    def _close_transport(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            _browser_cdp._send_frame(self._stream, 0x8, b"")
        except (_browser_cdp.BrowserCdpError, OSError):
            pass
        try:
            self._stream.close()
        except OSError:
            pass


def _runtime_value(result: dict[str, Any]) -> RuntimeValue:
    if "exceptionDetails" in result:
        raise BrowserUiCdpError("browser_ui_cdp_runtime_failed")
    remote = result.get("result")
    if not isinstance(remote, dict) or "objectId" in remote or "unserializableValue" in remote:
        raise BrowserUiCdpError("browser_ui_cdp_runtime_failed")
    value_type = remote.get("type")
    subtype = remote.get("subtype")
    if not isinstance(value_type, str) or (
        subtype is not None and not isinstance(subtype, str)
    ):
        raise BrowserUiCdpError("browser_ui_cdp_runtime_failed")
    if value_type == "undefined" and "value" not in remote:
        value: JsonValue = None
    elif value_type in {"boolean", "number", "object", "string"} and "value" in remote:
        value = _validate_json_value(remote["value"])
    else:
        raise BrowserUiCdpError("browser_ui_cdp_runtime_failed")
    return RuntimeValue(type=value_type, subtype=subtype, value=value)


def _target_infos(result: dict[str, Any]) -> list[dict[str, Any]]:
    target_infos = result.get("targetInfos")
    if (
        not isinstance(target_infos, list)
        or len(target_infos) > MAX_TARGETS
        or not all(isinstance(info, dict) for info in target_infos)
    ):
        raise BrowserUiCdpError("browser_ui_cdp_target_state_invalid")
    return target_infos


class _BrowserTargetController:
    def __init__(
        self,
        channel: BrowserUiCdpChannel,
        cdp_url: str,
        port: int,
    ) -> None:
        self.channel = channel
        self.cdp_url = cdp_url
        self.port = port

    def create_blank_target(self, *, deadline: float) -> str:
        result = self.channel.command(
            "Target.createTarget", {"url": "about:blank"}, deadline=deadline
        )
        return _valid_identifier(
            result.get("targetId"), error="browser_ui_cdp_target_create_failed"
        )

    def _registry_has_target(self, target_id: str, *, deadline: float) -> bool:
        infos = _target_infos(
            self.channel.command("Target.getTargets", {}, deadline=deadline)
        )
        matches = [info for info in infos if info.get("targetId") == target_id]
        if len(matches) > 1:
            raise BrowserUiCdpError("browser_ui_cdp_target_state_invalid")
        return bool(matches)

    def target_descriptor(
        self,
        target_id: str,
        *,
        deadline: float,
    ) -> dict[str, Any]:
        while True:
            infos = _target_infos(
                self.channel.command("Target.getTargets", {}, deadline=deadline)
            )
            registry_matches = [
                info for info in infos if info.get("targetId") == target_id
            ]
            descriptors = _target_list(self.cdp_url, self.port, deadline=deadline)
            list_matches = [item for item in descriptors if item.get("id") == target_id]
            if len(registry_matches) > 1 or len(list_matches) > 1:
                raise BrowserUiCdpError("browser_ui_cdp_target_state_invalid")
            if registry_matches or list_matches:
                if not registry_matches or not list_matches:
                    time.sleep(min(0.02, _remaining(deadline)))
                    continue
                info = registry_matches[0]
                descriptor = list_matches[0]
                if (
                    info.get("type") != "page"
                    or info.get("url") != "about:blank"
                    or descriptor.get("type") != "page"
                    or descriptor.get("url") != "about:blank"
                ):
                    raise BrowserUiCdpError("browser_ui_cdp_target_state_invalid")
                return descriptor
            time.sleep(min(0.02, _remaining(deadline)))

    def close_target(self, target_id: str, *, deadline: float) -> None:
        target_id = _valid_identifier(
            target_id, error="browser_ui_cdp_target_close_failed"
        )
        registry_present = self._registry_has_target(target_id, deadline=deadline)
        descriptors = _target_list(self.cdp_url, self.port, deadline=deadline)
        listed = [item for item in descriptors if item.get("id") == target_id]
        if len(listed) > 1:
            raise BrowserUiCdpError("browser_ui_cdp_target_state_invalid")
        if registry_present:
            result = self.channel.command(
                "Target.closeTarget", {"targetId": target_id}, deadline=deadline
            )
            if result.get("success") is not True:
                raise BrowserUiCdpError("browser_ui_cdp_target_close_failed")
        while True:
            registry_present = self._registry_has_target(target_id, deadline=deadline)
            descriptors = _target_list(self.cdp_url, self.port, deadline=deadline)
            listed = [item for item in descriptors if item.get("id") == target_id]
            if len(listed) > 1:
                raise BrowserUiCdpError("browser_ui_cdp_target_state_invalid")
            if not registry_present and not listed:
                return
            time.sleep(min(0.02, _remaining(deadline)))

    def close_transport(self) -> None:
        self.channel._close_transport()


_RETAINED_UNCLOSED_TARGETS: list[object] = []


def _close_target_with_fresh_controller(
    cdp_url: str,
    port: int,
    target_id: str,
    *,
    deadline: float,
) -> None:
    browser_url = _browser_websocket(cdp_url, port, deadline=deadline)
    browser_stream = _open_websocket(browser_url, port=port, deadline=deadline)
    browser_channel = BrowserUiCdpChannel(
        browser_stream,
        _BROWSER_METHODS,
        role="browser-lifecycle-recovery",
    )
    controller = _BrowserTargetController(browser_channel, cdp_url, port)
    try:
        controller.close_target(target_id, deadline=deadline)
    finally:
        controller.close_transport()


def _close_target_over_http(
    cdp_url: str,
    port: int,
    target_id: str,
    *,
    deadline: float,
) -> None:
    target_id = _valid_identifier(
        target_id,
        error="browser_ui_cdp_target_close_failed",
    )
    initial_descriptors = _target_list(cdp_url, port, deadline=deadline)
    initial_matches = [
        item for item in initial_descriptors if item.get("id") == target_id
    ]
    if len(initial_matches) > 1:
        raise BrowserUiCdpError("browser_ui_cdp_target_state_invalid")
    if not initial_matches:
        _close_target_with_fresh_controller(
            cdp_url,
            port,
            target_id,
            deadline=deadline_after(_CLEANUP_SECONDS),
        )
        return
    scope = _browser_cdp._cdp_scope(port)
    path_id = urllib.parse.quote(target_id, safe="")
    request = urllib.request.Request(
        f"{cdp_url}/json/close/{path_id}",
        headers={"Accept": "application/json"},
        method="GET",
    )
    try:
        with open_scoped_url(
            scope,
            request,
            timeout=_remaining(deadline),
            max_redirects=0,
            transport=_browser_cdp._loopback_transport(scope),
        ) as response:
            if getattr(response, "status", None) != 200:
                raise BrowserUiCdpError("browser_ui_cdp_target_close_failed")
            payload = response.read(4_097)
            if not isinstance(payload, bytes) or len(payload) > 4_096:
                raise BrowserUiCdpError("browser_ui_cdp_target_close_failed")
    except BrowserUiCdpError:
        raise
    except (
        _browser_cdp.BrowserCdpError,
        OSError,
        RuntimeError,
        TimeoutError,
        ValueError,
    ) as exc:
        raise BrowserUiCdpError("browser_ui_cdp_target_close_failed") from exc
    while True:
        descriptors = _target_list(cdp_url, port, deadline=deadline)
        matches = [item for item in descriptors if item.get("id") == target_id]
        if len(matches) > 1:
            raise BrowserUiCdpError("browser_ui_cdp_target_state_invalid")
        if not matches:
            _close_target_with_fresh_controller(
                cdp_url,
                port,
                target_id,
                deadline=deadline_after(_CLEANUP_SECONDS),
            )
            return
        time.sleep(min(0.02, _remaining(deadline)))


class OwnedBrowserTarget:
    """One adapter-owned page and its confirmed browser-level lifecycle.

    Use this object as a context manager or call ``close`` with an absolute
    monotonic deadline.  The page and browser transports are closed only after
    Chrome confirms that ``target_id`` is absent.  If confirmation fails, the
    transports are retained and ``BrowserUiCdpError`` is raised so an armed
    Fetch session cannot be silently detached.
    """

    def __init__(
        self,
        controller: _BrowserTargetController,
        channel: BrowserUiCdpChannel,
        target_id: str,
    ) -> None:
        self._controller = controller
        self.channel = channel
        self.target_id = target_id
        self._closed = False
        self._retained = False

    @property
    def closed(self) -> bool:
        """Whether exact target absence has already been confirmed."""

        return self._closed

    def close(self, *, deadline: float) -> None:
        """Close the exact owned target and confirm absence before detaching."""

        if self._closed:
            return
        try:
            self._controller.close_target(self.target_id, deadline=deadline)
        except BrowserUiCdpError as primary_error:
            try:
                _close_target_with_fresh_controller(
                    self._controller.cdp_url,
                    self._controller.port,
                    self.target_id,
                    deadline=deadline_after(_CLEANUP_SECONDS),
                )
            except BrowserUiCdpError:
                try:
                    _close_target_over_http(
                        self._controller.cdp_url,
                        self._controller.port,
                        self.target_id,
                        deadline=deadline_after(_CLEANUP_SECONDS),
                    )
                except BrowserUiCdpError as recovery_error:
                    if not self._retained:
                        _RETAINED_UNCLOSED_TARGETS.append(self)
                        self._retained = True
                    raise recovery_error from primary_error
        self._closed = True
        self.channel._close_transport()
        self._controller.close_transport()
        if self._retained:
            _RETAINED_UNCLOSED_TARGETS.remove(self)
            self._retained = False

    def __enter__(self) -> "OwnedBrowserTarget":
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: object,
    ) -> bool:
        del exc_type, traceback
        try:
            self.close(deadline=deadline_after(_CLEANUP_SECONDS))
        except BrowserUiCdpError as cleanup_error:
            if exc_value is not None:
                raise cleanup_error from exc_value
            raise
        return False


def _open_page_channel(
    controller: _BrowserTargetController,
    target_id: str,
    *,
    deadline: float,
) -> BrowserUiCdpChannel:
    descriptor = controller.target_descriptor(target_id, deadline=deadline)
    websocket_url = _validate_websocket_url(
        descriptor.get("webSocketDebuggerUrl"),
        port=controller.port,
        path_prefix="/devtools/page/",
        exact_path=f"/devtools/page/{target_id}",
    )
    stream = _open_websocket(websocket_url, port=controller.port, deadline=deadline)
    return BrowserUiCdpChannel(stream, _PAGE_METHODS, role="page")


def _cleanup_failed_open(
    controller: _BrowserTargetController,
    target_id: str,
    page: BrowserUiCdpChannel | None,
    cause: BaseException,
) -> None:
    try:
        controller.close_target(target_id, deadline=deadline_after(_CLEANUP_SECONDS))
    except BrowserUiCdpError as cleanup_error:
        _RETAINED_UNCLOSED_TARGETS.append((controller, page, target_id))
        raise cleanup_error from cause
    if page is not None:
        page._close_transport()
    controller.close_transport()


def open_owned_browser_target(
    cdp_url: str,
    *,
    timeout_seconds: float = 10.0,
) -> OwnedBrowserTarget:
    """Create, open, and verify one download-denied ``about:blank`` target.

    Discovery and both WebSocket connections are restricted to the configured
    IPv4 loopback CDP port through Rookery's scoped transport.  Failure after
    target creation starts an independent bounded cleanup attempt.  If exact
    absence cannot be confirmed, that cleanup failure is raised and the live
    transports are retained rather than silently detached.

    Args:
        cdp_url: Exact ``http://127.0.0.1:<port>`` DevTools endpoint.
        timeout_seconds: Total create/open/verification budget, up to 60 seconds.

    Returns:
        Owned target with a bounded public page channel.

    Raises:
        BrowserUiCdpError: If discovery, creation, validation, download denial,
            or required cleanup fails.
    """

    deadline = deadline_after(timeout_seconds)
    try:
        normalized_url, port = resolve_browser_cdp_endpoint(cdp_url)
    except EnvironmentPolicyError as exc:
        raise BrowserUiCdpError("browser_ui_cdp_endpoint_invalid") from exc
    browser_url = _browser_websocket(normalized_url, port, deadline=deadline)
    browser_stream = _open_websocket(browser_url, port=port, deadline=deadline)
    browser_channel = BrowserUiCdpChannel(
        browser_stream,
        _BROWSER_METHODS,
        role="browser-lifecycle",
    )
    controller = _BrowserTargetController(browser_channel, normalized_url, port)
    target_id: str | None = None
    page: BrowserUiCdpChannel | None = None
    try:
        target_id = controller.create_blank_target(deadline=deadline)
        page = _open_page_channel(controller, target_id, deadline=deadline)
        target_info = page.command("Target.getTargetInfo", {}, deadline=deadline).get(
            "targetInfo"
        )
        if (
            not isinstance(target_info, dict)
            or target_info.get("targetId") != target_id
            or target_info.get("type") != "page"
            or target_info.get("url") != "about:blank"
        ):
            raise BrowserUiCdpError("browser_ui_cdp_target_state_invalid")
        page.deny_downloads(deadline=deadline)
        return OwnedBrowserTarget(controller, page, target_id)
    except BaseException as exc:
        if target_id is None:
            controller.close_transport()
        else:
            _cleanup_failed_open(controller, target_id, page, exc)
        raise


__all__ = [
    "BrowserUiCdpChannel",
    "BrowserUiCdpError",
    "JsonValue",
    "NavigationResult",
    "OwnedBrowserTarget",
    "RuntimeValue",
    "deadline_after",
    "open_owned_browser_target",
]
