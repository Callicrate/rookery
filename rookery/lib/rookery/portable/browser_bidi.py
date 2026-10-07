"""Bounded Firefox WebDriver BiDi access for adapter-owned browser sessions.

This module owns only the local protocol connection and read-only browser
primitives. Platform URLs, cookie reuse, and scoring authority stay with the
selected adapter.
"""

from __future__ import annotations

import json
import socket
import time
from typing import Any

from . import browser_cdp as _websocket
from . import browser_ui_cdp as _websocket_io
from .environment import EnvironmentPolicyError, resolve_browser_bidi_endpoint

BIDI_TIMEOUT_SECONDS = 5
BIDI_MAX_RESPONSE_FRAMES = 8
BIDI_MAX_COMMANDS = 16
BIDI_MAX_CONTEXTS = 128
BIDI_MAX_COOKIES = 256
BIDI_MAX_IDENTIFIER_BYTES = 512


class BrowserBidiError(RuntimeError):
    """A value-free failure of the local Firefox BiDi connection."""


def _identifier(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > BIDI_MAX_IDENTIFIER_BYTES
        or _websocket._has_control(value)
    ):
        raise BrowserBidiError("browser_bidi_response_invalid")
    return value


class FirefoxBidiSession:
    """One short-lived Firefox BiDi session on an exact loopback endpoint."""

    def __init__(self, endpoint: str) -> None:
        try:
            url, port = resolve_browser_bidi_endpoint(endpoint)
            stream = _websocket_io._open_websocket(
                url,
                port=port,
                deadline=time.monotonic() + BIDI_TIMEOUT_SECONDS,
            )
        except (EnvironmentPolicyError, _websocket_io.BrowserUiCdpError, OSError, RuntimeError, ValueError) as exc:
            raise BrowserBidiError("browser_bidi_unreachable") from exc
        self._stream: socket.socket = stream
        self._next_id = 1
        self._closed = False
        self._session_started = False
        try:
            result = self._command(
                "session.new",
                {"capabilities": {"alwaysMatch": {"browserName": "firefox"}}},
            )
            self._session_started = True
            capabilities = result.get("capabilities")
            if not isinstance(capabilities, dict) or capabilities.get("browserName") != "firefox":
                raise BrowserBidiError("browser_bidi_browser_invalid")
            _identifier(result.get("sessionId"))
        except BaseException:
            try:
                self.close()
            except BrowserBidiError:
                pass
            raise

    def _command(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        if self._closed or self._next_id > BIDI_MAX_COMMANDS:
            raise BrowserBidiError("browser_bidi_command_limit")
        identifier = self._next_id
        self._next_id += 1
        payload = json.dumps(
            {"id": identifier, "method": method, "params": params},
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
        if len(payload) > _websocket.CDP_MAX_FRAME_BYTES:
            raise BrowserBidiError("browser_bidi_command_invalid")
        try:
            deadline = time.monotonic() + BIDI_TIMEOUT_SECONDS
            _websocket_io._set_socket_timeout(self._stream, deadline)
            _websocket._send_frame(self._stream, 0x1, payload)
            for _ in range(BIDI_MAX_RESPONSE_FRAMES):
                opcode, frame = _websocket_io._recv_frame(self._stream, deadline=deadline)
                if opcode == 0x9:
                    _websocket._send_frame(self._stream, 0xA, frame)
                    continue
                if opcode == 0x8:
                    raise BrowserBidiError("browser_bidi_disconnected")
                if opcode != 0x1:
                    raise BrowserBidiError("browser_bidi_response_invalid")
                response = json.loads(frame.decode("utf-8"))
                if not isinstance(response, dict):
                    raise BrowserBidiError("browser_bidi_response_invalid")
                if response.get("type") == "event":
                    continue
                if response.get("id") != identifier:
                    raise BrowserBidiError("browser_bidi_response_invalid")
                if response.get("type") != "success" or not isinstance(response.get("result"), dict):
                    raise BrowserBidiError("browser_bidi_command_failed")
                return response["result"]
        except BrowserBidiError:
            raise
        except (OSError, TimeoutError) as exc:
            raise BrowserBidiError("browser_bidi_timeout") from exc
        except (_websocket.BrowserCdpError, _websocket_io.BrowserUiCdpError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise BrowserBidiError("browser_bidi_response_invalid") from exc
        raise BrowserBidiError("browser_bidi_response_missing")

    def contexts(self) -> list[dict[str, Any]]:
        """Return bounded top-level context descriptors without navigation."""

        result = self._command("browsingContext.getTree", {})
        contexts = result.get("contexts")
        if (
            not isinstance(contexts, list)
            or len(contexts) > BIDI_MAX_CONTEXTS
            or not all(isinstance(item, dict) for item in contexts)
        ):
            raise BrowserBidiError("browser_bidi_contexts_invalid")
        return contexts

    def user_agent(self, context: str) -> str:
        """Read Firefox's user agent in an isolated realm of one context."""

        result = self._command(
            "script.evaluate",
            {
                "expression": "navigator.userAgent",
                "target": {"context": _identifier(context), "sandbox": "rookery"},
                "awaitPromise": False,
            },
        )
        remote = result.get("result")
        value = remote.get("value") if isinstance(remote, dict) and remote.get("type") == "string" else None
        if (
            result.get("type") != "success"
            or not isinstance(value, str)
            or not value
            or len(value.encode("utf-8")) > _websocket.CDP_MAX_USER_AGENT_BYTES
            or _websocket._has_control(value)
        ):
            raise BrowserBidiError("browser_bidi_user_agent_invalid")
        return value

    def cookies(self, context: str) -> dict[str, Any]:
        """Read only the cookie partition of one selected browser context."""

        result = self._command(
            "storage.getCookies",
            {"partition": {"type": "context", "context": _identifier(context)}},
        )
        cookies = result.get("cookies")
        if (
            not isinstance(cookies, list)
            or len(cookies) > BIDI_MAX_COOKIES
            or not all(isinstance(item, dict) for item in cookies)
            or not isinstance(result.get("partitionKey"), dict)
        ):
            raise BrowserBidiError("browser_bidi_cookies_invalid")
        return result

    def close(self) -> None:
        """End the Firefox session so a later adapter operation can attach."""

        if self._closed:
            return
        failure: BrowserBidiError | None = None
        if self._session_started:
            try:
                self._command("session.end", {})
            except BrowserBidiError as exc:
                failure = exc
        self._closed = True
        try:
            _websocket._send_frame(self._stream, 0x8, b"")
        except (_websocket.BrowserCdpError, OSError):
            pass
        try:
            self._stream.close()
        except OSError:
            pass
        if failure is not None:
            raise BrowserBidiError("browser_bidi_session_end_failed") from failure

    def __enter__(self) -> FirefoxBidiSession:
        return self

    def __exit__(self, exc_type: object, exc_value: object, traceback: object) -> bool:
        del exc_type, exc_value, traceback
        self.close()
        return False


def verify_browser_bidi_endpoint(value: str | None) -> None:
    """Require an available Firefox BiDi service on exact IPv4 loopback."""

    try:
        with FirefoxBidiSession(value or ""):
            pass
    except BrowserBidiError as exc:
        raise EnvironmentPolicyError(str(exc)) from exc
