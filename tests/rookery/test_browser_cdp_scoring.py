from __future__ import annotations

import base64
import datetime
import hashlib
import json
import os
import select
import socket
import socketserver
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.request
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from tests.rookery.support import ROOKERY_ROOT

LIB = ROOKERY_ROOT / "lib"
if str(LIB) not in sys.path:
    sys.path.insert(0, str(LIB))

# ruff: noqa: E402
from rookery.portable.browser_cdp_scoring import (
    BrowserCdpScoringError,
    BrowserScoringBinding,
    CTFdReadOnlyRequest,
    CTFdScoringAction,
    bootstrap_owned_browser_target,
    execute_ctfd_browser_read,
    execute_ctfd_browser_scoring,
    prepare_browser_scoring_binding,
    preflight_ctfd_browser_scoring,
)


class _ScriptedCdp:
    def __init__(
        self,
        *,
        response_document: dict[str, Any] | None = None,
        request_url: str = "https://ctf.example/api/v1/challenges/attempt",
        response_url: str = "https://ctf.example/api/v1/challenges/attempt",
        response_status: int = 200,
        response_headers: list[dict[str, str]] | None = None,
        response_body: str | None = None,
        response_base64: bool = False,
        runtime_value: dict[str, Any] | None = None,
        extra_targets: list[dict[str, Any]] | None = None,
        event_after_commit: dict[str, Any] | None = None,
        disconnect_after_commit: bool = False,
        timeout_after_commit: bool = False,
        discover_bound_event: bool = False,
        tamper_post_data: bool = False,
        target_info: dict[str, Any] | None = None,
        second_paused_request: bool = False,
        timeout_after_trigger: bool = False,
    ) -> None:
        self.next_id = 1
        self.messages: deque[dict[str, Any] | BaseException] = deque()
        self.commands: list[tuple[int, str, dict[str, Any]]] = []
        self.call_id: int | None = None
        self.request_url = request_url
        self.response_url = response_url
        self.response_status = response_status
        self.response_headers = response_headers or [
            {"name": "Content-Type", "value": "application/json"},
            {"name": "Set-Cookie", "value": "must-not-be-retained=1"},
        ]
        document = response_document or {
            "success": True,
            "data": {"status": "correct"},
        }
        self.response_body = response_body or json.dumps(document)
        self.response_base64 = response_base64
        self.runtime_value = runtime_value or {
            "url": response_url,
            "status": response_status,
            "redirected": False,
            "type": "basic",
            "contentType": "application/json",
        }
        self.extra_targets = extra_targets or []
        self.event_after_commit = event_after_commit
        self.disconnect_after_commit = disconnect_after_commit
        self.timeout_after_commit = timeout_after_commit
        self.discover_bound_event = discover_bound_event
        self.tamper_post_data = tamper_post_data
        self.active_method = "GET"
        self.target_info = target_info or self._binding_target()
        self.second_paused_request = second_paused_request
        self.timeout_after_trigger = timeout_after_trigger

    @staticmethod
    def _binding_target() -> dict[str, Any]:
        return {
            "targetId": "target-1",
            "type": "page",
            "url": "https://ctf.example/challenges",
            "browserContextId": "context-1",
        }

    def _response(self, identifier: int, result: dict[str, Any]) -> None:
        self.messages.append({"id": identifier, "result": result})

    def send_command(self, method: str, params: dict[str, Any]) -> int:
        identifier = self.next_id
        self.next_id += 1
        self.commands.append((identifier, method, params))
        if method == "Target.getTargetInfo":
            self._response(identifier, {"targetInfo": self.target_info})
        elif method == "Target.getTargets":
            self._response(
                identifier,
                {"targetInfos": [self.target_info, *self.extra_targets]},
            )
        elif method == "Runtime.evaluate":
            self._response(identifier, {"result": {"objectId": "global-object"}})
        elif method == "Target.setDiscoverTargets" and self.discover_bound_event:
            self.messages.append(
                {
                    "method": "Target.targetCreated",
                    "params": {"targetInfo": self.target_info},
                }
            )
            self._response(identifier, {})
        elif method == "Runtime.callFunctionOn":
            self.call_id = identifier
            request_method = params["arguments"][1]["value"]
            self.active_method = request_method
            body = params["arguments"][2]["value"]
            csrf = params["arguments"][3]["value"]
            accept = params["arguments"][4]["value"]
            headers = {"Accept": accept}
            if body is not None:
                headers["Content-Type"] = "application/json"
                headers["Origin"] = "https://ctf.example"
            if csrf:
                headers["CSRF-Token"] = csrf
            if self.timeout_after_trigger:
                self.messages.append(TimeoutError("fixture trigger timeout"))
            else:
                self.messages.append(
                    {
                        "method": "Fetch.requestPaused",
                        "params": {
                            "requestId": "fetch-1",
                            "frameId": "frame-1",
                            "resourceType": "Fetch",
                            "request": {
                                "url": self.request_url,
                                "method": request_method,
                                "headers": headers,
                                **(
                                    {"postData": body + " " if self.tamper_post_data else body}
                                    if body is not None
                                    else {}
                                ),
                            },
                        },
                    }
                )
        elif method == "Fetch.continueRequest":
            self._response(identifier, {})
            if self.second_paused_request:
                self.messages.append(
                    {
                        "method": "Fetch.requestPaused",
                        "params": {
                            "requestId": "fetch-background",
                            "frameId": "frame-1",
                            "resourceType": "XHR",
                            "request": {
                                "url": "https://ctf.example/api/v1/challenges/attempt",
                                "method": "POST",
                                "headers": {
                                    "Accept": "application/json",
                                    "Content-Type": "application/json",
                                    "Origin": "https://ctf.example",
                                },
                                "postData": '{"challenge_id":99,"submission":"background"}',
                            },
                        },
                    }
                )
            elif self.disconnect_after_commit:
                self.messages.append(EOFError("fixture disconnect"))
            elif self.timeout_after_commit:
                self.messages.append(TimeoutError("fixture timeout"))
            elif self.event_after_commit is not None:
                self.messages.append(self.event_after_commit)
            else:
                self.messages.append(
                    {
                        "method": "Fetch.requestPaused",
                        "params": {
                            "requestId": "fetch-1",
                            "frameId": "frame-1",
                            "resourceType": "Fetch",
                            "request": {
                                "url": self.response_url,
                                "method": self.active_method,
                                "headers": {},
                            },
                            "responseStatusCode": self.response_status,
                            "responseHeaders": self.response_headers,
                        },
                    }
                )
        elif method == "Fetch.getResponseBody":
            body = self.response_body
            if self.response_base64:
                body = base64.b64encode(body.encode("utf-8")).decode("ascii")
            self._response(
                identifier,
                {"body": body, "base64Encoded": self.response_base64},
            )
        elif method == "Fetch.continueResponse":
            self._response(identifier, {})
            if self.call_id is None:
                raise AssertionError("runtime call was not sent")
            self._response(
                self.call_id,
                {"result": {"type": "object", "value": self.runtime_value}},
            )
        elif method == "Fetch.failRequest":
            self._response(identifier, {})
        else:
            self._response(identifier, {})
        return identifier

    def receive_message(self, timeout_seconds: float) -> dict[str, Any]:
        if timeout_seconds <= 0 or not self.messages:
            raise TimeoutError("fixture timeout")
        message = self.messages.popleft()
        if isinstance(message, BaseException):
            raise message
        return message


class _PrepareCdp:
    def __init__(
        self,
        *,
        targets: list[dict[str, Any]],
        current: dict[str, Any] | None = None,
        frame_id: str = "frame-1",
        unique_context_id: str = "isolated-world-1",
        existing_world: bool = False,
        event_before_response: bool = True,
    ) -> None:
        self.targets = targets
        self.current = current or (targets[0] if targets else {})
        self.frame_id = frame_id
        self.unique_context_id = unique_context_id
        self.existing_world = existing_world
        self.event_before_response = event_before_response
        self.messages: deque[dict[str, Any]] = deque()
        self.commands: list[tuple[int, str, dict[str, Any]]] = []
        self.next_id = 1

    def _context(self, identifier: int = 77) -> dict[str, Any]:
        return {
            "id": identifier,
            "origin": "https://ctf.example",
            "name": "rookery-browser-scoring",
            "uniqueId": self.unique_context_id,
            "auxData": {
                "isDefault": False,
                "type": "isolated",
                "frameId": self.frame_id,
            },
        }

    def send_command(self, method: str, params: dict[str, Any]) -> int:
        identifier = self.next_id
        self.next_id += 1
        self.commands.append((identifier, method, params))
        if method == "Target.getTargets":
            result = {"targetInfos": self.targets}
        elif method == "Target.getTargetInfo":
            result = {"targetInfo": self.current}
        elif method == "Page.getFrameTree":
            result = {
                "frameTree": {
                    "frame": {
                        "id": self.frame_id,
                        "url": self.current.get("url"),
                    }
                }
            }
        elif method == "Runtime.enable":
            if self.existing_world:
                self.messages.append(
                    {
                        "method": "Runtime.executionContextCreated",
                        "params": {"context": self._context()},
                    }
                )
            result = {}
        elif method == "Page.createIsolatedWorld":
            event = {
                "method": "Runtime.executionContextCreated",
                "params": {"context": self._context()},
            }
            response = {"id": identifier, "result": {"executionContextId": 77}}
            if self.event_before_response:
                self.messages.extend((event, response))
            else:
                self.messages.extend((response, event))
            return identifier
        else:
            result = {}
        self.messages.append({"id": identifier, "result": result})
        return identifier

    def receive_message(self, timeout_seconds: float) -> dict[str, Any]:
        if timeout_seconds <= 0 or not self.messages:
            raise TimeoutError("fixture timeout")
        return self.messages.popleft()


class _BootstrapCdp(_PrepareCdp):
    def __init__(self, *, response_status: int = 200) -> None:
        target = {
            "targetId": "target-owned",
            "type": "page",
            "url": "about:blank",
            "browserContextId": "context-1",
        }
        super().__init__(targets=[target], current=target)
        self.response_status = response_status
        self.account_url = "https://ctf.example/api/v1/users/me"

    def send_command(self, method: str, params: dict[str, Any]) -> int:
        if method not in {
            "Page.setDownloadBehavior",
            "Network.enable",
            "Network.setBypassServiceWorker",
            "Network.setCacheDisabled",
            "Page.enable",
            "Fetch.enable",
            "Page.navigate",
            "Fetch.continueRequest",
            "Fetch.getResponseBody",
            "Fetch.continueResponse",
            "Page.disable",
            "Network.disable",
        }:
            return super().send_command(method, params)
        identifier = self.next_id
        self.next_id += 1
        self.commands.append((identifier, method, params))
        if method == "Page.navigate":
            self.messages.extend(
                (
                    {
                        "id": identifier,
                        "result": {
                            "frameId": self.frame_id,
                            "loaderId": "loader-bootstrap",
                        },
                    },
                    {
                        "method": "Network.requestWillBeSent",
                        "params": {
                            "requestId": "network-bootstrap",
                            "frameId": self.frame_id,
                            "type": "Document",
                            "request": {"url": self.account_url, "method": "GET"},
                        },
                    },
                    {
                        "method": "Fetch.requestPaused",
                        "params": {
                            "requestId": "fetch-bootstrap",
                            "networkId": "network-bootstrap",
                            "frameId": self.frame_id,
                            "resourceType": "Document",
                            "request": {"url": self.account_url, "method": "GET"},
                        },
                    },
                )
            )
            return identifier
        if method == "Fetch.continueRequest":
            self.messages.extend(
                (
                    {"id": identifier, "result": {}},
                    {
                        "method": "Fetch.requestPaused",
                        "params": {
                            "requestId": "fetch-bootstrap",
                            "networkId": "network-bootstrap",
                            "frameId": self.frame_id,
                            "resourceType": "Document",
                            "request": {"url": self.account_url, "method": "GET"},
                            "responseStatusCode": self.response_status,
                            "responseHeaders": [
                                {
                                    "name": "Content-Type",
                                    "value": "application/json",
                                }
                            ],
                        },
                    },
                )
            )
            return identifier
        if method == "Fetch.getResponseBody":
            self.messages.append(
                {
                    "id": identifier,
                    "result": {
                        "body": '{"success":true,"data":{"id":7}}',
                        "base64Encoded": False,
                    },
                }
            )
            return identifier
        if method == "Fetch.continueResponse":
            self.current = {**self.current, "url": self.account_url}
            self.targets = [self.current]
            self.messages.extend(
                (
                    {"id": identifier, "result": {}},
                    {
                        "method": "Network.responseReceived",
                        "params": {"requestId": "network-bootstrap"},
                    },
                    {
                        "method": "Network.dataReceived",
                        "params": {"requestId": "network-bootstrap"},
                    },
                    {
                        "method": "Network.loadingFinished",
                        "params": {"requestId": "network-bootstrap"},
                    },
                    {
                        "method": "Page.frameNavigated",
                        "params": {"frame": {"id": self.frame_id, "url": self.account_url}},
                    },
                    {"method": "Page.domContentEventFired", "params": {}},
                    {"method": "Page.loadEventFired", "params": {}},
                )
            )
            return identifier
        self.messages.append({"id": identifier, "result": {}})
        return identifier


class _SocketCdp:
    def __init__(self, websocket_url: str, *, origin: str) -> None:
        import websocket

        self._websocket_module = websocket
        self._socket = websocket.create_connection(
            websocket_url,
            timeout=5,
            origin=origin,
            enable_multithread=False,
        )
        self._next_id = 1

    def send_command(self, method: str, params: dict[str, Any]) -> int:
        identifier = self._next_id
        self._next_id += 1
        self._socket.send(
            json.dumps(
                {"id": identifier, "method": method, "params": params},
                separators=(",", ":"),
            )
        )
        return identifier

    def receive_message(self, timeout_seconds: float) -> dict[str, Any]:
        self._socket.settimeout(timeout_seconds)
        try:
            payload = self._socket.recv()
        except self._websocket_module.WebSocketTimeoutException as exc:
            raise TimeoutError("CDP receive timed out") from exc
        if not isinstance(payload, str):
            raise OSError("CDP returned a non-text frame")
        value = json.loads(payload)
        if not isinstance(value, dict):
            raise OSError("CDP returned a non-object message")
        return value

    def command(self, method: str, params: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        identifier = self.send_command(method, params)
        events: list[dict[str, Any]] = []
        deadline = time.monotonic() + 5
        while True:
            message = self.receive_message(deadline - time.monotonic())
            if message.get("id") == identifier:
                if "error" in message or not isinstance(message.get("result"), dict):
                    raise RuntimeError(f"CDP command failed: {method}")
                return message["result"], events
            events.append(message)

    def drain(self) -> None:
        while True:
            try:
                self.receive_message(0.05)
            except TimeoutError:
                return

    def close(self) -> None:
        self._socket.close()


class _LoopbackConnectProxy(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def _proxy_handler(
    *, target_port: int, counters: dict[str, int], lock: threading.Lock
) -> type[socketserver.BaseRequestHandler]:
    class Handler(socketserver.BaseRequestHandler):
        def handle(self) -> None:
            data = bytearray()
            while b"\r\n\r\n" not in data and len(data) <= 8192:
                chunk = self.request.recv(1024)
                if not chunk:
                    return
                data.extend(chunk)
            first = bytes(data).split(b"\r\n", 1)[0]
            expected = f"CONNECT ctfd.localhost:{target_port} HTTP/1.1".encode("ascii")
            if first != expected:
                with lock:
                    counters["rejected"] += 1
                self.request.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                return
            with socket.create_connection(("127.0.0.1", target_port), timeout=5) as upstream:
                with lock:
                    counters["accepted"] += 1
                self.request.sendall(b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: rookery-test\r\n\r\n")
                sockets = (self.request, upstream)
                while True:
                    readable, _writable, _exceptional = select.select(sockets, (), sockets, 5)
                    if not readable:
                        return
                    for source in readable:
                        destination = upstream if source is self.request else self.request
                        try:
                            payload = source.recv(64 * 1024)
                        except (ConnectionResetError, OSError):
                            return
                        if not payload:
                            return
                        try:
                            destination.sendall(payload)
                        except (ConnectionResetError, OSError):
                            return

    return Handler


def _https_handler(
    *, counters: dict[str, int], lock: threading.Lock, behavior: dict[str, bool]
) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"

        def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract.
            with lock:
                counters[self.path] = counters.get(self.path, 0) + 1
            if self.path == "/challenges":
                body = b"<html><body>fixture</body></html>"
                content_type = "text/html"
            elif self.path == "/api/v1/challenges":
                body = b'{"success":true,"data":[]}'
                content_type = "application/json"
            elif self.path == "/api/v1/users/me":
                if behavior.get("redirect_account", False):
                    self.send_response(302)
                    self.send_header("Location", "/redirect-sink")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                body = b'{"success":true,"data":{"id":7}}'
                content_type = "application/json"
            elif self.path == "/redirect-sink":
                body = b'{"unexpected":true}'
                content_type = "application/json"
            else:
                body = b'{"success":false}'
                content_type = "application/json"
            self.send_response(
                200
                if self.path
                in {
                    "/challenges",
                    "/api/v1/challenges",
                    "/api/v1/users/me",
                    "/redirect-sink",
                }
                else 404
            )
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract.
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                length = -1
            if not 0 <= length <= 64 * 1024:
                self.send_error(413)
                return
            body = self.rfile.read(length)
            with lock:
                counters[self.path] = counters.get(self.path, 0) + 1
            try:
                document = json.loads(body.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                document = None
            valid = (
                self.path == "/api/v1/challenges/attempt"
                and isinstance(document, dict)
                and document.get("challenge_id") == 41
                and document.get("submission") == "flag{fixture-only}"
            )
            response = b'{"success":true,"data":{"correct":false}}' if valid else b'{"success":false}'
            if valid:
                time.sleep(0.2)
            self.send_response(200 if valid else 400)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            try:
                self.wfile.write(response)
            except (BrokenPipeError, ConnectionResetError, OSError):
                return

        def log_message(self, format: str, *args: object) -> None:
            return

    return Handler


def _free_high_port() -> int:
    for port in range(19011, 19111):
        with socket.socket() as listener:
            try:
                listener.bind(("127.0.0.1", port))
            except OSError:
                continue
            return port
    raise RuntimeError("could not reserve a high loopback port")


def _chrome_path() -> Path | None:
    candidates = (
        Path(os.environ.get("PROGRAMFILES", "")) / "Google/Chrome/Application/chrome.exe",
        Path(os.environ.get("LOCALAPPDATA", "")) / "Google/Chrome/Application/chrome.exe",
    )
    return next((candidate for candidate in candidates if candidate.is_file()), None)


def _write_fixture_certificate(directory: Path) -> tuple[Path, Path, str]:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ctfd.localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(hours=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("ctfd.localhost")]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    key_path = directory / "fixture-key.pem"
    certificate_path = directory / "fixture-cert.pem"
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    certificate_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    spki = key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    pin = base64.b64encode(hashlib.sha256(spki).digest()).decode("ascii")
    return certificate_path, key_path, pin


def _read_loopback_json(url: str) -> Any:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(url, timeout=2) as response:
        return json.loads(response.read(256 * 1024).decode("utf-8"))


def _wait_until(predicate: Any, *, timeout: float = 10.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.05)
    raise TimeoutError("fixture condition was not reached")


def _binding(**overrides: str) -> BrowserScoringBinding:
    values = {
        "origin": "https://ctf.example",
        "page_url": "https://ctf.example/challenges",
        "target_id": "target-1",
        "browser_context_id": "context-1",
        "frame_id": "frame-1",
        "execution_context_unique_id": "isolated-world-1",
        "gateway_policy_sha256": "a" * 64,
    }
    values.update(overrides)
    return BrowserScoringBinding(**values)


def _action(
    *,
    candidate: str = "flag{typed-secret}",
    csrf_token: str | None = "fixture.csrf-token-1234",
    max_response_bytes: int = 262_144,
) -> CTFdScoringAction:
    return CTFdScoringAction(
        binding=_binding(),
        challenge_id=41,
        candidate=candidate,
        csrf_token=csrf_token,
        max_response_bytes=max_response_bytes,
    )


def _close_ok(target_id: str, timeout_seconds: float) -> bool:
    return bool(target_id) and timeout_seconds > 0


def _run_read(channel: Any, request: CTFdReadOnlyRequest) -> Any:
    return execute_ctfd_browser_read(channel, request, close_owned_target=_close_ok)


def _run_scoring(channel: Any, action: CTFdScoringAction) -> Any:
    return execute_ctfd_browser_scoring(channel, action, close_owned_target=_close_ok)


class BrowserCdpScoringTests(unittest.TestCase):
    def test_bootstrap_arms_controls_before_exact_account_navigation(self) -> None:
        channel = _BootstrapCdp()
        closed: list[str] = []

        def close_target(target_id: str, _timeout: float) -> bool:
            closed.append(target_id)
            return True

        result = bootstrap_owned_browser_target(
            channel,
            "https://ctf.example",
            "a" * 64,
            "target-owned",
            close_owned_target=close_target,
        )

        self.assertEqual(result.account_document["data"]["id"], 7)
        self.assertEqual(result.binding.target_id, "target-owned")
        self.assertEqual(result.binding.page_url, channel.account_url)
        self.assertEqual(closed, [])
        methods = [method for _id, method, _params in channel.commands]
        navigate_index = methods.index("Page.navigate")
        for required in (
            "Page.setDownloadBehavior",
            "Network.setBypassServiceWorker",
            "Network.setCacheDisabled",
            "Fetch.enable",
        ):
            self.assertLess(methods.index(required), navigate_index)
        navigate = next(params for _id, method, params in channel.commands if method == "Page.navigate")
        self.assertEqual(navigate["url"], channel.account_url)

    def test_bootstrap_closes_owned_target_before_following_redirect(self) -> None:
        channel = _BootstrapCdp(response_status=302)
        closed: list[str] = []

        def close_target(target_id: str, _timeout: float) -> bool:
            closed.append(target_id)
            return True

        with self.assertRaises(BrowserCdpScoringError) as caught:
            bootstrap_owned_browser_target(
                channel,
                "https://ctf.example",
                "a" * 64,
                "target-owned",
                close_owned_target=close_target,
            )

        self.assertEqual(caught.exception.reason, "browser_request_interception_mismatch")
        self.assertTrue(caught.exception.committed)
        self.assertEqual(closed, ["target-owned"])
        methods = [method for _id, method, _params in channel.commands]
        self.assertNotIn("Fetch.continueResponse", methods)
        self.assertNotIn("Fetch.disable", methods)

    def test_prepare_derives_ephemeral_binding_without_network_commands(self) -> None:
        target = _ScriptedCdp._binding_target()
        channel = _PrepareCdp(targets=[target])

        binding = prepare_browser_scoring_binding(channel, "https://ctf.example", "a" * 64)

        self.assertEqual(binding.target_id, "target-1")
        self.assertEqual(binding.browser_context_id, "context-1")
        self.assertEqual(binding.frame_id, "frame-1")
        self.assertEqual(binding.execution_context_unique_id, "isolated-world-1")
        methods = [method for _id, method, _params in channel.commands]
        self.assertEqual(
            methods,
            [
                "Target.getTargets",
                "Target.getTargetInfo",
                "Page.getFrameTree",
                "Runtime.enable",
                "Page.createIsolatedWorld",
                "Runtime.disable",
            ],
        )
        self.assertFalse(any(method.startswith(("Fetch.", "Network.")) for method in methods))
        self.assertNotIn("Runtime.evaluate", methods)

    def test_prepare_reuses_one_existing_fixed_isolated_world(self) -> None:
        channel = _PrepareCdp(targets=[_ScriptedCdp._binding_target()], existing_world=True)

        binding = prepare_browser_scoring_binding(channel, "https://ctf.example", "b" * 64)

        self.assertEqual(binding.execution_context_unique_id, "isolated-world-1")
        self.assertNotIn(
            "Page.createIsolatedWorld",
            [method for _id, method, _params in channel.commands],
        )

    def test_prepare_binds_owned_target_and_preserves_same_origin_source(self) -> None:
        source = _ScriptedCdp._binding_target()
        owned = {
            **source,
            "targetId": "target-owned",
            "url": "https://ctf.example/api/v1/users/me",
        }
        channel = _PrepareCdp(targets=[source, owned], current=owned)

        binding = prepare_browser_scoring_binding(
            channel,
            "https://ctf.example",
            "b" * 64,
            owned_target_id="target-owned",
        )

        self.assertEqual(binding.target_id, "target-owned")
        self.assertEqual(binding.page_url, "https://ctf.example/api/v1/users/me")

    def test_prepare_rejects_zero_or_multiple_exact_origin_pages(self) -> None:
        cases = (
            ([], "browser_target_missing"),
            (
                [
                    _ScriptedCdp._binding_target(),
                    {
                        **_ScriptedCdp._binding_target(),
                        "targetId": "target-2",
                        "browserContextId": "context-2",
                    },
                ],
                "browser_target_ambiguous",
            ),
        )
        for targets, reason in cases:
            with self.subTest(reason=reason):
                channel = _PrepareCdp(targets=targets)
                with self.assertRaises(BrowserCdpScoringError) as caught:
                    prepare_browser_scoring_binding(channel, "https://ctf.example", "c" * 64)
                self.assertEqual(caught.exception.reason, reason)
                self.assertFalse(caught.exception.committed)

    def test_prepare_rejects_wrong_origin_or_current_context(self) -> None:
        correct = _ScriptedCdp._binding_target()
        cases = (
            _PrepareCdp(
                targets=[
                    {
                        **correct,
                        "url": "https://elsewhere.example/challenges",
                    }
                ]
            ),
            _PrepareCdp(
                targets=[correct],
                current={**correct, "browserContextId": "context-other"},
            ),
        )
        expected = ("browser_target_missing", "browser_target_binding_mismatch")
        for channel, reason in zip(cases, expected, strict=True):
            with self.subTest(reason=reason):
                with self.assertRaises(BrowserCdpScoringError) as caught:
                    prepare_browser_scoring_binding(channel, "https://ctf.example", "d" * 64)
                self.assertEqual(caught.exception.reason, reason)

    def test_prepare_supports_a_proxy_bound_default_browser_context(self) -> None:
        target = _ScriptedCdp._binding_target()
        target.pop("browserContextId")
        channel = _PrepareCdp(targets=[target])

        binding = prepare_browser_scoring_binding(channel, "https://ctf.example", "e" * 64)

        self.assertIsNone(binding.browser_context_id)

    def test_default_context_omits_context_id_from_browser_commands(self) -> None:
        target = _ScriptedCdp._binding_target()
        target.pop("browserContextId")
        binding = BrowserScoringBinding(
            origin="https://ctf.example",
            page_url="https://ctf.example/challenges",
            target_id="target-1",
            browser_context_id=None,
            frame_id="frame-1",
            execution_context_unique_id="isolated-world-1",
            gateway_policy_sha256="e" * 64,
        )
        channel = _ScriptedCdp(
            target_info=target,
            request_url="https://ctf.example/api/v1/challenges",
            response_url="https://ctf.example/api/v1/challenges",
        )

        result = _run_read(
            channel,
            CTFdReadOnlyRequest(binding=binding, operation="inventory"),
        )

        self.assertEqual(result.document, {"success": True, "data": {"status": "correct"}})
        download_commands = [
            params for _id, method, params in channel.commands if method == "Browser.setDownloadBehavior"
        ]
        self.assertEqual(download_commands, [])

    def test_old_binding_fails_after_browser_restart_and_fresh_prepare_succeeds(
        self,
    ) -> None:
        first_target = _ScriptedCdp._binding_target()
        first = prepare_browser_scoring_binding(
            _PrepareCdp(targets=[first_target]),
            "https://ctf.example",
            "f" * 64,
        )
        second_target = {
            **first_target,
            "targetId": "target-restarted",
            "browserContextId": "context-restarted",
        }
        restarted = _PrepareCdp(
            targets=[second_target],
            frame_id="frame-restarted",
            unique_context_id="isolated-restarted",
        )

        with self.assertRaises(BrowserCdpScoringError):
            preflight_ctfd_browser_scoring(restarted, first)
        fresh = prepare_browser_scoring_binding(restarted, "https://ctf.example", "f" * 64)

        self.assertEqual(fresh.target_id, "target-restarted")
        self.assertEqual(fresh.frame_id, "frame-restarted")
        self.assertNotEqual(fresh, first)

    def test_preflight_is_read_only_and_requires_one_bound_target(self) -> None:
        channel = _ScriptedCdp()

        proof = preflight_ctfd_browser_scoring(channel, _binding())

        self.assertEqual(proof.target_id, "target-1")
        self.assertEqual(
            [method for _id, method, _params in channel.commands],
            ["Target.getTargetInfo", "Target.getTargets"],
        )

    def test_preflight_rejects_an_extra_worker_in_the_bound_context(self) -> None:
        channel = _ScriptedCdp(
            extra_targets=[
                {
                    "targetId": "worker-1",
                    "type": "service_worker",
                    "url": "https://ctf.example/sw.js",
                    "browserContextId": "context-1",
                    "openerId": "target-1",
                }
            ]
        )

        with self.assertRaises(BrowserCdpScoringError) as caught:
            preflight_ctfd_browser_scoring(channel, _binding())

        self.assertEqual(caught.exception.reason, "browser_target_binding_mismatch")
        self.assertFalse(caught.exception.committed)

    def test_happy_path_uses_fixed_source_and_typed_arguments(self) -> None:
        candidate = 'flag{quote"-and-${not-code}}'
        csrf = "fixture.csrf-token-1234"
        channel = _ScriptedCdp(discover_bound_event=True)

        result = _run_scoring(channel, _action(candidate=candidate, csrf_token=csrf))

        self.assertEqual(result.verdict["verdict"], "accepted")
        self.assertNotIn("set-cookie", result.response["headers"])
        call = next(params for _id, method, params in channel.commands if method == "Runtime.callFunctionOn")
        self.assertNotIn(candidate, call["functionDeclaration"])
        self.assertNotIn(csrf, call["functionDeclaration"])
        self.assertEqual(call["arguments"][1], {"value": "POST"})
        self.assertEqual(
            json.loads(call["arguments"][2]["value"]),
            {"challenge_id": 41, "submission": candidate},
        )
        self.assertEqual(call["arguments"][3], {"value": csrf})
        methods = [method for _id, method, _params in channel.commands]
        self.assertIn("Network.setBypassServiceWorker", methods)
        self.assertIn("Network.setCacheDisabled", methods)
        self.assertIn("Fetch.enable", methods)
        self.assertIn("Fetch.continueRequest", methods)
        evaluate = next(params for _id, method, params in channel.commands if method == "Runtime.evaluate")
        self.assertEqual(evaluate["uniqueContextId"], "isolated-world-1")

    def test_structured_rejection_outranks_wrapper_success(self) -> None:
        channel = _ScriptedCdp(response_document={"success": True, "data": {"correct": False}})

        result = _run_scoring(channel, _action())

        self.assertEqual(result.verdict["verdict"], "rejected")
        self.assertEqual(result.verdict["scorer_truth"], "rejected")

    def test_duplicate_set_cookie_headers_are_ignored_for_read_and_post(self) -> None:
        headers = [
            {"name": "Content-Type", "value": "application/json"},
            {"name": "Set-Cookie", "value": "first=fixture"},
            {"name": "Set-Cookie", "value": "second=fixture"},
        ]
        read_channel = _ScriptedCdp(
            request_url="https://ctf.example/api/v1/challenges",
            response_url="https://ctf.example/api/v1/challenges",
            response_headers=headers,
            response_document={"success": True, "data": []},
        )
        post_channel = _ScriptedCdp(
            response_headers=headers,
            response_document={"success": True, "data": {"correct": False}},
        )

        read = _run_read(
            read_channel,
            CTFdReadOnlyRequest(binding=_binding(), operation="inventory"),
        )
        post = _run_scoring(post_channel, _action())

        self.assertEqual(read.document, {"success": True, "data": []})
        self.assertEqual(post.verdict["verdict"], "rejected")
        self.assertNotIn("set-cookie", read.headers)
        self.assertNotIn("set-cookie", post.response["headers"])

    def test_second_paused_post_is_failed_then_owned_target_is_closed(self) -> None:
        channel = _ScriptedCdp(second_paused_request=True)
        closed: list[str] = []

        def close_target(target_id: str, timeout_seconds: float) -> bool:
            closed.append(target_id)
            return timeout_seconds > 0

        with self.assertRaises(BrowserCdpScoringError) as caught:
            execute_ctfd_browser_scoring(
                channel,
                _action(),
                close_owned_target=close_target,
            )

        self.assertTrue(caught.exception.committed)
        self.assertEqual(closed, ["target-1"])
        methods = [method for _id, method, _params in channel.commands]
        self.assertIn("Fetch.failRequest", methods)
        self.assertNotIn("Fetch.disable", methods)

    def test_timeout_after_call_function_trigger_is_indeterminate(self) -> None:
        channel = _ScriptedCdp(timeout_after_trigger=True)

        with self.assertRaises(BrowserCdpScoringError) as caught:
            _run_scoring(channel, _action())

        self.assertEqual(caught.exception.reason, "browser_cdp_timeout")
        self.assertTrue(caught.exception.committed)

    def test_inventory_read_uses_the_same_fixed_intercepted_browser_path(self) -> None:
        url = "https://ctf.example/api/v1/challenges"
        channel = _ScriptedCdp(
            request_url=url,
            response_url=url,
            response_document={"success": True, "data": []},
        )

        result = _run_read(
            channel,
            CTFdReadOnlyRequest(binding=_binding(), operation="inventory"),
        )

        self.assertEqual(result.document, {"success": True, "data": []})
        call = next(params for _id, method, params in channel.commands if method == "Runtime.callFunctionOn")
        self.assertEqual(call["arguments"][0], {"value": url})
        self.assertEqual(call["arguments"][1], {"value": "GET"})
        self.assertEqual(call["arguments"][2], {"value": None})
        methods = [method for _id, method, _params in channel.commands]
        self.assertIn("Fetch.continueRequest", methods)
        self.assertNotIn("Fetch.failRequest", methods)

    def test_csrf_read_allows_only_the_reviewed_local_page_path(self) -> None:
        url = "https://ctf.example/challenges"
        channel = _ScriptedCdp(
            request_url=url,
            response_url=url,
            response_headers=[{"name": "Content-Type", "value": "text/html"}],
            response_body='<meta name="csrf" content="fixture-value">',
            runtime_value={
                "url": url,
                "status": 200,
                "redirected": False,
                "type": "basic",
                "contentType": "text/html",
            },
        )

        result = _run_read(
            channel,
            CTFdReadOnlyRequest(binding=_binding(), operation="csrf", csrf_page_path="/challenges"),
        )

        self.assertIn("fixture-value", result.text or "")
        with self.assertRaises(BrowserCdpScoringError):
            CTFdReadOnlyRequest(binding=_binding(), operation="csrf", csrf_page_path="//evil.invalid")

    def test_wrong_request_url_is_blocked_before_commit(self) -> None:
        channel = _ScriptedCdp(request_url="https://ctf.example/api/v1/users/me")

        with self.assertRaises(BrowserCdpScoringError) as caught:
            _run_scoring(channel, _action())

        self.assertEqual(caught.exception.reason, "browser_unexpected_network_effect")
        self.assertFalse(caught.exception.committed)
        methods = [method for _id, method, _params in channel.commands]
        self.assertIn("Fetch.failRequest", methods)
        self.assertNotIn("Fetch.continueRequest", methods)

    def test_noncanonical_request_body_is_blocked_before_commit(self) -> None:
        channel = _ScriptedCdp(tamper_post_data=True)

        with self.assertRaises(BrowserCdpScoringError) as caught:
            _run_scoring(channel, _action())

        self.assertFalse(caught.exception.committed)
        methods = [method for _id, method, _params in channel.commands]
        self.assertIn("Fetch.failRequest", methods)
        self.assertNotIn("Fetch.continueRequest", methods)

    def test_redirect_after_release_is_indeterminate(self) -> None:
        channel = _ScriptedCdp(response_status=302)

        with self.assertRaises(BrowserCdpScoringError) as caught:
            _run_scoring(channel, _action())

        self.assertEqual(caught.exception.reason, "browser_request_interception_mismatch")
        self.assertTrue(caught.exception.committed)
        self.assertEqual(caught.exception.outcome, "indeterminate")

    def test_disconnect_after_release_is_indeterminate(self) -> None:
        channel = _ScriptedCdp(disconnect_after_commit=True)

        with self.assertRaises(BrowserCdpScoringError) as caught:
            _run_scoring(channel, _action())

        self.assertEqual(caught.exception.reason, "browser_cdp_disconnected")
        self.assertTrue(caught.exception.committed)

    def test_timeout_after_release_is_indeterminate(self) -> None:
        channel = _ScriptedCdp(timeout_after_commit=True)

        with self.assertRaises(BrowserCdpScoringError) as caught:
            _run_scoring(channel, _action())

        self.assertEqual(caught.exception.reason, "browser_cdp_timeout")
        self.assertTrue(caught.exception.committed)

    def test_extra_target_after_release_is_indeterminate(self) -> None:
        channel = _ScriptedCdp(
            event_after_commit={
                "method": "Target.targetCreated",
                "params": {"targetInfo": {"targetId": "popup-1", "type": "page"}},
            }
        )

        with self.assertRaises(BrowserCdpScoringError) as caught:
            _run_scoring(channel, _action())

        self.assertEqual(caught.exception.reason, "browser_unexpected_network_effect")
        self.assertTrue(caught.exception.committed)

    def test_oversized_response_after_release_is_indeterminate(self) -> None:
        channel = _ScriptedCdp(response_body="x" * 33, response_base64=True)

        with self.assertRaises(BrowserCdpScoringError) as caught:
            _run_scoring(channel, _action(max_response_bytes=32))

        self.assertEqual(caught.exception.reason, "browser_scorer_response_too_large")
        self.assertTrue(caught.exception.committed)

    def test_unstructured_json_after_release_is_indeterminate(self) -> None:
        channel = _ScriptedCdp(response_document={"success": True, "data": {}})

        result = _run_scoring(channel, _action())

        self.assertEqual(result.verdict["verdict"], "unknown")
        self.assertEqual(result.verdict["scorer_truth"], "unknown")

    def test_deep_json_after_release_is_indeterminate(self) -> None:
        body = '{"success":true,"data":' + "[" * 40 + "0" + "]" * 40 + "}"
        channel = _ScriptedCdp(response_body=body)

        with self.assertRaises(BrowserCdpScoringError) as caught:
            _run_scoring(channel, _action())

        self.assertEqual(caught.exception.reason, "browser_scorer_response_invalid")
        self.assertTrue(caught.exception.committed)

    def test_binding_requires_a_sealed_gateway_digest(self) -> None:
        with self.assertRaises(BrowserCdpScoringError) as caught:
            _binding(gateway_policy_sha256="unsealed")

        self.assertEqual(caught.exception.reason, "browser_gateway_unsealed")
        self.assertFalse(caught.exception.committed)

    def test_binding_rejects_a_noncanonical_origin(self) -> None:
        with self.assertRaises(BrowserCdpScoringError) as caught:
            _binding(origin="https://ctf.example/")

        self.assertEqual(caught.exception.reason, "browser_ctfd_origin_invalid")

    def test_secret_fields_are_omitted_from_action_repr(self) -> None:
        action = _action(candidate="flag{do-not-log}", csrf_token="fixture.csrf-token-1234")

        rendered = repr(action)

        self.assertNotIn("flag{do-not-log}", rendered)
        self.assertNotIn("fixture.csrf-token-1234", rendered)


@unittest.skipUnless(
    os.environ.get("ROOKERY_RUN_DISPOSABLE_CHROME") == "1",
    "set ROOKERY_RUN_DISPOSABLE_CHROME=1 for the isolated Chrome/gateway rehearsal",
)
class BrowserCdpChromeGatewayTests(unittest.TestCase):
    def test_proxy_bound_chrome_has_no_direct_fallback(self) -> None:
        chrome = _chrome_path()
        if chrome is None:
            self.skipTest("Google Chrome is not installed")
        try:
            import cryptography  # noqa: F401 - explicit optional-fixture readiness check.
            import websocket  # noqa: F401 - explicit optional-fixture readiness check.
        except ImportError as exc:
            self.skipTest(f"fixture dependency unavailable: {exc}")

        hit_lock = threading.Lock()
        hits: dict[str, int] = {}
        http_behavior: dict[str, bool] = {}
        proxy_lock = threading.Lock()
        proxy_counts = {"accepted": 0, "rejected": 0}
        https_server: ThreadingHTTPServer | None = None
        proxy_server: _LoopbackConnectProxy | None = None
        browser_channel: _SocketCdp | None = None
        page_channels: list[_SocketCdp] = []
        chrome_process: subprocess.Popen[bytes] | None = None
        blocked_context_id: str | None = None
        with tempfile.TemporaryDirectory(prefix="rookery-chrome-gateway-") as raw_temp:
            temp = Path(raw_temp)
            certificate_path, key_path, certificate_pin = _write_fixture_certificate(temp)
            https_server = ThreadingHTTPServer(
                ("127.0.0.1", 0),
                _https_handler(
                    counters=hits,
                    lock=hit_lock,
                    behavior=http_behavior,
                ),
            )
            https_server.daemon_threads = True
            tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            tls.minimum_version = ssl.TLSVersion.TLSv1_3
            tls.load_cert_chain(certificate_path, key_path)
            https_server.socket = tls.wrap_socket(https_server.socket, server_side=True)
            https_port = int(https_server.server_address[1])
            https_thread = threading.Thread(target=https_server.serve_forever, daemon=True)
            https_thread.start()

            proxy_server = _LoopbackConnectProxy(
                ("127.0.0.1", 0),
                _proxy_handler(
                    target_port=https_port,
                    counters=proxy_counts,
                    lock=proxy_lock,
                ),
            )
            proxy_port = int(proxy_server.server_address[1])
            proxy_thread = threading.Thread(target=proxy_server.serve_forever, daemon=True)
            proxy_thread.start()

            cdp_port = _free_high_port()
            cdp_origin = f"http://127.0.0.1:{cdp_port}"
            creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
            chrome_process = subprocess.Popen(
                [
                    str(chrome),
                    "--headless=new",
                    "--disable-background-networking",
                    "--disable-component-update",
                    "--disable-default-apps",
                    "--disable-gpu",
                    "--disable-sync",
                    "--metrics-recording-only",
                    "--no-default-browser-check",
                    "--no-first-run",
                    f"--proxy-server=http://127.0.0.1:{proxy_port}",
                    "--proxy-bypass-list=<-loopback>",
                    f"--remote-debugging-port={cdp_port}",
                    "--remote-debugging-address=127.0.0.1",
                    f"--remote-allow-origins={cdp_origin}",
                    f"--user-data-dir={temp / 'profile'}",
                    f"--ignore-certificate-errors-spki-list={certificate_pin}",
                    "about:blank",
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=creation_flags,
            )
            try:
                version_url = f"{cdp_origin}/json/version"
                _wait_until(lambda: isinstance(_read_loopback_json(version_url), dict))
                version = _read_loopback_json(version_url)
                browser_channel = _SocketCdp(version["webSocketDebuggerUrl"], origin=cdp_origin)
                existing, _events = browser_channel.command("Target.getTargets", {})
                for info in existing.get("targetInfos", []):
                    if isinstance(info, dict) and info.get("type") == "page":
                        browser_channel.command("Target.closeTarget", {"targetId": info["targetId"]})

                fixture_origin = f"https://ctfd.localhost:{https_port}"
                source_url = fixture_origin + "/challenges"
                source, _events = browser_channel.command(
                    "Target.createTarget",
                    {"url": source_url},
                )
                source_target_id = source["targetId"]
                _wait_until(lambda: hits.get("/challenges", 0) >= 1)

                def page_descriptor(target_id: str) -> dict[str, Any] | None:
                    rows = _read_loopback_json(f"{cdp_origin}/json/list")
                    return next(
                        (row for row in rows if isinstance(row, dict) and row.get("id") == target_id),
                        None,
                    )

                policy_digest = hashlib.sha256(f"ctfd.localhost:{https_port}".encode("ascii")).hexdigest()
                owned_targets: set[str] = set()

                def close_owned_target(target_id: str, timeout_seconds: float) -> bool:
                    if target_id not in owned_targets or timeout_seconds <= 0:
                        return False
                    result, _events = browser_channel.command("Target.closeTarget", {"targetId": target_id})
                    if result.get("success") is not True:
                        return False
                    deadline = time.monotonic() + timeout_seconds
                    while time.monotonic() < deadline:
                        if page_descriptor(target_id) is None:
                            owned_targets.remove(target_id)
                            return True
                        time.sleep(0.02)
                    return False

                def open_blank_owned() -> tuple[_SocketCdp, str]:
                    target, _events = browser_channel.command("Target.createTarget", {"url": "about:blank"})
                    target_id = target["targetId"]
                    owned_targets.add(target_id)
                    _wait_until(lambda: page_descriptor(target_id) is not None)
                    descriptor = page_descriptor(target_id)
                    assert descriptor is not None
                    channel = _SocketCdp(descriptor["webSocketDebuggerUrl"], origin=cdp_origin)
                    page_channels.append(channel)
                    return channel, target_id

                def new_owned_page() -> tuple[_SocketCdp, BrowserScoringBinding]:
                    channel, target_id = open_blank_owned()
                    bootstrap = bootstrap_owned_browser_target(
                        channel,
                        fixture_origin,
                        policy_digest,
                        target_id,
                        close_owned_target=close_owned_target,
                    )
                    self.assertEqual(bootstrap.account_document["data"]["id"], 7)
                    self.assertEqual(bootstrap.binding.target_id, target_id)
                    self.assertEqual(
                        bootstrap.binding.page_url,
                        fixture_origin + "/api/v1/users/me",
                    )
                    return channel, bootstrap.binding

                redirect_channel, redirect_target_id = open_blank_owned()
                with hit_lock:
                    redirect_sink_before = hits.get("/redirect-sink", 0)
                http_behavior["redirect_account"] = True
                try:
                    with self.assertRaises(BrowserCdpScoringError) as caught:
                        bootstrap_owned_browser_target(
                            redirect_channel,
                            fixture_origin,
                            policy_digest,
                            redirect_target_id,
                            close_owned_target=close_owned_target,
                        )
                finally:
                    http_behavior["redirect_account"] = False
                self.assertEqual(
                    caught.exception.reason,
                    "browser_request_interception_mismatch",
                )
                time.sleep(0.2)
                with hit_lock:
                    self.assertEqual(hits.get("/redirect-sink", 0), redirect_sink_before)
                self.assertNotIn(redirect_target_id, owned_targets)

                read_channel, read_binding = new_owned_page()

                result = execute_ctfd_browser_read(
                    read_channel,
                    CTFdReadOnlyRequest(
                        binding=read_binding,
                        operation="inventory",
                    ),
                    close_owned_target=close_owned_target,
                )
                self.assertEqual(result.document, {"success": True, "data": []})

                scoring_channel, scoring_binding = new_owned_page()
                scoring_result = execute_ctfd_browser_scoring(
                    scoring_channel,
                    CTFdScoringAction(
                        binding=scoring_binding,
                        challenge_id=41,
                        candidate="flag{fixture-only}",
                        csrf_token="fixture.csrf-token-1234",
                    ),
                    close_owned_target=close_owned_target,
                )
                self.assertEqual(scoring_result.verdict["verdict"], "rejected")
                with hit_lock:
                    self.assertEqual(hits.get("/api/v1/challenges/attempt"), 1)

                race_channel, race_binding = new_owned_page()
                race_channel.command(
                    "Runtime.evaluate",
                    {
                        "expression": """
setTimeout(() => fetch('/api/v1/challenges/attempt', {
  method: 'POST',
  headers: {'Accept': 'application/json', 'Content-Type': 'application/json'},
  body: JSON.stringify({challenge_id: 99, submission: 'background'})
}), 50); true
""",
                        "returnByValue": True,
                    },
                )
                with hit_lock:
                    attempts_before_race = hits.get("/api/v1/challenges/attempt", 0)
                with self.assertRaises(BrowserCdpScoringError) as caught:
                    execute_ctfd_browser_scoring(
                        race_channel,
                        CTFdScoringAction(
                            binding=race_binding,
                            challenge_id=41,
                            candidate="flag{fixture-only}",
                            csrf_token="fixture.csrf-token-1234",
                        ),
                        close_owned_target=close_owned_target,
                    )
                self.assertEqual(caught.exception.reason, "browser_unexpected_network_effect")
                self.assertTrue(caught.exception.committed)
                time.sleep(0.3)
                with hit_lock:
                    self.assertEqual(
                        hits.get("/api/v1/challenges/attempt", 0),
                        attempts_before_race + 1,
                    )
                targets_after_close, _events = browser_channel.command("Target.getTargets", {})
                self.assertTrue(
                    any(
                        isinstance(info, dict) and info.get("targetId") == source_target_id
                        for info in targets_after_close.get("targetInfos", [])
                    )
                )
                self.assertEqual(owned_targets, set())
                with proxy_lock:
                    self.assertGreaterEqual(proxy_counts["accepted"], 1)
                with hit_lock:
                    direct_baseline = sum(hits.values())

                unavailable_proxy_port = _free_high_port()
                blocked, _events = browser_channel.command(
                    "Target.createBrowserContext",
                    {
                        "proxyServer": f"http://127.0.0.1:{unavailable_proxy_port}",
                        "proxyBypassList": "<-loopback>",
                    },
                )
                blocked_context_id = blocked["browserContextId"]
                browser_channel.command(
                    "Target.createTarget",
                    {
                        "url": fixture_origin + "/api/v1/users/me",
                        "browserContextId": blocked_context_id,
                    },
                )
                time.sleep(2)
                with hit_lock:
                    self.assertEqual(sum(hits.values()), direct_baseline)
            finally:
                if browser_channel is not None and blocked_context_id is not None:
                    try:
                        browser_channel.command(
                            "Target.disposeBrowserContext",
                            {"browserContextId": blocked_context_id},
                        )
                    except (OSError, RuntimeError, TimeoutError):
                        pass
                for channel in page_channels:
                    try:
                        channel.close()
                    except OSError:
                        pass
                if browser_channel is not None:
                    browser_channel.close()
                if chrome_process is not None:
                    chrome_process.terminate()
                    try:
                        chrome_process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        chrome_process.kill()
                        chrome_process.wait(timeout=5)
                if proxy_server is not None:
                    proxy_server.shutdown()
                    proxy_server.server_close()
                if https_server is not None:
                    https_server.shutdown()
                    https_server.server_close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
