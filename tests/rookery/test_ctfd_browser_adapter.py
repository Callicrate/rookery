from __future__ import annotations

import io
import json
import os
import runpy
import sys
import tempfile
import threading
import unittest
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Iterator, Self
from unittest import mock

from tests.rookery.support import ROOKERY_ROOT

LIB = ROOKERY_ROOT / "lib"
if str(LIB) not in sys.path:
    sys.path.insert(0, str(LIB))

# ruff: noqa: E402
from rookery.portable import browser_cdp
from rookery.portable.cli import startup_checks
from rookery.portable.environment import EnvironmentPolicyError


def scoped() -> dict[str, object]:
    return {
        "acknowledged": True,
        "generation": 1,
        "expires_at": "unknown",
        "allowed_hosts": ["fixture.invalid"],
        "allowed_cidrs": ["127.0.0.0/8", "::1/128"],
        "allowed_ports": [],
        "allowed_protocols": ["http", "https"],
        "allowed_file_origins": [],
        "platform_hosts": ["fixture.invalid"],
        "max_attachment_bytes": 4096,
    }


class _Response(io.BytesIO):
    def __init__(
        self,
        body: bytes,
        *,
        status: int = 200,
        headers: dict[str, str] | None = None,
        url: str | None = None,
    ) -> None:
        super().__init__(body)
        self.status = status
        self.headers = headers or {"Content-Type": "application/json"}
        self._url = url

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def geturl(self) -> str:
        if self._url is None:
            raise AttributeError("fixture response has no final URL")
        return self._url


class _FakeCdpSocket:
    def __init__(self, cookies: list[dict[str, Any]]) -> None:
        self.cookies = cookies
        self.commands: list[tuple[str, dict[str, Any]]] = []
        self.closed = False

    def command(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        self.commands.append((method, params))
        if method == "Network.getCookies":
            return {"cookies": self.cookies}
        raise AssertionError(method)

    def close(self) -> None:
        self.closed = True


def _read_client_frame(stream: Any) -> tuple[int, bytes]:
    first, second = stream.read(2)
    length = second & 0x7F
    if length == 126:
        length = int.from_bytes(stream.read(2), "big")
    mask = stream.read(4)
    encoded = stream.read(length)
    return first & 0x0F, bytes(value ^ mask[index % 4] for index, value in enumerate(encoded))


def _send_server_frame(stream: Any, payload: dict[str, Any]) -> None:
    encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    if len(encoded) < 126:
        header = bytes([0x81, len(encoded)])
    else:
        header = bytes([0x81, 126]) + len(encoded).to_bytes(2, "big")
    stream.write(header + encoded)
    stream.flush()


@contextmanager
def serve_fake_cdp() -> Iterator[ThreadingHTTPServer]:
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self) -> None:
            self.server.paths.append(self.path)  # type: ignore[attr-defined]
            port = self.server.server_port
            if self.path == "/json/version":
                self._json(
                    {
                        "Browser": "Chrome/fixture",
                        "Protocol-Version": "1.3",
                        "User-Agent": "fixture/1.0",
                        "webSocketDebuggerUrl": (f"ws://127.0.0.1:{port}/devtools/browser/browser-1"),
                    }
                )
                return
            if self.path == "/json/list":
                self._json(
                    [
                        {
                            "id": "page-1",
                            "type": "page",
                            "url": "https://fixture.invalid/challenges",
                            "webSocketDebuggerUrl": (f"ws://127.0.0.1:{port}/devtools/page/page-1"),
                        }
                    ]
                )
                return
            if self.path != "/devtools/page/page-1":
                self.send_error(404)
                return
            if self.headers.get("Origin") is not None:
                self.send_error(403)
                return
            key = self.headers.get("Sec-WebSocket-Key", "")
            accept = browser_cdp._websocket_acceptance(key)
            self.send_response(101, "WebSocket Protocol Handshake")
            self.send_header("Upgrade", "websocket")
            self.send_header("Connection", "Upgrade")
            self.send_header("Sec-WebSocket-Accept", accept)
            self.end_headers()
            for expected_id in (1, 2):
                opcode, payload = _read_client_frame(self.rfile)
                if opcode != 1:
                    return
                request = json.loads(payload.decode("utf-8"))
                self.server.commands.append(request)  # type: ignore[attr-defined]
                if request.get("id") != expected_id:
                    return
                if request["method"] == "Browser.getVersion":
                    _send_server_frame(
                        self.wfile,
                        {"id": expected_id, "result": {"userAgent": "fixture/1.0"}},
                    )
                elif request["method"] == "Network.getCookies":
                    _send_server_frame(
                        self.wfile,
                        {
                            "id": expected_id,
                            "result": {
                                "cookies": [
                                    {
                                        "name": "session",
                                        "value": "fixture-secret",
                                        "domain": "fixture.invalid",
                                        "path": "/",
                                        "secure": True,
                                        "expires": -1,
                                    }
                                ]
                            },
                        },
                    )
                else:
                    return
            self.close_connection = True

        def _json(self, data: object) -> None:
            payload = json.dumps(data).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, _format: str, *args: object) -> None:
            del args

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.paths = []  # type: ignore[attr-defined]
    server.commands = []  # type: ignore[attr-defined]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


class BrowserCdpSessionTests(unittest.TestCase):
    def _target(self, **overrides: object) -> dict[str, object]:
        target = {
            "id": "page-1",
            "type": "page",
            "url": "https://fixture.invalid/challenges",
            "webSocketDebuggerUrl": "ws://127.0.0.1:9001/devtools/page/page-1",
        }
        target.update(overrides)
        return target

    def _cookie(self, **overrides: object) -> dict[str, object]:
        cookie = {
            "name": "session",
            "value": "browser-session-secret",
            "domain": "fixture.invalid",
            "path": "/",
            "secure": True,
            "expires": -1,
        }
        cookie.update(overrides)
        return cookie

    def test_reader_uses_exact_target_and_only_the_cdp_read_commands(self) -> None:
        socket = _FakeCdpSocket([self._cookie()])
        with (
            mock.patch.object(
                browser_cdp,
                "resolve_browser_cdp_endpoint",
                return_value=("http://127.0.0.1:9001", 9001),
            ),
            mock.patch.object(browser_cdp, "verify_browser_cdp_endpoint"),
            mock.patch.object(
                browser_cdp,
                "_read_version_user_agent",
                return_value="fixture-browser/1.0",
            ),
            mock.patch.object(
                browser_cdp,
                "_read_targets",
                return_value=[self._target()],
            ),
            mock.patch.object(browser_cdp, "_open_target_socket", return_value=socket),
        ):
            session = browser_cdp.read_browser_session("http://127.0.0.1:9001", "https://fixture.invalid")

        self.assertEqual(session.origin, "https://fixture.invalid")
        self.assertEqual(session.target_id, "page-1")
        self.assertEqual(session.cookie_header, "session=browser-session-secret")
        self.assertEqual(session.user_agent, "fixture-browser/1.0")
        self.assertEqual(
            socket.commands,
            [
                (
                    "Network.getCookies",
                    {
                        "urls": [
                            "https://fixture.invalid/api/v1/users/me",
                            "https://fixture.invalid/api/v1/challenges",
                            "https://fixture.invalid/api/v1/challenges/attempt",
                        ]
                    },
                ),
            ],
        )
        self.assertTrue(socket.closed)

    def test_reader_uses_pinned_loopback_http_and_websocket_with_fake_cdp(self) -> None:
        with serve_fake_cdp() as server:
            session = browser_cdp.read_browser_session(
                f"http://127.0.0.1:{server.server_port}",
                "https://fixture.invalid",
            )

        self.assertEqual(session.cookie_header, "session=fixture-secret")
        self.assertEqual(session.user_agent, "fixture/1.0")
        self.assertEqual(
            server.paths,  # type: ignore[attr-defined]
            [
                "/json/version",
                "/json/version",
                "/json/list",
                "/devtools/page/page-1",
            ],
        )
        self.assertEqual(  # type: ignore[attr-defined]
            [command["method"] for command in server.commands],
            ["Network.getCookies"],
        )

    def test_reader_rejects_ambiguous_or_wrong_origin_pages_before_websocket(self) -> None:
        socket = mock.Mock()
        targets = [self._target(), self._target(id="page-2")]
        with (
            mock.patch.object(
                browser_cdp,
                "resolve_browser_cdp_endpoint",
                return_value=("http://127.0.0.1:9001", 9001),
            ),
            mock.patch.object(browser_cdp, "verify_browser_cdp_endpoint"),
            mock.patch.object(
                browser_cdp,
                "_read_version_user_agent",
                return_value="fixture-browser/1.0",
            ),
            mock.patch.object(browser_cdp, "_read_targets", return_value=targets),
            mock.patch.object(browser_cdp, "_open_target_socket", socket),
            self.assertRaisesRegex(browser_cdp.BrowserCdpError, "target_ambiguous"),
        ):
            browser_cdp.read_browser_session("http://127.0.0.1:9001", "https://fixture.invalid")
        socket.assert_not_called()

        with self.assertRaisesRegex(browser_cdp.BrowserCdpError, "origin_invalid"):
            browser_cdp.read_browser_session("http://127.0.0.1:9001", "https://fixture.invalid/outside")

    def test_cookie_selection_rejects_off_origin_and_partial_path_cookies(self) -> None:
        origin = browser_cdp._configured_origin("https://fixture.invalid")
        with self.assertRaisesRegex(browser_cdp.BrowserCdpError, "cookie_invalid"):
            browser_cdp._cookie_header(
                [self._cookie(domain="outside.invalid")],
                origin,
            )
        with self.assertRaisesRegex(browser_cdp.BrowserCdpError, "cookie_invalid"):
            browser_cdp._cookie_header(
                [self._cookie(path="/api/v1/challenge")],
                origin,
            )


class CTFdBrowserAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.root.joinpath(".env").write_text(
            "BROWSER_CDP_URL=http://127.0.0.1:9001\n",
            encoding="utf-8",
        )
        self.namespace = runpy.run_path(str(ROOKERY_ROOT / "adapters" / "ctfd_browser" / "adapter.py"))
        self.adapter_class = self.namespace["CTFdBrowserAdapter"]
        self.verify_browser_cdp = mock.Mock()
        self.adapter_class.sync.__globals__["verify_browser_cdp_endpoint"] = self.verify_browser_cdp

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _adapter(self):
        return self.adapter_class(
            self.root,
            {
                "adapter": {
                    "config": {
                        "base_url": "https://fixture.invalid",
                        "expected_account_id": "42",
                        "scoring_mode": "user",
                        "session_lease_seconds": 60,
                    }
                }
            },
            scoped(),
        )

    def _sequential_adapter(self):
        adapter = self._adapter()
        adapter.config["sequential_unlock"] = True
        return adapter

    def _token_adapter(self):
        self.root.joinpath(".env").write_text(
            "BROWSER_CDP_URL=http://127.0.0.1:9001\nCTFD_TOKEN=fixture-token\n",
            encoding="utf-8",
        )
        return self._adapter()

    @staticmethod
    def _inventory(rows: list[dict[str, object]]) -> _Response:
        return _Response(json.dumps({"success": True, "data": rows}).encode("utf-8"))

    @staticmethod
    def _sequential_rows(*rows: tuple[int, bool, int]) -> list[dict[str, object]]:
        return [
            {"id": identifier, "position": position, "solved_by_me": solved} for position, solved, identifier in rows
        ]

    @staticmethod
    def _hidden_preview(identifier: int) -> dict[str, object]:
        return {
            "id": identifier,
            "type": "hidden",
            "solved_by_me": False,
            "template": "",
            "script": "",
        }

    @staticmethod
    def _browser_session() -> browser_cdp.BrowserSession:
        return browser_cdp.BrowserSession(
            origin="https://fixture.invalid",
            target_id="page-1",
            cookie_header="session=browser-session-secret",
            user_agent="fixture-browser/1.0",
        )

    def test_token_success_reports_verified_cdp_without_reading_browser_session(
        self,
    ) -> None:
        adapter = self._token_adapter()
        transport = mock.Mock(
            side_effect=[
                _Response(b'{"success": true, "data": {"id": 42}}'),
                self._inventory([{"id": 1, "name": "fixture"}]),
            ]
        )
        browser = mock.Mock()
        globals_ = self.adapter_class.sync.__globals__
        with mock.patch.dict(
            globals_,
            {"read_browser_session": browser, "open_scoped_url": transport},
        ):
            snapshot = adapter.sync()

        self.verify_browser_cdp.assert_called_once_with("http://127.0.0.1:9001")
        browser.assert_not_called()
        self.assertEqual(snapshot["capabilities"]["browser_cdp"]["health"], "healthy")
        self.assertEqual(snapshot["capabilities"]["platform_inventory"]["health"], "healthy")
        self.assertEqual([str(item["id"]) for item in snapshot["challenges"]], ["1"])

    def test_dead_cdp_blocks_token_route_before_platform_access(self) -> None:
        adapter = self._token_adapter()
        self.verify_browser_cdp.side_effect = EnvironmentPolicyError("browser_cdp_unreachable")
        transport = mock.Mock()
        browser = mock.Mock()
        globals_ = self.adapter_class.sync.__globals__
        with mock.patch.dict(
            globals_,
            {"read_browser_session": browser, "open_scoped_url": transport},
        ):
            snapshot = adapter.sync()

        self.verify_browser_cdp.assert_called_once_with("http://127.0.0.1:9001")
        browser.assert_not_called()
        transport.assert_not_called()
        self.assertEqual(snapshot["challenges"], [])
        self.assertEqual(snapshot["capabilities"]["browser_cdp"]["health"], "unhealthy")
        self.assertEqual(
            snapshot["capabilities"]["browser_cdp"]["detail"],
            "browser_cdp_unreachable",
        )
        self.assertTrue(all(capability["health"] == "unhealthy" for capability in snapshot["capabilities"].values()))

    def test_cookie_session_failure_overrides_initial_cdp_probe(self) -> None:
        adapter = self._adapter()
        browser = mock.Mock(side_effect=browser_cdp.BrowserCdpError("browser_cdp_target_missing"))
        transport = mock.Mock()
        globals_ = self.adapter_class.sync.__globals__
        with mock.patch.dict(
            globals_,
            {"read_browser_session": browser, "open_scoped_url": transport},
        ):
            snapshot = adapter.sync()

        self.verify_browser_cdp.assert_called_once_with("http://127.0.0.1:9001")
        browser.assert_called_once_with(
            "http://127.0.0.1:9001",
            "https://fixture.invalid",
            target_id=None,
        )
        transport.assert_not_called()
        self.assertEqual(snapshot["capabilities"]["browser_cdp"]["health"], "unhealthy")
        self.assertEqual(
            snapshot["capabilities"]["browser_cdp"]["detail"],
            "browser_cdp_target_missing",
        )
        self.assertEqual(snapshot["capabilities"]["scoring"]["health"], "unhealthy")

    def test_browser_cdp_snapshot_drives_required_startup_check(self) -> None:
        adapter = self._token_adapter()
        transport = mock.Mock(
            side_effect=[
                _Response(b'{"success": true, "data": {"id": 42}}'),
                self._inventory([{"id": 1, "name": "fixture"}]),
            ]
        )
        globals_ = self.adapter_class.sync.__globals__
        with mock.patch.dict(globals_, {"open_scoped_url": transport}):
            healthy_snapshot = adapter.sync()

        manifest = {
            "adapter": {"id": "ctfd_browser"},
            "capabilities": {
                "required": [
                    "local_shell",
                    "browser_cdp",
                    "platform_inventory",
                    "challenge_details",
                    "scoring",
                ],
                "optional": [],
            },
            "scoring": {"completion_mode": "scorer_truth"},
        }
        healthy_checks = startup_checks(
            self.root,
            manifest,
            scoped(),
            healthy_snapshot,
        )
        healthy_cdp = next(check for check in healthy_checks if check["name"] == "browser_cdp")
        self.assertTrue(healthy_cdp["ok"])

        self.verify_browser_cdp.reset_mock()
        self.verify_browser_cdp.side_effect = EnvironmentPolicyError("browser_cdp_unreachable")
        dead_snapshot = adapter.sync()
        dead_checks = startup_checks(self.root, manifest, scoped(), dead_snapshot)
        dead_cdp = next(check for check in dead_checks if check["name"] == "browser_cdp")
        self.assertFalse(dead_cdp["ok"])
        self.assertEqual(dead_cdp["detail"], "browser_cdp_unreachable")

    @unittest.skipUnless(os.name == "posix", "private evidence modes require Linux/WSL")
    def test_preflight_to_post_uses_one_memory_lease_and_persists_no_credentials(self) -> None:
        transport = mock.Mock(
            side_effect=[
                _Response(b'{"success": true, "data": {"id": 42}}'),
                _Response(
                    b'<script>var init = {"csrfNonce": "fixture.csrf-nonce-123456"};</script>',
                    headers={"Content-Type": "text/html"},
                ),
                _Response(b'{"success": true, "data": [{"id": 1, "name": "fixture"}]}'),
                _Response(b'{"success": true, "data": {"correct": false, "status": "incorrect"}}'),
            ]
        )
        adapter = self._adapter()
        globals_ = self.adapter_class.execute_action.__globals__
        with (
            mock.patch.dict(
                globals_,
                {
                    "read_browser_session": mock.Mock(return_value=self._browser_session()),
                    "open_scoped_url": transport,
                },
            ),
        ):
            preflight = adapter.preflight_action({"action_kind": "flag"})
            result = adapter.execute_action(
                {
                    "objective_id": "1",
                    "exact_value": "flag{fixture}",
                    "action_kind": "flag",
                },
                self.root / "evidence",
            )

        self.assertTrue(preflight["ok"])
        self.assertEqual(result["verdict"]["verdict"], "rejected")
        self.assertEqual(transport.call_count, 4)
        requests = [call.args[1] for call in transport.call_args_list]
        self.assertEqual(
            [request.full_url for request in requests],
            [
                "https://fixture.invalid/api/v1/users/me",
                "https://fixture.invalid/challenges",
                "https://fixture.invalid/api/v1/challenges",
                "https://fixture.invalid/api/v1/challenges/attempt",
            ],
        )
        for request in requests:
            self.assertEqual(request.get_header("Cookie"), "session=browser-session-secret")
            self.assertEqual(request.get_header("User-agent"), "fixture-browser/1.0")
        for request in requests[:-1]:
            self.assertFalse(any(name.casefold() == "csrf-token" for name, _value in request.header_items()))
        self.assertEqual(
            next(value for name, value in requests[-1].header_items() if name.casefold() == "csrf-token"),
            "fixture.csrf-nonce-123456",
        )
        stored = "\n".join(
            path.read_text(encoding="utf-8") for path in (self.root / "evidence").iterdir() if path.is_file()
        )
        self.assertNotIn("browser-session-secret", stored)
        self.assertNotIn("fixture-browser/1.0", stored)
        self.assertNotIn("fixture.csrf-nonce-123456", stored)
        with self.assertRaisesRegex(RuntimeError, "lease is unavailable"):
            adapter.execute_action(
                {"objective_id": "1", "exact_value": "flag{fixture}"},
                self.root / "evidence",
            )
        self.assertEqual(transport.call_count, 4)

    def test_sequential_unlock_exposes_only_lowest_unsolved_position(self) -> None:
        adapter = self._sequential_adapter()
        transport = mock.Mock(
            side_effect=[
                _Response(b'{"success": true, "data": {"id": 42}}'),
                _Response(
                    b'<script>var csrf_nonce = "fixture.csrf-nonce-123456";</script>',
                    headers={"Content-Type": "text/html"},
                ),
                self._inventory(
                    self._sequential_rows(
                        (3, False, 303),
                        (1, True, 101),
                        (2, False, 202),
                    )
                ),
            ]
        )
        globals_ = self.adapter_class.execute_action.__globals__
        with mock.patch.dict(
            globals_,
            {
                "read_browser_session": mock.Mock(return_value=self._browser_session()),
                "open_scoped_url": transport,
            },
        ):
            snapshot = adapter.sync()

        self.assertEqual([str(item["id"]) for item in snapshot["challenges"]], ["202"])
        self.assertEqual(snapshot["capabilities"]["scoring"]["health"], "healthy")
        rendered = json.dumps(snapshot, sort_keys=True)
        self.assertNotIn("browser-session-secret", rendered)
        self.assertNotIn("fixture.csrf-nonce-123456", rendered)

    def test_sequential_unlock_skips_ctfd_hidden_prerequisite_previews(self) -> None:
        adapter = self._sequential_adapter()
        transport = mock.Mock(
            side_effect=[
                _Response(b'{"success": true, "data": {"id": 42}}'),
                _Response(
                    b'<script>var csrf_nonce = "fixture.csrf-nonce-123456";</script>',
                    headers={"Content-Type": "text/html"},
                ),
                self._inventory(
                    [
                        self._hidden_preview(202),
                        {"id": 101, "type": "standard", "position": 1, "solved_by_me": False},
                        self._hidden_preview(303),
                    ]
                ),
            ]
        )
        globals_ = self.adapter_class.execute_action.__globals__
        with mock.patch.dict(
            globals_,
            {
                "read_browser_session": mock.Mock(return_value=self._browser_session()),
                "open_scoped_url": transport,
            },
        ):
            snapshot = adapter.sync()
            with self.assertRaisesRegex(RuntimeError, "sequential challenge changed since preflight"):
                adapter.execute_action(
                    {"objective_id": "202", "exact_value": "flag{fixture}", "action_kind": "flag"},
                    self.root / "hidden-preview-evidence",
                )

        self.assertEqual([str(item["id"]) for item in snapshot["challenges"]], ["101"])
        self.assertEqual(snapshot["capabilities"]["scoring"]["health"], "healthy")
        self.assertEqual(transport.call_count, 3)

    def test_sequential_unlock_advances_only_after_fresh_inventory(self) -> None:
        adapter = self._sequential_adapter()
        transport = mock.Mock(
            side_effect=[
                _Response(b'{"success": true, "data": {"id": 42}}'),
                _Response(
                    b'<script>var csrf_nonce = "fixture.csrf-nonce-123456";</script>',
                    headers={"Content-Type": "text/html"},
                ),
                self._inventory(
                    [
                        *self._sequential_rows((1, True, 101), (2, False, 202)),
                        self._hidden_preview(303),
                    ]
                ),
                _Response(b'{"success": true, "data": {"correct": true, "status": "correct"}}'),
                _Response(b'{"success": true, "data": {"id": 42}}'),
                _Response(
                    b'<script>var csrf_nonce = "fixture.csrf-nonce-123456";</script>',
                    headers={"Content-Type": "text/html"},
                ),
                self._inventory(self._sequential_rows((1, True, 101), (2, True, 202), (3, False, 303))),
            ]
        )
        globals_ = self.adapter_class.execute_action.__globals__
        with mock.patch.dict(
            globals_,
            {
                "read_browser_session": mock.Mock(return_value=self._browser_session()),
                "open_scoped_url": transport,
            },
        ):
            first = adapter.sync()
            scored = adapter.execute_action(
                {"objective_id": "202", "exact_value": "flag{fixture}", "action_kind": "flag"},
                self.root / "sequential-evidence",
            )
            second = adapter.sync()

        self.assertEqual([str(item["id"]) for item in first["challenges"]], ["202"])
        self.assertEqual(scored["verdict"]["verdict"], "accepted")
        self.assertEqual([str(item["id"]) for item in second["challenges"]], ["303"])

    def test_sequential_unlock_disabled_preserves_the_full_inventory(self) -> None:
        adapter = self._adapter()
        transport = mock.Mock(
            side_effect=[
                _Response(b'{"success": true, "data": {"id": 42}}'),
                _Response(
                    b'<script>var csrf_nonce = "fixture.csrf-nonce-123456";</script>',
                    headers={"Content-Type": "text/html"},
                ),
                self._inventory(self._sequential_rows((2, False, 202), (1, True, 101))),
            ]
        )
        globals_ = self.adapter_class.execute_action.__globals__
        with mock.patch.dict(
            globals_,
            {
                "read_browser_session": mock.Mock(return_value=self._browser_session()),
                "open_scoped_url": transport,
            },
        ):
            snapshot = adapter.sync()

        self.assertEqual([str(item["id"]) for item in snapshot["challenges"]], ["202", "101"])

    @unittest.skipUnless(os.name == "posix", "private evidence modes require Linux/WSL")
    def test_token_first_sequential_inventory_and_post_never_read_browser_session(self) -> None:
        adapter = self._token_adapter()
        adapter.config["sequential_unlock"] = True
        transport = mock.Mock(
            side_effect=[
                _Response(b'{"success": true, "data": {"id": 42}}'),
                self._inventory(self._sequential_rows((2, False, 202), (1, True, 101))),
                _Response(b'{"success": true, "data": {"correct": false, "status": "incorrect"}}'),
            ]
        )
        globals_ = self.adapter_class.execute_action.__globals__
        browser = mock.Mock()
        with mock.patch.dict(
            globals_,
            {"read_browser_session": browser, "open_scoped_url": transport},
        ):
            snapshot = adapter.sync()
            result = adapter.execute_action(
                {"objective_id": "202", "exact_value": "flag{fixture}", "action_kind": "flag"},
                self.root / "token-evidence",
            )

        self.assertEqual([str(item["id"]) for item in snapshot["challenges"]], ["202"])
        self.assertEqual(result["verdict"]["verdict"], "rejected")
        browser.assert_not_called()
        requests = [call.args[1] for call in transport.call_args_list]
        self.assertEqual(len(requests), 3)
        for request in requests:
            self.assertEqual(request.get_header("Authorization"), "Token fixture-token")
            self.assertIsNone(request.get_header("Cookie"))
        evidence = "\n".join(
            path.read_text(encoding="utf-8") for path in (self.root / "token-evidence").iterdir() if path.is_file()
        )
        self.assertNotIn("fixture-token", evidence)

    def test_token_login_redirect_uses_cookie_relay_after_the_read_only_probe(self) -> None:
        adapter = self._token_adapter()
        transport = mock.Mock(
            side_effect=[
                _Response(
                    b"",
                    status=302,
                    headers={"Content-Type": "text/html"},
                    url="https://fixture.invalid/login",
                ),
                _Response(b'{"success": true, "data": {"id": 42}}'),
                _Response(
                    b'<script>var csrf_nonce = "fixture.csrf-nonce-123456";</script>',
                    headers={"Content-Type": "text/html"},
                ),
                self._inventory(self._sequential_rows((1, False, 101))),
            ]
        )
        globals_ = self.adapter_class.execute_action.__globals__
        browser = mock.Mock(return_value=self._browser_session())
        with mock.patch.dict(
            globals_,
            {"read_browser_session": browser, "open_scoped_url": transport},
        ):
            snapshot = adapter.sync()

        self.assertEqual([str(item["id"]) for item in snapshot["challenges"]], ["101"])
        self.assertEqual(snapshot["capabilities"]["browser_cdp"]["health"], "healthy")
        self.verify_browser_cdp.assert_called_once_with("http://127.0.0.1:9001")
        browser.assert_called_once()
        requests = [call.args[1] for call in transport.call_args_list]
        self.assertEqual(requests[0].get_header("Authorization"), "Token fixture-token")
        self.assertIsNone(requests[0].get_header("Cookie"))
        for request in requests[1:]:
            self.assertIsNone(request.get_header("Authorization"))
            self.assertEqual(request.get_header("Cookie"), "session=browser-session-secret")

    @unittest.skipUnless(os.name == "posix", "private evidence modes require Linux/WSL")
    def test_token_post_timeout_never_falls_back_to_cookie_relay(self) -> None:
        adapter = self._token_adapter()
        transport = mock.Mock(
            side_effect=[
                _Response(b'{"success": true, "data": {"id": 42}}'),
                self._inventory(self._sequential_rows((1, False, 101))),
                TimeoutError("fixture timeout"),
            ]
        )
        globals_ = self.adapter_class.execute_action.__globals__
        browser = mock.Mock()
        with mock.patch.dict(
            globals_,
            {"read_browser_session": browser, "open_scoped_url": transport},
        ):
            self.assertEqual(adapter.sync()["capabilities"]["scoring"]["health"], "healthy")
            with self.assertRaisesRegex(RuntimeError, "ctfd_token_post_indeterminate"):
                adapter.execute_action(
                    {"objective_id": "101", "exact_value": "flag{fixture}", "action_kind": "flag"},
                    self.root / "token-timeout",
                )

        self.assertEqual(transport.call_count, 3)
        browser.assert_not_called()
        response = (self.root / "token-timeout" / "response.json").read_text(encoding="utf-8")
        self.assertIn("ctfd_token_post_indeterminate", response)

    def test_sequential_unlock_hides_inventory_after_all_rows_are_solved(self) -> None:
        adapter = self._sequential_adapter()
        transport = mock.Mock(
            side_effect=[
                _Response(b'{"success": true, "data": {"id": 42}}'),
                _Response(
                    b'<script>var csrf_nonce = "fixture.csrf-nonce-123456";</script>',
                    headers={"Content-Type": "text/html"},
                ),
                self._inventory(self._sequential_rows((1, True, 101), (2, True, 202))),
            ]
        )
        globals_ = self.adapter_class.execute_action.__globals__
        with mock.patch.dict(
            globals_,
            {
                "read_browser_session": mock.Mock(return_value=self._browser_session()),
                "open_scoped_url": transport,
            },
        ):
            snapshot = adapter.sync()

        self.assertEqual(snapshot["challenges"], [])

    def test_sequential_unlock_rejects_malformed_or_duplicate_positions(self) -> None:
        cases = (
            [{"id": 101, "position": "1", "solved_by_me": False}],
            self._sequential_rows((1, False, 101), (1, False, 202)),
            [{"id": 101, "position": 1, "solved_by_me": "false"}],
            [{"id": 101, "type": "standard", "solved_by_me": False}],
            [{**self._hidden_preview(101), "position": 1}],
            [{**self._hidden_preview(101), "template": "active"}],
            [{**self._hidden_preview(101), "solved_by_me": True}],
        )
        for rows in cases:
            with self.subTest(rows=rows):
                adapter = self._sequential_adapter()
                transport = mock.Mock(
                    side_effect=[
                        _Response(b'{"success": true, "data": {"id": 42}}'),
                        _Response(
                            b'<script>var csrf_nonce = "fixture.csrf-nonce-123456";</script>',
                            headers={"Content-Type": "text/html"},
                        ),
                        self._inventory(rows),
                    ]
                )
                globals_ = self.adapter_class.execute_action.__globals__
                with mock.patch.dict(
                    globals_,
                    {
                        "read_browser_session": mock.Mock(return_value=self._browser_session()),
                        "open_scoped_url": transport,
                    },
                ):
                    snapshot = adapter.sync()

                self.assertEqual(snapshot["challenges"], [])
                self.assertEqual(snapshot["capabilities"]["scoring"]["health"], "unhealthy")
                self.assertIn("sequential inventory", snapshot["capabilities"]["scoring"]["detail"])

    @unittest.skipUnless(os.name == "posix", "private evidence modes require Linux/WSL")
    def test_sequential_unlock_blocks_a_stale_challenge_id_before_post(self) -> None:
        adapter = self._sequential_adapter()
        transport = mock.Mock(
            side_effect=[
                _Response(b'{"success": true, "data": {"id": 42}}'),
                _Response(
                    b'<script>var csrf_nonce = "fixture.csrf-nonce-123456";</script>',
                    headers={"Content-Type": "text/html"},
                ),
                self._inventory(self._sequential_rows((1, True, 101), (2, False, 202))),
            ]
        )
        globals_ = self.adapter_class.execute_action.__globals__
        with mock.patch.dict(
            globals_,
            {
                "read_browser_session": mock.Mock(return_value=self._browser_session()),
                "open_scoped_url": transport,
            },
        ):
            self.assertEqual([str(item["id"]) for item in adapter.sync()["challenges"]], ["202"])
            with self.assertRaisesRegex(RuntimeError, "sequential challenge changed since preflight"):
                adapter.execute_action(
                    {"objective_id": "101", "exact_value": "flag{fixture}", "action_kind": "flag"},
                    self.root / "evidence",
                )

        self.assertEqual(transport.call_count, 3)

    @unittest.skipUnless(os.name == "posix", "private evidence modes require Linux/WSL")
    def test_base_drift_blocks_before_it_can_send_the_session_to_another_host(self) -> None:
        adapter = self._adapter()
        globals_ = self.adapter_class.execute_action.__globals__
        transport = mock.Mock(
            side_effect=[
                _Response(b'{"success": true, "data": {"id": 42}}'),
                _Response(
                    b'<script>var csrf_nonce = "fixture.csrf-nonce-123456";</script>',
                    headers={"Content-Type": "text/html"},
                ),
                _Response(b'{"success": true, "data": [{"id": 1, "name": "fixture"}]}'),
            ]
        )
        with mock.patch.dict(
            globals_,
            {
                "read_browser_session": mock.Mock(return_value=self._browser_session()),
                "open_scoped_url": transport,
            },
        ):
            self.assertTrue(adapter.preflight_action({"action_kind": "flag"})["ok"])
            adapter.config["base_url"] = "https://other.fixture.invalid"
            adapter.scope["allowed_hosts"] = ["fixture.invalid", "other.fixture.invalid"]
            adapter.scope["platform_hosts"] = ["fixture.invalid", "other.fixture.invalid"]
            with self.assertRaisesRegex(RuntimeError, "base URL changed since preflight"):
                adapter.execute_action(
                    {"objective_id": "1", "exact_value": "flag{fixture}"},
                    self.root / "evidence",
                )

        self.assertEqual(transport.call_count, 3)
        self.assertFalse(
            any(
                request.full_url.startswith("https://other.fixture.invalid")
                for request in (call.args[1] for call in transport.call_args_list)
            )
        )

    def test_missing_or_ambiguous_csrf_nonce_blocks_before_inventory_or_post(self) -> None:
        for document in (
            b"<html>no nonce</html>",
            b'<script>var csrf_nonce = "fixture.csrf-nonce-123456";</script>'
            b'<script>var csrfNonce = "different-nonce-123456";</script>',
        ):
            with self.subTest(document=document):
                adapter = self._adapter()
                globals_ = self.adapter_class.execute_action.__globals__
                transport = mock.Mock(
                    side_effect=[
                        _Response(b'{"success": true, "data": {"id": 42}}'),
                        _Response(document, headers={"Content-Type": "text/html"}),
                    ]
                )
                with mock.patch.dict(
                    globals_,
                    {
                        "read_browser_session": mock.Mock(return_value=self._browser_session()),
                        "open_scoped_url": transport,
                    },
                ):
                    snapshot = adapter.sync()

                self.assertEqual(transport.call_count, 2)
                self.assertEqual(snapshot["capabilities"]["scoring"]["health"], "unhealthy")
                self.assertIn("CSRF nonce is missing or ambiguous", snapshot["capabilities"]["scoring"]["detail"])
                self.assertNotIn("fixture.csrf-nonce-123456", json.dumps(snapshot))

    def test_missing_mode_or_account_binding_fails_before_cdp_or_platform_access(self) -> None:
        cases = (
            ("scoring_mode", {}),
            ("expected_account_id", {}),
            ("expected_team_id", {"scoring_mode": "team"}),
            ("expected_team_id requires scoring_mode team", {"expected_team_id": "13"}),
        )
        for key, configuration in cases:
            with self.subTest(key=key):
                adapter = self._adapter()
                adapter.config.update(configuration)
                if key != "expected_team_id requires scoring_mode team":
                    adapter.config.pop(key, None)
                globals_ = self.adapter_class.execute_action.__globals__
                browser = mock.Mock()
                transport = mock.Mock()
                with mock.patch.dict(
                    globals_,
                    {"read_browser_session": browser, "open_scoped_url": transport},
                ):
                    snapshot = adapter.sync()

                browser.assert_not_called()
                transport.assert_not_called()
                self.verify_browser_cdp.assert_not_called()
                self.assertEqual(snapshot["capabilities"]["scoring"]["health"], "unhealthy")
                self.assertIn(
                    key,
                    snapshot["capabilities"]["scoring"]["detail"],
                )

    def test_wrong_account_or_team_binding_blocks_before_inventory(self) -> None:
        configurations = (
            (
                {"scoring_mode": "user", "expected_account_id": "42"},
                [
                    _Response(b'{"success": true, "data": {"id": 7}}'),
                ],
                "expected account",
                1,
            ),
            (
                {
                    "scoring_mode": "team",
                    "expected_account_id": "42",
                    "expected_team_id": "13",
                },
                [
                    _Response(b'{"success": true, "data": {"id": 42}}'),
                    _Response(
                        b'<script>var csrf_nonce = "fixture.csrf-nonce-123456";</script>',
                        headers={"Content-Type": "text/html"},
                    ),
                    _Response(b'{"success": true, "data": {"id": 8}}'),
                ],
                "expected team",
                3,
            ),
        )
        for config, responses, detail, request_count in configurations:
            with self.subTest(mode=config["scoring_mode"]):
                adapter = self._adapter()
                adapter.config.update(config)
                globals_ = self.adapter_class.execute_action.__globals__
                transport = mock.Mock(side_effect=responses)
                with mock.patch.dict(
                    globals_,
                    {
                        "read_browser_session": mock.Mock(return_value=self._browser_session()),
                        "open_scoped_url": transport,
                    },
                ):
                    snapshot = adapter.sync()

                self.assertEqual(transport.call_count, request_count)
                self.assertEqual(snapshot["capabilities"]["scoring"]["health"], "unhealthy")
                self.assertIn(detail, snapshot["capabilities"]["scoring"]["detail"])
                self.assertNotIn("browser-session-secret", json.dumps(snapshot))

    def test_cloudflare_session_failure_blocks_without_submission_evidence(self) -> None:
        adapter = self._adapter()
        globals_ = self.adapter_class.execute_action.__globals__
        transport = mock.Mock(
            return_value=_Response(
                b"<html>challenge</html>",
                status=403,
                headers={"Content-Type": "text/html", "CF-Mitigated": "challenge"},
            )
        )
        with mock.patch.dict(
            globals_,
            {
                "read_browser_session": mock.Mock(return_value=self._browser_session()),
                "open_scoped_url": transport,
            },
        ):
            snapshot = adapter.sync()

        self.assertEqual(transport.call_count, 1)
        self.assertEqual(snapshot["challenges"], [])
        self.assertEqual(snapshot["capabilities"]["browser_cdp"]["health"], "healthy")
        self.assertEqual(snapshot["capabilities"]["scoring"]["health"], "unhealthy")
        self.assertEqual(snapshot["capabilities"]["scoring"]["detail"], "HTTP 403 Cloudflare challenge")
        self.assertNotIn("browser-session-secret", json.dumps(snapshot))


if __name__ == "__main__":
    unittest.main(verbosity=2)
