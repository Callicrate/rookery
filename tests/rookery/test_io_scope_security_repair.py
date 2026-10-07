"""Focused P0-1 I/O-scope regression coverage.

Handoff gap report (2026-08-28): source edits were stopped after two consecutive
scope.py/adapters.py content drifts from another active session.  The tests below
are deliberately discriminating: they require traversal refusal before a local
open, no second HTTP request on an off-scope redirect, no-clobber attachment
publication, WebSocket scope preflight before connect, URL-aware cookie selection,
and a bounded WebSocket transcript.  At handoff, the still-unverified integration
gaps were use of the shared checked HTTP boundary by HTB and Immersive helpers,
descriptor identity binding for local reads, and the WebSocket cookie/TLS/resource
limits represented by these tests.  Re-run this module in WSL after serialization.
"""

from __future__ import annotations

# ruff: noqa: E402

from contextlib import nullcontext
import http.server
import json
import runpy
import sys
import tempfile
import threading
import types
import unittest
from pathlib import Path
from unittest import mock

from tests.rookery.support import ROOKERY_ROOT
from tests.rookery.test_acceptance_campaign import make_deployed_workspace

LIB = ROOKERY_ROOT / "lib"
if str(LIB) not in sys.path:
    sys.path.insert(0, str(LIB))

from rookery.portable.adapters import capture_file


def scoped(*, ports: list[int] | None = None) -> dict:
    return {
        "acknowledged": True,
        "generation": 1,
        "expires_at": "unknown",
        "allowed_hosts": ["127.0.0.1", "fixture.invalid"],
        "allowed_cidrs": [],
        "allowed_ports": ports or [],
        "allowed_protocols": ["http", "https", "wss"],
        "allowed_file_origins": ["downloads/*", "source.bin", "http://127.0.0.1:*/*"],
        "platform_hosts": ["fixture.invalid"],
        "max_attachment_bytes": 4096,
    }


def fake_binding(scope: dict[str, object]):
    return types.SimpleNamespace(
        scope=scope,
        scope_generation=int(scope["generation"]),
        stop_generation=0,
        file_sha256="a" * 64,
        content_sha256="b" * 64,
        launch_binding_sha256="c" * 64,
    )


class _RedirectServer(http.server.ThreadingHTTPServer):
    target_url = ""
    target_hits = 0


class _RedirectHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        self.send_response(302)
        self.send_header("Location", type(self.server).target_url)
        self.end_headers()

    def log_message(self, format: str, *args: object) -> None:
        del format, args


class _TargetHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        _RedirectServer.target_hits += 1
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"target bytes")

    def log_message(self, format: str, *args: object) -> None:
        del format, args


class IoScopeSecurityRepairTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_local_attachment_traversal_is_refused_before_open(self) -> None:
        (self.root / "downloads").mkdir()
        (self.root / ".env").write_text("sentinel", encoding="utf-8")

        with self.assertRaisesRegex(RuntimeError, "traversal"):
            capture_file(
                self.root,
                scoped(),
                {"path": "downloads/../.env"},
                self.root / "captured.bin",
            )
        self.assertFalse((self.root / "captured.bin").exists())

    def test_redirect_to_unscoped_port_is_refused_before_second_request(self) -> None:
        target = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _TargetHandler)
        redirect = _RedirectServer(("127.0.0.1", 0), _RedirectHandler)
        _RedirectServer.target_url = (
            f"http://127.0.0.1:{target.server_port}/target"
        )
        _RedirectServer.target_hits = 0
        target_thread = threading.Thread(target=target.serve_forever, daemon=True)
        redirect_thread = threading.Thread(target=redirect.serve_forever, daemon=True)
        target_thread.start()
        redirect_thread.start()
        try:
            origin = f"http://127.0.0.1:{redirect.server_port}/start"
            with self.assertRaisesRegex(RuntimeError, "scope"):
                capture_file(
                    self.root,
                    scoped(ports=[redirect.server_port]),
                    {"url": origin},
                    self.root / "captured.bin",
                )
            self.assertEqual(_RedirectServer.target_hits, 0)
            self.assertFalse((self.root / "captured.bin").exists())
        finally:
            redirect.shutdown()
            target.shutdown()
            redirect.server_close()
            target.server_close()
            redirect_thread.join(timeout=2)
            target_thread.join(timeout=2)

    def test_duplicate_attachment_destination_never_overwrites_first_capture(self) -> None:
        source = self.root / "source.bin"
        source.write_bytes(b"first")
        destination = self.root / "captured.bin"
        capture_file(self.root, scoped(), {"path": "source.bin"}, destination)
        source.write_bytes(b"second")

        with self.assertRaisesRegex(RuntimeError, "already exists"):
            capture_file(self.root, scoped(), {"path": "source.bin"}, destination)
        self.assertEqual(destination.read_bytes(), b"first")

    def _cluster_namespace(self) -> tuple[dict, dict, Path]:
        workspace = make_deployed_workspace("manual")
        self.addCleanup(workspace.cleanup)
        root = Path(workspace.name)
        namespace = runpy.run_path(
            str(root / "adapters/immersive/bin/immersive-cluster-capture")
        )
        globals_dict = namespace["main"].__globals__
        globals_dict["ROOT"] = root
        return namespace, globals_dict, root

    def test_offscope_websocket_is_not_connected_or_given_cookies(self) -> None:
        namespace, globals_dict, root = self._cluster_namespace()
        globals_dict["scope_guard_url"] = mock.Mock(
            side_effect=RuntimeError("scope denied")
        )
        fake_websocket = types.SimpleNamespace(create_connection=mock.Mock())
        outdir = root / "evidence" / "immersive" / "ws-offscope"
        with (
            mock.patch.object(
                sys,
                "argv",
                [
                    "immersive-cluster-capture",
                    "--url",
                    "wss://offscope.invalid/cable",
                    "--outdir",
                    str(outdir),
                ],
            ),
            mock.patch.dict(sys.modules, {"websocket": fake_websocket}),
        ):
            self.assertEqual(namespace["main"](), 4)
        fake_websocket.create_connection.assert_not_called()
        self.assertFalse(outdir.exists())

    def test_websocket_cookie_scope_and_frame_budget_are_enforced(self) -> None:
        namespace, globals_dict, root = self._cluster_namespace()
        globals_dict["scope_guard_url"] = lambda _url: fake_binding(scoped())
        globals_dict["_verify_effect_binding"] = lambda binding: binding
        globals_dict["_scope_effect"] = lambda binding: nullcontext(binding)
        globals_dict["scoped_connection_plan"] = mock.Mock(return_value=object())
        globals_dict["connect_scoped_stream"] = mock.Mock(return_value=mock.Mock())
        downloads = root / "downloads"
        downloads.mkdir(exist_ok=True)
        cookie_source = downloads / "cookies.json"
        cookie_source.write_text(
            json.dumps(
                {
                    "cookies": [
                        {
                            "name": "right",
                            "value": "one",
                            "domain": ".fixture.invalid",
                            "path": "/cable",
                            "secure": True,
                        },
                        {
                            "name": "wrong-path",
                            "value": "two",
                            "domain": "fixture.invalid",
                            "path": "/admin",
                        },
                        {
                            "name": "plain",
                            "value": "zero",
                            "domain": "fixture.invalid",
                            "path": "/",
                            "secure": False,
                        },
                        {
                            "name": "wrong-domain",
                            "value": "three",
                            "domain": "other.invalid",
                            "path": "/",
                        },
                        {
                            "name": "secure-over-ws",
                            "value": "four",
                            "domain": "fixture.invalid",
                            "path": "/",
                            "secure": True,
                        },
                    ]
                }
            ),
            encoding="utf-8",
        )
        header = namespace["cookie_header_for_url"](
            cookie_source,
            "wss://fixture.invalid/cable/live",
            max_source_bytes=4096,
            max_cookies=16,
            max_header_bytes=256,
        )
        self.assertEqual(header, "right=one; plain=zero; secure-over-ws=four")
        insecure_header = namespace["cookie_header_for_url"](
            cookie_source,
            "ws://fixture.invalid/cable/live",
            max_source_bytes=4096,
            max_cookies=16,
            max_header_bytes=256,
        )
        self.assertEqual(insecure_header, "plain=zero")

        class FakeWebSocket:
            def __init__(self) -> None:
                self.closed = False

            def send(self, _message: str) -> None:
                return None

            def recv(self) -> str:
                return "x" * 1025

            def close(self) -> None:
                self.closed = True

        connection = FakeWebSocket()
        fake_websocket = types.SimpleNamespace(
            create_connection=mock.Mock(return_value=connection)
        )
        outdir = root / "evidence" / "immersive" / "ws-bounded"
        with (
            mock.patch.object(
                sys,
                "argv",
                [
                    "immersive-cluster-capture",
                    "--url",
                    "wss://fixture.invalid/cable",
                    "--outdir",
                    str(outdir),
                    "--max-frame-bytes",
                    "1024",
                    "--max-messages",
                    "4",
                    "--max-transcript-bytes",
                    "4096",
                ],
            ),
            mock.patch.dict(sys.modules, {"websocket": fake_websocket}),
        ):
            self.assertEqual(namespace["main"](), 5)
        self.assertTrue(connection.closed)
        transcript = json.loads((outdir / "transcript.json").read_text(encoding="utf-8"))
        self.assertEqual(transcript["termination"], "output_limit")
        self.assertEqual(transcript["events"], [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
