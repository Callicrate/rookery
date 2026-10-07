from __future__ import annotations

from contextlib import nullcontext
import http.server
import io
import json
import os
import runpy
import sys
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


def scoped(*, host: str = "fixture.invalid", ports: list[int] | None = None) -> dict:
    return {
        "acknowledged": True,
        "generation": 1,
        "expires_at": "unknown",
        "allowed_hosts": [host],
        "allowed_cidrs": ["127.0.0.0/8", "::1/128"],
        "allowed_ports": ports or [],
        "allowed_protocols": ["http", "https", "ws", "wss"],
        "allowed_file_origins": [],
        "platform_hosts": [host],
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


def install_fake_authority(
    globals_dict: dict[str, object], scope: dict[str, object]
) -> None:
    globals_dict["scope_guard_url"] = lambda _url: fake_binding(scope)
    globals_dict["_verify_effect_binding"] = lambda binding: binding
    globals_dict["_scope_effect"] = lambda binding: nullcontext(binding)


class _RedirectServer(http.server.ThreadingHTTPServer):
    target_url = ""


class _RedirectHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        self.send_response(302)
        self.send_header("Location", type(self.server).target_url)
        self.end_headers()

    def log_message(self, format: str, *args: object) -> None:
        del format, args


class _TargetServer(http.server.ThreadingHTTPServer):
    hits = 0


class _TargetHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        type(self.server).hits += 1
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'{"data": []}')

    def log_message(self, format: str, *args: object) -> None:
        del format, args


class _Response(io.BytesIO):
    status = 200

    def __init__(self, body: bytes, headers: dict[str, str] | None = None) -> None:
        super().__init__(body)
        self.headers = headers or {"Content-Type": "application/json"}

    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()


@unittest.skipUnless(os.name == "posix", "requires private POSIX test storage")
class AdapterNetworkScopeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.workspace = make_deployed_workspace("manual")
        self.root = Path(self.workspace.name)

    def tearDown(self) -> None:
        self.workspace.cleanup()

    def test_ctfd_redirect_to_offscope_port_never_reaches_target(self) -> None:
        target = _TargetServer(("127.0.0.1", 0), _TargetHandler)
        redirect = _RedirectServer(("127.0.0.1", 0), _RedirectHandler)
        _TargetServer.hits = 0
        _RedirectServer.target_url = f"http://127.0.0.1:{target.server_port}/target"
        target_thread = threading.Thread(target=target.serve_forever, daemon=True)
        redirect_thread = threading.Thread(target=redirect.serve_forever, daemon=True)
        target_thread.start()
        redirect_thread.start()
        try:
            namespace = runpy.run_path(str(ROOKERY_ROOT / "adapters/ctfd/adapter.py"))
            (self.root / ".env").write_text(
                f"CTFD_URL=http://127.0.0.1:{redirect.server_port}\n",
                encoding="utf-8",
            )
            adapter = namespace["CTFdAdapter"](
                self.root,
                {
                    "adapter": {
                        "config": {
                            "base_url": f"http://127.0.0.1:{redirect.server_port}"
                        }
                    }
                },
                scoped(host="127.0.0.1", ports=[redirect.server_port]),
            )

            snapshot = adapter.sync()

            self.assertEqual(_TargetServer.hits, 0)
            self.assertEqual(
                snapshot["capabilities"]["platform_inventory"]["health"],
                "unhealthy",
            )
        finally:
            redirect.shutdown()
            target.shutdown()
            redirect.server_close()
            target.server_close()
            redirect_thread.join(timeout=2)
            target_thread.join(timeout=2)

    def test_ctfd_scoped_fixture_uses_fake_transport_and_redacts_headers(self) -> None:
        namespace = runpy.run_path(str(ROOKERY_ROOT / "adapters/ctfd/adapter.py"))
        globals_dict = namespace["CTFdAdapter"].execute_action.__globals__
        (self.root / ".env").write_text(
            "CTFD_URL=https://fixture.invalid\nCTFD_TOKEN=fixture-token\n",
            encoding="utf-8",
        )
        response = _Response(
            b'{"success": true, "data": {}}',
            {"Content-Type": "application/json", "Set-Cookie": "secret"},
        )
        transport = mock.Mock(return_value=response)
        globals_dict["open_scoped_url"] = transport
        adapter = namespace["CTFdAdapter"](
            self.root,
            {"adapter": {"config": {"base_url": "https://fixture.invalid"}}},
            scoped(),
        )

        result = adapter.execute_action(
            {"objective_id": "1", "exact_value": "FLAG{fixture}"},
            self.root / "evidence",
        )

        transport.assert_called_once()
        self.assertEqual(result["response"]["headers"]["set-cookie"], "[redacted]")

    def test_websocket_cookie_selection_and_limits_are_enforced(self) -> None:
        namespace = runpy.run_path(
            str(ROOKERY_ROOT / "adapters/immersive/bin/immersive-cluster-capture")
        )
        globals_dict = namespace["main"].__globals__
        globals_dict["ROOT"] = self.root
        downloads = self.root / "downloads"
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
                            "domain": ".fixture.invalid",
                            "path": "/admin",
                        },
                        {
                            "name": "wrong-domain",
                            "value": "three",
                            "domain": ".other.invalid",
                            "path": "/",
                        },
                        {
                            "name": "secure-wss",
                            "value": "four",
                            "domain": ".fixture.invalid",
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
        self.assertEqual(header, "right=one; secure-wss=four")

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
        install_fake_authority(globals_dict, scoped())
        pinned_stream = mock.Mock()
        globals_dict["scoped_connection_plan"] = mock.Mock(return_value=object())
        globals_dict["connect_scoped_stream"] = mock.Mock(return_value=pinned_stream)
        with (
            mock.patch.object(
                sys,
                "argv",
                [
                    "immersive-cluster-capture",
                    "--url",
                    "wss://fixture.invalid/cable",
                    "--outdir",
                    str(self.root / "evidence" / "immersive" / "ws"),
                    "--max-frame-bytes",
                    "1024",
                ],
            ),
            mock.patch.dict(sys.modules, {"websocket": fake_websocket}),
        ):
            self.assertEqual(namespace["main"](), 5)
        self.assertIs(
            fake_websocket.create_connection.call_args.kwargs["socket"], pinned_stream
        )
        self.assertEqual(
            fake_websocket.create_connection.call_args.kwargs["redirect_limit"], 0
        )
        self.assertTrue(connection.closed)
        transcript = json.loads(
            (self.root / "evidence" / "immersive" / "ws/transcript.json").read_text()
        )
        self.assertEqual(transcript["termination"], "output_limit")
        self.assertEqual(transcript["reason"], "frame_bytes")
        self.assertEqual(transcript["events"], [])

    def test_offscope_or_insecure_websocket_never_connects_or_loads_cookies(
        self,
    ) -> None:
        namespace = runpy.run_path(
            str(ROOKERY_ROOT / "adapters/immersive/bin/immersive-cluster-capture")
        )
        globals_dict = namespace["main"].__globals__
        globals_dict["ROOT"] = self.root
        fake_websocket = types.SimpleNamespace(create_connection=mock.Mock())
        cookie_builder = mock.Mock(return_value="session=secret")
        globals_dict["scope_guard_url"] = mock.Mock(
            side_effect=RuntimeError("scope denied")
        )
        globals_dict["cookie_header_for_url"] = cookie_builder
        with (
            mock.patch.object(
                sys,
                "argv",
                [
                    "immersive-cluster-capture",
                    "--url",
                    "wss://offscope.invalid/cable",
                    "--outdir",
                    str(self.root / "evidence" / "immersive" / "offscope"),
                ],
            ),
            mock.patch.dict(sys.modules, {"websocket": fake_websocket}),
        ):
            self.assertEqual(namespace["main"](), 4)
        fake_websocket.create_connection.assert_not_called()
        cookie_builder.assert_not_called()

        install_fake_authority(globals_dict, scoped())
        with (
            mock.patch.object(
                sys,
                "argv",
                [
                    "immersive-cluster-capture",
                    "--url",
                    "wss://fixture.invalid/cable",
                    "--insecure",
                ],
            ),
            mock.patch.dict(sys.modules, {"websocket": fake_websocket}),
        ):
            self.assertEqual(namespace["main"](), 2)
        fake_websocket.create_connection.assert_not_called()

    def test_refresh_http_scope_gate_precedes_cookies_and_scoped_fixture_works(
        self,
    ) -> None:
        namespace = runpy.run_path(
            str(ROOKERY_ROOT / "adapters/immersive/bin/immersive-selected-lab-refresh")
        )
        globals_dict = namespace["main"].__globals__
        globals_dict["ROOT"] = self.root
        globals_dict["read_env"] = lambda: {
            "IMMERSIVE_GRAPHQL_URL": "https://fixture.invalid/graphql",
            "IMMERSIVE_COOKIES_FILE": str(self.root / "cookies.json"),
        }
        globals_dict["scope_guard_url"] = mock.Mock(
            side_effect=RuntimeError("scope denied")
        )
        cookie_builder = mock.Mock(return_value="session=secret")
        globals_dict["cookie_header_for_url"] = cookie_builder
        with mock.patch.object(
            sys,
            "argv",
            [
                "immersive-selected-lab-refresh",
                "--outdir",
                str(self.root / "evidence" / "immersive" / "refresh-offscope"),
            ],
        ):
            self.assertEqual(namespace["main"](), 1)
        cookie_builder.assert_not_called()

        response = _Response(
            b'{"data": {"selectedLab": {"id": "fixture"}}}',
            {"Content-Type": "application/json", "Set-Cookie": "secret"},
        )
        transport = mock.Mock(return_value=response)
        install_fake_authority(globals_dict, scoped())
        globals_dict["cookie_header_for_url"] = lambda *_args, **_kwargs: ""
        globals_dict["mutation_check"] = lambda *_args, **_kwargs: True
        globals_dict["open_scoped_url"] = transport
        with mock.patch.object(
            sys,
            "argv",
            [
                "immersive-selected-lab-refresh",
                "--outdir",
                str(self.root / "evidence" / "immersive" / "refresh-ok"),
            ],
        ):
            self.assertEqual(namespace["main"](), 0)
        transport.assert_called_once()
        summary = json.loads(
            (self.root / "evidence" / "immersive" / "refresh-ok/summary.json").read_text()
        )
        self.assertEqual(summary["response_headers"]["set-cookie"], "[redacted]")


if __name__ == "__main__":
    unittest.main(verbosity=2)
