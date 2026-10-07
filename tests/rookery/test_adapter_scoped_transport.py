# ruff: noqa: E402, RUF100
from __future__ import annotations

import ast
import contextlib
import json
import os
import runpy
import sys
import tempfile
import threading
import unittest
import urllib.request
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

from tests.rookery.support import ROOKERY_ROOT

LIB = ROOKERY_ROOT / "lib"
if str(LIB) not in sys.path:
    sys.path.insert(0, str(LIB))

from rookery.portable.scope import CompiledScopeBinding
from rookery.portable.validator import _static_python_errors


def scoped(*, hosts: list[str], ports: list[int]) -> dict[str, object]:
    return {
        "acknowledged": True,
        "generation": 1,
        "expires_at": "unknown",
        "allowed_hosts": hosts,
        "allowed_cidrs": ["127.0.0.0/8", "::1/128"],
        "allowed_ports": ports,
        "allowed_protocols": ["http", "https"],
        "allowed_file_origins": [],
        "platform_hosts": hosts,
        "max_attachment_bytes": 4096,
    }


def bound(scope: dict[str, object]) -> CompiledScopeBinding:
    """Give direct transport tests the binding shape production callers retain."""

    return CompiledScopeBinding(
        scope=scope,
        scope_generation=int(scope["generation"]),
        stop_generation=0,
        file_sha256="a" * 64,
        content_sha256="b" * 64,
        launch_binding_sha256="c" * 64,
    )


@contextlib.contextmanager
def serve(handler: type[BaseHTTPRequestHandler]) -> Iterator[ThreadingHTTPServer]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


class AdapterScopedTransportTests(unittest.TestCase):
    """Regression coverage for the adapter-local raw-urllib removal.

    These checks deliberately exercise real loopback transports.  A monkeypatch
    of ``urllib`` would mask the very ambient-policy bypass this test guards.
    """

    def test_release_adapter_sources_do_not_reference_raw_urlopen(self) -> None:
        for relative in (
            "adapters/ctfd/adapter.py",
            "adapters/immersive/bin/immersive-selected-lab-refresh",
        ):
            with self.subTest(relative=relative):
                source = (ROOKERY_ROOT / relative).read_text(encoding="utf-8")
                tree = ast.parse(source, filename=relative)
                raw_references = [
                    node
                    for node in ast.walk(tree)
                    if isinstance(node, ast.Attribute)
                    and isinstance(node.value, ast.Attribute)
                    and isinstance(node.value.value, ast.Name)
                    and node.value.value.id == "urllib"
                    and node.value.attr == "request"
                    and node.attr == "urlopen"
                ]
                self.assertEqual(raw_references, [])
                self.assertIn("open_scoped_url", source)
                self.assertEqual(_static_python_errors(tree, relative), [])

    def test_ctfd_scoped_transport_ignores_ambient_proxy_and_blocks_redirect(self) -> None:
        target_hits: list[str] = []
        blocked_hits: list[str] = []

        class BlockedHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                blocked_hits.append(self.path)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'{"data": []}')

            def log_message(self, _format: str, *args: object) -> None:
                del args

        with serve(BlockedHandler) as blocked:

            class RedirectHandler(BaseHTTPRequestHandler):
                def do_GET(self) -> None:
                    target_hits.append(self.path)
                    self.send_response(302)
                    self.send_header(
                        "Location", f"http://localhost:{blocked.server_port}/outside"
                    )
                    self.end_headers()

                def log_message(self, _format: str, *args: object) -> None:
                    del args

            with serve(RedirectHandler) as target, tempfile.TemporaryDirectory() as name:
                namespace = runpy.run_path(
                    str(ROOKERY_ROOT / "adapters/ctfd/adapter.py")
                )
                adapter = namespace["CTFdAdapter"](
                    Path(name),
                    {
                        "adapter": {
                            "config": {
                                "base_url": f"http://127.0.0.1:{target.server_port}"
                            }
                        }
                    },
                    scoped(hosts=["127.0.0.1"], ports=[target.server_port]),
                )
                with mock.patch.dict(
                    os.environ,
                    {
                        "HTTP_PROXY": "http://127.0.0.1:1",
                        "HTTPS_PROXY": "http://127.0.0.1:1",
                        "ALL_PROXY": "http://127.0.0.1:1",
                    },
                    clear=False,
                ):
                    snapshot = adapter.sync()

        self.assertEqual(target_hits, ["/api/v1/challenges"])
        self.assertEqual(blocked_hits, [])
        capability = snapshot["capabilities"]["platform_inventory"]
        self.assertEqual(capability["health"], "unhealthy")

    def test_ctfd_declared_proxy_fails_before_any_proxy_effect(self) -> None:
        proxy_hits: list[str] = []

        class ProxyHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                proxy_hits.append(self.path)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'{"data": []}')

            def log_message(self, _format: str, *args: object) -> None:
                del args

        with serve(ProxyHandler) as proxy, tempfile.TemporaryDirectory() as name:
            root = Path(name)
            declared = f"http://127.0.0.1:{proxy.server_port}"
            root.joinpath(".env").write_text(
                "CTFD_URL=http://fixture.invalid\n"
                "CTFD_NETWORK_ENV_KEYS=[\"HTTP_PROXY\"]\n"
                f"HTTP_PROXY={declared}\n",
                encoding="utf-8",
            )
            namespace = runpy.run_path(str(ROOKERY_ROOT / "adapters/ctfd/adapter.py"))
            adapter = namespace["CTFdAdapter"](
                root,
                {"adapter": {"config": {}}},
                scoped(
                    hosts=["fixture.invalid", "127.0.0.1"],
                    ports=[80, proxy.server_port],
                ),
            )
            with mock.patch.dict(
                os.environ,
                {"HTTP_PROXY": "http://127.0.0.1:1"},
                clear=False,
            ):
                snapshot = adapter.sync()

        self.assertEqual(proxy_hits, [])
        self.assertEqual(
            snapshot["capabilities"]["platform_inventory"]["health"],
            "unhealthy",
            snapshot,
        )
        self.assertEqual(
            snapshot["capabilities"]["platform_inventory"]["detail"],
            "scoped_proxy_target_pinning_unavailable",
        )

    def test_ctfd_offscope_declared_proxy_is_never_contacted(self) -> None:
        proxy_hits: list[str] = []

        class ProxyHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                proxy_hits.append(self.path)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'{"data": []}')

            def log_message(self, _format: str, *args: object) -> None:
                del args

        with serve(ProxyHandler) as proxy, tempfile.TemporaryDirectory() as name:
            root = Path(name)
            root.joinpath(".env").write_text(
                "CTFD_URL=http://fixture.invalid\n"
                "CTFD_NETWORK_ENV_KEYS=[\"HTTP_PROXY\"]\n"
                f"HTTP_PROXY=http://127.0.0.1:{proxy.server_port}\n",
                encoding="utf-8",
            )
            namespace = runpy.run_path(str(ROOKERY_ROOT / "adapters/ctfd/adapter.py"))
            adapter = namespace["CTFdAdapter"](
                root,
                {"adapter": {"config": {}}},
                scoped(hosts=["fixture.invalid"], ports=[80]),
            )

            snapshot = adapter.sync()

        self.assertEqual(proxy_hits, [])
        capability = snapshot["capabilities"]["platform_inventory"]
        self.assertEqual(capability["health"], "unhealthy", snapshot)
        self.assertEqual(
            capability["detail"], "scoped_proxy_target_pinning_unavailable"
        )

    def test_ctfd_credentialed_offscope_proxy_is_value_free(self) -> None:
        proxy_hits: list[str] = []

        class ProxyHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                proxy_hits.append(self.path)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'{"data": []}')

            def log_message(self, _format: str, *args: object) -> None:
                del args

        with serve(ProxyHandler) as proxy, tempfile.TemporaryDirectory() as name:
            root = Path(name)
            username = "proxy-user"
            password = "proxy-pass"
            root.joinpath(".env").write_text(
                "CTFD_URL=http://fixture.invalid\n"
                "CTFD_NETWORK_ENV_KEYS=[\"HTTP_PROXY\"]\n"
                f"HTTP_PROXY=http://{username}:{password}@127.0.0.1:{proxy.server_port}\n",
                encoding="utf-8",
            )
            namespace = runpy.run_path(str(ROOKERY_ROOT / "adapters/ctfd/adapter.py"))
            adapter = namespace["CTFdAdapter"](
                root,
                {"adapter": {"config": {}}},
                scoped(hosts=["fixture.invalid"], ports=[80]),
            )

            snapshot = adapter.sync()

        self.assertEqual(proxy_hits, [])
        capability = snapshot["capabilities"]["platform_inventory"]
        self.assertEqual(capability["health"], "unhealthy")
        self.assertEqual(
            capability["detail"], "scoped_proxy_target_pinning_unavailable"
        )
        serialized = json.dumps(snapshot)
        self.assertNotIn(username, serialized)
        self.assertNotIn(password, serialized)
        self.assertNotIn("127.0.0.1", serialized)

    def test_ctfd_malformed_proxy_fails_before_transport(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            root.joinpath(".env").write_text(
                "CTFD_URL=http://fixture.invalid\n"
                "CTFD_NETWORK_ENV_KEYS=[\"HTTP_PROXY\"]\n"
                "HTTP_PROXY=ftp://malformed-proxy.invalid\n",
                encoding="utf-8",
            )
            namespace = runpy.run_path(str(ROOKERY_ROOT / "adapters/ctfd/adapter.py"))
            adapter = namespace["CTFdAdapter"](
                root,
                {"adapter": {"config": {}}},
                scoped(hosts=["fixture.invalid"], ports=[80]),
            )
            with mock.patch("socket.create_connection") as connect:
                snapshot = adapter.sync()

        connect.assert_not_called()
        capability = snapshot["capabilities"]["platform_inventory"]
        self.assertEqual(capability["health"], "unhealthy")
        self.assertEqual(capability["detail"], "configured proxy URL is invalid")
        self.assertNotIn("malformed-proxy.invalid", json.dumps(snapshot))

    def test_immersive_scoped_transport_ignores_ambient_proxy_and_checks_redirects(
        self,
    ) -> None:
        target_hits: list[str] = []
        blocked_hits: list[str] = []

        class BlockedHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                blocked_hits.append(self.path)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"{}")

            def log_message(self, _format: str, *args: object) -> None:
                del args

        with serve(BlockedHandler) as blocked:

            class RedirectHandler(BaseHTTPRequestHandler):
                def do_GET(self) -> None:
                    target_hits.append(self.path)
                    self.send_response(302)
                    self.send_header(
                        "Location", f"http://localhost:{blocked.server_port}/outside"
                    )
                    self.end_headers()

                def log_message(self, _format: str, *args: object) -> None:
                    del args

            with serve(RedirectHandler) as target, tempfile.TemporaryDirectory() as name:
                namespace = runpy.run_path(
                    str(
                        ROOKERY_ROOT
                        / "adapters/immersive/bin/immersive-selected-lab-refresh"
                    )
                )
                root = Path(name)
                with mock.patch.dict(
                    os.environ,
                    {"HTTP_PROXY": "http://127.0.0.1:1"},
                    clear=False,
                ):
                    network = namespace["resolve_network_policy"](root, "[]")
                    request = urllib.request.Request(
                        f"http://127.0.0.1:{target.server_port}/refresh"
                    )
                    with self.assertRaisesRegex(RuntimeError, "redirect blocked by scope"):
                        namespace["open_scoped"](
                            bound(
                                scoped(
                                    hosts=["127.0.0.1"],
                                    ports=[target.server_port],
                                )
                            ),
                            request,
                            timeout=5,
                            network=network,
                        )

        self.assertEqual(target_hits, ["/refresh"])
        self.assertEqual(blocked_hits, [])

    def test_immersive_declared_proxy_fails_before_any_proxy_effect(self) -> None:
        proxy_hits: list[str] = []

        class ProxyHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                proxy_hits.append(self.path)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"{}")

            def log_message(self, _format: str, *args: object) -> None:
                del args

        with serve(ProxyHandler) as proxy, tempfile.TemporaryDirectory() as name:
            namespace = runpy.run_path(
                str(
                    ROOKERY_ROOT
                    / "adapters/immersive/bin/immersive-selected-lab-refresh"
                )
            )
            root = Path(name)
            declared = f"http://127.0.0.1:{proxy.server_port}"
            root.joinpath(".env").write_text(
                "IMMERSIVE_NETWORK_ENV_KEYS=[\"HTTP_PROXY\"]\n"
                f"HTTP_PROXY={declared}\n",
                encoding="utf-8",
            )
            with mock.patch.dict(
                os.environ,
                {"HTTP_PROXY": "http://127.0.0.1:1"},
                clear=False,
            ):
                network = namespace["resolve_network_policy"](
                    root, '["HTTP_PROXY"]'
                )
                with self.assertRaisesRegex(
                    ValueError, "scoped_proxy_target_pinning_unavailable"
                ):
                    namespace["open_scoped"](
                        bound(scoped(hosts=["fixture.invalid"], ports=[])),
                        urllib.request.Request("http://fixture.invalid/refresh"),
                        timeout=5,
                        network=network,
                    )

        self.assertEqual(proxy_hits, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
