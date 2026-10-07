from __future__ import annotations

import contextlib
import io
import json
import os
import runpy
import socket
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

from tests.rookery.test_preparation_and_isolation import copy_rookery
from rookery.portable.scope import CompiledScopeBinding, ScopeAuthorityError


class _Response:
    def __init__(self, payload: bytes) -> None:
        self.payload = payload
        self.read_sizes: list[int] = []

    def __enter__(self) -> "_Response":
        return self

    def __exit__(self, *args: object) -> None:
        del args

    def read(self, size: int) -> bytes:
        self.read_sizes.append(size)
        return self.payload[:size]


class SearxngEnvironmentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        copy_rookery(self.root)
        self.module = runpy.run_path(
            str(self.root / "bin" / "searxng"),
            run_name=f"searxng_environment_{id(self)}",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write_scope(
        self,
        *,
        host: str = "fixture.invalid",
        cidrs: list[str] | None = None,
        ports: list[int] | None = None,
        protocols: list[str] | None = None,
    ) -> None:
        (self.root / "state").mkdir(exist_ok=True)
        scope = {
            "acknowledged": True,
            "generation": 1,
            "expires_at": "unknown",
            "allowed_hosts": [host],
            "allowed_cidrs": cidrs or [],
            "allowed_ports": ports or [443],
            "allowed_protocols": protocols or ["https"],
            "allowed_file_origins": [],
            "platform_hosts": [],
            "max_attachment_bytes": 1024,
        }
        (self.root / "state" / "scope.json").write_text(
            json.dumps(scope),
            encoding="utf-8",
        )
        self.binding = CompiledScopeBinding(
            scope=scope,
            scope_generation=1,
            stop_generation=0,
            file_sha256="a" * 64,
            content_sha256="b" * 64,
            launch_binding_sha256="c" * 64,
        )
        self.module["query"].__globals__.update(
            {
                "load_canonical_compiled_scope": lambda _root: self.binding,
                "verify_canonical_compiled_scope_binding": lambda _root, **_kwargs: self.binding,
            }
        )

    def _write_env(self, endpoint: str, extra: str = "") -> None:
        (self.root / ".env").write_text(
            "SEARXNG_MODE=auto\n" f"SEARXNG_URL={endpoint}\n" + extra,
            encoding="utf-8",
        )

    def _query_with_transport(
        self,
        payload: bytes = b'{"results": []}',
        argv: list[str] | None = None,
    ) -> tuple[dict[str, object], mock.Mock, _Response]:
        response = _Response(payload)
        transport = mock.Mock(return_value=response)
        with mock.patch.dict(
            self.module["query"].__globals__, {"open_scoped_url": transport}
        ):
            result = self.module["query"](self.root, argv or ["fixture"])
        return result, transport, response

    def _main_without_transport(self) -> tuple[int, str, str, mock.Mock]:
        output = io.StringIO()
        errors = io.StringIO()
        transport = mock.Mock()
        with (
            contextlib.redirect_stdout(output),
            contextlib.redirect_stderr(errors),
            mock.patch.dict(
                self.module["query"].__globals__, {"open_scoped_url": transport}
            ),
        ):
            result = self.module["main"](["fixture"], root=self.root)
        return result, output.getvalue(), errors.getvalue(), transport

    def test_uses_scope_checked_explicit_transport_and_bounds_selection(self) -> None:
        self._write_env("https://fixture.invalid/search")
        self._write_scope()
        result, transport, response = self._query_with_transport(
            json.dumps(
                {
                    "query": "fixture",
                    "number_of_results": 3,
                    "results": [
                        {"title": "one"},
                        {"title": "two"},
                        {"title": "three"},
                    ],
                }
            ).encode("utf-8"),
            ["fixture", "--top", "2"],
        )

        self.assertEqual([item["title"] for item in result["results"]], ["one", "two"])
        self.assertEqual(response.read_sizes, [8 * 1024 * 1024 + 1])
        scope, request = transport.call_args.args[:2]
        self.assertTrue(scope["acknowledged"])
        self.assertEqual(request.get_header("Accept"), "application/json")
        self.assertIn("transport", transport.call_args.kwargs)

    def test_canonical_loader_or_recheck_refusal_prevents_runtime_transport(self) -> None:
        self._write_env("https://fixture.invalid/search")
        self._write_scope()
        for stage in (
            "schema-less file",
            "widened same-generation file",
            "same-generation forged file",
            "manifest generation drift",
            "sqlite scope generation drift",
            "stop generation race",
            "file swap",
        ):
            with self.subTest(stage=stage):
                opened = mock.Mock()
                loader = (
                    mock.Mock(side_effect=ScopeAuthorityError("canonical_compiled_scope_unavailable"))
                    if "file" in stage
                    else lambda _root: self.binding
                )
                verifier = mock.Mock(
                    side_effect=ScopeAuthorityError("canonical_compiled_scope_unavailable")
                )
                with mock.patch.dict(
                    self.module["query"].__globals__,
                    {
                        "load_canonical_compiled_scope": loader,
                        "verify_canonical_compiled_scope_binding": verifier,
                        "open_scoped_url": opened,
                    },
                ):
                    self.assertEqual(self.module["main"](["fixture"], root=self.root), 2)
                opened.assert_not_called()

    def test_ambient_proxy_and_ca_are_ignored(self) -> None:
        target_hits: list[str] = []
        proxy_hits: list[str] = []

        class TargetHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                target_hits.append(self.path)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'{"results": []}')

            def log_message(self, _format: str, *args: object) -> None:
                del args

        class ProxyHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                proxy_hits.append(self.path)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'{"results": []}')

            def log_message(self, _format: str, *args: object) -> None:
                del args

        target = ThreadingHTTPServer(("127.0.0.1", 0), TargetHandler)
        proxy = ThreadingHTTPServer(("127.0.0.1", 0), ProxyHandler)
        target_thread = threading.Thread(target=target.serve_forever, daemon=True)
        proxy_thread = threading.Thread(target=proxy.serve_forever, daemon=True)
        target_thread.start()
        proxy_thread.start()
        original_getaddrinfo = socket.getaddrinfo
        resolution_count = 0

        def fixture_address(host: str, port: int, *args: object, **kwargs: object) -> object:
            nonlocal resolution_count
            if host == "fixture.invalid":
                resolution_count += 1
                return original_getaddrinfo("127.0.0.1", port, *args, **kwargs)
            return original_getaddrinfo(host, port, *args, **kwargs)

        try:
            self._write_env(f"http://fixture.invalid:{target.server_port}/search")
            self._write_scope(
                cidrs=["127.0.0.0/8"],
                ports=[target.server_port],
                protocols=["http"],
                host="fixture.invalid",
            )
            with (
                mock.patch.dict(
                    os.environ,
                    {
                        "HTTP_PROXY": f"http://127.0.0.1:{proxy.server_port}",
                        "HTTPS_PROXY": f"http://127.0.0.1:{proxy.server_port}",
                        "SSL_CERT_FILE": str(self.root / "ambient-ca-that-must-not-load.pem"),
                        "NO_PROXY": "",
                    },
                    clear=False,
                ),
                mock.patch("socket.getaddrinfo", side_effect=fixture_address),
                contextlib.redirect_stdout(io.StringIO()),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                result = self.module["main"](["fixture"], root=self.root)
        finally:
            target.shutdown()
            proxy.shutdown()
            target.server_close()
            proxy.server_close()
            target_thread.join(timeout=2)
            proxy_thread.join(timeout=2)

        self.assertEqual(result, 0)
        self.assertEqual(len(target_hits), 1)
        self.assertEqual(proxy_hits, [])
        self.assertEqual(resolution_count, 1)

    def test_declared_proxy_and_ca_fail_before_dns_or_socket_use(self) -> None:
        target_hits: list[str] = []

        class ProxyHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                target_hits.append(self.path)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'{"results": []}')

            def log_message(self, _format: str, *args: object) -> None:
                del args

        proxy = ThreadingHTTPServer(("127.0.0.1", 0), ProxyHandler)
        thread = threading.Thread(target=proxy.serve_forever, daemon=True)
        thread.start()
        cafile = __import__("ssl").get_default_verify_paths().openssl_cafile
        if not cafile or not Path(cafile).is_file():
            self.skipTest("compiled system CA file is unavailable")
        proxy_url = f"http://127.0.0.1:{proxy.server_port}"
        self._write_env(
            "http://fixture.invalid/search",
            "SEARXNG_NETWORK_ENV_KEYS=[\"HTTP_PROXY\",\"SSL_CERT_FILE\"]\n"
            f"HTTP_PROXY={proxy_url}\nSSL_CERT_FILE={Path(cafile).resolve()}\n",
        )
        self._write_scope(
            cidrs=["127.0.0.0/8"],
            ports=[80, proxy.server_port],
            protocols=["http"],
        )
        factory = self.module["ExplicitNetworkPolicy"].from_child_environment
        try:
            with (
                mock.patch.dict(
                    os.environ,
                    {
                        "HTTP_PROXY": "http://ambient-proxy.invalid:1",
                        "SSL_CERT_FILE": str(self.root / "ambient-ca-that-must-not-load.pem"),
                    },
                    clear=False,
                ),
                mock.patch.object(
                    self.module["ExplicitNetworkPolicy"],
                    "from_child_environment",
                    wraps=factory,
                ) as configured,
                mock.patch(
                    "socket.getaddrinfo",
                    side_effect=AssertionError("selected proxy reached DNS"),
                ),
                contextlib.redirect_stdout(io.StringIO()),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                result = self.module["main"](["fixture"], root=self.root)
        finally:
            proxy.shutdown()
            proxy.server_close()
            thread.join(timeout=2)

        self.assertEqual(result, 2)
        self.assertEqual(target_hits, [])
        child = configured.call_args.args[0]
        self.assertEqual(child.values["HTTP_PROXY"], proxy_url)
        self.assertEqual(child.values["SSL_CERT_FILE"], str(Path(cafile).resolve()))
        metadata = json.dumps(child.metadata())
        self.assertNotIn(proxy_url, metadata)
        self.assertNotIn(str(Path(cafile).resolve()), metadata)
        self.assertEqual(configured.call_args.kwargs["scope"]["generation"], 1)

    def test_offscope_declared_credentialed_proxy_fails_before_transport(self) -> None:
        secret = "searxng-proxy-password"
        self._write_env(
            "http://fixture.invalid/search",
            "SEARXNG_NETWORK_ENV_KEYS=[\"HTTP_PROXY\"]\n"
            f"HTTP_PROXY=http://proxy-user:{secret}@127.0.0.1:8118\n",
        )
        # The endpoint is allowed, but no local proxy authority is declared.
        self._write_scope(ports=[80], protocols=["http"])

        result, stdout, stderr, transport = self._main_without_transport()

        self.assertEqual(result, 2)
        self.assertEqual(stdout, "")
        self.assertEqual(stderr, "SearXNG request could not be completed\n")
        transport.assert_not_called()
        self.assertNotIn(secret, stdout + stderr)

    def test_declared_no_proxy_bypasses_the_declared_proxy(self) -> None:
        target_hits: list[str] = []
        proxy_hits: list[str] = []

        class TargetHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                target_hits.append(self.path)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'{"results": []}')

            def log_message(self, _format: str, *args: object) -> None:
                del args

        class ProxyHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                proxy_hits.append(self.path)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'{"results": []}')

            def log_message(self, _format: str, *args: object) -> None:
                del args

        target = ThreadingHTTPServer(("127.0.0.1", 0), TargetHandler)
        proxy = ThreadingHTTPServer(("127.0.0.1", 0), ProxyHandler)
        target_thread = threading.Thread(target=target.serve_forever, daemon=True)
        proxy_thread = threading.Thread(target=proxy.serve_forever, daemon=True)
        target_thread.start()
        proxy_thread.start()
        try:
            proxy_url = f"http://127.0.0.1:{proxy.server_port}"
            self._write_env(
                f"http://127.0.0.1:{target.server_port}/search",
                "SEARXNG_NETWORK_ENV_KEYS=[\"HTTP_PROXY\",\"NO_PROXY\"]\n"
                f"HTTP_PROXY={proxy_url}\nNO_PROXY=127.0.0.1\n",
            )
            self._write_scope(
                cidrs=["127.0.0.0/8"],
                ports=[target.server_port, proxy.server_port],
                protocols=["http"],
            )
            with (
                contextlib.redirect_stdout(io.StringIO()),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                result = self.module["main"](["fixture"], root=self.root)
        finally:
            target.shutdown()
            proxy.shutdown()
            target.server_close()
            proxy.server_close()
            target_thread.join(timeout=2)
            proxy_thread.join(timeout=2)

        self.assertEqual(result, 0)
        self.assertEqual(len(target_hits), 1)
        self.assertEqual(proxy_hits, [])

    def test_invalid_network_and_endpoint_configurations_fail_before_transport_without_values(self) -> None:
        secret = "sensitive-value-must-not-leak"
        configurations = (
            (
                "missing selected proxy",
                "https://fixture.invalid/search",
                'SEARXNG_NETWORK_ENV_KEYS=["HTTP_PROXY"]\n',
            ),
            (
                "conflicting aliases",
                "https://fixture.invalid/search",
                "SEARXNG_NETWORK_ENV_KEYS=[\"HTTP_PROXY\",\"http_proxy\"]\n"
                f"HTTP_PROXY=http://{secret}@one.invalid\n"
                f"http_proxy=http://{secret}@two.invalid\n",
            ),
            (
                "credentialed endpoint",
                f"https://user:{secret}@fixture.invalid/search",
                "",
            ),
            ("unsupported scheme", "file:///tmp/fixture", ""),
            (
                "control character",
                '"https://fixture.invalid/\\u0001"',
                "",
            ),
            (
                "oversized endpoint",
                "https://fixture.invalid/" + "x" * (8 * 1024),
                "",
            ),
        )
        self._write_scope()
        for label, endpoint, extra in configurations:
            with self.subTest(label=label):
                self._write_env(endpoint, extra)
                result, stdout, stderr, transport = self._main_without_transport()
                self.assertEqual(result, 2)
                self.assertEqual(stdout, "")
                self.assertEqual(stderr, "SearXNG request could not be completed\n")
                transport.assert_not_called()
                self.assertNotIn(secret, stdout + stderr)

    def test_disabled_mode_rejects_before_transport_and_validates_selector(self) -> None:
        (self.root / ".env").write_text(
            "SEARXNG_MODE=disabled\n"
            "SEARXNG_URL=https://fixture.invalid/search\n"
            "SEARXNG_NETWORK_ENV_KEYS=[\"HTTP_PROXY\"]\n",
            encoding="utf-8",
        )
        self._write_scope()
        result, stdout, stderr, transport = self._main_without_transport()
        self.assertEqual(result, 2)
        self.assertEqual(stdout, "")
        self.assertEqual(stderr, "SearXNG request could not be completed\n")
        transport.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
