from __future__ import annotations

import io
import json
import os
import runpy
import ssl
import sys
import tempfile
import threading
import urllib.error
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Self
from unittest import mock

from tests.rookery.support import ROOKERY_ROOT

LIB = ROOKERY_ROOT / "lib"
if str(LIB) not in sys.path:
    sys.path.insert(0, str(LIB))

# ruff: noqa: E402
from rookery.portable.adapters import CommandAdapter


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
    ) -> None:
        super().__init__(body)
        self.status = status
        self.headers: dict[str, str] = headers or {"Content-Type": "application/json"}

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()


class CTFdEnvironmentTransportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.namespace = runpy.run_path(str(ROOKERY_ROOT / "adapters/ctfd/adapter.py"))
        self.adapter_class = self.namespace["CTFdAdapter"]
        self.globals = self.adapter_class.execute_action.__globals__

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def adapter(self, config: dict[str, object] | None = None):
        return self.adapter_class(
            self.root,
            {"adapter": {"config": config or {}}},
            scoped(),
        )

    def _execute(self, adapter, transport: mock.Mock) -> dict[str, object]:
        with mock.patch.dict(self.globals, {"open_scoped_url": transport}):
            return adapter.execute_action(
                {"objective_id": "1", "exact_value": "FLAG{fixture}"},
                self.root / "evidence",
            )

    def _sync(self, response: object) -> dict[str, object]:
        transport = mock.Mock(return_value=response)
        with mock.patch.dict(self.globals, {"open_scoped_url": transport}):
            return self.adapter({"base_url": "https://fixture.invalid"}).sync()

    def _assert_sync_failure(self, snapshot: dict[str, object], detail: str) -> None:
        self.assertEqual(snapshot["challenges"], [])
        capabilities = snapshot["capabilities"]
        for name in ("platform_inventory", "challenge_details", "scoring"):
            with self.subTest(capability=name):
                capability = capabilities[name]
                self.assertEqual(capability["health"], "unhealthy")
                self.assertEqual(capability["detail"], detail)

    def test_sync_reports_a_cloudflare_challenge_without_reading_its_body(self) -> None:
        blocked = urllib.error.HTTPError(
            "https://fixture.invalid/api/v1/challenges",
            403,
            "Forbidden",
            {"Server": "cloudflare", "CF-Mitigated": "challenge"},
            None,
        )
        transport = mock.Mock(side_effect=blocked)
        with mock.patch.dict(self.globals, {"open_scoped_url": transport}):
            snapshot = self.adapter({"base_url": "https://fixture.invalid"}).sync()

        self._assert_sync_failure(snapshot, "HTTP 403 Cloudflare challenge")
        self.assertNotIn("fixture.invalid/api/v1/challenges", json.dumps(snapshot))

    def test_sync_rejects_non_json_and_empty_success_responses(self) -> None:
        cases = {
            "html": (
                _Response(
                    b"<html>challenge page</html>",
                    headers={"Content-Type": "text/html"},
                ),
                "HTTP 200 expected application/json",
            ),
            "empty": (_Response(b""), "HTTP 200 empty response"),
        }
        for name, (response, detail) in cases.items():
            with self.subTest(response=name):
                self._assert_sync_failure(self._sync(response), detail)

    def test_sync_rejects_malformed_ctfd_json_shapes(self) -> None:
        cases = {
            "invalid-json": (b"{", "HTTP 200 invalid JSON response"),
            "array": (b"[]", "HTTP 200 invalid CTFd response shape"),
            "unsuccessful": (
                b'{"success": false, "data": []}',
                "HTTP 200 CTFd response was unsuccessful",
            ),
            "missing-data": (b'{"success": true}', "HTTP 200 invalid CTFd response shape"),
            "mapping-data": (
                b'{"success": true, "data": {}}',
                "HTTP 200 invalid CTFd response shape",
            ),
            "non-object-challenge": (
                b'{"success": true, "data": ["challenge"]}',
                "HTTP 200 invalid CTFd response shape",
            ),
        }
        for name, (body, detail) in cases.items():
            with self.subTest(response=name):
                self._assert_sync_failure(self._sync(_Response(body)), detail)

    def test_sync_accepts_well_formed_ctfd_challenge_data(self) -> None:
        snapshot = self._sync(
            _Response(
                b'{"success": true, "data": [{"id": 1, "name": "fixture"}]}'
            )
        )

        self.assertEqual(snapshot["challenges"][0]["id"], "1")
        self.assertEqual(snapshot["challenges"][0]["title"], "fixture")
        for name in ("platform_inventory", "challenge_details", "scoring"):
            self.assertEqual(snapshot["capabilities"][name]["health"], "healthy")

    def test_configured_base_url_and_dotenv_then_parent_credentials_are_resolved_at_use(
        self,
    ) -> None:
        self.root.joinpath(".env").write_text(
            "CTFD_URL=https://dotenv.invalid\n"
            "CTFD_SELECTED_TOKEN=dotenv-selected\n",
            encoding="utf-8",
        )
        adapter = self.adapter(
            {
                "base_url": "https://fixture.invalid/canonical/",
                "token_env": "CTFD_SELECTED_TOKEN",
            }
        )
        transport = mock.Mock(return_value=_Response(b'{"success": true, "data": []}'))
        with (
            mock.patch.dict(
                os.environ,
                {
                    "CTFD_URL": "https://parent.invalid",
                    "CTFD_SELECTED_TOKEN": "parent-selected",
                },
                clear=False,
            ),
            mock.patch.dict(self.globals, {"open_scoped_url": transport}),
        ):
            snapshot = adapter.sync()

        request = transport.call_args.args[1]
        self.assertEqual(
            request.full_url,
            "https://fixture.invalid/canonical/api/v1/challenges",
        )
        self.assertEqual(request.get_header("Authorization"), "Token dotenv-selected")
        self.assertEqual(snapshot["capabilities"]["platform_inventory"]["health"], "healthy")

        self.root.joinpath(".env").write_text("", encoding="utf-8")
        transport.reset_mock()
        with (
            mock.patch.dict(
                os.environ,
                {
                    "CTFD_URL": "https://parent.invalid",
                    "CTFD_SELECTED_TOKEN": "parent-selected",
                },
                clear=False,
            ),
            mock.patch.dict(self.globals, {"open_scoped_url": transport}),
        ):
            adapter.sync()
        request = transport.call_args.args[1]
        self.assertEqual(
            request.full_url,
            "https://fixture.invalid/canonical/api/v1/challenges",
        )
        self.assertEqual(request.get_header("Authorization"), "Token parent-selected")

        self.root.joinpath(".env").write_text(
            "CTFD_URL=https://fixture.invalid/dotenv\n"
            "CTFD_SELECTED_TOKEN=dotenv-selected\n",
            encoding="utf-8",
        )
        fallback_adapter = self.adapter({"token_env": "CTFD_SELECTED_TOKEN"})
        transport.reset_mock()
        with (
            mock.patch.dict(
                os.environ,
                {
                    "CTFD_URL": "https://fixture.invalid/parent",
                    "CTFD_SELECTED_TOKEN": "parent-selected",
                },
                clear=False,
            ),
            mock.patch.dict(self.globals, {"open_scoped_url": transport}),
        ):
            fallback_adapter.sync()
        request = transport.call_args.args[1]
        self.assertEqual(
            request.full_url,
            "https://fixture.invalid/dotenv/api/v1/challenges",
        )
        self.assertEqual(request.get_header("Authorization"), "Token dotenv-selected")

    def test_custom_token_selector_is_allowed_but_secret_capabilities_fail_pre_effect(
        self,
    ) -> None:
        forbidden = (
            "IMMERSIVE_COOKIES_FILE",
            "VPN_AUTH_FILE",
            "SSL_CERT_FILE",
            "HTTP_PROXY",
            "OPENAI_API_KEY",
            "SSH_AUTH_SOCK",
            "ROOKERY_OWNER_TOKEN",
        )
        for selector in forbidden:
            with self.subTest(selector=selector):
                self.root.joinpath(".env").write_text(
                    f"{selector}=fixture-value\n", encoding="utf-8"
                )
                transport = mock.Mock()
                with (
                    mock.patch.dict(self.globals, {"open_scoped_url": transport}),
                    self.assertRaisesRegex(RuntimeError, "token_env forbids class"),
                ):
                    self.adapter(
                        {"base_url": "https://fixture.invalid", "token_env": selector}
                    ).execute_action(
                        {"objective_id": "1", "exact_value": "FLAG{fixture}"},
                        self.root / "evidence",
                    )
                transport.assert_not_called()
                self.assertFalse((self.root / "evidence").exists())

    def test_selected_proxy_fails_before_transport_or_submission_evidence(
        self,
    ) -> None:
        token = "ctfd-transport-token"
        declared_proxy = "http://fixture.invalid:8080"
        self.root.joinpath(".env").write_text(
            "CTFD_URL=https://fixture.invalid\n"
            f"CTFD_TOKEN={token}\n"
            "CTFD_NETWORK_ENV_KEYS=[\"HTTPS_PROXY\", \"NO_PROXY\"]\n"
            f"HTTPS_PROXY={declared_proxy}\n"
            "NO_PROXY=inside.fixture.invalid\n",
            encoding="utf-8",
        )
        transport = mock.Mock(return_value=_Response(b'{"success": true, "data": {}}'))
        with mock.patch.dict(
            os.environ,
            {
                "HTTP_PROXY": "http://ambient-proxy.invalid:9999",
                "HTTPS_PROXY": "http://ambient-proxy.invalid:9999",
                "ALL_PROXY": "http://ambient-proxy.invalid:9999",
                "SSL_CERT_FILE": str(self.root / "ambient-ca.pem"),
            },
            clear=False,
        ):
            with self.assertRaisesRegex(
                RuntimeError, "scoped_proxy_target_pinning_unavailable"
            ):
                self._execute(self.adapter(), transport)

        transport.assert_not_called()
        self.assertFalse((self.root / "evidence").exists())

    def test_ambient_proxy_is_ignored_and_declared_proxy_is_fail_closed(self) -> None:
        target_hits: list[str] = []
        proxy_hits: list[str] = []

        class TargetHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                target_hits.append(self.path)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'{"success": true, "data": []}')

            def log_message(self, _format: str, *args: object) -> None:
                del args

        class ProxyHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                proxy_hits.append(self.path)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'{"success": true, "data": []}')

            def log_message(self, _format: str, *args: object) -> None:
                del args

        target = ThreadingHTTPServer(("127.0.0.1", 0), TargetHandler)
        proxy = ThreadingHTTPServer(("127.0.0.1", 0), ProxyHandler)
        target_thread = threading.Thread(target=target.serve_forever, daemon=True)
        proxy_thread = threading.Thread(target=proxy.serve_forever, daemon=True)
        target_thread.start()
        proxy_thread.start()
        proxy_url = f"http://127.0.0.1:{proxy.server_port}"
        try:
            self.root.joinpath(".env").write_text(
                f"CTFD_URL=http://127.0.0.1:{target.server_port}\n",
                encoding="utf-8",
            )
            direct_scope = scoped()
            direct_scope["platform_hosts"] = ["127.0.0.1"]
            direct_scope["allowed_ports"] = [target.server_port]
            with mock.patch.dict(
                os.environ,
                {"HTTP_PROXY": proxy_url, "HTTPS_PROXY": proxy_url, "ALL_PROXY": proxy_url},
                clear=False,
            ):
                direct = self.adapter()
                direct.scope = direct_scope
                direct.sync()
            self.assertEqual(target_hits, ["/api/v1/challenges"])
            self.assertEqual(proxy_hits, [])

            self.root.joinpath(".env").write_text(
                "CTFD_URL=http://fixture.invalid\n"
                "CTFD_NETWORK_ENV_KEYS=[\"HTTP_PROXY\"]\n"
                f"HTTP_PROXY={proxy_url}\n",
                encoding="utf-8",
            )
            declared_scope = scoped()
            declared_scope["allowed_hosts"] = ["fixture.invalid", "127.0.0.1"]
            declared_scope["platform_hosts"] = ["fixture.invalid", "127.0.0.1"]
            declared_scope["allowed_ports"] = [80, proxy.server_port]
            declared = self.adapter()
            declared.scope = declared_scope
            snapshot = declared.sync()
            self.assertEqual(proxy_hits, [])
            self.assertEqual(
                snapshot["capabilities"]["platform_inventory"]["detail"],
                "scoped_proxy_target_pinning_unavailable",
            )
        finally:
            target.shutdown()
            proxy.shutdown()
            target.server_close()
            proxy.server_close()
            target_thread.join(timeout=2)
            proxy_thread.join(timeout=2)

    def test_conflicting_proxy_or_invalid_ca_fails_before_transport_or_evidence(self) -> None:
        ca_target = self.root / "ca-target.pem"
        ca_link: Path | None = self.root / "ca-link.pem"
        ca_target.write_text("fixture", encoding="utf-8")
        try:
            ca_link.symlink_to(ca_target)
        except OSError:
            ca_link = None
        cases = {
            "proxy": (
                "CTFD_NETWORK_ENV_KEYS=[\"HTTP_PROXY\", \"http_proxy\"]\n"
                "HTTP_PROXY=http://one.invalid:8080\n"
                "http_proxy=http://two.invalid:8080\n"
            ),
            "ca": (
                "CTFD_NETWORK_ENV_KEYS=[\"SSL_CERT_FILE\"]\n"
                f"SSL_CERT_FILE={self.root / 'missing-ca.pem'}\n"
            ),
            "forbidden-network-class": "CTFD_NETWORK_ENV_KEYS=[\"CTFD_TOKEN\"]\n",
        }
        if ca_link is not None:
            cases["symlink-ca"] = (
                "CTFD_NETWORK_ENV_KEYS=[\"SSL_CERT_FILE\"]\n"
                f"SSL_CERT_FILE={ca_link}\n"
            )
        for name, policy in cases.items():
            with self.subTest(policy=name):
                self.root.joinpath(".env").write_text(
                    "CTFD_URL=https://fixture.invalid\n"
                    "CTFD_TOKEN=fixture-token\n"
                    + policy,
                    encoding="utf-8",
                )
                transport = mock.Mock()
                with (
                    mock.patch.dict(self.globals, {"open_scoped_url": transport}),
                    mock.patch.object(ssl, "_create_unverified_context") as insecure,
                    self.assertRaises(RuntimeError),
                ):
                    self.adapter().execute_action(
                        {"objective_id": "1", "exact_value": "FLAG{fixture}"},
                        self.root / "evidence",
                    )
                transport.assert_not_called()
                insecure.assert_not_called()
                self.assertFalse((self.root / "evidence").exists())

    def test_command_adapter_accepts_declared_proxy_and_ca_but_not_other_capabilities(
        self,
    ) -> None:
        ca_path = self.root / "declared-ca.pem"
        ca_path.write_text("fixture", encoding="utf-8")
        capture = self.root / "command-environment.json"
        self.root.joinpath(".env").write_text(
            "HTTP_PROXY=http://dotenv-proxy.invalid:8080\n"
            f"SSL_CERT_FILE={ca_path}\n",
            encoding="utf-8",
        )
        program = (
            "import json, os, pathlib, sys; "
            "pathlib.Path(sys.argv[1]).write_text(json.dumps({"
            "'proxy': os.environ.get('HTTP_PROXY') == 'http://dotenv-proxy.invalid:8080', "
            "'ca': 'SSL_CERT_FILE' in os.environ, 'provider': 'OPENAI_API_KEY' in os.environ})); "
            "print(json.dumps({'challenges': []}))"
        )
        adapter = CommandAdapter(
            self.root,
            {
                "adapter": {
                    "config": {
                        "inventory_argv": [sys.executable, "-c", program, str(capture)],
                        "inventory_env_keys": ["HTTP_PROXY", "SSL_CERT_FILE"],
                    }
                }
            },
            {},
        )
        with mock.patch.dict(
            os.environ,
            {
                "HTTP_PROXY": "http://parent-proxy.invalid:8080",
                "OPENAI_API_KEY": "provider-sentinel",
            },
            clear=False,
        ):
            snapshot = adapter.sync()
        self.assertEqual(
            json.loads(capture.read_text(encoding="utf-8")),
            {"proxy": True, "ca": True, "provider": False},
        )
        passed = snapshot["environment"]["passed"]
        self.assertEqual(
            {(entry["name"], entry["class"]) for entry in passed}
            & {("HTTP_PROXY", "proxy-credential"), ("SSL_CERT_FILE", "ca-trust-path")},
            {("HTTP_PROXY", "proxy-credential"), ("SSL_CERT_FILE", "ca-trust-path")},
        )
        self.assertNotIn("dotenv-proxy.invalid", json.dumps(snapshot))

        for name in (
            "OPENAI_API_KEY",
            "ROOKERY_OWNER_TOKEN",
            "IMMERSIVE_COOKIES_FILE",
            "VPN_AUTH_FILE",
            "SSH_AUTH_SOCK",
        ):
            with self.subTest(name=name):
                blocked = CommandAdapter(
                    self.root,
                    {
                        "adapter": {
                            "config": {
                                "inventory_argv": [sys.executable, "-c", "raise SystemExit(1)"],
                                "inventory_env_keys": [name],
                            }
                        }
                    },
                    {},
                )
                with (
                    mock.patch("rookery.portable.adapters.run_bounded_argv") as runner,
                    self.assertRaisesRegex(
                        RuntimeError,
                        "forbidden owner key" if name == "ROOKERY_OWNER_TOKEN" else "forbids class",
                    ),
                ):
                    blocked.sync()
                runner.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
