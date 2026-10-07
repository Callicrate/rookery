from __future__ import annotations

import contextlib
import json
import os
import socket
import sys
import tempfile
import threading
import unittest
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

from tests.rookery.support import ROOKERY_ROOT

LIBRARY = ROOKERY_ROOT / "lib"
if str(LIBRARY) not in sys.path:
    sys.path.insert(0, str(LIBRARY))

from rookery.portable.environment import (  # noqa: E402
    BROWSER_GATEWAY_STATUS_MAX_BYTES,
    EnvironmentPolicyError,
    ResolvedEnvironment,
    verify_required_browser_gateway,
    verify_browser_gateway_endpoint,
)
from rookery.portable.browser_gateway_policy import (  # noqa: E402
    browser_gateway_origin,
    compile_browser_gateway_policy,
    policy_sha256,
)
from rookery.portable.manifest import ManifestResult  # noqa: E402
from rookery.portable.preparation import _prepare_browser_gateway  # noqa: E402


def minimal_parent() -> dict[str, str]:
    if os.name == "nt":
        return {
            "Path": os.environ.get("Path", os.defpath),
            "SystemRoot": os.environ.get("SystemRoot", r"C:\\Windows"),
            "ComSpec": os.environ.get("ComSpec", r"C:\\Windows\\System32\\cmd.exe"),
            "PATHEXT": os.environ.get("PATHEXT", ".COM;.EXE;.BAT;.CMD"),
            "TEMP": os.environ.get("TEMP", tempfile.gettempdir()),
            "TMP": os.environ.get("TMP", tempfile.gettempdir()),
        }
    return {"PATH": os.defpath}


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


class _GatewayStatusHandler(BaseHTTPRequestHandler):
    policy_digest = "a" * 64
    boot_nonce = "b" * 64
    expires_at = (datetime.now(UTC) + timedelta(minutes=5)).isoformat()

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        if self.path != "/status":
            self.send_error(404)
            return
        document = {
            "schema_version": "1",
            "boot_nonce": type(self).boot_nonce,
            "policy_sha256": type(self).policy_digest,
            "expires_at": type(self).expires_at,
            "listeners": {
                "proxy": "127.0.0.1:9002",
                "status": f"127.0.0.1:{self.server.server_port}",  # type: ignore[attr-defined]
            },
            "counters": {
                "accepted": 0,
                "refused": 0,
                "connected": 0,
                "completed": 0,
                "failed": 0,
                "bytes": 0,
            },
        }
        body = json.dumps(document).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=UTF-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *_args: object) -> None:
        return


class BrowserGatewayPreflightTests(unittest.TestCase):
    def setUp(self) -> None:
        _GatewayStatusHandler.policy_digest = "a" * 64
        _GatewayStatusHandler.boot_nonce = "b" * 64
        _GatewayStatusHandler.expires_at = (
            datetime.now(UTC) + timedelta(minutes=5)
        ).isoformat()

    def test_valid_status_binds_policy_expiry_and_nonce(self) -> None:
        with serve(_GatewayStatusHandler) as server:
            readiness = verify_browser_gateway_endpoint(
                f"http://127.0.0.1:{server.server_port}",
                expected_policy_sha256="a" * 64,
                expected_expires_at=_GatewayStatusHandler.expires_at,
                expected_boot_nonce="b" * 64,
            )
        self.assertEqual(readiness.policy_sha256, "a" * 64)
        self.assertEqual(readiness.boot_nonce, "b" * 64)
        self.assertEqual(readiness.proxy_port, 9002)
        self.assertEqual(readiness.status_port, server.server_port)

    def test_policy_mismatch_and_gateway_restart_are_refused(self) -> None:
        with serve(_GatewayStatusHandler) as server:
            endpoint = f"http://127.0.0.1:{server.server_port}"
            with self.assertRaisesRegex(EnvironmentPolicyError, "browser_gateway_policy_mismatch"):
                verify_browser_gateway_endpoint(
                    endpoint,
                    expected_policy_sha256="c" * 64,
                    expected_expires_at=_GatewayStatusHandler.expires_at,
                )
            with self.assertRaisesRegex(EnvironmentPolicyError, "browser_gateway_restarted"):
                verify_browser_gateway_endpoint(
                    endpoint,
                    expected_policy_sha256="a" * 64,
                    expected_expires_at=_GatewayStatusHandler.expires_at,
                    expected_boot_nonce="c" * 64,
                )

    def test_unreachable_redirect_and_oversized_status_are_rejected(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            with self.assertRaisesRegex(EnvironmentPolicyError, "browser_gateway_unreachable"):
                verify_browser_gateway_endpoint(
                    f"http://127.0.0.1:{listener.getsockname()[1]}"
                )

        class RedirectHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
                self.send_response(302)
                self.send_header("Location", "/status")
                self.end_headers()

            def log_message(self, _format: str, *_args: object) -> None:
                return

        with serve(RedirectHandler) as server:
            with self.assertRaisesRegex(EnvironmentPolicyError, "browser_gateway_redirected"):
                verify_browser_gateway_endpoint(f"http://127.0.0.1:{server.server_port}")

        class OversizedHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
                body = b"x" * (BROWSER_GATEWAY_STATUS_MAX_BYTES + 1)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, _format: str, *_args: object) -> None:
                return

        with serve(OversizedHandler) as server:
            with self.assertRaisesRegex(
                EnvironmentPolicyError, "browser_gateway_response_too_large"
            ):
                verify_browser_gateway_endpoint(f"http://127.0.0.1:{server.server_port}")

    def test_preparation_reports_a_configured_gateway_status(self) -> None:
        with serve(_GatewayStatusHandler) as server:
            report = _prepare_browser_gateway(
                {"BROWSER_GATEWAY_URL": f"http://127.0.0.1:{server.server_port}"},
                required=True,
            )
        self.assertTrue(report["available"])
        self.assertEqual(report["health"], "healthy")

    def test_preparation_ignores_gateway_configuration_for_other_adapters(self) -> None:
        with mock.patch("rookery.portable.preparation.verify_browser_gateway_endpoint") as verify:
            report = _prepare_browser_gateway(
                {"BROWSER_GATEWAY_URL": "http://127.0.0.1:9003"},
                required=False,
            )
        verify.assert_not_called()
        self.assertEqual(report["mode"], "not-selected")
        self.assertEqual(report["health"], "not-applicable")

    def test_gate_uses_the_shared_semantic_policy_for_support_origins(self) -> None:
        expires_at = (datetime.now(UTC) + timedelta(minutes=5)).isoformat()
        manifest = {
            "identity": {"id": "gateway-fixture"},
            "adapter": {
                "id": "ctfd_browser_gateway",
                "config": {
                    "base_url": "https://ctfd.fixture",
                    "browser_support_origins": ["https://support.fixture"],
                },
            },
            "scope": {
                "acknowledged": True,
                "allowed_hosts": ["ctfd.fixture", "support.fixture"],
                "allowed_cidrs": [],
                "allowed_ports": [443],
                "allowed_protocols": ["https"],
                "allowed_file_origins": [],
                "platform_hosts": ["ctfd.fixture", "support.fixture"],
                "max_attachment_bytes": 0,
                "expires_at": expires_at,
            },
        }
        origin = browser_gateway_origin(manifest)
        policy = compile_browser_gateway_policy(
            manifest,
            baseline_configuration_digest="a" * 64,
            origin=origin,
        )
        self.assertEqual(
            policy["origins"], ["https://ctfd.fixture", "https://support.fixture"]
        )
        _GatewayStatusHandler.policy_digest = policy_sha256(policy)
        _GatewayStatusHandler.expires_at = expires_at
        with tempfile.TemporaryDirectory() as temporary, serve(_GatewayStatusHandler) as server:
            readiness = verify_required_browser_gateway(
                Path(temporary),
                ResolvedEnvironment(
                    {"BROWSER_GATEWAY_URL": f"http://127.0.0.1:{server.server_port}"},
                    (),
                ),
                manifest,
                baseline_configuration_digest="a" * 64,
                parent=minimal_parent(),
            )
        self.assertIsNotNone(readiness)
        assert readiness is not None
        self.assertEqual(readiness.policy_sha256, policy_sha256(policy))

    def test_gateway_policy_failure_blocks_before_the_first_state_write(self) -> None:
        with (
            tempfile.TemporaryDirectory() as temporary,
            tempfile.TemporaryDirectory() as baseline_directory,
        ):
            root = Path(temporary)
            baseline_path = Path(baseline_directory) / "baseline.json"
            root.joinpath(".env").write_text(
                "BROWSER_MODE=cdp\n"
                "BROWSER_CDP_URL=http://127.0.0.1:9001\n"
                "BROWSER_GATEWAY_URL=http://127.0.0.1:9003\n"
                f"ROOKERY_MEASUREMENT_BASELINE_PATH={baseline_path}\n",
                encoding="utf-8",
            )
            result = ManifestResult(
                {
                    "adapter": {"id": "ctfd_browser_gateway", "config": {}},
                    "capabilities": {"required": []},
                    "surface": {"extensions": []},
                },
                (),
                (),
                (),
            )
            baseline = {
                "sha256": "a" * 64,
                "configuration_digest": "b" * 64,
                "release_version": "2026.09.28",
                "measurement_contract": {
                    "queue_automation_enabled": False,
                    "provider_fields": {
                        "queue": {"availability": "unavailable"},
                        "tokens": {"availability": "unavailable"},
                        "usage": {"availability": "unavailable"},
                    },
                },
            }
            with (
                mock.patch("rookery.portable.manifest.resolve_manifest", return_value=result),
                mock.patch(
                    "rookery.portable.baseline.verify_measurement_baseline",
                    return_value=baseline,
                ) as verify_baseline,
                mock.patch("rookery.portable.environment._selected_adapter_contract"),
                mock.patch("rookery.portable.environment.verify_browser_cdp_endpoint"),
                mock.patch(
                    "rookery.portable.environment.verify_required_browser_gateway",
                    side_effect=EnvironmentPolicyError("browser_gateway_policy_mismatch"),
                ) as verify_gateway,
                self.assertRaisesRegex(EnvironmentPolicyError, "browser_gateway_policy_mismatch"),
            ):
                from rookery.portable.environment import resolve_launch_gate

                resolve_launch_gate(root, parent=minimal_parent())
            verify_baseline.assert_called_once()
            verify_gateway.assert_called_once()
            self.assertFalse((root / "state").exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
