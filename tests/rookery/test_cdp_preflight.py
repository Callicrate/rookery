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
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

from tests.rookery.support import ROOKERY_ROOT

LIBRARY = ROOKERY_ROOT / "lib"
if str(LIBRARY) not in sys.path:
    sys.path.insert(0, str(LIBRARY))

from rookery.portable.environment import (  # noqa: E402
    CDP_RESPONSE_MAX_BYTES,
    ChildEnvironment,
    EnvironmentPolicyError,
    verify_browser_cdp_endpoint,
)
from rookery.portable.manifest import ManifestResult  # noqa: E402
from rookery.portable.preparation import _prepare_browser  # noqa: E402


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


class _ChromeVersionHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        if self.path != "/json/version":
            self.send_error(404)
            return
        document = {
            "Browser": "Chrome/140.0.0.0",
            "Protocol-Version": "1.3",
            "webSocketDebuggerUrl": (
                f"ws://127.0.0.1:{self.server.server_port}/devtools/browser/fixture"  # type: ignore[attr-defined]
            ),
        }
        body = json.dumps(document).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=UTF-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *_args: object) -> None:
        return


class CDPPreflightTests(unittest.TestCase):
    def test_valid_loopback_chrome_endpoint_ignores_ambient_proxy(self) -> None:
        with serve(_ChromeVersionHandler) as server:
            endpoint = f"http://127.0.0.1:{server.server_port}"
            with mock.patch.dict(
                os.environ,
                {"HTTP_PROXY": "http://127.0.0.1:1"},
                clear=False,
            ):
                verify_browser_cdp_endpoint(endpoint)

    def test_malformed_endpoints_are_rejected_before_connecting(self) -> None:
        invalid = (
            "",
            "https://127.0.0.1:9001",
            "http://localhost:9001",
            "http://127.0.0.1",
            "http://127.0.0.1:9001/json/version",
            "http://127.0.0.1:9001?query=1",
            "http://127.0.0.1:9001#fragment",
            "http://user@127.0.0.1:9001",
            "http://127.0.0.1:9001\nextra",
        )
        for endpoint in invalid:
            with self.subTest(endpoint=endpoint):
                with self.assertRaisesRegex(EnvironmentPolicyError, "browser_cdp_url_invalid"):
                    verify_browser_cdp_endpoint(endpoint)

    def test_unreachable_endpoint_is_actionable(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            endpoint = f"http://127.0.0.1:{listener.getsockname()[1]}"
            with self.assertRaisesRegex(EnvironmentPolicyError, "browser_cdp_unreachable"):
                verify_browser_cdp_endpoint(endpoint)

    def test_redirects_are_rejected_without_a_second_request(self) -> None:
        class RedirectHandler(BaseHTTPRequestHandler):
            requests = 0

            def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
                type(self).requests += 1
                self.send_response(302)
                self.send_header("Location", "/other")
                self.end_headers()

            def log_message(self, _format: str, *_args: object) -> None:
                return

        with serve(RedirectHandler) as server:
            with self.assertRaisesRegex(EnvironmentPolicyError, "browser_cdp_redirected"):
                verify_browser_cdp_endpoint(f"http://127.0.0.1:{server.server_port}")
        self.assertEqual(RedirectHandler.requests, 1)

    def test_oversized_version_response_is_rejected(self) -> None:
        class OversizedHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
                body = b"x" * (CDP_RESPONSE_MAX_BYTES + 1)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, _format: str, *_args: object) -> None:
                return

        with serve(OversizedHandler) as server:
            with self.assertRaisesRegex(
                EnvironmentPolicyError, "browser_cdp_response_too_large"
            ):
                verify_browser_cdp_endpoint(f"http://127.0.0.1:{server.server_port}")

    def test_wrong_websocket_origin_is_rejected(self) -> None:
        class WrongWebsocketHandler(_ChromeVersionHandler):
            def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
                document = {
                    "Browser": "Chrome/140.0.0.0",
                    "Protocol-Version": "1.3",
                    "webSocketDebuggerUrl": "ws://127.0.0.1:1/devtools/browser/fixture",
                }
                body = json.dumps(document).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        with serve(WrongWebsocketHandler) as server:
            with self.assertRaisesRegex(EnvironmentPolicyError, "browser_cdp_invalid_response"):
                verify_browser_cdp_endpoint(f"http://127.0.0.1:{server.server_port}")

    def test_preparation_reports_cdp_readiness_without_browser_executable(self) -> None:
        with serve(_ChromeVersionHandler) as server:
            report = _prepare_browser(
                Path(tempfile.gettempdir()),
                {
                    "BROWSER_MODE": "cdp",
                    "BROWSER_CDP_URL": f"http://127.0.0.1:{server.server_port}",
                },
                local=ChildEnvironment({}, "fixture", ()),
            )
        self.assertEqual(report["mode"], "cdp")
        self.assertTrue(report["available"])
        self.assertEqual(report["health"], "healthy")
        self.assertEqual(report["path"], "")

    def test_cdp_failure_prevents_the_first_state_write(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.joinpath(".env").write_text(
                "BROWSER_MODE=cdp\n"
                "BROWSER_CDP_URL=http://127.0.0.1:1\n"
                "ROOKERY_MEASUREMENT_BASELINE_PATH=baseline.json\n",
                encoding="utf-8",
            )
            result = ManifestResult(
                {
                    "adapter": {"id": "manual", "config": {}},
                    "capabilities": {"required": []},
                    "surface": {"extensions": []},
                },
                (),
                (),
                (),
            )
            with (
                mock.patch("rookery.portable.manifest.resolve_manifest", return_value=result),
                self.assertRaisesRegex(EnvironmentPolicyError, "browser_cdp_unreachable"),
            ):
                from rookery.portable.environment import resolve_launch_gate

                resolve_launch_gate(root, parent=minimal_parent())
            self.assertFalse((root / "state").exists())

    def test_browser_backed_adapter_requires_cdp_when_browser_mode_is_disabled(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.joinpath(".env").write_text(
                "BROWSER_MODE=disabled\n"
                "BROWSER_CDP_URL=\n",
                encoding="utf-8",
            )
            result = ManifestResult(
                {
                    "adapter": {"id": "ctfd_browser", "config": {}},
                    "capabilities": {"required": []},
                    "surface": {"extensions": []},
                },
                (),
                (),
                (),
            )
            with (
                mock.patch("rookery.portable.manifest.resolve_manifest", return_value=result),
                mock.patch("rookery.portable.environment.verify_browser_cdp_endpoint") as verify,
                self.assertRaisesRegex(EnvironmentPolicyError, "measurement_baseline_path_missing"),
            ):
                from rookery.portable.environment import resolve_launch_gate

                resolve_launch_gate(root, parent=minimal_parent())
            verify.assert_called_once_with(None)


if __name__ == "__main__":
    unittest.main(verbosity=2)
