from __future__ import annotations

import http.server
import os
import runpy
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).parents[2]
LIB = ROOT / "rookery/lib"
if str(LIB) not in sys.path:
    sys.path.insert(0, str(LIB))

class _RedirectServer(http.server.ThreadingHTTPServer):
    start_hits = 0
    target_hits = 0


class _RedirectHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/api/v1/challenges":
            type(self.server).start_hits += 1
            self.send_response(302)
            self.send_header(
                "Location", f"http://localhost:{self.server.server_port}/target"
            )
            self.end_headers()
            return
        if self.path == "/target":
            type(self.server).target_hits += 1
            self.send_response(200)
            self.end_headers()

    def log_message(self, format: str, *args: object) -> None:
        del format, args


class AdapterRedirectTests(unittest.TestCase):
    def setUp(self) -> None:
        self.server = _RedirectServer(("127.0.0.1", 0), _RedirectHandler)
        _RedirectServer.start_hits = 0
        _RedirectServer.target_hits = 0
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def test_ctfd_redirect_is_scope_checked_before_the_target_request(self) -> None:
        namespace = runpy.run_path(
            str(ROOT / "rookery/adapters/ctfd/adapter.py")
        )
        scope = {
            "acknowledged": True,
            "generation": 1,
            "expires_at": "unknown",
            "allowed_hosts": ["127.0.0.1"],
            "allowed_cidrs": ["127.0.0.0/8"],
            "allowed_ports": [self.server.server_port],
            "allowed_protocols": ["http"],
            "allowed_file_origins": [],
            "platform_hosts": ["127.0.0.1"],
            "max_attachment_bytes": 4096,
        }
        with tempfile.TemporaryDirectory() as name:
            adapter = namespace["CTFdAdapter"](
                Path(name),
                {"adapter": {"config": {"base_url": self.url}}},
                scope,
            )
            # A dead ambient proxy must not prevent the direct scoped request.
            with mock.patch.dict(
                os.environ,
                {"HTTP_PROXY": "http://127.0.0.1:1"},
                clear=False,
            ):
                snapshot = adapter.sync()

        self.assertEqual(
            snapshot["capabilities"]["platform_inventory"]["health"], "unhealthy"
        )
        self.assertEqual(_RedirectServer.start_hits, 1)
        self.assertEqual(_RedirectServer.target_hits, 0)

if __name__ == "__main__":
    unittest.main(verbosity=2)
