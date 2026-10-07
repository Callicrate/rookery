from __future__ import annotations

import os
import subprocess
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from rookery.portable.registry import render_surface
from tests.rookery.test_preparation_and_isolation import copy_rookery


class _BrowserNetworkHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        self.server.request_count += 1  # type: ignore[attr-defined]
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", self.server.sink_url + "/redirect-target")  # type: ignore[attr-defined]
            self.end_headers()
            return
        if self.path == "/subresource":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(
                ("<img src=\"" + self.server.sink_url + "/subresource-target\">").encode()  # type: ignore[attr-defined]
            )
            return
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"fixture")

    def log_message(self, _format: str, *_args: object) -> None:
        return


@unittest.skipUnless(os.name == "posix", "requires POSIX executable fixtures")
class BrowserSafetyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        copy_rookery(self.root)
        self.scope_called = self.root / "scope-called.txt"
        self.browser_called = self.root / "browser-called.txt"
        self.environment = {
            **os.environ,
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONPATH": str(self.root / "lib"),
        }

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_playq(self, url: str, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(self.root / "bin" / "playq"), url, *args],
            cwd=self.root,
            env=self.environment,
            text=True,
            capture_output=True,
            check=False,
            timeout=30,
        )

    def test_redirect_and_subresource_sinks_are_unreached_before_browser_launch(self) -> None:
        source = ThreadingHTTPServer(("127.0.0.1", 0), _BrowserNetworkHandler)
        sink = ThreadingHTTPServer(("127.0.0.1", 0), _BrowserNetworkHandler)
        source.request_count = 0  # type: ignore[attr-defined]
        sink.request_count = 0  # type: ignore[attr-defined]
        source.sink_url = f"http://127.0.0.1:{sink.server_port}"  # type: ignore[attr-defined]
        source_thread = threading.Thread(target=source.serve_forever, daemon=True)
        sink_thread = threading.Thread(target=sink.serve_forever, daemon=True)
        source_thread.start()
        sink_thread.start()
        try:
            source_url = f"http://127.0.0.1:{source.server_port}/redirect"
            browser = self.root / "fake-browser"
            browser.write_text(
                "#!/usr/bin/env python3\n"
                "from pathlib import Path\n"
                "from urllib.request import urlopen\n"
                "import os, re, sys\n"
                "urlopen(sys.argv[-1], timeout=3).read()\n"
                "markup = urlopen(os.environ['BROWSER_TEST_SOURCE'] + '/subresource', timeout=3).read().decode()\n"
                "urlopen(re.search(r'(?<=src=\\\")[^\\\"]+', markup).group(), timeout=3).read()\n"
                "Path(os.environ['BROWSER_TEST_MARKER']).touch()\n",
                encoding="utf-8",
            )
            browser.chmod(0o755)
            (self.root / ".env").write_text(
                "BROWSER_EXECUTABLE=" + str(browser) + "\n"
                "BROWSER_ENV_KEYS=[\"BROWSER_TEST_SOURCE\",\"BROWSER_TEST_MARKER\"]\n"
                "BROWSER_TEST_SOURCE=" + source_url.rsplit("/", 1)[0] + "\n"
                "BROWSER_TEST_MARKER=" + str(self.browser_called) + "\n",
                encoding="utf-8",
            )
            scope_check = self.root / "bin" / "scope-check"
            scope_check.write_text(
                "#!/usr/bin/env python3\n"
                "from pathlib import Path\n"
                f"Path({str(self.scope_called)!r}).touch()\n",
                encoding="utf-8",
            )
            scope_check.chmod(0o755)

            result = self.run_playq(source_url)

            self.assertEqual(result.returncode, 2)
            self.assertIn("browser_network_scope_unenforced", result.stderr)
            self.assertEqual(source.request_count, 0)  # type: ignore[attr-defined]
            self.assertEqual(sink.request_count, 0)  # type: ignore[attr-defined]
            self.assertFalse(self.browser_called.exists())
            self.assertFalse(self.scope_called.exists())
            self.assertFalse((self.root / "captures").exists())
        finally:
            source.shutdown()
            sink.shutdown()
            source.server_close()
            sink.server_close()
            source_thread.join(timeout=5)
            sink_thread.join(timeout=5)

    def test_disabled_browser_entries_are_absent_from_selected_surface(self) -> None:
        inventory = render_surface(
            self.root,
            {
                "profile": "browser-fixture",
                "adapter": {"id": "manual"},
                "capabilities": {"required": ["browser"]},
                "surface": {"categories": ["research", "web"]},
            },
        )

        tool_ids = {entry["id"] for entry in inventory["tools"]}
        agent_ids = {entry["id"] for entry in inventory["agents"]}
        self.assertNotIn("playq", tool_ids)
        self.assertNotIn("ctf_browser_operator", agent_ids)
        surface = (self.root / "ACTIVE_SURFACE.md").read_text(encoding="utf-8")
        self.assertNotIn("playq", surface)
        self.assertNotIn("ctf_browser_operator", surface)

    def test_help_and_version_remain_read_only(self) -> None:
        for argument in ("--help", "--version"):
            with self.subTest(argument=argument):
                result = subprocess.run(
                    [str(self.root / "bin" / "playq"), argument],
                    cwd=self.root,
                    env=self.environment,
                    text=True,
                    capture_output=True,
                    check=False,
                    timeout=30,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertFalse((self.root / "captures").exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
