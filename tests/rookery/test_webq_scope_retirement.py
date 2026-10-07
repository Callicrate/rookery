from __future__ import annotations

import copy
import json
import os
import shlex
import subprocess
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from rookery.portable.manifest import resolve_manifest
from rookery.portable.registry import render_surface
from tests.rookery.test_preparation_and_isolation import copy_rookery


class _RedirectHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        self.server.request_count += 1  # type: ignore[attr-defined]
        self.send_response(302)
        self.send_header("Location", self.server.redirect_target)  # type: ignore[attr-defined]
        self.end_headers()

    def log_message(self, _format: str, *_args: object) -> None:
        return


@unittest.skipUnless(os.name == "posix", "requires POSIX executable fixtures")
class WebqScopeRetirementTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        copy_rookery(self.root)
        self.scope_called = self.root / "scope-called"
        self.curl_called = self.root / "curl-called"
        self.output_path = self.root / "unexpected-output"
        self.config_path = self.root / "unexpected-config"
        self.config_path.write_text("--output should-not-be-read\n", encoding="utf-8")
        self.config_before = self.config_path.read_bytes()

        scope_check = self.root / "bin" / "scope-check"
        scope_check.write_text(
            "#!/usr/bin/env bash\n"
            f"touch {shlex.quote(str(self.scope_called))}\n",
            encoding="utf-8",
        )
        scope_check.chmod(0o755)
        fake_bin = self.root / "fake-bin"
        fake_bin.mkdir()
        curl = fake_bin / "curl"
        curl.write_text(
            "#!/usr/bin/env bash\n"
            f"touch {shlex.quote(str(self.curl_called))}\n",
            encoding="utf-8",
        )
        curl.chmod(0o755)
        self.environment = {
            **os.environ,
            "PATH": str(fake_bin) + os.pathsep + os.environ.get("PATH", ""),
            "PYTHONPATH": str(self.root / "lib"),
            "PYTHONDONTWRITEBYTECODE": "1",
        }

        self.source = ThreadingHTTPServer(("127.0.0.1", 0), _RedirectHandler)
        self.sink = ThreadingHTTPServer(("127.0.0.1", 0), _RedirectHandler)
        source_url = f"http://127.0.0.1:{self.source.server_port}/redirect"
        sink_url = f"http://127.0.0.1:{self.sink.server_port}/sink"
        self.source.request_count = 0  # type: ignore[attr-defined]
        self.sink.request_count = 0  # type: ignore[attr-defined]
        self.source.redirect_target = sink_url  # type: ignore[attr-defined]
        self.sink.redirect_target = source_url  # type: ignore[attr-defined]
        self.source_thread = threading.Thread(target=self.source.serve_forever)
        self.sink_thread = threading.Thread(target=self.sink.serve_forever)
        self.source_thread.start()
        self.sink_thread.start()
        self.source_url = source_url
        self.sink_url = sink_url

    def tearDown(self) -> None:
        self.source.shutdown()
        self.sink.shutdown()
        self.source_thread.join()
        self.sink_thread.join()
        self.source.server_close()
        self.sink.server_close()
        self.temporary.cleanup()

    def run_webq(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(self.root / "bin" / "webq"), *arguments],
            cwd=self.root,
            env=self.environment,
            text=True,
            capture_output=True,
            check=False,
            timeout=20,
        )

    def assert_network_and_files_untouched(self) -> None:
        self.assertEqual(self.source.request_count, 0)  # type: ignore[attr-defined]
        self.assertEqual(self.sink.request_count, 0)  # type: ignore[attr-defined]
        self.assertFalse(self.scope_called.exists())
        self.assertFalse(self.curl_called.exists())
        self.assertFalse(self.output_path.exists())
        self.assertEqual(self.config_path.read_bytes(), self.config_before)

    def test_request_and_passthrough_forms_fail_before_scope_transport_or_files(self) -> None:
        blocked_forms = (
            (self.source_url,),
            (self.source_url, "--url", self.sink_url),
            (self.source_url, "--proxy", "http://127.0.0.1:9"),
            (self.source_url, "--resolve", "example.invalid:443:127.0.0.1"),
            (self.source_url, "--config", str(self.config_path)),
            (self.source_url, "--output", str(self.output_path)),
            (self.source_url, "--insecure", "--location"),
            ("--url", self.source_url),
        )
        for arguments in blocked_forms:
            with self.subTest(arguments=arguments):
                result = self.run_webq(*arguments)
                self.assertEqual(result.returncode, 2)
                self.assertIn("web_network_scope_unenforced", result.stderr)
                self.assert_network_and_files_untouched()

    def test_help_and_version_are_read_only(self) -> None:
        for argument in ("--help", "--version"):
            with self.subTest(argument=argument):
                result = self.run_webq(argument)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertTrue(result.stdout.strip())
                self.assert_network_and_files_untouched()

    def test_registry_and_rendered_web_surface_have_no_webq_alias(self) -> None:
        entries = json.loads(
            (self.root / "registry" / "tools.json").read_text(encoding="utf-8")
        )
        self.assertNotIn("webq", json.dumps(entries, sort_keys=True).casefold())

        result = resolve_manifest(self.root)
        manifest = copy.deepcopy(result.manifest)
        manifest.setdefault("surface", {}).setdefault("categories", []).append("web")
        inventory = render_surface(self.root, manifest)
        rendered_aliases = {
            str(value)
            for entry in inventory["tools"]
            for key in ("id", "path", "purpose")
            if (value := entry.get(key))
        }
        self.assertFalse(any("webq" in alias.casefold() for alias in rendered_aliases))
        self.assertNotIn(
            "webq",
            (self.root / "ACTIVE_SURFACE.md").read_text(encoding="utf-8").casefold(),
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
