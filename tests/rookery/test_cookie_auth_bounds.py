from __future__ import annotations

import ast
import json
import os
import runpy
import stat
import subprocess
import tempfile
import time
import tracemalloc
import unittest
from pathlib import Path

from tests.rookery.test_preparation_and_isolation import copy_rookery


@unittest.skipUnless(os.name == "posix", "requires POSIX filesystem modes")
class CookieAndAuthBoundTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        copy_rookery(self.root)
        self.environment = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
        self.cookie_filter = self.root / "bin" / "cookie-filter"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_cookie(self, source: Path, output: Path, *limits: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                str(self.cookie_filter),
                "--file",
                str(source),
                "--domains",
                "fixture.invalid",
                "--outdir",
                str(output),
                "--json",
                *limits,
            ],
            cwd=self.root,
            env=self.environment,
            text=True,
            capture_output=True,
            timeout=30,
        )

    def json_source(self, name: str, value: str = "fixture") -> Path:
        source = self.root / f"{name}.json"
        source.write_text(
            json.dumps(
                [
                    {
                        "name": "session",
                        "value": value,
                        "domain": "fixture.invalid",
                        "expires": 4_102_444_800,
                    }
                ]
            ),
            encoding="utf-8",
        )
        return source

    def cookie_out(self, name: str) -> Path:
        return self.root / "platform" / "cookies" / name

    def write_50k_netscape_source(self) -> Path:
        source = self.root / "cookies.txt"
        count = 50_000
        target_bytes = 1_939_866
        base_lengths = [
            len(f"x\tFALSE\t/\tFALSE\t0\t{index:05d}\tv\n")
            for index in range(count)
        ]
        remaining = target_bytes - sum(base_lengths)
        self.assertGreaterEqual(remaining, 0)
        with source.open("w", encoding="utf-8", newline="\n") as handle:
            for index in range(count):
                lines_left = count - index
                extra = remaining // lines_left
                value = "v" * (extra + 1)
                handle.write(
                    f"x\tFALSE\t/\tFALSE\t0\t{index:05d}\t{value}\n"
                )
                remaining -= extra
        self.assertEqual(source.stat().st_size, target_bytes)
        return source

    def assert_refused_without_value(
        self,
        result: subprocess.CompletedProcess[str],
        value: str,
        output: Path,
        reason: str,
    ) -> None:
        self.assertEqual(result.returncode, 2)
        self.assertNotIn(value, result.stdout)
        self.assertNotIn(value, result.stderr)
        summary = json.loads((output / "summary.json").read_text(encoding="utf-8"))
        self.assertEqual(summary["status"], "refused")
        self.assertEqual(summary["reason"], reason)
        self.assertFalse((output / "cookie-header.txt").exists())
        self.assertFalse((output / "selected-cookies.json").exists())

    def test_streams_185mib_50k_netscape_source_with_bounded_output_and_memory(self) -> None:
        source = self.write_50k_netscape_source()
        output = self.cookie_out("out")
        result = subprocess.run(
            [
                str(self.cookie_filter),
                "--file",
                str(source),
                "--domains",
                "unmatched.invalid",
                "--outdir",
                str(output),
                "--json",
            ],
            cwd=self.root,
            env=self.environment,
            text=True,
            capture_output=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0)
        self.assertLessEqual(len(result.stdout.encode("utf-8")), 16 * 1024)
        summary = json.loads(result.stdout)
        self.assertEqual(summary["format"], "netscape")
        self.assertEqual(summary["total_count"], 50_000)
        self.assertEqual(summary["selected_count"], 0)
        self.assertLessEqual((output / "selected-cookies.json").stat().st_size, 16)
        self.assertLessEqual((output / "cookie-header.txt").stat().st_size, 16)

        module = runpy.run_path(str(self.cookie_filter), run_name="cookie_filter_bounds")
        limits = {
            "source_bytes": 2 * 1024 * 1024,
            "cookie_count": 50_000,
            "field_bytes": 4 * 1024,
            "line_bytes": 8 * 1024,
            "selected_json_bytes": 16 * 1024 * 1024,
            "header_bytes": 1024 * 1024,
        }
        tracemalloc.start()
        try:
            cookies = module["parse_netscape"](source, limits)
            _current, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        self.assertEqual(len(cookies), 50_000)
        self.assertLess(peak, 96 * 1024 * 1024)

    def test_cookie_limits_refuse_without_leaking_values(self) -> None:
        cases = [
            (
                self.json_source("field", "json-limit-value" * 64),
                ["--max-field-bytes", "64"],
                "field_too_large",
                "json-limit-value",
            ),
            (
                self.json_source("source", "source-limit-value" * 512),
                ["--max-source-bytes", "128"],
                "source_too_large",
                "source-limit-value",
            ),
            (
                self.json_source("header", "header-limit-value" * 8),
                ["--max-header-bytes", "32"],
                "header_too_large",
                "header-limit-value",
            ),
            (
                self.json_source("selected", "selected-limit-value" * 8),
                ["--max-selected-json-bytes", "32"],
                "selected_json_too_large",
                "selected-limit-value",
            ),
        ]
        for index, (source, limits, reason, marker) in enumerate(cases):
            output = self.cookie_out(f"case-{index}")
            result = self.run_cookie(source, output, *limits)
            self.assert_refused_without_value(result, marker, output, reason)

        marker = "count-limit-value"
        source = self.root / "count.json"
        source.write_text(
            json.dumps(
                [
                    {"name": "one", "value": marker, "domain": "fixture.invalid"},
                    {"name": "two", "value": marker, "domain": "fixture.invalid"},
                ]
            ),
            encoding="utf-8",
        )
        output = self.cookie_out("count-case")
        result = self.run_cookie(source, output, "--max-cookies", "1")
        self.assert_refused_without_value(result, marker, output, "too_many_cookies")

        source = self.root / "line.txt"
        marker = "line-limit-value"
        source.write_text(
            f"fixture.invalid\tFALSE\t/\tFALSE\t0\tsession\t{marker * 32}\n",
            encoding="utf-8",
        )
        output = self.cookie_out("line-case")
        result = self.run_cookie(source, output, "--max-line-bytes", "64")
        self.assert_refused_without_value(result, marker, output, "line_too_large")

        source = self.json_source("hard-limit")
        output = self.cookie_out("hard-limit-case")
        result = self.run_cookie(source, output, "--max-cookies", "100001")
        self.assertEqual(result.returncode, 2)
        self.assertIn("invalid_limit", result.stderr)
        self.assertFalse(output.exists())

    def test_cookie_source_rejects_symlinks_without_disclosing_content(self) -> None:
        marker = "source-link-value"
        target = self.json_source("source-target", marker)
        source = self.root / "source-link.json"
        source.symlink_to(target)
        output = self.cookie_out("source-link-out")
        result = self.run_cookie(source, output)
        self.assert_refused_without_value(result, marker, output, "invalid_source")

    def test_cookie_filter_uses_only_declared_environment_with_dotenv_precedence(self) -> None:
        source = self.json_source("dotenv-cookie-source", "cookie-content-sentinel")
        self.root.joinpath(".env").write_text(
            "\n".join(
                [
                    f"COOKIES_FILE={source}",
                    "COOKIE_FILTER_DOMAINS=fixture.invalid",
                    "COOKIE_FILTER_URLS=https://dotenv-url.invalid/path",
                    "AUTH_EXPIRY_SAFETY_MINUTES=7",
                    "COOKIE_FILTER_MAX_COOKIES=1",
                    "DUMMY_DOTENV_UNRELATED=dotenv-unrelated-sentinel",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        environment = {
            **self.environment,
            "COOKIES_FILE": str(self.root / "parent-cookies.json"),
            "COOKIE_FILTER_DOMAINS": "parent.invalid",
            "COOKIE_FILTER_URLS": "https://parent-url.invalid/path",
            "AUTH_EXPIRY_SAFETY_MINUTES": "999",
            "COOKIE_FILTER_MAX_COOKIES": "99",
            "OPENAI_API_KEY": "provider-sentinel",
            "CTFD_TOKEN": "adapter-sentinel",
            "HTTP_PROXY": "http://proxy-sentinel.invalid:8080",
            "SSH_AUTH_SOCK": "/tmp/ssh-sentinel.sock",
            "ROOKERY_OWNER_TOKEN": "owner-sentinel",
        }
        output = self.cookie_out("declared-environment-output")
        result = subprocess.run(
            [str(self.cookie_filter), "--outdir", str(output), "--json"],
            cwd=self.root,
            env=environment,
            text=True,
            capture_output=True,
            timeout=30,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        summary = json.loads(result.stdout)
        self.assertTrue(summary["cookie_source_configured"])
        self.assertNotIn(str(source), json.dumps(summary))
        self.assertEqual(summary["domains"], ["fixture.invalid", "dotenv-url.invalid"])
        self.assertEqual(summary["min_valid_minutes"], 7.0)
        self.assertEqual(summary["limits"]["cookie_count"], 1)
        self.assertEqual(summary["selected_count"], 1)
        rendered = result.stdout + result.stderr + (output / "summary.json").read_text(
            encoding="utf-8"
        )
        for sentinel in (
            "dotenv-unrelated-sentinel",
            "provider-sentinel",
            "adapter-sentinel",
            "proxy-sentinel.invalid",
            "ssh-sentinel.sock",
            "owner-sentinel",
        ):
            self.assertNotIn(sentinel, rendered)

        source_text = self.cookie_filter.read_text(encoding="utf-8")
        tree = ast.parse(source_text)
        self.assertFalse(
            any(
                isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                and node.name == "read_env"
                for node in ast.walk(tree)
            )
        )
        self.assertIn("read_declared_environment", source_text)
        self.assertNotIn("dict(os.environ)", source_text)

    def test_cookie_filter_rejects_invalid_dotenv_before_output_effects(self) -> None:
        marker = self.root / "dotenv-side-effect"
        self.root.joinpath(".env").write_text(
            f"$(touch {marker})\n", encoding="utf-8"
        )
        output = self.cookie_out("invalid-environment-output")
        result = subprocess.run(
            [str(self.cookie_filter), "--outdir", str(output)],
            cwd=self.root,
            env=self.environment,
            text=True,
            capture_output=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("cookie_filter_refused: invalid_environment", result.stderr)
        self.assertFalse(marker.exists())
        self.assertFalse(output.exists())

    def test_auth_handoff_bounds_2mb_diagnostic(self) -> None:
        marker = "auth-diagnostic-marker"

        def helper(name: str, source: str) -> None:
            path = self.root / "bin" / name
            path.write_text(source, encoding="utf-8")
            path.chmod(0o755)

        helper("platform-heavy-pause", "#!/usr/bin/env python3\n")
        helper(
            "reviewer-queue",
            "#!/usr/bin/env python3\n"
            "import os\n"
            f"os.write(1, b'x' * (2 * 1024 * 1024) + b'{marker}')\n",
        )
        helper("score-review", "#!/usr/bin/env python3\n")
        helper("frontier", "#!/usr/bin/env python3\n")
        result = subprocess.run(
            [
                str(self.root / "bin" / "auth-expired-stop"),
                "--max-command-output-bytes",
                "2048",
            ],
            cwd=self.root,
            env=self.environment,
            text=True,
            capture_output=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 3)
        self.assertNotIn(marker, result.stdout)
        self.assertNotIn(marker, result.stderr)
        handoff = next((self.root / "handoffs").glob("*.md"))
        content = handoff.read_text(encoding="utf-8")
        self.assertIn("termination: output_limit", content)
        self.assertIn("output_truncated: true", content)
        self.assertIn("captured_output_bytes: 2048", content)
        self.assertNotIn(marker, content)
        self.assertLess(handoff.stat().st_size, 32 * 1024)
        self.assertEqual(stat.S_IMODE(handoff.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(handoff.parent.stat().st_mode), 0o700)

    def test_auth_handoff_records_bounded_command_timeout(self) -> None:
        def helper(name: str, source: str) -> None:
            path = self.root / "bin" / name
            path.write_text(source, encoding="utf-8")
            path.chmod(0o755)

        helper("platform-heavy-pause", "#!/usr/bin/env python3\n")
        helper("reviewer-queue", "#!/usr/bin/env python3\n")
        helper("score-review", "#!/usr/bin/env python3\nimport time\ntime.sleep(10)\n")
        helper("frontier", "#!/usr/bin/env python3\n")
        started = time.monotonic()
        result = subprocess.run(
            [
                str(self.root / "bin" / "auth-expired-stop"),
                "--command-timeout-seconds",
                "1",
            ],
            cwd=self.root,
            env=self.environment,
            text=True,
            capture_output=True,
            timeout=10,
        )
        elapsed = time.monotonic() - started
        self.assertEqual(result.returncode, 3)
        self.assertLess(elapsed, 5)
        handoff = next((self.root / "handoffs").glob("*.md"))
        content = handoff.read_text(encoding="utf-8")
        self.assertIn("termination: timeout", content)
        self.assertIn("output_truncated: false", content)


if __name__ == "__main__":
    unittest.main(verbosity=2)
