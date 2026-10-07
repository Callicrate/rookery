from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from tests.rookery.test_preparation_and_isolation import copy_rookery


@unittest.skipUnless(os.name == "posix", "requires POSIX executable fixtures")
class PlayqSecurityRepairTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        copy_rookery(self.root)
        self.scope_called = self.root / "scope-called.txt"
        self.browser_called = self.root / "browser-called.txt"
        browser = self.root / "fake-browser"
        browser.write_text(
            "#!/usr/bin/env python3\n"
            "from pathlib import Path\n"
            "Path(" + repr(str(self.browser_called)) + ").touch()\n",
            encoding="utf-8",
        )
        browser.chmod(0o755)
        (self.root / ".env").write_text(
            f"BROWSER_EXECUTABLE={browser}\n", encoding="utf-8"
        )
        scope_check = self.root / "bin" / "scope-check"
        scope_check.write_text(
            "#!/usr/bin/env python3\n"
            "from pathlib import Path\n"
            f"Path({str(self.scope_called)!r}).touch()\n",
            encoding="utf-8",
        )
        scope_check.chmod(0o755)
        self.environment = {
            **os.environ,
            "PYTHONPATH": str(self.root / "lib"),
            "PYTHONDONTWRITEBYTECODE": "1",
        }

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_playq(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(self.root / "bin" / "playq"), "https://example.invalid/", *args],
            cwd=self.root,
            env=self.environment,
            text=True,
            capture_output=True,
            check=False,
            timeout=30,
        )

    def test_network_capture_fails_before_all_runtime_side_effects(self) -> None:
        result = self.run_playq("--label", "capture_01", "--screenshot", "--pdf")

        self.assertEqual(result.returncode, 2)
        self.assertIn("browser_network_scope_unenforced", result.stderr)
        self.assertFalse(self.scope_called.exists())
        self.assertFalse(self.browser_called.exists())
        self.assertFalse((self.root / "captures").exists())

    def test_no_flag_or_acknowledgement_can_reenable_capture(self) -> None:
        for arguments in (
            (),
            ("--network-scope", "initial_url_only"),
            ("--require-subresource-scope",),
            ("--dump-dom",),
        ):
            with self.subTest(arguments=arguments):
                result = self.run_playq(*arguments)
                self.assertEqual(result.returncode, 2)
                self.assertIn("browser_network_scope_unenforced", result.stderr)
                self.assertFalse(self.scope_called.exists())
                self.assertFalse(self.browser_called.exists())
                self.assertFalse((self.root / "captures").exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
