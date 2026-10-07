from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from tests.rookery.test_preparation_and_isolation import copy_rookery


@unittest.skipUnless(os.name == "posix", "requires POSIX executable fixtures")
class PlayqEnvironmentPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        copy_rookery(self.root)
        self.scope_record = self.root / "scope-environment.json"
        self.browser_record = self.root / "browser-environment.json"
        self.parent_environment = {
            **os.environ,
            "PYTHONPATH": str(self.root / "lib"),
            "PYTHONDONTWRITEBYTECODE": "1",
            "OPENAI_API_KEY": "provider-secret-must-not-reach-browser",
            "CTFD_TOKEN": "adapter-secret-must-not-reach-browser",
            "SSH_AUTH_SOCK": "/tmp/agent-capability-must-not-reach-browser",
            "ROOKERY_OWNER_TOKEN": "owner-secret-must-not-reach-browser",
        }

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_disabled_capture_never_loads_browser_or_scope_environment(self) -> None:
        browser = self.root / "fake-browser"
        browser.write_text(
            "#!/usr/bin/env python3\n"
            "from pathlib import Path\n"
            f"Path({str(self.browser_record)!r}).touch()\n",
            encoding="utf-8",
        )
        browser.chmod(0o755)
        (self.root / ".env").write_text(
            "BROWSER_EXECUTABLE=" + str(browser) + "\n"
            "BROWSER_ENV_KEYS=[\"OPENAI_API_KEY\"]\n",
            encoding="utf-8",
        )
        scope_check = self.root / "bin" / "scope-check"
        scope_check.write_text(
            "#!/usr/bin/env python3\n"
            "from pathlib import Path\n"
            f"Path({str(self.scope_record)!r}).touch()\n",
            encoding="utf-8",
        )
        scope_check.chmod(0o755)

        result = subprocess.run(
            [str(self.root / "bin" / "playq"), "https://example.invalid/"],
            cwd=self.root,
            env=self.parent_environment,
            text=True,
            capture_output=True,
            check=False,
            timeout=30,
        )

        self.assertEqual(result.returncode, 2)
        self.assertIn("browser_network_scope_unenforced", result.stderr)
        self.assertFalse(self.scope_record.exists())
        self.assertFalse(self.browser_record.exists())
        self.assertFalse((self.root / "captures").exists())

    def test_disabled_capture_wins_over_invalid_browser_configuration(self) -> None:
        (self.root / ".env").write_text(
            "BROWSER_EXECUTABLE=relative-browser\n"
            "BROWSER_ENV_KEYS=[not-json\n",
            encoding="utf-8",
        )

        result = subprocess.run(
            [str(self.root / "bin" / "playq"), "https://example.invalid/"],
            cwd=self.root,
            env=self.parent_environment,
            text=True,
            capture_output=True,
            check=False,
            timeout=30,
        )

        self.assertEqual(result.returncode, 2)
        self.assertIn("browser_network_scope_unenforced", result.stderr)
        self.assertFalse((self.root / "captures").exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
