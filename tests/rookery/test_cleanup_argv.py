from __future__ import annotations

# ruff: noqa: E402

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tests.rookery.env_fixtures import configure_event_environment
from tests.rookery.support import (
    ROOKERY_ROOT,
    copy_non_deployed_rookery,
    install_test_launch_binding,
    open_test_event_store,
)

LIB = ROOKERY_ROOT / "lib"
if str(LIB) not in sys.path:
    sys.path.insert(0, str(LIB))
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

from rookery.portable.control import resume


class CleanupArgvTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        copy_non_deployed_rookery(self.root)
        configure_event_environment(self.root, "manual")
        install_test_launch_binding(self.root)
        resume(open_test_event_store(self.root), reason="fixture")
        self.environment = {
            **os.environ,
            "PYTHONPATH": str(self.root / "lib"),
            "PYTHONDONTWRITEBYTECODE": "1",
        }

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def command(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(self.root / "bin/cleanup"), *arguments],
            cwd=self.root,
            env=self.environment,
            text=True,
            capture_output=True,
            timeout=30,
        )

    def test_cleanup_uses_argv_and_rejects_legacy_shell_strings(self) -> None:
        marker = self.root / "injected"
        shell_shaped = f"; touch {marker}"
        argv = [
            sys.executable,
            "-c",
            "import sys; print(sys.argv[1])",
            shell_shaped,
        ]
        registered = self.command(
            "register",
            "--label",
            "fixture",
            "--argv-json",
            json.dumps(argv),
        )
        executed = self.command("run")
        legacy = self.command(
            "register",
            "--label",
            "legacy",
            "--command",
            f"touch {marker}",
        )

        self.assertEqual(registered.returncode, 0, registered.stderr)
        self.assertEqual(executed.returncode, 0, executed.stderr)
        results = json.loads(executed.stdout)
        self.assertEqual(results[0]["termination"], "exited")
        self.assertIn(shell_shaped, results[0]["stdout"])
        self.assertFalse(marker.exists())
        self.assertNotEqual(legacy.returncode, 0)
        self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
