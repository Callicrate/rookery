from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tests.rookery.test_preparation_and_isolation import copy_rookery


class CredentialHealthBoundTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        copy_rookery(self.root)
        self.helper = self.root / "bin/credential-health"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_health_command_is_argv_and_output_bounded(self) -> None:
        marker = self.root / "injected"
        shell_shaped = (
            f'{sys.executable} -c "print(\"ok\")" ; touch {marker}'
        )
        no_shell = subprocess.run(
            [str(self.helper), "--json", "--command", shell_shaped],
            cwd=self.root,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
            text=True,
            capture_output=True,
            timeout=30,
        )
        argv = [
            sys.executable,
            "-c",
            "import os; os.write(1, b'x' * 1025)",
        ]
        bounded = subprocess.run(
            [
                str(self.helper),
                "--json",
                "--argv-json",
                json.dumps(argv),
                "--max-output-bytes",
                "1024",
            ],
            cwd=self.root,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
            text=True,
            capture_output=True,
            timeout=30,
        )

        self.assertEqual(no_shell.returncode, 0, no_shell.stderr)
        self.assertFalse(marker.exists())
        no_shell_report = json.loads(no_shell.stdout)
        self.assertIn(";", no_shell_report["health_command"]["command_argv"])
        self.assertEqual(bounded.returncode, 0, bounded.stderr)
        bounded_report = json.loads(bounded.stdout)
        self.assertEqual(
            bounded_report["health_command"]["termination"],
            "output_limit",
        )
        self.assertFalse(bounded_report["health_command"]["ok"])
        self.assertIn("health_command_failed", bounded_report["reasons"])
        self.assertLessEqual(
            len(bounded_report["health_command"]["stdout"].encode()),
            1024,
        )
        self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
