from __future__ import annotations

import json
import os
import runpy
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tests.rookery.support import ROOKERY_ROOT
from tests.rookery.test_preparation_and_isolation import copy_rookery


class NearMissBoundTests(unittest.TestCase):
    def test_argv_renderer_is_one_pass(self) -> None:
        namespace = runpy.run_path(str(ROOKERY_ROOT / "bin/near-miss-retry"))
        rendered = namespace["fill_argv"](
            ["tool", "{candidate}:{challenge}"],
            {"candidate": "FLAG{challenge}", "challenge": "CHALLENGE"},
        )
        self.assertEqual(rendered, ["tool", "FLAG{challenge}:CHALLENGE"])

    def test_legacy_shell_is_blocked_and_bounded_argv_remains_data(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        copy_rookery(root)
        # This bounds test deliberately exercises a helper-only fixture rather
        # than a public workspace; do not synthesize a launch binding.
        (root / "VERSION").unlink()
        (root / "bin" / "rookery").unlink()
        helper = root / "bin/near-miss-retry"
        marker = root / "injected"
        candidate = f"FLAG{{challenge}}; touch {marker}"
        legacy = subprocess.run(
            [
                str(helper),
                "challenge",
                candidate,
                "--run",
                "--budget",
                "1",
                "--probe-command",
                "echo {candidate}",
            ],
            cwd=root,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
            text=True,
            capture_output=True,
            timeout=30,
        )
        argv_template = [
            sys.executable,
            "-c",
            "import sys; print(sys.argv[1])",
            "{candidate}:{challenge}",
        ]
        executed = subprocess.run(
            [
                str(helper),
                "challenge",
                candidate,
                "--run",
                "--budget",
                "1",
                "--probe-argv-json",
                json.dumps(argv_template),
                "--json",
            ],
            cwd=root,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
            text=True,
            capture_output=True,
            timeout=30,
        )

        self.assertEqual(legacy.returncode, 2)
        self.assertIn("Legacy shell probe templates are disabled", legacy.stderr)
        self.assertEqual(executed.returncode, 0, executed.stderr)
        self.assertFalse(marker.exists())
        result = json.loads(executed.stdout)
        outdir = Path(result["outdir"])
        stdout = next(outdir.glob("probe-*/stdout.txt"))
        self.assertIn(candidate + ":challenge", stdout.read_text(encoding="utf-8"))
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(outdir.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(stdout.stat().st_mode), 0o600)
        temporary.cleanup()


if __name__ == "__main__":
    unittest.main(verbosity=2)
