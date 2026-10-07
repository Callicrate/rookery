from __future__ import annotations

import json
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

from tests.rookery.test_preparation_and_isolation import copy_rookery


class SafeRgBoundTests(unittest.TestCase):
    def test_search_output_is_bounded_before_persistence(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        copy_rookery(root)
        source = root / "large.txt"
        source.write_text("x" * 10000 + "\n", encoding="utf-8")
        result = subprocess.run(
            [
                str(root / "bin/safe-rg"),
                "x",
                str(source),
                "--max-bytes",
                "1024",
            ],
            cwd=root,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )
        meta_path = next((root / "research/search_guard").glob("*/meta.json"))
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        stdout_path = meta_path.parent / "stdout.txt"

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(meta["truncated"])
        self.assertEqual(meta["termination"], "output_limit")
        self.assertLessEqual(stdout_path.stat().st_size, 1024)
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(meta_path.parent.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(stdout_path.stat().st_mode), 0o600)
        temporary.cleanup()


if __name__ == "__main__":
    unittest.main(verbosity=2)
