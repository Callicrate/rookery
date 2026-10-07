from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tests.rookery.support import ROOKERY_ROOT

LIB = ROOKERY_ROOT / "lib"
if str(LIB) not in sys.path:
    sys.path.insert(0, str(LIB))

from rookery.verdict_parser import parse_file  # noqa: E402


class VerdictBoundTests(unittest.TestCase):
    def test_file_and_stdin_are_bounded_before_parse(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        path = Path(temporary.name) / "response.json"
        path.write_text(json.dumps({"message": "x" * 1024}), encoding="utf-8")

        with self.assertRaisesRegex(ValueError, "exceeds configured byte limit"):
            parse_file(path, max_bytes=100)
        process = subprocess.run(
            [
                sys.executable,
                str(ROOKERY_ROOT / "bin/verdict-parse"),
                "-",
                "--max-bytes",
                "100",
            ],
            input="x" * 101,
            text=True,
            capture_output=True,
            timeout=30,
        )
        self.assertNotEqual(process.returncode, 0)
        self.assertIn("exceeds configured byte limit", process.stderr)
        temporary.cleanup()


if __name__ == "__main__":
    unittest.main(verbosity=2)
