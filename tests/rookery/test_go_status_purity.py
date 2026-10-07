from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from tests.rookery.test_preparation_and_isolation import copy_rookery


class GoStatusPurityTests(unittest.TestCase):
    def test_status_does_not_evaluate_dotenv(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            copy_rookery(root)
            marker = root / "dotenv-side-effect"
            (root / ".env").write_text(
                f"SIDE_EFFECT=$(touch {marker})\n",
                encoding="utf-8",
            )

            result = subprocess.run(
                ["bash", str(root / "go"), "status"],
                cwd=root,
                env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("state=uninitialized", result.stdout)
            self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
