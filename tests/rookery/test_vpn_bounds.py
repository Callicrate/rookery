from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from tests.rookery.test_preparation_and_isolation import copy_rookery


class VpnRetirementAliasTests(unittest.TestCase):
    def test_compatibility_aliases_preserve_the_value_free_refusal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            copy_rookery(root)
            aliases = ("vpn-connect", "vpn-health", "vpn-reconnect", "vpn-status")
            for alias in aliases:
                with self.subTest(alias=alias):
                    result = subprocess.run(
                        [str(root / "bin" / alias)],
                        cwd=root,
                        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
                        text=True,
                        capture_output=True,
                        timeout=20,
                        check=False,
                    )
                    self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                    self.assertEqual(result.stdout, "")
                    self.assertEqual(result.stderr, "vpn_privileged_supervision_unavailable\n")


if __name__ == "__main__":
    unittest.main(verbosity=2)
