from __future__ import annotations

import subprocess
import sys
import unittest

from tests.rookery.support import ROOKERY_ROOT


class InputBoundTests(unittest.TestCase):
    def test_ctf_text_and_binary_stdin_limits_fail_closed(self) -> None:
        cases = [
            (
                [
                    sys.executable,
                    str(ROOKERY_ROOT / "bin/mutation-audit"),
                    "-",
                    "--max-bytes",
                    "100",
                ],
                "mutation-audit stdin exceeds",
            ),
            (
                [
                    sys.executable,
                    str(ROOKERY_ROOT / "bin/powershell-safe-deobfuscate"),
                    "-",
                    "--max-bytes",
                    "100",
                ],
                "PowerShell stdin exceeds",
            ),
            (
                [
                    sys.executable,
                    str(ROOKERY_ROOT / "bin/decoder-lab"),
                    "rot47",
                    "--max-bytes",
                    "100",
                ],
                "decoder stdin exceeds",
            ),
            (
                [
                    str(ROOKERY_ROOT / "bin/digest"),
                    "-",
                    "--max-bytes",
                    "100",
                ],
                "digest stdin exceeds",
            ),
        ]
        for command, expected in cases:
            with self.subTest(command=command[1]):
                result = subprocess.run(
                    command,
                    input="x" * 101,
                    text=True,
                    capture_output=True,
                    timeout=30,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(expected, result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
