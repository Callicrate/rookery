from __future__ import annotations

import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from tests.rookery.test_preparation_and_isolation import copy_rookery


class VpnRetirementProcessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        copy_rookery(self.root)
        self.helper = self.root / "bin" / "vpn"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_stop_refuses_without_signalling_legacy_pid_or_reading_configuration(self) -> None:
        process = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            cwd=self.root,
            start_new_session=True,
        )
        legacy_pid = self.root / "state" / "vpn" / "openvpn.pid"
        legacy_pid.parent.mkdir(parents=True)
        legacy_pid.write_text(f"{process.pid}\n", encoding="utf-8")
        self.root.joinpath(".env").write_text("VPN_SUDO=invalid\n", encoding="utf-8")
        try:
            result = subprocess.run(
                [str(self.helper), "stop", "--force"],
                cwd=self.root,
                env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
                text=True,
                capture_output=True,
                timeout=20,
                check=False,
            )
            self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
            self.assertEqual(result.stderr, "vpn_privileged_supervision_unavailable\n")
            self.assertIsNone(process.poll())
            self.assertEqual(legacy_pid.read_text(encoding="utf-8"), f"{process.pid}\n")
        finally:
            if process.poll() is None:
                os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                deadline = time.monotonic() + 3
                while process.poll() is None and time.monotonic() < deadline:
                    time.sleep(0.02)


if __name__ == "__main__":
    unittest.main(verbosity=2)
