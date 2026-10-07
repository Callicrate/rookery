from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from tests.rookery.test_preparation_and_isolation import copy_rookery


class VpnRetirementEnvironmentTests(unittest.TestCase):
    def test_refusal_is_independent_of_parent_and_dotenv_vpn_authority(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            copy_rookery(root)
            marker = root / "parent-authority-used"
            root.joinpath(".env").write_text(
                "VPN_ENABLED=1\n"
                "VPN_SUDO=$(touch parent-authority-used)\n"
                "OPENVPN_BIN=/does/not/exist\n"
                "VPN_CONNECT_ARGV=[\"/does/not/exist\"]\n",
                encoding="utf-8",
            )
            result = subprocess.run(
                [str(root / "bin" / "vpn"), "ensure"],
                cwd=root,
                env={
                    **os.environ,
                    "VPN_ENABLED": "1",
                    "VPN_SUDO": str(marker),
                    "OPENVPN_BIN": str(marker),
                    "PYTHONDONTWRITEBYTECODE": "1",
                },
                text=True,
                capture_output=True,
                timeout=20,
                check=False,
            )
            self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
            self.assertEqual(result.stderr, "vpn_privileged_supervision_unavailable\n")
            self.assertFalse(marker.exists())
            self.assertFalse((root / "state" / "vpn").exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
