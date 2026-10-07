from __future__ import annotations

import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

from tests.rookery.test_preparation_and_isolation import copy_rookery


REFUSAL = "vpn_privileged_supervision_unavailable"


class VpnRetirementSafetyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        copy_rookery(self.root)
        self.helper = self.root / "bin" / "vpn"
        self.poison = self.root / "poison"
        self.poison.mkdir()
        self.markers = self.root / "markers"
        self.markers.mkdir()
        for name in ("sudo", "openvpn", "ping", "health"):
            command = self.poison / name
            command.write_text(
                "#!/usr/bin/env sh\n"
                f"touch {str(self.markers / name)!r}\n",
                encoding="utf-8",
            )
            command.chmod(0o700)
        self.environment = {
            **os.environ,
            "PATH": str(self.poison) + os.pathsep + os.environ.get("PATH", ""),
            "PYTHONDONTWRITEBYTECODE": "1",
        }

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def invoke(self, executable: Path, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(executable), *args],
            cwd=self.root,
            env=self.environment,
            text=True,
            capture_output=True,
            timeout=20,
            check=False,
        )

    def test_operational_surface_refuses_before_poisoned_configuration_or_legacy_state(self) -> None:
        profile = self.root / "profile.ovpn"
        if hasattr(os, "mkfifo"):
            os.mkfifo(profile, 0o600)
        else:  # pragma: no cover - native Windows does not expose FIFO creation.
            profile.write_text("this profile must not be opened\n", encoding="utf-8")
        legacy = {
            self.root / "state" / "vpn" / "openvpn.pid": "99999\n",
            self.root / "state" / "vpn" / "events.jsonl": '{"legacy":true}\n',
            self.root / "logs" / "vpn" / "openvpn.log": "legacy\n",
        }
        for path, content in legacy.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
            path.chmod(0o666)
        before = {path: (path.read_bytes(), stat.S_IMODE(path.stat().st_mode)) for path in legacy}
        self.root.joinpath(".env").write_text(
            "\n".join(
                (
                    "not a dotenv assignment",
                    "VPN_OVPN_PATH=" + str(profile),
                    "VPN_SUDO=" + str(self.poison / "sudo"),
                    "OPENVPN_BIN=" + str(self.poison / "openvpn"),
                    "VPN_HEALTH_ARGV=[\"" + str(self.poison / "health") + "\"]",
                    "VPN_CHECK_TARGETS=fixture.invalid",
                    "",
                )
            ),
            encoding="utf-8",
        )

        commands = (
            (self.helper, "start"),
            (self.helper, "ensure"),
            (self.helper, "start-watch"),
            (self.helper, "stop"),
            (self.helper, "restart"),
            (self.helper, "health", "--json"),
            (self.helper, "status", "--json"),
            (self.helper, "logs"),
            (self.helper, "watch"),
            (self.root / "bin" / "vpn-connect",),
            (self.root / "bin" / "vpn-health",),
            (self.root / "bin" / "vpn-reconnect",),
            (self.root / "bin" / "vpn-status",),
        )
        for command in commands:
            with self.subTest(command=command):
                result = self.invoke(*command)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertEqual(result.stdout, "")
                self.assertEqual(result.stderr, REFUSAL + "\n")

        self.assertEqual(before, {path: (path.read_bytes(), stat.S_IMODE(path.stat().st_mode)) for path in legacy})
        self.assertEqual(list(self.markers.iterdir()), [])

    def test_help_and_version_are_static_and_do_not_touch_legacy_state(self) -> None:
        legacy = self.root / "state" / "vpn" / "openvpn.pid"
        legacy.parent.mkdir(parents=True)
        legacy.write_text("99999\n", encoding="utf-8")
        before = legacy.read_bytes()
        for argument, expected in (("--help", "externally supervised"), ("--version", "unavailable")):
            with self.subTest(argument=argument):
                result = self.invoke(self.helper, argument)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn(expected, result.stdout)
                self.assertEqual(result.stderr, "")
        self.assertEqual(legacy.read_bytes(), before)

    @unittest.skipUnless(os.name == "posix", "isolated shebang launch requires POSIX")
    def test_help_and_version_ignore_poisoned_python_startup(self) -> None:
        poison = self.root / "python-poison"
        poison.mkdir()
        marker = self.root / "python-startup-ran"
        startup = poison / "startup.py"
        startup.write_text(f"from pathlib import Path\nPath({str(marker)!r}).touch()\n", encoding="utf-8")
        (poison / "sitecustomize.py").write_text(startup.read_text(encoding="utf-8"), encoding="utf-8")
        environment = {
            **self.environment,
            "PYTHONPATH": str(poison),
            "PYTHONHOME": str(poison),
            "PYTHONSTARTUP": str(startup),
            "PYTHONUSERBASE": str(poison / "user-base"),
        }
        for argument, expected in (("--help", "externally supervised"), ("--version", "unavailable")):
            with self.subTest(argument=argument):
                result = subprocess.run(
                    [str(self.helper), argument],
                    cwd=self.root,
                    env=environment,
                    text=True,
                    capture_output=True,
                    timeout=20,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn(expected, result.stdout)
                self.assertEqual(result.stderr, "")
                self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
