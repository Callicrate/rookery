from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import unittest
from pathlib import Path

from tests.rookery.test_acceptance_campaign import make_deployed_workspace


class GuacExportBoundTests(unittest.TestCase):
    def setUp(self) -> None:
        self.workspace = make_deployed_workspace("manual")
        self.root = Path(self.workspace.name)
        self.helper = self.root / "extensions/guacamole/bin/guac-export-file"

    def tearDown(self) -> None:
        self.workspace.cleanup()

    def test_legacy_shell_is_blocked_and_argv_preserves_remote_path(self) -> None:
        marker = self.root / "injected"
        remote_path = f'"; touch {marker}; #'
        legacy_out = self.root / "evidence/guac/legacy"
        legacy = subprocess.run(
            [
                str(self.helper),
                remote_path,
                "--method",
                "configured",
                "--outdir",
                str(legacy_out),
            ],
            cwd=self.root,
            env={
                **os.environ,
                "GUAC_REMOTE_FILE_EXPORT_COMMAND": 'tool "{remote_path}"',
                "PYTHONDONTWRITEBYTECODE": "1",
            },
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )
        argv_out = self.root / "evidence/guac/argv"
        argv = [
            sys.executable,
            "-c",
            "import os,sys; os.write(1, sys.argv[1].encode())",
            "{remote_path}",
        ]
        executed = subprocess.run(
            [
                str(self.helper),
                remote_path,
                "--method",
                "configured",
                "--outdir",
                str(argv_out),
            ],
            cwd=self.root,
            env={
                **os.environ,
                "GUAC_REMOTE_FILE_EXPORT_ARGV": json.dumps(argv),
                "PYTHONDONTWRITEBYTECODE": "1",
            },
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )
        direct_path = subprocess.run(
            [
                str(self.helper),
                remote_path,
                "--method",
                "configured",
                "--outdir",
                str(self.root / "evidence/guac/direct-path"),
            ],
            cwd=self.root,
            env={
                **os.environ,
                "GUAC_REMOTE_FILE_EXPORT_ARGV": json.dumps(
                    [sys.executable, "-c", "print('x')", "{local_path}"]
                ),
                "PYTHONDWRITEBYTECODE": "1",
            },
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )

        self.assertEqual(legacy.returncode, 2, legacy.stderr)
        self.assertIn("legacy-shell-template-disabled", legacy.stdout)
        self.assertFalse(marker.exists())
        self.assertEqual(executed.returncode, 0, executed.stderr)
        self.assertNotEqual(direct_path.returncode, 0)
        self.assertIn("unknown placeholder", direct_path.stderr)
        summary = json.loads(executed.stdout)
        local_path = Path(summary["local_path"])
        self.assertEqual(local_path.parent, argv_out)
        self.assertEqual(local_path.name, "remote-file")
        self.assertEqual(local_path.read_text(encoding="utf-8"), remote_path)
        self.assertFalse(marker.exists())
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(argv_out.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(local_path.stat().st_mode), 0o600)

    def test_terminal_capture_uses_bounded_argv_and_blocks_legacy_shell(self) -> None:
        helper = self.root / "extensions/guacamole/bin/guac-terminal-capture"
        marker = self.root / "terminal-injected"
        command = f'echo "fixture"; touch {marker}'
        legacy = subprocess.run(
            [
                str(helper),
                command,
                "--no-lease",
                "--outdir",
                str(self.root / "evidence/guac/terminal-legacy"),
            ],
            cwd=self.root,
            env={
                **os.environ,
                "GUAC_TERMINAL_CAPTURE_COMMAND": 'tool "{command}"',
                "PYTHONDONTWRITEBYTECODE": "1",
            },
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )
        argv = [
            sys.executable,
            "-c",
            "import sys; print(sys.argv[1])",
            "{command}",
        ]
        argv_out = self.root / "evidence/guac/terminal-argv"
        executed = subprocess.run(
            [
                str(helper),
                command,
                "--no-lease",
                "--outdir",
                str(argv_out),
            ],
            cwd=self.root,
            env={
                **os.environ,
                "GUAC_TERMINAL_CAPTURE_ARGV": json.dumps(argv),
                "PYTHONDONTWRITEBYTECODE": "1",
            },
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )

        self.assertEqual(legacy.returncode, 1)
        self.assertIn("status=legacy-shell-template-disabled", legacy.stdout)
        self.assertFalse(marker.exists())
        self.assertEqual(executed.returncode, 0, executed.stderr)
        self.assertIn("status=ok", executed.stdout)
        self.assertIn(command, (argv_out / "stdout.log").read_text(encoding="utf-8"))
        self.assertFalse(marker.exists())
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(argv_out.stat().st_mode), 0o700)
            self.assertEqual(
                stat.S_IMODE((argv_out / "stdout.log").stat().st_mode),
                0o600,
            )

    def test_ssh_sender_uses_private_argv_and_stop_lock(self) -> None:
        helper = self.root / "extensions/guacamole/bin/guac-ssh-exec"
        marker = self.root / "ssh-injected"
        remote_command = f"echo fixture; touch {marker}"
        legacy = subprocess.run(
            [str(helper), remote_command, "--outdir", str(self.root / "evidence/guac/ssh-legacy")],
            cwd=self.root,
            env={
                **os.environ,
                "GUAC_SSH_EXEC_COMMAND": 'tool "{commands_file}"',
                "PYTHONDONTWRITEBYTECODE": "1",
            },
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )
        argv_out = self.root / "evidence/guac/ssh-argv"
        argv = [
            sys.executable,
            "-c",
            "import pathlib,sys; print(pathlib.Path(sys.argv[1]).read_text())",
            "{commands_file}",
        ]
        executed = subprocess.run(
            [str(helper), remote_command, "--outdir", str(argv_out)],
            cwd=self.root,
            env={
                **os.environ,
                "GUAC_SSH_EXEC_ARGV": json.dumps(argv),
                "PYTHONDONTWRITEBYTECODE": "1",
            },
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )

        self.assertEqual(legacy.returncode, 3)
        self.assertIn(
            "shell templates are disabled",
            (self.root / "evidence/guac/ssh-legacy/ERROR.txt").read_text(
                encoding="utf-8"
            ),
        )
        self.assertFalse(marker.exists())
        self.assertEqual(executed.returncode, 0, executed.stderr)
        result = json.loads((argv_out / "result.json").read_text(encoding="utf-8"))
        self.assertEqual(result["mode"], "command-argv")
        self.assertEqual(result["termination"], "exited")
        self.assertIn(remote_command, (argv_out / "stdout.txt").read_text(encoding="utf-8"))
        self.assertFalse(marker.exists())
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(argv_out.stat().st_mode), 0o700)
            self.assertEqual(
                stat.S_IMODE((argv_out / "commands.txt").stat().st_mode),
                0o600,
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
