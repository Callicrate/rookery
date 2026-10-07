from __future__ import annotations

import os
import runpy
import stat
import subprocess
import unittest
from pathlib import Path
from unittest import mock

from tests.rookery.support import ROOKERY_ROOT
from tests.rookery.test_acceptance_campaign import make_deployed_workspace


class ImmersiveRefreshBoundTests(unittest.TestCase):
    def test_renderer_is_one_pass_and_http_body_is_bounded(self) -> None:
        namespace = runpy.run_path(
            str(
                ROOKERY_ROOT
                / "adapters/immersive/bin/immersive-selected-lab-refresh"
            )
        )
        rendered = namespace["fill_argv"](
            ["tool", "{challenge}:{attempt-id}"],
            {
                "challenge": "FLAG{attempt-id}",
                "attempt_id": "ATTEMPT",
            },
        )
        response = mock.MagicMock()
        response.read.return_value = b"x" * 1025

        self.assertEqual(rendered, ["tool", "FLAG{attempt-id}:ATTEMPT"])
        with self.assertRaisesRegex(RuntimeError, "exceeds configured byte limit"):
            namespace["read_bounded"](response, 1024)
        response.read.assert_called_once_with(1025)

    def test_legacy_shell_and_mutation_override_fail_closed(self) -> None:
        fixture = make_deployed_workspace("manual")
        self.addCleanup(fixture.cleanup)
        root = Path(fixture.name)
        helper = root / "adapters/immersive/bin/immersive-selected-lab-refresh"
        marker = root / "injected"
        outdir = root / "evidence/immersive/refresh"
        environment = {
            **fixture.bootstrap.environment,
            "IMMERSIVE_SELECTED_LAB_REFRESH_COMMAND": f"touch {marker}",
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        legacy = subprocess.run(
            [str(helper), "--dry-run", "--outdir", str(outdir)],
            cwd=root,
            env=environment,
            text=True,
            capture_output=True,
            timeout=30,
        )
        mutation = subprocess.run(
            [str(helper), "--allow-mutation"],
            cwd=root,
            env={**fixture.bootstrap.environment, "PYTHONDONTWRITEBYTECODE": "1"},
            text=True,
            capture_output=True,
            timeout=30,
        )

        self.assertEqual(legacy.returncode, 2, legacy.stderr)
        self.assertIn("legacy-shell-template-disabled", legacy.stdout)
        self.assertFalse(marker.exists())
        self.assertEqual(mutation.returncode, 3)
        self.assertIn("canonical-executor-required", mutation.stdout)
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(outdir.stat().st_mode), 0o700)
            self.assertEqual(
                stat.S_IMODE((outdir / "summary.json").stat().st_mode),
                0o600,
            )
        fixture.cleanup()


if __name__ == "__main__":
    unittest.main(verbosity=2)
