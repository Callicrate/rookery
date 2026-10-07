from __future__ import annotations

import json
import os
import runpy
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

from tests.rookery.support import ROOKERY_ROOT
from tests.rookery.test_acceptance_campaign import make_deployed_workspace


class ImmersiveOutputContainmentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.workspace = make_deployed_workspace("manual")
        self.root = Path(self.workspace.name)
        self.environment = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}

    def tearDown(self) -> None:
        self.workspace.cleanup()

    def run_helper(self, relative: str, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(self.root / relative), *args],
            cwd=self.root,
            env=self.environment,
            text=True,
            capture_output=True,
            timeout=30,
        )

    def test_all_immersive_helpers_reject_an_actual_outside_temp_directory(self) -> None:
        outside = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(outside, ignore_errors=True))
        sentinel = outside / "sentinel.txt"
        sentinel.write_text("must remain outside Rookery", encoding="utf-8")
        cases = (
            (
                "adapters/immersive/bin/immersive-cluster-capture",
                self.root / "evidence" / "immersive",
                "--url",
                "wss://fixture.invalid/cable",
            ),
            (
                "adapters/immersive/bin/immersive-cookie-filter",
                self.root / "platform" / "cookies",
            ),
            (
                "adapters/immersive/bin/immersive-selected-lab-refresh",
                self.root / "evidence" / "immersive",
            ),
        )
        for case in cases:
            with self.subTest(helper=case[0]):
                result = self.run_helper(case[0], *case[2:], "--outdir", str(outside))
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(sentinel.read_text(encoding="utf-8"), "must remain outside Rookery")
                self.assertNotIn(str(outside), result.stdout + result.stderr)
                self.assertFalse(case[1].exists())

    def test_intermediate_symlink_and_owned_tree_hardlink_are_rejected(self) -> None:
        downloads = self.root / "downloads"
        downloads.mkdir(exist_ok=True)
        outside = downloads / "outside"
        outside.mkdir()
        sentinel = outside / "sentinel.txt"
        sentinel.write_text("outside", encoding="utf-8")
        base = self.root / "evidence" / "immersive"
        base.mkdir(parents=True)
        (base / "redirect").symlink_to(outside, target_is_directory=True)
        result = self.run_helper(
            "adapters/immersive/bin/immersive-cluster-capture",
            "--url",
            "wss://fixture.invalid/cable",
            "--outdir",
            str(base / "redirect" / "run"),
        )
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(sentinel.read_text(encoding="utf-8"), "outside")

        policy = runpy.run_path(
            str(ROOKERY_ROOT / "adapters" / "immersive" / "path_policy.py")
        )
        raced = policy["prepare_immersive_output"](
            self.root,
            family_parts=("evidence", "immersive"),
            raw_outdir=str(base / "race"),
            default_label="unused",
        )
        shutil.rmtree(raced.path)
        raced.path.symlink_to(outside, target_is_directory=True)
        with self.assertRaises(policy["ImmersiveOutputError"]):
            raced.guard()
        self.assertEqual(sentinel.read_text(encoding="utf-8"), "outside")

        downloads = self.root / "downloads"
        downloads.mkdir(exist_ok=True)
        cookies = downloads / "cookies.json"
        cookies.write_text(
            json.dumps({"cookies": [{"name": "session", "value": "safe"}]}),
            encoding="utf-8",
        )
        output = self.root / "platform" / "cookies" / "owned"
        first = self.run_helper(
            "adapters/immersive/bin/immersive-cookie-filter",
            "--file",
            str(cookies),
            "--outdir",
            str(output),
            "--json",
        )
        self.assertEqual(first.returncode, 0, first.stderr)
        os.link(output / "summary.json", output / "summary-hardlink.json")
        second = self.run_helper(
            "adapters/immersive/bin/immersive-cookie-filter",
            "--file",
            str(cookies),
            "--outdir",
            str(output),
        )
        self.assertEqual(second.returncode, 2, second.stderr)

    def test_normal_contained_output_redacts_machine_path_metadata(self) -> None:
        downloads = self.root / "downloads"
        downloads.mkdir(exist_ok=True)
        cookies = downloads / "cookies.json"
        cookies.write_text(
            json.dumps({"cookies": [{"name": "session", "value": "safe"}]}),
            encoding="utf-8",
        )
        output = self.root / "platform" / "cookies" / "normal"
        result = self.run_helper(
            "adapters/immersive/bin/immersive-cookie-filter",
            "--file",
            str(cookies),
            "--outdir",
            str(output),
            "--json",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        summary = (output / "summary.json").read_text(encoding="utf-8")
        self.assertIn('"outdir": "platform/cookies/normal"', summary)
        self.assertNotIn(str(self.root), summary)
        self.assertTrue((output / ".rookery-immersive-output.json").is_file())

    def test_contained_cluster_rechecks_scope_before_connecting(self) -> None:
        namespace = runpy.run_path(
            str(self.root / "adapters/immersive/bin/immersive-cluster-capture")
        )
        root = self.root
        globals_dict = namespace["main"].__globals__
        globals_dict["ROOT"] = root
        globals_dict["scope_guard_url"] = mock.Mock(
            side_effect=RuntimeError("scope refused")
        )
        websocket = types.SimpleNamespace(create_connection=mock.Mock())
        output = root / "evidence" / "immersive" / "scope-before-connect"
        with (
            mock.patch.object(
                sys,
                "argv",
                [
                    "immersive-cluster-capture",
                    "--url",
                    "wss://fixture.invalid/cable",
                    "--outdir",
                    str(output),
                ],
            ),
            mock.patch.dict(sys.modules, {"websocket": websocket}),
        ):
            self.assertEqual(namespace["main"](), 4)
        websocket.create_connection.assert_not_called()
        self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
