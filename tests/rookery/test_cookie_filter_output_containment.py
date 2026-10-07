from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from rookery.portable.cookie_output import (
    CookieOutputError,
    preflight_cookie_output,
    prepare_cookie_output,
    write_new_cookie_output,
)
from tests.rookery.test_preparation_and_isolation import copy_rookery


@unittest.skipUnless(os.name == "posix", "requires POSIX descriptor semantics")
class CookieFilterOutputContainmentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        copy_rookery(self.root)
        self.environment = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
        self.helper = self.root / "bin" / "cookie-filter"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def source(self) -> Path:
        source = self.root / "source.json"
        source.write_text(
            json.dumps(
                [
                    {
                        "name": "session",
                        "value": "cookie-value-not-for-metadata",
                        "domain": "fixture.invalid",
                    }
                ]
            ),
            encoding="utf-8",
        )
        return source

    def run_filter(self, source: Path, outdir: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                str(self.helper),
                "--file",
                str(source),
                "--domains",
                "fixture.invalid",
                "--outdir",
                str(outdir),
                "--json",
            ],
            cwd=self.root,
            env=self.environment,
            text=True,
            capture_output=True,
            timeout=30,
        )

    def owned_output(self, name: str) -> Path:
        path = self.root / "platform" / "cookies" / name
        prepare_cookie_output(preflight_cookie_output(self.root, str(path)))
        return path

    def test_outside_and_unowned_outputs_refuse_before_cookie_read_or_chmod(self) -> None:
        source = self.source()
        source_mode = stat.S_IMODE(source.stat().st_mode)
        outside = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(outside, ignore_errors=True))
        sentinel = outside / "sentinel.txt"
        sentinel.write_text("outside remains exact", encoding="utf-8")
        result = self.run_filter(source, outside)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(sentinel.read_text(encoding="utf-8"), "outside remains exact")
        self.assertEqual(stat.S_IMODE(source.stat().st_mode), source_mode)
        self.assertNotIn(str(outside), result.stdout + result.stderr)

        unowned = self.root / "platform" / "cookies" / "unowned"
        unowned.mkdir(parents=True)
        unowned.chmod(0o777)
        retained = unowned / "retained.txt"
        retained.write_text("do not chmod or rewrite", encoding="utf-8")
        retained.chmod(0o666)
        result = self.run_filter(source, unowned)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(retained.read_text(encoding="utf-8"), "do not chmod or rewrite")
        self.assertEqual(stat.S_IMODE(unowned.stat().st_mode), 0o777)
        self.assertEqual(stat.S_IMODE(retained.stat().st_mode), 0o666)
        self.assertEqual(stat.S_IMODE(source.stat().st_mode), source_mode)

    def test_fixed_file_collision_and_unsafe_owned_entries_never_overwrite(self) -> None:
        source = self.source()
        output = self.owned_output("collision")
        write_new_cookie_output(output=prepare_cookie_output(preflight_cookie_output(self.root, str(output))), name="summary.json", data=b"prior summary\n")
        result = self.run_filter(source, output)
        self.assertEqual(result.returncode, 2)
        self.assertEqual((output / "summary.json").read_bytes(), b"prior summary\n")

        symlinked = self.owned_output("symlink")
        outside = self.root / "outside.txt"
        outside.write_text("outside", encoding="utf-8")
        (symlinked / "summary.json").symlink_to(outside)
        result = self.run_filter(source, symlinked)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(outside.read_text(encoding="utf-8"), "outside")

        hardlinked = self.owned_output("hardlink")
        prior = hardlinked / "prior.txt"
        prior.write_text("prior", encoding="utf-8")
        os.link(prior, hardlinked / "prior-copy.txt")
        result = self.run_filter(source, hardlinked)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(prior.read_text(encoding="utf-8"), "prior")

    def test_fresh_admission_detects_a_preparation_time_symlink_swap(self) -> None:
        output = self.root / "platform" / "cookies" / "swap"
        plan = preflight_cookie_output(self.root, str(output))
        outside = self.root / "outside"
        outside.mkdir()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.symlink_to(outside, target_is_directory=True)
        with self.assertRaises(CookieOutputError):
            prepare_cookie_output(plan)
        self.assertFalse((outside / ".rookery-cookie-output.json").exists())

    def test_completed_temp_is_not_published_after_directory_move_and_replacement(self) -> None:
        output_path = self.root / "platform" / "cookies" / "race"
        output = prepare_cookie_output(preflight_cookie_output(self.root, str(output_path)))
        outside = self.root / "outside"
        outside.mkdir()
        sentinel = outside / "sentinel.txt"
        sentinel.write_text("outside sentinel", encoding="utf-8")
        ready = threading.Event()
        release = threading.Event()
        original_fsync = os.fsync
        first = True

        def pause_after_completed_temp(descriptor: int) -> None:
            nonlocal first
            if first:
                first = False
                ready.set()
                self.assertTrue(release.wait(timeout=10))
            original_fsync(descriptor)

        outcome: list[BaseException] = []

        def writer() -> None:
            try:
                write_new_cookie_output(output, "summary.json", b"new evidence\n")
            except BaseException as exc:  # asserted below; keep thread diagnostics.
                outcome.append(exc)

        with mock.patch("rookery.portable.cookie_output.os.fsync", pause_after_completed_temp):
            thread = threading.Thread(target=writer)
            thread.start()
            self.assertTrue(ready.wait(timeout=10))
            moved = outside / "moved-output"
            os.rename(output_path, moved)
            output_path.mkdir()
            release.set()
            thread.join(timeout=10)
        self.assertFalse(thread.is_alive())
        self.assertEqual(len(outcome), 1)
        self.assertIsInstance(outcome[0], CookieOutputError)
        self.assertEqual(sentinel.read_text(encoding="utf-8"), "outside sentinel")
        self.assertFalse((moved / "summary.json").exists())
        self.assertFalse((output_path / "summary.json").exists())

    def test_normal_contained_output_is_private_and_path_value_free(self) -> None:
        source = self.source()
        output = self.root / "platform" / "cookies" / "normal"
        result = self.run_filter(source, output)
        self.assertEqual(result.returncode, 0, result.stderr)
        summary = (output / "summary.json").read_text(encoding="utf-8")
        self.assertIn('"outdir": "platform/cookies/normal"', summary)
        self.assertNotIn(str(source), summary)
        self.assertNotIn("cookie-value-not-for-metadata", summary)
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)
        for name in (
            ".rookery-cookie-output.json",
            "cookie-header.txt",
            "selected-cookies.json",
            "summary.json",
        ):
            self.assertEqual(stat.S_IMODE((output / name).stat().st_mode), 0o600)


if __name__ == "__main__":
    unittest.main(verbosity=2)
