from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from tests.rookery.test_preparation_and_isolation import copy_rookery


@unittest.skipUnless(os.name == "posix", "the documented release wrapper requires a POSIX shell")
class ReleaseBuilderWrapperBytecodeIsolationTests(unittest.TestCase):
    def test_documented_wrapper_builds_without_bytecode_controls_or_source_cache(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            stage = Path(temporary)
            source = stage / "source"
            output = stage / "dist"
            copy_rookery(source)
            shutil.rmtree(source / ".ruff_cache", ignore_errors=True)
            environment = dict(os.environ)
            environment.pop("PYTHONDONTWRITEBYTECODE", None)
            environment.pop("PYTHONPYCACHEPREFIX", None)

            completed = subprocess.run(
                ["./bin/build-release", "--output-dir", "../dist"],
                cwd=source,
                env=environment,
                text=True,
                capture_output=True,
                timeout=30,
            )

            summary = json.loads(completed.stdout)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertTrue(summary["ok"])
            self.assertEqual(
                {path.name for path in output.iterdir()},
                {summary["archive"], summary["manifest"], summary["sha256_sidecar"]},
            )
            self.assertEqual(list(source.rglob("__pycache__")), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
