from __future__ import annotations

# ruff: noqa: E402

import os
import shutil
import subprocess
import sys
import unittest
from unittest import mock

from tests.rookery.support import ROOKERY_ROOT

LIBRARY = ROOKERY_ROOT / "lib"
if str(LIBRARY) not in sys.path:
    sys.path.insert(0, str(LIBRARY))

from rookery.portable.environment import ChildEnvironment
from rookery.portable.preparation import (
    _load_preparation_config,
    _preparation_markdown,
    _scan_binaries,
)


ENTRYPOINTS = (
    ROOKERY_ROOT / "bin" / "rookery-bootstrap.py",
    ROOKERY_ROOT / "bin" / "build-release",
    ROOKERY_ROOT / "bin" / "validate_rookery.py",
)
REQUIRED_VERSION = (3, 11)


class PythonRuntimeMinimumTests(unittest.TestCase):
    def test_supported_interpreter_reaches_each_guarded_entrypoint(self) -> None:
        """Python 3.11+ reaches command parsing through isolated startup."""

        self.assertGreaterEqual(sys.version_info[:2], REQUIRED_VERSION)
        environment = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
        for entrypoint in ENTRYPOINTS:
            with self.subTest(entrypoint=entrypoint.name):
                completed = subprocess.run(
                    [sys.executable, "-I", "-S", "-B", str(entrypoint), "--help"],
                    cwd=ROOKERY_ROOT,
                    env=environment,
                    text=True,
                    capture_output=True,
                    timeout=30,
                    check=False,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)

    @unittest.skipUnless(os.name == "posix", "Python 3.10 probe requires POSIX")
    def test_python310_refuses_before_importing_the_runtime(self) -> None:
        """An available Python 3.10 exits clearly instead of importing 3.11-only code."""

        legacy_python = shutil.which("python3.10")
        if legacy_python is None:
            self.skipTest("python3.10 is not installed")
        environment = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
        for entrypoint in ENTRYPOINTS:
            with self.subTest(entrypoint=entrypoint.name):
                completed = subprocess.run(
                    [legacy_python, "-I", "-S", "-B", str(entrypoint), "--help"],
                    cwd=ROOKERY_ROOT,
                    env=environment,
                    text=True,
                    capture_output=True,
                    timeout=30,
                    check=False,
                )
                self.assertEqual(completed.returncode, 2, completed.stderr)
                self.assertEqual(completed.stdout, "")
                self.assertIn("Rookery requires Python 3.11 or newer", completed.stderr)
                self.assertIn("found Python 3.10.", completed.stderr)
                self.assertNotIn("ModuleNotFoundError", completed.stderr)

    def test_preparation_reports_an_old_python_without_replacing_it(self) -> None:
        """Preparation records Python 3.10 as unsupported and never installs over it."""

        configuration = _load_preparation_config(ROOKERY_ROOT)
        python_item = next(
            item for item in configuration["binaries"] if item["id"] == "python3"
        )
        local = ChildEnvironment({"PATH": "/fixture/bin"}, "test", ())
        install_log: list[dict[str, object]] = []

        with (
            mock.patch(
                "rookery.portable.preparation._which_all",
                return_value=(True, {"python3": "/fixture/bin/python3"}),
            ),
            mock.patch(
                "rookery.portable.preparation._python_version", return_value=(3, 10)
            ),
            mock.patch(
                "rookery.portable.preparation._install_packages",
                side_effect=AssertionError("an old selected Python must not be replaced"),
            ),
        ):
            rows = _scan_binaries(
                ROOKERY_ROOT,
                {"binaries": [python_item]},
                {"ROOKERY_PREPARE_INSTALL": "1"},
                apply=True,
                manager="apt",
                install_log=install_log,
                local=local,
                network=local,
            )

        self.assertEqual(
            rows,
            [
                {
                    "id": "python3",
                    "commands": ["python3"],
                    "required": True,
                    "install_class": "core",
                    "available": False,
                    "paths": {"python3": "/fixture/bin/python3"},
                    "minimum_python_version": "3.11",
                    "python_version": "3.10",
                    "install_attempted": False,
                }
            ],
        )
        self.assertEqual(install_log, [])
        rendered = _preparation_markdown(
            {
                "generated_at": "fixture",
                "mode": "auto",
                "ready": False,
                "services": {},
                "binaries": rows,
                "data_files": [],
                "warnings": [],
            }
        )
        self.assertIn(
            "- `python3`: unsupported (found 3.10; requires 3.11 or newer)", rendered
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main(verbosity=2)
