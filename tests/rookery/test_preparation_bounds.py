from __future__ import annotations

# ruff: noqa: E402

import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from tests.rookery.support import ROOKERY_ROOT

LIB = ROOKERY_ROOT / "lib"
if str(LIB) not in sys.path:
    sys.path.insert(0, str(LIB))

from rookery.portable.environment import build_child_environment, purpose_policy
from rookery.portable.preparation import (
    DEFAULT_PREPARATION_OUTPUT_BYTES,
    PreparationOutputLimitError,
    _run,
)


class PreparationRunBoundsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.environment = build_child_environment(
            self.root,
            policy=purpose_policy("preparation-bounds-test"),
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_preparation(
        self,
        command: list[str],
        *,
        timeout: float,
        check: bool = False,
        max_output_bytes: int = DEFAULT_PREPARATION_OUTPUT_BYTES,
    ) -> subprocess.CompletedProcess[str]:
        return _run(
            command,
            root=self.root,
            environment=self.environment,
            timeout=timeout,
            check=check,
            max_output_bytes=max_output_bytes,
        )

    def test_short_success_preserves_completed_process_output(self) -> None:
        command = [
            sys.executable,
            "-c",
            (
                "import os; "
                "os.write(1, b'ready\\r\\n'); "
                "os.write(2, b'diagnostic\\r\\n')"
            ),
        ]

        completed = self.run_preparation(command, timeout=5)

        self.assertEqual(completed.args, command)
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(completed.stdout, "ready\n")
        self.assertEqual(completed.stderr, "diagnostic\n")

    def test_nonzero_and_check_behavior_match_subprocess(self) -> None:
        command = [
            sys.executable,
            "-c",
            "import sys; print('out'); print('err', file=sys.stderr); raise SystemExit(7)",
        ]

        completed = self.run_preparation(command, timeout=5)
        self.assertEqual(completed.returncode, 7)
        self.assertEqual(completed.stdout.strip(), "out")
        self.assertEqual(completed.stderr.strip(), "err")

        with self.assertRaises(subprocess.CalledProcessError) as raised:
            self.run_preparation(command, timeout=5, check=True)
        self.assertEqual(raised.exception.returncode, 7)
        self.assertEqual(raised.exception.stdout.strip(), "out")
        self.assertEqual(raised.exception.stderr.strip(), "err")

    def test_timeout_retains_partial_diagnostics(self) -> None:
        command = [
            sys.executable,
            "-c",
            (
                "import sys, time; "
                "print('before-timeout', flush=True); "
                "print('timeout-diagnostic', file=sys.stderr, flush=True); "
                "time.sleep(60)"
            ),
        ]
        started = time.monotonic()

        with self.assertRaises(subprocess.TimeoutExpired) as raised:
            self.run_preparation(command, timeout=0.2, max_output_bytes=4096)

        self.assertLess(time.monotonic() - started, 5)
        self.assertIn(b"before-timeout", raised.exception.stdout)
        self.assertIn(b"timeout-diagnostic", raised.exception.stderr)

    def test_cap_plus_one_reports_output_limit(self) -> None:
        limit = 4096
        command = [
            sys.executable,
            "-c",
            f"import os; os.write(1, b'x' * {limit + 1})",
        ]

        with self.assertRaises(PreparationOutputLimitError) as raised:
            self.run_preparation(command, timeout=5, max_output_bytes=limit)

        error = raised.exception
        self.assertEqual(error.termination, "output_limit")
        self.assertEqual(error.limit, limit)
        self.assertEqual(len(error.stdout), limit)
        self.assertEqual(error.stderr, "")

    def test_overflow_retains_only_bounded_combined_diagnostics(self) -> None:
        limit = 4096
        command = [
            sys.executable,
            "-c",
            (f"import os; os.write(2, b'installer-diagnostic\\n' + b'x' * {limit})"),
        ]

        with self.assertRaises(PreparationOutputLimitError) as raised:
            self.run_preparation(command, timeout=5, max_output_bytes=limit)

        error = raised.exception
        self.assertIn("installer-diagnostic", error.stderr)
        self.assertEqual(error.stdout, "")
        self.assertEqual(len(error.stdout.encode()) + len(error.stderr.encode()), limit)

    @unittest.skipUnless(os.name == "posix", "POSIX process-group assertion")
    def test_timeout_terminates_the_process_group(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            marker = Path(temporary) / "grandchild-survived"
            grandchild = (
                "import pathlib, time; "
                "time.sleep(0.75); "
                f"pathlib.Path({str(marker)!r}).write_text('survived')"
            )
            command = [
                sys.executable,
                "-c",
                (
                    "import subprocess, sys, time; "
                    f"subprocess.Popen([sys.executable, '-c', {grandchild!r}]); "
                    "print('parent-ready', flush=True); "
                    "time.sleep(60)"
                ),
            ]

            with self.assertRaises(subprocess.TimeoutExpired):
                self.run_preparation(command, timeout=0.2, max_output_bytes=4096)
            time.sleep(1)
            self.assertFalse(marker.exists())

    @unittest.skipUnless(os.name == "posix", "POSIX process-group assertion")
    def test_output_limit_terminates_the_process_group(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            marker = Path(temporary) / "grandchild-survived"
            grandchild = (
                "import pathlib, time; "
                "time.sleep(0.75); "
                f"pathlib.Path({str(marker)!r}).write_text('survived')"
            )
            command = [
                sys.executable,
                "-c",
                (
                    "import os, subprocess, sys, time; "
                    f"subprocess.Popen([sys.executable, '-c', {grandchild!r}]); "
                    "os.write(1, b'x' * 65536); "
                    "time.sleep(60)"
                ),
            ]

            with self.assertRaises(PreparationOutputLimitError):
                self.run_preparation(command, timeout=5, max_output_bytes=4096)
            time.sleep(1)
            self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
