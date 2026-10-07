from __future__ import annotations

# ruff: noqa: E402

import os
import re
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests.rookery.support import ROOKERY_ROOT

LIB = ROOKERY_ROOT / "lib"
if str(LIB) not in sys.path:
    sys.path.insert(0, str(LIB))
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

from rookery.portable.cli import build_parser, cmd_go, cmd_prepare
from rookery.portable.util import (
    PRIVATE_MODE_ERROR,
    ensure_private_dir,
    ensure_private_file,
    file_lock,
    private_storage_preflight,
)

PRIVATE_MODE_PATTERN = re.escape(PRIVATE_MODE_ERROR)


@unittest.skipUnless(os.name == "posix", "requires POSIX filesystem modes")
class PrivacyEnforcementTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def assert_mode(self, path: Path, expected: int) -> None:
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), expected, path)

    def test_ext4_preflight_proves_and_cleans_private_storage(self) -> None:
        state = self.root / "state"
        with mock.patch("rookery.portable.util.os.fsync", wraps=os.fsync) as fsync:
            private_storage_preflight(state)

        self.assert_mode(state, 0o700)
        self.assertEqual(list(state.iterdir()), [])
        self.assertGreaterEqual(fsync.call_count, 4)

    def test_noop_fchmod_and_public_fstat_fail_closed(self) -> None:
        directory = self.root / "public"
        directory.mkdir()
        directory.chmod(0o777)
        public_directory = os.stat_result((stat.S_IFDIR | 0o777,) + (0,) * 9)

        with (
            mock.patch("rookery.portable.util.os.fchmod", return_value=None),
            mock.patch(
                "rookery.portable.util.os.fstat", return_value=public_directory
            ),
            self.assertRaisesRegex(OSError, PRIVATE_MODE_PATTERN),
        ):
            ensure_private_dir(directory)

    def test_noop_fchmod_for_public_file_fails_closed(self) -> None:
        private_file = self.root / "public.bin"
        private_file.write_bytes(b"preserve these bytes")
        private_file.chmod(0o666)

        with (
            mock.patch("rookery.portable.util.os.fchmod", return_value=None),
            self.assertRaisesRegex(OSError, PRIVATE_MODE_PATTERN),
        ):
            ensure_private_file(private_file)

    def test_noop_chmod_for_public_directory_fails_closed(self) -> None:
        directory = self.root / "fallback-public"
        directory.mkdir()
        directory.chmod(0o777)

        with (
            mock.patch(
                "rookery.portable.util._descriptor_walk_supported", return_value=False
            ),
            mock.patch("rookery.portable.util.os.chmod", return_value=None),
            self.assertRaisesRegex(OSError, PRIVATE_MODE_PATTERN),
        ):
            ensure_private_dir(directory)

    def test_preflight_rejects_non_posix_or_unsupported_storage(self) -> None:
        with (
            mock.patch("rookery.portable.util.os.name", "nt"),
            self.assertRaisesRegex(OSError, PRIVATE_MODE_PATTERN),
        ):
            private_storage_preflight(self.root / "state")


class PrivacyCliBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_go_mutations_fail_before_runtime_or_store_work(self) -> None:
        for command in ([], ["resume"]):
            with self.subTest(command=command):
                args = build_parser().parse_args(["go", *command])
                with (
                    mock.patch(
                        "rookery.portable.cli.workspace_root", return_value=self.root
                    ),
                    mock.patch(
                        "rookery.portable.cli.resolve_launch_gate",
                        return_value=mock.sentinel.launch_gate,
                    ),
                    mock.patch(
                        "rookery.portable.cli.private_storage_preflight",
                        side_effect=OSError(PRIVATE_MODE_ERROR),
                    ),
                    mock.patch("rookery.portable.cli.ensure_runtime_dirs") as runtime,
                    mock.patch("rookery.portable.cli.load_context") as load_context,
                    self.assertRaisesRegex(OSError, PRIVATE_MODE_PATTERN),
                ):
                    cmd_go(args)
                runtime.assert_not_called()
                load_context.assert_not_called()

    def test_go_stop_fails_before_runtime_or_store_work(self) -> None:
        state = self.root / "state"
        state.mkdir()
        (state / "events.sqlite3").touch()
        args = build_parser().parse_args(["go", "stop"])
        with (
            mock.patch("rookery.portable.cli.workspace_root", return_value=self.root),
            mock.patch(
                "rookery.portable.cli.launch_binding_integrity_error",
                return_value=None,
            ),
            mock.patch(
                "rookery.portable.cli.private_storage_preflight",
                side_effect=OSError(PRIVATE_MODE_ERROR),
            ),
            mock.patch("rookery.portable.cli.ensure_runtime_dirs") as runtime,
            mock.patch("rookery.portable.cli._load_stop_context") as load_context,
            self.assertRaisesRegex(OSError, PRIVATE_MODE_PATTERN),
        ):
            cmd_go(args)
        runtime.assert_not_called()
        load_context.assert_not_called()

    def test_prepare_apply_fails_before_runtime_or_preparation(self) -> None:
        args = build_parser().parse_args(["prepare", "apply"])
        with (
            mock.patch("rookery.portable.cli.workspace_root", return_value=self.root),
            mock.patch(
                "rookery.portable.cli.resolve_launch_gate",
                return_value=mock.sentinel.launch_gate,
            ),
            mock.patch(
                "rookery.portable.cli.private_storage_preflight",
                side_effect=OSError(PRIVATE_MODE_ERROR),
            ),
            mock.patch("rookery.portable.cli.ensure_runtime_dirs") as runtime,
            mock.patch("rookery.portable.cli.prepare") as prepare,
            self.assertRaisesRegex(OSError, PRIVATE_MODE_PATTERN),
        ):
            cmd_prepare(args)
        runtime.assert_not_called()
        prepare.assert_not_called()

    def test_status_paths_are_pure_without_state(self) -> None:
        go_status = build_parser().parse_args(["go", "status"])
        prepare_status = build_parser().parse_args(["prepare", "status"])
        with mock.patch("rookery.portable.cli.workspace_root", return_value=self.root):
            self.assertEqual(cmd_go(go_status), 0)
            self.assertEqual(cmd_prepare(prepare_status), 1)

        self.assertFalse((self.root / "state").exists())

    def test_lock_reports_platform_boundary_without_import_failure(self) -> None:
        with (
            mock.patch("rookery.portable.util.fcntl", None),
            self.assertRaisesRegex(OSError, PRIVATE_MODE_PATTERN),
            file_lock(self.root / "state" / "mutation.lock"),
        ):
            self.fail("unsupported lock backend unexpectedly entered context")


if __name__ == "__main__":
    unittest.main(verbosity=2)
