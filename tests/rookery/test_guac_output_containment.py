from __future__ import annotations

import importlib.util
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests.rookery.env_fixtures import replace_env_assignments
from tests.rookery.test_acceptance_campaign import make_deployed_workspace


@unittest.skipUnless(os.name == "posix", "requires descriptor-relative POSIX paths")
class GuacOutputContainmentTests(unittest.TestCase):
    def setUp(self) -> None:
        transport = [sys.executable, "-c", "import os; os.write(1, b'payload')"]

        def prepare(root: Path) -> None:
            replace_env_assignments(
                root,
                {
                    "EVENT_EXTENSIONS": "guacamole",
                    "GUAC_SSH_EXEC_ARGV": json.dumps(transport),
                },
            )

        self.workspace = make_deployed_workspace("manual", prepare=prepare)
        self.outside_temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.workspace.name)
        self.outside = Path(self.outside_temporary.name)
        self.guac_bin = self.root / "extensions" / "guacamole" / "bin"
        self.environment = {
            **os.environ,
            "PYTHONDONTWRITEBYTECODE": "1",
        }

    def tearDown(self) -> None:
        self.outside_temporary.cleanup()
        self.workspace.cleanup()

    def snapshot(self, root: Path) -> tuple[tuple[str, str, bytes], ...]:
        rows: list[tuple[str, str, bytes]] = []
        for path in [root, *sorted(root.rglob("*"))]:
            relative = "." if path == root else path.relative_to(root).as_posix()
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode):
                rows.append((relative, "link", os.readlink(path).encode()))
            elif stat.S_ISDIR(info.st_mode):
                rows.append((relative, "dir", b""))
            elif stat.S_ISREG(info.st_mode):
                rows.append((relative, "file", path.read_bytes()))
            else:
                rows.append((relative, "other", b""))
        return tuple(rows)

    def helper_arguments(self, helper: str, outdir: str) -> list[str]:
        shared = ["--outdir", outdir]
        if helper == "guac-export-file":
            return ["/remote/report.txt", "--method", "configured", *shared]
        if helper == "guac-terminal-capture":
            return ["echo fixture", "--no-lease", *shared]
        if helper == "guac-contact-sheet":
            return ["--dir", str(self.root / "empty-stream"), *shared]
        if helper == "guac-remote-log-export":
            return ["/remote/report.txt", *shared]
        if helper == "guac-ssh-exec":
            return ["echo fixture", "--dry-run", *shared]
        raise AssertionError(helper)

    def run_helper(
        self, helper: str, outdir: str, *, environment: dict[str, str] | None = None
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(self.guac_bin / helper), *self.helper_arguments(helper, outdir)],
            cwd=self.root,
            env=environment or self.environment,
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )

    def test_export_rejects_real_outside_temp_before_configured_transport(self) -> None:
        sentinel = self.outside / "sentinel.txt"
        sentinel.write_text("do not modify", encoding="utf-8")
        marker = self.root / "transport-ran"
        transport = [
            sys.executable,
            "-c",
            "import pathlib,sys; pathlib.Path(sys.argv[1]).write_text('ran')",
            str(marker),
        ]
        before = self.snapshot(self.outside)

        result = self.run_helper(
            "guac-export-file",
            str(self.outside / "outside-export"),
            environment={
                **self.environment,
                "GUAC_REMOTE_FILE_EXPORT_ARGV": json.dumps(transport),
            },
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("workspace-owned evidence/guac", result.stderr)
        self.assertFalse(marker.exists())
        self.assertEqual(self.snapshot(self.outside), before)

    def test_every_helper_rejects_unsafe_output_spellings_without_external_writes(self) -> None:
        sentinel = self.outside / "sentinel.txt"
        sentinel.write_text("outside", encoding="utf-8")
        unsafe = (
            str(self.outside / "absolute-outside"),
            "evidence/guac/./dot",
            "evidence/guac/../parent",
            "evidence\\guac\\backslash",
            "evidence/guac/control\x01",
        )
        for helper in (
            "guac-export-file",
            "guac-terminal-capture",
            "guac-contact-sheet",
            "guac-remote-log-export",
            "guac-ssh-exec",
        ):
            for value in unsafe:
                with self.subTest(helper=helper, outdir=repr(value)):
                    before = self.snapshot(self.outside)
                    result = self.run_helper(helper, value)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(self.snapshot(self.outside), before)

    def test_symlink_hardlink_and_intermediate_swap_are_rejected_before_spawn(self) -> None:
        marker = self.root / "transport-ran"
        transport = [
            sys.executable,
            "-c",
            "import pathlib,sys; pathlib.Path(sys.argv[1]).write_text('ran')",
            str(marker),
        ]
        environment = {
            **self.environment,
            "GUAC_REMOTE_FILE_EXPORT_ARGV": json.dumps(transport),
        }
        family = self.root / "evidence" / "guac"
        linked_parent = family / "linked"
        linked_parent.parent.mkdir(parents=True)
        linked_parent.symlink_to(self.outside, target_is_directory=True)
        before = self.snapshot(self.outside)
        linked = self.run_helper(
            "guac-export-file", "evidence/guac/linked/child", environment=environment
        )
        self.assertNotEqual(linked.returncode, 0)
        self.assertFalse(marker.exists())
        self.assertEqual(self.snapshot(self.outside), before)

        hardlink_outdir = family / "hardlink"
        hardlink_outdir.mkdir()
        external_file = self.outside / "hardlink-sentinel.txt"
        external_file.write_text("exact bytes", encoding="utf-8")
        os.link(external_file, hardlink_outdir / "request.json")
        before = self.snapshot(self.outside)
        hardlink = self.run_helper(
            "guac-export-file", "evidence/guac/hardlink", environment=environment
        )
        self.assertNotEqual(hardlink.returncode, 0)
        self.assertFalse(marker.exists())
        self.assertEqual(self.snapshot(self.outside), before)

        module_path = self.root / "extensions" / "guacamole" / "guac_paths.py"
        specification = importlib.util.spec_from_file_location("guac_paths_race", module_path)
        assert specification is not None and specification.loader is not None
        module = importlib.util.module_from_spec(specification)
        sys.modules[specification.name] = module
        try:
            specification.loader.exec_module(module)
            output = module.resolve_guac_output(
                self.root,
                "evidence/guac/race/child",
                default_parts=("unused",),
            )
            original = module.ensure_private_dir
            inserted = False

            def interpose(path: Path) -> None:
                nonlocal inserted
                original(path)
                if not inserted and Path(path) == family:
                    (family / "race").symlink_to(self.outside, target_is_directory=True)
                    inserted = True

            before = self.snapshot(self.outside)
            with mock.patch.object(module, "ensure_private_dir", side_effect=interpose):
                with self.assertRaises(OSError):
                    output.prepare()
            self.assertTrue(inserted)
            self.assertEqual(self.snapshot(self.outside), before)
        finally:
            sys.modules.pop(specification.name, None)

    def test_contained_custom_output_is_private_no_clobber_and_nested_helpers_stay_contained(self) -> None:
        outdir = self.root / "evidence" / "guac" / "custom"
        transport = [sys.executable, "-c", "import os; os.write(1, b'payload')"]
        exported = self.run_helper(
            "guac-export-file",
            "evidence/guac/custom",
            environment={
                **self.environment,
                "GUAC_REMOTE_FILE_EXPORT_ARGV": json.dumps(transport),
            },
        )
        self.assertEqual(exported.returncode, 0, exported.stderr)
        self.assertEqual((outdir / "report.txt").read_bytes(), b"payload")
        self.assertEqual(stat.S_IMODE(outdir.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((outdir / "report.txt").stat().st_mode), 0o600)

        preserved = (outdir / "request.json").read_bytes()
        rerun = self.run_helper(
            "guac-export-file",
            "evidence/guac/custom",
            environment={
                **self.environment,
                "GUAC_REMOTE_FILE_EXPORT_ARGV": json.dumps(transport),
            },
        )
        self.assertNotEqual(rerun.returncode, 0)
        self.assertEqual((outdir / "request.json").read_bytes(), preserved)

        nested = self.root / "evidence" / "guac" / "terminal-parent"
        terminal = subprocess.run(
            [
                str(self.guac_bin / "guac-terminal-capture"),
                "echo fixture",
                "--no-lease",
                "--outdir",
                "evidence/guac/terminal-parent",
            ],
            cwd=self.root,
            env=self.environment,
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(terminal.returncode, 0, terminal.stderr)
        self.assertTrue((nested / "guac-ssh-exec" / "result.json").is_file())
        self.assertTrue((nested / "guac-ssh-exec" / "contact-sheet").is_dir())
        for path in nested.rglob("*"):
            self.assertTrue(path.is_relative_to(self.root / "evidence" / "guac"))

    def test_existing_owned_regular_tree_is_migrated_without_touching_its_bytes(self) -> None:
        outdir = self.root / "evidence" / "guac" / "migrated"
        outdir.mkdir(parents=True)
        outdir.chmod(0o777)
        prior = outdir / "prior.bin"
        prior.write_bytes(b"preserve exactly")
        prior.chmod(0o666)

        result = self.run_helper("guac-contact-sheet", "evidence/guac/migrated")

        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(prior.read_bytes(), b"preserve exactly")
        self.assertEqual(stat.S_IMODE(outdir.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(prior.stat().st_mode), 0o600)


if __name__ == "__main__":
    unittest.main(verbosity=2)
