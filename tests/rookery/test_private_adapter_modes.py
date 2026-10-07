from __future__ import annotations

import json
import os
import runpy
import stat
import subprocess
import sys
import types
import unittest
from pathlib import Path
from unittest import mock

from tests.rookery.test_acceptance_campaign import make_deployed_workspace


ASSIGNED_SCRIPTS = (
    "adapters/immersive/bin/immersive-cookie-filter",
    "adapters/immersive/bin/immersive-cluster-capture",
    "adapters/immersive/bin/immersive-selected-lab-refresh",
)


@unittest.skipUnless(os.name == "posix", "requires POSIX filesystem modes")
class PrivateAdapterModeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.original_umask = os.umask(0o022)
        self.workspace = make_deployed_workspace("manual")
        self.root = Path(self.workspace.name)
        self.environment = {
            **self.workspace.bootstrap.environment,
            "PYTHONPATH": str(self.root / "lib"),
            "PYTHONDONTWRITEBYTECODE": "1",
        }

    def tearDown(self) -> None:
        try:
            self.workspace.cleanup()
        finally:
            os.umask(self.original_umask)

    def assert_mode(self, path: Path, expected: int) -> None:
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), expected, path)

    def assert_private_tree(self, root: Path) -> None:
        self.assert_mode(root, 0o700)
        for path in root.rglob("*"):
            self.assertFalse(path.is_symlink(), path)
            if path.is_dir():
                self.assert_mode(path, 0o700)
            elif path.is_file():
                self.assert_mode(path, 0o600)

    def snapshot_tree(self, root: Path) -> tuple[tuple[str, str, int, bytes], ...]:
        snapshot = []
        for path in [root, *sorted(root.rglob("*"))]:
            relative = "." if path == root else path.relative_to(root).as_posix()
            mode = stat.S_IMODE(path.lstat().st_mode)
            if path.is_symlink():
                snapshot.append((relative, "symlink", mode, os.readlink(path).encode()))
            elif path.is_dir():
                snapshot.append((relative, "directory", mode, b""))
            elif path.is_file():
                snapshot.append((relative, "file", mode, path.read_bytes()))
            else:
                snapshot.append((relative, "other", mode, b""))
        return tuple(snapshot)

    def intermediate_link_outdir(self, name: str) -> tuple[Path, Path]:
        outside = self.download_input("outside") / name
        outside.mkdir(parents=True)
        outside.chmod(0o777)
        sentinel = outside / "sentinel.bin"
        sentinel.write_bytes(b"outside bytes must remain exact")
        sentinel.chmod(0o666)
        parent = self.root / "platform" / "cookies" / name
        parent.mkdir(parents=True)
        link = parent / "link"
        link.symlink_to(outside, target_is_directory=True)
        return link / "child", outside

    def existing_outdir(self, name: str, files: tuple[str, ...]) -> Path:
        outdir = self.root / "evidence" / name
        outdir.mkdir(parents=True)
        outdir.chmod(0o777)
        for item in files:
            path = outdir / item
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"old evidence")
            path.chmod(0o666)
        return outdir

    def immersive_outdir(self, name: str) -> Path:
        return self.root / "evidence" / "immersive" / name

    def cookie_outdir(self, name: str) -> Path:
        return self.root / "platform" / "cookies" / name

    def download_input(self, name: str) -> Path:
        downloads = self.root / "downloads"
        downloads.mkdir(exist_ok=True)
        return downloads / name

    @staticmethod
    def relax_private_tree(root: Path) -> None:
        for path in [root, *root.rglob("*")]:
            if path.is_dir():
                path.chmod(0o777)
            elif path.is_file():
                path.chmod(0o666)

    def guac_outdir(self, name: str) -> Path:
        return self.root / "evidence" / "guac" / name

    def guac_intermediate_link_outdir(self, name: str) -> tuple[Path, Path]:
        outside = self.download_input("outside") / name
        outside.mkdir(parents=True)
        outside.chmod(0o777)
        sentinel = outside / "sentinel.bin"
        sentinel.write_bytes(b"outside bytes must remain exact")
        sentinel.chmod(0o666)
        parent = self.root / "evidence" / "guac" / name
        parent.mkdir(parents=True)
        link = parent / "link"
        link.symlink_to(outside, target_is_directory=True)
        return link / "child", outside

    def run_helper(self, relative: str, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(self.root / relative), *arguments],
            cwd=self.root,
            env=self.environment,
            text=True,
            capture_output=True,
            timeout=30,
        )

    def test_cookie_filter_fresh_and_existing_outputs_are_private(self) -> None:
        cookie_file = self.download_input("cookies.json")
        cookie_file.write_text(
            json.dumps(
                {
                    "cookies": [
                        {
                            "name": "session",
                            "value": "dummy-value",
                            "domain": "fixture.invalid",
                            "path": "/",
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        for name, preexisting in (("cookie-fresh", False), ("cookie-existing", True)):
            outdir = self.cookie_outdir(name)
            arguments = (
                "adapters/immersive/bin/immersive-cookie-filter",
                "--file",
                str(cookie_file),
                "--domains",
                "fixture.invalid",
                "--outdir",
                str(outdir),
            )
            if preexisting:
                initial = self.run_helper(*arguments)
                self.assertEqual(initial.returncode, 0, initial.stderr)
                self.relax_private_tree(outdir)
            result = self.run_helper(
                *arguments,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assert_private_tree(outdir)

    def test_cookie_filter_rejects_count_and_input_byte_limits(self) -> None:
        netscape = self.download_input("many-cookies.txt")
        with netscape.open("w", encoding="utf-8") as handle:
            for index in range(50_000):
                handle.write(
                    f".fixture.invalid\tTRUE\t/\tFALSE\t0\tname{index}\tdummy{index}\n"
                )
        count_out = self.cookie_outdir("cookie-count-limit")
        count = self.run_helper(
            "adapters/immersive/bin/immersive-cookie-filter",
            "--file",
            str(netscape),
            "--outdir",
            str(count_out),
            "--max-input-bytes",
            str(4 * 1024 * 1024),
            "--max-cookies",
            "1000",
        )
        self.assertEqual(count.returncode, 4, count.stderr)
        count_summary = json.loads((count_out / "summary.json").read_text())
        self.assertEqual(count_summary["status"], "input_limit")
        self.assertEqual(count_summary["reason"], "cookie_count")
        self.assertFalse((count_out / "cookie-header.txt").exists())
        self.assertFalse((count_out / "selected-cookies.json").exists())
        self.assertNotIn("dummy999", count.stderr + count.stdout)

        oversized = self.download_input("oversized-cookies.txt")
        oversized.write_bytes(b"x" * 129)
        size_out = self.cookie_outdir("cookie-input-limit")
        size = self.run_helper(
            "adapters/immersive/bin/immersive-cookie-filter",
            "--file",
            str(oversized),
            "--outdir",
            str(size_out),
            "--max-input-bytes",
            "128",
        )
        self.assertEqual(size.returncode, 4, size.stderr)
        size_summary = json.loads((size_out / "summary.json").read_text())
        self.assertEqual(size_summary["reason"], "input_bytes")
        self.assert_private_tree(size_out)

        fifo = self.download_input("cookie-input.fifo")
        os.mkfifo(fifo)
        fifo_out = self.cookie_outdir("cookie-type-limit")
        special = self.run_helper(
            "adapters/immersive/bin/immersive-cookie-filter",
            "--file",
            str(fifo),
            "--outdir",
            str(fifo_out),
        )
        self.assertEqual(special.returncode, 4, special.stderr)
        special_summary = json.loads((fifo_out / "summary.json").read_text())
        self.assertEqual(special_summary["reason"], "input_type")
        self.assert_private_tree(fifo_out)

    def test_cookie_filter_rejects_field_header_and_output_expansion(self) -> None:
        helper = "adapters/immersive/bin/immersive-cookie-filter"
        secret = "secret-value-must-not-appear"
        cases = (
            (
                "name",
                {"cookies": [{"name": "n" * 9, "value": secret}]},
                ("--max-name-bytes", "8"),
                "cookie_name_bytes",
            ),
            (
                "value",
                {"cookies": [{"name": "session", "value": secret}]},
                ("--max-value-bytes", "8"),
                "cookie_value_bytes",
            ),
            (
                "header",
                {
                    "cookies": [
                        {"name": "one", "value": "12345678"},
                        {"name": "two", "value": "12345678"},
                    ]
                },
                ("--max-header-bytes", "16"),
                "header_bytes",
            ),
            (
                "output",
                {"cookies": [{"name": "session", "value": "x" * 5000}]},
                (
                    "--max-value-bytes",
                    "6000",
                    "--max-header-bytes",
                    "8192",
                    "--max-output-bytes",
                    "4096",
                ),
                "output_bytes",
            ),
        )
        for name, payload, limits, reason in cases:
            with self.subTest(name=name):
                cookie_file = self.download_input(f"cookie-{name}.json")
                cookie_file.write_text(json.dumps(payload), encoding="utf-8")
                outdir = self.cookie_outdir(f"cookie-{name}-limit")
                result = self.run_helper(
                    helper,
                    "--file",
                    str(cookie_file),
                    "--outdir",
                    str(outdir),
                    *limits,
                )
                self.assertEqual(result.returncode, 4, result.stderr)
                summary_text = (outdir / "summary.json").read_text(encoding="utf-8")
                summary = json.loads(summary_text)
                self.assertEqual(summary["status"], "input_limit")
                self.assertEqual(summary["reason"], reason)
                self.assertNotIn(secret, result.stdout + result.stderr + summary_text)
                self.assertFalse((outdir / "cookie-header.txt").exists())
                self.assertFalse((outdir / "selected-cookies.json").exists())
                self.assert_private_tree(outdir)

    def test_immersive_refresh_fresh_and_existing_outputs_are_private(self) -> None:
        for name, preexisting in (("refresh-fresh", False), ("refresh-existing", True)):
            outdir = self.immersive_outdir(name)
            arguments = (
                "adapters/immersive/bin/immersive-selected-lab-refresh",
                "--dry-run",
                "--outdir",
                str(outdir),
            )
            if preexisting:
                initial = self.run_helper(*arguments)
                self.assertEqual(initial.returncode, 2, initial.stderr)
                self.relax_private_tree(outdir)
            result = self.run_helper(*arguments)
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assert_private_tree(outdir)

    def test_mocked_cluster_writer_migrates_existing_outputs(self) -> None:
        cluster = runpy.run_path(
            str(self.root / "adapters/immersive/bin/immersive-cluster-capture")
        )
        cluster_globals = cluster["main"].__globals__
        cluster_globals["ROOT"] = self.root
        with mock.patch.dict(os.environ, self.environment, clear=True):
            binding = cluster_globals["load_canonical_compiled_scope"](self.root)
        cluster_globals["scope_guard_url"] = mock.Mock(return_value=binding)
        cluster_globals["scoped_connection_plan"] = mock.Mock(return_value=object())
        cluster_globals["connect_scoped_stream"] = mock.Mock(return_value=mock.Mock())
        fake_websocket = types.SimpleNamespace(
            create_connection=mock.Mock(side_effect=RuntimeError("dummy offline"))
        )
        for name, preexisting in (("cluster-fresh", False), ("cluster-existing", True)):
            outdir = self.immersive_outdir(name)
            if preexisting:
                os.umask(0o022)
                with (
                    mock.patch.object(
                        sys,
                        "argv",
                        [
                            "immersive-cluster-capture",
                            "--url",
                            "wss://fixture.invalid/cable",
                            "--outdir",
                            str(outdir),
                        ],
                    ),
                    mock.patch.dict(sys.modules, {"websocket": fake_websocket}),
                    mock.patch.dict(os.environ, self.environment, clear=True),
                ):
                    self.assertEqual(cluster["main"](), 4)
                self.relax_private_tree(outdir)
            os.umask(0o022)
            with (
                mock.patch.object(
                    sys,
                    "argv",
                    [
                        "immersive-cluster-capture",
                        "--url",
                        "wss://fixture.invalid/cable",
                        "--outdir",
                        str(outdir),
                    ],
                ),
                mock.patch.dict(sys.modules, {"websocket": fake_websocket}),
                mock.patch.dict(os.environ, self.environment, clear=True),
            ):
                self.assertEqual(cluster["main"](), 4)
            self.assert_private_tree(outdir)

    def test_intermediate_symlink_rejected_before_immersive_output(self) -> None:
        outdir, outside = self.intermediate_link_outdir("immersive-link")
        before = self.snapshot_tree(outside)
        cookie_file = self.download_input("dummy-cookies.json")
        cookie_file.write_text(
            json.dumps(
                {
                    "cookies": [
                        {
                            "name": "session",
                            "value": "dummy-value",
                            "domain": "fixture.invalid",
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )

        result = self.run_helper(
            "adapters/immersive/bin/immersive-cookie-filter",
            "--file",
            str(cookie_file),
            "--outdir",
            str(outdir),
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.snapshot_tree(outside), before)

    def test_intermediate_symlink_rejected_before_guac_external_tool(self) -> None:
        outdir, outside = self.guac_intermediate_link_outdir("guac-link")
        before = self.snapshot_tree(outside)
        executed = self.root / "external-tool-ran"
        argv = [
            sys.executable,
            "-c",
            "import pathlib,sys; pathlib.Path(sys.argv[1]).write_text('ran')",
            str(executed),
        ]
        environment = {
            **self.environment,
            "GUAC_REMOTE_FILE_EXPORT_ARGV": json.dumps(argv),
        }

        result = subprocess.run(
            [
                str(self.root / "extensions/guacamole/bin/guac-export-file"),
                "/remote/dummy.log",
                "--method",
                "configured",
                "--outdir",
                str(outdir),
            ],
            cwd=self.root,
            env=environment,
            text=True,
            capture_output=True,
            timeout=30,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(executed.exists())
        self.assertEqual(self.snapshot_tree(outside), before)

    def test_guacamole_dummy_modes_harden_fresh_outputs(self) -> None:
        cases = (
            (
                "extensions/guacamole/bin/guac-contact-sheet",
                ("--dir", str(self.root / "missing-stream")),
                1,
                ("manifest.json", "README.txt"),
            ),
            (
                "extensions/guacamole/bin/guac-export-file",
                ("/remote/dummy.log",),
                2,
                ("request.json", "EXPORT_PLAN.md", "summary.json"),
            ),
            (
                "extensions/guacamole/bin/guac-ssh-exec",
                ("echo dummy", "--dry-run"),
                0,
                ("request.json", "typed.txt"),
            ),
            (
                "extensions/guacamole/bin/guac-terminal-capture",
                ("--no-lease",),
                0,
                (
                    "command.txt",
                    "transcript.txt",
                    "manual_transcript_template.md",
                    "manifest.json",
                ),
            ),
            (
                "extensions/guacamole/bin/guac-remote-log-export",
                ("/remote/dummy.log",),
                2,
                (
                    "exported.bin",
                    "guac-export-file.stdout.log",
                    "guac-export-file.stderr.log",
                    "manual_transcript_template.md",
                    "manifest.json",
                ),
            ),
        )
        for relative, arguments, expected, _output_files in cases:
            stem = Path(relative).name
            outdir = self.guac_outdir(f"{stem}-fresh")
            result = self.run_helper(relative, *arguments, "--outdir", str(outdir))
            self.assertEqual(result.returncode, expected, result.stderr)
            self.assert_private_tree(outdir)

    def test_contact_sheet_chmods_external_tool_output(self) -> None:
        source = self.download_input("stream")
        source.mkdir()
        (source / "frame.png").write_bytes(b"not a real image")
        fake_bin = Path(self.workspace.fake_temporary.name) / "contact-fake-bin"
        fake_bin.mkdir()
        montage = fake_bin / "montage"
        montage.write_text(
            "#!/bin/sh\nfor item do destination=$item; done\nprintf external > \"$destination\"\nchmod 666 \"$destination\"\n",
            encoding="utf-8",
        )
        montage.chmod(0o755)
        outdir = self.guac_outdir("contact-external")
        environment = {
            **self.environment,
            "PATH": f"{fake_bin}:/usr/bin:/bin",
        }
        result = subprocess.run(
            [
                str(self.root / "extensions/guacamole/bin/guac-contact-sheet"),
                "--dir",
                str(source),
                "--outdir",
                str(outdir),
            ],
            cwd=self.root,
            env=environment,
            text=True,
            capture_output=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((outdir / "contact_sheet.jpg").read_bytes(), b"external")
        self.assert_private_tree(outdir)

    def test_configured_export_chmods_additional_external_tool_output(self) -> None:
        outdir = self.guac_outdir("export-external")
        argv = [
            sys.executable,
            "-c",
            (
                "import os,pathlib,sys; "
                "path=pathlib.Path(sys.argv[1])/'tool.log'; "
                "path.write_text('tool evidence'); path.chmod(0o666); "
                "os.write(1,b'exported bytes')"
            ),
            "{outdir}",
        ]
        environment = {
            **self.environment,
            "GUAC_REMOTE_FILE_EXPORT_ARGV": json.dumps(argv),
        }
        result = subprocess.run(
            [
                str(self.root / "extensions/guacamole/bin/guac-export-file"),
                "/remote/dummy.log",
                "--method",
                "configured",
                "--outdir",
                str(outdir),
            ],
            cwd=self.root,
            env=environment,
            text=True,
            capture_output=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((outdir / "tool.log").read_text(), "tool evidence")
        self.assert_private_tree(outdir)

    def test_permission_migration_preserves_bytes_and_rejects_links(self) -> None:
        for relative in ASSIGNED_SCRIPTS:
            with self.subTest(relative=relative):
                namespace = runpy.run_path(str(self.root / relative))
                family_parts = (
                    ("platform", "cookies")
                    if relative.endswith("immersive-cookie-filter")
                    else ("evidence", "immersive")
                )
                family = self.root.joinpath(*family_parts)
                directory = family / f"migration-{Path(relative).name}"
                output = namespace["prepare_immersive_output"](
                    self.root,
                    family_parts=family_parts,
                    raw_outdir=str(directory),
                    default_label="unused",
                )
                evidence = output.path / "evidence.bin"
                namespace["write_private_output_file"](
                    evidence, b"preserve these bytes"
                )
                directory.chmod(0o777)
                evidence.chmod(0o666)
                before = evidence.read_bytes()

                output.guard()

                self.assert_mode(directory, 0o700)
                self.assert_mode(evidence, 0o600)
                self.assertEqual(evidence.read_bytes(), before)

                target_dir = self.root / "migration" / f"{Path(relative).name}-target"
                target_dir.mkdir(parents=True)
                linked_dir = family / f"{Path(relative).name}-link"
                linked_dir.symlink_to(target_dir, target_is_directory=True)
                with self.assertRaises(namespace["ImmersiveOutputError"]):
                    namespace["prepare_immersive_output"](
                        self.root,
                        family_parts=family_parts,
                        raw_outdir=str(linked_dir),
                        default_label="unused",
                    )

                intermediate_target = (
                    self.root
                    / "migration"
                    / f"{Path(relative).name}-intermediate-target"
                )
                intermediate_target.mkdir()
                intermediate_sentinel = intermediate_target / "sentinel.bin"
                intermediate_sentinel.write_bytes(b"intermediate target unchanged")
                intermediate_sentinel.chmod(0o666)
                intermediate_before = self.snapshot_tree(intermediate_target)
                intermediate_parent = family / f"{Path(relative).name}-intermediate-parent"
                intermediate_parent.mkdir()
                intermediate_link = intermediate_parent / "link"
                intermediate_link.symlink_to(
                    intermediate_target, target_is_directory=True
                )
                with self.assertRaises(namespace["ImmersiveOutputError"]):
                    namespace["prepare_immersive_output"](
                        self.root,
                        family_parts=family_parts,
                        raw_outdir=str(intermediate_link / "child"),
                        default_label="unused",
                    )
                self.assertEqual(
                    self.snapshot_tree(intermediate_target), intermediate_before
                )

                target_file = target_dir / "target.bin"
                target_file.write_bytes(b"outside")
                linked_file = directory / "linked.bin"
                linked_file.symlink_to(target_file)
                with self.assertRaises(namespace["ImmersiveOutputError"]):
                    output.guard()
                self.assertEqual(target_file.read_bytes(), b"outside")
                linked_file.unlink()

                fifo = directory / "fifo"
                os.mkfifo(fifo)
                with self.assertRaises(namespace["ImmersiveOutputError"]):
                    output.guard()

                nondirectory = (
                    family / f"{Path(relative).name}-nondirectory"
                )
                nondirectory.write_bytes(b"not a directory")
                with self.assertRaises(namespace["ImmersiveOutputError"]):
                    namespace["prepare_immersive_output"](
                        self.root,
                        family_parts=family_parts,
                        raw_outdir=str(nondirectory),
                        default_label="unused",
                    )


if __name__ == "__main__":
    unittest.main(verbosity=2)
