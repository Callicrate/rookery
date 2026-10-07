from __future__ import annotations

import builtins
import importlib.util
import json
import os
import runpy
import stat
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

from tests.rookery.test_acceptance_campaign import make_deployed_workspace


@unittest.skipUnless(os.name == "posix", "requires POSIX filesystem semantics")
class GuacContactSheetBoundTests(unittest.TestCase):
    def setUp(self) -> None:
        self.original_umask = os.umask(0o022)
        self.workspace = make_deployed_workspace("manual")
        self.root = Path(self.workspace.name)
        self.helper = self.root / "extensions/guacamole/bin/guac-contact-sheet"
        self.downloads = self.root / "downloads"
        self.downloads.mkdir(exist_ok=True)
        self.source = self.downloads / "stream"
        self.source.mkdir()
        self.environment = {
            **os.environ,
            "PYTHONPATH": str(self.root / "lib"),
            "PYTHONDONTWRITEBYTECODE": "1",
        }

    def tearDown(self) -> None:
        try:
            self.workspace.cleanup()
        finally:
            os.umask(self.original_umask)

    def run_helper(
        self,
        outdir: Path,
        *arguments: str,
        environment: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                str(self.helper),
                "--dir",
                str(self.source),
                "--outdir",
                str(outdir),
                *arguments,
            ],
            cwd=self.root,
            env=environment or self.environment,
            text=True,
            capture_output=True,
            timeout=15,
            check=False,
        )

    def assert_mode(self, path: Path, expected: int) -> None:
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), expected, path)

    def assert_limited_failure(self, outdir: Path, reason: str) -> None:
        manifest = json.loads((outdir / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["status"], "input_limit")
        self.assertEqual(manifest["reason"], reason)
        self.assertFalse((outdir / "contact_sheet.jpg").exists())
        self.assertEqual(list(outdir.glob(".contact-sheet.*")), [])
        self.assert_mode(outdir, 0o700)
        self.assert_mode(outdir / "manifest.json", 0o600)

    def write_fake_montage(self, body: str) -> tuple[Path, dict[str, str]]:
        fake_bin = (
            Path(self.workspace.fake_temporary.name)
            / f"fake-bin-{len(list(Path(self.workspace.fake_temporary.name).glob('fake-bin-*')))}"
        )
        fake_bin.mkdir()
        montage = fake_bin / "montage"
        montage.write_text("#!/usr/bin/python3\n" + body, encoding="utf-8")
        montage.chmod(0o755)
        environment = {
            **self.environment,
            "PATH": f"{fake_bin}:/usr/bin:/bin",
        }
        return montage, environment

    def test_discovery_count_and_source_file_bytes_fail_before_render(self) -> None:
        for index in range(5):
            (self.source / f"frame-{index}.png").write_bytes(b"image")
        count_out = self.root / "evidence/guac/count"
        count = self.run_helper(
            count_out,
            "--max-discovered-files",
            "3",
        )
        self.assertEqual(count.returncode, 2, count.stderr)
        self.assert_limited_failure(count_out, "discovered_files")

        isolated = self.downloads / "oversize-stream"
        isolated.mkdir()
        (isolated / "large.png").write_bytes(b"x" * 65)
        self.source = isolated
        size_out = self.root / "evidence/guac/file-size"
        oversized = self.run_helper(size_out, "--max-file-bytes", "64")
        self.assertEqual(oversized.returncode, 2, oversized.stderr)
        self.assert_limited_failure(size_out, "file_bytes")

        aggregate = self.downloads / "aggregate-stream"
        aggregate.mkdir()
        (aggregate / "one.png").write_bytes(b"a" * 40)
        (aggregate / "two.png").write_bytes(b"b" * 40)
        self.source = aggregate
        aggregate_out = self.root / "evidence/guac/source-size"
        aggregate_result = self.run_helper(
            aggregate_out,
            "--max-file-bytes",
            "64",
            "--max-source-bytes",
            "64",
        )
        self.assertEqual(aggregate_result.returncode, 2, aggregate_result.stderr)
        self.assert_limited_failure(aggregate_out, "source_bytes")

    def test_last_above_fixed_maximum_is_rejected_without_output(self) -> None:
        outdir = self.root / "evidence/guac/max-last"
        result = self.run_helper(outdir, "--last", "65")
        self.assertEqual(result.returncode, 2)
        self.assertFalse(outdir.exists())

    def test_pillow_rejects_decoded_pixel_bomb_before_load(self) -> None:
        if importlib.util.find_spec("PIL") is None:
            self.skipTest("Pillow is optional; ImageMagick/copy fallback remains available")
        from PIL import Image

        image = Image.new("RGB", (100, 100), "white")
        image.save(self.source / "bomb.png")
        image.close()
        outdir = self.root / "evidence/guac/pixel-bomb"

        result = self.run_helper(outdir, "--max-pixels", "100")

        self.assertEqual(result.returncode, 2, result.stderr)
        self.assert_limited_failure(outdir, "decoded_pixels")

    def test_no_tool_copy_fallback_streams_within_aggregate_cap(self) -> None:
        for index in range(3):
            (self.source / f"copy-{index}.png").write_bytes(bytes([index]) * 4)
        namespace = runpy.run_path(str(self.helper))
        namespace["ROOT"] = self.root
        namespace["main"].__globals__["ROOT"] = self.root
        outdir = self.root / "evidence/guac/copy-success"
        real_import = builtins.__import__

        def without_pillow(name, *args, **kwargs):
            if name == "PIL" or name.startswith("PIL."):
                raise ImportError("Pillow unavailable fixture")
            return real_import(name, *args, **kwargs)

        with (
            mock.patch.object(
                sys,
                "argv",
                [
                    "guac-contact-sheet",
                    "--dir",
                    str(self.source),
                    "--outdir",
                    str(outdir),
                    "--max-output-bytes",
                    "16",
                ],
            ),
            mock.patch("builtins.__import__", side_effect=without_pillow),
            mock.patch.object(namespace["shutil"], "which", return_value=None),
        ):
            self.assertEqual(namespace["main"](), 0)

        copied = sorted(outdir.glob("copy-*.png"))
        self.assertEqual(len(copied), 3)
        self.assertLessEqual(sum(path.stat().st_size for path in copied), 16)
        for path in copied:
            self.assert_mode(path, 0o600)

        failure_out = self.root / "evidence/guac/copy-limit"
        os.umask(0o022)
        with (
            mock.patch.object(
                sys,
                "argv",
                [
                    "guac-contact-sheet",
                    "--dir",
                    str(self.source),
                    "--outdir",
                    str(failure_out),
                    "--max-output-bytes",
                    "5",
                ],
            ),
            mock.patch("builtins.__import__", side_effect=without_pillow),
            mock.patch.object(namespace["shutil"], "which", return_value=None),
        ):
            self.assertEqual(namespace["main"](), 2)
        self.assert_limited_failure(failure_out, "fallback_output_bytes")
        self.assertEqual(list(failure_out.glob("copy-*.png")), [])

    def test_imagemagick_timeout_and_failure_remove_partial_output(self) -> None:
        (self.source / "invalid.png").write_bytes(b"invalid image")
        _montage, timeout_env = self.write_fake_montage(
            "import pathlib,sys,time\n"
            "pathlib.Path(sys.argv[-1]).write_bytes(b'partial')\n"
            "time.sleep(5)\n"
        )
        timeout_out = self.root / "evidence/guac/tool-timeout"
        timed_out = self.run_helper(
            timeout_out,
            "--tool-timeout",
            "1",
            environment=timeout_env,
        )
        self.assertEqual(timed_out.returncode, 2, timed_out.stderr)
        timeout_manifest = json.loads(
            (timeout_out / "manifest.json").read_text(encoding="utf-8")
        )
        self.assertEqual(timeout_manifest["status"], "tool_timeout")
        self.assertFalse((timeout_out / "contact_sheet.jpg").exists())
        self.assertEqual(list(timeout_out.glob(".contact-sheet.*")), [])

        _montage, failure_env = self.write_fake_montage(
            "import pathlib,sys\n"
            "pathlib.Path(sys.argv[-1]).write_bytes(b'partial')\n"
            "raise SystemExit(7)\n"
        )
        failure_out = self.root / "evidence/guac/tool-failure"
        failed = self.run_helper(failure_out, environment=failure_env)
        self.assertEqual(failed.returncode, 2, failed.stderr)
        failure_manifest = json.loads(
            (failure_out / "manifest.json").read_text(encoding="utf-8")
        )
        self.assertEqual(failure_manifest["status"], "tool_failed")
        self.assertEqual(failure_manifest["returncode"], 7)
        self.assertFalse((failure_out / "contact_sheet.jpg").exists())
        self.assertEqual(list(failure_out.glob(".contact-sheet.*")), [])

    def test_imagemagick_resource_argv_and_output_limit(self) -> None:
        (self.source / "invalid.png").write_bytes(b"invalid image")
        argv_log = self.downloads / "montage-argv.json"
        _montage, environment = self.write_fake_montage(
            "import json,os,pathlib,sys\n"
            f"pathlib.Path({str(argv_log)!r}).write_text(json.dumps(sys.argv[1:]))\n"
            "pathlib.Path(sys.argv[-1]).write_bytes(b'x' * 100)\n"
            "os.chmod(sys.argv[-1], 0o666)\n"
        )
        outdir = self.root / "evidence/guac/tool-output-limit"

        result = self.run_helper(
            outdir,
            "--max-output-bytes",
            "16",
            environment=environment,
        )

        self.assertEqual(result.returncode, 2, result.stderr)
        self.assert_limited_failure(outdir, "output_bytes")
        argv = json.loads(argv_log.read_text(encoding="utf-8"))
        for resource in ("memory", "map", "disk", "area", "file", "time"):
            self.assertIn(resource, argv)


if __name__ == "__main__":
    unittest.main(verbosity=2)
