from __future__ import annotations

import os
import stat
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path

from tests.rookery.test_preparation_and_isolation import copy_rookery


@unittest.skipUnless(os.name == "posix", "requires POSIX filesystem modes")
class PrivateAnalysisModeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.original_umask = os.umask(0o022)
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        copy_rookery(self.root)
        self.environment = {
            **os.environ,
            "PYTHONPATH": str(self.root / "lib"),
            "PYTHONDONTWRITEBYTECODE": "1",
        }

    def tearDown(self) -> None:
        try:
            self.temporary.cleanup()
        finally:
            os.umask(self.original_umask)

    def assert_mode(self, path: Path, expected: int) -> None:
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), expected, path)

    def snapshot_tree(self, root: Path) -> dict[str, tuple[int, bytes | None]]:
        snapshot: dict[str, tuple[int, bytes | None]] = {}
        for path in [root, *sorted(root.rglob("*"))]:
            rel = "." if path == root else str(path.relative_to(root))
            info = path.lstat()
            snapshot[rel] = (
                stat.S_IMODE(info.st_mode),
                path.read_bytes() if path.is_file() else None,
            )
        return snapshot

    def run_tool(self, *args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(self.root / "bin" / args[0]), *args[1:]],
            cwd=self.root,
            env=env or self.environment,
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )

    def test_custom_private_output_dirs_are_migrated_across_writer_families(self) -> None:
        fixture = self.root / "fixture.txt"
        fixture.write_text("dummy marker\n", encoding="utf-8")
        feed = self.root / "fixture.zip"
        with zipfile.ZipFile(feed, "w") as archive:
            archive.writestr("stops.txt", "stop_id,stop_name\n1,Fixture\n")

        cases = [
            (
                "named-tool-recon",
                ("fixture", "--paths", "fixture.txt"),
                ("safe-rg.stdout", "safe-rg.stderr", "REPORT.md", "manifest.json"),
            ),
            (
                "lab-start-summary",
                ("fixture.txt",),
                ("summary.md", "summary.json"),
            ),
        ]
        for tool, arguments, files in cases:
            with self.subTest(tool=tool):
                outdir = self.root / "custom" / tool
                outdir.mkdir(parents=True)
                outdir.chmod(0o777)
                requested_outdir = str(outdir)
                result = self.run_tool(tool, *arguments, "--outdir", requested_outdir)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assert_mode(outdir, 0o700)
                for name in files:
                    self.assert_mode(outdir / name, 0o600)

    def test_existing_private_candidate_is_tightened_without_rewriting_bytes(self) -> None:
        image = self.root / "fixture.png"
        image.write_bytes(b"not-an-image")
        output = self.root / "custom" / "fixture.transcript.md"
        output.parent.mkdir(parents=True)
        original = b"already recorded\n"
        output.write_bytes(original)
        output.parent.chmod(0o777)
        output.chmod(0o666)

        result = self.run_tool("screenshot-transcribe-template", str(image), "--out", str(output))

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(output.read_bytes(), original)
        self.assert_mode(output.parent, 0o700)
        self.assert_mode(output, 0o600)

    def test_disabled_browser_capture_leaves_no_private_artifacts_under_umask_022(self) -> None:
        browser = self.root / "fixture-browser"
        browser.write_text(
            "#!/usr/bin/env bash\n"
            "for arg in \"$@\"; do case $arg in --screenshot=*) printf dummy > \"${arg#*=}\";; esac; done\n"
            "printf '<html>dummy</html>'\n",
            encoding="utf-8",
        )
        browser.chmod(0o755)
        (self.root / ".env").write_text(
            f"BROWSER_EXECUTABLE={browser}\n", encoding="utf-8"
        )
        scope_check = self.root / "bin" / "scope-check"
        scope_check.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
        scope_check.chmod(0o755)
        result = self.run_tool(
            "playq",
            "https://example.invalid/",
            "--screenshot",
            env={**self.environment, "BROWSER_EXECUTABLE": str(browser)},
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("browser_network_scope_unenforced", result.stderr)
        self.assertFalse((self.root / "captures").exists())

        search_root = self.root / "research" / "search_guard"
        search_root.mkdir(parents=True)
        search_root.chmod(0o777)
        result = self.run_tool("safe-rg", "dummy", "fixture.txt")
        self.assertIn(result.returncode, (0, 1, 2), result.stderr)
        bundle = next(search_root.iterdir())
        self.assert_mode(bundle, 0o700)
        for name in ("stdout.txt", "stderr.txt", "meta.json"):
            self.assert_mode(bundle / name, 0o600)

    def test_symlinked_private_output_targets_are_rejected(self) -> None:
        target = self.root / "outside"
        target.mkdir()
        link = self.root / "linked-output"
        link.symlink_to(target, target_is_directory=True)
        result = self.run_tool("named-tool-recon", "fixture", "--outdir", str(link))
        self.assertNotEqual(result.returncode, 0)

        source = self.root / "fixture.ps1"
        source.write_text("Write-Host dummy", encoding="utf-8")
        sidecar = self.root / "sidecar.json"
        sidecar.symlink_to(self.root / "outside-sidecar")
        result = self.run_tool("powershell-safe-deobfuscate", str(source), "--out", str(sidecar))
        self.assertNotEqual(result.returncode, 0)

    def test_intermediate_symlink_outputs_are_rejected_without_touching_external_tree(self) -> None:
        external = self.root / "external"
        external.mkdir()
        marker = external / "marker.txt"
        marker.write_bytes(b"external bytes must not change")
        marker.chmod(0o640)

        def assert_unchanged(result: subprocess.CompletedProcess[str]) -> None:
            self.assertNotEqual(result.returncode, 0, result.stdout)
            self.assertEqual(self.snapshot_tree(external), before)

        before = self.snapshot_tree(external)
        (self.root / "analysis").symlink_to(external, target_is_directory=True)
        assert_unchanged(self.run_tool("near-miss-retry", "fixture", "FLAG{dummy}"))
        assert_unchanged(self.run_tool("partial-report-new", "fixture"))
        assert_unchanged(self.run_tool("file-triage"))

        (self.root / "research").symlink_to(external, target_is_directory=True)
        assert_unchanged(self.run_tool("safe-rg", "dummy", "README.md"))

        bridge = self.root / "bridge"
        bridge.symlink_to(external, target_is_directory=True)
        assert_unchanged(
            self.run_tool(
                "named-tool-recon",
                "fixture",
                "--outdir",
                str(bridge / "candidate-report"),
            )
        )

        feed = self.root / "fixture.zip"
        with zipfile.ZipFile(feed, "w") as archive:
            archive.writestr("stops.txt", "stop_id,stop_name\n1,Fixture\n")
        assert_unchanged(
            self.run_tool(
                "transit-source",
                "--gtfs",
                str(feed),
                "--outdir",
                str(bridge / "raw-corpus"),
            )
        )

        browser = self.root / "fixture-browser"
        browser.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
        browser.chmod(0o755)
        (self.root / ".env").write_text(
            f"BROWSER_EXECUTABLE={browser}\n", encoding="utf-8"
        )
        scope_check = self.root / "bin" / "scope-check"
        scope_check.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
        scope_check.chmod(0o755)
        (self.root / "captures").symlink_to(external, target_is_directory=True)
        assert_unchanged(
            self.run_tool(
                "playq",
                "https://example.invalid/",
                env={**self.environment, "BROWSER_EXECUTABLE": str(browser)},
            )
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
