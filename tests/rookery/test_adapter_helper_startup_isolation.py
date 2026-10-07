from __future__ import annotations

# ruff: noqa: E402

import os
import json
import re
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tests.rookery.support import ROOKERY_ROOT
from tests.rookery.test_acceptance_campaign import make_workspace
from tests.rookery.test_preparation_and_isolation import copy_rookery


ISOLATED_SHEBANG = b"#!/usr/bin/env -S python3 -I -B"


def ordinary_adapter_helpers(root: Path) -> list[Path]:
    """Discover every shipped Python adapter/extension entrypoint."""

    helpers: list[Path] = []
    for relative_root in ("adapters/immersive/bin", "extensions/guacamole/bin", "extensions/koth/bin"):
        for candidate in sorted((root / relative_root).iterdir()):
            if not candidate.is_file():
                continue
            raw = candidate.read_bytes()
            first_line = raw.splitlines()[0:1]
            if not first_line or b"python" not in first_line[0].lower():
                continue
            helpers.append(candidate)
    return helpers


def poisoned_python_environment(workspace: Path) -> tuple[dict[str, str], Path]:
    """Make every ambient Python startup route observable without persisting it."""

    poison = workspace / "python-startup-poison"
    poison.mkdir()
    marker = workspace / "python-startup-executed"
    payload = (
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text('executed', encoding='utf-8')\n"
    )
    (poison / "sitecustomize.py").write_text(payload, encoding="utf-8")
    (poison / "usercustomize.py").write_text(payload, encoding="utf-8")
    startup = poison / "startup.py"
    startup.write_text(payload, encoding="utf-8")
    user_site = (
        poison
        / "user-base"
        / "lib"
        / f"python{sys.version_info.major}.{sys.version_info.minor}"
        / "site-packages"
    )
    user_site.mkdir(parents=True)
    (user_site / "sitecustomize.py").write_text(payload, encoding="utf-8")
    environment = dict(os.environ)
    environment.update(
        {
            "PYTHONPATH": str(poison),
            "PYTHONHOME": str(poison),
            "PYTHONSTARTUP": str(startup),
            "PYTHONUSERBASE": str(poison / "user-base"),
        }
    )
    return environment, marker


def poison_cwd_library(workspace: Path) -> Path:
    """Create a fake cwd/lib Rookery package whose import is observable."""

    marker = workspace / "cwd-library-imported"
    package = workspace / "lib" / "rookery" / "portable"
    package.mkdir(parents=True)
    (package.parent / "__init__.py").write_text("", encoding="utf-8")
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "environment.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text('imported', encoding='utf-8')\n",
        encoding="utf-8",
    )
    return marker


class AdapterHelperStartupIsolationTests(unittest.TestCase):
    def test_all_ordinary_adapter_helpers_have_exact_script_derived_bootstrap(self) -> None:
        helpers = ordinary_adapter_helpers(ROOKERY_ROOT)
        self.assertEqual(len(helpers), 13, [helper.as_posix() for helper in helpers])
        for helper in helpers:
            relative = helper.relative_to(ROOKERY_ROOT).as_posix()
            raw = helper.read_bytes()
            self.assertEqual(raw.splitlines()[0], ISOLATED_SHEBANG, relative)
            self.assertNotEqual(helper.stat().st_mode & stat.S_IXUSR, 0, relative)
            source = raw.decode("utf-8")
            imports = [
                line
                for line, text in enumerate(source.splitlines(), start=1)
                if re.match(r"\s*(?:from|import)\s+rookery(?:\.|\s)", text)
            ]
            insertions = [
                line
                for line, text in enumerate(source.splitlines(), start=1)
                if "sys.path.insert(" in text
            ]
            self.assertEqual(
                insertions,
                [
                    line
                    for line, text in enumerate(source.splitlines(), start=1)
                    if re.match(
                        r'\s*sys\.path\.insert\(0, str\(SOURCE_ROOT / "lib"\)\)',
                        text,
                    )
                ],
                f"{relative} must insert only SOURCE_ROOT/lib",
            )
            self.assertEqual(len(insertions), 1, relative)
            self.assertLess(insertions[0], min(imports), relative)
            self.assertEqual(
                sum(
                    bool(
                        re.match(
                            r"\s*SOURCE_ROOT = Path\(__file__\)\.resolve\(\)\.parents\[3\]",
                            text,
                        )
                    )
                    for text in source.splitlines()
                ),
                1,
                relative,
            )
            self.assertEqual(
                sum(bool(re.match(r"\s*ROOT = Path\.cwd\(\)", text)) for text in source.splitlines()),
                1,
                relative,
            )
            self.assertNotIn('(ROOT / "lib").is_dir()', source, relative)
            self.assertEqual(
                sum(
                    bool(
                        re.match(
                            r"\s*require_bound_runtime_workspace\(ROOT\)", text
                        )
                    )
                    for text in source.splitlines()
                ),
                1,
                relative,
            )
            self.assertFalse(
                any(re.search(r'(?<![A-Za-z0-9_])ROOT / "bin', text) for text in source.splitlines()),
                relative,
            )

    @unittest.skipUnless(os.name == "posix", "isolated shebang launch requires POSIX")
    def test_every_ordinary_adapter_helper_ignores_poisoned_startup_on_help(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            outer = Path(temporary)
            root = outer / "source"
            copy_rookery(root)
            environment, marker = poisoned_python_environment(outer)
            helpers = ordinary_adapter_helpers(root)
            self.assertEqual(len(helpers), 13)
            for helper in helpers:
                completed = subprocess.run(
                    [str(helper), "--help"],
                    cwd=root,
                    env=environment,
                    text=True,
                    capture_output=True,
                    timeout=30,
                    check=False,
                )
                self.assertEqual(
                    completed.returncode,
                    0,
                    f"{helper.relative_to(root)}: {completed.stderr}",
                )
                self.assertFalse(marker.exists(), helper.name)

    @unittest.skipUnless(os.name == "posix", "script-root symlink probe requires POSIX")
    def test_helpers_never_import_a_caller_owned_cwd_library(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            outer = Path(temporary)
            source = outer / "source"
            workspace = outer / "workspace"
            copy_rookery(source)
            workspace.mkdir()
            marker = poison_cwd_library(workspace)
            helpers = ordinary_adapter_helpers(source)
            self.assertEqual(len(helpers), 13)
            for helper in helpers:
                completed = subprocess.run(
                    [str(helper), "--help"],
                    cwd=workspace,
                    text=True,
                    capture_output=True,
                    timeout=30,
                    check=False,
                )
                self.assertEqual(
                    completed.returncode,
                    0,
                    f"{helper.relative_to(source)}: {completed.stderr}",
                )
                self.assertFalse(marker.exists(), helper.name)

            linked_helper = workspace / "linked-cookie-filter"
            linked_helper.symlink_to(
                source / "adapters" / "immersive" / "bin" / "immersive-cookie-filter"
            )
            linked = subprocess.run(
                [str(linked_helper), "--help"],
                cwd=workspace,
                text=True,
                capture_output=True,
                timeout=30,
                check=False,
            )
            self.assertEqual(linked.returncode, 0, linked.stderr)
            self.assertFalse(marker.exists(), linked.stdout)

    @unittest.skipUnless(os.name == "posix", "script-root operation probe requires POSIX")
    def test_unbound_cwd_cannot_run_fake_scope_helper_or_allocate_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            outer = Path(temporary)
            source = outer / "source"
            workspace = outer / "workspace"
            copy_rookery(source)
            workspace.mkdir()
            marker = poison_cwd_library(workspace)
            fake_bin = workspace / "bin"
            fake_bin.mkdir()
            child_marker = workspace / "fake-scope-check-ran"
            fake_scope_check = fake_bin / "scope-check"
            fake_scope_check.write_text(
                "#!/usr/bin/env bash\n"
                f"printf child > {str(child_marker)!r}\n",
                encoding="utf-8",
            )
            fake_scope_check.chmod(0o755)
            (workspace / "state").mkdir()
            (workspace / "state" / "scope.json").write_text("{}\n", encoding="utf-8")
            (workspace / "cookies.json").write_text(
                json.dumps(
                    [
                        {
                            "name": "session",
                            "value": "fixture-value",
                            "domain": ".fixture.invalid",
                        }
                    ]
                ),
                encoding="utf-8",
            )
            helper = source / "adapters" / "immersive" / "bin" / "immersive-cookie-filter"
            completed = subprocess.run(
                [
                    str(helper),
                    "--file",
                    "cookies.json",
                    "--domains",
                    "fixture.invalid",
                    "--urls",
                    "https://fixture.invalid/",
                    "--json",
                ],
                cwd=workspace,
                text=True,
                capture_output=True,
                timeout=30,
                check=False,
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("runtime_workspace_binding_invalid", completed.stderr)
            self.assertFalse(marker.exists(), completed.stdout)
            self.assertFalse(child_marker.exists(), completed.stderr)
            self.assertFalse((workspace / "platform").exists(), completed.stderr)

    def test_bound_workspace_cookie_filter_operation_preserves_cwd_semantics(self) -> None:
        fixture = make_workspace("fixture")
        try:
            root = Path(fixture.name)
            (root / "downloads").mkdir(exist_ok=True)
            (root / "downloads" / "cookies.json").write_text(
                json.dumps(
                    [
                        {
                            "name": "session",
                            "value": "fixture-value",
                            "domain": ".fixture.invalid",
                        }
                    ]
                ),
                encoding="utf-8",
            )
            helper = root / "adapters" / "immersive" / "bin" / "immersive-cookie-filter"
            completed = subprocess.run(
                [
                    str(helper),
                    "--file",
                    "downloads/cookies.json",
                    "--domains",
                    "fixture.invalid",
                    "--json",
                ],
                cwd=root,
                text=True,
                capture_output=True,
                timeout=30,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn('"status": "ok"', completed.stdout)
            self.assertTrue(
                any((root / "platform" / "cookies").rglob("summary.json")),
                completed.stdout,
            )
        finally:
            fixture.cleanup()

    @unittest.skipUnless(os.name == "posix", "workspace-link probe requires POSIX")
    def test_bound_workspace_symlink_is_canonicalized_but_binding_drift_fails_closed(self) -> None:
        fixture = make_workspace("fixture")
        try:
            root = Path(fixture.name)
            (root / "downloads").mkdir(exist_ok=True)
            (root / "downloads" / "cookies.json").write_text("[]\n", encoding="utf-8")
            helper = root / "adapters" / "immersive" / "bin" / "immersive-cookie-filter"
            with tempfile.TemporaryDirectory() as temporary:
                linked = Path(temporary) / "linked-workspace"
                linked.symlink_to(root, target_is_directory=True)
                through_link = subprocess.run(
                    [str(helper), "--file", "downloads/cookies.json", "--json"],
                    cwd=linked,
                    text=True,
                    capture_output=True,
                    timeout=30,
                    check=False,
                )
            self.assertEqual(through_link.returncode, 0, through_link.stderr)

            (root / ".env").write_text(
                (root / ".env").read_text(encoding="utf-8")
                + "IMMERSIVE_ORIGIN=https://drift.invalid\n",
                encoding="utf-8",
            )
            drifted = subprocess.run(
                [str(helper), "--file", "downloads/cookies.json", "--json"],
                cwd=root,
                text=True,
                capture_output=True,
                timeout=30,
                check=False,
            )
            self.assertNotEqual(drifted.returncode, 0)
            self.assertIn("runtime_workspace_binding_invalid", drifted.stderr)
        finally:
            fixture.cleanup()

    @unittest.skipUnless(os.name == "posix", "isolated interpreter probe requires POSIX")
    def test_isolated_shebang_mode_retains_available_system_optional_dependencies(self) -> None:
        """``-I`` keeps system site packages available while ignoring startup poison."""

        with tempfile.TemporaryDirectory() as temporary:
            environment, marker = poisoned_python_environment(Path(temporary))
            for statement in ("import websocket", "from PIL import Image"):
                completed = subprocess.run(
                    [sys.executable, "-I", "-B", "-c", statement],
                    env=environment,
                    text=True,
                    capture_output=True,
                    timeout=30,
                    check=False,
                )
                if completed.returncode:
                    self.assertIn("ModuleNotFoundError", completed.stderr, statement)
                self.assertFalse(marker.exists(), statement)


if __name__ == "__main__":  # pragma: no cover
    unittest.main(verbosity=2)
