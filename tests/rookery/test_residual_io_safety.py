from __future__ import annotations

import os
import runpy
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests.rookery.test_core import make_workspace, manifest_scope_store
from tests.rookery.test_acceptance_campaign import make_deployed_workspace
from tests.rookery.env_fixtures import replace_env_assignments
from rookery.portable import scope as scope_module
from rookery.portable.scoped_transport import ScopedHTTPTransport
from rookery.portable.scope import ScopeAuthorityError


class ResidualIoSafetyTests(unittest.TestCase):
    def test_guac_rejects_dot_symlink_and_oversized_command_file(self) -> None:
        with tempfile.TemporaryDirectory(), tempfile.TemporaryDirectory() as outside:
            fixture = make_deployed_workspace("manual")
            self.addCleanup(fixture.cleanup)
            root = Path(fixture.name)
            helper = root / "extensions/guacamole/bin/guac-ssh-exec"
            common = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}

            dot = subprocess.run(
                [str(helper), "echo safe", "--outdir", ".", "--dry-run"],
                cwd=root,
                env=common,
                text=True,
                capture_output=True,
                timeout=30,
            )
            self.assertNotEqual(dot.returncode, 0)
            self.assertIn("dot or parent component", dot.stderr)

            external = Path(outside) / "external"
            external.mkdir()
            sentinel = external / "sentinel.txt"
            sentinel.write_text("untouched", encoding="utf-8")
            linked = root / "evidence" / "guac" / "linked"
            linked.parent.mkdir(parents=True)
            linked.symlink_to(external, target_is_directory=True)
            symlink = subprocess.run(
                [str(helper), "echo safe", "--outdir", "evidence/guac/linked", "--dry-run"],
                cwd=root,
                env=common,
                text=True,
                capture_output=True,
                timeout=30,
            )
            self.assertNotEqual(symlink.returncode, 0)
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "untouched")

            downloads = root / "downloads"
            downloads.mkdir(exist_ok=True)
            cmd_file = downloads / "oversized-commands.txt"
            cmd_file.write_bytes(b"x" * (1024 * 1024 + 1))
            oversized = subprocess.run(
                [
                    str(helper),
                    "--cmd-file",
                    str(cmd_file),
                    "--outdir",
                    "evidence/guac/cmd-file-limit",
                    "--dry-run",
                ],
                cwd=root,
                env=common,
                text=True,
                capture_output=True,
                timeout=30,
            )
            self.assertNotEqual(oversized.returncode, 0)
            self.assertIn("--cmd-file exceeds byte limit", oversized.stderr)

    def test_searxng_caps_a_positive_caller_limit_before_reading(self) -> None:
        def prepare(root: Path) -> None:
            replace_env_assignments(
                root,
                {
                    "EVENT_ID": "residual-searxng",
                    "EVENT_NAME": "Residual SearXNG",
                    "EVENT_SCOPE_ACK": "1",
                    "ALLOWED_HOSTS": "fixture.invalid",
                    "ALLOWED_CIDRS": "",
                    "ALLOWED_PORTS": "443",
                    "ALLOWED_PROTOCOLS": "https",
                    "ALLOWED_FILE_ORIGINS": "",
                    "PLATFORM_HOSTS": "",
                    "SCOPE_MAX_BYTES": "1024",
                    "SEARXNG_MODE": "auto",
                    "SEARXNG_URL": "https://fixture.invalid/search",
                },
            )

        fixture = make_deployed_workspace("manual", prepare=prepare)
        self.addCleanup(fixture.cleanup)
        root = Path(fixture.name)
        namespace = runpy.run_path(
            str(root / "bin/searxng"), run_name="searxng_residual_io_test"
        )
        hard_maximum = namespace["MAX_RESPONSE_BYTES"]

        with mock.patch.dict(os.environ, fixture.bootstrap.environment, clear=True):
            for caller_limit in (hard_maximum, hard_maximum * 100):
                with self.subTest(caller_limit=caller_limit):
                    response = mock.MagicMock()
                    response.__enter__.return_value = response
                    response.read.side_effect = lambda count: b"x" * count
                    recorded: list[object] = []

                    def sealed_response_transport(scope, url, **kwargs):
                        transport = kwargs["transport"]
                        self.assertIs(type(transport), ScopedHTTPTransport)
                        sequence = scope_module._EndpointAwareTestTransport([response])
                        try:
                            return scope_module.open_scoped_url(
                                scope, url, _test_transport=sequence
                            )
                        finally:
                            recorded.extend(sequence.requests)
                    with (
                        mock.patch.object(
                            sys,
                            "argv",
                            [
                                "searxng",
                                "fixture",
                                "--max-response-bytes",
                                str(caller_limit),
                            ],
                        ),
                        mock.patch.dict(
                            namespace["query"].__globals__,
                            {"open_scoped_url": sealed_response_transport},
                        ),
                        self.assertRaisesRegex(
                            RuntimeError, "exceeds configured byte limit"
                        ),
                    ):
                        namespace["query"](root)
                    response.read.assert_called_once_with(hard_maximum + 1)
                    self.assertEqual(len(recorded), 1)

            (root / "state" / "scope.json").write_text("{}", encoding="utf-8")
            with self.assertRaises(ScopeAuthorityError):
                namespace["query"](root, ["fixture", "--max-response-bytes", "1024"])

    def test_render_surface_rejects_linked_or_hardlinked_generated_targets(self) -> None:
        with tempfile.TemporaryDirectory() as outside:
            external = Path(outside) / "external"
            external.mkdir()
            sentinel = external / "sentinel.toml"
            sentinel.write_text("keep = true\n", encoding="utf-8")

            workspace = make_workspace()
            root = Path(workspace.name)
            manifest, _, _, _ = manifest_scope_store(root)
            agents_dir = root / ".codex" / "agents"
            for path in agents_dir.iterdir():
                path.unlink()
            agents_dir.rmdir()
            agents_dir.symlink_to(external, target_is_directory=True)
            from rookery.portable.registry import render_surface

            with self.assertRaisesRegex(RuntimeError, "not a directory"):
                render_surface(root, manifest)
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "keep = true\n")
            workspace.cleanup()

            workspace = make_workspace()
            root = Path(workspace.name)
            manifest, _, _, _ = manifest_scope_store(root)
            config = root / ".codex" / "config.toml"
            config.unlink()
            os.link(sentinel, config)
            with self.assertRaisesRegex(RuntimeError, "unlinked regular file"):
                render_surface(root, manifest)
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "keep = true\n")
            workspace.cleanup()

    def test_render_surface_writes_selected_files_as_private_regular_files(self) -> None:
        workspace = make_workspace()
        root = Path(workspace.name)
        manifest, _, _, _ = manifest_scope_store(root)
        from rookery.portable.registry import render_surface

        inventory = render_surface(root, manifest)
        agents_dir = root / ".codex" / "agents"
        rendered = list(agents_dir.glob("*.toml"))
        self.assertEqual(len(rendered), len(inventory["agents"]))
        self.assertTrue(
            all(
                path.read_bytes().startswith(b"# Generated by Rookery surface renderer.\n")
                for path in rendered
            )
        )
        for path in [*rendered, root / ".codex" / "config.toml"]:
            info = os.lstat(path)
            self.assertTrue(stat.S_ISREG(info.st_mode))
            self.assertEqual(info.st_nlink, 1)
            if os.name == "posix":
                self.assertEqual(stat.S_IMODE(info.st_mode), 0o600)
        workspace.cleanup()


if __name__ == "__main__":
    unittest.main(verbosity=2)
