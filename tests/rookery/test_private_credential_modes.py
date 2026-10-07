from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from rookery.portable.cookie_output import (
    preflight_cookie_output,
    prepare_cookie_output,
)
from tests.rookery.env_fixtures import configure_event_environment
from tests.rookery.support import copy_non_deployed_rookery, install_test_launch_binding


@unittest.skipUnless(os.name == "posix", "requires POSIX filesystem modes")
class PrivateCredentialModeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.original_umask = os.umask(0o022)
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        copy_non_deployed_rookery(self.root)
        configure_event_environment(self.root, "manual")
        self.environment = {
            **os.environ,
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        self.dummy_value = "private-fixture-value"

    def tearDown(self) -> None:
        try:
            self.temporary.cleanup()
        finally:
            os.umask(self.original_umask)

    def assert_mode(self, path: Path, expected: int) -> None:
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), expected, path)

    def run_ok(self, *command: str) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            command,
            cwd=self.root,
            env=self.environment,
            text=True,
            capture_output=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, Path(command[0]).name)
        return result

    def run_bound_optional_helper(self, *command: str) -> subprocess.CompletedProcess[str]:
        """Rebind this non-deployed mutable fixture before helper I/O."""

        install_test_launch_binding(self.root)
        return self.run_ok(*command)

    def fake_command(self, name: str) -> None:
        path = self.root / "bin" / name
        path.write_text("#!/usr/bin/env python3\nprint('{}')\n", encoding="utf-8")
        path.chmod(0o755)

    def cookie_source(self) -> Path:
        source = self.root / "fixture-cookies.json"
        source.write_text(
            json.dumps(
                [
                    {
                        "name": "session",
                        "value": self.dummy_value,
                        "domain": "fixture.invalid",
                        "expires": 4_102_444_800,
                    }
                ]
            ),
            encoding="utf-8",
        )
        return source

    def test_fresh_private_credential_writers_use_private_modes(self) -> None:
        source = self.cookie_source()
        cookie_out = self.root / "platform" / "cookies" / "private-cookie-output"
        self.run_ok(
            str(self.root / "bin" / "cookie-filter"),
            "--file",
            str(source),
            "--domains",
            "fixture.invalid",
            "--outdir",
            str(cookie_out),
            "--json",
        )
        self.assert_mode(cookie_out, 0o700)
        for name in ("cookie-header.txt", "selected-cookies.json", "summary.json"):
            self.assert_mode(cookie_out / name, 0o600)

        self.run_ok(
            str(self.root / "bin" / "attempt-registry"),
            "answer",
            "--challenge",
            "fixture",
            "--value",
            self.dummy_value,
        )
        for path in (
            self.root / "state",
            self.root / "state" / "attempts",
            self.root / "state" / "challenges",
        ):
            self.assert_mode(path, 0o700)
        for path in (
            self.root / "state" / "attempt_registry.jsonl",
            self.root / "state" / "attempts" / "current.json",
            self.root / "state" / "challenges" / "fixture.json",
        ):
            self.assert_mode(path, 0o600)

        self.fake_command("scope-check")
        self.run_ok(
            str(self.root / "bin" / "rookery-ops"),
            "target-inventory",
            "add",
            "--host",
            "fixture.invalid",
        )
        self.run_ok(
            str(self.root / "bin" / "rookery-ops"),
            "cleanup",
            "register",
            "--label",
            "fixture",
            "--argv-json",
            json.dumps([sys.executable, "-c", "pass"]),
        )
        for path in (
            self.root / "state" / "target_inventory.jsonl",
            self.root / "state" / "cleanup_hooks.jsonl",
        ):
            self.assert_mode(path, 0o600)

        processes = []
        for index in range(6):
            processes.append(
                subprocess.Popen(
                    [
                        str(self.root / "bin" / "rookery-ops"),
                        "credential-ledger",
                        "add",
                        "--principal",
                        "fixture",
                        "--secret-ref",
                        f"ref-{index}",
                    ],
                    cwd=self.root,
                    env=self.environment,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                    text=True,
                )
            )
        results = []
        for process in processes:
            _, stderr = process.communicate(timeout=30)
            results.append((process.returncode, stderr))
        self.assertTrue(all(code == 0 for code, _ in results), results)
        credential_ledger = self.root / "evidence" / "credential_ledger.jsonl"
        self.assert_mode(self.root / "evidence", 0o700)
        self.assert_mode(credential_ledger, 0o600)
        self.assertEqual(len(credential_ledger.read_text(encoding="utf-8").splitlines()), 6)

        self.fake_command("reviewer-queue")
        self.run_ok(str(self.root / "bin" / "platform-heavy-pause"), "pause")
        self.assert_mode(self.root / "control", 0o700)
        self.assert_mode(self.root / "control" / "AUTH_PAUSED", 0o600)
        self.assert_mode(self.root / "AUTH_PAUSED.md", 0o600)

        self.fake_command("platform-heavy-pause")
        self.fake_command("score-review")
        self.fake_command("frontier")
        auth = subprocess.run(
            [str(self.root / "bin" / "auth-expired-stop")],
            cwd=self.root,
            env=self.environment,
            text=True,
            capture_output=True,
            timeout=30,
        )
        self.assertEqual(auth.returncode, 3, "auth-expired-stop")
        self.assert_mode(self.root / "handoffs", 0o700)
        self.assert_mode(self.root / "control" / "AUTH_EXPIRED", 0o600)
        self.assert_mode(next((self.root / "handoffs").glob("*.md")), 0o600)
        self.assert_mode(self.root / "AUTH_EXPIRED.md", 0o600)

        self.run_ok(
            str(self.root / "bin" / "credential-health"),
            "--file",
            str(source),
            "--json",
        )
        health_root = self.root / "platform" / "session-health"
        health_dir = next(health_root.iterdir())
        self.assert_mode(self.root / "platform", 0o700)
        self.assert_mode(health_root, 0o700)
        self.assert_mode(health_dir, 0o700)
        self.assert_mode(health_dir / "health.json", 0o600)
        cookie_health = next(
            (self.root / "platform" / "cookies").glob("credential-health-*")
        )
        self.assert_mode(cookie_health / "summary.json", 0o600)

        vpn = subprocess.run(
            [str(self.root / "bin" / "vpn"), "health", "--json"],
            cwd=self.root,
            env=self.environment,
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(vpn.returncode, 2, vpn.stdout + vpn.stderr)
        self.assertEqual(vpn.stderr, "vpn_privileged_supervision_unavailable\n")
        self.assertFalse((self.root / "state" / "vpn").exists())
        self.assertFalse((self.root / "logs" / "vpn").exists())

        self.run_bound_optional_helper(
            str(self.root / "extensions" / "guacamole" / "bin" / "console-lease"),
            "claim",
            "fixture-console",
            "--owner",
            "fixture",
        )
        self.assert_mode(self.root / "state" / "console_locks.json", 0o600)

    def test_permissive_private_paths_migrate_without_content_changes(self) -> None:
        source = self.cookie_source()
        prepare_cookie_output(
            preflight_cookie_output(
                self.root,
                str(self.root / "platform" / "cookies" / "cookie-migration"),
            )
        )
        paths = {
            self.root / "state" / "target_inventory.jsonl": '{"host":"fixture.invalid"}\n',
            self.root / "state" / "cleanup_hooks.jsonl": '{"label":"fixture"}\n',
            self.root / "state" / "attempt_registry.jsonl": '{"challenge":"fixture"}\n',
            self.root / "state" / "attempts" / "current.json": '{"by_challenge":{}}\n',
            self.root / "state" / "console_locks.json": '{"leases":{}}\n',
            self.root / "evidence" / "credential_ledger.jsonl": '{"credential_id":"fixture"}\n',
            self.root / "control" / "AUTH_PAUSED": "fixture-control\n",
            self.root / "handoffs" / "previous.md": "fixture-handoff\n",
            self.root / "platform" / "session-health" / "legacy" / "health.json": "{}\n",
            self.root
            / "platform"
            / "cookies"
            / "cookie-migration"
            / "prior.txt": "fixture-cookie-output\n",
            self.root / "state" / "vpn" / "watch.pid": "not-a-pid\n",
            self.root / "logs" / "vpn" / "watch.log": "fixture-vpn-log\n",
        }
        for path, content in paths.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
            path.chmod(0o666)
            for parent in [path.parent, *path.parents]:
                if parent == self.root.parent:
                    break
                if parent != self.root:
                    parent.chmod(0o777)
        before = {path: path.read_bytes() for path in paths}

        self.run_ok(str(self.root / "bin" / "rookery-ops"), "target-inventory", "list")
        self.run_ok(str(self.root / "bin" / "rookery-ops"), "cleanup", "list")
        self.run_ok(str(self.root / "bin" / "rookery-ops"), "credential-ledger", "list")
        self.run_ok(str(self.root / "bin" / "attempt-registry"), "list", "--json")
        self.run_ok(str(self.root / "bin" / "attempt-registry"), "current")
        self.run_bound_optional_helper(
            str(self.root / "extensions" / "guacamole" / "bin" / "console-lease"),
            "status",
            "--json",
        )
        self.run_ok(str(self.root / "bin" / "platform-heavy-pause"), "status", "--json")
        self.run_ok(
            str(self.root / "bin" / "cookie-filter"),
            "--file",
            str(source),
            "--domains",
            "fixture.invalid",
            "--outdir",
            str(self.root / "platform" / "cookies" / "cookie-migration"),
        )
        self.run_ok(
            str(self.root / "bin" / "credential-health"),
            "--file",
            str(source),
            "--json",
        )
        vpn = subprocess.run(
            [str(self.root / "bin" / "vpn"), "health", "--json"],
            cwd=self.root,
            env=self.environment,
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(vpn.returncode, 2, vpn.stdout + vpn.stderr)
        self.assertEqual(vpn.stderr, "vpn_privileged_supervision_unavailable\n")
        self.fake_command("platform-heavy-pause")
        self.fake_command("reviewer-queue")
        self.fake_command("score-review")
        self.fake_command("frontier")
        auth = subprocess.run(
            [str(self.root / "bin" / "auth-expired-stop")],
            cwd=self.root,
            env=self.environment,
            text=True,
            capture_output=True,
            timeout=30,
        )
        self.assertEqual(auth.returncode, 3, "auth-expired-stop")

        self.assertEqual(before, {path: path.read_bytes() for path in paths})
        legacy_vpn_paths = {
            self.root / "state" / "vpn" / "watch.pid",
            self.root / "logs" / "vpn" / "watch.log",
        }
        for path in paths:
            if path in legacy_vpn_paths:
                self.assert_mode(path, 0o666)
                self.assert_mode(path.parent, 0o777)
            else:
                self.assert_mode(path, 0o600)
                self.assert_mode(path.parent, 0o700)

    def test_cookie_filter_refuses_a_symlinked_private_output(self) -> None:
        source = self.cookie_source()
        output = self.root / "platform" / "cookies" / "symlink-output"
        prepare_cookie_output(preflight_cookie_output(self.root, str(output)))
        target = self.root / "outside"
        target.write_text("outside", encoding="utf-8")
        (output / "summary.json").symlink_to(target)
        result = subprocess.run(
            [
                str(self.root / "bin" / "cookie-filter"),
                "--file",
                str(source),
                "--outdir",
                str(output),
            ],
            cwd=self.root,
            env=self.environment,
            text=True,
            capture_output=True,
            timeout=30,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(target.read_text(encoding="utf-8"), "outside")


if __name__ == "__main__":
    unittest.main(verbosity=2)
