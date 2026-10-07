from __future__ import annotations

# ruff: noqa: E402

import importlib.util
import os
import signal
import subprocess
import sys
import tempfile
import unittest
from importlib.machinery import SourceFileLoader
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from tests.rookery.support import ROOKERY_ROOT
from tests.rookery.test_preparation_and_isolation import copy_rookery

LIB = ROOKERY_ROOT / "lib"
if str(LIB) not in sys.path:
    sys.path.insert(0, str(LIB))

from rookery.portable.control import resume, stop
from rookery.portable.store import EventStore


def load_script(root: Path, name: str):
    loader = SourceFileLoader(name, str(root / "bin" / name))
    spec = importlib.util.spec_from_loader(name, loader)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.ROOT = root
    return module


class ResidualActionGuardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        copy_rookery(self.root)
        # These direct control-path unit tests use an explicitly non-deployed
        # workspace. Public launch binding is covered through the real gate,
        # not a synthetic binding that could weaken this signal-guard claim.
        (self.root / "VERSION").unlink()
        (self.root / "bin" / "rookery").unlink()
        resume(EventStore(self.root), reason="fixture")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def lsof_result(pid: int = 4242) -> SimpleNamespace:
        # This intentionally mirrors the prior subprocess mock shape: text fields.
        return SimpleNamespace(
            stdout=f"COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\nrookery {pid} u 3u IPv4 1 0t0 TCP *:31337 (LISTEN)\n",
            stderr="",
        )

    def seed_owned_job(self, pid: int = 4242) -> None:
        EventStore(self.root).append(
            "job.running",
            {
                "job_id": "fixture-job",
                "status": "running",
                "pid": pid,
                "pgid": pid,
                "process_starttime": "fixture-start",
                "owner_token": "fixture-owner-token",
            },
            actor="fixture",
        )

    def test_operator_stop_is_refused_without_marker_or_side_effects(self) -> None:
        module = load_script(self.root, "auth-expired-stop")
        store = EventStore(self.root)
        before = store.count()
        with patch.object(module, "run") as run, patch.object(
            sys, "argv", ["auth-expired-stop", "--operator-stop"]
        ):
            self.assertEqual(module.main(), 2)
        self.assertFalse((self.root / "control/STOP_REQUESTED").exists())
        self.assertEqual(store.count(), before)
        run.assert_not_called()

    def test_cleanup_refuses_when_workspace_is_stopped(self) -> None:
        self.seed_owned_job()
        stop(EventStore(self.root), self.root, reason="fixture", wait_seconds=0)
        module = load_script(self.root, "stale-port-cleanup")
        with patch.object(module.shutil, "which", return_value="lsof"), patch.object(
            module, "run_bounded_argv", return_value=self.lsof_result()
        ), patch.object(module, "process_identity_matches", return_value=True), patch.object(
            module.os, "kill"
        ) as kill, patch.object(sys, "argv", ["stale-port-cleanup", "--ports", "31337", "--kill"]):
            self.assertEqual(module.main(), 0)
        kill.assert_not_called()

    def test_cleanup_refuses_external_listener_by_default(self) -> None:
        module = load_script(self.root, "stale-port-cleanup")
        with patch.object(module.shutil, "which", return_value="lsof"), patch.object(
            module, "run_bounded_argv", return_value=self.lsof_result()
        ), patch.object(module.os, "kill") as kill, patch.object(
            sys, "argv", ["stale-port-cleanup", "--ports", "31337", "--kill"]
        ):
            self.assertEqual(module.main(), 0)
        kill.assert_not_called()

    def test_cleanup_refuses_pid_reused_after_discovery(self) -> None:
        self.seed_owned_job()
        module = load_script(self.root, "stale-port-cleanup")
        with patch.object(module.shutil, "which", return_value="lsof"), patch.object(
            module, "run_bounded_argv", return_value=self.lsof_result()
        ), patch.object(
            module, "process_identity_matches", return_value=False
        ), patch.object(module.os, "kill") as kill, patch.object(
            sys, "argv", ["stale-port-cleanup", "--ports", "31337", "--kill"]
        ):
            self.assertEqual(module.main(), 0)
        kill.assert_not_called()

    def test_cleanup_signals_current_verified_owned_job(self) -> None:
        token = "fixture-owner-token"
        process = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            cwd=self.root,
            env={**os.environ, "ROOKERY_OWNER_TOKEN": token},
            start_new_session=True,
        )
        starttime = (Path("/proc") / str(process.pid) / "stat").read_text().split()[21]
        EventStore(self.root).append(
            "job.running",
            {
                "job_id": "owned-process",
                "status": "running",
                "pid": process.pid,
                "pgid": os.getpgid(process.pid),
                "process_starttime": starttime,
                "owner_token": token,
            },
            actor="fixture",
        )
        module = load_script(self.root, "stale-port-cleanup")
        try:
            with patch.object(module.shutil, "which", return_value="lsof"), patch.object(
                module, "run_bounded_argv", return_value=self.lsof_result(process.pid)
            ), patch.object(
                sys, "argv", ["stale-port-cleanup", "--ports", "31337", "--kill"]
            ):
                self.assertEqual(module.main(), 0)
            self.assertEqual(process.wait(timeout=5), -signal.SIGTERM)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)


if __name__ == "__main__":
    unittest.main(verbosity=2)
