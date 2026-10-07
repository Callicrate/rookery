from __future__ import annotations

# ruff: noqa: E402

import json
import os
import signal
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from contextlib import ExitStack, nullcontext
from pathlib import Path
from unittest import mock

from tests.rookery.support import ROOKERY_ROOT

LIB = ROOKERY_ROOT / "lib"
if str(LIB) not in sys.path:
    sys.path.insert(0, str(LIB))
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

from rookery.portable import environment as environment_module
from rookery.portable import adapters as adapters_module
from rookery.portable.adapters import run_bounded_argv
from rookery.portable.environment import EnvironmentPolicyError
from rookery.portable.environment import (
    ChildEnvironment,
    LaunchBinding,
    codex_launcher_main,
)
from rookery.portable.util import file_lock


@unittest.skipUnless(os.name == "posix", "requires POSIX process groups")
class BoundedProcessGroupCleanupTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.pgids: list[int] = []

    def tearDown(self) -> None:
        for pgid in self.pgids:
            try:
                os.killpg(pgid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        self.temporary.cleanup()

    @staticmethod
    def _group_exists(pgid: int) -> bool:
        try:
            os.killpg(pgid, 0)
        except ProcessLookupError:
            return False
        return True

    def _record_pgid(self, path: Path) -> int:
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            if path.exists():
                pgid = int(path.read_text(encoding="utf-8"))
                self.pgids.append(pgid)
                return pgid
            time.sleep(0.01)
        self.fail("child did not record its process group")

    def _assert_group_gone(self, pgid: int) -> None:
        deadline = time.monotonic() + 2
        while self._group_exists(pgid) and time.monotonic() < deadline:
            time.sleep(0.02)
        self.assertFalse(self._group_exists(pgid))

    def _delayed_marker_program(self, marker: Path) -> str:
        return (
            "import time; from pathlib import Path; "
            "time.sleep(0.8); "
            f"Path({str(marker)!r}).write_text('survived', encoding='utf-8'); "
            "time.sleep(30)"
        )

    def test_bounded_runner_stops_group_after_leader_exits_with_open_pipes(self) -> None:
        marker = self.root / "bounded-descendant-survived"
        pgid_path = self.root / "bounded.pgid"
        descendant = self._delayed_marker_program(marker)
        leader = (
            "import os, subprocess, sys; from pathlib import Path; "
            f"Path({str(pgid_path)!r}).write_text(str(os.getpgrp()), encoding='utf-8'); "
            f"subprocess.Popen([sys.executable, '-c', {descendant!r}])"
        )

        with self.assertRaisesRegex(
            RuntimeError, "^adapter process group outlived command leader$"
        ):
            run_bounded_argv(
                [sys.executable, "-c", leader],
                cwd=self.root,
                timeout=3,
                max_output_bytes=4096,
            )

        pgid = self._record_pgid(pgid_path)
        self._assert_group_gone(pgid)
        time.sleep(1)
        self.assertFalse(marker.exists())

    def test_bounded_runner_normal_exit_preserves_result(self) -> None:
        started_watchdogs = []
        original_start = adapters_module._start_parent_death_watchdog

        def capture_watchdog(*args, **kwargs):
            watchdog = original_start(*args, **kwargs)
            started_watchdogs.append(watchdog)
            return watchdog

        with mock.patch.object(
            adapters_module,
            "_start_parent_death_watchdog",
            side_effect=capture_watchdog,
        ):
            result = run_bounded_argv(
                [sys.executable, "-c", "print('bounded-ready')"],
                cwd=self.root,
                timeout=3,
                max_output_bytes=4096,
            )

        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.termination, "exited")
        self.assertEqual(result.stdout, b"bounded-ready\n")
        self.assertEqual(result.stderr, b"")
        self.assertEqual(len(started_watchdogs), 1)
        self.assertIsNotNone(started_watchdogs[0])
        self.assertEqual(started_watchdogs[0].process.returncode, 0)

    def test_bounded_runner_timeout_preserves_group_cleanup(self) -> None:
        marker = self.root / "timeout-child-survived"
        pgid_path = self.root / "timeout.pgid"
        child = (
            "import os, time; from pathlib import Path; "
            f"Path({str(pgid_path)!r}).write_text(str(os.getpgrp()), encoding='utf-8'); "
            "time.sleep(2); "
            f"Path({str(marker)!r}).write_text('survived', encoding='utf-8')"
        )

        result = run_bounded_argv(
            [sys.executable, "-c", child],
            cwd=self.root,
            timeout=1,
            max_output_bytes=4096,
        )

        self.assertEqual(result.termination, "timeout")
        pgid = self._record_pgid(pgid_path)
        self._assert_group_gone(pgid)
        time.sleep(1.25)
        self.assertFalse(marker.exists())

    def test_bounded_runner_continuation_guard_still_cancels_group(self) -> None:
        marker = self.root / "guard-cancelled-child-survived"
        pgid_path = self.root / "guard-cancelled.pgid"
        child = (
            "import os, time; from pathlib import Path; "
            f"Path({str(pgid_path)!r}).write_text(str(os.getpgrp()), encoding='utf-8'); "
            "time.sleep(1); "
            f"Path({str(marker)!r}).write_text('survived', encoding='utf-8')"
        )

        def revoke_continuation() -> None:
            raise RuntimeError("fixture continuation revoked")

        with self.assertRaisesRegex(RuntimeError, "fixture continuation revoked"):
            run_bounded_argv(
                [sys.executable, "-c", child],
                cwd=self.root,
                timeout=3,
                max_output_bytes=4096,
                spawn_guard=nullcontext,
                continuation_guard=revoke_continuation,
            )

        pgid = self._record_pgid(pgid_path)
        self._assert_group_gone(pgid)
        time.sleep(1.1)
        self.assertFalse(marker.exists())

    def _assert_child_dies_with_runner(
        self,
        runner_code: str,
        *,
        pid_path: Path,
        pgid_path: Path,
        marker: Path,
        barrier_path: Path | None = None,
    ) -> None:
        runner = subprocess.Popen(
            [sys.executable, "-c", runner_code],
            cwd=self.root,
            env={"PATH": os.defpath, "PYTHONDONTWRITEBYTECODE": "1"},
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        pgid = 0
        try:
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline and (
                not pid_path.exists()
                or (barrier_path is not None and not barrier_path.exists())
            ):
                if runner.poll() is not None:
                    self.fail("bounded runner exited before its child started")
                time.sleep(0.01)
            self.assertTrue(pid_path.exists(), "bounded child did not start")
            if barrier_path is not None:
                self.assertTrue(barrier_path.exists(), "post-Popen barrier was not reached")
            child_pid = int(pid_path.read_text(encoding="utf-8"))
            pgid = self._record_pgid(pgid_path)
            self.assertTrue(Path(f"/proc/{child_pid}").exists())

            os.kill(runner.pid, signal.SIGKILL)
            runner.wait(timeout=3)
            deadline = time.monotonic() + 2
            while Path(f"/proc/{child_pid}").exists() and time.monotonic() < deadline:
                time.sleep(0.02)

            self.assertFalse(Path(f"/proc/{child_pid}").exists())
            time.sleep(1.1)
            self.assertFalse(marker.exists())
            self._assert_group_gone(pgid)
        finally:
            if runner.poll() is None:
                runner.kill()
                runner.wait(timeout=3)
            if pgid and self._group_exists(pgid):
                os.killpg(pgid, signal.SIGKILL)

    @staticmethod
    def _parent_death_child(pid_path: Path, pgid_path: Path, marker: Path) -> str:
        return (
            "import os, time; from pathlib import Path; "
            f"Path({str(pid_path)!r}).write_text(str(os.getpid()), encoding='utf-8'); "
            f"Path({str(pgid_path)!r}).write_text(str(os.getpgrp()), encoding='utf-8'); "
            "time.sleep(1); "
            f"Path({str(marker)!r}).write_text('survived', encoding='utf-8'); "
            "time.sleep(30)"
        )

    @unittest.skipUnless(
        sys.platform == "linux" and Path("/proc").is_dir(),
        "requires Linux parent-death signals and procfs",
    )
    def test_bounded_child_dies_when_runner_parent_is_killed(self) -> None:
        marker = self.root / "parent-death-child-survived"
        pid_path = self.root / "parent-death.pid"
        pgid_path = self.root / "parent-death.pgid"
        child = self._parent_death_child(pid_path, pgid_path, marker)
        runner_code = (
            "import sys; from pathlib import Path; "
            f"sys.path.insert(0, {str(LIB)!r}); "
            "from rookery.portable.adapters import run_bounded_argv; "
            "run_bounded_argv("
            f"[{sys.executable!r}, '-c', {child!r}], "
            f"cwd=Path({str(self.root)!r}), timeout=30, max_output_bytes=4096)"
        )
        self._assert_child_dies_with_runner(
            runner_code,
            pid_path=pid_path,
            pgid_path=pgid_path,
            marker=marker,
        )

    @unittest.skipUnless(
        sys.platform == "linux" and Path("/proc").is_dir(),
        "requires Linux parent-death signals and procfs",
    )
    def test_same_pgid_descendant_dies_when_runner_parent_is_killed(self) -> None:
        marker = self.root / "same-pgid-descendant-survived"
        pid_path = self.root / "same-pgid-descendant.pid"
        pgid_path = self.root / "same-pgid-descendant.pgid"
        descendant = (
            "import os, time; from pathlib import Path; "
            "time.sleep(0.1); "
            f"Path({str(pid_path)!r}).write_text(str(os.getpid()), encoding='utf-8'); "
            f"Path({str(pgid_path)!r}).write_text(str(os.getpgrp()), encoding='utf-8'); "
            "time.sleep(1); "
            f"Path({str(marker)!r}).write_text('survived', encoding='utf-8'); "
            "time.sleep(30)"
        )
        leader = (
            "import subprocess, sys, time; "
            f"subprocess.Popen([sys.executable, '-c', {descendant!r}]); "
            "time.sleep(30)"
        )
        runner_code = (
            "import sys; from pathlib import Path; "
            f"sys.path.insert(0, {str(LIB)!r}); "
            "from rookery.portable.adapters import run_bounded_argv; "
            "run_bounded_argv("
            f"[{sys.executable!r}, '-c', {leader!r}], "
            f"cwd=Path({str(self.root)!r}), timeout=30, max_output_bytes=4096)"
        )

        self._assert_child_dies_with_runner(
            runner_code,
            pid_path=pid_path,
            pgid_path=pgid_path,
            marker=marker,
        )

    @unittest.skipUnless(
        sys.platform == "linux" and Path("/proc").is_dir(),
        "requires Linux parent-death signals and procfs",
    )
    def test_runner_death_in_post_popen_gap_cannot_orphan_descendant(self) -> None:
        marker = self.root / "post-popen-gap-descendant-survived"
        pid_path = self.root / "post-popen-gap-descendant.pid"
        pgid_path = self.root / "post-popen-gap-descendant.pgid"
        barrier_path = self.root / "post-popen-gap.barrier"
        descendant = self._parent_death_child(pid_path, pgid_path, marker)
        leader = (
            "import subprocess, sys, time; "
            f"subprocess.Popen([sys.executable, '-c', {descendant!r}]); "
            "time.sleep(30)"
        )
        runner_code = (
            "import sys, time\n"
            "from pathlib import Path\n"
            f"sys.path.insert(0, {str(LIB)!r})\n"
            "import rookery.portable.adapters as adapters\n"
            "def after_popen(_process):\n"
            f" Path({str(barrier_path)!r}).write_text('ready', encoding='utf-8')\n"
            " time.sleep(30)\n"
            "adapters._AFTER_BOUNDED_POPEN_HOOK = after_popen\n"
            "adapters.run_bounded_argv("
            f"[{sys.executable!r}, '-c', {leader!r}], "
            f"cwd=Path({str(self.root)!r}), timeout=30, max_output_bytes=4096)"
        )

        self._assert_child_dies_with_runner(
            runner_code,
            pid_path=pid_path,
            pgid_path=pgid_path,
            marker=marker,
            barrier_path=barrier_path,
        )

    @unittest.skipUnless(
        sys.platform == "linux" and Path("/proc").is_dir(),
        "requires Linux parent-death signals and procfs",
    )
    def test_immersive_custom_child_dies_when_helper_runner_is_killed(self) -> None:
        marker = self.root / "immersive-parent-death-child-survived"
        pid_path = self.root / "immersive-parent-death.pid"
        pgid_path = self.root / "immersive-parent-death.pgid"
        child = self._parent_death_child(pid_path, pgid_path, marker)
        helper = ROOKERY_ROOT / "adapters/immersive/bin/immersive-selected-lab-refresh"
        runner_code = (
            "import runpy; "
            f"namespace = runpy.run_path({str(helper)!r}); "
            "namespace['run']("
            f"[{sys.executable!r}, '-c', {child!r}], "
            "timeout=30, max_output_bytes=4096)"
        )

        self._assert_child_dies_with_runner(
            runner_code,
            pid_path=pid_path,
            pgid_path=pgid_path,
            marker=marker,
        )

    def test_non_linux_posix_fails_before_bounded_spawn(self) -> None:
        with (
            mock.patch.object(adapters_module.sys, "platform", "darwin"),
            mock.patch.object(adapters_module.subprocess, "Popen") as popen,
            self.assertRaisesRegex(
                RuntimeError, "parent-death supervision unavailable"
            ),
        ):
            run_bounded_argv(
                [sys.executable, "-c", "pass"],
                cwd=self.root,
                timeout=3,
                max_output_bytes=4096,
            )

        popen.assert_not_called()


@unittest.skipUnless(os.name == "posix", "requires the POSIX mutation lock")
class FinalCodexExecStopBarrierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        (self.root / "bin").mkdir()
        (self.root / "bin" / "rookery").write_text("fixture\n", encoding="utf-8")
        (self.root / "VERSION").write_text("fixture\n", encoding="utf-8")
        state = self.root / "state"
        state.mkdir(mode=0o700)
        self.binding = LaunchBinding(
            {"strict_config_supported": True},
            "a" * 64,
        )
        self.pgids: list[int] = []
        self.attempt_id = "b" * 64
        attempt = state / environment_module.LAUNCH_ATTEMPT_NAME
        attempt.write_text(
            json.dumps(
                {
                    "schema_version": "1",
                    "attempt_id": self.attempt_id,
                    "launch_binding_sha256": self.binding.sha256,
                    "stop_generation": 0,
                }
            )
            + "\n",
            encoding="utf-8",
        )
        attempt.chmod(0o600)
        self.database = state / "events.sqlite3"
        connection = sqlite3.connect(self.database)
        try:
            connection.executescript(
                """
                CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE events (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT NOT NULL UNIQUE,
                    event_type TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    generation INTEGER NOT NULL,
                    actor TEXT NOT NULL,
                    payload_json TEXT NOT NULL
                );
                """
            )
            connection.executemany(
                "INSERT INTO meta(key,value) VALUES(?,?)",
                (
                    ("stop_generation", "0"),
                    ("launch_binding_sha256", self.binding.sha256),
                ),
            )
            connection.commit()
        finally:
            connection.close()
        self.database.chmod(0o600)

    def tearDown(self) -> None:
        for pgid in self.pgids:
            try:
                os.killpg(pgid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        self.temporary.cleanup()

    @staticmethod
    def _group_exists(pgid: int) -> bool:
        try:
            os.killpg(pgid, 0)
        except ProcessLookupError:
            return False
        return True

    def _record_pgid(self, path: Path) -> int:
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            if path.exists():
                pgid = int(path.read_text(encoding="utf-8"))
                self.pgids.append(pgid)
                return pgid
            time.sleep(0.01)
        self.fail("child did not record its process group")

    def _assert_group_gone(self, pgid: int) -> None:
        deadline = time.monotonic() + 2
        while self._group_exists(pgid) and time.monotonic() < deadline:
            time.sleep(0.02)
        self.assertFalse(self._group_exists(pgid))

    @staticmethod
    def _delayed_marker_program(marker: Path) -> str:
        return (
            "import time; from pathlib import Path; "
            "time.sleep(0.8); "
            f"Path({str(marker)!r}).write_text('survived', encoding='utf-8'); "
            "time.sleep(30)"
        )

    def _stop_workspace(self) -> None:
        with file_lock(self.root / "state" / "mutation.lock"):
            connection = sqlite3.connect(self.database)
            try:
                connection.execute(
                    "UPDATE meta SET value='1' WHERE key='stop_generation'"
                )
                connection.execute(
                    "INSERT INTO events(event_id,event_type,created_at,generation,actor,payload_json) "
                    "VALUES('stop-fixture','control.stop','2026-08-29T00:00:00Z',1,'operator','{}')"
                )
                connection.commit()
            finally:
                connection.close()

    def _configure_resume(
        self,
        *,
        latest_actor: object = "operator",
        latest_event_generation: object = 1,
        latest_payload: object | None = None,
    ) -> None:
        attempt = self.root / "state" / environment_module.LAUNCH_ATTEMPT_NAME
        attempt_record = json.loads(attempt.read_text(encoding="utf-8"))
        attempt_record["stop_generation"] = 1
        attempt.write_text(
            json.dumps(attempt_record) + "\n",
            encoding="utf-8",
        )
        attempt.chmod(0o600)
        rows = [
            (
                "stop-before-resume",
                "control.stop",
                1,
                "operator",
                {"generation": 1, "reason": "fixture stop"},
            ),
            (
                "valid-resume",
                "control.resume",
                1,
                "operator",
                {"generation": 1, "reason": "fixture resume"},
            ),
        ]
        if latest_payload is not None:
            rows.append(
                (
                    "latest-resume",
                    "control.resume",
                    latest_event_generation,
                    latest_actor,
                    latest_payload,
                )
            )
        connection = sqlite3.connect(self.database)
        try:
            connection.execute("DELETE FROM events")
            connection.execute(
                "UPDATE meta SET value='1' WHERE key='stop_generation'"
            )
            connection.executemany(
                "INSERT INTO events(event_id,event_type,created_at,generation,actor,payload_json) "
                "VALUES(?,?, '2026-08-29T00:00:00Z',?,?,?)",
                [
                    (event_id, event_type, generation, actor, json.dumps(payload))
                    for event_id, event_type, generation, actor, payload in rows
                ],
            )
            connection.commit()
        finally:
            connection.close()

    def _launcher_patches(self, descriptor_side_effect):
        return (
            mock.patch.object(
                environment_module,
                "codex_launcher_environment",
                return_value=ChildEnvironment({"PATH": os.defpath}, "fixture", ()),
            ),
            mock.patch.object(
                environment_module,
                "_verify_exec_binding",
                return_value=self.binding,
            ),
            mock.patch.object(
                environment_module,
                "verify_launch_binding_integrity",
                return_value=self.binding,
            ),
            mock.patch.object(
                environment_module,
                "_open_verified_codex_descriptor",
                side_effect=descriptor_side_effect,
            ),
        )

    def test_final_exec_consumes_private_attempt_without_forwarding_it(self) -> None:
        def descriptor(_binding: LaunchBinding) -> int:
            return os.open(os.devnull, os.O_RDONLY)

        patches = self._launcher_patches(descriptor)
        with ExitStack() as stack:
            for patcher in patches:
                stack.enter_context(patcher)
            execute = stack.enter_context(
                mock.patch.object(
                environment_module.os,
                "execve",
                side_effect=RuntimeError("captured exec"),
            )
            )
            with self.assertRaisesRegex(RuntimeError, "captured exec"):
                codex_launcher_main(
                    [
                        environment_module.LAUNCH_ATTEMPT_ARGUMENT,
                        self.attempt_id,
                        "prompt",
                    ],
                    root=self.root,
                    parent={},
                )

        forwarded = execute.call_args.args[1]
        self.assertEqual(forwarded, [forwarded[0], "--strict-config", "prompt"])
        self.assertNotIn(environment_module.LAUNCH_ATTEMPT_ARGUMENT, forwarded)
        self.assertNotIn(self.attempt_id, forwarded)

    def test_stop_committed_after_descriptor_open_blocks_final_exec(self) -> None:
        def descriptor_after_delayed_stop(_binding: LaunchBinding) -> int:
            descriptor = os.open(os.devnull, os.O_RDONLY)
            stopper = threading.Thread(target=self._stop_workspace)
            stopper.start()
            stopper.join(timeout=3)
            self.assertFalse(stopper.is_alive())
            return descriptor

        patches = self._launcher_patches(descriptor_after_delayed_stop)
        with ExitStack() as stack:
            for patcher in patches:
                stack.enter_context(patcher)
            execute = stack.enter_context(
                mock.patch.object(environment_module.os, "execve")
            )
            result = codex_launcher_main(
                [
                    environment_module.LAUNCH_ATTEMPT_ARGUMENT,
                    self.attempt_id,
                    "prompt",
                ],
                root=self.root,
                parent={},
            )

        self.assertEqual(result, 2)
        execute.assert_not_called()

    def test_final_exec_accepts_one_exact_current_operator_resume(self) -> None:
        self._configure_resume()

        def descriptor(_binding: LaunchBinding) -> int:
            return os.open(os.devnull, os.O_RDONLY)

        patches = self._launcher_patches(descriptor)
        with ExitStack() as stack:
            for patcher in patches:
                stack.enter_context(patcher)
            execute = stack.enter_context(
                mock.patch.object(
                    environment_module.os,
                    "execve",
                    side_effect=RuntimeError("captured valid resume exec"),
                )
            )
            with self.assertRaisesRegex(RuntimeError, "captured valid resume exec"):
                codex_launcher_main(
                    [
                        environment_module.LAUNCH_ATTEMPT_ARGUMENT,
                        self.attempt_id,
                        "prompt",
                    ],
                    root=self.root,
                    parent={},
                )

        execute.assert_called_once()

    def test_final_exec_rejects_every_noncanonical_latest_resume(self) -> None:
        cases = (
            (
                "empty reason",
                "operator",
                1,
                {"generation": 1, "reason": ""},
            ),
            (
                "boolean payload generation",
                "operator",
                1,
                {"generation": True, "reason": "malformed boolean"},
            ),
            (
                "string payload generation",
                "operator",
                1,
                {"generation": "1", "reason": "malformed string"},
            ),
            (
                "stale payload generation",
                "operator",
                1,
                {"generation": 0, "reason": "stale payload"},
            ),
            (
                "stale event generation",
                "operator",
                0,
                {"generation": 1, "reason": "stale event"},
            ),
            (
                "non-operator actor",
                "solver",
                1,
                {"generation": 1, "reason": "wrong actor"},
            ),
        )
        for label, actor, event_generation, payload in cases:
            with self.subTest(case=label):
                self._configure_resume(
                    latest_actor=actor,
                    latest_event_generation=event_generation,
                    latest_payload=payload,
                )

                def descriptor(_binding: LaunchBinding) -> int:
                    return os.open(os.devnull, os.O_RDONLY)

                patches = self._launcher_patches(descriptor)
                with ExitStack() as stack:
                    for patcher in patches:
                        stack.enter_context(patcher)
                    execute = stack.enter_context(
                        mock.patch.object(environment_module.os, "execve")
                    )
                    result = codex_launcher_main(
                        [
                            environment_module.LAUNCH_ATTEMPT_ARGUMENT,
                            self.attempt_id,
                            "prompt",
                        ],
                        root=self.root,
                        parent={},
                    )

                self.assertEqual(result, 2)
                execute.assert_not_called()

    def test_deployed_launcher_rejects_missing_duplicate_and_malformed_attempts(self) -> None:
        cases = (
            ["prompt"],
            [environment_module.LAUNCH_ATTEMPT_ARGUMENT],
            [environment_module.LAUNCH_ATTEMPT_ARGUMENT, "not-an-id", "prompt"],
            [
                environment_module.LAUNCH_ATTEMPT_ARGUMENT,
                self.attempt_id,
                environment_module.LAUNCH_ATTEMPT_ARGUMENT,
                self.attempt_id,
                "prompt",
            ],
            [
                f"{environment_module.LAUNCH_ATTEMPT_ARGUMENT}={self.attempt_id}",
                "prompt",
            ],
        )
        for arguments in cases:
            with self.subTest(arguments=arguments):
                self.assertEqual(
                    codex_launcher_main(arguments, root=self.root, parent={}), 2
                )

    def test_codex_probe_overflow_stops_its_entire_group(self) -> None:
        marker = self.root / "probe-overflow-descendant-survived"
        pgid_path = self.root / "probe-overflow.pgid"
        descendant = self._delayed_marker_program(marker)
        probe = (
            "import os, subprocess, sys, time; from pathlib import Path; "
            f"Path({str(pgid_path)!r}).write_text(str(os.getpgrp()), encoding='utf-8'); "
            f"subprocess.Popen([sys.executable, '-c', {descendant!r}]); "
            "os.write(1, b'x' * 2048); time.sleep(30)"
        )

        with (
            mock.patch.object(environment_module, "CODEX_PROBE_MAX_OUTPUT_BYTES", 1024),
            self.assertRaises(EnvironmentPolicyError) as raised,
        ):
            environment_module._bounded_codex_probe(
                sys.executable,
                ("-c", probe),
                root=self.root,
                environment={},
            )

        self.assertEqual(str(raised.exception), "codex_probe_output_exceeds_limit")
        pgid = self._record_pgid(pgid_path)
        self._assert_group_gone(pgid)
        time.sleep(1)
        self.assertFalse(marker.exists())

    def test_codex_probe_timeout_stops_its_entire_group(self) -> None:
        marker = self.root / "probe-timeout-descendant-survived"
        pgid_path = self.root / "probe-timeout.pgid"
        descendant = self._delayed_marker_program(marker)
        probe = (
            "import os, subprocess, sys, time; from pathlib import Path; "
            f"Path({str(pgid_path)!r}).write_text(str(os.getpgrp()), encoding='utf-8'); "
            f"subprocess.Popen([sys.executable, '-c', {descendant!r}]); "
            "time.sleep(30)"
        )

        with self.assertRaises(EnvironmentPolicyError) as raised:
            environment_module._bounded_codex_probe(
                sys.executable,
                ("-c", probe),
                root=self.root,
                environment={},
                timeout_seconds=0.2,
            )

        self.assertEqual(str(raised.exception), "codex_probe_unavailable")
        pgid = self._record_pgid(pgid_path)
        self._assert_group_gone(pgid)
        time.sleep(1)
        self.assertFalse(marker.exists())

    def test_codex_probe_capture_failure_stops_its_entire_group(self) -> None:
        marker = self.root / "probe-capture-descendant-survived"
        pgid_path = self.root / "probe-capture.pgid"
        descendant = self._delayed_marker_program(marker)
        probe = (
            "import os, subprocess, sys, time; from pathlib import Path; "
            f"Path({str(pgid_path)!r}).write_text(str(os.getpgrp()), encoding='utf-8'); "
            f"subprocess.Popen([sys.executable, '-c', {descendant!r}]); "
            "os.write(1, b'ready'); time.sleep(30)"
        )

        selector_type = environment_module.selectors.DefaultSelector

        class FailingSelector:
            def __init__(self) -> None:
                self.delegate = selector_type()

            def register(self, *args, **kwargs):
                return self.delegate.register(*args, **kwargs)

            def select(self, timeout=None):
                events = self.delegate.select(timeout)
                if events:
                    raise OSError("simulated capture failure")
                return events

            def close(self) -> None:
                self.delegate.close()

        with (
            mock.patch.object(
                environment_module.selectors,
                "DefaultSelector",
                FailingSelector,
            ),
            self.assertRaises(EnvironmentPolicyError) as raised,
        ):
            environment_module._bounded_codex_probe(
                sys.executable,
                ("-c", probe),
                root=self.root,
                environment={},
            )

        self.assertEqual(str(raised.exception), "codex_probe_capture_failed")
        pgid = self._record_pgid(pgid_path)
        self._assert_group_gone(pgid)
        time.sleep(1)
        self.assertFalse(marker.exists())

    def test_abnormal_probe_cleans_descendant_that_closed_capture_pipe(self) -> None:
        marker = self.root / "probe-abnormal-descendant-survived"
        pgid_path = self.root / "probe-abnormal.pgid"
        descendant = self._delayed_marker_program(marker)
        probe = (
            "import os, subprocess, sys; from pathlib import Path; "
            f"Path({str(pgid_path)!r}).write_text(str(os.getpgrp()), encoding='utf-8'); "
            "subprocess.Popen("
            f"[sys.executable, '-c', {descendant!r}], "
            "stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL); "
            "raise SystemExit(3)"
        )

        with self.assertRaises(EnvironmentPolicyError) as raised:
            environment_module._bounded_codex_probe(
                sys.executable,
                ("-c", probe),
                root=self.root,
                environment={},
            )

        self.assertEqual(
            str(raised.exception), "codex_probe_process_group_outlived_leader"
        )
        pgid = self._record_pgid(pgid_path)
        self._assert_group_gone(pgid)
        time.sleep(1)
        self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
