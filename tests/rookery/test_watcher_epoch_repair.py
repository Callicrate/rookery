from __future__ import annotations

# ruff: noqa: E402

import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from tests.rookery.support import ROOKERY_ROOT

LIB = ROOKERY_ROOT / "lib"
if str(LIB) not in sys.path:
    sys.path.insert(0, str(LIB))
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

from rookery.portable.control import process_identity_matches, resume, stop
from rookery.portable.store import EventStore
from rookery.portable.watchers import ensure_queue_watcher, watcher_lease_is_current


@unittest.skipUnless(os.name == "posix", "requires POSIX process identity")
class WatcherEpochRepairTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory(prefix="rookery-watcher-epoch-")
        self.root = Path(self.tempdir.name)
        self.store = EventStore(self.root)
        self.children: list[subprocess.Popen[bytes]] = []

    def tearDown(self) -> None:
        for child in self.children:
            # The watcher starter deliberately clears its local Popen lifecycle
            # handle after registration, so ``child.poll()`` can report its
            # synthetic return code while this test child is still alive.
            try:
                os.killpg(os.getpgid(child.pid), signal.SIGKILL)
            except (ProcessLookupError, subprocess.TimeoutExpired):
                pass
            try:
                child.wait(timeout=2)
            except (ProcessLookupError, subprocess.TimeoutExpired):
                pass
        self.tempdir.cleanup()

    def _term_resistant_watcher_popen(self, ready_path: Path):
        original_popen = subprocess.Popen

        def fake_popen(command, **kwargs):
            environment = dict(kwargs["env"])
            environment["ROOKERY_TEST_READY_PATH"] = str(ready_path)
            kwargs["env"] = environment
            token = command[command.index("--owner-token") + 1]
            epoch = int(command[command.index("--watcher-epoch") + 1])
            self.assertTrue(watcher_lease_is_current(self.store, token, epoch))
            child = original_popen(
                [
                    sys.executable,
                    "-c",
                    (
                        "import os, signal, time; from pathlib import Path; "
                        "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                        "Path(os.environ['ROOKERY_TEST_READY_PATH']).write_text('ready'); "
                        "time.sleep(60)"
                    ),
                ],
                **kwargs,
            )
            self.children.append(child)
            return child

        return fake_popen

    def _wait_for_ready_child(self, ready_path: Path) -> None:
        deadline = time.monotonic() + 2
        while not ready_path.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertTrue(ready_path.exists(), "TERM-resistant child did not become ready")

    def _ordinary_watcher_popen(self, ready_path: Path):
        original_popen = subprocess.Popen

        def fake_popen(command, **kwargs):
            environment = dict(kwargs["env"])
            environment["ROOKERY_TEST_READY_PATH"] = str(ready_path)
            kwargs["env"] = environment
            child = original_popen(
                [
                    sys.executable,
                    "-c",
                    (
                        "import os, time; from pathlib import Path; "
                        "Path(os.environ['ROOKERY_TEST_READY_PATH']).write_text('ready'); "
                        "time.sleep(60)"
                    ),
                ],
                **kwargs,
            )
            self.children.append(child)
            return child

        return fake_popen

    def _owned_starting_watcher(self, job_id: str, *, starttime: str | None = None):
        """Model a crash after Popen but before the job.running append."""

        token = f"queuewatch_{job_id}"
        child = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            cwd=self.root,
            start_new_session=True,
            env={**os.environ, "ROOKERY_OWNER_TOKEN": token},
        )
        self.children.append(child)
        actual_starttime = Path(f"/proc/{child.pid}/stat").read_text().split()[21]
        payload = {
            "job_id": job_id,
            "kind": "queue-watcher",
            "owner": "go",
            "owner_token": token,
            "watcher_epoch": 0,
            "pid": child.pid,
            "pgid": os.getpgid(child.pid),
            "process_starttime": starttime or actual_starttime,
            "started_at": "2026-08-29T00:00:00Z",
        }
        self.store.append("job.starting", payload, actor="go")
        self.store.rebuild()
        return child, payload

    def test_stop_signals_exact_owned_starting_watcher_after_startup_crash(self) -> None:
        child, payload = self._owned_starting_watcher("starting-owned")

        stopped = stop(
            self.store,
            self.root,
            reason="startup crash window",
            wait_seconds=0.5,
        )

        child.wait(timeout=2)
        self.assertEqual(stopped["signalled_pids"], [child.pid])
        self.assertEqual(stopped["confirmed_cancelled"], [payload["job_id"]])
        self.assertEqual(stopped["unacknowledged"], [])
        self.assertEqual(stopped["unmanaged"], [])
        self.assertEqual(self.store.events("job.stopping")[-1]["payload"]["job_id"], payload["job_id"])
        self.assertEqual(self.store.events("job.cancelled")[-1]["payload"]["job_id"], payload["job_id"])

    def test_stop_never_signals_starting_watcher_with_mismatched_identity(self) -> None:
        child, payload = self._owned_starting_watcher(
            "starting-mismatch", starttime="not-the-child-starttime"
        )

        stopped = stop(
            self.store,
            self.root,
            reason="startup identity mismatch",
            wait_seconds=0,
        )

        self.assertIsNone(child.poll())
        self.assertEqual(stopped["signalled_pids"], [])
        self.assertEqual(stopped["confirmed_cancelled"], [])
        self.assertEqual(stopped["unacknowledged"], [])
        self.assertEqual(stopped["unmanaged"], [payload["job_id"]])
        self.assertEqual(self.store.events("job.unmanaged")[-1]["payload"]["job_id"], payload["job_id"])
        self.assertEqual(self.store.events("job.unmanaged")[-1]["payload"]["reason"], "no verifiable Rookery-owned process identity; closure is unknown")

    def test_real_launch_checkpoint_survives_running_publication_failure_for_stop(self) -> None:
        ready_path = self.root / "checkpoint-ready"
        manifest = {"queue": {"automation_enabled": True, "watch_interval_seconds": 1}}
        original_append = self.store.append

        def fail_running(event_type, payload, **kwargs):
            if event_type == "job.running":
                raise RuntimeError("simulated crash after identity checkpoint")
            return original_append(event_type, payload, **kwargs)

        with (
            mock.patch(
                "rookery.portable.watchers.subprocess.Popen",
                side_effect=self._ordinary_watcher_popen(ready_path),
            ),
            mock.patch.object(self.store, "append", side_effect=fail_running),
            self.assertRaisesRegex(RuntimeError, "identity checkpoint"),
        ):
            ensure_queue_watcher(self.store, self.root, manifest)

        self._wait_for_ready_child(ready_path)
        starting = self.store.events("job.starting")
        self.assertEqual(len(starting), 2)
        checkpoint = starting[-1]["payload"]
        self.assertTrue(process_identity_matches(self.root, checkpoint))
        self.assertFalse(self.store.events("job.running"))

        stopped = stop(
            self.store,
            self.root,
            reason="crash after identity checkpoint",
            wait_seconds=0.5,
        )

        child = self.children[-1]
        child.wait(timeout=2)
        self.assertEqual(stopped["signalled_pids"], [child.pid])
        self.assertEqual(stopped["confirmed_cancelled"], [checkpoint["job_id"]])
        self.assertFalse(stopped["unmanaged"])
        self.assertFalse(stopped["unacknowledged"])

    def test_checkpoint_publication_failure_stops_only_verified_child(self) -> None:
        ready_path = self.root / "checkpoint-failure-ready"
        manifest = {"queue": {"automation_enabled": True, "watch_interval_seconds": 1}}
        original_append = self.store.append

        def fail_identity_checkpoint(event_type, payload, **kwargs):
            if event_type == "job.starting" and payload.get("pid"):
                raise RuntimeError("simulated identity checkpoint failure")
            return original_append(event_type, payload, **kwargs)

        with (
            mock.patch(
                "rookery.portable.watchers.subprocess.Popen",
                side_effect=self._ordinary_watcher_popen(ready_path),
            ),
            mock.patch.object(self.store, "append", side_effect=fail_identity_checkpoint),
            self.assertRaisesRegex(RuntimeError, "identity checkpoint failure"),
        ):
            ensure_queue_watcher(self.store, self.root, manifest)

        child = self.children[-1]
        child.wait(timeout=2)
        self.assertEqual(len(self.store.events("job.starting")), 1)
        self.assertNotIn("pid", self.store.events("job.starting")[-1]["payload"])
        self.assertFalse(self.store.events("job.running"))
        job_id = self.store.events("job.failed")[-1]["payload"]["job_id"]
        self.assertEqual(job_id, self.store.events("job.starting")[-1]["payload"]["job_id"])
        current = self.store.rebuild()["current"]["jobs"][job_id]
        self.assertEqual(current["status"], "failed")
        self.assertNotIn("pid", current)

    def test_identity_failure_keeps_starting_record_identity_free_and_unsignalled(self) -> None:
        ready_path = self.root / "identity-failure-ready"
        manifest = {"queue": {"automation_enabled": True, "watch_interval_seconds": 1}}
        with (
            mock.patch(
                "rookery.portable.watchers.subprocess.Popen",
                side_effect=self._ordinary_watcher_popen(ready_path),
            ),
            mock.patch(
                "rookery.portable.watchers.process_identity_matches",
                return_value=False,
            ),
            self.assertRaisesRegex(RuntimeError, "not observable before identity checkpoint"),
        ):
            ensure_queue_watcher(self.store, self.root, manifest)

        self._wait_for_ready_child(ready_path)
        child = self.children[-1]
        self.assertIsNone(child.poll())
        self.assertEqual(len(self.store.events("job.starting")), 1)
        self.assertNotIn("pid", self.store.events("job.starting")[-1]["payload"])
        self.assertFalse(self.store.events("job.running"))
        self.assertEqual(self.store.events("job.failed")[-1]["payload"]["job_id"], self.store.events("job.starting")[-1]["payload"]["job_id"])

    def test_stop_unacknowledged_watcher_blocks_resume_replacement(self) -> None:
        ready_path = self.root / "term-resistant-ready"
        manifest = {"queue": {"automation_enabled": True, "watch_interval_seconds": 1}}
        with mock.patch(
            "rookery.portable.watchers.subprocess.Popen",
            side_effect=self._term_resistant_watcher_popen(ready_path),
        ) as popen:
            first = ensure_queue_watcher(self.store, self.root, manifest)
            self._wait_for_ready_child(ready_path)
            self.assertTrue(
                watcher_lease_is_current(
                    self.store,
                    first["job"]["owner_token"],
                    first["job"]["watcher_epoch"],
                )
            )

            stopped = stop(self.store, self.root, reason="TERM-resistant test", wait_seconds=0)
            self.assertEqual(stopped["unacknowledged"], [first["job"]["job_id"]])
            self.assertEqual(self.store.get_meta("watcher_epoch"), "1")
            self.assertEqual(
                self.store.events("control.stop")[-1]["payload"]["watcher_epoch"],
                1,
            )
            self.assertFalse(
                watcher_lease_is_current(
                    self.store,
                    first["job"]["owner_token"],
                    first["job"]["watcher_epoch"],
                )
            )

            resume(self.store, reason="explicit test resume")
            replacement = ensure_queue_watcher(self.store, self.root, manifest)

        self.assertFalse(replacement["running"])
        self.assertEqual(replacement["reason"], "blocked by residual watcher")
        self.assertEqual(replacement["job"]["job_id"], first["job"]["job_id"])
        self.assertEqual(popen.call_count, 1)

    def test_stale_watcher_lease_check_is_read_only_and_remains_invalid_after_resume(self) -> None:
        token = "queuewatch_test_lease"
        self.store.append(
            "job.running",
            {
                "job_id": "watcher-lease",
                "kind": "queue-watcher",
                "owner_token": token,
                "watcher_epoch": 0,
                "pid": 0,
                "pgid": 0,
                "process_starttime": "",
            },
            actor="test",
        )
        self.store.rebuild()
        count_before = self.store.count()
        self.assertTrue(watcher_lease_is_current(self.store, token, 0))
        self.assertEqual(self.store.count(), count_before)

        stop(self.store, self.root, reason="invalidate watcher lease", wait_seconds=0)
        resume(self.store, reason="explicit test resume")
        count_before_stale_check = self.store.count()
        self.assertFalse(watcher_lease_is_current(self.store, token, 0))
        self.assertEqual(self.store.count(), count_before_stale_check)


if __name__ == "__main__":
    unittest.main()
