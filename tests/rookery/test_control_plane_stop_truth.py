from __future__ import annotations

# ruff: noqa: E402

import io
import os
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from tests.rookery.test_acceptance_campaign import context, make_workspace

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
LIB = REPOSITORY_ROOT / "rookery" / "lib"
if str(LIB) not in os.sys.path:
    os.sys.path.insert(0, str(LIB))
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

from rookery.portable import cli as cli_module
from rookery.portable.cli import build_parser, cmd_go
from rookery.portable.control import resume, stop
from rookery.portable.reducers import reduce_events
from rookery.portable.scoring import admission_snapshot_in_transaction
from rookery.portable.scope import _scope_generations
from rookery.portable.status import read_snapshot, refresh_snapshot


class ControlTransitionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.workspace = make_workspace("fixture")
        self.root = Path(self.workspace.name)
        self.manifest, self.scope, self.store, self.result = context(
            self.root, "fixture"
        )

    def tearDown(self) -> None:
        self.workspace.cleanup()

    def test_invalid_resume_rows_fail_closed_in_reducer_and_scoring_snapshot(self) -> None:
        stop(self.store, self.root, reason="fixture stop", wait_seconds=0)
        invalid_rows = (
            {"reason": "stale", "generation": 0},
            {"reason": "", "generation": 1},
            {"reason": "non-operator", "generation": 1},
            {"reason": "malformed", "generation": "1"},
        )
        for index, payload in enumerate(invalid_rows):
            with self.subTest(payload=payload):
                actor = "operator" if index != 2 else "solver"
                self.store.append(
                    "control.resume",
                    payload,
                    actor=actor,
                    generation=1,
                    event_id=f"invalid-resume-{index}",
                )
                events = self.store.events()
                self.assertTrue(reduce_events(events, self.store)["current"]["stopped"])
                snapshot = self.store.transaction(admission_snapshot_in_transaction)
                self.assertTrue(snapshot["stopped"])
                self.assertTrue(_scope_generations(self.root)[2])

    def test_stop_and_resume_have_one_lock_defined_order(self) -> None:
        entered = threading.Event()
        release = threading.Event()
        original_transaction = self.store.transaction

        def pause_resume(callback):
            entered.set()
            self.assertTrue(release.wait(timeout=5))
            return original_transaction(callback)

        result: list[int] = []
        with mock.patch.object(self.store, "transaction", side_effect=pause_resume):
            resume_thread = threading.Thread(
                target=lambda: result.append(resume(self.store, reason="operator resume"))
            )
            resume_thread.start()
            self.assertTrue(entered.wait(timeout=5))
            stop_thread = threading.Thread(
                target=lambda: stop(
                    self.store, self.root, reason="newer stop", wait_seconds=0
                )
            )
            stop_thread.start()
            release.set()
            resume_thread.join(timeout=5)
            stop_thread.join(timeout=5)

        self.assertFalse(resume_thread.is_alive())
        self.assertFalse(stop_thread.is_alive())
        self.assertEqual(result, [0])
        self.assertTrue(self.store.rebuild()["current"]["stopped"])
        controls = [
            (event["event_type"], event["generation"])
            for event in self.store.events()
            if event["event_type"].startswith("control.")
        ]
        self.assertEqual(controls, [("control.resume", 0), ("control.stop", 1)])

    def test_later_stop_reconciles_prior_unacknowledged_job_only_with_identity_proof(self) -> None:
        payload = {
            "job_id": "prior-unacknowledged",
            "pid": 4321,
            "pgid": 4321,
            "process_starttime": "fixture",
            "owner_token": "fixture-owner",
        }
        self.store.append("job.unacknowledged", payload, actor="fixture")
        with (
            mock.patch(
                "rookery.portable.control.process_identity_matches",
                side_effect=(True, False),
            ),
            mock.patch("rookery.portable.control.os.killpg") as killpg,
        ):
            outcome = stop(
                self.store, self.root, reason="later stop", wait_seconds=0
            )

        killpg.assert_called_once()
        self.assertEqual(outcome["signalled_pids"], [4321])
        self.assertEqual(
            self.store.events("job.cancelled")[-1]["payload"]["job_id"],
            payload["job_id"],
        )


class StatusFreshnessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.workspace = make_workspace("fixture")
        self.root = Path(self.workspace.name)
        self.manifest, self.scope, self.store, self.result = context(
            self.root, "fixture"
        )

    def tearDown(self) -> None:
        self.workspace.cleanup()

    def test_cached_ready_becomes_stopped_after_canonical_stop_without_writes(self) -> None:
        initial = refresh_snapshot(self.store, self.root, self.manifest, self.result)
        self.assertEqual(initial["lifecycle_state"], "ready")
        stop(self.store, self.root, reason="crash boundary", wait_seconds=0)
        before = {
            path.relative_to(self.root): path.read_bytes()
            for path in (self.root / "state").iterdir()
            if path.is_file()
        }

        status = read_snapshot(self.root)

        after = {
            path.relative_to(self.root): path.read_bytes()
            for path in (self.root / "state").iterdir()
            if path.is_file()
        }
        self.assertEqual(status["lifecycle_state"], "stopped")
        self.assertTrue(status["stopped"])
        self.assertEqual(status["stop_generation"], 1)
        self.assertEqual(before, after)

    def test_wal_blocks_cached_ready_without_writing(self) -> None:
        initial = refresh_snapshot(self.store, self.root, self.manifest, self.result)
        self.assertEqual(initial["lifecycle_state"], "ready")
        wal = self.root / "state" / "events.sqlite3-wal"
        wal.write_bytes(b"status must not open a live WAL")
        before = wal.read_bytes()

        status = read_snapshot(self.root)

        self.assertEqual(status["lifecycle_state"], "blocked")
        self.assertIn("canonical status freshness", " | ".join(status["blockers"]))
        self.assertEqual(wal.read_bytes(), before)


class LaunchStopBarrierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.workspace = make_workspace("fixture")
        self.root = Path(self.workspace.name)
        self.manifest, self.scope, self.store, self.result = context(
            self.root, "fixture"
        )
        self.gate = SimpleNamespace(
            preparation_environment=SimpleNamespace(values={}),
            stage_c_environments={},
            strict_config_supported=True,
        )

    def tearDown(self) -> None:
        self.workspace.cleanup()

    def _bootstrap(self, _root: Path):
        return self.gate, object(), self.store, self.manifest, self.scope, self.result

    def test_stop_during_preparation_prevents_scope_and_adapter_handoff(self) -> None:
        sync = mock.Mock(return_value={"capabilities": {}, "challenges": []})
        adapter = SimpleNamespace(sync=sync)
        real_persist = cli_module._persist_compiled_scope
        persist_calls = 0

        def stop_before_post_preparation_scope(*args, **kwargs):
            nonlocal persist_calls
            persist_calls += 1
            if persist_calls == 2:
                stop(self.store, self.root, reason="interleaved stop", wait_seconds=0)
            return real_persist(*args, **kwargs)

        output = io.StringIO()
        with (
            mock.patch.object(cli_module, "workspace_root", return_value=self.root),
            mock.patch.object(cli_module, "_bootstrap_launch", side_effect=self._bootstrap),
            mock.patch.object(cli_module, "_record_measurement_started"),
            mock.patch.object(
                cli_module,
                "prepare",
                return_value={"ready": True, "capabilities": [], "services": {}},
            ),
            mock.patch.object(
                cli_module,
                "_persist_compiled_scope",
                side_effect=stop_before_post_preparation_scope,
            ),
            mock.patch.object(cli_module, "get_adapter", return_value=adapter),
            redirect_stdout(output),
        ):
            code = cmd_go(build_parser().parse_args(["go"]))

        self.assertEqual(code, 2)
        self.assertFalse(sync.called)
        self.assertFalse((self.root / "START_PROMPT.md").exists())
        self.assertTrue(self.store.rebuild()["current"]["stopped"])

    def test_stop_after_ready_snapshot_prevents_start_prompt_and_ready_return(self) -> None:
        sync = mock.Mock(return_value={"capabilities": {}, "challenges": []})
        adapter = SimpleNamespace(sync=sync)
        real_publish = cli_module._publish_start_prompt_and_attempt

        def stop_before_prompt(*args, **kwargs):
            stop(self.store, self.root, reason="late interleaved stop", wait_seconds=0)
            return real_publish(*args, **kwargs)

        output = io.StringIO()
        with (
            mock.patch.object(cli_module, "workspace_root", return_value=self.root),
            mock.patch.object(cli_module, "_bootstrap_launch", side_effect=self._bootstrap),
            mock.patch.object(cli_module, "_record_measurement_started"),
            mock.patch.object(
                cli_module,
                "prepare",
                return_value={"ready": True, "capabilities": [], "services": {}},
            ),
            mock.patch.object(cli_module, "get_adapter", return_value=adapter),
            mock.patch.object(
                cli_module,
                "refresh_snapshot",
                return_value={"lifecycle_state": "ready", "stopped": False},
            ),
            mock.patch.object(
                cli_module,
                "_publish_start_prompt_and_attempt",
                side_effect=stop_before_prompt,
            ),
            redirect_stdout(output),
        ):
            code = cmd_go(build_parser().parse_args(["go"]))

        self.assertEqual(code, 2)
        self.assertFalse((self.root / "START_PROMPT.md").exists())
        self.assertTrue(self.store.rebuild()["current"]["stopped"])


class EmergencyMetadataContainmentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.workspace = make_workspace("fixture")
        self.root = Path(self.workspace.name)
        _manifest, _scope, self.store, _result = context(self.root, "fixture")
        self.store.append(
            "job.running",
            {"job_id": "job-safe", "pid": 0, "status": "running"},
            actor="fixture",
        )
        self.outside_temporary = tempfile.TemporaryDirectory()
        self.outside = Path(self.outside_temporary.name) / "outside"
        self.outside.mkdir()
        self.victim = self.outside / "job-safe" / "meta.json"
        self.victim.parent.mkdir()
        self.original = b'{"sentinel":"outside-root","status":"running"}\n'
        self.victim.write_bytes(self.original)
        self.victim.chmod(0o600)

    def tearDown(self) -> None:
        self.outside_temporary.cleanup()
        self.workspace.cleanup()

    def test_emergency_stop_skips_symlinked_job_metadata_without_losing_revocation(self) -> None:
        jobs = self.root / "logs" / "jobs"
        jobs.parent.mkdir(parents=True, exist_ok=True)
        os.symlink(self.outside, jobs, target_is_directory=True)

        outcome = stop(self.store, self.root, reason="emergency metadata safety", wait_seconds=0)

        self.assertEqual(self.victim.read_bytes(), self.original)
        self.assertEqual(outcome["generation"], 1)
        self.assertTrue(self.store.events("control.stop"))

    def test_metadata_update_rejects_symlinked_job_and_metadata_components(self) -> None:
        for unsafe_component in ("job", "metadata"):
            with self.subTest(unsafe_component=unsafe_component):
                workspace = make_workspace("fixture")
                outside_temporary = tempfile.TemporaryDirectory()
                root = Path(workspace.name)
                try:
                    _manifest, _scope, store, _result = context(root, "fixture")
                    job = {
                        "job_id": "job-safe",
                        "pid": 0,
                        "status": "running",
                    }
                    store.append("job.running", job, actor="fixture")
                    outside = Path(outside_temporary.name) / "outside"
                    victim = outside / "job-safe" / "meta.json"
                    victim.parent.mkdir(parents=True)
                    original = b'{"sentinel":"outside-root","status":"running"}\n'
                    victim.write_bytes(original)
                    victim.chmod(0o600)
                    jobs = root / "logs" / "jobs"
                    jobs.mkdir(parents=True)
                    if unsafe_component == "job":
                        os.symlink(
                            victim.parent,
                            jobs / job["job_id"],
                            target_is_directory=True,
                        )
                    else:
                        (jobs / job["job_id"]).mkdir()
                        os.symlink(victim, jobs / job["job_id"] / "meta.json")

                    outcome = stop(
                        store, root, reason="metadata link safety", wait_seconds=0
                    )

                    self.assertEqual(victim.read_bytes(), original)
                    self.assertEqual(outcome["generation"], 1)
                    self.assertTrue(store.events("control.stop"))
                finally:
                    outside_temporary.cleanup()
                    workspace.cleanup()
