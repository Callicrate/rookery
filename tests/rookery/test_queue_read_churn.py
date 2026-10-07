from __future__ import annotations

# ruff: noqa: E402

import argparse
import datetime as dt
import json
import os
import stat
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from tests.rookery.support import ROOKERY_ROOT

LIB = ROOKERY_ROOT / "lib"
if str(LIB) not in sys.path:
    sys.path.insert(0, str(LIB))
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

from rookery.portable import cli
from rookery.portable.manifest import env_overlay
from rookery.portable.queue import persist_schedules
from rookery.portable.store import EventStore
from rookery.portable.util import parse_iso


class QueueReadChurnTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="rookery-queue-churn-")
        self.root = Path(self.temporary.name)
        self.store = EventStore(self.root)
        self.manifest = {
            "adapter": {"id": "fixture"},
            "queue": {
                "automation_enabled": True,
                "cadence_seconds": 0,
                "jitter_seconds": 0,
            },
        }
        self.args = argparse.Namespace(auto_execute=False, quiet=True)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _add_pending(self, count: int, *, schedules: bool) -> None:
        for index in range(count):
            proposal_id = f"proposal-{index:03d}"
            self.store.append(
                "proposal.created",
                {
                    "proposal_id": proposal_id,
                    "objective_id": "101",
                    "action_kind": "flag",
                    "exact_value": f"FIXTURE{{queue-{index}}}",
                    "adapter_id": "fixture",
                    "stop_generation": 0,
                },
                actor="fixture",
                event_id=f"proposal:{proposal_id}",
            )
            self.store.append(
                "review.recorded",
                {"proposal_id": proposal_id, "verdict": "approved"},
                actor="reviewer",
                event_id=f"review:{proposal_id}",
            )
            if schedules:
                self.store.append(
                    "queue.scheduled",
                    {
                        "proposal_id": proposal_id,
                        "scheduled_at": "2999-01-01T00:00:00Z",
                    },
                    actor="queue",
                    event_id=f"schedule:{proposal_id}",
                )

    def _advance_stop_generation(self) -> None:
        """Advance stop in one transaction without involving an OS process."""

        def advance(connection):
            generation = self.store.increment_meta_in_transaction(
                connection, "stop_generation"
            )
            watcher_epoch = self.store.increment_meta_in_transaction(
                connection, "watcher_epoch"
            )
            self.store.insert_in_transaction(
                connection,
                "control.stop",
                {
                    "reason": "queue snapshot barrier fixture",
                    "generation": generation,
                    "watcher_epoch": watcher_epoch,
                },
                actor="fixture",
                generation=generation,
            )

        self.store.transaction(advance)

    @staticmethod
    def _projection_identity(root: Path) -> dict[str, tuple[int, int]]:
        return {
            name: (
                (root / "state" / name).stat().st_ino,
                (root / "state" / name).stat().st_mtime_ns,
            )
            for name in (
                "events.jsonl",
                "runtime.json",
                "current.json",
                "policy_effective.json",
                "queue_state.json",
            )
        }

    def test_warm_ticks_take_one_read_snapshot_independent_of_queue_depth(self) -> None:
        for depth in (0, 1, 25, 100):
            with self.subTest(depth=depth):
                self._add_pending(depth, schedules=True)
                self.store.rebuild()
                before_count = self.store.count()
                before_files = self._projection_identity(self.root)
                statements: list[str] = []
                original_connect = self.store._connect

                def traced_connect(
                    original_connect=original_connect, statements=statements
                ):
                    connection = original_connect()
                    connection.set_trace_callback(statements.append)
                    return connection

                with (
                    mock.patch.object(
                        self.store, "_connect", side_effect=traced_connect
                    ),
                    mock.patch.object(
                        self.store, "read_snapshot", wraps=self.store.read_snapshot
                    ) as snapshots,
                    mock.patch(
                        "rookery.portable.store.atomic_write_json",
                        wraps=cli.atomic_write_json,
                    ) as json_writes,
                    mock.patch(
                        "rookery.portable.store.atomic_write_text",
                        wraps=cli.atomic_write_text,
                    ) as text_writes,
                ):
                    for _ in range(1_000):
                        result, output, queue = cli._queue_tick(
                            self.root, self.manifest, {}, self.store, self.args
                        )
                        self.assertEqual(result, 0)
                        self.assertEqual(output["reason"], "no eligible item")
                        self.assertEqual(queue["depth"], depth)

                self.assertEqual(snapshots.call_count, 1_000)
                self.assertFalse(
                    any(
                        "BEGIN IMMEDIATE" in statement.upper()
                        for statement in statements
                    )
                )
                self.assertEqual(json_writes.call_count, 0)
                self.assertEqual(text_writes.call_count, 0)
                self.assertEqual(self.store.count(), before_count)
                self.assertEqual(self._projection_identity(self.root), before_files)

                # Each subtest shares a store so its fixture events do not leak
                # into the next depth's expected queue size.
                self.temporary.cleanup()
                self.temporary = tempfile.TemporaryDirectory(
                    prefix="rookery-queue-churn-"
                )
                self.root = Path(self.temporary.name)
                self.store = EventStore(self.root)

    def test_cold_schedule_batch_is_single_mutation_then_warm_tick_is_read_only(
        self,
    ) -> None:
        self._add_pending(25, schedules=False)
        before = self.store.count()
        initial = self.store.read_snapshot()
        with (
            mock.patch.object(
                self.store, "append_many", wraps=self.store.append_many
            ) as batches,
            mock.patch.object(
                self.store, "rebuild", wraps=self.store.rebuild
            ) as rebuilds,
        ):
            queue = persist_schedules(self.store, self.manifest, snapshot=initial)

        self.assertEqual(queue["depth"], 25)
        self.assertEqual(batches.call_count, 1)
        self.assertEqual(rebuilds.call_count, 1)
        self.assertEqual(self.store.count() - before, 25)
        self.assertEqual(len(self.store.events("queue.scheduled")), 25)

        with (
            mock.patch.object(
                self.store, "append_many", wraps=self.store.append_many
            ) as batches,
            mock.patch.object(
                self.store, "rebuild", wraps=self.store.rebuild
            ) as rebuilds,
        ):
            persist_schedules(self.store, self.manifest)
        self.assertEqual(batches.call_count, 0)
        self.assertEqual(rebuilds.call_count, 0)

    def test_backlog_schedules_are_serialized_and_restart_stable(self) -> None:
        self.manifest["queue"].update(cadence_seconds=30, jitter_seconds=7)
        self._add_pending(3, schedules=False)

        first = persist_schedules(self.store, self.manifest)
        by_id = {item["proposal_id"]: item for item in first["items"]}
        scheduled = [
            parse_iso(by_id[f"proposal-{index:03d}"]["scheduled_at"])
            for index in range(3)
        ]
        self.assertTrue(all(value is not None for value in scheduled))
        for earlier, later in zip(scheduled[:-1], scheduled[1:], strict=True):
            spacing = int((later - earlier).total_seconds())
            self.assertGreaterEqual(spacing, 30)
            self.assertLessEqual(spacing, 37)

        event_count = len(self.store.events("queue.scheduled"))
        restarted = persist_schedules(EventStore(self.root), self.manifest)
        restarted_by_id = {
            item["proposal_id"]: item["scheduled_at"] for item in restarted["items"]
        }
        self.assertEqual(
            restarted_by_id,
            {key: item["scheduled_at"] for key, item in by_id.items()},
        )
        self.assertEqual(len(self.store.events("queue.scheduled")), event_count)

    def test_remaining_backlog_rebases_after_execution(self) -> None:
        self.manifest["queue"].update(cadence_seconds=20, jitter_seconds=0)
        self._add_pending(3, schedules=False)
        first = persist_schedules(self.store, self.manifest)
        before = {
            item["proposal_id"]: parse_iso(item["scheduled_at"])
            for item in first["items"]
        }
        executed_at = before["proposal-000"] + dt.timedelta(seconds=1)
        executed_stamp = executed_at.isoformat().replace("+00:00", "Z")
        with mock.patch("rookery.portable.store.iso_now", return_value=executed_stamp):
            self.store.append(
                "execution.planned",
                {"plan_id": "plan-000", "proposal_id": "proposal-000"},
                event_id="plan:000",
            )
            self.store.append(
                "execution.completed",
                {"plan_id": "plan-000", "proposal_id": "proposal-000"},
                event_id="execution:000",
            )

        rebased = persist_schedules(self.store, self.manifest)
        after = {
            item["proposal_id"]: parse_iso(item["scheduled_at"])
            for item in rebased["items"]
        }
        self.assertEqual(set(after), {"proposal-001", "proposal-002"})
        self.assertEqual(
            int((after["proposal-001"] - executed_at).total_seconds()), 20
        )
        self.assertEqual(
            int(
                (after["proposal-002"] - after["proposal-001"]).total_seconds()
            ),
            20,
        )
        self.assertGreater(after["proposal-001"], before["proposal-001"])
        self.assertEqual(len(self.store.events("queue.scheduled")), 5)

        stable = persist_schedules(EventStore(self.root), self.manifest)
        self.assertEqual(
            {item["proposal_id"]: item["scheduled_at"] for item in stable["items"]},
            {item["proposal_id"]: item["scheduled_at"] for item in rebased["items"]},
        )
        self.assertEqual(len(self.store.events("queue.scheduled")), 5)

    def test_queue_jitter_environment_override_is_numeric(self) -> None:
        overlay = env_overlay({"QUEUE_JITTER_SECONDS": "9"})
        self.assertEqual(overlay["queue"]["jitter_seconds"], 9)
        self.assertIsInstance(overlay["queue"]["jitter_seconds"], int)

    def test_stop_after_watcher_snapshot_blocks_cold_schedule_plan_and_adapter(
        self,
    ) -> None:
        self._add_pending(1, schedules=False)
        proposal_id = "proposal-000"
        self.store.append(
            "authorization.granted",
            {
                "authorization_id": "authorization-queue-stop-race",
                "mode": "exact",
                "proposal_id": proposal_id,
                "action_kind": "flag",
                "remaining": 1,
                "stop_generation": 0,
                "policy_generation": 0,
            },
            actor="fixture",
            event_id="authorization:queue-stop-race",
        )
        self.store.append(
            "job.running",
            {
                "job_id": "watcher-stop-race",
                "kind": "queue-watcher",
                "owner_token": "queuewatch-stop-race",
                "watcher_epoch": 0,
            },
            actor="fixture",
            event_id="job:watcher-stop-race",
        )
        args = argparse.Namespace(
            queue_action="watch",
            auto_execute=True,
            interval=1,
            once=True,
            owner_token="queuewatch-stop-race",
            watcher_epoch=0,
            diagnostic=False,
            quiet=True,
            heartbeat_seconds=300,
        )
        original_append_many = self.store.append_many

        def stop_then_append_many(events, *args, **kwargs):
            self._advance_stop_generation()
            return original_append_many(events, *args, **kwargs)

        with (
            mock.patch.object(cli, "workspace_root", return_value=self.root),
            mock.patch.object(
                cli, "load_context", return_value=(self.manifest, {}, self.store, None)
            ),
            mock.patch.object(
                self.store, "append_many", side_effect=stop_then_append_many
            ) as batches,
            mock.patch.object(cli, "compile_plan") as compile_plan,
            mock.patch.object(cli, "execute_plan") as execute_plan,
            mock.patch("builtins.print"),
        ):
            self.assertEqual(cli.cmd_queue(args), 0)

        self.assertEqual(batches.call_count, 1)
        self.assertEqual(self.store.current_stop_generation(), 1)
        self.assertFalse(self.store.events("queue.scheduled"))
        self.assertFalse(self.store.events("queue.escalated"))
        self.assertFalse(self.store.events("execution.planned"))
        compile_plan.assert_not_called()
        execute_plan.assert_not_called()

    @unittest.skipUnless(os.name == "posix", "requires POSIX no-follow semantics")
    def test_projection_rebuild_is_change_only_and_repairs_or_refuses_unsafe_paths(
        self,
    ) -> None:
        self._add_pending(1, schedules=True)
        self.store.rebuild()
        before = self._projection_identity(self.root)
        self.store.rebuild()
        self.assertEqual(self._projection_identity(self.root), before)

        runtime = self.root / "state" / "runtime.json"
        runtime.write_text('{"tampered": true}\n', encoding="utf-8")
        runtime.chmod(0o644)
        self.store.rebuild()
        self.assertEqual(stat.S_IMODE(runtime.stat().st_mode), 0o600)
        self.assertNotEqual(runtime.read_text(encoding="utf-8"), '{"tampered": true}\n')

        publication_lock = self.root / "state" / "projection.lock"
        self.assertEqual(stat.S_IMODE(publication_lock.stat().st_mode), 0o600)
        external_lock = self.root / "external.lock"
        external_lock.write_text("outside", encoding="utf-8")
        publication_lock.unlink()
        publication_lock.symlink_to(external_lock)
        with self.assertRaises(OSError):
            self.store.rebuild()
        self.assertEqual(external_lock.read_text(encoding="utf-8"), "outside")
        publication_lock.unlink()
        self.store.rebuild()

        external = self.root / "external.json"
        external.write_text("outside", encoding="utf-8")
        runtime.unlink()
        runtime.symlink_to(external)
        with self.assertRaises(OSError):
            self.store.rebuild()
        self.assertEqual(external.read_text(encoding="utf-8"), "outside")

    @unittest.skipUnless(os.name == "posix", "requires POSIX no-follow semantics")
    def test_projection_lock_validation_to_open_swaps_fail_closed(self) -> None:
        self.store.rebuild()
        state = self.root / "state"
        publication_lock = state / "projection.lock"
        external = self.root / "external-lock-target"
        external.write_text("outside", encoding="utf-8")
        original_prepare = self.store._prepare_private_projection

        def swap_final_after_prepare(path):
            original_prepare(path)
            if path == publication_lock:
                publication_lock.unlink()
                publication_lock.symlink_to(external)

        with (
            mock.patch.object(
                self.store,
                "_prepare_private_projection",
                side_effect=swap_final_after_prepare,
            ),
            self.assertRaises(OSError),
        ):
            self.store.rebuild()
        self.assertTrue(publication_lock.is_symlink())
        self.assertEqual(external.read_text(encoding="utf-8"), "outside")
        publication_lock.unlink()
        self.store.rebuild()

        publication_lock.unlink()
        os.mkfifo(publication_lock, 0o600)
        with self.assertRaises(OSError):
            self.store.rebuild()
        publication_lock.unlink()
        publication_lock.mkdir(mode=0o700)
        with self.assertRaises(OSError):
            self.store.rebuild()
        publication_lock.rmdir()
        self.store.rebuild()

        moved_state = self.root / "state-before-lock-open"
        external_state = self.root / "external-state"
        external_state.mkdir()

        def swap_parent_after_prepare(path):
            original_prepare(path)
            if path == publication_lock:
                state.rename(moved_state)
                state.symlink_to(external_state, target_is_directory=True)

        try:
            with (
                mock.patch.object(
                    self.store,
                    "_prepare_private_projection",
                    side_effect=swap_parent_after_prepare,
                ),
                self.assertRaises(OSError),
            ):
                self.store.rebuild()
            self.assertFalse(any(external_state.iterdir()))
        finally:
            if state.is_symlink():
                state.unlink()
            if moved_state.exists():
                moved_state.rename(state)
        self.store.rebuild()

    def test_concurrent_rebuilds_publish_one_coherent_newest_snapshot(self) -> None:
        self.store.rebuild()
        self.store.append(
            "fixture.one", {"sequence": 1}, actor="fixture", event_id="fixture:one"
        )
        first_snapshot = self.store.read_snapshot()
        self.store.append(
            "fixture.two", {"sequence": 2}, actor="fixture", event_id="fixture:two"
        )
        second_snapshot = self.store.read_snapshot()
        first_store = EventStore(self.root)
        second_store = EventStore(self.root)
        first_published = threading.Event()
        release_first = threading.Event()
        second_attempted = threading.Event()
        second_published = threading.Event()
        failures: list[BaseException] = []
        original_first_publish = first_store._publish_json_if_changed
        original_second_publish = second_store._publish_json_if_changed

        def block_first(path, payload):
            changed = original_first_publish(path, payload)
            if path.name == "runtime.json" and not first_published.is_set():
                first_published.set()
                self.assertTrue(release_first.wait(timeout=5))
            return changed

        def note_second(path, payload):
            second_published.set()
            return original_second_publish(path, payload)

        first_store._publish_json_if_changed = block_first
        second_store._publish_json_if_changed = note_second

        def publish(store, snapshot, attempted=None):
            try:
                if attempted is not None:
                    attempted.set()
                store.rebuild(snapshot)
            except (AssertionError, OSError, RuntimeError, ValueError) as exc:
                # Test threads cannot propagate failures to the main runner.
                failures.append(exc)

        first = threading.Thread(target=publish, args=(first_store, first_snapshot))
        second = threading.Thread(
            target=publish, args=(second_store, second_snapshot, second_attempted)
        )
        first.start()
        self.assertTrue(first_published.wait(timeout=5))
        second.start()
        self.assertTrue(second_attempted.wait(timeout=5))
        self.assertFalse(second_published.wait(timeout=0.2))
        release_first.set()
        first.join(timeout=10)
        second.join(timeout=10)
        self.assertFalse(first.is_alive())
        self.assertFalse(second.is_alive())
        self.assertFalse(failures)

        runtime = json.loads((self.root / "state" / "runtime.json").read_text())
        current = json.loads((self.root / "state" / "current.json").read_text())
        events = [
            json.loads(line)
            for line in (self.root / "state" / "events.jsonl").read_text().splitlines()
        ]
        self.assertEqual(runtime["current"]["event_count"], 2)
        self.assertEqual(current["event_count"], 2)
        self.assertEqual(len(events), 2)
        self.assertEqual(events[-1]["seq"], 2)
        self.assertEqual(self.store.count(), 2)

    def test_delayed_older_rebuild_cannot_regress_a_newer_publication(self) -> None:
        self.store.rebuild()
        self.store.append(
            "fixture.one", {"sequence": 1}, actor="fixture", event_id="fixture:one"
        )
        older_snapshot = self.store.read_snapshot()
        self.store.append(
            "fixture.two", {"sequence": 2}, actor="fixture", event_id="fixture:two"
        )
        newer_snapshot = self.store.read_snapshot()
        older_store = EventStore(self.root)
        newer_store = EventStore(self.root)
        newer_published = threading.Event()
        release_newer = threading.Event()
        failures: list[BaseException] = []
        older_runtime_counts: list[int] = []
        original_newer_publish = newer_store._publish_json_if_changed
        original_older_publish = older_store._publish_json_if_changed

        def block_newer(path, payload):
            changed = original_newer_publish(path, payload)
            if path.name == "runtime.json" and not newer_published.is_set():
                newer_published.set()
                self.assertTrue(release_newer.wait(timeout=5))
            return changed

        def record_older(path, payload):
            if path.name == "runtime.json":
                older_runtime_counts.append(payload["current"]["event_count"])
            return original_older_publish(path, payload)

        newer_store._publish_json_if_changed = block_newer
        older_store._publish_json_if_changed = record_older

        def publish(store, snapshot):
            try:
                store.rebuild(snapshot)
            except (AssertionError, OSError, RuntimeError, ValueError) as exc:
                # Test threads cannot propagate failures to the main runner.
                failures.append(exc)

        newer = threading.Thread(target=publish, args=(newer_store, newer_snapshot))
        older = threading.Thread(target=publish, args=(older_store, older_snapshot))
        newer.start()
        self.assertTrue(newer_published.wait(timeout=5))
        older.start()
        release_newer.set()
        newer.join(timeout=10)
        older.join(timeout=10)
        self.assertFalse(newer.is_alive())
        self.assertFalse(older.is_alive())
        self.assertFalse(failures)
        self.assertEqual(older_runtime_counts, [2])

        runtime = json.loads((self.root / "state" / "runtime.json").read_text())
        current = json.loads((self.root / "state" / "current.json").read_text())
        events = (self.root / "state" / "events.jsonl").read_text().splitlines()
        self.assertEqual(runtime["current"]["event_count"], 2)
        self.assertEqual(current["event_count"], 2)
        self.assertEqual(len(events), 2)

    def test_tampered_or_missing_projection_cannot_lower_delayed_publication(
        self,
    ) -> None:
        self.store.rebuild()
        self.store.append(
            "fixture.one", {"sequence": 1}, actor="fixture", event_id="fixture:one"
        )
        older_snapshot = self.store.read_snapshot()
        self.store.append(
            "fixture.two", {"sequence": 2}, actor="fixture", event_id="fixture:two"
        )
        self.store.rebuild()
        runtime_path = self.root / "state" / "runtime.json"

        for corruption in ("malformed", "missing", "lower"):
            with self.subTest(corruption=corruption):
                if corruption == "malformed":
                    runtime_path.write_text("{broken", encoding="utf-8")
                elif corruption == "missing":
                    runtime_path.unlink()
                else:
                    runtime_path.write_text(
                        json.dumps({"current": {"event_count": 0}}),
                        encoding="utf-8",
                    )

                # This caller is deliberately delayed behind a newer
                # publication and supplies a stale snapshot. Publication must
                # still use the locked fresh canonical SQLite sequence.
                self.store.rebuild(older_snapshot)

                runtime = json.loads(runtime_path.read_text(encoding="utf-8"))
                current = json.loads((self.root / "state" / "current.json").read_text())
                events = (self.root / "state" / "events.jsonl").read_text().splitlines()
                self.assertEqual(runtime["current"]["event_count"], 2)
                self.assertEqual(current["event_count"], 2)
                self.assertEqual(len(events), 2)

    def test_stale_watcher_lease_exits_before_queue_evaluation_or_write(self) -> None:
        args = argparse.Namespace(
            queue_action="watch",
            auto_execute=True,
            interval=1,
            once=True,
            owner_token="queuewatch-stale",
            watcher_epoch=0,
            diagnostic=False,
            quiet=True,
            heartbeat_seconds=300,
        )
        before = self.store.count()
        with (
            mock.patch.object(cli, "workspace_root", return_value=self.root),
            mock.patch.object(
                cli, "load_context", return_value=(self.manifest, {}, self.store, None)
            ),
            mock.patch.object(
                cli, "persist_schedules", wraps=persist_schedules
            ) as schedules,
        ):
            self.assertEqual(cli.cmd_queue(args), 0)
        self.assertEqual(schedules.call_count, 0)
        self.assertEqual(self.store.count(), before)

    def test_compact_watcher_record_excludes_queue_items_and_sensitive_fields(
        self,
    ) -> None:
        record = json.loads(
            cli._queue_watch_record(
                {"depth": 25, "eligible": 0, "next_proposal_id": "proposal-001"},
                reason="heartbeat",
                return_code=0,
                tick_duration_ms=12,
            )
        )
        self.assertEqual(record["event"], "queue.watch")
        self.assertEqual(record["reason"], "heartbeat")
        self.assertNotIn("items", record)
        for forbidden in (
            "candidate",
            "owner_token",
            "argv",
            "output",
            "authorization",
        ):
            self.assertNotIn(forbidden, record)

    def test_stable_queue_emits_one_transition_and_scheduled_heartbeats(self) -> None:
        state = {"depth": 25, "eligible": 0, "next_proposal_id": "proposal-001"}
        last_fingerprint = ""
        last_heartbeat = 0.0
        records = []
        record_seconds = []
        for second in range(1_000):
            record, last_fingerprint, last_heartbeat = cli._queue_watch_presentation(
                state,
                last_fingerprint=last_fingerprint,
                last_heartbeat=last_heartbeat,
                now=float(second),
                heartbeat_seconds=300,
                return_code=0,
                tick_duration_ms=1,
            )
            if record is not None:
                records.append(json.loads(record))
                record_seconds.append(second)
        self.assertEqual(
            [record["reason"] for record in records],
            ["transition", "heartbeat", "heartbeat", "heartbeat"],
        )
        self.assertEqual(record_seconds, [0, 300, 600, 900])
        self.assertTrue(all("items" not in record for record in records))


if __name__ == "__main__":
    unittest.main(verbosity=2)
