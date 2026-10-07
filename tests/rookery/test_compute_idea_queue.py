from __future__ import annotations

import datetime as dt
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from rookery.portable.cli import build_parser, render_start_prompt
from rookery.portable.compute import (
    admit_compute_tick,
    compute_queue_status,
    cpu_window_busy_percent,
    enqueue_compute_idea,
    finish_compute_idea,
    parse_proc_stat,
    project_compute_ideas,
    requeue_compute_idea,
    sample_host_cpu,
    start_compute_idea,
)
from rookery.portable.outcomes import (
    close_current_agent_attempt,
    harvest_report,
    record_outcome,
)
from rookery.portable.store import EventStore
from rookery.portable.util import UTC


def idea_payload(*, dedupe_key: str = "objective:method", dispatch_kind: str = "agent") -> dict[str, object]:
    return {
        "objective_id": "event-wide",
        "goal": "Test one bounded low-priority hypothesis",
        "scope": "analysis/idle-lane and local fixture only",
        "report_path": "analysis/idle-lane/REPORT.md",
        "stop_condition": "ten minutes or one exact negative",
        "mechanism": "bounded fixture search",
        "requested_cpu_threads": 1,
        "budget_seconds": 600,
        "checkpointable": True,
        "dispatch_kind": dispatch_kind,
        "expected_value": 2.0,
        "evidence_value": 1.0,
        "dedupe_key": dedupe_key,
    }


def manifest() -> dict[str, object]:
    return {
        "compute": {
            "interactive_reserve_units": 2,
            "admission_cooldown_seconds": 0,
            "lease_seconds": 30,
        },
        "concurrency": {"max_workers": 8, "max_jobs": 8},
    }


def observation(*, busy: float) -> dict[str, object]:
    return {
        "available": True,
        "visible_cpu_count": 8,
        "window_busy_percent": [busy, busy],
        "busy_cores": busy * 8 / 100,
        "sample_seconds": 1,
        "sampled_at": "2026-09-28T12:00:00Z",
    }


def write_private_report(root: Path, report_path: str, text: str) -> Path:
    path = root / report_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.parent.chmod(0o700)
    path.write_text(text, encoding="utf-8")
    path.chmod(0o600)
    return path


def complete_challenge(root: Path, challenge_id: str) -> dict[str, object]:
    """Create one complete, artifact-backed challenge row for queue tests."""

    directory = root / "captures" / challenge_id
    directory.mkdir(parents=True, exist_ok=True)
    directory.chmod(0o700)
    detail = directory / "detail.json"
    detail_bytes = json.dumps({"id": challenge_id, "files": []}, sort_keys=True).encode("utf-8")
    detail.write_bytes(detail_bytes)
    detail.chmod(0o600)
    return {
        "id": challenge_id,
        "files": [],
        "detail_path": detail.relative_to(root).as_posix(),
        "detail_sha256": hashlib.sha256(detail_bytes).hexdigest(),
        "detail_bytes": len(detail_bytes),
        "captured_files": [],
        "expected_file_count": 0,
        "captured_file_count": 0,
        "ingested_at": "2026-10-02T00:00:00Z",
        "intake_state": "complete",
        "intake_missing_material": [],
        "resources_truncated": False,
        "resources_complete": True,
    }


class CpuSamplingTests(unittest.TestCase):
    def test_affinity_filter_idle_iowait_and_guest_exclusion(self) -> None:
        before = parse_proc_stat(
            "cpu0 10 0 10 70 10 0 0 0 50 0\ncpu1 20 0 10 60 10 0 0 0 50 0\ncpu2 999 0 0 0 0 0 0 0 0 0\n",
            {0, 1},
        )
        after = parse_proc_stat(
            "cpu0 20 0 20 130 20 0 0 0 500 0\ncpu1 30 0 20 120 20 0 0 0 500 0\ncpu2 1999 0 0 0 0 0 0 0 0 0\n",
            {0, 1},
        )
        self.assertEqual(cpu_window_busy_percent(before, after), 22.222)

    def test_sample_uses_three_reads_and_fails_closed(self) -> None:
        samples = iter(
            [
                "cpu0 0 0 0 100 0 0 0 0\n",
                "cpu0 10 0 0 190 0 0 0 0\n",
                "cpu0 20 0 0 280 0 0 0 0\n",
            ]
        )
        result = sample_host_cpu(
            sample_seconds=0.01,
            affinity_reader=lambda: {0},
            stat_reader=lambda: next(samples),
            sleeper=lambda _seconds: None,
        )
        self.assertEqual(result["window_busy_percent"], [10.0, 10.0])

        unavailable = sample_host_cpu(
            sample_seconds=0.01,
            affinity_reader=lambda: {0, 1},
            stat_reader=lambda: "cpu0 0 0 0 1 0 0 0 0\n",
            sleeper=lambda _seconds: None,
        )
        self.assertFalse(unavailable["available"])


class ComputeIdeaLifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.store = EventStore(self.root)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_challenge_compute_requires_current_verified_intake_at_enqueue_and_start(self) -> None:
        challenge_id = "queue-challenge"
        pending = complete_challenge(self.root, challenge_id)
        pending["intake_state"] = "pending"
        self.store.append("platform.snapshot", {"challenges": [pending]}, actor="fixture")
        payload = {
            **idea_payload(dedupe_key="challenge:queue"),
            "challenge_id": challenge_id,
        }
        with self.assertRaisesRegex(ValueError, "challenge intake is not solver-ready"):
            enqueue_compute_idea(self.store, payload)
        self.assertEqual(self.store.events("compute.idea.queued"), [])

        ready = complete_challenge(self.root, challenge_id)
        self.store.append("challenge.upsert", ready, actor="fixture")
        queued = enqueue_compute_idea(self.store, payload)
        self.assertEqual(queued["challenge_id"], challenge_id)

        stale = {**ready, "intake_state": "partial"}
        self.store.append("challenge.upsert", stale, actor="fixture")
        lease = admit_compute_tick(self.store, manifest(), observation(busy=20))
        with self.assertRaisesRegex(ValueError, "challenge intake is not solver-ready"):
            start_compute_idea(
                self.store,
                idea_id=queued["idea_id"],
                admission_id=lease["admission_id"],
                agent_attempt_id="not-reached",
            )
        self.assertEqual(self.store.events("compute.idea.started"), [])

    def test_enqueue_lease_bind_complete_is_distinct_from_scoring(self) -> None:
        queued = enqueue_compute_idea(self.store, idea_payload())
        with self.assertRaisesRegex(ValueError, "dedupe key"):
            enqueue_compute_idea(self.store, idea_payload())

        admitted = admit_compute_tick(self.store, manifest(), observation(busy=20))
        self.assertEqual(admitted["action"], "lease")
        leases = self.store.events("compute.idea.leased")
        self.assertEqual(len(leases), 1)

        self.store.append(
            "agent.running",
            {
                "agent_id": "wrong-worker",
                "agent_attempt_id": "attempt-wrong",
                "objective_id": "different-objective",
                "report_path": "analysis/other/REPORT.md",
            },
            actor="coordinator",
        )
        with self.assertRaisesRegex(ValueError, "binding does not match"):
            start_compute_idea(
                self.store,
                idea_id=queued["idea_id"],
                admission_id=admitted["admission_id"],
                agent_attempt_id="attempt-wrong",
            )
        self.store.append(
            "agent.running",
            {
                "agent_id": "idle-worker",
                "agent_attempt_id": "attempt-idle",
                "objective_id": "event-wide",
                "report_path": "analysis/idle-lane/REPORT.md",
            },
            actor="coordinator",
        )
        started = start_compute_idea(
            self.store,
            idea_id=queued["idea_id"],
            admission_id=admitted["admission_id"],
            agent_attempt_id="attempt-idle",
        )
        self.assertEqual(started["effective_status"], "running")
        with self.assertRaisesRegex(ValueError, "admission ID does not match"):
            finish_compute_idea(
                self.store,
                idea_id=queued["idea_id"],
                status="completed",
                summary="Unbound completion attempt.",
                admission_id="admission_wrong",
                agent_attempt_id="attempt-idle",
            )
        with self.assertRaisesRegex(ValueError, "report does not exist"):
            finish_compute_idea(
                self.store,
                idea_id=queued["idea_id"],
                status="completed",
                summary="Completion without evidence must not close the work.",
                admission_id=admitted["admission_id"],
                agent_attempt_id="attempt-idle",
            )
        write_private_report(
            self.root,
            "analysis/idle-lane/REPORT.md",
            "# Result\n\nThe bounded search produced a useful negative.\n",
        )
        with self.assertRaisesRegex(ValueError, "exact registered agent to close"):
            finish_compute_idea(
                self.store,
                idea_id=queued["idea_id"],
                status="completed",
                summary="A report alone is not a completed worker handoff.",
                admission_id=admitted["admission_id"],
                agent_attempt_id="attempt-idle",
            )
        record_outcome(
            self.store,
            agent_id="idle-worker",
            agent_attempt_id="attempt-idle",
            objective_id="event-wide",
            outcome_type="technical_negative",
            report_path="analysis/idle-lane/REPORT.md",
            summary="The bounded search produced a useful negative.",
            mechanism="bounded fixture search",
        )
        harvest_report(
            self.store,
            self.root,
            "analysis/idle-lane/REPORT.md",
            agent_id="idle-worker",
            agent_attempt_id="attempt-idle",
            objective_id="event-wide",
        )
        close_current_agent_attempt(
            self.store,
            agent_id="idle-worker",
            reason="report, outcome, and handoff are complete",
        )
        completed = finish_compute_idea(
            self.store,
            idea_id=queued["idea_id"],
            status="completed",
            summary="Bounded search completed with a useful negative.",
            admission_id=admitted["admission_id"],
            agent_attempt_id="attempt-idle",
        )
        self.assertEqual(completed["effective_status"], "completed")
        with self.assertRaisesRegex(ValueError, "must start before an outcome"):
            finish_compute_idea(
                self.store,
                idea_id=queued["idea_id"],
                status="completed",
                summary="Duplicate completion attempt.",
                admission_id=admitted["admission_id"],
                agent_attempt_id="attempt-idle",
            )
        self.assertEqual(len(self.store.events("compute.idea.completed")), 1)
        self.assertEqual(compute_queue_status(self.store)["counts"], {"completed": 1})
        projection = self.store.rebuild()
        self.assertEqual(projection["queue"]["depth"], 0)
        self.assertEqual(projection["scoring_events"], [])

    def test_tick_admits_nothing_without_metrics_or_capacity(self) -> None:
        enqueue_compute_idea(self.store, idea_payload())
        before = len(self.store.events("compute.idea.leased"))
        result = admit_compute_tick(
            self.store,
            manifest(),
            {"available": False, "reason": "/proc/stat unavailable"},
        )
        self.assertEqual(result["reason"], "metrics_unavailable")
        self.assertEqual(len(self.store.events("compute.idea.leased")), before)

        constrained = manifest()
        constrained["concurrency"] = {"max_workers": 2, "max_jobs": 2}
        result = admit_compute_tick(self.store, constrained, observation(busy=20))
        self.assertEqual(result["reason"], "interactive_capacity_reserved")

    def test_duplicated_busy_core_summary_cannot_bypass_measured_windows(self) -> None:
        enqueue_compute_idea(self.store, idea_payload())
        measured = observation(busy=69)
        measured["busy_cores"] = 0
        result = admit_compute_tick(self.store, manifest(), measured)
        self.assertEqual(result["reason"], "cpu_prediction_exceeds_ceiling")

    def test_agent_and_job_ideas_use_only_their_matching_capacity(self) -> None:
        roomy_workers = manifest()
        roomy_workers["compute"] = {
            "interactive_reserve_units": 0,
            "admission_cooldown_seconds": 0,
        }
        roomy_workers["concurrency"] = {"max_workers": 64, "max_jobs": 1}
        enqueue_compute_idea(self.store, idea_payload())
        agent_result = admit_compute_tick(self.store, roomy_workers, observation(busy=20))
        self.assertEqual(agent_result["action"], "lease")

        with tempfile.TemporaryDirectory() as temporary:
            job_store = EventStore(Path(temporary))
            enqueue_compute_idea(
                job_store,
                idea_payload(dedupe_key="objective:job", dispatch_kind="job"),
            )
            no_jobs = dict(roomy_workers)
            no_jobs["concurrency"] = {"max_workers": 64, "max_jobs": 0}
            job_result = admit_compute_tick(job_store, no_jobs, observation(busy=20))
        self.assertEqual(job_result["reason"], "interactive_capacity_reserved")

    def test_target_prefers_equal_value_work_closest_to_75_percent(self) -> None:
        policy = manifest()
        policy["compute"] = {
            "interactive_reserve_units": 0,
            "admission_cooldown_seconds": 0,
        }
        enqueue_compute_idea(
            self.store,
            {**idea_payload(dedupe_key="target:small"), "requested_cpu_threads": 1},
        )
        closer = enqueue_compute_idea(
            self.store,
            {**idea_payload(dedupe_key="target:closer"), "requested_cpu_threads": 3},
        )
        result = admit_compute_tick(self.store, policy, observation(busy=25))
        self.assertEqual(result["idea"]["idea_id"], closer["idea_id"])
        self.assertEqual(result["idea"]["target_distance_cores"], 1.0)

    def test_job_start_requires_exact_lease_label_and_current_generation(self) -> None:
        self.store.set_meta("stop_generation", 1)
        self.store.append(
            "control.resume",
            {"generation": 1, "reason": "fixture resume"},
            actor="operator",
            generation=1,
        )
        queued = enqueue_compute_idea(
            self.store,
            idea_payload(dedupe_key="objective:job", dispatch_kind="job"),
        )
        admitted = admit_compute_tick(self.store, manifest(), observation(busy=20))
        expected_label = admitted["job_label"]
        self.store.append(
            "job.running",
            {"job_id": "unrelated-job", "label": "other"},
            actor="runbg",
            generation=1,
        )
        with self.assertRaisesRegex(ValueError, "lease-bound"):
            start_compute_idea(
                self.store,
                idea_id=queued["idea_id"],
                admission_id=admitted["admission_id"],
                job_id="unrelated-job",
            )
        self.store.append(
            "job.running",
            {"job_id": "stale-job", "label": expected_label},
            actor="runbg",
            generation=0,
        )
        with self.assertRaisesRegex(ValueError, "lease-bound"):
            start_compute_idea(
                self.store,
                idea_id=queued["idea_id"],
                admission_id=admitted["admission_id"],
                job_id="stale-job",
            )
        self.store.append(
            "job.running",
            {"job_id": "bound-job", "label": expected_label},
            actor="runbg",
            generation=1,
        )
        started = start_compute_idea(
            self.store,
            idea_id=queued["idea_id"],
            admission_id=admitted["admission_id"],
            job_id="bound-job",
        )
        self.assertEqual(started["job_id"], "bound-job")
        with self.assertRaisesRegex(ValueError, "runner identity does not match"):
            finish_compute_idea(
                self.store,
                idea_id=queued["idea_id"],
                status="completed",
                summary="Wrong job attempted closeout.",
                admission_id=admitted["admission_id"],
                job_id="unrelated-job",
            )
        report = write_private_report(
            self.root,
            "analysis/idle-lane/REPORT.md",
            " \n\t",
        )
        with self.assertRaisesRegex(ValueError, "non-whitespace evidence"):
            finish_compute_idea(
                self.store,
                idea_id=queued["idea_id"],
                status="completed",
                summary="An empty report cannot establish a completed job.",
                admission_id=admitted["admission_id"],
                job_id="bound-job",
            )
        report.write_text("# Job result\n\nThe bounded job completed.\n", encoding="utf-8")
        report.chmod(0o600)
        completed = finish_compute_idea(
            self.store,
            idea_id=queued["idea_id"],
            status="completed",
            summary="Exact bound job completed.",
            admission_id=admitted["admission_id"],
            job_id="bound-job",
        )
        self.assertEqual(completed["effective_status"], "completed")

    def test_failure_does_not_claim_a_useful_report_or_handoff(self) -> None:
        queued = enqueue_compute_idea(self.store, idea_payload())
        admitted = admit_compute_tick(self.store, manifest(), observation(busy=20))
        self.store.append(
            "agent.running",
            {
                "agent_id": "failed-worker",
                "agent_attempt_id": "attempt-failed",
                "objective_id": "event-wide",
                "report_path": "analysis/idle-lane/REPORT.md",
            },
            actor="coordinator",
        )
        start_compute_idea(
            self.store,
            idea_id=queued["idea_id"],
            admission_id=admitted["admission_id"],
            agent_attempt_id="attempt-failed",
        )
        failed = finish_compute_idea(
            self.store,
            idea_id=queued["idea_id"],
            status="failed",
            summary="The worker could not complete the bounded method.",
            admission_id=admitted["admission_id"],
            agent_attempt_id="attempt-failed",
        )
        self.assertEqual(failed["effective_status"], "failed")

    def test_stop_generation_makes_old_ideas_ineligible(self) -> None:
        queued = enqueue_compute_idea(self.store, idea_payload())
        self.store.set_meta("stop_generation", 1)
        self.store.append(
            "control.stop",
            {"generation": 1, "reason": "fixture stop"},
            actor="operator",
            generation=1,
        )
        result = admit_compute_tick(self.store, manifest(), observation(busy=20))
        self.assertEqual(result["reason"], "workspace_stopped")
        row = next(idea for idea in compute_queue_status(self.store)["ideas"] if idea["idea_id"] == queued["idea_id"])
        self.assertEqual(row["effective_status"], "stale")
        self.assertEqual(self.store.events("compute.idea.leased"), [])

    def test_start_rejects_matching_worker_from_an_old_generation(self) -> None:
        self.store.set_meta("stop_generation", 1)
        self.store.append(
            "control.resume",
            {"generation": 1, "reason": "fixture resume"},
            actor="operator",
            generation=1,
        )
        queued = enqueue_compute_idea(self.store, idea_payload())
        admitted = admit_compute_tick(self.store, manifest(), observation(busy=20))
        self.store.append(
            "agent.running",
            {
                "agent_id": "stale-worker",
                "agent_attempt_id": "attempt-stale",
                "objective_id": "event-wide",
                "report_path": "analysis/idle-lane/REPORT.md",
            },
            actor="coordinator",
            generation=0,
        )
        with self.assertRaisesRegex(ValueError, "binding does not match"):
            start_compute_idea(
                self.store,
                idea_id=queued["idea_id"],
                admission_id=admitted["admission_id"],
                agent_attempt_id="attempt-stale",
            )

    def test_stop_blocks_terminal_mutation_for_running_old_generation(self) -> None:
        queued = enqueue_compute_idea(self.store, idea_payload())
        admitted = admit_compute_tick(self.store, manifest(), observation(busy=20))
        self.store.append(
            "agent.running",
            {
                "agent_id": "idle-worker",
                "agent_attempt_id": "attempt-idle",
                "objective_id": "event-wide",
                "report_path": "analysis/idle-lane/REPORT.md",
            },
            actor="coordinator",
        )
        start_compute_idea(
            self.store,
            idea_id=queued["idea_id"],
            admission_id=admitted["admission_id"],
            agent_attempt_id="attempt-idle",
        )
        self.store.set_meta("stop_generation", 1)
        self.store.append(
            "control.stop",
            {"generation": 1, "reason": "fixture stop"},
            actor="operator",
            generation=1,
        )
        with self.assertRaisesRegex(RuntimeError, "workspace is stopped"):
            finish_compute_idea(
                self.store,
                idea_id=queued["idea_id"],
                status="failed",
                summary="Would be stale cleanup.",
                admission_id=admitted["admission_id"],
                agent_attempt_id="attempt-idle",
            )

    def test_expired_lease_returns_to_queued_projection(self) -> None:
        now = dt.datetime(2026, 9, 28, 12, 0, tzinfo=UTC)
        events = [
            {
                "event_id": "q",
                "event_type": "compute.idea.queued",
                "created_at": "2026-09-28T11:58:00Z",
                "generation": 0,
                "payload": {**idea_payload(), "idea_id": "idea_fixture", "queued_stop_generation": 0},
            },
            {
                "event_id": "l",
                "event_type": "compute.idea.leased",
                "created_at": "2026-09-28T11:59:00Z",
                "generation": 0,
                "payload": {
                    "idea_id": "idea_fixture",
                    "admission_id": "admission_fixture",
                    "lease_expires_at": "2026-09-28T11:59:30Z",
                },
            },
        ]
        projected = project_compute_ideas(events, current_stop_generation=0, now=now)
        self.assertEqual(projected["idea_fixture"]["effective_status"], "queued")
        self.assertTrue(projected["idea_fixture"]["lease_expired"])

    def test_sustained_high_cpu_requests_one_cooperative_pause(self) -> None:
        queued = enqueue_compute_idea(self.store, idea_payload())
        admitted = admit_compute_tick(self.store, manifest(), observation(busy=20))
        self.store.append(
            "agent.running",
            {
                "agent_id": "idle-worker",
                "agent_attempt_id": "attempt-idle",
                "objective_id": "event-wide",
                "report_path": "analysis/idle-lane/REPORT.md",
            },
            actor="coordinator",
        )
        start_compute_idea(
            self.store,
            idea_id=queued["idea_id"],
            admission_id=admitted["admission_id"],
            agent_attempt_id="attempt-idle",
        )
        result = admit_compute_tick(self.store, manifest(), observation(busy=90))
        self.assertEqual(result["action"], "backoff")
        self.assertEqual(len(self.store.events("compute.idea.pause_requested")), 1)
        with self.assertRaisesRegex(ValueError, "existing private file"):
            finish_compute_idea(
                self.store,
                idea_id=queued["idea_id"],
                status="paused",
                summary="Missing checkpoint must not become durable.",
                admission_id=admitted["admission_id"],
                agent_attempt_id="attempt-idle",
                checkpoint_path="analysis/idle-lane/missing.json",
            )
        checkpoint = self.root / "analysis/idle-lane/checkpoint.json"
        checkpoint.parent.mkdir(parents=True)
        checkpoint.parent.chmod(0o700)
        checkpoint.write_text("{}\n", encoding="utf-8")
        checkpoint.chmod(0o600)
        linked_checkpoint = checkpoint.with_name("linked.json")
        linked_checkpoint.symlink_to(checkpoint.name)
        with self.assertRaises(ValueError):
            finish_compute_idea(
                self.store,
                idea_id=queued["idea_id"],
                status="paused",
                summary="A linked checkpoint is not durable evidence.",
                admission_id=admitted["admission_id"],
                agent_attempt_id="attempt-idle",
                checkpoint_path="analysis/idle-lane/linked.json",
            )
        finish_compute_idea(
            self.store,
            idea_id=queued["idea_id"],
            status="paused",
            summary="Checkpointed after sustained host load.",
            admission_id=admitted["admission_id"],
            agent_attempt_id="attempt-idle",
            checkpoint_path="analysis/idle-lane/checkpoint.json",
        )
        checkpoint.unlink()
        with self.assertRaisesRegex(ValueError, "existing private file"):
            requeue_compute_idea(self.store, idea_id=queued["idea_id"])
        checkpoint.write_text("{}\n", encoding="utf-8")
        checkpoint.chmod(0o600)
        requeued = requeue_compute_idea(self.store, idea_id=queued["idea_id"])
        self.assertEqual(requeued["effective_status"], "queued")


class ComputeCliContractTests(unittest.TestCase):
    def test_parser_exposes_queue_lifecycle_and_legacy_schedule(self) -> None:
        parser = build_parser()
        self.assertEqual(parser.parse_args(["compute", "list"]).compute_action, "list")
        self.assertEqual(parser.parse_args(["compute", "tick"]).compute_action, "tick")
        self.assertEqual(
            parser.parse_args(["compute", "requeue", "idea_fixture"]).compute_action,
            "requeue",
        )
        self.assertIsNone(parser.parse_args(["compute", "--jobs", "jobs.json"]).compute_action)

    def test_start_prompt_carries_cpu_and_browser_scoring_boundaries(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest_value = {
                "identity": {"name": "fixture"},
                "profile": "ctfd-browser",
                "adapter": {"id": "ctfd_browser"},
            }
            path = render_start_prompt(
                root,
                manifest_value,
                SimpleNamespace(unresolved_required=[]),
                {"tools": []},
            )
            text = path.read_text(encoding="utf-8")
        self.assertIn("compute tick", text)
        self.assertIn("best-effort 75% CPU", text)
        self.assertIn("never create synthetic busywork", text)
        self.assertIn("Solvers never submit through raw CDP", text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
