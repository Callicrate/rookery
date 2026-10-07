from __future__ import annotations

# ruff: noqa: E402

import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

from tests.rookery.support import ROOKERY_ROOT

LIB = ROOKERY_ROOT / "lib"
if str(LIB) not in sys.path:
    sys.path.insert(0, str(LIB))
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

from rookery.portable.telemetry import build_report
from rookery.portable.util import canonical_json


def event(
    sequence: int,
    event_id: str,
    event_type: str,
    payload: dict[str, object] | None = None,
    *,
    second: int = 0,
) -> dict[str, object]:
    return {
        "seq": sequence,
        "event_id": event_id,
        "event_type": event_type,
        "created_at": f"2026-08-28T00:00:{second:02d}Z",
        "generation": 0,
        "actor": "fixture",
        "payload": payload or {},
    }


def write_events(root: Path, rows: list[dict[str, object]]) -> None:
    state = root / "state"
    state.mkdir(parents=True)
    (state / "events.jsonl").write_text(
        "".join(canonical_json(row) + "\n" for row in rows), encoding="utf-8"
    )
    connection = sqlite3.connect(state / "events.sqlite3")
    try:
        connection.execute(
            "CREATE TABLE events (seq INTEGER, event_id TEXT, event_type TEXT, "
            "created_at TEXT, generation INTEGER, actor TEXT, payload_json TEXT)"
        )
        for row in rows:
            connection.execute(
                "INSERT INTO events VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    row["seq"],
                    row["event_id"],
                    row["event_type"],
                    row["created_at"],
                    row["generation"],
                    row["actor"],
                    canonical_json(row["payload"]),
                ),
            )
        connection.commit()
    finally:
        connection.close()


class TelemetryTruthRepairTests(unittest.TestCase):
    def test_plan_finalization_preserves_multiple_plans_per_proposal(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        rows = [
            event(1, "proposal-0", "proposal.created", {"proposal_id": "p0"}),
            event(2, "proposal-1a", "proposal.created", {"proposal_id": "p1"}),
            event(3, "proposal-1b", "proposal.created", {"proposal_id": "p1"}, second=10),
            event(4, "proposal-2", "proposal.created", {"proposal_id": "p2"}),
            event(5, "proposal-3", "proposal.created", {"proposal_id": "p3"}),
            event(6, "proposal-4", "proposal.created", {"proposal_id": "p4"}),
            event(7, "proposal-missing", "proposal.created"),
            event(8, "plan-0", "execution.planned", {"plan_id": "plan-0", "proposal_id": "p0"}),
            event(9, "plan-1a", "execution.planned", {"plan_id": "plan-1a", "proposal_id": "p1"}),
            event(10, "plan-1b", "execution.planned", {"plan_id": "plan-1b", "proposal_id": "p1"}),
            event(11, "plan-2", "execution.planned", {"plan_id": "plan-2", "proposal_id": "p2"}),
            event(12, "plan-3", "execution.planned", {"plan_id": "plan-3", "proposal_id": "p3"}),
            event(13, "plan-4", "execution.planned", {"plan_id": "plan-4", "proposal_id": "p4"}),
            event(14, "plan-missing", "execution.planned"),
            event(15, "terminal-0", "execution.completed", {"plan_id": "plan-0", "proposal_id": "p0"}),
            event(16, "terminal-1a-blocked", "execution.blocked", {"plan_id": "plan-1a", "proposal_id": "p1"}, second=15),
            event(17, "terminal-1a-completed", "execution.completed", {"plan_id": "plan-1a", "proposal_id": "p1"}, second=20),
            event(18, "terminal-1b", "execution.indeterminate", {"plan_id": "plan-1b", "proposal_id": "p1"}, second=20),
            event(19, "terminal-2", "execution.completed", {"plan_id": "plan-2", "proposal_id": "p2"}, second=20),
            event(20, "terminal-3", "execution.completed", {"plan_id": "plan-3", "proposal_id": "p3"}, second=30),
            event(21, "terminal-4", "execution.completed", {"plan_id": "plan-4", "proposal_id": "p4"}, second=40),
            event(22, "terminal-missing", "execution.completed", second=50),
        ]
        write_events(root, rows)

        report = build_report(root)
        latency = report["measurement"]["proposal_to_terminal_latency"]

        self.assertEqual(latency["proposal_event_denominator"], 7)
        self.assertEqual(latency["unique_proposal_denominator"], 5)
        self.assertEqual(latency["duplicate_proposal_events"], 1)
        self.assertEqual(latency["proposal_events_missing_proposal_id"], 1)
        self.assertEqual(latency["plan_event_denominator"], 7)
        self.assertEqual(latency["unique_plan_denominator"], 6)
        self.assertEqual(latency["plan_events_missing_plan_id"], 1)
        self.assertEqual(latency["terminal_event_count"], 8)
        self.assertEqual(latency["terminal_denominator"], 7)
        self.assertEqual(latency["unique_final_plan_denominator"], 6)
        self.assertEqual(latency["duplicate_terminal_transitions"], 1)
        self.assertEqual(latency["terminal_events_missing_plan_id"], 1)
        self.assertEqual(latency["terminal_events_missing_proposal_id"], 1)
        self.assertNotIn("rejected", latency["by_outcome"])
        self.assertNotIn("blocked", latency["by_outcome"])
        self.assertEqual(latency["by_outcome"]["completed"]["matched"], 5)
        self.assertEqual(latency["by_outcome"]["indeterminate"]["matched"], 1)
        self.assertEqual(latency["matched_plan_denominator"], 6)
        self.assertEqual(latency["matched_proposal_denominator"], 5)
        self.assertEqual(report["measurement"]["proposal_to_final_latency"], latency)
        self.assertEqual(
            report["events"]["workflow"]["final_terminal_outcomes"]["indeterminate"],
            1,
        )
        self.assertEqual(latency["latency_seconds"]["p50"], 15.0)
        self.assertEqual(latency["latency_seconds"]["p95"], 37.5)
        temporary.cleanup()

    def test_resources_preserve_local_and_provider_metric_boundaries(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        rows = [
            event(
                1,
                "local",
                "job.closed",
                {
                    "job_id": "local",
                    "owned": True,
                    "resource_summary": {
                        "cpu_seconds": 2,
                        "rss_bytes": 1024,
                        "queue_ms": 900,
                        "usage_seconds": 9,
                    },
                },
            ),
            event(
                2,
                "provider",
                "job.closed",
                {
                    "job_id": "provider",
                    "resource_summary": {
                        "provider_queue_seconds": 4,
                        "provider_usage_seconds": 5,
                        "provider_token_count": 6,
                    },
                },
            ),
            event(
                3,
                "invalid",
                "job.closed",
                {
                    "job_id": "invalid",
                    "resource_summary": {
                        "cpu_seconds": -1,
                        "rss_bytes": float("nan"),
                        "provider_queue_seconds": float("inf"),
                        "provider_usage_seconds": -5,
                        "provider_token_count": -2,
                    },
                },
            ),
        ]
        write_events(root, rows)

        resources = build_report(root)["measurement"]["resources"]

        self.assertEqual(resources["local_process"]["cpu_seconds"]["unit"], "seconds")
        self.assertEqual(resources["local_process"]["cpu_seconds"]["values"]["sum"], 2.0)
        self.assertEqual(resources["provider_queue"]["source_field"], "provider_queue_seconds")
        self.assertEqual(resources["provider_queue"]["values"]["sum"], 4.0)
        self.assertEqual(resources["provider_queue"]["invalid_terminal_jobs_with_field"], 1)
        self.assertEqual(resources["provider_usage"]["source_field"], "provider_usage_seconds")
        self.assertEqual(resources["provider_usage"]["values"]["sum"], 5.0)
        self.assertEqual(resources["provider_usage"]["invalid_terminal_jobs_with_field"], 1)
        self.assertEqual(resources["local_process"]["cpu_seconds"]["invalid_owned_terminal_jobs_with_field"], 0)
        self.assertEqual(resources["local_process"]["rss_bytes"]["invalid_owned_terminal_jobs_with_field"], 0)
        self.assertEqual(resources["terminal_jobs_with_invalid_resource_metric"], 1)
        temporary.cleanup()

    def test_per_objective_elapsed_and_queue_rates_have_explicit_availability(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        rows = [
            event(
                1,
                "proposal",
                "proposal.created",
                {"proposal_id": "proposal", "objective_id": "objective"},
                second=1,
            ),
            event(
                2,
                "plan",
                "execution.planned",
                {
                    "plan_id": "plan",
                    "proposal_id": "proposal",
                    "objective_id": "objective",
                    "evidence_paths": ["evidence/plan.txt"],
                },
                second=2,
            ),
            event(
                3,
                "terminal",
                "execution.completed",
                {
                    "plan_id": "plan",
                    "proposal_id": "proposal",
                    "objective_id": "objective",
                },
                second=7,
            ),
        ]
        write_events(root, rows)
        queue_watch = root / "logs" / "queue-watch"
        queue_watch.mkdir(parents=True)
        (queue_watch / "heartbeat.log").write_bytes(b"one\ntwo\n")

        measurement = build_report(root)["measurement"]

        per_objective = measurement["per_objective_elapsed_latency"]
        self.assertEqual(per_objective["availability"], "available")
        self.assertEqual(per_objective["objective_denominator"], 1)
        self.assertEqual(per_objective["elapsed_seconds"]["mean"], 6.0)
        rates = measurement["queue_normalized_rates"]
        self.assertEqual(rates["availability"], "available")
        self.assertEqual(rates["canonical_event_denominator"], 3)
        self.assertEqual(rates["lines_per_canonical_event"], 2 / 3)
        temporary.cleanup()

    def test_stale_jobs_remain_in_stop_and_resource_denominators(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        rows = [
            event(1, "stop", "control.stop", {"generation": 1}, second=1),
            event(
                2,
                "stale",
                "job.stale",
                {
                    "job_id": "stale-job",
                    "resource_summary": {
                        "cpu_seconds": 1,
                        "rss_bytes": 1024,
                        "peak_rss_bytes": 2048,
                    },
                },
                second=2,
            ),
        ]
        for row in rows:
            row["generation"] = 1
        write_events(root, rows)

        measurement = build_report(root)["measurement"]

        self.assertEqual(measurement["resources"]["terminal_jobs"], 1)
        self.assertEqual(measurement["resources"]["terminal_jobs_with_resource"], 1)
        reconciliation = measurement["stop_reconciliation"]
        self.assertEqual(reconciliation["stop_generations_with_stale"], 1)
        self.assertEqual(reconciliation["unique_stale_actors_terminal"], 1)
        self.assertEqual(reconciliation["stops_with_terminal_closure"], 0)
        temporary.cleanup()

    def test_stop_reconciliation_uses_final_categories_per_generation(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        rows = [
            event(1, "stop-one", "control.stop", {"generation": 1}, second=0),
            event(2, "closed-one", "job.closed", {"job_id": "one"}, second=2),
            event(3, "cancelled-one", "job.cancelled", {"job_id": "two"}, second=3),
            event(4, "unacknowledged-one", "job.unacknowledged", {"job_id": "three"}, second=4),
            event(5, "unmanaged-one", "job.unmanaged", {"job_id": "four"}, second=5),
            event(6, "transition-one", "job.unacknowledged", {"job_id": "five"}, second=6),
            event(7, "transition-final", "job.closed", {"job_id": "five"}, second=7),
            event(8, "stop-two", "control.stop", {"generation": 2}, second=10),
            event(9, "closed-two", "job.closed", {"job_id": "six"}, second=15),
        ]
        for row in rows[:7]:
            row["generation"] = 1
        for row in rows[7:]:
            row["generation"] = 2
        write_events(root, rows)

        reconciliation = build_report(root)["measurement"]["stop_reconciliation"]

        self.assertEqual(reconciliation["stop_event_denominator"], 2)
        self.assertEqual(reconciliation["stop_generation_denominator"], 2)
        self.assertEqual(reconciliation["stops_with_confirmed_closure"], 2)
        self.assertEqual(reconciliation["stops_with_terminal_closure"], 1)
        self.assertEqual(reconciliation["stop_generations_with_unacknowledged"], 1)
        self.assertEqual(reconciliation["stop_generations_with_unmanaged"], 1)
        self.assertEqual(reconciliation["unique_owned_actors_closed"], 4)
        self.assertEqual(reconciliation["unique_cancelled_actors"], 1)
        self.assertEqual(reconciliation["unique_unacknowledged_actors"], 1)
        self.assertEqual(reconciliation["unique_unmanaged_actors_terminal"], 1)
        self.assertEqual(reconciliation["duration_seconds"]["count"], 1)
        self.assertEqual(reconciliation["duration_seconds"]["mean"], 5.0)
        temporary.cleanup()

    def test_unacknowledged_only_stop_is_not_a_closure(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        rows = [
            event(1, "stop", "control.stop", {"generation": 1}),
            event(2, "unacknowledged", "job.unacknowledged", {"job_id": "job"}, second=3),
        ]
        for row in rows:
            row["generation"] = 1
        write_events(root, rows)

        reconciliation = build_report(root)["measurement"]["stop_reconciliation"]

        self.assertEqual(reconciliation["availability"], "not_available")
        self.assertEqual(reconciliation["stops_with_terminal_closure"], 0)
        self.assertEqual(reconciliation["unique_owned_actors_closed"], 0)
        self.assertEqual(reconciliation["unique_unacknowledged_actors"], 1)
        self.assertEqual(reconciliation["reason"], "confirmed_closure_events_absent")
        temporary.cleanup()

    def test_scoring_proposal_retry_lineage_uses_prior_retry_terminals(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        rejected_fingerprint = "a" * 64
        indeterminate_fingerprint = "b" * 64
        accepted_fingerprint = "c" * 64
        rows = [
            event(1, "accepted-proposal", "proposal.created", {"proposal_id": "accepted"}),
            event(
                2,
                "accepted-terminal",
                "execution.completed",
                {
                    "proposal_id": "accepted",
                    "retry": {"fingerprint": accepted_fingerprint},
                },
            ),
            event(3, "rejected-proposal", "proposal.created", {"proposal_id": "rejected"}),
            event(
                4,
                "rejected-terminal",
                "execution.rejected",
                {
                    "proposal_id": "rejected",
                    "rejection": {"fingerprint": rejected_fingerprint},
                },
            ),
            event(
                5,
                "rejected-child",
                "proposal.created",
                {
                    "proposal_id": "rejected-child",
                    "parent_rejection_fingerprint": rejected_fingerprint,
                    "discriminator": "new evidence",
                },
            ),
            event(6, "indeterminate-proposal", "proposal.created", {"proposal_id": "indeterminate"}),
            event(
                7,
                "indeterminate-terminal",
                "execution.indeterminate",
                {
                    "proposal_id": "indeterminate",
                    "retry": {"fingerprint": indeterminate_fingerprint},
                },
            ),
            event(
                8,
                "indeterminate-child",
                "proposal.created",
                {
                    "proposal_id": "indeterminate-child",
                    "parent_rejection_fingerprint": indeterminate_fingerprint,
                    "discriminator": "independent verifier",
                },
            ),
            event(
                9,
                "accepted-child",
                "proposal.created",
                {
                    "proposal_id": "accepted-child",
                    "parent_rejection_fingerprint": accepted_fingerprint,
                    "discriminator": "should remain unknown",
                },
            ),
            event(10, "missing-child", "proposal.created", {"proposal_id": "missing-child"}),
            event(
                11,
                "invalid-child",
                "proposal.created",
                {
                    "proposal_id": "invalid-child",
                    "parent_rejection_fingerprint": "not-a-fingerprint",
                    "discriminator": "malformed parent",
                },
            ),
            event(
                12,
                "no-discriminator-child",
                "proposal.created",
                {
                    "proposal_id": "no-discriminator-child",
                    "parent_rejection_fingerprint": rejected_fingerprint,
                },
            ),
        ]
        write_events(root, rows)

        measurement = build_report(root)["measurement"]
        lineage = measurement["scoring_proposal_retry_lineage"]

        self.assertEqual(measurement["scheduled_retry_lineage"], measurement["retry_lineage"])
        self.assertEqual(lineage["proposal_denominator"], 9)
        self.assertEqual(lineage["proposals_with_parent_fingerprint"], 5)
        self.assertEqual(lineage["proposals_missing_parent_fingerprint"], 4)
        self.assertEqual(lineage["proposals_with_invalid_parent_fingerprint"], 1)
        self.assertEqual(lineage["proposals_missing_discriminator"], 1)
        self.assertEqual(lineage["proposals_with_valid_parent_lineage"], 1)
        self.assertEqual(lineage["proposals_with_known_parent_fingerprint"], 1)
        self.assertEqual(lineage["proposals_with_unknown_parent_fingerprint"], 2)
        temporary.cleanup()

    def test_retry_metrics_require_matching_unique_parent_identity(self) -> None:
        fingerprint_one = "a" * 64
        fingerprint_two = "b" * 64
        candidate_one = "c" * 64
        candidate_two = "d" * 64
        rows = [
            event(1, "parent-one", "execution.rejected", {
                "plan_id": "parent-one", "proposal_id": "parent-one", "objective_id": "one",
                "retry": {"fingerprint": fingerprint_one, "candidate_identity_sha256": candidate_one},
            }),
            event(2, "child-one", "proposal.created", {
                "proposal_id": "child-one", "objective_id": "one", "candidate_identity_sha256": candidate_one,
                "parent_rejection_fingerprint": fingerprint_one, "discriminator": "new method",
            }),
            event(3, "child-duplicate", "proposal.created", {
                "proposal_id": "child-duplicate", "objective_id": "one", "candidate_identity_sha256": candidate_one,
                "parent_rejection_fingerprint": fingerprint_one, "discriminator": "same parent reused",
            }),
            event(4, "parent-two", "execution.indeterminate", {
                "plan_id": "parent-two", "proposal_id": "parent-two", "objective_id": "two",
                "retry": {"fingerprint": fingerprint_two, "candidate_identity_sha256": candidate_two},
            }),
            event(5, "child-cross", "proposal.created", {
                "proposal_id": "child-cross", "objective_id": "one", "candidate_identity_sha256": candidate_one,
                "parent_rejection_fingerprint": fingerprint_two, "discriminator": "cross candidate",
            }),
        ]

        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        write_events(root, rows)
        lineage = build_report(root)["measurement"]["scoring_proposal_retry_lineage"]

        self.assertEqual(lineage["proposals_with_valid_parent_lineage"], 1)
        self.assertEqual(lineage["proposals_with_known_parent_fingerprint"], 1)
        self.assertEqual(lineage["proposals_with_unknown_parent_fingerprint"], 2)
        temporary.cleanup()

    def test_comparison_readiness_stays_ineligible_when_required_records_are_missing(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        write_events(root, [event(1, "proposal", "proposal.created", {"proposal_id": "p1"})])

        report = build_report(root)
        readiness = report["comparison_readiness"]

        self.assertTrue(report["coherent"])
        self.assertFalse(readiness["comparison_eligible"])
        self.assertEqual(readiness["effectiveness_claims"]["availability"], "not_available")
        self.assertFalse(readiness["gates"]["command_scan"]["passed"])
        self.assertFalse(readiness["gates"]["command_lifecycle"]["passed"])
        self.assertFalse(readiness["gates"]["evidence_completeness"]["passed"])
        self.assertFalse(readiness["gates"]["baseline_binding"]["passed"])
        temporary.cleanup()


if __name__ == "__main__":
    unittest.main(verbosity=2)
