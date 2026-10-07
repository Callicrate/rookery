from __future__ import annotations

# ruff: noqa: E402

import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests.rookery.support import ROOKERY_ROOT

LIB = ROOKERY_ROOT / "lib"
if str(LIB) not in sys.path:
    sys.path.insert(0, str(LIB))
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

from rookery.portable.telemetry import build_report
from rookery.portable.util import canonical_json


def event(sequence: int, event_id: str, event_type: str, payload: dict[str, object] | None = None) -> dict[str, object]:
    return {
        "seq": sequence,
        "event_id": event_id,
        "event_type": event_type,
        "created_at": f"2026-08-08T00:00:{sequence:02d}Z",
        "generation": 0,
        "actor": "fixture",
        "payload": payload or {},
    }


def write_events(
    root: Path,
    rows: list[dict[str, object]],
    *,
    sqlite_rows: list[dict[str, object]] | None = None,
    wal_mode: bool = False,
) -> None:
    state = root / "state"
    state.mkdir(parents=True)
    (state / "events.jsonl").write_text(
        "".join(canonical_json(row) + "\n" for row in rows), encoding="utf-8"
    )
    if sqlite_rows is None:
        sqlite_rows = rows
    connection = sqlite3.connect(state / "events.sqlite3")
    try:
        if wal_mode:
            connection.execute("PRAGMA journal_mode=WAL")
        connection.execute(
            "CREATE TABLE events (seq INTEGER, event_id TEXT, event_type TEXT, created_at TEXT, generation INTEGER, actor TEXT, payload_json TEXT)"
        )
        for row in sqlite_rows:
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


def write_v2_command(root: Path, secret: str) -> None:
    command_dir = root / "logs" / "commands" / "fixture-command"
    command_dir.mkdir(parents=True)
    stdout = f"output contains {secret}\n".encode()
    stderr = b""
    (command_dir / "stdout.log").write_bytes(stdout)
    (command_dir / "stderr.log").write_bytes(stderr)
    command = ["curl", "--user", secret]
    meta = {
        "schema_version": "2",
        "command_id": "fixture-command",
        "complete": True,
        "command": command,
        "argv_sha256": hashlib.sha256(canonical_json(command).encode()).hexdigest(),
        "exit_code": 0,
        "termination": "exited",
        "stdout_path": "logs/commands/fixture-command/stdout.log",
        "stderr_path": "logs/commands/fixture-command/stderr.log",
        "stdout_bytes": len(stdout),
        "stderr_bytes": len(stderr),
        "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
        "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
    }
    digest = {
        "schema_version": "2",
        "complete": True,
        "byte_count": len(stdout),
        "sha256": meta["stdout_sha256"],
        "stderr": {"byte_count": 0, "sha256": meta["stderr_sha256"]},
    }
    (command_dir / "meta.json").write_text(json.dumps(meta), encoding="utf-8")
    (command_dir / "digest.json").write_text(json.dumps(digest), encoding="utf-8")


class TelemetryReportTests(unittest.TestCase):
    def test_measurement_audit_uses_explicit_denominators_and_availability(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        rows = [
            event(1, "p1", "proposal.created", {"proposal_id": "p1", "objective_id": "one"}),
            event(2, "r1", "execution.rejected", {"proposal_id": "p1", "verdict": {"verdict": "rejected"}}),
            event(3, "p2", "proposal.created", {"proposal_id": "p2", "objective_id": "two", "retry_of": "p1"}),
            event(4, "r2", "execution.completed", {"proposal_id": "p2", "verdict": {"verdict": "accepted"}}),
            event(5, "retry", "retry.scheduled", {"retry_id": "r1", "objective_id": "two"}),
            event(6, "stop", "control.stop", {"generation": 1, "requested_at": "2026-08-08T00:01:00Z"}),
            event(7, "ack", "job.cancelled", {"job_id": "owned", "owner_token": "owned-token", "closed_at": "2026-08-08T00:01:06Z", "resource_summary": {"cpu_seconds": 3, "rss_bytes": 4096, "peak_rss_bytes": 8192}}),
            event(8, "job2", "job.closed", {"job_id": "external", "owned": False, "resource_summary": {}}),
        ]
        for index, row in enumerate(rows):
            row["created_at"] = f"2026-08-08T00:00:{index * 5:02d}Z"
        rows[6]["generation"] = 1
        write_events(root, rows)

        measurement = build_report(root)["measurement"]

        self.assertEqual(measurement["event_window"]["availability"], "available")
        self.assertEqual(measurement["event_window"]["denominator_events"], 8)
        latency = measurement["proposal_to_terminal_latency"]
        self.assertEqual(latency["scope"], "per_proposal_event")
        self.assertEqual(latency["proposal_event_denominator"], 2)
        self.assertEqual(latency["terminal_denominator"], 2)
        self.assertEqual(latency["by_outcome"]["rejected"]["matched"], 1)
        self.assertEqual(latency["by_outcome"]["accepted"]["latency_seconds"]["mean"], 5.0)
        self.assertEqual(measurement["retry_lineage"]["availability"], "not_available")
        self.assertEqual(measurement["retry_lineage"]["reason"], "typed_retry_parent_fields_not_emitted")
        self.assertEqual(measurement["stop_reconciliation"]["duration_seconds"]["mean"], 6.0)
        self.assertEqual(measurement["queue_timing"]["reason"], "canonical_queue_timing_events_not_emitted")
        resources = measurement["resources"]
        self.assertEqual(resources["terminal_jobs"], 2)
        self.assertEqual(resources["terminal_jobs_with_resource"], 1)
        self.assertEqual(resources["owned_coverage"]["numerator_owned_terminal_jobs_with_resource"], 1)
        self.assertEqual(resources["cpu_seconds"]["unit"], "seconds")
        self.assertEqual(resources["provider_tokens"]["availability"], "not_available")
        temporary.cleanup()

    def test_measurement_legacy_data_is_unavailable_not_zero(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        rows = [event(1, "legacy", "goal.set")]
        rows[0]["created_at"] = "not-a-timestamp"
        write_events(root, rows)

        measurement = build_report(root)["measurement"]

        self.assertEqual(measurement["event_window"]["availability"], "not_available")
        self.assertEqual(measurement["proposal_to_terminal_latency"]["reason"], "proposal_or_terminal_events_absent")
        self.assertEqual(measurement["queue_timing"]["availability"], "not_available")
        self.assertEqual(measurement["queue_timing"]["reason"], "canonical_queue_timing_events_not_emitted")
        self.assertEqual(measurement["resources"]["provider_queue"]["reason"], "provider_queue_seconds_not_emitted")
        temporary.cleanup()

    def test_valid_report_is_private_and_does_not_create_sqlite_sidecars(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        (root / "VERSION").write_text("2026.08.28\n", encoding="utf-8")
        (root / "evidence").mkdir()
        (root / "evidence" / "plan.md").write_text("plan", encoding="utf-8")
        (root / "evidence" / "response.json").write_text("{}", encoding="utf-8")
        rows = [
            event(
                1,
                "one",
                "proposal.created",
                {"proposal_id": "proposal", "agent_attempt_id": "attempt-fixture"},
            ),
            event(2, "two", "review.recorded", {"proposal_id": "proposal", "verdict": "approved"}),
            event(3, "three", "execution.planned", {"plan_id": "plan", "evidence_paths": ["/home/operator/rookery/evidence/plan.md"]}),
            event(4, "command-requested", "command.requested", {"command_id": "fixture-command"}),
            event(5, "command-completed", "command.completed", {"command_id": "fixture-command"}),
            event(6, "four", "control.stop"),
            event(
                7,
                "five",
                "execution.completed",
                {
                    "plan_id": "plan",
                    "response_path": "/home/operator/rookery/evidence/response.json",
                    "evidence_root": "/home/operator/rookery/evidence",
                    "verdict": {"verdict": "accepted"},
                },
            ),
            event(
                8,
                "six",
                "agent.closed",
                {"agent_id": "agent", "agent_attempt_id": "attempt-fixture"},
            ),
            event(
                9,
                "outcome",
                "outcome.recorded",
                {"outcome_id": "outcome", "agent_attempt_id": "attempt-fixture"},
            ),
            event(
                10,
                "job-terminal",
                "job.cancelled",
                {
                    "job_id": "job-fixture",
                    "resource_summary": {
                        "cpu_seconds": 0.1,
                        "rss_bytes": 4096,
                        "peak_rss_bytes": 8192,
                    },
                },
            ),
        ]
        write_events(root, rows)
        secret = "fixture-secret-must-not-appear"
        write_v2_command(root, secret)

        report = build_report(root, source_root="/home/operator/rookery")
        rendered = json.dumps(report, sort_keys=True)

        self.assertTrue(report["coherent"], report)
        self.assertEqual(report["release_version"], "2026.08.28")
        self.assertTrue(report["canonical"]["sqlite"]["matches_jsonl"])
        self.assertEqual(report["commands"]["v2_hashes"]["verified"], 1)
        self.assertEqual(report["commands"]["lifecycle"]["paired_events"], 1)
        self.assertEqual(report["commands"]["lifecycle"]["envelope_only"], 0)
        self.assertEqual(report["events"]["agents"]["attempt_ids"], 1)
        self.assertEqual(
            report["events"]["agents"]["terminal_attempts_missing_outcome"],
            0,
        )
        self.assertEqual(report["events"]["workflow"]["proposal_attempt_links"], 1)
        self.assertEqual(report["events"]["workflow"]["outcome_attempt_links"], 1)
        self.assertEqual(
            report["events"]["jobs"]["terminal_with_resource_summary"],
            1,
        )
        self.assertEqual(report["events"]["stop"]["post_stop_terminal_outcomes"], 1)
        self.assertEqual(report["evidence"]["plan_evidence_paths"]["present"], 1)
        self.assertNotIn(secret, rendered)
        self.assertNotIn("curl", rendered)
        self.assertFalse((root / "state" / "events.sqlite3-wal").exists())
        self.assertFalse((root / "state" / "events.sqlite3-shm").exists())
        queue_watch = root / "logs" / "queue-watch"
        queue_watch.mkdir(parents=True)
        (queue_watch / "stdout.log").write_bytes(b"one\ntwo")
        self.assertEqual(build_report(root)["queue_watch"]["lines"], 2)
        temporary.cleanup()

    def test_sqlite_count_bound_is_enforced_before_materialization(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        jsonl_rows = [event(1, "one", "goal.set"), event(2, "two", "goal.supersede")]
        sqlite_rows = [*jsonl_rows, event(3, "three", "goal.set")]
        write_events(root, jsonl_rows, sqlite_rows=sqlite_rows)

        with mock.patch(
            "rookery.portable.telemetry.MAX_EVENT_COUNT",
            2,
        ):
            report = build_report(root)

        self.assertFalse(report["coherent"])
        self.assertIn("sqlite.too_many", {entry["code"] for entry in report["errors"]})
        temporary.cleanup()

    def test_sqlite_file_size_bounds_preflight_scan_work(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        rows = [event(1, "one", "goal.set")]
        write_events(root, rows)
        size = (root / "state/events.sqlite3").stat().st_size

        with mock.patch(
            "rookery.portable.telemetry.MAX_SQLITE_FILE_BYTES",
            size - 1,
        ):
            report = build_report(root)

        self.assertFalse(report["coherent"])
        self.assertIn(
            "sqlite.file_too_large",
            {entry["code"] for entry in report["errors"]},
        )
        temporary.cleanup()

    def test_wal_format_main_database_is_read_immutably(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        rows = [event(1, "one", "goal.set")]
        write_events(root, rows, wal_mode=True)
        state = root / "state"
        self.assertFalse((state / "events.sqlite3-wal").exists())
        self.assertFalse((state / "events.sqlite3-shm").exists())
        before = {
            path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in state.iterdir()
            if path.is_file()
        }

        report = build_report(root)

        after = {
            path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in state.iterdir()
            if path.is_file()
        }
        self.assertTrue(report["coherent"], report)
        self.assertEqual(before, after)
        self.assertFalse((state / "events.sqlite3-wal").exists())
        self.assertFalse((state / "events.sqlite3-shm").exists())
        temporary.cleanup()

    def test_preserved_sqlite_sidecars_fail_closed_without_opening(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        rows = [event(1, "one", "goal.set")]
        write_events(root, rows)
        wal = root / "state" / "events.sqlite3-wal"
        wal.write_bytes(b"preserved")

        report = build_report(root)

        self.assertFalse(report["coherent"])
        self.assertIn(
            "sqlite.sidecar_present",
            {entry["code"] for entry in report["errors"]},
        )
        self.assertEqual(wal.read_bytes(), b"preserved")
        temporary.cleanup()

    def test_invalid_events_and_sqlite_mismatch_make_report_noncoherent(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        rows = [event(1, "duplicate", "goal.set"), event(2, "duplicate", "goal.supersede")]
        sqlite_rows = [event(1, "different", "goal.set")]
        write_events(root, rows, sqlite_rows=sqlite_rows)

        report = build_report(root)
        codes = {entry["code"] for entry in report["errors"]}

        self.assertFalse(report["coherent"])
        self.assertIn("events.duplicate_event_id", codes)
        self.assertIn("sqlite.logical_mismatch", codes)
        self.assertFalse((root / "state" / "events.sqlite3-wal").exists())
        temporary.cleanup()

    def test_source_remap_rejects_traversal_and_standalone_cli_returns_json(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        (root / "evidence").mkdir()
        (root / "evidence" / "valid.txt").write_text("ok", encoding="utf-8")
        rows = [
            event(
                1,
                "plan",
                "execution.planned",
                {
                    "plan_id": "plan",
                    "evidence_paths": [
                        "/home/operator/rookery/evidence/valid.txt",
                        "/home/operator/rookery/../outside.txt",
                    ],
                },
            )
        ]
        write_events(root, rows)
        output = root.parent / "telemetry-report.json"
        environment = {**os.environ, "PYTHONPATH": str(LIB), "PYTHONDONTWRITEBYTECODE": "1"}
        completed = subprocess.run(
            [
                sys.executable,
                str(ROOKERY_ROOT / "bin" / "telemetry-report"),
                str(root),
                "--source-root",
                "/home/operator/rookery",
                "--output",
                str(output),
            ],
            text=True,
            capture_output=True,
            env=environment,
            timeout=30,
        )
        report = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(completed.returncode, 0, completed.stderr)
        paths = report["evidence"]["plan_evidence_paths"]
        self.assertEqual(paths["present"], 1)
        self.assertEqual(paths["rejected"], 1)
        temporary.cleanup()


if __name__ == "__main__":
    unittest.main(verbosity=2)
