from __future__ import annotations

# ruff: noqa: E402

import hashlib
import json
import os
import sys
import threading
import unittest
from pathlib import Path

from tests.rookery.support import (
    ROOKERY_ROOT,
    install_solver_ready_challenge,
    open_test_event_store,
    render_handoff_report,
)

LIB = ROOKERY_ROOT / "lib"
if str(LIB) not in sys.path:
    sys.path.insert(0, str(LIB))
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

from rookery.portable.intake import (
    capture_artifact_status,
    capture_key,
    challenge_intake_status,
    platform_solver_eligibility,
)
from rookery.portable.outcomes import (
    close_current_agent_attempt,
    continuation_audit,
    harvest_report,
    record_continuation_boundary,
    record_outcome,
    register_agent_attempt,
)
from rookery.portable.priority import rank_challenges
from rookery.portable.control import stop
from rookery.portable.store import EventStore
from tests.rookery.test_acceptance_campaign import make_workspace, run_cli


class AgentAttemptIntegrityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.workspace = make_workspace("fixture")
        self.root = Path(self.workspace.name)
        self.store = open_test_event_store(self.root)
        self.store.append(
            "challenge.upsert",
            {"id": "101", "classification": "untriaged"},
            actor="fixture",
        )
        self._complete_intake()

    def tearDown(self) -> None:
        self.workspace.cleanup()

    def _complete_intake(self) -> None:
        intake = self.root / "captures" / "challenge-101"
        intake.mkdir(parents=True, exist_ok=True)
        detail = intake / "detail.json"
        capture = intake / "fixture.bin"
        files = [{"path": "fixture.bin"}]
        detail_bytes = json.dumps(
            {"id": "101", "files": files}, sort_keys=True
        ).encode("utf-8")
        capture_bytes = b"fixture intake bytes\n"
        detail.write_bytes(detail_bytes)
        capture.write_bytes(capture_bytes)
        detail.chmod(0o600)
        capture.chmod(0o600)
        self.store.append(
            "challenge.upsert",
            {
                "id": "101",
                "classification": "untriaged",
                "files": files,
                "detail_path": "captures/challenge-101/detail.json",
                "detail_sha256": hashlib.sha256(detail_bytes).hexdigest(),
                "detail_bytes": len(detail_bytes),
                "captured_files": [
                    {
                        "attachment_name": "fixture.bin",
                        "capture_key": capture_key(0, files[0]),
                        "path": "captures/challenge-101/fixture.bin",
                        "sha256": hashlib.sha256(capture_bytes).hexdigest(),
                        "bytes": len(capture_bytes),
                    }
                ],
                "expected_file_count": 1,
                "captured_file_count": 1,
                "ingested_at": "2026-10-02T00:00:00Z",
                "intake_state": "complete",
                "intake_missing_material": [],
                "resources_truncated": False,
                "resources_complete": True,
            },
            actor="fixture",
        )

    def _intake_row(self) -> dict[str, object]:
        return dict(self.store.rebuild()["current"]["challenges"]["101"])

    def _replace_intake(self, **changes: object) -> None:
        self.store.append(
            "challenge.upsert", {**self._intake_row(), **changes}, actor="fixture"
        )

    def _assert_registration_intake_rejected(self, attempt_id: str) -> None:
        with self.assertRaisesRegex(ValueError, "challenge intake is not solver-ready"):
            register_agent_attempt(
                self.store,
                self._challenge_registration(f"intake-{attempt_id}", attempt_id),
                max_workers=0,
            )

    def test_challenge_registration_requires_complete_verified_intake(self) -> None:
        admitted = register_agent_attempt(
            self.store,
            self._challenge_registration("intake-ready", "intake-ready"),
            max_workers=0,
        )
        self.assertTrue(admitted["admitted"])
        self.assertTrue(challenge_intake_status(self.root, self._intake_row())["ready"])
        self.assertEqual(challenge_intake_status(self.root, self._intake_row())["reason"], "")

    def _authoritative_snapshot(self, challenges: list[dict[str, object]], *, health: str = "healthy") -> None:
        self.store.append(
            "platform.snapshot",
            {
                "adapter_id": "fixture",
                "capabilities": {
                    "platform_inventory": {
                        "availability": "available",
                        "health": health,
                    }
                },
                "challenges": challenges,
            },
            actor="fixture",
        )

    def test_authoritative_inventory_omission_blocks_dispatch_until_reappearance(self) -> None:
        self._authoritative_snapshot([{"id": "101", "title": "fixture"}])
        self._authoritative_snapshot([])

        omitted = self._intake_row()
        self.assertFalse(omitted["platform_present"])
        self.assertEqual(challenge_intake_status(self.root, omitted)["reason"], "unavailable")
        self._assert_registration_intake_rejected("authoritative-omission")
        frontier = rank_challenges([omitted], {"priority": {"weights": {}}})
        self.assertEqual(frontier[0]["solver_ineligible_reason"], "unavailable")
        projection = self.store.rebuild()["current"]
        self.assertEqual(projection["counts"]["visible"], 0)
        self.assertEqual(projection["counts"]["unsolved"], 0)
        baseline = projection["authoritative_platform"]
        self.assertEqual(baseline["challenge_ids"], [])
        self.assertEqual(baseline["challenge_count"], 0)
        self.assertNotIn("challenges", baseline)

        self._authoritative_snapshot([{"id": "101", "title": "returned", "files": []}])

        returned = self._intake_row()
        self.assertTrue(returned["platform_present"])
        self.assertTrue(challenge_intake_status(self.root, returned)["ready"])
        admitted = register_agent_attempt(
            self.store,
            self._challenge_registration("intake-reappeared", "intake-reappeared"),
            max_workers=0,
        )
        self.assertTrue(admitted["admitted"])

    def test_unhealthy_empty_inventory_does_not_retire_present_challenge(self) -> None:
        self._authoritative_snapshot([{"id": "101", "title": "fixture"}])
        self._authoritative_snapshot([], health="unhealthy")

        challenge = self._intake_row()
        self.assertTrue(challenge["platform_present"])
        self.assertTrue(challenge_intake_status(self.root, challenge)["ready"])

    def test_challenge_registration_rejects_missing_intake_markers(self) -> None:
        self._replace_intake(detail_path="", ingested_at="")
        self._assert_registration_intake_rejected("missing-marker")

    def test_challenge_registration_rejects_partial_intake(self) -> None:
        self._replace_intake(intake_state="partial")
        self._assert_registration_intake_rejected("partial")
        self.assertEqual(
            challenge_intake_status(self.root, self._intake_row())["reason"], "intake_partial"
        )

    def test_intake_gate_precedes_worker_capacity_admission(self) -> None:
        first = register_agent_attempt(
            self.store,
            self._challenge_registration("intake-capacity-first", "intake-capacity-first"),
            max_workers=1,
        )
        self.assertTrue(first["admitted"])
        self._replace_intake(intake_state="partial")
        self._assert_registration_intake_rejected("intake-before-capacity")

    def test_challenge_registration_rejects_truncated_resources(self) -> None:
        self._replace_intake(resources_truncated=True)
        self._assert_registration_intake_rejected("truncated")

    def test_challenge_registration_rejects_capture_error_or_missing_capture(self) -> None:
        capture = dict(self._intake_row()["captured_files"][0])
        capture["error"] = "fixture failure"
        self._replace_intake(captured_files=[capture])
        self._assert_registration_intake_rejected("capture-error")
        self._complete_intake()
        self._replace_intake(captured_files=[])
        self._assert_registration_intake_rejected("capture-missing")

    def test_challenge_registration_rejects_tampered_or_symlink_capture(self) -> None:
        capture = self.root / "captures" / "challenge-101" / "fixture.bin"
        capture.write_bytes(b"tampered")
        capture.chmod(0o600)
        self._assert_registration_intake_rejected("tampered")
        self._complete_intake()
        capture.unlink()
        try:
            capture.symlink_to(self.root / "captures" / "challenge-101" / "detail.json")
        except OSError as exc:
            self.skipTest(f"symlinks unavailable: {exc}")
        self._assert_registration_intake_rejected("symlink")

    def test_challenge_registration_rejects_detail_attachment_contradiction(self) -> None:
        self._replace_intake(
            files=[],
            captured_files=[],
            expected_file_count=0,
            captured_file_count=0,
        )
        status = challenge_intake_status(self.root, self._intake_row())
        self.assertFalse(status["ready"])
        self.assertEqual(status["reason"], "intake_invalid")
        self._assert_registration_intake_rejected("detail-files-mismatch")

    def test_platform_eligibility_is_independent_from_intake_metadata(self) -> None:
        self.assertTrue(platform_solver_eligibility({"id": "101"})["ready"])
        blocked = platform_solver_eligibility(
            {
                "id": "101",
                "classification": "policy_blocked",
                "hidden": True,
                "solvable": False,
                "submission_mode": "manual",
                "submittable": False,
            }
        )
        self.assertFalse(blocked["ready"])
        self.assertEqual(
            blocked["reasons"],
            [
                "challenge_policy_blocked",
                "challenge_hidden",
                "challenge_unsupported",
                "challenge_manual",
                "challenge_not_submittable",
            ],
        )
        blocked = challenge_intake_status(
            self.root, {**self._intake_row(), "hidden": True}
        )
        self.assertEqual(blocked["reason"], "hidden")
        combined = challenge_intake_status(
            self.root,
            {
                **self._intake_row(),
                "classification": "policy_blocked",
                "hidden": True,
            },
        )
        self.assertEqual(combined["reason"], "policy_blocked")
        unsupported = platform_solver_eligibility(
            {"solvable": False, "submission_mode": "unsupported"}
        )
        self.assertEqual(unsupported["reasons"], ["challenge_unsupported"])

    def test_platform_eligibility_rejects_normalized_and_raw_locked_or_solved_modes(self) -> None:
        for fields, expected_reason in (
            ({"submission_mode": "locked"}, "locked"),
            ({"submission_mode": "already_solved"}, "solved"),
            ({"raw": {"submissionMode": "locked"}}, "locked"),
            ({"raw": {"submissionMode": "already_solved"}}, "solved"),
        ):
            with self.subTest(fields=fields):
                blocked = challenge_intake_status(self.root, {**self._intake_row(), **fields})
                self.assertFalse(blocked["ready"])
                self.assertEqual(blocked["reason"], expected_reason)

    def test_capture_artifact_status_requires_verified_private_bytes(self) -> None:
        capture = self._intake_row()["captured_files"][0]
        self.assertTrue(capture_artifact_status(self.root, capture)["ready"])
        capture = {**capture, "bytes": int(capture["bytes"]) + 1}
        self.assertFalse(capture_artifact_status(self.root, capture)["ready"])

    def test_capture_key_binds_the_full_attachment_declaration(self) -> None:
        first = {"name": "fixture.bin", "url": "https://example.test/one"}
        second = {"name": "fixture.bin", "url": "https://example.test/two"}
        self.assertRegex(capture_key(0, first), r"^[0-9a-f]{64}$")
        self.assertNotEqual(capture_key(0, first), capture_key(0, second))

    def test_event_wide_registration_is_exempt_from_intake_gate(self) -> None:
        self._replace_intake(intake_state="pending")
        admitted = register_agent_attempt(
            self.store,
            self._registration("event-intake-exempt", "event-intake-exempt"),
            max_workers=0,
        )
        self.assertTrue(admitted["admitted"])

    def _register(
        self,
        attempt_id: str,
        *,
        objective_id: str = "101",
        challenge_linked: bool = False,
    ) -> None:
        self.store.append(
            "agent.running",
            {
                "agent_id": "agent-a",
                "agent_attempt_id": attempt_id,
                "objective_id": objective_id,
                "challenge_id": "101" if challenge_linked else "",
                "event_wide": not challenge_linked,
                "role": "worker",
                "report_path": "analysis/agent-a/REPORT.md",
            },
            actor="coordinator",
        )

    @staticmethod
    def _registration(agent_id: str, attempt_id: str) -> dict[str, object]:
        return {
            "agent_id": agent_id,
            "agent_attempt_id": attempt_id,
            "parent_agent_attempt_id": "",
            "objective_id": "101",
            "challenge_id": "",
                "event_wide": True,
                "source_handoff_id": "none",
                "goal": "collect one bounded fixture result",
                "scope": "fixture event-wide lane",
                "stop_condition": "report one exact result",
                "role": "worker",
            "report_path": f"analysis/{agent_id}/REPORT.md",
            "owner": "coordinator",
            "pid": 0,
            "pgid": 0,
            "process_starttime": "",
            "owner_token": "",
            "started_at": "2026-08-28T00:00:00Z",
        }

    def _handoff_and_boundary(
        self,
        *,
        agent_id: str,
        attempt_id: str,
        report_path: str,
        status: str,
        route_key: str,
        source_handoff_id: str = "none",
    ) -> tuple[str, str]:
        source_report_sha256 = "none"
        if source_handoff_id != "none":
            registration = next(
                event["payload"]
                for event in self.store.events("agent.running")
                if str(event["payload"].get("agent_attempt_id") or "") == attempt_id
            )
            source_report_sha256 = str(
                registration["assignment_packet"]["source_report_sha256"]
            )
        self._write_canonical_report(
            report_path,
            status=status,
            route_key=route_key,
            source_handoff_id=source_handoff_id,
            source_report_sha256=source_report_sha256,
        )
        handoff = harvest_report(
            self.store,
            self.root,
            report_path,
            agent_id=agent_id,
            agent_attempt_id=attempt_id,
            challenge_id="101",
            objective_id="101",
            status=status,
            observed_result=f"{status} from {route_key}",
            route_key=route_key,
            proof_gap="the next route remains untested",
            next_step_or_return_trigger="run the named fixture continuation",
        )
        boundary = record_continuation_boundary(
            self.store,
            challenge_id="101",
            objective_id="101",
            name=f"continue-{attempt_id}",
            return_condition="the named fixture continuation completes",
            source_handoff_id=str(handoff["handoff_id"]),
        )
        return str(handoff["handoff_id"]), str(boundary["boundary_id"])

    def _write_canonical_report(
        self,
        report_path: str,
        *,
        status: str,
        route_key: str,
        source_handoff_id: str = "none",
        source_report_sha256: str = "none",
    ) -> None:
        report = self.root / report_path
        report.parent.mkdir(parents=True, exist_ok=True)
        command_path = report.parent / "command.txt"
        command_path.write_text("fixture-command --route exact\n", encoding="utf-8")
        report.write_text(
            render_handoff_report(
                status=status,
                source_handoff=source_handoff_id,
                source_report_sha256=source_report_sha256,
                observed_result=f"{status} from {route_key}",
                route_key=route_key,
                proof_gap="the next route remains untested",
                discriminating_test="run the named fixture continuation",
                next_step_or_return_trigger="run the named fixture continuation",
                evidence_paths=(report_path,),
                command_artifact_paths=(command_path.relative_to(self.root).as_posix(),),
                cleanup_jobs="none",
                evidence_body="Exact fixture evidence records the observed route and remaining proof gap.",
                commands_body="fixture-command --route exact",
            ),
            encoding="utf-8",
        )

    @staticmethod
    def _challenge_registration(agent_id: str, attempt_id: str, source_handoff_id: str = "none") -> dict[str, object]:
        return {
            "agent_id": agent_id,
            "agent_attempt_id": attempt_id,
            "parent_agent_attempt_id": "",
            "objective_id": "101",
            "challenge_id": "101",
            "event_wide": False,
            "source_handoff_id": source_handoff_id,
            "goal": "collect challenge evidence",
            "scope": "challenge 101 fixture lane",
            "stop_condition": "write canonical handoff",
            "role": "worker",
            "report_path": f"analysis/{agent_id}/REPORT.md",
            "owner": "coordinator",
            "pid": 0,
            "pgid": 0,
            "process_starttime": "",
            "owner_token": "",
            "started_at": "2026-08-28T00:00:00Z",
        }

    def test_nested_worker_requires_exact_active_challenge_coordinator_parent(
        self,
    ) -> None:
        parent = self._challenge_registration("coordinator-101", "attempt-parent")
        parent["role"] = "challenge-coordinator"
        admitted_parent = register_agent_attempt(self.store, parent, max_workers=8)
        self.assertEqual(admitted_parent["output"]["agent_depth"], 1)

        child = self._challenge_registration("worker-101", "attempt-child")
        child["parent_agent_attempt_id"] = "attempt-parent"
        admitted_child = register_agent_attempt(self.store, child, max_workers=8)
        self.assertEqual(admitted_child["output"]["agent_depth"], 2)
        packet = admitted_child["output"]["assignment_packet"]
        self.assertEqual(packet["role"], "worker")
        self.assertEqual(packet["parent_agent_attempt_id"], "attempt-parent")
        self.assertEqual(packet["agent_depth"], 2)

        grandchild = self._challenge_registration("nested-worker", "attempt-grandchild")
        grandchild["parent_agent_attempt_id"] = "attempt-child"
        with self.assertRaisesRegex(ValueError, "depth-1 challenge coordinator"):
            register_agent_attempt(self.store, grandchild, max_workers=8)

    def test_challenge_coordinator_role_aliases_are_normalized_for_children(self) -> None:
        for index, role in enumerate(
            ("challenge_coordinator", "ctf_autopilot_coordinator"), start=1
        ):
            with self.subTest(role=role):
                challenge_id = str(100 + index)
                install_solver_ready_challenge(self.root, self.store, challenge_id)
                parent_attempt_id = f"attempt-parent-{index}"
                parent = self._challenge_registration(
                    f"coordinator-{challenge_id}", parent_attempt_id
                )
                parent["challenge_id"] = challenge_id
                parent["objective_id"] = challenge_id
                parent["role"] = role
                admitted_parent = register_agent_attempt(
                    self.store, parent, max_workers=8
                )
                self.assertEqual(
                    admitted_parent["output"]["role"], "challenge-coordinator"
                )

                child = self._challenge_registration(
                    f"worker-{challenge_id}", f"attempt-child-{index}"
                )
                child["challenge_id"] = challenge_id
                child["objective_id"] = challenge_id
                child["parent_agent_attempt_id"] = parent_attempt_id
                admitted_child = register_agent_attempt(
                    self.store, child, max_workers=8
                )
                self.assertEqual(admitted_child["output"]["agent_depth"], 2)

    def test_nested_worker_rejects_missing_or_mismatched_parent(self) -> None:
        missing = self._challenge_registration("missing-parent", "attempt-missing")
        missing["parent_agent_attempt_id"] = "attempt-ghost"
        with self.assertRaisesRegex(ValueError, "active in the current generation"):
            register_agent_attempt(self.store, missing, max_workers=8)

        parent = self._challenge_registration("coordinator-101", "attempt-parent")
        parent["role"] = "challenge-coordinator"
        register_agent_attempt(self.store, parent, max_workers=8)
        mismatched = self._challenge_registration("wrong-objective", "attempt-wrong")
        mismatched["parent_agent_attempt_id"] = "attempt-parent"
        mismatched["objective_id"] = "different-objective"
        with self.assertRaisesRegex(ValueError, "objective_id must equal challenge_id"):
            register_agent_attempt(self.store, mismatched, max_workers=8)

    def test_nested_worker_rejects_inactive_or_stale_parent(self) -> None:
        parent = self._challenge_registration("coordinator-101", "attempt-parent")
        parent["role"] = "challenge-coordinator"
        register_agent_attempt(self.store, parent, max_workers=8)
        self.store.append(
            "agent.closed",
            {
                "agent_id": "coordinator-101",
                "agent_attempt_id": "attempt-parent",
                "objective_id": "101",
            },
            actor="fixture",
        )
        inactive = self._challenge_registration("inactive-child", "attempt-inactive")
        inactive["parent_agent_attempt_id"] = "attempt-parent"
        with self.assertRaisesRegex(ValueError, "active in the current generation"):
            register_agent_attempt(self.store, inactive, max_workers=8)

        fresh_parent = self._challenge_registration("coordinator-fresh", "attempt-fresh")
        fresh_parent["role"] = "challenge-coordinator"
        register_agent_attempt(self.store, fresh_parent, max_workers=8)
        self.store.set_meta("stop_generation", 1)
        self.store.append(
            "control.resume",
            {"generation": 1, "reason": "fixture resume"},
            actor="operator",
            generation=1,
        )
        stale = self._challenge_registration("stale-child", "attempt-stale")
        stale["parent_agent_attempt_id"] = "attempt-fresh"
        with self.assertRaisesRegex(ValueError, "active in the current generation"):
            register_agent_attempt(self.store, stale, max_workers=8)

    def test_empty_or_noncanonical_challenge_report_is_rejected(self) -> None:
        self._register("attempt-empty", challenge_linked=True)
        report_path = "analysis/agent-a/REPORT.md"
        report = self.root / report_path
        report.parent.mkdir(parents=True, exist_ok=True)
        report.write_text("", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "nonempty"):
            harvest_report(
                self.store,
                self.root,
                report_path,
                agent_id="agent-a",
                agent_attempt_id="attempt-empty",
                challenge_id="101",
                objective_id="101",
                status="technical_negative",
                observed_result="fixture result",
                route_key="fixture-route",
                proof_gap="fixture gap",
                next_step_or_return_trigger="fixture next step",
            )
        self._write_canonical_report(report_path, status="technical_negative", route_key="fixture-route")
        with self.assertRaisesRegex(ValueError, "CLI fields do not match"):
            harvest_report(
                self.store,
                self.root,
                report_path,
                agent_id="agent-a",
                agent_attempt_id="attempt-empty",
                challenge_id="101",
                objective_id="101",
                status="candidate",
                observed_result="fixture result",
                route_key="fixture-route",
                proof_gap="the next route remains untested",
                next_step_or_return_trigger="run the named fixture continuation",
            )

    def test_successor_requires_source_after_current_handoff_but_initial_parallel_work_is_allowed(self) -> None:
        first = register_agent_attempt(
            self.store, self._challenge_registration("initial-a", "initial-a"), max_workers=0
        )
        self.assertTrue(first["admitted"])
        parallel = register_agent_attempt(
            self.store, self._challenge_registration("initial-b", "initial-b"), max_workers=0
        )
        self.assertTrue(parallel["admitted"])
        self._write_canonical_report(
            "analysis/initial-a/REPORT.md", status="technical_negative", route_key="first-route"
        )
        handoff = harvest_report(
            self.store,
            self.root,
            "analysis/initial-a/REPORT.md",
            agent_id="initial-a",
            agent_attempt_id="initial-a",
            challenge_id="101",
            objective_id="101",
            status="technical_negative",
            observed_result="technical_negative from first-route",
            route_key="first-route",
            proof_gap="the next route remains untested",
            next_step_or_return_trigger="run the named fixture continuation",
        )
        with self.assertRaisesRegex(ValueError, "requires source_handoff_id"):
            register_agent_attempt(
                self.store, self._challenge_registration("late-none", "late-none"), max_workers=0
            )
        successor = register_agent_attempt(
            self.store,
            self._challenge_registration(
                "linked-next", "linked-next", str(handoff["handoff_id"])
            ),
            max_workers=0,
        )
        self.assertEqual(
            successor["output"]["assignment_packet"]["source_handoff_id"],
            handoff["handoff_id"],
        )

    def test_late_stopped_report_records_reconciliation_debt_without_handoff(self) -> None:
        admitted = register_agent_attempt(
            self.store, self._challenge_registration("stopped-worker", "stopped-attempt"), max_workers=0
        )
        self.assertTrue(admitted["admitted"])
        report_path = "analysis/stopped-worker/REPORT.md"
        self._write_canonical_report(report_path, status="technical_negative", route_key="stopped-route")
        stop(self.store, self.root, reason="fixture stop", wait_seconds=0)
        debt = harvest_report(
            self.store,
            self.root,
            report_path,
            agent_id="stopped-worker",
            agent_attempt_id="stopped-attempt",
            challenge_id="101",
            objective_id="101",
            status="technical_negative",
            observed_result="technical_negative from stopped-route",
            route_key="stopped-route",
            proof_gap="the next route remains untested",
            next_step_or_return_trigger="run the named fixture continuation",
        )
        self.assertTrue(debt["reconciliation_debt"])
        self.assertFalse(debt["structured"])
        self.assertEqual(debt["handoff_id"], "")
        audit = continuation_audit(
            self.store.events(), current_generation=self.store.current_stop_generation()
        )
        self.assertEqual(audit["reconciliation_debt_attempt_ids"], ["stopped-attempt"])
        self.assertEqual(audit["reconciliation_debt_report_paths"], [report_path])

    def test_event_wide_attempt_requires_canonical_harvest_for_outcome_and_close(self) -> None:
        registration = self._registration("event-worker", "event-attempt")
        admitted = register_agent_attempt(self.store, registration, max_workers=0)
        self.assertTrue(admitted["admitted"])
        report_path = str(registration["report_path"])
        report = self.root / report_path
        report.parent.mkdir(parents=True, exist_ok=True)
        report.write_text("opaque report\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "requires exactly one ## Handoff"):
            harvest_report(
                self.store,
                self.root,
                report_path,
                agent_id="event-worker",
                agent_attempt_id="event-attempt",
                objective_id="101",
                status="technical_negative",
                observed_result="technical_negative from event-route",
                route_key="event-route",
                proof_gap="the next route remains untested",
                next_step_or_return_trigger="run the named fixture continuation",
            )
        self._write_canonical_report(
            report_path, status="technical_negative", route_key="event-route"
        )
        harvest_report(
            self.store,
            self.root,
            report_path,
            agent_id="event-worker",
            agent_attempt_id="event-attempt",
            objective_id="101",
            status="technical_negative",
            observed_result="technical_negative from event-route",
            route_key="event-route",
            proof_gap="the next route remains untested",
            next_step_or_return_trigger="run the named fixture continuation",
        )
        outcome = record_outcome(
            self.store,
            agent_id="event-worker",
            agent_attempt_id="event-attempt",
            objective_id="101",
            outcome_type="technical_negative",
            report_path=report_path,
            summary="event-wide fixture negative",
            mechanism="event-route",
        )
        self.assertEqual(outcome["event_wide"], True)
        closed = close_current_agent_attempt(
            self.store, agent_id="event-worker", reason="event-wide report integrated"
        )
        self.assertEqual(closed["agent_attempt_id"], "event-attempt")

    def test_event_wide_outcome_rejects_mismatched_or_mutated_harvest(self) -> None:
        registration = self._registration("event-mutate", "event-mutate-attempt")
        register_agent_attempt(self.store, registration, max_workers=0)
        report_path = str(registration["report_path"])
        self._write_canonical_report(
            report_path, status="technical_negative", route_key="original-route"
        )
        harvest_report(
            self.store,
            self.root,
            report_path,
            agent_id="event-mutate",
            agent_attempt_id="event-mutate-attempt",
            objective_id="101",
            status="technical_negative",
            observed_result="technical_negative from original-route",
            route_key="original-route",
            proof_gap="the next route remains untested",
            next_step_or_return_trigger="run the named fixture continuation",
        )
        with self.assertRaisesRegex(ValueError, "exact current harvested report"):
            record_outcome(
                self.store,
                agent_id="event-mutate",
                agent_attempt_id="event-mutate-attempt",
                objective_id="101",
                outcome_type="technical_negative",
                report_path=report_path,
                summary="route mismatch",
                mechanism="different-route",
            )
        report = self.root / report_path
        report.write_text(report.read_text(encoding="utf-8") + "\nnew evidence\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "exact current harvested report"):
            record_outcome(
                self.store,
                agent_id="event-mutate",
                agent_attempt_id="event-mutate-attempt",
                objective_id="101",
                outcome_type="technical_negative",
                report_path=report_path,
                summary="report drift",
                mechanism="original-route",
            )

    def test_outcome_requires_one_active_exact_registration(self) -> None:
        common = {
            "agent_id": "agent-a",
            "objective_id": "101",
            "outcome_type": "technical_negative",
            "report_path": "analysis/agent-a/REPORT.md",
            "summary": "fixture",
        }
        with self.assertRaisesRegex(ValueError, "agent_attempt_id"):
            record_outcome(self.store, **common)
        with self.assertRaisesRegex(ValueError, "active registered"):
            record_outcome(self.store, agent_attempt_id="attempt-a", **common)

        self._register("attempt-a")
        with self.assertRaisesRegex(ValueError, "active registered"):
            record_outcome(self.store, agent_attempt_id="unknown-attempt", **common)
        with self.assertRaisesRegex(ValueError, "does not match"):
            record_outcome(
                self.store,
                agent_attempt_id="attempt-a",
                **{**common, "objective_id": "different-objective"},
            )
        with self.assertRaisesRegex(ValueError, "does not match"):
            record_outcome(
                self.store,
                agent_attempt_id="attempt-a",
                **{**common, "agent_id": "different-agent"},
            )

        recorded = record_outcome(
            self.store, agent_attempt_id="attempt-a", **common
        )
        self.assertEqual(recorded["agent_attempt_id"], "attempt-a")
        with self.assertRaisesRegex(ValueError, "already recorded"):
            record_outcome(
                self.store,
                agent_attempt_id="attempt-a",
                **common,
            )

    def test_reused_display_agent_cannot_close_with_an_older_attempt_outcome(self) -> None:
        def command(*args: str):
            result = run_cli(self.root, *args)
            self.assertEqual(result.returncode, 0, result.stderr)
            return result

        command(
            "agent",
            "register",
            "reused-agent",
            "--objective-id",
            "101",
            "--role",
            "worker",
            "--report-path",
            "analysis/reused/old.md",
            "--goal",
            "fixture reuse goal",
            "--scope",
            "challenge 101 fixture",
            "--stop-condition",
            "canonical handoff written",
            "--attempt-id",
            "attempt-old",
            "--challenge-id",
            "101",
        )
        old_handoff, old_boundary = self._handoff_and_boundary(
            agent_id="reused-agent",
            attempt_id="attempt-old",
            report_path="analysis/reused/old.md",
            status="supported_finding",
            route_key="old-route",
        )
        command(
            "outcome",
            "record",
            "--agent-id",
            "reused-agent",
            "--agent-attempt-id",
            "attempt-old",
            "--objective-id",
            "101",
            "--type",
            "supported_finding",
            "--report-path",
            "analysis/reused/old.md",
            "--summary",
            "old attempt",
            "--mechanism",
            "old-route",
            "--challenge-id",
            "101",
            "--handoff-id",
            old_handoff,
            "--continuation",
            f"boundary:{old_boundary}",
        )
        command("agent", "close", "reused-agent", "--reason", "old complete")
        command(
            "agent",
            "register",
            "reused-agent",
            "--objective-id",
            "101",
            "--role",
            "worker",
            "--report-path",
            "analysis/reused/new.md",
            "--goal",
            "fixture reuse goal",
            "--scope",
            "challenge 101 fixture",
            "--stop-condition",
            "canonical handoff written",
            "--attempt-id",
            "attempt-new",
            "--challenge-id",
            "101",
            "--handoff-id",
            old_handoff,
        )

        blocked = run_cli(
            self.root,
            "agent",
            "close",
            "reused-agent",
            "--reason",
            "new complete",
        )
        self.assertNotEqual(blocked.returncode, 0)
        self.assertIn("exact agent attempt", blocked.stderr)

        new_handoff, new_boundary = self._handoff_and_boundary(
            agent_id="reused-agent",
            attempt_id="attempt-new",
            report_path="analysis/reused/new.md",
            status="supported_finding",
            route_key="new-route",
            source_handoff_id=old_handoff,
        )
        command(
            "outcome",
            "record",
            "--agent-id",
            "reused-agent",
            "--agent-attempt-id",
            "attempt-new",
            "--objective-id",
            "101",
            "--type",
            "supported_finding",
            "--report-path",
            "analysis/reused/new.md",
            "--summary",
            "new attempt",
            "--mechanism",
            "new-route",
            "--challenge-id",
            "101",
            "--handoff-id",
            new_handoff,
            "--continuation",
            f"boundary:{new_boundary}",
        )
        command("agent", "close", "reused-agent", "--reason", "new complete")
        command("agent", "close", "reused-agent", "--reason", "repeat")
        closed_events = self.store.events("agent.closed")
        self.assertEqual(len(closed_events), 2)
        self.assertEqual(closed_events[-1]["payload"]["agent_attempt_id"], "attempt-new")

    def test_registration_rejects_duplicate_attempt_and_active_display_id(self) -> None:
        first = register_agent_attempt(
            self.store,
            self._registration("agent-duplicate", "attempt-duplicate"),
            max_workers=0,
        )
        self.assertTrue(first["admitted"])
        with self.assertRaisesRegex(ValueError, "attempt ID is already registered"):
            register_agent_attempt(
                self.store,
                self._registration("another-agent", "attempt-duplicate"),
                max_workers=0,
            )
        with self.assertRaisesRegex(ValueError, "display ID already has an active"):
            register_agent_attempt(
                self.store,
                self._registration("agent-duplicate", "attempt-new"),
                max_workers=0,
            )
        self.assertEqual(len(self.store.events("agent.running")), 1)

    def test_cli_registration_rejects_a_duplicate_attempt_id(self) -> None:
        first = run_cli(
            self.root,
            "agent",
            "register",
            "cli-agent-one",
            "--objective-id",
            "101",
            "--role",
            "worker",
            "--report-path",
            "analysis/cli-one/REPORT.md",
            "--goal",
            "duplicate fixture goal",
            "--scope",
            "event-wide fixture",
            "--stop-condition",
            "fixture report written",
            "--attempt-id",
            "cli-duplicate-attempt",
            "--event-wide",
        )
        duplicate = run_cli(
            self.root,
            "agent",
            "register",
            "cli-agent-two",
            "--objective-id",
            "101",
            "--role",
            "worker",
            "--report-path",
            "analysis/cli-two/REPORT.md",
            "--goal",
            "duplicate fixture goal",
            "--scope",
            "event-wide fixture",
            "--stop-condition",
            "fixture report written",
            "--attempt-id",
            "cli-duplicate-attempt",
            "--event-wide",
        )
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertNotEqual(duplicate.returncode, 0)
        self.assertIn("attempt ID is already registered", duplicate.stderr)
        self.assertEqual(len(self.store.events("agent.running")), 1)

    def test_capacity_rejected_attempt_id_cannot_be_admitted_later(self) -> None:
        admitted = register_agent_attempt(
            self.store,
            self._registration("agent-active", "attempt-active"),
            max_workers=1,
        )
        rejected = register_agent_attempt(
            self.store,
            self._registration("agent-rejected", "attempt-rejected"),
            max_workers=1,
        )
        self.assertTrue(admitted["admitted"])
        self.assertFalse(rejected["admitted"])
        with self.assertRaisesRegex(ValueError, "attempt ID is already registered"):
            register_agent_attempt(
                self.store,
                self._registration("agent-later", "attempt-rejected"),
                max_workers=0,
            )
        self.assertEqual(len(self.store.events("agent.running")), 1)
        self.assertEqual(len(self.store.events("agent.capacity_rejected")), 1)

    def test_capacity_rejection_does_not_mask_the_registered_attempt_for_close(self) -> None:
        self._register("attempt-active", challenge_linked=True)
        handoff_id, boundary_id = self._handoff_and_boundary(
            agent_id="agent-a",
            attempt_id="attempt-active",
            report_path="analysis/agent-a/REPORT.md",
            status="technical_negative",
            route_key="capacity-mask-route",
        )
        record_outcome(
            self.store,
            agent_id="agent-a",
            agent_attempt_id="attempt-active",
            objective_id="101",
            outcome_type="technical_negative",
            report_path="analysis/agent-a/REPORT.md",
            summary="active attempt",
            mechanism="capacity-mask-route",
            challenge_id="101",
            handoff_id=handoff_id,
            continuation=f"boundary:{boundary_id}",
        )
        self.store.append(
            "agent.capacity_rejected",
            {
                "agent_id": "agent-a",
                "agent_attempt_id": "attempt-rejected",
                "objective_id": "101",
                "challenge_id": "101",
                "event_wide": False,
                "status": "capacity_rejected",
            },
            actor="fixture",
        )

        closed = close_current_agent_attempt(
            self.store,
            agent_id="agent-a",
            reason="registered attempt complete",
        )
        self.assertEqual(closed["agent_attempt_id"], "attempt-active")
        self.assertEqual(len(self.store.events("agent.closed")), 1)

    def test_concurrent_capacity_admission_records_one_registration_and_rejection(self) -> None:
        start = threading.Barrier(3)
        results: list[dict[str, object]] = []
        errors: list[BaseException] = []

        def admit(agent_id: str, attempt_id: str) -> None:
            try:
                start.wait(timeout=5)
                results.append(
                    register_agent_attempt(
                        EventStore(self.root),
                        self._registration(agent_id, attempt_id),
                        max_workers=1,
                    )
                )
            except BaseException as exc:
                errors.append(exc)

        workers = [
            threading.Thread(target=admit, args=("agent-one", "attempt-one")),
            threading.Thread(target=admit, args=("agent-two", "attempt-two")),
        ]
        for worker in workers:
            worker.start()
        start.wait(timeout=5)
        for worker in workers:
            worker.join(timeout=10)
            self.assertFalse(worker.is_alive())

        self.assertEqual(errors, [])
        self.assertEqual(sum(bool(result["admitted"]) for result in results), 1)
        self.assertEqual(len(self.store.events("agent.running")), 1)
        rejections = self.store.events("agent.capacity_rejected")
        self.assertEqual(len(rejections), 1)
        self.assertEqual(rejections[0]["payload"]["active_workers"], 1)
        self.assertEqual(rejections[0]["payload"]["max_workers"], 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
