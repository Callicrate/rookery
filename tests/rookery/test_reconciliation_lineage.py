from __future__ import annotations

# ruff: noqa: E402

import json
import os
import sys
import unittest
from pathlib import Path
from unittest import mock


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
LIB = REPOSITORY_ROOT / "rookery" / "lib"
if str(LIB) not in sys.path:
    sys.path.insert(0, str(LIB))
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

from rookery.portable.adapters import CommandAdapter
from rookery.portable.control import resume
from rookery.portable.execution import compile_plan, execute_plan
from rookery.portable.reconciliation import import_response, reconcile_all
from rookery.portable.scoring import (
    claim_plan_authority,
    create_proposal,
    grant_exact,
    record_review,
)
from rookery.portable.store import EventStore
from rookery.portable.telemetry import summarize_measurement
from rookery.portable.util import atomic_write_json
from rookery.verdict_parser import parse_verdict
from tests.rookery.test_acceptance_campaign import context, make_workspace
from tests.rookery.support import install_solver_ready_challenge

MISMATCH_OBJECTIVE_SENTINEL = "objective-mismatch-sentinel-not-a-digest"


class ReconciliationProposalLineageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = make_workspace("fixture")
        self.root = Path(self.temporary_directory.name)
        self.manifest, self.scope, self.store, _ = context(self.root, "fixture")
        install_solver_ready_challenge(self.root, self.store)

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def proposal(self, *, attempt_scope: dict[str, str] | None = None) -> dict:
        proposal = create_proposal(
            self.store,
            self.manifest,
            objective_id="101",
            action_kind="flag",
            exact_value="FIXTURE{right}",
            attempt_scope=attempt_scope,
            source="analysis/reconciliation/REPORT.md",
            rationale="proposal lineage regression fixture",
            actor="solver-a",
        )
        record_review(
            self.store,
            proposal["proposal_id"],
            "approved",
            reviewer="reviewer-b",
            reason="proposal lineage fixture review",
        )
        return proposal

    def claim(self, proposal: dict) -> dict:
        if proposal["action_kind"] != "no_submit_evidence":
            grant_exact(
                self.store,
                proposal["proposal_id"],
                reason="reconciliation lineage fixture",
            )
        plan = compile_plan(
            self.store,
            self.root,
            self.manifest,
            self.scope,
            proposal["proposal_id"],
        )
        claim_plan_authority(self.store, plan, loaded_plan=plan, actor="fixture")
        return plan

    def response_path(
        self,
        name: str,
        response: dict,
        *,
        request: dict | None = None,
    ) -> Path:
        response_directory = self.root / "submissions" / "external" / name
        response_directory.mkdir(parents=True)
        if request is not None:
            (response_directory / "request.json").write_text(
                json.dumps(request), encoding="utf-8"
            )
        path = response_directory / "response.json"
        path.write_text(json.dumps(response), encoding="utf-8")
        return path

    def assert_no_execution_or_challenge_effects(self) -> None:
        self.assertEqual(self.store.events("execution.completed"), [])
        self.assertEqual(self.store.events("execution.rejected"), [])
        self.assertEqual(self.store.events("execution.indeterminate"), [])
        self.assertEqual(self.store.events("challenge.upsert"), [])

    def assert_value_free_observation(self, forbidden: tuple[str, ...]) -> None:
        payload = self.store.events("platform.observed")[-1]["payload"]
        encoded = json.dumps(payload, sort_keys=True)
        for value in forbidden:
            self.assertNotIn(value, encoded)
        self.assertNotIn("path", payload["evidence_provenance"]["response"])
        self.assertRegex(
            payload["evidence_provenance"]["response"]["sha256"],
            r"^[0-9a-f]{64}$",
        )

    def test_response_mismatch_quarantines_every_terminal_truth_once(
        self,
    ) -> None:
        proposal = self.proposal()
        baseline_events = len(self.store.events())
        baseline_queue = self.store.rebuild()["queue"]
        cases = {
            "accepted": {"correct": True},
            "rejected": {"correct": False},
            "unknown": {"http_status": 200, "opaque": "response"},
        }
        for name, verdict in cases.items():
            with self.subTest(verdict=name):
                response = {
                    **verdict,
                    "proposal_id": proposal["proposal_id"],
                    "objective_id": MISMATCH_OBJECTIVE_SENTINEL,
                    "candidate": "FIXTURE{other}",
                }
                path = self.response_path(name, response)
                first = import_response(self.store, self.root, path)
                second = import_response(self.store, self.root, path)
                self.assertEqual(first["import_status"], "observed")
                self.assertEqual(second["import_status"], "already-observed")
                self.assertEqual(
                    len(self.store.events()), baseline_events + len(self.store.events("platform.observed"))
                )
                self.assert_no_execution_or_challenge_effects()
                self.assertEqual(self.store.rebuild()["queue"], baseline_queue)
                self.assert_value_free_observation(
                    (
                        proposal["proposal_id"],
                        MISMATCH_OBJECTIVE_SENTINEL,
                        "FIXTURE{other}",
                    )
                )
                self.assertNotIn(
                    MISMATCH_OBJECTIVE_SENTINEL,
                    self.store.rebuild()["current"]["challenges"],
                )

    def test_sibling_request_mismatch_quarantines_before_accepted_mutation(self) -> None:
        proposal = self.proposal()
        baseline_events = len(self.store.events())
        baseline_queue = self.store.rebuild()["queue"]
        path = self.response_path(
            "request-mismatch",
            {"http_status": 200, "data": {"correct": True}},
            request={
                "proposalId": proposal["proposal_id"],
                "challengeId": MISMATCH_OBJECTIVE_SENTINEL,
                "answerValue": "FIXTURE{other}",
            },
        )
        first = import_response(self.store, self.root, path)
        second = import_response(self.store, self.root, path)
        self.assertEqual(first["import_status"], "observed")
        self.assertEqual(second["import_status"], "already-observed")
        self.assertEqual(len(self.store.events()), baseline_events + 1)
        self.assert_no_execution_or_challenge_effects()
        self.assertEqual(self.store.rebuild()["queue"], baseline_queue)
        self.assert_value_free_observation(
            (
                proposal["proposal_id"],
                MISMATCH_OBJECTIVE_SENTINEL,
                "FIXTURE{other}",
            )
        )
        self.assertNotIn(
            MISMATCH_OBJECTIVE_SENTINEL,
            self.store.rebuild()["current"]["challenges"],
        )

    def test_adapter_and_canonical_attempt_scope_cannot_be_overridden(self) -> None:
        proposal = self.proposal(attempt_scope={"attempt_id": "attempt-right"})
        baseline_events = len(self.store.events())
        baseline_queue = self.store.rebuild()["queue"]
        cases = {
            "adapter": {"adapterId": "other-adapter"},
            "attempt": {"attemptId": "attempt-wrong"},
        }
        for name, mismatch in cases.items():
            with self.subTest(field=name):
                path = self.response_path(
                    name,
                    {
                        "correct": True,
                        "proposal_id": proposal["proposal_id"],
                        **mismatch,
                    },
                )
                first = import_response(self.store, self.root, path)
                second = import_response(self.store, self.root, path)
                self.assertEqual(first["import_status"], "observed")
                self.assertEqual(second["import_status"], "already-observed")
                self.assertEqual(
                    len(self.store.events()), baseline_events + len(self.store.events("platform.observed"))
                )
                self.assert_no_execution_or_challenge_effects()
                self.assertEqual(self.store.rebuild()["queue"], baseline_queue)
                self.assert_value_free_observation(
                    (
                        proposal["proposal_id"],
                        "other-adapter",
                        "attempt-wrong",
                        "attempt-right",
                    )
                )

    def test_request_proposal_alias_binds_and_missing_identity_inherits(self) -> None:
        proposal = self.proposal()
        plan = self.claim(proposal)
        path = self.response_path(
            "fill-from-proposal",
            {"http_status": 200, "data": {"correct": True}},
            request={"proposalId": proposal["proposal_id"]},
        )

        first = import_response(self.store, self.root, path)
        event_count = len(self.store.events())
        second = import_response(self.store, self.root, path)

        self.assertEqual(first["import_status"], "reconciled")
        self.assertEqual(second["status"], "already-recorded")
        self.assertEqual(second["import_status"], "already-recorded")
        self.assertEqual(first["proposal_id"], proposal["proposal_id"])
        self.assertEqual(first["plan_id"], plan["plan_id"])
        self.assertEqual(first["objective_id"], "101")
        self.assertEqual(first["exact_value"], "FIXTURE{right}")
        self.assertEqual(first["adapter_id"], "fixture")
        self.assertEqual(first["attempt_scope"], {})
        self.assertEqual(len(self.store.events()), event_count)
        challenge = self.store.rebuild()["current"]["challenges"]["101"]
        self.assertTrue(challenge["solved"])
        self.assertEqual(len(self.store.events("execution.completed")), 1)
        self.assertEqual(len(self.store.events("challenge.upsert")), 1)

    def test_artifact_digest_is_derived_or_quarantined_as_lowercase_sha256(
        self,
    ) -> None:
        self.manifest["scoring"]["action_kinds"].append("proof_artifact")
        proposal = create_proposal(
            self.store,
            self.manifest,
            objective_id="101",
            action_kind="proof_artifact",
            artifact_reference="evidence/proof.bin",
            source="analysis/reconciliation/REPORT.md",
            rationale="artifact lineage regression fixture",
            actor="solver-a",
        )
        record_review(
            self.store,
            proposal["proposal_id"],
            "approved",
            reviewer="reviewer-b",
            reason="artifact lineage fixture review",
        )
        self.claim(proposal)
        valid_path = self.response_path(
            "artifact-fill",
            {"correct": True},
            request={"proposal_id": proposal["proposal_id"]},
        )
        imported = import_response(self.store, self.root, valid_path)
        self.assertEqual(imported["import_status"], "reconciled")
        self.assertEqual(imported["artifact_reference"], "evidence/proof.bin")

        invalid_path = self.response_path(
            "artifact-invalid",
            {
                "correct": True,
                "proposal_id": proposal["proposal_id"],
                "artifact_digest": "A" * 64,
            },
        )
        observed = import_response(self.store, self.root, invalid_path)
        repeated = import_response(self.store, self.root, invalid_path)
        self.assertEqual(observed["import_status"], "observed")
        self.assertEqual(repeated["import_status"], "already-observed")
        quarantine = self.store.events("platform.observed")[-1]["payload"]
        self.assertEqual(quarantine["artifact_digest"], "")
        self.assertNotIn(proposal["proposal_id"], json.dumps(quarantine))
        self.assertEqual(len(self.store.events("execution.completed")), 1)
        self.assertEqual(len(self.store.events("challenge.upsert")), 1)


class _SparseCtfdAdapter:
    def preflight_action(self, envelope: dict) -> dict:
        return {"ok": True, "reason": "fixture preflight"}

    def execute_action(self, envelope: dict, evidence_root: Path) -> dict:
        request = {
            "url": "https://fixture.invalid/api/v1/challenges/attempt",
            "body": {
                "challenge_id": int(envelope["objective_id"]),
                "submission": envelope["exact_value"],
            },
            "objective_id": envelope["objective_id"],
            "candidate": envelope["exact_value"],
        }
        response = {
            "http_status": 200,
            "data": {"success": True, "data": {"status": "correct"}},
        }
        evidence_root.mkdir(parents=True, exist_ok=True)
        atomic_write_json(evidence_root / "request.json", request)
        atomic_write_json(evidence_root / "response.json", response)
        return {
            "response": response,
            "response_path": str(evidence_root / "response.json"),
            "verdict": parse_verdict(response).to_dict(),
        }


class _UnknownFixtureAdapter:
    def preflight_action(self, envelope: dict) -> dict:
        return {"ok": True, "reason": "fixture preflight"}

    def execute_action(self, envelope: dict, evidence_root: Path) -> dict:
        response = {"http_status": 200, "success": True, "data": {"opaque": True}}
        evidence_root.mkdir(parents=True, exist_ok=True)
        atomic_write_json(evidence_root / "request.json", envelope)
        atomic_write_json(evidence_root / "response.json", response)
        return {
            "response": response,
            "response_path": str(evidence_root / "response.json"),
            "verdict": parse_verdict(response).to_dict(),
        }


class _TerminalFixtureAdapter:
    def __init__(self, correct: bool):
        self.correct = correct

    def preflight_action(self, envelope: dict) -> dict:
        return {"ok": True, "reason": "fixture preflight"}

    def execute_action(self, envelope: dict, evidence_root: Path) -> dict:
        response = {"http_status": 200, "data": {"correct": self.correct}}
        evidence_root.mkdir(parents=True, exist_ok=True)
        atomic_write_json(evidence_root / "request.json", envelope)
        atomic_write_json(evidence_root / "response.json", response)
        return {
            "response": response,
            "response_path": str(evidence_root / "response.json"),
            "verdict": parse_verdict(response).to_dict(),
        }


class ReconciliationTerminalEvidenceDeduplicationTests(unittest.TestCase):
    def _case(self, adapter_id: str) -> tuple:
        temporary_directory = make_workspace("fixture")
        root = Path(temporary_directory.name)
        manifest, scope, store, _result = context(root, "fixture")
        install_solver_ready_challenge(root, store)
        resume(store, reason="terminal evidence dedupe fixture")
        if adapter_id == "command":
            manifest["adapter"] = {
                "id": "command",
                "config": {
                    "inventory_argv": ["/bin/echo", '{"challenges":[]}'],
                    "submit_argv": ["/bin/true"],
                    "inventory_env_keys": [],
                    "submit_env_keys": [],
                },
            }
        elif adapter_id == "ctfd":
            manifest["adapter"] = {"id": "ctfd", "config": {}}
        proposal = create_proposal(
            store,
            manifest,
            objective_id="101",
            action_kind="flag",
            exact_value="FIXTURE{accepted}",
            source="analysis/reconciliation/REPORT.md",
            rationale=f"{adapter_id} terminal evidence dedupe fixture",
            actor="solver-a",
        )
        record_review(
            store,
            proposal["proposal_id"],
            "approved",
            reviewer="reviewer-b",
            reason="independent fixture review",
        )
        grant_exact(store, proposal["proposal_id"], reason="exact fixture authority")
        plan = compile_plan(store, root, manifest, scope, proposal["proposal_id"])
        return temporary_directory, root, manifest, scope, store, plan

    def _assert_reconcile_is_read_only_for_terminal_evidence(
        self, store: EventStore, root: Path
    ) -> None:
        before_events = store.events()
        before_projection = store.rebuild()
        reconciliation = reconcile_all(store, root)
        self.assertEqual(reconciliation["count"], 1)
        self.assertEqual(reconciliation["rows"][0]["status"], "already-recorded")
        self.assertEqual(
            reconciliation["rows"][0]["import_status"], "already-recorded"
        )
        self.assertEqual(store.events(), before_events)
        self.assertEqual(store.rebuild(), before_projection)

    def test_fixture_execute_then_reconcile_does_not_duplicate_terminal(self) -> None:
        temporary_directory, root, manifest, scope, store, plan = self._case("fixture")
        try:
            result, return_code = execute_plan(
                store, root, manifest, scope, plan["plan_id"]
            )
            self.assertEqual(return_code, 0)
            self.assertEqual(result["status"], "completed")
            self._assert_reconcile_is_read_only_for_terminal_evidence(store, root)
            self.assertEqual(len(store.events("execution.completed")), 1)
            self.assertEqual(store.events("challenge.upsert"), [])
        finally:
            temporary_directory.cleanup()

    def test_sparse_command_and_ctfd_execute_then_reconcile_are_deduplicated(
        self,
    ) -> None:
        for adapter_id in ("command", "ctfd"):
            with self.subTest(adapter=adapter_id):
                temporary_directory, root, manifest, scope, store, plan = self._case(
                    adapter_id
                )
                try:
                    adapter = (
                        _SparseCtfdAdapter()
                        if adapter_id == "ctfd"
                        else CommandAdapter(root, manifest, scope)
                    )
                    with mock.patch(
                        "rookery.portable.execution.get_adapter",
                        return_value=adapter,
                    ):
                        result, _return_code = execute_plan(
                            store, root, manifest, scope, plan["plan_id"]
                        )
                    self.assertIn(
                        result["status"], {"completed", "rejected", "indeterminate"}
                    )
                    self._assert_reconcile_is_read_only_for_terminal_evidence(
                        store, root
                    )
                    self.assertEqual(store.events("challenge.upsert"), [])
                finally:
                    temporary_directory.cleanup()

    def test_unchanged_legacy_indeterminate_evidence_is_already_recorded(self) -> None:
        temporary_directory, root, manifest, scope, store, plan = self._case("fixture")
        try:
            with mock.patch(
                "rookery.portable.execution.get_adapter",
                return_value=_UnknownFixtureAdapter(),
            ):
                result, return_code = execute_plan(
                    store, root, manifest, scope, plan["plan_id"]
                )
            self.assertEqual(return_code, 2)
            self.assertEqual(result["status"], "indeterminate")
            self._assert_reconcile_is_read_only_for_terminal_evidence(store, root)
            self.assertEqual(len(store.events("execution.indeterminate")), 1)
        finally:
            temporary_directory.cleanup()

    def test_changed_legacy_indeterminate_evidence_can_reconcile_accepted(self) -> None:
        temporary_directory, root, manifest, scope, store, plan = self._case("fixture")
        try:
            with mock.patch(
                "rookery.portable.execution.get_adapter",
                return_value=_UnknownFixtureAdapter(),
            ):
                result, return_code = execute_plan(
                    store, root, manifest, scope, plan["plan_id"]
                )
            self.assertEqual(return_code, 2)
            self.assertEqual(result["status"], "indeterminate")
            atomic_write_json(
                Path(result["response_path"]),
                {"http_status": 200, "data": {"correct": True}},
            )
            before_count = len(store.events())
            reconciliation = reconcile_all(store, root)
            self.assertEqual(reconciliation["rows"][0]["status"], "completed")
            self.assertEqual(
                reconciliation["rows"][0]["import_status"], "reconciled"
            )
            self.assertEqual(reconciliation["rows"][0]["plan_id"], plan["plan_id"])
            self.assertEqual(len(store.events()), before_count + 2)
            self.assertEqual(len(store.events("execution.indeterminate")), 1)
            self.assertEqual(len(store.events("execution.completed")), 1)
            self.assertEqual(len(store.events("challenge.upsert")), 1)
            current = store.rebuild()["current"]["executions"]
            self.assertEqual(set(current), {plan["plan_id"]})
            self.assertEqual(current[plan["plan_id"]]["status"], "completed")
            measurement = summarize_measurement(store.events())
            latency = measurement["proposal_to_terminal_latency"]
            self.assertEqual(latency["unique_final_plan_denominator"], 1)
            self.assertEqual(latency["terminal_denominator"], 1)
        finally:
            temporary_directory.cleanup()

    def test_changed_completed_and_rejected_evidence_is_quarantined_once(self) -> None:
        for initial_correct in (True, False):
            with self.subTest(initial_correct=initial_correct):
                temporary_directory, root, manifest, scope, store, plan = self._case(
                    "fixture"
                )
                try:
                    with mock.patch(
                        "rookery.portable.execution.get_adapter",
                        return_value=_TerminalFixtureAdapter(initial_correct),
                    ):
                        result, _return_code = execute_plan(
                            store, root, manifest, scope, plan["plan_id"]
                        )
                    initial_status = "completed" if initial_correct else "rejected"
                    self.assertEqual(result["status"], initial_status)
                    atomic_write_json(
                        Path(result["response_path"]),
                        {"http_status": 200, "data": {"correct": not initial_correct}},
                    )
                    before_count = len(store.events())
                    before_terminal = {
                        event_type: list(store.events(event_type))
                        for event_type in (
                            "execution.completed",
                            "execution.rejected",
                            "execution.indeterminate",
                            "challenge.upsert",
                        )
                    }
                    first = reconcile_all(store, root)["rows"][0]
                    second = reconcile_all(store, root)["rows"][0]
                    self.assertEqual(first["import_status"], "observed")
                    self.assertEqual(second["import_status"], "already-observed")
                    self.assertEqual(len(store.events()), before_count + 1)
                    for event_type, events in before_terminal.items():
                        self.assertEqual(store.events(event_type), events)
                    current = store.rebuild()["current"]["executions"]
                    self.assertEqual(set(current), {plan["plan_id"]})
                    self.assertEqual(current[plan["plan_id"]]["status"], initial_status)
                finally:
                    temporary_directory.cleanup()


if __name__ == "__main__":
    unittest.main(verbosity=2)
