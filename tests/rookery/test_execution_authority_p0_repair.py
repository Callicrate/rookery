from __future__ import annotations

# ruff: noqa: E402

import os
import sys
import tempfile
import threading
import unittest
from copy import deepcopy
from pathlib import Path
from unittest import mock


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
LIB = REPOSITORY_ROOT / "rookery" / "lib"
if str(LIB) not in sys.path:
    sys.path.insert(0, str(LIB))
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

from rookery.portable.adapters import get_adapter
from rookery.portable.execution import compile_plan, execute_plan
from rookery.portable.queue import build_queue, persist_schedules
from rookery.portable.policy import set_policy
from rookery.portable.reconciliation import import_response
from rookery.portable.scoring import (
    available_authorization,
    claim_plan_authority,
    create_proposal,
    grant_allowance,
    grant_exact,
    record_review,
)
from rookery.portable.store import EventStore
from rookery.portable.util import atomic_write_json, canonical_json, sha256_bytes
from tests.rookery.test_acceptance_campaign import context, make_workspace
from tests.rookery.support import install_solver_ready_challenge


class ExecutionAuthorityP0RepairTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = make_workspace("fixture")
        self.root = Path(self.temporary_directory.name)
        self.manifest, self.scope, self.store, _ = context(self.root, "fixture")
        install_solver_ready_challenge(self.root, self.store)
        self.manifest["queue"]["cadence_seconds"] = 0
        self.manifest["queue"]["jitter_seconds"] = 0

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def approved(
        self,
        *,
        action_kind: str = "flag",
        value: str = "authority-p0",
        attempt_scope: dict | None = None,
    ) -> dict:
        proposal = create_proposal(
            self.store,
            self.manifest,
            objective_id="101",
            action_kind=action_kind,
            exact_value=f"FIXTURE{{{value}}}" if action_kind == "flag" else "",
            artifact_reference=(
                "evidence/authority-p0.txt"
                if action_kind == "no_submit_evidence"
                else ""
            ),
            source="analysis/authority-p0/REPORT.md",
            rationale="focused execution-authority regression",
            attempt_scope=attempt_scope,
            actor="solver-a",
        )
        record_review(
            self.store,
            proposal["proposal_id"],
            "approved",
            reviewer="reviewer-b",
            reason="independent fixture review",
        )
        return proposal

    def test_nonempty_proposal_attempt_scope_compiles_and_claims_authority(self) -> None:
        proposal = self.approved(
            value="nonempty-attempt-scope",
            attempt_scope={
                "challenge_id": "101",
                "method": "offline fixture decode",
            },
        )
        grant_exact(
            self.store,
            proposal["proposal_id"],
            reason="pinned fixture authority",
        )

        plan = compile_plan(
            self.store,
            self.root,
            self.manifest,
            self.scope,
            proposal["proposal_id"],
        )
        self.assertEqual(plan["lifecycle_refs"], proposal["attempt_scope"])

        claimed = claim_plan_authority(self.store, plan)
        self.assertEqual(claimed["proposal_id"], proposal["proposal_id"])

    def test_multi_count_allowance_compiles_after_prior_execution_start(self) -> None:
        first = self.approved(value="allowance-first")
        authorization = grant_allowance(
            self.store,
            self.manifest,
            "flag",
            2,
            reason="two-plan fixture allowance",
        )
        first_plan = compile_plan(
            self.store,
            self.root,
            self.manifest,
            self.scope,
            first["proposal_id"],
        )
        claim_plan_authority(self.store, first_plan)

        second = self.approved(value="allowance-second")
        second_plan = compile_plan(
            self.store,
            self.root,
            self.manifest,
            self.scope,
            second["proposal_id"],
        )

        self.assertEqual(
            second_plan["predicates"]["authorization_id"],
            authorization["authorization_id"],
        )
        self.assertEqual(
            self.store.rebuild()["current"]["authorizations"][
                authorization["authorization_id"]
            ]["remaining"],
            1,
        )

    def test_unknown_and_exception_after_dispatch_are_terminal_and_not_requeued(self) -> None:
        for outcome in ("unknown", "exception"):
            with self.subTest(outcome=outcome):
                proposal = self.approved(value=f"authority-p0-{outcome}")
                grant_exact(
                    self.store,
                    proposal["proposal_id"],
                    reason="pinned fixture authority",
                )
                grant_allowance(
                    self.store,
                    self.manifest,
                    "flag",
                    2,
                    reason="two-count fixture allowance",
                )
                plan = compile_plan(
                    self.store,
                    self.root,
                    self.manifest,
                    self.scope,
                    proposal["proposal_id"],
                )
                self.assertEqual(
                    plan["predicates"]["proposal_event_id"],
                    self.store.rebuild()["current"]["proposals"][
                        proposal["proposal_id"]
                    ]["event_id"],
                )
                adapter = get_adapter(self.root, self.manifest, self.scope)

                if outcome == "unknown":
                    execute_behavior = {
                        "return_value": {
                        "verdict": {"verdict": "unknown", "reason": "ambiguous scorer truth"},
                        "response_path": "submissions/fixture-response.json",
                        }
                    }
                else:
                    def execute_after_evidence(_envelope, evidence_root):
                        evidence_root.mkdir(parents=True, exist_ok=True)
                        (evidence_root / "response.json").write_text(
                            '{"verdict":"unknown"}', encoding="utf-8"
                        )
                        raise TimeoutError("adapter timed out after preserving response")

                    execute_behavior = {"side_effect": execute_after_evidence}

                with (
                    mock.patch(
                        "rookery.portable.execution.get_adapter", return_value=adapter
                    ),
                    mock.patch.object(adapter, "execute_action", **execute_behavior) as execute_action,
                ):
                    first, first_rc = execute_plan(
                        self.store,
                        self.root,
                        self.manifest,
                        self.scope,
                        plan["plan_id"],
                    )
                    second, second_rc = execute_plan(
                        self.store,
                        self.root,
                        self.manifest,
                        self.scope,
                        plan["plan_id"],
                    )

                self.assertEqual(first_rc, 2)
                self.assertEqual(first["status"], "indeterminate")
                self.assertTrue(second["idempotent"])
                self.assertEqual(second["status"], "indeterminate")
                self.assertEqual(second_rc, 2)
                execute_action.assert_called_once()
                for _ in range(2):
                    queued = {
                        item["proposal_id"]
                        for item in build_queue(self.store, self.manifest)["items"]
                    }
                    self.assertNotIn(proposal["proposal_id"], queued)
                with self.assertRaisesRegex(RuntimeError, "durable execution claim"):
                    compile_plan(
                        self.store,
                        self.root,
                        self.manifest,
                        self.scope,
                        proposal["proposal_id"],
                    )

    def test_review_revocation_and_authorization_substitution_make_zero_adapter_calls(self) -> None:
        for mismatch in ("review", "authorization"):
            with self.subTest(mismatch=mismatch):
                proposal = self.approved(value=f"authority-p0-{mismatch}")
                exact = grant_exact(
                    self.store, proposal["proposal_id"], reason="pinned exact authority"
                )
                plan = compile_plan(
                    self.store,
                    self.root,
                    self.manifest,
                    self.scope,
                    proposal["proposal_id"],
                )
                if mismatch == "review":
                    record_review(
                        self.store,
                        proposal["proposal_id"],
                        "rejected",
                        reviewer="reviewer-c",
                        reason="later independent revocation",
                    )
                else:
                    self.store.append(
                        "authorization.revoked",
                        {
                            **exact,
                            "remaining": 0,
                            "reason": "operator revoked the pinned exact authorization",
                        },
                        actor="operator",
                    )
                    grant_allowance(
                        self.store,
                        self.manifest,
                        "flag",
                        1,
                        reason="different authorization must not substitute",
                    )
                adapter = get_adapter(self.root, self.manifest, self.scope)
                with (
                    mock.patch(
                        "rookery.portable.execution.get_adapter", return_value=adapter
                    ),
                    mock.patch.object(
                        adapter,
                        "execute_action",
                        return_value={
                            "verdict": {"verdict": "accepted"},
                            "response_path": "submissions/unexpected-dispatch.json",
                        },
                    ) as execute_action,
                ):
                    result, rc = execute_plan(
                        self.store,
                        self.root,
                        self.manifest,
                        self.scope,
                        plan["plan_id"],
                    )
                self.assertEqual(rc, 2)
                self.assertEqual(result["status"], "blocked")
                execute_action.assert_not_called()
                self.assertEqual(
                    self.store.rebuild()["current"]["authorizations"][
                        exact["authorization_id"]
                    ]["remaining"],
                    1 if mismatch == "review" else 0,
                )

    def test_no_submit_evidence_requires_the_pinned_current_approval(self) -> None:
        proposal = self.approved(action_kind="no_submit_evidence")
        plan = compile_plan(
            self.store,
            self.root,
            self.manifest,
            self.scope,
            proposal["proposal_id"],
        )
        record_review(
            self.store,
            proposal["proposal_id"],
            "rejected",
            reviewer="reviewer-c",
            reason="later independent revocation",
        )
        with mock.patch(
            "rookery.portable.execution.get_adapter",
            side_effect=AssertionError("no-submit execution must not initialize an adapter"),
        ):
            result, rc = execute_plan(
                self.store,
                self.root,
                self.manifest,
                self.scope,
                plan["plan_id"],
            )
        self.assertEqual(rc, 2)
        self.assertEqual(result["status"], "blocked")
        self.assertFalse(
            any(
                event["payload"].get("plan_id") == plan["plan_id"]
                for event in self.store.events("execution.completed")
            )
        )

    def test_pinned_exact_and_allowance_are_consumed_by_identity(self) -> None:
        for mode in ("exact", "allowance"):
            with self.subTest(mode=mode):
                proposal = self.approved(value=f"authority-p0-{mode}")
                authorization = (
                    grant_exact(
                        self.store,
                        proposal["proposal_id"],
                        reason="pinned exact authority",
                    )
                    if mode == "exact"
                    else grant_allowance(
                        self.store,
                        self.manifest,
                        "flag",
                        2,
                        reason="pinned allowance authority",
                    )
                )
                plan = compile_plan(
                    self.store,
                    self.root,
                    self.manifest,
                    self.scope,
                    proposal["proposal_id"],
                )
                adapter = get_adapter(self.root, self.manifest, self.scope)
                with (
                    mock.patch(
                        "rookery.portable.execution.get_adapter", return_value=adapter
                    ),
                    mock.patch.object(
                        adapter,
                        "execute_action",
                        return_value={
                            "verdict": {
                                "verdict": "accepted",
                                "scorer_truth": "accepted",
                            },
                            "response_path": "submissions/authority-fixture.json",
                        },
                    ),
                ):
                    result, rc = execute_plan(
                        self.store,
                        self.root,
                        self.manifest,
                        self.scope,
                        plan["plan_id"],
                    )
                self.assertIn(rc, {0, 1}, result)
                consumed = next(
                    event["payload"]
                    for event in self.store.events("authorization.consumed")
                    if event["payload"].get("consumed_for_plan") == plan["plan_id"]
                )
                self.assertEqual(
                    consumed["authorization_id"],
                    plan["predicates"]["authorization_id"],
                )
                self.assertEqual(
                    consumed["authorization_id"], authorization["authorization_id"]
                )

    def test_stale_policy_authorization_is_not_selected_or_consumed(self) -> None:
        proposal = self.approved(value="authority-p0-policy")
        authorization = grant_allowance(
            self.store,
            self.manifest,
            "flag",
            1,
            reason="generation-zero allowance",
        )
        set_policy(
            self.store,
            "strategy",
            "points",
            source="operator",
            reason="advance policy generation",
        )
        self.assertIsNone(available_authorization(self.store, proposal))
        with self.assertRaisesRegex(RuntimeError, "authorization"):
            compile_plan(
                self.store,
                self.root,
                self.manifest,
                self.scope,
                proposal["proposal_id"],
            )
        self.assertEqual(
            self.store.rebuild()["current"]["authorizations"][
                authorization["authorization_id"]
            ]["remaining"],
            1,
        )

    def test_legacy_post_start_blocked_and_failed_events_are_quarantined(self) -> None:
        proposal = self.approved(value="authority-p0-legacy")
        legacy_started = "plan_legacy_started_blocked"
        legacy_failed = "plan_legacy_failed"
        for plan_id in (legacy_started, legacy_failed):
            self.store.append(
                "execution.planned",
                {
                    "plan_id": plan_id,
                    "proposal_id": proposal["proposal_id"],
                    "objective_id": "101",
                    "semantic_action": "flag",
                },
                actor="fixture",
            )
        self.store.append(
            "execution.started",
            {
                "plan_id": legacy_started,
                "proposal_id": proposal["proposal_id"],
                "objective_id": "101",
                "action_kind": "flag",
            },
            actor="fixture",
        )
        self.store.append(
            "execution.blocked",
            {
                "plan_id": legacy_started,
                "proposal_id": proposal["proposal_id"],
                "reason": "legacy post-start failure",
            },
            actor="fixture",
        )
        self.store.append(
            "execution.failed",
            {
                "plan_id": legacy_failed,
                "proposal_id": proposal["proposal_id"],
                "reason": "legacy adapter exception",
            },
            actor="fixture",
        )
        executions = self.store.rebuild()["current"]["executions"]
        self.assertEqual(executions[legacy_started]["status"], "indeterminate")
        self.assertEqual(executions[legacy_failed]["status"], "indeterminate")
        queued = {
            item["proposal_id"]
            for item in build_queue(self.store, self.manifest)["items"]
        }
        self.assertNotIn(proposal["proposal_id"], queued)

    def test_recomputed_plan_file_tampering_fails_before_adapter_or_claim(self) -> None:
        proposal = self.approved(value="authority-p0-canonical-plan")
        authorization = grant_exact(
            self.store, proposal["proposal_id"], reason="pinned exact authority"
        )
        plan = compile_plan(
            self.store,
            self.root,
            self.manifest,
            self.scope,
            proposal["proposal_id"],
        )
        plan_path = self.root / "state" / "execution_plans" / f"{plan['plan_id']}.json"
        cases = (
            "exact_value",
            "artifact_reference",
            "attempt_scope",
            "lifecycle",
            "adapter_id",
            "proposal_action",
            "predicates",
            "proposal_event_id",
            "plan_path",
        )
        for field in cases:
            with self.subTest(field=field):
                tampered = deepcopy(plan)
                if field == "exact_value":
                    tampered["envelope"]["exact_value"] = "FIXTURE{tampered}"
                elif field == "artifact_reference":
                    tampered["envelope"]["artifact_reference"] = "evidence/tampered.txt"
                elif field == "attempt_scope":
                    tampered["envelope"]["attempt_scope"] = {"attempt_id": "tampered"}
                elif field == "lifecycle":
                    tampered["lifecycle_refs"] = {"attempt_id": "tampered"}
                elif field == "adapter_id":
                    tampered["adapter_id"] = "tampered-adapter"
                    tampered["envelope"]["adapter_id"] = "tampered-adapter"
                elif field == "proposal_action":
                    tampered["proposal_id"] = "prop_tampered"
                    tampered["semantic_action"] = "free_text"
                    tampered["envelope"]["action_kind"] = "free_text"
                elif field == "predicates":
                    tampered["predicates"]["authorization_id"] = "auth_tampered"
                elif field == "proposal_event_id":
                    tampered["predicates"]["proposal_event_id"] = "evt_tampered"
                else:
                    tampered["plan_path"] = "state/execution_plans/plan_tampered.json"
                tampered["plan_sha256"] = sha256_bytes(
                    canonical_json(
                        {
                            key: value
                            for key, value in tampered.items()
                            if key != "plan_sha256"
                        }
                    ).encode("utf-8")
                )
                atomic_write_json(plan_path, tampered)
                with mock.patch(
                    "rookery.portable.execution.get_adapter"
                ) as get_adapter:
                    result, rc = execute_plan(
                        self.store,
                        self.root,
                        self.manifest,
                        self.scope,
                        plan["plan_id"],
                    )
                self.assertEqual(rc, 2)
                self.assertEqual(result["status"], "blocked")
                self.assertIn("canonical", result["reason"])
                get_adapter.assert_not_called()
                self.assertEqual(
                    self.store.rebuild()["current"]["authorizations"][
                        authorization["authorization_id"]
                    ]["remaining"],
                    1,
                )
                self.assertFalse(self.store.events("authorization.consumed"))
                self.assertFalse(self.store.events("execution.started"))
        atomic_write_json(plan_path, plan)

    def test_missing_proposal_event_predicate_fails_claim_closed(self) -> None:
        proposal = self.approved(value="authority-p0-proposal-event")
        grant_exact(self.store, proposal["proposal_id"], reason="pinned authority")
        plan = compile_plan(
            self.store,
            self.root,
            self.manifest,
            self.scope,
            proposal["proposal_id"],
        )
        missing = deepcopy(plan)
        del missing["predicates"]["proposal_event_id"]
        with self.assertRaisesRegex(RuntimeError, "immutable authority predicates"):
            claim_plan_authority(self.store, missing)
        self.assertFalse(self.store.events("authorization.consumed"))
        self.assertFalse(self.store.events("execution.started"))

    def test_policy_generation_change_waits_for_dispatch_barrier(self) -> None:
        proposal = self.approved(value="authority-p0-policy-lock")
        grant_exact(self.store, proposal["proposal_id"], reason="pinned authority")
        plan = compile_plan(
            self.store,
            self.root,
            self.manifest,
            self.scope,
            proposal["proposal_id"],
        )
        adapter = get_adapter(self.root, self.manifest, self.scope)
        policy_started = threading.Event()
        policy_finished = threading.Event()
        policy_thread: threading.Thread | None = None

        def change_policy() -> None:
            policy_started.set()
            set_policy(
                self.store,
                "strategy",
                "points",
                source="operator",
                reason="racing policy update",
            )
            policy_finished.set()

        def execute_while_policy_waits(envelope, evidence_root):
            nonlocal policy_thread
            policy_thread = threading.Thread(target=change_policy)
            policy_thread.start()
            self.assertTrue(policy_started.wait(timeout=2))
            self.assertFalse(policy_finished.is_set())
            return {
                "verdict": {
                    "verdict": "accepted",
                    "scorer_truth": "accepted",
                },
                "response_path": str(evidence_root / "response.json"),
            }

        with (
            mock.patch("rookery.portable.execution.get_adapter", return_value=adapter),
            mock.patch.object(
                adapter, "execute_action", side_effect=execute_while_policy_waits
            ) as execute_action,
        ):
            result, rc = execute_plan(
                self.store,
                self.root,
                self.manifest,
                self.scope,
                plan["plan_id"],
            )
        self.assertIn(rc, {0, 1}, result)
        execute_action.assert_called_once()
        self.assertIsNotNone(policy_thread)
        policy_thread.join(timeout=3)
        self.assertTrue(policy_finished.is_set())
        events = self.store.events()
        terminal_sequence = next(
            event["seq"]
            for event in events
            if event["event_type"] == "execution.completed"
            and event["payload"].get("plan_id") == plan["plan_id"]
        )
        policy_sequence = next(
            event["seq"] for event in events if event["event_type"] == "policy.set"
        )
        self.assertLess(terminal_sequence, policy_sequence)


class DurableClaimQueueQuarantineTests(unittest.TestCase):
    def test_durable_start_claim_is_quarantined_from_repeated_queue_ticks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            store = EventStore(root)
            install_solver_ready_challenge(root, store)
            manifest = {
                "adapter": {"id": "fixture"},
                "scoring": {"action_kinds": ["flag"]},
                "authorization": {
                    "automation_permitted_action_kinds": ["flag"],
                },
                "queue": {"cadence_seconds": 0, "jitter_seconds": 0},
            }
            scope = {"generation": 0}
            proposal = create_proposal(
                store,
                manifest,
                objective_id="101",
                action_kind="flag",
                exact_value="FIXTURE{crash-after-claim}",
                source="analysis/crash/REPORT.md",
                rationale="durable claim quarantine regression",
                actor="solver-a",
            )
            record_review(
                store,
                proposal["proposal_id"],
                "approved",
                reviewer="reviewer-b",
                reason="independent fixture review",
            )
            authorization = grant_allowance(
                store,
                manifest,
                "flag",
                2,
                reason="two-count crash fixture allowance",
            )
            plan = compile_plan(store, root, manifest, scope, proposal["proposal_id"])
            claim_plan_authority(store, plan)
            for _ in range(2):
                queue = persist_schedules(store, manifest)
                self.assertFalse(
                    any(
                        item["proposal_id"] == proposal["proposal_id"]
                        for item in queue["items"]
                    )
                )
            self.assertEqual(len(store.events("execution.planned")), 1)
            self.assertFalse(store.events("queue.scheduled"))
            self.assertEqual(
                store.rebuild()["current"]["authorizations"][
                    authorization["authorization_id"]
                ]["remaining"],
                1,
            )
            with self.assertRaisesRegex(RuntimeError, "durable execution claim"):
                compile_plan(store, root, manifest, scope, proposal["proposal_id"])


class BoundUnknownReconciliationTests(unittest.TestCase):
    def test_bound_unknown_response_is_indeterminate_and_requires_lineage(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            store = EventStore(root)
            install_solver_ready_challenge(root, store)
            manifest = {
                "adapter": {"id": "fixture"},
                "scoring": {"action_kinds": ["flag"]},
                "queue": {"cadence_seconds": 0, "jitter_seconds": 0},
            }
            proposal = create_proposal(
                store,
                manifest,
                objective_id="101",
                action_kind="flag",
                exact_value="FIXTURE{reconciliation-unknown}",
                attempt_scope={},
                challenge_id="101",
                source="analysis/reconciliation/REPORT.md",
                rationale="bound unknown reconciliation regression",
                actor="solver-a",
            )
            record_review(
                store,
                proposal["proposal_id"],
                "approved",
                reviewer="reviewer-b",
                reason="independent fixture review",
            )
            grant_exact(
                store, proposal["proposal_id"], reason="unknown import fixture"
            )
            plan = compile_plan(
                store,
                root,
                manifest,
                {"generation": 0},
                proposal["proposal_id"],
            )
            claim_plan_authority(store, plan, loaded_plan=plan, actor="fixture")
            response_dir = root / "submissions" / "external" / "unknown"
            response_dir.mkdir(parents=True)
            atomic_write_json(
                response_dir / "request.json",
                {
                    "proposal_id": proposal["proposal_id"],
                    "challenge_id": "101",
                    "value": proposal["exact_value"],
                    "action_kind": proposal["action_kind"],
                    "adapter_id": proposal["adapter_id"],
                    "attempt_scope": proposal["attempt_scope"],
                },
            )
            atomic_write_json(
                response_dir / "response.json",
                {"http_status": 200, "success": True, "data": {"opaque": "response"}},
            )
            first = import_response(store, root, response_dir / "response.json")
            second = import_response(store, root, response_dir / "response.json")
            self.assertEqual(first["verdict"]["verdict"], "unknown")
            self.assertEqual(first["status"], "indeterminate")
            self.assertEqual(first["retry"]["terminal_state"], "indeterminate")
            self.assertRegex(first["retry"]["fingerprint"], r"^[0-9a-f]{64}$")
            self.assertEqual(second["import_status"], "already-recorded")
            self.assertEqual(len(store.events("execution.indeterminate")), 1)
            queued = {
                item["proposal_id"] for item in build_queue(store, manifest)["items"]
            }
            self.assertNotIn(proposal["proposal_id"], queued)
            with self.assertRaisesRegex(ValueError, "identical candidate"):
                create_proposal(
                    store,
                    manifest,
                    objective_id="101",
                    action_kind="flag",
                    exact_value=proposal["exact_value"],
                    attempt_scope=proposal["attempt_scope"],
                    source="analysis/reconciliation/retry.md",
                    rationale="same unknown response without lineage",
                    actor="solver-c",
                )
            follow_up = create_proposal(
                store,
                manifest,
                objective_id="101",
                action_kind="flag",
                exact_value=proposal["exact_value"],
                attempt_scope=proposal["attempt_scope"],
                source="analysis/reconciliation/retry.md",
                rationale="same unknown response with new evidence",
                parent_rejection_fingerprint=first["retry"]["fingerprint"],
                discriminator="new independent verifier evidence",
                challenge_id="101",
                source_handoff_id="handoff-reconciliation-retry-fixture",
                actor="solver-c",
            )
            self.assertEqual(
                follow_up["parent_rejection_fingerprint"], first["retry"]["fingerprint"]
            )
            self.assertEqual(follow_up["challenge_id"], "101")
            self.assertEqual(
                follow_up["source_handoff_id"],
                "handoff-reconciliation-retry-fixture",
            )


class ProposalAgentAttemptLineageTests(unittest.TestCase):
    def test_supplied_attempt_must_be_the_actor_current_registered_attempt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            store = EventStore(root)
            install_solver_ready_challenge(root, store)
            install_solver_ready_challenge(root, store, "102")
            manifest = {
                "adapter": {"id": "fixture"},
                "scoring": {"action_kinds": ["flag"]},
            }

            def propose(
                *,
                value: str,
                actor: str = "solver-a",
                objective_id: str = "101",
                agent_attempt_id: str = "",
            ) -> dict:
                return create_proposal(
                    store,
                    manifest,
                    objective_id=objective_id,
                    action_kind="flag",
                    exact_value=value,
                    source="analysis/attempt/REPORT.md",
                    rationale="proposal attempt lineage regression",
                    agent_attempt_id=agent_attempt_id,
                    actor=actor,
                )

            # Coordinator/manual proposals retain their intentionally empty link.
            manual = propose(value="FIXTURE{manual}", actor="coordinator")
            self.assertEqual(manual["agent_attempt_id"], "")
            self.assertNotIn("parent_agent_attempt_id", manual)

            with self.assertRaisesRegex(ValueError, "active registered"):
                propose(value="FIXTURE{unknown}", agent_attempt_id="attempt-unknown")

            store.append(
                "agent.running",
                {
                    "agent_id": "solver-a",
                    "agent_attempt_id": "attempt-valid",
                    "objective_id": "101",
                    "role": "worker",
                    "report_path": "analysis/attempt/REPORT.md",
                },
                actor="coordinator",
            )
            with self.assertRaisesRegex(ValueError, "does not match actor"):
                propose(
                    value="FIXTURE{wrong-actor}",
                    actor="solver-b",
                    agent_attempt_id="attempt-valid",
                )
            valid = propose(
                value="FIXTURE{valid}", agent_attempt_id="attempt-valid"
            )
            self.assertEqual(valid["agent_attempt_id"], "attempt-valid")

            store.append(
                "agent.running",
                {
                    "agent_id": "solver-a",
                    "agent_attempt_id": "attempt-objective",
                    "objective_id": "101",
                    "role": "worker",
                    "report_path": "analysis/attempt/objective.md",
                },
                actor="coordinator",
            )
            with self.assertRaisesRegex(ValueError, "does not match objective"):
                propose(
                    value="FIXTURE{wrong-objective}",
                    objective_id="102",
                    agent_attempt_id="attempt-objective",
                )

            store.append(
                "agent.running",
                {
                    "agent_id": "solver-a",
                    "agent_attempt_id": "attempt-closed",
                    "objective_id": "101",
                    "role": "worker",
                    "report_path": "analysis/attempt/closed.md",
                },
                actor="coordinator",
            )
            store.append(
                "agent.closed",
                {
                    "agent_id": "solver-a",
                    "agent_attempt_id": "attempt-closed",
                    "objective_id": "101",
                    "reason": "fixture complete",
                },
                actor="coordinator",
            )
            with self.assertRaisesRegex(ValueError, "active registered"):
                propose(value="FIXTURE{closed}", agent_attempt_id="attempt-closed")


if __name__ == "__main__":
    unittest.main()
