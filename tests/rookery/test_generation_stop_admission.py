from __future__ import annotations

# ruff: noqa: E402

import os
import sys
import threading
import unittest
from copy import deepcopy
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
LIB = REPOSITORY_ROOT / "rookery" / "lib"
if str(LIB) not in sys.path:
    sys.path.insert(0, str(LIB))
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

from rookery.portable.control import resume, stop
from rookery.portable.execution import compile_plan
from rookery.portable.outcomes import harvest_report, record_outcome, register_agent_attempt
from rookery.portable.policy import set_policy
from rookery.portable.queue import build_queue, persist_schedules
from rookery.portable.scoring import (
    claim_plan_authority,
    create_proposal,
    grant_allowance,
    grant_exact,
    record_review,
)
from rookery.portable.store import EventStore
from rookery.portable.util import canonical_json, sha256_bytes
from tests.rookery.support import install_solver_ready_challenge, render_handoff_report
from tests.rookery.test_acceptance_campaign import context, make_workspace


class GenerationStopAdmissionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.workspace = make_workspace("fixture")
        self.root = Path(self.workspace.name)
        self.manifest, self.scope, self.store, _ = context(self.root, "fixture")
        install_solver_ready_challenge(self.root, self.store)
        self.manifest["queue"]["cadence_seconds"] = 0
        self.manifest["queue"]["jitter_seconds"] = 0

    def tearDown(self) -> None:
        self.workspace.cleanup()

    def _approved(self, value: str = "generation-stop") -> dict[str, object]:
        proposal = create_proposal(
            self.store,
            self.manifest,
            objective_id="101",
            action_kind="flag",
            exact_value=f"FIXTURE{{{value}}}",
            source="analysis/generation-stop/REPORT.md",
            rationale="generation and stop admission regression",
            actor="solver-a",
        )
        record_review(
            self.store,
            str(proposal["proposal_id"]),
            "approved",
            reviewer="reviewer-b",
            reason="independent fixture review",
        )
        return proposal

    def _fresh_manual_authorization_and_plan(
        self, old_plan: dict[str, object]
    ) -> dict[str, object]:
        """Forge only canonical fixture evidence for a stale-tuple negative test."""

        current = self.store.rebuild()["current"]
        proposal_id = str(old_plan["proposal_id"])
        generation = int(current["stop_generation"])
        policy_generation = int(current["policy_generation"])
        authorization_id = f"auth-fixture-{generation}-{policy_generation}"
        self.store.append(
            "authorization.granted",
            {
                "authorization_id": authorization_id,
                "mode": "exact",
                "proposal_id": proposal_id,
                "action_kind": "flag",
                "remaining": 1,
                "reason": "fixture fresh authority after generation change",
                "stop_generation": generation,
                "policy_generation": policy_generation,
            },
            actor="fixture",
            generation=generation,
        )
        plan = deepcopy(old_plan)
        plan_id = f"plan-fixture-{generation}-{policy_generation}"
        plan["plan_id"] = plan_id
        plan["generation"] = generation
        plan["policy_generation"] = policy_generation
        predicates = dict(plan["predicates"])
        predicates["authorization_id"] = authorization_id
        plan["predicates"] = predicates
        plan["created_at"] = f"2026-08-29T00:00:{generation:02d}Z"
        plan.pop("plan_sha256", None)
        plan["plan_sha256"] = sha256_bytes(canonical_json(plan).encode("utf-8"))
        self.store.append(
            "execution.planned",
            {
                **plan,
                "plan_path": f"state/execution_plans/{plan_id}.json",
            },
            actor="fixture",
            generation=generation,
        )
        return plan

    def test_policy_advance_rejects_stale_proposal_review_with_fresh_plan_tuple(self) -> None:
        proposal = self._approved("policy-stale")
        grant_exact(self.store, str(proposal["proposal_id"]), reason="fixture")
        old_plan = compile_plan(
            self.store, self.root, self.manifest, self.scope, str(proposal["proposal_id"])
        )
        set_policy(
            self.store,
            "strategy",
            "changed",
            source="operator",
            reason="fixture policy generation advance",
        )
        queue_item = next(
            item
            for item in build_queue(self.store, self.manifest)["items"]
            if item["proposal_id"] == proposal["proposal_id"]
        )
        self.assertFalse(queue_item["eligible"])
        self.assertIn(
            "proposal belongs to a stale policy generation",
            queue_item["wait_reasons"],
        )
        self.assertIn(
            "review belongs to a stale policy generation",
            queue_item["wait_reasons"],
        )
        before = self.store.count()
        with self.assertRaisesRegex(RuntimeError, "stale generation"):
            compile_plan(
                self.store,
                self.root,
                self.manifest,
                self.scope,
                str(proposal["proposal_id"]),
            )
        self.assertEqual(self.store.count(), before)
        forged = self._fresh_manual_authorization_and_plan(old_plan)
        with self.assertRaisesRegex(RuntimeError, "bind current generations"):
            claim_plan_authority(self.store, forged)
        self.assertFalse(self.store.events("authorization.consumed"))
        self.assertFalse(self.store.events("execution.started"))

    def test_reducer_preserves_authorization_payload_generation_over_event_stamp(self) -> None:
        stop(self.store, self.root, reason="advance fixture generation", wait_seconds=0)
        resume(self.store, reason="fixture explicit resume")
        self.store.append(
            "authorization.granted",
            {
                "authorization_id": "auth-stale-payload",
                "mode": "allowance",
                "action_kind": "flag",
                "remaining": 1,
                "stop_generation": 0,
                "policy_generation": 0,
            },
            actor="fixture",
            generation=1,
        )
        authorization = self.store.rebuild()["current"]["authorizations"][
            "auth-stale-payload"
        ]
        self.assertEqual(authorization["stop_generation"], 0)
        self.assertEqual(authorization["event_stop_generation"], 1)

    def test_stop_resume_rejects_stale_proposal_review_with_fresh_plan_tuple(self) -> None:
        proposal = self._approved("stop-stale")
        grant_exact(self.store, str(proposal["proposal_id"]), reason="fixture")
        old_plan = compile_plan(
            self.store, self.root, self.manifest, self.scope, str(proposal["proposal_id"])
        )
        stop(self.store, self.root, reason="fixture stop", wait_seconds=0)
        resume(self.store, reason="fixture explicit resume")
        forged = self._fresh_manual_authorization_and_plan(old_plan)
        with self.assertRaisesRegex(RuntimeError, "bind current generations"):
            claim_plan_authority(self.store, forged)
        self.assertFalse(self.store.events("authorization.consumed"))
        self.assertFalse(self.store.events("execution.started"))

    def test_stopped_workspace_rejects_new_admission_and_keeps_late_report_as_debt(self) -> None:
        proposal = self._approved("stopped-admission")
        register_agent_attempt(
            self.store,
            {
                "agent_id": "closeout-agent",
                "agent_attempt_id": "closeout-attempt",
                "objective_id": "101",
                "event_wide": True,
                "source_handoff_id": "none",
                "goal": "record bounded stop closeout",
                "scope": "event-wide fixture closeout",
                "stop_condition": "record one typed closeout outcome",
                "role": "worker",
                "report_path": "analysis/closeout/REPORT.md",
            },
            max_workers=2,
        )
        stop(self.store, self.root, reason="fixture stop", wait_seconds=0)
        before = self.store.count()
        with self.assertRaisesRegex(RuntimeError, "workspace is stopped"):
            create_proposal(
                self.store,
                self.manifest,
                objective_id="101",
                action_kind="flag",
                exact_value="FIXTURE{blocked}",
                source="analysis/stopped/REPORT.md",
                rationale="must not admit while stopped",
                actor="solver-c",
            )
        with self.assertRaisesRegex(RuntimeError, "workspace is stopped"):
            record_review(
                self.store,
                str(proposal["proposal_id"]),
                "approved",
                reviewer="reviewer-c",
                reason="must not review while stopped",
            )
        with self.assertRaisesRegex(RuntimeError, "workspace is stopped"):
            grant_exact(self.store, str(proposal["proposal_id"]), reason="blocked")
        with self.assertRaisesRegex(RuntimeError, "workspace is stopped"):
            grant_allowance(self.store, self.manifest, "flag", 1, reason="blocked")
        with self.assertRaisesRegex(RuntimeError, "workspace is stopped"):
            compile_plan(
                self.store,
                self.root,
                self.manifest,
                self.scope,
                str(proposal["proposal_id"]),
            )
        with self.assertRaisesRegex(RuntimeError, "workspace is stopped"):
            register_agent_attempt(
                self.store,
                {
                    "agent_id": "blocked-agent",
                    "agent_attempt_id": "blocked-attempt",
                    "objective_id": "101",
                    "event_wide": True,
                    "source_handoff_id": "none",
                    "goal": "blocked registration fixture",
                    "scope": "event-wide fixture admission",
                    "stop_condition": "must not start while stopped",
                    "role": "worker",
                    "report_path": "analysis/blocked/REPORT.md",
                },
                max_workers=2,
            )
        persist_schedules(self.store, self.manifest)
        self.assertEqual(self.store.count(), before)
        self.assertTrue(self.store.rebuild()["current"]["stopped"])

        report_path = "analysis/closeout/REPORT.md"
        report = self.root / report_path
        report.parent.mkdir(parents=True, exist_ok=True)
        command = report.parent / "command.txt"
        command.write_text("fixture closeout command\n", encoding="utf-8")
        report.write_text(
            render_handoff_report(
                observed_result="The stopped worker left a bounded negative.",
                route_key="late-closeout-route",
                evidence_paths=(report_path,),
                command_artifact_paths=("analysis/closeout/command.txt",),
            ),
            encoding="utf-8",
        )
        debt = harvest_report(
            self.store,
            self.root,
            report_path,
            agent_id="closeout-agent",
            agent_attempt_id="closeout-attempt",
            objective_id="101",
            status="technical_negative",
            observed_result="The stopped worker left a bounded negative.",
            route_key="late-closeout-route",
            proof_gap="One independent fixture route remains untested.",
            next_step_or_return_trigger="Queue the alternate bounded fixture route.",
        )
        self.assertTrue(debt["reconciliation_debt"])
        self.assertEqual(debt["report_path"], report_path)
        self.assertEqual(debt["handoff_id"], "")
        with self.assertRaisesRegex(ValueError, "exact current harvested report"):
            record_outcome(
                self.store,
                agent_id="closeout-agent",
                agent_attempt_id="closeout-attempt",
                objective_id="101",
                outcome_type="technical_negative",
                report_path=report_path,
                summary="late report cannot become a new outcome after stop",
                mechanism="late-closeout-route",
            )
        self.assertFalse(self.store.events("outcome.recorded"))

    def test_grant_stop_barrier_never_creates_current_generation_authority(self) -> None:
        proposal = self._approved("grant-stop-race")
        observed_generation = self.store.current_stop_generation()
        outcomes: list[BaseException | dict[str, object]] = []
        start = threading.Barrier(2)

        def grant() -> None:
            try:
                start.wait(timeout=5)
                outcomes.append(
                    grant_exact(
                        EventStore(self.root),
                        str(proposal["proposal_id"]),
                        reason="racy fixture grant",
                        expected_stop_generation=observed_generation,
                    )
                )
            except BaseException as exc:  # pragma: no cover - propagated below.
                outcomes.append(exc)

        thread = threading.Thread(target=grant)
        thread.start()
        start.wait(timeout=5)
        stop(self.store, self.root, reason="race stop", wait_seconds=0)
        thread.join(timeout=10)
        self.assertFalse(thread.is_alive())
        current_generation = self.store.current_stop_generation()
        grants = self.store.events("authorization.granted")
        self.assertFalse(
            any(
                int(event["payload"].get("stop_generation", -1))
                == current_generation
                for event in grants
            )
        )
        self.assertTrue(outcomes)
