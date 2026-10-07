from __future__ import annotations

# ruff: noqa: E402

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

from rookery.portable import execution
from rookery.portable.adapters import get_adapter
from rookery.portable.execution import compile_plan, execute_plan
from rookery.portable.scoring import create_proposal, grant_exact, record_review
from tests.rookery.support import install_solver_ready_challenge
from tests.rookery.test_acceptance_campaign import context, make_workspace


ELIGIBILITY_ERROR = "challenge is not currently solver-eligible"


class ScoringIntakeEligibilityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.workspace = make_workspace("fixture")
        self.root = Path(self.workspace.name)
        self.manifest, self.scope, self.store, _ = context(self.root, "fixture")

    def tearDown(self) -> None:
        self.workspace.cleanup()

    def _proposal(self, *, action_kind: str = "flag", value: str = "ready") -> dict:
        return create_proposal(
            self.store,
            self.manifest,
            objective_id="101",
            action_kind=action_kind,
            exact_value=f"FIXTURE{{{value}}}",
            source="analysis/scoring-intake/REPORT.md",
            rationale="verified scoring-intake eligibility regression",
            actor="solver-a",
        )

    def _approved_plan(self) -> tuple[dict, dict, dict]:
        proposal = self._proposal()
        record_review(
            self.store,
            proposal["proposal_id"],
            "approved",
            reviewer="reviewer-b",
            reason="independent fixture review",
        )
        authorization = grant_exact(
            self.store,
            proposal["proposal_id"],
            reason="bounded fixture authorization",
        )
        plan = compile_plan(
            self.store,
            self.root,
            self.manifest,
            self.scope,
            proposal["proposal_id"],
        )
        return proposal, authorization, plan

    def _mark_intake(self, state: str) -> None:
        self.store.append(
            "challenge.upsert",
            {"id": "101", "intake_state": state},
            actor="fixture",
        )

    def test_text_proposal_requires_current_canonical_verified_challenge(self) -> None:
        for action_kind in ("flag", "free_text"):
            with self.subTest(action_kind=action_kind):
                if action_kind == "free_text":
                    self.manifest["scoring"]["action_kinds"].append("free_text")
                before = self.store.count()
                with self.assertRaisesRegex(ValueError, ELIGIBILITY_ERROR):
                    self._proposal(action_kind=action_kind, value=action_kind)
                self.assertEqual(self.store.count(), before)

    def _assert_intake_state_blocks(self, state: str) -> None:
        row = install_solver_ready_challenge(self.root, self.store)
        if state in {"pending", "partial"}:
            self._mark_intake(state)
        elif state == "tampered":
            (self.root / str(row["detail_path"])).write_text(
                "tampered", encoding="utf-8"
            )
        elif state == "unavailable":
            self.store.append(
                "platform.snapshot",
                {
                    "adapter_id": "fixture",
                    "capabilities": {
                        "platform_inventory": {
                            "availability": "available",
                            "health": "healthy",
                        }
                    },
                    "challenges": [],
                },
                actor="fixture",
            )
        else:
            raise AssertionError(f"unknown fixture state: {state}")
        before = self.store.count()
        with self.assertRaisesRegex(ValueError, ELIGIBILITY_ERROR):
            self._proposal(value=state)
        self.assertEqual(self.store.count(), before)

    def test_pending_intake_blocks_proposal(self) -> None:
        self._assert_intake_state_blocks("pending")

    def test_partial_intake_blocks_proposal(self) -> None:
        self._assert_intake_state_blocks("partial")

    def test_tampered_intake_blocks_proposal(self) -> None:
        self._assert_intake_state_blocks("tampered")

    def test_unavailable_challenge_blocks_proposal(self) -> None:
        self._assert_intake_state_blocks("unavailable")

    def test_complete_verified_intake_allows_text_proposal(self) -> None:
        install_solver_ready_challenge(self.root, self.store)
        proposal = self._proposal()
        self.assertEqual(proposal["objective_id"], "101")
        self.assertEqual(len(self.store.events("proposal.created")), 1)

    def test_invalidation_after_proposal_blocks_plan_publication(self) -> None:
        install_solver_ready_challenge(self.root, self.store)
        proposal = self._proposal()
        record_review(
            self.store,
            proposal["proposal_id"],
            "approved",
            reviewer="reviewer-b",
            reason="independent fixture review",
        )
        grant_exact(
            self.store,
            proposal["proposal_id"],
            reason="bounded fixture authorization",
        )
        self._mark_intake("partial")

        with self.assertRaisesRegex(RuntimeError, ELIGIBILITY_ERROR):
            compile_plan(
                self.store,
                self.root,
                self.manifest,
                self.scope,
                proposal["proposal_id"],
            )
        self.assertFalse(self.store.events("execution.planned"))

    def test_invalidation_before_execution_does_not_consume_authority(self) -> None:
        install_solver_ready_challenge(self.root, self.store)
        proposal, authorization, plan = self._approved_plan()
        adapter = get_adapter(self.root, self.manifest, self.scope)
        self._mark_intake("partial")

        with (
            mock.patch(
                "rookery.portable.execution.get_adapter", return_value=adapter
            ) as get_adapter_mock,
            mock.patch.object(adapter, "preflight_action") as preflight_action,
            mock.patch.object(adapter, "execute_action") as execute_action,
        ):
            result, code = execute_plan(
                self.store,
                self.root,
                self.manifest,
                self.scope,
                plan["plan_id"],
            )

        self.assertEqual(code, 2)
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["reason"], ELIGIBILITY_ERROR)
        get_adapter_mock.assert_not_called()
        preflight_action.assert_not_called()
        execute_action.assert_not_called()
        self.assertFalse(self.store.events("execution.started"))
        self.assertFalse(self.store.events("authorization.consumed"))
        current = self.store.rebuild()["current"]
        self.assertEqual(
            current["authorizations"][authorization["authorization_id"]]["remaining"],
            1,
        )
        self.assertEqual(proposal["objective_id"], "101")

    def test_final_post_claim_revalidation_fails_closed(self) -> None:
        row = install_solver_ready_challenge(self.root, self.store)
        _, _, plan = self._approved_plan()
        adapter = get_adapter(self.root, self.manifest, self.scope)
        real_claim = execution.claim_plan_authority

        def claim_then_tamper(*args, **kwargs):
            claimed = real_claim(*args, **kwargs)
            (self.root / str(row["detail_path"])).write_text(
                "tampered after claim", encoding="utf-8"
            )
            return claimed

        with (
            mock.patch("rookery.portable.execution.get_adapter", return_value=adapter),
            mock.patch(
                "rookery.portable.execution.claim_plan_authority",
                side_effect=claim_then_tamper,
            ),
            mock.patch.object(adapter, "execute_action") as execute_action,
        ):
            result, code = execute_plan(
                self.store,
                self.root,
                self.manifest,
                self.scope,
                plan["plan_id"],
            )

        self.assertEqual(code, 2)
        self.assertEqual(result["status"], "indeterminate")
        self.assertEqual(result["reason"], ELIGIBILITY_ERROR)
        execute_action.assert_not_called()
        self.assertEqual(len(self.store.events("execution.started")), 1)
        self.assertEqual(len(self.store.events("authorization.consumed")), 1)

    def test_no_submit_evidence_remains_usable_without_challenge_intake(self) -> None:
        proposal = create_proposal(
            self.store,
            self.manifest,
            objective_id="event-wide-evidence",
            action_kind="no_submit_evidence",
            artifact_reference="evidence/event-wide.txt",
            source="analysis/scoring-intake/REPORT.md",
            rationale="event-wide evidence completion fixture",
            actor="solver-a",
        )
        record_review(
            self.store,
            proposal["proposal_id"],
            "approved",
            reviewer="reviewer-b",
            reason="independent fixture review",
        )
        plan = compile_plan(
            self.store,
            self.root,
            self.manifest,
            self.scope,
            proposal["proposal_id"],
        )
        result, code = execute_plan(
            self.store,
            self.root,
            self.manifest,
            self.scope,
            plan["plan_id"],
        )
        self.assertEqual(code, 0)
        self.assertEqual(result["status"], "completed")
        self.assertFalse(self.store.events("authorization.consumed"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
