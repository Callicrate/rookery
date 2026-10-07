from __future__ import annotations

# ruff: noqa: E402

import os
import sys
import unittest
from pathlib import Path
from unittest import mock

from tests.rookery.support import ROOKERY_ROOT

LIB = ROOKERY_ROOT / "lib"
if str(LIB) not in sys.path:
    sys.path.insert(0, str(LIB))
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

from rookery.portable.adapters import get_adapter
from rookery.portable import execution
from rookery.portable.control import resume, stop
from rookery.portable.execution import compile_plan, execute_plan
from rookery.portable.policy import set_policy
from rookery.portable.scoring import (
    admission_wait_reasons,
    claim_plan_authority,
    create_proposal,
    grant_exact,
    proposal_and_review_bind_current_generation,
    record_review,
)
from rookery.portable.util import canonical_json, sha256_bytes
from tests.rookery.test_acceptance_campaign import context, make_workspace
from tests.rookery.support import install_solver_ready_challenge


class ScoringGenerationAuthorityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.workspace = make_workspace("fixture")
        self.root = Path(self.workspace.name)
        self.manifest, self.scope, self.store, _ = context(self.root, "fixture")
        install_solver_ready_challenge(self.root, self.store)

    def tearDown(self) -> None:
        self.workspace.cleanup()

    def _proposal(self, value: str) -> dict[str, object]:
        return create_proposal(
            self.store,
            self.manifest,
            objective_id="101",
            action_kind="flag",
            exact_value=f"FIXTURE{{{value}}}",
            source="analysis/generation-authority/REPORT.md",
            rationale="generation-bound authority regression",
            actor="solver-a",
        )

    def _approve(self, proposal: dict[str, object], reviewer: str = "reviewer-b") -> dict[str, object]:
        return record_review(
            self.store,
            str(proposal["proposal_id"]),
            "approved",
            reviewer=reviewer,
            reason="independent generation-bound review",
        )

    def _advance_generation(self, kind: str) -> None:
        if kind == "policy":
            set_policy(
                self.store,
                "strategy",
                "points",
                source="operator",
                reason="policy generation drift fixture",
            )
            return
        stop(self.store, self.root, reason="stop generation drift fixture", wait_seconds=0)
        resume(self.store, reason="resume generation drift fixture")

    def _legacy_current_authorization(
        self, proposal: dict[str, object]
    ) -> dict[str, object]:
        payload = {
            "authorization_id": "auth_legacy_current_generation",
            "mode": "exact",
            "proposal_id": proposal["proposal_id"],
            "action_kind": "flag",
            "remaining": 1,
            "reason": "legacy stale-proposal authority fixture",
            "stop_generation": self.store.current_stop_generation(),
            "policy_generation": int(self.store.get_meta("policy_generation", "0")),
        }
        self.store.append(
            "authorization.granted",
            payload,
            actor="operator",
        )
        return payload

    def _stale_claim_plan(
        self,
        proposal: dict[str, object],
        review: dict[str, object],
        authorization: dict[str, object],
    ) -> dict[str, object]:
        plan_id = "plan_stale_" + str(proposal["proposal_id"])
        plan = {
            "schema_version": "1",
            "plan_id": plan_id,
            "generation": self.store.current_stop_generation(),
            "policy_generation": int(self.store.get_meta("policy_generation", "0")),
            "adapter_id": proposal["adapter_id"],
            "objective_id": proposal["objective_id"],
            "proposal_id": proposal["proposal_id"],
            "semantic_action": proposal["action_kind"],
            "envelope": {"attempt_scope": proposal["attempt_scope"]},
            "lifecycle_refs": {},
            "predicates": {
                "proposal_event_id": proposal["event_id"],
                "review_event_id": review["event_id"],
                "authorization_id": authorization["authorization_id"],
                "scope_generation": self.scope["generation"],
            },
        }
        plan["plan_sha256"] = sha256_bytes(canonical_json(plan).encode("utf-8"))
        self.store.append(
            "execution.planned",
            {
                **plan,
                "plan_path": f"state/execution_plans/{plan_id}.json",
            },
            actor="fixture",
        )
        return plan

    def test_stale_proposal_and_review_cannot_claim_fresh_authority(self) -> None:
        for kind in ("policy", "stop"):
            with self.subTest(kind=kind):
                proposal = self._proposal(f"stale-{kind}")
                old_review = self._approve(proposal)
                self._advance_generation(kind)
                # Old work cannot be re-attested or re-authorized after drift.
                with self.assertRaisesRegex(RuntimeError, "stale generation"):
                    self._approve(proposal, reviewer="reviewer-c")
                with self.assertRaisesRegex(RuntimeError, "stale generation"):
                    grant_exact(
                        self.store,
                        str(proposal["proposal_id"]),
                        reason="fresh exact authority after drift",
                    )
                authorization = self._legacy_current_authorization(proposal)

                if kind == "stop":
                    self.assertNotEqual(
                        proposal["stop_generation"],
                        self.store.current_stop_generation(),
                    )
                else:
                    self.assertNotEqual(
                        proposal["policy_generation"],
                        int(self.store.get_meta("policy_generation", "0")),
                    )
                self.assertIn("policy_generation", old_review)

                with self.assertRaisesRegex(RuntimeError, "generation"):
                    compile_plan(
                        self.store,
                        self.root,
                        self.manifest,
                        self.scope,
                        str(proposal["proposal_id"]),
                    )

                plan = self._stale_claim_plan(proposal, old_review, authorization)
                with self.assertRaisesRegex(RuntimeError, "generation"):
                    claim_plan_authority(self.store, plan)
                self.assertFalse(
                    any(
                        event["payload"].get("plan_id") == plan["plan_id"]
                        for event in self.store.events("execution.started")
                    )
                )
                self.assertFalse(
                    any(
                        event["payload"].get("consumed_for_plan") == plan["plan_id"]
                        for event in self.store.events("authorization.consumed")
                    )
                )

    def test_fresh_proposal_and_review_can_claim_current_authority(self) -> None:
        self._advance_generation("policy")
        proposal = self._proposal("current")
        review = self._approve(proposal)
        authorization = grant_exact(
            self.store, str(proposal["proposal_id"]), reason="current exact authority"
        )
        self.assertEqual(
            proposal["policy_generation"],
            int(self.store.get_meta("policy_generation", "0")),
        )
        self.assertEqual(review["policy_generation"], proposal["policy_generation"])
        plan = compile_plan(
            self.store,
            self.root,
            self.manifest,
            self.scope,
            str(proposal["proposal_id"]),
        )
        adapter = get_adapter(self.root, self.manifest, self.scope)
        with (
            mock.patch("rookery.portable.execution.get_adapter", return_value=adapter),
            mock.patch.object(
                adapter,
                "execute_action",
                return_value={
                    "verdict": {"verdict": "accepted", "scorer_truth": "accepted"},
                    "response_path": "submissions/generation-authority.json",
                },
            ) as execute_action,
        ):
            result, code = execute_plan(
                self.store, self.root, self.manifest, self.scope, plan["plan_id"]
            )
        self.assertIn(code, {0, 1}, result)
        execute_action.assert_called_once()
        self.assertTrue(
            any(
                event["payload"].get("plan_id") == plan["plan_id"]
                for event in self.store.events("execution.started")
            )
        )
        consumed = next(
            event["payload"]
            for event in self.store.events("authorization.consumed")
            if event["payload"].get("consumed_for_plan") == plan["plan_id"]
        )
        self.assertEqual(consumed["authorization_id"], authorization["authorization_id"])

    def test_adapter_identity_stays_bound_through_proposal_and_dispatch(self) -> None:
        before = self.store.count()
        with self.assertRaisesRegex(ValueError, "adapter_id must match"):
            create_proposal(
                self.store,
                self.manifest,
                objective_id="101",
                action_kind="flag",
                exact_value="FIXTURE{wrong-adapter}",
                adapter_id="manual",
                source="analysis/generation-authority/REPORT.md",
                rationale="adapter override must not change the selected adapter",
                actor="solver-a",
            )
        self.assertEqual(self.store.count(), before)

        proposal = self._proposal("adapter-drift")
        self._approve(proposal)
        authorization = grant_exact(
            self.store, str(proposal["proposal_id"]), reason="adapter fixture authority"
        )
        plan = compile_plan(
            self.store,
            self.root,
            self.manifest,
            self.scope,
            str(proposal["proposal_id"]),
        )
        self.assertEqual(plan["adapter_id"], "fixture")
        self.assertEqual(plan["envelope"]["adapter_id"], "fixture")
        self.assertEqual(plan["adapter_id"], proposal["adapter_id"])

        self.manifest["adapter"]["id"] = "manual"
        with mock.patch("rookery.portable.execution.get_adapter") as get_adapter:
            result, code = execute_plan(
                self.store, self.root, self.manifest, self.scope, plan["plan_id"]
            )
        self.assertEqual(code, 2)
        self.assertEqual(result["status"], "blocked")
        self.assertIn("adapter does not match", result["reason"])
        get_adapter.assert_not_called()
        self.assertEqual(
            self.store.rebuild()["current"]["authorizations"][
                authorization["authorization_id"]
            ]["remaining"],
            1,
        )
        self.assertFalse(self.store.events("execution.started"))

    def test_adapter_identity_is_rechecked_immediately_before_dispatch(self) -> None:
        proposal = self._proposal("adapter-dispatch-drift")
        self._approve(proposal)
        grant_exact(
            self.store,
            str(proposal["proposal_id"]),
            reason="adapter dispatch fixture authority",
        )
        plan = compile_plan(
            self.store,
            self.root,
            self.manifest,
            self.scope,
            str(proposal["proposal_id"]),
        )
        adapter = get_adapter(self.root, self.manifest, self.scope)
        real_claim = execution.claim_plan_authority

        def claim_then_change_adapter(*args, **kwargs):
            result = real_claim(*args, **kwargs)
            self.manifest["adapter"]["id"] = "manual"
            return result

        with (
            mock.patch("rookery.portable.execution.get_adapter", return_value=adapter),
            mock.patch(
                "rookery.portable.execution.claim_plan_authority",
                side_effect=claim_then_change_adapter,
            ),
            mock.patch.object(adapter, "execute_action") as execute_action,
        ):
            result, code = execute_plan(
                self.store, self.root, self.manifest, self.scope, plan["plan_id"]
            )
        self.assertEqual(code, 2)
        self.assertEqual(result["status"], "indeterminate")
        self.assertIn("adapter does not match", result["reason"])
        execute_action.assert_not_called()

    def test_malformed_generation_fields_fail_closed_without_watcher_exceptions(self) -> None:
        current = {"stop_generation": 4, "policy_generation": 7, "stopped": False}
        authorization = {"authorization_id": "auth-current"}
        proposal = {
            "action_kind": "flag",
            "stop_generation": 4,
            "policy_generation": 7,
        }
        review = {
            "verdict": "approved",
            "stop_generation": 4,
            "policy_generation": 7,
        }
        self.assertEqual(admission_wait_reasons(current, proposal, review, authorization), [])
        self.assertTrue(
            proposal_and_review_bind_current_generation(
                proposal, review, stop_generation=4, policy_generation=7
            )
        )

        cases = (
            ("proposal", "stop_generation", True, "proposal has malformed stop_generation"),
            ("proposal", "policy_generation", 7.0, "proposal has malformed policy_generation"),
            ("review", "stop_generation", "4", "review has malformed stop_generation"),
            ("review", "policy_generation", -1, "review has malformed policy_generation"),
            ("review", "policy_generation", None, "review is missing policy_generation"),
        )
        for subject, field, value, expected in cases:
            with self.subTest(subject=subject, field=field, value=value):
                candidate_proposal = dict(proposal)
                candidate_review = dict(review)
                target = candidate_proposal if subject == "proposal" else candidate_review
                target[field] = value
                reasons = admission_wait_reasons(
                    current, candidate_proposal, candidate_review, authorization
                )
                self.assertIn(expected, reasons)
                self.assertFalse(
                    proposal_and_review_bind_current_generation(
                        candidate_proposal,
                        candidate_review,
                        stop_generation=4,
                        policy_generation=7,
                    )
                )


if __name__ == "__main__":
    unittest.main(verbosity=2)
