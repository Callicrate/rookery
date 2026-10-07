from __future__ import annotations

# ruff: noqa: E402

import os
import sys
import threading
import unittest
from pathlib import Path
from unittest import mock

from tests.rookery.support import (
    ROOKERY_ROOT,
    install_solver_ready_challenge,
    open_test_event_store,
)

LIB = ROOKERY_ROOT / "lib"
if str(LIB) not in sys.path:
    sys.path.insert(0, str(LIB))
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

from rookery.portable.adapters import get_adapter
from rookery.portable.control import resume
from rookery.portable.execution import compile_plan, execute_plan
from rookery.portable.manifest import resolve_manifest
from rookery.portable.queue import build_queue
from rookery.portable.scoring import (
    consume_authorization,
    create_proposal,
    grant_allowance,
    grant_exact,
    record_review,
)
from rookery.portable.scope import compile_scope


def make_workspace():
    from tests.rookery.test_acceptance_campaign import (
        make_workspace as campaign_workspace,
    )

    return campaign_workspace("fixture")


class ScoringRetryIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.td = make_workspace()
        self.root = Path(self.td.name)
        self.manifest, self.scope = self._context()
        self.store = open_test_event_store(self.root)
        self.store.set_meta("scope_generation", 1)
        resume(self.store, reason="scoring integrity fixture")
        self.store.append(
            "platform.snapshot",
            get_adapter(self.root, self.manifest, self.scope).sync(),
            actor="fixture",
        )
        install_solver_ready_challenge(self.root, self.store)

    def tearDown(self):
        self.td.cleanup()

    def _context(self):
        result = resolve_manifest(self.root)
        return result.manifest, compile_scope(result.manifest, 1)

    def _proposal(self, value: str):
        proposal = create_proposal(
            self.store,
            self.manifest,
            objective_id="101",
            action_kind="flag",
            exact_value=value,
            challenge_id="101",
            source="analysis/scoring-integrity/REPORT.md",
            rationale="local fixture",
            actor="solver-a",
        )
        record_review(
            self.store,
            proposal["proposal_id"],
            "approved",
            reviewer="reviewer-b",
            reason="independent local fixture review",
        )
        return proposal

    def _plan(self, proposal):
        return compile_plan(
            self.store,
            self.root,
            self.manifest,
            self.scope,
            proposal["proposal_id"],
        )

    def _reject(self, value: str = "FIXTURE{rejected}"):
        proposal = self._proposal(value)
        grant_exact(self.store, proposal["proposal_id"], reason="fixture exact")
        result, code = execute_plan(
            self.store,
            self.root,
            self.manifest,
            self.scope,
            self._plan(proposal)["plan_id"],
        )
        self.assertEqual(code, 1)
        self.assertEqual(result["status"], "rejected")
        return proposal, result

    def test_changed_review_blocks_stale_plan_and_reapproval_requires_new_plan(self):
        proposal = self._proposal("FIXTURE{accepted}")
        authorization = grant_exact(
            self.store, proposal["proposal_id"], reason="fixture exact"
        )
        stale_plan = self._plan(proposal)
        record_review(
            self.store,
            proposal["proposal_id"],
            "rejected",
            reviewer="reviewer-c",
            reason="withdrawn after plan compilation",
        )

        blocked, code = execute_plan(
            self.store,
            self.root,
            self.manifest,
            self.scope,
            stale_plan["plan_id"],
        )
        self.assertEqual(code, 2)
        self.assertEqual(blocked["status"], "blocked")
        self.assertIn("review predicate", blocked["reason"])
        self.assertEqual(
            self.store.rebuild()["current"]["authorizations"][
                authorization["authorization_id"]
            ]["remaining"],
            1,
        )
        self.assertFalse(
            (self.root / "submissions" / "executions" / stale_plan["plan_id"]).exists()
        )

        record_review(
            self.store,
            proposal["proposal_id"],
            "approved",
            reviewer="reviewer-d",
            reason="new independent review",
        )
        still_stale, code = execute_plan(
            self.store,
            self.root,
            self.manifest,
            self.scope,
            stale_plan["plan_id"],
        )
        self.assertEqual(code, 2)
        self.assertIn("review predicate", still_stale["reason"])

        fresh_plan = self._plan(proposal)
        self.assertNotEqual(
            fresh_plan["predicates"]["review_event_id"],
            stale_plan["predicates"]["review_event_id"],
        )
        completed, code = execute_plan(
            self.store,
            self.root,
            self.manifest,
            self.scope,
            fresh_plan["plan_id"],
        )
        self.assertEqual(code, 0)
        self.assertEqual(completed["status"], "completed")

    def test_unknown_truth_is_indeterminate_and_not_auto_queue_eligible(self):
        proposal = self._proposal("FIXTURE{unknown}")
        grant_allowance(
            self.store, self.manifest, "flag", 2, reason="fixture allowance"
        )

        adapter = mock.Mock()
        adapter.preflight_action.return_value = {"ok": True}
        adapter.execute_action.return_value = {
            "verdict": {
                "verdict": "unknown",
                "scorer_truth": "unknown",
                "transport_truth": "unknown",
                "reason": "opaque response",
            },
            "response_path": "",
        }
        with mock.patch("rookery.portable.execution.get_adapter", return_value=adapter):
            result, code = execute_plan(
                self.store,
                self.root,
                self.manifest,
                self.scope,
                self._plan(proposal)["plan_id"],
            )
        self.assertEqual(code, 2)
        self.assertEqual(result["status"], "indeterminate")
        self.assertEqual(result["retry"]["terminal_state"], "indeterminate")
        queued = {
            item["proposal_id"]
            for item in build_queue(self.store, self.manifest)["items"]
        }
        self.assertNotIn(proposal["proposal_id"], queued)
        with self.assertRaisesRegex(ValueError, "identical candidate"):
            create_proposal(
                self.store,
                self.manifest,
                objective_id="101",
                action_kind="flag",
                exact_value="FIXTURE{unknown}",
                source="analysis/scoring-integrity/retry.md",
                rationale="same candidate without lineage",
            )

    def test_identical_rejected_candidate_requires_matching_retry_lineage(self):
        proposal, rejected = self._reject()
        self.assertNotEqual(
            rejected["retry"]["fingerprint"],
            proposal["candidate_identity_sha256"],
        )
        with self.assertRaisesRegex(ValueError, "identical candidate"):
            create_proposal(
                self.store,
                self.manifest,
                objective_id="101",
                action_kind="flag",
                exact_value="FIXTURE{rejected}",
                source="analysis/scoring-integrity/retry.md",
                rationale="same candidate without lineage",
            )
        retry = create_proposal(
            self.store,
            self.manifest,
            objective_id="101",
            action_kind="flag",
            exact_value="FIXTURE{rejected}",
            source="analysis/scoring-integrity/retry.md",
            rationale="same candidate with new discriminating evidence",
            parent_rejection_fingerprint=rejected["retry"]["fingerprint"],
            discriminator="new verifier evidence distinguishes the route",
            challenge_id="101",
            source_handoff_id="handoff-scoring-retry-fixture",
            actor="solver-c",
        )
        self.assertEqual(
            retry["candidate_identity_sha256"], proposal["candidate_identity_sha256"]
        )
        self.assertEqual(retry["challenge_id"], "101")
        self.assertEqual(
            retry["source_handoff_id"], "handoff-scoring-retry-fixture"
        )
        record_review(
            self.store,
            retry["proposal_id"],
            "approved",
            reviewer="reviewer-d",
            reason="new independent retry review",
        )
        grant_exact(self.store, retry["proposal_id"], reason="retry exact")
        retry_plan = self._plan(retry)
        self.assertEqual(retry_plan["proposal_id"], retry["proposal_id"])

    def test_materially_changed_value_remains_admissible_after_rejection(self):
        proposal, _ = self._reject()
        changed = create_proposal(
            self.store,
            self.manifest,
            objective_id="101",
            action_kind="flag",
            exact_value="FIXTURE{materially-changed}",
            source="analysis/scoring-integrity/changed.md",
            rationale="different candidate value",
        )
        self.assertNotEqual(
            changed["candidate_identity_sha256"], proposal["candidate_identity_sha256"]
        )

    def test_consumed_planned_authorization_does_not_drift_to_later_grant(self):
        proposal = self._proposal("FIXTURE{rejected}")
        first = grant_allowance(self.store, self.manifest, "flag", 1, reason="first")
        second = grant_allowance(self.store, self.manifest, "flag", 1, reason="second")
        first_plan = self._plan(proposal)
        stale_plan = self._plan(proposal)
        self.assertEqual(
            first_plan["predicates"]["authorization_id"], first["authorization_id"]
        )
        self.assertEqual(
            stale_plan["predicates"]["authorization_id"], first["authorization_id"]
        )
        consume_authorization(self.store, first, plan_id="other-plan")

        blocked, code = execute_plan(
            self.store,
            self.root,
            self.manifest,
            self.scope,
            stale_plan["plan_id"],
        )
        self.assertEqual(code, 2)
        self.assertEqual(blocked["status"], "blocked")
        self.assertIn("authorization predicate", blocked["reason"])
        current = self.store.rebuild()["current"]["authorizations"]
        self.assertEqual(current[second["authorization_id"]]["remaining"], 1)
        fresh_plan = self._plan(proposal)
        self.assertEqual(
            fresh_plan["predicates"]["authorization_id"], second["authorization_id"]
        )

    def test_concurrent_duplicate_admission_creates_exactly_one_proposal(self):
        barrier = threading.Barrier(3)
        successes = []
        failures = []

        def admit():
            local_store = open_test_event_store(self.root)
            barrier.wait()
            try:
                successes.append(
                    create_proposal(
                        local_store,
                        self.manifest,
                        objective_id="101",
                        action_kind="flag",
                        exact_value="FIXTURE{racing}",
                        source="analysis/scoring-integrity/race.md",
                        rationale="simultaneous duplicate admission",
                    )
                )
            except ValueError as exc:
                failures.append(str(exc))

        threads = [threading.Thread(target=admit) for _ in range(2)]
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join(timeout=10)
            self.assertFalse(thread.is_alive())
        self.assertEqual(len(successes), 1)
        self.assertEqual(len(failures), 1)
        self.assertIn("duplicate candidate", failures[0])
        self.assertEqual(len(self.store.events("proposal.created")), 1)

    def test_accepted_candidate_cannot_be_proposed_again(self):
        proposal = self._proposal("FIXTURE{accepted}")
        grant_exact(self.store, proposal["proposal_id"], reason="fixture exact")
        result, code = execute_plan(
            self.store,
            self.root,
            self.manifest,
            self.scope,
            self._plan(proposal)["plan_id"],
        )
        self.assertEqual(code, 0)
        self.assertEqual(result["status"], "completed")
        with self.assertRaisesRegex(ValueError, "duplicate candidate"):
            create_proposal(
                self.store,
                self.manifest,
                objective_id="101",
                action_kind="flag",
                exact_value="FIXTURE{accepted}",
                source="analysis/scoring-integrity/duplicate.md",
                rationale="duplicate accepted candidate",
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
