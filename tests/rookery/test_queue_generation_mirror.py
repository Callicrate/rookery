from __future__ import annotations

# ruff: noqa: E402

import argparse
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

from tests.rookery.support import ROOKERY_ROOT, install_solver_ready_challenge

LIB = ROOKERY_ROOT / "lib"
if str(LIB) not in sys.path:
    sys.path.insert(0, str(LIB))
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

from rookery.portable import cli
from rookery.portable.control import resume, stop
from rookery.portable.policy import set_policy
from rookery.portable.queue import build_queue, persist_schedules
from rookery.portable.scoring import create_proposal, grant_exact, record_review
from tests.rookery.test_acceptance_campaign import context, make_workspace


class QueueGenerationMirrorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.workspace = make_workspace("fixture")
        self.root = Path(self.workspace.name)
        manifest, self.scope, self.store, _ = context(self.root, "fixture")
        install_solver_ready_challenge(self.root, self.store)
        self.manifest = {
            **manifest,
            "queue": {
                **manifest.get("queue", {}),
                "automation_enabled": True,
                "cadence_seconds": 0,
                "jitter_seconds": 0,
            },
        }

    def tearDown(self) -> None:
        self.workspace.cleanup()

    def _proposal_and_review(self, suffix: str) -> tuple[dict, dict]:
        proposal = create_proposal(
            self.store,
            self.manifest,
            objective_id="101",
            action_kind="flag",
            exact_value=f"FIXTURE{{queue-generation-{suffix}}}",
            source="analysis/queue-generation-mirror/REPORT.md",
            rationale="queue advisory generation regression",
            actor="solver-a",
        )
        review = record_review(
            self.store,
            proposal["proposal_id"],
            "approved",
            reviewer="reviewer-b",
            reason="independent queue generation review",
        )
        return proposal, review

    def _advance_generation(self, kind: str) -> None:
        if kind == "policy":
            set_policy(
                self.store,
                "strategy",
                "queue-generation-regression",
                source="operator",
                reason="policy drift fixture",
            )
            return
        stop(
            self.store,
            self.root,
            reason="stop drift fixture",
            wait_seconds=0,
        )
        resume(self.store, reason="resume after stop drift fixture")

    def _fresh_exact_authorization(self, proposal: dict) -> dict:
        payload = {
            "authorization_id": f"auth_current_{proposal['proposal_id']}",
            "mode": "exact",
            "proposal_id": proposal["proposal_id"],
            "action_kind": proposal["action_kind"],
            "remaining": 1,
            "reason": "current-generation regression authority",
            "stop_generation": self.store.current_stop_generation(),
            "policy_generation": int(self.store.get_meta("policy_generation", "0")),
        }
        self.store.append(
            "authorization.granted",
            payload,
            actor="operator",
            generation=payload["stop_generation"],
        )
        return payload

    def _queue_item(self, proposal: dict) -> dict:
        return next(
            item
            for item in build_queue(self.store, self.manifest)["items"]
            if item["proposal_id"] == proposal["proposal_id"]
        )

    def test_policy_drift_reports_stale_proposal_and_review(self) -> None:
        proposal, _ = self._proposal_and_review("policy")
        self._advance_generation("policy")
        self._fresh_exact_authorization(proposal)

        item = self._queue_item(proposal)

        self.assertFalse(item["eligible"])
        self.assertEqual(
            item["wait_reasons"],
            [
                "proposal belongs to a stale policy generation",
                "review belongs to a stale policy generation",
            ],
        )

    def test_stop_drift_reports_stale_proposal_and_review(self) -> None:
        proposal, _ = self._proposal_and_review("stop")
        self._advance_generation("stop")
        self._fresh_exact_authorization(proposal)

        item = self._queue_item(proposal)

        self.assertFalse(item["eligible"])
        self.assertEqual(
            item["wait_reasons"],
            [
                "proposal belongs to a stale stop generation",
                "review belongs to a stale stop generation",
            ],
        )

    def test_current_generations_remain_eligible(self) -> None:
        proposal, review = self._proposal_and_review("current")
        authorization = grant_exact(
            self.store,
            proposal["proposal_id"],
            reason="current generation exact authority",
        )

        item = self._queue_item(proposal)

        self.assertEqual(
            proposal["stop_generation"], self.store.current_stop_generation()
        )
        self.assertEqual(
            proposal["policy_generation"],
            int(self.store.get_meta("policy_generation", "0")),
        )
        self.assertEqual(review["stop_generation"], proposal["stop_generation"])
        self.assertEqual(review["policy_generation"], proposal["policy_generation"])
        self.assertTrue(authorization["authorization_id"])
        self.assertTrue(item["eligible"])
        self.assertEqual(item["wait_reasons"], [])

    def test_malformed_generation_evidence_fails_closed_with_stable_reasons(
        self,
    ) -> None:
        projection = {
            "current": {
                "stop_generation": 4,
                "policy_generation": 9,
                "stopped": False,
                "proposals": {
                    "proposal-malformed": {
                        "proposal_id": "proposal-malformed",
                        "objective_id": "101",
                        "action_kind": "flag",
                        "stop_generation": 4,
                        "policy_generation": "malformed",
                        "event_at": "2026-08-29T00:00:00Z",
                    }
                },
                "reviews": {
                    "proposal-malformed": {
                        "proposal_id": "proposal-malformed",
                        "verdict": "approved",
                        "stop_generation": None,
                        "policy_generation": 9,
                    }
                },
                "executions": {},
                "authorizations": {
                    "authorization-malformed": {
                        "authorization_id": "authorization-malformed",
                        "status": "granted",
                        "mode": "exact",
                        "proposal_id": "proposal-malformed",
                        "action_kind": "flag",
                        "remaining": "malformed",
                        "stop_generation": 4,
                        "policy_generation": 9,
                    }
                },
            },
            "queue": {"schedules": {}, "escalated": []},
        }
        store = mock.Mock()
        store.read_snapshot.return_value = {"events": [], "meta": {}}
        store.projection_from_snapshot.return_value = projection

        queue = build_queue(store, self.manifest)

        self.assertEqual(queue["eligible"], 0)
        self.assertFalse(queue["items"][0]["eligible"])
        self.assertEqual(
            queue["items"][0]["wait_reasons"],
            [
                "proposal has malformed policy_generation",
                "review is missing stop_generation",
                "no action-specific authorization",
            ],
        )

    def _assert_owned_watcher_survives_stale_item(self, kind: str) -> None:
        proposal, _ = self._proposal_and_review(f"watch-{kind}")
        persist_schedules(self.store, self.manifest)
        self._advance_generation(kind)
        self._fresh_exact_authorization(proposal)
        watcher_epoch = int(
            self.store.get_meta(
                "watcher_epoch", str(self.store.current_stop_generation())
            )
        )
        owner_token = f"queuewatch-generation-{kind}"
        job = {
            "job_id": f"watcher-generation-{kind}",
            "kind": "queue-watcher",
            "owner_token": owner_token,
            "watcher_epoch": watcher_epoch,
        }
        self.store.append("job.running", job, actor="fixture")
        args = argparse.Namespace(
            queue_action="watch",
            auto_execute=True,
            interval=1,
            once=False,
            owner_token=owner_token,
            watcher_epoch=watcher_epoch,
            diagnostic=False,
            quiet=True,
            heartbeat_seconds=300,
        )

        def retire_after_first_tick(_seconds: int) -> None:
            self.store.append("job.cancelled", job, actor="fixture")

        with (
            mock.patch.object(cli, "workspace_root", return_value=self.root),
            mock.patch.object(
                cli,
                "load_context",
                return_value=(self.manifest, self.scope, self.store, None),
            ),
            mock.patch.object(cli, "compile_plan") as compile_plan,
            mock.patch.object(cli, "execute_plan") as execute_plan,
            mock.patch("rookery.portable.execution.get_adapter") as get_adapter,
            mock.patch.object(cli.time, "sleep", side_effect=retire_after_first_tick) as sleep,
            mock.patch("builtins.print"),
        ):
            self.assertEqual(cli.cmd_queue(args), 0)

        sleep.assert_called_once_with(1)
        compile_plan.assert_not_called()
        execute_plan.assert_not_called()
        get_adapter.assert_not_called()
        self.assertFalse(self.store.events("execution.planned"))

    def test_owned_watcher_survives_policy_stale_item(self) -> None:
        self._assert_owned_watcher_survives_stale_item("policy")

    def test_owned_watcher_survives_stop_stale_item(self) -> None:
        self._assert_owned_watcher_survives_stale_item("stop")


if __name__ == "__main__":
    unittest.main(verbosity=2)
