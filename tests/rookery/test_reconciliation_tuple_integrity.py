from __future__ import annotations

# ruff: noqa: E402

import json
import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from tests.rookery.support import ROOKERY_ROOT, install_solver_ready_challenge

LIB = ROOKERY_ROOT / "lib"
if str(LIB) not in sys.path:
    sys.path.insert(0, str(LIB))
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

from rookery.portable.queue import build_queue
from rookery.portable.control import stop
from rookery.portable.execution import compile_plan
from rookery.portable.reconciliation import import_response
from rookery.portable.scoring import (
    claim_plan_authority,
    create_proposal,
    grant_exact,
    record_review,
)
from rookery.portable.util import atomic_write_json, sha256_bytes
from rookery.verdict_parser import (
    ContainedEvidenceError,
    read_contained_evidence,
    read_contained_json,
)
from tests.rookery.test_acceptance_campaign import context, make_workspace


class ReconciliationTupleIntegrityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = make_workspace("fixture")
        self.root = Path(self.temporary_directory.name)
        self.manifest, self.scope, self.store, _ = context(self.root, "fixture")
        install_solver_ready_challenge(self.root, self.store)

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def _proposal(
        self,
        *,
        candidate: str = "FIXTURE{tuple}",
        action_kind: str = "flag",
        artifact_reference: str = "",
        attempt_scope: dict[str, str] | None = None,
    ) -> dict:
        proposal = create_proposal(
            self.store,
            self.manifest,
            objective_id="101",
            action_kind=action_kind,
            exact_value=candidate if action_kind == "flag" else "",
            artifact_reference=artifact_reference,
            attempt_scope=attempt_scope if attempt_scope is not None else {},
            source="analysis/reconciliation/REPORT.md",
            rationale="tuple-integrity fixture",
            actor="solver-a",
        )
        record_review(
            self.store,
            proposal["proposal_id"],
            "approved",
            reviewer="reviewer-b",
            reason="tuple-integrity fixture review",
        )
        return proposal

    def _claim(self, proposal: dict) -> dict:
        if proposal["action_kind"] != "no_submit_evidence":
            grant_exact(
                self.store, proposal["proposal_id"], reason="tuple-import fixture"
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

    def _paths(self, name: str) -> tuple[Path, Path]:
        directory = self.root / "submissions" / "external" / name
        directory.mkdir(parents=True)
        return directory / "request.json", directory / "response.json"

    @staticmethod
    def _request_for(proposal: dict) -> dict:
        payload = {
            "proposal_id": proposal["proposal_id"],
            "objective_id": proposal["objective_id"],
            "action_kind": proposal["action_kind"],
            "adapter_id": proposal["adapter_id"],
            "attempt_scope": proposal["attempt_scope"],
        }
        if proposal["exact_value"]:
            payload["candidate"] = proposal["exact_value"]
        else:
            payload["artifact_sha256"] = sha256_bytes(
                proposal["artifact_reference"].encode("utf-8")
            )
        return payload

    def test_exact_tuple_import_is_atomic_and_idempotent(self) -> None:
        proposal = self._proposal()
        plan = self._claim(proposal)
        request, response = self._paths("normal")
        atomic_write_json(request, self._request_for(proposal))
        atomic_write_json(response, {"http_status": 200, "data": {"correct": True}})

        first = import_response(self.store, self.root, response)
        second = import_response(self.store, self.root, response)

        self.assertEqual(first["status"], "completed")
        self.assertEqual(first["import_status"], "reconciled")
        self.assertEqual(second["import_status"], "already-recorded")
        self.assertEqual(len(self.store.events("execution.completed")), 1)
        self.assertEqual(len(self.store.events("challenge.upsert")), 1)
        terminal = self.store.events("execution.completed")[0]["payload"]
        self.assertEqual(terminal["proposal_id"], proposal["proposal_id"])
        self.assertEqual(terminal["plan_id"], plan["plan_id"])
        self.assertEqual(terminal["evidence_provenance"]["response"]["bytes"], response.stat().st_size)
        self.assertTrue(
            terminal["response_path"].startswith("evidence/imports/sha256/")
        )
        retained_response = self.root / terminal["response_path"]
        self.assertEqual(retained_response.read_bytes(), response.read_bytes())
        self.assertEqual(
            terminal["evidence_provenance"]["response"]["sha256"],
            sha256_bytes(response.read_bytes()),
        )
        self.assertNotIn(str(self.root), json.dumps(terminal))
        self.assertNotIn("matched_value", terminal["verdict"])

    def test_artifact_digest_can_link_a_non_value_proposal(self) -> None:
        proposal = self._proposal(
            action_kind="no_submit_evidence",
            artifact_reference="evidence/tuple-proof.bin",
        )
        self._claim(proposal)
        request, response = self._paths("artifact")
        atomic_write_json(request, self._request_for(proposal))
        atomic_write_json(response, {"data": {"accepted": True}})

        imported = import_response(self.store, self.root, response)

        self.assertEqual(imported["status"], "completed")
        self.assertEqual(imported["proposal_id"], proposal["proposal_id"])
        self.assertEqual(imported["exact_value"], "")

    def test_mismatch_and_ambiguous_tuple_are_observations_not_terminals(self) -> None:
        proposal = self._proposal()
        mismatch_request, mismatch_response = self._paths("mismatch")
        mismatched = self._request_for(proposal)
        mismatched["candidate"] = "FIXTURE{other}"
        atomic_write_json(mismatch_request, mismatched)
        atomic_write_json(mismatch_response, {"data": {"correct": True}})

        mismatch = import_response(self.store, self.root, mismatch_response)
        self.assertEqual(mismatch["status"], "observed")
        self.assertIn("conflicts", mismatch["reason"])
        self.assertEqual(len(self.store.events("execution.completed")), 0)
        self.assertFalse(
            self.store.rebuild()["current"]["challenges"].get("101", {}).get("solved")
        )

        clone = {**proposal, "proposal_id": "prop_ambiguous_tuple"}
        self.store.append(
            "proposal.created",
            clone,
            actor="fixture",
            event_id="proposal-ambiguous-tuple",
        )
        ambiguous_request, ambiguous_response = self._paths("ambiguous")
        tuple_without_identifier = self._request_for(proposal)
        tuple_without_identifier.pop("proposal_id")
        atomic_write_json(ambiguous_request, tuple_without_identifier)
        atomic_write_json(ambiguous_response, {"data": {"correct": True}})

        ambiguous = import_response(self.store, self.root, ambiguous_response)
        self.assertEqual(ambiguous["status"], "observed")
        self.assertIn("ambiguous", ambiguous["reason"])
        self.assertEqual(len(self.store.events("execution.completed")), 0)

    def test_unlinked_accepted_response_cannot_change_challenge_or_queue(self) -> None:
        request, response = self._paths("unlinked")
        atomic_write_json(
            request,
            {"objective_id": "101", "candidate": "FIXTURE{unlinked}"},
        )
        atomic_write_json(response, {"data": {"correct": True}})

        observed = import_response(self.store, self.root, response)

        self.assertEqual(observed["status"], "observed")
        self.assertEqual(len(self.store.events("platform.observed")), 1)
        self.assertEqual(len(self.store.events("execution.completed")), 0)
        challenge = self.store.rebuild()["current"]["challenges"].get("101", {})
        self.assertFalse(challenge.get("solved", False))
        self.assertEqual(build_queue(self.store, self.manifest)["items"], [])
        observation = self.store.events("platform.observed")[0]["payload"]
        self.assertNotIn("FIXTURE{unlinked}", json.dumps(observation))
        self.assertNotIn(str(self.root), json.dumps(observation))

    def test_outside_request_link_and_mid_read_swap_are_rejected(self) -> None:
        proposal = self._proposal()
        request, response = self._paths("unsafe")
        outside = Path(self.temporary_directory.name) / "outside-request.json"
        atomic_write_json(outside, self._request_for(proposal))
        request.symlink_to(outside)
        atomic_write_json(response, {"data": {"correct": True}})

        with self.assertRaises(ContainedEvidenceError):
            import_response(self.store, self.root, response)

        special = self.root / "submissions" / "external" / "special" / "response.json"
        special.parent.mkdir(parents=True)
        os.mkfifo(special)
        with self.assertRaises(ContainedEvidenceError):
            import_response(self.store, self.root, special)

        stable = self.root / "submissions" / "external" / "swap" / "response.json"
        stable.parent.mkdir(parents=True)
        stable.write_bytes(b'{"data":{"correct":true}}')
        replacement = stable.with_name("replacement.json")
        replacement.write_bytes(b'{"data":{"correct":false}}')
        original_read = os.read
        swapped = False

        def swapping_read(descriptor: int, maximum: int) -> bytes:
            nonlocal swapped
            block = original_read(descriptor, maximum)
            if not swapped:
                swapped = True
                os.replace(replacement, stable)
            return block

        with mock.patch("rookery.verdict_parser.os.read", side_effect=swapping_read):
            with self.assertRaises(ContainedEvidenceError):
                read_contained_evidence(self.root, stable)

        swap_request, swap_response = self._paths("swap-request")
        atomic_write_json(swap_request, self._request_for(proposal))
        atomic_write_json(swap_response, {"data": {"correct": True}})
        replacement_request = swap_request.with_name("replacement-request.json")
        atomic_write_json(replacement_request, {"proposal_id": "untrusted"})
        request_inode = swap_request.stat().st_ino
        swapped_request = False

        def swapping_request_read(descriptor: int, maximum: int) -> bytes:
            nonlocal swapped_request
            block = original_read(descriptor, maximum)
            if not swapped_request and os.fstat(descriptor).st_ino == request_inode:
                swapped_request = True
                os.replace(replacement_request, swap_request)
            return block

        with mock.patch(
            "rookery.verdict_parser.os.read", side_effect=swapping_request_read
        ):
            with self.assertRaises(ContainedEvidenceError):
                import_response(self.store, self.root, swap_response)

    def test_oversized_artifact_fails_before_verdict_parse(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            response = root / "response.json"
            response.write_bytes(b"{" + b"x" * 128 + b"}")
            with self.assertRaisesRegex(ContainedEvidenceError, "byte limit"):
                read_contained_evidence(root, response, max_bytes=64)

    def test_metadata_depth_and_item_limits_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            deep = root / "deep.json"
            deep.write_text("[" * 33 + "0" + "]" * 33, encoding="utf-8")
            with self.assertRaisesRegex(ContainedEvidenceError, "depth limit"):
                read_contained_json(root, deep)

            many = root / "many.json"
            many.write_text("[" + ",".join("0" for _ in range(8_193)) + "]")
            with self.assertRaisesRegex(ContainedEvidenceError, "item limit"):
                read_contained_json(root, many)

    def test_same_inode_overwrite_truncate_and_growth_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            target = root / "response.json"
            original_read = os.read

            def exercise(replacement: bytes, *, truncate: bool = False) -> None:
                target.write_bytes(b'{"status":"good"}')
                changed = False

                def mutate_after_read(descriptor: int, maximum: int) -> bytes:
                    nonlocal changed
                    data = original_read(descriptor, maximum)
                    if not changed:
                        changed = True
                        with target.open("r+b", buffering=0) as handle:
                            if truncate:
                                handle.truncate(0)
                            else:
                                handle.seek(0)
                                handle.write(replacement)
                            os.fsync(handle.fileno())
                    return data

                with mock.patch(
                    "rookery.verdict_parser.os.read", side_effect=mutate_after_read
                ):
                    with self.assertRaisesRegex(ContainedEvidenceError, "changed|size"):
                        read_contained_evidence(root, target)

            # `nope` is the same byte length as `good`, preserving inode and size.
            exercise(b'{"status":"nope"}')
            exercise(b"", truncate=True)
            exercise(b'{"status":"good"}x')

    def test_retained_evidence_collision_and_tamper_fail_closed(self) -> None:
        proposal = self._proposal()
        self._claim(proposal)
        request, response = self._paths("retention")
        atomic_write_json(request, self._request_for(proposal))
        atomic_write_json(response, {"data": {"correct": True}})
        digest = sha256_bytes(response.read_bytes())
        collision = self.root / "evidence" / "imports" / "sha256" / digest
        collision.parent.mkdir(parents=True)
        collision.write_bytes(b"different retained bytes")

        with self.assertRaisesRegex(ContainedEvidenceError, "collision"):
            import_response(self.store, self.root, response)
        self.assertEqual(self.store.events("execution.completed"), [])
        self.assertEqual(self.store.events("challenge.upsert"), [])

        collision.unlink()
        collision.write_bytes(response.read_bytes())
        collision.chmod(0o644)
        with self.assertRaisesRegex(ContainedEvidenceError, "collision"):
            import_response(self.store, self.root, response)
        collision.unlink()
        imported = import_response(self.store, self.root, response)
        retained = self.root / imported["response_path"]
        retained.write_bytes(b"tampered retained bytes")
        with self.assertRaisesRegex(ContainedEvidenceError, "changed|provenance"):
            import_response(self.store, self.root, response)
        self.assertEqual(len(self.store.events("execution.completed")), 1)

    def test_distinct_terminal_artifacts_cannot_compete_for_one_proposal(self) -> None:
        for first_correct in (True, False):
            with self.subTest(first_correct=first_correct):
                install_solver_ready_challenge(self.root, self.store)
                proposal = self._proposal(
                    candidate=f"FIXTURE{{sequential-{first_correct}}}"
                )
                self._claim(proposal)
                first_request, first_response = self._paths(
                    f"sequential-{first_correct}-first"
                )
                atomic_write_json(first_request, self._request_for(proposal))
                atomic_write_json(
                    first_response, {"data": {"correct": first_correct}}
                )
                second_request, second_response = self._paths(
                    f"sequential-{first_correct}-second"
                )
                atomic_write_json(second_request, self._request_for(proposal))
                atomic_write_json(
                    second_response, {"data": {"correct": not first_correct}}
                )

                first = import_response(self.store, self.root, first_response)
                second = import_response(self.store, self.root, second_response)

                self.assertEqual(
                    first["status"], "completed" if first_correct else "rejected"
                )
                self.assertEqual(second["status"], "observed")
                terminals = [
                    event
                    for event in self.store.events()
                    if event["event_type"]
                    in {"execution.completed", "execution.rejected"}
                    and event["payload"].get("proposal_id") == proposal["proposal_id"]
                ]
                self.assertEqual(len(terminals), 1)

    def test_concurrent_distinct_artifacts_have_one_terminal_winner(self) -> None:
        proposal = self._proposal(candidate="FIXTURE{concurrent-terminal}")
        self._claim(proposal)
        accepted_request, accepted_response = self._paths("concurrent-accepted")
        rejected_request, rejected_response = self._paths("concurrent-rejected")
        atomic_write_json(accepted_request, self._request_for(proposal))
        atomic_write_json(rejected_request, self._request_for(proposal))
        atomic_write_json(accepted_response, {"data": {"correct": True}})
        atomic_write_json(rejected_response, {"data": {"correct": False}})
        barrier = threading.Barrier(3)
        results: list[dict] = []

        def reconcile(path: Path) -> None:
            local_store = type(self.store)(self.root)
            barrier.wait(timeout=10)
            results.append(import_response(local_store, self.root, path))

        workers = [
            threading.Thread(target=reconcile, args=(accepted_response,)),
            threading.Thread(target=reconcile, args=(rejected_response,)),
        ]
        for worker in workers:
            worker.start()
        barrier.wait(timeout=10)
        for worker in workers:
            worker.join(timeout=20)
            self.assertFalse(worker.is_alive())

        self.assertEqual(len(results), 2)
        self.assertEqual(sum(row["status"] == "observed" for row in results), 1)
        self.assertEqual(
            sum(row["status"] in {"completed", "rejected"} for row in results), 1
        )
        terminals = [
            event
            for event in self.store.events()
            if event["event_type"] in {"execution.completed", "execution.rejected"}
            and event["payload"].get("proposal_id") == proposal["proposal_id"]
        ]
        self.assertEqual(len(terminals), 1)

    def test_terminal_import_requires_authorized_durable_execution_claim(self) -> None:
        cases = ("bare", "review", "authorization", "plan")
        for case in cases:
            with self.subTest(case=case):
                if case == "bare":
                    install_solver_ready_challenge(
                        self.root, self.store, f"bare-{case}"
                    )
                    proposal = create_proposal(
                        self.store,
                        self.manifest,
                        objective_id=f"bare-{case}",
                        action_kind="flag",
                        exact_value=f"FIXTURE{{{case}}}",
                        source="analysis/reconciliation/REPORT.md",
                        rationale="missing authority fixture",
                        actor="solver-a",
                    )
                else:
                    proposal = self._proposal(
                        candidate=f"FIXTURE{{missing-{case}}}"
                    )
                if case in {"authorization", "plan"}:
                    grant_exact(
                        self.store,
                        proposal["proposal_id"],
                        reason="missing claim fixture",
                    )
                if case == "plan":
                    compile_plan(
                        self.store,
                        self.root,
                        self.manifest,
                        self.scope,
                        proposal["proposal_id"],
                    )
                request, response = self._paths(f"missing-{case}")
                atomic_write_json(request, self._request_for(proposal))
                atomic_write_json(response, {"data": {"correct": True}})

                observed = import_response(self.store, self.root, response)

                self.assertEqual(observed["status"], "observed")
                self.assertEqual(
                    [
                        event
                        for event in self.store.events()
                        if event["event_type"] == "execution.completed"
                        and event["payload"].get("proposal_id")
                        == proposal["proposal_id"]
                    ],
                    [],
                )

    def test_stop_requires_pre_stop_claim_but_allows_claimed_closeout(self) -> None:
        unclaimed = self._proposal(candidate="FIXTURE{stopped-unclaimed}")
        unclaimed_request, unclaimed_response = self._paths("stopped-unclaimed")
        atomic_write_json(unclaimed_request, self._request_for(unclaimed))
        atomic_write_json(unclaimed_response, {"data": {"correct": True}})
        stop(self.store, self.root, reason="stop reconciliation fixture", wait_seconds=0)
        queue_before = build_queue(self.store, self.manifest)["items"]
        blocked = import_response(self.store, self.root, unclaimed_response)
        self.assertEqual(blocked["status"], "observed")
        self.assertEqual(self.store.events("execution.completed"), [])
        self.assertEqual(self.store.events("challenge.upsert"), [])
        self.assertEqual(build_queue(self.store, self.manifest)["items"], queue_before)

        # Use a fresh workspace because the stopped generation must not resume
        # implicitly while proving a pre-stop claim may still close out.
        temporary_directory = make_workspace("fixture")
        try:
            root = Path(temporary_directory.name)
            manifest, scope, store, _ = context(root, "fixture")
            install_solver_ready_challenge(root, store)
            proposal = create_proposal(
                store,
                manifest,
                objective_id="101",
                action_kind="flag",
                exact_value="FIXTURE{stopped-claimed}",
                attempt_scope={},
                source="analysis/reconciliation/REPORT.md",
                rationale="pre-stop claim fixture",
                actor="solver-a",
            )
            record_review(
                store,
                proposal["proposal_id"],
                "approved",
                reviewer="reviewer-b",
                reason="pre-stop claim fixture",
            )
            grant_exact(store, proposal["proposal_id"], reason="pre-stop claim")
            plan = compile_plan(store, root, manifest, scope, proposal["proposal_id"])
            claim_plan_authority(store, plan, loaded_plan=plan, actor="fixture")
            directory = root / "submissions" / "external" / "stopped-claimed"
            directory.mkdir(parents=True)
            atomic_write_json(directory / "request.json", self._request_for(proposal))
            atomic_write_json(directory / "response.json", {"data": {"correct": True}})
            stop(store, root, reason="close out claimed response", wait_seconds=0)

            closed = import_response(store, root, directory / "response.json")

            self.assertEqual(closed["status"], "completed")
            self.assertEqual(closed["plan_id"], plan["plan_id"])
            self.assertEqual(len(store.events("execution.completed")), 1)
        finally:
            temporary_directory.cleanup()


if __name__ == "__main__":
    unittest.main(verbosity=2)
