from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from tests.rookery.support import ROOKERY_ROOT, install_solver_ready_challenge

LIB = ROOKERY_ROOT / "lib"
if str(LIB) not in sys.path:
    sys.path.insert(0, str(LIB))
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

from rookery.portable import cli, writeups  # noqa: E402
from rookery.portable.execution import compile_plan, execute_plan  # noqa: E402
from rookery.portable.owned_paths import objective_storage_component  # noqa: E402
from rookery.portable.reconciliation import (  # noqa: E402
    record_task_completion,
    task_completion_audit,
)
from rookery.portable.scoring import (  # noqa: E402
    claim_plan_authority,
    create_proposal,
    grant_allowance,
    grant_exact,
    record_review,
)
from rookery.portable.store import EventStore  # noqa: E402
from rookery.portable.util import iso_now  # noqa: E402
from rookery.portable.writeups import check_writeups, create_capsule, create_writeup  # noqa: E402
from tests.rookery.test_acceptance_campaign import make_workspace  # noqa: E402


class ObjectiveCapsuleLifecycleTests(unittest.TestCase):
    @staticmethod
    def _manifest(*, evidence_only: bool = False) -> dict[str, object]:
        return {
            "adapter": {"id": "fixture"},
            "scoring": {
                "completion_mode": "evidence_only" if evidence_only else "scorer_truth",
                "action_kinds": ["no_submit_evidence"] if evidence_only else ["flag"],
            },
            "writeups": {"mode": "closeout", "full_required_at_closeout": True},
        }

    def _accepted_execution(
        self,
        store: EventStore,
        root: Path,
        objective_id: str,
        *,
        attempt_scope: dict[str, str] | None = None,
        coordinator_allowance: bool = False,
    ) -> tuple[dict[str, object], str]:
        manifest = self._manifest()
        if coordinator_allowance:
            manifest["authorization"] = {
                "automation_permitted_action_kinds": ["flag"]
            }
        install_solver_ready_challenge(root, store, objective_id)
        if attempt_scope:
            store.append(
                "challenge.upsert",
                {"id": objective_id, "attempt_scope": attempt_scope},
                actor="fixture",
            )
        proposal = create_proposal(
            store,
            manifest,
            objective_id=objective_id,
            action_kind="flag",
            exact_value="FIXTURE{capsule}",
            attempt_scope=attempt_scope,
            source="analysis/capsule/REPORT.md",
            rationale="canonical capsule lifecycle fixture",
            actor="solver-a",
        )
        record_review(
            store,
            str(proposal["proposal_id"]),
            "approved",
            reviewer="reviewer-b",
            reason="independent fixture review",
        )
        if coordinator_allowance:
            grant_allowance(
                store,
                manifest,
                "flag",
                1,
                reason="fixture configured automation allowance",
                actor="coordinator",
            )
        else:
            grant_exact(
                store, str(proposal["proposal_id"]), reason="fixture exact authority"
            )
        plan = compile_plan(
            store,
            root,
            manifest,
            {"generation": 0},
            str(proposal["proposal_id"]),
        )
        claim_plan_authority(store, plan, loaded_plan=plan, actor="fixture")
        evidence_root = f"submissions/executions/{plan['plan_id']}"
        store.append(
            "execution.completed",
            {
                "plan_id": plan["plan_id"],
                "proposal_id": proposal["proposal_id"],
                "objective_id": objective_id,
                "action_kind": "flag",
                "status": "completed",
                "verdict": {
                    "verdict": "accepted",
                    "scorer_truth": "accepted",
                    "transport_truth": "accepted",
                },
                "response_path": f"{evidence_root}/response.json",
                "evidence_root": evidence_root,
                "completed_at": iso_now(),
            },
            actor="fixture",
        )
        return plan, evidence_root

    @staticmethod
    def _legacy_capsule_payload(objective_id: str) -> dict[str, object]:
        canonical = {
            "objective_id": objective_id,
            "action_reference": "legacy:free-form",
            "scorer_evidence": "submissions/legacy/response.json",
            "reproduction_path": "analysis/legacy/REPORT.md",
            "material_provenance": ["analysis/legacy/REPORT.md"],
            "dead_path_checkpoint": "legacy",
        }
        digest = writeups._capsule_hash(canonical)
        return {
            "capsule_id": writeups._capsule_id(digest),
            **canonical,
            "canonical_sha256": digest,
            "created_at": iso_now(),
        }

    def _capsule_kwargs(
        self, objective_id: str, plan: dict[str, object], scorer_evidence: str
    ) -> dict[str, object]:
        return {
            "objective_id": objective_id,
            "action_reference": plan["plan_id"],
            "scorer_evidence": scorer_evidence,
            "reproduction_path": "exploit/solve.py",
            "material_provenance": ["analysis/report.md"],
            "dead_path_checkpoint": "none",
        }

    def _assert_ingest_capsule_writeup_closeout(self, raw_id: str) -> None:
        workspace = make_workspace("manual")
        root = Path(workspace.name)
        adapter = mock.Mock()
        adapter.detail.return_value = {"id": raw_id, "files": []}
        try:
            with (
                mock.patch("rookery.portable.cli.workspace_root", return_value=root),
                mock.patch("rookery.portable.cli.get_adapter", return_value=adapter),
            ):
                self.assertEqual(
                    cli.cmd_platform(
                        SimpleNamespace(
                            platform_action="ingest",
                            challenge_id=raw_id,
                            no_files=True,
                            quiet=True,
                        )
                    ),
                    0,
                )

            component = objective_storage_component(raw_id)
            self.assertTrue((root / "platform" / "challenges" / component).is_dir())
            store = EventStore(root)
            plan, evidence_root = self._accepted_execution(store, root, raw_id)
            payload = create_capsule(
                store, root, **self._capsule_kwargs(raw_id, plan, evidence_root)
            )
            create_writeup(root, raw_id, "Fixture")

            self.assertEqual(payload["objective_id"], raw_id)
            self.assertEqual(
                json.loads(
                    (root / "writeups" / component / "CAPSULE.json").read_text(
                        encoding="utf-8"
                    )
                )["objective_id"],
                raw_id,
            )
            self.assertTrue(
                check_writeups(
                    store,
                    root,
                    {"writeups": {"mode": "immediate"}},
                    closeout=True,
                )["ok"]
            )
        finally:
            workspace.cleanup()

    def test_safe_and_unsafe_lifecycles_share_opaque_storage_mapping(self) -> None:
        for raw_id in ("safe-101", "../external Challenge/01"):
            with self.subTest(raw_id=raw_id):
                self._assert_ingest_capsule_writeup_closeout(raw_id)

    def test_coordinator_allowance_supports_canonical_completion_capsule(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            store = EventStore(root)
            plan, evidence_root = self._accepted_execution(
                store,
                root,
                "fixture-coordinator-allowance",
                coordinator_allowance=True,
            )
            capsule = create_capsule(
                store,
                root,
                **self._capsule_kwargs(
                    "fixture-coordinator-allowance", plan, evidence_root
                ),
            )
            self.assertEqual(
                capsule["objective_id"], "fixture-coordinator-allowance"
            )

    def test_capsule_retries_converge_after_each_persisted_stage(self) -> None:
        for stage in ("publish", "append", "rebuild"):
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                store = EventStore(root)
                plan, evidence_root = self._accepted_execution(store, root, "fixture-101")
                kwargs = self._capsule_kwargs("fixture-101", plan, evidence_root)
                original = {
                    "publish": writeups.atomic_write_json,
                    "append": store.append,
                    "rebuild": store.rebuild,
                }[stage]

                if stage == "publish":
                    def fail_after_publish(*args, **kwargs):
                        original(*args, **kwargs)
                        raise RuntimeError("after file publish")

                    patch = mock.patch.object(
                        writeups, "atomic_write_json", side_effect=fail_after_publish
                    )
                elif stage == "append":
                    def fail_after_append(*args, **kwargs):
                        original(*args, **kwargs)
                        raise RuntimeError("after event append")

                    patch = mock.patch.object(store, "append", side_effect=fail_after_append)
                else:
                    def fail_after_rebuild(*args, **kwargs):
                        original(*args, **kwargs)
                        raise RuntimeError("after rebuild")

                    patch = mock.patch.object(store, "rebuild", side_effect=fail_after_rebuild)

                expected_error = {
                    "publish": "after file publish",
                    "append": "after event append",
                    "rebuild": "after rebuild",
                }[stage]
                with patch, self.assertRaisesRegex(RuntimeError, expected_error):
                    create_capsule(store, root, **kwargs)

                recovered = create_capsule(store, root, **kwargs)
                component = objective_storage_component(str(kwargs["objective_id"]))
                capsule_files = list((root / "writeups" / component).glob("CAPSULE.json"))
                events = store.events("solve.capsule")

                self.assertEqual(len(capsule_files), 1)
                self.assertEqual(len(events), 1)
                self.assertEqual(events[0]["payload"]["capsule_id"], recovered["capsule_id"])
                self.assertEqual(events[0]["payload"]["canonical_sha256"], recovered["canonical_sha256"])

    def test_capsule_rejects_incomplete_and_tampered_preseeded_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            store = EventStore(root)
            plan, evidence_root = self._accepted_execution(store, root, "fixture-101")
            kwargs = self._capsule_kwargs("fixture-101", plan, evidence_root)
            capsule_path = (
                root
                / "writeups"
                / objective_storage_component("fixture-101")
                / "CAPSULE.json"
            )
            capsule_path.parent.mkdir(parents=True)
            capsule_path.write_text("{}", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "invalid schema"):
                create_capsule(store, root, **kwargs)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            store = EventStore(root)
            plan, evidence_root = self._accepted_execution(store, root, "fixture-101")
            kwargs = self._capsule_kwargs("fixture-101", plan, evidence_root)
            create_capsule(store, root, **kwargs)
            capsule_path = (
                root
                / "writeups"
                / objective_storage_component("fixture-101")
                / "CAPSULE.json"
            )
            tampered = json.loads(capsule_path.read_text(encoding="utf-8"))
            tampered["canonical_sha256"] = "0" * 64
            capsule_path.write_text(json.dumps(tampered), encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "canonical_sha256"):
                create_capsule(store, root, **kwargs)

    def test_bare_completed_event_cannot_create_a_solve_capsule(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            store = EventStore(root)
            store.append(
                "execution.completed",
                {
                    "plan_id": "plan_unbound",
                    "proposal_id": "prop_unbound",
                    "objective_id": "fixture-101",
                    "action_kind": "flag",
                    "status": "completed",
                    "verdict": {"verdict": "accepted", "scorer_truth": "accepted"},
                    "evidence_root": "submissions/unbound",
                    "completed_at": iso_now(),
                },
                actor="fixture",
            )
            with self.assertRaisesRegex(ValueError, "canonical execution truth"):
                create_capsule(
                    store,
                    root,
                    **{
                        "objective_id": "fixture-101",
                        "action_reference": "plan_unbound",
                        "scorer_evidence": "submissions/unbound",
                        "reproduction_path": "exploit/solve.py",
                        "material_provenance": ["analysis/report.md"],
                        "dead_path_checkpoint": "none",
                    },
                )

    def test_evidence_capsule_is_not_a_solve_capsule(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            store = EventStore(root)
            manifest = self._manifest(evidence_only=True)
            proposal = create_proposal(
                store,
                manifest,
                objective_id="fixture-evidence",
                action_kind="no_submit_evidence",
                artifact_reference="analysis/evidence/REPORT.md",
                source="analysis/capsule/REPORT.md",
                rationale="canonical evidence capsule fixture",
                actor="solver-a",
            )
            record_review(
                store,
                str(proposal["proposal_id"]),
                "approved",
                reviewer="reviewer-b",
                reason="independent evidence review",
            )
            plan = compile_plan(
                store,
                root,
                manifest,
                {"generation": 0},
                str(proposal["proposal_id"]),
            )
            result, exit_code = execute_plan(
                store, root, manifest, {"generation": 0}, str(plan["plan_id"])
            )
            self.assertEqual(exit_code, 0)
            self.assertEqual(result["verdict"]["scorer_truth"], "non_scoring")
            payload = create_capsule(
                store,
                root,
                **self._capsule_kwargs(
                    "fixture-evidence",
                    plan,
                    "analysis/evidence/REPORT.md",
                ),
            )
            component = objective_storage_component("fixture-evidence")
            self.assertIn("evidence_capsule_id", payload)
            self.assertTrue(
                (root / "writeups" / component / "EVIDENCE_CAPSULE.json").is_file()
            )
            self.assertFalse(store.events("solve.capsule"))
            self.assertEqual(len(store.events("evidence.capsule")), 1)
            with self.assertRaisesRegex(ValueError, "accepted scorer truth"):
                record_task_completion(store, plan_id=str(plan["plan_id"]))
            self.assertFalse(store.events("task.completed"))
            checks = check_writeups(store, root, manifest, closeout=True)
            self.assertEqual(checks["completed"], [])
            self.assertEqual(checks["evidence_completed"], ["fixture-evidence"])
            self.assertTrue(checks["ok"])

    def test_file_only_legacy_capsule_fails_closeout_without_rewriting_it(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            store = EventStore(root)
            objective_id = "legacy-file-only"
            capsule_path = (
                root
                / "writeups"
                / objective_storage_component(objective_id)
                / "CAPSULE.json"
            )
            capsule_path.parent.mkdir(parents=True)
            payload = self._legacy_capsule_payload(objective_id)
            capsule_path.write_text(json.dumps(payload), encoding="utf-8")

            result = check_writeups(
                store, root, {"writeups": {"mode": "closeout"}}, closeout=True
            )

            self.assertFalse(result["ok"])
            self.assertEqual(
                result["unverified_capsules"],
                [{"objective_id": objective_id, "status": "unverified_legacy"}],
            )
            self.assertEqual(
                json.loads(capsule_path.read_text(encoding="utf-8")), payload
            )

    def test_valid_canonical_capsule_and_file_only_legacy_are_distinct(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            store = EventStore(root)
            manifest = self._manifest()
            plan, evidence_root = self._accepted_execution(
                store, root, "canonical-objective"
            )
            create_capsule(
                store,
                root,
                **self._capsule_kwargs("canonical-objective", plan, evidence_root),
            )
            create_writeup(root, "canonical-objective", "Canonical")
            legacy_objective = "legacy-beside-canonical"
            legacy_path = (
                root
                / "writeups"
                / objective_storage_component(legacy_objective)
                / "CAPSULE.json"
            )
            legacy_path.parent.mkdir(parents=True)
            legacy_path.write_text(
                json.dumps(self._legacy_capsule_payload(legacy_objective)),
                encoding="utf-8",
            )

            result = check_writeups(store, root, manifest, closeout=True)

            self.assertFalse(result["ok"])
            self.assertEqual(result["completed"], ["canonical-objective"])
            self.assertEqual(
                result["unverified_capsules"],
                [{"objective_id": legacy_objective, "status": "unverified_legacy"}],
            )

    def test_completion_record_derives_accepted_plan_fields(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            store = EventStore(root)
            plan, evidence_root = self._accepted_execution(
                store,
                root,
                "completion-objective",
                attempt_scope={"attempt_id": "fixture-attempt"},
            )

            completion = record_task_completion(
                store, plan_id=str(plan["plan_id"])
            )

            self.assertEqual(completion["plan_id"], plan["plan_id"])
            self.assertEqual(completion["objective_id"], "completion-objective")
            self.assertEqual(
                completion["attempt_scope"], {"attempt_id": "fixture-attempt"}
            )
            self.assertEqual(
                completion["evidence_path"], f"{evidence_root}/response.json"
            )
            self.assertTrue(task_completion_audit(store)["ok"])

    def test_later_review_does_not_invalidate_completed_plan(self) -> None:
        for verdict in ("approved", "rejected"):
            with self.subTest(verdict=verdict), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                store = EventStore(root)
                plan, _evidence_root = self._accepted_execution(
                    store,
                    root,
                    f"completion-later-{verdict}-review",
                    attempt_scope={"attempt_id": "fixture-attempt"},
                )
                completion = record_task_completion(
                    store, plan_id=str(plan["plan_id"])
                )

                record_review(
                    store,
                    str(plan["proposal_id"]),
                    verdict,
                    reviewer="reviewer-c",
                    reason="later independent review",
                )

                audit = task_completion_audit(store)
                self.assertTrue(audit["ok"])
                self.assertEqual(audit["completion_records"], 1)
                self.assertEqual(completion["plan_id"], str(plan["plan_id"]))

    def test_completion_record_and_audit_reject_orphan_or_mismatched_truth(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            store = EventStore(root)
            with self.assertRaisesRegex(ValueError, "accepted scorer truth"):
                record_task_completion(store, plan_id="plan_orphan")

            plan, _evidence_root = self._accepted_execution(
                store,
                root,
                "completion-mismatch",
                attempt_scope={"attempt_id": "canonical-attempt"},
            )
            store.append(
                "task.completed",
                {
                    "completion_id": "completion_forged",
                    "plan_id": plan["plan_id"],
                    "objective_id": "completion-mismatch",
                    "attempt_scope": {"attempt_id": "wrong-attempt"},
                    "evidence_path": "submissions/wrong/response.json",
                    "completed_at": iso_now(),
                },
                actor="fixture",
                event_id="completion_forged",
            )

            audit = task_completion_audit(store)

            self.assertFalse(audit["ok"])
            self.assertEqual(len(audit["invalid_completion_records"]), 1)
            self.assertEqual(
                audit["invalid_completion_records"][0]["reason"],
                "completion does not match canonical plan evidence",
            )

    def test_completion_audit_rejects_a_raw_orphan_event(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            store = EventStore(root)
            store.append(
                "task.completed",
                {
                    "completion_id": "completion_raw_orphan",
                    "plan_id": "plan_raw_orphan",
                    "objective_id": "raw-orphan",
                    "attempt_scope": {},
                    "evidence_path": "submissions/raw/response.json",
                    "completed_at": iso_now(),
                },
                actor="fixture",
                event_id="completion_raw_orphan",
            )

            audit = task_completion_audit(store)

            self.assertFalse(audit["ok"])
            self.assertEqual(
                audit["invalid_completion_records"],
                [
                    {
                        "completion_id": "completion_raw_orphan",
                        "reason": "completion plan lacks accepted scorer truth",
                    }
                ],
            )

    def test_completion_record_cli_accepts_only_a_plan_id(self) -> None:
        parser = cli.build_parser()
        args = parser.parse_args(["completion", "record", "plan_fixture"])
        self.assertEqual(args.plan_id, "plan_fixture")
        with mock.patch("sys.stderr"):
            with self.assertRaises(SystemExit):
                parser.parse_args(
                    [
                        "completion",
                        "record",
                        "plan_fixture",
                        "--evidence-path",
                        "submissions/forged/response.json",
                    ]
                )


if __name__ == "__main__":
    unittest.main(verbosity=2)
