from __future__ import annotations

# ruff: noqa: E402

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tests.rookery.env_fixtures import configure_event_environment
from tests.rookery.support import (
    ROOKERY_ROOT,
    copy_non_deployed_rookery,
    install_test_launch_binding,
    open_test_event_store,
)

LIB = ROOKERY_ROOT / "lib"
if str(LIB) not in sys.path:
    sys.path.insert(0, str(LIB))
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

from rookery.portable.util import canonical_json, load_json


class EvidenceManifestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        copy_non_deployed_rookery(self.root)
        configure_event_environment(self.root, "manual")
        install_test_launch_binding(self.root)
        self.environment = {
            **os.environ,
            "PYTHONPATH": str(self.root / "lib"),
            "PYTHONDONTWRITEBYTECODE": "1",
        }

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_manifest(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(self.root / "bin/evidence-manifest"), "--require-complete"],
            cwd=self.root,
            env=self.environment,
            text=True,
            capture_output=True,
            timeout=30,
        )

    def test_manifest_hashes_files_and_fails_closed_on_missing_references(self) -> None:
        evidence = self.root / "evidence"
        evidence.mkdir()
        (evidence / "present.txt").write_text("present\n", encoding="utf-8")
        store = open_test_event_store(self.root)
        store.append(
            "execution.planned",
            {
                "plan_id": "plan-fixture",
                "proposal_id": "proposal-fixture",
                "evidence_paths": [
                    "evidence/present.txt",
                    "analysis/missing/REPORT.md",
                    "../outside",
                ],
            },
            actor="fixture",
        )
        store.append(
            "execution.completed",
            {
                "plan_id": "plan-fixture",
                "proposal_id": "proposal-fixture",
                "response_path": "submissions/response.json",
                "evidence_root": "submissions/executions/plan-fixture",
                "verdict": {"verdict": "accepted"},
            },
            actor="fixture",
        )
        store.rebuild()

        incomplete = self.run_manifest()
        manifest = load_json(evidence / "latest-manifest.json", {})

        self.assertEqual(incomplete.returncode, 2, incomplete.stderr)
        self.assertFalse(manifest["complete"])
        self.assertEqual(manifest["schema_version"], "3")
        self.assertEqual(manifest["reference_counts"]["present_file"], 1)
        self.assertEqual(manifest["reference_counts"]["missing"], 3)
        self.assertEqual(manifest["reference_counts"]["rejected"], 1)
        self.assertEqual(manifest["required_reference_counts"]["empty"], 0)
        self.assertEqual(manifest["required_reference_counts"]["missing"], 3)
        self.assertEqual(manifest["required_reference_counts"]["rejected"], 1)
        present = next(
            row for row in manifest["files"] if row["path"] == "evidence/present.txt"
        )
        self.assertEqual(len(present["sha256"]), 64)
        self.assertNotIn("evidence/latest-manifest.json", {
            row["path"] for row in manifest["files"]
        })

        (self.root / "analysis/missing").mkdir(parents=True)
        (self.root / "analysis/missing/REPORT.md").write_text("report\n", encoding="utf-8")
        (self.root / "submissions/executions/plan-fixture").mkdir(parents=True)
        (self.root / "submissions/response.json").write_text("{}\n", encoding="utf-8")
        complete = self.run_manifest()
        updated = json.loads((evidence / "latest-manifest.json").read_text(encoding="utf-8"))

        self.assertEqual(complete.returncode, 2)
        self.assertEqual(updated["reference_counts"].get("missing", 0), 0)
        self.assertEqual(updated["reference_counts"]["rejected"], 1)
        self.assertFalse(updated["complete"])

    def test_empty_required_references_fail_require_complete(self) -> None:
        evidence = self.root / "evidence"
        evidence.mkdir()
        store = open_test_event_store(self.root)
        store.append(
            "execution.planned",
            {
                "plan_id": "plan-empty",
                "proposal_id": "proposal-empty",
                "evidence_paths": [],
            },
            actor="fixture",
        )
        store.append(
            "execution.completed",
            {"plan_id": "plan-empty", "proposal_id": "proposal-empty"},
            actor="fixture",
        )
        store.rebuild()

        result = self.run_manifest()
        summary = json.loads(result.stdout)
        manifest = load_json(evidence / "latest-manifest.json", {})

        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertFalse(manifest["complete"])
        self.assertEqual(manifest["reference_counts"]["empty"], 3)
        self.assertEqual(manifest["required_reference_count"], 3)
        self.assertEqual(manifest["required_reference_counts"]["empty"], 3)
        self.assertEqual(summary["required_reference_counts"]["empty"], 3)
        self.assertTrue(all(row["required"] for row in manifest["references"]))
        self.assertEqual(
            [row["kind"] for row in manifest["references"]],
            ["plan_evidence", "response", "execution_evidence"],
        )

    def test_no_submit_response_is_not_a_required_manifest_reference(self) -> None:
        evidence = self.root / "evidence"
        evidence.mkdir()
        (evidence / "proof.txt").write_text("retained proof\n", encoding="utf-8")
        store = open_test_event_store(self.root)
        store.append(
            "execution.planned",
            {
                "plan_id": "plan-no-submit",
                "proposal_id": "proposal-no-submit",
                "semantic_action": "no_submit_evidence",
                "evidence_paths": ["evidence/proof.txt"],
            },
            actor="fixture",
        )
        store.append(
            "execution.completed",
            {
                "plan_id": "plan-no-submit",
                "proposal_id": "proposal-no-submit",
                "response_path": "",
                "evidence_root": "evidence/proof.txt",
            },
            actor="fixture",
        )
        store.rebuild()

        result = self.run_manifest()
        manifest = load_json(evidence / "latest-manifest.json", {})

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(manifest["complete"])
        self.assertEqual(manifest["required_reference_count"], 2)
        self.assertEqual(manifest["required_reference_counts"]["present_file"], 2)
        self.assertNotIn("response", [row["kind"] for row in manifest["references"]])

    def test_value_only_no_submit_omits_empty_terminal_evidence(self) -> None:
        evidence = self.root / "evidence"
        evidence.mkdir()
        (evidence / "source.md").write_text("source evidence\n", encoding="utf-8")
        plan_path = self.root / "state" / "execution_plans" / "plan-value-only.json"
        plan_path.parent.mkdir(parents=True)
        plan = {
            "plan_id": "plan-value-only",
            "proposal_id": "proposal-value-only",
            "semantic_action": "no_submit_evidence",
            "envelope": {"artifact_reference": ""},
            "evidence_paths": ["evidence/source.md"],
        }
        plan["plan_sha256"] = hashlib.sha256(
            canonical_json(plan).encode("utf-8")
        ).hexdigest()
        plan_path.write_text(canonical_json(plan), encoding="utf-8")
        store = open_test_event_store(self.root)
        store.append(
            "execution.planned",
            {
                "plan_path": "state/execution_plans/plan-value-only.json",
                **plan,
            },
            actor="fixture",
        )
        store.append(
            "execution.completed",
            {
                "plan_id": "plan-value-only",
                "proposal_id": "proposal-value-only",
                "response_path": "",
                "evidence_root": "",
            },
            actor="fixture",
        )
        store.rebuild()

        result = self.run_manifest()
        manifest = load_json(evidence / "latest-manifest.json", {})

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(manifest["complete"])
        self.assertEqual(manifest["required_reference_count"], 2)
        self.assertEqual(
            [row["kind"] for row in manifest["references"]],
            ["plan_evidence", "execution_evidence"],
        )

        plan_path.write_text("{}\n", encoding="utf-8")
        substituted = self.run_manifest()
        substituted_manifest = load_json(evidence / "latest-manifest.json", {})

        self.assertEqual(substituted.returncode, 2, substituted.stderr)
        self.assertFalse(substituted_manifest["complete"])
        execution_evidence = next(
            row
            for row in substituted_manifest["references"]
            if row["kind"] == "execution_evidence"
        )
        self.assertEqual(execution_evidence["status"], "rejected")

    def test_rejected_terminal_references_are_required(self) -> None:
        evidence = self.root / "evidence"
        evidence.mkdir()
        (evidence / "present.txt").write_text("present\n", encoding="utf-8")
        store = open_test_event_store(self.root)
        store.append(
            "execution.planned",
            {
                "plan_id": "plan-rejected",
                "proposal_id": "proposal-rejected",
                "evidence_paths": ["evidence/present.txt"],
            },
            actor="fixture",
        )
        store.append(
            "execution.rejected",
            {"plan_id": "plan-rejected", "proposal_id": "proposal-rejected"},
            actor="fixture",
        )
        store.rebuild()

        result = self.run_manifest()
        manifest = load_json(evidence / "latest-manifest.json", {})
        terminal = [
            row for row in manifest["references"] if row["kind"] != "plan_evidence"
        ]

        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(manifest["required_reference_counts"]["present_file"], 1)
        self.assertEqual(manifest["required_reference_counts"]["empty"], 2)
        self.assertTrue(all(row["required"] for row in terminal))
        self.assertTrue(all(row["status"] == "empty" for row in terminal))

    def test_optional_terminal_references_do_not_gate_completion(self) -> None:
        evidence = self.root / "evidence"
        evidence.mkdir()
        (evidence / "present.txt").write_text("present\n", encoding="utf-8")
        store = open_test_event_store(self.root)
        store.append(
            "execution.planned",
            {
                "plan_id": "plan-optional",
                "proposal_id": "proposal-optional",
                "evidence_paths": ["evidence/present.txt"],
            },
            actor="fixture",
        )
        store.append(
            "execution.blocked",
            {
                "plan_id": "plan-optional",
                "response_path": "analysis/blocked-response.json",
                "evidence_root": "evidence",
            },
            actor="fixture",
        )
        store.append(
            "execution.failed",
            {"plan_id": "plan-optional"},
            actor="fixture",
        )
        store.rebuild()

        result = self.run_manifest()
        manifest = load_json(evidence / "latest-manifest.json", {})
        optional = [row for row in manifest["references"] if not row["required"]]

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(manifest["complete"])
        self.assertEqual(manifest["required_reference_counts"]["present_file"], 1)
        self.assertEqual(manifest["optional_reference_counts"]["empty"], 2)
        self.assertEqual(manifest["optional_reference_counts"]["missing"], 1)
        self.assertEqual(manifest["optional_reference_counts"]["present_directory"], 1)
        self.assertTrue(all(not row["required"] for row in optional))
        self.assertEqual(
            {row["status"] for row in optional},
            {"empty", "missing", "present_directory"},
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
