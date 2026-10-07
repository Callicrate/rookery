from __future__ import annotations

import copy
import io
import hashlib
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
import sys
from unittest import mock

# Keep this focused module directly runnable under the release test commands.
from tests.rookery.support import ROOKERY_ROOT, render_handoff_report

LIB = ROOKERY_ROOT / "lib"
if str(LIB) not in sys.path:
    sys.path.insert(0, str(LIB))

# ruff: noqa: E402
from rookery.portable.exploration import (
    claim_ideation,
    claim_synthesis,
    open_campaign,
    record_dispatch_claim,
    record_idea_batch,
    synthesize_campaign,
)
from rookery.portable.compute import admit_compute_tick, finish_compute_idea, start_compute_idea
from rookery.portable import cli
from rookery.portable.outcomes import (
    close_current_agent_attempt,
    harvest_report,
    record_outcome,
    validate_continuation,
)
from rookery.portable.store import EventStore
from rookery.portable.util import (
    atomic_write_json,
    atomic_write_text,
    canonical_json,
    ensure_private_dir,
)


CHALLENGE_ID = "challenge_demo"
OBJECTIVE_ID = "objective_demo"
SOURCE_ATTEMPT_ID = "attempt_source"
SOURCE_HANDOFF_ID = "handoff_source"


def _agent(
    agent_id: str,
    attempt_id: str,
    report_path: str,
    *,
    source_handoff_id: str = "",
) -> dict[str, object]:
    return {
        "agent_id": agent_id,
        "agent_attempt_id": attempt_id,
        "objective_id": OBJECTIVE_ID,
        "challenge_id": CHALLENGE_ID,
        "event_wide": False,
        "source_handoff_id": source_handoff_id,
        "role": "ctf_hard_investigator",
        "report_path": report_path,
    }


def _idea(idea_id: str, route_key: str) -> dict[str, object]:
    return {
        "idea_id": idea_id,
        "route_key": route_key,
        "next_step": "Inspect the bounded local parser bytes for this route.",
        "mechanism": "local parser inspection",
        "prerequisite_evidence": "preserved artifact metadata",
        "discriminating_test": "compare exact parser branch behavior",
        "estimated_cost_seconds": 300,
        "expected_value": 1,
        "evidence_value": 1,
        "why_novel": "the route is assessed against the structured handoff",
    }


def _complete_challenge(root: Path, challenge_id: str = CHALLENGE_ID) -> dict[str, object]:
    directory = root / "captures" / challenge_id
    directory.mkdir(parents=True, exist_ok=True)
    directory.chmod(0o700)
    detail = directory / "detail.json"
    detail_bytes = json.dumps({"id": challenge_id, "files": []}, sort_keys=True).encode("utf-8")
    detail.write_bytes(detail_bytes)
    detail.chmod(0o600)
    return {
        "id": challenge_id,
        "solved": False,
        "files": [],
        "detail_path": detail.relative_to(root).as_posix(),
        "detail_sha256": hashlib.sha256(detail_bytes).hexdigest(),
        "detail_bytes": len(detail_bytes),
        "captured_files": [],
        "expected_file_count": 0,
        "captured_file_count": 0,
        "ingested_at": "2026-10-02T00:00:00Z",
        "intake_state": "complete",
        "intake_missing_material": [],
        "resources_truncated": False,
        "resources_complete": True,
    }


class ExplorationCampaignTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.store = EventStore(self.root)
        self.store.append(
            "platform.snapshot",
            {"challenges": [_complete_challenge(self.root)]},
            actor="adapter",
        )
        self.store.append(
            "agent.running",
            _agent(
                "source-worker",
                SOURCE_ATTEMPT_ID,
                "analysis/source/REPORT.md",
            ),
            actor="coordinator",
        )
        self.store.append(
            "report.harvested",
            {
                "handoff_id": SOURCE_HANDOFF_ID,
                "structured": True,
                "agent_id": "source-worker",
                "agent_attempt_id": SOURCE_ATTEMPT_ID,
                "challenge_id": CHALLENGE_ID,
                "objective_id": OBJECTIVE_ID,
                "report_path": "analysis/source/REPORT.md",
                "sha256": "a" * 64,
                "status": "technical_negative",
                "observed_result": "the first parser route is disproven",
                "route_key": "tried_route",
                "proof_gap": "the alternate parser family remains untested",
                "next_step_or_return_trigger": "try a distinct parser family",
            },
            actor="coordinator",
        )
        self.campaign = open_campaign(
            self.store,
            challenge_id=CHALLENGE_ID,
            objective_id=OBJECTIVE_ID,
            source_handoff_id=SOURCE_HANDOFF_ID,
            route_keys=["tried_route"],
            campaign_id="campaign_demo",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_open_campaign_rejects_incomplete_hidden_and_tampered_intake(self) -> None:
        cases = (
            {"intake_state": "partial"},
            {"hidden": True},
        )
        for changes in cases:
            with self.subTest(changes=changes), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                store = EventStore(root)
                row = {**_complete_challenge(root), **changes}
                store.append("platform.snapshot", {"challenges": [row]}, actor="fixture")
                with self.assertRaisesRegex(ValueError, "challenge intake is not solver-ready"):
                    open_campaign(
                        store,
                        challenge_id=CHALLENGE_ID,
                        objective_id=OBJECTIVE_ID,
                        source_handoff_id="handoff-unreached",
                        route_keys=["unreached-route"],
                    )
                self.assertEqual(store.events("exploration.campaign.opened"), [])

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            store = EventStore(root)
            row = _complete_challenge(root)
            store.append("platform.snapshot", {"challenges": [row]}, actor="fixture")
            (root / str(row["detail_path"])).write_bytes(b'{"id":"tampered"}')
            (root / str(row["detail_path"])).chmod(0o600)
            with self.assertRaisesRegex(ValueError, "challenge intake is not solver-ready"):
                open_campaign(
                    store,
                    challenge_id=CHALLENGE_ID,
                    objective_id=OBJECTIVE_ID,
                    source_handoff_id="handoff-unreached",
                    route_keys=["unreached-route"],
                )
            self.assertEqual(store.events("exploration.campaign.opened"), [])

    def _campaign_agent(self, name: str) -> tuple[str, str, str]:
        attempt_id = f"attempt_{name}"
        report_path = f"analysis/{name}/REPORT.md"
        handoff_id = f"handoff_{name}"
        self.store.append(
            "agent.running",
            _agent(
                f"worker-{name}",
                attempt_id,
                report_path,
                source_handoff_id=SOURCE_HANDOFF_ID,
            ),
            actor="coordinator",
        )
        self.store.append(
            "report.harvested",
            {
                "handoff_id": handoff_id,
                "structured": True,
                "agent_id": f"worker-{name}",
                "agent_attempt_id": attempt_id,
                "challenge_id": CHALLENGE_ID,
                "objective_id": OBJECTIVE_ID,
                "report_path": report_path,
                "sha256": "b" * 64,
                "status": "technical_negative",
                "observed_result": f"{name} bounded result",
                "route_key": f"{name}_route",
                "proof_gap": f"{name} proof gap",
                "next_step_or_return_trigger": f"{name} next step",
            },
            actor="coordinator",
        )
        return attempt_id, report_path, handoff_id

    def test_claim_rejects_forged_worker_and_binds_current_attempt(self) -> None:
        with self.assertRaisesRegex(ValueError, "active registered agent attempt"):
            claim_ideation(
                self.store,
                campaign_id="campaign_demo",
                lens="fresh",
                agent_attempt_id="forged",
            )

        attempt_id, report_path, _ = self._campaign_agent("fresh")
        claim = claim_ideation(
            self.store,
            campaign_id="campaign_demo",
            lens="fresh",
            agent_attempt_id=attempt_id,
        )
        self.assertEqual(claim["agent_attempt_id"], attempt_id)
        self.assertEqual(claim["report_path"], report_path)
        self.assertEqual(claim["source_handoff_id"], SOURCE_HANDOFF_ID)
        packet = claim["assignment_packet"]
        self.assertEqual(packet["kind"], "exploration.ideation")
        self.assertEqual(packet["source_handoff"]["report_path"], "analysis/source/REPORT.md")
        self.assertEqual(packet["source_handoff"]["sha256"], "a" * 64)
        self.assertEqual(packet["source_handoff"]["proof_gap"], "the alternate parser family remains untested")
        self.assertEqual(packet["artifact"]["path"], "analysis/fresh/IDEAS.json")
        self.assertEqual(packet["artifact"]["template"], "templates/IDEAS.json")
        self.assertEqual(packet["forbidden_actions"], ["score", "dispatch"])

    def test_ideation_requires_exactly_ten_ideas_and_campaign_source(self) -> None:
        attempt_id, report_path, handoff_id = self._campaign_agent("nine")
        claim = claim_ideation(
            self.store,
            campaign_id="campaign_demo",
            lens="fresh",
            agent_attempt_id=attempt_id,
        )
        ideas_path = self.root / claim["assignment_packet"]["artifact"]["path"]
        ensure_private_dir(ideas_path.parent)
        atomic_write_json(
            ideas_path,
            {
                "campaign_id": "campaign_demo",
                "lens": "fresh",
                "ideas": [_idea(f"nine{index}", f"nine_route_{index}") for index in range(9)],
            },
        )
        with self.assertRaisesRegex(ValueError, "exactly ten"):
            record_idea_batch(
                self.store,
                self.root,
                campaign_id="campaign_demo",
                lens="fresh",
                agent_attempt_id=attempt_id,
                handoff_id=handoff_id,
                ideas_file=ideas_path.relative_to(self.root).as_posix(),
            )
        missing_source_store = EventStore(self.root / "missing-source")
        missing_source_store.append(
            "platform.snapshot",
            {"challenges": [_complete_challenge(self.root / "missing-source")]},
            actor="adapter",
        )
        with self.assertRaisesRegex(ValueError, "exact structured handoff"):
            open_campaign(
                missing_source_store,
                challenge_id=CHALLENGE_ID,
                objective_id=OBJECTIVE_ID,
                source_handoff_id="handoff_missing",
                route_keys=["missing_source_route"],
                campaign_id="campaign_missing_source",
            )

    def test_batch_rejects_a_stale_assignment_packet_before_recording(self) -> None:
        attempt_id, report_path, handoff_id = self._campaign_agent("stale")
        claim = claim_ideation(
            self.store,
            campaign_id="campaign_demo",
            lens="fresh",
            agent_attempt_id=attempt_id,
        )
        stale_packet = copy.deepcopy(claim["assignment_packet"])
        stale_packet["source_handoff"]["handoff_id"] = "handoff_missing"
        stale_claim = dict(claim)
        stale_claim["assignment_packet"] = stale_packet
        stale_claim["assignment_packet_sha256"] = hashlib.sha256(
            canonical_json(stale_packet).encode("utf-8")
        ).hexdigest()
        self.store.append(
            "exploration.ideation.claimed",
            stale_claim,
            actor="test",
        )
        ideas_path = self.root / report_path.replace("REPORT.md", "IDEAS.json")
        ensure_private_dir(ideas_path.parent)
        atomic_write_json(
            ideas_path,
            {
                "campaign_id": "campaign_demo",
                "lens": "fresh",
                "ideas": [_idea(f"stale{index}", f"stale_route_{index}") for index in range(10)],
            },
        )
        with self.assertRaisesRegex(ValueError, "assignment packet is stale"):
            record_idea_batch(
                self.store,
                self.root,
                campaign_id="campaign_demo",
                lens="fresh",
                agent_attempt_id=attempt_id,
                handoff_id=handoff_id,
                ideas_file=ideas_path.relative_to(self.root).as_posix(),
            )

    def test_ideator_handoff_is_consumed_by_batch_then_outcome_and_close(self) -> None:
        attempt_id = "attempt_closable"
        report_path = "analysis/closable/REPORT.md"
        report = self.root / report_path
        ensure_private_dir(report.parent)
        atomic_write_text(
            self.root / "analysis/closable/evidence.txt",
            "bounded fixture evidence for the closable exploration route\n",
        )
        atomic_write_text(
            self.root / "analysis/closable/commands.txt",
            "fixture-ideation --bounded\n",
        )
        atomic_write_text(
            report,
            render_handoff_report(
                source_handoff=SOURCE_HANDOFF_ID,
                source_report_sha256="a" * 64,
                observed_result="fresh ideas were gathered without solving the lane",
                route_key="closable_route",
                proof_gap="which fresh route is most informative remains open",
                discriminating_test="Compare the next route against this negative.",
                next_step_or_return_trigger="synthesize the fresh idea batch",
                evidence_paths=("analysis/closable/evidence.txt",),
                command_artifact_paths=("analysis/closable/commands.txt",),
                cleanup_jobs="none",
                evidence_body="The preserved evidence identifies ten independent candidate routes.",
                commands_body="fixture-ideation --bounded",
            ),
        )
        self.store.append(
            "agent.running",
            _agent(
                "closable-worker",
                attempt_id,
                report_path,
                source_handoff_id=SOURCE_HANDOFF_ID,
            ),
            actor="coordinator",
        )
        handoff = harvest_report(
            self.store,
            self.root,
            report_path,
            agent_id="closable-worker",
            agent_attempt_id=attempt_id,
            challenge_id=CHALLENGE_ID,
            objective_id=OBJECTIVE_ID,
            status="technical_negative",
            observed_result="fresh ideas were gathered without solving the lane",
            route_key="closable_route",
            proof_gap="which fresh route is most informative remains open",
            next_step_or_return_trigger="synthesize the fresh idea batch",
        )
        claim_ideation(
            self.store,
            campaign_id="campaign_demo",
            lens="fresh",
            agent_attempt_id=attempt_id,
        )
        ideas_path = self.root / "analysis/closable/IDEAS.json"
        atomic_write_json(
            ideas_path,
            {
                "campaign_id": "campaign_demo",
                "lens": "fresh",
                "ideas": [_idea(f"close{index}", f"close_route_{index}") for index in range(10)],
            },
        )
        record_idea_batch(
            self.store,
            self.root,
            campaign_id="campaign_demo",
            lens="fresh",
            agent_attempt_id=attempt_id,
            handoff_id=handoff["handoff_id"],
            ideas_file="analysis/closable/IDEAS.json",
        )
        outcome = record_outcome(
            self.store,
            agent_id="closable-worker",
            agent_attempt_id=attempt_id,
            objective_id=OBJECTIVE_ID,
            challenge_id=CHALLENGE_ID,
            outcome_type="technical_negative",
            report_path=report_path,
            summary="The ideation report is complete and has a campaign continuation.",
            mechanism="closable_route",
            continuation="explore:campaign_demo",
            handoff_id=handoff["handoff_id"],
        )
        self.assertEqual(outcome["continuation_id"], "campaign_demo")
        closed = close_current_agent_attempt(
            self.store,
            agent_id="closable-worker",
            reason="campaign handoff recorded",
        )
        self.assertEqual(closed["agent_attempt_id"], attempt_id)

    def test_zero_eligible_synthesis_parks_only_after_four_exact_batches(self) -> None:
        for lens in ("fresh", "evidence", "artifact", "contrarian"):
            attempt_id, report_path, handoff_id = self._campaign_agent(lens)
            claim_ideation(
                self.store,
                campaign_id="campaign_demo",
                lens=lens,
                agent_attempt_id=attempt_id,
            )
            ideas_path = self.root / report_path.replace("REPORT.md", "IDEAS.json")
            ensure_private_dir(ideas_path.parent)
            atomic_write_json(
                ideas_path,
                {
                    "campaign_id": "campaign_demo",
                    "lens": lens,
                    "ideas": [_idea(f"{lens}{index}", "tried_route") for index in range(10)],
                },
            )
            record_idea_batch(
                self.store,
                self.root,
                campaign_id="campaign_demo",
                lens=lens,
                agent_attempt_id=attempt_id,
                handoff_id=handoff_id,
                ideas_file=ideas_path.relative_to(self.root).as_posix(),
            )
            route = validate_continuation(
                self.store.events(),
                reference="explore:campaign_demo",
                challenge_id=CHALLENGE_ID,
                objective_id=OBJECTIVE_ID,
                current_generation=0,
                handoff_id=handoff_id,
            )
            self.assertEqual(route["consumption_event_type"], "exploration.idea_batch.recorded")

        synthesis_attempt, synthesis_report, synthesis_handoff = self._campaign_agent("synthesis")
        selection_path = self.root / synthesis_report.replace("REPORT.md", "SELECTION.json")
        ensure_private_dir(selection_path.parent)
        atomic_write_json(
            selection_path,
            {
                "campaign_id": "campaign_demo",
                "selected_idea_ids": [],
                "rationale": "Every proposed route is already in the rejected index.",
                "handoff_learning": "The handoff rules out the only route family proposed.",
                "park_reason": "No novel route remains after all forty classifications.",
                "recheck_condition": "new artifact, hint, or platform behavior appears",
            },
        )
        with self.assertRaisesRegex(ValueError, "exact claimed worker"):
            synthesize_campaign(
                self.store,
                self.root,
                campaign_id="campaign_demo",
                synthesizer_attempt_id=synthesis_attempt,
                handoff_id=synthesis_handoff,
                selection_file=selection_path.relative_to(self.root).as_posix(),
            )
        claim_synthesis(
            self.store,
            campaign_id="campaign_demo",
            agent_attempt_id=synthesis_attempt,
        )
        result = synthesize_campaign(
            self.store,
            self.root,
            campaign_id="campaign_demo",
            synthesizer_attempt_id=synthesis_attempt,
            handoff_id=synthesis_handoff,
            selection_file=selection_path.relative_to(self.root).as_posix(),
        )
        self.assertEqual(result["workflow_state"], "parked")
        campaign = self.store.rebuild()["current"]["exploration_campaigns"]["campaign_demo"]
        self.assertEqual(campaign["effective_status"], "parked")
        self.assertEqual(campaign["recheck_condition"], "new artifact, hint, or platform behavior appears")

    def test_cli_claim_synthesis_returns_packet_before_selection_acceptance(self) -> None:
        for lens in ("fresh", "evidence", "artifact", "contrarian"):
            attempt_id, report_path, handoff_id = self._campaign_agent(f"cli_{lens}")
            claim_ideation(
                self.store,
                campaign_id="campaign_demo",
                lens=lens,
                agent_attempt_id=attempt_id,
            )
            ideas_path = self.root / report_path.replace("REPORT.md", "IDEAS.json")
            ensure_private_dir(ideas_path.parent)
            atomic_write_json(
                ideas_path,
                {
                    "campaign_id": "campaign_demo",
                    "lens": lens,
                    "ideas": [_idea(f"cli{lens}{index}", "tried_route") for index in range(10)],
                },
            )
            record_idea_batch(
                self.store,
                self.root,
                campaign_id="campaign_demo",
                lens=lens,
                agent_attempt_id=attempt_id,
                handoff_id=handoff_id,
                ideas_file=ideas_path.relative_to(self.root).as_posix(),
            )

        synthesis_attempt, synthesis_report, synthesis_handoff = self._campaign_agent("cli_synthesis")
        selection_path = self.root / synthesis_report.replace("REPORT.md", "SELECTION.json")
        ensure_private_dir(selection_path.parent)
        atomic_write_json(
            selection_path,
            {
                "campaign_id": "campaign_demo",
                "selected_idea_ids": [],
                "rationale": "Every candidate is in the tried route index.",
                "handoff_learning": "All four lenses agree that no novel route remains.",
                "park_reason": "No eligible route remains after the four ideation batches.",
                "recheck_condition": "new evidence or platform behavior appears",
            },
        )
        with self.assertRaisesRegex(ValueError, "exact claimed worker"):
            synthesize_campaign(
                self.store,
                self.root,
                campaign_id="campaign_demo",
                synthesizer_attempt_id=synthesis_attempt,
                handoff_id=synthesis_handoff,
                selection_file=selection_path.relative_to(self.root).as_posix(),
            )

        captured = io.StringIO()
        with (
            mock.patch.object(cli, "workspace_root", return_value=self.root),
            mock.patch.object(cli, "load_context", return_value=({}, {}, self.store, object())),
            mock.patch.object(cli, "refresh_snapshot"),
            redirect_stdout(captured),
        ):
            self.assertEqual(
                cli.main(
                    [
                        "explore",
                        "claim-synthesis",
                        "--campaign-id",
                        "campaign_demo",
                        "--agent-attempt-id",
                        synthesis_attempt,
                    ]
                ),
                0,
            )
        packet = json.loads(captured.getvalue())["assignment_packet"]
        self.assertEqual(packet["kind"], "exploration.synthesis")
        self.assertEqual(packet["worker"]["agent_attempt_id"], synthesis_attempt)
        self.assertEqual(packet["artifact"]["path"], selection_path.relative_to(self.root).as_posix())
        self.assertEqual(packet["artifact"]["template"], "templates/SELECTION.json")

        result = synthesize_campaign(
            self.store,
            self.root,
            campaign_id="campaign_demo",
            synthesizer_attempt_id=synthesis_attempt,
            handoff_id=synthesis_handoff,
            selection_file=selection_path.relative_to(self.root).as_posix(),
        )
        self.assertEqual(result["workflow_state"], "parked")

    def test_selected_native_agent_cannot_finish_before_handoff_outcome_and_close(self) -> None:
        self.store.append(
            "exploration.idea.selected",
            {
                "campaign_id": "campaign_demo",
                "challenge_id": CHALLENGE_ID,
                "objective_id": OBJECTIVE_ID,
                "idea_id": "selected_native",
                "compute_idea_id": "idea_native",
                "route_key": "new_route",
                "source_handoff_id": SOURCE_HANDOFF_ID,
                "dispatch_kind": "agent",
                "queued_stop_generation": 0,
            },
            actor="coordinator",
        )
        self.store.append(
            "compute.idea.queued",
            {
                "idea_id": "idea_native",
                "objective_id": OBJECTIVE_ID,
                "goal": "Test a selected route through a registered agent.",
                "scope": "bounded local fixture",
                "report_path": "analysis/native/REPORT.md",
                "stop_condition": "one exact negative",
                "mechanism": "bounded parser route",
                "requested_cpu_threads": 1,
                "budget_seconds": 300,
                "checkpointable": True,
                "dispatch_kind": "agent",
                "expected_value": 1.0,
                "evidence_value": 1.0,
                "dedupe_key": "new_route",
                "queued_stop_generation": 0,
                "exploration_campaign_id": "campaign_demo",
                "exploration_idea_id": "selected_native",
                "challenge_id": CHALLENGE_ID,
                "route_key": "new_route",
                "source_handoff_id": SOURCE_HANDOFF_ID,
            },
            actor="coordinator",
        )
        self.store.append(
            "compute.idea.leased",
            {
                "idea_id": "idea_native",
                "admission_id": "admission_native",
                "lease_expires_at": "2099-01-01T00:00:00Z",
            },
            actor="coordinator",
        )
        owner_attempt = "attempt_native"
        self.store.append(
            "agent.running",
            _agent(
                "native-worker",
                owner_attempt,
                "analysis/native/REPORT.md",
                source_handoff_id=SOURCE_HANDOFF_ID,
            ),
            actor="coordinator",
        )
        self.store.append(
            "compute.idea.started",
            {
                "idea_id": "idea_native",
                "admission_id": "admission_native",
                "agent_attempt_id": owner_attempt,
                "job_id": "",
            },
            actor="coordinator",
        )
        with self.assertRaisesRegex(ValueError, "exact registered owner to close"):
            finish_compute_idea(
                self.store,
                idea_id="idea_native",
                status="completed",
                summary="Unsafe premature native completion.",
                admission_id="admission_native",
                agent_attempt_id=owner_attempt,
            )

    def test_full_campaign_synthesis_lease_start_and_dispatch_uses_synthesis_handoff(self) -> None:
        ideation_claims = []
        for lens in ("fresh", "evidence", "artifact", "contrarian"):
            attempt_id, report_path, handoff_id = self._campaign_agent(f"full_{lens}")
            claim = claim_ideation(
                self.store,
                campaign_id="campaign_demo",
                lens=lens,
                agent_attempt_id=attempt_id,
            )
            ideation_claims.append(claim)
            ideas_path = self.root / report_path.replace("REPORT.md", "IDEAS.json")
            ensure_private_dir(ideas_path.parent)
            atomic_write_json(
                ideas_path,
                {
                    "campaign_id": "campaign_demo",
                    "lens": lens,
                    "ideas": [_idea(f"{lens}{index}", f"{lens}_route_{index}") for index in range(10)],
                },
            )
            record_idea_batch(
                self.store,
                self.root,
                campaign_id="campaign_demo",
                lens=lens,
                agent_attempt_id=attempt_id,
                handoff_id=handoff_id,
                ideas_file=ideas_path.relative_to(self.root).as_posix(),
            )

        self.assertEqual(
            [claim["assignment_packet"]["lens"]["id"] for claim in ideation_claims],
            ["fresh", "evidence", "artifact", "contrarian"],
        )
        self.assertTrue(
            all(
                claim["assignment_packet"]["artifact"]["path"]
                == claim["report_path"].replace("REPORT.md", "IDEAS.json")
                for claim in ideation_claims
            )
        )
        synthesis_attempt, synthesis_report, synthesis_handoff = self._campaign_agent("full_synthesis")
        synthesis_claim = claim_synthesis(
            self.store,
            campaign_id="campaign_demo",
            agent_attempt_id=synthesis_attempt,
        )
        self.assertEqual(synthesis_claim["assignment_packet"]["kind"], "exploration.synthesis")
        self.assertEqual(
            synthesis_claim["assignment_packet"]["artifact"]["path"],
            synthesis_report.replace("REPORT.md", "SELECTION.json"),
        )
        self.assertEqual(len(synthesis_claim["assignment_packet"]["ideation_inputs"]), 4)
        selection_path = self.root / synthesis_report.replace("REPORT.md", "SELECTION.json")
        ensure_private_dir(selection_path.parent)
        atomic_write_json(
            selection_path,
            {
                "campaign_id": "campaign_demo",
                "selected_idea_ids": ["fresh0"],
                "rationale": "The fresh route separates the untested parser behavior.",
                "handoff_learning": "The synthesis handoff establishes the current proof gap.",
                "park_reason": "",
                "recheck_condition": "",
            },
        )
        synthesis = synthesize_campaign(
            self.store,
            self.root,
            campaign_id="campaign_demo",
            synthesizer_attempt_id=synthesis_attempt,
            handoff_id=synthesis_handoff,
            selection_file=selection_path.relative_to(self.root).as_posix(),
        )
        compute_idea_id = synthesis["selected"][0]["compute_idea_id"]
        lease = admit_compute_tick(
            self.store,
            {
                "compute": {"interactive_reserve_units": 0, "admission_cooldown_seconds": 0},
                "concurrency": {"max_workers": 20, "max_jobs": 20},
            },
            {
                "available": True,
                "visible_cpu_count": 8,
                "window_busy_percent": [20.0, 20.0],
                "sampled_at": "2026-09-28T12:00:00Z",
            },
        )
        self.assertEqual(lease["idea"]["idea_id"], compute_idea_id)
        report_path = lease["idea"]["report_path"]
        solver_attempt = "attempt_full_solver"
        self.store.append(
            "agent.running",
            _agent(
                "full-solver",
                solver_attempt,
                report_path,
                source_handoff_id=synthesis_handoff,
            ),
            actor="coordinator",
        )
        started = start_compute_idea(
            self.store,
            idea_id=compute_idea_id,
            admission_id=lease["admission_id"],
            agent_attempt_id=solver_attempt,
        )
        self.assertEqual(started["source_handoff_id"], synthesis_handoff)
        dispatch = record_dispatch_claim(
            self.store,
            campaign_id="campaign_demo",
            idea_id="fresh0",
            compute_idea_id=compute_idea_id,
            agent_attempt_id=solver_attempt,
        )
        self.assertEqual(dispatch["source_handoff_id"], synthesis_handoff)

if __name__ == "__main__":  # pragma: no cover
    unittest.main()
