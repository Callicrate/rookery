from __future__ import annotations

import importlib.util
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from importlib.machinery import SourceFileLoader
from pathlib import Path
from unittest import mock

from tests.rookery.support import ROOKERY_ROOT, copy_non_deployed_rookery

LIB = ROOKERY_ROOT / "lib"
if str(LIB) not in sys.path:
    sys.path.insert(0, str(LIB))

# ruff: noqa: E402
from rookery.portable.adapters import BoundedCommandResult


def load_harvest(root: Path):
    loader = SourceFileLoader(
        f"agent_harvest_{id(root)}", str(root / "bin" / "agent-harvest")
    )
    spec = importlib.util.spec_from_loader(loader.name, loader)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.root = root
    return module


def report_text(
    *,
    status: str = "technical_negative",
    source_handoff: str = "none",
    source_report_sha256: str = "none",
) -> str:
    return "\n".join(
        (
            "# Worker report",
            "",
            "## Handoff",
            f"Status: {status}",
            f"Source handoff: {source_handoff}",
            f"Source report SHA-256: {source_report_sha256}",
            "Observed result: The bounded route produced the recorded negative.",
            "Route key: fixture-route",
            "Proof gap: One independent route remains untested.",
            "Discriminating test: Compare the alternate representation once.",
            "Next step or return trigger: Queue the alternate bounded route.",
            'Evidence paths: ["analysis/lane/artifact.txt"]',
            'Command/artifact paths: ["analysis/lane/commands.txt"]',
            "Blocker: none",
            "Cleanup/jobs: no background jobs",
            "",
            "## Evidence",
            "The exact evidence remains in the declared private path.",
            "",
            "## Commands",
            "The bounded command record is listed above.",
            "",
        )
    )


class AgentHarvestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="rookery-agent-harvest-")
        self.root = Path(self.temporary.name)
        copy_non_deployed_rookery(self.root)
        self.report = self.root / "analysis" / "lane" / "REPORT.md"
        self.report.parent.mkdir(parents=True)
        (self.report.parent / "artifact.txt").write_text("fixture evidence\n", encoding="utf-8")
        (self.report.parent / "commands.txt").write_text("fixture command\n", encoding="utf-8")
        self.module = load_harvest(self.root)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def bounded(environment, *, stdout: bytes) -> BoundedCommandResult:
        return BoundedCommandResult(
            0,
            stdout,
            b"",
            "exited",
            environment.metadata()["environment"],
        )

    def registration(self, *, event_wide: bool = False) -> dict[str, object]:
        return {
            "agent-a": {
                "agent_id": "agent-a",
                "agent_attempt_id": "attempt-a",
                "objective_id": "objective-a",
                "challenge_id": "" if event_wide else "challenge-a",
                "event_wide": event_wide,
                "report_path": "analysis/lane/REPORT.md",
                "source_handoff_id": "",
                "status": "running",
            }
        }

    def run_harvest(self, side_effect) -> tuple[int, dict[str, object], mock.Mock]:
        launched = mock.Mock(side_effect=side_effect)
        stdout = io.StringIO()
        with (
            mock.patch.object(self.module, "run_bounded_argv", launched),
            mock.patch.object(sys, "argv", ["agent-harvest"]),
            redirect_stdout(stdout),
        ):
            code = self.module.main()
        return code, json.loads(stdout.getvalue()), launched

    def test_registered_complete_report_integrates_with_derived_identity(self) -> None:
        self.report.write_text(report_text(), encoding="utf-8")
        query = json.dumps(self.registration()).encode("utf-8")
        handoff = json.dumps(
            {
                "report_path": "analysis/lane/REPORT.md",
                "agent_id": "agent-a",
                "agent_attempt_id": "attempt-a",
                "objective_id": "objective-a",
                "challenge_id": "challenge-a",
                "structured": True,
                "handoff_id": "handoff_123",
            }
        ).encode("utf-8")

        def command(argv, *, env, **_kwargs):
            return self.bounded(env, stdout=query if argv[-2:] == ["agent", "list"] else handoff)

        code, output, launched = self.run_harvest(command)
        self.assertEqual(code, 0)
        self.assertEqual(output["status"], "ok")
        self.assertEqual(output["integrated"][0]["path"], "analysis/lane/REPORT.md")
        integrate = launched.call_args_list[1].args[0]
        self.assertIn("--agent-id", integrate)
        self.assertIn("agent-a", integrate)
        self.assertIn("--agent-attempt-id", integrate)
        self.assertIn("attempt-a", integrate)
        self.assertIn("--objective-id", integrate)
        self.assertIn("objective-a", integrate)
        self.assertIn("--challenge-id", integrate)
        self.assertIn("challenge-a", integrate)
        self.assertNotIn("--event-wide", integrate)

    def test_bare_report_is_debt_and_never_spawns_a_child(self) -> None:
        self.report.write_text("# Incomplete\n", encoding="utf-8")
        query = json.dumps(self.registration()).encode("utf-8")
        code, output, launched = self.run_harvest(
            lambda _argv, *, env, **_kwargs: self.bounded(env, stdout=query)
        )
        self.assertEqual(code, 1)
        self.assertEqual(output["status"], "needs_harvest")
        self.assertEqual(output["debt"][0]["reason"], "handoff_contract_invalid")
        self.assertEqual(launched.call_count, 1)

    def test_ambiguous_or_inactive_registration_is_debt_before_integration(self) -> None:
        self.report.write_text(report_text(), encoding="utf-8")
        registrations = self.registration()
        registrations["agent-b"] = {
            **registrations["agent-a"],
            "agent_id": "agent-b",
            "agent_attempt_id": "attempt-b",
        }
        query = json.dumps(registrations).encode("utf-8")

        def command(_argv, *, env, **_kwargs):
            return self.bounded(env, stdout=query)

        code, output, launched = self.run_harvest(command)
        self.assertEqual(code, 1)
        self.assertEqual(output["debt"][0]["reason"], "registration_ambiguous")
        self.assertEqual(launched.call_count, 1)

    def test_zero_exit_without_matching_handoff_is_not_success(self) -> None:
        self.report.write_text(report_text(), encoding="utf-8")
        query = json.dumps(self.registration()).encode("utf-8")

        def command(argv, *, env, **_kwargs):
            return self.bounded(env, stdout=query if argv[-2:] == ["agent", "list"] else b"{}")

        code, output, _ = self.run_harvest(command)
        self.assertEqual(code, 1)
        self.assertEqual(output["status"], "needs_harvest")
        self.assertEqual(output["debt"][0]["reason"], "integration_unverified")

    def test_rerun_before_close_is_classified_as_already_integrated(self) -> None:
        self.report.write_text(report_text(), encoding="utf-8")
        query = json.dumps(self.registration()).encode("utf-8")
        idempotent = json.dumps(
            {
                "report_path": "analysis/lane/REPORT.md",
                "agent_id": "agent-a",
                "agent_attempt_id": "attempt-a",
                "objective_id": "objective-a",
                "challenge_id": "challenge-a",
                "structured": True,
                "handoff_id": "handoff_123",
                "idempotent": True,
            }
        ).encode("utf-8")

        def command(argv, *, env, **_kwargs):
            return self.bounded(env, stdout=query if argv[-2:] == ["agent", "list"] else idempotent)

        code, output, launched = self.run_harvest(command)
        self.assertEqual(code, 0)
        self.assertEqual(output["status"], "ok")
        self.assertEqual(output["integrated"][0]["status"], "already_integrated")
        self.assertEqual(launched.call_count, 2)

    def test_successor_report_uses_the_exact_source_report_digest(self) -> None:
        source_hash = "a" * 64
        self.report.write_text(
            report_text(
                source_handoff="handoff_previous",
                source_report_sha256=source_hash,
            ),
            encoding="utf-8",
        )
        registration = self.registration()
        registration["agent-a"] = {
            **registration["agent-a"],
            "source_handoff_id": "handoff_previous",
        }
        query = json.dumps(registration).encode("utf-8")
        handoff = json.dumps(
            {
                "report_path": "analysis/lane/REPORT.md",
                "agent_id": "agent-a",
                "agent_attempt_id": "attempt-a",
                "objective_id": "objective-a",
                "challenge_id": "challenge-a",
                "structured": True,
                "handoff_id": "handoff_successor",
            }
        ).encode("utf-8")

        def command(argv, *, env, **_kwargs):
            return self.bounded(env, stdout=query if argv[-2:] == ["agent", "list"] else handoff)

        code, output, _ = self.run_harvest(command)
        self.assertEqual(code, 0)
        self.assertEqual(output["integrated"][0]["status"], "integrated")

    def test_closed_historical_reports_are_ignored_by_default(self) -> None:
        self.report.write_text("# Closed historical report\n", encoding="utf-8")
        closed = self.registration()
        closed["agent-a"] = {**closed["agent-a"], "status": "closed"}
        query = json.dumps(closed).encode("utf-8")

        code, output, launched = self.run_harvest(
            lambda _argv, *, env, **_kwargs: self.bounded(env, stdout=query)
        )
        self.assertEqual(code, 0)
        self.assertEqual(output["status"], "ok")
        self.assertEqual(output["count"], 0)
        self.assertEqual(output["debt"], [])
        self.assertEqual(launched.call_count, 1)

    def test_active_missing_report_remains_explicit_harvest_debt(self) -> None:
        query = json.dumps(self.registration()).encode("utf-8")
        code, output, launched = self.run_harvest(
            lambda _argv, *, env, **_kwargs: self.bounded(env, stdout=query)
        )
        self.assertEqual(code, 1)
        self.assertEqual(output["status"], "needs_harvest")
        self.assertEqual(output["debt"][0]["path"], "analysis/lane/REPORT.md")
        self.assertEqual(output["debt"][0]["reason"], "handoff_contract_invalid")
        self.assertEqual(launched.call_count, 1)

    def test_generate_prints_contract_without_accessing_reports_or_platform(self) -> None:
        stdout = io.StringIO()
        with (
            mock.patch.object(self.module, "run_bounded_argv") as launched,
            mock.patch.object(sys, "argv", ["agent-harvest", "--generate"]),
            redirect_stdout(stdout),
        ):
            self.assertEqual(self.module.main(), 0)
        output = json.loads(stdout.getvalue())
        self.assertEqual(output["status"], "guide")
        self.assertIn("Discriminating test", output["handoff_labels"])
        launched.assert_not_called()


if __name__ == "__main__":  # pragma: no cover
    unittest.main(verbosity=2)
