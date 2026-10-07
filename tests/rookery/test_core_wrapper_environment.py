from __future__ import annotations

# ruff: noqa: E402

import importlib.util
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from importlib.machinery import SourceFileLoader
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from tests.rookery.support import ROOKERY_ROOT
from tests.rookery.test_preparation_and_isolation import copy_rookery

LIB = ROOKERY_ROOT / "lib"
if str(LIB) not in sys.path:
    sys.path.insert(0, str(LIB))

from rookery.portable.adapters import BoundedCommandResult

SENTINELS = {
    "DUMMY_B3A_SECRET": "must-not-reach-core-wrappers",
    "CTFD_TOKEN": "must-not-reach-adapter",
    "ROOKERY_OWNER_TOKEN": "must-not-reach-child",
}


def load_script(root: Path, name: str):
    loader = SourceFileLoader(f"{name.replace('-', '_')}_{id(root)}", str(root / "bin" / name))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if hasattr(module, "ROOT"):
        module.ROOT = root
    if hasattr(module, "root"):
        module.root = root
    return module


@unittest.skipUnless(os.name == "posix", "requires POSIX private file modes")
class CoreWrapperEnvironmentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        copy_rookery(self.root)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def assert_minimal(self, environment) -> None:
        self.assertFalse(set(SENTINELS) & set(environment.values))
        rendered = json.dumps(environment.metadata(), sort_keys=True)
        for value in SENTINELS.values():
            self.assertNotIn(value, rendered)

    def bounded(self, environment, *, stdout: bytes = b"", stderr: bytes = b""):
        return BoundedCommandResult(
            0,
            stdout,
            stderr,
            "exited",
            environment.metadata()["environment"],
        )

    def test_analysis_and_diagnostic_wrappers_use_explicit_minimal_children(self) -> None:
        with mock.patch.dict(os.environ, SENTINELS, clear=False):
            agent = load_script(self.root, "agent-harvest")
            report = self.root / "analysis" / "fixture" / "REPORT.md"
            report.parent.mkdir(parents=True)
            (report.parent / "evidence.txt").write_text("fixture evidence\n", encoding="utf-8")
            (report.parent / "commands.txt").write_text("fixture commands\n", encoding="utf-8")
            report.write_text(
                "\n".join(
                    (
                        "# Fixture report",
                        "",
                        "## Handoff",
                        "Status: technical_negative",
                        "Source handoff: none",
                        "Source report SHA-256: none",
                        "Observed result: Fixture result.",
                        "Route key: fixture-route",
                        "Proof gap: Fixture proof gap.",
                        "Discriminating test: Fixture discriminating test.",
                        "Next step or return trigger: Fixture next step.",
                        'Evidence paths: ["analysis/fixture/evidence.txt"]',
                        'Command/artifact paths: ["analysis/fixture/commands.txt"]',
                        "Blocker: none",
                        "Cleanup/jobs: no jobs",
                        "",
                        "## Evidence",
                        "Fixture evidence.",
                        "",
                        "## Commands",
                        "Fixture command record.",
                        "",
                    )
                ),
                encoding="utf-8",
            )
            with (
                mock.patch.object(agent, "run_bounded_argv") as launched,
                mock.patch.object(sys, "argv", ["agent-harvest"]),
                redirect_stdout(io.StringIO()),
            ):
                registrations = {
                    "fixture-agent": {
                        "agent_id": "fixture-agent",
                        "agent_attempt_id": "fixture-attempt",
                        "objective_id": "fixture-objective",
                        "challenge_id": "fixture-challenge",
                        "event_wide": False,
                        "report_path": "analysis/fixture/REPORT.md",
                        "source_handoff_id": "",
                        "status": "running",
                    }
                }
                handoff = {
                    "report_path": "analysis/fixture/REPORT.md",
                    "agent_id": "fixture-agent",
                    "agent_attempt_id": "fixture-attempt",
                    "objective_id": "fixture-objective",
                    "challenge_id": "fixture-challenge",
                    "structured": True,
                    "handoff_id": "handoff_fixture",
                }
                launched.side_effect = lambda argv, **kwargs: self.bounded(
                    kwargs["env"],
                    stdout=json.dumps(
                        registrations if argv[-2:] == ["agent", "list"] else handoff
                    ).encode("utf-8"),
                )
                self.assertEqual(agent.main(), 0)
            self.assert_minimal(launched.call_args.kwargs["env"])

            named = load_script(self.root, "named-tool-recon")
            named_out = self.root / "named-output"
            with (
                mock.patch.object(named, "run_bounded_argv") as launched,
                mock.patch.object(
                    sys,
                    "argv",
                    ["named-tool-recon", "fixture", "--outdir", str(named_out)],
                ),
                redirect_stdout(io.StringIO()),
            ):
                launched.side_effect = lambda *_args, **kwargs: self.bounded(kwargs["env"])
                self.assertEqual(named.main(), 0)
            self.assert_minimal(launched.call_args.kwargs["env"])
            manifest = json.loads((named_out / "manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["environment"]["policy"], "named-tool-recon")
            self.assertNotIn(SENTINELS["DUMMY_B3A_SECRET"], json.dumps(manifest))

            safe_rg = load_script(self.root, "safe-rg")
            with (
                mock.patch.object(safe_rg.shutil, "which", return_value="/usr/bin/rg"),
                mock.patch.object(safe_rg, "run_bounded_argv") as launched,
                mock.patch.object(sys, "argv", ["safe-rg", "fixture", "README.md"]),
                redirect_stdout(io.StringIO()),
            ):
                launched.side_effect = lambda *_args, **kwargs: self.bounded(kwargs["env"])
                self.assertEqual(safe_rg.main(), 0)
            self.assert_minimal(launched.call_args.kwargs["env"])
            meta = json.loads(next((self.root / "research/search_guard").glob("*/meta.json")).read_text())
            self.assertEqual(meta["environment"]["policy"], "safe-rg")

            stale = load_script(self.root, "stale-port-cleanup")
            with (
                mock.patch.object(stale.shutil, "which", return_value="/usr/bin/lsof"),
                mock.patch.object(stale, "run_bounded_argv") as launched,
                mock.patch.object(sys, "argv", ["stale-port-cleanup", "--ports", "31337"]),
                redirect_stdout(io.StringIO()),
            ):
                launched.side_effect = lambda *_args, **kwargs: self.bounded(kwargs["env"])
                self.assertEqual(stale.main(), 0)
            self.assert_minimal(launched.call_args.kwargs["env"])

            pause = load_script(self.root, "platform-heavy-pause")
            with (
                mock.patch.object(pause, "run_bounded_argv") as launched,
                mock.patch.object(sys, "argv", ["platform-heavy-pause", "pause"]),
                redirect_stdout(io.StringIO()),
            ):
                launched.side_effect = lambda *_args, **kwargs: self.bounded(kwargs["env"])
                self.assertEqual(pause.main(), 0)
            self.assert_minimal(launched.call_args.kwargs["env"])

    def test_run_ledger_forwards_names_only_before_separator(self) -> None:
        ledger = load_script(self.root, "run-ledger")
        with (
            mock.patch.dict(os.environ, SENTINELS, clear=False),
            mock.patch.object(
                ledger.subprocess,
                "run",
                return_value=SimpleNamespace(returncode=0, stdout="ok\n", stderr=""),
            ) as launched,
            mock.patch.object(
                sys,
                "argv",
                [
                    "run-ledger",
                    "fixture",
                    "--pass-env",
                    "DUMMY_REQUIRED_KEY",
                    "--env-policy",
                    "network-client",
                    "--",
                    sys.executable,
                    "-c",
                    "print('fixture')",
                ],
            ),
            redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(ledger.main(), 0)
        argv = launched.call_args.args[0]
        self.assertLess(argv.index("DUMMY_REQUIRED_KEY"), argv.index("--"))
        self.assertIn("network-client", argv[: argv.index("--")])
        environment = launched.call_args.kwargs["env"]
        self.assertFalse(set(SENTINELS) & set(environment))
        record = json.loads((self.root / "research/run-ledger.jsonl").read_text().splitlines()[-1])
        self.assertEqual(record["environment"]["policy"], "run-ledger")
        self.assertNotIn(SENTINELS["DUMMY_B3A_SECRET"], json.dumps(record))


if __name__ == "__main__":
    unittest.main(verbosity=2)
