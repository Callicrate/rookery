from __future__ import annotations

import contextlib
import io
import tempfile
import tomllib
import unittest
import shutil
import sys
from pathlib import Path
from unittest import mock

SOURCE = Path(__file__).resolve().parents[2] / "rookery"
if str(SOURCE / "lib") not in sys.path:
    sys.path.insert(0, str(SOURCE / "lib"))

from rookery.portable.cli import build_parser, cmd_agent, cmd_score, render_start_prompt  # noqa: E402
from rookery.portable.manifest import ManifestResult  # noqa: E402
from rookery.portable.outcomes import (  # noqa: E402
    OUTCOME_TYPES,
    _HANDOFF_LABELS,
    _parse_structured_handoff_report,
)
from rookery.portable.registry import _render_codex_files  # noqa: E402
from tests.rookery.support import ROOKERY_ROOT  # noqa: E402


HANDOFF_LABELS = tuple(f"{label}:" for label in _HANDOFF_LABELS)
class WorkerPromptHandoffTests(unittest.TestCase):
    def test_review_cli_exposes_exact_verdict_choices(self) -> None:
        parser = build_parser()
        parsed = parser.parse_args(
            [
                "score",
                "review",
                "proposal-one",
                "approved",
                "--reviewer",
                "reviewer-one",
                "--reason",
                "independent verification",
            ]
        )
        self.assertEqual(parsed.verdict, "approved")
        with self.assertRaises(SystemExit):
            parser.parse_args(
                [
                    "score",
                    "review",
                    "proposal-one",
                    "approve",
                    "--reviewer",
                    "reviewer-one",
                    "--reason",
                    "near miss",
                ]
            )

    def test_report_template_has_exact_canonical_block_after_title(self) -> None:
        template = (ROOKERY_ROOT / "templates" / "REPORT.md").read_bytes()
        lines = template.decode("utf-8").splitlines()
        self.assertEqual(lines[0], "# Report")
        self.assertEqual(lines[2], "## Handoff")
        positions = [
            next(index for index, line in enumerate(lines) if line.startswith(label))
            for label in HANDOFF_LABELS
        ]
        self.assertEqual(positions, list(range(4, 4 + len(HANDOFF_LABELS))))
        self.assertEqual(lines[positions[0]], "Status: incomplete_evidence")
        self.assertEqual(lines[positions[1]], "Source handoff: none")
        self.assertLess(positions[-1], lines.index("## Evidence"))
        self.assertLess(lines.index("## Evidence"), lines.index("## Commands"))
        with self.assertRaisesRegex(ValueError, "requires at least one evidence path"):
            _parse_structured_handoff_report(template)
        finalized = template.replace(
            b"Evidence paths: []",
            b'Evidence paths: ["analysis/lane/evidence.txt"]',
        )
        parsed = _parse_structured_handoff_report(finalized)
        self.assertEqual(parsed["status"], "incomplete_evidence")
        self.assertEqual(parsed["source_handoff_id"], "none")
        self.assertEqual(parsed["evidence_paths"], ["analysis/lane/evidence.txt"])
        self.assertEqual(parsed["command_artifact_paths"], [])
        successor = finalized.replace(
            b"Source handoff: none",
            b"Source handoff: handoff-one",
        ).replace(
            b"Source report SHA-256: none",
            b"Source report SHA-256: " + b"a" * 64,
        )
        successor_parsed = _parse_structured_handoff_report(successor)
        self.assertEqual(successor_parsed["source_handoff_id"], "handoff-one")
        self.assertEqual(successor_parsed["source_report_sha256"], "a" * 64)

    def test_scout_card_carries_bounded_assignment_and_report_contract(self) -> None:
        card = (ROOKERY_ROOT / "templates" / "SCOUT_CARD.md").read_text(
            encoding="utf-8"
        )
        for prefix in (
            "Goal:",
            "Scope:",
            "Source handoff:",
            "Source report SHA-256:",
            "Report:",
            "Stop:",
        ):
            self.assertIn(prefix, card)
        for required in ("templates/REPORT.md", "## Handoff", "## Evidence", "## Commands"):
            self.assertIn(required, card)

    def test_every_rendered_catalog_prompt_exposes_the_same_handoff_contract(self) -> None:
        sources = sorted((ROOKERY_ROOT / "agents" / "catalog").glob("*.toml"))
        sources.extend(sorted((ROOKERY_ROOT / "adapters").glob("*/agents/*.toml")))
        sources.extend(sorted((ROOKERY_ROOT / "extensions").glob("*/agents/*.toml")))
        self.assertGreater(len(sources), 0)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            copied_catalog = root / "agent-sources"
            copied_catalog.mkdir()
            (root / ".codex" / "agents").mkdir(parents=True)
            config = root / "config.toml"
            config.write_text(
                'approval_policy = "never"\nsandbox_mode = "danger-full-access"\n\n'
                "[agents]\nmax_concurrent_threads_per_session = 96\nmax_depth = 2\n"
                "job_max_runtime_seconds = 5400\n",
                encoding="utf-8",
            )
            entries = []
            for source in sources:
                destination = copied_catalog / source.name
                self.assertFalse(destination.exists(), source.name)
                shutil.copy2(source, destination)
                entries.append({"source": destination.relative_to(root).as_posix()})
            _render_codex_files(
                root,
                entries,
                config,
                max_concurrent_threads=4,
                strict_config_supported=False,
            )
            generated = sorted((root / ".codex" / "agents").glob("*.toml"))
            self.assertEqual(len(generated), len(sources))
            documents = [
                (path.name, tomllib.loads(path.read_text(encoding="utf-8")))
                for path in generated
            ]

        for name, document in documents:
            with self.subTest(path=name):
                instructions = str(document["developer_instructions"])
                self.assertIn("## Report handoff", instructions)
                positions = [instructions.index(f"`{label}`") for label in HANDOFF_LABELS]
                self.assertEqual(positions, sorted(positions))
                for outcome_type in OUTCOME_TYPES:
                    self.assertIn(f"`{outcome_type}`", instructions)
                self.assertIn("open and read the exact source report", instructions)
                self.assertIn(
                    "`Source handoff` and `Source report SHA-256` are `none` only for an initial route",
                    instructions,
                )
                self.assertIn("Evidence paths` and `Command/artifact paths` are JSON arrays", instructions)

    def test_generated_start_prompt_contains_card_and_successor_packet(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = {
                "profile": "manual",
                "identity": {"name": "Prompt fixture"},
                "adapter": {"id": "manual"},
                "scoring": {"completion_mode": "evidence_only"},
                "surface": {},
            }
            result = ManifestResult(manifest, (), (), ())
            path = render_start_prompt(root, manifest, result, {"tools": []})
            prompt = path.read_text(encoding="utf-8")

        for line in (
            "Goal: <one bounded question>",
            "Scope: <targets, files, allowed actions, forbidden actions, and budget>",
            "Parent attempt: none for a depth-1 worker; exact challenge-coordinator attempt ID for depth 2",
            "Depth: 1 or 2",
            "Source handoff: none for an initial route; otherwise <handoff ID and report path>",
            "Source report SHA-256: none for an initial route; otherwise <exact registered 64hex report hash>",
            "Report: analysis/<lane>/REPORT.md",
            "Stop: <time, artifact, signal, or exact negative>",
        ):
            self.assertIn(line, prompt)
        for label in HANDOFF_LABELS:
            self.assertIn(f"`{label}`", prompt)
        self.assertIn("open and read the exact source report", prompt)
        self.assertIn("The coordinator alone integrates", prompt)
        self.assertIn("canonical `--role challenge-coordinator`", prompt)
        self.assertIn("explore claim-synthesis", prompt)
        self.assertIn("including event-wide work", prompt)
        self.assertIn("including initial event-wide work", prompt)
        self.assertIn("materially different route", prompt)
        self.assertIn("nonempty discriminating test", prompt)
        self.assertIn("[a-z0-9][a-z0-9._:-]{0,127}", prompt)
        self.assertIn("current-workspace-relative POSIX paths", prompt)
        self.assertIn("`state/`, `platform/`, absolute paths", prompt)
        self.assertIn("./bin/agent-harvest", prompt)
        self.assertIn("AUTOMATION_PERMITTED_ACTION_KINDS", prompt)
        self.assertIn("score allowance flag N", prompt)
        self.assertIn("--actor coordinator", prompt)
        self.assertIn("does not itself grant authority", prompt)

    def test_allowance_requires_and_records_explicit_actor(self) -> None:
        parser = build_parser()
        base = ["score", "allowance", "flag", "1", "--reason", "fixture grant"]
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            parser.parse_args(base)
        args = parser.parse_args([*base, "--actor", "coordinator"])
        store = object()
        manifest: dict[str, object] = {}
        with (
            mock.patch("rookery.portable.cli.workspace_root", return_value=SOURCE),
            mock.patch("rookery.portable.cli.load_context", return_value=(manifest, {}, store, object())),
            mock.patch("rookery.portable.cli.grant_allowance", return_value={"actor": "coordinator"}) as grant,
            mock.patch("rookery.portable.cli.refresh_snapshot"),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(cmd_score(args), 0)
        grant.assert_called_once_with(
            store, manifest, "flag", 1,
            reason="fixture grant", actor="coordinator",
        )

    def test_agent_registration_requires_bounded_assignment_fields(self) -> None:
        parser = build_parser()
        base = [
            "agent",
            "register",
            "worker-one",
            "--objective-id",
            "objective-one",
            "--role",
            "ctf_shell_sprinter",
            "--report-path",
            "analysis/lane/REPORT.md",
            "--event-wide",
        ]
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            parser.parse_args(base)
        arguments = parser.parse_args(
            [
                *base,
                "--goal",
                "Test one bounded route",
                "--scope",
                "artifact.bin; read-only; 10 minutes",
                "--stop-condition",
                "one proof or exact negative",
            ]
        )
        self.assertEqual(arguments.goal, "Test one bounded route")
        self.assertEqual(arguments.scope, "artifact.bin; read-only; 10 minutes")
        self.assertEqual(arguments.stop_condition, "one proof or exact negative")

    def test_agent_registration_passes_bounded_fields_to_runtime(self) -> None:
        arguments = build_parser().parse_args(
            [
                "agent",
                "register",
                "worker-one",
                "--objective-id",
                "objective-one",
                "--role",
                "ctf_shell_sprinter",
                "--report-path",
                "analysis/lane/REPORT.md",
                "--goal",
                "Test one bounded route",
                "--scope",
                "artifact.bin; read-only; 10 minutes",
                "--stop-condition",
                "one proof or exact negative",
                "--event-wide",
            ]
        )
        store = object()
        with (
            mock.patch(
                "rookery.portable.cli.load_context",
                return_value=(
                    {"concurrency": {"max_workers": 4}},
                    {},
                    store,
                    object(),
                ),
            ),
            mock.patch(
                "rookery.portable.cli.register_agent_attempt",
                return_value={"admitted": True, "output": {"ok": True}},
            ) as register,
            mock.patch("rookery.portable.cli.refresh_snapshot"),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(cmd_agent(arguments), 0)
        registration = register.call_args.args[1]
        self.assertEqual(registration["goal"], arguments.goal)
        self.assertEqual(registration["scope"], arguments.scope)
        self.assertEqual(registration["stop_condition"], arguments.stop_condition)
        self.assertEqual(registration["report_path"], "analysis/lane/REPORT.md")


if __name__ == "__main__":
    unittest.main()
