from __future__ import annotations

import copy
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
import unittest
from contextlib import contextmanager, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from tests.rookery.support import (
    install_solver_ready_challenge,
    open_test_event_store,
    rebind_test_workspace,
)
from tests.rookery.env_fixtures import replace_env_assignments
from tests.rookery.test_acceptance_campaign import make_workspace

from rookery.portable.cli import (
    _record_measurement_started,
    _persist_compiled_scope,
    build_parser,
    cmd_agent,
    cmd_go,
    cmd_outcome,
    cmd_platform,
    cmd_queue,
    render_start_prompt,
)
from rookery.portable.manifest import resolve_manifest, validate_manifest
from rookery.portable.queue import build_queue
from rookery.portable.registry import render_surface
from rookery.portable.scoring import create_proposal, grant_exact, record_review
from rookery.portable.scope import compile_scope
from rookery.portable.status import read_snapshot, refresh_snapshot, render_status
from rookery.portable.util import tree_hash


class PublicSurfaceTruthRepairTests(unittest.TestCase):
    @staticmethod
    def _bootstrap_fixture(root: Path):
        result = resolve_manifest(root)
        store = open_test_event_store(root)
        scope = compile_scope(result.manifest, 1)
        gate = SimpleNamespace(
            preparation_environment=SimpleNamespace(values={}),
            strict_config_supported=True,
            stage_c_environments=(),
        )
        binding = SimpleNamespace(
            sha256="a" * 64,
            record={
                "baseline_sha256": "b" * 64,
                "baseline_configuration_digest": "c" * 64,
                "release_version": "test-only",
                "measurement_contract": {
                    "queue_automation_enabled": False,
                    "provider_fields": {},
                },
            },
        )
        return gate, binding, store, result.manifest, scope, result

    def test_automated_watch_requires_a_lease_or_bounded_diagnostic(self) -> None:
        td = make_workspace("manual")
        root = Path(td.name)
        try:
            replace_env_assignments(root, {"QUEUE_AUTOMATION": "1"})
            rebind_test_workspace(root)
            args = SimpleNamespace(
                queue_action="watch",
                auto_execute=False,
                interval=1,
                once=True,
                owner_token="",
                watcher_epoch=None,
                quiet=True,
                heartbeat_seconds=300,
                diagnostic=False,
            )
            with (
                mock.patch("rookery.portable.cli.workspace_root", return_value=root),
                mock.patch("rookery.portable.cli.persist_schedules") as schedule,
                self.assertRaisesRegex(RuntimeError, "requires --owner-token"),
            ):
                cmd_queue(args)
            schedule.assert_not_called()

            args.diagnostic = True
            output = io.StringIO()
            with (
                mock.patch("rookery.portable.cli.workspace_root", return_value=root),
                mock.patch("rookery.portable.cli.persist_schedules") as schedule,
                redirect_stdout(output),
            ):
                self.assertEqual(cmd_queue(args), 0)
            schedule.assert_not_called()
            self.assertTrue(json.loads(output.getvalue())["diagnostic"])
            self.assertTrue(
                build_parser().parse_args(["queue", "watch", "--diagnostic"])
                .diagnostic
            )
        finally:
            td.cleanup()

    def test_disabled_auto_execute_rejects_before_queue_mutation(self) -> None:
        td = make_workspace("manual")
        root = Path(td.name)
        try:
            replace_env_assignments(
                root,
                {
                    "SCORING_ACTION_KINDS": "flag,no_submit_evidence",
                    "SCORING_COMPLETION_MODE": "scorer_truth",
                },
            )
            rebind_test_workspace(root)
            result = resolve_manifest(root)
            store = open_test_event_store(root)
            install_solver_ready_challenge(root, store)
            proposal = create_proposal(
                store,
                result.manifest,
                objective_id="101",
                action_kind="flag",
                exact_value="FIXTURE{policy-order}",
                source="analysis/policy/REPORT.md",
                rationale="policy ordering regression",
            )
            record_review(
                store,
                proposal["proposal_id"],
                "approved",
                reviewer="independent-reviewer",
                reason="fixture approval",
                verifier_report="analysis/policy/review.md",
            )
            grant_exact(store, proposal["proposal_id"], reason="fixture authority")
            self.assertTrue(
                any(item["eligible"] for item in build_queue(store, result.manifest)["items"])
            )
            before_events = len(store.events())
            before_tree = tree_hash(root)
            with (
                mock.patch("rookery.portable.cli.workspace_root", return_value=root),
                self.assertRaisesRegex(RuntimeError, "automation is disabled"),
            ):
                cmd_queue(
                    SimpleNamespace(
                        queue_action="tick", auto_execute=True, quiet=True
                    )
                )
            self.assertEqual(len(store.events()), before_events)
            self.assertEqual(tree_hash(root), before_tree)
            self.assertFalse((root / "state" / "execution_plans").exists())
            with (
                mock.patch("rookery.portable.cli.workspace_root", return_value=root),
                self.assertRaisesRegex(RuntimeError, "watch is disabled"),
            ):
                cmd_queue(
                    SimpleNamespace(
                        queue_action="watch",
                        auto_execute=False,
                        interval=1,
                        once=True,
                        owner_token="",
                        watcher_epoch=None,
                        quiet=True,
                        heartbeat_seconds=300,
                        diagnostic=False,
                    )
                )
            self.assertEqual(len(store.events()), before_events)
            self.assertEqual(tree_hash(root), before_tree)
            self.assertFalse((root / "state" / "execution_plans").exists())
        finally:
            td.cleanup()

    def test_watcher_blocker_survives_queue_agent_and_outcome_refreshes(self) -> None:
        td = make_workspace("manual")
        root = Path(td.name)
        try:
            replace_env_assignments(root, {"QUEUE_AUTOMATION": "1"})
            rebind_test_workspace(root)
            result = resolve_manifest(root)
            store = open_test_event_store(root)
            store.append(
                "job.starting",
                {
                    "job_id": "watcher-residual",
                    "kind": "queue-watcher",
                    "owner_token": "stale-token",
                    "pid": 123,
                    "pgid": 123,
                    "process_starttime": "fixture",
                },
                actor="fixture",
            )
            report_dir = root / "analysis" / "worker-one"
            report_dir.mkdir(parents=True)
            (report_dir / "trace.txt").write_text(
                "Fixture observed the residual watcher blocker.\n", encoding="utf-8"
            )
            (report_dir / "REPORT.md").write_text(
                "# Worker report\n\n"
                "## Handoff\n\n"
                "Status: technical_negative\n"
                "Source handoff: none\n"
                "Source report SHA-256: none\n"
                "Observed result: Fixture observed a residual watcher blocker.\n"
                "Route key: watcher-state-observation\n"
                "Proof gap: No live watcher process is available in this fixture.\n"
                "Discriminating test: Recheck the blocker after each command.\n"
                "Next step or return trigger: Continue only when the watcher is cleared.\n"
                'Evidence paths: ["analysis/worker-one/trace.txt"]\n'
                "Command/artifact paths: []\n"
                "Blocker: residual watcher\n"
                "Cleanup/jobs: none\n\n"
                "## Evidence\n\n"
                "The fixture records a residual watcher blocker for status checks.\n\n"
                "## Commands\n\n"
                "No external commands were run.\n",
                encoding="utf-8",
            )
            commands = (
                lambda: cmd_queue(SimpleNamespace(queue_action="schedule")),
                lambda: cmd_agent(
                    SimpleNamespace(
                        agent_action="register",
                        agent_id="worker-one",
                        objective_id="101",
                        role="worker",
                        report_path="analysis/worker-one/REPORT.md",
                        owner="fixture",
                        attempt_id="attempt-one",
                        parent_attempt_id="",
                        pid=0,
                        pgid=0,
                        process_starttime="",
                        owner_token="",
                        challenge_id="",
                        event_wide=True,
                        handoff_id="",
                        goal="Check residual watcher status across command refreshes.",
                        scope="Local fixture state and status only.",
                        stop_condition="Status checks complete.",
                    )
                ),
                lambda: cmd_agent(
                    SimpleNamespace(
                        agent_action="integrate",
                        agent_id="worker-one",
                        agent_attempt_id="attempt-one",
                        challenge_id="",
                        objective_id="101",
                        report_path="analysis/worker-one/REPORT.md",
                        status="technical_negative",
                        observed_result="Fixture observed a residual watcher blocker.",
                        route_key="watcher-state-observation",
                        proof_gap="No live watcher process is available in this fixture.",
                        next_step_or_return_trigger="Continue only when the watcher is cleared.",
                    )
                ),
                lambda: cmd_outcome(
                    SimpleNamespace(
                        outcome_action="record",
                        agent_id="worker-one",
                        objective_id="101",
                        type="technical_negative",
                        report_path="analysis/worker-one/REPORT.md",
                        summary="fixture outcome",
                        mechanism="watcher-state-observation",
                        agent_attempt_id="attempt-one",
                        provenance=[],
                        challenge_id="",
                        continuation="",
                        handoff_id="",
                    )
                ),
            )
            with (
                mock.patch("rookery.portable.cli.workspace_root", return_value=root),
                mock.patch(
                    "rookery.portable.watchers.process_identity_matches",
                    return_value=True,
                ),
                redirect_stdout(io.StringIO()),
            ):
                initial = refresh_snapshot(store, root, result.manifest, result)
                self.assertEqual(initial["lifecycle_state"], "blocked")
                for command in commands:
                    self.assertEqual(command(), 0)
                    snapshot = read_snapshot(root)
                    self.assertEqual(snapshot["lifecycle_state"], "blocked")
                    self.assertEqual(
                        snapshot["watcher"].get("reason"),
                        "blocked by residual watcher",
                    )
                    self.assertIn(
                        "queue watcher: blocked by residual watcher",
                        snapshot["blockers"],
                    )
        finally:
            td.cleanup()

    def test_watcher_startup_result_gates_automation_lifecycle(self) -> None:
        cases = (
            (
                "residual",
                True,
                {"running": False, "reason": "blocked by residual watcher"},
                "blocked",
                "queue watcher: blocked by residual watcher",
            ),
            (
                "multiple",
                True,
                {"running": False, "reason": "blocked by multiple live watchers"},
                "blocked",
                "queue watcher: blocked by multiple live watchers",
            ),
            (
                "not-running",
                True,
                {"running": False, "reason": "watcher launch did not persist"},
                "blocked",
                "queue watcher: watcher launch did not persist",
            ),
            (
                "running",
                True,
                {
                    "running": True,
                    "reused": True,
                    "job": {
                        "pid": 4242,
                        "pgid": 4242,
                        "process_starttime": "fixture",
                        "owner_token": "fixture-owner",
                        "watcher_epoch": 0,
                    },
                },
                "ready",
                None,
            ),
            (
                "disabled",
                False,
                {"running": False, "reason": "automation disabled"},
                "ready",
                None,
            ),
        )
        for name, enabled, watcher_result, expected_state, expected_blocker in cases:
            with self.subTest(watcher=name):
                td = make_workspace("manual")
                root = Path(td.name)
                try:
                    replace_env_assignments(
                        root, {"QUEUE_AUTOMATION": "1" if enabled else "0"}
                    )
                    rebind_test_workspace(root)
                    output = io.StringIO()
                    with (
                        mock.patch(
                            "rookery.portable.cli.workspace_root", return_value=root
                        ),
                        mock.patch(
                            "rookery.portable.cli._bootstrap_launch",
                            return_value=self._bootstrap_fixture(root),
                        ),
                        mock.patch(
                            "rookery.portable.cli.prepare",
                            return_value={
                                "ready": True,
                                "capabilities": [],
                                "services": {},
                            },
                        ),
                        mock.patch(
                            "rookery.portable.cli._ensure_queue_watcher_locked",
                            return_value=watcher_result,
                        ) as ensure_watcher,
                        redirect_stdout(output),
                    ):
                        self.assertEqual(
                            cmd_go(build_parser().parse_args(["go"])),
                            2 if expected_state == "blocked" else 0,
                        )

                    snapshot = json.loads(
                        (root / "state" / "status_snapshot.json").read_text(
                            encoding="utf-8"
                        )
                    )
                    self.assertEqual(snapshot["lifecycle_state"], expected_state)
                    self.assertEqual(snapshot["watcher"], watcher_result)
                    self.assertIn(
                        f"rookery_state={expected_state}", output.getvalue()
                    )
                    ensure_watcher.assert_called_once()
                    if expected_blocker:
                        self.assertIn(expected_blocker, snapshot["blockers"])
                        self.assertIn(expected_blocker, render_status(snapshot))
                        self.assertFalse((root / "START_PROMPT.md").exists())
                    else:
                        self.assertFalse(
                            any(
                                blocker.startswith("queue watcher:")
                                for blocker in snapshot["blockers"]
                            )
                        )
                        self.assertTrue((root / "START_PROMPT.md").is_file())
                finally:
                    td.cleanup()

    def test_preparation_missing_required_blocks_before_watcher_or_prompt(self) -> None:
        td = make_workspace("manual")
        root = Path(td.name)
        try:
            output = io.StringIO()
            with (
                mock.patch("rookery.portable.cli.workspace_root", return_value=root),
                mock.patch(
                    "rookery.portable.cli._bootstrap_launch",
                    return_value=self._bootstrap_fixture(root),
                ),
                mock.patch(
                    "rookery.portable.cli.prepare",
                    return_value={
                        "ready": False,
                        "missing_required": ["python3", "jq"],
                        "capabilities": [],
                        "services": {},
                    },
                ),
                mock.patch("rookery.portable.cli._ensure_queue_watcher_locked") as watcher,
                redirect_stdout(output),
            ):
                self.assertEqual(cmd_go(build_parser().parse_args(["go"])), 2)

            snapshot = read_snapshot(root)
            self.assertEqual(snapshot["lifecycle_state"], "blocked")
            self.assertIn(
                "preparation: missing required capability: python3",
                snapshot["blockers"],
            )
            self.assertIn(
                "preparation: missing required capability: jq", snapshot["blockers"]
            )
            self.assertIn("required_check_failures=preparation", output.getvalue())
            watcher.assert_not_called()
            self.assertFalse((root / "START_PROMPT.md").exists())
        finally:
            td.cleanup()

    def test_status_revalidates_cached_watcher_without_writing_state(self) -> None:
        td = make_workspace("manual")
        root = Path(td.name)
        try:
            state = root / "state"
            state.mkdir(exist_ok=True)
            store = open_test_event_store(root)
            store.set_meta("watcher_epoch", 4)
            snapshot_path = state / "status_snapshot.json"
            cached = {
                "generated_at": "fixture",
                "lifecycle_state": "ready",
                "queue_automation_enabled": True,
                "watcher_epoch": 4,
                "watcher": {
                    "running": True,
                    "job": {
                        "pid": 4242,
                        "pgid": 4242,
                        "process_starttime": "fixture",
                        "owner_token": "fixture-owner",
                        "watcher_epoch": 4,
                    },
                },
                "blockers": [],
            }
            encoded = json.dumps(cached, sort_keys=True)
            snapshot_path.write_text(encoded, encoding="utf-8")
            before = {
                path.relative_to(state).as_posix(): path.read_bytes()
                for path in state.rglob("*")
                if path.is_file()
            }
            output = io.StringIO()
            with (
                mock.patch("rookery.portable.cli.workspace_root", return_value=root),
                mock.patch(
                    "rookery.portable.cli.launch_binding_integrity_error", return_value=None
                ),
                mock.patch(
                    "rookery.portable.status.process_identity_matches", return_value=False
                ) as identity,
                redirect_stdout(output),
            ):
                self.assertEqual(cmd_go(build_parser().parse_args(["go", "status"])), 0)

            identity.assert_called_once_with(root, cached["watcher"]["job"])
            self.assertIn("state=blocked", output.getvalue())
            self.assertIn("cached watcher is stale or dead", output.getvalue())
            after = {
                path.relative_to(state).as_posix(): path.read_bytes()
                for path in state.rglob("*")
                if path.is_file()
            }
            self.assertEqual(before, after)
        finally:
            td.cleanup()

    def test_status_blocks_cached_watcher_epoch_mismatch_without_process_control(self) -> None:
        td = make_workspace("manual")
        root = Path(td.name)
        try:
            state = root / "state"
            state.mkdir(exist_ok=True)
            store = open_test_event_store(root)
            store.set_meta("watcher_epoch", 5)
            snapshot_path = state / "status_snapshot.json"
            cached = {
                "generated_at": "fixture",
                "lifecycle_state": "ready",
                "queue_automation_enabled": True,
                "watcher_epoch": 4,
                "watcher": {
                    "running": True,
                    "job": {
                        "pid": 4242,
                        "pgid": 4242,
                        "process_starttime": "fixture",
                        "owner_token": "fixture-owner",
                        "watcher_epoch": 5,
                    },
                },
                "blockers": [],
            }
            encoded = json.dumps(cached, sort_keys=True)
            snapshot_path.write_text(encoded, encoding="utf-8")
            with mock.patch(
                "rookery.portable.status.process_identity_matches",
                side_effect=AssertionError("epoch mismatch must not control a process"),
            ):
                status = read_snapshot(root)
            self.assertEqual(status["lifecycle_state"], "blocked")
            self.assertTrue(
                any("cached watcher is stale or dead" in blocker for blocker in status["blockers"])
            )
            self.assertEqual(snapshot_path.read_text(encoding="utf-8"), encoded)
        finally:
            td.cleanup()

    def test_measurement_start_persists_bound_value_free_contract_once(self) -> None:
        td = make_workspace("manual")
        root = Path(td.name)
        try:
            store = open_test_event_store(root)
            contract = {
                "queue_automation_enabled": True,
                "provider_fields": {
                    "queue": {"availability": "available"},
                    "tokens": {"availability": "unavailable"},
                    "usage": {"availability": "unavailable"},
                },
            }
            binding = SimpleNamespace(
                sha256="fixture-binding",
                record={
                    "baseline_sha256": "a" * 64,
                    "baseline_configuration_digest": "b" * 64,
                    "release_version": "fixture",
                    "measurement_contract": contract,
                },
            )
            _record_measurement_started(store, binding)
            _record_measurement_started(store, binding)
            events = store.events("measurement.started")
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0]["payload"]["measurement_contract"], contract)
            self.assertNotIn("baseline_path", json.dumps(events[0]["payload"]))
        finally:
            td.cleanup()

    @unittest.skipIf(os.name == "nt", "Bash wrapper integration runs on Linux or WSL")
    def test_go_wrapper_stops_before_fake_codex_for_nonready_result(self) -> None:
        source_go = Path(__file__).resolve().parents[2] / "rookery" / "go"
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / "bin").mkdir()
            shutil.copy2(source_go, root / "go")
            (root / "go").chmod(0o755)
            codex_marker = root / "codex-invoked"
            (root / "bin" / "rookery").write_text(
                "#!/usr/bin/env bash\n"
                "set -euo pipefail\n"
                "if [[ ${ROOKERY_FAKE_LAUNCH:-} = ready ]]; then\n"
                "  printf 'ready prompt\\n' > START_PROMPT.md\n"
                "  mkdir -p state\n"
                "  printf '%s\\n' '{' '  \"attempt_id\": \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",' '  \"launch_binding_sha256\": \"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",' '  \"schema_version\": \"1\",' '  \"stop_generation\": 0' '}' > state/launch_attempt.json\n"
                "  exit 0\n"
                "fi\n"
                "exit 2\n",
                encoding="utf-8",
            )
            (root / "bin" / "rookery").chmod(0o755)
            (root / "run-codex").write_text(
                "#!/usr/bin/env bash\n"
                f"printf '%s' \"$3\" > {codex_marker}\n",
                encoding="utf-8",
            )
            (root / "run-codex").chmod(0o755)
            for reason in (
                "preparation-failure",
                "watcher-blocked",
                "watcher-stale",
                "watcher-dead",
            ):
                with self.subTest(reason=reason):
                    codex_marker.unlink(missing_ok=True)
                    result = subprocess.run(
                        ["bash", str(root / "go")],
                        cwd=root,
                        env={**os.environ, "ROOKERY_FAKE_LAUNCH": reason},
                        text=True,
                        capture_output=True,
                        check=False,
                    )
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertFalse(codex_marker.exists())

            ready = subprocess.run(
                ["bash", str(root / "go")],
                cwd=root,
                env={**os.environ, "ROOKERY_FAKE_LAUNCH": "ready"},
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(ready.returncode, 0, ready.stderr)
            self.assertEqual(codex_marker.read_text(encoding="utf-8"), "ready prompt")

    def test_queue_watch_exits_before_tick_when_its_lease_is_stale(self) -> None:
        td = make_workspace("manual")
        root = Path(td.name)
        try:
            replace_env_assignments(root, {"QUEUE_AUTOMATION": "1"})
            rebind_test_workspace(root)
            args = SimpleNamespace(
                queue_action="watch",
                auto_execute=False,
                interval=1,
                once=True,
                owner_token="stale-watcher",
                watcher_epoch=4,
                quiet=True,
                heartbeat_seconds=300,
                diagnostic=False,
            )
            with (
                mock.patch("rookery.portable.cli.workspace_root", return_value=root),
                mock.patch(
                    "rookery.portable.cli.watcher_lease_is_current", return_value=False
                ) as lease,
                mock.patch("rookery.portable.cli.persist_schedules") as schedule,
            ):
                self.assertEqual(cmd_queue(args), 0)

            lease.assert_called_once()
            schedule.assert_not_called()
        finally:
            td.cleanup()

    def test_platform_ingest_uses_opaque_paths_for_external_ids_and_duplicates(
        self,
    ) -> None:
        td = make_workspace("manual")
        root = Path(td.name)
        try:
            challenge_id = "../challenge-escape"
            attachment_name = "../../attachment-escape"
            attachments = [
                {"name": attachment_name, "path": "fixture://one"},
                {"name": attachment_name, "path": "fixture://two"},
            ]
            adapter = mock.Mock()
            adapter.detail.return_value = {"id": challenge_id, "files": attachments}
            destinations: list[Path] = []

            def capture(_item, destination):
                destinations.append(destination)
                data = f"fixture:{destination.name}\n".encode("utf-8")
                destination.write_bytes(data)
                destination.chmod(0o600)
                return {
                    "path": destination.relative_to(root).as_posix(),
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "bytes": len(data),
                    "origin": str(_item.get("path") or _item.get("url") or ""),
                }

            adapter.capture_file.side_effect = capture

            with (
                mock.patch("rookery.portable.cli.workspace_root", return_value=root),
                mock.patch("rookery.portable.cli.get_adapter", return_value=adapter),
            ):
                self.assertEqual(
                    cmd_platform(
                        SimpleNamespace(
                            platform_action="ingest",
                            challenge_id=challenge_id,
                            no_files=False,
                            quiet=True,
                        )
                    ),
                    0,
                )

            challenge_dirs = list((root / "platform" / "challenges").iterdir())
            self.assertEqual(len(challenge_dirs), 1)
            self.assertTrue(challenge_dirs[0].name.startswith("challenge-"))
            self.assertFalse((root / "platform" / "challenge-escape").exists())
            self.assertEqual(len(destinations), 2)
            self.assertEqual(len({path.name for path in destinations}), 2)
            self.assertTrue(all(path.is_relative_to(root) for path in destinations))
            payload = open_test_event_store(root).rebuild()["current"]["challenges"][challenge_id]
            self.assertEqual(payload["files"], attachments)
            self.assertEqual(
                [file["attachment_name"] for file in payload["captured_files"]],
                [attachment_name, attachment_name],
            )
        finally:
            td.cleanup()

    def test_unlock_check_does_not_retry_recorded_attachment_failure(self) -> None:
        td = make_workspace("manual")
        root = Path(td.name)
        try:
            adapter = mock.Mock()
            adapter.id = "fixture"
            adapter.sync.return_value = {
                "schema_version": "1",
                "adapter_id": "fixture",
                "generated_at": "2026-01-01T00:00:00Z",
                "artifact": "",
                "capabilities": {},
                "challenges": [{"id": "101", "title": "Fixture"}],
                "releases": [],
                "collaboration": {},
                "session": {},
            }
            adapter.detail.return_value = {
                "id": "101",
                "files": [{"name": "broken.bin", "url": "fixture://broken"}],
            }
            adapter.capture_file.side_effect = OSError("fixture capture failed")
            args = SimpleNamespace(
                platform_action="unlock-check",
                ingest=True,
                limit=20,
            )

            first_output = io.StringIO()
            with (
                mock.patch("rookery.portable.cli.workspace_root", return_value=root),
                mock.patch("rookery.portable.cli.get_adapter", return_value=adapter),
                redirect_stdout(first_output),
            ):
                self.assertEqual(cmd_platform(args), 2)
            first_payload = json.loads(first_output.getvalue())
            self.assertEqual(first_payload["ingested_ids"], [])
            self.assertEqual(first_payload["intake_partial_ids"], ["101"])
            challenge = open_test_event_store(root).rebuild()["current"]["challenges"]["101"]
            self.assertIn("error", challenge["captured_files"][0])
            self.assertTrue(challenge["detail_path"])
            self.assertEqual(challenge["ingested_at"], "")
            self.assertEqual(challenge["intake_state"], "partial")
            self.assertEqual(challenge["intake_attempt_count"], 1)

            second_output = io.StringIO()
            with (
                mock.patch("rookery.portable.cli.workspace_root", return_value=root),
                mock.patch("rookery.portable.cli.get_adapter", return_value=adapter),
                redirect_stdout(second_output),
            ):
                self.assertEqual(cmd_platform(args), 2)
            second_payload = json.loads(second_output.getvalue())
            self.assertEqual(second_payload["ingested_ids"], [])
            self.assertEqual(second_payload["intake_pending_count"], 0)
            self.assertEqual(second_payload["intake_partial_ids"], ["101"])
            self.assertEqual(adapter.detail.call_count, 1)
            self.assertEqual(adapter.capture_file.call_count, 1)
        finally:
            td.cleanup()

    def test_unlock_check_keeps_last_authoritative_inventory_as_new_id_baseline(self) -> None:
        authoritative = {
            "schema_version": "1",
            "adapter_id": "fixture",
            "generated_at": "2026-01-01T00:00:00Z",
            "artifact": "",
            "capabilities": {
                "platform_inventory": {
                    "availability": "available",
                    "health": "healthy",
                }
            },
            "challenges": [{"id": "101", "title": "Fixture"}],
            "releases": [],
            "collaboration": {},
            "session": {},
        }
        nonauthoritative = {
            "unhealthy": {
                **authoritative,
                "capabilities": {
                    "platform_inventory": {
                        "availability": "available",
                        "health": "unhealthy",
                    }
                },
                "challenges": [],
            },
            "legacy": {**authoritative, "capabilities": {}, "challenges": []},
        }
        for label, prior_snapshot in nonauthoritative.items():
            with self.subTest(snapshot=label):
                td = make_workspace("manual")
                root = Path(td.name)
                try:
                    store = open_test_event_store(root)
                    store.append("platform.snapshot", authoritative, actor="fixture")
                    store.append("platform.snapshot", prior_snapshot, actor="fixture")
                    adapter = mock.Mock()
                    adapter.id = "fixture"
                    adapter.sync.return_value = authoritative
                    output = io.StringIO()
                    with (
                        mock.patch("rookery.portable.cli.workspace_root", return_value=root),
                        mock.patch("rookery.portable.cli.get_adapter", return_value=adapter),
                        redirect_stdout(output),
                    ):
                        self.assertEqual(
                            cmd_platform(
                                SimpleNamespace(
                                    platform_action="unlock-check",
                                    ingest=False,
                                    limit=20,
                                )
                            ),
                            0,
                        )
                    self.assertEqual(json.loads(output.getvalue())["new_ids"], [])
                finally:
                    td.cleanup()

    def test_unlock_check_reports_policy_blocked_hidden_challenge_as_blocked(self) -> None:
        td = make_workspace("manual")
        root = Path(td.name)
        try:
            store = open_test_event_store(root)
            store.append(
                "challenge.upsert",
                {
                    "id": "101",
                    "classification": "policy_blocked",
                    "hidden": True,
                },
                actor="fixture",
            )
            adapter = mock.Mock()
            adapter.id = "fixture"
            adapter.sync.return_value = {
                "schema_version": "1",
                "adapter_id": "fixture",
                "generated_at": "2026-01-01T00:00:00Z",
                "artifact": "",
                "capabilities": {
                    "platform_inventory": {
                        "availability": "available",
                        "health": "healthy",
                    }
                },
                "challenges": [{"id": "101", "title": "Fixture"}],
                "releases": [],
                "collaboration": {},
                "session": {},
            }
            output = io.StringIO()
            with (
                mock.patch("rookery.portable.cli.workspace_root", return_value=root),
                mock.patch("rookery.portable.cli.get_adapter", return_value=adapter),
                redirect_stdout(output),
            ):
                self.assertEqual(
                    cmd_platform(
                        SimpleNamespace(
                            platform_action="unlock-check",
                            ingest=False,
                            limit=20,
                        )
                    ),
                    0,
                )
            payload = json.loads(output.getvalue())
            self.assertEqual(payload["intake_blocked_ids"], ["101"])
            self.assertEqual(
                payload["intake_deferred"],
                [{"id": "101", "reason": "policy_blocked"}],
            )
        finally:
            td.cleanup()

    def test_unlock_check_admits_authoritative_reappearance_in_same_cycle(self) -> None:
        prior_inventory = {
            "schema_version": "1",
            "adapter_id": "fixture",
            "generated_at": "2026-01-01T00:00:00Z",
            "artifact": "",
            "capabilities": {
                "platform_inventory": {
                    "availability": "available",
                    "health": "healthy",
                }
            },
            "challenges": [{"id": "101", "title": "Fixture"}],
            "releases": [],
            "collaboration": {},
            "session": {},
        }
        reappearing = {**prior_inventory, "challenges": [{"id": "101", "title": "Back"}]}
        nonauthoritative = {**reappearing, "capabilities": {}}
        cases = (("authoritative", reappearing, ["101"], []), ("legacy", nonauthoritative, [], [{"id": "101", "reason": "unavailable"}]))
        for name, current_inventory, pending_ids, deferred in cases:
            with self.subTest(inventory=name):
                td = make_workspace("manual")
                root = Path(td.name)
                try:
                    store = open_test_event_store(root)
                    store.append("platform.snapshot", prior_inventory, actor="fixture")
                    store.append(
                        "platform.snapshot",
                        {**prior_inventory, "challenges": []},
                        actor="fixture",
                    )
                    adapter = mock.Mock()
                    adapter.id = "fixture"
                    adapter.sync.return_value = current_inventory
                    output = io.StringIO()
                    with (
                        mock.patch("rookery.portable.cli.workspace_root", return_value=root),
                        mock.patch("rookery.portable.cli.get_adapter", return_value=adapter),
                        redirect_stdout(output),
                    ):
                        self.assertEqual(
                            cmd_platform(
                                SimpleNamespace(
                                    platform_action="unlock-check",
                                    ingest=False,
                                    limit=20,
                                )
                            ),
                            0,
                        )
                    payload = json.loads(output.getvalue())
                    self.assertEqual(payload["intake_pending_ids"], pending_ids)
                    self.assertEqual(payload["intake_deferred"], deferred)
                finally:
                    td.cleanup()

    def test_unlock_check_rotates_detail_failures_behind_unattempted_ids(self) -> None:
        td = make_workspace("manual")
        root = Path(td.name)
        try:
            adapter = mock.Mock()
            adapter.id = "fixture"
            adapter.sync.return_value = {
                "schema_version": "1",
                "adapter_id": "fixture",
                "generated_at": "2026-01-01T00:00:00Z",
                "artifact": "",
                "capabilities": {},
                "challenges": [
                    {"id": "101", "title": "Broken detail"},
                    {"id": "102", "title": "Healthy detail"},
                ],
                "releases": [],
                "collaboration": {},
                "session": {},
            }
            detail_calls: list[str] = []

            def detail(challenge_id: str) -> dict[str, object]:
                detail_calls.append(challenge_id)
                if challenge_id == "101":
                    raise RuntimeError("fixture detail unavailable")
                return {"id": challenge_id, "files": []}

            adapter.detail.side_effect = detail
            args = SimpleNamespace(
                platform_action="unlock-check",
                ingest=True,
                limit=1,
            )

            first_output = io.StringIO()
            with (
                mock.patch("rookery.portable.cli.workspace_root", return_value=root),
                mock.patch("rookery.portable.cli.get_adapter", return_value=adapter),
                redirect_stdout(first_output),
            ):
                self.assertEqual(cmd_platform(args), 2)
            first_payload = json.loads(first_output.getvalue())
            self.assertEqual(first_payload["intake_errors"][0]["id"], "101")
            self.assertEqual(first_payload["intake_pending_ids"], ["101", "102"])

            second_output = io.StringIO()
            with (
                mock.patch("rookery.portable.cli.workspace_root", return_value=root),
                mock.patch("rookery.portable.cli.get_adapter", return_value=adapter),
                redirect_stdout(second_output),
            ):
                self.assertEqual(cmd_platform(args), 0)
            second_payload = json.loads(second_output.getvalue())
            self.assertEqual(second_payload["new_ids"], [])
            self.assertEqual(second_payload["ingested_ids"], ["102"])
            self.assertEqual(second_payload["intake_pending_ids"], ["101"])
            self.assertEqual(detail_calls, ["101", "102"])
            failed = open_test_event_store(root).rebuild()["current"]["challenges"]["101"]
            self.assertTrue(failed["intake_last_attempt_at"])
            self.assertEqual(failed["intake_attempt_count"], 1)
            self.assertEqual(
                failed["intake_last_error"],
                "fixture detail unavailable",
            )
        finally:
            td.cleanup()

    def test_unlock_check_round_robins_same_second_failures(self) -> None:
        td = make_workspace("manual")
        root = Path(td.name)
        try:
            adapter = mock.Mock()
            adapter.id = "fixture"
            adapter.sync.return_value = {
                "schema_version": "1",
                "adapter_id": "fixture",
                "generated_at": "2026-01-01T00:00:00Z",
                "artifact": "",
                "capabilities": {},
                "challenges": [
                    {"id": "101", "title": "First broken detail"},
                    {"id": "102", "title": "Second broken detail"},
                ],
                "releases": [],
                "collaboration": {},
                "session": {},
            }
            detail_calls: list[str] = []

            def detail(challenge_id: str) -> dict[str, object]:
                detail_calls.append(challenge_id)
                raise RuntimeError("fixture detail unavailable")

            adapter.detail.side_effect = detail
            args = SimpleNamespace(
                platform_action="unlock-check",
                ingest=True,
                limit=1,
            )

            with (
                mock.patch("rookery.portable.cli.workspace_root", return_value=root),
                mock.patch("rookery.portable.cli.get_adapter", return_value=adapter),
            ):
                for _ in range(4):
                    with redirect_stdout(io.StringIO()):
                        self.assertEqual(cmd_platform(args), 2)

            self.assertEqual(detail_calls, ["101", "102", "101", "102"])
            challenges = open_test_event_store(root).rebuild()["current"]["challenges"]
            self.assertEqual(challenges["101"]["intake_attempt_count"], 2)
            self.assertEqual(challenges["102"]["intake_attempt_count"], 2)
        finally:
            td.cleanup()

    def test_platform_ingest_marks_missing_material_partial(self) -> None:
        cases = (
            (
                "skipped-files",
                {
                    "id": "101",
                    "files": [{"name": "required.bin", "path": "fixture://required"}],
                },
                True,
                "attachments_skipped",
            ),
            (
                "truncated-resources",
                {
                    "id": "101",
                    "files": [],
                    "resources_truncated": True,
                    "resources_complete": False,
                },
                False,
                "resources_truncated",
            ),
        )
        for name, detail, no_files, expected_reason in cases:
            with self.subTest(name=name):
                td = make_workspace("manual")
                root = Path(td.name)
                try:
                    adapter = mock.Mock()
                    adapter.detail.return_value = detail
                    output = io.StringIO()
                    with (
                        mock.patch("rookery.portable.cli.workspace_root", return_value=root),
                        mock.patch("rookery.portable.cli.get_adapter", return_value=adapter),
                        redirect_stdout(output),
                    ):
                        self.assertEqual(
                            cmd_platform(
                                SimpleNamespace(
                                    platform_action="ingest",
                                    challenge_id="101",
                                    no_files=no_files,
                                    quiet=False,
                                )
                            ),
                            2,
                        )
                    payload = json.loads(output.getvalue())
                    self.assertEqual(payload["intake_state"], "partial")
                    self.assertEqual(payload["ingested_at"], "")
                    self.assertIn(expected_reason, payload["intake_missing_material"])
                finally:
                    td.cleanup()

    def test_platform_ingest_reuses_verified_partial_capture(self) -> None:
        td = make_workspace("manual")
        root = Path(td.name)
        try:
            adapter = mock.Mock()
            adapter.detail.return_value = {
                "id": "101",
                "files": [
                    {"name": "first.bin", "path": "fixture://first"},
                    {"name": "second.bin", "path": "fixture://second"},
                ],
            }
            calls: list[str] = []
            second_attempts = 0

            def capture(item: dict[str, object], destination: Path) -> dict[str, object]:
                nonlocal second_attempts
                name = str(item["name"])
                calls.append(name)
                if name == "second.bin":
                    second_attempts += 1
                    if second_attempts == 1:
                        raise OSError("fixture second capture unavailable")
                data = f"fixture:{name}\n".encode("utf-8")
                destination.write_bytes(data)
                destination.chmod(0o600)
                return {
                    "path": destination.relative_to(root).as_posix(),
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "bytes": len(data),
                    "origin": str(item["path"]),
                }

            adapter.capture_file.side_effect = capture
            args = SimpleNamespace(
                platform_action="ingest",
                challenge_id="101",
                no_files=False,
                quiet=True,
            )
            with (
                mock.patch("rookery.portable.cli.workspace_root", return_value=root),
                mock.patch("rookery.portable.cli.get_adapter", return_value=adapter),
            ):
                self.assertEqual(cmd_platform(args), 2)
                first = open_test_event_store(root).rebuild()["current"]["challenges"]["101"]
                first_path = first["captured_files"][0]["path"]
                self.assertEqual(first["intake_state"], "partial")
                self.assertEqual(cmd_platform(args), 0)

            final = open_test_event_store(root).rebuild()["current"]["challenges"]["101"]
            self.assertEqual(final["intake_state"], "complete")
            self.assertEqual(final["captured_file_count"], 2)
            self.assertEqual(calls, ["first.bin", "second.bin", "second.bin"])
            reused = next(
                row for row in final["captured_files"] if row["attachment_name"] == "first.bin"
            )
            self.assertTrue(reused["reused_existing"])
            self.assertEqual(reused["path"], first_path)
            self.assertTrue((root / first_path).is_file())
        finally:
            td.cleanup()

    def test_platform_sync_artifacts_are_unique_private_and_self_bound(self) -> None:
        td = make_workspace("manual")
        root = Path(td.name)
        try:
            adapter = mock.Mock()
            adapter.id = "fixture"
            adapter.sync.return_value = {
                "schema_version": "1",
                "adapter_id": "fixture",
                "generated_at": "2026-01-01T00:00:00Z",
                "artifact": "",
                "capabilities": {},
                "challenges": [],
                "releases": [],
                "collaboration": {},
                "session": {},
            }
            args = SimpleNamespace(platform_action="sync")
            with (
                mock.patch("rookery.portable.cli.workspace_root", return_value=root),
                mock.patch("rookery.portable.cli.get_adapter", return_value=adapter),
                redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(cmd_platform(args), 0)
                self.assertEqual(cmd_platform(args), 0)

            events = open_test_event_store(root).events("platform.snapshot")
            paths = [root / event["payload"]["artifact"] for event in events]
            self.assertEqual(len(paths), 2)
            self.assertEqual(len(set(paths)), 2)
            for event, path in zip(events, paths, strict=True):
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                self.assertEqual(json.loads(path.read_text(encoding="utf-8")), event["payload"])
        finally:
            td.cleanup()

    def test_concurrent_unlock_checks_serialize_one_intake(self) -> None:
        td = make_workspace("manual")
        root = Path(td.name)
        try:
            adapter = mock.Mock()
            adapter.id = "fixture"
            adapter.sync.return_value = {
                "schema_version": "1",
                "adapter_id": "fixture",
                "generated_at": "2026-01-01T00:00:00Z",
                "artifact": "",
                "capabilities": {},
                "challenges": [{"id": "101", "title": "Fixture"}],
                "releases": [],
                "collaboration": {},
                "session": {},
            }
            adapter.detail.return_value = {"id": "101", "files": []}
            args = SimpleNamespace(
                platform_action="unlock-check",
                ingest=True,
                limit=1,
            )
            barrier = threading.Barrier(3)
            results: list[int] = []
            errors: list[BaseException] = []

            def run_check() -> None:
                try:
                    barrier.wait(timeout=5)
                    results.append(cmd_platform(args))
                except BaseException as exc:
                    errors.append(exc)

            workers = [threading.Thread(target=run_check) for _ in range(2)]
            with (
                mock.patch("rookery.portable.cli.workspace_root", return_value=root),
                mock.patch("rookery.portable.cli.get_adapter", return_value=adapter),
                mock.patch("builtins.print"),
            ):
                for worker in workers:
                    worker.start()
                barrier.wait(timeout=5)
                for worker in workers:
                    worker.join(timeout=20)
                    self.assertFalse(worker.is_alive())

            self.assertEqual(errors, [])
            self.assertEqual(results, [0, 0])
            self.assertEqual(adapter.detail.call_count, 1)
            self.assertEqual(
                len(open_test_event_store(root).events("challenge.upsert")),
                1,
            )
            snapshots = open_test_event_store(root).events("platform.snapshot")
            self.assertEqual(len(snapshots), 2)
            self.assertEqual(
                len({event["payload"]["artifact"] for event in snapshots}),
                2,
            )
        finally:
            td.cleanup()

    def test_go_snapshot_and_watcher_share_manifest_readiness(self) -> None:
        cases = (
            ("identity.name", "EVENT_NAME", "unknown"),
            ("scope.max_attachment_bytes", "SCOPE_MAX_BYTES", ""),
        )
        for expected, environment_name, value in cases:
            with self.subTest(unresolved_required=expected):
                td = make_workspace("manual", ready=False)
                root = Path(td.name)
                try:
                    replace_env_assignments(root, {environment_name: value})
                    output = io.StringIO()
                    with (
                        mock.patch(
                            "rookery.portable.cli.workspace_root", return_value=root
                        ),
                        mock.patch(
                            "rookery.portable.cli.prepare",
                            return_value={
                                "ready": True,
                                "capabilities": [],
                                "services": {},
                            },
                        ) as prepare,
                        mock.patch(
                            "rookery.portable.cli._ensure_queue_watcher_locked"
                        ) as watcher,
                        redirect_stdout(output),
                        mock.patch("sys.stderr", new=output),
                    ):
                        self.assertEqual(cmd_go(build_parser().parse_args(["go"])), 2)

                    self.assertIn("launch_error=launch_configuration_unresolved", output.getvalue())
                    prepare.assert_not_called()
                    watcher.assert_not_called()
                finally:
                    td.cleanup()

    def test_scope_generation_and_replacement_share_the_mutation_lock(self) -> None:
        td = make_workspace("manual")
        root = Path(td.name)
        try:
            result = resolve_manifest(root)
            store = open_test_event_store(root)
            locked_paths: list[Path] = []

            @contextmanager
            def tracking_lock(path: Path):
                locked_paths.append(path)
                yield

            with mock.patch("rookery.portable.cli.file_lock", tracking_lock):
                scope = _persist_compiled_scope(
                    root,
                    store,
                    result.manifest,
                    compile_scope(result.manifest, 1),
                )

            self.assertEqual(locked_paths, [root / "state" / "mutation.lock"])
            self.assertEqual(scope["generation"], 1)
            self.assertEqual(store.get_meta("scope_generation"), "1")
        finally:
            td.cleanup()

    def test_every_unresolved_manifest_requirement_is_not_ready(self) -> None:
        td = make_workspace("manual")
        root = Path(td.name)
        try:
            ready_result = resolve_manifest(root)
            self.assertTrue(ready_result.ready)
            store = open_test_event_store(root)
            cases = (
                ("identity.name", lambda m: m["identity"].update(name="unknown")),
                ("adapter.id", lambda m: m["adapter"].update(id="unknown")),
                (
                    "scoring.action_kinds",
                    lambda m: m["scoring"].update(action_kinds=[]),
                ),
                (
                    "scope.acknowledged",
                    lambda m: m["scope"].update(acknowledged=False),
                ),
                (
                    "scope.allowed_hosts|allowed_cidrs|allowed_file_origins",
                    lambda m: m["scope"].update(
                        allowed_hosts=[], allowed_cidrs=[], allowed_file_origins=[]
                    ),
                ),
                (
                    "scope.max_attachment_bytes",
                    lambda m: m["scope"].update(max_attachment_bytes=0),
                ),
            )
            for expected, mutate in cases:
                with self.subTest(unresolved_required=expected):
                    manifest = copy.deepcopy(ready_result.manifest)
                    mutate(manifest)
                    result = validate_manifest(manifest)
                    self.assertIn(expected, result.unresolved_required)
                    self.assertFalse(result.ready)
                    snapshot = refresh_snapshot(store, root, result.manifest, result)
                    self.assertEqual(snapshot["lifecycle_state"], "unresolved")
                    self.assertIn(
                        f"configuration unresolved: {expected}",
                        snapshot["blockers"],
                    )

            snapshot = refresh_snapshot(
                store, root, ready_result.manifest, ready_result
            )
            self.assertEqual(snapshot["lifecycle_state"], "ready")
        finally:
            td.cleanup()

    def test_starter_commands_and_selected_roles_are_inventory_closed(self) -> None:
        td = make_workspace("manual")
        root = Path(td.name)
        try:
            result = resolve_manifest(root)
            for advanced_scoring in (False, True):
                with self.subTest(advanced_scoring=advanced_scoring):
                    manifest = copy.deepcopy(result.manifest)
                    if advanced_scoring:
                        manifest["surface"]["bundles"].append(
                            "advanced-scoring-review"
                        )
                    inventory = render_surface(root, manifest)
                    render_start_prompt(root, manifest, validate_manifest(manifest), inventory)
                    active_paths = {
                        str(tool["path"])
                        for tool in inventory["tools"]
                        if tool.get("path")
                    }
                    prompt = (root / "START_PROMPT.md").read_text(encoding="utf-8")
                    self.assertNotIn("|| true", prompt)
                    self.assertIn(
                        "Treat verified challenge intake as a solver-dispatch gate.",
                        prompt,
                    )
                    self.assertIn(
                        "recheck immutable detail and capture artifacts",
                        prompt,
                    )
                    self.assertIn(
                        "Do not dispatch when required material is missing, "
                        "a capture is unverified, or resources are truncated.",
                        prompt,
                    )
                    for command in re.findall(
                        r"^\./(bin/[A-Za-z0-9_.-]+)", prompt, flags=re.MULTILINE
                    ):
                        self.assertIn(command, active_paths)
                    for role in (root / ".codex" / "agents").glob("*.toml"):
                        for command in re.findall(
                            r"\./(bin/[A-Za-z0-9_.-]+)",
                            role.read_text(encoding="utf-8"),
                        ):
                            self.assertIn(command, active_paths, role.name)
                    selected_roles = {role["id"] for role in inventory["agents"]}
                    if advanced_scoring:
                        self.assertTrue(
                            {
                                "ctf_independent_review_auditor",
                                "ctf_submission_budget_steward",
                            }.issubset(selected_roles)
                        )
                    else:
                        self.assertNotIn(
                            "ctf_independent_review_auditor", selected_roles
                        )
                        self.assertNotIn(
                            "ctf_submission_budget_steward", selected_roles
                        )
        finally:
            td.cleanup()
