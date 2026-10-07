from __future__ import annotations

# ruff: noqa: E402

import json
import multiprocessing as mp
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from tests.rookery.support import (
    ROOKERY_ROOT,
    install_fixture_adapter,
    install_solver_ready_challenge,
    install_test_launch_binding,
    open_test_event_store,
)
from tests.rookery.env_fixtures import configure_event_environment

LIB = ROOKERY_ROOT / "lib"
if str(LIB) not in sys.path:
    sys.path.insert(0, str(LIB))
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

from rookery.portable.adapters import CommandAdapter, capture_file, get_adapter
from rookery.portable.compat import execute_plan_alias
from rookery.portable.compute import schedule_useful_jobs
from rookery.portable.control import mutation_guard, resume, stop
from rookery.portable.execution import compile_plan, execute_plan
from rookery.portable.environment import codex_shell_policy_toml
from rookery.portable.manifest import profile_has_platform_assumption, resolve_manifest
from rookery.portable.outcomes import confusion_brake, harvest_report, record_outcome
from rookery.portable.policy import set_policy
from rookery.portable.priority import rank_challenges
from rookery.portable.reducers import PLATFORM_HISTORY_LIMIT
from rookery.portable.queue import persist_schedules
from rookery.portable.reconciliation import correlation_ledger
from rookery.portable.registry import load_registry, render_surface, validate_admission
from rookery.portable.scope import check_cidr, check_file_origin, check_host, check_url, compile_scope
from rookery.portable.scoring import consume_authorization, create_proposal, grant_allowance, grant_exact, record_review
from rookery.portable.status import read_snapshot, refresh_snapshot, render_status
from rookery.portable.store import EventStore
from rookery.portable.util import atomic_write_json, load_json, tree_hash
from rookery.portable.validator import validate_tree
from rookery.portable.writeups import check_writeups, create_capsule, create_writeup


def make_workspace(
    profile: str = "fixture", *, deployed: bool = False
) -> tempfile.TemporaryDirectory:
    td = tempfile.TemporaryDirectory()
    root = Path(td.name)
    for rel in [
        ".agents",
        ".codex",
        "profiles",
        "registry",
        "agents",
        "configs",
        "docs",
        "lib",
        "bin",
        "prompts",
        "templates",
        "adapters",
        "extensions",
        "services",
        "knowledge",
    ]:
        src = ROOKERY_ROOT / rel
        if src.is_dir():
            shutil.copytree(
                src,
                root / rel,
                dirs_exist_ok=True,
                ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
            )
    if profile == "fixture":
        install_fixture_adapter(root)
    for rel in [
        ".env.example",
        "CHANGELOG.md",
        "release.json",
        "VERSION",
        "README.md",
        "AGENTS.md",
        "LICENSE",
        "go",
        "run-codex",
    ]:
        shutil.copy2(ROOKERY_ROOT / rel, root / rel)
    adapter_environment = {
        "ctfd": {
            "CTFD_URL": "https://fixture.invalid",
            "CTFD_TOKEN": "synthetic-fixture-token",
            "ADAPTER_CONFIG_BASE_URL": "https://fixture.invalid",
        },
        "htb": {
            "ADAPTER_CONFIG_INVENTORY_ARGV": json.dumps(
                [sys.executable, "-c", "print('{}')"]
            ),
            "ADAPTER_CONFIG_SUBMIT_ARGV": json.dumps(
                [sys.executable, "-c", "print('{}')"]
            ),
        },
    }
    configure_event_environment(root, profile, extra=adapter_environment.get(profile, {}))
    if deployed:
        return td
    # Core unit tests exercise library semantics, not public launch. Remove
    # both deployment markers before installing their explicitly synthetic
    # test-only binding.
    (root / "VERSION").unlink()
    (root / "bin" / "rookery").unlink()
    install_test_launch_binding(root)
    open_test_event_store(root)
    return td


def manifest_scope_store(root: Path):
    result = resolve_manifest(root)
    store = open_test_event_store(root)
    scope = compile_scope(result.manifest, 1)
    return result.manifest, scope, store, result


def stress_writer(root_text: str, worker: int, count: int):
    root = Path(root_text)
    sys.path.insert(0, str(ROOKERY_ROOT / "lib"))
    from rookery.portable.store import EventStore

    store = EventStore(root)
    aid = f"agent-{worker}"
    store.append(
        "agent.running",
        {"agent_id": aid, "objective_id": str(worker), "report_path": f"analysis/{aid}/REPORT.md"},
        actor=aid,
        event_id=f"agent-start-{worker}",
    )
    for i in range(count):
        pid = f"p-{worker}-{i}"
        store.append(
            "proposal.created",
            {
                "proposal_id": pid,
                "objective_id": str(worker),
                "action_kind": "flag",
                "exact_value": f"FIXTURE{{{worker}-{i}}}",
                "source": "fixture",
                "rationale": "stress",
                "stop_generation": 0,
            },
            actor=aid,
            event_id=f"proposal-{worker}-{i}",
        )
    store.append("agent.closed", {"agent_id": aid, "reason": "done"}, actor=aid, event_id=f"agent-close-{worker}")


def concurrent_policy_writer(root_text: str, worker: int):
    store = EventStore(Path(root_text))
    set_policy(
        store,
        "strategy",
        f"worker-{worker}",
        source=f"worker-{worker}",
        reason="concurrency regression",
    )


def concurrent_authorization_consumer(
    root_text: str,
    authorization: dict,
    worker: int,
    start: mp.Event,
):
    start.wait(10)
    try:
        consume_authorization(
            EventStore(Path(root_text)),
            authorization,
            plan_id=f"plan-{worker}",
            actor=f"executor-{worker}",
        )
        result = "consumed"
    except RuntimeError:
        result = "blocked"
    result_path = Path(root_text) / "results" / str(worker)
    result_path.parent.mkdir(parents=True, exist_ok=True)
    result_path.write_text(result, encoding="utf-8")


class ManifestAdapterScopeTests(unittest.TestCase):
    def test_command_adapter_keeps_candidate_in_one_argv_element(self):
        td = tempfile.TemporaryDirectory()
        root = Path(td.name)
        marker = root / "injected"
        manifest = {
            "identity": {"id": "fixture-event"},
            "adapter": {
                "config": {
                    "submit_command": [
                        sys.executable,
                        "-c",
                        "import json,sys; print(json.dumps({'success': True, 'correct': True, 'received': sys.argv[1]}))",
                        "{candidate}:{event}",
                    ]
                }
            },
        }
        adapter = CommandAdapter(root, manifest, {})
        candidates = [
            f"benign; printf injected > {marker}",
            "FLAG{accepted}",
            "FLAG{event}",
        ]
        for index, candidate in enumerate(candidates):
            result = adapter.execute_action(
                {
                    "objective_id": "101",
                    "exact_value": candidate,
                    "action_kind": "free_text",
                    "proposal_id": "proposal-fixture",
                },
                root / f"evidence-{index}",
            )
            self.assertEqual(result["response"]["returncode"], 0)
            response = json.loads(result["response"]["stdout"])
            self.assertEqual(response["received"], candidate + ":fixture-event")

        self.assertFalse(marker.exists())
        if os.name == "posix":
            self.assertEqual(
                stat.S_IMODE((root / "evidence-0").stat().st_mode),
                0o700,
            )
            self.assertEqual(
                stat.S_IMODE((root / "evidence-0/request.json").stat().st_mode),
                0o600,
            )
        with self.assertRaisesRegex(RuntimeError, "JSON argv array"):
            CommandAdapter(
                root,
                {
                    "adapter": {
                        "config": {"submit_command": "printf %s {candidate}"}
                    }
                },
                {},
            ).execute_action(
                {
                    "objective_id": "101",
                    "exact_value": candidate,
                    "action_kind": "free_text",
                },
                root / "legacy-evidence",
            )
        td.cleanup()

    def test_command_adapter_caps_combined_output(self):
        td = tempfile.TemporaryDirectory()
        root = Path(td.name)
        manifest = {
            "identity": {"id": "fixture-event"},
            "adapter": {
                "config": {
                    "max_output_bytes": 1024,
                    "submit_argv": [
                        sys.executable,
                        "-c",
                        "import os; os.write(1, b'A' * 1025)",
                    ],
                }
            },
        }
        adapter = CommandAdapter(root, manifest, {})
        for index in range(100):
            evidence = root / f"evidence-{index}"
            with self.assertRaisesRegex(RuntimeError, "output_limit"):
                adapter.execute_action(
                    {
                        "objective_id": "101",
                        "exact_value": "FIXTURE{value}",
                        "action_kind": "flag",
                    },
                    evidence,
                )

            response = load_json(evidence / "response.json", {})
            self.assertEqual(response["termination"], "output_limit")
            self.assertLessEqual(
                len(response["stdout"].encode())
                + len(response["stderr"].encode()),
                1024,
            )
        td.cleanup()

    def test_profiles_render_and_generic_is_neutral(self):
        for profile in ["manual", "ctfd", "fixture", "htb"]:
            td = make_workspace(profile)
            root = Path(td.name)
            result = resolve_manifest(root)
            self.assertFalse(result.errors, (profile, result.errors))
            self.assertEqual(result.manifest["profile"], profile)
            if profile in {"manual", "fixture"}:
                self.assertFalse(
                    profile_has_platform_assumption(result.manifest, ["ctfd", "htb", "immersive"]), profile
                )
            td.cleanup()

    def test_placeholder_environment_values_leave_profile_defaults_and_explicit_values_override(self):
        td = make_workspace("manual", deployed=True)
        root = Path(td.name)
        defaults = resolve_manifest(
            root,
            env={"PLATFORM_ADAPTER": "manual", "EVENT_NAME": "unknown", "FLAG_REGEX": "unknown"},
        )
        self.assertEqual(defaults.manifest["identity"]["name"], "unknown")
        self.assertEqual(defaults.manifest["answer_morphology"]["regex"], "unknown")

        explicit = resolve_manifest(
            root,
            env={
                "PLATFORM_ADAPTER": "manual",
                "EVENT_ID": "canonical-event",
                "EVENT_NAME": "Canonical Event",
                "EVENT_SCOPE_ACK": "1",
                "ALLOWED_HOSTS": "fixture.invalid",
                "SCOPE_MAX_BYTES": "4096",
                "FLAG_REGEX": r"FIXTURE\{[^}]+\}",
            },
        )
        self.assertEqual(explicit.manifest["identity"]["name"], "Canonical Event")
        self.assertTrue(explicit.manifest["scope"]["acknowledged"])
        self.assertEqual(
            explicit.manifest["answer_morphology"]["regex"],
            r"FIXTURE\{[^}]+\}",
        )
        td.cleanup()

    def test_two_adapters_normalize(self):
        for profile in ["fixture", "manual"]:
            td = make_workspace(profile)
            root = Path(td.name)
            if profile == "manual":
                (root / "platform").mkdir()
                atomic_write_json(
                    root / "platform/manual_inventory.json",
                    {"challenges": [{"id": "manual-1", "name": "Manual", "category": "misc", "points": 1}]},
                )
            manifest, scope, store, result = manifest_scope_store(root)
            snapshot = get_adapter(root, manifest, scope).sync()
            self.assertIn("capabilities", snapshot)
            self.assertIn("challenges", snapshot)
            self.assertGreaterEqual(len(snapshot["challenges"]), 1)
            td.cleanup()

    def test_scope_refuses_stale_broad_offscope_and_oversize(self):
        td = make_workspace()
        root = Path(td.name)
        manifest, scope, store, result = manifest_scope_store(root)
        self.assertTrue(check_host(scope, "192.0.2.10", port=31337, protocol="tcp").allowed)
        self.assertFalse(check_host(scope, "198.51.100.10", port=31337, protocol="tcp").allowed)
        wildcard_scope = {**scope, "allowed_hosts": ["*.Example.Test."]}
        self.assertTrue(check_host(wildcard_scope, "direct.example.test").allowed)
        self.assertTrue(check_host(wildcard_scope, "nested.direct.example.test.").allowed)
        self.assertFalse(check_host(wildcard_scope, "example.test").allowed)
        self.assertFalse(check_cidr(scope, "10.0.0.0/8").allowed)
        self.assertFalse(check_file_origin(scope, "fixture://large", size=1048577).allowed)
        invalid_url = check_url(scope, "http://fixture.invalid:not-a-port")
        self.assertFalse(invalid_url.allowed)
        self.assertIn("invalid URL", invalid_url.reason)
        stale = dict(scope)
        stale["expires_at"] = "2000-01-01T00:00:00Z"
        self.assertFalse(check_url(stale, "http://fixture.invalid").allowed)
        td.cleanup()

    def test_capture_file_bounds_local_reads(self):
        td = tempfile.TemporaryDirectory()
        root = Path(td.name)
        source = root / "source.bin"
        source.write_bytes(b"x" * 4096)
        scope = {
            "acknowledged": True,
            "generation": 1,
            "expires_at": "unknown",
            "allowed_file_origins": ["source.bin"],
            "max_attachment_bytes": 32,
        }
        with mock.patch.object(Path, "read_bytes", side_effect=AssertionError("unbounded read")):
            with self.assertRaisesRegex(RuntimeError, "attachment exceeds declared byte bound"):
                capture_file(root, scope, {"path": "source.bin"}, root / "captured.bin")
        self.assertFalse((root / "captured.bin").exists())
        td.cleanup()


class StatePolicyStopTests(unittest.TestCase):
    def test_empty_state_rebuild_is_byte_stable(self):
        td = tempfile.TemporaryDirectory()
        root = Path(td.name)
        store = EventStore(root)
        store.rebuild()
        first = (root / "state/runtime.json").read_bytes()
        store.rebuild()
        second = (root / "state/runtime.json").read_bytes()
        self.assertEqual(first, second)
        self.assertEqual(
            load_json(root / "state/current.json", {})["updated_at"],
            "1970-01-01T00:00:00Z",
        )
        td.cleanup()

    def test_32_process_state_stress_and_stable_rebuild(self):
        td = tempfile.TemporaryDirectory()
        root = Path(td.name)
        store = EventStore(root)
        processes = [mp.Process(target=stress_writer, args=(str(root), i, 20)) for i in range(32)]
        for p in processes:
            p.start()
        for p in processes:
            p.join(30)
            self.assertEqual(p.exitcode, 0)
        self.assertEqual(store.count(), 32 * 22)
        projection = store.rebuild()
        self.assertEqual(len(projection["current"]["proposals"]), 32 * 20)
        self.assertEqual(projection["current"]["counts"]["active_agents"], 0)
        first = (root / "state/runtime.json").read_bytes()
        store.rebuild()
        second = (root / "state/runtime.json").read_bytes()
        self.assertEqual(first, second)
        json.loads((root / "state/current.json").read_text())
        td.cleanup()

    def test_policy_supersession_and_restart(self):
        td = make_workspace()
        root = Path(td.name)
        store = EventStore(root)
        one = set_policy(store, "strategy", "speed", source="operator", reason="opening")
        two = set_policy(store, "strategy", "points", source="operator", reason="late event")
        self.assertGreater(two["generation"], one["generation"])
        restarted = EventStore(root).rebuild()["policy"]
        self.assertEqual(restarted["effective"]["strategy"]["value"], "points")
        self.assertEqual(len(restarted["history"]["strategy"]), 2)
        td.cleanup()

    def test_concurrent_policy_updates_use_unique_generations(self):
        td = tempfile.TemporaryDirectory()
        root = Path(td.name)
        EventStore(root)
        processes = [mp.Process(target=concurrent_policy_writer, args=(str(root), worker)) for worker in range(8)]
        for process in processes:
            process.start()
        for process in processes:
            process.join(30)
            self.assertEqual(process.exitcode, 0)
        events = EventStore(root).events("policy.set")
        generations = [int(event["payload"]["generation"]) for event in events]
        self.assertEqual(len(generations), 8)
        self.assertEqual(sorted(generations), list(range(1, 9)))
        td.cleanup()

    def test_stop_generation_blocks_mutation_and_revokes(self):
        td = make_workspace()
        root = Path(td.name)
        manifest, scope, store, result = manifest_scope_store(root)
        resume(store, reason="test")
        install_solver_ready_challenge(root, store)
        proposal = create_proposal(
            store,
            manifest,
            objective_id="101",
            action_kind="flag",
            exact_value="FIXTURE{accepted}",
            source="analysis/report",
            rationale="test",
        )
        record_review(store, proposal["proposal_id"], "approved", reviewer="independent", reason="verified")
        grant_allowance(store, manifest, "flag", 2, reason="test")
        generation = store.current_stop_generation()
        out = stop(store, root, reason="test stop", wait_seconds=0.1)
        self.assertEqual(out["generation"], generation + 1)
        with self.assertRaises(RuntimeError):
            mutation_guard(store, generation)
        auth = store.rebuild()["current"]["authorizations"]
        self.assertTrue(all(int(x.get("remaining", 0)) == 0 or x.get("status") != "granted" for x in auth.values()))
        td.cleanup()


class ScoringQueueExecutionTests(unittest.TestCase):
    def setUp(self):
        self.td = make_workspace("fixture")
        self.root = Path(self.td.name)
        self.manifest, self.scope, self.store, self.result = manifest_scope_store(self.root)
        resume(self.store, reason="test start")
        snapshot = get_adapter(self.root, self.manifest, self.scope).sync()
        self.store.append("platform.snapshot", snapshot, actor="fixture")
        install_solver_ready_challenge(self.root, self.store)

    def tearDown(self):
        self.td.cleanup()

    def _approved(self, value="FIXTURE{accepted}", kind="flag"):
        proposal = create_proposal(
            self.store,
            self.manifest,
            objective_id="101",
            action_kind=kind,
            exact_value=value if kind not in {"proof_artifact", "no_submit_evidence"} else "",
            artifact_reference="evidence/proof.bin" if kind in {"proof_artifact", "no_submit_evidence"} else "",
            source="analysis/test/REPORT.md",
            rationale="fixture",
        )
        record_review(
            self.store,
            proposal["proposal_id"],
            "approved",
            reviewer="reviewer-1",
            reason="fixture verified",
            verifier_report="analysis/verify/REPORT.md",
        )
        return proposal

    def test_all_declared_action_kinds_propose(self):
        install_solver_ready_challenge(self.root, self.store, "x-flag")
        install_solver_ready_challenge(self.root, self.store, "x-free_text")
        for kind in ["flag", "free_text", "multi_objective", "proof_artifact", "no_submit_evidence"]:
            p = create_proposal(
                self.store,
                self.manifest,
                objective_id=f"x-{kind}",
                action_kind=kind,
                exact_value="value" if kind not in {"proof_artifact", "no_submit_evidence"} else "",
                artifact_reference="evidence/proof" if kind in {"proof_artifact", "no_submit_evidence"} else "",
                source="analysis/report",
                rationale="test",
            )
            self.assertEqual(p["action_kind"], kind)

    def test_proposal_and_correlation_retain_agent_attempt_lineage(self):
        self.store.append(
            "agent.running",
            {
                "agent_id": "agent-fixture",
                "agent_attempt_id": "attempt-fixture",
                "objective_id": "101",
                "role": "worker",
                "report_path": "analysis/attempt/REPORT.md",
            },
            actor="coordinator",
        )
        proposal = create_proposal(
            self.store,
            self.manifest,
            objective_id="101",
            action_kind="flag",
            exact_value="FIXTURE{candidate}",
            source="analysis/attempt/REPORT.md",
            rationale="attempt lineage",
            agent_attempt_id="attempt-fixture",
            actor="agent-fixture",
        )
        ledger = correlation_ledger(self.store)
        row = next(
            row
            for row in ledger["rows"]
            if row["proposal_id"] == proposal["proposal_id"]
        )
        self.assertEqual(row["agent_attempt_id"], "attempt-fixture")

    def test_preflight_does_not_consume_then_execute_is_idempotent(self):
        proposal = self._approved()
        auth = grant_exact(self.store, proposal["proposal_id"], reason="manual")
        plan = compile_plan(self.store, self.root, self.manifest, self.scope, proposal["proposal_id"])
        before = self.store.rebuild()["current"]["authorizations"][auth["authorization_id"]]["remaining"]
        self.assertEqual(before, 1)
        result, rc = execute_plan(self.store, self.root, self.manifest, self.scope, plan["plan_id"])
        self.assertEqual(rc, 0)
        self.assertEqual(result["status"], "completed")
        result2, rc2 = execute_plan(self.store, self.root, self.manifest, self.scope, plan["plan_id"])
        self.assertTrue(result2["idempotent"])
        self.assertEqual(rc2, 0)
        correlation = correlation_ledger(self.store)
        row = next(
            row
            for row in correlation["rows"]
            if row["proposal_id"] == proposal["proposal_id"]
        )
        self.assertNotIn("exact_value", row)
        self.assertEqual(row["value_sha256"], proposal["value_sha256"])
        self.assertEqual(len(row["plans"]), 1)
        self.assertTrue(row["plans"][0]["complete_chain"])
        self.assertTrue(row["plans"][0]["authorization_event_id"])
        self.assertTrue(row["plans"][0]["started_event_id"])

    def test_exact_authorization_is_consumed_once_under_concurrency(self):
        proposal = self._approved()
        authorization = grant_exact(self.store, proposal["proposal_id"], reason="single use")
        start = mp.Event()
        processes = [
            mp.Process(
                target=concurrent_authorization_consumer,
                args=(str(self.root), authorization, worker, start),
            )
            for worker in range(8)
        ]
        for process in processes:
            process.start()
        start.set()
        for process in processes:
            process.join(30)
            self.assertEqual(process.exitcode, 0)
        results = [path.read_text(encoding="utf-8") for path in (self.root / "results").iterdir()]
        self.assertEqual(results.count("consumed"), 1)
        self.assertEqual(results.count("blocked"), 7)

    def test_same_plan_executes_once_with_multi_count_allowance(self):
        proposal = self._approved()
        authorization = grant_allowance(
            self.store,
            self.manifest,
            "flag",
            2,
            reason="bounded",
        )
        plan = compile_plan(
            self.store,
            self.root,
            self.manifest,
            self.scope,
            proposal["proposal_id"],
        )
        adapter = get_adapter(self.root, self.manifest, self.scope)
        executor_count = 32
        start = threading.Barrier(executor_count + 1)
        results: list[tuple[dict, int]] = []

        def run_plan() -> None:
            start.wait(timeout=5)
            results.append(
                execute_plan(
                    EventStore(self.root),
                    self.root,
                    self.manifest,
                    self.scope,
                    plan["plan_id"],
                )
            )

        threads = [threading.Thread(target=run_plan) for _ in range(executor_count)]
        with (
            mock.patch("rookery.portable.execution.get_adapter", return_value=adapter),
            mock.patch.object(
                adapter,
                "execute_action",
                wraps=adapter.execute_action,
            ) as execute_action,
        ):
            for thread in threads:
                thread.start()
            start.wait(timeout=5)
            for thread in threads:
                thread.join(timeout=10)

        self.assertTrue(all(not thread.is_alive() for thread in threads))
        self.assertEqual(len(results), executor_count)
        self.assertEqual(execute_action.call_count, 1)
        self.assertEqual(
            sum(1 for result, _rc in results if result.get("idempotent")),
            executor_count - 1,
        )
        current = self.store.rebuild()["current"]
        self.assertEqual(
            current["authorizations"][authorization["authorization_id"]]["remaining"],
            1,
        )
        terminals = [
            event
            for event in self.store.events("execution.completed")
            if event["payload"].get("plan_id") == plan["plan_id"]
        ]
        self.assertEqual(len(terminals), 1)

    def test_execution_alias_has_a_bounded_timeout(self):
        plan_id = "plan_fixture"
        path = self.root / "state/execution_plans" / f"{plan_id}.json"
        atomic_write_json(path, {"semantic_action": "flag", "adapter_id": "fixture"})
        with mock.patch(
            "rookery.portable.compat.subprocess.run",
            side_effect=subprocess.TimeoutExpired(["rookery"], timeout=1),
        ):
            with self.assertRaisesRegex(RuntimeError, "timed out"):
                execute_plan_alias(self.root, plan_id, allowed_actions={"flag"}, timeout=1)

    def test_http200_rejection_fails_closed(self):
        proposal = self._approved("FIXTURE{rejected}")
        grant_exact(self.store, proposal["proposal_id"], reason="manual")
        plan = compile_plan(self.store, self.root, self.manifest, self.scope, proposal["proposal_id"])
        result, rc = execute_plan(self.store, self.root, self.manifest, self.scope, plan["plan_id"])
        self.assertEqual(rc, 1)
        self.assertEqual(result["status"], "rejected")
        self.assertEqual(result["verdict"]["scorer_truth"], "rejected")

    def test_queue_schedule_stable_and_escalates_once(self):
        self.manifest["queue"] = {
            "automation_enabled": True,
            "cadence_seconds": 10,
            "jitter_seconds": 5,
            "latency_objective_seconds": 1,
        }
        self._approved()
        grant_allowance(self.store, self.manifest, "flag", 1, reason="test")
        first = persist_schedules(self.store, self.manifest)
        schedule1 = first["items"][0]["scheduled_at"]
        second = persist_schedules(EventStore(self.root), self.manifest)
        self.assertEqual(schedule1, second["items"][0]["scheduled_at"])
        escalations = self.store.events("queue.escalated")
        self.assertLessEqual(len(escalations), 1)


class PriorityOutcomeStatusComputeSurfaceWriteupTests(unittest.TestCase):
    def setUp(self):
        self.td = make_workspace("fixture")
        self.root = Path(self.td.name)
        self.manifest, self.scope, self.store, self.result = manifest_scope_store(self.root)
        resume(self.store, reason="test")
        install_solver_ready_challenge(self.root, self.store)

    def tearDown(self):
        self.td.cleanup()

    def test_priority_modes_differ_and_explain(self):
        challenges = [
            {
                "id": "a",
                "points": 500,
                "solve_count": 100,
                "expected_effort": 0.9,
                "evidence_maturity": 0.9,
                "released_at": "2026-01-01T00:00:00Z",
            },
            {
                "id": "b",
                "points": 100,
                "solve_count": 1,
                "expected_effort": 0.1,
                "evidence_maturity": 0.1,
                "released_at": "2026-01-02T00:00:00Z",
            },
        ]
        base = rank_challenges(challenges, self.manifest)
        self.assertTrue(all(x.get("priority_reason") for x in base))
        points = json.loads(json.dumps(self.manifest))
        points["priority"]["weights"]["value"] = 5.0
        speed = json.loads(json.dumps(self.manifest))
        speed["priority"]["weights"]["expected_effort"] = -5.0
        self.assertNotEqual(
            [x["id"] for x in rank_challenges(challenges, points)],
            [x["id"] for x in rank_challenges(challenges, speed)],
        )

    def test_platform_history_is_bounded_compact_and_canonical_events_remain_complete(self):
        initial_count = len(self.store.events("platform.snapshot"))
        appended_count = PLATFORM_HISTORY_LIMIT + 8
        for index in range(appended_count):
            self.store.append(
                "platform.snapshot",
                {
                    "adapter_id": "fixture",
                    "secret_marker": f"snapshot-value-{index}",
                    "capabilities": {"inventory": {"health": "healthy"}},
                    "challenges": [
                        {
                            "id": str(index),
                            "title": f"challenge-value-{index}",
                            "points": index,
                        }
                    ],
                },
                actor="fixture",
            )

        canonical = self.store.events("platform.snapshot")
        projection = self.store.rebuild()
        history = projection["platform_history"]

        self.assertEqual(len(canonical), initial_count + appended_count)
        self.assertEqual(
            canonical[initial_count]["payload"]["secret_marker"],
            "snapshot-value-0",
        )
        self.assertEqual(
            canonical[-1]["payload"]["secret_marker"],
            f"snapshot-value-{PLATFORM_HISTORY_LIMIT + 7}",
        )
        self.assertEqual(len(history), PLATFORM_HISTORY_LIMIT)
        self.assertEqual(history[0]["event_id"], canonical[-PLATFORM_HISTORY_LIMIT]["event_id"])
        self.assertEqual(history[-1]["event_id"], canonical[-1]["event_id"])
        self.assertEqual(
            set(history[-1]),
            {
                "event_id",
                "event_at",
                "stop_generation",
                "actor",
                "adapter_id",
                "challenge_count",
                "capability_count",
            },
        )
        self.assertNotIn("snapshot-value", json.dumps(history))
        self.assertNotIn("challenge-value", json.dumps(history))
        self.assertEqual(
            projection["current"]["platform"]["secret_marker"],
            f"snapshot-value-{PLATFORM_HISTORY_LIMIT + 7}",
        )

    def test_sparse_platform_snapshot_preserves_materialized_intake(self):
        materialized = {
            "id": "intake-fixture",
            "title": "Old summary",
            "points": 100,
            "solved": False,
            "hidden": False,
            "solvable": True,
            "submission_mode": "text",
            "raw": {"revision": "old"},
            "description": "materialized text",
            "description_text": "materialized text",
            "description_html": "<p>materialized text</p>",
            "text": "materialized text",
            "html": "<p>materialized text</p>",
            "detail_metadata": {"source": "detail"},
            "metadata": {"manual_grade": False},
            "detail_path": "platform/challenges/intake-fixture/attempt/detail.json",
            "detail_sha256": "a" * 64,
            "detail_bytes": 123,
            "files": [{"name": "evidence.zip"}],
            "resources": [{"kind": "attachment"}],
            "resources_complete": True,
            "resources_truncated": False,
            "hints": ["detail hint"],
            "tags": ["forensics"],
            "captured_files": [{"path": "private/evidence.zip"}],
            "expected_file_count": 1,
            "captured_file_count": 1,
            "intake_attempt_id": "intake_fixture",
            "intake_attempt_count": 1,
            "intake_state": "complete",
            "intake_missing_material": [],
            "intake_custom_marker": "preserved",
            "ingested_at": "2026-10-02T00:00:00Z",
        }
        self.store.append("challenge.upsert", materialized, actor="platform")
        self.store.append(
            "platform.snapshot",
            {
                "adapter_id": "fixture",
                "artifact": "platform/normalized/latest.json",
                "challenges": [
                    {
                        "id": "intake-fixture",
                        "title": "Latest summary",
                        "points": 250,
                        "solved": True,
                        "hidden": True,
                        "solvable": False,
                        "submission_mode": "manual",
                        "raw": {"revision": "latest"},
                        "description": "",
                        "files": [],
                        "resources": [],
                        "resources_complete": False,
                    }
                ],
            },
            actor="platform",
        )

        challenge = self.store.rebuild()["current"]["challenges"]["intake-fixture"]

        for key in (
            "description",
            "description_text",
            "description_html",
            "text",
            "html",
            "detail_metadata",
            "metadata",
            "detail_path",
            "detail_sha256",
            "detail_bytes",
            "files",
            "resources",
            "resources_complete",
            "resources_truncated",
            "hints",
            "tags",
            "captured_files",
            "expected_file_count",
            "captured_file_count",
            "intake_attempt_id",
            "intake_attempt_count",
            "intake_state",
            "intake_missing_material",
            "intake_custom_marker",
            "ingested_at",
        ):
            with self.subTest(key=key):
                self.assertEqual(challenge[key], materialized[key])
        self.assertEqual(challenge["title"], "Latest summary")
        self.assertEqual(challenge["points"], 250)
        self.assertTrue(challenge["solved"])
        self.assertTrue(challenge["hidden"])
        self.assertFalse(challenge["solvable"])
        self.assertEqual(challenge["submission_mode"], "manual")
        self.assertEqual(challenge["raw"], {"revision": "latest"})
        self.assertEqual(challenge["source"], "platform/normalized/latest.json")

    def test_priority_keeps_unavailable_rows_visible_but_out_of_foreground(self):
        cases = {
            "solved-flag": ({"solved": True}, "solved"),
            "solved-mode": ({"submission_mode": "already_solved"}, "solved"),
            "hidden": ({"hidden": True}, "hidden"),
            "unsolvable": ({"solvable": False}, "unsupported"),
            "policy": ({"classification": "policy_blocked"}, "policy_blocked"),
            "operator": ({"classification": "operator_only"}, "operator_only"),
            "locked": ({"submission_mode": "locked"}, "locked"),
            "manual": ({"submission_mode": "manual"}, "manual"),
            "multiple-choice": ({"submission_mode": "multiple_choice"}, "unsupported"),
            "unsupported": ({"submission_mode": "unsupported"}, "unsupported"),
            "intake-pending": ({"intake_state": "pending"}, "intake_pending"),
            "intake-partial": ({"intake_state": "partial"}, "intake_partial"),
            "intake-invalid": ({"intake_state": "unexpected"}, "intake_invalid"),
            "unavailable": ({"platform_present": False}, "unavailable"),
            "explicit": (
                {
                    "solver_eligible": False,
                    "solver_ineligible_reason": "intake_partial",
                },
                "intake_partial",
            ),
            "explicit-unknown": (
                {
                    "solver_eligible": False,
                    "solver_ineligible_reason": "contains-a-platform-value",
                },
                "solver_ineligible",
            ),
            "raw-platform-mode": (
                {"raw": {"submissionMode": "locked"}},
                "locked",
            ),
        }
        challenges = [
            {"id": challenge_id, "points": 100, **fields}
            for challenge_id, (fields, _reason) in cases.items()
        ]

        ranked = rank_challenges(challenges, self.manifest)

        self.assertEqual({row["id"] for row in ranked}, set(cases))
        by_id = {row["id"]: row for row in ranked}
        for challenge_id, (_fields, expected_reason) in cases.items():
            with self.subTest(challenge_id=challenge_id):
                row = by_id[challenge_id]
                self.assertEqual(row["priority_score"], -999.0)
                self.assertEqual(row["frontier_tier"], 9)
                self.assertFalse(row["foreground_eligible"])
                self.assertFalse(row["solver_eligible"])
                self.assertEqual(row["solver_ineligible_reason"], expected_reason)

    def test_priority_keeps_generic_and_complete_intake_rows_compatible(self):
        ranked = rank_challenges(
            [
                {"id": "generic", "points": 100},
                {"id": "complete", "points": 100, "intake_state": "complete"},
            ],
            self.manifest,
        )

        self.assertEqual({row["id"] for row in ranked}, {"generic", "complete"})
        self.assertTrue(all(row["solver_eligible"] for row in ranked))
        self.assertTrue(all(row["foreground_eligible"] for row in ranked))
        self.assertTrue(all(row["solver_ineligible_reason"] == "" for row in ranked))

    def test_outcome_recovery_brake_and_exactly_once_harvest(self):
        report = self.root / "analysis/x/REPORT.md"
        report.parent.mkdir(parents=True)
        report.write_text("# report\n")
        for i in range(3):
            self.store.append(
                "agent.running",
                {
                    "agent_id": f"a{i}",
                    "agent_attempt_id": f"attempt-{i}",
                    "objective_id": "x",
                    "role": "worker",
                    "report_path": "analysis/x/REPORT.md",
                },
                actor="fixture",
            )
            record_outcome(
                self.store,
                agent_id=f"a{i}",
                objective_id="x",
                outcome_type="technical_negative",
                report_path="analysis/x/REPORT.md",
                summary="same",
                mechanism="same-mechanism",
                agent_attempt_id=f"attempt-{i}",
            )
        self.assertTrue(confusion_brake(self.store, "x", "same-mechanism")["brake"])
        harvest_report(self.store, self.root, "analysis/x/REPORT.md")
        second = harvest_report(self.store, self.root, "analysis/x/REPORT.md")
        self.assertTrue(second["idempotent"])
        self.store.append(
            "agent.running",
            {
                "agent_id": "r",
                "agent_attempt_id": "attempt-r",
                "objective_id": "x",
                "role": "worker",
                "report_path": "analysis/x/REPORT.md",
            },
            actor="fixture",
        )
        record_outcome(
            self.store,
            agent_id="r",
            objective_id="x",
            outcome_type="generic_refusal",
            report_path="analysis/x/REPORT.md",
            summary="refused",
            agent_attempt_id="attempt-r",
        )
        self.assertTrue(
            any(
                e["payload"].get("method") == "default-worker-short-context"
                for e in self.store.events("retry.scheduled")
            )
        )

    def test_status_is_pure_read(self):
        snapshot = refresh_snapshot(self.store, self.root, self.manifest)
        self.assertEqual(snapshot["release_version"], "unknown")
        before = tree_hash(self.root)
        for _ in range(5):
            read_snapshot(self.root)
        after = tree_hash(self.root)
        self.assertEqual(before, after)

    def test_uninitialized_status_is_explicit(self):
        td = tempfile.TemporaryDirectory()
        root = Path(td.name)
        (root / "VERSION").write_text("2026.08.28\n", encoding="utf-8")
        snapshot = read_snapshot(root)
        rendered = render_status(snapshot)
        self.assertIn("state=uninitialized", rendered)
        self.assertIn(
            f"version={(root / 'VERSION').read_text(encoding='utf-8').strip()}",
            rendered,
        )
        self.assertIn("message=run ./go to initialize status", rendered)
        td.cleanup()

    def test_required_startup_failure_is_blocked_in_status(self):
        atomic_write_json(
            self.root / "state/startup_checks.json",
            {
                "checks": [
                    {
                        "name": "required-fixture",
                        "classification": "required",
                        "ok": False,
                    }
                ]
            },
        )
        snapshot = refresh_snapshot(self.store, self.root, self.manifest)
        self.assertEqual(snapshot["lifecycle_state"], "blocked")
        self.assertIn("state=blocked", render_status(read_snapshot(self.root)))

    def test_useful_compute_idles_and_reserves(self):
        jobs = [
            {
                "job_id": "good",
                "cost_units": 3,
                "expected_value": 3,
                "evidence_value": 1,
                "budget_remaining_seconds": 100,
                "checkpointable": True,
            },
            {
                "job_id": "bad",
                "cost_units": 1,
                "expected_value": 1,
                "budget_remaining_seconds": 0,
                "checkpointable": True,
            },
        ]
        out = schedule_useful_jobs(jobs, self.manifest)
        self.assertEqual(out["interactive_reserve_units"], 2)
        self.assertEqual([x["job_id"] for x in out["selected"]], ["good"])
        self.assertGreaterEqual(out["idle_units"], 0)
        self.assertEqual(out["retired"][0]["job_id"], "bad")

    def test_surface_profiles_and_persona_admission(self):
        self.assertFalse(validate_admission(load_registry(self.root, "agents")))
        inv = render_surface(self.root, self.manifest)
        rendered_config = (self.root / ".codex/config.toml").read_text(encoding="utf-8")
        self.assertIn(codex_shell_policy_toml(), rendered_config)
        ids = {x["id"] for x in inv["agents"]}
        self.assertFalse(any("htb" in x for x in ids))
        configure_event_environment(self.root, "htb")
        manifest, scope, store, result = manifest_scope_store(self.root)
        inv2 = render_surface(self.root, manifest)
        self.assertTrue(any("htb" in x["id"] for x in inv2["agents"]))
        rendered_overlay = (self.root / ".codex/config.toml").read_text(encoding="utf-8")
        self.assertIn(codex_shell_policy_toml(), rendered_overlay)

    def test_capsule_then_closeout_writeup(self):
        proposal = create_proposal(
            self.store,
            self.manifest,
            objective_id="101",
            action_kind="flag",
            exact_value="FIXTURE{accepted}",
            source="analysis/test/REPORT.md",
            rationale="canonical capsule fixture",
            actor="solver-a",
        )
        record_review(
            self.store,
            proposal["proposal_id"],
            "approved",
            reviewer="reviewer-b",
            reason="independent fixture review",
        )
        grant_exact(self.store, proposal["proposal_id"], reason="fixture authority")
        plan = compile_plan(
            self.store, self.root, self.manifest, self.scope, proposal["proposal_id"]
        )
        execution, return_code = execute_plan(
            self.store, self.root, self.manifest, self.scope, plan["plan_id"]
        )
        self.assertEqual(return_code, 0)
        create_capsule(
            self.store,
            self.root,
            objective_id="101",
            action_reference=plan["plan_id"],
            scorer_evidence=execution["evidence_root"],
            reproduction_path="exploit/solve.py",
            material_provenance=["analysis/report"],
            dead_path_checkpoint="none",
        )
        self.assertTrue(check_writeups(self.store, self.root, self.manifest, closeout=False)["ok"])
        close = check_writeups(self.store, self.root, self.manifest, closeout=True)
        self.assertIn("101", close["missing_writeups"])
        create_writeup(self.root, "101", "Fixture Challenge")
        self.assertTrue(check_writeups(self.store, self.root, self.manifest, closeout=True)["ok"])


class ValidatorTests(unittest.TestCase):
    def test_validator_read_only_and_contamination(self):
        td = make_workspace("manual", deployed=True)
        root = Path(td.name)
        before = tree_hash(root)
        report = validate_tree(root, adapter="manual", strict_release=True)
        after = tree_hash(root)
        self.assertEqual(before, after)
        self.assertTrue(report["ok"], report["errors"])
        unexpected = root / "unexpected-root"
        unexpected.mkdir()
        (unexpected / "file.txt").write_text("unexpected\n")
        bad_root = validate_tree(root, adapter="manual", strict_release=True)
        self.assertTrue(
            any("undeclared top-level release path: unexpected-root" in error for error in bad_root["errors"])
        )
        shutil.rmtree(unexpected)
        mystery = root / "MYSTERY_FILE.txt"
        mystery.write_text("unexpected\n")
        bad_file = validate_tree(root, adapter="manual", strict_release=True)
        self.assertTrue(
            any("undeclared top-level release path: MYSTERY_FILE.txt" in error for error in bad_file["errors"])
        )
        mystery.unlink()
        command = root / "bin/rookery"
        original_mode = command.stat().st_mode
        command.chmod(original_mode & ~0o111)
        bad_mode = validate_tree(root, adapter="manual", strict_release=True)
        self.assertIn("deployed command is not executable: bin/rookery", bad_mode["errors"])
        command.chmod(original_mode)
        environment = root / ".env"
        operator_value = "fixture-session-value-123456"
        configure_event_environment(
            root,
            "ctfd",
            extra={
                "CTFD_URL": "https://fixture.invalid",
                "CTFD_TOKEN": operator_value,
                "ADAPTER_CONFIG_BASE_URL": "https://fixture.invalid",
            },
        )
        release_report = validate_tree(root, adapter="ctfd", strict_release=True)
        self.assertTrue(release_report["ok"], release_report["errors"])
        self.assertNotIn(operator_value, json.dumps(release_report))

        # Installed validation parses the selected live dotenv but reports only
        # value-free field errors. Source-checkout validation remains template-only.
        valid_environment = environment.read_text(encoding="utf-8")
        environment.write_text(
            valid_environment + "not-an-assignment\n", encoding="utf-8"
        )
        malformed = validate_tree(root, adapter="ctfd", strict_release=True)
        self.assertFalse(malformed["ok"])
        self.assertNotIn(operator_value, json.dumps(malformed))
        source_report = validate_tree(
            root,
            adapter="ctfd",
            strict_release=True,
            source_checkout=True,
        )
        self.assertTrue(source_report["ok"], source_report["errors"])
        self.assertNotIn(operator_value, json.dumps(source_report))
        from rookery.portable.environment import EnvironmentPolicyError, resolve_launch_gate

        with self.assertRaisesRegex(EnvironmentPolicyError, "is not a valid assignment"):
            resolve_launch_gate(root, parent={})
        self.assertFalse((root / "state").exists())
        td.cleanup()


if __name__ == "__main__":
    unittest.main(verbosity=2)
