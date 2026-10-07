from __future__ import annotations

# ruff: noqa: E402, I001

import io
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from collections.abc import Callable
from contextlib import redirect_stdout
from dataclasses import dataclass
from pathlib import Path
from unittest import mock

from tests.rookery.support import (
    ROOKERY_ROOT,
    TESTS_ROOT,
    PublicWorkspaceBootstrap,
    bootstrap_public_workspace,
    install_fixture_adapter,
    install_solver_ready_challenge,
    install_test_launch_binding,
    open_test_event_store,
    rebind_test_workspace,
    render_handoff_report,
)
from tests.rookery.env_fixtures import (
    configure_event_environment,
    replace_env_assignments,
)

LIB = ROOKERY_ROOT / "lib"
if str(LIB) not in sys.path:
    sys.path.insert(0, str(LIB))
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

from rookery.portable.adapters import get_adapter
from rookery.portable.cli import build_parser, cmd_go, cmd_queue, startup_checks
from rookery.portable.compute import schedule_useful_jobs
from rookery.portable.control import resume, stop
from rookery.portable.execution import compile_plan, execute_plan
from rookery.portable.lessons import create_lessons_document
from rookery.portable.manifest import profile_has_platform_assumption, resolve_manifest
from rookery.portable.outcomes import record_outcome
from rookery.portable.owned_paths import objective_storage_component
from rookery.portable.policy import set_policy
from rookery.portable.priority import rank_challenges
from rookery.portable.queue import build_queue, persist_schedules
from rookery.portable.reconciliation import (
    answer_ledger,
    import_response,
    record_task_completion,
    task_completion_audit,
)
from rookery.portable.registry import render_surface, validate_admission
from rookery.portable.scope import (
    check_cidr,
    check_file_origin,
    check_host,
    check_url,
    compile_scope,
)
from rookery.portable.scoring import (
    claim_plan_authority,
    create_proposal,
    grant_allowance,
    grant_exact,
    record_review,
)
from rookery.portable.status import read_snapshot, refresh_snapshot
from rookery.portable.store import EventStore
from rookery.portable.util import atomic_write_json, load_json, tree_hash
from rookery.portable.validator import validate_tree
from rookery.portable.watchers import ensure_queue_watcher, queue_watcher_status
from rookery.portable.writeups import check_writeups, create_capsule, create_writeup
from rookery.verdict_parser import parse_file, parse_verdict

from tests.rookery.rehearsal import run_pre_event_rehearsal


def copy_rookery_surface(root: Path, *, deployed: bool = False) -> None:
    """Copy a unit fixture, optionally retaining the public deployment markers."""

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
    for rel in [
        ".env.example",
        "CHANGELOG.md",
        "release.json",
        "README.md",
        "LICENSE",
        "AGENTS.md",
        "go",
        "run-codex",
    ]:
        shutil.copy2(ROOKERY_ROOT / rel, root / rel)
    if deployed:
        shutil.copy2(ROOKERY_ROOT / "VERSION", root / "VERSION")


def configure_workspace(root: Path, profile: str = "fixture", *, ready: bool = True) -> None:
    """Configure a copied tree without deciding its launch-binding contract."""

    if profile == "fixture":
        install_fixture_adapter(root)
    adapter_extra = {}
    if profile == "ctfd":
        adapter_extra = {
            "ADAPTER_CONFIG_BASE_URL": "https://fixture.invalid",
            "CTFD_TOKEN": "fixture-token",
        }
    elif profile == "htb":
        adapter_extra = {
            "ADAPTER_CONFIG_INVENTORY_ARGV": '["fixture-inventory"]',
            "ADAPTER_CONFIG_SUBMIT_ARGV": '["fixture-submit"]',
        }
    configure_event_environment(
        root,
        profile,
        ready=ready,
        name_suffix="Acceptance Event",
        extra=adapter_extra,
    )


def make_workspace(profile: str = "fixture", *, ready: bool = True) -> tempfile.TemporaryDirectory:
    """Make a non-deployed structural unit fixture.

    Its missing ``VERSION`` marker keeps it outside the public launch contract;
    callers must not use it to support a public-launch claim.
    """

    td = tempfile.TemporaryDirectory()
    root = Path(td.name)
    copy_rookery_surface(root)
    configure_workspace(root, profile, ready=ready)
    assert not (root / "VERSION").is_file()
    if ready:
        install_test_launch_binding(root)
        open_test_event_store(root)
    return td


def make_release_workspace(
    profile: str = "manual", *, ready: bool = True
) -> tempfile.TemporaryDirectory:
    """Make a deployed-shaped source fixture with no synthetic state."""

    td = tempfile.TemporaryDirectory()
    root = Path(td.name)
    copy_rookery_surface(root, deployed=True)
    configure_workspace(root, profile, ready=ready)
    return td


@dataclass
class DeployedWorkspace:
    temporary: tempfile.TemporaryDirectory
    fake_temporary: tempfile.TemporaryDirectory
    bootstrap: PublicWorkspaceBootstrap
    invocation_log: Path

    @property
    def name(self) -> str:
        return self.temporary.name

    def cleanup(self) -> None:
        self.bootstrap.cleanup()
        self.fake_temporary.cleanup()
        self.temporary.cleanup()


def make_deployed_workspace(
    profile: str = "manual", *, prepare: Callable[[Path], None] | None = None
) -> DeployedWorkspace:
    """Bootstrap a real public root using a hermetic fake Codex executable."""

    td = make_release_workspace(profile)
    root = Path(td.name)
    if prepare is not None:
        prepare(root)
    fake_temporary = tempfile.TemporaryDirectory()
    fake_bin = Path(fake_temporary.name) / "bin"
    fake_bin.mkdir()
    invocation_log = root / "state" / "codex-invocation.txt"
    codex = fake_bin / "codex"
    log_target = shlex.quote(str(invocation_log))
    codex.write_text(
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        "if [ \"$1\" = --version ]; then echo 'codex-cli 0.150.0'; exit 0; fi\n"
        "if [ \"$1\" = --strict-config ] && [ \"$2\" = --version ]; then exit 0; fi\n"
        "if [ \"$1\" = doctor ]; then printf '%s\\n' '{\"checks\":{\"config.load\":{\"status\":\"ok\"}}}'; exit 0; fi\n"
        "if [ \"$1\" = --strict-config ] && [ \"$2\" = login ] && [ \"$3\" = status ]; then\n"
        "  test \"${DUMMY_PROVIDER_KEY:-}\" = provider-fixture\n"
        "  exit 0\n"
        "fi\n"
        "if [ \"$1\" = login ] && [ \"$2\" = status ]; then exit 0; fi\n"
        "if [ \"$1\" = --strict-config ]; then\n"
        f"  printf '%s\\n' \"$1\" > {log_target}\n"
        f"  printf '%s' \"$2\" >> {log_target}\n"
        "  exit 0\n"
        "fi\n"
        "exit 2\n",
        encoding="utf-8",
    )
    codex.chmod(0o755)
    replace_env_assignments(
        root,
        {
            "CODEX_AUTH_MODE": "environment",
            "CODEX_PROVIDER_ENV_KEYS": '["DUMMY_PROVIDER_KEY"]',
            "DUMMY_PROVIDER_KEY": "provider-fixture",
        },
    )
    environment = {
        **os.environ,
        "PATH": str(fake_bin) + os.pathsep + os.environ.get("PATH", ""),
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    try:
        bootstrap = bootstrap_public_workspace(root, environment=environment)
    except BaseException:
        fake_temporary.cleanup()
        td.cleanup()
        raise
    return DeployedWorkspace(td, fake_temporary, bootstrap, invocation_log)


def context(root: Path, profile: str):
    result = resolve_manifest(root, profile=profile)
    store = open_test_event_store(root)
    store.set_meta("scope_generation", 1)
    scope = compile_scope(result.manifest, 1)
    return result.manifest, scope, store, result


def run_cli(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    if (root / "VERSION").is_file():
        raise AssertionError("run_cli is only for non-deployed structural fixtures")
    if args and args[0] == "go":
        raise AssertionError("public go tests must use make_deployed_workspace")
    env = dict(os.environ)
    env["ROOKERY_ROOT"] = str(root)
    env["PYTHONPATH"] = str(root / "lib")
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return subprocess.run(
        [str(root / "bin" / "rookery"), *args], cwd=root, env=env, text=True, capture_output=True, timeout=60
    )


class RookeryConfigurationAndBootAcceptance(unittest.TestCase):
    def test_go_and_status_share_blocked_lifecycle_state(self):
        td = make_deployed_workspace("manual")
        root = Path(td.name)
        args = build_parser().parse_args(["go"])
        preparation = {"ready": True, "capabilities": [], "services": {}}
        checks = [
            {
                "name": "required-fixture",
                "classification": "required",
                "ok": False,
                "detail": "fixture failure",
            }
        ]
        output = io.StringIO()
        with (
            mock.patch.dict(os.environ, td.bootstrap.environment, clear=True),
            mock.patch("rookery.portable.cli.workspace_root", return_value=root),
            mock.patch("rookery.portable.cli.prepare", return_value=preparation),
            mock.patch("rookery.portable.cli.startup_checks", return_value=checks),
            redirect_stdout(output),
        ):
            result = cmd_go(args)

        snapshot = read_snapshot(root)
        self.assertEqual(result, 2)
        self.assertEqual(snapshot["lifecycle_state"], "blocked")
        self.assertIn("rookery_state=blocked", output.getvalue())
        self.assertEqual(
            snapshot["release_version"],
            (root / "VERSION").read_text(encoding="utf-8").strip(),
        )
        td.cleanup()

    def test_manual_start_has_no_htb_or_vpn_assumptions(self):
        td = make_deployed_workspace("manual")
        root = Path(td.name)
        cp = subprocess.run(
            [str(root / "bin" / "rookery"), "go"],
            cwd=root,
            env=td.bootstrap.environment,
            text=True,
            capture_output=True,
            timeout=60,
            check=False,
        )
        self.assertEqual(cp.returncode, 0, cp.stdout + cp.stderr)
        combined = "\n".join(
            (root / x).read_text(errors="replace") for x in ["START_PROMPT.md", "NEW_CTF_SETUP.md", "ACTIVE_SURFACE.md"]
        )
        self.assertNotIn("salt crown", combined.lower())
        self.assertNotIn("hackthebox", combined.lower())
        checks = load_json(root / "state/startup_checks.json", {})["checks"]
        names = {x["name"] for x in checks}
        self.assertNotIn("vpn", names)
        self.assertFalse(any("htb" in x["id"] for x in load_json(root / "state/active_surface.json", {})["agents"]))
        td.cleanup()

    def test_synthetic_bindings_reject_deployed_markers_before_state_cleanup(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            copy_rookery_surface(root, deployed=True)
            state = root / "state"
            state.mkdir()
            marker = state / "must-survive"
            marker.write_text("preserve", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "synthetic launch bindings"):
                install_test_launch_binding(root)
            with self.assertRaisesRegex(RuntimeError, "synthetic launch bindings"):
                rebind_test_workspace(root)
            self.assertTrue(marker.exists())
            self.assertFalse((state / "launch_binding.json").exists())

    def test_vpn_retirement_tests_do_not_claim_managed_lifecycle(self):
        for path in (
            TESTS_ROOT / "rookery" / "test_vpn_process_scope.py",
            TESTS_ROOT / "rookery" / "test_vpn_safety_repair.py",
        ):
            source = path.read_text(encoding="utf-8")
            self.assertIn("vpn_privileged_supervision_unavailable", source, str(path))
            self.assertNotIn("openvpn.identity.json", source, str(path))

    def test_generic_configuration_keeps_platform_code_in_optional_adapters(self):
        generic = "\n".join(
            (ROOKERY_ROOT / rel).read_text(errors="replace").lower()
            for rel in ["README.md", "AGENTS.md"]
        )
        adapter_ids = [p.parent.name for p in (ROOKERY_ROOT / "adapters").glob("*/adapter.json")]
        for adapter_id in adapter_ids:
            self.assertNotIn(adapter_id.lower(), generic)
            self.assertTrue((ROOKERY_ROOT / "adapters" / adapter_id / "profile.json").exists())
        release = load_json(ROOKERY_ROOT / "release.json", {})
        self.assertIn("adapters", release["optional_bundle_roots"])
        self.assertEqual(
            release["version"],
            (ROOKERY_ROOT / "VERSION").read_text(encoding="utf-8").strip(),
        )
        self.assertEqual({p.stem for p in (ROOKERY_ROOT / "profiles").glob("*.json")}, {"generic", "manual"})
        base_names = [p.name.lower() for p in (ROOKERY_ROOT / "bin").iterdir() if p.is_file()]
        for adapter_id in adapter_ids:
            self.assertFalse(any(adapter_id.lower() in name for name in base_names))

    def test_optional_network_helpers_fail_scope_before_access(self):
        td = make_workspace("fixture")
        root = Path(td.name)
        offscope = "http://198.51.100.7"
        transit = subprocess.run(
            [str(root / "bin/transit-source"), "--feed-url", offscope + "/feed.zip"],
            cwd=root,
            text=True,
            capture_output=True,
        )
        self.assertNotEqual(transit.returncode, 0)
        self.assertIn("scope", (transit.stdout + transit.stderr).lower())
        ovpn = root / "fixture.ovpn"
        ovpn.write_text("client\nremote 198.51.100.7 1194\nproto udp\n", encoding="utf-8")
        marker = root / "openvpn-ran"
        fake = root / "fake-openvpn"
        fake.write_text("#!/usr/bin/env bash\ntouch " + str(marker) + "\n", encoding="utf-8")
        fake.chmod(0o755)
        replace_env_assignments(
            root,
            {
                "VPN_ENABLED": "1",
                "VPN_OVPN_PATH": str(ovpn),
                "VPN_AUTO_CONNECT": "1",
                "OPENVPN_BIN": str(fake),
                "VPN_SUDO": "",
            },
        )
        vpn = subprocess.run([str(root / "bin/vpn"), "start"], cwd=root, text=True, capture_output=True)
        self.assertEqual(vpn.returncode, 2, vpn.stdout + vpn.stderr)
        self.assertEqual(vpn.stderr, "vpn_privileged_supervision_unavailable\n")
        self.assertFalse(marker.exists(), "OpenVPN executable ran despite denied scope")
        td.cleanup()

    def test_missing_required_ctfd_adapter_fails_clearly_without_network(self):
        td = make_workspace("ctfd")
        root = Path(td.name)
        replace_env_assignments(root, {"ADAPTER_CONFIG_BASE_URL": "unknown"})
        with mock.patch("urllib.request.urlopen", side_effect=AssertionError("network must not run")):
            result = resolve_manifest(root)
            scope = compile_scope(result.manifest, 1)
            checks = startup_checks(root, result.manifest, scope)
        failed = {x["name"] for x in checks if x["classification"] == "required" and not x["ok"]}
        self.assertTrue({"platform_inventory", "challenge_details", "scoring"} & failed)
        td.cleanup()

    def test_public_go_explicitly_resumes_stopped_generation(self):
        td = make_deployed_workspace("manual")
        root = Path(td.name)
        _manifest, _scope, store, _result = context(root, "manual")
        resume(store, reason="initial")
        stop(store, root, reason="pause", wait_seconds=0)
        before = store.current_stop_generation()
        cp = subprocess.run(
            [str(root / "go")],
            cwd=root,
            text=True,
            capture_output=True,
            env=td.bootstrap.environment,
            check=False,
        )
        self.assertEqual(cp.returncode, 0, cp.stdout + cp.stderr)
        current = EventStore(root).rebuild()["current"]
        self.assertFalse(current["stopped"])
        self.assertEqual(EventStore(root).current_stop_generation(), before)
        self.assertEqual(
            td.invocation_log.read_text(encoding="utf-8"),
            "--strict-config\n"
            + (root / "START_PROMPT.md").read_text(encoding="utf-8").rstrip("\n"),
        )
        self.assertNotEqual(
            subprocess.run([str(root / "go"), "resume"], cwd=root, text=True, capture_output=True).returncode, 0
        )
        td.cleanup()

    def test_unresolved_generic_profile_blocks_only_required_contracts(self):
        td = make_workspace("manual", ready=False)
        root = Path(td.name)
        replace_env_assignments(root, {"EVENT_NAME": "unknown"})
        result = resolve_manifest(root)
        self.assertIn("identity.name", result.unresolved_required)
        self.assertIn("scope.acknowledged", result.unresolved_required)
        self.assertFalse(profile_has_platform_assumption(result.manifest, ["ctfd", "htb", "immersive"]))
        td.cleanup()

    def test_goal_supersede_requires_an_existing_goal(self):
        td = make_workspace("manual")
        root = Path(td.name)
        result = run_cli(root, "goal", "supersede", "--reason", "nothing active")
        self.assertEqual(result.returncode, 2)
        self.assertIn("no active goal", result.stderr)
        self.assertFalse(EventStore(root).events("goal.supersede"))
        td.cleanup()

    def test_offline_rehearsal_covers_critical_path(self):
        # The rehearsal creates and labels its own non-deployed copy before it
        # installs a synthetic binding; the source root remains read-only.
        out = run_pre_event_rehearsal(ROOKERY_ROOT)
        self.assertTrue(out["ok"], out)
        self.assertFalse(out["network_used"])
        self.assertFalse(out["credentials_used"])
        self.assertEqual(out["scorer_truth"], "accepted")


class AdapterIngestFrontierAcceptance(unittest.TestCase):
    def test_unlock_check_backfills_visible_challenges_after_prior_sync(self):
        td = make_workspace("fixture")
        root = Path(td.name)
        try:
            synced = run_cli(root, "platform", "sync")
            self.assertEqual(synced.returncode, 0, synced.stderr)

            first = run_cli(
                root,
                "platform",
                "unlock-check",
                "--ingest",
                "--limit",
                "1",
            )
            self.assertEqual(first.returncode, 0, first.stderr)
            first_payload = json.loads(first.stdout)
            self.assertEqual(first_payload["new_ids"], [])
            self.assertEqual(first_payload["ingested_ids"], ["101"])
            self.assertEqual(first_payload["intake_pending_ids"], [])
            self.assertEqual(
                first_payload["intake_deferred"],
                [{"id": "102", "reason": "solved"}],
            )

            current = load_json(root / "state/current.json", {})["challenges"]
            self.assertTrue(current["101"]["detail_path"])
            self.assertTrue(current["101"]["ingested_at"])
            self.assertTrue(current["101"]["captured_files"])

            upserts_before = len(EventStore(root).events("challenge.upsert"))
            second = run_cli(root, "platform", "unlock-check", "--ingest")
            self.assertEqual(second.returncode, 0, second.stderr)
            second_payload = json.loads(second.stdout)
            self.assertEqual(second_payload["ingested_ids"], [])
            self.assertEqual(second_payload["intake_pending_count"], 0)
            self.assertEqual(
                len(EventStore(root).events("challenge.upsert")),
                upserts_before,
            )
        finally:
            td.cleanup()

    def test_unlock_check_prioritizes_new_ids_before_existing_backlog(self):
        td = make_workspace("fixture")
        root = Path(td.name)
        try:
            synced = run_cli(root, "platform", "sync")
            self.assertEqual(synced.returncode, 0, synced.stderr)
            fixture = root / "adapters/fixture/event.json"
            data = load_json(fixture)
            data["challenges"].append(
                {
                    "id": "103",
                    "name": "New Fixture",
                    "category": "forensics",
                    "value": 250,
                    "solved": False,
                    "files": [],
                }
            )
            atomic_write_json(fixture, data)

            first = run_cli(
                root,
                "platform",
                "unlock-check",
                "--ingest",
                "--limit",
                "1",
            )
            self.assertEqual(first.returncode, 0, first.stderr)
            first_payload = json.loads(first.stdout)
            self.assertEqual(first_payload["new_ids"], ["103"])
            self.assertEqual(first_payload["ingested_ids"], ["103"])
            self.assertEqual(first_payload["intake_pending_ids"], ["101"])

            second = run_cli(
                root,
                "platform",
                "unlock-check",
                "--ingest",
                "--limit",
                "1",
            )
            self.assertEqual(second.returncode, 0, second.stderr)
            second_payload = json.loads(second.stdout)
            self.assertEqual(second_payload["new_ids"], [])
            self.assertEqual(second_payload["ingested_ids"], ["101"])
            self.assertEqual(second_payload["intake_pending_ids"], [])
        finally:
            td.cleanup()

    def test_fixture_unlock_ingest_download_hash_and_frontier(self):
        td = make_workspace("fixture")
        root = Path(td.name)
        first = run_cli(root, "platform", "sync")
        self.assertEqual(first.returncode, 0, first.stderr)
        fixture = root / "adapters/fixture/event.json"
        data = load_json(fixture)
        data["challenges"].append(
            {
                "id": "103",
                "name": "New Fixture",
                "category": "forensics",
                "value": 250,
                "solved": False,
                "files": [{"path": "adapters/fixture/sample.bin", "url": "fixture://sample.bin", "size": 12}],
            }
        )
        atomic_write_json(fixture, data)
        unlocked = run_cli(root, "platform", "unlock-check", "--ingest")
        self.assertEqual(unlocked.returncode, 0, unlocked.stderr)
        self.assertIn("103", json.loads(unlocked.stdout)["new_ids"])
        current = load_json(root / "state/current.json", {})
        challenge = current["challenges"]["103"]
        self.assertTrue(challenge["captured_files"])
        captured = challenge["captured_files"][0]
        self.assertEqual(len(captured["sha256"]), 64)
        frontier = run_cli(root, "frontier", "--json")
        self.assertEqual(frontier.returncode, 0, frontier.stderr)
        ids = {x["id"] for x in json.loads(frontier.stdout)}
        self.assertIn("103", ids)
        td.cleanup()

    def test_ctfd_and_fixture_share_normalized_contract(self):
        snapshots = []
        for profile in ("ctfd", "fixture"):
            td = make_workspace(profile)
            root = Path(td.name)
            manifest, scope, store, result = context(root, profile)
            if profile == "ctfd":
                response = mock.MagicMock()
                response.__enter__.return_value = response
                response.status = 200
                response.headers = {"Content-Type": "application/json"}
                response.read.return_value = json.dumps(
                    load_json(TESTS_ROOT / "fixtures/adapters/ctfd/event.json", {})
                ).encode("utf-8")
                with mock.patch("urllib.request.urlopen", return_value=response):
                    snapshot = get_adapter(root, manifest, scope).sync()
            else:
                snapshot = get_adapter(root, manifest, scope).sync()
            snapshots.append(snapshot)
            self.assertEqual(
                set(snapshot),
                {
                    "schema_version",
                    "adapter_id",
                    "generated_at",
                    "artifact",
                    "capabilities",
                    "challenges",
                    "releases",
                    "collaboration",
                    "session",
                },
            )
            for cap in snapshot["capabilities"].values():
                self.assertTrue(
                    {"availability", "health", "freshness", "read_write_scope", "permitted_mutations"}.issubset(cap)
                )
            td.cleanup()
        self.assertNotEqual(snapshots[0]["adapter_id"], snapshots[1]["adapter_id"])

    def test_ctfd_response_body_is_bounded(self):
        td = make_workspace("ctfd")
        root = Path(td.name)
        replace_env_assignments(
            root,
            {
                "CTFD_URL": "https://fixture.invalid",
                "CTFD_TOKEN": "fixture-token",
            },
        )
        manifest, scope, store, result = context(root, "ctfd")
        del store, result
        manifest["adapter"]["config"]["max_response_bytes"] = 1024
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.status = 200
        response.read.return_value = b"x" * 1025
        adapter = get_adapter(root, manifest, scope)
        transport = mock.Mock(return_value=response)

        with (
            mock.patch.dict(
                adapter.execute_action.__globals__, {"open_scoped_url": transport}
            ),
            self.assertRaisesRegex(RuntimeError, "exceeds configured byte limit"),
        ):
            adapter.execute_action(
                {
                    "objective_id": "101",
                    "exact_value": "FIXTURE{value}",
                    "action_kind": "flag",
                },
                root / "evidence/ctfd-limit",
            )
        transport.assert_called_once()
        td.cleanup()

    def test_policy_blocked_lane_prevents_ingestion(self):
        td = make_workspace("fixture")
        root = Path(td.name)
        manifest, scope, store, result = context(root, "fixture")
        resume(store, reason="test")
        snapshot = get_adapter(root, manifest, scope).sync()
        store.append("platform.snapshot", snapshot, actor="fixture")
        store.append(
            "challenge.classify",
            {"id": "101", "classification": "policy_blocked", "policy_reason": "event rules forbid this technique"},
            actor="operator",
        )
        store.rebuild()
        cp = run_cli(root, "platform", "ingest", "101")
        self.assertNotEqual(cp.returncode, 0)
        self.assertIn("policy_blocked", cp.stderr)
        td.cleanup()


class ScopeAndStateAcceptance(unittest.TestCase):
    def test_stop_result_distinguishes_unmanaged_from_unacknowledged(self):
        td = make_workspace("fixture")
        root = Path(td.name)
        manifest, scope, store, result = context(root, "fixture")
        del manifest, scope, result
        store.append(
            "agent.running",
            {"agent_id": "external", "pid": 0, "pgid": 0},
            actor="fixture",
        )
        job_dir = root / "logs/jobs/stubborn"
        job_dir.mkdir(parents=True)
        atomic_write_json(
            job_dir / "meta.json",
            {"job_id": "stubborn", "status": "running", "pid": 4242},
        )
        store.append(
            "job.running",
            {
                "job_id": "stubborn",
                "pid": 4242,
                "pgid": 4242,
                "process_starttime": "fixture",
                "owner_token": "fixture",
            },
            actor="fixture",
        )

        def identity_matches(_root, row):
            return row.get("job_id") == "stubborn"

        with (
            mock.patch(
                "rookery.portable.control.process_identity_matches",
                side_effect=identity_matches,
            ),
            mock.patch("rookery.portable.control.os.killpg"),
        ):
            outcome = stop(store, root, reason="test", wait_seconds=0)

        self.assertEqual(outcome["unmanaged"], ["external"])
        self.assertEqual(outcome["unacknowledged"], ["stubborn"])
        self.assertEqual(outcome["not_confirmed"], ["external", "stubborn"])
        self.assertEqual(
            store.rebuild()["current"]["agents"]["external"]["status"],
            "unmanaged",
        )
        self.assertEqual(
            store.rebuild()["current"]["jobs"]["stubborn"]["status"],
            "unacknowledged",
        )
        job_meta = load_json(job_dir / "meta.json", {})
        self.assertEqual(job_meta["status"], "unacknowledged")
        self.assertTrue(job_meta["finished_at"])
        td.cleanup()

    def test_scope_refuses_before_access_and_override_is_narrow(self):
        td = make_workspace("fixture")
        root = Path(td.name)
        manifest, scope, store, result = context(root, "fixture")
        self.assertFalse(check_cidr(scope, "10.0.0.0/8").allowed)
        self.assertFalse(check_host(scope, "198.51.100.4", port=31337, protocol="tcp").allowed)
        self.assertFalse(check_file_origin(scope, "fixture://sample.bin", size=1048577).allowed)
        stale = dict(scope)
        stale["expires_at"] = "2000-01-01T00:00:00Z"
        self.assertFalse(check_url(stale, "http://fixture.invalid").allowed)
        cp = run_cli(
            root,
            "scope",
            "override",
            "--cidr",
            "198.51.100.4/32",
            "--duration",
            "60s",
            "--reason",
            "single authorized fixture address",
        )
        self.assertEqual(cp.returncode, 0, cp.stderr)
        overrides = [e["payload"] for e in EventStore(root).events("scope.override")]
        self.assertTrue(check_host(scope, "198.51.100.4", port=31337, protocol="tcp", overrides=overrides).allowed)
        self.assertFalse(check_host(scope, "198.51.100.5", port=31337, protocol="tcp", overrides=overrides).allowed)
        host_only = {**overrides[0], "allowed_hosts": ["198.51.100.4"], "allowed_cidrs": []}
        self.assertFalse(
            check_host(
                scope,
                "198.51.100.4",
                port=31337,
                protocol="tcp",
                overrides=[host_only],
            ).allowed
        )
        td.cleanup()

    def test_state_idempotence_authorization_totals_and_crash_temp(self):
        td = make_workspace("fixture")
        root = Path(td.name)
        manifest, scope, store, result = context(root, "fixture")
        resume(store, reason="start")
        install_solver_ready_challenge(root, store)
        proposal = create_proposal(
            store,
            manifest,
            objective_id="101",
            action_kind="flag",
            exact_value="FIXTURE{accepted}",
            source="analysis/a/REPORT.md",
            rationale="fixture",
            actor="solver-a",
        )
        record_review(store, proposal["proposal_id"], "approved", reviewer="reviewer-b", reason="verified")
        auth = grant_allowance(store, manifest, "flag", 3, reason="three fixture actions")
        before = store.rebuild()
        (root / "state/current.json.tmp.crash").write_text("{broken", encoding="utf-8")
        after = EventStore(root).rebuild()
        self.assertEqual(before["current"]["authorizations"][auth["authorization_id"]]["remaining"], 3)
        self.assertEqual(after["current"]["authorizations"][auth["authorization_id"]]["remaining"], 3)
        json.loads((root / "state/current.json").read_text())
        self.assertTrue((root / "state/current.json.tmp.crash").exists())
        td.cleanup()

    def test_stop_barrier_revokes_cancels_and_stales_execution(self):
        td = make_workspace("fixture")
        root = Path(td.name)
        manifest, scope, store, result = context(root, "fixture")
        resume(store, reason="start")
        snapshot = get_adapter(root, manifest, scope).sync()
        store.append("platform.snapshot", snapshot, actor="fixture")
        install_solver_ready_challenge(root, store)
        proposal = create_proposal(
            store,
            manifest,
            objective_id="101",
            action_kind="flag",
            exact_value="FIXTURE{accepted}",
            source="analysis/a/REPORT.md",
            rationale="fixture",
            actor="solver-a",
        )
        record_review(store, proposal["proposal_id"], "approved", reviewer="reviewer-b", reason="verified")
        grant_exact(store, proposal["proposal_id"], reason="exact")
        plan = compile_plan(store, root, manifest, scope, proposal["proposal_id"])
        store.append(
            "retry.scheduled",
            {
                "retry_id": "r1",
                "objective_id": "101",
                "earliest_at": "2099-01-01T00:00:00Z",
                "method": "fresh",
                "status": "scheduled",
            },
            actor="coordinator",
        )
        store.append(
            "agent.running",
            {"agent_id": "a1", "objective_id": "101", "report_path": "analysis/a1/REPORT.md"},
            actor="coordinator",
        )
        store.append("job.running", {"job_id": "watcher-1", "kind": "watcher"}, actor="coordinator")
        store.rebuild()
        out = stop(store, root, reason="barrier test", wait_seconds=0)
        current = store.rebuild()["current"]
        self.assertTrue(current["stopped"])
        self.assertEqual(current["retries"]["r1"]["status"], "cancelled")
        self.assertEqual(current["agents"]["a1"]["status"], "unmanaged")
        self.assertEqual(current["jobs"]["watcher-1"]["status"], "unmanaged")
        self.assertEqual(out["unacknowledged"], [])
        self.assertEqual(out["unmanaged"], ["a1", "watcher-1"])
        self.assertEqual(out["not_confirmed"], ["a1", "watcher-1"])
        self.assertTrue(
            all(
                x.get("status") != "granted" or int(x.get("remaining", 0)) == 0
                for x in current["authorizations"].values()
            )
        )
        execution, rc = execute_plan(store, root, manifest, scope, plan["plan_id"])
        self.assertNotEqual(rc, 0)
        self.assertIn("stale stop generation", execution.get("reason", "") if isinstance(execution, dict) else "")
        marker = root / "cleanup-ran"
        (root / "state/cleanup_hooks.jsonl").write_text(
            json.dumps({"cleanup_id": "blocked", "command": f"touch {marker}"}) + "\n"
        )
        cleanup = subprocess.run(
            [str(root / "bin/rookery-ops"), "cleanup", "run"], cwd=root, text=True, capture_output=True
        )
        self.assertNotEqual(cleanup.returncode, 0)
        self.assertFalse(marker.exists())
        td.cleanup()

    def test_stop_signals_only_owned_process_identity(self):
        td = make_workspace("fixture")
        root = Path(td.name)
        manifest, scope, store, result = context(root, "fixture")
        resume(store, reason="test")
        token = "ctf-owned-stop-fixture"
        proc = subprocess.Popen(["bash", "-lc", f"exec -a {token} sleep 60"], cwd=root, start_new_session=True)
        try:
            starttime = (Path("/proc") / str(proc.pid) / "stat").read_text().split()[21]
            store.append(
                "agent.running",
                {
                    "agent_id": "owned",
                    "objective_id": "101",
                    "role": "worker",
                    "report_path": "analysis/owned/REPORT.md",
                    "pid": proc.pid,
                    "pgid": os.getpgid(proc.pid),
                    "process_starttime": starttime,
                    "owner_token": token,
                },
                actor="fixture",
            )
            out = stop(store, root, reason="fixture", wait_seconds=0.2)
            self.assertIn(proc.pid, out["signalled_pids"])
            proc.wait(timeout=3)
            self.assertIsNotNone(proc.returncode)
            self.assertEqual(
                store.rebuild()["current"]["agents"]["owned"]["status"],
                "closed",
            )
            stale_token = "ctf-stale-job-fixture"
            stale = subprocess.Popen(
                ["bash", "-lc", f"exec -a {stale_token} sleep 60"],
                cwd=root,
                start_new_session=True,
                env={**os.environ, "ROOKERY_OWNER_TOKEN": stale_token},
            )
            try:
                job_dir = root / "logs/jobs/stale-job"
                job_dir.mkdir(parents=True)
                atomic_write_json(
                    job_dir / "meta.json",
                    {
                        "job_id": "stale-job",
                        "pid": stale.pid,
                        "pgid": os.getpgid(stale.pid),
                        "process_starttime": "stale",
                        "owner_token": stale_token,
                    },
                )
                killed = subprocess.run(
                    [str(root / "bin/killq"), "stale-job"], cwd=root, text=True, capture_output=True
                )
                self.assertEqual(killed.returncode, 2)
                self.assertIsNone(stale.poll())
            finally:
                if stale.poll() is None:
                    stale.terminate()
                    stale.wait(timeout=3)
        finally:
            if proc.poll() is None:
                proc.terminate()
                proc.wait(timeout=3)
            td.cleanup()

    def test_disabled_queue_watch_uses_explicit_diagnostic_read(self):
        td = make_workspace("fixture")
        root = Path(td.name)
        context(root, "fixture")
        args = build_parser().parse_args(
            [
                "queue",
                "watch",
                "--once",
                "--quiet",
                "--diagnostic",
                "--heartbeat-seconds",
                "300",
            ]
        )
        output = io.StringIO()
        with (
            mock.patch("rookery.portable.cli.workspace_root", return_value=root),
            redirect_stdout(output),
        ):
            result = cmd_queue(args)

        self.assertEqual(result, 0)
        diagnostic = json.loads(output.getvalue())
        self.assertTrue(diagnostic["diagnostic"])
        self.assertFalse(diagnostic["automation_enabled"])
        self.assertEqual(diagnostic["queue"]["depth"], 0)
        self.assertEqual(diagnostic["queue"]["eligible"], 0)
        self.assertNotIn("items", diagnostic)
        td.cleanup()

    def test_go_owned_queue_watcher_reuses_and_stops(self):
        td = make_workspace("fixture")
        root = Path(td.name)
        manifest, scope, store, result = context(root, "fixture")
        resume(store, reason="test")
        manifest["queue"]["automation_enabled"] = True
        manifest["queue"]["watch_interval_seconds"] = 1
        first = ensure_queue_watcher(store, root, manifest)
        second = ensure_queue_watcher(store, root, manifest)
        try:
            self.assertTrue(first["running"])
            self.assertTrue(second["reused"])
            self.assertIn("--quiet", first["job"]["command"])
            self.assertIn("--heartbeat-seconds", first["job"]["command"])
            self.assertTrue(queue_watcher_status(store, root)["running"])
            outcome = stop(store, root, reason="test", wait_seconds=0.5)
            self.assertIn(first["job"]["pid"], outcome["signalled_pids"])
            self.assertNotIn(first["job"]["job_id"], outcome["unacknowledged"])
            cancelled = [
                event
                for event in store.events("job.cancelled")
                if event["payload"].get("job_id") == first["job"]["job_id"]
            ]
            self.assertEqual(len(cancelled), 1)
            self.assertIn("cpu_seconds", cancelled[0]["payload"]["resource_summary"])
            self.assertGreaterEqual(
                cancelled[0]["payload"]["resource_summary"]["rss_bytes"],
                0,
            )
        finally:
            pid = first.get("job", {}).get("pid")
            if pid:
                try:
                    os.killpg(first["job"]["pgid"], 15)
                except ProcessLookupError:
                    pass
            td.cleanup()

    def test_concurrent_queue_watcher_start_is_singleton(self):
        td = make_workspace("fixture")
        root = Path(td.name)
        manifest, scope, store, result = context(root, "fixture")
        del scope, result
        resume(store, reason="test")
        manifest["queue"]["automation_enabled"] = True
        manifest["queue"]["watch_interval_seconds"] = 1
        start = threading.Barrier(9)
        outcomes: list[dict] = []
        errors: list[Exception] = []

        def invoke() -> None:
            try:
                start.wait(timeout=5)
                outcomes.append(
                    ensure_queue_watcher(EventStore(root), root, manifest)
                )
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=invoke) for _ in range(8)]
        for thread in threads:
            thread.start()
        start.wait(timeout=5)
        for thread in threads:
            thread.join(timeout=10)
        try:
            self.assertTrue(all(not thread.is_alive() for thread in threads))
            self.assertEqual(errors, [])
            self.assertEqual(len(outcomes), 8)
            self.assertEqual(sum(1 for outcome in outcomes if not outcome["reused"]), 1)
            self.assertEqual(
                len({outcome["job"]["pid"] for outcome in outcomes}),
                1,
            )
            stop(store, root, reason="test", wait_seconds=0.5)
        finally:
            for outcome in outcomes:
                job = outcome.get("job", {})
                if job.get("pgid"):
                    try:
                        os.killpg(job["pgid"], 15)
                    except ProcessLookupError:
                        pass
            td.cleanup()


class ScoringQueueExecutionAcceptance(unittest.TestCase):
    def setUp(self):
        self.td = make_workspace("fixture")
        self.root = Path(self.td.name)
        self.manifest, self.scope, self.store, self.result = context(self.root, "fixture")
        resume(self.store, reason="test")
        self.store.append(
            "platform.snapshot", get_adapter(self.root, self.manifest, self.scope).sync(), actor="fixture"
        )
        install_solver_ready_challenge(self.root, self.store)

    def tearDown(self):
        self.td.cleanup()

    def approved(self, *, kind: str = "flag", value: str = "FIXTURE{accepted}", attempt_scope=None):
        proposal = create_proposal(
            self.store,
            self.manifest,
            objective_id="101",
            action_kind=kind,
            exact_value=value if kind != "no_submit_evidence" else "",
            artifact_reference="evidence/proof.txt" if kind == "no_submit_evidence" else "",
            attempt_scope=attempt_scope or {},
            challenge_id="101",
            source="analysis/a/REPORT.md",
            rationale="fixture",
            actor="solver-a",
        )
        record_review(self.store, proposal["proposal_id"], "approved", reviewer="reviewer-b", reason="independent")
        return proposal

    def test_independent_reviewer_and_allowance_policy(self):
        proposal = create_proposal(
            self.store,
            self.manifest,
            objective_id="101",
            action_kind="flag",
            exact_value="FIXTURE{x}",
            source="analysis/a/REPORT.md",
            rationale="fixture",
            actor="same",
        )
        with self.assertRaises(ValueError):
            record_review(self.store, proposal["proposal_id"], "approved", reviewer="same", reason="not independent")
        denied = json.loads(json.dumps(self.manifest))
        denied["authorization"]["automation_permitted_action_kinds"] = []
        with self.assertRaises(RuntimeError):
            grant_allowance(self.store, denied, "flag", 1, reason="not permitted")
        self.manifest["scoring"]["action_kinds"].append("handle_write")
        handle_write = self.approved(kind="handle_write", value="FIXTURE{accepted}")
        grant_exact(self.store, handle_write["proposal_id"], reason="authorized write")
        plan = compile_plan(self.store, self.root, self.manifest, self.scope, handle_write["proposal_id"])
        env = {**os.environ, "PYTHONPATH": str(self.root / "lib"), "PYTHONDONTWRITEBYTECODE": "1"}
        executed = subprocess.run(
            [str(self.root / "extensions/koth/bin/verified-write"), plan["plan_id"]],
            cwd=self.root,
            env=env,
            text=True,
            capture_output=True,
        )
        self.assertEqual(executed.returncode, 0, executed.stderr)
        self.assertEqual(self.store.rebuild()["current"]["executions"][plan["plan_id"]]["status"], "completed")
        marker = self.root / "raw-write-ran"
        raw = subprocess.run(
            [
                str(self.root / "extensions/koth/bin/verified-write"),
                "--target",
                "fixture.invalid",
                "--command",
                f"touch {marker}",
                "--execute",
            ],
            cwd=self.root,
            env=env,
            text=True,
            capture_output=True,
        )
        self.assertNotEqual(raw.returncode, 0)
        self.assertFalse(marker.exists())

    def test_no_submit_evidence_requires_no_mutation_authority(self):
        proposal = self.approved(kind="no_submit_evidence")
        plan = compile_plan(self.store, self.root, self.manifest, self.scope, proposal["proposal_id"])
        before_auth = dict(self.store.rebuild()["current"]["authorizations"])
        out, rc = execute_plan(self.store, self.root, self.manifest, self.scope, plan["plan_id"])
        self.assertEqual(rc, 0)
        self.assertEqual(out["verdict"]["scorer_truth"], "non_scoring")
        self.assertEqual(before_auth, self.store.rebuild()["current"]["authorizations"])

    def test_lifecycle_policy_and_scope_rotation_stale_plans_without_consuming(self):
        for mode in ("lifecycle", "policy", "scope"):
            proposal = self.approved(attempt_scope={"attempt_id": f"a-{mode}"})
            self.store.append(
                "challenge.upsert", {"id": "101", "attempt_scope": {"attempt_id": f"a-{mode}"}}, actor="fixture"
            )
            auth = grant_exact(self.store, proposal["proposal_id"], reason="exact")
            plan = compile_plan(self.store, self.root, self.manifest, self.scope, proposal["proposal_id"])
            if mode == "lifecycle":
                self.store.append(
                    "challenge.upsert", {"id": "101", "attempt_scope": {"attempt_id": "rotated"}}, actor="fixture"
                )
            elif mode == "policy":
                set_policy(self.store, "strategy", "points", source="operator", reason="changed")
            else:
                self.store.set_meta("scope_generation", 2)
            out, rc = execute_plan(self.store, self.root, self.manifest, self.scope, plan["plan_id"])
            self.assertEqual(rc, 2, (mode, out))
            remaining = self.store.rebuild()["current"]["authorizations"][auth["authorization_id"]]["remaining"]
            self.assertEqual(remaining, 1)
            if mode == "scope":
                self.store.set_meta("scope_generation", 1)

    def test_stop_change_after_durable_start_is_indeterminate(self):
        proposal = self.approved()
        authorization = grant_exact(self.store, proposal["proposal_id"], reason="exact")
        plan = compile_plan(self.store, self.root, self.manifest, self.scope, proposal["proposal_id"])
        with mock.patch(
            "rookery.portable.execution.mutation_guard",
            side_effect=[
                None,
                None,
                RuntimeError("stale stop generation at mutation boundary"),
            ],
        ):
            out, rc = execute_plan(self.store, self.root, self.manifest, self.scope, plan["plan_id"])
        self.assertEqual(rc, 2)
        # The durable start consumes authority and terminally quarantines this
        # plan; retrying it would risk a second external mutation.
        self.assertEqual(out["status"], "indeterminate")
        self.assertIn("stale stop generation", out["reason"])
        remaining = self.store.rebuild()["current"]["authorizations"][authorization["authorization_id"]]["remaining"]
        self.assertEqual(remaining, 0)

    def test_execution_and_stop_share_one_linearization_barrier(self):
        proposal = self.approved()
        grant_exact(self.store, proposal["proposal_id"], reason="exact")
        plan = compile_plan(
            self.store,
            self.root,
            self.manifest,
            self.scope,
            proposal["proposal_id"],
        )
        adapter = get_adapter(self.root, self.manifest, self.scope)
        real_execute = adapter.execute_action
        stop_started = threading.Event()
        stop_finished = threading.Event()
        stop_result: dict[str, object] = {}
        stop_threads: list[threading.Thread] = []

        def request_stop() -> None:
            stop_started.set()
            stop_result.update(
                stop(self.store, self.root, reason="test race", wait_seconds=0)
            )
            stop_finished.set()

        def execute_while_stop_waits(envelope, evidence_root):
            stop_thread = threading.Thread(target=request_stop)
            stop_threads.append(stop_thread)
            stop_thread.start()
            self.assertTrue(stop_started.wait(timeout=2))
            self.assertFalse(stop_finished.is_set())
            result = real_execute(envelope, evidence_root)
            return {**result, "stop_thread": stop_thread}

        with (
            mock.patch("rookery.portable.execution.get_adapter", return_value=adapter),
            mock.patch.object(
                adapter,
                "execute_action",
                side_effect=execute_while_stop_waits,
            ) as execute_action,
        ):
            out, rc = execute_plan(
                self.store,
                self.root,
                self.manifest,
                self.scope,
                plan["plan_id"],
            )
        execute_action.assert_called_once()
        # The adapter result is recorded before the executor releases the barrier;
        # stop then advances the generation and completes.
        self.assertEqual(len(stop_threads), 1)
        stop_threads[0].join(timeout=3)
        self.assertEqual(rc, 0)
        self.assertEqual(out["status"], "completed")
        self.assertTrue(stop_finished.wait(timeout=3))
        self.assertEqual(stop_result["generation"], 1)
        events = self.store.events()
        stop_sequence = next(
            event["seq"] for event in events if event["event_type"] == "control.stop"
        )
        terminal_sequence = next(
            event["seq"]
            for event in events
            if event["event_type"] == "execution.completed"
            and event["payload"].get("plan_id") == plan["plan_id"]
        )
        self.assertLess(terminal_sequence, stop_sequence)

    def test_blocked_stale_plan_returns_proposal_to_queue(self):
        proposal = self.approved()
        grant_exact(self.store, proposal["proposal_id"], reason="exact")
        plan = compile_plan(self.store, self.root, self.manifest, self.scope, proposal["proposal_id"])
        set_policy(self.store, "strategy", "points", source="operator", reason="changed")
        out, rc = execute_plan(self.store, self.root, self.manifest, self.scope, plan["plan_id"])
        self.assertEqual(rc, 2)
        self.assertEqual(out["status"], "blocked")
        queued = {item["proposal_id"] for item in build_queue(self.store, self.manifest)["items"]}
        self.assertIn(proposal["proposal_id"], queued)

    def test_authorization_race_blocks_cleanly(self):
        proposal = self.approved()
        grant_exact(self.store, proposal["proposal_id"], reason="exact")
        plan = compile_plan(self.store, self.root, self.manifest, self.scope, proposal["proposal_id"])
        with mock.patch(
            "rookery.portable.execution.claim_plan_authority",
            side_effect=RuntimeError("authorization unavailable"),
        ):
            out, rc = execute_plan(self.store, self.root, self.manifest, self.scope, plan["plan_id"])
        self.assertEqual(rc, 2)
        self.assertEqual(out["status"], "blocked")
        self.assertIn("authorization unavailable", out["reason"])

    def test_missing_and_corrupt_plan_files_block_cleanly(self):
        missing, missing_rc = execute_plan(
            self.store,
            self.root,
            self.manifest,
            self.scope,
            "plan_missing",
        )
        self.assertEqual(missing_rc, 2)
        self.assertEqual(missing["status"], "blocked")
        self.assertIn("execution plan file", missing["reason"])

        corrupt_path = self.root / "state/execution_plans/plan_corrupt.json"
        corrupt_path.parent.mkdir(parents=True, exist_ok=True)
        corrupt_path.write_text("{broken", encoding="utf-8")
        corrupt, corrupt_rc = execute_plan(
            self.store,
            self.root,
            self.manifest,
            self.scope,
            "plan_corrupt",
        )
        self.assertEqual(corrupt_rc, 2)
        self.assertEqual(corrupt["status"], "blocked")
        self.assertIn("execution plan file", corrupt["reason"])

        proposal = self.approved()
        grant_exact(self.store, proposal["proposal_id"], reason="exact")
        plan = compile_plan(self.store, self.root, self.manifest, self.scope, proposal["proposal_id"])
        plan_path = self.root / "state/execution_plans" / f"{plan['plan_id']}.json"
        tampered = load_json(plan_path, {})
        tampered["semantic_action"] = "tampered"
        atomic_write_json(plan_path, tampered)
        integrity, integrity_rc = execute_plan(
            self.store,
            self.root,
            self.manifest,
            self.scope,
            plan["plan_id"],
        )
        self.assertEqual(integrity_rc, 2)
        self.assertEqual(integrity["status"], "blocked")
        self.assertIn("integrity check failed", integrity["reason"])

    def test_missing_proposal_state_blocks_plan_cleanly(self):
        proposal = self.approved()
        grant_exact(self.store, proposal["proposal_id"], reason="exact")
        plan = compile_plan(self.store, self.root, self.manifest, self.scope, proposal["proposal_id"])
        self.store.transaction(
            lambda connection: connection.execute(
                "DELETE FROM events WHERE event_type='proposal.created' AND payload_json LIKE ?",
                (f'%"proposal_id":"{proposal["proposal_id"]}"%',),
            )
        )
        out, rc = execute_plan(self.store, self.root, self.manifest, self.scope, plan["plan_id"])
        self.assertEqual(rc, 2)
        self.assertEqual(out["status"], "blocked")
        self.assertIn("proposal is unavailable", out["reason"])

    def test_queue_wait_reasons_restart_and_single_escalation(self):
        self.manifest["queue"] = {
            "automation_enabled": True,
            "cadence_seconds": 120,
            "jitter_seconds": 10,
            "latency_objective_seconds": 1,
        }
        proposal = self.approved()
        grant_allowance(self.store, self.manifest, "flag", 1, reason="bounded fixture")
        first = persist_schedules(self.store, self.manifest)
        item = next(x for x in first["items"] if x["proposal_id"] == proposal["proposal_id"])
        self.assertTrue(any("cadence wait" in x for x in item["wait_reasons"]))
        second = persist_schedules(EventStore(self.root), self.manifest)
        item2 = next(x for x in second["items"] if x["proposal_id"] == proposal["proposal_id"])
        self.assertEqual(item["scheduled_at"], item2["scheduled_at"])
        self.assertLessEqual(len(self.store.events("queue.escalated")), 1)

    def test_verdict_fixture_matrix(self):
        expected = {
            "accepted.json": "accepted",
            "already_captured.json": "already-accepted",
            "auth_failed.json": "auth_blocked",
            "command_stdout_reject.json": "rejected",
            "non_scoring_join.json": "non_scoring",
            "rejected_http200.json": "rejected",
            "transport_success_unknown.json": "unknown",
        }
        for name, verdict in expected.items():
            got = parse_file(TESTS_ROOT / "fixtures/verdict" / name)
            self.assertEqual(got.verdict, verdict, name)
        got = parse_verdict({"http_status": 200, "success": True, "data": {"correct": False}})
        self.assertEqual(got.verdict, "rejected")

    def test_rejected_execution_requires_discriminated_follow_up_lineage(self):
        first = self.approved(value="FIXTURE{rejected-first}")
        grant_exact(self.store, first["proposal_id"], reason="exact")
        plan = compile_plan(
            self.store,
            self.root,
            self.manifest,
            self.scope,
            first["proposal_id"],
        )
        rejected, rc = execute_plan(
            self.store,
            self.root,
            self.manifest,
            self.scope,
            plan["plan_id"],
        )
        self.assertEqual(rc, 1)
        self.assertEqual(rejected["status"], "rejected")
        fingerprint = rejected["rejection"]["fingerprint"]
        self.assertRegex(fingerprint, r"^[0-9a-f]{64}$")
        self.assertNotIn("exact_value", rejected["rejection"])

        with self.assertRaisesRegex(ValueError, "discriminating change"):
            create_proposal(
                self.store,
                self.manifest,
                objective_id="101",
                action_kind="flag",
                exact_value="FIXTURE{rejected-second}",
                source="analysis/follow-up/REPORT.md",
                rationale="follow-up",
                parent_rejection_fingerprint=fingerprint,
            )
        follow_up = create_proposal(
            self.store,
            self.manifest,
            objective_id="101",
            action_kind="flag",
            exact_value="FIXTURE{rejected-second}",
            source="analysis/follow-up/REPORT.md",
            rationale="follow-up",
            parent_rejection_fingerprint=fingerprint,
            discriminator="different representation and independent evidence",
            challenge_id="101",
            source_handoff_id="handoff-acceptance-follow-up",
        )
        self.assertEqual(follow_up["parent_rejection_fingerprint"], fingerprint)
        self.assertTrue(follow_up["discriminator"])


class DecisionOutcomeStatusSurfaceAcceptance(unittest.TestCase):
    def setUp(self):
        self.td = make_workspace("fixture")
        self.root = Path(self.td.name)
        self.manifest, self.scope, self.store, self.result = context(self.root, "fixture")
        resume(self.store, reason="test")

    def tearDown(self):
        self.td.cleanup()

    def test_priority_speed_points_fresh_and_infra_modes_are_distinct(self):
        challenges = [
            {
                "id": "speed",
                "points": 100,
                "solve_count": 50,
                "expected_effort": 0.05,
                "evidence_maturity": 0.7,
                "released_at": "2025-01-01T00:00:00Z",
                "infrastructure_readiness": 1.0,
            },
            {
                "id": "points",
                "points": 1000,
                "solve_count": 1,
                "expected_effort": 0.9,
                "evidence_maturity": 0.5,
                "released_at": "2025-01-01T00:00:00Z",
                "infrastructure_readiness": 1.0,
            },
            {
                "id": "fresh",
                "points": 250,
                "solve_count": 2,
                "expected_effort": 0.5,
                "evidence_maturity": 0.3,
                "released_at": "2099-01-01T00:00:00Z",
                "infrastructure_readiness": 1.0,
            },
            {
                "id": "infra",
                "points": 300,
                "solve_count": 3,
                "expected_effort": 0.4,
                "evidence_maturity": 0.6,
                "released_at": "2025-01-01T00:00:00Z",
                "infrastructure_readiness": 0.0,
            },
        ]
        modes = {
            "speed": {"expected_effort": -8.0},
            "points": {"value": 8.0},
            "fresh": {"release_freshness": 8.0},
            "infra": {"infrastructure_readiness": 8.0, "value": 0.0},
        }
        tops = {}
        for name, weights in modes.items():
            m = json.loads(json.dumps(self.manifest))
            m["priority"]["weights"] = {k: 0.0 for k in m["priority"]["weights"]}
            m["priority"]["weights"].update(weights)
            ranked = rank_challenges(challenges, m)
            tops[name] = ranked[0]["id"]
            self.assertTrue(ranked[0]["priority_reason"])
        self.assertEqual(tops["speed"], "speed")
        self.assertEqual(tops["points"], "points")
        self.assertEqual(tops["fresh"], "fresh")
        self.assertNotEqual(tops["infra"], "infra")

    def test_typed_outcomes_route_refusal_capacity_environment_and_finding(self):
        cases = {
            "generic_refusal": "requeue_shorter_ctf_context",
            "capacity_failure": "requeue_default_worker",
            "environment_failure": "repair_environment_or_reassign",
            "supported_finding": "advance_or_verify",
        }
        for i, (kind, transition) in enumerate(cases.items()):
            self.store.append(
                "agent.running",
                {
                    "agent_id": f"a{i}",
                    "agent_attempt_id": f"attempt-{i}",
                    "objective_id": "101",
                    "role": "worker",
                    "report_path": f"analysis/a{i}/REPORT.md",
                },
                actor="fixture",
            )
            out = record_outcome(
                self.store,
                agent_id=f"a{i}",
                objective_id="101",
                outcome_type=kind,
                report_path=f"analysis/a{i}/REPORT.md",
                summary=kind,
                agent_attempt_id=f"attempt-{i}",
            )
            self.assertEqual(out["transition"], transition)
            self.assertEqual(out["agent_attempt_id"], f"attempt-{i}")
        retries = self.store.events("retry.scheduled")
        self.assertEqual(len(retries), 2)

    def test_agent_close_requires_typed_outcome_for_attempt(self):
        registered = run_cli(
            self.root,
            "agent",
            "register",
            "agent-fixture",
            "--objective-id",
            "101",
            "--role",
            "worker",
            "--report-path",
            "analysis/agent-fixture/REPORT.md",
            "--goal",
            "Exercise the event-wide fixture closeout gate.",
            "--scope",
            "Fixture state and analysis/agent-fixture only.",
            "--stop-condition",
            "Close after one typed fixture outcome.",
            "--attempt-id",
            "attempt-fixture",
            "--event-wide",
        )
        blocked = run_cli(
            self.root,
            "agent",
            "close",
            "agent-fixture",
            "--reason",
            "done",
        )
        report = self.root / "analysis/agent-fixture/REPORT.md"
        report.parent.mkdir(parents=True, exist_ok=True)
        evidence = report.parent / "evidence.txt"
        evidence.write_text("Exact event-wide result.\n", encoding="utf-8")
        command = report.parent / "command.txt"
        command.write_text("fixture-command --route exact\n", encoding="utf-8")
        report.write_text(
            render_handoff_report(
                status="supported_finding",
                observed_result="fixture result",
                route_key="fixture-route",
                proof_gap="none for the attempt identity assertion",
                next_step_or_return_trigger="close the exact attempt",
                evidence_paths=("analysis/agent-fixture/evidence.txt",),
                command_artifact_paths=("analysis/agent-fixture/command.txt",),
            ),
            encoding="utf-8",
        )
        integrated = run_cli(
            self.root,
            "agent",
            "integrate",
            "analysis/agent-fixture/REPORT.md",
            "--agent-id",
            "agent-fixture",
            "--agent-attempt-id",
            "attempt-fixture",
            "--objective-id",
            "101",
            "--event-wide",
            "--status",
            "supported_finding",
            "--observed-result",
            "fixture result",
            "--route-key",
            "fixture-route",
            "--proof-gap",
            "none for the attempt identity assertion",
            "--next-step-or-return-trigger",
            "close the exact attempt",
        )
        self.assertEqual(integrated.returncode, 0, integrated.stderr)
        outcome = run_cli(
            self.root,
            "outcome",
            "record",
            "--agent-id",
            "agent-fixture",
            "--agent-attempt-id",
            "attempt-fixture",
            "--objective-id",
            "101",
            "--type",
            "supported_finding",
            "--mechanism",
            "fixture-route",
            "--report-path",
            "analysis/agent-fixture/REPORT.md",
            "--summary",
            "fixture",
        )
        closed = run_cli(
            self.root,
            "agent",
            "close",
            "agent-fixture",
            "--reason",
            "done",
        )

        self.assertEqual(registered.returncode, 0, registered.stderr)
        self.assertNotEqual(blocked.returncode, 0)
        self.assertIn("requires a typed outcome", blocked.stderr)
        self.assertEqual(outcome.returncode, 0, outcome.stderr)
        self.assertEqual(closed.returncode, 0, closed.stderr)
        current = EventStore(self.root).rebuild()["current"]
        self.assertEqual(current["agents"]["agent-fixture"]["status"], "closed")
        self.assertEqual(
            current["outcomes"][next(iter(current["outcomes"]))][
                "agent_attempt_id"
            ],
            "attempt-fixture",
        )

    def test_agent_registration_records_and_enforces_capacity(self):
        self.manifest["concurrency"]["max_workers"] = 1
        replace_env_assignments(self.root, {"CONCURRENCY_MAX_WORKERS": "1"})
        rebind_test_workspace(self.root)
        first = run_cli(
            self.root,
            "agent",
            "register",
            "agent-one",
            "--objective-id",
            "101",
            "--role",
            "worker",
            "--report-path",
            "analysis/one/REPORT.md",
            "--goal",
            "Exercise the first bounded capacity fixture lane.",
            "--scope",
            "Fixture state and analysis/one only.",
            "--stop-condition",
            "Stop after the capacity admission decision.",
            "--event-wide",
        )
        second = run_cli(
            self.root,
            "agent",
            "register",
            "agent-two",
            "--objective-id",
            "102",
            "--role",
            "worker",
            "--report-path",
            "analysis/two/REPORT.md",
            "--goal",
            "Exercise the second bounded capacity fixture lane.",
            "--scope",
            "Fixture state and analysis/two only.",
            "--stop-condition",
            "Stop after the capacity rejection decision.",
            "--event-wide",
        )

        self.assertEqual(first.returncode, 0, first.stderr)
        first_payload = json.loads(first.stdout)
        self.assertEqual(first_payload["dispatch"]["active_workers_before"], 0)
        self.assertEqual(first_payload["dispatch"]["max_workers"], 1)
        self.assertNotEqual(second.returncode, 0)
        rejected = EventStore(self.root).events("agent.capacity_rejected")
        self.assertEqual(len(rejected), 1)
        self.assertEqual(rejected[0]["payload"]["active_workers"], 1)
        self.assertEqual(rejected[0]["payload"]["max_workers"], 1)

    def test_status_is_repeated_pure_read_and_contains_next_action(self):
        refresh_snapshot(self.store, self.root, self.manifest)
        before = tree_hash(self.root)
        snapshots = [read_snapshot(self.root) for _ in range(10)]
        after = tree_hash(self.root)
        self.assertEqual(before, after)
        for snapshot in snapshots:
            age = snapshot["status_truth"].pop("snapshot_age_seconds")
            self.assertIsInstance(age, int)
            self.assertGreaterEqual(age, 0)
        self.assertTrue(all(x == snapshots[0] for x in snapshots))
        self.assertIn("next_autonomous_action", snapshots[0])

    def test_admission_rule_rejects_duplicate_tool_contracts(self):
        entries = [
            {"id": "a", "admission": {"capability_gap": "g", "evidence": "e", "distinct_contract": "same"}},
            {"id": "b", "admission": {"capability_gap": "g2", "evidence": "e2", "distinct_contract": "same"}},
        ]
        errors = validate_admission(entries, kind="tool")
        self.assertTrue(any("duplicate contract" in error for error in errors))
        dormant = json.loads(json.dumps(entries[0]))
        dormant["id"] = "dormant"
        dormant["requires_any"] = ["legacy-optional"]
        dormant_errors = validate_admission([dormant], kind="tool")
        self.assertTrue(
            any("has no activation route" in error for error in dormant_errors)
        )

    def test_surface_is_capability_selected_for_three_profiles(self):
        counts = {}
        for profile in ("manual", "fixture", "htb"):
            td = make_workspace(profile)
            root = Path(td.name)
            manifest, scope, store, result = context(root, profile)
            inv = render_surface(root, manifest)
            counts[profile] = (len(inv["agents"]), len(inv["tools"]))
            text = (root / "ACTIVE_SURFACE.md").read_text().lower()
            if profile != "htb":
                self.assertNotIn("ctf_htb", text)
            else:
                self.assertIn("ctf_htb", text)
            td.cleanup()
        self.assertGreater(counts["htb"][0], counts["manual"][0])

    def test_compute_scheduler_idles_reserves_checkpoints_and_retires(self):
        jobs = [
            {
                "job_id": "useful",
                "cost_units": 3,
                "expected_value": 5,
                "evidence_value": 2,
                "budget_remaining_seconds": 60,
                "checkpointable": True,
                "progress_rate": 1,
            },
            {
                "job_id": "exhausted",
                "cost_units": 1,
                "expected_value": 9,
                "budget_remaining_seconds": 0,
                "checkpointable": True,
            },
            {
                "job_id": "uncheckpointable",
                "cost_units": 1,
                "expected_value": 9,
                "budget_remaining_seconds": 60,
                "checkpointable": False,
            },
            {
                "job_id": "stalled",
                "cost_units": 1,
                "expected_value": 9,
                "budget_remaining_seconds": 60,
                "checkpointable": True,
                "progress_rate": 0,
                "no_progress_windows": 2,
            },
        ]
        out = schedule_useful_jobs(jobs, self.manifest)
        self.assertEqual([x["job_id"] for x in out["selected"]], ["useful"])
        self.assertEqual(out["interactive_reserve_units"], self.manifest["compute"]["interactive_reserve_units"])
        self.assertGreaterEqual(out["idle_units"], 0)
        self.assertEqual({x["job_id"] for x in out["retired"]}, {"exhausted", "uncheckpointable", "stalled"})


class WriteupLessonsValidatorAcceptance(unittest.TestCase):
    def test_capsule_reconstructs_without_chat_and_closeout_requires_narrative(self):
        td = make_workspace("fixture")
        root = Path(td.name)
        manifest, scope, store, result = context(root, "fixture")
        install_solver_ready_challenge(root, store)
        proposal = create_proposal(
            store,
            manifest,
            objective_id="101",
            action_kind="flag",
            exact_value="FIXTURE{capsule-accepted}",
            source="analysis/report.md",
            rationale="canonical capsule acceptance fixture",
            actor="solver-a",
        )
        record_review(
            store,
            proposal["proposal_id"],
            "approved",
            reviewer="reviewer-b",
            reason="independent fixture review",
        )
        grant_exact(store, proposal["proposal_id"], reason="fixture exact authority")
        plan = compile_plan(
            store, root, manifest, scope, proposal["proposal_id"]
        )
        claim_plan_authority(store, plan, loaded_plan=plan, actor="fixture")
        evidence_root = f"submissions/executions/{plan['plan_id']}"
        store.append(
            "execution.completed",
            {
                "plan_id": plan["plan_id"],
                "proposal_id": proposal["proposal_id"],
                "objective_id": "101",
                "action_kind": "flag",
                "status": "completed",
                "verdict": {
                    "verdict": "accepted",
                    "scorer_truth": "accepted",
                    "transport_truth": "accepted",
                },
                "response_path": f"{evidence_root}/response.json",
                "evidence_root": evidence_root,
                "completed_at": "2026-09-28T00:00:00Z",
            },
            actor="fixture",
        )
        create_capsule(
            store,
            root,
            objective_id="101",
            action_reference=plan["plan_id"],
            scorer_evidence=evidence_root,
            reproduction_path="exploit/solve.py",
            material_provenance=["analysis/report.md", "evidence/raw.bin"],
            dead_path_checkpoint="rejected route x",
        )
        loaded = load_json(
            root / "writeups" / objective_storage_component("101") / "CAPSULE.json",
            {},
        )
        self.assertEqual(loaded["objective_id"], "101")
        self.assertEqual(loaded["material_provenance"], ["analysis/report.md", "evidence/raw.bin"])
        self.assertFalse(check_writeups(store, root, manifest, closeout=True)["ok"])
        create_writeup(root, "101", "Fixture")
        self.assertTrue(check_writeups(store, root, manifest, closeout=True)["ok"])
        td.cleanup()

    def test_stop_lessons_singleton_is_improvements_only(self):
        td = make_workspace("fixture")
        root = Path(td.name)
        manifest, scope, store, result = context(root, "fixture")
        resume(store, reason="start")
        stop(store, root, reason="done", wait_seconds=0)
        one = create_lessons_document(store, root, reason="done")
        two = create_lessons_document(store, root, reason="done again")
        self.assertEqual(one["path"], two["path"])
        self.assertTrue(two["reused"])
        text = (root / one["path"]).read_text().lower()
        self.assertIn("remove or simplify", text)
        self.assertIn("future rookery releases", text)
        self.assertEqual(one["release_version"], "unknown")
        self.assertIn(f"rookery release: `{one['release_version']}`", text)
        self.assertNotIn("current score", text)
        self.assertEqual(len(store.events("lessons.created")), 1)
        td.cleanup()

    def test_validator_generic_and_htb_profiles_and_contamination_fixtures(self):
        for profile in ("manual", "htb"):
            td = make_release_workspace(profile)
            root = Path(td.name)
            before = tree_hash(root)
            report = validate_tree(root, adapter=profile, strict_release=True)
            self.assertTrue(report["ok"], (profile, report["errors"]))
            self.assertEqual(before, tree_hash(root))
            td.cleanup()
        contaminations = [
            ("team.ovpn", "client\nremote fixture.invalid\n"),
            ("logs/runtime.log", "runtime\n"),
            ("state/current.json.tmp.123", "{}\n"),
            ("README.md", "\nlocal=/" + "home/alice/private\n"),
            ("START_PROMPT.md", "generated\n"),
        ]
        for rel, content in contaminations:
            td = make_release_workspace("manual")
            root = Path(td.name)
            (root / ".env").unlink()
            path = root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
            report = validate_tree(root, adapter="manual", strict_release=True)
            self.assertFalse(report["ok"], (rel, report))
            td.cleanup()


class CanonicalReconciliationAcceptance(unittest.TestCase):
    def test_response_import_ledger_completion_and_dedupe(self):
        td = make_workspace("fixture")
        root = Path(td.name)
        manifest, scope, store, result = context(root, "fixture")
        resume(store, reason="test")
        install_solver_ready_challenge(root, store)
        proposal = create_proposal(
            store,
            manifest,
            objective_id="101",
            action_kind="flag",
            exact_value="FIXTURE{ok}",
            attempt_scope={},
            source="analysis/solve/REPORT.md",
            rationale="fixture",
            actor="solver",
        )
        record_review(
            store,
            proposal["proposal_id"],
            "approved",
            reviewer="reviewer-b",
            reason="canonical reconciliation fixture review",
        )
        grant_exact(store, proposal["proposal_id"], reason="import fixture")
        plan = compile_plan(store, root, manifest, scope, proposal["proposal_id"])
        claim_plan_authority(store, plan, loaded_plan=plan, actor="fixture")
        request_dir = root / "submissions" / "external" / "one"
        request_dir.mkdir(parents=True)
        (request_dir / "request.json").write_text(
            json.dumps(
                {
                    "proposal_id": proposal["proposal_id"],
                    "challenge_id": "101",
                    "value": "FIXTURE{ok}",
                    "action_kind": proposal["action_kind"],
                    "adapter_id": proposal["adapter_id"],
                    "attempt_scope": proposal["attempt_scope"],
                }
            )
        )
        (request_dir / "response.json").write_text(json.dumps({"http_status": 200, "data": {"correct": True}}))
        first = import_response(store, root, request_dir / "response.json")
        second = import_response(store, root, request_dir / "response.json")
        self.assertEqual(first["import_status"], "reconciled")
        self.assertEqual(second["import_status"], "already-recorded")
        ledger = answer_ledger(store)
        self.assertEqual(ledger["counts"]["platform_accepted"], 1)
        audit = task_completion_audit(store)
        self.assertTrue(audit["ok"])
        record_task_completion(
            store,
            plan_id=plan["plan_id"],
        )
        self.assertTrue(task_completion_audit(store)["ok"])
        td.cleanup()

    def test_unbound_raw_wrapper_is_ignored_by_default(self):
        td = make_workspace("fixture")
        root = Path(td.name)
        manifest, scope, store, result = context(root, "fixture")
        path = root / "submissions" / "external" / "noise" / "response.json"
        path.parent.mkdir(parents=True)
        path.write_text(json.dumps({"http_status": 200, "success": True}))
        out = import_response(store, root, path)
        self.assertEqual(out["status"], "skipped")
        self.assertEqual(answer_ledger(store)["count"], 0)
        td.cleanup()


if __name__ == "__main__":
    unittest.main(verbosity=2)
