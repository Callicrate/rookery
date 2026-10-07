from __future__ import annotations

# ruff: noqa: E402

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests.rookery.support import ROOKERY_ROOT, bootstrap_public_workspace
from tests.rookery.env_fixtures import (
    configure_event_environment,
    replace_env_assignments,
)
from tests.rookery.test_preparation_and_isolation import copy_rookery

LIB = ROOKERY_ROOT / "lib"
if str(LIB) not in os.sys.path:
    os.sys.path.insert(0, str(LIB))

from rookery.portable import environment as environment_module
from rookery.portable.baseline import write_measurement_baseline
from rookery.portable.execution import compile_plan, execute_plan
from rookery.portable.environment import (
    EnvironmentPolicyError,
    _open_verified_codex_descriptor,
    _selected_adapter_contract,
    codex_policy,
    immutable_source_digest,
    read_launch_binding,
    resolve_launch_gate,
    verify_launch_binding_integrity,
)
from rookery.portable.manifest import resolve_manifest
from rookery.portable.release import build_release
from rookery.portable.scope import compile_scope, load_canonical_compiled_scope
from rookery.portable.scoring import create_proposal, record_review
from rookery.portable.store import EventStore
from rookery.portable.util import tree_hash


class LaunchBindingIntegrityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "rookery"
        copy_rookery(self.root)
        shutil.rmtree(self.root / ".ruff_cache", ignore_errors=True)
        shutil.rmtree(self.root / ".pytest_cache", ignore_errors=True)
        self._configure_ready_event(self.root)
        self.fake_temporary = tempfile.TemporaryDirectory()
        self.fake_bin = Path(self.fake_temporary.name) / "bin"
        self.fake_bin.mkdir()
        self.login_log = Path(self.fake_temporary.name) / "login.log"
        self.codex = self.fake_bin / "codex"
        self.codex.write_text(
            "#!/usr/bin/env bash\n"
            "set -euo pipefail\n"
            "if [ \"$1\" = --version ]; then echo 'codex-cli 0.150.0'; exit 0; fi\n"
            "if [ \"$1\" = --strict-config ] && [ \"$2\" = --version ]; then exit 0; fi\n"
            "if [ \"$1\" = doctor ]; then printf '%s\\n' '{\"checks\":{\"config.load\":{\"status\":\"ok\"}}}'; exit 0; fi\n"
            "if [ \"$1\" = --strict-config ] && [ \"$2\" = login ] && [ \"$3\" = status ]; then\n"
            "  test \"${DUMMY_PROVIDER_KEY:-}\" = 'provider-fixture'\n"
            "  test -z \"${CTFD_TOKEN:-}\"\n"
            f"  printf '%s' environment > {json.dumps(str(self.login_log))}\n"
            "  exit 0\n"
            "fi\n"
            "exit 0\n",
            encoding="utf-8",
        )
        self.codex.chmod(0o755)
        self.environment = {
            **os.environ,
            "PATH": str(self.fake_bin) + os.pathsep + os.environ.get("PATH", ""),
            "CODEX_AUTH_MODE": "environment",
            "CODEX_PROVIDER_ENV_KEYS": '["DUMMY_PROVIDER_KEY"]',
            "DUMMY_PROVIDER_KEY": "provider-fixture",
            "CTFD_TOKEN": "adapter-fixture-must-not-reach-codex",
        }
        self.bootstrap = bootstrap_public_workspace(
            self.root, environment=self.environment
        )

    def tearDown(self) -> None:
        getattr(self, "bootstrap", None) and self.bootstrap.cleanup()
        self.fake_temporary.cleanup()
        self.temporary.cleanup()

    @staticmethod
    def _configure_ready_event(root: Path) -> None:
        configure_event_environment(
            root,
            "manual",
            name_suffix="Binding Fixture",
            extra={
                "EVENT_ID": "binding-fixture",
                "ALLOWED_HOSTS": "fixture.invalid",
                "ALLOWED_CIDRS": "",
                "ALLOWED_PORTS": "443",
                "ALLOWED_PROTOCOLS": "https",
                "ALLOWED_FILE_ORIGINS": "fixture://*",
                "PLATFORM_HOSTS": "",
                "SCOPE_MAX_BYTES": "1024",
                "ROOKERY_MEASUREMENT_BASELINE_PATH": "",
                "CODEX_AUTH_MODE": "",
                "CODEX_PROVIDER_ENV_KEYS": "",
            },
        )

    def test_environment_login_uses_exact_filtered_launcher_environment(self) -> None:
        self.assertEqual(self.login_log.read_text(encoding="utf-8"), "environment")
        binding = verify_launch_binding_integrity(self.root)
        self.assertEqual(binding.record["auth_mode"], "environment")

    def test_effect_scope_binding_carries_current_launch_identity(self) -> None:
        with mock.patch.dict(
            os.environ,
            {"ROOKERY_MEASUREMENT_BASELINE_PATH": str(self.bootstrap.baseline_path)},
            clear=False,
        ):
            scope_binding = load_canonical_compiled_scope(self.root)
        self.assertEqual(
            scope_binding.launch_binding_sha256,
            verify_launch_binding_integrity(self.root).sha256,
        )

    def test_public_start_allows_immediate_normal_stop_without_source_drift(self) -> None:
        before_hash = immutable_source_digest(self.root)
        before_binding = verify_launch_binding_integrity(self.root).sha256
        stopped = subprocess.run(
            [str(self.root / "go"), "stop"],
            cwd=self.root,
            env=self.bootstrap.environment,
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(stopped.returncode, 0, stopped.stderr)
        self.assertNotIn('"emergency_stop": true', stopped.stdout)
        self.assertNotIn("binding_integrity_blocker", stopped.stdout)
        self.assertEqual(immutable_source_digest(self.root), before_hash)
        self.assertEqual(verify_launch_binding_integrity(self.root).sha256, before_binding)

    def test_sqlite_metadata_and_open_store_detect_binding_removal(self) -> None:
        binding = verify_launch_binding_integrity(self.root)
        store = EventStore(self.root)
        self.assertEqual(store.get_meta("launch_binding_sha256"), binding.sha256)
        self.assertEqual(
            store.get_meta("launch_workspace_identity"), binding.record["workspace_identity"]
        )
        self.assertEqual(
            store.get_meta("immutable_source_sha256"),
            binding.record["immutable_source_sha256"],
        )

        path = self.root / "state" / "launch_binding.json"
        path.unlink()
        with self.assertRaisesRegex(RuntimeError, "launch binding integrity"):
            store.append("fixture.event", {"ok": True})
        before_status = tree_hash(self.root)
        rendered = subprocess.run(
            [str(self.root / "go"), "status"],
            cwd=self.root,
            env=self.bootstrap.environment,
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(before_status, tree_hash(self.root))
        self.assertEqual(rendered.returncode, 0, rendered.stderr)
        self.assertIn("binding_integrity=launch_binding_missing", rendered.stdout)
        stopped = subprocess.run(
            [str(self.root / "go"), "stop"],
            cwd=self.root,
            env=self.bootstrap.environment,
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(stopped.returncode, 0, stopped.stderr)
        self.assertIn('"emergency_stop": true', stopped.stdout)
        self.assertFalse(path.exists())

    def test_source_config_and_copied_root_drift_fail_closed(self) -> None:
        store = EventStore(self.root)
        source = self.root / "README.md"
        original = source.read_bytes()
        source.write_bytes((b"X" if original[:1] != b"X" else b"Y") + original[1:])
        with self.assertRaisesRegex(RuntimeError, "immutable_source_drift"):
            store.append("fixture.event", {"source": "changed"})
        source.write_bytes(original)

        environment = self.root / ".env"
        original_environment = environment.read_bytes()
        stamp = environment.stat().st_mtime_ns
        environment.write_bytes(
            original_environment.replace(b"manual", b"manuaL", 1)
        )
        os.utime(environment, ns=(stamp, stamp))
        with self.assertRaisesRegex(RuntimeError, "launch_configuration_drift"):
            EventStore(self.root)
        environment.write_bytes(original_environment)

        copied = Path(self.temporary.name) / "copied"
        shutil.copytree(self.root, copied)
        with self.assertRaisesRegex(RuntimeError, "launch_workspace_identity_drift"):
            EventStore(copied)

    def test_same_stat_codex_replacement_is_detected_by_content_digest(self) -> None:
        binding = read_launch_binding(self.root)
        original = self.codex.read_bytes()
        info = self.codex.stat()
        replacement = original.replace(b"exit 0", b"exit 1", 1)
        self.assertEqual(len(replacement), len(original))
        self.codex.write_bytes(replacement)
        os.utime(self.codex, ns=(info.st_atime_ns, info.st_mtime_ns))
        with self.assertRaisesRegex(EnvironmentPolicyError, "codex_executable_drift"):
            _open_verified_codex_descriptor(binding)
        self.codex.write_bytes(original)

    def test_local_login_named_provider_and_htb_implicit_token_are_rejected_or_absent(self) -> None:
        environment = self.root / ".env"
        original = environment.read_bytes()
        try:
            replace_env_assignments(
                self.root,
                {
                    "CODEX_AUTH_MODE": "local-login",
                    "CODEX_PROVIDER_ENV_KEYS": '["DUMMY_PROVIDER_KEY"]',
                },
            )
            with self.assertRaisesRegex(EnvironmentPolicyError, "local-login forbids"):
                codex_policy(self.root, parent={"PATH": os.defpath})
        finally:
            environment.write_bytes(original)
        _selected_adapter_contract(
            self.root,
            {
                "adapter": {"id": "htb", "config": {}},
                "capabilities": {"required": ["platform_inventory"]},
            },
        )

    def _approved_plan_inputs(self) -> tuple[EventStore, dict, dict, dict]:
        store = EventStore(self.root)
        resolved = resolve_manifest(self.root)
        self.assertTrue(resolved.ready, resolved)
        proposal = create_proposal(
            store,
            resolved.manifest,
            objective_id="binding-objective",
            action_kind="no_submit_evidence",
            artifact_reference="analysis/binding/REPORT.md",
            source="analysis/binding/REPORT.md",
            rationale="plan publication fixture",
            actor="solver-a",
        )
        record_review(
            store,
            proposal["proposal_id"],
            "approved",
            reviewer="reviewer-b",
            reason="independent fixture review",
        )
        return store, resolved.manifest, compile_scope(resolved.manifest), proposal

    def test_plan_publication_drift_leaves_no_event_or_orphan_file(self) -> None:
        store, manifest, scope, proposal = self._approved_plan_inputs()
        environment_path = self.root / ".env"
        original_environment = environment_path.read_bytes()
        from rookery.portable import execution as execution_module

        real_snapshot = execution_module.admission_snapshot_in_transaction

        def snapshot_then_configuration_drift(connection):
            snapshot = real_snapshot(connection)
            environment_path.write_bytes(original_environment + b"# drift\n")
            return snapshot

        try:
            with (
                mock.patch.object(
                    execution_module,
                    "admission_snapshot_in_transaction",
                    side_effect=snapshot_then_configuration_drift,
                ),
                self.assertRaisesRegex(RuntimeError, "launch_configuration_drift"),
            ):
                compile_plan(store, self.root, manifest, scope, proposal["proposal_id"])
        finally:
            environment_path.write_bytes(original_environment)

        self.assertEqual(store.events("execution.planned"), [])
        self.assertFalse(list((self.root / "state" / "execution_plans").glob("plan_*.json")))

    def test_plan_publication_writes_derived_file_after_canonical_event(self) -> None:
        store, manifest, scope, proposal = self._approved_plan_inputs()
        plan = compile_plan(store, self.root, manifest, scope, proposal["proposal_id"])
        events = store.events("execution.planned")
        self.assertEqual(len(events), 1)
        path = self.root / "state" / "execution_plans" / f"{plan['plan_id']}.json"
        self.assertTrue(path.is_file())
        self.assertEqual(json.loads(path.read_text(encoding="utf-8")), plan)

    def test_missing_derived_plan_recovers_from_canonical_event_after_write_failure(self) -> None:
        store, manifest, scope, proposal = self._approved_plan_inputs()
        with (
            mock.patch(
                "rookery.portable.execution.atomic_write_json",
                side_effect=OSError("fixture derived-plan write failure"),
            ),
            self.assertRaisesRegex(OSError, "derived-plan write failure"),
        ):
            compile_plan(store, self.root, manifest, scope, proposal["proposal_id"])

        events = store.events("execution.planned")
        self.assertEqual(len(events), 1)
        plan_id = events[0]["payload"]["plan_id"]
        self.assertFalse(
            (self.root / "state" / "execution_plans" / f"{plan_id}.json").exists()
        )
        adapter = mock.Mock()
        adapter.preflight_action.return_value = {"ok": True}
        adapter.execute_action.return_value = {
            "verdict": {"verdict": "accepted", "scorer_truth": "accepted"},
            "response_path": "submissions/recovered-plan-response.json",
        }
        with mock.patch(
            "rookery.portable.execution.get_adapter", return_value=adapter
        ):
            outcome, rc = execute_plan(store, self.root, manifest, scope, plan_id)
        self.assertEqual(rc, 0, outcome)
        self.assertEqual(outcome["status"], "completed")
        adapter.execute_action.assert_not_called()


class ProbeMutationBeforePublicationTests(unittest.TestCase):
    def test_probe_mutation_is_rejected_before_binding_publication(self) -> None:
        with tempfile.TemporaryDirectory() as name, tempfile.TemporaryDirectory() as external_name:
            root = Path(name) / "rookery"
            copy_rookery(root)
            LaunchBindingIntegrityTests._configure_ready_event(root)
            artifacts = Path(external_name) / "artifacts"
            baseline = Path(external_name) / "baseline.json"
            replace_env_assignments(
                root,
                {"ROOKERY_MEASUREMENT_BASELINE_PATH": str(baseline)},
            )
            summary = build_release(root, artifacts)
            write_measurement_baseline(
                root,
                artifacts / str(summary["archive"]),
                artifacts / str(summary["manifest"]),
                baseline,
            )
            readme = root / "README.md"
            original = readme.read_bytes()

            def mutate_probe(*_args, **_kwargs):
                readme.write_bytes((b"X" if original[:1] != b"X" else b"Y") + original[1:])
                return (
                    "/fixture/codex",
                    {
                        "path": "/fixture/codex",
                        "device": 1,
                        "inode": 1,
                        "size": 1,
                        "mtime_ns": 1,
                        "sha256": "a" * 64,
                    },
                    "0.150.0",
                    True,
                )

            with (
                mock.patch.object(environment_module, "_probe_codex", side_effect=mutate_probe),
                self.assertRaisesRegex(EnvironmentPolicyError, "immutable_source_drift"),
            ):
                resolve_launch_gate(
                    root,
                    parent={
                        "PATH": os.defpath,
                        "ROOKERY_MEASUREMENT_BASELINE_PATH": str(baseline),
                    },
                )
            self.assertFalse((root / "state").exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
