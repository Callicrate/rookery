from __future__ import annotations

# ruff: noqa: E402

import ast
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from tests.rookery.support import ROOKERY_ROOT
from tests.rookery.test_preparation_and_isolation import copy_rookery

LIB = ROOKERY_ROOT / "lib"
if str(LIB) not in sys.path:
    sys.path.insert(0, str(LIB))
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

from rookery.portable.adapters import CommandAdapter, run_bounded_argv
from rookery.portable.compat import execute_plan_alias
from rookery.portable.control import stop
from rookery.portable.environment import (
    EnvClass,
    EnvKey,
    EnvironmentPolicyError,
    build_child_environment,
    purpose_policy,
)
from rookery.portable.store import EventStore
from rookery.portable.validator import (
    _child_environment_launch_errors,
    _validate_child_environment_launches,
    validate_tree,
)
from rookery.portable.watchers import ensure_queue_watcher


SENTINELS = {
    "DUMMY_PARENT_SECRET": "parent-value",
    "DUMMY_PROVIDER_SECRET": "provider-value",
    "DUMMY_ADAPTER_SECRET": "adapter-value",
    "ROOKERY_OWNER_TOKEN": "owner-value",
}


def environment_names(script: str = "") -> list[str]:
    body = script or "import json, os; print(json.dumps(sorted(os.environ)))"
    return [sys.executable, "-c", body]


class BoundedChildEnvironmentTests(unittest.TestCase):
    def test_default_bounded_command_excludes_all_ambient_secret_sources(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / ".env").write_text(
                "DUMMY_DOTENV_SECRET=dotenv-value\n"
                "DUMMY_PROVIDER_SECRET=dotenv-provider\n"
                "DUMMY_ADAPTER_SECRET=dotenv-adapter\n",
                encoding="utf-8",
            )
            (root / "state").mkdir()
            (root / "state" / "prepared.env").write_text(
                "DUMMY_PREPARED_SECRET=prepared-value\n", encoding="utf-8"
            )
            with mock.patch.dict(os.environ, SENTINELS, clear=False):
                result = run_bounded_argv(
                    environment_names(),
                    cwd=root,
                    timeout=5,
                    max_output_bytes=16 * 1024,
                )

            self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8"))
            names = set(json.loads(result.stdout))
            excluded = {
                *SENTINELS,
                "DUMMY_DOTENV_SECRET",
                "DUMMY_PREPARED_SECRET",
            }
            self.assertFalse(names & excluded)
            metadata = result.metadata()
            self.assertEqual(metadata["environment"]["policy"], "bounded-command")
            serialized = json.dumps(metadata, sort_keys=True)
            for value in (
                *SENTINELS.values(),
                "dotenv-value",
                "dotenv-provider",
                "dotenv-adapter",
                "prepared-value",
            ):
                self.assertNotIn(value, serialized)

    def test_command_adapter_passes_only_declared_existing_keys_and_records_metadata(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / ".env").write_text(
                "DUMMY_COMMAND_KEY=declared-command-value\n"
                "DUMMY_ADAPTER_SECRET=dotenv-adapter-value\n",
                encoding="utf-8",
            )
            command = environment_names(
                "import json, os; print(json.dumps({'schema_version': '1', 'capabilities': {}, 'challenges': [], 'keys': sorted(os.environ)}))"
            )
            adapter = CommandAdapter(
                root,
                {
                    "identity": {"id": "fixture"},
                    "adapter": {
                        "config": {
                            "inventory_argv": command,
                            "inventory_env_keys": ["DUMMY_COMMAND_KEY"],
                        }
                    },
                },
                {},
            )
            with mock.patch.dict(os.environ, SENTINELS, clear=False):
                snapshot = adapter.sync()

            self.assertIn("DUMMY_COMMAND_KEY", snapshot["keys"])
            self.assertFalse(set(SENTINELS) & set(snapshot["keys"]))
            metadata = snapshot["environment"]
            self.assertEqual(metadata["policy"], "adapter-inventory")
            self.assertIn(
                {"name": "DUMMY_COMMAND_KEY", "class": "unknown-explicit"},
                metadata["passed"],
            )
            self.assertNotIn("declared-command-value", json.dumps(metadata))

            missing = CommandAdapter(
                root,
                {
                    "adapter": {
                        "config": {
                            "inventory_argv": command,
                            "inventory_env_keys": ["MISSING_COMMAND_KEY"],
                        }
                    }
                },
                {},
            )
            with self.assertRaisesRegex(
                RuntimeError,
                "required environment key missing.*MISSING_COMMAND_KEY",
            ):
                missing.sync()

            with self.assertRaisesRegex(
                EnvironmentPolicyError,
                "required environment key missing.*MISSING_COMMAND_KEY",
            ):
                build_child_environment(
                    root,
                    policy=purpose_policy("required-explicit-name"),
                    pass_names=("MISSING_COMMAND_KEY",),
                    parent={},
                )

    def test_submit_environment_metadata_never_records_values(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / ".env").write_text(
                "DUMMY_SUBMIT_KEY=submit-command-value\n", encoding="utf-8"
            )
            adapter = CommandAdapter(
                root,
                {
                    "identity": {"id": "fixture"},
                    "adapter": {
                        "config": {
                            "submit_argv": environment_names(
                                "import json, os; print(json.dumps({'success': True, 'correct': True, 'keys': sorted(os.environ)}))"
                            ),
                            "submit_env_keys": ["DUMMY_SUBMIT_KEY"],
                        }
                    },
                },
                {},
            )
            records: list[dict[str, object]] = []

            def capture(_path: Path, value: dict[str, object], **_kwargs: object) -> None:
                records.append(value)

            with mock.patch("rookery.portable.adapters.atomic_write_json", capture):
                adapter.execute_action(
                    {
                        "objective_id": "objective",
                        "exact_value": "candidate",
                        "action_kind": "flag",
                    },
                    root / "evidence",
                )

            self.assertEqual(len(records), 2)
            for record in records:
                metadata = record["environment"]
                self.assertIn(
                    {"name": "DUMMY_SUBMIT_KEY", "class": "unknown-explicit"},
                    metadata["passed"],
                )
                self.assertNotIn("submit-command-value", json.dumps(metadata))


@unittest.skipUnless(
    os.name == "posix" and hasattr(os, "mkfifo"),
    "requires POSIX regular-file and FIFO semantics",
)
class ChildEnvironmentValueValidationTests(unittest.TestCase):
    @staticmethod
    def ca_child(root: Path, path: Path) -> object:
        parent = dict(os.environ)
        parent["SSL_CERT_FILE"] = str(path)
        return build_child_environment(
            root,
            policy=purpose_policy(
                "ca-trust",
                (EnvKey("SSL_CERT_FILE", EnvClass.CA_TRUST_PATH),),
            ),
            parent=parent,
        )

    def test_ca_trust_path_rejects_unreadable_link_and_special_files_without_values(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            bundle = root / "bundle.pem"
            bundle.write_text("fixture certificate bundle\n", encoding="utf-8")
            child = self.ca_child(root, bundle)
            self.assertIn("SSL_CERT_FILE", child.values)

            with mock.patch(
                "rookery.portable.environment.os.open",
                side_effect=PermissionError("denied"),
            ):
                with self.assertRaises(EnvironmentPolicyError) as unreadable:
                    self.ca_child(root, bundle)
            self.assertIn("SSL_CERT_FILE", str(unreadable.exception))
            self.assertNotIn(str(bundle), str(unreadable.exception))

            link = root / "bundle-link.pem"
            link.symlink_to(bundle)
            with self.assertRaises(EnvironmentPolicyError) as linked:
                self.ca_child(root, link)
            self.assertIn("SSL_CERT_FILE", str(linked.exception))
            self.assertNotIn(str(link), str(linked.exception))

            hard_link = root / "bundle-hard-link.pem"
            os.link(bundle, hard_link)
            with self.assertRaises(EnvironmentPolicyError) as hard_linked:
                self.ca_child(root, hard_link)
            self.assertIn("SSL_CERT_FILE", str(hard_linked.exception))
            self.assertNotIn(str(hard_link), str(hard_linked.exception))

            special = root / "bundle.fifo"
            os.mkfifo(special)
            with self.assertRaises(EnvironmentPolicyError) as fifo:
                self.ca_child(root, special)
            self.assertIn("SSL_CERT_FILE", str(fifo.exception))
            self.assertNotIn(str(special), str(fifo.exception))

    def test_proxy_aliases_must_not_conflict(self):
        with self.assertRaisesRegex(EnvironmentPolicyError, "conflicting proxy aliases"):
            build_child_environment(
                Path.cwd(),
                policy=purpose_policy(
                    "proxy-aliases",
                    (
                        EnvKey("HTTP_PROXY", EnvClass.PROXY_CREDENTIAL),
                        EnvKey("http_proxy", EnvClass.PROXY_CREDENTIAL),
                    ),
                ),
                parent={
                    "HTTP_PROXY": "http://first.invalid",
                    "http_proxy": "http://second.invalid",
                },
            )


class FixedChildEnvironmentTests(unittest.TestCase):
    def test_compatibility_child_is_minimal(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            plan = root / "state" / "execution_plans"
            plan.mkdir(parents=True)
            (plan / "plan_fixture.json").write_text(
                json.dumps({"semantic_action": "flag", "adapter_id": "fixture"}),
                encoding="utf-8",
            )
            with (
                mock.patch.dict(os.environ, SENTINELS, clear=False),
                mock.patch(
                    "rookery.portable.compat.subprocess.run",
                    return_value=SimpleNamespace(returncode=0),
                ) as run,
            ):
                self.assertEqual(
                    execute_plan_alias(
                        root,
                        "plan_fixture",
                        allowed_actions={"flag"},
                        adapter_id="fixture",
                    ),
                    0,
                )
            self.assertFalse(set(SENTINELS) & set(run.call_args.kwargs["env"]))

    def test_validator_child_is_minimal_and_static_gate_rejects_ambient_launches(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            copy_rookery(root)
            with (
                mock.patch.dict(os.environ, SENTINELS, clear=False),
                mock.patch("shutil.which", return_value="/fake/bash"),
                mock.patch(
                    "rookery.portable.validator.subprocess.run",
                    return_value=SimpleNamespace(returncode=0, stderr=""),
                ) as run,
            ):
                validate_tree(root, adapter="manual", strict_release=True)
            self.assertTrue(run.call_args_list)
            for call in run.call_args_list:
                self.assertFalse(set(SENTINELS) & set(call.kwargs["env"]))

            errors: list[str] = []
            _validate_child_environment_launches(root, errors)
            # Every shipped Python module and Python-shebang entrypoint is
            # clean after the ambient-environment and raw-transport repairs.
            # Synthetic caller violations remain covered by the dedicated
            # static-validator regression module.
            self.assertEqual(errors, [])
            compat = root / "lib" / "rookery" / "portable" / "compat.py"
            compat.write_text(
                compat.read_text(encoding="utf-8").replace(
                    "env=child_environment.values", "env=None", 1
                ),
                encoding="utf-8",
            )
            errors = []
            _validate_child_environment_launches(root, errors)
            self.assertTrue(any("requires ChildEnvironment.values" in error for error in errors))

    def test_static_gate_detects_every_subprocess_launch_kind_and_ambient_patterns(self):
        tree = ast.parse(
            "\n".join(
                [
                    f"subprocess.{method}(['tool'], env=None)"
                    for method in ("Popen", "run", "call", "check_call", "check_output")
                ]
                + [
                    "subprocess.run(['tool'], env=dict(os.environ))",
                    "subprocess.run(['tool'], env=os.environ)",
                ]
            )
        )
        errors = _child_environment_launch_errors(tree, "synthetic.py")
        self.assertEqual(
            sum("requires ChildEnvironment.values" in error for error in errors),
            5,
        )
        self.assertTrue(
            any("whole ambient environment mapping is forbidden" in error for error in errors)
        )
        self.assertTrue(any("forbids a whole environment mapping" in error for error in errors))


@unittest.skipUnless(
    os.name == "posix" and Path("/proc").is_dir(),
    "requires POSIX /proc process environments",
)
class QueueWatcherEnvironmentTests(unittest.TestCase):
    def test_watcher_proc_environment_has_only_minimal_names_and_owner_token(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            copy_rookery(root)
            # This test exercises the watcher launcher in an isolated fixture,
            # not a deployed workspace; avoid importing the independent
            # launch-binding admission contract into that setup.
            (root / "VERSION").unlink()
            store = EventStore(root)
            with mock.patch.dict(os.environ, SENTINELS, clear=False):
                watcher = ensure_queue_watcher(
                    store,
                    root,
                    {"queue": {"automation_enabled": True, "watch_interval_seconds": 1}},
                )
            try:
                self.assertTrue(watcher["running"])
                pid = int(watcher["job"]["pid"])
                deadline = time.monotonic() + 3
                names: set[str] = set()
                while time.monotonic() < deadline:
                    try:
                        names = {
                            item.split("=", 1)[0]
                            for item in (Path("/proc") / str(pid) / "environ")
                            .read_bytes()
                            .decode("utf-8", errors="replace")
                            .split("\0")
                            if item
                        }
                    except FileNotFoundError:
                        break
                    if "ROOKERY_OWNER_TOKEN" in names:
                        break
                    time.sleep(0.02)
                self.assertIn("ROOKERY_OWNER_TOKEN", names)
                self.assertFalse(set(SENTINELS) - {"ROOKERY_OWNER_TOKEN"} & names)
                self.assertNotIn("DUMMY_PARENT_SECRET", names)
                self.assertNotIn("DUMMY_PROVIDER_SECRET", names)
                self.assertNotIn("DUMMY_ADAPTER_SECRET", names)
            finally:
                stop(store, root, reason="test cleanup", wait_seconds=2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
