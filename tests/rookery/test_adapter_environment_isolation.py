from __future__ import annotations

# ruff: noqa: E402

import io
import json
import os
import runpy
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests.rookery.support import ROOKERY_ROOT

LIB = ROOKERY_ROOT / "lib"
if str(LIB) not in sys.path:
    sys.path.insert(0, str(LIB))

from rookery.portable.adapters import CommandAdapter
from rookery.portable.manifest import env_overlay


def scoped() -> dict[str, object]:
    return {
        "acknowledged": True,
        "generation": 1,
        "expires_at": "unknown",
        "allowed_hosts": ["fixture.invalid"],
        "allowed_cidrs": [],
        "allowed_ports": [],
        "allowed_protocols": ["http", "https"],
        "allowed_file_origins": [],
        "platform_hosts": ["fixture.invalid"],
        "max_attachment_bytes": 4096,
    }


class _Response(io.BytesIO):
    status = 200
    headers = {"Content-Type": "application/json"}

    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()


class AdapterEnvironmentIsolationTests(unittest.TestCase):
    def test_manifest_parses_separate_exact_child_key_arrays(self) -> None:
        overlay = env_overlay(
            {
                "ADAPTER_CONFIG_INVENTORY_ENV_KEYS": '["INVENTORY_SECRET"]',
                "ADAPTER_CONFIG_SUBMIT_ENV_KEYS": '["SUBMIT_SECRET"]',
            }
        )
        config = overlay["adapter"]["config"]
        self.assertEqual(config["inventory_env_keys"], ["INVENTORY_SECRET"])
        self.assertEqual(config["submit_env_keys"], ["SUBMIT_SECRET"])
        with self.assertRaisesRegex(ValueError, "exact environment key"):
            env_overlay({"ADAPTER_CONFIG_INVENTORY_ENV_KEYS": '["TOKEN_*"]'})

    def test_ctfd_uses_bounded_dotenv_token_and_blocks_missing_mutation(self) -> None:
        namespace = runpy.run_path(str(ROOKERY_ROOT / "adapters/ctfd/adapter.py"))
        adapter_class = namespace["CTFdAdapter"]
        module_globals = adapter_class.sync.__globals__
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            token = "fixture-selected-token"
            root.joinpath(".env").write_text(
                "CTFD_URL=https://fixture.invalid\n"
                f"CTFD_LOCAL_TOKEN={token}\n"
                "OTHER_ADAPTER_TOKEN=unrelated\n",
                encoding="utf-8",
            )
            request_headers: list[str | None] = []

            def fake_endpoint(_scope: dict, request, *, timeout: int, transport: object):
                del timeout, transport
                request_headers.append(request.get_header("Authorization"))
                return _Response(b'{"success": true, "data": []}')

            adapter = adapter_class(
                root,
                {"adapter": {"config": {"token_env": "CTFD_LOCAL_TOKEN"}}},
                scoped(),
            )
            with mock.patch.dict(os.environ, {"CTFD_LOCAL_TOKEN": "ambient-wrong"}):
                with mock.patch.dict(module_globals, {"_open_scoped": fake_endpoint}):
                    snapshot = adapter.sync()
            self.assertEqual(snapshot["capabilities"]["platform_inventory"]["health"], "healthy")
            self.assertEqual(request_headers, [f"Token {token}"])
            self.assertNotIn(token, repr(adapter))

            root.joinpath(".env").write_text(
                "CTFD_URL=https://fixture.invalid\n", encoding="utf-8"
            )
            transport = mock.Mock()
            with (
                mock.patch.dict(module_globals, {"_open_scoped": transport}),
                self.assertRaisesRegex(RuntimeError, "required environment key missing"),
            ):
                adapter.execute_action(
                    {"objective_id": "1", "exact_value": "FLAG{fixture}"},
                    root / "evidence",
                )
            transport.assert_not_called()
            self.assertFalse((root / "evidence").exists())

    def test_command_children_receive_only_their_exact_declared_keys(self) -> None:
        child = (
            "import json, os, pathlib, sys; seen = {key: key in os.environ for key in "
            "['INVENTORY_SECRET','SUBMIT_SECRET','CTFD_TOKEN','OPENAI_API_KEY',"
            "'ROOKERY_OWNER_TOKEN','IMMERSIVE_COOKIES_FILE']}; "
            "pathlib.Path(sys.argv[1]).write_text(json.dumps(seen)); "
            "print(json.dumps({'challenges': []}))"
        )
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            inventory_capture = root / "inventory-seen.json"
            submit_capture = root / "submit-seen.json"
            inventory_token = "inventory-only-fixture"
            submit_token = "submit-only-fixture"
            root.joinpath(".env").write_text(
                f"INVENTORY_SECRET={inventory_token}\n"
                f"SUBMIT_SECRET={submit_token}\n"
                "CTFD_TOKEN=other-adapter\n"
                "IMMERSIVE_COOKIES_FILE=other-session\n",
                encoding="utf-8",
            )
            manifest = {
                "identity": {"id": "fixture"},
                "adapter": {
                    "config": {
                        "inventory_argv": [
                            sys.executable,
                            "-c",
                            child,
                            str(inventory_capture),
                        ],
                        "inventory_env_keys": ["INVENTORY_SECRET"],
                        "submit_argv": [
                            sys.executable,
                            "-c",
                            child,
                            str(submit_capture),
                        ],
                        "submit_env_keys": ["SUBMIT_SECRET"],
                    }
                },
            }
            adapter = CommandAdapter(root, manifest, {})
            with mock.patch.dict(
                os.environ,
                {
                    "OPENAI_API_KEY": "provider-fixture",
                    "ROOKERY_OWNER_TOKEN": "owner-fixture",
                    "CTFD_TOKEN": "ambient-other-adapter",
                },
                clear=False,
            ):
                adapter.sync()
                result = adapter.execute_action(
                    {"objective_id": "1", "exact_value": "FLAG{fixture}"},
                    root / "evidence",
                )

            inventory_seen = json.loads(inventory_capture.read_text(encoding="utf-8"))
            submit_seen = json.loads(submit_capture.read_text(encoding="utf-8"))
            self.assertTrue(inventory_seen["INVENTORY_SECRET"])
            for key in (
                "SUBMIT_SECRET",
                "CTFD_TOKEN",
                "OPENAI_API_KEY",
                "ROOKERY_OWNER_TOKEN",
                "IMMERSIVE_COOKIES_FILE",
            ):
                self.assertFalse(inventory_seen[key], key)
            self.assertTrue(submit_seen["SUBMIT_SECRET"])
            for key in (
                "INVENTORY_SECRET",
                "CTFD_TOKEN",
                "OPENAI_API_KEY",
                "ROOKERY_OWNER_TOKEN",
                "IMMERSIVE_COOKIES_FILE",
            ):
                self.assertFalse(submit_seen[key], key)
            passed = result["response"]["environment"]["passed"]
            passed_names = {item["name"] for item in passed}
            self.assertIn("SUBMIT_SECRET", passed_names)
            self.assertNotIn("INVENTORY_SECRET", passed_names)
            serialized = json.dumps(result)
            self.assertNotIn(inventory_token, serialized)
            self.assertNotIn(submit_token, serialized)

            blocked = CommandAdapter(
                root,
                {
                    "adapter": {
                        "config": {
                            "inventory_argv": [
                                sys.executable,
                                "-c",
                                child,
                                str(root / "blocked-seen.json"),
                            ],
                            "inventory_env_keys": ["OPENAI_API_KEY"],
                        }
                    }
                },
                {},
            )
            with self.assertRaisesRegex(RuntimeError, "forbids class provider-auth"):
                blocked.sync()

    def test_immersive_helper_resolves_only_its_fixed_runtime_references(self) -> None:
        namespace = runpy.run_path(
            str(ROOKERY_ROOT / "adapters/immersive/bin/immersive-selected-lab-refresh")
        )
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            root.joinpath(".env").write_text(
                "IMMERSIVE_GRAPHQL_URL=https://dotenv.invalid/graphql\n"
                "CTFD_TOKEN=must-not-be-loaded\n",
                encoding="utf-8",
            )
            namespace["read_env"].__globals__["ROOT"] = root
            with mock.patch.dict(
                os.environ,
                {
                    "IMMERSIVE_GRAPHQL_URL": "https://fixture.invalid/graphql",
                    "CTFD_TOKEN": "must-not-be-loaded",
                    "UNDECLARED_SECRET": "must-not-be-loaded",
                },
                clear=False,
            ):
                resolved = namespace["read_env"]()
            self.assertEqual(
                resolved,
                {"IMMERSIVE_GRAPHQL_URL": "https://dotenv.invalid/graphql"},
            )

    def test_htb_uses_generic_command_adapter_with_separate_key_arrays(self) -> None:
        namespace = runpy.run_path(str(ROOKERY_ROOT / "adapters/htb/adapter.py"))
        adapter_class = namespace["HTBAdapter"]
        self.assertIs(adapter_class.__bases__[0], CommandAdapter)
        child = (
            "import json, os, pathlib, sys; "
            "seen = {key: key in os.environ for key in "
            "['HTB_INVENTORY_ENV', 'HTB_SUBMIT_ENV', 'UNRELATED_SECRET']}; "
            "pathlib.Path(sys.argv[1]).write_text(json.dumps(seen)); "
            "print(json.dumps({'challenges': []}))"
        )
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            inventory_capture = root / "inventory.json"
            submit_capture = root / "submit.json"
            root.joinpath(".env").write_text(
                "HTB_INVENTORY_ENV=inventory-only\n"
                "HTB_SUBMIT_ENV=submit-only\n"
                "UNRELATED_SECRET=not-for-child\n",
                encoding="utf-8",
            )
            manifest = {
                "adapter": {
                    "config": {
                        "inventory_argv": [
                            sys.executable,
                            "-c",
                            child,
                            str(inventory_capture),
                        ],
                        "inventory_env_keys": ["HTB_INVENTORY_ENV"],
                        "submit_argv": [
                            sys.executable,
                            "-c",
                            child,
                            str(submit_capture),
                        ],
                        "submit_env_keys": ["HTB_SUBMIT_ENV"],
                    }
                }
            }
            adapter = adapter_class(root, manifest, scoped())
            with mock.patch.dict(
                os.environ, {"UNRELATED_SECRET": "ambient-not-for-child"}, clear=False
            ):
                adapter.sync()
                adapter.execute_action(
                    {"objective_id": "1", "exact_value": "FLAG{fixture}"},
                    root / "evidence",
                )

            inventory_seen = json.loads(inventory_capture.read_text(encoding="utf-8"))
            submit_seen = json.loads(submit_capture.read_text(encoding="utf-8"))
            self.assertEqual(
                inventory_seen,
                {
                    "HTB_INVENTORY_ENV": True,
                    "HTB_SUBMIT_ENV": False,
                    "UNRELATED_SECRET": False,
                },
            )
            self.assertEqual(
                submit_seen,
                {
                    "HTB_INVENTORY_ENV": False,
                    "HTB_SUBMIT_ENV": True,
                    "UNRELATED_SECRET": False,
                },
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
