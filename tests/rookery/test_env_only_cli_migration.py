from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from rookery.portable.cli import load_context, main, render_start_prompt, write_setup_note
from rookery.portable.config_migration import (
    ConfigurationMigrationError,
    migrate_event_configuration,
)
from rookery.portable.manifest import ManifestResult
from tests.rookery.support import ROOKERY_ROOT


def legacy_event() -> dict[str, object]:
    return {
        "identity": {
            "id": "legacy-fixture",
            "name": "Legacy fixture",
            "url": "https://ctf.example",
            "starts_at": "2026-09-28T00:00:00Z",
            "ends_at": "2026-09-29T00:00:00Z",
        },
        "adapter": {"id": "ctfd"},
        "scope": {
            "acknowledged": True,
            "allowed_hosts": ["ctf.example"],
            "allowed_cidrs": [],
            "allowed_ports": [443],
            "allowed_protocols": ["https"],
            "allowed_file_origins": [],
            "platform_hosts": ["ctf.example"],
            "max_attachment_bytes": 4096,
            "expires_at": "2026-09-29T00:00:00Z",
        },
        "answer_morphology": {
            "regex": r"flag\{[^}]+\}",
            "examples": ["flag{fixture}"],
        },
        "scoring": {
            "action_kinds": ["flag"],
            "completion_mode": "scorer_truth",
        },
        "authorization": {"automation_permitted_action_kinds": ["flag"]},
    }


class EnvironmentOnlyCliMigrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="rookery-env-migration-")
        self.root = Path(self.temporary.name)
        shutil.copytree(ROOKERY_ROOT / "profiles", self.root / "profiles")
        shutil.copytree(
            ROOKERY_ROOT / "adapters" / "ctfd", self.root / "adapters" / "ctfd"
        )
        self.event = self.root / "event.json"
        self.environment = self.root / ".env"
        self.output = self.root / ".env.migrated"
        self.event.write_text(json.dumps(legacy_event()), encoding="utf-8")
        self.environment.write_text(
            "PLATFORM_ADAPTER=ctfd\nEVENT_MANIFEST=event.json\n",
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @unittest.skipUnless(os.name == "posix", "private drafts require a POSIX workspace")
    def test_migration_is_value_private_no_clobber_and_does_not_create_runtime_state(self) -> None:
        event_before = self.event.read_bytes()
        environment_before = self.environment.read_bytes()
        result = migrate_event_configuration(
            self.root,
            input_path=self.event,
            environment_path=self.environment,
            output_path=self.output,
        )
        self.assertIn("EVENT_NAME", result.migrated_keys)
        self.assertIn("EVENT_MANIFEST", result.removed_legacy_keys)
        self.assertEqual(self.event.read_bytes(), event_before)
        self.assertEqual(self.environment.read_bytes(), environment_before)
        self.assertFalse((self.root / "state").exists())
        draft = self.output.read_text(encoding="utf-8")
        self.assertIn('EVENT_NAME="Legacy fixture"', draft)
        self.assertIn('PLATFORM_ADAPTER="ctfd"', draft)
        self.assertNotIn("EVENT_MANIFEST", draft)
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o600)

        before = self.output.read_bytes()
        with self.assertRaisesRegex(
            ConfigurationMigrationError, "migration_output_exists"
        ):
            migrate_event_configuration(
                self.root,
                input_path=self.event,
                environment_path=self.environment,
                output_path=self.output,
            )
        self.assertEqual(self.output.read_bytes(), before)

    def test_migration_reports_unsupported_and_conflicting_keys_without_values(self) -> None:
        document = legacy_event()
        identity = document["identity"]
        assert isinstance(identity, dict)
        identity["unsupported"] = "do-not-disclose"
        self.event.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaisesRegex(
            ConfigurationMigrationError,
            "migration_unsupported_fields: identity.unsupported",
        ) as unsupported:
            migrate_event_configuration(
                self.root,
                input_path=self.event,
                environment_path=self.environment,
                output_path=self.output,
            )
        self.assertNotIn("do-not-disclose", str(unsupported.exception))
        self.assertFalse(self.output.exists())

        document = legacy_event()
        identity = document["identity"]
        assert isinstance(identity, dict)
        identity["unsafe\nprivate-value"] = "also-private"
        self.event.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaisesRegex(
            ConfigurationMigrationError, "legacy_json_field"
        ) as unsafe_key:
            migrate_event_configuration(
                self.root,
                input_path=self.event,
                environment_path=self.environment,
                output_path=self.output,
            )
        self.assertNotIn("private-value", str(unsafe_key.exception))

        self.event.write_text(json.dumps(legacy_event()), encoding="utf-8")
        self.environment.write_text(
            "PLATFORM_ADAPTER=ctfd\nEVENT_NAME=keep-private\nEVENT_MANIFEST=event.json\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(
            ConfigurationMigrationError,
            "migration_conflicting_fields: EVENT_NAME",
        ) as conflict:
            migrate_event_configuration(
                self.root,
                input_path=self.event,
                environment_path=self.environment,
                output_path=self.output,
            )
        self.assertNotIn("keep-private", str(conflict.exception))
        self.assertFalse(self.output.exists())

    def test_migration_rejects_a_linked_legacy_input(self) -> None:
        linked = self.root / "linked-event.json"
        try:
            linked.symlink_to(self.event)
        except (NotImplementedError, OSError) as exc:  # pragma: no cover - native Windows
            self.skipTest(str(exc))
        with self.assertRaisesRegex(
            ConfigurationMigrationError, "migration_input_invalid"
        ):
            migrate_event_configuration(
                self.root,
                input_path=linked,
                environment_path=self.environment,
                output_path=self.output,
            )
        self.assertFalse(self.output.exists())

    @unittest.skipUnless(os.name == "posix", "private drafts require a POSIX workspace")
    def test_migration_supports_the_profile_only_manual_adapter(self) -> None:
        document = legacy_event()
        adapter = document["adapter"]
        assert isinstance(adapter, dict)
        adapter["id"] = "manual"
        self.event.write_text(json.dumps(document), encoding="utf-8")
        self.environment.write_text(
            "PLATFORM_ADAPTER=manual\nEVENT_MANIFEST=event.json\n",
            encoding="utf-8",
        )
        manual_draft = self.root / ".env.manual.migrated"
        result = migrate_event_configuration(
            self.root,
            input_path=self.event,
            environment_path=self.environment,
            output_path=manual_draft,
        )
        self.assertIn("PLATFORM_ADAPTER", result.migrated_keys)
        self.assertIn('PLATFORM_ADAPTER="manual"', manual_draft.read_text(encoding="utf-8"))

    @unittest.skipUnless(os.name == "posix", "private drafts require a POSIX workspace")
    def test_cli_uses_the_explicit_nonlaunch_migration_path(self) -> None:
        stdout = io.StringIO()
        with mock.patch("rookery.portable.cli.workspace_root", return_value=self.root), contextlib.redirect_stdout(stdout):
            self.assertEqual(
                main(
                    [
                        "config",
                        "migrate-event",
                        "--input",
                        "event.json",
                        "--env",
                        ".env",
                        "--output",
                        ".env.migrated",
                    ]
                ),
                0,
            )
        presentation = json.loads(stdout.getvalue())
        self.assertEqual(presentation["status"], "draft_written")
        self.assertNotIn("Legacy fixture", stdout.getvalue())
        self.assertFalse((self.root / "state").exists())

    @unittest.skipUnless(os.name == "posix", "requires a POSIX private workspace")
    def test_generated_setup_and_start_prompt_only_direct_operators_to_dotenv(self) -> None:
        result = ManifestResult(
            manifest={
                "profile": "ctfd",
                "identity": {"name": "fixture"},
                "adapter": {"id": "ctfd"},
                "scoring": {"completion_mode": "scorer_truth"},
            },
            errors=(),
            warnings=(),
            unresolved_required=("scope.acknowledged",),
        )
        write_setup_note(self.root, result)
        render_start_prompt(self.root, result.manifest, result, {"tools": []})
        setup = (self.root / "NEW_CTF_SETUP.md").read_text(encoding="utf-8")
        prompt = (self.root / "START_PROMPT.md").read_text(encoding="utf-8")
        for text in (setup, prompt):
            self.assertIn(".env", text)
            self.assertNotIn("`event.json`", text)
        self.assertIn("state/resolved_event.json", setup)
        self.assertIn("validate the resolved configuration", prompt)


class EnvironmentOnlyRuntimeResolverTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="rookery-env-runtime-")
        self.root = Path(self.temporary.name)
        shutil.copytree(ROOKERY_ROOT / "profiles", self.root / "profiles")
        shutil.copytree(
            ROOKERY_ROOT / "adapters" / "ctfd_browser_gateway",
            self.root / "adapters" / "ctfd_browser_gateway",
        )
        (self.root / ".env").write_text(
            "\n".join(
                (
                    "PLATFORM_ADAPTER=ctfd_browser_gateway",
                    "EVENT_ID=runtime-fixture",
                    "EVENT_NAME=Runtime fixture",
                    "EVENT_URL=https://ctf.example/event",
                    "EVENT_SCOPE_ACK=1",
                    "ALLOWED_HOSTS=ctf.example",
                    "ALLOWED_PORTS=443",
                    "ALLOWED_PROTOCOLS=https",
                    "PLATFORM_HOSTS=ctf.example",
                    "SCOPE_MAX_BYTES=4096",
                    "CTFD_URL=https://ctf.example",
                    "CTFD_TOKEN=fixture-token-not-a-credential",
                    "BROWSER_MODE=cdp",
                    "BROWSER_CDP_URL=http://127.0.0.1:9001",
                    "BROWSER_GATEWAY_URL=http://127.0.0.1:9003",
                    "ADAPTER_CONFIG_BASE_URL=https://ctf.example",
                    "ADAPTER_CONFIG_SCORING_MODE=team",
                    "ADAPTER_CONFIG_EXPECTED_ACCOUNT_ID=account-7",
                    "ADAPTER_CONFIG_EXPECTED_TEAM_ID=team-9",
                    "ADAPTER_CONFIG_CSRF_PAGE_PATH=/challenges",
                    "ADAPTER_CONFIG_SESSION_LEASE_SECONDS=60",
                    "ADAPTER_CONFIG_TIMEOUT=30",
                    "ADAPTER_CONFIG_MAX_RESPONSE_BYTES=262144",
                    "ADAPTER_CONFIG_BROWSER_SUPPORT_ORIGINS=[]",
                    "",
                )
            ),
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_load_context_retains_the_selected_adapter_schema_values(self) -> None:
        manifest, _, _, result = load_context(self.root, require_ready=True)
        self.assertTrue(result.ready)
        config = manifest["adapter"]["config"]
        self.assertEqual(config["base_url"], "https://ctf.example")
        self.assertEqual(config["scoring_mode"], "team")
        self.assertEqual(config["expected_account_id"], "account-7")
        self.assertEqual(config["expected_team_id"], "team-9")


if __name__ == "__main__":  # pragma: no cover
    unittest.main(verbosity=2)
