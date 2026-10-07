from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[2] / "rookery"
if str(SOURCE / "lib") not in sys.path:
    sys.path.insert(0, str(SOURCE / "lib"))

from rookery.portable.environment import (  # noqa: E402
    EnvironmentPolicyError,
    _editable_configuration_digests,
    immutable_source_digest,
)
from rookery.portable.event_env import event_environment_names, resolve_event_environment  # noqa: E402
from rookery.portable.manifest import resolve_manifest  # noqa: E402


class EnvironmentOnlyEventTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        shutil.copytree(SOURCE / "profiles", self.root / "profiles")
        (self.root / "adapters").mkdir()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _copy_adapter(self, adapter_id: str) -> None:
        shutil.copytree(SOURCE / "adapters" / adapter_id, self.root / "adapters" / adapter_id)

    @staticmethod
    def _event(adapter: str = "manual") -> dict[str, str]:
        return {
            "PLATFORM_ADAPTER": adapter,
            "EVENT_ID": "fixture",
            "EVENT_NAME": "Fixture event",
            "EVENT_URL": "https://example.test/event/path?view=active",
            "EVENT_SCOPE_ACK": "1",
            "ALLOWED_HOSTS": "example.test",
            "SCOPE_MAX_BYTES": "4096",
        }

    def test_normal_resolver_never_reads_event_json(self) -> None:
        (self.root / "event.json").write_bytes(b"not json\x00private legacy material")
        first = resolve_manifest(self.root, env=self._event())
        (self.root / "event.json").write_text('{"identity":{"name":"wrong"}}', encoding="utf-8")
        second = resolve_manifest(self.root, env=self._event())
        self.assertTrue(first.ready)
        self.assertEqual(first.manifest, second.manifest)
        self.assertEqual(first.manifest["identity"]["name"], "Fixture event")

    def test_dotenv_is_the_complete_normal_launch_input(self) -> None:
        (self.root / ".env").write_text(
            "\n".join(f"{name}={value}" for name, value in self._event().items()) + "\n",
            encoding="utf-8",
        )
        (self.root / "event.json").write_bytes(b"\x00legacy file must stay unread")
        result = resolve_manifest(self.root, parent={"EVENT_NAME": "ambient must not win"})
        self.assertTrue(result.ready, result)
        self.assertEqual(result.manifest["identity"]["name"], "Fixture event")

    def test_removed_manifest_selector_fails_with_migration_direction(self) -> None:
        values = self._event()
        values["EVENT_MANIFEST"] = "event.json"
        with self.assertRaisesRegex(
            EnvironmentPolicyError,
            "event_manifest_removed_use_migrate_event",
        ):
            resolve_manifest(self.root, env=values)

    def test_gateway_fields_are_typed_and_selected(self) -> None:
        self._copy_adapter("ctfd_browser_gateway")
        values = self._event("ctfd_browser_gateway")
        values.update(
            {
                "CTFD_URL": "https://ctf.example",
                "CTFD_TOKEN": "test-secret-never-enters-manifest",
                "PLATFORM_HOSTS": "ctf.example,challenges.cloudflare.com",
                "BROWSER_MODE": "cdp",
                "BROWSER_CDP_URL": "http://127.0.0.1:9001",
                "BROWSER_GATEWAY_URL": "http://127.0.0.1:9003",
                "ADAPTER_CONFIG_TOKEN_ENV": "CTFD_TOKEN",
                "ADAPTER_CONFIG_SCORING_MODE": "team",
                "ADAPTER_CONFIG_EXPECTED_ACCOUNT_ID": "account-7",
                "ADAPTER_CONFIG_EXPECTED_TEAM_ID": "team-9",
                "ADAPTER_CONFIG_CSRF_PAGE_PATH": "/challenges",
                "ADAPTER_CONFIG_SESSION_LEASE_SECONDS": "60",
                "ADAPTER_CONFIG_TIMEOUT": "30",
                "ADAPTER_CONFIG_MAX_RESPONSE_BYTES": "262144",
                "ADAPTER_CONFIG_BROWSER_SUPPORT_ORIGINS": '["https://challenges.cloudflare.com"]',
            }
        )
        result = resolve_manifest(self.root, env=values)
        self.assertTrue(result.ready, result)
        config = result.manifest["adapter"]["config"]
        self.assertEqual(config["timeout"], 30)
        self.assertEqual(config["expected_team_id"], "team-9")
        self.assertEqual(config["browser_support_origins"], ["https://challenges.cloudflare.com"])
        self.assertNotIn("test-secret-never-enters-manifest", json.dumps(result.manifest, sort_keys=True))

    def test_gateway_team_mode_requires_team_identity(self) -> None:
        self._copy_adapter("ctfd_browser_gateway")
        values = self._event("ctfd_browser_gateway")
        values.update(
            {
                "ADAPTER_CONFIG_SCORING_MODE": "team",
                "ADAPTER_CONFIG_EXPECTED_ACCOUNT_ID": "account-7",
            }
        )
        result = resolve_event_environment(self.root, env=values)
        self.assertIn("ADAPTER_CONFIG_EXPECTED_TEAM_ID", result.unresolved_required)

    def test_unselected_adapter_field_is_rejected(self) -> None:
        self._copy_adapter("ctfd_browser_gateway")
        values = self._event()
        values["ADAPTER_CONFIG_EXPECTED_ACCOUNT_ID"] = "account-7"
        with self.assertRaisesRegex(EnvironmentPolicyError, "event_environment_unselected"):
            resolve_manifest(self.root, env=values)

    def test_blank_unselected_catalog_fields_are_inert_but_blank_typos_fail(self) -> None:
        self._copy_adapter("ctfd_browser_gateway")
        values = self._event()
        values["ADAPTER_CONFIG_EXPECTED_ACCOUNT_ID"] = ""
        self.assertTrue(resolve_manifest(self.root, env=values).ready)
        values["MISSPELLED_EVENT_OPTION"] = ""
        with self.assertRaisesRegex(EnvironmentPolicyError, "event_environment_undeclared"):
            resolve_manifest(self.root, env=values)

    def test_dynamic_selectors_cannot_admit_owner_authority(self) -> None:
        values = self._event()
        values.update(
            {
                "CODEX_PROVIDER_ENV_KEYS": '["ROOKERY_OWNER_TOKEN"]',
                "ROOKERY_OWNER_TOKEN": "must-not-become-event-input",
            }
        )
        with self.assertRaisesRegex(EnvironmentPolicyError, "CODEX_PROVIDER_ENV_KEYS"):
            resolve_manifest(self.root, env=values)

    def test_exact_origins_reject_paths_and_uppercase_hosts(self) -> None:
        self._copy_adapter("ctfd")
        for origin in ("https://ctf.example/path", "https://CTF.example"):
            with self.subTest(origin=origin):
                values = self._event("ctfd")
                values["ADAPTER_CONFIG_BASE_URL"] = origin
                with self.assertRaisesRegex(EnvironmentPolicyError, "ADAPTER_CONFIG_BASE_URL"):
                    resolve_manifest(self.root, env=values)

    def test_adapter_examples_cover_declared_schema(self) -> None:
        for adapter_id in ("ctfd", "ctfd_browser", "ctfd_browser_gateway", "immersive"):
            with self.subTest(adapter=adapter_id):
                self._copy_adapter(adapter_id)
                names = event_environment_names(self.root, adapter_id)
                adapter_names = {name for name in names if name.startswith(("ADAPTER_CONFIG_", "CTFD_", "IMMERSIVE_"))}
                example = (self.root / "adapters" / adapter_id / "env.example").read_text(encoding="utf-8")
                assigned = {
                    line.split("=", 1)[0]
                    for line in example.splitlines()
                    if line and not line.startswith("#") and "=" in line
                }
                example_adapter_names = {
                    name for name in assigned if name.startswith(("ADAPTER_CONFIG_", "CTFD_", "IMMERSIVE_"))
                }
                self.assertEqual(adapter_names, example_adapter_names)

    def test_configuration_digest_ignores_legacy_event_file(self) -> None:
        (self.root / ".env").write_text("PLATFORM_ADAPTER=manual\n", encoding="utf-8")
        manifest = {"schema_version": "1", "identity": {"id": "fixture"}}
        (self.root / "event.json").write_text('{"private":"one"}', encoding="utf-8")
        first = _editable_configuration_digests(self.root, manifest)
        (self.root / "event.json").write_text('{"private":"two"}', encoding="utf-8")
        second = _editable_configuration_digests(self.root, manifest)
        self.assertEqual(first, second)

    def test_immutable_source_digest_ignores_legacy_event_file(self) -> None:
        before = immutable_source_digest(self.root)
        (self.root / "event.json").write_bytes(b"\x00legacy file must stay unread")
        after = immutable_source_digest(self.root)
        self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
