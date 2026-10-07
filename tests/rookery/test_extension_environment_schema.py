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

from rookery.portable.environment import EnvironmentPolicyError  # noqa: E402
from rookery.portable.event_env import resolve_event_environment  # noqa: E402
from rookery.portable.manifest import resolve_manifest  # noqa: E402


class ExtensionEnvironmentSchemaTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        shutil.copytree(SOURCE / "profiles", self.root / "profiles")
        shutil.copytree(
            SOURCE / "extensions" / "guacamole",
            self.root / "extensions" / "guacamole",
        )
        (self.root / "adapters").mkdir()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def _event(*, guacamole: bool) -> dict[str, str]:
        values = {
            "PLATFORM_ADAPTER": "manual",
            "EVENT_ID": "extension-fixture",
            "EVENT_NAME": "Extension fixture",
            "EVENT_URL": "https://fixture.invalid/event",
            "EVENT_SCOPE_ACK": "1",
            "ALLOWED_HOSTS": "fixture.invalid",
            "SCOPE_MAX_BYTES": "4096",
        }
        if guacamole:
            values["EVENT_EXTENSIONS"] = "guacamole"
        return values

    @staticmethod
    def _guac_schema() -> list[dict[str, object]]:
        descriptor = json.loads(
            (SOURCE / "extensions" / "guacamole" / "extension.json").read_text(
                encoding="utf-8"
            )
        )
        return descriptor["environment_schema"]

    def test_selected_extension_fields_are_typed_without_entering_manifest(self) -> None:
        values = self._event(guacamole=True)
        values.update(
            {
                "GUAC_SSH_EXEC_ARGV": '["/usr/bin/printf","%s"]',
                "GUAC_SSH_EXEC_ENV_KEYS": '["SSH_AUTH_SOCK"]',
                "GUAC_STREAM_DIR": "evidence/guac/stream",
                "GUAC_EXEC_TIMEOUT": "120",
                "SSH_AUTH_SOCK": "/run/user/1000/agent.sock",
            }
        )

        resolved = resolve_event_environment(self.root, env=values)
        result = resolve_manifest(self.root, env=values)

        self.assertTrue(result.ready, result)
        self.assertEqual(resolved.values["GUAC_SSH_EXEC_ARGV"], ["/usr/bin/printf", "%s"])
        self.assertEqual(resolved.values["GUAC_SSH_EXEC_ENV_KEYS"], ["SSH_AUTH_SOCK"])
        self.assertEqual(resolved.values["GUAC_EXEC_TIMEOUT"], 120)
        self.assertIn("SSH_AUTH_SOCK", resolved.declared_names)
        serialized = json.dumps(result.manifest, sort_keys=True)
        self.assertNotIn("GUAC_", serialized)
        self.assertNotIn("/run/user/1000/agent.sock", serialized)

    def test_unselected_nonblank_extension_field_is_rejected(self) -> None:
        values = self._event(guacamole=False)
        values["GUAC_EXEC_TIMEOUT"] = "120"
        with self.assertRaisesRegex(
            EnvironmentPolicyError,
            "event_environment_unselected:GUAC_EXEC_TIMEOUT",
        ):
            resolve_manifest(self.root, env=values)

    def test_blank_unselected_extension_catalog_is_inert(self) -> None:
        values = self._event(guacamole=False)
        values.update({str(field["name"]): "" for field in self._guac_schema()})
        self.assertTrue(resolve_manifest(self.root, env=values).ready)

    def test_selected_extension_rejects_malformed_values(self) -> None:
        cases = {
            "argv must be JSON": {"GUAC_SSH_EXEC_ARGV": "/bin/true"},
            "argv elements are strings": {"GUAC_SSH_EXEC_ARGV": '["/bin/true",1]'},
            "environment names are exact": {
                "GUAC_SSH_EXEC_ENV_KEYS": '["SSH_*"]'
            },
            "timeout minimum": {"GUAC_EXEC_TIMEOUT": "0"},
            "timeout maximum": {"GUAC_EXEC_TIMEOUT": "3601"},
        }
        for label, extra in cases.items():
            with self.subTest(label=label):
                values = self._event(guacamole=True)
                values.update(extra)
                with self.assertRaises(EnvironmentPolicyError):
                    resolve_manifest(self.root, env=values)

    def test_examples_cover_schema_and_root_catalog_stays_blank(self) -> None:
        names = {str(field["name"]) for field in self._guac_schema()}
        extension_assignments = self._assignments(
            SOURCE / "extensions" / "guacamole" / "env.example"
        )
        root_assignments = self._assignments(SOURCE / ".env.example")

        self.assertEqual(
            names,
            {name for name in extension_assignments if name.startswith("GUAC_")},
        )
        self.assertEqual(
            names,
            {name for name in root_assignments if name.startswith("GUAC_")},
        )
        self.assertTrue(all(root_assignments[name] == "" for name in names))
        self.assertFalse(any(name.endswith("_COMMAND") for name in names))

    @staticmethod
    def _assignments(path: Path) -> dict[str, str]:
        result: dict[str, str] = {}
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line or line.startswith("#") or "=" not in line:
                continue
            name, value = line.split("=", 1)
            if name in result:
                raise AssertionError(f"duplicate assignment in {path.name}: {name}")
            result[name] = value
        return result


if __name__ == "__main__":
    unittest.main()
