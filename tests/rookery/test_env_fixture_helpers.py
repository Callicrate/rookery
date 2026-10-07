from __future__ import annotations

# ruff: noqa: E402

import tempfile
import unittest
import sys
from pathlib import Path

from tests.rookery.env_fixtures import (
    configure_event_environment,
    replace_env_assignments,
)
from tests.rookery.support import ROOKERY_ROOT, copy_non_deployed_rookery
from tests.rookery.test_preparation_and_isolation import copy_rookery

LIB = ROOKERY_ROOT / "lib"
if str(LIB) not in sys.path:
    sys.path.insert(0, str(LIB))

from rookery.portable.manifest import resolve_manifest
from rookery.portable.environment import EnvironmentPolicyError
from rookery.portable.validator import validate_tree


class EnvironmentFixtureHelperTests(unittest.TestCase):
    def test_replacement_removes_duplicates_and_retired_selector(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / ".env").write_text(
                "# retained\nEVENT_NAME=old\nEVENT_MANIFEST=event.json\nEVENT_NAME=duplicate\n",
                encoding="utf-8",
            )
            replace_env_assignments(root, {"EVENT_NAME": "current"})
            text = (root / ".env").read_text(encoding="utf-8")
            self.assertEqual(text.count("EVENT_NAME="), 1)
            self.assertIn("EVENT_NAME=current", text)
            self.assertNotIn("EVENT_MANIFEST", text)
            self.assertIn("# retained", text)

    def test_complete_manual_fixture_is_env_only_and_ready(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            copy_non_deployed_rookery(root)
            configure_event_environment(root, "manual")
            text = (root / ".env").read_text(encoding="utf-8")
            self.assertNotIn("EVENT_MANIFEST", text)
            self.assertFalse((root / "event.json").exists())
            result = resolve_manifest(root)
            self.assertTrue(result.ready, result)

    def test_invalid_operational_control_and_missing_selected_value_fail_early(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            copy_rookery(root)
            configure_event_environment(root, "manual")

            replace_env_assignments(root, {"QUEUE_AUTOMATION": "maybe"})
            with self.assertRaises(EnvironmentPolicyError):
                resolve_manifest(root)
            invalid = validate_tree(root, adapter="manual", strict_release=True)
            self.assertFalse(invalid["ok"])
            self.assertNotIn("maybe", str(invalid))

            configure_event_environment(
                root,
                "manual",
                extra={
                    "QUEUE_AUTOMATION": "0",
                    "CODEX_AUTH_MODE": "environment",
                    "CODEX_PROVIDER_ENV_KEYS": '["MISSING_PROVIDER_KEY"]',
                },
            )
            unresolved = resolve_manifest(root)
            self.assertFalse(unresolved.ready)
            self.assertTrue(
                any(
                    "MISSING_PROVIDER_KEY" in item
                    for item in unresolved.unresolved_required
                )
            )
            missing = validate_tree(root, adapter="manual", strict_release=True)
            self.assertFalse(missing["ok"])
            self.assertNotIn("missing-provider-secret", str(missing))


if __name__ == "__main__":
    unittest.main(verbosity=2)
