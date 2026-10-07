from __future__ import annotations

import shutil
import sys
import tempfile
import unittest
from pathlib import Path


SOURCE = Path(__file__).resolve().parents[2] / "rookery"
if str(SOURCE / "lib") not in sys.path:
    sys.path.insert(0, str(SOURCE / "lib"))

from rookery.portable.manifest import resolve_manifest  # noqa: E402


class PlatformScopeAdmissionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        shutil.copytree(SOURCE / "profiles", self.root / "profiles")
        (self.root / "adapters").mkdir()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _event(self, adapter_id: str) -> dict[str, str]:
        shutil.copytree(SOURCE / "adapters" / adapter_id, self.root / "adapters" / adapter_id)
        values = {
            "PLATFORM_ADAPTER": adapter_id,
            "EVENT_ID": "scope-fixture",
            "EVENT_NAME": "Scope fixture",
            "EVENT_URL": "https://ctf.example",
            "EVENT_SCOPE_ACK": "1",
            "ALLOWED_HOSTS": "ctf.example,support.example",
            "PLATFORM_HOSTS": "ctf.example",
            "ALLOWED_PORTS": "443",
            "ALLOWED_PROTOCOLS": "https",
            "SCOPE_MAX_BYTES": "4096",
            "CTFD_URL": "https://ctf.example",
            "CTFD_TOKEN": "fixture-token",
        }
        if adapter_id in {"ctfd_browser", "ctfd_browser_gateway"}:
            values.update(
                {
                    "BROWSER_MODE": "cdp",
                    "BROWSER_CDP_URL": "http://127.0.0.1:9001",
                    "ADAPTER_CONFIG_SCORING_MODE": "user",
                    "ADAPTER_CONFIG_EXPECTED_ACCOUNT_ID": "account-1",
                }
            )
        if adapter_id == "ctfd_browser_gateway":
            values["BROWSER_GATEWAY_URL"] = "http://127.0.0.1:9003"
        return values

    def test_each_ctfd_adapter_rejects_origin_outside_platform_scope(self) -> None:
        for adapter_id in ("ctfd", "ctfd_browser", "ctfd_browser_gateway"):
            with self.subTest(adapter=adapter_id):
                values = self._event(adapter_id)
                self.assertTrue(resolve_manifest(self.root, env=values).ready)
                values["PLATFORM_HOSTS"] = "support.example"
                result = resolve_manifest(self.root, env=values)
                self.assertFalse(result.ready)
                self.assertIn(
                    "selected platform origin outside scope: CTFD_URL",
                    result.errors,
                )

    def test_gateway_support_origin_requires_platform_scope(self) -> None:
        values = self._event("ctfd_browser_gateway")
        values["ADAPTER_CONFIG_BROWSER_SUPPORT_ORIGINS"] = '["https://support.example"]'
        result = resolve_manifest(self.root, env=values)
        self.assertIn(
            "selected platform support origin outside scope: ADAPTER_CONFIG_BROWSER_SUPPORT_ORIGINS",
            result.errors,
        )
        values["PLATFORM_HOSTS"] = "ctf.example,support.example"
        self.assertTrue(resolve_manifest(self.root, env=values).ready)


if __name__ == "__main__":
    unittest.main()
