from __future__ import annotations

import copy
import os
import shutil
import stat
import sys
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest import mock

from tests.rookery.support import ROOKERY_ROOT
from tests.rookery.env_fixtures import replace_env_assignments

LIB = ROOKERY_ROOT / "lib"
if str(LIB) not in sys.path:
    sys.path.insert(0, str(LIB))

# ruff: noqa: E402
from rookery.portable.baseline import MeasurementBaselineError
from rookery.portable.browser_gateway_policy import (
    BrowserGatewayPolicyError,
    GATEWAY_ADAPTER_ID,
    compile_browser_gateway_policy,
    export_browser_gateway_policy,
    policy_sha256,
    resolve_browser_gateway_policy,
)
from rookery.portable.manifest import ManifestResult


class BrowserGatewayPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        if os.name != "posix":
            self.skipTest("requires POSIX private-file mode enforcement")
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        self.root = self.base / "source"
        self.root.mkdir()
        self.output_parent = self.base / "private"
        self.output_parent.mkdir()
        shutil.copytree(ROOKERY_ROOT / "profiles", self.root / "profiles")
        shutil.copytree(
            ROOKERY_ROOT / "adapters" / GATEWAY_ADAPTER_ID,
            self.root / "adapters" / GATEWAY_ADAPTER_ID,
        )
        replace_env_assignments(
            self.root,
            {
                "PLATFORM_ADAPTER": "ctfd_browser_gateway",
                "ROOKERY_MEASUREMENT_BASELINE_PATH": "/private/baseline.json",
                "CTFD_URL": "https://ctfd.fixture",
            },
        )
        self.manifest = self._manifest()
        self.baseline = {"configuration_digest": "a" * 64}

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def _manifest() -> dict[str, object]:
        return {
            "identity": {"id": "gateway-fixture"},
            "adapter": {
                "id": GATEWAY_ADAPTER_ID,
                "config": {"base_url": "https://ctfd.fixture"},
            },
            "scope": {
                "acknowledged": True,
                "allowed_hosts": ["ctfd.fixture"],
                "allowed_cidrs": [],
                "allowed_ports": [443],
                "allowed_protocols": ["https"],
                "allowed_file_origins": [],
                "platform_hosts": ["ctfd.fixture"],
                "max_attachment_bytes": 1024,
                "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
            },
        }

    def _export(self, output: Path, *, manifest: dict[str, object] | None = None, origin: str = "https://ctfd.fixture") -> dict[str, object]:
        resolved = ManifestResult(manifest or self.manifest, (), (), ())
        with (
            mock.patch(
                "rookery.portable.browser_gateway_policy.resolve_manifest",
                return_value=resolved,
            ),
            mock.patch(
                "rookery.portable.browser_gateway_policy.verify_measurement_baseline",
                return_value=self.baseline,
            ) as verify,
        ):
            policy = export_browser_gateway_policy(
                self.root,
                origin=origin,
                output=output,
                parent={},
            )
        verify.assert_called_once()
        self.assertTrue(verify.call_args.kwargs["verify_source_tree"])
        return policy

    def test_semantic_scope_digest_is_stable_across_compilation_timestamps(self) -> None:
        with mock.patch(
            "rookery.portable.scope.iso_now", side_effect=["first", "second"]
        ):
            first = compile_browser_gateway_policy(
                self.manifest,
                baseline_configuration_digest="a" * 64,
                origin="https://ctfd.fixture",
            )
            second = compile_browser_gateway_policy(
                self.manifest,
                baseline_configuration_digest="a" * 64,
                origin="https://ctfd.fixture",
            )
        self.assertNotEqual(first["scope"]["compiled_at"], second["scope"]["compiled_at"])
        self.assertEqual(first["scope_sha256"], second["scope_sha256"])
        self.assertEqual(policy_sha256(first), policy_sha256(second))

    def test_verified_baseline_binds_one_canonical_scoped_origin(self) -> None:
        output = self.output_parent / "gateway-policy.json"
        policy = self._export(output, origin="https://CTFD.FIXTURE:443/")
        self.assertEqual(policy["baseline_configuration_digest"], "a" * 64)
        self.assertEqual(policy["origins"], ["https://ctfd.fixture"])
        self.assertEqual(policy["scope_generation"], 1)
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)

    def test_support_origins_are_canonical_scoped_and_sorted(self) -> None:
        manifest = copy.deepcopy(self.manifest)
        manifest["scope"]["allowed_hosts"] += ["alpha.fixture", "zulu.fixture"]
        manifest["scope"]["platform_hosts"] += ["alpha.fixture", "zulu.fixture"]
        manifest["adapter"]["config"]["browser_support_origins"] = [
            "https://zulu.fixture",
            "https://alpha.fixture",
        ]
        policy = compile_browser_gateway_policy(
            manifest,
            baseline_configuration_digest="a" * 64,
            origin="https://ctfd.fixture",
        )
        self.assertEqual(
            policy["origins"],
            ["https://ctfd.fixture", "https://alpha.fixture", "https://zulu.fixture"],
        )

    def test_invalid_or_offscope_support_origins_are_refused(self) -> None:
        cases: tuple[object, ...] = (
            "https://support.fixture",
            ["https://support.fixture/"],
            ["https://*.fixture"],
            ["https://127.0.0.1"],
            ["https://ctfd.fixture"],
            ["https://support.fixture", "https://support.fixture"],
            ["https://support.fixture"] * 9,
        )
        for support_origins in cases:
            with self.subTest(support_origins=support_origins):
                manifest = copy.deepcopy(self.manifest)
                manifest["adapter"]["config"]["browser_support_origins"] = support_origins
                with self.assertRaisesRegex(
                    BrowserGatewayPolicyError, "support_origins_invalid"
                ):
                    compile_browser_gateway_policy(
                        manifest,
                        baseline_configuration_digest="a" * 64,
                        origin="https://ctfd.fixture",
                    )

        manifest = copy.deepcopy(self.manifest)
        manifest["adapter"]["config"]["browser_support_origins"] = [
            "https://support.fixture"
        ]
        with self.assertRaisesRegex(BrowserGatewayPolicyError, "scope_denied"):
            compile_browser_gateway_policy(
                manifest,
                baseline_configuration_digest="a" * 64,
                origin="https://ctfd.fixture",
            )

    def test_wrong_baseline_scope_or_origin_leaves_no_file(self) -> None:
        output = self.output_parent / "gateway-policy.json"
        resolved = ManifestResult(self.manifest, (), (), ())
        with (
            mock.patch(
                "rookery.portable.browser_gateway_policy.resolve_manifest",
                return_value=resolved,
            ),
            mock.patch(
                "rookery.portable.browser_gateway_policy.verify_measurement_baseline",
                side_effect=MeasurementBaselineError("fixture baseline failed"),
            ),
            self.assertRaisesRegex(BrowserGatewayPolicyError, "baseline_invalid"),
        ):
            export_browser_gateway_policy(
                self.root,
                origin="https://ctfd.fixture",
                output=output,
                parent={},
            )
        self.assertFalse(output.exists())

        scope_denied = copy.deepcopy(self.manifest)
        scope_denied["scope"]["platform_hosts"] = ["other.fixture"]
        with self.assertRaisesRegex(BrowserGatewayPolicyError, "scope_denied"):
            self._export(output, manifest=scope_denied)
        self.assertFalse(output.exists())

        with self.assertRaisesRegex(BrowserGatewayPolicyError, "origin_mismatch"):
            self._export(output, origin="https://other.fixture")
        self.assertFalse(output.exists())

    def test_symlink_and_no_clobber_outputs_are_refused(self) -> None:
        output = self.output_parent / "gateway-policy.json"
        self._export(output)
        original = output.read_bytes()
        with self.assertRaisesRegex(BrowserGatewayPolicyError, "output_already_exists"):
            self._export(output)
        self.assertEqual(output.read_bytes(), original)

        target = self.output_parent / "target.json"
        target.write_text("keep", encoding="utf-8")
        link = self.output_parent / "gateway-policy-link.json"
        try:
            link.symlink_to(target)
        except (NotImplementedError, OSError):
            self.skipTest("filesystem does not support symlink fixtures")
        with self.assertRaisesRegex(BrowserGatewayPolicyError, "output_symlink"):
            self._export(link)
        self.assertEqual(target.read_text(encoding="utf-8"), "keep")

    def test_export_does_not_create_or_modify_event_state(self) -> None:
        state = self.root / "state"
        state.mkdir()
        marker = state / "must-survive"
        marker.write_text("unchanged", encoding="utf-8")
        before = (marker.read_bytes(), marker.stat().st_mtime_ns, state.stat().st_mtime_ns)
        output = self.output_parent / "gateway-policy.json"

        self._export(output)

        after = (marker.read_bytes(), marker.stat().st_mtime_ns, state.stat().st_mtime_ns)
        self.assertEqual(before, after)

    def test_policy_resolution_retains_selected_gateway_schema_values(self) -> None:
        source = self.base / "configured-source"
        source.mkdir()
        shutil.copytree(ROOKERY_ROOT / "profiles", source / "profiles")
        shutil.copytree(
            ROOKERY_ROOT / "adapters" / GATEWAY_ADAPTER_ID,
            source / "adapters" / GATEWAY_ADAPTER_ID,
        )
        (source / ".env").write_text(
            "\n".join(
                (
                    f"PLATFORM_ADAPTER={GATEWAY_ADAPTER_ID}",
                    "EVENT_ID=gateway-runtime",
                    "EVENT_NAME=Gateway runtime",
                    "EVENT_URL=https://ctfd.fixture/event",
                    "EVENT_SCOPE_ACK=1",
                    "ALLOWED_HOSTS=ctfd.fixture,support.fixture",
                    "ALLOWED_PORTS=443",
                    "ALLOWED_PROTOCOLS=https",
                    "PLATFORM_HOSTS=ctfd.fixture,support.fixture",
                    "SCOPE_MAX_BYTES=4096",
                    "SCOPE_EXPIRES_AT=2099-01-01T00:00:00Z",
                    "ROOKERY_MEASUREMENT_BASELINE_PATH=/private/baseline.json",
                    "BROWSER_MODE=cdp",
                    "BROWSER_CDP_URL=http://127.0.0.1:9001",
                    "BROWSER_GATEWAY_URL=http://127.0.0.1:9003",
                    "CTFD_URL=https://ctfd.fixture",
                    "CTFD_TOKEN=fixture-only-token",
                    "ADAPTER_CONFIG_BASE_URL=https://ctfd.fixture",
                    "ADAPTER_CONFIG_SCORING_MODE=team",
                    "ADAPTER_CONFIG_EXPECTED_ACCOUNT_ID=account-7",
                    "ADAPTER_CONFIG_EXPECTED_TEAM_ID=team-9",
                    "ADAPTER_CONFIG_CSRF_PAGE_PATH=/challenges",
                    "ADAPTER_CONFIG_SESSION_LEASE_SECONDS=60",
                    "ADAPTER_CONFIG_TIMEOUT=30",
                    "ADAPTER_CONFIG_MAX_RESPONSE_BYTES=262144",
                    'ADAPTER_CONFIG_BROWSER_SUPPORT_ORIGINS=["https://support.fixture"]',
                    "",
                )
            ),
            encoding="utf-8",
        )
        with mock.patch(
            "rookery.portable.browser_gateway_policy.verify_measurement_baseline",
            return_value={"configuration_digest": "a" * 64},
        ):
            policy = resolve_browser_gateway_policy(
                source,
                origin="https://ctfd.fixture",
                parent={},
            )
        self.assertEqual(
            policy["origins"],
            ["https://ctfd.fixture", "https://support.fixture"],
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
