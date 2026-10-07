from __future__ import annotations

import copy
import unittest

from rookery.portable.manifest import resolve_manifest, validate_manifest
from tests.rookery.support import ROOKERY_ROOT


class ComputePolicyConfigTests(unittest.TestCase):
    def test_default_cpu_policy_is_explicit_in_resolved_event(self) -> None:
        result = resolve_manifest(ROOKERY_ROOT, env={"PLATFORM_ADAPTER": "manual"})

        self.assertEqual(result.errors, ())
        self.assertEqual(
            {
                name: result.manifest["compute"][name]
                for name in (
                    "target_percent",
                    "admit_percent",
                    "ceiling_percent",
                    "backoff_percent",
                    "sample_seconds",
                    "admission_cooldown_seconds",
                    "lease_seconds",
                )
            },
            {
                "target_percent": 75,
                "admit_percent": 70,
                "ceiling_percent": 80,
                "backoff_percent": 85,
                "sample_seconds": 1,
                "admission_cooldown_seconds": 5,
                "lease_seconds": 30,
            },
        )

    def test_invalid_cpu_policy_is_rejected_by_manifest_validation(self) -> None:
        resolved = resolve_manifest(ROOKERY_ROOT, env={"PLATFORM_ADAPTER": "manual"})
        manifest = copy.deepcopy(resolved.manifest)
        manifest["compute"]["admit_percent"] = 90
        manifest["compute"]["lease_seconds"] = 1

        invalid = validate_manifest(manifest)

        self.assertIn(
            "compute CPU thresholds must satisfy 0 <= admit < target <= ceiling < backoff <= 100",
            invalid.errors,
        )
        self.assertIn(
            "compute.lease_seconds must be an integer from 5 to 300",
            invalid.errors,
        )


if __name__ == "__main__":
    unittest.main()
