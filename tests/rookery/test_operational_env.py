from __future__ import annotations

import sys
import unittest

from tests.rookery.support import ROOKERY_ROOT

LIB = ROOKERY_ROOT / "lib"
if str(LIB) not in sys.path:
    sys.path.insert(0, str(LIB))

# ruff: noqa: E402
from rookery.portable.environment import EnvironmentPolicyError
from rookery.portable.operational_env import validate_operational_environment


class OperationalEnvironmentTests(unittest.TestCase):
    def validate(self, **values: str) -> tuple[str, ...]:
        return validate_operational_environment(values)

    def test_defaults_are_pure_and_resolved(self) -> None:
        self.assertEqual(self.validate(), ())

    def test_preparation_controls_reject_invalid_mode_integer_boolean_image_and_url(self) -> None:
        cases = (
            ("ROOKERY_PREPARE_MODE", "surprise"),
            ("ROOKERY_PREPARE_TIMEOUT", "0"),
            ("ROOKERY_ALLOW_INSTALL_NETWORK", "perhaps"),
            ("SEARXNG_IMAGE", "ghcr.io/searxng/searxng:latest"),
            ("SEARXNG_URL", "https://user:pass@fixture.invalid"),
        )
        for name, value in cases:
            with self.subTest(name=name):
                with self.assertRaisesRegex(EnvironmentPolicyError, name):
                    self.validate(**{name: value})

    def test_cdp_mode_requires_valid_loopback_cdp_and_optional_gateway_syntax(self) -> None:
        self.assertEqual(
            self.validate(BROWSER_MODE="cdp"),
            ("BROWSER_CDP_URL",),
        )
        with self.assertRaisesRegex(EnvironmentPolicyError, "BROWSER_CDP_URL"):
            self.validate(BROWSER_MODE="cdp", BROWSER_CDP_URL="http://localhost:9001")
        with self.assertRaisesRegex(EnvironmentPolicyError, "BROWSER_GATEWAY_URL"):
            self.validate(BROWSER_GATEWAY_URL="https://127.0.0.1:9003")
        self.assertEqual(
            self.validate(
                BROWSER_MODE="cdp",
                BROWSER_CDP_URL="http://127.0.0.1:9001",
                BROWSER_GATEWAY_URL="http://127.0.0.1:9003",
            ),
            (),
        )

    def test_codex_environment_mode_requires_declared_present_provider_and_network_values(self) -> None:
        unresolved = self.validate(
            CODEX_AUTH_MODE="environment",
            CODEX_PROVIDER_ENV_KEYS='["OPENAI_API_KEY"]',
            CODEX_NETWORK_ENV_KEYS='["HTTPS_PROXY"]',
        )
        self.assertEqual(unresolved, ("HTTPS_PROXY", "OPENAI_API_KEY"))
        self.assertEqual(
            self.validate(
                CODEX_AUTH_MODE="environment",
                CODEX_PROVIDER_ENV_KEYS='["OPENAI_API_KEY"]',
                OPENAI_API_KEY="fixture-provider-value",
                CODEX_NETWORK_ENV_KEYS='["HTTPS_PROXY"]',
                HTTPS_PROXY="http://fixture.invalid:8080",
            ),
            (),
        )
        with self.assertRaisesRegex(EnvironmentPolicyError, "CODEX_AUTH_MODE"):
            self.validate(
                CODEX_AUTH_MODE="local-login",
                CODEX_PROVIDER_ENV_KEYS='["OPENAI_API_KEY"]',
            )
        with self.assertRaisesRegex(EnvironmentPolicyError, "CODEX_NETWORK_ENV_KEYS"):
            self.validate(
                CODEX_AUTH_MODE="environment",
                CODEX_PROVIDER_ENV_KEYS='["OPENAI_API_KEY"]',
                OPENAI_API_KEY="fixture-provider-value",
                CODEX_NETWORK_ENV_KEYS='["CTFD_TOKEN"]',
                CTFD_TOKEN="fixture-adapter-value",
            )

    def test_stage_c_selectors_check_classes_and_require_values_only_when_active(self) -> None:
        self.assertEqual(
            self.validate(
                ROOKERY_PREPARE_MODE="off",
                ROOKERY_PREPARE_NETWORK_ENV_KEYS='["HTTP_PROXY"]',
            ),
            (),
        )
        self.assertEqual(
            self.validate(
                ROOKERY_PREPARE_MODE="auto",
                ROOKERY_ALLOW_INSTALL_NETWORK="1",
                ROOKERY_PREPARE_NETWORK_ENV_KEYS='["HTTP_PROXY"]',
            ),
            ("HTTP_PROXY",),
        )
        with self.assertRaisesRegex(EnvironmentPolicyError, "ROOKERY_PREPARE_NETWORK_ENV_KEYS"):
            self.validate(ROOKERY_PREPARE_NETWORK_ENV_KEYS='["CTFD_TOKEN"]')
        self.assertEqual(
            self.validate(BROWSER_MODE="disabled", BROWSER_ENV_KEYS='["PATH"]'),
            (),
        )
        self.assertEqual(
            self.validate(BROWSER_MODE="auto", BROWSER_ENV_KEYS='["PATH"]'),
            ("PATH",),
        )

    def test_optional_argv_and_paths_are_syntax_checked_without_opening_them(self) -> None:
        self.assertEqual(
            self.validate(
                CREDENTIAL_HEALTH_ARGV='["python3","-V"]',
                NEAR_MISS_PROBE_ARGV='["python3","probe.py"]',
                ROCKYOU_PATH="relative/wordlist.txt",
            ),
            (),
        )
        with self.assertRaisesRegex(EnvironmentPolicyError, "CREDENTIAL_HEALTH_ARGV"):
            self.validate(CREDENTIAL_HEALTH_ARGV='["python3", 7]')
        with self.assertRaisesRegex(EnvironmentPolicyError, "ROCKYOU_PATH"):
            self.validate(ROCKYOU_PATH="bad\npath")


if __name__ == "__main__":
    unittest.main(verbosity=2)
