from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest
import zipfile
from pathlib import Path

from tests.rookery.support import ROOKERY_ROOT
from tests.rookery.env_fixtures import configure_event_environment
from tests.rookery.test_preparation_and_isolation import copy_rookery

LIB = ROOKERY_ROOT / "lib"
if str(LIB) not in os.sys.path:
    os.sys.path.insert(0, str(LIB))
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

from rookery.portable.release import build_release  # noqa: E402
from rookery.portable.validator import validate_tree  # noqa: E402


RETIRED_VPN_TEMPLATE_KEYS = frozenset(
    {
        "VPN_ENABLED",
        "VPN_OVPN_PATH",
        "VPN_AUTO_CONNECT",
        "VPN_WATCH_ENABLED",
        "VPN_RECONNECT_ON_FAILURE",
        "VPN_INTERFACE",
        "VPN_SUDO",
        "OPENVPN_BIN",
        "VPN_HEALTH_ARGV",
        "VPN_CONNECT_ARGV",
        "VPN_MAX_OUTPUT_BYTES",
        "VPN_CONNECT_COMMAND_SCOPE_ACK",
        "VPN_HEALTH_ENV_KEYS",
        "VPN_CONNECT_ENV_KEYS",
    }
)
RETIRED_VPN_AUTHORITY_TEXT = (
    *sorted(RETIRED_VPN_TEMPLATE_KEYS),
    "ctf_vpn_steward",
    "vpn_health_environment",
    "vpn_connect_environment",
    "VPN_HEALTH_ENV_KEYS",
    "VPN_CONNECT_ENV_KEYS",
)


class ReleaseConfigHygieneTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        copy_rookery(self.root)
        configure_event_environment(self.root, "manual")
        shutil.rmtree(self.root / ".ruff_cache", ignore_errors=True)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def validate(self) -> dict[str, object]:
        return validate_tree(self.root, strict_release=True)

    def test_segment_aware_credential_assignments_are_rejected_without_values(self) -> None:
        secret_values = (
            "session-secret-sentinel-123456",
            "auth-secret-sentinel-123456",
            "authorization-secret-sentinel-123456",
            "bearer-secret-sentinel-123456",
            "credential-secret-sentinel-123456",
            "pass-secret-sentinel-123456",
            "access-secret-sentinel-123456",
        )
        assignments = (
            f"SESSION_ID={secret_values[0]}",
            f"AUTH_HEADER=Bearer {secret_values[1]}",
            f"AUTHORIZATION_TOKEN={secret_values[2]}",
            f"BEARER_TOKEN={secret_values[3]}",
            f"CREDENTIAL_RECORD={secret_values[4]}",
            f"PASSCODE={secret_values[5]}",
            f"AWS_ACCESS_KEY_ID={secret_values[6]}",
        )
        target = self.root / "adapters" / "ctfd" / "env.example"
        with target.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write("\n" + "\n".join(assignments) + "\n")

        report = self.validate()

        self.assertFalse(report["ok"])
        self.assertIn("secret-shaped assignment in adapters/ctfd/env.example", report["errors"])
        rendered = "\n".join(report["errors"])
        for value in secret_values:
            self.assertNotIn(value, rendered)

    def test_operational_ack_and_configuration_keys_are_not_credentials(self) -> None:
        target = self.root / ".env.example"
        with target.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(
                "\nAUTH_EXPIRED_STOP_ACK=operator-confirmed\n"
                "AUTHORIZATION_MODE=manual-release\n"
                "SESSION_TIMEOUT_SECONDS=1800\n"
                "CREDENTIAL_HEALTH_ARGV=python bin/credential-health\n"
                "ACCESS_MODE=read-only\n"
            )

        report = self.validate()

        self.assertNotIn("secret-shaped assignment in .env.example", report["errors"])

    def test_release_template_omits_retired_managed_vpn_controls(self) -> None:
        template = (self.root / ".env.example").read_text(encoding="utf-8")
        template_keys = {
            line.split("=", 1)[0]
            for line in template.splitlines()
            if line and not line.startswith("#") and "=" in line
        }
        self.assertFalse(RETIRED_VPN_TEMPLATE_KEYS & template_keys)
        self.assertIn("external to Rookery", template)
        validation = self.validate()
        self.assertTrue(validation["ok"], validation["errors"])

        with tempfile.TemporaryDirectory() as output_name:
            output = Path(output_name)
            summary = build_release(self.root, output)
            archive = output / str(summary["archive"])
            with zipfile.ZipFile(archive) as packaged:
                root_name = json.loads(
                    (self.root / "release.json").read_text(encoding="utf-8")
                )["archive_root"]
                environment = packaged.read(f"{root_name}/.env").decode("utf-8")
                members = set(packaged.namelist())
                self.assertNotIn(f"{root_name}/agents/catalog/ctf_vpn_steward.toml", members)
                for member in (
                    "profiles/generic.json",
                    "adapters/ctfd/profile.json",
                    "adapters/htb/profile.json",
                ):
                    profile = json.loads(packaged.read(f"{root_name}/{member}").decode("utf-8"))
                    self.assertNotIn("vpn", profile.get("capabilities", {}).get("optional", []))
                    self.assertNotIn("vpn", profile.get("surface", {}).get("bundles", []))
                for member in ("registry/tools.json", "registry/agents.json", "lib/rookery/portable/environment.py"):
                    payload = packaged.read(f"{root_name}/{member}").decode("utf-8")
                    for retired in RETIRED_VPN_AUTHORITY_TEXT:
                        self.assertNotIn(retired, payload, member)
                permitted_retirement_text = {
                    f"{root_name}/docs/network_vpn.md",
                }
                for member in members:
                    if member.endswith("/") or member in permitted_retirement_text:
                        continue
                    try:
                        payload = packaged.read(member).decode("utf-8")
                    except UnicodeDecodeError:
                        continue
                    for retired in RETIRED_VPN_AUTHORITY_TEXT:
                        self.assertNotIn(retired, payload, member)
        packaged_keys = {
            line.split("=", 1)[0]
            for line in environment.splitlines()
            if line and not line.startswith("#") and "=" in line
        }
        self.assertEqual(environment, template)
        self.assertFalse(RETIRED_VPN_TEMPLATE_KEYS & packaged_keys)

    def test_stage_c_names_only_controls_are_declared_and_reject_value_syntax(self) -> None:
        clean = self.validate()
        self.assertFalse(
            [
                item
                for item in clean["errors"]
                if "undeclared release configuration key" in item
                or "names-only JSON string array" in item
            ],
            clean["errors"],
        )
        self.assertIn(
            "TRANSIT_SOURCE_NETWORK_ENV_KEYS=[]",
            (self.root / ".env.example").read_text(encoding="utf-8"),
        )
        self.assertIn(
            "NCQ_NETWORK_ENV_KEYS=[]",
            (self.root / ".env.example").read_text(encoding="utf-8"),
        )

        transit_secret = "transit-network-value-sentinel-123456"
        target = self.root / ".env.example"
        with target.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(
                "\nTRANSIT_SOURCE_NETWORK_ENV_KEYS=[\"HTTP_PROXY="
                + transit_secret
                + "\"]\n"
            )
        transit_report = self.validate()
        transit_rendered = "\n".join(transit_report["errors"])
        self.assertIn(
            "TRANSIT_SOURCE_NETWORK_ENV_KEYS must be a names-only JSON string array "
            "in .env.example",
            transit_report["errors"],
        )
        self.assertNotIn(transit_secret, transit_rendered)

        secret = "stage-c-value-sentinel-123456"
        with target.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(
                "\nBROWSER_ENV_KEYS=[\"BROWSER_SETTING=" + secret + "\"]\n"
            )
        report = self.validate()
        rendered = "\n".join(report["errors"])
        self.assertIn(
            "BROWSER_ENV_KEYS must be a names-only JSON string array in .env.example",
            report["errors"],
        )
        self.assertNotIn(secret, rendered)

    def test_supply_chain_defaults_are_pinned_offline_and_reject_retired_controls(self) -> None:
        template = self.root / ".env.example"
        rendered = template.read_text(encoding="utf-8")
        self.assertIn("ROOKERY_ALLOW_INSTALL_NETWORK=0", rendered)
        self.assertIn(
            "SEARXNG_IMAGE=ghcr.io/searxng/searxng:2026.8.28-a30b2d474"
            "@sha256:addd2cf36efb4b9815a2820a522aef7cce4da0d1c0e4527f6675f5663332fc9b",
            rendered,
        )
        self.assertNotIn("CHROME_FOR_TESTING_CHANNEL", rendered)
        self.assertTrue(self.validate()["ok"])

        template.write_text(
            rendered.replace("ROOKERY_ALLOW_INSTALL_NETWORK=0", "ROOKERY_ALLOW_INSTALL_NETWORK=1"),
            encoding="utf-8",
            newline="\n",
        )
        report = self.validate()
        self.assertIn(
            "ROOKERY_ALLOW_INSTALL_NETWORK must default to 0 in .env.example",
            report["errors"],
        )

        template.write_text(
            rendered.replace(
                "SEARXNG_IMAGE=ghcr.io/searxng/searxng:2026.8.28-a30b2d474"
                "@sha256:addd2cf36efb4b9815a2820a522aef7cce4da0d1c0e4527f6675f5663332fc9b",
                "SEARXNG_IMAGE=ghcr.io/searxng/searxng:latest",
            ),
            encoding="utf-8",
            newline="\n",
        )
        report = self.validate()
        self.assertIn(
            "SEARXNG_IMAGE must be the approved exact OCI reference in .env.example",
            report["errors"],
        )

        template.write_text(
            rendered + "\nCHROME_FOR_TESTING_CHANNEL=Stable\n",
            encoding="utf-8",
            newline="\n",
        )
        report = self.validate()
        self.assertIn(
            "undeclared release configuration key in .env.example: CHROME_FOR_TESTING_CHANNEL",
            report["errors"],
        )

    def test_credentialed_urls_and_private_keys_are_rejected_without_values(self) -> None:
        default_file = self.root / "configs" / "operator.default.env"
        url_secret = "url-secret-sentinel-123456"
        key_payload = "key-payload-sentinel-123456"
        default_file.write_text(
            "SERVICE_ENDPOINT=https://operator:"
            f"{url_secret}@fixture.invalid/service\n"
            "-----BEGIN OPENSSH PRIVATE KEY-----\n"
            f"{key_payload}\n"
            "-----END OPENSSH PRIVATE KEY-----\n",
            encoding="utf-8",
            newline="\n",
        )

        report = self.validate()

        self.assertFalse(report["ok"])
        self.assertIn("secret-shaped assignment in configs/operator.default.env", report["errors"])
        rendered = "\n".join(report["errors"])
        self.assertNotIn(url_secret, rendered)
        self.assertNotIn(key_payload, rendered)

    def test_crlf_source_template_is_rejected(self) -> None:
        template = self.root / ".env.example"
        template.write_bytes(template.read_bytes().replace(b"\n", b"\r\n"))
        crlf_report = self.validate()
        self.assertIn(
            "CRLF line endings in shell-consumed release file: .env.example",
            crlf_report["errors"],
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
