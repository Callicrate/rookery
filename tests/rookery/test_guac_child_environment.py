from __future__ import annotations

import json
import os
import runpy
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

from tests.rookery.env_fixtures import replace_env_assignments
from tests.rookery.test_acceptance_campaign import make_deployed_workspace

GUAC_SOURCE = Path(__file__).resolve().parents[2] / "rookery" / "extensions" / "guacamole"
if str(GUAC_SOURCE) not in sys.path:
    sys.path.insert(0, str(GUAC_SOURCE))

from guac_environment import (  # noqa: E402
    read_guac_configuration,
    transport_child_environment,
)
from rookery.portable.environment import EnvironmentPolicyError  # noqa: E402

AMBIENT_SENTINELS = {
    "DUMMY_GUAC_AMBIENT": "ambient-value",
    "OPENAI_API_KEY": "provider-value",
    "CTFD_TOKEN": "adapter-value",
    "ROOKERY_OWNER_TOKEN": "owner-value",
}


class GuacChildEnvironmentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.workspace = make_deployed_workspace("manual")
        self.root = Path(self.workspace.name)
        self.guac_bin = self.root / "extensions" / "guacamole" / "bin"

    def tearDown(self) -> None:
        self.workspace.cleanup()

    def replace_workspace(self, prepare=None) -> None:
        self.workspace.cleanup()
        self.workspace = make_deployed_workspace("manual", prepare=prepare)
        self.root = Path(self.workspace.name)
        self.guac_bin = self.root / "extensions" / "guacamole" / "bin"

    def runtime_input(self, name: str) -> Path:
        downloads = self.root / "downloads"
        downloads.mkdir(exist_ok=True)
        return downloads / name

    def run_helper(
        self, helper: str, *arguments: str, environment: dict[str, str]
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(self.guac_bin / helper), *arguments],
            cwd=self.root,
            env=environment,
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )

    def test_custom_transport_receives_only_exact_declared_names(self) -> None:
        child = (
            "import json,os,pathlib,sys; "
            "pathlib.Path(sys.argv[1]).write_text(json.dumps(sorted(os.environ))); "
            "os.write(1, b'payload')"
        )
        template = [sys.executable, "-c", child, "{outdir}/child-environment-names.json"]
        def prepare(root: Path) -> None:
            replace_env_assignments(
                root,
                {
                    "EVENT_EXTENSIONS": "guacamole",
                    "GUAC_REMOTE_FILE_EXPORT_ARGV": json.dumps(template),
                    "GUAC_REMOTE_FILE_EXPORT_ENV_KEYS": '["DUMMY_GUAC_NEEDED"]',
                    "DUMMY_GUAC_NEEDED": "dotenv-needed",
                },
            )
        self.replace_workspace(prepare)
        outdir = self.root / "evidence" / "guac" / "custom-transport"
        names_path = outdir / "child-environment-names.json"
        result = self.run_helper(
            "guac-export-file",
            "/tmp/report.txt",
            "--method",
            "configured",
            "--outdir",
            str(outdir),
            environment={
                **os.environ,
                **AMBIENT_SENTINELS,
                "DUMMY_GUAC_NEEDED": "parent-should-lose",
                "PYTHONDONTWRITEBYTECODE": "1",
            },
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        names = set(json.loads(names_path.read_text(encoding="utf-8")))
        self.assertIn("DUMMY_GUAC_NEEDED", names)
        self.assertFalse(set(AMBIENT_SENTINELS) & names)
        summary = (outdir / "summary.json").read_text(encoding="utf-8")
        self.assertIn('"policy": "guac-configured-transport"', summary)
        self.assertIn('"name": "DUMMY_GUAC_NEEDED"', summary)
        self.assertNotIn("dotenv-needed", summary)
        self.assertNotIn("parent-should-lose", summary)

    def test_missing_transport_grant_fails_before_evidence_creation(self) -> None:
        def prepare(root: Path) -> None:
            replace_env_assignments(
                root,
                {
                    "EVENT_EXTENSIONS": "guacamole",
                    "GUAC_REMOTE_FILE_EXPORT_ARGV": '["/bin/true"]',
                    "GUAC_REMOTE_FILE_EXPORT_ENV_KEYS": '["DUMMY_GUAC_REQUIRED"]',
                },
            )
        self.replace_workspace(prepare)
        outdir = self.root / "evidence" / "guac" / "missing-grant"
        result = self.run_helper(
            "guac-export-file",
            "/tmp/report.txt",
            "--method",
            "configured",
            "--outdir",
            str(outdir),
            environment={**os.environ, **AMBIENT_SENTINELS},
        )

        self.assertEqual(result.returncode, 2)
        self.assertIn("DUMMY_GUAC_REQUIRED", result.stderr)
        self.assertFalse(outdir.exists())

    def test_non_ssh_selectors_reject_sensitive_environment_classes(self) -> None:
        selectors = (
            "GUAC_REMOTE_FILE_EXPORT_ENV_KEYS",
            "GUAC_CLIPBOARD_EXPORT_ENV_KEYS",
            "GUAC_BASE64_EXPORT_ENV_KEYS",
            "GUAC_HTTP_EXPORT_ENV_KEYS",
            "GUAC_SCREENSHOT_TRANSCRIBE_ENV_KEYS",
            "GUAC_TERMINAL_CAPTURE_ENV_KEYS",
        )
        rejected = {
            "SSH_AUTH_SOCK": "agent capability",
            "OPENAI_API_KEY": "provider-auth",
            "CTFD_TOKEN": "adapter-secret",
            "COOKIES_FILE": "session-secret-reference",
            "VPN_AUTH_FILE": "vpn-secret-reference",
            "ROOKERY_OWNER_TOKEN": "forbidden owner key",
        }
        for selector in selectors:
            for name, reason in rejected.items():
                with self.subTest(selector=selector, name=name):
                    self.root.joinpath(".env").write_text(
                        f'{selector}=["{name}"]\n{name}=fixture-value\n',
                        encoding="utf-8",
                    )
                    configuration = read_guac_configuration(self.root)
                    with self.assertRaisesRegex(EnvironmentPolicyError, reason):
                        transport_child_environment(
                            self.root,
                            configuration,
                            policy_name="guac-test-non-ssh",
                            keys_control=selector,
                            parent={},
                        )

    def test_ssh_selector_rejects_other_agent_and_credential_classes(self) -> None:
        rejected = {
            "SSH_AGENT_PID": "agent capability",
            "DISPLAY": "agent capability",
            "WAYLAND_DISPLAY": "agent capability",
            "XAUTHORITY": "agent capability",
            "DBUS_SESSION_BUS_ADDRESS": "agent capability",
            "OPENAI_API_KEY": "provider-auth",
            "CTFD_TOKEN": "adapter-secret",
            "COOKIES_FILE": "session-secret-reference",
            "VPN_AUTH_FILE": "vpn-secret-reference",
            "ROOKERY_OWNER_TOKEN": "forbidden owner key",
        }
        selector = "GUAC_SSH_EXEC_ENV_KEYS"
        for name, reason in rejected.items():
            with self.subTest(name=name):
                self.root.joinpath(".env").write_text(
                    f'{selector}=["{name}"]\n{name}=fixture-value\n',
                    encoding="utf-8",
                )
                configuration = read_guac_configuration(self.root)
                with self.assertRaisesRegex(EnvironmentPolicyError, reason):
                    transport_child_environment(
                        self.root,
                        configuration,
                        policy_name="guac-test-ssh",
                        keys_control=selector,
                        parent={},
                    )

    def test_unknown_selector_cannot_bypass_transport_policy(self) -> None:
        configuration = read_guac_configuration(self.root)
        with self.assertRaisesRegex(
            EnvironmentPolicyError,
            "unknown Guacamole transport environment selector",
        ):
            transport_child_environment(
                self.root,
                configuration,
                policy_name="guac-test-unknown",
                keys_control="GUAC_NOT_A_SELECTOR",
                parent={},
            )

    def test_xdotool_gets_only_interactive_desktop_capabilities(self) -> None:
        fake_bin = Path(self.workspace.fake_temporary.name) / "xdotool-bin"
        fake_bin.mkdir()
        names_path = self.runtime_input("xdotool-environment-names.json")
        fake_xdotool = fake_bin / "xdotool"
        fake_xdotool.write_text(
            "#!/usr/bin/python3\n"
            "import json, os, pathlib\n"
            f"pathlib.Path({str(names_path)!r}).write_text(json.dumps(sorted(os.environ)))\n",
            encoding="utf-8",
        )
        fake_xdotool.chmod(0o755)
        result = self.run_helper(
            "guac-ssh-exec",
            "echo fixture",
            "--outdir",
            str(self.root / "evidence" / "guac" / "xdotool"),
            environment={
                **os.environ,
                **AMBIENT_SENTINELS,
                "PATH": f"{fake_bin}:/usr/bin:/bin",
                "DISPLAY": ":77",
                "WAYLAND_DISPLAY": "wayland-fixture",
                "XAUTHORITY": "/tmp/xauthority-fixture",
                "DBUS_SESSION_BUS_ADDRESS": "unix:path=/tmp/dbus-fixture",
                "SSH_AUTH_SOCK": "/tmp/ssh-agent-fixture",
                "PYTHONDONTWRITEBYTECODE": "1",
            },
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        names = set(json.loads(names_path.read_text(encoding="utf-8")))
        for name in (
            "DISPLAY",
            "WAYLAND_DISPLAY",
            "XAUTHORITY",
            "DBUS_SESSION_BUS_ADDRESS",
        ):
            self.assertIn(name, names)
        self.assertNotIn("SSH_AUTH_SOCK", names)
        self.assertFalse(set(AMBIENT_SENTINELS) & names)
        result_record = json.loads(
            (self.root / "evidence" / "guac" / "xdotool" / "result.json").read_text(
                encoding="utf-8"
            )
        )
        passed = result_record["environment"]["passed"]
        self.assertIn({"name": "DISPLAY", "class": "agent-capability"}, passed)
        self.assertNotIn(
            {"name": "SSH_AUTH_SOCK", "class": "agent-capability"}, passed
        )

    def test_custom_ssh_sender_gets_agent_only_when_named(self) -> None:
        child = (
            "import json,os,pathlib,sys; "
            "pathlib.Path(sys.argv[1]).write_text(json.dumps(sorted(os.environ))); "
            "print(pathlib.Path(sys.argv[2]).read_text())"
        )
        template = [
            sys.executable,
            "-c",
            child,
            "{outdir}/ssh-child-environment-names.json",
            "{commands_file}",
        ]
        def prepare(root: Path) -> None:
            replace_env_assignments(
                root,
                {
                    "EVENT_EXTENSIONS": "guacamole",
                    "GUAC_SSH_EXEC_ARGV": json.dumps(template),
                    "GUAC_SSH_EXEC_ENV_KEYS": '["SSH_AUTH_SOCK"]',
                    "SSH_AUTH_SOCK": "/tmp/ssh-agent-fixture",
                },
            )
        self.replace_workspace(prepare)
        outdir = self.root / "evidence" / "guac" / "ssh-agent"
        names_path = outdir / "ssh-child-environment-names.json"
        result = self.run_helper(
            "guac-ssh-exec",
            "echo fixture",
            "--outdir",
            str(outdir),
            environment={
                **os.environ,
                **AMBIENT_SENTINELS,
                "DISPLAY": ":88",
                "PYTHONDONTWRITEBYTECODE": "1",
            },
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        names = set(json.loads(names_path.read_text(encoding="utf-8")))
        self.assertIn("SSH_AUTH_SOCK", names)
        self.assertNotIn("DISPLAY", names)
        self.assertFalse(set(AMBIENT_SENTINELS) & names)
        result_record = json.loads((outdir / "result.json").read_text(encoding="utf-8"))
        self.assertIn(
            {"name": "SSH_AUTH_SOCK", "class": "agent-capability"},
            result_record["environment"]["passed"],
        )

    def test_guac_helpers_no_longer_contain_whole_environment_parsers(self) -> None:
        for helper in (
            "guac-contact-sheet",
            "guac-export-file",
            "guac-remote-log-export",
            "guac-terminal-capture",
            "guac-ssh-exec",
        ):
            source = (self.guac_bin / helper).read_text(encoding="utf-8")
            self.assertNotIn("def read_env", source)
            self.assertNotIn("dict(os.environ)", source)
            self.assertIn("read_guac_configuration", source)

    def test_koth_delegate_uses_a_minimal_child_environment(self) -> None:
        namespace = runpy.run_path(
            str(self.root / "extensions" / "koth" / "bin" / "koth-review")
        )
        with (
            mock.patch.dict(os.environ, AMBIENT_SENTINELS, clear=False),
            mock.patch.object(namespace["subprocess"], "call", return_value=0) as call,
        ):
            self.assertEqual(namespace["_call_rookery"](["fixture-command"]), 0)
        child_environment = call.call_args.kwargs["env"]
        self.assertFalse(set(AMBIENT_SENTINELS) & set(child_environment))
        self.assertIn("PATH", child_environment)


if __name__ == "__main__":
    unittest.main(verbosity=2)
