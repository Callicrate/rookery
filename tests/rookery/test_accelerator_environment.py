from __future__ import annotations

# ruff: noqa: E402

import io
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stdout
from importlib.machinery import SourceFileLoader
from importlib.util import module_from_spec, spec_from_loader
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from tests.rookery.support import ROOKERY_ROOT
from tests.rookery.env_fixtures import configure_event_environment
from tests.rookery.test_preparation_and_isolation import copy_rookery

LIB = ROOKERY_ROOT / "lib"
if str(LIB) not in sys.path:
    sys.path.insert(0, str(LIB))
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

from rookery.portable.baseline import write_measurement_baseline
from rookery.portable.release import ReleaseBuildError, build_release
from rookery.portable.store import EventStore
from rookery.portable.validator import validate_tree

ENVIRONMENT_NAMES = "import json, os; print(json.dumps(sorted(os.environ)))"
NETWORK_NAMES = {
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "no_proxy",
    "CODEX_CA_CERTIFICATE",
    "SSL_CERT_FILE",
    "REQUESTS_CA_BUNDLE",
    "CURL_CA_BUNDLE",
    "NODE_EXTRA_CA_CERTS",
    "GIT_SSL_CAINFO",
}
DESKTOP_NAMES = {
    "DISPLAY",
    "WAYLAND_DISPLAY",
    "XAUTHORITY",
    "DBUS_SESSION_BUS_ADDRESS",
}
SSH_NAMES = {"SSH_AUTH_SOCK", "SSH_AGENT_PID"}
AMBIENT_SENTINELS = {
    "CODEX_API_KEY": "provider-sentinel-value",
    "CTFD_TOKEN": "ctfd-sentinel-value",
    "HTB_MCP_TOKEN": "htb-sentinel-value",
    "IMMERSIVE_COOKIES_FILE": "/tmp/immersive-sentinel-cookie",
    "VPN_AUTH_FILE": "/tmp/vpn-sentinel-auth",
    "ROOKERY_OWNER_TOKEN": "ambient-owner-sentinel",
    "DUMMY_REQUIRED_KEY": "parent-required-sentinel",
    "HTTP_PROXY": "http://proxy-sentinel.invalid",
    "DISPLAY": ":99",
    "DBUS_SESSION_BUS_ADDRESS": "unix:path=/tmp/desktop-sentinel",
    "SSH_AUTH_SOCK": "/tmp/ssh-agent-sentinel.sock",
    # Keep this numeric like the real variable, but long enough that a random
    # SHA-256 or timestamp cannot create a flaky substring "leak" match.
    "SSH_AGENT_PID": "991149725839104723650281",
}


def bootstrap_public_accelerator_workspace(
    root: Path,
    *,
    extra_environment: dict[str, str] | None = None,
) -> tempfile.TemporaryDirectory:
    """Run the real hermetic baseline and public ``./go`` admission path.

    Accelerator tests invoke deployed commands, so they must exercise the same
    binding publication and first-store contract as an operator workspace.  The
    fake Codex is only a local executable used by the gate; it supplies neither
    credentials nor a mocked gate result.
    """

    shutil.rmtree(root / ".ruff_cache", ignore_errors=True)
    artifacts = tempfile.TemporaryDirectory(prefix="rookery-accelerator-baseline-")
    artifact_root = Path(artifacts.name)
    fake_bin = artifact_root / "bin"
    fake_bin.mkdir()
    codex = fake_bin / "codex"
    codex.write_text(
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        "if [ \"${1:-}\" = --version ]; then echo 'codex-cli 0.150.0'; exit 0; fi\n"
        "if [ \"${1:-}\" = login ] && [ \"${2:-}\" = status ]; then exit 0; fi\n"
        "if [ \"${1:-}\" = --strict-config ] && [ \"${2:-}\" = login ] && [ \"${3:-}\" = status ]; then exit 0; fi\n"
        "if [ \"${1:-}\" = --strict-config ] && [ \"${2:-}\" = --version ]; then exit 0; fi\n"
        "if [ \"${1:-}\" = doctor ]; then printf '%s\\n' '{\"checks\":{\"config.load\":{\"status\":\"ok\"}}}'; exit 0; fi\n"
        "exit 0\n",
        encoding="utf-8",
    )
    codex.chmod(0o755)
    baseline_path = artifact_root / "measurement-baseline.json"
    entries = {
        "CODEX_AUTH_MODE": "local-login",
        "ROOKERY_MEASUREMENT_BASELINE_PATH": str(baseline_path),
        "EVENT_ID": "accelerator-fixture",
        "EVENT_NAME": "Accelerator Fixture",
        "ALLOWED_HOSTS": "localhost",
        "ALLOWED_CIDRS": "",
        "ALLOWED_PORTS": "80",
        "ALLOWED_PROTOCOLS": "http",
        "ALLOWED_FILE_ORIGINS": "fixture://*",
        "PLATFORM_HOSTS": "",
        "SCOPE_MAX_BYTES": "1024",
    }
    entries.update(extra_environment or {})
    configure_event_environment(
        root,
        "manual",
        name_suffix="Accelerator Fixture",
        extra=entries,
    )
    release_artifacts = artifact_root / "release-artifacts"
    try:
        summary = build_release(root, release_artifacts)
    except ReleaseBuildError as exc:
        report = validate_tree(root, adapter="manual", strict_release=True)
        artifacts.cleanup()
        raise RuntimeError(
            f"public accelerator baseline validation failed: {report['errors']}"
        ) from exc
    write_measurement_baseline(
        root,
        release_artifacts / str(summary["archive"]),
        release_artifacts / str(summary["manifest"]),
        baseline_path,
    )
    environment = dict(os.environ)
    environment["PATH"] = str(fake_bin) + os.pathsep + environment.get("PATH", "")
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    launched = subprocess.run(
        [str(root / "go")],
        cwd=root,
        env=environment,
        text=True,
        capture_output=True,
        timeout=60,
        check=False,
    )
    if launched.returncode != 0:
        artifacts.cleanup()
        raise RuntimeError(f"public accelerator preflight failed: {launched.stderr}")
    return artifacts


@unittest.skipUnless(
    os.name == "posix" and Path("/proc").is_dir(),
    "requires POSIX process environments",
)
class AcceleratorEnvironmentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        copy_rookery(self.root)
        self.baseline = bootstrap_public_accelerator_workspace(self.root)
        self.parent = dict(os.environ)
        for name in NETWORK_NAMES | DESKTOP_NAMES | SSH_NAMES:
            self.parent.pop(name, None)
        self.parent.update(AMBIENT_SENTINELS)
        self.parent["TERM"] = "xterm-256color"
        self.parent["PYTHONPATH"] = str(self.root / "lib")
        self.parent["PYTHONDONTWRITEBYTECODE"] = "1"

    def tearDown(self) -> None:
        try:
            self.temporary.cleanup()
        finally:
            self.baseline.cleanup()

    def invoke(self, command: str, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(self.root / "bin" / command), *arguments],
            cwd=self.root,
            env=self.parent,
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )

    def runq(self, *arguments: str) -> tuple[subprocess.CompletedProcess[str], dict[str, object]]:
        completed = self.invoke("runq", *arguments)
        self.assertTrue(completed.stdout, completed.stderr)
        return completed, json.loads(completed.stdout)

    def runbg(self, *arguments: str) -> tuple[subprocess.CompletedProcess[str], dict[str, object]]:
        completed = self.invoke("runbg", *arguments)
        self.assertTrue(completed.stdout, completed.stderr)
        return completed, json.loads(completed.stdout)

    def command_names(self, metadata: dict[str, object]) -> set[str]:
        path = self.root / str(metadata["stdout_path"])
        return set(json.loads(path.read_text(encoding="utf-8")))

    @staticmethod
    def proc_names(pid: int) -> set[str]:
        return {
            item.split("=", 1)[0]
            for item in (Path("/proc") / str(pid) / "environ")
            .read_bytes()
            .decode("utf-8", errors="strict")
            .split("\0")
            if item
        }

    def assert_value_free(self, record: object) -> None:
        rendered = json.dumps(record, sort_keys=True)
        for value in AMBIENT_SENTINELS.values():
            self.assertNotIn(value, rendered)

    def test_runq_default_exact_grants_and_builtin_policies_are_names_only(self) -> None:
        default, default_meta = self.runq(
            "--", sys.executable, "-c", ENVIRONMENT_NAMES
        )
        self.assertEqual(default.returncode, 0, default.stderr)
        default_names = self.command_names(default_meta)
        self.assertFalse(set(AMBIENT_SENTINELS) & default_names)
        self.assertEqual(default_meta["environment"]["policy"], "runq-minimal")
        self.assert_value_free(default_meta)

        granted, granted_meta = self.runq(
            "--pass-env",
            "TERM",
            "--",
            sys.executable,
            "-c",
            ENVIRONMENT_NAMES,
        )
        self.assertEqual(granted.returncode, 0, granted.stderr)
        granted_names = self.command_names(granted_meta)
        self.assertIn("TERM", granted_names)
        self.assertFalse(
            set(AMBIENT_SENTINELS) & granted_names
        )
        self.assertIn(
            {"name": "TERM", "class": "terminal-setting"},
            granted_meta["environment"]["passed"],
        )
        self.assert_value_free(granted_meta)

        policy, policy_meta = self.runq(
            "--env-policy",
            "network-client",
            "--env-policy",
            "interactive-desktop",
            "--env-policy",
            "ssh-agent",
            "--",
            sys.executable,
            "-c",
            ENVIRONMENT_NAMES,
        )
        self.assertEqual(policy.returncode, 0, policy.stderr)
        policy_names = self.command_names(policy_meta)
        self.assertTrue(
            {
                "HTTP_PROXY",
                "DISPLAY",
                "DBUS_SESSION_BUS_ADDRESS",
                "SSH_AUTH_SOCK",
                "SSH_AGENT_PID",
            }
            <= policy_names,
            policy_names,
        )
        self.assertFalse(
            {"CODEX_API_KEY", "CTFD_TOKEN", "HTB_MCP_TOKEN", "VPN_AUTH_FILE"}
            & policy_names
        )
        self.assert_value_free(policy_meta)

        events = EventStore(self.root).events()
        self.assert_value_free(events)
        for event in events:
            if event["event_type"] in {"command.requested", "command.completed"}:
                self.assertIn("environment", event["payload"])

    def test_invalid_environment_requests_fail_before_runtime_effects(self) -> None:
        marker = self.root / "must-not-run"
        command = [
            "--",
            sys.executable,
            "-c",
            f"from pathlib import Path; Path({str(marker)!r}).touch()",
        ]
        overflow: list[str] = []
        for index in range(257):
            overflow.extend(("--pass-env", f"OVERFLOW_KEY_{index}"))
        invalid_requests = (
            ("--pass-env", "DUMMY_REQUIRED_KEY=value"),
            ("--pass-env", "DUMMY_*"),
            ("--pass-env", "DUMMY_REQUIRED_KEY", "--pass-env", "DUMMY_REQUIRED_KEY"),
            ("--pass-env", "DUMMY_REQUIRED_KEY"),
            ("--pass-env", "UNLISTED_PRIVATE_CREDENTIAL"),
            ("--pass-env", "MISSING_REQUIRED_KEY"),
            ("--pass-env", "ROOKERY_OWNER_TOKEN"),
            ("--pass-env", "CODEX_API_KEY"),
            ("--pass-env", "CTFD_TOKEN"),
            ("--pass-env", "IMMERSIVE_COOKIES_FILE"),
            ("--pass-env", "VPN_AUTH_FILE"),
            ("--pass-env", "HTTP_PROXY"),
            ("--pass-env", "SSL_CERT_FILE"),
            ("--pass-env", "SSH_AUTH_SOCK"),
            ("--env-policy", "not-a-policy"),
            tuple(overflow),
        )
        before_events = EventStore(self.root).count()
        for request in invalid_requests:
            with self.subTest(request=request[:2]):
                completed = self.invoke("runq", *request, *command)
                self.assertNotEqual(completed.returncode, 0)
                self.assertFalse(marker.exists())
                self.assertEqual(EventStore(self.root).count(), before_events)
                self.assertFalse((self.root / "logs" / "commands").exists())
                self.assert_value_free(
                    {"stdout": completed.stdout, "stderr": completed.stderr}
                )

    def test_runbg_sensitive_generic_environment_grants_fail_before_admission(self) -> None:
        marker = self.root / "runbg-sensitive-environment-marker"
        before_events = EventStore(self.root).count()
        before_jobs = list((self.root / "logs" / "jobs").glob("*"))
        for name in (
            "CODEX_API_KEY",
            "CTFD_TOKEN",
            "IMMERSIVE_COOKIES_FILE",
            "VPN_AUTH_FILE",
            "HTTP_PROXY",
            "SSL_CERT_FILE",
            "SSH_AUTH_SOCK",
            "ROOKERY_OWNER_TOKEN",
            "UNLISTED_PRIVATE_CREDENTIAL",
        ):
            with self.subTest(name=name):
                completed = self.invoke(
                    "runbg",
                    "--pass-env",
                    name,
                    "--",
                    sys.executable,
                    "-c",
                    f"from pathlib import Path; Path({str(marker)!r}).touch()",
                )
                self.assertNotEqual(completed.returncode, 0)
                self.assertFalse(marker.exists())
                self.assertEqual(EventStore(self.root).count(), before_events)
                self.assertEqual(list((self.root / "logs" / "jobs").glob("*")), before_jobs)
                self.assert_value_free(
                    {"stdout": completed.stdout, "stderr": completed.stderr}
                )

    def test_runbg_proc_environment_has_only_direct_owner_and_explicit_grants(self) -> None:
        running, metadata = self.runbg(
            "--pass-env",
            "TERM",
            "--env-policy",
            "ssh-agent",
            "--",
            sys.executable,
            "-c",
            "import time; time.sleep(20)",
        )
        self.assertEqual(running.returncode, 0, running.stderr)
        pid = int(metadata["pid"])
        try:
            names = self.proc_names(pid)
            self.assertIn("ROOKERY_OWNER_TOKEN", names)
            self.assertIn("TERM", names)
            self.assertTrue(SSH_NAMES <= names)
            self.assertFalse(
                {"CODEX_API_KEY", "CTFD_TOKEN", "HTB_MCP_TOKEN", "HTTP_PROXY"}
                & names
            )
            self.assertEqual(metadata["environment"]["policy"], "runbg-minimal")
            self.assert_value_free(metadata)
        finally:
            try:
                os.killpg(int(metadata["pgid"]), signal.SIGTERM)
            except ProcessLookupError:
                pass
            deadline = time.monotonic() + 5
            while (
                (Path("/proc") / str(metadata["supervisor_pid"])).exists()
                and time.monotonic() < deadline
            ):
                time.sleep(0.05)

        output = self.root / "nested-environment-names.json"
        nested, nested_metadata = self.runbg(
            "--",
            str(self.root / "bin" / "runq"),
            "--",
            sys.executable,
            "-c",
            (
                "import json, os; from pathlib import Path; "
                f"Path({str(output)!r}).write_text(json.dumps(sorted(os.environ)))"
            ),
        )
        self.assertEqual(nested.returncode, 0, nested.stderr)
        deadline = time.monotonic() + 5
        while not output.is_file() and time.monotonic() < deadline:
            time.sleep(0.02)
        self.assertTrue(output.is_file())
        self.assertNotIn(
            "ROOKERY_OWNER_TOKEN",
            set(json.loads(output.read_text(encoding="utf-8"))),
        )
        self.assert_value_free(nested_metadata)
        try:
            os.killpg(int(nested_metadata["pgid"]), signal.SIGTERM)
        except ProcessLookupError:
            pass
        deadline = time.monotonic() + 5
        while (
            (Path("/proc") / str(nested_metadata["supervisor_pid"])).exists()
            and time.monotonic() < deadline
        ):
            time.sleep(0.05)

    def test_query_ledger_searxng_child_uses_minimal_environment(self) -> None:
        module_name = f"accelerator_query_fixture_{time.monotonic_ns()}"
        loader = SourceFileLoader(
            module_name, str(ROOKERY_ROOT / "bin" / "rookery-accelerators")
        )
        spec = spec_from_loader(module_name, loader)
        self.assertIsNotNone(spec)
        module = module_from_spec(spec)
        loader.exec_module(module)
        module.ROOT = self.root
        arguments = SimpleNamespace(
            qcmd="search",
            objective="fixture",
            query="bounded environment fixture",
            top=1,
            categories="general",
            force=False,
        )
        captured = io.StringIO()
        with (
            redirect_stdout(captured),
            mock.patch.dict(os.environ, AMBIENT_SENTINELS, clear=False),
            mock.patch.object(
                module.subprocess,
                "run",
                return_value=SimpleNamespace(stdout="{}", stderr="", returncode=0),
            ) as launched,
        ):
            self.assertEqual(module.query_ledger(arguments), 0)
        child_environment = dict(launched.call_args.kwargs["env"])
        self.assertFalse(set(AMBIENT_SENTINELS) & set(child_environment))


if __name__ == "__main__":
    unittest.main(verbosity=2)
