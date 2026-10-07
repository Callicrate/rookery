from __future__ import annotations

# ruff: noqa: E402

import gzip
import hashlib
import io
import json
import os
import runpy
import shutil
import ssl
import subprocess
import sys
import tarfile
import tempfile
import threading
import unittest
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

from tests.rookery.support import (
    ROOKERY_ROOT,
    copy_non_deployed_rookery,
)
from tests.rookery.env_fixtures import configure_event_environment
from tests.rookery.test_acceptance_campaign import make_deployed_workspace

LIB = ROOKERY_ROOT / "lib"
if str(LIB) not in sys.path:
    sys.path.insert(0, str(LIB))
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

from rookery.portable.cli import build_parser, cmd_go
from rookery.portable.manifest import resolve_manifest
from rookery.portable.scope import CompiledScopeBinding
from rookery.portable import scope as scope_module
from rookery.portable.scoped_transport import ScopedHTTPTransport
from rookery.portable.environment import (
    EnvClass,
    EnvKey,
    EnvironmentPolicyError,
    EnvSource,
    preparation_local_environment,
    preparation_network_environment,
    read_declared_environment,
    searxng_network_environment,
)
from rookery.portable.preparation import (
    APPROVED_MANAGED_SEARXNG_IMAGE,
    _materialize_rockyou,
    _prepared_env,
    prepare,
)
from rookery.portable.baseline import write_measurement_baseline
from rookery.portable.release import build_release
from rookery.portable.registry import render_surface
from rookery.portable.store import EventStore
from rookery.portable.util import atomic_write_json, load_json, sha256_file
from rookery.portable.validator import validate_tree


def minimal_preparation_root() -> tempfile.TemporaryDirectory:
    td = tempfile.TemporaryDirectory()
    root = Path(td.name)
    (root / "configs").mkdir(parents=True)
    (root / "services" / "searxng").mkdir(parents=True)
    shutil.copy2(
        ROOKERY_ROOT / "services/searxng/settings.template.yml", root / "services/searxng/settings.template.yml"
    )
    atomic_write_json(
        root / "configs/preparation.json",
        {
            "schema_version": "1",
            "binaries": [],
            "data_files": [],
        },
    )
    return td


def managed_searxng_inspection(
    root: Path, *, port: int, running: bool
) -> dict[str, object]:
    settings = root / "state" / "services" / "searxng" / "settings.yml"
    settings.parent.mkdir(parents=True, exist_ok=True)
    settings.write_text("use_default_settings: true\n", encoding="utf-8")
    return {
        "Config": {"Image": APPROVED_MANAGED_SEARXNG_IMAGE},
        "State": {"Running": running},
        "HostConfig": {
            "Privileged": False,
            "CapAdd": None,
            "RestartPolicy": {"Name": "unless-stopped", "MaximumRetryCount": 0},
            "PortBindings": {
                "8080/tcp": [{"HostIp": "127.0.0.1", "HostPort": str(port)}]
            },
        },
        "Mounts": [
            {
                "Type": "bind",
                "Source": str(settings.resolve()),
                "Destination": "/etc/searxng/settings.yml",
                "RW": False,
            }
        ],
    }


def copy_rookery(root: Path) -> None:
    # Directory iteration order differs across filesystems. Ensure top-level
    # files can be copied even when no source directory was visited first.
    root.mkdir(parents=True, exist_ok=True)
    for child in ROOKERY_ROOT.iterdir():
        if child.name in {
            "state",
            "analysis",
            "evidence",
            "submissions",
            "logs",
            "captures",
            "downloads",
            "work",
            "writeups",
            "control",
            "START_PROMPT.md",
            "STOP_PROMPT.md",
            "NEW_CTF_SETUP.md",
            "PREPARATION.md",
            "ACTIVE_SURFACE.md",
            "STATUS.md",
            "FINDINGS.md",
            "FLAGS.md",
            "DEAD_PATHS.md",
            ".ruff_cache",
            ".pytest_cache",
        }:
            continue
        target = root / child.name
        if child.is_dir():
            shutil.copytree(
                child,
                target,
                symlinks=True,
                ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
            )
        else:
            shutil.copy2(child, target)
    shutil.copyfile(root / ".env.example", root / ".env")
    for path in [root / "go", root / "run-codex", *list((root / "bin").glob("*"))]:
        if path.is_file():
            path.chmod(path.stat().st_mode | 0o111)


class PreparationTests(unittest.TestCase):
    def test_external_searxng_and_configured_browser_are_never_replaced(self):
        td = minimal_preparation_root()
        root = Path(td.name)
        browser = root / "existing-headless"
        browser.write_text("#!/usr/bin/env bash\necho 'Existing Headless 1.0'\n", encoding="utf-8")
        browser.chmod(0o755)
        env = {
            "PATH": os.environ.get("PATH", ""),
            "ROOKERY_PREPARE_MODE": "auto",
            "ROOKERY_PREPARE_INSTALL": "1",
            "ROOKERY_ALLOW_INSTALL_NETWORK": "1",
            "SEARXNG_URL": "http://search.example.invalid/search",
            "SEARXNG_MODE": "auto",
            "BROWSER_EXECUTABLE": str(browser),
            "BROWSER_MODE": "auto",
        }
        with (
            mock.patch("rookery.portable.preparation._http_json", return_value=(True, "healthy")),
            mock.patch(
                "rookery.portable.preparation._container_engine",
                side_effect=AssertionError("container engine must not be consulted"),
            ),
            mock.patch(
                "rookery.portable.preparation._install_packages",
                side_effect=AssertionError("package install must not run"),
            ),
        ):
            report = prepare(root, apply=True, env=env)
        self.assertEqual(report["services"]["searxng"]["mode"], "external")
        self.assertFalse(report["services"]["searxng"]["managed"])
        self.assertEqual(report["services"]["browser"]["mode"], "configured")
        self.assertFalse(report["services"]["browser"]["install_attempted"])
        td.cleanup()

    def test_configured_searxng_proxy_fails_before_dns_or_health_connection(self):
        td = minimal_preparation_root()
        root = Path(td.name)
        (root / "state").mkdir()
        scope = {
            "acknowledged": True,
            "generation": 1,
            "expires_at": "unknown",
            "allowed_hosts": ["search.example.invalid"],
            "allowed_cidrs": [],
            "allowed_ports": [443],
            "allowed_protocols": ["https"],
            "allowed_file_origins": [],
            "platform_hosts": [],
            "max_attachment_bytes": 1024,
        }
        atomic_write_json(
            root / "state" / "scope.json",
            scope,
        )
        binding = CompiledScopeBinding(
            scope=scope,
            scope_generation=1,
            stop_generation=0,
            file_sha256="a" * 64,
            content_sha256="b" * 64,
            launch_binding_sha256="c" * 64,
        )
        env = {
            "PATH": os.environ.get("PATH", ""),
            "SEARXNG_MODE": "auto",
            "SEARXNG_URL": "https://search.example.invalid/search",
            "SEARXNG_NETWORK_ENV_KEYS": '["HTTP_PROXY"]',
            "HTTP_PROXY": "http://proxy.example.invalid:8080",
            "BROWSER_MODE": "disabled",
        }

        with (
            mock.patch(
                "socket.getaddrinfo", side_effect=AssertionError("selected proxy reached DNS")
            ),
            mock.patch(
                "rookery.portable.preparation._available_canonical_scope_binding",
                return_value=binding,
            ),
            mock.patch(
                "rookery.portable.preparation._verify_scope_binding", return_value=binding
            ),
        ):
            report = prepare(root, apply=True, env=env)

        service = report["services"]["searxng"]
        self.assertFalse(service["available"])
        self.assertEqual(service["health"], "unhealthy")
        td.cleanup()

    def test_unconfigured_services_are_planned_without_network_in_check_mode(self):
        td = minimal_preparation_root()
        root = Path(td.name)
        env = {
            "PATH": "",
            "ROOKERY_PREPARE_MODE": "check",
            "ROOKERY_PREPARE_INSTALL": "1",
            "ROOKERY_ALLOW_INSTALL_NETWORK": "1",
            "SEARXNG_URL": "",
            "SEARXNG_MODE": "auto",
            "BROWSER_MODE": "auto",
            "BROWSER_EXECUTABLE": "",
            "CHROME_BIN": "",
        }
        with (
            mock.patch(
                "rookery.portable.preparation._http_json",
                side_effect=AssertionError("check mode must not make a health request"),
            ),
            mock.patch(
                "rookery.portable.preparation._container_engine",
                side_effect=AssertionError("check mode must not start containers"),
            ),
            mock.patch("rookery.portable.preparation.shutil.which", return_value=None),
        ):
            report = prepare(root, apply=False, env=env)
        self.assertEqual(report["services"]["searxng"]["health"], "planned")
        self.assertEqual(report["services"]["browser"]["health"], "unavailable")
        self.assertFalse(report["services"]["searxng"]["install_attempted"])
        self.assertFalse(report["services"]["searxng"]["managed"])
        self.assertFalse(report["services"]["browser"]["install_attempted"])
        td.cleanup()

    def test_unconfigured_searxng_provisions_loopback_container(self):
        td = minimal_preparation_root()
        root = Path(td.name)
        env = {
            "PATH": os.environ.get("PATH", ""),
            "ROOKERY_PREPARE_MODE": "auto",
            "ROOKERY_PREPARE_INSTALL": "1",
            "ROOKERY_ALLOW_INSTALL_NETWORK": "1",
            "SEARXNG_URL": "",
            "SEARXNG_MODE": "auto",
            "SEARXNG_LOCAL_PORT": "18080",
            "BROWSER_MODE": "disabled",
        }
        commands = []

        def fake_run(command, **kwargs):
            commands.append(command)
            if "ps" in command:
                return subprocess.CompletedProcess(command, 0, "", "")
            return subprocess.CompletedProcess(command, 0, "container-id\n", "")

        with (
            mock.patch("rookery.portable.preparation._http_json", return_value=(True, "healthy")),
            mock.patch("rookery.portable.preparation._container_engine", return_value=(["docker"], "docker")),
            mock.patch("rookery.portable.preparation._free_port", return_value=18080),
            mock.patch("rookery.portable.preparation._run", side_effect=fake_run),
        ):
            report = prepare(root, apply=True, env=env)
        service = report["services"]["searxng"]
        self.assertTrue(service["available"], service)
        self.assertTrue(service["managed"])
        self.assertEqual(service["url"], "http://127.0.0.1:18080/search")
        run_commands = [row for row in commands if "run" in row]
        self.assertEqual(len(run_commands), 1)
        self.assertIn("127.0.0.1:18080:8080", run_commands[0])
        self.assertEqual(run_commands[0][-1], APPROVED_MANAGED_SEARXNG_IMAGE)
        self.assertEqual(
            service["requested_image_reference"],
            "ghcr.io/searxng/searxng:2026.8.28-a30b2d474",
        )
        self.assertEqual(
            service["requested_image_digest"],
            "sha256:addd2cf36efb4b9815a2820a522aef7cce4da0d1c0e4527f6675f5663332fc9b",
        )
        self.assertTrue((root / "state/services/searxng/settings.yml").exists())
        td.cleanup()

    def test_healthy_unowned_loopback_listener_is_not_managed_or_pinned(self):
        td = minimal_preparation_root()
        root = Path(td.name)
        requests: list[str] = []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                requests.append(self.path)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"results": []}')

            def log_message(self, _format: str, *args: object) -> None:
                del args

        listener = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=listener.serve_forever, daemon=True)
        thread.start()
        env = {
            "PATH": os.environ.get("PATH", ""),
            "ROOKERY_PREPARE_MODE": "auto",
            "ROOKERY_ALLOW_INSTALL_NETWORK": "1",
            "SEARXNG_MODE": "auto",
            "SEARXNG_LOCAL_PORT": str(listener.server_port),
            "BROWSER_MODE": "disabled",
        }
        commands: list[list[str]] = []

        def fake_run(command, **_kwargs):
            commands.append(command)
            if "ps" in command:
                return subprocess.CompletedProcess(command, 0, "", "")
            raise AssertionError(f"unowned listener triggered container operation: {command}")

        try:
            with (
                mock.patch(
                    "rookery.portable.preparation._container_engine",
                    return_value=(["docker"], "docker"),
                ),
                mock.patch("rookery.portable.preparation._run", side_effect=fake_run),
            ):
                report = prepare(root, apply=True, env=env)
        finally:
            listener.shutdown()
            listener.server_close()
            thread.join(timeout=2)

        service = report["services"]["searxng"]
        self.assertEqual(service["mode"], "external-untrusted")
        self.assertFalse(service["available"])
        self.assertFalse(service["managed"])
        self.assertEqual(service["health"], "unavailable")
        self.assertEqual(requests, [])
        self.assertNotIn("requested_image_digest", service)
        self.assertNotIn("observed_image_digest", service)
        self.assertFalse(any("run" in command or "start" in command for command in commands))
        self.assertFalse((root / "state" / "services" / "searxng").exists())
        td.cleanup()

    def test_absent_managed_container_does_not_probe_or_start_without_network(self):
        td = minimal_preparation_root()
        root = Path(td.name)
        env = {
            "PATH": os.environ.get("PATH", ""),
            "ROOKERY_PREPARE_MODE": "auto",
            "ROOKERY_PREPARE_INSTALL": "1",
            "ROOKERY_ALLOW_INSTALL_NETWORK": "0",
            "SEARXNG_MODE": "auto",
            "SEARXNG_LOCAL_PORT": "18080",
            "BROWSER_MODE": "disabled",
        }
        commands: list[list[str]] = []

        def fake_run(command, **_kwargs):
            commands.append(command)
            if "ps" in command:
                return subprocess.CompletedProcess(command, 0, "", "")
            raise AssertionError(f"absent container triggered lifecycle operation: {command}")

        with (
            mock.patch(
                "rookery.portable.preparation._http_json",
                side_effect=AssertionError("absent container reached loopback listener"),
            ),
            mock.patch(
                "rookery.portable.preparation._container_engine",
                return_value=(["docker"], "docker"),
            ),
            mock.patch("rookery.portable.preparation._free_port", return_value=18080),
            mock.patch("rookery.portable.preparation._run", side_effect=fake_run),
        ):
            report = prepare(root, apply=True, env=env)

        service = report["services"]["searxng"]
        self.assertEqual(service["mode"], "managed")
        self.assertFalse(service["available"])
        self.assertFalse(service["managed"])
        self.assertEqual(service["health"], "unavailable")
        self.assertEqual(service["detail"], "installation network disabled")
        self.assertFalse(any("run" in command or "start" in command or "rm" in command for command in commands))
        self.assertFalse((root / "state" / "services" / "searxng").exists())
        td.cleanup()

    def test_existing_managed_container_must_match_the_configured_digest_before_start(self):
        td = minimal_preparation_root()
        root = Path(td.name)
        container = "rookery-searxng-" + hashlib.sha256(
            str(root).encode()
        ).hexdigest()[:10]
        env = {
            "PATH": os.environ.get("PATH", ""),
            "ROOKERY_PREPARE_MODE": "auto",
            "ROOKERY_ALLOW_INSTALL_NETWORK": "1",
            "SEARXNG_MODE": "auto",
            "SEARXNG_LOCAL_PORT": "18080",
            "BROWSER_MODE": "disabled",
        }
        commands: list[list[str]] = []
        inspection = managed_searxng_inspection(root, port=18080, running=False)

        def fake_run(command, **_kwargs):
            commands.append(command)
            if "ps" in command:
                return subprocess.CompletedProcess(command, 0, container + "\n", "")
            if "inspect" in command:
                return subprocess.CompletedProcess(
                    command, 0, json.dumps([inspection]), ""
                )
            if "start" in command:
                return subprocess.CompletedProcess(command, 0, container + "\n", "")
            raise AssertionError(f"unexpected container operation: {command}")

        def healthy_after_start(*_args, **_kwargs):
            self.assertTrue(any("start" in command for command in commands))
            return True, "healthy"

        with (
            mock.patch(
                "rookery.portable.preparation._http_json", side_effect=healthy_after_start
            ),
            mock.patch(
                "rookery.portable.preparation._container_engine",
                return_value=(["docker"], "docker"),
            ),
            mock.patch("rookery.portable.preparation._free_port", return_value=18080),
            mock.patch("rookery.portable.preparation._run", side_effect=fake_run),
        ):
            report = prepare(root, apply=True, env=env)

        service = report["services"]["searxng"]
        self.assertTrue(service["available"], service)
        self.assertEqual(service["observed_image_reference"], service["requested_image_reference"])
        self.assertEqual(service["observed_image_digest"], service["requested_image_digest"])
        self.assertTrue(any("inspect" in command for command in commands))
        self.assertTrue(any("start" in command for command in commands))
        td.cleanup()

    def test_existing_running_managed_container_is_healthy_without_lifecycle_action(self):
        td = minimal_preparation_root()
        root = Path(td.name)
        container = "rookery-searxng-" + hashlib.sha256(
            str(root).encode()
        ).hexdigest()[:10]
        inspection = managed_searxng_inspection(root, port=18080, running=True)
        commands: list[list[str]] = []

        def fake_run(command, **_kwargs):
            commands.append(command)
            if "ps" in command:
                return subprocess.CompletedProcess(command, 0, container + "\n", "")
            if "inspect" in command:
                return subprocess.CompletedProcess(command, 0, json.dumps([inspection]), "")
            raise AssertionError(f"running managed container triggered lifecycle action: {command}")

        with (
            mock.patch(
                "rookery.portable.preparation._http_json", return_value=(True, "healthy")
            ) as health,
            mock.patch(
                "rookery.portable.preparation._container_engine",
                return_value=(["docker"], "docker"),
            ),
            mock.patch("rookery.portable.preparation._run", side_effect=fake_run),
        ):
            report = prepare(
                root,
                apply=True,
                env={
                    "PATH": os.environ.get("PATH", ""),
                    "ROOKERY_PREPARE_MODE": "auto",
                    "SEARXNG_MODE": "auto",
                    "SEARXNG_LOCAL_PORT": "18080",
                    "BROWSER_MODE": "disabled",
                },
            )

        service = report["services"]["searxng"]
        self.assertTrue(service["available"])
        self.assertTrue(service["managed"])
        self.assertEqual(service["detail"], "existing-healthy")
        self.assertEqual(health.call_count, 1)
        self.assertFalse(any("start" in command or "run" in command or "rm" in command for command in commands))
        td.cleanup()

    def test_existing_managed_container_digest_mismatch_never_starts_or_removes_it(self):
        td = minimal_preparation_root()
        root = Path(td.name)
        container = "rookery-searxng-" + hashlib.sha256(
            str(root).encode()
        ).hexdigest()[:10]
        env = {
            "PATH": os.environ.get("PATH", ""),
            "ROOKERY_PREPARE_MODE": "auto",
            "ROOKERY_ALLOW_INSTALL_NETWORK": "1",
            "SEARXNG_MODE": "auto",
            "SEARXNG_LOCAL_PORT": "18080",
            "BROWSER_MODE": "disabled",
        }
        commands: list[list[str]] = []
        inspection = managed_searxng_inspection(root, port=18080, running=False)
        inspection["Config"]["Image"] = "ghcr.io/searxng/searxng:latest"

        def fake_run(command, **_kwargs):
            commands.append(command)
            if "ps" in command:
                return subprocess.CompletedProcess(command, 0, container + "\n", "")
            if "inspect" in command:
                return subprocess.CompletedProcess(
                    command, 0, json.dumps([inspection]), ""
                )
            raise AssertionError(f"mismatched container was operated: {command}")

        with (
            mock.patch(
                "rookery.portable.preparation._http_json",
                side_effect=AssertionError("mismatched container reached loopback listener"),
            ),
            mock.patch(
                "rookery.portable.preparation._container_engine",
                return_value=(["docker"], "docker"),
            ),
            mock.patch("rookery.portable.preparation._free_port", return_value=18080),
            mock.patch("rookery.portable.preparation._run", side_effect=fake_run),
        ):
            report = prepare(root, apply=True, env=env)

        service = report["services"]["searxng"]
        self.assertFalse(service["available"])
        self.assertEqual(service["mode"], "external-untrusted")
        self.assertFalse(service["managed"])
        self.assertEqual(service["detail"], "existing managed container configuration is not trusted")
        self.assertFalse(any("start" in command or "rm" in command for command in commands))
        self.assertNotIn("requested_image_reference", service)
        self.assertNotIn("requested_image_digest", service)
        self.assertNotIn("observed_image_reference", service)
        self.assertNotIn("observed_image_digest", service)
        td.cleanup()

    def test_existing_managed_container_configuration_mismatches_never_start_or_probe(self):
        mismatches = {
            "non-loopback port": lambda inspected: inspected["HostConfig"][
                "PortBindings"
            ]["8080/tcp"][0].update({"HostIp": "0.0.0.0"}),
            "wrong settings mount": lambda inspected: inspected["Mounts"][0].update(
                {"RW": True}
            ),
            "privileged": lambda inspected: inspected["HostConfig"].update(
                {"Privileged": True}
            ),
            "extra capability": lambda inspected: inspected["HostConfig"].update(
                {"CapAdd": ["NET_ADMIN"]}
            ),
            "restart surprise": lambda inspected: inspected["HostConfig"].update(
                {"RestartPolicy": {"Name": "always", "MaximumRetryCount": 0}}
            ),
        }
        for label, mutate in mismatches.items():
            with self.subTest(label=label):
                td = minimal_preparation_root()
                root = Path(td.name)
                container = "rookery-searxng-" + hashlib.sha256(
                    str(root).encode()
                ).hexdigest()[:10]
                inspection = managed_searxng_inspection(
                    root, port=18080, running=False
                )
                mutate(inspection)
                commands: list[list[str]] = []

                def fake_run(command, **_kwargs):
                    commands.append(command)
                    if "ps" in command:
                        return subprocess.CompletedProcess(
                            command, 0, container + "\n", ""
                        )
                    if "inspect" in command:
                        return subprocess.CompletedProcess(
                            command, 0, json.dumps([inspection]), ""
                        )
                    raise AssertionError(
                        f"{label} mismatch triggered lifecycle action: {command}"
                    )

                with (
                    mock.patch(
                        "rookery.portable.preparation._http_json",
                        side_effect=AssertionError(
                            f"{label} mismatch reached loopback listener"
                        ),
                    ),
                    mock.patch(
                        "rookery.portable.preparation._container_engine",
                        return_value=(["docker"], "docker"),
                    ),
                    mock.patch(
                        "rookery.portable.preparation._run", side_effect=fake_run),
                ):
                    report = prepare(
                        root,
                        apply=True,
                        env={
                            "PATH": os.environ.get("PATH", ""),
                            "ROOKERY_PREPARE_MODE": "auto",
                            "SEARXNG_MODE": "auto",
                            "SEARXNG_LOCAL_PORT": "18080",
                            "BROWSER_MODE": "disabled",
                        },
                    )

                service = report["services"]["searxng"]
                self.assertEqual(service["mode"], "external-untrusted")
                self.assertFalse(service["available"])
                self.assertFalse(service["managed"])
                self.assertEqual(
                    service["detail"],
                    "existing managed container configuration is not trusted",
                )
                self.assertFalse(
                    any(
                        "start" in command or "run" in command or "rm" in command
                        for command in commands
                    )
                )
                td.cleanup()

    def test_unapproved_searxng_images_fail_before_state_or_engine_effects(self):
        candidates = (
            "ghcr.io/searxng/searxng:latest",
            "ghcr.io/searxng/searxng:2026.8.28-a30b2d474@sha256:"
            "ADDD2CF36EFB4B9815A2820A522AEF7CCE4DA0D1C0E4527F6675F5663332FC9B",
            "ghcr.io/searxng/searxng:2026.8.28-a30b2d474@sha256:"
            "0000000000000000000000000000000000000000000000000000000000000000",
        )
        for image in candidates:
            with self.subTest(image=image):
                td = minimal_preparation_root()
                root = Path(td.name)
                env = {
                    "PATH": os.environ.get("PATH", ""),
                    "SEARXNG_IMAGE": image,
                    "SEARXNG_MODE": "auto",
                    "BROWSER_MODE": "disabled",
                }
                with mock.patch(
                    "rookery.portable.preparation._container_engine",
                    side_effect=AssertionError("unapproved image reached container engine"),
                ):
                    with self.assertRaises(EnvironmentPolicyError):
                        prepare(root, apply=True, env=env)
                self.assertFalse((root / "state").exists())
                td.cleanup()

    def test_unconfigured_browser_remains_an_optional_gap_even_with_network(self):
        td = minimal_preparation_root()
        root = Path(td.name)
        env = {
            "PATH": os.environ.get("PATH", ""),
            "ROOKERY_PREPARE_MODE": "auto",
            "ROOKERY_PREPARE_INSTALL": "1",
            "ROOKERY_ALLOW_INSTALL_NETWORK": "1",
            "SEARXNG_MODE": "disabled",
            "BROWSER_MODE": "auto",
            "BROWSER_EXECUTABLE": "",
            "CHROME_BIN": "",
        }

        with (
            mock.patch("rookery.portable.preparation._browser_candidates", return_value=[]),
            mock.patch(
                "rookery.portable.preparation._install_packages",
                side_effect=AssertionError("browser packages must never be installed"),
            ),
            mock.patch(
                "rookery.portable.preparation._open_checked",
                side_effect=AssertionError("browser metadata/download must never be requested"),
            ),
        ):
            report = prepare(root, apply=True, env=env)
        browser = report["services"]["browser"]
        self.assertFalse(browser["available"])
        self.assertEqual(browser["mode"], "unavailable")
        self.assertFalse(browser["install_attempted"])
        self.assertFalse((root / "state/services/chrome-headless-shell").exists())
        td.cleanup()

    def test_existing_system_browser_is_discovered_without_network_authority(self):
        td = minimal_preparation_root()
        root = Path(td.name)
        browser = root / "system-browser"
        browser.write_text(
            "#!/usr/bin/env bash\necho 'System Headless 1.0'\n", encoding="utf-8"
        )
        browser.chmod(0o755)
        with (
            mock.patch(
                "rookery.portable.preparation._browser_candidates",
                return_value=[str(browser)],
            ),
            mock.patch(
                "rookery.portable.preparation._container_engine",
                side_effect=AssertionError("offline preparation reached an engine"),
            ),
            mock.patch(
                "rookery.portable.preparation._install_packages",
                side_effect=AssertionError("offline preparation installed a package"),
            ),
            mock.patch(
                "rookery.portable.preparation._http_json", return_value=(False, "offline")
            ),
        ):
            report = prepare(
                root,
                apply=True,
                env={
                    "PATH": os.environ.get("PATH", ""),
                    "SEARXNG_MODE": "disabled",
                    "BROWSER_MODE": "auto",
                },
        )
        self.assertEqual(report["services"]["browser"]["mode"], "system")
        self.assertTrue(report["services"]["browser"]["available"])
        td.cleanup()

    def test_rockyou_decompression_is_bounded(self):
        td = tempfile.TemporaryDirectory()
        root = Path(td.name)
        source = root / "rockyou.txt.gz"
        destination = root / "state/data/rockyou.txt"
        destination.parent.mkdir(parents=True)
        destination.write_text("existing", encoding="utf-8")
        with gzip.open(source, "wb") as archive:
            archive.write(b"oversized")
        with mock.patch("rookery.portable.preparation.WORDLIST_MAX_BYTES", 4):
            with self.assertRaisesRegex(RuntimeError, "rockyou wordlist exceeds"):
                _materialize_rockyou(source, destination)
        self.assertEqual(destination.read_text(encoding="utf-8"), "existing")
        td.cleanup()

    def test_rockyou_tar_member_scan_is_bounded(self):
        td = tempfile.TemporaryDirectory()
        root = Path(td.name)
        source = root / "rockyou.txt.tar.gz"
        destination = root / "state/data/rockyou.txt"
        with tarfile.open(source, "w:gz") as archive:
            for name in ("other.txt", "rockyou.txt"):
                data = name.encode("utf-8")
                member = tarfile.TarInfo(name)
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
        with mock.patch("rookery.portable.preparation.WORDLIST_ARCHIVE_MAX_FILES", 1):
            with self.assertRaisesRegex(RuntimeError, "wordlist archive exceeds"):
                _materialize_rockyou(source, destination)
        self.assertFalse(destination.exists())
        td.cleanup()

    def test_invalid_configured_browser_fails_visible_without_installing_another(self):
        td = minimal_preparation_root()
        root = Path(td.name)
        env = {
            "PATH": os.environ.get("PATH", ""),
            "ROOKERY_PREPARE_MODE": "auto",
            "ROOKERY_PREPARE_INSTALL": "1",
            "ROOKERY_ALLOW_INSTALL_NETWORK": "1",
            "SEARXNG_MODE": "disabled",
            "BROWSER_MODE": "auto",
            "BROWSER_EXECUTABLE": str(root / "missing-browser"),
        }
        with mock.patch(
            "rookery.portable.preparation._install_packages",
            side_effect=AssertionError("configured browser must not trigger installation"),
        ):
            report = prepare(root, apply=True, env=env)
        browser = report["services"]["browser"]
        self.assertEqual(browser["mode"], "configured")
        self.assertFalse(browser["available"])
        self.assertFalse(browser["install_attempted"])
        td.cleanup()

    def test_binary_and_data_inventory_reports_paths(self):
        td = minimal_preparation_root()
        root = Path(td.name)
        fake_bin = root / "fake-bin"
        fake_bin.mkdir()
        rg = fake_bin / "rg"
        rg.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
        rg.chmod(0o755)
        wordlist = root / "rockyou.txt"
        wordlist.write_text("password\n", encoding="utf-8")
        atomic_write_json(
            root / "configs/preparation.json",
            {
                "schema_version": "1",
                "binaries": [
                    {
                        "id": "ripgrep",
                        "commands": ["rg"],
                        "required": False,
                        "install_class": "recommended",
                        "packages": {},
                    }
                ],
                "data_files": [
                    {
                        "id": "rockyou",
                        "env": "ROCKYOU_PATH",
                        "required": False,
                        "install_class": "recommended",
                        "candidates": [],
                        "packages": {},
                    }
                ],
            },
        )
        env = {
            "PATH": str(fake_bin),
            "ROCKYOU_PATH": str(wordlist),
            "ROOKERY_PREPARE_MODE": "check",
            "SEARXNG_MODE": "disabled",
            "BROWSER_MODE": "disabled",
        }
        with mock.patch.dict(os.environ, {"PATH": str(fake_bin)}, clear=False):
            report = prepare(root, apply=False, env=env)
        self.assertTrue(report["binaries"][0]["available"])
        self.assertEqual(Path(report["data_files"][0]["path"]), wordlist)
        self.assertIn("tool:ripgrep", report["capabilities"])
        self.assertIn("data:rockyou", report["capabilities"])
        td.cleanup()

    def test_preparation_uses_exact_network_grants_and_minimal_local_children(self):
        td = minimal_preparation_root()
        root = Path(td.name)
        browser = root / "browser"
        browser.write_text("fixture", encoding="utf-8")
        browser.chmod(0o755)
        atomic_write_json(
            root / "configs/preparation.json",
            {
                "schema_version": "1",
                "binaries": [
                    {
                        "id": "fixture-tool",
                        "commands": ["fixture-tool"],
                        "required": False,
                        "install_class": "core",
                        "packages": {"apt": ["fixture-tool"]},
                    }
                ],
                "data_files": [],
            },
        )
        env = {
            "PATH": os.environ.get("PATH", ""),
            "ROOKERY_PREPARE_MODE": "auto",
            "ROOKERY_PREPARE_INSTALL": "1",
            "ROOKERY_ALLOW_INSTALL_NETWORK": "1",
            "ROOKERY_PREPARE_NETWORK_ENV_KEYS": '["HTTP_PROXY"]',
            "HTTP_PROXY": "http://declared-proxy.invalid:8080",
            "DUMMY_UNRELATED_SECRET": "must-not-reach-children",
            "SEARXNG_MODE": "disabled",
            "BROWSER_MODE": "auto",
            "BROWSER_EXECUTABLE": str(browser),
        }
        children = []

        def fake_run(command, *, root, environment, **_kwargs):
            children.append((command, dict(environment.values), environment.policy_name))
            return subprocess.CompletedProcess(command, 0, "HeadlessChrome fixture", "")

        with (
            mock.patch("rookery.portable.preparation._manager", return_value="apt"),
            mock.patch("rookery.portable.preparation._run", side_effect=fake_run),
        ):
            report = prepare(root, apply=True, env=env)
        local = [values for _command, values, policy in children if policy == "preparation-local"]
        network = [values for _command, values, policy in children if policy == "preparation-network"]
        self.assertTrue(local)
        self.assertTrue(network)
        self.assertTrue(all("HTTP_PROXY" not in values for values in local))
        self.assertTrue(all("DUMMY_UNRELATED_SECRET" not in values for _command, values, _policy in children))
        self.assertTrue(
            all(
                values["HTTP_PROXY"] == "http://declared-proxy.invalid:8080"
                for values in network
            )
        )
        metadata = json.dumps(report["environment"])
        self.assertIn("HTTP_PROXY", metadata)
        self.assertNotIn("http://declared-proxy.invalid:8080", metadata)
        td.cleanup()

    def test_invalid_preparation_policy_or_config_fails_before_state_or_child_effects(self):
        for label, config, env, forbidden_value in (
            (
                "missing network grant",
                None,
                {
                    "PATH": os.environ.get("PATH", ""),
                    "ROOKERY_PREPARE_NETWORK_ENV_KEYS": '["HTTP_PROXY"]',
                    "ROOKERY_PREPARE_MODE": "auto",
                    "ROOKERY_ALLOW_INSTALL_NETWORK": "1",
                },
                "",
            ),
            (
                "invalid proxy value",
                None,
                {
                    "PATH": os.environ.get("PATH", ""),
                    "ROOKERY_PREPARE_NETWORK_ENV_KEYS": '["HTTP_PROXY"]',
                    "HTTP_PROXY": "ftp://proxy-value-must-not-leak.invalid",
                    "ROOKERY_PREPARE_MODE": "auto",
                    "ROOKERY_ALLOW_INSTALL_NETWORK": "1",
                },
                "ftp://proxy-value-must-not-leak.invalid",
            ),
            (
                "invalid config",
                {"schema_version": "1", "binaries": "not-an-array"},
                {"PATH": os.environ.get("PATH", ""), "ROOKERY_PREPARE_MODE": "off"},
                "",
            ),
        ):
            with self.subTest(label=label):
                td = minimal_preparation_root()
                root = Path(td.name)
                if config is not None:
                    atomic_write_json(root / "configs/preparation.json", config)
                with mock.patch(
                    "rookery.portable.preparation._run",
                    side_effect=AssertionError("invalid preparation reached child execution"),
                ):
                    with self.assertRaises(ValueError) as raised:
                        prepare(root, apply=True, env=env)
                if forbidden_value:
                    self.assertNotIn(forbidden_value, str(raised.exception))
                self.assertFalse((root / "state").exists())
                td.cleanup()

    def test_prepared_environment_round_trips_literal_paths_without_shell_quoting(self):
        td = tempfile.TemporaryDirectory()
        root = Path(td.name)
        browser_path = root / "brow'ser Ω"
        report = {
            "services": {
                "searxng": {"available": True, "url": "https://search.example.invalid/search"},
                "browser": {"available": True, "path": str(browser_path)},
            },
            "data_files": [
                {
                    "available": True,
                    "env": "ROCKYOU_PATH",
                    "path": str(root / "data with $() and `ticks`"),
                }
            ],
        }
        _prepared_env(root, report)
        declarations = tuple(
            EnvKey(name, EnvClass.CAPABILITY_PATH, sources=(EnvSource.PREPARED,))
            for name in ("SEARXNG_URL", "BROWSER_EXECUTABLE", "CHROME_BIN", "ROCKYOU_PATH")
        )
        restored = read_declared_environment(
            root, declarations, include_prepared=True, parent={}
        )
        self.assertEqual(restored.values["BROWSER_EXECUTABLE"], str(browser_path))
        self.assertEqual(restored.values["CHROME_BIN"], str(browser_path))
        self.assertEqual(
            restored.values["ROCKYOU_PATH"], str(root / "data with $() and `ticks`")
        )
        self.assertEqual(
            restored.values["SEARXNG_URL"], "https://search.example.invalid/search"
        )
        td.cleanup()

    def test_bound_stage_c_policies_do_not_reread_dotenv_after_launch_gate(self):
        td = minimal_preparation_root()
        root = Path(td.name)
        parent = {
            "PATH": os.environ.get("PATH", ""),
            "ROOKERY_PREPARE_MODE": "off",
            "ROOKERY_ALLOW_INSTALL_NETWORK": "0",
            "SEARXNG_MODE": "disabled",
            "BROWSER_MODE": "disabled",
            "ROOKERY_PREPARE_NETWORK_ENV_KEYS": '["HTTP_PROXY"]',
            "HTTP_PROXY": "http://bound-proxy.invalid:8080",
        }
        stage_c = {
            "preparation-local": preparation_local_environment(root, parent=parent),
            "preparation-network": preparation_network_environment(
                root, parent=parent, required=False
            ),
            "searxng-network": searxng_network_environment(
                root, parent=parent, required=False
            ),
        }
        # A changed/broken file after launch admission must not replace the
        # policy values held by the authenticated launch gate.
        (root / ".env").write_text("not-an-assignment\n", encoding="utf-8")
        report = prepare(
            root,
            apply=True,
            env={
                name: parent[name]
                for name in (
                    "PATH",
                    "ROOKERY_PREPARE_MODE",
                    "ROOKERY_ALLOW_INSTALL_NETWORK",
                    "SEARXNG_MODE",
                    "BROWSER_MODE",
                )
            },
            environment_resolved=True,
            stage_c_environments=stage_c,
        )
        self.assertEqual(report["mode"], "off")
        self.assertTrue((root / "state" / "preparation.json").is_file())
        self.assertNotIn(
            "http://bound-proxy.invalid:8080", json.dumps(report["environment"])
        )
        td.cleanup()


class AdapterIsolationAndGoTests(unittest.TestCase):
    def test_unresolved_go_fails_before_preparation_or_runtime_writes(self):
        td = tempfile.TemporaryDirectory()
        root = Path(td.name)
        copy_rookery(root)
        args = build_parser().parse_args(["go"])

        with (
            mock.patch("rookery.portable.cli.workspace_root", return_value=root),
            mock.patch(
                "rookery.portable.cli.prepare",
                side_effect=AssertionError("unresolved configuration reached preparation"),
            ) as prepare_mock,
            mock.patch("sys.stderr"),
        ):
            self.assertEqual(cmd_go(args), 2)

        prepare_mock.assert_not_called()
        self.assertFalse((root / "state").exists())
        td.cleanup()

    def test_manual_surface_excludes_optional_adapter_and_extension_entries(self):
        td = tempfile.TemporaryDirectory()
        root = Path(td.name)
        copy_rookery(root)
        configure_event_environment(root, "manual", name_suffix="Surface Fixture")
        result = resolve_manifest(root, parent={})
        inventory = render_surface(root, result.manifest)
        ids = {row["id"] for row in inventory["agents"]} | {row["id"] for row in inventory["tools"]}
        optional_ids = {p.parent.name for p in (root / "adapters").glob("*/adapter.json")} | {
            p.parent.name for p in (root / "extensions").glob("*/extension.json")
        }
        for optional_id in optional_ids:
            self.assertFalse(any(optional_id in ident for ident in ids), (optional_id, sorted(ids)))
        td.cleanup()

    def test_selected_adapter_contributes_only_its_surface(self):
        td = tempfile.TemporaryDirectory()
        root = Path(td.name)
        copy_rookery(root)
        configure_event_environment(root, "htb", name_suffix="Surface Fixture")
        result = resolve_manifest(root, parent={})
        inventory = render_surface(root, result.manifest)
        ids = {row["id"] for row in inventory["agents"]} | {row["id"] for row in inventory["tools"]}
        self.assertTrue(any("htb" in ident for ident in ids))
        self.assertFalse(any("immersive" in ident for ident in ids))
        self.assertFalse(any("koth" in ident for ident in ids))
        optional_commands = [
            "adapters/immersive/bin/immersive-ledger-import",
            "adapters/immersive/bin/immersive-submit-answer",
            "extensions/koth/bin/score-correlate",
            "extensions/koth/bin/verified-write",
            "extensions/koth/bin/verified-write-linux",
            "extensions/koth/bin/verified-write-windows",
        ]
        env = {**os.environ, "PYTHONPATH": str(root / "lib"), "PYTHONDONTWRITEBYTECODE": "1"}
        for rel in optional_commands:
            help_result = subprocess.run([str(root / rel), "--help"], cwd=root, env=env, text=True, capture_output=True)
            self.assertEqual(help_result.returncode, 0, (rel, help_result.stderr))
        td.cleanup()

    def test_guacamole_export_writes_plan_when_no_transport_is_configured(self):
        fixture = make_deployed_workspace("manual")
        self.addCleanup(fixture.cleanup)
        root = Path(fixture.name)
        outdir = root / "evidence/guac/export-test"
        result = subprocess.run(
            [
                str(root / "extensions/guacamole/bin/guac-export-file"),
                "/tmp/remote.bin",
                "--outdir",
                str(outdir),
            ],
            cwd=root,
            env={
                key: value
                for key, value in fixture.bootstrap.environment.items()
                if not key.startswith("GUAC_")
            },
            text=True,
            capture_output=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 2, result.stderr)
        plan = (outdir / "EXPORT_PLAN.md").read_text(encoding="utf-8")
        self.assertIn("{remote_path}", plan)
        self.assertNotIn("{local_path}", plan)
        self.assertIn("emit the exported bytes on stdout", plan)

    def test_go_uses_existing_configuration_and_starts_codex(self):
        td = tempfile.TemporaryDirectory()
        root = Path(td.name)
        copy_rookery(root)
        shutil.rmtree(root / ".ruff_cache", ignore_errors=True)
        baseline_dir = tempfile.TemporaryDirectory()
        fake_bin = Path(baseline_dir.name) / "test-bin"
        fake_bin.mkdir()
        invocation_log = Path(baseline_dir.name) / "codex-invocation.txt"
        codex = fake_bin / "codex"
        codex.write_text(
            "#!/usr/bin/env bash\n"
            "set -euo pipefail\n"
            "if [ \"$1\" = --version ]; then echo 'codex-cli 0.150.0'; exit 0; fi\n"
            "if [ \"$1\" = --strict-config ] && [ \"$2\" = --version ]; then exit 0; fi\n"
            "if [ \"$1\" = doctor ]; then printf '%s\\n' '{\"checks\":{\"config.load\":{\"status\":\"ok\"}}}'; exit 0; fi\n"
            "if [ \"$1\" = --strict-config ] && [ \"$2\" = login ]; then test \"$3\" = status; exit 0; fi\n"
            'shell_provider=$(env -i PATH="$PATH" bash -c \'printf %s "${DUMMY_PROVIDER_KEY:-}"\')\n'
            f'printf \'argc=%s\\nprovider_env=%s\\nadapter_env=%s\\nshell_provider=%s\\n\' "$#" "${{DUMMY_PROVIDER_KEY:-}}" "${{CTFD_TOKEN:-}}" "$shell_provider" > {invocation_log!s}\n'
            f'printf \'%s\' "$2" >> {invocation_log!s}\n',
            encoding="utf-8",
        )
        codex.chmod(0o755)
        baseline_path = Path(baseline_dir.name) / "measurement-baseline.json"
        configure_event_environment(
            root,
            "manual",
            name_suffix="Prepared Fixture",
            extra={
                "EVENT_ID": "prepared-fixture",
                "ALLOWED_HOSTS": "localhost",
                "ALLOWED_CIDRS": "",
                "ALLOWED_PORTS": "80",
                "ALLOWED_PROTOCOLS": "http",
                "ALLOWED_FILE_ORIGINS": "fixture://*",
                "PLATFORM_HOSTS": "",
                "SCOPE_MAX_BYTES": "1024",
                "CODEX_AUTH_MODE": "environment",
                "CODEX_PROVIDER_ENV_KEYS": '["DUMMY_PROVIDER_KEY"]',
                "DUMMY_PROVIDER_KEY": "loaded",
                "ROOKERY_MEASUREMENT_BASELINE_PATH": str(baseline_path),
            },
        )
        launcher_env = {
            **os.environ,
            "PATH": str(fake_bin) + os.pathsep + os.environ.get("PATH", ""),
        }
        report = validate_tree(root, adapter="manual", strict_release=True)
        self.assertTrue(report["ok"], report["errors"])
        artifacts = Path(baseline_dir.name) / "release-artifacts"
        summary = build_release(root, artifacts)
        write_measurement_baseline(
            root,
            artifacts / str(summary["archive"]),
            artifacts / str(summary["manifest"]),
            baseline_path,
        )
        result = subprocess.run(
            [str(root / "go")], cwd=root, env=launcher_env, text=True, capture_output=True, timeout=60
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((root / "PREPARATION.md").exists())
        self.assertTrue((root / "START_PROMPT.md").exists())
        self.assertTrue((root / "state/preparation.json").exists())
        started = EventStore(root).events("measurement.started")
        self.assertEqual(len(started), 1)
        self.assertEqual(
            set(started[0]["payload"]),
            {
                "launch_binding_sha256",
                "baseline_sha256",
                "configuration_digest",
                "release_version",
                "stop_generation",
                "policy_generation",
                "scope_generation",
                "measurement_contract",
            },
        )
        self.assertNotIn(str(baseline_path), json.dumps(started[0]))
        invocation = invocation_log.read_text(encoding="utf-8")
        self.assertTrue(
            invocation.startswith(
                "argc=2\nprovider_env=loaded\nadapter_env=\nshell_provider=\n"
            ),
            invocation,
        )
        received_prompt = invocation.split("\n", 4)[4]
        self.assertEqual(received_prompt, (root / "START_PROMPT.md").read_text(encoding="utf-8").rstrip("\n"))
        baseline_dir.cleanup()
        td.cleanup()

    def test_go_does_not_create_live_configuration(self):
        td = tempfile.TemporaryDirectory()
        root = Path(td.name)
        copy_rookery(root)
        (root / ".env").unlink()
        result = subprocess.run([str(root / "bin/rookery"), "go"], cwd=root, text=True, capture_output=True, timeout=60)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertFalse((root / ".env").exists())
        self.assertFalse((root / "event.json").exists())
        self.assertFalse((root / "state").exists())
        td.cleanup()

    def test_release_validator_is_read_only_and_generic(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            copy_rookery(root)
            configure_event_environment(root, "manual")
            before = validate_tree(root, adapter="manual", strict_release=False)[
                "tree_hash_before"
            ]
            report = validate_tree(root, adapter="manual", strict_release=False)
            self.assertTrue(report["ok"], report["errors"])
            self.assertEqual(before, report["tree_hash_after"])

    def test_auxiliary_bin_commands_preserve_location_and_argv(self):
        td = tempfile.TemporaryDirectory()
        outside = tempfile.TemporaryDirectory()
        temp_files = tempfile.TemporaryDirectory()
        root = Path(td.name)
        copy_non_deployed_rookery(root)

        for command in ("playq", "searxng"):
            help_result = subprocess.run(
                [str(root / "bin" / command), "--help"],
                cwd=outside.name,
                text=True,
                capture_output=True,
                timeout=30,
            )
            self.assertEqual(help_result.returncode, 0, (command, help_result.stderr))

        r2q = subprocess.run(
            [str(root / "bin/r2q"), "fixture.bin", "--cmd"],
            cwd=outside.name,
            text=True,
            capture_output=True,
            timeout=30,
        )
        self.assertEqual(r2q.returncode, 2)
        self.assertIn("--cmd requires a command", r2q.stderr)

        ledger = subprocess.run(
            [
                str(root / "bin/run-ledger"),
                "fixture",
                "--",
                sys.executable,
                "-c",
                "print('argv preserved')",
            ],
            cwd=root,
            text=True,
            capture_output=True,
            timeout=30,
        )
        self.assertEqual(ledger.returncode, 0, ledger.stderr)
        self.assertTrue(
            any("argv preserved" in path.read_text() for path in (root / "logs/commands").glob("*/stdout.log"))
        )

        command_dirs_before = set((root / "logs/commands").iterdir())
        for marker in ("first", "second"):
            captured = subprocess.run(
                [
                    str(root / "bin/runq"),
                    "--label",
                    "envelope-test",
                    "--attempt-id",
                    "attempt-fixture",
                    "--proposal-id",
                    "proposal-fixture",
                    "--plan-id",
                    "plan-fixture",
                    "--",
                    sys.executable,
                    "-c",
                    f"print('{marker}')",
                ],
                cwd=root,
                text=True,
                capture_output=True,
                timeout=30,
            )
            self.assertEqual(captured.returncode, 0, captured.stderr)
        command_dirs_after = set((root / "logs/commands").iterdir())
        envelope_dirs = sorted(command_dirs_after - command_dirs_before)
        self.assertEqual(len(envelope_dirs), 2)
        self.assertEqual(len({path.name for path in envelope_dirs}), 2)
        for command_dir in envelope_dirs:
            meta = load_json(command_dir / "meta.json", {})
            digest = load_json(command_dir / "digest.json", {})
            stdout_path = root / meta["stdout_path"]
            stderr_path = root / meta["stderr_path"]
            self.assertEqual(meta["schema_version"], "2")
            self.assertTrue(meta["complete"])
            self.assertEqual(
                meta["release_version"],
                "unknown",
            )
            self.assertGreaterEqual(meta["elapsed_ms"], 0)
            self.assertEqual(meta["termination"], "exited")
            self.assertEqual(meta["attempt_id"], "attempt-fixture")
            self.assertEqual(meta["proposal_id"], "proposal-fixture")
            self.assertEqual(meta["plan_id"], "plan-fixture")
            self.assertEqual(meta["stdout_bytes"], stdout_path.stat().st_size)
            self.assertEqual(meta["stderr_bytes"], stderr_path.stat().st_size)
            self.assertEqual(meta["stdout_sha256"], sha256_file(stdout_path))
            self.assertEqual(meta["stderr_sha256"], sha256_file(stderr_path))
            self.assertEqual(digest["byte_count"], stdout_path.stat().st_size)
            self.assertEqual(digest["sha256"], meta["stdout_sha256"])
            self.assertEqual(digest["stderr"]["byte_count"], stderr_path.stat().st_size)
            self.assertEqual(digest["stderr"]["sha256"], meta["stderr_sha256"])
        command_events = EventStore(root).events()
        requested = [
            event
            for event in command_events
            if event["event_type"] == "command.requested"
            and event["payload"].get("attempt_id") == "attempt-fixture"
        ]
        completed = [
            event
            for event in command_events
            if event["event_type"] == "command.completed"
            and event["payload"].get("attempt_id") == "attempt-fixture"
        ]
        self.assertEqual(len(requested), 2)
        self.assertEqual(len(completed), 2)
        self.assertEqual(
            {event["payload"]["command_id"] for event in requested},
            {event["payload"]["command_id"] for event in completed},
        )

        fake_bin = root / "test-bin"
        fake_bin.mkdir()
        fake_gdb = fake_bin / "gdb"
        fake_gdb.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
        fake_gdb.chmod(0o755)
        gdb = subprocess.run(
            [str(root / "bin/gdbq"), "fixture.bin"],
            cwd=root,
            env={
                **os.environ,
                "PATH": str(fake_bin) + os.pathsep + os.environ.get("PATH", ""),
                "TMPDIR": temp_files.name,
            },
            text=True,
            capture_output=True,
            timeout=30,
        )
        self.assertEqual(gdb.returncode, 0, gdb.stderr)
        self.assertFalse(any(Path(temp_files.name).iterdir()))

        temp_files.cleanup()
        outside.cleanup()
        td.cleanup()

    def test_recursive_scanners_honor_bounds(self):
        td = tempfile.TemporaryDirectory()
        root = Path(td.name)
        for index in range(3):
            (root / f"fixture-{index}.txt").write_text(
                "aHR0cHM6Ly9maXh0dXJlLmludmFsaWQ= https://fixture.invalid/path\n",
                encoding="utf-8",
            )

        b64 = subprocess.run(
            [sys.executable, str(ROOKERY_ROOT / "bin/b64hunt.py"), str(root), "--max-files", "1"],
            text=True,
            capture_output=True,
            timeout=30,
        )
        self.assertEqual(b64.returncode, 0, b64.stderr)
        self.assertIn("stopped after 1 files", b64.stderr)

        urls = subprocess.run(
            [sys.executable, str(ROOKERY_ROOT / "bin/urlgrab.py"), str(root), "--max-files", "1"],
            text=True,
            capture_output=True,
            timeout=30,
        )
        self.assertEqual(urls.returncode, 0, urls.stderr)
        self.assertEqual(len(urls.stdout.splitlines()), 1)
        self.assertIn("stopped after 1 files", urls.stderr)

        changes = subprocess.run(
            [sys.executable, str(ROOKERY_ROOT / "bin/change-summary"), "--scan-limit", "1", "--json"],
            cwd=root,
            text=True,
            capture_output=True,
            timeout=30,
        )
        self.assertEqual(changes.returncode, 0, changes.stderr)
        change_summary = json.loads(changes.stdout)
        self.assertEqual(change_summary["scanned_files"], 1)
        self.assertTrue(change_summary["truncated"])
        td.cleanup()

    def test_health_summary_uses_cookie_filter_expiry_contract(self):
        td = tempfile.TemporaryDirectory()
        root = Path(td.name)
        copy_rookery(root)
        health_dir = root / "platform/session-health/fixture"
        health_dir.mkdir(parents=True)
        expiry = "2026-08-07T12:00:00Z"
        atomic_write_json(
            health_dir / "health.json",
            {"status": "ok", "cookie_filter": {"summary": {"status": "ok", "nearest_expiry_utc": expiry}}},
        )

        result = subprocess.run(
            [str(root / "bin/health-summary"), "--json"],
            cwd=root,
            text=True,
            capture_output=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["required_cookie_expiry"], expiry)
        td.cleanup()

    def test_transit_source_bounds_archive_extraction(self):
        def prepare(root: Path) -> None:
            configure_event_environment(
                root,
                "manual",
                name_suffix="Transit Bound",
                extra={
                    "EVENT_ID": "transit-bound",
                    "ALLOWED_HOSTS": "fixture.invalid",
                    "ALLOWED_CIDRS": "",
                    "ALLOWED_PORTS": "443",
                    "ALLOWED_PROTOCOLS": "https",
                    "ALLOWED_FILE_ORIGINS": "https://fixture.invalid/*",
                    "PLATFORM_HOSTS": "",
                    "SCOPE_MAX_BYTES": "1024",
                },
            )

        fixture = make_deployed_workspace("manual", prepare=prepare)
        self.addCleanup(fixture.cleanup)
        root = Path(fixture.name)
        input_temporary = tempfile.TemporaryDirectory()
        self.addCleanup(input_temporary.cleanup)
        valid_feed = Path(input_temporary.name) / "valid-feed.zip"
        with zipfile.ZipFile(valid_feed, "w") as archive:
            archive.writestr("stops.txt", "stop_id,stop_name\n1,Fixture Stop\n")
        valid = subprocess.run(
            [str(root / "bin/transit-source"), "--gtfs", str(valid_feed), "--outdir", "research/transit/test"],
            cwd=root,
            env=fixture.bootstrap.environment,
            text=True,
            capture_output=True,
            timeout=30,
        )
        self.assertEqual(valid.returncode, 0, valid.stderr)
        summary = load_json(root / "research/transit/test/transit_source.json", {})
        self.assertEqual(summary["counts"]["stops"], 1)

        unsafe_feed = Path(input_temporary.name) / "unsafe-feed.zip"
        with zipfile.ZipFile(unsafe_feed, "w") as archive:
            archive.writestr("../escaped.txt", "must not escape")
            archive.writestr("stops.txt", "stop_id,stop_name\n1,Fixture Stop\n")
        unsafe = subprocess.run(
            [str(root / "bin/transit-source"), "--gtfs", str(unsafe_feed), "--outdir", "research/transit/unsafe"],
            cwd=root,
            env=fixture.bootstrap.environment,
            text=True,
            capture_output=True,
            timeout=30,
        )
        self.assertNotEqual(unsafe.returncode, 0)
        self.assertFalse((root / "escaped.txt").exists())

        transit = runpy.run_path(
            str(root / "bin/transit-source"), run_name="transit_source_test"
        )
        scope = {
            "acknowledged": True,
            "generation": 1,
            "allowed_hosts": ["fixture.invalid"],
            "allowed_cidrs": [],
            "allowed_ports": [443],
            "allowed_protocols": ["https"],
            "allowed_file_origins": ["https://fixture.invalid/*"],
            "max_attachment_bytes": 4,
            "expires_at": "unknown",
        }
        response = mock.MagicMock()
        response.status = 200
        response.geturl.return_value = "https://fixture.invalid/feed.zip"
        response.read.return_value = b"oversized"
        response.__enter__.return_value = response
        checked_transport = ScopedHTTPTransport(scope, ssl.create_default_context())
        recorded_requests: list[object] = []

        def sealed_response_transport(scoped_scope, url, **kwargs):
            self.assertIs(kwargs["transport"], checked_transport)
            sequence = scope_module._EndpointAwareTestTransport([response])
            try:
                return scope_module.open_scoped_url(
                    scoped_scope, url, _test_transport=sequence
                )
            finally:
                recorded_requests.extend(sequence.requests)

        output = mock.Mock()
        with (
            mock.patch.dict(
                transit["download_feed"].__globals__,
                {"open_scoped_url": sealed_response_transport},
            ),
            self.assertRaisesRegex(RuntimeError, "attachment byte bound"),
        ):
            transit["download_feed"](
                "https://fixture.invalid/feed.zip",
                output,
                4,
                scope=scope,
                transport=checked_transport,
                binding=None,
            )
        self.assertEqual(len(recorded_requests), 1)
        request = recorded_requests[0]
        self.assertEqual(request.full_url, "https://fixture.invalid/feed.zip")
        output.write_bytes.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
