from __future__ import annotations

from contextlib import nullcontext
import json
import os
import runpy
import ssl
import subprocess
import sys
import tempfile
import time
import types
import unittest
from pathlib import Path
from unittest import mock

from tests.rookery.env_fixtures import replace_env_assignments
from tests.rookery.support import ROOKERY_ROOT
from tests.rookery.test_acceptance_campaign import make_deployed_workspace


def scoped() -> dict[str, object]:
    return {
        "acknowledged": True,
        "generation": 1,
        "expires_at": "unknown",
        "allowed_hosts": ["fixture.invalid"],
        "allowed_cidrs": [],
        "allowed_ports": [],
        "allowed_protocols": ["http", "https", "ws", "wss"],
        "allowed_file_origins": [],
        "platform_hosts": ["fixture.invalid"],
        "max_attachment_bytes": 4096,
    }


def fake_binding(scope: dict[str, object]):
    return types.SimpleNamespace(
        scope=scope,
        scope_generation=int(scope["generation"]),
        stop_generation=0,
        file_sha256="a" * 64,
        content_sha256="b" * 64,
        launch_binding_sha256="c" * 64,
    )


def install_fake_authority(globals_dict: dict[str, object]) -> None:
    globals_dict["scope_guard_url"] = lambda _url: fake_binding(scoped())
    globals_dict["_verify_effect_binding"] = lambda binding: binding
    globals_dict["_scope_effect"] = lambda binding: nullcontext(binding)


def configure_immersive_fixture(root: Path, extra: dict[str, str]) -> None:
    replace_env_assignments(
        root,
        {
            "ADAPTER_CONFIG_INVENTORY_ARGV": '["/usr/bin/printf","{}"]',
            "ADAPTER_CONFIG_SUBMIT_ARGV": '["true"]',
            "IMMERSIVE_COOKIES_FILE": "/private/cookies.json",
            **extra,
        },
    )


class ImmersiveEnvironmentTests(unittest.TestCase):
    def selected_namespace(self):
        return runpy.run_path(
            str(ROOKERY_ROOT / "adapters/immersive/bin/immersive-selected-lab-refresh")
        )

    def cluster_namespace(self):
        return runpy.run_path(
            str(ROOKERY_ROOT / "adapters/immersive/bin/immersive-cluster-capture")
        )

    def test_dotenv_wins_parent_and_undeclared_values_are_excluded(self) -> None:
        namespace = self.selected_namespace()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.joinpath(".env").write_text(
                "IMMERSIVE_GRAPHQL_URL=https://dotenv.invalid/graphql\n"
                "IMMERSIVE_COOKIES_FILE=/private/dotenv-cookies.json\n"
                "UNDECLARED_DOTENV=not-visible\n",
                encoding="utf-8",
            )
            namespace["read_env"].__globals__["ROOT"] = root
            with mock.patch.dict(
                os.environ,
                {
                    "IMMERSIVE_GRAPHQL_URL": "https://parent.invalid/graphql",
                    "IMMERSIVE_COOKIES_FILE": "/private/parent-cookies.json",
                    "OPENAI_API_KEY": "provider-dummy-not-visible",
                    "UNDECLARED_PARENT": "not-visible",
                },
                clear=False,
            ):
                result = namespace["read_env"]()
        self.assertEqual(result["IMMERSIVE_GRAPHQL_URL"], "https://dotenv.invalid/graphql")
        self.assertEqual(result["IMMERSIVE_COOKIES_FILE"], "/private/dotenv-cookies.json")
        self.assertNotIn("OPENAI_API_KEY", result)
        self.assertNotIn("UNDECLARED_PARENT", result)
        self.assertNotIn("UNDECLARED_DOTENV", result)

    def test_custom_refresh_child_receives_declared_names_only(self) -> None:
        probe = (
            "import json,os; print(json.dumps({key: key in os.environ for key in "
            "['DECLARED_HELPER','IMMERSIVE_COOKIES_FILE','OPENAI_API_KEY',"
            "'HTTP_PROXY','ROOKERY_OWNER_TOKEN','UNRELATED_PARENT']}))"
        )

        def prepare(root: Path) -> None:
            command = [sys.executable, "-c", probe]
            configure_immersive_fixture(
                root,
                {
                    "IMMERSIVE_SELECTED_LAB_REFRESH_ARGV": json.dumps(command),
                    "IMMERSIVE_SELECTED_LAB_REFRESH_ENV_KEYS": json.dumps(["DECLARED_HELPER"]),
                    "DECLARED_HELPER": "allowed-child-value",
                    "IMMERSIVE_COOKIES_FILE": "/private/cookies.json",
                },
            )

        fixture = make_deployed_workspace("immersive", prepare=prepare)
        self.addCleanup(fixture.cleanup)
        root = Path(fixture.name)
        try:
            outdir = root / "evidence" / "immersive" / "custom-refresh"
            environment = {
                **fixture.bootstrap.environment,
                "OPENAI_API_KEY": "provider-dummy-not-visible",
                "HTTP_PROXY": "http://ambient.invalid:8080",
                "ROOKERY_OWNER_TOKEN": "owner-dummy-not-visible",
                "UNRELATED_PARENT": "unrelated-dummy-not-visible",
                "PYTHONDONTWRITEBYTECODE": "1",
            }
            result = subprocess.run(
                [
                    str(root / "adapters/immersive/bin/immersive-selected-lab-refresh"),
                    "--outdir",
                    str(outdir),
                ],
                cwd=root,
                env=environment,
                text=True,
                capture_output=True,
                timeout=30,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            seen = json.loads((outdir / "stdout.log").read_text(encoding="utf-8"))
            self.assertTrue(seen["DECLARED_HELPER"])
            for name in (
                "IMMERSIVE_COOKIES_FILE",
                "OPENAI_API_KEY",
                "HTTP_PROXY",
                "ROOKERY_OWNER_TOKEN",
                "UNRELATED_PARENT",
            ):
                self.assertFalse(seen[name], name)
            metadata = (outdir / "summary.json").read_text(encoding="utf-8")
            self.assertIn("DECLARED_HELPER", metadata)
            for value in (
                "allowed-child-value",
                "provider-dummy-not-visible",
                "owner-dummy-not-visible",
                "unrelated-dummy-not-visible",
                "/private/cookies.json",
            ):
                self.assertNotIn(value, metadata)
        finally:
            fixture.cleanup()

    @unittest.skipUnless(os.name == "posix", "requires owned process groups")
    def test_custom_refresh_mid_run_stop_is_prompt_and_cancels_child(self) -> None:
        def prepare(root: Path) -> None:
            configure_immersive_fixture(
                root,
                {
                    "IMMERSIVE_SELECTED_LAB_REFRESH_ARGV": json.dumps(["/usr/bin/sleep", "4"]),
                },
            )

        fixture = make_deployed_workspace("immersive", prepare=prepare)
        self.addCleanup(fixture.cleanup)
        root = Path(fixture.name)
        outdir = root / "evidence" / "immersive" / "cancelled-custom-refresh"
        helper = root / "adapters/immersive/bin/immersive-selected-lab-refresh"
        process = subprocess.Popen(
            [str(helper), "--outdir", str(outdir)],
            cwd=root,
            env=fixture.bootstrap.environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.addCleanup(
            lambda: process.kill() if process.poll() is None else None
        )
        child_pid: int | None = None
        deadline = time.monotonic() + 5
        children_path = Path(f"/proc/{process.pid}/task/{process.pid}/children")
        while time.monotonic() < deadline and process.poll() is None:
            try:
                children = children_path.read_text(encoding="ascii").split()
            except OSError:
                children = []
            for raw_pid in children:
                candidate = int(raw_pid)
                try:
                    command = Path(f"/proc/{candidate}/cmdline").read_bytes()
                except OSError:
                    continue
                if command.startswith(b"/usr/bin/sleep\x004\x00"):
                    child_pid = candidate
                    break
            if child_pid is not None:
                break
            time.sleep(0.02)
        if child_pid is None:
            stdout, stderr = process.communicate(timeout=5)
            self.fail(f"custom sleep child did not start: {stdout!r} {stderr!r}")

        started = time.monotonic()
        stopped = subprocess.run(
            [str(root / "go"), "stop"],
            cwd=root,
            env=fixture.bootstrap.environment,
            text=True,
            capture_output=True,
            timeout=5,
        )
        stop_elapsed = time.monotonic() - started
        stdout, stderr = process.communicate(timeout=3)

        self.assertEqual(stopped.returncode, 0, stopped.stdout + stopped.stderr)
        self.assertLess(
            stop_elapsed,
            2.0,
            f"operator stop took {stop_elapsed:.3f}s while custom child ran",
        )
        self.assertEqual(process.returncode, 4, stdout + stderr)
        self.assertFalse(Path(f"/proc/{child_pid}").exists())
        self.assertFalse((outdir / "stdout.log").exists())
        self.assertFalse((outdir / "stderr.log").exists())

    def test_missing_custom_refresh_key_fails_before_output_or_spawn(self) -> None:
        def prepare(root: Path) -> None:
            configure_immersive_fixture(
                root,
                {
                    "IMMERSIVE_SELECTED_LAB_REFRESH_ARGV": '["true"]',
                    "IMMERSIVE_SELECTED_LAB_REFRESH_ENV_KEYS": '["MISSING_HELPER"]',
                },
            )

        fixture = make_deployed_workspace("immersive", prepare=prepare)
        self.addCleanup(fixture.cleanup)
        root = Path(fixture.name)
        try:
            outdir = root / "evidence" / "immersive" / "missing-refresh-key"
            result = subprocess.run(
                [
                    str(root / "adapters/immersive/bin/immersive-selected-lab-refresh"),
                    "--outdir",
                    str(outdir),
                ],
                cwd=root,
                env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
                text=True,
                capture_output=True,
                timeout=30,
            )
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertFalse(outdir.exists())
        finally:
            fixture.cleanup()

    def test_scope_authority_load_is_in_process(self) -> None:
        namespace = self.selected_namespace()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            namespace["scope_guard_url"].__globals__["ROOT"] = root
            binding = fake_binding(scoped())
            loader = mock.Mock(return_value=binding)
            captured = mock.Mock(side_effect=AssertionError("scope child launched"))
            with mock.patch.dict(
                namespace["scope_guard_url"].__globals__,
                {
                    "load_canonical_compiled_scope": loader,
                    "run_bounded_argv": captured,
                },
            ):
                self.assertIs(
                    namespace["scope_guard_url"](
                        "https://fixture.invalid/graphql"
                    ),
                    binding,
                )
            loader.assert_called_once_with(root)
            captured.assert_not_called()

    def test_network_policy_uses_declared_proxy_ca_and_names_only_metadata(self) -> None:
        namespace = self.selected_namespace()
        cafile = ssl.get_default_verify_paths().openssl_cafile
        if not cafile or not Path(cafile).is_file():
            self.skipTest("compiled system CA file is unavailable on this host")
        cafile = str(Path(cafile).resolve())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.joinpath(".env").write_text(
                "IMMERSIVE_NETWORK_ENV_KEYS=[\"HTTPS_PROXY\",\"SSL_CERT_FILE\"]\n"
                "HTTPS_PROXY=http://dotenv-proxy.invalid:8080\n"
                f"SSL_CERT_FILE={cafile}\n",
                encoding="utf-8",
            )
            with mock.patch.dict(
                os.environ,
                {
                    "HTTPS_PROXY": "http://parent-proxy.invalid:9090",
                    "OPENAI_API_KEY": "provider-dummy-not-visible",
                },
                clear=False,
            ):
                policy = namespace["resolve_network_policy"](
                    root, '["HTTPS_PROXY","SSL_CERT_FILE"]'
                )
            with self.assertRaisesRegex(
                ValueError, "scoped_proxy_target_pinning_unavailable"
            ):
                policy.route_for("fixture.invalid", 443, "wss")
            metadata = json.dumps(policy.metadata())
            self.assertIn("HTTPS_PROXY", metadata)
            self.assertIn("SSL_CERT_FILE", metadata)
            self.assertNotIn("dotenv-proxy.invalid", metadata)
            self.assertNotIn(str(cafile), metadata)
            self.assertNotIn("provider-dummy-not-visible", metadata)

    def test_ambient_websocket_proxy_is_disabled_and_invalid_ca_never_retries(self) -> None:
        namespace = self.cluster_namespace()
        fixture = make_deployed_workspace("manual")
        self.addCleanup(fixture.cleanup)
        root = Path(fixture.name)
        try:
            globals_dict = namespace["main"].__globals__
            globals_dict["ROOT"] = root
            install_fake_authority(globals_dict)
            pinned_stream = mock.Mock()
            globals_dict["scoped_connection_plan"] = mock.Mock(return_value=object())
            globals_dict["connect_scoped_stream"] = mock.Mock(
                return_value=pinned_stream
            )
            socket = types.SimpleNamespace(create_connection=mock.Mock(side_effect=RuntimeError("offline")))
            outdir = root / "evidence" / "immersive" / "ambient-proxy"
            with (
                mock.patch.dict(
                    os.environ,
                    {
                        "HTTP_PROXY": "http://ambient.invalid:8080",
                        "WEBSOCKET_CLIENT_CA_BUNDLE": "/ambient/ca.pem",
                    },
                    clear=False,
                ),
                mock.patch.dict(sys.modules, {"websocket": socket}),
                mock.patch.object(
                    sys,
                    "argv",
                    [
                        "immersive-cluster-capture",
                        "--url",
                        "wss://fixture.invalid/cable",
                        "--outdir",
                        str(outdir),
                    ],
                ),
            ):
                self.assertEqual(namespace["main"](), 4)
            options = socket.create_connection.call_args.kwargs
            self.assertIs(options["socket"], pinned_stream)
            self.assertEqual(options["redirect_limit"], 0)
            self.assertNotIn("http_proxy_host", options)
            globals_dict["scoped_connection_plan"].assert_called_once()
            globals_dict["connect_scoped_stream"].assert_called_once()
            pinned_stream.close.assert_called_once()
            self.assertNotIn("/ambient/ca.pem", json.dumps(
                json.loads((outdir / "request_meta.json").read_text(encoding="utf-8"))
            ))

            globals_dict["resolve_network_policy"] = mock.Mock(
                side_effect=globals_dict["EnvironmentPolicyError"](
                    "invalid_declared_ca"
                )
            )
            socket.create_connection.reset_mock()
            with (
                mock.patch.dict(sys.modules, {"websocket": socket}),
                mock.patch.object(
                    sys,
                    "argv",
                    [
                        "immersive-cluster-capture",
                        "--url",
                        "wss://fixture.invalid/cable",
                        "--outdir",
                        str(root / "evidence" / "immersive" / "invalid-ca"),
                    ],
                ),
            ):
                self.assertEqual(namespace["main"](), 2)
            socket.create_connection.assert_not_called()

            globals_dict["scoped_connection_plan"] = mock.Mock(
                side_effect=RuntimeError("scoped_proxy_target_pinning_unavailable")
            )
            socket.create_connection.reset_mock()
            unsupported_outdir = root / "evidence" / "immersive" / "unsupported-proxy"
            with (
                mock.patch.dict(sys.modules, {"websocket": socket}),
                mock.patch.object(
                    sys,
                    "argv",
                    [
                        "immersive-cluster-capture",
                        "--url",
                        "wss://fixture.invalid/cable",
                        "--outdir",
                        str(unsupported_outdir),
                    ],
                ),
            ):
                self.assertEqual(namespace["main"](), 2)
            self.assertFalse(unsupported_outdir.exists())
            socket.create_connection.assert_not_called()
        finally:
            fixture.cleanup()

    def test_cookie_target_matching_keeps_secure_path_and_host_constraints(self) -> None:
        namespace = runpy.run_path(
            str(ROOKERY_ROOT / "adapters/immersive/bin/immersive-cookie-filter")
        )
        cookie = {
            "domain": ".fixture.invalid",
            "path": "/labs",
            "secure": True,
            "hostOnly": False,
        }
        good = namespace["_validated_target_url"](
            "https://child.fixture.invalid/labs/current"
        )
        wrong_path = namespace["_validated_target_url"](
            "https://child.fixture.invalid/other"
        )
        insecure = namespace["_validated_target_url"](
            "http://child.fixture.invalid/labs/current"
        )
        self.assertTrue(namespace["cookie_matches_target"](cookie, good))
        self.assertFalse(namespace["cookie_matches_target"](cookie, wrong_path))
        self.assertFalse(namespace["cookie_matches_target"](cookie, insecure))


if __name__ == "__main__":
    unittest.main(verbosity=2)
