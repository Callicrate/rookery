from __future__ import annotations

import json
import os
import ssl
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

from tests.rookery.support import ROOKERY_ROOT

LIB = ROOKERY_ROOT / "lib"
if str(LIB) not in sys.path:
    sys.path.insert(0, str(LIB))

# ruff: noqa: E402
from rookery.portable.environment import (
    EnvClass,
    EnvKey,
    EnvironmentPolicyError,
    build_child_environment,
    preparation_network_environment,
    purpose_policy,
    resolve_stage_c_launch_environment,
)
from rookery.portable.network_policy import ExplicitNetworkPolicy
from rookery.portable.scope import open_scoped_url


class StageCEnvironmentPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_env(self, text: str) -> None:
        self.root.joinpath(".env").write_text(text, encoding="utf-8")

    def test_network_selector_is_exact_dotenv_wins_and_metadata_has_no_values(self) -> None:
        dotenv_proxy = "http://dotenv-proxy.invalid:8080"
        self.write_env(
            "ROOKERY_PREPARE_NETWORK_ENV_KEYS=[\"HTTP_PROXY\"]\n"
            f"HTTP_PROXY={dotenv_proxy}\n"
        )
        with mock.patch.dict(
            os.environ,
            {"HTTP_PROXY": "http://parent-proxy.invalid:9090"},
            clear=False,
        ):
            child = preparation_network_environment(self.root)
        self.assertEqual(child.values["HTTP_PROXY"], dotenv_proxy)
        metadata = json.dumps(child.metadata())
        self.assertIn("HTTP_PROXY", metadata)
        self.assertNotIn(dotenv_proxy, metadata)

    def test_known_secret_and_owner_classes_are_rejected_pre_effect(self) -> None:
        for selector, name in (
            ("BROWSER_ENV_KEYS", "OPENAI_API_KEY"),
            ("ROOKERY_PREPARE_NETWORK_ENV_KEYS", "CTFD_TOKEN"),
        ):
            with self.subTest(selector=selector, name=name):
                self.write_env(f'{selector}=["{name}"]\n{name}=dummy-secret\n')
                with self.assertRaises(EnvironmentPolicyError):
                    resolve_stage_c_launch_environment(self.root)
                self.assertFalse((self.root / "state").exists())

    def test_active_selected_value_is_required_but_disabled_purpose_is_not(self) -> None:
        self.write_env(
            "ROOKERY_PREPARE_NETWORK_ENV_KEYS=[\"HTTP_PROXY\"]\n"
            "ROOKERY_PREPARE_MODE=auto\n"
            "ROOKERY_ALLOW_INSTALL_NETWORK=1\n"
        )
        with self.assertRaisesRegex(EnvironmentPolicyError, "HTTP_PROXY"):
            resolve_stage_c_launch_environment(self.root)
        self.assertFalse((self.root / "state").exists())

        self.write_env(
            "ROOKERY_PREPARE_NETWORK_ENV_KEYS=[\"HTTP_PROXY\"]\n"
            "ROOKERY_PREPARE_MODE=off\n"
            "ROOKERY_ALLOW_INSTALL_NETWORK=0\n"
        )
        policies = resolve_stage_c_launch_environment(self.root)
        self.assertNotIn("HTTP_PROXY", policies["preparation-network"].values)

    def test_proxy_alias_conflict_and_linked_ca_fail_before_transport(self) -> None:
        self.write_env(
            "SEARXNG_NETWORK_ENV_KEYS=[\"HTTP_PROXY\",\"http_proxy\"]\n"
            "HTTP_PROXY=http://one.invalid:8080\n"
            "http_proxy=http://two.invalid:8080\n"
        )
        expected = "duplicate assignment" if os.name == "nt" else "conflicting proxy aliases"
        with self.assertRaisesRegex(EnvironmentPolicyError, expected):
            resolve_stage_c_launch_environment(self.root)

        ca_target = self.root / "ca-target.pem"
        ca_target.write_text("fixture", encoding="utf-8")
        ca_link = self.root / "ca-link.pem"
        try:
            ca_link.symlink_to(ca_target)
        except OSError:
            self.skipTest("host does not support symlink probes")
        self.write_env(
            "SEARXNG_NETWORK_ENV_KEYS=[\"SSL_CERT_FILE\"]\n"
            f"SSL_CERT_FILE={ca_link}\n"
        )
        with self.assertRaisesRegex(EnvironmentPolicyError, "CA trust path"):
            resolve_stage_c_launch_environment(self.root)

    def test_explicit_transport_ignores_ambient_proxy_and_honors_declared_no_proxy(self) -> None:
        target_hits: list[str] = []
        proxy_hits: list[str] = []

        class TargetHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                target_hits.append(self.path)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, _format: str, *args: object) -> None:
                del args

        class ProxyHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                proxy_hits.append(self.path)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"proxy")

            def log_message(self, _format: str, *args: object) -> None:
                del args

        target = ThreadingHTTPServer(("127.0.0.1", 0), TargetHandler)
        proxy = ThreadingHTTPServer(("127.0.0.1", 0), ProxyHandler)
        target_thread = threading.Thread(target=target.serve_forever, daemon=True)
        proxy_thread = threading.Thread(target=proxy.serve_forever, daemon=True)
        target_thread.start()
        proxy_thread.start()
        try:
            target_url = f"http://127.0.0.1:{target.server_port}/resource"
            target_scope = {
                "acknowledged": True,
                "generation": 1,
                "expires_at": "unknown",
                "allowed_hosts": ["127.0.0.1", "fixture.invalid"],
                "allowed_cidrs": ["127.0.0.0/8"],
                "allowed_ports": [80, target.server_port],
                "allowed_protocols": ["http"],
                "allowed_file_origins": [],
                "platform_hosts": ["127.0.0.1"],
                "max_attachment_bytes": 4096,
            }
            proxy_url = f"http://127.0.0.1:{proxy.server_port}"
            self.write_env("")
            with mock.patch.dict(os.environ, {"HTTP_PROXY": proxy_url}, clear=False):
                policy = ExplicitNetworkPolicy.from_child_environment(
                    preparation_network_environment(self.root)
                )
                with open_scoped_url(
                    target_scope,
                    target_url,
                    timeout=5,
                    transport=policy.scoped_transport(target_scope),
                ) as response:
                    self.assertEqual(response.read(), b"ok")
            self.assertEqual(target_hits, ["/resource"])
            self.assertEqual(proxy_hits, [])

            self.write_env(
                "ROOKERY_PREPARE_NETWORK_ENV_KEYS=[\"HTTP_PROXY\",\"NO_PROXY\"]\n"
                f"HTTP_PROXY={proxy_url}\n"
                "NO_PROXY=127.0.0.1\n"
            )
            policy = ExplicitNetworkPolicy.from_child_environment(
                preparation_network_environment(self.root)
            )
            with open_scoped_url(
                target_scope,
                target_url,
                timeout=5,
                transport=policy.scoped_transport(target_scope),
            ) as response:
                self.assertEqual(response.read(), b"ok")
            self.assertEqual(target_hits, ["/resource", "/resource"])
            self.assertEqual(proxy_hits, [])
            self.assertNotIn(proxy_url, json.dumps(policy.metadata()))

            self.write_env(
                "ROOKERY_PREPARE_NETWORK_ENV_KEYS=[\"HTTP_PROXY\"]\n"
                f"HTTP_PROXY={proxy_url}\n"
            )
            policy = ExplicitNetworkPolicy.from_child_environment(
                preparation_network_environment(self.root)
            )
            with self.assertRaisesRegex(
                EnvironmentPolicyError, "scoped_proxy_target_pinning_unavailable"
            ):
                policy.scoped_transport(target_scope).preflight_url(
                    "http://fixture.invalid/resource"
                )
            self.assertEqual(proxy_hits, [])
        finally:
            target.shutdown()
            proxy.shutdown()
            target.server_close()
            proxy.server_close()
            target_thread.join(timeout=2)
            proxy_thread.join(timeout=2)

    def test_declared_ca_is_loaded_without_ambient_ca_fallback_or_insecure_retry(self) -> None:
        cafile = __import__("ssl").get_default_verify_paths().openssl_cafile
        if not cafile or not Path(cafile).is_file():
            self.skipTest("compiled system CA file is unavailable")
        self.write_env(
            "ROOKERY_PREPARE_NETWORK_ENV_KEYS=[\"SSL_CERT_FILE\"]\n"
            f"SSL_CERT_FILE={Path(cafile).resolve()}\n"
        )
        with mock.patch.dict(
            os.environ,
            {"SSL_CERT_FILE": str(self.root / "ambient-invalid-ca.pem")},
            clear=False,
        ):
            policy = ExplicitNetworkPolicy.from_child_environment(
                preparation_network_environment(self.root)
            )
        self.assertTrue(policy.trust_context.check_hostname)
        self.assertNotIn(str(Path(cafile).resolve()), json.dumps(policy.metadata()))

    @unittest.skipUnless(
        os.name == "posix" and bool(getattr(os, "O_NOFOLLOW", 0)),
        "requires POSIX no-follow descriptor semantics",
    )
    def test_ca_bundle_bytes_are_bound_before_tls_context_use(self) -> None:
        cafile = ssl.get_default_verify_paths().openssl_cafile
        if not cafile or not Path(cafile).is_file():
            self.skipTest("compiled system CA file is unavailable")
        bundle = self.root / "declared-ca.pem"
        original = Path(cafile).read_bytes()
        bundle.write_bytes(original)
        child = build_child_environment(
            self.root,
            policy=purpose_policy(
                "declared-ca",
                (EnvKey("SSL_CERT_FILE", EnvClass.CA_TRUST_PATH),),
                allowed_classes={EnvClass.CA_TRUST_PATH},
            ),
            parent={"SSL_CERT_FILE": str(bundle)},
        )
        replacement = self.root / "replacement-ca.pem"
        replacement.write_bytes(b"not the admitted bundle")
        os.replace(replacement, bundle)
        context = mock.Mock()
        with mock.patch(
            "rookery.portable.network_policy._system_trust_context",
            return_value=context,
        ):
            ExplicitNetworkPolicy.from_child_environment(child)
        self.assertEqual(
            context.load_verify_locations.call_args.kwargs,
            {"cadata": original.decode("ascii")},
        )
        self.assertNotIn(str(bundle), json.dumps(child.metadata()))

    @unittest.skipUnless(
        os.name == "posix" and bool(getattr(os, "O_NOFOLLOW", 0)),
        "requires POSIX no-follow descriptor semantics",
    )
    def test_ca_path_swap_during_descriptor_read_is_rejected_without_insecure_retry(self) -> None:
        bundle = self.root / "declared-ca.pem"
        bundle.write_bytes(b"first trusted bytes")
        replacement = self.root / "replacement-ca.pem"
        replacement.write_bytes(b"second trusted bytes")
        original_read = os.read
        swapped = False

        def read_then_swap(descriptor: int, count: int) -> bytes:
            nonlocal swapped
            data = original_read(descriptor, count)
            if not swapped:
                swapped = True
                os.replace(replacement, bundle)
            return data

        with (
            mock.patch("rookery.portable.environment.os.read", side_effect=read_then_swap),
            mock.patch.object(ssl, "_create_unverified_context") as insecure,
            self.assertRaisesRegex(EnvironmentPolicyError, "CA trust path"),
        ):
            build_child_environment(
                self.root,
                policy=purpose_policy(
                    "declared-ca",
                    (EnvKey("SSL_CERT_FILE", EnvClass.CA_TRUST_PATH),),
                    allowed_classes={EnvClass.CA_TRUST_PATH},
                ),
                parent={"SSL_CERT_FILE": str(bundle)},
            )
        self.assertTrue(swapped)
        insecure.assert_not_called()

    def test_retired_vpn_controls_do_not_construct_launch_environment_policy(self) -> None:
        self.write_env(
            "VPN_ENABLED=1\n"
            "VPN_HEALTH_ENV_KEYS=[\"ROOKERY_OWNER_TOKEN\"]\n"
            "VPN_CONNECT_ENV_KEYS=[\"VPN_HELPER_SETTING\"]\n"
            "VPN_HELPER_SETTING=legacy-value\n"
        )
        policies = resolve_stage_c_launch_environment(self.root)
        self.assertFalse(any(name.startswith("vpn-") for name in policies))
        self.assertNotIn("VPN_HELPER_SETTING", json.dumps([policy.metadata() for policy in policies.values()]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
