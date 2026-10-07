from __future__ import annotations

import ipaddress
import socket
import ssl
import sys
import threading
import unittest
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

from tests.rookery.support import ROOKERY_ROOT

LIB = ROOKERY_ROOT / "lib"
if str(LIB) not in sys.path:
    sys.path.insert(0, str(LIB))

# ruff: noqa: E402
from rookery.portable.scope import (
    check_cidr,
    check_resolved_addresses,
    check_url,
    open_scoped_url,
)
from rookery.portable.network_policy import _no_proxy_rules
from rookery.portable.environment import EnvironmentPolicyError
from rookery.portable.scoped_transport import (
    ScopedConnectionPlan,
    ScopedHTTPTransport,
    ScopedTransportError,
    connect_scoped_stream,
    resolve_scoped_addresses,
    scoped_connection_plan,
)


def scoped(**changes: object) -> dict[str, object]:
    value: dict[str, object] = {
        "acknowledged": True,
        "generation": 2,
        "expires_at": "unknown",
        "allowed_hosts": ["*.chal.uiuc.tf", "fixture.invalid"],
        "allowed_cidrs": [],
        "allowed_ports": [],
        "allowed_protocols": ["http", "https"],
        "allowed_file_origins": [],
        "platform_hosts": ["*.chal.uiuc.tf", "fixture.invalid"],
        "max_attachment_bytes": 4096,
    }
    value.update(changes)
    return value


def answer(address: str, port: int) -> tuple[object, ...]:
    parsed = ipaddress.ip_address(address)
    if isinstance(parsed, ipaddress.IPv4Address):
        return (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (address, port))
    return (socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (address, port, 0, 0))


class DNSAuthorizationTests(unittest.TestCase):
    def test_uiuctf_hostname_with_global_a_and_aaaa_needs_no_cidr(self) -> None:
        scope = scoped()
        with mock.patch(
            "socket.getaddrinfo",
            return_value=[
                answer("8.8.8.8", 443),
                answer("2001:4860:4860::8888", 443),
            ],
        ):
            plan = resolve_scoped_addresses(scope, "pwn.chal.uiuc.tf", 443)
        self.assertEqual(len(plan), 2)

    def test_special_and_mixed_answers_fail_before_any_socket(self) -> None:
        denied = (
            "127.0.0.1",
            "10.0.0.1",
            "100.64.0.1",
            "169.254.169.254",
            "192.0.2.1",
            "198.18.0.1",
            "224.0.0.1",
            "0.0.0.0",
            "::1",
            "::",
            "fc00::1",
            "fe80::1",
            "ff02::1",
            "::ffff:10.0.0.1",
            "64:ff9b::a9fe:a9fe",
            "64:ff9b:1::a9fe:a9fe",
        )
        for address in denied:
            with self.subTest(address=address), mock.patch(
                "socket.getaddrinfo", return_value=[answer(address, 443)]
            ), mock.patch("socket.socket") as socket_factory:
                with self.assertRaisesRegex(RuntimeError, "scoped_dns_answer_outside_scope"):
                    resolve_scoped_addresses(scoped(), "pwn.chal.uiuc.tf", 443)
                socket_factory.assert_not_called()

        with mock.patch(
            "socket.getaddrinfo",
            return_value=[answer("8.8.8.8", 443), answer("127.0.0.1", 443)],
        ), mock.patch("socket.socket") as socket_factory:
            with self.assertRaisesRegex(RuntimeError, "scoped_dns_answer_outside_scope"):
                resolve_scoped_addresses(scoped(), "pwn.chal.uiuc.tf", 443)
            socket_factory.assert_not_called()

    def test_special_address_requires_its_explicit_cidr(self) -> None:
        address = ipaddress.IPv4Address("169.254.169.254")
        self.assertFalse(
            check_resolved_addresses(scoped(), "fixture.invalid", [address]).allowed
        )
        admitted = scoped(allowed_cidrs=["169.254.0.0/16"])
        self.assertTrue(
            check_resolved_addresses(admitted, "fixture.invalid", [address]).allowed
        )

    def test_rfc6052_prefix_specific_ipv4_extraction_and_malformed_suffixes(self) -> None:
        prefix48 = ipaddress.IPv6Address("64:ff9b:1:a9fe:a9:fe00::")
        prefix96 = ipaddress.IPv6Address("64:ff9b::c0a8:101")
        admitted = scoped(
            allowed_cidrs=["64:ff9b:1::/48", "64:ff9b::/96", "169.254.0.0/16", "192.168.0.0/16"]
        )
        self.assertTrue(
            check_resolved_addresses(admitted, "fixture.invalid", [prefix48]).allowed
        )
        self.assertTrue(
            check_resolved_addresses(admitted, "fixture.invalid", [prefix96]).allowed
        )
        public48 = ipaddress.IPv6Address("64:ff9b:1:808:8:800::")
        self.assertTrue(
            check_resolved_addresses(
                scoped(allowed_cidrs=["64:ff9b:1::/48"]),
                "fixture.invalid",
                [public48],
            ).allowed
        )
        link_local48 = ipaddress.IPv6Address("64:ff9b:1:a9fe:a9:fe00::")
        self.assertFalse(
            check_resolved_addresses(
                scoped(allowed_cidrs=["64:ff9b:1::/48"]),
                "fixture.invalid",
                [link_local48],
            ).allowed
        )
        self.assertTrue(
            check_resolved_addresses(
                scoped(allowed_cidrs=["64:ff9b:1::/48", "169.254.0.0/16"]),
                "fixture.invalid",
                [link_local48],
            ).allowed
        )
        for malformed in (
            ipaddress.IPv6Address("64:ff9b:1:a9fe:1a9:fe00::"),  # nonzero u octet
            ipaddress.IPv6Address("64:ff9b:1:a9fe:a9:fe01::"),  # nonzero suffix
        ):
            with self.subTest(malformed=malformed):
                self.assertFalse(
                    check_resolved_addresses(
                        admitted, "fixture.invalid", [malformed]
                    ).allowed
                )

    def test_dual_stack_cidr_order_never_raises_or_changes_result(self) -> None:
        dual = scoped(allowed_cidrs=["::/0", "10.0.0.0/8"])
        self.assertTrue(check_cidr(dual, "10.10.0.0/16").allowed)
        self.assertTrue(check_cidr(dual, "2001:db8::/32").allowed)

    def test_literals_require_cidr_even_when_hostname_wildcard_matches(self) -> None:
        wildcard = scoped(allowed_hosts=["*"], platform_hosts=["*"])
        self.assertFalse(check_url(wildcard, "http://8.8.8.8/").allowed)
        self.assertFalse(check_url(wildcard, "http://[::1]/").allowed)
        admitted = scoped(allowed_hosts=["*"], allowed_cidrs=["8.8.8.8/32"])
        self.assertTrue(check_url(admitted, "http://8.8.8.8/").allowed)

    def test_pure_pattern_normalization_keeps_one_legacy_trailing_dot(self) -> None:
        legacy = scoped(allowed_hosts=["*.Example.Test."])
        self.assertTrue(
            check_url(legacy, "https://direct.example.test/resource").allowed
        )
        self.assertFalse(
            check_url(legacy, "https://example.test/resource").allowed
        )

    def test_host_only_override_cannot_admit_a_literal(self) -> None:
        host_only = {
            "id": "host-only",
            "expires_at": "2099-01-01T00:00:00Z",
            "allowed_hosts": ["198.51.100.4"],
            "allowed_cidrs": [],
        }
        cidr_override = {**host_only, "allowed_hosts": [], "allowed_cidrs": ["198.51.100.4/32"]}
        self.assertFalse(
            check_url(
                scoped(),
                "https://198.51.100.4/",
                overrides=[host_only],
            ).allowed
        )
        self.assertTrue(
            check_url(
                scoped(),
                "https://198.51.100.4/",
                overrides=[cidr_override],
            ).allowed
        )

    def test_no_proxy_grammar_is_canonical_and_strict(self) -> None:
        rules = _no_proxy_rules(
            ".xn--bcher-kva.example:443,api.example.,[2001:db8::1]:8443,*"
        )
        self.assertTrue(rules[0].matches("api.xn--bcher-kva.example", 443))
        self.assertFalse(rules[0].matches("api.xn--bcher-kva.example", 80))
        self.assertTrue(rules[1].matches("api.example", 80))
        self.assertTrue(rules[2].matches("2001:db8::1", 8443))
        self.assertTrue(rules[3].matches("anything.invalid", 9))
        for invalid in (
            "10.0.0.0/8",
            "http://proxy.invalid",
            "user@proxy.invalid",
            "[2001:db8::1",
            "example.invalid/path",
            ",example.invalid",
        ):
            with self.subTest(invalid=invalid):
                with self.assertRaisesRegex(EnvironmentPolicyError, "NO_PROXY is invalid"):
                    _no_proxy_rules(invalid)


class PinnedConnectionTests(unittest.TestCase):
    def test_unverified_https_and_wss_contexts_fail_before_dns_or_socket(self) -> None:
        unverified = ssl._create_unverified_context()
        transport = ScopedHTTPTransport(scoped(), unverified)
        request = urllib.request.Request("https://fixture.invalid/resource")
        with mock.patch("socket.getaddrinfo") as resolver, mock.patch(
            "socket.socket"
        ) as socket_factory:
            with self.assertRaisesRegex(
                ScopedTransportError, "scoped_tls_context_invalid"
            ):
                transport.open(request, timeout=5)
            wss = ScopedConnectionPlan(
                "wss://fixture.invalid/cable",
                "wss",
                "fixture.invalid",
                443,
                (),
            )
            with self.assertRaisesRegex(
                ScopedTransportError, "scoped_tls_context_invalid"
            ):
                connect_scoped_stream(wss, timeout=5, tls_context=unverified)
        resolver.assert_not_called()
        socket_factory.assert_not_called()

    def test_plan_is_the_only_resolution_and_stream_uses_its_numeric_candidate(self) -> None:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        accepted: list[tuple[str, int]] = []

        def serve_once() -> None:
            peer, address = listener.accept()
            accepted.append((address[0], address[1]))
            peer.close()

        thread = threading.Thread(target=serve_once, daemon=True)
        thread.start()
        try:
            with mock.patch(
                "socket.getaddrinfo", return_value=[answer("127.0.0.1", port)]
            ) as resolver:
                plan = scoped_connection_plan(
                    scoped(allowed_ports=[port], allowed_cidrs=["127.0.0.1/32"]),
                    f"http://fixture.invalid:{port}/stream",
                )
                resolver.assert_called_once()
                stream = connect_scoped_stream(plan, timeout=5)
                stream.close()
        finally:
            listener.close()
            thread.join(timeout=2)
        self.assertEqual(len(plan.candidates), 1)
        self.assertEqual(plan.candidates[0].sockaddr, ("127.0.0.1", port))
        self.assertEqual(len(accepted), 1)

    def test_proxy_route_failure_precedes_resolver(self) -> None:
        class RejectingRoute:
            def route_for(self, _host: str, _port: int, _scheme: str) -> str:
                raise ScopedTransportError("scoped_proxy_target_pinning_unavailable")

        with mock.patch("socket.getaddrinfo") as resolver, self.assertRaisesRegex(
            ScopedTransportError, "scoped_proxy_target_pinning_unavailable"
        ):
            scoped_connection_plan(
                scoped(),
                "https://fixture.invalid/",
                route_policy=RejectingRoute(),
            )
        resolver.assert_not_called()

    def test_rebinding_cannot_trigger_a_second_resolution_and_host_is_preserved(self) -> None:
        received_hosts: list[str] = []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                received_hosts.append(self.headers.get("Host", ""))
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"pinned")

            def log_message(self, _format: str, *args: object) -> None:
                del args

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        calls = 0

        def resolver(host: str, port: int, *_args: object) -> list[tuple[object, ...]]:
            nonlocal calls
            calls += 1
            self.assertEqual(host, "fixture.invalid")
            self.assertEqual(port, server.server_port)
            if calls != 1:
                self.fail("connector attempted a second DNS resolution")
            return [answer("127.0.0.1", port)]

        try:
            with mock.patch("socket.getaddrinfo", side_effect=resolver):
                with open_scoped_url(
                    scoped(
                        allowed_ports=[server.server_port],
                        allowed_cidrs=["127.0.0.1/32"],
                    ),
                    f"http://fixture.invalid:{server.server_port}/pinned",
                ) as response:
                    self.assertEqual(response.read(), b"pinned")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

        self.assertEqual(calls, 1)
        self.assertEqual(received_hosts, [f"fixture.invalid:{server.server_port}"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
