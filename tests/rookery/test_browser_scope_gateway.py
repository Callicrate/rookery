from __future__ import annotations

import contextlib
import hashlib
import json
import os
import runpy
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest import mock

from tests.rookery.support import ROOKERY_ROOT


GATEWAY = ROOKERY_ROOT / "bin" / "browser-scope-gateway.py"


class _EchoHandler(socketserver.BaseRequestHandler):
    hits = 0
    payloads: list[bytes] = []

    def handle(self) -> None:
        type(self).hits += 1
        payload = self.request.recv(4096)
        type(self).payloads.append(payload)
        self.request.sendall(b"fixture:" + payload)


class _LoopbackEcho(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as stream:
        stream.bind(("127.0.0.1", 0))
        return int(stream.getsockname()[1])


class BrowserScopeGatewayTests(unittest.TestCase):
    def setUp(self) -> None:
        self.namespace = runpy.run_path(str(GATEWAY))
        self.gateway_globals = self.namespace["ScopeGateway"].handle_proxy.__globals__
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.proxy_port = _free_port()
        self.status_port = _free_port()
        while self.status_port == self.proxy_port:
            self.status_port = _free_port()
        self.gateway: Any | None = None
        self.proxy: Any | None = None
        self.status: Any | None = None
        self.threads: list[threading.Thread] = []
        self.destination: _LoopbackEcho | None = None
        self.destination_thread: threading.Thread | None = None

    def tearDown(self) -> None:
        self.stop_gateway()
        if self.destination is not None:
            self.destination.shutdown()
            self.destination.server_close()
        if self.destination_thread is not None:
            self.destination_thread.join(timeout=2)
        self.temporary.cleanup()

    def scope(
        self,
        *,
        expires_at: str | None = None,
        compiled_at: str = "first",
        hosts: list[str] | None = None,
    ) -> dict[str, Any]:
        platform_hosts = hosts or ["ctfd.fixture"]
        return {
            "schema_version": "2",
            "generation": 1,
            "compiled_at": compiled_at,
            "acknowledged": True,
            "allowed_hosts": platform_hosts,
            "allowed_cidrs": ["127.0.0.1/32"],
            "allowed_ports": [443],
            "allowed_protocols": ["https"],
            "allowed_file_origins": [],
            "platform_hosts": platform_hosts,
            "max_attachment_bytes": 0,
            "expires_at": expires_at or (datetime.now(UTC) + timedelta(minutes=5)).isoformat(),
        }

    def policy_document(
        self,
        *,
        scope: dict[str, Any] | None = None,
        origins: list[str] | None = None,
    ) -> dict[str, Any]:
        policy_scope = scope or self.scope()
        semantic = {key: value for key, value in policy_scope.items() if key != "compiled_at"}
        return {
            "schema_version": "1",
            "event_id": "gateway-fixture",
            "baseline_configuration_digest": "a" * 64,
            "scope_generation": 1,
            "scope_sha256": hashlib.sha256(
                json.dumps(semantic, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest(),
            "expires_at": policy_scope["expires_at"],
            "origins": origins or ["https://ctfd.fixture"],
            "scope": policy_scope,
        }

    def policy_path(self, document: dict[str, Any]) -> Path:
        path = self.root / "browser-gateway-policy.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        if os.name == "posix":
            path.chmod(0o600)
        return path

    def start_gateway(self, document: dict[str, Any] | None = None) -> None:
        policy = self.namespace["_load_policy"](self.policy_path(document or self.policy_document()))
        self.gateway = self.namespace["ScopeGateway"](policy, proxy_port=self.proxy_port, status_port=self.status_port)
        self.proxy, self.status = self.namespace["_servers"](self.gateway)
        for server, name in ((self.proxy, "proxy"), (self.status, "status")):
            thread = threading.Thread(target=server.serve_forever, name=name, daemon=True)
            thread.start()
            self.threads.append(thread)

    def stop_gateway(self) -> None:
        for server in (self.proxy, self.status):
            if server is not None:
                server.shutdown()
                server.server_close()
        for thread in self.threads:
            thread.join(timeout=2)
        self.threads.clear()
        self.proxy = None
        self.status = None

    def start_destination(self) -> None:
        _EchoHandler.hits = 0
        _EchoHandler.payloads = []
        self.destination = _LoopbackEcho(("127.0.0.1", 0), _EchoHandler)
        self.destination_thread = threading.Thread(target=self.destination.serve_forever, daemon=True)
        self.destination_thread.start()

    def recv_headers(self, stream: socket.socket) -> bytes:
        data = bytearray()
        while b"\r\n\r\n" not in data:
            chunk = stream.recv(4096)
            if not chunk:
                break
            data.extend(chunk)
        return bytes(data)

    def connect(self, request: bytes) -> socket.socket:
        stream = socket.create_connection(("127.0.0.1", self.proxy_port), timeout=3)
        stream.settimeout(3)
        stream.sendall(request)
        return stream

    @contextlib.contextmanager
    def resolved_fixture(self, *names: str):
        original = socket.getaddrinfo
        allowed_names = set(names or ("ctfd.fixture",))

        def resolver(host: str, port: int, *args: Any, **kwargs: Any) -> Any:
            if host in allowed_names:
                return [
                    (
                        socket.AF_INET,
                        socket.SOCK_STREAM,
                        socket.IPPROTO_TCP,
                        "",
                        ("127.0.0.1", port),
                    )
                ]
            return original(host, port, *args, **kwargs)

        with mock.patch("socket.getaddrinfo", side_effect=resolver):
            yield

    @contextlib.contextmanager
    def pinned_fixture_dial(self, expected_host: str = "ctfd.fixture"):
        assert self.destination is not None
        plans: list[Any] = []

        def dial(plan: Any, *, timeout: float) -> socket.socket:
            plans.append(plan)
            self.assertEqual(timeout, self.namespace["CONNECT_TIMEOUT_SECONDS"])
            self.assertEqual(plan.scheme, "tcp")
            self.assertEqual(plan.host, expected_host)
            self.assertEqual(plan.port, 443)
            self.assertEqual(len(plan.candidates), 1)
            self.assertEqual(str(plan.candidates[0].address), "127.0.0.1")
            self.assertEqual(plan.candidates[0].sockaddr, ("127.0.0.1", 443))
            return socket.create_connection(("127.0.0.1", self.destination.server_address[1]), timeout=timeout)

        with mock.patch.dict(self.gateway_globals, {"connect_scoped_stream": dial}):
            yield plans

    def test_allowed_connect_uses_one_scope_authorized_numeric_peer(self) -> None:
        self.start_destination()
        self.start_gateway()
        with self.resolved_fixture(), self.pinned_fixture_dial() as plans:
            stream = self.connect(b"CONNECT ctfd.fixture:443 HTTP/1.1\r\nHost: ctfd.fixture:443\r\n\r\n")
            try:
                self.assertEqual(self.recv_headers(stream), b"HTTP/1.1 200 Connection Established\r\n\r\n")
                stream.sendall(b"hello")
                self.assertEqual(stream.recv(64), b"fixture:hello")
            finally:
                stream.close()
        self.assertEqual(_EchoHandler.hits, 1)
        self.assertEqual(_EchoHandler.payloads, [b"hello"])
        self.assertEqual(len(plans), 1)
        self.assertEqual(self.gateway.counters.snapshot()["connected"], 1)

    def test_sealed_support_origin_connects_without_changing_the_main_origin(self) -> None:
        support = "support.fixture"
        scope = self.scope(hosts=["ctfd.fixture", support])
        policy = self.policy_document(
            scope=scope,
            origins=["https://ctfd.fixture", f"https://{support}"],
        )
        sealed = self.namespace["_load_policy"](self.policy_path(policy))
        self.assertEqual(sealed.origin, "https://ctfd.fixture")
        self.assertEqual(sealed.host, "ctfd.fixture")
        self.assertEqual(sealed.origins, ("https://ctfd.fixture", f"https://{support}"))
        self.assertEqual(sealed.hosts, frozenset({"ctfd.fixture", support}))

        self.start_destination()
        self.start_gateway(policy)
        with self.resolved_fixture(support), self.pinned_fixture_dial(support) as plans:
            stream = self.connect(f"CONNECT {support}:443 HTTP/1.1\r\nHost: {support}:443\r\n\r\n".encode("ascii"))
            try:
                self.assertEqual(self.recv_headers(stream), b"HTTP/1.1 200 Connection Established\r\n\r\n")
                stream.sendall(b"support")
                self.assertEqual(stream.recv(64), b"fixture:support")
            finally:
                stream.close()
        self.assertEqual(len(plans), 1)

    def test_duplicate_or_excess_origins_are_rejected_before_listeners_start(self) -> None:
        duplicate = self.policy_document(origins=["https://ctfd.fixture", "https://CTFD.fixture/"])
        with self.assertRaisesRegex(RuntimeError, "browser_gateway_policy_invalid"):
            self.namespace["_load_policy"](self.policy_path(duplicate))

        noncanonical_support = self.policy_document(
            scope=self.scope(hosts=["ctfd.fixture", "support.fixture"]),
            origins=["https://ctfd.fixture", "https://support.fixture/"],
        )
        with self.assertRaisesRegex(RuntimeError, "browser_gateway_policy_invalid"):
            self.namespace["_load_policy"](self.policy_path(noncanonical_support))

        hosts = ["ctfd.fixture", *(f"support{index}.fixture" for index in range(9))]
        excessive = self.policy_document(
            scope=self.scope(hosts=hosts),
            origins=[f"https://{host}" for host in hosts],
        )
        with self.assertRaisesRegex(RuntimeError, "browser_gateway_policy_invalid"):
            self.namespace["_load_policy"](self.policy_path(excessive))

    def test_support_origin_outside_platform_scope_is_rejected_before_listeners_start(self) -> None:
        policy = self.policy_document(origins=["https://ctfd.fixture", "https://offscope.fixture"])
        with self.assertRaisesRegex(RuntimeError, "browser_gateway_policy_scope_denied"):
            self.namespace["_load_policy"](self.policy_path(policy))

    def test_mixed_dns_answer_set_is_refused_before_a_numeric_dial(self) -> None:
        self.start_destination()
        self.start_gateway()
        original = socket.getaddrinfo
        connector = mock.Mock()

        def resolver(host: str, port: int, *args: Any, **kwargs: Any) -> Any:
            if host == "ctfd.fixture":
                return [
                    (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.1", port)),
                    (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.2", port)),
                ]
            return original(host, port, *args, **kwargs)

        with (
            mock.patch("socket.getaddrinfo", side_effect=resolver),
            mock.patch.dict(self.gateway_globals, {"connect_scoped_stream": connector}),
        ):
            stream = self.connect(b"CONNECT ctfd.fixture:443 HTTP/1.1\r\nHost: ctfd.fixture:443\r\n\r\n")
            try:
                self.assertEqual(stream.recv(1), b"")
            finally:
                stream.close()
        connector.assert_not_called()
        self.assertEqual(_EchoHandler.hits, 0)

    def test_offscope_destination_is_refused_without_a_second_connection(self) -> None:
        self.start_destination()
        self.start_gateway()
        before = _EchoHandler.hits
        stream = self.connect(b"CONNECT offscope.fixture:443 HTTP/1.1\r\nHost: offscope.fixture:443\r\n\r\n")
        try:
            self.assertEqual(stream.recv(1), b"")
        finally:
            stream.close()
        self.assertEqual(_EchoHandler.hits, before)
        self.assertGreaterEqual(self.gateway.counters.snapshot()["refused"], 1)

    def test_expired_policy_does_not_open_listeners(self) -> None:
        scope = self.scope(expires_at=(datetime.now(UTC) - timedelta(seconds=1)).isoformat())
        with self.assertRaisesRegex(RuntimeError, "browser_gateway_policy_expired"):
            self.namespace["_load_policy"](self.policy_path(self.policy_document(scope=scope)))
        with self.assertRaises(OSError):
            socket.create_connection(("127.0.0.1", self.proxy_port), timeout=0.2)

    def test_open_tunnel_stops_at_monotonic_policy_expiry(self) -> None:
        expiry = (datetime.now(UTC) + timedelta(seconds=1)).isoformat()
        policy = self.policy_document(scope=self.scope(expires_at=expiry))
        self.start_destination()
        self.start_gateway(policy)
        with self.resolved_fixture(), self.pinned_fixture_dial() as plans:
            stream = self.connect(b"CONNECT ctfd.fixture:443 HTTP/1.1\r\nHost: ctfd.fixture:443\r\n\r\n")
            try:
                self.assertEqual(self.recv_headers(stream), b"HTTP/1.1 200 Connection Established\r\n\r\n")
                deadline = time.monotonic() + 3
                while time.monotonic() < deadline and not self.gateway.expired():
                    time.sleep(0.01)
                self.assertTrue(self.gateway.expired())
                with contextlib.suppress(ConnectionResetError, OSError):
                    stream.sendall(b"late-after-expiry")
                    self.assertEqual(stream.recv(1), b"")

                new_connection = self.connect(b"CONNECT ctfd.fixture:443 HTTP/1.1\r\nHost: ctfd.fixture:443\r\n\r\n")
                try:
                    with contextlib.suppress(ConnectionAbortedError, ConnectionResetError):
                        self.assertEqual(new_connection.recv(1), b"")
                finally:
                    new_connection.close()
            finally:
                stream.close()
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline and not _EchoHandler.payloads:
            time.sleep(0.01)
        self.assertEqual(len(plans), 1)
        self.assertEqual(_EchoHandler.payloads, [b""])

    def test_gateway_expiry_uses_the_monotonic_deadline_after_startup(self) -> None:
        expiry = (datetime.now(UTC) + timedelta(minutes=1)).isoformat()
        policy = self.namespace["_load_policy"](
            self.policy_path(self.policy_document(scope=self.scope(expires_at=expiry)))
        )
        gateway = self.namespace["ScopeGateway"](policy, proxy_port=self.proxy_port, status_port=self.status_port)
        with mock.patch.object(self.gateway_globals["time"], "time", return_value=policy.expires_timestamp + 3600):
            self.assertFalse(gateway.expired())

    def test_oversized_and_malformed_requests_do_not_reach_destination(self) -> None:
        self.start_destination()
        self.start_gateway()
        malformed = self.connect(b"GET https://ctfd.fixture/ HTTP/1.1\r\nHost: ctfd.fixture\r\n\r\n")
        try:
            self.assertEqual(malformed.recv(1), b"")
        finally:
            malformed.close()
        oversized = self.connect(b"CONNECT ctfd.fixture:443 HTTP/1.1\r\nHost: ctfd.fixture:443\r\nX: " + b"x" * 9000)
        try:
            with contextlib.suppress(ConnectionResetError):
                self.assertEqual(oversized.recv(1), b"")
        finally:
            oversized.close()
        self.assertEqual(_EchoHandler.hits, 0)

    def test_gateway_down_never_becomes_a_direct_fixture_connection(self) -> None:
        self.start_destination()
        with self.assertRaises(OSError):
            socket.create_connection(("127.0.0.1", self.proxy_port), timeout=0.2)
        self.assertEqual(_EchoHandler.hits, 0)

    def test_status_and_failures_expose_no_event_or_request_secret(self) -> None:
        policy = self.policy_document()
        self.start_gateway(policy)
        secret = "dont-log-this-cookie"
        stream = self.connect(
            b"CONNECT ctfd.fixture:443 HTTP/1.1\r\nHost: ctfd.fixture:443\r\n"
            + f"Proxy-Authorization: {secret}\r\n\r\n".encode("ascii")
        )
        try:
            self.assertEqual(stream.recv(1), b"")
        finally:
            stream.close()
        with socket.create_connection(("127.0.0.1", self.status_port), timeout=3) as status:
            status.settimeout(3)
            status.sendall(f"GET /status HTTP/1.1\r\nHost: 127.0.0.1:{self.status_port}\r\n\r\n".encode("ascii"))
            response = self.recv_headers(status)
        body = response.split(b"\r\n\r\n", 1)[1]
        document = json.loads(body.decode("utf-8"))
        serialized = json.dumps(document)
        self.assertNotIn(secret, serialized)
        self.assertNotIn("gateway-fixture", serialized)
        self.assertNotIn("ctfd.fixture", serialized)
        self.assertEqual(document["listeners"]["proxy"], f"127.0.0.1:{self.proxy_port}")
        self.assertEqual(
            document["policy_sha256"],
            self.gateway_globals["policy_sha256"](policy),
        )

    def test_status_accepts_a_split_header_without_accepting_a_body(self) -> None:
        self.start_gateway()
        with socket.create_connection(("127.0.0.1", self.status_port), timeout=3) as status:
            status.settimeout(3)
            status.sendall(f"GET /status HTTP/1.1\r\nHost: 127.0.0.1:{self.status_port}\r\n".encode("ascii"))
            time.sleep(0.05)
            status.sendall(b"\r\n")
            self.assertIn(b"HTTP/1.1 200 OK", self.recv_headers(status))

    def test_proxy_admission_is_bounded_before_handler_threads_start(self) -> None:
        self.start_gateway()
        streams: list[socket.socket] = []
        try:
            for _ in range(self.namespace["MAX_CONNECTIONS"] + 4):
                stream = socket.create_connection(("127.0.0.1", self.proxy_port), timeout=2)
                stream.settimeout(2)
                stream.sendall(b"CONNECT ctfd.fixture:443 HTTP/1.1\r\n")
                streams.append(stream)
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline and self.proxy.active_requests < self.namespace["MAX_CONNECTIONS"]:
                time.sleep(0.01)
            self.assertEqual(self.proxy.active_requests, self.namespace["MAX_CONNECTIONS"])
            self.assertLessEqual(self.proxy.max_observed_requests, self.namespace["MAX_CONNECTIONS"])
            self.assertEqual(self.status.max_request_threads, 4)
        finally:
            for stream in streams:
                stream.close()

    def test_semantic_scope_digest_survives_a_fresh_compilation_timestamp(self) -> None:
        first = self.scope(compiled_at="first")
        second = self.scope(expires_at=first["expires_at"], compiled_at="second")
        first_document = self.policy_document(scope=first)
        second_document = self.policy_document(scope=second)
        self.assertEqual(first_document["scope_sha256"], second_document["scope_sha256"])
        self.assertEqual(
            self.gateway_globals["policy_sha256"](first_document),
            self.gateway_globals["policy_sha256"](second_document),
        )

    def test_isolated_entrypoint_starts_only_with_a_private_valid_policy(self) -> None:
        path = self.policy_path(self.policy_document())
        command = [
            sys.executable,
            "-I",
            "-S",
            "-B",
            str(GATEWAY),
            "--policy",
            str(path),
            "--proxy-port",
            str(self.proxy_port),
            "--status-port",
            str(self.status_port),
        ]
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                try:
                    with socket.create_connection(("127.0.0.1", self.status_port), timeout=0.2) as status:
                        status.sendall(
                            f"GET /status HTTP/1.1\r\nHost: 127.0.0.1:{self.status_port}\r\n\r\n".encode("ascii")
                        )
                        if b"200 OK" in self.recv_headers(status):
                            break
                except OSError:
                    time.sleep(0.05)
            else:
                self.fail(f"isolated gateway did not start: {process.stderr.read()}")
        finally:
            process.terminate()
            process.wait(timeout=5)
            assert process.stdout is not None
            assert process.stderr is not None
            process.stdout.close()
            process.stderr.close()

    def test_isolated_gateway_exits_and_releases_listeners_at_policy_expiry(self) -> None:
        expiry = (datetime.now(UTC) + timedelta(seconds=2)).isoformat()
        policy = self.policy_document(scope=self.scope(expires_at=expiry))
        path = self.policy_path(policy)
        command = [
            sys.executable,
            "-I",
            "-S",
            "-B",
            str(GATEWAY),
            "--policy",
            str(path),
            "--proxy-port",
            str(self.proxy_port),
            "--status-port",
            str(self.status_port),
        ]
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    self.fail(f"gateway exited before expiry: {process.stderr.read()}")
                try:
                    with socket.create_connection(("127.0.0.1", self.status_port), timeout=0.2) as status:
                        status.sendall(
                            f"GET /status HTTP/1.1\r\nHost: 127.0.0.1:{self.status_port}\r\n\r\n".encode("ascii")
                        )
                        if b"200 OK" in self.recv_headers(status):
                            break
                except OSError:
                    time.sleep(0.05)
            else:
                self.fail("isolated gateway did not start")
            self.assertEqual(process.wait(timeout=5), 0)
            with self.assertRaises(OSError):
                socket.create_connection(("127.0.0.1", self.proxy_port), timeout=0.2)
            with self.assertRaises(OSError):
                socket.create_connection(("127.0.0.1", self.status_port), timeout=0.2)
        finally:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=5)
            assert process.stdout is not None
            assert process.stderr is not None
            process.stdout.close()
            process.stderr.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
