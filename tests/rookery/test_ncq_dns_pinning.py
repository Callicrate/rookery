from __future__ import annotations

import ipaddress
import os
import runpy
import socket
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests.rookery.support import ROOKERY_ROOT

LIB = ROOKERY_ROOT / "lib"
if str(LIB) not in sys.path:
    sys.path.insert(0, str(LIB))

from rookery.portable.adapters import BoundedCommandResult  # noqa: E402
from rookery.portable.scope import CompiledScopeBinding  # noqa: E402


def _scope() -> dict[str, object]:
    return {
        "acknowledged": True,
        "generation": 3,
        "expires_at": "unknown",
        "allowed_hosts": ["fixture.invalid"],
        "allowed_cidrs": [],
        "allowed_ports": [31337],
        "allowed_protocols": ["tcp"],
        "allowed_file_origins": [],
        "platform_hosts": [],
        "max_attachment_bytes": 1024,
    }


def _answer(address: str, port: int) -> tuple[object, ...]:
    parsed = ipaddress.ip_address(address)
    if isinstance(parsed, ipaddress.IPv4Address):
        return (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (address, port))
    return (socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (address, port, 0, 0))


class _Environment:
    values = {"PATH": os.defpath}


class _RoutePolicy:
    def __init__(self, error: Exception | None = None) -> None:
        self.calls: list[tuple[str, int, str]] = []
        self.error = error

    def route_for(self, host: str, port: int, scheme: str) -> str:
        self.calls.append((host, port, scheme))
        if self.error is not None:
            raise self.error
        return "direct"


class NcqDnsPinningTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.module = runpy.run_path(str(ROOKERY_ROOT / "bin" / "ncq"), run_name=f"ncq_{id(self)}")
        self.globals = self.module["main"].__globals__
        self.globals["ROOT"] = self.root
        self.scope = _scope()
        self.binding = CompiledScopeBinding(
            scope=self.scope,
            scope_generation=3,
            stop_generation=0,
            file_sha256="a" * 64,
            content_sha256="b" * 64,
            launch_binding_sha256="c" * 64,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _patch_common(self, policy: _RoutePolicy, calls: list[list[str]]):
        def runq(argv: list[str], **_kwargs: object) -> BoundedCommandResult:
            calls.append(argv)
            return BoundedCommandResult(0, b"pinned-output", b"", "exited", {})

        return (
            mock.patch.dict(
                self.globals,
                {
                    "load_canonical_compiled_scope": lambda _root: self.binding,
                    "_network_policy": lambda _root, _scope: policy,
                    "minimal_child_environment": lambda _root, **_kwargs: _Environment(),
                    "run_bounded_argv": runq,
                },
            ),
            mock.patch.object(self.module["shutil"], "which", return_value="/usr/bin/ncat"),
        )

    def test_one_resolution_then_numeric_ipv4_argv_without_hostname(self) -> None:
        policy = _RoutePolicy()
        calls: list[list[str]] = []
        resolver_calls = 0

        def resolver(host: str, port: int, *_args: object) -> list[tuple[object, ...]]:
            nonlocal resolver_calls
            resolver_calls += 1
            self.assertEqual((host, port), ("fixture.invalid", 31337))
            if resolver_calls != 1:
                self.fail("ncq attempted a second DNS lookup")
            return [_answer("8.8.8.8", port), _answer("1.1.1.1", port)]

        patches = self._patch_common(policy, calls)
        with patches[0], patches[1], mock.patch(
            "rookery.portable.scoped_transport.socket.getaddrinfo", side_effect=resolver
        ):
            self.assertEqual(self.module["main"](["fixture.invalid", "31337"]), 0)

        self.assertEqual(resolver_calls, 1)
        self.assertEqual(policy.calls, [("fixture.invalid", 31337, "tcp")])
        self.assertEqual(
            calls,
            [[
                str(self.root / "bin" / "runq"), "-t", "20", "-l", "ncq", "-p",
                "--scope-generation", "3", "--stop-generation", "0",
                "--scope-file-sha256", "a" * 64,
                "--scope-content-sha256", "b" * 64,
                "--launch-binding-sha256", "c" * 64, "--",
                "/usr/bin/ncat", "-n", "-v", "-4", "1.1.1.1", "31337",
            ]],
        )
        self.assertNotIn("fixture.invalid", calls[0])

    def test_ipv6_uses_numeric_flag_and_bracketed_input_is_rejected(self) -> None:
        policy = _RoutePolicy()
        calls: list[list[str]] = []
        patches = self._patch_common(policy, calls)
        with patches[0], patches[1], mock.patch(
            "rookery.portable.scoped_transport.socket.getaddrinfo",
            return_value=[_answer("2001:4860:4860::8888", 31337)],
        ):
            self.assertEqual(self.module["main"](["fixture.invalid", "31337"]), 0)
            self.assertEqual(self.module["main"](["[::1]", "31337"]), 2)
        self.assertEqual(calls[0][-3:], ["-6", "2001:4860:4860::8888", "31337"])

    def test_proxy_route_denial_happens_before_dns_or_runq(self) -> None:
        policy = _RoutePolicy(RuntimeError("scoped_proxy_target_pinning_unavailable"))
        calls: list[list[str]] = []
        patches = self._patch_common(policy, calls)
        with patches[0], patches[1], mock.patch(
            "rookery.portable.scoped_transport.socket.getaddrinfo"
        ) as resolver:
            self.assertEqual(self.module["main"](["fixture.invalid", "31337"]), 2)
        self.assertEqual(policy.calls, [("fixture.invalid", 31337, "tcp")])
        resolver.assert_not_called()
        self.assertEqual(calls, [])

    def test_mixed_or_special_dns_answers_fail_before_runq(self) -> None:
        for answers in (
            [_answer("8.8.8.8", 31337), _answer("127.0.0.1", 31337)],
            [_answer("127.0.0.1", 31337)],
        ):
            with self.subTest(answers=answers):
                policy = _RoutePolicy()
                calls: list[list[str]] = []
                patches = self._patch_common(policy, calls)
                with patches[0], patches[1], mock.patch(
                    "rookery.portable.scoped_transport.socket.getaddrinfo", return_value=answers
                ):
                    self.assertEqual(self.module["main"](["fixture.invalid", "31337"]), 2)
                self.assertEqual(calls, [])

    def test_literal_send_is_bounded_and_never_interpreted_by_a_shell(self) -> None:
        policy = _RoutePolicy()
        calls: list[tuple[list[str], bytes]] = []
        patches = self._patch_common(policy, [])

        def send(argv: list[str], payload: bytes, _environment: object) -> int:
            calls.append((argv, payload))
            return 0

        with patches[0], patches[1], mock.patch.dict(
            self.globals, {"_run_with_send": send}
        ), mock.patch(
            "rookery.portable.scoped_transport.socket.getaddrinfo",
            return_value=[_answer("8.8.8.8", 31337)],
        ):
            self.assertEqual(
                self.module["main"](["fixture.invalid", "31337", "--send", "$(touch no)\\n"]),
                0,
            )
            self.assertEqual(
                self.module["main"](["fixture.invalid", "31337", "--send", "x" * (64 * 1024 + 1)]),
                2,
            )
        self.assertEqual(calls[0][1], b"$(touch no)\\n")
        self.assertNotIn("fixture.invalid", calls[0][0])

    def test_help_and_version_do_not_read_scope_or_launch_a_child(self) -> None:
        with mock.patch.dict(
            self.globals,
            {"load_canonical_compiled_scope": mock.Mock(side_effect=AssertionError("scope read"))},
        ):
            self.assertEqual(self.module["main"](["--help"]), 0)
            self.assertEqual(self.module["main"](["--version"]), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
