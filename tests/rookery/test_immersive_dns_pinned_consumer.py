from __future__ import annotations

from contextlib import nullcontext
import ipaddress
import json
import os
import runpy
import socket
import ssl
import sys
import tempfile
import threading
import types
import unittest
from pathlib import Path
from unittest import mock

from tests.rookery.support import (
    ROOKERY_ROOT,
    copy_non_deployed_rookery,
    install_test_launch_binding,
)
from tests.rookery.test_acceptance_campaign import make_deployed_workspace
from tests.rookery.env_fixtures import (
    configure_event_environment,
    replace_env_assignments,
)

LIB = ROOKERY_ROOT / "lib"
if str(LIB) not in sys.path:
    sys.path.insert(0, str(LIB))

# ruff: noqa: E402
from rookery.portable.scoped_transport import (
    ResolvedAddress,
    ScopedConnectionPlan,
    connect_scoped_stream,
)
from rookery.portable.environment import read_launch_binding
from rookery.portable.manifest import resolve_manifest
from rookery.portable.scope import CompiledScopeBinding, compile_scope
from rookery.portable.store import EventStore
from rookery.portable.util import file_lock


def scoped(*, port: int, cidrs: list[str] | None = None) -> dict[str, object]:
    return {
        "acknowledged": True,
        "generation": 1,
        "expires_at": "unknown",
        "allowed_hosts": ["fixture.invalid"],
        "allowed_cidrs": cidrs or [],
        "allowed_ports": [port],
        "allowed_protocols": ["http", "https", "ws", "wss"],
        "allowed_file_origins": [],
        "platform_hosts": ["fixture.invalid"],
        "max_attachment_bytes": 4096,
    }


def answer(port: int) -> tuple[object, ...]:
    return (
        socket.AF_INET,
        socket.SOCK_STREAM,
        socket.IPPROTO_TCP,
        "",
        ("127.0.0.1", port),
    )


def bound(scope: dict[str, object]) -> CompiledScopeBinding:
    return CompiledScopeBinding(
        scope=scope,
        scope_generation=int(scope["generation"]),
        stop_generation=0,
        file_sha256="a" * 64,
        content_sha256="b" * 64,
        launch_binding_sha256="c" * 64,
    )


@unittest.skipUnless(os.name == "posix", "requires the supported Linux/WSL runtime")
class ImmersivePinnedConsumerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.workspace = make_deployed_workspace("manual")
        self.root = Path(self.workspace.name)
        self.namespace = runpy.run_path(
            str(self.root / "adapters/immersive/bin/immersive-cluster-capture")
        )
        self.globals = self.namespace["main"].__globals__
        self.globals["ROOT"] = self.root
        self.globals["_verify_effect_binding"] = lambda binding: binding
        self.globals["_scope_effect"] = lambda binding: nullcontext(binding)

    def tearDown(self) -> None:
        self.workspace.cleanup()

    def invoke(self, url: str, outdir: Path, websocket: object, *extra: str) -> int:
        with (
            mock.patch.object(
                sys,
                "argv",
                [
                    "immersive-cluster-capture",
                    "--url",
                    url,
                    "--outdir",
                    str(outdir),
                    *extra,
                ],
            ),
            mock.patch.dict(sys.modules, {"websocket": websocket}),
        ):
            return self.namespace["main"]()

    def test_ws_consumer_resolves_once_then_passes_only_the_pinned_stream(self) -> None:
        port = 48123
        self.globals["scope_guard_url"] = lambda _url: bound(
            scoped(port=port, cidrs=["127.0.0.1/32"])
        )
        stream = mock.Mock()
        self.globals["connect_scoped_stream"] = mock.Mock(return_value=stream)

        class FakeWebSocket:
            def send(self, _message: str) -> None:
                return None

            def recv(self) -> str:
                return "event"

            def close(self) -> None:
                return None

        websocket = types.SimpleNamespace(
            create_connection=mock.Mock(return_value=FakeWebSocket())
        )
        resolver_calls = 0

        def resolver(host: str, requested_port: int, *_args: object):
            nonlocal resolver_calls
            resolver_calls += 1
            self.assertEqual((host, requested_port), ("fixture.invalid", port))
            if resolver_calls != 1:
                self.fail("Immersive consumer attempted a second DNS resolution")
            return [answer(port)]

        with mock.patch(
            "rookery.portable.scoped_transport.socket.getaddrinfo", side_effect=resolver
        ):
            result = self.invoke(
                f"ws://fixture.invalid:{port}/cable",
                self.root / "evidence/immersive/pinned-ws",
                websocket,
                "--max-messages",
                "1",
            )

        self.assertEqual(result, 5)
        self.assertEqual(resolver_calls, 1)
        kwargs = websocket.create_connection.call_args.kwargs
        self.assertIs(kwargs["socket"], stream)
        self.assertEqual(kwargs["redirect_limit"], 0)
        self.assertNotIn("http_proxy_host", kwargs)
        self.globals["connect_scoped_stream"].assert_called_once()

    def test_ws_and_wss_keep_the_core_stream_tls_boundary(self) -> None:
        candidate = ResolvedAddress(
            socket.AF_INET,
            ("127.0.0.1", 443),
            ipaddress.IPv4Address("127.0.0.1"),
        )
        ws_plan = ScopedConnectionPlan(
            "ws://fixture.invalid/cable", "ws", "fixture.invalid", 80, (candidate,)
        )
        wss_plan = ScopedConnectionPlan(
            "wss://fixture.invalid/cable", "wss", "fixture.invalid", 443, (candidate,)
        )
        raw_ws = mock.Mock()
        context = mock.Mock(check_hostname=True, verify_mode=ssl.CERT_REQUIRED)
        tls_stream = mock.Mock()
        context.wrap_socket.return_value = tls_stream
        with mock.patch(
            "rookery.portable.scoped_transport._connect_recorded", return_value=raw_ws
        ):
            self.assertIs(
                connect_scoped_stream(ws_plan, timeout=1, tls_context=context), raw_ws
            )
        context.wrap_socket.assert_not_called()

        raw_wss = mock.Mock()
        with mock.patch(
            "rookery.portable.scoped_transport._connect_recorded", return_value=raw_wss
        ):
            self.assertIs(
                connect_scoped_stream(wss_plan, timeout=1, tls_context=context),
                tls_stream,
            )
        context.wrap_socket.assert_called_once_with(
            raw_wss, server_hostname="fixture.invalid"
        )

    def test_special_answer_and_declared_proxy_fail_before_output_or_client(self) -> None:
        port = 48124
        self.globals["scope_guard_url"] = lambda _url: bound(scoped(port=port))
        websocket = types.SimpleNamespace(create_connection=mock.Mock())
        special_outdir = self.root / "evidence/immersive/special-address"
        with mock.patch(
            "rookery.portable.scoped_transport.socket.getaddrinfo",
            return_value=[answer(port)],
        ) as resolver:
            self.assertEqual(
                self.invoke(
                    f"ws://fixture.invalid:{port}/cable", special_outdir, websocket
                ),
                2,
            )
        resolver.assert_called_once()
        self.assertFalse(special_outdir.exists())
        websocket.create_connection.assert_not_called()

        proxy_outdir = self.root / "evidence/immersive/declared-proxy"
        proxy_route = mock.Mock(
            side_effect=RuntimeError("configured_proxy_route_rejected")
        )
        self.globals["resolve_network_policy"] = mock.Mock(
            return_value=types.SimpleNamespace(
                route_for=proxy_route,
                trust_context=ssl.create_default_context(),
            )
        )
        with mock.patch(
            "rookery.portable.scoped_transport.socket.getaddrinfo"
        ) as resolver:
            self.assertEqual(
                self.invoke(
                    f"wss://fixture.invalid:{port}/cable", proxy_outdir, websocket
                ),
                2,
            )
        resolver.assert_not_called()
        proxy_route.assert_called_once()
        self.assertFalse(proxy_outdir.exists())
        websocket.create_connection.assert_not_called()

    def test_binding_drift_blocks_before_output_dns_or_websocket(self) -> None:
        port = 48126
        self.globals["scope_guard_url"] = lambda _url: scoped(
            port=port, cidrs=["127.0.0.1/32"]
        )
        replace_env_assignments(
            self.root,
            {"IMMERSIVE_ORIGIN": "https://binding-drift.invalid"},
        )
        websocket = types.SimpleNamespace(create_connection=mock.Mock())
        outdir = self.root / "evidence/immersive/binding-drift"
        with mock.patch(
            "rookery.portable.scoped_transport.socket.getaddrinfo"
        ) as resolver:
            with self.assertRaisesRegex(SystemExit, "runtime_workspace_binding_invalid"):
                self.invoke(
                    f"ws://fixture.invalid:{port}/cable", outdir, websocket
                )
        resolver.assert_not_called()
        websocket.create_connection.assert_not_called()
        self.assertFalse(outdir.exists())


@unittest.skipUnless(os.name == "posix", "requires POSIX mutation-lock semantics")
class ImmersiveCanonicalAuthorityTests(unittest.TestCase):
    def _workspace(self) -> tempfile.TemporaryDirectory[str]:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        copy_non_deployed_rookery(root)
        configure_event_environment(
            root,
            "manual",
            name_suffix="Immersive Authority",
            extra={
                "EVENT_ID": "immersive-authority",
                "ALLOWED_HOSTS": "fixture.invalid",
                "ALLOWED_CIDRS": "127.0.0.1/32",
                "ALLOWED_PORTS": "31337",
                "ALLOWED_PROTOCOLS": "http,https,tcp,ws,wss",
                "ALLOWED_FILE_ORIGINS": "",
                "PLATFORM_HOSTS": "fixture.invalid",
                "SCOPE_MAX_BYTES": "4096",
            },
        )
        install_test_launch_binding(root)
        resolved = resolve_manifest(root)
        self.assertFalse(resolved.errors)
        state = root / "state"
        store = EventStore(root, launch_binding=read_launch_binding(root))
        store.set_meta("scope_generation", 1)
        store.set_meta("stop_generation", 0)
        (state / "resolved_event.json").write_text(
            json.dumps(resolved.manifest), encoding="utf-8"
        )
        (state / "scope.json").write_text(
            json.dumps(compile_scope(resolved.manifest, 1)), encoding="utf-8"
        )
        return temporary

    def _stop(self, root: Path) -> None:
        with file_lock(root / "state" / "mutation.lock"):
            store = EventStore(root, launch_binding=read_launch_binding(root))
            generation = store.current_stop_generation() + 1
            store.set_meta("stop_generation", generation)
            store.append(
                "control.stop",
                {"generation": generation, "reason": "Immersive authority regression"},
                actor="operator",
                generation=generation,
            )

    def _rotate_scope(self, root: Path) -> None:
        with file_lock(root / "state" / "mutation.lock"):
            store = EventStore(root, launch_binding=read_launch_binding(root))
            generation = int(store.get_meta("scope_generation", "1")) + 1
            store.set_meta("scope_generation", generation)
            manifest = json.loads(
                (root / "state" / "resolved_event.json").read_text(encoding="utf-8")
            )
            (root / "state" / "scope.json").write_text(
                json.dumps(compile_scope(manifest, generation)), encoding="utf-8"
            )

    def _namespace(self, root: Path, helper: str) -> dict[str, object]:
        namespace = runpy.run_path(
            str(ROOKERY_ROOT / "adapters/immersive/bin" / helper)
        )
        namespace["main"].__globals__["ROOT"] = root
        return namespace

    def test_real_stop_before_start_blocks_both_helpers_before_effects(self) -> None:
        temporary = self._workspace()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        self._stop(root)
        url = "ws://fixture.invalid:31337/cable"
        cluster_out = root / "evidence/immersive/stopped-cluster"
        cluster = self._namespace(root, "immersive-cluster-capture")
        cluster_globals = cluster["main"].__globals__
        cluster_globals["cookie_header_for_url"] = mock.Mock()
        websocket = types.SimpleNamespace(create_connection=mock.Mock())
        with (
            mock.patch.object(
                sys,
                "argv",
                [
                    "immersive-cluster-capture",
                    "--url",
                    url,
                    "--cookies",
                    str(root / "cookies.json"),
                    "--outdir",
                    str(cluster_out),
                ],
            ),
            mock.patch.dict(sys.modules, {"websocket": websocket}),
            mock.patch("rookery.portable.scoped_transport.socket.getaddrinfo") as dns,
        ):
            self.assertEqual(cluster["main"](), 4)
        dns.assert_not_called()
        cluster_globals["cookie_header_for_url"].assert_not_called()
        websocket.create_connection.assert_not_called()
        self.assertFalse(cluster_out.exists())

        refresh_out = root / "evidence/immersive/stopped-refresh"
        refresh = self._namespace(root, "immersive-selected-lab-refresh")
        refresh_globals = refresh["main"].__globals__
        refresh_globals["read_env"] = lambda: {
            "IMMERSIVE_GRAPHQL_URL": "http://fixture.invalid:31337/graphql",
            "IMMERSIVE_COOKIES_FILE": str(root / "cookies.json"),
        }
        refresh_globals["cookie_header_for_url"] = mock.Mock()
        refresh_globals["open_scoped"] = mock.Mock()
        with (
            mock.patch.object(
                sys,
                "argv",
                ["immersive-selected-lab-refresh", "--outdir", str(refresh_out)],
            ),
            mock.patch("rookery.portable.scoped_transport.socket.getaddrinfo") as dns,
        ):
            self.assertEqual(refresh["main"](), 4)
        dns.assert_not_called()
        refresh_globals["cookie_header_for_url"].assert_not_called()
        refresh_globals["open_scoped"].assert_not_called()
        self.assertFalse(refresh_out.exists())

    def test_cluster_stop_after_numeric_plan_blocks_output_cookie_and_socket(self) -> None:
        temporary = self._workspace()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        namespace = self._namespace(root, "immersive-cluster-capture")
        globals_ = namespace["main"].__globals__
        real_prepare = globals_["_prepare_capture_output"]
        globals_["cookie_header_for_url"] = mock.Mock(return_value="")
        globals_["connect_scoped_stream"] = mock.Mock()
        websocket = types.SimpleNamespace(create_connection=mock.Mock())
        outdir = root / "evidence/immersive/rotated-cluster"

        def stop_then_prepare(*args: object, **kwargs: object):
            self._stop(root)
            return real_prepare(*args, **kwargs)

        globals_["_prepare_capture_output"] = stop_then_prepare
        with (
            mock.patch.object(
                sys,
                "argv",
                [
                    "immersive-cluster-capture",
                    "--url",
                    "ws://fixture.invalid:31337/cable",
                    "--cookies",
                    str(root / "cookies.json"),
                    "--outdir",
                    str(outdir),
                ],
            ),
            mock.patch.dict(sys.modules, {"websocket": websocket}),
            mock.patch(
                "rookery.portable.scoped_transport.socket.getaddrinfo",
                return_value=[answer(31337)],
            ) as dns,
        ):
            self.assertEqual(namespace["main"](), 4)
        dns.assert_called_once()
        globals_["cookie_header_for_url"].assert_not_called()
        globals_["connect_scoped_stream"].assert_not_called()
        websocket.create_connection.assert_not_called()
        self.assertFalse(outdir.exists())

    def test_refresh_stop_in_custom_argv_spawn_gap_blocks_child(self) -> None:
        temporary = self._workspace()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        namespace = self._namespace(root, "immersive-selected-lab-refresh")
        globals_ = namespace["main"].__globals__
        outdir = root / "evidence/immersive/stopped-custom-refresh"
        marker = root / "custom-child-ran"
        command = [
            sys.executable,
            "-c",
            "from pathlib import Path; "
            f"Path({str(marker)!r}).write_text('spawned', encoding='utf-8')",
        ]
        globals_["read_env"] = lambda: {
            "IMMERSIVE_SELECTED_LAB_REFRESH_ARGV": json.dumps(command),
        }
        globals_["mutation_check"] = mock.Mock(return_value=True)
        real_verify = globals_["_verify_effect_binding"]
        spawn_gap = threading.Event()
        stop_committed = threading.Event()
        stop_errors: list[BaseException] = []

        def verify_with_spawn_gap(binding: object):
            current = real_verify(binding)
            spawn_gap.set()
            if not stop_committed.wait(timeout=5):
                raise AssertionError("operator stop did not commit in spawn gap")
            return current

        def stop_in_gap() -> None:
            try:
                if not spawn_gap.wait(timeout=5):
                    raise AssertionError("custom argv branch did not reach spawn gap")
                self._stop(root)
            except BaseException as exc:  # pragma: no cover - surfaced below
                stop_errors.append(exc)
            finally:
                stop_committed.set()

        globals_["_verify_effect_binding"] = verify_with_spawn_gap
        stopper = threading.Thread(target=stop_in_gap, daemon=True)
        stopper.start()
        with (
            mock.patch.object(
                sys,
                "argv",
                ["immersive-selected-lab-refresh", "--outdir", str(outdir)],
            ),
            mock.patch("rookery.portable.adapters.subprocess.Popen") as popen,
        ):
            self.assertEqual(namespace["main"](), 4)
        stopper.join(timeout=5)

        self.assertFalse(stopper.is_alive())
        self.assertEqual(stop_errors, [])
        popen.assert_not_called()
        self.assertFalse(marker.exists())
        self.assertFalse((outdir / "stdout.log").exists())
        self.assertFalse((outdir / "stderr.log").exists())

    def test_refresh_scope_rotation_after_cookie_plan_blocks_request_and_publication(
        self,
    ) -> None:
        temporary = self._workspace()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        namespace = self._namespace(root, "immersive-selected-lab-refresh")
        globals_ = namespace["main"].__globals__
        outdir = root / "evidence/immersive/rotated-refresh"
        globals_["read_env"] = lambda: {
            "IMMERSIVE_GRAPHQL_URL": "http://fixture.invalid:31337/graphql",
            "IMMERSIVE_COOKIES_FILE": str(root / "cookies.json"),
        }
        globals_["mutation_check"] = mock.Mock(return_value=True)
        globals_["open_scoped"] = mock.Mock()
        real_write = globals_["private_write_text"]

        def stop_before_request_publication(
            path: Path, text: str, *, errors: str = "strict"
        ) -> None:
            if path.name == "request.json":
                self._rotate_scope(root)
            real_write(path, text, errors=errors)

        globals_["cookie_header_for_url"] = mock.Mock(return_value="")
        globals_["private_write_text"] = stop_before_request_publication
        with (
            mock.patch.object(
                sys,
                "argv",
                ["immersive-selected-lab-refresh", "--outdir", str(outdir)],
            ),
            mock.patch("rookery.portable.scoped_transport.socket.getaddrinfo") as dns,
        ):
            self.assertEqual(namespace["main"](), 4)
        globals_["cookie_header_for_url"].assert_called_once()
        globals_["open_scoped"].assert_not_called()
        dns.assert_not_called()
        self.assertTrue(outdir.is_dir())
        self.assertFalse((outdir / "request.json").exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
