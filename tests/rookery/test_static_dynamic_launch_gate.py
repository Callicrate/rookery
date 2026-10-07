from __future__ import annotations

# ruff: noqa: E402

import ast
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

from tests.rookery.support import ROOKERY_ROOT

LIBRARY = ROOKERY_ROOT / "lib"
if str(LIBRARY) not in sys.path:
    sys.path.insert(0, str(LIBRARY))

from rookery.portable.validator import (  # noqa: E402
    _adapter_extension_python_shebang_errors,
    _child_environment_launch_errors,
    _core_bin_python_shebang_errors,
    _iter_shipped_python_sources,
    _validate_child_environment_launches,
)


def static_errors(source: str, relative: str = "bin/synthetic") -> list[str]:
    return _child_environment_launch_errors(ast.parse(textwrap.dedent(source)), relative)


def write_source(root: Path, relative: str, content: str) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(content).lstrip(), encoding="utf-8")


EXACT_CENTRAL_EXEC_REPLACEMENT = """
    import os
    from rookery.portable.environment import ChildEnvironment

    def codex_launcher_main(workspace, parent):
        child = codex_launcher_environment(workspace, parent=parent)
        binding = _verify_exec_binding(workspace, child, parent=parent)
        descriptor = _open_verified_codex_descriptor(binding)
        executable = f"/proc/self/fd/{descriptor}"
        final_arguments = [executable]
        os.execve(executable, final_arguments, dict(child.values))
"""


class StaticDynamicLaunchGateTests(unittest.TestCase):
    def test_dynamic_imports_reject_process_modules_and_unknown_authority(self) -> None:
        errors = static_errors(
            """
            import importlib as importer
            from builtins import __import__ as dynamic_import

            known_process_module = "sub" + "process"
            dynamic_import(known_process_module)
            importer.import_module("os.path")
            importer.import_module("p" + "ty")
            importer.import_module("multiprocessing")

            def unresolved(name):
                return importer.import_module(name)

            stale_proof = "hashlib"
            stale_proof = runtime_value()
            importer.import_module(stale_proof)
            """
        )
        self.assertEqual(
            sum("process-capable dynamic import is forbidden" in error for error in errors),
            4,
            errors,
        )
        self.assertEqual(
            sum("unresolved dynamic import is forbidden" in error for error in errors),
            2,
            errors,
        )

    def test_static_safe_import_and_inert_text_are_not_launch_findings(self) -> None:
        errors = static_errors(
            """
            import importlib

            helper = "hash" + "lib"
            imported = importlib.import_module(helper)
            description = "__import__('os'); os.system('not executed')"
            """
        )
        self.assertEqual(errors, [])

    def test_dynamic_lookup_and_extended_launch_apis_are_denied(self) -> None:
        errors = static_errors(
            """
            import asyncio as events
            import os as operating_system
            import pty as pseudo_terminal
            from os import execvp as replace_process

            def launch(name):
                getattr(operating_system, name)("tool")
                getattr(pseudo_terminal, name)("tool")
                getattr(events, name)("tool")
                operating_system.posix_spawn("tool", [], {})
                operating_system.posix_spawnp("tool", [], {})
                operating_system.spawnv(0, "tool", ["tool"])
                operating_system.system("tool")
                operating_system.popen("tool")
                replace_process("tool", ["tool"])
                pseudo_terminal.spawn(["tool"])

            async def async_launch():
                await events.create_subprocess_exec("tool")
            """
        )
        self.assertEqual(
            sum("computed process API lookup is forbidden" in error for error in errors),
            3,
            errors,
        )
        self.assertEqual(
            sum("unsafe os process API is forbidden" in error for error in errors),
            6,
            errors,
        )
        self.assertEqual(
            sum("unsafe pty process API is forbidden" in error for error in errors),
            1,
            errors,
        )
        self.assertTrue(any("ChildEnvironment.values" in error for error in errors), errors)
        self.assertTrue(
            any("asyncio subprocess launch is forbidden" in error for error in errors),
            errors,
        )

    def test_process_pools_callable_aliases_and_builtin_code_execution_are_denied(self) -> None:
        errors = static_errors(
            """
            import builtins
            import concurrent.futures as futures
            import functools as tools
            import multiprocessing as workers
            from builtins import eval as evaluate
            from multiprocessing import Process as Worker

            direct_alias = workers.Process
            context_alias = workers.get_context("spawn").Process

            def launch(name):
                workers.Process(target=print)
                Worker(target=print)
                direct_alias(target=print)
                context_alias(target=print)
                workers.Pool(1)
                workers.get_context("spawn").Pool(1)
                futures.ProcessPoolExecutor(max_workers=1)
                tools.partial(workers.Process, target=print)
                tools.partial(getattr(workers, name), target=print)
                getattr(workers, name)()
                evaluate("1 + 1")
                builtins.exec("value = 1")
                eval("1 + 1")
            """
        )
        self.assertEqual(
            sum("process-backed concurrency launch is forbidden" in error for error in errors),
            7,
            errors,
        )
        self.assertEqual(
            sum("unsafe functools callable alias is forbidden" in error for error in errors),
            2,
            errors,
        )
        self.assertEqual(
            sum("builtins code execution is forbidden" in error for error in errors),
            3,
            errors,
        )
        self.assertTrue(
            any("computed process API lookup is forbidden" in error for error in errors),
            errors,
        )

        safe = static_errors(
            """
            import concurrent.futures
            import functools

            description = "eval('not executed'); multiprocessing.Process()"
            worker = concurrent.futures.ThreadPoolExecutor(max_workers=1)
            upper = functools.partial(str.upper, "safe")
            """
        )
        self.assertEqual(safe, [])

    def test_direct_builtins_dictionary_lookup_is_not_a_callable_bypass(self) -> None:
        errors = static_errors(
            """
            import builtins

            builtins.__dict__["eval"]("1 + 1")
            builtins.__dict__["exec"]("value = 1")
            builtins.__dict__["__import__"]("os")
            """
        )
        self.assertEqual(
            sum("builtins code execution is forbidden" in error for error in errors),
            2,
            errors,
        )
        self.assertTrue(
            any("process-capable dynamic import is forbidden: os" in error for error in errors),
            errors,
        )

    def test_reflected_process_module_launches_cannot_bypass_child_environment_policy(self) -> None:
        errors = static_errors(
            """
            import builtins
            import operator
            import subprocess

            vars(subprocess)["run"](["tool"], env={})
            subprocess.__dict__["Popen"](["tool"], env=None)
            launch = vars(subprocess)["check_output"]
            launch(["tool"], env={})
            vars(subprocess).get("call")(["tool"], env={})
            subprocess.__dict__.get("check_call")(["tool"], env=None)
            get_launch = vars(subprocess).get
            get_launch("run")(["tool"], env={})
            operator.getitem(vars(subprocess), "check_output")(["tool"], env={})
            dict.get(vars(subprocess), "run")(["tool"], env={})
            dict.get(subprocess.__dict__, "Popen")(["tool"], env=None)
            get_from_dict = dict.get
            get_from_dict(vars(subprocess), "check_output")(["tool"], env={})
            member = runtime_value()
            vars(subprocess).get(member)(["tool"], env={})
            dict.get(vars(subprocess), member)(["tool"], env={})
            capabilities = vars(subprocess)
            capabilities.setdefault("run")(["tool"], env={})
            dict.setdefault(vars(subprocess), "Popen")(["tool"], env=None)
            set_default = capabilities.setdefault
            set_default("check_output")(["tool"], env={})
            dict_set_default = dict.setdefault
            dict_set_default(capabilities, "call")(["tool"], env={})
            capabilities.pop("run")(["tool"], env={})
            dict.values(capabilities)
            capabilities.items()
            getattr(vars(subprocess), "get")("run")(["tool"], env={})
            getattr(capabilities, "setdefault")("run")(["tool"], env={})
            access = getattr
            access(capabilities, runtime_value())("run")(["tool"], env={})
            access(capabilities, "pop")("run")(["tool"], env={})
            builtins.__dict__["getattr"](vars(subprocess), "get")("run")(
                ["tool"], env={}
            )
            vars(builtins).get("getattr")(capabilities, "setdefault")("run")(
                ["tool"], env={}
            )
            reflected_access = vars(builtins)["getattr"]
            reflected_access(capabilities, runtime_value())("run")(["tool"], env={})
            """
        )
        self.assertEqual(sum("child environment launch" in error for error in errors), 10, errors)
        self.assertTrue(any("computed module capability lookup" in error for error in errors), errors)
        self.assertGreaterEqual(
            sum("capability module dictionary operation" in error for error in errors),
            7,
            errors,
        )
        self.assertGreaterEqual(
            sum("capability module dictionary getattr" in error for error in errors),
            7,
            errors,
        )
        self.assertEqual(
            errors,
            sorted(errors),
            "findings must retain deterministic ordering",
        )

    def test_reflected_raw_network_callables_and_computed_members_are_denied(self) -> None:
        errors = static_errors(
            """
            import builtins
            import http.client
            import operator
            import socket
            import urllib.request
            import websocket

            vars(urllib.request)["urlopen"]("https://scoped.example/")
            socket.__dict__["getaddrinfo"]("scoped.example", 443)
            connect = vars(socket)["create_connection"]
            connect(("198.51.100.4", 443))
            websocket.__dict__["create_connection"]("wss://scoped.example/socket")
            vars(http.client)["HTTPConnection"]("scoped.example")
            vars(urllib.request).get("urlopen")("https://scoped.example/")
            socket.__dict__.get("getaddrinfo")("scoped.example", 443)
            get_connect = vars(socket).get
            get_connect("create_connection")(("198.51.100.4", 443))
            operator.getitem(websocket.__dict__, "create_connection")(
                "wss://scoped.example/socket"
            )
            vars(http.client).get("HTTPSConnection")("scoped.example")
            dict.get(vars(urllib.request), "urlopen")("https://scoped.example/")
            get_from_dict = dict.get
            get_from_dict(socket.__dict__, "getaddrinfo")("scoped.example", 443)
            dict.get(websocket.__dict__, "create_connection")(
                "wss://scoped.example/socket"
            )
            member = runtime_value()
            vars(socket).get(member)
            dict.get(vars(socket), member)
            network = vars(urllib.request)
            network.setdefault("urlopen")("https://scoped.example/")
            dict.setdefault(vars(socket), "create_connection")(("198.51.100.4", 443))
            pop_network = network.pop
            pop_network("urlopen")("https://scoped.example/")
            dict.values(network)
            vars(socket).items()
            getattr(network, "get")("urlopen")("https://scoped.example/")
            access = getattr
            access(vars(socket), "setdefault")("create_connection")(
                ("198.51.100.4", 443)
            )
            access(network, runtime_value())("urlopen")("https://scoped.example/")
            builtins.__dict__["getattr"](network, "get")("urlopen")(
                "https://scoped.example/"
            )
            reflected_access = vars(builtins).get("getattr")
            reflected_access(vars(socket), "setdefault")("create_connection")(
                ("198.51.100.4", 443)
            )
            """
        )
        self.assertTrue(any("raw urllib transfer" in error for error in errors), errors)
        self.assertTrue(any("raw socket DNS lookup" in error for error in errors), errors)
        self.assertTrue(any("unpinned socket connection" in error for error in errors), errors)
        self.assertTrue(any("unpinned websocket connection" in error for error in errors), errors)
        self.assertTrue(any("raw HTTP client" in error for error in errors), errors)
        self.assertTrue(any("computed module capability lookup" in error for error in errors), errors)
        self.assertGreaterEqual(
            sum("capability module dictionary operation" in error for error in errors),
            5,
            errors,
        )
        self.assertGreaterEqual(
            sum("capability module dictionary getattr" in error for error in errors),
            5,
            errors,
        )

        self.assertEqual(
            static_errors(
                """
                import builtins

                callbacks = {"run": lambda arguments: arguments}
                callback = callbacks["run"]
                callback(["safe"])
                callback = callbacks.get("run")
                callback(["safe"])
                get_callback = callbacks.get
                get_callback("run")(["safe"])
                callback = dict.get(callbacks, "run")
                callback(["safe"])
                get_from_dict = dict.get
                get_from_dict(callbacks, "run")(["safe"])
                callbacks.setdefault("fallback", lambda arguments: arguments)
                dict.setdefault(callbacks, "second", lambda arguments: arguments)
                callbacks.pop("missing", None)
                dict.values(callbacks)
                callbacks.items()
                getattr(callbacks, "get")("run")(["safe"])
                access = getattr
                access(callbacks, "setdefault")("third", lambda arguments: arguments)
                builtins.__dict__["getattr"](callbacks, "get")("run")(["safe"])
                reflected_access = vars(builtins).get("getattr")
                reflected_access(callbacks, "setdefault")(
                    "fourth", lambda arguments: arguments
                )
                record = {"name": "safe"}
                value = record["name"]
                """
            ),
            [],
        )

    def test_direct_operator_callable_aliases_cannot_reach_known_launch_modules(self) -> None:
        errors = static_errors(
            """
            import builtins
            import multiprocessing as workers
            import operator
            import os

            operator.attrgetter("system")(os)
            operator.methodcaller("exec", "value = 1")(builtins)
            operator.attrgetter("Process")(workers)(target=print)
            """
        )
        self.assertEqual(
            sum("unsafe operator callable alias is forbidden" in error for error in errors),
            3,
            errors,
        )
        self.assertEqual(
            static_errors(
                """
                import operator

                record = {"name": "safe"}
                value = operator.attrgetter("name")(type("Item", (), record))
                """
            ),
            [],
        )

    def test_dns_pinned_transport_is_the_only_raw_client_network_owner(self) -> None:
        untrusted_errors = static_errors(
            """
            import socket as networking
            import subprocess
            import urllib.request as request
            from websocket import create_connection as websocket_connect
            from rookery.portable.adapters import run_bounded_argv
            from rookery.portable.environment import ChildEnvironment

            def connect(environment: ChildEnvironment):
                client = networking.socket()
                client.connect(("198.51.100.4", 443))
                networking.create_connection(("198.51.100.4", 443))
                networking.getaddrinfo("scoped.example", 443)
                request.urlopen("https://scoped.example/")
                opener = request.build_opener()
                opener.open("https://scoped.example/")
                websocket_connect("wss://scoped.example/socket")
                subprocess.run(["nc", "scoped.example", "443"], env=environment.values)
                run_bounded_argv(["ncat", "scoped.example", "443"], env=environment)
            """
        )
        self.assertTrue(
            any("raw socket DNS lookup" in error for error in untrusted_errors),
            untrusted_errors,
        )
        self.assertEqual(
            sum("unpinned socket connection" in error for error in untrusted_errors),
            2,
            untrusted_errors,
        )
        self.assertEqual(
            sum("generic urllib opener" in error for error in untrusted_errors),
            2,
            untrusted_errors,
        )
        self.assertTrue(
            any("raw urllib transfer" in error for error in untrusted_errors),
            untrusted_errors,
        )
        self.assertTrue(
            any("unpinned websocket connection" in error for error in untrusted_errors),
            untrusted_errors,
        )
        self.assertEqual(
            sum("raw netcat helper" in error for error in untrusted_errors),
            2,
            untrusted_errors,
        )

        trusted_errors = static_errors(
            """
            import socket
            import urllib.request

            def transport_owner():
                socket.getaddrinfo("scoped.example", 443)
                stream = socket.socket()
                stream.connect(("198.51.100.4", 443))
                urllib.request.urlopen("https://scoped.example/")
                opener = urllib.request.build_opener()
                opener.open("https://scoped.example/")
            """,
            "lib/rookery/portable/scoped_transport.py",
        )
        self.assertEqual(trusted_errors, [])

        pinned_websocket_errors = static_errors(
            """
            import websocket
            from rookery.portable.scoped_transport import connect_scoped_stream

            def connect(plan, tls_context):
                stream = connect_scoped_stream(plan, timeout=5, tls_context=tls_context)
                return websocket.create_connection(
                    "wss://scoped.example/socket", socket=stream, timeout=5
                )
            """,
            "adapters/fixture/bin/pinned-websocket",
        )
        self.assertEqual(pinned_websocket_errors, [])

    def test_extended_raw_network_matrix_rejects_nine_direct_escape_shapes(self) -> None:
        errors = static_errors(
            """
            import functools
            import http.client
            import socket
            import urllib.request

            def escape():
                client = http.client.HTTPConnection("scoped.example")
                client.request("GET", "/")
                http.client.HTTPSConnection("scoped.example").connect()
                stream = socket.socket()
                stream.connect_ex(("198.51.100.4", 443))
                socket.socket().connect_ex(("198.51.100.4", 443))
                stream.sendto(b"x", ("198.51.100.4", 443))
                socket.gethostbyname("scoped.example")
                urllib.request.urlretrieve("https://scoped.example/", "out")
                vars(urllib.request)["urlopen"]("https://scoped.example/")
                getattr(socket.socket(), "connect")(("198.51.100.4", 443))
                functools.partial(socket.create_connection, ("198.51.100.4", 443))
                escaped = socket.create_connection
                return escaped
            """
        )
        self.assertTrue(any("raw HTTP client" in error for error in errors), errors)
        self.assertGreaterEqual(sum("unpinned socket connection" in error for error in errors), 2, errors)
        self.assertTrue(any("raw socket datagram send" in error for error in errors), errors)
        self.assertTrue(any("raw socket DNS lookup" in error for error in errors), errors)
        self.assertTrue(any("urlretrieve" in error for error in errors), errors)
        self.assertTrue(any("urlopen" in error for error in errors), errors)
        self.assertTrue(any("unsafe functools callable alias" in error for error in errors), errors)
        self.assertGreaterEqual(
            sum("raw network callable reference" in error for error in errors),
            2,
            errors,
        )

        trusted = static_errors(
            """
            import http.client
            import socket

            def transport_owner():
                socket.gethostbyname("scoped.example")
                stream = socket.socket()
                stream.connect_ex(("198.51.100.4", 443))
                client = http.client.HTTPConnection("scoped.example")
                client.request("GET", "/")
            """,
            "lib/rookery/portable/scoped_transport.py",
        )
        self.assertEqual(trusted, [])

    def test_with_bound_socket_preserves_raw_client_identity(self) -> None:
        errors = static_errors(
            """
            import socket

            def connect():
                with socket.socket() as stream:
                    stream.connect(("198.51.100.4", 443))
            """
        )
        self.assertTrue(any("unpinned socket connection" in error for error in errors), errors)
        self.assertEqual(
            static_errors(
                """
                import socket

                def transport_owner():
                    with socket.socket() as stream:
                        stream.connect(("198.51.100.4", 443))
                """,
                "lib/rookery/portable/scoped_transport.py",
            ),
            [],
        )

    def test_listener_and_current_dns_security_modules_remain_visible_to_the_gate(self) -> None:
        listener_errors = static_errors(
            """
            import socket

            def _free_port():
                listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                listener.bind(("127.0.0.1", 0))
                listener.listen(1)
                return listener
            """
        )
        self.assertEqual(listener_errors, [])

        discovery_errors: list[str] = []
        discovered = {relative for relative, _raw in _iter_shipped_python_sources(ROOKERY_ROOT, discovery_errors)}
        self.assertEqual(discovery_errors, [])
        self.assertTrue(
            {
                "lib/rookery/portable/scoped_transport.py",
                "lib/rookery/portable/network_policy.py",
                "lib/rookery/portable/cookie_output.py",
                "lib/rookery/portable/telemetry_compare.py",
            }.issubset(discovered),
            discovered,
        )

    def test_compiled_scope_reads_are_centralized_at_the_loader_boundary(self) -> None:
        consumer_errors = static_errors(
            """
            import json
            from rookery.portable.util import load_json

            def consume(root):
                path = root / "state" / "scope.json"
                first = json.loads(path.read_text())
                second = load_json(root / "state/scope.json", {})
                return first, second
            """,
            "bin/untrusted-scope-reader",
        )
        self.assertEqual(
            sum("direct state/scope.json read" in error for error in consumer_errors),
            2,
            consumer_errors,
        )

        canonical_consumer = static_errors(
            """
            from rookery.portable.scope import load_canonical_compiled_scope

            def consume(root):
                return load_canonical_compiled_scope(root)
            """,
            "bin/canonical-scope-reader",
        )
        self.assertEqual(canonical_consumer, [])

        self.assertEqual(
            static_errors(
                """
                from rookery.portable.util import load_json

                def publish(root):
                    return load_json(root / "state" / "scope.json", {})
                """,
                "lib/rookery/portable/cli.py",
            ),
            [],
        )
        self.assertEqual(
            static_errors(
                """
                def load(root):
                    return (root / "state" / "scope.json").read_bytes()
                """,
                "lib/rookery/portable/scope.py",
            ),
            [],
        )

    def test_only_exact_verified_codex_exec_replacement_is_allowed(self) -> None:
        self.assertEqual(
            static_errors(
                EXACT_CENTRAL_EXEC_REPLACEMENT,
                "lib/rookery/portable/environment.py",
            ),
            [],
        )

        altered_executable = EXACT_CENTRAL_EXEC_REPLACEMENT.replace(
            'f"/proc/self/fd/{descriptor}"', '"/tmp/not-verified"'
        )
        self.assertTrue(
            any(
                "unsafe os process API is forbidden" in error
                for error in static_errors(altered_executable, "lib/rookery/portable/environment.py")
            )
        )

        ambient_environment = EXACT_CENTRAL_EXEC_REPLACEMENT.replace("dict(child.values)", "dict(os.environ)")
        near_miss_errors = static_errors(ambient_environment, "lib/rookery/portable/environment.py")
        self.assertTrue(
            any("unsafe os process API is forbidden" in error for error in near_miss_errors),
            near_miss_errors,
        )

        wrong_owner_errors = static_errors(
            EXACT_CENTRAL_EXEC_REPLACEMENT.replace("def codex_launcher_main", "def unverified_exec"),
            "lib/rookery/portable/environment.py",
        )
        self.assertTrue(
            any("unsafe os process API is forbidden" in error for error in wrong_owner_errors),
            wrong_owner_errors,
        )

        aliased_exec_errors = static_errors(
            EXACT_CENTRAL_EXEC_REPLACEMENT.replace("os.execve(", 'getattr(os, "execve")('),
            "lib/rookery/portable/environment.py",
        )
        self.assertTrue(
            any("unsafe os process API is forbidden" in error for error in aliased_exec_errors),
            aliased_exec_errors,
        )

    def test_unlisted_pypy_helpers_are_discovered_and_cannot_claim_cpython_contract(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            write_source(
                root,
                "bin/unlisted-pypy-helper",
                """
                #!/usr/bin/env -S PyPy3 -I -B
                from rookery.portable.environment import ChildEnvironment
                import os
                os.system("tool")
                """,
            )
            write_source(
                root,
                "extensions/fixture/bin/pypy-rookery-helper",
                """
                #!/usr/bin/env pypy3
                from rookery.portable.environment import ChildEnvironment
                """,
            )
            write_source(
                root,
                "bin/inert-shell-helper",
                """
                #!/usr/bin/env bash
                printf '%s\\n' '__import__("os")'
                """,
            )

            discovery_errors: list[str] = []
            discovered = [relative for relative, _raw in _iter_shipped_python_sources(root, discovery_errors)]
            self.assertEqual(discovery_errors, [])
            self.assertEqual(
                discovered,
                [
                    "bin/unlisted-pypy-helper",
                    "extensions/fixture/bin/pypy-rookery-helper",
                ],
            )

            static_errors_found: list[str] = []
            _validate_child_environment_launches(root, static_errors_found)
            self.assertTrue(
                any(
                    "unsafe os process API is forbidden: bin/unlisted-pypy-helper" in error
                    for error in static_errors_found
                ),
                static_errors_found,
            )
            self.assertTrue(
                _core_bin_python_shebang_errors(
                    "bin/unlisted-pypy-helper",
                    (root / "bin/unlisted-pypy-helper").read_bytes(),
                )
            )
            self.assertTrue(
                _adapter_extension_python_shebang_errors(
                    "extensions/fixture/bin/pypy-rookery-helper",
                    (root / "extensions/fixture/bin/pypy-rookery-helper").read_bytes(),
                )
            )


if __name__ == "__main__":  # pragma: no cover
    unittest.main(verbosity=2)
