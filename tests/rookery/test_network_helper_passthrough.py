from __future__ import annotations

import os
import runpy
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

from tests.rookery.test_preparation_and_isolation import copy_rookery
from tests.rookery.test_acceptance_campaign import make_deployed_workspace
from tests.rookery.env_fixtures import replace_env_assignments
from rookery.portable import preparation as preparation_module
from rookery.portable import scope as scope_module
from rookery.portable.scoped_transport import ScopedHTTPTransport
from rookery.portable.scope import (
    CompiledScopeBinding,
    ScopeAuthorityError,
    load_canonical_compiled_scope,
)


def _scope(
    *,
    ports: list[int],
    hosts: list[str] | None = None,
    cidrs: list[str] | None = None,
    origins: list[str] | None = None,
) -> dict[str, object]:
    return {
        "acknowledged": True,
        "generation": 1,
        "expires_at": "unknown",
        "allowed_hosts": hosts or [],
        "allowed_cidrs": cidrs or [],
        "allowed_ports": ports,
        "allowed_protocols": ["http", "https"],
        "allowed_file_origins": origins or [],
        "platform_hosts": [],
        "max_attachment_bytes": 1024 * 1024,
    }


@unittest.skipUnless(os.name == "posix", "requires POSIX private output modes")
class RangeSweepArgumentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = None
        self.external_temporary = tempfile.TemporaryDirectory()
        self._write_scope()

    def tearDown(self) -> None:
        if self.fixture is not None:
            self.fixture.cleanup()
        self.external_temporary.cleanup()

    def _write_helper(self, name: str, body: str) -> None:
        path = self.root / "bin" / name
        path.write_text(
            "#!/usr/bin/env bash\n"
            "set -euo pipefail\n"
            "ROOT=$(cd \"$(dirname \"$0\")/..\" && pwd)\n"
            + body,
            encoding="utf-8",
        )
        path.chmod(0o755)

    @staticmethod
    def _successful_runq_body() -> str:
        return (
            "capture=\"$ROOT/logs/commands/range-$$\"\n"
            "mkdir -p \"$capture\"\n"
            "printf '%s\\n' \"$@\" > \"$capture/argv.txt\"\n"
            "printf 'fixture nmap output\\n' > \"$capture/stdout.log\"\n"
            "bytes=$(wc -c < \"$capture/stdout.log\" | tr -d ' ')\n"
            "digest=$(sha256sum \"$capture/stdout.log\" | awk '{print $1}')\n"
            "printf '{\\\"stdout_path\\\":\\\"logs/commands/range-%s/stdout.log\\\",\\\"stdout_bytes\\\":%s,\\\"stdout_sha256\\\":\\\"%s\\\"}\\n' \"$$\" \"$bytes\" \"$digest\"\n"
        )

    def _run(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(self.root / "bin" / "range-sweep"), *arguments],
            cwd=self.root,
            env=self.fixture.bootstrap.environment,
            text=True,
            capture_output=True,
            timeout=20,
            check=False,
        )

    def _runq_argv_captures(self) -> list[Path]:
        return list((self.root / "logs" / "commands").glob("range-*/argv.txt"))

    def _write_scope(
        self,
        *,
        ports: list[int] | None = None,
        protocols: list[str] | None = None,
    ) -> None:
        declared_scope = {
            "acknowledged": True,
            "allowed_hosts": [],
            "allowed_cidrs": ["10.10.0.0/16"],
            "allowed_ports": ports if ports is not None else [22, 443],
            "allowed_protocols": protocols if protocols is not None else ["tcp"],
            "allowed_file_origins": [],
            "platform_hosts": [],
            "max_attachment_bytes": 1024,
            "expires_at": "unknown",
        }
        if self.fixture is not None:
            self.fixture.cleanup()

        def prepare(root: Path) -> None:
            replace_env_assignments(
                root,
                {
                    "EVENT_ID": "range-fixture",
                    "EVENT_NAME": "Range fixture",
                    "EVENT_URL": "https://fixture.invalid/range",
                    "EVENT_SCOPE_ACK": "1",
                    "ALLOWED_HOSTS": "",
                    "ALLOWED_CIDRS": ",".join(declared_scope["allowed_cidrs"]),
                    "ALLOWED_PORTS": ",".join(
                        str(port) for port in declared_scope["allowed_ports"]
                    ),
                    "ALLOWED_PROTOCOLS": ",".join(
                        declared_scope["allowed_protocols"]
                    ),
                    "ALLOWED_FILE_ORIGINS": "",
                    "PLATFORM_HOSTS": "",
                    "SCOPE_MAX_BYTES": "1024",
                },
            )
            path = root / "bin" / "runq"
            path.write_text(
                "#!/usr/bin/env bash\n"
                "set -euo pipefail\n"
                "ROOT=$(cd \"$(dirname \"$0\")/..\" && pwd)\n"
                + self._successful_runq_body(),
                encoding="utf-8",
            )
            path.chmod(0o755)

        self.fixture = make_deployed_workspace("manual", prepare=prepare)
        self.root = Path(self.fixture.name)

    def test_exact_cidr_is_the_only_nmap_input(self) -> None:
        result = self._run("10.10.0.0/24")

        self.assertEqual(result.returncode, 0, result.stderr)
        captures = self._runq_argv_captures()
        self.assertEqual(len(captures), 1)
        self.assertFalse((self.root / "runq-argv").exists())
        argv = captures[0].read_text(encoding="utf-8").splitlines()
        self.assertEqual(argv[:5], ["-t", "900", "-l", "range-sweep", "--scope-generation"])
        self.assertEqual(argv[5:9], ["1", "--stop-generation", "0", "--scope-file-sha256"])
        self.assertEqual(argv[10], "--scope-content-sha256")
        self.assertEqual(len(argv[9]), 64)
        self.assertEqual(len(argv[11]), 64)
        self.assertEqual(argv[12], "--launch-binding-sha256")
        self.assertEqual(len(argv[13]), 64)
        self.assertEqual(
            argv[14:],
            ["--", "nmap", "-n", "-Pn", "-sT", "-p", "22,443", "-oN", "-", "--", "10.10.0.0/24"],
        )
        markers = list((self.root / "research" / "range-sweep").glob("*/.rookery-range-sweep"))
        self.assertEqual(len(markers), 1)
        output = markers[0].parent
        self.assertEqual((output / ".rookery-range-sweep").read_text(), "rookery range-sweep output\n")
        self.assertEqual((output / "scan.nmap").read_text(), "fixture nmap output\n")

    def test_help_and_version_are_read_only_startup_smokes(self) -> None:
        (self.root / "state" / "scope.json").unlink()
        for argument in ("--help", "--version"):
            with self.subTest(argument=argument):
                result = self._run(argument)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("range-sweep", result.stdout)
                self.assertFalse(self._runq_argv_captures())
                self.assertFalse((self.root / "research" / "range-sweep").exists())

    def test_extra_or_option_like_inputs_fail_before_scope_spawn_or_output(self) -> None:
        invalid_inputs = (
            ("--script", "vuln"),
            ("10.10.0.0/24", "--script", "vuln"),
            ("10.10.0.0/24", "-oA", "other"),
            ("10.10.0.0/24", "--datadir", "config"),
            ("10.10.0.0/24", "10.20.0.0/24"),
        )
        for arguments in invalid_inputs:
            with self.subTest(arguments=arguments):
                result = self._run(*arguments)
                self.assertEqual(result.returncode, 2)
                self.assertFalse(self._runq_argv_captures())
                self.assertFalse((self.root / "research" / "range-sweep").exists())

    def test_missing_exact_tcp_authority_fails_before_output_or_child(self) -> None:
        for ports, protocols in (([], ["tcp"]), ([443], ["https"])):
            with self.subTest(ports=ports, protocols=protocols):
                self._write_scope(ports=ports, protocols=protocols)
                result = self._run("10.10.0.0/24")
                self.assertEqual(result.returncode, 2)
                self.assertFalse(self._runq_argv_captures())
                self.assertFalse((self.root / "research" / "range-sweep").exists())

    def test_offscope_target_fails_before_output_or_runq(self) -> None:
        result = self._run("10.20.0.0/24")
        self.assertEqual(result.returncode, 2)
        self.assertFalse(self._runq_argv_captures())
        self.assertFalse((self.root / "research" / "range-sweep").exists())

    def test_output_base_symlink_fails_before_runq_and_preserves_sentinel(self) -> None:
        external = Path(self.external_temporary.name) / "external"
        external.mkdir()
        sentinel = external / "sentinel"
        sentinel.write_bytes(b"external bytes")
        research = self.root / "research"
        research.mkdir(exist_ok=True)
        (research / "range-sweep").symlink_to(external, target_is_directory=True)
        result = self._run("10.10.0.0/24")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(sentinel.read_bytes(), b"external bytes")
        self.assertFalse(self._runq_argv_captures())

    def test_output_collision_is_skipped_and_parallel_scans_reserve_distinct_outputs(self) -> None:
        module = runpy.run_path(str(self.root / "bin" / "range-sweep"))
        module["main"].__globals__["ROOT"] = self.root
        base = self.root / "research" / "range-sweep"
        base.mkdir(parents=True)
        fixed = base / "scan-20260829t010101z-fixed"
        fixed.mkdir()
        sentinel = fixed / "preserve"
        sentinel.write_bytes(b"do not overwrite")
        with (
            mock.patch.object(module["secrets"], "token_hex", side_effect=["fixed", "fresh"]),
            mock.patch.dict(module, {"compact_now": lambda: "20260829T010101Z"}),
        ):
            output = module["_create_output_directory"](self.root)
        output.close()
        self.assertNotEqual(output.path, fixed)
        self.assertEqual(sentinel.read_bytes(), b"do not overwrite")

        command = [str(self.root / "bin" / "range-sweep"), "10.10.0.0/24"]
        first = subprocess.Popen(
            command,
            cwd=self.root,
            env=self.fixture.bootstrap.environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        second = subprocess.Popen(
            command,
            cwd=self.root,
            env=self.fixture.bootstrap.environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        first.communicate(timeout=30)
        second.communicate(timeout=30)
        self.assertEqual((first.returncode, second.returncode), (0, 0))
        markers = list(base.glob("*/.rookery-range-sweep"))
        self.assertGreaterEqual(len(markers), 3)

    def test_detached_output_ancestry_refuses_final_publication_after_rename_symlink_swap(self) -> None:
        module = runpy.run_path(str(self.root / "bin" / "range-sweep"))
        module["main"].__globals__["ROOT"] = self.root
        output = module["_create_output_directory"](self.root)
        external = Path(self.external_temporary.name) / "external-output"
        external.mkdir()
        sentinel = external / "sentinel"
        sentinel.write_bytes(b"outside bytes")
        moved = output.path.with_name(output.path.name + "-moved")
        ready = threading.Event()

        def swap() -> None:
            ready.wait(timeout=5)
            output.path.rename(moved)
            output.path.symlink_to(external, target_is_directory=True)

        worker = threading.Thread(target=swap)
        worker.start()
        try:
            ready.set()
            worker.join(timeout=5)
            self.assertFalse(worker.is_alive())
            with self.assertRaises(OSError):
                module["_publish_output_file"](
                    output, "scan.nmap", b"captured nmap output\n"
                )
        finally:
            output.close()

        self.assertEqual(sentinel.read_bytes(), b"outside bytes")
        self.assertFalse((moved / "scan.nmap").exists())
        self.assertFalse((external / "scan.nmap").exists())
        self.assertTrue(output.path.is_symlink())


@unittest.skipUnless(os.name == "posix", "requires POSIX private output modes")
class TransitOutputContainmentTests(unittest.TestCase):
    def setUp(self) -> None:
        def prepare(root: Path) -> None:
            replace_env_assignments(
                root,
                {
                    "EVENT_ID": "transit-output-fixture",
                    "EVENT_NAME": "Transit Output Fixture",
                    "EVENT_URL": "https://fixture.invalid/transit-output",
                    "EVENT_SCOPE_ACK": "1",
                    "ALLOWED_HOSTS": "",
                    "ALLOWED_CIDRS": "192.0.2.0/24",
                    "ALLOWED_PORTS": "443",
                    "ALLOWED_PROTOCOLS": "https",
                    "ALLOWED_FILE_ORIGINS": "fixture://*",
                    "PLATFORM_HOSTS": "",
                    "SCOPE_MAX_BYTES": "1024",
                },
            )

        self.fixture = make_deployed_workspace("manual", prepare=prepare)
        self.root = Path(self.fixture.name)
        self.input_temporary = tempfile.TemporaryDirectory()
        self.external_temporary = tempfile.TemporaryDirectory()
        self.feed = Path(self.input_temporary.name) / "fixture.zip"
        with zipfile.ZipFile(self.feed, "w") as archive:
            archive.writestr("stops.txt", "stop_id,stop_name\n1,Fixture\n")

    def tearDown(self) -> None:
        self.fixture.cleanup()
        self.input_temporary.cleanup()
        self.external_temporary.cleanup()

    def _run(self, output: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                str(self.root / "bin" / "transit-source"),
                "--gtfs",
                str(self.feed),
                "--outdir",
                output,
            ],
            cwd=self.root,
            env=self.fixture.bootstrap.environment,
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )

    def test_output_is_fresh_marker_owned_and_private(self) -> None:
        result = self._run("research/transit/fixture")

        output = self.root / "research" / "transit" / "fixture"
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((output / ".rookery-transit-output").read_text(), "rookery transit output\n")
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)
        self.assertEqual(
            stat.S_IMODE((output / ".rookery-transit-output").stat().st_mode), 0o600
        )
        self.assertTrue((output / "transit_source.json").is_file())

    def test_output_escape_or_existing_collision_fails_without_overwrite(self) -> None:
        for raw in ("/tmp/transit", "../outside", "custom/transit", "research/transit/../outside"):
            with self.subTest(raw=raw):
                result = self._run(raw)
                self.assertEqual(result.returncode, 2)
                self.assertFalse((self.root / "research" / "transit").exists())

        existing = self.root / "research" / "transit" / "collision"
        existing.mkdir(parents=True)
        marker = existing / "preserve"
        marker.write_bytes(b"must not be overwritten")
        result = self._run("research/transit/collision")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(marker.read_bytes(), b"must not be overwritten")

    def test_symlinked_base_and_concurrent_same_name_are_rejected_without_reuse(self) -> None:
        external = Path(self.external_temporary.name) / "external"
        external.mkdir()
        sentinel = external / "sentinel"
        sentinel.write_bytes(b"external tree")
        research = self.root / "research"
        research.mkdir(exist_ok=True)
        (research / "transit").symlink_to(external, target_is_directory=True)
        result = self._run("research/transit/linked")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(sentinel.read_bytes(), b"external tree")

        (research / "transit").unlink()
        command = [
            str(self.root / "bin" / "transit-source"),
            "--gtfs",
            str(self.feed),
            "--outdir",
            "research/transit/shared",
        ]
        first = subprocess.Popen(
            command,
            cwd=self.root,
            env=self.fixture.bootstrap.environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        second = subprocess.Popen(
            command,
            cwd=self.root,
            env=self.fixture.bootstrap.environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        _first_stdout, first_stderr = first.communicate(timeout=30)
        _second_stdout, second_stderr = second.communicate(timeout=30)
        self.assertEqual(
            sorted((first.returncode, second.returncode)),
            [0, 2],
            (first_stderr, second_stderr),
        )
        self.assertTrue((self.root / "research" / "transit" / "shared" / ".rookery-transit-output").is_file())

    def test_first_use_family_admission_handles_n_processes_and_existing_marker(self) -> None:
        commands = [
            [
                str(self.root / "bin" / "transit-source"),
                "--gtfs",
                str(self.feed),
                "--outdir",
                f"research/transit/worker-{index}",
            ]
            for index in range(4)
        ]
        processes = [
            subprocess.Popen(
                command,
                cwd=self.root,
                env=self.fixture.bootstrap.environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            for command in commands
        ]
        for process in processes:
            process.communicate(timeout=30)
        self.assertEqual([process.returncode for process in processes], [0, 0, 0, 0])
        family = self.root / "research" / "transit"
        self.assertEqual((family / ".rookery-transit-family").read_bytes(), b"rookery transit family v1\n")
        self.assertEqual(
            len(list(family.glob("worker-*/.rookery-transit-output"))), 4
        )

    def test_unmarked_crash_residue_is_reclaimed_but_attacker_content_is_refused(self) -> None:
        module = runpy.run_path(str(self.root / "bin" / "transit-source"))
        globals_dict = module["main"].__globals__
        globals_dict["ROOT"] = self.root
        with mock.patch.dict(os.environ, self.fixture.bootstrap.environment, clear=True):
            binding = load_canonical_compiled_scope(self.root)
        globals_dict["verify_scope_binding"] = lambda current: current
        globals_dict["_after_family_mkdir"] = lambda: (_ for _ in ()).throw(RuntimeError("crash"))
        with self.assertRaisesRegex(RuntimeError, "crash"):
            module["_create_output_directory"]("crashed", binding=binding)
        family = self.root / "research" / "transit"
        self.assertTrue(family.is_dir())
        self.assertFalse((family / ".rookery-transit-family").exists())
        globals_dict["_after_family_mkdir"] = lambda: None
        recovered = module["_create_output_directory"]("recovered", binding=binding)
        recovered.close()
        self.assertTrue((family / ".rookery-transit-family").is_file())
        self.assertFalse(list(family.glob(".pending-*")))

        family_marker = family / ".rookery-transit-family"
        family_marker.unlink()
        attacker = family / "attacker"
        attacker.write_bytes(b"preserve")
        with self.assertRaisesRegex(OSError, "transit family is unowned"):
            module["_create_output_directory"]("attacker-refused", binding=binding)
        self.assertEqual(attacker.read_bytes(), b"preserve")

    def test_pinned_output_descriptor_rejects_rename_and_symlink_race_without_external_write(self) -> None:
        module = runpy.run_path(str(self.root / "bin" / "transit-source"))
        globals_dict = module["main"].__globals__
        globals_dict["ROOT"] = self.root
        with mock.patch.dict(os.environ, self.fixture.bootstrap.environment, clear=True):
            binding = load_canonical_compiled_scope(self.root)
        globals_dict["verify_scope_binding"] = lambda current: current
        output = module["_create_output_directory"]("race", binding=binding)
        external = Path(self.external_temporary.name) / "external"
        external.mkdir()
        sentinel = external / "sentinel"
        sentinel.write_bytes(b"outside bytes")
        moved = output.path.with_name("race-held")
        original_write = os.write
        swapped = False

        def write_then_swap(descriptor: int, data: bytes) -> int:
            nonlocal swapped
            count = original_write(descriptor, data)
            if not swapped:
                swapped = True
                os.rename(output.path, moved)
                output.path.symlink_to(external, target_is_directory=True)
            return count

        try:
            with mock.patch.object(module["os"], "write", side_effect=write_then_swap):
                with self.assertRaisesRegex(OSError, "transit output path was replaced"):
                    output.write_bytes("transit_source.json", b"{}", binding=binding)
        finally:
            output.close()

        self.assertTrue(swapped)
        self.assertEqual(sentinel.read_bytes(), b"outside bytes")
        self.assertFalse((moved / "transit_source.json").exists())


class PreparationExternalHealthScopeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def _binding(scope: dict[str, object], *, stop_generation: int = 0) -> CompiledScopeBinding:
        return CompiledScopeBinding(
            scope=scope,
            scope_generation=1,
            stop_generation=stop_generation,
            file_sha256="a" * 64,
            content_sha256="b" * 64,
            launch_binding_sha256="c" * 64,
        )

    class Response:
        def __init__(self, status: int, *, payload: bytes = b"", location: str = "") -> None:
            self.status = status
            self.payload = payload
            self.headers = {"Location": location} if location else {}
            self.closed = False

        def getcode(self) -> int:
            return self.status

        def read(self, _size: int) -> bytes:
            return self.payload

        def close(self) -> None:
            self.closed = True

        def __enter__(self):
            return self

        def __exit__(self, *_args: object) -> None:
            self.close()

    class ScopedOpen:
        """Deterministic response seam while production builds pinned transport."""

        def __init__(self, responses: list["PreparationExternalHealthScopeTests.Response"]) -> None:
            self.responses = responses
            self.requests: list[object] = []
            self.transports: list[object] = []

        def __call__(self, scope, url, **kwargs):
            transport = kwargs["transport"]
            if type(transport) is not ScopedHTTPTransport:
                raise AssertionError("preparation did not construct the pinned transport")
            self.transports.append(transport)
            sequence = scope_module._EndpointAwareTestTransport(self.responses)
            try:
                return scope_module.open_scoped_url(scope, url, _test_transport=sequence)
            finally:
                self.requests = sequence.requests

    class Transport:
        def __init__(self) -> None:
            self.scoped_calls = 0
            self.scopes: list[dict[str, object]] = []

        def scoped_transport(self, scope: dict[str, object]):
            self.scoped_calls += 1
            self.scopes.append(scope)
            return ScopedHTTPTransport(scope, ssl.create_default_context())

    def test_external_health_checks_target_and_each_redirect_before_opening(self) -> None:
        target_scope = _scope(ports=[80], hosts=["allowed.test"])
        binding = self._binding(target_scope)
        blocked_target = self.Transport()
        opened = self.ScopedOpen([])
        with (
            mock.patch.object(preparation_module, "_verify_scope_binding", return_value=binding),
            mock.patch.object(preparation_module, "open_scoped_url", side_effect=opened),
        ):
            ok, detail = preparation_module._http_json(
                "http://outside.test/search",
                root=self.root,
                transport=blocked_target,
                scope=target_scope,
                binding=binding,
            )
        self.assertFalse(ok)
        self.assertEqual(detail, "network request failed")
        self.assertEqual(blocked_target.scoped_calls, 1)
        self.assertEqual(opened.requests, [])
        self.assertEqual(opened.transports, [])

        redirected = self.Response(302, location="http://outside.test/search")
        redirect_transport = self.Transport()
        opened = self.ScopedOpen([redirected])
        with (
            mock.patch.object(preparation_module, "_verify_scope_binding", return_value=binding),
            mock.patch.object(preparation_module, "open_scoped_url", side_effect=opened),
        ):
            ok, detail = preparation_module._http_json(
                "http://allowed.test/search",
                root=self.root,
                transport=redirect_transport,
                scope=target_scope,
                binding=binding,
            )
        self.assertFalse(ok)
        self.assertEqual(detail, "network request failed")
        self.assertEqual(len(opened.requests), 1)
        self.assertEqual(len(opened.transports), 1)
        self.assertTrue(redirected.closed)

    def test_external_scope_and_managed_attestation_use_endpoint_aware_transports(self) -> None:
        scope = _scope(ports=[80], hosts=["allowed.test"])
        binding = self._binding(scope)
        external = self.Transport()
        opened = self.ScopedOpen([self.Response(200, payload=b'{"results": []}')])
        with (
            mock.patch.object(preparation_module, "_verify_scope_binding", return_value=binding),
            mock.patch.object(preparation_module, "open_scoped_url", side_effect=opened),
        ):
            ok, detail = preparation_module._http_json(
                "http://allowed.test/search",
                root=self.root,
                transport=external,
                scope=scope,
                binding=binding,
            )
        self.assertTrue(ok)
        self.assertEqual(detail, "healthy")
        self.assertEqual(external.scoped_calls, 1)
        self.assertEqual(len(opened.requests), 1)
        self.assertEqual(len(opened.transports), 1)

        loopback = self.Transport()
        opened = self.ScopedOpen([self.Response(200, payload=b'{"results": []}')])
        with (
            mock.patch.object(preparation_module, "_verify_scope_binding", return_value=binding),
            mock.patch.object(preparation_module, "open_scoped_url", side_effect=opened),
        ):
            ok, detail = preparation_module._http_json(
                "http://127.0.0.1:8080/search",
                root=self.root,
                transport=loopback,
                binding=binding,
            )
        self.assertTrue(ok)
        self.assertEqual(detail, "healthy")
        self.assertEqual(loopback.scoped_calls, 1)
        self.assertEqual(loopback.scopes[0]["allowed_hosts"], ["127.0.0.1"])
        self.assertEqual(len(opened.requests), 1)

    def test_binding_drift_blocks_external_and_managed_health_before_endpoint_open(self) -> None:
        scope = _scope(ports=[80], hosts=["allowed.test"])
        binding = self._binding(scope)
        for label, url, supplied_scope in (
            ("external", "http://allowed.test/search", scope),
            ("managed", "http://127.0.0.1:8080/search", None),
        ):
            with self.subTest(label=label):
                transport = self.Transport()
                opened = self.ScopedOpen([self.Response(200, payload=b'{"results": []}')])
                with mock.patch.object(
                    preparation_module,
                    "_verify_scope_binding",
                    side_effect=ScopeAuthorityError("canonical_compiled_scope_unavailable"),
                ), mock.patch.object(preparation_module, "open_scoped_url", side_effect=opened):
                    ok, detail = preparation_module._http_json(
                        url,
                        root=self.root,
                        transport=transport,
                        scope=supplied_scope,
                        binding=binding,
                    )
                self.assertFalse(ok)
                self.assertEqual(detail, "network request failed")
                self.assertEqual(opened.requests, [])
                self.assertEqual(opened.transports, [])


class TransitSourceTransportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        copy_rookery(self.root)
        self.module = runpy.run_path(
            str(self.root / "bin" / "transit-source"), run_name=f"transit_network_{id(self)}"
        )
        self.module["main"].__globals__["ROOT"] = self.root

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write_env(self, text: str) -> None:
        (self.root / ".env").write_text(text, encoding="utf-8")

    def test_ambient_proxy_is_ignored_and_redirects_are_scope_checked_per_hop(self) -> None:
        target_hits: list[str] = []
        proxy_hits: list[str] = []

        class TargetHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                target_hits.append(self.path)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"feed")

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
        original_getaddrinfo = socket.getaddrinfo
        resolution_count = 0

        def fixture_address(host: str, port: int, *args: object, **kwargs: object) -> object:
            nonlocal resolution_count
            if host == "fixture.invalid":
                resolution_count += 1
                return original_getaddrinfo("127.0.0.1", port, *args, **kwargs)
            return original_getaddrinfo(host, port, *args, **kwargs)

        try:
            self._write_env("TRANSIT_SOURCE_NETWORK_ENV_KEYS=[]\n")
            scope = _scope(
                ports=[target.server_port],
                hosts=["fixture.invalid"],
                cidrs=["127.0.0.0/8"],
                origins=[f"http://fixture.invalid:{target.server_port}/*"],
            )
            with mock.patch.dict(
                os.environ,
                {"HTTP_PROXY": f"http://127.0.0.1:{proxy.server_port}", "NO_PROXY": ""},
                clear=False,
            ), mock.patch("socket.getaddrinfo", side_effect=fixture_address):
                policy = self.module["transit_network_policy"](scope)
                destination = mock.Mock()
                self.module["download_feed"](
                    f"http://fixture.invalid:{target.server_port}/feed.zip",
                    destination,
                    1024,
                    scope=scope,
                    transport=policy.scoped_transport(scope),
                    binding=None,
                )
        finally:
            target.shutdown()
            proxy.shutdown()
            target.server_close()
            proxy.server_close()
            target_thread.join(timeout=2)
            proxy_thread.join(timeout=2)

        destination.write_bytes.assert_called_once_with("feed.zip", b"feed", binding=None)
        self.assertEqual(target_hits, ["/feed.zip"])
        self.assertEqual(proxy_hits, [])
        self.assertEqual(resolution_count, 1)
        self.assertNotIn("127.0.0.1", str(policy.metadata()))

    def test_selected_proxy_fails_before_dns_or_evidence_directory(self) -> None:
        scope = _scope(
            ports=[80],
            hosts=["fixture.invalid"],
            origins=["http://fixture.invalid/*"],
        )
        binding = CompiledScopeBinding(
            scope=scope,
            scope_generation=1,
            stop_generation=0,
            file_sha256="a" * 64,
            content_sha256="b" * 64,
            launch_binding_sha256="c" * 64,
        )
        self._write_env(
            "TRANSIT_SOURCE_NETWORK_ENV_KEYS=[\"HTTP_PROXY\"]\n"
            "HTTP_PROXY=http://proxy-user:private@127.0.0.1:8118\n"
        )
        with (
            mock.patch.object(sys, "argv", ["transit-source", "--feed-url", "http://fixture.invalid/feed.zip"]),
            mock.patch("socket.getaddrinfo", side_effect=AssertionError("proxy reached DNS")),
            mock.patch.dict(
                self.module["main"].__globals__,
                {
                    "load_canonical_compiled_scope": lambda _root: binding,
                    "verify_canonical_compiled_scope_binding": lambda _root, **_kwargs: binding,
                },
            ),
        ):
            self.assertEqual(self.module["main"](), 2)
        self.assertFalse((self.root / "research" / "transit").exists())

    def test_canonical_binding_drift_blocks_transit_before_output_or_network(self) -> None:
        scope = _scope(
            ports=[80], hosts=["fixture.invalid"], origins=["http://fixture.invalid/*"]
        )
        binding = CompiledScopeBinding(
            scope=scope,
            scope_generation=1,
            stop_generation=0,
            file_sha256="a" * 64,
            content_sha256="b" * 64,
            launch_binding_sha256="c" * 64,
        )
        for stage in (
            "schema-less file",
            "widened same-generation file",
            "same-generation forged file",
            "manifest generation drift",
            "sqlite scope generation drift",
            "stop generation race",
            "file swap",
        ):
            with self.subTest(stage=stage):
                loader = (
                    mock.Mock(side_effect=ScopeAuthorityError("canonical_compiled_scope_unavailable"))
                    if "file" in stage
                    else lambda _root: binding
                )
                verifier = mock.Mock(
                    side_effect=ScopeAuthorityError("canonical_compiled_scope_unavailable")
                )
                with (
                    mock.patch.object(sys, "argv", ["transit-source", "--gtfs", "missing.zip"]),
                    mock.patch("socket.getaddrinfo", side_effect=AssertionError("drift reached DNS")),
                    mock.patch.dict(
                        self.module["main"].__globals__,
                        {
                            "load_canonical_compiled_scope": loader,
                            "verify_canonical_compiled_scope_binding": verifier,
                        },
                    ),
                ):
                    self.assertEqual(self.module["main"](), 2)
                self.assertFalse((self.root / "research" / "transit").exists())

    def test_declared_proxy_and_no_proxy_are_honored_without_value_leakage(self) -> None:
        target_hits: list[str] = []
        proxy_hits: list[str] = []

        class TargetHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                target_hits.append(self.path)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"feed")

            def log_message(self, _format: str, *args: object) -> None:
                del args

        class ProxyHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                proxy_hits.append(self.path)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"feed")

            def log_message(self, _format: str, *args: object) -> None:
                del args

        target = ThreadingHTTPServer(("127.0.0.1", 0), TargetHandler)
        proxy = ThreadingHTTPServer(("127.0.0.1", 0), ProxyHandler)
        target_thread = threading.Thread(target=target.serve_forever, daemon=True)
        proxy_thread = threading.Thread(target=proxy.serve_forever, daemon=True)
        target_thread.start()
        proxy_thread.start()
        try:
            proxy_url = f"http://127.0.0.1:{proxy.server_port}"
            scope = _scope(
                ports=[target.server_port, proxy.server_port],
                cidrs=["127.0.0.0/8"],
                origins=[f"http://127.0.0.1:{target.server_port}/*"],
            )
            self._write_env(
                "TRANSIT_SOURCE_NETWORK_ENV_KEYS=[\"HTTP_PROXY\",\"NO_PROXY\"]\n"
                f"HTTP_PROXY={proxy_url}\nNO_PROXY=127.0.0.1\n"
            )
            policy = self.module["transit_network_policy"](scope)
            self.module["download_feed"](
                f"http://127.0.0.1:{target.server_port}/feed.zip",
                mock.Mock(),
                1024,
                scope=scope,
                transport=policy.scoped_transport(scope),
                binding=None,
            )
        finally:
            target.shutdown()
            proxy.shutdown()
            target.server_close()
            proxy.server_close()
            target_thread.join(timeout=2)
            proxy_thread.join(timeout=2)

        self.assertEqual(target_hits, ["/feed.zip"])
        self.assertEqual(proxy_hits, [])
        self.assertNotIn(proxy_url, str(policy.metadata()))

    def test_offscope_credentialed_proxy_and_offscope_redirect_fail_before_follow_on_access(self) -> None:
        proxy_secret = "transit-proxy-password"
        self._write_env(
            "TRANSIT_SOURCE_NETWORK_ENV_KEYS=[\"HTTP_PROXY\"]\n"
            f"HTTP_PROXY=http://proxy-user:{proxy_secret}@127.0.0.1:8118\n"
        )
        scope = _scope(ports=[80], hosts=["fixture.invalid"])
        policy = self.module["transit_network_policy"](scope)
        with self.assertRaisesRegex(
            self.module["EnvironmentPolicyError"], "scoped_proxy_target_pinning_unavailable"
        ) as blocked:
            policy.scoped_transport(scope).preflight_url("http://fixture.invalid/feed.zip")
        self.assertNotIn(proxy_secret, str(blocked.exception))

        redirects: list[str] = []

        class RedirectHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                redirects.append(self.path)
                self.send_response(302)
                self.send_header("Location", "http://127.0.0.1:9/outside")
                self.end_headers()

            def log_message(self, _format: str, *args: object) -> None:
                del args

        redirect = ThreadingHTTPServer(("127.0.0.1", 0), RedirectHandler)
        thread = threading.Thread(target=redirect.serve_forever, daemon=True)
        thread.start()
        try:
            self._write_env("TRANSIT_SOURCE_NETWORK_ENV_KEYS=[]\n")
            scoped = _scope(
                ports=[redirect.server_port],
                cidrs=["127.0.0.0/8"],
                origins=[f"http://127.0.0.1:{redirect.server_port}/*"],
            )
            policy = self.module["transit_network_policy"](scoped)
            destination = mock.Mock()
            with self.assertRaisesRegex(RuntimeError, "redirect blocked by scope"):
                self.module["download_feed"](
                    f"http://127.0.0.1:{redirect.server_port}/feed.zip",
                    destination,
                    1024,
                scope=scoped,
                transport=policy.scoped_transport(scoped),
                binding=None,
                )
        finally:
            redirect.shutdown()
            redirect.server_close()
            thread.join(timeout=2)

        self.assertEqual(redirects, ["/feed.zip"])
        destination.write_bytes.assert_not_called()

    @unittest.skipUnless(os.name == "posix", "requires no-follow CA binding semantics")
    def test_ca_path_swap_after_admission_cannot_change_the_tls_bytes(self) -> None:
        cafile = ssl.get_default_verify_paths().openssl_cafile
        if not cafile or not Path(cafile).is_file():
            self.skipTest("compiled system CA file is unavailable")
        original = Path(cafile).read_bytes()
        bundle = self.root / "declared-ca.pem"
        replacement = self.root / "replacement-ca.pem"
        bundle.write_bytes(original)
        replacement.write_bytes(b"replacement bytes must never be read")
        self._write_env(
            "TRANSIT_SOURCE_NETWORK_ENV_KEYS=[\"SSL_CERT_FILE\"]\n"
            f"SSL_CERT_FILE={bundle}\n"
        )
        factory = self.module["ExplicitNetworkPolicy"].from_child_environment
        context = mock.Mock()

        def swap_after_admission(child, *, scope):
            os.replace(replacement, bundle)
            return factory(child, scope=scope)

        with (
            mock.patch(
                "rookery.portable.network_policy._system_trust_context", return_value=context
            ),
            mock.patch.object(
                self.module["ExplicitNetworkPolicy"],
                "from_child_environment",
                side_effect=swap_after_admission,
            ),
            mock.patch.object(ssl, "_create_unverified_context") as insecure,
        ):
            self.module["transit_network_policy"](
                _scope(ports=[443], hosts=["fixture.invalid"])
            )

        self.assertEqual(
            context.load_verify_locations.call_args.kwargs,
            {"cadata": original.decode("ascii")},
        )
        insecure.assert_not_called()

    def test_transit_source_has_no_raw_proxy_tls_or_scope_helper_bypass(self) -> None:
        source = (self.root / "bin" / "transit-source").read_text(encoding="utf-8")
        for forbidden in (
            "urllib.request.ProxyHandler",
            "ssl.create_default_context",
            "build_scoped_opener",
            "run_bounded_argv",
            "scope-check",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)
        self.assertIn("ExplicitNetworkPolicy.from_child_environment", source)
        self.assertIn("open_scoped_url", source)


if __name__ == "__main__":  # pragma: no cover
    unittest.main(verbosity=2)
