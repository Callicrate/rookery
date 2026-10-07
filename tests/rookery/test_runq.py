from __future__ import annotations

# ruff: noqa: E402

import hashlib
import io
import json
import os
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from contextlib import redirect_stdout
from importlib.machinery import SourceFileLoader
from importlib.util import module_from_spec, spec_from_loader
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from tests.rookery.support import ROOKERY_ROOT
from tests.rookery.test_accelerator_environment import (
    bootstrap_public_accelerator_workspace,
)
from tests.rookery.test_preparation_and_isolation import copy_rookery

LIB = ROOKERY_ROOT / "lib"
if str(LIB) not in sys.path:
    sys.path.insert(0, str(LIB))
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

from rookery.portable.control import process_identity_matches, stop
from rookery.portable.scope import ScopeAuthorityError, load_canonical_compiled_scope
from rookery.portable.store import EventStore
from rookery.portable.util import canonical_json


class RunqStreamingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        copy_rookery(self.root)
        self.baseline = bootstrap_public_accelerator_workspace(self.root)
        self.environment = {
            **os.environ,
            "PYTHONPATH": str(self.root / "lib"),
            "PYTHONDONTWRITEBYTECODE": "1",
        }

    def tearDown(self) -> None:
        try:
            self.temporary.cleanup()
        finally:
            self.baseline.cleanup()

    def runq(self, *arguments: str) -> tuple[subprocess.CompletedProcess[str], dict[str, object]]:
        completed = subprocess.run(
            [str(self.root / "bin" / "runq"), *arguments],
            cwd=self.root,
            env=self.environment,
            text=True,
            capture_output=True,
            timeout=20,
            check=False,
        )
        self.assertTrue(completed.stdout, completed.stderr)
        return completed, json.loads(completed.stdout)

    def runbg(self, *arguments: str) -> tuple[subprocess.CompletedProcess[str], dict[str, object]]:
        completed = subprocess.run(
            [str(self.root / "bin" / "runbg"), *arguments],
            cwd=self.root,
            env=self.environment,
            text=True,
            capture_output=True,
            timeout=20,
            check=False,
        )
        self.assertTrue(completed.stdout, completed.stderr)
        return completed, json.loads(completed.stdout)

    def wait_for_job_terminal(
        self, metadata: dict[str, object], *, timeout: float = 10
    ) -> dict[str, object]:
        path = self.root / str(metadata["report_path"]) / "meta.json"
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            current = json.loads(path.read_text(encoding="utf-8"))
            if current.get("status") in {
                "closed",
                "cancelled",
                "unacknowledged",
                "unmanaged",
                "failed",
            }:
                return current
            time.sleep(0.05)
        self.fail("background job did not publish a terminal envelope")

    def output_paths(self, metadata: dict[str, object]) -> tuple[Path, Path]:
        return (
            self.root / str(metadata["stdout_path"]),
            self.root / str(metadata["stderr_path"]),
        )

    def scoped_arguments(self) -> list[str]:
        binding = load_canonical_compiled_scope(self.root)
        return [
            "--scope-generation",
            str(binding.scope_generation),
            "--stop-generation",
            str(binding.stop_generation),
            "--scope-file-sha256",
            binding.file_sha256,
            "--scope-content-sha256",
            binding.content_sha256,
            "--launch-binding-sha256",
            binding.launch_binding_sha256,
        ]

    def start_scoped_runq(self, ready_path: Path) -> subprocess.Popen[str]:
        return subprocess.Popen(
            [
                str(self.root / "bin" / "runq"),
                *self.scoped_arguments(),
                "--timeout",
                "60",
                "--",
                sys.executable,
                "-c",
                (
                    "import time; from pathlib import Path; "
                    f"Path({str(ready_path)!r}).write_text('ready'); time.sleep(60)"
                ),
            ],
            cwd=self.root,
            env=self.environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def wait_for_command_started(self) -> dict[str, object]:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            rows = EventStore(self.root).events("command.started")
            if rows:
                return dict(rows[-1]["payload"])
            time.sleep(0.02)
        self.fail("scoped runq did not publish command.started")

    @staticmethod
    def terminate_group(pgid: int) -> None:
        try:
            os.killpg(pgid, signal.SIGKILL)
        except ProcessLookupError:
            pass

    def command_process_proofs(self, pid: int) -> dict[str, str]:
        argv = [
            value.decode("utf-8", errors="replace")
            for value in (Path("/proc") / str(pid) / "cmdline").read_bytes().split(b"\0")
            if value
        ]
        self.assertTrue(argv)
        return {
            "argv_sha256": hashlib.sha256(
                canonical_json(argv).encode("utf-8")
            ).hexdigest(),
            "executable_sha256": hashlib.sha256(
                argv[0].encode("utf-8")
            ).hexdigest(),
            "workspace_root_sha256": hashlib.sha256(
                str(self.root.resolve()).encode("utf-8")
            ).hexdigest(),
        }

    def test_scoped_runq_command_is_durable_and_stoppable(self) -> None:
        ready = self.root / "logs" / "scoped-ready"
        parent = self.start_scoped_runq(ready)
        payload: dict[str, object] = {}
        try:
            payload = self.wait_for_command_started()
            deadline = time.monotonic() + 5
            while not ready.exists() and time.monotonic() < deadline:
                time.sleep(0.02)
            self.assertTrue(ready.exists())
            self.assertIn("owner_token_sha256", payload)
            self.assertNotIn("owner_token", payload)
            self.assertEqual(len(str(payload["owner_token_sha256"])), 64)
            self.assertTrue({"pid", "pgid", "process_starttime", "argv_sha256", "executable_sha256", "workspace_root_sha256"} <= set(payload))

            stopped = stop(
                EventStore(self.root),
                self.root,
                reason="runq lifecycle test",
                wait_seconds=0.5,
            )
            self.assertEqual(stopped["confirmed_stopped"], [payload["command_id"]])
            self.assertEqual(stopped["unacknowledged"], [])
            self.assertEqual(stopped["unmanaged"], [])
            parent.wait(timeout=10)
            self.assertIsNotNone(parent.returncode)
            events = EventStore(self.root).events()
            self.assertEqual(len([row for row in events if row["event_type"] == "command.stopped"]), 1)
            self.assertEqual(len([row for row in events if row["event_type"] == "command.completed"]), 1)
        finally:
            if payload:
                self.terminate_group(int(payload["pgid"]))
            if parent.poll() is None:
                parent.kill()
            try:
                parent.wait(timeout=2)
            except subprocess.TimeoutExpired:
                pass
            for stream in (parent.stdout, parent.stderr):
                if stream is not None:
                    stream.close()

    def test_killed_runq_parent_leaves_durable_child_for_stop(self) -> None:
        ready = self.root / "logs" / "orphan-ready"
        parent = self.start_scoped_runq(ready)
        payload: dict[str, object] = {}
        try:
            payload = self.wait_for_command_started()
            os.kill(parent.pid, signal.SIGKILL)
            parent.wait(timeout=5)
            self.assertTrue((Path("/proc") / str(payload["pid"])).exists())
            stopped = stop(
                EventStore(self.root),
                self.root,
                reason="orphaned runq parent",
                wait_seconds=0.5,
            )
            self.assertEqual(stopped["confirmed_stopped"], [payload["command_id"]])
            self.assertFalse(stopped["unacknowledged"])
            self.assertFalse(stopped["unmanaged"])
        finally:
            if payload:
                self.terminate_group(int(payload["pgid"]))
            if parent.poll() is None:
                parent.kill()
            for stream in (parent.stdout, parent.stderr):
                if stream is not None:
                    stream.close()

    def test_stop_never_signals_command_with_mismatched_owner_proof(self) -> None:
        token = "actual-command-owner"
        child = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            cwd=self.root,
            start_new_session=True,
            env={**self.environment, "ROOKERY_OWNER_TOKEN": token},
        )
        try:
            starttime = (Path("/proc") / str(child.pid) / "stat").read_text().split()[21]
            store = EventStore(self.root)
            store.append(
                "command.started",
                {
                    "command_id": "command-owner-mismatch",
                    "pid": child.pid,
                    "pgid": os.getpgid(child.pid),
                    "process_starttime": starttime,
                    "owner_token_sha256": hashlib.sha256(b"wrong-owner").hexdigest(),
                    **self.command_process_proofs(child.pid),
                },
                actor="fixture",
            )
            stopped = stop(store, self.root, reason="mismatch", wait_seconds=0)
            self.assertIsNone(child.poll())
            self.assertEqual(stopped["signalled_pids"], [])
            self.assertEqual(stopped["confirmed_stopped"], [])
            self.assertEqual(stopped["unmanaged"], ["command-owner-mismatch"])
        finally:
            try:
                self.terminate_group(os.getpgid(child.pid))
            except ProcessLookupError:
                pass
            try:
                child.wait(timeout=2)
            except subprocess.TimeoutExpired:
                pass

    def test_stop_records_term_resistant_owned_command_as_unacknowledged(self) -> None:
        token = "term-resistant-command-owner"
        child = subprocess.Popen(
            [
                sys.executable,
                "-c",
                "import signal, time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(60)",
            ],
            cwd=self.root,
            start_new_session=True,
            env={**self.environment, "ROOKERY_OWNER_TOKEN": token},
        )
        try:
            starttime = (Path("/proc") / str(child.pid) / "stat").read_text().split()[21]
            store = EventStore(self.root)
            command_id = "command-term-resistant"
            store.append(
                "command.started",
                {
                    "command_id": command_id,
                    "pid": child.pid,
                    "pgid": os.getpgid(child.pid),
                    "process_starttime": starttime,
                    "owner_token_sha256": hashlib.sha256(token.encode()).hexdigest(),
                    **self.command_process_proofs(child.pid),
                },
                actor="fixture",
            )
            stopped = stop(store, self.root, reason="term resistant", wait_seconds=0)
            self.assertIsNone(child.poll())
            self.assertEqual(stopped["confirmed_stopped"], [])
            self.assertEqual(stopped["unacknowledged"], [command_id])
            self.assertEqual(stopped["unmanaged"], [])
            self.assertEqual(
                store.events("command.unacknowledged")[-1]["payload"]["command_id"],
                command_id,
            )
            self.assertFalse(store.events("command.completed"))
        finally:
            try:
                self.terminate_group(os.getpgid(child.pid))
            except ProcessLookupError:
                pass
            try:
                child.wait(timeout=2)
            except subprocess.TimeoutExpired:
                pass

    def test_post_request_scope_refusal_emits_one_value_free_terminal(self) -> None:
        module_name = f"runq_scope_refusal_{time.monotonic_ns()}"
        loader = SourceFileLoader(
            module_name, str(self.root / "bin" / "rookery-accelerators")
        )
        spec = spec_from_loader(module_name, loader)
        self.assertIsNotNone(spec)
        module = module_from_spec(spec)
        loader.exec_module(module)
        module.ROOT = self.root
        binding = load_canonical_compiled_scope(self.root)
        arguments = SimpleNamespace(
            command=[sys.executable, "-c", "raise SystemExit(0)"],
            timeout=10,
            max_output_bytes=1024,
            label="scope-refusal",
            attempt_id="",
            parent_attempt_id="",
            proposal_id="",
            plan_id="",
            mutation=False,
            print_output=False,
            pass_env=[],
            env_policy=[],
            scope_generation=binding.scope_generation,
            stop_generation=binding.stop_generation,
            scope_file_sha256=binding.file_sha256,
            scope_content_sha256=binding.content_sha256,
            launch_binding_sha256=binding.launch_binding_sha256,
        )
        with (
            mock.patch.object(module, "verify_canonical_compiled_scope_binding"),
            mock.patch.object(
                module,
                "verified_canonical_scope_effect",
                side_effect=ScopeAuthorityError("canonical_compiled_scope_unavailable"),
            ),
            mock.patch.object(module.subprocess, "Popen") as popen,
        ):
            self.assertEqual(module.runq(arguments), 126)
        popen.assert_not_called()
        events = EventStore(self.root).events()
        requested = [row for row in events if row["event_type"] == "command.requested"]
        completed = [row for row in events if row["event_type"] == "command.completed"]
        self.assertEqual(len(requested), 1)
        self.assertEqual(len(completed), 1)
        self.assertEqual(requested[0]["payload"]["command_id"], completed[0]["payload"]["command_id"])
        self.assertEqual(completed[0]["payload"]["status"], "stale_binding")
        self.assertNotIn("command", completed[0]["payload"])

    def test_stop_waits_for_scoped_command_identity_handoff(self) -> None:
        module_name = f"runq_stop_race_{time.monotonic_ns()}"
        loader = SourceFileLoader(
            module_name, str(self.root / "bin" / "rookery-accelerators")
        )
        spec = spec_from_loader(module_name, loader)
        self.assertIsNotNone(spec)
        module = module_from_spec(spec)
        loader.exec_module(module)
        module.ROOT = self.root
        binding = load_canonical_compiled_scope(self.root)
        arguments = SimpleNamespace(
            command=[sys.executable, "-c", "import time; time.sleep(60)"],
            timeout=60,
            max_output_bytes=1024,
            label="stop-race",
            attempt_id="",
            parent_attempt_id="",
            proposal_id="",
            plan_id="",
            mutation=False,
            print_output=False,
            pass_env=[],
            env_policy=[],
            scope_generation=binding.scope_generation,
            stop_generation=binding.stop_generation,
            scope_file_sha256=binding.file_sha256,
            scope_content_sha256=binding.content_sha256,
            launch_binding_sha256=binding.launch_binding_sha256,
        )
        store = EventStore(self.root)
        original_append = store.append
        stop_finished = threading.Event()
        stop_result: dict[str, object] = {}
        stop_thread: threading.Thread | None = None
        was_blocked = False

        def append(event_type, payload, **kwargs):
            nonlocal stop_thread, was_blocked
            if event_type == "command.started":
                stop_thread = threading.Thread(
                    target=lambda: (
                        stop_result.update(
                            stop(store, self.root, reason="handoff race", wait_seconds=0.5)
                        ),
                        stop_finished.set(),
                    ),
                    daemon=True,
                )
                stop_thread.start()
                time.sleep(0.1)
                was_blocked = not stop_finished.is_set()
            return original_append(event_type, payload, **kwargs)

        with (
            mock.patch.object(module, "EventStore", return_value=store),
            mock.patch.object(store, "append", side_effect=append),
            redirect_stdout(io.StringIO()),
        ):
            module.runq(arguments)
        self.assertTrue(was_blocked)
        self.assertIsNotNone(stop_thread)
        stop_thread.join(timeout=5)
        self.assertTrue(stop_finished.is_set())
        self.assertEqual(len(stop_result["confirmed_stopped"]), 1)
        events = EventStore(self.root).events()
        self.assertEqual(len([row for row in events if row["event_type"] == "command.started"]), 1)
        self.assertEqual(len([row for row in events if row["event_type"] == "command.stopped"]), 1)

    def test_failed_scoped_identity_handoff_reaps_the_just_spawned_child(self) -> None:
        marker = self.root / "failed-scoped-handoff-marker"
        module_name = f"runq_unverified_handoff_{time.monotonic_ns()}"
        loader = SourceFileLoader(
            module_name, str(self.root / "bin" / "rookery-accelerators")
        )
        spec = spec_from_loader(module_name, loader)
        self.assertIsNotNone(spec)
        module = module_from_spec(spec)
        loader.exec_module(module)
        module.ROOT = self.root
        binding = load_canonical_compiled_scope(self.root)
        arguments = SimpleNamespace(
            command=[
                sys.executable,
                "-c",
                (
                    "import time; from pathlib import Path; "
                    f"time.sleep(2); Path({str(marker)!r}).touch()"
                ),
            ],
            timeout=10,
            max_output_bytes=1024,
            label="unverified-handoff",
            attempt_id="",
            parent_attempt_id="",
            proposal_id="",
            plan_id="",
            mutation=False,
            print_output=False,
            pass_env=[],
            env_policy=[],
            scope_generation=binding.scope_generation,
            stop_generation=binding.stop_generation,
            scope_file_sha256=binding.file_sha256,
            scope_content_sha256=binding.content_sha256,
            launch_binding_sha256=binding.launch_binding_sha256,
        )
        with (
            mock.patch.object(module, "_command_identity", return_value=None),
            redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(module.runq(arguments), 74)
        time.sleep(2.25)
        self.assertFalse(marker.exists(), "unverified scoped child survived handoff failure")
        events = EventStore(self.root).events()
        self.assertFalse([row for row in events if row["event_type"] == "command.started"])
        self.assertEqual(
            len([row for row in events if row["event_type"] == "command.stopped"]), 1
        )

    def test_normal_hashes_permissions_collision_and_event_pairing(self) -> None:
        command = (
            "import os; "
            "os.write(1, b'normal stdout'); "
            "os.write(2, b'normal stderr')"
        )
        first, metadata = self.runq(
            "--label",
            "same-label",
            "--attempt-id",
            "attempt-1",
            "--proposal-id",
            "proposal-1",
            "--plan-id",
            "plan-1",
            "--",
            sys.executable,
            "-c",
            command,
        )
        second, second_metadata = self.runq(
            "--label",
            "same-label",
            "--",
            sys.executable,
            "-c",
            "print('second')",
        )

        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertNotEqual(metadata["command_id"], second_metadata["command_id"])
        command_dirs = list((self.root / "logs" / "commands").iterdir())
        self.assertEqual(len(command_dirs), 2)
        stdout_path, stderr_path = self.output_paths(metadata)
        self.assertEqual(stdout_path.read_bytes(), b"normal stdout")
        self.assertEqual(stderr_path.read_bytes(), b"normal stderr")
        self.assertEqual(metadata["stdout_bytes"], stdout_path.stat().st_size)
        self.assertEqual(metadata["stderr_bytes"], stderr_path.stat().st_size)
        self.assertEqual(metadata["stdout_sha256"], hashlib.sha256(stdout_path.read_bytes()).hexdigest())
        self.assertEqual(metadata["stderr_sha256"], hashlib.sha256(stderr_path.read_bytes()).hexdigest())
        self.assertEqual(metadata["termination"], "exited")
        self.assertEqual(metadata["exit_code"], 0)
        self.assertEqual(metadata["max_output_bytes"], 64 * 1024 * 1024)
        digest = json.loads((stdout_path.parent / "digest.json").read_text(encoding="utf-8"))
        self.assertEqual(set(digest), {"schema_version", "complete", "sha256", "byte_count", "stderr"})
        self.assertEqual(digest["sha256"], metadata["stdout_sha256"])
        self.assertEqual(digest["stderr"]["sha256"], metadata["stderr_sha256"])
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(stdout_path.parent.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(stdout_path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(stderr_path.stat().st_mode), 0o600)
        events = EventStore(self.root).events()
        requested = [
            event
            for event in events
            if event["event_type"] == "command.requested"
            and event["payload"].get("attempt_id") == "attempt-1"
        ]
        completed = [
            event
            for event in events
            if event["event_type"] == "command.completed"
            and event["payload"].get("attempt_id") == "attempt-1"
        ]
        self.assertEqual(len(requested), 1)
        self.assertEqual(len(completed), 1)
        self.assertEqual(requested[0]["payload"]["command_id"], completed[0]["payload"]["command_id"])
        self.assertNotIn("command", completed[0]["payload"])

    def test_argv_does_not_interpolate_shell_marker(self) -> None:
        marker = self.root / "shell-marker"
        injected_argument = f"; touch {marker}"
        completed, metadata = self.runq(
            "--",
            sys.executable,
            "-c",
            "import sys; print(sys.argv[1])",
            injected_argument,
        )

        stdout_path, _stderr_path = self.output_paths(metadata)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertFalse(marker.exists())
        self.assertEqual(stdout_path.read_text(encoding="utf-8"), injected_argument + "\n")

    def test_timeout_and_spawn_error_publish_terminal_envelopes(self) -> None:
        timed_out, timeout_metadata = self.runq(
            "--timeout",
            "1",
            "--",
            sys.executable,
            "-c",
            "import time; time.sleep(10)",
        )
        spawned, spawn_metadata = self.runq("--", str(self.root / "missing-command"))

        self.assertEqual(timed_out.returncode, 124, timed_out.stderr)
        self.assertEqual(timeout_metadata["termination"], "timeout")
        self.assertEqual(timeout_metadata["exit_code"], 124)
        self.assertTrue((self.output_paths(timeout_metadata)[0].parent / "meta.json").is_file())
        self.assertEqual(spawned.returncode, 127, spawned.stderr)
        self.assertEqual(spawn_metadata["termination"], "spawn_error")
        self.assertEqual(spawn_metadata["exit_code"], 127)
        self.assertTrue((self.output_paths(spawn_metadata)[0].parent / "meta.json").is_file())

    def test_signal_and_combined_output_limit_publish_truthful_terminal_envelopes(self) -> None:
        signalled, signal_metadata = self.runq(
            "--",
            sys.executable,
            "-c",
            "import os, signal; os.kill(os.getpid(), signal.SIGTERM)",
        )
        limited, limit_metadata = self.runq(
            "--max-output-bytes",
            "1024",
            "--",
            sys.executable,
            "-c",
            "import os; os.write(1, b'A' * 4096); os.write(2, b'B' * 4096)",
        )

        self.assertNotEqual(signalled.returncode, 0)
        self.assertEqual(signal_metadata["termination"], "signal")
        self.assertLess(int(signal_metadata["exit_code"]), 0)
        stdout_path, stderr_path = self.output_paths(limit_metadata)
        captured_bytes = stdout_path.stat().st_size + stderr_path.stat().st_size
        self.assertEqual(limited.returncode, 125, limited.stderr)
        self.assertEqual(limit_metadata["termination"], "output_limit")
        self.assertEqual(limit_metadata["exit_code"], 125)
        self.assertEqual(limit_metadata["max_output_bytes"], 1024)
        self.assertLessEqual(captured_bytes, 1024)
        self.assertEqual(int(limit_metadata["stdout_bytes"]) + int(limit_metadata["stderr_bytes"]), captured_bytes)

    def test_runbg_output_limit_stops_the_producer_and_retains_only_the_cap(self) -> None:
        launched, metadata = self.runbg(
            "--timeout",
            "10",
            "--max-output-bytes",
            "1024",
            "--",
            sys.executable,
            "-c",
            (
                "import os\n"
                "while True:\n"
                " os.write(1, b'A' * 4096)\n"
                " os.write(2, b'B' * 4096)\n"
            ),
        )
        self.assertEqual(launched.returncode, 0, launched.stderr)
        terminal = self.wait_for_job_terminal(metadata)
        stdout_path = self.root / str(terminal["stdout_path"])
        stderr_path = self.root / str(terminal["stderr_path"])
        self.assertEqual(terminal["status"], "closed")
        self.assertEqual(terminal["termination"], "output_limit")
        self.assertLessEqual(stdout_path.stat().st_size + stderr_path.stat().st_size, 1024)
        self.assertEqual(
            int(terminal["stdout_bytes"]) + int(terminal["stderr_bytes"]),
            stdout_path.stat().st_size + stderr_path.stat().st_size,
        )
        self.assertFalse(
            (Path("/proc") / str(metadata["pid"])).exists(),
            "output producer survived its terminal envelope",
        )
        closed = EventStore(self.root).events("job.closed")
        self.assertEqual(closed[-1]["payload"]["termination"], "output_limit")

    def test_runbg_timeout_stops_the_owned_process_group(self) -> None:
        launched, metadata = self.runbg(
            "--timeout",
            "1",
            "--",
            sys.executable,
            "-c",
            "import time; time.sleep(60)",
        )
        self.assertEqual(launched.returncode, 0, launched.stderr)
        terminal = self.wait_for_job_terminal(metadata)
        self.assertEqual(terminal["status"], "closed")
        self.assertEqual(terminal["termination"], "timeout")
        self.assertFalse((Path("/proc") / str(metadata["pid"])).exists())

    def test_runbg_cleans_chdir_closed_stdio_descendant_after_leader_exit(self) -> None:
        marker = self.root / "chdir-closed-stdio-descendant"
        descendant = (
            "import os, time; from pathlib import Path; os.chdir('/tmp'); time.sleep(4); "
            f"Path({str(marker)!r}).write_text('survived')"
        )
        launched, metadata = self.runbg(
            "--timeout",
            "10",
            "--",
            sys.executable,
            "-c",
            (
                "import subprocess, sys; "
                f"subprocess.Popen([sys.executable, '-c', {descendant!r}], "
                "stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL); "
                "__import__('time').sleep(0.2)"
            ),
        )
        self.assertEqual(launched.returncode, 0, launched.stderr)
        terminal = self.wait_for_job_terminal(metadata, timeout=8)
        self.assertEqual(terminal["status"], "closed")
        self.assertEqual(terminal["termination"], "capture_error")
        time.sleep(4.25)
        self.assertFalse(marker.exists(), "chdir descendant escaped group cleanup")

    def test_job_kill_escalates_term_resistant_job_before_closure(self) -> None:
        launched, metadata = self.runbg(
            "--timeout",
            "20",
            "--",
            sys.executable,
            "-c",
            (
                "import signal, time; "
                "signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(60)"
            ),
        )
        self.assertEqual(launched.returncode, 0, launched.stderr)
        killed = subprocess.run(
            [
                str(self.root / "bin" / "rookery-accelerators"),
                "job-kill",
                str(metadata["job_id"]),
            ],
            cwd=self.root,
            env=self.environment,
            text=True,
            capture_output=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(killed.returncode, 0, killed.stderr)
        result = json.loads(killed.stdout)
        self.assertEqual(result["status"], "closed")
        terminal = self.wait_for_job_terminal(metadata)
        self.assertEqual(terminal["status"], "closed")
        deadline = time.monotonic() + 5
        while (
            (Path("/proc") / str(metadata["supervisor_pid"])).exists()
            and time.monotonic() < deadline
        ):
            time.sleep(0.05)
        self.assertFalse((Path("/proc") / str(metadata["pid"])).exists())
        self.assertFalse((Path("/proc") / str(metadata["supervisor_pid"])).exists())
        self.assertFalse(EventStore(self.root).events("job.unacknowledged"))

    def test_job_kill_closes_exact_chdir_job(self) -> None:
        launched, metadata = self.runbg(
            "--timeout",
            "20",
            "--",
            sys.executable,
            "-c",
            "import os, time; os.chdir('/tmp'); time.sleep(60)",
        )
        self.assertEqual(launched.returncode, 0, launched.stderr)
        killed = subprocess.run(
            [
                str(self.root / "bin" / "rookery-accelerators"),
                "job-kill",
                str(metadata["job_id"]),
            ],
            cwd=self.root,
            env=self.environment,
            text=True,
            capture_output=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(killed.returncode, 0, killed.stderr)
        terminal = self.wait_for_job_terminal(metadata)
        self.assertEqual(terminal["status"], "closed")
        self.assertFalse((Path("/proc") / str(metadata["pid"])).exists())

    def test_job_kill_closes_exact_exec_job_and_refuses_stable_proof_mismatches(
        self,
    ) -> None:
        launched, metadata = self.runbg(
            "--timeout",
            "20",
            "--",
            sys.executable,
            "-c",
            (
                "import os, time; time.sleep(0.4); "
                "os.execv('/usr/bin/sleep', ['sleep', '60'])"
            ),
        )
        self.assertEqual(launched.returncode, 0, launched.stderr)
        pid = int(metadata["pid"])
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            argv = (Path("/proc") / str(pid) / "cmdline").read_bytes().split(b"\0")
            if argv and argv[0] == b"sleep":
                break
            time.sleep(0.02)
        self.assertEqual(argv[0], b"sleep")
        self.assertTrue(process_identity_matches(self.root, metadata))
        for field, value in (
            ("process_starttime", "0"),
            ("pgid", int(metadata["pgid"]) + 1),
            ("workspace_root_sha256", "0" * 64),
            ("owner_token_sha256", "0" * 64),
        ):
            with self.subTest(field=field):
                mismatched = {**metadata, field: value}
                self.assertFalse(process_identity_matches(self.root, mismatched))
        killed = subprocess.run(
            [
                str(self.root / "bin" / "rookery-accelerators"),
                "job-kill",
                str(metadata["job_id"]),
            ],
            cwd=self.root,
            env=self.environment,
            text=True,
            capture_output=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(killed.returncode, 0, killed.stderr)
        terminal = self.wait_for_job_terminal(metadata)
        self.assertEqual(terminal["status"], "closed")
        self.assertFalse((Path("/proc") / str(pid)).exists())

    def test_stop_cancels_exact_chdir_job(self) -> None:
        launched, metadata = self.runbg(
            "--timeout",
            "20",
            "--",
            sys.executable,
            "-c",
            "import os, time; os.chdir('/tmp'); time.sleep(60)",
        )
        self.assertEqual(launched.returncode, 0, launched.stderr)
        stopped = stop(
            EventStore(self.root),
            self.root,
            reason="chdir ownership regression",
            wait_seconds=0.5,
        )
        self.assertEqual(stopped["confirmed_cancelled"], [metadata["job_id"]])
        self.assertFalse(stopped["unmanaged"])
        self.assertFalse(stopped["unacknowledged"])
        self.assertFalse((Path("/proc") / str(metadata["pid"])).exists())
        deadline = time.monotonic() + 5
        while (
            (Path("/proc") / str(metadata["supervisor_pid"])).exists()
            and time.monotonic() < deadline
        ):
            time.sleep(0.05)
        self.assertFalse((Path("/proc") / str(metadata["supervisor_pid"])).exists())

    def test_unmanaged_live_job_remains_capacity_blocking(self) -> None:
        (self.root / "state/resolved_event.json").write_text(
            json.dumps({"concurrency": {"max_jobs": 1}}), encoding="utf-8"
        )
        launched, metadata = self.runbg(
            "--timeout",
            "20",
            "--",
            sys.executable,
            "-c",
            "import time; time.sleep(60)",
        )
        self.assertEqual(launched.returncode, 0, launched.stderr)
        meta_path = self.root / str(metadata["report_path"]) / "meta.json"
        corrupted = json.loads(meta_path.read_text(encoding="utf-8"))
        corrupted["workspace_root_sha256"] = "0" * 64
        meta_path.write_text(json.dumps(corrupted), encoding="utf-8")
        try:
            killed = subprocess.run(
                [
                    str(self.root / "bin" / "rookery-accelerators"),
                    "job-kill",
                    str(metadata["job_id"]),
                ],
                cwd=self.root,
                env=self.environment,
                text=True,
                capture_output=True,
                timeout=10,
                check=False,
            )
            self.assertEqual(killed.returncode, 2, killed.stderr)
            result = json.loads(killed.stdout)
            self.assertEqual(result["status"], "unmanaged")
            self.assertTrue((Path("/proc") / str(metadata["pid"])).exists())
            self.assertFalse(EventStore(self.root).events("job.closed"))
            self.assertEqual(
                EventStore(self.root).events("job.unmanaged")[-1]["payload"]["job_id"],
                metadata["job_id"],
            )
            marker = self.root / "capacity-after-unmanaged"
            rejected, payload = self.runbg(
                "--",
                sys.executable,
                "-c",
                f"from pathlib import Path; Path({str(marker)!r}).touch()",
            )
            self.assertEqual(rejected.returncode, 3, rejected.stderr)
            self.assertEqual(payload["status"], "capacity_rejected")
            self.assertEqual(payload["active_jobs"], 1)
            self.assertFalse(marker.exists())
            self.assertEqual(len(EventStore(self.root).events("job.running")), 1)
        finally:
            try:
                os.killpg(int(metadata["pgid"]), signal.SIGKILL)
            except ProcessLookupError:
                pass
            deadline = time.monotonic() + 5
            while (
                (Path("/proc") / str(metadata["supervisor_pid"])).exists()
                and time.monotonic() < deadline
            ):
                time.sleep(0.05)

    def test_runbg_stop_race_reconciles_the_reserved_exact_identity(self) -> None:
        marker = self.root / "post-stop-runbg-marker"
        launcher = subprocess.Popen(
            [
                str(self.root / "bin" / "runbg"),
                "--",
                sys.executable,
                "-c",
                (
                    "import time; from pathlib import Path; "
                    f"time.sleep(2); Path({str(marker)!r}).touch()"
                ),
            ],
            cwd=self.root,
            env=self.environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        stop_result: dict[str, object] = {}
        stop_thread: threading.Thread | None = None
        try:
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                if EventStore(self.root).events("job.starting"):
                    stop_thread = threading.Thread(
                        target=lambda: stop_result.update(
                            stop(
                                EventStore(self.root),
                                self.root,
                                reason="runbg reservation race",
                                wait_seconds=0.5,
                            )
                        ),
                        daemon=True,
                    )
                    stop_thread.start()
                    break
                time.sleep(0.01)
            self.assertIsNotNone(stop_thread, "runbg did not reserve a job")
            stdout, stderr = launcher.communicate(timeout=10)
            self.assertEqual(launcher.returncode, 0, stderr)
            metadata = json.loads(stdout)
            stop_thread.join(timeout=10)
            self.assertTrue(stop_result)
            self.assertIn(metadata["job_id"], stop_result["confirmed_cancelled"])
            self.assertFalse(marker.exists())
        finally:
            if launcher.poll() is None:
                launcher.kill()
            if stop_thread is not None:
                stop_thread.join(timeout=2)

    def test_runbg_rejects_out_of_bounds_lifetime_and_output_before_admission(self) -> None:
        marker = self.root / "runbg-limit-marker"
        before = EventStore(self.root).count()
        invalid = (
            ("--timeout", "0"),
            ("--timeout", str(24 * 60 * 60 + 1)),
            ("--max-output-bytes", "0"),
            ("--max-output-bytes", str(64 * 1024 * 1024 + 1)),
        )
        for arguments in invalid:
            with self.subTest(arguments=arguments):
                completed = subprocess.run(
                    [
                        str(self.root / "bin" / "runbg"),
                        *arguments,
                        "--",
                        sys.executable,
                        "-c",
                        f"from pathlib import Path; Path({str(marker)!r}).touch()",
                    ],
                    cwd=self.root,
                    env=self.environment,
                    text=True,
                    capture_output=True,
                    timeout=10,
                    check=False,
                )
                self.assertNotEqual(completed.returncode, 0)
                self.assertFalse(marker.exists())
                self.assertEqual(EventStore(self.root).count(), before)

    def test_run_ledger_blocks_duplicate_without_force(self) -> None:
        command = [sys.executable, "-c", "print('fixture')"]

        def run_ledger(*extra: str) -> subprocess.CompletedProcess[str]:
            return subprocess.run(
                [
                    str(self.root / "bin/run-ledger"),
                    *extra,
                    "scope-fixture",
                    "--",
                    *command,
                ],
                cwd=self.root,
                env=self.environment,
                text=True,
                capture_output=True,
                timeout=30,
                check=False,
            )

        first = run_ledger()
        duplicate = run_ledger()
        forced = run_ledger("--force")

        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(duplicate.returncode, 3)
        self.assertIn("duplicate normalized command family", duplicate.stdout)
        self.assertEqual(forced.returncode, 0, forced.stderr)
        command_dirs = list((self.root / "logs/commands").iterdir())
        self.assertEqual(len(command_dirs), 2)
        rows = [
            json.loads(line)
            for line in (self.root / "research/run-ledger.jsonl")
            .read_text(encoding="utf-8")
            .splitlines()
        ]
        self.assertEqual(len(rows), 3)
        self.assertEqual(sum(1 for row in rows if row.get("blocked")), 1)

    def test_runbg_enforces_job_capacity_before_spawn(self) -> None:
        marker = self.root / "should-not-run"
        store = EventStore(self.root)
        store.append(
            "job.running",
            {"job_id": "existing", "status": "running"},
            actor="fixture",
        )
        store.rebuild()
        state = self.root / "state/resolved_event.json"
        state.write_text(
            json.dumps({"concurrency": {"max_jobs": 1}}),
            encoding="utf-8",
        )
        result = subprocess.run(
            [
                str(self.root / "bin/runbg"),
                "--",
                sys.executable,
                "-c",
                f"from pathlib import Path; Path({str(marker)!r}).touch()",
            ],
            cwd=self.root,
            env=self.environment,
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )

        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertFalse(marker.exists())
        payload = json.loads(result.stdout)
        self.assertEqual(payload["status"], "capacity_rejected")
        self.assertEqual(payload["active_jobs"], 1)
        self.assertEqual(payload["max_jobs"], 1)
        self.assertEqual(len(EventStore(self.root).events("job.capacity_rejected")), 1)

    def test_runbg_capacity_reservation_is_atomic_for_two_callers(self) -> None:
        state = self.root / "state/resolved_event.json"
        state.write_text(
            json.dumps({"concurrency": {"max_jobs": 1}}), encoding="utf-8"
        )
        command = [
            "--",
            sys.executable,
            "-c",
            "import time; time.sleep(30)",
        ]
        callers = [
            subprocess.Popen(
                [str(self.root / "bin" / "runbg"), *command],
                cwd=self.root,
                env=self.environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            for _ in range(2)
        ]
        results: list[tuple[subprocess.Popen[str], dict[str, object]]] = []
        try:
            for caller in callers:
                stdout, stderr = caller.communicate(timeout=10)
                self.assertTrue(stdout, stderr)
                results.append((caller, json.loads(stdout)))
            admitted = [payload for caller, payload in results if caller.returncode == 0]
            rejected = [payload for caller, payload in results if caller.returncode == 3]
            self.assertEqual(len(admitted), 1)
            self.assertEqual(len(rejected), 1)
            self.assertEqual(rejected[0]["status"], "capacity_rejected")
            self.assertEqual(len(EventStore(self.root).events("job.running")), 1)
        finally:
            for _caller, payload in results:
                if payload.get("status") != "running":
                    continue
                try:
                    os.killpg(int(payload["pgid"]), signal.SIGTERM)
                except ProcessLookupError:
                    pass
                self.wait_for_job_terminal(payload)


if __name__ == "__main__":
    unittest.main(verbosity=2)
