from __future__ import annotations

# ruff: noqa: E402

import json
import os
import signal
import sqlite3
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
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

from rookery.portable.store import EventStore
from rookery.portable.watchers import ensure_queue_watcher


@unittest.skipUnless(os.name == "posix", "requires POSIX filesystem modes")
class PrivateRuntimeModeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.original_umask = os.umask(0o022)
        self.temporary = tempfile.TemporaryDirectory()
        self.external_temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.external_root = Path(self.external_temporary.name)
        copy_rookery(self.root)
        self.environment = {
            **os.environ,
            "PYTHONPATH": str(self.root / "lib"),
            "PYTHONDONTWRITEBYTECODE": "1",
        }

    def tearDown(self) -> None:
        try:
            self.temporary.cleanup()
        finally:
            try:
                self.external_temporary.cleanup()
            finally:
                try:
                    self.baseline.cleanup()
                except AttributeError:
                    pass
                finally:
                    os.umask(self.original_umask)

    def assert_mode(self, path: Path, expected: int) -> None:
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), expected, path)

    def assert_descriptor_mode(self, descriptor: int, expected: int) -> None:
        self.assertEqual(stat.S_IMODE(os.fstat(descriptor).st_mode), expected)

    def external_database(
        self, name: str, *, directory: Path | None = None
    ) -> tuple[Path, bytes, int, str]:
        path = (directory or self.external_root) / f"{name}.sqlite3"
        table = f"external_{name}"
        connection = sqlite3.connect(path)
        try:
            connection.execute(f"CREATE TABLE {table} (value TEXT)")
            connection.execute(f"INSERT INTO {table}(value) VALUES('unchanged')")
            connection.commit()
        finally:
            connection.close()
        path.chmod(0o644)
        return path, path.read_bytes(), stat.S_IMODE(path.stat().st_mode), table

    def assert_external_database_unchanged(
        self, path: Path, expected_bytes: bytes, expected_mode: int, table: str
    ) -> None:
        self.assertEqual(path.read_bytes(), expected_bytes)
        self.assert_mode(path, expected_mode)
        connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        try:
            tables = connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
            ).fetchall()
            self.assertEqual(tables, [(table,)])
        finally:
            connection.close()

    def initialize_store(self) -> EventStore:
        # These direct EventStore cases are deliberately uninstalled unit
        # fixtures. Public command cases below use the real go/bootstrap path.
        (self.root / "VERSION").unlink(missing_ok=True)
        store = EventStore(self.root)
        store.append("privacy.fixture", {"candidate": "private"})
        store.rebuild()
        return store

    @staticmethod
    def remove_path(path: Path) -> None:
        if path.is_dir() and not path.is_symlink():
            path.rmdir()
        else:
            path.unlink(missing_ok=True)

    def test_fresh_event_store_and_projections_are_private(self) -> None:
        self.initialize_store()

        state = self.root / "state"
        self.assert_mode(state, 0o700)
        self.assert_mode(state / "events.sqlite3", 0o600)
        for name in (
            "events.jsonl",
            "runtime.json",
            "current.json",
            "policy_effective.json",
            "queue_state.json",
        ):
            self.assert_mode(state / name, 0o600)

    def test_existing_state_migration_preserves_bytes_and_wal_access(self) -> None:
        self.initialize_store()
        state = self.root / "state"
        main = state / "events.sqlite3"
        projections = [
            state / "events.jsonl",
            state / "runtime.json",
            state / "current.json",
            state / "policy_effective.json",
            state / "queue_state.json",
        ]
        state.chmod(0o755)
        for path in [main, *projections]:
            path.chmod(0o644)

        connection = sqlite3.connect(main, timeout=30, isolation_level=None)
        try:
            journal_mode = connection.execute("PRAGMA journal_mode=WAL").fetchone()[0]
            self.assertEqual(journal_mode, "wal")
            connection.execute(
                "CREATE TABLE IF NOT EXISTS permission_fixture (value TEXT)"
            )
            connection.execute("INSERT INTO permission_fixture(value) VALUES('ok')")
            artifacts = [
                main,
                main.with_name(main.name + "-wal"),
                main.with_name(main.name + "-shm"),
            ]
            for path in artifacts:
                self.assertTrue(path.is_file(), path)
                path.chmod(0o644)
            bytes_before = {path: path.read_bytes() for path in [main, *projections]}

            migrated = EventStore(self.root)

            self.assert_mode(state, 0o700)
            for path in artifacts:
                self.assert_mode(path, 0o600)
            for path in projections:
                self.assert_mode(path, 0o600)
            self.assertEqual(
                bytes_before,
                {path: path.read_bytes() for path in [main, *projections]},
            )

            migrated.append("privacy.concurrent", {"result": "still-writable"})
            count = connection.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            self.assertGreaterEqual(count, 2)
            for path in artifacts:
                self.assert_mode(path, 0o600)
        finally:
            connection.close()

    def test_state_directory_links_fail_without_touching_external_directory(self) -> None:
        # This is the EventStore's isolated storage-contract fixture, not a
        # public command launch; suppress the installed-workspace gate so the
        # test reaches the link defense it is asserting.
        (self.root / "VERSION").unlink()
        state = self.root / "state"
        external = self.external_root / "state-target"
        external.mkdir(mode=0o755)
        marker = external / "marker.txt"
        marker.write_bytes(b"outside state")
        marker.chmod(0o644)
        expected_bytes = marker.read_bytes()
        expected_mode = stat.S_IMODE(external.stat().st_mode)
        database, database_bytes, database_mode, table = self.external_database(
            "state_target", directory=external
        )
        state.symlink_to(external, target_is_directory=True)

        with self.assertRaises(OSError):
            EventStore(self.root)

        self.assert_mode(external, expected_mode)
        self.assertEqual(marker.read_bytes(), expected_bytes)
        self.assert_mode(marker, 0o644)
        self.assert_external_database_unchanged(
            database, database_bytes, database_mode, table
        )
        state.unlink()
        state.symlink_to(self.external_root / "missing-state", target_is_directory=True)
        with self.assertRaises(OSError):
            EventStore(self.root)

    def test_database_links_and_special_files_fail_without_external_writes(self) -> None:
        self.initialize_store()
        main = self.root / "state" / "events.sqlite3"
        external, expected_bytes, expected_mode, table = self.external_database("main")
        self.remove_path(main)
        main.symlink_to(external)
        with self.assertRaises(OSError):
            EventStore(self.root)
        self.assert_external_database_unchanged(
            external, expected_bytes, expected_mode, table
        )

        main.unlink()
        main.symlink_to(self.external_root / "missing-main")
        with self.assertRaises(OSError):
            EventStore(self.root)

        main.unlink()
        os.mkfifo(main, 0o600)
        with self.assertRaises(OSError):
            EventStore(self.root)
        main.unlink()
        main.mkdir(mode=0o700)
        with self.assertRaises(OSError):
            EventStore(self.root)

    def test_sidecar_and_projection_links_are_rejected_without_external_writes(
        self,
    ) -> None:
        self.initialize_store()
        state = self.root / "state"
        main = state / "events.sqlite3"
        for suffix in ("-wal", "-shm"):
            sidecar = main.with_name(main.name + suffix)
            self.remove_path(sidecar)
            external, expected_bytes, expected_mode, table = self.external_database(
                suffix.removeprefix("-")
            )
            sidecar.symlink_to(external)
            with self.assertRaises(OSError):
                EventStore(self.root)
            self.assert_external_database_unchanged(
                external, expected_bytes, expected_mode, table
            )
            sidecar.unlink()
            sidecar.symlink_to(self.external_root / f"missing{suffix}")
            with self.assertRaises(OSError):
                EventStore(self.root)
            sidecar.unlink()
            os.mkfifo(sidecar, 0o600)
            with self.assertRaises(OSError):
                EventStore(self.root)
            sidecar.unlink()

        EventStore(self.root)
        for name in (
            "events.jsonl",
            "runtime.json",
            "current.json",
            "policy_effective.json",
            "queue_state.json",
        ):
            projection = state / name
            self.remove_path(projection)
            external, expected_bytes, expected_mode, table = self.external_database(
                name.replace(".", "_")
            )
            projection.symlink_to(external)
            with self.assertRaises(OSError):
                EventStore(self.root)
            self.assert_external_database_unchanged(
                external, expected_bytes, expected_mode, table
            )
            projection.unlink()
            projection.symlink_to(self.external_root / f"missing-{name}")
            with self.assertRaises(OSError):
                EventStore(self.root)
            projection.unlink()
            os.mkfifo(projection, 0o600)
            with self.assertRaises(OSError):
                EventStore(self.root)
            projection.unlink()
            EventStore(self.root).rebuild()

    def test_runq_runbg_and_watcher_paths_are_private(self) -> None:
        self.baseline = bootstrap_public_accelerator_workspace(self.root)
        logs = self.root / "logs"
        commands = logs / "commands"
        jobs = logs / "jobs"
        commands.mkdir(parents=True)
        jobs.mkdir(parents=True)
        logs.chmod(0o755)
        commands.chmod(0o755)
        jobs.chmod(0o755)

        runq = subprocess.run(
            [
                str(self.root / "bin" / "runq"),
                "--",
                sys.executable,
                "-c",
                "print('private runq')",
            ],
            cwd=self.root,
            env=self.environment,
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(runq.returncode, 0, runq.stderr)
        runq_meta = json.loads(runq.stdout)
        command_dir = self.root / Path(str(runq_meta["stdout_path"])).parent
        for path in [logs, commands, command_dir]:
            self.assert_mode(path, 0o700)
        for name in ("stdout.log", "stderr.log", "digest.json", "meta.json"):
            self.assert_mode(command_dir / name, 0o600)

        runbg = subprocess.run(
            [
                str(self.root / "bin" / "runbg"),
                "--",
                sys.executable,
                "-c",
                "import time; time.sleep(30)",
            ],
            cwd=self.root,
            env=self.environment,
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(runbg.returncode, 0, runbg.stderr)
        runbg_meta = json.loads(runbg.stdout)
        job_dir = self.root / str(runbg_meta["report_path"])
        try:
            for path in [logs, jobs, job_dir]:
                self.assert_mode(path, 0o700)
            for name in ("stdout.log", "stderr.log", "meta.json"):
                self.assert_mode(job_dir / name, 0o600)
        finally:
            try:
                os.killpg(int(runbg_meta["pgid"]), signal.SIGTERM)
            except ProcessLookupError:
                pass

        observed_handles: list[object] = []

        class FakeProcess:
            pid = os.getpid()
            returncode: int | None = None

            def poll(self) -> None:
                return None

        def fake_popen(*_args: object, **kwargs: object) -> FakeProcess:
            stdout = kwargs["stdout"]
            stderr = kwargs["stderr"]
            self.assert_descriptor_mode(stdout.fileno(), 0o600)
            self.assert_descriptor_mode(stderr.fileno(), 0o600)
            observed_handles.extend([stdout, stderr])
            return FakeProcess()

        watcher_store = EventStore(self.root)
        with (
            mock.patch("rookery.portable.watchers.subprocess.Popen", fake_popen),
            mock.patch(
                "rookery.portable.watchers.process_identity_matches",
                return_value=True,
            ),
        ):
            watcher = ensure_queue_watcher(
                watcher_store,
                self.root,
                {"queue": {"automation_enabled": True, "watch_interval_seconds": 1}},
            )

        self.assertTrue(watcher["running"])
        queue_watch = logs / "queue-watch"
        for path in [logs, queue_watch]:
            self.assert_mode(path, 0o700)
        for name in ("stdout.log", "stderr.log"):
            self.assert_mode(queue_watch / name, 0o600)
        self.assertTrue(all(handle.closed for handle in observed_handles))


if __name__ == "__main__":
    unittest.main(verbosity=2)
