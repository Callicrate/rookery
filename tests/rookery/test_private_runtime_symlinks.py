from __future__ import annotations

import os
import runpy
import sqlite3
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests.rookery.env_fixtures import configure_event_environment
from tests.rookery.support import (
    ROOKERY_ROOT,
    copy_non_deployed_rookery,
    install_test_launch_binding,
    open_test_event_store,
)

LIB = ROOKERY_ROOT / "lib"
if str(LIB) not in sys.path:
    sys.path.insert(0, str(LIB))
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

from rookery.portable.watchers import ensure_queue_watcher  # noqa: E402


@unittest.skipUnless(os.name == "posix", "requires POSIX filesystem modes")
class PrivateRuntimeSymlinkTests(unittest.TestCase):
    def setUp(self) -> None:
        self.original_umask = os.umask(0o022)
        self.temporary = tempfile.TemporaryDirectory()
        self.external_temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.external_root = Path(self.external_temporary.name)
        copy_non_deployed_rookery(self.root)
        configure_event_environment(self.root, "manual", name_suffix="Symlink Safety")
        install_test_launch_binding(self.root)
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
                os.umask(self.original_umask)

    def assert_mode(self, path: Path, expected: int) -> None:
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), expected, path)

    def external_file(self, name: str) -> tuple[Path, bytes, int]:
        path = self.external_root / name
        path.write_bytes(b"outside bytes must remain unchanged")
        path.chmod(0o644)
        return path, path.read_bytes(), stat.S_IMODE(path.stat().st_mode)

    def external_database(self, name: str) -> tuple[Path, bytes, int]:
        path = self.external_root / f"{name}.sqlite3"
        connection = sqlite3.connect(path)
        try:
            connection.execute("CREATE TABLE protected_data (value TEXT)")
            connection.execute("INSERT INTO protected_data(value) VALUES('unchanged')")
            connection.commit()
        finally:
            connection.close()
        path.chmod(0o644)
        return path, path.read_bytes(), stat.S_IMODE(path.stat().st_mode)

    def assert_external_file_unchanged(
        self, path: Path, expected_bytes: bytes, expected_mode: int
    ) -> None:
        self.assertEqual(path.read_bytes(), expected_bytes)
        self.assert_mode(path, expected_mode)

    def accelerators(self) -> dict[str, object]:
        namespace = runpy.run_path(str(self.root / "bin" / "rookery-accelerators"))
        namespace["ROOT"] = self.root
        return namespace

    def run_helper(self, relative: str, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(self.root / relative), *arguments],
            cwd=self.root,
            env=self.environment,
            text=True,
            capture_output=True,
            timeout=20,
        )

    def assert_watcher_rejects(self, path: Path) -> None:
        target = self.external_root / f"{path.name}-target"
        target.mkdir(mode=0o755)
        marker = target / "marker.txt"
        marker.write_bytes(b"watcher target")
        marker.chmod(0o644)
        expected_dir_mode = stat.S_IMODE(target.stat().st_mode)
        expected_bytes = marker.read_bytes()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.symlink_to(target, target_is_directory=True)
        store = open_test_event_store(self.root)
        with mock.patch(
            "rookery.portable.watchers.subprocess.Popen",
            side_effect=AssertionError("unsafe watcher path reached process spawn"),
        ):
            with self.assertRaises(OSError):
                ensure_queue_watcher(
                    store,
                    self.root,
                    {"queue": {"automation_enabled": True, "watch_interval_seconds": 1}},
                )
        self.assert_mode(target, expected_dir_mode)
        self.assertEqual(marker.read_bytes(), expected_bytes)
        self.assert_mode(marker, 0o644)

    def test_existing_normal_paths_migrate_without_rewriting(self) -> None:
        namespace = self.accelerators()
        directory = self.root / "logs" / "commands"
        directory.mkdir(parents=True, mode=0o777)
        directory.chmod(0o777)
        artifact = directory / "existing.log"
        artifact.write_bytes(b"retained bytes")
        artifact.chmod(0o666)

        namespace["_ensure_private_directory"](directory)
        namespace["_ensure_private_file"](artifact)
        with namespace["_open_private_append"](artifact) as handle:
            handle.write(b"+")

        self.assert_mode(self.root / "logs", 0o700)
        self.assert_mode(directory, 0o700)
        self.assert_mode(artifact, 0o600)
        self.assertEqual(artifact.read_bytes(), b"retained bytes+")

    def test_accelerators_reject_symlinked_logs_jobs_and_streams(self) -> None:
        log_target = self.external_root / "logs-target"
        log_target.mkdir(mode=0o755)
        log_marker = log_target / "marker.txt"
        log_marker.write_bytes(b"outside logs")
        log_marker.chmod(0o644)
        log_dir_mode = stat.S_IMODE(log_target.stat().st_mode)
        self.root.joinpath("logs").symlink_to(log_target, target_is_directory=True)

        runq = self.run_helper(
            "bin/runq", "--", sys.executable, "-c", "print('must not run')"
        )
        self.assertNotEqual(runq.returncode, 0)
        self.assert_mode(log_target, log_dir_mode)
        self.assertEqual(log_marker.read_bytes(), b"outside logs")
        self.assert_mode(log_marker, 0o644)
        (self.root / "logs").unlink()

        jobs_target = self.external_root / "jobs-target"
        jobs_target.mkdir(mode=0o755)
        jobs_marker = jobs_target / "marker.txt"
        jobs_marker.write_bytes(b"outside jobs")
        jobs_marker.chmod(0o644)
        jobs_dir_mode = stat.S_IMODE(jobs_target.stat().st_mode)
        (self.root / "logs").mkdir()
        (self.root / "logs" / "jobs").symlink_to(jobs_target, target_is_directory=True)

        runbg = self.run_helper(
            "bin/runbg", "--", sys.executable, "-c", "print('must not run')"
        )
        self.assertNotEqual(runbg.returncode, 0)
        self.assert_mode(jobs_target, jobs_dir_mode)
        self.assertEqual(jobs_marker.read_bytes(), b"outside jobs")
        self.assert_mode(jobs_marker, 0o644)
        (self.root / "logs" / "jobs").unlink()

        namespace = self.accelerators()
        job_dir = self.root / "logs" / "jobs" / "job-fixture"
        job_dir.mkdir(parents=True)
        for name in ("stdout.log", "stderr.log"):
            with self.subTest(name=name):
                target, expected_bytes, expected_mode = self.external_file(name)
                stream = job_dir / name
                stream.symlink_to(target)
                with self.assertRaises(OSError):
                    namespace["_open_private_append"](stream)
                self.assert_external_file_unchanged(target, expected_bytes, expected_mode)
                stream.unlink()

        broken = job_dir / "broken.log"
        broken.symlink_to(self.external_root / "missing-log")
        with self.assertRaises(OSError):
            namespace["_open_private_append"](broken)
        broken.unlink()
        fifo = job_dir / "stream.fifo"
        os.mkfifo(fifo, 0o600)
        with self.assertRaises(OSError):
            namespace["_open_private_append"](fifo)

    def test_watcher_rejects_symlinked_queue_watch_roots_and_logs(self) -> None:
        self.assert_watcher_rejects(self.root / "logs")
        (self.root / "logs").unlink()
        (self.root / "logs").mkdir()
        self.assert_watcher_rejects(self.root / "logs" / "queue-watch")
        (self.root / "logs" / "queue-watch").unlink()

        queue_watch = self.root / "logs" / "queue-watch"
        queue_watch.mkdir()
        store = open_test_event_store(self.root)
        for name in ("stdout.log", "stderr.log"):
            with self.subTest(name=name):
                target, expected_bytes, expected_mode = self.external_file(
                    f"queue-{name}"
                )
                stream = queue_watch / name
                stream.symlink_to(target)
                with mock.patch(
                    "rookery.portable.watchers.subprocess.Popen",
                    side_effect=AssertionError("unsafe watcher log reached process spawn"),
                ):
                    with self.assertRaises(OSError):
                        ensure_queue_watcher(
                            store,
                            self.root,
                            {
                                "queue": {
                                    "automation_enabled": True,
                                    "watch_interval_seconds": 1,
                                }
                            },
                        )
                self.assert_external_file_unchanged(target, expected_bytes, expected_mode)
                stream.unlink()

    def test_knowledge_database_symlink_and_special_files_are_rejected(self) -> None:
        database, expected_bytes, expected_mode = self.external_database("knowledge")
        knowledge = self.root / "knowledge"
        local_database = knowledge / "ctf_knowledge.sqlite3"
        local_database.symlink_to(database)

        linked = self.run_helper("bin/knowledge", "status")
        self.assertNotEqual(linked.returncode, 0)
        self.assert_external_file_unchanged(database, expected_bytes, expected_mode)
        local_database.unlink()

        local_database.symlink_to(self.external_root / "missing-knowledge.sqlite3")
        broken = self.run_helper("bin/knowledge", "status")
        self.assertNotEqual(broken.returncode, 0)
        local_database.unlink()

        os.mkfifo(local_database, 0o600)
        special = self.run_helper("bin/knowledge", "status")
        self.assertNotEqual(special.returncode, 0)
        local_database.unlink()

        namespace = self.accelerators()
        namespace["_ensure_private_file"](local_database)
        for suffix in ("-wal", "-shm"):
            with self.subTest(suffix=suffix):
                sidecar, sidecar_bytes, sidecar_mode = self.external_file(
                    f"knowledge{suffix}"
                )
                linked_sidecar = local_database.with_name(local_database.name + suffix)
                linked_sidecar.symlink_to(sidecar)
                with self.assertRaises(OSError):
                    namespace["_tighten_sqlite_artifacts"](local_database)
                self.assert_external_file_unchanged(
                    sidecar, sidecar_bytes, sidecar_mode
                )
                linked_sidecar.unlink()


if __name__ == "__main__":
    unittest.main(verbosity=2)
