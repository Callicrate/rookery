from __future__ import annotations

import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests.rookery.support import ROOKERY_ROOT

LIB = ROOKERY_ROOT / "lib"
if str(LIB) not in sys.path:
    sys.path.insert(0, str(LIB))
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

from rookery.portable.adapters import capture_file  # noqa: E402
from rookery.portable.cli import ensure_runtime_dirs  # noqa: E402
from rookery.portable.owned_paths import objective_storage_component  # noqa: E402
from rookery.portable.preparation import (  # noqa: E402
    APPROVED_MANAGED_SEARXNG_IMAGE,
    _prepare_searxng,
)
from rookery.portable.store import EventStore  # noqa: E402
from rookery.portable.util import (  # noqa: E402
    ensure_private_dir,
    ensure_private_file,
)
from rookery.portable.writeups import create_capsule, create_writeup  # noqa: E402


PRIVATE_DIRS = (
    "state",
    "state/execution_plans",
    "state/challenges",
    "state/platform",
    "analysis",
    "evidence",
    "submissions",
    "submissions/executions",
    "submissions/proposals",
    "platform",
    "platform/runtime",
    "platform/challenges",
    "work",
    "writeups",
    "control",
    "logs",
    "research",
    "candidates",
    "exploit",
    "captures",
    "downloads",
    "handoffs",
)
PRIVATE_LEDGERS = ("STATUS.md", "FINDINGS.md", "FLAGS.md", "DEAD_PATHS.md")


@unittest.skipUnless(os.name == "posix", "requires POSIX filesystem modes")
class PrivateCoreModeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.original_umask = os.umask(0o022)
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        try:
            self.temporary.cleanup()
        finally:
            os.umask(self.original_umask)

    def assert_mode(self, path: Path, expected: int) -> None:
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), expected, path)

    def snapshot_tree(self, root: Path) -> dict[str, tuple[int, bytes | None]]:
        snapshot = {}
        for path in [root, *sorted(root.rglob("*"))]:
            info = path.lstat()
            relative = "." if path == root else path.relative_to(root).as_posix()
            content = path.read_bytes() if stat.S_ISREG(info.st_mode) else None
            snapshot[relative] = (stat.S_IMODE(info.st_mode), content)
        return snapshot

    def test_runtime_bootstrap_fresh_paths_are_private(self) -> None:
        ensure_runtime_dirs(self.root)

        for relative in PRIVATE_DIRS:
            self.assert_mode(self.root / relative, 0o700)
        for name in PRIVATE_LEDGERS:
            self.assert_mode(self.root / name, 0o600)
        self.assertFalse((self.root / ".env").exists())

    def test_runtime_migration_preserves_bytes_and_public_docs(self) -> None:
        for relative in PRIVATE_DIRS:
            (self.root / relative).mkdir(parents=True, exist_ok=True)
        for relative in PRIVATE_DIRS:
            (self.root / relative).chmod(0o777)

        private_files = [self.root / name for name in PRIVATE_LEDGERS]
        private_files.append(self.root / ".env")
        for index, path in enumerate(private_files):
            path.write_bytes(f"private-{index}\x00\xff".encode("latin-1"))
            path.chmod(0o666)
        bytes_before = {path: path.read_bytes() for path in private_files}

        public_docs = [self.root / "PREPARATION.md", self.root / "NEW_CTF_SETUP.md"]
        for path in public_docs:
            path.write_text("public setup\n", encoding="utf-8")
            path.chmod(0o666)

        ensure_runtime_dirs(self.root)

        for relative in PRIVATE_DIRS:
            self.assert_mode(self.root / relative, 0o700)
        for path in private_files:
            self.assert_mode(path, 0o600)
            self.assertEqual(path.read_bytes(), bytes_before[path])
        for path in public_docs:
            self.assert_mode(path, 0o666)

    def test_private_primitives_refuse_symlinks_and_nonregular_files(self) -> None:
        target_dir = self.root / "target-dir"
        target_dir.mkdir()
        target_dir.chmod(0o777)
        linked_dir = self.root / "linked-dir"
        linked_dir.symlink_to(target_dir, target_is_directory=True)
        with self.assertRaises(OSError):
            ensure_private_dir(linked_dir)
        self.assert_mode(target_dir, 0o777)

        target_file = self.root / "target-file"
        target_file.write_bytes(b"unchanged\x00bytes")
        target_file.chmod(0o666)
        linked_file = self.root / "linked-file"
        linked_file.symlink_to(target_file)
        with self.assertRaises(OSError):
            ensure_private_file(linked_file)
        self.assert_mode(target_file, 0o666)
        self.assertEqual(target_file.read_bytes(), b"unchanged\x00bytes")

        fifo = self.root / "not-regular"
        os.mkfifo(fifo)
        with self.assertRaises(OSError):
            ensure_private_file(fifo)

    def test_private_file_migration_preserves_arbitrary_bytes(self) -> None:
        path = self.root / "private.bin"
        content = bytes(range(256))
        path.write_bytes(content)
        path.chmod(0o666)

        ensure_private_file(path)

        self.assert_mode(path, 0o600)
        self.assertEqual(path.read_bytes(), content)

    def test_missing_intermediate_directories_are_created_private(self) -> None:
        directory = self.root / "fresh-dirs" / "nested" / "private"
        ensure_private_dir(directory)
        for path in (directory.parent.parent, directory.parent, directory):
            self.assert_mode(path, 0o700)

        private_file = self.root / "fresh-files" / "nested" / "private.bin"
        ensure_private_file(private_file)
        for path in (private_file.parent.parent, private_file.parent):
            self.assert_mode(path, 0o700)
        self.assert_mode(private_file, 0o600)

    def test_private_primitives_refuse_intermediate_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as external_name:
            external = Path(external_name)
            marker = external / "marker.bin"
            marker.write_bytes(b"external\x00unchanged")
            marker.chmod(0o666)
            external.chmod(0o777)
            before = self.snapshot_tree(external)

            linked_dir = self.root / "linked-dir-parent"
            linked_dir.symlink_to(external, target_is_directory=True)
            with self.assertRaises(OSError):
                ensure_private_dir(linked_dir / "nested" / "private")
            self.assertEqual(self.snapshot_tree(external), before)

            linked_file = self.root / "linked-file-parent"
            linked_file.symlink_to(external, target_is_directory=True)
            with self.assertRaises(OSError):
                ensure_private_file(linked_file / "nested" / "private.bin")
            self.assertEqual(self.snapshot_tree(external), before)

            broken = self.root / "broken-parent"
            broken.symlink_to(external / "missing", target_is_directory=True)
            with self.assertRaises(OSError):
                ensure_private_dir(broken / "nested")
            with self.assertRaises(OSError):
                ensure_private_file(broken / "private.bin")
            self.assertEqual(self.snapshot_tree(external), before)

    def test_fallback_walk_refuses_intermediate_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as external_name:
            external = Path(external_name)
            marker = external / "marker.bin"
            marker.write_bytes(b"fallback external tree")
            marker.chmod(0o666)
            external.chmod(0o777)
            before = self.snapshot_tree(external)
            linked = self.root / "fallback-link"
            linked.symlink_to(external, target_is_directory=True)

            with mock.patch(
                "rookery.portable.util._descriptor_walk_supported",
                return_value=False,
            ):
                with self.assertRaises(OSError):
                    ensure_private_dir(linked / "nested")
                with self.assertRaises(OSError):
                    ensure_private_file(linked / "private.bin")
                private_file = self.root / "fallback" / "nested" / "private.bin"
                ensure_private_file(private_file)

            self.assertEqual(self.snapshot_tree(external), before)
            self.assert_mode(private_file.parent.parent, 0o700)
            self.assert_mode(private_file.parent, 0o700)
            self.assert_mode(private_file, 0o600)

    def test_capture_file_refuses_duplicate_destination_without_rewriting(self) -> None:
        source = self.root / "source.bin"
        source.write_bytes(b"captured bytes")
        destination = self.root / "captures" / "fixture" / "attachment.bin"
        destination.parent.mkdir(parents=True)
        destination.parent.chmod(0o777)
        destination.write_bytes(b"old bytes")
        destination.chmod(0o666)
        scope = {
            "acknowledged": True,
            "generation": 1,
            "expires_at": "unknown",
            "allowed_file_origins": ["source.bin"],
            "max_attachment_bytes": 1024,
        }

        with self.assertRaisesRegex(RuntimeError, "already exists"):
            capture_file(
                self.root,
                scope,
                {"path": "source.bin"},
                destination,
            )

        self.assertEqual(destination.read_bytes(), b"old bytes")
        self.assert_mode(destination.parent, 0o777)
        self.assert_mode(destination, 0o666)

    def test_capture_file_refuses_intermediate_symlink_without_external_change(
        self,
    ) -> None:
        source = self.root / "source.bin"
        source.write_bytes(b"captured bytes")
        scope = {
            "acknowledged": True,
            "generation": 1,
            "expires_at": "unknown",
            "allowed_file_origins": ["source.bin"],
            "max_attachment_bytes": 1024,
        }
        with tempfile.TemporaryDirectory() as external_name:
            external = Path(external_name)
            marker = external / "marker.bin"
            marker.write_bytes(b"external attachment tree")
            marker.chmod(0o666)
            external.chmod(0o777)
            before = self.snapshot_tree(external)
            (self.root / "captures").symlink_to(
                external,
                target_is_directory=True,
            )

            with self.assertRaises(OSError):
                capture_file(
                    self.root,
                    scope,
                    {"path": "source.bin"},
                    self.root / "captures" / "fixture" / "attachment.bin",
                )

            self.assertEqual(self.snapshot_tree(external), before)

    def test_searxng_secret_and_service_paths_are_private(self) -> None:
        template_dir = self.root / "services" / "searxng"
        template_dir.mkdir(parents=True)
        (template_dir / "settings.template.yml").write_text(
            "server:\n  secret_key: __ROOKERY_SECRET__\n",
            encoding="utf-8",
        )
        runtime = self.root / "state" / "services" / "searxng"
        runtime.mkdir(parents=True)
        for path in (self.root / "state", self.root / "state/services", runtime):
            path.chmod(0o777)
        settings = runtime / "settings.yml"
        settings.write_bytes(b"old-secret-bytes")
        settings.chmod(0o666)
        completed = subprocess.CompletedProcess(["docker"], 0, "", "")

        with (
            mock.patch(
                "rookery.portable.preparation._http_json",
                side_effect=[(False, "missing"), (True, "healthy")],
            ),
            mock.patch(
                "rookery.portable.preparation._container_engine",
                return_value=(["docker"], "docker"),
            ),
            mock.patch("rookery.portable.preparation._free_port", return_value=18080),
            mock.patch("rookery.portable.preparation._run", return_value=completed),
        ):
            result = _prepare_searxng(
                self.root,
                {
                    "SEARXNG_MODE": "managed",
                    "SEARXNG_LOCAL_PORT": "18080",
                    "ROOKERY_ALLOW_INSTALL_NETWORK": "1",
                    "SEARXNG_IMAGE": APPROVED_MANAGED_SEARXNG_IMAGE,
                },
                apply=True,
                manager=None,
                install_log=[],
            )

        self.assertTrue(result["available"])
        for path in (self.root / "state", self.root / "state/services", runtime):
            self.assert_mode(path, 0o700)
        self.assert_mode(settings, 0o600)
        self.assertNotEqual(settings.read_bytes(), b"old-secret-bytes")
        self.assertNotIn(b"__ROOKERY_SECRET__", settings.read_bytes())

    def test_writeup_and_capsule_paths_are_private(self) -> None:
        directory = self.root / "writeups" / objective_storage_component("fixture")
        directory.mkdir(parents=True)
        (self.root / "writeups").chmod(0o777)
        directory.chmod(0o777)
        writeup = directory / "WRITEUP.md"
        writeup.write_bytes(b"existing writeup\x00")
        writeup.chmod(0o666)
        store = EventStore(self.root)

        returned = create_writeup(self.root, "fixture", "Fixture")
        with mock.patch(
            "rookery.portable.writeups.resolve_canonical_completion",
            return_value={
                "state": "accepted",
                "plan_id": "plan:fixture",
                "scorer_evidence": "submissions/response.json",
            },
        ):
            create_capsule(
                store,
                self.root,
                objective_id="fixture",
                action_reference="plan:fixture",
                scorer_evidence="submissions/response.json",
                reproduction_path="exploit/solve.py",
                material_provenance=["analysis/report.md"],
                dead_path_checkpoint="none",
            )

        self.assertEqual(returned, writeup)
        self.assertEqual(writeup.read_bytes(), b"existing writeup\x00")
        self.assert_mode(self.root / "writeups", 0o700)
        self.assert_mode(directory, 0o700)
        self.assert_mode(writeup, 0o600)
        self.assert_mode(directory / "CAPSULE.json", 0o600)


if __name__ == "__main__":
    unittest.main(verbosity=2)
