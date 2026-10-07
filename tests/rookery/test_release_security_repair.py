from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from tests.rookery.support import ROOKERY_ROOT
from tests.rookery.env_fixtures import configure_event_environment
from tests.rookery.test_preparation_and_isolation import copy_rookery

LIB = ROOKERY_ROOT / "lib"
if str(LIB) not in os.sys.path:
    os.sys.path.insert(0, str(LIB))
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

from rookery.portable.release import (  # noqa: E402
    BUILDER_IDENTITY,
    ReleaseBuildError,
    ReleaseVerificationError,
    build_release,
    extract_release_archive,
    verify_release_archive,
)
from rookery.portable import release as release_module  # noqa: E402
from rookery.portable.baseline import _validate_release_manifest  # noqa: E402
from rookery.portable.validator import _is_credential_key, validate_tree  # noqa: E402


def manifest_tree_sha256(rows: list[dict[str, object]]) -> str:
    digest = hashlib.sha256()
    for row in rows:
        digest.update(str(row["path"]).encode("utf-8") + b"\0")
        digest.update(str(row["sha256"]).encode("ascii") + b"\0")
    return digest.hexdigest()


def tree_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        digest.update(path.relative_to(root).as_posix().encode("utf-8") + b"\0")
        digest.update(path.read_bytes())
    return digest.hexdigest()


class ReleaseSecurityRepairTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        copy_rookery(self.source)
        shutil.rmtree(self.source / ".ruff_cache", ignore_errors=True)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def assert_extraction_rejected(
        self,
        name: str,
        archive_path: Path,
        manifest_path: Path,
        **limits: int,
    ) -> None:
        destination = self.root / f"{name}-destination"
        with self.assertRaises(ReleaseVerificationError):
            extract_release_archive(archive_path, manifest_path, destination, **limits)
        self.assertFalse(destination.exists(), f"partial extraction remained at {destination}")

    def _write_fixture(
        self,
        name: str,
        entries: list[tuple[str, bytes, int]],
        *,
        duplicate_entry: str | None = None,
        compression: int = zipfile.ZIP_DEFLATED,
        include_required_configuration: bool = True,
    ) -> tuple[Path, Path]:
        entry_paths = {path for path, _, _ in entries}
        if include_required_configuration:
            entries = [
                *entries,
                *(
                    (path, contents, mode)
                    for path, contents, mode in (
                        (".env", b"PLATFORM_ADAPTER=manual\n", 0o600),
                    )
                    if path not in entry_paths
                ),
            ]
        archive_path = self.root / f"{name}.zip"
        rows = [
            {
                "path": path,
                "bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
                "mode": f"{mode:04o}",
            }
            for path, data, mode in entries
        ]
        rows.sort(key=lambda row: str(row["path"]))
        with zipfile.ZipFile(archive_path, "w", compression=compression) as archive:
            root = zipfile.ZipInfo("rookery/")
            root.create_system = 3
            root.compress_type = compression
            root.external_attr = (0o755 << 16) | 0x10
            archive.writestr(root, b"")
            for path, data, mode in entries:
                info = zipfile.ZipInfo(f"rookery/{path}")
                info.create_system = 3
                info.compress_type = compression
                info.external_attr = mode << 16
                archive.writestr(info, data)
                if duplicate_entry == path:
                    archive.writestr(info, data)
        manifest_path = self.root / f"{name}.manifest.json"
        manifest_path.write_text(
            json.dumps(
                {
                    "schema_version": "2",
                    "identity": "rookery",
                    "version": "2026.08.28",
                    "archive": archive_path.name,
                    "archive_root": "rookery",
                    "builder_identity": BUILDER_IDENTITY,
                    "source_tree_sha256": manifest_tree_sha256(rows),
                    "directories": [],
                    "files": rows,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n",
            encoding="utf-8",
        )
        return archive_path, manifest_path

    def _rewrite_same_inode(self, path: Path, payload: bytes) -> None:
        before = path.stat()
        self.assertEqual(len(payload), before.st_size)
        with path.open("r+b", buffering=0) as handle:
            handle.seek(0)
            handle.write(payload)
            handle.truncate(len(payload))
            os.fsync(handle.fileno())
        timestamp_arguments = {"ns": (before.st_atime_ns, before.st_mtime_ns)}
        if os.utime in os.supports_follow_symlinks:
            os.utime(path, follow_symlinks=False, **timestamp_arguments)
        else:
            os.utime(path, **timestamp_arguments)
        after = path.stat()
        self.assertEqual(
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns),
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns),
        )

    def _assert_no_receive_residue(self, destination: Path) -> None:
        self.assertFalse(destination.exists())
        self.assertEqual(
            list(destination.parent.glob(f".{destination.name}.extracting-*")),
            [],
        )

    def _corrupt_deflate_member(self, archive_path: Path, member_name: str) -> None:
        with zipfile.ZipFile(archive_path) as archive:
            info = archive.getinfo(member_name)
        payload = bytearray(archive_path.read_bytes())
        header = info.header_offset
        self.assertEqual(payload[header : header + 4], b"PK\x03\x04")
        name_length = int.from_bytes(payload[header + 26 : header + 28], "little")
        extra_length = int.from_bytes(payload[header + 28 : header + 30], "little")
        data_offset = header + 30 + name_length + extra_length
        self.assertGreater(info.compress_size, 0)
        # Deflate block type 3 is reserved. Corrupting only these low bits
        # reliably exercises the decompressor's external-data error path.
        payload[data_offset] = (payload[data_offset] & 0xF8) | 0x07
        archive_path.write_bytes(payload)

    def _corrupt_member_crc(self, archive_path: Path, member_name: str) -> None:
        payload = bytearray(archive_path.read_bytes())
        offset = payload.find(b"PK\x01\x02")
        while offset >= 0:
            self.assertLessEqual(offset + 46, len(payload))
            name_length = int.from_bytes(payload[offset + 28 : offset + 30], "little")
            extra_length = int.from_bytes(payload[offset + 30 : offset + 32], "little")
            comment_length = int.from_bytes(payload[offset + 32 : offset + 34], "little")
            name_start = offset + 46
            name_end = name_start + name_length
            if bytes(payload[name_start:name_end]).decode("utf-8") == member_name:
                crc = int.from_bytes(payload[offset + 16 : offset + 20], "little")
                payload[offset + 16 : offset + 20] = (crc ^ 1).to_bytes(4, "little")
                archive_path.write_bytes(payload)
                return
            offset = payload.find(
                b"PK\x01\x02", name_end + extra_length + comment_length
            )
        self.fail(f"central-directory member not found: {member_name}")

    @staticmethod
    def _truncate_archive(archive_path: Path, _member_name: str) -> None:
        payload = archive_path.read_bytes()
        if len(payload) < 8:
            raise AssertionError("fixture archive unexpectedly short")
        archive_path.write_bytes(payload[:-8])

    def test_manifest_modes_follow_the_builder_policy_before_extraction(self) -> None:
        archive_path, manifest_path = self._write_fixture(
            "mode-policy",
            [
                (".env", b"PLATFORM_ADAPTER=manual\n", 0o600),
                ("README.md", b"safe archive\n", 0o644),
                ("go", b"#!/usr/bin/env bash\n", 0o755),
                ("bin/tool", b"#!/usr/bin/env bash\n", 0o755),
                ("extensions/example/bin/tool", b"#!/usr/bin/env bash\n", 0o755),
            ],
        )
        self.assertTrue(verify_release_archive(archive_path, manifest_path)["ok"])
        original = json.loads(manifest_path.read_text(encoding="utf-8"))
        invalid_modes = {
            ".env": ("0644", "0777"),
            "README.md": ("0755", "0777"),
            "go": ("0644",),
            "bin/tool": ("0644",),
            "extensions/example/bin/tool": ("0644",),
        }
        for path, modes in invalid_modes.items():
            for mode in modes:
                with self.subTest(path=path, mode=mode):
                    mutated = json.loads(json.dumps(original))
                    row = next(item for item in mutated["files"] if item["path"] == path)
                    row["mode"] = mode
                    changed_manifest = self.root / f"mode-policy-{path.replace('/', '-')}-{mode}.json"
                    changed_manifest.write_text(
                        json.dumps(mutated, sort_keys=True, separators=(",", ":")) + "\n",
                        encoding="utf-8",
                    )
                    with self.assertRaisesRegex(
                        ReleaseVerificationError, "release_manifest_mode_policy_invalid"
                    ):
                        verify_release_archive(archive_path, changed_manifest)
                    self.assert_extraction_rejected(
                        f"mode-policy-{path.replace('/', '-')}-{mode}",
                        archive_path,
                        changed_manifest,
                    )

    @unittest.skipIf(os.name == "nt", "requires the POSIX renameat2 receiver")
    def test_publication_rejects_competitor_created_at_final_barrier(self) -> None:
        archive_path, manifest_path = self._write_fixture(
            "publication-barrier", [("README.md", b"safe archive\n", 0o644)]
        )
        for kind in ("empty", "nonempty"):
            with self.subTest(kind=kind):
                destination = self.root / f"barrier-{kind}"
                original = release_module._rename_noreplace_at

                def create_competitor(parent_fd: int, source: str, target: str) -> None:
                    os.mkdir(target, dir_fd=parent_fd)
                    if kind == "nonempty":
                        target_fd = os.open(
                            target, os.O_RDONLY | os.O_DIRECTORY, dir_fd=parent_fd
                        )
                        try:
                            marker_fd = os.open(
                                "marker",
                                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                                0o600,
                                dir_fd=target_fd,
                            )
                            try:
                                os.write(marker_fd, b"keep")
                            finally:
                                os.close(marker_fd)
                        finally:
                            os.close(target_fd)
                    original(parent_fd, source, target)

                with mock.patch.object(
                    release_module, "_rename_noreplace_at", side_effect=create_competitor
                ):
                    with self.assertRaisesRegex(
                        ReleaseVerificationError, "release_destination_exists"
                    ):
                        extract_release_archive(archive_path, manifest_path, destination)
                self.assertTrue(destination.is_dir())
                if kind == "nonempty":
                    self.assertEqual((destination / "marker").read_bytes(), b"keep")
                self.assertFalse((destination / "rookery").exists())
                self.assertEqual(
                    list(self.root.glob(f".{destination.name}.extracting-*")), [],
                    "failed publication left a staging directory",
                )

    @unittest.skipIf(os.name == "nt", "requires the POSIX renameat2 receiver")
    def test_publication_fails_closed_without_renameat2(self) -> None:
        archive_path, manifest_path = self._write_fixture(
            "publication-unavailable", [("README.md", b"safe archive\n", 0o644)]
        )
        destination = self.root / "unavailable"
        with mock.patch.object(release_module.ctypes, "CDLL", return_value=object()):
            with self.assertRaisesRegex(
                ReleaseVerificationError, "release_atomic_noreplace_unavailable"
            ):
                extract_release_archive(archive_path, manifest_path, destination)
        self.assertFalse(destination.exists())
        self.assertEqual(
            list(self.root.glob(".unavailable.extracting-*")), [],
            "unavailable publication primitive left a staging directory",
        )

    @unittest.skipIf(os.name == "nt", "requires the POSIX renameat2 receiver")
    def test_publication_rejects_final_symlink_swap(self) -> None:
        archive_path, manifest_path = self._write_fixture(
            "final-symlink", [("README.md", b"safe archive\n", 0o644)]
        )
        destination = self.root / "symlink-final"
        replacement = self.root / "replacement"
        replacement.mkdir()
        original = release_module._rename_noreplace_at

        def create_symlink(parent_fd: int, source: str, target: str) -> None:
            os.symlink(os.fspath(replacement), target, dir_fd=parent_fd)
            original(parent_fd, source, target)

        with mock.patch.object(
            release_module, "_rename_noreplace_at", side_effect=create_symlink
        ):
            with self.assertRaisesRegex(
                ReleaseVerificationError, "release_destination_exists"
            ):
                extract_release_archive(archive_path, manifest_path, destination)
        self.assertTrue(destination.is_symlink())
        self.assertFalse((replacement / "rookery").exists())
        self.assertEqual(
            list(self.root.glob(".symlink-final.extracting-*")), [],
            "final symlink race left a staging directory",
        )

    @unittest.skipIf(os.name == "nt", "requires the POSIX descriptor receiver")
    def test_publication_rejects_parent_symlink_swap(self) -> None:
        archive_path, manifest_path = self._write_fixture(
            "parent-swap", [("README.md", b"safe archive\n", 0o644)]
        )
        parent = self.root / "receiver"
        parent.mkdir()
        destination = parent / "install"
        moved_parent = self.root / "receiver-moved"
        replacement = self.root / "replacement"
        replacement.mkdir()
        original = release_module._rename_noreplace_at

        def swap_parent(parent_fd: int, source: str, target: str) -> None:
            parent.rename(moved_parent)
            parent.symlink_to(replacement, target_is_directory=True)
            original(parent_fd, source, target)

        with mock.patch.object(release_module, "_rename_noreplace_at", side_effect=swap_parent):
            with self.assertRaisesRegex(
                ReleaseVerificationError, "release_destination_parent_changed"
            ):
                extract_release_archive(archive_path, manifest_path, destination)
        self.assertFalse((replacement / "install").exists())
        self.assertFalse((moved_parent / "install").exists())
        self.assertEqual(
            list(moved_parent.glob(".install.extracting-*")), [],
            "parent swap left a staging directory behind",
        )

    def test_live_operator_environment_is_not_payload_scanned_and_archive_uses_reviewed_template(self) -> None:
        original_environment = (self.source / ".env").read_bytes()
        live_assignments = (
            "SESSION_ID=FAKE_SESSION_SENTINEL_123456\n",
            "AUTH_HEADER=Bearer fixture-session-token-123456\n",
            "CUSTOM_COMMAND_CREDENTIAL=fixture-custom-credential-123456\n",
            "CUSTOM_VALUE=Bearer fixture-custom-value-123456\n",
            "CF_CLEARANCE=fixture-clearance-sentinel-123456\n",
            "PHPSESSID=fixture-php-session-123456\n",
            "JSESSIONID=fixture-java-session-123456\n",
        )
        (self.source / ".env").write_bytes(
            original_environment + "".join(live_assignments).encode("utf-8")
        )
        report = validate_tree(self.source, strict_release=True, source_checkout=True)
        self.assertTrue(report["ok"], report["errors"])
        for assignment in live_assignments:
            self.assertNotIn(assignment.split("=", 1)[1].strip(), json.dumps(report))
        self.assertFalse(_is_credential_key("CF_CLEARANCE_MODE"))
        self.assertFalse(_is_credential_key("AUTH_TICKET_TIMEOUT"))
        self.assertFalse(_is_credential_key("SESSION_COOKIE_PATH"))
        private_path = "/home/operator/private-path-sentinel"
        (self.source / ".env").write_bytes(
            original_environment.replace(
                b"ROCKYOU_PATH=\n",
                f"ROCKYOU_PATH={private_path}\n".encode("utf-8"),
                1,
            )
        )
        report = validate_tree(self.source, strict_release=True, source_checkout=True)
        self.assertTrue(report["ok"], report["errors"])
        self.assertNotIn(private_path, json.dumps(report))
        (self.source / ".env").write_bytes(
            original_environment.replace(
                b"QUEUE_CADENCE_SECONDS=", b"QUEUE_CADENCE_SECONDS=3", 1
            )
            .replace(b"VPN_MAX_OUTPUT_BYTES=8388608", b"VPN_MAX_OUTPUT_BYTES=2048", 1)
            .replace(b"BROWSER_MODE=auto", b"BROWSER_MODE=disabled", 1)
        )
        self.assertTrue(validate_tree(self.source, strict_release=True, source_checkout=True)["ok"])
        for assignment in (b"UNKNOWN_BENIGN=\n", b"UNKNOWN_BENIGN=fixture-value\n"):
            (self.source / ".env").write_bytes(original_environment + assignment)
            report = validate_tree(self.source, strict_release=True, source_checkout=True)
            self.assertTrue(report["ok"], report["errors"])
            value = assignment.split(b"=", 1)[1].strip().decode("ascii")
            if value:
                self.assertNotIn(value, json.dumps(report))
        template = self.source / ".env.example"
        template_bytes = template.read_bytes()
        template.write_bytes(template_bytes + b"TEMPLATE_UNKNOWN=fixture-template-value\n")
        template_report = validate_tree(self.source, strict_release=True)
        self.assertIn(
            "undeclared release configuration key in .env.example: TEMPLATE_UNKNOWN",
            template_report["errors"],
        )
        self.assertNotIn("fixture-template-value", json.dumps(template_report))
        template.write_bytes(template_bytes)
        (self.source / ".env").write_bytes(
            original_environment.replace(
                b"ROCKYOU_PATH=\n", b"ROCKYOU_PATH=source-only-value\n", 1
            )
            + "".join(live_assignments).encode("utf-8")
            + b"UNKNOWN_BENIGN=fixture-value\n"
        )

        output = self.root / "release"
        summary = build_release(self.source, output)
        archive_path = output / str(summary["archive"])
        manifest_path = output / str(summary["manifest"])
        with zipfile.ZipFile(archive_path) as archive:
            packaged_environment = archive.read("rookery/.env")
        self.assertEqual(packaged_environment, (self.source / ".env.example").read_bytes())
        private_assignments = (
            *live_assignments,
            "UNKNOWN_BENIGN=fixture-value\n",
            "ROCKYOU_PATH=source-only-value\n",
        )
        for assignment in private_assignments:
            value = assignment.split("=", 1)[1].strip().encode("utf-8")
            self.assertNotIn(value, archive_path.read_bytes())
            self.assertNotIn(value.decode("utf-8"), manifest_path.read_text(encoding="utf-8"))
            self.assertNotIn(value, packaged_environment)

        # The release scan remains payload-focused, but launch admission must
        # reject syntactically invalid live operator configuration before any
        # runtime state can be created.
        (self.source / ".env").write_bytes(original_environment + b"not-an-assignment\n")
        from rookery.portable.environment import EnvironmentPolicyError, resolve_launch_gate

        with self.assertRaisesRegex(EnvironmentPolicyError, "is not a valid assignment"):
            resolve_launch_gate(self.source, parent={})
        self.assertFalse((self.source / "state").exists())

        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        self.assertEqual(manifest["schema_version"], "2")
        self.assertEqual(manifest["builder_identity"], BUILDER_IDENTITY)
        self.assertEqual(manifest["source_tree_sha256"], manifest_tree_sha256(manifest["files"]))
        verification = verify_release_archive(archive_path, manifest_path)
        self.assertTrue(verification["ok"])
        self.assertEqual(verification["archive_sha256"], hashlib.sha256(archive_path.read_bytes()).hexdigest())

    def test_legacy_event_input_is_not_a_release_payload(self) -> None:
        configure_event_environment(self.source, "manual", name_suffix="Release Fixture")
        event = self.source / "event.json"
        private_value = "private-event-sentinel-123456"
        event.write_text(
            json.dumps(
                {
                    "identity": {"name": private_value},
                    "scope": {"acknowledged": False},
                }
            )
            + "\n",
            encoding="utf-8",
        )

        report = validate_tree(self.source, strict_release=True)
        self.assertTrue(report["ok"], report["errors"])
        self.assertNotIn(private_value, json.dumps(report))
        output = self.root / "event-template-release"
        summary = build_release(self.source, output)
        archive_path = output / str(summary["archive"])
        manifest_path = output / str(summary["manifest"])

        with zipfile.ZipFile(archive_path) as archive:
            self.assertFalse(
                any(
                    name == "rookery/event.json" or name.startswith("rookery/event.json/")
                    for name in archive.namelist()
                )
            )
        self.assertNotIn(private_value.encode("utf-8"), archive_path.read_bytes())
        self.assertNotIn(private_value, manifest_path.read_text(encoding="utf-8"))
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        self.assertNotIn("event.json", {row["path"] for row in manifest["files"]})

    def test_legacy_event_path_rejects_nonregular_forms_before_collection(self) -> None:
        cases = ["directory", "symlink"]
        if os.name == "posix":
            cases.append("fifo")
        for kind in cases:
            with self.subTest(kind=kind):
                source = self.root / f"legacy-{kind}-source"
                copy_rookery(source)
                legacy = source / "event.json"
                if kind == "directory":
                    legacy.mkdir()
                    (legacy / "private.txt").write_text("legacy-private-sentinel", encoding="utf-8")
                elif kind == "symlink":
                    target = self.root / "legacy-target"
                    target.write_text("legacy-private-sentinel", encoding="utf-8")
                    legacy.symlink_to(target)
                else:
                    os.mkfifo(legacy)
                with self.assertRaisesRegex(ReleaseBuildError, "legacy_event_path_invalid"):
                    release_module._collect_source_files(
                        source,
                        max_files=release_module.DEFAULT_MAX_FILES,
                        max_total_bytes=release_module.DEFAULT_MAX_TOTAL_BYTES,
                    )
                output = self.root / f"legacy-{kind}-release"
                with self.assertRaisesRegex(ReleaseBuildError, "legacy_event_path_invalid"):
                    build_release(source, output)
                self.assertFalse(output.exists() and any(output.iterdir()))

    def test_pre_extraction_verifier_rejects_structural_corruption(self) -> None:
        clean_archive, clean_manifest = self._write_fixture(
            "clean", [("README.md", b"safe archive\n", 0o644)]
        )
        self.assertTrue(verify_release_archive(clean_archive, clean_manifest)["ok"])
        legacy_manifest = json.loads(clean_manifest.read_text(encoding="utf-8"))
        legacy_manifest.pop("builder_identity")
        legacy_manifest.pop("source_tree_sha256")
        legacy_manifest.pop("directories")
        legacy_manifest["schema_version"] = "1"
        legacy_path = self.root / "legacy.manifest.json"
        legacy_path.write_text(json.dumps(legacy_manifest), encoding="utf-8")
        legacy_files, legacy_directories, legacy_total = _validate_release_manifest(
            legacy_manifest, "2026.08.28"
        )
        self.assertEqual(len(legacy_files), 2)
        self.assertEqual(legacy_directories, [])
        self.assertEqual(legacy_total, sum(int(row["bytes"]) for row in legacy_files))
        self.assertTrue(verify_release_archive(clean_archive, legacy_path)["ok"])

        mode_manifest = json.loads(clean_manifest.read_text(encoding="utf-8"))
        next(row for row in mode_manifest["files"] if row["path"] == "README.md")["mode"] = "0600"
        mode_path = self.root / "mode-mismatch.manifest.json"
        mode_path.write_text(json.dumps(mode_manifest), encoding="utf-8")
        with self.assertRaises(ReleaseVerificationError):
            verify_release_archive(clean_archive, mode_path)

        hash_manifest = json.loads(clean_manifest.read_text(encoding="utf-8"))
        hash_manifest["files"][0]["sha256"] = "0" * 64
        hash_manifest["source_tree_sha256"] = manifest_tree_sha256(hash_manifest["files"])
        hash_path = self.root / "hash-mismatch.manifest.json"
        hash_path.write_text(json.dumps(hash_manifest), encoding="utf-8")
        with self.assertRaises(ReleaseVerificationError):
            verify_release_archive(clean_archive, hash_path)

        traversal_archive, traversal_manifest = self._write_fixture(
            "traversal", [("../README.md", b"escape\n", 0o644)]
        )
        with self.assertRaises(ReleaseVerificationError):
            verify_release_archive(traversal_archive, traversal_manifest)

        duplicate_archive, duplicate_manifest = self._write_fixture(
            "duplicate",
            [("README.md", b"duplicate\n", 0o644)],
            duplicate_entry="README.md",
        )
        with self.assertRaises(ReleaseVerificationError):
            verify_release_archive(duplicate_archive, duplicate_manifest)

        collision_archive, collision_manifest = self._write_fixture(
            "collision",
            [("Readme", b"upper\n", 0o644), ("readme", b"lower\n", 0o644)],
        )
        with self.assertRaises(ReleaseVerificationError):
            verify_release_archive(collision_archive, collision_manifest)

        link_archive, link_manifest = self._write_fixture(
            "link", [("README.md", b"not-a-link\n", 0o644)]
        )
        with zipfile.ZipFile(link_archive, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            root = zipfile.ZipInfo("rookery/")
            root.create_system = 3
            root.external_attr = (0o755 << 16) | 0x10
            archive.writestr(root, b"")
            link = zipfile.ZipInfo("rookery/README.md")
            link.create_system = 3
            link.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(link, b"target")
        with self.assertRaises(ReleaseVerificationError):
            verify_release_archive(link_archive, link_manifest)

        with self.assertRaises(ReleaseVerificationError):
            verify_release_archive(clean_archive, clean_manifest, max_total_bytes=1)

    def test_receiver_requires_synthesized_configuration_members(self) -> None:
        archive_path, manifest_path = self._write_fixture(
            "missing-configuration",
            [("README.md", b"safe archive\n", 0o644)],
            include_required_configuration=False,
        )

        with self.assertRaisesRegex(
            ReleaseVerificationError,
            r"^release_manifest_required_configuration_missing$",
        ):
            verify_release_archive(archive_path, manifest_path)
        self.assert_extraction_rejected(
            "missing-configuration",
            archive_path,
            manifest_path,
        )

    def test_corrupt_archive_reads_are_bounded_and_leave_no_receiver_residue(self) -> None:
        receiver_before = tree_digest(self.source)
        corruptions = (
            ("deflate", self._corrupt_deflate_member),
            ("crc", self._corrupt_member_crc),
            ("truncate", self._truncate_archive),
        )
        for name, corrupt in corruptions:
            with self.subTest(corruption=name):
                archive_path, manifest_path = self._write_fixture(
                    f"corrupt-{name}", [("README.md", b"bounded archive data\n" * 4096, 0o644)]
                )
                corrupt(archive_path, "rookery/README.md")
                archive_before = archive_path.read_bytes()
                manifest_before = manifest_path.read_bytes()

                with self.assertRaisesRegex(
                    ReleaseVerificationError, r"^release_archive_malformed$"
                ):
                    verify_release_archive(archive_path, manifest_path)

                direct_destination = self.root / f"corrupt-{name}-direct-install"
                with self.assertRaisesRegex(
                    ReleaseVerificationError, r"^release_archive_malformed$"
                ):
                    extract_release_archive(
                        archive_path,
                        manifest_path,
                        direct_destination,
                    )
                self.assertFalse(direct_destination.exists())
                self.assertEqual(
                    list(self.root.glob(f".{direct_destination.name}.extracting-*")), []
                )

                cli_destination = self.root / f"corrupt-{name}-cli-install"
                completed = subprocess.run(
                    [
                        sys.executable,
                        str(self.source / "bin" / "build-release"),
                        "--extract-archive",
                        str(archive_path),
                        "--manifest",
                        str(manifest_path),
                        "--extract-dir",
                        str(cli_destination),
                    ],
                    cwd=self.root,
                    env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
                    text=True,
                    capture_output=True,
                    timeout=30,
                )
                self.assertEqual(completed.returncode, 2, completed.stdout)
                self.assertEqual(
                    json.loads(completed.stdout),
                    {"error": "release_extract_failed", "ok": False},
                )
                self.assertNotIn("Traceback", completed.stdout)
                self.assertNotIn("Traceback", completed.stderr)
                self.assertFalse(cli_destination.exists())
                self.assertEqual(
                    list(self.root.glob(f".{cli_destination.name}.extracting-*")), []
                )
                self.assertEqual(archive_path.read_bytes(), archive_before)
                self.assertEqual(manifest_path.read_bytes(), manifest_before)

        self.assertEqual(tree_digest(self.source), receiver_before)

    def test_pinned_sources_reject_same_inode_rewrites_before_publication(self) -> None:
        archive_path, manifest_path = self._write_fixture(
            "pinned-a",
            [("README.md", b"A" * 8192, 0o644)],
            compression=zipfile.ZIP_STORED,
        )
        replacement_archive, _ = self._write_fixture(
            "pinned-b",
            [("README.md", b"B" * 8192, 0o644)],
            compression=zipfile.ZIP_STORED,
        )
        archive_a = archive_path.read_bytes()
        archive_b = replacement_archive.read_bytes()
        manifest_a = manifest_path.read_bytes()
        self.assertEqual(len(archive_a), len(archive_b))
        self.assertNotEqual(archive_a, archive_b)

        original_hash = release_module._sha256_pinned_regular_file
        archive_hash_calls = 0

        def rewrite_before_verify_recheck(source: object) -> str:
            nonlocal archive_hash_calls
            if source.label == "release_archive":
                archive_hash_calls += 1
                if archive_hash_calls == 2:
                    self._rewrite_same_inode(archive_path, archive_b)
            return original_hash(source)

        with mock.patch.object(
            release_module,
            "_sha256_pinned_regular_file",
            side_effect=rewrite_before_verify_recheck,
        ):
            with self.assertRaisesRegex(ReleaseVerificationError, r"^release_archive_changed$"):
                verify_release_archive(archive_path, manifest_path)
        self.assertEqual(archive_path.read_bytes(), archive_b)
        self.assertEqual(manifest_path.read_bytes(), manifest_a)

        self._rewrite_same_inode(archive_path, archive_a)
        archive_hash_calls = 0

        def rewrite_before_publication(source: object) -> str:
            nonlocal archive_hash_calls
            if source.label == "release_archive":
                archive_hash_calls += 1
                if archive_hash_calls == 3:
                    self._rewrite_same_inode(archive_path, archive_b)
            return original_hash(source)

        archive_destination = self.root / "pinned-archive-install"
        with mock.patch.object(
            release_module,
            "_sha256_pinned_regular_file",
            side_effect=rewrite_before_publication,
        ):
            with self.assertRaisesRegex(ReleaseVerificationError, r"^release_archive_changed$"):
                extract_release_archive(archive_path, manifest_path, archive_destination)
        self._assert_no_receive_residue(archive_destination)
        self.assertEqual(archive_path.read_bytes(), archive_b)

        self._rewrite_same_inode(archive_path, archive_a)
        manifest_b = manifest_a[:-1] + b" "
        self.assertNotEqual(manifest_a, manifest_b)
        manifest_hash_calls = 0

        def rewrite_manifest_before_verify_recheck(source: object) -> str:
            nonlocal manifest_hash_calls
            if source.label == "release_manifest":
                manifest_hash_calls += 1
                if manifest_hash_calls == 1:
                    self._rewrite_same_inode(manifest_path, manifest_b)
            return original_hash(source)

        with mock.patch.object(
            release_module,
            "_sha256_pinned_regular_file",
            side_effect=rewrite_manifest_before_verify_recheck,
        ):
            with self.assertRaisesRegex(ReleaseVerificationError, r"^release_manifest_changed$"):
                verify_release_archive(archive_path, manifest_path)

        self._rewrite_same_inode(manifest_path, manifest_a)
        manifest_hash_calls = 0

        def rewrite_manifest_before_publication(source: object) -> str:
            nonlocal manifest_hash_calls
            if source.label == "release_manifest":
                manifest_hash_calls += 1
                if manifest_hash_calls == 2:
                    self._rewrite_same_inode(manifest_path, manifest_b)
            return original_hash(source)

        manifest_destination = self.root / "pinned-manifest-install"
        with mock.patch.object(
            release_module,
            "_sha256_pinned_regular_file",
            side_effect=rewrite_manifest_before_publication,
        ):
            with self.assertRaisesRegex(ReleaseVerificationError, r"^release_manifest_changed$"):
                extract_release_archive(archive_path, manifest_path, manifest_destination)
        self._assert_no_receive_residue(manifest_destination)
        self.assertEqual(archive_path.read_bytes(), archive_a)

    def test_pinned_archive_rejects_size_and_descriptor_read_races(self) -> None:
        for name in ("truncate", "grow", "append"):
            with self.subTest(race=name):
                archive_path, manifest_path = self._write_fixture(
                    f"size-race-{name}",
                    [("README.md", b"bounded\n" * 1024, 0o644)],
                    compression=zipfile.ZIP_STORED,
                )
                original_hash = release_module._sha256_pinned_regular_file
                archive_hash_calls = 0

                def mutate_before_publication(source: object) -> str:
                    nonlocal archive_hash_calls
                    if source.label == "release_archive":
                        archive_hash_calls += 1
                        if archive_hash_calls == 3:
                            if name == "truncate":
                                with archive_path.open("r+b") as handle:
                                    handle.truncate(archive_path.stat().st_size - 1)
                            elif name == "grow":
                                with archive_path.open("r+b") as handle:
                                    handle.seek(archive_path.stat().st_size + 7)
                                    handle.write(b"grow")
                            else:
                                with archive_path.open("ab") as handle:
                                    handle.write(b"append")
                    return original_hash(source)

                destination = self.root / f"size-race-{name}-install"
                with mock.patch.object(
                    release_module,
                    "_sha256_pinned_regular_file",
                    side_effect=mutate_before_publication,
                ):
                    with self.assertRaisesRegex(
                        ReleaseVerificationError, r"^release_archive_changed$"
                    ):
                        extract_release_archive(archive_path, manifest_path, destination)
                self._assert_no_receive_residue(destination)

        archive_path, manifest_path = self._write_fixture(
            "descriptor-race-a",
            [("README.md", b"A" * (3 * release_module.STREAM_CHUNK_BYTES), 0o644)],
            compression=zipfile.ZIP_STORED,
        )
        replacement_archive, _ = self._write_fixture(
            "descriptor-race-b",
            [("README.md", b"B" * (3 * release_module.STREAM_CHUNK_BYTES), 0o644)],
            compression=zipfile.ZIP_STORED,
        )
        archive_b = replacement_archive.read_bytes()
        self.assertEqual(archive_path.stat().st_size, len(archive_b))
        original_hash = release_module._sha256_pinned_regular_file
        original_read = release_module.os.read
        archive_hash_calls = 0
        armed_descriptor: int | None = None
        rewritten = False

        def arm_final_descriptor_read(source: object) -> str:
            nonlocal archive_hash_calls, armed_descriptor
            if source.label == "release_archive":
                archive_hash_calls += 1
                if archive_hash_calls == 3:
                    armed_descriptor = source.descriptor
            try:
                return original_hash(source)
            finally:
                armed_descriptor = None

        def rewrite_after_first_descriptor_chunk(descriptor: int, count: int) -> bytes:
            nonlocal rewritten
            chunk = original_read(descriptor, count)
            if descriptor == armed_descriptor and chunk and not rewritten:
                self._rewrite_same_inode(archive_path, archive_b)
                rewritten = True
            return chunk

        destination = self.root / "descriptor-race-install"
        with (
            mock.patch.object(
                release_module,
                "_sha256_pinned_regular_file",
                side_effect=arm_final_descriptor_read,
            ),
            mock.patch.object(
                release_module.os,
                "read",
                side_effect=rewrite_after_first_descriptor_chunk,
            ),
        ):
            with self.assertRaisesRegex(ReleaseVerificationError, r"^release_archive_changed$"):
                extract_release_archive(archive_path, manifest_path, destination)
        self.assertTrue(rewritten)
        self._assert_no_receive_residue(destination)

    def test_receiver_rejects_multiply_linked_inputs_without_staging(self) -> None:
        for linked_input in ("archive", "manifest"):
            with self.subTest(linked_input=linked_input):
                archive_path, manifest_path = self._write_fixture(
                    f"linked-{linked_input}", [("README.md", b"safe\n", 0o644)]
                )
                linked_path = archive_path if linked_input == "archive" else manifest_path
                os.link(linked_path, self.root / f"{linked_input}-hardlink")
                destination = self.root / f"linked-{linked_input}-install"
                with self.assertRaisesRegex(
                    ReleaseVerificationError,
                    rf"^release_{linked_input}_link_count_invalid$",
                ):
                    extract_release_archive(archive_path, manifest_path, destination)
                self._assert_no_receive_residue(destination)

    def test_verified_extraction_is_exact_no_clobber_and_fail_closed(self) -> None:
        clean_archive, clean_manifest = self._write_fixture(
            "extract-clean", [("README.md", b"safe archive\n", 0o644)]
        )
        clean_archive_before = clean_archive.read_bytes()
        clean_manifest_before = clean_manifest.read_bytes()
        destination = self.root / "install"
        summary = extract_release_archive(clean_archive, clean_manifest, destination)
        installed_root = destination / "rookery"
        installed_file = installed_root / "README.md"
        self.assertTrue(summary["ok"])
        self.assertEqual(installed_file.read_bytes(), b"safe archive\n")
        self.assertEqual(clean_archive.read_bytes(), clean_archive_before)
        self.assertEqual(clean_manifest.read_bytes(), clean_manifest_before)
        if os.name != "nt":
            self.assertEqual(stat.S_IMODE(installed_root.stat().st_mode), 0o755)
            self.assertEqual(stat.S_IMODE(installed_file.stat().st_mode), 0o644)

        occupied = self.root / "occupied"
        occupied.mkdir()
        marker = occupied / "existing"
        marker.write_text("keep", encoding="utf-8")
        with self.assertRaises(ReleaseVerificationError):
            extract_release_archive(clean_archive, clean_manifest, occupied)
        self.assertEqual(marker.read_text(encoding="utf-8"), "keep")

        cli_destination = self.root / "cli-install"
        completed = subprocess.run(
            [
                sys.executable,
                str(ROOKERY_ROOT / "bin" / "build-release"),
                "--extract-archive",
                str(clean_archive),
                "--manifest",
                str(clean_manifest),
                "--extract-dir",
                str(cli_destination),
            ],
            cwd=self.root,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
            text=True,
            capture_output=True,
            timeout=30,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertTrue(json.loads(completed.stdout)["ok"])
        self.assertEqual((cli_destination / "rookery/README.md").read_bytes(), b"safe archive\n")

        mode_manifest = json.loads(clean_manifest.read_text(encoding="utf-8"))
        next(row for row in mode_manifest["files"] if row["path"] == "README.md")["mode"] = "0600"
        mode_path = self.root / "extract-mode-mismatch.manifest.json"
        mode_path.write_text(json.dumps(mode_manifest), encoding="utf-8")
        self.assert_extraction_rejected("mode", clean_archive, mode_path)

        hash_manifest = json.loads(clean_manifest.read_text(encoding="utf-8"))
        hash_manifest["files"][0]["sha256"] = "0" * 64
        hash_manifest["source_tree_sha256"] = manifest_tree_sha256(hash_manifest["files"])
        hash_path = self.root / "extract-hash-mismatch.manifest.json"
        hash_path.write_text(json.dumps(hash_manifest), encoding="utf-8")
        self.assert_extraction_rejected("hash", clean_archive, hash_path)

        traversal_archive, traversal_manifest = self._write_fixture(
            "extract-traversal", [("../README.md", b"escape\n", 0o644)]
        )
        self.assert_extraction_rejected("traversal", traversal_archive, traversal_manifest)

        duplicate_archive, duplicate_manifest = self._write_fixture(
            "extract-duplicate",
            [("README.md", b"duplicate\n", 0o644)],
            duplicate_entry="README.md",
        )
        self.assert_extraction_rejected("duplicate", duplicate_archive, duplicate_manifest)

        collision_archive, collision_manifest = self._write_fixture(
            "extract-collision",
            [("Readme", b"upper\n", 0o644), ("readme", b"lower\n", 0o644)],
        )
        self.assert_extraction_rejected("collision", collision_archive, collision_manifest)

        link_archive, link_manifest = self._write_fixture(
            "extract-link", [("README.md", b"not-a-link\n", 0o644)]
        )
        with zipfile.ZipFile(link_archive, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            root = zipfile.ZipInfo("rookery/")
            root.create_system = 3
            root.external_attr = (0o755 << 16) | 0x10
            archive.writestr(root, b"")
            link = zipfile.ZipInfo("rookery/README.md")
            link.create_system = 3
            link.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(link, b"target")
        self.assert_extraction_rejected("link", link_archive, link_manifest)
        self.assert_extraction_rejected(
            "size", clean_archive, clean_manifest, max_total_bytes=1
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
