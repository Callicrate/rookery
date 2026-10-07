"""Deterministic, bounded release archive construction for a strict Rookery tree."""

from __future__ import annotations

import argparse
import ctypes
import datetime as dt
import errno
import hashlib
import json
import os
import re
import secrets
import shutil
import stat
import tempfile
import unicodedata
import zipfile
import zlib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Sequence

from .util import load_json
from .validator import RELEASE_CONFIGURATION_TEMPLATES, validate_tree

UTC = dt.timezone.utc
STREAM_CHUNK_BYTES = 64 * 1024
DEFAULT_MAX_FILES = 20_000
DEFAULT_MAX_TOTAL_BYTES = 512 * 1024 * 1024
DEFAULT_MAX_MANIFEST_BYTES = 16 * 1024 * 1024
ARCHIVE_OVERHEAD_BYTES = 64 * 1024 * 1024
MANIFEST_SCHEMA_VERSION = "2"
BUILDER_IDENTITY = "rookery.portable.release/2"
CALVER = re.compile(r"(\d{4})\.(\d{2})\.(\d{2})(?:\.\d+)?$")
SAFE_ARCHIVE_ROOT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*$")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
RENAME_NOREPLACE = 1
LEGACY_EVENT_PATH = "event.json"
MAX_DEFAULT_EXTENSIONS = 64
class ReleaseBuildError(ValueError):
    """Raised for a release source or output boundary that cannot be packaged."""


class ReleaseVerificationError(ValueError):
    """Raised when an unextracted release archive fails its bounded checks."""


@dataclass(frozen=True)
class ReleaseFile:
    """A verified source file and its size at collection time."""

    path: Path
    relative_path: str
    size: int


@dataclass(frozen=True)
class _ExtractionDestination:
    """A receiver-owned destination with an optional pinned POSIX parent."""

    target: Path
    parent: Path
    name: str
    parent_identity: tuple[int, int]
    parent_fd: int | None


@dataclass(frozen=True)
class _RegularFileSignature:
    """All receiver-visible identity and mutation fields for one input file."""

    device: int
    inode: int
    file_type: int
    size: int
    mtime_ns: int
    ctime_ns: int
    link_count: int


@dataclass(frozen=True)
class _PinnedRegularFile:
    """One no-follow descriptor retained for an entire receive operation."""

    path: Path
    label: str
    descriptor: int
    path_signature: _RegularFileSignature
    descriptor_signature: _RegularFileSignature


def source_root_from_wrapper(wrapper_path: Path) -> Path:
    """Derive the shipped release source root from its installed bin wrapper."""

    wrapper = wrapper_path.resolve()
    if wrapper.name != "build-release" or wrapper.parent.name != "bin":
        raise ReleaseBuildError("invalid_release_wrapper")
    return wrapper.parents[1]


def _output_outside_source(source_root: Path, output_directory: Path) -> Path:
    output = output_directory.resolve()
    try:
        output.relative_to(source_root)
    except ValueError:
        return output
    raise ReleaseBuildError("output_inside_source")


def _release_metadata(source_root: Path) -> tuple[dict[str, Any], str, tuple[int, int, int, int, int, int]]:
    release = load_json(source_root / "release.json", {})
    version = (source_root / "VERSION").read_text(encoding="utf-8").strip()
    match = CALVER.fullmatch(version)
    if not isinstance(release, dict) or match is None:
        raise ReleaseBuildError("invalid_release_metadata")
    try:
        stamp = dt.datetime(
            int(match.group(1)),
            int(match.group(2)),
            int(match.group(3)),
            tzinfo=UTC,
        )
    except ValueError as exc:
        raise ReleaseBuildError("invalid_calver_date") from exc
    archive_root = str(release.get("archive_root") or "")
    if not SAFE_ARCHIVE_ROOT.fullmatch(archive_root) or archive_root in {".", ".."}:
        raise ReleaseBuildError("invalid_archive_root")
    return release, version, (stamp.year, stamp.month, stamp.day, 0, 0, 0)


def _strict_validate(source_root: Path, *, mutation_check: bool = False) -> str:
    """Validate strictly and return the stable tree hash used for quiescence checks."""

    report = validate_tree(
        source_root,
        adapter="manual",
        strict_release=True,
        source_checkout=True,
    )
    if not report.get("ok"):
        raise ReleaseBuildError(
            "release_source_changed" if mutation_check else "strict_release_validation_failed"
        )
    before = str(report.get("tree_hash_before") or "")
    after = str(report.get("tree_hash_after") or "")
    if not before or before != after:
        raise ReleaseBuildError("release_source_changed")
    return after


def _selected_adapter_default_extensions(source_root: Path, selected_adapter: str | None) -> frozenset[str]:
    """Return reviewed default extensions required by one adapter-only archive."""

    if selected_adapter is None:
        return frozenset()
    descriptor = source_root / "adapters" / selected_adapter / "adapter.json"
    try:
        descriptor_info = descriptor.lstat()
    except OSError as exc:
        raise ReleaseBuildError("selected_adapter_missing") from exc
    if descriptor.is_symlink() or not stat.S_ISREG(descriptor_info.st_mode):
        raise ReleaseBuildError("selected_adapter_missing")
    data = load_json(descriptor, {})
    defaults = data.get("default_extensions", []) if isinstance(data, dict) else []
    if (
        not isinstance(defaults, list)
        or len(defaults) > MAX_DEFAULT_EXTENSIONS
        or any(
            not isinstance(extension, str)
            or not SAFE_ARCHIVE_ROOT.fullmatch(extension)
            or extension in {".", ".."}
            for extension in defaults
        )
        or len(set(defaults)) != len(defaults)
    ):
        raise ReleaseBuildError("selected_adapter_extensions_invalid")
    for extension in defaults:
        extension_root = source_root / "extensions" / extension
        extension_descriptor = extension_root / "extension.json"
        try:
            root_info = extension_root.lstat()
            descriptor_info = extension_descriptor.lstat()
        except OSError as exc:
            raise ReleaseBuildError("selected_adapter_extension_missing") from exc
        if (
            extension_root.is_symlink()
            or not stat.S_ISDIR(root_info.st_mode)
            or extension_descriptor.is_symlink()
            or not stat.S_ISREG(descriptor_info.st_mode)
        ):
            raise ReleaseBuildError("selected_adapter_extension_missing")
    return frozenset(defaults)


def _validate_legacy_event_root(source_root: Path) -> None:
    """Allow only a root-level regular legacy migration input, without reading it."""

    legacy = source_root / LEGACY_EVENT_PATH
    try:
        legacy_info = legacy.lstat()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise ReleaseBuildError("legacy_event_path_invalid") from exc
    if legacy.is_symlink() or not stat.S_ISREG(legacy_info.st_mode):
        raise ReleaseBuildError("legacy_event_path_invalid")


def _release_path_selected(
    relative: Path, selected_adapter: str | None, selected_extensions: frozenset[str]
) -> bool:
    if selected_adapter is None or not relative.parts:
        return True
    if relative.parts[0] == "extensions":
        return len(relative.parts) > 1 and relative.parts[1] in selected_extensions
    if relative.parts[0] == "adapters" and len(relative.parts) > 1:
        return relative.parts[1] == selected_adapter
    return True


def _collect_source_files(
    source_root: Path,
    *,
    max_files: int,
    max_total_bytes: int,
    selected_adapter: str | None = None,
) -> tuple[list[Path], list[ReleaseFile], int]:
    """Collect selected package nodes, rejecting links and special files."""

    if max_files <= 0 or max_total_bytes <= 0:
        raise ReleaseBuildError("invalid_release_limits")
    _validate_legacy_event_root(source_root)
    selected_extensions = _selected_adapter_default_extensions(source_root, selected_adapter)
    files: list[ReleaseFile] = []
    total_bytes = 0
    for candidate in source_root.rglob("*"):
        relative = candidate.relative_to(source_root)
        relative_path = relative.as_posix()
        # Do this before the directory branch. A non-regular root path is
        # rejected above, so this also prevents a race-created legacy subtree
        # from ever reaching archive inventory or recursive collection.
        if relative.parts and relative.parts[0] == LEGACY_EVENT_PATH:
            if relative_path != LEGACY_EVENT_PATH:
                raise ReleaseBuildError("legacy_event_path_invalid")
            try:
                legacy_info = candidate.lstat()
            except OSError as exc:
                raise ReleaseBuildError("legacy_event_path_invalid") from exc
            if candidate.is_symlink() or not stat.S_ISREG(legacy_info.st_mode):
                raise ReleaseBuildError("legacy_event_path_invalid")
            continue
        if candidate.is_symlink():
            raise ReleaseBuildError("release_symlink_rejected")
        selected = _release_path_selected(relative, selected_adapter, selected_extensions)
        if candidate.is_dir():
            continue
        try:
            status = candidate.stat()
        except OSError as exc:
            raise ReleaseBuildError("release_source_unreadable") from exc
        if not candidate.is_file() or not stat.S_ISREG(status.st_mode):
            raise ReleaseBuildError("release_non_regular_file")
        # Live configuration is a valid local source input but never an
        # archive input.  It still passed the node checks above and remains in
        # the strict tree hash used by the quiescence checks.
        if relative_path in RELEASE_CONFIGURATION_TEMPLATES:
            continue
        if not selected:
            continue
        if len(files) >= max_files:
            raise ReleaseBuildError("release_file_limit_exceeded")
        total_bytes += status.st_size
        if total_bytes > max_total_bytes:
            raise ReleaseBuildError("release_byte_limit_exceeded")
        files.append(
            ReleaseFile(
                path=candidate,
                relative_path=relative_path,
                size=status.st_size,
            )
        )
    for archive_relative, template_relative in RELEASE_CONFIGURATION_TEMPLATES.items():
        template = source_root / template_relative
        try:
            template_status = template.lstat()
        except OSError as exc:
            raise ReleaseBuildError("release_configuration_template_unreadable") from exc
        if template.is_symlink() or not stat.S_ISREG(template_status.st_mode):
            raise ReleaseBuildError("release_configuration_template_invalid")
        if len(files) >= max_files:
            raise ReleaseBuildError("release_file_limit_exceeded")
        total_bytes += template_status.st_size
        if total_bytes > max_total_bytes:
            raise ReleaseBuildError("release_byte_limit_exceeded")
        files.append(
            ReleaseFile(
                path=template,
                relative_path=archive_relative,
                size=template_status.st_size,
            )
        )
    # A release describes files, not checkout residue.  Git cannot reproduce
    # untracked empty directories, so emit only ancestors needed to contain
    # selected packaged files (the archive root is written separately).
    directories = sorted(
        {
            Path(*parts[:depth])
            for source_file in files
            for parts in (PurePosixPath(source_file.relative_path).parts,)
            for depth in range(1, len(parts))
        },
        key=lambda path: path.as_posix(),
    )
    if len(directories) + len(files) > max_files:
        raise ReleaseBuildError("release_file_limit_exceeded")
    files.sort(key=lambda source_file: source_file.relative_path)
    return directories, files, total_bytes


def _normalized_file_mode(relative_path: str) -> int:
    """Return the one archive mode policy shared by builder and receiver.

    This intentionally derives permissions from the shipped archive path, not
    the source checkout's mode bits.  It keeps operator configuration private,
    makes the public launchers and every shipped ``bin`` entrypoint
    executable, and makes all remaining regular members ordinary data files.
    """

    parts = PurePosixPath(relative_path).parts
    if relative_path == ".env":
        return 0o600
    if relative_path in {"go", "run-codex"} or "bin" in parts[:-1]:
        return 0o755
    return 0o644


def _zip_info(name: str, timestamp: tuple[int, int, int, int, int, int], mode: int, *, directory: bool) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=timestamp)
    info.create_system = 3
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = (mode & 0o777) << 16
    if directory:
        info.external_attr |= 0x10
    return info


def _write_release_file(
    archive: zipfile.ZipFile,
    entry_name: str,
    source: ReleaseFile,
    timestamp: tuple[int, int, int, int, int, int],
) -> dict[str, Any]:
    """Stream a source file once into the archive and prove its collected size."""

    digest = hashlib.sha256()
    remaining = source.size
    info = _zip_info(entry_name, timestamp, _normalized_file_mode(source.relative_path), directory=False)
    try:
        with source.path.open("rb") as origin, archive.open(info, "w") as destination:
            while remaining:
                chunk = origin.read(min(STREAM_CHUNK_BYTES, remaining))
                if not chunk:
                    raise ReleaseBuildError("release_source_changed")
                destination.write(chunk)
                digest.update(chunk)
                remaining -= len(chunk)
            if origin.read(1):
                raise ReleaseBuildError("release_source_changed")
    except OSError as exc:
        raise ReleaseBuildError("release_source_changed") from exc
    return {
        "path": source.relative_path,
        "bytes": source.size,
        "sha256": digest.hexdigest(),
        "mode": f"{_normalized_file_mode(source.relative_path):04o}",
    }


def _fsync(path: Path) -> None:
    with path.open("rb") as handle:
        os.fsync(handle.fileno())


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(STREAM_CHUNK_BYTES), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _manifest_tree_sha256(files: list[dict[str, Any]]) -> str:
    """Hash the archive's logical source tree without referring to local paths."""

    digest = hashlib.sha256()
    for row in files:
        digest.update(str(row["path"]).encode("utf-8") + b"\0")
        digest.update(str(row["sha256"]).encode("ascii") + b"\0")
    return digest.hexdigest()


def _safe_manifest_path(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value or "\0" in value:
        raise ReleaseVerificationError(f"{label}_path_invalid")
    if len(value.encode("utf-8")) > 1024:
        raise ReleaseVerificationError(f"{label}_path_invalid")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or value != path.as_posix()
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise ReleaseVerificationError(f"{label}_path_invalid")
    return value


def _path_collision_key(value: str) -> str:
    """Collapse names that collide on common case-folding/NFC filesystems."""

    return unicodedata.normalize("NFC", value).casefold()


def _signature_from_stat(info: os.stat_result) -> _RegularFileSignature:
    return _RegularFileSignature(
        device=info.st_dev,
        inode=info.st_ino,
        file_type=stat.S_IFMT(info.st_mode),
        size=info.st_size,
        mtime_ns=info.st_mtime_ns,
        ctime_ns=info.st_ctime_ns,
        link_count=info.st_nlink,
    )


def _regular_file_signature(path: Path, label: str) -> _RegularFileSignature:
    try:
        info = path.lstat()
    except OSError as exc:
        raise ReleaseVerificationError(f"{label}_missing_or_unreadable") from exc
    signature = _signature_from_stat(info)
    if signature.file_type != stat.S_IFREG:
        raise ReleaseVerificationError(f"{label}_not_regular")
    if signature.link_count != 1:
        raise ReleaseVerificationError(f"{label}_link_count_invalid")
    return signature


def _path_and_descriptor_signatures_match(
    path_signature: _RegularFileSignature,
    descriptor_signature: _RegularFileSignature,
) -> bool:
    """Compare one object across pathname and descriptor stat APIs.

    Native Windows exposes creation time as pathname ``ctime`` but currently
    reports modification time in the descriptor ``ctime`` field.  Each value
    is still retained and compared with its own before/after API; only this
    cross-API identity check omits that semantically different field there.
    """

    common_equal = (
        path_signature.device == descriptor_signature.device
        and path_signature.inode == descriptor_signature.inode
        and path_signature.file_type == descriptor_signature.file_type
        and path_signature.size == descriptor_signature.size
        and path_signature.mtime_ns == descriptor_signature.mtime_ns
        and path_signature.link_count == descriptor_signature.link_count
    )
    return common_equal and (
        os.name == "nt" or path_signature.ctime_ns == descriptor_signature.ctime_ns
    )


def _open_pinned_regular_file(path: Path, maximum: int, label: str) -> _PinnedRegularFile:
    if maximum <= 0:
        raise ReleaseVerificationError("invalid_release_limits")
    before = _regular_file_signature(path, label)
    if before.size > maximum:
        raise ReleaseVerificationError(f"{label}_too_large")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ReleaseVerificationError(f"{label}_missing_or_unreadable") from exc
    try:
        opened = _signature_from_stat(os.fstat(descriptor))
        if opened.file_type != stat.S_IFREG:
            raise ReleaseVerificationError(f"{label}_not_regular")
        if opened.link_count != 1:
            raise ReleaseVerificationError(f"{label}_link_count_invalid")
        if not _path_and_descriptor_signatures_match(before, opened):
            raise ReleaseVerificationError(f"{label}_changed")
        return _PinnedRegularFile(Path(path), label, descriptor, before, opened)
    except Exception:
        os.close(descriptor)
        raise


def _assert_pinned_regular_file_unchanged(source: _PinnedRegularFile) -> None:
    try:
        descriptor_signature = _signature_from_stat(os.fstat(source.descriptor))
        path_signature = _signature_from_stat(source.path.lstat())
    except OSError as exc:
        raise ReleaseVerificationError(f"{source.label}_changed") from exc
    if (
        descriptor_signature.file_type != stat.S_IFREG
        or descriptor_signature.link_count != 1
        or path_signature.file_type != stat.S_IFREG
        or path_signature.link_count != 1
        or descriptor_signature != source.descriptor_signature
        or path_signature != source.path_signature
        or not _path_and_descriptor_signatures_match(path_signature, descriptor_signature)
    ):
        raise ReleaseVerificationError(f"{source.label}_changed")


def _read_exact_pinned_regular_file(source: _PinnedRegularFile) -> bytes:
    try:
        os.lseek(source.descriptor, 0, os.SEEK_SET)
        remaining = source.descriptor_signature.size
        chunks: list[bytes] = []
        while remaining:
            chunk = os.read(source.descriptor, min(STREAM_CHUNK_BYTES, remaining))
            if not chunk:
                raise ReleaseVerificationError(f"{source.label}_changed")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(source.descriptor, 1):
            raise ReleaseVerificationError(f"{source.label}_changed")
    except OSError as exc:
        raise ReleaseVerificationError(f"{source.label}_changed") from exc
    _assert_pinned_regular_file_unchanged(source)
    return b"".join(chunks)


def _sha256_pinned_regular_file(source: _PinnedRegularFile) -> str:
    digest = hashlib.sha256()
    try:
        os.lseek(source.descriptor, 0, os.SEEK_SET)
        remaining = source.descriptor_signature.size
        while remaining:
            chunk = os.read(source.descriptor, min(STREAM_CHUNK_BYTES, remaining))
            if not chunk:
                raise ReleaseVerificationError(f"{source.label}_changed")
            digest.update(chunk)
            remaining -= len(chunk)
        if os.read(source.descriptor, 1):
            raise ReleaseVerificationError(f"{source.label}_changed")
    except OSError as exc:
        raise ReleaseVerificationError(f"{source.label}_changed") from exc
    _assert_pinned_regular_file_unchanged(source)
    return digest.hexdigest()


def _load_external_manifest(source: _PinnedRegularFile) -> tuple[dict[str, Any], str]:
    raw = _read_exact_pinned_regular_file(source)

    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ReleaseVerificationError("release_manifest_duplicate_key")
            value[key] = item
        return value

    try:
        parsed = json.loads(raw.decode("utf-8"), object_pairs_hook=reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseVerificationError("release_manifest_invalid") from exc
    if not isinstance(parsed, dict):
        raise ReleaseVerificationError("release_manifest_invalid")
    return parsed, hashlib.sha256(raw).hexdigest()


def _validate_external_manifest(
    manifest: dict[str, Any], *, max_files: int, max_total_bytes: int
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    schema = manifest.get("schema_version")
    legacy_fields = {"schema_version", "identity", "version", "archive", "archive_root", "files"}
    current_fields = legacy_fields | {"builder_identity", "source_tree_sha256", "directories"}
    if schema == "1" and set(manifest) == legacy_fields:
        directories: list[dict[str, Any]] = []
    elif schema == MANIFEST_SCHEMA_VERSION and set(manifest) == current_fields:
        builder_identity = manifest.get("builder_identity")
        if builder_identity != BUILDER_IDENTITY:
            raise ReleaseVerificationError("release_manifest_builder_identity_invalid")
        source_tree_sha256 = manifest.get("source_tree_sha256")
        if not isinstance(source_tree_sha256, str) or not SHA256.fullmatch(source_tree_sha256):
            raise ReleaseVerificationError("release_manifest_source_tree_hash_invalid")
        raw_directories = manifest.get("directories")
        if not isinstance(raw_directories, list):
            raise ReleaseVerificationError("release_manifest_directory_invalid")
        directories = []
        seen_directories: set[str] = set()
        seen_directory_collisions: set[str] = set()
        for row in raw_directories:
            if not isinstance(row, dict) or set(row) != {"path", "mode"}:
                raise ReleaseVerificationError("release_manifest_directory_invalid")
            relative = _safe_manifest_path(row.get("path"), "release_manifest")
            collision = _path_collision_key(relative)
            if relative in seen_directories or collision in seen_directory_collisions:
                raise ReleaseVerificationError("release_manifest_directory_collision")
            if row.get("mode") != "0755":
                raise ReleaseVerificationError("release_manifest_directory_mode_invalid")
            seen_directories.add(relative)
            seen_directory_collisions.add(collision)
            directories.append({"path": relative, "mode": "0755"})
        if [row["path"] for row in directories] != sorted(seen_directories):
            raise ReleaseVerificationError("release_manifest_directories_not_sorted")
    else:
        raise ReleaseVerificationError("release_manifest_schema_invalid")

    identity = manifest.get("identity")
    archive_root = manifest.get("archive_root")
    version = manifest.get("version")
    archive = manifest.get("archive")
    if not isinstance(identity, str) or not SAFE_ARCHIVE_ROOT.fullmatch(identity):
        raise ReleaseVerificationError("release_manifest_identity_invalid")
    if not isinstance(archive_root, str) or not SAFE_ARCHIVE_ROOT.fullmatch(archive_root):
        raise ReleaseVerificationError("release_manifest_archive_root_invalid")
    if not isinstance(version, str) or not CALVER.fullmatch(version):
        raise ReleaseVerificationError("release_manifest_version_invalid")
    if not isinstance(archive, str) or Path(archive).name != archive or len(archive) > 255:
        raise ReleaseVerificationError("release_manifest_archive_invalid")
    raw_files = manifest.get("files")
    if not isinstance(raw_files, list) or len(raw_files) + len(directories) + 1 > max_files:
        raise ReleaseVerificationError("release_manifest_entry_limit_exceeded")
    files: list[dict[str, Any]] = []
    seen_files: set[str] = set()
    seen_file_collisions: set[str] = set()
    total_bytes = 0
    for row in raw_files:
        if not isinstance(row, dict) or set(row) != {"path", "bytes", "sha256", "mode"}:
            raise ReleaseVerificationError("release_manifest_file_invalid")
        relative = _safe_manifest_path(row.get("path"), "release_manifest")
        collision = _path_collision_key(relative)
        if relative in seen_files or collision in seen_file_collisions:
            raise ReleaseVerificationError("release_manifest_file_collision")
        byte_count = row.get("bytes")
        digest = row.get("sha256")
        mode = row.get("mode")
        if isinstance(byte_count, bool) or not isinstance(byte_count, int) or byte_count < 0:
            raise ReleaseVerificationError("release_manifest_size_invalid")
        if not isinstance(digest, str) or not SHA256.fullmatch(digest):
            raise ReleaseVerificationError("release_manifest_hash_invalid")
        if not isinstance(mode, str) or not re.fullmatch(r"0[0-7]{3}", mode):
            raise ReleaseVerificationError("release_manifest_mode_invalid")
        if mode != f"{_normalized_file_mode(relative):04o}":
            raise ReleaseVerificationError("release_manifest_mode_policy_invalid")
        total_bytes += byte_count
        if total_bytes > max_total_bytes:
            raise ReleaseVerificationError("release_manifest_content_bytes_exceeded")
        seen_files.add(relative)
        seen_file_collisions.add(collision)
        files.append({"path": relative, "bytes": byte_count, "sha256": digest, "mode": mode})
    if [row["path"] for row in files] != sorted(seen_files):
        raise ReleaseVerificationError("release_manifest_files_not_sorted")
    if not set(RELEASE_CONFIGURATION_TEMPLATES).issubset(seen_files):
        raise ReleaseVerificationError("release_manifest_required_configuration_missing")
    if schema == MANIFEST_SCHEMA_VERSION and manifest["source_tree_sha256"] != _manifest_tree_sha256(files):
        raise ReleaseVerificationError("release_manifest_source_tree_hash_mismatch")
    return files, directories


def _open_release_inputs(
    archive_path: Path, manifest_path: Path, *, max_total_bytes: int
) -> tuple[_PinnedRegularFile, _PinnedRegularFile]:
    archive = _open_pinned_regular_file(
        archive_path,
        max_total_bytes + ARCHIVE_OVERHEAD_BYTES,
        "release_archive",
    )
    try:
        manifest = _open_pinned_regular_file(
            manifest_path,
            DEFAULT_MAX_MANIFEST_BYTES,
            "release_manifest",
        )
    except Exception:
        os.close(archive.descriptor)
        raise
    return archive, manifest


def _verify_pinned_release_archive(
    archive: _PinnedRegularFile,
    manifest_source: _PinnedRegularFile,
    archive_name: str,
    *,
    max_files: int,
    max_total_bytes: int,
) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    manifest, manifest_sha256 = _load_external_manifest(manifest_source)
    files, directories = _validate_external_manifest(
        manifest, max_files=max_files, max_total_bytes=max_total_bytes
    )
    if manifest["archive"] != archive_name:
        raise ReleaseVerificationError("release_manifest_archive_name_mismatch")
    archive_root = str(manifest["archive_root"])
    expected_files = {f"{archive_root}/{row['path']}": row for row in files}
    expected_directories = {archive_root, *(f"{archive_root}/{row['path']}" for row in directories)}
    seen_files: set[str] = set()
    seen_directories: set[str] = set()
    seen_collisions: set[str] = set()
    total_bytes = 0
    archive_sha256 = _sha256_pinned_regular_file(archive)
    duplicate = -1
    try:
        duplicate = os.dup(archive.descriptor)
        os.lseek(duplicate, 0, os.SEEK_SET)
        with os.fdopen(duplicate, "rb") as archive_file:
            duplicate = -1
            with zipfile.ZipFile(archive_file) as zip_archive:
                infos = zip_archive.infolist()
                if len(infos) > max_files:
                    raise ReleaseVerificationError("release_archive_entry_limit_exceeded")
                for info in infos:
                    is_directory = info.is_dir()
                    raw_name = info.filename
                    name = raw_name[:-1] if is_directory else raw_name
                    _safe_manifest_path(name, "release_archive")
                    collision = _path_collision_key(name)
                    if collision in seen_collisions:
                        raise ReleaseVerificationError("release_archive_name_collision")
                    seen_collisions.add(collision)
                    if not (name == archive_root or name.startswith(f"{archive_root}/")):
                        raise ReleaseVerificationError("release_archive_root_mismatch")
                    if info.flag_bits & 0x1:
                        raise ReleaseVerificationError("release_archive_encrypted_entry")
                    if info.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}:
                        raise ReleaseVerificationError("release_archive_compression_invalid")
                    unix_type = (info.external_attr >> 16) & 0o170000
                    mode = (info.external_attr >> 16) & 0o777
                    if is_directory:
                        if unix_type not in {0, stat.S_IFDIR} or info.file_size != 0 or mode != 0o755:
                            raise ReleaseVerificationError("release_archive_directory_invalid")
                        if (
                            manifest["schema_version"] == MANIFEST_SCHEMA_VERSION
                            and name not in expected_directories
                        ):
                            raise ReleaseVerificationError("release_archive_unmanifested_directory")
                        seen_directories.add(name)
                        continue
                    if unix_type not in {0, stat.S_IFREG}:
                        raise ReleaseVerificationError("release_archive_special_entry")
                    row = expected_files.get(name)
                    if row is None:
                        raise ReleaseVerificationError("release_archive_unmanifested_entry")
                    if info.file_size != row["bytes"] or mode != int(str(row["mode"]), 8):
                        raise ReleaseVerificationError("release_archive_member_metadata_mismatch")
                    total_bytes += info.file_size
                    if total_bytes > max_total_bytes:
                        raise ReleaseVerificationError("release_archive_content_bytes_exceeded")
                    digest = hashlib.sha256()
                    member_bytes = 0
                    with zip_archive.open(info, "r") as member:
                        while chunk := member.read(STREAM_CHUNK_BYTES):
                            member_bytes += len(chunk)
                            if member_bytes > row["bytes"]:
                                raise ReleaseVerificationError("release_archive_member_size_mismatch")
                            digest.update(chunk)
                    if member_bytes != row["bytes"] or digest.hexdigest() != row["sha256"]:
                        raise ReleaseVerificationError("release_archive_member_hash_mismatch")
                    seen_files.add(name)
    except ReleaseVerificationError:
        raise
    except (
        OSError,
        RuntimeError,
        EOFError,
        zipfile.BadZipFile,
        zipfile.LargeZipFile,
        zlib.error,
    ) as exc:
        raise ReleaseVerificationError("release_archive_malformed") from exc
    finally:
        if duplicate >= 0:
            os.close(duplicate)
    if seen_files != set(expected_files):
        raise ReleaseVerificationError("release_archive_manifest_members_mismatch")
    if manifest["schema_version"] == MANIFEST_SCHEMA_VERSION:
        if seen_directories != expected_directories:
            raise ReleaseVerificationError("release_archive_manifest_directories_mismatch")
    elif archive_root not in seen_directories:
        raise ReleaseVerificationError("release_archive_root_missing")
    if _sha256_pinned_regular_file(manifest_source) != manifest_sha256:
        raise ReleaseVerificationError("release_manifest_changed")
    if _sha256_pinned_regular_file(archive) != archive_sha256:
        raise ReleaseVerificationError("release_archive_changed")
    summary = {
        "ok": True,
        "identity": manifest["identity"],
        "version": manifest["version"],
        "archive": manifest["archive"],
        "archive_sha256": archive_sha256,
        "manifest_sha256": manifest_sha256,
        "file_count": len(files),
        "total_bytes": total_bytes,
    }
    return summary, manifest, files, directories


def verify_release_archive(
    archive_path: Path,
    manifest_path: Path,
    *,
    max_files: int = DEFAULT_MAX_FILES,
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
) -> dict[str, Any]:
    """Verify a release ZIP and manifest before extraction or code execution.

    This verifies local archive structure and content integrity only.  It does
    not establish who produced the archive; a colocated SHA-256 sidecar is
    deliberately not a trust input.
    """

    if max_files <= 0 or max_total_bytes <= 0:
        raise ReleaseVerificationError("invalid_release_limits")
    archive, manifest = _open_release_inputs(
        archive_path,
        manifest_path,
        max_total_bytes=max_total_bytes,
    )
    try:
        summary, _, _, _ = _verify_pinned_release_archive(
            archive,
            manifest,
            archive_path.name,
            max_files=max_files,
            max_total_bytes=max_total_bytes,
        )
        return summary
    finally:
        os.close(manifest.descriptor)
        os.close(archive.descriptor)


def _extraction_destination(destination: Path) -> _ExtractionDestination:
    """Pin a new destination below a non-link parent before extraction.

    POSIX receivers retain an opened descriptor for the parent.  That
    descriptor remains valid if a path spelling is later swapped, and is the
    only parent used for staging and publication.  Native Windows has no
    equivalent ``dir_fd`` primitive in the standard runtime, so it keeps the
    validated path and performs a second fail-closed check at publication.
    """

    target = Path(os.path.abspath(os.fspath(destination)))
    if not target.name or target.name in {".", ".."}:
        raise ReleaseVerificationError("release_destination_invalid")
    parent = target.parent
    try:
        parent_info = parent.lstat()
    except OSError as exc:
        raise ReleaseVerificationError("release_destination_parent_unreadable") from exc
    if stat.S_ISLNK(parent_info.st_mode) or not stat.S_ISDIR(parent_info.st_mode):
        raise ReleaseVerificationError("release_destination_parent_invalid")
    identity = (parent_info.st_dev, parent_info.st_ino)
    if os.name == "nt":
        if os.path.lexists(target):
            raise ReleaseVerificationError("release_destination_exists")
        return _ExtractionDestination(target, parent, target.name, identity, None)

    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(parent, flags)
    except OSError as exc:
        raise ReleaseVerificationError("release_destination_parent_unreadable") from exc
    try:
        opened = os.fstat(descriptor)
        if (
            stat.S_ISLNK(opened.st_mode)
            or not stat.S_ISDIR(opened.st_mode)
            or (opened.st_dev, opened.st_ino) != identity
        ):
            raise ReleaseVerificationError("release_destination_parent_invalid")
        try:
            os.stat(target.name, dir_fd=descriptor, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise ReleaseVerificationError("release_destination_exists")
    except Exception:
        os.close(descriptor)
        raise
    return _ExtractionDestination(target, parent, target.name, identity, descriptor)


def _destination_parent_path_is_expected(destination: _ExtractionDestination) -> bool:
    """Check that the caller's parent spelling still names the pinned parent."""

    try:
        info = destination.parent.lstat()
    except OSError:
        return False
    return (
        not stat.S_ISLNK(info.st_mode)
        and stat.S_ISDIR(info.st_mode)
        and (info.st_dev, info.st_ino) == destination.parent_identity
    )


def _open_directory_at(parent_fd: int, name: str, *, error: str) -> int:
    """Open exactly one non-link directory below an already pinned parent."""

    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(name, flags, dir_fd=parent_fd)
    except OSError as exc:
        raise ReleaseVerificationError(error) from exc
    try:
        info = os.fstat(descriptor)
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise ReleaseVerificationError(error)
    except Exception:
        os.close(descriptor)
        raise
    return descriptor


def _mkdir_open_directory_at(parent_fd: int, parts: Sequence[str]) -> int:
    """Create/open an owned directory path without resolving a pathname twice."""

    current = os.dup(parent_fd)
    try:
        for part in parts:
            if not part or part in {".", ".."} or "/" in part or "\\" in part:
                raise ReleaseVerificationError("release_extraction_path_invalid")
            try:
                os.mkdir(part, mode=0o755, dir_fd=current)
            except FileExistsError:
                pass
            except OSError as exc:
                raise ReleaseVerificationError("release_extraction_directory_create_failed") from exc
            next_descriptor = _open_directory_at(
                current, part, error="release_extraction_directory_invalid"
            )
            try:
                os.fchmod(next_descriptor, 0o755)
                info = os.fstat(next_descriptor)
                if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o755:
                    raise ReleaseVerificationError("release_extraction_directory_mode_mismatch")
            except Exception:
                os.close(next_descriptor)
                raise
            os.close(current)
            current = next_descriptor
        return current
    except Exception:
        os.close(current)
        raise


def _create_staging_directory(parent_fd: int, target_name: str) -> tuple[str, int, tuple[int, int]]:
    """Make one private sibling staging directory through the pinned parent."""

    for _ in range(16):
        name = f".{target_name}.extracting-{secrets.token_hex(16)}"
        try:
            os.mkdir(name, mode=0o700, dir_fd=parent_fd)
        except FileExistsError:
            continue
        except OSError as exc:
            raise ReleaseVerificationError("release_extraction_staging_create_failed") from exc
        descriptor = _open_directory_at(
            parent_fd, name, error="release_extraction_staging_invalid"
        )
        try:
            info = os.fstat(descriptor)
            if stat.S_IMODE(info.st_mode) != 0o700:
                raise ReleaseVerificationError("release_extraction_staging_mode_invalid")
            return name, descriptor, (info.st_dev, info.st_ino)
        except Exception:
            os.close(descriptor)
            raise
    raise ReleaseVerificationError("release_extraction_staging_create_failed")


def _copy_verified_member_at(
    archive: zipfile.ZipFile,
    entry_name: str,
    row: dict[str, Any],
    parent_fd: int,
    name: str,
) -> None:
    """Copy one verified member through an owned directory descriptor."""

    expected_mode = int(str(row["mode"]), 8)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(name, flags, expected_mode, dir_fd=parent_fd)
    except OSError as exc:
        raise ReleaseVerificationError("release_extraction_file_create_failed") from exc
    remove = True
    try:
        digest = hashlib.sha256()
        remaining = int(row["bytes"])
        with os.fdopen(descriptor, "wb") as output:
            descriptor = -1
            with archive.open(entry_name, "r") as member:
                while remaining:
                    chunk = member.read(min(STREAM_CHUNK_BYTES, remaining))
                    if not chunk:
                        raise ReleaseVerificationError("release_extraction_member_size_mismatch")
                    output.write(chunk)
                    digest.update(chunk)
                    remaining -= len(chunk)
                if member.read(1):
                    raise ReleaseVerificationError("release_extraction_member_size_mismatch")
            output.flush()
            os.fsync(output.fileno())
            os.fchmod(output.fileno(), expected_mode)
            info = os.fstat(output.fileno())
            if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != expected_mode:
                raise ReleaseVerificationError("release_extraction_member_mode_mismatch")
        if digest.hexdigest() != row["sha256"]:
            raise ReleaseVerificationError("release_extraction_member_hash_mismatch")
        remove = False
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if remove:
            try:
                os.unlink(name, dir_fd=parent_fd)
            except OSError:
                pass


def _staging_entry_is_expected(parent_fd: int, name: str, identity: tuple[int, int]) -> bool:
    """Confirm the staging name still denotes the private directory we made."""

    try:
        info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError:
        return False
    return (
        not stat.S_ISLNK(info.st_mode)
        and stat.S_ISDIR(info.st_mode)
        and (info.st_dev, info.st_ino) == identity
    )


def _cleanup_staging_directory(
    parent_fd: int, name: str, identity: tuple[int, int]
) -> None:
    """Best-effort cleanup that never follows or removes a replaced staging name."""

    if not _staging_entry_is_expected(parent_fd, name, identity):
        return
    try:
        descriptor = _open_directory_at(
            parent_fd, name, error="release_extraction_staging_invalid"
        )
    except ReleaseVerificationError:
        return
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != identity:
            return
        for child in os.listdir(descriptor):
            try:
                info = os.stat(child, dir_fd=descriptor, follow_symlinks=False)
            except OSError:
                continue
            if stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode):
                _cleanup_staging_directory(descriptor, child, (info.st_dev, info.st_ino))
            else:
                try:
                    os.unlink(child, dir_fd=descriptor)
                except OSError:
                    pass
    finally:
        os.close(descriptor)
    if _staging_entry_is_expected(parent_fd, name, identity):
        try:
            os.rmdir(name, dir_fd=parent_fd)
        except OSError:
            pass


def _rename_noreplace_at(parent_fd: int, source: str, destination: str) -> None:
    """Publish a sibling directory without replacement using Linux renameat2."""

    try:
        libc = ctypes.CDLL(None, use_errno=True)
        renameat2 = libc.renameat2
    except (AttributeError, OSError) as exc:
        raise ReleaseVerificationError("release_atomic_noreplace_unavailable") from exc
    renameat2.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameat2.restype = ctypes.c_int
    result = renameat2(
        parent_fd,
        os.fsencode(source),
        parent_fd,
        os.fsencode(destination),
        RENAME_NOREPLACE,
    )
    if result == 0:
        return
    failure = ctypes.get_errno()
    if failure in {errno.EEXIST, errno.ENOTEMPTY}:
        raise ReleaseVerificationError("release_destination_exists")
    if failure in {errno.ENOSYS, errno.EINVAL, errno.EOPNOTSUPP}:
        raise ReleaseVerificationError("release_atomic_noreplace_unavailable")
    raise ReleaseVerificationError("release_destination_publish_failed")


def _staged_path(root: Path, relative: str) -> Path:
    """Join an already-validated POSIX member below the owned staging root."""

    path = root.joinpath(*PurePosixPath(relative).parts)
    try:
        path.relative_to(root)
    except ValueError as exc:  # Defense in depth for future manifest changes.
        raise ReleaseVerificationError("release_extraction_path_invalid") from exc
    return path


def _copy_verified_member(
    archive: zipfile.ZipFile,
    entry_name: str,
    row: dict[str, Any],
    destination: Path,
) -> None:
    """Copy one already-verified ZIP member into a no-clobber regular file."""

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(destination, flags, int(str(row["mode"]), 8))
    except OSError as exc:
        raise ReleaseVerificationError("release_extraction_file_create_failed") from exc
    try:
        digest = hashlib.sha256()
        remaining = int(row["bytes"])
        with os.fdopen(descriptor, "wb") as output:
            descriptor = -1
            with archive.open(entry_name, "r") as member:
                while remaining:
                    chunk = member.read(min(STREAM_CHUNK_BYTES, remaining))
                    if not chunk:
                        raise ReleaseVerificationError("release_extraction_member_size_mismatch")
                    output.write(chunk)
                    digest.update(chunk)
                    remaining -= len(chunk)
                if member.read(1):
                    raise ReleaseVerificationError("release_extraction_member_size_mismatch")
                output.flush()
                os.fsync(output.fileno())
        os.chmod(destination, int(str(row["mode"]), 8), follow_symlinks=False)
        if os.name != "nt":
            info = destination.lstat()
            if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != int(str(row["mode"]), 8):
                raise ReleaseVerificationError("release_extraction_member_mode_mismatch")
        if digest.hexdigest() != row["sha256"]:
            raise ReleaseVerificationError("release_extraction_member_hash_mismatch")
    except Exception:
        destination.unlink(missing_ok=True)
        raise
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def extract_release_archive(
    archive_path: Path,
    manifest_path: Path,
    destination: Path,
    *,
    max_files: int = DEFAULT_MAX_FILES,
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
) -> dict[str, Any]:
    """Safely extract one verified release into a new destination directory.

    This is a local content-integrity operation, not publisher authentication.
    It never calls ``ZipFile.extract``/``extractall`` and publishes the staged
    directory only after every member is copied, hashed, and mode-checked.
    """

    if max_files <= 0 or max_total_bytes <= 0:
        raise ReleaseVerificationError("invalid_release_limits")
    archive_source, manifest_source = _open_release_inputs(
        archive_path,
        manifest_path,
        max_total_bytes=max_total_bytes,
    )
    target: _ExtractionDestination | None = None
    staging: Path | None = None
    staging_name: str | None = None
    staging_fd: int | None = None
    staging_identity: tuple[int, int] | None = None
    duplicate = -1
    try:
        verified, manifest, files, directories = _verify_pinned_release_archive(
            archive_source,
            manifest_source,
            archive_path.name,
            max_files=max_files,
            max_total_bytes=max_total_bytes,
        )
        archive_root = str(manifest["archive_root"])
        target = _extraction_destination(destination)
        duplicate = os.dup(archive_source.descriptor)
        os.lseek(duplicate, 0, os.SEEK_SET)
        with os.fdopen(duplicate, "rb") as archive_file:
            duplicate = -1
            with zipfile.ZipFile(archive_file) as zip_archive:
                if target.parent_fd is not None:
                    staging_name, staging_fd, staging_identity = _create_staging_directory(
                        target.parent_fd, target.name
                    )
                    staged_root_fd = _mkdir_open_directory_at(staging_fd, (archive_root,))
                    try:
                        for directory in directories:
                            directory_fd = _mkdir_open_directory_at(
                                staged_root_fd,
                                PurePosixPath(str(directory["path"])).parts,
                            )
                            os.close(directory_fd)
                        for row in files:
                            relative = str(row["path"])
                            parts = PurePosixPath(relative).parts
                            parent_fd = _mkdir_open_directory_at(staged_root_fd, parts[:-1])
                            try:
                                _copy_verified_member_at(
                                    zip_archive,
                                    f"{archive_root}/{relative}",
                                    row,
                                    parent_fd,
                                    parts[-1],
                                )
                            finally:
                                os.close(parent_fd)
                    finally:
                        os.close(staged_root_fd)
                    # The receiver-owned wrapper stays private; the archived
                    # root and every manifest directory are already 0755.
                    os.fchmod(staging_fd, 0o700)
                    staged_info = os.fstat(staging_fd)
                    if (
                        not stat.S_ISDIR(staged_info.st_mode)
                        or stat.S_IMODE(staged_info.st_mode) != 0o700
                        or (staged_info.st_dev, staged_info.st_ino) != staging_identity
                    ):
                        raise ReleaseVerificationError("release_extraction_staging_invalid")
                else:
                    # Native Windows has no standard-library equivalent to a
                    # descriptor-anchored renameat2.  It still refuses an
                    # existing destination before calling os.rename(), but
                    # this branch deliberately does not claim POSIX atomicity.
                    staging = Path(
                        tempfile.mkdtemp(prefix=f".{target.name}.extracting-", dir=str(target.parent))
                    )
                    os.chmod(staging, 0o700)
                    staged_root = staging / archive_root
                    staged_root.mkdir(mode=0o755)
                    for directory in directories:
                        path = _staged_path(staged_root, str(directory["path"]))
                        path.mkdir(mode=0o755)
                        os.chmod(path, 0o755, follow_symlinks=False)
                    for row in files:
                        relative = str(row["path"])
                        path = _staged_path(staged_root, relative)
                        path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
                        _copy_verified_member(
                            zip_archive,
                            f"{archive_root}/{relative}",
                            row,
                            path,
                        )
                    for directory in [staged_root, *sorted(staged_root.rglob("*"))]:
                        if directory.is_dir() and not directory.is_symlink():
                            os.chmod(directory, 0o755, follow_symlinks=False)
                    os.chmod(staging, 0o700)
        if target.parent_fd is not None:
            if (
                staging_name is None
                or staging_identity is None
                or not _staging_entry_is_expected(
                    target.parent_fd, staging_name, staging_identity
                )
            ):
                raise ReleaseVerificationError("release_destination_parent_changed")
            parent_info = os.fstat(target.parent_fd)
            if (
                not stat.S_ISDIR(parent_info.st_mode)
                or (parent_info.st_dev, parent_info.st_ino) != target.parent_identity
                or not _destination_parent_path_is_expected(target)
            ):
                raise ReleaseVerificationError("release_destination_parent_changed")
            if _sha256_pinned_regular_file(manifest_source) != verified["manifest_sha256"]:
                raise ReleaseVerificationError("release_manifest_changed")
            if _sha256_pinned_regular_file(archive_source) != verified["archive_sha256"]:
                raise ReleaseVerificationError("release_archive_changed")
            _rename_noreplace_at(target.parent_fd, staging_name, target.name)
            if not _destination_parent_path_is_expected(target):
                _cleanup_staging_directory(
                    target.parent_fd, target.name, staging_identity
                )
                raise ReleaseVerificationError("release_destination_parent_changed")
            staging_name = None
        else:
            if not _destination_parent_path_is_expected(target):
                raise ReleaseVerificationError("release_destination_parent_changed")
            if os.path.lexists(target.target):
                raise ReleaseVerificationError("release_destination_exists")
            if _sha256_pinned_regular_file(manifest_source) != verified["manifest_sha256"]:
                raise ReleaseVerificationError("release_manifest_changed")
            if _sha256_pinned_regular_file(archive_source) != verified["archive_sha256"]:
                raise ReleaseVerificationError("release_archive_changed")
            os.rename(staging, target.target)
            staging = None
    except ReleaseVerificationError:
        raise
    except (
        OSError,
        RuntimeError,
        EOFError,
        zipfile.BadZipFile,
        zipfile.LargeZipFile,
        zlib.error,
    ) as exc:
        raise ReleaseVerificationError("release_extraction_failed") from exc
    finally:
        if duplicate >= 0:
            os.close(duplicate)
        if staging is not None:
            shutil.rmtree(staging, ignore_errors=True)
        if (
            target is not None
            and target.parent_fd is not None
            and staging_name is not None
            and staging_identity is not None
        ):
            _cleanup_staging_directory(target.parent_fd, staging_name, staging_identity)
        if staging_fd is not None:
            os.close(staging_fd)
        if target is not None and target.parent_fd is not None:
            os.close(target.parent_fd)
        os.close(manifest_source.descriptor)
        os.close(archive_source.descriptor)
    assert target is not None
    return {
        "ok": True,
        "archive": verified["archive"],
        "archive_sha256": verified["archive_sha256"],
        "file_count": len(files),
        "total_bytes": sum(int(row["bytes"]) for row in files),
        "destination": target.name,
    }


def _inventory_signature(
    directories: list[Path], files: list[ReleaseFile], total_bytes: int
) -> tuple[tuple[str, ...], tuple[tuple[str, int], ...], int]:
    """Represent the bounded inventory without leaking absolute source paths."""

    return (
        tuple(directory.as_posix() for directory in directories),
        tuple((source_file.relative_path, source_file.size) for source_file in files),
        total_bytes,
    )


def _hash_current_source(path: Path) -> tuple[int, str]:
    """Hash one regular source file while rejecting a concurrent node replacement."""

    try:
        if path.is_symlink():
            raise ReleaseBuildError("release_source_changed")
        before = path.stat()
        if not stat.S_ISREG(before.st_mode):
            raise ReleaseBuildError("release_source_changed")
        digest = hashlib.sha256()
        byte_count = 0
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(STREAM_CHUNK_BYTES), b""):
                digest.update(chunk)
                byte_count += len(chunk)
        after = path.stat()
    except OSError as exc:
        raise ReleaseBuildError("release_source_changed") from exc
    if (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ):
        raise ReleaseBuildError("release_source_changed")
    return byte_count, digest.hexdigest()


def _verify_quiescent_source(
    source_root: Path,
    directories: list[Path],
    files: list[ReleaseFile],
    total_bytes: int,
    manifest_files: list[dict[str, Any]],
    initial_tree_hash: str,
    *,
    max_files: int,
    max_total_bytes: int,
    selected_adapter: str | None = None,
) -> None:
    """Require the post-archive source to match both inventory and archived bytes."""

    expected_inventory = _inventory_signature(directories, files, total_bytes)
    try:
        post_directories, post_files, post_total_bytes = _collect_source_files(
            source_root,
            max_files=max_files,
            max_total_bytes=max_total_bytes,
            selected_adapter=selected_adapter,
        )
    except ReleaseBuildError as exc:
        raise ReleaseBuildError("release_source_changed") from exc
    if _inventory_signature(post_directories, post_files, post_total_bytes) != expected_inventory:
        raise ReleaseBuildError("release_source_changed")
    if _strict_validate(source_root, mutation_check=True) != initial_tree_hash:
        raise ReleaseBuildError("release_source_changed")
    if len(manifest_files) != len(files):
        raise ReleaseBuildError("release_source_changed")
    for source_file, manifest_file in zip(files, manifest_files, strict=True):
        if (
            manifest_file.get("path") != source_file.relative_path
            or manifest_file.get("bytes") != source_file.size
        ):
            raise ReleaseBuildError("release_source_changed")
        byte_count, digest = _hash_current_source(source_file.path)
        if byte_count != manifest_file.get("bytes") or digest != manifest_file.get("sha256"):
            raise ReleaseBuildError("release_source_changed")
    try:
        final_directories, final_files, final_total_bytes = _collect_source_files(
            source_root,
            max_files=max_files,
            max_total_bytes=max_total_bytes,
            selected_adapter=selected_adapter,
        )
    except ReleaseBuildError as exc:
        raise ReleaseBuildError("release_source_changed") from exc
    if _inventory_signature(final_directories, final_files, final_total_bytes) != expected_inventory:
        raise ReleaseBuildError("release_source_changed")
    if _strict_validate(source_root, mutation_check=True) != initial_tree_hash:
        raise ReleaseBuildError("release_source_changed")


def _write_temporary_bytes(directory: Path, prefix: str, data: bytes) -> Path:
    descriptor, name = tempfile.mkstemp(prefix=prefix, dir=str(directory))
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    return temporary


def _publish_new_file(temporary: Path, final: Path) -> None:
    """Atomically publish without replacing a pre-existing release artifact."""

    os.link(temporary, final)
    temporary.unlink()


def build_release(
    source_root: Path,
    output_directory: Path,
    *,
    max_files: int = DEFAULT_MAX_FILES,
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
    selected_adapter: str | None = None,
) -> dict[str, Any]:
    """Validate and package one strict source tree into deterministic sidecar artifacts."""

    source = source_root.resolve()
    if not source.is_dir():
        raise ReleaseBuildError("release_source_missing")
    output = _output_outside_source(source, output_directory)
    # Reject a directory, link, or special legacy path before strict validation
    # can traverse and hash any private descendant.
    _validate_legacy_event_root(source)
    if selected_adapter is not None:
        if not SAFE_ARCHIVE_ROOT.fullmatch(selected_adapter):
            raise ReleaseBuildError("invalid_selected_adapter")
        descriptor = source / "adapters" / selected_adapter / "adapter.json"
        if descriptor.is_symlink() or not descriptor.is_file():
            raise ReleaseBuildError("selected_adapter_missing")
    initial_tree_hash = _strict_validate(source)
    release, version, timestamp = _release_metadata(source)
    archive_root = str(release["archive_root"])
    directories, files, total_bytes = _collect_source_files(
        source,
        max_files=max_files,
        max_total_bytes=max_total_bytes,
        selected_adapter=selected_adapter,
    )
    identity = str(release.get("identity") or "rookery")
    if not SAFE_ARCHIVE_ROOT.fullmatch(identity):
        raise ReleaseBuildError("invalid_release_identity")
    archive_name = f"{identity}-{version}.zip"
    manifest_name = f"{identity}-{version}.manifest.json"
    sha_name = f"{archive_name}.sha256"
    output.mkdir(parents=True, exist_ok=True)
    final_archive = output / archive_name
    final_manifest = output / manifest_name
    final_sha = output / sha_name
    if any(path.exists() for path in (final_archive, final_manifest, final_sha)):
        raise ReleaseBuildError("release_artifact_already_exists")

    zip_descriptor, zip_name = tempfile.mkstemp(prefix=f".{archive_name}.", dir=str(output))
    os.close(zip_descriptor)
    temporary_archive = Path(zip_name)
    temporary_manifest: Path | None = None
    temporary_sha: Path | None = None
    published: list[Path] = []
    try:
        manifest_files: list[dict[str, Any]] = []
        with zipfile.ZipFile(
            temporary_archive,
            mode="w",
            compression=zipfile.ZIP_DEFLATED,
            compresslevel=9,
            strict_timestamps=True,
        ) as archive:
            members = [(f"{archive_root}/", None)]
            members.extend((f"{archive_root}/{directory.as_posix()}/", None) for directory in directories)
            members.extend((f"{archive_root}/{source_file.relative_path}", source_file) for source_file in files)
            for entry_name, source_file in sorted(members, key=lambda member: member[0]):
                if source_file is None:
                    archive.writestr(_zip_info(entry_name, timestamp, 0o755, directory=True), b"")
                else:
                    manifest_files.append(
                        _write_release_file(archive, entry_name, source_file, timestamp)
                    )
        _fsync(temporary_archive)
        _verify_quiescent_source(
            source,
            directories,
            files,
            total_bytes,
            manifest_files,
            initial_tree_hash,
            max_files=max_files,
            max_total_bytes=max_total_bytes,
            selected_adapter=selected_adapter,
        )
        archive_sha256 = _sha256_file(temporary_archive)
        manifest = {
            "schema_version": MANIFEST_SCHEMA_VERSION,
            "identity": identity,
            "version": version,
            "archive": archive_name,
            "archive_root": archive_root,
            "builder_identity": BUILDER_IDENTITY,
            # This describes the bytes that will exist after extraction.  It
            # intentionally uses the synthesized configuration templates
            # rather than possibly private working-tree inputs.
            "source_tree_sha256": _manifest_tree_sha256(manifest_files),
            "directories": [
                {"path": directory.as_posix(), "mode": "0755"}
                for directory in directories
            ],
            "files": manifest_files,
        }
        temporary_manifest = _write_temporary_bytes(
            output,
            f".{manifest_name}.",
            (json.dumps(manifest, sort_keys=True, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8"),
        )
        temporary_sha = _write_temporary_bytes(
            output,
            f".{sha_name}.",
            f"{archive_sha256}  {archive_name}\n".encode("ascii"),
        )
        for temporary, final in (
            (temporary_archive, final_archive),
            (temporary_manifest, final_manifest),
            (temporary_sha, final_sha),
        ):
            _publish_new_file(temporary, final)
            published.append(final)
        return {
            "ok": True,
            "archive": archive_name,
            "manifest": manifest_name,
            "sha256_sidecar": sha_name,
            "version": version,
            "file_count": len(files),
            "total_bytes": total_bytes,
            "archive_sha256": archive_sha256,
            "selected_adapter": selected_adapter,
        }
    except Exception:
        for path in published:
            path.unlink(missing_ok=True)
        raise
    finally:
        for temporary in (temporary_archive, temporary_manifest, temporary_sha):
            if temporary is not None:
                temporary.unlink(missing_ok=True)


def _positive_integer(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return parsed


def main(wrapper_path: Path, argv: Sequence[str] | None = None) -> int:
    """Run the shipped deterministic release builder or verified extractor."""

    parser = argparse.ArgumentParser(description="Build a deterministic strict Rookery release archive")
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--extract-archive", type=Path)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--extract-dir", type=Path)
    parser.add_argument("--adapter-only")
    parser.add_argument("--max-files", type=_positive_integer, default=DEFAULT_MAX_FILES)
    parser.add_argument("--max-total-bytes", type=_positive_integer, default=DEFAULT_MAX_TOTAL_BYTES)
    arguments = parser.parse_args(argv)
    try:
        if arguments.output_dir is not None:
            if any(
                value is not None
                for value in (arguments.extract_archive, arguments.manifest, arguments.extract_dir)
            ):
                parser.error("--output-dir cannot be combined with extraction arguments")
            summary = build_release(
                source_root_from_wrapper(wrapper_path),
                arguments.output_dir,
                max_files=arguments.max_files,
                max_total_bytes=arguments.max_total_bytes,
                selected_adapter=arguments.adapter_only,
            )
        else:
            if arguments.adapter_only is not None:
                parser.error("--adapter-only requires --output-dir")
            if not all((arguments.extract_archive, arguments.manifest, arguments.extract_dir)):
                parser.error(
                    "supply --output-dir or all of --extract-archive, --manifest, and --extract-dir"
                )
            summary = extract_release_archive(
                arguments.extract_archive,
                arguments.manifest,
                arguments.extract_dir,
                max_files=arguments.max_files,
                max_total_bytes=arguments.max_total_bytes,
            )
    except (OSError, ReleaseBuildError, ReleaseVerificationError):
        error = "release_extract_failed" if arguments.extract_archive is not None else "release_build_failed"
        print(json.dumps({"ok": False, "error": error}, sort_keys=True))
        return 2
    print(json.dumps(summary, sort_keys=True))
    return 0
