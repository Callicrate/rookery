"""Private, race-resistant output handling shared by Guacamole helpers.

Guacamole transports are optionally supplied by an operator, so their output
directory is both an evidence boundary and a child-process boundary.  A helper
must never turn an arbitrary ``--outdir`` into a writable path merely because
it is lexically convenient.  This module keeps that policy in one place.
"""

from __future__ import annotations

import os
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath

from rookery.portable.util import contained_private_path, ensure_private_dir


GUAC_EVIDENCE_COMPONENTS = ("evidence", "guac")
PRIVATE_DIRECTORY_MODE = 0o700
PRIVATE_FILE_MODE = 0o600


class GuacOutputPathError(ValueError):
    """An output path cannot safely be used as Guacamole-owned evidence."""


def _absolute(path: Path | str) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _has_control_characters(value: str) -> bool:
    return any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)


def _one_component(value: str, *, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise GuacOutputPathError(f"{label} must be a non-empty path component")
    if value in {".", ".."}:
        raise GuacOutputPathError(f"{label} must not be a dot or parent component")
    if _has_control_characters(value):
        raise GuacOutputPathError(f"{label} must not contain control characters")
    if "/" in value or "\\" in value or PureWindowsPath(value).is_absolute():
        raise GuacOutputPathError(f"{label} must be one relative path component")
    if len(value) > 255 or value.endswith((".", " ")):
        raise GuacOutputPathError(f"{label} is not a portable path component")
    return value


def _input_components(value: str) -> tuple[bool, tuple[str, ...]]:
    """Parse a caller path before any normalization can hide traversal."""

    if not isinstance(value, str) or not value:
        raise GuacOutputPathError("--outdir must be non-empty when supplied")
    if _has_control_characters(value):
        raise GuacOutputPathError("--outdir must not contain control characters")
    if "\\" in value:
        raise GuacOutputPathError("--outdir must not contain backslashes")
    windows = PureWindowsPath(value)
    if windows.is_absolute():
        raise GuacOutputPathError("--outdir must not use a Windows absolute path")
    absolute = value.startswith("/")
    raw_parts = value.split("/")
    if absolute:
        raw_parts = raw_parts[1:]
    if not raw_parts or any(part == "" for part in raw_parts):
        raise GuacOutputPathError("--outdir must use normalized path components")
    components = tuple(_one_component(part, label="--outdir") for part in raw_parts)
    return absolute, components


def guac_evidence_root(root: Path | str) -> Path:
    """Return the fixed, workspace-owned family for every Guac artifact."""

    workspace = _absolute(root)
    return contained_private_path(workspace, workspace, *GUAC_EVIDENCE_COMPONENTS)


def _candidate_from_input(root: Path, value: str) -> Path:
    absolute, components = _input_components(value)
    family = guac_evidence_root(root)
    if absolute:
        candidate = Path("/").joinpath(*components)
    else:
        candidate = root.joinpath(*components)
    candidate = _absolute(candidate)
    try:
        relative = candidate.relative_to(family)
    except ValueError as exc:
        raise GuacOutputPathError(
            "--outdir must be contained under the workspace-owned evidence/guac family"
        ) from exc
    if not relative.parts:
        raise GuacOutputPathError("--outdir must name a Guacamole evidence subdirectory")
    # Reconstruct through the shared portable validator.  It rejects current
    # symlink components and ensures the resolved location remains in family.
    return contained_private_path(root, family, *relative.parts)


def _open_directory(path: Path) -> int:
    """Open every component with ``O_NOFOLLOW`` and retain the final FD."""

    absolute = _absolute(path)
    parts = absolute.parts
    if not parts:
        raise GuacOutputPathError(f"unable to open private directory: {path}")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(parts[0], flags)
    try:
        for component in parts[1:]:
            child = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        info = os.fstat(descriptor)
        if not stat.S_ISDIR(info.st_mode):
            raise GuacOutputPathError(f"private output is not a directory: {path}")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _open_child_directory(parent: int, name: str, display: Path) -> int:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(name, flags, dir_fd=parent)
    try:
        if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise GuacOutputPathError(f"owned output component is not a directory: {display}")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _open_regular(parent: int, name: str, display: Path, *, writable: bool) -> int:
    flags = (
        (os.O_WRONLY if writable else os.O_RDONLY)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    descriptor = os.open(name, flags, dir_fd=parent)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise GuacOutputPathError(
                f"owned output must be an unlinked regular file: {display}"
            )
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _harden_tree_descriptor(descriptor: int, display: Path) -> None:
    """Validate and harden one already-owned regular tree by descriptor."""

    info = os.fstat(descriptor)
    if not stat.S_ISDIR(info.st_mode):
        raise GuacOutputPathError(f"owned output is not a directory: {display}")
    os.fchmod(descriptor, PRIVATE_DIRECTORY_MODE)
    names = [entry.name for entry in os.scandir(descriptor)]
    for name in names:
        child_display = display / name
        info = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        if stat.S_ISDIR(info.st_mode):
            child = _open_child_directory(descriptor, name, child_display)
            try:
                _harden_tree_descriptor(child, child_display)
            finally:
                os.close(child)
            continue
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise GuacOutputPathError(
                f"owned output must contain only unlinked regular files: {child_display}"
            )
        child = _open_regular(descriptor, name, child_display, writable=True)
        try:
            os.fchmod(child, PRIVATE_FILE_MODE)
        finally:
            os.close(child)


def harden_owned_output_tree(directory: Path) -> None:
    """Reject links/special files, then migrate only the fixed-family tree."""

    descriptor = _open_directory(directory)
    try:
        _harden_tree_descriptor(descriptor, directory)
    finally:
        os.close(descriptor)


def _write_all(descriptor: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("short private output write")
        view = view[written:]


@dataclass(frozen=True)
class GuacOutput:
    """One private evidence directory under ``<workspace>/evidence/guac``."""

    root: Path
    path: Path

    def child_directory(self, name: str) -> Path:
        return contained_private_path(self.root, self.path, _one_component(name, label="child"))

    def prepare(self) -> "GuacOutput":
        # ``ensure_private_dir`` is descriptor-relative on supported runtime
        # filesystems.  Its no-follow walk closes the validate/create race for
        # every existing or newly-created component before a child sees a path.
        family = guac_evidence_root(self.root)
        ensure_private_dir(family)
        ensure_private_dir(self.path)
        harden_owned_output_tree(self.path)
        return self

    def before_external_tool(self) -> None:
        """Recheck the entire owned tree immediately before every spawn."""

        self.prepare()

    def after_external_tool(self) -> None:
        """Accept only regular, unlinked output written by a transport."""

        harden_owned_output_tree(self.path)

    def _name(self, name: str) -> str:
        return _one_component(name, label="output filename")

    def write_bytes(self, name: str, data: bytes) -> Path:
        """Create a fresh private evidence file without replacement semantics."""

        filename = self._name(name)
        descriptor = _open_directory(self.path)
        created = False
        try:
            try:
                existing = os.stat(filename, dir_fd=descriptor, follow_symlinks=False)
            except FileNotFoundError:
                existing = None
            if existing is not None:
                raise FileExistsError(f"refusing to replace existing evidence: {self.path / filename}")
            flags = (
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_NONBLOCK", 0)
            )
            child = os.open(filename, flags, PRIVATE_FILE_MODE, dir_fd=descriptor)
            created = True
            try:
                info = os.fstat(child)
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise GuacOutputPathError(
                        f"private output must be an unlinked regular file: {self.path / filename}"
                    )
                os.fchmod(child, PRIVATE_FILE_MODE)
                _write_all(child, data)
                os.fsync(child)
            finally:
                os.close(child)
            return self.path / filename
        except BaseException:
            if created:
                try:
                    os.unlink(filename, dir_fd=descriptor)
                except OSError:
                    pass
            raise
        finally:
            os.close(descriptor)

    def write_text(self, name: str, text: str, *, errors: str = "strict") -> Path:
        return self.write_bytes(name, text.encode("utf-8", errors=errors))

    def temporary(self, suffix: str) -> Path:
        if not isinstance(suffix, str) or "/" in suffix or "\\" in suffix:
            raise GuacOutputPathError("temporary suffix is invalid")
        filename = f".guac-{secrets.token_hex(16)}{suffix}"
        self.write_bytes(filename, b"")
        return self.path / filename

    def stream_copy_to_temporary(self, source: Path, *, suffix: str, maximum: int) -> tuple[Path, int]:
        if maximum <= 0:
            raise GuacOutputPathError("copy maximum must be positive")
        temporary = self.temporary(suffix)
        out_descriptor = _open_directory(self.path)
        try:
            writer = _open_regular(out_descriptor, temporary.name, temporary, writable=True)
            flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
            reader = os.open(source, flags)
            try:
                source_info = os.fstat(reader)
                if not stat.S_ISREG(source_info.st_mode):
                    raise GuacOutputPathError(f"source must be a regular file: {source}")
                os.ftruncate(writer, 0)
                written = 0
                while True:
                    block = os.read(reader, min(1024 * 1024, maximum - written + 1))
                    if not block:
                        break
                    written += len(block)
                    if written > maximum:
                        raise GuacOutputPathError("copy exceeds configured byte limit")
                    _write_all(writer, block)
                os.fsync(writer)
                return temporary, written
            finally:
                os.close(reader)
                os.close(writer)
        except BaseException:
            self.remove_temporary(temporary)
            raise
        finally:
            os.close(out_descriptor)

    def publish_temporary(self, temporary: Path, name: str, *, maximum: int) -> int:
        """Publish an owned temporary through atomic no-clobber hard-linking."""

        filename = self._name(name)
        temporary = _absolute(temporary)
        if temporary.parent != self.path or temporary.name.startswith(".") is False:
            raise GuacOutputPathError("temporary output is not owned by this evidence directory")
        descriptor = _open_directory(self.path)
        try:
            source = _open_regular(descriptor, temporary.name, temporary, writable=False)
            try:
                size = os.fstat(source).st_size
                if size <= 0:
                    raise GuacOutputPathError("renderer produced no output")
                if size > maximum:
                    raise GuacOutputPathError("output exceeds configured byte limit")
            finally:
                os.close(source)
            try:
                os.stat(filename, dir_fd=descriptor, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise FileExistsError(f"refusing to replace existing evidence: {self.path / filename}")
            # ``link`` is the POSIX no-replace publish primitive within one
            # descriptor-owned directory.  The temporary's initial link is
            # removed only after the destination exists.
            os.link(
                temporary.name,
                filename,
                src_dir_fd=descriptor,
                dst_dir_fd=descriptor,
                follow_symlinks=False,
            )
            os.unlink(temporary.name, dir_fd=descriptor)
            return int(size)
        finally:
            os.close(descriptor)

    def remove_temporary(self, temporary: Path) -> None:
        temporary = _absolute(temporary)
        if temporary.parent != self.path or not temporary.name.startswith(".guac-"):
            raise GuacOutputPathError("temporary output is not owned by this evidence directory")
        descriptor = _open_directory(self.path)
        try:
            try:
                child = _open_regular(descriptor, temporary.name, temporary, writable=False)
            except FileNotFoundError:
                return
            try:
                pass
            finally:
                os.close(child)
            os.unlink(temporary.name, dir_fd=descriptor)
        finally:
            os.close(descriptor)


def resolve_guac_output(
    root: Path | str,
    value: str | None,
    *,
    default_parts: tuple[str, ...],
) -> GuacOutput:
    """Resolve but do not create one contained Guacamole output directory."""

    workspace = _absolute(root)
    family = guac_evidence_root(workspace)
    if value:
        candidate = _candidate_from_input(workspace, value)
    else:
        if not default_parts:
            raise GuacOutputPathError("default Guacamole output path is empty")
        candidate = contained_private_path(
            workspace,
            family,
            *(_one_component(part, label="default output") for part in default_parts),
        )
    return GuacOutput(workspace, candidate)
