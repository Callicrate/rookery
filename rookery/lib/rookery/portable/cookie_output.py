"""Descriptor-safe, marker-owned output directories for ``bin/cookie-filter``.

Cookie evidence is credential-adjacent.  Caller-provided output paths therefore
need read-only admission before configuration or source-cookie access, and new
evidence files must never replace a pre-existing fixed filename.
"""

from __future__ import annotations

import json
import os
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath

from .util import contained_private_path


_FAMILY = ("platform", "cookies")
_MARKER = ".rookery-cookie-output.json"
_SCHEMA = 1
_MAX_MARKER_BYTES = 1024
_FIXED_FILES = frozenset(
    {"cookie-header.txt", "selected-cookies.json", "summary.json"}
)


class CookieOutputError(RuntimeError):
    """A safe, value-free output-admission refusal."""


@dataclass(frozen=True)
class CookieOutputPlan:
    root: Path
    base: Path
    path: Path
    components: tuple[str, ...]
    existing: bool


@dataclass
class CookieOutput:
    root: Path
    base: Path
    path: Path
    components: tuple[str, ...]
    root_fd: int
    family_fd: int
    parent_fd: int
    root_identity: tuple[int, int]
    family_identity: tuple[int, int]
    parent_identity: tuple[int, int]
    closed: bool = False

    @property
    def metadata_path(self) -> str:
        return self.path.relative_to(self.root).as_posix()

    def _recheck_attached(self) -> None:
        if self.closed:
            raise CookieOutputError("output publication handle is closed")
        if _identity(os.fstat(self.root_fd)) != self.root_identity:
            raise CookieOutputError("output workspace changed after admission")
        if _identity(os.fstat(self.family_fd)) != self.family_identity:
            raise CookieOutputError("output family changed after admission")
        if _identity(os.fstat(self.parent_fd)) != self.parent_identity:
            raise CookieOutputError("output directory changed after admission")
        platform_fd: int | None = None
        attached_family_fd: int | None = None
        current_fd: int | None = None
        try:
            platform_fd = _open_verified_child(
                self.root_fd, "platform", None
            )
            attached_family_fd = _open_verified_child(
                platform_fd, "cookies", self.family_identity
            )
            current_fd = attached_family_fd
            for name in self.components:
                child = _open_verified_child(current_fd, name, None)
                if current_fd != attached_family_fd:
                    os.close(current_fd)
                current_fd = child
            if _identity(os.fstat(current_fd)) != self.parent_identity:
                raise CookieOutputError("output directory detached before publication")
        finally:
            if current_fd is not None and current_fd != attached_family_fd:
                os.close(current_fd)
            if attached_family_fd is not None:
                os.close(attached_family_fd)
            if platform_fd is not None:
                os.close(platform_fd)

    def guard(self) -> None:
        self._recheck_attached()
        _verify_marker(self.parent_fd)
        _inspect_tree(
            self.parent_fd, migrate=True, reject_fixed_collisions=False
        )

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        for descriptor in (self.parent_fd, self.family_fd, self.root_fd):
            os.close(descriptor)


def _dir_flags() -> int:
    return (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )


def _identity(info: os.stat_result) -> tuple[int, int]:
    return info.st_dev, info.st_ino


def _open_verified_child(
    parent: int, name: str, expected_identity: tuple[int, int] | None
) -> int:
    """Open one directory relative to a retained descriptor without links."""

    try:
        before = os.stat(name, dir_fd=parent, follow_symlinks=False)
        child = os.open(name, _dir_flags(), dir_fd=parent)
    except OSError as exc:
        raise CookieOutputError("output directory detached before publication") from exc
    try:
        opened = os.fstat(child)
        if (
            not stat.S_ISDIR(before.st_mode)
            or not _is_owner(before)
            or _identity(opened) != _identity(before)
            or (expected_identity is not None and _identity(opened) != expected_identity)
        ):
            raise CookieOutputError("output directory detached before publication")
        return child
    except BaseException:
        os.close(child)
        raise


def _read_flags() -> int:
    return (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )


def _write_flags() -> int:
    return (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )


def _is_owner(info: os.stat_result) -> bool:
    return not hasattr(os, "geteuid") or info.st_uid == os.geteuid()


def _is_private_dir(info: os.stat_result) -> bool:
    return stat.S_IMODE(info.st_mode) == 0o700


def _safe_components(root: Path, base: Path, raw: str) -> tuple[str, ...]:
    if not isinstance(raw, str) or not raw:
        raise CookieOutputError("output directory is invalid")
    if "\\" in raw or any(ord(char) < 0x20 or ord(char) == 0x7F for char in raw):
        raise CookieOutputError("output directory is invalid")
    if any(part in {".", ".."} for part in raw.split("/")) or any(
        part in {".", ".."} for part in PurePosixPath(raw).parts
    ):
        raise CookieOutputError("output directory is invalid")
    candidate = Path(raw)
    if candidate.is_absolute() or PureWindowsPath(raw).is_absolute():
        absolute = Path(os.path.abspath(os.fspath(candidate)))
    else:
        absolute = Path(os.path.abspath(os.fspath(root / candidate)))
    try:
        relative = absolute.relative_to(base)
    except ValueError as exc:
        raise CookieOutputError("output directory is outside the cookie family") from exc
    if not relative.parts:
        raise CookieOutputError("output directory is invalid")
    return tuple(relative.parts)


def _open_existing_directory(root: Path, path: Path) -> int:
    try:
        relative = path.relative_to(root)
        descriptor = os.open(root, _dir_flags())
    except (OSError, ValueError) as exc:
        raise CookieOutputError("output workspace cannot be inspected safely") from exc
    try:
        for name in relative.parts:
            try:
                before = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            except OSError as exc:
                raise CookieOutputError("output directory is unavailable") from exc
            if not stat.S_ISDIR(before.st_mode) or not _is_owner(before):
                raise CookieOutputError("output path is unsafe")
            try:
                child = os.open(name, _dir_flags(), dir_fd=descriptor)
            except OSError as exc:
                raise CookieOutputError("output path is unsafe") from exc
            opened = os.fstat(child)
            if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                os.close(child)
                raise CookieOutputError("output path changed during validation")
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _retain_output_descriptors(
    root: Path, base: Path, path: Path, components: tuple[str, ...]
) -> CookieOutput:
    """Bind publication to root/family/output descriptors while still attached."""

    root_fd: int | None = None
    platform_fd: int | None = None
    family_fd: int | None = None
    parent_fd: int | None = None
    try:
        root_fd = os.open(root, _dir_flags())
        root_identity = _identity(os.fstat(root_fd))
        platform_fd = _open_verified_child(root_fd, "platform", None)
        family_fd = _open_verified_child(platform_fd, "cookies", None)
        family_identity = _identity(os.fstat(family_fd))
        current_fd = family_fd
        for name in components:
            child = _open_verified_child(current_fd, name, None)
            if current_fd != family_fd:
                os.close(current_fd)
            current_fd = child
        parent_fd = current_fd
        parent_identity = _identity(os.fstat(parent_fd))
        if parent_identity == family_identity:
            raise CookieOutputError("output directory is invalid")
        os.close(platform_fd)
        platform_fd = None
        return CookieOutput(
            root=root,
            base=base,
            path=path,
            components=components,
            root_fd=root_fd,
            family_fd=family_fd,
            parent_fd=parent_fd,
            root_identity=root_identity,
            family_identity=family_identity,
            parent_identity=parent_identity,
        )
    except BaseException:
        for descriptor in (parent_fd, family_fd, platform_fd, root_fd):
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
        raise


def _read_regular(directory: int, name: str) -> bytes:
    try:
        before = os.stat(name, dir_fd=directory, follow_symlinks=False)
    except OSError as exc:
        raise CookieOutputError("output marker is unavailable") from exc
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > _MAX_MARKER_BYTES:
        raise CookieOutputError("output marker is invalid")
    try:
        descriptor = os.open(name, _read_flags(), dir_fd=directory)
    except OSError as exc:
        raise CookieOutputError("output marker is invalid") from exc
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or opened.st_size > _MAX_MARKER_BYTES
            or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
        ):
            raise CookieOutputError("output marker changed during validation")
        data = os.read(descriptor, _MAX_MARKER_BYTES + 1)
        if len(data) > _MAX_MARKER_BYTES:
            raise CookieOutputError("output marker is invalid")
        return data
    finally:
        os.close(descriptor)


def _verify_marker(directory: int) -> None:
    try:
        marker = json.loads(_read_regular(directory, _MARKER))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CookieOutputError("output marker is invalid") from exc
    if marker != {"family": "platform/cookies", "schema": _SCHEMA}:
        raise CookieOutputError("output directory is not owned by cookie-filter")


def _inspect_tree(
    directory: int, *, migrate: bool, reject_fixed_collisions: bool
) -> None:
    info = os.fstat(directory)
    if not stat.S_ISDIR(info.st_mode) or not _is_owner(info):
        raise CookieOutputError("output directory changed during validation")
    if migrate:
        os.fchmod(directory, 0o700)
        if not _is_private_dir(os.fstat(directory)):
            raise CookieOutputError("private output mode cannot be enforced")
    try:
        names = os.listdir(directory)
    except OSError as exc:
        raise CookieOutputError("output directory cannot be listed safely") from exc
    for name in names:
        try:
            before = os.stat(name, dir_fd=directory, follow_symlinks=False)
        except OSError as exc:
            raise CookieOutputError("output entry changed during validation") from exc
        if name in _FIXED_FILES and reject_fixed_collisions:
            raise CookieOutputError("output fixed-file collision")
        if stat.S_ISDIR(before.st_mode):
            try:
                child = os.open(name, _dir_flags(), dir_fd=directory)
            except OSError as exc:
                raise CookieOutputError("output tree contains an unsafe entry") from exc
            try:
                opened = os.fstat(child)
                if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                    raise CookieOutputError("output entry changed during validation")
                _inspect_tree(
                    child,
                    migrate=migrate,
                    reject_fixed_collisions=reject_fixed_collisions,
                )
            finally:
                os.close(child)
            continue
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise CookieOutputError("output tree contains an unsafe entry")
        try:
            descriptor = os.open(name, _read_flags(), dir_fd=directory)
        except OSError as exc:
            raise CookieOutputError("output tree contains an unsafe entry") from exc
        try:
            opened = os.fstat(descriptor)
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_nlink != 1
                or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
            ):
                raise CookieOutputError("output entry changed during validation")
            if migrate:
                os.fchmod(descriptor, 0o600)
        finally:
            os.close(descriptor)


def preflight_cookie_output(root: Path, raw_outdir: str) -> CookieOutputPlan:
    """Read-only output validation, performed before dotenv or cookie reads."""

    root = Path(os.path.abspath(os.fspath(root)))
    base = root.joinpath(*_FAMILY)
    try:
        components = (
            _safe_components(root, base, raw_outdir)
            if raw_outdir
            else (f"cookie-filter-{secrets.token_hex(16)}",)
        )
        path = contained_private_path(root, base, *components)
    except (OSError, ValueError) as exc:
        raise CookieOutputError("output directory is invalid") from exc
    current = root
    for name in path.relative_to(root).parts:
        current /= name
        if not os.path.lexists(current):
            break
        try:
            info = os.lstat(current)
        except OSError as exc:
            raise CookieOutputError("output path cannot be inspected safely") from exc
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or not _is_owner(info):
            raise CookieOutputError("output path is unsafe")
    if not os.path.lexists(path):
        return CookieOutputPlan(root, base, path, components, False)
    descriptor = _open_existing_directory(root, path)
    try:
        _verify_marker(descriptor)
        _inspect_tree(descriptor, migrate=False, reject_fixed_collisions=True)
    finally:
        os.close(descriptor)
    return CookieOutputPlan(root, base, path, components, True)


def _open_or_create_family(root: Path) -> Path:
    try:
        descriptor = os.open(root, _dir_flags())
    except OSError as exc:
        raise CookieOutputError("output workspace cannot be opened safely") from exc
    current = root
    try:
        for name in _FAMILY:
            current /= name
            try:
                child = os.open(name, _dir_flags(), dir_fd=descriptor)
                created = False
            except FileNotFoundError:
                try:
                    os.mkdir(name, 0o700, dir_fd=descriptor)
                except FileExistsError:
                    pass
                child = os.open(name, _dir_flags(), dir_fd=descriptor)
                created = True
            except OSError as exc:
                raise CookieOutputError("cookie output family is unsafe") from exc
            info = os.fstat(child)
            if not stat.S_ISDIR(info.st_mode) or not _is_owner(info):
                os.close(child)
                raise CookieOutputError("cookie output family is unsafe")
            if created or not _is_private_dir(info):
                os.fchmod(child, 0o700)
                if not _is_private_dir(os.fstat(child)):
                    os.close(child)
                    raise CookieOutputError("private output mode cannot be enforced")
            os.close(descriptor)
            descriptor = child
        return current
    finally:
        os.close(descriptor)


def prepare_cookie_output(plan: CookieOutputPlan) -> CookieOutput:
    """Create a fresh marker directory or migrate the admitted owned tree."""

    base = _open_or_create_family(plan.root)
    try:
        path = contained_private_path(plan.root, base, *plan.components)
    except (OSError, ValueError) as exc:
        raise CookieOutputError("output directory changed after admission") from exc
    if path != plan.path:
        raise CookieOutputError("output directory changed after admission")
    if plan.existing:
        descriptor = _open_existing_directory(plan.root, path)
        try:
            _verify_marker(descriptor)
            _inspect_tree(descriptor, migrate=True, reject_fixed_collisions=True)
        finally:
            os.close(descriptor)
    else:
        parent = base
        descriptor = os.open(base, _dir_flags())
        try:
            for index, name in enumerate(plan.components):
                final = index == len(plan.components) - 1
                if final:
                    try:
                        os.mkdir(name, 0o700, dir_fd=descriptor)
                    except FileExistsError as exc:
                        raise CookieOutputError(
                            "fresh output directory was claimed concurrently"
                        ) from exc
                    child = os.open(name, _dir_flags(), dir_fd=descriptor)
                    if not _is_private_dir(os.fstat(child)):
                        os.close(child)
                        raise CookieOutputError("private output mode cannot be enforced")
                    _write_marker(child)
                else:
                    try:
                        child = os.open(name, _dir_flags(), dir_fd=descriptor)
                    except FileNotFoundError:
                        os.mkdir(name, 0o700, dir_fd=descriptor)
                        child = os.open(name, _dir_flags(), dir_fd=descriptor)
                    info = os.fstat(child)
                    if not stat.S_ISDIR(info.st_mode) or not _is_owner(info):
                        os.close(child)
                        raise CookieOutputError("output path is unsafe")
                    if not _is_private_dir(info):
                        os.fchmod(child, 0o700)
                os.close(descriptor)
                descriptor = child
                parent /= name
        finally:
            os.close(descriptor)
    output = _retain_output_descriptors(plan.root, base, path, plan.components)
    output.guard()
    return output


def _write_marker(directory: int) -> None:
    payload = b'{"family":"platform/cookies","schema":1}\n'
    try:
        descriptor = os.open(_MARKER, _write_flags(), 0o600, dir_fd=directory)
    except OSError as exc:
        raise CookieOutputError("output marker cannot be created") from exc
    try:
        os.fchmod(descriptor, 0o600)
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("marker write did not make progress")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.fsync(directory)


def write_new_cookie_output(output: CookieOutput, name: str, data: bytes) -> Path:
    """Publish one completed bounded file without any pathname re-admission.

    The completed temporary inode is held through the retained output-directory
    descriptor.  Immediately before the no-clobber link, root -> family ->
    output identities are rechecked through descriptors; a detached output is
    refused rather than receiving a fixed evidence filename.
    """

    if name not in _FIXED_FILES:
        raise CookieOutputError("output file name is invalid")
    output.guard()
    temporary_name = f".{name}.{secrets.token_hex(16)}.tmp"
    temporary: int | None = None
    descriptor = os.dup(output.parent_fd)
    temporary_identity: tuple[int, int] | None = None
    try:
        try:
            os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise CookieOutputError("output fixed-file collision")
        temporary = os.open(temporary_name, _write_flags(), 0o600, dir_fd=descriptor)
        os.fchmod(temporary, 0o600)
        view = memoryview(data)
        while view:
            written = os.write(temporary, view)
            if written <= 0:
                raise OSError("output write did not make progress")
            view = view[written:]
        os.fsync(temporary)
        temporary_identity = _identity(os.fstat(temporary))
        os.close(temporary)
        temporary = None
        # The expensive/content-bearing phase is complete.  Do not publish
        # into a directory which was renamed or replaced while it ran.
        output._recheck_attached()
        if _identity(os.fstat(descriptor)) != output.parent_identity:
            raise CookieOutputError("output directory detached before publication")
        try:
            os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise CookieOutputError("output fixed-file collision")
        try:
            os.link(
                temporary_name,
                name,
                src_dir_fd=descriptor,
                dst_dir_fd=descriptor,
                follow_symlinks=False,
            )
        except FileExistsError as exc:
            raise CookieOutputError("output fixed-file collision") from exc
        published = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        if (
            temporary_identity is None
            or _identity(published) != temporary_identity
            or not stat.S_ISREG(published.st_mode)
        ):
            raise CookieOutputError("output publication changed during validation")
        os.unlink(temporary_name, dir_fd=descriptor)
        published = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        if (
            temporary_identity is None
            or _identity(published) != temporary_identity
            or published.st_nlink != 1
        ):
            raise CookieOutputError("output publication changed during validation")
        os.fsync(descriptor)
    except OSError as exc:
        raise CookieOutputError("output file cannot be written safely") from exc
    finally:
        if temporary is not None:
            os.close(temporary)
        try:
            os.unlink(temporary_name, dir_fd=descriptor)
        except FileNotFoundError:
            pass
        finally:
            os.close(descriptor)
    return output.path / name


def read_cookie_output(output: CookieOutput, name: str) -> bytes:
    """Read one fixed output only after revalidating its marker-owned tree."""

    if name not in _FIXED_FILES:
        raise CookieOutputError("output file name is invalid")
    output.guard()
    descriptor = os.dup(output.parent_fd)
    try:
        try:
            file_descriptor = os.open(name, _read_flags(), dir_fd=descriptor)
        except OSError as exc:
            raise CookieOutputError("output file is unavailable") from exc
        try:
            info = os.fstat(file_descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise CookieOutputError("output file is unsafe")
            return os.read(file_descriptor, info.st_size + 1)
        finally:
            os.close(file_descriptor)
    finally:
        os.close(descriptor)
