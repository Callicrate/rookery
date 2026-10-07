"""Private, contained output directories for the Immersive adapter.

The adapter accepts an operator-selected output directory, but evidence must
never be written outside its fixed workspace family.  This module keeps that
policy out of individual helpers and uses descriptor-relative operations for
the ownership marker and new output directory creation.
"""

from __future__ import annotations

import json
import os
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath

from rookery.portable.util import contained_private_path


_MARKER_NAME = ".rookery-immersive-output.json"
_MARKER_SCHEMA = 1
_MAX_MARKER_BYTES = 1024


class ImmersiveOutputError(RuntimeError):
    """A path-policy refusal that is safe to display to an operator."""


@dataclass(frozen=True)
class ImmersiveOutputPlan:
    """A read-only admission result consumed after configuration validation."""

    root: Path
    base: Path
    path: Path
    family: str
    components: tuple[str, ...]
    existing: bool


def _directory_flags() -> int:
    return (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )


def _file_read_flags() -> int:
    return (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )


def _file_write_flags() -> int:
    return (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )


def _safe_raw_path(raw: str) -> str:
    if not isinstance(raw, str) or not raw:
        raise ImmersiveOutputError("output directory must be a non-empty path")
    if "\\" in raw or any(
        ord(character) < 0x20 or ord(character) == 0x7F for character in raw
    ):
        raise ImmersiveOutputError("output directory contains an unsafe path character")
    return raw


def _relative_components(root: Path, base: Path, raw: str) -> tuple[str, ...]:
    """Parse an explicit path without accepting dot or traversal spellings."""

    text = _safe_raw_path(raw)
    posix = PurePosixPath(text)
    if any(part in {".", ".."} for part in text.split("/")) or any(
        part in {".", ".."} for part in posix.parts
    ):
        raise ImmersiveOutputError("output directory must not contain dot or traversal components")
    candidate = Path(text)
    if candidate.is_absolute() or PureWindowsPath(text).is_absolute():
        absolute = Path(os.path.abspath(os.fspath(candidate)))
    else:
        absolute = Path(os.path.abspath(os.fspath(root / candidate)))
    try:
        relative = absolute.relative_to(base)
    except ValueError as exc:
        raise ImmersiveOutputError("output directory is outside its fixed workspace family") from exc
    if not relative.parts:
        raise ImmersiveOutputError("output directory must name a child of its workspace family")
    return tuple(relative.parts)


def _private_directory_mode(info: os.stat_result) -> bool:
    return stat.S_IMODE(info.st_mode) == 0o700


def _owned_by_current_user(info: os.stat_result) -> bool:
    return not hasattr(os, "geteuid") or info.st_uid == os.geteuid()


def _open_child_directory(
    parent: int,
    name: str,
    display: Path,
    *,
    create: bool,
    allow_nonprivate_existing: bool = False,
    migrate_existing: bool = False,
) -> tuple[int, bool]:
    created = False
    try:
        descriptor = os.open(name, _directory_flags(), dir_fd=parent)
    except FileNotFoundError:
        if not create:
            raise ImmersiveOutputError("owned output directory is unavailable") from None
        try:
            os.mkdir(name, mode=0o700, dir_fd=parent)
            created = True
        except FileExistsError:
            # A concurrent creator must still pass the no-follow open below.
            pass
        try:
            descriptor = os.open(name, _directory_flags(), dir_fd=parent)
        except OSError as exc:
            raise ImmersiveOutputError("output directory cannot be opened safely") from exc
    except OSError as exc:
        raise ImmersiveOutputError("output directory cannot be opened safely") from exc
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISDIR(info.st_mode):
            raise ImmersiveOutputError("output path contains a non-directory component")
        if not _owned_by_current_user(info):
            raise ImmersiveOutputError("output directory is not owned by the current user")
        if created:
            os.fchmod(descriptor, 0o700)
            if not _private_directory_mode(os.fstat(descriptor)):
                raise ImmersiveOutputError("private output directory mode cannot be enforced")
        elif not _private_directory_mode(info):
            if not allow_nonprivate_existing:
                raise ImmersiveOutputError("preexisting output directory is not private")
            if migrate_existing:
                os.fchmod(descriptor, 0o700)
                if not _private_directory_mode(os.fstat(descriptor)):
                    raise ImmersiveOutputError(
                        "private output directory mode cannot be enforced"
                    )
        return descriptor, created
    except BaseException:
        os.close(descriptor)
        raise


def _open_output_directory(
    base: Path,
    components: tuple[str, ...],
    *,
    create: bool,
    require_fresh_final: bool = False,
    migrate_existing: bool = False,
) -> tuple[int, bool]:
    try:
        descriptor = os.open(base, _directory_flags())
    except OSError as exc:
        raise ImmersiveOutputError("output workspace family cannot be opened safely") from exc
    created_final = False
    current = base
    try:
        for index, name in enumerate(components):
            current /= name
            final = index == len(components) - 1
            if final and require_fresh_final:
                try:
                    os.mkdir(name, mode=0o700, dir_fd=descriptor)
                except FileExistsError as exc:
                    raise ImmersiveOutputError(
                        "fresh output directory was claimed concurrently"
                    ) from exc
                child, _created = _open_child_directory(
                    descriptor, name, current, create=False
                )
                created = True
            else:
                child, created = _open_child_directory(
                    descriptor,
                    name,
                    current,
                    create=create,
                    allow_nonprivate_existing=True,
                    migrate_existing=migrate_existing,
                )
            os.close(descriptor)
            descriptor = child
            if index == len(components) - 1:
                created_final = created
        return descriptor, created_final
    except BaseException:
        os.close(descriptor)
        raise


def _ensure_private_family(root: Path, components: tuple[str, ...]) -> Path:
    """Create a missing family without changing any preexisting component."""

    try:
        descriptor = os.open(root, _directory_flags())
    except OSError as exc:
        raise ImmersiveOutputError("output workspace root cannot be opened safely") from exc
    current = root
    try:
        for name in components:
            current /= name
            child, _created = _open_child_directory(
                descriptor,
                name,
                current,
                create=True,
                allow_nonprivate_existing=True,
                migrate_existing=True,
            )
            os.close(descriptor)
            descriptor = child
        return current
    finally:
        os.close(descriptor)


def _read_regular_at(directory: int, name: str, *, maximum: int) -> bytes:
    try:
        before = os.stat(name, dir_fd=directory, follow_symlinks=False)
    except OSError as exc:
        raise ImmersiveOutputError("owned output marker is unavailable") from exc
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > maximum:
        raise ImmersiveOutputError("owned output marker is invalid")
    try:
        descriptor = os.open(name, _file_read_flags(), dir_fd=directory)
    except OSError as exc:
        raise ImmersiveOutputError("owned output marker cannot be opened safely") from exc
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or opened.st_size > maximum
            or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
        ):
            raise ImmersiveOutputError("owned output marker changed while being opened")
        data = os.read(descriptor, maximum + 1)
        if len(data) > maximum:
            raise ImmersiveOutputError("owned output marker is oversized")
        return data
    finally:
        os.close(descriptor)


def _write_marker(directory: int, family: str) -> None:
    payload = json.dumps(
        {"family": family, "schema": _MARKER_SCHEMA},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8") + b"\n"
    try:
        descriptor = os.open(_MARKER_NAME, _file_write_flags(), 0o600, dir_fd=directory)
    except FileExistsError as exc:
        raise ImmersiveOutputError("new output directory was claimed concurrently") from exc
    except OSError as exc:
        raise ImmersiveOutputError("output ownership marker cannot be created") from exc
    try:
        os.fchmod(descriptor, 0o600)
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("ownership marker write did not make progress")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.fsync(directory)


def write_private_output_file(path: Path, data: bytes) -> None:
    """Atomically write one regular private file without following a link.

    The first write uses an ``O_EXCL`` descriptor-relative link, so an
    unexpected pre-existing destination cannot be clobbered.  A later write
    may replace only a single-link regular file already owned by the private
    output directory (needed for evolving request/summary evidence).
    """

    path = Path(os.path.abspath(os.fspath(path)))
    if not path.name or path.name in {".", ".."}:
        raise ImmersiveOutputError("private output file has an unsafe name")
    try:
        directory = os.open(path.parent, _directory_flags())
    except OSError as exc:
        raise ImmersiveOutputError("private output parent cannot be opened safely") from exc
    parent_info = os.fstat(directory)
    if not _owned_by_current_user(parent_info) or not _private_directory_mode(
        parent_info
    ):
        os.close(directory)
        raise ImmersiveOutputError("private output parent is not owned and private")
    temporary_name = f".{path.name}.{secrets.token_hex(16)}.tmp"
    temporary: int | None = None
    try:
        try:
            existing = os.stat(path.name, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            existing = None
        except OSError as exc:
            raise ImmersiveOutputError("private output destination cannot be checked") from exc
        if existing is not None and (
            not stat.S_ISREG(existing.st_mode) or existing.st_nlink != 1
        ):
            raise ImmersiveOutputError("private output destination is not an owned regular file")
        temporary = os.open(temporary_name, _file_write_flags(), 0o600, dir_fd=directory)
        os.fchmod(temporary, 0o600)
        view = memoryview(data)
        while view:
            written = os.write(temporary, view)
            if written <= 0:
                raise OSError("private output write did not make progress")
            view = view[written:]
        os.fsync(temporary)
        os.close(temporary)
        temporary = None
        if existing is None:
            try:
                os.link(
                    temporary_name,
                    path.name,
                    src_dir_fd=directory,
                    dst_dir_fd=directory,
                    follow_symlinks=False,
                )
            except FileExistsError as exc:
                raise ImmersiveOutputError("new private output destination already exists") from exc
            os.unlink(temporary_name, dir_fd=directory)
        else:
            # ``os.replace`` changes the entry itself, not a symlink target;
            # the checked old entry is a single-link regular file.
            os.replace(
                temporary_name,
                path.name,
                src_dir_fd=directory,
                dst_dir_fd=directory,
            )
        os.fsync(directory)
    except OSError as exc:
        raise ImmersiveOutputError("private output file cannot be written safely") from exc
    finally:
        if temporary is not None:
            os.close(temporary)
        try:
            os.unlink(temporary_name, dir_fd=directory)
        except FileNotFoundError:
            pass
        finally:
            os.close(directory)


def _verify_marker(directory: int, family: str) -> None:
    try:
        marker = json.loads(_read_regular_at(directory, _MARKER_NAME, maximum=_MAX_MARKER_BYTES))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ImmersiveOutputError("owned output marker is invalid") from exc
    if marker != {"family": family, "schema": _MARKER_SCHEMA}:
        raise ImmersiveOutputError("output directory is not owned by this Immersive helper")


def _inspect_owned_tree(directory: int, *, migrate: bool) -> None:
    """Reject unsafe owned-tree entries, optionally migrating private modes."""

    directory_info = os.fstat(directory)
    if not stat.S_ISDIR(directory_info.st_mode) or not _owned_by_current_user(
        directory_info
    ):
        raise ImmersiveOutputError("owned output directory changed during validation")
    if migrate:
        os.fchmod(directory, 0o700)
        if not _private_directory_mode(os.fstat(directory)):
            raise ImmersiveOutputError("owned output directory mode cannot be enforced")
    try:
        names = os.listdir(directory)
    except OSError as exc:
        raise ImmersiveOutputError("owned output directory cannot be listed safely") from exc
    for name in names:
        try:
            info = os.stat(name, dir_fd=directory, follow_symlinks=False)
        except OSError as exc:
            raise ImmersiveOutputError("owned output entry changed during validation") from exc
        if stat.S_ISDIR(info.st_mode):
            try:
                child = os.open(name, _directory_flags(), dir_fd=directory)
            except OSError as exc:
                raise ImmersiveOutputError("owned output directory cannot be opened safely") from exc
            try:
                opened = os.fstat(child)
                if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                    raise ImmersiveOutputError(
                        "owned output directory changed during validation"
                    )
                _inspect_owned_tree(child, migrate=migrate)
            finally:
                os.close(child)
            continue
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ImmersiveOutputError("owned output contains a link or special file")
        try:
            descriptor = os.open(name, _file_read_flags(), dir_fd=directory)
        except OSError as exc:
            raise ImmersiveOutputError("owned output file cannot be opened safely") from exc
        try:
            opened = os.fstat(descriptor)
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_nlink != 1
                or (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino)
            ):
                raise ImmersiveOutputError("owned output file changed during validation")
            if migrate:
                os.fchmod(descriptor, 0o600)
        finally:
            os.close(descriptor)


def _harden_owned_tree(directory: int) -> None:
    """Migrate an already-admitted output tree to restrictive private modes."""

    _inspect_owned_tree(directory, migrate=True)


def _preflight_existing_output(root: Path, path: Path, family: str) -> bool:
    """Read-only descriptor walk returning whether the final output exists."""

    try:
        relative = path.relative_to(root)
        descriptor = os.open(root, _directory_flags())
    except (OSError, ValueError) as exc:
        raise ImmersiveOutputError("output workspace root cannot be inspected safely") from exc
    try:
        for index, name in enumerate(relative.parts):
            final = index == len(relative.parts) - 1
            try:
                before = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            except FileNotFoundError:
                return False
            except OSError as exc:
                raise ImmersiveOutputError(
                    "output directory cannot be inspected safely"
                ) from exc
            if not stat.S_ISDIR(before.st_mode) or not _owned_by_current_user(before):
                raise ImmersiveOutputError("output path has a link or special component")
            try:
                child = os.open(name, _directory_flags(), dir_fd=descriptor)
            except OSError as exc:
                raise ImmersiveOutputError(
                    "output directory cannot be opened safely"
                ) from exc
            try:
                opened = os.fstat(child)
                if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                    raise ImmersiveOutputError(
                        "output directory changed during preflight"
                    )
                if final:
                    _verify_marker(child, family)
                    _inspect_owned_tree(child, migrate=False)
                    os.close(child)
                    return True
            except BaseException:
                os.close(child)
                raise
            os.close(descriptor)
            descriptor = child
        raise ImmersiveOutputError("output directory preflight is incomplete")
    finally:
        os.close(descriptor)


def preflight_immersive_output(
    root: Path,
    *,
    family_parts: tuple[str, ...],
    raw_outdir: str,
    default_label: str,
) -> ImmersiveOutputPlan:
    """Read-only admission before dotenv, cookies, scope, or process effects.

    A non-existing target is reserved only conceptually; the later creation
    phase requires it still be fresh. An existing target must already carry the
    exact family marker and contain no links, hard links, or special files.
    """

    if not family_parts or any(
        not part or "/" in part or "\\" in part for part in family_parts
    ):
        raise ValueError("Immersive output family must have safe path components")
    root = Path(os.path.abspath(os.fspath(root)))
    base = root.joinpath(*family_parts)
    family = "/".join(family_parts)
    try:
        if raw_outdir:
            components = _relative_components(root, base, raw_outdir)
        else:
            components = (default_label, f"{secrets.token_hex(16)}")
        path = contained_private_path(root, base, *components)
    except (OSError, ValueError) as exc:
        raise ImmersiveOutputError(
            "output directory is not a safe contained private path"
        ) from exc
    existing = _preflight_existing_output(root, path, family)
    return ImmersiveOutputPlan(
        root=root,
        base=base,
        path=path,
        family=family,
        components=components,
        existing=existing,
    )


@dataclass(frozen=True)
class ImmersiveOutput:
    """A prepared, fixed-family output directory with an ownership marker."""

    root: Path
    base: Path
    path: Path
    family: str

    @property
    def metadata_path(self) -> str:
        return self.path.relative_to(self.root).as_posix()

    def guard(self) -> None:
        """Recheck ownership immediately before a sensitive operation."""

        try:
            candidate = contained_private_path(
                self.root, self.base, *self.path.relative_to(self.base).parts
            )
        except (OSError, ValueError) as exc:
            raise ImmersiveOutputError(
                "output directory changed or escapes its workspace family"
            ) from exc
        if candidate != self.path:
            raise ImmersiveOutputError("output directory changed unexpectedly")
        descriptor, _created = _open_output_directory(
            self.base,
            self.path.relative_to(self.base).parts,
            create=False,
            migrate_existing=False,
        )
        try:
            _verify_marker(descriptor, self.family)
            _harden_owned_tree(descriptor)
        finally:
            os.close(descriptor)


def prepare_immersive_output(
    root: Path,
    *,
    family_parts: tuple[str, ...],
    raw_outdir: str,
    default_label: str,
    plan: ImmersiveOutputPlan | None = None,
) -> ImmersiveOutput:
    """Create or validate a Rookery-owned output below one fixed family.

    Explicit output paths may be absolute only when they are already under the
    selected workspace family.  New outputs receive a no-clobber ownership
    marker.  Existing directories are accepted solely when that marker proves
    that the same family previously created them.
    """

    if plan is None:
        plan = preflight_immersive_output(
            root,
            family_parts=family_parts,
            raw_outdir=raw_outdir,
            default_label=default_label,
        )
    root = Path(os.path.abspath(os.fspath(root)))
    expected_base = root.joinpath(*family_parts)
    if (
        plan.root != root
        or plan.base != expected_base
        or plan.family != "/".join(family_parts)
    ):
        raise ImmersiveOutputError("output preflight does not match this helper")
    try:
        base = _ensure_private_family(root, family_parts)
        path = contained_private_path(root, base, *plan.components)
    except (OSError, ValueError) as exc:
        raise ImmersiveOutputError(
            "output directory is not a safe contained private path"
        ) from exc
    if path != plan.path:
        raise ImmersiveOutputError("output directory changed after preflight")
    descriptor, created = _open_output_directory(
        base,
        plan.components,
        create=not plan.existing,
        require_fresh_final=not plan.existing,
        migrate_existing=not plan.existing,
    )
    try:
        if not plan.existing:
            if not created:
                raise ImmersiveOutputError("fresh output directory was not created")
            _write_marker(descriptor, plan.family)
        else:
            if created:
                raise ImmersiveOutputError("owned output directory was recreated")
            _verify_marker(descriptor, plan.family)
            _harden_owned_tree(descriptor)
    finally:
        os.close(descriptor)
    output = ImmersiveOutput(root=root, base=base, path=path, family=plan.family)
    output.guard()
    return output
