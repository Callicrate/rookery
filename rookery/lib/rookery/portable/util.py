from __future__ import annotations

import contextlib
import datetime as dt
import fnmatch
import hashlib
import ipaddress
import json
import os
import re
import secrets
import shutil
import stat
import tempfile
import unicodedata
from collections.abc import Generator
from pathlib import Path, PureWindowsPath
from typing import Any

try:
    import fcntl
except ImportError:  # pragma: no cover - exercised by native Windows imports
    fcntl = None  # type: ignore[assignment]

UTC = dt.timezone.utc
PRIVATE_MODE_ERROR = (
    "private modes not enforced; use Linux/WSL ext4 or configured "
    "metadata+restrictive ACLs"
)
PORTABLE_COMPONENT_MAX_LENGTH = 128
_PORTABLE_COMPONENT_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}\Z")
_WINDOWS_RESERVED_COMPONENTS = {
    "con",
    "prn",
    "aux",
    "nul",
    "clock$",
    *(f"com{number}" for number in range(1, 10)),
    *(f"lpt{number}" for number in range(1, 10)),
}
_WINDOWS_FORBIDDEN_COMPONENT_CHARS = frozenset('<>:"|?*')


def _private_mode_failure(path: Path, expected: int, actual: int | None = None) -> OSError:
    detail = f" ({path}: expected {expected:04o}"
    if actual is not None:
        detail += f", found {actual:04o}"
    return OSError(PRIVATE_MODE_ERROR + detail + ")")


def _verify_private_mode(info: os.stat_result, expected: int, path: Path) -> None:
    actual = stat.S_IMODE(info.st_mode)
    if actual != expected or actual & 0o077:
        raise _private_mode_failure(path, expected, actual)


def _fchmod_private(descriptor: int, expected: int, path: Path) -> None:
    try:
        os.fchmod(descriptor, expected)
    except OSError as exc:
        raise _private_mode_failure(path, expected) from exc
    _verify_private_mode(os.fstat(descriptor), expected, path)


def _chmod_exact(path: Path, expected: int) -> None:
    try:
        os.chmod(path, expected, follow_symlinks=False)
    except OSError as exc:
        raise _private_mode_failure(path, expected) from exc
    actual = stat.S_IMODE(os.lstat(path).st_mode)
    if actual != expected:
        raise _private_mode_failure(path, expected, actual)


def _chmod_private(path: Path, expected: int) -> None:
    _chmod_exact(path, expected)
    _verify_private_mode(os.lstat(path), expected, path)


def _fsync_private(descriptor: int, path: Path) -> None:
    try:
        os.fsync(descriptor)
    except OSError as exc:
        raise OSError(f"{PRIVATE_MODE_ERROR} (fsync failed for {path})") from exc


def _lexical_absolute(path: Path) -> tuple[Path, tuple[str, ...]]:
    absolute = Path(os.path.abspath(os.fspath(path)))
    parts = absolute.parts
    if not absolute.is_absolute() or not parts:
        raise ValueError(f"private path is not absolute: {path}")
    return Path(parts[0]), parts[1:]


def path_component_id(value: str, *, label: str = "identifier") -> str:
    """Validate a portable, collision-resistant directory identifier.

    The lower-case ASCII policy is deliberate: an ID cannot gain a distinct
    spelling on a case-insensitive or Unicode-normalizing filesystem.
    """

    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be a non-empty text component")
    if value in {".", ".."}:
        raise ValueError(f"{label} must not be a dot or traversal component")
    if len(value) > PORTABLE_COMPONENT_MAX_LENGTH:
        raise ValueError(
            f"{label} exceeds {PORTABLE_COMPONENT_MAX_LENGTH} characters"
        )
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        raise ValueError(f"{label} must not contain control characters")
    if not value.isascii():
        raise ValueError(f"{label} must use portable ASCII only")
    if unicodedata.normalize("NFC", value) != value:
        raise ValueError(f"{label} must be NFC-normalized")
    if value != value.casefold():
        raise ValueError(f"{label} must be casefold-stable")
    if value.endswith((".", " ")):
        raise ValueError(f"{label} must not end in a dot or space")
    if not _PORTABLE_COMPONENT_RE.fullmatch(value):
        raise ValueError(f"{label} is not a portable path component")
    stem = value.split(".", 1)[0]
    if stem.casefold() in _WINDOWS_RESERVED_COMPONENTS:
        raise ValueError(f"{label} is a reserved Windows device name")
    return value


def _path_component(value: str, *, label: str = "path component") -> str:
    """Validate one non-ID path component used by a contained resolver."""

    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be a non-empty text component")
    if value in {".", ".."}:
        raise ValueError(f"{label} must not be a dot or traversal component")
    if len(value) > 255:
        raise ValueError(f"{label} exceeds 255 characters")
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        raise ValueError(f"{label} must not contain control characters")
    if (
        Path(value).is_absolute()
        or PureWindowsPath(value).is_absolute()
        or "/" in value
        or "\\" in value
        or any(character in _WINDOWS_FORBIDDEN_COMPONENT_CHARS for character in value)
    ):
        raise ValueError(f"{label} must be one relative path component")
    if value.endswith((".", " ")):
        raise ValueError(f"{label} must not end in a dot or space")
    return value


def _absolute_path(path: Path | str) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _require_beneath(candidate: Path, base: Path, *, label: str) -> None:
    try:
        candidate.relative_to(base)
    except ValueError as exc:
        raise ValueError(f"{label} escapes its declared base: {candidate}") from exc


def _reject_existing_symlink_components(root: Path, candidate: Path) -> None:
    """Reject existing links in the candidate chain before callers use it."""

    relative = candidate.relative_to(root)
    current = root
    for component in relative.parts:
        current /= component
        try:
            info = os.lstat(current)
        except FileNotFoundError:
            return
        if stat.S_ISLNK(info.st_mode):
            raise ValueError(f"contained path has a symlink component: {current}")


def contained_private_path(
    root: Path | str, base: Path | str, *components: str
) -> Path:
    """Return a safe candidate below ``base`` without following symlinks.

    Both lexical and resolved paths must remain under the declared workspace
    root and base. Existing symlink components are rejected so a later file
    operation cannot redirect an otherwise lexical-safe path.
    """

    root_path = _absolute_path(root)
    base_path = _absolute_path(base)
    _require_beneath(base_path, root_path, label="declared base")
    candidate = base_path.joinpath(
        *(_path_component(component) for component in components)
    )
    _require_beneath(candidate, base_path, label="candidate path")
    try:
        resolved_root = root_path.resolve(strict=False)
        resolved_base = base_path.resolve(strict=False)
        resolved_candidate = candidate.resolve(strict=False)
    except OSError as exc:
        raise ValueError(f"unable to resolve contained path: {candidate}") from exc
    _require_beneath(resolved_base, resolved_root, label="resolved declared base")
    _require_beneath(resolved_candidate, resolved_base, label="resolved candidate path")
    _reject_existing_symlink_components(root_path, candidate)
    return candidate


def _descriptor_walk_supported() -> bool:
    return (
        os.name == "posix"
        and bool(getattr(os, "O_DIRECTORY", 0))
        and bool(getattr(os, "O_NOFOLLOW", 0))
        and os.open in os.supports_dir_fd
        and os.mkdir in os.supports_dir_fd
    )


def _directory_flags() -> int:
    return (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )


def _open_private_directory_at(parent: int, name: str, display: Path) -> int:
    created = False
    try:
        descriptor = os.open(name, _directory_flags(), dir_fd=parent)
    except FileNotFoundError:
        try:
            os.mkdir(name, mode=0o700, dir_fd=parent)
            created = True
        except FileExistsError:
            # A concurrent creator still has to pass the no-follow open below.
            pass
        descriptor = os.open(name, _directory_flags(), dir_fd=parent)
    try:
        if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise OSError(f"private directory component is not a directory: {display}")
        if created:
            _fchmod_private(descriptor, 0o700, display)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _open_directory_chain(path: Path) -> int:
    anchor, parts = _lexical_absolute(path)
    descriptor = os.open(anchor, _directory_flags())
    try:
        current = anchor
        for name in parts:
            current /= name
            child = _open_private_directory_at(descriptor, name, current)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _fallback_private_directories(path: Path) -> None:
    """Best-effort component checks where descriptor-relative APIs are absent."""

    anchor, parts = _lexical_absolute(path)
    current = anchor
    for name in parts:
        current /= name
        try:
            info = os.lstat(current)
        except FileNotFoundError:
            os.mkdir(current, mode=0o700)
            info = os.lstat(current)
            if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
                raise OSError(
                    f"private directory component is not a directory: {current}"
                )
            _chmod_private(current, 0o700)
            continue
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise OSError(f"private directory component is not a directory: {current}")


def ensure_private_dir(path: Path) -> None:
    """Create or migrate a directory without following any symlink component."""

    _, parts = _lexical_absolute(path)
    if not parts:
        raise ValueError("refusing to change a filesystem root to private mode")
    if not _descriptor_walk_supported():
        _fallback_private_directories(path)
        _chmod_private(path, 0o700)
        return
    descriptor = _open_directory_chain(path)
    try:
        _fchmod_private(descriptor, 0o700, path)
    finally:
        os.close(descriptor)


def ensure_private_file(path: Path) -> None:
    """Create or migrate a regular file without following any symlink component."""

    absolute = Path(os.path.abspath(os.fspath(path)))
    _, parts = _lexical_absolute(absolute)
    if not parts:
        raise ValueError("private file path must name a file")
    if not _descriptor_walk_supported():
        _fallback_private_directories(absolute.parent)
        try:
            info = os.lstat(absolute)
        except FileNotFoundError:
            descriptor = os.open(
                absolute,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NONBLOCK", 0),
                0o600,
            )
        else:
            if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
                raise OSError(f"private file path is not a regular file: {path}")
            descriptor = os.open(
                absolute,
                os.O_WRONLY
                | getattr(os, "O_NONBLOCK", 0)
                | getattr(os, "O_NOFOLLOW", 0),
            )
    else:
        parent = _open_directory_chain(absolute.parent)
        try:
            try:
                existing = os.stat(
                    absolute.name,
                    dir_fd=parent,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                pass
            else:
                if not stat.S_ISREG(existing.st_mode):
                    raise OSError(f"private file path is not a regular file: {path}")
            flags = (
                os.O_WRONLY
                | os.O_CREAT
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_NONBLOCK", 0)
            )
            descriptor = os.open(absolute.name, flags, 0o600, dir_fd=parent)
        finally:
            os.close(parent)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise OSError(f"private file path is not a regular file: {path}")
        _fchmod_private(descriptor, 0o600, path)
    finally:
        os.close(descriptor)


def private_storage_preflight(state_dir: Path) -> None:
    """Prove that the state filesystem can enforce private POSIX modes."""

    if os.name != "posix" or not _descriptor_walk_supported():
        raise OSError(PRIVATE_MODE_ERROR)

    ensure_private_dir(state_dir)
    state_descriptor = _open_directory_chain(state_dir)
    directory_name = f".privacy-preflight-{secrets.token_hex(16)}"
    directory_path = state_dir / directory_name
    directory_descriptor: int | None = None
    directory_created = False
    file_name = ".private"
    file_created = False
    try:
        try:
            os.mkdir(directory_name, mode=0o700, dir_fd=state_descriptor)
            directory_created = True
        except OSError as exc:
            raise OSError(
                f"unable to create private storage preflight directory: {directory_path}"
            ) from exc
        directory_descriptor = os.open(
            directory_name, _directory_flags(), dir_fd=state_descriptor
        )
        _verify_private_mode(os.fstat(directory_descriptor), 0o700, directory_path)

        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        file_descriptor = os.open(
            file_name, flags, 0o600, dir_fd=directory_descriptor
        )
        file_created = True
        try:
            file_path = directory_path / file_name
            if not stat.S_ISREG(os.fstat(file_descriptor).st_mode):
                raise OSError(f"private storage preflight file is not regular: {file_path}")
            _fchmod_private(file_descriptor, 0o600, file_path)
            os.write(file_descriptor, b"private storage preflight\n")
            _fsync_private(file_descriptor, file_path)
        finally:
            os.close(file_descriptor)
        _fsync_private(directory_descriptor, directory_path)
    finally:
        if directory_descriptor is not None:
            try:
                if file_created:
                    os.unlink(file_name, dir_fd=directory_descriptor)
                    _fsync_private(directory_descriptor, directory_path)
            finally:
                os.close(directory_descriptor)
        try:
            if directory_created:
                os.rmdir(directory_name, dir_fd=state_descriptor)
                _fsync_private(state_descriptor, state_dir)
        finally:
            os.close(state_descriptor)


def iso_now() -> str:
    return (
        dt.datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    )


def compact_now() -> str:
    return dt.datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")


def parse_iso(value: str | None) -> dt.datetime | None:
    if not value or value == "unknown":
        return None
    text = str(value).strip().replace("Z", "+00:00")
    try:
        out = dt.datetime.fromisoformat(text)
    except ValueError:
        return None
    if out.tzinfo is None:
        out = out.replace(tzinfo=UTC)
    return out.astimezone(UTC)


def parse_duration(value: str | float | None) -> int:
    if value in (None, ""):
        return 0
    if isinstance(value, (int, float)):
        return max(0, int(value))
    text = str(value).strip().lower()
    m = re.fullmatch(r"(\d+)([smhd]?)", text)
    if not m:
        raise ValueError(f"invalid duration: {value}")
    n = int(m.group(1))
    return n * {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)]


def bool_value(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on", "enabled"}


def split_csv(value: str | None) -> list[str]:
    if not value:
        return []
    return [x.strip() for x in str(value).split(",") if x.strip()]


def load_json(path: Path, default: Any = None) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def atomic_write_text(path: Path, text: str, mode: int | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        if mode is not None:
            _chmod_exact(tmp, mode)
        os.replace(tmp, path)
        dir_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        if tmp.exists():
            tmp.unlink(missing_ok=True)


def atomic_write_bytes(path: Path, data: bytes, mode: int | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        if mode is not None:
            _chmod_exact(tmp, mode)
        os.replace(tmp, path)
        dir_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        if tmp.exists():
            tmp.unlink(missing_ok=True)


def atomic_write_json(path: Path, obj: Any, mode: int | None = None) -> None:
    atomic_write_text(
        path,
        json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        mode=mode,
    )


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def event_id(event_type: str, payload: Any, nonce: str = "") -> str:
    base = canonical_json({"type": event_type, "payload": payload, "nonce": nonce})
    return hashlib.sha256(base.encode("utf-8")).hexdigest()


def tree_hash(root: Path, exclude: set[str] | None = None) -> str:
    exclude = exclude or set()
    h = hashlib.sha256()
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        rel = path.relative_to(root).as_posix()
        if rel in exclude or any(
            rel.startswith(prefix.rstrip("/") + "/") for prefix in exclude
        ):
            continue
        h.update(rel.encode("utf-8") + b"\0")
        h.update(sha256_file(path).encode("ascii") + b"\0")
    return h.hexdigest()


def deep_merge(base: Any, overlay: Any) -> Any:
    if isinstance(base, dict) and isinstance(overlay, dict):
        out = {
            k: deep_merge(v, {}) if isinstance(v, dict) else v for k, v in base.items()
        }
        for key, value in overlay.items():
            out[key] = deep_merge(out.get(key), value) if key in out else value
        return out
    return overlay


def safe_relative(root: Path, value: str | Path) -> Path:
    root = root.resolve()
    path = Path(value)
    if path.is_absolute():
        resolved = path.resolve()
    else:
        resolved = (root / path).resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"path escapes workspace: {value}") from exc
    return resolved


def ensure_no_traversal_member(name: str) -> bool:
    path = Path(name)
    return (
        not path.is_absolute()
        and ".." not in path.parts
        and not (path.parts and ":" in path.parts[0])
    )


@contextlib.contextmanager
def file_lock(path: Path, exclusive: bool = True) -> Generator[None, None, None]:
    if fcntl is None:
        raise OSError(f"{PRIVATE_MODE_ERROR} (file locks require POSIX support)")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+") as handle:
        flock = fcntl.flock
        flock(
            handle.fileno(),
            fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH,
        )
        try:
            yield
        finally:
            flock(handle.fileno(), fcntl.LOCK_UN)


def host_matches(host: str, patterns: list[str], cidrs: list[str]) -> bool:
    """Match a normalized host against explicit shell-style patterns or CIDRs."""
    host = host.strip().lower().rstrip(".")
    if not host:
        return False
    for pattern in patterns:
        p = pattern.strip().lower().rstrip(".")
        if p and fnmatch.fnmatchcase(host, p):
            return True
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return False
    for network in cidrs:
        try:
            if addr in ipaddress.ip_network(network, strict=False):
                return True
        except ValueError:
            continue
    return False


def copy_clean(src: Path, dst: Path) -> None:
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(src, dst, symlinks=True)
