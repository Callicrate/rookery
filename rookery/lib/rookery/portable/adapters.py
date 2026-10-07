from __future__ import annotations

import ctypes
import errno
import hashlib
import importlib.util
import json
import os
import re
import secrets
import signal
import stat
import subprocess
import sys
import threading
import time
import urllib.request
from collections.abc import Mapping
from contextlib import nullcontext
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable, ContextManager

from rookery.verdict_parser import parse_verdict

from .environment import (
    ChildEnvironment,
    EnvClass,
    EnvironmentPolicyError,
    EnvKey,
    EnvSource,
    build_child_environment,
    classify_environment_name,
    parse_name_array,
    purpose_policy,
    read_declared_environment,
)
from .scope import check_file_origin, normalize_file_origin, open_scoped_url
from .util import (
    atomic_write_json,
    ensure_private_dir,
    ensure_private_file,
    iso_now,
    load_json,
)

ADAPTER_ID = re.compile(r"^[A-Za-z0-9_.-]+$")
DEFAULT_ADAPTER_OUTPUT_BYTES = 8 * 1024 * 1024
MAX_ADAPTER_OUTPUT_BYTES = 64 * 1024 * 1024
STREAM_CHUNK_BYTES = 64 * 1024
BOUNDED_GUARD_POLL_SECONDS = 0.05
MAX_ATTACHMENT_REQUEST_HEADER_NAME = 64
MAX_ATTACHMENT_REQUEST_HEADER_VALUE = 16 * 1024
MAX_ATTACHMENT_REQUEST_HEADERS_BYTES = 32 * 1024
MAX_ATTACHMENT_FINAL_URL = 8 * 1024
MAX_NORMALIZED_SUBMISSION_MODE = 128
_ATTACHMENT_REQUEST_HEADERS = {
    "accept": "Accept",
    "cookie": "Cookie",
    "user-agent": "User-Agent",
}
_ATTACHMENT_RESPONSE_HEADERS = {
    "content_type": ("Content-Type", 1024),
    "content_disposition": ("Content-Disposition", 8 * 1024),
    "etag": ("ETag", 2 * 1024),
    "last_modified": ("Last-Modified", 1024),
}
_HTTP_CONTROL_CHARACTERS = re.compile(r"[\x00-\x1f\x7f]")
_PR_SET_PDEATHSIG = 1
_WATCHDOG_DISARM = b"D"
_AFTER_BOUNDED_POPEN_HOOK: Callable[[subprocess.Popen[Any]], None] | None = None
_PARENT_DEATH_WATCHDOG_PROGRAM = r"""
import os
import select
import signal
import sys
import time

control_fd = int(sys.argv[1])
activation_fd = int(sys.argv[2])
known = set()
pgid = None


def identity(pid):
    try:
        proc = os.stat(f"/proc/{pid}", follow_symlinks=False)
        descriptor = os.open(
            f"/proc/{pid}/stat", os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        )
        try:
            raw = os.read(descriptor, 4096)
        finally:
            os.close(descriptor)
        closing = raw.rfind(b")")
        fields = raw[closing + 2 :].split()
        if closing < 0 or len(fields) < 20:
            return None
        return int(fields[2]), fields[19].decode("ascii"), int(proc.st_ino)
    except (OSError, ValueError, UnicodeDecodeError):
        return None


def observe_group():
    if pgid is None:
        return
    try:
        names = os.listdir("/proc")
    except OSError:
        return
    for name in names:
        if not name.isdigit():
            continue
        pid = int(name)
        observed = identity(pid)
        if observed is not None and observed[0] == pgid:
            known.add((pid, observed[1], observed[2]))


poller = select.poll()
poller.register(control_fd, select.POLLIN | select.POLLHUP | select.POLLERR)
poller.register(activation_fd, select.POLLIN | select.POLLHUP | select.POLLERR)
activation = bytearray()
runner_dead = False
while True:
    observe_group()
    events = poller.poll(10)
    # Identity activation always wins over a simultaneous runner EOF.  The
    # child writes it atomically before arbitrary exec.
    for descriptor, _event in events:
        if descriptor != activation_fd:
            continue
        try:
            block = os.read(activation_fd, 256 - len(activation))
        except OSError:
            block = b""
        activation.extend(block)
        if len(activation) > 255:
            raise SystemExit(4)
        if block and b"\n" not in activation:
            continue
        if activation:
            try:
                line, remainder = bytes(activation).split(b"\n", 1)
                parts = line.split(b" ")
                if remainder or len(parts) != 4:
                    raise ValueError
                pid = int(parts[0])
                activated_pgid = int(parts[1])
                starttime = parts[2].decode("ascii")
                inode = int(parts[3])
                if pid <= 1 or activated_pgid != pid or not starttime.isdigit():
                    raise ValueError
            except (ValueError, UnicodeDecodeError):
                raise SystemExit(4)
            pgid = activated_pgid
            known.add((pid, starttime, inode))
        poller.unregister(activation_fd)
        os.close(activation_fd)
        activation_fd = -1
    for descriptor, _event in events:
        if descriptor != control_fd:
            continue
        try:
            token = os.read(control_fd, 1)
        except OSError:
            token = b""
        if token:
            if activation_fd >= 0:
                os.close(activation_fd)
            os.close(control_fd)
            raise SystemExit(0)
        runner_dead = True
        poller.unregister(control_fd)
        os.close(control_fd)
        control_fd = -1
    if runner_dead and (pgid is not None or activation_fd < 0):
        observe_group()
        break
if control_fd >= 0:
    os.close(control_fd)
if activation_fd >= 0:
    os.close(activation_fd)
if pgid is None:
    raise SystemExit(0)

# A matching live member pins the original group across the final signal.  A
# reused PID/PGID has a different proc inode or start time and is never touched.
pinned = None
for pid, starttime, inode in sorted(known):
    observed = identity(pid)
    if observed != (pgid, starttime, inode):
        continue
    try:
        pidfd = os.pidfd_open(pid)
    except (AttributeError, OSError):
        continue
    try:
        if identity(pid) != observed:
            os.close(pidfd)
            continue
        signal.pidfd_send_signal(pidfd, signal.SIGSTOP, None, 0)
        if identity(pid) != observed:
            os.close(pidfd)
            continue
    except (AttributeError, OSError):
        os.close(pidfd)
        continue
    pinned = pidfd
    break

if pinned is None:
    raise SystemExit(0)
try:
    try:
        os.killpg(pgid, signal.SIGKILL)
    except ProcessLookupError:
        pass
finally:
    os.close(pinned)

deadline = time.monotonic() + 2.0
while time.monotonic() < deadline:
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        raise SystemExit(0)
    time.sleep(0.01)
raise SystemExit(3)
"""


@dataclass(frozen=True)
class BoundedCommandResult:
    returncode: int
    stdout: bytes
    stderr: bytes
    termination: str
    environment: dict[str, Any]

    def metadata(self) -> dict[str, Any]:
        """Return value-free metadata for the environment used at launch."""

        return {"environment": dict(self.environment)}


@dataclass
class _ParentDeathWatchdog:
    process: subprocess.Popen[Any]
    disarm_fd: int
    activation_fd: int | None


def bounded_response_bytes(response: Any, maximum: int) -> bytes:
    """Read at most ``maximum`` response bytes and fail on overflow."""

    if maximum <= 0 or maximum > MAX_ADAPTER_OUTPUT_BYTES:
        raise ValueError("response byte limit is outside the supported range")
    data = response.read(maximum + 1)
    if len(data) > maximum:
        raise RuntimeError("adapter response exceeds configured byte limit")
    return data


def render_argv_template(
    template: object,
    fields: dict[str, str],
    *,
    label: str = "command",
) -> list[str]:
    """Render known placeholders once into bounded argv elements."""

    if (
        not isinstance(template, list)
        or not template
        or len(template) > 128
        or any(
            not isinstance(argument, str) or not argument or len(argument) > 8_192
            for argument in template
        )
    ):
        raise ValueError(f"{label} argv must be a bounded non-empty string array")
    rendered = []
    for argument in template:
        placeholders = set(re.findall(r"\{([A-Za-z_][A-Za-z0-9_-]*)\}", argument))
        unknown = placeholders - set(fields)
        if unknown:
            raise ValueError(f"{label} argv contains an unknown placeholder")
        rendered.append(
            re.sub(
                r"\{([A-Za-z_][A-Za-z0-9_-]*)\}",
                lambda match: fields[match.group(1)],
                argument,
            )
        )
    return rendered


def _process_group_exists(pgid: int) -> bool:
    """Return whether the exact POSIX process group still has a member."""

    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _wait_for_process_group_exit(
    process: subprocess.Popen[Any], pgid: int, timeout: float
) -> bool:
    deadline = time.monotonic() + timeout
    while True:
        # Reap the direct child when another waiter has not already done so.
        # Group existence remains the authority after that leader is gone.
        process.poll()
        if not _process_group_exists(pgid):
            return True
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        time.sleep(min(0.02, remaining))


def _stop_process_group(process: subprocess.Popen[Any], pgid: int) -> bool:
    """Stop and verify one owned group, even when its leader already exited.

    A descendant that deliberately creates a different session/process group is
    outside this ownership boundary and requires a stronger sandbox or cgroup.
    """

    if os.name != "posix":  # pragma: no cover - operational launch is POSIX-only.
        if process.poll() is not None:
            return True
        try:
            process.terminate()
            process.wait(timeout=1)
            return True
        except subprocess.TimeoutExpired:
            process.kill()
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                return False
            return True
        except ProcessLookupError:
            return process.poll() is not None

    try:
        os.killpg(pgid, signal.SIGTERM)
    except ProcessLookupError:
        process.poll()
        return True
    except OSError:
        return False
    if _wait_for_process_group_exit(process, pgid, 1.0):
        return True
    try:
        os.killpg(pgid, signal.SIGKILL)
    except ProcessLookupError:
        process.poll()
        return True
    except OSError:
        return False
    return _wait_for_process_group_exit(process, pgid, 1.0)


def _parent_death_preexec(activation_fd: int | None) -> Callable[[], None] | None:
    """Return the Linux-only child setup that binds it to this runner.

    Native Windows execution is source/test portability only; Rookery's
    effect-producing runtime is Linux/WSL.  Another POSIX runtime fails before
    spawn because it cannot satisfy this Linux lifecycle contract.
    """

    if os.name != "posix":  # pragma: no cover - native runtime is unavailable.
        return None
    if sys.platform != "linux":
        raise RuntimeError("bounded command parent-death supervision unavailable")
    if threading.active_count() != 1:
        # CPython documents preexec_fn as unsafe when another Python thread can
        # hold interpreter/library locks across fork.  Fail before spawn rather
        # than trade the orphan fix for a possible child-side deadlock.
        raise RuntimeError("bounded command parent-death supervision unavailable")
    try:
        prctl = ctypes.CDLL(None).prctl
    except (AttributeError, OSError) as exc:
        raise RuntimeError(
            "bounded command parent-death supervision unavailable"
        ) from exc
    prctl.argtypes = (
        ctypes.c_int,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
    )
    prctl.restype = ctypes.c_int
    expected_parent_pid = os.getpid()

    def install_parent_death_signal() -> None:
        # This function runs after fork and before exec.  The C symbol is bound
        # in the parent so child setup performs only the prctl/getppid/_exit
        # sequence.  If the parent died before prctl, the second check refuses
        # exec; if it dies after prctl, the kernel delivers SIGKILL.
        if prctl(_PR_SET_PDEATHSIG, signal.SIGKILL, 0, 0, 0) != 0:
            os._exit(127)
        if os.getppid() != expected_parent_pid:
            os._exit(127)
        if activation_fd is None:
            os._exit(127)
        try:
            pid = os.getpid()
            pgid = os.getpgrp()
            proc = os.stat("/proc/self", follow_symlinks=False)
            descriptor = os.open(
                "/proc/self/stat",
                os.O_RDONLY | getattr(os, "O_CLOEXEC", 0),
            )
            try:
                raw = os.read(descriptor, 4096)
            finally:
                os.close(descriptor)
            closing = raw.rfind(b")")
            fields = raw[closing + 2 :].split()
            if (
                closing < 0
                or len(fields) < 20
                or pgid != pid
                or int(fields[2]) != pgid
            ):
                os._exit(127)
            starttime = fields[19].decode("ascii")
            message = f"{pid} {pgid} {starttime} {int(proc.st_ino)}\n".encode(
                "ascii"
            )
            if len(message) > 255 or os.write(activation_fd, message) != len(message):
                os._exit(127)
        except BaseException:
            os._exit(127)
        finally:
            os.close(activation_fd)

    return install_parent_death_signal


def _start_parent_death_watchdog(
    *,
    cwd: Path,
    environment: ChildEnvironment,
) -> _ParentDeathWatchdog | None:
    if os.name != "posix":  # pragma: no cover - native runtime is unavailable.
        return None
    if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
        raise RuntimeError("bounded command parent-death supervision unavailable")
    control_read, control_write = os.pipe()
    activation_read, activation_write = os.pipe()
    try:
        watchdog = subprocess.Popen(
            [
                sys.executable,
                "-I",
                "-S",
                "-B",
                "-c",
                _PARENT_DEATH_WATCHDOG_PROGRAM,
                str(control_read),
                str(activation_read),
            ],
            cwd=cwd,
            env=environment.values,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=False,
            start_new_session=True,
            close_fds=True,
            pass_fds=(control_read, activation_read),
        )
    except BaseException:
        os.close(control_read)
        os.close(control_write)
        os.close(activation_read)
        os.close(activation_write)
        raise
    os.close(control_read)
    os.close(activation_read)
    return _ParentDeathWatchdog(watchdog, control_write, activation_write)


def _close_parent_death_activation(
    watchdog: _ParentDeathWatchdog | None,
) -> None:
    if watchdog is None or watchdog.activation_fd is None:
        return
    os.close(watchdog.activation_fd)
    watchdog.activation_fd = None


def _disarm_parent_death_watchdog(
    watchdog: _ParentDeathWatchdog | None,
) -> bool:
    if watchdog is None:
        return True
    _close_parent_death_activation(watchdog)
    try:
        try:
            os.write(watchdog.disarm_fd, _WATCHDOG_DISARM)
        except (BrokenPipeError, OSError):
            pass
    finally:
        os.close(watchdog.disarm_fd)
    try:
        return watchdog.process.wait(timeout=2) == 0
    except subprocess.TimeoutExpired:
        watchdog.process.kill()
        try:
            watchdog.process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            return False
        return False


def _collect_bounded_process(
    process: subprocess.Popen[Any],
    *,
    owned_pgid: int,
    child_environment: ChildEnvironment,
    watchdog: _ParentDeathWatchdog | None,
    timeout: int,
    max_output_bytes: int,
    continuation_guard: Callable[[], None] | None,
) -> BoundedCommandResult:
    if process.stdout is None or process.stderr is None:
        if not _stop_process_group(process, owned_pgid):
            raise RuntimeError("adapter process group cleanup failed")
        raise RuntimeError("adapter output pipes are unavailable")
    lock = threading.Lock()
    wake = threading.Event()
    limited = threading.Event()
    failed = threading.Event()
    captured = 0
    outputs = {"stdout": bytearray(), "stderr": bytearray()}

    def read_stream(name: str, stream: Any) -> None:
        nonlocal captured
        try:
            while True:
                chunk = stream.read(STREAM_CHUNK_BYTES)
                if not chunk:
                    break
                with lock:
                    remaining = max_output_bytes - captured
                    accepted = min(len(chunk), max(0, remaining))
                    if accepted:
                        outputs[name].extend(chunk[:accepted])
                        captured += accepted
                    if accepted < len(chunk):
                        limited.set()
                        wake.set()
        except OSError:
            failed.set()
            wake.set()
        finally:
            try:
                stream.close()
            except OSError:
                failed.set()
                wake.set()

    readers = [
        threading.Thread(
            target=read_stream,
            args=("stdout", process.stdout),
            daemon=True,
        ),
        threading.Thread(
            target=read_stream,
            args=("stderr", process.stderr),
            daemon=True,
        ),
    ]
    for reader in readers:
        reader.start()

    def wait_for_exit() -> None:
        process.wait()
        wake.set()

    waiter = threading.Thread(target=wait_for_exit, daemon=True)
    waiter.start()
    deadline = time.monotonic() + timeout
    group_outlived_leader = False
    lifecycle_error: Exception | None = None
    while True:
        remaining = max(0, deadline - time.monotonic())
        needs_poll = continuation_guard is not None or watchdog is not None
        wait_seconds = (
            min(remaining, BOUNDED_GUARD_POLL_SECONDS)
            if needs_poll
            else remaining
        )
        if wake.wait(timeout=wait_seconds):
            break
        if remaining <= 0:
            break
        if watchdog is not None and watchdog.process.poll() is not None:
            lifecycle_error = RuntimeError(
                "bounded command parent-death supervision unavailable"
            )
            break
        if continuation_guard is not None:
            try:
                continuation_guard()
            except Exception as exc:
                lifecycle_error = exc
                break
    if lifecycle_error is not None:
        termination = "guard_cancelled"
        if not _stop_process_group(process, owned_pgid):
            raise RuntimeError("adapter process group cleanup failed") from lifecycle_error
    elif time.monotonic() >= deadline and not wake.is_set():
        termination = "timeout"
        if not _stop_process_group(process, owned_pgid):
            raise RuntimeError("adapter process group cleanup failed")
    elif failed.is_set():
        termination = "capture_error"
        if not _stop_process_group(process, owned_pgid):
            raise RuntimeError("adapter process group cleanup failed")
    elif limited.is_set():
        termination = "output_limit"
        if not _stop_process_group(process, owned_pgid):
            raise RuntimeError("adapter process group cleanup failed")
    else:
        termination = "signal" if process.returncode < 0 else "exited"
        if os.name == "posix" and _process_group_exists(owned_pgid):
            group_outlived_leader = True
            if not _stop_process_group(process, owned_pgid):
                raise RuntimeError("adapter process group cleanup failed")
    for reader in readers:
        reader.join(timeout=2)
    waiter.join(timeout=2)
    if group_outlived_leader:
        raise RuntimeError("adapter process group outlived command leader")
    if any(reader.is_alive() for reader in readers) or failed.is_set():
        if os.name == "posix" and _process_group_exists(owned_pgid):
            if not _stop_process_group(process, owned_pgid):
                raise RuntimeError("adapter process group cleanup failed")
        raise RuntimeError("adapter output capture failed")
    if lifecycle_error is not None:
        raise lifecycle_error
    if limited.is_set():
        termination = "output_limit"
    return BoundedCommandResult(
        returncode=int(process.returncode if process.returncode is not None else -1),
        stdout=bytes(outputs["stdout"]),
        stderr=bytes(outputs["stderr"]),
        termination=termination,
        environment=child_environment.metadata()["environment"],
    )


def run_bounded_argv(
    argv: list[str],
    *,
    cwd: Path,
    timeout: int,
    max_output_bytes: int,
    env: ChildEnvironment | None = None,
    spawn_guard: Callable[[], ContextManager[Any]] | None = None,
    continuation_guard: Callable[[], None] | None = None,
) -> BoundedCommandResult:
    """Run bounded argv, optionally guarding spawn and continued authority.

    A paired ``spawn_guard`` context must retain its authority lock through
    ``Popen`` only.  The matching continuation callback is then polled while
    the child runs; a refusal terminates and verifies the owned process group
    before the same value-free refusal is re-raised.
    """

    if timeout <= 0:
        raise ValueError("adapter timeout must be positive")
    if max_output_bytes <= 0 or max_output_bytes > MAX_ADAPTER_OUTPUT_BYTES:
        raise ValueError("adapter output limit is outside the supported range")
    if env is not None and not isinstance(env, ChildEnvironment):
        raise TypeError("adapter environment must be a ChildEnvironment or None")
    if (spawn_guard is None) != (continuation_guard is None):
        raise ValueError("bounded command guards must be supplied together")
    if spawn_guard is not None and not callable(spawn_guard):
        raise TypeError("bounded command spawn guard must be callable")
    if continuation_guard is not None and not callable(continuation_guard):
        raise TypeError("bounded command continuation guard must be callable")
    child_environment = env or build_child_environment(
        cwd,
        policy=purpose_policy("bounded-command"),
    )
    watchdog_environment = build_child_environment(
        cwd,
        policy=purpose_policy("bounded-watchdog"),
    )
    # Refuse an unsupported runtime before creating even the inert watchdog.
    _parent_death_preexec(None)
    process: subprocess.Popen[Any] | None = None
    watchdog: _ParentDeathWatchdog | None = None
    try:
        with spawn_guard() if spawn_guard is not None else nullcontext():
            watchdog = _start_parent_death_watchdog(
                cwd=cwd,
                environment=watchdog_environment,
            )
            activation_fd = watchdog.activation_fd if watchdog is not None else None
            parent_death_preexec = _parent_death_preexec(activation_fd)
            process = subprocess.Popen(
                argv,
                cwd=cwd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=child_environment.values,
                shell=False,
                start_new_session=True,
                preexec_fn=parent_death_preexec,
                close_fds=True,
                pass_fds=((activation_fd,) if activation_fd is not None else ()),
            )
            if _AFTER_BOUNDED_POPEN_HOOK is not None:
                _AFTER_BOUNDED_POPEN_HOOK(process)
            _close_parent_death_activation(watchdog)
    except BaseException as exc:
        if process is not None:
            if not _stop_process_group(process, process.pid):
                raise RuntimeError("adapter process group cleanup failed") from exc
        cleanup_ok = _disarm_parent_death_watchdog(watchdog)
        if not cleanup_ok:
            raise RuntimeError("adapter parent-death watchdog cleanup failed") from exc
        raise
    if process is None:  # defensive: a successful Popen always assigns it.
        raise RuntimeError("bounded command spawn failed")
    # start_new_session makes the direct child's PID the owned PGID.  Retain it
    # independently because Popen.poll()/wait() can reap the leader while a
    # same-group descendant still owns output pipes or continues side effects.
    try:
        return _collect_bounded_process(
            process,
            owned_pgid=process.pid,
            child_environment=child_environment,
            watchdog=watchdog,
            timeout=timeout,
            max_output_bytes=max_output_bytes,
            continuation_guard=continuation_guard,
        )
    finally:
        cleanup_ok = _disarm_parent_death_watchdog(watchdog)
        if not cleanup_ok and sys.exc_info()[0] is None:
            raise RuntimeError("adapter parent-death watchdog cleanup failed")


@dataclass(frozen=True)
class CapabilityHealth:
    name: str
    availability: str
    health: str
    freshness: str
    read_write_scope: str
    permitted_mutations: tuple[str, ...]
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        out = asdict(self)
        out["permitted_mutations"] = list(self.permitted_mutations)
        return out


def normalize_challenge(raw: dict[str, Any]) -> dict[str, Any]:
    aliases = {
        "id": ["id", "challenge_id", "challengeId", "slug"],
        "title": ["title", "name", "challenge_name"],
        "category": ["category", "type", "track"],
        "points": ["points", "value", "score"],
        "solved": ["solved", "solved_by_me", "completed"],
        "attempts": ["attempts", "tries", "attempt_count"],
        "max_attempts": ["max_attempts", "attempt_limit", "maxTries"],
        "description": ["description", "prompt", "content"],
        "connection_info": ["connection_info", "connectionInfo", "instance"],
        "released_at": ["released_at", "release_time", "created_at"],
    }
    out: dict[str, Any] = {}
    for target, names in aliases.items():
        for name in names:
            if name in raw:
                out[target] = raw[name]
                break
    out["id"] = str(out.get("id", ""))
    out["title"] = str(out.get("title", out["id"]))
    out["category"] = str(out.get("category", "unknown"))
    try:
        out["points"] = int(out.get("points", 0) or 0)
    except (TypeError, ValueError):
        out["points"] = 0
    out["solved"] = bool(out.get("solved", False))
    out["files"] = raw.get("files", raw.get("attachments", [])) or []
    for field in (
        "hidden",
        "solvable",
        "submittable",
        "platform_submittable",
    ):
        value = raw.get(field)
        if isinstance(value, bool):
            out[field] = value
    submission_mode = raw.get("submission_mode")
    if isinstance(submission_mode, str) and len(submission_mode) <= MAX_NORMALIZED_SUBMISSION_MODE:
        out["submission_mode"] = submission_mode
    out["raw"] = raw
    return out


def normalized_snapshot(
    adapter_id: str,
    capabilities: list[CapabilityHealth],
    challenges: list[dict[str, Any]],
    *,
    releases: list[dict[str, Any]] | None = None,
    collaboration: dict[str, Any] | None = None,
    session: dict[str, Any] | None = None,
    artifact: str = "",
) -> dict[str, Any]:
    return {
        "schema_version": "1",
        "adapter_id": adapter_id,
        "generated_at": iso_now(),
        "artifact": artifact,
        "capabilities": {cap.name: cap.to_dict() for cap in capabilities},
        "challenges": [normalize_challenge(x) for x in challenges],
        "releases": releases or [],
        "collaboration": collaboration or {},
        "session": session or {},
    }


class Adapter:
    id = "base"

    def __init__(self, root: Path, manifest: dict[str, Any], scope: dict[str, Any]):
        self.root = root
        self.manifest = manifest
        self.scope = scope
        self.config = manifest.get("adapter", {}).get("config", {}) or {}

    def _resolve_local_environment(
        self, declarations: tuple[EnvKey, ...]
    ):
        """Resolve declared adapter values with dotenv precedence over parent."""

        try:
            return read_declared_environment(
                self.root,
                declarations,
            )
        except EnvironmentPolicyError as exc:
            raise RuntimeError(str(exc)) from exc

    def sync(self) -> dict[str, Any]:
        raise NotImplementedError

    def detail(self, challenge_id: str) -> dict[str, Any]:
        snapshot = self.sync()
        for challenge in snapshot.get("challenges", []):
            if str(challenge.get("id")) == str(challenge_id):
                return challenge
        raise KeyError(challenge_id)

    def capture_file(
        self, item: dict[str, Any], destination: Path
    ) -> dict[str, Any]:
        return capture_file(self.root, self.scope, item, destination)

    def preflight_action(self, envelope: dict[str, Any]) -> dict[str, Any]:
        action_kind = envelope.get("action_kind")
        cap = self.sync().get("capabilities", {}).get("scoring", {})
        if cap.get("availability") != "available" or cap.get("health") not in {
            "healthy",
            "degraded",
        }:
            return {
                "ok": False,
                "reason": "scoring capability unavailable or unhealthy",
            }
        if action_kind not in cap.get("permitted_mutations", []):
            return {"ok": False, "reason": f"unsupported scoring action: {action_kind}"}
        return {"ok": True, "reason": "preflight passed"}

    def execute_action(
        self, envelope: dict[str, Any], evidence_root: Path
    ) -> dict[str, Any]:
        raise NotImplementedError


class ManualAdapter(Adapter):
    id = "manual"

    def _path(self) -> Path:
        return self.root / str(
            self.config.get("inventory_path") or "platform/manual_inventory.json"
        )

    def sync(self) -> dict[str, Any]:
        path = self._path()
        data = load_json(path, {}) if path.exists() else {}
        challenges = data.get("challenges", []) if isinstance(data, dict) else []
        status = "available" if path.exists() else "configured"
        health = "healthy" if path.exists() else "unknown"
        caps = [
            CapabilityHealth(
                "platform_inventory", status, health, "local-file", "read-only", ()
            ),
            CapabilityHealth(
                "challenge_details", status, health, "local-file", "read-only", ()
            ),
            CapabilityHealth(
                "release_changes", status, health, "local-file", "read-only", ()
            ),
            CapabilityHealth("scoring", "unavailable", "unknown", "none", "none", ()),
            CapabilityHealth(
                "session", "not-applicable", "healthy", "none", "read-only", ()
            ),
            CapabilityHealth(
                "collaboration", "not-applicable", "healthy", "none", "read-only", ()
            ),
        ]
        artifact = str(path.relative_to(self.root)) if path.exists() else ""
        return normalized_snapshot(
            self.id,
            caps,
            challenges,
            releases=data.get("releases", []) if isinstance(data, dict) else [],
            artifact=artifact,
        )

    def execute_action(
        self, envelope: dict[str, Any], evidence_root: Path
    ) -> dict[str, Any]:
        raise RuntimeError("manual adapter has no mutation capability")


class CommandAdapter(Adapter):
    """Generic adapter edge for operator-supplied inventory and mutation commands."""

    id = "command"
    default_action_kinds: tuple[str, ...] = ("flag", "free_text")

    def _command_argv(self, name: str) -> list[str] | None:
        value = self.config.get(f"{name}_argv", self.config.get(f"{name}_command"))
        if value in (None, "", "unknown"):
            return None
        if (
            not isinstance(value, list)
            or not value
            or len(value) > 128
            or any(
                not isinstance(argument, str) or not argument or len(argument) > 8_192
                for argument in value
            )
        ):
            raise RuntimeError(
                f"{self.id} {name} command must be a non-empty JSON argv array"
            )
        return list(value)

    def _render_argv(self, template: list[str], envelope: dict[str, Any]) -> list[str]:
        fields = {
            "id": str(envelope.get("objective_id", "")),
            "candidate": str(envelope.get("exact_value", "")),
            "event": str(self.manifest.get("identity", {}).get("id", "")),
            "action_kind": str(envelope.get("action_kind", "")),
            "proposal_id": str(envelope.get("proposal_id", "")),
        }
        try:
            return render_argv_template(template, fields, label=self.id)
        except ValueError as exc:
            raise RuntimeError(str(exc)) from exc

    def _limits(self) -> tuple[int, int]:
        timeout = int(self.config.get("timeout", 60))
        maximum = int(self.config.get("max_output_bytes", DEFAULT_ADAPTER_OUTPUT_BYTES))
        if timeout <= 0:
            raise RuntimeError(f"{self.id} timeout must be positive")
        if maximum <= 0 or maximum > MAX_ADAPTER_OUTPUT_BYTES:
            raise RuntimeError(f"{self.id} output limit is outside supported range")
        return timeout, maximum

    def _command_environment(self, name: str) -> ChildEnvironment:
        raw_names = self.config.get(f"{name}_env_keys", [])
        if not isinstance(raw_names, list):
            raise RuntimeError(  # noqa: TRY004 - invalid operator config is a runtime boundary.
                f"{self.id} {name}_env_keys must be a JSON string array"
            )
        try:
            # Reuse the shared parser for exact-name, duplicate, and owner-token
            # checks while retaining the parsed manifest representation as a list.
            names = parse_name_array(
                json.dumps(raw_names),
                label=f"{self.id} {name}_env_keys",
            )
            declarations: list[EnvKey] = []
            for key in names:
                classification = classify_environment_name(key)
                if classification in {
                    EnvClass.OWNER_TOKEN,
                    EnvClass.PROVIDER_AUTH,
                    EnvClass.AGENT_CAPABILITY,
                    EnvClass.SESSION_SECRET_REF,
                    EnvClass.VPN_SECRET_REF,
                }:
                    raise EnvironmentPolicyError(
                        f"{self.id} {name}_env_keys forbids class "
                        f"{classification.value}: {key}"
                    )
                declarations.append(
                    EnvKey(
                        key,
                        classification,
                        required=True,
                        sources=(EnvSource.DOTENV, EnvSource.PARENT),
                    )
                )
            child_environment = build_child_environment(
                self.root,
                policy=purpose_policy(
                    f"adapter-{name}",
                    declarations,
                    allowed_classes={
                        EnvClass.ADAPTER_SECRET,
                        EnvClass.CAPABILITY_PATH,
                        EnvClass.PROXY_CREDENTIAL,
                        EnvClass.CA_TRUST_PATH,
                        EnvClass.UNKNOWN_EXPLICIT,
                    },
                ),
            )
        except EnvironmentPolicyError as exc:
            raise RuntimeError(str(exc)) from exc
        return child_environment

    @staticmethod
    def _record_environment(
        result: dict[str, Any], child_environment: ChildEnvironment
    ) -> dict[str, Any]:
        result["environment"] = child_environment.metadata()["environment"]
        return result

    def sync(self) -> dict[str, Any]:
        command = self._command_argv("inventory")
        kinds = tuple(
            self.config.get("scoring_action_kinds") or self.default_action_kinds
        )
        if command is None:
            caps = [
                CapabilityHealth(
                    "platform_inventory",
                    "configured",
                    "unknown",
                    "unknown",
                    "read-only",
                    (),
                    "inventory command unresolved",
                ),
                CapabilityHealth(
                    "scoring",
                    "configured",
                    "unknown",
                    "unknown",
                    "reviewer-only",
                    kinds,
                    "submit command unresolved",
                ),
            ]
            return normalized_snapshot(self.id, caps, [])
        timeout, maximum = self._limits()
        child_environment = self._command_environment("inventory")
        cp = run_bounded_argv(
            command,
            cwd=self.root,
            timeout=timeout,
            max_output_bytes=maximum,
            env=child_environment,
        )
        if cp.returncode != 0 or cp.termination != "exited":
            caps = [
                CapabilityHealth(
                    "platform_inventory",
                    "available",
                    "unhealthy",
                    "unknown",
                    "read-only",
                    (),
                    cp.stderr[-500:].decode("utf-8", errors="replace"),
                ),
                CapabilityHealth(
                    "scoring",
                    "configured",
                    "unknown",
                    "unknown",
                    "reviewer-only",
                    kinds,
                ),
            ]
            return self._record_environment(
                normalized_snapshot(self.id, caps, []), child_environment
            )
        data = json.loads(cp.stdout.decode("utf-8"))
        if (
            isinstance(data, dict)
            and data.get("schema_version")
            and data.get("capabilities") is not None
        ):
            data["adapter_id"] = self.id
            return self._record_environment(data, child_environment)
        challenges = (
            data.get("challenges", data.get("data", []))
            if isinstance(data, dict)
            else []
        )
        caps = [
            CapabilityHealth(
                "platform_inventory", "available", "healthy", iso_now(), "read-only", ()
            ),
            CapabilityHealth(
                "challenge_details", "available", "healthy", iso_now(), "read-only", ()
            ),
            CapabilityHealth(
                "release_changes", "available", "healthy", iso_now(), "read-only", ()
            ),
            CapabilityHealth(
                "scoring", "available", "healthy", iso_now(), "reviewer-only", kinds
            ),
        ]
        return self._record_environment(
            normalized_snapshot(self.id, caps, challenges), child_environment
        )

    def execute_action(
        self, envelope: dict[str, Any], evidence_root: Path
    ) -> dict[str, Any]:
        command = self._command_argv("submit")
        if command is None:
            raise RuntimeError(f"{self.id} submit command unresolved")
        rendered = self._render_argv(command, envelope)
        child_environment = self._command_environment("submit")
        evidence_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        if os.name == "posix":
            os.chmod(evidence_root, 0o700)
        atomic_write_json(
            evidence_root / "request.json",
            {
                "command_argv_template": command,
                "objective_id": envelope.get("objective_id"),
                "candidate": envelope.get("exact_value"),
                "action_kind": envelope.get("action_kind"),
                "environment": child_environment.metadata()["environment"],
            },
            mode=0o600,
        )
        timeout, maximum = self._limits()
        cp = run_bounded_argv(
            rendered,
            cwd=self.root,
            timeout=timeout,
            max_output_bytes=maximum,
            env=child_environment,
        )
        response_obj = {
            "returncode": cp.returncode,
            "termination": cp.termination,
            "stdout": cp.stdout.decode("utf-8", errors="replace"),
            "stderr": cp.stderr.decode("utf-8", errors="replace"),
            "environment": cp.environment,
        }
        atomic_write_json(evidence_root / "response.json", response_obj, mode=0o600)
        if cp.termination != "exited":
            raise RuntimeError(f"{self.id} submit command ended as {cp.termination}")
        verdict = parse_verdict(response_obj, process_returncode=cp.returncode)
        return {
            "response": response_obj,
            "response_path": str(evidence_root / "response.json"),
            "verdict": verdict.to_dict(),
        }


def adapter_descriptor(root: Path, adapter_id: str) -> dict[str, Any] | None:
    if not ADAPTER_ID.fullmatch(adapter_id):
        raise ValueError(f"invalid adapter id: {adapter_id}")
    path = root / "adapters" / adapter_id / "adapter.json"
    if not path.exists():
        return None
    data = load_json(path, {})
    if not isinstance(data, dict) or data.get("id") != adapter_id:
        raise ValueError(f"invalid adapter descriptor: {path}")
    return data


def adapter_bundle_path(root: Path, adapter_id: str) -> Path:
    return root / "adapters" / adapter_id


def load_adapter_class(root: Path, adapter_id: str) -> type[Adapter]:
    core: dict[str, type[Adapter]] = {"manual": ManualAdapter}
    if adapter_id in core:
        return core[adapter_id]
    desc = adapter_descriptor(root, adapter_id)
    if desc is None:
        raise ValueError(f"unknown adapter: {adapter_id}")
    module_rel = str(desc.get("module", "adapter.py"))
    class_name = str(desc.get("class", "AdapterImplementation"))
    module_path = adapter_bundle_path(root, adapter_id) / module_rel
    if not module_path.exists():
        raise FileNotFoundError(module_path)
    spec = importlib.util.spec_from_file_location(
        f"rookery_adapter_{adapter_id}", module_path
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load adapter module: {module_path}")
    module = importlib.util.module_from_spec(spec)
    previous_module = sys.modules.get(spec.name)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
        cls = getattr(module, class_name, None)
        if not isinstance(cls, type) or not issubclass(cls, Adapter):
            raise TypeError(f"adapter class {class_name} is not a Rookery Adapter")
    except BaseException:
        if sys.modules.get(spec.name) is module:
            if previous_module is None:
                sys.modules.pop(spec.name, None)
            else:
                sys.modules[spec.name] = previous_module
        raise
    return cls


def get_adapter(root: Path, manifest: dict[str, Any], scope: dict[str, Any]) -> Adapter:
    adapter_id = str(manifest.get("adapter", {}).get("id", "manual"))
    return load_adapter_class(root, adapter_id)(root, manifest, scope)


def _absolute_path(path: Path | str) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _require_contained(candidate: Path, root: Path, *, label: str) -> None:
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise RuntimeError(f"{label} escapes the workspace root") from exc


def _prepare_destination(root: Path, destination: Path) -> Path:
    root_path = _absolute_path(root)
    destination_path = _absolute_path(
        destination if destination.is_absolute() else root_path / destination
    )
    _require_contained(destination_path, root_path, label="attachment destination")
    if destination_path == root_path:
        raise RuntimeError(
            "attachment destination must name a file below the workspace"
        )
    try:
        os.lstat(destination_path)
    except FileNotFoundError:
        pass
    else:
        # An existing entry can only be considered after the source has been
        # bounded and read.  The publisher then opens it without following
        # links and accepts it only when its exact bytes and private metadata
        # match.  Do not migrate its parent here: a failed reuse must leave an
        # existing destination untouched.
        return destination_path
    ensure_private_dir(destination_path.parent)
    try:
        resolved_root = root_path.resolve(strict=True)
        resolved_parent = destination_path.parent.resolve(strict=True)
    except OSError as exc:
        raise RuntimeError("attachment destination cannot be resolved safely") from exc
    _require_contained(
        resolved_parent, resolved_root, label="resolved attachment destination"
    )
    return destination_path


def _source_identity(info: os.stat_result) -> tuple[int, int, int, int]:
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)


def _descriptor_walk_supported() -> bool:
    return (
        os.name == "posix"
        and bool(getattr(os, "O_DIRECTORY", 0))
        and bool(getattr(os, "O_NOFOLLOW", 0))
        and os.open in os.supports_dir_fd
    )


def _directory_read_flags() -> int:
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
        | getattr(os, "O_BINARY", 0)
    )


def _open_local_descriptor(root: Path, origin: str) -> int:
    normalized = normalize_file_origin(origin)
    root_path = _absolute_path(root)
    try:
        resolved_root = root_path.resolve(strict=True)
        resolved_source = (root_path / Path(*normalized.split("/"))).resolve(
            strict=True
        )
    except (OSError, RuntimeError) as exc:
        raise RuntimeError("local attachment is missing or has a broken path") from exc
    _require_contained(
        resolved_source, resolved_root, label="resolved local attachment"
    )
    parts = tuple(normalized.split("/"))
    if _descriptor_walk_supported():
        descriptor = os.open(resolved_root, _directory_read_flags())
        try:
            current = resolved_root
            for component in parts[:-1]:
                current /= component
                try:
                    child = os.open(
                        component,
                        _directory_read_flags(),
                        dir_fd=descriptor,
                    )
                except OSError as exc:
                    if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
                        raise RuntimeError(
                            "local attachment path contains a symlink or non-directory"
                        ) from exc
                    raise
                os.close(descriptor)
                descriptor = child
            try:
                file_descriptor = os.open(
                    parts[-1],
                    _file_read_flags(),
                    dir_fd=descriptor,
                )
            except OSError as exc:
                if exc.errno == errno.ELOOP:
                    raise RuntimeError(
                        "local attachment path contains a symlink"
                    ) from exc
                raise
        except BaseException:
            os.close(descriptor)
            raise
        os.close(descriptor)
        return file_descriptor

    current = resolved_root
    before_open: os.stat_result | None = None
    for index, component in enumerate(parts):
        current /= component
        try:
            info = os.lstat(current)
        except FileNotFoundError as exc:
            raise RuntimeError(
                "local attachment is missing or has a broken path"
            ) from exc
        if stat.S_ISLNK(info.st_mode):
            raise RuntimeError("local attachment path contains a symlink")
        if index < len(parts) - 1:
            if not stat.S_ISDIR(info.st_mode):
                raise RuntimeError("local attachment parent is not a directory")
        else:
            before_open = info
    descriptor = os.open(current, _file_read_flags())
    opened = os.fstat(descriptor)
    if before_open is None or _source_identity(opened) != _source_identity(before_open):
        os.close(descriptor)
        raise RuntimeError("local attachment changed before descriptor open")
    return descriptor


def _read_local_attachment(root: Path, origin: str, maximum: int) -> bytes:
    descriptor = _open_local_descriptor(root, origin)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise RuntimeError("local attachment is not a regular file")
        if before.st_size > maximum:
            raise RuntimeError("attachment exceeds declared byte bound")
        data = bytearray()
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            while True:
                chunk = handle.read(min(STREAM_CHUNK_BYTES, maximum + 1 - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
                if len(data) > maximum:
                    raise RuntimeError("attachment exceeds declared byte bound")
            after = os.fstat(handle.fileno())
        if _source_identity(before) != _source_identity(after):
            raise RuntimeError("local attachment changed while it was being read")
        return bytes(data)
    finally:
        os.close(descriptor)


def _read_http_attachment(response: Any, maximum: int) -> bytes:
    data = bytearray()
    while True:
        chunk = response.read(min(STREAM_CHUNK_BYTES, maximum + 1 - len(data)))
        if not chunk:
            return bytes(data)
        data.extend(chunk)
        if len(data) > maximum:
            raise RuntimeError("attachment exceeds declared byte bound")


def _attachment_request_headers(
    headers: Mapping[str, str] | None,
) -> dict[str, str]:
    if headers is None:
        return {}
    if not isinstance(headers, Mapping) or len(headers) > len(
        _ATTACHMENT_REQUEST_HEADERS
    ):
        raise TypeError("attachment request headers must be a bounded mapping")
    normalized: dict[str, str] = {}
    total = 0
    for raw_name, value in headers.items():
        if not isinstance(raw_name, str) or not isinstance(value, str):
            raise TypeError("attachment request headers must contain strings")
        name = raw_name.strip()
        canonical = _ATTACHMENT_REQUEST_HEADERS.get(name.casefold())
        if (
            canonical is None
            or name != raw_name
            or not name
            or len(name) > MAX_ATTACHMENT_REQUEST_HEADER_NAME
            or _HTTP_CONTROL_CHARACTERS.search(name)
        ):
            raise RuntimeError("attachment request header is not allowed")
        if canonical in normalized:
            raise RuntimeError("attachment request header is duplicated")
        try:
            encoded_value = value.encode("latin-1")
        except UnicodeEncodeError as exc:
            raise RuntimeError("attachment request header value is invalid") from exc
        if len(encoded_value) > MAX_ATTACHMENT_REQUEST_HEADER_VALUE or (
            _HTTP_CONTROL_CHARACTERS.search(value)
        ):
            raise RuntimeError("attachment request header value is invalid")
        total += len(name.encode("ascii")) + len(encoded_value)
        if total > MAX_ATTACHMENT_REQUEST_HEADERS_BYTES:
            raise RuntimeError("attachment request headers exceed the byte bound")
        normalized[canonical] = value
    return normalized


def _bounded_response_metadata_value(
    headers: Any, name: str, maximum: int
) -> str | None:
    if headers is None:
        return None
    get_all = getattr(headers, "get_all", None)
    values = get_all(name) if callable(get_all) else None
    if values is not None:
        if not isinstance(values, list) or len(values) != 1:
            raise RuntimeError("attachment response metadata is ambiguous")
        value = values[0]
    else:
        value = headers.get(name)
    if value is None:
        return None
    if not isinstance(value, str):
        raise RuntimeError("attachment response metadata is invalid")
    if len(value.encode("utf-8")) > maximum or _HTTP_CONTROL_CHARACTERS.search(value):
        raise RuntimeError("attachment response metadata is invalid")
    return value


def _http_attachment_metadata(response: Any, maximum: int) -> dict[str, Any]:
    status = getattr(response, "status", None)
    if status is None:
        status = response.getcode()
    if isinstance(status, bool):
        raise RuntimeError("attachment HTTP status is invalid")
    try:
        http_status = int(status)
    except (TypeError, ValueError) as exc:
        raise RuntimeError("attachment HTTP status is invalid") from exc
    if http_status < 100 or http_status > 599:
        raise RuntimeError("attachment HTTP status is invalid")

    final_url = response.geturl()
    if (
        not isinstance(final_url, str)
        or not final_url
        or len(final_url.encode("utf-8")) > MAX_ATTACHMENT_FINAL_URL
        or _HTTP_CONTROL_CHARACTERS.search(final_url)
    ):
        raise RuntimeError("attachment final URL is invalid")

    response_headers = getattr(response, "headers", None)
    metadata: dict[str, Any] = {
        "http_status": http_status,
        "final_url": final_url,
    }
    for field, (header, bound) in _ATTACHMENT_RESPONSE_HEADERS.items():
        value = _bounded_response_metadata_value(response_headers, header, bound)
        if value is not None:
            metadata[field] = value

    length = _bounded_response_metadata_value(response_headers, "Content-Length", 32)
    if length is not None:
        if not length.isascii() or not length.isdecimal():
            raise RuntimeError("attachment Content-Length is invalid")
        declared_length = int(length)
        if declared_length > maximum:
            raise RuntimeError("attachment exceeds declared byte bound")
        metadata["content_length"] = declared_length
    return metadata


def _write_private_descriptor(descriptor: int, data: bytes) -> None:
    os.fchmod(descriptor, 0o600)
    if stat.S_IMODE(os.fstat(descriptor).st_mode) != 0o600:
        raise OSError("attachment temporary file did not retain private mode")
    with os.fdopen(descriptor, "wb", closefd=False) as handle:
        for offset in range(0, len(data), STREAM_CHUNK_BYTES):
            handle.write(data[offset : offset + STREAM_CHUNK_BYTES])
        handle.flush()
        os.fsync(handle.fileno())


def _reusable_destination_error(destination: Path, reason: str) -> RuntimeError:
    return RuntimeError(
        "attachment destination already exists and cannot be safely reused: "
        f"{reason}: {destination}"
    )


def _require_private_regular_destination(
    info: os.stat_result, destination: Path
) -> None:
    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600:
        raise _reusable_destination_error(
            destination, "it is not a private regular file"
        )


def _same_file_identity(left: os.stat_result, right: os.stat_result) -> bool:
    return _source_identity(left) == _source_identity(right)


def _verify_existing_destination(
    destination: Path,
    data: bytes,
    *,
    open_file: Callable[[], int],
    stat_path: Callable[[], os.stat_result],
) -> None:
    """Prove an existing destination is stable, private, and byte-identical."""

    try:
        path_before = stat_path()
    except OSError as exc:
        raise _reusable_destination_error(
            destination, "it disappeared before verification"
        ) from exc
    _require_private_regular_destination(path_before, destination)

    try:
        descriptor = open_file()
    except OSError as exc:
        raise _reusable_destination_error(
            destination, "it could not be opened without following links"
        ) from exc
    try:
        before = os.fstat(descriptor)
        _require_private_regular_destination(before, destination)
        if not _same_file_identity(path_before, before):
            raise _reusable_destination_error(
                destination, "it changed before verification"
            )

        expected_digest = hashlib.sha256(data).digest()
        actual_digest = hashlib.sha256()
        byte_equal = before.st_size == len(data)
        offset = 0
        if byte_equal:
            while offset < len(data):
                chunk = os.read(descriptor, min(STREAM_CHUNK_BYTES, len(data) - offset))
                if not chunk:
                    byte_equal = False
                    break
                actual_digest.update(chunk)
                if chunk != data[offset : offset + len(chunk)]:
                    byte_equal = False
                offset += len(chunk)
            if offset != len(data) or os.read(descriptor, 1):
                byte_equal = False

        after = os.fstat(descriptor)
        _require_private_regular_destination(after, destination)
        if not _same_file_identity(before, after):
            raise _reusable_destination_error(
                destination, "it changed while it was being verified"
            )
    except OSError as exc:
        raise _reusable_destination_error(
            destination, "it could not be read securely"
        ) from exc
    finally:
        os.close(descriptor)

    try:
        path_after = stat_path()
    except OSError as exc:
        raise _reusable_destination_error(
            destination, "it disappeared during verification"
        ) from exc
    _require_private_regular_destination(path_after, destination)
    if not _same_file_identity(after, path_after):
        raise _reusable_destination_error(
            destination, "it changed during verification"
        )
    if not byte_equal or actual_digest.digest() != expected_digest:
        raise _reusable_destination_error(destination, "its content differs")


def _verify_fallback_destination_parent(root: Path, destination: Path) -> None:
    root_path = _absolute_path(root)
    relative_parent = destination.parent.relative_to(root_path)
    current = root_path
    for component in (None, *relative_parent.parts):
        if component is not None:
            current /= component
        info = os.lstat(current)
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise OSError("attachment destination parent is not a directory")
    if stat.S_IMODE(os.lstat(destination.parent).st_mode) != 0o700:
        raise OSError("attachment destination parent is not a private directory")


def _reuse_private_descriptor(
    root: Path, destination: Path, data: bytes
) -> bool:
    try:
        parent = _open_destination_parent(root, destination)
    except OSError as exc:
        raise _reusable_destination_error(
            destination, "its parent cannot be opened securely"
        ) from exc
    try:
        _verify_existing_destination(
            destination,
            data,
            open_file=lambda: os.open(
                destination.name,
                _file_read_flags(),
                dir_fd=parent,
            ),
            stat_path=lambda: os.stat(
                destination.name,
                dir_fd=parent,
                follow_symlinks=False,
            ),
        )
    finally:
        os.close(parent)
    return True


def _reuse_private_fallback(root: Path, destination: Path, data: bytes) -> bool:
    try:
        _verify_fallback_destination_parent(root, destination)
    except OSError as exc:
        raise _reusable_destination_error(
            destination, "its parent cannot be opened securely"
        ) from exc
    _verify_existing_destination(
        destination,
        data,
        open_file=lambda: os.open(destination, _file_read_flags()),
        stat_path=lambda: os.lstat(destination),
    )
    return True


def _verify_fallback_publication(
    root: Path,
    destination: Path,
    expected_identity: tuple[int, int],
) -> None:
    """Confirm a no-clobber fallback link still names the file we created."""

    _verify_fallback_destination_parent(root, destination)
    path_before = os.lstat(destination)
    _require_private_regular_destination(path_before, destination)
    if (path_before.st_dev, path_before.st_ino) != expected_identity:
        raise OSError("attachment destination changed during no-clobber publication")
    descriptor = os.open(destination, _file_read_flags())
    try:
        opened = os.fstat(descriptor)
        _require_private_regular_destination(opened, destination)
        if (opened.st_dev, opened.st_ino) != expected_identity:
            raise OSError("attachment destination changed during no-clobber publication")
    finally:
        os.close(descriptor)
    path_after = os.lstat(destination)
    _require_private_regular_destination(path_after, destination)
    if (path_after.st_dev, path_after.st_ino) != expected_identity:
        raise OSError("attachment destination changed during no-clobber publication")


def _open_destination_parent(root: Path, destination: Path) -> int:
    root_path = _absolute_path(root)
    relative_parent = destination.parent.relative_to(root_path)
    descriptor = os.open(root_path, _directory_read_flags())
    try:
        for component in relative_parent.parts:
            child = os.open(
                component,
                _directory_read_flags(),
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = child
        info = os.fstat(descriptor)
        if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700:
            raise OSError("attachment destination parent is not a private directory")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _publish_private_descriptor_no_clobber(
    root: Path, destination: Path, data: bytes
) -> bool:
    if _destination_exists(destination):
        return _reuse_private_descriptor(root, destination, data)
    parent = _open_destination_parent(root, destination)
    temporary_name = f".{destination.name}.{secrets.token_hex(16)}.tmp"
    descriptor: int | None = None
    published = False
    published_identity: tuple[int, int] | None = None
    try:
        descriptor = os.open(
            temporary_name,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=parent,
        )
        _write_private_descriptor(descriptor, data)
        temporary_info = os.fstat(descriptor)
        published_identity = (temporary_info.st_dev, temporary_info.st_ino)
        try:
            os.link(
                temporary_name,
                destination.name,
                src_dir_fd=parent,
                dst_dir_fd=parent,
                follow_symlinks=False,
            )
        except FileExistsError:
            _verify_existing_destination(
                destination,
                data,
                open_file=lambda: os.open(
                    destination.name,
                    _file_read_flags(),
                    dir_fd=parent,
                ),
                stat_path=lambda: os.stat(
                    destination.name,
                    dir_fd=parent,
                    follow_symlinks=False,
                ),
            )
            return True
        published = True
        published_descriptor = os.open(
            destination.name,
            _file_read_flags(),
            dir_fd=parent,
        )
        try:
            published_info = os.fstat(published_descriptor)
            if (
                not stat.S_ISREG(published_info.st_mode)
                or (published_info.st_dev, published_info.st_ino) != published_identity
                or stat.S_IMODE(published_info.st_mode) != 0o600
            ):
                raise OSError(
                    "attachment destination changed during no-clobber publication"
                )
        finally:
            os.close(published_descriptor)
        os.fsync(parent)
        return False
    except BaseException:
        if published and published_identity is not None:
            try:
                published_info = os.stat(
                    destination.name,
                    dir_fd=parent,
                    follow_symlinks=False,
                )
                if (published_info.st_dev, published_info.st_ino) == published_identity:
                    os.unlink(destination.name, dir_fd=parent)
            except (FileNotFoundError, OSError):
                pass
        raise
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            os.unlink(temporary_name, dir_fd=parent)
        except FileNotFoundError:
            pass
        os.close(parent)


def _destination_exists(destination: Path) -> bool:
    try:
        os.lstat(destination)
    except FileNotFoundError:
        return False
    return True


def _publish_private_no_clobber(root: Path, destination: Path, data: bytes) -> bool:
    if _descriptor_walk_supported():
        return _publish_private_descriptor_no_clobber(root, destination, data)
    if _destination_exists(destination):
        return _reuse_private_fallback(root, destination, data)
    _verify_fallback_destination_parent(root, destination)
    temporary = destination.with_name(
        f".{destination.name}.{secrets.token_hex(16)}.tmp"
    )
    descriptor: int | None = None
    published = False
    published_identity: tuple[int, int] | None = None
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_BINARY", 0),
            0o600,
        )
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            for offset in range(0, len(data), STREAM_CHUNK_BYTES):
                handle.write(data[offset : offset + STREAM_CHUNK_BYTES])
            handle.flush()
            os.fsync(handle.fileno())
        os.close(descriptor)
        descriptor = None
        ensure_private_file(temporary)
        temporary_info = os.lstat(temporary)
        published_identity = (temporary_info.st_dev, temporary_info.st_ino)
        try:
            os.link(temporary, destination, follow_symlinks=False)
        except FileExistsError:
            return _reuse_private_fallback(root, destination, data)
        published = True
        _verify_fallback_publication(root, destination, published_identity)
        return False
    except BaseException:
        if published and published_identity is not None:
            try:
                published_info = os.lstat(destination)
                if (published_info.st_dev, published_info.st_ino) == published_identity:
                    destination.unlink()
            except (FileNotFoundError, OSError):
                pass
        raise
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def capture_file(
    root: Path,
    scope: dict[str, Any],
    item: dict[str, Any],
    destination: Path,
    *,
    headers: Mapping[str, str] | None = None,
    platform: bool = False,
) -> dict[str, Any]:
    request_headers = _attachment_request_headers(headers)
    if not isinstance(platform, bool):
        raise TypeError("attachment platform classification must be boolean")
    has_path = bool(item.get("path"))
    has_url = bool(item.get("url"))
    if not has_path and not has_url:
        raise RuntimeError("attachment must declare a path or URL origin")
    origin = str(item.get("path") if has_path else item.get("url"))
    size = item.get("size")
    try:
        declared_size = int(size) if size is not None else None
    except (TypeError, ValueError) as exc:
        raise RuntimeError("attachment size metadata is invalid") from exc
    if declared_size is not None and declared_size < 0:
        raise RuntimeError("attachment size metadata is invalid")
    decision = check_file_origin(scope, origin, size=declared_size)
    if not decision.allowed:
        raise RuntimeError(decision.reason)
    max_bytes = int(scope.get("max_attachment_bytes", 0) or 0)
    if max_bytes <= 0:
        raise RuntimeError("compiled scope has no attachment byte bound")
    if has_path:
        data = _read_local_attachment(root, decision.target, max_bytes)
        response_metadata: dict[str, Any] = {}
    else:
        request = urllib.request.Request(
            origin,
            headers=request_headers,
            method="GET",
        )
        with open_scoped_url(
            scope,
            request,
            timeout=30,
            platform=platform,
            attachment=True,
        ) as response:
            response_metadata = _http_attachment_metadata(response, max_bytes)
            data = _read_http_attachment(response, max_bytes)
        content_length = response_metadata.get("content_length")
        if content_length is not None and content_length != len(data):
            raise RuntimeError("attachment Content-Length does not match response body")
    destination_path = _prepare_destination(root, destination)
    reused_existing = _publish_private_no_clobber(root, destination_path, data)
    return {
        "path": destination_path.relative_to(_absolute_path(root)).as_posix(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "bytes": len(data),
        "origin": origin,
        "scope_generation": int(scope.get("generation", 0)),
        "reused_existing": reused_existing,
        **response_metadata,
    }
