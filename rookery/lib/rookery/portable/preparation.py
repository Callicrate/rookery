from __future__ import annotations

import gzip
import json
import locale
import os
import re
import secrets
import shlex
import shutil
import socket
import subprocess
import tarfile
import time
import urllib.parse
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .adapters import run_bounded_argv
from .environment import (
    PREPARATION_KEYS,
    ChildEnvironment,
    EnvClass,
    EnvironmentPolicyError,
    EnvKey,
    browser_mode,
    minimal_child_environment,
    preparation_local_environment,
    preparation_network_environment,
    read_declared_environment,
    searxng_network_environment,
    validate_environment_name,
    verify_browser_cdp_endpoint,
    verify_browser_gateway_endpoint,
    write_prepared_environment,
)
from .network_policy import ExplicitNetworkPolicy
from .scope import (
    CompiledScopeBinding,
    ScopeAuthorityError,
    load_canonical_compiled_scope,
    open_scoped_url,
    verify_canonical_compiled_scope_binding,
)
from .util import (
    atomic_write_json,
    atomic_write_text,
    ensure_private_dir,
    ensure_private_file,
    iso_now,
    load_json,
)

MANAGED_SEARXNG_HOST = "127.0.0.1"
HTTP_JSON_MAX_BYTES = 8 * 1024 * 1024
WORDLIST_MAX_BYTES = 1024 * 1024 * 1024
WORDLIST_ARCHIVE_MAX_FILES = 10000
# Package managers can be verbose, but preparation diagnostics must remain bounded.
DEFAULT_PREPARATION_OUTPUT_BYTES = 8 * 1024 * 1024
MANAGED_SEARXNG_INSPECT_MAX_BYTES = 64 * 1024
MANAGED_SEARXNG_SETTINGS_DESTINATION = "/etc/searxng/settings.yml"
PREPARATION_CONFIG_MAX_BYTES = 1024 * 1024
PREPARATION_CONFIG_MAX_BINARIES = 256
PREPARATION_CONFIG_MAX_DATA_FILES = 128
PREPARATION_CONFIG_MAX_COMMANDS = 32
PREPARATION_CONFIG_MAX_CANDIDATES = 64
PREPARATION_CONFIG_MAX_PACKAGES = 128

# This is an approved OCI identity, not a claim that a vendor signature was
# verified at runtime.  The release's local policy accepts only this reviewed
# reference; a future image requires a fresh explicit review and source change.
APPROVED_MANAGED_SEARXNG_IMAGE = (
    "ghcr.io/searxng/searxng:2026.8.28-a30b2d474"
    "@sha256:addd2cf36efb4b9815a2820a522aef7cce4da0d1c0e4527f6675f5663332fc9b"
)
_MANAGED_SEARXNG_IMAGE = re.compile(
    r"^(?P<reference>ghcr\.io/searxng/searxng:"
    r"(?P<version>[0-9][0-9A-Za-z._-]*))"
    r"@(?P<digest>sha256:[0-9a-f]{64})$"
)


@dataclass(frozen=True)
class PreparationPlan:
    """Validated, value-private preparation authority resolved before effects."""

    environment: Mapping[str, str]
    config: Mapping[str, Any]
    apply: bool
    local: ChildEnvironment
    network: ChildEnvironment
    searxng_network: ChildEnvironment
    searxng_loopback: ChildEnvironment
    searxng_transport: ExplicitNetworkPolicy
    loopback_transport: ExplicitNetworkPolicy
    scope_binding: CompiledScopeBinding | None


class PreparationOutputLimitError(RuntimeError):
    """Report bounded diagnostics when a preparation command exceeds its budget."""

    def __init__(
        self,
        command: list[str],
        limit: int,
        returncode: int,
        stdout: str,
        stderr: str,
    ) -> None:
        super().__init__(
            "preparation command ended as output_limit after exceeding "
            f"the {limit}-byte combined output budget"
        )
        self.cmd = command
        self.limit = limit
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        self.output = stdout
        self.termination = "output_limit"


def _decode_command_output(data: bytes, *, errors: str = "strict") -> str:
    text = data.decode(locale.getpreferredencoding(False), errors=errors)
    return text.replace("\r\n", "\n").replace("\r", "\n")


def _bool(env: dict[str, str], key: str, default: bool) -> bool:
    raw = str(env.get(key, "1" if default else "0")).strip().lower()
    return raw in {"1", "true", "yes", "on"}


def _int(env: dict[str, str], key: str, default: int) -> int:
    try:
        return int(str(env.get(key, default)))
    except (TypeError, ValueError):
        return default


def _managed_searxng_image_identity(image: str) -> dict[str, str] | None:
    """Return the non-secret identity fields of one exact OCI reference."""

    match = _MANAGED_SEARXNG_IMAGE.fullmatch(image)
    if match is None:
        return None
    return {
        "reference": match.group("reference"),
        "digest": match.group("digest"),
    }


def _approved_managed_searxng_image(env: Mapping[str, str]) -> str:
    """Require the reviewed OCI reference before any engine or state effect."""

    configured = str(env.get("SEARXNG_IMAGE", APPROVED_MANAGED_SEARXNG_IMAGE))
    identity = _managed_searxng_image_identity(configured)
    if identity is None or configured != APPROVED_MANAGED_SEARXNG_IMAGE:
        raise EnvironmentPolicyError(
            "SEARXNG_IMAGE must be the approved exact OCI reference with a lowercase sha256 digest"
        )
    return configured


def _available_canonical_scope_binding(root: Path) -> CompiledScopeBinding | None:
    """Load canonical scope authority without treating state JSON as evidence."""

    try:
        return load_canonical_compiled_scope(root)
    except ScopeAuthorityError:
        return None


def _verify_scope_binding(root: Path, binding: CompiledScopeBinding) -> CompiledScopeBinding:
    return verify_canonical_compiled_scope_binding(
        root,
        scope_generation=binding.scope_generation,
        stop_generation=binding.stop_generation,
        file_sha256=binding.file_sha256,
        content_sha256=binding.content_sha256,
        launch_binding_sha256=binding.launch_binding_sha256,
    )


def _run(
    command: list[str],
    *,
    root: Path,
    environment: ChildEnvironment,
    timeout: float = 120,
    check: bool = False,
    max_output_bytes: int = DEFAULT_PREPARATION_OUTPUT_BYTES,
) -> subprocess.CompletedProcess[str]:
    """Run a preparation command with one bounded stdout/stderr budget."""

    result = run_bounded_argv(
        command,
        cwd=root,
        timeout=timeout,
        max_output_bytes=max_output_bytes,
        env=environment,
    )
    if result.termination == "timeout":
        raise subprocess.TimeoutExpired(
            command, timeout, output=result.stdout, stderr=result.stderr
        )
    if result.termination == "output_limit":
        raise PreparationOutputLimitError(
            command,
            max_output_bytes,
            result.returncode,
            _decode_command_output(result.stdout, errors="replace"),
            _decode_command_output(result.stderr, errors="replace"),
        )
    stdout = _decode_command_output(result.stdout)
    stderr = _decode_command_output(result.stderr)
    completed = subprocess.CompletedProcess(
        command,
        result.returncode,
        stdout,
        stderr,
    )
    if check:
        completed.check_returncode()
    return completed


def _read_limited(response: Any, max_bytes: int, label: str) -> bytes:
    data = response.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise RuntimeError(f"{label} exceeds {max_bytes} bytes")
    return data


def _copy_limited(source: Any, destination: Any, max_bytes: int, label: str) -> int:
    total = 0
    while True:
        block = source.read(min(1024 * 1024, max_bytes - total + 1))
        if not block:
            return total
        total += len(block)
        if total > max_bytes:
            raise RuntimeError(f"{label} exceeds {max_bytes} bytes")
        destination.write(block)


def _which(command: str, *, path: str) -> str | None:
    """Use only the declared preparation PATH for executable discovery."""

    return shutil.which(command, path=path)


def _manager(*, path: str) -> str | None:
    for name in ("apt-get", "dnf", "yum"):
        if _which(name, path=path):
            return "dnf" if name in {"dnf", "yum"} else "apt"
    return None


def _sudo_prefix(env: dict[str, str]) -> list[str]:
    configured = str(env.get("ROOKERY_SUDO", "sudo")).strip()
    if os.geteuid() == 0 or not configured:
        return []
    command = shlex.split(configured)
    if not command:
        return []
    if any(argument == "-E" or argument.startswith("--preserve-env") for argument in command):
        raise EnvironmentPolicyError("preparation sudo environment preservation is forbidden")
    return command


def _install_packages(
    root: Path,
    manager: str | None,
    packages: list[str],
    env: dict[str, str],
    log: list[dict[str, Any]],
    *,
    network: ChildEnvironment,
) -> bool:
    packages = sorted(set(x for x in packages if x))
    if (
        not packages
        or manager is None
        or not _bool(env, "ROOKERY_ALLOW_INSTALL_NETWORK", False)
    ):
        return False
    prefix = _sudo_prefix(env)
    timeout = _int(env, "ROOKERY_PREPARE_TIMEOUT", 1200)
    if manager == "apt":
        update = prefix + ["apt-get", "update"]
        cp = _run(update, root=root, environment=network, timeout=timeout)
        log.append(
            {
                "command": update,
                "returncode": cp.returncode,
                "stderr": cp.stderr[-1000:],
            }
        )
        if cp.returncode != 0:
            return False
        ok = True
        for package in packages:
            command = prefix + [
                "apt-get",
                "install",
                "-y",
                "--no-install-recommends",
                package,
            ]
            cp = _run(command, root=root, environment=network, timeout=timeout)
            log.append(
                {
                    "command": command,
                    "returncode": cp.returncode,
                    "stderr": cp.stderr[-1000:],
                }
            )
            ok = ok and cp.returncode == 0
        return ok
    ok = True
    binary = "dnf" if _which("dnf", path=network.values.get("PATH", "")) else "yum"
    for package in packages:
        command = prefix + [binary, "install", "-y", package]
        cp = _run(command, root=root, environment=network, timeout=timeout)
        log.append(
            {
                "command": command,
                "returncode": cp.returncode,
                "stderr": cp.stderr[-1000:],
            }
        )
        ok = ok and cp.returncode == 0
    return ok


def _which_all(commands: list[str], *, path: str) -> tuple[bool, dict[str, str]]:
    paths: dict[str, str] = {}
    for command in commands:
        found = _which(command, path=path)
        if found:
            paths[command] = found
    return len(paths) == len(commands), paths


def _python_version(
    executable: str,
    *,
    root: Path,
    environment: ChildEnvironment,
) -> tuple[int, int] | None:
    """Read one Python executable's major and minor version with bounded output."""

    try:
        completed = _run(
            [
                executable,
                "-I",
                "-S",
                "-B",
                "-c",
                "import sys; print('{}.{}'.format(sys.version_info.major, sys.version_info.minor))",
            ],
            root=root,
            environment=environment,
            timeout=10,
            max_output_bytes=1024,
        )
    except (OSError, subprocess.TimeoutExpired, PreparationOutputLimitError):
        return None
    if completed.returncode != 0:
        return None
    values = completed.stdout.strip().split(".")
    if len(values) != 2:
        return None
    try:
        major, minor = (int(value) for value in values)
    except ValueError:
        return None
    if major < 0 or minor < 0:
        return None
    return major, minor


def _minimum_python_version(item: Mapping[str, Any]) -> tuple[int, int] | None:
    configured = item.get("minimum_python_version")
    if configured is None:
        return None
    return configured[0], configured[1]


def _install_enabled(item: dict[str, Any], env: dict[str, str]) -> bool:
    if not _bool(env, "ROOKERY_PREPARE_INSTALL", True):
        return False
    level = str(item.get("install_class", "recommended"))
    if level == "core":
        return True
    if level == "recommended":
        return _bool(env, "ROOKERY_INSTALL_RECOMMENDED", True)
    return _bool(env, "ROOKERY_INSTALL_HEAVY", False)


def _scan_binaries(
    root: Path,
    config: dict[str, Any],
    env: dict[str, str],
    *,
    apply: bool,
    manager: str | None,
    install_log: list[dict[str, Any]],
    local: ChildEnvironment,
    network: ChildEnvironment,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for item in config.get("binaries", []):
        commands = [str(x) for x in item.get("commands", [])]
        commands_available, paths = _which_all(
            commands, path=local.values.get("PATH", "")
        )
        minimum_python_version = _minimum_python_version(item)
        python_version: tuple[int, int] | None = None
        available = commands_available
        version_mismatch = False
        if available and minimum_python_version is not None:
            python_version = _python_version(
                paths["python3"], root=root, environment=local
            )
            available = (
                python_version is not None
                and python_version >= minimum_python_version
            )
            version_mismatch = not available
        attempted = False
        # An older python3 is the active interpreter candidate, not a missing
        # package. Do not replace it during preparation; require the operator
        # to select Python 3.11+ explicitly.
        if (
            not available
            and not version_mismatch
            and apply
            and _install_enabled(item, env)
        ):
            packages = list((item.get("packages") or {}).get(manager or "", []))
            if packages:
                attempted = True
                _install_packages(root, manager, packages, env, install_log, network=network)
                commands_available, paths = _which_all(
                    commands, path=local.values.get("PATH", "")
                )
                available = commands_available
                if available and minimum_python_version is not None:
                    python_version = _python_version(
                        paths["python3"], root=root, environment=local
                    )
                    available = (
                        python_version is not None
                        and python_version >= minimum_python_version
                    )
        rows.append(
            {
                "id": item.get("id"),
                "commands": commands,
                "required": bool(item.get("required", False)),
                "install_class": item.get("install_class", "recommended"),
                "available": available,
                "paths": paths,
                "minimum_python_version": (
                    ".".join(str(part) for part in minimum_python_version)
                    if minimum_python_version is not None
                    else ""
                ),
                "python_version": (
                    ".".join(str(part) for part in python_version)
                    if python_version is not None
                    else ""
                ),
                "install_attempted": attempted,
            }
        )
    return rows


def _candidate_path(raw: str, root: Path) -> Path:
    path = Path(os.path.expanduser(raw))
    return path if path.is_absolute() else root / path


def _materialize_rockyou(source: Path, destination: Path) -> Path | None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.{secrets.token_hex(8)}.tmp")
    try:
        if source.name.endswith(".txt.gz"):
            with gzip.open(source, "rb") as src, temporary.open("wb") as dst:
                _copy_limited(src, dst, WORDLIST_MAX_BYTES, "rockyou wordlist")
            os.replace(temporary, destination)
            return destination
        if source.name.endswith(".tar.gz"):
            with tarfile.open(source, "r:gz") as archive:
                member = None
                for index, candidate in enumerate(archive):
                    if index >= WORDLIST_ARCHIVE_MAX_FILES:
                        raise RuntimeError(
                            f"wordlist archive exceeds {WORDLIST_ARCHIVE_MAX_FILES} files"
                        )
                    if candidate.isfile() and candidate.name.lower().endswith(
                        "rockyou.txt"
                    ):
                        member = candidate
                        break
                if member is None:
                    return None
                if member.size > WORDLIST_MAX_BYTES:
                    raise RuntimeError(
                        f"rockyou wordlist exceeds {WORDLIST_MAX_BYTES} bytes"
                    )
                extracted = archive.extractfile(member)
                if extracted is None:
                    return None
                with extracted, temporary.open("wb") as dst:
                    _copy_limited(
                        extracted, dst, WORDLIST_MAX_BYTES, "rockyou wordlist"
                    )
            os.replace(temporary, destination)
            return destination
    finally:
        temporary.unlink(missing_ok=True)
    return source


def _scan_data(
    root: Path,
    config: dict[str, Any],
    env: dict[str, str],
    *,
    apply: bool,
    manager: str | None,
    install_log: list[dict[str, Any]],
    network: ChildEnvironment,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for item in config.get("data_files", []):
        ident = str(item.get("id"))
        env_key = str(item.get("env", ""))
        candidates: list[Path] = []
        if env_key and env.get(env_key):
            candidates.append(_candidate_path(env[env_key], root))
        candidates.extend(
            _candidate_path(str(x), root) for x in item.get("candidates", [])
        )
        source = next((x for x in candidates if x.exists()), None)
        attempted = False
        if source is None and apply and _install_enabled(item, env):
            packages = list((item.get("packages") or {}).get(manager or "", []))
            if packages:
                attempted = True
                _install_packages(
                    root, manager, packages, env, install_log, network=network
                )
                source = next((x for x in candidates if x.exists()), None)
        resolved = source
        if (
            source
            and ident == "rockyou"
            and source.is_file()
            and source.name.endswith((".gz", ".tar.gz"))
        ):
            if apply:
                resolved = _materialize_rockyou(
                    source, root / "state" / "data" / "rockyou.txt"
                )
            else:
                resolved = source
        rows.append(
            {
                "id": ident,
                "env": env_key,
                "required": bool(item.get("required", False)),
                "install_class": item.get("install_class", "recommended"),
                "available": bool(resolved and resolved.exists()),
                "path": str(resolved) if resolved and resolved.exists() else "",
                "source_path": str(source) if source else "",
                "install_attempted": attempted,
            }
        )
    return rows


def _validated_http_url(url: str, *, label: str) -> str:
    """Accept an explicit HTTP(S) endpoint without embedded credentials."""

    try:
        parsed = urllib.parse.urlsplit(url)
        port = parsed.port
    except (TypeError, ValueError) as exc:
        raise EnvironmentPolicyError(f"{label} URL is invalid") from exc
    if (
        parsed.scheme.casefold() not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or (port is not None and not 1 <= port <= 65535)
    ):
        raise EnvironmentPolicyError(f"{label} URL is invalid")
    return url


def _open_checked(
    transport: ExplicitNetworkPolicy,
    url: str,
    *,
    root: Path,
    timeout: int,
    scope: Mapping[str, Any] | None = None,
    binding: CompiledScopeBinding | None = None,
) -> Any:
    """Open one bounded preparation request through explicit transport only.

    An external health check has event authority only through its compiled
    scope. Managed loopback attestation deliberately remains separate: it is
    permitted only after the local container identity has been verified.
    """

    _validated_http_url(url, label="preparation network")
    if binding is None:
        raise ScopeAuthorityError("canonical_compiled_scope_unavailable")
    verified = _verify_scope_binding(root, binding)
    effective_scope = dict(verified.scope) if scope is not None else _managed_loopback_scope(url)
    endpoint_transport = transport.scoped_transport(effective_scope)
    # This happens before resolver, socket, or evidence effects. The same
    # transport object is retained for the later open and every redirect hop.
    endpoint_transport.preflight_url(url)
    return open_scoped_url(
        effective_scope,
        url,
        timeout=timeout,
        transport=endpoint_transport,
    )


def _http_json(
    url: str,
    *,
    root: Path,
    transport: ExplicitNetworkPolicy,
    timeout: int = 8,
    scope: Mapping[str, Any] | None = None,
    binding: CompiledScopeBinding | None = None,
) -> tuple[bool, str]:
    try:
        with _open_checked(
            transport, url, root=root, timeout=timeout, scope=scope, binding=binding
        ) as response:
            data = json.loads(
                _read_limited(
                    response, HTTP_JSON_MAX_BYTES, "HTTP JSON response"
                ).decode("utf-8")
            )
        if isinstance(data, dict) and "results" in data:
            return True, "healthy"
        return False, "response was not a SearXNG JSON result"
    except Exception:
        # Network and TLS exceptions can contain an operator-controlled proxy,
        # CA, or endpoint value. Keep preparation reports value-free.
        return False, "network request failed"


def _searxng_health_url(base: str) -> str:
    separator = "&" if "?" in base else "?"
    return (
        base
        + separator
        + urllib.parse.urlencode(
            {"q": "rookery health", "format": "json", "categories": "general"}
        )
    )


def _managed_loopback_scope(url: str) -> dict[str, Any]:
    """Return the fixed direct authority used after container attestation only."""

    parsed = urllib.parse.urlsplit(_validated_http_url(url, label="managed loopback"))
    if parsed.scheme.casefold() != "http" or parsed.hostname != MANAGED_SEARXNG_HOST:
        raise EnvironmentPolicyError("managed loopback endpoint is invalid")
    port = parsed.port or 80
    return {
        "acknowledged": True,
        "generation": 0,
        "expires_at": "unknown",
        "allowed_hosts": [MANAGED_SEARXNG_HOST],
        "allowed_cidrs": [f"{MANAGED_SEARXNG_HOST}/32"],
        "allowed_ports": [port],
        "allowed_protocols": ["http"],
        "allowed_file_origins": [],
        "platform_hosts": [],
        "max_attachment_bytes": 0,
    }


def _free_port(start: int) -> int:
    for port in range(start, start + 40):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            try:
                sock.bind((MANAGED_SEARXNG_HOST, port))
            except OSError:
                continue
            return port
    raise RuntimeError("no free local port found for SearXNG")


def _container_engine(
    root: Path,
    env: dict[str, str],
    *,
    local: ChildEnvironment,
) -> tuple[list[str] | None, str]:
    requested = str(env.get("SEARXNG_CONTAINER_ENGINE", "auto")).strip()
    candidates = [requested] if requested not in {"", "auto"} else ["docker", "podman"]
    for name in candidates:
        path = _which(name, path=local.values.get("PATH", ""))
        if not path:
            continue
        direct = [path]
        cp = _run(direct + ["info"], root=root, environment=local, timeout=20)
        if cp.returncode == 0:
            return direct, name
        prefix = _sudo_prefix(env)
        if prefix:
            cp = _run(
                prefix + direct + ["info"], root=root, environment=local, timeout=20
            )
            if cp.returncode == 0:
                return prefix + direct, name
    return None, ""


def _managed_searxng_container(root: Path) -> str:
    """Return the single Rookery-owned container name for this workspace."""

    return "rookery-searxng-" + __import__("hashlib").sha256(
        str(root).encode()
    ).hexdigest()[:10]


def _untrusted_loopback_service(
    url: str,
    *,
    detail: str,
    container: str | None = None,
    engine: str | None = None,
) -> dict[str, Any]:
    """Describe a listener that cannot be attributed to Rookery ownership."""

    report: dict[str, Any] = {
        "mode": "external-untrusted",
        "available": False,
        "health": "unavailable",
        "url": url,
        "managed": False,
        "detail": detail,
        "install_attempted": False,
    }
    if container:
        report["container"] = container
    if engine:
        report["engine"] = engine
    return report


def _managed_searxng_inspection(
    raw: str,
    *,
    image: str,
    settings: Path,
    port: int,
) -> tuple[dict[str, str], bool] | None:
    """Validate one existing container against Rookery's exact create contract."""

    try:
        records = json.loads(raw)
    except (TypeError, json.JSONDecodeError, RecursionError):
        return None
    if not isinstance(records, list) or len(records) != 1:
        return None
    record = records[0]
    if not isinstance(record, dict):
        return None
    config = record.get("Config")
    state = record.get("State")
    host_config = record.get("HostConfig")
    mounts = record.get("Mounts")
    if not all(
        isinstance(value, dict) for value in (config, state, host_config)
    ) or not isinstance(mounts, list):
        return None
    observed = config.get("Image")
    observed_identity = (
        _managed_searxng_image_identity(observed) if isinstance(observed, str) else None
    )
    if observed != image or observed_identity is None:
        return None
    running = state.get("Running")
    if not isinstance(running, bool):
        return None
    if host_config.get("Privileged") is not False:
        return None
    if host_config.get("CapAdd") not in (None, []):
        return None
    restart_policy = host_config.get("RestartPolicy")
    if (
        not isinstance(restart_policy, dict)
        or restart_policy.get("Name") != "unless-stopped"
        or restart_policy.get("MaximumRetryCount") != 0
    ):
        return None
    port_bindings = host_config.get("PortBindings")
    if not isinstance(port_bindings, dict) or set(port_bindings) != {"8080/tcp"}:
        return None
    bindings = port_bindings.get("8080/tcp")
    if not isinstance(bindings, list) or len(bindings) != 1:
        return None
    binding = bindings[0]
    if (
        not isinstance(binding, dict)
        or binding.get("HostIp") != MANAGED_SEARXNG_HOST
        or binding.get("HostPort") != str(port)
    ):
        return None
    if settings.is_symlink() or not settings.is_file() or len(mounts) != 1:
        return None
    mount = mounts[0]
    if (
        not isinstance(mount, dict)
        or mount.get("Type") != "bind"
        or mount.get("Source") != str(settings.resolve())
        or mount.get("Destination") != MANAGED_SEARXNG_SETTINGS_DESTINATION
        or mount.get("RW") is not False
    ):
        return None
    return observed_identity, running


def _prepare_searxng(
    root: Path,
    env: dict[str, str],
    *,
    apply: bool,
    manager: str | None,
    install_log: list[dict[str, Any]],
    local: ChildEnvironment | None = None,
    network: ChildEnvironment | None = None,
    searxng_transport: ExplicitNetworkPolicy | None = None,
    loopback_transport: ExplicitNetworkPolicy | None = None,
    scope_binding: CompiledScopeBinding | None = None,
) -> dict[str, Any]:
    mode = str(env.get("SEARXNG_MODE", "auto")).strip().lower()
    configured = str(env.get("SEARXNG_URL", "")).strip()
    image = _approved_managed_searxng_image(env)
    image_identity = _managed_searxng_image_identity(image)
    if image_identity is None:  # Defensive: approval above is the authority.
        raise EnvironmentPolicyError("approved SearXNG image identity is invalid")
    image_report = {
        "requested_image_reference": image_identity["reference"],
        "requested_image_digest": image_identity["digest"],
        "observed_image_reference": "",
        "observed_image_digest": "",
    }
    # Retain the helper's direct-test compatibility while applying the same
    # central policies before it creates its first service path.
    local = local or preparation_local_environment(root, parent=env)
    network = network or preparation_network_environment(
        root,
        parent=env,
        required=apply and _bool(env, "ROOKERY_ALLOW_INSTALL_NETWORK", False),
    )
    if searxng_transport is None:
        searxng_transport = ExplicitNetworkPolicy.from_child_environment(
            searxng_network_environment(root, parent=env, required=bool(configured)),
            scope=scope_binding.scope if configured and scope_binding is not None else None,
        )
    if loopback_transport is None:
        loopback_transport = ExplicitNetworkPolicy.from_child_environment(
            minimal_child_environment(root, policy_name="searxng-loopback", parent=env)
        )
    if mode == "disabled":
        return {
            "mode": "disabled",
            "available": False,
            "health": "not-applicable",
            "url": "",
            "managed": False,
        }
    if configured:
        if not apply:
            # Check mode must not probe an operator-selected endpoint.  The
            # endpoint remains external until a live, scope-authorized health
            # check occurs during an apply run.
            return {
                "mode": "external",
                "available": False,
                "health": "planned",
                "url": configured,
                "managed": False,
                "detail": "health check skipped in check mode",
                "install_attempted": False,
            }
        if scope_binding is None:
            return {
                "mode": "external",
                "available": False,
                "health": "unavailable",
                "url": configured,
                "managed": False,
                "detail": "compiled event scope is unavailable",
                "install_attempted": False,
            }
        ok, detail = _http_json(
            _searxng_health_url(configured),
            root=root,
            transport=searxng_transport,
            scope=scope_binding.scope,
            binding=scope_binding,
        )
        return {
            "mode": "external",
            "available": ok,
            "health": "healthy" if ok else "unhealthy",
            "url": configured,
            "managed": False,
            "detail": detail,
            "install_attempted": False,
        }

    requested_port = _int(env, "SEARXNG_LOCAL_PORT", 8080)
    existing_url = f"http://{MANAGED_SEARXNG_HOST}:{requested_port}/search"
    settings = root / "state" / "services" / "searxng" / "settings.yml"
    if not apply:
        return {
            "mode": "managed",
            "available": False,
            "health": "planned",
            "url": existing_url,
            "managed": False,
            "detail": "managed service not checked in check mode",
            "install_attempted": False,
            **image_report,
        }

    engine, engine_name = _container_engine(root, env, local=local)
    attempted_engine_install = False
    if engine is None and _free_port(requested_port) != requested_port:
        return _untrusted_loopback_service(
            existing_url,
            detail="managed loopback port is occupied without a verified container",
        )
    if (
        engine is None
        and _bool(env, "ROOKERY_PREPARE_INSTALL", True)
        and _bool(env, "ROOKERY_ALLOW_INSTALL_NETWORK", False)
    ):
        attempted_engine_install = True
        packages = ["docker.io"] if manager == "apt" else ["docker"]
        _install_packages(root, manager, packages, env, install_log, network=network)
        engine, engine_name = _container_engine(root, env, local=local)
    if engine is None:
        return {
            "mode": "managed",
            "available": False,
            "health": "unavailable",
            "url": existing_url,
            "managed": False,
            "detail": "no usable Docker or Podman engine",
            "install_attempted": attempted_engine_install,
            **image_report,
        }

    container = _managed_searxng_container(root)
    ps = _run(
        engine
        + ["ps", "-a", "--filter", f"name=^{container}$", "--format", "{{.Names}}"],
        root=root,
        environment=local,
        timeout=30,
    )
    if ps.returncode != 0:
        return {
            "mode": "managed",
            "available": False,
            "health": "unavailable",
            "url": existing_url,
            "managed": False,
            "detail": "managed container identity could not be inspected",
            "container": container,
            "engine": engine_name,
            "install_attempted": False,
            **image_report,
        }
    if container in ps.stdout.splitlines():
        try:
            inspected = _run(
                engine + ["container", "inspect", container],
                root=root,
                environment=local,
                timeout=30,
                max_output_bytes=MANAGED_SEARXNG_INSPECT_MAX_BYTES,
            )
        except (
            PreparationOutputLimitError,
            subprocess.TimeoutExpired,
            UnicodeDecodeError,
        ):
            return _untrusted_loopback_service(
                existing_url,
                detail="existing managed container configuration is not trusted",
                container=container,
                engine=engine_name,
            )
        attested = (
            _managed_searxng_inspection(
                inspected.stdout,
                image=image,
                settings=settings,
                port=requested_port,
            )
            if inspected.returncode == 0
            else None
        )
        if attested is None:
            return _untrusted_loopback_service(
                existing_url,
                detail="existing managed container configuration is not trusted",
                container=container,
                engine=engine_name,
            )
        observed_identity, running = attested
        image_report.update(
            {
                "observed_image_reference": observed_identity["reference"],
                "observed_image_digest": observed_identity["digest"],
            }
        )
        if running:
            # A SearXNG-shaped listener is only useful after the exact owned,
            # running container and reviewed image identity are established.
            # Do not probe an unverified loopback process, even when it
            # occupies the managed port and returns plausible JSON.
            loopback_healthy, detail = _http_json(
                _searxng_health_url(existing_url),
                root=root,
                transport=loopback_transport,
                timeout=3,
                binding=scope_binding,
            )
            if loopback_healthy:
                return {
                    "mode": "managed",
                    "available": True,
                    "health": "healthy",
                    "url": existing_url,
                    "managed": True,
                    "detail": "existing-healthy",
                    "container": container,
                    "engine": engine_name,
                    "install_attempted": False,
                    **image_report,
                }
            return {
                "mode": "managed",
                "available": False,
                "health": "unhealthy",
                "url": existing_url,
                "managed": True,
                "detail": detail,
                "container": container,
                "engine": engine_name,
                "install_attempted": False,
                **image_report,
            }
        cp = _run(
            engine + ["start", container], root=root, environment=local, timeout=60
        )
        url = existing_url
        action = "start-existing"
    else:
        port = _free_port(requested_port)
        if port != requested_port:
            return _untrusted_loopback_service(
                existing_url,
                detail="managed loopback port is occupied without a verified container",
                container=container,
                engine=engine_name,
            )
        if not _bool(env, "ROOKERY_ALLOW_INSTALL_NETWORK", False):
            return {
                "mode": "managed",
                "available": False,
                "health": "unavailable",
                "url": existing_url,
                "managed": False,
                "detail": "installation network disabled",
                "install_attempted": False,
                **image_report,
            }
        url = f"http://{MANAGED_SEARXNG_HOST}:{port}/search"
        ensure_private_dir(root / "state")
        ensure_private_dir(root / "state" / "services")
        runtime = root / "state" / "services" / "searxng"
        ensure_private_dir(runtime)
        template = (root / "services" / "searxng" / "settings.template.yml").read_text(
            encoding="utf-8"
        )
        settings = runtime / "settings.yml"
        if settings.exists() or settings.is_symlink():
            ensure_private_file(settings)
        atomic_write_text(
            settings,
            template.replace("__ROOKERY_SECRET__", secrets.token_urlsafe(48)),
            mode=0o600,
        )
        ensure_private_file(settings)
        cp = _run(
            engine
            + [
                "run",
                "-d",
                "--name",
                container,
                "--restart",
                "unless-stopped",
                "-p",
                f"127.0.0.1:{port}:8080",
                "-v",
                f"{settings}:{MANAGED_SEARXNG_SETTINGS_DESTINATION}:ro",
                image,
            ],
            root=root,
            environment=network,
            timeout=_int(env, "ROOKERY_PREPARE_TIMEOUT", 1200),
        )
        action = "create"
    install_log.append(
        {
            "command": engine + [action, container],
            "returncode": cp.returncode,
            "stderr": cp.stderr[-1000:],
        }
    )
    if cp.returncode != 0:
        return {
            "mode": "managed",
            "available": False,
            "health": "unhealthy",
            "url": url,
            "managed": False,
            "detail": cp.stderr[-1000:],
            "container": container,
            "engine": engine_name,
            "install_attempted": True,
            **image_report,
        }
    wait_seconds = _int(env, "SEARXNG_START_TIMEOUT", 120)
    last_detail = "starting"
    deadline = time.time() + wait_seconds
    while time.time() < deadline:
        ok, last_detail = _http_json(
            _searxng_health_url(url),
            root=root,
            transport=loopback_transport,
            timeout=4,
            binding=scope_binding,
        )
        if ok:
            return {
                "mode": "managed",
                "available": True,
                "health": "healthy",
                "url": url,
                "managed": True,
                "detail": action,
                "container": container,
                "engine": engine_name,
                "install_attempted": True,
                **image_report,
            }
        time.sleep(2)
    return {
        "mode": "managed",
        "available": False,
        "health": "unhealthy",
        "url": url,
        "managed": True,
        "detail": last_detail,
        "container": container,
        "engine": engine_name,
        "install_attempted": True,
        **image_report,
    }


def _browser_candidates(env: dict[str, str], *, path: str) -> list[str]:
    values = [
        str(env.get("BROWSER_EXECUTABLE", "")).strip(),
        str(env.get("CHROME_BIN", "")).strip(),
    ]
    for command in (
        "chrome-headless-shell",
        "google-chrome-stable",
        "google-chrome",
        "chromium",
        "chromium-browser",
    ):
        found = _which(command, path=path)
        if found:
            values.append(found)
    return [x for x in values if x]


def _browser_ok(
    path: Path, *, root: Path, local: ChildEnvironment
) -> tuple[bool, str]:
    if not path.exists() or not os.access(path, os.X_OK):
        return False, "not executable"
    try:
        cp = _run(
            [str(path), "--version"], root=root, environment=local, timeout=20
        )
        return cp.returncode == 0, (cp.stdout or cp.stderr).strip()[:500]
    except Exception as exc:
        return False, str(exc)


def _prepare_browser(
    root: Path,
    env: dict[str, str],
    *,
    local: ChildEnvironment,
) -> dict[str, Any]:
    mode = browser_mode(env.get("BROWSER_MODE"))
    if mode == "disabled":
        return {
            "mode": "disabled",
            "available": False,
            "health": "not-applicable",
            "path": "",
        }
    if mode == "cdp":
        try:
            verify_browser_cdp_endpoint(env.get("BROWSER_CDP_URL"))
        except EnvironmentPolicyError as exc:
            return {
                "mode": "cdp",
                "available": False,
                "health": "unhealthy",
                "path": "",
                "detail": str(exc),
                "install_attempted": False,
            }
        return {
            "mode": "cdp",
            "available": True,
            "health": "healthy",
            "path": "",
            "detail": "Chrome DevTools Protocol is ready",
            "install_attempted": False,
        }
    if mode == "bidi":
        from .browser_bidi import verify_browser_bidi_endpoint

        try:
            verify_browser_bidi_endpoint(env.get("BROWSER_BIDI_URL"))
        except EnvironmentPolicyError as exc:
            return {
                "mode": "bidi",
                "available": False,
                "health": "unhealthy",
                "path": "",
                "detail": str(exc),
                "install_attempted": False,
            }
        return {
            "mode": "bidi",
            "available": True,
            "health": "healthy",
            "path": "",
            "detail": "Firefox WebDriver BiDi is ready",
            "install_attempted": False,
        }
    configured = str(
        env.get("BROWSER_EXECUTABLE", "") or env.get("CHROME_BIN", "")
    ).strip()
    if configured:
        path = Path(configured).expanduser()
        ok, detail = _browser_ok(path, root=root, local=local)
        return {
            "mode": "configured",
            "available": ok,
            "health": "healthy" if ok else "unhealthy",
            "path": str(path.resolve()) if path.exists() else str(path),
            "detail": detail,
            "install_attempted": False,
        }
    for raw in _browser_candidates(env, path=local.values.get("PATH", "")):
        path = Path(raw)
        ok, detail = _browser_ok(path, root=root, local=local)
        if ok:
            return {
                "mode": "system",
                "available": True,
                "health": "healthy",
                "path": str(path.resolve()),
                "detail": detail,
                "install_attempted": False,
            }
    return {
        "mode": "unavailable",
        "available": False,
        "health": "unavailable",
        "path": "",
        "detail": "no configured or system headless browser found",
        "install_attempted": False,
    }


def _prepare_browser_gateway(
    env: Mapping[str, str], *, required: bool
) -> dict[str, Any]:
    """Report loopback gateway health without claiming its event-policy binding."""

    if not required:
        return {
            "mode": "not-selected",
            "available": False,
            "health": "not-applicable",
            "path": "",
        }
    endpoint = str(env.get("BROWSER_GATEWAY_URL", "")).strip()
    if not endpoint:
        return {
            "mode": "required",
            "available": False,
            "health": "unhealthy",
            "path": "",
            "detail": "browser_gateway_url_invalid",
        }
    try:
        verify_browser_gateway_endpoint(endpoint)
    except EnvironmentPolicyError as exc:
        return {
            "mode": "configured",
            "available": False,
            "health": "unhealthy",
            "path": "",
            "detail": str(exc),
        }
    return {
        "mode": "configured",
        "available": True,
        "health": "healthy",
        "path": "",
        "detail": "browser gateway status is ready",
    }


def _resolved_adapter_id(root: Path) -> str | None:
    """Read the already-bound adapter choice without consulting mutable dotenv."""

    resolved = load_json(root / "state" / "resolved_event.json", {})
    adapter = resolved.get("adapter") if isinstance(resolved, dict) else None
    adapter_id = adapter.get("id") if isinstance(adapter, dict) else None
    return adapter_id if isinstance(adapter_id, str) else None


def _prepared_env(root: Path, report: dict[str, Any]) -> None:
    values: dict[str, str] = {}
    searx = report.get("services", {}).get("searxng", {})
    browser = report.get("services", {}).get("browser", {})
    if searx.get("available") and searx.get("url"):
        values["SEARXNG_URL"] = str(searx["url"])
    if browser.get("available") and browser.get("path"):
        values["BROWSER_EXECUTABLE"] = str(browser["path"])
        values["CHROME_BIN"] = str(browser["path"])
    for item in report.get("data_files", []):
        if item.get("available") and item.get("env") and item.get("path"):
            values[str(item["env"])] = str(item["path"])
    declarations = tuple(
        EnvKey(name, EnvClass.CAPABILITY_PATH) for name in sorted(values)
    )
    write_prepared_environment(root, values, declarations)
    ensure_private_file(root / "state" / "prepared.env")


def _preparation_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Rookery Preparation",
        "",
        f"Generated: `{report.get('generated_at')}`",
        f"Mode: `{report.get('mode')}`",
        f"Ready: `{str(report.get('ready')).lower()}`",
        "",
        "## Services",
    ]
    for name, row in report.get("services", {}).items():
        target = row.get("url") or row.get("path") or "not available"
        lines.append(f"- `{name}`: {row.get('health')} — {target}")
    lines += ["", "## Required binaries"]
    for row in report.get("binaries", []):
        if row.get("required"):
            if (
                row.get("id") == "python3"
                and not row.get("available")
                and row.get("python_version")
                and row.get("minimum_python_version")
            ):
                status = (
                    "unsupported "
                    f"(found {row['python_version']}; requires "
                    f"{row['minimum_python_version']} or newer)"
                )
            else:
                status = "available" if row.get("available") else "missing"
            lines.append(f"- `{row.get('id')}`: {status}")
    missing_optional = [
        row.get("id")
        for row in report.get("binaries", [])
        if not row.get("required") and not row.get("available")
    ]
    lines += [
        "",
        "## Optional gaps",
        "- " + (", ".join(missing_optional) if missing_optional else "none"),
    ]
    lines += ["", "## Data"]
    for row in report.get("data_files", []):
        lines.append(f"- `{row.get('id')}`: {row.get('path') or 'not found'}")
    if report.get("warnings"):
        lines += ["", "## Warnings"] + [f"- {x}" for x in report["warnings"]]
    return "\n".join(lines) + "\n"


def _config_error(reason: str) -> ValueError:
    return ValueError(f"configs/preparation.json is invalid: {reason}")


def _bounded_string(value: Any, *, label: str, maximum: int = 4096) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum or "\0" in value:
        raise _config_error(label)
    return value


def _package_map(value: Any, *, label: str) -> dict[str, list[str]]:
    if not isinstance(value, dict) or set(value).difference({"apt", "dnf"}):
        raise _config_error(label)
    result: dict[str, list[str]] = {}
    for manager, packages in value.items():
        if not isinstance(packages, list) or len(packages) > PREPARATION_CONFIG_MAX_PACKAGES:
            raise _config_error(label)
        result[manager] = [
            _bounded_string(package, label=label, maximum=256)
            for package in packages
        ]
    return result


def _validate_inventory_item(
    item: Any,
    *,
    data_file: bool,
    identifiers: set[str],
) -> dict[str, Any]:
    if not isinstance(item, dict):
        raise _config_error("inventory item must be an object")
    identifier = _bounded_string(item.get("id"), label="inventory id", maximum=128)
    if identifier in identifiers:
        raise _config_error("inventory ids must be unique")
    identifiers.add(identifier)
    required = item.get("required", False)
    install_class = item.get("install_class", "recommended")
    if not isinstance(required, bool) or install_class not in {"core", "recommended", "heavy"}:
        raise _config_error("inventory item has invalid policy fields")
    packages = _package_map(item.get("packages", {}), label="inventory packages")
    normalized: dict[str, Any] = {
        "id": identifier,
        "required": required,
        "install_class": install_class,
        "packages": packages,
    }
    if data_file:
        env_key = item.get("env", "")
        if not isinstance(env_key, str):
            raise _config_error("data-file environment key is invalid")
        if env_key:
            try:
                validate_environment_name(env_key, label="data-file environment key")
            except EnvironmentPolicyError as exc:
                raise _config_error("data-file environment key is invalid") from exc
        candidates = item.get("candidates", [])
        if not isinstance(candidates, list) or len(candidates) > PREPARATION_CONFIG_MAX_CANDIDATES:
            raise _config_error("data-file candidates are invalid")
        normalized["env"] = env_key
        normalized["candidates"] = [
            _bounded_string(candidate, label="data-file candidate")
            for candidate in candidates
        ]
    else:
        commands = item.get("commands")
        if (
            not isinstance(commands, list)
            or not commands
            or len(commands) > PREPARATION_CONFIG_MAX_COMMANDS
        ):
            raise _config_error("binary commands are invalid")
        normalized["commands"] = [
            _bounded_string(command, label="binary command", maximum=256)
            for command in commands
        ]
        minimum_python_version = item.get("minimum_python_version")
        if identifier == "python3" and minimum_python_version is None:
            raise _config_error("Python 3 must declare a minimum version")
        if minimum_python_version is not None:
            if (
                identifier != "python3"
                or normalized["commands"] != ["python3"]
                or not isinstance(minimum_python_version, list)
                or len(minimum_python_version) != 2
                or any(
                    isinstance(part, bool)
                    or not isinstance(part, int)
                    or part < 0
                    or part > 99
                    for part in minimum_python_version
                )
                or tuple(minimum_python_version) < (3, 11)
            ):
                raise _config_error("minimum Python version is invalid")
            normalized["minimum_python_version"] = minimum_python_version
    return normalized


def _load_preparation_config(root: Path) -> dict[str, Any]:
    path = root / "configs" / "preparation.json"
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise _config_error("cannot be read") from exc
    if len(raw) > PREPARATION_CONFIG_MAX_BYTES:
        raise _config_error("exceeds the byte limit")
    try:
        loaded = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise _config_error("is not UTF-8 JSON") from exc
    if not isinstance(loaded, dict) or set(loaded).difference(
        {"schema_version", "binaries", "data_files"}
    ):
        raise _config_error("has an unsupported top-level shape")
    if loaded.get("schema_version") != "1":
        raise _config_error("schema_version is unsupported")
    binaries = loaded.get("binaries")
    data_files = loaded.get("data_files")
    if (
        not isinstance(binaries, list)
        or len(binaries) > PREPARATION_CONFIG_MAX_BINARIES
        or not isinstance(data_files, list)
        or len(data_files) > PREPARATION_CONFIG_MAX_DATA_FILES
    ):
        raise _config_error("inventory counts are invalid")
    binary_ids: set[str] = set()
    data_ids: set[str] = set()
    normalized = {
        "schema_version": "1",
        "binaries": [
            _validate_inventory_item(item, data_file=False, identifiers=binary_ids)
            for item in binaries
        ],
        "data_files": [
            _validate_inventory_item(item, data_file=True, identifiers=data_ids)
            for item in data_files
        ],
    }
    return normalized


def _validate_preparation_controls(env: Mapping[str, str]) -> None:
    modes = {
        "ROOKERY_PREPARE_MODE": {"auto", "check", "off"},
        "SEARXNG_MODE": {"auto", "disabled"},
        "BROWSER_MODE": {"auto", "cdp", "bidi", "disabled"},
        "SEARXNG_CONTAINER_ENGINE": {"", "auto", "docker", "podman"},
    }
    for name, allowed in modes.items():
        raw = str(env.get(name, "")).strip().casefold()
        if raw and raw not in allowed:
            raise EnvironmentPolicyError(f"preparation configuration is invalid: {name}")
    for name, default, maximum in (
        ("ROOKERY_PREPARE_TIMEOUT", 1200, 3600),
        ("SEARXNG_START_TIMEOUT", 120, 900),
        ("SEARXNG_LOCAL_PORT", 8080, 65535),
    ):
        raw = str(env.get(name, default)).strip()
        try:
            parsed = int(raw)
        except ValueError as exc:
            raise EnvironmentPolicyError(f"preparation configuration is invalid: {name}") from exc
        if not 1 <= parsed <= maximum:
            raise EnvironmentPolicyError(f"preparation configuration is invalid: {name}")
    for name in (
        "ROOKERY_PREPARE_INSTALL",
        "ROOKERY_INSTALL_RECOMMENDED",
        "ROOKERY_INSTALL_HEAVY",
        "ROOKERY_ALLOW_INSTALL_NETWORK",
    ):
        raw = str(env.get(name, "")).strip().casefold()
        if raw and raw not in {"1", "0", "true", "false", "yes", "no", "on", "off"}:
            raise EnvironmentPolicyError(f"preparation configuration is invalid: {name}")
    configured = str(env.get("SEARXNG_URL", "")).strip()
    if configured:
        _validated_http_url(configured, label="SearXNG")
    _approved_managed_searxng_image(env)


def _resolve_preparation_plan(
    root: Path,
    *,
    apply: bool,
    parent: Mapping[str, str] | None,
    environment_resolved: bool = False,
    stage_c_environments: Mapping[str, ChildEnvironment] | None = None,
) -> PreparationPlan:
    """Resolve every preparation policy/configuration before runtime writes."""

    if environment_resolved:
        if parent is None:
            raise EnvironmentPolicyError("resolved preparation environment is missing")
        env = dict(parent)
    else:
        resolved = read_declared_environment(root, PREPARATION_KEYS, parent=parent)
        env = dict(resolved.values)
    _validate_preparation_controls(env)
    config = _load_preparation_config(root)
    mode = str(env.get("ROOKERY_PREPARE_MODE", "auto")).strip().casefold()
    effective_apply = apply and mode not in {"check", "off"}
    preparation_network_active = (
        mode != "off" and _bool(env, "ROOKERY_ALLOW_INSTALL_NETWORK", False)
    )
    external_searxng_active = (
        str(env.get("SEARXNG_MODE", "auto")).strip().casefold() != "disabled"
        and bool(str(env.get("SEARXNG_URL", "")).strip())
    )
    if stage_c_environments is None:
        # Direct preparation is permitted, but still resolves each selector
        # through the central declared-key APIs rather than an ambient map.
        local = preparation_local_environment(root, parent=parent)
        network = preparation_network_environment(
            root, parent=parent, required=preparation_network_active
        )
        searxng_network = searxng_network_environment(
            root, parent=parent, required=external_searxng_active
        )
    else:
        required_names = (
            "preparation-local",
            "preparation-network",
            "searxng-network",
        )
        try:
            local, network, searxng_network = (
                stage_c_environments[name] for name in required_names
            )
        except KeyError as exc:
            raise EnvironmentPolicyError("resolved Stage-C preparation policy is missing") from exc
        if not all(
            isinstance(item, ChildEnvironment)
            for item in (local, network, searxng_network)
        ):
            raise EnvironmentPolicyError("resolved Stage-C preparation policy is invalid")
        if (
            local.policy_name != "preparation-local"
            or network.policy_name != "preparation-network"
            or searxng_network.policy_name != "searxng-network"
        ):
            raise EnvironmentPolicyError("resolved Stage-C preparation policy is mismatched")
    if environment_resolved and stage_c_environments is not None:
        # The bound local policy is the exact minimal profile; only its purpose
        # label changes for loopback transport metadata. Rebuilding it would
        # parse mutable dotenv bytes after launch admission.
        loopback = ChildEnvironment(
            values=dict(local.values),
            policy_name="searxng-loopback",
            passed=local.passed,
        )
    else:
        loopback = minimal_child_environment(
            root, policy_name="searxng-loopback", parent=parent
        )
    # Construct all urllib transports before state exists as well. This turns a
    # bad declared CA/system trust configuration into a pre-effect failure.
    # The generic preparation transport has no HTTP consumer in this release,
    # but validate its explicit proxy/CA authority whenever networked package
    # or image acquisition is enabled.  Otherwise a malformed declared value
    # could evade the launch gate until a future consumer used it.
    # Validate declared proxy/CA material before the canonical loader opens its
    # read lock.  A malformed selector must fail before it can create a state
    # directory/lock side effect in a previously untouched workspace.
    if preparation_network_active:
        ExplicitNetworkPolicy.from_child_environment(network, scope=None)
    searxng_transport = ExplicitNetworkPolicy.from_child_environment(
        searxng_network,
        scope=None,
    )
    scope_binding = _available_canonical_scope_binding(root)
    loopback_transport = ExplicitNetworkPolicy.from_child_environment(loopback)
    return PreparationPlan(
        environment=env,
        config=config,
        apply=effective_apply,
        local=local,
        network=network,
        searxng_network=searxng_network,
        searxng_loopback=loopback,
        searxng_transport=searxng_transport,
        loopback_transport=loopback_transport,
        scope_binding=scope_binding,
    )


def prepare(
    root: Path,
    *,
    apply: bool = True,
    env: Mapping[str, str] | None = None,
    environment_resolved: bool = False,
    stage_c_environments: Mapping[str, ChildEnvironment] | None = None,
) -> dict[str, Any]:
    plan = _resolve_preparation_plan(
        root,
        apply=apply,
        parent=env,
        environment_resolved=environment_resolved,
        stage_c_environments=stage_c_environments,
    )
    env = dict(plan.environment)
    config = dict(plan.config)
    apply = plan.apply
    mode = str(env.get("ROOKERY_PREPARE_MODE", "auto")).strip().lower()
    # Nothing above this point writes state or starts a process/network request.
    ensure_private_dir(root / "state")
    ensure_private_dir(root / "state" / "services")
    manager = _manager(path=plan.local.values.get("PATH", ""))
    install_log: list[dict[str, Any]] = []
    binaries = _scan_binaries(
        root,
        config,
        env,
        apply=apply,
        manager=manager,
        install_log=install_log,
        local=plan.local,
        network=plan.network,
    )
    data_files = _scan_data(
        root,
        config,
        env,
        apply=apply,
        manager=manager,
        install_log=install_log,
        network=plan.network,
    )
    searxng = _prepare_searxng(
        root,
        env,
        apply=apply,
        manager=manager,
        install_log=install_log,
        local=plan.local,
        network=plan.network,
        searxng_transport=plan.searxng_transport,
        loopback_transport=plan.loopback_transport,
        scope_binding=plan.scope_binding,
    )
    browser = _prepare_browser(root, env, local=plan.local)
    browser_gateway = _prepare_browser_gateway(
        env,
        required=_resolved_adapter_id(root) in {"ctfd_browser_gateway", "skillbit"},
    )
    missing_required = [
        str(x.get("id"))
        for x in binaries
        if x.get("required") and not x.get("available")
    ]
    missing_required += [
        str(x.get("id"))
        for x in data_files
        if x.get("required") and not x.get("available")
    ]
    capabilities = [f"tool:{x['id']}" for x in binaries if x.get("available")]
    capabilities += [f"data:{x['id']}" for x in data_files if x.get("available")]
    if searxng.get("available"):
        capabilities.append("searxng")
    if browser.get("available"):
        capabilities.append("browser")
    if browser_gateway.get("available"):
        capabilities.append("browser_gateway")
    warnings = []
    if not searxng.get("available"):
        warnings.append(
            "SearXNG is unavailable; public research can continue through other configured methods."
        )
    if not browser.get("available"):
        warnings.append(
            "A headless browser is unavailable; shell HTTP tooling remains usable."
        )
    if str(env.get("BROWSER_GATEWAY_URL", "")).strip() and not browser_gateway.get("available"):
        warnings.append("The configured browser gateway status endpoint is unavailable.")
    report = {
        "schema_version": "1",
        "project": "rookery",
        "generated_at": iso_now(),
        "mode": mode,
        "apply": apply,
        "system_package_manager": manager or "none",
        "ready": not missing_required,
        "missing_required": missing_required,
        "services": {
            "searxng": searxng,
            "browser": browser,
            "browser_gateway": browser_gateway,
        },
        "binaries": binaries,
        "data_files": data_files,
        "capabilities": sorted(set(capabilities)),
        "warnings": warnings,
        "install_log": install_log,
        "environment": {
            "preparation-local": plan.local.metadata()["environment"],
            "preparation-network": plan.network.metadata()["environment"],
            "searxng-network": plan.searxng_network.metadata()["environment"],
            "searxng-loopback": plan.searxng_loopback.metadata()["environment"],
        },
    }
    ensure_private_dir(root / "state")
    preparation_path = root / "state" / "preparation.json"
    if preparation_path.exists() or preparation_path.is_symlink():
        ensure_private_file(preparation_path)
    atomic_write_json(preparation_path, report, mode=0o600)
    ensure_private_file(preparation_path)
    _prepared_env(root, report)
    atomic_write_text(root / "PREPARATION.md", _preparation_markdown(report))
    return report


def read_preparation(root: Path) -> dict[str, Any]:
    data = load_json(root / "state" / "preparation.json", {})
    return data if isinstance(data, dict) else {}
